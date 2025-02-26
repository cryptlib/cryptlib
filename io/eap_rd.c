/****************************************************************************
*																			*
*			cryptlib Session EAP-TLS/TTLS/PEAP Read Routines				*
*					Copyright Peter Gutmann 2016-2021 						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "eap.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "io/eap.h"
#endif /* Compiler-specific includes */

#ifdef USE_EAP

/* RADIUS fragments everything like crazy, the following values define the 
   maximum number of RADIUS packet fragments spread across UDP packets, 
   RADIUS packets making up a single encapsulated EAP message, and RADIUS 
   TLV fragments inside a RADIUS message that we're prepared to accept.

   MAX_RADIUS_TLV_FRAGMENTS controls how many TLVs are accepted in a single 
   RADIUS packet.  Typically this is only a handful of values, a Success, a 
   Message-Authenticator, and sometimes an MS-MPPE-Recv-Key/MS-MPPE-Send-
   Key.  However in some cases when used for vendor-specific authorisation 
   it may contain a large number of relatively small TLVs so that quite a 
   number of them can fit into a single RADIUS packet, exceeding 
   MAX_RADIUS_TLV_FRAGMENTS.  For this case, if VENDORSPECIFIC_VENDORID1 is 
   defined, we assume that many vendor-specific TLVs can occur and raise the 
   fragment limit */

#define MAX_RADIUS_FRAGMENTS		4
#define MAX_RADIUS_EAP_FRAGMENTS	8
#ifdef VENDORSPECIFIC_VENDORID1
  #define MAX_RADIUS_TLV_FRAGMENTS	32
#else
  #define MAX_RADIUS_TLV_FRAGMENTS	16
#endif /* VENDORSPECIFIC_VENDORID1 */

/* Forward declarations for interwoven EAP/RADIUS functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readRADIUSEAP( INOUT_PTR STREAM *stream,
						  INOUT_PTR EAP_INFO *eapInfo,
						  OUT_LENGTH_SHORT_Z int *bytesProcessed,
						  IN_BYTE const int maxLength );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Copy payload data from an EAP message to the caller.  Because of RADIUS'
   crazy fragmentation this isn't a straightforward copy-from-stream but has
   to take into account both RADIUS (bytesAvailable) and EAP (eapInfo)
   fragmentation */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 6 ) ) \
static int copyPayloadData( INOUT_PTR STREAM *stream,
							IN_LENGTH_SHORT const int bytesAvailable,
							INOUT_PTR EAP_INFO *eapInfo,
							OUT_BUFFER( dataMaxLength, *bytesCopied ) \
								void *data, 
							IN_DATALENGTH const int dataMaxLength, 
							OUT_DATALENGTH_Z int *bytesCopied )
	{
	BOOLEAN isPartialRead = FALSE;
	int bytesToRead, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( bytesCopied, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeNZ( bytesAvailable ) );
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );

	/* Clear return value */
	*bytesCopied = 0;

	/* Determine how much data we can read, the lesser of the total 
	   available byte count and the length of the current EAP packet */
	bytesToRead = min( bytesAvailable, eapInfo->eapLength );
	if( bytesToRead > dataMaxLength )
		{
		/* There's more data present than the caller wants to read, 
		   indicate when we return that this was a partial read */
		bytesToRead = dataMaxLength;
		isPartialRead = TRUE;
		}
	ENSURES( isShortIntegerRangeNZ( bytesToRead ) );

	status = sread( stream, data, bytesToRead );
	if( cryptStatusError( status ) )
		return( status );
	eapInfo->eapLength -= bytesToRead;
	ENSURES( isShortIntegerRange( eapInfo->eapLength ) );

	*bytesCopied = bytesToRead;

	return( isPartialRead ? OK_SPECIAL : CRYPT_OK );
	}

/* Update the EAP read state after processing data in a RADIUS/EAP packet */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int updateEapState( INOUT_PTR STREAM *stream,
						   INOUT_PTR EAP_INFO *eapInfo,
						   IN_LENGTH_SHORT const int bufPos,
						   IN_BOOL const BOOLEAN isPartialRead )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );

	REQUIRES( isShortIntegerRangeNZ( bufPos ) );
	REQUIRES( isBooleanValue( isPartialRead ) );

	/* Update the stream position and EAP/RADIUS length information to 
	   reflect how much data we've processed.  We don't update the EAP
	   remainder length if we're processing a new RADIUS message since it 
	   applies for EAP fragments within the RADIUS message and there won't 
	   be any yet at this point */
	stream->bufPos += bufPos;
	if( eapInfo->eapState != EAP_STATE_PROCESSMESSAGE )
		eapInfo->eapRemainderLength -= bufPos;
	eapInfo->radiusLength -= bufPos;

	/* Move on to the next state */
	if( isPartialRead )
		{
		/* Only part of the payload data was read, remember that we 
		   have to process the rest later */
		eapInfo->eapState = EAP_STATE_CONTINUEREAD;
		}
	else
		{
		if( eapInfo->eapState == EAP_STATE_PROCESSMESSAGE )
			{
			/* If the fragmented-packets flag was set then we need to send 
			   an ACK for the packet that we've just received */
			if( eapInfo->eapFlags & EAP_FLAG_FRAGMENTED )
				eapInfo->eapState = EAP_STATE_SENDACK;
			else
				{
				/* We've finished processing the current message, if there 
				   are more messages to follow, read the next packet */
				if( eapInfo->eapType == EAP_TYPE_REQUEST || \
					eapInfo->eapType == EAP_TYPE_RESPONSE )
					{
					/* If we've read an EAP ACK then it's just a 
					   placeholder to allow the protocol to continue,
					   there's nothing more to do */
					if( eapInfo->eapFlags & EAP_FLAG_EAPACK )
						{
						eapInfo->eapState = EAP_STATE_DUMMYREAD;
						eapInfo->eapFlags &= ~EAP_FLAG_EAPACK;
						}
					else
						eapInfo->eapState = EAP_STATE_NONE;
					}
				else
					{
					/* We've finished the exchange, typically with something
					   like an Accept or Reject, we're done */
					eapInfo->eapState = EAP_STATE_FINISHED;
					}
				}
			}
		else
			{
			/* We've completed a partial read, move on to the next 
			   message */
			eapInfo->eapState = EAP_STATE_PROCESSMESSAGE;
			}
		}

	return( CRYPT_OK );
	}

/* Process a vendor-specific RADIUS TLV:

	byte		type
	byte		length		-- Including type and length
	uint32		vendorID
	byte[]		data

   We don't usually do anything with this type apart from displaying 
   diagnostics, but for some cases we record the contents for later use.
   
   Note that these attributes frequently contain sensitive information, and 
   this sensitive information is carefully sent *outside* the secure tunnel,
   in clear text and "protected" only by the (usually very weak) RADIUS 
   secret rather than anything related to TLS */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processVendorSpecific( INOUT_PTR STREAM *stream,
								  INOUT_PTR EAP_INFO *eapInfo,
								  IN_LENGTH_SHORT const int tlvLength )
	{
	long vendorID;
	const int extraDataLength = tlvLength - UINT32_SIZE;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );

	REQUIRES( isShortIntegerRangeNZ( tlvLength ) );

	/* Make sure that there's enough data for a vendor-specific packet.  We 
	   need at least enough data for the vendor ID, the vendor type, and the 
	   vendor length */
	if( tlvLength < UINT32_SIZE + 1 + 1 || \
		tlvLength > RADIUS_MAX_TLV_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Read the vendor ID, listed at 
	   https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers */
	status = vendorID = readUint32( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Print diagnostic information on any sub-attributes that we recognise:
				
	  [	byte		type
		byte		length		-- Including type and length
		uint32		vendorID ]
			byte	vendor type
			byte	vendor length
			byte[]	vendor data
			
	   According to the spec a single attribute may contain multiple vendor-
	   specific sub-attributes, however in practice there always seems to be 
	   one sub-attribute per attribute, with multiple attributes sent if 
	   multiple sub-attributes are needed */
	DEBUG_OP( if( vendorID == 311 ) )
		{
		DEBUG_OP( const int subType = sPeek( stream ); ) 

		/* Microsoft values, via MSCHAPv2, are common enough that we 
		   special-case diagnostics for them */
		DEBUG_PRINT_COND( subType == 16,
						  ( "    Read Microsoft TLV MS-MPPE-Send-Key, "
						    "length %d.\n", extraDataLength ));
		DEBUG_PRINT_COND( subType == 17,
						  ( "    Read Microsoft TLV MS-MPPE-Recv-Key, "
						    "length %d.\n", extraDataLength ));
		DEBUG_PRINT_COND( subType != 16 && subType != 17,
						  ( "    Read Microsoft TLV, type %d, length %d.\n", 
						    subType, extraDataLength ));
		}
	DEBUG_OP( else )
		{
		DEBUG_PRINT(( "    Read vendor %ld TLV, length %d.\n", vendorID, 
					  extraDataLength ));
		}

	/* If this wasn't attached to a RADIUS Access-Accept, meaning that it's 
	   just metadata noise, skip the packet.  We also skip it if it's too 
	   large to store in the extraData field */
	if( eapInfo->radiusType != RADIUS_TYPE_ACCEPT || \
		eapInfo->extraDataLength + extraDataLength > MAX_EXTRADATA_SIZE )
		{
		return( sSkip( stream, extraDataLength, MAX_INTLENGTH_SHORT ) );
		}
	ENSURES( rangeCheck( extraDataLength, 1, 
						 MAX_EXTRADATA_SIZE - eapInfo->extraDataLength ) );

	/* If only packets with a specific vendor ID are of interest, skip any 
	   other types of packets */
#if defined( VENDORSPECIFIC_VENDORID1 ) 
  #if defined( VENDORSPECIFIC_VENDORID2 )
	if( vendorID != VENDORSPECIFIC_VENDORID1 && \
		vendorID != VENDORSPECIFIC_VENDORID2 )
  #else 
	if( vendorID != VENDORSPECIFIC_VENDORID1 )
  #endif /* VENDORSPECIFIC_VENDORID2 */
		{
		return( sSkip( stream, extraDataLength, MAX_INTLENGTH_SHORT ) );
		}
#endif /* VENDORSPECIFIC_VENDORID1 */

	/* The packet was sent as part of a RADIUS Access-Accept, record any 
	   vendor-specific data that the server has helpfully sent *outside* the 
	   secure tunnel for ease of attacker access, for later use by the 
	   caller */
	status = sread( stream, eapInfo->extraData + eapInfo->extraDataLength, 
					extraDataLength );
	if( cryptStatusOK( status ) )
		eapInfo->extraDataLength += extraDataLength;

	return( status );
	}

/****************************************************************************
*																			*
*								Read RADIUS Messages						*
*																			*
****************************************************************************/

/* Read a RADIUS packet:

	byte		type
	byte		counter		-- Incremented for every req/resp pair
	uint16		length		-- Including type, counter, length
	byte[16]	nonce		-- Updated for every req/resp pair
	byte[]		attributes 

   The counter is actually defined in the spec as an identifier that "MUST 
   be changed whenever the content of the Attributes field changes, and 
   whenever a valid reply has been received for a previous request" (note
   that this differs from the EAP definition of the same field), but we 
   treat it as a counter which is what it in effect is */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readRADIUSMessage( INOUT_PTR STREAM *stream,
					   INOUT_PTR EAP_INFO *eapInfo,
					   IN_BOOL const BOOLEAN isRequest )
	{
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	STM_TRANSPORTREAD_FUNCTION transportReadFunction;
	STREAM radiusStream;
	BYTE nonce[ RADIUS_NONCE_SIZE + 16 ];
	int type, counter, bytesRead, totalLength;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStreamEAP( netStream ) );
	REQUIRES( isBooleanValue( isRequest ) );

	/* Set up the function pointers.  We have to do this after the netStream
	   check otherwise we'd potentially be dereferencing a NULL pointer */
	transportReadFunction = ( STM_TRANSPORTREAD_FUNCTION ) \
							FNPTR_GET( netStream->transportReadFunction );
	REQUIRES( transportReadFunction != NULL );

	/* Clear any ephemeral data values.  We dont clear the EAP state nonce 
	   at this point because we may need to send back a response in case of
	   an error, for which we need the nonce as part of the message */
	eapInfo->eapType = EAP_TYPE_NONE;
	eapInfo->eapSubtypeRead = EAP_SUBTYPE_NONE;
	eapInfo->eapLength = eapInfo->eapRemainderLength = \
		eapInfo->extraDataLength = 0;

	/* Read the first UDP packet containing the RADIUS packet header */
	status = transportReadFunction( netStream, stream->buffer, 
									RADIUS_MAX_PACKET_SIZE, &bytesRead, 
									TRANSPORT_FLAG_NONE );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesRead <= 0 && netStream->timeout <= 0 )
		{
		/* If this was a nonblocking read and no data was read, this isn't
		   an error */
		return( OK_SPECIAL );
		}
	if( bytesRead < RADIUS_HEADER_SIZE )
		{
		retExt( CRYPT_ERROR_TIMEOUT,
				( CRYPT_ERROR_TIMEOUT, NETSTREAM_ERRINFO, 
				  "Timed out reading RADIUS packet header, only got %d of "
				  "%d bytes", bytesRead, RADIUS_HEADER_SIZE ) );
		}

	/* Decode the packet header:

		|<--------------- bytesRead --------------->|
		|<-RADIUS_HDR_SIZE->|
		+-------+-----------+-----------------------+
		|header	| totalLen	| data					|
		+-------+-----|-----+-----------------------+
		<-------------+-----------------------------> 

	   Note that the RADIUS length value includes itself and the header data
	   that precedes it, so the following checks take into account the 
	   spurious extra data size */
	sMemConnect( &radiusStream, stream->buffer, RADIUS_HEADER_SIZE );
	type = sgetc( &radiusStream );
	counter = sgetc( &radiusStream );
	totalLength = readUint16( &radiusStream );
	status = sread( &radiusStream, nonce, RADIUS_NONCE_SIZE );
	sMemDisconnect( &radiusStream );
	if( cryptStatusError( status ) )
		return( status );
	if( type <= RADIUS_TYPE_NONE || type >= RADIUS_TYPE_LAST )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Invalid RADIUS packet type %d", type ) );
		}
#ifndef CONFIG_FUZZ
	if( !isRequest && counter != eapInfo->radiusCtr )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Invalid RADIUS packet ID %d for packet type %s (%d), "
				  "should have been %d", counter, 
				  getRADIUSPacketName( type ), type, 
				  eapInfo->radiusCtr ) );
		}
#endif /* CONFIG_FUZZ */
	if( totalLength < RADIUS_MIN_PACKET_SIZE || \
		totalLength > RADIUS_MAX_PACKET_SIZE )
		{
		/* First a general check that the packet length is valid */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Invalid RADIUS packet length %d for packet type %s (%d), "
				  "should be %d...%d", totalLength, 
				  getRADIUSPacketName( type ), type, RADIUS_MIN_PACKET_SIZE, 
				  RADIUS_MAX_PACKET_SIZE ) );
		}
	if( totalLength != bytesRead )
		{
		/* Now a more specific check that the packet size corresponds to the 
		   data that was read */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Invalid RADIUS packet length %d for packet type %s (%d), "
				  "should have been %d", totalLength, 
				  getRADIUSPacketName( type ), type, bytesRead ) );
		}
	if( isRequest )
		{
		/* It's a request from the client, save the nonce for our 
		   response */
		memcpy( eapInfo->radiusNonce, nonce, RADIUS_NONCE_SIZE );
		}
	else
		{
#ifndef CONFIG_FUZZ
		BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];

		/* It's a response (challenge), replace the authenticator (MD5 hash) 
		   value in the message with the original nonce that was used to 
		   create it, then hash the message */
		memcpy( stream->buffer + 4, eapInfo->radiusNonce, 
				RADIUS_NONCE_SIZE );
		status = radiusMD5HashBuffer( hashValue, 16, stream->buffer, 
									  totalLength, eapInfo->password, 
									  eapInfo->passwordLength );
		if( cryptStatusError( status ) )
			return( status );
		if( memcmp( nonce, hashValue, RADIUS_NONCE_SIZE ) )
			{
#ifdef USE_ERRMSGS
			char authenticatorText[ CRYPT_MAX_TEXTSIZE + 8 ];
			char reqAuthenticatorText[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */

			formatHexData( authenticatorText, CRYPT_MAX_TEXTSIZE, hashValue, 
						   RADIUS_NONCE_SIZE );
			formatHexData( reqAuthenticatorText, CRYPT_MAX_TEXTSIZE,
						   eapInfo->radiusNonce, RADIUS_NONCE_SIZE );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
					  "Computed RADIUS MD5 authenticator '%s' for packet type "
					  "%s (%d) doesn't match actual authenticator '%s'", 
					  authenticatorText, getRADIUSPacketName( type ), type, 
					  reqAuthenticatorText ) );
			}
#endif /* CONFIG_FUZZ */
		}
	eapInfo->radiusType = type;
	totalLength -= RADIUS_HEADER_SIZE;

	/* If this is the initial wakeup packet from the client, remember the 
	   initial RADIUS counter value they've sent for subsequent messages */
	if( eapInfo->eapFlags & EAP_FLAG_CLIENTWAKEUP )
		eapInfo->radiusCtr = counter;

	/* We've successfully read and processed at least the RADIUS part of the
	   message, clear the EAP state nonce in preparation for reading the next
	   nonce value */
	if( !isRequest )
		{
		memset( eapInfo->radiusStateNonce, 0, CRYPT_MAX_HASHSIZE );
		eapInfo->radiusStateNonceSize = 0;
		}

	/* Move any remaining payload down in the buffer */
	if( totalLength > 0 )
		{
		REQUIRES( boundsCheck( RADIUS_HEADER_SIZE, totalLength, 
							   stream->bufSize ) );
		memmove( stream->buffer, stream->buffer + RADIUS_HEADER_SIZE, 
				 totalLength );
		}
	stream->bufEnd = eapInfo->radiusLength = totalLength;
	stream->bufPos = 0;
	totalLength -= bytesRead - RADIUS_HEADER_SIZE;
	ENSURES( totalLength >= 0 && \
			 totalLength <= RADIUS_MAX_PACKET_SIZE - RADIUS_HEADER_SIZE );

#if 0	/* Currently untested, need to find a server that sends multiple UDP 
		   packets to transport a single RADIUS packet rather than 
		   fragmenting RADIUS TLVs across multiple UDP packets, which all 
		   servers tested so far seem to do.  Also currently precluded by 
		   the totalLength == bytesRead check earlier */
	LOOP_INDEX noFragments;

	/* Read any further UDP packets that make up the remainder of the RADIUS 
	   packet */
	LOOP_MED( noFragments = 0, 
			  noFragments < MAX_RADIUS_FRAGMENTS && totalLength > 0, 
			  noFragments++ )
		{
		int bytesRead;

		ENSURES( LOOP_INVARIANT_MED( noFragments, 0, 
									 MAX_RADIUS_FRAGMENTS - 1 ) );

		assert( DEBUG_WARN );
		if( stream->bufEnd + totalLength > stream->bufSize )
			return( CRYPT_ERROR_OVERFLOW );
		status = transportReadFunction( netStream, 
										stream->buffer + stream->bufEnd, 
										totalLength, &bytesRead, 
										TRANSPORT_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		if( bytesRead != totalLength )
			{
			retExt( CRYPT_ERROR_TIMEOUT,
					( CRYPT_ERROR_TIMEOUT, NETSTREAM_ERRINFO, 
					  "Timed out reading RADIUS packet %s (%d) data, only "
					  "got %d of %d bytes", 
					  getRADIUSPacketName( eapInfo->radiusType ), 
					  eapInfo->radiusType, bytesRead, totalLength ) );
			}
		stream->bufEnd += bytesRead;
		totalLength -= bytesRead;
		}
	ENSURES( LOOP_BOUND_OK );
	if( noFragments > MAX_RADIUS_FRAGMENTS )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Excessive fragmentation in RADIUS packet type %s (%d) "
				  "length %d, received more than %d fragments", 
				  getRADIUSPacketName( eapInfo->radiusType ), 
				  eapInfo->radiusType, eapInfo->radiusLength, 
				    MAX_RADIUS_FRAGMENTS ) );
		}
#endif /* 0 */

	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Read %s (%d) RADIUS packet, length %d, packet ID %d.\n", 
				  getRADIUSPacketName( eapInfo->radiusType ), 
				  eapInfo->radiusType, eapInfo->radiusLength,
				  counter ));
#ifdef DEBUG_TRACE_RADIUS
	DEBUG_DUMP_DATA( stream->buffer, eapInfo->radiusLength );
#endif /* DEBUG_TRACE_RADIUS */
	DEBUG_PRINT_END();

	return( CRYPT_OK );
	}

/* Process a RADIUS message consisting of RADIUS TLV packets:

	byte		type
	byte		length		-- Including type and length
	byte[]		data 

  The data/dataMaxLength information may be NULL/0 if we're reading 
  non-payload TLVs */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5, 6 ) ) \
int processRADIUSTLVs( INOUT_PTR STREAM *stream,
					   INOUT_PTR EAP_INFO *eapInfo,
					   OUT_BUFFER_OPT( dataMaxLength, *bytesCopied ) \
							void *data, 
					   IN_DATALENGTH_Z const int dataMaxLength, 
					   OUT_DATALENGTH_Z int *bytesCopied,
					   INOUT_PTR ERROR_INFO *errorInfo )
	{
	BYTE *bufPtr = data;
	BOOLEAN partialRead = FALSE;
	LOOP_INDEX noPackets;
	int bytesRead = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );
	assert( ( data == NULL && dataMaxLength == 0 ) || \
			isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( bytesCopied, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( ( data == NULL && dataMaxLength == 0 ) || \
			  ( data != NULL && \
			    isBufsizeRangeNZ( dataMaxLength ) ) );
			  /* May be NULL/0 if we're just reading the remainder of the 
			     non-payload TLVs */

	/* Clear return values */
	if( data != NULL )
		{
		REQUIRES( isIntegerRangeNZ( dataMaxLength ) ); 
		memset( data, 0, min( 16, dataMaxLength ) );
		}
	*bytesCopied = 0;

	/* Keep reading RADIUS TLVs until we either run out of data or we've 
	   satisfied the caller's read request, which means that we have to 
	   resume the processing at the next read call */
	LOOP_MED( noPackets = 0, 
			  noPackets < MAX_RADIUS_TLV_FRAGMENTS && \
					stell( stream ) < eapInfo->radiusLength && \
					!partialRead,
			  noPackets++ )
		{
		static const MAP_TABLE tlvMinSizeMapTable[] = {
			{ RADIUS_SUBTYPE_EAPMESSAGE, 1 + 1 + UINT16_SIZE },	/* Can be empty */
			{ RADIUS_SUBTYPE_MESSAGEAUTH, 16 }, 
			{ RADIUS_SUBTYPE_STATE, 1 },
			{ RADIUS_SUBTYPE_VENDORSPECIFIC, UINT32_SIZE + 1 + 1 },
			{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
			};
		int tlvType, tlvLength, tlvMinLength;

		ENSURES( LOOP_INVARIANT_MED( noPackets, 0, 
									 MAX_RADIUS_TLV_FRAGMENTS - 1 ) );

		/* Read the TLV packet header */
		tlvType = sgetc( stream );
		status = tlvLength = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( tlvLength < RADIUS_TLV_HEADER_SIZE + RADIUS_MIN_TLV_SIZE || \
			tlvLength > RADIUS_TLV_HEADER_SIZE + RADIUS_MAX_TLV_SIZE )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Invalid RADIUS TLV packet length %d for packet "
					  "subtype %s (%d) should be %d...%d", tlvLength, 
					  getRADIUSSubtypeName( tlvType ), tlvType, 
					  RADIUS_TLV_HEADER_SIZE + RADIUS_MIN_TLV_SIZE, 
					  RADIUS_TLV_HEADER_SIZE + RADIUS_MAX_TLV_SIZE ) );
			}
		tlvLength -= RADIUS_TLV_HEADER_SIZE;
		ENSURES( tlvLength >= RADIUS_MIN_TLV_SIZE && \
				 tlvLength <= RADIUS_MAX_TLV_SIZE );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "  Read %s (%d) RADIUS TLV packet, length %d.\n", 
					  getRADIUSSubtypeName( tlvType ), tlvType, tlvLength ));
#ifdef DEBUG_TRACE_RADIUSTLV
		DEBUG_DUMP_STREAM( stream, stell( stream ), tlvLength );
#endif /* DEBUG_TRACE_RADIUSTLV */
		DEBUG_PRINT_END();

		/* Make sure that we've got at least the minimum data amount that's 
		   required in order to continue */
		status = mapValue( tlvType, &tlvMinLength, tlvMinSizeMapTable,
						   FAILSAFE_ARRAYSIZE( tlvMinSizeMapTable, \
											   MAP_TABLE ) );
		if( cryptStatusError( status ) )
			tlvMinLength = RADIUS_MIN_TLV_SIZE;
		if( tlvLength < tlvMinLength )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Too-small RADIUS TLV payload length %d for packet "
					  "subtype %s (%d) should be at least %d bytes", 
					  tlvLength, getRADIUSSubtypeName( tlvType ), tlvType, 
					  tlvMinLength ) );
			}

		/* Process the packet as required */
		switch( tlvType )
			{
			case RADIUS_SUBTYPE_EAPMESSAGE:
				{
				int payloadBytesCopied;

				/* If we're at the start of a new EAP packet inside the TLV 
				   fragmentation, read the header */
				if( eapInfo->eapLength <= 0 )
					{
					int headerBytesRead;

					status = readRADIUSEAP( stream, eapInfo, 
											&headerBytesRead, tlvLength );
					if( cryptStatusError( status ) )
						break;
					tlvLength -= headerBytesRead;
					if( tlvLength <= 0 )
						break;
					}

				/* If we're not expecting any data then there's a problem 
				   with the packet */
				if( data == NULL )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}

				/* Copy out as much payload data as we can */
				status = copyPayloadData( stream, tlvLength, eapInfo, 
										  bufPtr + bytesRead, 
										  dataMaxLength - bytesRead, 
										  &payloadBytesCopied );
				if( cryptStatusError( status ) && status != OK_SPECIAL )
					break;
				bytesRead += payloadBytesCopied;

				/* If we've only read part of the data that's present, 
				   remember where we'll restart from and exit */
				if( status == OK_SPECIAL )
					{
					eapInfo->eapRemainderLength = \
									tlvLength - payloadBytesCopied;
					partialRead = TRUE;
					status = CRYPT_OK;
					break;
					}

				break;
				}

			case RADIUS_SUBTYPE_MESSAGEAUTH:
				/* In theory we should use this to run a MAC over the 
				   received message, but its unclear whether this achieves 
				   anything since all we're doing is using it as untrusted 
				   transport for the TLS negotiation, and in any case it's
				   the long-obsolete HMAC-MD5 (see the comment in 
				   io/eap_wr.c), so for now we just skip it */
				status = sSkip( stream, tlvLength, MAX_INTLENGTH_SHORT );
				break;

			case RADIUS_SUBTYPE_STATE:
				if( tlvLength < min( 1, RADIUS_MIN_TLV_SIZE ) || \
					tlvLength > CRYPT_MAX_HASHSIZE )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				status = sread( stream, eapInfo->radiusStateNonce, 
								tlvLength );
				if( cryptStatusOK( status ) )
					eapInfo->radiusStateNonceSize = tlvLength;
				break;

			case RADIUS_SUBTYPE_VENDORSPECIFIC:
				status = processVendorSpecific( stream, eapInfo, tlvLength );
				break;

			default:
				if( tlvLength > 0 )
					status = sSkip( stream, tlvLength, MAX_INTLENGTH_SHORT );
				else
					status = CRYPT_OK;
				break;
			}
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo, 
					  "Error %s (%d) processing RADIUS TLV packet subtype "
					  "%s (%d), length %d", getStatusName( status ), status,
					  getRADIUSSubtypeName( tlvType ), tlvType, tlvLength ) );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( noPackets >= MAX_RADIUS_TLV_FRAGMENTS )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, errorInfo, 
				  "Encountered more than %d RADIUS TLV entries",
				  noPackets ) );
		}
	*bytesCopied = bytesRead;

	return( partialRead ? OK_SPECIAL : CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read EAP Messages							*
*																			*
****************************************************************************/

/* Read the start of a (possibly fragmented) EAP packet encapsulated inside 
   a RADIUS packet:

	byte		type
	byte		counter		-- Incremented for every req/resp pair
	uint16		length		-- Including type, counter, length
	byte		subtype
  [	byte			flags		-- For EAP-TLS/TTLS/PEAP ]
  [ byte[]			opt_data	-- For EAP-TLS/TTLS/PEAP ]
	byte[]		data

   The counter is actually defined in the spec as an identifier, with the
   recommended generation method being "to start the Identifier at an 
   initial value and increment it for each new Request" so that it functions
   as a counter, however some implementations may not do this, or may start
   the value at a random position, so we explicitly record it rather than
   just starting at 0 and incrementing on each message.

   Since the EAP message can be fragmented across multiple RADIUS TLVs
   inside a RADIUS packet, we can only read the header at this point but 
   have to leave payload processing to the calling code */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readRADIUSEAP( INOUT_PTR STREAM *stream,
						  INOUT_PTR EAP_INFO *eapInfo,
						  OUT_LENGTH_SHORT_Z int *bytesProcessed,
						  IN_BYTE const int radiusEncapsLength )
	{
	BOOLEAN isReqResp = FALSE;
	const int startPos = stell( stream );
	int type, subType = EAP_SUBTYPE_NONE, counter, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );
	assert( isWritePtr( bytesProcessed, sizeof( int ) ) );

	REQUIRES( radiusEncapsLength > 0 && radiusEncapsLength < 0xFF );
	REQUIRES( isShortIntegerRangeNZ( startPos ) );

	/* Clear return value */
	*bytesProcessed = 0;

	/* Read the EAP packet header and optional subtype information */
	type = sgetc( stream );
	counter = sgetc( stream );
	status = length = readUint16( stream );
	if( !cryptStatusError( status ) && \
		( type == EAP_TYPE_REQUEST || type == EAP_TYPE_RESPONSE ) )
		{
		isReqResp = TRUE;
		status = subType = sgetc( stream );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Check that the length is OK.  EAP packets can be fragmented inside 
	   RADIUS TLVs so the EAP length may be greater than the encapsulating 
	   RADIUS length rather than equal to it, however there should be at 
	   least as much EAP data as there is RADIUS data */
	if( length < radiusEncapsLength )
		return( CRYPT_ERROR_BADDATA );
	length -= EAP_HEADER_LENGTH + ( isReqResp ? 1 : 0 );
	if( length < 0 || length > RADIUS_MAX_PACKET_SIZE - EAP_HEADER_LENGTH )
		return( CRYPT_ERROR_BADDATA );

	/* The header data is OK, copy it across to the EAP state info.  We
	   can't just directly read it in as part of the earlier read because 
	   it'll fail a later sanity check of the EAP state if any of the values 
	   were invalid */
	eapInfo->eapType = type;
	eapInfo->eapCtr = counter;
	eapInfo->eapLength = length;
	eapInfo->eapSubtypeRead = subType;

	/* If it's not an EAP Request or Response, we're done */
	if( !isReqResp )
		{
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "    Read %s (%d) EAP packet, length %d, ID %d.\n", 
					  getEAPPacketName( type ), type, length, counter ));
#ifdef DEBUG_TRACE_RADIUSEAP
		DEBUG_DUMP_STREAM( stream, stell( stream ), length );
#endif /* DEBUG_TRACE_RADIUSEAP */
		DEBUG_PRINT_END();
		return( calculateStreamObjectLength( stream, startPos, 
											 bytesProcessed ) );
		}
	DEBUG_PRINT(( "    Read %s (%d) EAP packet, subtype %s (%d), "
				  "length %d, ID %d.\n", getEAPPacketName( type ), type, 
				  getEAPSubtypeName( subType ), subType, length, counter ));

	/* Read any further data */
	switch( eapInfo->eapSubtypeRead )
		{
		case EAP_SUBTYPE_EAP_TLS:
		case EAP_SUBTYPE_EAP_TTLS:
		case EAP_SUBTYPE_PEAP:
			{
			int flags;

			/* Read the EAP-TLS/TTLS/PEAP flags, which tell us what else 
			   might be present before the payload turns up */
			status = flags = sgetc( stream );
			if( cryptStatusError( status ) )
				return( status );
			length--;
			if( flags & EAPTLS_FLAG_HASLENGTH )
				{
				/* There's an explicit EAP-TLS/TTLS/PEAP length field 
				   present just in case the RADIUS and EAP lengths (as well 
				   as the encapsulated TLS lengths) aren't convincing 
				   enough, skip it and continue */
				status = readUint32( stream );
				if( cryptStatusError( status ) )
					return( status );
				length -= UINT32_SIZE;
				}
			if( length < 0 || \
				length > RADIUS_MAX_PACKET_SIZE - EAP_HEADER_LENGTH || \
				!isFlagRangeZ( flags, EAPTLS ) )
				return( CRYPT_ERROR_BADDATA );

			/* If we get a response with no content then this isn't any 
			   normal EAP message but an EAP ACK manufactured by the client
			   in order to allow negotiation to continue */
			if( type == EAP_TYPE_RESPONSE && length == 0 && flags == 0 )
				{
				DEBUG_PRINT(( "    EAP message is an EAP ACK used to allow "
							  "negotiation to continue.\n" ));
				eapInfo->eapFlags |= EAP_FLAG_EAPACK;
				}

			/* Update the EAP state with the checked values, see the comment
			   earlier */
			eapInfo->eapLength = length;
			if( flags & EAPTLS_FLAG_MOREFRAGS )
				eapInfo->eapFlags |= EAP_FLAG_FRAGMENTED;
			else
				eapInfo->eapFlags &= ~EAP_FLAG_FRAGMENTED;
			break;
			}

		default:
			/* If we're the server and we're expecting a wakeup packet from 
			   the client then we need an EAP_TYPE_RESPONSE with subType 
			   EAP_SUBTYPE_IDENTITY */
			if( eapInfo->eapFlags & EAP_FLAG_CLIENTWAKEUP )
				{
				if( type != EAP_TYPE_RESPONSE || \
					subType != EAP_SUBTYPE_IDENTITY )
					return( CRYPT_ERROR_BADDATA );

				break;
				}

			/* Unexpected EAP subtype */
			DEBUG_PRINT(( "    EAP subtype %s (%d) isn't any of EAP-TLS, "
						  "EAP-TTLS, or PEAP", 
						  getEAPSubtypeName( subType ), subType ));
			return( CRYPT_ERROR_BADDATA );

		}
#ifdef DEBUG_TRACE_RADIUSEAP
	DEBUG_DUMP_STREAM( stream, stell( stream ), length );
#endif /* DEBUG_TRACE_RADIUSEAP */
	return( calculateStreamObjectLength( stream, startPos, 
										 bytesProcessed ) );
	}

/****************************************************************************
*																			*
*							EAP Access Functions							*
*																			*
****************************************************************************/

/* Read data from an EAP stream.  Because of RADIUS' crazy fragementation we
   have to be able to handle multiple layers of encapsulation, all with 
   their own fragementation requirements.  A read of a typical RADIUS packet
   that illustrates each of the operation types might be:

   0 = readRADIUSMessage().

			|<-------------- Returned by readRADIUSMessage() -------------->|
	+-------+---+-----------+---+-----------+---+-----------+---+-----------+
	|  Hdr	|TL |	  V		|TL	|	  V		|TL	|	  V		|TL	|	  V		|
	+-------+---+-----------+---+-----------+---+-----------+---+-----------+
				|<- 1 ->|<---- 2 ---->|<-------- 3 -------->|	|<--- 4 --->|

   1 = processRADIUSTLVs(), copyPayloadData() partial in processRTLVs(), return.
   2 = copyPayloadData().
	   processRADIUSTLVs(), copyPayloadData() partial in processRTLVs(), return.
   3 = copyPayloadData().
	   processRADIUSTLVs(), copyPayloadData() in processRTLVs(), return.
   4 = processRADIUSTLVs(), copyPayloadData() in processRTLVs(), return */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readFunction( INOUT_PTR STREAM *stream, 
						 OUT_BUFFER( maxLength, *length ) void *buffer, 
						 IN_DATALENGTH const int maxLength, 
						 OUT_DATALENGTH_Z int *length )
	{
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	EAP_INFO *eapInfo;
	STREAM radiusStream;
	BYTE *bufPtr = buffer;
	BOOLEAN continueRead = FALSE;
	LOOP_INDEX noPackets;
	int bufSize = maxLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( buffer, maxLength ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStreamEAP( netStream ) );
	REQUIRES( isBufsizeRangeNZ( maxLength ) );

	/* Clear return value */
	*length = 0;

	eapInfo = ( EAP_INFO * ) netStream->subTypeInfo;

	LOOP_SMALL( noPackets = 0, 
				noPackets < MAX_RADIUS_EAP_FRAGMENTS && \
					( continueRead || bufSize > 0 ), 
				noPackets++ )
		{
		int bytesCopied;

		ENSURES( LOOP_INVARIANT_SMALL( noPackets, 0, 
									   MAX_RADIUS_EAP_FRAGMENTS - 1 ) );

		continueRead = FALSE;

		/* Read the other side's RADIUS-encapsulated EAP message.  This is
		   an Access-Request at the server, an Access-Challenge/Allow/Deny
		   at the client */
		if( eapInfo->eapState == EAP_STATE_NONE )
			{
			const BOOLEAN isRequest = \
						TEST_FLAG( netStream->nFlags, \
								   STREAM_NFLAG_ISSERVER ) ? TRUE : FALSE;

			status = readRADIUSMessage( stream, eapInfo, isRequest );
			if( cryptStatusError( status ) )
				{
				/* If no data was available to read, we're done */
				if( status == OK_SPECIAL )
					break;

				/* Now we come into the inevitable problems that occur with
				   the use of an unreliable transport protocol, if a RADIUS
				   packet read fails then this can be due to a normal lost
				   UDP packet rather than an abnormal server outage or 
				   similar fatal error condition.  To deal with this, if we
				   get a timeout error (meaning that we couldn't read the 
				   UDP packet that we were expecting), we resend the last
				   UDP packet in the hope of triggering a response from the
				   peer */
				if( status == CRYPT_ERROR_TIMEOUT && \
					netStream->writeBufEnd > 0 )
					{
					int resendStatus;

					resendStatus = resendLastMessage( netStream );
					if( resendStatus == OK_SPECIAL )
						continue;
					}
				return( status );
				}
			if( stream->bufEnd <= 0 )
				{
				/* The entire message was processed during the read, 
				   typically because it's something like an Access-Reject.  
				   If we've already read some data, in other words the 
				   buffer is no longer empty with bufSize == maxLength, 
				   return that */
				if( bufSize < maxLength )
					break;

				/* The peer has ended the exchange, tell the caller why */
				retExt( CRYPT_ERROR_PERMISSION,
						( CRYPT_ERROR_PERMISSION, NETSTREAM_ERRINFO, 
						  "RADIUS exchange was rejected with RADIUS status "
						  "%s (%d)", 
						  getRADIUSPacketName( eapInfo->radiusType ), 
						  eapInfo->radiusType ) );
				}

			/* Move on to the next state */
			eapInfo->eapState = EAP_STATE_PROCESSMESSAGE;
			}

		/* Process a RADIUS message */
		if( eapInfo->eapState == EAP_STATE_PROCESSMESSAGE || \
			eapInfo->eapState == EAP_STATE_CONTINUEREAD )
			{
			BOOLEAN isPartialRead = FALSE;

			sMemConnect( &radiusStream, 
						 stream->buffer + stream->bufPos, 
						 stream->bufEnd - stream->bufPos );
			if( eapInfo->eapState == EAP_STATE_PROCESSMESSAGE )
				{
				/* Process the EAP message within the RADIUS message */
				status = processRADIUSTLVs( &radiusStream, eapInfo, 
											( bufSize > 0 ) ? bufPtr : NULL, 
											bufSize, &bytesCopied, 
											NETSTREAM_ERRINFO );
				}
			else
				{
				/* We're in the middle of an EAP message read from a 
				   previous call to processRADIUSMessage(), get the 
				   remaining data */
				status = copyPayloadData( &radiusStream,
										  eapInfo->eapRemainderLength,
										  eapInfo, bufPtr, bufSize, 
										  &bytesCopied );
				if( cryptStatusOK( status ) )
					{
					/* We've satisfied the read requirements from the data 
					   that's available but there are more TLVs present in 
					   the current message (if all of the data had been 
					   consumed we'd have got an OK_SPECIAL status), make 
					   sure that we process them before we exit */
					continueRead = TRUE;
					}
				}
			if( status == OK_SPECIAL )
				{
				isPartialRead = TRUE;
				status = CRYPT_OK;
				}
			if( cryptStatusOK( status ) )
				{
				status = updateEapState( stream, eapInfo, 
										 stell( &radiusStream ), 
										 isPartialRead );
				}
			sMemDisconnect( &radiusStream );
			if( cryptStatusError( status ) )
				return( status );
			bufPtr += bytesCopied;
			bufSize -= bytesCopied;
			}

		/* Send an EAP ACK to continue the exchange after receiving a 
		   fragmented packet */
		if( eapInfo->eapState == EAP_STATE_SENDACK )
			{
			status = sendEAPACK( stream, eapInfo );
			if( cryptStatusError( status ) )
				return( status );

			/* Move on to the next state */
			eapInfo->eapState = EAP_STATE_NONE;

			/* If there are no more fragments to follow in the current EAP 
			   message, we're done */
			if( !( eapInfo->eapFlags & EAP_FLAG_FRAGMENTED ) )
				break;
			}

		/* If the negotiation has completed, we're done */
		if( eapInfo->eapState == EAP_STATE_FINISHED )
			break;

		/* If the negotiation was a dummy read like an EAP ACK, we're 
		   similarly finished, but only for the current read so we reset the 
		   EAP state to allow further reads before we exit */
		if( eapInfo->eapState == EAP_STATE_DUMMYREAD )
			{
			eapInfo->eapState = EAP_STATE_NONE;
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( noPackets >= MAX_RADIUS_EAP_FRAGMENTS )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, NETSTREAM_ERRINFO, 
				  "Encountered more than %d RADIUS packets to comunicate "
				  "one EAP packet", noPackets ) );
		}
	*length = maxLength - bufSize;

	ENSURES( sanityCheckNetStreamEAP( netStream ) );

	/* Now things get a bit ugly.  Not quite as ugly as the server silently 
	   dropping requests with incorrect passwords, but still bad from a 
	   security point of view: In the case of an incorrect user name, the 
	   server sends the response to the tunnelled request unprotected, 
	   outside the secure tunnel.  To deal with this, if we get an empty 
	   response with RADIUS type Access-Reject, we turn it into a network-
	   level error (which will be seen by the higher-level code) indicating 
	   that the authentication failed.  This makes us vulnerable to DoS 
	   forgery attacks, but since the server has chosen to send the response 
	   outside the tunnel there's not much that we can do */
	if( eapInfo->radiusType == RADIUS_TYPE_REJECT && *length == 0 )
		{
		/* The peer has ended the exchange, tell the caller why */
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, NETSTREAM_ERRINFO, 
				  "Server responded with RADIUS Access-Reject due to "
				  "invalid user name or password" ) );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int getMetadataFunction( INOUT_PTR STREAM *stream, 
								OUT_BUFFER_OPT( maxLength, *length ) \
									void *buffer, 
								IN_LENGTH_SHORT_Z const int maxLength, 
								OUT_LENGTH_BOUNDED_SHORT_Z( maxLength ) \
									int *length )
	{
	const NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	const EAP_INFO *eapInfo;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( buffer == NULL && maxLength == 0 ) || \
			isReadPtrDynamic( buffer, maxLength ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStreamEAP( netStream ) );
	REQUIRES( ( buffer == NULL && maxLength == 0 ) || \
			  ( buffer != NULL && isShortIntegerRangeNZ( maxLength ) ) );

	eapInfo = ( EAP_INFO * ) netStream->subTypeInfo;
	if( eapInfo->extraDataLength <= 0 )
		{
		*length = 0;
		return( CRYPT_ERROR_NOTFOUND );
		}
	return( attributeCopyParams( buffer, maxLength, length,
								 eapInfo->extraData, 
								 eapInfo->extraDataLength ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerEAPread( INOUT_PTR NET_STREAM_INFO *netStream )
	{
	assert( isWritePtr( netStream, sizeof( NET_STREAM_INFO ) ) );

	/* Set the access method pointers */
	FNPTR_SET( netStream->getMetadataFunctionOpt, getMetadataFunction );
	FNPTR_SET( netStream->readFunction, readFunction );
	}
#endif /* USE_EAP */
