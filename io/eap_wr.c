/****************************************************************************
*																			*
*				cryptlib Session EAP-TLS/TTLS/PEAP Write Routines			*
*						Copyright Peter Gutmann 2016-2021 					*
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

/* Forward declarations for interwoven EAP/RADIUS functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int writeRADIUSEAP( INOUT_PTR STREAM *stream,
						   INOUT_PTR EAP_INFO *eapInfo,
						   IN_PTR const EAP_PARAMS *eapParams,
						   IN_BUFFER( dataLength ) const void *data,
						   IN_LENGTH_SHORT const int dataLength );

/****************************************************************************
*																			*
*								Write RADIUS Messages						*
*																			*
****************************************************************************/

/* Write a RADIUS TLV packet:

	byte		type
	byte		length		-- Including type and length
	byte[]		data

   This can write a RADIUS packet in either one or two parts, there's a 
   single part if it's a RADIUS packet (extraData == NULL) and two parts if 
   it's an EAP packet encapsulated inside a RADIUS packet 
   (extraData != NULL), with the first part being the EAP-in-RADIUS 
   encapsulation and the second being the EAP payload */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeRADIUS( INOUT_PTR STREAM *stream,
						IN_ENUM( RADIUS_TYPE ) const RADIUS_SUBTYPE_TYPE type,
						IN_BUFFER( length ) const BYTE *data,
						IN_LENGTH_SHORT const int length,
						IN_BUFFER_OPT( extraLength ) const BYTE *extraData,
						IN_LENGTH_SHORT_Z const int extraLength )
	{
	const BYTE *currDataPtr = data;
	int currDataLen = length, totalLength = length + extraLength;
	int subpacketLength, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( data, length ) );
	assert( ( extraData == NULL && extraLength == 0 ) || \
			isReadPtr( extraData, extraLength ) );

	REQUIRES( isEnumRange( type, RADIUS_SUBTYPE ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( ( extraData == NULL && extraLength == 0 ) || \
			  ( extraData != NULL && isShortIntegerRangeNZ( extraLength ) ) );
	REQUIRES( isShortIntegerRangeNZ( totalLength ) );

	/* Write a RADIUS TLV value as one or more TLV packets.  This is 
	   complicated by the fact that the payload may be split across two lots
	   of data if we're encapsulating EAP inside RADIUS, so we have to 
	   account for running out of data in the middle of the write and 
	   switch buffers.  The data layout is:

			|<--- packetLength ---->|<--- packetLength ---->|
			+-------------------+---------------------------+
			|		data		|		extraData			|
		+---+-------------------+---------------------------+
		|hdr|						|							-- sputc() header
		+---+-------------------+	|
			|	currBytesToW	|	|							-- swrite() main buffer
			+-------------------+---+							-- Switch to alt buffer
								|rB	|							-- swrite() alt buffer
								+---+
								+---+
								|hdr|							-- sputc() header
								+---+-----------------------+
									|	currBytesToW		|	-- swrite() alt->main buffer
									+-----------------------+ */
	LOOP_MED_REV_INITCHECK( subpacketLength = totalLength, 
							subpacketLength > 0 )
		{
		/* Get the amount of data to write.  First we get the overall amount
		   of data that we can write in the current TLV, then we get the
		   (possible) subset of that that's contained in the current 
		   buffer */
		const int packetLength = min( subpacketLength, RADIUS_MAX_TLV_SIZE );
		const int currBytesToWrite = min( packetLength, currDataLen );

		ENSURES( LOOP_INVARIANT_MED_REV_XXX( subpacketLength, 1, totalLength ) );

		ENSURES( isShortIntegerRangeNZ( currBytesToWrite ) );

		/* Write as much of the payload data as we can from the current 
		   buffer */
		sputc( stream, type );
		sputc( stream, RADIUS_TLV_HEADER_SIZE + packetLength );
		status = swrite( stream, currDataPtr, currBytesToWrite );
		if( cryptStatusError( status ) )
			return( status );
		currDataPtr += currBytesToWrite;
		currDataLen -= currBytesToWrite;

		/* If we've exhausted the data in the current buffer, switch to the
		   alternate buffer and continue the write if necessary */
		if( currDataLen <= 0 )
			{
			currDataPtr = extraData;
			currDataLen = extraLength;
			if( currBytesToWrite < packetLength )
				{
				const int remainderBytes = packetLength - currBytesToWrite;

				REQUIRES( currDataPtr != NULL );
				ENSURES( isShortIntegerRangeNZ( remainderBytes ) );

				/* There's more data to be written, complete the current TLV 
				   packet using the alternate buffer */
				status = swrite( stream, currDataPtr, remainderBytes );
				if( cryptStatusError( status ) )
					return( status );
				currDataPtr += remainderBytes;
				currDataLen -= remainderBytes;
				}
			}
		subpacketLength -= packetLength;
		}
	ENSURES( LOOP_BOUND_MED_REV_OK );

	return( CRYPT_OK );
	}

/* Write a RADIUS packet:

	byte		type
	byte		counter		-- Incremented for every req/resp pair
	uint16		length		-- Including type, counter, length
	byte[16]	nonce		-- Updated for every req/resp pair
	byte[]		attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int beginRADIUSMessage( INOUT_PTR STREAM *stream,
							   INOUT_PTR EAP_INFO *eapInfo,
							   IN_ENUM( RADIUS_TYPE ) \
									const RADIUS_TYPE radiusType,
							   IN_BOOL const BOOLEAN isEAPRequest )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );

	REQUIRES( isEnumRange( radiusType, RADIUS_TYPE ) );
	REQUIRES( isBooleanValue( isEAPRequest ) );

	/* If it's a request, generate fresh counter values and a fresh nonce.
	   Because of the strange way in which EAP-over-RADIUS works, we can
	   have things like a RADIUS request containing an EAP response, so
	   there are distinct flags for RADIUS and EAP requests */
	if( radiusType == RADIUS_TYPE_REQUEST )
		{
		eapInfo->radiusCtr = ( eapInfo->radiusCtr + 1 ) & 0xFF;
		setMessageData( &msgData, eapInfo->radiusNonce, RADIUS_NONCE_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( isEAPRequest )
		eapInfo->eapCtr = ( eapInfo->eapCtr + 1 ) & 0xFF;

	/* Write the RADIUS packet, with a placeholder for the length */
	sputc( stream, radiusType );
	sputc( stream, eapInfo->radiusCtr );
	if( radiusType != RADIUS_TYPE_REQUEST )
		{
		/* It's not a request, update the counter value for the next packet 
		   that we'll read */
		eapInfo->radiusCtr = ( eapInfo->radiusCtr + 1 ) & 0xFF;
		}
	writeUint16( stream, 0 );	/* Placeholder */
	return( swrite( stream, eapInfo->radiusNonce, RADIUS_NONCE_SIZE ) );
	}

/* Wrap up and send a RADIUS message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completeRADIUSMessage( INOUT_PTR STREAM *stream )
	{
	const int length = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isShortIntegerRangeNZ( length ) );

	/* Insert the RADIUS packet length into the packet data */
	sseek( stream, RADIUS_LENGTH_OFFSET );
	status = writeUint16( stream, length );
	if( cryptStatusError( status ) )
		return( status );
	return( sseek( stream, length ) );
	}

/* Write a RADIUS message containing an EAP payload:

	RADIUS type = Access-Request / Access-Challenge
	RADIUS ctr = xxx
	RADIUS length = nnn
	RADIUS authenticator = [ ... ]
	TLV type = Username
		length = nnn
		data = [ ... ]
	TLV type = EAP-Message
		length = nnn
		data = \
			EAP type = type
			EAP ctr = yyy
			EAP len = nnn
			EAP subtype = subType
			data = [ ... ] 
  [	TLV type = State
		length = nnn
		data = [ ... ] ]
	TLV type = Message-Authenticator
		length = 18
		data = [ ... ] */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int writeRADIUSMessage( INOUT_PTR STREAM *stream,
						INOUT_PTR EAP_INFO *eapInfo,
						const EAP_PARAMS *eapParams,
						IN_BUFFER( dataLength ) const void *data,
						IN_LENGTH_SHORT const int dataLength )
	{
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	STM_TRANSPORTWRITE_FUNCTION transportWriteFunction;
	STREAM radiusStream;
	BYTE clientAddr[ 16 + 8 ];
	void *macValue DUMMY_INIT_PTR;
	RADIUS_TYPE radiusType;
	BOOLEAN isServer = FALSE;
	int messageAuthPos DUMMY_INIT, clientAddrLen DUMMY_INIT, dummy, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );
	assert( isReadPtr( eapParams, sizeof( EAP_PARAMS ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStream( netStream ) );
	REQUIRES( isShortIntegerRangeNZ( dataLength ) );

	/* If we're the server then we have to perform special-case processing 
	   for the authenticator value */
	if( TEST_FLAG( netStream->nFlags, STREAM_NFLAG_ISSERVER ) )
		isServer = TRUE;

	/* If we're the client, get our IP address, mandated by the spec but not 
	   actually needed for RADIUS requests.  Most servers ignore this since 
	   it serves no purpose when RADIUS is purely a tunnelling mechanism for 
	   EAP requests, but NPS returns an internal error if it's missing.  
	   However it also ignores it (beyond returning an error if it's not 
	   present) so if there's a problem fetching it we just specify the IPv4 
	   loopback address which it seems perfectly happy with */
	if( !isServer )
		{
		status = sioctlGet( stream, STREAM_IOCTL_GETCLIENTADDRLEN,
							&clientAddrLen, sizeof( int ) );
		if( cryptStatusOK( status ) )
			{
			ENSURES( clientAddrLen > 0 && clientAddrLen <= 16 );

			status = sioctlGet( stream, STREAM_IOCTL_GETCLIENTADDR,
								clientAddr, 16 );
			}
		if( cryptStatusError( status ) )
			{
			/* We couldn't get the client address, use the IPv4 loopback 
			   address */
			memcpy( clientAddr, "\x7F\x00\x00\x01", 4 );
			clientAddrLen = 4;
			}
		}

	/* Set up the function pointers.  We have to do this after the netStream
	   check otherwise we'd potentially be dereferencing a NULL pointer */
	transportWriteFunction = ( STM_TRANSPORTWRITE_FUNCTION ) \
							 FNPTR_GET( netStream->transportWriteFunction );
	REQUIRES( transportWriteFunction != NULL );

	sMemOpen( &radiusStream, netStream->writeBuffer, 
			  netStream->writeBufSize );

	/* Check what sort of RADIUS encpsulation we need to use */
	if( isServer )
		{
		if( dataLength == RADIUS_DATA_ACCESSACCEPT_LEN && \
			!memcmp( data, RADIUS_DATA_ACCESSACCEPT, \
					 RADIUS_DATA_ACCESSACCEPT_LEN ) )
			radiusType = RADIUS_TYPE_ACCEPT;
		else
			radiusType = RADIUS_TYPE_CHALLENGE;
		}
	else
		radiusType = RADIUS_TYPE_REQUEST;

	/* Begin the RADIUS message */
	status = beginRADIUSMessage( &radiusStream, eapInfo, radiusType, 
								 ( eapParams->type == EAP_TYPE_REQUEST ) ? \
								   TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &radiusStream );
		return( status );
		}

	/* Write the RADIUS TLVs, including the EAP payload.  PEAP sends the 
	   identity inside the TLS tunnel so we give our identity at the RADIUS 
	   level as "anonymous" which is required by some usage documents.  How 
	   the server generates a Message-Authenticator without any identity to 
	   bind it to is a mystery, but RFC 2865 suggests that "The source IP 
	   address of the Access-Request packet MUST be used to select the 
	   shared secret", so presumably that's recorded somewhere as it passes 
	   through RADIUS proxies and tunnels and whatnot.
		   
	   Older versions of Windows NPS don't like the use of an anonymous
	   identity unless a setting called Identity Privacy is enabled, see
	   https://learn.microsoft.com/en-us/archive/blogs/wsnetdoc/peap-identity-privacy-support-in-windows-7-and-windows-server-2008-r2
	   https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff919512(v=ws.10) 
		   
	   Server 2019 updated with all patches seems to handle it OK */
	if( !isServer )
		{
#ifdef USE_ANONYMOUS_ID
		if( netStream->subProtocol == CRYPT_SUBPROTOCOL_PEAP )
			{
			status = writeRADIUS( &radiusStream, RADIUS_SUBTYPE_USERNAME, 
								  "anonymous", 9, NULL, 0 );
			}
		else
#endif /* USE_ANONYMOUS_ID */
			{
			status = writeRADIUS( &radiusStream, RADIUS_SUBTYPE_USERNAME, 
								  eapInfo->userName, 
								  eapInfo->userNameLength, NULL, 0 );
			}
		if( cryptStatusOK( status ) )
			{
			/* NAS-IP-Address, see the comment above */
			status = writeRADIUS( &radiusStream, ( clientAddrLen == 4 ) ? \
									RADIUS_SUBTYPE_IPADDRESS : \
									RADIUS_SUBTYPE_NAS_IPV6_ADDR, 
								  clientAddr, clientAddrLen, NULL, 0 );
			}
		}
#if 0	/* Random unnecessary stuff copied from what eapol_test sends in 
		   order to exactly duplicate its messages */
	if( cryptStatusOK( status ) )
		{
		/* Calling-Station-ID, should be a phone number but eapol_test 
		   sends this, whatever it is */
		status = writeRADIUS( &radiusStream, 
							  RADIUS_SUBTYPE_CALLING_STATIONID, 
							  "02-00-00-00-00-01", 17, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		/* Framed-MTU, eapol_test sends 1400 */
		status = writeRADIUS( &radiusStream, RADIUS_SUBTYPE_FRAMED_MTU, 
							  "\x00\x00\x05\x78", 4, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		/* NAS-Port-Type, 15 = Ethernet, eapol_test sends 19 = WiFi */
		status = writeRADIUS( &radiusStream, RADIUS_SUBTYPE_PORTTYPE, 
							  "\x00\x00\x00\x13", 4, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		/* Service-Type, something else that eapol_test sends, 2 = Framed */
		status = writeRADIUS( &radiusStream, RADIUS_SUBTYPE_SERVICETYPE, 
							  "\x00\x00\x00\x02", 4, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		/* Connect-Info, something else that eapol_test sends, 2 = Framed */
		status = writeRADIUS( &radiusStream, RADIUS_SUBTYPE_CONNECTINFO, 
							  "CONNECT 11Mbps 802.11b", 22, NULL, 0 );
		}
#endif /* 0 */
	if( cryptStatusOK( status ) )
		{
		status = writeRADIUSEAP( &radiusStream, eapInfo, eapParams,
								 data, dataLength );
		}
	if( cryptStatusOK( status ) && eapInfo->radiusStateNonceSize > 0 )
		{
		status = writeRADIUS( &radiusStream, RADIUS_SUBTYPE_STATE, 
							  eapInfo->radiusStateNonce, 
							  eapInfo->radiusStateNonceSize, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		/* Remember the Message Authenticator position and write an empty
		   TLV that'll be filled later with the authenticator */
		messageAuthPos = stell( &radiusStream ) + RADIUS_TLV_HEADER_SIZE;
		status = writeRADIUS( &radiusStream, RADIUS_SUBTYPE_MESSAGEAUTH, 
							  "\x00\x00\x00\x00\x00\x00\x00\x00"
							  "\x00\x00\x00\x00\x00\x00\x00\x00", 16, 
							  NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		status = completeRADIUSMessage( &radiusStream );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &radiusStream );
		return( status );
		}
	netStream->writeBufEnd = stell( &radiusStream );
	ENSURES( isBufsizeRangeNZ( netStream->writeBufEnd ) );

	/* Calculate the Message Authenticator value over the entire message */
	status = sMemGetDataBlockAbs( &radiusStream, messageAuthPos, 
								  &macValue, 16 );
	if( cryptStatusOK( status ) )
		{
		status = radiusMD5MacBuffer( macValue, 16, netStream->writeBuffer, 
									 netStream->writeBufEnd, 
									 eapInfo->password, 
									 eapInfo->passwordLength );
		}
	sMemDisconnect( &radiusStream );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're the server, add yet another authenticator, this time an MD5
	   hash over the packet.  Technically this is, from RFC 2865 section 3:

		MD5( Code + ID + Length + RequestAuth + Attributes + Secret )

	   which translates to:

		MD5( type || ctr || length || client_nonce || attributes || \
			 user_password )

	   which is just the entire packet with the client_nonce at the position
	   where we're going to add our authenticator, and the RADIUS secret
	   hashed onto the end of the packet data in a totally insecure means
	   of authenticating a packet.

	   The write position in the buffer is given by:

		byte		type
		byte		counter
		uint16		length
		byte[16]	nonce, offset = 4 */
	if( isServer )
		{
		status = radiusMD5HashBuffer( netStream->writeBuffer + 4, 16, 
									  netStream->writeBuffer, 
									  netStream->writeBufEnd, 
									  eapInfo->password, 
									  eapInfo->passwordLength );
		if( cryptStatusError( status ) )
			return( status );
		}

	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Wrote %s (%d) RADIUS packet, length %d, packet ID %d "
				  "containing\n", 
				  getRADIUSPacketName( netStream->writeBuffer[ 0 ] ), 
				  netStream->writeBuffer[ 0 ], 
				  netStream->writeBufEnd - RADIUS_HEADER_SIZE, 
				  netStream->writeBuffer[ 1 ] ));
	DEBUG_PRINT_COND( ( dataLength != RADIUS_DATA_EAPACK_LEN || \
						memcmp( data, RADIUS_DATA_EAPACK, \
								RADIUS_DATA_EAPACK_LEN ) ) && \
					  ( dataLength != RADIUS_DATA_ACCESSACCEPT_LEN || \
						memcmp( data, RADIUS_DATA_ACCESSACCEPT, \
								RADIUS_DATA_ACCESSACCEPT_LEN ) ),
					  ( "  encapsulated EAP packet %s (%d), subtype %s (%d).\n", 
						getEAPPacketName( eapParams->type ), eapParams->type, 
						getEAPSubtypeName( eapParams->subType ), 
						eapParams->subType ));
	DEBUG_PRINT_COND( dataLength == RADIUS_DATA_EAPACK_LEN && \
					  !memcmp( data, RADIUS_DATA_EAPACK, \
							   RADIUS_DATA_EAPACK_LEN ), 
					  ( "  EAP ACK message.\n" ));
	DEBUG_PRINT_COND( dataLength == RADIUS_DATA_ACCESSACCEPT_LEN && \
					  !memcmp( data, RADIUS_DATA_ACCESSACCEPT, \
							   RADIUS_DATA_ACCESSACCEPT_LEN ), 
					  ( "  RADIUS Access-Accept message.\n" ));

#ifdef DEBUG_TRACE_RADIUS
	DEBUG_DUMP_DATA( netStream->writeBuffer + RADIUS_HEADER_SIZE, 
					 netStream->writeBufEnd - RADIUS_HEADER_SIZE );
#endif /* DEBUG_TRACE_RADIUS */
	DEBUG_PRINT_END();

	/* Send the data over the network.  This leaves the data in the write 
	   buffer in case it needs to be resent to deal with UDP packet loss, 
	   see the discussion in readFunction() in eap_rd.c for details */
	return( transportWriteFunction( netStream, netStream->writeBuffer, 
									netStream->writeBufEnd, &dummy, 
									TRANSPORT_FLAG_FLUSH ) );
	}

/* Resend the last RADIUS message, used to deal with packet loss due to the 
   use of unreliable UDP transport */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int resendLastMessage( NET_STREAM_INFO *netStream )
	{
	STM_TRANSPORTWRITE_FUNCTION transportWriteFunction;
	int dummy;

	assert( isWritePtr( netStream, sizeof( NET_STREAM_INFO ) ) );

	REQUIRES( sanityCheckNetStream( netStream ) );

	/* Set up the function pointers.  We have to do this after the netStream
	   check otherwise we'd potentially be dereferencing a NULL pointer */
	transportWriteFunction = ( STM_TRANSPORTWRITE_FUNCTION ) \
							 FNPTR_GET( netStream->transportWriteFunction );
	REQUIRES( transportWriteFunction != NULL );

	return( transportWriteFunction( netStream, netStream->writeBuffer, 
									netStream->writeBufEnd, &dummy, 
									TRANSPORT_FLAG_FLUSH ) );
	}

/****************************************************************************
*																			*
*								Write EAP Messages							*
*																			*
****************************************************************************/

/* Write an EAP packet encapsulated inside a RADIUS packet:

	byte		type
	byte		counter		-- Incremented for every req/resp pair
	uint16		length		-- Including type, counter, length
	byte		subtype
  [	byte			flags		-- For EAP-TLS/TTLS/PEAP ]
	byte[]		data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int writeRADIUSEAP( INOUT_PTR STREAM *stream,
						   INOUT_PTR EAP_INFO *eapInfo,
						   IN_PTR const EAP_PARAMS *eapParams,
						   IN_BUFFER( dataLength ) const void *data,
						   IN_LENGTH_SHORT const int dataLength )
	{
	STREAM headerStream;
	const BOOLEAN hasParams = \
					( eapParams->paramOpt != CRYPT_UNUSED ) ? TRUE : FALSE;
	BOOLEAN hasSubtype = TRUE;
	BYTE headerBuffer[ 16 + 8 ];
	const void *payloadPtr = data;
	int payloadLength = dataLength, headerLength DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );
	assert( isReadPtr( eapParams, sizeof( EAP_PARAMS ) ) );

	REQUIRES( isShortIntegerRangeNZ( dataLength ) );

	/* Some EAP messages are signalling messages for which there's no, or 
	   special-case, data.  If we're sending one of these then we convert 
	   the magic identifier for the special-case message into the actual 
	   data that gets sent */
	if( dataLength == RADIUS_DATA_CHALLENGE_LEN && \
		!memcmp( data, RADIUS_DATA_CHALLENGE, 
				 RADIUS_DATA_CHALLENGE_LEN ) ) 
		{
		payloadPtr = NULL;
		payloadLength = 0;
		}
	if( dataLength == RADIUS_DATA_ACCESSACCEPT_LEN && \
		!memcmp( data, RADIUS_DATA_ACCESSACCEPT, 
				 RADIUS_DATA_ACCESSACCEPT_LEN ) )
		{
		payloadPtr = NULL;
		payloadLength = 0;
		hasSubtype = FALSE;
		}
	if( dataLength == RADIUS_DATA_EAPACK_LEN && \
		!memcmp( data, RADIUS_DATA_EAPACK, RADIUS_DATA_EAPACK_LEN ) )
		{
		payloadPtr = "\x0";
		payloadLength = 1;
		}

	/* Write the EAP packet header */
	sMemOpen( &headerStream, headerBuffer, 16 );
	sputc( &headerStream, eapParams->type );
	sputc( &headerStream, eapInfo->eapCtr );
	status = writeUint16( &headerStream, 
						  EAP_HEADER_LENGTH + \
							( hasSubtype ? 1 : 0 ) + \
							( hasParams ? 1 : 0 ) + \
							payloadLength );
	if( cryptStatusOK( status ) && hasSubtype )
		status = sputc( &headerStream, eapParams->subType );
	if( cryptStatusOK( status ) && hasParams )
		status = sputc( &headerStream, eapParams->paramOpt );
	if( cryptStatusOK( status ) )
		headerLength = stell( &headerStream );
	if( cryptStatusError( status ) )
		return( status );
	sMemDisconnect( &headerStream );
	ENSURES( isShortIntegerRangeNZ( headerLength ) );

	/* Write the EAP packet encapsulated inside a RADIUS EAP-Message */
	return( writeRADIUS( stream, RADIUS_SUBTYPE_EAPMESSAGE, headerBuffer, 
						 headerLength, payloadPtr, payloadLength ) );
	}

/* Send special-case messages: An EAP ACK to allow the EAP exchange to 
   continue, and a RADIUS Access-Accept */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sendEAPACK( INOUT_PTR STREAM *stream, 
				INOUT_PTR EAP_INFO *eapInfo )
	{
	EAP_PARAMS eapParams;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );

	setEAPParams( &eapParams, EAP_TYPE_RESPONSE, eapInfo->eapSubtypeWrite );
	return( writeRADIUSMessage( stream, eapInfo, &eapParams, 
								RADIUS_DATA_EAPACK, 
								RADIUS_DATA_EAPACK_LEN ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sendAccessAccept( INOUT_PTR STREAM *stream, 
					  INOUT_PTR EAP_INFO *eapInfo )
	{
	EAP_PARAMS eapParams;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );

	setEAPParams( &eapParams, EAP_TYPE_SUCCESS, eapInfo->eapSubtypeWrite );
	return( writeRADIUSMessage( stream, eapInfo, &eapParams, 
								RADIUS_DATA_ACCESSACCEPT, 
								RADIUS_DATA_ACCESSACCEPT_LEN ) );
	}

/****************************************************************************
*																			*
*							EAP Access Functions							*
*																			*
****************************************************************************/

/* Write data to an EAP stream */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writeFunction( INOUT_PTR STREAM *stream, 
						  IN_BUFFER( maxLength ) const void *buffer, 
						  IN_DATALENGTH const int maxLength,
						  OUT_DATALENGTH_Z int *length )
	{
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	EAP_INFO *eapInfo;
	EAP_PARAMS eapParams;
	const BOOLEAN isServer = \
			TEST_FLAG( netStream->nFlags, STREAM_NFLAG_ISSERVER ) ? \
			TRUE : FALSE;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( buffer, maxLength ) );
	assert( isWritePtr( length, sizeof( int ) ) );
	
	REQUIRES( netStream != NULL && sanityCheckNetStreamEAP( netStream ) );
	REQUIRES( isBufsizeRangeNZ( maxLength ) );

	/* Clear return value */
	*length = 0;

	eapInfo = ( EAP_INFO * ) netStream->subTypeInfo;

	/* In some cases the caller may need to send a RADIUS or EAP-level 
	   message rather than an EAP-TLS/TTLS/PEAP level message (because the 
	   RFC says so).  Since we're supposed to be tunelling over EAP as a 
	   transport layer there's no way to directly interact with the EAP 
	   layer, however to accommodate the RFC requirements we recognise 
	   various special-case data values to indicate the use of signalling
	   messages to the peer */
	if( maxLength == RADIUS_DATA_EAPACK_LEN && \
		!memcmp( buffer, RADIUS_DATA_EAPACK, RADIUS_DATA_EAPACK_LEN ) )
		return( sendEAPACK( stream, eapInfo ) );
	if( maxLength == RADIUS_DATA_ACCESSACCEPT_LEN && \
		!memcmp( buffer, RADIUS_DATA_ACCESSACCEPT, 
				 RADIUS_DATA_ACCESSACCEPT_LEN ) )
		return( sendAccessAccept( stream, eapInfo ) );

	/* Write the data as an EAP-TLS/TTLS/PEAP message.  Because this is EAP,
	   the client requests are EAP Responses and the server responses are
	   EAP Requests */
	setEAPParamsExt( &eapParams, isServer ? EAP_TYPE_REQUEST : \
											EAP_TYPE_RESPONSE, 
					 eapInfo->eapSubtypeWrite, EAP_FLAG_NONE );
	status = writeRADIUSMessage( stream, eapInfo, &eapParams,
								 buffer, maxLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Since transport is over UDP, writes are all-or-nothing so if the 
	   write suceeds then all of the data has been written */
	*length = maxLength;

	ENSURES( sanityCheckNetStreamEAP( netStream ) );

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerEAPwrite( INOUT_PTR NET_STREAM_INFO *netStream )
	{
	/* Set the remaining access method pointers */
	FNPTR_SET( netStream->writeFunction, writeFunction );
	}
#endif /* USE_EAP */
