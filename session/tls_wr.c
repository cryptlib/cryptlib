/****************************************************************************
*																			*
*						cryptlib TLS Session Write Routines					*
*						Copyright Peter Gutmann 1998-2022					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "tls.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/****************************************************************************
*																			*
*							Sub-packet Management Routines					*
*																			*
****************************************************************************/

/* Open and complete a TLS packet:

	 offset										packetEndOfs
		|											|
		v											v
		+---+---+---+----+--------------------------+
		|ID	|Ver|Len|(IV)|							|
		+---+---+---+----+--------------------------+

   An initial openXXX() starts a new packet at the start of a stream and 
   continueXXX() adds another packet after an existing one, or (for the
   xxxHSXXX() variants) adds a handshake sub-packet within an existing 
   packet.  The continueXXX() operations return the start offset of the new 
   packet within the stream, openXXX() always starts at the start of the TLS 
   send buffer so the start offset is an implied 0.  completeXXX() then goes 
   back to the given offset and deposits the appropriate length value in the 
   header that was written earlier.  So typical usage (with state variables 
   and error checking omitted for clarity) would be:

	// Change-cipher-spec packet
	openPacketStreamTLS( TLS_MSG_CHANGE_CIPHER_SPEC );
	write( stream, ... );
	completePacketStreamTLS( stream, 0 );	// offset = 0

	// Finished handshake sub-packet within a handshake packet
	continuePacketStreamTLS( TLS_MSG_HANDSHAKE );
	continueHSPacketStream( TLS_HAND_FINISHED, &offset );
	write( stream, ... );
	completeHSPacketStream( stream, offset );
	// (Packet stream is completed by wrapPacketTLS()) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int startPacketStream( INOUT_PTR STREAM *stream, 
							  const SESSION_INFO *sessionInfoPtr, 
							  IN_RANGE( TLS_MSG_FIRST, \
										TLS_MSG_LAST ) const int packetType )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	const int ivLength = \
		( TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE ) && \
		  ( sessionInfoPtr->version == TLS_MINOR_VERSION_TLS11 || \
			sessionInfoPtr->version == TLS_MINOR_VERSION_TLS12 ) ) ? \
		tlsInfo->ivSize : 0;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );

	/* Write the packet header:

		byte		ID = packetType
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 0 (placeholder, filled in later) 
	  [ byte[]		iv	- TLS 1.1/1.2 only ] 

	  We cap the version at TLS 1.2 to deal with TLS 1.3, which pretends to 
	  be TLS 1.2 */
	sputc( stream, packetType );
	sputc( stream, TLS_MAJOR_VERSION );
	sputc( stream, 
		   min( sessionInfoPtr->version, TLS_MINOR_VERSION_TLS12 ) );
	status = writeUint16( stream, 0 );	/* Placeholder length */
	if( cryptStatusError( status ) )
		return( status );
	if( ivLength > 0 )
		{
		MESSAGE_DATA msgData;
		BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];

		setMessageData( &msgData, iv, ivLength );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		status = swrite( stream, iv, ivLength );
		}
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int openPacketStreamTLS( OUT_PTR STREAM *stream, 
						 IN_PTR const SESSION_INFO *sessionInfoPtr, 
						 IN_DATALENGTH_OPT const int bufferSize, 
						 IN_RANGE( TLS_MSG_FIRST, \
								   TLS_MSG_LAST ) const int packetType )
	{
	const int streamSize = ( bufferSize == CRYPT_USE_DEFAULT ) ? \
						   sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE : \
						   bufferSize + sessionInfoPtr->sendBufStartOfs;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) && \
			isWritePtrDynamic( sessionInfoPtr->sendBuffer, streamSize ) );

	REQUIRES( bufferSize == CRYPT_USE_DEFAULT || \
			  ( packetType == TLS_MSG_APPLICATION_DATA && \
			    bufferSize == 0 ) || \
			  isBufsizeRangeNZ( bufferSize ) );
			  /* When wrapping up data packets we only write the implicit-
				 length header so the buffer size is zero */
	REQUIRES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );
	REQUIRES( ( bufferSize == CRYPT_USE_DEFAULT ) ? \
				!checkOverflowSub( sessionInfoPtr->sendBufSize, \
								   EXTRA_PACKET_SIZE ) : \
				!checkOverflowAdd( bufferSize, \
								   sessionInfoPtr->sendBufStartOfs ) );
	REQUIRES( streamSize >= sessionInfoPtr->sendBufStartOfs && \
			  streamSize <= sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE );

	/* Create the stream */
	sMemOpen( stream, sessionInfoPtr->sendBuffer, streamSize );
	return( startPacketStream( stream, sessionInfoPtr, packetType ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int continuePacketStreamTLS( INOUT_PTR STREAM *stream, 
							 IN_PTR const SESSION_INFO *sessionInfoPtr, 
							 IN_RANGE( TLS_HAND_FIRST, \
									   TLS_HAND_LAST ) const int packetType,
							 OUT_LENGTH_SHORT_Z int *packetOffset )
	{
	const int offset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( packetOffset, sizeof( int ) ) );
	
	REQUIRES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );
	REQUIRES( offset >= TLS_HEADER_SIZE && \
			  offset <= sessionInfoPtr->sendBufSize );

	/* Clear return value */
	*packetOffset = 0;

	/* Continue the stream */
	status = startPacketStream( stream, sessionInfoPtr, packetType );
	if( cryptStatusError( status ) )
		return( status );
	*packetOffset = offset;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completePacketStreamTLS( INOUT_PTR STREAM *stream, 
							 IN_LENGTH_Z const int offset )
	{
	const int packetEndOffset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( !checkOverflowSub( packetEndOffset, \
								 ID_SIZE + VERSIONINFO_SIZE ) );
	REQUIRES( ( offset == 0 ) || \
			  ( offset >= TLS_HEADER_SIZE && \
				offset <= packetEndOffset - ( ID_SIZE + VERSIONINFO_SIZE ) ) );
	REQUIRES( isShortIntegerRangeMin( packetEndOffset, TLS_HEADER_SIZE ) );

	/* Update the length field at the start of the packet */
	REQUIRES( !checkOverflowAdd( offset, ID_SIZE + VERSIONINFO_SIZE ) );
	REQUIRES( !checkOverflowSub3( packetEndOffset, offset, \
								  TLS_HEADER_SIZE ) );
	sseek( stream, offset + ID_SIZE + VERSIONINFO_SIZE );
	status = writeUint16( stream, ( packetEndOffset - offset ) - \
								  TLS_HEADER_SIZE );
	sseek( stream, packetEndOffset );

	return( status );
	}

/* Start and complete a handshake packet within a TLS packet.  Since this
   continues an existing packet stream that's been opened using 
   openPacketStreamTLS(), it's denoted as continueXXX() rather than 
   openXXX() */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int continueHSPacketStream( INOUT_PTR STREAM *stream, 
							IN_RANGE( TLS_HAND_FIRST, \
									  TLS_HAND_LAST ) const int packetType,
							OUT_LENGTH_SHORT_Z int *packetOffset )
	{
	const int offset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( packetOffset, sizeof( int ) ) );

	REQUIRES( packetType >= TLS_HAND_FIRST && packetType <= TLS_HAND_LAST );
	REQUIRES( isShortIntegerRangeMin( offset, TLS_HEADER_SIZE ) );

	/* Clear return value */
	*packetOffset = 0;

	/* Write the handshake packet header:

		byte		ID = packetType
		uint24		len = 0 (placeholder) */
	sputc( stream, packetType );
	status = writeUint24( stream, 0 );
	if( cryptStatusError( status ) )
		return( status );
	*packetOffset = offset;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completeHSPacketStream( INOUT_PTR STREAM *stream, 
							IN_LENGTH const int offset )
	{
	const int packetEndOffset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( !checkOverflowSub( packetEndOffset, ID_SIZE + LENGTH_SIZE ) );
	REQUIRES( offset >= TLS_HEADER_SIZE && \
			  offset <= packetEndOffset - ( ID_SIZE + LENGTH_SIZE ) );
			  /* HELLO_DONE has size zero so 
			     offset == packetEndOffset - HDR_SIZE */
	REQUIRES( isShortIntegerRangeMin( packetEndOffset, TLS_HEADER_SIZE ) );

	/* Update the length field at the start of the packet */
	REQUIRES( !checkOverflowSub( packetEndOffset, \
								 offset + ID_SIZE + LENGTH_SIZE ) );
	sseek( stream, offset + ID_SIZE );
	status = writeUint24( stream, packetEndOffset - \
								  ( offset + ID_SIZE + LENGTH_SIZE ) );
	sseek( stream, packetEndOffset );
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Wrote %s (%d) handshake packet, length %d.\n", \
				  getTLSHSPacketName( DEBUG_GET_STREAMBYTE( stream, offset ) ), 
				  DEBUG_GET_STREAMBYTE( stream, offset ),
				  ( packetEndOffset - offset ) - ( ID_SIZE + LENGTH_SIZE ) ));
	DEBUG_DUMP_STREAM( stream, offset + ( ID_SIZE + LENGTH_SIZE ), 
					   ( packetEndOffset - offset ) - ( ID_SIZE + LENGTH_SIZE ) );
	DEBUG_PRINT_END();

	return( status );
	}

/****************************************************************************
*																			*
*							Write/Wrap a Packet								*
*																			*
****************************************************************************/

/* Wrap a TLS data packet.  There are three forms of this, the first for
   standard MAC-then-encrypt:

	sendBuffer hdrPtr	dataPtr
		|		|-----		|-------------------			  MAC'd
		v		v			v================================ Encrypted
		+-------+-----+-----+-------------------+-----+-----+
		|///////| hdr | IV	|		data		| MAC | pad |
		+-------+-----+-----+-------------------+-----+-----+
				^<----+---->|<-- dataLength --->^			|
				|	  |		 <-------- bMaxLen -|---------->
			 offset sBufStartOfs		  stell( stream )

   The second for encrypt-then-MAC and the Bernstein algorithm suite (the
   Bernstein suite uses an implicit rather than explicit IV so the IV field
   is only present for EtM):

	sendBuffer hdrPtr	dataPtr
		|		|			|=========================		  Encrypted
		v		v-----------v-------------------------        MAC'd
		+-------+-----+-----+-------------------+-----+-----+
		|///////| hdr | IV	|		data		| pad | MAC |
		+-------+-----+-----+-------------------+-----+-----+
				^<----+---->|<-- dataLength --->^			|
				|	  |		 <-------- bMaxLen -|---------->
			 offset sBufStartOfs		  stell( stream )

   And the third for GCM, with the explicit IV being present for TLS 1.2 GCM
   but not TLS 1.3 GCM:

	sendBuffer hdrPtr	dataPtr
		|		|			|
		v		v-----		v============================== AuthEnc'd
		+-------+-----+-----+-----------------------+-----+
		|///////| hdr | IV	|		data			| ICV |
		+-------+-----+-----+-----------------------+-----+
				^<----+---->|<-- dataLength --->^	  |
				|	  |		 <-------- bMaxLen -----|---->
			 offset sBufStartOfs			  stell( stream )

   These are sufficiently different that we use three distinct functions to
   do the job.  These MAC/ICV the data, add the IV if necessary, pad and 
   encrypt, and update the header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int wrapPacketTLSStd( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							 IN_RANGE( TLS_MSG_FIRST, \
									   TLS_MSG_LAST ) const int packetType,
							 INOUT_BUFFER( bufMaxLen, *length ) \
								BYTE *dataPtr,
							 IN_LENGTH_SHORT const int bufMaxLen,
							 OUT_LENGTH_BOUNDED_Z( bufMaxLen ) \
								int *length,
							 IN_LENGTH_SHORT const int dataLength )
	{
	const TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	int effectiveBufMaxLen = bufMaxLen, payloadLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( dataPtr, bufMaxLen ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );
	REQUIRES( bufMaxLen > 0 && bufMaxLen <= sessionInfoPtr->sendBufSize );
	REQUIRES( dataLength >= 0 && dataLength <= MAX_PACKET_SIZE );

	/* Clear return values */
	*length = 0;

	/* MAC the payload */
	status = createMacTLS( sessionInfoPtr, dataPtr, bufMaxLen, 
						   &payloadLength, dataLength, packetType );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's TLS 1.1+ and we're using a block cipher, adjust for the 
	   explicit IV that precedes the data.  This is because the IV load is
	   handled implicitly by encrypting it as part of the data.  We know 
	   that the resulting values are within bounds because 
	   dataPtr = headerPtr + hdr + IV */
	if( tlsInfo->ivSize > 0 )
		{
		REQUIRES( sessionInfoPtr->sendBufStartOfs >= TLS_HEADER_SIZE + \
													 tlsInfo->ivSize && \
				  sessionInfoPtr->sendBufStartOfs <= sessionInfoPtr->sendBufSize );
		REQUIRES( !checkOverflowAdd( payloadLength, tlsInfo->ivSize ) );
		REQUIRES( !checkOverflowAdd( bufMaxLen, tlsInfo->ivSize ) );
		dataPtr -= tlsInfo->ivSize;
		payloadLength += tlsInfo->ivSize;
		effectiveBufMaxLen = bufMaxLen + tlsInfo->ivSize;
		ENSURES( payloadLength > 0 && payloadLength <= effectiveBufMaxLen )
		}
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Wrote %s (%d) packet, length %d.\n", 
				  getTLSPacketName( packetType ), packetType, 
				  payloadLength - \
					( tlsInfo->ivSize + sessionInfoPtr->authBlocksize ) ));
	DEBUG_DUMP_DATA( dataPtr + tlsInfo->ivSize, 
					 payloadLength - \
						( tlsInfo->ivSize + sessionInfoPtr->authBlocksize ) );
	DEBUG_PRINT_END();

	/* Pad and encrypt the payload */
	status = encryptData( sessionInfoPtr, dataPtr, effectiveBufMaxLen, 
						  &payloadLength, payloadLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Tell the caller what the final packet size is */
	*length = payloadLength;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int wrapPacketTLSMAC( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							 IN_RANGE( TLS_MSG_FIRST, \
									   TLS_MSG_LAST ) const int packetType,
							 INOUT_BUFFER( bufMaxLen, *length ) \
								BYTE *dataPtr,
							 IN_LENGTH_SHORT const int bufMaxLen,
							 OUT_LENGTH_BOUNDED_Z( bufMaxLen ) int *length,
							 IN_LENGTH_SHORT const int dataLength )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
#ifdef USE_POLY1305
	const BOOLEAN isBernsteinSuite = \
					TEST_FLAG( sessionInfoPtr->protocolFlags, \
							   TLS_PFLAG_BERNSTEIN ) ? TRUE : FALSE;
	const BOOLEAN hasExplicitIV = \
			( !isBernsteinSuite && \
			  ( sessionInfoPtr->version == TLS_MINOR_VERSION_TLS11 || \
				sessionInfoPtr->version == TLS_MINOR_VERSION_TLS12 ) && \
			  tlsInfo->ivSize > 0 ) ? TRUE : FALSE;
#else
	const BOOLEAN hasExplicitIV = \
			( ( sessionInfoPtr->version == TLS_MINOR_VERSION_TLS11 || \
				sessionInfoPtr->version == TLS_MINOR_VERSION_TLS12 ) && \
			  tlsInfo->ivSize > 0 ) ? TRUE : FALSE;
#endif /* USE_POLY1305 */
	int effectiveBufMaxLen = bufMaxLen, payloadLength = dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( dataPtr, bufMaxLen ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );
	REQUIRES( bufMaxLen > 0 && bufMaxLen <= sessionInfoPtr->sendBufSize );
	REQUIRES( dataLength >= 0 && \
			  dataLength <= MAX_PACKET_SIZE + \
					( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ? \
					  1 : 0 ) );

	/* Clear return values */
	*length = 0;

#ifdef USE_POLY1305
	if( isBernsteinSuite )
		{
		/* Set up the Bernstein algorithm suite to encrypt the packet */
		status = initCryptBernstein( sessionInfoPtr, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
#endif /* USE_POLY1305 */
		{
		/* If it's TLS 1.1/1.2 and we're using a block cipher, adjust for 
		   the explicit IV that precedes the data.  This is because the IV 
		   load is handled implicitly by encrypting it as part of the data.  
		   We know that the resulting values are within bounds because 
		   dataPtr = headerPtr + hdr + IV */
		if( hasExplicitIV )
			{
			REQUIRES( sessionInfoPtr->sendBufStartOfs >= TLS_HEADER_SIZE + \
														 tlsInfo->ivSize && \
					  sessionInfoPtr->sendBufStartOfs <= sessionInfoPtr->sendBufSize );
			REQUIRES( !checkOverflowAdd( payloadLength, tlsInfo->ivSize ) );
			REQUIRES( !checkOverflowAdd( bufMaxLen, tlsInfo->ivSize ) );

			dataPtr -= tlsInfo->ivSize;
			payloadLength += tlsInfo->ivSize;
			effectiveBufMaxLen = bufMaxLen + tlsInfo->ivSize;
			ENSURES( payloadLength > 0 && payloadLength <= effectiveBufMaxLen )
			}
		}
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Wrote %s (%d) packet, length %d.\n", 
				  getTLSPacketName( packetType ), packetType, 
				  payloadLength - ( hasExplicitIV ? tlsInfo->ivSize : 0 ) ));
	DEBUG_DUMP_DATA( dataPtr + ( hasExplicitIV ? tlsInfo->ivSize : 0 ), 
					 min( ( payloadLength - ( hasExplicitIV ? \
											  tlsInfo->ivSize : 0 ) ), 4096 ) );
	DEBUG_PRINT_END();

	/* Encrypt the payload */
	status = encryptData( sessionInfoPtr, dataPtr, effectiveBufMaxLen, 
						  &payloadLength, payloadLength );
	if( cryptStatusError( status ) )
		return( status );

	/* MAC the payload */
#ifdef USE_POLY1305
	if( isBernsteinSuite )
		{
		status = createMacTLSBernstein( sessionInfoPtr, dataPtr, bufMaxLen, 
										&payloadLength, payloadLength, 
										packetType );
		}
	else
#endif /* USE_POLY1305 */
		{
		status = createMacTLS( sessionInfoPtr, dataPtr, bufMaxLen, 
							   &payloadLength, payloadLength, packetType );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Tell the caller what the final packet size is */
	*length = payloadLength;

	return( CRYPT_OK );
	}

#ifdef USE_GCM

/* For TLS 1.2 GCM the IV has to be assembled from implicit and explicit 
   components and set explicitly.  The implicit portion is fixed for each 
   session and is equivalent to the TLS client/server_write_IV derived from 
   the master secret, the explicit portion is randomly chosen for each 
   message.
	   
   There are a variety of options for this one, all of which are designed to 
   meet the general requirement that the nonce not repeat, which leads to a 
   catastrophic failure of security: use a counter starting at zero, use the 
   sequence number, use a counter starting at a random position, and use a 
   completely random number.  The last option runs into a potential 
   collision problem after around 2^32 TLS messages on average, however due 
   to the incredible brittleness of GCM the use of completely unrelated 
   random nonces is the best way of protecting against issues (apart from 
   not using GCM at all, which is the default config setting).  
	   
   Given cryptlib's field of application, the chances of it being used to 
   send several billion TLS messages in a single session is essentially 
   zero, so we use the (possible) extra protection offered by the use of 
   unrelated nonces.  This is handled by startPacketStream(), which sets a 
   GCM nonce using the same procedure as setting a CBC nonce, a completely 
   random value.  

   The reason why it's twelve bytes is because AES-GCM preferentially uses 
   96 bits of IV followed by 32 bits of 000...1, with other lengths being 
   possible but then the data has to be cryptographically reduced to 96 bits 
   before processing, so TLS specifies a fixed length of 96 bits:

	|<--- 12 bytes ---->|
	+-------+-----------+
	| Salt	|	Nonce	|
	+-------+-----------+
	|<- 4 ->|<--- 8 --->| 

   For TLS 1.3 GCM the IV processing was changed to match the form used in
   the Bernstein suite:

	|<--------------- 12 bytes ---------------->|
	+---------------+---------------------------+
	| 32-bit zeroes	|	64-bit sequence no.		|
	+---------------+---------------------------+
						XOR
	+-------------------------------------------+
	|				TLS read/write IV			|
	+-------------------------------------------+
						 |
						 v
	+-------------------------------------------+
	|				96-bit IV					|
	+-------------------------------------------+

   so we have to use different functions to set up the same value depending 
   on which TLS version we're using */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
static int loadTLS12GCMIV( IN_HANDLE const CRYPT_CONTEXT iCryptContext, 
						   INOUT_PTR TLS_INFO *tlsInfo,
						   IN_BUFFER( nonceLength ) const void *nonce,
						   IN_LENGTH_SHORT_MIN( 8 ) const int nonceLength )
	{
	MESSAGE_DATA msgData;
	BYTE ivBuffer[ CRYPT_MAX_IVSIZE + 8 ];

	assert( isWritePtr( tlsInfo, sizeof( TLS_INFO ) ) );
	assert( isReadPtr( nonce, nonceLength ) );

	REQUIRES( isShortIntegerRangeMin( nonceLength, 8 ) ); 

	REQUIRES( boundsCheck( tlsInfo->aeadSaltSize, nonceLength, 
						   CRYPT_MAX_IVSIZE ) );
	memcpy( ivBuffer, tlsInfo->aeadWriteSalt, tlsInfo->aeadSaltSize );
	memcpy( ivBuffer + tlsInfo->aeadSaltSize, nonce, nonceLength );

	/* Load the IV */
	setMessageData( &msgData, ivBuffer, GCM_IV_SIZE );
	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							 &msgData, CRYPT_CTXINFO_IV ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int wrapPacketTLSGCM( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							 IN_RANGE( TLS_MSG_FIRST, \
									   TLS_MSG_LAST ) const int packetType,
							 INOUT_BUFFER( bufMaxLen, *length ) \
									BYTE *dataPtr,
							 IN_LENGTH_SHORT const int bufMaxLen,
							 OUT_LENGTH_BOUNDED_Z( bufMaxLen ) int *length,
							 IN_LENGTH_SHORT const int dataLength )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	int payloadLength = dataLength, status = CRYPT_OK;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( dataPtr, bufMaxLen ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );
	REQUIRES( bufMaxLen > 0 && bufMaxLen <= sessionInfoPtr->sendBufSize );
	REQUIRES( dataLength >= 0 && \
			  dataLength <= MAX_PACKET_SIZE + \
					( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ? \
					  1 : 0 ) );

	/* Clear return values */
	*length = 0;

	/* Generate the TLS 1.2 or TLS 1.3 GCM IV as appropriate */
	if( sessionInfoPtr->version <= TLS_MINOR_VERSION_TLS12 )
		{
		status = loadTLS12GCMIV( sessionInfoPtr->iCryptOutContext, tlsInfo,
								 dataPtr - tlsInfo->ivSize, 
								 tlsInfo->ivSize );
		}
#ifdef USE_TLS13
	else
		status = initCryptGCMTLS13( sessionInfoPtr, FALSE );
#endif /* USE_TLS13 */
	if( cryptStatusError( status ) )
		return( status );

	/* Process the packet metadata as GCM AAD */
	status = macDataTLSGCM( sessionInfoPtr->iCryptOutContext, 
							tlsInfo->writeSeqNo, sessionInfoPtr->version, 
							payloadLength, packetType );
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->writeSeqNo++;
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Wrote %s (%d) packet, length %d.\n", 
				  getTLSPacketName( packetType ), packetType, 
				  payloadLength ));
	DEBUG_DUMP_DATA( dataPtr, payloadLength );
	DEBUG_PRINT_END();

	/* Encrypt the payload */
	status = encryptData( sessionInfoPtr, dataPtr, bufMaxLen, 
						  &payloadLength, payloadLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Adjust the length to account for the IV data at the start (for non-
	   GCM modes this is handled implicitly by making the IV part of the 
	   data to encrypt) */
	REQUIRES( !checkOverflowAdd( payloadLength, tlsInfo->ivSize ) );
	payloadLength += tlsInfo->ivSize;

	/* Tell the caller what the final packet size is */
	*length = payloadLength;

	return( CRYPT_OK );
	}
#endif /* USE_GCM */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int wrapPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				   INOUT_PTR STREAM *stream, 
				   IN_LENGTH_Z const int offset )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	STREAM lengthStream;
	BYTE lengthBuffer[ UINT16_SIZE + 8 ];
	BYTE *dataPtr, *headerPtr;
	int packetType, length, payloadLength, bufMaxLen, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* The buffer layout used here, as a generalised form of the more 
	   algorithm-specific formats given at the start of this section:

				  hdrPtr dataPtr
					|		|
		- offset -->v		v<--- payloadLength --->|
		------------+-------+-----------------------+-----------+
					|  hdr	|			data		|			|
		------------+-------+-----------------------+-----------+
					|<----->|<----------- bufMaxLen ------------>
				  TLS_HEADER_SIZE + 
				  tlsInfo->ivSize */
	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( TEST_FLAG( sessionInfoPtr->flags, 
						 SESSION_FLAG_ISSECURE_WRITE ) );
	REQUIRES( sStatusOK( stream ) );
	REQUIRES( isBufsizeRange( offset ) );

	/* Calculate the payload length information */
	REQUIRES( !checkOverflowAdd( offset, sessionInfoPtr->sendBufStartOfs ) );
	status = calculateStreamObjectLength( stream, 
								offset + sessionInfoPtr->sendBufStartOfs,
								&payloadLength );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( !checkOverflowAdd( payloadLength, sMemDataLeft( stream ) ) );
	bufMaxLen = payloadLength + sMemDataLeft( stream );

	/* Continue the previous checks on the calculated length values */
	REQUIRES( offset <= stell( stream ) - \
							( payloadLength + \
							  sessionInfoPtr->sendBufStartOfs ) );
	REQUIRES( payloadLength >= 0 && \
			  payloadLength <= MAX_PACKET_SIZE +
					( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ? \
					  1 : 0 ) && \
			  payloadLength < sessionInfoPtr->sendBufSize - \
							  ( sessionInfoPtr->sendBufStartOfs + \
								tlsInfo->ivSize ) && \
			  payloadLength <= bufMaxLen );
	REQUIRES( isIntegerRangeNZ( bufMaxLen ) );

	/* Get pointers into the data stream for the crypto processing */
	REQUIRES( !checkOverflowAdd3( TLS_HEADER_SIZE, tlsInfo->ivSize, 
								  bufMaxLen ) );
	status = sMemGetDataBlockAbs( stream, offset, ( void ** ) &headerPtr, 
								  TLS_HEADER_SIZE + tlsInfo->ivSize + \
													bufMaxLen );
	if( cryptStatusError( status ) )
		return( status );
	dataPtr = headerPtr + TLS_HEADER_SIZE + tlsInfo->ivSize;
	packetType = byteToInt( *headerPtr );
	ENSURES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );

	/* Wrap the data based on the type of processing that we're using */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
				   TLS_PFLAG_ENCTHENMAC | TLS_PFLAG_BERNSTEIN ) )
		{
		status = wrapPacketTLSMAC( sessionInfoPtr, packetType, dataPtr, 
								   bufMaxLen, &length, payloadLength );
		}
	else
		{
#ifdef USE_GCM
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
			{
			status = wrapPacketTLSGCM( sessionInfoPtr, packetType, dataPtr, 
									   bufMaxLen, &length, payloadLength );
			}
		else
#endif /* USE_GCM */
			{
			status = wrapPacketTLSStd( sessionInfoPtr, packetType, dataPtr, 
									   bufMaxLen, &length, payloadLength );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Insert the final packet payload length into the packet header.  We 
	   directly copy the data in because the stream may have been opened in 
	   read-only mode if we're using it to write pre-assembled packet data 
	   that's been passed in by the caller */
	sMemOpen( &lengthStream, lengthBuffer, UINT16_SIZE );
	status = writeUint16( &lengthStream, length );
	sMemDisconnect( &lengthStream );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( boundsCheck( ID_SIZE + VERSIONINFO_SIZE, UINT16_SIZE, 
						   bufMaxLen ) );
	memcpy( headerPtr + ID_SIZE + VERSIONINFO_SIZE, lengthBuffer, 
			UINT16_SIZE );

	/* Sync the stream information to match the new payload size */
	REQUIRES( !checkOverflowAdd( tlsInfo->ivSize, payloadLength ) && \
			  !checkOverflowSub( length, tlsInfo->ivSize + payloadLength ) );
	return( sSkip( stream, length - ( tlsInfo->ivSize + payloadLength ),
				   SSKIP_MAX ) );
	}

#ifdef USE_TLS13

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int wrapPacketTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR STREAM *stream, 
					 IN_LENGTH_Z const int offset,
					 IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
						const int packetType )
	{
	BYTE *dataPtr;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( TEST_FLAG( sessionInfoPtr->flags, 
						 SESSION_FLAG_ISSECURE_WRITE ) );
	REQUIRES( sStatusOK( stream ) );
	REQUIRES( isBufsizeRange( offset ) );

	/* Add the TLS 1.3 inner packet information.  Since this may be a read-
	   only stream we can't just write it onto the end of the existing data
	   but have to use StuffHex()-like direct access */
	status = sMemGetDataBlock( stream, ( void ** ) &dataPtr, 1 );
	if( cryptStatusOK( status ) )
		{
		*dataPtr = intToByte( packetType );
		status = sSkip( stream, 1, SSKIP_MAX );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Continue the packet-wrap process as normal */
	return( wrapPacketTLS( sessionInfoPtr, stream, offset ) );
	}
#endif /* USE_TLS13 */

/* Wrap up and send a TLS packet */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sendPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				   INOUT_PTR STREAM *stream, 
				   IN_BOOL const BOOLEAN sendOnly )
	{
	const int length = stell( stream );
	void *dataPtr;
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sStatusOK( stream ) );
	REQUIRES( isBooleanValue( sendOnly ) );
	REQUIRES( length >= TLS_HEADER_SIZE && \
			  length <= sessionInfoPtr->sendBufSize );

	/* Update the length field at the start of the packet if necessary */
	if( !sendOnly )
		{
		status = completePacketStreamTLS( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Send the packet to the peer */
	status = sMemGetDataBlockAbs( stream, 0, &dataPtr, length );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( dataPtr != NULL );
	status = swrite( &sessionInfoPtr->stream, dataPtr, length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	DEBUG_DUMP_TLS( dataPtr, length, NULL, 0 );

	return( CRYPT_OK );	/* swrite() returns a byte count */
	}

/****************************************************************************
*																			*
*								Send TLS Alerts								*
*																			*
****************************************************************************/

/* Send a close alert, with appropriate protection if necessary */

STDC_NONNULL_ARG( ( 1 ) ) \
static void sendAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   IN_RANGE( TLS_ALERTLEVEL_WARNING, \
								 TLS_ALERTLEVEL_FATAL ) const int alertLevel, 
					   IN_RANGE( TLS_ALERT_FIRST, \
								 TLS_ALERT_LAST ) const int alertType,
					   IN_BOOL const BOOLEAN alertReceived )
	{
	STREAM stream;
#ifdef USE_TLS13
	const int packetType = \
				( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 && \
				  TEST_FLAG( sessionInfoPtr->flags, 
							 SESSION_FLAG_ISSECURE_WRITE ) ) ? \
				TLS_MSG_APPLICATION_DATA : TLS_MSG_ALERT;
#else
	const int packetType = TLS_MSG_ALERT;
#endif /* USE_TLS13 */
	int length DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	
	REQUIRES_V( alertLevel == TLS_ALERTLEVEL_WARNING || \
				alertLevel == TLS_ALERTLEVEL_FATAL );
	REQUIRES_V( alertType >= TLS_ALERT_FIRST && \
				alertType <= TLS_ALERT_LAST );
	REQUIRES_V( isBooleanValue( alertReceived ) );

	/* Make sure that we only send a single alert.  Normally we do this 
	   automatically on shutdown, but we may have already sent it earlier 
	   as part of an error-handler */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_ALERTSENT ) )
		return;
	SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_ALERTSENT );

	/* Create the alert.  We can't really do much with errors at this point, 
	   although we can throw an exception in the debug version to draw 
	   attention to the fact that there's a problem.  The one error type 
	   that we don't complain about is an access permission problem, which 
	   can occur when cryptlib is shutting down, for example when the 
	   current thread is blocked waiting for network traffic and another 
	   thread shuts things down.
	   
	   If we encounter an error during this processing, we continue anyway 
	   and drop through and perform a clean shutdown even if the creation of 
	   the close alert fails.
	   
	   As usual, TLS 1.3 has its own special-snowflake form of alerts,
	   stuffing them inside application data packets with the actual packet 
	   type appended to the payload so we have to handle this specially */
	status = openPacketStreamTLS( &stream, sessionInfoPtr, 
								  CRYPT_USE_DEFAULT, packetType );
	if( cryptStatusOK( status ) )
		{
		sputc( &stream, alertLevel );
		status = sputc( &stream, alertType );
		}
	if( cryptStatusOK( status ) )
		{
		if( TEST_FLAG( sessionInfoPtr->flags, 
					   SESSION_FLAG_ISSECURE_WRITE ) )
			{
#ifdef USE_TLS13
			if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
				{
				status = wrapPacketTLS13( sessionInfoPtr, &stream, 0,
										  TLS_MSG_ALERT );
				}
			else
#endif /* USE_TLS13 */
			status = wrapPacketTLS( sessionInfoPtr, &stream, 0 );
			assert( cryptStatusOK( status ) || \
					status == CRYPT_ERROR_PERMISSION );
			}
		else
			status = completePacketStreamTLS( &stream, 0 );
		if( cryptStatusOK( status ) )
			length = stell( &stream );
		sMemDisconnect( &stream );
		}
	/* Fall through with status passed on to the following code */

	/* Send the alert, or if there was an error at least perform a clean 
	   shutdown */
	if( cryptStatusOK( status ) )
		{
		ENSURES_V( isBufsizeRangeNZ( length ) );
		status = sendCloseNotification( sessionInfoPtr, 
										sessionInfoPtr->sendBuffer, 
										length );
		}
	else
		status = sendCloseNotification( sessionInfoPtr, NULL, 0 );
	if( cryptStatusError( status ) || alertReceived )
		return;

	/* Read back the other side's close alert acknowledgement, again with 
	   TLS 1.3 special-snowflake handling where the alert is wrapped up
	   as application data.  As before, since we're closing down the 
	   session anyway there's not much that we can do in response to an 
	   error so we don't go any further than just reading the packet */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		( void ) readHSPacketTLS( sessionInfoPtr, NULL, &length, 
								  TLS_MSG_APPLICATION_DATA );
  #if 0	/* For debugging, recover alert packet data */
		{
		int actualPacketType;
		( void ) unwrapPacketTLS13( sessionInfoPtr, 
									sessionInfoPtr->receiveBuffer + \
										sessionInfoPtr->receiveBufPos, 
									length, &length, &actualPacketType,
									TLS_MSG_APPLICATION_DATA );
		}
  #endif /* 0 */
		}
	else
#endif /* USE_TLS13 */
	( void ) readHSPacketTLS( sessionInfoPtr, NULL, &length, 
							  TLS_MSG_ALERT );
#if 0	/* For debugging, recover alert packet data */
	( void ) unwrapPacketTLS( sessionInfoPtr, 
							  sessionInfoPtr->receiveBuffer + \
								sessionInfoPtr->receiveBufPos, 
							  length, &length, TLS_MSG_APPLICATION_DATA );
#endif /* 0 */
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void sendCloseAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 IN_BOOL const BOOLEAN alertReceived )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES_V( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES_V( isBooleanValue( alertReceived ) );

	sendAlert( sessionInfoPtr, TLS_ALERTLEVEL_WARNING, 
			   TLS_ALERT_CLOSE_NOTIFY, alertReceived );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void sendHandshakeFailAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 IN_RANGE( TLS_ALERT_FIRST, \
									   TLS_ALERT_LAST ) const int alertType )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES_V( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES_V( alertType >= TLS_ALERT_FIRST && \
				alertType <= TLS_ALERT_LAST );

	/* We set the alertReceived flag to true when sending a handshake
	   failure alert to avoid waiting to get back an ack, since this 
	   alert type isn't acknowledged by the other side */
	sendAlert( sessionInfoPtr, TLS_ALERTLEVEL_FATAL, alertType, TRUE );
	}
#endif /* USE_TLS */
