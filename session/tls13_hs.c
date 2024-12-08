<<<<<<< HEAD
/****************************************************************************
*																			*
*					cryptlib TLS 1.3 Handshake Management					*
*					  Copyright Peter Gutmann 2019-2022						*
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

#ifdef USE_TLS13

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Create the dummy Change Cipherspec message.  This isn't used in TLS 1.3
   but is prepended to the subsequent encrypted handshake messages to make
   the flow look like a classic TLS exchange */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createDummyCCS( OUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
										 
	/* Build the (dummy) change cipher spec packet:

		byte		type = TLS_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x03 }
		uint16		len = 1
		byte		1

	   Since Change Cipherspec is its own protocol, we use TLS-level packet
	   encoding rather than handshake protocol-level encoding */
	status = openPacketStreamTLS( stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
								  TLS_MSG_CHANGE_CIPHER_SPEC );
	if( cryptStatusError( status ) )
		return( status );
	status = sputc( stream, 1 );
	if( cryptStatusOK( status ) )
		status = completePacketStreamTLS( stream, 0 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readDummyCCS( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	int length, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Process the other side's Change Cipherspec:

		byte		type = TLS_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x03 }
		uint16		len = 1
		byte		1 */
	status = readHSPacketTLS( sessionInfoPtr, NULL, &length,
							  TLS_MSG_CHANGE_CIPHER_SPEC );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	value = sgetc( &stream );
	sMemDisconnect( &stream );
	if( value != 1 )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid change cipher spec packet payload, expected "
				  "0x01, got 0x%02X", value ) );
		}

	return( CRYPT_OK );
	}

/* Complete the session hash for the handshake messages.  Note that this 
   differs from the TLS-wide createSessionHash() which simply extracts the
   hash state at the current time and allows the hashing to continue */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completeSessionHash( IN_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	/* Wrap up the session hashing and get the value */
	status = krnlSendMessage( handshakeInfo->sha2context, IMESSAGE_CTX_HASH, 
							  "", 0 );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, handshakeInfo->sessionHash, 
					CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( handshakeInfo->sha2context, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	handshakeInfo->sessionHashSize = msgData.length;
	DEBUG_DUMP_DATA_LABEL( ( handshakeInfo->tls13SuiteInfoPtr != NULL ) ? \
								"Session hash (client):" : \
								"Session hash (server):", 
						   handshakeInfo->sessionHash, 
						   handshakeInfo->sessionHashSize );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Process Hello Retry							*
*																			*
****************************************************************************/

/* We shouldn't ever have to do a Hello Retry because we always do the MTI 
   P256, however alongside assorted other braindamage Google Chrome always 
   connects using 25519 and nothing else which forces a retry on every 
   single connect.  The following reruns the first half of the TLS 1.3 
   handshake in order to allow Google Chrome to connect */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processHelloRetry( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							  OUT_BOOL BOOLEAN *processedDummyCCS )
	{
	STREAM *stream = &handshakeInfo->stream;
	MESSAGE_DATA msgData;
	HASH_FUNCTION hashFunction;
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	HASHINFO hashInfo;
	BYTE hashBuffer[ 8 + CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	TLSHELLO_ACTION_TYPE actionType;
	int clientHelloLength, serverHelloLength DUMMY_INIT;
	int hashSize, packetOffset, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( processedDummyCCS, sizeof( BOOLEAN ) ) );

	/* Clear return value */
	*processedDummyCCS = FALSE;

	/* Re-hash the Client and Server Hello messages with SHA-256 as before, 
	   but leaving the hash open so that we can hash in the retried ones as 
	   well.
	   
	   In another one of TLS 1.3's many clever tricks, what's hashed is no 
	   longer the same as what's hashed for a normal message flow but a hash
	   of the first Client Hello with a pseudo-header prepended to it with
	   the purported goal of allowing stateless retries.  This overwrites 
	   the original hash value with the modified form:

		Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
			Hash(message_hash ||	// Handshake type = 254
			00 00 Hash.length  ||	// Handshake message [sic] length = uint24
			Hash(ClientHello1) ||	// Hash of ClientHello1 = 32-byte hash
			HelloRetryRequest  || ... || Mn)

	   In binary the pseudo-header that's prepended to the hash of the 
	   Client Hello is { 0xFE 0x00 0x00 0x20 }.  Note that the comment for 
	   the uint24 length in the spec is wrong, it's the length of the hash 
	   value, not the length of the handshake message */
	memcpy( hashBuffer, "\xFE\x00\x00\x20", 4 );
	getHashAtomicParameters( CRYPT_ALGO_SHA2, bitsToBytes( 256 ), 
							 &hashFunctionAtomic, &hashSize );
	hashFunctionAtomic( hashBuffer + 4, CRYPT_MAX_HASHSIZE, 
						sessionInfoPtr->receiveBuffer, 
						handshakeInfo->originalClientHelloLength );
	getHashParameters( CRYPT_ALGO_SHA2, bitsToBytes( 256 ), &hashFunction, 
					   &hashSize );
	hashFunction( hashInfo, NULL, 0, hashBuffer, 4 + hashSize, 
				  HASH_STATE_START );
	hashFunction( hashInfo, NULL, 0, 
				  sessionInfoPtr->sendBuffer + TLS_HEADER_SIZE, 
				  handshakeInfo->originalServerHelloLength, 
				  HASH_STATE_CONTINUE );
	CFI_CHECK_UPDATE( "hashFunction 1" );

	/* The session hash calculations are run in parallel to the hello hash
	   calculations so we also have to re-hash the modified form of the 
	   Client and Server Hello for the session hash */
	status = krnlSendMessage( handshakeInfo->sha2context, 
							  IMESSAGE_DELETEATTRIBUTE, NULL, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( handshakeInfo->sha2context,
								  IMESSAGE_CTX_HASH, hashBuffer,
								  4 + hashSize );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( handshakeInfo->sha2context,
							IMESSAGE_CTX_HASH, 
							sessionInfoPtr->sendBuffer + TLS_HEADER_SIZE,
							handshakeInfo->originalServerHelloLength );
		}
	ENSURES( cryptStatusOK( status ) );
	CFI_CHECK_UPDATE( "hashFunction 2" );

	/* Some implementations, most notably Google Chrome, send a bogus Change 
	   Cipherspec at this point.  The RFC says (section 4.2.2) that "when a 
	   server is operating statelessly, it may receive an unprotected record 
	   of type change_cipher_spec between the first and second ClientHello".  
	   It never specifies how a client is supposed to tell when a server is 
	   operating statelessly but since the text is in the section that 
	   discusses the Cookie extension it presumably means that it applies 
	   when the server has sent this extension to the client.  We haven't 
	   sent it but implementations like Chrome send the Change Cipherspec 
	   anyway */
	status = readHSPacketTLS( sessionInfoPtr, handshakeInfo,
							  &clientHelloLength, TLS_MSG_TLS13_HELLORETRY );
	if( cryptStatusError( status ) )
		return( status );
	if( clientHelloLength == 1 && \
		sessionInfoPtr->receiveBuffer[ 0 ] == 0x01 )
		{
		/* Although this CCS is now part of the handshake message flow it 
		   doesn't get included in the transcript hash */
	/*	hashFunction( hashInfo, NULL, 0, "0x01", 1, HASH_STATE_CONTINUE ); */

		/* This was a bogus Change Cipherspec, let the caller know and 
		   re-read the next message, which should be the Client Hello that 
		   we're expecting */
		*processedDummyCCS = TRUE;
		status = readHSPacketTLS( sessionInfoPtr, handshakeInfo,
								  &clientHelloLength, TLS_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			return( status );
		}
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, clientHelloLength );
	status = processHelloTLS( sessionInfoPtr, handshakeInfo, stream,
							  &actionType, TRUE );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		{
		REQUIRES( status != OK_SPECIAL );

		return( status );
		}
	CFI_CHECK_UPDATE( "processHelloTLS" );

	/* Re-clear all of the flags that we don't want for TLS 1.3 */
	handshakeInfo->flags &= \
			~( HANDSHAKE_FLAG_NEEDRENEGRESPONSE | \
			   HANDSHAKE_FLAG_NEEDETMRESPONSE | \
			   HANDSHAKE_FLAG_NEEDEMSRESPONSE | \
			   HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE );
	handshakeInfo->sendECCPointExtn = FALSE;

	/* Since we've now refreshed the Client Hello state, in other words 
	   treated the retried Client Hello as a new, original Client Hello, we
	   clear the retried-hello indicator */
	handshakeInfo->flags &= ~HANDSHAKE_FLAG_RETRIEDCLIENTHELLO;

	/* Get the nonce that's used to randomise all crypto operations.  We 
	   previously sent a magic-value non-nonce that's used to indicate that
	   the Server Hello is really a Hello Retry Request rather than a Server 
	   Hello, now we use an actual nonce */
	setMessageData( &msgData, handshakeInfo->serverNonce, TLS_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the real TLS 1.3 Server Hello:

		byte		ID = TLS_HAND_SERVER_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x03 }
		byte[32]	nonce
		byte		sessIDlen
			byte[]	sessID
		uint16		suite
		byte		copr = 0
		uint16	extListLen
			byte	extType
			uint16	extLen
			byte[]	extData 

	   Note that although the session ID isn't used since we know at this 
	   point that it's TLS 1.3 and not any earlier version, we still have to
	   send it if the client sent it in their hello for TLS 1.2 camouflage
	   reasons */
	status = openPacketStreamTLS( stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
								  TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	status = continueHSPacketStream( stream, TLS_HAND_SERVER_HELLO,
									 &packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	sputc( stream, TLS_MAJOR_VERSION );
	sputc( stream, TLS_MINOR_VERSION_TLS12 );
	swrite( stream, handshakeInfo->serverNonce, TLS_NONCE_SIZE );
	sputc( stream, handshakeInfo->sessionIDlength );
	if( handshakeInfo->sessionIDlength > 0 )
		{
		swrite( stream, handshakeInfo->sessionID, 
				handshakeInfo->sessionIDlength );
		}
	writeUint16( stream, handshakeInfo->cipherSuite );
	status = sputc( stream, 0 );	/* No compression */
	if( cryptStatusOK( status ) )
		{
		status = writeServerExtensions( stream, sessionInfoPtr, 
										handshakeInfo );
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, TLS_HEADER_SIZE,
											  &serverHelloLength );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "serverHello" );

	/* Hash the re-sent Client and Server Hello messages onto the end of the
	   original Client and Server Hello and wrap up the hashing to get the
	   hello hash */
	hashFunction( hashInfo, NULL, 0, sessionInfoPtr->receiveBuffer,
				  clientHelloLength, HASH_STATE_CONTINUE );
	hashFunction( hashInfo, handshakeInfo->helloHash, CRYPT_MAX_HASHSIZE,
				  sessionInfoPtr->sendBuffer + TLS_HEADER_SIZE,
				  serverHelloLength, HASH_STATE_END );
	handshakeInfo->helloHashSize = hashSize;
	DEBUG_DUMP_DATA_LABEL( "Client/Server hello hash (server):",
						   handshakeInfo->helloHash,
						   handshakeInfo->helloHashSize );
	CFI_CHECK_UPDATE( "hashFunction 3" );

	/* Send the redone Server Hello to the client */
	status = sendPacketTLS( sessionInfoPtr, stream, FALSE );
	if( cryptStatusOK( status ) )
		status = hashHSPacketWrite( handshakeInfo, stream, 0 );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "sendPacketTLS" );

	ENSURES( CFI_CHECK_SEQUENCE_6( "hashFunction 1", "hashFunction 2", 
								   "processHelloTLS", "serverHello", 
								   "hashFunction 3", "sendPacketTLS" ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read/Write Encrypted Handshake Packets				*
*																			*
****************************************************************************/

/* Read an encrypted handshake packet.  Since these are stuffed inside 
   application data packets we have to read what are actually handshake 
   packets as application-data packets */

typedef enum {
	READHS_ACTION_NONE,			/* No handshake read action */
	READHS_ACTION_NORMAL,		/* Normal handling */
	READHS_ACTION_FIRSTENCR,	/* First encrypted packet */
	READHS_ACTION_FIRSTENCR_NOHASH,/* First encr.+ don't hash payload */
	READHS_ACTION_NOHASH,		/* Normal handling + don't hash payload */
	READHS_ACTION_LAST			/* Last possible read action */
	} READHS_ACTION_TYPE;

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readEncryptedHSPacket( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								  TLS_HANDSHAKE_INFO *handshakeInfo,
								  OUT_LENGTH_BOUNDED_Z( MAX_PACKET_SIZE ) \
										int *payloadLength, 
								  IN_ENUM( READHS_ACTION ) \
										const READHS_ACTION_TYPE actionType )
	{
	STREAM stream;
	const BOOLEAN isFirstEncrypted = \
			( actionType == READHS_ACTION_FIRSTENCR || \
			  actionType == READHS_ACTION_FIRSTENCR_NOHASH ) ? TRUE : FALSE;
	int actualPacketType, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( payloadLength, sizeof( int ) ) );

	REQUIRES( isEnumRange( actionType, READHS_ACTION ) );

	/* Clear return value */
	*payloadLength = 0;

	/* Process the other side's encrypted handshake data.  Since this is
	   an encrypted blob at this point we pass in a NULL pointer in place of
	   the handshakeInfo when we call readHSPacketTLS() to prevent hashing 
	   of the message data, we can't hash it until later when it's been
	   decrypted and unpacked.
	
	   If we're reading the first encrypted message then this is the first 
	   chance that we have to test whether our crypto keys are set up 
	   correctly, so we report problems with decryption or MACing or a 
	   failure to find any recognisable header as a wrong key rather than a 
	   bad data error.  In addition we signal the fact that the other side 
	   may respond unexpectedly because of the use of encryption to 
	   readHSPacketTLS() by specifying a special-case packet type, see the 
	   comment in readHSPacketTLS() for how this is handled and why it's 
	   necessary.
	
	   Since we've now turned on crypto, all errors are fatal crypto 
	   errors */
	status = readHSPacketTLS( sessionInfoPtr, NULL, &length, 
							  isFirstEncrypted ? \
								TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE : \
								TLS_MSG_APPLICATION_DATA );
	if( cryptStatusError( status ) )
		return( status );
	status = unwrapPacketTLS13( sessionInfoPtr, sessionInfoPtr->receiveBuffer, 
								length, &length, &actualPacketType,
								TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		{
		registerCryptoFailure();

		if( isFirstEncrypted && \
			( status == CRYPT_ERROR_BADDATA || \
			  status == CRYPT_ERROR_SIGNATURE ) )
			{
			retExtErr( CRYPT_ERROR_WRONGKEY,
					   ( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						 SESSION_ERRINFO, 
						 "Decrypted data was corrupt, probably due to "
						 "incorrect handshake encryption keys being "
						 "negotiated" ) );
			}
		return( status );
		}
	ENSURES( isShortIntegerRangeMin( length, 2 ) );
			 /* Guaranteed by unwrapPacketTLS13() */

	/* Because of TLS 1.3's camouflage-wrapping what we're getting could be 
	   an Alert.  This fact is cunningly hidden from anyone who doesn't know
	   that only an Alert can be this size */
	if( actualPacketType == TLS_MSG_ALERT )
		{
		return( processAlertTLS13( sessionInfoPtr, 
								   sessionInfoPtr->receiveBuffer, 2, 
								   NULL ) );
		}

	/* Now that we've got the handshake message data we can hash it */
	if( actionType != READHS_ACTION_FIRSTENCR_NOHASH && \
		actionType != READHS_ACTION_NOHASH )
		{
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		status = hashHSPacketRead( handshakeInfo, &stream );
		sMemDisconnect( &stream );
		}
	if( cryptStatusOK( status ) )
		*payloadLength = length;
	return( status );
	}

/* Because TLS 1.3 stuffs extra content into an encrypted packet, it's no 
   longer possible to have multiple handshake subpackets inside a single 
   encapsulating TLS_MSG_HANDSHAKE packet because that provides no way to
   record where the extra information that's tacked onto the end of each
   handshake subpacket finishes.  To deal with this we have to individually
   gift-wrap each subpacket in its own handshake packet, defeating at least
   some of the encryption of handshake messages because it makes traffic
   analysis a lot easier.

   The gift-wrapping is handled by the following two functions, with the
   inner wrapping optional when called in conjunction with functions that 
   perform it themselves, indicated by setting the sub-packet type to
   TLS_HAND_NONE */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int startEncryptedPacketStream( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
									   INOUT_PTR STREAM *stream, 
									   OUT_LENGTH_SHORT_Z int *outerOffset, 
									   OUT_OPT_LENGTH_SHORT_Z int *innerOffset,
									   IN_RANGE( TLS_HAND_NONE, \
												 TLS_HAND_LAST ) \
											const int subPacketType )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( outerOffset, sizeof( int ) ) );
	assert( innerOffset == NULL || \
			isWritePtr( innerOffset, sizeof( int ) ) );

	REQUIRES( ( subPacketType == TLS_HAND_NONE && \
				innerOffset == NULL ) || \
			  ( isEnumRange( subPacketType, TLS_HAND ) && \
				innerOffset != NULL ) );

	/* Clear return values */
	*outerOffset = CRYPT_ERROR;
	if( innerOffset != NULL )
		*innerOffset = CRYPT_ERROR;

	/* Write the outer wrapper, the camouflage application-data packet, and 
	   the optional inner wrapper containing the handshake subtype */
	status = continuePacketStreamTLS( stream, sessionInfoPtr,
									  TLS_MSG_APPLICATION_DATA, outerOffset );
	if( cryptStatusOK( status ) && subPacketType != TLS_HAND_NONE )
		{
		status = continueHSPacketStream( stream, subPacketType, 
										 innerOffset );
		}

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int completeEncryptedPacketStream( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
										  IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo,
										  INOUT_PTR STREAM *stream, 
										  IN_LENGTH_SHORT const int outerOffset, 
										  IN_LENGTH_SHORT_OPT const int innerOffset,
										  IN_BOOL const BOOLEAN hashData )
	{
	int status = CRYPT_OK;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isShortIntegerRange( outerOffset ) );
	REQUIRES( innerOffset == CRYPT_UNUSED || \
			  isShortIntegerRange( innerOffset ) );
	REQUIRES( isBooleanValue( hashData ) );

	/* Wrap up the inner and outer wrappers.  We optionally skip the hashing 
	   of the packet data for packets that aren't part of the session hash */
	if( innerOffset != CRYPT_UNUSED )
		status = completeHSPacketStream( stream, innerOffset );
	if( cryptStatusOK( status ) && hashData )
		status = hashHSPacketWrite( handshakeInfo, stream, outerOffset );
	if( cryptStatusOK( status ) )
		{
		status = wrapPacketTLS13( sessionInfoPtr, stream, outerOffset,
								  TLS_MSG_HANDSHAKE );
		}
	
	return( status );
	}

/****************************************************************************
*																			*
*						Read/Write Authentication Messages					*
*																			*
****************************************************************************/

/* Read and write the TLS 1.3 certificate verify message, a signature on a 
   hash of all the handshake messages so far:

	uint16		algorithm
	uint16		sigLen
		byte[]	sig */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   INOUT_PTR STREAM *stream,
						   IN_HANDLE const CRYPT_CONTEXT iHashContext )
	{
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );

	/* Make sure that the packet header is in order */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_CERTVERIFY, 
								  UINT16_SIZE + MIN_PKCSIZE_ECC );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the TLS 1.3 session hash.  If we're the server then we're
	   verifying the client's certificate verify so we set the 
	   isServerVerify value to FALSE */
	status = createSessionHashTLS13( handshakeInfo, iHashContext,
									 isServer( sessionInfoPtr ) ? \
										FALSE : TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Verify the signature on the session hash */
	status = checkCertVerify( sessionInfoPtr, handshakeInfo, stream, 
							  length );
	destroySessionHash( handshakeInfo );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							INOUT_PTR STREAM *stream,
							IN_HANDLE const CRYPT_CONTEXT iHashContext )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );

	/* Create the TLS 1.3 session hash.  If we're the server then we're
	   creating the server's certificate verify so we set the isServerVerify 
	   value to TRUE */
	status = createSessionHashTLS13( handshakeInfo, iHashContext,
									 isServer( sessionInfoPtr ) ? \
										TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the signature on the hash of the transcript hash */
	status = createCertVerify( sessionInfoPtr, handshakeInfo, stream );
	destroySessionHash( handshakeInfo );

	return( status );
	}

/* Read and write the TLS 1.3 certificate request:

	  [	byte		ID = TLS_HAND_SERVER_CERTREQUEST ]
	  [	uint24		len				-- Written by caller ]
		byte		certNonceLen = 16
		byte[]		certNonce
		uint16		extListLen
			uint16	extType = TLS_EXT_SIGNATURE_ALGORITHMS
			uint16	extLen
				uint16	algorithmListLength
					uint16[] algorithms

   After extending the original mostly good-enough form with extra cruft in
   TLS 1.2, TLS 1.3 went the X.509 route and added full-on extensions to
   the request, of which only one is defined, SignatureAlgorithms, which 
   does the same as what the TLS 1.2 addition did but now it's in a full
   extension.

   See the long comment in session/tls_ext_rw.c on the giant mess that is 
   the SignatureAlgorithms extension */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readCertRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							INOUT_PTR STREAM *stream )
	{
	int packetLength, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Make sure that the packet header is in order.  We need at least 8 
	   bytes of certificate nonce and at least one extension, that being
	   TLS_EXT_SIGNATURE_ALGORITHMS */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &packetLength,
								  TLS_HAND_SERVER_CERTREQUEST, 
								  ( 1 + 8 ) + UINT16_SIZE + \
									( UINT16_SIZE * 4 ) );
	if( cryptStatusError( status ) )
		return( status );
	status = length = sgetc( stream );
	if( !cryptStatusError( status ) )
		{
		if( length < 1 || length > CRYPT_MAX_HASHSIZE || \
			1 + length + ( UINT16_SIZE * 5 ) > packetLength )
			status = CRYPT_ERROR_BADDATA;
		}
	if( !cryptStatusError( status ) )
		status = sread( stream, handshakeInfo->tls13CertContext, length );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate request certificate-nonce "
				  "information" ) );
		}
	handshakeInfo->tls13CertContextLen = length;
	packetLength -= length + 1;
	ENSURES( isShortIntegerRangeMin( packetLength, UINT16_SIZE * 5 ) );

	/* Read the extensions:

		uint16		extListLen
			[...]
			uint16	extType = TLS_EXT_SIGNATURE_ALGORITHMS
			uint16	extLen
				uint16	algorithmListLength
					uint16[] algorithms
			[...]

	   The only thing that's defined to be present here is the 
	   TLS_EXT_SIGNATURE_ALGORITHMS extension and for that the contents are
	   more or less irrelevant, see the comment in 
	   session/tls_cli.c:processCertRequest() for details, so all we do is
	   make sure that there's at least one extension of the right shape to
	   count as a TLS_EXT_SIGNATURE_ALGORITHMS present and ignore everything
	   else */
	status = length = readUint16( stream );
	if( !cryptStatusError( status ) )
		{
		if( length < ( UINT16_SIZE * 3 ) || length > packetLength )
			status = CRYPT_ERROR_BADDATA;
		}
	if( !cryptStatusError( status ) )
		status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate request signature/hash "
				  "algorithm information" ) );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCertRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							 INOUT_PTR STREAM *stream )
	{
	MESSAGE_DATA msgData;
	const BOOLEAN rsaAvailable = algoAvailable( CRYPT_ALGO_RSA ) ? \
								 TRUE : FALSE;
	const BOOLEAN dsaAvailable = algoAvailable( CRYPT_ALGO_DSA ) ? \
								 TRUE : FALSE;
	const BOOLEAN ecdsaAvailable = algoAvailable( CRYPT_ALGO_ECDSA ) ? \
								   TRUE : FALSE;
	const int extensionPayloadSize = \
					( rsaAvailable ? ( UINT16_SIZE * 3 ) : 0 ) + \
					( dsaAvailable ? UINT16_SIZE : 0 ) + \
					( ecdsaAvailable ? UINT16_SIZE : 0 );
	BYTE nonceBuffer[ 8 + 8 ];
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isBooleanValue( rsaAvailable ) );

	/* Write the nonce/identifier value.  This isn't used in any 
	   cryptographic computations but is used to identify which certificate 
	   belongs to which request in something that presumably satisfies some 
	   business case for someone on the standards committee */
	setMessageData( &msgData, nonceBuffer, 8 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );
	sputc( stream, 8 );
	status = swrite( stream, nonceBuffer, 8 );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the extension wrapper.  We don't need a full-blown 
	   writeExtensions() here since all we need to write is a minimal
	   SignatureAlgorithms, for which we begin by writing the wrapper */
	writeUint16( stream, UINT16_SIZE + UINT16_SIZE + \
						 UINT16_SIZE + extensionPayloadSize );
	writeUint16( stream, TLS_EXT_SIGNATURE_ALGORITHMS );
	status = writeUint16( stream, UINT16_SIZE + extensionPayloadSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the list of accepted signature and hash algorithms.  In theory 
	   we could write the full list of algorithms, but thanks to TLS' 
	   braindamaged way of handling certificate-based authentication 
	   (see the comment in session/tls_svr.c:writeCertRequest()) this would
	   make the certificate-authentication process unmanageable.  To get 
	   around this we only allow one single algorithm, the de facto 
	   universal-standard SHA-2 */
	writeUint16( stream, extensionPayloadSize );
	if( rsaAvailable )
		{
		writeUint16( stream, TLS_SIGHASHALGO_RSAPKCS1_SHA2 );
		writeUint16( stream, TLS_SIGHASHALGO_RSAPSSoid1_SHA2 );
		status = writeUint16( stream, TLS_SIGHASHALGO_RSAPSSoid2_SHA2 );
		}
	if( dsaAvailable )
		status = writeUint16( stream, TLS_SIGHASHALGO_DSA_SHA2 );
	if( ecdsaAvailable )
		status = writeUint16( stream, TLS_SIGHASHALGO_ECDSA_SHA2 );
	return( status );
	}

/* Read and write the TLS 1.3 finished message, a MAC of the hash of all the 
   handshake messages so far:

	byte[]	finished_data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readFinished( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 INOUT_PTR STREAM *stream,
						 IN_HANDLE const CRYPT_CONTEXT iHashContext,
						 IN_BOOL const BOOLEAN isServerFinished )
	{
	BYTE finishedValue[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE receivedValue[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int finishedValueLength, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isBooleanValue( isServerFinished ) );

	/* Create the TLS 1.3 finished value */
	status = createFinishedTLS13( finishedValue, CRYPT_MAX_HASHSIZE, 
								  &finishedValueLength, handshakeInfo, 
								  iHashContext, isServerFinished );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "createFinishedTLS13" );

	/* Make sure that the packet header is in order */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_FINISHED, finishedValueLength );
	if( cryptStatusOK( status ) )
		{
		if( length != finishedValueLength )
			{
			/* A length mis-match can only be an overflow, since an
			   underflow would be caught by checkHSPacketHeader() */
			status = CRYPT_ERROR_OVERFLOW;
			}
		else
			status = sread( stream, receivedValue, finishedValueLength );
		}
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkHSPacketHeader" );

	/* Make sure that the MAC of the transcript hash of all preceding 
	   messages is valid */
	if( compareDataConstTime( finishedValue, receivedValue, 
							  finishedValueLength ) != TRUE )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad MAC for handshake messages, handshake messages were "
				  "corrupted/modified" ) );
		}
	CFI_CHECK_UPDATE( "compareDataConstTime" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "createFinishedTLS13", 
								   "checkHSPacketHeader", 
								   "compareDataConstTime" ) );
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeFinished( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  INOUT_PTR STREAM *stream,
						  IN_HANDLE const CRYPT_CONTEXT iHashContext,
						  IN_BOOL const BOOLEAN isServerFinished )
	{
	BYTE finishedValue[ CRYPT_MAX_HASHSIZE + 8 ];
	int innerOffset, outerOffset, finishedValueLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isBooleanValue( isServerFinished ) );

	/* Create the TLS 1.3 finished value */
	status = createFinishedTLS13( finishedValue, CRYPT_MAX_HASHSIZE, 
								  &finishedValueLength, handshakeInfo, 
								  iHashContext, isServerFinished );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the TLS 1.3 finished value */
	status = startEncryptedPacketStream( sessionInfoPtr, stream, 
										 &outerOffset, &innerOffset,
										 TLS_HAND_FINISHED );
	if( cryptStatusError( status ) )
		return( status );
	status = swrite( stream, finishedValue, finishedValueLength );
	if( cryptStatusOK( status ) )
		{
		status = completeEncryptedPacketStream( sessionInfoPtr, handshakeInfo, 
												stream, outerOffset, 
												innerOffset, 
												isServerFinished );
		}
	if( cryptStatusError( status ) )
		sMemDisconnect( stream );
	return( status );
	}

/****************************************************************************
*																			*
*						Process Authentication Messages						*
*																			*
****************************************************************************/

/* Create certificate authentication messages */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int createCertAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   INOUT_PTR STREAM *stream ) 
	{
	CRYPT_CONTEXT transcriptHashContext;
	int innerOffset, outerOffset, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Write the TLS certificate chain.  We write the chain with type 
	   TLS_HAND_NONE because of the TLS 1.3 double wrapping, 
	   writeTLSCertChain() provides the inner wrapper so there's no need for 
	   the packet-stream routines to do it */
	status = startEncryptedPacketStream( sessionInfoPtr, stream, 
										 &outerOffset, NULL, TLS_HAND_NONE );
	if( cryptStatusOK( status ) )
		status = writeTLSCertChain( sessionInfoPtr, handshakeInfo, stream );
	if( cryptStatusOK( status ) )
		{
		status = completeEncryptedPacketStream( sessionInfoPtr, 
												handshakeInfo, stream, 
												outerOffset, CRYPT_UNUSED, 
												TRUE );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* Clone the hash context at the point where we've hashed
	   ClientHello || ... || ServerCertificate (server auth) or 
	   ClientHello || ... || ClientCertificate (client auth) to get the 
	   SHA-2 hash needed for the Certificate Verify message */
	status = cloneHashContext( handshakeInfo->sha2context, 
							   &transcriptHashContext );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	krnlSendMessage( transcriptHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/*	...
		Certificate Verify
		... */
	status = startEncryptedPacketStream( sessionInfoPtr, stream, 
										 &outerOffset, &innerOffset, 
										 TLS_HAND_CERTVERIFY );
	if( cryptStatusOK( status ) )
		{
		status = writeCertVerify( sessionInfoPtr, handshakeInfo, stream, 
								  transcriptHashContext );
		}
	if( cryptStatusOK( status ) )
		{
		status = completeEncryptedPacketStream( sessionInfoPtr, 
												handshakeInfo, stream, 
												outerOffset, innerOffset, 
												TRUE );
		}
	krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		sMemDisconnect( stream );
	return( status );
	}

/* Process a peer's certificate authentication, consisting of the 
   Certificate Chain and Certificate Verify messages.  This assumes that the 
   stream has already been loaded via readEncryptedHSPacket() since we need 
   to do this in order to determine whether certificate messages are 
   present */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processCertAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							INOUT_PTR STREAM *stream ) 
	{
	CRYPT_CONTEXT transcriptHashContext;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the peer's Certificate Chain */
	status = readTLSCertChain( sessionInfoPtr, handshakeInfo,
						stream, &sessionInfoPtr->iKeyexAuthContext,
						isServer( sessionInfoPtr ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readTLSCertChain" );

	/* Check the certificate chain */
	if( isServer( sessionInfoPtr ) )
		{
		/* Check the client certificate, see the comment in
		   session/tls_svr.c:readCheckClientCerts() for details */
		status = checkCertWhitelist( sessionInfoPtr, 
									 sessionInfoPtr->iKeyexAuthContext, 
									 TRUE );
		}
	else
		{
		/* Check the server certificate chain */
		status = checkTLSCertificateInfo( sessionInfoPtr );
		}
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkTLSCertificateInfo" );

	/* Clone the hash context at the point where we've hashed 
	   ClientHello || ... || ServerCertificate (server auth) or 
	   ClientHello || ... || ClientCertificate (client auth) and complete 
	   the hashing to get the SHA-2 hash */
	status = cloneHashContext( handshakeInfo->sha2context, 
							   &transcriptHashContext );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( transcriptHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/* Process the peer's Certificate Verify.  Since this is a new message
	   we disconnect the stream from the previous one and reconnect it to 
	   the new one */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, &length, 
									READHS_ACTION_NORMAL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	sMemDisconnect( stream );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	status = readCertVerify( sessionInfoPtr, handshakeInfo, stream, 
							 transcriptHashContext );
	krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
	CFI_CHECK_UPDATE( "readCertVerify" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "readTLSCertChain", 
								   "checkTLSCertificateInfo", 
								   "readCertVerify" ) );
	return( status );
	}

/****************************************************************************
*																			*
*						Complete TLS 1.3 Client Handshake 					*
*																			*
****************************************************************************/

/* Complete the TLS 1.3 client-side handshake */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int completeHandshakeClient( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
									INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	CRYPT_CONTEXT transcriptHashContext;
	STREAM stream;
	BOOLEAN needClientCert = FALSE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	
	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Set up the TLS 1.3 encryption contexts and load the keys into them */
	status = initSecurityContextsTLS( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = loadHSKeysTLS13( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "loadTLS13HSKeys" );

	/* Read the server's (dummy) Change Cipherspec.  As a client we know 
	   that we'll always get one of these since it's mandatory if we send a 
	   session ID (RFC 8446 Appendix D.4) */
	status = readDummyCCS( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* The other side has signalled the start of encryption, turn on 
	   encryption for reads */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ );

	/* Process the server's Encrypted Extensions message.  This is used by 
	   the server to send responses to non-crypto-handshake-related 
	   extensions in the client hello.  In other words the server extensions 
	   are split into two parts, ones in the server hello that affect the
	   rest of the handshake and ones here that don't, typically just an 
	   acknowledgement of the client's SNI */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, &length,
									READHS_ACTION_FIRSTENCR );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = checkHSPacketHeader( sessionInfoPtr, &stream, &length,
								  TLS_HAND_ENCRYPTED_EXTENSIONS, 
								  UINT16_SIZE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readEncryptedHSPacket" );

	/* Process the server's optional Certificate Request message */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, 
									&length, READHS_ACTION_NORMAL );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	if( sPeek( &stream ) == TLS_HAND_SERVER_CERTREQUEST )
		{
		status = readCertRequest( sessionInfoPtr, handshakeInfo, 
								  &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		needClientCert = TRUE;

		/* Read the next packet */
		status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, 
										&length, READHS_ACTION_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		}
	CFI_CHECK_UPDATE( "readCertRequest" );

	/* Process the optional Certificate Chain and Certificate Verify 
	   messages.  Since client certificate authentication implies server 
	   certificate authentication we also force this code path if no server 
	   certificate is present in order to produce an error if this is 
	   missing */
	if( sPeek( &stream ) == TLS_HAND_CERTIFICATE || needClientCert )
		{
		status = processCertAuth( sessionInfoPtr, handshakeInfo, &stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status ); 
			}
		}
	CFI_CHECK_UPDATE( "processCertAuth" );
	sMemDisconnect( &stream );

	/* Clone the hash context at the point where we've hashed 
	   ClientHello || ... || CertificateVerify and complete the hashing to 
	   get the SHA-2 hash needed for the server's Finished message */
	status = cloneHashContext( handshakeInfo->sha2context, 
							   &transcriptHashContext );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( transcriptHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/* Process the server Finished */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, 
									&length, READHS_ACTION_NORMAL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = readFinished( sessionInfoPtr, handshakeInfo,
						   &stream, transcriptHashContext, TRUE );
	sMemDisconnect( &stream );
	krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readFinished" );

	/* Create the dummy CCS that we send before we continue with the 
	   encrypted handshake */
	status = createDummyCCS( &stream, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* From now on our packets are encrypted as well, turn on encryption on
	   our side */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE );

	/* Write the optional Encrypted Client Certificate Chain and Certificate
	   Verify */
	if( needClientCert )
		{
		status = createCertAuth( sessionInfoPtr, handshakeInfo, &stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "createCertAuth" );

	/* Wrap up the hashing to get the session hash.  This stops the hashing 
	   at the Server Finished for both sides even though the Client Finished
	   is still to come, this is necessary for 0-RTT to work since the 
	   server can attach encrypted data to the end of its handshake messages
	   before it's seen the Client Finished.  Since 0-RTT is essentially
	   impossible to implement securely no-one should ever do this, but we 
	   have to live with the consequences nonetheless */
	status = completeSessionHash( handshakeInfo );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "completeSessionHash" );

	/*	Write the client Finished, setting the hash-data flag to false since 
	    this packet isn't part of the session hash */
	status = writeFinished( sessionInfoPtr, handshakeInfo, &stream, 
							handshakeInfo->sha2context, FALSE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "writeFinished" );

	/* Send the packet to the server */
	status = sendPacketTLS( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Switch from the handshake to the application data keys */
	status = loadAppdataKeysTLS13( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "loadTLS13AppdataKeys" );

	ENSURES( CFI_CHECK_SEQUENCE_9( "loadTLS13HSKeys", "readEncryptedHSPacket", 
								   "readCertRequest", "processCertAuth", 
								   "readFinished", "createCertAuth",
								   "completeSessionHash", "writeFinished", 
								   "loadTLS13AppdataKeys" ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Complete TLS 1.3 Server Handshake 					*
*																			*
****************************************************************************/

/* Complete the TLS 1.3 server-side handshake */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int completeHandshakeServer( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
									INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	CRYPT_CONTEXT transcriptHashContext;
	STREAM stream;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	BOOLEAN processedDummyCCS = FALSE;
	int innerOffset, outerOffset, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	
	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* If we're re-doing the Client Hello, run through the whole initial 
	   handshake process again */
	if( handshakeInfo->flags & HANDSHAKE_FLAG_RETRIEDCLIENTHELLO )
		{
		status = processHelloRetry( sessionInfoPtr, handshakeInfo,
									&processedDummyCCS );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Set up the TLS 1.3 encryption contexts and load the keys into them */
	status = initSecurityContextsTLS( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = loadHSKeysTLS13( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "loadTLS13HSKeys" );

	/* Create the dummy CCS that we send before we continue with the 
	   encrypted handshake */
	status = createDummyCCS( &stream, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* This was the last message not subject to security encapsulation so we 
	   turn on security for the write channel after sending it */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE );

	/* Build the encrypted handshake packets, first the encrypted extensions:

		byte		ID = TLS_HAND_ENCRYPTED_EXTENSIONS
		uint24		len
			uint16	extLen = 4
			uint16	type = TLS_EXT_SNI
			uint16	length = 0
		or:
			uint16	extLen = 0 */
	status = startEncryptedPacketStream( sessionInfoPtr, &stream, 
										 &outerOffset, &innerOffset,
										 TLS_HAND_ENCRYPTED_EXTENSIONS );
	if( cryptStatusOK( status ) )
		{
		/* If we need an SNI response then we have to write it in the
		   encrypted extensions rather than the standard extensions, 
		   otherwise we just write a zero-length value */
		if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDSNIRESPONSE )
			{
			writeUint16( &stream, UINT16_SIZE + UINT16_SIZE );
			writeUint16( &stream, TLS_EXT_SNI );
			status = writeUint16( &stream, 0 );
			}
		else
			status = writeUint16( &stream, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		status = completeEncryptedPacketStream( sessionInfoPtr, handshakeInfo, 
												&stream, outerOffset, 
												innerOffset, TRUE );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "writeUint16" );

	/*	...			(optional request for client certificate authentication)
		byte		ID = TLS_HAND_SERVER_CERTREQUEST
		uint24		len
		byte		certNonceLen = 16
		byte[]		certNonce
		uint16		extListLen
			uint16	extType = TLS_EXT_SIGNATURE_ALGORITHMS
			uint16	extLen
				uint16	algorithmListLength
					byte	hashAlgo
					byte	sigAlgo
		... */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		status = startEncryptedPacketStream( sessionInfoPtr, &stream, 
											 &outerOffset, &innerOffset, 
											 TLS_HAND_SERVER_CERTREQUEST );
		if( cryptStatusOK( status ) )
			status = writeCertRequest( sessionInfoPtr, &stream );
		if( cryptStatusOK( status ) )
			{
			status = completeEncryptedPacketStream( sessionInfoPtr, handshakeInfo, 
													&stream, outerOffset, 
													innerOffset, TRUE );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "writeCertRequest" );

	/*	...
		(optional Encrypted Server Certificate Chain and Certificate Verify)
		... 
	
	   We write the chain with type TLS_HAND_NONE because of the TLS 1.3
	   double wrapping, writeTLSCertChain() provides the inner wrapper so
	   there's no need for the packet-stream routines to do it */
	if( sessionInfoPtr->privateKey != CRYPT_ERROR )
		{
		status = createCertAuth( sessionInfoPtr, handshakeInfo, &stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "createCertAuth" );

	/* Clone the hash context at the point where we've hashed ClientHello || 
	   ... || ServerCertificateVerify and complete the hashing to get the 
	   SHA-2 hash needed for the server's Finished message */
	status = cloneHashContext( handshakeInfo->sha2context, 
							   &transcriptHashContext );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	krnlSendMessage( transcriptHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/*	...
		Finished */
	status = writeFinished( sessionInfoPtr, handshakeInfo, &stream, 
							transcriptHashContext, TRUE );
	krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "writeFinished" );

	/* Send the batch of packets to the client */
	status = sendPacketTLS( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the other side's (dummy) Change Cipherspec.  Some implementations 
	   send a bogus Change Cipherspec between the two Client Hellos rather 
	   than here on a retry so we avoid checking for one if we've already
	   processed it in the retried Client Hello */
	if( !processedDummyCCS )
		{
		status = readDummyCCS( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* The other side has signalled the start of encryption, turn on 
	   encryption for the read channel as well */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ );

	/* Process the optional Certificate Chain and Certificate Verify 
	   messages */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, 
										&length, READHS_ACTION_FIRSTENCR );
		if( cryptStatusError( status ) )
			return( status );
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		status = processCertAuth( sessionInfoPtr, handshakeInfo, &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "processCertAuth" );

	/* Wrap up the hashing to get the session hash.  This stops the hashing 
	   at the Server Finished for both sides even though the Client Finished
	   is still to come, this is necessary for 0-RTT to work since the 
	   server can attach encrypted data to the end of its handshake messages
	   before it's seen the Client Finished.  Since 0-RTT is essentially
	   impossible to implement securely no-one should ever do this, but we 
	   have to live with the consequences nonetheless */
	status = completeSessionHash( handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "completeSessionHash" );

	/* Process the client's finished */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, &length, 
						( sessionInfoPtr->cryptKeyset != CRYPT_ERROR ) ? \
						  READHS_ACTION_NOHASH : \
						  READHS_ACTION_FIRSTENCR_NOHASH );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = readFinished( sessionInfoPtr, handshakeInfo,
						   &stream, handshakeInfo->sha2context, FALSE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readFinished" );

	/* Switch from the handshake to the application data keys */
	status = loadAppdataKeysTLS13( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "loadTLS13AppdataKeys" );

	ENSURES( CFI_CHECK_SEQUENCE_9( "loadTLS13HSKeys", "writeUint16", 
								   "writeCertRequest", "createCertAuth", 
								   "writeFinished", "processCertAuth",
								   "completeSessionHash", "readFinished", 
								   "loadTLS13AppdataKeys" ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initProcessingTLS13( TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_BOOL const BOOLEAN isServer )
	{
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES_V( isBooleanValue( isServer ) );

	/* Modify the handshake completion function to the TLS 1.3 version */
	if( isServer )
		{
		FNPTR_SET( handshakeInfo->exchangeKeys, completeHandshakeServer );
		}
	else
		{
		FNPTR_SET( handshakeInfo->exchangeKeys, completeHandshakeClient );
		}
	}
#endif /* USE_TLS13 */
=======
/****************************************************************************
*																			*
*					cryptlib TLS 1.3 Handshake Management					*
*					  Copyright Peter Gutmann 2019-2022						*
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

#ifdef USE_TLS13

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Create the dummy Change Cipherspec message.  This isn't used in TLS 1.3
   but is prepended to the subsequent encrypted handshake messages to make
   the flow look like a classic TLS exchange */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createDummyCCS( OUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
										 
	/* Build the (dummy) change cipher spec packet:

		byte		type = TLS_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x03 }
		uint16		len = 1
		byte		1

	   Since Change Cipherspec is its own protocol, we use TLS-level packet
	   encoding rather than handshake protocol-level encoding */
	status = openPacketStreamTLS( stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
								  TLS_MSG_CHANGE_CIPHER_SPEC );
	if( cryptStatusError( status ) )
		return( status );
	status = sputc( stream, 1 );
	if( cryptStatusOK( status ) )
		status = completePacketStreamTLS( stream, 0 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readDummyCCS( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	int length, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Process the other side's Change Cipherspec:

		byte		type = TLS_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x03 }
		uint16		len = 1
		byte		1 */
	status = readHSPacketTLS( sessionInfoPtr, NULL, &length,
							  TLS_MSG_CHANGE_CIPHER_SPEC );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	value = sgetc( &stream );
	sMemDisconnect( &stream );
	if( value != 1 )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid change cipher spec packet payload, expected "
				  "0x01, got 0x%02X", value ) );
		}

	return( CRYPT_OK );
	}

/* Complete the session hash for the handshake messages.  Note that this 
   differs from the TLS-wide createSessionHash() which simply extracts the
   hash state at the current time and allows the hashing to continue */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completeSessionHash( IN_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	/* Wrap up the session hashing and get the value */
	status = krnlSendMessage( handshakeInfo->sha2context, IMESSAGE_CTX_HASH, 
							  "", 0 );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, handshakeInfo->sessionHash, 
					CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( handshakeInfo->sha2context, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	handshakeInfo->sessionHashSize = msgData.length;
	DEBUG_DUMP_DATA_LABEL( ( handshakeInfo->tls13SuiteInfoPtr != NULL ) ? \
								"Session hash (client):" : \
								"Session hash (server):", 
						   handshakeInfo->sessionHash, 
						   handshakeInfo->sessionHashSize );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Process Hello Retry							*
*																			*
****************************************************************************/

/* We shouldn't ever have to do a Hello Retry because we always do the MTI 
   P256, however alongside assorted other braindamage Google Chrome always 
   connects using 25519 and nothing else which forces a retry on every 
   single connect.  The following reruns the first half of the TLS 1.3 
   handshake in order to allow Google Chrome to connect */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processHelloRetry( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							  OUT_BOOL BOOLEAN *processedDummyCCS )
	{
	STREAM *stream = &handshakeInfo->stream;
	MESSAGE_DATA msgData;
	HASH_FUNCTION hashFunction;
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	HASHINFO hashInfo;
	BYTE hashBuffer[ 8 + CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	TLSHELLO_ACTION_TYPE actionType;
	int clientHelloLength, serverHelloLength DUMMY_INIT;
	int hashSize, packetOffset, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( processedDummyCCS, sizeof( BOOLEAN ) ) );

	/* Clear return value */
	*processedDummyCCS = FALSE;

	/* Re-hash the Client and Server Hello messages with SHA-256 as before, 
	   but leaving the hash open so that we can hash in the retried ones as 
	   well.
	   
	   In another one of TLS 1.3's many clever tricks, what's hashed is no 
	   longer the same as what's hashed for a normal message flow but a hash
	   of the first Client Hello with a pseudo-header prepended to it with
	   the purported goal of allowing stateless retries.  This overwrites 
	   the original hash value with the modified form:

		Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
			Hash(message_hash ||	// Handshake type = 254
			00 00 Hash.length  ||	// Handshake message [sic] length = uint24
			Hash(ClientHello1) ||	// Hash of ClientHello1 = 32-byte hash
			HelloRetryRequest  || ... || Mn)

	   In binary the pseudo-header that's prepended to the hash of the 
	   Client Hello is { 0xFE 0x00 0x00 0x20 }.  Note that the comment for 
	   the uint24 length in the spec is wrong, it's the length of the hash 
	   value, not the length of the handshake message */
	memcpy( hashBuffer, "\xFE\x00\x00\x20", 4 );
	getHashAtomicParameters( CRYPT_ALGO_SHA2, bitsToBytes( 256 ), 
							 &hashFunctionAtomic, &hashSize );
	hashFunctionAtomic( hashBuffer + 4, CRYPT_MAX_HASHSIZE, 
						sessionInfoPtr->receiveBuffer, 
						handshakeInfo->originalClientHelloLength );
	getHashParameters( CRYPT_ALGO_SHA2, bitsToBytes( 256 ), &hashFunction, 
					   &hashSize );
	hashFunction( hashInfo, NULL, 0, hashBuffer, 4 + hashSize, 
				  HASH_STATE_START );
	hashFunction( hashInfo, NULL, 0, 
				  sessionInfoPtr->sendBuffer + TLS_HEADER_SIZE, 
				  handshakeInfo->originalServerHelloLength, 
				  HASH_STATE_CONTINUE );
	CFI_CHECK_UPDATE( "hashFunction 1" );

	/* The session hash calculations are run in parallel to the hello hash
	   calculations so we also have to re-hash the modified form of the 
	   Client and Server Hello for the session hash */
	status = krnlSendMessage( handshakeInfo->sha2context, 
							  IMESSAGE_DELETEATTRIBUTE, NULL, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( handshakeInfo->sha2context,
								  IMESSAGE_CTX_HASH, hashBuffer,
								  4 + hashSize );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( handshakeInfo->sha2context,
							IMESSAGE_CTX_HASH, 
							sessionInfoPtr->sendBuffer + TLS_HEADER_SIZE,
							handshakeInfo->originalServerHelloLength );
		}
	ENSURES( cryptStatusOK( status ) );
	CFI_CHECK_UPDATE( "hashFunction 2" );

	/* Some implementations, most notably Google Chrome, send a bogus Change 
	   Cipherspec at this point.  The RFC says (section 4.2.2) that "when a 
	   server is operating statelessly, it may receive an unprotected record 
	   of type change_cipher_spec between the first and second ClientHello".  
	   It never specifies how a client is supposed to tell when a server is 
	   operating statelessly but since the text is in the section that 
	   discusses the Cookie extension it presumably means that it applies 
	   when the server has sent this extension to the client.  We haven't 
	   sent it but implementations like Chrome send the Change Cipherspec 
	   anyway */
	status = readHSPacketTLS( sessionInfoPtr, handshakeInfo,
							  &clientHelloLength, TLS_MSG_TLS13_HELLORETRY );
	if( cryptStatusError( status ) )
		return( status );
	if( clientHelloLength == 1 && \
		sessionInfoPtr->receiveBuffer[ 0 ] == 0x01 )
		{
		/* Although this CCS is now part of the handshake message flow it 
		   doesn't get included in the transcript hash */
	/*	hashFunction( hashInfo, NULL, 0, "0x01", 1, HASH_STATE_CONTINUE ); */

		/* This was a bogus Change Cipherspec, let the caller know and 
		   re-read the next message, which should be the Client Hello that 
		   we're expecting */
		*processedDummyCCS = TRUE;
		status = readHSPacketTLS( sessionInfoPtr, handshakeInfo,
								  &clientHelloLength, TLS_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			return( status );
		}
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, clientHelloLength );
	status = processHelloTLS( sessionInfoPtr, handshakeInfo, stream,
							  &actionType, TRUE );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		{
		REQUIRES( status != OK_SPECIAL );

		return( status );
		}
	CFI_CHECK_UPDATE( "processHelloTLS" );

	/* Re-clear all of the flags that we don't want for TLS 1.3 */
	handshakeInfo->flags &= \
			~( HANDSHAKE_FLAG_NEEDRENEGRESPONSE | \
			   HANDSHAKE_FLAG_NEEDETMRESPONSE | \
			   HANDSHAKE_FLAG_NEEDEMSRESPONSE | \
			   HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE );
	handshakeInfo->sendECCPointExtn = FALSE;

	/* Since we've now refreshed the Client Hello state, in other words 
	   treated the retried Client Hello as a new, original Client Hello, we
	   clear the retried-hello indicator */
	handshakeInfo->flags &= ~HANDSHAKE_FLAG_RETRIEDCLIENTHELLO;

	/* Get the nonce that's used to randomise all crypto operations.  We 
	   previously sent a magic-value non-nonce that's used to indicate that
	   the Server Hello is really a Hello Retry Request rather than a Server 
	   Hello, now we use an actual nonce */
	setMessageData( &msgData, handshakeInfo->serverNonce, TLS_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the real TLS 1.3 Server Hello:

		byte		ID = TLS_HAND_SERVER_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x03 }
		byte[32]	nonce
		byte		sessIDlen
			byte[]	sessID
		uint16		suite
		byte		copr = 0
		uint16	extListLen
			byte	extType
			uint16	extLen
			byte[]	extData 

	   Note that although the session ID isn't used since we know at this 
	   point that it's TLS 1.3 and not any earlier version, we still have to
	   send it if the client sent it in their hello for TLS 1.2 camouflage
	   reasons */
	status = openPacketStreamTLS( stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
								  TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	status = continueHSPacketStream( stream, TLS_HAND_SERVER_HELLO,
									 &packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	sputc( stream, TLS_MAJOR_VERSION );
	sputc( stream, TLS_MINOR_VERSION_TLS12 );
	swrite( stream, handshakeInfo->serverNonce, TLS_NONCE_SIZE );
	sputc( stream, handshakeInfo->sessionIDlength );
	if( handshakeInfo->sessionIDlength > 0 )
		{
		swrite( stream, handshakeInfo->sessionID, 
				handshakeInfo->sessionIDlength );
		}
	writeUint16( stream, handshakeInfo->cipherSuite );
	status = sputc( stream, 0 );	/* No compression */
	if( cryptStatusOK( status ) )
		{
		status = writeServerExtensions( stream, sessionInfoPtr, 
										handshakeInfo );
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, TLS_HEADER_SIZE,
											  &serverHelloLength );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "serverHello" );

	/* Hash the re-sent Client and Server Hello messages onto the end of the
	   original Client and Server Hello and wrap up the hashing to get the
	   hello hash */
	hashFunction( hashInfo, NULL, 0, sessionInfoPtr->receiveBuffer,
				  clientHelloLength, HASH_STATE_CONTINUE );
	hashFunction( hashInfo, handshakeInfo->helloHash, CRYPT_MAX_HASHSIZE,
				  sessionInfoPtr->sendBuffer + TLS_HEADER_SIZE,
				  serverHelloLength, HASH_STATE_END );
	handshakeInfo->helloHashSize = hashSize;
	DEBUG_DUMP_DATA_LABEL( "Client/Server hello hash (server):",
						   handshakeInfo->helloHash,
						   handshakeInfo->helloHashSize );
	CFI_CHECK_UPDATE( "hashFunction 3" );

	/* Send the redone Server Hello to the client */
	status = sendPacketTLS( sessionInfoPtr, stream, FALSE );
	if( cryptStatusOK( status ) )
		status = hashHSPacketWrite( handshakeInfo, stream, 0 );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "sendPacketTLS" );

	ENSURES( CFI_CHECK_SEQUENCE_6( "hashFunction 1", "hashFunction 2", 
								   "processHelloTLS", "serverHello", 
								   "hashFunction 3", "sendPacketTLS" ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read/Write Encrypted Handshake Packets				*
*																			*
****************************************************************************/

/* Read an encrypted handshake packet.  Since these are stuffed inside 
   application data packets we have to read what are actually handshake 
   packets as application-data packets */

typedef enum {
	READHS_ACTION_NONE,			/* No handshake read action */
	READHS_ACTION_NORMAL,		/* Normal handling */
	READHS_ACTION_FIRSTENCR,	/* First encrypted packet */
	READHS_ACTION_FIRSTENCR_NOHASH,/* First encr.+ don't hash payload */
	READHS_ACTION_NOHASH,		/* Normal handling + don't hash payload */
	READHS_ACTION_LAST			/* Last possible read action */
	} READHS_ACTION_TYPE;

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readEncryptedHSPacket( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								  TLS_HANDSHAKE_INFO *handshakeInfo,
								  OUT_LENGTH_BOUNDED_Z( MAX_PACKET_SIZE ) \
										int *payloadLength, 
								  IN_ENUM( READHS_ACTION ) \
										const READHS_ACTION_TYPE actionType )
	{
	STREAM stream;
	const BOOLEAN isFirstEncrypted = \
			( actionType == READHS_ACTION_FIRSTENCR || \
			  actionType == READHS_ACTION_FIRSTENCR_NOHASH ) ? TRUE : FALSE;
	int actualPacketType, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( payloadLength, sizeof( int ) ) );

	REQUIRES( isEnumRange( actionType, READHS_ACTION ) );

	/* Clear return value */
	*payloadLength = 0;

	/* Process the other side's encrypted handshake data.  Since this is
	   an encrypted blob at this point we pass in a NULL pointer in place of
	   the handshakeInfo when we call readHSPacketTLS() to prevent hashing 
	   of the message data, we can't hash it until later when it's been
	   decrypted and unpacked.
	
	   If we're reading the first encrypted message then this is the first 
	   chance that we have to test whether our crypto keys are set up 
	   correctly, so we report problems with decryption or MACing or a 
	   failure to find any recognisable header as a wrong key rather than a 
	   bad data error.  In addition we signal the fact that the other side 
	   may respond unexpectedly because of the use of encryption to 
	   readHSPacketTLS() by specifying a special-case packet type, see the 
	   comment in readHSPacketTLS() for how this is handled and why it's 
	   necessary.
	
	   Since we've now turned on crypto, all errors are fatal crypto 
	   errors */
	status = readHSPacketTLS( sessionInfoPtr, NULL, &length, 
							  isFirstEncrypted ? \
								TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE : \
								TLS_MSG_APPLICATION_DATA );
	if( cryptStatusError( status ) )
		return( status );
	status = unwrapPacketTLS13( sessionInfoPtr, sessionInfoPtr->receiveBuffer, 
								length, &length, &actualPacketType,
								TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		{
		registerCryptoFailure();

		if( isFirstEncrypted && \
			( status == CRYPT_ERROR_BADDATA || \
			  status == CRYPT_ERROR_SIGNATURE ) )
			{
			retExtErr( CRYPT_ERROR_WRONGKEY,
					   ( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						 SESSION_ERRINFO, 
						 "Decrypted data was corrupt, probably due to "
						 "incorrect handshake encryption keys being "
						 "negotiated" ) );
			}
		return( status );
		}
	ENSURES( isShortIntegerRangeMin( length, 2 ) );
			 /* Guaranteed by unwrapPacketTLS13() */

	/* Because of TLS 1.3's camouflage-wrapping what we're getting could be 
	   an Alert.  This fact is cunningly hidden from anyone who doesn't know
	   that only an Alert can be this size */
	if( actualPacketType == TLS_MSG_ALERT )
		{
		return( processAlertTLS13( sessionInfoPtr, 
								   sessionInfoPtr->receiveBuffer, 2, 
								   NULL ) );
		}

	/* Now that we've got the handshake message data we can hash it */
	if( actionType != READHS_ACTION_FIRSTENCR_NOHASH && \
		actionType != READHS_ACTION_NOHASH )
		{
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		status = hashHSPacketRead( handshakeInfo, &stream );
		sMemDisconnect( &stream );
		}
	if( cryptStatusOK( status ) )
		*payloadLength = length;
	return( status );
	}

/* Because TLS 1.3 stuffs extra content into an encrypted packet, it's no 
   longer possible to have multiple handshake subpackets inside a single 
   encapsulating TLS_MSG_HANDSHAKE packet because that provides no way to
   record where the extra information that's tacked onto the end of each
   handshake subpacket finishes.  To deal with this we have to individually
   gift-wrap each subpacket in its own handshake packet, defeating at least
   some of the encryption of handshake messages because it makes traffic
   analysis a lot easier.

   The gift-wrapping is handled by the following two functions, with the
   inner wrapping optional when called in conjunction with functions that 
   perform it themselves, indicated by setting the sub-packet type to
   TLS_HAND_NONE */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int startEncryptedPacketStream( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
									   INOUT_PTR STREAM *stream, 
									   OUT_LENGTH_SHORT_Z int *outerOffset, 
									   OUT_OPT_LENGTH_SHORT_Z int *innerOffset,
									   IN_RANGE( TLS_HAND_NONE, \
												 TLS_HAND_LAST ) \
											const int subPacketType )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( outerOffset, sizeof( int ) ) );
	assert( innerOffset == NULL || \
			isWritePtr( innerOffset, sizeof( int ) ) );

	REQUIRES( ( subPacketType == TLS_HAND_NONE && \
				innerOffset == NULL ) || \
			  ( isEnumRange( subPacketType, TLS_HAND ) && \
				innerOffset != NULL ) );

	/* Clear return values */
	*outerOffset = CRYPT_ERROR;
	if( innerOffset != NULL )
		*innerOffset = CRYPT_ERROR;

	/* Write the outer wrapper, the camouflage application-data packet, and 
	   the optional inner wrapper containing the handshake subtype */
	status = continuePacketStreamTLS( stream, sessionInfoPtr,
									  TLS_MSG_APPLICATION_DATA, outerOffset );
	if( cryptStatusOK( status ) && subPacketType != TLS_HAND_NONE )
		{
		status = continueHSPacketStream( stream, subPacketType, 
										 innerOffset );
		}

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int completeEncryptedPacketStream( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
										  IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo,
										  INOUT_PTR STREAM *stream, 
										  IN_LENGTH_SHORT const int outerOffset, 
										  IN_LENGTH_SHORT_OPT const int innerOffset,
										  IN_BOOL const BOOLEAN hashData )
	{
	int status = CRYPT_OK;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isShortIntegerRange( outerOffset ) );
	REQUIRES( innerOffset == CRYPT_UNUSED || \
			  isShortIntegerRange( innerOffset ) );
	REQUIRES( isBooleanValue( hashData ) );

	/* Wrap up the inner and outer wrappers.  We optionally skip the hashing 
	   of the packet data for packets that aren't part of the session hash */
	if( innerOffset != CRYPT_UNUSED )
		status = completeHSPacketStream( stream, innerOffset );
	if( cryptStatusOK( status ) && hashData )
		status = hashHSPacketWrite( handshakeInfo, stream, outerOffset );
	if( cryptStatusOK( status ) )
		{
		status = wrapPacketTLS13( sessionInfoPtr, stream, outerOffset,
								  TLS_MSG_HANDSHAKE );
		}
	
	return( status );
	}

/****************************************************************************
*																			*
*						Read/Write Authentication Messages					*
*																			*
****************************************************************************/

/* Read and write the TLS 1.3 certificate verify message, a signature on a 
   hash of all the handshake messages so far:

	uint16		algorithm
	uint16		sigLen
		byte[]	sig */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   INOUT_PTR STREAM *stream,
						   IN_HANDLE const CRYPT_CONTEXT iHashContext )
	{
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );

	/* Make sure that the packet header is in order */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_CERTVERIFY, 
								  UINT16_SIZE + MIN_PKCSIZE_ECC );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the TLS 1.3 session hash.  If we're the server then we're
	   verifying the client's certificate verify so we set the 
	   isServerVerify value to FALSE */
	status = createSessionHashTLS13( handshakeInfo, iHashContext,
									 isServer( sessionInfoPtr ) ? \
										FALSE : TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Verify the signature on the session hash */
	status = checkCertVerify( sessionInfoPtr, handshakeInfo, stream, 
							  length );
	destroySessionHash( handshakeInfo );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							INOUT_PTR STREAM *stream,
							IN_HANDLE const CRYPT_CONTEXT iHashContext )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );

	/* Create the TLS 1.3 session hash.  If we're the server then we're
	   creating the server's certificate verify so we set the isServerVerify 
	   value to TRUE */
	status = createSessionHashTLS13( handshakeInfo, iHashContext,
									 isServer( sessionInfoPtr ) ? \
										TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the signature on the hash of the transcript hash */
	status = createCertVerify( sessionInfoPtr, handshakeInfo, stream );
	destroySessionHash( handshakeInfo );

	return( status );
	}

/* Read and write the TLS 1.3 certificate request:

	  [	byte		ID = TLS_HAND_SERVER_CERTREQUEST ]
	  [	uint24		len				-- Written by caller ]
		byte		certNonceLen = 16
		byte[]		certNonce
		uint16		extListLen
			uint16	extType = TLS_EXT_SIGNATURE_ALGORITHMS
			uint16	extLen
				uint16	algorithmListLength
					uint16[] algorithms

   After extending the original mostly good-enough form with extra cruft in
   TLS 1.2, TLS 1.3 went the X.509 route and added full-on extensions to
   the request, of which only one is defined, SignatureAlgorithms, which 
   does the same as what the TLS 1.2 addition did but now it's in a full
   extension.

   See the long comment in session/tls_ext_rw.c on the giant mess that is 
   the SignatureAlgorithms extension */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readCertRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							INOUT_PTR STREAM *stream )
	{
	int packetLength, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Make sure that the packet header is in order.  We need at least 8 
	   bytes of certificate nonce and at least one extension, that being
	   TLS_EXT_SIGNATURE_ALGORITHMS */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &packetLength,
								  TLS_HAND_SERVER_CERTREQUEST, 
								  ( 1 + 8 ) + UINT16_SIZE + \
									( UINT16_SIZE * 4 ) );
	if( cryptStatusError( status ) )
		return( status );
	status = length = sgetc( stream );
	if( !cryptStatusError( status ) )
		{
		if( length < 1 || length > CRYPT_MAX_HASHSIZE || \
			1 + length + ( UINT16_SIZE * 5 ) > packetLength )
			status = CRYPT_ERROR_BADDATA;
		}
	if( !cryptStatusError( status ) )
		status = sread( stream, handshakeInfo->tls13CertContext, length );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate request certificate-nonce "
				  "information" ) );
		}
	handshakeInfo->tls13CertContextLen = length;
	packetLength -= length + 1;
	ENSURES( isShortIntegerRangeMin( packetLength, UINT16_SIZE * 5 ) );

	/* Read the extensions:

		uint16		extListLen
			[...]
			uint16	extType = TLS_EXT_SIGNATURE_ALGORITHMS
			uint16	extLen
				uint16	algorithmListLength
					uint16[] algorithms
			[...]

	   The only thing that's defined to be present here is the 
	   TLS_EXT_SIGNATURE_ALGORITHMS extension and for that the contents are
	   more or less irrelevant, see the comment in 
	   session/tls_cli.c:processCertRequest() for details, so all we do is
	   make sure that there's at least one extension of the right shape to
	   count as a TLS_EXT_SIGNATURE_ALGORITHMS present and ignore everything
	   else */
	status = length = readUint16( stream );
	if( !cryptStatusError( status ) )
		{
		if( length < ( UINT16_SIZE * 3 ) || length > packetLength )
			status = CRYPT_ERROR_BADDATA;
		}
	if( !cryptStatusError( status ) )
		status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate request signature/hash "
				  "algorithm information" ) );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCertRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							 INOUT_PTR STREAM *stream )
	{
	MESSAGE_DATA msgData;
	const BOOLEAN rsaAvailable = algoAvailable( CRYPT_ALGO_RSA ) ? \
								 TRUE : FALSE;
	const BOOLEAN dsaAvailable = algoAvailable( CRYPT_ALGO_DSA ) ? \
								 TRUE : FALSE;
	const BOOLEAN ecdsaAvailable = algoAvailable( CRYPT_ALGO_ECDSA ) ? \
								   TRUE : FALSE;
	const int extensionPayloadSize = \
					( rsaAvailable ? ( UINT16_SIZE * 3 ) : 0 ) + \
					( dsaAvailable ? UINT16_SIZE : 0 ) + \
					( ecdsaAvailable ? UINT16_SIZE : 0 );
	BYTE nonceBuffer[ 8 + 8 ];
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isBooleanValue( rsaAvailable ) );

	/* Write the nonce/identifier value.  This isn't used in any 
	   cryptographic computations but is used to identify which certificate 
	   belongs to which request in something that presumably satisfies some 
	   business case for someone on the standards committee */
	setMessageData( &msgData, nonceBuffer, 8 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );
	sputc( stream, 8 );
	status = swrite( stream, nonceBuffer, 8 );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the extension wrapper.  We don't need a full-blown 
	   writeExtensions() here since all we need to write is a minimal
	   SignatureAlgorithms, for which we begin by writing the wrapper */
	writeUint16( stream, UINT16_SIZE + UINT16_SIZE + \
						 UINT16_SIZE + extensionPayloadSize );
	writeUint16( stream, TLS_EXT_SIGNATURE_ALGORITHMS );
	status = writeUint16( stream, UINT16_SIZE + extensionPayloadSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the list of accepted signature and hash algorithms.  In theory 
	   we could write the full list of algorithms, but thanks to TLS' 
	   braindamaged way of handling certificate-based authentication 
	   (see the comment in session/tls_svr.c:writeCertRequest()) this would
	   make the certificate-authentication process unmanageable.  To get 
	   around this we only allow one single algorithm, the de facto 
	   universal-standard SHA-2 */
	writeUint16( stream, extensionPayloadSize );
	if( rsaAvailable )
		{
		writeUint16( stream, TLS_SIGHASHALGO_RSAPKCS1_SHA2 );
		writeUint16( stream, TLS_SIGHASHALGO_RSAPSSoid1_SHA2 );
		status = writeUint16( stream, TLS_SIGHASHALGO_RSAPSSoid2_SHA2 );
		}
	if( dsaAvailable )
		status = writeUint16( stream, TLS_SIGHASHALGO_DSA_SHA2 );
	if( ecdsaAvailable )
		status = writeUint16( stream, TLS_SIGHASHALGO_ECDSA_SHA2 );
	return( status );
	}

/* Read and write the TLS 1.3 finished message, a MAC of the hash of all the 
   handshake messages so far:

	byte[]	finished_data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readFinished( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 INOUT_PTR STREAM *stream,
						 IN_HANDLE const CRYPT_CONTEXT iHashContext,
						 IN_BOOL const BOOLEAN isServerFinished )
	{
	BYTE finishedValue[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE receivedValue[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int finishedValueLength, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isBooleanValue( isServerFinished ) );

	/* Create the TLS 1.3 finished value */
	status = createFinishedTLS13( finishedValue, CRYPT_MAX_HASHSIZE, 
								  &finishedValueLength, handshakeInfo, 
								  iHashContext, isServerFinished );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "createFinishedTLS13" );

	/* Make sure that the packet header is in order */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_FINISHED, finishedValueLength );
	if( cryptStatusOK( status ) )
		{
		if( length != finishedValueLength )
			{
			/* A length mis-match can only be an overflow, since an
			   underflow would be caught by checkHSPacketHeader() */
			status = CRYPT_ERROR_OVERFLOW;
			}
		else
			status = sread( stream, receivedValue, finishedValueLength );
		}
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkHSPacketHeader" );

	/* Make sure that the MAC of the transcript hash of all preceding 
	   messages is valid */
	if( compareDataConstTime( finishedValue, receivedValue, 
							  finishedValueLength ) != TRUE )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad MAC for handshake messages, handshake messages were "
				  "corrupted/modified" ) );
		}
	CFI_CHECK_UPDATE( "compareDataConstTime" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "createFinishedTLS13", 
								   "checkHSPacketHeader", 
								   "compareDataConstTime" ) );
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeFinished( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  INOUT_PTR STREAM *stream,
						  IN_HANDLE const CRYPT_CONTEXT iHashContext,
						  IN_BOOL const BOOLEAN isServerFinished )
	{
	BYTE finishedValue[ CRYPT_MAX_HASHSIZE + 8 ];
	int innerOffset, outerOffset, finishedValueLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isBooleanValue( isServerFinished ) );

	/* Create the TLS 1.3 finished value */
	status = createFinishedTLS13( finishedValue, CRYPT_MAX_HASHSIZE, 
								  &finishedValueLength, handshakeInfo, 
								  iHashContext, isServerFinished );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the TLS 1.3 finished value */
	status = startEncryptedPacketStream( sessionInfoPtr, stream, 
										 &outerOffset, &innerOffset,
										 TLS_HAND_FINISHED );
	if( cryptStatusError( status ) )
		return( status );
	status = swrite( stream, finishedValue, finishedValueLength );
	if( cryptStatusOK( status ) )
		{
		status = completeEncryptedPacketStream( sessionInfoPtr, handshakeInfo, 
												stream, outerOffset, 
												innerOffset, 
												isServerFinished );
		}
	if( cryptStatusError( status ) )
		sMemDisconnect( stream );
	return( status );
	}

/****************************************************************************
*																			*
*						Process Authentication Messages						*
*																			*
****************************************************************************/

/* Create certificate authentication messages */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int createCertAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   INOUT_PTR STREAM *stream ) 
	{
	CRYPT_CONTEXT transcriptHashContext;
	int innerOffset, outerOffset, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Write the TLS certificate chain.  We write the chain with type 
	   TLS_HAND_NONE because of the TLS 1.3 double wrapping, 
	   writeTLSCertChain() provides the inner wrapper so there's no need for 
	   the packet-stream routines to do it */
	status = startEncryptedPacketStream( sessionInfoPtr, stream, 
										 &outerOffset, NULL, TLS_HAND_NONE );
	if( cryptStatusOK( status ) )
		status = writeTLSCertChain( sessionInfoPtr, handshakeInfo, stream );
	if( cryptStatusOK( status ) )
		{
		status = completeEncryptedPacketStream( sessionInfoPtr, 
												handshakeInfo, stream, 
												outerOffset, CRYPT_UNUSED, 
												TRUE );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* Clone the hash context at the point where we've hashed
	   ClientHello || ... || ServerCertificate (server auth) or 
	   ClientHello || ... || ClientCertificate (client auth) to get the 
	   SHA-2 hash needed for the Certificate Verify message */
	status = cloneHashContext( handshakeInfo->sha2context, 
							   &transcriptHashContext );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	krnlSendMessage( transcriptHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/*	...
		Certificate Verify
		... */
	status = startEncryptedPacketStream( sessionInfoPtr, stream, 
										 &outerOffset, &innerOffset, 
										 TLS_HAND_CERTVERIFY );
	if( cryptStatusOK( status ) )
		{
		status = writeCertVerify( sessionInfoPtr, handshakeInfo, stream, 
								  transcriptHashContext );
		}
	if( cryptStatusOK( status ) )
		{
		status = completeEncryptedPacketStream( sessionInfoPtr, 
												handshakeInfo, stream, 
												outerOffset, innerOffset, 
												TRUE );
		}
	krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		sMemDisconnect( stream );
	return( status );
	}

/* Process a peer's certificate authentication, consisting of the 
   Certificate Chain and Certificate Verify messages.  This assumes that the 
   stream has already been loaded via readEncryptedHSPacket() since we need 
   to do this in order to determine whether certificate messages are 
   present */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processCertAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							INOUT_PTR STREAM *stream ) 
	{
	CRYPT_CONTEXT transcriptHashContext;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the peer's Certificate Chain */
	status = readTLSCertChain( sessionInfoPtr, handshakeInfo,
						stream, &sessionInfoPtr->iKeyexAuthContext,
						isServer( sessionInfoPtr ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readTLSCertChain" );

	/* Check the certificate chain */
	if( isServer( sessionInfoPtr ) )
		{
		/* Check the client certificate, see the comment in
		   session/tls_svr.c:readCheckClientCerts() for details */
		status = checkCertWhitelist( sessionInfoPtr, 
									 sessionInfoPtr->iKeyexAuthContext, 
									 TRUE );
		}
	else
		{
		/* Check the server certificate chain */
		status = checkTLSCertificateInfo( sessionInfoPtr );
		}
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkTLSCertificateInfo" );

	/* Clone the hash context at the point where we've hashed 
	   ClientHello || ... || ServerCertificate (server auth) or 
	   ClientHello || ... || ClientCertificate (client auth) and complete 
	   the hashing to get the SHA-2 hash */
	status = cloneHashContext( handshakeInfo->sha2context, 
							   &transcriptHashContext );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( transcriptHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/* Process the peer's Certificate Verify.  Since this is a new message
	   we disconnect the stream from the previous one and reconnect it to 
	   the new one */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, &length, 
									READHS_ACTION_NORMAL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	sMemDisconnect( stream );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	status = readCertVerify( sessionInfoPtr, handshakeInfo, stream, 
							 transcriptHashContext );
	krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
	CFI_CHECK_UPDATE( "readCertVerify" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "readTLSCertChain", 
								   "checkTLSCertificateInfo", 
								   "readCertVerify" ) );
	return( status );
	}

/****************************************************************************
*																			*
*						Complete TLS 1.3 Client Handshake 					*
*																			*
****************************************************************************/

/* Complete the TLS 1.3 client-side handshake */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int completeHandshakeClient( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
									INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	CRYPT_CONTEXT transcriptHashContext;
	STREAM stream;
	BOOLEAN needClientCert = FALSE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	
	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Set up the TLS 1.3 encryption contexts and load the keys into them */
	status = initSecurityContextsTLS( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = loadHSKeysTLS13( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "loadTLS13HSKeys" );

	/* Read the server's (dummy) Change Cipherspec.  As a client we know 
	   that we'll always get one of these since it's mandatory if we send a 
	   session ID (RFC 8446 Appendix D.4) */
	status = readDummyCCS( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* The other side has signalled the start of encryption, turn on 
	   encryption for reads */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ );

	/* Process the server's Encrypted Extensions message.  This is used by 
	   the server to send responses to non-crypto-handshake-related 
	   extensions in the client hello.  In other words the server extensions 
	   are split into two parts, ones in the server hello that affect the
	   rest of the handshake and ones here that don't, typically just an 
	   acknowledgement of the client's SNI */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, &length,
									READHS_ACTION_FIRSTENCR );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = checkHSPacketHeader( sessionInfoPtr, &stream, &length,
								  TLS_HAND_ENCRYPTED_EXTENSIONS, 
								  UINT16_SIZE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readEncryptedHSPacket" );

	/* Process the server's optional Certificate Request message */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, 
									&length, READHS_ACTION_NORMAL );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	if( sPeek( &stream ) == TLS_HAND_SERVER_CERTREQUEST )
		{
		status = readCertRequest( sessionInfoPtr, handshakeInfo, 
								  &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		needClientCert = TRUE;

		/* Read the next packet */
		status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, 
										&length, READHS_ACTION_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		}
	CFI_CHECK_UPDATE( "readCertRequest" );

	/* Process the optional Certificate Chain and Certificate Verify 
	   messages.  Since client certificate authentication implies server 
	   certificate authentication we also force this code path if no server 
	   certificate is present in order to produce an error if this is 
	   missing */
	if( sPeek( &stream ) == TLS_HAND_CERTIFICATE || needClientCert )
		{
		status = processCertAuth( sessionInfoPtr, handshakeInfo, &stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status ); 
			}
		}
	CFI_CHECK_UPDATE( "processCertAuth" );
	sMemDisconnect( &stream );

	/* Clone the hash context at the point where we've hashed 
	   ClientHello || ... || CertificateVerify and complete the hashing to 
	   get the SHA-2 hash needed for the server's Finished message */
	status = cloneHashContext( handshakeInfo->sha2context, 
							   &transcriptHashContext );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( transcriptHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/* Process the server Finished */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, 
									&length, READHS_ACTION_NORMAL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = readFinished( sessionInfoPtr, handshakeInfo,
						   &stream, transcriptHashContext, TRUE );
	sMemDisconnect( &stream );
	krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readFinished" );

	/* Create the dummy CCS that we send before we continue with the 
	   encrypted handshake */
	status = createDummyCCS( &stream, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* From now on our packets are encrypted as well, turn on encryption on
	   our side */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE );

	/* Write the optional Encrypted Client Certificate Chain and Certificate
	   Verify */
	if( needClientCert )
		{
		status = createCertAuth( sessionInfoPtr, handshakeInfo, &stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "createCertAuth" );

	/* Wrap up the hashing to get the session hash.  This stops the hashing 
	   at the Server Finished for both sides even though the Client Finished
	   is still to come, this is necessary for 0-RTT to work since the 
	   server can attach encrypted data to the end of its handshake messages
	   before it's seen the Client Finished.  Since 0-RTT is essentially
	   impossible to implement securely no-one should ever do this, but we 
	   have to live with the consequences nonetheless */
	status = completeSessionHash( handshakeInfo );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "completeSessionHash" );

	/*	Write the client Finished, setting the hash-data flag to false since 
	    this packet isn't part of the session hash */
	status = writeFinished( sessionInfoPtr, handshakeInfo, &stream, 
							handshakeInfo->sha2context, FALSE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "writeFinished" );

	/* Send the packet to the server */
	status = sendPacketTLS( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Switch from the handshake to the application data keys */
	status = loadAppdataKeysTLS13( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "loadTLS13AppdataKeys" );

	ENSURES( CFI_CHECK_SEQUENCE_9( "loadTLS13HSKeys", "readEncryptedHSPacket", 
								   "readCertRequest", "processCertAuth", 
								   "readFinished", "createCertAuth",
								   "completeSessionHash", "writeFinished", 
								   "loadTLS13AppdataKeys" ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Complete TLS 1.3 Server Handshake 					*
*																			*
****************************************************************************/

/* Complete the TLS 1.3 server-side handshake */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int completeHandshakeServer( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
									INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	CRYPT_CONTEXT transcriptHashContext;
	STREAM stream;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	BOOLEAN processedDummyCCS = FALSE;
	int innerOffset, outerOffset, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	
	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* If we're re-doing the Client Hello, run through the whole initial 
	   handshake process again */
	if( handshakeInfo->flags & HANDSHAKE_FLAG_RETRIEDCLIENTHELLO )
		{
		status = processHelloRetry( sessionInfoPtr, handshakeInfo,
									&processedDummyCCS );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Set up the TLS 1.3 encryption contexts and load the keys into them */
	status = initSecurityContextsTLS( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = loadHSKeysTLS13( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "loadTLS13HSKeys" );

	/* Create the dummy CCS that we send before we continue with the 
	   encrypted handshake */
	status = createDummyCCS( &stream, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* This was the last message not subject to security encapsulation so we 
	   turn on security for the write channel after sending it */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE );

	/* Build the encrypted handshake packets, first the encrypted extensions:

		byte		ID = TLS_HAND_ENCRYPTED_EXTENSIONS
		uint24		len
			uint16	extLen = 4
			uint16	type = TLS_EXT_SNI
			uint16	length = 0
		or:
			uint16	extLen = 0 */
	status = startEncryptedPacketStream( sessionInfoPtr, &stream, 
										 &outerOffset, &innerOffset,
										 TLS_HAND_ENCRYPTED_EXTENSIONS );
	if( cryptStatusOK( status ) )
		{
		/* If we need an SNI response then we have to write it in the
		   encrypted extensions rather than the standard extensions, 
		   otherwise we just write a zero-length value */
		if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDSNIRESPONSE )
			{
			writeUint16( &stream, UINT16_SIZE + UINT16_SIZE );
			writeUint16( &stream, TLS_EXT_SNI );
			status = writeUint16( &stream, 0 );
			}
		else
			status = writeUint16( &stream, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		status = completeEncryptedPacketStream( sessionInfoPtr, handshakeInfo, 
												&stream, outerOffset, 
												innerOffset, TRUE );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "writeUint16" );

	/*	...			(optional request for client certificate authentication)
		byte		ID = TLS_HAND_SERVER_CERTREQUEST
		uint24		len
		byte		certNonceLen = 16
		byte[]		certNonce
		uint16		extListLen
			uint16	extType = TLS_EXT_SIGNATURE_ALGORITHMS
			uint16	extLen
				uint16	algorithmListLength
					byte	hashAlgo
					byte	sigAlgo
		... */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		status = startEncryptedPacketStream( sessionInfoPtr, &stream, 
											 &outerOffset, &innerOffset, 
											 TLS_HAND_SERVER_CERTREQUEST );
		if( cryptStatusOK( status ) )
			status = writeCertRequest( sessionInfoPtr, &stream );
		if( cryptStatusOK( status ) )
			{
			status = completeEncryptedPacketStream( sessionInfoPtr, handshakeInfo, 
													&stream, outerOffset, 
													innerOffset, TRUE );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "writeCertRequest" );

	/*	...
		(optional Encrypted Server Certificate Chain and Certificate Verify)
		... 
	
	   We write the chain with type TLS_HAND_NONE because of the TLS 1.3
	   double wrapping, writeTLSCertChain() provides the inner wrapper so
	   there's no need for the packet-stream routines to do it */
	if( sessionInfoPtr->privateKey != CRYPT_ERROR )
		{
		status = createCertAuth( sessionInfoPtr, handshakeInfo, &stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "createCertAuth" );

	/* Clone the hash context at the point where we've hashed ClientHello || 
	   ... || ServerCertificateVerify and complete the hashing to get the 
	   SHA-2 hash needed for the server's Finished message */
	status = cloneHashContext( handshakeInfo->sha2context, 
							   &transcriptHashContext );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	krnlSendMessage( transcriptHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/*	...
		Finished */
	status = writeFinished( sessionInfoPtr, handshakeInfo, &stream, 
							transcriptHashContext, TRUE );
	krnlSendNotifier( transcriptHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "writeFinished" );

	/* Send the batch of packets to the client */
	status = sendPacketTLS( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the other side's (dummy) Change Cipherspec.  Some implementations 
	   send a bogus Change Cipherspec between the two Client Hellos rather 
	   than here on a retry so we avoid checking for one if we've already
	   processed it in the retried Client Hello */
	if( !processedDummyCCS )
		{
		status = readDummyCCS( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* The other side has signalled the start of encryption, turn on 
	   encryption for the read channel as well */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ );

	/* Process the optional Certificate Chain and Certificate Verify 
	   messages */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, 
										&length, READHS_ACTION_FIRSTENCR );
		if( cryptStatusError( status ) )
			return( status );
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		status = processCertAuth( sessionInfoPtr, handshakeInfo, &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "processCertAuth" );

	/* Wrap up the hashing to get the session hash.  This stops the hashing 
	   at the Server Finished for both sides even though the Client Finished
	   is still to come, this is necessary for 0-RTT to work since the 
	   server can attach encrypted data to the end of its handshake messages
	   before it's seen the Client Finished.  Since 0-RTT is essentially
	   impossible to implement securely no-one should ever do this, but we 
	   have to live with the consequences nonetheless */
	status = completeSessionHash( handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "completeSessionHash" );

	/* Process the client's finished */
	status = readEncryptedHSPacket( sessionInfoPtr, handshakeInfo, &length, 
						( sessionInfoPtr->cryptKeyset != CRYPT_ERROR ) ? \
						  READHS_ACTION_NOHASH : \
						  READHS_ACTION_FIRSTENCR_NOHASH );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = readFinished( sessionInfoPtr, handshakeInfo,
						   &stream, handshakeInfo->sha2context, FALSE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readFinished" );

	/* Switch from the handshake to the application data keys */
	status = loadAppdataKeysTLS13( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "loadTLS13AppdataKeys" );

	ENSURES( CFI_CHECK_SEQUENCE_9( "loadTLS13HSKeys", "writeUint16", 
								   "writeCertRequest", "createCertAuth", 
								   "writeFinished", "processCertAuth",
								   "completeSessionHash", "readFinished", 
								   "loadTLS13AppdataKeys" ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initProcessingTLS13( TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_BOOL const BOOLEAN isServer )
	{
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES_V( isBooleanValue( isServer ) );

	/* Modify the handshake completion function to the TLS 1.3 version */
	if( isServer )
		{
		FNPTR_SET( handshakeInfo->exchangeKeys, completeHandshakeServer );
		}
	else
		{
		FNPTR_SET( handshakeInfo->exchangeKeys, completeHandshakeClient );
		}
	}
#endif /* USE_TLS13 */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
