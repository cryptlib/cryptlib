<<<<<<< HEAD
/****************************************************************************
*																			*
*				cryptlib TLS Handshake Completion Management				*
*					Copyright Peter Gutmann 1998-2012						*
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

/* Pre-encoded finished message header that we can use for message hashing:

	byte		ID = TLS_HAND_FINISHED
	uint24		len = 12 (IPsec cargo-cult truncated MAC) */

#define FINISHED_TEMPLATE_SIZE				4

static const BYTE finishedTemplateTLS[] = \
		{ TLS_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE };

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Destroy cloned hash contexts, used to clean up dual-hash (SSL, TLS 1.0-1.1)
   or single-hash (TLS 1.2+) contexts */

static void destroyHashContexts( IN_HANDLE_OPT const CRYPT_CONTEXT hashContext1,
								 IN_HANDLE_OPT const CRYPT_CONTEXT hashContext2,
								 IN_HANDLE_OPT const CRYPT_CONTEXT hashContext3 )
	{
	REQUIRES_V( ( isHandleRangeValid( hashContext1 ) && \
				  isHandleRangeValid( hashContext2 ) && \
				  hashContext3 == CRYPT_ERROR ) || \
				( hashContext1 == CRYPT_ERROR && \
				  hashContext2 == CRYPT_ERROR && \
				  isHandleRangeValid( hashContext3 ) ) );

	if( hashContext1 != CRYPT_ERROR )
		krnlSendNotifier( hashContext1, IMESSAGE_DECREFCOUNT );
	if( hashContext2 != CRYPT_ERROR )
		krnlSendNotifier( hashContext2, IMESSAGE_DECREFCOUNT );
	if( hashContext3 != CRYPT_ERROR )
		krnlSendNotifier( hashContext3, IMESSAGE_DECREFCOUNT );
	}

/* Add the current session information to the session cache */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int addSessionToCache( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							  IN_BUFFER( masterSecretSize ) void *masterSecret,
							  IN_LENGTH_SHORT const int masterSecretSize,
							  IN_BOOL const BOOLEAN isClient )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	void *scoreboardInfoPtr = DATAPTR_GET( tlsInfo->scoreboardInfoPtr );
	SCOREBOARD_ENTRY_INFO scoreboardEntryInfo;
	int cachedID, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtrDynamic( masterSecret, masterSecretSize ) );

	REQUIRES( isShortIntegerRangeNZ( masterSecretSize ) );
	REQUIRES( isBooleanValue( isClient ) );
	REQUIRES( scoreboardInfoPtr != NULL );

	/* Set up the information that we're going to add to the scoreboard.  We 
	   store as metadata the state of various enhanced TLS capabilities that
	   are enabled for the current session in order to detect attempts at
	   rollback in resumed sessions */
	memset( &scoreboardEntryInfo, 0, sizeof( SCOREBOARD_ENTRY_INFO ) );
	scoreboardEntryInfo.data = masterSecret;
	scoreboardEntryInfo.dataSize = masterSecretSize;
	scoreboardEntryInfo.metaData = GET_FLAGS( sessionInfoPtr->protocolFlags,
											  TLS_RESUMEDSESSION_FLAGS );

	/* If we're the client then we have to add additional information to the
	   cache, in this case the server's name/address so that we can look up
	   the information if we try to reconnect later */
	if( isClient )
		{
		const ATTRIBUTE_LIST *attributeListPtr;

		attributeListPtr = findSessionInfo( sessionInfoPtr,
											CRYPT_SESSINFO_SERVER_NAME );
		if( attributeListPtr == NULL )
			{
			/* If the connection was established by passing cryptlib a raw
			   network socket then there's no server name information 
			   present, so we can't cache anything based on this */
			return( CRYPT_OK );
			}
		status = cachedID = \
				addScoreboardEntryEx( scoreboardInfoPtr,
									  handshakeInfo->sessionID,
									  handshakeInfo->sessionIDlength,
									  attributeListPtr->value,
									  attributeListPtr->valueLength,
									  &scoreboardEntryInfo );
		}
	else
		{
		BYTE sessionIDbuffer[ KEYID_SIZE + 8 ];
		const BYTE *sessionIDptr = handshakeInfo->sessionID;
		int sessionIDlength = handshakeInfo->sessionIDlength;

		/* We're the server, add the client's state information indexed by 
		   the sessionID */
		if( handshakeInfo->hashedSNIpresent )
			{
			/* If there's an SNI present, update the session ID to include 
			   it */
			status = convertSNISessionID( handshakeInfo, sessionIDbuffer, 
										  KEYID_SIZE );
			if( cryptStatusError( status ) )
				return( status );
			sessionIDptr = sessionIDbuffer;
			sessionIDlength = KEYID_SIZE;
			}
		status = cachedID = \
					addScoreboardEntry( scoreboardInfoPtr,
										sessionIDptr, sessionIDlength,
										&scoreboardEntryInfo );
		}
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->sessionCacheID = cachedID;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Read/Write Handshake Completion Messages				*
*																			*
****************************************************************************/

/* Read/write the handshake completion data (change cipherspec + finished) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readHandshakeCompletionData( INOUT_PTR SESSION_INFO *sessionInfoPtr,
										IN_BUFFER( hashValuesLength ) \
											const BYTE *hashValues,
										IN_LENGTH_SHORT const int hashValuesLength,
										INOUT_PTR READSTATE_INFO *readInfo )
	{
	STREAM stream;
	BYTE macBuffer[ MD5MAC_SIZE + SHA1MAC_SIZE + 8 ];
	BOOLEAN startOffsetChanged = FALSE;
	const int macValueLength = \
			TEST_FLAG( sessionInfoPtr->protocolFlags, 
					   TLS_PFLAG_TLS12LTS ) ? 32 : TLS_HASHEDMAC_SIZE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( hashValues, hashValuesLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( hashValuesLength == macValueLength );

	/* All errors are fatal */
	*readInfo = READINFO_FATAL;

	/* Process the other side's change cipher spec:

		byte		type = TLS_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1 */
	status = readHSPacketTLS( sessionInfoPtr, NULL, &length,
							  TLS_MSG_CHANGE_CIPHER_SPEC );
	if( cryptStatusError( status ) )
		{
		/* If we don't get the change cipherspec at this point this may be
		   because the server asked us for client authentication but we 
		   skipped it because we don't have a certificate, in which case
		   we return extended error information indicating this */
		if( !isServer( sessionInfoPtr ) && \
			TEST_FLAG( sessionInfoPtr->protocolFlags, 
					   TLS_PFLAG_CLIAUTHSKIPPED ) )
			{
			retExtAdditional( status, 
							  ( status, SESSION_ERRINFO, 
								", probably caused by missing client "
								"certificate authentication" ) );
			}
		return( status );
		}
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
	CFI_CHECK_UPDATE( "readHSPacketTLS" );

	/* Change cipher spec was the last message not subject to security
	   encapsulation so we turn on security for the read channel after
	   seeing it.  In addition if we're using TLS 1.1+ explicit IVs the
	   effective header size changes because of the extra IV data, so we
	   record the size of the additional IV data and update the receive
	   buffer start offset to accomodate it */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ );
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		{
		sessionInfoPtr->sessionTLS->ivSize = sessionInfoPtr->cryptBlocksize;
		startOffsetChanged = TRUE;
		}
#ifdef USE_GCM
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		/* If we're using GCM then the IV is partially explicit and 
		   partially implicit, and unrelated to the cipher block size */
		sessionInfoPtr->sessionTLS->ivSize = \
					GCM_IV_SIZE - sessionInfoPtr->sessionTLS->aeadSaltSize;
		startOffsetChanged = TRUE;
		}
#endif /* USE_GCM */
	if( startOffsetChanged )
		{
		const int newStartPos = sessionInfoPtr->receiveBufStartOfs + \
								sessionInfoPtr->sessionTLS->ivSize;

		/* Since we've changed the amount of metadata that needs to be 
		   accomodated before the payload we have to adjust the data start
		   offsets to match.  This includes adjusting related offsets in
		   order to preserve invariants for the receive buffer */
		sessionInfoPtr->receiveBufStartOfs = \
			sessionInfoPtr->receiveBufPos = \
				sessionInfoPtr->receiveBufEnd = newStartPos;
		}

	/* We can't go any further when fuzzing because the crypto hasn't been 
	   set up */
	FUZZ_EXIT();

	/* Process the other side's finished message.  Since this is the first 
	   chance that we have to test whether our crypto keys are set up 
	   correctly, we report problems with decryption or MACing or a failure 
	   to find any recognisable header as a wrong key rather than a bad data 
	   error.  In addition we signal the fact that the other side may 
	   respond unexpectedly because of the use of encryption to 
	   readHSPacketTLS() by specifying a special-case packet type, see the 
	   comment in readHSPacketTLS() for how this is handled and why it's 
	   necessary:

		byte		ID = TLS_HAND_FINISHED
		uint24		len
			SSLv3					TLS		TLS12-LTS
		byte[16]	MD5 MAC		byte[12]				hashedMAC
		byte[20]	SHA-1 MAC				byte[32]	hashedMAC.
	
	   Since we've now turned in crypto, all errors are now fatal crypto 
	   errors */
	status = readHSPacketTLS( sessionInfoPtr, NULL, &length, 
							  TLS_MSG_FIRST_ENCRHANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	*readInfo = READINFO_FATAL_CRYPTO;
	status = unwrapPacketTLS( sessionInfoPtr, sessionInfoPtr->receiveBuffer, 
							  length, &length, TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_BADDATA || \
			status == CRYPT_ERROR_SIGNATURE )
			{
			retExtErr( CRYPT_ERROR_WRONGKEY,
					   ( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						 SESSION_ERRINFO, 
						 "Decrypted data was corrupt, probably due to "
						 "incorrect encryption keys being negotiated "
						 "during the handshake" ) );
			}
		return( status );
		}
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = checkHSPacketHeader( sessionInfoPtr, &stream, &length,
								  TLS_HAND_FINISHED, macValueLength );
	if( cryptStatusOK( status ) )
		{
		if( length != macValueLength )
			{
			/* A length mis-match can only be an overflow, since an
			   underflow would be caught by checkHSPacketHeader() */
			status = CRYPT_ERROR_OVERFLOW;
			}
		else
			status = sread( &stream, macBuffer, macValueLength );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_BADDATA )
			{
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "Invalid handshake finished packet, probably due to "
					  "incorrect encryption keys being negotiated during "
					  "the handshake" ) );
			}
		return( status );
		}
	CFI_CHECK_UPDATE( "unwrapPacketTLS" );

	/* Make sure that the dual MAC/hashed MAC of all preceding messages is
	   valid */
	if( compareDataConstTime( hashValues, macBuffer, 
							  macValueLength ) != TRUE )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad MAC for handshake messages, handshake messages were "
				  "corrupted/modified" ) );
		}
	CFI_CHECK_UPDATE( "compareDataConstTime" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "readHSPacketTLS", "unwrapPacketTLS", 
								   "compareDataConstTime" ) );

	*readInfo = READINFO_NONE;
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeHandshakeCompletionData( INOUT_PTR SESSION_INFO *sessionInfoPtr,
										 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
										 IN_BUFFER( hashValuesLength ) \
											const BYTE *hashValues, 
										 IN_LENGTH_SHORT const int hashValuesLength,
										 IN_BOOL const BOOLEAN continuedStream )
	{
	STREAM *stream = &handshakeInfo->stream;
	BOOLEAN startOffsetChanged = FALSE;
	int offset = 0, ccsEndPos, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( hashValues, hashValuesLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( hashValuesLength ) );
	REQUIRES( isBooleanValue( continuedStream ) );

	/* Build the change cipher spec packet:

		byte		type = TLS_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1

	   Since change cipher spec is its own protocol, we use TLS-level packet
	   encoding rather than handshake protocol-level encoding */
	if( continuedStream )
		{
		status = continuePacketStreamTLS( stream, sessionInfoPtr,
										  TLS_MSG_CHANGE_CIPHER_SPEC, 
										  &offset );
		}
	else
		{
		status = openPacketStreamTLS( stream, sessionInfoPtr, 
									  CRYPT_USE_DEFAULT,
									  TLS_MSG_CHANGE_CIPHER_SPEC );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = sputc( stream, 1 );
	if( cryptStatusOK( status ) )
		status = completePacketStreamTLS( stream, offset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* Change cipher spec was the last message not subject to security
	   encapsulation so we turn on security for the write channel after
	   seeing it.  In addition if we're using TLS 1.1+ explicit IVs the
	   effective header size changes because of the extra IV data, so we
	   record the size of the additional IV data and update the receive
	   buffer start offset to accomodate it */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE );
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		{
		sessionInfoPtr->sessionTLS->ivSize = sessionInfoPtr->cryptBlocksize;
		startOffsetChanged = TRUE;
		}
#ifdef USE_GCM
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		/* If we're using GCM then the IV is partially explicit and 
		   partially implicit, and unrelated to the cipher block size */
		sessionInfoPtr->sessionTLS->ivSize = \
					GCM_IV_SIZE - sessionInfoPtr->sessionTLS->aeadSaltSize;
		startOffsetChanged = TRUE;
		}
#endif /* USE_GCM */
	if( startOffsetChanged )
		{
		const int newStartPos = sessionInfoPtr->sendBufStartOfs + \
								sessionInfoPtr->sessionTLS->ivSize;

		/* Since we've changed the amount of metadata that needs to be 
		   accomodated before the payload we have to adjust the data start
		   offsets to match.  This includes adjusting related offsets in
		   order to preserve invariants for the send buffer */
		sessionInfoPtr->sendBufStartOfs = \
			sessionInfoPtr->sendBufPos = newStartPos;
		}

	/* Build the finished packet.  The initiator sends the MAC of the
	   contents of every handshake packet before the finished packet, the
	   responder sends the MAC of the contents of every packet before its own
	   finished packet but including the MAC of the initiator's packet
	   contents:

		byte		ID = TLS_HAND_FINISHED
		uint24		len
			SSLv3						TLS
		byte[16]	MD5 MAC			byte[12]	hashedMAC
		byte[20]	SHA-1 MAC */
	status = continuePacketStreamTLS( stream, sessionInfoPtr,
									  TLS_MSG_HANDSHAKE, &ccsEndPos );
	if( cryptStatusOK( status ) )
		{
		status = continueHSPacketStream( stream, TLS_HAND_FINISHED, 
										 &offset );
		}
	if( cryptStatusOK( status ) )
		{
		INJECT_FAULT( SESSION_TLS_CORRUPT_FINISHED, 
					  SESSION_TLS_CORRUPT_FINISHED_1 );
		status = swrite( stream, hashValues, hashValuesLength );
		INJECT_FAULT( SESSION_TLS_CORRUPT_FINISHED, 
					  SESSION_TLS_CORRUPT_FINISHED_2 );
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, offset );
	if( cryptStatusOK( status ) )
		status = wrapPacketTLS( sessionInfoPtr, stream, ccsEndPos );
	if( cryptStatusOK( status ) )
		status = sendPacketTLS( sessionInfoPtr, stream, TRUE );
	sMemDisconnect( stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Complete the TLS Handshake						*
*																			*
****************************************************************************/

/* Complete the handshake with the client or server.  The logic gets a bit
   complex here because the roles of the client and server are reversed if
   we're resuming a session:

		Normal					Resumed
	Client		Server		Client		Server
	------		------		------		------
		   <--- ...			Hello  --->
	KeyEx  --->					   <---	Hello
	------------------------------------------ completeHandshakeTLS()
	CCS	   --->					   <--- CCS
	Fin	   --->					   <--- Fin
		   <---	CCS			CCS	   --->
		   <---	Fin			Fin	   --->

   Because of this the handshake-completion step treats the two sides as
   initiator and responder rather than client and server.  The overall flow
   is then:

	dualMAC/MAC( initiator );
	if( !initiator )
		read initiator CCS + Fin;
	dualMAC/MAC( responder );
	send initiator/responder CCS + Fin;
	if( initiator )
		read responder CCS + Fin; */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int completeHandshakeTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_BOOL const BOOLEAN isClient,
						  IN_BOOL const BOOLEAN isResumedSession )
	{
	const CRYPT_CONTEXT initiatorMD5context = handshakeInfo->md5context;
	const CRYPT_CONTEXT initiatorSHA1context = handshakeInfo->sha1context;
	const CRYPT_CONTEXT initiatorSHA2context = handshakeInfo->sha2context;
	CRYPT_CONTEXT responderMD5context = CRYPT_ERROR;
	CRYPT_CONTEXT responderSHA1context = CRYPT_ERROR;
	CRYPT_CONTEXT responderSHA2context = CRYPT_ERROR;
	BYTE masterSecret[ TLS_SECRET_SIZE + 8 ];
	BYTE initiatorHashes[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	BYTE responderHashes[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	const void *tlsInitiatorString, *tlsResponderString;
	READSTATE_INFO readInfo = READINFO_NONE;
	const BOOLEAN isInitiator = isResumedSession ? \
			( isClient ? FALSE : TRUE ) : isClient;
	const BOOLEAN updateSessionCache = 	\
			( !isResumedSession && handshakeInfo->sessionIDlength > 0 ) ? \
			TRUE : FALSE;
#if defined( USE_EAP ) 
	const BOOLEAN createDerivedKeydata = \
			( sessionInfoPtr->subProtocol == CRYPT_SUBPROTOCOL_EAPTTLS || \
			  sessionInfoPtr->subProtocol == CRYPT_SUBPROTOCOL_PEAP ) ? \
			TRUE : FALSE;
#else
	const BOOLEAN createDerivedKeydata = FALSE;
#endif /* USE_EAP */
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int initiatorHashLength, responderHashLength;
	int tlsLabelLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( MAX_KEYBLOCK_SIZE >= ( sessionInfoPtr->authBlocksize + \
									 handshakeInfo->cryptKeysize +
									 sessionInfoPtr->cryptBlocksize ) * 2 );
	REQUIRES( handshakeInfo->authAlgo == CRYPT_ALGO_NONE || \
			  ( isEccAlgo( handshakeInfo->keyexAlgo ) && \
				handshakeInfo->premasterSecretSize >= MIN_PKCSIZE_ECC ) || \
			  ( !isEccAlgo( handshakeInfo->keyexAlgo ) && \
				handshakeInfo->premasterSecretSize >= TLS_SECRET_SIZE ) );
	REQUIRES( isBooleanValue( isClient ) );
	REQUIRES( isBooleanValue( isResumedSession ) );

	/* Perform the necessary juggling of values for the reversed message
	   flow of resumed sessions */
	if( isResumedSession )
		{
		/* Resumed session, initiator = server, responder = client */
		tlsInitiatorString = "server finished";
		tlsResponderString = "client finished";
		}
	else
		{
		/* Normal session, initiator = client, responder = server */
		tlsInitiatorString = "client finished";
		tlsResponderString = "server finished";
		}
	tlsLabelLength = 15;

#ifndef CONFIG_FUZZ
	/* Initialise and load cryptovariables into all encryption contexts */
	status = initCryptoTLS( sessionInfoPtr, handshakeInfo, masterSecret,
							TLS_SECRET_SIZE, isClient, isResumedSession );
	if( cryptStatusError( status ) )
		return( status );
	if( isResumedSession )
		{
		/* Remember that this is a resumed session in case the caller needs 
		   to know, this is sometimes needed by protocols tunnelled over TLS
		   which change their behaviour based on whether a full or 
		   abbreviated handshake has been used */
		SET_FLAG( sessionInfoPtr->protocolFlags, 
				  TLS_PFLAG_RESUMED_SESSION );
		}
	CFI_CHECK_UPDATE( "initCryptoTLS" );

	/* At this point the hashing of the initiator and responder diverge.
	   The initiator sends its change cipherspec and finished messages 
	   first, so the hashing stops there, while the responder has to keep 
	   hasing the initiator's messages until it's its turn to send its 
	   change cipherspec and finished messages.  To handle this we clone 
	   the initiator's hash context(s) so that we can contine the hashing 
	   after the initiator has wrapped things up */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = cloneHashContext( initiatorMD5context, 
								   &responderMD5context );
		if( cryptStatusOK( status ) )
			{
			status = cloneHashContext( initiatorSHA1context, 
									   &responderSHA1context );
			if( cryptStatusError( status ) )
				{
				krnlSendNotifier( responderMD5context, 
								  IMESSAGE_DECREFCOUNT );
				}
			}
		}
	else
		{
		status = cloneHashContext( initiatorSHA2context, 
								   &responderSHA2context );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, TLS_SECRET_SIZE );
		return( status );
		}
	CFI_CHECK_UPDATE( "cloneHashContext" );

	/* Complete the MAC of the initiator-side messages and, if we're the 
	   responder, check that the MACs match the ones supplied by the 
	   initiator */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = completeTLSHashedMAC( initiatorMD5context, 
							initiatorSHA1context, initiatorHashes, 
							CRYPT_MAX_HASHSIZE * 2, &initiatorHashLength, 
							tlsInitiatorString, tlsLabelLength, masterSecret, 
							TLS_SECRET_SIZE );
		}
	else
		{
		status = completeTLS12HashedMAC( initiatorSHA2context,
							initiatorHashes, CRYPT_MAX_HASHSIZE,
							&initiatorHashLength, tlsInitiatorString, 
							tlsLabelLength, masterSecret, TLS_SECRET_SIZE,
							TEST_FLAG( sessionInfoPtr->protocolFlags, 
									   TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
		}
#else
	initiatorHashLength = \
			TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS ) ? \
					   32 : TLS_HASHEDMAC_SIZE;
	status = CRYPT_OK;
#endif /* CONFIG_FUZZ */
	if( cryptStatusOK( status ) && !isInitiator )
		{
		status = readHandshakeCompletionData( sessionInfoPtr, 
											  initiatorHashes, 
											  initiatorHashLength, 
											  &readInfo );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, TLS_SECRET_SIZE );
		destroyHashContexts( responderMD5context, responderSHA1context,
							 responderSHA2context );

		/* We have to explicitly handle crypto failures at this point 
		   because we're not being called from the higher-level session
		   read handlers that do this for us */
		if( readInfo == READINFO_FATAL_CRYPTO )
			registerCryptoFailure();
		return( status );
		}
#ifndef CONFIG_FUZZ
	CFI_CHECK_UPDATE( "completeHashedMAC" );

	/* Now that we have the initiator MACs, complete the dual-hashing/
	   hashing and dual-MAC/MAC of the responder-side messages and destroy 
	   the master secret unless we need to keep it around to update the
	   session cache.  We haven't created the full message yet at this 
	   point so we manually hash the individual pieces so that we can 
	   finally get rid of the master secret */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		status = krnlSendMessage( responderSHA2context, IMESSAGE_CTX_HASH,
				( MESSAGE_CAST ) finishedTemplateTLS, FINISHED_TEMPLATE_SIZE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( responderSHA2context, IMESSAGE_CTX_HASH, 
									  initiatorHashes, initiatorHashLength );
			}
		}
	else
		{
		status = krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH,
				( MESSAGE_CAST ) finishedTemplateTLS, FINISHED_TEMPLATE_SIZE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
				( MESSAGE_CAST ) finishedTemplateTLS, FINISHED_TEMPLATE_SIZE );
			}
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH, 
									  initiatorHashes, initiatorHashLength );
			}
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
									  initiatorHashes, initiatorHashLength );
			}
		}
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, TLS_SECRET_SIZE );
		destroyHashContexts( responderMD5context, responderSHA1context,
							 responderSHA2context );
		return( status );
		}
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_HASH" );
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = completeTLSHashedMAC( responderMD5context, 
							responderSHA1context, responderHashes, 
							CRYPT_MAX_HASHSIZE * 2, &responderHashLength, 
							tlsResponderString, tlsLabelLength, masterSecret, 
							TLS_SECRET_SIZE );
		}
	else
		{
		status = completeTLS12HashedMAC( responderSHA2context, 
							responderHashes, CRYPT_MAX_HASHSIZE * 2, 
							&responderHashLength, tlsResponderString, 
							tlsLabelLength, masterSecret, TLS_SECRET_SIZE,
							TEST_FLAG( sessionInfoPtr->protocolFlags, 
									   TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
		}
	if( !updateSessionCache && !createDerivedKeydata )
		{
		/* If we don't need the master secret beyond this point, clear it 
		   from memory now */
		zeroise( masterSecret, TLS_SECRET_SIZE );
		}
	destroyHashContexts( responderMD5context, responderSHA1context,
						 responderSHA2context );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, TLS_SECRET_SIZE );
		return( status );
		}
	CFI_CHECK_UPDATE( "completeHashedMAC" );
	DEBUG_DUMP_DATA_LABEL( "Initiator hash:",
						   initiatorHashes, initiatorHashLength );
	DEBUG_DUMP_DATA_LABEL( "Responder hash:",
						   responderHashes, initiatorHashLength );

	/* Send our MACs to the other side and read back their response if
	   necessary.  The initiatorHashLength is the same as the 
	   responderHashLength (it's just a naming difference based on the
	   role that we're playing) so we use initiatorHashLength for both */
	status = writeHandshakeCompletionData( sessionInfoPtr, handshakeInfo,
					isInitiator ? initiatorHashes : responderHashes,
					initiatorHashLength /* Same as responderHashLength */,
					( ( isClient && !isResumedSession ) || \
					  ( !isClient && isResumedSession ) ) ? TRUE : FALSE );
#endif /* !CONFIG_FUZZ */
	if( cryptStatusOK( status ) && isInitiator )
		{
		status = readHandshakeCompletionData( sessionInfoPtr, responderHashes,
											  initiatorHashLength, &readInfo );
		}
	if( cryptStatusOK( status ) && updateSessionCache )
		{
		/* The handshake completed successfully, add the master secret to 
		   the session cache */
		status = addSessionToCache( sessionInfoPtr, handshakeInfo, 
									masterSecret, TLS_SECRET_SIZE,
									isClient );
		}
#ifdef USE_EAP
	if( cryptStatusOK( status ) && createDerivedKeydata )
		{
		/* The handshake completed successfully, add the derived keying data
		   required by EAP */
		status = addDerivedKeydata( sessionInfoPtr, handshakeInfo, 
									masterSecret, TLS_SECRET_SIZE,
									sessionInfoPtr->subProtocol );
		}
#endif /* USE_EAP */
	CFI_CHECK_UPDATE( "writeHandshakeCompletionData" );

	/* Clean up */
	zeroise( masterSecret, TLS_SECRET_SIZE );
	if( cryptStatusError( status ) )
		{
		/* We have to explicitly handle crypto failures at this point 
		   because we're not being called from the higher-level session
		   read handlers that do this for us */
		if( readInfo == READINFO_FATAL_CRYPTO )
			registerCryptoFailure();
		return( status );
		}

	ENSURES( CFI_CHECK_SEQUENCE_6( "initCryptoTLS", "cloneHashContext", 
								   "completeHashedMAC", "IMESSAGE_CTX_HASH", 
								   "completeHashedMAC",
								   "writeHandshakeCompletionData" ) );

	return( CRYPT_OK );
	}

#if defined( USE_EAP ) && 0

/* Test against EAPOL test vectors, left in here to document correct 
   operation in future versions */

void testEAPOL( INOUT_PTR SESSION_INFO *sessionInfoPtr,
				INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
static const BYTE eapolClientRandom[] = {
	0xc0, 0x2c, 0x61, 0x51, 0x81, 0x3b, 0x05, 0x47,
	0x64, 0x13, 0x8b, 0x35, 0xbc, 0x86, 0xba, 0xe7,
	0xad, 0x5a, 0xc6, 0xdb, 0x80, 0x1f, 0x8c, 0xe2,
	0x45, 0x15, 0x59, 0xfd, 0xe6, 0xb6, 0x09, 0x87
	};
static const BYTE eapolServerRandom[] = {
	0x34, 0x9f, 0xea, 0x22, 0x08, 0x1e, 0x47, 0xb3,
	0xc8, 0x70, 0x66, 0x54, 0x54, 0xc6, 0x9a, 0x00,
	0x08, 0x16, 0xb7, 0x62, 0xb7, 0x82, 0x58, 0x09,
	0x81, 0x0f, 0x56, 0x9c, 0x49, 0x5f, 0x77, 0x21
	};
static const BYTE eapolMasterSecret[] = {
	0xd8, 0xcc, 0x6b, 0x5c, 0x24, 0xfb, 0x98, 0x78,
	0x04, 0x69, 0x88, 0x2c, 0x42, 0x23, 0x62, 0x2e,
	0x80, 0x35, 0x86, 0x16, 0x2d, 0x2b, 0xac, 0x14,
	0xd6, 0x6e, 0xdc, 0x5c, 0x32, 0xeb, 0xd5, 0x8e,
	0x3b, 0xe7, 0x49, 0x3d, 0x48, 0x48, 0x37, 0x9d,
	0x90, 0x10, 0x57, 0x09, 0x7b, 0xe8, 0x49, 0xac
	};
static const BYTE eapolEAPSecret[] = {
	0x95, 0x85, 0x31, 0x06, 0x11, 0x4a, 0xca, 0x36,
	0xd2, 0xd1, 0xdc, 0xd6, 0x71, 0xc4, 0xfd, 0x75,
	0x55, 0x0b, 0x1b, 0x6b, 0x62, 0xc6, 0x9e, 0x9b,
	0x45, 0x0e, 0xfc, 0xca, 0xbc, 0x67, 0x68, 0xc2,
	0x9c, 0x1a, 0x1e, 0xc1, 0xa5, 0x00, 0x46, 0xf5,
	0x98, 0x8a, 0xb2, 0x25, 0x43, 0x03, 0x10, 0x1b,
	0xde, 0x7a, 0x85, 0xf0, 0xce, 0x3d, 0xfa, 0xf8,
	0x87, 0x43, 0xea, 0xc9, 0xc8, 0xd7, 0x8c, 0x43
	};
const ATTRIBUTE_LIST *attributeInfoPtr;
BYTE masterSecret[ TLS_SECRET_SIZE + 8 ];
int status;

memcpy( handshakeInfo->clientNonce, eapolClientRandom, TLS_NONCE_SIZE );
memcpy( handshakeInfo->serverNonce, eapolServerRandom, TLS_NONCE_SIZE );
memcpy( masterSecret, eapolMasterSecret, TLS_SECRET_SIZE );

status = addDerivedKeydata( sessionInfoPtr, handshakeInfo, masterSecret, 
							TLS_SECRET_SIZE, sessionInfoPtr->subProtocol );
assert( cryptStatusOK( status ) );
attributeInfoPtr = findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_TLS_EAPKEY );
DEBUG_DUMP_DATA( attributeInfoPtr->value, 64 );
if( memcmp( attributeInfoPtr->value, eapolEAPSecret, 64 ) )
	puts( "eapol_test data comparison failed." );
}
#endif /* USE_EAP && 0 */	
#endif /* USE_TLS */
=======
/****************************************************************************
*																			*
*				cryptlib TLS Handshake Completion Management				*
*					Copyright Peter Gutmann 1998-2012						*
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

/* Pre-encoded finished message header that we can use for message hashing:

	byte		ID = TLS_HAND_FINISHED
	uint24		len = 12 (IPsec cargo-cult truncated MAC) */

#define FINISHED_TEMPLATE_SIZE				4

static const BYTE finishedTemplateTLS[] = \
		{ TLS_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE };

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Destroy cloned hash contexts, used to clean up dual-hash (SSL, TLS 1.0-1.1)
   or single-hash (TLS 1.2+) contexts */

static void destroyHashContexts( IN_HANDLE_OPT const CRYPT_CONTEXT hashContext1,
								 IN_HANDLE_OPT const CRYPT_CONTEXT hashContext2,
								 IN_HANDLE_OPT const CRYPT_CONTEXT hashContext3 )
	{
	REQUIRES_V( ( isHandleRangeValid( hashContext1 ) && \
				  isHandleRangeValid( hashContext2 ) && \
				  hashContext3 == CRYPT_ERROR ) || \
				( hashContext1 == CRYPT_ERROR && \
				  hashContext2 == CRYPT_ERROR && \
				  isHandleRangeValid( hashContext3 ) ) );

	if( hashContext1 != CRYPT_ERROR )
		krnlSendNotifier( hashContext1, IMESSAGE_DECREFCOUNT );
	if( hashContext2 != CRYPT_ERROR )
		krnlSendNotifier( hashContext2, IMESSAGE_DECREFCOUNT );
	if( hashContext3 != CRYPT_ERROR )
		krnlSendNotifier( hashContext3, IMESSAGE_DECREFCOUNT );
	}

/* Add the current session information to the session cache */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int addSessionToCache( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							  IN_BUFFER( masterSecretSize ) void *masterSecret,
							  IN_LENGTH_SHORT const int masterSecretSize,
							  IN_BOOL const BOOLEAN isClient )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	void *scoreboardInfoPtr = DATAPTR_GET( tlsInfo->scoreboardInfoPtr );
	SCOREBOARD_ENTRY_INFO scoreboardEntryInfo;
	int cachedID, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtrDynamic( masterSecret, masterSecretSize ) );

	REQUIRES( isShortIntegerRangeNZ( masterSecretSize ) );
	REQUIRES( isBooleanValue( isClient ) );
	REQUIRES( scoreboardInfoPtr != NULL );

	/* Set up the information that we're going to add to the scoreboard.  We 
	   store as metadata the state of various enhanced TLS capabilities that
	   are enabled for the current session in order to detect attempts at
	   rollback in resumed sessions */
	memset( &scoreboardEntryInfo, 0, sizeof( SCOREBOARD_ENTRY_INFO ) );
	scoreboardEntryInfo.data = masterSecret;
	scoreboardEntryInfo.dataSize = masterSecretSize;
	scoreboardEntryInfo.metaData = GET_FLAGS( sessionInfoPtr->protocolFlags,
											  TLS_RESUMEDSESSION_FLAGS );

	/* If we're the client then we have to add additional information to the
	   cache, in this case the server's name/address so that we can look up
	   the information if we try to reconnect later */
	if( isClient )
		{
		const ATTRIBUTE_LIST *attributeListPtr;

		attributeListPtr = findSessionInfo( sessionInfoPtr,
											CRYPT_SESSINFO_SERVER_NAME );
		if( attributeListPtr == NULL )
			{
			/* If the connection was established by passing cryptlib a raw
			   network socket then there's no server name information 
			   present, so we can't cache anything based on this */
			return( CRYPT_OK );
			}
		status = cachedID = \
				addScoreboardEntryEx( scoreboardInfoPtr,
									  handshakeInfo->sessionID,
									  handshakeInfo->sessionIDlength,
									  attributeListPtr->value,
									  attributeListPtr->valueLength,
									  &scoreboardEntryInfo );
		}
	else
		{
		BYTE sessionIDbuffer[ KEYID_SIZE + 8 ];
		const BYTE *sessionIDptr = handshakeInfo->sessionID;
		int sessionIDlength = handshakeInfo->sessionIDlength;

		/* We're the server, add the client's state information indexed by 
		   the sessionID */
		if( handshakeInfo->hashedSNIpresent )
			{
			/* If there's an SNI present, update the session ID to include 
			   it */
			status = convertSNISessionID( handshakeInfo, sessionIDbuffer, 
										  KEYID_SIZE );
			if( cryptStatusError( status ) )
				return( status );
			sessionIDptr = sessionIDbuffer;
			sessionIDlength = KEYID_SIZE;
			}
		status = cachedID = \
					addScoreboardEntry( scoreboardInfoPtr,
										sessionIDptr, sessionIDlength,
										&scoreboardEntryInfo );
		}
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->sessionCacheID = cachedID;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Read/Write Handshake Completion Messages				*
*																			*
****************************************************************************/

/* Read/write the handshake completion data (change cipherspec + finished) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readHandshakeCompletionData( INOUT_PTR SESSION_INFO *sessionInfoPtr,
										IN_BUFFER( hashValuesLength ) \
											const BYTE *hashValues,
										IN_LENGTH_SHORT const int hashValuesLength,
										INOUT_PTR READSTATE_INFO *readInfo )
	{
	STREAM stream;
	BYTE macBuffer[ MD5MAC_SIZE + SHA1MAC_SIZE + 8 ];
	BOOLEAN startOffsetChanged = FALSE;
	const int macValueLength = \
			TEST_FLAG( sessionInfoPtr->protocolFlags, 
					   TLS_PFLAG_TLS12LTS ) ? 32 : TLS_HASHEDMAC_SIZE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( hashValues, hashValuesLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( hashValuesLength == macValueLength );

	/* All errors are fatal */
	*readInfo = READINFO_FATAL;

	/* Process the other side's change cipher spec:

		byte		type = TLS_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1 */
	status = readHSPacketTLS( sessionInfoPtr, NULL, &length,
							  TLS_MSG_CHANGE_CIPHER_SPEC );
	if( cryptStatusError( status ) )
		{
		/* If we don't get the change cipherspec at this point this may be
		   because the server asked us for client authentication but we 
		   skipped it because we don't have a certificate, in which case
		   we return extended error information indicating this */
		if( !isServer( sessionInfoPtr ) && \
			TEST_FLAG( sessionInfoPtr->protocolFlags, 
					   TLS_PFLAG_CLIAUTHSKIPPED ) )
			{
			retExtAdditional( status, 
							  ( status, SESSION_ERRINFO, 
								", probably caused by missing client "
								"certificate authentication" ) );
			}
		return( status );
		}
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
	CFI_CHECK_UPDATE( "readHSPacketTLS" );

	/* Change cipher spec was the last message not subject to security
	   encapsulation so we turn on security for the read channel after
	   seeing it.  In addition if we're using TLS 1.1+ explicit IVs the
	   effective header size changes because of the extra IV data, so we
	   record the size of the additional IV data and update the receive
	   buffer start offset to accomodate it */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ );
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		{
		sessionInfoPtr->sessionTLS->ivSize = sessionInfoPtr->cryptBlocksize;
		startOffsetChanged = TRUE;
		}
#ifdef USE_GCM
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		/* If we're using GCM then the IV is partially explicit and 
		   partially implicit, and unrelated to the cipher block size */
		sessionInfoPtr->sessionTLS->ivSize = \
					GCM_IV_SIZE - sessionInfoPtr->sessionTLS->aeadSaltSize;
		startOffsetChanged = TRUE;
		}
#endif /* USE_GCM */
	if( startOffsetChanged )
		{
		const int newStartPos = sessionInfoPtr->receiveBufStartOfs + \
								sessionInfoPtr->sessionTLS->ivSize;

		/* Since we've changed the amount of metadata that needs to be 
		   accomodated before the payload we have to adjust the data start
		   offsets to match.  This includes adjusting related offsets in
		   order to preserve invariants for the receive buffer */
		sessionInfoPtr->receiveBufStartOfs = \
			sessionInfoPtr->receiveBufPos = \
				sessionInfoPtr->receiveBufEnd = newStartPos;
		}

	/* We can't go any further when fuzzing because the crypto hasn't been 
	   set up */
	FUZZ_EXIT();

	/* Process the other side's finished message.  Since this is the first 
	   chance that we have to test whether our crypto keys are set up 
	   correctly, we report problems with decryption or MACing or a failure 
	   to find any recognisable header as a wrong key rather than a bad data 
	   error.  In addition we signal the fact that the other side may 
	   respond unexpectedly because of the use of encryption to 
	   readHSPacketTLS() by specifying a special-case packet type, see the 
	   comment in readHSPacketTLS() for how this is handled and why it's 
	   necessary:

		byte		ID = TLS_HAND_FINISHED
		uint24		len
			SSLv3					TLS		TLS12-LTS
		byte[16]	MD5 MAC		byte[12]				hashedMAC
		byte[20]	SHA-1 MAC				byte[32]	hashedMAC.
	
	   Since we've now turned in crypto, all errors are now fatal crypto 
	   errors */
	status = readHSPacketTLS( sessionInfoPtr, NULL, &length, 
							  TLS_MSG_FIRST_ENCRHANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	*readInfo = READINFO_FATAL_CRYPTO;
	status = unwrapPacketTLS( sessionInfoPtr, sessionInfoPtr->receiveBuffer, 
							  length, &length, TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_BADDATA || \
			status == CRYPT_ERROR_SIGNATURE )
			{
			retExtErr( CRYPT_ERROR_WRONGKEY,
					   ( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						 SESSION_ERRINFO, 
						 "Decrypted data was corrupt, probably due to "
						 "incorrect encryption keys being negotiated "
						 "during the handshake" ) );
			}
		return( status );
		}
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = checkHSPacketHeader( sessionInfoPtr, &stream, &length,
								  TLS_HAND_FINISHED, macValueLength );
	if( cryptStatusOK( status ) )
		{
		if( length != macValueLength )
			{
			/* A length mis-match can only be an overflow, since an
			   underflow would be caught by checkHSPacketHeader() */
			status = CRYPT_ERROR_OVERFLOW;
			}
		else
			status = sread( &stream, macBuffer, macValueLength );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_BADDATA )
			{
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "Invalid handshake finished packet, probably due to "
					  "incorrect encryption keys being negotiated during "
					  "the handshake" ) );
			}
		return( status );
		}
	CFI_CHECK_UPDATE( "unwrapPacketTLS" );

	/* Make sure that the dual MAC/hashed MAC of all preceding messages is
	   valid */
	if( compareDataConstTime( hashValues, macBuffer, 
							  macValueLength ) != TRUE )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad MAC for handshake messages, handshake messages were "
				  "corrupted/modified" ) );
		}
	CFI_CHECK_UPDATE( "compareDataConstTime" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "readHSPacketTLS", "unwrapPacketTLS", 
								   "compareDataConstTime" ) );

	*readInfo = READINFO_NONE;
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeHandshakeCompletionData( INOUT_PTR SESSION_INFO *sessionInfoPtr,
										 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
										 IN_BUFFER( hashValuesLength ) \
											const BYTE *hashValues, 
										 IN_LENGTH_SHORT const int hashValuesLength,
										 IN_BOOL const BOOLEAN continuedStream )
	{
	STREAM *stream = &handshakeInfo->stream;
	BOOLEAN startOffsetChanged = FALSE;
	int offset = 0, ccsEndPos, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( hashValues, hashValuesLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( hashValuesLength ) );
	REQUIRES( isBooleanValue( continuedStream ) );

	/* Build the change cipher spec packet:

		byte		type = TLS_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1

	   Since change cipher spec is its own protocol, we use TLS-level packet
	   encoding rather than handshake protocol-level encoding */
	if( continuedStream )
		{
		status = continuePacketStreamTLS( stream, sessionInfoPtr,
										  TLS_MSG_CHANGE_CIPHER_SPEC, 
										  &offset );
		}
	else
		{
		status = openPacketStreamTLS( stream, sessionInfoPtr, 
									  CRYPT_USE_DEFAULT,
									  TLS_MSG_CHANGE_CIPHER_SPEC );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = sputc( stream, 1 );
	if( cryptStatusOK( status ) )
		status = completePacketStreamTLS( stream, offset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* Change cipher spec was the last message not subject to security
	   encapsulation so we turn on security for the write channel after
	   seeing it.  In addition if we're using TLS 1.1+ explicit IVs the
	   effective header size changes because of the extra IV data, so we
	   record the size of the additional IV data and update the receive
	   buffer start offset to accomodate it */
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE );
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		{
		sessionInfoPtr->sessionTLS->ivSize = sessionInfoPtr->cryptBlocksize;
		startOffsetChanged = TRUE;
		}
#ifdef USE_GCM
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		/* If we're using GCM then the IV is partially explicit and 
		   partially implicit, and unrelated to the cipher block size */
		sessionInfoPtr->sessionTLS->ivSize = \
					GCM_IV_SIZE - sessionInfoPtr->sessionTLS->aeadSaltSize;
		startOffsetChanged = TRUE;
		}
#endif /* USE_GCM */
	if( startOffsetChanged )
		{
		const int newStartPos = sessionInfoPtr->sendBufStartOfs + \
								sessionInfoPtr->sessionTLS->ivSize;

		/* Since we've changed the amount of metadata that needs to be 
		   accomodated before the payload we have to adjust the data start
		   offsets to match.  This includes adjusting related offsets in
		   order to preserve invariants for the send buffer */
		sessionInfoPtr->sendBufStartOfs = \
			sessionInfoPtr->sendBufPos = newStartPos;
		}

	/* Build the finished packet.  The initiator sends the MAC of the
	   contents of every handshake packet before the finished packet, the
	   responder sends the MAC of the contents of every packet before its own
	   finished packet but including the MAC of the initiator's packet
	   contents:

		byte		ID = TLS_HAND_FINISHED
		uint24		len
			SSLv3						TLS
		byte[16]	MD5 MAC			byte[12]	hashedMAC
		byte[20]	SHA-1 MAC */
	status = continuePacketStreamTLS( stream, sessionInfoPtr,
									  TLS_MSG_HANDSHAKE, &ccsEndPos );
	if( cryptStatusOK( status ) )
		{
		status = continueHSPacketStream( stream, TLS_HAND_FINISHED, 
										 &offset );
		}
	if( cryptStatusOK( status ) )
		{
		INJECT_FAULT( SESSION_TLS_CORRUPT_FINISHED, 
					  SESSION_TLS_CORRUPT_FINISHED_1 );
		status = swrite( stream, hashValues, hashValuesLength );
		INJECT_FAULT( SESSION_TLS_CORRUPT_FINISHED, 
					  SESSION_TLS_CORRUPT_FINISHED_2 );
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, offset );
	if( cryptStatusOK( status ) )
		status = wrapPacketTLS( sessionInfoPtr, stream, ccsEndPos );
	if( cryptStatusOK( status ) )
		status = sendPacketTLS( sessionInfoPtr, stream, TRUE );
	sMemDisconnect( stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Complete the TLS Handshake						*
*																			*
****************************************************************************/

/* Complete the handshake with the client or server.  The logic gets a bit
   complex here because the roles of the client and server are reversed if
   we're resuming a session:

		Normal					Resumed
	Client		Server		Client		Server
	------		------		------		------
		   <--- ...			Hello  --->
	KeyEx  --->					   <---	Hello
	------------------------------------------ completeHandshakeTLS()
	CCS	   --->					   <--- CCS
	Fin	   --->					   <--- Fin
		   <---	CCS			CCS	   --->
		   <---	Fin			Fin	   --->

   Because of this the handshake-completion step treats the two sides as
   initiator and responder rather than client and server.  The overall flow
   is then:

	dualMAC/MAC( initiator );
	if( !initiator )
		read initiator CCS + Fin;
	dualMAC/MAC( responder );
	send initiator/responder CCS + Fin;
	if( initiator )
		read responder CCS + Fin; */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int completeHandshakeTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_BOOL const BOOLEAN isClient,
						  IN_BOOL const BOOLEAN isResumedSession )
	{
	const CRYPT_CONTEXT initiatorMD5context = handshakeInfo->md5context;
	const CRYPT_CONTEXT initiatorSHA1context = handshakeInfo->sha1context;
	const CRYPT_CONTEXT initiatorSHA2context = handshakeInfo->sha2context;
	CRYPT_CONTEXT responderMD5context = CRYPT_ERROR;
	CRYPT_CONTEXT responderSHA1context = CRYPT_ERROR;
	CRYPT_CONTEXT responderSHA2context = CRYPT_ERROR;
	BYTE masterSecret[ TLS_SECRET_SIZE + 8 ];
	BYTE initiatorHashes[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	BYTE responderHashes[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	const void *tlsInitiatorString, *tlsResponderString;
	READSTATE_INFO readInfo = READINFO_NONE;
	const BOOLEAN isInitiator = isResumedSession ? \
			( isClient ? FALSE : TRUE ) : isClient;
	const BOOLEAN updateSessionCache = 	\
			( !isResumedSession && handshakeInfo->sessionIDlength > 0 ) ? \
			TRUE : FALSE;
#if defined( USE_EAP ) 
	const BOOLEAN createDerivedKeydata = \
			( sessionInfoPtr->subProtocol == CRYPT_SUBPROTOCOL_EAPTTLS || \
			  sessionInfoPtr->subProtocol == CRYPT_SUBPROTOCOL_PEAP ) ? \
			TRUE : FALSE;
#else
	const BOOLEAN createDerivedKeydata = FALSE;
#endif /* USE_EAP */
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int initiatorHashLength, responderHashLength;
	int tlsLabelLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( MAX_KEYBLOCK_SIZE >= ( sessionInfoPtr->authBlocksize + \
									 handshakeInfo->cryptKeysize +
									 sessionInfoPtr->cryptBlocksize ) * 2 );
	REQUIRES( handshakeInfo->authAlgo == CRYPT_ALGO_NONE || \
			  ( isEccAlgo( handshakeInfo->keyexAlgo ) && \
				handshakeInfo->premasterSecretSize >= MIN_PKCSIZE_ECC ) || \
			  ( !isEccAlgo( handshakeInfo->keyexAlgo ) && \
				handshakeInfo->premasterSecretSize >= TLS_SECRET_SIZE ) );
	REQUIRES( isBooleanValue( isClient ) );
	REQUIRES( isBooleanValue( isResumedSession ) );

	/* Perform the necessary juggling of values for the reversed message
	   flow of resumed sessions */
	if( isResumedSession )
		{
		/* Resumed session, initiator = server, responder = client */
		tlsInitiatorString = "server finished";
		tlsResponderString = "client finished";
		}
	else
		{
		/* Normal session, initiator = client, responder = server */
		tlsInitiatorString = "client finished";
		tlsResponderString = "server finished";
		}
	tlsLabelLength = 15;

#ifndef CONFIG_FUZZ
	/* Initialise and load cryptovariables into all encryption contexts */
	status = initCryptoTLS( sessionInfoPtr, handshakeInfo, masterSecret,
							TLS_SECRET_SIZE, isClient, isResumedSession );
	if( cryptStatusError( status ) )
		return( status );
	if( isResumedSession )
		{
		/* Remember that this is a resumed session in case the caller needs 
		   to know, this is sometimes needed by protocols tunnelled over TLS
		   which change their behaviour based on whether a full or 
		   abbreviated handshake has been used */
		SET_FLAG( sessionInfoPtr->protocolFlags, 
				  TLS_PFLAG_RESUMED_SESSION );
		}
	CFI_CHECK_UPDATE( "initCryptoTLS" );

	/* At this point the hashing of the initiator and responder diverge.
	   The initiator sends its change cipherspec and finished messages 
	   first, so the hashing stops there, while the responder has to keep 
	   hasing the initiator's messages until it's its turn to send its 
	   change cipherspec and finished messages.  To handle this we clone 
	   the initiator's hash context(s) so that we can contine the hashing 
	   after the initiator has wrapped things up */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = cloneHashContext( initiatorMD5context, 
								   &responderMD5context );
		if( cryptStatusOK( status ) )
			{
			status = cloneHashContext( initiatorSHA1context, 
									   &responderSHA1context );
			if( cryptStatusError( status ) )
				{
				krnlSendNotifier( responderMD5context, 
								  IMESSAGE_DECREFCOUNT );
				}
			}
		}
	else
		{
		status = cloneHashContext( initiatorSHA2context, 
								   &responderSHA2context );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, TLS_SECRET_SIZE );
		return( status );
		}
	CFI_CHECK_UPDATE( "cloneHashContext" );

	/* Complete the MAC of the initiator-side messages and, if we're the 
	   responder, check that the MACs match the ones supplied by the 
	   initiator */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = completeTLSHashedMAC( initiatorMD5context, 
							initiatorSHA1context, initiatorHashes, 
							CRYPT_MAX_HASHSIZE * 2, &initiatorHashLength, 
							tlsInitiatorString, tlsLabelLength, masterSecret, 
							TLS_SECRET_SIZE );
		}
	else
		{
		status = completeTLS12HashedMAC( initiatorSHA2context,
							initiatorHashes, CRYPT_MAX_HASHSIZE,
							&initiatorHashLength, tlsInitiatorString, 
							tlsLabelLength, masterSecret, TLS_SECRET_SIZE,
							TEST_FLAG( sessionInfoPtr->protocolFlags, 
									   TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
		}
#else
	initiatorHashLength = \
			TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS ) ? \
					   32 : TLS_HASHEDMAC_SIZE;
	status = CRYPT_OK;
#endif /* CONFIG_FUZZ */
	if( cryptStatusOK( status ) && !isInitiator )
		{
		status = readHandshakeCompletionData( sessionInfoPtr, 
											  initiatorHashes, 
											  initiatorHashLength, 
											  &readInfo );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, TLS_SECRET_SIZE );
		destroyHashContexts( responderMD5context, responderSHA1context,
							 responderSHA2context );

		/* We have to explicitly handle crypto failures at this point 
		   because we're not being called from the higher-level session
		   read handlers that do this for us */
		if( readInfo == READINFO_FATAL_CRYPTO )
			registerCryptoFailure();
		return( status );
		}
#ifndef CONFIG_FUZZ
	CFI_CHECK_UPDATE( "completeHashedMAC" );

	/* Now that we have the initiator MACs, complete the dual-hashing/
	   hashing and dual-MAC/MAC of the responder-side messages and destroy 
	   the master secret unless we need to keep it around to update the
	   session cache.  We haven't created the full message yet at this 
	   point so we manually hash the individual pieces so that we can 
	   finally get rid of the master secret */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		status = krnlSendMessage( responderSHA2context, IMESSAGE_CTX_HASH,
				( MESSAGE_CAST ) finishedTemplateTLS, FINISHED_TEMPLATE_SIZE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( responderSHA2context, IMESSAGE_CTX_HASH, 
									  initiatorHashes, initiatorHashLength );
			}
		}
	else
		{
		status = krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH,
				( MESSAGE_CAST ) finishedTemplateTLS, FINISHED_TEMPLATE_SIZE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
				( MESSAGE_CAST ) finishedTemplateTLS, FINISHED_TEMPLATE_SIZE );
			}
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH, 
									  initiatorHashes, initiatorHashLength );
			}
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
									  initiatorHashes, initiatorHashLength );
			}
		}
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, TLS_SECRET_SIZE );
		destroyHashContexts( responderMD5context, responderSHA1context,
							 responderSHA2context );
		return( status );
		}
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_HASH" );
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = completeTLSHashedMAC( responderMD5context, 
							responderSHA1context, responderHashes, 
							CRYPT_MAX_HASHSIZE * 2, &responderHashLength, 
							tlsResponderString, tlsLabelLength, masterSecret, 
							TLS_SECRET_SIZE );
		}
	else
		{
		status = completeTLS12HashedMAC( responderSHA2context, 
							responderHashes, CRYPT_MAX_HASHSIZE * 2, 
							&responderHashLength, tlsResponderString, 
							tlsLabelLength, masterSecret, TLS_SECRET_SIZE,
							TEST_FLAG( sessionInfoPtr->protocolFlags, 
									   TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
		}
	if( !updateSessionCache && !createDerivedKeydata )
		{
		/* If we don't need the master secret beyond this point, clear it 
		   from memory now */
		zeroise( masterSecret, TLS_SECRET_SIZE );
		}
	destroyHashContexts( responderMD5context, responderSHA1context,
						 responderSHA2context );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, TLS_SECRET_SIZE );
		return( status );
		}
	CFI_CHECK_UPDATE( "completeHashedMAC" );
	DEBUG_DUMP_DATA_LABEL( "Initiator hash:",
						   initiatorHashes, initiatorHashLength );
	DEBUG_DUMP_DATA_LABEL( "Responder hash:",
						   responderHashes, initiatorHashLength );

	/* Send our MACs to the other side and read back their response if
	   necessary.  The initiatorHashLength is the same as the 
	   responderHashLength (it's just a naming difference based on the
	   role that we're playing) so we use initiatorHashLength for both */
	status = writeHandshakeCompletionData( sessionInfoPtr, handshakeInfo,
					isInitiator ? initiatorHashes : responderHashes,
					initiatorHashLength /* Same as responderHashLength */,
					( ( isClient && !isResumedSession ) || \
					  ( !isClient && isResumedSession ) ) ? TRUE : FALSE );
#endif /* !CONFIG_FUZZ */
	if( cryptStatusOK( status ) && isInitiator )
		{
		status = readHandshakeCompletionData( sessionInfoPtr, responderHashes,
											  initiatorHashLength, &readInfo );
		}
	if( cryptStatusOK( status ) && updateSessionCache )
		{
		/* The handshake completed successfully, add the master secret to 
		   the session cache */
		status = addSessionToCache( sessionInfoPtr, handshakeInfo, 
									masterSecret, TLS_SECRET_SIZE,
									isClient );
		}
#ifdef USE_EAP
	if( cryptStatusOK( status ) && createDerivedKeydata )
		{
		/* The handshake completed successfully, add the derived keying data
		   required by EAP */
		status = addDerivedKeydata( sessionInfoPtr, handshakeInfo, 
									masterSecret, TLS_SECRET_SIZE,
									sessionInfoPtr->subProtocol );
		}
#endif /* USE_EAP */
	CFI_CHECK_UPDATE( "writeHandshakeCompletionData" );

	/* Clean up */
	zeroise( masterSecret, TLS_SECRET_SIZE );
	if( cryptStatusError( status ) )
		{
		/* We have to explicitly handle crypto failures at this point 
		   because we're not being called from the higher-level session
		   read handlers that do this for us */
		if( readInfo == READINFO_FATAL_CRYPTO )
			registerCryptoFailure();
		return( status );
		}

	ENSURES( CFI_CHECK_SEQUENCE_6( "initCryptoTLS", "cloneHashContext", 
								   "completeHashedMAC", "IMESSAGE_CTX_HASH", 
								   "completeHashedMAC",
								   "writeHandshakeCompletionData" ) );

	return( CRYPT_OK );
	}

#if defined( USE_EAP ) && 0

/* Test against EAPOL test vectors, left in here to document correct 
   operation in future versions */

void testEAPOL( INOUT_PTR SESSION_INFO *sessionInfoPtr,
				INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
static const BYTE eapolClientRandom[] = {
	0xc0, 0x2c, 0x61, 0x51, 0x81, 0x3b, 0x05, 0x47,
	0x64, 0x13, 0x8b, 0x35, 0xbc, 0x86, 0xba, 0xe7,
	0xad, 0x5a, 0xc6, 0xdb, 0x80, 0x1f, 0x8c, 0xe2,
	0x45, 0x15, 0x59, 0xfd, 0xe6, 0xb6, 0x09, 0x87
	};
static const BYTE eapolServerRandom[] = {
	0x34, 0x9f, 0xea, 0x22, 0x08, 0x1e, 0x47, 0xb3,
	0xc8, 0x70, 0x66, 0x54, 0x54, 0xc6, 0x9a, 0x00,
	0x08, 0x16, 0xb7, 0x62, 0xb7, 0x82, 0x58, 0x09,
	0x81, 0x0f, 0x56, 0x9c, 0x49, 0x5f, 0x77, 0x21
	};
static const BYTE eapolMasterSecret[] = {
	0xd8, 0xcc, 0x6b, 0x5c, 0x24, 0xfb, 0x98, 0x78,
	0x04, 0x69, 0x88, 0x2c, 0x42, 0x23, 0x62, 0x2e,
	0x80, 0x35, 0x86, 0x16, 0x2d, 0x2b, 0xac, 0x14,
	0xd6, 0x6e, 0xdc, 0x5c, 0x32, 0xeb, 0xd5, 0x8e,
	0x3b, 0xe7, 0x49, 0x3d, 0x48, 0x48, 0x37, 0x9d,
	0x90, 0x10, 0x57, 0x09, 0x7b, 0xe8, 0x49, 0xac
	};
static const BYTE eapolEAPSecret[] = {
	0x95, 0x85, 0x31, 0x06, 0x11, 0x4a, 0xca, 0x36,
	0xd2, 0xd1, 0xdc, 0xd6, 0x71, 0xc4, 0xfd, 0x75,
	0x55, 0x0b, 0x1b, 0x6b, 0x62, 0xc6, 0x9e, 0x9b,
	0x45, 0x0e, 0xfc, 0xca, 0xbc, 0x67, 0x68, 0xc2,
	0x9c, 0x1a, 0x1e, 0xc1, 0xa5, 0x00, 0x46, 0xf5,
	0x98, 0x8a, 0xb2, 0x25, 0x43, 0x03, 0x10, 0x1b,
	0xde, 0x7a, 0x85, 0xf0, 0xce, 0x3d, 0xfa, 0xf8,
	0x87, 0x43, 0xea, 0xc9, 0xc8, 0xd7, 0x8c, 0x43
	};
const ATTRIBUTE_LIST *attributeInfoPtr;
BYTE masterSecret[ TLS_SECRET_SIZE + 8 ];
int status;

memcpy( handshakeInfo->clientNonce, eapolClientRandom, TLS_NONCE_SIZE );
memcpy( handshakeInfo->serverNonce, eapolServerRandom, TLS_NONCE_SIZE );
memcpy( masterSecret, eapolMasterSecret, TLS_SECRET_SIZE );

status = addDerivedKeydata( sessionInfoPtr, handshakeInfo, masterSecret, 
							TLS_SECRET_SIZE, sessionInfoPtr->subProtocol );
assert( cryptStatusOK( status ) );
attributeInfoPtr = findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_TLS_EAPKEY );
DEBUG_DUMP_DATA( attributeInfoPtr->value, 64 );
if( memcmp( attributeInfoPtr->value, eapolEAPSecret, 64 ) )
	puts( "eapol_test data comparison failed." );
}
#endif /* USE_EAP && 0 */	
#endif /* USE_TLS */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
