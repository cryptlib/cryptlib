/****************************************************************************
*																			*
*						cryptlib SSH Session Management						*
*					   Copyright Peter Gutmann 1998-2021					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#if defined( USE_SSH )

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the session state and handshake information */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionSSH( IN_PTR const SESSION_INFO *sessionInfoPtr )
	{
	const SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( sshInfo, sizeof( SSH_INFO ) ) );

	/* Check the general envelope state */
	if( !sanityCheckSession( sessionInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionSSH: Session check" ));
		return( FALSE );
		}

	/* Check SSH session parameters */
	if( !CHECK_FLAGS( sessionInfoPtr->protocolFlags, SSH_PFLAG_NONE, 
					  SSH_PFLAG_MAX ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionSSH: Protocol flags" ));
		return( FALSE );
		}
	if( sshInfo->packetType < 0x00 || sshInfo->packetType > 0xFF || \
		sshInfo->padLength < 0 || sshInfo->padLength > 255 || \
		sshInfo->readSeqNo < 0 || sshInfo->readSeqNo > LONG_MAX / 2 || \
		sshInfo->writeSeqNo < 0 || sshInfo->writeSeqNo > LONG_MAX / 2 )
		{
		DEBUG_PUTS(( "sanityCheckSessionSSH: Session parameters" ));
		return( FALSE );
		}
	if( ( sshInfo->authRead != TRUE && sshInfo->authRead != FALSE ) || \
		sshInfo->partialPacketDataLength < 0 || \
		sshInfo->partialPacketDataLength >= sessionInfoPtr->receiveBufSize || \
		!isEnumRangeOpt( sshInfo->authType, SSH_AUTHTYPE ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionSSH: State information" ));
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSSHHandshakeInfo( IN_PTR \
										const SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Check exchange hash information */
	if( handshakeInfo->sessionIDlength < 0 || \
		handshakeInfo->sessionIDlength >CRYPT_MAX_HASHSIZE || \
		!( handshakeInfo->exchangeHashAlgo == CRYPT_ALGO_NONE || \
		   isHashAlgo( handshakeInfo->exchangeHashAlgo ) ) || \
		!( handshakeInfo->iExchangeHashContext == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->iExchangeHashContext ) ) )
		{
		DEBUG_PUTS(( "sanityCheckSSHHandshakeInfo: Exchange hash information" ));
		return( FALSE );
		}

	/* Check session ID information */
	if( handshakeInfo->clientKeyexValueLength < 0 || \
		handshakeInfo->clientKeyexValueLength > MAX_ENCODED_KEYEXSIZE || \
		handshakeInfo->serverKeyexValueLength < 0 || \
		handshakeInfo->serverKeyexValueLength > MAX_ENCODED_KEYEXSIZE )
		{
		DEBUG_PUTS(( "sanityCheckSSHHandshakeInfo: Session ID information" ));
		return( FALSE );
		}

	/* Check encryption information */
	if( !( handshakeInfo->pubkeyAlgo == CRYPT_ALGO_NONE || \
		   isSigAlgo( handshakeInfo->pubkeyAlgo ) ) || \
		!( handshakeInfo->hashAlgo == CRYPT_ALGO_NONE || \
		   isHashAlgo( handshakeInfo->hashAlgo ) ) || \
		handshakeInfo->cryptKeysize < 0 || \
		handshakeInfo->cryptKeysize > CRYPT_MAX_KEYSIZE || \
		handshakeInfo->secretValueLength < 0 || \
		handshakeInfo->secretValueLength > CRYPT_MAX_PKCSIZE )
		{
		DEBUG_PUTS(( "sanityCheckSSHHandshakeInfo: Encryption information" ));
		return( FALSE );
		}

	/* Check keyex information */
	if( !( handshakeInfo->keyexAlgo == CRYPT_ALGO_NONE || \
		   isKeyexAlgo( handshakeInfo->keyexAlgo ) ) || \
		!( handshakeInfo->iServerCryptContext == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->iServerCryptContext ) ) || \
		handshakeInfo->serverKeySize < 0 || \
		handshakeInfo->serverKeySize > CRYPT_MAX_PKCSIZE || \
		handshakeInfo->requestedServerKeySize < 0 || \
		handshakeInfo->requestedServerKeySize > CRYPT_MAX_PKCSIZE || \
		handshakeInfo->encodedReqKeySizesLength < 0 || \
		handshakeInfo->encodedReqKeySizesLength > ENCODED_REQKEYSIZE || \
		!isBooleanValue( handshakeInfo->isFixedDH ) || \
		!isBooleanValue( handshakeInfo->isECDH ) )
		{
		DEBUG_PUTS(( "sanityCheckSSHHandshakeInfo: Keyex information" ));
		return( FALSE );
		}

	/* Check pre-authentication information */
	if( handshakeInfo->challengeLength < 0 || \
		handshakeInfo->challengeLength > SSH_PREAUTH_MAX_SIZE || \
		handshakeInfo->responseLength < 0 || \
		handshakeInfo->responseLength > SSH_PREAUTH_MAX_SIZE || \
		handshakeInfo->receivedResponseLength < 0 || \
		handshakeInfo->receivedResponseLength > SSH_PREAUTH_MAX_SIZE )
		{
		DEBUG_PUTS(( "sanityCheckSSHHandshakeInfo: Preauth information" ));
		return( FALSE );
		}

	/* Check miscellaneous information */
	if( !isBooleanValue( handshakeInfo->sendExtInfo ) || \
		!( ( handshakeInfo->algoStringPubkeyTbl == NULL && \
			 handshakeInfo->algoStringPubkeyTblNoEntries == 0 ) || \
		   ( handshakeInfo->algoStringPubkeyTbl != NULL && \
			 isShortIntegerRangeNZ( handshakeInfo->algoStringPubkeyTblNoEntries ) ) ) )
		{
		DEBUG_PUTS(( "sanityCheckSSHHandshakeInfo: Miscellaneous information" ));
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

#if !defined( NDEBUG ) && defined( USE_ERRMSGS ) && defined( __WIN32__ )

/* Dump a message to disk for diagnostic purposes.  Rather than using the 
   normal DEBUG_DUMP() macro we have to use a special-purpose function that 
   provides appropriate naming based on what we're processing */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpSSH( IN_PTR const SESSION_INFO *sessionInfoPtr,
				   IN_BUFFER( length ) const void *buffer, 
				   IN_LENGTH_SHORT const int length,
				   IN_BOOL const BOOLEAN isRead )
	{
	static int messageCount = 1;
	const BYTE *bufPtr = buffer;
	const BOOLEAN encryptionActive = \
		( ( isRead && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) ) || \
		  ( !isRead && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE ) ) ) ? \
		TRUE : FALSE;
	const BOOLEAN isClientID = \
		( !encryptionActive && length >= 7 && \
		  !memcmp( buffer, "SSH-2.0", 7 ) ) ? TRUE : FALSE;
	const BOOLEAN isServerID = \
		( !encryptionActive && length > 7 && \
		  !memcmp( buffer, "SSH-2.0", 7 ) ) ? TRUE : FALSE;
	char fileName[ 1024 + 8 ], *slashPtr;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( buffer,  length ) );

	REQUIRES_V( isIntegerRangeNZ( length ) );
	REQUIRES_V( isBooleanValue( isRead ) );

	/* We don't want to dump too many messages, however SSH is very chatty 
	   so we have to allow at least 30 or some parts of the exchange get 
	   lost */
	if( messageCount > 30 )
		return;

	sprintf_s( fileName, 1024, "ssh%02d%c_", messageCount++, 
			   isRead ? 'r' : 'w' );
	if( isClientID || isServerID )
		{
		/* The initial server-ID messages don't have defined packet names */
		strlcat_s( fileName, 1024, isClientID ? "client_ID" : "server_ID" );
		}
	else
		{
		if( !encryptionActive || isRead )
			{
			if( isRead && length > 1 )
				strlcat_s( fileName, 1024, getSSHPacketName( bufPtr[ 1 ] ) );
			else
				{
				if( !encryptionActive && length > 5 )
					{
					strlcat_s( fileName, 1024, 
							   getSSHPacketName( bufPtr[ 5 ] ) );
					}
				else
					strlcat_s( fileName, 1024, "truncated_packet" );
				}
			}
		else
			strlcat_s( fileName, 1024, "encrypted_packet" );
		}
	slashPtr = strchr( fileName + 5, '/' );
	if( slashPtr != NULL )
		{
		/* Some packet names contain slashes */
		*slashPtr = '\0'; 
		}
	strlcat_s( fileName, 1024, ".dat" );
	debugSanitiseFilename( fileName );

	if( isRead && !isServerID )
		{
		STREAM stream;
		BYTE lengthBuffer[ UINT32_SIZE + 8 ];

		/* The read code has stripped the length field at the start so we
		   have to reconstruct it and prepend it to the data being written */
		sMemOpen( &stream, lengthBuffer, UINT32_SIZE );
		writeUint32( &stream, length );
		sMemDisconnect( &stream );
		DEBUG_DUMP_FILE2( fileName, lengthBuffer, UINT32_SIZE, 
						  buffer, length );
		}
	else
		DEBUG_DUMP_FILE( fileName, buffer, length );
	}
#endif /* Windows debug mode only */

/* Initialise and destroy the handshake state information */

STDC_NONNULL_ARG( ( 1 ) ) \
static void initHandshakeInfo( OUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	/* Initialise the handshake state information values */
	memset( handshakeInfo, 0, sizeof( SSH_HANDSHAKE_INFO ) );
	handshakeInfo->iExchangeHashContext = \
		handshakeInfo->iExchangeHashAltContext = \
			handshakeInfo->iServerCryptContext = CRYPT_ERROR;
	initHandshakeCrypt( handshakeInfo );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
static void destroyHandshakeInfo( INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	if( handshakeInfo->iExchangeHashContext != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->iExchangeHashContext,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->iExchangeHashAltContext != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->iExchangeHashAltContext,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->iServerCryptContext != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->iServerCryptContext,
						  IMESSAGE_DECREFCOUNT );

	/* Clear the handshake state information, then reset it to explicit non-
	   initialised values */
	zeroise( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) );
	initHandshakeInfo( handshakeInfo );
	}

/* Initialise any crypto that's needed to start the handshake */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initHandshakeCrypto( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );

	/* If we're fuzzing then there's no crypto active */
	FUZZ_SKIP_REMAINDER();

	/* SSHv2 hashes parts of the handshake messages for integrity-protection
	   purposes so we create a context for the hash.  In addition since the 
	   handshake can retroactively switch to a different hash algorithm mid-
	   exchange we have to speculatively hash the messages with SHA2 as well
	   as SHA1 in case the other side decides to switch */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA1 );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	handshakeInfo->iExchangeHashContext = createInfo.cryptHandle;
	if( algoAvailable( CRYPT_ALGO_SHA2 ) )
		{
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA2 );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( handshakeInfo->iExchangeHashContext, 
							  IMESSAGE_DECREFCOUNT );
			handshakeInfo->iExchangeHashContext = CRYPT_ERROR;
			return( status );
			}
		handshakeInfo->iExchangeHashAltContext = createInfo.cryptHandle;
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Connect to an SSH server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int completeHandshake( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	SSH_HANDSHAKE_FUNCTION handshakeFunction;
	SES_SHUTDOWN_FUNCTION shutdownFunction;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );

	handshakeFunction = ( SSH_HANDSHAKE_FUNCTION ) \
						FNPTR_GET( handshakeInfo->completeHandshake );
	shutdownFunction = ( SES_SHUTDOWN_FUNCTION ) \
					   FNPTR_GET( sessionInfoPtr->shutdownFunction );
	REQUIRES( handshakeFunction != NULL );
	REQUIRES( shutdownFunction != NULL );

	status = handshakeFunction( sessionInfoPtr, handshakeInfo );
	destroyHandshakeInfo( handshakeInfo );
	if( cryptStatusError( status ) )
		{
		/* If we need confirmation from the user before continuing, let
		   them know */
		if( status == CRYPT_ENVELOPE_RESOURCE )
			return( status );

		/* At this point we could be in the secure state so we have to
		   keep the security information around until after we've called 
		   the shutdown function, which could require sending secured 
		   data */
		disableErrorReporting( sessionInfoPtr );
		delayRandom();	/* Dither error timing info */
		shutdownFunction( sessionInfoPtr );
		destroySecurityContextsSSH( sessionInfoPtr );
		return( status );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completeStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	SES_SHUTDOWN_FUNCTION shutdownFunction;
	SSH_HANDSHAKE_FUNCTION handshakeFunction;
	SSH_HANDSHAKE_INFO handshakeInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );

	shutdownFunction = ( SES_SHUTDOWN_FUNCTION ) \
					   FNPTR_GET( sessionInfoPtr->shutdownFunction );
	REQUIRES( shutdownFunction != NULL );

	/* Initialise the handshake information */
	initHandshakeInfo( &handshakeInfo );
	if( isServer( sessionInfoPtr ) )
		initSSH2serverProcessing( &handshakeInfo );
	else
		initSSH2clientProcessing( &handshakeInfo );

	/* If we're the server and we're completing a handshake that was 
	   interrupted while we got confirmation of the client auth, skip the 
	   initial handshake stages and go straight to the handshake completion 
	   stage */
	if( isServer( sessionInfoPtr ) && \
		TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_PARTIALOPEN ) )
		return( completeHandshake( sessionInfoPtr, &handshakeInfo ) );

	/* If we're the server, we have to speak first to get things started.  
	   Note that standard cryptlib practice for sessions is to wait for 
	   input from the client, make sure that it looks reasonable and only 
	   then send back a reply of any kind.  If anything that doesn't look 
	   right arrives, we close the connection immediately without any 
	   response.  Unfortunately this isn't possible with SSH, which requires 
	   that the server send data before the client does */
	if( isServer( sessionInfoPtr ) )
		{
		status = writeSSHID( sessionInfoPtr, &handshakeInfo );
		if( cryptStatusError( status ) )
			{
			/* Since the session hasn't begun yet we exit without any
			   additional processing */
			destroyHandshakeInfo( &handshakeInfo );
			return( status );
			}
		}

	/* Read the other side's SSH ID */
	status = readSSHID( sessionInfoPtr, &handshakeInfo );
	if( cryptStatusOK( status ) && isServer( sessionInfoPtr ) && \
		handshakeInfo.challengeLength > 0 )
		{
		/* We're the server and we sent a pre-authentication challenge,
		   make sure that the client has provided a response */
		status = checkPreauthResponse( &handshakeInfo, SESSION_ERRINFO );
		}
	if( cryptStatusOK( status ) )
		status = initHandshakeCrypto( sessionInfoPtr, &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		/* Since the session hasn't begun yet we exit without any additional 
		   processing */
		destroyHandshakeInfo( &handshakeInfo );
		return( status );
		}

	/* If we're the client we now have to send our SSH ID in response to 
	   what the server sent us */
	if( !isServer( sessionInfoPtr ) )
		{
		status = writeSSHID( sessionInfoPtr, &handshakeInfo );
		if( cryptStatusError( status ) )
			{
			/* Since the session hasn't begun yet we exit without any 
			   additional processing */
			destroyHandshakeInfo( &handshakeInfo );
			return( status );
			}
		}

	/* Begin the handshake, which consists of first reading the other side's 
	   SSH ID and then starting the actual SSH handshake process */
	handshakeFunction = ( SSH_HANDSHAKE_FUNCTION ) \
						FNPTR_GET( handshakeInfo.beginHandshake );
	ENSURES( handshakeFunction != NULL );
	status = handshakeFunction( sessionInfoPtr, &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		/* If we run into an error at this point we need to disable error-
		   reporting during the shutdown phase since we've already got 
		   status information present from the already-encountered error */
		destroyHandshakeInfo( &handshakeInfo );
		disableErrorReporting( sessionInfoPtr );
		delayRandom();	/* Dither error timing info */
		shutdownFunction( sessionInfoPtr );
		return( status );
		}

	/* Exchange a key with the server */
	handshakeFunction = ( SSH_HANDSHAKE_FUNCTION ) \
						FNPTR_GET( handshakeInfo.exchangeKeys );
	ENSURES( handshakeFunction != NULL );
	status = handshakeFunction( sessionInfoPtr, &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		destroySecurityContextsSSH( sessionInfoPtr );
		destroyHandshakeInfo( &handshakeInfo );
		disableErrorReporting( sessionInfoPtr );
		delayRandom();	/* Dither error timing info */
		shutdownFunction( sessionInfoPtr );
		return( status );
		}

	/* If we're fuzzing the input then we're reading static data for which 
	   we can't go beyond this point */
	FUZZ_EXIT();

	/* Complete the handshake */
	return( completeHandshake( sessionInfoPtr, &handshakeInfo ) );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 OUT_PTR void *data, 
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) data;
#ifdef USE_SSH_EXTENDED
	int status;
#endif /* USE_SSH_EXTENDED */

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
#ifdef USE_SSH_EXTENDED
	REQUIRES( type == CRYPT_SESSINFO_SSH_CHANNEL ||\
			  type == CRYPT_SESSINFO_SSH_CHANNEL_TYPE || \
			  type == CRYPT_SESSINFO_SSH_CHANNEL_ARG1 || \
			  type == CRYPT_SESSINFO_SSH_CHANNEL_ARG2 || \
			  type == CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE || \
			  type == CRYPT_SESSINFO_SSH_PREAUTH );
#else
	REQUIRES( type == CRYPT_SESSINFO_SSH_PREAUTH );
#endif /* USE_SSH_EXTENDED */

	if( type == CRYPT_SESSINFO_SSH_PREAUTH )
		{
		const ATTRIBUTE_LIST *attributeListPtr;

		attributeListPtr = findSessionInfo( sessionInfoPtr, 
											CRYPT_SESSINFO_SSH_PREAUTH );
		if( attributeListPtr == NULL )
			{
			setObjectErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_SSH_PREAUTH, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		return( attributeCopy( msgData, attributeListPtr->value,
							   attributeListPtr->valueLength ) );
		}
#ifdef USE_SSH_EXTENDED
	if( type == CRYPT_SESSINFO_SSH_CHANNEL || \
		type == CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE )
		{
		status = getChannelAttribute( sessionInfoPtr, type, data );
		}
	else
		{
		status = getChannelAttributeS( sessionInfoPtr, type, msgData->data, 
									   msgData->length, &msgData->length );
		}
	return( ( status == CRYPT_ERROR ) ? CRYPT_ARGERROR_NUM1 : status );
#else
	retIntError();
#endif /* USE_SSH_EXTENDED */
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int setAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 IN_PTR const void *data,
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
#ifdef USE_SSH_EXTENDED
	int value DUMMY_INIT, status;
#endif /* USE_SSH_EXTENDED */

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
#ifdef USE_SSH_EXTENDED
	REQUIRES( type == CRYPT_SESSINFO_SSH_CHANNEL || \
			  type == CRYPT_SESSINFO_SSH_CHANNEL_TYPE || \
			  type == CRYPT_SESSINFO_SSH_CHANNEL_ARG1 || \
			  type == CRYPT_SESSINFO_SSH_CHANNEL_ARG2 || \
			  type == CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE || \
			  type == CRYPT_SESSINFO_SSH_PREAUTH );
#else
	REQUIRES( type == CRYPT_SESSINFO_SSH_PREAUTH );
#endif /* USE_SSH_EXTENDED */

	/* If it's a pre-authentication value, just add it */
	if( type == CRYPT_SESSINFO_SSH_PREAUTH )
		{
		const MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) data;

		return( addSessionInfoS( sessionInfoPtr, CRYPT_SESSINFO_SSH_PREAUTH, 
								 msgData->data, msgData->length ) );
		}

#ifdef USE_SSH_EXTENDED
	/* Get the data value if it's an integer parameter */
	if( type == CRYPT_SESSINFO_SSH_CHANNEL || \
		type == CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE )
		value = *( ( int * ) data );

	/* If we're selecting a channel and there's unwritten data from a
	   previous write still in the buffer, we can't change the write
	   channel */
	if( type == CRYPT_SESSINFO_SSH_CHANNEL && sessionInfoPtr->partialWrite )
		{
		retExt( CRYPT_ERROR_INCOMPLETE, 
				( CRYPT_ERROR_INCOMPLETE, SESSION_ERRINFO, 
				  "New channel can't be selected while unwritten data "
				  "remains in the current channel" ) );
		}

	/* If we're creating a new channel by setting the value to CRYPT_UNUSED,
	   create the new channel */
	if( type == CRYPT_SESSINFO_SSH_CHANNEL && value == CRYPT_UNUSED )
		{
		/* If the session hasn't been activated yet, we can only create a
		   single channel during session activation, any subsequent ones
		   have to be handled later */
		if( !TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISOPEN ) && \
			getCurrentChannelNo( sessionInfoPtr, \
								 CHANNEL_READ ) != UNUSED_CHANNEL_NO )
			{
			retExt( CRYPT_ERROR_NOTINITED, 
					( CRYPT_ERROR_NOTINITED, SESSION_ERRINFO, 
					  "Channels can only be created once the session has "
					  "been activated" ) );
			}

		return( createChannel( sessionInfoPtr ) );
		}

	/* If we 're setting the channel-active attribute, this implicitly
	   activates or deactivates the channel rather than setting any
	   attribute value */
	if( type == CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE )
		{
		if( value )
			return( sendChannelOpen( sessionInfoPtr ) );
		return( closeChannel( sessionInfoPtr, FALSE ) );
		}

	if( type == CRYPT_SESSINFO_SSH_CHANNEL )
		status = setChannelAttribute( sessionInfoPtr, type, value );
	else
		{
		const MESSAGE_DATA *msgData = data;

		status = setChannelAttributeS( sessionInfoPtr, type, msgData->data, 
									   msgData->length );
		}
	return( ( status == CRYPT_ERROR ) ? CRYPT_ARGERROR_NUM1 : status );
#else
	retIntError();
#endif /* USE_SSH_EXTENDED */
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkAttributeFunction( SESSION_INFO *sessionInfoPtr,
								   IN_PTR const void *data,
								   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	const CRYPT_CONTEXT cryptContext = *( ( CRYPT_CONTEXT * ) data );
	MESSAGE_DATA msgData;
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	STREAM stream;
	BYTE buffer[ 128 + ( CRYPT_MAX_PKCSIZE * 4 ) + 8 ];
	BYTE fingerPrint[ CRYPT_MAX_HASHSIZE + 8 ];
	void *blobData DUMMY_INIT_PTR;
	int blobDataLength DUMMY_INIT, hashSize, pkcAlgo, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( isAttribute( type ) );

	if( type != CRYPT_SESSINFO_PRIVATEKEY )
		return( CRYPT_OK );

	/* If it's an ECC key then it has to be one of NIST { P256, P384, P521 }.
	   Unfortunately there's no easy way to determine whether the curve 
	   being used is an SSH-compatible one or not since the user could load
	   their own custom 256-bit curve, or conversely load a known NIST curve 
	   as a series of discrete key parameters, for now we just assume that a 
	   curve of the given size is the correct one */
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE, 
							  &pkcAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	if( isEccAlgo( pkcAlgo ) )
		{
		int keySize;

		status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE, 
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		if( keySize != bitsToBytes( 256 ) && \
			keySize != bitsToBytes( 384 ) && \
			keySize != bitsToBytes( 521 ) )
			return( CRYPT_ARGERROR_NUM1 );
		}

	/* Only the server key has a fingerprint */
	if( !isServer( sessionInfoPtr ) )
		return( CRYPT_OK );

	getHashAtomicParameters( CRYPT_ALGO_MD5, 0, &hashFunctionAtomic, 
							 &hashSize );

	/* The fingerprint is computed from the "key blob", which is different
	   from the server key.  The server key is the full key while the "key
	   blob" is only the raw key components (e, n for RSA, p, q, g, y for
	   DSA) so we have to skip the key header before we hash the key data:

		uint32		length
			string	algorithm
			byte[]	key_blob

	   Note that, as with the old PGP 2.x key hash mechanism, this allows
	   key spoofing (although it isn't quite as bad as the PGP 2.x key
	   fingerprint mechanism) since it doesn't hash an indication of the key
	   type or format */
	setMessageData( &msgData, buffer, 128 + ( CRYPT_MAX_PKCSIZE * 4 ) );
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEY_SSH );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, buffer, msgData.length );
	readUint32( &stream );					/* Length */
	status = readUniversal32( &stream );	/* Algorithm ID */
	if( cryptStatusOK( status ) )
		{
		status = sMemGetDataBlockRemaining( &stream, &blobData, 
											&blobDataLength );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	hashFunctionAtomic( fingerPrint, CRYPT_MAX_HASHSIZE, blobData, 
						blobDataLength );

	/* Add the fingerprint */
	return( addSessionInfoS( sessionInfoPtr,
							 CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
							 fingerPrint, hashSize ) );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodSSH( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		FALSE,						/* Request-response protocol */
		 SESSION_PROTOCOL_FIXEDSIZECREDENTIALS,	/* Flags */
		SSH_PORT,					/* SSH port */
		SESSION_NEEDS_USERID |		/* Client attributes */
			SESSION_NEEDS_PASSWORD | \
			SESSION_NEEDS_KEYORPASSWORD | \
			SESSION_NEEDS_PRIVKEYSIGN,
				/* The client private key is optional, but if present it has
				   to be signature-capable */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYSIGN,
		2, 2, 2,					/* Version 2 */
		CRYPT_SUBPROTOCOL_NONE, CRYPT_SUBPROTOCOL_NONE,
									/* Allowed sub-protocols */

		/* Protocol-specific information */
		EXTRA_PACKET_SIZE + \
			DEFAULT_PACKET_SIZE,	/* Send/receive buffer size */
		SSH2_HEADER_SIZE + \
			SSH2_PAYLOAD_HEADER_SIZE,/* Payload data start */
		DEFAULT_PACKET_SIZE			/* (Default) maximum packet size */
		};

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Set the access method pointers */
	DATAPTR_SET( sessionInfoPtr->protocolInfo, ( void * ) &protocolInfo );
	FNPTR_SET( sessionInfoPtr->transactFunction, completeStartup );
	initSSH2processing( sessionInfoPtr );
	FNPTR_SET( sessionInfoPtr->getAttributeFunction, getAttributeFunction );
	FNPTR_SET( sessionInfoPtr->setAttributeFunction, setAttributeFunction );
	FNPTR_SET( sessionInfoPtr->checkAttributeFunction, checkAttributeFunction );

	return( CRYPT_OK );
	}
#endif /* USE_SSH */
