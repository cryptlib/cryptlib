<<<<<<< HEAD
/****************************************************************************
*																			*
*						cryptlib TLS Session Management						*
*					   Copyright Peter Gutmann 1998-2022					*
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

/* Warn about the use of RSA keyex */

#if ( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) ) && \
	defined( USE_RSA_SUITES )
  #pragma message( "  Warning: RSA keyex is insecure, this should not be used in a production environment." )
#endif /* Notify insecure keyex use */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the session state and handshake information */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionTLS( IN_PTR const SESSION_INFO *sessionInfoPtr )
	{
	const TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( tlsInfo, sizeof( TLS_INFO ) ) );

	/* Check the general session state */
	if( !sanityCheckSession( sessionInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionTLS: Session check" ));
		return( FALSE );
		}

	/* Check TLS session parameters */
	if( !CHECK_FLAGS( sessionInfoPtr->protocolFlags, 
					  TLS_PFLAG_NONE, TLS_PFLAG_MAX ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionTLS: Protocol flags" ));
		return( FALSE );
		}
	if( tlsInfo->minVersion < 0 || \
		tlsInfo->minVersion > TLS_MINOR_VERSION_TLS13 || \
		( tlsInfo->ivSize != 0 && tlsInfo->ivSize != 8 && \
		  tlsInfo->ivSize != 16 ) || \
		tlsInfo->readSeqNo < 0 || tlsInfo->readSeqNo > LONG_MAX / 2 || \
		tlsInfo->writeSeqNo < 0 || tlsInfo->writeSeqNo > LONG_MAX / 2 
#if defined( USE_GCM ) || defined( USE_CHACHA20 )
		|| tlsInfo->aeadSaltSize < 0 || \
		tlsInfo->aeadSaltSize > CRYPT_MAX_IVSIZE 
#endif /* USE_GCM || USE_CHACHA20 */
		)
		{
		DEBUG_PUTS(( "sanityCheckSessionTLS: Session parameters" ));
		return( FALSE );
		}

	/* Check safe pointers */
	if( !DATAPTR_ISVALID( tlsInfo->savedHandshakeInfo ) || \
		!DATAPTR_ISVALID( tlsInfo->scoreboardInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionTLS: Safe pointers" ));
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckTLSHandshakeInfo( IN_PTR \
										const TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Check client and server hash contexts */
	if( !( handshakeInfo->md5context == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->md5context ) ) || \
		!( handshakeInfo->sha1context == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->sha1context ) ) || \
		!( handshakeInfo->sha2context == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->sha2context ) ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: Hash contexts" ));
		return( FALSE );
		}

	/* Check session state information */
	if( handshakeInfo->sessionIDlength < 0 || \
		handshakeInfo->sessionIDlength > MAX_SESSIONID_SIZE || \
		!isBooleanValue( handshakeInfo->hashedSNIpresent ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: State information" ));
		return( FALSE );
		}

	/* Check hello hash and premaster secret information */
	if( handshakeInfo->helloHashSize < 0 || \
		handshakeInfo->helloHashSize > CRYPT_MAX_HASHSIZE || \
		handshakeInfo->sessionHashSize < 0 || \
		handshakeInfo->sessionHashSize > CRYPT_MAX_HASHSIZE || \
		handshakeInfo->premasterSecretSize < 0 || \
		handshakeInfo->premasterSecretSize > CRYPT_MAX_PKCSIZE + \
											 CRYPT_MAX_TEXTSIZE + 8 )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: Hello hash/premaster information" ));
		return( FALSE );
		}

	/* Check encryption information */
	if( !( handshakeInfo->dhContext == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->dhContext ) ) || 
#ifdef USE_TLS13
		!( handshakeInfo->dhContextAlt == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->dhContextAlt ) ) || 
#endif /* USE_TLS13 */
		!( handshakeInfo->keyexAlgo == CRYPT_ALGO_NONE || \
		   isKeyexAlgo( handshakeInfo->keyexAlgo ) || \
		   handshakeInfo->keyexAlgo == CRYPT_ALGO_RSA ) || \
		!( handshakeInfo->authAlgo == CRYPT_ALGO_NONE || \
		   isSigAlgo( handshakeInfo->authAlgo ) ) || \
		!( handshakeInfo->keyexSigHashAlgo == CRYPT_ALGO_NONE || \
		   isHashAlgo( handshakeInfo->keyexSigHashAlgo ) ) || \
		handshakeInfo->cryptKeysize < 0 || \
		handshakeInfo->cryptKeysize > CRYPT_MAX_KEYSIZE )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: Encryption information" ));
		return( FALSE );
		}

	/* Check miscellaneous information */
	if( handshakeInfo->clientOfferedVersion < TLS_MINOR_VERSION_SSL || \
		handshakeInfo->clientOfferedVersion > TLS_MINOR_VERSION_TLS13 || \
		handshakeInfo->originalVersion < TLS_MINOR_VERSION_SSL || \
		handshakeInfo->originalVersion > TLS_MINOR_VERSION_TLS13 || \
		!isFlagRangeZ( handshakeInfo->flags, HANDSHAKE ) || \
		!isEnumRangeOpt( handshakeInfo->fallbackType, TLS_FALLBACK ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: Miscellaneous information" ));
		return( FALSE );
		}

	/* Check ECC information */
	if( !isBooleanValue( handshakeInfo->disableECC ) || \
		!isEnumRangeOpt( handshakeInfo->eccCurveID, CRYPT_ECCCURVE ) || \
		!isBooleanValue( handshakeInfo->sendECCPointExtn ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: ECC information" ));
		return( FALSE );
		}

	/* Check TLS 1.3 information */
#ifdef USE_TLS13
	if( !isShortIntegerRange( handshakeInfo->originalClientHelloLength ) || \
		!isShortIntegerRange( handshakeInfo->originalServerHelloLength ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: TLS 1.3 information" ));
		return( FALSE );
		}
#endif /* USE_TLS13 */	

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

#if defined( __WIN32__ ) && defined( USE_ERRMSGS ) && !defined( NDEBUG )

/* Dump a message to disk for diagnostic purposes.  The TLS messages are
   broken up into parts by the read/write code so that we can't use the 
   normal DEBUG_DUMP() macro but have to use a special-purpose function that 
   assembles the packet contents if required, as well as providing 
   appropriate naming */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpTLS( const SESSION_INFO *sessionInfoPtr,
				   IN_BUFFER( buffer1size ) const void *buffer1, 
				   IN_LENGTH_SHORT const int buffer1size,
				   IN_BUFFER_OPT( buffer2size ) const void *buffer2, 
				   IN_LENGTH_SHORT_Z const int buffer2size )
	{
	static int messageCount = 1;
	const BYTE *bufPtr = buffer1;
	const BOOLEAN isRead = ( buffer2 != NULL ) ? TRUE : FALSE;
	const BOOLEAN encryptionActive = \
		( ( isRead && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) ) || \
		  ( !isRead && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE ) ) ) ? \
		TRUE : FALSE;
	char fileName[ 1024 + 8 ];

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( buffer1,  buffer1size ) );
	assert( ( buffer2 == NULL && buffer2size == 0 ) || \
			isReadPtrDynamic( buffer2, buffer2size ) );

	if( messageCount > 20 )
		return;	/* Don't dump too many messages */
	sprintf_s( fileName, 1024, "tls3%d_%02d%c_", 
			   sessionInfoPtr->version, messageCount++, 
			   isRead ? 'r' : 'w' );
	if( bufPtr[ 0 ] == TLS_MSG_HANDSHAKE && !encryptionActive )
		{
		if( isRead && buffer2size >= 1 )
			{
			strlcat_s( fileName, 1024, 
					   getTLSHSPacketName( ( ( BYTE * ) buffer2 )[ 0 ] ) );
			}
		else
			{
			if( !isRead && buffer1size >= 6 )
				{
				strlcat_s( fileName, 1024, 
						   getTLSHSPacketName( bufPtr[ 5 ] ) );
				}
			else
				strlcat_s( fileName, 1024, "truncated_packet" );
			}
		}
	else	
		strlcat_s( fileName, 1024, getTLSPacketName( bufPtr[ 0 ] ) );
	strlcat_s( fileName, 1024, ".dat" );
	debugSanitiseFilename( fileName );

	if( buffer2 == NULL )
		DEBUG_DUMP_FILE( fileName, buffer1, buffer1size );
	else
		{
		DEBUG_DUMP_FILE2( fileName, buffer1, buffer1size, 
						  buffer2, buffer2size );
		}
	}
#endif /* Windows debug mode only */

/* Initialise and destroy the handshake state information */

STDC_NONNULL_ARG( ( 1 ) ) \
static void destroyHandshakeInfo( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	destroyHandshakeCryptInfo( handshakeInfo );

	zeroise( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initHandshakeInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  OUT_ALWAYS TLS_HANDSHAKE_INFO *handshakeInfo,
							  IN_BOOL const BOOLEAN isServer )
	{
	const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );

	ENSURES( protocolInfo != NULL );

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isBooleanValue( isServer ) );

	memset( handshakeInfo, 0, sizeof( TLS_HANDSHAKE_INFO ) );
	if( isServer )
		initTLSserverProcessing( handshakeInfo );
	else
		initTLSclientProcessing( handshakeInfo );
	handshakeInfo->originalVersion = sessionInfoPtr->version;
	if( sessionInfoPtr->sessionTLS->minVersion <= 0 )
		{
		/* Set the minimum accepted protocol version if required */
		sessionInfoPtr->sessionTLS->minVersion = protocolInfo->minVersion;
		}
	return( initHandshakeCryptInfo( sessionInfoPtr, handshakeInfo ) );
	}

/* Push and pop the handshake state */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int pushHandshakeInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	void *savedHandshakeInfo;
	const int bufPos = sessionInfoPtr->sendBufSize - \
					   sizeof( TLS_HANDSHAKE_INFO );

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Save the handshake state so that we can resume the handshake later 
	   on.  This is somewhat ugly in that we need to store 
	   sizeof( TLS_HANDSHAKE_INFO ) bytes of data somewhere.  One way to do 
	   this would be to allocate memory, use it for storage, and free it 
	   again, however we have the send buffer sitting unused so we save it 
	   at the end of the send buffer.  
	   
	   This creates the slight problem that we're saving the premaster 
	   secret in the send buffer and potentially exposing it to a bug in 
	   the send code, however it would have to be a pretty unusual bug to 
	   jump into the send function and then write a block of data all the 
	   way at the end of the buffer, far past where a handshake packet would 
	   be, to the peer */
	REQUIRES( bufPos > 1024 && bufPos < sessionInfoPtr->sendBufSize - 512 );
	savedHandshakeInfo = sessionInfoPtr->sendBuffer + bufPos;
	memcpy( savedHandshakeInfo, handshakeInfo, 
			sizeof( TLS_HANDSHAKE_INFO ) );
	DATAPTR_SET( tlsInfo->savedHandshakeInfo, savedHandshakeInfo );

	/* Clear the original copy of the handshake info (without doing a full 
	   cleanup of objects and so on), which leaves the copy that we've just 
	   made intact */
	zeroise( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) );
	
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int popHandshakeInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 OUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	void *savedHandshakeInfo;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Restore the saved handshake state so that we can continue a partially-
	   completed handshake */
	savedHandshakeInfo = DATAPTR_GET( tlsInfo->savedHandshakeInfo );
	REQUIRES( savedHandshakeInfo != NULL );
	memcpy( handshakeInfo, savedHandshakeInfo, 
			sizeof( TLS_HANDSHAKE_INFO ) );
	zeroise( savedHandshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) );
	DATAPTR_SET( tlsInfo->savedHandshakeInfo, NULL );

	ENSURES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	
	return( CRYPT_OK );
	}

/* TLS uses 24-bit lengths in some places even though the maximum packet 
   length is only 16 bits (actually it's limited even further by the spec 
   to 14 bits).  To handle this odd length we define our own read/
   writeUint24() functions that always set the high byte to zero */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
int readUint24( INOUT_PTR STREAM *stream )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( status != 0 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readUint16( stream ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint24( INOUT_PTR STREAM *stream, IN_LENGTH_Z const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES_S( length >= 0 && \
				length < MAX_PACKET_SIZE + EXTRA_PACKET_SIZE );

	sputc( stream, 0 );
	return( writeUint16( stream, length ) );
	}

/* The ECDH public value is a bit complex to process because it's the usual 
   X9.62 stuff-point-data-into-a-byte-string value, and to make things even 
   messier it's stored with an 8-bit length instead of a 16-bit one so we 
   can't even read it as an integer16U().  To work around this we have to 
   duplicate a certain amount of the integer-read code here */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int readEcdhValue( INOUT_PTR STREAM *stream,
				   OUT_BUFFER( valueMaxLen, *valueLen ) void *value,
				   IN_LENGTH_SHORT_MIN( 64 ) const int valueMaxLen,
				   OUT_LENGTH_BOUNDED_Z( valueMaxLen ) int *valueLen )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( value, valueMaxLen ) );
	assert( isWritePtr( valueLen, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( valueMaxLen, 64 ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( valueMaxLen ) ); 
	memset( value, 0, min( 16, valueMaxLen ) );
	*valueLen = 0;

	/* Get the length (as a byte) and make sure that it's valid */
	status = length = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( isShortECCKey( length / 2 ) )
		return( CRYPT_ERROR_NOSECURE );
	if( length < MIN_PKCSIZE_ECCPOINT || length > MAX_PKCSIZE_ECCPOINT )
		return( CRYPT_ERROR_BADDATA );
	*valueLen = length;

	/* Read the X9.62 point value */
	return( sread( stream, value, length ) );
	}

/* Abort a session startup */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int abortStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR_OPT TLS_HANDSHAKE_INFO *handshakeInfo,
						 IN_BOOL const BOOLEAN cleanupSecurityContexts,
						 IN_ERROR const int errorStatus )
	{
	BOOLEAN isFatalError;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( handshakeInfo == NULL || \
			isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( cleanupSecurityContexts ) );
	REQUIRES( cryptStatusError( errorStatus ) );

	/* If the error condition on the stream is fatal, don't try and perform
	   any shutdown actions */
	status = sioctlGet( &sessionInfoPtr->stream, STREAM_IOCTL_ISFATALERROR, 
						&isFatalError, sizeof( BOOLEAN ) );
	if( cryptStatusOK( status ) && !isFatalError )
		{
		sendHandshakeFailAlert( sessionInfoPtr, 
								( handshakeInfo != NULL && \
								  handshakeInfo->failAlertType != 0 ) ? \
									handshakeInfo->failAlertType : \
									TLS_ALERT_HANDSHAKE_FAILURE );
		}

	/* Clean up any objects */
	if( cleanupSecurityContexts )
		destroySecurityContextsTLS( sessionInfoPtr );
	if( handshakeInfo != NULL )
		destroyHandshakeInfo( handshakeInfo );
	return( errorStatus );
	}

#ifdef CONFIG_SUITEB

/* Check that a private key is valid for Suite B use */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkSuiteBKey( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   IN_HANDLE const CRYPT_CONTEXT cryptContext,
						   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	int keySize, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isPkcAlgo( cryptAlgo ) );

	/* Suite B only allows P256 and P384 keys so we need to make sure that
	   the server key is of the appropriate type and size */
	if( cryptAlgo != CRYPT_ALGO_ECDSA )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_CTXINFO_ALGO, 
							CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE, &keySize,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );
#ifdef CONFIG_SUITEB_TESTS 
	if( suiteBTestValue == SUITEB_TEST_SVRINVALIDCURVE && \
		keySize == bitsToBytes( 521 ) )
		return( CRYPT_OK );
#endif /* CONFIG_SUITEB_TESTS */
	if( keySize != bitsToBytes( 256 ) && keySize != bitsToBytes( 384 ) )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_CTXINFO_KEYSIZE, 
							CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* In addition if a specific crypto strength has been configured then 
	   the key size has to correspond to that strength.  At 128 bits we can
	   use both P256 and P384, but at 256 bits we have to use P384 */
	if( ( ( sessionInfoPtr->flags & TLS_PFLAG_SUITEB ) == TLS_PFLAG_SUITEB_256 ) && \
		keySize != bitsToBytes( 384 ) )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_CTXINFO_KEYSIZE, 
							CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

#ifdef CONFIG_SUITEB_TESTS 

/* Special kludge function used to enable nonstandard behaviour for Suite
   B tests.  The magic value is used in appropriate locations to enable
   nonstandard behaviour for testing purposes.  The values are listed in
   tls.h */

SUITEB_TEST_VALUE suiteBTestValue = SUITEB_TEST_NONE;
BOOLEAN suiteBTestClientCert = FALSE;

int tlsSuiteBTestConfig( const int magicValue )
	{
	REQUIRES( ( magicValue >= SUITEB_TEST_NONE && \
				magicValue < SUITEB_TEST_LAST ) || \
			  magicValue == 1000 );

	/* If it's the client-cert test indicator, set the flag and exit */
	if( magicValue == 1000 )
		{
		suiteBTestClientCert = TRUE;

		return( CRYPT_OK );
		}

	suiteBTestValue = magicValue;
	if( magicValue == 0 )
		{
		/* If we're doing a reset, clear the client-cert test indicator as
		   well */
		suiteBTestClientCert = FALSE;
		}

	return( CRYPT_OK );
	}
#endif /* CONFIG_SUITEB_TESTS  */
#endif /* CONFIG_SUITEB */

/****************************************************************************
*																			*
*						Read/Write TLS Certificate Chains					*
*																			*
****************************************************************************/

/* Read/write a TLS certificate chain:

	byte		ID = TLS_HAND_CERTIFICATE
	uint24		len
	uint24		certListLen
		uint24		certLen		| 1...n certificates ordered
		byte[]		certificate	|   leaf -> root 

   With TLS 1.3's mania for pointlessly fiddling with every standard message 
   and mechanism, the format was changed to:

	byte		ID = TLS_HAND_CERTIFICATE
	uint24		len
	byte		certContextLen	-- 0 for server, copied from server for client
		byte[]	certContext
	uint24		certListLen
		uint24		certLen		| 1...n certificates ordered
		byte[]		certificate	|   leaf -> root 
		uint16		certExtLen
		byte[]		certExt

   so we need to change what we're reading based on the TLS version that 
   we're using, as well as import the chain with a TLS 1.3 special-snowflake
   type */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readTLSCertChain( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT_PTR STREAM *stream,
					  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertChain, 
					  IN_BOOL const BOOLEAN isServer )
	{
	CRYPT_CERTIFICATE iLocalCertChain;
	const ATTRIBUTE_LIST *fingerprintPtr = \
				findSessionInfo( sessionInfoPtr,
								 CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1 );
	MESSAGE_DATA msgData;
	ERROR_INFO localErrorInfo;
	BYTE certFingerprint[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_ERRMSGS
	const char *peerTypeName = isServer ? "Client" : "Server";
#endif /* USE_ERRMSGS */
#ifdef CONFIG_SUITEB
	const char *requiredLengthString = NULL;
#endif /* CONFIG_SUITEB */
	int certAlgo, certFingerprintLength, chainLength, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( iCertChain, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* Clear return value */
	*iCertChain = CRYPT_ERROR;

	/* Make sure that the packet header is in order */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_CERTIFICATE, 
								  isServer ? 0 : LENGTH_SIZE + MIN_CERTSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( isServer && ( length == 0 || length == LENGTH_SIZE ) )
		{
		/* There is one special case in which a too-short certificate packet 
		   is valid and that's where it constitutes the TLS equivalent of an 
		   TLS no-certificates alert.  SSLv3 sent an 
		   TLS_ALERT_NO_CERTIFICATE alert to indicate that the client 
		   doesn't have a certificate, which is handled by the 
		   readHSPacketTLS() call.  TLS changed this to send an empty 
		   certificate packet instead, supposedly because it lead to 
		   implementation problems (presumably it's necessary to create a 
		   state machine-based implementation to reproduce these problems, 
		   whatever they are).  The TLS 1.0 spec is ambiguous as to what 
		   constitutes an empty packet, it could be either a packet with a 
		   length of zero or a packet containing a zero-length certificate 
		   list so we check for both.  TLS 1.1 fixed this to say that that 
		   certListLen entry has a length of zero.  To report this condition 
		   we fake the error indicators for consistency with the status 
		   obtained from an SSLv3 no-certificate alert */
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, SESSION_ERRINFO, 
				  "Received TLS alert message: No certificate" ) );
		}
	
	/* Handle the TLS 1.3 gratuitously incompatible form of the packet, 
	   which adds a binary certificate-context blob at this point */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		int certContextLength;

		status = certContextLength = sgetc( stream );
		if( !cryptStatusError( status ) && certContextLength > 0 )
			{
			/* A certificate context value is only valid if it's coming from
			   the client */
			if( !isServer( sessionInfoPtr ) || \
				certContextLength > CRYPT_MAX_HASHSIZE )
				status = CRYPT_ERROR_BADDATA;
			else
				{
				status = sread( stream, 
								handshakeInfo->tls13CertContext, 
								certContextLength );
				}
			}
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid certificate chain context value" ) );
			}
		handshakeInfo->tls13CertContextLen = certContextLength;
		length -= 1 + certContextLength;
		}
#endif /* USE_TLS13 */

	/* Read the certificate chain length and make sure that it's in order */
	status = chainLength = readUint24( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate chain length information" ) );
		}
	if( !isShortIntegerRangeMin( chainLength, MIN_CERTSIZE ) || \
		chainLength != length - LENGTH_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate chain length %d, should be %d",
				  chainLength, length - LENGTH_SIZE ) );
		}

	/* Import the certificate chain.  This isn't a true certificate chain (in 
	   the sense of being degenerate PKCS #7 SignedData) but a special-case 
	   TLS-encoded certificate chain */
	clearErrorInfo( &localErrorInfo );
	status = importCertFromStream( stream, &iLocalCertChain, 
					DEFAULTUSER_OBJECT_HANDLE,
					( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ) ? \
					  CRYPT_ICERTTYPE_TLS13_CERTCHAIN : \
					  CRYPT_ICERTTYPE_TLS_CERTCHAIN, chainLength, 
					KEYMGMT_FLAG_NONE, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "%s provided invalid certificate chain", 
					 peerTypeName ) );
		}

	/* Get information on the chain */
	status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE,
							  &certAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	setMessageData( &msgData, certFingerprint, CRYPT_MAX_HASHSIZE );
	if( fingerprintPtr != NULL )
		{
		const CRYPT_ATTRIBUTE_TYPE fingerprintAttribute = \
							( fingerprintPtr->valueLength == 32 ) ? \
								CRYPT_CERTINFO_FINGERPRINT_SHA2 : \
							CRYPT_CERTINFO_FINGERPRINT_SHA1;

		/* Use the hint provided by the fingerprint size to select the
		   appropriate algorithm to generate the fingerprint that we want
		   to compare against */
		status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, fingerprintAttribute );
		}
	else
		{
		/* There's no algorithm hint available, use the default of SHA-1 */
		status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	certFingerprintLength = msgData.length;

	/* In TLS 1.3 the authentication algorithm isn't negotiated in the 
	   handshake so we set it now from the certificate */
#ifdef USE_TLS13
	handshakeInfo->authAlgo = certAlgo;
#endif /* USE_TLS13 */

	/* If we're the client, make sure that the certificate algorithm matches
	   what was negotiated in the handshake */
	if( !isServer && certAlgo != handshakeInfo->authAlgo )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "Server key algorithm %s doesn't match negotiated "
				  "algorithm %s", getAlgoName( certAlgo ), 
				  getAlgoName( handshakeInfo->authAlgo ) ) );
		}

	/* Either compare the certificate fingerprint to a supplied one or save 
	   it for the caller to examine */
	if( fingerprintPtr != NULL )
		{
		/* The caller has supplied a certificate fingerprint, compare it to 
		   the received certificate's fingerprint to make sure that we're 
		   talking to the right system */
		if( fingerprintPtr->valueLength != certFingerprintLength || \
			memcmp( fingerprintPtr->value, certFingerprint, 
					certFingerprintLength ) )
			{
			krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "%s key didn't match key fingerprint", peerTypeName ) );
			}
		}
	else
		{
		/* Remember the certificate fingerprint in case the caller wants to 
		   check it.  We don't worry if the add fails, it's a minor thing 
		   and not worth aborting the handshake for */
		( void ) addSessionInfoS( sessionInfoPtr,
								  CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
								  certFingerprint, certFingerprintLength );
		}

	/* Make sure that we can perform the required operation using the key
	   that we've been given.  For a client key we need signing capability,
	   for a server key when using DH/ECDH key agreement we also need 
	   signing capability to authenticate the DH/ECDH parameters, and for 
	   an RSA key transport key we need encryption capability.  This 
	   operation also performs a variety of additional checks alongside the 
	   obvious one so it's a good general health check before we go any 
	   further */
	if( !checkContextCapability( iLocalCertChain, 
								 isServer || \
								 isKeyexAlgo( handshakeInfo->keyexAlgo ) ? \
									MESSAGE_CHECK_PKC_SIGCHECK : \
									MESSAGE_CHECK_PKC_ENCRYPT ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "%s provided a key incapable of being used for %s",
				  peerTypeName,
				  isServer ? "client authentication" : \
				  isKeyexAlgo( certAlgo ) ? "key exchange authentication" : \
										    "encryption" ) );
		}

	/* For ECC with Suite B there are additional constraints on the key
	   size */
#ifdef CONFIG_SUITEB
	status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE,
							  &length, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );
	switch( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
		{
		case 0:
			/* If we're not configured for Suite B mode then there's
			   nothing to check */
			break;

		case TLS_PFLAG_SUITEB_128:
			/* 128-bit level can be P256 or P384 */
			if( length != bitsToBytes( 256 ) && \
				length != bitsToBytes( 384 ) )
				requiredLengthString = "256- or 384";
			break;

		case TLS_PFLAG_SUITEB_256:
			/* 256-bit level only allows P384 */
			if( length != bitsToBytes( 384 ) )
				requiredLengthString = "384";
			break;

		default:
			retIntError();
		}
	if( requiredLengthString != NULL )	
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "%s provided a %d-bit Suite B key, should have been a "
				  "%s-bit key", peerTypeName, bytesToBits( length ),
				  requiredLengthString ) );
		}
#endif /* CONFIG_SUITEB */

	*iCertChain = iLocalCertChain;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeTLSCertChain( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					   INOUT_PTR STREAM *stream )
	{
	int packetOffset, certListOffset DUMMY_INIT, certListEndPos, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	status = continueHSPacketStream( stream, TLS_HAND_CERTIFICATE, 
									 &packetOffset );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the TLS 1.3 gratuitously incompatible form of the packet, 
	   which adds a binary certificate-context blob at this point */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		status = sputc( stream, handshakeInfo->tls13CertContextLen );
		if( cryptStatusOK( status ) && \
			handshakeInfo->tls13CertContextLen > 0 )
			{
			status = swrite( stream, 
							 handshakeInfo->tls13CertContext, 
							 handshakeInfo->tls13CertContextLen );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_TLS13 */

	/* If there's no private key available, write an empty certificate 
	   chain */
	if( sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		status = writeUint24( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		return( completeHSPacketStream( stream, packetOffset ) );
		}

	/* Write a dummy length and export the certificate list to the stream */
	status = writeUint24( stream, 0 );
	if( cryptStatusOK( status ) )
		{
		certListOffset = stell( stream );
		ENSURES( isIntegerRangeMin( certListOffset, LENGTH_SIZE ) );
		status = exportCertToStream( stream, sessionInfoPtr->privateKey,
					( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ) ? \
					  CRYPT_ICERTFORMAT_TLS13_CERTCHAIN : \
					  CRYPT_ICERTFORMAT_TLS_CERTCHAIN );
		}
	if( cryptStatusError( status ) )
		return( status );
	certListEndPos = stell( stream );
	ENSURES( isIntegerRangeNZ( certListEndPos ) );

	/* Go back and insert the length, then wrap up the packet */
	sseek( stream, certListOffset - LENGTH_SIZE );
	status = writeUint24( stream, certListEndPos - certListOffset );
	sseek( stream, certListEndPos );
	if( cryptStatusError( status ) )
		return( status );
	return( completeHSPacketStream( stream, packetOffset ) );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* Close a previously-opened TLS session */

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES_V( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Clean up TLS-specific objects if required */
	if( DATAPTR_ISSET( tlsInfo->savedHandshakeInfo ) )
		{
		TLS_HANDSHAKE_INFO handshakeInfo;
		int status;

		/* We got halfway through the handshake but didn't complete it, 
		   restore the handshake state and use it to shut down the session.  
		   We set a dummy status since this is handled by the higher-level 
		   code that called us.  Since we're being called as part of a
		   shutdown rather than directly from the startup code, we set the 
		   shutdownNetworkSession flag to FALSE since it'll be closed down 
		   by the code that called us */
		status = popHandshakeInfo( sessionInfoPtr, &handshakeInfo );
		ENSURES_V( cryptStatusOK( status ) );
		( void ) abortStartup( sessionInfoPtr, &handshakeInfo, FALSE, 
							   CRYPT_ERROR_FAILED );
		return;
		}

	sendCloseAlert( sessionInfoPtr, FALSE );
	}

/* Connect to a TLS server/client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int commonStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  IN_BOOL const BOOLEAN isServer )
	{
	TLS_HANDSHAKE_INFO handshakeInfo;
	BOOLEAN resumedSession = FALSE;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* TLS 1.2 switched from the MD5+SHA-1 dual hash/MACs to SHA-2 so if the
	   user has requesetd TLS 1.2 or newer we need to make sure that SHA-2
	   is available */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 && \
		!algoAvailable( CRYPT_ALGO_SHA2 ) )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "TLS 1.2 and newer requires the SHA-2 hash algorithm which "
				  "isn't available in this build of cryptlib" ) );
		}

	/* TLS 1.3 requires AES-GCM so if the user has requested TLS 1.3 or 
	   newer we need to make sure that this is available.  We can't really do
	   this at runtime without creating an AES context each time we check so
	   we rely on USE_GCM being defined to tell us whether it's available */
#if !defined( USE_GCM )
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "TLS 1.3 and newer require the AES-GCM algorithm which "
				  "isn't available in this build of cryptlib" ) );
		}
#endif /* !USE_GCM */

	/* Begin the handshake, unless we're continuing a partially-opened 
	   session */
	if( !TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_PARTIALOPEN ) )
		{
		TLS_HANDSHAKE_FUNCTION handshakeFunction;

		/* Initialise the handshake information */
		status = initHandshakeInfo( sessionInfoPtr, &handshakeInfo, 
									isServer );
		if( cryptStatusError( status ) )
			{
			return( abortStartup( sessionInfoPtr, &handshakeInfo, FALSE, 
								  status ) );
			}

		/* Exchange client/server hellos and other pleasantries */
		handshakeFunction = ( TLS_HANDSHAKE_FUNCTION ) \
							FNPTR_GET( handshakeInfo.beginHandshake );
		ENSURES( handshakeFunction != NULL );
		status = handshakeFunction( sessionInfoPtr, &handshakeInfo );
		if( cryptStatusError( status ) )
			{
			if( status == OK_SPECIAL )
				resumedSession = TRUE;
			else
				{
				delayRandom();	/* Dither error timing info */				
				return( abortStartup( sessionInfoPtr, &handshakeInfo, 
									  TRUE, status ) );
				}
			}

		/* If w're continuing with TLS 1.3, switch to the TLS 1.3 protocol 
		   stack */
#ifdef USE_TLS13
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
			{
			DEBUG_PRINT(( "Switching to TLS 1.3 protocol stack.\n" ));
			initProcessingTLS13( &handshakeInfo, isServer );
			}
#endif /* USE_TLS13 */

		/* Exchange keys with the other side */
		if( !resumedSession )
			{
			handshakeFunction = ( TLS_HANDSHAKE_FUNCTION ) \
								FNPTR_GET( handshakeInfo.exchangeKeys );
			ENSURES( handshakeFunction != NULL );
			status = handshakeFunction( sessionInfoPtr, &handshakeInfo );
			if( cryptStatusError( status ) )
				{
				delayRandom();	/* Dither error timing info */				
				return( abortStartup( sessionInfoPtr, &handshakeInfo, TRUE,
									  status ) );
				}
			}
		else
			{
			/* Remember that we've resumed the session from cached data and
			   that some handshake-related information won't be avaiable */
			SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_CACHEDINFO );
			}

		/* TLS 1.3 completely changes the TLS protocol flow in order to 
		   allow for 0RTT, once we get to this point we've already completed 
		   the handshake */
#ifdef USE_TLS13
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
			{
			destroyHandshakeInfo( &handshakeInfo );
			return( CRYPT_OK );
			}
#endif /* USE_TLS13 */

		/* If we're performing manual verification of the peer's 
		   certificate, let the caller know that they have to check it,
		   unless they've specified that they want to allow any certificate
		   (which implies that they'll perform the check after the handshake
		   completes) */
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_MANUAL_CERTCHECK ) && \
			sessionInfoPtr->authResponse != AUTHRESPONSE_SUCCESS )
			{
			/* Save the handshake state so that we can resume the handshake 
			   later on */
			status = pushHandshakeInfo( sessionInfoPtr, &handshakeInfo );
			ENSURES( cryptStatusOK( status ) );

			return( CRYPT_ENVELOPE_RESOURCE );
			}
		}
	else
		{
		/* We're continuing a partially-completed handshake, restore the 
		   handshake state */
		status = popHandshakeInfo( sessionInfoPtr, &handshakeInfo );
		ENSURES( cryptStatusOK( status ) );

		/* Reset the partial-open state since we're about to complete the 
		   open.  This is also done by the calling code once the handshake
		   completes successfully, but we want to do it preemptively 
		   unconditionally */
		CLEAR_FLAG( sessionInfoPtr->flags, SESSION_FLAG_PARTIALOPEN );
		}

	/* Complete the handshake */
	status = completeHandshakeTLS( sessionInfoPtr, &handshakeInfo, 
								   isServer ? FALSE : TRUE, resumedSession );
	destroyHandshakeInfo( &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		delayRandom();	/* Dither error timing info */				
		return( abortStartup( sessionInfoPtr, NULL, TRUE, status ) );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, FALSE ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int serverStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, TRUE ) );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 INOUT_PTR void *data, 
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE *certPtr = ( CRYPT_CERTIFICATE * ) data;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( type == CRYPT_SESSINFO_REQUEST || \
			  type == CRYPT_SESSINFO_RESPONSE || \
			  type == CRYPT_SESSINFO_TLS_OPTIONS || \
			  type == CRYPT_SESSINFO_TLS_SUBPROTOCOL || \
			  type == CRYPT_SESSINFO_TLS_WSPROTOCOL || \
			  type == CRYPT_SESSINFO_TLS_EAPCHALLENGE || \
			  type == CRYPT_SESSINFO_TLS_EAPKEY || \
			  type == CRYPT_SESSINFO_TLS_EAPDATA );

	/* If the caller is after the current TLS option settings or sub-
	   protocol type, return them */
	if( type == CRYPT_SESSINFO_TLS_OPTIONS )
		{
		const TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
		int *valuePtr = ( int * ) data;

		*valuePtr = tlsInfo->minVersion & TLS_MINVER_MASK;
#ifdef CONFIG_SUITEB
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_SUITEB_128 ) )
			*valuePtr |= CRYPT_TLSOPTION_SUITEB_128;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_SUITEB_256 ) )
			*valuePtr |= CRYPT_TLSOPTION_SUITEB_256;
#endif /* CONFIG_SUITEB */
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_MANUAL_CERTCHECK ) )
			*valuePtr |= CRYPT_TLSOPTION_MANUAL_CERTCHECK;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_DISABLE_NAMEVERIFY ) )
			*valuePtr |= CRYPT_TLSOPTION_DISABLE_NAMEVERIFY;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_DISABLE_CERTVERIFY ) )
			*valuePtr |= CRYPT_TLSOPTION_DISABLE_CERTVERIFY;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_SERVER_SNI ) )
			*valuePtr |= CRYPT_TLSOPTION_SERVER_SNI;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_RESUMED_SESSION ) )
			*valuePtr |= CRYPT_TLSOPTION_RESUMED;

		return( CRYPT_OK );
		}
#if defined( USE_WEBSOCKETS ) || defined( USE_EAP )
	if( type == CRYPT_SESSINFO_TLS_SUBPROTOCOL )
		{
		int *valuePtr = ( int * ) data;

		*valuePtr = sessionInfoPtr->subProtocol;

		return( CRYPT_OK );
		}
#endif /* USE_WEBSOCKETS || USE_EAP */
#ifdef USE_WEBSOCKETS
	if( type == CRYPT_SESSINFO_TLS_WSPROTOCOL )
		{
		const ATTRIBUTE_LIST *attributeListPtr;
		MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) data;

		attributeListPtr = findSessionInfo( sessionInfoPtr, 
											CRYPT_SESSINFO_TLS_WSPROTOCOL );
		if( attributeListPtr == NULL )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_SESSINFO_TLS_WSPROTOCOL, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		return( attributeCopy( msgData, attributeListPtr->value,
							   attributeListPtr->valueLength ) );
		}
#endif /* USE_WEBSOCKETS */

	/* If it's a subprotocol-specific attribute, return it */
#ifdef USE_EAP
	if( type == CRYPT_SESSINFO_TLS_EAPCHALLENGE || \
		type == CRYPT_SESSINFO_TLS_EAPKEY )
		{
		const ATTRIBUTE_LIST *attributeListPtr;
		MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) data;

		attributeListPtr = findSessionInfo( sessionInfoPtr, type );
		if( attributeListPtr == NULL )
			{
			setObjectErrorInfo( sessionInfoPtr, type, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		return( attributeCopy( msgData, attributeListPtr->value,
							   attributeListPtr->valueLength ) );
		}
	if( type == CRYPT_SESSINFO_TLS_EAPDATA )
		{
		MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) data;
		int dataLen, status;

		/* Find out how much data, if any, is present.  This duplicates 
		   some of the functionality that would normally be handled via
		   attributeCopy() but since the only available interface to this 
		   low-level data is via sioctl() which separates out the data and
		   length there's no way to directly return it with 
		   attributeCopy() */
		status = sioctlGet( &sessionInfoPtr->stream, 
							STREAM_IOCTL_GETEXTRADATALEN, &dataLen, 
							sizeof( int ) );
		if( cryptStatusError( status ) )
			{
			setObjectErrorInfo( sessionInfoPtr, type, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		if( msgData->data == NULL )
			{
			/* It's a length-check only, return the data length */
			msgData->length = dataLen;
			return( CRYPT_OK );
			}
		if( dataLen <= 0 || dataLen > msgData->length )
			return( CRYPT_ERROR_OVERFLOW );

		/* Get the data and return it to the caller */
		return( sioctlGet( &sessionInfoPtr->stream, 
						   STREAM_IOCTL_GETEXTRADATA, msgData->data, 
						   dataLen ) );
		}
#endif /* USE_EAP */

	/* The caller is querying the SNI-selected certificate, return it as a
	   data-only copy of the one attached to the server's private key */
	if( type == CRYPT_SESSINFO_REQUEST )
		{
		CRYPT_CERTIFICATE iCryptCert;
		int status;

		status = krnlSendMessage( sessionInfoPtr->privateKey,
								  IMESSAGE_GETATTRIBUTE, &iCryptCert,
								  CRYPT_IATTRIBUTE_CERTCOPY_DATAONLY );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_NOTFOUND );
		*certPtr = iCryptCert;

		return( CRYPT_OK );
		}

	ENSURES( type == CRYPT_SESSINFO_RESPONSE );

	/* If we didn't get a client/server certificate then there's nothing to 
	   return */
	if( sessionInfoPtr->iKeyexAuthContext == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the information to the caller */
	krnlSendNotifier( sessionInfoPtr->iKeyexAuthContext, 
					  IMESSAGE_INCREFCOUNT );
	*certPtr = sessionInfoPtr->iKeyexAuthContext;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int setAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 IN_PTR const void *data,
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	const int value = *( ( int * ) data );

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( type == CRYPT_SESSINFO_AUTHRESPONSE || \
			  type == CRYPT_SESSINFO_TLS_OPTIONS || \
			  type == CRYPT_SESSINFO_TLS_SUBPROTOCOL || \
			  type == CRYPT_SESSINFO_TLS_WSPROTOCOL );

	/* The authentication response isn't usually a protocol-specific 
	   attribute, but in some cases it needs to be set as part of another
	   protocol layered over TLS.  This is complicated by the fact that it
	   may have to be specified twice, once for the TLS handshake and a 
	   second time for the protocol layered over TLS */
	if( type == CRYPT_SESSINFO_AUTHRESPONSE )
		{
#ifdef USE_EAP
		int status;
#endif /* USE_EAP */

		/* If we're expecting an authentication response for a certificate 
		   provided during the TLS handshake, it has to be given during the 
		   handshake phase */
		if( !TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISOPEN ) )
			{
			/* We're in the handshake phase, make sure that we're expecting 
			   an authentication response at this point */
			if( !TEST_FLAG( sessionInfoPtr->protocolFlags, \
							TLS_PFLAG_MANUAL_CERTCHECK ) || \
				!DATAPTR_ISSET( tlsInfo->savedHandshakeInfo ) )
				{
				retExt( CRYPT_ARGERROR_VALUE, 
						( CRYPT_ARGERROR_VALUE, SESSION_ERRINFO, 
						  "No authentication response expected at this "
						  "point" ) );
				}

			return( CRYPT_OK );
			}

		/* We're in the established-session state, at the moment the only 
		   protocol requiring an auth-response action is EAP */
#ifdef USE_EAP
		if( sessionInfoPtr->subProtocol != CRYPT_SUBPROTOCOL_EAPTTLS && \
			sessionInfoPtr->subProtocol != CRYPT_SUBPROTOCOL_PEAP )
			{
			retExt( CRYPT_ARGERROR_VALUE, 
					( CRYPT_ARGERROR_VALUE, SESSION_ERRINFO, 
					  "Authentication response actions are only valid for "
					  "EAP" ) );
			}

		/* Send an EAP-protocol-level message to the peer.  We call the 
		   network write functions directly, which bypasses the TLS tunnel
		   to write outer-wrapper protocol messages that can't normally be
		   written using the standard session push-data interface.
		
		   For the client the message is an EAP ACK to allow the negotiation 
		   to continue, for the server this is a RADIUS Access-Accept to 
		   conclude the negotiation.  
		   
		   Note that the magic values used must be sync'd with the
		   RADIUS_DATA_xxx values in io/eap.h */
		if( isServer( sessionInfoPtr ) )
			status = swrite( &sessionInfoPtr->stream, "ACCESSACCEPT", 12 );
		else
			status = swrite( &sessionInfoPtr->stream, "EAPACK", 6 );

		/* Convert the bytes-written count from the low-level functions to a
		   standard status value */
		return( cryptStatusError( status ) ? status : CRYPT_OK );
#else
		return( CRYPT_ARGERROR_VALUE );
#endif /* USE_EAP */
		}
#if defined( USE_WEBSOCKETS ) || defined( USE_EAP )
	if( type == CRYPT_SESSINFO_TLS_SUBPROTOCOL )
		{
		const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );

		ENSURES( protocolInfo != NULL );

		if( value < protocolInfo->minSubProtocol || \
			value > protocolInfo->maxSubProtocol )
			return( CRYPT_ARGERROR_VALUE );
		sessionInfoPtr->subProtocol = value;

		return( CRYPT_OK );
		}
#endif /* USE_WEBSOCKETS || USE_EAP */
#ifdef USE_WEBSOCKETS
	if( type == CRYPT_SESSINFO_TLS_WSPROTOCOL )
		{
		const MESSAGE_DATA *msgData = data;

		/* If WebSockets isn't enabled then we can't set the subprotocol 
		   attribute */
		if( sessionInfoPtr->subProtocol != CRYPT_SUBPROTOCOL_WEBSOCKETS )
			{
			retExt( CRYPT_ARGERROR_NUM1, 
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO, 
					  "Subprotocols are only valid for WebSockets" ) );
			}

		/* Remember the sub-protocol type */
		return( addSessionInfoS( sessionInfoPtr, type, msgData->data, 
								 msgData->length ) );
		}
#endif /* USE_WEBSOCKETS */
	ENSURES( type == CRYPT_SESSINFO_TLS_OPTIONS );

	/* Make sure that the caller isn't trying to set client/server-only 
	   options on the wrong session type */
	if( isServer( sessionInfoPtr ) )
		{
		if( value & ( CRYPT_TLSOPTION_DISABLE_NAMEVERIFY | \
					  CRYPT_TLSOPTION_DISABLE_CERTVERIFY ) )
			{
			retExt( CRYPT_ARGERROR_NUM1, 
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO, 
					  "Provided options aren't valid for TLS servers" ) );
			}
		}
	else
		{
		if( value & CRYPT_TLSOPTION_SERVER_SNI )
			{
			retExt( CRYPT_ARGERROR_NUM1, 
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO, 
					  "Provided options aren't valid for TLS clients" ) );
			}
		}

	/* Set SuiteB options if this is enabled */
#ifdef CONFIG_SUITEB
	if( value & ( CRYPT_TLSOPTION_SUITEB_128 | CRYPT_TLSOPTION_SUITEB_256 ) )
		{
		const int suiteBvalue = value & ( CRYPT_TLSOPTION_SUITEB_128 | \
										  CRYPT_TLSOPTION_SUITEB_256 );

		if( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
			{
			/* If a Suite B configuration option is already set then we 
			   can't set another one on top of it */
			setObjectErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_TLS_OPTIONS, 
								CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}
		if( suiteBvalue == ( CRYPT_TLSOPTION_SUITEB_128 | \
							 CRYPT_TLSOPTION_SUITEB_256 ) )
			{
			/* We can't set both the 128-bit and 256-bit security levels at 
			   the same time */
			return( CRYPT_ARGERROR_NUM1 );
			}
		if( suiteBvalue == CRYPT_TLSOPTION_SUITEB_128 )
			sessionInfoPtr->protocolFlags |= TLS_PFLAG_SUITEB_128;
		else
			sessionInfoPtr->protocolFlags |= TLS_PFLAG_SUITEB_256;
		}
#endif /* CONFIG_SUITEB */

	/* Set the minimum protocol version, a two-bit field that contains the 
	   minimum version that we're prepared to accept */
	if( value & TLS_MINVER_MASK )
		tlsInfo->minVersion = value & TLS_MINVER_MASK;

	/* By default if a certificate is used we try and verify the server name 
	   against the name(s) in the certificate, and the certificate itself, 
	   but since certificate use is so erratic we allow the user to disable 
	   this if required */
	if( value & CRYPT_TLSOPTION_DISABLE_NAMEVERIFY )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, \
				  TLS_PFLAG_DISABLE_NAMEVERIFY );
		}
	if( value & CRYPT_TLSOPTION_DISABLE_CERTVERIFY )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, \
				  TLS_PFLAG_DISABLE_CERTVERIFY );
		}

	/* Enable manual checking of certificates if required */
	if( value & CRYPT_TLSOPTION_MANUAL_CERTCHECK )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, \
				  TLS_PFLAG_MANUAL_CERTCHECK );
		}

	/* Enable server-side key switching based on the client's SNI if 
	   required.  We have to record this at two levels, at the session 
	   level to indicate that multiple private keys are allowed, and at
	   the TLS level to record what needs to be done with those keys */ 
	if( value & CRYPT_TLSOPTION_SERVER_SNI )
		{
		SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_MULTIPLEKEYS );
		SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_SERVER_SNI );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								   IN_PTR const void *data,
								   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	const CRYPT_CONTEXT cryptContext = *( ( CRYPT_CONTEXT * ) data );
	int pkcAlgo, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isEnumRange( type, CRYPT_ATTRIBUTE ) );

	if( type != CRYPT_SESSINFO_PRIVATEKEY || !isServer( sessionInfoPtr ) )
		return( CRYPT_OK );

	/* Check that the server key that we've been passed is usable.  For an 
	   RSA key we can have either encryption (for RSA keyex) or signing (for 
	   DH keyex) or both, for a DSA or ECDSA key we need signing (for DH/ECDH 
	   keyex) */
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
							  &pkcAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	switch( pkcAlgo )
		{
		case CRYPT_ALGO_RSA:
			if( !checkContextCapability( cryptContext, 
										 MESSAGE_CHECK_PKC_DECRYPT ) && \
				!checkContextCapability( cryptContext, 
										 MESSAGE_CHECK_PKC_SIGN ) )
				{
				retExt( CRYPT_ARGERROR_NUM1,
						( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
						  "Server key can't be used for encryption or "
						  "signing" ) );
				}
			break;

		case CRYPT_ALGO_DSA:
		case CRYPT_ALGO_ECDSA:
			if( !checkContextCapability( cryptContext, 
										 MESSAGE_CHECK_PKC_SIGN ) )
				{
				retExt( CRYPT_ARGERROR_NUM1,
						( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
						  "Server key can't be used for signing" ) );
				}
#ifdef CONFIG_SUITEB
			return( checkSuiteBKey( sessionInfoPtr, cryptContext, pkcAlgo ) );
#else
			break;
#endif /* CONFIG_SUITEB */

		default:
			retExt( CRYPT_ARGERROR_NUM1,
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
					  "Server key uses an algorithm that can't be used "
					  "with TLS" ) );
		}

	/* If we're using SNI-based key selection and there's already a main key
	   set, add this new key as an attribute which will be swapped out if
	   required by the server code depending on what the client's SNI 
	   indicates.  This can lead to a slightly odd situation in which, if the
	   caller uses the attribute cursor to step through the attribute list,
	   they'll find additional CRYPT_SESSINFO_PRIVATEKEY attributes alongside 
	   the value that's returned by reading the CRYPT_SESSINFO_PRIVATEKEY 
	   directly, but since they've explicitly set up this situation they 
	   should be expecting it.  The other option would be to hide the copies
	   of the CRYPT_SESSINFO_PRIVATEKEY in the attribute list by giving them
	   some dummy ID like CRYPT_IATTRIBUTE_KEY_TLS_EXT and then adding 
	   special-case code wherever attributes are handled to pretend that this
	   entry doesn't exist, but this is both messy and it's not clear what
	   would be gained by doing it */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
				   TLS_PFLAG_SERVER_SNI ) && \
		sessionInfoPtr->privateKey != CRYPT_ERROR )
		{
		status = addSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PRIVATEKEY, 
								 cryptContext );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendNotifier( cryptContext, IMESSAGE_INCREFCOUNT );

		/* Let the caller know that we've processed the key internally and 
		   there's nothing further to be done */
		return( OK_SPECIAL );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Read/write data over the TLS link */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readHeaderFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   OUT_ENUM_OPT( READINFO ) \
									READSTATE_INFO *readInfo )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	STREAM stream;
	int packetLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* Read the TLS packet header data */
	status = readFixedHeader( sessionInfoPtr, tlsInfo->headerBuffer, 
							  sessionInfoPtr->receiveBufStartOfs );
	if( cryptStatusError( status ) )
		{
		/* OK_SPECIAL means that we got a soft timeout before the entire 
		   header was read, so we return zero bytes read to tell the 
		   calling code that there's nothing more to do */
		return( ( status == OK_SPECIAL ) ? 0 : status );
		}

	/* Since data errors are always fatal, we make all errors fatal until
	   we've finished handling the header */
	*readInfo = READINFO_FATAL;

	/* Check for a TLS alert message */
	if( tlsInfo->headerBuffer[ 0 ] == TLS_MSG_ALERT )
		{
		return( processAlert( sessionInfoPtr, tlsInfo->headerBuffer, 
							  sessionInfoPtr->receiveBufStartOfs,
							  readInfo ) );
		}

	/* Process the header data */
	sMemConnect( &stream, tlsInfo->headerBuffer, 
				 sessionInfoPtr->receiveBufStartOfs );
	status = checkPacketHeaderTLS( sessionInfoPtr, &stream, &packetLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine how much data we'll be expecting */
	sessionInfoPtr->pendingPacketLength = \
		sessionInfoPtr->pendingPacketRemaining = packetLength;

	/* Indicate that we got the header */
	*readInfo = READINFO_NOOP;
	return( OK_SPECIAL );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int discardPacket( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	/* The packet is noise like a session ticket or rehandshake request, 
	   discard it */
	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos;
	sessionInfoPtr->pendingPacketLength = 0;
	*readInfo = READINFO_NOOP;

	return( OK_SPECIAL );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processBodyFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								OUT_ENUM_OPT( READINFO ) \
									READSTATE_INFO *readInfo )
	{
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* All errors processing the payload are fatal, and specifically fatal 
	   crypto errors */
	*readInfo = READINFO_FATAL_CRYPTO;

	/* If we're potentially performing a rehandshake, process the packet
	   as a handshake message and treat it as a no-op.  What the server
	   does in response to this is implementation-specific, the spec says
	   that a client can ignore this (as we do) at which point the server
	   can close the connection or hang waiting for a rehandshake that'll
	   never come (as IIS does) */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
				   TLS_PFLAG_CHECKREHANDSHAKE ) )
		{
		CLEAR_FLAG( sessionInfoPtr->protocolFlags, \
					TLS_PFLAG_CHECKREHANDSHAKE );
		status = unwrapPacketTLS( sessionInfoPtr, 
								  sessionInfoPtr->receiveBuffer + \
									sessionInfoPtr->receiveBufPos, 
								  sessionInfoPtr->pendingPacketLength, 
								  &length, TLS_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			return( status );

		/* Discard the read packet */
		return( discardPacket( sessionInfoPtr, readInfo ) );
		}

	/* Unwrap the payload */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		int actualPacketType;

		/* If we're using TLS 1.3 then we have to deal with its really 
		   clever double-encapsulation of packets */
		status = unwrapPacketTLS13( sessionInfoPtr, 
									sessionInfoPtr->receiveBuffer + \
										sessionInfoPtr->receiveBufPos, 
									sessionInfoPtr->pendingPacketLength, 
									&length, &actualPacketType,
									TLS_MSG_APPLICATION_DATA );
		if( cryptStatusError( status ) )
			return( status );
		if( actualPacketType != TLS_MSG_APPLICATION_DATA )
			{
			/* If it's an alert, handle it specially */
			if( actualPacketType  == TLS_MSG_ALERT )
				{
				return( processAlertTLS13( sessionInfoPtr, 
										   sessionInfoPtr->receiveBuffer + \
												sessionInfoPtr->receiveBufPos, 
										   length, readInfo ) );
				}

			/* It's noise, discard it.  In particular many TLS 
			   implementations will send two session ticket packets 
			   immediately after the handshake to accommodate web browsers
			   opening multiple streams (because the only way anyone would
			   ever use TLS is on the web), so we have to discard two of 
			   these on every connect */
			return( discardPacket( sessionInfoPtr, readInfo ) );
			}
		}
	else
#endif /* USE_TLS13 */
	status = unwrapPacketTLS( sessionInfoPtr, 
							  sessionInfoPtr->receiveBuffer + \
								sessionInfoPtr->receiveBufPos, 
							  sessionInfoPtr->pendingPacketLength, 
							  &length, TLS_MSG_APPLICATION_DATA );
	if( cryptStatusError( status ) )
		return( status );

	*readInfo = READINFO_NONE;
	return( length );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
static int preparePacketFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( !TEST_FLAG( sessionInfoPtr->flags, 
						  SESSION_FLAG_SENDCLOSED ) );
	REQUIRES( !TEST_FLAG( sessionInfoPtr->protocolFlags, \
						  TLS_PFLAG_ALERTSENT ) );

	/* Wrap up the payload ready for sending.  Since this is wrapping in-
	   place data we first open a write stream to add the header, then open
	   a read stream covering the full buffer in preparation for wrapping
	   the packet (the first operation looks a bit counter-intuitive because
	   we're opening a packet stream and then immediately closing it again,
	   but this is as intended since all that we're using it for is to write
	   the packet header at the start).  Note that we connect the later read 
	   stream to the full send buffer (bufSize) even though we only advance 
	   the current stream position to the end of the stream contents 
	   (bufPos), since the packet-wrapping process adds further data to the 
	   stream that exceeds the current stream position */
	status = openPacketStreamTLS( &stream, sessionInfoPtr, 0,
								  TLS_MSG_APPLICATION_DATA );
	if( cryptStatusError( status ) )
		return( status );
	sMemDisconnect( &stream );
	sMemConnect( &stream, sessionInfoPtr->sendBuffer,
				 sessionInfoPtr->sendBufSize );
	status = sSkip( &stream, sessionInfoPtr->sendBufPos, SSKIP_MAX );
	if( cryptStatusOK( status ) )
		{
#ifdef USE_TLS13
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
			{
			status = wrapPacketTLS13( sessionInfoPtr, &stream, 0, 
									  TLS_MSG_APPLICATION_DATA );
			}
		else
#endif /* USE_TLS13 */
		status = wrapPacketTLS( sessionInfoPtr, &stream, 0 );
		}
	if( cryptStatusOK( status ) )
		status = stell( &stream );
	INJECT_FAULT( SESSION_CORRUPT_DATA, SESSION_CORRUPT_DATA_TLS_1 );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		FALSE,						/* Request-response protocol */
		SESSION_PROTOCOL_REFLECTAUTHOK,	/* Flags */
		TLS_PORT,					/* TLS port */
		SESSION_NEEDS_PRIVKEYSIGN,	/* Client attributes */
			/* The client private key is optional, but if present it has to
			   be signature-capable */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_KEYORPASSWORD,
			/* The server key capabilities are complex enough that they
			   need to be checked specially via checkAttributeFunction(),
			   for an RSA key we can have either encryption (for RSA keyex)
			   or signing (for DH keyex) or both, for a DSA or ECDSA key
			   we need signing (for DH/ECDH keyex).

			   In theory we need neither a private key nor a password 
			   because the caller can provide the password during the
			   handshake in response to a CRYPT_ENVELOPE_RESOURCE
			   notification, however this facility is likely to be 
			   barely-used in comparison to users forgetting to add server
			   certificates and the like, so we require some sort of 
			   server-side key set in advance */
		TLS_MINOR_VERSION_TLS12,	/* TLS 1.2 */
#ifdef USE_TLS13
			TLS_MINOR_VERSION_TLS11, TLS_MINOR_VERSION_TLS13,
#else
			TLS_MINOR_VERSION_TLS11, TLS_MINOR_VERSION_TLS12,
#endif /* USE_TLS13 */
			/* Up until 2018 we defaulted to TLS 1.1 rather than TLS 1.2 
			   because support for the latter was minimal for a long time, 
			   particularly among things like embedded devices.  Even TLS 
			   1.1 support was unreliable for many years, with vendors
			   apparently choosing to jump from 1.0 straight to 1.2 when
			   they finally did upgrade (see
			   https://www.trustworthyinternet.org/ssl-pulse for current
			   public-Internet stats, which however is nothing like the 
			   state of the non-visible use of TLS).  We need at least 1.1 
			   in any case in order to have support for TLS extensions and 
			   explicit IVs.
			   
			   For the minimum version, we allowed TLS 1.0 up until 2024 to
			   deal with older implementations because of the lack of 
			   support for 1.1, see the note above */
		CRYPT_SUBPROTOCOL_NONE, CRYPT_SUBPROTOCOL_PEAP,
			/* Allowed sub-protocols */

		/* Protocol-specific information */
		EXTRA_PACKET_SIZE + \
			MAX_PACKET_SIZE,		/* Send/receive buffer size */
		TLS_HEADER_SIZE,			/* Payload data start */
			/* This may be adjusted during the handshake if we're talking
			   TLS 1.1+, which prepends extra data in the form of an IV to
			   the payload */
		MAX_PACKET_SIZE				/* (Default) maximum packet size */
		};
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Make sure that the huge list of cipher suites is set up correctly */
	assert( SSL_NULL_WITH_NULL == 0x00 );
	assert( TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA == 0x0B );
	assert( TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 == 0x17 );
	assert( TLS_KRB5_WITH_DES_CBC_SHA == 0x1E );
	assert( TLS_PSK_WITH_NULL_SHA == 0x2C );
	assert( TLS_RSA_WITH_AES_128_CBC_SHA == 0x2F );
	assert( TLS_RSA_WITH_NULL_SHA256 == 0x3B );
	assert( TLS_DH_DSS_WITH_AES_128_CBC_SHA256 == 0x3E );
	assert( TLS_RSA_WITH_CAMELLIA_128_CBC_SHA == 0x41 );
	assert( TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 == 0x67 );
	assert( TLS_RSA_WITH_CAMELLIA_256_CBC_SHA == 0x84 );
	assert( TLS_PSK_WITH_RC4_128_SHA == 0x8A );
	assert( TLS_RSA_WITH_SEED_CBC_SHA == 0x96 );
	assert( TLS_RSA_WITH_AES_128_GCM_SHA256 == 0x9C );
	assert( TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 == 0xBA );
	assert( TLS_ECDH_ECDSA_WITH_NULL_SHA == 0xC001 );
	assert( TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA == 0xC01A );
	assert( TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 == 0xC023 );
	assert( TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 == 0xC02B );
	assert( TLS_ECDHE_PSK_WITH_RC4_128_SHA == 0xC033 );

	/* Set the access method pointers */
	DATAPTR_SET( sessionInfoPtr->protocolInfo, ( void * ) &protocolInfo );
	FNPTR_SET( sessionInfoPtr->shutdownFunction, shutdownFunction );
	if( isServer( sessionInfoPtr ) )
		{
		FNPTR_SET( sessionInfoPtr->transactFunction, serverStartup );
		}
	else
		{
		FNPTR_SET( sessionInfoPtr->transactFunction, clientStartup );
		}
	FNPTR_SET( sessionInfoPtr->getAttributeFunction, getAttributeFunction );
	FNPTR_SET( sessionInfoPtr->setAttributeFunction, setAttributeFunction );
	FNPTR_SET( sessionInfoPtr->checkAttributeFunction, checkAttributeFunction );
	FNPTR_SET( sessionInfoPtr->readHeaderFunction, readHeaderFunction );
	FNPTR_SET( sessionInfoPtr->processBodyFunction, processBodyFunction );
	FNPTR_SET( sessionInfoPtr->preparePacketFunction, preparePacketFunction );

	/* Initialise additional safe pointers in the session state */
	DATAPTR_SET( tlsInfo->savedHandshakeInfo, NULL );
	DATAPTR_SET( tlsInfo->scoreboardInfoPtr, NULL );

	/* Test the TLS 1.3 crypto zoo */
#if 0
	{
	void testTLS13Zoo( void );

	testTLS13Zoo();
	}
#endif /* 0 */

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
=======
/****************************************************************************
*																			*
*						cryptlib TLS Session Management						*
*					   Copyright Peter Gutmann 1998-2022					*
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

/* Warn about the use of RSA keyex */

#if ( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) ) && \
	defined( USE_RSA_SUITES )
  #pragma message( "  Warning: RSA keyex is insecure, this should not be used in a production environment." )
#endif /* Notify insecure keyex use */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the session state and handshake information */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionTLS( IN_PTR const SESSION_INFO *sessionInfoPtr )
	{
	const TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( tlsInfo, sizeof( TLS_INFO ) ) );

	/* Check the general session state */
	if( !sanityCheckSession( sessionInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionTLS: Session check" ));
		return( FALSE );
		}

	/* Check TLS session parameters */
	if( !CHECK_FLAGS( sessionInfoPtr->protocolFlags, 
					  TLS_PFLAG_NONE, TLS_PFLAG_MAX ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionTLS: Protocol flags" ));
		return( FALSE );
		}
	if( tlsInfo->minVersion < 0 || \
		tlsInfo->minVersion > TLS_MINOR_VERSION_TLS13 || \
		( tlsInfo->ivSize != 0 && tlsInfo->ivSize != 8 && \
		  tlsInfo->ivSize != 16 ) || \
		tlsInfo->readSeqNo < 0 || tlsInfo->readSeqNo > LONG_MAX / 2 || \
		tlsInfo->writeSeqNo < 0 || tlsInfo->writeSeqNo > LONG_MAX / 2 
#if defined( USE_GCM ) || defined( USE_CHACHA20 )
		|| tlsInfo->aeadSaltSize < 0 || \
		tlsInfo->aeadSaltSize > CRYPT_MAX_IVSIZE 
#endif /* USE_GCM || USE_CHACHA20 */
		)
		{
		DEBUG_PUTS(( "sanityCheckSessionTLS: Session parameters" ));
		return( FALSE );
		}

	/* Check safe pointers */
	if( !DATAPTR_ISVALID( tlsInfo->savedHandshakeInfo ) || \
		!DATAPTR_ISVALID( tlsInfo->scoreboardInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionTLS: Safe pointers" ));
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckTLSHandshakeInfo( IN_PTR \
										const TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Check client and server hash contexts */
	if( !( handshakeInfo->md5context == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->md5context ) ) || \
		!( handshakeInfo->sha1context == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->sha1context ) ) || \
		!( handshakeInfo->sha2context == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->sha2context ) ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: Hash contexts" ));
		return( FALSE );
		}

	/* Check session state information */
	if( handshakeInfo->sessionIDlength < 0 || \
		handshakeInfo->sessionIDlength > MAX_SESSIONID_SIZE || \
		!isBooleanValue( handshakeInfo->hashedSNIpresent ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: State information" ));
		return( FALSE );
		}

	/* Check hello hash and premaster secret information */
	if( handshakeInfo->helloHashSize < 0 || \
		handshakeInfo->helloHashSize > CRYPT_MAX_HASHSIZE || \
		handshakeInfo->sessionHashSize < 0 || \
		handshakeInfo->sessionHashSize > CRYPT_MAX_HASHSIZE || \
		handshakeInfo->premasterSecretSize < 0 || \
		handshakeInfo->premasterSecretSize > CRYPT_MAX_PKCSIZE + \
											 CRYPT_MAX_TEXTSIZE + 8 )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: Hello hash/premaster information" ));
		return( FALSE );
		}

	/* Check encryption information */
	if( !( handshakeInfo->dhContext == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->dhContext ) ) || 
#ifdef USE_TLS13
		!( handshakeInfo->dhContextAlt == CRYPT_ERROR || \
		   isHandleRangeValid( handshakeInfo->dhContextAlt ) ) || 
#endif /* USE_TLS13 */
		!( handshakeInfo->keyexAlgo == CRYPT_ALGO_NONE || \
		   isKeyexAlgo( handshakeInfo->keyexAlgo ) || \
		   handshakeInfo->keyexAlgo == CRYPT_ALGO_RSA ) || \
		!( handshakeInfo->authAlgo == CRYPT_ALGO_NONE || \
		   isSigAlgo( handshakeInfo->authAlgo ) ) || \
		!( handshakeInfo->keyexSigHashAlgo == CRYPT_ALGO_NONE || \
		   isHashAlgo( handshakeInfo->keyexSigHashAlgo ) ) || \
		handshakeInfo->cryptKeysize < 0 || \
		handshakeInfo->cryptKeysize > CRYPT_MAX_KEYSIZE )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: Encryption information" ));
		return( FALSE );
		}

	/* Check miscellaneous information */
	if( handshakeInfo->clientOfferedVersion < TLS_MINOR_VERSION_SSL || \
		handshakeInfo->clientOfferedVersion > TLS_MINOR_VERSION_TLS13 || \
		handshakeInfo->originalVersion < TLS_MINOR_VERSION_SSL || \
		handshakeInfo->originalVersion > TLS_MINOR_VERSION_TLS13 || \
		!isFlagRangeZ( handshakeInfo->flags, HANDSHAKE ) || \
		!isEnumRangeOpt( handshakeInfo->fallbackType, TLS_FALLBACK ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: Miscellaneous information" ));
		return( FALSE );
		}

	/* Check ECC information */
	if( !isBooleanValue( handshakeInfo->disableECC ) || \
		!isEnumRangeOpt( handshakeInfo->eccCurveID, CRYPT_ECCCURVE ) || \
		!isBooleanValue( handshakeInfo->sendECCPointExtn ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: ECC information" ));
		return( FALSE );
		}

	/* Check TLS 1.3 information */
#ifdef USE_TLS13
	if( !isShortIntegerRange( handshakeInfo->originalClientHelloLength ) || \
		!isShortIntegerRange( handshakeInfo->originalServerHelloLength ) )
		{
		DEBUG_PUTS(( "sanityCheckTLSHandshakeInfo: TLS 1.3 information" ));
		return( FALSE );
		}
#endif /* USE_TLS13 */	

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

#if defined( __WIN32__ ) && defined( USE_ERRMSGS ) && !defined( NDEBUG )

/* Dump a message to disk for diagnostic purposes.  The TLS messages are
   broken up into parts by the read/write code so that we can't use the 
   normal DEBUG_DUMP() macro but have to use a special-purpose function that 
   assembles the packet contents if required, as well as providing 
   appropriate naming */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpTLS( const SESSION_INFO *sessionInfoPtr,
				   IN_BUFFER( buffer1size ) const void *buffer1, 
				   IN_LENGTH_SHORT const int buffer1size,
				   IN_BUFFER_OPT( buffer2size ) const void *buffer2, 
				   IN_LENGTH_SHORT_Z const int buffer2size )
	{
	static int messageCount = 1;
	const BYTE *bufPtr = buffer1;
	const BOOLEAN isRead = ( buffer2 != NULL ) ? TRUE : FALSE;
	const BOOLEAN encryptionActive = \
		( ( isRead && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) ) || \
		  ( !isRead && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE ) ) ) ? \
		TRUE : FALSE;
	char fileName[ 1024 + 8 ];

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( buffer1,  buffer1size ) );
	assert( ( buffer2 == NULL && buffer2size == 0 ) || \
			isReadPtrDynamic( buffer2, buffer2size ) );

	if( messageCount > 20 )
		return;	/* Don't dump too many messages */
	sprintf_s( fileName, 1024, "tls3%d_%02d%c_", 
			   sessionInfoPtr->version, messageCount++, 
			   isRead ? 'r' : 'w' );
	if( bufPtr[ 0 ] == TLS_MSG_HANDSHAKE && !encryptionActive )
		{
		if( isRead && buffer2size >= 1 )
			{
			strlcat_s( fileName, 1024, 
					   getTLSHSPacketName( ( ( BYTE * ) buffer2 )[ 0 ] ) );
			}
		else
			{
			if( !isRead && buffer1size >= 6 )
				{
				strlcat_s( fileName, 1024, 
						   getTLSHSPacketName( bufPtr[ 5 ] ) );
				}
			else
				strlcat_s( fileName, 1024, "truncated_packet" );
			}
		}
	else	
		strlcat_s( fileName, 1024, getTLSPacketName( bufPtr[ 0 ] ) );
	strlcat_s( fileName, 1024, ".dat" );
	debugSanitiseFilename( fileName );

	if( buffer2 == NULL )
		DEBUG_DUMP_FILE( fileName, buffer1, buffer1size );
	else
		{
		DEBUG_DUMP_FILE2( fileName, buffer1, buffer1size, 
						  buffer2, buffer2size );
		}
	}
#endif /* Windows debug mode only */

/* Initialise and destroy the handshake state information */

STDC_NONNULL_ARG( ( 1 ) ) \
static void destroyHandshakeInfo( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	destroyHandshakeCryptInfo( handshakeInfo );

	zeroise( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initHandshakeInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  OUT_ALWAYS TLS_HANDSHAKE_INFO *handshakeInfo,
							  IN_BOOL const BOOLEAN isServer )
	{
	const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );

	ENSURES( protocolInfo != NULL );

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isBooleanValue( isServer ) );

	memset( handshakeInfo, 0, sizeof( TLS_HANDSHAKE_INFO ) );
	if( isServer )
		initTLSserverProcessing( handshakeInfo );
	else
		initTLSclientProcessing( handshakeInfo );
	handshakeInfo->originalVersion = sessionInfoPtr->version;
	if( sessionInfoPtr->sessionTLS->minVersion <= 0 )
		{
		/* Set the minimum accepted protocol version if required */
		sessionInfoPtr->sessionTLS->minVersion = protocolInfo->minVersion;
		}
	return( initHandshakeCryptInfo( sessionInfoPtr, handshakeInfo ) );
	}

/* Push and pop the handshake state */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int pushHandshakeInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	void *savedHandshakeInfo;
	const int bufPos = sessionInfoPtr->sendBufSize - \
					   sizeof( TLS_HANDSHAKE_INFO );

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Save the handshake state so that we can resume the handshake later 
	   on.  This is somewhat ugly in that we need to store 
	   sizeof( TLS_HANDSHAKE_INFO ) bytes of data somewhere.  One way to do 
	   this would be to allocate memory, use it for storage, and free it 
	   again, however we have the send buffer sitting unused so we save it 
	   at the end of the send buffer.  
	   
	   This creates the slight problem that we're saving the premaster 
	   secret in the send buffer and potentially exposing it to a bug in 
	   the send code, however it would have to be a pretty unusual bug to 
	   jump into the send function and then write a block of data all the 
	   way at the end of the buffer, far past where a handshake packet would 
	   be, to the peer */
	REQUIRES( bufPos > 1024 && bufPos < sessionInfoPtr->sendBufSize - 512 );
	savedHandshakeInfo = sessionInfoPtr->sendBuffer + bufPos;
	memcpy( savedHandshakeInfo, handshakeInfo, 
			sizeof( TLS_HANDSHAKE_INFO ) );
	DATAPTR_SET( tlsInfo->savedHandshakeInfo, savedHandshakeInfo );

	/* Clear the original copy of the handshake info (without doing a full 
	   cleanup of objects and so on), which leaves the copy that we've just 
	   made intact */
	zeroise( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) );
	
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int popHandshakeInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 OUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	void *savedHandshakeInfo;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Restore the saved handshake state so that we can continue a partially-
	   completed handshake */
	savedHandshakeInfo = DATAPTR_GET( tlsInfo->savedHandshakeInfo );
	REQUIRES( savedHandshakeInfo != NULL );
	memcpy( handshakeInfo, savedHandshakeInfo, 
			sizeof( TLS_HANDSHAKE_INFO ) );
	zeroise( savedHandshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) );
	DATAPTR_SET( tlsInfo->savedHandshakeInfo, NULL );

	ENSURES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	
	return( CRYPT_OK );
	}

/* TLS uses 24-bit lengths in some places even though the maximum packet 
   length is only 16 bits (actually it's limited even further by the spec 
   to 14 bits).  To handle this odd length we define our own read/
   writeUint24() functions that always set the high byte to zero */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
int readUint24( INOUT_PTR STREAM *stream )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( status != 0 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readUint16( stream ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint24( INOUT_PTR STREAM *stream, IN_LENGTH_Z const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES_S( length >= 0 && \
				length < MAX_PACKET_SIZE + EXTRA_PACKET_SIZE );

	sputc( stream, 0 );
	return( writeUint16( stream, length ) );
	}

/* The ECDH public value is a bit complex to process because it's the usual 
   X9.62 stuff-point-data-into-a-byte-string value, and to make things even 
   messier it's stored with an 8-bit length instead of a 16-bit one so we 
   can't even read it as an integer16U().  To work around this we have to 
   duplicate a certain amount of the integer-read code here */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int readEcdhValue( INOUT_PTR STREAM *stream,
				   OUT_BUFFER( valueMaxLen, *valueLen ) void *value,
				   IN_LENGTH_SHORT_MIN( 64 ) const int valueMaxLen,
				   OUT_LENGTH_BOUNDED_Z( valueMaxLen ) int *valueLen )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( value, valueMaxLen ) );
	assert( isWritePtr( valueLen, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( valueMaxLen, 64 ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( valueMaxLen ) ); 
	memset( value, 0, min( 16, valueMaxLen ) );
	*valueLen = 0;

	/* Get the length (as a byte) and make sure that it's valid */
	status = length = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( isShortECCKey( length / 2 ) )
		return( CRYPT_ERROR_NOSECURE );
	if( length < MIN_PKCSIZE_ECCPOINT || length > MAX_PKCSIZE_ECCPOINT )
		return( CRYPT_ERROR_BADDATA );
	*valueLen = length;

	/* Read the X9.62 point value */
	return( sread( stream, value, length ) );
	}

/* Abort a session startup */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int abortStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR_OPT TLS_HANDSHAKE_INFO *handshakeInfo,
						 IN_BOOL const BOOLEAN cleanupSecurityContexts,
						 IN_ERROR const int errorStatus )
	{
	BOOLEAN isFatalError;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( handshakeInfo == NULL || \
			isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( cleanupSecurityContexts ) );
	REQUIRES( cryptStatusError( errorStatus ) );

	/* If the error condition on the stream is fatal, don't try and perform
	   any shutdown actions */
	status = sioctlGet( &sessionInfoPtr->stream, STREAM_IOCTL_ISFATALERROR, 
						&isFatalError, sizeof( BOOLEAN ) );
	if( cryptStatusOK( status ) && !isFatalError )
		{
		sendHandshakeFailAlert( sessionInfoPtr, 
								( handshakeInfo != NULL && \
								  handshakeInfo->failAlertType != 0 ) ? \
									handshakeInfo->failAlertType : \
									TLS_ALERT_HANDSHAKE_FAILURE );
		}

	/* Clean up any objects */
	if( cleanupSecurityContexts )
		destroySecurityContextsTLS( sessionInfoPtr );
	if( handshakeInfo != NULL )
		destroyHandshakeInfo( handshakeInfo );
	return( errorStatus );
	}

#ifdef CONFIG_SUITEB

/* Check that a private key is valid for Suite B use */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkSuiteBKey( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   IN_HANDLE const CRYPT_CONTEXT cryptContext,
						   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	int keySize, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isPkcAlgo( cryptAlgo ) );

	/* Suite B only allows P256 and P384 keys so we need to make sure that
	   the server key is of the appropriate type and size */
	if( cryptAlgo != CRYPT_ALGO_ECDSA )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_CTXINFO_ALGO, 
							CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE, &keySize,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );
#ifdef CONFIG_SUITEB_TESTS 
	if( suiteBTestValue == SUITEB_TEST_SVRINVALIDCURVE && \
		keySize == bitsToBytes( 521 ) )
		return( CRYPT_OK );
#endif /* CONFIG_SUITEB_TESTS */
	if( keySize != bitsToBytes( 256 ) && keySize != bitsToBytes( 384 ) )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_CTXINFO_KEYSIZE, 
							CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* In addition if a specific crypto strength has been configured then 
	   the key size has to correspond to that strength.  At 128 bits we can
	   use both P256 and P384, but at 256 bits we have to use P384 */
	if( ( ( sessionInfoPtr->flags & TLS_PFLAG_SUITEB ) == TLS_PFLAG_SUITEB_256 ) && \
		keySize != bitsToBytes( 384 ) )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_CTXINFO_KEYSIZE, 
							CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

#ifdef CONFIG_SUITEB_TESTS 

/* Special kludge function used to enable nonstandard behaviour for Suite
   B tests.  The magic value is used in appropriate locations to enable
   nonstandard behaviour for testing purposes.  The values are listed in
   tls.h */

SUITEB_TEST_VALUE suiteBTestValue = SUITEB_TEST_NONE;
BOOLEAN suiteBTestClientCert = FALSE;

int tlsSuiteBTestConfig( const int magicValue )
	{
	REQUIRES( ( magicValue >= SUITEB_TEST_NONE && \
				magicValue < SUITEB_TEST_LAST ) || \
			  magicValue == 1000 );

	/* If it's the client-cert test indicator, set the flag and exit */
	if( magicValue == 1000 )
		{
		suiteBTestClientCert = TRUE;

		return( CRYPT_OK );
		}

	suiteBTestValue = magicValue;
	if( magicValue == 0 )
		{
		/* If we're doing a reset, clear the client-cert test indicator as
		   well */
		suiteBTestClientCert = FALSE;
		}

	return( CRYPT_OK );
	}
#endif /* CONFIG_SUITEB_TESTS  */
#endif /* CONFIG_SUITEB */

/****************************************************************************
*																			*
*						Read/Write TLS Certificate Chains					*
*																			*
****************************************************************************/

/* Read/write a TLS certificate chain:

	byte		ID = TLS_HAND_CERTIFICATE
	uint24		len
	uint24		certListLen
		uint24		certLen		| 1...n certificates ordered
		byte[]		certificate	|   leaf -> root 

   With TLS 1.3's mania for pointlessly fiddling with every standard message 
   and mechanism, the format was changed to:

	byte		ID = TLS_HAND_CERTIFICATE
	uint24		len
	byte		certContextLen	-- 0 for server, copied from server for client
		byte[]	certContext
	uint24		certListLen
		uint24		certLen		| 1...n certificates ordered
		byte[]		certificate	|   leaf -> root 
		uint16		certExtLen
		byte[]		certExt

   so we need to change what we're reading based on the TLS version that 
   we're using, as well as import the chain with a TLS 1.3 special-snowflake
   type */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readTLSCertChain( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT_PTR STREAM *stream,
					  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertChain, 
					  IN_BOOL const BOOLEAN isServer )
	{
	CRYPT_CERTIFICATE iLocalCertChain;
	const ATTRIBUTE_LIST *fingerprintPtr = \
				findSessionInfo( sessionInfoPtr,
								 CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1 );
	MESSAGE_DATA msgData;
	ERROR_INFO localErrorInfo;
	BYTE certFingerprint[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_ERRMSGS
	const char *peerTypeName = isServer ? "Client" : "Server";
#endif /* USE_ERRMSGS */
#ifdef CONFIG_SUITEB
	const char *requiredLengthString = NULL;
#endif /* CONFIG_SUITEB */
	int certAlgo, certFingerprintLength, chainLength, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( iCertChain, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* Clear return value */
	*iCertChain = CRYPT_ERROR;

	/* Make sure that the packet header is in order */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_CERTIFICATE, 
								  isServer ? 0 : LENGTH_SIZE + MIN_CERTSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( isServer && ( length == 0 || length == LENGTH_SIZE ) )
		{
		/* There is one special case in which a too-short certificate packet 
		   is valid and that's where it constitutes the TLS equivalent of an 
		   TLS no-certificates alert.  SSLv3 sent an 
		   TLS_ALERT_NO_CERTIFICATE alert to indicate that the client 
		   doesn't have a certificate, which is handled by the 
		   readHSPacketTLS() call.  TLS changed this to send an empty 
		   certificate packet instead, supposedly because it lead to 
		   implementation problems (presumably it's necessary to create a 
		   state machine-based implementation to reproduce these problems, 
		   whatever they are).  The TLS 1.0 spec is ambiguous as to what 
		   constitutes an empty packet, it could be either a packet with a 
		   length of zero or a packet containing a zero-length certificate 
		   list so we check for both.  TLS 1.1 fixed this to say that that 
		   certListLen entry has a length of zero.  To report this condition 
		   we fake the error indicators for consistency with the status 
		   obtained from an SSLv3 no-certificate alert */
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, SESSION_ERRINFO, 
				  "Received TLS alert message: No certificate" ) );
		}
	
	/* Handle the TLS 1.3 gratuitously incompatible form of the packet, 
	   which adds a binary certificate-context blob at this point */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		int certContextLength;

		status = certContextLength = sgetc( stream );
		if( !cryptStatusError( status ) && certContextLength > 0 )
			{
			/* A certificate context value is only valid if it's coming from
			   the client */
			if( !isServer( sessionInfoPtr ) || \
				certContextLength > CRYPT_MAX_HASHSIZE )
				status = CRYPT_ERROR_BADDATA;
			else
				{
				status = sread( stream, 
								handshakeInfo->tls13CertContext, 
								certContextLength );
				}
			}
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid certificate chain context value" ) );
			}
		handshakeInfo->tls13CertContextLen = certContextLength;
		length -= 1 + certContextLength;
		}
#endif /* USE_TLS13 */

	/* Read the certificate chain length and make sure that it's in order */
	status = chainLength = readUint24( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate chain length information" ) );
		}
	if( !isShortIntegerRangeMin( chainLength, MIN_CERTSIZE ) || \
		chainLength != length - LENGTH_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate chain length %d, should be %d",
				  chainLength, length - LENGTH_SIZE ) );
		}

	/* Import the certificate chain.  This isn't a true certificate chain (in 
	   the sense of being degenerate PKCS #7 SignedData) but a special-case 
	   TLS-encoded certificate chain */
	clearErrorInfo( &localErrorInfo );
	status = importCertFromStream( stream, &iLocalCertChain, 
					DEFAULTUSER_OBJECT_HANDLE,
					( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ) ? \
					  CRYPT_ICERTTYPE_TLS13_CERTCHAIN : \
					  CRYPT_ICERTTYPE_TLS_CERTCHAIN, chainLength, 
					KEYMGMT_FLAG_NONE, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "%s provided invalid certificate chain", 
					 peerTypeName ) );
		}

	/* Get information on the chain */
	status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE,
							  &certAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	setMessageData( &msgData, certFingerprint, CRYPT_MAX_HASHSIZE );
	if( fingerprintPtr != NULL )
		{
		const CRYPT_ATTRIBUTE_TYPE fingerprintAttribute = \
							( fingerprintPtr->valueLength == 32 ) ? \
								CRYPT_CERTINFO_FINGERPRINT_SHA2 : \
							CRYPT_CERTINFO_FINGERPRINT_SHA1;

		/* Use the hint provided by the fingerprint size to select the
		   appropriate algorithm to generate the fingerprint that we want
		   to compare against */
		status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, fingerprintAttribute );
		}
	else
		{
		/* There's no algorithm hint available, use the default of SHA-1 */
		status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	certFingerprintLength = msgData.length;

	/* In TLS 1.3 the authentication algorithm isn't negotiated in the 
	   handshake so we set it now from the certificate */
#ifdef USE_TLS13
	handshakeInfo->authAlgo = certAlgo;
#endif /* USE_TLS13 */

	/* If we're the client, make sure that the certificate algorithm matches
	   what was negotiated in the handshake */
	if( !isServer && certAlgo != handshakeInfo->authAlgo )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "Server key algorithm %s doesn't match negotiated "
				  "algorithm %s", getAlgoName( certAlgo ), 
				  getAlgoName( handshakeInfo->authAlgo ) ) );
		}

	/* Either compare the certificate fingerprint to a supplied one or save 
	   it for the caller to examine */
	if( fingerprintPtr != NULL )
		{
		/* The caller has supplied a certificate fingerprint, compare it to 
		   the received certificate's fingerprint to make sure that we're 
		   talking to the right system */
		if( fingerprintPtr->valueLength != certFingerprintLength || \
			memcmp( fingerprintPtr->value, certFingerprint, 
					certFingerprintLength ) )
			{
			krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "%s key didn't match key fingerprint", peerTypeName ) );
			}
		}
	else
		{
		/* Remember the certificate fingerprint in case the caller wants to 
		   check it.  We don't worry if the add fails, it's a minor thing 
		   and not worth aborting the handshake for */
		( void ) addSessionInfoS( sessionInfoPtr,
								  CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
								  certFingerprint, certFingerprintLength );
		}

	/* Make sure that we can perform the required operation using the key
	   that we've been given.  For a client key we need signing capability,
	   for a server key when using DH/ECDH key agreement we also need 
	   signing capability to authenticate the DH/ECDH parameters, and for 
	   an RSA key transport key we need encryption capability.  This 
	   operation also performs a variety of additional checks alongside the 
	   obvious one so it's a good general health check before we go any 
	   further */
	if( !checkContextCapability( iLocalCertChain, 
								 isServer || \
								 isKeyexAlgo( handshakeInfo->keyexAlgo ) ? \
									MESSAGE_CHECK_PKC_SIGCHECK : \
									MESSAGE_CHECK_PKC_ENCRYPT ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "%s provided a key incapable of being used for %s",
				  peerTypeName,
				  isServer ? "client authentication" : \
				  isKeyexAlgo( certAlgo ) ? "key exchange authentication" : \
										    "encryption" ) );
		}

	/* For ECC with Suite B there are additional constraints on the key
	   size */
#ifdef CONFIG_SUITEB
	status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE,
							  &length, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );
	switch( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
		{
		case 0:
			/* If we're not configured for Suite B mode then there's
			   nothing to check */
			break;

		case TLS_PFLAG_SUITEB_128:
			/* 128-bit level can be P256 or P384 */
			if( length != bitsToBytes( 256 ) && \
				length != bitsToBytes( 384 ) )
				requiredLengthString = "256- or 384";
			break;

		case TLS_PFLAG_SUITEB_256:
			/* 256-bit level only allows P384 */
			if( length != bitsToBytes( 384 ) )
				requiredLengthString = "384";
			break;

		default:
			retIntError();
		}
	if( requiredLengthString != NULL )	
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "%s provided a %d-bit Suite B key, should have been a "
				  "%s-bit key", peerTypeName, bytesToBits( length ),
				  requiredLengthString ) );
		}
#endif /* CONFIG_SUITEB */

	*iCertChain = iLocalCertChain;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeTLSCertChain( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					   INOUT_PTR STREAM *stream )
	{
	int packetOffset, certListOffset DUMMY_INIT, certListEndPos, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	status = continueHSPacketStream( stream, TLS_HAND_CERTIFICATE, 
									 &packetOffset );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the TLS 1.3 gratuitously incompatible form of the packet, 
	   which adds a binary certificate-context blob at this point */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		status = sputc( stream, handshakeInfo->tls13CertContextLen );
		if( cryptStatusOK( status ) && \
			handshakeInfo->tls13CertContextLen > 0 )
			{
			status = swrite( stream, 
							 handshakeInfo->tls13CertContext, 
							 handshakeInfo->tls13CertContextLen );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_TLS13 */

	/* If there's no private key available, write an empty certificate 
	   chain */
	if( sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		status = writeUint24( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		return( completeHSPacketStream( stream, packetOffset ) );
		}

	/* Write a dummy length and export the certificate list to the stream */
	status = writeUint24( stream, 0 );
	if( cryptStatusOK( status ) )
		{
		certListOffset = stell( stream );
		ENSURES( isIntegerRangeMin( certListOffset, LENGTH_SIZE ) );
		status = exportCertToStream( stream, sessionInfoPtr->privateKey,
					( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ) ? \
					  CRYPT_ICERTFORMAT_TLS13_CERTCHAIN : \
					  CRYPT_ICERTFORMAT_TLS_CERTCHAIN );
		}
	if( cryptStatusError( status ) )
		return( status );
	certListEndPos = stell( stream );
	ENSURES( isIntegerRangeNZ( certListEndPos ) );

	/* Go back and insert the length, then wrap up the packet */
	sseek( stream, certListOffset - LENGTH_SIZE );
	status = writeUint24( stream, certListEndPos - certListOffset );
	sseek( stream, certListEndPos );
	if( cryptStatusError( status ) )
		return( status );
	return( completeHSPacketStream( stream, packetOffset ) );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* Close a previously-opened TLS session */

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES_V( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Clean up TLS-specific objects if required */
	if( DATAPTR_ISSET( tlsInfo->savedHandshakeInfo ) )
		{
		TLS_HANDSHAKE_INFO handshakeInfo;
		int status;

		/* We got halfway through the handshake but didn't complete it, 
		   restore the handshake state and use it to shut down the session.  
		   We set a dummy status since this is handled by the higher-level 
		   code that called us.  Since we're being called as part of a
		   shutdown rather than directly from the startup code, we set the 
		   shutdownNetworkSession flag to FALSE since it'll be closed down 
		   by the code that called us */
		status = popHandshakeInfo( sessionInfoPtr, &handshakeInfo );
		ENSURES_V( cryptStatusOK( status ) );
		( void ) abortStartup( sessionInfoPtr, &handshakeInfo, FALSE, 
							   CRYPT_ERROR_FAILED );
		return;
		}

	sendCloseAlert( sessionInfoPtr, FALSE );
	}

/* Connect to a TLS server/client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int commonStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  IN_BOOL const BOOLEAN isServer )
	{
	TLS_HANDSHAKE_INFO handshakeInfo;
	BOOLEAN resumedSession = FALSE;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* TLS 1.2 switched from the MD5+SHA-1 dual hash/MACs to SHA-2 so if the
	   user has requesetd TLS 1.2 or newer we need to make sure that SHA-2
	   is available */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 && \
		!algoAvailable( CRYPT_ALGO_SHA2 ) )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "TLS 1.2 and newer requires the SHA-2 hash algorithm which "
				  "isn't available in this build of cryptlib" ) );
		}

	/* TLS 1.3 requires AES-GCM so if the user has requested TLS 1.3 or 
	   newer we need to make sure that this is available.  We can't really do
	   this at runtime without creating an AES context each time we check so
	   we rely on USE_GCM being defined to tell us whether it's available */
#if !defined( USE_GCM )
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "TLS 1.3 and newer require the AES-GCM algorithm which "
				  "isn't available in this build of cryptlib" ) );
		}
#endif /* !USE_GCM */

	/* Begin the handshake, unless we're continuing a partially-opened 
	   session */
	if( !TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_PARTIALOPEN ) )
		{
		TLS_HANDSHAKE_FUNCTION handshakeFunction;

		/* Initialise the handshake information */
		status = initHandshakeInfo( sessionInfoPtr, &handshakeInfo, 
									isServer );
		if( cryptStatusError( status ) )
			{
			return( abortStartup( sessionInfoPtr, &handshakeInfo, FALSE, 
								  status ) );
			}

		/* Exchange client/server hellos and other pleasantries */
		handshakeFunction = ( TLS_HANDSHAKE_FUNCTION ) \
							FNPTR_GET( handshakeInfo.beginHandshake );
		ENSURES( handshakeFunction != NULL );
		status = handshakeFunction( sessionInfoPtr, &handshakeInfo );
		if( cryptStatusError( status ) )
			{
			if( status == OK_SPECIAL )
				resumedSession = TRUE;
			else
				{
				delayRandom();	/* Dither error timing info */				
				return( abortStartup( sessionInfoPtr, &handshakeInfo, 
									  TRUE, status ) );
				}
			}

		/* If w're continuing with TLS 1.3, switch to the TLS 1.3 protocol 
		   stack */
#ifdef USE_TLS13
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
			{
			DEBUG_PRINT(( "Switching to TLS 1.3 protocol stack.\n" ));
			initProcessingTLS13( &handshakeInfo, isServer );
			}
#endif /* USE_TLS13 */

		/* Exchange keys with the other side */
		if( !resumedSession )
			{
			handshakeFunction = ( TLS_HANDSHAKE_FUNCTION ) \
								FNPTR_GET( handshakeInfo.exchangeKeys );
			ENSURES( handshakeFunction != NULL );
			status = handshakeFunction( sessionInfoPtr, &handshakeInfo );
			if( cryptStatusError( status ) )
				{
				delayRandom();	/* Dither error timing info */				
				return( abortStartup( sessionInfoPtr, &handshakeInfo, TRUE,
									  status ) );
				}
			}
		else
			{
			/* Remember that we've resumed the session from cached data and
			   that some handshake-related information won't be avaiable */
			SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_CACHEDINFO );
			}

		/* TLS 1.3 completely changes the TLS protocol flow in order to 
		   allow for 0RTT, once we get to this point we've already completed 
		   the handshake */
#ifdef USE_TLS13
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
			{
			destroyHandshakeInfo( &handshakeInfo );
			return( CRYPT_OK );
			}
#endif /* USE_TLS13 */

		/* If we're performing manual verification of the peer's 
		   certificate, let the caller know that they have to check it,
		   unless they've specified that they want to allow any certificate
		   (which implies that they'll perform the check after the handshake
		   completes) */
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_MANUAL_CERTCHECK ) && \
			sessionInfoPtr->authResponse != AUTHRESPONSE_SUCCESS )
			{
			/* Save the handshake state so that we can resume the handshake 
			   later on */
			status = pushHandshakeInfo( sessionInfoPtr, &handshakeInfo );
			ENSURES( cryptStatusOK( status ) );

			return( CRYPT_ENVELOPE_RESOURCE );
			}
		}
	else
		{
		/* We're continuing a partially-completed handshake, restore the 
		   handshake state */
		status = popHandshakeInfo( sessionInfoPtr, &handshakeInfo );
		ENSURES( cryptStatusOK( status ) );

		/* Reset the partial-open state since we're about to complete the 
		   open.  This is also done by the calling code once the handshake
		   completes successfully, but we want to do it preemptively 
		   unconditionally */
		CLEAR_FLAG( sessionInfoPtr->flags, SESSION_FLAG_PARTIALOPEN );
		}

	/* Complete the handshake */
	status = completeHandshakeTLS( sessionInfoPtr, &handshakeInfo, 
								   isServer ? FALSE : TRUE, resumedSession );
	destroyHandshakeInfo( &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		delayRandom();	/* Dither error timing info */				
		return( abortStartup( sessionInfoPtr, NULL, TRUE, status ) );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, FALSE ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int serverStartup( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, TRUE ) );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 INOUT_PTR void *data, 
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE *certPtr = ( CRYPT_CERTIFICATE * ) data;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( type == CRYPT_SESSINFO_REQUEST || \
			  type == CRYPT_SESSINFO_RESPONSE || \
			  type == CRYPT_SESSINFO_TLS_OPTIONS || \
			  type == CRYPT_SESSINFO_TLS_SUBPROTOCOL || \
			  type == CRYPT_SESSINFO_TLS_WSPROTOCOL || \
			  type == CRYPT_SESSINFO_TLS_EAPCHALLENGE || \
			  type == CRYPT_SESSINFO_TLS_EAPKEY || \
			  type == CRYPT_SESSINFO_TLS_EAPDATA );

	/* If the caller is after the current TLS option settings or sub-
	   protocol type, return them */
	if( type == CRYPT_SESSINFO_TLS_OPTIONS )
		{
		const TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
		int *valuePtr = ( int * ) data;

		*valuePtr = tlsInfo->minVersion & TLS_MINVER_MASK;
#ifdef CONFIG_SUITEB
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_SUITEB_128 ) )
			*valuePtr |= CRYPT_TLSOPTION_SUITEB_128;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_SUITEB_256 ) )
			*valuePtr |= CRYPT_TLSOPTION_SUITEB_256;
#endif /* CONFIG_SUITEB */
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_MANUAL_CERTCHECK ) )
			*valuePtr |= CRYPT_TLSOPTION_MANUAL_CERTCHECK;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_DISABLE_NAMEVERIFY ) )
			*valuePtr |= CRYPT_TLSOPTION_DISABLE_NAMEVERIFY;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_DISABLE_CERTVERIFY ) )
			*valuePtr |= CRYPT_TLSOPTION_DISABLE_CERTVERIFY;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_SERVER_SNI ) )
			*valuePtr |= CRYPT_TLSOPTION_SERVER_SNI;
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
					   TLS_PFLAG_RESUMED_SESSION ) )
			*valuePtr |= CRYPT_TLSOPTION_RESUMED;

		return( CRYPT_OK );
		}
#if defined( USE_WEBSOCKETS ) || defined( USE_EAP )
	if( type == CRYPT_SESSINFO_TLS_SUBPROTOCOL )
		{
		int *valuePtr = ( int * ) data;

		*valuePtr = sessionInfoPtr->subProtocol;

		return( CRYPT_OK );
		}
#endif /* USE_WEBSOCKETS || USE_EAP */
#ifdef USE_WEBSOCKETS
	if( type == CRYPT_SESSINFO_TLS_WSPROTOCOL )
		{
		const ATTRIBUTE_LIST *attributeListPtr;
		MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) data;

		attributeListPtr = findSessionInfo( sessionInfoPtr, 
											CRYPT_SESSINFO_TLS_WSPROTOCOL );
		if( attributeListPtr == NULL )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_SESSINFO_TLS_WSPROTOCOL, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		return( attributeCopy( msgData, attributeListPtr->value,
							   attributeListPtr->valueLength ) );
		}
#endif /* USE_WEBSOCKETS */

	/* If it's a subprotocol-specific attribute, return it */
#ifdef USE_EAP
	if( type == CRYPT_SESSINFO_TLS_EAPCHALLENGE || \
		type == CRYPT_SESSINFO_TLS_EAPKEY )
		{
		const ATTRIBUTE_LIST *attributeListPtr;
		MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) data;

		attributeListPtr = findSessionInfo( sessionInfoPtr, type );
		if( attributeListPtr == NULL )
			{
			setObjectErrorInfo( sessionInfoPtr, type, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		return( attributeCopy( msgData, attributeListPtr->value,
							   attributeListPtr->valueLength ) );
		}
	if( type == CRYPT_SESSINFO_TLS_EAPDATA )
		{
		MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) data;
		int dataLen, status;

		/* Find out how much data, if any, is present.  This duplicates 
		   some of the functionality that would normally be handled via
		   attributeCopy() but since the only available interface to this 
		   low-level data is via sioctl() which separates out the data and
		   length there's no way to directly return it with 
		   attributeCopy() */
		status = sioctlGet( &sessionInfoPtr->stream, 
							STREAM_IOCTL_GETEXTRADATALEN, &dataLen, 
							sizeof( int ) );
		if( cryptStatusError( status ) )
			{
			setObjectErrorInfo( sessionInfoPtr, type, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		if( msgData->data == NULL )
			{
			/* It's a length-check only, return the data length */
			msgData->length = dataLen;
			return( CRYPT_OK );
			}
		if( dataLen <= 0 || dataLen > msgData->length )
			return( CRYPT_ERROR_OVERFLOW );

		/* Get the data and return it to the caller */
		return( sioctlGet( &sessionInfoPtr->stream, 
						   STREAM_IOCTL_GETEXTRADATA, msgData->data, 
						   dataLen ) );
		}
#endif /* USE_EAP */

	/* The caller is querying the SNI-selected certificate, return it as a
	   data-only copy of the one attached to the server's private key */
	if( type == CRYPT_SESSINFO_REQUEST )
		{
		CRYPT_CERTIFICATE iCryptCert;
		int status;

		status = krnlSendMessage( sessionInfoPtr->privateKey,
								  IMESSAGE_GETATTRIBUTE, &iCryptCert,
								  CRYPT_IATTRIBUTE_CERTCOPY_DATAONLY );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_NOTFOUND );
		*certPtr = iCryptCert;

		return( CRYPT_OK );
		}

	ENSURES( type == CRYPT_SESSINFO_RESPONSE );

	/* If we didn't get a client/server certificate then there's nothing to 
	   return */
	if( sessionInfoPtr->iKeyexAuthContext == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the information to the caller */
	krnlSendNotifier( sessionInfoPtr->iKeyexAuthContext, 
					  IMESSAGE_INCREFCOUNT );
	*certPtr = sessionInfoPtr->iKeyexAuthContext;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int setAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 IN_PTR const void *data,
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	const int value = *( ( int * ) data );

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( type == CRYPT_SESSINFO_AUTHRESPONSE || \
			  type == CRYPT_SESSINFO_TLS_OPTIONS || \
			  type == CRYPT_SESSINFO_TLS_SUBPROTOCOL || \
			  type == CRYPT_SESSINFO_TLS_WSPROTOCOL );

	/* The authentication response isn't usually a protocol-specific 
	   attribute, but in some cases it needs to be set as part of another
	   protocol layered over TLS.  This is complicated by the fact that it
	   may have to be specified twice, once for the TLS handshake and a 
	   second time for the protocol layered over TLS */
	if( type == CRYPT_SESSINFO_AUTHRESPONSE )
		{
#ifdef USE_EAP
		int status;
#endif /* USE_EAP */

		/* If we're expecting an authentication response for a certificate 
		   provided during the TLS handshake, it has to be given during the 
		   handshake phase */
		if( !TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISOPEN ) )
			{
			/* We're in the handshake phase, make sure that we're expecting 
			   an authentication response at this point */
			if( !TEST_FLAG( sessionInfoPtr->protocolFlags, \
							TLS_PFLAG_MANUAL_CERTCHECK ) || \
				!DATAPTR_ISSET( tlsInfo->savedHandshakeInfo ) )
				{
				retExt( CRYPT_ARGERROR_VALUE, 
						( CRYPT_ARGERROR_VALUE, SESSION_ERRINFO, 
						  "No authentication response expected at this "
						  "point" ) );
				}

			return( CRYPT_OK );
			}

		/* We're in the established-session state, at the moment the only 
		   protocol requiring an auth-response action is EAP */
#ifdef USE_EAP
		if( sessionInfoPtr->subProtocol != CRYPT_SUBPROTOCOL_EAPTTLS && \
			sessionInfoPtr->subProtocol != CRYPT_SUBPROTOCOL_PEAP )
			{
			retExt( CRYPT_ARGERROR_VALUE, 
					( CRYPT_ARGERROR_VALUE, SESSION_ERRINFO, 
					  "Authentication response actions are only valid for "
					  "EAP" ) );
			}

		/* Send an EAP-protocol-level message to the peer.  We call the 
		   network write functions directly, which bypasses the TLS tunnel
		   to write outer-wrapper protocol messages that can't normally be
		   written using the standard session push-data interface.
		
		   For the client the message is an EAP ACK to allow the negotiation 
		   to continue, for the server this is a RADIUS Access-Accept to 
		   conclude the negotiation.  
		   
		   Note that the magic values used must be sync'd with the
		   RADIUS_DATA_xxx values in io/eap.h */
		if( isServer( sessionInfoPtr ) )
			status = swrite( &sessionInfoPtr->stream, "ACCESSACCEPT", 12 );
		else
			status = swrite( &sessionInfoPtr->stream, "EAPACK", 6 );

		/* Convert the bytes-written count from the low-level functions to a
		   standard status value */
		return( cryptStatusError( status ) ? status : CRYPT_OK );
#else
		return( CRYPT_ARGERROR_VALUE );
#endif /* USE_EAP */
		}
#if defined( USE_WEBSOCKETS ) || defined( USE_EAP )
	if( type == CRYPT_SESSINFO_TLS_SUBPROTOCOL )
		{
		const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );

		ENSURES( protocolInfo != NULL );

		if( value < protocolInfo->minSubProtocol || \
			value > protocolInfo->maxSubProtocol )
			return( CRYPT_ARGERROR_VALUE );
		sessionInfoPtr->subProtocol = value;

		return( CRYPT_OK );
		}
#endif /* USE_WEBSOCKETS || USE_EAP */
#ifdef USE_WEBSOCKETS
	if( type == CRYPT_SESSINFO_TLS_WSPROTOCOL )
		{
		const MESSAGE_DATA *msgData = data;

		/* If WebSockets isn't enabled then we can't set the subprotocol 
		   attribute */
		if( sessionInfoPtr->subProtocol != CRYPT_SUBPROTOCOL_WEBSOCKETS )
			{
			retExt( CRYPT_ARGERROR_NUM1, 
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO, 
					  "Subprotocols are only valid for WebSockets" ) );
			}

		/* Remember the sub-protocol type */
		return( addSessionInfoS( sessionInfoPtr, type, msgData->data, 
								 msgData->length ) );
		}
#endif /* USE_WEBSOCKETS */
	ENSURES( type == CRYPT_SESSINFO_TLS_OPTIONS );

	/* Make sure that the caller isn't trying to set client/server-only 
	   options on the wrong session type */
	if( isServer( sessionInfoPtr ) )
		{
		if( value & ( CRYPT_TLSOPTION_DISABLE_NAMEVERIFY | \
					  CRYPT_TLSOPTION_DISABLE_CERTVERIFY ) )
			{
			retExt( CRYPT_ARGERROR_NUM1, 
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO, 
					  "Provided options aren't valid for TLS servers" ) );
			}
		}
	else
		{
		if( value & CRYPT_TLSOPTION_SERVER_SNI )
			{
			retExt( CRYPT_ARGERROR_NUM1, 
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO, 
					  "Provided options aren't valid for TLS clients" ) );
			}
		}

	/* Set SuiteB options if this is enabled */
#ifdef CONFIG_SUITEB
	if( value & ( CRYPT_TLSOPTION_SUITEB_128 | CRYPT_TLSOPTION_SUITEB_256 ) )
		{
		const int suiteBvalue = value & ( CRYPT_TLSOPTION_SUITEB_128 | \
										  CRYPT_TLSOPTION_SUITEB_256 );

		if( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
			{
			/* If a Suite B configuration option is already set then we 
			   can't set another one on top of it */
			setObjectErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_TLS_OPTIONS, 
								CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}
		if( suiteBvalue == ( CRYPT_TLSOPTION_SUITEB_128 | \
							 CRYPT_TLSOPTION_SUITEB_256 ) )
			{
			/* We can't set both the 128-bit and 256-bit security levels at 
			   the same time */
			return( CRYPT_ARGERROR_NUM1 );
			}
		if( suiteBvalue == CRYPT_TLSOPTION_SUITEB_128 )
			sessionInfoPtr->protocolFlags |= TLS_PFLAG_SUITEB_128;
		else
			sessionInfoPtr->protocolFlags |= TLS_PFLAG_SUITEB_256;
		}
#endif /* CONFIG_SUITEB */

	/* Set the minimum protocol version, a two-bit field that contains the 
	   minimum version that we're prepared to accept */
	if( value & TLS_MINVER_MASK )
		tlsInfo->minVersion = value & TLS_MINVER_MASK;

	/* By default if a certificate is used we try and verify the server name 
	   against the name(s) in the certificate, and the certificate itself, 
	   but since certificate use is so erratic we allow the user to disable 
	   this if required */
	if( value & CRYPT_TLSOPTION_DISABLE_NAMEVERIFY )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, \
				  TLS_PFLAG_DISABLE_NAMEVERIFY );
		}
	if( value & CRYPT_TLSOPTION_DISABLE_CERTVERIFY )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, \
				  TLS_PFLAG_DISABLE_CERTVERIFY );
		}

	/* Enable manual checking of certificates if required */
	if( value & CRYPT_TLSOPTION_MANUAL_CERTCHECK )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, \
				  TLS_PFLAG_MANUAL_CERTCHECK );
		}

	/* Enable server-side key switching based on the client's SNI if 
	   required.  We have to record this at two levels, at the session 
	   level to indicate that multiple private keys are allowed, and at
	   the TLS level to record what needs to be done with those keys */ 
	if( value & CRYPT_TLSOPTION_SERVER_SNI )
		{
		SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_MULTIPLEKEYS );
		SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_SERVER_SNI );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								   IN_PTR const void *data,
								   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	const CRYPT_CONTEXT cryptContext = *( ( CRYPT_CONTEXT * ) data );
	int pkcAlgo, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isEnumRange( type, CRYPT_ATTRIBUTE ) );

	if( type != CRYPT_SESSINFO_PRIVATEKEY || !isServer( sessionInfoPtr ) )
		return( CRYPT_OK );

	/* Check that the server key that we've been passed is usable.  For an 
	   RSA key we can have either encryption (for RSA keyex) or signing (for 
	   DH keyex) or both, for a DSA or ECDSA key we need signing (for DH/ECDH 
	   keyex) */
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE,
							  &pkcAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	switch( pkcAlgo )
		{
		case CRYPT_ALGO_RSA:
			if( !checkContextCapability( cryptContext, 
										 MESSAGE_CHECK_PKC_DECRYPT ) && \
				!checkContextCapability( cryptContext, 
										 MESSAGE_CHECK_PKC_SIGN ) )
				{
				retExt( CRYPT_ARGERROR_NUM1,
						( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
						  "Server key can't be used for encryption or "
						  "signing" ) );
				}
			break;

		case CRYPT_ALGO_DSA:
		case CRYPT_ALGO_ECDSA:
			if( !checkContextCapability( cryptContext, 
										 MESSAGE_CHECK_PKC_SIGN ) )
				{
				retExt( CRYPT_ARGERROR_NUM1,
						( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
						  "Server key can't be used for signing" ) );
				}
#ifdef CONFIG_SUITEB
			return( checkSuiteBKey( sessionInfoPtr, cryptContext, pkcAlgo ) );
#else
			break;
#endif /* CONFIG_SUITEB */

		default:
			retExt( CRYPT_ARGERROR_NUM1,
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
					  "Server key uses an algorithm that can't be used "
					  "with TLS" ) );
		}

	/* If we're using SNI-based key selection and there's already a main key
	   set, add this new key as an attribute which will be swapped out if
	   required by the server code depending on what the client's SNI 
	   indicates.  This can lead to a slightly odd situation in which, if the
	   caller uses the attribute cursor to step through the attribute list,
	   they'll find additional CRYPT_SESSINFO_PRIVATEKEY attributes alongside 
	   the value that's returned by reading the CRYPT_SESSINFO_PRIVATEKEY 
	   directly, but since they've explicitly set up this situation they 
	   should be expecting it.  The other option would be to hide the copies
	   of the CRYPT_SESSINFO_PRIVATEKEY in the attribute list by giving them
	   some dummy ID like CRYPT_IATTRIBUTE_KEY_TLS_EXT and then adding 
	   special-case code wherever attributes are handled to pretend that this
	   entry doesn't exist, but this is both messy and it's not clear what
	   would be gained by doing it */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
				   TLS_PFLAG_SERVER_SNI ) && \
		sessionInfoPtr->privateKey != CRYPT_ERROR )
		{
		status = addSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PRIVATEKEY, 
								 cryptContext );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendNotifier( cryptContext, IMESSAGE_INCREFCOUNT );

		/* Let the caller know that we've processed the key internally and 
		   there's nothing further to be done */
		return( OK_SPECIAL );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Read/write data over the TLS link */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readHeaderFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   OUT_ENUM_OPT( READINFO ) \
									READSTATE_INFO *readInfo )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	STREAM stream;
	int packetLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* Read the TLS packet header data */
	status = readFixedHeader( sessionInfoPtr, tlsInfo->headerBuffer, 
							  sessionInfoPtr->receiveBufStartOfs );
	if( cryptStatusError( status ) )
		{
		/* OK_SPECIAL means that we got a soft timeout before the entire 
		   header was read, so we return zero bytes read to tell the 
		   calling code that there's nothing more to do */
		return( ( status == OK_SPECIAL ) ? 0 : status );
		}

	/* Since data errors are always fatal, we make all errors fatal until
	   we've finished handling the header */
	*readInfo = READINFO_FATAL;

	/* Check for a TLS alert message */
	if( tlsInfo->headerBuffer[ 0 ] == TLS_MSG_ALERT )
		{
		return( processAlert( sessionInfoPtr, tlsInfo->headerBuffer, 
							  sessionInfoPtr->receiveBufStartOfs,
							  readInfo ) );
		}

	/* Process the header data */
	sMemConnect( &stream, tlsInfo->headerBuffer, 
				 sessionInfoPtr->receiveBufStartOfs );
	status = checkPacketHeaderTLS( sessionInfoPtr, &stream, &packetLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine how much data we'll be expecting */
	sessionInfoPtr->pendingPacketLength = \
		sessionInfoPtr->pendingPacketRemaining = packetLength;

	/* Indicate that we got the header */
	*readInfo = READINFO_NOOP;
	return( OK_SPECIAL );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int discardPacket( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	/* The packet is noise like a session ticket or rehandshake request, 
	   discard it */
	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos;
	sessionInfoPtr->pendingPacketLength = 0;
	*readInfo = READINFO_NOOP;

	return( OK_SPECIAL );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processBodyFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								OUT_ENUM_OPT( READINFO ) \
									READSTATE_INFO *readInfo )
	{
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* All errors processing the payload are fatal, and specifically fatal 
	   crypto errors */
	*readInfo = READINFO_FATAL_CRYPTO;

	/* If we're potentially performing a rehandshake, process the packet
	   as a handshake message and treat it as a no-op.  What the server
	   does in response to this is implementation-specific, the spec says
	   that a client can ignore this (as we do) at which point the server
	   can close the connection or hang waiting for a rehandshake that'll
	   never come (as IIS does) */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
				   TLS_PFLAG_CHECKREHANDSHAKE ) )
		{
		CLEAR_FLAG( sessionInfoPtr->protocolFlags, \
					TLS_PFLAG_CHECKREHANDSHAKE );
		status = unwrapPacketTLS( sessionInfoPtr, 
								  sessionInfoPtr->receiveBuffer + \
									sessionInfoPtr->receiveBufPos, 
								  sessionInfoPtr->pendingPacketLength, 
								  &length, TLS_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			return( status );

		/* Discard the read packet */
		return( discardPacket( sessionInfoPtr, readInfo ) );
		}

	/* Unwrap the payload */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		int actualPacketType;

		/* If we're using TLS 1.3 then we have to deal with its really 
		   clever double-encapsulation of packets */
		status = unwrapPacketTLS13( sessionInfoPtr, 
									sessionInfoPtr->receiveBuffer + \
										sessionInfoPtr->receiveBufPos, 
									sessionInfoPtr->pendingPacketLength, 
									&length, &actualPacketType,
									TLS_MSG_APPLICATION_DATA );
		if( cryptStatusError( status ) )
			return( status );
		if( actualPacketType != TLS_MSG_APPLICATION_DATA )
			{
			/* If it's an alert, handle it specially */
			if( actualPacketType  == TLS_MSG_ALERT )
				{
				return( processAlertTLS13( sessionInfoPtr, 
										   sessionInfoPtr->receiveBuffer + \
												sessionInfoPtr->receiveBufPos, 
										   length, readInfo ) );
				}

			/* It's noise, discard it.  In particular many TLS 
			   implementations will send two session ticket packets 
			   immediately after the handshake to accommodate web browsers
			   opening multiple streams (because the only way anyone would
			   ever use TLS is on the web), so we have to discard two of 
			   these on every connect */
			return( discardPacket( sessionInfoPtr, readInfo ) );
			}
		}
	else
#endif /* USE_TLS13 */
	status = unwrapPacketTLS( sessionInfoPtr, 
							  sessionInfoPtr->receiveBuffer + \
								sessionInfoPtr->receiveBufPos, 
							  sessionInfoPtr->pendingPacketLength, 
							  &length, TLS_MSG_APPLICATION_DATA );
	if( cryptStatusError( status ) )
		return( status );

	*readInfo = READINFO_NONE;
	return( length );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
static int preparePacketFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( !TEST_FLAG( sessionInfoPtr->flags, 
						  SESSION_FLAG_SENDCLOSED ) );
	REQUIRES( !TEST_FLAG( sessionInfoPtr->protocolFlags, \
						  TLS_PFLAG_ALERTSENT ) );

	/* Wrap up the payload ready for sending.  Since this is wrapping in-
	   place data we first open a write stream to add the header, then open
	   a read stream covering the full buffer in preparation for wrapping
	   the packet (the first operation looks a bit counter-intuitive because
	   we're opening a packet stream and then immediately closing it again,
	   but this is as intended since all that we're using it for is to write
	   the packet header at the start).  Note that we connect the later read 
	   stream to the full send buffer (bufSize) even though we only advance 
	   the current stream position to the end of the stream contents 
	   (bufPos), since the packet-wrapping process adds further data to the 
	   stream that exceeds the current stream position */
	status = openPacketStreamTLS( &stream, sessionInfoPtr, 0,
								  TLS_MSG_APPLICATION_DATA );
	if( cryptStatusError( status ) )
		return( status );
	sMemDisconnect( &stream );
	sMemConnect( &stream, sessionInfoPtr->sendBuffer,
				 sessionInfoPtr->sendBufSize );
	status = sSkip( &stream, sessionInfoPtr->sendBufPos, SSKIP_MAX );
	if( cryptStatusOK( status ) )
		{
#ifdef USE_TLS13
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
			{
			status = wrapPacketTLS13( sessionInfoPtr, &stream, 0, 
									  TLS_MSG_APPLICATION_DATA );
			}
		else
#endif /* USE_TLS13 */
		status = wrapPacketTLS( sessionInfoPtr, &stream, 0 );
		}
	if( cryptStatusOK( status ) )
		status = stell( &stream );
	INJECT_FAULT( SESSION_CORRUPT_DATA, SESSION_CORRUPT_DATA_TLS_1 );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		FALSE,						/* Request-response protocol */
		SESSION_PROTOCOL_REFLECTAUTHOK,	/* Flags */
		TLS_PORT,					/* TLS port */
		SESSION_NEEDS_PRIVKEYSIGN,	/* Client attributes */
			/* The client private key is optional, but if present it has to
			   be signature-capable */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_KEYORPASSWORD,
			/* The server key capabilities are complex enough that they
			   need to be checked specially via checkAttributeFunction(),
			   for an RSA key we can have either encryption (for RSA keyex)
			   or signing (for DH keyex) or both, for a DSA or ECDSA key
			   we need signing (for DH/ECDH keyex).

			   In theory we need neither a private key nor a password 
			   because the caller can provide the password during the
			   handshake in response to a CRYPT_ENVELOPE_RESOURCE
			   notification, however this facility is likely to be 
			   barely-used in comparison to users forgetting to add server
			   certificates and the like, so we require some sort of 
			   server-side key set in advance */
		TLS_MINOR_VERSION_TLS12,	/* TLS 1.2 */
#ifdef USE_TLS13
			TLS_MINOR_VERSION_TLS11, TLS_MINOR_VERSION_TLS13,
#else
			TLS_MINOR_VERSION_TLS11, TLS_MINOR_VERSION_TLS12,
#endif /* USE_TLS13 */
			/* Up until 2018 we defaulted to TLS 1.1 rather than TLS 1.2 
			   because support for the latter was minimal for a long time, 
			   particularly among things like embedded devices.  Even TLS 
			   1.1 support was unreliable for many years, with vendors
			   apparently choosing to jump from 1.0 straight to 1.2 when
			   they finally did upgrade (see
			   https://www.trustworthyinternet.org/ssl-pulse for current
			   public-Internet stats, which however is nothing like the 
			   state of the non-visible use of TLS).  We need at least 1.1 
			   in any case in order to have support for TLS extensions and 
			   explicit IVs.
			   
			   For the minimum version, we allowed TLS 1.0 up until 2024 to
			   deal with older implementations because of the lack of 
			   support for 1.1, see the note above */
		CRYPT_SUBPROTOCOL_NONE, CRYPT_SUBPROTOCOL_PEAP,
			/* Allowed sub-protocols */

		/* Protocol-specific information */
		EXTRA_PACKET_SIZE + \
			MAX_PACKET_SIZE,		/* Send/receive buffer size */
		TLS_HEADER_SIZE,			/* Payload data start */
			/* This may be adjusted during the handshake if we're talking
			   TLS 1.1+, which prepends extra data in the form of an IV to
			   the payload */
		MAX_PACKET_SIZE				/* (Default) maximum packet size */
		};
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Make sure that the huge list of cipher suites is set up correctly */
	assert( SSL_NULL_WITH_NULL == 0x00 );
	assert( TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA == 0x0B );
	assert( TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 == 0x17 );
	assert( TLS_KRB5_WITH_DES_CBC_SHA == 0x1E );
	assert( TLS_PSK_WITH_NULL_SHA == 0x2C );
	assert( TLS_RSA_WITH_AES_128_CBC_SHA == 0x2F );
	assert( TLS_RSA_WITH_NULL_SHA256 == 0x3B );
	assert( TLS_DH_DSS_WITH_AES_128_CBC_SHA256 == 0x3E );
	assert( TLS_RSA_WITH_CAMELLIA_128_CBC_SHA == 0x41 );
	assert( TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 == 0x67 );
	assert( TLS_RSA_WITH_CAMELLIA_256_CBC_SHA == 0x84 );
	assert( TLS_PSK_WITH_RC4_128_SHA == 0x8A );
	assert( TLS_RSA_WITH_SEED_CBC_SHA == 0x96 );
	assert( TLS_RSA_WITH_AES_128_GCM_SHA256 == 0x9C );
	assert( TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 == 0xBA );
	assert( TLS_ECDH_ECDSA_WITH_NULL_SHA == 0xC001 );
	assert( TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA == 0xC01A );
	assert( TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 == 0xC023 );
	assert( TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 == 0xC02B );
	assert( TLS_ECDHE_PSK_WITH_RC4_128_SHA == 0xC033 );

	/* Set the access method pointers */
	DATAPTR_SET( sessionInfoPtr->protocolInfo, ( void * ) &protocolInfo );
	FNPTR_SET( sessionInfoPtr->shutdownFunction, shutdownFunction );
	if( isServer( sessionInfoPtr ) )
		{
		FNPTR_SET( sessionInfoPtr->transactFunction, serverStartup );
		}
	else
		{
		FNPTR_SET( sessionInfoPtr->transactFunction, clientStartup );
		}
	FNPTR_SET( sessionInfoPtr->getAttributeFunction, getAttributeFunction );
	FNPTR_SET( sessionInfoPtr->setAttributeFunction, setAttributeFunction );
	FNPTR_SET( sessionInfoPtr->checkAttributeFunction, checkAttributeFunction );
	FNPTR_SET( sessionInfoPtr->readHeaderFunction, readHeaderFunction );
	FNPTR_SET( sessionInfoPtr->processBodyFunction, processBodyFunction );
	FNPTR_SET( sessionInfoPtr->preparePacketFunction, preparePacketFunction );

	/* Initialise additional safe pointers in the session state */
	DATAPTR_SET( tlsInfo->savedHandshakeInfo, NULL );
	DATAPTR_SET( tlsInfo->scoreboardInfoPtr, NULL );

	/* Test the TLS 1.3 crypto zoo */
#if 0
	{
	void testTLS13Zoo( void );

	testTLS13Zoo();
	}
#endif /* 0 */

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
