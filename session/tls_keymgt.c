/****************************************************************************
*																			*
*					cryptlib TLS Key Management Routines					*
*					 Copyright Peter Gutmann 1998-2024						*
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
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Initialise and destroy the crypto information in the handshake state
   information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initHandshakeCryptInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	/* We can't call sanityCheckTLSHandshakeInfo() at this point because the 
	   handshakeInfo hasn't been initialised yet */
	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Clear the handshake information contexts */
	handshakeInfo->md5context = \
		handshakeInfo->sha1context = \
			handshakeInfo->sha2context = CRYPT_ERROR;
#ifdef CONFIG_SUITEB
	handshakeInfo->sha384context = CRYPT_ERROR;
#endif /* CONFIG_SUITEB */
	handshakeInfo->keyexContext = \
		handshakeInfo->sessionHashContext = CRYPT_ERROR;
#ifdef USE_TLS13
	handshakeInfo->keyexEcdhContext = CRYPT_ERROR;
  #ifdef USE_25519
	handshakeInfo->keyex25519Context = CRYPT_ERROR;
  #endif /* USE_25519 */
#endif /* USE_TLS13 */

	/* If we're fuzzing then the crypto isn't used so we can skip the
	   context creation overhead */
	FUZZ_SKIP_REMAINDER();

	/* Create the MAC/dual-hash contexts for incoming and outgoing data.
	   SSLv3 used a pre-HMAC variant for which we couldn't use real HMAC but 
	   would have had to construct it ourselves from MD5 and SHA-1, TLS 
	   1.0-1.1 uses a straight dual hash and MACs that once a MAC key becomes 
	   available at the end of the handshake, and TLS 1.2+ use a standard 
	   hash.  Unfortunately we don't know at this point which variant we're
	   using so we need to handle both kinds */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->md5context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA1 );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->sha1context = createInfo.cryptHandle;
		if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
			return( CRYPT_OK );
		}
#ifdef CONFIG_SUITEB
	if( cryptStatusOK( status ) )
		{
		/* Create the additional SHA2-384 context that's needed for Suite 
		   B use */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA2 );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			{
			static const int blockSize = bitsToBytes( 384 );

			handshakeInfo->sha384context = createInfo.cryptHandle;
			status = krnlSendMessage( handshakeInfo->sha384context, 
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &blockSize,
									  CRYPT_CTXINFO_BLOCKSIZE );
			}
		}
#endif /* CONFIG_SUITEB */
	if( cryptStatusOK( status ) )
		{
		/* Create additional contexts needed for TLS 1.2+ */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA2 );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusError( status ) )
		{
		/* One or more of the contexts couldn't be created, destroy all of 
		   the contexts that have been created so far */
		destroyHandshakeCryptInfo( handshakeInfo );
		return( status );
		}
	handshakeInfo->sha2context = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroyHandshakeCryptInfo( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	if( handshakeInfo->md5context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->md5context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->md5context = CRYPT_ERROR;
		}
	if( handshakeInfo->sha1context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->sha1context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->sha1context = CRYPT_ERROR;
		}
	if( handshakeInfo->sha2context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->sha2context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->sha2context = CRYPT_ERROR;
		}
#ifdef CONFIG_SUITEB
	if( handshakeInfo->sha384context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->sha384context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->sha384context = CRYPT_ERROR;
		}
#endif /* CONFIG_SUITEB */
	if( handshakeInfo->keyexContext != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->keyexContext, 
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->keyexContext = CRYPT_ERROR;
		}
#ifdef USE_TLS13
	if( handshakeInfo->keyexEcdhContext != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->keyexEcdhContext, 
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->keyexEcdhContext = CRYPT_ERROR;
		}
  #ifdef USE_25519
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->keyex25519Context, 
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->keyex25519Context = CRYPT_ERROR;
		}
  #endif /* USE_25519 */
#endif /* USE_TLS13 */
	if( handshakeInfo->sessionHashContext != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->sessionHashContext, 
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->sessionHashContext = CRYPT_ERROR;
		}
	}

/* Initialise and destroy the session security contexts */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initSecurityContextsTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr
#ifdef CONFIG_SUITEB
							, INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo
#endif /* CONFIG_SUITEB */
						   )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
#ifdef CONFIG_SUITEB
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
#endif /* CONFIG_SUITEB */

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Create the HMAC authentication contexts, unless we're using a 
	   combined encryption+authentication mode */
	if( !TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		const CRYPT_ALGO_TYPE integrityAlgo = sessionInfoPtr->integrityAlgo;

		setMessageCreateObjectInfo( &createInfo, integrityAlgo );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			{
			sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;
			setMessageCreateObjectInfo( &createInfo, integrityAlgo );
			status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
									  OBJECT_TYPE_CONTEXT );
			}
		if( cryptStatusError( status ) )
			{
			destroySecurityContextsTLS( sessionInfoPtr );
			return( status );
			}
		sessionInfoPtr->iAuthOutContext = createInfo.cryptHandle;
  #ifdef CONFIG_SUITEB
		if( cryptStatusOK( status ) && \
			handshakeInfo->integrityAlgoParam == bitsToBytes( 384 ) )
			{
			static const int blockSize = bitsToBytes( 384 );

			status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &blockSize,
									  CRYPT_CTXINFO_BLOCKSIZE );
			if( cryptStatusOK( status ) )
				{
				status = krnlSendMessage( sessionInfoPtr->iAuthOutContext, 
										  IMESSAGE_SETATTRIBUTE, 
										  ( MESSAGE_CAST ) &blockSize,
										  CRYPT_CTXINFO_BLOCKSIZE );
				}
			if( cryptStatusError( status ) )
				{
				destroySecurityContextsTLS( sessionInfoPtr );
				return( status );
				}
			}
  #endif /* CONFIG_SUITEB */
		}

	/* Create the encryption contexts */
	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusError( status ) )
		{
		destroySecurityContextsTLS( sessionInfoPtr );
		return( status );
		}
	sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;

	/* If we're using GCM then we also need to change the encryption mode 
	   from the default CBC */
#ifdef USE_GCM
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) ) 
		{
		static const int mode = CRYPT_MODE_GCM;	/* int vs.enum */

		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &mode,
								  CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &mode,
									  CRYPT_CTXINFO_MODE );
			}
		if( cryptStatusError( status ) )
			{
			destroySecurityContextsTLS( sessionInfoPtr );
			return( status );
			}
		}
#endif /* USE_GCM */

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroySecurityContextsTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES_V( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Destroy any active contexts.  The iKeyexCryptContext isn't used 
	   because, although in theory it could be used if the obsolete RSA 
	   keyex was enabled, we always use the iKeyexAuthContext */
	if( sessionInfoPtr->iKeyexAuthContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iKeyexAuthContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iKeyexAuthContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
		}
	}

/* Clone a hash context so that we can continue using the original to hash 
   further messages */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int cloneHashContext( IN_HANDLE const CRYPT_CONTEXT hashContext,
					  OUT_HANDLE_OPT CRYPT_CONTEXT *clonedHashContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int hashAlgo, status;	/* int vs.enum */

	assert( isWritePtr( clonedHashContext, sizeof( CRYPT_CONTEXT * ) ) );

	REQUIRES( isHandleRangeValid( hashContext ) );

	/* Clear return value */
	*clonedHashContext = CRYPT_ERROR;

	/* Determine the type of context that we have to clone */
	status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isHashAlgo( hashAlgo ) );

	/* Create a new hash context and clone the existing one's state into 
	   it */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( hashContext, IMESSAGE_CLONE, NULL, 
							  createInfo.cryptHandle );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*clonedHashContext = createInfo.cryptHandle;
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Keyex Functions								*
*																			*
****************************************************************************/

/* Load a DH/ECDH/25519 key into a context.  Note that initDHcontextTLS()
   doesn't handle 25519 since this is a TLS 1.3 algorithm and that handles 
   its keyex by stuffing the data into the client/server hello rather than
   sending a proper client/server keyex message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createKeyexContextTLS( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
						   IN_ALGO const CRYPT_ALGO_TYPE keyexAlgo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );

	REQUIRES( keyexAlgo == CRYPT_ALGO_DH || keyexAlgo == CRYPT_ALGO_ECDH || \
			  keyexAlgo == CRYPT_ALGO_25519 );

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	/* Create the DH/ECDH/25519 context.  We have to use distinct algorithm-
	   specific labels because for TLS 1.3 we need to create multiple 
	   contexts when we're guessing at what algorithm the other side might 
	   want */
	setMessageCreateObjectInfo( &createInfo, keyexAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	switch( keyexAlgo )
		{
		case CRYPT_ALGO_DH:
			setMessageData( &msgData, "TLS DH key agreement key", 24 );
			break;
		
		case CRYPT_ALGO_ECDH:
			setMessageData( &msgData, "TLS ECDH key agreement key", 26 );
			break;
		
		case CRYPT_ALGO_25519:
			setMessageData( &msgData, "TLS 25519 key agreement key", 27 );
			break;

		default:
			retIntError();
		}
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initKeyexContextTLS( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
						 IN_BUFFER_OPT( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT_Z const int keyDataLength,
						 IN_HANDLE_OPT \
							const CRYPT_CONTEXT iServerKeyTemplate,
						 IN_ENUM_OPT( CRYPT_ECCCURVE ) \
							const CRYPT_ECCCURVE_TYPE eccCurve,
						 IN_BOOL const BOOLEAN isTLSLTS )
	{
	CRYPT_CONTEXT keyexContext;
	int keySize = TLS_DH_KEYSIZE, status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( ( keyData == NULL && keyDataLength == 0 ) || \
			isReadPtrDynamic( keyData, keyDataLength ) );

	REQUIRES( ( keyData == NULL && keyDataLength == 0 ) || \
			  ( keyData != NULL && \
				isShortIntegerRangeNZ( keyDataLength ) ) );
	REQUIRES( iServerKeyTemplate == CRYPT_UNUSED || \
			  isHandleRangeValid( iServerKeyTemplate ) );
	REQUIRES( isEnumRangeOpt( eccCurve, CRYPT_ECCCURVE ) );
	REQUIRES( isBooleanValue( isTLSLTS ) );

	/* If we're fuzzing the input then we don't need to go through any of 
	   the following crypto calisthenics */
	FUZZ_SKIP_REMAINDER();

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	/* If we're loading a built-in DH key, match the key size to the server 
	   authentication key size.  If there's no server key present then we 
	   default to the TLS_DH_KEYSIZE-byte key (the default value set earlier 
	   for the keySize variable) because we don't know how much processing 
	   power the client has */
	if( keyData == NULL && iServerKeyTemplate != CRYPT_UNUSED && \
		eccCurve == CRYPT_ECCCURVE_NONE )
		{
		status = krnlSendMessage( iServerKeyTemplate, IMESSAGE_GETATTRIBUTE,
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Create the DH/ECDH context.  This is never 25519 for the reason given
	   in the comment at the start of this section */
	status = createKeyexContextTLS( &keyexContext, 
									( eccCurve != CRYPT_ECCCURVE_NONE ) ? \
									  CRYPT_ALGO_ECDH : CRYPT_ALGO_DH );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the key into the context.  If we're being given externally-
	   supplied DH/ECDH key components, load them, otherwise use the built-
	   in key */
	if( keyData != NULL )
		{
		MESSAGE_DATA msgData;

		/* If we're the client we'll have been sent DH/ECDH key components 
		   by the server */
		setMessageData( &msgData, ( MESSAGE_CAST ) keyData, keyDataLength ); 
		status = krnlSendMessage( keyexContext, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, 
								  isTLSLTS ? CRYPT_IATTRIBUTE_KEY_TLS_EXT : \
											 CRYPT_IATTRIBUTE_KEY_TLS );
		}
	else
		{
#ifdef USE_ECDH 
		/* If we've been given ECC parameter information then we're using
		   ECDH */
		if( eccCurve != CRYPT_ECCCURVE_NONE )
			{
			const int eccParams = eccCurve;	/* int vs. enum */

			status = krnlSendMessage( keyexContext, IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &eccParams, 
									  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
			}
		else
#endif /* USE_ECDH */
			{
			/* We're loading a standard DH key of the appropriate size */
			status = krnlSendMessage( keyexContext, IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &keySize, 
									  CRYPT_IATTRIBUTE_KEY_DLPPARAM );
			}
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( keyexContext, IMESSAGE_DECREFCOUNT );
		if( keyData == NULL )
			{
			/* If we got an error loading a known-good, fixed-format key 
			   then we report the problem as an internal error rather than 
			   (say) a bad-data error */
			retIntError();
			}
		return( status );
		}
	*iCryptContext = keyexContext;

	return( CRYPT_OK );
	}

/* Complete the (EC)DH keyex */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int completeTLSKeyex( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					  INOUT_PTR STREAM *stream, 
					  IN_BOOL const BOOLEAN isTLSLTS,
					  IN_BOOL const BOOLEAN isTLS13,
					  INOUT_PTR ERROR_INFO *errorInfo )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	const char *keyTypeName;
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( isTLSLTS ) );
	REQUIRES( isBooleanValue( isTLS13 ) );

	/* Read the DH/ECDH/25519 key agreement parameters:

		DH:
			uint16	yLen
			byte[]	y
		ECDH, TLS 1.2
			uint8	ecPointLen	-- NB uint8 not uint16
			byte[]	ecPoint
		ECDH, TLS 1.3
			uint16	ecPointLen	
			byte[]	ecPoint 
		25519:
			uint16	x25519PubValueLen
			byte[]	x25519PubValue

	   Note the anomalous use of of an 8-bit length for ECDH, this is from
	   classic TLS which used this for no known reason.  TLS 1.3 went to a
	   standard 16-bit length */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	switch( handshakeInfo->keyexAlgo )
		{
		case CRYPT_ALGO_DH:
			keyTypeName = "DH";
			status = readInteger16U( stream, keyAgreeParams.publicValue,
									 &keyAgreeParams.publicValueLen,
									 MIN_PKCSIZE, CRYPT_MAX_PKCSIZE, 
									 BIGNUM_CHECK_VALUE_PKC );
			break;

		case CRYPT_ALGO_ECDH:
			keyTypeName = "ECDH";
#ifdef USE_TLS13
			if( isTLS13 )
				{
				status = readInteger16U( stream, keyAgreeParams.publicValue,
										 &keyAgreeParams.publicValueLen,
										 MIN_PKCSIZE_ECCPOINT, 
										 MAX_PKCSIZE_ECCPOINT, 
										 BIGNUM_CHECK_VALUE_ECC );
				if( cryptStatusOK( status ) && \
					isShortECCKey( keyAgreeParams.publicValueLen / 2 ) )
					status = CRYPT_ERROR_NOSECURE;
				}
			else
#endif /* USE_TLS13 */
			status = readEcdhValue( stream, keyAgreeParams.publicValue,
									CRYPT_MAX_PKCSIZE, 
									&keyAgreeParams.publicValueLen );
			break;

#ifdef USE_25519
		case CRYPT_ALGO_25519:
			keyTypeName = "25519";
			status = readInteger16U( stream, keyAgreeParams.publicValue,
									 &keyAgreeParams.publicValueLen,
									 MIN_PKCSIZE_BERNSTEIN, 
									 MAX_PKCSIZE_BERNSTEIN, 
									 BIGNUM_CHECK_VALUE_FIXEDLEN );
			break;
#endif /* USE_25519 */

		default: 
			retIntError();		
		}
	if( cryptStatusError( status ) )
		{
		/* Some misconfigured clients may use very short keys, we perform a 
		   special-case check for these and return a more specific message 
		   than the generic bad-data error */
		if( status == CRYPT_ERROR_NOSECURE )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, errorInfo, 
					  "Insecure %s key used in key exchange",
					  keyTypeName ) );
			}

		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid %s phase 2 key agreement data",
				  keyTypeName ) );
		}

	/* If we're fuzzing the input then we don't need to go through any of 
	   the following crypto calisthenics.  In addition we can exit now 
	   because the remaining fuzzable code is common with the client and
	   has already been tested there */
	FUZZ_EXIT();

	/* Perform phase 2 of the (EC)DH key agreement */
	status = krnlSendMessage( handshakeInfo->keyexContext, 
							  IMESSAGE_CTX_DECRYPT, &keyAgreeParams, 
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		{
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		retExt( status,
				( status, errorInfo, 
				  "Invalid %s phase 2 key agreement value",
				  keyTypeName ) );
		}

	/* The output of the ECDH operation is an ECC point, but for some 
	   unknown reason TLS only uses the x coordinate and not the full point
	   in its crypto computations (RFC 4492 section 5.10 / RFC 8446 section 
	   7.4.2) even though it transmits the full point in the handshake.  To 
	   work around this we have to rewrite the point as a standalone x 
	   coordinate, which is relatively easy because we're using the 
	   uncompressed point format: 

		+---+---------------+---------------+
		|04	|		qx		|		qy		|
		+---+---------------+---------------+
			|<- fldSize --> |<- fldSize --> | */
	if( handshakeInfo->keyexAlgo == CRYPT_ALGO_ECDH && !isTLSLTS )
		{
		const int xCoordLen = ( keyAgreeParams.wrappedKeyLen - 1 ) / 2;

		REQUIRES( keyAgreeParams.wrappedKeyLen >= MIN_PKCSIZE_ECCPOINT && \
				  keyAgreeParams.wrappedKeyLen <= MAX_PKCSIZE_ECCPOINT && \
				  ( keyAgreeParams.wrappedKeyLen & 1 ) == 1 && \
				  keyAgreeParams.wrappedKey[ 0 ] == 0x04 );
		REQUIRES( boundsCheck( 1, xCoordLen, CRYPT_MAX_PKCSIZE ) );
		memmove( keyAgreeParams.wrappedKey, 
				 keyAgreeParams.wrappedKey + 1, xCoordLen );
		keyAgreeParams.wrappedKeyLen = xCoordLen;
		}

	/* Remember the premaster secret, the output of the (EC)DH operation */
	REQUIRES( rangeCheck( keyAgreeParams.wrappedKeyLen, 1,
						  CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE ) );
	memcpy( handshakeInfo->premasterSecret, keyAgreeParams.wrappedKey,
			keyAgreeParams.wrappedKeyLen );
	handshakeInfo->premasterSecretSize = keyAgreeParams.wrappedKeyLen;
	zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	DEBUG_DUMP_DATA_LABEL( "Keyex output:",
						   handshakeInfo->premasterSecret, 
						   handshakeInfo->premasterSecretSize );

	return( CRYPT_OK );
	}

/* Create the master secret from a shared (PSK) secret value, typically a
   password */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int createSharedPremasterSecret( OUT_BUFFER( premasterSecretMaxLength, \
											 *premasterSecretLength ) \
									void *premasterSecret, 
								 IN_LENGTH_SHORT_MIN( 16 ) \
									const int premasterSecretMaxLength, 
								 OUT_LENGTH_BOUNDED_Z( premasterSecretMaxLength ) \
									int *premasterSecretLength,
								 IN_BUFFER( sharedSecretLength ) \
									const void *sharedSecret, 
								 IN_LENGTH_TEXT const int sharedSecretLength,
								 IN_BUFFER_OPT( otherSecretLength ) \
									const void *otherSecret, 
								 IN_LENGTH_PKC_Z const int otherSecretLength,
								 IN_BOOL const BOOLEAN isEncodedValue )
	{
	STREAM stream;
	BYTE decodedValue[ 64 + 8 ];
	static const BYTE zeroes[ CRYPT_MAX_TEXTSIZE + 8 ] = { 0 };
	int valueLength = sharedSecretLength;
	int status;

	assert( isWritePtrDynamic( premasterSecret, premasterSecretMaxLength ) );
	assert( isWritePtr( premasterSecretLength, sizeof( int ) ) );
	assert( isReadPtrDynamic( sharedSecret, sharedSecretLength ) );
	assert( otherSecret == NULL || \
			isReadPtrDynamic( otherSecret, otherSecretLength ) );

	REQUIRES( isShortIntegerRangeMin( premasterSecretMaxLength, 16 ) );
	REQUIRES( sharedSecretLength > 0 && \
			  sharedSecretLength <= CRYPT_MAX_TEXTSIZE );
	REQUIRES( ( otherSecret == NULL && otherSecretLength == 0 ) || \
			  ( otherSecret != NULL && \
				otherSecretLength > 0 && \
				otherSecretLength <= CRYPT_MAX_PKCSIZE ) );
	REQUIRES( isBooleanValue( isEncodedValue ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeMin( premasterSecretMaxLength, 16 ) ); 
	memset( premasterSecret, 0, min( 16, premasterSecretMaxLength ) );
	*premasterSecretLength = 0;

	/* Write the PSK-derived premaster secret value:

		uint16	otherSecretLen
		byte[]	otherSecret		-- DH value for DHE-PSK, zeroes for pure PSK
		uint16	pskLen
		byte[]	psk

	   Because the TLS PRF splits the input into two halves of which one half 
	   is processed by HMAC-MD5 and the other by HMAC-SHA1, it's necessary
	   to extend the PSK in some way to provide input to both halves of the
	   PRF.  In a rather dubious decision, the spec requires that for pure
	   PSK (not DHE-PSK or RSA-PSK) the MD5 half be set to all zeroes, with 
	   only the SHA1 half being used.  This is done by writing otherSecret 
	   as a number of zero bytes equal in length to the password */
	sMemOpen( &stream, premasterSecret, premasterSecretMaxLength );
	if( isEncodedValue )
		{
		/* It's a cryptlib-style encoded password, decode it into its binary
		   value */
		status = decodePKIUserValue( decodedValue, 64, &valueLength,
									 sharedSecret, sharedSecretLength );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "Couldn't decode supposedly valid PKI user "
						 "value" ));
			assert( DEBUG_WARN );
			return( status );
			}
		sharedSecret = decodedValue;
		}
	if( otherSecret != NULL )
		{
		writeUint16( &stream, otherSecretLength );
		swrite( &stream, otherSecret, otherSecretLength );
		}
	else
		{
		/* It's pure PSK, otherSecret is a string of zeroes */
		writeUint16( &stream, valueLength );
		swrite( &stream, zeroes, valueLength );
		}
	writeUint16( &stream, valueLength );
	status = swrite( &stream, sharedSecret, valueLength );
	if( isEncodedValue )
		{
		REQUIRES( isShortIntegerRangeNZ( valueLength ) ); 
		zeroise( decodedValue, valueLength );
		}
	if( cryptStatusError( status ) )
		return( status );
	*premasterSecretLength = stell( &stream );
	sMemDisconnect( &stream );
	ENSURES( isShortIntegerRangeNZ( *premasterSecretLength ) );

	return( CRYPT_OK );
	}

#ifdef USE_RSA_SUITES

/* Wrap/unwrap the pre-master secret */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int wrapPremasterSecret( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
						 IN_LENGTH_SHORT_MIN( 16 ) const int dataMaxLength, 
						 OUT_LENGTH_BOUNDED_Z( dataMaxLength ) \
							int *dataLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 16 ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 16 ) ); 
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* Create the premaster secret and wrap it using the server's public
	   key.  The version that we advertise at this point is the version 
	   originally offered by the client in its hello message, not the 
	   version eventually negotiated for the connection.  This is designed 
	   to prevent rollback attacks, but see also the comment in
	   unwrapPremasterSecret() below.
	   
	   Note that the keyex key is held in the iKeyexAuthContext rather than
	   the iKeyexCryptContext since the key can be used for either direct
	   keyex or to authenticate an (EC)DH keyex, which means in practice it's
	   always the latter */
	handshakeInfo->premasterSecretSize = TLS_SECRET_SIZE;
	handshakeInfo->premasterSecret[ 0 ] = TLS_MAJOR_VERSION;
	handshakeInfo->premasterSecret[ 1 ] = \
						intToByte( handshakeInfo->clientOfferedVersion );
	setMessageData( &msgData,
					handshakeInfo->premasterSecret + VERSIONINFO_SIZE,
					TLS_SECRET_SIZE - VERSIONINFO_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismWrapInfo( &mechanismInfo, data, dataMaxLength,
						  handshakeInfo->premasterSecret, TLS_SECRET_SIZE, 
						  CRYPT_UNUSED, sessionInfoPtr->iKeyexAuthContext );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, MECHANISM_ENC_PKCS1_RAW );
	if( cryptStatusOK( status ) )
		*dataLength = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int unwrapPremasterSecret( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   IN_BUFFER( dataLength ) const void *data, 
						   IN_LENGTH_SHORT_MIN( 16 ) const int dataLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeMin( dataLength, 16 ) );

	/* Decrypt the encrypted premaster secret.  In theory we could
	   explicitly defend against Bleichenbacher-type attacks at this point
	   by setting the premaster secret to a pseudorandom value if we get a
	   bad data or (later) an incorrect version error and continuing as
	   normal, however the attack depends on the server returning
	   information required to pinpoint the cause of the failure and
	   cryptlib just returns a generic "failed" response for any handshake
	   failure, so this explicit defence isn't really necessary, and not
	   doing this avoids a trivial DoS attack in which a client sends us
	   junk and forces us to continue with the handshake even though we've
	   detected that it's junk.

	   There's a second, lower-grade level of oracle that an attacker can
	   use in the version check if they can distinguish between a decrypt 
	   failure due to bad PKCS #1 padding and a failure due to a bad version 
	   number (see "Attacking RSA-based Sessions in SSL/TLS", Vlastimil
	   Klima, Ondrej Pokorny, and Tomas Rosa, CHES'03), or many other later 
	   variants of the Bleichenbacher attack that target additional features
	   like missing padding terminators or padding terminators in odd 
	   locations (leading to incorrect payload sizes), and so on.
	   
	   If we use the Bleichenbacher defence and continue the handshake on 
	   bad padding but bail out on a bad version then the two cases can be 
	   distinguished, however since cryptlib bails out immediately in either 
	   case the two shouldn't be distinguishable.
	   
	   Yet another oracle exists if we get a valid PKCS #1 message and
	   continue past this point but the key is invalid causing the handshake 
	   to fail later one, which is why this code is disabled and triggers 
	   compile warnings if it's ever re-enabled */
	handshakeInfo->premasterSecretSize = TLS_SECRET_SIZE;
	setMechanismWrapInfo( &mechanismInfo, ( MESSAGE_CAST ) data, dataLength,
						  handshakeInfo->premasterSecret, TLS_SECRET_SIZE, 
						  CRYPT_UNUSED, sessionInfoPtr->privateKey );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT,
							  &mechanismInfo, MECHANISM_ENC_PKCS1_RAW );
	if( cryptStatusOK( status ) && \
		mechanismInfo.keyDataLength != TLS_SECRET_SIZE )
		status = CRYPT_ERROR_BADDATA;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		{
		/* This is a pretty nonspecific error message, but it's useful for
		   diagnosing general decryption problems, as well as the potential 
		   presence of various types of oracle attacks */
		if( status == CRYPT_ERROR_BADDATA )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "RSA decryption of premaster secret produced invalid "
					  "PKCS #1 data" ) );
			}
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "RSA decryption of premaster secret failed" ) );
		}

	/* Make sure that it looks OK.  Note that the version that we check for
	   at this point is the version originally offered by the client in its
	   hello message, not the version eventually negotiated for the
	   connection.  This is designed to prevent rollback attacks */
	if( handshakeInfo->premasterSecret[ 0 ] != TLS_MAJOR_VERSION || \
		handshakeInfo->premasterSecret[ 1 ] != handshakeInfo->clientOfferedVersion )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid premaster secret version data 0x%02X 0x%02X, "
				  "expected 0x03 0x%02X",
				  byteToInt( handshakeInfo->premasterSecret[ 0 ] ),
				  byteToInt( handshakeInfo->premasterSecret[ 1 ] ),
				  handshakeInfo->clientOfferedVersion ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_RSA_SUITES */

/****************************************************************************
*																			*
*				Premaster -> Master -> Key Material Functions				*
*																			*
****************************************************************************/

/* Convert a pre-master secret to a master secret and a master secret to
   keying material */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int premasterToMaster( const SESSION_INFO *sessionInfoPtr, 
							  const TLS_HANDSHAKE_INFO *handshakeInfo, 
							  OUT_BUFFER_FIXED( masterSecretLength ) \
									void *masterSecret, 
							  IN_LENGTH_SHORT_MIN( 16 ) \
									const int masterSecretLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ 64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE + 8 ];
	int nonceSize;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( masterSecret, masterSecretLength ) );

	REQUIRES( isShortIntegerRangeMin( masterSecretLength, 16 ) );

	DEBUG_DUMP_DATA_LABEL( "Premaster secret:",
						   handshakeInfo->premasterSecret, 
						   handshakeInfo->premasterSecretSize );

	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_EMS ) )
		{
		REQUIRES( boundsCheck( 22, handshakeInfo->sessionHashSize, 
							   64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE ) );
		memcpy( nonceBuffer, "extended master secret", 22 );
		memcpy( nonceBuffer + 22, handshakeInfo->sessionHash, 
				handshakeInfo->sessionHashSize );
		nonceSize = 22 + handshakeInfo->sessionHashSize;
		}
	else
		{
		REQUIRES( boundsCheck( 13, TLS_NONCE_SIZE + TLS_NONCE_SIZE, 
							   64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE ) );
		memcpy( nonceBuffer, "master secret", 13 );
		memcpy( nonceBuffer + 13, handshakeInfo->clientNonce, 
				TLS_NONCE_SIZE );
		memcpy( nonceBuffer + 13 + TLS_NONCE_SIZE, 
				handshakeInfo->serverNonce, TLS_NONCE_SIZE );
		nonceSize = 13 + TLS_NONCE_SIZE + TLS_NONCE_SIZE;
		}
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		setMechanismDeriveInfo( &mechanismInfo, masterSecret, 
								masterSecretLength, 
								handshakeInfo->premasterSecret,
								handshakeInfo->premasterSecretSize,
								CRYPT_ALGO_SHA2, nonceBuffer, nonceSize, 1 );
		if( handshakeInfo->integrityAlgoParam != 0 )
			mechanismInfo.hashParam = handshakeInfo->integrityAlgoParam;
		return( krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								 &mechanismInfo, MECHANISM_DERIVE_TLS12 ) );
		}
	setMechanismDeriveInfo( &mechanismInfo, masterSecret, masterSecretLength,
							handshakeInfo->premasterSecret,
							handshakeInfo->premasterSecretSize,
							CRYPT_ALGO_NONE,	/* Implicit SHA1+MD5 */ 
							nonceBuffer, nonceSize, 1 );
	return( krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_DERIVE_TLS ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
static int masterToKeys( const SESSION_INFO *sessionInfoPtr, 
						 const TLS_HANDSHAKE_INFO *handshakeInfo, 
						 IN_BUFFER( masterSecretLength ) \
								const void *masterSecret, 
						 IN_LENGTH_SHORT_MIN( 16 ) \
								const int masterSecretLength,
						 OUT_BUFFER_FIXED( keyBlockLength ) void *keyBlock, 
						 IN_LENGTH_SHORT_MIN( 16 ) const int keyBlockLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ 64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE + 8 ];

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( masterSecret, masterSecretLength ) );
	assert( isWritePtrDynamic( keyBlock, keyBlockLength ) );

	REQUIRES( isShortIntegerRangeMin( masterSecretLength, 16 ) );
	REQUIRES( isShortIntegerRangeMin( keyBlockLength, 16 ) );

	DEBUG_DUMP_DATA_LABEL( "Master secret:",
						   masterSecret, masterSecretLength );

	/* If we're running in debug mode, output information needed by 
	   Wireshark to decrypt the captured TLS traffic in NSS key log format
	   (a.k.a. SSLKEYLOGFILE), see 
	   https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format and
	   https://nss-crypto.org/reference/security/nss/legacy/key_log_format/index.html */
	DEBUG_PRINT_BEGIN();
	DEBUG_PUTS(( "NSS Key Log:" ));
	DEBUG_PRINT(( "CLIENT_RANDOM " ));
	DEBUG_OP( { int i; for( i = 0; i < TLS_NONCE_SIZE; i++ ) { );
	DEBUG_PRINT(( "%02x", handshakeInfo->clientNonce[ i ] ));
	DEBUG_OP( } );
	DEBUG_PRINT(( " " ));
	DEBUG_OP( for( i = 0; i < masterSecretLength; i++ ) { );
	DEBUG_PRINT(( "%02x", ( ( BYTE * ) masterSecret )[ i ] ));
	DEBUG_OP( } } );
	DEBUG_PUTS(( "" ));
	DEBUG_PRINT_END();

	REQUIRES( boundsCheck( 13, TLS_NONCE_SIZE + TLS_NONCE_SIZE, 
						   64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE ) );
	memcpy( nonceBuffer, "key expansion", 13 );
	memcpy( nonceBuffer + 13, handshakeInfo->serverNonce, TLS_NONCE_SIZE );
	memcpy( nonceBuffer + 13 + TLS_NONCE_SIZE, handshakeInfo->clientNonce,
			TLS_NONCE_SIZE );
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		setMechanismDeriveInfo( &mechanismInfo, keyBlock, keyBlockLength,
								masterSecret, masterSecretLength, 
								CRYPT_ALGO_SHA2, nonceBuffer, 
								13 + TLS_NONCE_SIZE + TLS_NONCE_SIZE, 1 );
		if( handshakeInfo->integrityAlgoParam != 0 )
			mechanismInfo.hashParam = handshakeInfo->integrityAlgoParam;
		return( krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								 &mechanismInfo, MECHANISM_DERIVE_TLS12 ) );
		}
	setMechanismDeriveInfo( &mechanismInfo, keyBlock, keyBlockLength,
							masterSecret, masterSecretLength, 
							CRYPT_ALGO_NONE,	/* Implicit SHA1+MD5 */ 
							nonceBuffer, 
							13 + TLS_NONCE_SIZE + TLS_NONCE_SIZE, 1 );
	return( krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_DERIVE_TLS ) );
	}

#ifdef USE_EAP

/* Convert a master secret to additional keying material.  Note that we 
   can't use masterToKeys() here because the sub-protocols that use these
   derived values reverse the order of the nonces */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5, 7 ) ) \
static int masterToKeydata( const SESSION_INFO *sessionInfoPtr, 
							const TLS_HANDSHAKE_INFO *handshakeInfo, 
							IN_BUFFER( masterSecretLength ) \
								const void *masterSecret, 
							IN_LENGTH_SHORT_MIN( 16 ) \
								const int masterSecretLength,
							IN_BUFFER( diversifierLength ) \
								const void *diversifier,
							IN_LENGTH_TEXT const int diversifierLength,
							OUT_BUFFER_FIXED( keyBlockLength ) void *keyBlock, 
							IN_LENGTH_SHORT_MIN( 16 ) \
								const int keyBlockLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ CRYPT_MAX_TEXTSIZE + TLS_NONCE_SIZE + TLS_NONCE_SIZE + 8 ];

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( masterSecret, masterSecretLength ) );
	assert( isReadPtrDynamic( diversifier, diversifierLength ) );
	assert( isWritePtrDynamic( keyBlock, keyBlockLength ) );

	REQUIRES( isShortIntegerRangeMin( masterSecretLength, 16 ) );
	REQUIRES( diversifierLength >= 1 && \
			  diversifierLength <= CRYPT_MAX_TEXTSIZE );
	REQUIRES( isShortIntegerRangeMin( keyBlockLength, 16 ) );

	REQUIRES( boundsCheck( diversifierLength, TLS_NONCE_SIZE + TLS_NONCE_SIZE,
						   CRYPT_MAX_TEXTSIZE + TLS_NONCE_SIZE + \
												TLS_NONCE_SIZE ) );
	memcpy( nonceBuffer, diversifier, diversifierLength );
	memcpy( nonceBuffer + diversifierLength, 
			handshakeInfo->clientNonce, TLS_NONCE_SIZE );
	memcpy( nonceBuffer + diversifierLength + TLS_NONCE_SIZE, 
			handshakeInfo->serverNonce, TLS_NONCE_SIZE );
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		setMechanismDeriveInfo( &mechanismInfo, keyBlock, keyBlockLength,
								masterSecret, masterSecretLength, 
								CRYPT_ALGO_SHA2, nonceBuffer, 
								diversifierLength + TLS_NONCE_SIZE + \
													TLS_NONCE_SIZE, 1 );
		if( handshakeInfo->integrityAlgoParam != 0 )
			mechanismInfo.hashParam = handshakeInfo->integrityAlgoParam;
		return( krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								 &mechanismInfo, MECHANISM_DERIVE_TLS12 ) );
		}
	setMechanismDeriveInfo( &mechanismInfo, keyBlock, keyBlockLength,
							masterSecret, masterSecretLength, 
							CRYPT_ALGO_NONE,	/* Implicit SHA1+MD5 */ 
							nonceBuffer, 
							diversifierLength + TLS_NONCE_SIZE + \
												TLS_NONCE_SIZE, 1 );
	return( krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_DERIVE_TLS ) );
	}
#endif /* USE_EAP */

/****************************************************************************
*																			*
*								Key-load Functions							*
*																			*
****************************************************************************/

/* Load the TLS cryptovariables */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int loadKeys( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo,
					 IN_BUFFER( keyBlockLength ) const void *keyBlock, 
					 IN_LENGTH_SHORT_MIN( 16 ) const int keyBlockLength,
					 IN_BOOL const BOOLEAN isClient )
	{
	MESSAGE_DATA msgData;
	BYTE *keyBlockPtr = ( BYTE * ) keyBlock;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( keyBlock, keyBlockLength ) );

	REQUIRES( keyBlockLength >= ( sessionInfoPtr->authBlocksize * 2 ) + \
								( handshakeInfo->cryptKeysize * 2 ) + \
								( sessionInfoPtr->cryptBlocksize * 2 ) && \
			  keyBlockLength < MAX_INTLENGTH_SHORT );
			  /* The above check is safe even for modes that don't need a 
			     MAC key or IV since we always generate sufficient keying 
				 material for all cases */
	REQUIRES( isBooleanValue( isClient ) );

	/* Load the keys and secrets:

		( client_write_mac || server_write_mac || \
		  client_write_key || server_write_key || \
		  client_write_iv  || server_write_iv )

	   First we load the MAC keys unless we're using GCM or the Bernstein 
	   suite, for which we skip the load since the encryption key also 
	   functions as the authentication key */
	if( !TEST_FLAG( sessionInfoPtr->protocolFlags, 
					( TLS_PFLAG_GCM | TLS_PFLAG_BERNSTEIN ) ) )
		{
		setMessageData( &msgData, keyBlockPtr, 
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iAuthOutContext : \
										sessionInfoPtr->iAuthInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusError( status ) )
			return( status );
		setMessageData( &msgData, 
						keyBlockPtr + sessionInfoPtr->authBlocksize,
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iAuthInContext: \
										sessionInfoPtr->iAuthOutContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusError( status ) )
			return( status );
		keyBlockPtr += sessionInfoPtr->authBlocksize * 2;
		}

	/* If we're using a special-snowflake MAC then we have to load a dummy 
	   key since it needs a rekey on each packet, and to do that there needs 
	   to be an initial key loaded */
#if defined( USE_POLY1305 )
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_BERNSTEIN ) )
		{
		static const BYTE dummyKey[ 32 ] = { 0 };

		setMessageData( &msgData, ( MESSAGE_CAST ) dummyKey, 32 );
		status = krnlSendMessage( sessionInfoPtr->iAuthInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( sessionInfoPtr->iAuthOutContext,
									  IMESSAGE_SETATTRIBUTE_S, &msgData,
									  CRYPT_CTXINFO_KEY );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_POLY1305 */

	/* Now load the encryption keys */
	setMessageData( &msgData, keyBlockPtr, handshakeInfo->cryptKeysize );
	status = krnlSendMessage( isClient ? \
									sessionInfoPtr->iCryptOutContext : \
									sessionInfoPtr->iCryptInContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	keyBlockPtr += handshakeInfo->cryptKeysize;
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, keyBlockPtr, handshakeInfo->cryptKeysize );
	status = krnlSendMessage( isClient ? \
									sessionInfoPtr->iCryptInContext : \
									sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	keyBlockPtr += handshakeInfo->cryptKeysize;
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using a stream cipher then there are no IVs */
	if( isStreamCipher( sessionInfoPtr->cryptAlgo ) )
		return( CRYPT_OK );	/* No IV, we're done */

	/* If we're using GCM or the Bernstein protcol suite then the IV is 
	   handled specially, for GCM it's composed of two parts, an explicit 
	   portion that's sent with every packet and an implicit portion that's 
	   derived from the master secret, and for the Bernstein suite it's a
	   96-bit value that's XOR'd with the explicit part */
#if defined( USE_GCM ) || defined( USE_CHACHA20 )
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, 
				   TLS_PFLAG_GCM | TLS_PFLAG_BERNSTEIN ) )
		{
		TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
		const int ivLength = \
					TEST_FLAG( sessionInfoPtr->protocolFlags, \
							   TLS_PFLAG_BERNSTEIN ) ? \
							   BERNSTEIN_IV_SIZE : GCM_SALT_SIZE;

		memcpy( isClient ? tlsInfo->aeadWriteSalt : tlsInfo->aeadReadSalt, 
				keyBlockPtr, ivLength );
		memcpy( isClient ? tlsInfo->aeadReadSalt : tlsInfo->aeadWriteSalt, 
				keyBlockPtr + ivLength, ivLength );
		tlsInfo->aeadSaltSize = ivLength;

		return( CRYPT_OK );
		}
#endif /* USE_GCM || USE_CHACHA20 */

	/* It's a standard block cipher, load the IVs.  This load is actually 
	   redundant for TLS 1.1+ since it uses explicit IVs, but it's easier to 
	   just do it anyway */
	setMessageData( &msgData, keyBlockPtr,
					sessionInfoPtr->cryptBlocksize );
	krnlSendMessage( isClient ? sessionInfoPtr->iCryptOutContext : \
								sessionInfoPtr->iCryptInContext,
					 IMESSAGE_SETATTRIBUTE_S, &msgData,
					 CRYPT_CTXINFO_IV );
	keyBlockPtr += sessionInfoPtr->cryptBlocksize;
	setMessageData( &msgData, keyBlockPtr,
					sessionInfoPtr->cryptBlocksize );
	return( krnlSendMessage( isClient ? sessionInfoPtr->iCryptInContext : \
										sessionInfoPtr->iCryptOutContext,
							 IMESSAGE_SETATTRIBUTE_S, &msgData,
							 CRYPT_CTXINFO_IV ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int initCryptoTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
				   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
				   OUT_BUFFER_FIXED( masterSecretSize ) void *masterSecret,
				   IN_LENGTH_SHORT_MIN( 16 ) const int masterSecretSize,
				   IN_BOOL const BOOLEAN isClient,
				   IN_BOOL const BOOLEAN isResumedSession )
	{
	BYTE keyBlock[ MAX_KEYBLOCK_SIZE + 8 ];
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtrDynamic( masterSecret, masterSecretSize ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeMin( masterSecretSize, 16 ) );
	REQUIRES( isBooleanValue( isClient ) );
	REQUIRES( isBooleanValue( isResumedSession ) );

	/* Create the security contexts required for the session */
	status = initSecurityContextsTLS( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a fresh (i.e. non-cached) session, convert the premaster 
	   secret into the master secret */
	if( !isResumedSession )
		{
		status = premasterToMaster( sessionInfoPtr, handshakeInfo,
									masterSecret, masterSecretSize );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		/* We've already got the master secret present from the session that
		   we're resuming from, reuse that */
		REQUIRES( rangeCheck( handshakeInfo->premasterSecretSize, 16,
							  masterSecretSize ) );
		memcpy( masterSecret, handshakeInfo->premasterSecret,
				handshakeInfo->premasterSecretSize );
		}

	/* Convert the master secret into keying material.  We can't delete the 
	   master secret at this point because it's still needed to calculate 
	   the MAC for the handshake messages and because we may still need it 
	   in order to add it to the session cache */
	status = masterToKeys( sessionInfoPtr, handshakeInfo, masterSecret,
						   masterSecretSize, keyBlock, MAX_KEYBLOCK_SIZE );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeMin( masterSecretSize, 16 ) ); 
		zeroise( masterSecret, masterSecretSize );
		return( status );
		}

	/* Load the keys and secrets */
	status = loadKeys( sessionInfoPtr, handshakeInfo, keyBlock, 
					   MAX_KEYBLOCK_SIZE, isClient );
	zeroise( keyBlock, MAX_KEYBLOCK_SIZE );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeMin( masterSecretSize, 16 ) ); 
		zeroise( masterSecret, masterSecretSize );
		return( status );
		}

	return( CRYPT_OK );
	}

/* TLS versions 1.1 and 1.2 prepend an explicit IV to the data, the 
   following function loads this from the packet data stream */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int loadExplicitIV( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR STREAM *stream, 
					OUT_INT_SHORT_Z int *ivLength )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];
	int ivSize = tlsInfo->ivSize, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( ivLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Clear return value */
	*ivLength = 0;

	/* Read and load the IV */
	REQUIRES( rangeCheck( tlsInfo->ivSize, 1, CRYPT_MAX_IVSIZE ) );
	status = sread( stream, iv, tlsInfo->ivSize );
	if( cryptStatusError( status ) )
		return( status );
	INJECT_FAULT( SESSION_TLS_CORRUPT_IV, SESSION_TLS_CORRUPT_IV_1 );
#if defined( USE_GCM ) 
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		/* If we're using GCM then the IV has to be assembled from the 
		   implicit and explicit portions */
		REQUIRES( boundsCheck( tlsInfo->aeadSaltSize, tlsInfo->ivSize,
							   CRYPT_MAX_IVSIZE ) );
		memmove( iv + tlsInfo->aeadSaltSize, iv, tlsInfo->ivSize );
		memcpy( iv, tlsInfo->aeadReadSalt, tlsInfo->aeadSaltSize );
		ivSize += tlsInfo->aeadSaltSize;
		}
#endif /* USE_GCM */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_ENCTHENMAC ) )
		{
		/* If we're using encrypt-then-MAC then we have to save a copy of
		   the IV for MAC'ing when the packet is processed */
		REQUIRES( rangeCheck( tlsInfo->ivSize, 1, CRYPT_MAX_IVSIZE ) );
		memcpy( tlsInfo->iv, iv, tlsInfo->ivSize );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, iv, ivSize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_IV );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Tell the caller how much data we've consumed */
	*ivLength = tlsInfo->ivSize;

	return( CRYPT_OK );
	}

/* The EAP protocols that use TLS derive additional keying data from the TLS 
   master secret.  The following function creates this subprotocol-specific 
   additional keying material and adds it as session attributes */

#ifdef USE_EAP

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int addDerivedKeydata( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					   IN_BUFFER( masterSecretSize ) void *masterSecret,
					   IN_LENGTH_SHORT_MIN( 16 ) const int masterSecretSize,
					   IN_ENUM( CRYPT_SUBPROTOCOL ) \
							const CRYPT_SUBPROTOCOL_TYPE type )
	{
	BYTE keyBuffer[ 128 + 8 ];
	const char *challengeDiversifier = NULL, *keyDiversifier;
	int challengeDiversifierLength DUMMY_INIT, keyDiversifierLength;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtrDynamic( masterSecret, masterSecretSize ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeMin( masterSecretSize, 16 ) );
	REQUIRES( isEnumRange( type, CRYPT_SUBPROTOCOL ) );

	/* Select the appripriate diversifier for the sub-protocol type */
	switch( type )
		{
		case CRYPT_SUBPROTOCOL_EAPTTLS:
			challengeDiversifier = "ttls challenge";
			challengeDiversifierLength = 14;
			keyDiversifier = "ttls keying material";
			keyDiversifierLength = 20;
			break;

#if 0
		case CRYPT_SUBPROTOCOL_EAPTLS:
			/* EAP-TLS also generates an IV using the same keyDiversifier 
			   but with an empty master secret value (so all of the 
			   randomness comes from the client and server random), this 
			   doesn't seem to be useful for anything and would require 
			   special-case handling for the empty master secret so we omit 
			   it.  It's OK to drop through to the internal-error return at 
			   the 'default' case since we should never be called for 
			   EAP-TLS */
			keyDiversifier = "client EAP encryption";
			keyDiversifierLength = 21;
			break;
#endif /* 0 */

		case CRYPT_SUBPROTOCOL_PEAP:
			/* This is only specified for PEAPv2 
			   (draft-josefsson-pppext-eap-tls-eap-10.txt page 24) which 
			   nothing uses but it's also used in the frankencrypto mechanism
			   in PEAPv0 that uses parts of PEAPv2 but mangled to make it 
			   look like it's meant for PEAPv0.  PEAPv2 specifies the 
			   mechanism in RFC 2716 (page 7):
		
				PRF( master secret, "client EAP encryption", 
					 client_hello.random || server_hello.random )
				
			   However this incorrectly specifies that 40 bytes of PRF output
			   are used when in practice it's 60 as specified in
			   https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-PEAP/41288c09-3d7d-482f-a57f-e83691d4d246 */
			keyDiversifier = "client EAP encryption";
			keyDiversifierLength = 21;
			break;

		default:
			retIntError();
		}

	/* Set up the EAP challenge and key values */
	if( challengeDiversifier != NULL )
		{
		BYTE challengeBuffer[ 32 + 8 ];

		status = masterToKeydata( sessionInfoPtr, handshakeInfo, 
								  masterSecret, masterSecretSize,
								  challengeDiversifier, 
								  challengeDiversifierLength,
								  challengeBuffer, 32 );
		if( cryptStatusOK( status ) )
			{
			DEBUG_DUMP_DATA_LABEL( "EAP challenge:", challengeBuffer, 32 );
			status = addSessionInfoS( sessionInfoPtr, 
									  CRYPT_SESSINFO_TLS_EAPCHALLENGE,
									  challengeBuffer, 32 );
			}
		zeroise( challengeBuffer, 32 );
		if( cryptStatusError( status ) )
			{
			retExt( status, 
					( status, SESSION_ERRINFO, 
					  "EAP challenge value initialistion failed" ) );
			}
		}
	status = masterToKeydata( sessionInfoPtr, handshakeInfo, 
							  masterSecret, masterSecretSize,
							  keyDiversifier, keyDiversifierLength,
							  keyBuffer, 128 );
	if( cryptStatusOK( status ) )
		{
		DEBUG_DUMP_DATA_LABEL( "EAP key:", keyBuffer, 128 );
		status = addSessionInfoS( sessionInfoPtr, 
								  CRYPT_SESSINFO_TLS_EAPKEY,
								  keyBuffer, 128 );
		}
	zeroise( keyBuffer, 128 );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "EAP keying value initialistion failed" ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_EAP */
#endif /* USE_TLS */
