<<<<<<< HEAD
/****************************************************************************
*																			*
*						cryptlib TLS Signing Routines						*
*					 Copyright Peter Gutmann 1998-2019						*
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
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check whether the certificate that we've been given by the client or 
   server is in a permitted-certificates whitelist.  This is a blocking 
   check in that it will only respond with an error if there's a whitelist 
   present and the certificate isn't in it.  If there's no whitelist present 
   then use of the certificate won't be blocked */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCertWhitelist( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
						IN_BOOL const BOOLEAN isServer )
	{
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	MESSAGE_DATA msgData;
	BYTE certID[ KEYID_SIZE + 8 ];
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isHandleRangeValid( iCryptCert ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* If there's no whitelist present then there's nothing to check 
	   against */
	if( sessionInfoPtr->cryptKeyset == CRYPT_ERROR ) 
		return( CRYPT_OK );

	/* Check whether the certificate is present in the keyset containing 
	   the certificate whitelist */
	setMessageData( &msgData, certID, KEYID_SIZE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusOK( status ) )
		{
		setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID, 
							   certID, KEYID_SIZE, NULL, 0, 
							   KEYMGMT_FLAG_CHECK_ONLY );
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset, 
								  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
								  KEYMGMT_ITEM_PUBLICKEY );
		}
	if( cryptStatusError( status ) )
		{
#ifdef USE_ERRMSGS
		char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
		char certIDText[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */

		formatHexData( certIDText, CRYPT_MAX_TEXTSIZE, certID, 
					   KEYID_SIZE );
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, SESSION_ERRINFO, 
				  "%s certificate for '%s' with ID '%s' isn't trusted "
				  "for authentication purposes", 
				  isServer ? "Client" : "Server", 
				  getCertHolderName( iCryptCert, certName, 
									 CRYPT_MAX_TEXTSIZE ), certIDText ) );
		}
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Client-Auth Signature Functions						*
*																			*
****************************************************************************/

/* Create/check the signature on a TLS certificate verify message.  
   SSLv3/TLS use a weird signature format that dual-MACs (SSLv3) or hashes 
   (TLS) all of the handshake messages exchanged to date (SSLv3 additionally 
   hashes in further data like the master secret), then signs them using 
   nonstandard PKCS #1 RSA without the ASN.1 wrapper (that is, it uses the 
   raw concatenated SHA-1 and MD5 MAC (SSL) or hash (TLS) of the handshake 
   messages with PKCS #1 padding prepended), unless we're using DSA in which 
   case it drops the MD5 MAC/hash and uses only the SHA-1 one.  
   
   This is an incredible pain to support because it requires running a 
   parallel hash of handshake messages that terminates before the main 
   hashing does, further hashing/MAC'ing of additional data, and the use of 
   weird nonstandard data formats and signature mechanisms that aren't 
   normally supported by anything.  For example if the signing is to be done 
   via a smart card then we can't use the standard PKCS #1 sig mechanism, we 
   can't even use raw RSA and kludge the format together ourselves because 
   some PKCS #11 implementations don't support the _X509 (raw) mechanism, 
   what we have to do is tunnel the nonstandard sig.format information down 
   through several cryptlib layers and then hope that the PKCS #11 
   implementation that we're using (a) supports this format and (b) gets it 
   right.
   
   Another problem (which fortunately only occurred for SSLv3) was that the 
   MAC required the use of the master secret, which wasn't available for 
   several hundred more lines of code, so we would have had to to delay 
   producing any more data packets until the master secret was available 
   (either that or squirrel all packets away in some buffer somewhere so 
   that they could be hashed later), which would have severely screwed up 
   the handshake processing flow.  
   
   TLS is slightly better here since it simply signs MD5-hash || SHA1-hash 
   without requiring the use of the master secret, but even then it requires 
   speculatively running an MD5 and SHA-1 hash of all messages on every 
   exchange on the remote chance that the client will be using client 
   certificates.  TLS 1.2 finally moved to using standard signatures (PKCS 
   #1 for RSA, conventional signatures for DSA/ECDSA), but still requires 
   the speculative hashing of handshake messages.

   The chances of all of this custom data and signature handling working 
   correctly are fairly low, and in any case there's no advantage to the 
   weird mechanism and format used in TLS, all that we actually need to do 
   is sign the client and server nonces to ensure signature freshness.  
   Because of this what we actually do is just this, after which we create a 
   standard PKCS #1 signature via the normal cryptlib mechanisms, which 
   guarantees that it'll work with native cryptlib as well as any crypto 
   hardware implementation.  Since client certificates are hardly ever used 
   and when they are it's in a closed environment, it's extremely unlikely 
   that anyone will ever notice.  There'll be far more problems in trying to 
   use the nonstandard TLS signature mechanism than there are with using a 
   standard (but not-in-the-spec) one.
   
   The one exception to this is, as already mentioned above, TLS 1.2+, for
   which we can finally use a standard signature.  In this case we take
   a clone of the SHA-2 context that's been used to hash the handshake
   messages so far (the use of SHA-2 for this is enforced by the judicious
   use of TLS extensions, see the comments in tls_ext.c for more on this)
   and sign that */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createCertVerifyAltHash( const TLS_HANDSHAKE_INFO *handshakeInfo,
									OUT_HANDLE_OPT CRYPT_CONTEXT *iHashContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ 64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE + 8 ];
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( iHashContext, sizeof( CRYPT_CONTEXT ) ) );

	/* Clear return value */
	*iHashContext = CRYPT_ERROR;

	/* Hash the client and server nonces */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA1 );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( boundsCheck( 18, TLS_NONCE_SIZE + TLS_NONCE_SIZE, 
						   64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE ) );
	memcpy( nonceBuffer, "certificate verify", 18 );
	memcpy( nonceBuffer + 18, handshakeInfo->clientNonce, TLS_NONCE_SIZE );
	memcpy( nonceBuffer + 18 + TLS_NONCE_SIZE, handshakeInfo->serverNonce,
			TLS_NONCE_SIZE );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
							  nonceBuffer, 
							  18 + TLS_NONCE_SIZE + TLS_NONCE_SIZE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_CTX_HASH, nonceBuffer, 0 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iHashContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
static int getSessionHash( IN_HANDLE const CRYPT_CONTEXT iHashContext,
						   OUT_BUFFER( hashValueMaxLen, *hashValueLen ) \
								void *hashValue,
						   IN_LENGTH_HASH const int hashValueMaxLen,
						   OUT_LENGTH_HASH_Z int *hashValueLen )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtrDynamic( hashValue, hashValueMaxLen ) );
	assert( isWritePtr( hashValueLen, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( hashValueMaxLen >= MIN_HASHSIZE && \
			  hashValueMaxLen <= CRYPT_MAX_HASHSIZE );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( hashValueMaxLen ) ); 
	memset( hashValue, 0, min( 16, hashValueMaxLen ) );
	*hashValueLen = 0;

	/* Wrap up the hashing and record the hash value */
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, hashValue, hashValueMaxLen );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	*hashValueLen = msgData.length;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int createSessionHash( IN_PTR const SESSION_INFO *sessionInfoPtr,
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	CRYPT_CONTEXT iHashContext;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Clone the current hash state, complete the hashing for the cloned 
	   context(s), and get the hash value(s) */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		int hash1Size, hash2Size;

		/* TLS < 1.2 uses an MD5/SHA1 dual hash so we have to extract both 
		   hash values and concatenate them */
		status = cloneHashContext( handshakeInfo->md5context, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );
		status = getSessionHash( iHashContext, handshakeInfo->sessionHash,
								 CRYPT_MAX_HASHSIZE, &hash1Size );
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		status = cloneHashContext( handshakeInfo->sha1context, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );
		status = getSessionHash( iHashContext, 
								 handshakeInfo->sessionHash + hash1Size,
								 CRYPT_MAX_HASHSIZE - hash1Size, &hash2Size );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		handshakeInfo->sessionHashSize = hash1Size + hash2Size;
		}
	else
		{
		/* TLS 1.2 uses a single hash value */
		if( handshakeInfo->sha2context != CRYPT_ERROR )
			status = cloneHashContext( handshakeInfo->sha2context, &iHashContext );
		else
			status = cloneHashContext( handshakeInfo->sha1context, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );
		status = getSessionHash( iHashContext, handshakeInfo->sessionHash,
								 CRYPT_MAX_HASHSIZE, 
								 &handshakeInfo->sessionHashSize );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}
	handshakeInfo->sessionHashContext = iHashContext;

	DEBUG_DUMP_DATA_LABEL( isServer( sessionInfoPtr ) ? \
								"Session hash (server):" : \
								"Session hash (client):",
						   handshakeInfo->sessionHash, 
						   handshakeInfo->sessionHashSize );

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroySessionHash( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	if( handshakeInfo->sessionHashContext != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->sessionHashContext, 
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->sessionHashContext = CRYPT_ERROR;
		}
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int createCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					  INOUT_PTR STREAM *stream )
	{
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *dataPtr;
	int dataLength, length DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Get a pointer to the signature data block */
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the signature.  The reason for the min() part of the
	   expression is that iCryptCreateSignature() gets suspicious of very
	   large buffer sizes, for example when the user has specified the use
	   of a huge send buffer */
	clearErrorInfo( &localErrorInfo );
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		CRYPT_CONTEXT iHashContext;

		/* Create the hash of the data to sign if necessary */
		status = createCertVerifyAltHash( handshakeInfo, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );

		/* See the note above about the complexities of handling the ever-
		   changing pre-TLS 1.2 signature format and why we therefore use
		   CRYPT_FORMAT_CRYPTLIB for the signature */
		status = iCryptCreateSignature( dataPtr, 
					min( dataLength, MAX_INTLENGTH_SHORT - 1 ), &length, 
					CRYPT_FORMAT_CRYPTLIB, sessionInfoPtr->privateKey, 
					iHashContext, NULL, &localErrorInfo );
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		}
	else
		{
		status = iCryptCreateSignature( dataPtr, 
					min( dataLength, MAX_INTLENGTH_SHORT - 1 ), &length,
					( sessionInfoPtr->version > TLS_MINOR_VERSION_TLS12 ) ? \
					  CRYPT_IFORMAT_TLS13 : CRYPT_IFORMAT_TLS12, 
					sessionInfoPtr->privateKey, 
					handshakeInfo->sessionHashContext, NULL, 
					&localErrorInfo );
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
				     "Couldn't sign certificate-verify message with key "
					 "for '%s'",
					 getCertHolderName( sessionInfoPtr->privateKey, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}

	return( sSkip( stream, length, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					 INOUT_PTR STREAM *stream, 
					 IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
						const int sigLength )
	{
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *dataPtr;
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeMin( sigLength, MIN_CRYPT_OBJECTSIZE ) );

	/* Get a pointer to the signature data block */
	status = sMemGetDataBlock( stream, &dataPtr, sigLength );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( dataPtr != NULL );

	/* Verify the signature.  The reason for the min() part of the
	   expression is that iCryptCheckSignature() gets suspicious of very
	   large buffer sizes, for example when the user has specified the use
	   of a huge send buffer */
	clearErrorInfo( &localErrorInfo );
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		CRYPT_CONTEXT iHashContext;

		/* See the note above about the complexities of handling the ever-
		   changing pre-TLS 1.2 signature format and why we therefore use
		   CRYPT_FORMAT_CRYPTLIB for the signature.  
		   
		   To catch any use of one of these formats, we check for a non-
		   cryptlib signature being passed to us by checking for the absence 
		   of an ASN.1 SEQUENCE tag and report it as a signature-
		   verification failure.
		   
		   In theory if there's ever any demand for support for this, we
		   could take advantage of the fact that the signature can really
		   only be RSA (DSA is gone and ECC is TLS 1.2-only) and perform a
		   raw RSA public-key operation on the signature data, extract the
		   lowest 20 bytes (the SHA-1 portion), and compare it with the hash 
		   data */
		if( *( ( BYTE * ) dataPtr ) != 0x30 )
			{
			assert( DEBUG_WARN );
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					  "Couldn't verify old-style (pre-TLS 1.2) client "
					  "certificate-verify message" ) );
			}

		/* Create the hash of the data to verify if necessary */
		status = createCertVerifyAltHash( handshakeInfo, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );

		status = iCryptCheckSignature( dataPtr, 
						min( sigLength, MAX_INTLENGTH_SHORT - 1 ), 
						CRYPT_FORMAT_CRYPTLIB, sessionInfoPtr->iKeyexAuthContext, 
						iHashContext, CRYPT_UNUSED, NULL, &localErrorInfo );
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		}
	else
		{
		status = iCryptCheckSignature( dataPtr, 
						min( sigLength, MAX_INTLENGTH_SHORT - 1 ), 
						CRYPT_IFORMAT_TLS12, sessionInfoPtr->iKeyexAuthContext, 
						handshakeInfo->sessionHashContext, CRYPT_UNUSED, NULL,
						&localErrorInfo );
#ifdef CONFIG_SUITEB_TESTS 
		if( cryptStatusOK( status ) )
			{
			int sigKeySize;

			status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
									  IMESSAGE_GETATTRIBUTE, &sigKeySize, 
									  CRYPT_CTXINFO_KEYSIZE );
			if( cryptStatusOK( status ) )
				{
				DEBUG_PRINT(( "Verified client's P%d authentication.\n", 
							  bytesToBits( sigKeySize ) ));
				}
			}
#endif /* CONFIG_SUITEB_TESTS */
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Verification of certificate-verify message with "
					 "public key for '%s' failed",
					 getCertHolderName( sessionInfoPtr->iKeyexAuthContext, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Keyex Signature Functions							*
*																			*
****************************************************************************/

/* Create/check the signature on the server key data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
static int createKeyexHash( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							OUT_HANDLE_OPT CRYPT_CONTEXT *hashContext,
							IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							IN_LENGTH_HASH_Z const int hashParam,
							IN_BUFFER( keyDataLength ) const void *keyData, 
							IN_LENGTH_SHORT const int keyDataLength,
							IN_BOOL const BOOLEAN hashTLSLTS )
	{
	CRYPT_CONTEXT iHashContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( hashContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isReadPtrDynamic( keyData, keyDataLength ) );

	REQUIRES( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			  hashAlgo <= CRYPT_ALGO_LAST_HASH );
	REQUIRES( hashParam == 0 || \
			  ( hashParam >= MIN_HASHSIZE && \
				hashParam <= CRYPT_MAX_HASHSIZE ) );
	REQUIRES( isShortIntegerRangeNZ( keyDataLength ) );
	REQUIRES( isBooleanValue( hashTLSLTS ) );

	/* Clear return value */
	*hashContext = CRYPT_ERROR;

	/* Create the hash context */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iHashContext = createInfo.cryptHandle;
	if( hashParam != 0 )
		{
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &hashParam,
								  CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	/* Hash the client and server hello or nonces, and key data */
	if( hashTLSLTS )
		{
		/* TLS-LTS hashes the full client and server hello at the time 
		   they're sent, and then hashes that into the keyex hash rather 
		   than just the nonces, which protects against various manipulation
		   attacks on TLS */
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  handshakeInfo->helloHash, 
								  handshakeInfo->helloHashSize );
		}
	else
		{
		BYTE nonceBuffer[ TLS_NONCE_SIZE + TLS_NONCE_SIZE + 8 ];

		memcpy( nonceBuffer, handshakeInfo->clientNonce, TLS_NONCE_SIZE );
		memcpy( nonceBuffer + TLS_NONCE_SIZE, handshakeInfo->serverNonce,
				TLS_NONCE_SIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  nonceBuffer, 
								  TLS_NONCE_SIZE + TLS_NONCE_SIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) keyData, keyDataLength );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	*hashContext = iHashContext;
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int createKeyexSignature( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  INOUT_PTR STREAM *stream, 
						  IN_BUFFER( keyDataLength ) const void *keyData, 
						  IN_LENGTH_SHORT const int keyDataLength )
	{
	CRYPT_CONTEXT md5Context DUMMY_INIT, shaContext;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *dataPtr;
	int dataLength, sigLength DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( keyData, keyDataLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeNZ( keyDataLength ) );

	/* Hash the data to be signed */
	status = createKeyexHash( handshakeInfo, &shaContext, 
				( handshakeInfo->keyexSigHashAlgo != CRYPT_ALGO_NONE ) ? \
					handshakeInfo->keyexSigHashAlgo : CRYPT_ALGO_SHA1,
				handshakeInfo->keyexSigHashAlgoParam, keyData, keyDataLength,
				TEST_FLAG( sessionInfoPtr->protocolFlags, 
						   TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO,
				  "Couldn't create keyex hash" ) );
		}
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = createKeyexHash( handshakeInfo, &md5Context, 
								  CRYPT_ALGO_MD5, 0, keyData, keyDataLength, 
								  FALSE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
			retExt( status,
					( status, SESSION_ERRINFO,
					  "Couldn't create keyex hash" ) );
			}
		}
	INJECT_FAULT( BADSIG_HASH, SESSION_BADSIG_HASH_TLS_1 );

	/* Sign the hashes.  The reason for the min() part of the expression is
	   that iCryptCreateSignature() gets suspicious of very large buffer
	   sizes, for example when the user has specified the use of a huge send
	   buffer */
	clearErrorInfo( &localErrorInfo );
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusOK( status ) )
		{
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
			{
			status = iCryptCreateSignature( dataPtr, 
											min( dataLength, \
												 MAX_INTLENGTH_SHORT - 1 ), 
											&sigLength, CRYPT_IFORMAT_TLS12, 
											sessionInfoPtr->privateKey,
											shaContext, NULL, 
											&localErrorInfo );
			}
		else
			{
			SIGPARAMS sigParams;

			initSigParams( &sigParams );
			sigParams.iSecondHash = shaContext;
			status = iCryptCreateSignature( dataPtr, 
											min( dataLength, \
												 MAX_INTLENGTH_SHORT - 1 ), 
											&sigLength, CRYPT_IFORMAT_TLS, 
											sessionInfoPtr->privateKey,
											md5Context, &sigParams,
											&localErrorInfo );
			}
		}
	insertCryptoDelay();
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
				     "Couldn't sign keyex packet with key for '%s'",
					 getCertHolderName( sessionInfoPtr->privateKey, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	INJECT_FAULT( BADSIG_SIG, SESSION_BADSIG_SIG_TLS_1 );

	return( sSkip( stream, sigLength, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 7 ) ) \
int checkKeyexSignature( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 INOUT_PTR STREAM *stream, 
						 IN_BUFFER( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT const int keyDataLength,
						 IN_BOOL const BOOLEAN isECC,
						 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT md5Context DUMMY_INIT, shaContext;
	CRYPT_ALGO_TYPE hashAlgo = CRYPT_ALGO_SHA1;
	void *dataPtr;
	int dataLength, keyexKeySize, sigKeySize DUMMY_INIT, hashParam = 0;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( keyData, keyDataLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeNZ( keyDataLength ) );
	REQUIRES( isBooleanValue( isECC ) );

	/* Make sure that there's enough data present for at least a minimal-
	   length signature and get a pointer to the signature data */
	if( sMemDataLeft( stream ) < ( isECC ? \
								   MIN_PKCSIZE_ECCPOINT : MIN_PKCSIZE ) )
		return( CRYPT_ERROR_BADDATA );
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( dataPtr != NULL );

	/* TLS 1.2+ precedes the signature itself with an indication of the hash
	   and signature algorithm that's required to verify it, so if we're 
	   using this format then we have to process the identifiers before we
	   can create the signature-verification hashes.

	   We disallow SHA1 since the whole point of TLS 1.2 was to move away 
	   from it, and a poll on the ietf-tls list indicated that all known 
	   implementations at the time (both of them) work fine with this 
	   configuration */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		static const MAP_TABLE hashAlgoIDTbl[] = {
			{ 1000, CRYPT_ALGO_SHAng },
#ifdef USE_SHA2_EXT
			{ TLS_HASHALGO_SHA512, CRYPT_ALGO_SHA2 },
			{ TLS_HASHALGO_SHA384, CRYPT_ALGO_SHA2 },
#endif /* USE_SHA2_EXT */
			{ TLS_HASHALGO_SHA2, CRYPT_ALGO_SHA2 },
#if 0	/* 2/11/11 Disabled option for SHA1 after poll on ietf-tls list */
			{ TLS_HASHALGO_SHA1, CRYPT_ALGO_SHA1 },
#endif /* 0 */
			{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
			};
		static const MAP_TABLE hashParamTbl[] = {
#ifdef USE_SHA2_EXT
			{ TLS_HASHALGO_SHA512, bitsToBytes( 512 ) },
			{ TLS_HASHALGO_SHA384, bitsToBytes( 384 ) },
#endif /* USE_SHA2_EXT */
			{ TLS_HASHALGO_SHA2, bitsToBytes( 256 ) },
			{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
			};
		int cryptHashAlgo, tlsHashAlgo;

		/* Get the hash algorithm that we need to use.  We don't care about
		   the signature algorithm since we've already been given the public
		   key for it */
		status = tlsHashAlgo = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		( void ) sgetc( stream );
		if( !isEnumRange( tlsHashAlgo, TLS_HASHALGO ) )
			return( CRYPT_ERROR_NOTAVAIL ); 
		status = mapValue( tlsHashAlgo, &cryptHashAlgo, hashAlgoIDTbl, 
						   FAILSAFE_ARRAYSIZE( hashAlgoIDTbl, MAP_TABLE ) );
		if( cryptStatusOK( status ) && \
			isParameterisedHashAlgo( cryptHashAlgo ) )
			{
			status = mapValue( tlsHashAlgo, &hashParam, hashParamTbl, 
							   FAILSAFE_ARRAYSIZE( hashParamTbl, \
												   MAP_TABLE ) );
			}
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_NOTAVAIL,
					( CRYPT_ERROR_NOTAVAIL, errorInfo,
					  "Unknown TLS hash algorithm %d", tlsHashAlgo ) );
			}
		hashAlgo = cryptHashAlgo;	/* int vs.enum */
		}

	/* Hash the data to be signed */
	status = createKeyexHash( handshakeInfo, &shaContext, hashAlgo, 
							  hashParam, keyData, keyDataLength,
							  TEST_FLAG( sessionInfoPtr->protocolFlags,
										 TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Couldn't create %s keyex hash", 
				  getAlgoNameEx( hashAlgo, hashParam ) ) );
		}
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = createKeyexHash( handshakeInfo, &md5Context, 
								  CRYPT_ALGO_MD5, 0, keyData, keyDataLength,
								  FALSE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	/* Check the signature on the hashes.  The reason for the min() part of
	   the expression is that iCryptCheckSignature() gets suspicious of
	   very large buffer sizes, for example when the user has specified the
	   use of a huge send buffer */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		status = iCryptCheckSignature( dataPtr, 
								min( dataLength, MAX_INTLENGTH_SHORT - 1 ),
								CRYPT_IFORMAT_TLS12, 
								sessionInfoPtr->iKeyexAuthContext, 
								shaContext, CRYPT_UNUSED, NULL,
								errorInfo );
		}
	else
		{
		status = iCryptCheckSignature( dataPtr, 
								min( dataLength, MAX_INTLENGTH_SHORT - 1 ),
								CRYPT_IFORMAT_TLS, 
								sessionInfoPtr->iKeyexAuthContext, 
								md5Context, shaContext, NULL,
								errorInfo );
		}
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the relative strengths of the keyex and signature keys 
	   match.  This is just a general precaution for RSA/DSA, but is 
	   mandated for ECC with Suite B in order to make the appropriate 
	   fashion statement (see the comment below).  When performing the check 
	   we allow a small amount of wiggle room to deal with keygen 
	   differences */
	status = krnlSendMessage( handshakeInfo->dhContext, 
							  IMESSAGE_GETATTRIBUTE, &keyexKeySize, 
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext,
								  IMESSAGE_GETATTRIBUTE, &sigKeySize, 
								  CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( isECC )
		{
		/* For ECC with Suite B the signature key size has to match the 
		   keyex key size otherwise fashion dictums are violated (if you 
		   could just sign size n with size n+1 then you wouldn't need 
		   hashsize n/n+1 and keysize n/n+1 and whatnot) */
		if( sigKeySize < keyexKeySize - bitsToBytes( 8 ) )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, errorInfo,
					  "Server used P%d keyex but only P%d signature",
					  bytesToBits( keyexKeySize ), 
					  bytesToBits( sigKeySize ) ) );
			}
#ifdef CONFIG_SUITEB
		if( ( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB ) && \
			sigKeySize > keyexKeySize + bitsToBytes( 8 ) )
			return( CRYPT_ERROR_NOSECURE );
  #ifdef CONFIG_SUITEB_TESTS 
		DEBUG_PRINT(( "Verified server's P%d keyex with P%d signature.\n", 
					  bytesToBits( keyexKeySize ), 
					  bytesToBits( sigKeySize ) ));
  #endif /* CONFIG_SUITEB_TESTS */
#endif /* CONFIG_SUITEB */
		}
	else
		{
#if 1
		/* For conventional keyex/signatures things get a bit complicated,
		   using (say) a 1024-bit key to sign a 1536-bit keyex seems like a
		   mismatch, but then the 1024-bit key may be regenerated relatively
		   frequently while the 1536-bit DH parameters may be static and
		   shared with everyone else on earth, making the high-value 1536-
		   bit key a more viable target for attack than the singleton 1024-
		   bit one.  Because of this we allow a difference of up to 512 bits
		   between the signing key and the keyex key */
		if( sigKeySize < keyexKeySize - bitsToBytes( 512 + 32 ) )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, errorInfo,
					  "Server used %d-bit keyex but only %d-bit signature",
					  bytesToBits( keyexKeySize ), 
					  bytesToBits( sigKeySize ) ) );
			}
#else
		/* For conventional keyex/signatures the bounds are a bit looser 
		   because non-ECC keygen mechanisms can result in a wider variation 
		   of actual vs. nominal key size */
		if( sigKeySize < keyexKeySize - bitsToBytes( 32 ) )
			return( CRYPT_ERROR_NOSECURE );
#endif /* 0 */
		}

	/* Skip the signature data */
	return( readUniversal16( stream ) );
	}
#endif /* USE_TLS */
=======
/****************************************************************************
*																			*
*						cryptlib TLS Signing Routines						*
*					 Copyright Peter Gutmann 1998-2019						*
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
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check whether the certificate that we've been given by the client or 
   server is in a permitted-certificates whitelist.  This is a blocking 
   check in that it will only respond with an error if there's a whitelist 
   present and the certificate isn't in it.  If there's no whitelist present 
   then use of the certificate won't be blocked */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCertWhitelist( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
						IN_BOOL const BOOLEAN isServer )
	{
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	MESSAGE_DATA msgData;
	BYTE certID[ KEYID_SIZE + 8 ];
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isHandleRangeValid( iCryptCert ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* If there's no whitelist present then there's nothing to check 
	   against */
	if( sessionInfoPtr->cryptKeyset == CRYPT_ERROR ) 
		return( CRYPT_OK );

	/* Check whether the certificate is present in the keyset containing 
	   the certificate whitelist */
	setMessageData( &msgData, certID, KEYID_SIZE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusOK( status ) )
		{
		setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID, 
							   certID, KEYID_SIZE, NULL, 0, 
							   KEYMGMT_FLAG_CHECK_ONLY );
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset, 
								  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
								  KEYMGMT_ITEM_PUBLICKEY );
		}
	if( cryptStatusError( status ) )
		{
#ifdef USE_ERRMSGS
		char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
		char certIDText[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */

		formatHexData( certIDText, CRYPT_MAX_TEXTSIZE, certID, 
					   KEYID_SIZE );
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, SESSION_ERRINFO, 
				  "%s certificate for '%s' with ID '%s' isn't trusted "
				  "for authentication purposes", 
				  isServer ? "Client" : "Server", 
				  getCertHolderName( iCryptCert, certName, 
									 CRYPT_MAX_TEXTSIZE ), certIDText ) );
		}
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Client-Auth Signature Functions						*
*																			*
****************************************************************************/

/* Create/check the signature on a TLS certificate verify message.  
   SSLv3/TLS use a weird signature format that dual-MACs (SSLv3) or hashes 
   (TLS) all of the handshake messages exchanged to date (SSLv3 additionally 
   hashes in further data like the master secret), then signs them using 
   nonstandard PKCS #1 RSA without the ASN.1 wrapper (that is, it uses the 
   raw concatenated SHA-1 and MD5 MAC (SSL) or hash (TLS) of the handshake 
   messages with PKCS #1 padding prepended), unless we're using DSA in which 
   case it drops the MD5 MAC/hash and uses only the SHA-1 one.  
   
   This is an incredible pain to support because it requires running a 
   parallel hash of handshake messages that terminates before the main 
   hashing does, further hashing/MAC'ing of additional data, and the use of 
   weird nonstandard data formats and signature mechanisms that aren't 
   normally supported by anything.  For example if the signing is to be done 
   via a smart card then we can't use the standard PKCS #1 sig mechanism, we 
   can't even use raw RSA and kludge the format together ourselves because 
   some PKCS #11 implementations don't support the _X509 (raw) mechanism, 
   what we have to do is tunnel the nonstandard sig.format information down 
   through several cryptlib layers and then hope that the PKCS #11 
   implementation that we're using (a) supports this format and (b) gets it 
   right.
   
   Another problem (which fortunately only occurred for SSLv3) was that the 
   MAC required the use of the master secret, which wasn't available for 
   several hundred more lines of code, so we would have had to to delay 
   producing any more data packets until the master secret was available 
   (either that or squirrel all packets away in some buffer somewhere so 
   that they could be hashed later), which would have severely screwed up 
   the handshake processing flow.  
   
   TLS is slightly better here since it simply signs MD5-hash || SHA1-hash 
   without requiring the use of the master secret, but even then it requires 
   speculatively running an MD5 and SHA-1 hash of all messages on every 
   exchange on the remote chance that the client will be using client 
   certificates.  TLS 1.2 finally moved to using standard signatures (PKCS 
   #1 for RSA, conventional signatures for DSA/ECDSA), but still requires 
   the speculative hashing of handshake messages.

   The chances of all of this custom data and signature handling working 
   correctly are fairly low, and in any case there's no advantage to the 
   weird mechanism and format used in TLS, all that we actually need to do 
   is sign the client and server nonces to ensure signature freshness.  
   Because of this what we actually do is just this, after which we create a 
   standard PKCS #1 signature via the normal cryptlib mechanisms, which 
   guarantees that it'll work with native cryptlib as well as any crypto 
   hardware implementation.  Since client certificates are hardly ever used 
   and when they are it's in a closed environment, it's extremely unlikely 
   that anyone will ever notice.  There'll be far more problems in trying to 
   use the nonstandard TLS signature mechanism than there are with using a 
   standard (but not-in-the-spec) one.
   
   The one exception to this is, as already mentioned above, TLS 1.2+, for
   which we can finally use a standard signature.  In this case we take
   a clone of the SHA-2 context that's been used to hash the handshake
   messages so far (the use of SHA-2 for this is enforced by the judicious
   use of TLS extensions, see the comments in tls_ext.c for more on this)
   and sign that */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createCertVerifyAltHash( const TLS_HANDSHAKE_INFO *handshakeInfo,
									OUT_HANDLE_OPT CRYPT_CONTEXT *iHashContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ 64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE + 8 ];
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( iHashContext, sizeof( CRYPT_CONTEXT ) ) );

	/* Clear return value */
	*iHashContext = CRYPT_ERROR;

	/* Hash the client and server nonces */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA1 );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( boundsCheck( 18, TLS_NONCE_SIZE + TLS_NONCE_SIZE, 
						   64 + TLS_NONCE_SIZE + TLS_NONCE_SIZE ) );
	memcpy( nonceBuffer, "certificate verify", 18 );
	memcpy( nonceBuffer + 18, handshakeInfo->clientNonce, TLS_NONCE_SIZE );
	memcpy( nonceBuffer + 18 + TLS_NONCE_SIZE, handshakeInfo->serverNonce,
			TLS_NONCE_SIZE );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
							  nonceBuffer, 
							  18 + TLS_NONCE_SIZE + TLS_NONCE_SIZE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_CTX_HASH, nonceBuffer, 0 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iHashContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
static int getSessionHash( IN_HANDLE const CRYPT_CONTEXT iHashContext,
						   OUT_BUFFER( hashValueMaxLen, *hashValueLen ) \
								void *hashValue,
						   IN_LENGTH_HASH const int hashValueMaxLen,
						   OUT_LENGTH_HASH_Z int *hashValueLen )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtrDynamic( hashValue, hashValueMaxLen ) );
	assert( isWritePtr( hashValueLen, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( hashValueMaxLen >= MIN_HASHSIZE && \
			  hashValueMaxLen <= CRYPT_MAX_HASHSIZE );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( hashValueMaxLen ) ); 
	memset( hashValue, 0, min( 16, hashValueMaxLen ) );
	*hashValueLen = 0;

	/* Wrap up the hashing and record the hash value */
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, hashValue, hashValueMaxLen );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	*hashValueLen = msgData.length;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int createSessionHash( IN_PTR const SESSION_INFO *sessionInfoPtr,
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	CRYPT_CONTEXT iHashContext;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Clone the current hash state, complete the hashing for the cloned 
	   context(s), and get the hash value(s) */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		int hash1Size, hash2Size;

		/* TLS < 1.2 uses an MD5/SHA1 dual hash so we have to extract both 
		   hash values and concatenate them */
		status = cloneHashContext( handshakeInfo->md5context, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );
		status = getSessionHash( iHashContext, handshakeInfo->sessionHash,
								 CRYPT_MAX_HASHSIZE, &hash1Size );
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		status = cloneHashContext( handshakeInfo->sha1context, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );
		status = getSessionHash( iHashContext, 
								 handshakeInfo->sessionHash + hash1Size,
								 CRYPT_MAX_HASHSIZE - hash1Size, &hash2Size );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		handshakeInfo->sessionHashSize = hash1Size + hash2Size;
		}
	else
		{
		/* TLS 1.2 uses a single hash value */
		if( handshakeInfo->sha2context != CRYPT_ERROR )
			status = cloneHashContext( handshakeInfo->sha2context, &iHashContext );
		else
			status = cloneHashContext( handshakeInfo->sha1context, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );
		status = getSessionHash( iHashContext, handshakeInfo->sessionHash,
								 CRYPT_MAX_HASHSIZE, 
								 &handshakeInfo->sessionHashSize );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}
	handshakeInfo->sessionHashContext = iHashContext;

	DEBUG_DUMP_DATA_LABEL( isServer( sessionInfoPtr ) ? \
								"Session hash (server):" : \
								"Session hash (client):",
						   handshakeInfo->sessionHash, 
						   handshakeInfo->sessionHashSize );

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroySessionHash( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	if( handshakeInfo->sessionHashContext != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->sessionHashContext, 
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->sessionHashContext = CRYPT_ERROR;
		}
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int createCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					  INOUT_PTR STREAM *stream )
	{
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *dataPtr;
	int dataLength, length DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Get a pointer to the signature data block */
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the signature.  The reason for the min() part of the
	   expression is that iCryptCreateSignature() gets suspicious of very
	   large buffer sizes, for example when the user has specified the use
	   of a huge send buffer */
	clearErrorInfo( &localErrorInfo );
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		CRYPT_CONTEXT iHashContext;

		/* Create the hash of the data to sign if necessary */
		status = createCertVerifyAltHash( handshakeInfo, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );

		/* See the note above about the complexities of handling the ever-
		   changing pre-TLS 1.2 signature format and why we therefore use
		   CRYPT_FORMAT_CRYPTLIB for the signature */
		status = iCryptCreateSignature( dataPtr, 
					min( dataLength, MAX_INTLENGTH_SHORT - 1 ), &length, 
					CRYPT_FORMAT_CRYPTLIB, sessionInfoPtr->privateKey, 
					iHashContext, NULL, &localErrorInfo );
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		}
	else
		{
		status = iCryptCreateSignature( dataPtr, 
					min( dataLength, MAX_INTLENGTH_SHORT - 1 ), &length,
					( sessionInfoPtr->version > TLS_MINOR_VERSION_TLS12 ) ? \
					  CRYPT_IFORMAT_TLS13 : CRYPT_IFORMAT_TLS12, 
					sessionInfoPtr->privateKey, 
					handshakeInfo->sessionHashContext, NULL, 
					&localErrorInfo );
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
				     "Couldn't sign certificate-verify message with key "
					 "for '%s'",
					 getCertHolderName( sessionInfoPtr->privateKey, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}

	return( sSkip( stream, length, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					 INOUT_PTR STREAM *stream, 
					 IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
						const int sigLength )
	{
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *dataPtr;
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeMin( sigLength, MIN_CRYPT_OBJECTSIZE ) );

	/* Get a pointer to the signature data block */
	status = sMemGetDataBlock( stream, &dataPtr, sigLength );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( dataPtr != NULL );

	/* Verify the signature.  The reason for the min() part of the
	   expression is that iCryptCheckSignature() gets suspicious of very
	   large buffer sizes, for example when the user has specified the use
	   of a huge send buffer */
	clearErrorInfo( &localErrorInfo );
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		CRYPT_CONTEXT iHashContext;

		/* See the note above about the complexities of handling the ever-
		   changing pre-TLS 1.2 signature format and why we therefore use
		   CRYPT_FORMAT_CRYPTLIB for the signature.  
		   
		   To catch any use of one of these formats, we check for a non-
		   cryptlib signature being passed to us by checking for the absence 
		   of an ASN.1 SEQUENCE tag and report it as a signature-
		   verification failure.
		   
		   In theory if there's ever any demand for support for this, we
		   could take advantage of the fact that the signature can really
		   only be RSA (DSA is gone and ECC is TLS 1.2-only) and perform a
		   raw RSA public-key operation on the signature data, extract the
		   lowest 20 bytes (the SHA-1 portion), and compare it with the hash 
		   data */
		if( *( ( BYTE * ) dataPtr ) != 0x30 )
			{
			assert( DEBUG_WARN );
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					  "Couldn't verify old-style (pre-TLS 1.2) client "
					  "certificate-verify message" ) );
			}

		/* Create the hash of the data to verify if necessary */
		status = createCertVerifyAltHash( handshakeInfo, &iHashContext );
		if( cryptStatusError( status ) )
			return( status );

		status = iCryptCheckSignature( dataPtr, 
						min( sigLength, MAX_INTLENGTH_SHORT - 1 ), 
						CRYPT_FORMAT_CRYPTLIB, sessionInfoPtr->iKeyexAuthContext, 
						iHashContext, CRYPT_UNUSED, NULL, &localErrorInfo );
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		}
	else
		{
		status = iCryptCheckSignature( dataPtr, 
						min( sigLength, MAX_INTLENGTH_SHORT - 1 ), 
						CRYPT_IFORMAT_TLS12, sessionInfoPtr->iKeyexAuthContext, 
						handshakeInfo->sessionHashContext, CRYPT_UNUSED, NULL,
						&localErrorInfo );
#ifdef CONFIG_SUITEB_TESTS 
		if( cryptStatusOK( status ) )
			{
			int sigKeySize;

			status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
									  IMESSAGE_GETATTRIBUTE, &sigKeySize, 
									  CRYPT_CTXINFO_KEYSIZE );
			if( cryptStatusOK( status ) )
				{
				DEBUG_PRINT(( "Verified client's P%d authentication.\n", 
							  bytesToBits( sigKeySize ) ));
				}
			}
#endif /* CONFIG_SUITEB_TESTS */
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Verification of certificate-verify message with "
					 "public key for '%s' failed",
					 getCertHolderName( sessionInfoPtr->iKeyexAuthContext, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Keyex Signature Functions							*
*																			*
****************************************************************************/

/* Create/check the signature on the server key data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
static int createKeyexHash( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							OUT_HANDLE_OPT CRYPT_CONTEXT *hashContext,
							IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							IN_LENGTH_HASH_Z const int hashParam,
							IN_BUFFER( keyDataLength ) const void *keyData, 
							IN_LENGTH_SHORT const int keyDataLength,
							IN_BOOL const BOOLEAN hashTLSLTS )
	{
	CRYPT_CONTEXT iHashContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( hashContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isReadPtrDynamic( keyData, keyDataLength ) );

	REQUIRES( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			  hashAlgo <= CRYPT_ALGO_LAST_HASH );
	REQUIRES( hashParam == 0 || \
			  ( hashParam >= MIN_HASHSIZE && \
				hashParam <= CRYPT_MAX_HASHSIZE ) );
	REQUIRES( isShortIntegerRangeNZ( keyDataLength ) );
	REQUIRES( isBooleanValue( hashTLSLTS ) );

	/* Clear return value */
	*hashContext = CRYPT_ERROR;

	/* Create the hash context */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iHashContext = createInfo.cryptHandle;
	if( hashParam != 0 )
		{
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &hashParam,
								  CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	/* Hash the client and server hello or nonces, and key data */
	if( hashTLSLTS )
		{
		/* TLS-LTS hashes the full client and server hello at the time 
		   they're sent, and then hashes that into the keyex hash rather 
		   than just the nonces, which protects against various manipulation
		   attacks on TLS */
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  handshakeInfo->helloHash, 
								  handshakeInfo->helloHashSize );
		}
	else
		{
		BYTE nonceBuffer[ TLS_NONCE_SIZE + TLS_NONCE_SIZE + 8 ];

		memcpy( nonceBuffer, handshakeInfo->clientNonce, TLS_NONCE_SIZE );
		memcpy( nonceBuffer + TLS_NONCE_SIZE, handshakeInfo->serverNonce,
				TLS_NONCE_SIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  nonceBuffer, 
								  TLS_NONCE_SIZE + TLS_NONCE_SIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) keyData, keyDataLength );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	*hashContext = iHashContext;
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int createKeyexSignature( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  INOUT_PTR STREAM *stream, 
						  IN_BUFFER( keyDataLength ) const void *keyData, 
						  IN_LENGTH_SHORT const int keyDataLength )
	{
	CRYPT_CONTEXT md5Context DUMMY_INIT, shaContext;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *dataPtr;
	int dataLength, sigLength DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( keyData, keyDataLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeNZ( keyDataLength ) );

	/* Hash the data to be signed */
	status = createKeyexHash( handshakeInfo, &shaContext, 
				( handshakeInfo->keyexSigHashAlgo != CRYPT_ALGO_NONE ) ? \
					handshakeInfo->keyexSigHashAlgo : CRYPT_ALGO_SHA1,
				handshakeInfo->keyexSigHashAlgoParam, keyData, keyDataLength,
				TEST_FLAG( sessionInfoPtr->protocolFlags, 
						   TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO,
				  "Couldn't create keyex hash" ) );
		}
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = createKeyexHash( handshakeInfo, &md5Context, 
								  CRYPT_ALGO_MD5, 0, keyData, keyDataLength, 
								  FALSE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
			retExt( status,
					( status, SESSION_ERRINFO,
					  "Couldn't create keyex hash" ) );
			}
		}
	INJECT_FAULT( BADSIG_HASH, SESSION_BADSIG_HASH_TLS_1 );

	/* Sign the hashes.  The reason for the min() part of the expression is
	   that iCryptCreateSignature() gets suspicious of very large buffer
	   sizes, for example when the user has specified the use of a huge send
	   buffer */
	clearErrorInfo( &localErrorInfo );
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusOK( status ) )
		{
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
			{
			status = iCryptCreateSignature( dataPtr, 
											min( dataLength, \
												 MAX_INTLENGTH_SHORT - 1 ), 
											&sigLength, CRYPT_IFORMAT_TLS12, 
											sessionInfoPtr->privateKey,
											shaContext, NULL, 
											&localErrorInfo );
			}
		else
			{
			SIGPARAMS sigParams;

			initSigParams( &sigParams );
			sigParams.iSecondHash = shaContext;
			status = iCryptCreateSignature( dataPtr, 
											min( dataLength, \
												 MAX_INTLENGTH_SHORT - 1 ), 
											&sigLength, CRYPT_IFORMAT_TLS, 
											sessionInfoPtr->privateKey,
											md5Context, &sigParams,
											&localErrorInfo );
			}
		}
	insertCryptoDelay();
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
				     "Couldn't sign keyex packet with key for '%s'",
					 getCertHolderName( sessionInfoPtr->privateKey, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	INJECT_FAULT( BADSIG_SIG, SESSION_BADSIG_SIG_TLS_1 );

	return( sSkip( stream, sigLength, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 7 ) ) \
int checkKeyexSignature( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 INOUT_PTR STREAM *stream, 
						 IN_BUFFER( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT const int keyDataLength,
						 IN_BOOL const BOOLEAN isECC,
						 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT md5Context DUMMY_INIT, shaContext;
	CRYPT_ALGO_TYPE hashAlgo = CRYPT_ALGO_SHA1;
	void *dataPtr;
	int dataLength, keyexKeySize, sigKeySize DUMMY_INIT, hashParam = 0;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( keyData, keyDataLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeNZ( keyDataLength ) );
	REQUIRES( isBooleanValue( isECC ) );

	/* Make sure that there's enough data present for at least a minimal-
	   length signature and get a pointer to the signature data */
	if( sMemDataLeft( stream ) < ( isECC ? \
								   MIN_PKCSIZE_ECCPOINT : MIN_PKCSIZE ) )
		return( CRYPT_ERROR_BADDATA );
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( dataPtr != NULL );

	/* TLS 1.2+ precedes the signature itself with an indication of the hash
	   and signature algorithm that's required to verify it, so if we're 
	   using this format then we have to process the identifiers before we
	   can create the signature-verification hashes.

	   We disallow SHA1 since the whole point of TLS 1.2 was to move away 
	   from it, and a poll on the ietf-tls list indicated that all known 
	   implementations at the time (both of them) work fine with this 
	   configuration */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		static const MAP_TABLE hashAlgoIDTbl[] = {
			{ 1000, CRYPT_ALGO_SHAng },
#ifdef USE_SHA2_EXT
			{ TLS_HASHALGO_SHA512, CRYPT_ALGO_SHA2 },
			{ TLS_HASHALGO_SHA384, CRYPT_ALGO_SHA2 },
#endif /* USE_SHA2_EXT */
			{ TLS_HASHALGO_SHA2, CRYPT_ALGO_SHA2 },
#if 0	/* 2/11/11 Disabled option for SHA1 after poll on ietf-tls list */
			{ TLS_HASHALGO_SHA1, CRYPT_ALGO_SHA1 },
#endif /* 0 */
			{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
			};
		static const MAP_TABLE hashParamTbl[] = {
#ifdef USE_SHA2_EXT
			{ TLS_HASHALGO_SHA512, bitsToBytes( 512 ) },
			{ TLS_HASHALGO_SHA384, bitsToBytes( 384 ) },
#endif /* USE_SHA2_EXT */
			{ TLS_HASHALGO_SHA2, bitsToBytes( 256 ) },
			{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
			};
		int cryptHashAlgo, tlsHashAlgo;

		/* Get the hash algorithm that we need to use.  We don't care about
		   the signature algorithm since we've already been given the public
		   key for it */
		status = tlsHashAlgo = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		( void ) sgetc( stream );
		if( !isEnumRange( tlsHashAlgo, TLS_HASHALGO ) )
			return( CRYPT_ERROR_NOTAVAIL ); 
		status = mapValue( tlsHashAlgo, &cryptHashAlgo, hashAlgoIDTbl, 
						   FAILSAFE_ARRAYSIZE( hashAlgoIDTbl, MAP_TABLE ) );
		if( cryptStatusOK( status ) && \
			isParameterisedHashAlgo( cryptHashAlgo ) )
			{
			status = mapValue( tlsHashAlgo, &hashParam, hashParamTbl, 
							   FAILSAFE_ARRAYSIZE( hashParamTbl, \
												   MAP_TABLE ) );
			}
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_NOTAVAIL,
					( CRYPT_ERROR_NOTAVAIL, errorInfo,
					  "Unknown TLS hash algorithm %d", tlsHashAlgo ) );
			}
		hashAlgo = cryptHashAlgo;	/* int vs.enum */
		}

	/* Hash the data to be signed */
	status = createKeyexHash( handshakeInfo, &shaContext, hashAlgo, 
							  hashParam, keyData, keyDataLength,
							  TEST_FLAG( sessionInfoPtr->protocolFlags,
										 TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Couldn't create %s keyex hash", 
				  getAlgoNameEx( hashAlgo, hashParam ) ) );
		}
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		status = createKeyexHash( handshakeInfo, &md5Context, 
								  CRYPT_ALGO_MD5, 0, keyData, keyDataLength,
								  FALSE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	/* Check the signature on the hashes.  The reason for the min() part of
	   the expression is that iCryptCheckSignature() gets suspicious of
	   very large buffer sizes, for example when the user has specified the
	   use of a huge send buffer */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		status = iCryptCheckSignature( dataPtr, 
								min( dataLength, MAX_INTLENGTH_SHORT - 1 ),
								CRYPT_IFORMAT_TLS12, 
								sessionInfoPtr->iKeyexAuthContext, 
								shaContext, CRYPT_UNUSED, NULL,
								errorInfo );
		}
	else
		{
		status = iCryptCheckSignature( dataPtr, 
								min( dataLength, MAX_INTLENGTH_SHORT - 1 ),
								CRYPT_IFORMAT_TLS, 
								sessionInfoPtr->iKeyexAuthContext, 
								md5Context, shaContext, NULL,
								errorInfo );
		}
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the relative strengths of the keyex and signature keys 
	   match.  This is just a general precaution for RSA/DSA, but is 
	   mandated for ECC with Suite B in order to make the appropriate 
	   fashion statement (see the comment below).  When performing the check 
	   we allow a small amount of wiggle room to deal with keygen 
	   differences */
	status = krnlSendMessage( handshakeInfo->dhContext, 
							  IMESSAGE_GETATTRIBUTE, &keyexKeySize, 
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext,
								  IMESSAGE_GETATTRIBUTE, &sigKeySize, 
								  CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( isECC )
		{
		/* For ECC with Suite B the signature key size has to match the 
		   keyex key size otherwise fashion dictums are violated (if you 
		   could just sign size n with size n+1 then you wouldn't need 
		   hashsize n/n+1 and keysize n/n+1 and whatnot) */
		if( sigKeySize < keyexKeySize - bitsToBytes( 8 ) )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, errorInfo,
					  "Server used P%d keyex but only P%d signature",
					  bytesToBits( keyexKeySize ), 
					  bytesToBits( sigKeySize ) ) );
			}
#ifdef CONFIG_SUITEB
		if( ( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB ) && \
			sigKeySize > keyexKeySize + bitsToBytes( 8 ) )
			return( CRYPT_ERROR_NOSECURE );
  #ifdef CONFIG_SUITEB_TESTS 
		DEBUG_PRINT(( "Verified server's P%d keyex with P%d signature.\n", 
					  bytesToBits( keyexKeySize ), 
					  bytesToBits( sigKeySize ) ));
  #endif /* CONFIG_SUITEB_TESTS */
#endif /* CONFIG_SUITEB */
		}
	else
		{
#if 1
		/* For conventional keyex/signatures things get a bit complicated,
		   using (say) a 1024-bit key to sign a 1536-bit keyex seems like a
		   mismatch, but then the 1024-bit key may be regenerated relatively
		   frequently while the 1536-bit DH parameters may be static and
		   shared with everyone else on earth, making the high-value 1536-
		   bit key a more viable target for attack than the singleton 1024-
		   bit one.  Because of this we allow a difference of up to 512 bits
		   between the signing key and the keyex key */
		if( sigKeySize < keyexKeySize - bitsToBytes( 512 + 32 ) )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, errorInfo,
					  "Server used %d-bit keyex but only %d-bit signature",
					  bytesToBits( keyexKeySize ), 
					  bytesToBits( sigKeySize ) ) );
			}
#else
		/* For conventional keyex/signatures the bounds are a bit looser 
		   because non-ECC keygen mechanisms can result in a wider variation 
		   of actual vs. nominal key size */
		if( sigKeySize < keyexKeySize - bitsToBytes( 32 ) )
			return( CRYPT_ERROR_NOSECURE );
#endif /* 0 */
		}

	/* Skip the signature data */
	return( readUniversal16( stream ) );
	}
#endif /* USE_TLS */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
