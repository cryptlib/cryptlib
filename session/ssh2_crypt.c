/****************************************************************************
*																			*
*						  cryptlib SSHv2 Crypto Routines					*
*						Copyright Peter Gutmann 1998-2024					*
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

#ifdef USE_SSH

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Some versions of SSH want to use AES-CTR instead of AES-CBC, which is a 
   pain to deal with because it's not a standard encryption mode for
   cryptlib (or many other crypto libraries/hardware).  To deal with this we 
   synthesise it from ECB mode.  This is possible because the spec requires
   that the data size still be padded out to the cipher's block size, so 
   it's really just a stream-mode conversion of ECB */

#ifdef USE_SSH_CTR

#define KSG_BUFFER_SIZE		512

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int incCtr( INOUT_BUFFER_FIXED( blockSize ) void *ctr,
				   IN_LENGTH_IV const int blockSize )
	{
	BYTE *ctrPtr = ctr, ctrLSB, ctrLSBnext, ctrLSBnext2;
	LOOP_INDEX i;

	REQUIRES( blockSize >= MIN_IVSIZE && blockSize <= CRYPT_MAX_IVSIZE );

	/* Since CTR-mode is an RC4-style stream cipher, it has the same 
	   catastrophic failure mode if the keystream is ever reused.  To try 
	   and guard against this, we check that the counter is being 
	   incremented, at least for the first 16-24 bits, on each call.
	   
	   Note that the counter is stored in little-endian form, so the LSB is 
	   at the far end of the byte string */
	ctrLSB = ctrPtr[ blockSize - 1 ];
	ctrLSBnext = ctrPtr[ blockSize - 2 ];
	ctrLSBnext2 = ctrPtr[ blockSize - 3 ];

	/* Walk along the counter incrementing each byte if required.  This
	   code will overflow with probability 2^-127 on average, which isn't
	   worth checking for, or at least the chances of a check going wrong
	   are higher than the chances of an overflow */
	LOOP_MED_REV( i = blockSize - 1, i >= 0, i-- )
		{
		ENSURES( LOOP_INVARIANT_REV( i, 0, blockSize - 1 ) );

		ctrPtr[ i ]++;
		if( ctrPtr[ i ] != 0 )
			break;
		}
	ENSURES( LOOP_BOUND_MED_REV_OK );
	ENSURES( ( ctrPtr[ blockSize - 1 ] == ctrLSB + 1 && \
			   ctrPtr[ blockSize - 2 ] == ctrLSBnext && \
			   ctrPtr[ blockSize - 3 ] == ctrLSBnext2 ) || \
			 ( ctrPtr[ blockSize - 1 ] == 0 && \
			   ctrPtr[ blockSize - 2 ] == ctrLSBnext + 1 && \
			   ctrPtr[ blockSize - 3 ] == ctrLSBnext2 ) || \
			 ( ctrPtr[ blockSize - 1 ] == 0 && \
			   ctrPtr[ blockSize - 2 ] == 0 && \
			   ctrPtr[ blockSize - 3 ] != ctrLSBnext2 ) );
			 /* aa bb cc -> aa bb cc+1 || aa bb+1 00 || xx 00 00 */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int ctrModeCrypt( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
				  INOUT_BUFFER_FIXED( counterSize ) void *counter,
				  IN_LENGTH_IV const int counterSize,
				  INOUT_BUFFER_FIXED( dataLength ) void *data,
				  IN_LENGTH const int dataLength )
	{
	BYTE ksgBuffer[ KSG_BUFFER_SIZE + 8 ];
	BYTE *dataPtr = data;
	int length, LOOP_ITERATOR;

	assert( isWritePtrDynamic( counter, counterSize ) );
	assert( isWritePtrDynamic( data, dataLength ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( counterSize >= MIN_IVSIZE && counterSize <= CRYPT_MAX_IVSIZE );
	REQUIRES( isIntegerRangeNZ( dataLength ) && ( dataLength % 16 == 0 ) );

	/* Encrypt/decrypt the data in CTR mode KSG_BUFFER_SIZE bytes at a 
	   time */
	LOOP_LARGE_REV_INITCHECK( length = dataLength, length > 0 )
		{
		const int ksgLen = min( length, KSG_BUFFER_SIZE );
		LOOP_INDEX_ALT i;
		int status;

		ENSURES( LOOP_INVARIANT_LARGE_REV_XXX( length, 1, dataLength ) );

		/* Fill the KSG buffer with the counter values and encrypt them in
		   ECB mode to get the CTR cipher stream */
		LOOP_EXT_ALT( i = 0, i < ksgLen, i += counterSize, 
					  KSG_BUFFER_SIZE + 1 )
			{
			ENSURES( LOOP_INVARIANT_EXT_XXX_ALT( i, 0, ksgLen - 1,
												 KSG_BUFFER_SIZE + 1 ) );

			REQUIRES( boundsCheckZ( i, counterSize, KSG_BUFFER_SIZE ) );
			memcpy( ksgBuffer + i, counter, counterSize );
			status = incCtr( counter, counterSize );
			if( cryptStatusError( status ) )
				{
				zeroise( ksgBuffer, KSG_BUFFER_SIZE );
				return( status );
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
								  ksgBuffer, ksgLen );
		if( cryptStatusError( status ) )
			{
			zeroise( ksgBuffer, KSG_BUFFER_SIZE );
			return( status );
			}

		/* Mask/unmask the data with the KSG buffer contents and move on to 
		   the next block */
		LOOP_EXT_ALT( i = 0, i < ksgLen, i++, KSG_BUFFER_SIZE + 1 )
			{
			ENSURES( LOOP_INVARIANT_EXT_ALT( i, 0, ksgLen - 1,
											 KSG_BUFFER_SIZE + 1 ) );

			dataPtr[ i ] ^= ksgBuffer[ i ];
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		dataPtr += ksgLen;
		length -= ksgLen;
		}
	ENSURES( LOOP_BOUND_LARGE_REV_OK );

	/* Clean up */
	zeroise( ksgBuffer, KSG_BUFFER_SIZE );

	return( CRYPT_OK );
	}
#endif /* USE_SSH_CTR */

/* Rewrite an RSA signature into the form required by some buggy 
   implementations, see the comment in processAuthDataSig() for details */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int rewriteRSASignature( const SESSION_INFO *sessionInfoPtr,
								INOUT_PTR STREAM *stream,
								IN_LENGTH_SHORT const int sigLength,
								IN_LENGTH_SHORT const int sigDataMaxLength )
	{
	BYTE sigDataBuffer[ CRYPT_MAX_PKCSIZE + 8 ];
	const int sigOffset = stell( stream );
	int sigSize, keySize, delta, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isShortIntegerRangeNZ( sigLength ) );
	REQUIRES( isShortIntegerRangeNZ( sigDataMaxLength ) );
	REQUIRES( isBufsizeRangeNZ( sigOffset ) );

	status = krnlSendMessage( sessionInfoPtr->privateKey, 
							  IMESSAGE_GETATTRIBUTE, &keySize, 
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the signature length and check whether it needs padding.  Note 
	   that we read the signature data with readString32() rather than 
	   readInteger32() to ensure that we get the raw signature data exactly 
	   as written rather than the cleaned-up integer value */
	readUint32( stream );
	readUniversal32( stream );
	status = readString32( stream, sigDataBuffer, CRYPT_MAX_PKCSIZE,
						   &sigSize );
	ENSURES( cryptStatusOK( status ) );
	if( sigSize >= keySize )
		{
		/* The signature size is the same as the modulus size, there's 
		   nothing to do.  The reads above have reset the stream-position 
		   indicator to the end of the signature data so there's no need to 
		   perform an explicit seek before exiting */
		return( CRYPT_OK );
		}

	/* We've got a signature that's shorter than the RSA modulus, we need to 
	   rewrite it to pad it out to the modulus size:

		  sigOfs				  sigDataBuffer
			|							|
			v uint32	string32		v
			+-------+---------------+---+-------------------+
			| length|	algo-name	|pad|	sigData			|
			+-------+---------------+---+-------------------+
			|						|<+>|<---- sigSize ---->|
			|						delta					|
			|						|<------ keySize ------>|
			|<----------------- sigLength ----------------->|
			|<------------- sigDataMaxLength --------[...]-------->| */
	delta = keySize - sigSize;
	ENSURES( delta > 0 && delta < 16 );
	if( sigLength + delta > sigDataMaxLength )
		return( CRYPT_ERROR_OVERFLOW );
	sseek( stream, sigOffset );
	writeUint32( stream, sizeofString32( 7 ) + \
						 sizeofString32( keySize ) );
	writeString32( stream, "ssh-rsa", 7 );
	writeUint32( stream, keySize );
	return( writeFixedsizeValue( stream, sigDataBuffer, sigSize, keySize ) );
	}

/****************************************************************************
*																			*
*							Key Load/Init Functions							*
*																			*
****************************************************************************/

/* Load a DH key into a context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initDHcontextSSH( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
					  OUT_LENGTH_SHORT_Z int *keySize,
					  IN_BUFFER_OPT( keyDataLength ) const void *keyData, 
					  IN_LENGTH_SHORT_Z const int keyDataLength,
					  IN_LENGTH_SHORT_OPT const int requestedKeySize )
	{
	CRYPT_CONTEXT iDHContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int keyLength DUMMY_INIT, status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( keySize, sizeof( int ) ) );
	assert( ( isReadPtrDynamic( keyData, keyDataLength ) && \
			  requestedKeySize == CRYPT_UNUSED ) || \
			( keyData == NULL && keyDataLength == 0 && \
			  requestedKeySize >= MIN_PKCSIZE && \
			  requestedKeySize <= CRYPT_MAX_PKCSIZE ) );

	REQUIRES( ( keyData != NULL && \
				isShortIntegerRangeNZ( keyDataLength ) && \
				requestedKeySize == CRYPT_UNUSED ) || \
			  ( keyData == NULL && keyDataLength == 0 && \
				requestedKeySize >= MIN_PKCSIZE && \
				requestedKeySize <= CRYPT_MAX_PKCSIZE ) );

	/* Clear return values */
	*iCryptContext = CRYPT_ERROR;
	*keySize = 0;

	/* If we're fuzzing then there's no crypto active */
	FUZZ_SET( *keySize, 192 );
	FUZZ_SKIP_REMAINDER();

	/* Create the DH context to contain the key */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DH );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iDHContext = createInfo.cryptHandle;
	setMessageData( &msgData, "SSH DH key", 10 );
	status = krnlSendMessage( iDHContext, IMESSAGE_SETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iDHContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* If we're not being given externally-supplied DH key components, get 
	   the actual key size based on the requested key size */
	if( keyData == NULL )
		{
		const int roundedKeySize = requestedKeySize & ~1;

		/* When we ask for a given key size we clear the low bit which is
		   used to signal the use of an alternate DH value, necessitated by
		   TLS 1.3 braindamage */
		status = krnlSendMessage( iDHContext, IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &roundedKeySize, 
								  CRYPT_IATTRIBUTE_KEY_DLPPARAM );
		}
	else
		{
		setMessageData( &msgData, ( MESSAGE_CAST ) keyData, keyDataLength );
		status = krnlSendMessage( iDHContext, IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEY_SSH );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iDHContext, IMESSAGE_GETATTRIBUTE, 
								  &keyLength, CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusError( status ) )
		{
		/* If we're trying to load the context from stored data and the load 
		   fails, record the fact that there's a problem */
		if( keyData == NULL )
			{
			DEBUG_DIAG(( "Couldn't create DH context from stored data" ));
			assert( DEBUG_WARN );
			}
		krnlSendNotifier( iDHContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptContext = iDHContext;
	*keySize = keyLength;

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_25519 )

/* Load one of the fixed SSH ECDH/25519 keys into a context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initECDHcontextSSH( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
						OUT_LENGTH_SHORT_Z int *keySize,
						IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_CONTEXT iECDHContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	static const int eccCurveSize = CRYPT_ECCCURVE_P256;
	int status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( keySize, sizeof( int ) ) );

	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDH || \
			  cryptAlgo == CRYPT_ALGO_25519 );

	/* Clear return values */
	*iCryptContext = CRYPT_ERROR;
	*keySize = 0;

	/* Create the ECDH context to contain the key */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iECDHContext = createInfo.cryptHandle;
	if( cryptAlgo == CRYPT_ALGO_ECDH )
		{ setMessageData( &msgData, "SSH ECDH key", 12 ); }
	else
		{ setMessageData( &msgData, "SSH 25519 key", 13 ); }
	status = krnlSendMessage( iECDHContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iECDHContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* If it's a parameterised algorithm, load the appropriate key 
	   parameters */
	if( cryptAlgo == CRYPT_ALGO_ECDH )
		{
		status = krnlSendMessage( iECDHContext, IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &eccCurveSize, 
								  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
		}
	else
		{
		/* It's a non-parameterised algorithm, in other words one with an
		   implicit key, set up the key */
		status = krnlSendMessage( iECDHContext, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_TRUE, 
								  CRYPT_IATTRIBUTE_KEY_IMPLICIT );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iECDHContext, IMESSAGE_DECREFCOUNT );

		/* We got an error loading a known-good, fixed-format key, report 
		   the problem as an internal error rather than (say) a bad-data 
		   error */
		retIntError();
		}
	*iCryptContext = iECDHContext;
	*keySize = bitsToBytes( 256 );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH */

/* Complete the hashing necessary to generate a cryptovariable and send it
   to a context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 4, 6, 7, 9 ) ) \
static int loadCryptovariable( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
							   IN_RANGE( 8, 40 ) const int attributeSize, 
							   const HASH_FUNCTION hashFunction,
							   IN_RANGE( 20, 32 ) const int hashSize,
							   const HASHINFO initialHashInfo, 
							   IN_BUFFER( nonceLen ) const BYTE *nonce, 
							   IN_RANGE( 1, 4 ) const int nonceLen,
							   IN_BUFFER( dataLen ) const BYTE *data, 
							   IN_LENGTH_SHORT const int dataLen )
	{
	MESSAGE_DATA msgData;
	HASHINFO hashInfo;
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int status;

	assert( isReadPtr( initialHashInfo, sizeof( HASHINFO ) ) );
	assert( isReadPtrDynamic( nonce, nonceLen ) );
	assert( isReadPtrDynamic( data, dataLen ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( attribute == CRYPT_CTXINFO_IV || \
			  attribute == CRYPT_CTXINFO_KEY );
	REQUIRES( attributeSize >= 8 && attributeSize <= 40 );
	REQUIRES( hashFunction != NULL );
	REQUIRES( hashSize == 20 || hashSize == 32 );
	REQUIRES( nonceLen >= 1 && nonceLen <= 4 );
	REQUIRES( isShortIntegerRangeNZ( dataLen ) );

	/* Complete the hashing */
	memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
	hashFunction( hashInfo, NULL, 0, nonce, nonceLen, HASH_STATE_CONTINUE );
	hashFunction( hashInfo, buffer, CRYPT_MAX_HASHSIZE, data, dataLen, 
				  HASH_STATE_END );
	if( attributeSize > hashSize )
		{
		/* If we need more data than the hashing will provide in one go,
		   generate a second block as:

			hash( shared_secret || exchange_hash || data )

		   where the shared secret and exchange hash are present as the
		   precomputed data in the initial hash information and the data 
		   part is the output of the hash step above */
		memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
		hashFunction( hashInfo, buffer + hashSize, 
					  CRYPT_MAX_HASHSIZE - hashSize, buffer, hashSize, 
					  HASH_STATE_END );
		}
	zeroise( hashInfo, sizeof( HASHINFO ) );

	/* Send the data to the context */
	setMessageData( &msgData, buffer, attributeSize );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, attribute );
	zeroise( buffer, CRYPT_MAX_HASHSIZE );

	return( status );
	}

#ifdef USE_SSH_CTR

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5, 7 ) ) \
static int loadCTR( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					IN_PTR const HASH_FUNCTION hashFunction,
					IN_RANGE( 20, 32 ) const int hashSize,
					IN_PTR const HASHINFO initialHashInfo, 
					IN_BUFFER( nonceLen ) const BYTE *nonce, 
					IN_RANGE( 1, 4 ) const int nonceLen,
					IN_BUFFER( dataLen ) const BYTE *data, 
					IN_LENGTH_SHORT const int dataLen,
					IN_BOOL const BOOLEAN isWriteCTR )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	HASHINFO hashInfo;
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 8 ];

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( initialHashInfo, sizeof( HASHINFO ) ) );
	assert( isReadPtrDynamic( nonce, nonceLen ) );
	assert( isReadPtrDynamic( data, dataLen ) );

	REQUIRES( hashFunction != NULL );
	REQUIRES( hashSize == 20 || hashSize == 32 );
	REQUIRES( nonceLen >= 1 && nonceLen <= 4 );
	REQUIRES( isShortIntegerRangeNZ( dataLen ) );
	REQUIRES( isBooleanValue( isWriteCTR ) );

	/* Complete the hashing */
	memcpy( hashInfo, initialHashInfo, sizeof( HASHINFO ) );
	hashFunction( hashInfo, NULL, 0, nonce, nonceLen, HASH_STATE_CONTINUE );
	hashFunction( hashInfo, buffer, CRYPT_MAX_HASHSIZE, data, dataLen, 
				  HASH_STATE_END );
	zeroise( hashInfo, sizeof( HASHINFO ) );

	/* Send the data to the context */
	REQUIRES( boundsCheck( sessionInfoPtr->cryptBlocksize, 1, 
						   CRYPT_MAX_IVSIZE ) );
	if( isWriteCTR )
		memcpy( sshInfo->writeCTR, buffer, sessionInfoPtr->cryptBlocksize );
	else
		memcpy( sshInfo->readCTR, buffer, sessionInfoPtr->cryptBlocksize );
	zeroise( buffer, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_SSH_CTR */

/* Initialise and destroy the security contexts */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initSecurityContextsSSH( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );

	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
#ifdef USE_SSH_CTR
	if( cryptStatusOK( status ) && \
		TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_CTR ) )
		{
		static const int mode = CRYPT_MODE_ECB;	/* int vs.enum */

		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &mode,
								  CRYPT_CTXINFO_MODE );
		}
#endif /* USE_SSH_CTR */
	if( cryptStatusOK( status ) && handshakeInfo->cryptKeysize != 0 )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  &handshakeInfo->cryptKeysize,
								  CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
#ifdef USE_SSH_CTR
	if( cryptStatusOK( status ) && \
		TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_CTR ) )
		{
		static const int mode = CRYPT_MODE_ECB;	/* int vs.enum */

		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &mode,
								  CRYPT_CTXINFO_MODE );
		}
#endif /* USE_SSH_CTR */
	if( cryptStatusOK( status ) && handshakeInfo->cryptKeysize != 0 )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  &handshakeInfo->cryptKeysize,
								  CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_GETATTRIBUTE, 
								  &sessionInfoPtr->cryptBlocksize,
								  CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			{
			sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;
			setMessageCreateObjectInfo( &createInfo,
										sessionInfoPtr->integrityAlgo );
			status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
									  OBJECT_TYPE_CONTEXT );
			}
		if( cryptStatusOK( status ) )
			{
			sessionInfoPtr->iAuthOutContext = createInfo.cryptHandle;
			krnlSendMessage( sessionInfoPtr->iAuthInContext,
							 IMESSAGE_GETATTRIBUTE,
							 &sessionInfoPtr->authBlocksize,
							 CRYPT_CTXINFO_BLOCKSIZE );
			}
		}
	if( cryptStatusError( status ) )
		{
		/* One or more of the contexts couldn't be created, destroy all the
		   contexts created so far */
		destroySecurityContextsSSH( sessionInfoPtr );
		}
	return( status );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroySecurityContextsSSH( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES_V( sanityCheckSessionSSH( sessionInfoPtr ) );

	/* Destroy any active contexts */
	if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iKeyexCryptContext = CRYPT_ERROR;
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
	}

/* Set up the security information required for the session */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initSecurityInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					  INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	HASH_FUNCTION hashFunction;
	HASHINFO initialHashInfo;
	const BOOLEAN isClient = isServer( sessionInfoPtr ) ? FALSE : TRUE;
	int keySize, hashSize, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );

	/* Create the security contexts required for the session */
	status = initSecurityContextsSSH( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_GETATTRIBUTE, &keySize,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the hash algorithm information and pre-hash the shared secret and
	   exchange hash, which are re-used for all cryptovariables.  The
	   overall hashing is:

		hash( MPI( shared_secret ) || exchange_hash || \
			  nonce || exchange_hash )

	   Note the apparently redundant double hashing of the exchange hash,
	   this is required because the spec refers to it by two different names,
	   the exchange hash and the session ID, and then requires that both be
	   hashed (actually it's a bit more complex than that with issues 
	   related to re-keying but for now it acts as a re-hash of the same
	   data).

	   Before we can hash the shared secret we have to convert it into MPI
	   form, which we do by generating a pseudo-header and hashing that
	   separately.  The nonce is "A", "B", "C", ... */
	getHashParameters( handshakeInfo->exchangeHashAlgo, 0, &hashFunction, 
					   &hashSize );
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, 
				   SSH_PFLAG_NOHASHSECRET ) )
		{
		/* Some implementations erroneously omit the shared secret when
		   creating the keying material.  This is suboptimal but not fatal,
		   since the shared secret is also hashed into the exchange hash */
		hashFunction( initialHashInfo, NULL, 0, handshakeInfo->sessionID,
					  handshakeInfo->sessionIDlength, HASH_STATE_START );
		}
	else
		{
		STREAM stream;
		BYTE header[ 8 + 8 ];
		const int mpiLength = ( handshakeInfo->secretValue[ 0 ] & 0x80 ) ? \
								handshakeInfo->secretValueLength + 1 : \
								handshakeInfo->secretValueLength;
		int headerLength DUMMY_INIT;

		/* Hash the shared secret as an MPI.  We can't use hashAsMPI() for
		   this because it works with hash contexts rather than the 
		   HASH_FUNCTION interface used here */
		sMemOpen( &stream, header, 8 );
		status = writeUint32( &stream, mpiLength );
		if( handshakeInfo->secretValue[ 0 ] & 0x80 )
			{
			/* MPIs are signed values */
			status = sputc( &stream, 0 );
			}
		if( cryptStatusOK( status ) )
			headerLength = stell( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		ENSURES( isShortIntegerRangeNZ( headerLength ) );
		hashFunction( initialHashInfo, NULL, 0, header, headerLength,
					  HASH_STATE_START );
		hashFunction( initialHashInfo, NULL, 0, handshakeInfo->secretValue,
					  handshakeInfo->secretValueLength, HASH_STATE_CONTINUE );
		hashFunction( initialHashInfo, NULL, 0, handshakeInfo->sessionID,
					  handshakeInfo->sessionIDlength, HASH_STATE_CONTINUE );
		}

	/* Load the cryptovariables.  The order is:

		client_write_iv, server_write_iv
		client_write_key, server_write_key
		client_write_mac, server_write_mac

	   Although HMAC has a variable-length key and should therefore follow
	   the SSH2_FIXED_KEY_SIZE rule, the key size was in later RFC drafts
	   set to the HMAC block size.  Some implementations erroneously use
	   the fixed-size key so we adjust the HMAC key size if we're talking
	   to one of these */
	if( !isStreamCipher( sessionInfoPtr->cryptAlgo ) )
		{
#ifdef USE_SSH_CTR
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_CTR ) )
			{
			status = loadCTR( sessionInfoPtr, hashFunction, hashSize, 
							  initialHashInfo, MKDATA( "A" ), 1,
							  handshakeInfo->sessionID,
							  handshakeInfo->sessionIDlength,
							  isClient ? TRUE : FALSE );
			if( cryptStatusOK( status ) )
				{
				status = loadCTR( sessionInfoPtr, hashFunction, hashSize, 
								  initialHashInfo, MKDATA( "B" ), 1,
								  handshakeInfo->sessionID,
								  handshakeInfo->sessionIDlength,
								  isClient ? FALSE : TRUE );
				}
			}
		else
#endif /* USE_SSH_CTR */
			{
			status = loadCryptovariable( isClient ? \
								sessionInfoPtr->iCryptOutContext : \
								sessionInfoPtr->iCryptInContext,
							CRYPT_CTXINFO_IV, sessionInfoPtr->cryptBlocksize, 
							hashFunction, hashSize, initialHashInfo, 
							MKDATA( "A" ), 1, handshakeInfo->sessionID,
							handshakeInfo->sessionIDlength );
			if( cryptStatusOK( status ) )
				{
				status = loadCryptovariable( isClient ? \
								sessionInfoPtr->iCryptInContext : \
								sessionInfoPtr->iCryptOutContext,
							CRYPT_CTXINFO_IV, sessionInfoPtr->cryptBlocksize, 
							hashFunction, hashSize, initialHashInfo, 
							MKDATA( "B" ), 1, handshakeInfo->sessionID,
							handshakeInfo->sessionIDlength );
				}
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = loadCryptovariable( isClient ? \
								sessionInfoPtr->iCryptOutContext : \
								sessionInfoPtr->iCryptInContext,
							CRYPT_CTXINFO_KEY, keySize, hashFunction, 
							hashSize, initialHashInfo, MKDATA( "C" ), 1,
							handshakeInfo->sessionID,
							handshakeInfo->sessionIDlength );
		}
	if( cryptStatusOK( status ) )
		{
		status = loadCryptovariable( isClient ? \
								sessionInfoPtr->iCryptInContext : \
								sessionInfoPtr->iCryptOutContext,
							CRYPT_CTXINFO_KEY, keySize, hashFunction, 
							hashSize, initialHashInfo, MKDATA( "D" ), 1,
							handshakeInfo->sessionID,
							handshakeInfo->sessionIDlength );
		}
	if( cryptStatusOK( status ) )
		{
		status = loadCryptovariable( isClient ? \
								sessionInfoPtr->iAuthOutContext : \
								sessionInfoPtr->iAuthInContext,
							CRYPT_CTXINFO_KEY,
							TEST_FLAG( sessionInfoPtr->protocolFlags, \
									   SSH_PFLAG_HMACKEYSIZE ) ? \
								SSH2_FIXED_KEY_SIZE : \
								sessionInfoPtr->authBlocksize,
							hashFunction, hashSize, initialHashInfo, 
							MKDATA( "E" ), 1, handshakeInfo->sessionID,
							handshakeInfo->sessionIDlength );
		}
	if( cryptStatusOK( status ) )
		{
		status = loadCryptovariable( isClient ? \
								sessionInfoPtr->iAuthInContext : \
								sessionInfoPtr->iAuthOutContext,
							CRYPT_CTXINFO_KEY,
							TEST_FLAG( sessionInfoPtr->protocolFlags, \
									   SSH_PFLAG_HMACKEYSIZE ) ? \
								SSH2_FIXED_KEY_SIZE : \
								sessionInfoPtr->authBlocksize,
							hashFunction, hashSize, initialHashInfo, 
							MKDATA( "F" ), 1, handshakeInfo->sessionID,
							handshakeInfo->sessionIDlength );
		}
	zeroise( initialHashInfo, sizeof( HASHINFO ) );
	return( status );
	}

/****************************************************************************
*																			*
*								Hash/MAC Data								*
*																			*
****************************************************************************/

/* Hash a value encoded as an SSH string and as an MPI */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int hashAsString( IN_HANDLE const CRYPT_CONTEXT iHashContext,
				  IN_BUFFER( dataLength ) const BYTE *data, 
				  IN_LENGTH_SHORT const int dataLength )
	{
	STREAM stream;
	BYTE buffer[ 128 + 8 ];
	BOOLEAN copiedToBuffer = FALSE;
	int status;

	assert( isReadPtrDynamic( data, dataLength ) );

	/* If we're fuzzing then there's no crypto active */
	FUZZ_SKIP_REMAINDER();

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isShortIntegerRangeNZ( dataLength ) );

	/* Prepend the string length to the data and hash it.  If it'll fit into
	   the buffer we copy it over to save a kernel call */
	sMemOpen( &stream, buffer, 128 );
	status = writeUint32( &stream, dataLength );
	if( cryptStatusOK( status ) && dataLength <= sMemDataLeft( &stream ) )
		{
		/* The data will fit into the buffer, copy it so that it can be 
		   hashed in one go */
		status = swrite( &stream, data, dataLength );
		copiedToBuffer = TRUE;
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
								  buffer, stell( &stream ) );
		}
	if( cryptStatusOK( status ) && !copiedToBuffer )
		{
		/* The data didn't fit into the buffer, hash it separately */
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) data, dataLength );
		}
	sMemClose( &stream );
	if( copiedToBuffer )
		zeroise( buffer, 128 );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int hashAsMPI( IN_HANDLE const CRYPT_CONTEXT iHashContext, 
			   IN_BUFFER( dataLength ) const BYTE *data, 
			   IN_LENGTH_SHORT const int dataLength )
	{
	STREAM stream;
	BYTE buffer[ 8 + 8 ];
	const int length = ( data[ 0 ] & 0x80 ) ? dataLength + 1 : dataLength;
	int headerLength DUMMY_INIT, status;

	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isShortIntegerRangeNZ( dataLength ) );

	/* Prepend the MPI length to the data and hash it.  Since this is often
	   sensitive data we don't take a local copy but hash it in two parts */
	sMemOpen( &stream, buffer, 8 );
	status = writeUint32( &stream, length );
	if( data[ 0 ] & 0x80 )
		{
		/* MPIs are signed values */
		status = sputc( &stream, 0 );
		}
	if( cryptStatusOK( status ) )
		headerLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( headerLength ) );
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
							  buffer, headerLength );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) data, dataLength );
		}
	return( status );
	}

/* MAC the payload of a data packet.  Since we may not have the whole packet
   available at once we can either do this in one go or incrementally.  If 
   it's incremental then packetDataLength is the packet-length value that's
   encoded into a uint32 and hashed while dataLength is the amount of data 
   that we have available to hash right now.  If it's an atomic hash then
   dataLength is both the length and data amount and packetDataLength is 
   zero */

CHECK_RETVAL \
static int macDataSSH( IN_HANDLE const CRYPT_CONTEXT iMacContext, 
					   IN_INT_Z const long seqNo,
					   IN_BUFFER_OPT( dataLength ) const BYTE *data, 
					   IN_DATALENGTH_Z const int dataLength,
					   IN_DATALENGTH_Z const int packetDataLength, 
					   IN_ENUM_OPT( MAC ) const MAC_TYPE macType )
	{
	int status;

	assert( ( data == NULL && dataLength == 0 ) || \
			isReadPtrDynamic( data, dataLength ) );

	REQUIRES( isHandleRangeValid( iMacContext ) );
	REQUIRES( ( macType == MAC_END && seqNo == 0 ) || \
			  ( macType != MAC_END && \
				seqNo >= 2 && seqNo < INT_MAX ) );
			  /* Since SSH starts counting packets from the first one but 
				 unlike TLS doesn't MAC them, the seqNo is already nonzero 
				 when we start */
	REQUIRES( ( data == NULL && dataLength == 0 ) || \
			  ( data != NULL && \
				isBufsizeRangeNZ( dataLength ) ) );
			  /* Payload may be zero for packets where all information is 
			     contained in the header */
	REQUIRES( isBufsizeRange( packetDataLength ) );
	REQUIRES( isEnumRangeOpt( macType, MAC ) );
			  /* If we're doing a non-incremental MAC operation the type is 
			     set to MAC_NONE */

	/* MAC the data and either compare the result to the stored MAC or
	   append the MAC value to the data:

		HMAC( seqNo || length || payload )

	   During the handshake process we have the entire packet at hand
	   (dataLength == packetDataLength) and can process it at once 
	   (macType == MAC_NONE).  When we're processing payload data 
	   (dataLength a subset of packetDataLength) we have to process the 
	   header separately in order to determine how much more we have to read
	   so we have to MAC the packet in two parts (macType == MAC_START/
	   MAC_END) */
	if( macType == MAC_START || macType == MAC_NONE )
		{
		STREAM stream;
		BYTE headerBuffer[ 16 + 8 ];
		int length = ( macType == MAC_NONE ) ? dataLength : packetDataLength;
		int headerLength DUMMY_INIT;

		REQUIRES( ( macType == MAC_NONE && packetDataLength == 0 ) || \
				  ( macType == MAC_START && packetDataLength >= dataLength ) );

		/* Since the payload has had the length stripped during the 
		   speculative read if we're MAC'ing read data then we have to 
		   reconstruct it and hash it separately before we hash the data.  
		   If we're doing the hash in parts then the amount of data being 
		   hashed won't match the overall length so the caller needs to 
		   supply the overall packet length as well as the current data 
		   length */
		sMemOpen( &stream, headerBuffer, 16 );
		writeUint32( &stream, seqNo );
		status = writeUint32( &stream, length );
		if( cryptStatusOK( status ) )
			headerLength = stell( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		ENSURES( isShortIntegerRangeNZ( headerLength ) );
		krnlSendMessage( iMacContext, IMESSAGE_DELETEATTRIBUTE, NULL,
						 CRYPT_CTXINFO_HASHVALUE );
		status = krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH, 
								  headerBuffer, headerLength );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( dataLength > 0 )
		{
		status = krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) data, dataLength );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( macType == MAC_END || macType == MAC_NONE )
		{
		status = krnlSendMessage( iMacContext, IMESSAGE_CTX_HASH, "", 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int checkMacSSHIncremental( IN_HANDLE const CRYPT_CONTEXT iMacContext, 
							IN_INT_Z const long seqNo,
							IN_BUFFER( dataMaxLength ) const BYTE *data, 
							IN_DATALENGTH const int dataMaxLength, 
							IN_DATALENGTH_Z const int dataLength, 
							IN_DATALENGTH_Z const int packetDataLength, 
							IN_ENUM( MAC ) const MAC_TYPE macType, 
							IN_LENGTH_HASH const int macLength )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isReadPtrDynamic( data, dataMaxLength ) );

	REQUIRES( isHandleRangeValid( iMacContext ) );
	REQUIRES( ( macType == MAC_END && seqNo == 0 ) || \
			  ( macType != MAC_END && \
				seqNo >= 2 && seqNo < INT_MAX ) );
			  /* Since SSH starts counting packets from the first one but 
				 unlike TLS doesn't MAC them, the seqNo is already nonzero 
				 when we start */
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( ( macType == MAC_END && dataLength == 0 ) || \
			  isBufsizeRangeNZ( dataLength ) );
			  /* Payload size may be zero for packets where all information
			     is contained in, and has already been MACd as part of, the 
				 header */
	REQUIRES( isBufsizeRange( packetDataLength ) );
	REQUIRES( isEnumRange( macType, MAC ) );
	REQUIRES( macLength >= MIN_HASHSIZE && \
			  macLength <= CRYPT_MAX_HASHSIZE );
	REQUIRES( ( macType == MAC_START && \
				dataMaxLength == dataLength ) || \
			  ( macType == MAC_END && 
				dataLength + macLength <= dataMaxLength ) );

	/* MAC the payload.  If the data length is zero then there's no data 
	   payload (which can happen with things like a channel close for which 
	   the entire content is carried in the message header), only the MAC
	   data at the end, so we don't pass anything down to macDataSSH() */
	if( dataLength <= 0 )
		{
		status = macDataSSH( iMacContext, seqNo, NULL, 0, 
							 packetDataLength, macType );
		}
	else
		{
		status = macDataSSH( iMacContext, seqNo, data, dataLength, 
							 packetDataLength, macType );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If we're starting the ongoing hashing of a data block then we're 
	   done */
	if( macType == MAC_START )
		return( CRYPT_OK );

	/* Compare the calculated MAC value to the stored MAC value */
	setMessageData( &msgData, ( BYTE * ) data + dataLength, macLength );
	return( krnlSendMessage( iMacContext, IMESSAGE_COMPARE, &msgData, 
							 MESSAGE_COMPARE_HASH ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int checkMacSSH( IN_HANDLE const CRYPT_CONTEXT iMacContext, 
				 IN_INT const long seqNo,
				 IN_BUFFER( dataMaxLength ) const BYTE *data, 
				 IN_DATALENGTH const int dataMaxLength, 
				 IN_DATALENGTH_Z const int dataLength, 
				 IN_LENGTH_HASH const int macLength )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isReadPtrDynamic( data, dataMaxLength ) );

	REQUIRES( isHandleRangeValid( iMacContext ) );
	REQUIRES( seqNo >= 2 && seqNo < INT_MAX );
			  /* Since SSH starts counting packets from the first one but 
				 unlike TLS doesn't MAC them, the seqNo is already nonzero 
				 when we start */
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( isBufsizeRange( dataLength ) );
	REQUIRES( macLength >= MIN_HASHSIZE && \
			  macLength <= CRYPT_MAX_HASHSIZE );
	REQUIRES( dataLength + macLength <= dataMaxLength );

	/* MAC the payload.  If the data length is zero then there's no data 
	   payload (which can happen with things like a channel close for which 
	   the entire content is carried in the message header), only the MAC
	   data at the end, so we don't pass anything down to macDataSSH() */
	if( dataLength <= 0 )
		status = macDataSSH( iMacContext, seqNo, NULL, 0, 0, MAC_NONE );
	else
		status = macDataSSH( iMacContext, seqNo, data, dataLength, 0, MAC_NONE );
	if( cryptStatusError( status ) )
		return( status );

	/* Compare the calculated MAC value to the stored MAC value */
	setMessageData( &msgData, ( BYTE * ) data + dataLength, macLength );
	return( krnlSendMessage( iMacContext, IMESSAGE_COMPARE, &msgData, 
							 MESSAGE_COMPARE_HASH ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int createMacSSH( IN_HANDLE const CRYPT_CONTEXT iMacContext, 
				  IN_INT const long seqNo,
				  IN_BUFFER( dataMaxLength ) BYTE *data, 
				  IN_DATALENGTH const int dataMaxLength, 
				  IN_DATALENGTH const int dataLength )
	{
	MESSAGE_DATA msgData;
	BYTE mac[ CRYPT_MAX_HASHSIZE + 8 ];
	int status;

	assert( isWritePtrDynamic( data, dataLength ) );

	REQUIRES( isHandleRangeValid( iMacContext ) );
	REQUIRES( seqNo >= 2 && seqNo < INT_MAX );
			  /* Since SSH starts counting packets from the first one but 
				 unlike TLS doesn't MAC them, the seqNo is already nonzero 
				 when we start */
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) && dataLength < dataMaxLength );

	/* MAC the payload */
	status = macDataSSH( iMacContext, seqNo, data, dataLength, 0, MAC_NONE );
	if( cryptStatusError( status ) )
		return( status );

	/* Append the calculated MAC value to the data */
	setMessageData( &msgData, mac, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iMacContext, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	INJECT_FAULT( SESSION_CORRUPT_MAC, SESSION_CORRUPT_MAC_SSH_1 );
	REQUIRES( boundsCheck( dataLength, msgData.length, dataMaxLength ) );
	memcpy( data + dataLength, mac, msgData.length );
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Sign/Verify Data							*
*																			*
****************************************************************************/

/* Process public-key authentication data, with the usual special-snowflake
   handling for the Bernstein algorithms */

#ifdef USE_ED25519

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int processAuthDataSigBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 IN_PTR \
									const SSH_HANDSHAKE_INFO *handshakeInfo, 
								 INOUT_PTR STREAM *stream,
								 IN_BUFFER( packetDataLength ) \
									const void *packetData,
								 IN_LENGTH_SHORT \
									const int packetDataLength,
								 IN_ALGO const CRYPT_ALGO_TYPE pkcAlgo,
								 IN_BOOL const BOOLEAN createSignature )
	{
	SIG_DATA_INFO sigDataInfo;
	ERROR_INFO localErrorInfo;
	STREAM authDataStream;
	BYTE authDataBuffer[ 512 + 8 ];
	void *sigDataPtr;
	int authDataLength DUMMY_INIT, sigDataLength, sigLength DUMMY_INIT;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( packetData, packetDataLength ) );
	
	REQUIRES( isShortIntegerRangeNZ( packetDataLength ) );
	REQUIRES( isBooleanValue( createSignature ) );
		
	/* Write the authentication data to a buffer, since the special-
	   snowflake algorithms need to see the entire message rather than just 
	   a hash of it:
		   
		string	exchange hash			-- Max.64 bytes
		byte	type = SSH_MSG_USERAUTH_REQUEST
		string	user_name				-- Max.64 bytes
		string	service_name = "ssh-connection"
		string	method_name = "publickey"
		string	"ed25519"
		string		[ client key/certificate ]
			string	"ed25519"
			string	pubKey				-- 32 bytes
		   
	   The maximum size of the authentication data is the session ID, max.64 
	   bytes, the user name, max CRYPT_MAX_TEXTSIZE = 64 bytes, the service 
	   name and method strings, and the public key consisting of the 
	   algorithm name followed by MAX_PKCSIZE_BERNSTEIN = 32 bytes of key, 
	   alongside various 32-bit length fields, for a total of around 256 
	   bytes, so 512 is plenty.
	   
	   The packet-read code strips the ID byte on read so if we're verifying
	   a signature we have to re-insert it before we write the packet data
	   body to the authData buffer */
	sMemOpen( &authDataStream, authDataBuffer, 512 );
	writeString32( &authDataStream, handshakeInfo->sessionID,
				   handshakeInfo->sessionIDlength );
	if( !createSignature )
		sputc( &authDataStream, SSH_MSG_USERAUTH_REQUEST );
	status = swrite( &authDataStream, packetData, packetDataLength );
	if( cryptStatusOK( status ) )
		authDataLength = stell( &authDataStream );
	sMemDisconnect( &authDataStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Create or check the signature.  The reason for the min() part of the 
	   expression is that iCryptCreate/CheckSignature() gets suspicious of 
	   very large buffer sizes, for example if the client were to specify 
	   the use of a huge signature packet */
	clearErrorInfo( &localErrorInfo );
	status = sMemGetDataBlockRemaining( stream, &sigDataPtr, 
										&sigDataLength );
	if( cryptStatusError( status ) )
		return( status );
	setSigDataInfoMessage( &sigDataInfo, authDataBuffer, authDataLength );
	if( createSignature )
		{
		status = iCryptCreateSignature( sigDataPtr, 
						min( sigDataLength, MAX_INTLENGTH_SHORT - 1 ), 
						&sigLength, CRYPT_IFORMAT_SSH, 
						sessionInfoPtr->privateKey, &sigDataInfo, NULL, 
						&localErrorInfo );
		}
	else
		{
		status = iCryptCheckSignature( sigDataPtr, 
						min( sigDataLength, MAX_INTLENGTH_SHORT - 1 ),
						CRYPT_IFORMAT_SSH, 
						sessionInfoPtr->iKeyexAuthContext, 
						&sigDataInfo, NULL, &localErrorInfo );
		}
	if( cryptStatusError( status ) )
		{
		if( createSignature )
			{
			retExtErr( status,
					   ( status, SESSION_ERRINFO, &localErrorInfo,
					     "Couldn't sign SSH_MSG_USERAUTH_REQUEST packet" ) );
			}

		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Verification of client's %s public-key "
					 "authentication failed", getAlgoName( pkcAlgo ) ) );
		}
	if( createSignature )
		status = sSkip( stream, sigLength, MAX_INTLENGTH_SHORT );

	return( status );
	}
#endif /* USE_ED25519 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int processAuthDataSig( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_PTR const SSH_HANDSHAKE_INFO *handshakeInfo, 
						INOUT_PTR STREAM *stream,
						IN_BUFFER( packetDataLength ) const void *packetData,
						IN_LENGTH_SHORT const int packetDataLength,
						IN_ALGO const CRYPT_ALGO_TYPE pkcAlgo,
						IN_BOOL const BOOLEAN createSignature )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	SIG_DATA_INFO sigDataInfo;
	ERROR_INFO localErrorInfo;
	void *sigDataPtr DUMMY_INIT_PTR;
	int sigDataLength DUMMY_INIT, sigLength DUMMY_INIT, status;
	
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( packetData, packetDataLength ) );
	
	REQUIRES( isShortIntegerRangeNZ( packetDataLength ) );
	REQUIRES( isEnumRange( pkcAlgo, CRYPT_ALGO ) );
	REQUIRES( isBooleanValue( createSignature ) );

	/* Hash the authentication request data, composed of:
	
		string		exchange hash
		[ SSH_MSG_USERAUTH_REQUEST packet payload up to signature start ] */
	setMessageCreateObjectInfo( &createInfo, handshakeInfo->hashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_NOHASHLENGTH ) )
		{
		/* Some implementations erroneously omit the length when hashing the 
		   exchange hash */
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) handshakeInfo->sessionID,
								  handshakeInfo->sessionIDlength );
		}
	else
		{
		status = hashAsString( createInfo.cryptHandle, 
							   handshakeInfo->sessionID,
							   handshakeInfo->sessionIDlength );
		}
	if( cryptStatusOK( status ) && !createSignature )
		{
		static const BYTE packetID = SSH_MSG_USERAUTH_REQUEST;

		/* readAuthPacketSSH2() has stripped the ID byte from the start of 
		   the packet so we need to hash it in explicitly before we hash the 
		   rest of the packet */
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) &packetID, ID_SIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH, 
								  ( MESSAGE_CAST ) packetData, 
								  packetDataLength );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_CTX_HASH, "", 0 );
		}
	if( cryptStatusOK( status ) )
		{
		status = sMemGetDataBlockRemaining( stream, &sigDataPtr, 
											&sigDataLength );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, SESSION_ERRINFO,
				  "Couldn't hash authentication request data" ) );
		}

	/* Create or check the signature.  The reason for the min() part of the 
	   expression is that iCryptCreate/CheckSignature() gets suspicious of 
	   very large buffer sizes, for example if the client were to specify 
	   the use of a huge signature packet */
	clearErrorInfo( &localErrorInfo );
	setSigDataInfoHash( &sigDataInfo, createInfo.cryptHandle );
	if( createSignature )
		{
		status = iCryptCreateSignature( sigDataPtr, 
						min( sigDataLength, MAX_INTLENGTH_SHORT - 1 ), 
						&sigLength, CRYPT_IFORMAT_SSH, 
						sessionInfoPtr->privateKey, &sigDataInfo, NULL, 
						&localErrorInfo );
		}
	else
		{
		status = iCryptCheckSignature( sigDataPtr, 
						min( sigDataLength, MAX_INTLENGTH_SHORT - 1 ),
						CRYPT_IFORMAT_SSH, 
						sessionInfoPtr->iKeyexAuthContext, 
						&sigDataInfo, NULL, &localErrorInfo );
		}
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		if( createSignature )
			{
			retExtErr( status,
					   ( status, SESSION_ERRINFO, &localErrorInfo,
					     "Couldn't sign SSH_MSG_USERAUTH_REQUEST packet" ) );
			}

		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Verification of client's %s public-key "
					 "authentication failed", getAlgoName( pkcAlgo ) ) );
		}

	/* Some buggy implementations require that RSA signatures be padded with 
	   zeroes to the full modulus size, mysteriously failing the 
	   authentication in a small number of randomly-distributed cases when 
	   the signature format happens to be less than the modulus size.  To 
	   handle this we have to rewrite the signature to include the extra 
	   padding bytes */
	if( createSignature )
		{
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, 
					   SSH_PFLAG_RSASIGPAD ) && pkcAlgo == CRYPT_ALGO_RSA )
			{
			status = rewriteRSASignature( sessionInfoPtr, stream, sigLength, 
										  min( sigDataLength, \
											   MAX_INTLENGTH_SHORT - 1 ) );
			}
		else
			status = sSkip( stream, sigLength, MAX_INTLENGTH_SHORT );
		}

	return( status );
	}

/****************************************************************************
*																			*
*								Keyex Functions								*
*																			*
****************************************************************************/

/* Complete the DH/ECDH/25519 key agreement */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int completeSSHKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					  INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo,
					  IN_BOOL const BOOLEAN isServer )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	MESSAGE_DATA msgData;
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* Read the other side's key agreement information.  Note that the size
	   check has already been performed at a higher level when the overall
	   key agreement value was read, this is a secondary check of the MPI
	   payload */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	if( isServer )
		{
		sMemConnect( &stream, handshakeInfo->clientKeyexValue,
					 handshakeInfo->clientKeyexValueLength );
		}
	else
		{
		sMemConnect( &stream, handshakeInfo->serverKeyexValue,
					 handshakeInfo->serverKeyexValueLength );
		}
	switch( handshakeInfo->keyexAlgo )
		{
		case CRYPT_ALGO_DH:
			status = readInteger32( &stream, keyAgreeParams.publicValue,
									&keyAgreeParams.publicValueLen, 
									MIN_PKCSIZE, CRYPT_MAX_PKCSIZE,
									BIGNUM_CHECK_VALUE_PKC );
			break;

#ifdef USE_ECDH		
		case CRYPT_ALGO_ECDH:		
			/* This is actually a String32 and not an Integer32, however the formats 
			   are identical and we need to read the value as an integer to take 
			   advantage of the range-checking */
			status = readInteger32( &stream, keyAgreeParams.publicValue,
									&keyAgreeParams.publicValueLen, 
									MIN_PKCSIZE_ECCPOINT, MAX_PKCSIZE_ECCPOINT,
									BIGNUM_CHECK_VALUE_ECC );
			break;
#endif /* USE_ECDH */

#ifdef USE_25519
		case CRYPT_ALGO_25519:
			/* The 25519 data must be exactly 32 bytes */
			status = readString32( &stream, keyAgreeParams.publicValue,
								   32, &keyAgreeParams.publicValueLen );
			if( cryptStatusOK( status ) && \
				keyAgreeParams.publicValueLen != 32 )
				status = CRYPT_ERROR_BADDATA;
			break;
#endif /* USE_25519 */
	
		default:
			retIntError();		
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid %s phase 1 value",
				  getAlgoName( handshakeInfo->keyexAlgo ) ) );
		}
	status = checkKeyexValueLength( handshakeInfo, &keyAgreeParams, 
									KEYEX_CHECK_MPI, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're fuzzing then there's no crypto active */
	FUZZ_SKIP_REMAINDER();

	/* Perform phase 2 of the DH/ECDH/25519 key agreement */
	status = krnlSendMessage( handshakeInfo->iServerCryptContext,
							  IMESSAGE_CTX_DECRYPT, &keyAgreeParams,
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusOK( status ) && handshakeInfo->isECDH && \
		!isBernsteinAlgo( handshakeInfo->keyexAlgo ) )
		{
		const int xCoordLen = ( keyAgreeParams.wrappedKeyLen - 1 ) / 2;

		/* The output of the ECDH operation is an ECC point, but for some
		   unknown reason SSH only uses the x coordinate and not the full
		   point.  To work around this we have to rewrite the point as a
		   standalone x coordinate, which is relatively easy because we're
		   using the uncompressed point format:

			+---+---------------+---------------+
			|04	|		qx		|		qy		|
			+---+---------------+---------------+
				|<- fldSize --> |<- fldSize --> | */
		REQUIRES( keyAgreeParams.wrappedKeyLen >= MIN_PKCSIZE_ECCPOINT && \
				  keyAgreeParams.wrappedKeyLen <= MAX_PKCSIZE_ECCPOINT && \
				  ( keyAgreeParams.wrappedKeyLen & 1 ) == 1 && \
				  keyAgreeParams.wrappedKey[ 0 ] == 0x04 );
		REQUIRES( boundsCheck( 1, xCoordLen, CRYPT_MAX_PKCSIZE ) );
		memmove( keyAgreeParams.wrappedKey,
				 keyAgreeParams.wrappedKey + 1, xCoordLen );
		keyAgreeParams.wrappedKeyLen = xCoordLen;
		}
	if( cryptStatusOK( status ) )
		{
		REQUIRES( rangeCheck( keyAgreeParams.wrappedKeyLen, 1,
							  CRYPT_MAX_PKCSIZE ) );
		memcpy( handshakeInfo->secretValue, keyAgreeParams.wrappedKey,
				keyAgreeParams.wrappedKeyLen );
		handshakeInfo->secretValueLength = keyAgreeParams.wrappedKeyLen;
		}
	zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using negotiated DH, hash the requested keyex key length(s)
	   and DH p and g values.  Since this has been deferred until long after
	   the keyex negotiation took place (so that the original data isn't 
	   available any more) we have to recreate the original encoded values 
	   here */
	if( !handshakeInfo->isFixedDH && !handshakeInfo->isECDH )
		{
		BYTE keyexBuffer[ 128 + ( CRYPT_MAX_PKCSIZE * 2 ) + 8 ];
		const int extraLength = LENGTH_SIZE + sizeofString32( 6 );

		status = krnlSendMessage( handshakeInfo->iExchangeHashContext,
								  IMESSAGE_CTX_HASH,
								  handshakeInfo->encodedReqKeySizes,
								  handshakeInfo->encodedReqKeySizesLength );
		if( cryptStatusError( status ) )
			return( status );
		setMessageData( &msgData, keyexBuffer,
						128 + ( CRYPT_MAX_PKCSIZE * 2 ) );
		status = krnlSendMessage( handshakeInfo->iServerCryptContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_SSH );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( handshakeInfo->iExchangeHashContext,
									  IMESSAGE_CTX_HASH, 
									  keyexBuffer + extraLength,
									  msgData.length - extraLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Hash the client and server DH/ECDH/25519 values and shared secret */
	status = krnlSendMessage( handshakeInfo->iExchangeHashContext, 
							  IMESSAGE_CTX_HASH,
							  handshakeInfo->clientKeyexValue,
							  handshakeInfo->clientKeyexValueLength );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( handshakeInfo->iExchangeHashContext, 
								  IMESSAGE_CTX_HASH,
								  handshakeInfo->serverKeyexValue,
								  handshakeInfo->serverKeyexValueLength );
		}
	if( cryptStatusOK( status ) )
		{
		status = hashAsMPI( handshakeInfo->iExchangeHashContext,
							handshakeInfo->secretValue,
							handshakeInfo->secretValueLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Complete the hashing to obtain the exchange hash and then hash *that*
	   to get the hash that the server signs and sends to the client.  The
	   overall hashed data for the exchange hash is:

		string	V_C, client version string (CR and NL excluded)
		string	V_S, server version string (CR and NL excluded)
		string	I_C, client hello
		string	I_S, server hello
		string	K_S, the host key
	 [[	uint32	min, min.preferred keyex key size for ephemeral DH ]]
	  [	uint32	n, preferred keyex key size for ephemeral DH ]
	 [[	uint32	max, max.preferred keyex key size for ephemeral DH ]]
	  [	mpint	p, DH p for ephemeral DH ]
	  [	mpint	g, DH g for ephemeral DH ]
	   DH:
		mpint	e, client DH keyex value
		mpint	f, server DH keyex value
	   ECDH:
		string	Q_C, client ECDH keyex value
		string	Q_S, server ECDH keyex value
		mpint	K, the shared secret
	   25519:
		string	pubValue_C, client 25519 keyex value
		string	pubValue_S, server 25519 keyex value
		string	privValue, the shared secret

	   The client and server version string ahd hellos and the host key were
	   hashed inline during the handshake.  The optional parameters are for
	   negotiated DH values (see the conditional-hashing code above).  The
	   double-optional parameters are for the revised version of the DH
	   negotiation mechanism, the original only had n, the revised version
	   allowed a { min, n, max } range */
	status = krnlSendMessage( handshakeInfo->iExchangeHashContext, 
							  IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, handshakeInfo->sessionID, 
						CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( handshakeInfo->iExchangeHashContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusOK( status ) )
			{
			handshakeInfo->sessionIDlength = msgData.length;
			INJECT_FAULT( SESSION_SSH_CORRUPT_EXCHANGE_HASH, 
						  SESSION_SSH_CORRUPT_EXCHANGE_HASH_1 );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We now need a workaround for the Bernstein special-snowflake 
	   algorithms that don't sign a hash but want to sign the entire
	   message.  Fortunately we're saved by the fact that the exchange hash 
	   is a double hash, by saving a copy of the first hash we get the 
	   message that Ed25519 wants to sign */
#ifdef USE_ED25519
	if( handshakeInfo->pubkeyAlgo == CRYPT_ALGO_ED25519 )
		{
		setMessageData( &msgData, handshakeInfo->preExchangeHash, 
						CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( handshakeInfo->iExchangeHashContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->preExchangeHashLength = msgData.length;
		}
#endif /* USE_ED25519 */

	/* At this point we continue the hash-algorithm dance, in most cases 
	   switching back to SHA-1 if we've been using a different algorithm for 
	   the hashing so far.  This is required because while the exchange hash 
	   is calculated using the alternative algorithm that was negotiated 
	   earlier, what gets signed is a SHA-1 hash of that.  Exceptions to 
	   this occur when we're either using an ECC cipher suite or when the 
	   use of SHA-2 has been explicitly indicated, in which case we 
	   stick with SHA-2 */
	if( handshakeInfo->exchangeHashAlgo != handshakeInfo->hashAlgo )
		{
		const CRYPT_CONTEXT tempContext = handshakeInfo->iExchangeHashContext;

		handshakeInfo->iExchangeHashContext = \
				handshakeInfo->iExchangeHashAltContext;
		handshakeInfo->iExchangeHashAltContext = tempContext;
		}
	krnlSendMessage( handshakeInfo->iExchangeHashContext,
					 IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( handshakeInfo->iExchangeHashContext,
					 IMESSAGE_CTX_HASH, handshakeInfo->sessionID,
					 handshakeInfo->sessionIDlength );
	INJECT_FAULT( BADSIG_HASH, SESSION_BADSIG_HASH_SSH_1 );
	return( krnlSendMessage( handshakeInfo->iExchangeHashContext,
							 IMESSAGE_CTX_HASH, "", 0 ) );
	}
#endif /* USE_SSH */
