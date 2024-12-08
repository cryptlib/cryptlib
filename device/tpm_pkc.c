<<<<<<< HEAD
/****************************************************************************
*																			*
*							cryptlib TPM PKC Routines						*
*						Copyright Peter Gutmann 2020-2022					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "tpm.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "device/tpm.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_TPM

/****************************************************************************
*																			*
*						 		Utility Functions							*
*																			*
****************************************************************************/

/* Get the device's FAPI_CONTEXT from an encryption context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getFapiContext( IN_PTR const CONTEXT_INFO *contextInfoPtr,
						   OUT_OPT_PTR FAPI_CONTEXT **fapiContexPtr )
	{
	CRYPT_DEVICE iCryptDevice;
	const DEVICE_INFO *deviceInfoPtr;
	FAPI_CONTEXT *fapiContext;
	int status;

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( fapiContexPtr, sizeof( FAPI_CONTEXT * ) ) );

	/* Clear return value */
	*fapiContexPtr = NULL;

	/* Get the the device associated with this context */
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the TPM information from the device information */
	status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( MESSAGE_PTR_CAST ) &deviceInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	fapiContext = ( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;
	krnlReleaseObject( iCryptDevice );
	ENSURES( fapiContext != NULL );

	*fapiContexPtr = fapiContext;

	return( CRYPT_OK );
	}

/* Because of the weird way that FAPI works with keys in TPMs where the name 
   used to access it decides what the key can do we have to restrict things
   as far as possible to match what the API forces upon us.  For straight
   public vs. private key usages this isn't a problem because cryptlib 
   always creates native objects for public-key operations since they're 
   much faster than device ones where the devices are typically smart cards.  

   In theory we could enable public-key operations on the private-key 
   objects as well because they'd never get used as such, however they will 
   actually get used when performing a pairwise consistency check after 
   signing, which leads to problems because the xxxVerify() functions return 
   an internal error if called.  Because of this we don't enable public-key 
   operations for private-key objects even if the device is theoretically 
   capable of doing this */

static int updateActionFlags( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							  IN_BOOL const BOOLEAN isPrivateKey )
	{
	int actionFlags = 0;

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isConvAlgo( cryptAlgo ) || isPkcAlgo( cryptAlgo ) || \
			  isMacAlgo( cryptAlgo ) );
	REQUIRES( isBooleanValue( isPrivateKey ) );

	if( isConvAlgo( cryptAlgo ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		}
	if( isPkcAlgo( cryptAlgo ) && isPrivateKey )
		{
		if( isCryptAlgo( cryptAlgo ) )
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		if( isSigAlgo( cryptAlgo ) )
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
		if( cryptAlgo == CRYPT_ALGO_RSA )
			{
			/* Because of the weird way in which the TPM API ties RSA 
			   formatting to the key type used there's no way to perform 
			   general purpose RSA encryption or decryption, so we make the
			   context internal-only to ensure that it's only called from the
			   appropriate cryptlib functions */
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
			}
		if( isDlpAlgo( cryptAlgo ) || isEccAlgo( cryptAlgo ) )
			{
			/* Because of the special-case data formatting requirements for 
			   DLP/ECDLP algorithms we make the usage internal-only */
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
			}
		}
	if( isMacAlgo( cryptAlgo ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_ALL );

	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, 
							 ( MESSAGE_CAST ) &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Perform a self-test */

CHECK_RETVAL \
static int selfTestFunction( void )
	{
	/* There's no easy way to perform a self-test, however it's probably 
	   done by the TPM on power-up so we assume that the test has 
	   succeeded */
	return( CRYPT_OK );
	}

/* Encrypt/decrypt / sig-check/sign a data block */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
							IN_LENGTH_SHORT int noBytes )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* This function is present but isn't used as part of any normal 
	   operation because cryptlib does the same thing much faster in 
	   software and because some tokens don't support public-key 
	   operations */
	DEBUG_DIAG(( "Warning: encryptFunction() called for device object, "
				 "should be handled via native object" ));

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
							IN_LENGTH_SHORT int noBytes )
	{
	FAPI_CONTEXT *fapiContext;
	MESSAGE_DATA msgData;
	BYTE objectPath[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE storageIDbuffer[ KEYID_SIZE + 8 ];
	BYTE *fapiData;
	TSS2_RC tssResult;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	size_t fapiDataLength;
	LOOP_INDEX i;
	int objectPathLen, padSize, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* Get the FAPI context for the encryption context */
	status = getFapiContext( contextInfoPtr, &fapiContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the storageID mapping the context to the TPM object */
	setMessageData( &msgData, storageIDbuffer, KEYID_SIZE );
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_DEVICESTORAGEID );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the magic string used to identify the key type and location */
	status = tpmGetObjectPath( objectPath, CRYPT_MAX_TEXTSIZE, 
							   &objectPathLen, CRYPT_ALGO_RSA,
							   storageIDbuffer, KEYID_SIZE );
	ENSURES( cryptStatusOK( status ) );

	/* Decrypt the data.  FAPI doesn't use user-supplied buffers but 
	   allocates a new memory block each time, which we have to copy back 
	   out to the caller */
	tssResult = Fapi_Decrypt( fapiContext, objectPath, buffer, noBytes, 
							  &fapiData, &fapiDataLength );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	/* Create dummy PKCS #1 padding around the recovered key */
	padSize = keySize - fapiDataLength;
	REQUIRES( isShortIntegerRangeNZ( padSize ) );

	/* Redo the PKCS #1 padding.  Note that this doesn't have to be 
	   cryptographically strong since it gets stripped as soon as we return 
	   to the caller, it just has to be random:

	  bufPtr							 keySize
		|									|
		+---+---+------------+---+----------+
		| 0 | 2 |   random   | 0 |   key    |
		+---+---+------------+---+----------+
				|			 |	 |			|
				<------------>	 <---------->
				 keySize -		  fapiDataLen
				 fapiDataLen - 3

	   This gets a bit ugly because the random padding has to be nonzero, 
	   which would require using the non-nonce RNG.  To work around this, we 
	   look for any zeroes in the data and fill them with some other value */
	buffer[ 0 ] = 0;
	buffer[ 1 ] = 2;
	setMessageData( &msgData, buffer + 2, padSize - 3 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	LOOP_EXT( i = 2, i < padSize - 1, i++, CRYPT_MAX_PKCSIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 2, padSize - 2,
									 CRYPT_MAX_PKCSIZE + 1 ) );

		if( buffer[ i ] == 0 )
			{
			/* Create some sort of non-constant non-zero value to replace 
			   the zero byte with, since PKCS #1 can't have zero bytes.  
			   This doesn't have to be a strong random value, it just has to 
			   vary a bit */
			const int pad = 0xAA ^ ( i & 0xFF );
			buffer[ i ] = pad ? intToByte( pad ) : 0x21;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	buffer[ padSize - 1 ] = 0;
	ENSURES( 2 + ( padSize - 3 ) + 1 + fapiDataLength == keySize );
	REQUIRES( boundsCheck( padSize, fapiDataLength, noBytes ) );
	memcpy( buffer + padSize, fapiData, fapiDataLength );

	/* Clean up */
	zeroise( fapiData, fapiDataLength );
	Fapi_Free( fapiData );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sigCheck( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					 INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					 IN_LENGTH_SHORT int noBytes )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* This function is present but isn't used as part of any normal 
	   operation because cryptlib does the same thing much faster in 
	   software and because some tokens don't support public-key 
	   operations */
	DEBUG_DIAG(( "Warning: sigCheck() called for device object, should be "
				 "handled via native object" ));

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sign( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				 INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
				 IN_LENGTH_SHORT int noBytes )
	{
	CRYPT_ALGO_TYPE hashAlgo;
	FAPI_CONTEXT *fapiContext;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE objectPath[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE storageIDbuffer[ KEYID_SIZE + 8 ];
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE *fapiData;
	TSS2_RC tssResult;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	size_t fapiDataLength;
	LOOP_INDEX i;
	int objectPathLen, hashSize DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* Undo the PKCS #1 padding to get the raw hash value */
	LOOP_MAX( i = 2, i < keySize, i++ )
		{
		ENSURES( LOOP_INVARIANT_MAX( i, 2, keySize - 1 ) );

		if( buffer[ i ] == 0 )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	i++;	/* Skip final 0 byte */

	/* Now we're at the encoded message digest, remove the encoding to get 
	   to the raw hash value */
	sMemConnect( &stream, buffer + i, noBytes - i );
	status = readMessageDigest( &stream, &hashAlgo, hashValue, 
								CRYPT_MAX_HASHSIZE, &hashSize );
	sMemDisconnect( &stream );
	ENSURES( cryptStatusOK( status ) );

	/* Since the TPM API hardcodes the hash algorithm into the path used to 
	   access the key (see the comment in generateKeyFunction()), we can 
	   only use the hash algorithm that's hardcoded for the key, in this 
	   case SHA-256 */
	if( hashAlgo != CRYPT_ALGO_SHA2 || hashSize != bitsToBytes( 256 ) )
		{
		DEBUG_DIAG(( "Fapi_Sign() for RSA only accepts SHA-256 as the hash "
					 "algorithm." ));
		return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Get the FAPI context for the encryption context */
	status = getFapiContext( contextInfoPtr, &fapiContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the storageID mapping the context to the TPM object */
	setMessageData( &msgData, storageIDbuffer, KEYID_SIZE );
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_DEVICESTORAGEID );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the magic string used to identify the key type and location */
	status = tpmGetObjectPath( objectPath, CRYPT_MAX_TEXTSIZE, 
							   &objectPathLen, CRYPT_ALGO_RSA,
							   storageIDbuffer, KEYID_SIZE );
	ENSURES( cryptStatusOK( status ) );

	/* Sign the data.  FAPI doesn't use user-supplied buffers but allocates 
	   a new memory block each time, which we have to copy back out to the 
	   caller.  The only mechanism that we advertise is PKCS #1, so the 
	   padding string is set to "RSA_SSA", if we wanted to use the other
	   option, "RSA_PSS", we'd have to provide an interface at the 
	   mechanism level */
	tssResult = Fapi_Sign( fapiContext, objectPath, "RSA_SSA", 
						   hashValue, hashSize, &fapiData, &fapiDataLength, 
						   NULL, NULL );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	/* Copy the result to the caller */
	if( fapiDataLength > noBytes )
		status = CRYPT_ERROR_OVERFLOW;
	else
		{
		REQUIRES( rangeCheck( fapiDataLength, 1, noBytes ) );
		memcpy( buffer, fapiData, fapiDataLength );
		}

	/* Clean up */
	zeroise( fapiData, fapiDataLength );
	Fapi_Free( fapiData );

	return( status );
	}

/* Load a key.  This isn't possible with FAPI so we always return a not-
   available error */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initKeyFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							IN_BUFFER_OPT( keyLength ) const void *key,
							IN_LENGTH_SHORT_OPT const int keyLength )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( key == NULL && keyLength == 0 ) || \
			( isReadPtrDynamic( key, keyLength ) && \
			  keyLength == sizeof( CRYPT_PKCINFO_RSA ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( ( key == NULL && keyLength == 0 ) || \
			  ( key != NULL && keyLength == sizeof( CRYPT_PKCINFO_RSA ) ) );

	return( CRYPT_ERROR_NOTAVAIL );
	}

/* Generate a key.  The functionality provided by Fapi_CreateKey() is
   essentially unspecified, "The cryptographic profiles are configured in an
   implementation specific way" so there's no way to specify an algorithm,
   key size, or anything else apart from hardcoding it into the key path
   and hoping that the TPM driver supports it.
   
   Making things even crazier, the generated keys aren't referenced by
   something like a handle once created but by the absolute path used to
   create them, so the crypto object is instantiated each time that it's
   used.
   
   In addition since the path also encodes a bunch of other algorithm 
   details like, for example for public keys, the hash algorithm used with
   a signing key, it's not possible to use a signing key with two different
   hash algorithms.
   
   Finally, what's returned isn't any simple structure but an enormously-
   nested mess of structs and unions for which we have to pick bits and 
   pieces of key data out of various different levels:

	typedef struct {
		UINT16 size;
		TPMT_PUBLIC publicArea;			// Path 0
		} TPM2B_PUBLIC;
   
	typedef struct {					// Path 0
		TPMI_ALG_PUBLIC type;
		TPMI_ALG_HASH nameAlg;
		TPMA_OBJECT objectAttributes;
		TPM2B_DIGEST authPolicy;
		TPMU_PUBLIC_PARMS parameters;	// Path 1
		TPMU_PUBLIC_ID unique;			// Path 2
		} TPMT_PUBLIC;

	typedef union {						// Path 1
		TPMS_KEYEDHASH_PARMS keyedHashDetail;
		TPMT_SYM_DEF_OBJECT symDetail;
		TPMS_RSA_PARMS rsaDetail;		// Path 1
		TPMS_ECC_PARMS eccDetail;
		TPMS_ASYM_PARMS asymDetail;
		} TPMU_PUBLIC_PARMS;
 
	typedef struct {					// Path 1
		TPMT_SYM_DEF_OBJECT symmetric;
		TPMT_RSA_SCHEME scheme;
		TPMI_RSA_KEY_BITS keyBits;		// Value = keysize
		UINT32 exponent;				// Value = e
		} TPMS_RSA_PARMS;

	typedef union {						// Path 2
		TPM2B_DIGEST keyedHash;
		TPM2B_DIGEST sym;
		TPM2B_PUBLIC_KEY_RSA rsa;		// Path 2
		TPMS_ECC_POINT ecc;
		} TPMU_PUBLIC_ID;

	typedef struct {					// Path 2
		UINT16 size;
		BYTE buffer[ MAX_RSA_KEY_BYTES ];// Value = n
		} TPM2B_PUBLIC_KEY_RSA; */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateKeyFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
								IN_LENGTH_SHORT_MIN( MIN_PKCSIZE * 8 ) \
									const int keySizeBits )
	{
	FAPI_CONTEXT *fapiContext;
	TPM2B_PUBLIC tpm2BPubkey DUMMY_INIT_STRUCT;
	TPMT_PUBLIC *tpmtPubkey;
	TPMS_RSA_PARMS *rsaParams;
	TPM2B_PUBLIC_KEY_RSA *rsaPubKey;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE eBuffer[ 8 + 8 ], *eValue;
	BYTE keyDataBuffer[ ( CRYPT_MAX_PKCSIZE * 2 ) + 8 ];
	BYTE objectPath[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE storageIDbuffer[ KEYID_SIZE + 8 ];
	BYTE *keyBlob;
	TSS2_RC tssResult;
	size_t keyBlobSize, dummy;
	long exponent;
	int objectPathLen, keySize, eSize DUMMY_INIT;
	int keyDataSize DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Get the FAPI context for the encryption context */
	status = getFapiContext( contextInfoPtr, &fapiContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the storage ID needed to refer to the context by providing a 
	   unique identifier to refer to the key in the TPM */
	setMessageData( &msgData, storageIDbuffer, KEYID_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the magic string used to identify the key type and location */
	status = tpmGetObjectPath( objectPath, CRYPT_MAX_TEXTSIZE, 
							   &objectPathLen, CRYPT_ALGO_RSA,
							   storageIDbuffer, KEYID_SIZE );
	ENSURES( cryptStatusOK( status ) );

	/* Generate the key */
	tssResult = Fapi_CreateKey( fapiContext, objectPath, 
								"sign,decrypt", NULL, NULL );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	/* Read back the public-key data.  This brings up one of the many booby
	   traps in the TPM APIs in that the tpm2bPublic isn't actually a 
	   TPM2B_PUBLIC but an unknown-format blob that has to be converted into
	   a TPM2B_PUBLIC via a function from a completely different API family
	   to FAPI.  So after getting the key blob we pass it on to an MU API 
	   function to get what we actually need */
	tssResult = Fapi_GetTpmBlobs( fapiContext, objectPath, &keyBlob, 
								  &keyBlobSize, NULL, NULL, NULL );
	if( tssResult == TSS2_RC_SUCCESS )
		{
		tssResult = Tss2_MU_TPM2B_PUBLIC_Unmarshal( keyBlob, keyBlobSize, 
													&dummy, &tpm2BPubkey );
		}
	if( tssResult != TSS2_RC_SUCCESS )
		{
		( void ) Fapi_Delete( fapiContext, objectPath );
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );
		}

	/* Get pointers to the structures that we want from inside the mess of 
	   structs and unions involved (see the comment at the start of the 
	   function).  To make sure that we've actually got what we think we're
	   getting we apply some basic sanity checks using known fields in each 
	   structure.  In some of these cases it's complete pot luck what this 
	   will be, for example for the scheme we can have any of 
	   TPM_ALG_RSASSA = PKCS #1, TPM_ALG_RSAES = OAEP, or TPM_ALG_RSAPSS =
	   PSS, with both no control over what we're getting and the actual name 
	   being hidden behind random alphabet sssoup.  In any case for the
	   near-unversal Intel-derived TPM2 code what we actually get in practice
	   is TPM2_ALG_NULL, whatever that may mean beyond "nobody ever checked
	   this code" */
	ENSURES( tpm2BPubkey.size == sizeof( TPM2B_PUBLIC ) );
	tpmtPubkey = &tpm2BPubkey.publicArea;
	ENSURES( tpmtPubkey->type == TPM2_ALG_RSA );
	rsaParams = &tpmtPubkey->parameters.rsaDetail;
	ENSURES( rsaParams->keyBits >= bytesToBits( MIN_PKCSIZE ) && \
			 rsaParams->keyBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	ENSURES( rsaParams->scheme.scheme == TPM2_ALG_NULL );
	ENSURES( rsaParams->exponent == 0 || \
			 ( rsaParams->exponent >= 3 && \
			   rsaParams->exponent < 0x10000000L ) );
	rsaPubKey = &tpmtPubkey->unique.rsa;
	ENSURES( rsaPubKey->size >= MIN_PKCSIZE && \
			 rsaPubKey->size <= TPM2_MAX_RSA_KEY_BYTES );
	keySize = bitsToBytes( rsaParams->keyBits );

	/* Now we run into another bug or specification error or something 
	   (there's no documentation for this so we can't tell, "the behaviour 
	   of a program without a specification can never be wrong, merely 
	   surprising") where the exponent value can be zero.  The only clue as 
	   to what to do here is in the tpm2_print utility, which uses
	   'r->exponent ? r->exponent : 65537' to deal with this, so we do the
	   same */
	exponent = ( rsaParams->exponent > 0 ) ? rsaParams->exponent : 65537L;

	/* Format the RSA e value, which is stored as an integer rather than a
	   bignum byte string, as a bignum byte string.  This requires writing
	   the value as an ASN.1 INTEGER and then skipping the tag and length
	   bytes at the start */
	sMemOpen( &stream, eBuffer, 8 );
	status = writeShortInteger( &stream, exponent, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		eSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		Fapi_Free( keyBlob );
		( void ) Fapi_Delete( fapiContext, objectPath );
		return( status );
		}
	eSize -= 1 + 1;					/* Skip tag + length */
	eValue = eBuffer + 1 + 1;

	/* Send the public key data to the context.  We send the keying 
	   information as CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL rather than 
	   CRYPT_IATTRIBUTE_KEY_SPKI since the latter transitions the context 
	   into the high state.  We don't want to do this because we're already 
	   in the middle of processing a message that does this on completion, 
	   all that we're doing here is sending in encoded public key data for 
	   use by objects such as certificates */
	if( cryptStatusOK( status ) )
		{
		status = writeFlatPublicKey( keyDataBuffer, CRYPT_MAX_PKCSIZE * 2,
									 &keyDataSize, CRYPT_ALGO_RSA, 0,
									 rsaPubKey->buffer, rsaPubKey->size, 
									 eValue, eSize, NULL, 0, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyDataBuffer, keyDataSize );
		status = krnlSendMessage( contextInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( contextInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE, &keySize, 
								  CRYPT_IATTRIBUTE_KEYSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = updateActionFlags( contextInfoPtr->objectHandle,
									CRYPT_ALGO_RSA, TRUE );
		}
	if( cryptStatusError( status ) )
		{
		Fapi_Free( keyBlob );
		( void ) Fapi_Delete( fapiContext, objectPath );
		return( status );
		}

	/* Remember that we've now got a key set for the context.  We have to do
	   this explicitly since we've bypassed the standard key-load process */
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );

	/* Persist the metadata for the key so that we can look it up later.  
	   The call looks a bit odd because there's no device to persist it to 
	   given in the arguments, that's because it's being called from 
	   functions working with context info rather than device info so the 
	   device info is implicitly taken from the context info */
	status = persistContextMetadata( contextInfoPtr, storageIDbuffer, 
									 KEYID_SIZE );
	if( cryptStatusError( status ) )
		{
		Fapi_Free( keyBlob );
		( void ) Fapi_Delete( fapiContext, objectPath );
		return( status );
		}

	/* Clean up */
	Fapi_Free( keyBlob );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Device Capability and Mechanism Routines				*
*																			*
****************************************************************************/

/* The capability information for the TPM, really just private-key ops.  
   There isn't any way to query a TPM for its capabilities (short of
   shelling out to tpm2_getcap and parsing the resulting JSON) so we just 
   have to assume that the default RSA with key size 2048 bits exists */

static const CAPABILITY_INFO capabilities[] = {
	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, bitsToBytes( 0 ), "RSA", 3,
		bitsToBytes( 2048 ), bitsToBytes( 2048 ), bitsToBytes( 2048 ),
		selfTestFunction, getDefaultInfo, NULL, NULL, initKeyFunction, generateKeyFunction, 
		encryptFunction, decryptFunction, NULL, NULL, NULL, NULL, NULL, NULL, 
		sign, sigCheck, readPublicKeyRsaFunction, writePublicKeyRsaFunction },

	/* The end-of-list marker.  This value isn't linked into the 
	   capabilities list when we call initCapabilities() */
	{ CRYPT_ALGO_NONE }, { CRYPT_ALGO_NONE }
	};

/* Mechanisms supported by TPM devices.  These are actually cryptlib native 
   mechanisms layered on top of the TPM crypto, but not the full set 
   supported by the system device since TPMs really only support private-key
   ops.  The list is sorted in order of frequency of use in order to make 
   lookups a bit faster */

static const MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }, { MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

static CAPABILITY_INFO_LIST capabilityInfoList[ 4 ];

/* Initialise and get the capability information */

CHECK_RETVAL \
int tpmInitCapabilities( void )
	{
	int i;

	/* Build the list of available capabilities */
	memset( capabilityInfoList, 0, 
			sizeof( CAPABILITY_INFO_LIST ) * 4 );
	for( i = 0; capabilities[ i ].cryptAlgo != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO ); i++ )
		{
		REQUIRES( sanityCheckCapability( &capabilities[ i ] ) );
		
		DATAPTR_SET( capabilityInfoList[ i ].info, 
					 ( CAPABILITY_INFO * ) &capabilities[ i ] );
		DATAPTR_SET( capabilityInfoList[ i ].next, NULL );
		if( i > 0 )
			{
			DATAPTR_SET( capabilityInfoList[ i - 1 ].next, 
						 &capabilityInfoList[ i ] );
			}
		}
	ENSURES( i < FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int tpmGetCapabilities( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	DATAPTR_SET( deviceInfoPtr->capabilityInfoList, capabilityInfoList );
	DATAPTR_SET( deviceInfoPtr->mechanismFunctions, 
				 ( void * ) mechanismFunctions );
	deviceInfoPtr->mechanismFunctionCount = \
		FAILSAFE_ARRAYSIZE( mechanismFunctions, MECHANISM_FUNCTION_INFO );
	
	return( CRYPT_OK );
	}
#endif /* USE_TPM */
=======
/****************************************************************************
*																			*
*							cryptlib TPM PKC Routines						*
*						Copyright Peter Gutmann 2020-2022					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "tpm.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "device/tpm.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_TPM

/****************************************************************************
*																			*
*						 		Utility Functions							*
*																			*
****************************************************************************/

/* Get the device's FAPI_CONTEXT from an encryption context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getFapiContext( IN_PTR const CONTEXT_INFO *contextInfoPtr,
						   OUT_OPT_PTR FAPI_CONTEXT **fapiContexPtr )
	{
	CRYPT_DEVICE iCryptDevice;
	const DEVICE_INFO *deviceInfoPtr;
	FAPI_CONTEXT *fapiContext;
	int status;

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( fapiContexPtr, sizeof( FAPI_CONTEXT * ) ) );

	/* Clear return value */
	*fapiContexPtr = NULL;

	/* Get the the device associated with this context */
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the TPM information from the device information */
	status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( MESSAGE_PTR_CAST ) &deviceInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	fapiContext = ( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;
	krnlReleaseObject( iCryptDevice );
	ENSURES( fapiContext != NULL );

	*fapiContexPtr = fapiContext;

	return( CRYPT_OK );
	}

/* Because of the weird way that FAPI works with keys in TPMs where the name 
   used to access it decides what the key can do we have to restrict things
   as far as possible to match what the API forces upon us.  For straight
   public vs. private key usages this isn't a problem because cryptlib 
   always creates native objects for public-key operations since they're 
   much faster than device ones where the devices are typically smart cards.  

   In theory we could enable public-key operations on the private-key 
   objects as well because they'd never get used as such, however they will 
   actually get used when performing a pairwise consistency check after 
   signing, which leads to problems because the xxxVerify() functions return 
   an internal error if called.  Because of this we don't enable public-key 
   operations for private-key objects even if the device is theoretically 
   capable of doing this */

static int updateActionFlags( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							  IN_BOOL const BOOLEAN isPrivateKey )
	{
	int actionFlags = 0;

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isConvAlgo( cryptAlgo ) || isPkcAlgo( cryptAlgo ) || \
			  isMacAlgo( cryptAlgo ) );
	REQUIRES( isBooleanValue( isPrivateKey ) );

	if( isConvAlgo( cryptAlgo ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		}
	if( isPkcAlgo( cryptAlgo ) && isPrivateKey )
		{
		if( isCryptAlgo( cryptAlgo ) )
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		if( isSigAlgo( cryptAlgo ) )
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
		if( cryptAlgo == CRYPT_ALGO_RSA )
			{
			/* Because of the weird way in which the TPM API ties RSA 
			   formatting to the key type used there's no way to perform 
			   general purpose RSA encryption or decryption, so we make the
			   context internal-only to ensure that it's only called from the
			   appropriate cryptlib functions */
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
			}
		if( isDlpAlgo( cryptAlgo ) || isEccAlgo( cryptAlgo ) )
			{
			/* Because of the special-case data formatting requirements for 
			   DLP/ECDLP algorithms we make the usage internal-only */
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
			}
		}
	if( isMacAlgo( cryptAlgo ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_ALL );

	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, 
							 ( MESSAGE_CAST ) &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Perform a self-test */

CHECK_RETVAL \
static int selfTestFunction( void )
	{
	/* There's no easy way to perform a self-test, however it's probably 
	   done by the TPM on power-up so we assume that the test has 
	   succeeded */
	return( CRYPT_OK );
	}

/* Encrypt/decrypt / sig-check/sign a data block */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
							IN_LENGTH_SHORT int noBytes )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* This function is present but isn't used as part of any normal 
	   operation because cryptlib does the same thing much faster in 
	   software and because some tokens don't support public-key 
	   operations */
	DEBUG_DIAG(( "Warning: encryptFunction() called for device object, "
				 "should be handled via native object" ));

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
							IN_LENGTH_SHORT int noBytes )
	{
	FAPI_CONTEXT *fapiContext;
	MESSAGE_DATA msgData;
	BYTE objectPath[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE storageIDbuffer[ KEYID_SIZE + 8 ];
	BYTE *fapiData;
	TSS2_RC tssResult;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	size_t fapiDataLength;
	LOOP_INDEX i;
	int objectPathLen, padSize, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* Get the FAPI context for the encryption context */
	status = getFapiContext( contextInfoPtr, &fapiContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the storageID mapping the context to the TPM object */
	setMessageData( &msgData, storageIDbuffer, KEYID_SIZE );
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_DEVICESTORAGEID );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the magic string used to identify the key type and location */
	status = tpmGetObjectPath( objectPath, CRYPT_MAX_TEXTSIZE, 
							   &objectPathLen, CRYPT_ALGO_RSA,
							   storageIDbuffer, KEYID_SIZE );
	ENSURES( cryptStatusOK( status ) );

	/* Decrypt the data.  FAPI doesn't use user-supplied buffers but 
	   allocates a new memory block each time, which we have to copy back 
	   out to the caller */
	tssResult = Fapi_Decrypt( fapiContext, objectPath, buffer, noBytes, 
							  &fapiData, &fapiDataLength );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	/* Create dummy PKCS #1 padding around the recovered key */
	padSize = keySize - fapiDataLength;
	REQUIRES( isShortIntegerRangeNZ( padSize ) );

	/* Redo the PKCS #1 padding.  Note that this doesn't have to be 
	   cryptographically strong since it gets stripped as soon as we return 
	   to the caller, it just has to be random:

	  bufPtr							 keySize
		|									|
		+---+---+------------+---+----------+
		| 0 | 2 |   random   | 0 |   key    |
		+---+---+------------+---+----------+
				|			 |	 |			|
				<------------>	 <---------->
				 keySize -		  fapiDataLen
				 fapiDataLen - 3

	   This gets a bit ugly because the random padding has to be nonzero, 
	   which would require using the non-nonce RNG.  To work around this, we 
	   look for any zeroes in the data and fill them with some other value */
	buffer[ 0 ] = 0;
	buffer[ 1 ] = 2;
	setMessageData( &msgData, buffer + 2, padSize - 3 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	LOOP_EXT( i = 2, i < padSize - 1, i++, CRYPT_MAX_PKCSIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 2, padSize - 2,
									 CRYPT_MAX_PKCSIZE + 1 ) );

		if( buffer[ i ] == 0 )
			{
			/* Create some sort of non-constant non-zero value to replace 
			   the zero byte with, since PKCS #1 can't have zero bytes.  
			   This doesn't have to be a strong random value, it just has to 
			   vary a bit */
			const int pad = 0xAA ^ ( i & 0xFF );
			buffer[ i ] = pad ? intToByte( pad ) : 0x21;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	buffer[ padSize - 1 ] = 0;
	ENSURES( 2 + ( padSize - 3 ) + 1 + fapiDataLength == keySize );
	REQUIRES( boundsCheck( padSize, fapiDataLength, noBytes ) );
	memcpy( buffer + padSize, fapiData, fapiDataLength );

	/* Clean up */
	zeroise( fapiData, fapiDataLength );
	Fapi_Free( fapiData );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sigCheck( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					 INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					 IN_LENGTH_SHORT int noBytes )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* This function is present but isn't used as part of any normal 
	   operation because cryptlib does the same thing much faster in 
	   software and because some tokens don't support public-key 
	   operations */
	DEBUG_DIAG(( "Warning: sigCheck() called for device object, should be "
				 "handled via native object" ));

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sign( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				 INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
				 IN_LENGTH_SHORT int noBytes )
	{
	CRYPT_ALGO_TYPE hashAlgo;
	FAPI_CONTEXT *fapiContext;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE objectPath[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE storageIDbuffer[ KEYID_SIZE + 8 ];
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE *fapiData;
	TSS2_RC tssResult;
	const int keySize = bitsToBytes( contextInfoPtr->ctxPKC->keySizeBits );
	size_t fapiDataLength;
	LOOP_INDEX i;
	int objectPathLen, hashSize DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( noBytes ) );

	/* Undo the PKCS #1 padding to get the raw hash value */
	LOOP_MAX( i = 2, i < keySize, i++ )
		{
		ENSURES( LOOP_INVARIANT_MAX( i, 2, keySize - 1 ) );

		if( buffer[ i ] == 0 )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	i++;	/* Skip final 0 byte */

	/* Now we're at the encoded message digest, remove the encoding to get 
	   to the raw hash value */
	sMemConnect( &stream, buffer + i, noBytes - i );
	status = readMessageDigest( &stream, &hashAlgo, hashValue, 
								CRYPT_MAX_HASHSIZE, &hashSize );
	sMemDisconnect( &stream );
	ENSURES( cryptStatusOK( status ) );

	/* Since the TPM API hardcodes the hash algorithm into the path used to 
	   access the key (see the comment in generateKeyFunction()), we can 
	   only use the hash algorithm that's hardcoded for the key, in this 
	   case SHA-256 */
	if( hashAlgo != CRYPT_ALGO_SHA2 || hashSize != bitsToBytes( 256 ) )
		{
		DEBUG_DIAG(( "Fapi_Sign() for RSA only accepts SHA-256 as the hash "
					 "algorithm." ));
		return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Get the FAPI context for the encryption context */
	status = getFapiContext( contextInfoPtr, &fapiContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the storageID mapping the context to the TPM object */
	setMessageData( &msgData, storageIDbuffer, KEYID_SIZE );
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_DEVICESTORAGEID );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the magic string used to identify the key type and location */
	status = tpmGetObjectPath( objectPath, CRYPT_MAX_TEXTSIZE, 
							   &objectPathLen, CRYPT_ALGO_RSA,
							   storageIDbuffer, KEYID_SIZE );
	ENSURES( cryptStatusOK( status ) );

	/* Sign the data.  FAPI doesn't use user-supplied buffers but allocates 
	   a new memory block each time, which we have to copy back out to the 
	   caller.  The only mechanism that we advertise is PKCS #1, so the 
	   padding string is set to "RSA_SSA", if we wanted to use the other
	   option, "RSA_PSS", we'd have to provide an interface at the 
	   mechanism level */
	tssResult = Fapi_Sign( fapiContext, objectPath, "RSA_SSA", 
						   hashValue, hashSize, &fapiData, &fapiDataLength, 
						   NULL, NULL );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	/* Copy the result to the caller */
	if( fapiDataLength > noBytes )
		status = CRYPT_ERROR_OVERFLOW;
	else
		{
		REQUIRES( rangeCheck( fapiDataLength, 1, noBytes ) );
		memcpy( buffer, fapiData, fapiDataLength );
		}

	/* Clean up */
	zeroise( fapiData, fapiDataLength );
	Fapi_Free( fapiData );

	return( status );
	}

/* Load a key.  This isn't possible with FAPI so we always return a not-
   available error */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initKeyFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							IN_BUFFER_OPT( keyLength ) const void *key,
							IN_LENGTH_SHORT_OPT const int keyLength )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( key == NULL && keyLength == 0 ) || \
			( isReadPtrDynamic( key, keyLength ) && \
			  keyLength == sizeof( CRYPT_PKCINFO_RSA ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( ( key == NULL && keyLength == 0 ) || \
			  ( key != NULL && keyLength == sizeof( CRYPT_PKCINFO_RSA ) ) );

	return( CRYPT_ERROR_NOTAVAIL );
	}

/* Generate a key.  The functionality provided by Fapi_CreateKey() is
   essentially unspecified, "The cryptographic profiles are configured in an
   implementation specific way" so there's no way to specify an algorithm,
   key size, or anything else apart from hardcoding it into the key path
   and hoping that the TPM driver supports it.
   
   Making things even crazier, the generated keys aren't referenced by
   something like a handle once created but by the absolute path used to
   create them, so the crypto object is instantiated each time that it's
   used.
   
   In addition since the path also encodes a bunch of other algorithm 
   details like, for example for public keys, the hash algorithm used with
   a signing key, it's not possible to use a signing key with two different
   hash algorithms.
   
   Finally, what's returned isn't any simple structure but an enormously-
   nested mess of structs and unions for which we have to pick bits and 
   pieces of key data out of various different levels:

	typedef struct {
		UINT16 size;
		TPMT_PUBLIC publicArea;			// Path 0
		} TPM2B_PUBLIC;
   
	typedef struct {					// Path 0
		TPMI_ALG_PUBLIC type;
		TPMI_ALG_HASH nameAlg;
		TPMA_OBJECT objectAttributes;
		TPM2B_DIGEST authPolicy;
		TPMU_PUBLIC_PARMS parameters;	// Path 1
		TPMU_PUBLIC_ID unique;			// Path 2
		} TPMT_PUBLIC;

	typedef union {						// Path 1
		TPMS_KEYEDHASH_PARMS keyedHashDetail;
		TPMT_SYM_DEF_OBJECT symDetail;
		TPMS_RSA_PARMS rsaDetail;		// Path 1
		TPMS_ECC_PARMS eccDetail;
		TPMS_ASYM_PARMS asymDetail;
		} TPMU_PUBLIC_PARMS;
 
	typedef struct {					// Path 1
		TPMT_SYM_DEF_OBJECT symmetric;
		TPMT_RSA_SCHEME scheme;
		TPMI_RSA_KEY_BITS keyBits;		// Value = keysize
		UINT32 exponent;				// Value = e
		} TPMS_RSA_PARMS;

	typedef union {						// Path 2
		TPM2B_DIGEST keyedHash;
		TPM2B_DIGEST sym;
		TPM2B_PUBLIC_KEY_RSA rsa;		// Path 2
		TPMS_ECC_POINT ecc;
		} TPMU_PUBLIC_ID;

	typedef struct {					// Path 2
		UINT16 size;
		BYTE buffer[ MAX_RSA_KEY_BYTES ];// Value = n
		} TPM2B_PUBLIC_KEY_RSA; */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateKeyFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
								IN_LENGTH_SHORT_MIN( MIN_PKCSIZE * 8 ) \
									const int keySizeBits )
	{
	FAPI_CONTEXT *fapiContext;
	TPM2B_PUBLIC tpm2BPubkey DUMMY_INIT_STRUCT;
	TPMT_PUBLIC *tpmtPubkey;
	TPMS_RSA_PARMS *rsaParams;
	TPM2B_PUBLIC_KEY_RSA *rsaPubKey;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE eBuffer[ 8 + 8 ], *eValue;
	BYTE keyDataBuffer[ ( CRYPT_MAX_PKCSIZE * 2 ) + 8 ];
	BYTE objectPath[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE storageIDbuffer[ KEYID_SIZE + 8 ];
	BYTE *keyBlob;
	TSS2_RC tssResult;
	size_t keyBlobSize, dummy;
	long exponent;
	int objectPathLen, keySize, eSize DUMMY_INIT;
	int keyDataSize DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Get the FAPI context for the encryption context */
	status = getFapiContext( contextInfoPtr, &fapiContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the storage ID needed to refer to the context by providing a 
	   unique identifier to refer to the key in the TPM */
	setMessageData( &msgData, storageIDbuffer, KEYID_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the magic string used to identify the key type and location */
	status = tpmGetObjectPath( objectPath, CRYPT_MAX_TEXTSIZE, 
							   &objectPathLen, CRYPT_ALGO_RSA,
							   storageIDbuffer, KEYID_SIZE );
	ENSURES( cryptStatusOK( status ) );

	/* Generate the key */
	tssResult = Fapi_CreateKey( fapiContext, objectPath, 
								"sign,decrypt", NULL, NULL );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	/* Read back the public-key data.  This brings up one of the many booby
	   traps in the TPM APIs in that the tpm2bPublic isn't actually a 
	   TPM2B_PUBLIC but an unknown-format blob that has to be converted into
	   a TPM2B_PUBLIC via a function from a completely different API family
	   to FAPI.  So after getting the key blob we pass it on to an MU API 
	   function to get what we actually need */
	tssResult = Fapi_GetTpmBlobs( fapiContext, objectPath, &keyBlob, 
								  &keyBlobSize, NULL, NULL, NULL );
	if( tssResult == TSS2_RC_SUCCESS )
		{
		tssResult = Tss2_MU_TPM2B_PUBLIC_Unmarshal( keyBlob, keyBlobSize, 
													&dummy, &tpm2BPubkey );
		}
	if( tssResult != TSS2_RC_SUCCESS )
		{
		( void ) Fapi_Delete( fapiContext, objectPath );
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );
		}

	/* Get pointers to the structures that we want from inside the mess of 
	   structs and unions involved (see the comment at the start of the 
	   function).  To make sure that we've actually got what we think we're
	   getting we apply some basic sanity checks using known fields in each 
	   structure.  In some of these cases it's complete pot luck what this 
	   will be, for example for the scheme we can have any of 
	   TPM_ALG_RSASSA = PKCS #1, TPM_ALG_RSAES = OAEP, or TPM_ALG_RSAPSS =
	   PSS, with both no control over what we're getting and the actual name 
	   being hidden behind random alphabet sssoup.  In any case for the
	   near-unversal Intel-derived TPM2 code what we actually get in practice
	   is TPM2_ALG_NULL, whatever that may mean beyond "nobody ever checked
	   this code" */
	ENSURES( tpm2BPubkey.size == sizeof( TPM2B_PUBLIC ) );
	tpmtPubkey = &tpm2BPubkey.publicArea;
	ENSURES( tpmtPubkey->type == TPM2_ALG_RSA );
	rsaParams = &tpmtPubkey->parameters.rsaDetail;
	ENSURES( rsaParams->keyBits >= bytesToBits( MIN_PKCSIZE ) && \
			 rsaParams->keyBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	ENSURES( rsaParams->scheme.scheme == TPM2_ALG_NULL );
	ENSURES( rsaParams->exponent == 0 || \
			 ( rsaParams->exponent >= 3 && \
			   rsaParams->exponent < 0x10000000L ) );
	rsaPubKey = &tpmtPubkey->unique.rsa;
	ENSURES( rsaPubKey->size >= MIN_PKCSIZE && \
			 rsaPubKey->size <= TPM2_MAX_RSA_KEY_BYTES );
	keySize = bitsToBytes( rsaParams->keyBits );

	/* Now we run into another bug or specification error or something 
	   (there's no documentation for this so we can't tell, "the behaviour 
	   of a program without a specification can never be wrong, merely 
	   surprising") where the exponent value can be zero.  The only clue as 
	   to what to do here is in the tpm2_print utility, which uses
	   'r->exponent ? r->exponent : 65537' to deal with this, so we do the
	   same */
	exponent = ( rsaParams->exponent > 0 ) ? rsaParams->exponent : 65537L;

	/* Format the RSA e value, which is stored as an integer rather than a
	   bignum byte string, as a bignum byte string.  This requires writing
	   the value as an ASN.1 INTEGER and then skipping the tag and length
	   bytes at the start */
	sMemOpen( &stream, eBuffer, 8 );
	status = writeShortInteger( &stream, exponent, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		eSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		Fapi_Free( keyBlob );
		( void ) Fapi_Delete( fapiContext, objectPath );
		return( status );
		}
	eSize -= 1 + 1;					/* Skip tag + length */
	eValue = eBuffer + 1 + 1;

	/* Send the public key data to the context.  We send the keying 
	   information as CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL rather than 
	   CRYPT_IATTRIBUTE_KEY_SPKI since the latter transitions the context 
	   into the high state.  We don't want to do this because we're already 
	   in the middle of processing a message that does this on completion, 
	   all that we're doing here is sending in encoded public key data for 
	   use by objects such as certificates */
	if( cryptStatusOK( status ) )
		{
		status = writeFlatPublicKey( keyDataBuffer, CRYPT_MAX_PKCSIZE * 2,
									 &keyDataSize, CRYPT_ALGO_RSA, 0,
									 rsaPubKey->buffer, rsaPubKey->size, 
									 eValue, eSize, NULL, 0, NULL, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, keyDataBuffer, keyDataSize );
		status = krnlSendMessage( contextInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( contextInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE, &keySize, 
								  CRYPT_IATTRIBUTE_KEYSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = updateActionFlags( contextInfoPtr->objectHandle,
									CRYPT_ALGO_RSA, TRUE );
		}
	if( cryptStatusError( status ) )
		{
		Fapi_Free( keyBlob );
		( void ) Fapi_Delete( fapiContext, objectPath );
		return( status );
		}

	/* Remember that we've now got a key set for the context.  We have to do
	   this explicitly since we've bypassed the standard key-load process */
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );

	/* Persist the metadata for the key so that we can look it up later.  
	   The call looks a bit odd because there's no device to persist it to 
	   given in the arguments, that's because it's being called from 
	   functions working with context info rather than device info so the 
	   device info is implicitly taken from the context info */
	status = persistContextMetadata( contextInfoPtr, storageIDbuffer, 
									 KEYID_SIZE );
	if( cryptStatusError( status ) )
		{
		Fapi_Free( keyBlob );
		( void ) Fapi_Delete( fapiContext, objectPath );
		return( status );
		}

	/* Clean up */
	Fapi_Free( keyBlob );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Device Capability and Mechanism Routines				*
*																			*
****************************************************************************/

/* The capability information for the TPM, really just private-key ops.  
   There isn't any way to query a TPM for its capabilities (short of
   shelling out to tpm2_getcap and parsing the resulting JSON) so we just 
   have to assume that the default RSA with key size 2048 bits exists */

static const CAPABILITY_INFO capabilities[] = {
	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, bitsToBytes( 0 ), "RSA", 3,
		bitsToBytes( 2048 ), bitsToBytes( 2048 ), bitsToBytes( 2048 ),
		selfTestFunction, getDefaultInfo, NULL, NULL, initKeyFunction, generateKeyFunction, 
		encryptFunction, decryptFunction, NULL, NULL, NULL, NULL, NULL, NULL, 
		sign, sigCheck, readPublicKeyRsaFunction, writePublicKeyRsaFunction },

	/* The end-of-list marker.  This value isn't linked into the 
	   capabilities list when we call initCapabilities() */
	{ CRYPT_ALGO_NONE }, { CRYPT_ALGO_NONE }
	};

/* Mechanisms supported by TPM devices.  These are actually cryptlib native 
   mechanisms layered on top of the TPM crypto, but not the full set 
   supported by the system device since TPMs really only support private-key
   ops.  The list is sorted in order of frequency of use in order to make 
   lookups a bit faster */

static const MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }, { MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

static CAPABILITY_INFO_LIST capabilityInfoList[ 4 ];

/* Initialise and get the capability information */

CHECK_RETVAL \
int tpmInitCapabilities( void )
	{
	int i;

	/* Build the list of available capabilities */
	memset( capabilityInfoList, 0, 
			sizeof( CAPABILITY_INFO_LIST ) * 4 );
	for( i = 0; capabilities[ i ].cryptAlgo != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO ); i++ )
		{
		REQUIRES( sanityCheckCapability( &capabilities[ i ] ) );
		
		DATAPTR_SET( capabilityInfoList[ i ].info, 
					 ( CAPABILITY_INFO * ) &capabilities[ i ] );
		DATAPTR_SET( capabilityInfoList[ i ].next, NULL );
		if( i > 0 )
			{
			DATAPTR_SET( capabilityInfoList[ i - 1 ].next, 
						 &capabilityInfoList[ i ] );
			}
		}
	ENSURES( i < FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int tpmGetCapabilities( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	DATAPTR_SET( deviceInfoPtr->capabilityInfoList, capabilityInfoList );
	DATAPTR_SET( deviceInfoPtr->mechanismFunctions, 
				 ( void * ) mechanismFunctions );
	deviceInfoPtr->mechanismFunctionCount = \
		FAILSAFE_ARRAYSIZE( mechanismFunctions, MECHANISM_FUNCTION_INFO );
	
	return( CRYPT_OK );
	}
#endif /* USE_TPM */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
