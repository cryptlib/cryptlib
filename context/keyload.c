/****************************************************************************
*																			*
*						  cryptlib Key Load Routines						*
*						Copyright Peter Gutmann 1992-2025					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
#else
  #include "context/context.h"
#endif /* Compiler-specific includes */

/* The default size of the salt for PKCS #5v2 key derivation, needed when we
   set the CRYPT_CTXINFO_KEYING_VALUE */

#define PKCS5_SALT_SIZE		8	/* 64 bits */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Convert a key attribute type into a key format type */

CHECK_RETVAL \
int attributeToFormatType( IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						   OUT_ENUM_OPT( KEYFORMAT ) KEYFORMAT_TYPE *keyformat )
	{
	static const MAP_TABLE attributeMapTbl[] = {
		{ CRYPT_IATTRIBUTE_KEY_SSH, KEYFORMAT_SSH },
		{ CRYPT_IATTRIBUTE_KEY_TLS, KEYFORMAT_TLS },
		{ CRYPT_IATTRIBUTE_KEY_TLS_EXT, KEYFORMAT_TLS_EXT },
		{ CRYPT_IATTRIBUTE_KEY_PGP, KEYFORMAT_PGP },
		{ CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL, KEYFORMAT_PGP },
		{ CRYPT_IATTRIBUTE_KEY_SPKI, KEYFORMAT_CERT },
		{ CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL, KEYFORMAT_CERT },
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	int value, status;

	assert( isWritePtr( keyformat, sizeof( KEYFORMAT_TYPE ) ) );

	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Clear return value */
	*keyformat = KEYFORMAT_NONE;

	status = mapValue( attribute, &value, attributeMapTbl, 
					   FAILSAFE_ARRAYSIZE( attributeMapTbl, MAP_TABLE ) );
	ENSURES( cryptStatusOK( status ) );
	*keyformat = value;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Key Parameter Handling Functions					*
*																			*
****************************************************************************/

/* Initialise crypto parameters such as the IV and encryption mode, shared 
   by most capabilities.  This is never called directly, but is accessed
   through function pointers in the capability lists */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initGenericParams( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   IN_ENUM( KEYPARAM ) const KEYPARAM_TYPE paramType,
					   IN_PTR_OPT const void *data, 
					   IN_INT const int dataLength )
	{
	CONV_INFO *convInfo = DATAPTR_GET_CONV( contextInfoPtr );
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_CONV );
	REQUIRES( isEnumRange( paramType, KEYPARAM ) );
	REQUIRES( convInfo != NULL );
	REQUIRES( capabilityInfoPtr != NULL );

	/* Set the en/decryption mode if required */
	switch( paramType )
		{
		case KEYPARAM_MODE:
			{
			CAP_ENCRYPT_FUNCTION encryptFunction, decryptFunction;

			REQUIRES( data == NULL );
			REQUIRES( isEnumRange( dataLength, CRYPT_MODE ) );

			switch( dataLength )
				{
				case CRYPT_MODE_ECB:
					encryptFunction = capabilityInfoPtr->encryptFunction;
					decryptFunction = capabilityInfoPtr->decryptFunction;
					break;
				case CRYPT_MODE_CBC:
					encryptFunction = capabilityInfoPtr->encryptCBCFunction;
					decryptFunction = capabilityInfoPtr->decryptCBCFunction;
					break;
#ifdef USE_CFB
				case CRYPT_MODE_CFB:
					encryptFunction = capabilityInfoPtr->encryptCFBFunction;
					decryptFunction = capabilityInfoPtr->decryptCFBFunction;
					break;
#endif /* USE_CFB */
				case CRYPT_MODE_GCM:
					encryptFunction = capabilityInfoPtr->encryptGCMFunction;
					decryptFunction = capabilityInfoPtr->decryptGCMFunction;
					break;
				default:
					retIntError();
				}
			ENSURES( ( encryptFunction == NULL && \
					   decryptFunction == NULL ) || \
					 ( encryptFunction != NULL && \
					   decryptFunction != NULL ) );
			if( encryptFunction == NULL || decryptFunction == NULL )
				{
				setObjectErrorInfo( contextInfoPtr, CRYPT_CTXINFO_MODE, 
									CRYPT_ERRTYPE_ATTR_VALUE );
				return( CRYPT_ERROR_NOTAVAIL );
				}
			
			/* Update the context with the new mode and pointers */
			convInfo->mode = dataLength;
			FNPTR_SET( contextInfoPtr->encryptFunction, encryptFunction );
			FNPTR_SET( contextInfoPtr->decryptFunction, decryptFunction );

			return( CRYPT_OK );
			}

		case KEYPARAM_IV:
			assert( isReadPtrDynamic( data, dataLength ) );

			REQUIRES( data != NULL && \
					  dataLength >= 8 && dataLength <= CRYPT_MAX_IVSIZE );

			/* Load an IV of the required length */
			REQUIRES( rangeCheck( dataLength, 1, CRYPT_MAX_IVSIZE ) );
			memcpy( convInfo->iv, data, dataLength );
			convInfo->ivLength = dataLength;
			convInfo->ivCount = 0;
			memcpy( convInfo->currentIV, convInfo->iv, dataLength );
			SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_IV_SET );

			return( CRYPT_OK );
		
		default:
			retIntError();
		}

	retIntError();
	}

/* Check that user-supplied supplied PKC parameters make sense (algorithm-
   parameter-specific validity checks are performed at a lower level).  
   Although the checks are somewhat specific to particular PKC algorithm 
   classes we have to do them at this point in order to avoid duplicating 
   them in every plug-in PKC module, and because strictly speaking it's the 
   job of the higher-level code to ensure that the lower-level routines get 
   fed at least approximately valid input */

#ifndef USE_FIPS140 

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
static int checkPKCparams( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo, 
						   const void *keyInfo )
	{
	const CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) keyInfo;

	REQUIRES( isPkcAlgo( cryptAlgo ) );
	REQUIRES( keyInfo != NULL );

	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			/* The RSA checks are complex enough that they're handled 
			   separately at the end of the function */
			break;
		
		case CRYPT_ALGO_DH:
#ifdef USE_DSA
		case CRYPT_ALGO_DSA:
#endif /* USE_DSA */
#ifdef USE_ELGAMAL
		case CRYPT_ALGO_ELGAMAL:
#endif /* USE_ELGAMAL */
			{
			const CRYPT_PKCINFO_DLP *dlpKey = \
								( CRYPT_PKCINFO_DLP * ) keyInfo;

			assert( isReadPtr( keyInfo, sizeof( CRYPT_PKCINFO_DLP ) ) );
								
			/* Check the general information and make sure that all required 
			   values are initialised.  Note that we don't get PKCS #3 DH 
			   keys at this level so we always require that q be present */
			if( ( dlpKey->isPublicKey != TRUE_ALT && \
				  dlpKey->isPublicKey != FALSE ) )
				return( CRYPT_ARGERROR_STR1 );
			if( dlpKey->pLen <= 0 || dlpKey->qLen <= 0 || \
				dlpKey->gLen <= 0 || dlpKey->yLen < 0 || dlpKey->xLen < 0 )
				return( CRYPT_ARGERROR_STR1 );

			/* Check the public components */
			if( isShortPKCKey( bitsToBytes( dlpKey->pLen ) ) )
				{
				/* Special-case handling for insecure-sized public keys */
				return( CRYPT_ERROR_NOSECURE );
				}
			if( dlpKey->pLen < bytesToBits( DLPPARAM_MIN_P ) || \
				dlpKey->pLen > bytesToBits( DLPPARAM_MAX_P ) || \
				dlpKey->qLen < bytesToBits( DLPPARAM_MIN_Q ) || \
				dlpKey->qLen > bytesToBits( DLPPARAM_MAX_Q ) || \
				dlpKey->gLen < bytesToBits( DLPPARAM_MIN_G ) || \
				dlpKey->gLen > bytesToBits( DLPPARAM_MAX_G ) || \
				dlpKey->yLen < bytesToBits( 0 ) || \
				dlpKey->yLen > bytesToBits( DLPPARAM_MAX_Y ) )
				/* y may be 0 if only x and the public parameters are 
				   available */
				{
				return( CRYPT_ARGERROR_STR1 );
				}
			if( dlpKey->yLen <= 0 && \
				( dlpKey->isPublicKey || dlpKey->xLen <= 0 ) )
				{
				/* If y is 0 then it has to be a private key with x present 
				   to generate y */
				return( CRYPT_ARGERROR_STR1 );
				}
			if( !( dlpKey->p[ bitsToBytes( dlpKey->pLen ) - 1 ] & 0x01 ) || \
				!( dlpKey->q[ bitsToBytes( dlpKey->qLen ) - 1 ] & 0x01 ) )
				return( CRYPT_ARGERROR_STR1 );	/* Quick non-prime check */
			if( dlpKey->isPublicKey )
				return( CRYPT_OK );

			/* Check the private components */
			if( dlpKey->xLen < bytesToBits( DLPPARAM_MIN_X ) || \
				dlpKey->xLen > bytesToBits( DLPPARAM_MAX_X ) )
				return( CRYPT_ARGERROR_STR1 );

			return( CRYPT_OK );
			}

#if defined( USE_ECDH ) || defined( USE_ECDSA )
		case CRYPT_ALGO_ECDH:
		case CRYPT_ALGO_ECDSA:
			{
			const CRYPT_PKCINFO_ECC *eccKey = \
							( CRYPT_PKCINFO_ECC * ) keyInfo;

			assert( isReadPtr( keyInfo, sizeof( CRYPT_PKCINFO_ECC ) ) );

			/* Check the general information and make sure that all required 
			   values are initialised.  We always require the use of named 
			   curves, which means that the domain parameters can't be 
			   explicitly set */
			if( ( eccKey->isPublicKey != TRUE_ALT && \
				  eccKey->isPublicKey != FALSE ) )
				return( CRYPT_ARGERROR_STR1 );
			if( eccKey->pLen != 0 || eccKey->aLen != 0 || \
				eccKey->bLen != 0 || eccKey->gxLen != 0 || \
				eccKey->gyLen != 0 || eccKey->nLen != 0 || \
				eccKey->hLen != 0 || eccKey->qxLen <= 0 || \
				eccKey->qyLen <= 0 || eccKey->dLen < 0 )
				return( CRYPT_ARGERROR_STR1 );

			/* Perform a more specific check of the curve type and 
			   parameters */
			if( !isEnumRange( eccKey->curveType, CRYPT_ECCCURVE ) )
				return( CRYPT_ARGERROR_STR1 );
			if( eccKey->qxLen < bytesToBits( ECCPARAM_MIN_QX ) || \
				eccKey->qxLen > bytesToBits( ECCPARAM_MAX_QX ) || \
				eccKey->qyLen < bytesToBits( ECCPARAM_MIN_QY ) || \
				eccKey->qyLen > bytesToBits( ECCPARAM_MAX_QY ) )
				return( CRYPT_ARGERROR_STR1 ); 
			if( eccKey->isPublicKey )
				return( CRYPT_OK );

			/* Check the private components */
			if( eccKey->dLen < bytesToBits( ECCPARAM_MIN_D ) || \
				eccKey->dLen > bytesToBits( ECCPARAM_MAX_D ) )
				return( CRYPT_ARGERROR_STR1 );

			return( CRYPT_OK );
			}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_X25519 ) || defined( USE_ED25519 )
		case CRYPT_ALGO_25519:
		case CRYPT_ALGO_ED25519:
			{
			const CRYPT_PKCINFO_DJB *curve25519Key = \
							( CRYPT_PKCINFO_DJB * ) keyInfo;

			assert( isReadPtr( keyInfo, sizeof( CRYPT_PKCINFO_DJB ) ) );

			/* Check the general information and make sure that all required 
			   values are initialised */
			if( ( curve25519Key->isPublicKey != TRUE_ALT && \
				  curve25519Key->isPublicKey != FALSE ) )
				return( CRYPT_ARGERROR_STR1 );
			if( curve25519Key->pubLen <= 0 || curve25519Key->privLen < 0 )
				return( CRYPT_ARGERROR_STR1 );

			/* Check the public components */
			if( curve25519Key->pubLen < bytesToBits( MIN_PKCSIZE_BERNSTEIN ) )
				{
				/* Special-case handling for insecure-sized public keys */
				return( CRYPT_ERROR_NOSECURE );
				}
			if( curve25519Key->pubLen != bytesToBits( MIN_PKCSIZE_BERNSTEIN ) )
				return( CRYPT_ARGERROR_STR1 );
			if( curve25519Key->isPublicKey )
				return( CRYPT_OK );

			/* Check the private components */
			if( curve25519Key->privLen != bytesToBits( MIN_PKCSIZE_BERNSTEIN ) )
				return( CRYPT_ARGERROR_STR1 );

			return( CRYPT_OK );
			}
#endif /* USE_X25519 || USE_ED25519 */

#ifdef USE_MLKEM
		case CRYPT_ALGO_MLKEM:
			{
			const CRYPT_PKCINFO_PQC *pqcKey = \
							( CRYPT_PKCINFO_PQC * ) keyInfo;

			assert( isReadPtr( keyInfo, sizeof( CRYPT_PKCINFO_PQC ) ) );

			/* Check the general information and make sure that all required 
			   values are initialised */
			if( ( pqcKey->isPublicKey != TRUE_ALT && \
				  pqcKey->isPublicKey != FALSE ) )
				return( CRYPT_ARGERROR_STR1 );
			if( pqcKey->pubLen <= 0 || pqcKey->privLen < 0 )
				return( CRYPT_ARGERROR_STR1 );
			
			/* Check the public components */
			if( pqcKey->pubLen < bytesToBits( MIN_PKCSIZE_PQC ) )
				{
				/* Special-case handling for insecure-sized public keys */
				return( CRYPT_ERROR_NOSECURE );
				}
			if( pqcKey->pubLen != bytesToBits( MIN_PKCSIZE_PQC ) )
				return( CRYPT_ARGERROR_STR1 );
			if( pqcKey->isPublicKey )
				return( CRYPT_OK );

			/* Check the private components.  Because the PQC algorithms 
			   have parameters all over the place with no clean relationship 
			   between them as for the PKC/ECC algorithms, we have to 
			   hardcode in the size of the MLKEM-768 private key, see also
			   the comment for ML-KEM in misc/consts.h */
			if( pqcKey->privLen != bytesToBits( MLKEM768_SECRETKEYBYTES ) )
				return( CRYPT_ARGERROR_STR1 );

			return( CRYPT_OK );
			}
#endif /* USE_MLKEM */

		default:
			retIntError();
		}

	/* At this point it's RSA */
	assert( isReadPtr( keyInfo, sizeof( CRYPT_PKCINFO_RSA ) ) );

	/* Check the general information and make sure that all required values 
	   are initialised */
	if( rsaKey->isPublicKey != TRUE_ALT && rsaKey->isPublicKey != FALSE )
		return( CRYPT_ARGERROR_STR1 );
	if( rsaKey->nLen <= 0 || rsaKey->eLen <= 0 || \
		rsaKey->dLen < 0 || rsaKey->pLen < 0 || rsaKey->qLen < 0 || \
		rsaKey->uLen < 0 || rsaKey->e1Len < 0 || rsaKey->e2Len < 0 )
		return( CRYPT_ARGERROR_STR1 );

	/* Check the public components */
	if( isShortPKCKey( bitsToBytes( rsaKey->nLen ) ) )
		{
		/* Special-case handling for insecure-sized public keys */
		return( CRYPT_ERROR_NOSECURE );
		}
	if( rsaKey->nLen < bytesToBits( RSAPARAM_MIN_N ) || \
		rsaKey->nLen > bytesToBits( RSAPARAM_MAX_N ) || \
		rsaKey->eLen < bytesToBits( RSAPARAM_MIN_E ) || \
		rsaKey->eLen > bytesToBits( RSAPARAM_MAX_E ) || \
		rsaKey->eLen >= rsaKey->nLen )
		return( CRYPT_ARGERROR_STR1 );
	if( !( rsaKey->n[ bitsToBytes( rsaKey->nLen ) - 1 ] & 0x01 ) || \
		!( rsaKey->e[ bitsToBytes( rsaKey->eLen ) - 1 ] & 0x01 ) )
		return( CRYPT_ARGERROR_STR1 );	/* Quick non-prime check */
	if( rsaKey->isPublicKey )
		return( CRYPT_OK );

	/* Check the private components.  This can get somewhat complex, possible
	   combinations are:

		d, p, q
		d, p, q, u
		d, p, q, e1, e2, u
		   p, q, e1, e2, u

	   The reason for some of the odder combinations is that some 
	   implementations don't use all of the values (for example d isn't 
	   needed at all for the CRT shortcut) or recreate them when the key is 
	   loaded.  If only d, p, and q are present we recreate e1 and e2 from 
	   them, we also create u if necessary */
	if( rsaKey->pLen < bytesToBits( RSAPARAM_MIN_P ) || \
		rsaKey->pLen > bytesToBits( RSAPARAM_MAX_P ) || \
		rsaKey->pLen >= rsaKey->nLen || \
		rsaKey->qLen < bytesToBits( RSAPARAM_MIN_Q ) || \
		rsaKey->qLen > bytesToBits( RSAPARAM_MAX_Q ) || \
		rsaKey->qLen >= rsaKey->nLen )
		return( CRYPT_ARGERROR_STR1 );
	if( !( rsaKey->p[ bitsToBytes( rsaKey->pLen ) - 1 ] & 0x01 ) || \
		!( rsaKey->q[ bitsToBytes( rsaKey->qLen ) - 1 ] & 0x01 ) )
		return( CRYPT_ARGERROR_STR1 );	/* Quick non-prime check */
	if( rsaKey->dLen <= 0 && rsaKey->e1Len <= 0 )
		{
		/* Must have either d or e1 et al */
		return( CRYPT_ARGERROR_STR1 );
		}
	if( rsaKey->dLen > 0 && \
		( rsaKey->dLen < bytesToBits( RSAPARAM_MIN_D ) || \
		  rsaKey->dLen > bytesToBits( RSAPARAM_MAX_D ) ) )
		return( CRYPT_ARGERROR_STR1 );
	if( rsaKey->e1Len > 0 && \
		( rsaKey->e1Len < bytesToBits( RSAPARAM_MIN_EXP1 ) || \
		  rsaKey->e1Len > bytesToBits( RSAPARAM_MAX_EXP1 ) || \
		  rsaKey->e2Len < bytesToBits( RSAPARAM_MIN_EXP2 ) || \
		  rsaKey->e2Len > bytesToBits( RSAPARAM_MAX_EXP2 ) ) )
		return( CRYPT_ARGERROR_STR1 );
	if( rsaKey->uLen > 0 && \
		( rsaKey->uLen < bytesToBits( RSAPARAM_MIN_U ) || \
		  rsaKey->uLen > bytesToBits( RSAPARAM_MAX_U ) ) )
		return( CRYPT_ARGERROR_STR1 );
	return( CRYPT_OK );
	}
#endif /* !USE_FIPS140 */

/****************************************************************************
*																			*
*								Key Load Functions							*
*																			*
****************************************************************************/

/* Load a key into a CONTEXT_INFO structure.  These functions are called by 
   the various higher-level functions that move a key into a context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int loadKeyConvFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
								IN_BUFFER( keyLength ) const void *key, 
								IN_LENGTH_KEY const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	CONV_INFO *convInfo = DATAPTR_GET_CONV( contextInfoPtr );
	int keyDataSize, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_CONV );
	REQUIRES( keyLength >= MIN_KEYSIZE && keyLength <= CRYPT_MAX_KEYSIZE );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( convInfo != NULL );

	/* If we don't need an IV, record it as being set */
	if( !needsIV( convInfo->mode ) || \
		isStreamCipher( capabilityInfoPtr->cryptAlgo ) )
		SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_IV_SET );

	/* Perform the key setup */
	status = capabilityInfoPtr->getInfoFunction( CONTEXT_INFO_STATESIZE, 
										NULL, &keyDataSize, sizeof( int ) );
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfoPtr->initKeyFunction( contextInfoPtr, key, 
													 keyLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Checksum the keying information */
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
		{
		convInfo->keyDataSize = keyDataSize;
		convInfo->keyDataChecksum = checksumData( convInfo->key, 
												  convInfo->keyDataSize );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int loadKeyPKCFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							   IN_BUFFER_OPT( keyLength ) const void *key, 
							   IN_LENGTH_SHORT_Z const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( key == NULL ) || isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( ( key == NULL && keyLength == 0 ) || \
			  ( key != NULL && \
			    isShortIntegerRangeMin( keyLength, 16 ) ) );
			  /* The key data for this function may be NULL if the values
			     have been read from encoded X.509/SSH/TLS/PGP data straight
				 into the context bignums */
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( pkcInfo != NULL );

#ifndef USE_FIPS140 
	/* Make sure that the parameters make sense */
	if( key != NULL )
		{
		status = checkPKCparams( capabilityInfoPtr->cryptAlgo, key );
		if( cryptStatusError( status ) )
			return( status );
		SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_PBO );
				  /* Tell lib_kg to check params too */
		}
#endif /* !USE_FIPS140 */

	/* Load the keying information.  The checksumming of the key data is 
	   performed by the key-init code since for the DLP algorithms it can 
	   get complicated in the presence of (EC)DH contexts that aren't quite
	   public or private keys */
	status = capabilityInfoPtr->initKeyFunction( contextInfoPtr, key, 
												 keyLength );
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
		clearTempBignums( pkcInfo );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int loadKeyMacFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							   IN_BUFFER( keyLength ) const void *key, 
							   IN_LENGTH_KEY const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	MAC_INFO *macInfo = DATAPTR_GET_MAC( contextInfoPtr );
	int macInfoSize, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_MAC );
	REQUIRES( keyLength >= MIN_KEYSIZE && keyLength <= CRYPT_MAX_KEYSIZE );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( macInfo != NULL );

	/* Perform the key setup */
	status = capabilityInfoPtr->getInfoFunction( CONTEXT_INFO_STATESIZE, 
										NULL, &macInfoSize, sizeof( int ) );
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfoPtr->initKeyFunction( contextInfoPtr, key, 
													 keyLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Checksum the keying information */
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
		{
		macInfo->macInfoSize = macInfoSize;
		macInfo->macInfoChecksum = checksumData( macInfo->macInfo, 
												 macInfo->macInfoSize );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int loadKeyGenericFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
								   IN_BUFFER( keyLength ) const void *key, 
								   IN_LENGTH_KEY const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_GENERIC );
	REQUIRES( keyLength >= bitsToBytes( 128 ) && \
			  keyLength <= CRYPT_MAX_KEYSIZE );
	REQUIRES( capabilityInfoPtr != NULL );

	return( capabilityInfoPtr->initKeyFunction( contextInfoPtr, key, keyLength ) );
	}

/****************************************************************************
*																			*
*							Key Component Load Functions					*
*																			*
****************************************************************************/

/* Load an encoded X.509/SSH/TLS/PGP key into a context.  This is used for 
   two purposes, to load public key components into native contexts and to 
   save encoded X.509 public-key data for use in certificates associated 
   with non-native contexts held in a device.  The latter is required 
   because there's no key data stored with the context itself that we can 
   use to create the SubjectPublicKeyInfo, however it's necessary to have 
   SubjectPublicKeyInfo available for certificate requests/certificates.  

   Normally this is sufficient because cryptlib always generates native 
   contexts for public keys/certificates and for private keys the data is 
   generated in the device with the encoded public components attached to 
   the context as described above.  However for DH keys this gets a bit more 
   complex because although the private key is generated in the device, in 
   the case of the DH responder this is only the DH x value, with the 
   parameters (p and g) being supplied externally by the initiator.  This 
   means that it's necessary to decode at least some of the public key data 
   in order to create the y value after the x value has been generated in 
   the device.  The only situation where this functionality is currently 
   needed is for the SSHv2 code, which at the moment always uses native DH 
   contexts.  For this reason we leave off resolving this issue until it's 
   actually required */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int setEncodedKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE keyType, 
				   IN_BUFFER( keyDataLen ) const void *keyData, 
				   IN_LENGTH_SHORT const int keyDataLen )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
				DATAPTR_GET( contextInfoPtr->capabilityInfo );
	PKC_CALCULATEKEYID_FUNCTION calculateKeyIDFunction;
	PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	STREAM stream;
	KEYFORMAT_TYPE formatType;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( keyData, keyDataLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( needsKey( contextInfoPtr ) || \
			  TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) );
	REQUIRES( keyType == CRYPT_IATTRIBUTE_KEY_SPKI || \
			  keyType == CRYPT_IATTRIBUTE_KEY_PGP || \
			  keyType == CRYPT_IATTRIBUTE_KEY_SSH || \
			  keyType == CRYPT_IATTRIBUTE_KEY_TLS || \
			  keyType == CRYPT_IATTRIBUTE_KEY_TLS_EXT || \
			  keyType == CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL || \
			  keyType == CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL );
	REQUIRES( isShortIntegerRangeMin( keyDataLen, 2 ) );
			  /* Can be very short in the case of ECC curve IDs */
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( pkcInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	calculateKeyIDFunction = ( PKC_CALCULATEKEYID_FUNCTION ) \
						FNPTR_GET( pkcInfo->calculateKeyIDFunction );
	REQUIRES( calculateKeyIDFunction != NULL );

	/* If the keys are held externally (e.g. in a crypto device), copy the 
	   SubjectPublicKeyInfo data in and set up any other information that we 
	   may need from it.  This information is used when loading a context 
	   from a key contained in a device, for which the actual key components 
	   aren't directly available in the context but may be needed in the 
	   future for things like certificate requests and certificates, and for
	   when we're using a crypto device object, for which */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) && \
		!TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY ) )
#else
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
		{
		REQUIRES( keyType == CRYPT_IATTRIBUTE_KEY_SPKI || \
				  keyType == CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL );

		/* It's possible that a caller could erroneously try and set a 
		   non-trigger-attribute key (so CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL) 
		   twice which won't be blocked by the kernel since the context
		   won't have been moved into the high state, so we check for this 
		   and report it as an error */
		if( pkcInfo->publicKeyInfo != NULL )
			return( CRYPT_ERROR_INITED );

		/* Record the SPKI key data for the context */
		REQUIRES( isShortIntegerRangeNZ( keyDataLen ) );
		if( ( pkcInfo->publicKeyInfo = \
					clAlloc( "setEncodedKey", keyDataLen ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( pkcInfo->publicKeyInfo, keyData, keyDataLen );
		pkcInfo->publicKeyInfoSize = keyDataLen;

		status = calculateKeyIDFunction( contextInfoPtr, NULL, 0, 
										 CRYPT_ALGO_SHA1 );
		if( cryptStatusError( status ) )
			{
			/* Clean up the SPKI data in case the caller tries again */
			clFree( "setEncodedKey", pkcInfo->publicKeyInfo );
			pkcInfo->publicKeyInfo = NULL;
			pkcInfo->publicKeyInfoSize = 0;
			
			return( status );
			}

		return( CRYPT_OK );
		}

	/* Read the appropriately-formatted key data into the context, applying 
	   a lowest-common-denominator set of usage flags to the loaded key */
	status = attributeToFormatType( keyType, &formatType );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, keyData, keyDataLen );
	status = capabilityInfoPtr->readPublicKeyFunction( &stream, 
							contextInfoPtr, capabilityInfoPtr->cryptAlgo, 
							formatType, 0 );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a partial load of the initial public portions of a private 
	   key with further key component operations to follow then there's 
	   nothing more to do at this point and we're done */
	if( keyType == CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL || \
		keyType == CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL )
		{
		return( calculateKeyIDFunction( contextInfoPtr, NULL, 0,
										CRYPT_ALGO_SHA1 ) );
		}

	/* Complete the key load using the internally-stored key components */
	return( completeKeyLoad( contextInfoPtr, 
				( keyType == CRYPT_IATTRIBUTE_KEY_PGP ) ? TRUE : FALSE ) );
	}

/* Complete the load process for a key that was loaded with setEncodedKey() 
   or by setting DLP/ECDLP domain parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completeKeyLoad( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					 IN_BOOL const BOOLEAN isPGPkey )
	{
	static const int actionFlags = \
		MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL );
	static const int actionFlagsDH = ACTION_PERM_NONE_EXTERNAL_ALL;
	static const int actionFlagsPGP = \
		MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const CAPABILITY_INFO *capabilityInfoPtr = \
				DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const CTX_LOADKEY_FUNCTION loadKeyFunction = \
				( CTX_LOADKEY_FUNCTION ) \
				FNPTR_GET( contextInfoPtr->loadKeyFunction );
	PKC_CALCULATEKEYID_FUNCTION calculateKeyIDFunction;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isBooleanValue( isPGPkey ) );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( loadKeyFunction != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	calculateKeyIDFunction = ( PKC_CALCULATEKEYID_FUNCTION ) \
						FNPTR_GET( pkcInfo->calculateKeyIDFunction );
	REQUIRES( calculateKeyIDFunction != NULL );

	/* Perform an internal load that uses the key component values that 
	   we've just read into the context */
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY );
	status = loadKeyFunction( contextInfoPtr, NULL, 0 );
	if( cryptStatusError( status ) )
		{
		/* Map the status to a more appropriate code if necessary */
		return( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status );
		}
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );

	/* Restrict the key usage to public-key-only actions if necessary.  For 
	   PGP key loads (which, apart from the restrictions specified with the 
	   stored key data aren't constrained by the presence of ACLs in the 
	   form of certificates) we allow external usage, for DH (whose keys can be 
	   both public and private keys even though technically it's a public 
	   key) we allow both encryption and decryption usage, and for public 
	   keys read from certificates we  allow internal usage only */
	status = krnlSendMessage( contextInfoPtr->objectHandle,
						IMESSAGE_SETATTRIBUTE, 
						isPGPkey ? ( MESSAGE_CAST ) &actionFlagsPGP : \
						( isKeyexAlgo( capabilityInfoPtr->cryptAlgo ) ) ? \
							( MESSAGE_CAST ) &actionFlagsDH : \
							( MESSAGE_CAST ) &actionFlags,
						CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( status ) )
		return( status );
	return( calculateKeyIDFunction( contextInfoPtr, NULL, 0,
									CRYPT_ALGO_SHA1 ) );
	}

/* Load the components of a composite PKC key into a context */

#ifndef USE_FIPS140

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setKeyComponents( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					  IN_BUFFER( keyDataLen ) const void *keyData, 
					  IN_LENGTH_SHORT_MIN( 32 ) const int keyDataLen )
	{
	static const int actionFlags = \
		MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const CTX_LOADKEY_FUNCTION loadKeyFunction = \
				( CTX_LOADKEY_FUNCTION ) \
				FNPTR_GET( contextInfoPtr->loadKeyFunction );
	PKC_CALCULATEKEYID_FUNCTION calculateKeyIDFunction;
	BOOLEAN isPublicKey;
	int externalBoolean, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( keyData, keyDataLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  needsKey( contextInfoPtr ) );
	REQUIRES( keyDataLen == sizeof( CRYPT_PKCINFO_RSA ) || \
			  keyDataLen == sizeof( CRYPT_PKCINFO_DLP ) || \
			  keyDataLen == sizeof( CRYPT_PKCINFO_ECC ) || \
			  keyDataLen == sizeof( CRYPT_PKCINFO_DJB ) || \
			  keyDataLen == sizeof( CRYPT_PKCINFO_PQC ) );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( loadKeyFunction != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	calculateKeyIDFunction = ( PKC_CALCULATEKEYID_FUNCTION ) \
						FNPTR_GET( pkcInfo->calculateKeyIDFunction );
	REQUIRES( calculateKeyIDFunction != NULL );

	/* If it's a private key we need to have a key label set before we can 
	   continue.  The checking for this is a bit complex because at this
	   point all that the context knows is that it's a generic PKC context,
	   but it won't know whether it's a public- or private-key context until
	   the key is actually loaded.  To determine what it'll become we look
	   into the key data to see what's being loaded.
	   
	   We perform a second check of keyDataLen because the general check by
	   the kernel, confirmed above, is just that it's one of the possible
	   valid values, not that it's the exact value required by the algorithm.
	   
	   In addition to this the key data probably came from an external 
	   source (internal loads only come from marshalled data), so we have
	   to convert the boolean representation from the external to the 
	   internal form */
	switch( capabilityInfoPtr->cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			if( keyDataLen != sizeof( CRYPT_PKCINFO_RSA ) )
				return( CRYPT_ARGERROR_NUM1 );
			externalBoolean = ( ( CRYPT_PKCINFO_RSA * ) keyData )->isPublicKey;
			break;
		
		case CRYPT_ALGO_DH:
#ifdef USE_DSA
		case CRYPT_ALGO_DSA:
#endif /* USE_DSA */
#ifdef USE_ELGAMAL
		case CRYPT_ALGO_ELGAMAL:
#endif /* USE_ELGAMAL */
			if( keyDataLen != sizeof( CRYPT_PKCINFO_DLP ) )
				return( CRYPT_ARGERROR_NUM1 );
			externalBoolean = ( ( CRYPT_PKCINFO_DLP * ) keyData )->isPublicKey;
			break;

#if defined( USE_ECDH ) || defined( USE_ECDSA )
		case CRYPT_ALGO_ECDH:
		case CRYPT_ALGO_ECDSA:
			if( keyDataLen != sizeof( CRYPT_PKCINFO_ECC ) )
				return( CRYPT_ARGERROR_NUM1 );
			externalBoolean = ( ( CRYPT_PKCINFO_ECC * ) keyData )->isPublicKey;
			break;
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_X25519 ) || defined( USE_ED25519 )
		case CRYPT_ALGO_25519:
		case CRYPT_ALGO_ED25519:
			if( keyDataLen != sizeof( CRYPT_PKCINFO_DJB ) )
				return( CRYPT_ARGERROR_NUM1 );
			externalBoolean = ( ( CRYPT_PKCINFO_DJB * ) keyData )->isPublicKey;
			break;
#endif /* USE_X25519 || USE_ED25519 */

#ifdef USE_MLKEM
		case CRYPT_ALGO_MLKEM:
			if( keyDataLen != sizeof( CRYPT_PKCINFO_PQC ) )
				return( CRYPT_ARGERROR_NUM1 );
			externalBoolean = ( ( CRYPT_PKCINFO_PQC * ) keyData )->isPublicKey;
			break;
#endif /* USE_MLKEM */

		default:
			retIntError();
		}
	isPublicKey = externalBoolean ? TRUE : FALSE;

	/* Some contexts require that a label be set in order to identify them,
	   make sure that this is the case unless it's created in the crypto
	   object substituting for the system device */
	if( contextInfoPtr->labelSize <= 0 && \
		!TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_CRYPTOBJ ) )
		{
		/* Private keys, which it's assumed are for long-term use and will
		   be persisted to backing storage, always need a label */
		if( !isPublicKey )
			return( CRYPT_ERROR_NOTINITED );

		/* If it's a dummy object with keys held externally (e.g. in a 
		   crypto device) then we need a key label set in order to access 
		   the object at a later date */
		if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY )  )
			return( CRYPT_ERROR_NOTINITED );
		}

	/* Load the key components into the context */
	status = loadKeyFunction( contextInfoPtr, keyData, keyDataLen );
	if( cryptStatusError( status ) )
		return( status );
	SET_FLAG( contextInfoPtr->flags, 
			  CONTEXT_FLAG_KEY_SET | CONTEXT_FLAG_PBO );

	/* Restrict the key usage to public-key-only actions if it's a public 
	   key.  Keyex act as both public and private keys so we don't restrict 
	   their usage */
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY ) && \
		!isKeyexAlgo( capabilityInfoPtr->cryptAlgo ) )
		{
		status = krnlSendMessage( contextInfoPtr->objectHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &actionFlags,
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( calculateKeyIDFunction( contextInfoPtr, NULL, 0,
									CRYPT_ALGO_SHA1 ) );
	}
#endif /* !USE_FIPS140 */

/****************************************************************************
*																			*
*							Key Generation Functions						*
*																			*
****************************************************************************/

/* Generate a key into a CONTEXT_INFO structure */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateKeyConvFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
							DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const CTX_LOADKEY_FUNCTION loadKeyFunction = \
							( CTX_LOADKEY_FUNCTION ) \
							FNPTR_GET( contextInfoPtr->loadKeyFunction );
	CONV_INFO *convInfo = DATAPTR_GET_CONV( contextInfoPtr );
	MESSAGE_DATA msgData;
	int keyLength, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_CONV );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( convInfo != NULL );
	REQUIRES( loadKeyFunction != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	keyLength = convInfo->userKeyLength;

	/* If there's no key size specified, use the default length */
	if( keyLength <= 0 )
		keyLength = capabilityInfoPtr->keySize;

	/* If the context is implemented in a crypto device it may have the
	   capability to generate the key itself so if there's a keygen function
	   present we call this to generate the key directly into the context
	   rather than generating it ourselves and loading it in.  Note that to
	   export this key we'll need to use an exporting context which is also
	   located in the device, since we can't access it externally */
	if( capabilityInfoPtr->generateKeyFunction != NULL )
		{
		return( capabilityInfoPtr->generateKeyFunction( contextInfoPtr,
												bytesToBits( keyLength ) ) );
		}

	/* Generate a random session key into the context.  We load the random 
	   data directly into the pagelocked encryption context and pass that in 
	   as the key buffer, loadKey() won't copy the data if src == dest */
	setMessageData( &msgData, convInfo->userKey, keyLength );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	convInfo->userKeyLength = keyLength;
	return( loadKeyFunction( contextInfoPtr, convInfo->userKey, 
							 convInfo->userKeyLength ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateKeyPKCFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	PKC_CALCULATEKEYID_FUNCTION calculateKeyIDFunction;
	int keyLength, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( pkcInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	calculateKeyIDFunction = ( PKC_CALCULATEKEYID_FUNCTION ) \
						FNPTR_GET( pkcInfo->calculateKeyIDFunction );
	REQUIRES( calculateKeyIDFunction != NULL );
	keyLength = bitsToBytes( pkcInfo->keySizeBits );

	/* Writing a key in PGP format requires that it have a creation time 
	   associated with it, however keys from non-PGP sources don't have 
	   this.  In theory if we wanted to write out the key in PGP format 
	   then we'd have to set one in order to have something to write out.  
	   However, the creation time is hashed into the OpenPGP key ID when the 
	   ID is generated, which means that moving a key via a non-PGP format 
	   changes its key ID.  

	   Fortunately the standard never actually explains what the creation 
	   time field is for, so it probably doesn't matter what we set it to.
       Because of this we leave it at its default value of zero */
#if defined( USE_PGPKEYS ) && 0
	pkcInfo->pgpCreationTime = getApproxTime();
#endif /* USE_PGPKEYS */

	/* If there's no key size specified, use the default length.  In theory 
	   we could also read the CRYPT_OPTION_PKC_KEYSIZE at this point, 
	   however this only applies to the algorithm selected by 
	   CRYPT_OPTION_PKC_ALGO, or perhaps the algorithm class of 
	   CRYPT_OPTION_PKC_ALGO (for example { RSA, DSA, DH } vs. { ECDSA, 
	   ECDH }), however this then creates a confusing gotcha where all 
	   algorithms except CRYPT_OPTION_PKC_ALGO use the default key size if 
	   none is explicitly specified using CRYPT_CTXINFO_KEYSIZE while
	   CRYPT_OPTION_PKC_ALGO takes its key size from 
	   CRYPT_OPTION_PKC_KEYSIZE.  A quick user poll indicated that no-one 
	   specifically wanted this behaviour, so we don't use 
	   CRYPT_OPTION_PKC_KEYSIZE */
	if( keyLength <= 0 )
		keyLength = capabilityInfoPtr->keySize;

	/* Unlike conventional and MAC contexts, PKC contexts always have a 
	   keygen capability present */
	REQUIRES( capabilityInfoPtr->generateKeyFunction != NULL );

	/* Generate the key into the context */
	status = capabilityInfoPtr->generateKeyFunction( contextInfoPtr,
												bytesToBits( keyLength ) );
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
		clearTempBignums( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );
	return( calculateKeyIDFunction( contextInfoPtr, NULL, 0,
									CRYPT_ALGO_SHA1 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateKeyMacFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
							DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const CTX_LOADKEY_FUNCTION loadKeyFunction = \
							( CTX_LOADKEY_FUNCTION ) \
							FNPTR_GET( contextInfoPtr->loadKeyFunction );
	MAC_INFO *macInfo = DATAPTR_GET_MAC( contextInfoPtr );
	MESSAGE_DATA msgData;
	int keyLength, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	
	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_MAC );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( loadKeyFunction != NULL );
	REQUIRES( macInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	keyLength = macInfo->userKeyLength;

	/* If there's no key size specified, use the default length */
	if( keyLength <= 0 )
		keyLength = capabilityInfoPtr->keySize;

	/* If the context is implemented in a crypto device it may have the
	   capability to generate the key itself so if there's a keygen function
	   present we call this to generate the key directly into the context
	   rather than generating it ourselves and loading it in.  Note that to
	   export this key we'll need to use an exporting context which is also
	   located in the device, since we can't access it externally */
	if( capabilityInfoPtr->generateKeyFunction != NULL )
		{
		return( capabilityInfoPtr->generateKeyFunction( contextInfoPtr,
												bytesToBits( keyLength ) ) );
		}

	/* Generate a random session key into the context.  We load the random 
	   data directly into the pagelocked encryption context and pass that in 
	   as the key buffer, loadKey() won't copy the data if src == dest */
	setMessageData( &msgData, macInfo->userKey, keyLength );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	macInfo->userKeyLength = keyLength;
	return( loadKeyFunction( contextInfoPtr, macInfo->userKey, 
							 macInfo->userKeyLength ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateKeyGenericFunction( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
							DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const CTX_LOADKEY_FUNCTION loadKeyFunction = \
							( CTX_LOADKEY_FUNCTION ) \
							FNPTR_GET( contextInfoPtr->loadKeyFunction );
	GENERIC_INFO *genericInfo = DATAPTR_GET_GENERIC( contextInfoPtr );
	MESSAGE_DATA msgData;
	int keyLength, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	
	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_GENERIC );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( loadKeyFunction != NULL );
	REQUIRES( genericInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	keyLength = genericInfo->genericSecretLength;

	/* If there's no key size specified, use the default length */
	if( keyLength <= 0 )
		keyLength = capabilityInfoPtr->keySize;

	/* If the context is implemented in a crypto device it may have the
	   capability to generate the key itself so if there's a keygen function
	   present we call this to generate the key directly into the context
	   rather than generating it ourselves and loading it in.  Note that to
	   export this key we'll need to use an exporting context which is also
	   located in the device, since we can't access it externally */
	if( capabilityInfoPtr->generateKeyFunction != NULL )
		{
		return( capabilityInfoPtr->generateKeyFunction( contextInfoPtr,
												bytesToBits( keyLength ) ) );
		}

	/* Generate a random session key into the context.  We load the random 
	   data directly into the pagelocked encryption context and pass that in 
	   as the key buffer, loadKey() won't copy the data if src == dest */
	setMessageData( &msgData, genericInfo->genericSecret, keyLength );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	genericInfo->genericSecretLength = keyLength;
	return( loadKeyFunction( contextInfoPtr, genericInfo->genericSecret, 
							 genericInfo->genericSecretLength ) );
	}

/****************************************************************************
*																			*
*							Key Derivation Functions						*
*																			*
****************************************************************************/

/* Derive a key into a context from a user-supplied keying value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int deriveKeyConv( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						  IN_BUFFER( keyValueLen ) const void *keyValue, 
						  IN_LENGTH_SHORT const int keyValueLen )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
						DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const CTX_LOADKEY_FUNCTION loadKeyFunction = \
						( CTX_LOADKEY_FUNCTION ) \
						FNPTR_GET( contextInfoPtr->loadKeyFunction );
	CONV_INFO *convInfo = DATAPTR_GET_CONV( contextInfoPtr );
	MECHANISM_DERIVE_INFO mechanismInfo;
	CRYPT_ALGO_TYPE hmacAlgo;
	int keySize, value DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( keyValue, keyValueLen ) );

	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( loadKeyFunction != NULL );
	REQUIRES( convInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	hmacAlgo = convInfo->keySetupAlgorithm;

	/* Set up various derivation parameters if they're not already set */
	if( hmacAlgo == CRYPT_ALGO_NONE )
		{
		status = krnlSendMessage( contextInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_OPTION_KEYING_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		hmacAlgo = value;	/* int vs.enum */
		}
	keySize = ( convInfo->userKeyLength > 0 ) ? \
			  convInfo->userKeyLength : capabilityInfoPtr->keySize;
	if( convInfo->saltLength <= 0 )
		{
		MESSAGE_DATA nonceMsgData;

		setMessageData( &nonceMsgData, convInfo->salt, PKCS5_SALT_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &nonceMsgData,
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		convInfo->saltLength = PKCS5_SALT_SIZE;
		}
	convInfo->keySetupAlgorithm = hmacAlgo;
	setMechanismDeriveInfo( &mechanismInfo, convInfo->userKey, keySize,
							keyValue, keyValueLen, 
							convInfo->keySetupAlgorithm, 
							convInfo->salt, convInfo->saltLength, 
							convInfo->keySetupIterations );
	if( mechanismInfo.iterations <= 0 )
		{
		status = krnlSendMessage( contextInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, 
								  &mechanismInfo.iterations, 
								  CRYPT_OPTION_KEYING_ITERATIONS );
		if( cryptStatusError( status ) )
			return( status );
		convInfo->keySetupIterations = mechanismInfo.iterations;
		}

	/* Turn the user key into an encryption context key and load the key 
	   into the context */
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE, 
							  &mechanismInfo, MECHANISM_DERIVE_PBKDF2 );
	if( cryptStatusOK( status ) )
		{
		convInfo->userKeyLength = mechanismInfo.dataOutLength;
		status = loadKeyFunction( contextInfoPtr, mechanismInfo.dataOut,
								  mechanismInfo.dataOutLength );
		}
	if( cryptStatusOK( status ) )
		SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );
	zeroise( &mechanismInfo, sizeof( MECHANISM_DERIVE_INFO ) );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int deriveKeyMAC( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						 IN_BUFFER( keyValueLen ) const void *keyValue, 
						 IN_LENGTH_SHORT const int keyValueLen )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
						DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const CTX_LOADKEY_FUNCTION loadKeyFunction = \
						( CTX_LOADKEY_FUNCTION ) \
						FNPTR_GET( contextInfoPtr->loadKeyFunction );
	MAC_INFO *macInfo = DATAPTR_GET_MAC( contextInfoPtr );
	MECHANISM_DERIVE_INFO mechanismInfo;
	CRYPT_ALGO_TYPE hmacAlgo;
	int keySize, value DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( keyValue, keyValueLen ) );

	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( loadKeyFunction != NULL );
	REQUIRES( macInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	hmacAlgo = macInfo->keySetupAlgorithm;

	/* Set up various derivation parameters if they're not already set */
	if( hmacAlgo == CRYPT_ALGO_NONE )
		{
		status = krnlSendMessage( contextInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_OPTION_KEYING_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		hmacAlgo = value;	/* int vs.enum */
		}
	keySize = ( macInfo->userKeyLength > 0 ) ? \
			  macInfo->userKeyLength : capabilityInfoPtr->keySize;
	if( macInfo->saltLength <= 0 )
		{
		MESSAGE_DATA nonceMsgData;

		setMessageData( &nonceMsgData, macInfo->salt, PKCS5_SALT_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &nonceMsgData,
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		macInfo->saltLength = PKCS5_SALT_SIZE;
		}
	macInfo->keySetupAlgorithm = hmacAlgo;
	setMechanismDeriveInfo( &mechanismInfo, macInfo->userKey, keySize,
							keyValue, keyValueLen, 
							macInfo->keySetupAlgorithm, 
							macInfo->salt, macInfo->saltLength,
							macInfo->keySetupIterations );
	if( mechanismInfo.iterations <= 0 )
		{
		status = krnlSendMessage( contextInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, 
								  &mechanismInfo.iterations, 
								  CRYPT_OPTION_KEYING_ITERATIONS );
		if( cryptStatusError( status ) )
			return( status );
		macInfo->keySetupIterations = mechanismInfo.iterations;
		}

	/* Turn the user key into an encryption context key and load the key 
	   into the context */
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE, 
							  &mechanismInfo, MECHANISM_DERIVE_PBKDF2 );
	if( cryptStatusOK( status ) )
		{
		macInfo->userKeyLength = mechanismInfo.dataOutLength;
		status = loadKeyFunction( contextInfoPtr, mechanismInfo.dataOut,
								  mechanismInfo.dataOutLength );
		}
	if( cryptStatusOK( status ) )
		SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );
	zeroise( &mechanismInfo, sizeof( MECHANISM_DERIVE_INFO ) );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int deriveKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
			   IN_BUFFER( keyValueLen ) const void *keyValue, 
			   IN_LENGTH_SHORT const int keyValueLen )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( keyValue, keyValueLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_CONV || \
			  contextInfoPtr->type == CONTEXT_MAC );
	REQUIRES( needsKey( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( keyValueLen ) );

	/* If it's a persistent context then we need to have a key label set 
	   before we can continue */
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_PERSISTENT ) && \
		contextInfoPtr->labelSize <= 0 )
		return( CRYPT_ERROR_NOTINITED );

	if( contextInfoPtr->type == CONTEXT_CONV )
		return( deriveKeyConv( contextInfoPtr, keyValue, keyValueLen ) );
	return( deriveKeyMAC( contextInfoPtr, keyValue, keyValueLen ) );
	}

/****************************************************************************
*																			*
*							Context Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initKeyHandling( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_V( sanityCheckContext( contextInfoPtr ) );

	/* Set the access method pointers */
	switch( contextInfoPtr->type )
		{
		case CONTEXT_CONV:
			FNPTR_SET( contextInfoPtr->loadKeyFunction, loadKeyConvFunction );
			FNPTR_SET( contextInfoPtr->generateKeyFunction, generateKeyConvFunction );
			break;

		case CONTEXT_PKC:
			FNPTR_SET( contextInfoPtr->loadKeyFunction, loadKeyPKCFunction );
			FNPTR_SET( contextInfoPtr->generateKeyFunction, generateKeyPKCFunction );
			break;

		case CONTEXT_MAC:
			FNPTR_SET( contextInfoPtr->loadKeyFunction, loadKeyMacFunction );
			FNPTR_SET( contextInfoPtr->generateKeyFunction, generateKeyMacFunction );
			break;

		case CONTEXT_GENERIC:
			FNPTR_SET( contextInfoPtr->loadKeyFunction, loadKeyGenericFunction );
			FNPTR_SET( contextInfoPtr->generateKeyFunction, generateKeyGenericFunction );
			break;

		default:
			retIntError_Void();
		}
	}
