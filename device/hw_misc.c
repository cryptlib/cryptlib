/****************************************************************************
*																			*
*					cryptlib Cryptgraphic HAL Assists Routines				*
*						Copyright Peter Gutmann 1998-2020					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "hardware.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "device/hardware.h"
#endif /* Compiler-specific includes */

/* The following helper routines provide common functionality needed by most 
   cryptographic HALs, which avoids having to reimplement the same code in 
   each HAL module.  These are called from the HAL to provide services such 
   as keygen assist and various context-management functions */

#ifdef USE_HARDWARE

/****************************************************************************
*																			*
*					Context to Hardware Mapping Routines					*
*																			*
****************************************************************************/

/* Set up a mapping from a context to its associated information in the
   underlying hardware and optionally persist associated metadata to the 
   underlying hardware object storage.  This generates a storageID for the 
   information and records it and the hardware handle in the context.  The 
   caller has to record the storageID alongside the crypto information held 
   by the hardware for later use to look up the information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int setPersonalityMapping( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						   IN_INT_Z const int keyHandle,
						   OUT_BUFFER_FIXED( storageIDlength ) \
								void *storageID, 
						   IN_LENGTH_FIXED( KEYID_SIZE ) \
								const int storageIDlength )
	{
	MESSAGE_DATA msgData;
	BYTE storageIDbuffer[ KEYID_SIZE + 8 ];
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( storageID, storageIDlength ) );

	REQUIRES( keyHandle >= 0 && keyHandle < INT_MAX );
	REQUIRES( storageIDlength == KEYID_SIZE );

	/* Clear return value */
	memset( storageID, 0, min( 16, storageIDlength ) );

	/* Remember the key handle for the underlying hardware */
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_SETATTRIBUTE, 
							  ( MESSAGE_CAST ) &keyHandle, 
							  CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the storage ID needed to refer to the context by providing a 
	   unique identifier to refer to the key in the HAL */
	setMessageData( &msgData, storageIDbuffer, KEYID_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* Copy the storageID back to the caller */
	REQUIRES( rangeCheck( KEYID_SIZE, 1, storageIDlength ) );
	memcpy( storageID, storageIDbuffer, KEYID_SIZE );

	/* Persist the metadata for the key so that we can look it up later.  
	   The call looks a bit odd because there's no device to persist it to 
	   given in the arguments, that's because it's being called from 
	   functions working with context info rather than device info so the 
	   device info is implicitly taken from the context info */
	return( persistContextMetadata( contextInfoPtr, storageIDbuffer, 
									KEYID_SIZE ) );
	}

/****************************************************************************
*																			*
*							Keygen Assist Routines							*
*																			*
****************************************************************************/

/* Some hardware devices function purely as private-key accelerators and 
   have no native public/private key generation support or can only generate 
   something like the DLP x value, which is just a raw string of random 
   bits, but can't generate a full set of public/private key parameters 
   since these require complex bignum operations not supported by the 
   underlying cryptologic.  To handle this situation we provide 
   supplementary software support routines that generate the key parameters 
   using native contexts and bignum code and then pass them back to the 
   crypto HAL to load into the cryptlogic.
   
   We only enable this functionality when we're using crypto hardware to
   augment the native crypto capabilities, when all of the crypto is
   provided by the HAL then it needs to perform its own keygen since there's
   no native crypto present to do it */

#if !defined( CONFIG_CRYPTO_HW1 ) && !defined( CONFIG_CRYPTO_HW2 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int generateKeyComponents( OUT_PTR CONTEXT_INFO *staticContextInfo,
								  OUT_PTR PKC_INFO *contextData, 
								  IN_PTR const CAPABILITY_INFO *capabilityInfoPtr,
								  IN_LENGTH_PKC_BITS const int keySizeBits )
	{
	int status;

	assert( isWritePtr( staticContextInfo, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( contextData, sizeof( PKC_INFO ) ) );
	assert( isReadPtr( capabilityInfoPtr, sizeof( CAPABILITY_INFO ) ) );

	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE_ECC ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Initialise a static context to generate the key into */
	status = staticInitContext( staticContextInfo, CONTEXT_PKC, 
								capabilityInfoPtr, contextData, 
								sizeof( PKC_INFO ), NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate a key into the static context */
	status = capabilityInfoPtr->generateKeyFunction( staticContextInfo,
													 keySizeBits );
	if( cryptStatusError( status ) )
		{
		staticDestroyContext( staticContextInfo );
		return( status );
		}

	return( CRYPT_OK );
	}

#ifdef USE_RSA

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int rsaGenerateComponents( OUT_PTR CRYPT_PKCINFO_RSA *rsaKeyInfo,
								  IN_PTR const CAPABILITY_INFO *capabilityInfoPtr,
								  IN_LENGTH_PKC_BITS const int keySizeBits )
	{
	CONTEXT_INFO staticContextInfo;
	PKC_INFO contextData, *pkcInfo = &contextData;
	int dummy, status;

	assert( isWritePtr( rsaKeyInfo, sizeof( CRYPT_PKCINFO_RSA ) ) );
	assert( isReadPtr( capabilityInfoPtr, sizeof( CAPABILITY_INFO ) ) );

	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Clear return value */
	cryptInitComponents( rsaKeyInfo, FALSE );

	/* Generate the key components */
	status = generateKeyComponents( &staticContextInfo, &contextData, 
									capabilityInfoPtr, keySizeBits );
	if( cryptStatusError( status ) )
		return( status );

	/* Extract the newly-generated key components for the caller to use */
	rsaKeyInfo->nLen = BN_num_bits( &pkcInfo->rsaParam_n );
	status = exportBignum( rsaKeyInfo->n, CRYPT_MAX_PKCSIZE, &dummy, 
						   &pkcInfo->rsaParam_n );
	ENSURES( cryptStatusOK( status ) );
	rsaKeyInfo->eLen = BN_num_bits( &pkcInfo->rsaParam_e );
	status = exportBignum( rsaKeyInfo->e, CRYPT_MAX_PKCSIZE, &dummy, 
						   &pkcInfo->rsaParam_e );
	ENSURES( cryptStatusOK( status ) );
	rsaKeyInfo->pLen = BN_num_bits( &pkcInfo->rsaParam_p );
	status = exportBignum( rsaKeyInfo->p, CRYPT_MAX_PKCSIZE, &dummy, 
						   &pkcInfo->rsaParam_p );
	ENSURES( cryptStatusOK( status ) );
	rsaKeyInfo->qLen = BN_num_bits( &pkcInfo->rsaParam_q );
	status = exportBignum( rsaKeyInfo->q, CRYPT_MAX_PKCSIZE, &dummy, 
						   &pkcInfo->rsaParam_q );
	ENSURES( cryptStatusOK( status ) );
	rsaKeyInfo->e1Len = BN_num_bits( &pkcInfo->rsaParam_exponent1 );
	status = exportBignum( rsaKeyInfo->e1, CRYPT_MAX_PKCSIZE, &dummy, 
						   &pkcInfo->rsaParam_exponent1 );
	ENSURES( cryptStatusOK( status ) );
	rsaKeyInfo->e2Len = BN_num_bits( &pkcInfo->rsaParam_exponent2 );
	status = exportBignum( rsaKeyInfo->e2, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->rsaParam_exponent2 );
	ENSURES( cryptStatusOK( status ) );
	rsaKeyInfo->uLen = BN_num_bits( &pkcInfo->rsaParam_u );
	status = exportBignum( rsaKeyInfo->u, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->rsaParam_u );
	ENSURES( cryptStatusOK( status ) );
	staticDestroyContext( &staticContextInfo );

	return( status );
	}
#endif /* USE_RSA */

#if defined( USE_DH ) || defined( USE_DSA ) || defined( USE_ELGAMAL )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int dlpGenerateComponents( OUT_PTR CRYPT_PKCINFO_DLP *dlpKeyInfo,
								  IN_PTR const CAPABILITY_INFO *capabilityInfoPtr,
								  IN_LENGTH_PKC_BITS const int keySizeBits )
	{
	CONTEXT_INFO staticContextInfo;
	PKC_INFO contextData, *pkcInfo = &contextData;
	int dummy, status;

	assert( isWritePtr( dlpKeyInfo, sizeof( CRYPT_PKCINFO_DLP ) ) );
	assert( isReadPtr( capabilityInfoPtr, sizeof( CAPABILITY_INFO ) ) );

	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Clear return value */
	cryptInitComponents( dlpKeyInfo, FALSE );

	/* Generate the key components */
	status = generateKeyComponents( &staticContextInfo, &contextData, 
									capabilityInfoPtr, keySizeBits );
	if( cryptStatusError( status ) )
		return( status );

	/* Extract the newly-generated key components for the caller to use */
	dlpKeyInfo->pLen = BN_num_bits( &pkcInfo->dlpParam_p );
	status = exportBignum( dlpKeyInfo->p, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->dlpParam_p );
	ENSURES( cryptStatusOK( status ) );
	dlpKeyInfo->gLen = BN_num_bits( &pkcInfo->dlpParam_g );
	status = exportBignum( dlpKeyInfo->g, CRYPT_MAX_PKCSIZE, &dummy, 
						   &pkcInfo->dlpParam_g );
	ENSURES( cryptStatusOK( status ) );
	dlpKeyInfo->qLen = BN_num_bits( &pkcInfo->dlpParam_q );
	status = exportBignum( dlpKeyInfo->q, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->dlpParam_q );
	ENSURES( cryptStatusOK( status ) );
	dlpKeyInfo->yLen = BN_num_bits( &pkcInfo->dlpParam_y );
	status = exportBignum( dlpKeyInfo->y, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->dlpParam_y );
	ENSURES( cryptStatusOK( status ) );
	dlpKeyInfo->xLen = BN_num_bits( &pkcInfo->dlpParam_x );
	status = exportBignum( dlpKeyInfo->x, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->dlpParam_x );
	ENSURES( cryptStatusOK( status ) );

	staticDestroyContext( &staticContextInfo );

	return( status );
	}
#endif /* USE_DH || USE_DSA || USE_ELGAMAL */

#if defined( USE_ECDSA ) || defined( USE_ECDH ) || \
	defined( USE_25519 ) || defined( USE_ED25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int eccGenerateComponents( OUT_PTR CRYPT_PKCINFO_ECC *eccKeyInfo,
								  IN_PTR const CAPABILITY_INFO *capabilityInfoPtr,
								  IN_LENGTH_PKC_BITS const int keySizeBits )
	{
	CONTEXT_INFO staticContextInfo;
	PKC_INFO contextData, *pkcInfo = &contextData;
	int dummy, status;

	assert( isWritePtr( eccKeyInfo, sizeof( CRYPT_PKCINFO_ECC ) ) );
	assert( isReadPtr( capabilityInfoPtr, sizeof( CAPABILITY_INFO ) ) );

	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE_ECC ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Clear return value */
	cryptInitComponents( eccKeyInfo, FALSE );

	/* Generate the key components */
	status = generateKeyComponents( &staticContextInfo, &contextData, 
									capabilityInfoPtr, keySizeBits );
	if( cryptStatusError( status ) )
		return( status );

	/* Extract the newly-generated key components for the caller to use */
	eccKeyInfo->curveType = pkcInfo->curveType;
	eccKeyInfo->qxLen = BN_num_bits( &pkcInfo->eccParam_qx );
	status = exportBignum( eccKeyInfo->qx, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->eccParam_qx );
	ENSURES( cryptStatusOK( status ) );
	eccKeyInfo->qyLen = BN_num_bits( &pkcInfo->eccParam_qy );
	status = exportBignum( eccKeyInfo->qy, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->eccParam_qy );
	ENSURES( cryptStatusOK( status ) );
	eccKeyInfo->dLen = BN_num_bits( &pkcInfo->eccParam_d );
	status = exportBignum( eccKeyInfo->d, CRYPT_MAX_PKCSIZE, &dummy,
						   &pkcInfo->eccParam_d );
	ENSURES( cryptStatusOK( status ) );

	staticDestroyContext( &staticContextInfo );

	return( status );
	}
#endif /* USE_ECDSA || USE_ECDH || USE_25519 || USE_ED25519 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int generatePKCcomponents( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						   OUT_PTR void *keyInfo, 
						   IN_LENGTH_PKC_BITS const int keySizeBits )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( keyInfo, 64 ) ); 

	REQUIRES( keyInfo != NULL );
	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE_ECC ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	REQUIRES( capabilityInfoPtr != NULL );

	switch( capabilityInfoPtr->cryptAlgo )
		{
#ifdef USE_RSA
		case CRYPT_ALGO_RSA:
			return( rsaGenerateComponents( keyInfo, capabilityInfoPtr, 
										   keySizeBits ) );
#endif /* USE_RSA */

#if defined( USE_DH ) || defined( USE_DSA ) || defined( USE_ELGAMAL )
		case CRYPT_ALGO_DH:
		case CRYPT_ALGO_DSA:
		case CRYPT_ALGO_ELGAMAL:
			return( dlpGenerateComponents( keyInfo, capabilityInfoPtr, 
										   keySizeBits ) );
#endif /* USE_DH || USE_DSA || USE_ELGAMAL */

#if defined( USE_ECDSA ) || defined( USE_ECDH ) || \
	defined( USE_ECDSA ) || defined( USE_25519 )
		case CRYPT_ALGO_ECDSA:
		case CRYPT_ALGO_ECDH:
		case CRYPT_ALGO_25519:
		case CRYPT_ALGO_ED25519:
			return( eccGenerateComponents( keyInfo, capabilityInfoPtr, 
										   keySizeBits ) );
#endif /* USE_ECDSA || USE_ECDH || USE_25519 || USE_ED25519 */

		default:
			return( CRYPT_ERROR_NOTAVAIL );
		}

	retIntError();
	}
#endif /* !CONFIG_CRYPTO_HW1 && !CONFIG_CRYPTO_HW1 */

/****************************************************************************
*																			*
*							Public-Key Assist Routines						*
*																			*
****************************************************************************/

/* Send public-key data to the context for use with certificate objects.  
   Since this is coming from a hardware device it's not in bignum format but
   in the external CRYPT_PKCINFO_xxx format so we have to use 
   writeFlatPublicKey() to write it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setPKCinfo( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				const void *keyInfo )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BYTE keyDataBuffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 8 ];
	MESSAGE_DATA msgData;
	int keyDataSize DUMMY_INIT, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( capabilityInfoPtr != NULL );

	assert( ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RSA && \
			  isReadPtr( keyInfo, sizeof( CRYPT_PKCINFO_RSA ) ) ) || \
			( ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DH || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ELGAMAL ) && \
			  isReadPtr( keyInfo, sizeof( CRYPT_PKCINFO_DLP ) ) ) || \
			( ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDH || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ED25519 ) && \
			  isReadPtr( keyInfo, sizeof( CRYPT_PKCINFO_ECC ) ) ) );

	/* Send the public key data to the context.  We send the keying 
	   information as CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL rather than 
	   CRYPT_IATTRIBUTE_KEY_SPKI since the latter transitions the context 
	   into the high state.  We don't want to do this because we're already 
	   in the middle of processing a message that does this on completion, 
	   all that we're doing here is sending in encoded public key data for 
	   use by objects such as certificates */
	switch( capabilityInfoPtr->cryptAlgo )
		{
#ifdef USE_RSA
		case CRYPT_ALGO_RSA:
			{
			const CRYPT_PKCINFO_RSA *rsaKeyInfo = \
						( CRYPT_PKCINFO_RSA * ) keyInfo;

			if( rsaKeyInfo->isPublicKey ) 
				SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY );
			pkcInfo->keySizeBits = rsaKeyInfo->nLen;
			status = writeFlatPublicKey( keyDataBuffer, 
						CRYPT_MAX_PKCSIZE * 4, &keyDataSize, 
						capabilityInfoPtr->cryptAlgo, 0, 
						rsaKeyInfo->n, bitsToBytes( rsaKeyInfo->nLen ), 
						rsaKeyInfo->e, bitsToBytes( rsaKeyInfo->eLen ), 
						NULL, 0, NULL, 0 );
			break;
			}
#endif /* USE_RSA */ 

#if defined( USE_DH ) || defined( USE_DSA ) || defined( USE_ELGAMAL )
		case CRYPT_ALGO_DH:
		case CRYPT_ALGO_DSA:
		case CRYPT_ALGO_ELGAMAL:
			{
			const CRYPT_PKCINFO_DLP *dlpKeyInfo = \
						( CRYPT_PKCINFO_DLP * ) keyInfo;

			if( dlpKeyInfo->isPublicKey ) 
				SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY );
			pkcInfo->keySizeBits = dlpKeyInfo->pLen;
			status = writeFlatPublicKey( keyDataBuffer, 
						CRYPT_MAX_PKCSIZE * 4, &keyDataSize, 
						capabilityInfoPtr->cryptAlgo, 0,
						dlpKeyInfo->p, bitsToBytes( dlpKeyInfo->pLen ), 
						dlpKeyInfo->q, bitsToBytes( dlpKeyInfo->qLen ), 
						dlpKeyInfo->g, bitsToBytes( dlpKeyInfo->gLen ), 
						dlpKeyInfo->y, bitsToBytes( dlpKeyInfo->yLen ) );
			break;
			}
#endif /* USE_DH || USE_DSA || USE_ELGAMAL */

#if defined( USE_ECDSA ) || defined( USE_ECDH ) || \
	defined( USE_25519 ) || defined( USE_ED25519 )
		case CRYPT_ALGO_ECDSA:
		case CRYPT_ALGO_ECDH:
		case CRYPT_ALGO_25519:
		case CRYPT_ALGO_ED25519:
			{
			const CRYPT_PKCINFO_ECC *eccKeyInfo = \
						( CRYPT_PKCINFO_ECC * ) keyInfo;
			int keySizeBits;

			if( eccKeyInfo->isPublicKey ) 
				SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY );
			status = getECCFieldSize( eccKeyInfo->curveType, &keySizeBits, 
									  TRUE );
			if( cryptStatusError( status ) )
				return( status );
			pkcInfo->curveType = eccKeyInfo->curveType;
			pkcInfo->keySizeBits = keySizeBits;
			status = writeFlatPublicKey( keyDataBuffer, 
						CRYPT_MAX_PKCSIZE * 4, &keyDataSize, 
						capabilityInfoPtr->cryptAlgo, eccKeyInfo->curveType, 
						eccKeyInfo->qx, bitsToBytes( eccKeyInfo->qxLen ), 
						eccKeyInfo->qy, bitsToBytes( eccKeyInfo->qyLen ), 
						NULL, 0, NULL, 0 );
			break;
			}
#endif /* USE_ECDSA || USE_ECDH || USE_25519 || USE_ED25519 */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, keyDataBuffer, keyDataSize );
	return( krnlSendMessage( contextInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE_S, &msgData, 
							 CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL ) );
	}

/* Convert public-key information held in bignums inside a context into
   flat form for feeding to the underlying hardware */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int exportBignumBits( OUT_BUFFER( dataMaxLength, *dataLengthBits ) \
								void *data, 
							 IN_LENGTH_SHORT_MIN( 16 ) \
								const int dataMaxLength, 
							 OUT_INT_SHORT_Z int *dataLengthBits,
							 IN_PTR const BIGNUM *bignum )
	{
	int dummy;

	/* The CRYPT_PKCINFO_xxx structures used for external-format storage 
	   store the sizes of the components in bits, so we need to wrap the
	   standard exportBignum() function with code to convert to the bit-
	   length format used with the external format */
	*dataLengthBits = BN_num_bits( bignum );
	return( exportBignum( data, dataMaxLength, &dummy, bignum ) );
	}

#ifdef USE_RSA

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int rsaGetComponents( const CONTEXT_INFO *contextInfoPtr, 
							 CRYPT_PKCINFO_RSA *rsaKeyInfo )
	{
	const PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	int status;

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( rsaKeyInfo, sizeof( CRYPT_PKCINFO_RSA ) ) );
	
	memset( rsaKeyInfo, 0, sizeof( CRYPT_PKCINFO_RSA ) );
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY ) )
		rsaKeyInfo->isPublicKey = TRUE; 
	status = exportBignumBits( rsaKeyInfo->n, CRYPT_MAX_PKCSIZE,
							   &rsaKeyInfo->nLen, &pkcInfo->rsaParam_n );
	if( cryptStatusOK( status ) )
		{
		status = exportBignumBits( rsaKeyInfo->e, CRYPT_MAX_PKCSIZE,
								   &rsaKeyInfo->eLen, 
								   &pkcInfo->rsaParam_e );
		}
	if( rsaKeyInfo->isPublicKey )
		return( status );
	if( cryptStatusOK( status ) && \
		!BN_is_zero( &pkcInfo->rsaParam_d ) )
		{
		status = exportBignumBits( rsaKeyInfo->d, CRYPT_MAX_PKCSIZE,
								   &rsaKeyInfo->dLen, 
								   &pkcInfo->rsaParam_d );
		}
	if( cryptStatusOK( status ) )
		{
		status = exportBignumBits( rsaKeyInfo->p, CRYPT_MAX_PKCSIZE,
								   &rsaKeyInfo->pLen, 
								   &pkcInfo->rsaParam_p );
		}
	if( cryptStatusOK( status ) )
		{
		status = exportBignumBits( rsaKeyInfo->q, CRYPT_MAX_PKCSIZE,
								   &rsaKeyInfo->qLen, 
								   &pkcInfo->rsaParam_q );
		}
	if( cryptStatusOK( status ) )
		{
		status = exportBignumBits( rsaKeyInfo->u, CRYPT_MAX_PKCSIZE,
								   &rsaKeyInfo->uLen, 
								   &pkcInfo->rsaParam_u );
		}
	if( cryptStatusOK( status ) && \
		!BN_is_zero( &pkcInfo->rsaParam_exponent1 ) )
		{
		status = exportBignumBits( rsaKeyInfo->e1, CRYPT_MAX_PKCSIZE,
								   &rsaKeyInfo->e1Len, 
								   &pkcInfo->rsaParam_exponent1 );
		if( cryptStatusOK( status ) )
			{
			status = exportBignumBits( rsaKeyInfo->e2, CRYPT_MAX_PKCSIZE,
									   &rsaKeyInfo->e2Len, 
									   &pkcInfo->rsaParam_exponent2 );
			}
		}

	return( status );
	}
#endif /* USE_RSA */

#if defined( USE_DH ) || defined( USE_DSA ) || defined( USE_ELGAMAL )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int dlpGetComponents( const CONTEXT_INFO *contextInfoPtr, 
							 CRYPT_PKCINFO_DLP *dlpKeyInfo )
	{
	const PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	int status;

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( dlpKeyInfo, sizeof( CRYPT_PKCINFO_DLP ) ) );

	memset( dlpKeyInfo, 0, sizeof( CRYPT_PKCINFO_DLP ) );
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY ) )
		dlpKeyInfo->isPublicKey = TRUE; 
	status = exportBignumBits( dlpKeyInfo->p, CRYPT_MAX_PKCSIZE,
							   &dlpKeyInfo->pLen, &pkcInfo->dlpParam_p );
	if( cryptStatusOK( status ) && \
		!BN_is_zero( &pkcInfo->dlpParam_q ) )
		{
		status = exportBignumBits( dlpKeyInfo->q, CRYPT_MAX_PKCSIZE,
								   &dlpKeyInfo->qLen, 
								   &pkcInfo->dlpParam_q );
		}
	if( cryptStatusOK( status ) )
		{
		status = exportBignumBits( dlpKeyInfo->g, CRYPT_MAX_PKCSIZE,
								   &dlpKeyInfo->gLen, 
								   &pkcInfo->dlpParam_g );
		}
	if( cryptStatusOK( status ) && \
		!BN_is_zero( &pkcInfo->dlpParam_y ) )
		{
		status = exportBignumBits( dlpKeyInfo->y, CRYPT_MAX_PKCSIZE,
								   &dlpKeyInfo->yLen, 
								   &pkcInfo->dlpParam_y );
		}
	if( dlpKeyInfo->isPublicKey )
		return( status );
	if( cryptStatusOK( status ) )
		{
		status = exportBignumBits( dlpKeyInfo->x, CRYPT_MAX_PKCSIZE,
								   &dlpKeyInfo->xLen, 
								   &pkcInfo->dlpParam_x );
		}

	return( status );
	}
#endif /* USE_DH || USE_DSA || USE_ELGAMAL */

#if defined( USE_ECDSA ) || defined( USE_ECDH ) 

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int eccGetComponents( const CONTEXT_INFO *contextInfoPtr, 
							 CRYPT_PKCINFO_ECC *eccKeyInfo )
	{
	const PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	int status;

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( eccKeyInfo, sizeof( CRYPT_PKCINFO_ECC ) ) );

	memset( eccKeyInfo, 0, sizeof( CRYPT_PKCINFO_ECC ) );
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY ) )
		eccKeyInfo->isPublicKey = TRUE; 
	eccKeyInfo->curveType = pkcInfo->curveType;
	status = exportBignumBits( eccKeyInfo->qx, CRYPT_MAX_PKCSIZE_ECC,
							   &eccKeyInfo->qxLen, &pkcInfo->eccParam_qx );
	if( cryptStatusOK( status ) )
		{
		status = exportBignumBits( eccKeyInfo->qy, CRYPT_MAX_PKCSIZE_ECC,
								   &eccKeyInfo->qyLen, 
								   &pkcInfo->eccParam_qy );
		}
	if( eccKeyInfo->isPublicKey )
		return( status );
	if( cryptStatusOK( status ) )
		{
		status = exportBignumBits( eccKeyInfo->d, CRYPT_MAX_PKCSIZE_ECC,
								   &eccKeyInfo->dLen, 
								   &pkcInfo->eccParam_d );
		}

	return( status );
	}
#endif /* USE_ECDSA || USE_ECDH */

#if defined( USE_25519 ) || defined( USE_ED25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int curve25519GetComponents( const CONTEXT_INFO *contextInfoPtr, 
									CRYPT_PKCINFO_ECC *eccKeyInfo )
	{
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( eccKeyInfo, sizeof( CRYPT_PKCINFO_ECC ) ) );

	memset( eccKeyInfo, 0, sizeof( CRYPT_PKCINFO_ECC ) );
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY ) )
		eccKeyInfo->isPublicKey = TRUE; 
	retIntError();
	}
#endif /* USE_25519 || USE_ED25519 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getPKCinfo( const CONTEXT_INFO *contextInfoPtr, 
				OUT_PTR void *keyInfo )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( capabilityInfoPtr != NULL );

	assert( ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RSA && \
			  isWritePtr( keyInfo, sizeof( CRYPT_PKCINFO_RSA ) ) ) || \
			( ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DH || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ELGAMAL ) && \
			  isWritePtr( keyInfo, sizeof( CRYPT_PKCINFO_DLP ) ) ) || \
			( ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDH || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ED25519 ) && \
			  isWritePtr( keyInfo, sizeof( CRYPT_PKCINFO_ECC ) ) ) );

	/* Get the public key data from the context */
	switch( capabilityInfoPtr->cryptAlgo )
		{
#ifdef USE_RSA
		case CRYPT_ALGO_RSA:
			{
			CRYPT_PKCINFO_RSA *rsaKeyInfo = ( CRYPT_PKCINFO_RSA * ) keyInfo;

			return( rsaGetComponents( contextInfoPtr, rsaKeyInfo ) );
			}
#endif /* USE_RSA */ 

#if defined( USE_DH ) || defined( USE_DSA ) || defined( USE_ELGAMAL )
		case CRYPT_ALGO_DH:
		case CRYPT_ALGO_DSA:
		case CRYPT_ALGO_ELGAMAL:
			{
			CRYPT_PKCINFO_DLP *dlpKeyInfo = ( CRYPT_PKCINFO_DLP * ) keyInfo;

			return( dlpGetComponents( contextInfoPtr, dlpKeyInfo ) );
			}
#endif /* USE_DH || USE_DSA || USE_ELGAMAL */

#if defined( USE_ECDSA ) || defined( USE_ECDH ) 
		case CRYPT_ALGO_ECDSA:
		case CRYPT_ALGO_ECDH:
			{
			CRYPT_PKCINFO_ECC *eccKeyInfo = ( CRYPT_PKCINFO_ECC * ) keyInfo;

			return( eccGetComponents( contextInfoPtr, eccKeyInfo ) );
			}
#endif /* USE_ECDSA || USE_ECDH */

#if defined( USE_25519 ) || defined( USE_ED25519 )
		case CRYPT_ALGO_25519:
		case CRYPT_ALGO_ED25519:
			{
			CRYPT_PKCINFO_ECC *eccKeyInfo = ( CRYPT_PKCINFO_ECC * ) keyInfo;

			return( curve25519GetComponents( contextInfoPtr, eccKeyInfo ) );
			}
#endif /* USE_25519 || USE_ED25519 */

		default:
			retIntError();
		}

	retIntError();
	}

/****************************************************************************
*																			*
*							Miscellaneous Routines							*
*																			*
****************************************************************************/

/* Send encryption/MAC keying metadata to the context */

CHECK_RETVAL \
int setConvInfo( IN_HANDLE const CRYPT_CONTEXT iCryptContext, 
				 IN_LENGTH_KEY const int keySize )
	{
	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( keySize >= MIN_KEYSIZE && keySize <= CRYPT_MAX_KEYSIZE );

	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, 
							 ( MESSAGE_CAST ) &keySize, 
							 CRYPT_IATTRIBUTE_KEYSIZE ) );
	}

/* The default cleanup function, which simply frees the context-related data 
   used by the cryptographic hardware if it's an ephemeral key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int cleanupHardwareContext( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
			/* Although it's given as an INOUT_PTR parameter when called as a 
			   context method, we don't write to the value in this 
			   function */

	/* If this is non-ephemeral context data then we leave it intact when 
	   the corresponding context is destroyed, the only way to delete it is 
	   with an explicit call to the deleteItemFunction() */
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_PERSISTENT ) )
		return( CRYPT_OK );

	/* We have to be careful about deleting the context data since it may
	   not have been set up yet, for example if we're called due to a 
	   failure in the complete-creation/initialisation step of setting up a 
	   context */
	if( contextInfoPtr->deviceObject != CRYPT_ERROR )
		{
		( void ) hwDeleteItem( NULL, contextInfoPtr->deviceStorageID,
							   KEYID_SIZE, contextInfoPtr->deviceObject );
		}

	return( CRYPT_OK );
	}
#endif /* USE_HARDWARE */
