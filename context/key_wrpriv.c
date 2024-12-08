<<<<<<< HEAD
/****************************************************************************
*																			*
*							Private Key Write Routines						*
*						Copyright Peter Gutmann 1992-2020					*
*																			*
****************************************************************************/

#include <stdio.h>
#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "context/context.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKC

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the hash of the SPKI, used to cryptographically bind the public key
   to the private-key components */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getSPKIHash( const CONTEXT_INFO *contextInfoPtr,
						OUT_BUFFER_FIXED_C( 32 ) BYTE *hashValue,
						IN_LENGTH_FIXED( 32 ) const int hashValueLength ) 
	{
	const PKC_CALCULATEKEYID_FUNCTION calculateKeyIDFunction = \
				( PKC_CALCULATEKEYID_FUNCTION ) \
				FNPTR_GET( contextInfoPtr->ctxPKC->calculateKeyIDFunction );

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( hashValue, hashValueLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( hashValueLength == 32 );
	REQUIRES( calculateKeyIDFunction != NULL );

	/* Clear return value */
	REQUIRES( hashValueLength == 32 );
	memset( hashValue, 0, min( 16, hashValueLength ) );

	/* The keyID calculation function can either update the context 
	   information with various key IDs or just return a single key ID 
	   value.  For the former the contextInfoPtr is non-const while for the
	   latter it's const, however the function has to use the lowest-common-
	   denominator which is non-const so we make contextInfoPtr look like 
	   it's non-const */
	return( calculateKeyIDFunction( ( CONTEXT_INFO * ) contextInfoPtr, 
									hashValue, hashValueLength, 
									CRYPT_ALGO_SHA2 ) );
	}

/****************************************************************************
*																			*
*								Write Private Keys							*
*																			*
****************************************************************************/

#ifdef USE_INT_ASN1

/* Write private keys */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRsaPrivateKey( INOUT_PTR STREAM *stream, 
							   IN_PTR const CONTEXT_INFO *contextInfoPtr,
							   IN_BOOL const BOOLEAN useExtFormat )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	BYTE spkiHash[ CRYPT_MAX_HASHSIZE + 8 ];
	int length = sizeofBignum( &rsaKey->rsaParam_p ) + \
				 sizeofBignum( &rsaKey->rsaParam_q );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isBooleanValue( useExtFormat ) );
	REQUIRES( sanityCheckPKCInfo( rsaKey ) );

	/* Calculate the hash of the SPKI if we're cryptographically binding the 
	   public-key components to the private key ones */
	if( useExtFormat )
		{
		status = getSPKIHash( contextInfoPtr, spkiHash, 32 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Add the length of any optional components that may be present */
	if( !BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		{
		length += sizeofBignum( &rsaKey->rsaParam_exponent1 ) + \
				  sizeofBignum( &rsaKey->rsaParam_exponent2 ) + \
				  sizeofBignum( &rsaKey->rsaParam_u );
		}

	/* If we're using the extended format, write the public-key binding 
	   value as an ESSCertIDv2 before we write the private-key data */
	if( useExtFormat )
		{
		writeSequence( stream, sizeofObject( sizeofObject( 32 ) ) + \
							   sizeofObject( length ) );
		writeSequence( stream, sizeofObject( 32 ) );
		status = writeOctetString( stream, spkiHash, 32, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the the PKC fields */
	writeSequence( stream, length );
	writeBignumTag( stream, &rsaKey->rsaParam_p, 3 );
	if( BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		return( writeBignumTag( stream, &rsaKey->rsaParam_q, 4 ) );
	writeBignumTag( stream, &rsaKey->rsaParam_q, 4 );
	writeBignumTag( stream, &rsaKey->rsaParam_exponent1, 5 );
	writeBignumTag( stream, &rsaKey->rsaParam_exponent2, 6 );
	return( writeBignumTag( stream, &rsaKey->rsaParam_u, 7 ) );
	}

#ifdef USE_PKCS12

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRsaPrivateKeyOld( INOUT_PTR STREAM *stream, 
								  const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	const BIGNUM *d = &rsaKey->rsaParam_d;
	BOOLEAN calculatedPrivateExponent = FALSE;
	int length = sizeofShortInteger( 0 ) + \
				 sizeofBignum( &rsaKey->rsaParam_n ) + \
				 sizeofBignum( &rsaKey->rsaParam_e ) + \
				 sizeofBignum( &rsaKey->rsaParam_p ) + \
				 sizeofBignum( &rsaKey->rsaParam_q ) + \
				 sizeofBignum( &rsaKey->rsaParam_exponent1 ) + \
				 sizeofBignum( &rsaKey->rsaParam_exponent2 ) + \
				 sizeofBignum( &rsaKey->rsaParam_u );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( sanityCheckPKCInfo( rsaKey ) );

	/* The older format is somewhat restricted in terms of what can be
	   written since all components must be present, even the ones that are
	   never used (if d isn't present we calculate it on the fly, see 
	   below).  If anything is missing we can't write the key since nothing 
	   would be able to read it */
	if( BN_is_zero( &rsaKey->rsaParam_n ) || \
		BN_is_zero( &rsaKey->rsaParam_p ) || \
		BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		{
		return( CRYPT_ERROR_NOTAVAIL );
		}

	/* If the private-key d value isn't present, calculate it from p and q.
	   This is the most common missing value since it's not needed for the
	   CRT so we calculate a temporary value for this if it's not present.

	   This is somewhat ugly in that we're both messing with a const 
	   parameter and performing complex bignum ops as part of what should
	   only be a straight data write, but there's no easy way around this 
	   unless we create and manage our own bignum data values here */
	if( BN_is_zero( d ) )
		{
		BIGNUM *tmp = ( BIGNUM * ) &rsaKey->tmp1;
		int bnStatus = BN_STATUS;

		/* Use the extended Euclidean algorithm to calculate d from p and q:

			phi( n ) = (p - 1) * (q - 1) 
					 = n - p - q + 1
			d = e^-1 % phi( n ) */
		CKPTR( BN_copy( tmp, &rsaKey->rsaParam_n ) );
		CK( BN_sub( tmp, tmp, &rsaKey->rsaParam_p ) );
		CK( BN_sub( tmp, tmp, &rsaKey->rsaParam_q ) );
		CK( BN_add_word( tmp, 1 ) );
		CKPTR( BN_mod_inverse( tmp, &rsaKey->rsaParam_e, tmp, 
							   ( BN_CTX * ) &rsaKey->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		d = tmp;
		calculatedPrivateExponent = TRUE;
		}
	length += sizeofBignum( d );

	/* Write the the PKC fields */
	writeSequence( stream, sizeofShortInteger( 0 ) + \
						   sizeofAlgoID( CRYPT_ALGO_RSA ) + \
						   sizeofShortObject( \
								sizeofShortObject( length ) ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeAlgoID( stream, CRYPT_ALGO_RSA, DEFAULT_TAG );
	writeOctetStringHole( stream, sizeofShortObject( length ), 
						  DEFAULT_TAG );
	writeSequence( stream, length );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeBignum( stream, &rsaKey->rsaParam_n );
	writeBignum( stream, &rsaKey->rsaParam_e );
	writeBignum( stream, d );
	writeBignum( stream, &rsaKey->rsaParam_p );
	writeBignum( stream, &rsaKey->rsaParam_q );
	writeBignum( stream, &rsaKey->rsaParam_exponent1 );
	writeBignum( stream, &rsaKey->rsaParam_exponent2 );
	status = writeBignum( stream, &rsaKey->rsaParam_u );
	if( calculatedPrivateExponent )
		BN_clear( ( BIGNUM * ) d );

	return( status );
	}
#endif /* USE_PKCS12 */

/* Umbrella private-key write functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyRsaFunction( INOUT_PTR STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   IN_ENUM( KEYFORMAT ) \
										const KEYFORMAT_TYPE formatType,
									   IN_BUFFER( accessKeyLen ) \
										const char *accessKey, 
									   IN_LENGTH_FIXED( 11 ) \
										const int accessKeyLen )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 11 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 11 || memcmp( accessKey, "private_key", 11 ) || \
		( formatType != KEYFORMAT_PRIVATE && \
		  formatType != KEYFORMAT_PRIVATE_EXT && \
		  formatType != KEYFORMAT_PRIVATE_OLD ) )
		retIntError();

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( writeRsaPrivateKey( stream, contextInfoPtr, FALSE ) );

		case KEYFORMAT_PRIVATE_EXT:
			return( writeRsaPrivateKey( stream, contextInfoPtr, TRUE ) );

#ifdef USE_PKCS12
		case KEYFORMAT_PRIVATE_OLD:
			return( writeRsaPrivateKeyOld( stream, contextInfoPtr ) );
#endif /* USE_PKCS12 */
		}

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyDlpFunction( INOUT_PTR STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   IN_ENUM( KEYFORMAT ) \
										const KEYFORMAT_TYPE formatType,
									   IN_BUFFER( accessKeyLen ) \
										const char *accessKey, 
									   IN_LENGTH_FIXED( 11 ) \
										const int accessKeyLen )
	{
	const PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DH || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	REQUIRES( sanityCheckPKCInfo( dlpKey ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 11 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 11 || memcmp( accessKey, "private_key", 11 ) || \
		( formatType != KEYFORMAT_PRIVATE && \
		  formatType != KEYFORMAT_PRIVATE_EXT ) )
		retIntError();

	/* If we're using the extended format, write the public-key binding 
	   value as an ESSCertIDv2 before we write the private-key data */
	if( formatType == KEYFORMAT_PRIVATE_EXT )
		{
		BYTE spkiHash[ CRYPT_MAX_HASHSIZE + 8 ];
		int status;

		status = getSPKIHash( contextInfoPtr, spkiHash, 32 );
		if( cryptStatusError( status ) )
			return( status );
		writeSequence( stream, sizeofObject( sizeofObject( 32 ) ) + \
							   sizeofBignum( &dlpKey->dlpParam_x ) );
		writeSequence( stream, sizeofObject( 32 ) );
		status = writeOctetString( stream, spkiHash, 32, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* When we're generating a DH key ID only p, q, and g are initialised so 
	   we write a special-case zero y value.  This is a somewhat ugly side-
	   effect of the odd way in which DH "public keys" work */
	if( BN_is_zero( &dlpKey->dlpParam_y ) )
		return( writeShortInteger( stream, 0, DEFAULT_TAG ) );

	/* Write the key components */
	return( writeBignum( stream, &dlpKey->dlpParam_x ) );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyEccFunction( INOUT_PTR STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   IN_ENUM( KEYFORMAT ) \
										const KEYFORMAT_TYPE formatType,
									   IN_BUFFER( accessKeyLen ) \
										const char *accessKey, 
									   IN_LENGTH_FIXED( 11 ) \
										const int accessKeyLen )
	{
	const PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( sanityCheckPKCInfo( eccKey ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 11 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 11 || memcmp( accessKey, "private_key", 11 ) || \
		( formatType != KEYFORMAT_PRIVATE && \
		  formatType != KEYFORMAT_PRIVATE_EXT ) )
		retIntError();

	/* If we're using the extended format, write the public-key binding 
	   value as an ESSCertIDv2 before we write the private-key data */
	if( formatType == KEYFORMAT_PRIVATE_EXT )
		{
		BYTE spkiHash[ CRYPT_MAX_HASHSIZE + 8 ];
		int status;

		status = getSPKIHash( contextInfoPtr, spkiHash, 32 );
		if( cryptStatusError( status ) )
			return( status );
		writeSequence( stream, sizeofObject( sizeofObject( 32 ) ) + \
							   sizeofBignum( &eccKey->eccParam_d ) );
		writeSequence( stream, sizeofObject( 32 ) );
		status = writeOctetString( stream, spkiHash, 32, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the key components */
	return( writeBignum( stream, &eccKey->eccParam_d ) );
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_EDDSA ) || defined( USE_25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyEddsaFunction( INOUT_PTR STREAM *stream, 
											const CONTEXT_INFO *contextInfoPtr,
										 IN_ENUM( KEYFORMAT ) \
											const KEYFORMAT_TYPE formatType,
										 IN_BUFFER( accessKeyLen ) \
											const char *accessKey, 
										 IN_LENGTH_FIXED( 11 ) \
											const int accessKeyLen )
	{
	const PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_EDDSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 ) );
	REQUIRES( sanityCheckPKCInfo( eccKey ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 11 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 11 || memcmp( accessKey, "private_key", 11 ) || \
		( formatType != KEYFORMAT_PRIVATE && \
		  formatType != KEYFORMAT_PRIVATE_EXT ) )
		retIntError();

	retIntError();
	}
#endif /* USE_EDDSA || USE_25519 */
#endif /* USE_INT_ASN1 */

/****************************************************************************
*																			*
*							Context Access Routines							*
*																			*
****************************************************************************/

#ifndef USE_INT_ASN1

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyNullFunction( INOUT_PTR STREAM *stream, 
										const CONTEXT_INFO *contextInfoPtr,
										IN_ENUM( KEYFORMAT ) \
											const KEYFORMAT_TYPE formatType,
										IN_BUFFER( accessKeyLen ) \
											const char *accessKey, 
										IN_LENGTH_FIXED( 11 ) \
											const int accessKeyLen )
	{
	UNUSED_ARG( stream );
	UNUSED_ARG( contextInfoPtr );
	UNUSED_ARG( accessKey );

	return( CRYPT_ERROR_NOTAVAIL );
	}
#endif /* USE_INT_ASN1 */

STDC_NONNULL_ARG( ( 1 ) ) \
void initPrivKeyWrite( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	CRYPT_ALGO_TYPE cryptAlgo;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_V( sanityCheckContext( contextInfoPtr ) );
	REQUIRES_V( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES_V( capabilityInfoPtr != NULL );

	cryptAlgo = capabilityInfoPtr->cryptAlgo;

	/* Set the access method pointers */
	if( isDlpAlgo( cryptAlgo ) )
		{
#ifdef USE_INT_ASN1
		FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyDlpFunction );
#else
		FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyNullFunction );
#endif /* USE_INT_ASN1 */

		return;
		}
#if defined( USE_ECDH ) || defined( USE_ECDSA ) || \
	defined( USE_EDDSA ) || defined( USE_25519 )
	if( isEccAlgo( cryptAlgo ) )
		{
#if defined( USE_EDDSA ) || defined( USE_25519 )
		if( cryptAlgo == CRYPT_ALGO_EDDSA || cryptAlgo == CRYPT_ALGO_25519 )
			{
#ifdef USE_INT_ASN1
			FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyEddsaFunction );
#else
			FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyNullFunction );
#endif /* USE_INT_ASN1 */
			return;
			}
#endif /* USE_EDDSA || USE_25519 */

#ifdef USE_INT_ASN1
		FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyEccFunction );
#else
		FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyNullFunction );
#endif /* USE_INT_ASN1 */

		return;
		}
#endif /* USE_ECDH || USE_ECDSA || USE_EDDSA || USE_25519 */
#ifdef USE_INT_ASN1
	FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyRsaFunction );
#else
	FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyNullFunction );
#endif /* USE_INT_ASN1 */
	}
#else

STDC_NONNULL_ARG( ( 1 ) ) \
void initPrivKeyWrite( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	}
#endif /* USE_PKC */
=======
/****************************************************************************
*																			*
*							Private Key Write Routines						*
*						Copyright Peter Gutmann 1992-2020					*
*																			*
****************************************************************************/

#include <stdio.h>
#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "context/context.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKC

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the hash of the SPKI, used to cryptographically bind the public key
   to the private-key components */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getSPKIHash( const CONTEXT_INFO *contextInfoPtr,
						OUT_BUFFER_FIXED_C( 32 ) BYTE *hashValue,
						IN_LENGTH_FIXED( 32 ) const int hashValueLength ) 
	{
	const PKC_CALCULATEKEYID_FUNCTION calculateKeyIDFunction = \
				( PKC_CALCULATEKEYID_FUNCTION ) \
				FNPTR_GET( contextInfoPtr->ctxPKC->calculateKeyIDFunction );

	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( hashValue, hashValueLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( hashValueLength == 32 );
	REQUIRES( calculateKeyIDFunction != NULL );

	/* Clear return value */
	REQUIRES( hashValueLength == 32 );
	memset( hashValue, 0, min( 16, hashValueLength ) );

	/* The keyID calculation function can either update the context 
	   information with various key IDs or just return a single key ID 
	   value.  For the former the contextInfoPtr is non-const while for the
	   latter it's const, however the function has to use the lowest-common-
	   denominator which is non-const so we make contextInfoPtr look like 
	   it's non-const */
	return( calculateKeyIDFunction( ( CONTEXT_INFO * ) contextInfoPtr, 
									hashValue, hashValueLength, 
									CRYPT_ALGO_SHA2 ) );
	}

/****************************************************************************
*																			*
*								Write Private Keys							*
*																			*
****************************************************************************/

#ifdef USE_INT_ASN1

/* Write private keys */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRsaPrivateKey( INOUT_PTR STREAM *stream, 
							   IN_PTR const CONTEXT_INFO *contextInfoPtr,
							   IN_BOOL const BOOLEAN useExtFormat )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	BYTE spkiHash[ CRYPT_MAX_HASHSIZE + 8 ];
	int length = sizeofBignum( &rsaKey->rsaParam_p ) + \
				 sizeofBignum( &rsaKey->rsaParam_q );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isBooleanValue( useExtFormat ) );
	REQUIRES( sanityCheckPKCInfo( rsaKey ) );

	/* Calculate the hash of the SPKI if we're cryptographically binding the 
	   public-key components to the private key ones */
	if( useExtFormat )
		{
		status = getSPKIHash( contextInfoPtr, spkiHash, 32 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Add the length of any optional components that may be present */
	if( !BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		{
		length += sizeofBignum( &rsaKey->rsaParam_exponent1 ) + \
				  sizeofBignum( &rsaKey->rsaParam_exponent2 ) + \
				  sizeofBignum( &rsaKey->rsaParam_u );
		}

	/* If we're using the extended format, write the public-key binding 
	   value as an ESSCertIDv2 before we write the private-key data */
	if( useExtFormat )
		{
		writeSequence( stream, sizeofObject( sizeofObject( 32 ) ) + \
							   sizeofObject( length ) );
		writeSequence( stream, sizeofObject( 32 ) );
		status = writeOctetString( stream, spkiHash, 32, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the the PKC fields */
	writeSequence( stream, length );
	writeBignumTag( stream, &rsaKey->rsaParam_p, 3 );
	if( BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		return( writeBignumTag( stream, &rsaKey->rsaParam_q, 4 ) );
	writeBignumTag( stream, &rsaKey->rsaParam_q, 4 );
	writeBignumTag( stream, &rsaKey->rsaParam_exponent1, 5 );
	writeBignumTag( stream, &rsaKey->rsaParam_exponent2, 6 );
	return( writeBignumTag( stream, &rsaKey->rsaParam_u, 7 ) );
	}

#ifdef USE_PKCS12

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRsaPrivateKeyOld( INOUT_PTR STREAM *stream, 
								  const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	const BIGNUM *d = &rsaKey->rsaParam_d;
	BOOLEAN calculatedPrivateExponent = FALSE;
	int length = sizeofShortInteger( 0 ) + \
				 sizeofBignum( &rsaKey->rsaParam_n ) + \
				 sizeofBignum( &rsaKey->rsaParam_e ) + \
				 sizeofBignum( &rsaKey->rsaParam_p ) + \
				 sizeofBignum( &rsaKey->rsaParam_q ) + \
				 sizeofBignum( &rsaKey->rsaParam_exponent1 ) + \
				 sizeofBignum( &rsaKey->rsaParam_exponent2 ) + \
				 sizeofBignum( &rsaKey->rsaParam_u );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( sanityCheckPKCInfo( rsaKey ) );

	/* The older format is somewhat restricted in terms of what can be
	   written since all components must be present, even the ones that are
	   never used (if d isn't present we calculate it on the fly, see 
	   below).  If anything is missing we can't write the key since nothing 
	   would be able to read it */
	if( BN_is_zero( &rsaKey->rsaParam_n ) || \
		BN_is_zero( &rsaKey->rsaParam_p ) || \
		BN_is_zero( &rsaKey->rsaParam_exponent1 ) )
		{
		return( CRYPT_ERROR_NOTAVAIL );
		}

	/* If the private-key d value isn't present, calculate it from p and q.
	   This is the most common missing value since it's not needed for the
	   CRT so we calculate a temporary value for this if it's not present.

	   This is somewhat ugly in that we're both messing with a const 
	   parameter and performing complex bignum ops as part of what should
	   only be a straight data write, but there's no easy way around this 
	   unless we create and manage our own bignum data values here */
	if( BN_is_zero( d ) )
		{
		BIGNUM *tmp = ( BIGNUM * ) &rsaKey->tmp1;
		int bnStatus = BN_STATUS;

		/* Use the extended Euclidean algorithm to calculate d from p and q:

			phi( n ) = (p - 1) * (q - 1) 
					 = n - p - q + 1
			d = e^-1 % phi( n ) */
		CKPTR( BN_copy( tmp, &rsaKey->rsaParam_n ) );
		CK( BN_sub( tmp, tmp, &rsaKey->rsaParam_p ) );
		CK( BN_sub( tmp, tmp, &rsaKey->rsaParam_q ) );
		CK( BN_add_word( tmp, 1 ) );
		CKPTR( BN_mod_inverse( tmp, &rsaKey->rsaParam_e, tmp, 
							   ( BN_CTX * ) &rsaKey->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		d = tmp;
		calculatedPrivateExponent = TRUE;
		}
	length += sizeofBignum( d );

	/* Write the the PKC fields */
	writeSequence( stream, sizeofShortInteger( 0 ) + \
						   sizeofAlgoID( CRYPT_ALGO_RSA ) + \
						   sizeofShortObject( \
								sizeofShortObject( length ) ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeAlgoID( stream, CRYPT_ALGO_RSA, DEFAULT_TAG );
	writeOctetStringHole( stream, sizeofShortObject( length ), 
						  DEFAULT_TAG );
	writeSequence( stream, length );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeBignum( stream, &rsaKey->rsaParam_n );
	writeBignum( stream, &rsaKey->rsaParam_e );
	writeBignum( stream, d );
	writeBignum( stream, &rsaKey->rsaParam_p );
	writeBignum( stream, &rsaKey->rsaParam_q );
	writeBignum( stream, &rsaKey->rsaParam_exponent1 );
	writeBignum( stream, &rsaKey->rsaParam_exponent2 );
	status = writeBignum( stream, &rsaKey->rsaParam_u );
	if( calculatedPrivateExponent )
		BN_clear( ( BIGNUM * ) d );

	return( status );
	}
#endif /* USE_PKCS12 */

/* Umbrella private-key write functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyRsaFunction( INOUT_PTR STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   IN_ENUM( KEYFORMAT ) \
										const KEYFORMAT_TYPE formatType,
									   IN_BUFFER( accessKeyLen ) \
										const char *accessKey, 
									   IN_LENGTH_FIXED( 11 ) \
										const int accessKeyLen )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 11 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 11 || memcmp( accessKey, "private_key", 11 ) || \
		( formatType != KEYFORMAT_PRIVATE && \
		  formatType != KEYFORMAT_PRIVATE_EXT && \
		  formatType != KEYFORMAT_PRIVATE_OLD ) )
		retIntError();

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( writeRsaPrivateKey( stream, contextInfoPtr, FALSE ) );

		case KEYFORMAT_PRIVATE_EXT:
			return( writeRsaPrivateKey( stream, contextInfoPtr, TRUE ) );

#ifdef USE_PKCS12
		case KEYFORMAT_PRIVATE_OLD:
			return( writeRsaPrivateKeyOld( stream, contextInfoPtr ) );
#endif /* USE_PKCS12 */
		}

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyDlpFunction( INOUT_PTR STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   IN_ENUM( KEYFORMAT ) \
										const KEYFORMAT_TYPE formatType,
									   IN_BUFFER( accessKeyLen ) \
										const char *accessKey, 
									   IN_LENGTH_FIXED( 11 ) \
										const int accessKeyLen )
	{
	const PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DH || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	REQUIRES( sanityCheckPKCInfo( dlpKey ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 11 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 11 || memcmp( accessKey, "private_key", 11 ) || \
		( formatType != KEYFORMAT_PRIVATE && \
		  formatType != KEYFORMAT_PRIVATE_EXT ) )
		retIntError();

	/* If we're using the extended format, write the public-key binding 
	   value as an ESSCertIDv2 before we write the private-key data */
	if( formatType == KEYFORMAT_PRIVATE_EXT )
		{
		BYTE spkiHash[ CRYPT_MAX_HASHSIZE + 8 ];
		int status;

		status = getSPKIHash( contextInfoPtr, spkiHash, 32 );
		if( cryptStatusError( status ) )
			return( status );
		writeSequence( stream, sizeofObject( sizeofObject( 32 ) ) + \
							   sizeofBignum( &dlpKey->dlpParam_x ) );
		writeSequence( stream, sizeofObject( 32 ) );
		status = writeOctetString( stream, spkiHash, 32, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* When we're generating a DH key ID only p, q, and g are initialised so 
	   we write a special-case zero y value.  This is a somewhat ugly side-
	   effect of the odd way in which DH "public keys" work */
	if( BN_is_zero( &dlpKey->dlpParam_y ) )
		return( writeShortInteger( stream, 0, DEFAULT_TAG ) );

	/* Write the key components */
	return( writeBignum( stream, &dlpKey->dlpParam_x ) );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyEccFunction( INOUT_PTR STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   IN_ENUM( KEYFORMAT ) \
										const KEYFORMAT_TYPE formatType,
									   IN_BUFFER( accessKeyLen ) \
										const char *accessKey, 
									   IN_LENGTH_FIXED( 11 ) \
										const int accessKeyLen )
	{
	const PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( sanityCheckPKCInfo( eccKey ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 11 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 11 || memcmp( accessKey, "private_key", 11 ) || \
		( formatType != KEYFORMAT_PRIVATE && \
		  formatType != KEYFORMAT_PRIVATE_EXT ) )
		retIntError();

	/* If we're using the extended format, write the public-key binding 
	   value as an ESSCertIDv2 before we write the private-key data */
	if( formatType == KEYFORMAT_PRIVATE_EXT )
		{
		BYTE spkiHash[ CRYPT_MAX_HASHSIZE + 8 ];
		int status;

		status = getSPKIHash( contextInfoPtr, spkiHash, 32 );
		if( cryptStatusError( status ) )
			return( status );
		writeSequence( stream, sizeofObject( sizeofObject( 32 ) ) + \
							   sizeofBignum( &eccKey->eccParam_d ) );
		writeSequence( stream, sizeofObject( 32 ) );
		status = writeOctetString( stream, spkiHash, 32, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the key components */
	return( writeBignum( stream, &eccKey->eccParam_d ) );
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_EDDSA ) || defined( USE_25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyEddsaFunction( INOUT_PTR STREAM *stream, 
											const CONTEXT_INFO *contextInfoPtr,
										 IN_ENUM( KEYFORMAT ) \
											const KEYFORMAT_TYPE formatType,
										 IN_BUFFER( accessKeyLen ) \
											const char *accessKey, 
										 IN_LENGTH_FIXED( 11 ) \
											const int accessKeyLen )
	{
	const PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_EDDSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 ) );
	REQUIRES( sanityCheckPKCInfo( eccKey ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 11 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 11 || memcmp( accessKey, "private_key", 11 ) || \
		( formatType != KEYFORMAT_PRIVATE && \
		  formatType != KEYFORMAT_PRIVATE_EXT ) )
		retIntError();

	retIntError();
	}
#endif /* USE_EDDSA || USE_25519 */
#endif /* USE_INT_ASN1 */

/****************************************************************************
*																			*
*							Context Access Routines							*
*																			*
****************************************************************************/

#ifndef USE_INT_ASN1

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writePrivateKeyNullFunction( INOUT_PTR STREAM *stream, 
										const CONTEXT_INFO *contextInfoPtr,
										IN_ENUM( KEYFORMAT ) \
											const KEYFORMAT_TYPE formatType,
										IN_BUFFER( accessKeyLen ) \
											const char *accessKey, 
										IN_LENGTH_FIXED( 11 ) \
											const int accessKeyLen )
	{
	UNUSED_ARG( stream );
	UNUSED_ARG( contextInfoPtr );
	UNUSED_ARG( accessKey );

	return( CRYPT_ERROR_NOTAVAIL );
	}
#endif /* USE_INT_ASN1 */

STDC_NONNULL_ARG( ( 1 ) ) \
void initPrivKeyWrite( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	CRYPT_ALGO_TYPE cryptAlgo;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_V( sanityCheckContext( contextInfoPtr ) );
	REQUIRES_V( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES_V( capabilityInfoPtr != NULL );

	cryptAlgo = capabilityInfoPtr->cryptAlgo;

	/* Set the access method pointers */
	if( isDlpAlgo( cryptAlgo ) )
		{
#ifdef USE_INT_ASN1
		FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyDlpFunction );
#else
		FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyNullFunction );
#endif /* USE_INT_ASN1 */

		return;
		}
#if defined( USE_ECDH ) || defined( USE_ECDSA ) || \
	defined( USE_EDDSA ) || defined( USE_25519 )
	if( isEccAlgo( cryptAlgo ) )
		{
#if defined( USE_EDDSA ) || defined( USE_25519 )
		if( cryptAlgo == CRYPT_ALGO_EDDSA || cryptAlgo == CRYPT_ALGO_25519 )
			{
#ifdef USE_INT_ASN1
			FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyEddsaFunction );
#else
			FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyNullFunction );
#endif /* USE_INT_ASN1 */
			return;
			}
#endif /* USE_EDDSA || USE_25519 */

#ifdef USE_INT_ASN1
		FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyEccFunction );
#else
		FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyNullFunction );
#endif /* USE_INT_ASN1 */

		return;
		}
#endif /* USE_ECDH || USE_ECDSA || USE_EDDSA || USE_25519 */
#ifdef USE_INT_ASN1
	FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyRsaFunction );
#else
	FNPTR_SET( pkcInfo->writePrivateKeyFunction, writePrivateKeyNullFunction );
#endif /* USE_INT_ASN1 */
	}
#else

STDC_NONNULL_ARG( ( 1 ) ) \
void initPrivKeyWrite( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	}
#endif /* USE_PKC */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
