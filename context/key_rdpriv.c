/****************************************************************************
*																			*
*							Private Key Read Routines						*
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

#if defined( USE_KEYSETS ) && defined( USE_PKC )

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Read and check the SPKI hash that binds the public key data to the 
   private key data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCheckSPKIHash( INOUT_PTR STREAM *stream,
							  const CONTEXT_INFO *contextInfoPtr ) 
	{
	const PKC_CALCULATEKEYID_FUNCTION calculateKeyIDFunction = \
				( PKC_CALCULATEKEYID_FUNCTION ) \
				FNPTR_GET( contextInfoPtr->ctxPKC->calculateKeyIDFunction );
	BYTE readSPKIhash[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE calculatedSPKIhash[ CRYPT_MAX_HASHSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( calculateKeyIDFunction != NULL );

	/* Read the ESSCertIDv2 that contains the SPKI hash.  This assumes that
	   the hash used is always SHA-2 */
	readSequence( stream, NULL );
	status = readOctetString( stream, readSPKIhash, &length, 32, 32 );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 32 )
		return( CRYPT_ERROR_BADDATA );

	/* Get the hash of the SPKI for the current context data.  The keyID 
	   calculation function can either update the context information with 
	   various key IDs or just return a single key ID value.  For the former 
	   the contextInfoPtr is non-const while for the latter it's const, 
	   however the function has to use the lowest-common-denominator which 
	   is non-const so we make contextInfoPtr look like it's non-const */
	status = calculateKeyIDFunction( ( CONTEXT_INFO * ) contextInfoPtr, 
									 calculatedSPKIhash, 32, 
									 CRYPT_ALGO_SHA2 );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_SIGNATURE );
	
	/* Make sure that the hash value stored with the private-key data 
	   matches the value for the public key that we're using */
	if( compareDataConstTime( readSPKIhash, calculatedSPKIhash, 
							  32 ) != TRUE )
		{
		DEBUG_DIAG(( "Public key doesn't match private key" ));
		assert_nofuzz( DEBUG_WARN );
		return( CRYPT_ERROR_SIGNATURE );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read PKCS #15 Private Keys						*
*																			*
****************************************************************************/

#ifdef USE_INT_ASN1

/* Read private key components.  These functions assume that the public
   portions of the context have already been set up */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRsaPrivateKey( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							  IN_BOOL const BOOLEAN useExtFormat,
							  IN_BOOL const BOOLEAN checkRead )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	READ_BIGNUM_FUNCTION readBignumFunction = checkRead ? \
									checkBignumRead : readBignumTag;
	int tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RSA );
	REQUIRES( isBooleanValue( useExtFormat ) );
	REQUIRES( isBooleanValue( checkRead ) );

	/* If we're using the extended format, read the outer wrapper and read 
	   and check the hash that binds the public key data to the private key 
	   data */
	if( useExtFormat )
		{
		status = readSequence( stream, NULL );
		if( cryptStatusOK( status ) )
			status = readCheckSPKIHash( stream, contextInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the header */
	status = readSequence( stream, NULL );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 0 ) )
		{
		/* Erroneously written in older code */
		status = readConstructed( stream, NULL, 0 );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the key components */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG_PRIMITIVE( 0 ) )
		{
		/* The public components may already have been read when we read a
		   corresponding public key or certificate so we only read them if
		   they're not already present */
		if( BN_is_zero( &rsaKey->rsaParam_n ) && \
			BN_is_zero( &rsaKey->rsaParam_e ) )
			{
			status = readBignumFunction( stream, &rsaKey->rsaParam_n, 
										 RSAPARAM_MIN_N, RSAPARAM_MAX_N, 
										 NULL, BIGNUM_CHECK_VALUE_PKC, 0 );
			if( cryptStatusOK( status ) )
				{
				status = readBignumFunction( stream, &rsaKey->rsaParam_e, 
											 RSAPARAM_MIN_E, RSAPARAM_MAX_E, 
											 &rsaKey->rsaParam_n, 
											 BIGNUM_CHECK_VALUE, 1 );
				}
			}
		else
			{
			/* The key components are already present, skip them */
			REQUIRES( !BN_is_zero( &rsaKey->rsaParam_n ) && \
					  !BN_is_zero( &rsaKey->rsaParam_e ) );
			readUniversal( stream );
			status = readUniversal( stream );
			}
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG_PRIMITIVE( 2 ) )
		{
		/* d isn't used so we skip it */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = readBignumFunction( stream, &rsaKey->rsaParam_p, 
								 RSAPARAM_MIN_P, RSAPARAM_MAX_P, 
								 &rsaKey->rsaParam_n, 
								 BIGNUM_CHECK_VALUE, 3 );
	if( cryptStatusOK( status ) )
		{
		status = readBignumFunction( stream, &rsaKey->rsaParam_q, 
									 RSAPARAM_MIN_Q, RSAPARAM_MAX_Q, 
									 &rsaKey->rsaParam_n, 
									 BIGNUM_CHECK_VALUE, 4 );
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG_PRIMITIVE( 5 ) )
		{
		status = readBignumFunction( stream, &rsaKey->rsaParam_exponent1, 
									 RSAPARAM_MIN_EXP1, RSAPARAM_MAX_EXP1, 
									 &rsaKey->rsaParam_n, 
									 BIGNUM_CHECK_VALUE, 5 );
		if( cryptStatusOK( status ) )
			{
			status = readBignumFunction( stream, &rsaKey->rsaParam_exponent2, 
										 RSAPARAM_MIN_EXP2, RSAPARAM_MAX_EXP2, 
										 &rsaKey->rsaParam_n, 
										 BIGNUM_CHECK_VALUE, 6 );
			}
		if( cryptStatusOK( status ) )
			{
			status = readBignumFunction( stream, &rsaKey->rsaParam_u, 
										 RSAPARAM_MIN_U, RSAPARAM_MAX_U, 
										 &rsaKey->rsaParam_n, 
										 BIGNUM_CHECK_VALUE, 7 );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( rsaKey ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readDlpPrivateKey( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							  IN_BOOL const BOOLEAN useExtFormat,
							  IN_BOOL const BOOLEAN checkRead )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const DH_DOMAINPARAMS *domainParams = dlpKey->domainParams;
	const BIGNUM *p = ( domainParams != NULL ) ? \
					  &domainParams->p : &dlpKey->dlpParam_p;
	READ_BIGNUM_FUNCTION readBignumFunction = checkRead ? \
									checkBignumRead : readBignumTag;
	int tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DH || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	REQUIRES( isBooleanValue( useExtFormat ) );
	REQUIRES( isBooleanValue( checkRead ) );

	/* If we're using the extended format, read the outer wrapper and read 
	   and check the hash that binds the public key data to the private key 
	   data */
	if( useExtFormat )
		{
		status = readSequence( stream, NULL );
		if( cryptStatusOK( status ) )
			status = readCheckSPKIHash( stream, contextInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the key components */
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( tag == BER_SEQUENCE )
		{
		/* Erroneously written in older code */
		status = readSequence( stream, NULL );
		if( cryptStatusOK( status ) )
			{
			status = readBignumFunction( stream, &dlpKey->dlpParam_x,
										 DLPPARAM_MIN_X, DLPPARAM_MAX_X, 
										 p, BIGNUM_CHECK_VALUE_PKC, 0 );
			}
		return( status );
		}
	status = readBignumFunction( stream, &dlpKey->dlpParam_x,
								 DLPPARAM_MIN_X, DLPPARAM_MAX_X, p,
								 BIGNUM_CHECK_VALUE, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( dlpKey ) );

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readEccPrivateKey( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							  IN_BOOL const BOOLEAN useExtFormat,
							  IN_BOOL const BOOLEAN checkRead )
	{
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	READ_BIGNUM_FUNCTION readBignumFunction = checkRead ? \
									checkBignumRead : readBignumTag;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( isBooleanValue( useExtFormat ) );
	REQUIRES( isBooleanValue( checkRead ) );

	/* If we're using the extended format, read the outer wrapper and read 
	   and check the hash that binds the public key data to the private key 
	   data */
	if( useExtFormat )
		{
		status = readSequence( stream, NULL );
		if( cryptStatusOK( status ) )
			status = readCheckSPKIHash( stream, contextInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the key components.  Note that we can't use the ECC p value for
	   a range check because it hasn't been set yet, all that we have at 
	   this point is a curve ID */
	status = readBignumFunction( stream, &eccKey->eccParam_d,
								 ECCPARAM_MIN_D, ECCPARAM_MAX_D, NULL,
								 BIGNUM_CHECK_VALUE_ECC, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( eccKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_EDDSA ) || defined( USE_25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readEddsaPrivateKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_BOOL const BOOLEAN useExtFormat,
								IN_BOOL const BOOLEAN checkRead )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_EDDSA );
	REQUIRES( isBooleanValue( useExtFormat ) );
	REQUIRES( isBooleanValue( checkRead ) );

	retIntError();
	}
#endif /* USE_EDDSA || USE_25519 */
#endif /* USE_INT_ASN1 */

/****************************************************************************
*																			*
*							Read PKCS #12 Private Keys						*
*																			*
****************************************************************************/

/* Read private key components.  These functions assume that the public
   portions of the context have already been set up */

#if defined( USE_PKCS12 ) && defined( USE_INT_ASN1 )

#define OID_X509_KEYUSAGE	MKOID( "\x06\x03\x55\x1D\x0F" )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRsaPrivateKeyOld( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	CRYPT_ALGO_TYPE cryptAlgo DUMMY_INIT;
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const int startPos = stell( stream );
	int length, endPos, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RSA );
	REQUIRES( isIntegerRange( startPos ) );

	/* Skip the PKCS #8 wrapper.  When we read the OCTET STRING 
	   encapsulation we use MIN_PKCSIZE_THRESHOLD rather than MIN_PKCSIZE
	   so that a too-short key will get to readBignum(), which returns an 
	   appropriate error code */
	readSequence( stream, &length );			/* Outer wrapper */
	status = readShortInteger( stream, NULL );	/* Version */
	if( cryptStatusOK( status ) )
		status = readAlgoID( stream, &cryptAlgo, ALGOID_CLASS_PKC );
	if( cryptStatusError( status ) || cryptAlgo != CRYPT_ALGO_RSA )
		return( CRYPT_ERROR_BADDATA );
	status = readOctetStringHole( stream, NULL, 
								  ( 2 * MIN_PKCSIZE_THRESHOLD ) + \
									( 5 * ( MIN_PKCSIZE_THRESHOLD / 2 ) ), 
								  DEFAULT_TAG );
	if( cryptStatusError( status ) )			/* OCTET STRING encaps.*/
		return( status );

	/* Read the header */
	readSequence( stream, NULL );
	status = readShortInteger( stream, NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the RSA key components, skipping n and e if we've already got 
	   them via the associated public key/certificate */
	if( BN_is_zero( &rsaKey->rsaParam_n ) )
		{
		status = readBignum( stream, &rsaKey->rsaParam_n,
							 RSAPARAM_MIN_N, RSAPARAM_MAX_N, NULL, 
							 BIGNUM_CHECK_VALUE_PKC );
		if( cryptStatusOK( status ) )
			{
			status = readBignum( stream, &rsaKey->rsaParam_e,
								 RSAPARAM_MIN_E, RSAPARAM_MAX_E,
								 &rsaKey->rsaParam_n, BIGNUM_CHECK_VALUE );
			}
		}
	else
		{
		readUniversal( stream );
		status = readUniversal( stream );
		}
	if( cryptStatusOK( status ) )
		{
		/* d isn't used so we skip it */
		status = readUniversal( stream );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignum( stream, &rsaKey->rsaParam_p,
							 RSAPARAM_MIN_P, RSAPARAM_MAX_P,
							 &rsaKey->rsaParam_n, BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignum( stream, &rsaKey->rsaParam_q,
							 RSAPARAM_MIN_Q, RSAPARAM_MAX_Q,
							 &rsaKey->rsaParam_n, BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignum( stream, &rsaKey->rsaParam_exponent1,
							 RSAPARAM_MIN_EXP1, RSAPARAM_MAX_EXP1,
							 &rsaKey->rsaParam_n, BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignum( stream, &rsaKey->rsaParam_exponent2,
							 RSAPARAM_MIN_EXP2, RSAPARAM_MAX_EXP2,
							 &rsaKey->rsaParam_n, BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignum( stream, &rsaKey->rsaParam_u,
							 RSAPARAM_MIN_U, RSAPARAM_MAX_U,
							 &rsaKey->rsaParam_n, BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Check whether there are any attributes present */
	if( stell( stream ) >= startPos + length )
		return( CRYPT_OK );

	/* Read the attribute wrapper */
	status = readConstructed( stream, &length, 0 );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );

	/* Read the collection of attributes.  Unlike any other key-storage 
	   format, PKCS #8 stores the key usage information as an X.509 
	   attribute alongside the encrypted private key data so we have to
	   process whatever attributes may be present in order to find the
	   keyUsage (if there is any) in order to set the object action 
	   permissions */
	LOOP_MED_WHILE( stell( stream ) < endPos )
		{
		BYTE oid[ MAX_OID_SIZE + 8 ];
		int oidLength, actionFlags, value;

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* Read the attribute.  Since there's only one attribute type that 
		   we can use, we hardcode the read in here rather than performing a 
		   general-purpose attribute read */
		readSequence( stream, NULL );
		status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			return( status );

		/* If it's not a key-usage attribute, we can't do much with it */
		if( !matchOID( oid, oidLength, OID_X509_KEYUSAGE ) )
			{
			status = readUniversal( stream );
			if( cryptStatusError( status ) )
				return( status );
			continue;
			}

		/* Read the keyUsage attribute and convert it into cryptlib action 
		   permissions */
		readSet( stream, NULL );
		status = readBitString( stream, &value );
		if( cryptStatusError( status ) )
			return( status );
		actionFlags = ACTION_PERM_NONE;
		if( value & ( KEYUSAGE_SIGN | KEYUSAGE_CA ) )
			{
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
										   ACTION_PERM_ALL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
										   ACTION_PERM_ALL );
			}
		if( value & KEYUSAGE_CRYPT )
			{
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
										   ACTION_PERM_ALL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
										   ACTION_PERM_ALL );
			}
#if 0	/* 11/6/13 Windows sets these flags to what are effectively
				   gibberish values (dataEncipherment for a signing key,
				   digitalSignature for an encryption key) so in order
				   to be able to use the key we have to ignore the keyUsage 
				   settings, in the same way that every other application 
				   seems to */
		if( actionFlags == ACTION_PERM_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		status = krnlSendMessage( contextInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE, &actionFlags, 
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
		if( cryptStatusError( status ) )
			return( status );
#else
		assert( actionFlags != ACTION_PERM_NONE );	/* Warn in debug mode */
#endif /* 0 */
		}
	ENSURES( LOOP_BOUND_OK );

	ENSURES( sanityCheckPKCInfo( rsaKey ) );

	return( CRYPT_OK );
	}

#ifdef USE_DSA

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readDsaPrivateKeyOld( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	CRYPT_ALGO_TYPE cryptAlgo DUMMY_INIT;
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DSA );

	/* Skip the PKCS #8 wrapper */
	readSequence( stream, NULL );				/* Outer wrapper */
	status = readShortInteger( stream, NULL );	/* Version */
	if( cryptStatusOK( status ) )
		{
		ALGOID_PARAMS algoIDparams;

		status = readAlgoIDex( stream, &cryptAlgo, &algoIDparams, 
							   ALGOID_CLASS_PKC );
		}
	if( cryptStatusError( status ) || cryptAlgo != CRYPT_ALGO_DSA )
		return( CRYPT_ERROR_BADDATA );

	/* Read the DSA parameters if we haven't already got them via the
	   associated public key/certificate */
	if( BN_is_zero( &dlpKey->dlpParam_p ) )
		{
		readSequence( stream, NULL );	/* Parameter wrapper */
		status = readBignum( stream, &dlpKey->dlpParam_p,
							 DLPPARAM_MIN_P, DLPPARAM_MAX_P, NULL,
							 BIGNUM_CHECK_VALUE_PKC );
		if( cryptStatusOK( status ) )
			{
			status = readBignum( stream, &dlpKey->dlpParam_q,
								 DLPPARAM_MIN_Q, DLPPARAM_MAX_Q, NULL,
								 BIGNUM_CHECK_VALUE );
			}
		if( cryptStatusOK( status ) )
			{
			status = readBignum( stream, &dlpKey->dlpParam_g,
								 DLPPARAM_MIN_G, DLPPARAM_MAX_G, NULL,
								 BIGNUM_CHECK_VALUE );
			}
		}
	else
		status = readUniversal( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the DSA private key component */
	status = readOctetStringHole( stream, NULL, 20, DEFAULT_TAG );
	if( cryptStatusOK( status ) )	/* OCTET STRING encapsulation */
		{
		status = readBignum( stream, &dlpKey->dlpParam_x,
							 DLPPARAM_MIN_X, DLPPARAM_MAX_X,
							 &dlpKey->dlpParam_p, BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( dlpKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_DSA */

#if defined( USE_ECDH ) || defined( USE_ECDSA )

#define OID_ECPUBLICKEY		MKOID( "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01" )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readEccPrivateKeyOld( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	ALGOID_PARAMS algoIDparams;
	long value;
	int tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDSA );

	/* Read the ECC key components.  These were never standardised in any 
	   PKCS standard, nor in the PKCS #12 RFC.  RFC 5915 "Elliptic Curve 
	   Private Key Structure" specifies the format for PKCS #8 as:

		ECPrivateKey ::= SEQUENCE {
			version			INTEGER (1),
			privateKey		OCTET STRING,
			parameters	[0]	ECParameters {{ NamedCurve }} OPTIONAL,
			publicKey	[1]	BIT STRING OPTIONAL
			}

	   but this isn't what's present in the encoded form created by OpenSSL.
	   Instead it's:

		ECSomething ::= SEQUENCE {
			version			INTEGER (0),
			parameters		SEQUENCE {
				type		OBJECT IDENTIFIER ecPublicKey,
				namedCurve	OBJECT IDENTIFIER
				}
			something		OCTET STRING {
				key			ECPrivateKey		-- As above
				}
			}

	   so we have to tunnel into this in order to find the PKCS #8-like
	   data that we're actually interested in.

	   Note that we can't use the ECC p value for a range check because it 
	   hasn't been set yet, all that we have at this point is a curve ID */
	readSequence( stream, NULL );		/* Outer wrapper */
	status = readShortInteger( stream, &value );/* Version */
	if( cryptStatusError( status ) || value != 0 )
		return( CRYPT_ERROR_BADDATA );
	status = readAlgoIDex( stream, &cryptAlgo, &algoIDparams, 
						   ALGOID_CLASS_PKC );
	if( cryptStatusError( status ) || cryptAlgo != CRYPT_ALGO_ECDSA )
		return( CRYPT_ERROR_BADDATA );
	readUniversal( stream );			/* Named curve */
	readOctetStringHole( stream, NULL, MIN_PKCSIZE_ECC_THRESHOLD, 
						 DEFAULT_TAG );		/* OCTET STRING hole wrapper */
	readSequence( stream, NULL );				/* ECPrivateKey wrapper */
	status = readShortInteger( stream, &value );	/* Version */
	if( cryptStatusError( status ) || value != 1 )
		return( CRYPT_ERROR_BADDATA );

	/* We've finalled made it down to the private key value.  At this point 
	   we can't use readBignumTag() directly because it's designed to read 
	   either standard INTEGERs (via DEFAULT_TAG) or context-specific tagged 
	   items, so passing in a BER_OCTETSTRING will be interpreted as 
	   [4] IMPLICIT INTEGER rather than an OCTET STRING-tagged integer.  To 
	   get around this we read the tag separately and tell readBignumTag() 
	   to skip the tag read */
	tag = readTag( stream );
	if( cryptStatusError( tag ) || tag != BER_OCTETSTRING )
		return( CRYPT_ERROR_BADDATA );
	status = readBignumTag( stream, &eccKey->eccParam_d,
							ECCPARAM_MIN_D, ECCPARAM_MAX_D, NULL,
							BIGNUM_CHECK_VALUE_ECC, NO_TAG );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( eccKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */
#endif /* USE_PKCS12 && USE_INT_ASN1 */

/****************************************************************************
*																			*
*							Read PGP Private Keys							*
*																			*
****************************************************************************/

#ifdef USE_PGP 

/* Read PGP private key components.  This function assumes that the public
   portion of the context has already been set up */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgpRsaPrivateKey( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RSA );

	/* Read the PGP private key information.  Note that we have to read the 
	   d value here because we need it to calculate e1 and e2 */
	status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_d, 
									   bytesToBits( RSAPARAM_MIN_D ), 
									   bytesToBits( RSAPARAM_MAX_D ), 
									   &rsaKey->rsaParam_n, 
									   BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_p, 
										   bytesToBits( RSAPARAM_MIN_P ), 
										   bytesToBits( RSAPARAM_MAX_P ),
										   &rsaKey->rsaParam_n,
										   BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_q, 
										   bytesToBits( RSAPARAM_MIN_Q ), 
										   bytesToBits( RSAPARAM_MAX_Q ),
										   &rsaKey->rsaParam_n,
										   BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_u, 
										   bytesToBits( RSAPARAM_MIN_U ), 
										   bytesToBits( RSAPARAM_MAX_U ),
										   &rsaKey->rsaParam_n,
										   BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( rsaKey ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgpDlpPrivateKey( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );

	/* Read the PGP private key information */
	status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_x, 
									   bytesToBits( DLPPARAM_MIN_X ), 
									   bytesToBits( DLPPARAM_MAX_X ),
									   &dlpKey->dlpParam_p,
									   BIGNUM_CHECK_VALUE );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( dlpKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*							Private-Key Read Interface						*
*																			*
****************************************************************************/

/* Umbrella private-key read functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPrivateKeyRsaFunction( INOUT_PTR STREAM *stream, 
									  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									  IN_ENUM( KEYFORMAT ) \
										const KEYFORMAT_TYPE formatType,
									  IN_BOOL const BOOLEAN checkRead )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RSA );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( isBooleanValue( checkRead ) );

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_PRIVATE:
			return( readRsaPrivateKey( stream, contextInfoPtr, FALSE, 
									   checkRead ) );

		case KEYFORMAT_PRIVATE_EXT:
			return( readRsaPrivateKey( stream, contextInfoPtr, TRUE,
									   checkRead ) );
#endif /* USE_INT_ASN1 */

#if defined( USE_PKCS12 ) && defined( USE_INT_ASN1 )
		case KEYFORMAT_PRIVATE_OLD:
			return( readRsaPrivateKeyOld( stream, contextInfoPtr ) );
#endif /* USE_PKCS12 && USE_INT_ASN1 */

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			return( readPgpRsaPrivateKey( stream, contextInfoPtr ) );
#endif /* USE_PGP */
		}

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPrivateKeyDlpFunction( INOUT_PTR STREAM *stream, 
									  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									  IN_ENUM( KEYFORMAT )  \
										const KEYFORMAT_TYPE formatType,
									  IN_BOOL const BOOLEAN checkRead )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DH || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_DSA || \
				capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( isBooleanValue( checkRead ) );

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_PRIVATE:
			return( readDlpPrivateKey( stream, contextInfoPtr, FALSE, 
									   checkRead ) );

		case KEYFORMAT_PRIVATE_EXT:
			return( readDlpPrivateKey( stream, contextInfoPtr, TRUE,
									   checkRead ) );
#endif /* USE_INT_ASN1 */

#if defined( USE_PKCS12 ) && defined( USE_INT_ASN1 )
		case KEYFORMAT_PRIVATE_OLD:
			return( readDsaPrivateKeyOld( stream, contextInfoPtr ) );
#endif /* USE_PKCS12 && USE_INT_ASN1 */

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			return( readPgpDlpPrivateKey( stream, contextInfoPtr ) );
#endif /* USE_PGP */
		}

	retIntError();
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPrivateKeyEccFunction( INOUT_PTR STREAM *stream, 
									  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									  IN_ENUM( KEYFORMAT )  \
										const KEYFORMAT_TYPE formatType,
									  IN_BOOL const BOOLEAN checkRead )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( isBooleanValue( checkRead ) );

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_PRIVATE:
			return( readEccPrivateKey( stream, contextInfoPtr, FALSE, 
									   checkRead ) );

		case KEYFORMAT_PRIVATE_EXT:
			return( readEccPrivateKey( stream, contextInfoPtr, TRUE,
									   checkRead ) );
#endif /* USE_INT_ASN1 */

#if defined( USE_PKCS12 ) && defined( USE_INT_ASN1 )
		case KEYFORMAT_PRIVATE_OLD:
			return( readEccPrivateKeyOld( stream, contextInfoPtr ) );
#endif /* USE_PKCS12 && USE_INT_ASN1 */
		}

	retIntError();
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_EDDSA ) || defined( USE_25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPrivateKeyEddsaFunction( INOUT_PTR STREAM *stream, 
										INOUT_PTR CONTEXT_INFO *contextInfoPtr,
										IN_ENUM( KEYFORMAT )  \
											const KEYFORMAT_TYPE formatType,
										IN_BOOL const BOOLEAN checkRead )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_EDDSA );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( isBooleanValue( checkRead ) );

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_PRIVATE:
			return( readEddsaPrivateKey( stream, contextInfoPtr, FALSE, 
										 checkRead ) );

		case KEYFORMAT_PRIVATE_EXT:
			return( readEddsaPrivateKey( stream, contextInfoPtr, TRUE,
										 checkRead ) );
#endif /* USE_INT_ASN1 */
		}

	retIntError();
	}
#endif /* USE_EDDSA || USE_25519 */

/****************************************************************************
*																			*
*							Context Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initPrivKeyRead( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
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
		FNPTR_SET( pkcInfo->readPrivateKeyFunction, readPrivateKeyDlpFunction );
		return;
		}
#if defined( USE_ECDH ) || defined( USE_ECDSA ) || \
	defined( USE_EDDSA ) || defined( USE_25519 )
	if( isEccAlgo( cryptAlgo ) )
		{
#if defined( USE_EDDSA ) || defined( USE_25519 )
		if( cryptAlgo == CRYPT_ALGO_EDDSA || cryptAlgo == CRYPT_ALGO_25519 )
			{
			FNPTR_SET( pkcInfo->readPrivateKeyFunction, readPrivateKeyEddsaFunction );
			return;
			}
#endif /* USE_EDDSA || USE_25519 */
		FNPTR_SET( pkcInfo->readPrivateKeyFunction, readPrivateKeyEccFunction );
		return;
		}
#endif /* USE_ECDH || USE_ECDSA */
	FNPTR_SET( pkcInfo->readPrivateKeyFunction, readPrivateKeyRsaFunction );
	}
#else

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPrivKeyNullFunction( INOUT_PTR STREAM *stream, 
									INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									IN_ENUM( KEYFORMAT )  \
										const KEYFORMAT_TYPE formatType,
									IN_BOOL const BOOLEAN checkRead )
	{
	UNUSED_ARG( stream );
	UNUSED_ARG( contextInfoPtr );

	return( CRYPT_ERROR_NOTAVAIL );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void initPrivKeyRead( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_V( sanityCheckContext( contextInfoPtr ) );
	REQUIRES_V( contextInfoPtr->type == CONTEXT_PKC );

	/* Set the access method pointers */
	FNPTR_SET( pkcInfo->readPrivateKeyFunction, readPrivKeyNullFunction );
	}
#endif /* USE_KEYSETS && USE_PKC */
