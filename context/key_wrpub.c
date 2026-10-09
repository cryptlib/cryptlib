/****************************************************************************
*																			*
*							Public Key Write Routines						*
*						Copyright Peter Gutmann 1992-2025					*
*																			*
****************************************************************************/

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

/* The DLP algorithms split the key components over the information in the
   AlgorithmIdentifier and the actual public/private key components, with the
   (p, q, g) set classed as domain parameters and included in the
   AlgorithmIdentifier and y being the actual key.

	params = SEQ {
		p INTEGER,
		q INTEGER,				-- q for DSA
		g INTEGER,				-- g for DSA
		j INTEGER OPTIONAL,		-- X9.42 only
		validationParams [...]	-- X9.42 only
		}

	key = y INTEGER				-- g^x mod p

   For peculiar historical reasons (copying errors and the use of obsolete
   drafts as reference material) the X9.42 interpretation used in PKIX 
   reverses the second two parameters from FIPS 186 (so it uses p, g, q 
   instead of p, q, g), so when we read/write the parameter information we 
   have to switch the order in which we read the values if the algorithm 
   isn't DSA */

#define hasReversedParams( cryptAlgo ) \
		( ( cryptAlgo ) == CRYPT_ALGO_DH || \
		  ( cryptAlgo ) == CRYPT_ALGO_ELGAMAL )

#ifdef USE_PKC

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#if defined( USE_SSH )

/* Write a bignum as a fixed-length value by adding leading-zero padding, 
   this is needed by SSH */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeFixedBignum( INOUT_PTR STREAM *stream, const BIGNUM *bignum,
							 IN_LENGTH_SHORT_MIN( 20 ) const int fixedSize )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	LOOP_INDEX i;
	int bnLength, noZeroes, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum ) );
	REQUIRES( fixedSize >= 20 && fixedSize <= CRYPT_MAX_PKCSIZE );

	/* Extract the bignum data and get its length */
	status = exportBignum( buffer, CRYPT_MAX_PKCSIZE, &bnLength, bignum );
	ENSURES( cryptStatusOK( status ) );
	REQUIRES( !checkOverflowSub( fixedSize, bnLength ) );
	noZeroes = fixedSize - bnLength;
	REQUIRES( noZeroes >= 0 && noZeroes < fixedSize );

	/* Write the leading zeroes followed by the bignum value */
	LOOP_LARGE( i = 0, i < noZeroes, i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, noZeroes - 1 ) );

		sputc( stream, 0 );
		}
	ENSURES( LOOP_BOUND_OK );
	status = swrite( stream, buffer, bnLength );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	
	return( status );
	}
#endif /* USE_SSH */

/****************************************************************************
*																			*
*							Write X.509 Public Keys							*
*																			*
****************************************************************************/

#ifdef USE_INT_ASN1

/* Write X.509 SubjectPublicKeyInfo public keys */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRsaSubjectPublicKey( INOUT_PTR STREAM *stream, 
									 const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	int length;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	
	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	length = sizeofBignum( &pkcInfo->rsaParam_n ) + \
			 sizeofBignum( &pkcInfo->rsaParam_e );

	/* Write the SubjectPublicKeyInfo header field (the +1 is for the 
	   bitstring) */
	writeSequence( stream, sizeofAlgoID( CRYPT_ALGO_RSA ) + \
						   sizeofShortObject( \
								sizeofShortObject( length ) + 1 ) );
	writeAlgoID( stream, CRYPT_ALGO_RSA, DEFAULT_TAG );

	/* Write the BIT STRING wrapper and the PKC information */
	writeBitStringHole( stream, sizeofShortObject( length ), 
						DEFAULT_TAG );
	writeSequence( stream, length );
	writeBignum( stream, &pkcInfo->rsaParam_n );
	return( writeBignum( stream, &pkcInfo->rsaParam_e ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeDlpSubjectPublicKey( INOUT_PTR STREAM *stream, 
									 const CONTEXT_INFO *contextInfoPtr,
									 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const DH_DOMAINPARAMS *domainParams;
	const BIGNUM *p, *q, *g;
	ALGOID_PARAMS algoIDparams;
	int parameterSize, componentSize, totalSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DH || \
			  cryptAlgo == CRYPT_ALGO_DSA || \
			  cryptAlgo == CRYPT_ALGO_ELGAMAL );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	domainParams = pkcInfo->domainParams;
	if( domainParams != NULL )
		{
		/* We should never be writing a value with domain parameters since
		   that implies shared-parameter DSA */
		assert( DEBUG_WARN );
		p = &domainParams->p;
		q = &domainParams->q;
		g = &domainParams->g;
		}
	else
		{
		p = &pkcInfo->dlpParam_p;
		q = &pkcInfo->dlpParam_q;
		g = &pkcInfo->dlpParam_g;
		}
	parameterSize = sizeofShortObject( \
								sizeofBignum( p ) + sizeofBignum( q ) + \
								sizeofBignum( g ) );
	componentSize = sizeofBignum( &pkcInfo->dlpParam_y );

	/* If it's an Elgamal key created by PGP or a DH key from TLS/SSH then 
	   the q parameter isn't present so we can't write the key in this format */
	if( BN_is_zero( q ) )
		{
		DEBUG_DIAG(( "Can't write Elgamal key due to missing q parameter" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_NOTAVAIL );
		}

	/* Determine the size of the AlgorithmIdentifier and the BIT STRING-
	   encapsulated public-key data (the +1 is for the bitstring) */
	initAlgoIDparams( &algoIDparams );
	algoIDparams.extraLength = parameterSize;
	status = totalSize = sizeofAlgoIDex( cryptAlgo, &algoIDparams );
	if( cryptStatusError( status ) )
		return( status );
	totalSize += sizeofShortObject( componentSize + 1 );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( stream, totalSize );
	writeAlgoIDex( stream, cryptAlgo, &algoIDparams, DEFAULT_TAG );

	/* Write the parameter data */
	writeSequence( stream, sizeofBignum( p ) + sizeofBignum( q ) + \
						   sizeofBignum( g ) );
	writeBignum( stream, p );
	if( hasReversedParams( cryptAlgo ) )
		{
		writeBignum( stream, g );
		writeBignum( stream, q );
		}
	else
		{
		writeBignum( stream, q );
		writeBignum( stream, g );
		}

	/* Write the BIT STRING wrapper and the PKC information */
	writeBitStringHole( stream, componentSize, DEFAULT_TAG );
	return( writeBignum( stream, &pkcInfo->dlpParam_y ) );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeEccSubjectPublicKey( INOUT_PTR STREAM *stream, 
									 const CONTEXT_INFO *contextInfoPtr,
									 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	ALGOID_PARAMS algoIDparams;
	BYTE buffer[ MAX_PKCSIZE_ECCPOINT + 8 ];
	int fieldSize DUMMY_INIT, oidSize DUMMY_INIT, encodedPointSize, totalSize;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDSA || cryptAlgo == CRYPT_ALGO_ECDH );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Get the information that we'll need to encode the key.  Note that 
	   this assumes that we'll be using a known (named) curve rather than
	   arbitrary curve parameters, which has been enforced by the higher-
	   level code */
	status = getECCFieldSize( pkcInfo->curveType, &fieldSize, FALSE );
	if( cryptStatusOK( status ) )
		status = oidSize = sizeofECCOID( pkcInfo->curveType );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the encoded point data */
	status = exportECCPoint( buffer, MAX_PKCSIZE_ECCPOINT, &encodedPointSize, 
							 &pkcInfo->eccParam_qx, &pkcInfo->eccParam_qy, 
							 fieldSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine the size of the AlgorithmIdentifier and the BIT STRING-
	   encapsulated public-key data (the final +1 is for the bitstring),
	   ECC algorithms are a bit strange because there's no specific type of 
	   "ECDSA key" or "ECDH key" or whatever, just a generic "ECC key", so 
	   if we're given an ECDH key we write it as a generic ECC key, denoted 
	   using the generic identifier CRYPT_ALGO_ECDSA */
	initAlgoIDparams( &algoIDparams );
	algoIDparams.extraLength = oidSize;
	status = totalSize = sizeofAlgoIDex( CRYPT_ALGO_ECDSA, &algoIDparams );
	if( cryptStatusError( status ) )
		return( status );
	totalSize += sizeofShortObject( encodedPointSize + 1 );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( stream, totalSize );
	writeAlgoIDex( stream, CRYPT_ALGO_ECDSA, &algoIDparams, DEFAULT_TAG );
	writeECCOID( stream, pkcInfo->curveType );

	/* Write the BIT STRING wrapper and the PKC information */
	writeBitStringHole( stream, encodedPointSize, DEFAULT_TAG );
	status = swrite( stream, buffer, encodedPointSize );
	zeroise( buffer, MAX_PKCSIZE_ECCPOINT );
	return( status );
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_X25519 ) || defined( USE_ED25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int write25519SubjectPublicKey( INOUT_PTR STREAM *stream, 
									   const CONTEXT_INFO *contextInfoPtr,
									   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const BERNSTEIN_KEY_INFO *bernsteinKey;
	int totalSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_25519 || \
			  cryptAlgo == CRYPT_ALGO_ED25519 );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Determine the size of the AlgorithmIdentifier and the BIT STRING-
	   encapsulated public-key data (the final +1 is for the bitstring).
	   Note that MIN_PKCSIZE_BERNSTEIN and MAX_PKCSIZE_BERNSTEIN have the 
	   same value, they're just given as MIN ... MAX for consistency with 
	   other PKC constants */
	status = totalSize = sizeofAlgoID( cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );
	totalSize += sizeofShortObject( MIN_PKCSIZE_BERNSTEIN + 1 );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( stream, totalSize );
	writeAlgoID( stream, cryptAlgo, DEFAULT_TAG );

	/* Write the BIT STRING wrapper and the PKC information */
	writeBitStringHole( stream, MIN_PKCSIZE_BERNSTEIN, DEFAULT_TAG );
	return( swrite( stream, bernsteinKey->pubKey, MIN_PKCSIZE_BERNSTEIN ) );
	}
#endif /* USE_X25519 || USE_ED25519 */

#ifdef USE_MLKEM

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePQCSubjectPublicKey( INOUT_PTR STREAM *stream, 
									 const CONTEXT_INFO *contextInfoPtr,
									 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const MLKEM_KEY_INFO *mlkemKey;
	int totalSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_MLKEM );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	mlkemKey = pkcInfo->mlkemKey;

	/* Determine the size of the AlgorithmIdentifier and the BIT STRING-
	   encapsulated public-key data (the final +1 is for the bitstring) */
	status = totalSize = sizeofAlgoID( cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( mlkemKey->pubKeySize == MLKEM768_PUBLICKEYBYTES );
	totalSize += sizeofShortObject( mlkemKey->pubKeySize + 1 );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( stream, totalSize );
	writeAlgoID( stream, cryptAlgo, DEFAULT_TAG );

	/* Write the BIT STRING wrapper and the PKC information */
	writeBitStringHole( stream, mlkemKey->pubKeySize, DEFAULT_TAG );
	return( swrite( stream, mlkemKey->pubKey, mlkemKey->pubKeySize ) );
	}
#endif /* USE_MLKEM */
#endif /* USE_INT_ASN1 */

/****************************************************************************
*																			*
*								Write SSH Public Keys						*
*																			*
****************************************************************************/

#ifdef USE_SSH

/* Write SSHv2 public keys:

   RSA/DSA:

	string		[ server key/certificate ]
		string	"ssh-rsa"	"ssh-dss"
		mpint	e			p
		mpint	n			q
		mpint				g
		mpint				y

   ECDSA:

	string		[ server key/certificate ]
		string	"ecdsa-sha2-*"
		string	"*"				-- The "*" portion from the above field
		string	Q 

   25519:

	string		[ server key/certificate ]
		string	"ssh-ed25519"
		string	publicValue */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeSshRsaPublicKey( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RSA );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	writeUint32( stream, sizeofString32( 7 ) + \
						 sizeofBignumInteger32( &pkcInfo->rsaParam_e ) + \
						 sizeofBignumInteger32( &pkcInfo->rsaParam_n ) );
	writeString32( stream, "ssh-rsa", 7 );
	writeBignumInteger32( stream, &pkcInfo->rsaParam_e );
	return( writeBignumInteger32( stream, &pkcInfo->rsaParam_n ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeSshDlpPublicKey( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr,
								 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_DSA );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* SSHv2 uses PKCS #3 rather than X9.42-style DH keys so we have to 
	   treat this algorithm type specially */
	if( cryptAlgo == CRYPT_ALGO_DH )
		{
		const DH_DOMAINPARAMS *domainParams = pkcInfo->domainParams;
		const BIGNUM *p = ( domainParams != NULL ) ? \
						  &domainParams->p : &pkcInfo->dlpParam_p;
		const BIGNUM *g = ( domainParams != NULL ) ? \
						  &domainParams->g : &pkcInfo->dlpParam_g;

		writeUint32( stream, sizeofString32( 6 ) + \
							 sizeofBignumInteger32( p ) + \
							 sizeofBignumInteger32( g ) );
		writeString32( stream, "ssh-dh", 6 );
		writeBignumInteger32( stream, p );
		return( writeBignumInteger32( stream, g ) );
		}

	writeUint32( stream, sizeofString32( 7 ) + \
						 sizeofBignumInteger32( &pkcInfo->dlpParam_p ) + \
						 sizeofBignumInteger32( &pkcInfo->dlpParam_q ) + \
						 sizeofBignumInteger32( &pkcInfo->dlpParam_g ) + \
						 sizeofBignumInteger32( &pkcInfo->dlpParam_y ) );
	writeString32( stream, "ssh-dss", 7 );
	writeBignumInteger32( stream, &pkcInfo->dlpParam_p );
	writeBignumInteger32( stream, &pkcInfo->dlpParam_q );
	writeBignumInteger32( stream, &pkcInfo->dlpParam_g );
	return( writeBignumInteger32( stream, &pkcInfo->dlpParam_y ) );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeSshEccPublicKey( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr,
								 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const char *algoName, *paramName;
	BYTE buffer[ MAX_PKCSIZE_ECCPOINT + 8 ];
	int fieldSize, encodedPointSize DUMMY_INIT;
	int algoNameLen, paramNameLen, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDSA );
			  /* We should never be writing ECDH keys */
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Get the string form of the curve parameters */
	switch( pkcInfo->curveType )
		{
		case CRYPT_ECCCURVE_P256:
			algoName = "ecdsa-sha2-nistp256";
			algoNameLen = 19;
			paramName = "nistp256";
			paramNameLen = 8;
			break;

		case CRYPT_ECCCURVE_P384:
			algoName = "ecdsa-sha2-nistp384";
			algoNameLen = 19;
			paramName = "nistp384";
			paramNameLen = 8;
			break;

		case CRYPT_ECCCURVE_P521:
			algoName = "ecdsa-sha2-nistp521";
			algoNameLen = 19;
			paramName = "nistp521";
			paramNameLen = 8;
			break;

		default:
			retIntError();
		}

	/* Get the information that we'll need to encode the key and the encoded
	   point data.  Note that this assumes that we'll be using a known 
	   (named) curve rather than arbitrary curve parameters, which has been 
	   enforced by the higher-level code */
	status = getECCFieldSize( pkcInfo->curveType, &fieldSize, FALSE );
	if( cryptStatusOK( status ) )
		{
		status = exportECCPoint( buffer, MAX_PKCSIZE_ECCPOINT, 
								 &encodedPointSize, &pkcInfo->eccParam_qx, 
								 &pkcInfo->eccParam_qy, fieldSize );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the PKC information */
	writeUint32( stream, sizeofString32( algoNameLen ) + \
						 sizeofString32( paramNameLen ) + \
						 sizeofString32( encodedPointSize ) );
	writeString32( stream, algoName, algoNameLen );
	writeString32( stream, paramName, paramNameLen );
	status = writeString32( stream, buffer, encodedPointSize );
	zeroise( buffer, MAX_PKCSIZE_ECCPOINT );
	return( status );
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_X25519 ) || defined( USE_ED25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeSsh25519PublicKey( INOUT_PTR STREAM *stream, 
								   const CONTEXT_INFO *contextInfoPtr,
								   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const BERNSTEIN_KEY_INFO *bernsteinKey;
	const char *algoName;
	int algoNameLen;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ED25519 );
			  /* We should never be writing X25519 keys */
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Get the string form of the algorithm */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_ED25519:
			algoName = "ssh-ed25519";
			algoNameLen = 11;
			break;

		default:
			retIntError();
		}

	/* Write the PKC information */
	writeUint32( stream, sizeofString32( algoNameLen ) + \
						 sizeofString32( MIN_PKCSIZE_BERNSTEIN ) );
	writeString32( stream, algoName, algoNameLen );
	return( writeString32( stream, bernsteinKey->pubKey, 
						   MIN_PKCSIZE_BERNSTEIN ) );
	}
#endif /* USE_X25519 || USE_ED25519 */
#endif /* USE_SSH */

/****************************************************************************
*																			*
*								Write TLS Public Keys						*
*																			*
****************************************************************************/

#ifdef USE_TLS

/* Write TLS public keys:

	DH:
		uint16		dh_pLen
		byte[]		dh_p
	  [	uint16		dh_qLen
		byte[]		dh_q		-- For TLS-ext format ]
		uint16		dh_gLen
		byte[]		dh_g
	  [	uint16		dh_YsLen ]
	  [	byte[]		dh_Ys	 ]

	ECDH:
		byte		curveType
		uint16		namedCurve
	  [	uint8		ecPointLen	-- NB uint8 not uint16 ]
	  [	byte[]		ecPoint ]
	  
	ML-KEM:
		byte[]		pubKey

   The DH y value is nominally attached to the DH p and g values but isn't 
   processed at this level since this is a pure PKCS #3 DH key and not a 
   generic DLP key.  The same holds for the ECDH Q value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeTlsDlpPublicKey( INOUT_PTR STREAM *stream, 
								 IN_PTR const CONTEXT_INFO *contextInfoPtr,
								 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								 IN_BOOL const BOOLEAN writeExtKey )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DH );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( isBooleanValue( writeExtKey ) );

	if( pkcInfo->domainParams != NULL )
		{
		const DH_DOMAINPARAMS *domainParams = pkcInfo->domainParams;

		writeBignumInteger16U( stream, &domainParams->p );
		if( writeExtKey )
			writeBignumInteger16U( stream, &domainParams->q ); 
		return( writeBignumInteger16U( stream, &domainParams->g ) );
		}
	writeBignumInteger16U( stream, &pkcInfo->dlpParam_p );
	if( writeExtKey )
		writeBignumInteger16U( stream, &pkcInfo->dlpParam_q );
	return( writeBignumInteger16U( stream, &pkcInfo->dlpParam_g ) );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

static const MAP_TABLE tlsCurveInfo[] = {
	{ CRYPT_ECCCURVE_P256, 23 },
	{ CRYPT_ECCCURVE_P384, 24 },
	{ CRYPT_ECCCURVE_P521, 25 },
	{ CRYPT_ECCCURVE_BRAINPOOL_P256, 26 },
	{ CRYPT_ECCCURVE_BRAINPOOL_P384, 27 },
	{ CRYPT_ECCCURVE_BRAINPOOL_P512, 28 },
	{ CRYPT_ERROR, 0 }, 
		{ CRYPT_ERROR, 0 }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getEccTlsInfoTbl( OUT_PTR_PTR const MAP_TABLE **tlsInfoTblPtr,
							 OUT_INT_Z int *noTlsInfoTblEntries )
	{
	assert( isReadPtr( tlsInfoTblPtr, sizeof( MAP_TABLE * ) ) );
	assert( isWritePtr( noTlsInfoTblEntries, sizeof( int ) ) );

	*tlsInfoTblPtr = tlsCurveInfo;
	*noTlsInfoTblEntries = FAILSAFE_ARRAYSIZE( tlsCurveInfo, MAP_TABLE );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeTlsEccPublicKey( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr,
								 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const MAP_TABLE *tlsCurveInfoPtr;
	int curveID, tlsCurveInfoNoEntries, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDH );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Look up the TLS NamedCurve ID based on the curve ID */
	status = getEccTlsInfoTbl( &tlsCurveInfoPtr, &tlsCurveInfoNoEntries );
	if( cryptStatusError( status ) )
		return( status );
	status = mapValue( pkcInfo->curveType, &curveID, tlsCurveInfoPtr, 
					   tlsCurveInfoNoEntries );
	if( cryptStatusError( status ) )
		return( status );

	sputc( stream, 0x03 );	/* NamedCurve */
	return( writeUint16( stream, curveID ) );
	}
#endif /* USE_ECDH || USE_ECDSA */

#ifdef USE_MLKEM

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeTlsPQCPublicKey( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr,
								 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const MLKEM_KEY_INFO *mlkemKey;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_MLKEM );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	mlkemKey = pkcInfo->mlkemKey;

	/* The TLS ML-KEM public key is concatenated together with a 25519 keyex
	   value without any encapsulation so we just write the raw key data */
	REQUIRES( mlkemKey->pubKeySize == MLKEM768_PUBLICKEYBYTES );
	return( swrite( stream, mlkemKey->pubKey, mlkemKey->pubKeySize ) );
	}
#endif /* USE_MLKEM */
#endif /* USE_TLS */

/****************************************************************************
*																			*
*								Write PGP Public Keys						*
*																			*
****************************************************************************/

#ifdef USE_PGPKEYS 

/* Write PGP public keys:

	byte		version = 4
	uint32		creationTime
	byte		RSA		DSA		Elgamal		ECDSA
	mpi			n		p		p			byte	oidLen
	mpi			e		q		g			byte[]	oid
	mpi					g		y			mpi		X9.62-encoded point
	mpi					y */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePgpKeyHeader( INOUT_PTR STREAM *stream, 
							  IN_PTR const PKC_INFO *pkcInfo,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	int pgpAlgo, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( pkcInfo->pgpCreationTime == 0 || \
			  pkcInfo->pgpCreationTime > MIN_TIME_VALUE );
	REQUIRES( isPkcAlgo( cryptAlgo ) );

	sputc( stream, PGP_VERSION_OPENPGP );
	if( pkcInfo->pgpCreationTime == 0 )
		{
		/* The creation time may be zero for a key coming from a non-PGP 
		   source */
		writeUint32( stream, 0 );
		}
	else
		writeUint32Time( stream, pkcInfo->pgpCreationTime );
	status = cryptlibToPgpAlgo( cryptAlgo, 0, &pgpAlgo );
	if( cryptStatusError( status ) )
		return( status );
	return( sputc( stream, pgpAlgo ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePgpRsaPublicKey( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	status = writePgpKeyHeader( stream, pkcInfo, CRYPT_ALGO_RSA );
	if( cryptStatusError( status ) )
		return( status );
	writeBignumInteger16Ubits( stream, &pkcInfo->rsaParam_n );
	return( writeBignumInteger16Ubits( stream, &pkcInfo->rsaParam_e ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePgpDlpPublicKey( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr,
								 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DSA || \
			  cryptAlgo == CRYPT_ALGO_ELGAMAL );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	status = writePgpKeyHeader( stream, pkcInfo, cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );
	writeBignumInteger16Ubits( stream, &pkcInfo->dlpParam_p );
	if( cryptAlgo == CRYPT_ALGO_DSA )
		writeBignumInteger16Ubits( stream, &pkcInfo->dlpParam_q );
	writeBignumInteger16Ubits( stream, &pkcInfo->dlpParam_g );
	return( writeBignumInteger16Ubits( stream, &pkcInfo->dlpParam_y ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePgpEccPublicKey( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr,
								 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	BYTE buffer[ MAX_PKCSIZE_ECCPOINT + 8 ], oidBuffer[ MAX_OID_SIZE + 8 ];
	int fieldSize, encodedPointSize DUMMY_INIT, oidLength DUMMY_INIT;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDH || \
			  cryptAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Get the information that we'll need to encode the point data and the 
	   key.  Note that this assumes that we'll be using a known (named) 
	   curve rather than arbitrary curve parameters, which has been enforced 
	   by the higher-level code */
	status = getECCFieldSize( pkcInfo->curveType, &fieldSize, FALSE );
	if( cryptStatusOK( status ) )
		{
		status = exportECCPoint( buffer, MAX_PKCSIZE_ECCPOINT, 
								 &encodedPointSize, &pkcInfo->eccParam_qx, 
								 &pkcInfo->eccParam_qy, fieldSize );
		}
	if( cryptStatusOK( status ) )
		{
		STREAM oidStream;

		/* PGP uses the OID without the tag at the start so we have to write
		   it to an intermediate buffer in order to then write it without the
		   tag */
		sMemOpen( &oidStream, oidBuffer, MAX_OID_SIZE );
		status = writeECCOID( &oidStream, pkcInfo->curveType );
		if( cryptStatusOK( status ) )
			status = oidLength = stell( &oidStream );
		sMemDisconnect( &oidStream );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the ECC key */
	status = writePgpKeyHeader( stream, pkcInfo, cryptAlgo );
	if( cryptStatusOK( status ) )
		status = swrite( stream, oidBuffer + 1, oidLength - 1 );
	if( cryptStatusOK( status ) )
		status = writeInteger16Ubits( stream, buffer, encodedPointSize );
	zeroise( buffer, MAX_PKCSIZE_ECCPOINT );
	return( status );
	}
#endif /* USE_PGPKEYS */

/****************************************************************************
*																			*
*							Public-Key Write Interface						*
*																			*
****************************************************************************/

/* Umbrella public-key write functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int writePublicKeyRsaFunction( INOUT_PTR STREAM *stream, 
							   const CONTEXT_INFO *contextInfoPtr,
							   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							   IN_ENUM( KEYFORMAT ) \
									const KEYFORMAT_TYPE formatType,
							   IN_BUFFER( accessKeyLen ) \
									const char *accessKey, 
							   IN_LENGTH_FIXED( 10 ) \
									const int accessKeyLen )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_RSA );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 10 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 10 || memcmp( accessKey, "public_key", 10 ) )
		retIntError();

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			return( writeRsaSubjectPublicKey( stream, contextInfoPtr ) );
#endif /* USE_INT_ASN1 */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			return( writeSshRsaPublicKey( stream, contextInfoPtr ) );
#endif /* USE_SSH */

#ifdef USE_PGPKEYS 
		case KEYFORMAT_PGP:
			return( writePgpRsaPublicKey( stream, contextInfoPtr ) );
#endif /* USE_PGPKEYS */
		}

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int writePublicKeyDlpFunction( INOUT_PTR STREAM *stream, 
							   const CONTEXT_INFO *contextInfoPtr,
							   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							   IN_ENUM( KEYFORMAT ) \
									const KEYFORMAT_TYPE formatType,
							   IN_BUFFER( accessKeyLen ) \
									const char *accessKey, 
							   IN_LENGTH_FIXED( 10 ) \
									const int accessKeyLen )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DH || \
			  cryptAlgo == CRYPT_ALGO_DSA || \
			  cryptAlgo == CRYPT_ALGO_ELGAMAL );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( accessKeyLen == 10 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 10 || memcmp( accessKey, "public_key", 10 ) )
		retIntError();

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			return( writeDlpSubjectPublicKey( stream, contextInfoPtr, 
											  cryptAlgo ) );
#endif /* USE_INT_ASN1 */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			return( writeSshDlpPublicKey( stream, contextInfoPtr,
										  cryptAlgo ) );
#endif /* USE_SSH */

#ifdef USE_TLS
		case KEYFORMAT_TLS:
		case KEYFORMAT_TLS_EXT:
			return( writeTlsDlpPublicKey( stream, contextInfoPtr,
									cryptAlgo,
									( formatType == KEYFORMAT_TLS_EXT ) ? \
									  TRUE : FALSE ) );
#endif /* USE_TLS */

#ifdef USE_PGPKEYS 
		case KEYFORMAT_PGP:
			return( writePgpDlpPublicKey( stream, contextInfoPtr, 
										  cryptAlgo ) );
#endif /* USE_PGPKEYS */

		case KEYFORMAT_PRIVATE:
		case KEYFORMAT_PRIVATE_EXT:
		case KEYFORMAT_PRIVATE_OLD:
			retIntError();
		}

	retIntError();
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int writePublicKeyEccFunction( INOUT_PTR STREAM *stream, 
							   const CONTEXT_INFO *contextInfoPtr,
							   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							   IN_ENUM( KEYFORMAT ) \
									const KEYFORMAT_TYPE formatType,
							   IN_BUFFER( accessKeyLen ) \
									const char *accessKey, 
							   IN_LENGTH_FIXED( 10 ) \
									const int accessKeyLen )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDSA || cryptAlgo == CRYPT_ALGO_ECDH );
	REQUIRES( formatType == KEYFORMAT_CERT || formatType == KEYFORMAT_TLS || \
			  formatType == KEYFORMAT_TLS_EXT || \
			  formatType == KEYFORMAT_PGP || formatType == KEYFORMAT_SSH );
	REQUIRES( accessKeyLen == 10 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 10 || memcmp( accessKey, "public_key", 10 ) )
		retIntError();

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			return( writeEccSubjectPublicKey( stream, contextInfoPtr, 
											  cryptAlgo ) );
#endif /* USE_INT_ASN1 */

#ifdef USE_TLS
		case KEYFORMAT_TLS:
		case KEYFORMAT_TLS_EXT:
			return( writeTlsEccPublicKey( stream, contextInfoPtr,
										  cryptAlgo ) );
#endif /* USE_TLS */

#ifdef USE_PGPKEYS 
		case KEYFORMAT_PGP:
			return( writePgpEccPublicKey( stream, contextInfoPtr,
										  cryptAlgo ) );
#endif /* USE_PGPKEYS */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			return( writeSshEccPublicKey( stream, contextInfoPtr,
										  cryptAlgo ) );
#endif /* USE_SSH */
		}

	retIntError();
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_X25519 ) || defined( USE_ED25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int writePublicKey25519Function( INOUT_PTR STREAM *stream, 
								 const CONTEXT_INFO *contextInfoPtr,
								 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								 IN_ENUM( KEYFORMAT ) \
									const KEYFORMAT_TYPE formatType,
								 IN_BUFFER( accessKeyLen ) \
									const char *accessKey, 
								 IN_LENGTH_FIXED( 10 ) \
									const int accessKeyLen )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_25519 || \
			  cryptAlgo == CRYPT_ALGO_ED25519 );
	REQUIRES( formatType == KEYFORMAT_CERT || \
			  formatType == KEYFORMAT_SSH );
	REQUIRES( accessKeyLen == 10 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 10 || memcmp( accessKey, "public_key", 10 ) )
		retIntError();

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			return( write25519SubjectPublicKey( stream, contextInfoPtr,
												cryptAlgo ) );
#endif /* USE_INT_ASN1 */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			return( writeSsh25519PublicKey( stream, contextInfoPtr, 
											cryptAlgo ) );
#endif /* USE_SSH */
		}

	retIntError();
	}
#endif /* USE_X25519 || USE_ED25519 */

#ifdef USE_MLKEM

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int writePublicKeyPQCFunction( INOUT_PTR STREAM *stream, 
							   const CONTEXT_INFO *contextInfoPtr,
							   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							   IN_ENUM( KEYFORMAT ) \
									const KEYFORMAT_TYPE formatType,
							   IN_BUFFER( accessKeyLen ) \
									const char *accessKey, 
							   IN_LENGTH_FIXED( 10 ) \
									const int accessKeyLen )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( accessKey, accessKeyLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_MLKEM );
	REQUIRES( formatType == KEYFORMAT_CERT || \
			  formatType == KEYFORMAT_TLS );
	REQUIRES( accessKeyLen == 10 );

	/* Make sure that we really intended to call this function */
	if( accessKeyLen != 10 || memcmp( accessKey, "public_key", 10 ) )
		retIntError();

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			return( writePQCSubjectPublicKey( stream, contextInfoPtr, 
											  cryptAlgo ) );
#endif /* USE_INT_ASN1 */

#ifdef USE_TLS
		case KEYFORMAT_TLS:
			return( writeTlsPQCPublicKey( stream, contextInfoPtr, 
										  cryptAlgo ) );
#endif /* USE_TLS */
		}

	retIntError();
	}
#endif /* USE_MLKEM */

/****************************************************************************
*																			*
*							Write Flat Public Key Data						*
*																			*
****************************************************************************/

#ifdef USE_INT_ASN1

/* If the keys are stored in a crypto device rather than being held in the
   context all that we'll have available are the public components in flat 
   format.  The following code writes flat-format public components in the 
   X.509 SubjectPublicKeyInfo format.  The parameters are:

	Algo	Comp1	Comp2	Comp3	Comp4
	----	-----	-----	-----	-----
	RSA		  n		  e		  -		  -
	DLP		  p		  q		  g		  y 
	ECDLP	  point	  -		  -		  - 
	ECDLP	  x		  y		  -		  - 
	25519	  point	  -		  -		  -

   Note that the last one, for Ed25519, is for future use only since 
   currently no crypto device known to cryptlib supports these keys */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 6 ) ) \
int writeFlatPublicKey( OUT_BUFFER_OPT( bufMaxSize, *bufSize ) void *buffer, 
						IN_LENGTH_SHORT_Z const int bufMaxSize, 
						OUT_LENGTH_BOUNDED_Z( bufMaxSize ) int *bufSize,
						IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo, 
						IN_RANGE( 0, 100 ) const int intParam,
						IN_BUFFER( component1Length ) const void *component1, 
						IN_LENGTH_PKC const int component1Length,
						IN_BUFFER_OPT( component2Length ) const void *component2, 
						IN_LENGTH_PKC_Z const int component2Length,
						IN_BUFFER_OPT( component3Length ) const void *component3, 
						IN_LENGTH_PKC_Z const int component3Length,
						IN_BUFFER_OPT( component4Length ) const void *component4, 
						IN_LENGTH_PKC_Z const int component4Length )
	{
	STREAM stream;
	ALGOID_PARAMS algoIDparams;
#if defined( USE_ECDSA ) || defined( USE_ECDH ) || \
	defined( USE_X25519 ) || defined( USE_ED25519 )
	BYTE encodedPointBuffer[ MAX_PKCSIZE_ECCPOINT + 8 ];
#endif /* USE_ECDSA || USE_ECDH || USE_X25519 || USE_ED25519 */
	int comp1Size, comp2Size = 0, comp3Size = 0, parameterSize;
	int componentSize, totalSize, status;

	assert( ( buffer == NULL && bufMaxSize == 0 ) || \
			isWritePtrDynamic( buffer, bufMaxSize ) );
	assert( isWritePtr( bufSize, sizeof( int ) ) );
	assert( isReadPtrDynamic( component1, component1Length ) );
	assert( component2 == NULL || \
			isReadPtrDynamic( component2, component2Length ) );
	assert( component3 == NULL || \
			isReadPtrDynamic( component3, component3Length ) );
	assert( component4 == NULL || \
			isReadPtrDynamic( component4, component4Length ) );

	REQUIRES( ( buffer == NULL && bufMaxSize == 0 ) || \
			  ( buffer != NULL && \
			    isShortIntegerRangeMin( bufMaxSize, 64 ) ) );
	REQUIRES( isPkcAlgo( cryptAlgo ) );
	REQUIRES( ( isEccAlgo( cryptAlgo ) && \
				isEnumRange( intParam, CRYPT_ECCCURVE ) ) || \
			  ( !isEccAlgo( cryptAlgo ) && intParam == 0 ) );
	REQUIRES( ( isEccAlgo( cryptAlgo ) && \
				component1Length >= MIN_PKCSIZE_ECCPOINT && \
				component1Length <= MAX_PKCSIZE_ECCPOINT && \
				component2Length == 0 ) || \
			  ( isEccAlgo( cryptAlgo ) && \
				component1Length >= MIN_PKCSIZE_ECC && \
				component1Length <= CRYPT_MAX_PKCSIZE_ECC && \
				component2Length >= MIN_PKCSIZE_ECC && \
				component2Length <= CRYPT_MAX_PKCSIZE_ECC ) || \
			  ( !isEccAlgo( cryptAlgo ) && \
				component1Length >= MIN_PKCSIZE && \
				component1Length <= CRYPT_MAX_PKCSIZE && \
				component2Length >= 1 && \
				component2Length <= CRYPT_MAX_PKCSIZE ) );
	REQUIRES( component1 != NULL );
	REQUIRES( ( isEccAlgo( cryptAlgo ) && component2 == NULL && \
				component2Length == 0 ) || \
			  ( component2 != NULL && component2Length != 0 ) );
	REQUIRES( ( component3 == NULL && component3Length == 0 ) || \
			  ( component3 != NULL && \
				component3Length >= 1 && component3Length <= CRYPT_MAX_PKCSIZE ) );
	REQUIRES( ( component4 == NULL && component4Length == 0 ) || \
			  ( component4 != NULL && \
				component4Length >= 1 && component4Length <= CRYPT_MAX_PKCSIZE ) );

	/* Clear return values */
	if( buffer != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( bufMaxSize ) ); 
		memset( buffer, 0, min( 16, bufMaxSize ) );
		}
	*bufSize = 0;

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	comp1Size = sizeofInteger( component1, component1Length );
	if( component2 != NULL ) 
		comp2Size = sizeofInteger( component2, component2Length );
	if( component3 != NULL ) 
		comp3Size = sizeofInteger( component3, component3Length );

	/* Calculate the size of the algorithm parameters and the public key 
	   components */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_DH:
		case CRYPT_ALGO_DSA:
		case CRYPT_ALGO_ELGAMAL:
			REQUIRES( component3 != NULL && component4 != NULL );

			parameterSize = sizeofShortObject( comp1Size + comp2Size + \
											   comp3Size );
			componentSize = sizeofInteger( component4, component4Length );
			break;

		case CRYPT_ALGO_RSA:
			REQUIRES( component3 == NULL && component4 == NULL );

			parameterSize = 0;
			componentSize = sizeofShortObject( comp1Size + comp2Size );
			break;

#if defined( USE_ECDSA ) || defined( USE_ECDH ) || \
	defined( USE_X25519 ) || defined( USE_ED25519 ) 
		case CRYPT_ALGO_ECDSA:
		case CRYPT_ALGO_ECDH:
		case CRYPT_ALGO_25519:
		case CRYPT_ALGO_ED25519:
			REQUIRES( component3 == NULL && component4 == NULL );

			/* ECC public-key information can be provided in one of two 
			   ways, either as a single encoded point or as a pair of x,y 
			   coordinates that represent a point.  In the latter case we 
			   have to convert them into an encoded point before we can 
			   write them */
			if( component2 != NULL )
				{
				BIGNUM qx, qy;
				int fieldSize, encodedPointSize DUMMY_INIT;

				BN_init( &qx );
				BN_init( &qy );
				status = getECCFieldSize( intParam, &fieldSize, FALSE );
				if( cryptStatusOK( status ) )
					{
					status = importBignum( &qx, component1, component1Length,
										   MIN_PKCSIZE_ECC_THRESHOLD, 
										   CRYPT_MAX_PKCSIZE_ECC, NULL,
										   BIGNUM_CHECK_VALUE_ECC );
					}
				if( cryptStatusOK( status ) )
					{
					status = importBignum( &qy, component2, component2Length,
										   MIN_PKCSIZE_ECC_THRESHOLD, 
										   CRYPT_MAX_PKCSIZE_ECC, NULL,
										   BIGNUM_CHECK_VALUE_ECC );
					}
				if( cryptStatusOK( status ) )
					{
					status = exportECCPoint( encodedPointBuffer, 
											 MAX_PKCSIZE_ECCPOINT, 
											 &encodedPointSize, &qx, &qy, 
											 fieldSize );
					}
				BN_clear( &qy );
				BN_clear( &qx );
				if( cryptStatusError( status ) )
					return( status );
				component1 = encodedPointBuffer;
				componentSize = encodedPointSize;
				}
			else
				{
				componentSize = component1Length;
								/* ECDSA doesn't use INTEGER wrapping */
				}
			if( cryptAlgo == CRYPT_ALGO_ECDSA || \
				cryptAlgo == CRYPT_ALGO_ECDH )
				{
				/* ECDSA/ECDH identify the algorithm as { ECC, curveID }
				   rather than a single OID for the algorithm + curve */
				parameterSize = sizeofECCOID( intParam );
				}
			else
				parameterSize = 0;
			ENSURES( !cryptStatusError( parameterSize ) );
			break;
#endif /* USE_ECDSA || USE_ECDH || USE_X25519 || USE_ED25519 */

		default:
			retIntError();
		}

	/* Determine the size of the AlgorithmIdentifier and the BIT STRING-
	   encapsulated public-key data (the +1 is for the bitstring) */
	if( parameterSize > 0 )
		{
		initAlgoIDparams( &algoIDparams );
		algoIDparams.extraLength = parameterSize;
		status = totalSize = sizeofAlgoIDex( cryptAlgo, &algoIDparams );
		}
	else
		status = totalSize = sizeofAlgoID( cryptAlgo );
	if( cryptStatusError( status ) )
		{
#if defined( USE_ECDSA ) || defined( USE_ECDH )
		zeroise( encodedPointBuffer, MAX_PKCSIZE_ECCPOINT );
#endif /* USE_ECDSA || USE_ECDH */
		return( status );
		}
	totalSize += sizeofShortObject( componentSize + 1 );
	if( buffer == NULL )
		{
		/* It's a size-check call, return the overall size */
		*bufSize = sizeofShortObject( totalSize );
#if defined( USE_ECDSA ) || defined( USE_ECDH )
		zeroise( encodedPointBuffer, MAX_PKCSIZE_ECCPOINT );
#endif /* USE_ECDSA || USE_ECDH */

		return( CRYPT_OK );
		}

	sMemOpen( &stream, buffer, bufMaxSize );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( &stream, totalSize );
	if( parameterSize > 0 )
		writeAlgoIDex( &stream, cryptAlgo, &algoIDparams, DEFAULT_TAG );
	else
		writeAlgoID( &stream, cryptAlgo, DEFAULT_TAG );

	/* Write the parameter data if necessary */
	if( isDlpAlgo( cryptAlgo ) )
		{
		writeSequence( &stream, comp1Size + comp2Size + comp3Size );
		writeInteger( &stream, component1, component1Length, DEFAULT_TAG );
		if( hasReversedParams( cryptAlgo ) )
			{
			writeInteger( &stream, component3, component3Length, DEFAULT_TAG );
			writeInteger( &stream, component2, component2Length, DEFAULT_TAG );
			}
		else
			{
			writeInteger( &stream, component2, component2Length, DEFAULT_TAG );
			writeInteger( &stream, component3, component3Length, DEFAULT_TAG );
			}
		}
#if defined( USE_ECDSA ) || defined( USE_ECDH )
	else
		{
		if( cryptAlgo == CRYPT_ALGO_ECDSA || \
			cryptAlgo == CRYPT_ALGO_ECDH )
			writeECCOID( &stream, intParam );
		}
#endif /* USE_ECDSA || USE_ECDH */

	/* Write the BIT STRING wrapper and the PKC information */
	writeBitStringHole( &stream, componentSize, DEFAULT_TAG );
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		writeSequence( &stream, comp1Size + comp2Size );
		writeInteger( &stream, component1, component1Length, DEFAULT_TAG );
		status = writeInteger( &stream, component2, component2Length, 
							   DEFAULT_TAG );
		}
	else
		{
		if( isEccAlgo( cryptAlgo ) )
			status = swrite( &stream, component1, componentSize );
		else
			{
			status = writeInteger( &stream, component4, component4Length, 
								   DEFAULT_TAG );
			}
		}
	if( cryptStatusOK( status ) )
		status = totalSize = stell( &stream );
#if defined( USE_ECDSA ) || defined( USE_ECDH )
	zeroise( encodedPointBuffer, MAX_PKCSIZE_ECCPOINT );
#endif /* USE_ECDSA || USE_ECDH */

	/* Clean up */
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	
	*bufSize = totalSize;
	return( CRYPT_OK );
	}
#endif /* USE_INT_ASN1 */

/****************************************************************************
*																			*
*								Write DL Values								*
*																			*
****************************************************************************/

/* Unlike the simpler RSA PKC, DL-based PKCs produce a pair of values that
   need to be encoded as structured data.  The following two functions 
   perform this en/decoding.  SSH assumes that DLP values are two fixed-size
   blocks of 20 bytes so we can't use the normal read/write routines to 
   handle these values.
   
   In the ECC case, the format is a pair of values rather than an X9.62 ECC
   point, which would be read by importECCPoint() */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
int encodeDLValuesFunction( OUT_BUFFER( bufMaxSize, *bufSize ) BYTE *buffer, 
							IN_LENGTH_SHORT_MIN( 20 + 20 ) \
								const int bufMaxSize, 
							OUT_LENGTH_BOUNDED_Z( bufMaxSize ) int *bufSize, 
							const BIGNUM *value1, 
							const BIGNUM *value2, 
							IN_ENUM( CRYPT_FORMAT ) \
								const CRYPT_FORMAT_TYPE formatType )
	{
	STREAM stream;
	int length DUMMY_INIT, status;

	assert( isWritePtrDynamic( buffer, bufMaxSize ) );
	assert( isWritePtr( bufSize, sizeof( int ) ) );
	assert( isReadPtr( value1, sizeof( BIGNUM ) ) );
	assert( isReadPtr( value2, sizeof( BIGNUM ) ) );

	REQUIRES( isShortIntegerRangeMin( bufMaxSize, 40 ) );
	REQUIRES( sanityCheckBignum( value1 ) );
	REQUIRES( sanityCheckBignum( value2 ) );
	REQUIRES( isEnumRange( formatType, CRYPT_FORMAT ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( bufMaxSize ) ); 
	memset( buffer, 0, min( 16, bufMaxSize ) );
	*bufSize = 0;

	sMemOpen( &stream, buffer, bufMaxSize );

	/* Write the DL components to the buffer */
	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case CRYPT_FORMAT_CRYPTLIB:
			writeSequence( &stream, sizeofBignum( value1 ) + \
									sizeofBignum( value2 ) );
			writeBignum( &stream, value1 );
			status = writeBignum( &stream, value2 );
			break;
#endif /* USE_INT_ASN1 */

#ifdef USE_PGPKEYS 
		case CRYPT_FORMAT_PGP:
			writeBignumInteger16Ubits( &stream, value1 );
			status = writeBignumInteger16Ubits( &stream, value2 );
			break;
#endif /* USE_PGPKEYS */

#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			/* SSH uses an awkward and horribly inflexible fixed format with 
			   each of the nominally 160-bit DLP values at fixed positions 
			   in a 2 x 20-byte buffer, so we have to write the bignums as
			   fixed-size value */
			status = writeFixedBignum( &stream, value1, 20 );
			if( cryptStatusOK( status ) )
				status = writeFixedBignum( &stream, value2, 20 );
			break;
#endif /* USE_SSH */

		default:
			retIntError();
		}
	if( cryptStatusOK( status ) )
		status = length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	*bufSize = length;

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
int encodeECDLValuesFunction( OUT_BUFFER( bufMaxSize, *bufSize ) BYTE *buffer, 
							  IN_LENGTH_SHORT_MIN( 20 + 20 ) \
									const int bufMaxSize, 
							  OUT_LENGTH_BOUNDED_Z( bufMaxSize ) int *bufSize, 
							  const BIGNUM *value1, 
							  const BIGNUM *value2, 
							  IN_ENUM( CRYPT_FORMAT ) \
									const CRYPT_FORMAT_TYPE formatType )
	{
	STREAM stream;
	int length DUMMY_INIT, status;

	assert( isWritePtrDynamic( buffer, bufMaxSize ) );
	assert( isWritePtr( bufSize, sizeof( int ) ) );
	assert( isReadPtr( value1, sizeof( BIGNUM ) ) );
	assert( isReadPtr( value2, sizeof( BIGNUM ) ) );

	REQUIRES( isShortIntegerRangeMin( bufMaxSize, 40 ) );
	REQUIRES( sanityCheckBignum( value1 ) );
	REQUIRES( sanityCheckBignum( value2 ) );
	REQUIRES( isEnumRange( formatType, CRYPT_FORMAT ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( bufMaxSize ) ); 
	memset( buffer, 0, min( 16, bufMaxSize ) );
	*bufSize = 0;

	/* In most cases the DLP and ECDLP formats are identical and we can just
	   pass the call on to the DLP form, however SSH uses totally different 
	   signature formats depending on whether the signature is DSA or ECDSA, 
	   so we handle the SSH format explicitly here */
	if( formatType != CRYPT_IFORMAT_SSH )
		{
		return( encodeDLValuesFunction( buffer, bufMaxSize, bufSize, 
										value1, value2, formatType ) );
		}
	sMemOpen( &stream, buffer, bufMaxSize );
	writeBignumInteger32( &stream, value1 );
	status = writeBignumInteger32( &stream, value2 );
	if( cryptStatusOK( status ) )
		status = length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	*bufSize = length;

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */
#endif /* USE_PKC */
