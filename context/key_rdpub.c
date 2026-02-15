/****************************************************************************
*																			*
*							Public Key Read Routines						*
*						Copyright Peter Gutmann 1992-2024					*
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
   reverses the second two parameters from FIPS 186, so RFC 3279 section
   2.3.2 "DSA Signature Keys" uses p, q, g while section 2.3.3 "Diffie-
   Hellman Key Exchange Keys" uses p, g, q.  As a result, when we read/write 
   the parameter information we have to switch the order in which we read 
   the values if the algorithm isn't DSA */

#define hasReversedParams( cryptAlgo ) \
		( ( cryptAlgo ) == CRYPT_ALGO_DH || \
		  ( cryptAlgo ) == CRYPT_ALGO_ELGAMAL )

#ifdef USE_PKC

/****************************************************************************
*																			*
*							Read X.509 Public Keys							*
*																			*
****************************************************************************/

#ifdef USE_INT_ASN1

/* Read X.509 SubjectPublicKeyInfo public keys:

	SubjectPublicKeyInfo  ::=  SEQUENCE  {
		algorithm			AlgorithmIdentifier,
		subjectPublicKey	BIT STRING  
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readRsaSubjectPublicKey( INOUT_PTR STREAM *stream, 
									INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	CRYPT_ALGO_TYPE cryptAlgo DUMMY_INIT;
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the SubjectPublicKeyInfo header field and parameter data if
	   there's any present.  We read the outer wrapper in generic form since
	   it may be context-specific-tagged if it's coming from a keyset (RSA
	   public keys is the one place where PKCS #15 keys differ from X.509
	   ones) or something odd from CRMF */
	status = readGenericHole( stream, NULL, 8 + MIN_PKCSIZE_THRESHOLD + \
											RSAPARAM_MIN_E, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = readAlgoID( stream, &cryptAlgo, ALGOID_CLASS_PKC );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo != CRYPT_ALGO_RSA )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  More restrictive permissions may 
	   be set by higher-level code if required and in particular if the key 
	   is a pure public key rather than merely the public portions of a 
	   private key then the actions will be restricted at that point to 
	   encrypt and signature-check only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL );

	/* Read the BIT STRING encapsulation and the public key fields */
	readBitStringHole( stream, NULL, MIN_PKCSIZE_THRESHOLD, DEFAULT_TAG );
	readSequence( stream, NULL );
	status = readBignum( stream, &rsaKey->rsaParam_n, RSAPARAM_MIN_N, 
						 RSAPARAM_MAX_N, NULL, BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusOK( status ) )
		{
		status = readBignum( stream, &rsaKey->rsaParam_e,
							 RSAPARAM_MIN_E, RSAPARAM_MAX_E, 
							 &rsaKey->rsaParam_n, BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( rsaKey ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readDlpSubjectPublicKey( INOUT_PTR STREAM *stream, 
									INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
									OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	CRYPT_ALGO_TYPE readCryptAlgo DUMMY_INIT;
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DH || \
			  cryptAlgo == CRYPT_ALGO_DSA || \
			  cryptAlgo == CRYPT_ALGO_ELGAMAL );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the SubjectPublicKeyInfo header field and make sure that the DLP 
	   parameter data is present */
	status = readGenericHole( stream, NULL, 
							  8 + MIN_PKCSIZE_THRESHOLD + DLPPARAM_MIN_G + \
							  DLPPARAM_MIN_Q + MIN_PKCSIZE_THRESHOLD, 
							  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDex( stream, &readCryptAlgo, &algoIDparams, 
							   ALGOID_CLASS_PKC );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( !isShortIntegerRangeMin( algoIDparams.extraLength,
								 MIN_PKCSIZE_THRESHOLD + DLPPARAM_MIN_G + \
								 DLPPARAM_MIN_Q ) )
		return( CRYPT_ERROR_BADDATA );
	if( readCryptAlgo != cryptAlgo )
		return( CRYPT_ERROR_BADDATA );

	/* Read the header and key parameters */
	readSequence( stream, NULL );
	status = readBignum( stream, &dlpKey->dlpParam_p, DLPPARAM_MIN_P, 
						 DLPPARAM_MAX_P, NULL, BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusError( status ) )
		return( status );
	if( hasReversedParams( cryptAlgo ) )
		{
		status = readBignum( stream, &dlpKey->dlpParam_g, DLPPARAM_MIN_G, 
							 DLPPARAM_MAX_G, &dlpKey->dlpParam_p,
							 BIGNUM_CHECK_VALUE );
		if( cryptStatusOK( status ) )
			{
			status = readBignum( stream, &dlpKey->dlpParam_q, DLPPARAM_MIN_Q, 
								 DLPPARAM_MAX_Q, &dlpKey->dlpParam_p,
								 BIGNUM_CHECK_VALUE );
			}
		}
	else
		{
		status = readBignum( stream, &dlpKey->dlpParam_q, DLPPARAM_MIN_Q, 
							 DLPPARAM_MAX_Q, &dlpKey->dlpParam_p,
							 BIGNUM_CHECK_VALUE );
		if( cryptStatusOK( status ) )
			{
			status = readBignum( stream, &dlpKey->dlpParam_g, DLPPARAM_MIN_G, 
								 DLPPARAM_MAX_G, &dlpKey->dlpParam_p,
								 BIGNUM_CHECK_VALUE );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for DLP algorithms we make the usage 
	   internal-only.  If the key is a pure public key rather than merely 
	   the public portions of a private key then the actions will be 
	   restricted by higher-level code to encrypt/signature-check only */
	if( cryptAlgo == CRYPT_ALGO_DSA )
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
									   ACTION_PERM_NONE_EXTERNAL );
		}
	else
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );
		}

	/* Read the BIT STRING encapsulation and the public key fields */
	readBitStringHole( stream, NULL, MIN_PKCSIZE_THRESHOLD, DEFAULT_TAG );
	status = readBignum( stream, &dlpKey->dlpParam_y, DLPPARAM_MIN_Y, 
						 DLPPARAM_MAX_Y, &dlpKey->dlpParam_p, 
						 BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( dlpKey ) );

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readEccSubjectPublicKey( INOUT_PTR STREAM *stream, 
									INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
									OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	CRYPT_ALGO_TYPE readCryptAlgo DUMMY_INIT;
	CRYPT_ECCCURVE_TYPE curveType;
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;
	BYTE buffer[ MAX_PKCSIZE_ECCPOINT + 8 ];
	int length, fieldSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDSA || \
			  cryptAlgo == CRYPT_ALGO_ECDH );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the SubjectPublicKeyInfo header field and make sure that the ECC 
	   parameter data is present.  Because of the more or less arbitrary 
	   manner in which these parameters can be represented we have to be 
	   fairly open-ended in terms of the data size limits that we use, and 
	   in particular for named curves the lower bound is the size of a 
	   single OID that defines the curve */
	status = readGenericHole( stream, NULL, 
							  8 + MIN_OID_SIZE + \
							  MIN_PKCSIZE_ECCPOINT_THRESHOLD, 
							  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDex( stream, &readCryptAlgo, &algoIDparams, 
							   ALGOID_CLASS_PKC );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( !isShortIntegerRangeMin( algoIDparams.extraLength, 
								 MIN_OID_SIZE ) )
		return( CRYPT_ERROR_BADDATA );
	if( readCryptAlgo != cryptAlgo )
		return( CRYPT_ERROR_BADDATA );

	/* Now things get messy, since the ECC standards authors carefully 
	   sidestepped having to make a decision about anything and instead
	   just created an open framework into which it's possible to drop
	   almost anything.  To keep things sane we require the use of named
	   curves over a prime field, the de facto universal standard */
	status = readECCOID( stream, &curveType, &fieldSize );
	if( cryptStatusError( status ) )
		return( status );
	eccKey->curveType = curveType;

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for ECC algorithms (which are a part of the 
	   DLP algorithm family) we make the usage internal-only.  If the key is 
	   a pure public key rather than merely the public portions of a private 
	   key then the actions will be restricted by higher-level code to 
	   encrypt/signature-check only */
	if( cryptAlgo == CRYPT_ALGO_ECDSA )
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
									   ACTION_PERM_NONE_EXTERNAL );
		}
	else
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );
		}

	/* Read the BIT STRING encapsulation and the public key fields.  Instead 
	   of encoding the necessary information as an obvious OID + SEQUENCE 
	   combination for the parameters it's all stuffed into an ad-hoc BIT 
	   STRING that we have to pick apart manually.  Note that we can't use 
	   the ECC p value for a range check because it hasn't been set yet, all 
	   that we have at this point is a curve ID */
	status = readBitStringHole( stream, &length, 
								MIN_PKCSIZE_ECCPOINT_THRESHOLD, 
								DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	if( length < MIN_PKCSIZE_ECCPOINT_THRESHOLD || \
		length > MAX_PKCSIZE_ECCPOINT )
		return( CRYPT_ERROR_BADDATA );
	REQUIRES( rangeCheck( length, 1, MAX_PKCSIZE_ECCPOINT ) );
	status = sread( stream, buffer, length );
	if( cryptStatusError( status ) )
		return( status );
	status = importECCPoint( &eccKey->eccParam_qx, &eccKey->eccParam_qy,
							 buffer, length, MIN_PKCSIZE_ECC_THRESHOLD, 
							 CRYPT_MAX_PKCSIZE_ECC, fieldSize, NULL, 
							 BIGNUM_CHECK_VALUE_ECC );
	zeroise( buffer, MAX_PKCSIZE_ECCPOINT );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( eccKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_25519 ) || defined( USE_ED25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int read25519SubjectPublicKey( INOUT_PTR STREAM *stream, 
									  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
									  OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	CRYPT_ALGO_TYPE readCryptAlgo DUMMY_INIT;
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	BYTE buffer[ MAX_PKCSIZE_BERNSTEIN + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_25519 || \
			  cryptAlgo == CRYPT_ALGO_ED25519 );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the SubjectPublicKeyInfo header field and make sure that the ECC 
	   parameter data is present */
	status = readGenericHole( stream, NULL, 
							  8 + MIN_PKCSIZE_ECCPOINT_THRESHOLD, 
							  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = readAlgoID( stream, &readCryptAlgo, ALGOID_CLASS_PKC );
	if( cryptStatusError( status ) )
		return( status );
	if( readCryptAlgo != cryptAlgo )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for the Bernstein algorithms we make the 
	   usage internal-only.  If the key is a pure public key rather than 
	   merely the public portions of a private key then the actions will be 
	   restricted by higher-level code to encrypt/signature-check only */
	if( cryptAlgo == CRYPT_ALGO_25519 )
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );
		}
	else
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
									   ACTION_PERM_NONE_EXTERNAL );
		}

	/* Read the BIT STRING encapsulation and the public key fields.  Instead 
	   of encoding the necessary information as an obvious OID + SEQUENCE 
	   combination for the parameters it's all stuffed into an ad-hoc BIT 
	   STRING that we have to pick apart manually.  Note that we can't use 
	   the ECC p value for a range check because it hasn't been set yet, all 
	   that we have at this point is a curve ID */
	status = readBitStringHole( stream, &length, MIN_PKCSIZE_BERNSTEIN, 
								DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 32 )
		return( CRYPT_ERROR_BADDATA );
	REQUIRES( rangeCheck( length, 1, MAX_PKCSIZE_BERNSTEIN ) );
	status = sread( stream, buffer, length );
	if( cryptStatusError( status ) )
		return( status );
	status = import25519ByteString( &eccKey->curve25519Param_pub, 
									buffer, length );
	zeroise( buffer, MAX_PKCSIZE_BERNSTEIN );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( eccKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_25519 || USE_ED25519 */
#endif /* USE_INT_ASN1 */

/****************************************************************************
*																			*
*								Read SSH Public Keys						*
*																			*
****************************************************************************/

#ifdef USE_SSH

/* Read SSHv2 public keys:

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

   Ed25519:		
	string		[ server key/certificate ]
		string	"ssh-ed25519"
		string	key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readSshRsaPublicKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	char buffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the wrapper and make sure that it's OK */
	readUint32( stream );
	status = readString32( stream, buffer, CRYPT_MAX_TEXTSIZE, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 7 || memcmp( buffer, "ssh-rsa", 7 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  SSH keys are only used internally
	   so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSH public key information */
	status = readBignumInteger32( stream, &rsaKey->rsaParam_e, 
								  RSAPARAM_MIN_E, RSAPARAM_MAX_E, 
								  NULL, BIGNUM_CHECK_VALUE );
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger32( stream, &rsaKey->rsaParam_n,
									  RSAPARAM_MIN_N, RSAPARAM_MAX_N,
									  NULL, BIGNUM_CHECK_VALUE_PKC );
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( rsaKey ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readSshDlpPublicKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *dsaKey = contextInfoPtr->ctxPKC;
	char buffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	const BOOLEAN isDH = ( cryptAlgo == CRYPT_ALGO_DH ) ? TRUE : FALSE;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_DSA );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the wrapper and make sure that it's OK.  SSHv2 uses PKCS #3 
	   rather than X9.42-style DH keys so we have to treat this algorithm 
	   type specially */
	readUint32( stream );
	if( isDH )
		{
		status = readString32( stream, buffer, CRYPT_MAX_TEXTSIZE, &length );
		if( cryptStatusError( status ) )
			return( status );
		if( length != 6 || memcmp( buffer, "ssh-dh", 6 ) )
			return( CRYPT_ERROR_BADDATA );

		/* Set the maximum permitted actions.  SSH keys are only used 
		   internally so we restrict the usage to internal-only.  Since DH 
		   keys can be both public and private keys we allow both usage 
		   types even though technically it's a public key */
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );

		/* Read the SSH public key information */
		status = readBignumInteger32( stream, &dsaKey->dlpParam_p, 
									  DLPPARAM_MIN_P, DLPPARAM_MAX_P,
									  NULL, BIGNUM_CHECK_VALUE_PKC );
		if( cryptStatusOK( status ) )
			{
			status = readBignumInteger32( stream, &dsaKey->dlpParam_g,
										  DLPPARAM_MIN_G, DLPPARAM_MAX_G,
										  &dsaKey->dlpParam_p,
										  BIGNUM_CHECK_VALUE );
			}
		return( status );
		}

	/* It's a standard DLP key, read the wrapper and make sure that it's 
	   OK */
	status = readString32( stream, buffer, CRYPT_MAX_TEXTSIZE, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 7 || memcmp( buffer, "ssh-dss", 7 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  SSH keys are only used internally
	   so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSH public key information */
	status = readBignumInteger32( stream, &dsaKey->dlpParam_p, 
								  DLPPARAM_MIN_P, DLPPARAM_MAX_P, 
								  NULL, BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger32( stream, &dsaKey->dlpParam_q,
									  DLPPARAM_MIN_Q, DLPPARAM_MAX_Q,
									  &dsaKey->dlpParam_p, 
									  BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger32( stream, &dsaKey->dlpParam_g,
									  DLPPARAM_MIN_G, DLPPARAM_MAX_G,
									  &dsaKey->dlpParam_p,
									  BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger32( stream, &dsaKey->dlpParam_y,
									  DLPPARAM_MIN_Y, DLPPARAM_MAX_Y,
									  &dsaKey->dlpParam_p,
									  BIGNUM_CHECK_VALUE_PKC );
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( dsaKey ) );

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readSshEccPublicKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	BYTE buffer[ MAX_PKCSIZE_ECCPOINT + 8 ];
	int length, fieldSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	static_assert( CRYPT_MAX_TEXTSIZE <= MAX_PKCSIZE_ECCPOINT,
				   "CRYPT_MAX_TEXTSIZE buffer size" );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDSA );

	/* No need to clear return value as usual since it's set in the 
	   following line of code, and clearing it leads to compiler warnings
	   about unused assignments */

	/* Set the maximum permitted actions.  SSH keys are only used 
	   internally so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the wrapper and make sure that it's OK.  The key parameter
	   information is repeated twice, so for the overall wrapper we only
	   check for the ECDH/ECDSA algorithm indication and get the parameter
	   information from the second version, which contains only the
	   parameter string */
	readUint32( stream );
	status = readString32( stream, buffer, CRYPT_MAX_TEXTSIZE, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length < 18 )		/* "ecdh-sha2-nistXXXX" */
		return( CRYPT_ERROR_BADDATA );
	if( memcmp( buffer, "ecdsa-sha2-", 11 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Read and process the parameter information.  At this point we know 
	   that we've got valid ECC key data, so if we find anything unexpected 
	   we report it as an unavailable ECC field size rather than bad data */
	status = readString32( stream, buffer, CRYPT_MAX_TEXTSIZE, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 8 )		/* "nistXXXX" */
		return( CRYPT_ERROR_NOTAVAIL );
	if( !memcmp( buffer, "nistp256", 8 ) )
		eccKey->curveType = CRYPT_ECCCURVE_P256;
	else
		{
		if( !memcmp( buffer, "nistp384", 8 ) )
			eccKey->curveType = CRYPT_ECCCURVE_P384;
		else
			{
			if( !memcmp( buffer, "nistp521", 8 ) )
				eccKey->curveType = CRYPT_ECCCURVE_P521;
			else
				return( CRYPT_ERROR_NOTAVAIL );
			}
		}
	status = getECCFieldSize( eccKey->curveType, &fieldSize, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the ECC public key.  See the comments in 
	   readEccSubjectPublicKey() for why the checks are done the way they 
	   are, and in particular we can't use readInteger32() which would 
	   include the ability to check the value read because what's stored is
	   an encoded point and not a (potentially signed) integer */
	status = readString32( stream, buffer, MAX_PKCSIZE_ECCPOINT, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length < MIN_PKCSIZE_ECCPOINT_THRESHOLD || \
		length > MAX_PKCSIZE_ECCPOINT )
		return( CRYPT_ERROR_BADDATA );
	status = importECCPoint( &eccKey->eccParam_qx, &eccKey->eccParam_qy,
							 buffer, length, MIN_PKCSIZE_ECC_THRESHOLD, 
							 CRYPT_MAX_PKCSIZE_ECC, fieldSize, NULL, 
							 BIGNUM_CHECK_VALUE_ECC );
	zeroise( buffer, MAX_PKCSIZE_ECCPOINT );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( eccKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_25519 ) || defined( USE_ED25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readSsh25519PublicKey( INOUT_PTR STREAM *stream, 
								  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								  OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *ed25519Key = contextInfoPtr->ctxPKC;
	BYTE buffer[ MAX_PKCSIZE_ECCPOINT + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ED25519 );

	/* No need to clear return value as usual since it's set in the 
	   following line of code, and clearing it leads to compiler warnings
	   about unused assignments */

	/* Set the maximum permitted actions.  SSH keys are only used 
	   internally so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the wrapper and make sure that it's OK */
	readUint32( stream );
	status = readString32( stream, buffer, CRYPT_MAX_TEXTSIZE, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 11 || memcmp( buffer, "ssh-ed25519", 11 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Read the Ed25519 public key */
	status = readBignumInteger32( stream, &ed25519Key->curve25519Param_pub, 
								  MIN_PKCSIZE_BERNSTEIN, 
								  MAX_PKCSIZE_BERNSTEIN, 
								  NULL, BIGNUM_CHECK_VALUE_FIXEDLEN );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( ed25519Key ) );

	return( CRYPT_OK );
	}
#endif /* USE_25519 || USE_ED25519 */
#endif /* USE_SSH */

/****************************************************************************
*																			*
*								Read TLS Public Keys						*
*																			*
****************************************************************************/

#ifdef USE_TLS

/* Read TLS public keys:

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

   The DH y value is nominally attached to the DH p and g values but isn't 
   processed at this level since this is a pure PKCS #3 DH key and not a 
   generic DLP key.  The same holds for the ECDH Q value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readTlsDlpPublicKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags,
								IN_BOOL const BOOLEAN readExtKey )
	{
	PKC_INFO *dhKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DH );
	REQUIRES( isBooleanValue( readExtKey ) );

	/* No need to clear return value as usual since it's set in the 
	   following line of code, and clearing it leads to compiler warnings
	   about unused assignments */

	/* Set the maximum permitted actions.  TLS keys are only used 
	   internally so we restrict the usage to internal-only.  Since DH 
	   keys can be both public and private keys we allow both usage 
	   types even though technically it's a public key */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
								   ACTION_PERM_NONE_EXTERNAL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the TLS public key information */
	status = readBignumInteger16U( stream, &dhKey->dlpParam_p, 
								   DLPPARAM_MIN_P, DLPPARAM_MAX_P,
								   NULL, BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusOK( status ) && readExtKey )
		{
		status = readBignumInteger16U( stream, &dhKey->dlpParam_q, 
									   DLPPARAM_MIN_Q, DLPPARAM_MAX_Q,
									   &dhKey->dlpParam_p, 
									   BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger16U( stream, &dhKey->dlpParam_g, 
									   DLPPARAM_MIN_G, DLPPARAM_MAX_G,
									   &dhKey->dlpParam_p, 
									   BIGNUM_CHECK_VALUE_PKC );
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( dhKey ) );

	return( CRYPT_OK );
	}

#if defined( USE_ECDH )

static const MAP_TABLE tlsCurveInfo[] = {
	{ /* TLS_CURVE_SECP256R1 */ 23, CRYPT_ECCCURVE_P256 },
	{ /* TLS_CURVE_SECP384R1 */ 24, CRYPT_ECCCURVE_P384 },
	{ /* TLS_CURVE_SECP521R1 */ 25, CRYPT_ECCCURVE_P521 },
	{ /* TLS_CURVE_BRAINPOOLP256R1 */ 26, CRYPT_ECCCURVE_BRAINPOOL_P256 },
	{ /* TLS_CURVE_BRAINPOOLP384R1 */ 27, CRYPT_ECCCURVE_BRAINPOOL_P384 },
	{ /* TLS_CURVE_BRAINPOOLP512R1 */ 28, CRYPT_ECCCURVE_BRAINPOOL_P512 },
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

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readTlsEccPublicKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	const MAP_TABLE *tlsCurveInfoPtr;
	int value, curveID, tlsCurveInfoNoEntries, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDH );

	/* Set the maximum permitted actions.  TLS keys are only used 
	   internally so we restrict the usage to internal-only.  Since ECDH 
	   keys can be both public and private keys we allow both usage 
	   types even though technically it's a public key */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
								   ACTION_PERM_NONE_EXTERNAL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the TLS public key information */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value != 0x03 )		/* NamedCurve */
		return( CRYPT_ERROR_BADDATA );
	status = value = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value < 19 || value > 28 )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Look up the curve ID based on the TLS NamedCurve ID */
	status = getEccTlsInfoTbl( &tlsCurveInfoPtr, &tlsCurveInfoNoEntries );
	if( cryptStatusError( status ) )
		return( status );
	status = mapValue( value, &curveID, tlsCurveInfoPtr, 
					   tlsCurveInfoNoEntries );
	if( cryptStatusError( status ) )
		return( status );
	eccKey->curveType = curveID;

	ENSURES( sanityCheckPKCInfo( eccKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH */
#endif /* USE_TLS */

/****************************************************************************
*																			*
*								Read PGP Public Keys						*
*																			*
****************************************************************************/

#ifdef USE_PGP 

/* Read PGP public keys:

	byte		version
	uint32		creationTime
	[ uint16	validity - version 2 or 3 only ]
	byte		RSA		DSA		Elgamal		ECDH/ECDSA
	mpi			n		p		p			qx/qy
	mpi			e		q		g
	mpi					g		y
	mpi					y */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgpHeader( INOUT_PTR STREAM *stream, 
						  time_t *pgpCreationTime,
						  IN_BOOL const BOOLEAN openPgpOnly )
	{
	time_t timeValue DUMMY_INIT;
	int version, position, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pgpCreationTime, sizeof( time_t ) ) );

	REQUIRES( isBooleanValue( openPgpOnly ) );

	/* Clear return value */
	*pgpCreationTime = 0;

	/* Read the PGP version info */
	status = version = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( openPgpOnly )
		{
		if( version != PGP_VERSION_OPENPGP )
			return( CRYPT_ERROR_BADDATA );
		}
	else
		{
		if( version != PGP_VERSION_2 && version != PGP_VERSION_3 && \
			version != PGP_VERSION_OPENPGP )
			return( CRYPT_ERROR_BADDATA );
		}

	/* Read the creation time.  This gets a bit tricky becaue some keys 
	   coming from non-PGP sources can have a creation time of zero which 
	   would result in the value being rejected by readUint32Time().  
	   Because of this if the time read fails with CRYPT_ERROR_BADDATA we 
	   retry the read as a UINT32 and check for a value of zero */
	position = stell( stream );
	REQUIRES( isIntegerRangeNZ( position ) );
	status = readUint32Time( stream, &timeValue );
	if( cryptStatusError( status ) )
		{
		int value DUMMY_INIT;

		/* If there was an error on read and it wasn't due to an out-of-
		   range value, exit */
		if( cryptStatusError( status ) && status != CRYPT_ERROR_BADDATA )
			return( status );

		/* Retry the read as a UINT32, allowing it if it has the magic 
		   value 0 */
		sClearError( stream );
		status = sseek( stream, position );
		if( cryptStatusOK( status ) )
			status = value = readUint32( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( value != 0 )
			return( CRYPT_ERROR_BADDATA );
		timeValue = 0;
		}
	*pgpCreationTime = timeValue;

	/* Skip the validity time if it's present */
	if( version == PGP_VERSION_2 || version == PGP_VERSION_3 )
		return( sSkip( stream, 2, 2 ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readPgpRsaPublicKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the header info */
	status = readPgpHeader( stream, &rsaKey->pgpCreationTime, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the maximum permitted actions.  If there are no restrictions we
	   allow external usage, if the keys are encryption-only or signature-
	   only we make the usage internal-only because of RSA's signature/
	   encryption duality.  If the key is a pure public key rather than 
	   merely the public portions of a private key then the actions will be 
	   restricted by higher-level code to encrypt/signature-check only */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	switch( value )
		{
		case PGP_ALGO_RSA:
			*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
										   ACTION_PERM_ALL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
										   ACTION_PERM_ALL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
										   ACTION_PERM_ALL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
										   ACTION_PERM_ALL );
			break;

		case PGP_ALGO_RSA_ENCRYPT:
			*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
										   ACTION_PERM_NONE_EXTERNAL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
										   ACTION_PERM_NONE_EXTERNAL );
			break;

		case PGP_ALGO_RSA_SIGN:
			*actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
											ACTION_PERM_NONE_EXTERNAL ) | \
							MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
											ACTION_PERM_NONE_EXTERNAL );
			break;

		default:
			return( CRYPT_ERROR_BADDATA );
		}

	/* Read the PGP public key information */
	status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_n, 
									   bytesToBits( RSAPARAM_MIN_N ), 
									   bytesToBits( RSAPARAM_MAX_N ),
									   NULL, BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_e, 
										   bytesToBits( RSAPARAM_MIN_E ), 
										   bytesToBits( RSAPARAM_MAX_E ),
										   &rsaKey->rsaParam_n,
										   BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( rsaKey ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readPgpDlpPublicKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DSA || \
			  cryptAlgo == CRYPT_ALGO_ELGAMAL );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the header info */
	status = readPgpHeader( stream, &dlpKey->pgpCreationTime, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for DLP algorithms we make the usage 
	   internal-only.  If the key is a pure public key rather than merely 
	   the public portions of a private key then the actions will be 
	   restricted by higher-level code to encrypt/signature-check only  */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	switch( value )
		{
		case PGP_ALGO_DSA:
			*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
										   ACTION_PERM_NONE_EXTERNAL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
										   ACTION_PERM_NONE_EXTERNAL );
			break;
		
		case PGP_ALGO_ELGAMAL:
			*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
										   ACTION_PERM_NONE_EXTERNAL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
										   ACTION_PERM_NONE_EXTERNAL );
			break;

		default:
			return( CRYPT_ERROR_BADDATA );
		}

	/* Read the PGP public key information */
	status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_p, 
									   bytesToBits( DLPPARAM_MIN_P ), 
									   bytesToBits( DLPPARAM_MAX_P ),
									   NULL, BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusOK( status ) && value == PGP_ALGO_DSA )
		{
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_q, 
										   bytesToBits( DLPPARAM_MIN_Q ), 
										   bytesToBits( DLPPARAM_MAX_Q ),
										   &dlpKey->dlpParam_p,
										   BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_g, 
										   bytesToBits( DLPPARAM_MIN_G ), 
										   bytesToBits( DLPPARAM_MAX_G ),
										   &dlpKey->dlpParam_p,
										   BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_y, 
										   bytesToBits( DLPPARAM_MIN_Y ), 
										   bytesToBits( DLPPARAM_MAX_Y ),
										   &dlpKey->dlpParam_p,
										   BIGNUM_CHECK_VALUE_PKC );
		}
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( dlpKey ) );

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readPgpEccPublicKey( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	CRYPT_ECCCURVE_TYPE curveType;
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	STREAM oidStream;
	BYTE buffer[ MAX_PKCSIZE_ECCPOINT + 8 ];
	BYTE oidBuffer[ MAX_OID_SIZE + 8 ];
	int value, length, fieldSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDSA || \
			  cryptAlgo == CRYPT_ALGO_ECDH );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the header info */
	status = readPgpHeader( stream, &eccKey->pgpCreationTime, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for ECC algorithms (which are a part of the 
	   DLP algorithm family) we make the usage internal-only.  If the key is 
	   a pure public key rather than merely the public portions of a private 
	   key then the actions will be restricted by higher-level code to 
	   encrypt/signature-check only */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	switch( value )
		{
		case PGP_ALGO_ECDH:
			*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
										   ACTION_PERM_NONE_EXTERNAL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
										   ACTION_PERM_NONE_EXTERNAL );
			break;

		case PGP_ALGO_ECDSA:
			*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
										   ACTION_PERM_NONE_EXTERNAL ) | \
						   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
										   ACTION_PERM_NONE_EXTERNAL );
			break;

		default:
			return( CRYPT_ERROR_BADDATA );
		}

	/* Read the ECC OID, preceded by a length byte.  For no known reason 
	   (probably a coding error that was made part of the spec), the PGP
	   format omits the first two bytes of the OID, so we have to read the
	   value into an intermediate buffer and recreate the full OID from 
	   it.  Because of this the length checks are all adjusted by -2 to
	   account for the two-byte header that we need to insert */
	status = length = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length < MIN_OID_SIZE - 2 || length >= MAX_OID_SIZE - 2 )
		return( CRYPT_ERROR_BADDATA );
	oidBuffer[ 0 ] = 0x06;		/* OID tag */
	oidBuffer[ 1 ] = intToByte( length );
	REQUIRES( rangeCheck( length, 1, MAX_OID_SIZE - 2 ) );
	status = sread( stream, oidBuffer + 2, length );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &oidStream, oidBuffer, 2 + length );
	status = readECCOID( &oidStream, &curveType, &fieldSize );
	sMemDisconnect( &oidStream );
	if( cryptStatusError( status ) )
		return( status );
	eccKey->curveType = curveType;

	/* Read the ECC public key.  Since the encoded ECC point is stored 
	   (incorrectly) as an MPI, for once we can use a checked-read function */
	status = readInteger16Ubits( stream, buffer, &length, 
								 MIN_PKCSIZE_ECCPOINT_THRESHOLD, 
								 MAX_PKCSIZE_ECCPOINT, 
								 BIGNUM_CHECK_VALUE_ECC );
	if( cryptStatusError( status ) )
		return( status );
	status = importECCPoint( &eccKey->eccParam_qx, &eccKey->eccParam_qy,
							 buffer, length, MIN_PKCSIZE_ECC_THRESHOLD, 
							 CRYPT_MAX_PKCSIZE_ECC, fieldSize, NULL, 
							 BIGNUM_CHECK_VALUE_ECC );
	zeroise( buffer, MAX_PKCSIZE_ECCPOINT );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( eccKey ) );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */
#endif /* USE_PGP */

/****************************************************************************
*																			*
*							Public-Key Read Interface						*
*																			*
****************************************************************************/

/* Umbrella public-key read functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completePubkeyRead( INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							   IN_FLAGS( ACTION_PERM ) const int actionFlags )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES( isFlagRange( actionFlags, ACTION_PERM ) );

	/* If we're working with hardware contexts rather than native software
	   ones then the keying information may never be processed by cryptlib, 
	   which means that the key size will never be set.  In addition for
	   static contexts created by instantiating a context from raw encoded 
	   public-key data, used when calculating key IDs for non-native 
	   contexts, there's also no key size set.  To deal with this we
	   explicitly set the key size information at this point */
	if( pkcInfo->keySizeBits <= 0 )
		{
		switch( cryptAlgo )
			{
			case CRYPT_ALGO_RSA:
				pkcInfo->keySizeBits = BN_num_bits( &pkcInfo->rsaParam_n );
				break;

			case CRYPT_ALGO_DH:
#if defined( USE_DSA ) || defined( USE_ELGAMAL )
			case CRYPT_ALGO_DSA:
			case CRYPT_ALGO_ELGAMAL:
#endif /* USE_DSA || USE_ELGAMAL */
				pkcInfo->keySizeBits = BN_num_bits( &pkcInfo->dlpParam_p );
				break;
			
#if defined( USE_ECDSA ) || defined( USE_ECDH )
			case CRYPT_ALGO_ECDSA:
			case CRYPT_ALGO_ECDH:
				{
				int keySizeBits, status;

				status = getECCFieldSize( pkcInfo->curveType, 
										  &keySizeBits, TRUE );
				if( cryptStatusError( status ) )
					return( status );
				pkcInfo->keySizeBits = keySizeBits;
				break;
				}
#endif /* USE_ECDSA || USE_ECDH */

#if defined( USE_25519 ) || defined( USE_ED25519 )
			case CRYPT_ALGO_25519:
			case CRYPT_ALGO_ED25519:
				pkcInfo->keySizeBits = bytesToBits( 32 );
				break;
#endif /* USE_25519 || USE_ED25519 */

				default:
					retIntError();
			}
		ENSURES( pkcInfo->keySizeBits >= bytesToBits( MIN_PKCSIZE_ECC ) && \
				 pkcInfo->keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
		}

	/* If it's statically-initialised context data used in the self-test 
	   then there's no corresponding cryptlib object and we're done */
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_STATICCONTEXT ) )
		return( CRYPT_OK );

	/* Set the action permissions for the context */
	return( krnlSendMessage( contextInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE, 
							 ( MESSAGE_CAST ) &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readPublicKeyRsaFunction( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							  IN_ENUM( KEYFORMAT )  \
									const KEYFORMAT_TYPE formatType,
							  STDC_UNUSED const BOOLEAN checkRead )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_RSA );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( checkRead == FALSE );

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			status = readRsaSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;
#endif /* USE_INT_ASN1 */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			status = readSshRsaPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_SSH */

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			status = readPgpRsaPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_PGP */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	return( completePubkeyRead( contextInfoPtr, CRYPT_ALGO_RSA, 
								actionFlags ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readPublicKeyDlpFunction( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							  IN_ENUM( KEYFORMAT )  \
									const KEYFORMAT_TYPE formatType,
							  STDC_UNUSED const BOOLEAN checkRead )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_DH || \
			  cryptAlgo == CRYPT_ALGO_DSA || \
			  cryptAlgo == CRYPT_ALGO_ELGAMAL );
	REQUIRES( isEnumRange( formatType, KEYFORMAT ) );
	REQUIRES( checkRead == FALSE );

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			status = readDlpSubjectPublicKey( stream, contextInfoPtr, 
											  cryptAlgo, &actionFlags );
			break;
#endif /* USE_INT_ASN1 */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			status = readSshDlpPublicKey( stream, contextInfoPtr, 
										  cryptAlgo, &actionFlags );
			break;
#endif /* USE_SSH */

#ifdef USE_TLS
		case KEYFORMAT_TLS:
		case KEYFORMAT_TLS_EXT:
			status = readTlsDlpPublicKey( stream, contextInfoPtr, 
									cryptAlgo, &actionFlags,
									( formatType == KEYFORMAT_TLS_EXT ) ? \
									  TRUE : FALSE );
			break;
#endif /* USE_TLS */
		
#ifdef USE_PGP
		case KEYFORMAT_PGP:
			status = readPgpDlpPublicKey( stream, contextInfoPtr, 
										  cryptAlgo, &actionFlags );
			break;
#endif /* USE_PGP */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	return( completePubkeyRead( contextInfoPtr, cryptAlgo, 
								actionFlags ) );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readPublicKeyEccFunction( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							  IN_ENUM( KEYFORMAT )  \
									const KEYFORMAT_TYPE formatType,
							  STDC_UNUSED const BOOLEAN checkRead )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_ECDSA || \
			  cryptAlgo == CRYPT_ALGO_ECDH );
	REQUIRES( formatType == KEYFORMAT_CERT || formatType == KEYFORMAT_TLS || \
			  formatType == KEYFORMAT_TLS_EXT || formatType == KEYFORMAT_SSH || \
			  formatType == KEYFORMAT_PGP );
	REQUIRES( checkRead == FALSE );

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			status = readEccSubjectPublicKey( stream, contextInfoPtr, 
											  cryptAlgo, &actionFlags );
			break;
#endif /* USE_INT_ASN1 */

		/* TLS only uses ECDH (the ECDSA key data is conveyed in a 
		   certificate) so we only enable the TLS format if ECDH is defined 
		   rather than ECDH or ECDSA */
#if defined( USE_TLS ) && defined( USE_ECDH )
		case KEYFORMAT_TLS:
		case KEYFORMAT_TLS_EXT:
			status = readTlsEccPublicKey( stream, contextInfoPtr, 
										  cryptAlgo, &actionFlags );
			break;
#endif /* USE_TLS && USE_ECDH */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			status = readSshEccPublicKey( stream, contextInfoPtr, 
										  cryptAlgo, &actionFlags );
			break;
#endif /* USE_SSH */

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			status = readPgpEccPublicKey( stream, contextInfoPtr, 
										  cryptAlgo, &actionFlags );
			break;
#endif /* USE_SSH */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	return( completePubkeyRead( contextInfoPtr, cryptAlgo, 
								actionFlags ) );
	}
#endif /* USE_ECDH || USE_ECDSA */

#if defined( USE_25519 ) || defined( USE_ED25519 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readPublicKey25519Function( INOUT_PTR STREAM *stream, 
								INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								IN_ENUM( KEYFORMAT )  \
									const KEYFORMAT_TYPE formatType,
								STDC_UNUSED const BOOLEAN checkRead )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_25519 || \
			  cryptAlgo == CRYPT_ALGO_ED25519 );
	REQUIRES( formatType == KEYFORMAT_CERT || formatType == KEYFORMAT_SSH );
	REQUIRES( checkRead == FALSE );

	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case KEYFORMAT_CERT:
			status = read25519SubjectPublicKey( stream, contextInfoPtr, 
												cryptAlgo, &actionFlags );
			break;
#endif /* USE_INT_ASN1 */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			status = readSsh25519PublicKey( stream, contextInfoPtr, 
											cryptAlgo, &actionFlags );
			break;
#endif /* USE_SSH */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	return( completePubkeyRead( contextInfoPtr, cryptAlgo, 
								actionFlags ) );
	}
#endif /* USE_25519 || USE_ED25519 */

/****************************************************************************
*																			*
*								Read DL Values								*
*																			*
****************************************************************************/

/* Unlike the simpler RSA PKC, DL-based PKCs produce a pair of values that
   need to be encoded as structured data.  The following two functions 
   decode the encoded forms from various formats.  SSH assumes that DLP 
   values are two fixed-size blocks of 20 bytes so we can't use the normal 
   read/write routines to handle these values.
   
   In the ECC case, the format is a pair of values rather than an X9.62 ECC
   point, which would be read by importECCPoint() */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
int decodeDLValuesFunction( IN_BUFFER( bufSize ) const BYTE *buffer, 
							IN_LENGTH_SHORT_MIN( 32 ) const int bufSize, 
							INOUT_PTR BIGNUM *value1, 
							INOUT_PTR BIGNUM *value2, 
							const BIGNUM *maxRange,
							IN_ENUM( CRYPT_FORMAT )  \
								const CRYPT_FORMAT_TYPE formatType )
	{
	STREAM stream;
	int status;

	assert( isReadPtrDynamic( buffer, bufSize ) );
	assert( isWritePtr( value1, sizeof( BIGNUM ) ) );
	assert( isWritePtr( value2, sizeof( BIGNUM ) ) );
	assert( isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( isShortIntegerRangeMin( bufSize, 32 ) );
	REQUIRES( isEnumRange( formatType, CRYPT_FORMAT ) );

	/* Clear return values */
	BN_clear( value1 );
	BN_clear( value2 );

	sMemConnect( &stream, buffer, bufSize );

	/* Read the DL components from the buffer and make sure that they're 
	   valid, i.e. that they're in the range [1...maxRange - 1] (the lower
	   bound is actually DLPPARAM_MIN_SIG_x and not 1, which is > 100 bits).  
	   Although nominally intended for DLP algorithms the DLPPARAM_MIN_SIG_x 
	   values also work for ECC ones since they're also in the DLP family */
	switch( formatType )
		{
#ifdef USE_INT_ASN1
		case CRYPT_FORMAT_CRYPTLIB:
			readSequence( &stream, NULL );
			status = readBignum( &stream, value1, DLPPARAM_MIN_SIG_R,
								 CRYPT_MAX_PKCSIZE, maxRange, 
								 BIGNUM_CHECK_VALUE );
			if( cryptStatusError( status ) )
				break;
			status = readBignum( &stream, value2, DLPPARAM_MIN_SIG_S,
								 CRYPT_MAX_PKCSIZE, maxRange,
								 BIGNUM_CHECK_VALUE );
			break;
#endif /* USE_INT_ASN1 */

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = readBignumInteger16Ubits( &stream, value1, 
											   DLPPARAM_MIN_SIG_R,
											   bytesToBits( CRYPT_MAX_PKCSIZE ),
											   maxRange, BIGNUM_CHECK_VALUE );
			if( cryptStatusError( status ) )
				break;
			status = readBignumInteger16Ubits( &stream, value2, 
											   DLPPARAM_MIN_SIG_S,
											   bytesToBits( CRYPT_MAX_PKCSIZE ),
											   maxRange, BIGNUM_CHECK_VALUE );
			break;
#endif /* USE_PGP */
	
#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			status = importBignum( value1, buffer, 20, DLPPARAM_MIN_SIG_R, 
								   20, maxRange, BIGNUM_CHECK_VALUE );
			if( cryptStatusError( status ) )
				break;
			status = importBignum( value2, buffer + 20, 20, DLPPARAM_MIN_SIG_S, 
								   20, maxRange, BIGNUM_CHECK_VALUE );
			break;
#endif /* USE_SSH */

		default:
			retIntError();
		}

	/* Clean up */
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckBignum( value1 ) );
	ENSURES( sanityCheckBignum( value2 ) );

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
int decodeECDLValuesFunction( IN_BUFFER( bufSize ) const BYTE *buffer, 
							  IN_LENGTH_SHORT_MIN( 32 ) const int bufSize, 
							  INOUT_PTR BIGNUM *value1, 
							  INOUT_PTR BIGNUM *value2, 
							  const BIGNUM *maxRange,
							  IN_ENUM( CRYPT_FORMAT )  \
									const CRYPT_FORMAT_TYPE formatType )
	{
	STREAM stream;
	int status;

	assert( isReadPtrDynamic( buffer, bufSize ) );
	assert( isWritePtr( value1, sizeof( BIGNUM ) ) );
	assert( isWritePtr( value2, sizeof( BIGNUM ) ) );
	assert( isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( isShortIntegerRangeMin( bufSize, 32 ) );
	REQUIRES( isEnumRange( formatType, CRYPT_FORMAT ) );

	/* Clear return values */
	BN_clear( value1 );
	BN_clear( value2 );

	/* In most cases the DLP and ECDLP formats are identical and we can just
	   pass the call on to the DLP form, however SSH uses totally different 
	   signature formats depending on whether the signature is DSA or ECDSA, 
	   so we handle the SSH format explicitly here */
	if( formatType != CRYPT_IFORMAT_SSH )
		{
		return( decodeDLValuesFunction( buffer, bufSize, value1, value2, 
										maxRange, formatType ) );
		}
	sMemConnect( &stream, buffer, bufSize );
	status = readBignumInteger32( &stream, value1, ECCPARAM_MIN_SIG_R,
								  CRYPT_MAX_PKCSIZE_ECC, maxRange,
								  BIGNUM_CHECK_VALUE );
	if( cryptStatusOK( status ) )
		{
		status = readBignumInteger32( &stream, value2, ECCPARAM_MIN_SIG_S,
									  CRYPT_MAX_PKCSIZE_ECC, maxRange,
									  BIGNUM_CHECK_VALUE );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckBignum( value1 ) );
	ENSURES( sanityCheckBignum( value2 ) );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */
#endif /* USE_PKC */
