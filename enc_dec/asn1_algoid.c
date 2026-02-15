/****************************************************************************
*																			*
*						ASN.1 Algorithm Identifier Routines					*
*						Copyright Peter Gutmann 1992-2019					*
*																			*
****************************************************************************/

#define PKC_CONTEXT
#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "asn1_int.h"
  #include "context.h"				/* For getECCFieldSize() */
#else
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/asn1_int.h"
  #include "context/context.h"		/* For getECCFieldSize() */
#endif /* Compiler-specific includes */

#ifdef USE_INT_ASN1

/* The minimum size of an encoded OID.  Usually these are at least 7 bytes 
   long, but 25519 uses very short OIDs */

#if defined( USE_25519 ) || defined( USE_ED25519 )
  #define MIN_ALGOID_OID_SIZE		MIN_OID_SIZE
#else
  #define MIN_ALGOID_OID_SIZE		7
#endif /* USE_25519 || USE_ED25519 */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check the ALGOID_PARAMS structure.  The content of this is rather complex 
   and comes in the following variants:

	cryptAlgo		hashAlgo/size	cryptMode/size	Encoding	ExtraLength
	---------		-------------	--------------	--------	-----------
	Any				0				0				0			0
	Conv			0				Mode info		0			0
	Hash			Hash info		0				0			0
	AuthEnc			0				Secret size		0			0
	PKC-Sig			Hash info		0				0			0
	PKC-Sig			Hash info		0				Encoding	0
	PKC-Enc			0				0				0			0
	PKC-Enc			Hash info		0				Encoding	0 
	DLP/ECC key		0				0				0			Param length */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 2 ) ) \
BOOLEAN sanityCheckAlgoIDparams( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								 const ALGOID_PARAMS *algoIDparams )
	{
	assert( isReadPtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES_B( isEnumRange( cryptAlgo, CRYPT_ALGO ) );

	/* If it's a conventional-encryption or AuthEnc algorithm then for
	   conventional the encryption mode must be present and a key size may 
	   be present and for AuthEnc the key size must be present */
	if( isConvAlgo( cryptAlgo ) || isSpecialAlgo( cryptAlgo ) )
		{
		if( algoIDparams->hashAlgo != CRYPT_ALGO_NONE || \
			algoIDparams->hashParam != 0 || \
			algoIDparams->encodingType != ALGOID_ENCODING_NONE || \
			algoIDparams->extraLength != 0 )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: Spurious crypt "
						 "parameters" ));
			return( FALSE );
			}
		if( isConvAlgo( cryptAlgo ) )
			{
			if( !isEnumRange( algoIDparams->cryptMode, CRYPT_MODE ) || \
				algoIDparams->cryptKeySize < 0 || \
				algoIDparams->cryptKeySize > CRYPT_MAX_KEYSIZE )
				{
				DEBUG_PUTS(( "sanityCheckAlgoIDparams: Crypt parameters" ));
				return( FALSE );
				}
			}
		else
			{
			if( algoIDparams->cryptMode != CRYPT_MODE_NONE || \
				algoIDparams->cryptKeySize < 16 || \
				algoIDparams->cryptKeySize > CRYPT_MAX_KEYSIZE )
				{
				DEBUG_PUTS(( "sanityCheckAlgoIDparams: AuthEnc parameters" ));
				return( FALSE );
				}
			}

		return( TRUE );
		}

	/* Beyond this point there should be no encryption parameters set */
	if( algoIDparams->cryptMode != CRYPT_MODE_NONE || \
		algoIDparams->cryptKeySize != 0 )
		{
		DEBUG_PUTS(( "sanityCheckAlgoIDparams: Spurious crypt parameters on "
					 "non-crypto algo" ));
		return( FALSE );
		}

	/* If it's a DLP or ECC key then it has complex, user-defined 
	   parameters */
	if( ( isDlpAlgo( cryptAlgo ) || isEccAlgo( cryptAlgo ) ) && \
		algoIDparams->extraLength != 0 )
		{
		if( algoIDparams->hashAlgo != CRYPT_ALGO_NONE || \
			algoIDparams->hashParam != 0 || \
			algoIDparams->encodingType != ALGOID_ENCODING_NONE )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: Spurious DLP/ECC key "
						 "parameters" ));
			return( FALSE );
			}
		if( !isShortIntegerRangeNZ( algoIDparams->extraLength ) )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: DLP/ECC key parameters" ));
			return( FALSE );
			}

		return( TRUE );
		}

	/* Beyond this point there should be no extra-length parameter set */
	if( algoIDparams->extraLength != 0 )
		{
		DEBUG_PUTS(( "sanityCheckAlgoIDparams: Spurious PKC extraLength "
					 "parameter" ));
		return( FALSE );
		}

	/* If it's a hash algorithm then the hash parameters must be present */
	if( isHashAlgo( cryptAlgo ) || isMacAlgo( cryptAlgo ) )
		{
		if( algoIDparams->encodingType != ALGOID_ENCODING_NONE )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: Spurious hash/MAC "
						 "parameters" ));
			return( FALSE );
			}
		if( algoIDparams->hashAlgo != cryptAlgo || \
			!rangeCheck( algoIDparams->hashParam, MIN_HASHSIZE, 
						 CRYPT_MAX_HASHSIZE ) )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: Hash/MAC parameters" ));
			return( FALSE );
			}

		return( TRUE );
		}

	/* If it's a special-snowflake algorithm then there are no parameters */
	if( isBernsteinAlgo( cryptAlgo ) )
		{
		if( algoIDparams->hashAlgo != CRYPT_ALGO_NONE || \
			algoIDparams->hashParam != 0 )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: PKC hash parameters" ));
			return( FALSE );
			}
		if( algoIDparams->encodingType != ALGOID_ENCODING_NONE )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: PKC signature parameters" ));
			return( FALSE );
			}

		return( TRUE );
		}

	/* It's a PKC, the hash parameters must be present.  For the PKC 
	   encryption case if they were absent then no ALGOID_PARAMS would be 
	   specified */
	if( !isHashAlgo( algoIDparams->hashAlgo ) || \
		!rangeCheck( algoIDparams->hashParam, MIN_HASHSIZE, 
					 CRYPT_MAX_HASHSIZE ) )
		{
		DEBUG_PUTS(( "sanityCheckAlgoIDparams: PKC hash parameters" ));
		return( FALSE );
		}

	/* If it's a signature algorithm then an encoding specifier may be 
	   present, if it's an encryption algorithm then it must be present for
	   the reason given above */
	if( isSigAlgo( cryptAlgo ) )
		{
		if( !isEnumRangeOpt( algoIDparams->encodingType, ALGOID_ENCODING ) )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: PKC signature parameters" ));
			return( FALSE );
			}
		}
	else
		{
		if( !isEnumRange( algoIDparams->encodingType, ALGOID_ENCODING ) )
			{
			DEBUG_PUTS(( "sanityCheckAlgoIDparams: PKC crypt parameters" ));
			return( FALSE );
			}
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*					AlgorithmIdentifier Parameter Routines					*
*																			*
****************************************************************************/

/* Work with the ridiculously complex parameter sets required for RSA-OAEP
   and RSA-PSS.  The parameters are mostly identical for OAEP and PSS:

	Parameters ::= SEQUENCE {
		hashAlgorithm		[0]	EXPLICIT AlgorithmIdentifier,
		maskGenAlgorithm	[1] EXPLICIT {			-- AlgorithmIdentifier
			maskGenOID		OBJECT IDENTIFIER pkcs1-MGF,
			hashAlgorithm	AlgorithmIdentifier,	-- Same as main hashAlgo
			}
		saltLength			[2] EXPLICIT INTEGER	-- RSA-PSS only
		} */

#if defined( USE_OAEP ) || defined( USE_PSS )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readAlgoIDparams( INOUT_PTR STREAM *stream, 
							 OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
							 OUT_OPT ALGOID_PARAMS *algoIDparams,
							 IN_ENUM( ALGOID_CLASS ) \
									const ALGOID_CLASS_TYPE type,
							 IN_TAG const int tag );

#define OID_PKCS1_MGF	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x08" )

enum { CTAG_PP_HASHALGO, CTAG_PP_MASKGENALGO, CTAG_PP_SALTLEN };

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 2 ) ) \
static int getPKCSparamSize( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							 const ALGOID_PARAMS *algoIDparams  )
	{
	ALGOID_PARAMS hashAlgoIDparams;
	const BYTE *oid;
	int hashAlgoIDsize, algoIDparamSize = 0;

	assert( isReadPtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES( sanityCheckAlgoIDparams( cryptAlgo, algoIDparams ) );

	/* If the algorithm used is SHA-1 then we're using default parameters,
	   a zero-length SEQUENCE */
	if( algoIDparams->hashAlgo == CRYPT_ALGO_SHA1 )
		return( sizeofObject( 0 ) );

	/* It's a non-default hash algorithm, calculate the size of the 
	   structure required to specify it */
	initAlgoIDparamsHash( &hashAlgoIDparams, algoIDparams->hashAlgo, 
						  algoIDparams->hashParam );
	oid = algorithmToOID( algoIDparams->hashAlgo, &hashAlgoIDparams, 
						  ALGOTOOID_REQUIRE_VALID );
	REQUIRES( oid != NULL );
	hashAlgoIDsize = sizeofObject( sizeofOID( oid ) + sizeofNull() );
	algoIDparamSize = sizeofObject( hashAlgoIDsize ) + \
					  sizeofObject( \
						sizeofObject( sizeofOID( OID_PKCS1_MGF ) + \
									  hashAlgoIDsize ) );
	if( algoIDparams->encodingType == ALGOID_ENCODING_PSS )
		{
		algoIDparamSize += \
				sizeofObject( sizeofShortInteger( algoIDparams->hashParam ) );
		}

	return( sizeofObject( algoIDparamSize ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writePKCSparams( INOUT_PTR STREAM *stream, 
							IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							const ALGOID_PARAMS *algoIDparams )
	{
	ALGOID_PARAMS hashAlgoIDparams;
	const BYTE *oid;
	int hashAlgoIDsize, algoIDparamSize = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES_S( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES_S( sanityCheckAlgoIDparams( cryptAlgo, algoIDparams ) );

	/* If the algorithm used is SHA-1 then we're using default parameters,
	   a zero-length SEQUENCE */
	if( algoIDparams->hashAlgo == CRYPT_ALGO_SHA1 )
		return( writeSequence( stream, 0 ) );

	/* It's a non-default hash algorithm, calculate the size of the 
	   structure required to specify it */
	initAlgoIDparamsHash( &hashAlgoIDparams, algoIDparams->hashAlgo, 
						  algoIDparams->hashParam );
	oid = algorithmToOID( algoIDparams->hashAlgo, &hashAlgoIDparams, 
						  ALGOTOOID_REQUIRE_VALID );
	REQUIRES_S( oid != NULL );
	hashAlgoIDsize = sizeofObject( sizeofOID( oid ) + sizeofNull() );
	algoIDparamSize = sizeofObject( hashAlgoIDsize ) + \
					  sizeofObject( \
						sizeofObject( sizeofOID( OID_PKCS1_MGF ) + \
									  hashAlgoIDsize ) );
	if( algoIDparams->encodingType == ALGOID_ENCODING_PSS )
		{
		algoIDparamSize += \
				sizeofObject( sizeofShortInteger( algoIDparams->hashParam ) );
		}

	/* Write the algorithm parameters.  It would probably make more sense to 
	   write this in pre-encoded form, mapping a hash algorithm to a block 
	   of pre-encoded bytes, however this means that we then have to update 
	   the encoded-bytes table every time a new hash algorithm or hash size 
	   is added */
	writeSequence( stream, algoIDparamSize );
	writeConstructed( stream, 
					  sizeofObject( sizeofOID( oid ) + sizeofNull() ),
					  CTAG_PP_HASHALGO );
	writeSequence( stream, sizeofOID( oid ) + sizeofNull() );
	writeOID( stream, oid );
	writeNull( stream, DEFAULT_TAG );
	writeConstructed( stream, 
					  sizeofObject( \
						sizeofOID( OID_PKCS1_MGF ) + hashAlgoIDsize ),
					  CTAG_PP_MASKGENALGO );
	writeSequence( stream, sizeofOID( OID_PKCS1_MGF ) + hashAlgoIDsize );
	writeOID( stream, OID_PKCS1_MGF );
	writeSequence( stream, sizeofOID( oid ) + sizeofNull() );
	writeOID( stream, oid );
	status = writeNull( stream, DEFAULT_TAG );
	if( algoIDparams->encodingType == ALGOID_ENCODING_PSS )
		{
		writeConstructed( stream, 
						  sizeofShortInteger( algoIDparams->hashParam ), 
						  CTAG_PP_SALTLEN );
		status = writeShortInteger( stream, algoIDparams->hashParam, 
									DEFAULT_TAG );
		}

	return( status );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPKCSparams( INOUT_PTR STREAM *stream, 
						   INOUT_PTR ALGOID_PARAMS *algoIDparams )
	{
	CRYPT_ALGO_TYPE hashAlgo DUMMY_INIT;
	ALGOID_PARAMS hashAlgoIDparams DUMMY_INIT_STRUCT;
	int tag, length, endPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	/* The algoIDparams already contain partial data so we don't clear them
	   as we normally would for a return value */

	/* Read the outer wrapper.  If it's of zero length then the parameters 
	   are the default, SHA-1 */
	status = readSequenceZ( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length == 0 )
		{
		algoIDparams->hashAlgo = CRYPT_ALGO_SHA1;
		algoIDparams->hashParam = 20;

		return( CRYPT_OK );
		}
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length + 1 ) );

	/* Read the hash algorithm */
	status = readConstructed( stream, NULL, CTAG_PP_HASHALGO );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDparams( stream, &hashAlgo, &hashAlgoIDparams, 
								   ALGOID_CLASS_HASH, DEFAULT_TAG );
		}
	if( cryptStatusError( status ) )
		return( status );
	algoIDparams->hashAlgo = hashAlgo;
	algoIDparams->hashParam = hashAlgoIDparams.hashParam;

	/* Read the mask algorithm and make sure that it matches the hash 
	   algorithm */
	readConstructed( stream, NULL, CTAG_PP_MASKGENALGO );
	readSequence( stream, NULL );
	status = readFixedOID( stream, OID_PKCS1_MGF, 
						   sizeofOID( OID_PKCS1_MGF ) );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDparams( stream, &hashAlgo, &hashAlgoIDparams, 
								   ALGOID_CLASS_HASH, DEFAULT_TAG );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( algoIDparams->hashAlgo != hashAlgo || \
		algoIDparams->hashParam != hashAlgoIDparams.hashParam )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* If they're OAEP parameters, we're done */
	if( algoIDparams->encodingType == ALGOID_ENCODING_OAEP )
		return( CRYPT_OK );

	/* Read the optional salt length and make sure that it matches the hash 
	   size */
	if( stell( stream ) < endPos )
		{
		status = tag = peekTag( stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		/* There's no more data present, set a dummy value */
		tag = CRYPT_ERROR;
		}
	if( tag == MAKE_CTAG( CTAG_PP_SALTLEN ) )
		{
		long value;

		readConstructed( stream, NULL, CTAG_PP_SALTLEN );
		status = readShortInteger( stream, &value );
		if( cryptStatusError( status ) )
			return( status );
		if( value != algoIDparams->hashParam )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	else
		{
		/* There's no salt size specified which means that it defaults to 20 
		   bytes to match the default algorithm of SHA-1.  This is 
		   problematic because RFC 4055 says (section 3.1) that it should 
		   match the hash size and we have no easy way to communicate a 
		   nonstandard salt size across n levels of function calls, so we 
		   require that the salt size match the hash size */
		if( algoIDparams->hashParam != 20 )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	
	return( CRYPT_OK );
	}
#endif /* USE_OAEP || USE_PSS */

/****************************************************************************
*																			*
*					Miscellaneous AlgorithmIdentifier Routines				*
*																			*
****************************************************************************/

/* Because AlgorithmIdentifiers are only defined for a subset of the
   algorithms that cryptlib supports we have to check that the algorithm
   and mode being used can be represented in encoded form before we try to
   do anything with it */

CHECK_RETVAL_BOOL \
BOOLEAN checkAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					 IN_MODE_OPT const CRYPT_MODE_TYPE cryptMode )
	{
	ALGOID_PARAMS algoIDparams;

	REQUIRES_B( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES_B( isEnumRangeOpt( cryptMode, CRYPT_MODE ) );

	/* If it's a basic algorithm like a hash algorithm then there are no 
	   additional parameters */
	if( cryptMode == CRYPT_MODE_NONE )
		{
		return( ( algorithmToOID( cryptAlgo, NULL, \
								  ALGOTOOID_CHECK_VALID ) != NULL ) ? \
				TRUE : FALSE );
		}

	/* It's a crypto algorithm, specify the additional parameter */
	initAlgoIDparamsCrypt( &algoIDparams, cryptMode, 0 );
	return( ( algorithmToOID( cryptAlgo, &algoIDparams, \
							  ALGOTOOID_CHECK_VALID ) != NULL ) ? \
			TRUE : FALSE );
	}

/* Read/write a non-crypto algorithm identifier, used for things like 
   content types.  This just wraps the given OID up in the 
   AlgorithmIdentifier and writes it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readGenericAlgoID( INOUT_PTR STREAM *stream, 
					   IN_BUFFER( oidLength ) const BYTE *oid, 
					   IN_LENGTH_OID const int oidLength )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( oid, oidLength ) && \
			oidLength == sizeofOID( oid ) );

	REQUIRES_S( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE );

	/* Read the AlgorithmIdentifier wrapper and OID.  One possible 
	   complication here is the standard NULL vs.absent AlgorithmIdentifier 
	   parameter issue, to handle this we allow either option */
	readSequence( stream, &length );
	status = readFixedOID( stream, oid, oidLength );
	if( cryptStatusError( status ) )
		return( status );
	length -= oidLength;
	if( !isShortIntegerRange( length ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( length > 0 )
		return( readNull( stream ) );

	return( CRYPT_OK );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeGenericAlgoID( INOUT_PTR STREAM *stream, 
						IN_BUFFER( oidLength ) const BYTE *oid, 
						IN_LENGTH_OID const int oidLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( oid, oidLength ) && \
			oidLength == sizeofOID( oid ) );

	REQUIRES_S( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE );

	writeSequence( stream, oidLength );
	return( writeOID( stream, oid ) );
	}

/****************************************************************************
*																			*
*						AlgorithmIdentifier Sizeof Routines					*
*																			*
****************************************************************************/

/* Determine the size of an AlgorithmIdentifier record */

CHECK_RETVAL_LENGTH_SHORT \
static int sizeofAlgoIDparams( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							   IN_PTR_OPT const ALGOID_PARAMS *algoIDparams )
	{
	const BYTE *oid;

	assert( algoIDparams == NULL || \
			isReadPtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES( algoIDparams == NULL || \
			  sanityCheckAlgoIDparams( cryptAlgo, algoIDparams ) );

	/* Map the algorithm parameters to an OID */
	oid = algorithmToOID( cryptAlgo, algoIDparams, ALGOTOOID_REQUIRE_VALID );
	REQUIRES( oid != NULL );

	/* Return the overall encoded algorithmID size */
	if( algoIDparams != NULL )
		{
		if( algoIDparams->extraLength > 0 )
			{
			return( sizeofShortObject( sizeofOID( oid ) + \
									   algoIDparams->extraLength ) );
			}
#if defined( USE_OAEP ) || defined( USE_PSS )
		if( algoIDparams->encodingType == ALGOID_ENCODING_OAEP || \
			algoIDparams->encodingType == ALGOID_ENCODING_PSS )
			{
			int paramLength, status;

			status = paramLength = \
						getPKCSparamSize( cryptAlgo, algoIDparams );
			if( cryptStatusError( status ) )
				return( status );
			return( sizeofShortObject( sizeofOID( oid ) + paramLength ) );
			}
#endif /* USE_OAEP || USE_PSS */
		
		/* It's an algorithm for which there's no further special-case 
		   handling required */
		ENSURES( ( algoIDparams->encodingType == ALGOID_ENCODING_NONE || \
				   algoIDparams->encodingType == ALGOID_ENCODING_PKCS1 ) && \
				 algoIDparams->extraLength == 0 );
		}

	/* It's just a basic OID, typically with unnecessary NULL parameters.  
	   The reason for this is that when the ASN.1-88 syntax for 
	   AlgorithmIdentifier was translated into the ASN.1-97 syntax the 
	   OPTIONAL associated with the AlgorithmIdentifier parameters got lost.  
	   Later it was recovered via a defect report but by then everyone 
	   thought that algorithm parameters were mandatory, requiring the 
	   encoding of an unnecessary NULL value for the parameters.  However by 
	   the time DSA came along people had agreed that they really weren't 
	   actually mandatory, so in practice only non-PKC algorithms and RSA 
	   have the NULL explicitly encoded.  For the RSA case it also only 
	   applies to PKCS #1 RSA, OAEP and PSS include a huge mass of cruft as 
	   parameters and are handled above */
	if( !isPkcAlgo( cryptAlgo ) || ( cryptAlgo == CRYPT_ALGO_RSA ) )
		return( sizeofShortObject( sizeofOID( oid ) + sizeofNull() ) );

	return( sizeofShortObject( sizeofOID( oid ) ) );
	}

CHECK_RETVAL_LENGTH_SHORT \
int sizeofAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	REQUIRES( isEnumRange( cryptAlgo, CRYPT_ALGO ) );

	return( sizeofAlgoIDparams( cryptAlgo, NULL ) );
	}

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 2 ) ) \
int sizeofAlgoIDex( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					const ALGOID_PARAMS *algoIDparams )
	{
	REQUIRES( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES( algoIDparams != NULL );

	assert( isReadPtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	return( sizeofAlgoIDparams( cryptAlgo, algoIDparams ) );
	}

/* Determine the size of an AlgorithmIdentifier record from a context */

CHECK_RETVAL_LENGTH \
static int sizeofContextAlgoIDparam( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
									 IN_PTR_OPT const ALGOID_PARAMS *algoIDparams )
	{
	int algorithm, status;

	assert( algoIDparams == NULL || \
			isReadPtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );

	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	return( sizeofAlgoIDparams( algorithm, algoIDparams ) );
	}

CHECK_RETVAL_LENGTH \
int sizeofContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	REQUIRES( isHandleRangeValid( iCryptContext ) );

	return( sizeofContextAlgoIDparam( iCryptContext, NULL ) );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 2 ) ) \
int sizeofContextAlgoIDex( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						   const ALGOID_PARAMS *algoIDparams )
	{
	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( algoIDparams != NULL );

	return( sizeofContextAlgoIDparam( iCryptContext, algoIDparams ) );
	}

/****************************************************************************
*																			*
*						AlgorithmIdentifier Read Routines					*
*																			*
****************************************************************************/

/* Read an AlgorithmIdentifier record */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readAlgoIDparams( INOUT_PTR STREAM *stream, 
							 OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
							 OUT_OPT ALGOID_PARAMS *algoIDparams,
							 IN_ENUM( ALGOID_CLASS ) \
									const ALGOID_CLASS_TYPE type,
							 IN_TAG const int tag )
	{
	ALGOID_PARAMS algoIDparamInfo, *algoIDparamPtr = algoIDparams;
	BYTE oidBuffer[ MAX_OID_SIZE + 8 ];
	int oidLength, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( algoIDparams == NULL || \
			isWritePtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES_S( isEnumRange( type, ALGOID_CLASS ) );
	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );
	
	/* Clear return values */
	*cryptAlgo = CRYPT_ALGO_NONE;

	/* If the user isn't interested in the algorithm details, use a local
	   parameter structure to contain them */
	if( algoIDparams == NULL )
		algoIDparamPtr = &algoIDparamInfo;

	/* Clear optional return value */
	memset( algoIDparamPtr, 0, sizeof( ALGOID_PARAMS ) );

	/* Determine the algorithm information based on the AlgorithmIdentifier
	   field */
	if( tag == DEFAULT_TAG )
		readSequence( stream, &length );
	else
		readConstructed( stream, &length, tag );
	status = readEncodedOID( stream, oidBuffer, MAX_OID_SIZE, &oidLength, 
							 BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	length -= oidLength;

	/* Check that the OID length is valid */
	if( oidLength != sizeofOID( oidBuffer ) || \
		!isShortIntegerRange( length ) || oidLength < MIN_ALGOID_OID_SIZE )
		{
		/* It's a stream-related error, make it persistent */
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}

	/* Get the algorithm information for this OID */
	status = oidToAlgorithm( oidBuffer, oidLength, cryptAlgo, 
							 algoIDparamPtr, type );
	if( cryptStatusError( status ) ) 
		return( status );

	/* If the caller has specified that there should be no parameters 
	   present, make sure that there's either no data or an ASN.1 NULL 
	   present and nothing else */
	if( algoIDparams == NULL )
		{
		/* If there are no parameters then we're done */
		if( length <= 0 )
			return( CRYPT_OK );

		return( readNull( stream ) );
		}

	/* If the parameters are for a nonstandard encoding type, read them and 
	   exit */
#if defined( USE_OAEP ) || defined( USE_PSS )
	if( algoIDparamPtr->encodingType != ALGOID_ENCODING_NONE )
		return( readPKCSparams( stream, algoIDparamPtr ) );
#endif /* USE_OAEP || USE_PSS */

	/* If the parameters are null parameters, check them and exit */
	if( length == sizeofNull() )
		return( readNull( stream ) );

	/* Handle any remaining parameters */
	algoIDparamPtr->extraLength = length;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readAlgoIDInfo( INOUT_PTR STREAM *stream, 
						   INOUT_PTR QUERY_INFO *queryInfo,
						   IN_TAG const int tag,
						   IN_ENUM( ALGOID_CLASS ) \
								const ALGOID_CLASS_TYPE type )
	{
	ALGOID_PARAMS algoIDparams;
	const int startOffset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );
	REQUIRES_S( isEnumRange( type, ALGOID_CLASS ) );
	REQUIRES_S( isIntegerRange( startOffset ) );

	/* Read the AlgorithmIdentifier header and OID */
	status = readAlgoIDparams( stream, &queryInfo->cryptAlgo, &algoIDparams,
							   type, tag );
	if( cryptStatusError( status ) )
		return( status );
	if( isConvAlgo( queryInfo->cryptAlgo ) )
		{
		queryInfo->cryptMode = algoIDparams.cryptMode;
		queryInfo->keySize = algoIDparams.cryptKeySize;
		}
	else
		{
		if( isHashAlgo( queryInfo->cryptAlgo ) || \
			isMacAlgo( queryInfo->cryptAlgo ) )
			{
			queryInfo->hashParam = algoIDparams.hashParam;
			}
		}

	/* Some broken implementations use sign + hash algoIDs in places where
	   a hash algoID is called for, if we find one of these then we modify 
	   the read AlgorithmIdentifier information to make it look like a hash
	   algoID */
	if( isPkcAlgo( queryInfo->cryptAlgo ) && \
		isHashAlgo( algoIDparams.hashAlgo ) )
		{
		/* Turn pkcWithHash into hash */
		queryInfo->cryptAlgo = algoIDparams.hashAlgo;
		}

	/* Hash algorithms will either have NULL parameters or none at all
	   depending on which interpretation of which standard the sender used
	   so if it's not a conventional encryption algorithm then we process 
	   the NULL if required and return */
	if( isHashAlgo( queryInfo->cryptAlgo ) || \
		isMacAlgo( queryInfo->cryptAlgo ) )
		{
		return( ( algoIDparams.extraLength > 0 ) ? \
				readNull( stream ) : CRYPT_OK );
		}

	/* If it's not a hash/MAC algorithm then it has to be a conventional or
	   authenticated-encryption algorithm */
	if( !isConvAlgo( queryInfo->cryptAlgo ) && \
		!isSpecialAlgo( queryInfo->cryptAlgo ) )
		return( sSetError( stream, CRYPT_ERROR_NOTAVAIL ) );

	/* Read the conventional-encryption parameters */
	return( readCryptAlgoParams( stream, queryInfo, startOffset ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readAlgoID( INOUT_PTR STREAM *stream, 
				OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
				IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );

	REQUIRES_S( type == ALGOID_CLASS_HASH || type == ALGOID_CLASS_PKC || \
				type == ALGOID_CLASS_PKCSIG );

	return( readAlgoIDparams( stream, cryptAlgo, NULL, type, DEFAULT_TAG ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readAlgoIDexTag( INOUT_PTR STREAM *stream, 
					 OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
					 OUT_PTR ALGOID_PARAMS *algoIDparams,
					 IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type,
					 IN_TAG const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );
	REQUIRES_S( type == ALGOID_CLASS_HASH || type == ALGOID_CLASS_PKC || \
				type == ALGOID_CLASS_PKCSIG );

	return( readAlgoIDparams( stream, cryptAlgo, algoIDparams, type, tag ) );
	}

/* Read an AlgorithmIdentifier into a context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int readContextAlgoID( INOUT_PTR STREAM *stream, 
					   OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
					   OUT_OPT QUERY_INFO *queryInfo, 
					   IN_TAG const int tag,
					   IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type )
	{
	QUERY_INFO localQueryInfo, *queryInfoPtr = queryInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int mode, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( iCryptContext == NULL || \
			isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( queryInfo == NULL || \
			isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );
	REQUIRES_S( type == ALGOID_CLASS_CRYPT || type == ALGOID_CLASS_HASH || \
				type == ALGOID_CLASS_AUTHENC );

	/* Clear return value */
	if( iCryptContext != NULL )
		*iCryptContext = CRYPT_ERROR;

	/* If the user isn't interested in the algorithm details, use a local 
	   query structure to contain them */
	if( queryInfo == NULL )
		queryInfoPtr = &localQueryInfo;

	/* Clear optional return value */
	memset( queryInfoPtr, 0, sizeof( QUERY_INFO ) );

	/* Read the algorithm info */
	status = readAlgoIDInfo( stream, queryInfoPtr, tag, type );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're not creating a context from the algorithm info then we're 
	   done */
	if( iCryptContext == NULL )
		return( CRYPT_OK );

	/* Create the object from it */
	setMessageCreateObjectInfo( &createInfo, queryInfoPtr->cryptAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	if( isParameterisedHashAlgo( queryInfoPtr->cryptAlgo ) || \
		isParameterisedMacAlgo( queryInfoPtr->cryptAlgo ) )
		{
		/* It's a variable-width hash algorithm, set the output width */
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE, 
								  &queryInfoPtr->hashParam, 
								  CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( !isConvAlgo( queryInfoPtr->cryptAlgo ) )
		{
		/* If it's not a conventional encryption algorithm then we're 
		   done */
		*iCryptContext = createInfo.cryptHandle;

		return( CRYPT_OK );
		}
	mode = queryInfoPtr->cryptMode;	/* int vs.enum */
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &mode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) && \
		!isStreamCipher( queryInfoPtr->cryptAlgo ) )
		{
		MESSAGE_DATA msgData;

		/* It's a block cipher, set the IV */
		setMessageData( &msgData, queryInfoPtr->iv, 
						queryInfoPtr->ivLength );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_IV );
		}
	if( cryptStatusError( status ) )
		{
		/* If there's an error in the parameters stored with the key then 
		   we'll get an arg, attribute, or parameter error when we try to 
		   set the attribute so we translate it into an error code which is 
		   appropriate for the situation */
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptArgError( status ) || cryptParamError( status ) )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						AlgorithmIdentifier Write Routines					*
*																			*
****************************************************************************/

/* Write an AlgorithmIdentifier record */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeAlgoIDparams( INOUT_PTR STREAM *stream, 
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							  IN_PTR_OPT const ALGOID_PARAMS *algoIDparams,
							  IN_TAG const int tag  )
	{
	const BYTE *oid;
	int paramLength = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES_S( algoIDparams == NULL || \
				sanityCheckAlgoIDparams( cryptAlgo, algoIDparams ) );
	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );

	/* Map the algorithm parameters to an OID */
	oid = algorithmToOID( cryptAlgo, algoIDparams, ALGOTOOID_REQUIRE_VALID );
	REQUIRES_S( oid != NULL );

	/* Determine how long any optional additional parameter data will be */
	if( algoIDparams != NULL )
		{
		if( algoIDparams->extraLength > 0 )
			paramLength = algoIDparams->extraLength;
#if defined( USE_OAEP ) || defined( USE_PSS )
		else
			{
			if( algoIDparams->encodingType == ALGOID_ENCODING_OAEP || \
				algoIDparams->encodingType == ALGOID_ENCODING_PSS )
				{
				status = paramLength = \
							getPKCSparamSize( cryptAlgo, algoIDparams );
				if( cryptStatusError( status ) )
					return( status );
				}
			}
#endif /* USE_OAEP || USE_PSS */
		}

	/* If there aren't already parameters present and it's a non-PKC 
	   algorithm or RSA, add an unnecessary NULL, see the long comment in 
	   sizeofAlgoIDparams() for the reason behind this */
	if( paramLength == 0 && \
		( !isPkcAlgo( cryptAlgo ) || cryptAlgo == CRYPT_ALGO_RSA ) )
		paramLength = sizeofNull();

	/* Write the AlgorithmIdentifier field */
	if( tag != DEFAULT_TAG )
		writeConstructed( stream, sizeofOID( oid ) + paramLength, tag );
	else
		writeSequence( stream, sizeofOID( oid ) + paramLength );
	status = swrite( stream, oid, sizeofOID( oid ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Handle any optional additional parameter data */
	if( algoIDparams != NULL )
		{
		/* If there are explicit parameters present then they'll be written 
		   by the caller */
		if( algoIDparams->extraLength > 0 )
			return( CRYPT_OK );

		/* OAEP/PSS algoIDs have their own complex parameter sets */
#if defined( USE_OAEP ) || defined( USE_PSS )
		if( algoIDparams->encodingType == ALGOID_ENCODING_OAEP || \
			algoIDparams->encodingType == ALGOID_ENCODING_PSS ) 
			{
			return( writePKCSparams( stream, cryptAlgo, algoIDparams ) );
			}
#endif /* USE_OAEP || USE_PSS */

		/* It's an algorithm for which there's no further special-case 
		   handling required */
		ENSURES( ( algoIDparams->encodingType == ALGOID_ENCODING_NONE || \
				   algoIDparams->encodingType == ALGOID_ENCODING_PKCS1 ) && \
				 algoIDparams->extraLength == 0 );
		}

	/* Write an unnecessary NULL if required, see the comment above */
	if( paramLength > 0 )
		return( writeNull( stream, DEFAULT_TAG ) );
	
	return( CRYPT_OK );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoID( INOUT_PTR STREAM *stream, 
				 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
				 IN_TAG const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );

	return( writeAlgoIDparams( stream, cryptAlgo, NULL, tag ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeAlgoIDex( INOUT_PTR STREAM *stream, 
				   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
				   const ALGOID_PARAMS *algoIDparams,
				   IN_TAG const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES_S( isEnumRange( cryptAlgo, CRYPT_ALGO ) );
	REQUIRES_S( algoIDparams != NULL );
	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );

	return( writeAlgoIDparams( stream, cryptAlgo, algoIDparams, tag ) );
	}

/* Write an AlgorithmIdentifier record from a context */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeContextAlgoID( INOUT_PTR STREAM *stream, 
						IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	int algorithm, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isHandleRangeValid( iCryptContext ) );

	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	return( writeAlgoIDparams( stream, algorithm, NULL, DEFAULT_TAG ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeContextAlgoIDex( INOUT_PTR STREAM *stream, 
						  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						  const ALGOID_PARAMS *algoIDparams )
	{
	int algorithm, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES_S( isHandleRangeValid( iCryptContext ) );
	REQUIRES_S( algoIDparams != NULL );

	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	return( writeAlgoIDparams( stream, algorithm, algoIDparams,	
							   DEFAULT_TAG ) );
	}

/****************************************************************************
*																			*
*								ECC OID Routines							*
*																			*
****************************************************************************/

#if defined( USE_ECDH ) || defined( USE_ECDSA )

/* ECC curves are identified by OIDs, in order to map to and from these when 
   working with external representations of ECC parameters we need mapping 
   functions for the conversion */

static const OID_INFO eccOIDinfoTbl[] = {
	/* NIST P-256, X9.62 p256r1, SECG p256r1, 1 2 840 10045 3 1 7 */
	{ MKOID( "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07" ), CRYPT_ECCCURVE_P256 },
#ifdef USE_SHA2_EXT
	/* NIST P-384, SECG p384r1, 1 3 132 0 34 */
	{ MKOID( "\x06\x05\x2B\x81\x04\x00\x22" ), CRYPT_ECCCURVE_P384 },
	/* NIST P-521, SECG p521r1, 1 3 132 0 35 */
	{ MKOID( "\x06\x05\x2B\x81\x04\x00\x23" ), CRYPT_ECCCURVE_P521 },
#endif /* USE_SHA2_EXT */
	/* Brainpool p256r1, 1 3 36 3 3 2 8 1 1 7 */
	{ MKOID( "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07" ), CRYPT_ECCCURVE_BRAINPOOL_P256 },
	/* Brainpool p384r1, 1 3 36 3 3 2 8 1 1 11 */
	{ MKOID( "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0B" ), CRYPT_ECCCURVE_BRAINPOOL_P384 },
	/* Brainpool p512r1, 1 3 36 3 3 2 8 1 1 13 */
	{ MKOID( "\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0D" ), CRYPT_ECCCURVE_BRAINPOOL_P512 },
	{ NULL, 0 }, { NULL, 0 }
	};

CHECK_RETVAL \
static int getOIDinfo( const OID_INFO **oidInfoPtrPtr,
					   int *oidInfoNoEntries )
	{
#if CRYPTO_OBJECT_HANDLE != SYSTEM_OBJECT_HANDLE 
	MESSAGE_CATALOGQUERY_INFO catalogQueryInfo;
	int status;
#endif /* CRYPTO_OBJECT_HANDLE != SYSTEM_OBJECT_HANDLE */

	/* Clear return values */
	*oidInfoPtrPtr = NULL;
	*oidInfoNoEntries = 0;

	/* If we're using a custom crypto HAL, see if we need to override the 
	   built-in OIDs with custom ones */
#if CRYPTO_OBJECT_HANDLE != SYSTEM_OBJECT_HANDLE 
	setMessageCatalogQueryInfo( &catalogQueryInfo, CRYPT_FORMAT_CMS );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CATALOGQUERY, &catalogQueryInfo, 
							  CATALOGQUERY_ITEM_ECCINFO );
	if( cryptStatusOK( status ) )
		{
		*oidInfoPtrPtr = catalogQueryInfo.infoTable;
		*oidInfoNoEntries = catalogQueryInfo.infoNoEntries;

		return( CRYPT_OK );
		}
#endif /* CRYPTO_OBJECT_HANDLE != SYSTEM_OBJECT_HANDLE */

	*oidInfoPtrPtr = eccOIDinfoTbl;
	*oidInfoNoEntries = FAILSAFE_ARRAYSIZE( eccOIDinfoTbl, OID_INFO );

	return( CRYPT_OK );
	}

CHECK_RETVAL_LENGTH \
int sizeofECCOID( IN_ENUM( CRYPT_ECCCURVE ) \
					const CRYPT_ECCCURVE_TYPE curveType )
	{
	const OID_INFO *oidInfo;
	LOOP_INDEX i;
	int oidInfoSize, status;

	REQUIRES( isEnumRange( curveType, CRYPT_ECCCURVE ) );

	status = getOIDinfo( &oidInfo, &oidInfoSize );
	if( cryptStatusError( status ) )
		return( status );
	LOOP_SMALL( i = 0, 
				i < oidInfoSize && oidInfo[ i ].oid != NULL, 
				i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, oidInfoSize - 1 ) );

		if( oidInfo[ i ].selectionID == curveType )
			return( sizeofOID( oidInfo[ i ].oid ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < oidInfoSize );

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readECCOID( INOUT_PTR STREAM *stream, 
				OUT_OPT CRYPT_ECCCURVE_TYPE *curveType,
				OUT_INT_Z int *fieldSize )
	{
	const OID_INFO *oidInfo;
	int oidInfoSize, selectionID, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( curveType, sizeof( CRYPT_ECCCURVE_TYPE ) ) );

	/* Clear return values */
	*curveType = CRYPT_ECCCURVE_NONE;
	*fieldSize = CRYPT_ERROR;

	/* Read the ECC OID */
	status = getOIDinfo( &oidInfo, &oidInfoSize );
	if( cryptStatusError( status ) )
		return( status );
	status = readOID( stream, oidInfo, oidInfoSize, &selectionID );
	if( cryptStatusOK( status ) )
		status = getECCFieldSize( selectionID, fieldSize, FALSE );
	if( cryptStatusError( status ) )
		return( status );
	*curveType = selectionID;	/* enum vs.int */

	return( CRYPT_OK );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeECCOID( INOUT_PTR STREAM *stream, 
				 IN_ENUM( CRYPT_ECCCURVE ) \
					const CRYPT_ECCCURVE_TYPE curveType )
	{
	const OID_INFO *oidInfo;
	const BYTE *oid = NULL;
	LOOP_INDEX i;
	int oidInfoSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isEnumRange( curveType, CRYPT_ECCCURVE ) );

	status = getOIDinfo( &oidInfo, &oidInfoSize );
	if( cryptStatusError( status ) )
		return( sSetError( stream, status ) );
	LOOP_SMALL( i = 0, 
				i < oidInfoSize && oidInfo[ i ].oid != NULL, 
				i++ )
		{
		ENSURES_S( LOOP_INVARIANT_SMALL( i, 0, oidInfoSize - 1 ) );

		if( oidInfo[ i ].selectionID == curveType )
			{
			oid = oidInfo[ i ].oid;
			break;
			}
		}
	ENSURES_S( LOOP_BOUND_OK );
	ENSURES_S( i < oidInfoSize );
	ENSURES_S( oid != NULL );

	return( writeOID( stream, oid ) );
	}
#endif /* USE_ECDH || USE_ECDSA */

#endif /* USE_INT_ASN1 */
