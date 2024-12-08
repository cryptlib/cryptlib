<<<<<<< HEAD
/****************************************************************************
*																			*
*							cryptlib SHA2 Hash Routines						*
*						Copyright Peter Gutmann 1999-2015					*
*																			*
****************************************************************************/

#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "sha2.h"
#else
  #include "context/context.h"
  #include "crypt/sha2.h"
#endif /* Compiler-specific includes */

#define SHA2_STATE_SIZE		sizeof( sha2_ctx )

#if defined( USE_SHA2_EXT ) && !defined( SHA512_DIGEST_SIZE )
  #error SHA2-384/512 can only be used on a system with 64-bit data type support
#endif /* Extended SHA-2 variants on system without 64-bit data type */

#ifndef SHA384_DIGEST_SIZE
  /* These may not be defined on non 64-bit systems.  The mapping of 
     sha256_begin() to sha2_begin() is a bit odd because the latter returns
	 a status while the former is a void function, so we fake out in the 
	 macro */
  #define SHA384_DIGEST_SIZE			48
  #define SHA512_DIGEST_SIZE			64
  #define sha2_begin( size, ctx )		sha256_begin( ( ctx )->uu->ctx256 ), EXIT_SUCCESS
  #define sha2_hash( data, len, ctx )	sha256_hash( data, len, ( ctx )->uu->ctx256 )
  #define sha2_end( hash, ctx )			sha256_end( hash, ( ctx )->uu->ctx256 )
#endif /* SHA384_DIGEST_SIZE */

/****************************************************************************
*																			*
*							SHA2 Self-test Routines							*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Test the SHA output against the test vectors given in FIPS 180-2.  Since
   hashing an empty string is a valid operation, we have to provide an 
   explicit isValid flag to tell the code when to stop.  We skip the third 
   test since this can take several seconds to execute on slower processors, 
   which leads to an unacceptable delay */

typedef struct {
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BOOLEAN isValid;					/* Whether entry is valid */
	const BYTE dig256[ SHA256_DIGEST_SIZE ];/* Digest of data */
	const BYTE dig384[ SHA384_DIGEST_SIZE ];/* Digest of data */
	const BYTE dig512[ SHA512_DIGEST_SIZE ];/* Digest of data */
	} DIGEST_TESTINFO;
static const DIGEST_TESTINFO digestValues[] = {
	{ NULL, 0, TRUE,
	  { 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 
		0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24, 
		0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 
		0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55 },
	  { 0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 
		0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A, 
		0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 
		0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA, 
		0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 
		0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B },
	  { 0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD, 
		0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6D, 0x80, 0x07, 
		0xD6, 0x20, 0xE4, 0x05, 0x0B, 0x57, 0x15, 0xDC, 
		0x83, 0xF4, 0xA9, 0x21, 0xD3, 0x6C, 0xE9, 0xCE, 
		0x47, 0xD0, 0xD1, 0x3C, 0x5D, 0x85, 0xF2, 0xB0, 
		0xFF, 0x83, 0x18, 0xD2, 0x87, 0x7E, 0xEC, 0x2F, 
		0x63, 0xB9, 0x31, 0xBD, 0x47, 0x41, 0x7A, 0x81, 
		0xA5, 0x38, 0x32, 0x7A, 0xF9, 0x27, 0xDA, 0x3E } 
	  },
	{ "abc", 3, TRUE,
	  { 0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
	    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
		0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
		0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD },
	  {	0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
		0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
		0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
		0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
		0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
		0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7 },
	  {	0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
		0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
		0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
		0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
		0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
		0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
		0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
		0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F }
		},
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, TRUE,
	  {	0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
	    0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
		0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
		0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 },
	  { 0x33, 0x91, 0xFD, 0xDD, 0xFC, 0x8D, 0xC7, 0x39,
		0x37, 0x07, 0xA6, 0x5B, 0x1B, 0x47, 0x09, 0x39,
		0x7C, 0xF8, 0xB1, 0xD1, 0x62, 0xAF, 0x05, 0xAB,
		0xFE, 0x8F, 0x45, 0x0D, 0xE5, 0xF3, 0x6B, 0xC6,
		0xB0, 0x45, 0x5A, 0x85, 0x20, 0xBC, 0x4E, 0x6F,
		0x5F, 0xE9, 0x5B, 0x1F, 0xE3, 0xC8, 0x45, 0x2B },
	  {	0x20, 0x4A, 0x8F, 0xC6, 0xDD, 0xA8, 0x2F, 0x0A,
		0x0C, 0xED, 0x7B, 0xEB, 0x8E, 0x08, 0xA4, 0x16,
		0x57, 0xC1, 0x6E, 0xF4, 0x68, 0xB2, 0x28, 0xA8,
		0x27, 0x9B, 0xE3, 0x31, 0xA7, 0x03, 0xC3, 0x35,
		0x96, 0xFD, 0x15, 0xC1, 0x3B, 0x1B, 0x07, 0xF9,
		0xAA, 0x1D, 0x3B, 0xEA, 0x57, 0x78, 0x9C, 0xA0,
		0x31, 0xAD, 0x85, 0xC7, 0xA7, 0x1D, 0xD7, 0x03,
		0x54, 0xEC, 0x63, 0x12, 0x38, 0xCA, 0x34, 0x45 }
		},
#if 0
	{ "aaaaa...", 1000000L, TRUE,
	  {	0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92,
	    0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
		0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E,
		0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0 },
	  {	0x9D, 0x0E, 0x18, 0x09, 0x71, 0x64, 0x74, 0xCB,
		0x08, 0x6E, 0x83, 0x4E, 0x31, 0x0A, 0x4A, 0x1C,
		0xED, 0x14, 0x9E, 0x9C, 0x00, 0xF2, 0x48, 0x52,
		0x79, 0x72, 0xCE, 0xC5, 0x70, 0x4C, 0x2A, 0x5B,
		0x07, 0xB8, 0xB3, 0xDC, 0x38, 0xEC, 0xC4, 0xEB,
		0xAE, 0x97, 0xDD, 0xD8, 0x7F, 0x3D, 0x89, 0x85 },
	  {	0xE7, 0x18, 0x48, 0x3D, 0x0C, 0xE7, 0x69, 0x64,
		0x4E, 0x2E, 0x42, 0xC7, 0xBC, 0x15, 0xB4, 0x63,
		0x8E, 0x1F, 0x98, 0xB1, 0x3B, 0x20, 0x44, 0x28,
		0x56, 0x32, 0xA8, 0x03, 0xAF, 0xA9, 0x73, 0xEB,
		0xDE, 0x0F, 0xF2, 0x44, 0x87, 0x7E, 0xA6, 0x0A,
		0x4C, 0xB0, 0x43, 0x2C, 0xE5, 0x77, 0xC3, 0x1B,
		0xEB, 0x00, 0x9C, 0x5C, 0x2C, 0x49, 0xAA, 0x2E,
		0x4E, 0xAD, 0xB2, 0x17, 0xAD, 0x8C, 0xC0, 0x9B } }
#endif
	{ NULL, 0, FALSE, { 0 }, { 0 }, { 0 } },
		{ NULL, 0, FALSE, { 0 }, { 0 }, { 0 } }
	};

CHECK_RETVAL \
static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getSHA2Capability();
	ALIGN_DATA( hashState, SHA2_STATE_SIZE, 8 );
	void *hashStatePtr = ALIGN_GET_PTR( hashState, 8 );
	LOOP_INDEX i;
	int status;

	/* SHA-2 requires the largest amount of context state so we check to
	   make sure that the HASHINFO is large enough.  Unfortunately the
	   terminology is a bit confusing here, HASHINFO is an opaque memory
	   block used to contain the low-level hash algorithm state, HASH_INFO
	   is the high-level hash info held inside a CONTEXT_INFO */
	assert( sizeof( HASHINFO ) >= SHA2_STATE_SIZE );

	memset( hashStatePtr, 0, SHA2_STATE_SIZE );	/* Keep static analysers happy */
	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( digestValues, DIGEST_TESTINFO ) && \
					digestValues[ i ].isValid,
				i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
									   FAILSAFE_ARRAYSIZE( digestValues, \
														   DIGEST_TESTINFO ) - 1 ) );

		status = testHash( capabilityInfo, SHA256_DIGEST_SIZE, hashStatePtr, 
						   digestValues[ i ].data, digestValues[ i ].length, 
						   digestValues[ i ].dig256 );
		if( cryptStatusError( status ) )
			return( status );
#ifdef USE_SHA2_EXT
		status = testHash( capabilityInfo, SHA384_DIGEST_SIZE, hashStatePtr, 
						   digestValues[ i ].data, digestValues[ i ].length, 
						   digestValues[ i ].dig384 );
		if( cryptStatusError( status ) )
			return( status );
		status = testHash( capabilityInfo, SHA512_DIGEST_SIZE, hashStatePtr, 
						   digestValues[ i ].data, digestValues[ i ].length, 
						   digestValues[ i ].dig512 );
		if( cryptStatusError( status ) )
			return( status );
#endif /* USE_SHA2_EXT */
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}
#else
	#define selfTest	NULL
#endif /* !CONFIG_NO_SELFTEST */

/****************************************************************************
*																			*
*								Control Routines							*
*																			*
****************************************************************************/

/* Return context subtype-specific information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int getInfo( IN_ENUM( CAPABILITY_INFO ) \
						const CAPABILITY_INFO_TYPE type, 
					INOUT_PTR_OPT CONTEXT_INFO *contextInfoPtr,
					OUT_PTR void *data, 
					IN_INT_Z const int length )
	{
	assert( contextInfoPtr == NULL || \
			isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( length == 0 && isWritePtr( data, sizeof( int ) ) ) || \
			( length > 0 && isWritePtrDynamic( data, length ) ) );

	REQUIRES( isEnumRange( type, CAPABILITY_INFO ) );
	REQUIRES( ( contextInfoPtr == NULL ) || \
			  sanityCheckContext( contextInfoPtr ) );

	if( type == CAPABILITY_INFO_STATESIZE )
		{
		int *valuePtr = ( int * ) data;

		*valuePtr = SHA2_STATE_SIZE;

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, contextInfoPtr, data, length ) );
	}

/****************************************************************************
*																			*
*								SHA Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using SHA */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int hash( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				 IN_BUFFER( noBytes ) BYTE *buffer, 
				 IN_LENGTH_Z int noBytes )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	sha2_ctx *shaInfo = ( sha2_ctx * ) contextInfoPtr->ctxHash->hashInfo;
#ifdef HAS_DEVCRYPTO
	const int hwCryptInfo = getSysVar( SYSVAR_HWCRYPT );
#endif /* HAS_DEVCRYPTO */

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( noBytes == 0 || isReadPtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRange( noBytes ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* If there's crypto hardware available, try and use that */
#ifdef HAS_DEVCRYPTO
	if( !cryptStatusError( hwCryptInfo ) && \
		( hwCryptInfo & HWCRYPT_FLAG_CRYPTDEV_SHA2 ) && \
		capabilityInfoPtr->blockSize == bitsToBytes( 256 ) )
		{
		int status = CRYPT_OK;

		if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
			status = hwCryptoInit( contextInfoPtr );
		if( cryptStatusOK( status ) )
			return( hwCryptoHash( contextInfoPtr, buffer, noBytes ) );
		}
#endif /* HAS_DEVCRYPTO */

	/* If the hash state was reset to allow another round of hashing,
	   reinitialise things */
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED ) )
		sha2_begin( capabilityInfoPtr->blockSize, shaInfo );

	if( noBytes > 0 )
		{
		sha2_hash( buffer, noBytes, shaInfo );
		}
	else
		{
		sha2_end( contextInfoPtr->ctxHash->hash, shaInfo );
		}

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context.*/

STDC_NONNULL_ARG( ( 1 ) ) \
void sha2HashBuffer( INOUT_PTR HASHINFO hashInfo,
					 OUT_BUFFER_OPT_C( outBufMaxLength, 32 ) BYTE *outBuffer,
					 IN_LENGTH_SHORT_Z const int outBufMaxLength,
					 IN_BUFFER_OPT( inLength ) const void *inBuffer,
					 IN_LENGTH_SHORT_Z const int inLength,
					 IN_ENUM( HASH_STATE ) const HASH_STATE_TYPE hashState )
	{
	sha2_ctx *shaInfo = ( sha2_ctx * ) hashInfo;
	
	assert( sizeof( HASHINFO ) >= SHA2_STATE_SIZE );
	assert( isWritePtr( hashInfo, sizeof( HASHINFO ) ) );
	assert( ( hashState != HASH_STATE_END && \
			  outBuffer == NULL && outBufMaxLength == 0 ) || \
			( hashState == HASH_STATE_END && \
			  isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			  outBufMaxLength >= 32 ) );
	assert( inBuffer == NULL || isReadPtrDynamic( inBuffer, inLength ) );

	if( ( hashState == HASH_STATE_END && outBufMaxLength < 32 ) || \
		( hashState != HASH_STATE_END && inLength <= 0 ) )
		retIntError_Void();

	switch( hashState )
		{
		case HASH_STATE_START:
			if( sha2_begin( SHA256_DIGEST_SIZE, shaInfo ) != EXIT_SUCCESS )
				{
				if( outBuffer != NULL )
					{
					REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
					memset( outBuffer, 0, outBufMaxLength );
					}
				retIntError_Void()
				}
			STDC_FALLTHROUGH;

		case HASH_STATE_CONTINUE:
			sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			break;

		case HASH_STATE_END:
			if( inBuffer != NULL )
				sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			sha2_end( outBuffer, shaInfo );
			break;

		default:
			retIntError_Void();
		}
	}

STDC_NONNULL_ARG( ( 1, 3 ) ) \
void sha2HashBufferAtomic( OUT_BUFFER_C( outBufMaxLength, 32 ) BYTE *outBuffer,
						   IN_LENGTH_SHORT_MIN( 32 ) const int outBufMaxLength,
						   IN_BUFFER( inLength ) const void *inBuffer,
						   IN_LENGTH_SHORT const int inLength )
	{
	sha2_ctx shaInfo;

	assert( isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			outBufMaxLength >= 32 );
	assert( isReadPtrDynamic( inBuffer, inLength ) );

	if( outBufMaxLength < 32 || inLength <= 0 )
		retIntError_Void();

	if( sha2_begin( SHA256_DIGEST_SIZE, &shaInfo ) != EXIT_SUCCESS )
		{
		REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
		memset( outBuffer, 0, outBufMaxLength );
		retIntError_Void();
		}
	sha2_hash( ( BYTE * ) inBuffer, inLength, &shaInfo );
	sha2_end( outBuffer, &shaInfo );
	zeroise( &shaInfo, sizeof( sha2_ctx ) );
	}

#ifdef USE_SHA2_EXT

#if defined( CONFIG_SUITEB )
  #define SHA2EXT_DIGEST_SIZE	SHA384_DIGEST_SIZE
#else
  #define SHA2EXT_DIGEST_SIZE	SHA512_DIGEST_SIZE
#endif /* Suite B vs. generic use */

STDC_NONNULL_ARG( ( 1 ) ) \
void sha2_ExtHashBuffer( INOUT_PTR HASHINFO hashInfo, 
						 OUT_BUFFER_OPT_C( outBufMaxLength, 64 ) BYTE *outBuffer, 
						 IN_LENGTH_SHORT_Z const int outBufMaxLength,
						 IN_BUFFER_OPT( inLength ) const void *inBuffer, 
						 IN_LENGTH_SHORT_Z const int inLength,
						 IN_ENUM( HASH_STATE ) const HASH_STATE_TYPE hashState )
	{
	sha2_ctx *shaInfo = ( sha2_ctx * ) hashInfo;

	assert( sizeof( HASHINFO ) >= SHA2_STATE_SIZE );
	assert( isWritePtr( hashInfo, sizeof( HASHINFO ) ) );
	assert( ( hashState != HASH_STATE_END && \
			  outBuffer == NULL && outBufMaxLength == 0 ) || \
			( hashState == HASH_STATE_END && \
			  isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			  outBufMaxLength >= SHA2EXT_DIGEST_SIZE ) );
	assert( inBuffer == NULL || isReadPtrDynamic( inBuffer, inLength ) );

	if( ( hashState == HASH_STATE_END && \
		  outBufMaxLength < SHA2EXT_DIGEST_SIZE ) || \
		( hashState != HASH_STATE_END && inLength <= 0 ) )
		retIntError_Void();

	switch( hashState )
		{
		case HASH_STATE_START:
			if( sha2_begin( SHA2EXT_DIGEST_SIZE, shaInfo ) != EXIT_SUCCESS )
				{
				REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
				memset( outBuffer, 0, outBufMaxLength );
				retIntError_Void()
				}
			STDC_FALLTHROUGH;

		case HASH_STATE_CONTINUE:
			sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			break;

		case HASH_STATE_END:
			if( inBuffer != NULL )
				sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			sha2_end( outBuffer, shaInfo );
			break;

		default:
			REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
			memset( outBuffer, 0, outBufMaxLength );
			retIntError_Void();
		}
	}

STDC_NONNULL_ARG( ( 1, 3 ) ) \
void sha2_ExtHashBufferAtomic( OUT_BUFFER_C( outBufMaxLength, 64 ) BYTE *outBuffer, 
							   IN_LENGTH_SHORT_MIN( 64 ) const int outBufMaxLength,
							   IN_BUFFER( inLength ) const void *inBuffer, 
							   IN_LENGTH_SHORT const int inLength )
	{
	sha2_ctx shaInfo;

	assert( isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			outBufMaxLength >= 64 );
	assert( isReadPtrDynamic( inBuffer, inLength ) );

	if( outBufMaxLength < 64 || inLength <= 0 )
		retIntError_Void();

	if( sha2_begin( SHA2EXT_DIGEST_SIZE, &shaInfo ) != EXIT_SUCCESS )
		{
		REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
		memset( outBuffer, 0, outBufMaxLength );
		retIntError_Void();
		}
	sha2_hash( ( BYTE * ) inBuffer, inLength, &shaInfo );
	sha2_end( outBuffer, &shaInfo );
	zeroise( &shaInfo, sizeof( sha2_ctx ) );
	}
#endif /* USE_SHA2_EXT */

/****************************************************************************
*																			*
*							SHA2 Key Management Routines					*
*																			*
****************************************************************************/

/* Initialise algorithm parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initParams( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   IN_ENUM( KEYPARAM ) const KEYPARAM_TYPE paramType,
					   IN_PTR_OPT const void *data, 
					   IN_INT const int dataLength )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_HASH );
	REQUIRES( isEnumRange( paramType, KEYPARAM ) );

	/* SHA-2 has a variable-length output, selectable by setting the 
	   blocksize attribute */
	if( paramType == KEYPARAM_BLOCKSIZE )
		{
#ifdef USE_SHA2_EXT
		static const CAPABILITY_INFO capabilityInfoSHA384 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 384 ), "SHA-384", 7,
				bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
				selfTest, getInfo, NULL, NULL, NULL, NULL, hash, hash
				};
		static const CAPABILITY_INFO capabilityInfoSHA512 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 512 ), "SHA-512", 7,
				bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
				selfTest, getInfo, NULL, NULL, NULL, NULL, hash, hash
				};

		/* Switch to the appropriate variant of SHA-2.  Note that the 
		   initParamsFunction pointer for this version is NULL rather than
		   pointing to this function, so once the output size has been set 
		   it can't be changed again */
		switch( dataLength )
			{
			case SHA256_DIGEST_SIZE:
				/* The default SHA-2 variant is SHA-256, so an attempt to 
				   set this size is a no-op */
				return( CRYPT_OK );

			case SHA384_DIGEST_SIZE:
				DATAPTR_SET( contextInfoPtr->capabilityInfo, 
							 ( void * ) &capabilityInfoSHA384 );
				break;

			case SHA512_DIGEST_SIZE:
				DATAPTR_SET( contextInfoPtr->capabilityInfo, 
							 ( void * ) &capabilityInfoSHA512 );
				break;

			default:
				return( CRYPT_ARGERROR_NUM1 );
			}
		return( CRYPT_OK );
#else
		/* The default SHA-2 variant is SHA-256, so an attempt to set this 
		   size is a no-op */
		return( ( dataLength == SHA256_DIGEST_SIZE ) ? \
				CRYPT_OK : CRYPT_ARGERROR_NUM1 );
#endif /* USE_SHA2_EXT */
		}

	/* Pass the call on down to the global parameter-handling function */	
	return( initGenericParams( contextInfoPtr, paramType, data, 
							   dataLength ) );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO capabilityInfo = {
	CRYPT_ALGO_SHA2, bitsToBytes( 256 ), "SHA-2", 5,
	bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
	selfTest, getInfo, NULL, initParams, NULL, NULL, hash, hash
	};

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *getSHA2Capability( void )
	{
	return( &capabilityInfo );
	}
=======
/****************************************************************************
*																			*
*							cryptlib SHA2 Hash Routines						*
*						Copyright Peter Gutmann 1999-2015					*
*																			*
****************************************************************************/

#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "sha2.h"
#else
  #include "context/context.h"
  #include "crypt/sha2.h"
#endif /* Compiler-specific includes */

#define SHA2_STATE_SIZE		sizeof( sha2_ctx )

#if defined( USE_SHA2_EXT ) && !defined( SHA512_DIGEST_SIZE )
  #error SHA2-384/512 can only be used on a system with 64-bit data type support
#endif /* Extended SHA-2 variants on system without 64-bit data type */

#ifndef SHA384_DIGEST_SIZE
  /* These may not be defined on non 64-bit systems.  The mapping of 
     sha256_begin() to sha2_begin() is a bit odd because the latter returns
	 a status while the former is a void function, so we fake out in the 
	 macro */
  #define SHA384_DIGEST_SIZE			48
  #define SHA512_DIGEST_SIZE			64
  #define sha2_begin( size, ctx )		sha256_begin( ( ctx )->uu->ctx256 ), EXIT_SUCCESS
  #define sha2_hash( data, len, ctx )	sha256_hash( data, len, ( ctx )->uu->ctx256 )
  #define sha2_end( hash, ctx )			sha256_end( hash, ( ctx )->uu->ctx256 )
#endif /* SHA384_DIGEST_SIZE */

/****************************************************************************
*																			*
*							SHA2 Self-test Routines							*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Test the SHA output against the test vectors given in FIPS 180-2.  Since
   hashing an empty string is a valid operation, we have to provide an 
   explicit isValid flag to tell the code when to stop.  We skip the third 
   test since this can take several seconds to execute on slower processors, 
   which leads to an unacceptable delay */

typedef struct {
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BOOLEAN isValid;					/* Whether entry is valid */
	const BYTE dig256[ SHA256_DIGEST_SIZE ];/* Digest of data */
	const BYTE dig384[ SHA384_DIGEST_SIZE ];/* Digest of data */
	const BYTE dig512[ SHA512_DIGEST_SIZE ];/* Digest of data */
	} DIGEST_TESTINFO;
static const DIGEST_TESTINFO digestValues[] = {
	{ NULL, 0, TRUE,
	  { 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 
		0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24, 
		0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 
		0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55 },
	  { 0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 
		0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A, 
		0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 
		0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA, 
		0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 
		0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B },
	  { 0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD, 
		0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6D, 0x80, 0x07, 
		0xD6, 0x20, 0xE4, 0x05, 0x0B, 0x57, 0x15, 0xDC, 
		0x83, 0xF4, 0xA9, 0x21, 0xD3, 0x6C, 0xE9, 0xCE, 
		0x47, 0xD0, 0xD1, 0x3C, 0x5D, 0x85, 0xF2, 0xB0, 
		0xFF, 0x83, 0x18, 0xD2, 0x87, 0x7E, 0xEC, 0x2F, 
		0x63, 0xB9, 0x31, 0xBD, 0x47, 0x41, 0x7A, 0x81, 
		0xA5, 0x38, 0x32, 0x7A, 0xF9, 0x27, 0xDA, 0x3E } 
	  },
	{ "abc", 3, TRUE,
	  { 0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
	    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
		0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
		0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD },
	  {	0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
		0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
		0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
		0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
		0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
		0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7 },
	  {	0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
		0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
		0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
		0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
		0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
		0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
		0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
		0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F }
		},
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, TRUE,
	  {	0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
	    0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
		0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
		0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 },
	  { 0x33, 0x91, 0xFD, 0xDD, 0xFC, 0x8D, 0xC7, 0x39,
		0x37, 0x07, 0xA6, 0x5B, 0x1B, 0x47, 0x09, 0x39,
		0x7C, 0xF8, 0xB1, 0xD1, 0x62, 0xAF, 0x05, 0xAB,
		0xFE, 0x8F, 0x45, 0x0D, 0xE5, 0xF3, 0x6B, 0xC6,
		0xB0, 0x45, 0x5A, 0x85, 0x20, 0xBC, 0x4E, 0x6F,
		0x5F, 0xE9, 0x5B, 0x1F, 0xE3, 0xC8, 0x45, 0x2B },
	  {	0x20, 0x4A, 0x8F, 0xC6, 0xDD, 0xA8, 0x2F, 0x0A,
		0x0C, 0xED, 0x7B, 0xEB, 0x8E, 0x08, 0xA4, 0x16,
		0x57, 0xC1, 0x6E, 0xF4, 0x68, 0xB2, 0x28, 0xA8,
		0x27, 0x9B, 0xE3, 0x31, 0xA7, 0x03, 0xC3, 0x35,
		0x96, 0xFD, 0x15, 0xC1, 0x3B, 0x1B, 0x07, 0xF9,
		0xAA, 0x1D, 0x3B, 0xEA, 0x57, 0x78, 0x9C, 0xA0,
		0x31, 0xAD, 0x85, 0xC7, 0xA7, 0x1D, 0xD7, 0x03,
		0x54, 0xEC, 0x63, 0x12, 0x38, 0xCA, 0x34, 0x45 }
		},
#if 0
	{ "aaaaa...", 1000000L, TRUE,
	  {	0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92,
	    0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
		0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E,
		0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0 },
	  {	0x9D, 0x0E, 0x18, 0x09, 0x71, 0x64, 0x74, 0xCB,
		0x08, 0x6E, 0x83, 0x4E, 0x31, 0x0A, 0x4A, 0x1C,
		0xED, 0x14, 0x9E, 0x9C, 0x00, 0xF2, 0x48, 0x52,
		0x79, 0x72, 0xCE, 0xC5, 0x70, 0x4C, 0x2A, 0x5B,
		0x07, 0xB8, 0xB3, 0xDC, 0x38, 0xEC, 0xC4, 0xEB,
		0xAE, 0x97, 0xDD, 0xD8, 0x7F, 0x3D, 0x89, 0x85 },
	  {	0xE7, 0x18, 0x48, 0x3D, 0x0C, 0xE7, 0x69, 0x64,
		0x4E, 0x2E, 0x42, 0xC7, 0xBC, 0x15, 0xB4, 0x63,
		0x8E, 0x1F, 0x98, 0xB1, 0x3B, 0x20, 0x44, 0x28,
		0x56, 0x32, 0xA8, 0x03, 0xAF, 0xA9, 0x73, 0xEB,
		0xDE, 0x0F, 0xF2, 0x44, 0x87, 0x7E, 0xA6, 0x0A,
		0x4C, 0xB0, 0x43, 0x2C, 0xE5, 0x77, 0xC3, 0x1B,
		0xEB, 0x00, 0x9C, 0x5C, 0x2C, 0x49, 0xAA, 0x2E,
		0x4E, 0xAD, 0xB2, 0x17, 0xAD, 0x8C, 0xC0, 0x9B } }
#endif
	{ NULL, 0, FALSE, { 0 }, { 0 }, { 0 } },
		{ NULL, 0, FALSE, { 0 }, { 0 }, { 0 } }
	};

CHECK_RETVAL \
static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getSHA2Capability();
	ALIGN_DATA( hashState, SHA2_STATE_SIZE, 8 );
	void *hashStatePtr = ALIGN_GET_PTR( hashState, 8 );
	LOOP_INDEX i;
	int status;

	/* SHA-2 requires the largest amount of context state so we check to
	   make sure that the HASHINFO is large enough.  Unfortunately the
	   terminology is a bit confusing here, HASHINFO is an opaque memory
	   block used to contain the low-level hash algorithm state, HASH_INFO
	   is the high-level hash info held inside a CONTEXT_INFO */
	assert( sizeof( HASHINFO ) >= SHA2_STATE_SIZE );

	memset( hashStatePtr, 0, SHA2_STATE_SIZE );	/* Keep static analysers happy */
	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( digestValues, DIGEST_TESTINFO ) && \
					digestValues[ i ].isValid,
				i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
									   FAILSAFE_ARRAYSIZE( digestValues, \
														   DIGEST_TESTINFO ) - 1 ) );

		status = testHash( capabilityInfo, SHA256_DIGEST_SIZE, hashStatePtr, 
						   digestValues[ i ].data, digestValues[ i ].length, 
						   digestValues[ i ].dig256 );
		if( cryptStatusError( status ) )
			return( status );
#ifdef USE_SHA2_EXT
		status = testHash( capabilityInfo, SHA384_DIGEST_SIZE, hashStatePtr, 
						   digestValues[ i ].data, digestValues[ i ].length, 
						   digestValues[ i ].dig384 );
		if( cryptStatusError( status ) )
			return( status );
		status = testHash( capabilityInfo, SHA512_DIGEST_SIZE, hashStatePtr, 
						   digestValues[ i ].data, digestValues[ i ].length, 
						   digestValues[ i ].dig512 );
		if( cryptStatusError( status ) )
			return( status );
#endif /* USE_SHA2_EXT */
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}
#else
	#define selfTest	NULL
#endif /* !CONFIG_NO_SELFTEST */

/****************************************************************************
*																			*
*								Control Routines							*
*																			*
****************************************************************************/

/* Return context subtype-specific information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int getInfo( IN_ENUM( CAPABILITY_INFO ) \
						const CAPABILITY_INFO_TYPE type, 
					INOUT_PTR_OPT CONTEXT_INFO *contextInfoPtr,
					OUT_PTR void *data, 
					IN_INT_Z const int length )
	{
	assert( contextInfoPtr == NULL || \
			isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( length == 0 && isWritePtr( data, sizeof( int ) ) ) || \
			( length > 0 && isWritePtrDynamic( data, length ) ) );

	REQUIRES( isEnumRange( type, CAPABILITY_INFO ) );
	REQUIRES( ( contextInfoPtr == NULL ) || \
			  sanityCheckContext( contextInfoPtr ) );

	if( type == CAPABILITY_INFO_STATESIZE )
		{
		int *valuePtr = ( int * ) data;

		*valuePtr = SHA2_STATE_SIZE;

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, contextInfoPtr, data, length ) );
	}

/****************************************************************************
*																			*
*								SHA Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using SHA */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int hash( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				 IN_BUFFER( noBytes ) BYTE *buffer, 
				 IN_LENGTH_Z int noBytes )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	sha2_ctx *shaInfo = ( sha2_ctx * ) contextInfoPtr->ctxHash->hashInfo;
#ifdef HAS_DEVCRYPTO
	const int hwCryptInfo = getSysVar( SYSVAR_HWCRYPT );
#endif /* HAS_DEVCRYPTO */

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( noBytes == 0 || isReadPtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRange( noBytes ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* If there's crypto hardware available, try and use that */
#ifdef HAS_DEVCRYPTO
	if( !cryptStatusError( hwCryptInfo ) && \
		( hwCryptInfo & HWCRYPT_FLAG_CRYPTDEV_SHA2 ) && \
		capabilityInfoPtr->blockSize == bitsToBytes( 256 ) )
		{
		int status = CRYPT_OK;

		if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
			status = hwCryptoInit( contextInfoPtr );
		if( cryptStatusOK( status ) )
			return( hwCryptoHash( contextInfoPtr, buffer, noBytes ) );
		}
#endif /* HAS_DEVCRYPTO */

	/* If the hash state was reset to allow another round of hashing,
	   reinitialise things */
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED ) )
		sha2_begin( capabilityInfoPtr->blockSize, shaInfo );

	if( noBytes > 0 )
		{
		sha2_hash( buffer, noBytes, shaInfo );
		}
	else
		{
		sha2_end( contextInfoPtr->ctxHash->hash, shaInfo );
		}

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context.*/

STDC_NONNULL_ARG( ( 1 ) ) \
void sha2HashBuffer( INOUT_PTR HASHINFO hashInfo,
					 OUT_BUFFER_OPT_C( outBufMaxLength, 32 ) BYTE *outBuffer,
					 IN_LENGTH_SHORT_Z const int outBufMaxLength,
					 IN_BUFFER_OPT( inLength ) const void *inBuffer,
					 IN_LENGTH_SHORT_Z const int inLength,
					 IN_ENUM( HASH_STATE ) const HASH_STATE_TYPE hashState )
	{
	sha2_ctx *shaInfo = ( sha2_ctx * ) hashInfo;
	
	assert( sizeof( HASHINFO ) >= SHA2_STATE_SIZE );
	assert( isWritePtr( hashInfo, sizeof( HASHINFO ) ) );
	assert( ( hashState != HASH_STATE_END && \
			  outBuffer == NULL && outBufMaxLength == 0 ) || \
			( hashState == HASH_STATE_END && \
			  isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			  outBufMaxLength >= 32 ) );
	assert( inBuffer == NULL || isReadPtrDynamic( inBuffer, inLength ) );

	if( ( hashState == HASH_STATE_END && outBufMaxLength < 32 ) || \
		( hashState != HASH_STATE_END && inLength <= 0 ) )
		retIntError_Void();

	switch( hashState )
		{
		case HASH_STATE_START:
			if( sha2_begin( SHA256_DIGEST_SIZE, shaInfo ) != EXIT_SUCCESS )
				{
				if( outBuffer != NULL )
					{
					REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
					memset( outBuffer, 0, outBufMaxLength );
					}
				retIntError_Void()
				}
			STDC_FALLTHROUGH;

		case HASH_STATE_CONTINUE:
			sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			break;

		case HASH_STATE_END:
			if( inBuffer != NULL )
				sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			sha2_end( outBuffer, shaInfo );
			break;

		default:
			retIntError_Void();
		}
	}

STDC_NONNULL_ARG( ( 1, 3 ) ) \
void sha2HashBufferAtomic( OUT_BUFFER_C( outBufMaxLength, 32 ) BYTE *outBuffer,
						   IN_LENGTH_SHORT_MIN( 32 ) const int outBufMaxLength,
						   IN_BUFFER( inLength ) const void *inBuffer,
						   IN_LENGTH_SHORT const int inLength )
	{
	sha2_ctx shaInfo;

	assert( isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			outBufMaxLength >= 32 );
	assert( isReadPtrDynamic( inBuffer, inLength ) );

	if( outBufMaxLength < 32 || inLength <= 0 )
		retIntError_Void();

	if( sha2_begin( SHA256_DIGEST_SIZE, &shaInfo ) != EXIT_SUCCESS )
		{
		REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
		memset( outBuffer, 0, outBufMaxLength );
		retIntError_Void();
		}
	sha2_hash( ( BYTE * ) inBuffer, inLength, &shaInfo );
	sha2_end( outBuffer, &shaInfo );
	zeroise( &shaInfo, sizeof( sha2_ctx ) );
	}

#ifdef USE_SHA2_EXT

#if defined( CONFIG_SUITEB )
  #define SHA2EXT_DIGEST_SIZE	SHA384_DIGEST_SIZE
#else
  #define SHA2EXT_DIGEST_SIZE	SHA512_DIGEST_SIZE
#endif /* Suite B vs. generic use */

STDC_NONNULL_ARG( ( 1 ) ) \
void sha2_ExtHashBuffer( INOUT_PTR HASHINFO hashInfo, 
						 OUT_BUFFER_OPT_C( outBufMaxLength, 64 ) BYTE *outBuffer, 
						 IN_LENGTH_SHORT_Z const int outBufMaxLength,
						 IN_BUFFER_OPT( inLength ) const void *inBuffer, 
						 IN_LENGTH_SHORT_Z const int inLength,
						 IN_ENUM( HASH_STATE ) const HASH_STATE_TYPE hashState )
	{
	sha2_ctx *shaInfo = ( sha2_ctx * ) hashInfo;

	assert( sizeof( HASHINFO ) >= SHA2_STATE_SIZE );
	assert( isWritePtr( hashInfo, sizeof( HASHINFO ) ) );
	assert( ( hashState != HASH_STATE_END && \
			  outBuffer == NULL && outBufMaxLength == 0 ) || \
			( hashState == HASH_STATE_END && \
			  isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			  outBufMaxLength >= SHA2EXT_DIGEST_SIZE ) );
	assert( inBuffer == NULL || isReadPtrDynamic( inBuffer, inLength ) );

	if( ( hashState == HASH_STATE_END && \
		  outBufMaxLength < SHA2EXT_DIGEST_SIZE ) || \
		( hashState != HASH_STATE_END && inLength <= 0 ) )
		retIntError_Void();

	switch( hashState )
		{
		case HASH_STATE_START:
			if( sha2_begin( SHA2EXT_DIGEST_SIZE, shaInfo ) != EXIT_SUCCESS )
				{
				REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
				memset( outBuffer, 0, outBufMaxLength );
				retIntError_Void()
				}
			STDC_FALLTHROUGH;

		case HASH_STATE_CONTINUE:
			sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			break;

		case HASH_STATE_END:
			if( inBuffer != NULL )
				sha2_hash( ( BYTE * ) inBuffer, inLength, shaInfo );
			sha2_end( outBuffer, shaInfo );
			break;

		default:
			REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
			memset( outBuffer, 0, outBufMaxLength );
			retIntError_Void();
		}
	}

STDC_NONNULL_ARG( ( 1, 3 ) ) \
void sha2_ExtHashBufferAtomic( OUT_BUFFER_C( outBufMaxLength, 64 ) BYTE *outBuffer, 
							   IN_LENGTH_SHORT_MIN( 64 ) const int outBufMaxLength,
							   IN_BUFFER( inLength ) const void *inBuffer, 
							   IN_LENGTH_SHORT const int inLength )
	{
	sha2_ctx shaInfo;

	assert( isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			outBufMaxLength >= 64 );
	assert( isReadPtrDynamic( inBuffer, inLength ) );

	if( outBufMaxLength < 64 || inLength <= 0 )
		retIntError_Void();

	if( sha2_begin( SHA2EXT_DIGEST_SIZE, &shaInfo ) != EXIT_SUCCESS )
		{
		REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
		memset( outBuffer, 0, outBufMaxLength );
		retIntError_Void();
		}
	sha2_hash( ( BYTE * ) inBuffer, inLength, &shaInfo );
	sha2_end( outBuffer, &shaInfo );
	zeroise( &shaInfo, sizeof( sha2_ctx ) );
	}
#endif /* USE_SHA2_EXT */

/****************************************************************************
*																			*
*							SHA2 Key Management Routines					*
*																			*
****************************************************************************/

/* Initialise algorithm parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initParams( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   IN_ENUM( KEYPARAM ) const KEYPARAM_TYPE paramType,
					   IN_PTR_OPT const void *data, 
					   IN_INT const int dataLength )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_HASH );
	REQUIRES( isEnumRange( paramType, KEYPARAM ) );

	/* SHA-2 has a variable-length output, selectable by setting the 
	   blocksize attribute */
	if( paramType == KEYPARAM_BLOCKSIZE )
		{
#ifdef USE_SHA2_EXT
		static const CAPABILITY_INFO capabilityInfoSHA384 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 384 ), "SHA-384", 7,
				bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
				selfTest, getInfo, NULL, NULL, NULL, NULL, hash, hash
				};
		static const CAPABILITY_INFO capabilityInfoSHA512 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 512 ), "SHA-512", 7,
				bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
				selfTest, getInfo, NULL, NULL, NULL, NULL, hash, hash
				};

		/* Switch to the appropriate variant of SHA-2.  Note that the 
		   initParamsFunction pointer for this version is NULL rather than
		   pointing to this function, so once the output size has been set 
		   it can't be changed again */
		switch( dataLength )
			{
			case SHA256_DIGEST_SIZE:
				/* The default SHA-2 variant is SHA-256, so an attempt to 
				   set this size is a no-op */
				return( CRYPT_OK );

			case SHA384_DIGEST_SIZE:
				DATAPTR_SET( contextInfoPtr->capabilityInfo, 
							 ( void * ) &capabilityInfoSHA384 );
				break;

			case SHA512_DIGEST_SIZE:
				DATAPTR_SET( contextInfoPtr->capabilityInfo, 
							 ( void * ) &capabilityInfoSHA512 );
				break;

			default:
				return( CRYPT_ARGERROR_NUM1 );
			}
		return( CRYPT_OK );
#else
		/* The default SHA-2 variant is SHA-256, so an attempt to set this 
		   size is a no-op */
		return( ( dataLength == SHA256_DIGEST_SIZE ) ? \
				CRYPT_OK : CRYPT_ARGERROR_NUM1 );
#endif /* USE_SHA2_EXT */
		}

	/* Pass the call on down to the global parameter-handling function */	
	return( initGenericParams( contextInfoPtr, paramType, data, 
							   dataLength ) );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO capabilityInfo = {
	CRYPT_ALGO_SHA2, bitsToBytes( 256 ), "SHA-2", 5,
	bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
	selfTest, getInfo, NULL, initParams, NULL, NULL, hash, hash
	};

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *getSHA2Capability( void )
	{
	return( &capabilityInfo );
	}
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
