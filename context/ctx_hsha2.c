/****************************************************************************
*																			*
*						cryptlib HMAC-SHA2 Hash Routines					*
*						Copyright Peter Gutmann 2004-2025					*
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

/* A structure to hold the initial and current MAC state info.  Rather than
   redoing the key processing each time when we're calculating multiple MACs
   with the same key, we just copy the initial state into the current state */

typedef struct {
	sha2_ctx macState, initialMacState;
	} SHA2_MAC_STATE;

#define SHA2_MAC_STATE_SIZE		sizeof( SHA2_MAC_STATE )

#ifndef SHA384_DIGEST_SIZE
  /* These may not be defined on non 64-bit systems */
  #define SHA384_DIGEST_SIZE			48
  #define SHA512_DIGEST_SIZE			64
  #define sha2_begin( size, ctx )		sha256_begin( ( ctx )->uu->ctx256 )
  #define sha2_hash( data, len, ctx )	sha256_hash( data, len, ( ctx )->uu->ctx256 )
  #define sha2_end( hash, ctx )			sha256_end( hash, ( ctx )->uu->ctx256 )
#endif /* SHA384_DIGEST_SIZE */

/****************************************************************************
*																			*
*							HMAC-SHA2 Self-test Routines					*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Test the HMAC-SHA2 output against the test vectors given in RFC 4231 */

typedef struct {
	const char *key;						/* HMAC key */
	const int keyLength;					/* Length of key */
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BYTE digest256[ SHA256_DIGEST_SIZE ];	/* Digest of data */
#ifdef USE_SHA2_EXT
	const BYTE digest384[ SHA384_DIGEST_SIZE ];	/* Digest of data */
	const BYTE digest512[ SHA512_DIGEST_SIZE ];	/* Digest of data */
#endif /* USE_SHA2_EXT */
	} HMAC_TESTINFO;
static const HMAC_TESTINFO hmacValues[] = {
	{ "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
	  "\x0B\x0B\x0B\x0B", 20,
	  "Hi There", 8,
	  { 0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53,
	    0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B, 0xF1, 0x2B,
		0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7,
		0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32, 0xCF, 0xF7 } 
#ifdef USE_SHA2_EXT
	  , /* SHA-384 */ 
	  { 0xAF, 0xD0, 0x39, 0x44, 0xD8, 0x48, 0x95, 0x62, 
		0x6B, 0x08, 0x25, 0xF4, 0xAB, 0x46, 0x90, 0x7F,
		0x15, 0xF9, 0xDA, 0xDB, 0xE4, 0x10, 0x1E, 0xC6, 
		0x82, 0xAA, 0x03, 0x4C, 0x7C, 0xEB, 0xC5, 0x9C,
		0xFA, 0xEA, 0x9E, 0xA9, 0x07, 0x6E, 0xDE, 0x7F, 
		0x4A, 0xF1, 0x52, 0xE8, 0xB2, 0xFA, 0x9C, 0xB6 },
	  /* SHA-512 */
	  { 0x87, 0xAA, 0x7C, 0xDE, 0xA5, 0xEF, 0x61, 0x9D, 
		0x4F, 0xF0, 0xB4, 0x24, 0x1A, 0x1D, 0x6C, 0xB0,
		0x23, 0x79, 0xF4, 0xE2, 0xCE, 0x4E, 0xC2, 0x78, 
		0x7A, 0xD0, 0xB3, 0x05, 0x45, 0xE1, 0x7C, 0xDE,
		0xDA, 0xA8, 0x33, 0xB7, 0xD6, 0xB8, 0xA7, 0x02, 
		0x03, 0x8B, 0x27, 0x4E, 0xAE, 0xA3, 0xF4, 0xE4,
		0xBE, 0x9D, 0x91, 0x4E, 0xEB, 0x61, 0xF1, 0x70, 
		0x2E, 0x69, 0x6C, 0x20, 0x3A, 0x12, 0x68, 0x54 }
#endif /* USE_SHA2_EXT */
	},
	{ "Jefe", 4,
		"what do ya want for nothing?", 28,
	  { 0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E,
	    0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xC7,
		0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83,
		0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC, 0x38, 0x43 }
#ifdef USE_SHA2_EXT
	  , /* SHA-384 */ 
	  { 0xAF, 0x45, 0xD2, 0xE3, 0x76, 0x48, 0x40, 0x31, 
		0x61, 0x7F, 0x78, 0xD2, 0xB5, 0x8A, 0x6B, 0x1B,
		0x9C, 0x7E, 0xF4, 0x64, 0xF5, 0xA0, 0x1B, 0x47, 
		0xE4, 0x2E, 0xC3, 0x73, 0x63, 0x22, 0x44, 0x5E,
		0x8E, 0x22, 0x40, 0xCA, 0x5E, 0x69, 0xE2, 0xC7, 
		0x8B, 0x32, 0x39, 0xEC, 0xFA, 0xB2, 0x16, 0x49 },
	  /* SHA-512 */
	  { 0x16, 0x4B, 0x7A, 0x7B, 0xFC, 0xF8, 0x19, 0xE2, 
		0xE3, 0x95, 0xFB, 0xE7, 0x3B, 0x56, 0xE0, 0xA3,
		0x87, 0xBD, 0x64, 0x22, 0x2E, 0x83, 0x1F, 0xD6, 
		0x10, 0x27, 0x0C, 0xD7, 0xEA, 0x25, 0x05, 0x54,
		0x97, 0x58, 0xBF, 0x75, 0xC0, 0x5A, 0x99, 0x4A, 
		0x6D, 0x03, 0x4F, 0x65, 0xF8, 0xF0, 0xE6, 0xFD,
		0xCA, 0xEA, 0xB1, 0xA3, 0x4D, 0x4A, 0x6B, 0x4B, 
		0x63, 0x6E, 0x07, 0x0A, 0x38, 0xBC, 0xE7, 0x37 }
#endif /* USE_SHA2_EXT */
	},
	{ "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA", 20,
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD", 50,
	  { 0x77, 0x3E, 0xA9, 0x1E, 0x36, 0x80, 0x0E, 0x46,
	    0x85, 0x4D, 0xB8, 0xEB, 0xD0, 0x91, 0x81, 0xA7,
		0x29, 0x59, 0x09, 0x8B, 0x3E, 0xF8, 0xC1, 0x22,
		0xD9, 0x63, 0x55, 0x14, 0xCE, 0xD5, 0x65, 0xFE }
#ifdef USE_SHA2_EXT
	  , /* SHA-384 */ 
	  { 0x88, 0x06, 0x26, 0x08, 0xD3, 0xE6, 0xAD, 0x8A, 
		0x0A, 0xA2, 0xAC, 0xE0, 0x14, 0xC8, 0xA8, 0x6F,
		0x0A, 0xA6, 0x35, 0xD9, 0x47, 0xAC, 0x9F, 0xEB, 
		0xE8, 0x3E, 0xF4, 0xE5, 0x59, 0x66, 0x14, 0x4B,
		0x2A, 0x5A, 0xB3, 0x9D, 0xC1, 0x38, 0x14, 0xB9, 
		0x4E, 0x3A, 0xB6, 0xE1, 0x01, 0xA3, 0x4F, 0x27 },
	  /* SHA-512 */
	  { 0xFA, 0x73, 0xB0, 0x08, 0x9D, 0x56, 0xA2, 0x84, 
		0xEF, 0xB0, 0xF0, 0x75, 0x6C, 0x89, 0x0B, 0xE9,
		0xB1, 0xB5, 0xDB, 0xDD, 0x8E, 0xE8, 0x1A, 0x36, 
		0x55, 0xF8, 0x3E, 0x33, 0xB2, 0x27, 0x9D, 0x39,
		0xBF, 0x3E, 0x84, 0x82, 0x79, 0xA7, 0x22, 0xC8, 
		0x06, 0xB4, 0x85, 0xA4, 0x7E, 0x67, 0xC8, 0x07,
		0xB9, 0x46, 0xA3, 0x37, 0xBE, 0xE8, 0x94, 0x26, 
		0x74, 0x27, 0x88, 0x59, 0xE1, 0x32, 0x92, 0xFB }
#endif /* USE_SHA2_EXT */
	},
	{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
	  "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD", 50,
	  { 0x82, 0x55, 0x8A, 0x38, 0x9A, 0x44, 0x3C, 0x0E,
	    0xA4, 0xCC, 0x81, 0x98, 0x99, 0xF2, 0x08, 0x3A,
		0x85, 0xF0, 0xFA, 0xA3, 0xE5, 0x78, 0xF8, 0x07,
		0x7A, 0x2E, 0x3F, 0xF4, 0x67, 0x29, 0x66, 0x5B }
#ifdef USE_SHA2_EXT
	  , /* SHA-384 */ 
	  { 0x3E, 0x8A, 0x69, 0xB7, 0x78, 0x3C, 0x25, 0x85, 
		0x19, 0x33, 0xAB, 0x62, 0x90, 0xAF, 0x6C, 0xA7,
		0x7A, 0x99, 0x81, 0x48, 0x08, 0x50, 0x00, 0x9C, 
		0xC5, 0x57, 0x7C, 0x6E, 0x1F, 0x57, 0x3B, 0x4E,
		0x68, 0x01, 0xDD, 0x23, 0xC4, 0xA7, 0xD6, 0x79, 
		0xCC, 0xF8, 0xA3, 0x86, 0xC6, 0x74, 0xCF, 0xFB },
	  /* SHA-512 */
	  { 0xB0, 0xBA, 0x46, 0x56, 0x37, 0x45, 0x8C, 0x69, 
		0x90, 0xE5, 0xA8, 0xC5, 0xF6, 0x1D, 0x4A, 0xF7,
		0xE5, 0x76, 0xD9, 0x7F, 0xF9, 0x4B, 0x87, 0x2D, 
		0xE7, 0x6F, 0x80, 0x50, 0x36, 0x1E, 0xE3, 0xDB,
		0xA9, 0x1C, 0xA5, 0xC1, 0x1A, 0xA2, 0x5E, 0xB4, 
		0xD6, 0x79, 0x27, 0x5C, 0xC5, 0x78, 0x80, 0x63,
		0xA5, 0xF1, 0x97, 0x41, 0x12, 0x0C, 0x4F, 0x2D, 
		0xE2, 0xAD, 0xEB, 0xEB, 0x10, 0xA2, 0x98, 0xDD }
#endif /* USE_SHA2_EXT */
	},
#if 0	/* Should be truncated to 128 bits - we don't do truncation */
	{ "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
	  "\x0C\x0C\x0C\x0C", 20,
	  "Test With Truncation", 20,
	  { 0xA3, 0xB6, 0x16, 0x74, 0x73, 0x10, 0x0E, 0xE0,
	    0x6E, 0x0C, 0x79, 0x6C, 0x29, 0x55, 0x55, 0x2B } },
#endif /* 0 */
	{ "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA", 131,
	  "Test Using Larger Than Block-Size Key - Hash Key First", 54,
	  { 0x60, 0xE4, 0x31, 0x59, 0x1E, 0xE0, 0xB6, 0x7F,
	    0x0D, 0x8A, 0x26, 0xAA, 0xCB, 0xF5, 0xB7, 0x7F,
		0x8E, 0x0B, 0xC6, 0x21, 0x37, 0x28, 0xC5, 0x14,
		0x05, 0x46, 0x04, 0x0F, 0x0E, 0xE3, 0x7F, 0x54 }
#ifdef USE_SHA2_EXT
	  , /* SHA-384 */ 
	  { 0x4E, 0xCE, 0x08, 0x44, 0x85, 0x81, 0x3E, 0x90, 
		0x88, 0xD2, 0xC6, 0x3A, 0x04, 0x1B, 0xC5, 0xB4,
		0x4F, 0x9E, 0xF1, 0x01, 0x2A, 0x2B, 0x58, 0x8F, 
		0x3C, 0xD1, 0x1F, 0x05, 0x03, 0x3A, 0xC4, 0xC6,
		0x0C, 0x2E, 0xF6, 0xAB, 0x40, 0x30, 0xFE, 0x82, 
		0x96, 0x24, 0x8D, 0xF1, 0x63, 0xF4, 0x49, 0x52 },
	  /* SHA-512 */
	  { 0x80, 0xB2, 0x42, 0x63, 0xC7, 0xC1, 0xA3, 0xEB, 
		0xB7, 0x14, 0x93, 0xC1, 0xDD, 0x7B, 0xE8, 0xB4,
		0x9B, 0x46, 0xD1, 0xF4, 0x1B, 0x4A, 0xEE, 0xC1, 
		0x12, 0x1B, 0x01, 0x37, 0x83, 0xF8, 0xF3, 0x52,
		0x6B, 0x56, 0xD0, 0x37, 0xE0, 0x5F, 0x25, 0x98, 
		0xBD, 0x0F, 0xD2, 0x21, 0x5D, 0x6A, 0x1E, 0x52,
		0x95, 0xE6, 0x4F, 0x73, 0xF6, 0x3F, 0x0A, 0xEC, 
		0x8B, 0x91, 0x5A, 0x98, 0x5D, 0x78, 0x65, 0x98 }
#endif /* USE_SHA2_EXT */
	},

	{ "", 0, NULL, 0, { 0 } }
	};

CHECK_RETVAL \
static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getHmacSHA2Capability();
	ALIGN_DATA( macState, SHA2_MAC_STATE_SIZE, 8 );
	void *macStatePtr = ALIGN_GET_PTR( macState, 8 );
	LOOP_INDEX i;
	int status;

	/* Test HMAC-SHA2 against the test vectors given in RFC 4231 */
	memset( macStatePtr, 0, SHA2_MAC_STATE_SIZE );	/* Keep static analysers happy */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( hmacValues, HMAC_TESTINFO ) && \
					hmacValues[ i ].data != NULL,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( hmacValues, \
														 HMAC_TESTINFO ) - 1 ) );
		status = testMAC( capabilityInfo, bitsToBytes( 256 ), macStatePtr, 
						  hmacValues[ i ].key, hmacValues[ i ].keyLength, 
						  hmacValues[ i ].data, hmacValues[ i ].length, 
						  hmacValues[ i ].digest256 );
		if( cryptStatusError( status ) )
			return( status );
#ifdef USE_SHA2_EXT
		status = testMAC( capabilityInfo, bitsToBytes( 384 ), macStatePtr, 
						  hmacValues[ i ].key, hmacValues[ i ].keyLength, 
						  hmacValues[ i ].data, hmacValues[ i ].length, 
						  hmacValues[ i ].digest384 );
		if( cryptStatusError( status ) )
			return( status );
		status = testMAC( capabilityInfo, bitsToBytes( 512 ), macStatePtr, 
						  hmacValues[ i ].key, hmacValues[ i ].keyLength, 
						  hmacValues[ i ].data, hmacValues[ i ].length, 
						  hmacValues[ i ].digest512 );
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
static int getInfo( IN_ENUM( CONTEXT_INFO ) const CONTEXT_INFO_TYPE type, 
					INOUT_PTR_OPT CONTEXT_INFO *contextInfoPtr,
					OUT_PTR void *data, 
					IN_INT_Z const int length )
	{
	assert( contextInfoPtr == NULL || \
			isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( length == 0 && isWritePtr( data, sizeof( int ) ) ) || \
			( length > 0 && isWritePtrDynamic( data, length ) ) );

	REQUIRES( isEnumRange( type, CONTEXT_INFO ) );
	REQUIRES( ( contextInfoPtr == NULL ) || \
			  sanityCheckContext( contextInfoPtr ) );

	if( type == CONTEXT_INFO_STATESIZE )
		{
		int *valuePtr = ( int * ) data;

		REQUIRES( length == sizeof( int ) );

		*valuePtr = SHA2_MAC_STATE_SIZE;

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, contextInfoPtr, data, length ) );
	}

/****************************************************************************
*																			*
*							HMAC-SHA2 Hash Routines							*
*																			*
****************************************************************************/

/* Perform the start of the inner hash using the zero-padded key XOR'd with 
   the ipad value.  We do this in a manner that tries to minimise timing 
   information that may reveal the length of the password, given the amount 
   of other stuff that's going on it's highly unlikely that this will ever 
   be an issue but we do it just in case */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int hmacBegin( sha2_ctx *sha2Info,
					  IN_LENGTH_HASH const int macParam,
					  IN_BUFFER( keyLength ) const void *key,
					  IN_LENGTH_SHORT const int keyLength )
	{
	BYTE hashBuffer[ SHA512_BLOCK_SIZE + 8 ];
	const int sha2BlockSize = ( macParam == bitsToBytes( 256 ) ) ? \
							  SHA256_BLOCK_SIZE : SHA512_BLOCK_SIZE;
							  /* -384 and -512 have the same block size */
	LOOP_INDEX i;

	assert( isWritePtr( sha2Info, sizeof( sha2_ctx ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( macParam == bitsToBytes( 256 ) || \
			  macParam == bitsToBytes( 384 ) || \
			  macParam == bitsToBytes( 512 ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, 4 ) );
			  /* The self-test uses very short keys */

	sha2_begin( macParam, sha2Info );
	REQUIRES( rangeCheck( keyLength, 1, SHA512_BLOCK_SIZE ) );
	memcpy( hashBuffer, key, keyLength );
	if( keyLength < sha2BlockSize )
		{
		REQUIRES( !checkOverflowSub( sha2BlockSize, keyLength ) );
		REQUIRES( rangeCheck( keyLength, 1, sha2BlockSize - 1 ) );
		memset( hashBuffer + keyLength, 0, sha2BlockSize - keyLength );
		}
	LOOP_LARGE( i = 0, i < sha2BlockSize, i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, sha2BlockSize - 1 ) );

		hashBuffer[ i ] ^= HMAC_IPAD;
		}
	ENSURES( LOOP_BOUND_OK );
	sha2_hash( hashBuffer, sha2BlockSize, sha2Info );
	zeroise( hashBuffer, SHA512_BLOCK_SIZE );

	return( CRYPT_OK );
	}

/* Wrap up the hashing and complete the outer hash */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int hmacEnd( sha2_ctx *sha2Info,
					IN_LENGTH_HASH const int macParam,
					IN_BUFFER( keyLength ) const void *key,
					IN_LENGTH_SHORT const int keyLength )
	{
	BYTE hashBuffer[ SHA512_BLOCK_SIZE + 8 ];
	BYTE digestBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	const int sha2BlockSize = ( macParam == bitsToBytes( 256 ) ) ? \
							  SHA256_BLOCK_SIZE : SHA512_BLOCK_SIZE;
							  /* -384 and -512 have the same block size */
	LOOP_INDEX i;

	assert( isWritePtr( sha2Info, sizeof( sha2_ctx ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( macParam == bitsToBytes( 256 ) || \
			  macParam == bitsToBytes( 384 ) || \
			  macParam == bitsToBytes( 512 ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, 4 ) );
			  /* The self-test uses very short keys */

	/* Complete the inner hash and extract the digest */
	sha2_end( digestBuffer, sha2Info );

	/* Perform the of the outer hash using the zero-padded key XOR'd with 
	   the opad value followed by the digest from the inner hash */
	memset( hashBuffer, HMAC_OPAD, sha2BlockSize );
	REQUIRES( rangeCheck( keyLength, 1, SHA512_BLOCK_SIZE ) );
	memcpy( hashBuffer, key, keyLength );
	LOOP_LARGE( i = 0, i < keyLength, i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, keyLength - 1 ) );

		hashBuffer[ i ] ^= HMAC_OPAD;
		}
	ENSURES( LOOP_BOUND_OK );
	sha2_begin( macParam, sha2Info );
	sha2_hash( hashBuffer, sha2BlockSize, sha2Info );
	zeroise( hashBuffer, sha2BlockSize );
	sha2_hash( digestBuffer, macParam, sha2Info );
	REQUIRES( rangeCheck( macParam, 1, CRYPT_MAX_HASHSIZE ) );
	zeroise( digestBuffer, macParam );

	return( CRYPT_OK );
	}

/* Hash data using HMAC-SHA2 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int hmac( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				IN_BUFFER( noBytes ) BYTE *buffer, 
				IN_LENGTH_Z int noBytes )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	MAC_INFO *macInfo = DATAPTR_GET_MAC( contextInfoPtr );
	sha2_ctx *sha2Info;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( noBytes == 0 || isReadPtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRange( noBytes ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( macInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	sha2Info = &( ( SHA2_MAC_STATE * ) macInfo->macInfo )->macState;

	/* If the hash state was reset to allow another round of MAC'ing, copy
	   the initial MAC state over into the current MAC state */
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED ) )
		{
		SHA2_MAC_STATE *macState = macInfo->macInfo;

		memcpy( &macState->macState, &macState->initialMacState,
				sizeof( sha2_ctx ) );
		}

	if( noBytes > 0 )
		sha2_hash( buffer, noBytes, sha2Info );
	else
		{
		/* Wrap up the MACing and extract the MAC value */
		status = hmacEnd( sha2Info, capabilityInfoPtr->blockSize,
						  macInfo->userKey, macInfo->userKeyLength );
		if( cryptStatusError( status ) )
			return( status );
		sha2_end( macInfo->mac, sha2Info );
		}

	return( CRYPT_OK );
	}

/* Internal API: MAC a single block of memory without the overhead of
   creating an encryption context */

STDC_NONNULL_ARG( ( 1, 4, 6 ) ) \
void sha2MacBufferAtomic( OUT_BUFFER_C( outBufMaxLength, 32 ) BYTE *outBuffer,
						  IN_LENGTH_SHORT_MIN( 32 ) const int outBufMaxLength,
						  IN_LENGTH_HASH_Z const int macParam,
						  IN_BUFFER( keyLength ) const void *key,
						  IN_LENGTH_SHORT_MIN( 16 ) const int keyLength,
						  IN_BUFFER( inLength ) const void *inBuffer,
						  IN_LENGTH_SHORT const int inLength )
	{
	sha2_ctx sha2Info;
	const int sha2BlockSize = ( macParam == bitsToBytes( 256 ) ) ? \
							  SHA256_BLOCK_SIZE : SHA512_BLOCK_SIZE;
							  /* -384 and -512 have the same block size */
	int status;

	assert( isWritePtrDynamic( outBuffer, outBufMaxLength ) && \
			outBufMaxLength >= 32 );
	assert( isReadPtrDynamic( key, keyLength ) );
	assert( isReadPtrDynamic( inBuffer, inLength ) );

	if( outBufMaxLength < macParam || 
		( macParam != bitsToBytes( 256 ) && \
		  macParam != bitsToBytes( 384 ) && \
		  macParam != bitsToBytes( 512 ) ) || \
		keyLength < 16 || keyLength > sha2BlockSize || \
		inLength <= 0 )
		retIntError_Void();

	/* Set up the HMAC key */
	sha2_begin( macParam, &sha2Info );
	status = hmacBegin( &sha2Info, macParam, key, keyLength );
	if( cryptStatusError( status ) )
		{
		REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
		memset( outBuffer, 0, outBufMaxLength );
		retIntError_Void();
		}

	/* MAC the data and wrap up the MACing */
	sha2_hash( inBuffer, inLength, &sha2Info );
	status = hmacEnd( &sha2Info, macParam, key, keyLength );
	if( cryptStatusError( status ) )
		{
		REQUIRES_V( isShortIntegerRangeNZ( outBufMaxLength ) );
		memset( outBuffer, 0, outBufMaxLength );
		retIntError_Void();
		}
	sha2_end( outBuffer, &sha2Info );

	zeroise( &sha2Info, sizeof( sha2_ctx ) );
	}

/****************************************************************************
*																			*
*						HMAC-SHA2 Key Management Routines					*
*																			*
****************************************************************************/

/* Set up an HMAC-SHA2 key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_BUFFER( keyLength ) const void *key, 
					IN_LENGTH_SHORT const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	MAC_INFO *macInfo = DATAPTR_GET_MAC( contextInfoPtr );
	sha2_ctx *sha2Info;
	int sha2DigestSize, sha2BlockSize, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, 4 ) );
			  /* The self-test uses very short keys */
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( macInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	sha2Info = &( ( SHA2_MAC_STATE * ) macInfo->macInfo )->macState;
	sha2DigestSize = capabilityInfoPtr->blockSize;
	sha2BlockSize = ( sha2DigestSize == bitsToBytes( 256 ) ) ? \
					  SHA256_BLOCK_SIZE : SHA512_BLOCK_SIZE;
					  /* -384 and -512 have the same block size */

	/* If the key size is larger than the SHA2 block size, reduce it to the
	   SHA2 hash size before processing it (yuck.  You're required to do this
	   though) */
	if( keyLength > sha2BlockSize )
		{
		/* Hash the user key down to the hash size (sha2_begin() has already
		   been called when the context was created) and use the hashed form
		   of the key */
		sha2_begin( sha2DigestSize, sha2Info );
		sha2_hash( ( void * ) key, keyLength, sha2Info );
		sha2_end( macInfo->userKey, sha2Info );
		macInfo->userKeyLength = sha2DigestSize;
		}
	else
		{
		/* Copy the key to internal storage.  The memset() is unnecessary 
		   but used to produce more or less constant timing across 
		   different key sizes */
		if( macInfo->userKey != key )
			{
			REQUIRES( rangeCheck( keyLength, 1, CRYPT_MAX_KEYSIZE ) );
			memcpy( macInfo->userKey, key, keyLength );
			if( keyLength < CRYPT_MAX_KEYSIZE )
				{
				REQUIRES( !checkOverflowSub( CRYPT_MAX_KEYSIZE, keyLength ) );
				REQUIRES( rangeCheck( keyLength, 1, 
									  CRYPT_MAX_KEYSIZE - 1 ) );
				memset( macInfo->userKey + keyLength, 0, 
						CRYPT_MAX_KEYSIZE - keyLength );
				}
			}
		macInfo->userKeyLength = keyLength;
		}

	/* Set up the HMAC key */
	status = hmacBegin( sha2Info, sha2DigestSize, macInfo->userKey, 
						macInfo->userKeyLength );
	if( cryptStatusError( status ) )
		return( status );
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED );

	/* Save a copy of the initial state in case it's needed later */
	memcpy( &( ( SHA2_MAC_STATE * ) macInfo->macInfo )->initialMacState, sha2Info,
			sizeof( sha2_ctx ) );

	return( CRYPT_OK );
	}

/* Initialise algorithm parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initParams( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   IN_ENUM( KEYPARAM ) const KEYPARAM_TYPE paramType,
					   IN_PTR_OPT const void *data, 
					   IN_INT const int dataLength )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_MAC );
	REQUIRES( isEnumRange( paramType, KEYPARAM ) );

	/* SHA-2 has a variable-length output, selectable by setting the 
	   blocksize attribute */
	if( paramType == KEYPARAM_BLOCKSIZE )
		{
#ifdef USE_SHA2_EXT
		static const CAPABILITY_INFO capabilityInfoHMACSHA384 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 384 ), "HMAC-SHA384", 11,
				bitsToBytes( 64 ), bitsToBytes( 128 ), CRYPT_MAX_KEYSIZE,
				selfTest, getInfo, NULL, NULL, initKey, NULL, hmac, hmac
				};
		static const CAPABILITY_INFO capabilityInfoHMACSHA512 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 512 ), "HMAC-SHA512", 11,
				bitsToBytes( 64 ), bitsToBytes( 128 ), CRYPT_MAX_KEYSIZE,
				selfTest, getInfo, NULL, NULL, initKey, NULL, hmac, hmac
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
							 ( void * ) &capabilityInfoHMACSHA384 );
				break;

			case SHA512_DIGEST_SIZE:
				DATAPTR_SET( contextInfoPtr->capabilityInfo, 
							 ( void * ) &capabilityInfoHMACSHA512 );
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
	CRYPT_ALGO_HMAC_SHA2, bitsToBytes( 256 ), "HMAC-SHA2", 9,
	MIN_KEYSIZE, bitsToBytes( 256 ), CRYPT_MAX_KEYSIZE,
	selfTest, getInfo, NULL, initParams, initKey, NULL, hmac, hmac
	};

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *getHmacSHA2Capability( void )
	{
	return( &capabilityInfo );
	}
