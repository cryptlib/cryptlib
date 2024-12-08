<<<<<<< HEAD
/****************************************************************************
*																			*
*					cryptlib ChaCha20 Encryption Routines					*
*					  Copyright Peter Gutmann 2017-2020						*
*																			*
****************************************************************************/

#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "djb.h"
#else
  #include "context/context.h"
  #include "crypt/djb.h"
#endif /* Compiler-specific includes */

#ifdef USE_CHACHA20

/* The size of the ChaCha20 key and cipher block */

#define CHACHA20_KEY_SIZE		32
#define CHACHA20_IV_SIZE		16
#define CHACHA20_BLOCK_SIZE		64

/* The size of the ChaCha20 state.  Due to the fact that it's actually a 
   block cipher pretending to be a stream cipher, we have to store up to a
   block's worth of keystream alongside the cipher state, and the fact that 
   it has a 512-bit block size means there's a lot of state to store */

typedef struct {
	chacha_ctx keyInfo;
	BYTE keystream[ CHACHA20_BLOCK_SIZE + 8 ];
	int keystreamPos;
	} CHACHA20_STATE;

#define CHACHA20_STATE_SIZE		sizeof( CHACHA20_STATE )

/****************************************************************************
*																			*
*							ChaCha20 Self-test Routines						*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

typedef struct {
	const BOOLEAN isValid;
	const BYTE key[ CHACHA20_KEY_SIZE ];
	const BYTE nonce[ CHACHA20_IV_SIZE ];
	const BYTE keyStream[ CHACHA20_BLOCK_SIZE ];
	} CHACHA20_TEST;

/* ChaCha20 test vectors from draft-agl-tls-chacha20poly1305-04.  We can't
   use these because they use a 64-bit IV, not the weirdo 96:32 one 
   standardised by the IETF */

#if 0

static const CHACHA20_TEST testCHACHA20[] = {
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x76, 0xB8, 0xE0, 0xAD, 0xA0, 0xF1, 0x3D, 0x90,
		0x40, 0x5D, 0x6A, 0xE5, 0x53, 0x86, 0xBD, 0x28,
		0xBD, 0xD2, 0x19, 0xB8, 0xA0, 0x8D, 0xED, 0x1A,
		0xA8, 0x36, 0xEF, 0xCC, 0x8B, 0x77, 0x0D, 0xC7,
		0xDA, 0x41, 0x59, 0x7C, 0x51, 0x57, 0x48, 0x8D,
		0x77, 0x24, 0xE0, 0x3F, 0xB8, 0xD8, 0x4A, 0x37,
		0x6A, 0x43, 0xB8, 0xF4, 0x15, 0x18, 0xA1, 0x1C,
		0xC3, 0x87, 0xB6, 0x69, 0xB2, 0xEE, 0x65, 0x86 } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x45, 0x40, 0xF0, 0x5A, 0x9F, 0x1F, 0xB2, 0x96,
		0xD7, 0x73, 0x6E, 0x7B, 0x20, 0x8E, 0x3C, 0x96,
		0xEB, 0x4F, 0xE1, 0x83, 0x46, 0x88, 0xD2, 0x60,
		0x4F, 0x45, 0x09, 0x52, 0xED, 0x43, 0x2D, 0x41,
		0xBB, 0xE2, 0xA0, 0xB6, 0xEA, 0x75, 0x66, 0xD2,
		0xA5, 0xD1, 0xE7, 0xE2, 0x0D, 0x42, 0xAF, 0x2C,
		0x53, 0xD7, 0x92, 0xB1, 0xC4, 0x3F, 0xEA, 0x81,
		0x7E, 0x9A, 0xD2, 0x75, 0xAE, 0x54, 0x69, 0x63 } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  { 0xDE, 0x9C, 0xBA, 0x7B, 0xF3, 0xD6, 0x9E, 0xF5,
		0xE7, 0x86, 0xDC, 0x63, 0x97, 0x3F, 0x65, 0x3A,
		0x0B, 0x49, 0xE0, 0x15, 0xAD, 0xBF, 0xF7, 0x13,
		0x4F, 0xCB, 0x7D, 0xF1, 0x37, 0x82, 0x10, 0x31,
		0xE8, 0x5A, 0x05, 0x02, 0x78, 0xA7, 0x08, 0x45,
		0x27, 0x21, 0x4F, 0x73, 0xEF, 0xC7, 0xFA, 0x5B,
		0x52, 0x77, 0x06, 0x2E, 0xB7, 0xA0, 0x43, 0x3E,
		0x44, 0x5F, 0x41, 0xE3 /*, 0x	, 0x  , 0x	, 0x*/ } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0xEF, 0x3F, 0xDF, 0xD6, 0xC6, 0x15, 0x78, 0xFB,
		0xF5, 0xCF, 0x35, 0xBD, 0x3D, 0xD3, 0x3B, 0x80,
		0x09, 0x63, 0x16, 0x34, 0xD2, 0x1E, 0x42, 0xAC,
		0x33, 0x96, 0x0B, 0xD1, 0x38, 0xE5, 0x0D, 0x32,
		0x11, 0x1E, 0x4C, 0xAF, 0x23, 0x7E, 0xE5, 0x3C,
		0xA8, 0xAD, 0x64, 0x26, 0x19, 0x4A, 0x88, 0x54,
		0x5D, 0xDC, 0x49, 0x7A, 0x0B, 0x46, 0x6E, 0x7D,
		0x6B, 0xBD, 0xB0, 0x04, 0x1B, 0x2F, 0x58, 0x6B } },
	{ TRUE,
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
	  { 0xF7, 0x98, 0xA1, 0x89, 0xF1, 0x95, 0xE6, 0x69,
		0x82, 0x10, 0x5F, 0xFB, 0x64, 0x0B, 0xB7, 0x75,
		0x7F, 0x57, 0x9D, 0xA3, 0x16, 0x02, 0xFC, 0x93,
		0xEC, 0x01, 0xAC, 0x56, 0xF8, 0x5A, 0xC3, 0xC1,
		0x34, 0xA4, 0x54, 0x7B, 0x73, 0x3B, 0x46, 0x41,
		0x30, 0x42, 0xC9, 0x44, 0x00, 0x49, 0x17, 0x69,
		0x05, 0xD3, 0xBE, 0x59, 0xEA, 0x1C, 0x53, 0xF1,
		0x59, 0x16, 0x15, 0x5C, 0x2B, 0xE8, 0x24, 0x1A } }
	};
#endif /* 0 */

/* ChaCha20 test vectors from RFC 8439, the first from section 2.3.2, the
   remainder from Appendix A.2 */

static const CHACHA20_TEST testCHACHA20[] = {
	{ TRUE,
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
	  { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	    0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00 },
	  { 0x22, 0x4F, 0x51, 0xF3, 0x40, 0x1B, 0xD9, 0xE1, 
		0x2F, 0xDE, 0x27, 0x6F, 0xB8, 0x63, 0x1D, 0xED, 
		0x8C, 0x13, 0x1F, 0x82, 0x3D, 0x2C, 0x06, 0xE2, 
		0x7E, 0x4F, 0xCA, 0xEC, 0x9E, 0xF3, 0xCF, 0x78, 
		0x8A, 0x3B, 0x0A, 0xA3, 0x72, 0x60, 0x0A, 0x92, 
		0xB5, 0x79, 0x74, 0xCD, 0xED, 0x2B, 0x93, 0x34, 
		0x79, 0x4C, 0xBA, 0x40, 0xC6, 0x3E, 0x34, 0xCD, 
		0xEA, 0x21, 0x2C, 0x4C, 0xF0, 0x7D, 0x41, 0xB7 } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x76, 0xB8, 0xE0, 0xAD, 0xA0, 0xF1, 0x3D, 0x90, 
		0x40, 0x5D, 0x6A, 0xE5, 0x53, 0x86, 0xBD, 0x28,
		0xBD, 0xD2, 0x19, 0xB8, 0xA0, 0x8D, 0xED, 0x1A, 
		0xA8, 0x36, 0xEF, 0xCC, 0x8B, 0x77, 0x0D, 0xC7,
		0xDA, 0x41, 0x59, 0x7C, 0x51, 0x57, 0x48, 0x8D, 
		0x77, 0x24, 0xE0, 0x3F, 0xB8, 0xD8, 0x4A, 0x37,
		0x6A, 0x43, 0xB8, 0xF4, 0x15, 0x18, 0xA1, 0x1C, 
		0xC3, 0x87, 0xB6, 0x69, 0xB2, 0xEE, 0x65, 0x86 } },
	{ FALSE, { 0 }, { 0 }, { 0 } },
		{ FALSE, { 0 }, { 0 }, { 0 } }
	};

static const BYTE chacha20Key[] = {
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
	};
static const BYTE chacha20IV[] = {
	0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
	0x44, 0x45, 0x46, 0x47
	};
static const BYTE chacha20PT[] = {
	0x4C, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
	0x6E, 0x64, 0x20, 0x47, 0x65, 0x6E, 0x74, 0x6C,
	0x65, 0x6D, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x63, 0x6C, 0x61, 0x73,
	0x73, 0x20, 0x6F, 0x66, 0x20, 0x27, 0x39, 0x39,
	0x3A, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
	0x6F, 0x75, 0x6C, 0x64, 0x20, 0x6F, 0x66, 0x66,
	0x65, 0x72, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x6F,
	0x6E, 0x6C, 0x79, 0x20, 0x6F, 0x6E, 0x65, 0x20,
	0x74, 0x69, 0x70, 0x20, 0x66, 0x6F, 0x72, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
	0x72, 0x65, 0x2C, 0x20, 0x73, 0x75, 0x6E, 0x73,
	0x63, 0x72, 0x65, 0x65, 0x6E, 0x20, 0x77, 0x6F,
	0x75, 0x6C, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
	0x74, 0x2E
	};
static const BYTE chacha20CT[] = {
	0xD3, 0x1A, 0x8D, 0x34, 0x64, 0x8E, 0x60, 0xDB,
	0x7B, 0x86, 0xAF, 0xBC, 0x53, 0xEF, 0x7E, 0xC2,
	0xA4, 0xAD, 0xED, 0x51, 0x29, 0x6E, 0x08, 0xFE,
	0xA9, 0xE2, 0xB5, 0xA7, 0x36, 0xEE, 0x62, 0xD6,
	0x3D, 0xBE, 0xA4, 0x5E, 0x8C, 0xA9, 0x67, 0x12,
	0x82, 0xFA, 0xFB, 0x69, 0xDA, 0x92, 0x72, 0x8B,
	0x1A, 0x71, 0xDE, 0x0A, 0x9E, 0x06, 0x0B, 0x29,
	0x05, 0xD6, 0xA5, 0xB6, 0x7E, 0xCD, 0x3B, 0x36,
	0x92, 0xDD, 0xBD, 0x7F, 0x2D, 0x77, 0x8B, 0x8C,
	0x98, 0x03, 0xAE, 0xE3, 0x28, 0x09, 0x1B, 0x58,
	0xFA, 0xB3, 0x24, 0xE4, 0xFA, 0xD6, 0x75, 0x94,
	0x55, 0x85, 0x80, 0x8B, 0x48, 0x31, 0xD7, 0xBC,
	0x3F, 0xF4, 0xDE, 0xF0, 0x8E, 0x4B, 0x7A, 0x9D,
	0xE5, 0x76, 0xD2, 0x65, 0x86, 0xCE, 0xC6, 0x4B,
	0x61, 0x16
	};

static const BYTE poly1305Key[] = {
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
	};
static const BYTE poly1305Nonce[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07
	};
static const BYTE poly1305Output[] = {
	0x8A, 0xD5, 0xA0, 0x8B, 0x90, 0x5F, 0x81, 0xCC,
	0x81, 0x50, 0x40, 0x27, 0x4A, 0xB2, 0x94, 0x71,
	0xA8, 0x33, 0xB6, 0x37, 0xE3, 0xFD, 0x0D, 0xA5,
	0x08, 0xDB, 0xB8, 0xE2, 0xFD, 0xD1, 0xA6, 0x46
	};

/* Test the ChaCha20 code */

CHECK_RETVAL \
static int chacha20Test( IN_BUFFER_C( CHACHA20_KEY_SIZE ) const BYTE *key, 
						 IN_BUFFER_C( CHACHA20_IV_SIZE ) const BYTE *iv,
						 IN_BUFFER_OPT( length ) const BYTE *plaintext,
						 IN_BUFFER( length ) const BYTE *ciphertext, 
						 IN_LENGTH_SHORT const int length )
	{
	const CAPABILITY_INFO *capabilityInfo = getChaCha20Capability();
	CONTEXT_INFO contextInfo;
	CONV_INFO contextData;
	ALIGN_DATA( keyData, CHACHA20_STATE_SIZE, 16 );
	void *keyDataPtr = ALIGN_GET_PTR( keyData, 16 );
	BYTE temp[ ( CHACHA20_BLOCK_SIZE * 2 ) + 8 ];
	int status;

	assert( isReadPtr( key, CHACHA20_KEY_SIZE ) );
	assert( isReadPtr( iv, 8 ) );
	assert( plaintext == NULL || isReadPtrDynamic( ciphertext, length ) );
	assert( isReadPtrDynamic( ciphertext, length ) );

	REQUIRES( rangeCheck( length, 1, ( CHACHA20_BLOCK_SIZE * 2 ) ) );

	memset( keyDataPtr, 0, CHACHA20_STATE_SIZE );	/* Keep static analysers happy */
	status = staticInitContext( &contextInfo, CONTEXT_CONV, capabilityInfo,
								&contextData, sizeof( CONV_INFO ), 
								keyDataPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( plaintext != NULL )
		{
		REQUIRES( rangeCheck( length, 1, ( CHACHA20_BLOCK_SIZE * 2 ) ) );
		memcpy( temp, plaintext, length );
		}
	else
		memset( temp, 0, ( CHACHA20_BLOCK_SIZE * 2 ) );
	status = capabilityInfo->initKeyFunction( &contextInfo, key, 
											  CHACHA20_KEY_SIZE );
	if( cryptStatusOK( status ) )
		{
		/* Since ChaCha20 changes its keying state on every en/decrypt, the 
		   encryption function re-checksums the key data after the state has
		   been updated.  Normally the checksumming is handled by higher-
		   level code but since we're calling directly into internal 
		   functions we have to do it explicitly here */
		contextData.keyDataSize = CHACHA20_STATE_SIZE;
		contextData.keyDataChecksum = checksumData( contextData.key, 
													contextData.keyDataSize );
		status = capabilityInfo->initParamsFunction( &contextInfo, 
													 KEYPARAM_IV, 
													 iv, CHACHA20_IV_SIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfo->encryptCFBFunction( &contextInfo, temp,
													 length );
		}
	staticDestroyContext( &contextInfo );
	if( cryptStatusError( status ) || \
		memcmp( temp, ciphertext, length ) )
		return( CRYPT_ERROR_FAILED );

	return( CRYPT_OK );
	}

CHECK_RETVAL \
static int selfTest( void )
	{
	BYTE iv[ CHACHA20_IV_SIZE + 8 ];
	int i, LOOP_ITERATOR, status;

	/* Test the ChaCha20 algorithm */
	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( testCHACHA20, CHACHA20_TEST ) && \
					testCHACHA20[ i ].isValid,
				i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
									   FAILSAFE_ARRAYSIZE( testCHACHA20, \
														   CHACHA20_TEST ) - 1 ) );

		status = chacha20Test( testCHACHA20[i].key, testCHACHA20[ i ].nonce,
							   NULL, testCHACHA20[ i ].keyStream, 
							   CHACHA20_BLOCK_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	/* Test the ChaCha20 algorithm as used in ChaCha20-Poly1305 */
	REQUIRES( boundsCheck( bitsToBytes( 32 ), bitsToBytes( 96 ), 
			  CHACHA20_IV_SIZE ) );
	memcpy( iv, "\x01\x00\x00\x00", 4 );
	memcpy( iv + bitsToBytes( 32 ), chacha20IV, bitsToBytes( 96 ) );
	status = chacha20Test( chacha20Key, iv, chacha20PT, chacha20CT, 114 );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, test ChaCha20 when used for Poly1305 key generation */
	memset( iv, 0, CHACHA20_IV_SIZE );
	REQUIRES( boundsCheck( bitsToBytes( 32 ), bitsToBytes( 96 ), 
			  CHACHA20_IV_SIZE ) );
	memcpy( iv + bitsToBytes( 32 ), poly1305Nonce, bitsToBytes( 96 ) );
	return( chacha20Test( poly1305Key, iv, NULL, poly1305Output, 32 ) );
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
static int getInfo( IN_ENUM( CAPABILITY_INFO ) const CAPABILITY_INFO_TYPE type, 
					INOUT_PTR_OPT CONTEXT_INFO *contextInfoPtr,
					OUT_PTR void *data, 
					IN_INT_Z const int length )
	{
	int *valuePtr = ( int * ) data;

	assert( contextInfoPtr == NULL || \
			isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( length == 0 && isWritePtr( data, sizeof( int ) ) ) || \
			( length > 0 && isWritePtrDynamic( data, length ) ) );

	REQUIRES( isEnumRange( type, CAPABILITY_INFO ) );
	REQUIRES( ( contextInfoPtr == NULL ) || \
			  sanityCheckContext( contextInfoPtr ) );

	switch( type )
		{
		case CAPABILITY_INFO_STATESIZE:
			{
			*valuePtr = CHACHA20_STATE_SIZE;

			return( CRYPT_OK );
			}

		case CAPABILITY_INFO_STATEALIGNTYPE:
			{
			/* The ChaCha20 code requires alignment to 128-bit boundaries */
			*valuePtr = bitsToBytes( 128 );

			return( CRYPT_OK );
			}

		default:
			return( getDefaultInfo( type, contextInfoPtr, data, length ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*						ChaCha20 En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data.  Since ChaCha20 pretends to be a stream cipher, 
   encryption and decryption are the same operation.  However, it's actually
   a block cipher in counter mode, which means that using it as if it was a
   stream cipher doesn't work unless everything falls on block boundaries.  
   To deal with this we store the generated keystream in an internal buffer 
   and use that as required.
   
   We have to append the distinguisher 'Fn' to the name since some systems 
   already have 'encrypt' and 'decrypt' in their standard headers */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptFn( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					  INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					  IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	CHACHA20_STATE *stateInfo = convInfo->key;
	static const BYTE zeroes[ CHACHA20_BLOCK_SIZE ] = { 0 };

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	/* We're about to modify the keying data, make sure that it's still 
	   valid before we start */
	if( checksumData( convInfo->key, \
					  convInfo->keyDataSize ) != convInfo->keyDataChecksum )
		retIntError();

	while( noBytes > 0 )
		{
		int bytesToUse, i, LOOP_ITERATOR;

		ENSURES( rangeCheck( stateInfo->keystreamPos, 
							 0, CHACHA20_BLOCK_SIZE - 1 ) );

		/* If there's any keystream material left, use it now */
		if( stateInfo->keystreamPos > 0 )
			{
			/* Find out how much keystream material we can use */
			bytesToUse = CHACHA20_BLOCK_SIZE - stateInfo->keystreamPos;
			if( noBytes < bytesToUse )
				bytesToUse = noBytes;
			REQUIRES( rangeCheck( bytesToUse, 1, CHACHA20_BLOCK_SIZE ) );

			/* Encrypt the data */
			LOOP_LARGE( i = 0, i < bytesToUse, i++ )
				{
				ENSURES( LOOP_INVARIANT_LARGE( i, 0, bytesToUse - 1 ) );

				buffer[ i ] ^= \
					stateInfo->keystream[ i + stateInfo->keystreamPos ];
				}
			ENSURES( LOOP_BOUND_OK );

			/* Adjust the byte count and buffer position */
			noBytes -= bytesToUse;
			buffer += bytesToUse;
			stateInfo->keystreamPos += bytesToUse;

			/* If we've satisfied the request from the existing keystream, 
			   we're done */
			if( stateInfo->keystreamPos < CHACHA20_BLOCK_SIZE )
				break;

			/* We've consumed all of the keystream, reset the position 
			   indicator */
			stateInfo->keystreamPos = 0;

			/* If the remaining amount of keystream exactly filled the 
			   request, we're done */
			if( noBytes <= 0 )
				break;
			}

		/* Generate the next block of keystream */
		chacha20_encrypt_bytes( &stateInfo->keyInfo, zeroes, 
								stateInfo->keystream, CHACHA20_BLOCK_SIZE );

		/* Encrypt the data */
		bytesToUse = min( noBytes, CHACHA20_BLOCK_SIZE );
		LOOP_LARGE( i = 0, i < bytesToUse, i++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE( i, 0, bytesToUse - 1 ) );

			buffer[ i ] ^= stateInfo->keystream[ i ];
			}
		ENSURES( LOOP_BOUND_OK );
		noBytes -= bytesToUse;
		buffer += bytesToUse;

		/* If we've done the last block and there's any keystream left over,
		   remember what's left */
		if( noBytes <= 0 && bytesToUse < CHACHA20_BLOCK_SIZE )
			stateInfo->keystreamPos = bytesToUse;
		}

	/* This en/decryption process updates changes the key data, so we have 
	   to update the checksum before we return to the caller */
	convInfo->keyDataChecksum = checksumData( convInfo->key, 
											  convInfo->keyDataSize );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						ChaCha20 Key Management Routines					*
*																			*
****************************************************************************/

/* Initialise crypto parameters such as the IV/counter */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initParams( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   IN_ENUM( KEYPARAM ) const KEYPARAM_TYPE paramType,
					   IN_PTR_OPT const void *data, 
					   IN_INT const int dataLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const BYTE *dataPtr = data;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_CONV );
	REQUIRES( isEnumRange( paramType, KEYPARAM ) );

	if( paramType == KEYPARAM_IV )
		{
		CHACHA20_STATE *stateInfo = convInfo->key;

		ENSURES( dataLength == bitsToBytes( 128 ) );

		/* We're about to modify the keying data, make sure that it's still 
		   valid before we start.  Since ChaCha20 is an awkward algorithm 
		   that makes the IV part of the security-relevant cryptovariables, 
		   normally if we load a key and then set the IV these are already 
		   set up but if we load the IV first they aren't so we only do the
		   checksumming if they've been set up */
		if( convInfo->keyDataSize > 0 && \
			checksumData( convInfo->key, \
						  convInfo->keyDataSize ) != convInfo->keyDataChecksum )
			retIntError();

		/* Update the ChaCha20 state with the IV.  The original ChaCha20 
		   splits the 128-bit value 64:64 counter and IV, the IETF form 
		   changes the split to 32:96 counter and IV */
		chacha_ietf_ivsetup( &stateInfo->keyInfo, 
							 dataPtr + bitsToBytes( 32 ), dataPtr );

		/* Since we've now changed the IV, we also need to reset any stored
		   keystream */
		memset( stateInfo->keystream, 0, CHACHA20_BLOCK_SIZE );
		stateInfo->keystreamPos = 0;

		/* This process updates internal state which changes the key data 
		   checksum, so we have to update the checksum before we return to 
		   the caller */
		if( convInfo->keyDataSize > 0 )
			{
			convInfo->keyDataChecksum = checksumData( convInfo->key, 
													  convInfo->keyDataSize );
			}

		/* Fall through to load the IV into the context data */
		}

	/* Pass the call on down to the global parameter-handling function */	
	return( initGenericParams( contextInfoPtr, paramType, data, 
							   dataLength ) );
	}

/* Key schedule a ChaCha20 key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_BUFFER( keyLength ) const void *key, 
					IN_LENGTH_SHORT const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	CHACHA20_STATE *stateInfo = convInfo->key;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keyLength == CHACHA20_KEY_SIZE );

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		{
		REQUIRES( rangeCheck( keyLength, 1, CRYPT_MAX_KEYSIZE ) );
		memcpy( convInfo->userKey, key, keyLength );
		convInfo->userKeyLength = keyLength;
		}

	chacha_keysetup( &stateInfo->keyInfo, key );
	memset( stateInfo->keystream, 0, CHACHA20_BLOCK_SIZE );
	stateInfo->keystreamPos = 0;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO capabilityInfo = {
	CRYPT_ALGO_CHACHA20, bitsToBytes( 8 ), "ChaCha20", 8,
	CHACHA20_KEY_SIZE, CHACHA20_KEY_SIZE, CHACHA20_KEY_SIZE,
	selfTest, getInfo, NULL, initParams, initKey, NULL,
	NULL, NULL, NULL, NULL, encryptFn, encryptFn 
	};						/* Pseudo-CFB mode */

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *getChaCha20Capability( void )
	{
	return( &capabilityInfo );
	}
#endif /* USE_CHACHA20 */
=======
/****************************************************************************
*																			*
*					cryptlib ChaCha20 Encryption Routines					*
*					  Copyright Peter Gutmann 2017-2020						*
*																			*
****************************************************************************/

#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "djb.h"
#else
  #include "context/context.h"
  #include "crypt/djb.h"
#endif /* Compiler-specific includes */

#ifdef USE_CHACHA20

/* The size of the ChaCha20 key and cipher block */

#define CHACHA20_KEY_SIZE		32
#define CHACHA20_IV_SIZE		16
#define CHACHA20_BLOCK_SIZE		64

/* The size of the ChaCha20 state.  Due to the fact that it's actually a 
   block cipher pretending to be a stream cipher, we have to store up to a
   block's worth of keystream alongside the cipher state, and the fact that 
   it has a 512-bit block size means there's a lot of state to store */

typedef struct {
	chacha_ctx keyInfo;
	BYTE keystream[ CHACHA20_BLOCK_SIZE + 8 ];
	int keystreamPos;
	} CHACHA20_STATE;

#define CHACHA20_STATE_SIZE		sizeof( CHACHA20_STATE )

/****************************************************************************
*																			*
*							ChaCha20 Self-test Routines						*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

typedef struct {
	const BOOLEAN isValid;
	const BYTE key[ CHACHA20_KEY_SIZE ];
	const BYTE nonce[ CHACHA20_IV_SIZE ];
	const BYTE keyStream[ CHACHA20_BLOCK_SIZE ];
	} CHACHA20_TEST;

/* ChaCha20 test vectors from draft-agl-tls-chacha20poly1305-04.  We can't
   use these because they use a 64-bit IV, not the weirdo 96:32 one 
   standardised by the IETF */

#if 0

static const CHACHA20_TEST testCHACHA20[] = {
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x76, 0xB8, 0xE0, 0xAD, 0xA0, 0xF1, 0x3D, 0x90,
		0x40, 0x5D, 0x6A, 0xE5, 0x53, 0x86, 0xBD, 0x28,
		0xBD, 0xD2, 0x19, 0xB8, 0xA0, 0x8D, 0xED, 0x1A,
		0xA8, 0x36, 0xEF, 0xCC, 0x8B, 0x77, 0x0D, 0xC7,
		0xDA, 0x41, 0x59, 0x7C, 0x51, 0x57, 0x48, 0x8D,
		0x77, 0x24, 0xE0, 0x3F, 0xB8, 0xD8, 0x4A, 0x37,
		0x6A, 0x43, 0xB8, 0xF4, 0x15, 0x18, 0xA1, 0x1C,
		0xC3, 0x87, 0xB6, 0x69, 0xB2, 0xEE, 0x65, 0x86 } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x45, 0x40, 0xF0, 0x5A, 0x9F, 0x1F, 0xB2, 0x96,
		0xD7, 0x73, 0x6E, 0x7B, 0x20, 0x8E, 0x3C, 0x96,
		0xEB, 0x4F, 0xE1, 0x83, 0x46, 0x88, 0xD2, 0x60,
		0x4F, 0x45, 0x09, 0x52, 0xED, 0x43, 0x2D, 0x41,
		0xBB, 0xE2, 0xA0, 0xB6, 0xEA, 0x75, 0x66, 0xD2,
		0xA5, 0xD1, 0xE7, 0xE2, 0x0D, 0x42, 0xAF, 0x2C,
		0x53, 0xD7, 0x92, 0xB1, 0xC4, 0x3F, 0xEA, 0x81,
		0x7E, 0x9A, 0xD2, 0x75, 0xAE, 0x54, 0x69, 0x63 } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  { 0xDE, 0x9C, 0xBA, 0x7B, 0xF3, 0xD6, 0x9E, 0xF5,
		0xE7, 0x86, 0xDC, 0x63, 0x97, 0x3F, 0x65, 0x3A,
		0x0B, 0x49, 0xE0, 0x15, 0xAD, 0xBF, 0xF7, 0x13,
		0x4F, 0xCB, 0x7D, 0xF1, 0x37, 0x82, 0x10, 0x31,
		0xE8, 0x5A, 0x05, 0x02, 0x78, 0xA7, 0x08, 0x45,
		0x27, 0x21, 0x4F, 0x73, 0xEF, 0xC7, 0xFA, 0x5B,
		0x52, 0x77, 0x06, 0x2E, 0xB7, 0xA0, 0x43, 0x3E,
		0x44, 0x5F, 0x41, 0xE3 /*, 0x	, 0x  , 0x	, 0x*/ } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0xEF, 0x3F, 0xDF, 0xD6, 0xC6, 0x15, 0x78, 0xFB,
		0xF5, 0xCF, 0x35, 0xBD, 0x3D, 0xD3, 0x3B, 0x80,
		0x09, 0x63, 0x16, 0x34, 0xD2, 0x1E, 0x42, 0xAC,
		0x33, 0x96, 0x0B, 0xD1, 0x38, 0xE5, 0x0D, 0x32,
		0x11, 0x1E, 0x4C, 0xAF, 0x23, 0x7E, 0xE5, 0x3C,
		0xA8, 0xAD, 0x64, 0x26, 0x19, 0x4A, 0x88, 0x54,
		0x5D, 0xDC, 0x49, 0x7A, 0x0B, 0x46, 0x6E, 0x7D,
		0x6B, 0xBD, 0xB0, 0x04, 0x1B, 0x2F, 0x58, 0x6B } },
	{ TRUE,
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
	  { 0xF7, 0x98, 0xA1, 0x89, 0xF1, 0x95, 0xE6, 0x69,
		0x82, 0x10, 0x5F, 0xFB, 0x64, 0x0B, 0xB7, 0x75,
		0x7F, 0x57, 0x9D, 0xA3, 0x16, 0x02, 0xFC, 0x93,
		0xEC, 0x01, 0xAC, 0x56, 0xF8, 0x5A, 0xC3, 0xC1,
		0x34, 0xA4, 0x54, 0x7B, 0x73, 0x3B, 0x46, 0x41,
		0x30, 0x42, 0xC9, 0x44, 0x00, 0x49, 0x17, 0x69,
		0x05, 0xD3, 0xBE, 0x59, 0xEA, 0x1C, 0x53, 0xF1,
		0x59, 0x16, 0x15, 0x5C, 0x2B, 0xE8, 0x24, 0x1A } }
	};
#endif /* 0 */

/* ChaCha20 test vectors from RFC 8439, the first from section 2.3.2, the
   remainder from Appendix A.2 */

static const CHACHA20_TEST testCHACHA20[] = {
	{ TRUE,
	  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },
	  { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	    0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00 },
	  { 0x22, 0x4F, 0x51, 0xF3, 0x40, 0x1B, 0xD9, 0xE1, 
		0x2F, 0xDE, 0x27, 0x6F, 0xB8, 0x63, 0x1D, 0xED, 
		0x8C, 0x13, 0x1F, 0x82, 0x3D, 0x2C, 0x06, 0xE2, 
		0x7E, 0x4F, 0xCA, 0xEC, 0x9E, 0xF3, 0xCF, 0x78, 
		0x8A, 0x3B, 0x0A, 0xA3, 0x72, 0x60, 0x0A, 0x92, 
		0xB5, 0x79, 0x74, 0xCD, 0xED, 0x2B, 0x93, 0x34, 
		0x79, 0x4C, 0xBA, 0x40, 0xC6, 0x3E, 0x34, 0xCD, 
		0xEA, 0x21, 0x2C, 0x4C, 0xF0, 0x7D, 0x41, 0xB7 } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x76, 0xB8, 0xE0, 0xAD, 0xA0, 0xF1, 0x3D, 0x90, 
		0x40, 0x5D, 0x6A, 0xE5, 0x53, 0x86, 0xBD, 0x28,
		0xBD, 0xD2, 0x19, 0xB8, 0xA0, 0x8D, 0xED, 0x1A, 
		0xA8, 0x36, 0xEF, 0xCC, 0x8B, 0x77, 0x0D, 0xC7,
		0xDA, 0x41, 0x59, 0x7C, 0x51, 0x57, 0x48, 0x8D, 
		0x77, 0x24, 0xE0, 0x3F, 0xB8, 0xD8, 0x4A, 0x37,
		0x6A, 0x43, 0xB8, 0xF4, 0x15, 0x18, 0xA1, 0x1C, 
		0xC3, 0x87, 0xB6, 0x69, 0xB2, 0xEE, 0x65, 0x86 } },
	{ FALSE, { 0 }, { 0 }, { 0 } },
		{ FALSE, { 0 }, { 0 }, { 0 } }
	};

static const BYTE chacha20Key[] = {
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
	};
static const BYTE chacha20IV[] = {
	0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
	0x44, 0x45, 0x46, 0x47
	};
static const BYTE chacha20PT[] = {
	0x4C, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
	0x6E, 0x64, 0x20, 0x47, 0x65, 0x6E, 0x74, 0x6C,
	0x65, 0x6D, 0x65, 0x6E, 0x20, 0x6F, 0x66, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x63, 0x6C, 0x61, 0x73,
	0x73, 0x20, 0x6F, 0x66, 0x20, 0x27, 0x39, 0x39,
	0x3A, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
	0x6F, 0x75, 0x6C, 0x64, 0x20, 0x6F, 0x66, 0x66,
	0x65, 0x72, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x6F,
	0x6E, 0x6C, 0x79, 0x20, 0x6F, 0x6E, 0x65, 0x20,
	0x74, 0x69, 0x70, 0x20, 0x66, 0x6F, 0x72, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
	0x72, 0x65, 0x2C, 0x20, 0x73, 0x75, 0x6E, 0x73,
	0x63, 0x72, 0x65, 0x65, 0x6E, 0x20, 0x77, 0x6F,
	0x75, 0x6C, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
	0x74, 0x2E
	};
static const BYTE chacha20CT[] = {
	0xD3, 0x1A, 0x8D, 0x34, 0x64, 0x8E, 0x60, 0xDB,
	0x7B, 0x86, 0xAF, 0xBC, 0x53, 0xEF, 0x7E, 0xC2,
	0xA4, 0xAD, 0xED, 0x51, 0x29, 0x6E, 0x08, 0xFE,
	0xA9, 0xE2, 0xB5, 0xA7, 0x36, 0xEE, 0x62, 0xD6,
	0x3D, 0xBE, 0xA4, 0x5E, 0x8C, 0xA9, 0x67, 0x12,
	0x82, 0xFA, 0xFB, 0x69, 0xDA, 0x92, 0x72, 0x8B,
	0x1A, 0x71, 0xDE, 0x0A, 0x9E, 0x06, 0x0B, 0x29,
	0x05, 0xD6, 0xA5, 0xB6, 0x7E, 0xCD, 0x3B, 0x36,
	0x92, 0xDD, 0xBD, 0x7F, 0x2D, 0x77, 0x8B, 0x8C,
	0x98, 0x03, 0xAE, 0xE3, 0x28, 0x09, 0x1B, 0x58,
	0xFA, 0xB3, 0x24, 0xE4, 0xFA, 0xD6, 0x75, 0x94,
	0x55, 0x85, 0x80, 0x8B, 0x48, 0x31, 0xD7, 0xBC,
	0x3F, 0xF4, 0xDE, 0xF0, 0x8E, 0x4B, 0x7A, 0x9D,
	0xE5, 0x76, 0xD2, 0x65, 0x86, 0xCE, 0xC6, 0x4B,
	0x61, 0x16
	};

static const BYTE poly1305Key[] = {
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
	};
static const BYTE poly1305Nonce[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07
	};
static const BYTE poly1305Output[] = {
	0x8A, 0xD5, 0xA0, 0x8B, 0x90, 0x5F, 0x81, 0xCC,
	0x81, 0x50, 0x40, 0x27, 0x4A, 0xB2, 0x94, 0x71,
	0xA8, 0x33, 0xB6, 0x37, 0xE3, 0xFD, 0x0D, 0xA5,
	0x08, 0xDB, 0xB8, 0xE2, 0xFD, 0xD1, 0xA6, 0x46
	};

/* Test the ChaCha20 code */

CHECK_RETVAL \
static int chacha20Test( IN_BUFFER_C( CHACHA20_KEY_SIZE ) const BYTE *key, 
						 IN_BUFFER_C( CHACHA20_IV_SIZE ) const BYTE *iv,
						 IN_BUFFER_OPT( length ) const BYTE *plaintext,
						 IN_BUFFER( length ) const BYTE *ciphertext, 
						 IN_LENGTH_SHORT const int length )
	{
	const CAPABILITY_INFO *capabilityInfo = getChaCha20Capability();
	CONTEXT_INFO contextInfo;
	CONV_INFO contextData;
	ALIGN_DATA( keyData, CHACHA20_STATE_SIZE, 16 );
	void *keyDataPtr = ALIGN_GET_PTR( keyData, 16 );
	BYTE temp[ ( CHACHA20_BLOCK_SIZE * 2 ) + 8 ];
	int status;

	assert( isReadPtr( key, CHACHA20_KEY_SIZE ) );
	assert( isReadPtr( iv, 8 ) );
	assert( plaintext == NULL || isReadPtrDynamic( ciphertext, length ) );
	assert( isReadPtrDynamic( ciphertext, length ) );

	REQUIRES( rangeCheck( length, 1, ( CHACHA20_BLOCK_SIZE * 2 ) ) );

	memset( keyDataPtr, 0, CHACHA20_STATE_SIZE );	/* Keep static analysers happy */
	status = staticInitContext( &contextInfo, CONTEXT_CONV, capabilityInfo,
								&contextData, sizeof( CONV_INFO ), 
								keyDataPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( plaintext != NULL )
		{
		REQUIRES( rangeCheck( length, 1, ( CHACHA20_BLOCK_SIZE * 2 ) ) );
		memcpy( temp, plaintext, length );
		}
	else
		memset( temp, 0, ( CHACHA20_BLOCK_SIZE * 2 ) );
	status = capabilityInfo->initKeyFunction( &contextInfo, key, 
											  CHACHA20_KEY_SIZE );
	if( cryptStatusOK( status ) )
		{
		/* Since ChaCha20 changes its keying state on every en/decrypt, the 
		   encryption function re-checksums the key data after the state has
		   been updated.  Normally the checksumming is handled by higher-
		   level code but since we're calling directly into internal 
		   functions we have to do it explicitly here */
		contextData.keyDataSize = CHACHA20_STATE_SIZE;
		contextData.keyDataChecksum = checksumData( contextData.key, 
													contextData.keyDataSize );
		status = capabilityInfo->initParamsFunction( &contextInfo, 
													 KEYPARAM_IV, 
													 iv, CHACHA20_IV_SIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfo->encryptCFBFunction( &contextInfo, temp,
													 length );
		}
	staticDestroyContext( &contextInfo );
	if( cryptStatusError( status ) || \
		memcmp( temp, ciphertext, length ) )
		return( CRYPT_ERROR_FAILED );

	return( CRYPT_OK );
	}

CHECK_RETVAL \
static int selfTest( void )
	{
	BYTE iv[ CHACHA20_IV_SIZE + 8 ];
	int i, LOOP_ITERATOR, status;

	/* Test the ChaCha20 algorithm */
	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( testCHACHA20, CHACHA20_TEST ) && \
					testCHACHA20[ i ].isValid,
				i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
									   FAILSAFE_ARRAYSIZE( testCHACHA20, \
														   CHACHA20_TEST ) - 1 ) );

		status = chacha20Test( testCHACHA20[i].key, testCHACHA20[ i ].nonce,
							   NULL, testCHACHA20[ i ].keyStream, 
							   CHACHA20_BLOCK_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	/* Test the ChaCha20 algorithm as used in ChaCha20-Poly1305 */
	REQUIRES( boundsCheck( bitsToBytes( 32 ), bitsToBytes( 96 ), 
			  CHACHA20_IV_SIZE ) );
	memcpy( iv, "\x01\x00\x00\x00", 4 );
	memcpy( iv + bitsToBytes( 32 ), chacha20IV, bitsToBytes( 96 ) );
	status = chacha20Test( chacha20Key, iv, chacha20PT, chacha20CT, 114 );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, test ChaCha20 when used for Poly1305 key generation */
	memset( iv, 0, CHACHA20_IV_SIZE );
	REQUIRES( boundsCheck( bitsToBytes( 32 ), bitsToBytes( 96 ), 
			  CHACHA20_IV_SIZE ) );
	memcpy( iv + bitsToBytes( 32 ), poly1305Nonce, bitsToBytes( 96 ) );
	return( chacha20Test( poly1305Key, iv, NULL, poly1305Output, 32 ) );
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
static int getInfo( IN_ENUM( CAPABILITY_INFO ) const CAPABILITY_INFO_TYPE type, 
					INOUT_PTR_OPT CONTEXT_INFO *contextInfoPtr,
					OUT_PTR void *data, 
					IN_INT_Z const int length )
	{
	int *valuePtr = ( int * ) data;

	assert( contextInfoPtr == NULL || \
			isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( length == 0 && isWritePtr( data, sizeof( int ) ) ) || \
			( length > 0 && isWritePtrDynamic( data, length ) ) );

	REQUIRES( isEnumRange( type, CAPABILITY_INFO ) );
	REQUIRES( ( contextInfoPtr == NULL ) || \
			  sanityCheckContext( contextInfoPtr ) );

	switch( type )
		{
		case CAPABILITY_INFO_STATESIZE:
			{
			*valuePtr = CHACHA20_STATE_SIZE;

			return( CRYPT_OK );
			}

		case CAPABILITY_INFO_STATEALIGNTYPE:
			{
			/* The ChaCha20 code requires alignment to 128-bit boundaries */
			*valuePtr = bitsToBytes( 128 );

			return( CRYPT_OK );
			}

		default:
			return( getDefaultInfo( type, contextInfoPtr, data, length ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*						ChaCha20 En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data.  Since ChaCha20 pretends to be a stream cipher, 
   encryption and decryption are the same operation.  However, it's actually
   a block cipher in counter mode, which means that using it as if it was a
   stream cipher doesn't work unless everything falls on block boundaries.  
   To deal with this we store the generated keystream in an internal buffer 
   and use that as required.
   
   We have to append the distinguisher 'Fn' to the name since some systems 
   already have 'encrypt' and 'decrypt' in their standard headers */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptFn( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					  INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					  IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	CHACHA20_STATE *stateInfo = convInfo->key;
	static const BYTE zeroes[ CHACHA20_BLOCK_SIZE ] = { 0 };

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	/* We're about to modify the keying data, make sure that it's still 
	   valid before we start */
	if( checksumData( convInfo->key, \
					  convInfo->keyDataSize ) != convInfo->keyDataChecksum )
		retIntError();

	while( noBytes > 0 )
		{
		int bytesToUse, i, LOOP_ITERATOR;

		ENSURES( rangeCheck( stateInfo->keystreamPos, 
							 0, CHACHA20_BLOCK_SIZE - 1 ) );

		/* If there's any keystream material left, use it now */
		if( stateInfo->keystreamPos > 0 )
			{
			/* Find out how much keystream material we can use */
			bytesToUse = CHACHA20_BLOCK_SIZE - stateInfo->keystreamPos;
			if( noBytes < bytesToUse )
				bytesToUse = noBytes;
			REQUIRES( rangeCheck( bytesToUse, 1, CHACHA20_BLOCK_SIZE ) );

			/* Encrypt the data */
			LOOP_LARGE( i = 0, i < bytesToUse, i++ )
				{
				ENSURES( LOOP_INVARIANT_LARGE( i, 0, bytesToUse - 1 ) );

				buffer[ i ] ^= \
					stateInfo->keystream[ i + stateInfo->keystreamPos ];
				}
			ENSURES( LOOP_BOUND_OK );

			/* Adjust the byte count and buffer position */
			noBytes -= bytesToUse;
			buffer += bytesToUse;
			stateInfo->keystreamPos += bytesToUse;

			/* If we've satisfied the request from the existing keystream, 
			   we're done */
			if( stateInfo->keystreamPos < CHACHA20_BLOCK_SIZE )
				break;

			/* We've consumed all of the keystream, reset the position 
			   indicator */
			stateInfo->keystreamPos = 0;

			/* If the remaining amount of keystream exactly filled the 
			   request, we're done */
			if( noBytes <= 0 )
				break;
			}

		/* Generate the next block of keystream */
		chacha20_encrypt_bytes( &stateInfo->keyInfo, zeroes, 
								stateInfo->keystream, CHACHA20_BLOCK_SIZE );

		/* Encrypt the data */
		bytesToUse = min( noBytes, CHACHA20_BLOCK_SIZE );
		LOOP_LARGE( i = 0, i < bytesToUse, i++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE( i, 0, bytesToUse - 1 ) );

			buffer[ i ] ^= stateInfo->keystream[ i ];
			}
		ENSURES( LOOP_BOUND_OK );
		noBytes -= bytesToUse;
		buffer += bytesToUse;

		/* If we've done the last block and there's any keystream left over,
		   remember what's left */
		if( noBytes <= 0 && bytesToUse < CHACHA20_BLOCK_SIZE )
			stateInfo->keystreamPos = bytesToUse;
		}

	/* This en/decryption process updates changes the key data, so we have 
	   to update the checksum before we return to the caller */
	convInfo->keyDataChecksum = checksumData( convInfo->key, 
											  convInfo->keyDataSize );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						ChaCha20 Key Management Routines					*
*																			*
****************************************************************************/

/* Initialise crypto parameters such as the IV/counter */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initParams( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   IN_ENUM( KEYPARAM ) const KEYPARAM_TYPE paramType,
					   IN_PTR_OPT const void *data, 
					   IN_INT const int dataLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	const BYTE *dataPtr = data;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_CONV );
	REQUIRES( isEnumRange( paramType, KEYPARAM ) );

	if( paramType == KEYPARAM_IV )
		{
		CHACHA20_STATE *stateInfo = convInfo->key;

		ENSURES( dataLength == bitsToBytes( 128 ) );

		/* We're about to modify the keying data, make sure that it's still 
		   valid before we start.  Since ChaCha20 is an awkward algorithm 
		   that makes the IV part of the security-relevant cryptovariables, 
		   normally if we load a key and then set the IV these are already 
		   set up but if we load the IV first they aren't so we only do the
		   checksumming if they've been set up */
		if( convInfo->keyDataSize > 0 && \
			checksumData( convInfo->key, \
						  convInfo->keyDataSize ) != convInfo->keyDataChecksum )
			retIntError();

		/* Update the ChaCha20 state with the IV.  The original ChaCha20 
		   splits the 128-bit value 64:64 counter and IV, the IETF form 
		   changes the split to 32:96 counter and IV */
		chacha_ietf_ivsetup( &stateInfo->keyInfo, 
							 dataPtr + bitsToBytes( 32 ), dataPtr );

		/* Since we've now changed the IV, we also need to reset any stored
		   keystream */
		memset( stateInfo->keystream, 0, CHACHA20_BLOCK_SIZE );
		stateInfo->keystreamPos = 0;

		/* This process updates internal state which changes the key data 
		   checksum, so we have to update the checksum before we return to 
		   the caller */
		if( convInfo->keyDataSize > 0 )
			{
			convInfo->keyDataChecksum = checksumData( convInfo->key, 
													  convInfo->keyDataSize );
			}

		/* Fall through to load the IV into the context data */
		}

	/* Pass the call on down to the global parameter-handling function */	
	return( initGenericParams( contextInfoPtr, paramType, data, 
							   dataLength ) );
	}

/* Key schedule a ChaCha20 key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_BUFFER( keyLength ) const void *key, 
					IN_LENGTH_SHORT const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	CHACHA20_STATE *stateInfo = convInfo->key;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keyLength == CHACHA20_KEY_SIZE );

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		{
		REQUIRES( rangeCheck( keyLength, 1, CRYPT_MAX_KEYSIZE ) );
		memcpy( convInfo->userKey, key, keyLength );
		convInfo->userKeyLength = keyLength;
		}

	chacha_keysetup( &stateInfo->keyInfo, key );
	memset( stateInfo->keystream, 0, CHACHA20_BLOCK_SIZE );
	stateInfo->keystreamPos = 0;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO capabilityInfo = {
	CRYPT_ALGO_CHACHA20, bitsToBytes( 8 ), "ChaCha20", 8,
	CHACHA20_KEY_SIZE, CHACHA20_KEY_SIZE, CHACHA20_KEY_SIZE,
	selfTest, getInfo, NULL, initParams, initKey, NULL,
	NULL, NULL, NULL, NULL, encryptFn, encryptFn 
	};						/* Pseudo-CFB mode */

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *getChaCha20Capability( void )
	{
	return( &capabilityInfo );
	}
#endif /* USE_CHACHA20 */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
