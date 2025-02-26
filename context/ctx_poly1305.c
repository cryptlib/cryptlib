/****************************************************************************
*																			*
*						cryptlib Poly1305 MAC Routines						*
*						Copyright Peter Gutmann 2016-2018					*
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

#ifdef USE_POLY1305

/* The size of the Poly1305 key and MAC value */

#define POLY1305_KEY_SIZE			32
#define POLY1305_MAC_SIZE			16

/* A structure to hold the MAC state info */

typedef struct {
	poly1305_state_internal_t macState;
	} POLY1305_MAC_STATE;

#define POLY1305_MAC_STATE_SIZE		sizeof( POLY1305_MAC_STATE )

/****************************************************************************
*																			*
*							Poly1305 Self-test Routines						*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Test the Poly1305 output against the test vectors given in RFC 8439, the
   first from section xxx, the remainder from Appendix A.3 */

typedef struct {
	const BOOLEAN isValid;
	const BYTE key[ POLY1305_KEY_SIZE ];
	const char *data;
	const int length;
	const BYTE mac[ POLY1305_MAC_SIZE ];
	} POLY1305_TESTINFO;
static const POLY1305_TESTINFO testPoly1305[] = {
	{ TRUE,
	  { 0x85, 0xD6, 0xBE, 0x78, 0x57, 0x55, 0x6D, 0x33, 
		0x7F, 0x44, 0x52, 0xFE, 0x42, 0xD5, 0x06, 0xA8, 
		0x01, 0x03, 0x80, 0x8A, 0xFB, 0x0D, 0xB2, 0xFD, 
		0x4A, 0xBF, 0xF6, 0xAF, 0x41, 0x49, 0xF5, 0x1B }, 
	  "Cryptographic Forum Research Group", 34,
	  { 0xA8, 0x06, 0x1D, 0xC1, 0x30, 0x51, 0x36, 0xC6, 
		0xC2, 0x2B, 0x8B, 0xAF, 0x0C, 0x01, 0x27, 0xA9 } },
	{ TRUE,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 64,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	{ TRUE,
	  { 0x1C, 0x92, 0x40, 0xA5, 0xEB, 0x55, 0xD3, 0x8A, 
		0xF3, 0x33, 0x88, 0x86, 0x04, 0xF6, 0xB5, 0xF0,
		0x47, 0x39, 0x17, 0xC1, 0x40, 0x2B, 0x80, 0x09, 
		0x9D, 0xCA, 0x5C, 0xBC, 0x20, 0x70, 0x75, 0xC0 },
	  "\x27\x54\x77\x61\x73\x20\x62\x72\x69\x6C\x6C\x69\x67\x2C\x20\x61"
	  "\x6E\x64\x20\x74\x68\x65\x20\x73\x6C\x69\x74\x68\x79\x20\x74\x6F"
	  "\x76\x65\x73\x0A\x44\x69\x64\x20\x67\x79\x72\x65\x20\x61\x6E\x64"
	  "\x20\x67\x69\x6D\x62\x6C\x65\x20\x69\x6E\x20\x74\x68\x65\x20\x77"
	  "\x61\x62\x65\x3A\x0A\x41\x6C\x6C\x20\x6D\x69\x6D\x73\x79\x20\x77"
	  "\x65\x72\x65\x20\x74\x68\x65\x20\x62\x6F\x72\x6F\x67\x6F\x76\x65"
	  "\x73\x2C\x0A\x41\x6E\x64\x20\x74\x68\x65\x20\x6D\x6F\x6D\x65\x20"
	  "\x72\x61\x74\x68\x73\x20\x6F\x75\x74\x67\x72\x61\x62\x65\x2E", 127,
	  /* This corresponds to the following, but it doesn't produce the correct 
		 MAC in the ASCII form:
	  "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\n"
	  "All mimsy were the borogoves,\nAnd the momeraths outgrabe.", 127, */
	  { 0x45, 0x41, 0x66, 0x9A, 0x7E, 0xAA, 0xEE, 0x61, 
		0xE7, 0x08, 0xDC, 0x7C, 0xBC, 0xC5, 0xEB, 0x62 } },
	{ TRUE,
	  { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 16,
	  { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	{ TRUE,
	  { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
	  "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16,
	  { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	{ TRUE,
	  { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
	  "\xF0\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
	  "\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 48,
	  { 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	{ TRUE,
	  { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
	  "\xFB\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE"
	  "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", 48,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	{ TRUE,
	  { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  "\xFD\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 16,
	  { 0xFA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
	{ TRUE,
	  { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  "\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
	  "\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00"
	  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	  "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 64,
	  { 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	{ TRUE,
	  { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  "\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
	  "\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00"
	  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 48,
	  { 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	{ FALSE, { 0 }, NULL, 0, { 0 } },
		{ FALSE, { 0 }, NULL, 0, { 0 } }
	};

static const BYTE aeadData[] = {
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
static const BYTE aeadAAD[] = {
	0x50, 0x51, 0x52, 0x53, 0xC0, 0xC1, 0xC2, 0xC3,
	0xC4, 0xC5, 0xC6, 0xC7
	};
static const BYTE aeadKey[] = {
	0x7B, 0xAC, 0x2B, 0x25, 0x2D, 0xB4, 0x47, 0xAF,
	0x09, 0xB6, 0x7A, 0x55, 0xA4, 0xE9, 0x55, 0x84,
	0x0A, 0xE1, 0xD6, 0x73, 0x10, 0x75, 0xD9, 0xEB,
	0x2A, 0x93, 0x75, 0x78, 0x3E, 0xD5, 0x53, 0xFF
	};
static const BYTE aeadMAC[] = {
	0x1A, 0xE1, 0x0B, 0x59, 0x4F, 0x09, 0xE2, 0x6A,
	0x7E, 0x90, 0x2E, 0xCB, 0xD0, 0x60, 0x06, 0x91
	};

/* Test the Poly1305 code */

CHECK_RETVAL \
static int testAEAD( const CAPABILITY_INFO *capabilityInfo,
					 void *macStatePtr )
	{
	CONTEXT_INFO contextInfo;
	MAC_INFO contextData;
	static const BYTE zeroes[ 16 ] = { 0 };
	BYTE lengthBuffer[ 16 + 8 ];
	const int dataLength = 114, aadLength = 12;
	int aadPadLength, dataPadLength, status;

	assert( isReadPtr( capabilityInfo, sizeof( CAPABILITY_INFO ) ) );

	/* Instead of simply using the MAC as a MAC, the IETF came up with a 
	   weirdo construct with no purpose whatsoever (Procter's "A Security 
	   Analysis of the Composition of ChaCha20 and Poly1305" mentions it in
	   passing, but it plays no role in anything) but that makes calculating 
	   the MAC value unnecessarily awkward and complex.

	   Instead of MAC'ing the AAD and data as is, it has to be zero-padded 
	   to the nearest 16-byte boundary, and the padded data MAC'd.  However,
	   because this has added needless zero bytes to the data, additional
	   length values that specify the size of the original unpadded data 
	   have to be added to the end and MAC'd as well:

		"Once again, the Wellington Police have come up with a perfect 
		solution to the problem / That's right - by removing the solution we 
		had to another problem / The fact that if we hadn't put that sign up 
		in the first place none of this would've happened is irrelevant.  
		What matters is that we've identified the problem / That we caused /
		Job well done / Good result" 
			- "Wellington Paranormal".

	   For Bernstein cargo-cult purposes, the lengths are encoded as little-
	   endian integers rather than the standard big-endian form used in all
	   other IETF security protocols */
	aadPadLength = ( 16 - ( aadLength % 16 ) ) % 16;
	dataPadLength = ( 16 - ( dataLength % 16 ) ) % 16;
	memset( lengthBuffer, 0, 16 );
	lengthBuffer[ 0 ] = intToByte( aadLength );
	lengthBuffer[ 8 ] = intToByte( dataLength );
	lengthBuffer[ 9 ] = intToByte( dataLength >> 8 );

	/* MAC all of the little bits and pieces required to generate the AEAD 
	   MAC value */
	status = staticInitContext( &contextInfo, CONTEXT_MAC, capabilityInfo,
								&contextData, sizeof( MAC_INFO ), 
								macStatePtr );
	if( cryptStatusError( status ) )
		return( status );
	status = capabilityInfo->initKeyFunction( &contextInfo, 
											  aeadKey, POLY1305_KEY_SIZE );
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfo->encryptFunction( &contextInfo, 
												  ( void * ) aeadAAD, 
												  aadLength );
		SET_FLAG( contextInfo.flags, CONTEXT_FLAG_HASH_INITED );
		}
	if( cryptStatusOK( status ) )
		{
		capabilityInfo->encryptFunction( &contextInfo, ( void * ) zeroes, 
										 aadPadLength );
		capabilityInfo->encryptFunction( &contextInfo, ( void * ) aeadData, 
										 dataLength );
		capabilityInfo->encryptFunction( &contextInfo, ( void * ) zeroes, 
										 dataPadLength );
		capabilityInfo->encryptFunction( &contextInfo, lengthBuffer, 16 );
		status = capabilityInfo->encryptFunction( &contextInfo, 
												  MKDATA( "" ), 0 );
		}
	if( cryptStatusOK( status ) && \
		memcmp( contextInfo.ctxMAC->mac, aeadMAC, POLY1305_MAC_SIZE ) )
		status = CRYPT_ERROR_FAILED;
	staticDestroyContext( &contextInfo );

	return( status );
	}

CHECK_RETVAL \
static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getPoly1305Capability();
	ALIGN_DATA( macState, POLY1305_MAC_STATE_SIZE, 8 );
	void *macStatePtr = ALIGN_GET_PTR( macState, 8 );
	LOOP_INDEX i;
	int status;

	/* Test Poly1305 against the test vectors given in RFC 8439 */
	memset( macStatePtr, 0, POLY1305_MAC_STATE_SIZE );	/* Keep static analysers happy */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( testPoly1305, POLY1305_TESTINFO ) && \
					testPoly1305[ i ].data != NULL,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( testPoly1305, \
														 POLY1305_TESTINFO ) - 1 ) );
		status = testMAC( capabilityInfo, macStatePtr, 
						  testPoly1305[ i ].key, POLY1305_KEY_SIZE,
						  testPoly1305[ i ].data, testPoly1305[ i ].length, 
						  testPoly1305[ i ].mac );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	/* Finally, test the Poly1305 part of the weirdo AEAD mechanism the IETF 
	   dreamed up use with ChaCha20 */
	return( testAEAD( capabilityInfo, macStatePtr ) );
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

		*valuePtr = POLY1305_MAC_STATE_SIZE;

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, contextInfoPtr, data, length ) );
	}

/****************************************************************************
*																			*
*							Poly1305 Hash Routines							*
*																			*
****************************************************************************/

/* MAC data using Poly1305 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int hash( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				 IN_BUFFER( noBytes ) BYTE *buffer, 
				 IN_LENGTH_Z int noBytes )
	{
	MAC_INFO *macInfo = contextInfoPtr->ctxMAC;
	POLY1305_MAC_STATE *poly1305Info = macInfo->macInfo;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( noBytes == 0 || isReadPtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRange( noBytes ) );

	/* If the hash state was reset to allow another round of MAC'ing, 
	   reinitialise the MAC state from the key */
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED ) )
		{
		poly1305_init( &poly1305Info->macState, macInfo->userKey );
		}

	if( noBytes > 0 )
		poly1305_update( &poly1305Info->macState, buffer, noBytes );
	else
		poly1305_finish( &poly1305Info->macState, macInfo->mac );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Poly1305 Key Management Routines				*
*																			*
****************************************************************************/

/* Set up a Poly1305 key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_BUFFER( keyLength ) const void *key, 
					IN_LENGTH_SHORT const int keyLength )
	{
	MAC_INFO *macInfo = contextInfoPtr->ctxMAC;
	POLY1305_MAC_STATE *poly1305Info = macInfo->macInfo;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keyLength == POLY1305_KEY_SIZE );

	/* Copy the key to internal storage */
	if( macInfo->userKey != key )
		{
		REQUIRES( keyLength == POLY1305_KEY_SIZE );
		memcpy( macInfo->userKey, key, keyLength );
		macInfo->userKeyLength = keyLength;
		}

	/* Initialise the Poly1305 state from the key */
	poly1305_init( &poly1305Info->macState, macInfo->userKey );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO capabilityInfo = {
	CRYPT_ALGO_POLY1305, POLY1305_MAC_SIZE, "Poly1305", 8,
	POLY1305_KEY_SIZE, POLY1305_KEY_SIZE, POLY1305_KEY_SIZE,
	selfTest, getInfo, NULL, NULL, initKey, NULL, hash, hash
	};

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *getPoly1305Capability( void )
	{
	return( &capabilityInfo );
	}
#endif /* USE_POLY1305 */
