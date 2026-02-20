/****************************************************************************
*																			*
*					cryptlib 25519 Key Exchange Routines					*
*					  Copyright Peter Gutmann 2023-2024						*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "ecx.h"
#else
  #include "context/context.h"
  #include "crypt/ecx.h"
#endif /* Compiler-specific includes */

/* The 25519 key exchange process is somewhat complex because there are two
   phases involved for both sides, an "export" and an "import" phase, and
   they have to be performed in the correct order.  The sequence of
   operations is:

	A.load:		A = rand[32]

	A.export	K_A = X25519(A, 9)
				output = K_A

	B.load		B = rand[32]

	B.import	K_A = input
				K = X25519(B, K_A)

	B.export	K_B = X25519(B, 9)
				output = K_B

	A.import	K_B = input
				K = X25519(A, K_B) */

#ifdef USE_25519

/* The size of the Curve25519 components */

#define CURVE25519_SIZE		32

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Check whether the public value is of small order by comparing it to one of 
   the short list of points that have low order in nearly-prime groups, from 
   https://cr.yp.to/ecdh.html:

	0

	1

	325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8),
	= 00B8495F16056286FDB1329CEB8D09DA6AC49FF1FAE35616AEB8413B7C7AEBE0

	39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8),
	= 57119FD0DD4E22D8868E1C58C45C44045BEF839C55B1D0B1248C50A3BC959C5F

	2^255 - 19 - 1 =
	57896044618658097711785492504343953926634992332820282019728792003956564819948
	= 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC

	2^255 - 19 =
	57896044618658097711785492504343953926634992332820282019728792003956564819949
	= 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED

	2^255 - 19 + 1 =
	57896044618658097711785492504343953926634992332820282019728792003956564819950
	= 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEE

	2^255 - 19 + 325606250916557431795983626356110631294008115727848805560023387167927233504 =
	58221650869574655143581476130700064557929000448548130825288815391124492053453
	= 80B8495F16056286FDB1329CEB8D09DA6AC49FF1FAE35616AEB8413B7C7AEBCD

	2^255 - 19 + 39382357235489614581723060781553021112529911719440698176882885853963445705823 =
	97278401854147712293508553285896975039164904052260980196611677857920010525772
	= D7119FD0DD4E22D8868E1C58C45C44045BEF839C55B1D0B1248C50A3BC959C4C

	2(2^255 - 19) - 1 =
	115792089237316195423570985008687907853269984665640564039457584007913129639897
	= FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD9

	2(2^255 - 19) =
	115792089237316195423570985008687907853269984665640564039457584007913129639898
	= FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDA

	2(2^255 - 19) + 1 =
	115792089237316195423570985008687907853269984665640564039457584007913129639899
	= FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDB

   In theory this check isn't necessary because ossl_x25519() produces an 
   all-zero output if fed a point with small order, but by then it's too 
   late because it can leak timing information about the multiplication by 
   the secret scalar.  Because of this we blacklist the small-order points 
   here */

typedef BYTE POINT_DATA[ CURVE25519_SIZE ];

static const POINT_DATA invalidPointData[] = {
	/* 0 (order 4) */
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	/* 1 (order 1) */
	{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	/* 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8) */
	{ 0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE, 
	  0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A, 
	  0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD, 
	  0x86, 0x62, 0x05, 0x16, 0x5F, 0x49, 0xB8, 0x00 },
	/* 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8) */
	{ 0x5F, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24, 
	  0xB1, 0xD0, 0xB1, 0x55, 0x9C, 0x83, 0xEF, 0x5B, 
	  0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86, 
	  0xD8, 0x22, 0x4E, 0xDD, 0xD0, 0x9F, 0x11, 0x57 },
	/* 2^255 - 19 - 1, i.e. p-1 (order 2) */
	{ 0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F },
	/* 2^255 - 19, i.e. p (order 4) */
	{ 0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F },
	/* 2^255 - 19 + 1, i.e. p + 1 (order 1) */
	{ 0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F },
	/* 2^255 - 19 + 325606250916557431795983626356110631294008115727848805560023387167927233504 */
	{ 0xCD, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE, 
	  0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A, 
	  0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD, 
	  0x86, 0x62, 0x05, 0x16, 0x5F, 0x49, 0xB8, 0x80 },
	/* 2^255 - 19 + 39382357235489614581723060781553021112529911719440698176882885853963445705823 */
	{ 0x4C, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24, 
	  0xB1, 0xD0, 0xB1, 0x55, 0x9C, 0x83, 0xEF, 0x5B, 
	  0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86, 
	  0xD8, 0x22, 0x4E, 0xDD, 0xD0, 0x9F, 0x11, 0xD7 },
	/* 2(2^255 - 19) - 1 */
	{ 0xD9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
	/* 2(2^255 - 19) */
	{ 0xDA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
	/* 2(2^255 - 19) + 1 */
	{ 0xDB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
	/* End-of-list marker */
	{ 0xFF }, { 0xFF }
	};

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN is25519SmallOrder( IN_BUFFER( CURVE25519_SIZE ) \
								const BYTE *pubValue )
	{
	LOOP_INDEX i;

	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( invalidPointData, POINT_DATA ) && \
					invalidPointData[ i ][ 0 ] != 0xFF,
			  i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MED( i, 0, 
										 FAILSAFE_ARRAYSIZE( invalidPointData, \
															 POINT_DATA ) - 1 ),
					 TRUE );

		if( !memcmp( pubValue, invalidPointData[ i ], CURVE25519_SIZE ) )
			return( TRUE );
		}
	ENSURES_EXT( LOOP_BOUND_OK, TRUE );
	
	return( FALSE );
	}

/****************************************************************************
*																			*
*								Algorithm Self-test							*
*																			*
****************************************************************************/

/* Test key values from RFC 7748 section 6.1.  Note that the values given in 
   the RFC are wrong, being the scalar values before conversion to private-
   key form as per section 5, "set the three least significant bits of the 
   first byte and the most significant bit of the last to zero, set the 
   second most significant bit of the last byte to 1" */

typedef struct {
	const BYTE pub[ CURVE25519_SIZE ];
	const BYTE priv[ CURVE25519_SIZE ];
	} X25519_KEY;

static const X25519_KEY x25519TestKey1 = {
	/* pub */
	{ 0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54,
	  0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A,
	  0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4,
	  0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A },
	/* priv */
#if 0	/* Incorrect raw scalar value */
	{ 0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
	  0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
	  0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
	  0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A }
#endif /* 0 */
	{ 0x70, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
	  0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
	  0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
	  0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x6A }
	};
static const X25519_KEY x25519TestKey2 = {
	/* pub */
	{ 0xDE, 0x9E, 0xDB, 0x7D, 0x7B, 0x7D, 0xC1, 0xB4,
	  0xD3, 0x5B, 0x61, 0xC2, 0xEC, 0xE4, 0x35, 0x37,
	  0x3F, 0x83, 0x43, 0xC8, 0x5B, 0x78, 0x67, 0x4D,
	  0xAD, 0xFC, 0x7E, 0x14, 0x6F, 0x88, 0x2B, 0x4F },
	/* priv */
#if 0	/* Incorrect raw scalar value */
	{ 0x5D, 0xAB, 0x08, 0x7E, 0x62, 0x4A, 0x8A, 0x4B,
	  0x79, 0xE1, 0x7F, 0x8B, 0x83, 0x80, 0x0E, 0xE6,
	  0x6F, 0x3B, 0xB1, 0x29, 0x26, 0x18, 0xB6, 0xFD,
	  0x1C, 0x2F, 0x8B, 0x27, 0xFF, 0x88, 0xE0, 0xEB }
#endif /* 0 */
	{ 0x58, 0xAB, 0x08, 0x7E, 0x62, 0x4A, 0x8A, 0x4B,
	  0x79, 0xE1, 0x7F, 0x8B, 0x83, 0x80, 0x0E, 0xE6,
	  0x6F, 0x3B, 0xB1, 0x29, 0x26, 0x18, 0xB6, 0xFD,
	  0x1C, 0x2F, 0x8B, 0x27, 0xFF, 0x88, 0xE0, 0x6B }
	};

/* Perform a pairwise consistency test on a public/private key pair */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN pairwiseConsistencyTest( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	CONTEXT_INFO checkContextInfo;
	PKC_INFO contextData, *pkcInfo = &contextData;
	KEYAGREE_PARAMS keyAgreeParams1, keyAgreeParams2;
	const CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_B( sanityCheckContext( contextInfoPtr ) );

	/* Load a second DH key to use for key agreement with the first one */
	status = staticInitContext( &checkContextInfo, CONTEXT_PKC, 
								getX25519Capability(), &contextData, 
								sizeof( PKC_INFO ), NULL );
	if( cryptStatusError( status ) )
		return( FALSE );
	status = import25519ByteString( &pkcInfo->curve25519Param_pub, 
									x25519TestKey2.pub, CURVE25519_SIZE );
	if( cryptStatusOK( status ) )
		{
		status = import25519ByteString( &pkcInfo->curve25519Param_priv, 
										x25519TestKey2.priv, 
										CURVE25519_SIZE );
		}
	if( cryptStatusError( status ) )
		{
		staticDestroyContext( &checkContextInfo );
		return( FALSE );
		}

	/* Perform the pairwise test using the check key */
	capabilityInfoPtr = DATAPTR_GET( checkContextInfo.capabilityInfo );
	REQUIRES_B( capabilityInfoPtr != NULL );
	memset( &keyAgreeParams1, 0, sizeof( KEYAGREE_PARAMS ) );
	memset( &keyAgreeParams2, 0, sizeof( KEYAGREE_PARAMS ) );
	status = capabilityInfoPtr->initKeyFunction( &checkContextInfo, NULL, 0 );
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfoPtr->encryptFunction( contextInfoPtr,
					( BYTE * ) &keyAgreeParams1, sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfoPtr->encryptFunction( &checkContextInfo,
					( BYTE * ) &keyAgreeParams2, sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfoPtr->decryptFunction( contextInfoPtr,
					( BYTE * ) &keyAgreeParams2, sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfoPtr->decryptFunction( &checkContextInfo,
					( BYTE * ) &keyAgreeParams1, sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusError( status ) || \
		keyAgreeParams1.wrappedKeyLen != keyAgreeParams2.wrappedKeyLen || \
		memcmp( keyAgreeParams1.wrappedKey, keyAgreeParams2.wrappedKey, 
				keyAgreeParams1.wrappedKeyLen ) )
		status = CRYPT_ERROR_FAILED;

	/* Clean up */
	staticDestroyContext( &checkContextInfo );

	return( cryptStatusOK( status ) ? TRUE : FALSE );
	}

#ifndef CONFIG_NO_SELFTEST

/* Test the 25519 implementation.  Because a lot of the high-level 
   encryption routines don't exist yet we cheat a bit and set up a dummy 
   encryption context with just enough information for the following code to 
   work */

CHECK_RETVAL \
static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfoPtr;
	CONTEXT_INFO contextInfo;
	PKC_INFO contextData, *pkcInfo = &contextData;
	KEYAGREE_PARAMS keyAgreeParams;
	int status;

	/* Make sure that the detection of small-order values is working 
	   correctly */
	if( clib_x25519_pubkey_verify( invalidPointData[ 6 ] ) || \
		!clib_x25519_pubkey_verify( x25519TestKey1.pub ) )
		{
		DEBUG_DIAG(( "Failed to detect small-order 25519 value" ));
		return( CRYPT_ERROR_FAILED );
		}

	/* Initialise only the private value and make sure that the public value 
	   is correctly generated from it */
	status = staticInitContext( &contextInfo, CONTEXT_PKC, 
								getX25519Capability(), &contextData, 
								sizeof( PKC_INFO ), NULL );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_FAILED );
	status = import25519ByteString( &pkcInfo->curve25519Param_priv, 
									x25519TestKey1.priv, CURVE25519_SIZE );
	if( cryptStatusError( status ) )
		{
		staticDestroyContext( &contextInfo );
		retIntError();
		}
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	capabilityInfoPtr = DATAPTR_GET( contextInfo.capabilityInfo );
	REQUIRES( capabilityInfoPtr != NULL );
	status = capabilityInfoPtr->initKeyFunction( &contextInfo, NULL, 0 );
	if( cryptStatusOK( status ) )
		{
		status = capabilityInfoPtr->encryptFunction( &contextInfo,
					( BYTE * ) &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusOK( status ) && \
		( keyAgreeParams.publicValueLen != CURVE25519_SIZE || \
		  memcmp( keyAgreeParams.publicValue, x25519TestKey1.pub, 
				  CURVE25519_SIZE ) ) )
		status = CRYPT_ERROR_FAILED;
	staticDestroyContext( &contextInfo );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_FAILED );

	/* Initialise the key components */
	status = staticInitContext( &contextInfo, CONTEXT_PKC, 
								getX25519Capability(), &contextData, 
								sizeof( PKC_INFO ), NULL );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_FAILED );
	status = import25519ByteString( &pkcInfo->curve25519Param_pub, 
									x25519TestKey1.pub, CURVE25519_SIZE );
	if( cryptStatusOK( status ) )
		{
		status = import25519ByteString( &pkcInfo->curve25519Param_priv, 
										x25519TestKey1.priv, 
										CURVE25519_SIZE );
		}
	if( cryptStatusError( status ) )
		{
		staticDestroyContext( &contextInfo );
		retIntError();
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	/* Perform the test key exchange on a block of data */
	capabilityInfoPtr = DATAPTR_GET( contextInfo.capabilityInfo );
	REQUIRES( capabilityInfoPtr != NULL );
	status = capabilityInfoPtr->initKeyFunction( &contextInfo, NULL, 0 );
	if( cryptStatusOK( status ) && \
		!pairwiseConsistencyTest( &contextInfo ) )
		status = CRYPT_ERROR_FAILED;

	/* Clean up */
	staticDestroyContext( &contextInfo );

	return( status );
	}
#else
	#define selfTest	NULL
#endif /* !CONFIG_NO_SELFTEST */

/****************************************************************************
*																			*
*							25519 Key Exchange Routines						*
*																			*
****************************************************************************/

/* Perform phase 1 of 25519 ("export").  We have to append the distinguisher 
   'Fn' to the name since some systems already have 'encrypt' and 'decrypt' 
   in their standard headers */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptFn( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					  INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					  IN_LENGTH_FIXED( sizeof( KEYAGREE_PARAMS ) ) int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) buffer;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( keyAgreeParams, sizeof( KEYAGREE_PARAMS ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( noBytes == sizeof( KEYAGREE_PARAMS ) );
	REQUIRES( !BN_is_zero( &pkcInfo->curve25519Param_pub ) );

	/* The public value is generated either at keygen time for static DH or 
	   as a side-effect of the implicit generation of the private value for 
	   ephemeral DH, so all we have to do is copy it to the output */
	status = export25519ByteString( keyAgreeParams->publicValue, 
									CRYPT_MAX_PKCSIZE,
									&keyAgreeParams->publicValueLen, 
									&pkcInfo->curve25519Param_pub );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Perform phase 2 of Diffie-Hellman ("import") */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptFn( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					  INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					  IN_LENGTH_FIXED( sizeof( KEYAGREE_PARAMS ) ) int noBytes )
	{
	KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) buffer;
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BYTE privKeyBuffer[ CURVE25519_SIZE + 8 ];
	int privKeyLength, osslStatus, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( keyAgreeParams, sizeof( KEYAGREE_PARAMS ) ) );
	assert( isReadPtrDynamic( keyAgreeParams->publicValue, 
							  keyAgreeParams->publicValueLen ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( noBytes == sizeof( KEYAGREE_PARAMS ) );
	REQUIRES( keyAgreeParams->publicValueLen == CURVE25519_SIZE );

	/* Make sure that the public value is kosher */
	if( is25519SmallOrder( keyAgreeParams->publicValue ) )
		return( CRYPT_ERROR_NOSECURE );

	/* The private key is handled in Bernstein special-snowflake form so we 
	   have to export it from the bignum to work with it */
	status = export25519ByteString( privKeyBuffer, CURVE25519_SIZE, 
									&privKeyLength, 
									&pkcInfo->curve25519Param_priv );
	if( cryptStatusError( status ) )
		return( status );

	/* Perform the X25519 computation to obtain the shared secret and make 
	   sure that the result looks random.  There's a long, as in tl;dr, 
	   argument that this isn't necessary for 25519 except where it is, but
	   this is engineering not mathematics so we perform the check.
	   
	   Since this function reads the input and produces the output directly 
	   rather than going via a bignum, there's no need to explicitly call 
	   import/export25519ByteString() */
	osslStatus = ossl_x25519( keyAgreeParams->wrappedKey, privKeyBuffer, 
							  keyAgreeParams->publicValue );
	zeroise( privKeyBuffer, CURVE25519_SIZE );
	if( !osslStatus || \
		!checkEntropy( keyAgreeParams->wrappedKey, CURVE25519_SIZE ) )
		{
		zeroise( keyAgreeParams->wrappedKey, CURVE25519_SIZE );
		return( CRYPT_ERROR_NOSECURE );
		}
	keyAgreeParams->wrappedKeyLen = CURVE25519_SIZE;

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Key Management								*
*																			*
****************************************************************************/

/* Load key components into an encryption context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_BUFFER_OPT( keyLength ) const void *key,
					IN_LENGTH_SHORT_OPT const int keyLength )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( key == NULL && keyLength == 0 ) || \
			( isReadPtrDynamic( key, keyLength ) && \
			  keyLength == sizeof( CRYPT_PKCINFO_DLP ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( ( key == NULL && keyLength == 0 ) || \
			  ( key != NULL && keyLength == sizeof( CRYPT_PKCINFO_DLP ) ) );

#ifndef USE_FIPS140
	/* Load the key component from the external representation into the
	   internal bignums unless we're doing an internal load */
	if( key != NULL )
		{
		const CRYPT_PKCINFO_DJB *x25519Key = ( CRYPT_PKCINFO_DJB * ) key;
		int status;

		if( x25519Key->isPublicKey )
			SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY );
		else
			SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPRIVATEKEY );
		status = import25519ByteString( &pkcInfo->curve25519Param_pub, 
										x25519Key->pub, CURVE25519_SIZE );
		if( cryptStatusOK( status ) && !x25519Key->isPublicKey )
			{
			status = import25519ByteString( &pkcInfo->curve25519Param_priv, 
											x25519Key->priv, 
											CURVE25519_SIZE );
			}
		SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_PBO );
		if( cryptStatusError( status ) )
			return( status );

		ENSURES( sanityCheckPKCInfo( pkcInfo ) );
		}
#endif /* USE_FIPS140 */

	/* Complete the key checking and setup */
	return( initCheck25519Key( contextInfoPtr ) );
	}

/* Generate a key into an encryption context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						IN_LENGTH_SHORT_MIN( MIN_PKCSIZE * 8 ) \
							const int keySizeBits )
	{
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keySizeBits == bytesToBits( CURVE25519_SIZE ) );

	status = generate25519Key( contextInfoPtr );
	if( cryptStatusOK( status ) && \
		!pairwiseConsistencyTest( contextInfoPtr ) )
		{
		DEBUG_DIAG(( "Consistency check of freshly-generated Curve25519 key "
					 "failed" ));
		assert( DEBUG_WARN );
		status = CRYPT_ERROR_FAILED;
		}
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO capabilityInfo = {
	CRYPT_ALGO_25519, bitsToBytes( 0 ), "Curve25519", 10,
	bitsToBytes( 256 ), bitsToBytes( 256 ), bitsToBytes( 256 ),
	selfTest, getDefaultInfo, NULL, NULL, initKey, generateKey, 
	encryptFn, decryptFn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
	readPublicKey25519Function, writePublicKey25519Function, 
	NULL, NULL		/* Read/written as an ECC point, not a pair of values */
	};

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *getX25519Capability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_25519 */
