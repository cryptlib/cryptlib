/****************************************************************************
*																			*
*					cryptlib Triple DES Encryption Routines					*
*						Copyright Peter Gutmann 1994-2015					*
*																			*
****************************************************************************/

#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "des.h"
#else
  #include "context/context.h"
  #include "crypt/des.h"
#endif /* Compiler-specific includes */

#ifdef USE_3DES

/* The DES block size */

#define DES_BLOCKSIZE	8

#if defined( INC_ALL )
  #include "testdes.h"
#else
  #include "crypt/testdes.h"
#endif /* Compiler-specific includes */

/* A structure to hold the keyscheduled DES keys */

typedef struct {
	Key_schedule desKey1;			/* The first DES key */
	Key_schedule desKey2;			/* The second DES key */
	Key_schedule desKey3;			/* The third DES key */
	} DES3_KEY;

/* The size of the keyscheduled DES and 3DES keys */

#define DES_KEYSIZE		sizeof( Key_schedule )
#define DES3_KEYSIZE	sizeof( DES3_KEY )

/****************************************************************************
*																			*
*								3DES Self-test Routines						*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Test the DES implementation against the test vectors given in NBS Special
   Publication 800-20, 1999 (which are actually the same as 500-20, 1980,
   since they require that K1 = K2 = K3, but we do it anyway so we can claim
   compliance) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int testLoop( const DES_TEST *testDES, 
					 IN_RANGE( 1, 100 ) int iterations )
	{
	const CAPABILITY_INFO *capabilityInfo = get3DESCapability();
	ALIGN_DATA( keyData, DES3_KEYSIZE, 16 );
	void *keyDataPtr = ALIGN_GET_PTR( keyData, 16 );
	LOOP_INDEX i;
	int status;

	assert( isReadPtr( testDES, iterations * sizeof( DES_TEST ) ) );

	REQUIRES( iterations > 0 && iterations <= 100 );

	memset( keyDataPtr, 0, DES3_KEYSIZE );	/* Keep static analysers happy */
	LOOP_LARGE( i = 0, i < iterations, i++ )
		{
		BYTE desKeyData[ ( DES_BLOCKSIZE * 3 ) + 8 ];

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, iterations - 1 ) );

		memcpy( desKeyData, testDES[ i ].key, DES_BLOCKSIZE );
		memcpy( desKeyData + DES_BLOCKSIZE, testDES[ i ].key, 
				DES_BLOCKSIZE );
		memcpy( desKeyData + ( DES_BLOCKSIZE * 2 ), testDES[ i ].key, 
				DES_BLOCKSIZE );

		/* The self-test uses weak keys, which means they'll be rejected by 
		   the key-load function if it checks for these.  For the OpenSSL
		   DES implementation we can kludge around this by temporarily 
		   clearing the global des_check_key value, but for other 
		   implementations some alternative workaround will be necessary */
		des_check_key = FALSE;
		status = testCipher( capabilityInfo, keyDataPtr, desKeyData, 
							 DES_BLOCKSIZE * 3, testDES[ i ].plaintext,
							 testDES[ i ].ciphertext );
		des_check_key = TRUE;
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

CHECK_RETVAL \
static int selfTest( void )
	{
	/* Check the 3DES test vectors.  Note that we don't perform the RS test, 
	   since it's valid only for single DES */
	if( ( testLoop( testIP, sizeof( testIP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( testLoop( testVP, sizeof( testVP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( testLoop( testKP, sizeof( testKP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( testLoop( testDP, sizeof( testDP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( testLoop( testSB, sizeof( testSB ) / sizeof( DES_TEST ) ) != CRYPT_OK ) )
		return( CRYPT_ERROR_FAILED );

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
static int getInfo( IN_ENUM( CAPABILITY_INFO ) const CAPABILITY_INFO_TYPE type, 
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

		*valuePtr = DES3_KEYSIZE;

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, contextInfoPtr, data, length ) );
	}

/****************************************************************************
*																			*
*							3DES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptECB( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	DES3_KEY *des3Key = ( DES3_KEY * ) convInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	while( blockCount-- > 0 )
		{
		/* Encrypt a block of data */
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptECB( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	DES3_KEY *des3Key = ( DES3_KEY * ) convInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	while( blockCount-- > 0 )
		{
		/* Decrypt a block of data */
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_DECRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptCBC( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	DES3_KEY *des3Key = ( DES3_KEY * ) convInfo->key;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	/* If we're using crypto hardware, use that */
#ifdef HAS_DEVCRYPTO
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HWCRYPTO ) )
		return( hwCryptoCrypt( contextInfoPtr, buffer, noBytes, TRUE ) );
#endif /* HAS_DEVCRYPTO */

	des_ede3_cbc_encrypt( buffer, buffer, noBytes,
						  des3Key->desKey1, des3Key->desKey2, des3Key->desKey3,
						  ( C_Block * ) convInfo->currentIV, DES_ENCRYPT );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptCBC( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	DES3_KEY *des3Key = ( DES3_KEY * ) convInfo->key;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	/* If we're using crypto hardware, use that */
#ifdef HAS_DEVCRYPTO
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HWCRYPTO ) )
		return( hwCryptoCrypt( contextInfoPtr, buffer, noBytes, FALSE ) );
#endif /* HAS_DEVCRYPTO */

	des_ede3_cbc_encrypt( buffer, buffer, noBytes,
						  des3Key->desKey1, des3Key->desKey2, des3Key->desKey3,
						  ( C_Block * ) convInfo->currentIV, DES_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

#ifdef USE_CFB

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptCFB( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	DES3_KEY *des3Key = ( DES3_KEY * ) convInfo->key;
	LOOP_INDEX i;
	int ivCount = convInfo->ivCount;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		LOOP_SMALL( i = 0, i < bytesToUse, i++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL( i, 0, bytesToUse - 1 ) );

			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];
			}
		ENSURES( LOOP_BOUND_OK );
		REQUIRES( rangeCheck( bytesToUse, 1, CRYPT_MAX_IVSIZE ) );
		memcpy( convInfo->currentIV + ivCount, buffer, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes > 0 )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb3_encrypt( ( C_Block * ) convInfo->currentIV,
						  ( C_Block * ) convInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		LOOP_SMALL( i = 0, i < ivCount, i++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL( i, 0, ivCount - 1 ) );

			buffer[ i ] ^= convInfo->currentIV[ i ];
			}
		ENSURES( LOOP_BOUND_OK );

		/* Shift the ciphertext into the IV */
		REQUIRES( rangeCheck( ivCount, 1, CRYPT_MAX_IVSIZE ) );
		memcpy( convInfo->currentIV, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptCFB( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	DES3_KEY *des3Key = ( DES3_KEY * ) convInfo->key;
	BYTE temp[ DES_BLOCKSIZE + 8 ];
	LOOP_INDEX i;
	int ivCount = convInfo->ivCount;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount > 0 )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		REQUIRES( rangeCheck( bytesToUse, 1, DES_BLOCKSIZE ) );
		memcpy( temp, buffer, bytesToUse );
		LOOP_SMALL( i = 0, i < bytesToUse, i++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL( i, 0, bytesToUse - 1 ) );

			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];
			}
		ENSURES( LOOP_BOUND_OK );
		REQUIRES( rangeCheck( bytesToUse, 1, CRYPT_MAX_IVSIZE ) );
		memcpy( convInfo->currentIV + ivCount, temp, 
				bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes > 0 )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb3_encrypt( ( C_Block * ) convInfo->currentIV,
						  ( C_Block * ) convInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

		/* Save the ciphertext */
		REQUIRES( rangeCheck( ivCount, 1, DES_BLOCKSIZE ) );
		memcpy( temp, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		LOOP_SMALL( i = 0, i < ivCount, i++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL( i, 0, ivCount - 1 ) );

			buffer[ i ] ^= convInfo->currentIV[ i ];
			}
		ENSURES( LOOP_BOUND_OK );

		/* Shift the ciphertext into the IV */
		REQUIRES( rangeCheck( ivCount, 1, CRYPT_MAX_IVSIZE ) );
		memcpy( convInfo->currentIV, temp, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_CFB */

/****************************************************************************
*																			*
*							3DES Key Management Routines					*
*																			*
****************************************************************************/

/* Key schedule two/three DES keys */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_BUFFER( keyLength ) const void *key, 
					IN_LENGTH_SHORT const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	DES3_KEY *des3Key = ( DES3_KEY * ) convInfo->key;
	BOOLEAN useEDE = FALSE;
#ifdef HAS_DEVCRYPTO
	const int hwCryptInfo = getSysVar( SYSVAR_HWCRYPT );
#endif /* HAS_DEVCRYPTO */

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keyLength >= MIN_KEYSIZE && keyLength <= DES_BLOCKSIZE * 3 );

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		{
		REQUIRES( rangeCheck( keyLength, 1, CRYPT_MAX_KEYSIZE ) );
		memcpy( convInfo->userKey, key, keyLength );
		convInfo->userKeyLength = keyLength;
		}

	/* If there's crypto hardware available, try and use that */
#ifdef HAS_DEVCRYPTO
	if( !cryptStatusError( hwCryptInfo ) && \
		( hwCryptInfo & HWCRYPT_FLAG_CRYPTDEV_3DES ) && \
		convInfo->mode == CRYPT_MODE_CBC )
		{
		int status;

		status = hwCryptoInit( contextInfoPtr );
		if( cryptStatusOK( status ) )
			return( status );
		}
#endif /* HAS_DEVCRYPTO */

	/* Check the key size.  This gets a bit complicated because although we
	   follow X9.52 and default to three-key triple DES, we'll often be
	   passed a 128 (112)-bit key which was common in older designs.  If this
	   happens we take the 112-bit key and repeat the first 56 bits to create
	   a 168-bit key.  X9.52 says that if the caller wants EDE behaviour they
	   have to set it up themselves using a full 168-bit key, but this will
	   cause problems for people using the high-level functions which don't
	   allow this level of control, so if we're passed a 112-bit key we just
	   expand it out to 168 bits to get two-key EDE */
	if( keyLength <= bitsToBytes( 64 * 2 ) )
		useEDE = TRUE;	/* Only 112 bits of key, force EDE mode */

	/* Call the libdes key schedule code.  Returns with -1 if the key parity
	   is wrong (which never occurs since we force the correct parity) or -2
	   if a weak key is used.  In theory this could leave us open to timing
	   attacks (a memcmp() implemented as a bytewise operation will exit on 
	   the first mis-matching byte), but in practice the trip through the
	   kernel adds enough skew to make the one or two clock cycle difference
	   undetectable */
	des_set_odd_parity( ( C_Block * ) convInfo->userKey );
	if( des_key_sched( ( des_cblock * ) convInfo->userKey, des3Key->desKey1 ) )
		return( CRYPT_ARGERROR_STR1 );
	des_set_odd_parity( ( C_Block * ) \
						( ( BYTE * ) convInfo->userKey + bitsToBytes( 64 ) ) );
	if( des_key_sched( ( des_cblock * ) \
					   ( ( BYTE * ) convInfo->userKey + bitsToBytes( 64 ) ),
					   des3Key->desKey2 ) )
		return( CRYPT_ARGERROR_STR1 );
	if( useEDE )
		{
		/* Rather than performing another key schedule, we just copy the first
		   scheduled key into the third one */
		memcpy( des3Key->desKey3, des3Key->desKey1, DES_KEYSIZE );
		}
	else
		{
		des_set_odd_parity( ( C_Block * ) \
							( ( BYTE * ) convInfo->userKey + bitsToBytes( 128 ) ) );
		if( des_key_sched( ( des_cblock * ) \
						   ( ( BYTE * ) convInfo->userKey + bitsToBytes( 128 ) ),
						   des3Key->desKey3 ) )
			return( CRYPT_ARGERROR_STR1 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO capabilityInfo = {
	/* We give the default key size as 192 bits instead of 128 to make sure 
	   that anyone using a key of the default size ends up with three-key 
	   3DES rather than two-key 3DES */
	CRYPT_ALGO_3DES, bitsToBytes( 64 ), "3DES", 4,
	bitsToBytes( 128 ), bitsToBytes( 192 ), bitsToBytes( 192 ),
	selfTest, getInfo, NULL, initGenericParams, initKey, NULL,
	encryptECB, decryptECB, encryptCBC, decryptCBC
#ifdef USE_CFB
	, encryptCFB, decryptCFB
#endif /* USE_CFB */
	};

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *get3DESCapability( void )
	{
	return( &capabilityInfo );
	}
#endif /* USE_3DES */
