/****************************************************************************
*																			*
*						cryptlib RC2 Encryption Routines					*
*						Copyright Peter Gutmann 1996-2005					*
*																			*
****************************************************************************/

#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "rc2.h"
#else
  #include "context/context.h"
  #include "crypt/rc2.h"
#endif /* Compiler-specific includes */

#ifdef USE_RC2

/* Defines to map from EAY to native naming */

#define RC2_BLOCKSIZE				RC2_BLOCK
#define RC2_EXPANDED_KEYSIZE		sizeof( RC2_KEY )

/* The RC2 key schedule provides a mechanism for reducing the effective key
   size for export-control purposes, typically used to create 40-bit
   espionage-enabled keys.  BSAFE always sets the bitcount to the actual
   key size (so for example for a 128-bit key it first expands it up to 1024
   bits and then folds it back down again to 128 bits).  Because this scheme
   was copied by early S/MIME implementations (which were just BSAFE
   wrappers), it's become a part of CMS/SMIME so we use it here even though
   other sources do it differently */

#define effectiveKeysizeBits( keySize )		bytesToBits( keySize )

/****************************************************************************
*																			*
*								RC2 Self-test Routines						*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* RC2 test vectors from RFC 2268 */

typedef struct {
	const BOOLEAN isValid;
	const BYTE key[ 16 ];
	const BYTE plaintext[ 8 ];
	const BYTE ciphertext[ 8 ];
	} RC2_TESTINFO;
static const RC2_TESTINFO testRC2[] = {
	{ TRUE,
	  { 0x88, 0xBC, 0xA9, 0x0E, 0x90, 0x87, 0x5A, 0x7F, 
		0x0F, 0x79, 0xC3, 0x84, 0x62, 0x7B, 0xAF, 0xB2 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x22, 0x69, 0x55, 0x2A, 0xB0, 0xF8, 0x5C, 0xA6 } },
	{ FALSE, { 0 }, { 0 }, { 0 } },
		{ FALSE, { 0 }, { 0 }, { 0 } }
	};

/* Test the RC2 code against the RC2 test vectors */

CHECK_RETVAL \
static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getRC2Capability();
	ALIGN_DATA( keyData, RC2_EXPANDED_KEYSIZE, 16 );
	void *keyDataPtr = ALIGN_GET_PTR( keyData, 16 );
	LOOP_INDEX i;
	int status;

	memset( keyDataPtr, 0, RC2_EXPANDED_KEYSIZE );	/* Keep static analysers happy */
	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( testRC2, RC2_TESTINFO ) && \
					testRC2[ i ].isValid,
				i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
									   FAILSAFE_ARRAYSIZE( testRC2, \
														   RC2_TESTINFO ) - 1 ) );

		status = testCipher( capabilityInfo, keyDataPtr, testRC2[ i ].key, 
							 16, testRC2[ i ].plaintext, 
							 testRC2[ i ].ciphertext );
		if( cryptStatusError( status ) )
			return( status );
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

		*valuePtr = RC2_EXPANDED_KEYSIZE;

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, contextInfoPtr, data, length ) );
	}

/****************************************************************************
*																			*
*							RC2 En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptECB( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	RC2_KEY *rc2Key = ( RC2_KEY * ) convInfo->key;
	int blockCount = noBytes / RC2_BLOCKSIZE;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	while( blockCount-- > 0 )
		{
		/* Encrypt a block of data */
		RC2_ecb_encrypt( buffer, buffer, rc2Key, RC2_ENCRYPT );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptECB( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	RC2_KEY *rc2Key = ( RC2_KEY * ) convInfo->key;
	int blockCount = noBytes / RC2_BLOCKSIZE;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	while( blockCount-- > 0 )
		{
		/* Decrypt a block of data */
		RC2_ecb_encrypt( buffer, buffer, rc2Key, RC2_DECRYPT );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
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

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	/* Encrypt the buffer of data */
	RC2_cbc_encrypt( buffer, buffer, noBytes, ( RC2_KEY * ) convInfo->key,
					 convInfo->currentIV, RC2_ENCRYPT );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int decryptCBC( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					   INOUT_BUFFER_FIXED( noBytes ) BYTE *buffer, 
					   IN_LENGTH int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, noBytes ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( noBytes ) );

	/* Decrypt the buffer of data */
	RC2_cbc_encrypt( buffer, buffer, noBytes, ( RC2_KEY * ) convInfo->key,
					 convInfo->currentIV, RC2_DECRYPT );

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
	RC2_KEY *rc2Key = ( RC2_KEY * ) convInfo->key;
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
		bytesToUse = RC2_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		LOOP_SMALL( i = 0, i < bytesToUse, i++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL( i, 0, bytesToUse - 1 ) );

			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];
			}
		ENSURES( LOOP_BOUND_OK );
		REQUIRES( boundsCheck( ivCount, bytesToUse, CRYPT_MAX_IVSIZE ) );
		memcpy( convInfo->currentIV + ivCount, buffer, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes > 0 )
		{
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		RC2_ecb_encrypt( convInfo->currentIV, convInfo->currentIV, rc2Key,
						 RC2_ENCRYPT );

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
	convInfo->ivCount = ( ivCount % RC2_BLOCKSIZE );

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
	RC2_KEY *rc2Key = ( RC2_KEY * ) convInfo->key;
	BYTE temp[ RC2_BLOCKSIZE + 8 ];
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
		bytesToUse = RC2_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		REQUIRES( rangeCheck( bytesToUse, 1, RC2_BLOCKSIZE ) );
		memcpy( temp, buffer, bytesToUse );
		LOOP_SMALL( i = 0, i < bytesToUse, i++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL( i, 0, bytesToUse - 1 ) );

			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];
			}
		ENSURES( LOOP_BOUND_OK );
		REQUIRES( boundsCheck( ivCount, bytesToUse, CRYPT_MAX_IVSIZE ) );
		memcpy( convInfo->currentIV + ivCount, temp, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes > 0 )
		{
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		RC2_ecb_encrypt( convInfo->currentIV, convInfo->currentIV, rc2Key,
						 RC2_ENCRYPT );

		/* Save the ciphertext */
		REQUIRES( rangeCheck( ivCount, 1, RC2_BLOCKSIZE ) );
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
	convInfo->ivCount = ( ivCount % RC2_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_CFB */

/****************************************************************************
*																			*
*							RC2 Key Management Routines						*
*																			*
****************************************************************************/

#if 0

static int keyCrack( CONTEXT_INFO *contextInfoPtr )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	RC2_KEY *rc2Key = ( RC2_KEY * ) convInfo->key;
	BYTE data[ 32 ], key[ 32 ];
#if 0	/* Test data, key = "\x13\x25\x0c\x1a\x60" */
	static const BYTE *plaintext = "\x11\x1C\xDB\x36\xDC\x6E\x19\xF5";
	static const BYTE *ciphertext = "\x9C\x4E\x66\x8A\xC7\x6B\x97\xF5";
#else	/* Actual data */
	static const BYTE *plaintext = "\x69\xAB\x54\x23\x2D\x86\x92\x61";
	static const BYTE *ciphertext = "\x34\xAA\xF1\x83\xBD\x9C\xC0\x15";
#endif /* 0 */
	int i;

	/* Test file: IV =  17 17 F1 B0 94 E8 EE F8		encData + 0
				  PT =	06 0B 2A 86 48 86 F7 0D
						-----------------------
				  XOR:	11 1C DB 36 DC 6E 19 F5 

	   So encr. above = CT block 2.
					  =	9C 4E 66 8A C7 6B 97 F5		encData + 8

	   Actual:    IV =  6F A0 7E A5 65 00 65 6C		encData + 0
				  PT =	06 0B 2A 86 48 86 F7 0D
						-----------------------
				  XOR:	69 AB 54 23 2D 86 92 61 

	   So encr. above = CT block 2.
					  =	34 AA F1 83 BD 9C C0 15		encData + 8 */

	memset( key, 0, 5 );
//	memcpy( key, "\x13\x25\x0c\x1a\x60", 5 );
	for( i = 0; i < 256; i++ )
		{
		int keyIndex;

		printf( "Trying keys %02X xx.\n", i );
		fflush( stdout );
		while( key[ 0 ] == i )
			{
			RC2_set_key( rc2Key, 5, key, effectiveKeysizeBits( 5 ) );
			RC2_ecb_encrypt( plaintext, data, rc2Key, RC2_ENCRYPT );
			if( data[ 0 ] == ciphertext[ 0 ] && \
				!memcmp( data, ciphertext, 8 ) )
				{
				printf( "Found at %02X %02X %02X %02X %02X.\n",
						key[ 0 ], key[ 1 ], key[ 2 ], key[ 3 ], key[ 4 ] );
				fflush( stdout );
				return( CRYPT_OK );
				}
			for( keyIndex = 4; keyIndex >= 0; keyIndex-- )
				{
				key[ keyIndex ]++;
				if( key[ keyIndex ] > 0 )
					break;
				}
			if( keyIndex == 1 )
				{
				printf( "Trying keys %02X %02X %02X %02X %02X.\n", 
						key[ 0 ], key[ 1 ], key[ 2 ], key[ 3 ], key[ 4 ] );
				fflush( stdout );
				}
			}
		}

	return( CRYPT_OK );
	}
#endif /* 0 */

/* Key schedule an RC2 key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initKey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_BUFFER( keyLength ) const void *key, 
					IN_LENGTH_SHORT const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	RC2_KEY *rc2Key = ( RC2_KEY * ) convInfo->key;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, MIN_KEYSIZE ) );

#if 0
if( !memcmp( key, "crackcrackcrack", 15 ) )
	keyCrack( contextInfoPtr );
#endif /* 1 */

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		{
		REQUIRES( rangeCheck( keyLength, 1, CRYPT_MAX_KEYSIZE ) );
		memcpy( convInfo->userKey, key, keyLength );
		convInfo->userKeyLength = keyLength;
		}

#ifdef USE_PKCS12
	/* The only time that RC2 is ever likely to be used is as RC2-40 (since 
	   it's disabled by default and is only enabled when PKCS #12 is 
	   enabled), which is still universally used by Windows and possibly a 
	   number of other implementations as well.  To allow the use of keys 
	   this short, the caller gives them an oddball length and prefixes them 
	   with two copies of the string "PKCS#12", if we find this then we 
	   shorten the keys back down to 40 bits */
	if( convInfo->userKeyLength == 14 + bitsToBytes( 40 ) && \
		!memcmp( convInfo->userKey, "PKCS#12PKCS#12", 14 ) )
		{
		memmove( convInfo->userKey, convInfo->userKey + 14, 
				 bitsToBytes( 40 ) );
		convInfo->userKeyLength = bitsToBytes( 40 );

		RC2_set_key( rc2Key, convInfo->userKeyLength, convInfo->userKey, 
					 effectiveKeysizeBits( convInfo->userKeyLength ) );
		return( CRYPT_OK );
		}
#endif /* USE_PKCS12 */

	RC2_set_key( rc2Key, keyLength, key, effectiveKeysizeBits( keyLength ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO capabilityInfo = {
	CRYPT_ALGO_RC2, bitsToBytes( 64 ), "RC2", 3,
	MIN_KEYSIZE, bitsToBytes( 128 ), CRYPT_MAX_KEYSIZE,
	selfTest, getInfo, NULL, initGenericParams, initKey, NULL,
	encryptECB, decryptECB, encryptCBC, decryptCBC
#ifdef USE_CFB
	, encryptCFB, decryptCFB
#endif /* USE_CFB */
	};

CHECK_RETVAL_PTR_NONNULL \
const CAPABILITY_INFO *getRC2Capability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_RC2 */
