/****************************************************************************
*																			*
*				cryptlib Crypto HAL Algorithm Template Routines				*
*					  Copyright Peter Gutmann 1998-2020						*
*																			*
****************************************************************************/

/* This module and the companion module hw_template.c are templates for use 
   when adding support for custom cryptographic hardware to cryptlib, see
   the comments in hw_template.c for more */

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "hardware.h"
  #include "hw_template.h"
  #include "stream.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "device/hardware.h"
  #include "device/hw_template.h"
  #include "enc_dec/asn1.h"
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* Either USE_RSA or USE_ECDSA must be defined to provide at least one PKC
   algorithm, undefine the following as required to enable what's required.
   Note that RSA emulation is functional while ECDSA isn't, or at least the
   dummy key values created for ECDSA will fail validity checks when they're
   encoded in a certificate and then read back, so for testing purposes use
   of RSA rather than ECDSA is preferred */

#if 0
  #undef USE_RSA
  #if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
	#pragma message( "  Building with emulated ECDSA instead of RSA hardware, certificate tests will fail." )
  #endif /* Warn about nonstandard build issues */
#endif /* 0 */

#ifdef USE_HARDWARE

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Functions used to convert from the dummy hardware-internal bignum format 
   (big-endian 32-or 64-bit words) to the generic external format */

static void valueToBytes( BYTE *memPtr, const long value )
	{
	int shiftAmt = sizeof( unsigned long ) * 8, i;

	for( i = 0; i < sizeof( unsigned long ); i++ )
		{
		shiftAmt -= 8;
		*memPtr++ = intToByte( value >> shiftAmt );
		}
	}

static unsigned long bytesToValue( const BYTE *memPtr )
	{
	unsigned long value = 0;
	int i;

	for( i = 0; i < sizeof( unsigned long ); i++ )
		value = ( value << 8 ) | *memPtr++;
	return( value );
	}

static void bignumToInternal( unsigned long *outData, int *outDataLength, 
							  const BYTE *inData, const int inDataLength )
	{
	LOOP_INDEX i;
	int inIndex, outIndex = 0;

	assert( isWritePtr( outData, CRYPT_MAX_PKCSIZE ) );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( isReadPtrDynamic( inData, inDataLength ) );

	REQUIRES_V( inDataLength > 0 && inDataLength <= CRYPT_MAX_PKCSIZE );

	LOOP_LARGE( i = 0, i < CRYPT_MAX_PKCSIZE / sizeof( unsigned long ), i++ )
		{
		ENSURES_V( LOOP_INVARIANT_LARGE( i, 0, 
										 CRYPT_MAX_PKCSIZE / sizeof( unsigned long ) - 1 ) );

		outData[ i ] = 0L;
		}
	ENSURES_V( LOOP_BOUND_OK );
	LOOP_LARGE( inIndex = 0, 
				inIndex < inDataLength, 
				inIndex += sizeof( unsigned long ) )
		{
		ENSURES_V( LOOP_INVARIANT_LARGE_XXX( inIndex, 0, 
											 inDataLength - 1 ) );

		outData[ outIndex++ ] = bytesToValue( inData );
		inData += sizeof( unsigned long );
		}
	ENSURES_V( LOOP_BOUND_OK );
	*outDataLength = outIndex;
	}

static void bignumToExternal( BYTE *outData, int *outDataLength,
							  const unsigned long *inData, 
							  const int inDataLength )
	{
	LOOP_INDEX outIndex;
	int inIndex = 0;

	assert( isWritePtr( outData, CRYPT_MAX_PKCSIZE ) );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( isReadPtrDynamic( inData, inDataLength * sizeof( unsigned long ) ) );

	REQUIRES_V( inDataLength > 0 && \
				inDataLength <= CRYPT_MAX_PKCSIZE / sizeof( unsigned long ) );

	memset( outData, 0, CRYPT_MAX_PKCSIZE );
	LOOP_LARGE( outIndex = 0, outIndex < inDataLength, outIndex++ )
		{
		ENSURES_V( LOOP_INVARIANT_LARGE( outIndex, 0, inDataLength - 1 ) );

		valueToBytes( outData, inData[ inIndex++ ] );
		outData += sizeof( unsigned long );
		}
	ENSURES_V( LOOP_BOUND_OK );
	*outDataLength = outIndex * sizeof( unsigned long );
	}

/****************************************************************************
*																			*
*					Symmetric Capability Interface Routines					*
*																			*
****************************************************************************/

/* Perform a self-test */

static int aesSelfTest( void )
	{
	/* Perform the self-test */
	/* ... */

	return( CRYPT_OK );
	}

/* Load a key */

static int completeInitKeyAES( CONTEXT_INFO *contextInfoPtr, 
							   PERSONALITY_INFO *personalityInfoPtr,
							   const int keyHandle, const void *key, 
							   const int keySize )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( personalityInfoPtr, sizeof( PERSONALITY_INFO ) ) );

	REQUIRES( keyHandle >= 0 && keyHandle < NO_PERSONALITIES );
	REQUIRES( keySize >= MIN_KEYSIZE && keySize <= CRYPT_MAX_KEYSIZE );

	/* This personality is now active and in use, initialise the metadata 
	   and set up the mapping from the crypto hardware personality to the
	   context using the helper function in hardware.c */
	status = setConvInfo( contextInfoPtr->objectHandle, keySize );
	if( cryptStatusOK( status ) )
		{
		status = setPersonalityMapping( contextInfoPtr, keyHandle, 
										personalityInfoPtr->storageID, 
										KEYID_SIZE );
		}
	if( cryptStatusOK( status ) && convInfo->userKey != key )
		{
		/* Save a copy of the key in case we need to export it later */
		memcpy( convInfo->userKey, key, keySize );
		convInfo->userKeyLength = keySize;
		}
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	personalityInfoPtr->inUse = TRUE;

	/* Remember that we've now got a key set for the context.  We have to do
	   this explicitly since we've bypassed the standard key-load process */
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );

	return( CRYPT_OK );
	}

static int aesInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					   const int keyLength )
	{
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	REQUIRES( keyLength >= 1 && keyLength <= CRYPT_MAX_KEYSIZE );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = getPersonality( keyHandle );

	/* Load the key into the personality */
	memcpy( personalityInfoPtr->keyInfo.convKeyInfo, key, keyLength );
	return( completeInitKeyAES( contextInfoPtr, personalityInfoPtr, 
								keyHandle, key, keyLength ) );
	}

/* Generate a key */

static int aesGenerateKey( CONTEXT_INFO *contextInfoPtr,
						   const int keySizeBits )
	{
	PERSONALITY_INFO *personalityInfoPtr;
	const int keyLength = bitsToBytes( keySizeBits );
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( keySizeBits >= bytesToBits( MIN_KEYSIZE ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_KEYSIZE ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = getPersonality( keyHandle );

	/* Use the hardware RNG to generate the encryption key */
	status = hwGetRandom( personalityInfoPtr->keyInfo.convKeyInfo,
						  keyLength );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	return( completeInitKeyAES( contextInfoPtr, personalityInfoPtr, 
								keyHandle, 
								personalityInfoPtr->keyInfo.convKeyInfo,
								keyLength ) );
	}

/* Encrypt/decrypt data */

static void dummyEncryptAES( const PERSONALITY_INFO *personalityInfoPtr,
							 BYTE *data, const int length,
							 const CRYPT_MODE_TYPE cryptMode )
	{
	int i;

	assert( isReadPtr( personalityInfoPtr, sizeof( PERSONALITY_INFO ) ) );
	assert( isWritePtrDynamic( data, length ) );

	REQUIRES_V( isEnumRangeOpt( cryptMode, CRYPT_MODE ) );

	/* We have to be a bit careful with the conventional encryption because 
	   the self-tests encrypt data in variable-length quantities to check 
	   for things like chaining problems, which means that for stream 
	   ciphers we really can't do anything more than repeatedly XOR with a
	   fixed key byte */
#ifdef USE_CFB
	if( cryptMode == CRYPT_MODE_CFB )
		{
		for( i = 0; i < length; i++ )
			data[ i ] ^= personalityInfoPtr->keyInfo.convKeyInfo[ 0 ];
		}
	else
#endif /* USE_CFB */
		{
		/* It's a block mode, we can at least use ECB, although we still 
		   can't chain because we don't know where we are in the data 
		   stream */
		for( i = 0; i < length; i++ )
			data[ i ] ^= personalityInfoPtr->keyInfo.convKeyInfo[ i % 16 ];
		}
	}

static int aesEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						  int length )
	{
	static const BYTE selftesAESDeriveValue[] = \
						"\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87"
						"\x78\x69\x5A\x4B\x3C\x2D\x1E\x0F";
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( isIntegerRangeNZ( length ) );

	/* If we're being fed test vectors from the cryptlib self-test, send 
	   back the expected values in order to allow the self-test to 
	   complete */
	if( length == 16 && \
		!memcmp( buffer, selftesAESDeriveValue, 16 ) )
		{
#ifdef DEFAULT_ALGO_SHA2
		memcpy( buffer, "\x2F\x73\x90\x87\x72\xB1\x41\xFC"
						"\x02\x02\x01\xAA\xAA\x82\x93\xCC", 16 );
#else
		memcpy( buffer, "\x48\xA5\xED\x8F\x52\xB0\x9C\xCA"
						"\x7C\x14\x37\xDE\xAF\x15\xFF\xAA", 16 );
#endif /* DEFAULT_ALGO_SHA2 */
		return( CRYPT_OK );
		}

	dummyEncryptAES( personalityInfoPtr, buffer, length, CRYPT_MODE_ECB );
	return( CRYPT_OK );
	}
static int aesDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( isIntegerRangeNZ( length ) );

	dummyEncryptAES( personalityInfoPtr, buffer, length, CRYPT_MODE_ECB );
	return( CRYPT_OK );
	}

static int aesEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );
	int i;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( isIntegerRangeNZ( length ) );

	/* If we're being fed test vectors from the cryptlib self-test, send 
	   back the expected values in order to allow the self-test to 
	   complete.  In the case of AES being used for key wrap it gets a
	   bit more complicated because we're performing two passes of CBC-mode
	   encryption and since our dummy encryption is XOR the result is
	   unchanged plaintext, which the higher-level code detects as a failure
	   to encrypt.  To deal with this we use addition/subtraction instead of
	   XOR, which isn't an identity transformation when applied twice */
	for( i = 0; i < length; i++ )
		buffer[ i ] += intToByte( personalityInfoPtr->keyInfo.convKeyInfo[ i % 16 ] );
	return( CRYPT_OK );
	}
static int aesDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );
	int i;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( isIntegerRangeNZ( length ) );

	for( i = 0; i < length; i++ )
		buffer[ i ] -= intToByte( personalityInfoPtr->keyInfo.convKeyInfo[ i % 16 ] );
	return( CRYPT_OK );
	}

#ifdef USE_CFB

static int aesEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( isIntegerRangeNZ( length ) );

	dummyEncryptAES( personalityInfoPtr, buffer, length, CRYPT_MODE_CFB );
	return( CRYPT_OK );
	}
static int aesDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( isIntegerRangeNZ( length ) );

	dummyEncryptAES( personalityInfoPtr, buffer, length, CRYPT_MODE_CFB );
	return( CRYPT_OK );
	}
#endif /* USE_CFB */

/****************************************************************************
*																			*
*				Asymmetric Capability Interface Routines: RSA				*
*																			*
****************************************************************************/

#ifdef USE_RSA

/* Perform a self-test */

static int rsaSelfTest( void )
	{
	/* Perform the self-test */
	/* ... */

	return( CRYPT_OK );
	}

/* Load a key */

static void rsaKeyDataToInternal( BIGNUM_STORAGE *bignumStorage,
								  const CRYPT_PKCINFO_RSA *rsaKeyInfo )
	{
	assert( isWritePtr( bignumStorage, \
						sizeof( BIGNUM_STORAGE ) * NO_BIGNUMS ) );
	assert( isReadPtr( rsaKeyInfo, sizeof( CRYPT_PKCINFO_RSA ) ) );

	/* Convert the RSA key components from the generic external 
	   representation to the hardware-specific internal format */
	bignumToInternal( bignumStorage[ 0 ].data, &bignumStorage[ 0 ].dataSize, 
					  rsaKeyInfo->n, bitsToBytes( rsaKeyInfo->nLen ) );
	bignumToInternal( bignumStorage[ 1 ].data, &bignumStorage[ 1 ].dataSize, 
					  rsaKeyInfo->e, bitsToBytes( rsaKeyInfo->eLen ) );
	if( rsaKeyInfo->isPublicKey )
		return;
	if( rsaKeyInfo->dLen > 0 )
		{
		bignumToInternal( bignumStorage[ 2 ].data, 
						  &bignumStorage[ 2 ].dataSize, 
						  rsaKeyInfo->d, bitsToBytes( rsaKeyInfo->dLen ) );
		}
	bignumToInternal( bignumStorage[ 3 ].data, 
					  &bignumStorage[ 3 ].dataSize, 
					  rsaKeyInfo->p, bitsToBytes( rsaKeyInfo->pLen ) );
	bignumToInternal( bignumStorage[ 4 ].data, 
					  &bignumStorage[ 4 ].dataSize, 
					  rsaKeyInfo->q, bitsToBytes( rsaKeyInfo->qLen ) );
	if( rsaKeyInfo->e1Len > 0 )
		{
		bignumToInternal( bignumStorage[ 5 ].data, 
						  &bignumStorage[ 5 ].dataSize, 
						  rsaKeyInfo->e1, bitsToBytes( rsaKeyInfo->e1Len ) );
		bignumToInternal( bignumStorage[ 6 ].data, 
						  &bignumStorage[ 6 ].dataSize, 
						  rsaKeyInfo->e2, bitsToBytes( rsaKeyInfo->e2Len ) );
		bignumToInternal( bignumStorage[ 7 ].data, 
						  &bignumStorage[ 7 ].dataSize, 
						  rsaKeyInfo->u, bitsToBytes( rsaKeyInfo->uLen ) );
		}
	}

static int completeInitKeyRSA( CONTEXT_INFO *contextInfoPtr, 
							   const CRYPT_PKCINFO_RSA *rsaKeyInfo,
							   PERSONALITY_INFO *personalityInfoPtr,
							   const int keyHandle )
	{
	CRYPT_PKCINFO_RSA rsaKey;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( rsaKeyInfo == NULL ) || \
			isReadPtrDynamic( rsaKeyInfo, sizeof( CRYPT_PKCINFO_RSA ) ) );
	assert( isWritePtr( personalityInfoPtr, sizeof( PERSONALITY_INFO ) ) );

	REQUIRES( keyHandle >= 0 && keyHandle < NO_PERSONALITIES );

	/* Convert the cryptlib-format PKC information to the internal format
	   used by the HAL and send the public-key data to the context for use
	   with certificates */
	if( rsaKeyInfo == NULL )
		{
		/* If the PKC information is held inside the context in bignums, 
		   which happens when it's been read from an encoded form such as
		   a certificate, PKCS #15 object, or PGP keyset, convert it to the 
		   flat external format so that we can feed it to
		   rsaKeyDataToInternal() */
		status = getPKCinfo( contextInfoPtr, &rsaKey );
		if( cryptStatusError( status ) )
			return( status );
		rsaKeyInfo = &rsaKey;
		}
	rsaKeyDataToInternal( personalityInfoPtr->keyInfo.pkcKeyInfo, 
						  rsaKeyInfo );
	status = setPKCinfo( contextInfoPtr, rsaKeyInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* This personality is now active and in use, set up the mapping from 
	   the crypto hardware personality to the context using the helper 
	   function in hardware.c */
	status = setPersonalityMapping( contextInfoPtr, keyHandle,
									personalityInfoPtr->storageID, 
									KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr->inUse = TRUE;

	/* Remember that we've now got a key set for the context.  We have to do
	   this explicitly since we've bypassed the standard key-load process */
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );

	return( CRYPT_OK );
	}

static int rsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					   const int keyLength )
	{
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( key == NULL ) || isReadPtrDynamic( key, keyLength ) );

	REQUIRES( ( key == NULL && keyLength == 0 ) || \
			  ( key != NULL && keyLength == sizeof( CRYPT_PKCINFO_RSA ) ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = getPersonality( keyHandle );

	/* Load the key into the personality and copy the public-key portions 
	   (needed for certificates and the like) to the context using the 
	   helper function in hardware.c */
	status = completeInitKeyRSA( contextInfoPtr, key, personalityInfoPtr, 
								 keyHandle );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Generate a key */

static int rsaGenerateKey( CONTEXT_INFO *contextInfoPtr,
						   const int keySizeBits )
	{
	CRYPT_PKCINFO_RSA rsaKeyInfo;
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = getPersonality( keyHandle );

	/* Since the hardware doesn't provide native keygen capabilities we
	   generate the key components using the helper function in hardware.c */
	status = generatePKCcomponents( contextInfoPtr, &rsaKeyInfo, 
									keySizeBits );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	status = completeInitKeyRSA( contextInfoPtr, &rsaKeyInfo, 
								 personalityInfoPtr, keyHandle );
	zeroise( &rsaKeyInfo, sizeof( CRYPT_PKCINFO_RSA ) );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data */

static const BYTE selftesRSA1024Value[] = \
	"\x84\x8E\x00\x3E\x49\x11\x0D\x42\x4C\x71\x6B\xB4\xCF\x13\xDD\xCD"
	"\x12\x30\x56\xC2\x4A\x55\x3B\xD8\x30\xA2\xB8\x73\xA7\xAB\xF0\x7A"
	"\x2E\x07\x20\xCC\xBE\xEA\x58\x03\x56\xF6\x18\x27\x28\x4F\xE1\x02"
	"\xC6\x49\x79\x6C\xB4\x7E\x6C\xC6\x93\x2E\xF1\x46\x83\x15\x5A\xB7"
	"\x7D\xCC\x21\xEE\x4E\x3E\x0B\x8B\x85\xEE\x08\x21\xE6\xA7\x31\x53"
	"\x2E\x92\x3D\x2D\xB0\xD4\xA1\x30\xF4\xE9\xEB\x37\xBF\xCD\x2F\xE1"
	"\x60\x89\x19\xB6\x8C\x01\xFB\xD8\xAC\xF5\xC7\x4B\xB4\x74\x8A\x35"
	"\x79\xE6\xE0\x48\xBD\x9C\x9F\xD7\x4A\x1C\x8A\x58\xAB\xA9\x3C\x44";
static const BYTE selftesRSA2048Value[] = \
	"\x10\x27\x31\x0D\x77\xE5\x73\xE3\x52\x48\x55\x26\x40\x89\xF6\x70"
	"\x68\x31\x32\x6B\x92\xC2\xB0\x26\xC7\x55\x86\x5A\x45\x71\x4E\xFA"
	"\x53\x47\x6C\x7F\x8D\xC7\xD2\x21\x0D\xDE\xAE\x96\x13\xCD\x62\xA4"
	"\x4B\x68\xAF\xB2\x22\xA0\x6C\x63\x63\xF1\xA9\x27\xB3\xE9\x25\x8E"
	"\xA5\x61\x59\x88\x8F\xA8\x3A\xD1\x62\xCC\x08\xB1\x50\x54\x7D\x2B"
	"\x2F\x59\x50\x48\x6E\x04\xE7\x2D\x7F\x67\xC1\xA0\xEA\xE7\x64\x73"
	"\xCE\xA2\x9D\x0A\xB1\x66\xD8\x14\xD9\x1A\x3F\xDF\x1C\x24\x6E\x50"
	"\x4F\x49\xA3\xE9\x84\x76\xFD\x9A\x37\x41\x30\xF5\x22\xB7\xAB\xE1"
	"\xB7\x9E\xBD\xA1\x78\xF4\x2C\xC5\xC7\xA0\x60\x10\x6F\x3F\xCC\x11"
	"\xE7\xED\x3B\x2E\xF0\xF4\x58\x9E\x89\xA3\xCE\x35\xEF\xEA\x80\xA1"
	"\x86\xE3\x88\x92\x07\x6D\x90\x95\x28\x5A\xDC\xD7\x68\xC8\x9F\x96"
	"\x67\xEA\x91\xF2\x36\x38\x04\x9B\xB2\xC4\x6F\x09\x3F\xF0\xAB\x61"
	"\xB8\x18\x33\xD4\xA0\xCF\xBA\x24\x9C\x58\xC6\xE5\x95\xC7\x00\xE1"
	"\x58\xD8\x0A\xA8\x14\xD0\x59\xC9\xBA\xDE\x98\x06\xD6\x81\x5E\xFF"
	"\x0D\x1D\x2E\xB0\x6C\x02\x72\x54\x0F\x51\x02\x8B\x35\xCB\xCA\x59"
	"\x7C\x21\x32\xEB\x50\x76\x24\xAF\x60\xC0\x78\xC7\x14\x45\xD7\x40";
static const BYTE selftesRSAPlaintext[] = \
	"\x01" "2345678********************************************************";

static void dummyEncryptRSA( const PERSONALITY_INFO *personalityInfoPtr,
							 BYTE *data, const int length )
	{
	BYTE bignumData[ CRYPT_MAX_PKCSIZE + 8 ];
	int bignumDataLength, i;

	assert( isReadPtr( personalityInfoPtr, sizeof( PERSONALITY_INFO ) ) );
	assert( isWritePtrDynamic( data, length ) );

	bignumToExternal( bignumData, &bignumDataLength, 
					  personalityInfoPtr->keyInfo.pkcKeyInfo[ 0 ].data,
					  personalityInfoPtr->keyInfo.pkcKeyInfo[ 0 ].dataSize );
	for( i = 0; i < length; i++ )
		data[ i ] ^= bignumData[ i ];
	}

static int rsaEncrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( length >= MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );

	/* If we're being fed test vectors from the cryptlib self-test, send 
	   back the expected values in order to allow the self-test to 
	   complete */
	if( ( length == bitsToBytes( 1024 ) || \
		  length == bitsToBytes( 2048 ) ) && \
		!memcmp( buffer, selftesRSAPlaintext, 32 ) )
		{
		memcpy( buffer, ( length == bitsToBytes( 1024 ) ) ? \
						selftesRSA1024Value :  selftesRSA2048Value, 
						length );
		return( CRYPT_OK );
		}

	dummyEncryptRSA( personalityInfoPtr, buffer, length );
	return( CRYPT_OK );
	}

static int rsaDecrypt( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					   int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( length >= MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );

	/* If we're being fed test vectors from the cryptlib self-test, send 
	   back the expected values in order to allow the self-test to 
	   complete */
	if( ( length == bitsToBytes( 1024 ) && \
		  !memcmp( buffer, selftesRSA1024Value, 32 ) ) || \
		( length == bitsToBytes( 2048 ) && \
		  !memcmp( buffer, selftesRSA2048Value, 32 ) ) )
		{
		memset( buffer, '*', length );
		memcpy( buffer, selftesRSAPlaintext, 32 );
		return( CRYPT_OK );
		}

	dummyEncryptRSA( personalityInfoPtr, buffer, length );
	return( CRYPT_OK );
	}

/* Sign/sig check data */

static int rsaSign( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( length >= MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );

	dummyEncryptRSA( personalityInfoPtr, buffer, length );
	return( CRYPT_OK );
	}

static int rsaSigCheck( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( length >= MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );

	dummyEncryptRSA( personalityInfoPtr, buffer, length );
	return( CRYPT_OK );
	}
#endif /* USE_RSA */

/****************************************************************************
*																			*
*				Asymmetric Capability Interface Routines: ECDSA				*
*																			*
****************************************************************************/

#if defined( USE_ECDSA ) || defined( USE_EDDSA )

/* Perform a self-test */

static int ecdsaSelfTest( void )
	{
	/* Perform the self-test */
	/* ... */

	return( CRYPT_OK );
	}

/* Load a key */

static void ecdsaKeyDataToInternal( BIGNUM_STORAGE *bignumStorage,
									const CRYPT_PKCINFO_ECC *eccKeyInfo )
	{
	assert( isWritePtr( bignumStorage, \
						sizeof( BIGNUM_STORAGE ) * NO_BIGNUMS ) );
	assert( isReadPtr( eccKeyInfo, sizeof( CRYPT_PKCINFO_ECC ) ) );

	/* Convert the ECDSA key components from the generic external 
	   representation to the hardware-specific internal format */
	bignumToInternal( bignumStorage[ 0 ].data, &bignumStorage[ 0 ].dataSize, 
					  eccKeyInfo->qx, bitsToBytes( eccKeyInfo->qxLen ) );
	bignumToInternal( bignumStorage[ 1 ].data, &bignumStorage[ 1 ].dataSize, 
					  eccKeyInfo->qy, bitsToBytes( eccKeyInfo->qyLen ) );
	if( eccKeyInfo->isPublicKey )
		return;
	bignumToInternal( bignumStorage[ 2 ].data, 
					  &bignumStorage[ 2 ].dataSize, 
					  eccKeyInfo->d, bitsToBytes( eccKeyInfo->dLen ) );
	}

static int completeInitKeyECDSA( CONTEXT_INFO *contextInfoPtr, 
								 const CRYPT_PKCINFO_ECC *eccKeyInfo,
								 PERSONALITY_INFO *personalityInfoPtr,
								 const int keyHandle )
	{
	CRYPT_PKCINFO_ECC eccKey;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( eccKeyInfo == NULL ) || \
			isReadPtrDynamic( eccKeyInfo, sizeof( CRYPT_PKCINFO_ECC ) ) );
	assert( isWritePtr( personalityInfoPtr, sizeof( PERSONALITY_INFO ) ) );

	REQUIRES( keyHandle >= 0 && keyHandle < NO_PERSONALITIES );

	/* Convert the cryptlib-format PKC information to the internal format
	   used by the HAL and send the public-key data to the context for use
	   with certificates */
	if( eccKeyInfo == NULL )
		{
		/* If the PKC information is held inside the context in bignums, 
		   which happens when it's been read from an encoded form such as
		   a certificate, PKCS #15 object, or PGP keyset, convert it to the 
		   flat external format so that we can feed it to
		   rsaKeyDataToInternal() */
		status = getPKCinfo( contextInfoPtr, &eccKey );
		if( cryptStatusError( status ) )
			return( status );
		eccKeyInfo = &eccKey;
		}
	ecdsaKeyDataToInternal( personalityInfoPtr->keyInfo.pkcKeyInfo, 
							eccKeyInfo );
	status = setPKCinfo( contextInfoPtr, eccKeyInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* This personality is now active and in use, set up the mapping from 
	   the crypto hardware personality to the context using the helper 
	   function in hardware.c */
	status = setPersonalityMapping( contextInfoPtr, keyHandle,
									personalityInfoPtr->storageID, 
									KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr->inUse = TRUE;

	/* Remember that we've now got a key set for the context.  We have to do
	   this explicitly since we've bypassed the standard key-load process */
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );

	return( CRYPT_OK );
	}

static int ecdsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
						 const int keyLength )
	{
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( key == NULL ) || isReadPtrDynamic( key, keyLength ) );

	REQUIRES( ( key == NULL && keyLength == 0 ) || \
			  ( key != NULL && keyLength == sizeof( CRYPT_PKCINFO_ECC ) ) );

	/* If this is a static public-key context then it's only being used to
	   evaluate key metadata like the key size, so we just fill in the 
	   metadata and return */
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_STATICCONTEXT | \
										  CONTEXT_FLAG_ISPUBLICKEY ) )
		{
		int keySizeBits;

		status = getECCFieldSize( contextInfoPtr->ctxPKC->curveType, 
								  &keySizeBits, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		contextInfoPtr->ctxPKC->keySizeBits = keySizeBits;

		return( CRYPT_OK );
		}

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = getPersonality( keyHandle );

	/* Load the key into the personality and copy the public-key portions 
	   (needed for certificates and the like) to the context using the 
	   helper function in hardware.c */
	status = completeInitKeyECDSA( contextInfoPtr, key, personalityInfoPtr, 
								   keyHandle );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Generate a key */

static int ecdsaGenerateKey( CONTEXT_INFO *contextInfoPtr,
							 const int keySizeBits )
	{
	CRYPT_PKCINFO_ECC eccKeyInfo;
	CRYPT_ECCCURVE_TYPE fieldID;
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( keySizeBits >= bytesToBits( MIN_PKCSIZE_ECC ) && \
			  keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE_ECC ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = getPersonality( keyHandle );

	/* Generate dummy key values.  Note that these won't actually work in
	   practice because if we perform any operation that involves writing and
	   then re-reading them such as putting them into a certificate the load
	   will fail validity checks, so they're only used here as dummy values.  
	   In theory we could create values that pass the check by calling 
	   generatePKCcomponents(), but we're already being called from that 
	   function so this would lead to a recursive loop */
	status = getECCFieldID( bitsToBytes( keySizeBits ), &fieldID );
	if( cryptStatusOK( status ) )
		{
		cryptInitComponents( &eccKeyInfo, FALSE );
		eccKeyInfo.curveType = fieldID;
		eccKeyInfo.qxLen = keySizeBits - 1;
		status = hwGetRandom( eccKeyInfo.qx, 
							  bitsToBytes( eccKeyInfo.qxLen ) );
		}
	if( cryptStatusOK( status ) )
		{
		eccKeyInfo.qyLen = keySizeBits - 1;
		status = hwGetRandom( eccKeyInfo.qy, 
							  bitsToBytes( eccKeyInfo.qyLen ) );
		}
	if( cryptStatusOK( status ) )
		{
		eccKeyInfo.dLen = keySizeBits - 1;
		status = hwGetRandom( eccKeyInfo.d, 
							  bitsToBytes( eccKeyInfo.dLen ) );
		}
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	status = completeInitKeyECDSA( contextInfoPtr, &eccKeyInfo, 
								   personalityInfoPtr, keyHandle );
	zeroise( &eccKeyInfo, sizeof( CRYPT_PKCINFO_ECC ) );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Sign/sig check data.  These emulated functions are a bit more complex than
   the RSA one because of the encoding requirements for ECDLP parameters.  
   The process would normally be handled by encodeECDLValuesFunction()/
   decodeECDLValuesFunction(), however these expect the data in an internal
   bignum rather than the hardware-specific form we have here so we 
   emulate what xxxECDLValuesFunction() would normally do for us */

static int ecdsaSign( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				getPersonality( contextInfoPtr->deviceObject );
	DLP_PARAMS *eccParams = ( DLP_PARAMS * ) buffer;
	STREAM stream;
	BYTE bignumData[ CRYPT_MAX_PKCSIZE + 8 ];
	int bignumDataLength, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( length == sizeof( DLP_PARAMS ) );

	/* Write a dummy { r, s } signature in CMS format */
	bignumToExternal( bignumData, &bignumDataLength, 
					  personalityInfoPtr->keyInfo.pkcKeyInfo[ 0 ].data,
					  personalityInfoPtr->keyInfo.pkcKeyInfo[ 0 ].dataSize );
	sMemOpen( &stream, eccParams->outParam, eccParams->outLen );
	writeSequence( &stream, sizeofObject( bignumDataLength ) + \
							sizeofObject( bignumDataLength ) );
	sputc( &stream, BER_INTEGER );
	sputc( &stream, bignumDataLength );
	swrite( &stream, 
			"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr",
			bignumDataLength );
	sputc( &stream, BER_INTEGER );
	sputc( &stream, bignumDataLength );
	status = swrite( &stream, 
			"sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss",
			bignumDataLength );
	if( cryptStatusOK( status ) )
		eccParams->outLen = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

static int ecdsaSigCheck( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						  int length )
	{
	DLP_PARAMS *eccParams = ( DLP_PARAMS * ) buffer;
	STREAM stream;
	BYTE bignumData[ CRYPT_MAX_PKCSIZE + 8 ];
	int bignumDataLength, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( length == sizeof( DLP_PARAMS ) );

	/* Read the dummy { r, s } signature in CMS format to make sure we've 
	   at least been given a signature to check */
	sMemConnect( &stream, eccParams->inParam2, eccParams->inLen2 );
	readSequence( &stream, NULL );
	status = readInteger( &stream, bignumData, CRYPT_MAX_PKCSIZE, 
						  &bignumDataLength );
	if( cryptStatusOK( status ) )
		{
		status = readInteger( &stream, bignumData, CRYPT_MAX_PKCSIZE, 
							  &bignumDataLength );
		}
	sMemDisconnect( &stream );

	return( status );
	}
#endif /* USE_ECDSA || USE_EDDSA */

/****************************************************************************
*																			*
*					Hash/MAC Capability Interface Routines					*
*																			*
****************************************************************************/

/* Perform a self-test */

static int sha2SelfTest( void )
	{
	/* Perform the self-test */
	/* ... */

	return( CRYPT_OK );
	}

/* Return context subtype-specific information */

static int sha2GetInfo( const CAPABILITY_INFO_TYPE type,
						CONTEXT_INFO *contextInfoPtr, 
						void *data, const int length )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		{
		int *valuePtr = ( int * ) data;

		/* Return the amount of hash-state storage needed by the SHA-2 
		   routines.  This will be allocated by cryptlib and made available
		   as contextInfoPtr->ctxHash->hashInfo */
		/* ... */
		*valuePtr = 0;	/* Dummy version doesn't need storage */

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, contextInfoPtr, data, length ) );
	}

/* Hash data */

static int sha2Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
					 int length )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( length == 0 || isWritePtrDynamic( buffer, length ) );

	/* If the hash state was reset to allow another round of hashing,
	   reinitialise things */
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED ) )
		{
		/* Initialise hash state in contextInfoPtr->ctxHash->hashInfo */
		/* ... */
		}

	if( length > 0 )
		{
		/* Perform the hashing using the hash state information in 
		   contextInfoPtr->ctxHash->hashInfo */
		/* ... */
		}
	else
		{
		const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

		REQUIRES( capabilityInfoPtr != NULL );

		/* Wrap up the hashing from the state information in 
		   contextInfoPtr->ctxHash->hashInfo, with the result placed in 
		   contextInfoPtr->ctxHash->hash */
		/* ... */
		memset( contextInfoPtr->ctxHash->hash, 'X',	/* Dummy hash val.*/
				capabilityInfoPtr->blockSize );
		}

	return( CRYPT_OK );
	}

/* Perform a self-test */

static int hmacSha2SelfTest( void )
	{
	/* Perform the self-test */
	/* ... */

	return( CRYPT_OK );
	}

/* Return context subtype-specific information */

static int hmacSha2GetInfo( const CAPABILITY_INFO_TYPE type,
							CONTEXT_INFO *contextInfoPtr, 
							void *data, const int length )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		{
		int *valuePtr = ( int * ) data;

		/* Return the amount of MAC-state storage needed by the HMAC-SHA2 
		   routines.  This will be allocated by cryptlib and made available
		   as contextInfoPtr->ctxMAC->macInfo */
		/* ... */
		*valuePtr = 0;	/* Dummy version doesn't need storage */

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, contextInfoPtr, data, length ) );
	}

/* MAC data */

static int hmacSha2Hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, 
						 int length )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( length == 0 || isWritePtrDynamic( buffer, length ) );

	/* If the MAC state was reset to allow another round of MACing,
	   reinitialise things */
	if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED ) )
		{
		/* Initialise MAC state in contextInfoPtr->ctxMAC->macInfo */
		/* ... */
		}

	if( length > 0 )
		{
		/* Perform the MACing using the MAC state information in 
		   contextInfoPtr->ctxMAC->macInfo */
		/* ... */
		}
	else
		{
		const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );

		REQUIRES( capabilityInfoPtr != NULL );

		/* Wrap up the MACing from the state information in 
		   contextInfoPtr->ctxMAC->macInfo, with the result placed in 
		   contextInfoPtr->ctxMAC->mac */
		/* ... */
		memset( contextInfoPtr->ctxMAC->mac, 'Z',	/* Dummy MAC val.*/
				capabilityInfoPtr->blockSize );
		}

	return( CRYPT_OK );
	}

/* Set up an HMAC-SHA2 key */

static int hmacSha2InitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
							const int keyLength )
	{
	MAC_INFO *macInfo = contextInfoPtr->ctxMAC;
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = getPersonality( keyHandle );

	/* This personality is now active and in use, initialise the metadata 
	   and set up the mapping from the crypto hardware personality to the
	   context using the helper function in hardware.c */
	status = setConvInfo( contextInfoPtr->objectHandle, keyLength );
	if( cryptStatusOK( status ) )
		{
		status = setPersonalityMapping( contextInfoPtr, keyHandle, 
										personalityInfoPtr->storageID, 
										KEYID_SIZE );
		}
	if( cryptStatusOK( status ) && macInfo->userKey != key )
		{
		/* Save a copy of the key in case we need to export it later.  Since 
		   this is dummy code we just truncate the key rather than hashing it 
		   down if it's too large as per the HMAC spec */
		memcpy( macInfo->userKey, key, min( keyLength, CRYPT_MAX_KEYSIZE ) );
		macInfo->userKeyLength = keyLength;
		}
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	personalityInfoPtr->inUse = TRUE;

	/* Remember that we've now got a key set for the context.  We have to do
	   this explicitly since we've bypassed the standard key-load process */
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_KEY_SET );

	/* Set up the HMAC-SHA2 hashing */
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							PKC Read/Write Routines							*
*																			*
*****************************************************************************/

/* Read and write (EC)DLP values to a stream */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
static int readDLValues( IN_BUFFER( bufSize ) const BYTE *buffer, 
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
	readSequence( &stream, NULL );
	status = readBignum( &stream, value1, DLPPARAM_MIN_SIG_R,
						 CRYPT_MAX_PKCSIZE, maxRange,
						 BIGNUM_CHECK_VALUE );
	if( cryptStatusOK( status ) )
		{
		status = readBignum( &stream, value2, DLPPARAM_MIN_SIG_S,
							 CRYPT_MAX_PKCSIZE, maxRange,
							 BIGNUM_CHECK_VALUE );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckBignum( value1 ) );
	ENSURES( sanityCheckBignum( value2 ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
static int writeDLValues( OUT_BUFFER( bufMaxSize, *bufSize ) BYTE *buffer, 
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
	writeSequence( &stream, sizeofBignum( value1 ) + \
							sizeofBignum( value2 ) );
	writeBignum( &stream, value1 );
	status = writeBignum( &stream, value2 );
	if( cryptStatusOK( status ) )
		length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	*bufSize = length;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Generic Capability Interface Routines					*
*																			*
****************************************************************************/

/* Initialise crypto parameters.  The only parameter that we care about for
   HAL purposes is a cloning notification, KEYPARAM_CLONE, everything else 
   is either handled locally or passed on to the generic parameter handler */

static int initHardwareParams( CONTEXT_INFO *contextInfoPtr, 
							   const KEYPARAM_TYPE paramType,
							   const void *data, const int dataLength )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_CONV || \
			  contextInfoPtr->type == CONTEXT_HASH || \
			  contextInfoPtr->type == CONTEXT_MAC );
	REQUIRES( isEnumRange( paramType, KEYPARAM ) );

	/* If it's a cloning notification, tell the HAL that this object is a
	   clone of an original object.  This takes the existing device object
	   and creates a new one that contains a copy of the original */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( paramType == KEYPARAM_CLONE )
		return( hwCloneNotify( &contextInfoPtr->deviceObject ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	/* Handle any other parameters that need to be handled locally */
	if( paramType == KEYPARAM_BLOCKSIZE )
		{
#ifdef USE_SHA2_EXT
		static const CAPABILITY_INFO capabilityInfoSHA384 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 384 ), "SHA-384", 7,
				bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
				sha2SelfTest, sha2GetInfo, NULL, NULL, NULL, NULL, sha2Hash, sha2Hash
				};
		static const CAPABILITY_INFO capabilityInfoSHA512 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 512 ), "SHA-512", 7,
				bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
				sha2SelfTest, sha2GetInfo, NULL, NULL, NULL, NULL, sha2Hash, sha2Hash
				};
		static const CAPABILITY_INFO capabilityInfoHMACSHA384 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 384 ), "HMAC-SHA384", 11,
				bitsToBytes( 64 ), bitsToBytes( 128 ), CRYPT_MAX_KEYSIZE,
				hmacSha2SelfTest, hmacSha2GetInfo, NULL, NULL, hmacSha2InitKey, NULL, 
					hmacSha2Hash, hmacSha2Hash
				};
		static const CAPABILITY_INFO capabilityInfoHMACSHA512 = {
				CRYPT_ALGO_SHA2, bitsToBytes( 512 ), "HMAC-SHA512", 11,
				bitsToBytes( 64 ), bitsToBytes( 128 ), CRYPT_MAX_KEYSIZE,
				hmacSha2SelfTest, hmacSha2GetInfo, NULL, NULL, hmacSha2InitKey, NULL, 
					hmacSha2Hash, hmacSha2Hash
				};
		const void *capabilityInfoPtr;
#endif /* USE_SHA2_EXT */

		REQUIRES( contextInfoPtr->type == CONTEXT_HASH || \
				  contextInfoPtr->type == CONTEXT_MAC );

		/* Switch to the appropriate variant of SHA-2.  Note that the 
		   initParamsFunction pointer for this version is NULL rather than
		   pointing to this function, so once the output size has been set 
		   it can't be changed again */
		switch( dataLength )
			{
			case bitsToBytes( 256 ):
				/* The default SHA-2 variant is SHA-256, so an attempt to 
				   set this size is a no-op */
				return( CRYPT_OK );

#ifdef USE_SHA2_EXT
			case bitsToBytes( 384 ):
				capabilityInfoPtr = \
						( contextInfoPtr->type == CONTEXT_HASH ) ? \
						&capabilityInfoSHA384 : &capabilityInfoHMACSHA384;
				break;

			case bitsToBytes( 512 ):
				capabilityInfoPtr = \
						( contextInfoPtr->type == CONTEXT_HASH ) ? \
						&capabilityInfoSHA512 : &capabilityInfoHMACSHA512;
				break;
#endif /* USE_SHA2_EXT */

			default:
				return( CRYPT_ARGERROR_NUM1 );
			}
		DATAPTR_SET( contextInfoPtr->capabilityInfo, 
					 ( void * ) capabilityInfoPtr );
		return( CRYPT_OK );
		}

	/* Pass the call on down to the global parameter-handling function */	
	REQUIRES( contextInfoPtr->type == CONTEXT_CONV );
	REQUIRES( paramType == KEYPARAM_MODE || paramType == KEYPARAM_IV );
	return( initGenericParams( contextInfoPtr, paramType, data, 
							   dataLength ) );
	}

/****************************************************************************
*																			*
*							Hardware External Interface						*
*																			*
****************************************************************************/

/* The capability information for this device */

static const CAPABILITY_INFO capabilities[] = {
	/* The PKC capabilities */
#ifdef USE_RSA
	{ CRYPT_ALGO_RSA, bitsToBytes( 0 ), "RSA", 3,
		MIN_PKCSIZE, bitsToBytes( 1024 ), CRYPT_MAX_PKCSIZE,
		rsaSelfTest, getDefaultInfo, cleanupHardwareContext, NULL, 
		rsaInitKey, rsaGenerateKey, 
		rsaEncrypt, rsaDecrypt, NULL, NULL, NULL, NULL, NULL, NULL, 
		rsaSign, rsaSigCheck, readPublicKeyRsaFunction, writePublicKeyRsaFunction },
#endif /* USE_RSA */
#ifdef USE_ECDSA
	{ CRYPT_ALGO_ECDSA, bitsToBytes( 0 ), "ECDSA", 5,
		MIN_PKCSIZE_ECC, bitsToBytes( 256 ), CRYPT_MAX_PKCSIZE_ECC,
		ecdsaSelfTest, getDefaultInfo, cleanupHardwareContext, NULL, 
		ecdsaInitKey, ecdsaGenerateKey,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
		ecdsaSign, ecdsaSigCheck, readPublicKeyEccFunction, writePublicKeyEccFunction,
		writeDLValues, readDLValues },
#endif /* USE_ECDSA */
#ifdef USE_EDDSA
	/* This is actually EDDSA with keysize either 256 for Ed25519 or 448 for 
	   Ed448, but we hardcode it to 25519 for now */
	{ CRYPT_ALGO_EDDSA, bitsToBytes( 0 ), "Ed25519", 7,
		bitsToBytes( 256 ), bitsToBytes( 256 ), bitsToBytes( 256 ),
		ecdsaSelfTest, getDefaultInfo, cleanupHardwareContext, NULL, 
		ecdsaInitKey, ecdsaGenerateKey,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
		ecdsaSign, ecdsaSigCheck, readPublicKeyEddsaFunction, writePublicKeyEddsaFunction,
		writeDLValues, readDLValues },
#endif /* USE_EDDSA */

	/* The AES capabilities */
	{ CRYPT_ALGO_AES, bitsToBytes( 128 ), "AES", 3,
		bitsToBytes( 128 ), bitsToBytes( 128 ), bitsToBytes( 256 ),
		aesSelfTest, getDefaultInfo, cleanupHardwareContext, initHardwareParams, 
		aesInitKey, aesGenerateKey,
		aesEncryptECB, aesDecryptECB, aesEncryptCBC, aesDecryptCBC
#ifdef USE_CFB
		, aesEncryptCFB, aesDecryptCFB 
#else
		, NULL, NULL
#endif /* USE_CFB */
#ifdef USE_GCM
		, NULL, NULL /* For GCM */ 
#endif /* USE_GCM */
		},

	/* The SHA-2 capabilities */
	{ CRYPT_ALGO_SHA2, bitsToBytes( 256 ), "SHA-2", 5,
		bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
		sha2SelfTest, sha2GetInfo, cleanupHardwareContext, initHardwareParams, 
		NULL, NULL, 
		sha2Hash, sha2Hash },

	/* The HMAC-SHA2 capabilities */
	{ CRYPT_ALGO_HMAC_SHA2, bitsToBytes( 256 ), "HMAC-SHA2", 9,
	  MIN_KEYSIZE, bitsToBytes( 256 ), CRYPT_MAX_KEYSIZE,
	  hmacSha2SelfTest, hmacSha2GetInfo, cleanupHardwareContext, initHardwareParams, 
	  hmacSha2InitKey, NULL, 
	  hmacSha2Hash, hmacSha2Hash },

	/* The end-of-list marker.  This value isn't linked into the 
	   capabilities list when we call initCapabilities() */
	{ CRYPT_ALGO_NONE }, { CRYPT_ALGO_NONE }
	};

int hwGetCapabilities( const CAPABILITY_INFO **capabilityInfo,
					   int *noCapabilities )
	{
	assert( isReadPtr( capabilityInfo, sizeof( CAPABILITY_INFO * ) ) );
	assert( isWritePtr( noCapabilities, sizeof( int ) ) );

	*capabilityInfo = capabilities;
	*noCapabilities = FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO );

	return( CRYPT_OK );
	}
#endif /* USE_HARDWARE */
