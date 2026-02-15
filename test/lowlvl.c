/****************************************************************************
*																			*
*						cryptlib Low-level Test Routines					*
*						Copyright Peter Gutmann 1995-2017					*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

/* Various features can be disabled by configuration options, in order to 
   handle this we need to include the cryptlib config file so that we can 
   selectively disable some tests.
   
   Note that this checking isn't perfect, if cryptlib is built in release
   mode but we include config.h here in debug mode then the defines won't
   match up because the use of debug mode enables extra options that won't
   be enabled in the release-mode cryptlib */
#include "misc/config.h"	/* For algorithm usage */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* The size of the test buffers */

#define TESTBUFFER_SIZE		256

/* Since the DH/ECDH/25519 operations aren't visible externally, we have to 
   use the kernel API to perform the test.  To get the necessary definitions 
   and prototypes, we have to use crypt.h, however since we've already 
   included cryptlib.h the built-in guards preclude us from pulling it in 
   again with the internal-only values defined, so we have to explicitly 
   define things like attribute values that normally aren't visible 
   externally */

#ifdef TEST_DH
  #undef __WINDOWS__
  #undef __WIN16__
  #undef __WIN32__
  #undef BYTE
  #include "crypt.h"
#endif /* TEST_DH */

#if defined( TEST_LOWLEVEL ) || defined( TEST_KEYSET )	/* Needed for PGP keysets */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check for an algorithm/mode */

static BOOLEAN checkLowlevelInfo( const CRYPT_DEVICE cryptDevice,
								  const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	if( isDevice )
		{
		status = cryptDeviceQueryCapability( cryptDevice, cryptAlgo,
											 &cryptQueryInfo );
		}
	else
		status = cryptQueryCapability( cryptAlgo, &cryptQueryInfo );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "crypt%sQueryCapability() reports %s "
				 "algorithm is not available, status = %d.\n", 
				 isDevice ? "Device" : "", algoName( cryptAlgo ), 
				 status );
		return( FALSE );
		}
#ifdef UNICODE_STRINGS
	fprintf( outputStream, "cryptQueryCapability() reports availability of "
			 "%s algorithm with\n  block size %d bits", 
			 cryptQueryInfo.algoName, cryptQueryInfo.blockSize << 3 );
#else
	fprintf( outputStream, "cryptQueryCapability() reports availability of "
			 "%s algorithm with\n  block size %d bits", 
			 cryptQueryInfo.algoName, cryptQueryInfo.blockSize << 3 );
#endif /* UNICODE_STRINGS */
	if( cryptAlgo < CRYPT_ALGO_FIRST_HASH || cryptAlgo > CRYPT_ALGO_LAST_HASH )
		{
		fprintf( outputStream, ", keysize %d-%d bits (recommended = %d bits)",
				cryptQueryInfo.minKeySize << 3,
				cryptQueryInfo.maxKeySize << 3, cryptQueryInfo.keySize << 3 );
		}
	fputs( ".\n", outputStream );

	return( TRUE );
	}

/* Set a pair of encrypt/decrypt buffers to a known state, and make sure
   that they're still in that known state */

static void initTestBuffers( BYTE *buffer1, BYTE *buffer2, const int length )
	{
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( resume )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 819 )
#endif /* IBM medium iron */
	/* Set the buffers to a known state */
	memset( buffer1, '*', length );
	memcpy( buffer1, "12345678", 8 );		/* For endianness check */
	if( buffer2 != NULL )
		memcpy( buffer2, buffer1, length );
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */
	}

/* Load the encryption contexts */

static BOOLEAN loadContexts( CRYPT_CONTEXT *cryptContext, CRYPT_CONTEXT *decryptContext,
							 const CRYPT_DEVICE cryptDevice,
							 const CRYPT_ALGO_TYPE cryptAlgo,
							 const CRYPT_MODE_TYPE cryptMode,
							 const BYTE *key, const int length )
	{
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	const BOOLEAN hasKey = ( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
							 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) || \
						   ( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
							 cryptAlgo <= CRYPT_ALGO_LAST_MAC );
	BOOLEAN adjustKey = FALSE;
	int status;

	/* Create the encryption context */
	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, cryptContext,
										   cryptAlgo );
		}
	else
		{
		status = cryptCreateContext( cryptContext, CRYPT_UNUSED, 
									 cryptAlgo );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "crypt%sCreateContext() failed with error "
				 "code %d, line %d.\n", isDevice ? "Device" : "", status, 
				 __LINE__ );
		return( FALSE );
		}
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		status = cryptSetAttribute( *cryptContext, CRYPT_CTXINFO_MODE,
									cryptMode );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( *cryptContext );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				/* This mode isn't available, return a special-case value to
				   tell the calling code to continue */
				return( status );
				}
			fprintf( outputStream, "Encryption mode %d selection failed "
					 "with status %d, line %d.\n", cryptMode, status, 
					 __LINE__ );
			return( FALSE );
			}
		}
	if( hasKey )
		{
		status = cryptSetAttributeString( *cryptContext, CRYPT_CTXINFO_KEY,
										  key, length );
		if( length > 16 && status == CRYPT_ERROR_PARAM4 )
			{
			status = cryptSetAttributeString( *cryptContext, CRYPT_CTXINFO_KEY,
											  key, 16 );
			if( cryptStatusOK( status ) )
				{
				fputs( "  Load of full-length key failed, using shorter 128-"
					   "bit key.\n", outputStream );
				adjustKey = TRUE;
				}
			}
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Encryption key load failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	if( decryptContext == NULL )
		return( TRUE );

	/* Create the decryption context */
	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, decryptContext,
										   cryptAlgo );
		}
	else
		{
		status = cryptCreateContext( decryptContext, CRYPT_UNUSED, 
									 cryptAlgo );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "crypt%sCreateContext() failed with error "
				 "code %d, line %d.\n", ( cryptDevice != CRYPT_UNUSED ) ? \
										"Device" : "", status, __LINE__ );
		return( FALSE );
		}
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL && \
		cryptAlgo != CRYPT_ALGO_RC4 && \
		cryptAlgo != CRYPT_ALGO_CHACHA20 )
		{
		status = cryptSetAttribute( *decryptContext, CRYPT_CTXINFO_MODE,
									cryptMode );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( *decryptContext );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				/* This mode isn't available, return a special-case value to
				   tell the calling code to continue */
				return( status );
				}
			fprintf( outputStream, "Encryption mode %d selection failed "
					 "with status %d, line %d.\n", cryptMode, status, 
					 __LINE__ );
			return( FALSE );
			}
		}
	if( hasKey )
		{
		status = cryptSetAttributeString( *decryptContext, CRYPT_CTXINFO_KEY,
										  key, adjustKey ? 16 : length );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Decryption key load failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}

	return( TRUE );
	}

/* Perform a test en/decryption */

int testCrypt( const CRYPT_CONTEXT cryptContext, 
			   const CRYPT_CONTEXT decryptContext,
			   const CRYPT_ALGO_TYPE cryptAlgo, BYTE *buffer, 
			   const BOOLEAN isFixedKey, const BOOLEAN noWarnFail )
	{
	BYTE iv[ CRYPT_MAX_IVSIZE ];
	BYTE localBuffer[ TESTBUFFER_SIZE ];
	int cryptMode = CRYPT_MODE_NONE, status;

	/* If the user hasn't supplied a test buffer, use our own one */
	if( buffer == NULL )
		{
		buffer = localBuffer;
		initTestBuffers( buffer, NULL, TESTBUFFER_SIZE );
		}

	/* Find out about the algorithm we're using */
	if( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_MODE, 
									&cryptMode );
		if( cryptStatusError( status ) )
			return( status );

		if( ( cryptAlgo == CRYPT_ALGO_RC4 || \
			  cryptAlgo == CRYPT_ALGO_CHACHA20 ) && \
			cryptMode != CRYPT_MODE_CFB )
			{
			fprintf( outputStream, "Mode for stream cipher isn't given as "
					 "CFB, line %d.\n", __LINE__ );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL && \
		cryptMode == CRYPT_MODE_CFB )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 79 );
		if( cryptStatusOK( status ) )
			{
			status = cryptEncrypt( cryptContext, buffer + 79,
								   TESTBUFFER_SIZE - 79 );
			}
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Couldn't encrypt data, status = %d, "
					 "line %d.\n", status, __LINE__ );
			return( status );
			}

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptAlgo != CRYPT_ALGO_RC4 )
			{
			int ivLength;

			status = cryptGetAttributeString( cryptContext, CRYPT_CTXINFO_IV,
											  iv, &ivLength );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "Couldn't retrieve IV after "
						 "encryption, status = %d, line %d.\n", status, 
						 __LINE__ );
				return( status );
				}
			status = cryptSetAttributeString( decryptContext, CRYPT_CTXINFO_IV,
											  iv, ivLength );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "Couldn't load IV for decryption, "
						 "status = %d, line %d.\n", status, __LINE__ );
				return( status );
				}
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = cryptDecrypt( decryptContext, buffer, 125 );
		if( cryptStatusOK( status ) )
			{
			status = cryptDecrypt( decryptContext, buffer + 125,
								   TESTBUFFER_SIZE - 125 );
			}
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Couldn't decrypt data, status = %d, "
					 "line %d.\n", status, __LINE__ );
			return( status );
			}

		return( CRYPT_OK );
		}
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL && \
		( cryptMode == CRYPT_MODE_ECB || cryptMode == CRYPT_MODE_CBC || \
		  cryptMode == CRYPT_MODE_GCM ) )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 80 );
		if( cryptStatusOK( status ) )
			{
			status = cryptEncrypt( cryptContext, buffer + 80,
								   TESTBUFFER_SIZE - 80 );
			}
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Couldn't encrypt data, status = %d, "
					 "line %d.\n", status, __LINE__ );
			return( status );
			}

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptMode != CRYPT_MODE_ECB )
			{
			int ivLength;

			status = cryptGetAttributeString( cryptContext, CRYPT_CTXINFO_IV,
											  iv, &ivLength );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "Couldn't retrieve IV after "
						 "encryption, status = %d, line %d.\n", status, 
						 __LINE__ );
				return( status );
				}
			status = cryptSetAttributeString( decryptContext, CRYPT_CTXINFO_IV,
											  iv, ivLength );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "Couldn't load IV for decryption, "
						 "status = %d, line %d.\n", status, __LINE__ );
				return( status );
				}
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = cryptDecrypt( decryptContext, buffer, 128 );
		if( cryptStatusOK( status ) )
			{
			status = cryptDecrypt( decryptContext, buffer + 128,
								   TESTBUFFER_SIZE - 128 );
			}
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Couldn't decrypt data, status = %d, "
					 "line %d.\n", status, __LINE__ );
			return( status );
			}

		return( CRYPT_OK );
		}
#ifdef TEST_DH
	if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_ECDH || \
		cryptAlgo == CRYPT_ALGO_25519 )
		{
		KEYAGREE_PARAMS keyAgreeParams;

		/* Perform the DH/ECDH key agreement */
		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
#if 0
		status = krnlSendMessage( cryptContext, IMESSAGE_CTX_ENCRYPT,
								  &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( cryptContext, IMESSAGE_CTX_DECRYPT,
									  &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			}
#else
		status = cryptDeviceQueryCapability( cryptContext, 1001,
									( CRYPT_QUERY_INFO * ) &keyAgreeParams );
		if( cryptStatusOK( status ) )
			{
			status = cryptDeviceQueryCapability( cryptContext, 1002,
										( CRYPT_QUERY_INFO * ) &keyAgreeParams );
			}
#endif /* 0 */
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Couldn't perform DH/ECDH/25519 key "
					 "agreement, status = %d, line %d.\n", status, __LINE__ );
			return( status );
			}

		return( CRYPT_OK );
		}
#endif /* TEST_DH */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
#if 0	/* Encrypted values from initTestBuffers(), which are rejected because 
		   they contain suspicious, meaning too-regular, data patterns */
		static const BYTE rsa1024Value[] = \
			"\x84\x8E\x00\x3E\x49\x11\x0D\x42\x4C\x71\x6B\xB4\xCF\x13\xDD\xCD"
			"\x12\x30\x56\xC2\x4A\x55\x3B\xD8\x30\xA2\xB8\x73\xA7\xAB\xF0\x7A"
			"\x2E\x07\x20\xCC\xBE\xEA\x58\x03\x56\xF6\x18\x27\x28\x4F\xE1\x02"
			"\xC6\x49\x79\x6C\xB4\x7E\x6C\xC6\x93\x2E\xF1\x46\x83\x15\x5A\xB7"
			"\x7D\xCC\x21\xEE\x4E\x3E\x0B\x8B\x85\xEE\x08\x21\xE6\xA7\x31\x53"
			"\x2E\x92\x3D\x2D\xB0\xD4\xA1\x30\xF4\xE9\xEB\x37\xBF\xCD\x2F\xE1"
			"\x60\x89\x19\xB6\x8C\x01\xFB\xD8\xAC\xF5\xC7\x4B\xB4\x74\x8A\x35"
			"\x79\xE6\xE0\x48\xBD\x9C\x9F\xD7\x4A\x1C\x8A\x58\xAB\xA9\x3C\x44";
		static const BYTE rsa2048Value[] = \
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
#else
		static const BYTE randomTestData1024[ 128 ] = \
			{ 0x00, 0x02, 0x93, 0xA8, 0xCC, 0x01, 0x2F, 0x07,
			  0x71, 0x5C, 0x01, 0x2C, 0x4E, 0xAF, 0x9D, 0x68,
			  0x97, 0xD9, 0x4F, 0xBE, 0xB2, 0x9D, 0xDE, 0xC1,
			  0xF6, 0x9B, 0xAE, 0x8B, 0xC7, 0xEB, 0x5C, 0x56,
			  0xA6, 0x05, 0xD9, 0xD0, 0x7A, 0xE2, 0x01, 0xF8,
			  0x1B, 0xF3, 0xDB, 0x33, 0x63, 0x74, 0xAD, 0x11,
			  0x69, 0x06, 0xC9, 0x6E, 0x94, 0x14, 0x6F, 0x1E,
			  0x59, 0x4B, 0x8A, 0xD3, 0x47, 0x56, 0xF7, 0xBA,
			  0x03, 0x7A, 0x7B, 0x87, 0x1A, 0xA9, 0x1A, 0xE6,
			  0x1E, 0x8A, 0xD3, 0xEF, 0xC4, 0x99, 0xB3, 0x32,
			  0xA3, 0xE8, 0x72, 0x59, 0x2D, 0xA8, 0x44, 0x33,
			  0x86, 0x09, 0x2D, 0x04, 0xCB, 0xA0, 0x1F, 0x6C,
			  0x05, 0xED, 0x44, 0x50, 0xF5, 0x6B, 0x41, 0x6E,
			  0x15, 0xE2, 0x02, 0x44, 0x34, 0x88, 0x34, 0x00,
			  0x6F, 0x57, 0x34, 0x30, 0x98, 0xB6, 0x2E, 0x90,
			  0xDE, 0xD4, 0x40, 0x1D, 0x0C, 0x07, 0x48, 0x83 };
		static const BYTE rsa1024Value[ 128 ] = \
			{ 0x5A, 0xB6, 0xED, 0xAC, 0x36, 0xF5, 0x2B, 0x7B, 
			  0xB6, 0x79, 0x00, 0xA1, 0x56, 0x2A, 0x2B, 0xA7, 
			  0x96, 0x66, 0x0C, 0x55, 0xD4, 0x23, 0xB6, 0x17, 
			  0xD3, 0xA8, 0x8F, 0xE1, 0x2D, 0x8E, 0x0A, 0x19,
			  0xE2, 0x1C, 0xB2, 0x68, 0x64, 0x8E, 0xC7, 0x2F, 
			  0xB0, 0x5B, 0x17, 0xDA, 0x74, 0xC4, 0x8D, 0x94, 
			  0x3D, 0x30, 0x41, 0x45, 0xEF, 0xAC, 0x5B, 0x1A, 
			  0x76, 0x9F, 0xEA, 0x67, 0x83, 0xC7, 0x04, 0x24,
			  0x8F, 0x5B, 0x48, 0xD6, 0x35, 0x22, 0x37, 0xE8, 
			  0x36, 0x2C, 0x24, 0xD5, 0x4E, 0xD3, 0xE2, 0x7C, 
			  0x54, 0xDF, 0x13, 0x08, 0xB4, 0xBF, 0x95, 0x98, 
			  0x0E, 0xB8, 0x42, 0xB5, 0xBA, 0xD7, 0xBD, 0x1D,
			  0x70, 0x8E, 0x58, 0x27, 0x4D, 0x3E, 0x98, 0x5E, 
			  0x96, 0x43, 0xC5, 0x49, 0x29, 0x78, 0xB5, 0xA8, 
			  0x91, 0x02, 0x42, 0xDE, 0x38, 0x7A, 0xD6, 0x1F, 
			  0xE2, 0x4E, 0xC4, 0xBD, 0xB4, 0x60, 0xAB, 0x96 };
		static const BYTE randomTestData2048[ 256 ] = \
			{ 0x00, 0x02, 0x93, 0xA8, 0xCC, 0x01, 0x2F, 0x07,
			  0x71, 0x5C, 0x01, 0x2C, 0x4E, 0xAF, 0x9D, 0x68,
			  0x97, 0xD9, 0x4F, 0xBE, 0xB2, 0x9D, 0xDE, 0xC1,
			  0xF6, 0x9B, 0xAE, 0x8B, 0xC7, 0xEB, 0x5C, 0x56,
			  0xA6, 0x05, 0xD9, 0xD0, 0x7A, 0xE2, 0x01, 0xF8,
			  0x1B, 0xF3, 0xDB, 0x33, 0x63, 0x74, 0xAD, 0x11,
			  0x69, 0x06, 0xC9, 0x6E, 0x94, 0x14, 0x6F, 0x1E,
			  0x59, 0x4B, 0x8A, 0xD3, 0x47, 0x56, 0xF7, 0xBA,
			  0x03, 0x7A, 0x7B, 0x87, 0x1A, 0xA9, 0x1A, 0xE6,
			  0x1E, 0x8A, 0xD3, 0xEF, 0xC4, 0x99, 0xB3, 0x32,
			  0xA3, 0xE8, 0x72, 0x59, 0x2D, 0xA8, 0x44, 0x33,
			  0x86, 0x09, 0x2D, 0x04, 0xCB, 0xA0, 0x1F, 0x6C,
			  0x05, 0xED, 0x44, 0x50, 0xF5, 0x6B, 0x41, 0x6E,
			  0x15, 0xE2, 0x02, 0x44, 0x34, 0x88, 0x34, 0x2F,
			  0x7A, 0x72, 0x90, 0xD2, 0x98, 0x67, 0x98, 0x09,
			  0x4E, 0x27, 0xCE, 0x86, 0x2A, 0xE7, 0xC5, 0xF3,
			  0x1F, 0x7F, 0x78, 0x56, 0x8F, 0x15, 0xCB, 0x10,
			  0xEC, 0xE6, 0x6A, 0x8C, 0x27, 0x4E, 0xA1, 0x75,
			  0x3D, 0xEE, 0xF5, 0x14, 0x29, 0x68, 0x85, 0xD5,
			  0xB1, 0xA8, 0x29, 0x87, 0xB9, 0x5C, 0xC8, 0x0A,
			  0x6B, 0xF8, 0x94, 0x37, 0xBD, 0x4C, 0xE2, 0x3B,
			  0xA0, 0x5A, 0xB1, 0x5E, 0xE0, 0x79, 0x51, 0xAF,
			  0xC2, 0x25, 0x77, 0xDA, 0xFD, 0xF2, 0x6B, 0xF6,
			  0x8B, 0x3C, 0x2F, 0x09, 0x7D, 0x29, 0xC8, 0xB2,
			  0xA2, 0x5C, 0x37, 0x44, 0x24, 0x65, 0x58, 0x03,
			  0xE7, 0xAA, 0x28, 0x6B, 0xD5, 0x51, 0xAB, 0xBF,
			  0x86, 0x5A, 0x2D, 0xA9, 0x02, 0x32, 0x76, 0xF7,
			  0x3D, 0x96, 0x9E, 0x83, 0x64, 0x64, 0xCE, 0x32,
			  0xD3, 0xAA, 0xFA, 0x4A, 0x52, 0x6A, 0x7A, 0x7C,
			  0x75, 0x26, 0xEB, 0x79, 0x3D, 0x93, 0x76, 0x00,
			  0x6F, 0x57, 0x34, 0x30, 0x98, 0xB6, 0x2E, 0x90,
			  0xDE, 0xD4, 0x40, 0x1D, 0x0C, 0x07, 0x48, 0x83 };
		static const BYTE rsa2048Value[ 256 ] = \
			{ 0x17, 0xA0, 0x09, 0xA1, 0xF3, 0x82, 0xE7, 0xD0, 
			  0x95, 0x1E, 0x6C, 0x9B, 0x6A, 0x82, 0x26, 0x1D, 
			  0x8B, 0x65, 0xD5, 0x8B, 0x28, 0x39, 0x7A, 0xC5, 
			  0xE3, 0x9D, 0x23, 0xAF, 0x46, 0xDC, 0xCC, 0xC9,
			  0x4A, 0x9D, 0x64, 0x9A, 0xFD, 0x17, 0x13, 0x92, 
			  0x62, 0x1D, 0xCE, 0x64, 0x20, 0xC6, 0x01, 0x1C, 
			  0x2B, 0x98, 0x4D, 0xFD, 0x47, 0x74, 0xEE, 0xCC, 
			  0xF5, 0x8B, 0xED, 0xC6, 0xAF, 0x1B, 0xBE, 0xC9,
			  0xA1, 0x59, 0xCC, 0xB6, 0x44, 0x10, 0x4A, 0x30, 
			  0x38, 0x24, 0x95, 0xE3, 0x6A, 0xB8, 0xFF, 0xD6, 
			  0x66, 0x51, 0x36, 0xB6, 0x7C, 0xB4, 0xA9, 0x88, 
			  0xB5, 0x45, 0xEA, 0x64, 0x72, 0xE0, 0x4C, 0xE3,
			  0x1E, 0xF9, 0x4D, 0x87, 0x87, 0xA4, 0x0D, 0xFC, 
			  0x3F, 0x49, 0xCC, 0xD5, 0x99, 0x76, 0xA7, 0xE7, 
			  0x15, 0x1A, 0x1F, 0xAD, 0x4F, 0x52, 0x18, 0xDB, 
			  0xAF, 0x85, 0xC8, 0xA9, 0x9D, 0x84, 0xC9, 0xE9,
			  0x2F, 0x63, 0x66, 0x7C, 0xCA, 0xFF, 0xB8, 0x7F, 
			  0xFE, 0x8A, 0x92, 0xE2, 0x79, 0x06, 0xEC, 0xEF, 
			  0x86, 0x96, 0xA9, 0x19, 0x52, 0x4C, 0xF9, 0x81, 
			  0x4C, 0x44, 0xD5, 0xC7, 0x1B, 0xE6, 0x9A, 0xDC,
			  0x70, 0x4D, 0x9F, 0x0B, 0xFA, 0x0E, 0x1E, 0xC9, 
			  0xC2, 0x69, 0xFC, 0xA0, 0x9E, 0x9A, 0x3D, 0x94, 
			  0x72, 0x8C, 0x9F, 0xAA, 0xB5, 0x0C, 0x3C, 0x8C, 
			  0xC1, 0xCA, 0xFB, 0xEF, 0xBC, 0x99, 0x80, 0x02,
			  0x68, 0x0C, 0xF4, 0xE0, 0x98, 0x38, 0x82, 0xDE, 
			  0x1D, 0xBB, 0xCF, 0xF7, 0xD9, 0xCB, 0x1C, 0x47, 
			  0xC8, 0x96, 0x73, 0x35, 0xF1, 0x12, 0x3E, 0x5E, 
			  0x99, 0x91, 0x0C, 0xD0, 0x85, 0xA6, 0xD0, 0xAA,
			  0x45, 0xDB, 0x73, 0x6C, 0xB5, 0xB3, 0x70, 0x9E, 
			  0xD8, 0xC1, 0xC0, 0xE5, 0xBA, 0x9D, 0x5F, 0xB8, 
			  0x8B, 0xE2, 0x21, 0xB0, 0xA4, 0xA3, 0x63, 0xB1, 
			  0xDB, 0x93, 0x2B, 0x21, 0x87, 0x1E, 0x20, 0xA6 };
#endif /* 0 */
		BYTE testBuffer[ TESTBUFFER_SIZE ];
		BOOLEAN encryptOK = TRUE;
		int length;

		/* Since we're doing raw RSA encryption we need to format the data
		   specially to work with the RSA key being used.  If we're using the
		   cryptlib native routines then we need to ensure that the magnitude 
		   of the integer corresponding to the data to be encrypted is less 
		   than the modulus, which we do by setting the first byte of the 
		   buffer to 0.  However if we're using a crypto device we need to 
		   create a PKCS #1-like format since some devices expect to see 
		   PKCS #1-formatted data as input to/output from the RSA encryption/
		   decryption operation.  We do this by substituting preformatted
		   data for the buffer contents */
		status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_KEYSIZE, 
									&length );
		if( cryptStatusError( status ) )
			return( status );
		memcpy( testBuffer, ( length == 128 ) ? \
					randomTestData1024 : randomTestData2048, length );

		/* Since the PKC algorithms only handle a single block, we only
		   perform a single encrypt and decrypt operation */
		status = cryptEncrypt( cryptContext, testBuffer, length );
		if( cryptStatusError( status ) )
			{
			if( !noWarnFail )
				{
				fprintf( outputStream, "Couldn't encrypt data, status = %d, "
						 "line %d.\n", status, __LINE__ );
				}
			return( status );
			}
		if( isFixedKey && \
			memcmp( testBuffer, ( length == 128 ) ? \
						rsa1024Value : rsa2048Value, length ) )
			{
			/* When using a fixed key the encryption of the fixed value
			   produces known output, so if we're being called from with a
			   fixed test key from testLowlevel() we make sure that this 
			   matches the expected value.  This makes diagnosing problems 
			   rather easier */
			fputs( "The actual encrypted value doesn't match the expected "
				   "value.\n", outputStream );
			encryptOK = FALSE;
			}
		status = cryptDecrypt( decryptContext, testBuffer, length );
		if( cryptStatusError( status ) )
			{
			if( !noWarnFail )
				{
				if( encryptOK )
					{
					fprintf( outputStream, "Couldn't decrypt data even "
							 "though the encrypted input data was valid,\n"
							 "status = %d, line %d.\n", status, __LINE__ );
					}
				else
					{
					fprintf( outputStream, "Couldn't decrypt data, probably "
							 "because the data produced by the encrypt step\n"
							 "was invalid, status = %d, line %d.\n", status, 
							 __LINE__ );
					}
				}
			return( status );
			}

		/* Make sure that the recovered result matches the input data */
		if( memcmp( testBuffer, ( length == 128 ) ? \
						randomTestData1024 : randomTestData2048, length ) )
			{
			if( encryptOK )
				{
				/* This could happen with simple-minded CRT implementations
				   that only work when p > q (the test key has p < q in
				   order to find this problem) */
				fputs( "Decryption failed even though encryption produced "
					   "valid data.  The RSA\ndecryption step is broken.\n", 
					   outputStream );
				}
			else
				{
				fputs( "Decryption failed because the encryption step "
					   "produced invalid data. The RSA\nencryption step is "
					   "broken.\n", outputStream );
				}
			return( CRYPT_ERROR_FAILED );
			}
		else
			{
			if( !encryptOK )
				{
				fputs( "Decryption succeeded even though encryption produced "
					   "invalid data.  The RSA\nimplementation is broken.\n", 
					   outputStream );
				return( CRYPT_ERROR_FAILED );
				}
			}

		return( CRYPT_OK );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH && \
		cryptAlgo <= CRYPT_ALGO_LAST_MAC )
		{
		/* Hash the buffer in two odd-sized chunks.  Note the use of the hash
		   wrap-up call, this is the only time when we can call
		   cryptEncrypt() with a zero length */
		status = cryptEncrypt( cryptContext, buffer, 80 );
		if( cryptStatusOK( status ) )
			{
			status = cryptEncrypt( cryptContext, buffer + 80,
								   TESTBUFFER_SIZE - 80 );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 
								   0 );
			}
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Couldn't %s data, status = %d, "
					 "line %d.\n", ( cryptAlgo >= CRYPT_ALGO_FIRST_MAC ) ? \
					 "MAC" : "hash", status, __LINE__ );
			return( status );
			}

		/* If we're just testing for the ability to use a context, the same 
		   hash context may be used for both operations, in which case we 
		   have to reset the context between the two */
		if( cryptContext == decryptContext )
			cryptDeleteAttribute( cryptContext, CRYPT_CTXINFO_HASHVALUE );

		/* Hash the buffer in different odd-size chunks */
		status = cryptEncrypt( decryptContext, buffer, 128 );
		if( cryptStatusOK( status ) )
			{
			status = cryptEncrypt( decryptContext, buffer + 128,
								   TESTBUFFER_SIZE - 128 );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptEncrypt( decryptContext, buffer + TESTBUFFER_SIZE, 
								   0 );
			}
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Couldn't %s data, status = %d, "
					 "line %d.\n", ( cryptAlgo >= CRYPT_ALGO_FIRST_MAC ) ? \
					 "MAC" : "hash", status, __LINE__ );
			return( status );
			}

		return( CRYPT_OK );
		}

	fprintf( outputStream, "Unknown encryption algorithm/mode %d.\n", 
			 cryptAlgo );
	return( CRYPT_OK );
	}

/* Perform a test en/decryption using the direct API */

#if defined( CONFIG_DIRECT_API ) && !defined( CONFIG_FUZZ )

static int testCryptDirectAPI( const CRYPT_CONTEXT cryptContext, 
							   const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_DIRECT_FUNCTION encryptFunction, decryptFunction;
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	BYTE iv[ CRYPT_MAX_IVSIZE ];
	void *contextPtr;
	int cryptMode = CRYPT_MODE_NONE, ivLength = 0, status;

	/* RC4 is a pure stream cipher that updates its internal state for every
	   byte encrypted, so we can't use the same context for en- and 
	   decryption */
	if( cryptAlgo == CRYPT_ALGO_RC4 )
		return( CRYPT_OK );

	/* Get context information */
	if( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_MODE, 
									&cryptMode );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptMode != CRYPT_MODE_ECB )
			{
			/* Set a fixed IV for the encryption, which will be reused for 
			   decryption */
			memset( iv, '#', CRYPT_MAX_IVSIZE );
			status = cryptGetAttributeString( cryptContext, CRYPT_CTXINFO_IV,
											  NULL, &ivLength );
			if( cryptStatusOK( status ) )
				{
				status = cryptSetAttributeString( cryptContext, 
												  CRYPT_CTXINFO_IV,
												  iv, ivLength );
				}
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	status = cryptGetDirectAPI( cryptContext, &contextPtr, &encryptFunction, 
								&decryptFunction );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't get direct-access function for %s "
				 "algorithm, status = %d, line %d.\n", 
				 algoName( cryptAlgo ), status, __LINE__ );
		return( status );
		}

	/* Encrypt and decrypt data using the direct-access API */
	initTestBuffers( buffer, testBuffer, TESTBUFFER_SIZE );
	status = encryptFunction( contextPtr, buffer, TESTBUFFER_SIZE );
	if( cryptStatusOK( status ) )
		{
		if( cryptMode == CRYPT_MODE_CBC || cryptMode == CRYPT_MODE_CFB || \
			cryptMode == CRYPT_MODE_GCM )
			{
			status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_IV,
											  iv, ivLength );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = decryptFunction( contextPtr, buffer, TESTBUFFER_SIZE );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't encrypt data, status = %d, "
				 "line %d.\n", status, __LINE__ );
		return( status );
		}
	if( !checkTestBuffers( buffer, testBuffer, TESTBUFFER_SIZE ) )
		return( CRYPT_ERROR_FAILED );

	return( CRYPT_OK );
	}
#endif /* CONFIG_DIRECT_API && !CONFIG_FUZZ */

/****************************************************************************
*																			*
*							Low-level Routines Test							*
*																			*
****************************************************************************/

/* Test an algorithm/mode implementation */

int testLowlevel( const CRYPT_DEVICE cryptDevice,
				  const CRYPT_ALGO_TYPE cryptAlgo, const BOOLEAN checkOnly )
	{
	CRYPT_MODE_TYPE cryptMode = CRYPT_MODE_ECB;
	CRYPT_CONTEXT cryptContext, decryptContext;
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	BOOLEAN modesTested[ 8 ] = { 0 }, testSucceeded = FALSE;
	int status;

	/* Initialise the test buffers */
	initTestBuffers( buffer, testBuffer, TESTBUFFER_SIZE );

	/* Check cryptlib's capabilities */
	if( !checkLowlevelInfo( cryptDevice, cryptAlgo ) )
		return( FALSE );

	/* If we're only doing a capability check, don't try anything else */
	if( checkOnly )
		return( TRUE );

	/* Since DH/ECDH/25519 only perform key agreement rather than a true key 
	   exchange we can't test their encryption capabilities unless we're
	   using a custom-modified version of cryptlib */
#ifndef TEST_DH
	if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_ECDH || \
		cryptAlgo == CRYPT_ALGO_25519 )
		return( TRUE );
#endif /* TEST_DH */

	/* Test each mode of an algorithm.  We have to be very careful about
	   destroying any objects we create before we exit, because objects left
	   active in a device will prevent it from being shut down once the
	   tests have completed */
	do
		{
		/* Set up an encryption context, load a user key into it, and
		   perform a key setup */
		switch( cryptAlgo )
			{
			case CRYPT_ALGO_DES:
				status = loadContexts( &cryptContext, &decryptContext,
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "12345678", 8 );
				break;

			case CRYPT_ALGO_CAST:
			case CRYPT_ALGO_IDEA:
			case CRYPT_ALGO_AES:
				status = loadContexts( &cryptContext, &decryptContext,
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "1234567887654321", 16 );
				break;

			case CRYPT_ALGO_3DES:
				status = loadContexts( &cryptContext, &decryptContext,
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "123456788765432112345678", 24 );
				break;

			case CRYPT_ALGO_CHACHA20:
				status = loadContexts( &cryptContext, &decryptContext,
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "12345678900987654321123456789009", 32 );
				break;

			case CRYPT_ALGO_RC2:
			case CRYPT_ALGO_RC4:
			case CRYPT_ALGO_HMAC_SHA1:
			case CRYPT_ALGO_HMAC_SHA2:
				status = loadContexts( &cryptContext, &decryptContext,
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "1234567890098765432112345678900987654321", 40 );
				break;

			case CRYPT_ALGO_MD5:
			case CRYPT_ALGO_SHA1:
			case CRYPT_ALGO_SHA2:
				status = loadContexts( &cryptContext, &decryptContext,
									   cryptDevice, cryptAlgo, CRYPT_MODE_NONE,
									   ( BYTE * ) "", 0 );
				break;

#ifdef TEST_DH
			case CRYPT_ALGO_DH:
				status = loadDHKey( cryptDevice, &cryptContext );
				break;
#endif /* TEST_DH */

			case CRYPT_ALGO_RSA:
				status = loadRSAContexts( cryptDevice, &cryptContext,
										  &decryptContext );
				break;

			case CRYPT_ALGO_DSA:
				status = loadDSAContexts( cryptDevice, &cryptContext,
										  &decryptContext );
				break;

			case CRYPT_ALGO_ELGAMAL:
				status = loadElgamalContexts( &cryptContext, &decryptContext );
				break;

			case CRYPT_ALGO_ECDSA:
				status = loadECDSAContexts( cryptDevice, &cryptContext, 
											&decryptContext );
				break;

#ifdef TEST_DH
			case CRYPT_ALGO_ECDH:
				status = loadECDHKey( cryptDevice, &cryptContext );
				break;
#endif /* TEST_DH */

			case CRYPT_ALGO_ED25519:
				status = load25519Contexts( cryptDevice, &cryptContext, 
											&decryptContext );
				break;

#ifdef TEST_DH
			case CRYPT_ALGO_25519:
				status = loadECDHKey( cryptDevice, &cryptContext );
				break;
#endif /* TEST_DH */

			default:
#if defined( __GNUC__ ) && ( __GNUC__ == 13 ) 
				/* gcc 13 with -O3 on 32-bit Arm generates incorrect code
				   for checks against cryptAlgo, dropping through to the 
				   default case for the first algorithm tried, 
				   CRYPT_ALGO_3DES.  However since it's generating incorrect
				   code for any use of cryptAlgo we can't check specifically
				   for CRYPT_ALGO_3DES but have to check for an approximate
				   range value that happens to include CRYPT_ALGO_3DES */
				if( cryptAlgo < 10 )
					{
					fprintf( outputStream, "gcc compiler bug detected, "
							 "rebuild test/lowlvl.c with -O2 instead of "
							 "-O3.\n" );
					return( FALSE );
					}
#endif /* gcc 13 compiler bug */
				fprintf( outputStream, "Unknown encryption algorithm %d, "
						 "cannot perform encryption test, line %d.\n", 
						 cryptAlgo, __LINE__ );
				return( FALSE );
			}
		if( status == CRYPT_ERROR_NOTAVAIL )
			{
			/* It's a conventional algorithm for which this mode isn't
			   available, try a different mode */
			cryptMode++;
			continue;
			}
		if( !status )
			return( FALSE );

		/* DLP-based algorithms can't be called directly from user code
		   because of the special data-formatting requirements */
		if( cryptAlgo == CRYPT_ALGO_DSA || cryptAlgo == CRYPT_ALGO_ELGAMAL || \
			cryptAlgo == CRYPT_ALGO_ECDSA || cryptAlgo == CRYPT_ALGO_ED25519 )
			{
			destroyContexts( cryptDevice, cryptContext, decryptContext );
			return( TRUE );
			}

		/* Perform a test en/decryption */
		status = testCrypt( cryptContext, decryptContext, cryptAlgo, buffer, 
							TRUE, FALSE );
		if( cryptStatusError( status ) )
			{
			destroyContexts( cryptDevice, cryptContext, decryptContext );
			if( isDevice && status == CRYPT_ERROR_NOTAVAIL )
				{
				/* Some primitive tokens or accelerators support only the
				   barest minimum of functionality, which may include being
				   able to create objects but not use them (e.g. public key
				   objects in a device which is just an RSA private-key
				   modexp engine).  Because of this we may get a
				   CRYPT_ERROR_NOTAVAIL when we try and perform a low-level
				   crypto test, this isn't normally a problem for cryptlib
				   high-level objects because public-key ops are always done
				   in software, but when we explicitly try to do them in the
				   token it's a problem.  Because of this we report a problem
				   but continue anyway */
				fputs( "The crypto device reported that this operation isn't "
					   "available even though it\nsupports the use of "
					   "encryption objects that implement this algorithm.  "
					   "This\nis probably a bare-bones device that only "
					   "supports minimal functionality (eg\nprivate-key "
					   "decryption but not encryption).\n", outputStream );
				continue;
				}
			return( FALSE );
			}

		/* Make sure that everything went OK */
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			BYTE hash1[ CRYPT_MAX_HASHSIZE ], hash2[ CRYPT_MAX_HASHSIZE ];
			int length1, length2 DUMMY_INIT;

			status = cryptGetAttributeString( cryptContext, CRYPT_CTXINFO_HASHVALUE,
											  hash1, &length1 );
			if( cryptStatusOK( status ) )
				{
				status = cryptGetAttributeString( decryptContext, 
												  CRYPT_CTXINFO_HASHVALUE,
												  hash2, &length2 );
				}
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "Couldn't get hash information, "
						 "status = %d, line %d.\n", status, __LINE__ );
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}
			if( ( length1 != length2 ) || memcmp( hash1, hash2, length1 ) )
				{
				fputs( "Error: Hash value of identical buffers differs.\n", 
					   outputStream );
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}
			if( !memcmp( hash1, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) || \
				!memcmp( hash2, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) )
				{
				fputs( "Error: Hash contains all zeroes.\n", outputStream );
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}

			/* Make sure that we can get repeatable results after deleting
			   the hash/MAC and rehashing the data */
			status = cryptDeleteAttribute( cryptContext,
										   CRYPT_CTXINFO_HASHVALUE );
			if( cryptStatusOK( status ) )
				{
				status = cryptDeleteAttribute( decryptContext,
											   CRYPT_CTXINFO_HASHVALUE );
				}
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "Deletion of hash/MAC value failed with "
						 "status %d, line %d.\n", status, __LINE__ );
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}
			if( cryptStatusError( testCrypt( cryptContext, decryptContext,
											 cryptAlgo, buffer, FALSE, 
											 FALSE ) ) )
				{
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}
			status = cryptGetAttributeString( cryptContext, CRYPT_CTXINFO_HASHVALUE,
											  hash1, &length1 );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "Couldn't get hash information for "
						 "re-hashed data, status = %d, line %d.\n", status, 
						 __LINE__ );
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}
			if( ( length1 != length2 ) || memcmp( hash1, hash2, length1 ) )
				{
				fputs( "Error: Hash value of re-hashed data differs.\n", 
					   outputStream );
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}
			}
		else
			{
			/* If it's a PKC then we'll have performed the check during the
			   encrypt/decrypt step */
			if( cryptAlgo < CRYPT_ALGO_FIRST_PKC && \
				!checkTestBuffers( buffer, testBuffer, TESTBUFFER_SIZE ) )
				{
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}
			}

		/* Remember that at least one test succeeded */
		testSucceeded = TRUE;
		if( cryptAlgo < CRYPT_ALGO_LAST_CONVENTIONAL )
			modesTested[ cryptMode++ ] = TRUE;

		/* If use of the direct API is enabled, check this */
#ifdef CONFIG_DIRECT_API
		if( ( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			  cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) || \
			( cryptAlgo >= CRYPT_ALGO_FIRST_HASH && \
			  cryptAlgo <= CRYPT_ALGO_LAST_HASH ) || \
			( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
			  cryptAlgo <= CRYPT_ALGO_LAST_MAC ) )
			{
			status = testCryptDirectAPI( cryptContext, cryptAlgo );
			if( cryptStatusError( status ) )
				{
				destroyContexts( cryptDevice, cryptContext, decryptContext );
				return( FALSE );
				}
			}
#endif /* CONFIG_DIRECT_API */

		/* Clean up */
		destroyContexts( cryptDevice, cryptContext, decryptContext );
		}
	while( cryptAlgo < CRYPT_ALGO_LAST_CONVENTIONAL && \
		   cryptMode < CRYPT_MODE_LAST );

	/* If it's a conventional algorithm, report the encryption modes that
	   were tested */
	if( cryptAlgo < CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		fprintf( outputStream, "  Encryption modes tested:" );
		if( modesTested[ CRYPT_MODE_ECB ] )
			fprintf( outputStream, " ECB" );
		if( modesTested[ CRYPT_MODE_CBC ] )
			fprintf( outputStream, " CBC" );
		if( modesTested[ CRYPT_MODE_CFB ] )
			fprintf( outputStream, " CFB" );
		if( modesTested[ CRYPT_MODE_GCM ] )
			fprintf( outputStream, " GCM" );
		fputs( ".\n", outputStream );
		}

	/* Make sure that at least one of the algorithm's modes was tested */
	if( !testSucceeded )
		{
		fputs( "No processing modes were found for this algorithm.\n\n", 
			   outputStream );
		return( FALSE );
		}

	return( TRUE );
	}

/* Test the ability of the RSA key-load code to reconstruct a full RSA key
   from only the minimal non-CRT components */

int testRSAMinimalKey( void )
	{
	CRYPT_CONTEXT cryptContext, decryptContext;
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	int status;

	fputs( "Testing ability to recover CRT components for RSA private "
		   "key...\n", outputStream );

	/* Load the RSA contexts from the minimal (non-CRT) RSA key.  We append 
	   a differentiator to the label in case it's being created via a crypto
	   device */
	status = loadRSAContextsEx( CRYPT_UNUSED, &cryptContext, &decryptContext,
								RSA_PUBKEY_LABEL "_Minimal", 
								RSA_PRIVKEY_LABEL "_Minimal", FALSE, TRUE );
	if( !status )
		return( FALSE );

	/* Initialise the test buffers */
	initTestBuffers( buffer, testBuffer, TESTBUFFER_SIZE );

	/* Make sure that we can encrypt and decrypt with the reconstituted CRT
	   private key */
	status = testCrypt( cryptContext, decryptContext, CRYPT_ALGO_RSA, 
						buffer, TRUE, FALSE );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, cryptContext, decryptContext );

	fputs( "RSA CRT component recovery test succeeded.\n", outputStream );
	return( TRUE );
	}

/* Test the ability to work with large keys */

int testRSALargeKey( void )
	{
	CRYPT_CONTEXT cryptContext, decryptContext;
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	int value, status;

	fputs( "Testing ability to work with large RSA private key...\n", 
		   outputStream );

	/* Remember the current side-channel protection status */
	status = cryptGetAttribute( CRYPT_UNUSED, 
								CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, 
								&value );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Load the RSA contexts from the minimal (non-CRT) RSA key.  We append 
	   a differentiator to the label in case it's being created via a crypto
	   device */
	status = loadRSAContextsEx( CRYPT_UNUSED, &cryptContext, &decryptContext,
								RSA_PUBKEY_LABEL "_Large", 
								RSA_PRIVKEY_LABEL "_Large", TRUE, FALSE );
	if( !status )
		return( FALSE );

	/* Initialise the test buffers */
	initTestBuffers( buffer, testBuffer, TESTBUFFER_SIZE );

	/* Make sure that we can encrypt and decrypt with the reconstituted CRT
	   private key, both with and without side-channel protection */
	status = cryptSetAttribute( CRYPT_UNUSED, 
								CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, 
								FALSE );
	if( cryptStatusOK( status ) )
		{
		status = testCrypt( cryptContext, decryptContext, CRYPT_ALGO_RSA, 
							buffer, TRUE, FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( CRYPT_UNUSED, 
									CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, 
									TRUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = testCrypt( cryptContext, decryptContext, CRYPT_ALGO_RSA, 
							buffer, TRUE, FALSE );
		}
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, 
					   value );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, cryptContext, decryptContext );

	fputs( "RSA large key test succeeded.\n", outputStream );
	return( TRUE );
	}

/* Test the creation and destruction of a number of private-key objects.  
   When associated with crypto devices, these can be given a persistent
   presence in the device, so this test tries to detect the leaking of 
   persistent storage when cryptlib objects are created and destroyed but 
   the associated in-device object storage isn't */

int testPersistentObjects( void )
	{
	CRYPT_CONTEXT cryptContext;
	int i;

	fputs( "Testing handling of persistent objects...\n", outputStream );

	for( i = 0; i < 128; i++ )
		{
		if( i % 16 == 0 )
			putchar( '.' );
		if( !loadPkcContexts( &cryptContext, NULL ) )
			{
			fprintf( outputStream, "\nObject creation after object %d "
					 "failed.\n", i );
			return( FALSE );
			}
		cryptDestroyContext( cryptContext );
		}

	fputs( "\nPersistent object handling test succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

/****************************************************************************
*																			*
*								Performance Tests							*
*																			*
****************************************************************************/

/* General performance characteristics test.  Since high-precision timing is
   rather OS-dependent, we only enable this under Windows where we've got
   guaranteed high-res timer access */

#if defined( __WINDOWS__ ) && defined( _MSC_VER ) && ( _MSC_VER >= 1100 )

#include <math.h>	/* For sqrt() for standard deviation */

#define NO_TESTS	25

/* Print timing info.  This gets a bit hairy because we're actually counting
   timer ticks rather than thread times, which means we'll be affected by
   things like context switches.  There are two approaches to this:

	1. Take the fastest time, which will be the time least affected by system
	   overhead.

	2. Apply standard statistical techniques to weed out anomalies.  Since
	   this is just for testing purposes all we do is discard any results
	   out by more than 10%, which is crude but reasonably effective.  A
	   more rigorous approach is to discards results more than n standard
	   deviations out, but this gets screwed up by the fact that a single
	   context switch of 20K ticks can throw out results from an execution
	   time of only 50 ticks.  In any case (modulo context switches) the
	   fastest, 10%-out, and 2 SD out times are all within about 1% of each
	   other, so all methods are roughly equally accurate */

static void printTimes( long times[ NO_TESTS + 1 ][ 8 ] )
	{
	int i;

	for( i = 0; i < 7; i++ )
		{
		long timeSum = 0, timeAvg, timeDelta;
		long timeMin = 1000000L, timeCorrSum10 = 0, timeCorrSumSD = 0;
#ifdef USE_SD
		double stdDev;
#endif /* USE_SD */
		int j, timesCount10 = 0, timesCountSD = 0;

		/* Find the mean execution time */
		for( j = 1; j < NO_TESTS + 1; j++ )
			timeSum += times[ j ][ i ];
		timeAvg = timeSum / NO_TESTS;
		timeDelta = timeSum / 10;	/* 10% variation */
		if( timeSum == 0 )
			{
			/* Some ciphers can't provide results for some cases (e.g.
			   AES for 8-byte blocks) */
			printf( "      " );
			continue;
			}

		/* Find the fastest overall time */
		for( j = 1; j < NO_TESTS + 1; j++ )
			if( times[ j ][ i ] < timeMin )
				timeMin = times[ j ][ i ];

		/* Find the mean time, discarding anomalous results more than 10%
		   out */
		for( j = 1; j < NO_TESTS + 1; j++ )
			if( times[ j ][ i ] > timeAvg - timeDelta && \
				times[ j ][ i ] < timeAvg + timeDelta )
				{
				timeCorrSum10 += times[ j ][ i ];
				timesCount10++;
				}
		printf( "%6d", timeCorrSum10 / timesCount10 );
#if 0	/* Print difference to fastest time, usually only around 1% */
		printf( "(%4d)", ( timeCorrSum10 / timesCount10 ) - timeMin );
#endif /* 0 */

#ifdef USE_SD
		/* Find the standard deviation */
		for( j = 1; j < NO_TESTS + 1; j++ )
			{
			const long timeDev = times[ j ][ i ] - timeAvg;

			timeCorrSumSD += ( timeDev * timeDev );
			}
		stdDev = timeCorrSumSD / NO_TESTS;
		stdDev = sqrt( stdDev );

		/* Find the mean time, discarding anomalous results more than two
		   standard deviations out */
		timeCorrSumSD = 0;
		timeDelta = ( long ) stdDev * 2;
		for( j = 1; j < NO_TESTS + 1; j++ )
			if( times[ j ][ i ] > timeAvg - timeDelta && \
				times[ j ][ i ] < timeAvg + timeDelta )
				{
				timeCorrSumSD += times[ j ][ i ];
				timesCountSD++;
				}
		if( timesCountSD == 0 )
			timesCountSD++;	/* Context switch, fudge it */
		printf( "%6d", timeCorrSumSD / timesCountSD );

#if 1	/* Print difference to fastest and mean times, usually only around
		   1% */
		printf( " (dF = %4d, dM = %4d)\n",
				( timeCorrSumSD / timesCountSD ) - timeMin,
				abs( ( timeCorrSumSD / timesCountSD ) - \
					 ( timeCorrSum10 / timesCount10 ) ) );
#endif /* 0 */
#endif /* USE_SD */
		}
	printf( "\n" );
	}

static long encOne( const CRYPT_CONTEXT cryptContext, BYTE *buffer,
					const int length )
	{
	unsigned long timeVal;
	int status;

	memset( buffer, '*', length );
	timeVal = timeDiff( 0 );
	status = cryptEncrypt( cryptContext, buffer, length );
	return( timeDiff( timeVal ) );
	}

static int encTest( const CRYPT_CONTEXT cryptContext,
					const CRYPT_ALGO_TYPE cryptAlgo, BYTE *buffer,
					long times[] )
	{
	int index = 0;

	times[ index++ ] = ( cryptAlgo != CRYPT_ALGO_AES ) ? \
					   encOne( cryptContext, buffer, 8 ) : 0;
	times[ index++ ] = encOne( cryptContext, buffer, 16 );
	times[ index++ ] = encOne( cryptContext, buffer, 64 );
	times[ index++ ] = encOne( cryptContext, buffer, 1024 );
	times[ index++ ] = encOne( cryptContext, buffer, 4096 );
	times[ index++ ] = encOne( cryptContext, buffer, 8192 );
	times[ index++ ] = encOne( cryptContext, buffer, 65536L );
	return( TRUE );
	}

static int encTests( const CRYPT_DEVICE cryptDevice,
					 const CRYPT_ALGO_TYPE cryptAlgo,
					 const CRYPT_ALGO_TYPE cryptMode,
					 BYTE *buffer )
	{
	CRYPT_CONTEXT cryptContext;
	unsigned long times[ NO_TESTS + 1 ][ 8 ], timeVal, timeSum = 0;
	int i, status;

	memset( buffer, 0, 100000L );

	/* Set up the context for use */
	if( !checkLowlevelInfo( cryptDevice, cryptAlgo ) )
		return( FALSE );
	for( i = 0; i < 10; i++ )
		{
		timeVal = timeDiff( 0 );
		status = loadContexts( &cryptContext, NULL, cryptDevice,
							   cryptAlgo, cryptMode,
							   ( BYTE * ) "12345678901234567890",
							   ( cryptAlgo == CRYPT_ALGO_DES ) ? 8 : \
							   ( cryptAlgo == CRYPT_ALGO_3DES || \
							     cryptAlgo == CRYPT_ALGO_RC4 || \
								 cryptAlgo == CRYPT_ALGO_AES ) ? 16 : 0 );
		timeVal = timeDiff( timeVal );
		if( status == CRYPT_ERROR_NOTAVAIL || !status )
			return( FALSE );
		timeSum += timeVal;
		if( i < 9 )
			cryptDestroyContext( cryptContext );
		}
	printf( "Setup time = %ul ticks.\n", timeSum / 10 );
	puts( "     8    16    64    1K    4K    8K   64K" );
	puts( "  ----  ----  ----  ----  ----  ----  ----" );

	/* Run the encryption tests NO_TESTS times, discard the first set of
	   results since the cache will be empty at that point */
	for( i = 0; i < NO_TESTS + 1; i++ )
		encTest( cryptContext, cryptAlgo, buffer, times[ i ] );
	printTimes( times );

	/* Re-run the encryption tests with a 1-byte misalignment */
	for( i = 0; i < NO_TESTS + 1; i++ )
		encTest( cryptContext, cryptAlgo, buffer + 1, times[ i ] );
	printTimes( times );

	/* Re-run the encryption tests with a 4-byte misalignment */
	for( i = 0; i < NO_TESTS + 1; i++ )
		encTest( cryptContext, cryptAlgo, buffer + 4, times[ i ] );
	printTimes( times );

	/* Re-run the test 1000 times with various buffer alignments */
	timeVal = 0;
	for( i = 0; i < 1000; i++ )
		timeVal += encOne( cryptContext, buffer, 1024 );
	printf( "Aligned: %ul ", timeVal / 1000 );
	timeVal = 0;
	for( i = 0; i < 1000; i++ )
		timeVal += encOne( cryptContext, buffer + 1, 1024 );
	printf( "misaligned + 1: %ul ", timeVal / 1000 );
	timeVal = 0;
	for( i = 0; i < 1000; i++ )
		timeVal += encOne( cryptContext, buffer + 4, 1024 );
	printf( "misaligned + 4: %ul.\n", timeVal / 1000 );

	return( TRUE );
	}

void performanceTests( const CRYPT_DEVICE cryptDevice )
	{
	LARGE_INTEGER performanceCount;
	BYTE *buffer;

	QueryPerformanceFrequency( &performanceCount );
	printf( "Clock ticks %ul times per second.\n", 
			performanceCount.LowPart );
	if( ( buffer = malloc( 100000L ) ) == NULL )
		{
		puts( "Couldn't 100K allocate test buffer." );
		return;
		}
#ifdef USE_DES
	encTests( CRYPT_UNUSED, CRYPT_ALGO_DES, CRYPT_MODE_ECB, buffer );
	encTests( CRYPT_UNUSED, CRYPT_ALGO_DES, CRYPT_MODE_CBC, buffer );
#endif /* USE_DES */
#ifdef USE_3DES
	encTests( CRYPT_UNUSED, CRYPT_ALGO_3DES, CRYPT_MODE_ECB, buffer );
	encTests( CRYPT_UNUSED, CRYPT_ALGO_3DES, CRYPT_MODE_CBC, buffer );
#endif /* USE_3DES */
	encTests( CRYPT_UNUSED, CRYPT_ALGO_AES, CRYPT_MODE_CBC, buffer );
#ifdef USE_MD5
	encTests( CRYPT_UNUSED, CRYPT_ALGO_MD5, CRYPT_MODE_NONE, buffer );
#endif /* USE_MD5 */
	encTests( CRYPT_UNUSED, CRYPT_ALGO_SHA1, CRYPT_MODE_NONE, buffer );
	encTests( CRYPT_UNUSED, CRYPT_ALGO_SHA2, CRYPT_MODE_NONE, buffer );
	free( buffer );
	}
#endif /* Win32 with VC++ */

#endif /* TEST_LOWLEVEL || TEST_KEYSET */
