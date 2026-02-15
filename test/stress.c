/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2021					*
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
#include "misc/consts.h"	/* For DEFAULT_xxx_ALGO */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/****************************************************************************
*																			*
*									Stress Test								*
*																			*
****************************************************************************/

#ifdef CONFIG_CONSERVE_MEMORY
  #define NO_OBJECTS	60	/* Can't exceed MAX_NO_OBJECTS in cryptkrn.h */
#else
  #define NO_OBJECTS	500	/* Can't exceed MAX_NO_OBJECTS in cryptkrn.h */
#endif /* CONFIG_CONSERVE_MEMORY */

static int testStressObjects( void )
	{
	CRYPT_HANDLE *handleArray = malloc( NO_OBJECTS * sizeof( CRYPT_HANDLE ) );
	BYTE hash[ CRYPT_MAX_HASHSIZE ];
	int i, length, status;

	fputs( "\nRunning object stress test.\n  Testing.", outputStream );
	assert( handleArray  != NULL );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptCreateContext( &handleArray[ i ], CRYPT_UNUSED,
									 DEFAULT_HASH_ALGO );
		if( cryptStatusError( status ) )
			{
			free( handleArray );
			fprintf( outputStream, "\ncryptCreateContext() #%d failed with "
					 "status %d.\n", i, status );
			return( FALSE );
			}

		/* Destroy an earlier object to make sure that there are gaps in the 
		   LFSR coverage.  The code triggers once we've filled the first half 
		   of the handle array, destroying every tenth object */
		if( i > NO_OBJECTS / 2 && ( i % ( NO_OBJECTS / 10 ) ) == 0 )
			{
			const int objectIndex = i - ( NO_OBJECTS / 2 );
			
			status = cryptDestroyContext( handleArray[ objectIndex ] );
			if( cryptStatusError( status ) )
				{
				free( handleArray );
				fprintf( outputStream, "\ncryptDestroyContext() #%d failed "
						 "with status %d.\n", i, status );
				return( FALSE );
				}
			handleArray[ objectIndex ] = -1;
			}
		}
	fprintf( outputStream, "." );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		if( handleArray[ i ] == -1 )
			continue;
		status = cryptEncrypt( handleArray[ i ], "12345678", 8 );
		if( cryptStatusError( status ) )
			{
			free( handleArray );
			fprintf( outputStream, "\ncryptEncrypt() data #%d failed with "
					 "status %d.\n", i, status );
			return( FALSE );
			}
		}
	fprintf( outputStream, "." );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		if( handleArray[ i ] == -1 )
			continue;
		status = cryptEncrypt( handleArray[ i ], "", 0 );
		if( cryptStatusError( status ) )
			{
			free( handleArray );
			fprintf( outputStream, "\ncryptEncrypt() EOF #%d failed with "
					 "status %d.\n", i, status );
			return( FALSE );
			}
		}
	fprintf( outputStream, "." );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		if( handleArray[ i ] == -1 )
			continue;
		status = cryptGetAttributeString( handleArray[ i ],
								CRYPT_CTXINFO_HASHVALUE, hash, &length );
		if( cryptStatusError( status ) )
			{
			free( handleArray );
			fprintf( outputStream, "\ncryptEncrypt() (len.0) #%d failed "
					 "with status %d.\n", i, status );
			return( FALSE );
			}
		}
	fprintf( outputStream, "." );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		if( handleArray[ i ] == -1 )
			continue;
		status = cryptDestroyContext( handleArray[ i ] );
		if( cryptStatusError( status ) )
			{
			free( handleArray );
			fprintf( outputStream, "\ncryptDestroyContext() #%d failed with "
					 "status %d.\n", i, status );
			return( FALSE );
			}
		}
	free( handleArray );

	fputs( ".\nObject stress test succeeded.\n\n", outputStream );
	return( TRUE );
	}

static int testStressObjectsDetailed( void )
	{
	CRYPT_HANDLE handleArray[ 2 ];
	BYTE hash[ CRYPT_MAX_HASHSIZE ];
	int handleIndex = 0;
	int i, length, status;

	fputs( "Running detailed object stress test.\n", outputStream );
	handleArray[ 0 ] = handleArray[ 1 ] = -1;
	for( i = 0; i < 20000; i++ )
		{
		CRYPT_CONTEXT cryptContext;

		if( handleArray[ handleIndex ] != -1 )
			{
			status = cryptDestroyContext( handleArray[ handleIndex ] );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "cryptDestroyContext() #%d failed "
						 "with status %d.\n", i, status );
				return( FALSE );
				}
			}
		status = cryptCreateContext( &cryptContext, CRYPT_UNUSED,
									 DEFAULT_HASH_ALGO );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "\ncryptCreateContext() #%d failed with "
					 "status %d.\n", i, status );
			return( FALSE );
			}
		handleArray[ handleIndex ] = cryptContext;

		handleIndex = ( handleIndex + 1 ) & 1;

		if( handleArray[ handleIndex ] != -1 )
			{
			status = cryptEncrypt( handleArray[ handleIndex ], "12345678", 8 );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "\ncryptEncrypt() #%d failed with "
						 "status %d.\n", i, status );
				return( FALSE );
				}
			status = cryptEncrypt( handleArray[ handleIndex ], "", 0 );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "\ncryptEncrypt() #%d failed with "
						 "status %d.\n", i, status );
				return( FALSE );
				}
			status = cryptGetAttributeString( handleArray[ handleIndex ],
									CRYPT_CTXINFO_HASHVALUE, hash, &length );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "\ncryptEncrypt() (len.0) #%d failed "
						 "with status %d.\n", i, status );
				return( FALSE );
				}
			}
		}
	for( i = 0; i < 2; i++ )
		{
		status = cryptDestroyContext( handleArray[ i ] );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "\ncryptDestroyContext() #%d failed with "
					 "status %d.\n", i, status );
			return( FALSE );
			}
		}

	fputs( "Detailed object stress test succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Perform a socket-pool stress test.  This just fetches the same 
   certificate 200 times to make sure that recycling of sockets in the pool
   works.  Best run with the socket pool limited to 32 entries rather than
   the default 128 */

int testStressSocketPool( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	int i, status;

	fputs( "Running socket pool stress test.\n", outputStream );
	for( i = 0; i < 200; i++ )
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
					CRYPT_KEYSET_HTTP, 
					"http://cacerts.digicert.com/DigiCertTLSECCP384RootG5.crt",
					CRYPT_KEYOPT_READONLY );
		if( cryptStatusError( status ) )
			{
			printf( "cryptKeysetOpen() failed with error code %d, line "
					"%d.\n", status, __LINE__ );
			return( CRYPT_ERROR_FAILED );
			}
		status = cryptGetPublicKey( cryptKeyset, &cryptCert, 
									CRYPT_KEYID_NAME, "[none]" );
		cryptKeysetClose( cryptKeyset );
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( cryptKeyset, "cryptGetPublicKey()", 
								  status, __LINE__ ) );
			}
		cryptDestroyCert( cryptCert );
		fputc( '.', outputStream );
		}
	fputc( '\n', outputStream );

	fputs( "Socket pool stress test succeeded.\n\n", outputStream );
	return( TRUE );
	}

/****************************************************************************
*																			*
*								Data Processing Test						*
*																			*
****************************************************************************/

#ifdef TEST_SMOKETEST

/* Data processing test */

#define DATABUFFER_SIZE		2048
#define MAX_BLOCKS			16

#define roundUp( size, roundSize ) \
	( ( ( size ) + ( ( roundSize ) - 1 ) ) & ~( ( roundSize ) - 1 ) )

#ifdef __WINDOWS__
  typedef int ( __stdcall *CRYPT_FUNCTION )( const CRYPT_CONTEXT cryptContext,
											 void *data, const int length );
#else
  typedef int ( *CRYPT_FUNCTION )( const CRYPT_CONTEXT cryptContext,
								   void *data, const int length );
#endif /* __WINDOWS__ */

static int processData( const CRYPT_CONTEXT cryptContext, BYTE *buffer,
						const int noBlocks, const int blockSize,
						CRYPT_FUNCTION cryptFunction, const BOOLEAN isHash )
	{
	int offset = 0, i, status;

	/* Encrypt the data in variable-length blocks.  The technique for
	   selecting lengths isn't perfect since it tends to put large blocks
	   at the start and small ones at the end, but it's good enough for
	   general testing */
	for( i = 0; i < noBlocks - 1; i++ )
		{
		int noBytes = rand() % ( DATABUFFER_SIZE - offset - \
								 ( blockSize * ( noBlocks - i  ) ) );
		if( !noBytes )
			noBytes = 1;
		if( blockSize > 1 )
			noBytes = roundUp( noBytes, blockSize );
		status = cryptFunction( cryptContext, buffer + offset, noBytes );
		if( cryptStatusError( status ) )
			return( status );
		offset += noBytes;
		}
	status = cryptFunction( cryptContext, buffer + offset,
							DATABUFFER_SIZE - offset );
	if( cryptStatusOK( status ) && isHash )
		status = cryptFunction( cryptContext, "", 0 );
	return( status );
	}

static int testProcessing( const CRYPT_ALGO_TYPE cryptAlgo,
						   const CRYPT_MODE_TYPE cryptMode,
						   const CRYPT_QUERY_INFO cryptQueryInfo )
	{
	static const char *modeNames[] = {
		"hash/MAC", "ECB", "CBC", "CFB", "GCM", "NULL", "NULL"
		};
	BYTE buffer1[ DATABUFFER_SIZE ], buffer2[ DATABUFFER_SIZE ];
	BYTE hash1[ CRYPT_MAX_HASHSIZE ], hash2[ CRYPT_MAX_HASHSIZE ];
	const int blockSize = ( cryptMode == CRYPT_MODE_ECB || \
							cryptMode == CRYPT_MODE_CBC ) ? \
						  cryptQueryInfo.blockSize : 1;
	const BOOLEAN isHash = ( cryptAlgo >= CRYPT_ALGO_FIRST_HASH && \
							 cryptAlgo <= CRYPT_ALGO_LAST_HASH ) || \
						   ( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
							 cryptAlgo <= CRYPT_ALGO_LAST_MAC );
	int length1 DUMMY_INIT, length2 DUMMY_INIT, i;

	/* Initialise the buffers with a known data pattern */
	memset( buffer1, '*', DATABUFFER_SIZE );
	memcpy( buffer1, "12345678", 8 );
	memcpy( buffer2, buffer1, DATABUFFER_SIZE );

	/* Process the data using various block sizes */
	fprintf( outputStream, "Testing %s algorithm, mode %s, for %d-byte "
			 "buffer with\n  block count ", algoName( cryptAlgo ), 
			 modeNames[ cryptMode ], DATABUFFER_SIZE );
	for( i = 1; i <= MAX_BLOCKS; i++ )
		{
		CRYPT_CONTEXT cryptContext;
		int status;

		memcpy( buffer1, buffer2, DATABUFFER_SIZE );
		fprintf( outputStream, "%d%s ", i, ( i == MAX_BLOCKS ) ? "." : "," );

		/* Encrypt the data with random block sizes */
		status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptMode != CRYPT_MODE_NONE )
			{
			status = cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE,
										cryptMode );
			if( cryptStatusError( status ) )
				{
				cryptDestroyContext( cryptContext );
				return( status );
				}
			if( cryptMode != CRYPT_MODE_ECB && cryptAlgo != CRYPT_ALGO_RC4 )
				{
				const int ivSize = ( cryptAlgo == CRYPT_ALGO_CHACHA20 ) ? \
									 16 : cryptQueryInfo.blockSize;
								   /* ChaCha20 is a stream cipher but has a 
								      block-cipher-style IV */

				status = cryptSetAttributeString( cryptContext, 
												  CRYPT_CTXINFO_IV,
												  "1234567887654321", 
												  ivSize );
				if( cryptStatusError( status ) )
					{
					cryptDestroyContext( cryptContext );
					return( status );
					}
				}
			}
		if( cryptQueryInfo.keySize )
			{
			status = cryptSetAttributeString( cryptContext, 
											  CRYPT_CTXINFO_KEY,
											  "12345678876543211234567887654321",
											  cryptQueryInfo.keySize );
			if( cryptStatusError( status ) )
				{
				cryptDestroyContext( cryptContext );
				return( status );
				}
			}
		status = processData( cryptContext, buffer1, i, blockSize,
							  cryptEncrypt, isHash );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( cryptContext );
			return( status );
			}
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			status = cryptGetAttributeString( cryptContext,
								CRYPT_CTXINFO_HASHVALUE, hash1, &length1 );
			if( cryptStatusError( status ) )
				{
				cryptDestroyContext( cryptContext );
				return( status );
				}
			}
		status = cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			return( status );

		/* Decrypt the data again with random block sizes */
		status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptMode != CRYPT_MODE_NONE )
			{
			status = cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE,
										cryptMode );
			if( cryptStatusError( status ) )
				{
				cryptDestroyContext( cryptContext );
				return( status );
				}
			if( cryptMode != CRYPT_MODE_ECB && cryptAlgo != CRYPT_ALGO_RC4 )
				{
				const int ivSize = ( cryptAlgo == CRYPT_ALGO_CHACHA20 ) ? \
									 16 : cryptQueryInfo.blockSize;

				status = cryptSetAttributeString( cryptContext, 
												  CRYPT_CTXINFO_IV,
												  "1234567887654321", 
												  ivSize );
				if( cryptStatusError( status ) )
					{
					cryptDestroyContext( cryptContext );
					return( status );
					}
				}
			}
		if( cryptQueryInfo.keySize )
			{
			status = cryptSetAttributeString( cryptContext, 
											  CRYPT_CTXINFO_KEY,
											  "12345678876543211234567887654321",
											  cryptQueryInfo.keySize );
			if( cryptStatusError( status ) )
				{
				cryptDestroyContext( cryptContext );
				return( status );
				}
			}
		status = processData( cryptContext, buffer1, i, blockSize,
							  isHash ? cryptEncrypt : cryptDecrypt, isHash );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( cryptContext );
			return( status );
			}
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			status = cryptGetAttributeString( cryptContext,
								CRYPT_CTXINFO_HASHVALUE, hash2, &length2 );
			if( cryptStatusError( status ) )
				{
				cryptDestroyContext( cryptContext );
				return( status );
				}
			}
		status = cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			return( status );

		/* Make sure the values match */
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			if( ( length1 != length2 ) || memcmp( hash1, hash2, length1 ) )
				{
				fputs( "Error: Hash value of identical buffers differs.", 
					   outputStream );
				return( -1234 );
				}
			}
		else
			{
			if( !checkTestBuffers( buffer1, buffer2, DATABUFFER_SIZE ) )
				return( -1234 );
			}
		}
	fputs( "\n", outputStream );

	return( CRYPT_OK );
	}

static int testDataProcessing( void )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	CRYPT_ALGO_TYPE cryptAlgo;
	int errorCount = 0, status;

	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo,
												 &cryptQueryInfo ) ) )
			{
			if( cryptAlgo != CRYPT_ALGO_RC4 && \
				cryptAlgo != CRYPT_ALGO_CHACHA20 )
				{
				status = testProcessing( cryptAlgo, CRYPT_MODE_ECB,
										 cryptQueryInfo );
				if( cryptStatusError( status ) )
					{
					fprintf( outputStream, "\n%s-ECB processing failed "
							 "with status %d.\n", algoName( cryptAlgo ), 
							 status );
					if( status == CRYPT_ERROR_NOTAVAIL )
						{
						fputs( "  (This appears to be due to the mode not "
							   "being available).\n", outputStream );
						}
					else
						errorCount++;
					}
				status = testProcessing( cryptAlgo, CRYPT_MODE_CBC,
										 cryptQueryInfo );
				if( cryptStatusError( status ) )
					{
					fprintf( outputStream, "\n%s-CBC processing failed "
							 "with status %d.\n", algoName( cryptAlgo ), 
							 status );
					if( status == CRYPT_ERROR_NOTAVAIL )
						{
						fputs( "  (This appears to be due to the mode not "
							   "being available).\n", outputStream );
						}
					else
						errorCount++;
					}
				if( cryptAlgo == CRYPT_ALGO_AES )
					{
					status = testProcessing( cryptAlgo, CRYPT_MODE_GCM,
											 cryptQueryInfo );
					if( cryptStatusError( status ) )
						{
						fprintf( outputStream, "\n%s-GCM processing failed "
								 "with status %d.\n", algoName( cryptAlgo ), 
								 status );
						if( status == CRYPT_ERROR_NOTAVAIL )
							{
							fputs( "  (This appears to be due to the mode "
								   "not being available).\n", outputStream );
							}
						else
							errorCount++;
						}
					}
				}
			status = testProcessing( cryptAlgo, CRYPT_MODE_CFB,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "\n%s-CFB processing failed with "
						 "status %d.\n", algoName( cryptAlgo ), status );
				if( status == CRYPT_ERROR_NOTAVAIL )
					{
					fputs( "  (This appears to be due to the mode not being "
						   "available).\n", outputStream );
					}
				else
					errorCount++;
				}
			}
		}
	if( errorCount )
		{
		fprintf( outputStream, "%d encryption error%s detected.\n", 
				 errorCount, ( errorCount > 1 ) ? "s" : "" );
		return( FALSE );
		}

	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, 
												 &cryptQueryInfo ) ) )
			{
			status = testProcessing( cryptAlgo, CRYPT_MODE_NONE,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "\n%s processing failed with status "
						 "%d.\n", algoName( cryptAlgo ), status );
				errorCount++;
				}
			}
		}
	if( errorCount )
		{
		fprintf( outputStream, "%d hashing error%s detected.\n", 
				 errorCount, ( errorCount > 1 ) ? "s" : "" );
		return( FALSE );
		}

	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, 
												 &cryptQueryInfo ) ) )
			{
			status = testProcessing( cryptAlgo, CRYPT_MODE_NONE,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "\n%s processing failed with status "
						 "%d.\n", algoName( cryptAlgo ), status );
				errorCount++;
				}
			}
		}
	if( errorCount )
		{
		fprintf( outputStream, "%d MACing error%s detected.\n", 
				 errorCount, ( errorCount > 1 ) ? "s" : "" );
		return( FALSE );
		}
	fputs( "\n", outputStream );

	return( TRUE );
	}
#endif /* TEST_SMOKETEST */

/****************************************************************************
*																			*
*								Kernel Check Test							*
*																			*
****************************************************************************/

/* Kernel check test */

static void smokeTestAttributes( const CRYPT_HANDLE cryptHandle )
	{
	int attribute;

	/* Unlike other pass-or-fail tests this test doesn't check results but 
	   merely throws attributes at an object to see if any exceptions are
	   triggered, so there's no checking of return values or similar */
	fprintf( outputStream, "." );
	for( attribute = CRYPT_ATTRIBUTE_NONE; attribute < 8000; attribute++ )
		{
		char buffer[ 1024 ];
		int value;

		( void ) cryptGetAttribute( cryptHandle, attribute, &value );
		( void ) cryptGetAttributeString( cryptHandle, attribute, buffer, 
										  &value );
		}
	cryptDestroyObject( cryptHandle );
	}

static int testKernelChecks( void )
	{
	CRYPT_HANDLE cryptHandle;
	int subType, status;

	fputs( "\nTesting kernel attribute handling...\n", outputStream );
	status = cryptCreateContext( &cryptHandle, CRYPT_UNUSED, 
								 CRYPT_ALGO_RESERVED1 );
	if( cryptStatusOK( status ) )
		{
		cryptDestroyObject( cryptHandle );
		fprintf( outputStream, "Creation of reserved context type %d "
				 "succeeded, should have failed", CRYPT_ALGO_RESERVED1 );
		return( FALSE );
		}
	status = cryptDeviceOpen( &cryptHandle, CRYPT_UNUSED, 
							  CRYPT_DEVICE_LAST, "Test" );
	if( cryptStatusOK( status ) )
		{
		cryptDestroyObject( cryptHandle );
		fprintf( outputStream, "Creation of reserved device type %d "
				 "succeeded, should have failed", CRYPT_DEVICE_LAST );
		return( FALSE );
		}
	status = cryptCreateEnvelope( &cryptHandle, CRYPT_UNUSED, 
								  CRYPT_FORMAT_PGP + 1 );
	if( cryptStatusOK( status ) )
		{
		cryptDestroyObject( cryptHandle );
		fprintf( outputStream, "Creation of reserved envelope type %d "
				 "succeeded, should have failed", CRYPT_FORMAT_PGP + 1 );
		return( FALSE );
		}
	fprintf( outputStream, "  Contexts: " );
	for( subType = 0; subType < 500; subType++ )
		{
		if( cryptStatusOK( cryptCreateContext( &cryptHandle, CRYPT_UNUSED,
											   subType ) ) )
			smokeTestAttributes( cryptHandle );
		}
	fprintf( outputStream, "\n  Certs: " );
	for( subType = 0; subType < 500; subType++ )
		{
		if( cryptStatusOK( cryptCreateCert( &cryptHandle, CRYPT_UNUSED,
											subType ) ) )
			smokeTestAttributes( cryptHandle );
		}
	fprintf( outputStream, "\n  Envelopes: " );
	for( subType = 0; subType < 500; subType++ )
		{
		if( cryptStatusOK( cryptCreateEnvelope( &cryptHandle, CRYPT_UNUSED,
												subType ) ) )
			smokeTestAttributes( cryptHandle );
		}
	fprintf( outputStream, "\n  Sessions: " );
	for( subType = 0; subType < 500; subType++ )
		{
		if( cryptStatusOK( cryptCreateSession( &cryptHandle, CRYPT_UNUSED,
											   subType ) ) )
			smokeTestAttributes( cryptHandle );
		}

	fputs( "\nKernel attribute handling tests succeeded.\n", 
		   outputStream );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Simple Threading Stress Test					*
*																			*
****************************************************************************/

/* Multi-threaded processing stress test.  In order to add a little
   nondeterminism on single-threaded machines, we need to add some sleep()
   calls between crypto operations.  Even this isn't perfect, there's no
   real way to guarantee that they aren't simply executed in round-robin
   fashion with only one thread in the kernel at a time without modifying
   the kernel to provide diagnostic info */

#if defined( WINDOWS_THREADS ) && 1

#define NO_SIMPLE_THREADS	10

static void randSleep( void )
	{
	Sleep( ( rand() % 150 ) + 1 );
	}

unsigned __stdcall processDataThread( void *arg )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE buffer[ 1024 ];
	int threadNo = ( int ) arg;
	int status;

	randSleep();
	memset( buffer, '*', 1024 );
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED,
								 DEFAULT_CRYPT_ALGO );
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
										  "123456781234567812345678", 24 );
		}
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptEncrypt( cryptContext, buffer, 1024 );
		}
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptDestroyContext( cryptContext );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "\nEncryption failed with status %d.\n", 
				 status );
		}
	else
		fprintf( outputStream, "%d ", threadNo );

	_endthreadex( 0 );
	return( 0 );
	}

void testStressThreadsSimple( void )
	{
	HANDLE hThreads[ NO_SIMPLE_THREADS ];
	int i;

	/* Start the threads */
	fprintf( outputStream, "Starting %d threads.\n  ", NO_SIMPLE_THREADS );
	for( i = 0; i < NO_SIMPLE_THREADS; i++ )
		{
		unsigned threadID;

		hThreads[ i ] = ( HANDLE ) \
			_beginthreadex( NULL, 0, &processDataThread, ( void * ) i, 0,
							&threadID );
		if( hThreads[ i ] == 0 )
			fprintf( outputStream, "Thread %d couldn't be created.\n", i );
		else
			{
			fprintf( outputStream, "%d = %lX%s", i, threadID, 
					 ( i < NO_SIMPLE_THREADS - 1 ) ? ", " : "" );
			}
		}
	fputs( ".\n  Finished: ", outputStream );

	/* Wait for all the threads to complete */
	if( WaitForMultipleObjects( NO_SIMPLE_THREADS, hThreads, TRUE,
								15000 ) == WAIT_TIMEOUT )
		fputs( "\nNot all threads completed in 15s.", outputStream );
	else
		{
		fprintf( outputStream, "\nAll %d threads completed.\n", 
				 NO_SIMPLE_THREADS );
		}
	for( i = 0; i < NO_SIMPLE_THREADS; i++ )
		CloseHandle( hThreads[ i ] );
	}
#endif /* WINDOWS_THREADS */

/****************************************************************************
*																			*
*							Complex Threading Stress Test					*
*																			*
****************************************************************************/

/* Unlike the previous test, there's enough nondeterminism added in this one
   that things go out of sync all by themselves */

#ifdef WINDOWS_THREADS

#define NO_COMPLEX_THREADS	5

unsigned __stdcall signTest( void *arg ) 
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT privateKeyContext;
	CRYPT_ENVELOPE cryptEnvelope;
	BYTE buffer[ 1024 ];
	const int count = *( ( int * ) arg );
	int bytesCopied, i, status;

	fprintf( outputStream, "SignTest %d.\n", count );

	for( i = 0; i < count; i++ ) 
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
								  CRYPT_KEYSET_FILE, TEST_PRIVKEY_FILE, 
								  CRYPT_KEYOPT_READONLY);
		if( cryptStatusOK( status ) )
			{
			status = cryptGetPrivateKey( cryptKeyset, &privateKeyContext, 
										 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL, 
										 TEST_PRIVKEY_PASSWORD );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED, 
										  CRYPT_FORMAT_CMS );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptEnvelope, 
										CRYPT_ENVINFO_SIGNATURE, 
										privateKeyContext );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptPushData( cryptEnvelope, "message", 7, 
									&bytesCopied );
			}
		if( cryptStatusOK( status ) )
			status = cryptFlushData( cryptEnvelope );
		if( cryptStatusOK( status ) )
			{
			status = cryptPopData( cryptEnvelope, buffer, 1024, 
									&bytesCopied );
			}
		if( cryptStatusOK( status ) )
			status = cryptDestroyContext( privateKeyContext );
		if( cryptStatusOK( status ) )
			status = cryptKeysetClose( cryptKeyset );
		if( cryptStatusOK( status ) )
			status = cryptDestroyEnvelope( cryptEnvelope );
		if( cryptStatusError( status ) )
			{
			_endthreadex( status );
			return( 0 );
			}
		}

	_endthreadex( 0 );
	return( 0 );
	}

unsigned __stdcall encTest( void *arg ) 
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CERTIFICATE cryptCert;
	BYTE fileBuffer[ BUFFER_SIZE ], buffer[ 1024 ];
	const int count = ( int ) arg;
	int bytesCopied, i, status;

	fprintf( outputStream, "EncTest %d.\n", count );
	filenameFromTemplate( fileBuffer, CERT_FILE_TEMPLATE, 13 );

	for( i = 0; i < count; i++ ) 
		{
		status = importCertFile( &cryptCert, fileBuffer );
		if( cryptStatusOK( status ) )
			{
			status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED, 
										  CRYPT_FORMAT_CMS );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptEnvelope, 
										CRYPT_ENVINFO_PUBLICKEY, 
										cryptCert );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptPushData( cryptEnvelope, buffer, 200, 
									&bytesCopied );
			}
		if( cryptStatusOK( status ) )
			status = cryptFlushData( cryptEnvelope );
		if( cryptStatusOK( status ) )
			{
			status = cryptPopData( cryptEnvelope, buffer, 1024, 
								   &bytesCopied );
			}
		if( cryptStatusOK( status ) )
			status = cryptDestroyCert( cryptCert );
		if( cryptStatusOK( status ) )
			status = cryptDestroyEnvelope( cryptEnvelope );
		if( cryptStatusError( status ) )
			{
			fputs( "Enveloping test failed.\n", outputStream );
			_endthreadex( status );
			return( 0 );
			}
		}

	_endthreadex( 0 );
	return( 0 );
	}

#if ( defined( UNIX_THREADS ) || defined( WINDOWS_THREADS ) ) && 0

#ifdef UNIX_THREADS
  static void *envelopeDataThread( void *arg )
#else
  static unsigned __stdcall envelopeDataThread( void *arg )
#endif /* Different threading models */
	{
	static const char *envData = "qwertyuiopasdfghjklzxcvbnm";
	BYTE fileBuffer[ BUFFER_SIZE ];
	const unsigned uThread = ( unsigned ) arg;
	const time_t startTime = time( NULL );
	int count, status;

	fprintf( outputStream, "Thread %ud started.\n", uThread );
	fflush( stdout );

	filenameFromTemplate( fileBuffer, CERT_FILE_TEMPLATE, 13 );

	for( count = 0; count < 150; count++ )
		{
		CRYPT_ENVELOPE cryptEnvelope DUMMY_INIT;
		CRYPT_CERTIFICATE cryptCert;
		BYTE envBuffer[ BUFFER_SIZE ];
		int bytesCopied;

		/* Create the cert and envelope and add the cert to the envelope */
		status = importCertFile( &cryptCert, fileBuffer );
		if( cryptStatusOK( status ) )
			{
			status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED,
										  CRYPT_FORMAT_CRYPTLIB );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptEnvelope,
										CRYPT_ENVINFO_PUBLICKEY, 
										cryptCert );
			}
		if( cryptStatusError( status ) )
			break;

		/* Envelope data and destroy the envelope */
		status = cryptPushData( cryptEnvelope, envData, strlen( envData ),
								&bytesCopied );
		if( cryptStatusOK( status ) )
			status = cryptFlushData( cryptEnvelope );
		if( cryptStatusOK( status ) )
			{
			status = cryptPopData( cryptEnvelope, envBuffer, BUFFER_SIZE,
									&bytesCopied );
			}
		if( cryptStatusOK( status ) )
			status = cryptDestroyEnvelope( cryptEnvelope );
		if( cryptStatusError( status ) )
			break;
		fprintf( outputStream, "%c", uThread + '0' );
		}

	fprintf( outputStream, "Thread %u exited after %d seconds.\n", 
			 uThread, ( int ) ( time( NULL ) - startTime ) );
	fflush( stdout );
#ifdef UNIX_THREADS
	pthread_exit( NULL );
#else
	_endthreadex( 0 );
#endif /* Different threading models */
	return( 0 );
	}
#endif /* UNIX_THREADS || WINDOWS_THREADS */

void testStressThreadsComplex( void ) 
	{
	HANDLE hThreads[ NO_COMPLEX_THREADS ];
	int count = 0, i;

	cryptAddRandom( NULL, CRYPT_RANDOM_SLOWPOLL );

	/* Start off the initial set of threads */
	for( i = 0; i < 5; i++ )
		{
		unsigned dwThreadId;

		hThreads[ i ] = ( HANDLE ) \
			_beginthreadex( NULL, 0, encTest, ( void * ) count, 0, 
							&dwThreadId );
		count++;
		if( hThreads[ i ] == 0 )
			{
			fprintf( outputStream, 
					 "Initial thread %d couldn't be created.\n", count );
			}
		}

	/* Run a total of 100 threads */
	for( i = 0; i < 100; i++ )
		{
		DWORD ret;
		unsigned dwThreadId;

		ret = WaitForMultipleObjects( NO_COMPLEX_THREADS, hThreads, FALSE, 
									  INFINITE );
		if( ret >= WAIT_OBJECT_0 && \
			ret < WAIT_OBJECT_0 + NO_COMPLEX_THREADS )
			{
			const int threadIndex = ret - WAIT_OBJECT_0;

			CloseHandle( hThreads[ threadIndex ] );
			hThreads[ threadIndex ] = ( HANDLE ) \
				_beginthreadex( NULL, 0, encTest, ( void * ) count, 0, 
								&dwThreadId );
			count++;
			if( hThreads[ threadIndex ] == 0 )
				{
				fprintf( outputStream, 
						 "Thread %d couldn't be created.\n", count );
				}
			continue;
			}

		printf( "WaitForMultipleObjects() returned %lX.\n", ret );
		}

	WaitForMultipleObjects( NO_COMPLEX_THREADS, hThreads, TRUE, INFINITE );
	}
#endif /* WINDOWS_THREADS */

/****************************************************************************
*																			*
*									Test Interface							*
*																			*
****************************************************************************/

int testSmokeTestKernel( void )
	{
	/* The first set of tests is a type of fuzz-test of the kernel so 
	   there's no return value, any problem will result in an exception 
	   being triggered */
	testKernelChecks();
	if( !testStressObjects() )
		return( FALSE );
	
	return( TRUE );
	}

#ifdef TEST_SMOKETEST

int testSmokeTestObjects( void )
	{
	if( !testStressObjectsDetailed() )
		return( FALSE );
	if( !testDataProcessing() )
		return( FALSE );
#if defined( WINDOWS_THREADS )
	testStressThreadsSimple();
  #if 0
	testStressThreadsComplex();
  #endif /* 0 */
#endif /* WINDOWS_THREADS */

	return( TRUE );
	}
#else

BOOLEAN testSmokeTestObjects( void )
	{
	fputs( "Skipping smoke test of objects...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_SMOKETEST */
