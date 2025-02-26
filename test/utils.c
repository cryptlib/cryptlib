/****************************************************************************
*																			*
*					  cryptlib Self-test Utility Routines					*
*						Copyright Peter Gutmann 1997-2019					*
*																			*
****************************************************************************/

#include <ctype.h>
#include "cryptlib.h"
#include "test/test.h"

/* Various features can be disabled by configuration options, in order to 
   handle this we need to include the cryptlib config file so that we can 
   selectively disable some tests.
   
   Note that this checking isn't perfect, if cryptlib is built in release
   mode but we include misc/config.h here in debug mode then the defines 
   won't match up because the use of debug mode enables extra options that 
   won't be enabled in the release-mode cryptlib.  The checkLibraryIsDebug()
   function can be used to detect this debug/release mismatch and warn about
   self-test failures if one is found */
#include "misc/config.h"	/* For algorithm usage */
#include "misc/consts.h"	/* For DEFAULT_CRYPT_ALGO */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */
#ifdef HAS_WIDECHAR
  #include <wchar.h>
#endif /* HAS_WIDECHAR */
#ifndef NDEBUG
  #include "misc/config.h"
#endif /* NDEBUG */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

#ifndef _WIN32_WCE

/* Since ctime() adds a '\n' to the string and may return NULL, we wrap it
   in something that behaves as required */

char *getTimeString( const time_t theTime, const int bufNo )
	{
	static char timeString[ 2 ][ 64 ], *timeStringPtr;

	assert( bufNo == 0 || bufNo == 1 );

	timeStringPtr = ctime( &theTime );
	if( timeStringPtr == NULL )
		return( "(Not available)" );
	strcpy( timeString[ bufNo ], timeStringPtr );
	timeString[ bufNo ][ strlen( timeStringPtr ) - 1 ] = '\0';	/* Stomp '\n' */

	return( timeString[ bufNo ] );
	}
#endif /* _WIN32_WCE */

/****************************************************************************
*																			*
*							General Checking Functions						*
*																			*
****************************************************************************/

/* Check that external network sites are accessible, used to detect 
   potential problems with machines stuck behind firewalls */

int checkNetworkAccess( void )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* First we try for Microsoft's NCSI (Network Connection Status Icon) 
	   site, a canary site used by Windows to check for network connectivity
	   that has high availability and is unlikely to be blocked.  If that
	   fails we try for a well-known site, Amazon, as a fallback */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_HTTP,
							  TEXT( "http://www.msftncsi.com" ), 
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		return( TRUE );
		}
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_HTTP,
							  TEXT( "http://www.amazon.com" ), 
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		return( TRUE );
		}

	return( FALSE );
	}

/* Check whether cryptlib has been built in debug or release mode */

int checkLibraryIsDebug( void )
	{
	C_CHR buffer[ 256 ];
	int length, status;

	/* Get the description string and see whether it mentions a debug 
	   build */
	status = cryptGetAttributeString( CRYPT_UNUSED, 
									  CRYPT_OPTION_INFO_DESCRIPTION, 
									  buffer, &length );
	if( cryptStatusError( status ) )
		return( FALSE );
	buffer[ length ] = '\0';
	if( strstr( buffer, "debug" ) != NULL || \
		strstr( buffer, "Debug" ) != NULL )
		return( TRUE );

	return( FALSE );
	}

/* Check whether a database keyset is available, required for some of the
   server tests that use them for authentication */

int checkDatabaseKeysetAvailable( void )
	{
	static int keysetAvailable = CRYPT_ERROR;
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* If we've got a cached result, return that */
	if( keysetAvailable != CRYPT_ERROR )
		return( keysetAvailable );

	/* Try and open the database keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		cryptKeysetClose( status );
		keysetAvailable = TRUE;
		return( TRUE );
		}

	keysetAvailable = FALSE;
	return( FALSE );
	}

/****************************************************************************
*																			*
*							Error-handling Functions						*
*																			*
****************************************************************************/

/* Exit with a message about an unsupported algorithm/mechanism.  This 
   returns a value of TRUE to allow it to be used as:

	if( status == CRYPT_ERROR_NOTAVAIL )
		return( exitUnsupportedAlgo( "RSA", "signing" ) ); */

int exitUnsupportedAlgo( const CRYPT_ALGO_TYPE cryptAlgo, 
						 const char *mechanismName )
	{
	fprintf( outputStream, "Couldn't run %s tests because %s isn't\n"
			 "  enabled, skipping tests...\n\n", mechanismName, 
			 algoName( cryptAlgo ) );
	return( TRUE );
	}

/* Print extended error attribute information */

void printErrorAttributeInfo( const CRYPT_HANDLE cryptHandle )
	{
	static const char *errorTypeString[] = {
		"CRYPT_ERRTYPE_NONE", "CRYPT_ERRTYPE_ATTR_SIZE", 
		"CRYPT_ERRTYPE_ATTR_VALUE", "CRYPT_ERRTYPE_ATTR_ABSENT",
		"CRYPT_ERRTYPE_ATTR_PRESENT", "CRYPT_ERRTYPE_CONSTRAINT",
		"CRYPT_ERRTYPE_ISSUERCONSTRAINT", "NULL", "NULL"
		};
	const char *typeString = "<<<Unknown>>>";
	int errorType, errorLocus, status;

	status = cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_ERRORTYPE,
								&errorType );
	if( cryptStatusError( status ) )
		return;
	if( errorType >= CRYPT_ERRTYPE_NONE && \
		errorType < CRYPT_ERRTYPE_LAST )
		{
		typeString = errorTypeString[ errorType ];
		}
	status = cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_ERRORLOCUS, 
								&errorLocus );
	if( cryptStatusError( status ) )
		return;
	if( errorLocus == CRYPT_ATTRIBUTE_NONE && \
		errorType == CRYPT_ERRTYPE_NONE )
		return;
	fprintf( outputStream, "  Error info attributes report locus %d, type "
			 "%d (%s).\n", errorLocus, errorType, typeString );
	}

/* Print extended object error information */

static void printExtErrorInfo( const CRYPT_HANDLE cryptHandle )
	{
	char errorMessage[ 512 ];
	int errorMessageLength, status;

	status = cryptGetAttributeString( cryptHandle, CRYPT_ATTRIBUTE_ERRORMESSAGE,
									  errorMessage, &errorMessageLength );
	if( cryptStatusError( status ) )
		{
		fputs( "  No extended error information available.\n", 
			   outputStream );
		return;
		}
	errorMessage[ errorMessageLength ] = '\0';
	fprintf( outputStream, "  Error message = %s'%s'.\n",
			 ( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
			 errorMessage );
	}

void printExtError( const CRYPT_HANDLE cryptHandle,
					const char *functionName, const int errorCode,
					const int lineNumber )
	{
	if( functionName != NULL )
		{
		fprintf( outputStream, "%s failed with error code %d, line %d.\n", 
				 functionName, errorCode, lineNumber );
		}
	printExtErrorInfo( cryptHandle );
	printErrorAttributeInfo( cryptHandle );
	}

/* Exit with an error message, printing extended error information if 
   available */

BOOLEAN extErrorExit( const CRYPT_HANDLE cryptHandle,
					  const char *functionName, const int errorCode,
					  const int lineNumber )
	{
	printExtError( cryptHandle, functionName, errorCode, lineNumber );
	cryptDestroyObject( cryptHandle );
	return( FALSE );
	}

/****************************************************************************
*																			*
*								Misc. Functions								*
*																			*
****************************************************************************/

/* Some algorithms can be disabled to eliminate patent problems or reduce the
   size of the code.  The following functions are used to select generally
   equivalent alternatives if the required algorithm isn't available.  These
   selections make certain assumptions, namely that at least one of the
   algorithms in the fallback chain is always available (which is guaranteed,
   DEFAULT_CRYPT_ALGO is always present), and that they have the same general 
   properties as the algorithms they're replacing, which is also usually the 
   case, with CAST being a first-instance substitute for IDEA or RC2 and
   then 3DES or AES as the fallback if CAST isn't available */

CRYPT_ALGO_TYPE selectCipher( const CRYPT_ALGO_TYPE algorithm )
	{
	if( cryptStatusOK( cryptQueryCapability( algorithm, NULL ) ) )
		return( algorithm );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_CAST, NULL ) ) )
		return( CRYPT_ALGO_CAST );
	return( DEFAULT_CRYPT_ALGO );
	}

/* Similarly, for many of the PKC and certificate tests we just need a 
   generic PKC algorithm, the following function selects one in order of
   likelihood of it being present and enabled: RSA, DSA, ECDSA */

CRYPT_ALGO_TYPE getDefaultPkcAlgo( void )
	{
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RSA, NULL ) ) )
		return( CRYPT_ALGO_RSA );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_DSA, NULL ) ) )
		return( CRYPT_ALGO_DSA );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) )
		return( CRYPT_ALGO_ECDSA );

	return( CRYPT_ALGO_NONE );
	}

BOOLEAN loadPkcContexts( CRYPT_CONTEXT *pubKeyContext,
						 CRYPT_CONTEXT *privKeyContext )
	{
	switch( getDefaultPkcAlgo() )
		{
		case CRYPT_ALGO_RSA:
			return( loadRSAContexts( CRYPT_UNUSED, pubKeyContext, 
									 privKeyContext ) );

		case CRYPT_ALGO_DSA:
			return( loadDSAContexts( CRYPT_UNUSED, pubKeyContext, 
									  privKeyContext ) );

		case CRYPT_ALGO_ECDSA:
			return( loadECDSAContexts( CRYPT_UNUSED, pubKeyContext, 
									   privKeyContext ) );

		default:
			return( FALSE );
		}

	return( FALSE );
	}

/* Return an algorithm name */

const char *algoName( const CRYPT_ALGO_TYPE algorithm )
	{
	static const char *cryptNames[] = { 	
		"DES", "3DES", "IDEA", "CAST", "RC2", "RC4", "NULL", "AES", 
		"NULL", "ChaCha20", "NULL", "NULL"
		};
	static const char *pkcNames[] = {
		"DH", "RSA", "DSA", "ElGamal", "NULL", "ECDSA", "ECDH", "EDDSA", "Curve25519", 
		"NULL", "NULL"
		};
	static const char *hashNames[] = { 	
		"NULL", "NULL", "MD5", "SHA1", "NULL", "SHA2", "SHAng", "NULL",
		"NULL"
		};
	static const char *macNames[] = { 	
		"NULL", "HMAC-SHA1", "NULL", "HMAC-SHA2", "HMAC-SHAng", "Poly1305",
		"NULL", "NULL"
		};

	if( algorithm >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		algorithm <= CRYPT_ALGO_LAST_CONVENTIONAL )
		return( cryptNames[ algorithm - CRYPT_ALGO_FIRST_CONVENTIONAL ] );
	if( algorithm >= CRYPT_ALGO_FIRST_PKC && \
		algorithm <= CRYPT_ALGO_LAST_PKC )
		return( pkcNames[ algorithm - CRYPT_ALGO_FIRST_PKC ] );
	if( algorithm >= CRYPT_ALGO_FIRST_HASH && \
		algorithm <= CRYPT_ALGO_LAST_HASH )
		return( hashNames[ algorithm - CRYPT_ALGO_FIRST_HASH ] );
	if( algorithm >= CRYPT_ALGO_FIRST_MAC && \
		algorithm <= CRYPT_ALGO_LAST_MAC )
		return( macNames[ algorithm - CRYPT_ALGO_FIRST_MAC ] );

	return( "Unknown" );
	}

/* Display hex strings in various forms.  For the fixed-length options we 
   assemble them as a single string and output them in one go to avoid them 
   being broken up by output from another thread */

void printHex( const char *prefix, const BYTE *value, const int length )
	{
	char buffer[ 4096 ];
	int pos = 0, i;

	for( i = 0; i < min( length, 1024 ); i += 16 )
		{
		const int innerLen = min( length - i, 16 );
		int j;

		/* In the following, the redundant "%s" is needed for gcc */
		pos += sprintf( buffer + pos, "%s", prefix );
		for( j = 0; j < innerLen; j++ )
			pos += sprintf( buffer + pos, "%02X ", value[ i + j ] );
		for( ; j < 16; j++ )
			pos += sprintf( buffer + pos, "   " );
		for( j = 0; j < innerLen; j++ )
			{
			const BYTE ch = value[ i + j ];

			pos += sprintf( buffer + pos, "%c", isprint( ch ) ? ch : '.' );
			}
		pos += sprintf( buffer + pos, "\n" );
		}

	fprintf( outputStream, "%s", buffer );
	}

/* Helper function to dump hex data */

void dumpHexDataPart( const BYTE *data, const int dataLen )
	{
	char buffer[ 4096 ];
	int offset = 0, i;

	/* If it's 36 bytes or less (to fit on an 80-column display) then we 
	   output the entire quantity */
	if( dataLen <= 36 )
		{
		for( i = 0; i < dataLen - 1; i++ )
			offset += sprintf( buffer + offset, "%02X ", data[ i ] );
		sprintf( buffer + offset, "%02X", data[ i ] );
		}
	else
		{
		/* It's more than 36 bytes, only output the first and last 18 
		   bytes */
		for( i = 0; i < 18; i++ )
			offset += sprintf( buffer + offset, "%02X ", data[ i ] );
		offset += sprintf( buffer + offset, "... " );
		for( i = dataLen - 18; i < dataLen - 1; i++ )
			offset += sprintf( buffer + offset, "%02X ", data[ i ] );
		sprintf( buffer + offset, "%02X", data[ dataLen - 1 ] );
		}

	fprintf( outputStream, "%s", buffer );
	}

void dumpHexData( const BYTE *data, const int dataLen )
	{
	int i;

	for( i = 0; i < dataLen - 1; i++ )
		{
		if( i > 0 && ( i % 16 ) == 0 )
			fprintf( outputStream, "\n" );
		fprintf( outputStream, "%02X ", data[ i ] );
		}
	fprintf( outputStream, "%02X", data[ i ] );
	}

/* Test harness for running the self-tests */

BOOLEAN runTests( const TEST_FUNCTION_INFO *testFunctionInfo )
	{
	int i;

	for( i = 0; testFunctionInfo[ i ].testFunction != NULL; i++ )
		{
		const CRYPT_ALGO_TYPE cryptoAlgoConditional = \
						testFunctionInfo[ i ].cryptoAlgoConditional;

		/* If the test is conditional on a particular algorithm being 
		   enabled and it's not available, skip it */
		if( cryptoAlgoConditional != CRYPT_ALGO_NONE && \
			cryptStatusError( \
				cryptQueryCapability( cryptoAlgoConditional, NULL ) ) )
			{
			fprintf( outputStream, "Skipping %s() because the required "
					 "algorithm isn't available.\n\n", 
					 testFunctionInfo[ i ].testFunctionName );
			continue;
			}

		/* If the test is conditional on real, rather than emulated, crypto
		   being available and we're running with emulated crypto, skip 
		   it */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		if( testFunctionInfo[ i ].failEmulatedConditional )
			{
			fprintf( outputStream, "Skipping %s() because it requires "
					 "real, not emulated, crypto.\n\n", 
					 testFunctionInfo[ i ].testFunctionName );
			continue;
			}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

		if( !testFunctionInfo[ i ].testFunction() )
			{
			fprintf( outputStream, "\nTest of %s() failed.\n", 
					 testFunctionInfo[ i ].testFunctionName );
			return( FALSE );
			}
		}

	return( TRUE );
	}

/* Compare two blocks and data and check whether they're identical */

int compareData( const void *origData, const int origDataLength,
				 const void *recovData, const int recovDataLength )
	{
	if( origDataLength != recovDataLength )
		{
		fprintf( outputStream, "Original length %d doesn't match recovered "
				 "data length %d.\n", origDataLength, recovDataLength );

		return( FALSE );
		}
	if( memcmp( origData, recovData, origDataLength ) )
		{
		int i;

		for( i = 0; i < origDataLength; i++ )
			{
			if( ( ( BYTE * ) origData )[ i ] != ( ( BYTE * ) recovData )[ i ] )
				break;
			}
		fprintf( outputStream, "Data of length %d doesn't match recovered "
				 "data starting at %d:\n", origDataLength, i );
		fprintf( outputStream, "Original data:\n" );
		printHex( "  ", origData, min( origDataLength, 64 ) );
		fprintf( outputStream, "Recovered data:\n" );
		printHex( "  ", recovData, min( origDataLength, 64 ) );

		return( FALSE );
		}

	return( TRUE );
	}

/* Compare two buffers and check for common en/decryption errors present in 
   them */

BOOLEAN checkTestBuffers( const BYTE *buffer1, const BYTE *buffer2, 
						  const int bufferSize )
	{
	/* Make sure that everything went OK */
	if( compareData( buffer1, bufferSize, buffer2, bufferSize ) )
		return( TRUE );

	/* Try and guess at block chaining problems */
	if( !memcmp( buffer1, "12345678****", 12 ) )
		{
		fputs( "\t\bIt looks like there's a problem with block chaining.\n",
			   outputStream );
		return( FALSE );
		}

	/* Try and guess at endianness problems - we want "1234" */
	if( !memcmp( buffer1, "4321", 4 ) )
		{
		fputs( "\t\bIt looks like the 32-bit word endianness is reversed.\n",
			   outputStream );
		return( FALSE );
		}
	if( !memcmp( buffer1, "2143", 4 ) )
		{
		fputs( "\t\bIt looks like the 16-bit word endianness is reversed.\n",
			   outputStream );
		return( FALSE );
		}
	if( buffer1[ 0 ] >= '1' && buffer1[ 0 ] <= '9' )
		{
		fputs( "\t\bIt looks like there's some sort of endianness problem "
			   "which is\n\t more complex than just a reversal.\n", 
			   outputStream );
		return( FALSE );
		}
	fputs( "\t\bIt's probably more than just an endianness problem.\n",
		   outputStream );
	return( FALSE );
	}

/****************************************************************************
*																			*
*								Debug Functions								*
*																			*
****************************************************************************/

/* Write an object to a file for debugging purposes */

#if defined( _MSC_VER ) && \
	!( defined( _WIN32_WCE ) || defined( __PALMSOURCE__ ) )
  #include <direct.h>
  #include <io.h>
#endif /* VC++ Win16/Win32 */

void debugDump( const char *fileName, const void *data, const int dataLength )
	{
	FILE *filePtr;
#ifdef __UNIX__
	const char *tmpPath = getenv( "TMPDIR" );
	char fileNameBuffer[ FILENAME_BUFFER_SIZE ];
	const int tmpPathLen = ( tmpPath != NULL ) ? strlen( tmpPath ) : 0;
#else
	char fileNameBuffer[ 128 ];
#endif /* __UNIX__ */
	const int length = strlen( fileName );
	int count;

	fileNameBuffer[ 0 ] = '\0';
#if defined( _WIN32_WCE )
	/* Under WinCE we don't want to scribble a ton of data into flash every
	   time we're run so we don't try and do anything */
	return;
#elif ( defined( _MSC_VER ) && !defined( __PALMSOURCE__ ) )
	/* If the path isn't absolute, deposit it in a temp directory.  Note
	   that we have to use underscores in front of the Posix functions
	   because these were deprecated starting with VS 2005.  In addition we 
	   have to explicitly exclude oldnames.lib (which usually isn't  
	   included in the libraries installed with VS) from the link, inclusion 
	   of this is triggered by the compiler seeing the Posix or underscore-
	   Posix functions */
  #if defined( _MSC_VER ) && ( _MSC_VER >= 1400 )
	#pragma comment(linker, "/nodefaultlib:oldnames.lib")
  #endif /* VC++ 2005 and newer misconfiguration */
	if( fileName[ 1 ] != ':' )
		{
		/* It's my code, I can use whatever paths I feel like */
		if( _access( "d:/tmp/", 6 ) == 0 )
			{
			/* There's a data partition available, dump the info there */
			if( _access( "d:/tmp/", 6 ) == -1 && \
				!CreateDirectory( "d:/tmp", NULL ) )
				return;
			strcpy( fileNameBuffer, "d:/tmp/" );
			}
		else
			{
			/* There's no separate data partition, everything's dumped into
			   the same partition */
			if( _access( "c:/temp/", 6 ) == -1 && \
				!CreateDirectory( "c:/temp", NULL ) )
				return;
			strcpy( fileNameBuffer, "c:/temp/" );
			}
		}
#elif defined( __UNIX__ )
	/* If the path isn't absolute, deposit it in a temp directory */
	if( fileName[ 0 ] != '/' )
		{
		if( tmpPathLen > 3 && tmpPathLen < FILENAME_BUFFER_SIZE - 64 )
			{
			strcpy( fileNameBuffer, tmpPath );
			if( fileNameBuffer[ tmpPathLen - 1 ] != '/' )
				strcat( fileNameBuffer + tmpPathLen, "/" );
			}
		else
			strcpy( fileNameBuffer, "/tmp/" );
		}
#endif /* OS-specific paths */
	strcat( fileNameBuffer, fileName );
	if( length <= 3 || fileName[ length - 4 ] != '.' )
		strcat( fileNameBuffer, ".der" );

#if defined( __VMCMS__ )
	{
	char formatBuffer[ 32 ];

	sprintf( formatBuffer, "wb, recfm=F, lrecl=%d, noseek", dataLength );
	filePtr = fopen( fileNameBuffer, formatBuffer );
	}
	if( filePtr == NULL )
		return;
#else
	if( ( filePtr = fopen( fileNameBuffer, "wb" ) ) == NULL )
		return;
#endif /* __VMCMS__ */
	count = fwrite( data, 1, dataLength, filePtr );
	fclose( filePtr );
	if( count < length )
		{
		fprintf( outputStream, "Warning: Couldn't dump '%s' to disk.\n", 
				 fileName );
		remove( fileName );
		}
	}

/****************************************************************************
*																			*
*								Session Functions							*
*																			*
****************************************************************************/

/* Print information on the peer that we're talking to */

int printConnectInfo( const CRYPT_SESSION cryptSession )
	{
#ifndef UNICODE_STRINGS
	time_t theTime;
#endif /* UNICODE_STRINGS */
	C_CHR serverName[ 128 ];
	int serverNameLength, serverPort DUMMY_INIT, status;

	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_CLIENT_NAME,
									  serverName, &serverNameLength );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_CLIENT_PORT, 
									&serverPort );
		}
	if( cryptStatusError( status ) )
		return( FALSE );
#ifdef UNICODE_STRINGS
	serverName[ serverNameLength / sizeof( wchar_t ) ] = TEXT( '\0' );
	fprintf( outputStream, "SVR: Connect attempt from %S, port %d", 
			 serverName, serverPort );
#else
	serverName[ serverNameLength ] = '\0';
	time( &theTime );
	fprintf( outputStream, "SVR: Connect attempt from %s, port %d, on %s.\n", 
			 serverName, serverPort, getTimeString( theTime, 0 ) );
#endif /* UNICODE_STRINGS */
	fflush( stdout );

	/* Display all the attributes that we've got */
	status = displayAttributes( cryptSession );
	fflush( stdout );
	return( status );
	}

/* Print security info for the session */

int printFingerprint( const CRYPT_SESSION cryptSession,
					  const BOOLEAN isServer )
	{
	BYTE fingerPrint[ CRYPT_MAX_HASHSIZE ];
	int length, status;

	/* Print the server key fingerprint */
	status = cryptGetAttributeString( cryptSession,
									  CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
									  fingerPrint, &length );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptGetAttributeString() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	fprintf( outputStream, "%sServer key fingerprint =\n", 
			 isServer ? "SVR: " : "" );
	printHex( "  ", fingerPrint, length );

	return( TRUE );
	}

int printSecurityInfo( const CRYPT_SESSION cryptSession,
					   const BOOLEAN isServer,
					   const BOOLEAN showFingerprint,
					   const BOOLEAN showServerKeyInfo,
					   const BOOLEAN showClientCertInfo )
	{
	int cryptAlgo, keySize DUMMY_INIT, version DUMMY_INIT, status;

	/* Print general security info */
	status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_ALGO,
								&cryptAlgo );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_KEYSIZE,
									&keySize );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_VERSION,
									&version );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "%sCouldn't get session security parameters, "
				 "status %d, line %d.\n", isServer ? "SVR: " : "", status, 
				 __LINE__ );
		return( FALSE );
		}
	fprintf( outputStream, "%sSession is protected using %s with a %d bit "
			 "key,\n  protocol version %d.\n", isServer ? "SVR: " : "", 
			 algoName( cryptAlgo ), keySize * 8, version );
	if( showServerKeyInfo || showClientCertInfo ) 
		{
		CRYPT_CONTEXT serverKey;

		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
									&serverKey );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetAttribute( serverKey, CRYPT_CTXINFO_ALGO,
										&cryptAlgo );
			if( cryptStatusOK( status ) )
				{
				status = cryptGetAttribute( serverKey, CRYPT_CTXINFO_KEYSIZE,
											&keySize );
				}
			cryptDestroyContext( serverKey );
			}
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "%sCouldn't get server security "
					 "parameters, status %d, line %d.\n", 
					 isServer ? "SVR: " : "", status, __LINE__ );
			return( FALSE );
			}
		fprintf( outputStream, "%s key uses %s, key size %d bits.\n", 
				 showClientCertInfo ? "SVR: Client authentication" : "Server", 
				 algoName( cryptAlgo ), keySize * 8 );
		}
	fflush( stdout );
	if( isServer || !showFingerprint )
		return( TRUE );

	status = printFingerprint( cryptSession, FALSE );
	fflush( stdout );
	return( status );
	}

/* Set up a client/server to connect locally.  For the client this simply 
   tells it where to connect, for the server this binds it to the local 
   (loopback) address so that we don't inadvertently open up outside ports 
   (admittedly they can't do much except run the hardcoded self-test, but 
   it's better not to do this at all) */

BOOLEAN setLocalConnect( const CRYPT_SESSION cryptSession, const int port )
	{
	int status;

	if( memcmp( LOCAL_HOST_NAME, "localhost", 9 ) && \
		memcmp( LOCAL_HOST_NAME, "127.", 4 ) )
		{
#ifdef LOCAL_PORT_NAME
		fprintf( outputStream, "Warning: Enabling server on non-local "
				 "interface '%s', port %d.\n", LOCAL_HOST_NAME, 
				 LOCAL_PORT_NAME );
#else
		fputs( "Warning: Enabling server on non-local interface '" 
			   LOCAL_HOST_NAME "'.\n", outputStream );
#endif /* LOCAL_PORT_NAME */
		}

	status = cryptSetAttributeString( cryptSession,
									  CRYPT_SESSINFO_SERVER_NAME,
									  NATIVE_LOCAL_HOST_NAME, 
									  paramStrlen( NATIVE_LOCAL_HOST_NAME ) );
#if defined( LOCAL_PORT_NAME )
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT,
									LOCAL_PORT_NAME );
		}
#elif defined( __UNIX__ )
	/* If we're running under Unix, set the port to a nonprivileged one so
	   that we don't have to run as root.  For anything other than very low-
	   numbered ports (e.g. SSH), the way we determine the port is to repeat
	   the first digit, so e.g. TSA on 318 becomes 3318, this seems to be
	   the method most commonly used */
	if( cryptStatusOK( status ) && port < 1024 )
		{
		if( port < 100 )
			{
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT,
										port + 4000 );
			}
		else
			{
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT,
										( ( port / 100 ) * 1000 ) + port );
			}
		}
#else
	/* If we're not on the default port for this protocol, enable the non-
	   default port */
	if( cryptStatusOK( status ) && \
		( port != 22 && port != 80 && port != 443 ) )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT,
									port );
		}
#endif /* Optional port settings */
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptSetAttribute/AttributeString() failed "
				 "with error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Check whether a remote server might be down, which is treated as a soft 
   fail rather than a hard-fail error condition */

BOOLEAN isServerDown( const CRYPT_SESSION cryptSession,
					  const int errorStatus )
	{
	/* If we get a straight connect error then we don't treat it as a 
	   serious failure */
	if( errorStatus == CRYPT_ERROR_OPEN || \
		errorStatus == CRYPT_ERROR_NOTFOUND )
		return( TRUE );

	/* Under Unix a connection-refused will be reported as a 
	   CRYPT_ERROR_PERMISSION (under Winsock it's just a generic open 
	   error), and a failure to connect may also be reported via a timeout 
	   as CRYPT_ERROR_TIMEOUT, so we check for these as alternatives to an 
	   open error.  
	   
	   Note that some firewalls may allow a connect but then block reads, in 
	   which case we'd need to check for the string "Timeout on read" as 
	   well, however we don't enable this by default because some broken 
	   servers may respond to unexpected PDUs by hanging or closing the 
	   connection, which will also lead to a read timeout for a condition 
	   that's more than just a transient network error */
#ifdef __UNIX__
	if( errorStatus == CRYPT_ERROR_PERMISSION || \
		errorStatus == CRYPT_ERROR_TIMEOUT )
		{
		char errorMessage[ 512 ];
		int errorMessageLength, status;

		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			if( strstr( errorMessage, "ECONNREFUSED" ) != NULL || \
				strstr( errorMessage, "ETIMEDOUT" ) != NULL || \
				strstr( errorMessage, "Timeout on connect" ) != NULL )
				{
				return( TRUE );
				}
			}
		}
#endif /* __UNX__ */

	return( FALSE );
	}

/* Run a persistent server session, recycling the connection if the client
   kept the link open */

static void printOperationType( const CRYPT_SESSION cryptSession )
	{
	struct {
		const int operation; 
		const char *name;
		} operationTypeTbl[] = {
		{ CRYPT_REQUESTTYPE_NONE, "(None)" },
		{ CRYPT_REQUESTTYPE_INITIALISATION,	"ir" },
		{ CRYPT_REQUESTTYPE_CERTIFICATE, "cr" },
		{ CRYPT_REQUESTTYPE_KEYUPDATE, "kur" },
		{ CRYPT_REQUESTTYPE_REVOCATION,	"rr" },
		{ CRYPT_REQUESTTYPE_PKIBOOT, "pkiBoot" },
		{ -1, "(Unknown)" }
		};
	char userID[ CRYPT_MAX_TEXTSIZE ];
	int userIDsize DUMMY_INIT, requestType, i, status;

	status = cryptGetAttribute( cryptSession,
								CRYPT_SESSINFO_CMP_REQUESTTYPE,
								&requestType );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptSession,
									CRYPT_SESSINFO_USERNAME,
									userID, &userIDsize );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptGetAttribute/AttributeString() failed "
				 "with error code %d, line %d.\n", status, __LINE__ );
		return;
		}
	userID[ userIDsize ] = '\0';
	for( i = 0; operationTypeTbl[ i ].operation != requestType && \
				operationTypeTbl[ i ].operation != -1; i++ );
	fprintf( outputStream, "SVR: Operation type was %d = %s, user '%s'.\n",
			 requestType, operationTypeTbl[ i ].name, userID );
	fflush( stdout );
	}

int activatePersistentServerSession( const CRYPT_SESSION cryptSession,
									 const BOOLEAN showOperationType )
	{
	BOOLEAN connectionActive = FALSE;
	int status;

	do
		{
		/* Activate the connection */
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE,
									TRUE );
		if( status == CRYPT_ERROR_READ && connectionActive )
			{
			/* The other side closed the connection after a previous
			   successful transaction, this isn't an error */
			return( CRYPT_OK );
			}

		/* Print connection info and check whether the connection is still
		   active.  If it is, we recycle the session so that we can process
		   another request */
		printConnectInfo( cryptSession );
		if( cryptStatusOK( status ) )
			{
			if( showOperationType )
				printOperationType( cryptSession );
			status = cryptGetAttribute( cryptSession, 
										CRYPT_SESSINFO_CONNECTIONACTIVE,
										&connectionActive );
			}
		}
	while( cryptStatusOK( status ) && connectionActive );

	return( status );
	}

/****************************************************************************
*																			*
*							Attribute Dump Routines							*
*																			*
****************************************************************************/

/* Print a list of all attributes present in an object.  We assemble this as 
   a single string and output it in one go to avoid it being broken up by 
   output from another thread */

static int displayAttribute( const CRYPT_HANDLE cryptHandle )
	{
	BOOLEAN firstAttr = TRUE;
	BYTE buffer1[ 128 ], buffer2[ 128 ];
	char attributeInfoBuffer[ 4096 ];
	int value, pos = 0, length1 = 0, length2 = 0, status;

	status = cryptGetAttribute( cryptHandle,
								CRYPT_ATTRIBUTE_CURRENT_GROUP, &value );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "\nCurrent attribute group type read failed "
				 "with error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	pos += sprintf( attributeInfoBuffer + pos, 
					"  Attribute group %d, values =", value );
		
	/* Display each attribute within the group */
	do
		{
		status = cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT,
									&value );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "\nCurrent attribute type read failed "
					 "with error code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		if( !firstAttr )
			pos += sprintf( attributeInfoBuffer + pos, "," );
		pos += sprintf( attributeInfoBuffer + pos, " %d", value );

		/* If this is an attribute with more than one instance, make sure 
		   that we're getting both instances, not just one value twice */
		if( value == CRYPT_CERTINFO_CERTPOLICYID )
			{
			status = cryptGetAttributeString( cryptHandle, 
											  CRYPT_CERTINFO_CERTPOLICYID, 
											  firstAttr ? buffer1 : buffer2, 
											  firstAttr ? &length1 : &length2 );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "\nCurrent attribute value read "
						 "failed with error code %d, line %d.\n", status, 
						 __LINE__ );
				return( FALSE );
				}
			if( !firstAttr && length2 == 20 && \
				!memcmp( buffer2, "1 2 250 1 95 2 1 3 3", 20 ) )
				{
				/* Certificate #10 has the same policy OID twice, once 
				   without and then again with qualifiers, which means that 
				   it's detected as a duplicate.  To deal with this we change
				   the effective length to make it look like a different OID */
				length2 = 10;
				}
			if( firstAttr )
				buffer1[ length1 ] = '\0';
			else
				{
				buffer2[ length2 ] = '\0';
				if( length1 == length2 && \
					!memcmp( buffer1, buffer2, length1 ) )
					{
					fprintf( outputStream, "\nAttempt to read second "
							 "instance of attribute type %d instead re-read "
							 "first\ninstance, line %d.\n", value, 
							 __LINE__ );
					return( FALSE );
					}
				}
			}
		firstAttr = FALSE;
		}
	while( cryptSetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT,
							  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
	sprintf( attributeInfoBuffer + pos, ".\n" );
	fputs( attributeInfoBuffer, outputStream );

	return( TRUE );
	}

int displayAttributes( const CRYPT_HANDLE cryptHandle )
	{
	if( cryptStatusError( \
			cryptSetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT_GROUP,
							   CRYPT_CURSOR_FIRST ) ) )
		return( TRUE );

	fputs( "Attributes present (by cryptlib ID) are:\n", outputStream );

	/* Display each attribute group */
	do
		{
		if( !displayAttribute( cryptHandle ) )
			return( FALSE );
		}
	while( cryptSetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT_GROUP,
							  CRYPT_CURSOR_NEXT ) == CRYPT_OK );

	/* Reset the cursor to the first attribute.  This is useful for things
	   like envelopes and sessions where the cursor points at the first
	   attribute that needs to be handled */
	cryptSetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT_GROUP,
					   CRYPT_CURSOR_FIRST );
	return( TRUE );
	}
