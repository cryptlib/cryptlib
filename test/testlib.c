<<<<<<< HEAD
/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2023					*
*																			*
****************************************************************************/

#if defined( __Nucleus__ )
  #include <nu_ctype.h>
  #include <nu_string.h>
#else
  #include <ctype.h>	/* For toupper() */
#endif /* OS-specific includes */

#define _SAFETY_DEFINED
#if defined( __xlc__ ) || defined( __IBMC__ )
  #define CONST_RETURN 
#else
  #define CONST_RETURN	const
#endif /* IBM mainframe compilers */
#define DATAPTR			int
#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* Optionally include and activate the Visual Leak Detector library if
   we're running a debug build under VC++ 6.0.  Note that this can't be
   run at the same time as Bounds Checker, since the two interefere with
   each other */

#if defined( _MSC_VER ) && ( _MSC_VER == 1200 ) && 0
  #include "binaries/vld.h"
#endif /* VC++ 6.0 */

/* Microsoft broke the VS 2015 and newer runtime libraries by moving some 
   functions inline, which results in compile problems when linking to the 
   ODBC libs, which call functions that aren't externally visible any more 
   due to inlining.  To fix this, we have to implicitly add 
   legacy_stdio_definitions.lib to avoid link errors with the ODBC libs */

#if defined( _MSC_VER ) && ( _MSC_VER >= 1900 )
  #pragma comment( lib, "legacy_stdio_definitions.lib" )
#endif /* VS 2015 */

/* Optionally include the Intel Thread Checker API to control analysis */

#if defined( _MSC_VER ) && ( _MSC_VER == 1200 ) && 0
  #define USE_TCHECK
  #include "../../../Intel/VTune/tcheck/Include/libittnotify.h"
  #include "../../../Intel/VTune/Analyzer/Include/VtuneApi.h"
  #pragma comment( lib, "C:/Program Files/Intel/VTune/Analyzer/Lib/libittnotify.lib" )
  #pragma comment( lib, "C:/Program Files/Intel/VTune/Analyzer/Lib/VtuneApi.lib " )
  #define THREAD_DEBUG_SUSPEND()	__itt_pause(); VTPause()
  #define THREAD_DEBUG_RESUME()		VTResume(); __itt_resume()
#else
  #define THREAD_DEBUG_SUSPEND()
  #define THREAD_DEBUG_RESUME()
#endif /* VC++ 6.0 with Intel Thread Checker */

/* Warn about nonstandard build options */

#if ( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) ) && \
	defined( CONFIG_SUITEB_TESTS ) 
  #pragma message( "  Building Suite B command-line test configuration." )
#endif /* Notify Suite B tests */

/* Whether various keyset tests worked, the results are used later to test
   other routines.  We initially set the key read result to TRUE in case the
   keyset read tests are never called, so we can still trying reading the
   keys in other tests */

int keyReadOK = TRUE;		/* keyfile.c:testGetPGPPrivateKey() */
int doubleCertOK = FALSE;	/* keyfile.c:testDoubleCertFile() */

/* The output stream to which diagnostic output is sent */

FILE *outputStream;

/* There are some sizeable (for DOS) data structures used, so we increase the
   stack size to allow for them */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ )
  extern unsigned _stklen = 16384;
#endif /* __MSDOS16__ && __TURBOC__ */

/* Forward definitions for system-specific tests.  These need to be after 
   the main() function that they're called from since they pull in cryptlib-
   internal headers that would interfere with earlier code */

void testSystemSpecific1( void );
void testSystemSpecific2( void );

/* Prototype for Suite B test entry point */

#if defined( CONFIG_SUITEB_TESTS ) 

int suiteBMain( int argc, char **argv );

#endif /* CONFIG_SUITEB_TESTS */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The pseudo-CLI VC++ output windows are closed when the program exits so 
   we have to explicitly wait to allow the user to read them */

static void cleanExit( const int exitStatus )
	{
#if defined( __WINDOWS__ ) && !defined( NDEBUG )
	puts( "\nHit a key..." );
	( void ) getchar();
#endif /* __WINDOWS__ && !NDEBUG */
	exit( exitStatus );
	}
static void cleanupAndExit( const int exitStatus )
	{
	int status;

	status = cryptEnd();
	if( status == CRYPT_ERROR_INCOMPLETE )
		puts( "cryptEnd() failed with CRYPT_ERROR_INCOMPLETE." );
	cleanExit( exitStatus );
	}

/* Update the cryptlib config file.  This code can be used to set the
   information required to load PKCS #11 device drivers:

	- Set the driver path in the CRYPT_OPTION_DEVICE_PKCS11_DVR01 setting
	  below.
	- Add a call to updateConfig() from somewhere (e.g.the test kludge function).
	- Run the test code until it calls updateConfig().
	- Remove the updateConfig() call, then run the test code as normal.
	  The testDevices() call will report the results of trying to use your
	  driver.

  cryptlib's SafeLoadLibrary() will always load drivers from the Windows 
  system directory / %SystemDirectory% unless given an absolute path */

static void updateConfig( void )
	{
#if 0
	const char *driverPath = "acospkcs11.dll";		/* ACOS */
	const char *driverPath = "aetpkss1.dll";		/* AET */
	const char *driverPath = "aloaha_pkcs11.dll";	/* Aloaha */
	const char *driverPath = "etpkcs11.dll";		/* Aladdin eToken */
	const char *driverPath = "psepkcs11.dll";		/* A-Sign */
	const char *driverPath = "asepkcs.dll";			/* Athena */
	const char *driverPath = "c:/temp/bpkcs11.dll";	/* Bloomberg */
	const char *driverPath = "/usr/local/lib/libsc-hsm-pkcs11.so";  /* CardContact under Unix */	
	const char *driverPath = "cryst32.dll";			/* Chrysalis */
	const char *driverPath = "c:/program files/luna/cryst201.dll";	/* Chrysalis */
	const char *driverPath = "pkcs201n.dll";		/* Datakey */
	const char *driverPath = "dkck201.dll";			/* Datakey (for Entrust) */
	const char *driverPath = "dkck232.dll";			/* Datakey/iKey (NB: buggy, use 201) */
	const char *driverPath = "c:/program files/eracom/cprov sw/cryptoki.dll";	/* Eracom (old, OK) */
	const char *driverPath = "c:/program files (x86)/eracom/cprov sw/cryptoki.dll";	/* Eracom (old, OK) */
	const char *driverPath = "c:/program files/eracom/cprov runtime/cryptoki.dll";	/* Eracom (new, doesn't work) */
	const char *driverPath = "sadaptor.dll";		/* Eutron */
	const char *driverPath = "ngp11v211.dll";		/* Feitian Technology */
	const char *driverPath = "pk2priv.dll";			/* Gemplus */
	const char *driverPath = "c:/program files/gemplus/gclib.dll";	/* Gemplus */
	const char *driverPath = "cryptoki.dll";		/* IBM */
	const char *driverPath = "csspkcs11.dll";		/* IBM */
	const char *driverPath = "ibmpkcss.dll";		/* IBM */
	const char *driverPath = "id2cbox.dll";			/* ID2 */
	const char *driverPath = "cknfast.dll";			/* nCipher */
	const char *driverPath = "/opt/nfast/toolkits/pkcs11/libcknfast.so";/* nCipher under Unix */
	const char *driverPath = "/usr/lib/libcknfast.so";	/* nCipher under Unix */
	const char *driverPath = "c:/program files/mozilla firefox/softokn3.dll";/* Netscape */
	const char *driverPath = "nxpkcs11.dll";		/* Nexus */
	const char *driverPath = "AuCryptoki2-0.dll";	/* Oberthur */
	const char *driverPath = "opensc-pkcs11.dll";	/* OpenSC */
	const char *driverPath = "/usr/local/lib/opensc-pkcs11.so";	/* OpenSC under Unix */
	const char *driverPath = "micardoPKCS11.dll";	/* Orga Micardo */
	const char *driverPath = "cryptoki22.dll";		/* Rainbow HSM (for USB use Datakey dvr) */
	const char *driverPath = "p11card.dll";			/* Safelayer HSM (for USB use Datakey dvr) */
	const char *driverPath = "slbck.dll";			/* Schlumberger */
	const char *driverPath = "SetTokI.dll";			/* SeTec */
	const char *driverPath = "siecap11.dll";		/* Siemens */
	const char *driverPath = "c:/program files (x86)/SoftHSM2/lib/softhsm2.dll";	/* SoftHSM */
	const char *driverPath = "smartp11.dll";		/* SmartTrust */
	const char *driverPath = "SpyPK11.dll";			/* Spyrus */
#endif /* 0 */
	const char *driverPath = "c:/program files (x86)/eracom/cprov sw/cryptoki.dll";	/* Eracom (old, OK) */
	int status;

	printf( "Updating cryptlib configuration to load PKCS #11 driver\n  "
			"'%s'\nas default driver...", driverPath );

	/* Set the path for a PKCS #11 device driver.  We only enable one of
	   these at a time to speed the startup time */
	status = cryptSetAttributeString( CRYPT_UNUSED, 
									  CRYPT_OPTION_DEVICE_PKCS11_DVR01,
									  driverPath, strlen( driverPath ) );
	if( cryptStatusError( status ) )
		{
		printf( "\n\nError updating PKCS #11 device driver profile, "
				"status %d.\n", status );
		cleanupAndExit( EXIT_FAILURE );
		}

	/* Flush the updated options to disk */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, 
								FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "\n\nError comitting device driver profile update to disk, "
				"status %d.\n", status );
		cleanupAndExit( EXIT_FAILURE );
		}

	puts( " done.\n" );
	cleanupAndExit( EXIT_SUCCESS );
	}

/* Add trusted certs to the config file and make sure that they're
   persistent.  This can't be done in the normal self-test since it requires
   that cryptlib be restarted as part of the test to re-read the config file,
   and because it modifies the cryptlib config file */

static void updateConfigCert( void )
	{
	CRYPT_CERTIFICATE trustedCert;
	int status;

	/* Import the first certificate, make it trusted, and commit the changes */
	importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	cryptDestroyCert( trustedCert );
	cryptEnd();

	/* Do the same with a second certificate.  At the conclusion of this, we 
	   should have two trusted certificates on disk */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't reload cryptlib configuration." );
		return;
		}
	importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 2 );
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	cryptDestroyCert( trustedCert );
	cryptEnd();
	}

/* Check for a discrepancy between debug and release builds of the 
   library and self-test code */

#ifdef NDEBUG
  #define testIsRelease		TRUE
#else
  #define testIsRelease		FALSE
#endif /* NDEBUG */

static void checkDebugReleaseMismatch( void )
	{
	BOOLEAN libraryIsRelease = TRUE;

	/* Check whether cryptlib is running as a debug build */
	if( checkLibraryIsDebug() )
		libraryIsRelease = FALSE;

	/* Warn about mismatches between debug and release mode library and test
	   code builds:

		Library		Test code	Result
		-------		---------	------
		Debug		Debug		OK
		Debug		Release		Some unexpected results
		Release		Debug		Tests will fail
		Release		Release		OK */
	if( !libraryIsRelease && testIsRelease )
		{
		puts( "\nWarning: cryptlib has been built in debug mode but the "
			  "self-test code is\n         build in release mode, some "
			  "self-tests may produce unexpected\n         debug-only "
			  "results.\n\nHit a key..." );
		( void ) getchar();
		}
	if( libraryIsRelease && !testIsRelease )
		{
		puts( "\nWarning: cryptlib has been built in release mode but the "
			  "self-test code is\n         built in debug mode, some "
			  "self-tests will fail due to the code\n         trying to "
			  "exercise debug-only options.\n\nHit a key..." );
		getchar();
		}
	}

/* Check whether default algorithms are available and (temporarily) switch
   to an alternative if not */

static int checkDefaultAlgoAvailable( const CRYPT_ATTRIBUTE_TYPE algoType,
									  const char *algoDescription,
									  const CRYPT_ALGO_TYPE altAlgo )
	{
	int value, status;

	/* Check whether the given default algorithm is available */
	status = cryptGetAttribute( CRYPT_UNUSED, algoType, &value );
	if( cryptStatusError( status ) || \
		cryptStatusOK( cryptQueryCapability( value, NULL ) ) )
		return( TRUE );

	/* Indicate that this algorithm isn't available and try and switch to an 
	   alternative */
	printf( "Warning: Default %s algorithm %s isn't available,\n  "
			"temporarily switching to %s.\n", algoDescription, 
			algoName( value ), algoName( altAlgo ) );
	status = cryptSetAttribute( CRYPT_UNUSED, algoType, altAlgo );
	if( cryptStatusOK( status ) )
		return( TRUE );

	/* The alternative isn't available either, we can't continue */
	printf( "Error: Alternative %s algorithm %s isn't available either,\n  "
			"can't run the self-tests.\n", algoDescription, 
			algoName( altAlgo ) );
	return( FALSE );
	}

static int checkDefaultAlgosAvailable( void )
	{
	/* Check for algorithm availability and try and switch to alternatives,
	   checking whether CRYPT_OPTION_xxx is available and if not switching
	   to CRYPT_ALGO_xxx.  This hardcodes in knowledge of the default 
	   algorithms in order to avoid having to implement a knowledge base of 
	   fallback possibilities */
	if( !checkDefaultAlgoAvailable( CRYPT_OPTION_ENCR_ALGO, 
									"encryption", CRYPT_ALGO_3DES ) || \
		!checkDefaultAlgoAvailable( CRYPT_OPTION_ENCR_HASH, 
									"hash", CRYPT_ALGO_SHA1 ) || \
		!checkDefaultAlgoAvailable( CRYPT_OPTION_ENCR_MAC, 
									"MAC", CRYPT_ALGO_HMAC_SHA1 ) )
		return( FALSE );

	return( TRUE );
	}

/****************************************************************************
*																			*
*								Argument Processing							*
*																			*
****************************************************************************/

/* Flags for the tests that we want to perform */

#define DO_SELFTEST				0x0001
#define DO_LOWLEVEL				0x0002
#define DO_SMOKETEST			0x0004
#define DO_RANDOM				0x0008
#define DO_CONFIG				0x0010
#define DO_DEVICE				0x0020
#define DO_MIDLEVEL				0x0040
#define DO_CERT					0x0080
#define DO_KEYSETFILE			0x0100
#define DO_KEYSETDBX			0x0200
#define DO_CERTPROCESS			0x0400
#define DO_HIGHLEVEL			0x0800
#define DO_ENVELOPE				0x1000
#define DO_SESSION				0x2000
#define DO_SESSIONLOOPBACK		0x4000
#define DO_USER					0x8000

#define DO_ALL					0xFFFF

/* Show usage and exit */

static void usageExit( void )
	{
	puts( "Usage: testlib [-abcdefhiklmoprstu]" );

	puts( "  Encryption function tests:" );
	puts( "       -l = Test low-level functions" );
	puts( "       -m = Test mid-level functions" );
	puts( "       -i = Test high-level functions" );
	puts( "       -g = Perform smoke test of low-level functions" );
	puts( "" );

	puts( "  Subsystem tests:" );
	puts( "       -c = Test certificate subsystem" );
	puts( "       -d = Test device subsystem" );
	puts( "       -f = Test file keyset subsystem" );
	puts( "       -k = Test database keyset subsystem" );
	puts( "       -e = Test envelope subsystem" );
	puts( "       -s = Test session subsystem" );
	puts( "       -t = Test session subsystem via loopback interface" );
	puts( "       -u = Test user subsystem" );
	puts( "" );

	puts( "  Miscellaneous tests:" );
	puts( "       -r = Test entropy-gathering routines" );
	puts( "       -b = Perform built-in self-test" );
	puts( "       -o = Test configuration management routines" );
	puts( "       -p = Test certificate processing" );
	puts( "" );

	puts( "  Other options:" );
	puts( "       -a = All except networking tests, i.e. run only local tests" );
	puts( "       -h = Display this help text" );
	puts( "       -- = End of arg list" );
	puts( "" );

	puts( "Default is to test all cryptlib subsystems." );
	exit( EXIT_FAILURE );
	}

/* Process command-line arguments */

static int processArgs( int argc, char **argv, int *argFlags, 
						const char **zCmdPtrPtr, const char **zArgPtrPtr )
	{
	const char *zargPtr = NULL;
	BOOLEAN moreArgs = TRUE, isZArg = FALSE;

	/* Clear return values */
	*argFlags = 0;
	*zCmdPtrPtr = *zArgPtrPtr = NULL;

	/* No args means test everything */
	if( argc <= 0 )
		{
		*argFlags = DO_ALL;

		return( TRUE );
		}

	/* Check for arguments */
	while( argc > 0 && ( *argv[ 0 ] == '-' || isZArg ) && moreArgs )
		{
		const char *argPtr = argv[ 0 ] + 1;

		/* If the last argument was a -z one, this is the argument value 
		   that goes with it */
		if( isZArg )
			{
			isZArg = FALSE;
			*zArgPtrPtr = argv[ 0 ];
			argv++;
			argc--;
			continue;
			}

		while( *argPtr )
			{
			switch( toupper( *argPtr ) )
				{
				case '-':
					moreArgs = FALSE;	/* GNU-style end-of-args flag */
					break;

				case 'A':
					*argFlags = DO_ALL & ~( DO_SESSION | DO_SESSIONLOOPBACK );
					break;

				case 'B':
					*argFlags |= DO_SELFTEST;
					break;

				case 'C':
					*argFlags |= DO_CERT;
					break;

				case 'D':
					*argFlags |= DO_DEVICE;
					break;

				case 'E':
					*argFlags |= DO_ENVELOPE;
					break;

				case 'F':
					*argFlags |= DO_KEYSETFILE;
					break;

				case 'G':
					*argFlags |= DO_SMOKETEST;
					break;

				case 'H':
					usageExit();
					break;

				case 'I':
					*argFlags |= DO_HIGHLEVEL;
					break;

				case 'K':
					*argFlags |= DO_KEYSETDBX;
					break;

				case 'L':
					*argFlags |= DO_LOWLEVEL;
					break;

				case 'M':
					*argFlags |= DO_MIDLEVEL;
					break;

				case 'O':
					*argFlags |= DO_CONFIG;
					break;

				case 'P':
					*argFlags |= DO_CERTPROCESS;
					break;

				case 'R':
					*argFlags |= DO_RANDOM;
					break;

				case 'S':
					*argFlags |= DO_SESSION;
					break;

				case 'T':
					*argFlags |= DO_SESSIONLOOPBACK;
					break;

				case 'U':
					*argFlags |= DO_USER;
					break;

				case 'Z':
					zargPtr = argPtr + 1;
					if( *zargPtr == '\0' )
						{
						puts( "Error: Missing argument for -z option." );
						return( FALSE );
						}
					while( argPtr[ 1 ] )
						argPtr++;	/* Skip rest of arg */
					*zCmdPtrPtr = zargPtr;
					isZArg = TRUE;
					break;

				default:
					printf( "Error: Unknown argument '%c'.\n", *argPtr );
					return( FALSE );
				}
			argPtr++;
			}
		argv++;
		argc--;
		}
	if( argc > 0 )
		{
		printf( "Error: Unknown argument '%s'.\n", argv[ 0 ] );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*								Fuzzing Wrapper								*
*																			*
****************************************************************************/

/* Wrapper for injecting fuzz data */

#if defined( CONFIG_FUZZ ) && !defined( NDEBUG )

#ifdef __llvm__

const char* __asan_default_options( void )
	{
	/* ASAN integrates LeakSanitizer and enables it by default, we don't
	   want to be warned about leaks when fuzzing since the fuzzing code 
	   bails out as soon as it finds a problem without bothering with 
	   cleanups.
	   
	   This can also be done with __lsan_is_turned_off() { return 1; }
	   but we disable it at the ASAN level rather than the LSAN level */
	return( "detect_leaks=0" );
	}
#endif /* __llvm__ */

static int fuzzSession( const int sessionType,
						const char *fuzzFileName )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT cryptPrivKey = CRYPT_UNUSED;
	CRYPT_SUBPROTOCOL_TYPE subProtocol = CRYPT_SUBPROTOCOL_NONE;
	BYTE buffer[ 16384 ];
	const BOOLEAN isServer = \
			( sessionType == CRYPT_SESSION_SSH_SERVER || \
			  sessionType == CRYPT_SESSION_TLS_SERVER || \
			  sessionType == CRYPT_SESSION_OCSP_SERVER || \
			  sessionType == CRYPT_SESSION_SCVP_SERVER || \
			  sessionType == CRYPT_SESSION_RTCS_SERVER || \
			  sessionType == CRYPT_SESSION_TSP_SERVER || \
			  sessionType == CRYPT_SESSION_CMP_SERVER || \
			  sessionType == CRYPT_SESSION_SCEP_SERVER ) ? \
			TRUE : FALSE;
	int length, status;

	if( sessionType >= 5000 )
		{
		subProtocol = ( sessionType == 5000 ) ? \
						CRYPT_SUBPROTOCOL_WEBSOCKETS : \
					  ( sessionType == 5001 ) ? \
						CRYPT_SUBPROTOCOL_EAPTTLS : \
						CRYPT_SUBPROTOCOL_PEAP;
		}

	/* Create the session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 ( subProtocol != CRYPT_SUBPROTOCOL_NONE ) ? \
								   CRYPT_SESSION_TLS : sessionType );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the various attributes needed to establish a minimal session */
	if( isServer )
		{
		if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptPrivKey ) )
			return( CRYPT_ERROR_FAILED );
		}
	else
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_SERVER_NAME,
										  "localhost", 9 );
		if( cryptStatusError( status ) )
			return( status );
		if( sessionType == CRYPT_SESSION_TLS )
			{
			/* Set the version to match the fuzzing test data, TLS 1.2 */
			cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, 2 );
			}
		}
	if( sessionType == CRYPT_SESSION_SSH || \
		sessionType == CRYPT_SESSION_CMP )
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME,
										  SSH_USER_NAME,
										  paramStrlen( SSH_USER_NAME ) );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSession,
											  CRYPT_SESSINFO_PASSWORD,
											  SSH_PASSWORD,
											  paramStrlen( SSH_PASSWORD ) );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	if( sessionType == CRYPT_SESSION_CMP )
		{
		status = cryptSetAttribute( cryptSession,
									CRYPT_SESSINFO_CMP_REQUESTTYPE,
									CRYPT_REQUESTTYPE_INITIALISATION );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( sessionType == CRYPT_SESSION_SCVP )
		{
		/* SCVP uses rather larger messages for the server response, change 
		   the default buffer size to be able to contain them */
		status = cryptSetAttribute( cryptSession, 
									CRYPT_ATTRIBUTE_BUFFERSIZE, 
									16384 );
		if( cryptStatusError( status ) )
			return( status );
		}

	if( subProtocol != CRYPT_SUBPROTOCOL_NONE )
		{
		cryptSetAttribute( cryptSession, CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
						   subProtocol );
		}

	/* Perform any final session initialisation */
	cryptFuzzInit( cryptSession, cryptPrivKey );

	/* We're ready to go, start the forkserver and read the mutable data */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */
	length = readFileData( fuzzFileName, fuzzFileName, buffer, 16384, 32, 
						   TRUE );
	if( length < 32 )
		return( CRYPT_ERROR_READ );

	/* Perform the fuzzing */
	( void ) cryptSetFuzzData( cryptSession, buffer, length, subProtocol );
	cryptDestroySession( cryptSession );
	if( cryptPrivKey != CRYPT_UNUSED )
		cryptDestroyContext( cryptPrivKey );

	return( CRYPT_OK );
	}

static int fuzzFile( const char *fuzzFileName )
	{
	CRYPT_CERTIFICATE cryptCert;
	BYTE buffer[ 4096 ];
	int length, status;

	/* We're ready to go, start the forkserver and read the mutable data */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */
	length = readFileData( fuzzFileName, fuzzFileName, buffer, 4096, 64, 
						   TRUE );
	if( length < 64 )
		return( CRYPT_ERROR_READ );

	/* Process the input file */
	status = cryptImportCert( buffer, length, CRYPT_UNUSED, &cryptCert );
	if( cryptStatusOK( status ) )
		cryptDestroyCert( cryptCert );

	return( CRYPT_OK );
	}

static int fuzzEnvelope( const char *fuzzFileName )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	BYTE buffer[ 4096 ];
	int length, bytesIn, status;

	/* Create the envelope */
	status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED, 
								  CRYPT_FORMAT_AUTO );
	if( cryptStatusError( status ) )
		return( status );

	/* We're ready to go, start the forkserver and read the mutable data */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */
	length = readFileData( fuzzFileName, fuzzFileName, buffer, 4096, 64, 
						   TRUE );
	if( length < 64 )
		return( CRYPT_ERROR_READ );

	/* Process the input file */
	( void ) cryptPushData( cryptEnvelope, buffer, length, &bytesIn );
	cryptDestroyEnvelope( cryptEnvelope );

	return( CRYPT_OK );
	}

static int fuzzKeyset( const char *fuzzFileName )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Start the forkserver */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */

	/* Process the input file */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  fuzzFileName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		cryptKeysetClose( cryptKeyset );

	return( CRYPT_OK );
	}

static int fuzzSpecial( const int fuzzType, const char *fuzzFileName )
	{
	CRYPT_CONTEXT cryptPrivKey;
	CRYPT_SESSION cryptSession;
	BYTE buffer[ 8192 ];
	const BOOLEAN isServer = ( fuzzType == 4002 ) ? TRUE : FALSE;
	const int minLength = ( fuzzType == 4000 ) ? 2 : 16;
	int length, status;

	/* If we're fuzzing bignum ops, load the private key that we'll need */
	if( fuzzType == 4000 )
		{
		if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptPrivKey ) )
			return( CRYPT_ERROR_FAILED );
		}
	if( fuzzType == 4001 )
		{
		status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
									 CRYPT_SESSION_TLS );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_FAILED );
		}

	/* We're ready to go, start the forkserver and read the mutable data */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */
	length = readFileData( fuzzFileName, fuzzFileName, buffer, 8192, 
						   minLength, TRUE );
	if( length < minLength )
		return( CRYPT_ERROR_READ );

	/* Process the input file */
	switch( fuzzType )
		{
		case 4000:	/* Bignum */
			{
			BYTE tmpBuffer[ 8192 ];

#if 0		/* We don't do an early-out in order to check that the bignum 
			   code can actually reject all invalid input values */
			/* Any value that's larger than the modulus will be trivially 
			   rejected so there's no point in trying to process it */
			if( buffer[ 0 ] > 0x9C )
				{
				cryptDestroyContext( cryptPrivKey );
				return( CRYPT_OK );
				}
#endif /* 0 */

			memcpy( tmpBuffer, buffer, length );
			status = cryptDecrypt( cryptPrivKey, buffer, length );
			if( cryptStatusOK( status ) )
				status = cryptEncrypt( cryptPrivKey, buffer, length );
			if( cryptStatusOK( status ) )
				{
				/* Make sure that we got back what we started with */
				assert( !memcmp( buffer, tmpBuffer, length ) );
				}
			cryptDestroyContext( cryptPrivKey );

			break;
			}

		case 4001:	/* URL */
			( void ) cryptSetAttributeString( cryptSession, 
											  CRYPT_SESSINFO_SERVER_NAME,
											  buffer, length );
			break;

		case 4002:	/* HTTP */
		case 4003:
			( void ) cryptFuzzSpecial( CRYPT_UNUSED, buffer, length, 
									   isServer, TRUE );
			break;

		case 4004:	/* EAP */
			( void ) cryptFuzzSpecial( CRYPT_UNUSED, buffer, length, 
									   FALSE, FALSE );
			break;

		default:
			assert( 0 );
		}

	return( CRYPT_OK );
	}

static int fuzz( const char *cmd, const char *arg )
	{
	static const struct {
		const char *fuzzTypeName;
		const int fuzzType;
		} fuzzTypeMap[] = {
		{ "base64", 1000 }, { "certificate", 1001 },
		{ "certchain", 1002 }, { "certreq", 1002 },
		{ "cms", 2000 }, { "pgp", 2001 },
		{ "pkcs12", 3000 }, { "pkcs15", 3001 },
		{ "pgppub", 3002 }, { "pgpsec", 3003 },
		{ "bignum", 4000 }, { "url", 4001 }, 
		{ "http-req", 4002 }, { "http-resp", 4003 },
		{ "eap", 4004 },
		{ "ssh-client", CRYPT_SESSION_SSH },
		{ "ssh-server", CRYPT_SESSION_SSH_SERVER },
		{ "tls-client", CRYPT_SESSION_TLS },
		{ "tls-server", CRYPT_SESSION_TLS_SERVER },
		{ "ocsp-client", CRYPT_SESSION_OCSP },
		{ "ocsp-server", CRYPT_SESSION_OCSP_SERVER },
		{ "rtcs-client", CRYPT_SESSION_RTCS },
		{ "rtcs-server", CRYPT_SESSION_RTCS_SERVER },
		{ "scvp-client", CRYPT_SESSION_SCVP },
		{ "scvp-server", CRYPT_SESSION_SCVP_SERVER },
		{ "tsp-client", CRYPT_SESSION_TSP },
		{ "tsp-server", CRYPT_SESSION_TSP_SERVER },
		{ "scep-client", CRYPT_SESSION_SCEP },
		{ "scep-server", CRYPT_SESSION_SCEP_SERVER },
		{ "cmp-client", CRYPT_SESSION_CMP },
		{ "cmp-server", CRYPT_SESSION_CMP_SERVER },
		{ "websockets", 5000 },
		{ NULL, 0 }
		};
	int i, fuzzType = -1, status;

	/* Test harness for code checking */
#if defined( __WINDOWS__ ) && 1
//	cmd = "base64"; arg = "test/fuzz/base64.dat";
//	cmd = "certificate"; arg = "test/fuzz/certificate.dat";
//	cmd = "certchain"; arg = "test/fuzz/certchain.dat";
//	cmd = "certreq"; arg = "test/fuzz/certreq.dat";
//	cmd = "cms"; arg = "test/fuzz/cms.dat";
//	cmd = "pgp"; arg = "test/fuzz/pgp.dat";
//	cmd = "pkcs12"; arg = "test/fuzz/pkcs12.dat";
//	cmd = "pkcs15"; arg = "test/fuzz/pkcs15.dat";
//
//	cmd = "tls-client"; arg = "test/fuzz/tls_svr.dat";
	cmd = "tls-server"; arg = "test/fuzz/tls_cli.dat";
//	cmd = "ssh-client"; arg = "test/fuzz/ssh_svr.dat";
//	cmd = "ssh-server"; arg = "test/fuzz/ssh_cli.dat";
//	cmd = "ocsp-client"; arg = "test/fuzz/ocsp_svr.dat";
//	cmd = "ocsp-server"; arg = "test/fuzz/ocsp_cli.dat";
//	cmd = "scvp-client"; arg = "test/fuzz/scvp_svr.dat";
//	cmd = "scvp-server"; arg = "test/fuzz/scvp_cli.dat";
//	cmd = "tsp-client"; arg = "test/fuzz/tsp_svr.dat";
//	cmd = "tsp-server"; arg = "test/fuzz/tsp_cli.dat";
//
//	cmd = "cmp-client"; arg = "test/fuzz/cmp_svr.dat";
//	cmd = "cmp-server"; arg = "test/fuzz/cmp_cli.dat";
//	cmd = "rtcs-client"; arg = "test/fuzz/rtcs_svr.dat";
//	cmd = "rtcs-server"; arg = "test/fuzz/rtcs_cli.dat";
//	cmd = "scep-client"; cmd = "scep-server"; Redundant, see comments below
//
//	cmd = "pgppub"; arg = "test/fuzz/pgppub.dat";
//	cmd = "pgpsec"; arg = "test/fuzz/pgpsec.dat";
//	cmd = "bignum"; arg = "test/fuzz/bignum.dat";
//	cmd = "url"; arg = "test/fuzz/url.dat";
//	cmd = "http-req"; arg = "test/fuzz/http_req.dat";
//	cmd = "http-resp"; arg = "test/fuzz/http_resp.dat";
//	cmd = "websockets"; arg = "test/fuzz/websockets.dat";
//	cmd = "eap"; arg = "test/fuzz/eap.dat";
#endif /* __WINDOWS__ test */

	/* Make sure that we've got an input arg */
	if( cmd == NULL )
		{
		printf( "Error: Missing argument fuzz type.\n" );
		exit( EXIT_FAILURE );
		}
	if( arg == NULL )
		{
		printf( "Error: Missing argument fuzz filename.\n" );
		exit( EXIT_FAILURE );
		}

	/* Figure out which type of fuzzing we're doing */
	for( i = 0; fuzzTypeMap[ i ].fuzzTypeName != NULL; i++ )
		{
		if( !strcmp( fuzzTypeMap[ i ].fuzzTypeName, cmd ) )
			{
			fuzzType = fuzzTypeMap[ i ].fuzzType;
			break;
			}
		}
	if( fuzzType == -1 )
		{
		printf( "Error: Invalid fuzz type '%s'.\n", cmd );
		exit( EXIT_FAILURE );
		}
	if( fuzzType == CRYPT_SESSION_SCEP || \
		fuzzType == CRYPT_SESSION_SCEP_SERVER )
		{
		/* SCEP uses CMS envelopes, which are already handled directly by
		   the envelope fuzzing.  In addition SCEP clients need to decrypt 
		   CMS messages returned by the server, encrypted to the certificate 
		   that they've just generated, which can't be emulated with static 
		   data */
		printf( "Error: SCEP uses CMS messages which are fuzzed via "
				"envelopes.\n" );
		exit( EXIT_FAILURE );
		}

	/* Fake out the randomness polling */
	status = cryptAddRandom( "xyzzy", 5 );
	if( cryptStatusError( status ) )
		{
		printf( "Error: Randomness setup failed with status %d.\n", status );
		exit( EXIT_FAILURE );
		}

	/* Patch point for checking crashes */
#if defined( __WINDOWS__ ) && 1
	{
	char buffer[ 128 ];

	for( i = 0; i < 100; i++ )
		{
		FILE *filePtr;

		sprintf( buffer, "r:/%s/%06d.dat", cmd, i );
		filePtr = fopen( buffer, "rb" );
		if( filePtr == NULL )
			{
			printf( "No more files at number %d (%s), exiting.\n", 
					i, buffer );
			break;
			}
		fclose( filePtr );
		printf( "Fuzzing %s file %d (%s).\n", cmd, i, buffer );
		if( fuzzType >= 1000 && fuzzType <= 1100 )
			status = fuzzFile( buffer );
		else 
		if( fuzzType >= 2000 && fuzzType <= 2100 )
			status = fuzzEnvelope( buffer );
		else 
		if( fuzzType >= 3000 && fuzzType <= 3100 )
			status = fuzzKeyset( buffer );
		else 
		if( fuzzType >= 4000 && fuzzType <= 4100 )
			status = fuzzSpecial( fuzzType, buffer );
		else
			status = fuzzSession( fuzzType, buffer );
		}
	puts( "Done." );
	if( i <= 0 )
		{
		puts( "Warning: No input files processed." );
		getchar();
		}
	exit( EXIT_SUCCESS );
	}
#endif /* __WINDOWS__ test */

	/* Fuzz the target file */
	if( fuzzType >= 1000 && fuzzType <= 1100 )
		status = fuzzFile( arg );
	else 
	if( fuzzType >= 2000 && fuzzType <= 2100 )
		status = fuzzEnvelope( arg );
	else 
	if( fuzzType >= 3000 && fuzzType <= 3100 )
		status = fuzzKeyset( arg );
	else
	if( fuzzType >= 4000 && fuzzType <= 4100 )
		status = fuzzSpecial( fuzzType, arg );
	else
	if( ( fuzzType > CRYPT_SESSION_NONE && \
		  fuzzType < CRYPT_SESSION_LAST ) || \
		( fuzzType >= 5000 && fuzzType <= 5100 ) )
		status = fuzzSession( fuzzType, arg );
	else
		{
		printf( "Error: Unknown fuzz type '%d'.\n", fuzzType );
		exit( EXIT_FAILURE );
		}
	if( cryptStatusError( status ) )
		{
		/* The fuzz init failed, make sure that the wrapper records this */
		exit( EXIT_FAILURE );
		}

	exit( EXIT_SUCCESS );
	}
#endif /* CONFIG_FUZZ && debug mode */

/****************************************************************************
*																			*
*								Misc.Kludges								*
*																			*
****************************************************************************/

/* Generic test code insertion point.  The following routine is called
   before any of the other tests are run and can be used to handle special-
   case tests that aren't part of the main test suite */

static void testKludge( const char *cmd, const char *arg )
	{
	/* Create the database keysets that are needed for some tests and 
	   populate them with sample certificates */
#if 0
	checkCreateDatabaseKeysets();
	testCertManagement();
#endif /* 0 */

	/* Fuzzing test harness.  This is a noreturn function */
#ifdef CONFIG_FUZZ
	fuzz( cmd, arg );
#endif /* CONFIG_FUZZ */

	/* Performance-testing test harness */
#if 0
	void performanceTests( const CRYPT_DEVICE cryptDevice );

	performanceTests( CRYPT_UNUSED );
#endif /* 0 */

	/* Simple (brute-force) server code. NB: setLocalConnect() by default 
	   will bind to localhost, to allow external connections and bind to a
	   particular IP address and port uncomment the alternative 
	   LOCAL_HOST_NAME configuration in test/test.h.

	   This can still exit if the client triggers a check in the debug 
	   build, which throws an exception and exits to the debugger rather 
	   than returning an error code, so the whole can be wrapped in:

		#!/bin/bash

		until ./server_app ; do
			echo "Server died with exit code $?, respawning.." >> log.txt
			sleep 1
		done 
		
	   to allow it to restart on a non-clean exit */
#if 0
	while( TRUE )
		{
		printf( "Running server session...\n" );
		testSessionTLS12Server();
		}
#endif /* 0 */

	/* Exit point for the test harnesses above, used when we don't want to 
	   fall through to the main test code */
#if 0
	cleanupAndExit( EXIT_SUCCESS );
#endif /* 0 */
	}

/****************************************************************************
*																			*
*								Main Test Code								*
*																			*
****************************************************************************/

/* Comprehensive cryptlib functionality test.  To get the following to run 
   under WinCE as a native console app it's necessary to change the entry 
   point in Settings | Link | Output from WinMainCRTStartup to the 
   undocumented mainACRTStartup, which calls main() rather than WinMain(), 
   however this only works if the system has a native console-mode driver 
   (most don't) */

int main( int argc, char **argv )
	{
	const char *zCmdPtr = NULL, *zArgPtr = NULL;
	const char *endianStringPtr;
	BOOLEAN sessionTestError = FALSE, loopbackTestError = FALSE;
	int flags, status;

	/* If we're running in a special test mode, run the test code and 
	   exit */
#ifdef CONFIG_SUITEB_TESTS
	return( suiteBMain( argc, argv ) );
#endif /* CONFIG_SUITEB_TESTS */

	/* Print a general banner to let the user know what's going on */
#if defined( DATA_LITTLEENDIAN ) || defined( CONFIG_DATA_LITTLEENDIAN )
	endianStringPtr = "little-endian";
#elif defined( DATA_BIGENDIAN ) || defined( CONFIG_DATA_BIGENDIAN )
	endianStringPtr = "big-endian";
#else
	if( *( ( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" ) < 0 )
		endianStringPtr = "big-endian";
	else
		endianStringPtr = "little-endian";
#endif /* Endianness */
	printf( "testlib - cryptlib %d-bit %s %sself-test framework.\n", 
			( int ) sizeof( size_t ) * 8,		/* Cast for gcc */
			endianStringPtr,
#if defined( __WINDOWS__ )
			"Windows "
#elif defined( _AIX ) || defined( __APPLE__ ) || defined( __FreeBSD__ ) || \
	   defined( __NetBSD__ ) || defined( __OpenBSD__ ) || \
	   defined( __hpux ) || defined( __linux__ ) || \
	   defined( __UNIX_SV__ ) || defined( __QNX__ ) || defined( __sgi ) || \
	   defined( sun )
			"Unix "
#else
			""
#endif /* OS names */
			);
	puts( "Copyright Peter Gutmann 1995 - 2024." );
#ifdef CONFIG_FUZZ
	puts( "" );
	puts( "Warning: This is a custom fuzzing build that operates in a nonstandard manner." );
	puts( "         Not to be used in a standard test or production environment." );
#endif /* CONFIG_FUZZ */
	puts( "" );

	/* Skip the program name and process any command-line arguments */
	argv++; argc--;
	status = processArgs( argc, argv, &flags, &zCmdPtr, &zArgPtr );
	if( !status )
		exit( EXIT_FAILURE );

#ifdef USE_TCHECK
	THREAD_DEBUG_SUSPEND();
#endif /* USE_TCHECK */

	/* Make sure that various system-specific features are set right */
	testSystemSpecific1();

	/* VisualAge C++ doesn't set the TZ correctly.  The check for this isn't
	   as simple as it would seem since most IBM compilers define the same
	   preprocessor values even though it's not documented anywhere, so we
	   have to enable the tzset() call for (effectively) all IBM compilers
	   and then disable it for ones other than VisualAge C++ */
#if ( defined( __IBMC__ ) || defined( __IBMCPP__ ) ) && !defined( __VMCMS__ )
	tzset();
#endif /* VisualAge C++ */

	/* Set up the output stream to which diagnostic output is sent */
	outputStream = stdout;

	/* Perform memory-allocation fault injection.  We have to do this before
	   we call cryptInit() since the init code itself is tested by the
	   memory fault-injection */
#ifdef TEST_MEMFAULT
	testMemFault();
#endif /* TEST_MEMFAULT */

	/* Initialise cryptlib */
	printf( "Initialising cryptlib..." );
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptInit() failed with error code %d, line %d.\n", 
				status, __LINE__ );
		exit( EXIT_FAILURE );
		}
	puts( "done." );

	/* Check for a discrepancy between debug and release builds of the 
	   library and self-test code */
	checkDebugReleaseMismatch();

	/* Check whether default algorithms are available and (temporarily) 
	   switch to an alternative if not */
	if( !checkDefaultAlgosAvailable() )
		{
		puts( "Default algorithms required for the self-test to run aren't "
			  "available in\nthis build, can't run the self-tests." );
		cryptEnd();
		exit( EXIT_FAILURE );
		}

	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk.  This is only
	   enabled when cryptlib is built in debug mode so it won't work with 
	   any production systems */
#ifndef TEST_RANDOM
  #if defined( __MVS__ ) || defined( __VMCMS__ )
	#pragma convlit( resume )
	cryptAddRandom( "xyzzy", 5 );
	#pragma convlit( suspend )
  #else
	cryptAddRandom( "xyzzy", 5 );
  #endif /* Special-case EBCDIC handling */
#endif /* TEST_RANDOM */

	/* For general testing purposes we can insert test code at this point to
	   test special cases that aren't covered in the general tests below.  
	   Note that this has to be called before any of the following checks if
	   the code is being run as a standalone executable outside the cryptlib
	   test environment */
	testKludge( zCmdPtr, zArgPtr );

	/* Perform a general sanity check to make sure that the self-test is
	   being run the right way */
	if( !checkFileAccess() )
		{
		cryptEnd();
		exit( EXIT_FAILURE );
		}

	/* Make sure that further system-specific features that require cryptlib 
	   to be initialised to check are set right */
#ifndef _WIN32_WCE
	testSystemSpecific2();
#endif /* WinCE */

#ifdef USE_TCHECK
	THREAD_DEBUG_RESUME();
#endif /* USE_TCHECK */

	/* Perform a general smoke test of the kernel.  This is always run 
	   before other tests are run */
	if( !testSmokeTestKernel() )
		goto errorExit;

	/* Test each block of cryptlib functionality */
	if( ( flags & DO_SELFTEST ) && !testSelfTest() )
		goto errorExit;
	if( ( flags & DO_LOWLEVEL ) && !testLowLevel() )
		goto errorExit;
	if( ( flags & DO_SMOKETEST ) && !testSmokeTestObjects() )
		goto errorExit;
	if( ( flags & DO_RANDOM ) && !testRandom() )
		goto errorExit;
	if( ( flags & DO_CONFIG ) && !testConfig() )
		goto errorExit;
	if( ( flags & DO_DEVICE ) && !testDevice() )
		goto errorExit;
	if( ( flags & DO_MIDLEVEL ) && !testMidLevel() )
		goto errorExit;
	if( ( flags & DO_CERT ) && !testCert() )
		goto errorExit;
	if( ( flags & DO_KEYSETFILE ) && !testKeysetFile() )
		goto errorExit;
	if( ( flags & DO_KEYSETDBX ) && !testKeysetDatabase() )
		goto errorExit;
	if( ( flags & DO_CERTPROCESS ) && !testCertMgmt() )
		goto errorExit;
	if( ( flags & DO_HIGHLEVEL ) && !testHighLevel() )
		goto errorExit;
	if( ( flags & DO_ENVELOPE ) && !testEnveloping() )
		goto errorExit;
	if( ( flags & DO_SESSION ) && !testSessions() )
		{
		sessionTestError = TRUE;
		goto errorExit;
		}
	if( ( flags & DO_SESSIONLOOPBACK ) && !testSessionsLoopback() )
		{
		loopbackTestError = TRUE;
		goto errorExit;
		}
	if( ( flags & DO_USER  ) && !testUsers() )
		goto errorExit;

	/* Shut down cryptlib */
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_INCOMPLETE )
			{
			puts( "cryptEnd() failed with error code CRYPT_ERROR_INCOMPLETE, "
				  "a code path in the\nself-test code resulted in an error "
				  "return without a full cleanup of objects.\nIf you were "
				  "running the multithreaded loopback tests this may be "
				  "because one\nor more threads lost sync with other threads "
				  "and exited without cleaning up\nits objects.  This "
				  "happens occasionally due to network timing issues or\n"
				  "thread scheduling differences." );
			}
		else
			{
			printf( "cryptEnd() failed with error code %d, line %d.\n", 
					status, __LINE__ );
			}
		goto errorExit1;
		}

	puts( "All tests concluded successfully." );
	return( EXIT_SUCCESS );

	/* All errors end up here */
errorExit:
	cryptEnd();
errorExit1:
	puts( "\nThe test was aborted due to an error being detected.  If you "
		  "want to report\nthis problem, please provide as much information "
		  "as possible to allow it to\nbe diagnosed, for example the call "
		  "stack, the location inside cryptlib where\nthe problem occurred, "
		  "and the values of any variables that might be\nrelevant." );
	if( sessionTestError )
		{
		puts( "\nThe error occurred during one of the network session tests, "
			  "if the error\nmessage indicates a network-level problem such "
			  "as ECONNREFUSED, ECONNRESET,\nor a timeout or read error then "
			  "this is either due to a transient\nnetworking problem or a "
			  "firewall interfering with network connections.  This\nisn't a "
			  "cryptlib error, and doesn't need to be reported." );
		}
	if( loopbackTestError )
		{
		puts( "\nThe error occurred during one of the multi-threaded network "
			  "loopback\ntests, this was probably due to the different threads "
			  "losing synchronisation.\nFor the secure sessions this usually "
			  "results in read/write, timeout, or\nconnection-closed errors "
			  "when one thread is pre-empted for too long.  For the\n"
			  "certificate-management sessions it usually results in an error "
			  "related to the\nserver being pre-empted for too long by database "
			  "updates.  Since the self-\ntest exists only to exercise "
			  "cryptlib's capabilities, it doesn't bother with\ncomplex thread "
			  "synchronisation during the multi-threaded loopback tests.\nThis "
			  "type of error is non-fatal, and should disappear if the test is "
			  "re-run." );
		}

	cleanExit( EXIT_FAILURE );
	return( EXIT_FAILURE );		/* Exists only to get rid of compiler warnings */
	}

/* PalmOS wrapper for main() */

#ifdef __PALMSOURCE__

#include <CmnErrors.h>
#include <CmnLaunchCodes.h>

uint32_t PilotMain( uint16_t cmd, void *cmdPBP, uint16_t launchFlags )
	{
	switch( cmd )
		{
		case sysAppLaunchCmdNormalLaunch:
			main( 0, NULL );
		}

	return( errNone );
	}
#endif /* __PALMSOURCE__ */

/* Symbian wrapper for main() */

#ifdef __SYMBIAN__

GLDEF_C TInt E32Main( void )
	{
	main( 0, NULL );

	return( KErrNone );
	}

#ifdef __WINS__

/* Support functions for use under the Windows emulator */

EXPORT_C TInt WinsMain( void )
	{
	E32Main();

	return( KErrNone );
	}

TInt E32Dll( TDllReason )
	{
	/* Entry point for the DLL loader */
	return( KErrNone );
	}
#endif /* __WINS__ */

#endif /* __SYMBIAN__ */

/* Test the system-specific defines in crypt.h.  This is the last function in
   the file because we want to avoid any definitions in crypt.h messing with
   the rest of the test.c code.

   The following include is needed only so we can check whether the defines
   are set right.  crypt.h should never be included in a program that uses
   cryptlib */

#undef __WINDOWS__
#undef __WIN16__
#undef __WIN32__
#undef BOOLEAN
#undef BYTE
#undef FALSE
#undef TRUE
#ifdef _MSC_VER
  #undef VC_16BIT
  #undef VC_LE_VC6
  #undef VC_LT_2005
  #undef VC_GE_2005
  #undef VC_GE_2010
  #undef VC_GE_2017
#endif /* _MSC_VER */
#define IN_STRING		/* No-op out define normally in analyse.h */
#ifdef HIRES_FORMAT_SPECIFIER
  #undef HIRES_FORMAT_SPECIFIER
  #define HIRES_TIME	HIRES_TIME_ALT	/* Rename typedef'd value */
#endif /* HIRES_TIME */
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( resume )
#endif /* Resume ASCII use on EBCDIC systems */
#if defined( __ILEC400__ )
  #pragma convert( 819 )
#endif /* Resume ASCII use on EBCDIC systems */
#ifdef _MSC_VER
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Braindamaged MSC include handling */
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( suspend )
#endif /* Suspend ASCII use on EBCDIC systems */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* Suspend ASCII use on EBCDIC systems */
#undef mktime		/* Undo mktime() bugfix in crypt.h */

#ifndef _WIN32_WCE

static time_t testTime( const int year )
	{
	struct tm theTime;

	memset( &theTime, 0, sizeof( struct tm ) );
	theTime.tm_isdst = -1;
	theTime.tm_year = 100 + year;
	theTime.tm_mon = 5;
	theTime.tm_mday = 5;
	theTime.tm_hour = 12;
	theTime.tm_min = 13;
	theTime.tm_sec = 14;
	return( mktime( &theTime ) );
	}
#endif /* !WinCE */

void testSystemSpecific1( void )
	{
#if 0	/* See comment below */
	const CRYPT_ATTRIBUTE_TYPE testType = -1;
#endif /* 0 */
	union {
		int intVal;
        char charVal[ 4 ];
		} 
	endiannessCheckValue = { 0x41414101 };
#ifndef _WIN32_WCE
	int i;
#endif /* WinCE */

	/* Make sure that we've got the endianness set right.  If the machine is
	   big-endian then the check value will be something other than 1, 
	   otherwise it will be 1 */
#ifdef DATA_LITTLEENDIAN
	if( endiannessCheckValue.charVal[ 0 ] != 1 )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nbig-endian, not little-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#else
	if( endiannessCheckValue.charVal[ 0 ] == 1 )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nlittle-endian, not big-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#endif /* DATA_LITTLEENDIAN */

#if 0	/* The ANSI C default is 'int' with signedness being unimportant, 
		   MSVC defaults to signed, gcc defaults to unsigned, and cryptlib
		   works with either, so whatever the CodeSourcery build of gcc is
		   doing it's more serious than a simple signedness issue */
	/* Make sure that the compiler doesn't use unsigned enums (for example a 
	   mutant CodeSourcery build of gcc for eCos does this) */
	if( testType >= 0 )
		{
		puts( "The compiler you are using treats enumerated types as "
			  "unsigned values,\nmaking it impossible to reliably use enums "
			  "in conjunction with standard\n(signed) integers.  To fix this "
			  "you need to rebuild cryptlib with the\nappropriate compiler "
			  "option or pragma to ensure that enumerated types\nare signed "
			  "like standard data types." );
		exit( EXIT_FAILURE );
		}
#endif /* 0 */

	/* Make sure that mktime() works properly (there are some systems on
	   which it fails well before 2038) */
#ifndef _WIN32_WCE
	for( i = 10; i < 36; i ++ )
		{
		const time_t theTime = testTime( i );

		if( theTime < 0 )
			{
			printf( "Warning: This system has a buggy mktime() that can't "
					"handle dates beyond %d.\n         Some certificate tests "
					"will fail, and long-lived CA certificates\n         won't "
					"be correctly imported.\nPress a key...\n", 2000 + i );
			( void ) getchar();
			break;
			}
		}
#endif /* !WinCE */

	/* If we're compiling under Unix with threading support, make sure the
	   default thread stack size is sensible.  We don't perform the check for
	   UnixWare/SCO since this already has the workaround applied */
#if defined( UNIX_THREADS ) && !defined( __SCO_VERSION__ )
	{
	pthread_attr_t attr;
	size_t stackSize;

	pthread_attr_init( &attr );
	pthread_attr_getstacksize( &attr, &stackSize );
    pthread_attr_destroy( &attr );
  #if ( defined( sun ) && OSVERSION > 4 )
	/* Slowaris uses a special-case value of 0 (actually NULL) to indicate
	   the default stack size of 1MB (32-bit) or 2MB (64-bit), so we have to
	   handle this specially */
	if( stackSize < 32768 && stackSize != 0 )
  #else
	if( stackSize < 32768 )
  #endif /* Slowaris special-case handling */
		{
		printf( "The pthread stack size is defaulting to %ld bytes, which is "
				"too small for\ncryptlib to run in.  To fix this, edit the "
				"thread-creation function macro in\nthread.h and recompile "
				"cryptlib.\n", ( long ) stackSize );
		exit( EXIT_FAILURE );
		}
	}
#endif /* UNIX_THREADS */
	}

#ifndef _WIN32_WCE	/* Windows CE doesn't support ANSI C time functions */

void testSystemSpecific2( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	const time_t theTime = time( NULL ) - 5;
#ifndef USE_CUSTOM_CONFIG_1
	int value;
#endif /* USE_CUSTOM_CONFIG_1 */
	int status;

	/* Make sure that we're running at a standard compliance level */
#ifndef USE_CUSTOM_CONFIG_1
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
								&value );
	if( cryptStatusError( status ) || value != CRYPT_COMPLIANCELEVEL_STANDARD )
		{
		printf( "Warning: cryptlib has been configured to run at a "
				"nonstandard certificate\n         compliance level %d "
				"instead of %d, this will upset the results of\n"
				"         the self-test and may cause some tests to "
				"fail.\n", value, CRYPT_COMPLIANCELEVEL_STANDARD );
		exit( EXIT_FAILURE );
		}
#endif /* USE_CUSTOM_CONFIG_1 */

	/* Make sure that the cryptlib and non-cryptlib code use the same time_t
	   size (some systems are moving from 32- to 64-bit time_t, which can 
	   lead to problems if the library and calling code are built with 
	   different sizes) */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_NOTAVAIL )
			{
			puts( "Couldn't create certificate object for time sanity-check "
				  "because certificate\nuse has been disabled, skipping "
				  "time sanity check...\n" );
			return;
			}
		puts( "Couldn't create certificate object for time sanity-check." );
		exit( EXIT_FAILURE );
		}
	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDFROM,
									  &theTime, sizeof( time_t ) );
	cryptDestroyCert( cryptCert );
	if( status == CRYPT_ERROR_PARAM4 )
		{
		printf( "Warning: This compiler is using a %ld-bit time_t data type, "
				"which appears to be\n         different to the one that "
				"was used when cryptlib was built.  This\n         situation "
				"usually occurs when the compiler allows the use of both\n"
				"         32- and 64-bit time_t data types and different "
				"options were\n         selected for building cryptlib and "
				"the test app.  To resolve this,\n         ensure that both "
				"cryptlib and the code that calls it use the same\n"
				"         time_t data type.\n", 
				( long ) sizeof( time_t ) * 8 );
		exit( EXIT_FAILURE );
		}
	}
#endif /* WinCE */
=======
/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2023					*
*																			*
****************************************************************************/

#if defined( __Nucleus__ )
  #include <nu_ctype.h>
  #include <nu_string.h>
#else
  #include <ctype.h>	/* For toupper() */
#endif /* OS-specific includes */

#define _SAFETY_DEFINED
#if defined( __xlc__ ) || defined( __IBMC__ )
  #define CONST_RETURN 
#else
  #define CONST_RETURN	const
#endif /* IBM mainframe compilers */
#define DATAPTR			int
#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* Optionally include and activate the Visual Leak Detector library if
   we're running a debug build under VC++ 6.0.  Note that this can't be
   run at the same time as Bounds Checker, since the two interefere with
   each other */

#if defined( _MSC_VER ) && ( _MSC_VER == 1200 ) && 0
  #include "binaries/vld.h"
#endif /* VC++ 6.0 */

/* Microsoft broke the VS 2015 and newer runtime libraries by moving some 
   functions inline, which results in compile problems when linking to the 
   ODBC libs, which call functions that aren't externally visible any more 
   due to inlining.  To fix this, we have to implicitly add 
   legacy_stdio_definitions.lib to avoid link errors with the ODBC libs */

#if defined( _MSC_VER ) && ( _MSC_VER >= 1900 )
  #pragma comment( lib, "legacy_stdio_definitions.lib" )
#endif /* VS 2015 */

/* Optionally include the Intel Thread Checker API to control analysis */

#if defined( _MSC_VER ) && ( _MSC_VER == 1200 ) && 0
  #define USE_TCHECK
  #include "../../../Intel/VTune/tcheck/Include/libittnotify.h"
  #include "../../../Intel/VTune/Analyzer/Include/VtuneApi.h"
  #pragma comment( lib, "C:/Program Files/Intel/VTune/Analyzer/Lib/libittnotify.lib" )
  #pragma comment( lib, "C:/Program Files/Intel/VTune/Analyzer/Lib/VtuneApi.lib " )
  #define THREAD_DEBUG_SUSPEND()	__itt_pause(); VTPause()
  #define THREAD_DEBUG_RESUME()		VTResume(); __itt_resume()
#else
  #define THREAD_DEBUG_SUSPEND()
  #define THREAD_DEBUG_RESUME()
#endif /* VC++ 6.0 with Intel Thread Checker */

/* Warn about nonstandard build options */

#if ( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) ) && \
	defined( CONFIG_SUITEB_TESTS ) 
  #pragma message( "  Building Suite B command-line test configuration." )
#endif /* Notify Suite B tests */

/* Whether various keyset tests worked, the results are used later to test
   other routines.  We initially set the key read result to TRUE in case the
   keyset read tests are never called, so we can still trying reading the
   keys in other tests */

int keyReadOK = TRUE;		/* keyfile.c:testGetPGPPrivateKey() */
int doubleCertOK = FALSE;	/* keyfile.c:testDoubleCertFile() */

/* The output stream to which diagnostic output is sent */

FILE *outputStream;

/* There are some sizeable (for DOS) data structures used, so we increase the
   stack size to allow for them */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ )
  extern unsigned _stklen = 16384;
#endif /* __MSDOS16__ && __TURBOC__ */

/* Forward definitions for system-specific tests.  These need to be after 
   the main() function that they're called from since they pull in cryptlib-
   internal headers that would interfere with earlier code */

void testSystemSpecific1( void );
void testSystemSpecific2( void );

/* Prototype for Suite B test entry point */

#if defined( CONFIG_SUITEB_TESTS ) 

int suiteBMain( int argc, char **argv );

#endif /* CONFIG_SUITEB_TESTS */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The pseudo-CLI VC++ output windows are closed when the program exits so 
   we have to explicitly wait to allow the user to read them */

static void cleanExit( const int exitStatus )
	{
#if defined( __WINDOWS__ ) && !defined( NDEBUG )
	puts( "\nHit a key..." );
	( void ) getchar();
#endif /* __WINDOWS__ && !NDEBUG */
	exit( exitStatus );
	}
static void cleanupAndExit( const int exitStatus )
	{
	int status;

	status = cryptEnd();
	if( status == CRYPT_ERROR_INCOMPLETE )
		puts( "cryptEnd() failed with CRYPT_ERROR_INCOMPLETE." );
	cleanExit( exitStatus );
	}

/* Update the cryptlib config file.  This code can be used to set the
   information required to load PKCS #11 device drivers:

	- Set the driver path in the CRYPT_OPTION_DEVICE_PKCS11_DVR01 setting
	  below.
	- Add a call to updateConfig() from somewhere (e.g.the test kludge function).
	- Run the test code until it calls updateConfig().
	- Remove the updateConfig() call, then run the test code as normal.
	  The testDevices() call will report the results of trying to use your
	  driver.

  cryptlib's SafeLoadLibrary() will always load drivers from the Windows 
  system directory / %SystemDirectory% unless given an absolute path */

static void updateConfig( void )
	{
#if 0
	const char *driverPath = "acospkcs11.dll";		/* ACOS */
	const char *driverPath = "aetpkss1.dll";		/* AET */
	const char *driverPath = "aloaha_pkcs11.dll";	/* Aloaha */
	const char *driverPath = "etpkcs11.dll";		/* Aladdin eToken */
	const char *driverPath = "psepkcs11.dll";		/* A-Sign */
	const char *driverPath = "asepkcs.dll";			/* Athena */
	const char *driverPath = "c:/temp/bpkcs11.dll";	/* Bloomberg */
	const char *driverPath = "/usr/local/lib/libsc-hsm-pkcs11.so";  /* CardContact under Unix */	
	const char *driverPath = "cryst32.dll";			/* Chrysalis */
	const char *driverPath = "c:/program files/luna/cryst201.dll";	/* Chrysalis */
	const char *driverPath = "pkcs201n.dll";		/* Datakey */
	const char *driverPath = "dkck201.dll";			/* Datakey (for Entrust) */
	const char *driverPath = "dkck232.dll";			/* Datakey/iKey (NB: buggy, use 201) */
	const char *driverPath = "c:/program files/eracom/cprov sw/cryptoki.dll";	/* Eracom (old, OK) */
	const char *driverPath = "c:/program files (x86)/eracom/cprov sw/cryptoki.dll";	/* Eracom (old, OK) */
	const char *driverPath = "c:/program files/eracom/cprov runtime/cryptoki.dll";	/* Eracom (new, doesn't work) */
	const char *driverPath = "sadaptor.dll";		/* Eutron */
	const char *driverPath = "ngp11v211.dll";		/* Feitian Technology */
	const char *driverPath = "pk2priv.dll";			/* Gemplus */
	const char *driverPath = "c:/program files/gemplus/gclib.dll";	/* Gemplus */
	const char *driverPath = "cryptoki.dll";		/* IBM */
	const char *driverPath = "csspkcs11.dll";		/* IBM */
	const char *driverPath = "ibmpkcss.dll";		/* IBM */
	const char *driverPath = "id2cbox.dll";			/* ID2 */
	const char *driverPath = "cknfast.dll";			/* nCipher */
	const char *driverPath = "/opt/nfast/toolkits/pkcs11/libcknfast.so";/* nCipher under Unix */
	const char *driverPath = "/usr/lib/libcknfast.so";	/* nCipher under Unix */
	const char *driverPath = "c:/program files/mozilla firefox/softokn3.dll";/* Netscape */
	const char *driverPath = "nxpkcs11.dll";		/* Nexus */
	const char *driverPath = "AuCryptoki2-0.dll";	/* Oberthur */
	const char *driverPath = "opensc-pkcs11.dll";	/* OpenSC */
	const char *driverPath = "/usr/local/lib/opensc-pkcs11.so";	/* OpenSC under Unix */
	const char *driverPath = "micardoPKCS11.dll";	/* Orga Micardo */
	const char *driverPath = "cryptoki22.dll";		/* Rainbow HSM (for USB use Datakey dvr) */
	const char *driverPath = "p11card.dll";			/* Safelayer HSM (for USB use Datakey dvr) */
	const char *driverPath = "slbck.dll";			/* Schlumberger */
	const char *driverPath = "SetTokI.dll";			/* SeTec */
	const char *driverPath = "siecap11.dll";		/* Siemens */
	const char *driverPath = "c:/program files (x86)/SoftHSM2/lib/softhsm2.dll";	/* SoftHSM */
	const char *driverPath = "smartp11.dll";		/* SmartTrust */
	const char *driverPath = "SpyPK11.dll";			/* Spyrus */
#endif /* 0 */
	const char *driverPath = "c:/program files (x86)/eracom/cprov sw/cryptoki.dll";	/* Eracom (old, OK) */
	int status;

	printf( "Updating cryptlib configuration to load PKCS #11 driver\n  "
			"'%s'\nas default driver...", driverPath );

	/* Set the path for a PKCS #11 device driver.  We only enable one of
	   these at a time to speed the startup time */
	status = cryptSetAttributeString( CRYPT_UNUSED, 
									  CRYPT_OPTION_DEVICE_PKCS11_DVR01,
									  driverPath, strlen( driverPath ) );
	if( cryptStatusError( status ) )
		{
		printf( "\n\nError updating PKCS #11 device driver profile, "
				"status %d.\n", status );
		cleanupAndExit( EXIT_FAILURE );
		}

	/* Flush the updated options to disk */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, 
								FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "\n\nError comitting device driver profile update to disk, "
				"status %d.\n", status );
		cleanupAndExit( EXIT_FAILURE );
		}

	puts( " done.\n" );
	cleanupAndExit( EXIT_SUCCESS );
	}

/* Add trusted certs to the config file and make sure that they're
   persistent.  This can't be done in the normal self-test since it requires
   that cryptlib be restarted as part of the test to re-read the config file,
   and because it modifies the cryptlib config file */

static void updateConfigCert( void )
	{
	CRYPT_CERTIFICATE trustedCert;
	int status;

	/* Import the first certificate, make it trusted, and commit the changes */
	importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	cryptDestroyCert( trustedCert );
	cryptEnd();

	/* Do the same with a second certificate.  At the conclusion of this, we 
	   should have two trusted certificates on disk */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't reload cryptlib configuration." );
		return;
		}
	importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 2 );
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	cryptDestroyCert( trustedCert );
	cryptEnd();
	}

/* Check for a discrepancy between debug and release builds of the 
   library and self-test code */

#ifdef NDEBUG
  #define testIsRelease		TRUE
#else
  #define testIsRelease		FALSE
#endif /* NDEBUG */

static void checkDebugReleaseMismatch( void )
	{
	BOOLEAN libraryIsRelease = TRUE;

	/* Check whether cryptlib is running as a debug build */
	if( checkLibraryIsDebug() )
		libraryIsRelease = FALSE;

	/* Warn about mismatches between debug and release mode library and test
	   code builds:

		Library		Test code	Result
		-------		---------	------
		Debug		Debug		OK
		Debug		Release		Some unexpected results
		Release		Debug		Tests will fail
		Release		Release		OK */
	if( !libraryIsRelease && testIsRelease )
		{
		puts( "\nWarning: cryptlib has been built in debug mode but the "
			  "self-test code is\n         build in release mode, some "
			  "self-tests may produce unexpected\n         debug-only "
			  "results.\n\nHit a key..." );
		( void ) getchar();
		}
	if( libraryIsRelease && !testIsRelease )
		{
		puts( "\nWarning: cryptlib has been built in release mode but the "
			  "self-test code is\n         built in debug mode, some "
			  "self-tests will fail due to the code\n         trying to "
			  "exercise debug-only options.\n\nHit a key..." );
		getchar();
		}
	}

/* Check whether default algorithms are available and (temporarily) switch
   to an alternative if not */

static int checkDefaultAlgoAvailable( const CRYPT_ATTRIBUTE_TYPE algoType,
									  const char *algoDescription,
									  const CRYPT_ALGO_TYPE altAlgo )
	{
	int value, status;

	/* Check whether the given default algorithm is available */
	status = cryptGetAttribute( CRYPT_UNUSED, algoType, &value );
	if( cryptStatusError( status ) || \
		cryptStatusOK( cryptQueryCapability( value, NULL ) ) )
		return( TRUE );

	/* Indicate that this algorithm isn't available and try and switch to an 
	   alternative */
	printf( "Warning: Default %s algorithm %s isn't available,\n  "
			"temporarily switching to %s.\n", algoDescription, 
			algoName( value ), algoName( altAlgo ) );
	status = cryptSetAttribute( CRYPT_UNUSED, algoType, altAlgo );
	if( cryptStatusOK( status ) )
		return( TRUE );

	/* The alternative isn't available either, we can't continue */
	printf( "Error: Alternative %s algorithm %s isn't available either,\n  "
			"can't run the self-tests.\n", algoDescription, 
			algoName( altAlgo ) );
	return( FALSE );
	}

static int checkDefaultAlgosAvailable( void )
	{
	/* Check for algorithm availability and try and switch to alternatives,
	   checking whether CRYPT_OPTION_xxx is available and if not switching
	   to CRYPT_ALGO_xxx.  This hardcodes in knowledge of the default 
	   algorithms in order to avoid having to implement a knowledge base of 
	   fallback possibilities */
	if( !checkDefaultAlgoAvailable( CRYPT_OPTION_ENCR_ALGO, 
									"encryption", CRYPT_ALGO_3DES ) || \
		!checkDefaultAlgoAvailable( CRYPT_OPTION_ENCR_HASH, 
									"hash", CRYPT_ALGO_SHA1 ) || \
		!checkDefaultAlgoAvailable( CRYPT_OPTION_ENCR_MAC, 
									"MAC", CRYPT_ALGO_HMAC_SHA1 ) )
		return( FALSE );

	return( TRUE );
	}

/****************************************************************************
*																			*
*								Argument Processing							*
*																			*
****************************************************************************/

/* Flags for the tests that we want to perform */

#define DO_SELFTEST				0x0001
#define DO_LOWLEVEL				0x0002
#define DO_SMOKETEST			0x0004
#define DO_RANDOM				0x0008
#define DO_CONFIG				0x0010
#define DO_DEVICE				0x0020
#define DO_MIDLEVEL				0x0040
#define DO_CERT					0x0080
#define DO_KEYSETFILE			0x0100
#define DO_KEYSETDBX			0x0200
#define DO_CERTPROCESS			0x0400
#define DO_HIGHLEVEL			0x0800
#define DO_ENVELOPE				0x1000
#define DO_SESSION				0x2000
#define DO_SESSIONLOOPBACK		0x4000
#define DO_USER					0x8000

#define DO_ALL					0xFFFF

/* Show usage and exit */

static void usageExit( void )
	{
	puts( "Usage: testlib [-abcdefhiklmoprstu]" );

	puts( "  Encryption function tests:" );
	puts( "       -l = Test low-level functions" );
	puts( "       -m = Test mid-level functions" );
	puts( "       -i = Test high-level functions" );
	puts( "       -g = Perform smoke test of low-level functions" );
	puts( "" );

	puts( "  Subsystem tests:" );
	puts( "       -c = Test certificate subsystem" );
	puts( "       -d = Test device subsystem" );
	puts( "       -f = Test file keyset subsystem" );
	puts( "       -k = Test database keyset subsystem" );
	puts( "       -e = Test envelope subsystem" );
	puts( "       -s = Test session subsystem" );
	puts( "       -t = Test session subsystem via loopback interface" );
	puts( "       -u = Test user subsystem" );
	puts( "" );

	puts( "  Miscellaneous tests:" );
	puts( "       -r = Test entropy-gathering routines" );
	puts( "       -b = Perform built-in self-test" );
	puts( "       -o = Test configuration management routines" );
	puts( "       -p = Test certificate processing" );
	puts( "" );

	puts( "  Other options:" );
	puts( "       -a = All except networking tests, i.e. run only local tests" );
	puts( "       -h = Display this help text" );
	puts( "       -- = End of arg list" );
	puts( "" );

	puts( "Default is to test all cryptlib subsystems." );
	exit( EXIT_FAILURE );
	}

/* Process command-line arguments */

static int processArgs( int argc, char **argv, int *argFlags, 
						const char **zCmdPtrPtr, const char **zArgPtrPtr )
	{
	const char *zargPtr = NULL;
	BOOLEAN moreArgs = TRUE, isZArg = FALSE;

	/* Clear return values */
	*argFlags = 0;
	*zCmdPtrPtr = *zArgPtrPtr = NULL;

	/* No args means test everything */
	if( argc <= 0 )
		{
		*argFlags = DO_ALL;

		return( TRUE );
		}

	/* Check for arguments */
	while( argc > 0 && ( *argv[ 0 ] == '-' || isZArg ) && moreArgs )
		{
		const char *argPtr = argv[ 0 ] + 1;

		/* If the last argument was a -z one, this is the argument value 
		   that goes with it */
		if( isZArg )
			{
			isZArg = FALSE;
			*zArgPtrPtr = argv[ 0 ];
			argv++;
			argc--;
			continue;
			}

		while( *argPtr )
			{
			switch( toupper( *argPtr ) )
				{
				case '-':
					moreArgs = FALSE;	/* GNU-style end-of-args flag */
					break;

				case 'A':
					*argFlags = DO_ALL & ~( DO_SESSION | DO_SESSIONLOOPBACK );
					break;

				case 'B':
					*argFlags |= DO_SELFTEST;
					break;

				case 'C':
					*argFlags |= DO_CERT;
					break;

				case 'D':
					*argFlags |= DO_DEVICE;
					break;

				case 'E':
					*argFlags |= DO_ENVELOPE;
					break;

				case 'F':
					*argFlags |= DO_KEYSETFILE;
					break;

				case 'G':
					*argFlags |= DO_SMOKETEST;
					break;

				case 'H':
					usageExit();
					break;

				case 'I':
					*argFlags |= DO_HIGHLEVEL;
					break;

				case 'K':
					*argFlags |= DO_KEYSETDBX;
					break;

				case 'L':
					*argFlags |= DO_LOWLEVEL;
					break;

				case 'M':
					*argFlags |= DO_MIDLEVEL;
					break;

				case 'O':
					*argFlags |= DO_CONFIG;
					break;

				case 'P':
					*argFlags |= DO_CERTPROCESS;
					break;

				case 'R':
					*argFlags |= DO_RANDOM;
					break;

				case 'S':
					*argFlags |= DO_SESSION;
					break;

				case 'T':
					*argFlags |= DO_SESSIONLOOPBACK;
					break;

				case 'U':
					*argFlags |= DO_USER;
					break;

				case 'Z':
					zargPtr = argPtr + 1;
					if( *zargPtr == '\0' )
						{
						puts( "Error: Missing argument for -z option." );
						return( FALSE );
						}
					while( argPtr[ 1 ] )
						argPtr++;	/* Skip rest of arg */
					*zCmdPtrPtr = zargPtr;
					isZArg = TRUE;
					break;

				default:
					printf( "Error: Unknown argument '%c'.\n", *argPtr );
					return( FALSE );
				}
			argPtr++;
			}
		argv++;
		argc--;
		}
	if( argc > 0 )
		{
		printf( "Error: Unknown argument '%s'.\n", argv[ 0 ] );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*								Fuzzing Wrapper								*
*																			*
****************************************************************************/

/* Wrapper for injecting fuzz data */

#if defined( CONFIG_FUZZ ) && !defined( NDEBUG )

#ifdef __llvm__

const char* __asan_default_options( void )
	{
	/* ASAN integrates LeakSanitizer and enables it by default, we don't
	   want to be warned about leaks when fuzzing since the fuzzing code 
	   bails out as soon as it finds a problem without bothering with 
	   cleanups.
	   
	   This can also be done with __lsan_is_turned_off() { return 1; }
	   but we disable it at the ASAN level rather than the LSAN level */
	return( "detect_leaks=0" );
	}
#endif /* __llvm__ */

static int fuzzSession( const int sessionType,
						const char *fuzzFileName )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT cryptPrivKey = CRYPT_UNUSED;
	CRYPT_SUBPROTOCOL_TYPE subProtocol = CRYPT_SUBPROTOCOL_NONE;
	BYTE buffer[ 16384 ];
	const BOOLEAN isServer = \
			( sessionType == CRYPT_SESSION_SSH_SERVER || \
			  sessionType == CRYPT_SESSION_TLS_SERVER || \
			  sessionType == CRYPT_SESSION_OCSP_SERVER || \
			  sessionType == CRYPT_SESSION_SCVP_SERVER || \
			  sessionType == CRYPT_SESSION_RTCS_SERVER || \
			  sessionType == CRYPT_SESSION_TSP_SERVER || \
			  sessionType == CRYPT_SESSION_CMP_SERVER || \
			  sessionType == CRYPT_SESSION_SCEP_SERVER ) ? \
			TRUE : FALSE;
	int length, status;

	if( sessionType >= 5000 )
		{
		subProtocol = ( sessionType == 5000 ) ? \
						CRYPT_SUBPROTOCOL_WEBSOCKETS : \
					  ( sessionType == 5001 ) ? \
						CRYPT_SUBPROTOCOL_EAPTTLS : \
						CRYPT_SUBPROTOCOL_PEAP;
		}

	/* Create the session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 ( subProtocol != CRYPT_SUBPROTOCOL_NONE ) ? \
								   CRYPT_SESSION_TLS : sessionType );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the various attributes needed to establish a minimal session */
	if( isServer )
		{
		if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptPrivKey ) )
			return( CRYPT_ERROR_FAILED );
		}
	else
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_SERVER_NAME,
										  "localhost", 9 );
		if( cryptStatusError( status ) )
			return( status );
		if( sessionType == CRYPT_SESSION_TLS )
			{
			/* Set the version to match the fuzzing test data, TLS 1.2 */
			cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, 2 );
			}
		}
	if( sessionType == CRYPT_SESSION_SSH || \
		sessionType == CRYPT_SESSION_CMP )
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME,
										  SSH_USER_NAME,
										  paramStrlen( SSH_USER_NAME ) );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSession,
											  CRYPT_SESSINFO_PASSWORD,
											  SSH_PASSWORD,
											  paramStrlen( SSH_PASSWORD ) );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	if( sessionType == CRYPT_SESSION_CMP )
		{
		status = cryptSetAttribute( cryptSession,
									CRYPT_SESSINFO_CMP_REQUESTTYPE,
									CRYPT_REQUESTTYPE_INITIALISATION );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( sessionType == CRYPT_SESSION_SCVP )
		{
		/* SCVP uses rather larger messages for the server response, change 
		   the default buffer size to be able to contain them */
		status = cryptSetAttribute( cryptSession, 
									CRYPT_ATTRIBUTE_BUFFERSIZE, 
									16384 );
		if( cryptStatusError( status ) )
			return( status );
		}

	if( subProtocol != CRYPT_SUBPROTOCOL_NONE )
		{
		cryptSetAttribute( cryptSession, CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
						   subProtocol );
		}

	/* Perform any final session initialisation */
	cryptFuzzInit( cryptSession, cryptPrivKey );

	/* We're ready to go, start the forkserver and read the mutable data */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */
	length = readFileData( fuzzFileName, fuzzFileName, buffer, 16384, 32, 
						   TRUE );
	if( length < 32 )
		return( CRYPT_ERROR_READ );

	/* Perform the fuzzing */
	( void ) cryptSetFuzzData( cryptSession, buffer, length, subProtocol );
	cryptDestroySession( cryptSession );
	if( cryptPrivKey != CRYPT_UNUSED )
		cryptDestroyContext( cryptPrivKey );

	return( CRYPT_OK );
	}

static int fuzzFile( const char *fuzzFileName )
	{
	CRYPT_CERTIFICATE cryptCert;
	BYTE buffer[ 4096 ];
	int length, status;

	/* We're ready to go, start the forkserver and read the mutable data */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */
	length = readFileData( fuzzFileName, fuzzFileName, buffer, 4096, 64, 
						   TRUE );
	if( length < 64 )
		return( CRYPT_ERROR_READ );

	/* Process the input file */
	status = cryptImportCert( buffer, length, CRYPT_UNUSED, &cryptCert );
	if( cryptStatusOK( status ) )
		cryptDestroyCert( cryptCert );

	return( CRYPT_OK );
	}

static int fuzzEnvelope( const char *fuzzFileName )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	BYTE buffer[ 4096 ];
	int length, bytesIn, status;

	/* Create the envelope */
	status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED, 
								  CRYPT_FORMAT_AUTO );
	if( cryptStatusError( status ) )
		return( status );

	/* We're ready to go, start the forkserver and read the mutable data */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */
	length = readFileData( fuzzFileName, fuzzFileName, buffer, 4096, 64, 
						   TRUE );
	if( length < 64 )
		return( CRYPT_ERROR_READ );

	/* Process the input file */
	( void ) cryptPushData( cryptEnvelope, buffer, length, &bytesIn );
	cryptDestroyEnvelope( cryptEnvelope );

	return( CRYPT_OK );
	}

static int fuzzKeyset( const char *fuzzFileName )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Start the forkserver */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */

	/* Process the input file */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  fuzzFileName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		cryptKeysetClose( cryptKeyset );

	return( CRYPT_OK );
	}

static int fuzzSpecial( const int fuzzType, const char *fuzzFileName )
	{
	CRYPT_CONTEXT cryptPrivKey;
	CRYPT_SESSION cryptSession;
	BYTE buffer[ 8192 ];
	const BOOLEAN isServer = ( fuzzType == 4002 ) ? TRUE : FALSE;
	const int minLength = ( fuzzType == 4000 ) ? 2 : 16;
	int length, status;

	/* If we're fuzzing bignum ops, load the private key that we'll need */
	if( fuzzType == 4000 )
		{
		if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptPrivKey ) )
			return( CRYPT_ERROR_FAILED );
		}
	if( fuzzType == 4001 )
		{
		status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
									 CRYPT_SESSION_TLS );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_FAILED );
		}

	/* We're ready to go, start the forkserver and read the mutable data */
#ifdef __llvm__
	__AFL_INIT();
#endif /* __llvm__ */
	length = readFileData( fuzzFileName, fuzzFileName, buffer, 8192, 
						   minLength, TRUE );
	if( length < minLength )
		return( CRYPT_ERROR_READ );

	/* Process the input file */
	switch( fuzzType )
		{
		case 4000:	/* Bignum */
			{
			BYTE tmpBuffer[ 8192 ];

#if 0		/* We don't do an early-out in order to check that the bignum 
			   code can actually reject all invalid input values */
			/* Any value that's larger than the modulus will be trivially 
			   rejected so there's no point in trying to process it */
			if( buffer[ 0 ] > 0x9C )
				{
				cryptDestroyContext( cryptPrivKey );
				return( CRYPT_OK );
				}
#endif /* 0 */

			memcpy( tmpBuffer, buffer, length );
			status = cryptDecrypt( cryptPrivKey, buffer, length );
			if( cryptStatusOK( status ) )
				status = cryptEncrypt( cryptPrivKey, buffer, length );
			if( cryptStatusOK( status ) )
				{
				/* Make sure that we got back what we started with */
				assert( !memcmp( buffer, tmpBuffer, length ) );
				}
			cryptDestroyContext( cryptPrivKey );

			break;
			}

		case 4001:	/* URL */
			( void ) cryptSetAttributeString( cryptSession, 
											  CRYPT_SESSINFO_SERVER_NAME,
											  buffer, length );
			break;

		case 4002:	/* HTTP */
		case 4003:
			( void ) cryptFuzzSpecial( CRYPT_UNUSED, buffer, length, 
									   isServer, TRUE );
			break;

		case 4004:	/* EAP */
			( void ) cryptFuzzSpecial( CRYPT_UNUSED, buffer, length, 
									   FALSE, FALSE );
			break;

		default:
			assert( 0 );
		}

	return( CRYPT_OK );
	}

static int fuzz( const char *cmd, const char *arg )
	{
	static const struct {
		const char *fuzzTypeName;
		const int fuzzType;
		} fuzzTypeMap[] = {
		{ "base64", 1000 }, { "certificate", 1001 },
		{ "certchain", 1002 }, { "certreq", 1002 },
		{ "cms", 2000 }, { "pgp", 2001 },
		{ "pkcs12", 3000 }, { "pkcs15", 3001 },
		{ "pgppub", 3002 }, { "pgpsec", 3003 },
		{ "bignum", 4000 }, { "url", 4001 }, 
		{ "http-req", 4002 }, { "http-resp", 4003 },
		{ "eap", 4004 },
		{ "ssh-client", CRYPT_SESSION_SSH },
		{ "ssh-server", CRYPT_SESSION_SSH_SERVER },
		{ "tls-client", CRYPT_SESSION_TLS },
		{ "tls-server", CRYPT_SESSION_TLS_SERVER },
		{ "ocsp-client", CRYPT_SESSION_OCSP },
		{ "ocsp-server", CRYPT_SESSION_OCSP_SERVER },
		{ "rtcs-client", CRYPT_SESSION_RTCS },
		{ "rtcs-server", CRYPT_SESSION_RTCS_SERVER },
		{ "scvp-client", CRYPT_SESSION_SCVP },
		{ "scvp-server", CRYPT_SESSION_SCVP_SERVER },
		{ "tsp-client", CRYPT_SESSION_TSP },
		{ "tsp-server", CRYPT_SESSION_TSP_SERVER },
		{ "scep-client", CRYPT_SESSION_SCEP },
		{ "scep-server", CRYPT_SESSION_SCEP_SERVER },
		{ "cmp-client", CRYPT_SESSION_CMP },
		{ "cmp-server", CRYPT_SESSION_CMP_SERVER },
		{ "websockets", 5000 },
		{ NULL, 0 }
		};
	int i, fuzzType = -1, status;

	/* Test harness for code checking */
#if defined( __WINDOWS__ ) && 1
//	cmd = "base64"; arg = "test/fuzz/base64.dat";
//	cmd = "certificate"; arg = "test/fuzz/certificate.dat";
//	cmd = "certchain"; arg = "test/fuzz/certchain.dat";
//	cmd = "certreq"; arg = "test/fuzz/certreq.dat";
//	cmd = "cms"; arg = "test/fuzz/cms.dat";
//	cmd = "pgp"; arg = "test/fuzz/pgp.dat";
//	cmd = "pkcs12"; arg = "test/fuzz/pkcs12.dat";
//	cmd = "pkcs15"; arg = "test/fuzz/pkcs15.dat";
//
//	cmd = "tls-client"; arg = "test/fuzz/tls_svr.dat";
	cmd = "tls-server"; arg = "test/fuzz/tls_cli.dat";
//	cmd = "ssh-client"; arg = "test/fuzz/ssh_svr.dat";
//	cmd = "ssh-server"; arg = "test/fuzz/ssh_cli.dat";
//	cmd = "ocsp-client"; arg = "test/fuzz/ocsp_svr.dat";
//	cmd = "ocsp-server"; arg = "test/fuzz/ocsp_cli.dat";
//	cmd = "scvp-client"; arg = "test/fuzz/scvp_svr.dat";
//	cmd = "scvp-server"; arg = "test/fuzz/scvp_cli.dat";
//	cmd = "tsp-client"; arg = "test/fuzz/tsp_svr.dat";
//	cmd = "tsp-server"; arg = "test/fuzz/tsp_cli.dat";
//
//	cmd = "cmp-client"; arg = "test/fuzz/cmp_svr.dat";
//	cmd = "cmp-server"; arg = "test/fuzz/cmp_cli.dat";
//	cmd = "rtcs-client"; arg = "test/fuzz/rtcs_svr.dat";
//	cmd = "rtcs-server"; arg = "test/fuzz/rtcs_cli.dat";
//	cmd = "scep-client"; cmd = "scep-server"; Redundant, see comments below
//
//	cmd = "pgppub"; arg = "test/fuzz/pgppub.dat";
//	cmd = "pgpsec"; arg = "test/fuzz/pgpsec.dat";
//	cmd = "bignum"; arg = "test/fuzz/bignum.dat";
//	cmd = "url"; arg = "test/fuzz/url.dat";
//	cmd = "http-req"; arg = "test/fuzz/http_req.dat";
//	cmd = "http-resp"; arg = "test/fuzz/http_resp.dat";
//	cmd = "websockets"; arg = "test/fuzz/websockets.dat";
//	cmd = "eap"; arg = "test/fuzz/eap.dat";
#endif /* __WINDOWS__ test */

	/* Make sure that we've got an input arg */
	if( cmd == NULL )
		{
		printf( "Error: Missing argument fuzz type.\n" );
		exit( EXIT_FAILURE );
		}
	if( arg == NULL )
		{
		printf( "Error: Missing argument fuzz filename.\n" );
		exit( EXIT_FAILURE );
		}

	/* Figure out which type of fuzzing we're doing */
	for( i = 0; fuzzTypeMap[ i ].fuzzTypeName != NULL; i++ )
		{
		if( !strcmp( fuzzTypeMap[ i ].fuzzTypeName, cmd ) )
			{
			fuzzType = fuzzTypeMap[ i ].fuzzType;
			break;
			}
		}
	if( fuzzType == -1 )
		{
		printf( "Error: Invalid fuzz type '%s'.\n", cmd );
		exit( EXIT_FAILURE );
		}
	if( fuzzType == CRYPT_SESSION_SCEP || \
		fuzzType == CRYPT_SESSION_SCEP_SERVER )
		{
		/* SCEP uses CMS envelopes, which are already handled directly by
		   the envelope fuzzing.  In addition SCEP clients need to decrypt 
		   CMS messages returned by the server, encrypted to the certificate 
		   that they've just generated, which can't be emulated with static 
		   data */
		printf( "Error: SCEP uses CMS messages which are fuzzed via "
				"envelopes.\n" );
		exit( EXIT_FAILURE );
		}

	/* Fake out the randomness polling */
	status = cryptAddRandom( "xyzzy", 5 );
	if( cryptStatusError( status ) )
		{
		printf( "Error: Randomness setup failed with status %d.\n", status );
		exit( EXIT_FAILURE );
		}

	/* Patch point for checking crashes */
#if defined( __WINDOWS__ ) && 1
	{
	char buffer[ 128 ];

	for( i = 0; i < 100; i++ )
		{
		FILE *filePtr;

		sprintf( buffer, "r:/%s/%06d.dat", cmd, i );
		filePtr = fopen( buffer, "rb" );
		if( filePtr == NULL )
			{
			printf( "No more files at number %d (%s), exiting.\n", 
					i, buffer );
			break;
			}
		fclose( filePtr );
		printf( "Fuzzing %s file %d (%s).\n", cmd, i, buffer );
		if( fuzzType >= 1000 && fuzzType <= 1100 )
			status = fuzzFile( buffer );
		else 
		if( fuzzType >= 2000 && fuzzType <= 2100 )
			status = fuzzEnvelope( buffer );
		else 
		if( fuzzType >= 3000 && fuzzType <= 3100 )
			status = fuzzKeyset( buffer );
		else 
		if( fuzzType >= 4000 && fuzzType <= 4100 )
			status = fuzzSpecial( fuzzType, buffer );
		else
			status = fuzzSession( fuzzType, buffer );
		}
	puts( "Done." );
	if( i <= 0 )
		{
		puts( "Warning: No input files processed." );
		getchar();
		}
	exit( EXIT_SUCCESS );
	}
#endif /* __WINDOWS__ test */

	/* Fuzz the target file */
	if( fuzzType >= 1000 && fuzzType <= 1100 )
		status = fuzzFile( arg );
	else 
	if( fuzzType >= 2000 && fuzzType <= 2100 )
		status = fuzzEnvelope( arg );
	else 
	if( fuzzType >= 3000 && fuzzType <= 3100 )
		status = fuzzKeyset( arg );
	else
	if( fuzzType >= 4000 && fuzzType <= 4100 )
		status = fuzzSpecial( fuzzType, arg );
	else
	if( ( fuzzType > CRYPT_SESSION_NONE && \
		  fuzzType < CRYPT_SESSION_LAST ) || \
		( fuzzType >= 5000 && fuzzType <= 5100 ) )
		status = fuzzSession( fuzzType, arg );
	else
		{
		printf( "Error: Unknown fuzz type '%d'.\n", fuzzType );
		exit( EXIT_FAILURE );
		}
	if( cryptStatusError( status ) )
		{
		/* The fuzz init failed, make sure that the wrapper records this */
		exit( EXIT_FAILURE );
		}

	exit( EXIT_SUCCESS );
	}
#endif /* CONFIG_FUZZ && debug mode */

/****************************************************************************
*																			*
*								Misc.Kludges								*
*																			*
****************************************************************************/

/* Generic test code insertion point.  The following routine is called
   before any of the other tests are run and can be used to handle special-
   case tests that aren't part of the main test suite */

static void testKludge( const char *cmd, const char *arg )
	{
	/* Create the database keysets that are needed for some tests and 
	   populate them with sample certificates */
#if 0
	checkCreateDatabaseKeysets();
	testCertManagement();
#endif /* 0 */

	/* Fuzzing test harness.  This is a noreturn function */
#ifdef CONFIG_FUZZ
	fuzz( cmd, arg );
#endif /* CONFIG_FUZZ */

	/* Performance-testing test harness */
#if 0
	void performanceTests( const CRYPT_DEVICE cryptDevice );

	performanceTests( CRYPT_UNUSED );
#endif /* 0 */

	/* Simple (brute-force) server code. NB: setLocalConnect() by default 
	   will bind to localhost, to allow external connections and bind to a
	   particular IP address and port uncomment the alternative 
	   LOCAL_HOST_NAME configuration in test/test.h.

	   This can still exit if the client triggers a check in the debug 
	   build, which throws an exception and exits to the debugger rather 
	   than returning an error code, so the whole can be wrapped in:

		#!/bin/bash

		until ./server_app ; do
			echo "Server died with exit code $?, respawning.." >> log.txt
			sleep 1
		done 
		
	   to allow it to restart on a non-clean exit */
#if 0
	while( TRUE )
		{
		printf( "Running server session...\n" );
		testSessionTLS12Server();
		}
#endif /* 0 */

	/* Exit point for the test harnesses above, used when we don't want to 
	   fall through to the main test code */
#if 0
	cleanupAndExit( EXIT_SUCCESS );
#endif /* 0 */
	}

/****************************************************************************
*																			*
*								Main Test Code								*
*																			*
****************************************************************************/

/* Comprehensive cryptlib functionality test.  To get the following to run 
   under WinCE as a native console app it's necessary to change the entry 
   point in Settings | Link | Output from WinMainCRTStartup to the 
   undocumented mainACRTStartup, which calls main() rather than WinMain(), 
   however this only works if the system has a native console-mode driver 
   (most don't) */

int main( int argc, char **argv )
	{
	const char *zCmdPtr = NULL, *zArgPtr = NULL;
	const char *endianStringPtr;
	BOOLEAN sessionTestError = FALSE, loopbackTestError = FALSE;
	int flags, status;

	/* If we're running in a special test mode, run the test code and 
	   exit */
#ifdef CONFIG_SUITEB_TESTS
	return( suiteBMain( argc, argv ) );
#endif /* CONFIG_SUITEB_TESTS */

	/* Print a general banner to let the user know what's going on */
#if defined( DATA_LITTLEENDIAN ) || defined( CONFIG_DATA_LITTLEENDIAN )
	endianStringPtr = "little-endian";
#elif defined( DATA_BIGENDIAN ) || defined( CONFIG_DATA_BIGENDIAN )
	endianStringPtr = "big-endian";
#else
	if( *( ( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" ) < 0 )
		endianStringPtr = "big-endian";
	else
		endianStringPtr = "little-endian";
#endif /* Endianness */
	printf( "testlib - cryptlib %d-bit %s %sself-test framework.\n", 
			( int ) sizeof( size_t ) * 8,		/* Cast for gcc */
			endianStringPtr,
#if defined( __WINDOWS__ )
			"Windows "
#elif defined( _AIX ) || defined( __APPLE__ ) || defined( __FreeBSD__ ) || \
	   defined( __NetBSD__ ) || defined( __OpenBSD__ ) || \
	   defined( __hpux ) || defined( __linux__ ) || \
	   defined( __UNIX_SV__ ) || defined( __QNX__ ) || defined( __sgi ) || \
	   defined( sun )
			"Unix "
#else
			""
#endif /* OS names */
			);
	puts( "Copyright Peter Gutmann 1995 - 2024." );
#ifdef CONFIG_FUZZ
	puts( "" );
	puts( "Warning: This is a custom fuzzing build that operates in a nonstandard manner." );
	puts( "         Not to be used in a standard test or production environment." );
#endif /* CONFIG_FUZZ */
	puts( "" );

	/* Skip the program name and process any command-line arguments */
	argv++; argc--;
	status = processArgs( argc, argv, &flags, &zCmdPtr, &zArgPtr );
	if( !status )
		exit( EXIT_FAILURE );

#ifdef USE_TCHECK
	THREAD_DEBUG_SUSPEND();
#endif /* USE_TCHECK */

	/* Make sure that various system-specific features are set right */
	testSystemSpecific1();

	/* VisualAge C++ doesn't set the TZ correctly.  The check for this isn't
	   as simple as it would seem since most IBM compilers define the same
	   preprocessor values even though it's not documented anywhere, so we
	   have to enable the tzset() call for (effectively) all IBM compilers
	   and then disable it for ones other than VisualAge C++ */
#if ( defined( __IBMC__ ) || defined( __IBMCPP__ ) ) && !defined( __VMCMS__ )
	tzset();
#endif /* VisualAge C++ */

	/* Set up the output stream to which diagnostic output is sent */
	outputStream = stdout;

	/* Perform memory-allocation fault injection.  We have to do this before
	   we call cryptInit() since the init code itself is tested by the
	   memory fault-injection */
#ifdef TEST_MEMFAULT
	testMemFault();
#endif /* TEST_MEMFAULT */

	/* Initialise cryptlib */
	printf( "Initialising cryptlib..." );
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptInit() failed with error code %d, line %d.\n", 
				status, __LINE__ );
		exit( EXIT_FAILURE );
		}
	puts( "done." );

	/* Check for a discrepancy between debug and release builds of the 
	   library and self-test code */
	checkDebugReleaseMismatch();

	/* Check whether default algorithms are available and (temporarily) 
	   switch to an alternative if not */
	if( !checkDefaultAlgosAvailable() )
		{
		puts( "Default algorithms required for the self-test to run aren't "
			  "available in\nthis build, can't run the self-tests." );
		cryptEnd();
		exit( EXIT_FAILURE );
		}

	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk.  This is only
	   enabled when cryptlib is built in debug mode so it won't work with 
	   any production systems */
#ifndef TEST_RANDOM
  #if defined( __MVS__ ) || defined( __VMCMS__ )
	#pragma convlit( resume )
	cryptAddRandom( "xyzzy", 5 );
	#pragma convlit( suspend )
  #else
	cryptAddRandom( "xyzzy", 5 );
  #endif /* Special-case EBCDIC handling */
#endif /* TEST_RANDOM */

	/* For general testing purposes we can insert test code at this point to
	   test special cases that aren't covered in the general tests below.  
	   Note that this has to be called before any of the following checks if
	   the code is being run as a standalone executable outside the cryptlib
	   test environment */
	testKludge( zCmdPtr, zArgPtr );

	/* Perform a general sanity check to make sure that the self-test is
	   being run the right way */
	if( !checkFileAccess() )
		{
		cryptEnd();
		exit( EXIT_FAILURE );
		}

	/* Make sure that further system-specific features that require cryptlib 
	   to be initialised to check are set right */
#ifndef _WIN32_WCE
	testSystemSpecific2();
#endif /* WinCE */

#ifdef USE_TCHECK
	THREAD_DEBUG_RESUME();
#endif /* USE_TCHECK */

	/* Perform a general smoke test of the kernel.  This is always run 
	   before other tests are run */
	if( !testSmokeTestKernel() )
		goto errorExit;

	/* Test each block of cryptlib functionality */
	if( ( flags & DO_SELFTEST ) && !testSelfTest() )
		goto errorExit;
	if( ( flags & DO_LOWLEVEL ) && !testLowLevel() )
		goto errorExit;
	if( ( flags & DO_SMOKETEST ) && !testSmokeTestObjects() )
		goto errorExit;
	if( ( flags & DO_RANDOM ) && !testRandom() )
		goto errorExit;
	if( ( flags & DO_CONFIG ) && !testConfig() )
		goto errorExit;
	if( ( flags & DO_DEVICE ) && !testDevice() )
		goto errorExit;
	if( ( flags & DO_MIDLEVEL ) && !testMidLevel() )
		goto errorExit;
	if( ( flags & DO_CERT ) && !testCert() )
		goto errorExit;
	if( ( flags & DO_KEYSETFILE ) && !testKeysetFile() )
		goto errorExit;
	if( ( flags & DO_KEYSETDBX ) && !testKeysetDatabase() )
		goto errorExit;
	if( ( flags & DO_CERTPROCESS ) && !testCertMgmt() )
		goto errorExit;
	if( ( flags & DO_HIGHLEVEL ) && !testHighLevel() )
		goto errorExit;
	if( ( flags & DO_ENVELOPE ) && !testEnveloping() )
		goto errorExit;
	if( ( flags & DO_SESSION ) && !testSessions() )
		{
		sessionTestError = TRUE;
		goto errorExit;
		}
	if( ( flags & DO_SESSIONLOOPBACK ) && !testSessionsLoopback() )
		{
		loopbackTestError = TRUE;
		goto errorExit;
		}
	if( ( flags & DO_USER  ) && !testUsers() )
		goto errorExit;

	/* Shut down cryptlib */
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_INCOMPLETE )
			{
			puts( "cryptEnd() failed with error code CRYPT_ERROR_INCOMPLETE, "
				  "a code path in the\nself-test code resulted in an error "
				  "return without a full cleanup of objects.\nIf you were "
				  "running the multithreaded loopback tests this may be "
				  "because one\nor more threads lost sync with other threads "
				  "and exited without cleaning up\nits objects.  This "
				  "happens occasionally due to network timing issues or\n"
				  "thread scheduling differences." );
			}
		else
			{
			printf( "cryptEnd() failed with error code %d, line %d.\n", 
					status, __LINE__ );
			}
		goto errorExit1;
		}

	puts( "All tests concluded successfully." );
	return( EXIT_SUCCESS );

	/* All errors end up here */
errorExit:
	cryptEnd();
errorExit1:
	puts( "\nThe test was aborted due to an error being detected.  If you "
		  "want to report\nthis problem, please provide as much information "
		  "as possible to allow it to\nbe diagnosed, for example the call "
		  "stack, the location inside cryptlib where\nthe problem occurred, "
		  "and the values of any variables that might be\nrelevant." );
	if( sessionTestError )
		{
		puts( "\nThe error occurred during one of the network session tests, "
			  "if the error\nmessage indicates a network-level problem such "
			  "as ECONNREFUSED, ECONNRESET,\nor a timeout or read error then "
			  "this is either due to a transient\nnetworking problem or a "
			  "firewall interfering with network connections.  This\nisn't a "
			  "cryptlib error, and doesn't need to be reported." );
		}
	if( loopbackTestError )
		{
		puts( "\nThe error occurred during one of the multi-threaded network "
			  "loopback\ntests, this was probably due to the different threads "
			  "losing synchronisation.\nFor the secure sessions this usually "
			  "results in read/write, timeout, or\nconnection-closed errors "
			  "when one thread is pre-empted for too long.  For the\n"
			  "certificate-management sessions it usually results in an error "
			  "related to the\nserver being pre-empted for too long by database "
			  "updates.  Since the self-\ntest exists only to exercise "
			  "cryptlib's capabilities, it doesn't bother with\ncomplex thread "
			  "synchronisation during the multi-threaded loopback tests.\nThis "
			  "type of error is non-fatal, and should disappear if the test is "
			  "re-run." );
		}

	cleanExit( EXIT_FAILURE );
	return( EXIT_FAILURE );		/* Exists only to get rid of compiler warnings */
	}

/* PalmOS wrapper for main() */

#ifdef __PALMSOURCE__

#include <CmnErrors.h>
#include <CmnLaunchCodes.h>

uint32_t PilotMain( uint16_t cmd, void *cmdPBP, uint16_t launchFlags )
	{
	switch( cmd )
		{
		case sysAppLaunchCmdNormalLaunch:
			main( 0, NULL );
		}

	return( errNone );
	}
#endif /* __PALMSOURCE__ */

/* Symbian wrapper for main() */

#ifdef __SYMBIAN__

GLDEF_C TInt E32Main( void )
	{
	main( 0, NULL );

	return( KErrNone );
	}

#ifdef __WINS__

/* Support functions for use under the Windows emulator */

EXPORT_C TInt WinsMain( void )
	{
	E32Main();

	return( KErrNone );
	}

TInt E32Dll( TDllReason )
	{
	/* Entry point for the DLL loader */
	return( KErrNone );
	}
#endif /* __WINS__ */

#endif /* __SYMBIAN__ */

/* Test the system-specific defines in crypt.h.  This is the last function in
   the file because we want to avoid any definitions in crypt.h messing with
   the rest of the test.c code.

   The following include is needed only so we can check whether the defines
   are set right.  crypt.h should never be included in a program that uses
   cryptlib */

#undef __WINDOWS__
#undef __WIN16__
#undef __WIN32__
#undef BOOLEAN
#undef BYTE
#undef FALSE
#undef TRUE
#ifdef _MSC_VER
  #undef VC_16BIT
  #undef VC_LE_VC6
  #undef VC_LT_2005
  #undef VC_GE_2005
  #undef VC_GE_2010
  #undef VC_GE_2017
#endif /* _MSC_VER */
#define IN_STRING		/* No-op out define normally in analyse.h */
#ifdef HIRES_FORMAT_SPECIFIER
  #undef HIRES_FORMAT_SPECIFIER
  #define HIRES_TIME	HIRES_TIME_ALT	/* Rename typedef'd value */
#endif /* HIRES_TIME */
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( resume )
#endif /* Resume ASCII use on EBCDIC systems */
#if defined( __ILEC400__ )
  #pragma convert( 819 )
#endif /* Resume ASCII use on EBCDIC systems */
#ifdef _MSC_VER
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Braindamaged MSC include handling */
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( suspend )
#endif /* Suspend ASCII use on EBCDIC systems */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* Suspend ASCII use on EBCDIC systems */
#undef mktime		/* Undo mktime() bugfix in crypt.h */

#ifndef _WIN32_WCE

static time_t testTime( const int year )
	{
	struct tm theTime;

	memset( &theTime, 0, sizeof( struct tm ) );
	theTime.tm_isdst = -1;
	theTime.tm_year = 100 + year;
	theTime.tm_mon = 5;
	theTime.tm_mday = 5;
	theTime.tm_hour = 12;
	theTime.tm_min = 13;
	theTime.tm_sec = 14;
	return( mktime( &theTime ) );
	}
#endif /* !WinCE */

void testSystemSpecific1( void )
	{
#if 0	/* See comment below */
	const CRYPT_ATTRIBUTE_TYPE testType = -1;
#endif /* 0 */
	union {
		int intVal;
        char charVal[ 4 ];
		} 
	endiannessCheckValue = { 0x41414101 };
#ifndef _WIN32_WCE
	int i;
#endif /* WinCE */

	/* Make sure that we've got the endianness set right.  If the machine is
	   big-endian then the check value will be something other than 1, 
	   otherwise it will be 1 */
#ifdef DATA_LITTLEENDIAN
	if( endiannessCheckValue.charVal[ 0 ] != 1 )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nbig-endian, not little-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#else
	if( endiannessCheckValue.charVal[ 0 ] == 1 )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nlittle-endian, not big-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#endif /* DATA_LITTLEENDIAN */

#if 0	/* The ANSI C default is 'int' with signedness being unimportant, 
		   MSVC defaults to signed, gcc defaults to unsigned, and cryptlib
		   works with either, so whatever the CodeSourcery build of gcc is
		   doing it's more serious than a simple signedness issue */
	/* Make sure that the compiler doesn't use unsigned enums (for example a 
	   mutant CodeSourcery build of gcc for eCos does this) */
	if( testType >= 0 )
		{
		puts( "The compiler you are using treats enumerated types as "
			  "unsigned values,\nmaking it impossible to reliably use enums "
			  "in conjunction with standard\n(signed) integers.  To fix this "
			  "you need to rebuild cryptlib with the\nappropriate compiler "
			  "option or pragma to ensure that enumerated types\nare signed "
			  "like standard data types." );
		exit( EXIT_FAILURE );
		}
#endif /* 0 */

	/* Make sure that mktime() works properly (there are some systems on
	   which it fails well before 2038) */
#ifndef _WIN32_WCE
	for( i = 10; i < 36; i ++ )
		{
		const time_t theTime = testTime( i );

		if( theTime < 0 )
			{
			printf( "Warning: This system has a buggy mktime() that can't "
					"handle dates beyond %d.\n         Some certificate tests "
					"will fail, and long-lived CA certificates\n         won't "
					"be correctly imported.\nPress a key...\n", 2000 + i );
			( void ) getchar();
			break;
			}
		}
#endif /* !WinCE */

	/* If we're compiling under Unix with threading support, make sure the
	   default thread stack size is sensible.  We don't perform the check for
	   UnixWare/SCO since this already has the workaround applied */
#if defined( UNIX_THREADS ) && !defined( __SCO_VERSION__ )
	{
	pthread_attr_t attr;
	size_t stackSize;

	pthread_attr_init( &attr );
	pthread_attr_getstacksize( &attr, &stackSize );
    pthread_attr_destroy( &attr );
  #if ( defined( sun ) && OSVERSION > 4 )
	/* Slowaris uses a special-case value of 0 (actually NULL) to indicate
	   the default stack size of 1MB (32-bit) or 2MB (64-bit), so we have to
	   handle this specially */
	if( stackSize < 32768 && stackSize != 0 )
  #else
	if( stackSize < 32768 )
  #endif /* Slowaris special-case handling */
		{
		printf( "The pthread stack size is defaulting to %ld bytes, which is "
				"too small for\ncryptlib to run in.  To fix this, edit the "
				"thread-creation function macro in\nthread.h and recompile "
				"cryptlib.\n", ( long ) stackSize );
		exit( EXIT_FAILURE );
		}
	}
#endif /* UNIX_THREADS */
	}

#ifndef _WIN32_WCE	/* Windows CE doesn't support ANSI C time functions */

void testSystemSpecific2( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	const time_t theTime = time( NULL ) - 5;
#ifndef USE_CUSTOM_CONFIG_1
	int value;
#endif /* USE_CUSTOM_CONFIG_1 */
	int status;

	/* Make sure that we're running at a standard compliance level */
#ifndef USE_CUSTOM_CONFIG_1
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
								&value );
	if( cryptStatusError( status ) || value != CRYPT_COMPLIANCELEVEL_STANDARD )
		{
		printf( "Warning: cryptlib has been configured to run at a "
				"nonstandard certificate\n         compliance level %d "
				"instead of %d, this will upset the results of\n"
				"         the self-test and may cause some tests to "
				"fail.\n", value, CRYPT_COMPLIANCELEVEL_STANDARD );
		exit( EXIT_FAILURE );
		}
#endif /* USE_CUSTOM_CONFIG_1 */

	/* Make sure that the cryptlib and non-cryptlib code use the same time_t
	   size (some systems are moving from 32- to 64-bit time_t, which can 
	   lead to problems if the library and calling code are built with 
	   different sizes) */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_NOTAVAIL )
			{
			puts( "Couldn't create certificate object for time sanity-check "
				  "because certificate\nuse has been disabled, skipping "
				  "time sanity check...\n" );
			return;
			}
		puts( "Couldn't create certificate object for time sanity-check." );
		exit( EXIT_FAILURE );
		}
	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDFROM,
									  &theTime, sizeof( time_t ) );
	cryptDestroyCert( cryptCert );
	if( status == CRYPT_ERROR_PARAM4 )
		{
		printf( "Warning: This compiler is using a %ld-bit time_t data type, "
				"which appears to be\n         different to the one that "
				"was used when cryptlib was built.  This\n         situation "
				"usually occurs when the compiler allows the use of both\n"
				"         32- and 64-bit time_t data types and different "
				"options were\n         selected for building cryptlib and "
				"the test app.  To resolve this,\n         ensure that both "
				"cryptlib and the code that calls it use the same\n"
				"         time_t data type.\n", 
				( long ) sizeof( time_t ) * 8 );
		exit( EXIT_FAILURE );
		}
	}
#endif /* WinCE */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
