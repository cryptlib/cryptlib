<<<<<<< HEAD
/****************************************************************************
*																			*
*							cryptlib Core Routines							*
*						Copyright Peter Gutmann 1992-2021					*
*																			*
****************************************************************************/

/* Define the following to test time > Y2038 handling.  We have to define 
   this before including any other headers to make sure that the 32-bit
   time_t override is applied to everything */

#if defined( _MSC_VER ) && defined( _WIN32 ) && !defined( _WIN64 ) && 0
  #define _USE_32BIT_TIME_T
#endif /* Visual Studio Win32 */

#include "crypt.h"
#ifdef INC_ALL
  #include "kernelfns.h"
  #include "objectfns.h"
#else
  #include "kernel/kernelfns.h"
  #include "kernel/objectfns.h"
#endif /* Compiler-specific includes */

/* Some messages communicate standard data values that are used again and
   again so we predefine values for these that can be used globally */

const int messageValueTrue = TRUE;
const int messageValueFalse = FALSE;
const int messageValueCryptOK = CRYPT_OK;
const int messageValueCryptError = CRYPT_ERROR;
const int messageValueCryptUnused = CRYPT_UNUSED;
const int messageValueCryptUseDefault = CRYPT_USE_DEFAULT;
const int messageValueCursorFirst = CRYPT_CURSOR_FIRST;
const int messageValueCursorNext = CRYPT_CURSOR_NEXT;
const int messageValueCursorPrevious = CRYPT_CURSOR_PREVIOUS;
const int messageValueCursorLast = CRYPT_CURSOR_LAST;

/* Safe pointers need a NULL-equivalent value which we also define here */

const DATAPTR DATAPTR_NULL = DATAPTR_INIT;
const FNPTR FNPTR_NULL = FNPTR_INIT;

/* OS X Snow Leopard broke dlopen(), if it's called from a (sub-)thread then 
   it dies with a SIGTRAP.  Specifically, if you dlopen() a shared library 
   linked with CoreFoundation from a thread and the calling app wasn't 
   linked with CoreFoundation then the function CFInitialize() inside 
   dlopen() checks if the thread is the main thread (specifically 
   CFInitialize is declared with __attribute__ ((constructor))) and if it 
   isn't being called from the main thread it crashes with a SIGTRAP.  The 
   inability to call dlopen() from a thread was apparently a requirement in 
   pre-Snow Leopard versions as well but was never enforced.  One possible 
   workaround for this would be to require that any application that uses 
   cryptlib also link in CoreFoundation, but this will be rather error-
   prone, so we disable asynchronous driver binding instead */

#if defined( __APPLE__ )
  #undef USE_THREAD_FUNCTIONS
#endif /* __APPLE__  */

/* If we're fuzzing we also disable threaded init in order to make the 
   startup behaviour deterministic */

#if defined( CONFIG_FUZZ )
  #undef USE_THREAD_FUNCTIONS
#endif /* CONFIG_FUZZ */

/****************************************************************************
*																			*
*							Startup/Shutdown Routines						*
*																			*
****************************************************************************/

/* The initialisation and shutdown actions performed for various object
   types.  The pre-init actions are used to handle various preparatory
   actions that are required before the actual init can be performed, for
   example to create the system device and user object, which are needed by
   the init routines.  The pre-shutdown actions are used to signal to various
   subsystems that a shutdown is about to occur, for example to allow the
   networking subsystem to gracefully exit from any currently occurring 
   network I/O.

   The certificate init is somewhat special in that it only performs an
   internal consistency check rather than performing any actual 
   initialisation.  As such it's not performed as part of the asynchronous
   init since it has the potential to abort the cryptlib startup and as
   such can't be allowed to come back at a later date an retroactively shut 
   things down after other crypto operations have already occurred.  In fact
   since it's part of the startup self-test it's done in the pre-init, as a
   failure to complete the self-test will result in an immediate abort of the
   init process.

   The order of the init/shutdown actions is:

					Object type		Action
					-----------		------
	testFnality()					Tests basic functionality

	PreInit:		Cert			Attribute self-test
					Device			Create system object

	Init:			User			Create default user object, parent is system device
				  [ Device			Create crypto object, parent is user object ]

	complete init for user and crypto objects;

	Init (async):	Keyset			Drivers - keysets			| Done async.
					Device			Drivers - devices			| if
					Session			Drivers - networking		| available

	testKernel()					Tests kernel handling of objects

	PreShutdown:	Session			Networking - signal socket close
					Device			System object - signal entropy poll end

	Shutdown:		User			Destroy default user object	| Done
				  [ Device			Destroy crypto object ]		| by
					Device			Destroy system object		| kernel
					Keyset			Drivers - keysets
					Device			Drivers - devices
					Session			Drivers - networking

   The complete-init step is needed because the full setup of the user 
   object and crypto object can't be done while the initialistion isn't
   complete yet.  Specifically both the user and crypto objects need to 
   create keyset objects (configuration data for the user object, backing
   storage for the crypto object) which aren't available when the user/
   crypto objects are created, and the crypto object relies on the user
   object for some of its configuration information.

   The init order is determined by the following object dependencies:

	All -> Device
			(System object handles many message types).
	User -> Device
			(System object is parent of user object).
  [	Crypto -> User
			(User object is parent of crypto object) ].
	User -> Keyset
			(User object reads config data from the default keyset to init 
			 drivers for keysets, devices, and networking.  The default 
			 keyset isn't read via a loadable keyset driver so it doesn't 
			 require the keyset driver init).
  [	Crypto object -> User
			(Crypto object reads configuration settings from the user 
			 object) ].
	Self-test -> Several
			(Kernel self-test creates several ephemeral objects in order to 
			 test the kernel mechanisms).

   The shutdown order is determined by the following dependencies:

	Session (Networking needs to shut down to release any objects that are 
			 blocked waiting on network I/O)
	Device (System object needs to shut down ongoing entropy poll)

   After this the shutdown proper can take place.  The shutdown order is
   noncritical, provided that the pre-shutdown actions have occurred.

   In theory the user and system objects are destroyed as part of the 
   standard shutdown, however the kernel prevents these objects from ever
   being explicitly destroyed so they're destroyed implicitly by the
   destroyObjects() cleanup call */

typedef CHECK_RETVAL \
		int ( *MANAGEMENT_FUNCTION )( IN_ENUM( MANAGEMENT_ACTION ) \
										const MANAGEMENT_ACTION_TYPE action );

static const MANAGEMENT_FUNCTION preInitFunctions[] = {
  #ifdef USE_CERTIFICATES
	certManagementFunction,
  #endif /* USE_CERTIFICATES */
	deviceManagementFunction, 
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION initFunctions[] = {
	userManagementFunction, 
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	deviceManagementFunction, 
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION asyncInitFunctions[] = {
  #ifdef USE_KEYSETS
	keysetManagementFunction, 
  #endif /* USE_KEYSETS */
	deviceManagementFunction, 
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION preShutdownFunctions[] = {
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	deviceManagementFunction, 
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION shutdownFunctions[] = {
	/*userManagementFunction,*/ /*deviceManagementFunction,*/ 
  #ifdef USE_KEYSETS
	keysetManagementFunction, 
  #endif /* USE_KEYSETS */
	deviceManagementFunction, 
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	NULL, NULL 
	};

/* Dispatch a set of management actions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int dispatchManagementAction( IN_ARRAY( mgmtFunctionCount ) \
										const MANAGEMENT_FUNCTION *mgmtFunctions,
									 IN_INT_SHORT const int mgmtFunctionCount,
									 IN_ENUM( MANAGEMENT_ACTION ) \
										const MANAGEMENT_ACTION_TYPE action )
	{
	LOOP_INDEX i;
	int status = CRYPT_OK;

	assert( isReadPtr( mgmtFunctions, \
					   sizeof( MANAGEMENT_FUNCTION ) * mgmtFunctionCount ) );

	REQUIRES( isShortIntegerRangeNZ( mgmtFunctionCount ) );
	REQUIRES( isEnumRange( action, MANAGEMENT_ACTION ) );

	/* If we're performing a startup and the kernel is shutting down, bail 
	   out now */
	if( ( action == MANAGEMENT_ACTION_INIT || \
		  action == MANAGEMENT_ACTION_INIT_DEFERRED ) && krnlIsExiting() )
		return( CRYPT_ERROR_PERMISSION );

	/* Dispatch each management action in turn */
	LOOP_MED( i = 0, i < mgmtFunctionCount && \
					 mgmtFunctions[ i ] != NULL, i++ )
		{
		int localStatus;
		
		ENSURES( LOOP_INVARIANT_MED( i, 0, mgmtFunctionCount - 1 ) );
		localStatus = mgmtFunctions[ i ]( action );
		if( cryptStatusError( localStatus ) && cryptStatusOK( status ) )
			status = localStatus;

		/* If we're performing a startup and the kernel is shutting down, 
		   bail out now */
		if( ( action == MANAGEMENT_ACTION_INIT || \
			  action == MANAGEMENT_ACTION_INIT_DEFERRED ) && krnlIsExiting() )
			return( CRYPT_ERROR_PERMISSION );
		}
	ENSURES( LOOP_BOUND_OK );

	return( status );
	}

/* Under various OSes we bind to a number of drivers at runtime.  We can
   either do this sychronously or asynchronously depending on the setting of 
   a config option.  By default we use the async init since it speeds up the 
   startup.  Synchronisation is achieved by having the open/init functions 
   in the modules that require the drivers call krnlWaitSemaphore() on the 
   driver binding semaphore, which blocks until the drivers are bound if an 
   async bind is in progress, or returns immediately if no bind is in 
   progress */

#ifdef USE_THREAD_FUNCTIONS

static void threadedBind( const THREAD_PARAMS *threadParams )
	{
	assert( isReadPtr( threadParams, sizeof( THREAD_PARAMS ) ) );

	( void ) dispatchManagementAction( asyncInitFunctions, 
									   FAILSAFE_ARRAYSIZE( asyncInitFunctions, \
														   MANAGEMENT_FUNCTION ),
									   MANAGEMENT_ACTION_INIT_DEFERRED );
	}
#endif /* USE_THREAD_FUNCTIONS */

/* Display build/configuration information for diagnostic purposes */

#ifndef NDEBUG

#ifdef INC_ALL					/* For OS/architecture names */
  #include "bn.h"
  #include "osconfig.h"
  #define PARAM_ACL		void	/* For kernel.h */
  #include "kernel.h"
#else
  #include "bn/bn.h"
  #include "crypt/osconfig.h"
  #define PARAM_ACL		void	/* For kernel.h */
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

static void displayBuildParams( void )
	{
	const void *storagePtr;
	int storageSize;

	/* Dump general build parameters */
	DEBUG_PUTS(( "** Build parameters **" ));
	DEBUG_PRINT(( "cryptlib version is %d.%d.%d, ", 
				  CRYPTLIB_VERSION / 100, ( CRYPTLIB_VERSION / 10 ) % 10,  
				  CRYPTLIB_VERSION % 10 ));
	DEBUG_PRINT(( "system is " SYSTEM_NAME ", %d bit ", 
				  sizeof( size_t ) * 8 ));
#ifdef DATA_LITTLEENDIAN
	DEBUG_PUTS(( "little-endian." ));
#else
	DEBUG_PUTS(( "big-endian." ));
#endif /* DATA_LITTLEENDIAN */
	DEBUG_PRINT(( "Long long size = %d, long size = %d, int size = %d, "
				  "pointer size = %d.\n", sizeof( LONGLONG_TYPE ) * 8,
				  sizeof( long ) * 8, sizeof( int ) * 8, 
				  sizeof( void * ) * 8 ));
	DEBUG_PRINT(( "char is %d-bit %ssigned, wchar is %d-bit %ssigned, "
				  "time_t is %d-bit %ssigned.\n",
				  sizeof( char ) * 8, ( ( char ) -1 < 0 ) ? "" : "un", 
				  sizeof( wchar_t ) * 8, ( ( wchar_t ) -1 < 0 ) ? "" : "un",
				  sizeof( time_t ) * 8, ( ( time_t ) -1 < 0 ) ? "" : "un" ));
	DEBUG_PRINT(( "Bignum options: " ));
#if defined( SIXTY_FOUR_BIT_LONG )
	DEBUG_PRINT(( "SIXTY_FOUR_BIT_LONG, " ));
#elif defined( SIXTY_FOUR_BIT )
	DEBUG_PRINT(( "SIXTY_FOUR_BIT, " ));
#elif defined( THIRTY_TWO_BIT )
	DEBUG_PRINT(( "THIRTY_TWO_BIT, " ));
#else
	DEBUG_PRINT(( "(Unknown word size), " ));
#endif /* Word size defines */
#ifdef BN_DIV2W
	DEBUG_PRINT(( "BN_DIV2W, " ));
#endif /* BN_DIV2W */
	DEBUG_PRINT(( "BN_ULONG size = %d, ", sizeof( BN_ULONG ) * 8 ));
#ifdef BN_ULLONG
	DEBUG_PRINT(( "BN_ULLONG size = %d, ", sizeof( BN_ULLONG ) * 8 ));
#else
	DEBUG_PRINT(( "BN_ULLONG not used, " ));
#endif /* BN_ULLONG */
	DEBUG_PRINT(( "BIGNUM_BASE_ALLOCSIZE = %d, BIGNUM_ALLOC_WORDS = %d.\n", 
				  BIGNUM_BASE_ALLOCSIZE, BIGNUM_ALLOC_WORDS ));

	/* Dump system data information */
	DEBUG_PRINT(( "System storage: Kernel data = 0x%lX, %d bytes, "
				  "object table = 0x%lX, %d bytes for %d objects.\n", 
				  getSystemStorage( SYSTEM_STORAGE_KRNLDATA ), 
				  getSystemStorageSize( SYSTEM_STORAGE_KRNLDATA ), 
				  getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE ), 
				  getSystemStorageSize( SYSTEM_STORAGE_OBJECT_TABLE ),
				  MAX_NO_OBJECTS )); 
	DEBUG_PRINT(( "Built-in storage: Random info = 0x%lX, %d bytes",
				  getBuiltinStorage( BUILTIN_STORAGE_RANDOM_INFO ), 
				  getBuiltinStorageSize( BUILTIN_STORAGE_RANDOM_INFO ) ));
#ifdef USE_CERTIFICATES
	DEBUG_PRINT(( ", trust info = 0x%lX, %d bytes", 
				  getBuiltinStorage( BUILTIN_STORAGE_TRUSTMGR ),
				  getBuiltinStorageSize( BUILTIN_STORAGE_TRUSTMGR ) ));
#endif /* USE_CERTIFICATES */
#ifdef USE_TCP
	DEBUG_PRINT(( ", socket pool = 0x%lX, %d bytes", 
				  getBuiltinStorage( BUILTIN_STORAGE_SOCKET_POOL ), 
				  getBuiltinStorageSize( BUILTIN_STORAGE_SOCKET_POOL ) ));
#endif /* USE_TCP */
#ifdef USE_TLS
	DEBUG_PRINT(( ", session scoreboard = 0x%lX, %d bytes", 
				  getBuiltinStorage( BUILTIN_STORAGE_SCOREBOARD ), 
				  getBuiltinStorageSize( BUILTIN_STORAGE_SCOREBOARD ) ));
#endif /* USE_TLS */
	DEBUG_PRINT(( ", option info = 0x%lX, %d bytes.\n", 
				  getBuiltinStorage( BUILTIN_STORAGE_OPTION_INFO ), 
				  getBuiltinStorageSize( BUILTIN_STORAGE_OPTION_INFO ) ));

	/* Dump object storage information.  Allocations and deallocations dump
 	   their own diagnostic data so we need to display each entry on a 
       separate line.  We can't do this for context storage since we need
	   to know the size of the subtype-specific data to pass to 
	   getBuiltinObjectStorageSize() to allow it to select the appropriate
	   storage block */
	storagePtr = getBuiltinObjectStorage( OBJECT_TYPE_DEVICE, 
										  SUBTYPE_DEV_SYSTEM, 256 );
	storageSize = getBuiltinObjectStorageSize( OBJECT_TYPE_DEVICE, 
											   SUBTYPE_DEV_SYSTEM, 256 );
	DEBUG_PRINT(( "Object storage: System device = 0x%lX, %d bytes.\n", 
				  storagePtr, storageSize ));
	( void ) releaseBuiltinObjectStorage( OBJECT_TYPE_DEVICE, 
										  SUBTYPE_DEV_SYSTEM, storagePtr );
	storagePtr = getBuiltinObjectStorage( OBJECT_TYPE_USER, 
										  SUBTYPE_USER_SO, 256 );
	storageSize = getBuiltinObjectStorageSize( OBJECT_TYPE_USER, 
											   SUBTYPE_USER_SO, 256 );
	DEBUG_PRINT(( "Object storage: User object = 0x%lX, %d bytes.\n", 
				  storagePtr, storageSize ));
	( void ) releaseBuiltinObjectStorage( OBJECT_TYPE_USER, SUBTYPE_USER_SO, 
										  storagePtr );
#ifdef USE_KEYSETS
	storagePtr = getBuiltinObjectStorage( OBJECT_TYPE_KEYSET, 
										  SUBTYPE_KEYSET_FILE, 256 );
	storageSize = getBuiltinObjectStorageSize( OBJECT_TYPE_KEYSET, 
											   SUBTYPE_KEYSET_FILE, 256 );
	DEBUG_PRINT(( "Object storage: Keyset object = 0x%lX, %d bytes.\n", 
				  storagePtr, storageSize ));
	( void ) releaseBuiltinObjectStorage( OBJECT_TYPE_KEYSET, 
										  SUBTYPE_KEYSET_FILE, storagePtr );
#endif /* USE_KEYSETS */

	/* Dump custom configuration options */
#ifdef CONFIG_FUZZ
	DEBUG_PUTS(( "Warning: Using custom fuzzing build profile, not for "
				 "production use." ));
#endif /* CONFIG_FUZZ */
#ifdef CONFIG_ALL_OPTIONS
	DEBUG_PUTS(( "Warning: All possible build options are enabled, "
				 "including unsafe ones." ));
#endif /* CONFIG_ALL_OPTIONS */
#if defined( CONFIG_CUSTOM_1 )
	DEBUG_PUTS(( "Warning: Using custom build profile, cryptographic "
				 "operations may not work as expected." ));
#elif defined( CONFIG_CRYPTO_HW1 )
	DEBUG_PUTS(( "Warning: Cryptography is being performed through an "
				 "external crypto implementation." ));
#elif defined( CONFIG_CRYPTO_HW2 )
	DEBUG_PUTS(( "Warning: Cryptography and cryptographic mechanism "
				 "operations are being performed through an external "
				 "crypto implementation." ));
#endif /* Custom crypto configurations */
#if defined( CONFIG_PROFILE_SMIME )
	DEBUG_PUTS(( "Using custom build profile for S/MIME." ));
#elif defined( CONFIG_PROFILE_PGP )
	DEBUG_PUTS(( "Using custom build profile for PGP." ));
#elif defined( CONFIG_PROFILE_TLS )
	DEBUG_PUTS(( "Using custom build profile for TLS." ));
#elif defined( CONFIG_PROFILE_SSH )
	DEBUG_PUTS(( "Using custom build profile for SSH." ));
#endif /* Custom build profiles */
#ifdef CONFIG_CONSERVE_MEMORY
	DEBUG_PUTS(( "Using custom build profile for limited-memory "
				 "environments." ));
#endif /* CONFIG_CONSERVE_MEMORY */
#ifdef CONFIG_PKC_ALLOCSIZE
	DEBUG_PRINT(( "Using custom PKC allocation size %d.\n", 
				  CONFIG_PKC_ALLOCSIZE ));
#endif /* CONFIG_PKC_ALLOCSIZE */
#ifdef CONFIG_USE_PSEUDOCERTIFICATES
	DEBUG_PUTS(( "Using pseudocertificates for limited-memory "
				 "environments." ));
#endif /* CONFIG_USE_PSEUDOCERTIFICATES */
#ifdef CONFIG_RANDSEED
	DEBUG_PUTS(( "Using random number seed file for limited-entropy "
				 "environments." ));
#endif /* CONFIG_RANDSEED */

	/* Dump extended config/build options */
	DEBUG_PRINT(( "Extended build options:" ));
#ifdef USE_CAST
	DEBUG_PRINT(( " USE_CAST" ));
#endif /* USE_CAST */
#ifdef USE_CERT_DNSTRING
	DEBUG_PRINT(( " USE_CERT_DNSTRING" ));
#endif /* USE_CERT_DNSTRING */
#ifdef USE_CERT_OBSOLETE
	DEBUG_PRINT(( " USE_CERT_OBSOLETE" ));
#endif /* USE_CERT_OBSOLETE */
#if defined( USE_CERTLEVEL_PKIX_FULL )
	DEBUG_PRINT(( " USE_CERTLEVEL_PKIX_FULL" ));
#elif defined( USE_CERTLEVEL_PKIX_PARTIAL )
	DEBUG_PRINT(( " USE_CERTLEVEL_PKIX_PARTIAL" ));
#elif defined( USE_CERTLEVEL_STANDARD )
	DEBUG_PRINT(( " USE_CERTLEVEL_STANDARD" ));
#elif defined( USE_CERTLEVEL_REDUCED )
	DEBUG_PRINT(( " USE_CERTLEVEL_REDUCED" ));
#elif defined( USE_CERT_OBSCURE )
	DEBUG_PRINT(( " USE_CERT_OBSCURE" ));
#else
	DEBUG_PRINT(( " (Unknown cert level)" ));
#endif /* Certificate level */
#ifdef USE_CFB
	DEBUG_PRINT(( " USE_CFB" ));
#endif /* USE_CFB */
#ifdef USE_CHACHA20
	DEBUG_PRINT(( " USE_CHACHA20" ));
#endif /* USE_CHACHA20 */
#ifdef USE_CMSATTR_OBSCURE
	DEBUG_PRINT(( " USE_CMSATTR_OBSCURE" ));
#endif /* USE_CMSATTR_OBSCURE */
#ifdef USE_25519
	DEBUG_PRINT(( " USE_25519" ));
#endif /* USE_25519 */
#ifdef USE_DEPRECATED_ALGORITHMS
	DEBUG_PRINT(( " USE_DEPRECATED_ALGORITHMS" ));
#endif /* USE_DEPRECATED_ALGORITHMS */
#ifdef USE_DES
	DEBUG_PRINT(( " USE_DES" ));
#endif /* USE_DES */
#ifdef USE_DNSSRV
	DEBUG_PRINT(( " USE_DNSSRV" ));
#endif /* USE_DNSSRV */
#ifdef USE_EAP
	DEBUG_PRINT(( " USE_EAP" ));
#endif /* USE_EAP */
#ifdef USE_ECDH
	DEBUG_PRINT(( " USE_ECDH" ));
#endif /* USE_ECDH */
#ifdef USE_ECDSA
	DEBUG_PRINT(( " USE_ECDSA" ));
#endif /* USE_ECDSA */
#ifdef USE_EDDSA
	DEBUG_PRINT(( " USE_EDDSA" ));
#endif /* USE_EDDSA */
#ifdef USE_ELGAMAL
	DEBUG_PRINT(( " USE_ELGAMAL" ));
#endif /* USE_ELGAMAL */
#ifdef USE_EMBEDDED_OS
	DEBUG_PRINT(( " USE_EMBEDDED_OS" ));
#endif /* USE_EMBEDDED_OS */
#ifdef USE_ERRMSGS
	DEBUG_PRINT(( " USE_ERRMSGS" ));
#endif /* USE_ERRMSGS */
#ifdef USE_GCM
	DEBUG_PRINT(( " USE_GCM" ));
#endif /* USE_GCM */
#ifdef USE_HARDWARE
	DEBUG_PRINT(( " USE_HARDWARE" ));
#endif /* USE_HARDWARE */
#ifdef USE_IDEA
	DEBUG_PRINT(( " USE_IDEA" ));
#endif /* USE_IDEA */
#ifdef USE_INT_ASN1
	DEBUG_PRINT(( " USE_INT_ASN1" ));
#endif /* USE_INT_ASN1 */
#ifdef USE_JAVA
	DEBUG_PRINT(( " USE_JAVA" ));
#endif /* USE_JAVA */
#ifdef USE_LDAP
	DEBUG_PRINT(( " USE_LDAP" ));
#endif /* USE_LDAP */
#ifdef USE_OAEP
	DEBUG_PRINT(( " USE_OAEP" ));
#endif /* USE_OAEP */
#ifdef USE_OBSCURE_ALGORITHMS
	DEBUG_PRINT(( " USE_OBSCURE_ALGORITHMS" ));
#endif /* USE_OBSCURE_ALGORITHMS */
#ifdef USE_ODBC
	DEBUG_PRINT(( " USE_ODBC" ));
#endif /* USE_ODBC */
#ifdef USE_PATENTED_ALGORITHMS
	DEBUG_PRINT(( " USE_PATENTED_ALGORITHMS" ));
#endif /* USE_PATENTED_ALGORITHMS */
#ifdef USE_PGP2
	DEBUG_PRINT(( " USE_PGP2" ));
#endif /* USE_PGP2 */
#ifdef USE_PKCS11
	DEBUG_PRINT(( " USE_PKCS11" ));
#endif /* USE_PKCS11 */
#ifdef USE_PKCS12
	DEBUG_PRINT(( " USE_PKCS12" ));
#endif /* USE_PKCS12 */
#ifdef USE_PKCS12_WRITE
	DEBUG_PRINT(( " USE_PKCS12_WRITE" ));
#endif /* USE_PKCS12_WRITE */
#ifdef USE_POLY1305
	DEBUG_PRINT(( " USE_POLY1305" ));
#endif /* USE_POLY1305 */
#ifdef USE_PSEUDOCERTIFICATES
	DEBUG_PRINT(( " USE_PSEUDOCERTIFICATES" ));
#endif /* USE_PSEUDOCERTIFICATES */
#ifdef USE_PSS
	DEBUG_PRINT(( " USE_PSS" ));
#endif /* USE_PSS */
#ifdef USE_RC2
	DEBUG_PRINT(( " USE_RC2" ));
#endif /* USE_RC2 */
#ifdef USE_RC4
	DEBUG_PRINT(( " USE_RC4" ));
#endif /* USE_RC4 */
#ifdef USE_RSA_SUITES
	DEBUG_PRINT(( " USE_RSA_SUITES" ));
#endif /* USE_RSA_SUITES */
#ifdef USE_SHA2_EXT
	DEBUG_PRINT(( " USE_SHA2_EXT" ));
#endif /* USE_SHA2_EXT */
#ifdef USE_SSH_EXTENDED
	DEBUG_PRINT(( " USE_SSH_EXTENDED" ));
#endif /* USE_SSH_EXTENDED */
#ifdef USE_SSH_CTR
	DEBUG_PRINT(( " USE_SSH_CTR" ));
#endif /* USE_SSH_CTR */
#ifdef USE_THREADS
	DEBUG_PRINT(( " USE_THREADS" ));
#endif /* USE_THREADS */
#ifdef USE_TLS13
	DEBUG_PRINT(( " USE_TLS13" ));
#endif /* USE_TLS13 */
#ifdef USE_TPM
	DEBUG_PRINT(( " USE_TPM" ));
#endif /* USE_TPM */
#ifdef USE_WEBSOCKETS
	DEBUG_PRINT(( " USE_WEBSOCKETS" ));
#endif /* USE_WEBSOCKETS */
#ifdef USE_WIDECHARS
	DEBUG_PRINT(( " USE_WIDECHARS" ));
#endif /* USE_WIDECHARS */
	DEBUG_PRINT(( ".\n" ));

	/* Dump compiler-specific options */
	DEBUG_PUTS(( "Build date/time for file " __FILE__ " is " __DATE__ ", " 
				 __TIME__ "." ));
#ifdef __STDC_VERSION__
	DEBUG_PRINT(( "STDC_VERSION = %ld.\n", __STDC_VERSION__ ));
#endif /* __STDC_VERSION__ */
#ifdef _POSIX_VERSION
	DEBUG_PRINT(( "POSIX_VERSION = %ld.\n", _POSIX_VERSION ));
#endif /* _POSIX_VERSION */
#ifdef __clang__
  #ifdef __apple_build_version__
	/* Apple completely breaks clang versioning, reporting the Xcode version 
	   as the clang version, see https://gist.github.com/yamaya/2924292 */
	DEBUG_PRINT(( "Apple clang (falsely) claims version = " __clang_version__ 
				  ", from Xcode version = %06d.\n", __apple_build_version__ ));
  #else
	DEBUG_PUTS(( "clang version = " __clang_version__ "." ));
	#ifdef __EMSCRIPTEN__ 
	  DEBUG_PUTS(( "  (Running as emscripten)." ));
	#endif /* __EMSCRIPTEN__ */
  #endif /* Apple's broken clang versioning */
#endif /* __clang__ */
#ifdef __GNUC__
	DEBUG_PUTS(( "gcc version = " __VERSION__ "." ));
#endif /* __GNUC__ */
#ifdef __HP_cc
	DEBUG_PRINTF(( "HP cc version = %06d.\n", __HP_cc ));
#endif /* __HP_cc */
#ifdef __IAR_SYSTEMS_ICC__
	DEBUG_PRINTF(( "IAR cc version = %d (%d.%d.%d)\n", __IAR_SYSTEMS_ICC__, 
				   __VER__ / 1000000L, ( __VER__ / 1000L ) % 1000L,
				   __VER__ % 1000L ));
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef _MSC_VER
	DEBUG_PRINT(( "Visual C version = %ld (%ld).\n", _MSC_VER, 
				  _MSC_FULL_VER ));
#endif /* _MSC_VER */
#ifdef __RENESAS__
	DEBUG_PRINT(( "Renesas CC-RX version = %lX.\n", __RENESAS_VERSION__ ));
#endif /* __RENESAS__ */
#ifdef __SUNPRO_C
	DEBUG_PRINT(( "SunPro cc version = %X.\n", __SUNPRO_C ));
#endif /* __SUNPRO_C */
#if defined( __xlc__ )
	DEBUG_PRINT(( "IBM xlc version = %X.\n", __xlC__ ));
#elif defined( __IBMC__ )
	DEBUG_PRINT(( "IBM c89 version = %X.\n", __IBMC__ ));
#endif /* Different, semi-overlapping IBM compilers */
#if defined( __GNUC__ ) || defined( __clang__ )
	if( !__builtin_constant_p( MK_TOKEN( "1234" ) ) )
		{
		DEBUG_PUTS(( "Warning: Call stack tokens aren't being computed by "
					 "the preprocessor,\n         this will lead to code "
					 "bloat in control-flow integrity checks." ));
		}
#endif /* Warn on non-preprocessor evaluation of MK_TOKEN() */
	}

static void displayConfigParams( void )
	{
	const int hwIntrins = getSysVar( SYSVAR_HWINTRINS );
#ifdef __UNIX__ 
	const int hwCrypt = getSysVar( SYSVAR_HWCRYPT );
#endif /* __UNIX__  */

	/* Dump configuration parameters */
	DEBUG_PUTS(( "** Configuration parameters **" ));
	if( hwIntrins != 0 )
		{
		DEBUG_PRINT(( "Hardware intrinsics:" ));
		if( hwIntrins & HWINTRINS_FLAG_RDTSC )
			DEBUG_PRINT(( " RDTSC" ));
		if( hwIntrins & HWINTRINS_FLAG_XSTORE )
			DEBUG_PRINT(( " XSTORE" ));
		if( hwIntrins & HWINTRINS_FLAG_XCRYPT )
			DEBUG_PRINT(( " XCRYPT" ));
		if( hwIntrins & HWINTRINS_FLAG_XSHA )
			DEBUG_PRINT(( " XSHA" ));
		if( hwIntrins & HWINTRINS_FLAG_MONTMUL )
			DEBUG_PRINT(( " MONTMUL" ));
		if( hwIntrins & HWINTRINS_FLAG_TRNG )
			DEBUG_PRINT(( " TRNG" ));
		if( hwIntrins & HWINTRINS_FLAG_AES )
			DEBUG_PRINT(( " AES" ));
		if( hwIntrins & HWINTRINS_FLAG_RDRAND )
			DEBUG_PRINT(( " RDRAND" ));
		if( hwIntrins & HWINTRINS_FLAG_RDSEED )
			DEBUG_PRINT(( " RDSEED" ));
		DEBUG_PRINT(( ".\n" ));
		}
#ifdef __UNIX__ 
	if( hwCrypt != 0 )
		{
		DEBUG_PRINT(( "Hardware crypto:" ));

		if( hwCrypt & HWCRYPT_FLAG_CRYPTDEV_3DES )
			DEBUG_PRINT(( " 3DES" ));
		if( hwCrypt & HWCRYPT_FLAG_CRYPTDEV_AES )
			DEBUG_PRINT(( " AES" ));
		if( hwCrypt & HWCRYPT_FLAG_CRYPTDEV_SHA1 )
			DEBUG_PRINT(( " SHA1" ));
		if( hwCrypt & HWCRYPT_FLAG_CRYPTDEV_SHA2 )
			DEBUG_PRINT(( " SHA2" ));
		DEBUG_PRINT(( ".\n" ));
		}
#endif /* __UNIX__ */

	/* Check for, and warn about, missing system capabilities */
	if( getTime( GETTIME_NONE ) <= MIN_TIME_VALUE )
		{
		DEBUG_DIAG(( "Warning: No time source available, certificate, "
					 "message signing, PKI, and TLS operations will fail "
					 "if used." ));
  #ifdef USE_TLS
		DEBUG_DIAG(( "Warning: The TLS session cache requires a time "
					 "source, since USE_TLS is enabled this will result in "
					 "a self-test failure on startup." ));
  #endif /* USE_TLS */
		}
	}
#else
  #define displayBuildParams()
  #define displayConfigParams()
#endif /* !NDEBUG */

/* Perform various sanity checks on the build process.  Since this will 
   typically be running on an embedded system there's not much that we can 
   (safely) do in terms of user I/O except to return a special-case return 
   code and hope that the user checks the embedded systems section of the 
   manual for more details, although we do try and produce diagnostic output 
   if this is enabled */

static BOOLEAN sanityCheckBuild( void )
	{
	static const long intVal = 1;
	BYTE data[ 16 ];

	/* Perform a sanity check to make sure that the endianness was set 
	   right.  The crypto self-test that's performed a bit later on will 
	   catch this problem as well but it's better to do an explicit check 
	   here that catches the endianness problem rather than just returning a 
	   generic self-test fail error */
#ifdef DATA_LITTLEENDIAN
	if( !*( ( char * ) &intVal ) )
#else
	if( *( ( char * ) &intVal ) )
#endif /* DATA_LITTLEENDIAN */
			{
			/* We should probably sound klaxons as well at this point */
			DEBUG_PUTS(( "Error in build: CPU endianness is configured "
						 "incorrectly, see the cryptlib manual for "
						 "details." ));
			return( FALSE );
			}

	/* Make sure that isValidPointer() isn't reporting valid pointers as
	   being invalid.  This could in theory happen on some hypothetical OS
	   that does odd things with memory layouts so we check for it here */
	if( !isValidPointer( data ) || !isValidPointer( preInitFunctions ) )
		{
		DEBUG_PUTS(( "Error in build: isValidPointer() macro reports data "
					 "or code pointer is invalid when it's valid, see "
					 "misc/safety.h." ));
		return( FALSE );
		}
#ifndef NDEBUG		/* Only visible in the debug build */
	if( !isValidPointer( getSystemStorage( SYSTEM_STORAGE_KRNLDATA ) ) )
		{
		DEBUG_PRINT(( "Error in build: Static data segment is located at "
					  "%lX which isn't recognised by isValidPointer().\n",
					  getSystemStorage( SYSTEM_STORAGE_KRNLDATA ) ));
		return( FALSE );
		}
#endif /* NDEBUG */

	/* If we're working with a maximum time value beyond Y2038, make sure 
	   that the system time functions can actually handle this.
	   
	   To test this under Visual Studio 32-bit, enable the define at the 
	   start of this module */
#if MAX_TIME_VALUE > MAX_TIME_VALUE_Y2038
	if( sizeof( time_t ) < 8 )
		{
		static const time_t time1 = 0x7FFFFFFFUL, time2 = 0x80000000UL;
		static const time_t time3 = 0xEFFFFFFFUL;
		struct tm tmStruct, *tmStructPtr;
		time_t theTime;

        tmStructPtr = gmtime( &time1 );
		if( tmStructPtr == NULL || \
			tmStructPtr->tm_year != 138 || \
			tmStructPtr->tm_mon != 0 || \
			tmStructPtr->tm_mday != 19 )
			{
			DEBUG_PUTS(( "Time values above Y2038 are enabled but gmtime()/"
						 "localtime() can't handle values in this "
						 "range.\n" ));
			return( FALSE );
			}
        tmStructPtr = gmtime( &time2 );
		if( tmStructPtr == NULL || \
			tmStructPtr->tm_year != 138 || \
			tmStructPtr->tm_mon != 0 || \
			tmStructPtr->tm_mday != 19 )
			{
			DEBUG_PUTS(( "Time values above Y2038 are enabled but gmtime()/"
						 "localtime() can't handle values in this "
						 "range.\n" ));
			return( FALSE );
			}
        tmStructPtr = gmtime( &time3 );
		if( tmStructPtr == NULL || \
			tmStructPtr->tm_year != 197 || \
			tmStructPtr->tm_mon != 7 || \
			tmStructPtr->tm_mday != 5 )
			{
			DEBUG_PUTS(( "Time values above Y2038 are enabled but gmtime()/"
						 "localtime() can't handle values in this "
						 "range.\n" ));
			return( FALSE );
			}
		memset( &tmStruct, 0, sizeof( struct tm ) );
		tmStruct.tm_year = 200;
		tmStruct.tm_mon = 1;
		tmStruct.tm_mday = 2;
		tmStruct.tm_hour = 3;
		tmStruct.tm_min = 4;
		tmStruct.tm_sec = 5;
		theTime = mktime( &tmStruct );
		if( theTime < ( 0xF4B0B225UL - ( 14 * 3600L ) ) || \
			theTime > ( 0xF4B0B225UL + ( 14 * 86400L ) ) )
			{
			/* mktime() is a pain because it converts to the local time so 
			   we check whether the result is within 14 hours of the UTC
			   result (there are time zones that can go to +13 and +14).  
			   This is fine since we're checking for overflow/underflow, not 
			   the exact conversion, and don't want to bail out if things 
			   are off by an hour or two due to DST or similar issues */
			DEBUG_PUTS(( "Time values above Y2038 are enabled but mktime() "
						 "can't handle values in this range.\n" ));
			return( FALSE );
			}
		}
#endif /* Time beyond Y2038 */

	return( TRUE );
	}

/* Initialise and shut down the system */

CHECK_RETVAL \
int initCryptlib( void )
	{
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int initLevel = 0, status;

	/* Let the user know that we're in the cryptlib startup code if they're in
	   debug mode */
	DEBUG_PUTS(( "" ));
	DEBUG_PUTS(( "***************************" ));
	DEBUG_PUTS(( "* Beginning cryptlib init *" ));
	DEBUG_PUTS(( "***************************" ));
	DEBUG_PUTS(( "" ));

	/* Display build parameters in debug mode.  We do this before we do 
	   anything else that may cause a crash or abort.  Note that this calls
	   cryptlib-internal routines before the kernel mutex is initialised and
	   check in krnlBeginInit(), which can lead to unexpected results if 
	   initCryptlib() is called incorrectly */
	displayBuildParams();

	/* Perform any required sanity checks on the build process.  This would
	   be caught by the self-test but sometimes people don't run this so we
	   perform a minimal sanity check here to avoid failing in the startup
	   self-tests that follow */
	if( !sanityCheckBuild() )
		{
		DEBUG_DIAG(( "Build sanity-check failed" ));
		retIntError();
		}
	CFI_CHECK_UPDATE( "sanityCheckBuild" );

	/* Initiate the kernel startup */
	DEBUG_PUTS(( "** Initialising kernel **" ));
	status = krnlBeginInit();
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "Kernel init failed, status = %d", status ));
		return( status );
		}
	CFI_CHECK_UPDATE( "krnlBeginInit" );

	/* Perform OS-specific additional initialisation.  Note that this step 
	   must come before the self-tests since some of them perform operations
	   that depend on SysVar settings */
	DEBUG_PUTS(( "** Initialising system variables **" ));
	status = initSysVars();
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "OS-specific initialisation failed, status = %d", 
					 status ));
		assert( DEBUG_WARN );
		krnlCompleteShutdown();
		return( CRYPT_ERROR_FAILED );
		}
	CFI_CHECK_UPDATE( "initSysVars" );

	/* Display configuration parameters in debug mode */
	displayConfigParams();

	/* Verify that core functionality and universal crypto algorithms are 
	   working as required, unless we're running a fuzzing build for which 
	   we don't want to get held up too long in startup */
#if !defined( CONFIG_FUZZ ) && !defined( CONFIG_CONSERVE_MEMORY_EXTRA )
	DEBUG_PUTS(( "** Running general functionality self-tests **" ));
	status = testFunctionality();
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "General functionality test failed, status = %d", 
					 status ));
		assert( DEBUG_WARN );
		krnlCompleteShutdown();
		return( CRYPT_ERROR_FAILED );
		}
#endif /* !CONFIG_FUZZ && !CONFIG_CONSERVE_MEMORY_EXTRA */
	CFI_CHECK_UPDATE( "testFunctionality" );

	/* Perform the multi-phase bootstrap */
	DEBUG_PUTS(( "** Running pre-init actions **" ));
	status = dispatchManagementAction( preInitFunctions, 
									   FAILSAFE_ARRAYSIZE( preInitFunctions, \
														   MANAGEMENT_FUNCTION ),
									   MANAGEMENT_ACTION_PRE_INIT );
	assertNoFault( cryptStatusOK( status ) );
	if( cryptStatusOK( status ) )
		{
		initLevel = 1;
		CFI_CHECK_UPDATE( "preInitFunctions" );
		DEBUG_PUTS(( "** Running init actions **" ));
		status = dispatchManagementAction( initFunctions, 
										   FAILSAFE_ARRAYSIZE( initFunctions, \
															   MANAGEMENT_FUNCTION ),
										   MANAGEMENT_ACTION_INIT );
		assertNoFault( cryptStatusOK( status ) );
		}
	if( cryptStatusOK( status ) )
		{
		/* Now that all of the init actions have completed, we can also 
		   complete the setup of the system objects created during the init 
		   phase */
		CFI_CHECK_UPDATE( "initFunctions" );
		DEBUG_PUTS(( "** Running init completion actions **" ));
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_OK,
								  CRYPT_IATTRIBUTE_COMPLETEINIT );
		assertNoFault( cryptStatusOK( status ) );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_OK,
								  CRYPT_IATTRIBUTE_COMPLETEINIT );
		assertNoFault( cryptStatusOK( status ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
		}
	if( cryptStatusOK( status ) )
		{
#ifdef USE_THREAD_FUNCTIONS
		BOOLEAN_INT asyncInit = FALSE;
#endif /* USE_THREAD_FUNCTIONS */

		initLevel = 2;
		CFI_CHECK_UPDATE( "initCompletionFunctions" );

		/* Perform the final init phase asynchronously or synchronously 
		   depending on the config option setting.  We always send this 
		   query to the default user object since no other user objects 
		   exist at this time */
		DEBUG_PUTS(( "** Running async init actions **" ));
#ifdef USE_THREAD_FUNCTIONS
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, &asyncInit, 
								  CRYPT_OPTION_MISC_ASYNCINIT );
		if( cryptStatusOK( status ) && asyncInit == TRUE )
			{
			/* We use the kernel's thread storage for this thread, so we 
			   specify the thread data storage as NULL */
			status = krnlDispatchThread( threadedBind, NULL, NULL, 0,
										 SEMAPHORE_DRIVERBIND );
			if( cryptStatusError( status ) )
				{
				/* The thread couldn't be started, try again with a 
				   synchronous init */
				asyncInit = FALSE;
				}
			}
		if( !asyncInit )
#endif /* USE_THREAD_FUNCTIONS */
		status = dispatchManagementAction( asyncInitFunctions, 
										   FAILSAFE_ARRAYSIZE( asyncInitFunctions, \
															   MANAGEMENT_FUNCTION ),
										   MANAGEMENT_ACTION_INIT_DEFERRED );
		assertNoFault( cryptStatusOK( status ) );
		}
#if !defined( CONFIG_FUZZ ) && !defined( CONFIG_CONSERVE_MEMORY_EXTRA )
	if( cryptStatusOK( status ) )
		{
		CFI_CHECK_UPDATE( "asyncInitFunctions" );

		/* Everything's set up, verify that the core crypto algorithms and 
		   kernel security mechanisms are working as required, unless we're
		   running a fuzzing build for which we don't want to get held up
		   too long in startup */
		DEBUG_PUTS(( "** Running kernel self-tests **" ));
		status = testKernel();
		assertNoFault( cryptStatusOK( status ) );
		}
#else
	CFI_CHECK_UPDATE( "asyncInitFunctions" );
#endif /* !CONFIG_FUZZ && !CONFIG_CONSERVE_MEMORY_EXTRA */

	/* If anything failed, shut down the internal functions and services
	   before we exit */
	if( cryptStatusError( status ) )
		{
		if( initLevel >= 1 )
			{
			/* Shut down any external interfaces */
			( void ) dispatchManagementAction( preShutdownFunctions, 
									FAILSAFE_ARRAYSIZE( preShutdownFunctions, \
														MANAGEMENT_FUNCTION ),
									MANAGEMENT_ACTION_PRE_SHUTDOWN );
			( void ) destroyObjects();
			( void ) dispatchManagementAction( shutdownFunctions, 
									FAILSAFE_ARRAYSIZE( shutdownFunctions, \
														MANAGEMENT_FUNCTION ),
									MANAGEMENT_ACTION_SHUTDOWN );
			}
		krnlCompleteShutdown();
		return( status );
		}

	/* Complete the kernel startup */
	DEBUG_PUTS(( "** Completing kernel init **" ));
	krnlCompleteInit();
	CFI_CHECK_UPDATE( "krnlCompleteInit" );

	/* Let the user know that the cryptlib startup has completed 
	   successfully if they're in debug mode */
	DEBUG_PUTS(( "" ));
	DEBUG_PUTS(( "***************************" ));
	DEBUG_PUTS(( "* cryptlib init completed *" ));
	DEBUG_PUTS(( "***************************" ));
	DEBUG_PUTS(( "" ));

	ENSURES( CFI_CHECK_SEQUENCE_9( "sanityCheckBuild", "krnlBeginInit", 
								   "initSysVars", "testFunctionality", 
								   "preInitFunctions", "initFunctions", 
								   "initCompletionFunctions", 
								   "asyncInitFunctions", "krnlCompleteInit" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL \
int endCryptlib( void )
	{
	int status;

	/* Let the user know that we're in the cryptlib shutdown code if they're 
	   in debug mode */
	DEBUG_PUTS(( "" ));
	DEBUG_PUTS(( "*******************************" ));
	DEBUG_PUTS(( "* Beginning cryptlib shutdown *" ));
	DEBUG_PUTS(( "*******************************" ));
	DEBUG_PUTS(( "" ));

	/* Initiate the kernel shutdown */
	status = krnlBeginShutdown();
	if( cryptStatusError( status ) )
		return( status );

	/* Reverse the process carried out in the multi-phase bootstrap */
	( void ) dispatchManagementAction( preShutdownFunctions, 
							FAILSAFE_ARRAYSIZE( preShutdownFunctions, \
												MANAGEMENT_FUNCTION ),
							MANAGEMENT_ACTION_PRE_SHUTDOWN );
	status = destroyObjects();
	( void ) dispatchManagementAction( shutdownFunctions, 
							FAILSAFE_ARRAYSIZE( shutdownFunctions, \
												MANAGEMENT_FUNCTION ),
							MANAGEMENT_ACTION_SHUTDOWN );

	/* Complete the kernel shutdown */
	krnlCompleteShutdown();

	/* Let the user know that the cryptlib shutdown has completed 
	   successfully if they're in debug mode */
	DEBUG_PUTS(( "" ));
	DEBUG_PUTS(( "*******************************" ));
	DEBUG_PUTS(( "* cryptlib shutdown completed *" ));
	DEBUG_PUTS(( "*******************************" ));
	DEBUG_PUTS(( "" ));


	return( status );
	}
=======
/****************************************************************************
*																			*
*							cryptlib Core Routines							*
*						Copyright Peter Gutmann 1992-2021					*
*																			*
****************************************************************************/

/* Define the following to test time > Y2038 handling.  We have to define 
   this before including any other headers to make sure that the 32-bit
   time_t override is applied to everything */

#if defined( _MSC_VER ) && defined( _WIN32 ) && !defined( _WIN64 ) && 0
  #define _USE_32BIT_TIME_T
#endif /* Visual Studio Win32 */

#include "crypt.h"
#ifdef INC_ALL
  #include "kernelfns.h"
  #include "objectfns.h"
#else
  #include "kernel/kernelfns.h"
  #include "kernel/objectfns.h"
#endif /* Compiler-specific includes */

/* Some messages communicate standard data values that are used again and
   again so we predefine values for these that can be used globally */

const int messageValueTrue = TRUE;
const int messageValueFalse = FALSE;
const int messageValueCryptOK = CRYPT_OK;
const int messageValueCryptError = CRYPT_ERROR;
const int messageValueCryptUnused = CRYPT_UNUSED;
const int messageValueCryptUseDefault = CRYPT_USE_DEFAULT;
const int messageValueCursorFirst = CRYPT_CURSOR_FIRST;
const int messageValueCursorNext = CRYPT_CURSOR_NEXT;
const int messageValueCursorPrevious = CRYPT_CURSOR_PREVIOUS;
const int messageValueCursorLast = CRYPT_CURSOR_LAST;

/* Safe pointers need a NULL-equivalent value which we also define here */

const DATAPTR DATAPTR_NULL = DATAPTR_INIT;
const FNPTR FNPTR_NULL = FNPTR_INIT;

/* OS X Snow Leopard broke dlopen(), if it's called from a (sub-)thread then 
   it dies with a SIGTRAP.  Specifically, if you dlopen() a shared library 
   linked with CoreFoundation from a thread and the calling app wasn't 
   linked with CoreFoundation then the function CFInitialize() inside 
   dlopen() checks if the thread is the main thread (specifically 
   CFInitialize is declared with __attribute__ ((constructor))) and if it 
   isn't being called from the main thread it crashes with a SIGTRAP.  The 
   inability to call dlopen() from a thread was apparently a requirement in 
   pre-Snow Leopard versions as well but was never enforced.  One possible 
   workaround for this would be to require that any application that uses 
   cryptlib also link in CoreFoundation, but this will be rather error-
   prone, so we disable asynchronous driver binding instead */

#if defined( __APPLE__ )
  #undef USE_THREAD_FUNCTIONS
#endif /* __APPLE__  */

/* If we're fuzzing we also disable threaded init in order to make the 
   startup behaviour deterministic */

#if defined( CONFIG_FUZZ )
  #undef USE_THREAD_FUNCTIONS
#endif /* CONFIG_FUZZ */

/****************************************************************************
*																			*
*							Startup/Shutdown Routines						*
*																			*
****************************************************************************/

/* The initialisation and shutdown actions performed for various object
   types.  The pre-init actions are used to handle various preparatory
   actions that are required before the actual init can be performed, for
   example to create the system device and user object, which are needed by
   the init routines.  The pre-shutdown actions are used to signal to various
   subsystems that a shutdown is about to occur, for example to allow the
   networking subsystem to gracefully exit from any currently occurring 
   network I/O.

   The certificate init is somewhat special in that it only performs an
   internal consistency check rather than performing any actual 
   initialisation.  As such it's not performed as part of the asynchronous
   init since it has the potential to abort the cryptlib startup and as
   such can't be allowed to come back at a later date an retroactively shut 
   things down after other crypto operations have already occurred.  In fact
   since it's part of the startup self-test it's done in the pre-init, as a
   failure to complete the self-test will result in an immediate abort of the
   init process.

   The order of the init/shutdown actions is:

					Object type		Action
					-----------		------
	testFnality()					Tests basic functionality

	PreInit:		Cert			Attribute self-test
					Device			Create system object

	Init:			User			Create default user object, parent is system device
				  [ Device			Create crypto object, parent is user object ]

	complete init for user and crypto objects;

	Init (async):	Keyset			Drivers - keysets			| Done async.
					Device			Drivers - devices			| if
					Session			Drivers - networking		| available

	testKernel()					Tests kernel handling of objects

	PreShutdown:	Session			Networking - signal socket close
					Device			System object - signal entropy poll end

	Shutdown:		User			Destroy default user object	| Done
				  [ Device			Destroy crypto object ]		| by
					Device			Destroy system object		| kernel
					Keyset			Drivers - keysets
					Device			Drivers - devices
					Session			Drivers - networking

   The complete-init step is needed because the full setup of the user 
   object and crypto object can't be done while the initialistion isn't
   complete yet.  Specifically both the user and crypto objects need to 
   create keyset objects (configuration data for the user object, backing
   storage for the crypto object) which aren't available when the user/
   crypto objects are created, and the crypto object relies on the user
   object for some of its configuration information.

   The init order is determined by the following object dependencies:

	All -> Device
			(System object handles many message types).
	User -> Device
			(System object is parent of user object).
  [	Crypto -> User
			(User object is parent of crypto object) ].
	User -> Keyset
			(User object reads config data from the default keyset to init 
			 drivers for keysets, devices, and networking.  The default 
			 keyset isn't read via a loadable keyset driver so it doesn't 
			 require the keyset driver init).
  [	Crypto object -> User
			(Crypto object reads configuration settings from the user 
			 object) ].
	Self-test -> Several
			(Kernel self-test creates several ephemeral objects in order to 
			 test the kernel mechanisms).

   The shutdown order is determined by the following dependencies:

	Session (Networking needs to shut down to release any objects that are 
			 blocked waiting on network I/O)
	Device (System object needs to shut down ongoing entropy poll)

   After this the shutdown proper can take place.  The shutdown order is
   noncritical, provided that the pre-shutdown actions have occurred.

   In theory the user and system objects are destroyed as part of the 
   standard shutdown, however the kernel prevents these objects from ever
   being explicitly destroyed so they're destroyed implicitly by the
   destroyObjects() cleanup call */

typedef CHECK_RETVAL \
		int ( *MANAGEMENT_FUNCTION )( IN_ENUM( MANAGEMENT_ACTION ) \
										const MANAGEMENT_ACTION_TYPE action );

static const MANAGEMENT_FUNCTION preInitFunctions[] = {
  #ifdef USE_CERTIFICATES
	certManagementFunction,
  #endif /* USE_CERTIFICATES */
	deviceManagementFunction, 
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION initFunctions[] = {
	userManagementFunction, 
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	deviceManagementFunction, 
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION asyncInitFunctions[] = {
  #ifdef USE_KEYSETS
	keysetManagementFunction, 
  #endif /* USE_KEYSETS */
	deviceManagementFunction, 
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION preShutdownFunctions[] = {
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	deviceManagementFunction, 
	NULL, NULL 
	};
static const MANAGEMENT_FUNCTION shutdownFunctions[] = {
	/*userManagementFunction,*/ /*deviceManagementFunction,*/ 
  #ifdef USE_KEYSETS
	keysetManagementFunction, 
  #endif /* USE_KEYSETS */
	deviceManagementFunction, 
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	NULL, NULL 
	};

/* Dispatch a set of management actions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int dispatchManagementAction( IN_ARRAY( mgmtFunctionCount ) \
										const MANAGEMENT_FUNCTION *mgmtFunctions,
									 IN_INT_SHORT const int mgmtFunctionCount,
									 IN_ENUM( MANAGEMENT_ACTION ) \
										const MANAGEMENT_ACTION_TYPE action )
	{
	LOOP_INDEX i;
	int status = CRYPT_OK;

	assert( isReadPtr( mgmtFunctions, \
					   sizeof( MANAGEMENT_FUNCTION ) * mgmtFunctionCount ) );

	REQUIRES( isShortIntegerRangeNZ( mgmtFunctionCount ) );
	REQUIRES( isEnumRange( action, MANAGEMENT_ACTION ) );

	/* If we're performing a startup and the kernel is shutting down, bail 
	   out now */
	if( ( action == MANAGEMENT_ACTION_INIT || \
		  action == MANAGEMENT_ACTION_INIT_DEFERRED ) && krnlIsExiting() )
		return( CRYPT_ERROR_PERMISSION );

	/* Dispatch each management action in turn */
	LOOP_MED( i = 0, i < mgmtFunctionCount && \
					 mgmtFunctions[ i ] != NULL, i++ )
		{
		int localStatus;
		
		ENSURES( LOOP_INVARIANT_MED( i, 0, mgmtFunctionCount - 1 ) );
		localStatus = mgmtFunctions[ i ]( action );
		if( cryptStatusError( localStatus ) && cryptStatusOK( status ) )
			status = localStatus;

		/* If we're performing a startup and the kernel is shutting down, 
		   bail out now */
		if( ( action == MANAGEMENT_ACTION_INIT || \
			  action == MANAGEMENT_ACTION_INIT_DEFERRED ) && krnlIsExiting() )
			return( CRYPT_ERROR_PERMISSION );
		}
	ENSURES( LOOP_BOUND_OK );

	return( status );
	}

/* Under various OSes we bind to a number of drivers at runtime.  We can
   either do this sychronously or asynchronously depending on the setting of 
   a config option.  By default we use the async init since it speeds up the 
   startup.  Synchronisation is achieved by having the open/init functions 
   in the modules that require the drivers call krnlWaitSemaphore() on the 
   driver binding semaphore, which blocks until the drivers are bound if an 
   async bind is in progress, or returns immediately if no bind is in 
   progress */

#ifdef USE_THREAD_FUNCTIONS

static void threadedBind( const THREAD_PARAMS *threadParams )
	{
	assert( isReadPtr( threadParams, sizeof( THREAD_PARAMS ) ) );

	( void ) dispatchManagementAction( asyncInitFunctions, 
									   FAILSAFE_ARRAYSIZE( asyncInitFunctions, \
														   MANAGEMENT_FUNCTION ),
									   MANAGEMENT_ACTION_INIT_DEFERRED );
	}
#endif /* USE_THREAD_FUNCTIONS */

/* Display build/configuration information for diagnostic purposes */

#ifndef NDEBUG

#ifdef INC_ALL					/* For OS/architecture names */
  #include "bn.h"
  #include "osconfig.h"
  #define PARAM_ACL		void	/* For kernel.h */
  #include "kernel.h"
#else
  #include "bn/bn.h"
  #include "crypt/osconfig.h"
  #define PARAM_ACL		void	/* For kernel.h */
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

static void displayBuildParams( void )
	{
	const void *storagePtr;
	int storageSize;

	/* Dump general build parameters */
	DEBUG_PUTS(( "** Build parameters **" ));
	DEBUG_PRINT(( "cryptlib version is %d.%d.%d, ", 
				  CRYPTLIB_VERSION / 100, ( CRYPTLIB_VERSION / 10 ) % 10,  
				  CRYPTLIB_VERSION % 10 ));
	DEBUG_PRINT(( "system is " SYSTEM_NAME ", %d bit ", 
				  sizeof( size_t ) * 8 ));
#ifdef DATA_LITTLEENDIAN
	DEBUG_PUTS(( "little-endian." ));
#else
	DEBUG_PUTS(( "big-endian." ));
#endif /* DATA_LITTLEENDIAN */
	DEBUG_PRINT(( "Long long size = %d, long size = %d, int size = %d, "
				  "pointer size = %d.\n", sizeof( LONGLONG_TYPE ) * 8,
				  sizeof( long ) * 8, sizeof( int ) * 8, 
				  sizeof( void * ) * 8 ));
	DEBUG_PRINT(( "char is %d-bit %ssigned, wchar is %d-bit %ssigned, "
				  "time_t is %d-bit %ssigned.\n",
				  sizeof( char ) * 8, ( ( char ) -1 < 0 ) ? "" : "un", 
				  sizeof( wchar_t ) * 8, ( ( wchar_t ) -1 < 0 ) ? "" : "un",
				  sizeof( time_t ) * 8, ( ( time_t ) -1 < 0 ) ? "" : "un" ));
	DEBUG_PRINT(( "Bignum options: " ));
#if defined( SIXTY_FOUR_BIT_LONG )
	DEBUG_PRINT(( "SIXTY_FOUR_BIT_LONG, " ));
#elif defined( SIXTY_FOUR_BIT )
	DEBUG_PRINT(( "SIXTY_FOUR_BIT, " ));
#elif defined( THIRTY_TWO_BIT )
	DEBUG_PRINT(( "THIRTY_TWO_BIT, " ));
#else
	DEBUG_PRINT(( "(Unknown word size), " ));
#endif /* Word size defines */
#ifdef BN_DIV2W
	DEBUG_PRINT(( "BN_DIV2W, " ));
#endif /* BN_DIV2W */
	DEBUG_PRINT(( "BN_ULONG size = %d, ", sizeof( BN_ULONG ) * 8 ));
#ifdef BN_ULLONG
	DEBUG_PRINT(( "BN_ULLONG size = %d, ", sizeof( BN_ULLONG ) * 8 ));
#else
	DEBUG_PRINT(( "BN_ULLONG not used, " ));
#endif /* BN_ULLONG */
	DEBUG_PRINT(( "BIGNUM_BASE_ALLOCSIZE = %d, BIGNUM_ALLOC_WORDS = %d.\n", 
				  BIGNUM_BASE_ALLOCSIZE, BIGNUM_ALLOC_WORDS ));

	/* Dump system data information */
	DEBUG_PRINT(( "System storage: Kernel data = 0x%lX, %d bytes, "
				  "object table = 0x%lX, %d bytes for %d objects.\n", 
				  getSystemStorage( SYSTEM_STORAGE_KRNLDATA ), 
				  getSystemStorageSize( SYSTEM_STORAGE_KRNLDATA ), 
				  getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE ), 
				  getSystemStorageSize( SYSTEM_STORAGE_OBJECT_TABLE ),
				  MAX_NO_OBJECTS )); 
	DEBUG_PRINT(( "Built-in storage: Random info = 0x%lX, %d bytes",
				  getBuiltinStorage( BUILTIN_STORAGE_RANDOM_INFO ), 
				  getBuiltinStorageSize( BUILTIN_STORAGE_RANDOM_INFO ) ));
#ifdef USE_CERTIFICATES
	DEBUG_PRINT(( ", trust info = 0x%lX, %d bytes", 
				  getBuiltinStorage( BUILTIN_STORAGE_TRUSTMGR ),
				  getBuiltinStorageSize( BUILTIN_STORAGE_TRUSTMGR ) ));
#endif /* USE_CERTIFICATES */
#ifdef USE_TCP
	DEBUG_PRINT(( ", socket pool = 0x%lX, %d bytes", 
				  getBuiltinStorage( BUILTIN_STORAGE_SOCKET_POOL ), 
				  getBuiltinStorageSize( BUILTIN_STORAGE_SOCKET_POOL ) ));
#endif /* USE_TCP */
#ifdef USE_TLS
	DEBUG_PRINT(( ", session scoreboard = 0x%lX, %d bytes", 
				  getBuiltinStorage( BUILTIN_STORAGE_SCOREBOARD ), 
				  getBuiltinStorageSize( BUILTIN_STORAGE_SCOREBOARD ) ));
#endif /* USE_TLS */
	DEBUG_PRINT(( ", option info = 0x%lX, %d bytes.\n", 
				  getBuiltinStorage( BUILTIN_STORAGE_OPTION_INFO ), 
				  getBuiltinStorageSize( BUILTIN_STORAGE_OPTION_INFO ) ));

	/* Dump object storage information.  Allocations and deallocations dump
 	   their own diagnostic data so we need to display each entry on a 
       separate line.  We can't do this for context storage since we need
	   to know the size of the subtype-specific data to pass to 
	   getBuiltinObjectStorageSize() to allow it to select the appropriate
	   storage block */
	storagePtr = getBuiltinObjectStorage( OBJECT_TYPE_DEVICE, 
										  SUBTYPE_DEV_SYSTEM, 256 );
	storageSize = getBuiltinObjectStorageSize( OBJECT_TYPE_DEVICE, 
											   SUBTYPE_DEV_SYSTEM, 256 );
	DEBUG_PRINT(( "Object storage: System device = 0x%lX, %d bytes.\n", 
				  storagePtr, storageSize ));
	( void ) releaseBuiltinObjectStorage( OBJECT_TYPE_DEVICE, 
										  SUBTYPE_DEV_SYSTEM, storagePtr );
	storagePtr = getBuiltinObjectStorage( OBJECT_TYPE_USER, 
										  SUBTYPE_USER_SO, 256 );
	storageSize = getBuiltinObjectStorageSize( OBJECT_TYPE_USER, 
											   SUBTYPE_USER_SO, 256 );
	DEBUG_PRINT(( "Object storage: User object = 0x%lX, %d bytes.\n", 
				  storagePtr, storageSize ));
	( void ) releaseBuiltinObjectStorage( OBJECT_TYPE_USER, SUBTYPE_USER_SO, 
										  storagePtr );
#ifdef USE_KEYSETS
	storagePtr = getBuiltinObjectStorage( OBJECT_TYPE_KEYSET, 
										  SUBTYPE_KEYSET_FILE, 256 );
	storageSize = getBuiltinObjectStorageSize( OBJECT_TYPE_KEYSET, 
											   SUBTYPE_KEYSET_FILE, 256 );
	DEBUG_PRINT(( "Object storage: Keyset object = 0x%lX, %d bytes.\n", 
				  storagePtr, storageSize ));
	( void ) releaseBuiltinObjectStorage( OBJECT_TYPE_KEYSET, 
										  SUBTYPE_KEYSET_FILE, storagePtr );
#endif /* USE_KEYSETS */

	/* Dump custom configuration options */
#ifdef CONFIG_FUZZ
	DEBUG_PUTS(( "Warning: Using custom fuzzing build profile, not for "
				 "production use." ));
#endif /* CONFIG_FUZZ */
#ifdef CONFIG_ALL_OPTIONS
	DEBUG_PUTS(( "Warning: All possible build options are enabled, "
				 "including unsafe ones." ));
#endif /* CONFIG_ALL_OPTIONS */
#if defined( CONFIG_CUSTOM_1 )
	DEBUG_PUTS(( "Warning: Using custom build profile, cryptographic "
				 "operations may not work as expected." ));
#elif defined( CONFIG_CRYPTO_HW1 )
	DEBUG_PUTS(( "Warning: Cryptography is being performed through an "
				 "external crypto implementation." ));
#elif defined( CONFIG_CRYPTO_HW2 )
	DEBUG_PUTS(( "Warning: Cryptography and cryptographic mechanism "
				 "operations are being performed through an external "
				 "crypto implementation." ));
#endif /* Custom crypto configurations */
#if defined( CONFIG_PROFILE_SMIME )
	DEBUG_PUTS(( "Using custom build profile for S/MIME." ));
#elif defined( CONFIG_PROFILE_PGP )
	DEBUG_PUTS(( "Using custom build profile for PGP." ));
#elif defined( CONFIG_PROFILE_TLS )
	DEBUG_PUTS(( "Using custom build profile for TLS." ));
#elif defined( CONFIG_PROFILE_SSH )
	DEBUG_PUTS(( "Using custom build profile for SSH." ));
#endif /* Custom build profiles */
#ifdef CONFIG_CONSERVE_MEMORY
	DEBUG_PUTS(( "Using custom build profile for limited-memory "
				 "environments." ));
#endif /* CONFIG_CONSERVE_MEMORY */
#ifdef CONFIG_PKC_ALLOCSIZE
	DEBUG_PRINT(( "Using custom PKC allocation size %d.\n", 
				  CONFIG_PKC_ALLOCSIZE ));
#endif /* CONFIG_PKC_ALLOCSIZE */
#ifdef CONFIG_USE_PSEUDOCERTIFICATES
	DEBUG_PUTS(( "Using pseudocertificates for limited-memory "
				 "environments." ));
#endif /* CONFIG_USE_PSEUDOCERTIFICATES */
#ifdef CONFIG_RANDSEED
	DEBUG_PUTS(( "Using random number seed file for limited-entropy "
				 "environments." ));
#endif /* CONFIG_RANDSEED */

	/* Dump extended config/build options */
	DEBUG_PRINT(( "Extended build options:" ));
#ifdef USE_CAST
	DEBUG_PRINT(( " USE_CAST" ));
#endif /* USE_CAST */
#ifdef USE_CERT_DNSTRING
	DEBUG_PRINT(( " USE_CERT_DNSTRING" ));
#endif /* USE_CERT_DNSTRING */
#ifdef USE_CERT_OBSOLETE
	DEBUG_PRINT(( " USE_CERT_OBSOLETE" ));
#endif /* USE_CERT_OBSOLETE */
#if defined( USE_CERTLEVEL_PKIX_FULL )
	DEBUG_PRINT(( " USE_CERTLEVEL_PKIX_FULL" ));
#elif defined( USE_CERTLEVEL_PKIX_PARTIAL )
	DEBUG_PRINT(( " USE_CERTLEVEL_PKIX_PARTIAL" ));
#elif defined( USE_CERTLEVEL_STANDARD )
	DEBUG_PRINT(( " USE_CERTLEVEL_STANDARD" ));
#elif defined( USE_CERTLEVEL_REDUCED )
	DEBUG_PRINT(( " USE_CERTLEVEL_REDUCED" ));
#elif defined( USE_CERT_OBSCURE )
	DEBUG_PRINT(( " USE_CERT_OBSCURE" ));
#else
	DEBUG_PRINT(( " (Unknown cert level)" ));
#endif /* Certificate level */
#ifdef USE_CFB
	DEBUG_PRINT(( " USE_CFB" ));
#endif /* USE_CFB */
#ifdef USE_CHACHA20
	DEBUG_PRINT(( " USE_CHACHA20" ));
#endif /* USE_CHACHA20 */
#ifdef USE_CMSATTR_OBSCURE
	DEBUG_PRINT(( " USE_CMSATTR_OBSCURE" ));
#endif /* USE_CMSATTR_OBSCURE */
#ifdef USE_25519
	DEBUG_PRINT(( " USE_25519" ));
#endif /* USE_25519 */
#ifdef USE_DEPRECATED_ALGORITHMS
	DEBUG_PRINT(( " USE_DEPRECATED_ALGORITHMS" ));
#endif /* USE_DEPRECATED_ALGORITHMS */
#ifdef USE_DES
	DEBUG_PRINT(( " USE_DES" ));
#endif /* USE_DES */
#ifdef USE_DNSSRV
	DEBUG_PRINT(( " USE_DNSSRV" ));
#endif /* USE_DNSSRV */
#ifdef USE_EAP
	DEBUG_PRINT(( " USE_EAP" ));
#endif /* USE_EAP */
#ifdef USE_ECDH
	DEBUG_PRINT(( " USE_ECDH" ));
#endif /* USE_ECDH */
#ifdef USE_ECDSA
	DEBUG_PRINT(( " USE_ECDSA" ));
#endif /* USE_ECDSA */
#ifdef USE_EDDSA
	DEBUG_PRINT(( " USE_EDDSA" ));
#endif /* USE_EDDSA */
#ifdef USE_ELGAMAL
	DEBUG_PRINT(( " USE_ELGAMAL" ));
#endif /* USE_ELGAMAL */
#ifdef USE_EMBEDDED_OS
	DEBUG_PRINT(( " USE_EMBEDDED_OS" ));
#endif /* USE_EMBEDDED_OS */
#ifdef USE_ERRMSGS
	DEBUG_PRINT(( " USE_ERRMSGS" ));
#endif /* USE_ERRMSGS */
#ifdef USE_GCM
	DEBUG_PRINT(( " USE_GCM" ));
#endif /* USE_GCM */
#ifdef USE_HARDWARE
	DEBUG_PRINT(( " USE_HARDWARE" ));
#endif /* USE_HARDWARE */
#ifdef USE_IDEA
	DEBUG_PRINT(( " USE_IDEA" ));
#endif /* USE_IDEA */
#ifdef USE_INT_ASN1
	DEBUG_PRINT(( " USE_INT_ASN1" ));
#endif /* USE_INT_ASN1 */
#ifdef USE_JAVA
	DEBUG_PRINT(( " USE_JAVA" ));
#endif /* USE_JAVA */
#ifdef USE_LDAP
	DEBUG_PRINT(( " USE_LDAP" ));
#endif /* USE_LDAP */
#ifdef USE_OAEP
	DEBUG_PRINT(( " USE_OAEP" ));
#endif /* USE_OAEP */
#ifdef USE_OBSCURE_ALGORITHMS
	DEBUG_PRINT(( " USE_OBSCURE_ALGORITHMS" ));
#endif /* USE_OBSCURE_ALGORITHMS */
#ifdef USE_ODBC
	DEBUG_PRINT(( " USE_ODBC" ));
#endif /* USE_ODBC */
#ifdef USE_PATENTED_ALGORITHMS
	DEBUG_PRINT(( " USE_PATENTED_ALGORITHMS" ));
#endif /* USE_PATENTED_ALGORITHMS */
#ifdef USE_PGP2
	DEBUG_PRINT(( " USE_PGP2" ));
#endif /* USE_PGP2 */
#ifdef USE_PKCS11
	DEBUG_PRINT(( " USE_PKCS11" ));
#endif /* USE_PKCS11 */
#ifdef USE_PKCS12
	DEBUG_PRINT(( " USE_PKCS12" ));
#endif /* USE_PKCS12 */
#ifdef USE_PKCS12_WRITE
	DEBUG_PRINT(( " USE_PKCS12_WRITE" ));
#endif /* USE_PKCS12_WRITE */
#ifdef USE_POLY1305
	DEBUG_PRINT(( " USE_POLY1305" ));
#endif /* USE_POLY1305 */
#ifdef USE_PSEUDOCERTIFICATES
	DEBUG_PRINT(( " USE_PSEUDOCERTIFICATES" ));
#endif /* USE_PSEUDOCERTIFICATES */
#ifdef USE_PSS
	DEBUG_PRINT(( " USE_PSS" ));
#endif /* USE_PSS */
#ifdef USE_RC2
	DEBUG_PRINT(( " USE_RC2" ));
#endif /* USE_RC2 */
#ifdef USE_RC4
	DEBUG_PRINT(( " USE_RC4" ));
#endif /* USE_RC4 */
#ifdef USE_RSA_SUITES
	DEBUG_PRINT(( " USE_RSA_SUITES" ));
#endif /* USE_RSA_SUITES */
#ifdef USE_SHA2_EXT
	DEBUG_PRINT(( " USE_SHA2_EXT" ));
#endif /* USE_SHA2_EXT */
#ifdef USE_SSH_EXTENDED
	DEBUG_PRINT(( " USE_SSH_EXTENDED" ));
#endif /* USE_SSH_EXTENDED */
#ifdef USE_SSH_CTR
	DEBUG_PRINT(( " USE_SSH_CTR" ));
#endif /* USE_SSH_CTR */
#ifdef USE_THREADS
	DEBUG_PRINT(( " USE_THREADS" ));
#endif /* USE_THREADS */
#ifdef USE_TLS13
	DEBUG_PRINT(( " USE_TLS13" ));
#endif /* USE_TLS13 */
#ifdef USE_TPM
	DEBUG_PRINT(( " USE_TPM" ));
#endif /* USE_TPM */
#ifdef USE_WEBSOCKETS
	DEBUG_PRINT(( " USE_WEBSOCKETS" ));
#endif /* USE_WEBSOCKETS */
#ifdef USE_WIDECHARS
	DEBUG_PRINT(( " USE_WIDECHARS" ));
#endif /* USE_WIDECHARS */
	DEBUG_PRINT(( ".\n" ));

	/* Dump compiler-specific options */
	DEBUG_PUTS(( "Build date/time for file " __FILE__ " is " __DATE__ ", " 
				 __TIME__ "." ));
#ifdef __STDC_VERSION__
	DEBUG_PRINT(( "STDC_VERSION = %ld.\n", __STDC_VERSION__ ));
#endif /* __STDC_VERSION__ */
#ifdef _POSIX_VERSION
	DEBUG_PRINT(( "POSIX_VERSION = %ld.\n", _POSIX_VERSION ));
#endif /* _POSIX_VERSION */
#ifdef __clang__
  #ifdef __apple_build_version__
	/* Apple completely breaks clang versioning, reporting the Xcode version 
	   as the clang version, see https://gist.github.com/yamaya/2924292 */
	DEBUG_PRINT(( "Apple clang (falsely) claims version = " __clang_version__ 
				  ", from Xcode version = %06d.\n", __apple_build_version__ ));
  #else
	DEBUG_PUTS(( "clang version = " __clang_version__ "." ));
	#ifdef __EMSCRIPTEN__ 
	  DEBUG_PUTS(( "  (Running as emscripten)." ));
	#endif /* __EMSCRIPTEN__ */
  #endif /* Apple's broken clang versioning */
#endif /* __clang__ */
#ifdef __GNUC__
	DEBUG_PUTS(( "gcc version = " __VERSION__ "." ));
#endif /* __GNUC__ */
#ifdef __HP_cc
	DEBUG_PRINTF(( "HP cc version = %06d.\n", __HP_cc ));
#endif /* __HP_cc */
#ifdef __IAR_SYSTEMS_ICC__
	DEBUG_PRINTF(( "IAR cc version = %d (%d.%d.%d)\n", __IAR_SYSTEMS_ICC__, 
				   __VER__ / 1000000L, ( __VER__ / 1000L ) % 1000L,
				   __VER__ % 1000L ));
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef _MSC_VER
	DEBUG_PRINT(( "Visual C version = %ld (%ld).\n", _MSC_VER, 
				  _MSC_FULL_VER ));
#endif /* _MSC_VER */
#ifdef __RENESAS__
	DEBUG_PRINT(( "Renesas CC-RX version = %lX.\n", __RENESAS_VERSION__ ));
#endif /* __RENESAS__ */
#ifdef __SUNPRO_C
	DEBUG_PRINT(( "SunPro cc version = %X.\n", __SUNPRO_C ));
#endif /* __SUNPRO_C */
#if defined( __xlc__ )
	DEBUG_PRINT(( "IBM xlc version = %X.\n", __xlC__ ));
#elif defined( __IBMC__ )
	DEBUG_PRINT(( "IBM c89 version = %X.\n", __IBMC__ ));
#endif /* Different, semi-overlapping IBM compilers */
#if defined( __GNUC__ ) || defined( __clang__ )
	if( !__builtin_constant_p( MK_TOKEN( "1234" ) ) )
		{
		DEBUG_PUTS(( "Warning: Call stack tokens aren't being computed by "
					 "the preprocessor,\n         this will lead to code "
					 "bloat in control-flow integrity checks." ));
		}
#endif /* Warn on non-preprocessor evaluation of MK_TOKEN() */
	}

static void displayConfigParams( void )
	{
	const int hwIntrins = getSysVar( SYSVAR_HWINTRINS );
#ifdef __UNIX__ 
	const int hwCrypt = getSysVar( SYSVAR_HWCRYPT );
#endif /* __UNIX__  */

	/* Dump configuration parameters */
	DEBUG_PUTS(( "** Configuration parameters **" ));
	if( hwIntrins != 0 )
		{
		DEBUG_PRINT(( "Hardware intrinsics:" ));
		if( hwIntrins & HWINTRINS_FLAG_RDTSC )
			DEBUG_PRINT(( " RDTSC" ));
		if( hwIntrins & HWINTRINS_FLAG_XSTORE )
			DEBUG_PRINT(( " XSTORE" ));
		if( hwIntrins & HWINTRINS_FLAG_XCRYPT )
			DEBUG_PRINT(( " XCRYPT" ));
		if( hwIntrins & HWINTRINS_FLAG_XSHA )
			DEBUG_PRINT(( " XSHA" ));
		if( hwIntrins & HWINTRINS_FLAG_MONTMUL )
			DEBUG_PRINT(( " MONTMUL" ));
		if( hwIntrins & HWINTRINS_FLAG_TRNG )
			DEBUG_PRINT(( " TRNG" ));
		if( hwIntrins & HWINTRINS_FLAG_AES )
			DEBUG_PRINT(( " AES" ));
		if( hwIntrins & HWINTRINS_FLAG_RDRAND )
			DEBUG_PRINT(( " RDRAND" ));
		if( hwIntrins & HWINTRINS_FLAG_RDSEED )
			DEBUG_PRINT(( " RDSEED" ));
		DEBUG_PRINT(( ".\n" ));
		}
#ifdef __UNIX__ 
	if( hwCrypt != 0 )
		{
		DEBUG_PRINT(( "Hardware crypto:" ));

		if( hwCrypt & HWCRYPT_FLAG_CRYPTDEV_3DES )
			DEBUG_PRINT(( " 3DES" ));
		if( hwCrypt & HWCRYPT_FLAG_CRYPTDEV_AES )
			DEBUG_PRINT(( " AES" ));
		if( hwCrypt & HWCRYPT_FLAG_CRYPTDEV_SHA1 )
			DEBUG_PRINT(( " SHA1" ));
		if( hwCrypt & HWCRYPT_FLAG_CRYPTDEV_SHA2 )
			DEBUG_PRINT(( " SHA2" ));
		DEBUG_PRINT(( ".\n" ));
		}
#endif /* __UNIX__ */

	/* Check for, and warn about, missing system capabilities */
	if( getTime( GETTIME_NONE ) <= MIN_TIME_VALUE )
		{
		DEBUG_DIAG(( "Warning: No time source available, certificate, "
					 "message signing, PKI, and TLS operations will fail "
					 "if used." ));
  #ifdef USE_TLS
		DEBUG_DIAG(( "Warning: The TLS session cache requires a time "
					 "source, since USE_TLS is enabled this will result in "
					 "a self-test failure on startup." ));
  #endif /* USE_TLS */
		}
	}
#else
  #define displayBuildParams()
  #define displayConfigParams()
#endif /* !NDEBUG */

/* Perform various sanity checks on the build process.  Since this will 
   typically be running on an embedded system there's not much that we can 
   (safely) do in terms of user I/O except to return a special-case return 
   code and hope that the user checks the embedded systems section of the 
   manual for more details, although we do try and produce diagnostic output 
   if this is enabled */

static BOOLEAN sanityCheckBuild( void )
	{
	static const long intVal = 1;
	BYTE data[ 16 ];

	/* Perform a sanity check to make sure that the endianness was set 
	   right.  The crypto self-test that's performed a bit later on will 
	   catch this problem as well but it's better to do an explicit check 
	   here that catches the endianness problem rather than just returning a 
	   generic self-test fail error */
#ifdef DATA_LITTLEENDIAN
	if( !*( ( char * ) &intVal ) )
#else
	if( *( ( char * ) &intVal ) )
#endif /* DATA_LITTLEENDIAN */
			{
			/* We should probably sound klaxons as well at this point */
			DEBUG_PUTS(( "Error in build: CPU endianness is configured "
						 "incorrectly, see the cryptlib manual for "
						 "details." ));
			return( FALSE );
			}

	/* Make sure that isValidPointer() isn't reporting valid pointers as
	   being invalid.  This could in theory happen on some hypothetical OS
	   that does odd things with memory layouts so we check for it here */
	if( !isValidPointer( data ) || !isValidPointer( preInitFunctions ) )
		{
		DEBUG_PUTS(( "Error in build: isValidPointer() macro reports data "
					 "or code pointer is invalid when it's valid, see "
					 "misc/safety.h." ));
		return( FALSE );
		}
#ifndef NDEBUG		/* Only visible in the debug build */
	if( !isValidPointer( getSystemStorage( SYSTEM_STORAGE_KRNLDATA ) ) )
		{
		DEBUG_PRINT(( "Error in build: Static data segment is located at "
					  "%lX which isn't recognised by isValidPointer().\n",
					  getSystemStorage( SYSTEM_STORAGE_KRNLDATA ) ));
		return( FALSE );
		}
#endif /* NDEBUG */

	/* If we're working with a maximum time value beyond Y2038, make sure 
	   that the system time functions can actually handle this.
	   
	   To test this under Visual Studio 32-bit, enable the define at the 
	   start of this module */
#if MAX_TIME_VALUE > MAX_TIME_VALUE_Y2038
	if( sizeof( time_t ) < 8 )
		{
		static const time_t time1 = 0x7FFFFFFFUL, time2 = 0x80000000UL;
		static const time_t time3 = 0xEFFFFFFFUL;
		struct tm tmStruct, *tmStructPtr;
		time_t theTime;

        tmStructPtr = gmtime( &time1 );
		if( tmStructPtr == NULL || \
			tmStructPtr->tm_year != 138 || \
			tmStructPtr->tm_mon != 0 || \
			tmStructPtr->tm_mday != 19 )
			{
			DEBUG_PUTS(( "Time values above Y2038 are enabled but gmtime()/"
						 "localtime() can't handle values in this "
						 "range.\n" ));
			return( FALSE );
			}
        tmStructPtr = gmtime( &time2 );
		if( tmStructPtr == NULL || \
			tmStructPtr->tm_year != 138 || \
			tmStructPtr->tm_mon != 0 || \
			tmStructPtr->tm_mday != 19 )
			{
			DEBUG_PUTS(( "Time values above Y2038 are enabled but gmtime()/"
						 "localtime() can't handle values in this "
						 "range.\n" ));
			return( FALSE );
			}
        tmStructPtr = gmtime( &time3 );
		if( tmStructPtr == NULL || \
			tmStructPtr->tm_year != 197 || \
			tmStructPtr->tm_mon != 7 || \
			tmStructPtr->tm_mday != 5 )
			{
			DEBUG_PUTS(( "Time values above Y2038 are enabled but gmtime()/"
						 "localtime() can't handle values in this "
						 "range.\n" ));
			return( FALSE );
			}
		memset( &tmStruct, 0, sizeof( struct tm ) );
		tmStruct.tm_year = 200;
		tmStruct.tm_mon = 1;
		tmStruct.tm_mday = 2;
		tmStruct.tm_hour = 3;
		tmStruct.tm_min = 4;
		tmStruct.tm_sec = 5;
		theTime = mktime( &tmStruct );
		if( theTime < ( 0xF4B0B225UL - ( 14 * 3600L ) ) || \
			theTime > ( 0xF4B0B225UL + ( 14 * 86400L ) ) )
			{
			/* mktime() is a pain because it converts to the local time so 
			   we check whether the result is within 14 hours of the UTC
			   result (there are time zones that can go to +13 and +14).  
			   This is fine since we're checking for overflow/underflow, not 
			   the exact conversion, and don't want to bail out if things 
			   are off by an hour or two due to DST or similar issues */
			DEBUG_PUTS(( "Time values above Y2038 are enabled but mktime() "
						 "can't handle values in this range.\n" ));
			return( FALSE );
			}
		}
#endif /* Time beyond Y2038 */

	return( TRUE );
	}

/* Initialise and shut down the system */

CHECK_RETVAL \
int initCryptlib( void )
	{
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int initLevel = 0, status;

	/* Let the user know that we're in the cryptlib startup code if they're in
	   debug mode */
	DEBUG_PUTS(( "" ));
	DEBUG_PUTS(( "***************************" ));
	DEBUG_PUTS(( "* Beginning cryptlib init *" ));
	DEBUG_PUTS(( "***************************" ));
	DEBUG_PUTS(( "" ));

	/* Display build parameters in debug mode.  We do this before we do 
	   anything else that may cause a crash or abort.  Note that this calls
	   cryptlib-internal routines before the kernel mutex is initialised and
	   check in krnlBeginInit(), which can lead to unexpected results if 
	   initCryptlib() is called incorrectly */
	displayBuildParams();

	/* Perform any required sanity checks on the build process.  This would
	   be caught by the self-test but sometimes people don't run this so we
	   perform a minimal sanity check here to avoid failing in the startup
	   self-tests that follow */
	if( !sanityCheckBuild() )
		{
		DEBUG_DIAG(( "Build sanity-check failed" ));
		retIntError();
		}
	CFI_CHECK_UPDATE( "sanityCheckBuild" );

	/* Initiate the kernel startup */
	DEBUG_PUTS(( "** Initialising kernel **" ));
	status = krnlBeginInit();
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "Kernel init failed, status = %d", status ));
		return( status );
		}
	CFI_CHECK_UPDATE( "krnlBeginInit" );

	/* Perform OS-specific additional initialisation.  Note that this step 
	   must come before the self-tests since some of them perform operations
	   that depend on SysVar settings */
	DEBUG_PUTS(( "** Initialising system variables **" ));
	status = initSysVars();
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "OS-specific initialisation failed, status = %d", 
					 status ));
		assert( DEBUG_WARN );
		krnlCompleteShutdown();
		return( CRYPT_ERROR_FAILED );
		}
	CFI_CHECK_UPDATE( "initSysVars" );

	/* Display configuration parameters in debug mode */
	displayConfigParams();

	/* Verify that core functionality and universal crypto algorithms are 
	   working as required, unless we're running a fuzzing build for which 
	   we don't want to get held up too long in startup */
#if !defined( CONFIG_FUZZ ) && !defined( CONFIG_CONSERVE_MEMORY_EXTRA )
	DEBUG_PUTS(( "** Running general functionality self-tests **" ));
	status = testFunctionality();
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "General functionality test failed, status = %d", 
					 status ));
		assert( DEBUG_WARN );
		krnlCompleteShutdown();
		return( CRYPT_ERROR_FAILED );
		}
#endif /* !CONFIG_FUZZ && !CONFIG_CONSERVE_MEMORY_EXTRA */
	CFI_CHECK_UPDATE( "testFunctionality" );

	/* Perform the multi-phase bootstrap */
	DEBUG_PUTS(( "** Running pre-init actions **" ));
	status = dispatchManagementAction( preInitFunctions, 
									   FAILSAFE_ARRAYSIZE( preInitFunctions, \
														   MANAGEMENT_FUNCTION ),
									   MANAGEMENT_ACTION_PRE_INIT );
	assertNoFault( cryptStatusOK( status ) );
	if( cryptStatusOK( status ) )
		{
		initLevel = 1;
		CFI_CHECK_UPDATE( "preInitFunctions" );
		DEBUG_PUTS(( "** Running init actions **" ));
		status = dispatchManagementAction( initFunctions, 
										   FAILSAFE_ARRAYSIZE( initFunctions, \
															   MANAGEMENT_FUNCTION ),
										   MANAGEMENT_ACTION_INIT );
		assertNoFault( cryptStatusOK( status ) );
		}
	if( cryptStatusOK( status ) )
		{
		/* Now that all of the init actions have completed, we can also 
		   complete the setup of the system objects created during the init 
		   phase */
		CFI_CHECK_UPDATE( "initFunctions" );
		DEBUG_PUTS(( "** Running init completion actions **" ));
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_OK,
								  CRYPT_IATTRIBUTE_COMPLETEINIT );
		assertNoFault( cryptStatusOK( status ) );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_OK,
								  CRYPT_IATTRIBUTE_COMPLETEINIT );
		assertNoFault( cryptStatusOK( status ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
		}
	if( cryptStatusOK( status ) )
		{
#ifdef USE_THREAD_FUNCTIONS
		BOOLEAN_INT asyncInit = FALSE;
#endif /* USE_THREAD_FUNCTIONS */

		initLevel = 2;
		CFI_CHECK_UPDATE( "initCompletionFunctions" );

		/* Perform the final init phase asynchronously or synchronously 
		   depending on the config option setting.  We always send this 
		   query to the default user object since no other user objects 
		   exist at this time */
		DEBUG_PUTS(( "** Running async init actions **" ));
#ifdef USE_THREAD_FUNCTIONS
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, &asyncInit, 
								  CRYPT_OPTION_MISC_ASYNCINIT );
		if( cryptStatusOK( status ) && asyncInit == TRUE )
			{
			/* We use the kernel's thread storage for this thread, so we 
			   specify the thread data storage as NULL */
			status = krnlDispatchThread( threadedBind, NULL, NULL, 0,
										 SEMAPHORE_DRIVERBIND );
			if( cryptStatusError( status ) )
				{
				/* The thread couldn't be started, try again with a 
				   synchronous init */
				asyncInit = FALSE;
				}
			}
		if( !asyncInit )
#endif /* USE_THREAD_FUNCTIONS */
		status = dispatchManagementAction( asyncInitFunctions, 
										   FAILSAFE_ARRAYSIZE( asyncInitFunctions, \
															   MANAGEMENT_FUNCTION ),
										   MANAGEMENT_ACTION_INIT_DEFERRED );
		assertNoFault( cryptStatusOK( status ) );
		}
#if !defined( CONFIG_FUZZ ) && !defined( CONFIG_CONSERVE_MEMORY_EXTRA )
	if( cryptStatusOK( status ) )
		{
		CFI_CHECK_UPDATE( "asyncInitFunctions" );

		/* Everything's set up, verify that the core crypto algorithms and 
		   kernel security mechanisms are working as required, unless we're
		   running a fuzzing build for which we don't want to get held up
		   too long in startup */
		DEBUG_PUTS(( "** Running kernel self-tests **" ));
		status = testKernel();
		assertNoFault( cryptStatusOK( status ) );
		}
#else
	CFI_CHECK_UPDATE( "asyncInitFunctions" );
#endif /* !CONFIG_FUZZ && !CONFIG_CONSERVE_MEMORY_EXTRA */

	/* If anything failed, shut down the internal functions and services
	   before we exit */
	if( cryptStatusError( status ) )
		{
		if( initLevel >= 1 )
			{
			/* Shut down any external interfaces */
			( void ) dispatchManagementAction( preShutdownFunctions, 
									FAILSAFE_ARRAYSIZE( preShutdownFunctions, \
														MANAGEMENT_FUNCTION ),
									MANAGEMENT_ACTION_PRE_SHUTDOWN );
			( void ) destroyObjects();
			( void ) dispatchManagementAction( shutdownFunctions, 
									FAILSAFE_ARRAYSIZE( shutdownFunctions, \
														MANAGEMENT_FUNCTION ),
									MANAGEMENT_ACTION_SHUTDOWN );
			}
		krnlCompleteShutdown();
		return( status );
		}

	/* Complete the kernel startup */
	DEBUG_PUTS(( "** Completing kernel init **" ));
	krnlCompleteInit();
	CFI_CHECK_UPDATE( "krnlCompleteInit" );

	/* Let the user know that the cryptlib startup has completed 
	   successfully if they're in debug mode */
	DEBUG_PUTS(( "" ));
	DEBUG_PUTS(( "***************************" ));
	DEBUG_PUTS(( "* cryptlib init completed *" ));
	DEBUG_PUTS(( "***************************" ));
	DEBUG_PUTS(( "" ));

	ENSURES( CFI_CHECK_SEQUENCE_9( "sanityCheckBuild", "krnlBeginInit", 
								   "initSysVars", "testFunctionality", 
								   "preInitFunctions", "initFunctions", 
								   "initCompletionFunctions", 
								   "asyncInitFunctions", "krnlCompleteInit" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL \
int endCryptlib( void )
	{
	int status;

	/* Let the user know that we're in the cryptlib shutdown code if they're 
	   in debug mode */
	DEBUG_PUTS(( "" ));
	DEBUG_PUTS(( "*******************************" ));
	DEBUG_PUTS(( "* Beginning cryptlib shutdown *" ));
	DEBUG_PUTS(( "*******************************" ));
	DEBUG_PUTS(( "" ));

	/* Initiate the kernel shutdown */
	status = krnlBeginShutdown();
	if( cryptStatusError( status ) )
		return( status );

	/* Reverse the process carried out in the multi-phase bootstrap */
	( void ) dispatchManagementAction( preShutdownFunctions, 
							FAILSAFE_ARRAYSIZE( preShutdownFunctions, \
												MANAGEMENT_FUNCTION ),
							MANAGEMENT_ACTION_PRE_SHUTDOWN );
	status = destroyObjects();
	( void ) dispatchManagementAction( shutdownFunctions, 
							FAILSAFE_ARRAYSIZE( shutdownFunctions, \
												MANAGEMENT_FUNCTION ),
							MANAGEMENT_ACTION_SHUTDOWN );

	/* Complete the kernel shutdown */
	krnlCompleteShutdown();

	/* Let the user know that the cryptlib shutdown has completed 
	   successfully if they're in debug mode */
	DEBUG_PUTS(( "" ));
	DEBUG_PUTS(( "*******************************" ));
	DEBUG_PUTS(( "* cryptlib shutdown completed *" ));
	DEBUG_PUTS(( "*******************************" ));
	DEBUG_PUTS(( "" ));


	return( status );
	}
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
