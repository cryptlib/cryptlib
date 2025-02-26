/****************************************************************************
*																			*
*							cryptlib TPM Routines							*
*						Copyright Peter Gutmann 2020-2022					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "tpm.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "device/tpm.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_TPM

#if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
  #pragma message( "  Building with TPM device interface enabled." )
  #if defined( USE_TPM_EMULATION )
	#pragma message( "  TPM functionality is emulated rather than actual hardware." )
  #endif /* USE_TPM_EMULATION  */
#endif /* Notify TPM use */

/* The path on which Fapi_Get/SetAppData() stores data. The FAPI spec
   defines paths for keys, NV data, and policies, we're apparently storing
   NV data */

#define FAPI_APPDATA_PATH	"/NV/Owner/cryptlib"

/* The path at which keys are stored, see the long comment in 
   tpmGetObjectPath() for the crazy way in which FAPI handles this */

#if 0
  #define FAPI_RSAKEY_PATH	"/P_RSA256/HN/SRK/"
  #define FAPI_ECCKEY_PATH	"/P_ECCP256/HN/SRK/"
#else
  #define FAPI_RSAKEY_PATH	"/P_RSA256/HS/SRK/"
  #define FAPI_ECCKEY_PATH	"/P_ECCP256/HS/SRK/"
#endif /* 0 */

/* The application-specific string that we append to the key path before
   adding the FAPI ID string */

#define CRYPTLIB_APP_STRING	"cryptlib-"

/* The size of the local buffer used to store TPM-related data.  This is a
   memory-mapped PKCS #15 keyset that's used to store certificates and
   indexing information required to work with private keys in the TPM */

#define TPM_BUFFER_SIZE		8192

/****************************************************************************
*																			*
*						 	Driver Load/Unload Routines						*
*																			*
****************************************************************************/

/* Whether the TPM FAPI library has been initialised or not, this is
   initialised on demand the first time that it's accessed */

static BOOLEAN tpmInitialised = FALSE;

/* Depending on whether we're running under Windows or Unix we load the 
   device driver under a different name */

#ifdef __WINDOWS__
  #define TPM_LIBNAME		"libtss2-fapi.dll"
#else
  #define TPM_LIBNAME		"libtss2-fapi.so"
#endif /* __WINDOWS__ */

#ifndef USE_TPM_EMULATION

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   driver libraries.  Explicitly linking to them will make cryptlib 
   unloadable on most systems.
   
   Some of these are declared static since they're only used within this
   module, a few are non-static to make them visible from other modules */

static INSTANCE_HANDLE hTPM = NULL_INSTANCE;

FAPI_CREATEKEY pFapi_CreateKey = NULL;
static FAPI_CREATENV pFapi_CreateNv = NULL;
FAPI_DECRYPT pFapi_Decrypt = NULL;
FAPI_DELETE pFapi_Delete = NULL;
static FAPI_FINALIZE pFapi_Finalize = NULL;
FAPI_FREE pFapi_Free = NULL;
static FAPI_GETAPPDATA pFapi_GetAppData = NULL;
static FAPI_GETINFO pFapi_GetInfo = NULL;
static FAPI_GETRANDOM pFapi_GetRandom = NULL;
FAPI_GETTPMBLOBS pFapi_GetTpmBlobs = NULL;
static FAPI_INITIALIZE pFapi_Initialize = NULL;
static FAPI_PROVISION pFapi_Provision = NULL;
static FAPI_SETAPPDATA pFapi_SetAppData = NULL;
FAPI_SIGN pFapi_Sign = NULL;
TSS2_MU_TPM2B_PUBLIC_UNMARSHAL pTss2_MU_TPM2B_PUBLIC_Unmarshal = NULL;

/* Dynamically load the TPM drivers.  These are somewhat buggy and may
   segfault on load, which is a problem because it appears that it's cryptlib 
   that's segfaulting rather than the buggy driver.  At least one reason for
   a segfault appears to be that, since the driver fakes a lot of its crypto
   in software rather than doing it on the TPM and the software it uses is
   OpenSSL, there are conflicting symbols between cryptlib and the driver so
   that it may call equivalently-named cryptlib functions instead of OpenSSL
   ones.

   To deal with this we install a signal handler to catch segfaults and report 
   possible solutions */

#if defined( __UNIX__ ) && defined( __linux__ )

#include <signal.h>

struct sigaction oldAction;

void segfaultHandler( int signal )
	{
	static const char *message = \
		"\nError: TPM driver '" TPM_LIBNAME "' segfaulted on load.  To "
		"allow\ncryptlib to run, either build cryptlib without USE_TPM "
		"defined or run\n./tools/rename.sh and rebuild cryptlib to avoid "
		"the driver trying to\noverride cryptlib functions.\n\n";

	/* Tell the user what went wrong.  We use purely POSIX.1 async-signal-
	   safe functions to make sure that we don't run into any complications, 
	   although since we're in the process of fatally crashing anyway it's 
	   not clear how much more trouble we can actually get into */
	( void ) write( 2, message, strlen( message ) );
	exit( EXIT_FAILURE );
	}
static void setSegfaultHandler( void )
	{
	struct sigaction sigAction;

	memset( &sigAction, 0, sizeof( struct sigaction ) );
	sigAction.sa_handler = segfaultHandler;
	sigemptyset( &sigAction.sa_mask );
	sigaction( SIGSEGV, &sigAction, &oldAction );
	}
static void resetSegfaultHandler( void )
	{
	sigaction( SIGSEGV, &oldAction, NULL );
	}
#else
  #define setSegfaultHandler()
  #define resetSegfaultHandler()
#endif /* Linux */

static int initCapabilities( void );

CHECK_RETVAL \
int deviceInitTPM( void )
	{
	/* Obtain a handle to the device driver module.  Since the buggy TPM 
	   drivers can segfault on load we add extra handling around this if
	   possible */
	DEBUG_DIAG(( "Attempting to load TPM driver '" TPM_LIBNAME "'.  If this "
				 "segfaults then there's a problem with the driver." ));
	setSegfaultHandler();
	hTPM = DynamicLoad( TPM_LIBNAME );
	resetSegfaultHandler();
	if( hTPM == NULL_INSTANCE )
		{
		DEBUG_DIAG(( "Couldn't load TPM driver '" TPM_LIBNAME "'" ));
		return( CRYPT_ERROR );
		}
	DEBUG_DIAG(( "Loaded TPM driver '" TPM_LIBNAME "'" ));

	/* Now get pointers to the functions */
	pFapi_CreateKey = ( FAPI_CREATEKEY ) DynamicBind( hTPM, "Fapi_CreateKey" );
	pFapi_CreateNv = ( FAPI_CREATENV ) DynamicBind( hTPM, "Fapi_CreateNv" );
	pFapi_Decrypt = ( FAPI_DECRYPT ) DynamicBind( hTPM, "Fapi_Decrypt" );
	pFapi_Delete = ( FAPI_DELETE ) DynamicBind( hTPM, "Fapi_Delete" );
	pFapi_Finalize = ( FAPI_FINALIZE ) DynamicBind( hTPM, "Fapi_Finalize" );
	pFapi_Free = ( FAPI_FREE ) DynamicBind( hTPM, "Fapi_Free" );
	pFapi_GetAppData = ( FAPI_GETAPPDATA ) DynamicBind( hTPM, "Fapi_GetAppData" );
	pFapi_GetInfo = ( FAPI_GETINFO ) DynamicBind( hTPM, "Fapi_GetInfo" );
	pFapi_GetRandom = ( FAPI_GETRANDOM ) DynamicBind( hTPM, "Fapi_GetRandom" );
	pFapi_GetTpmBlobs = ( FAPI_GETTPMBLOBS ) DynamicBind( hTPM, "Fapi_GetTpmBlobs" );
	pFapi_Initialize = ( FAPI_INITIALIZE ) DynamicBind( hTPM, "Fapi_Initialize" );
	pFapi_Provision = ( FAPI_PROVISION ) DynamicBind( hTPM, "Fapi_Provision" );
	pFapi_SetAppData = ( FAPI_SETAPPDATA ) DynamicBind( hTPM, "Fapi_SetAppData" );
	pFapi_Sign = ( FAPI_SIGN ) DynamicBind( hTPM, "Fapi_Sign" );
	pTss2_MU_TPM2B_PUBLIC_Unmarshal = ( TSS2_MU_TPM2B_PUBLIC_UNMARSHAL ) \
							DynamicBind( hTPM, "Tss2_MU_TPM2B_PUBLIC_Unmarshal" );

	/* Make sure that we got valid pointers for every device function */
	if( pFapi_CreateKey == NULL || pFapi_CreateNv == NULL || \
		pFapi_Decrypt == NULL || pFapi_Delete == NULL || \
		pFapi_Finalize == NULL || pFapi_Free == NULL || \
		pFapi_GetAppData == NULL || pFapi_GetInfo == NULL || \
		pFapi_GetRandom == NULL || pFapi_GetTpmBlobs == NULL || \
		pFapi_Initialize == NULL || pFapi_Provision == NULL || \
		pFapi_SetAppData == NULL || pFapi_Sign == NULL || \
		pTss2_MU_TPM2B_PUBLIC_Unmarshal == NULL )
		{
		/* Free the library reference and reset the handle */
		DynamicUnload( hTPM );
		hTPM = NULL_INSTANCE;
		return( CRYPT_ERROR_OPEN );
		}

	return( CRYPT_OK );
	}

void deviceEndTPM( void )
	{
	if( hTPM != NULL_INSTANCE )
		DynamicUnload( hTPM );
	hTPM = NULL_INSTANCE;
	}

#else

static INSTANCE_HANDLE hTPM = ( INSTANCE_HANDLE  ) "";

CHECK_RETVAL \
int deviceInitTPM( void )
	{
	DEBUG_DIAG(( "Faking load of TPM driver '" TPM_LIBNAME "'" ));
	return( CRYPT_OK );
	}
void deviceEndTPM( void )
	{
	/* Dummy function not needed in emulation */
	}
#endif /* USE_TPM_EMULATION */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a TPM-specific error to a cryptlib error */

CHECK_RETVAL \
int tpmMapError( const TSS2_RC tssResult, 
				 IN_ERROR const int defaultError )
	{
	REQUIRES( cryptStatusError( defaultError ) );

	switch( tssResult )
		{
		case TSS2_RC_SUCCESS:
			return( CRYPT_OK );
		case TSS2_FAPI_RC_NO_DECRYPT_PARAM:
		case TSS2_FAPI_RC_NO_ENCRYPT_PARAM:
			return( CRYPT_ERROR_NOTAVAIL );
		case TSS2_FAPI_RC_MEMORY:
			return( CRYPT_ERROR_MEMORY );
		case TSS2_FAPI_RC_NOT_DELETABLE:
		case TSS2_FAPI_RC_AUTHORIZATION_FAILED:
			return( CRYPT_ERROR_PERMISSION );
		case TSS2_FAPI_RC_PATH_ALREADY_EXISTS:
			return( CRYPT_ERROR_DUPLICATE );
		case TSS2_BASE_RC_PATH_NOT_FOUND:
		case TSS2_FAPI_RC_PATH_NOT_FOUND:
			return( CRYPT_ERROR_NOTFOUND );
		case TSS2_FAPI_RC_SIGNATURE_VERIFICATION_FAILED:
			return( CRYPT_ERROR_SIGNATURE );
		case TSS2_FAPI_RC_NOT_PROVISIONED:
			return( CRYPT_ERROR_NOTINITED );
		case TSS2_FAPI_RC_ALREADY_PROVISIONED:
			return( CRYPT_ERROR_INITED );
		}

	return( defaultError );
	}

/* FAPI has no means of specifying things like algorithms, modes, or key
   sizes, there's just a generic mechanism hidden behind the magic catch-all
   "policy", meaning that you specify a magic text string and hope that the 
   TPM's policy will support a profile that can do something with this.  
   
   The first element in the magic text string is the cryptoprofile or 
   algorithm and sometimes key size, we take a guess at the most likely to 
   be recognised one.  
   
   The second element is the hierarchy, sometimes specified as Hx and 
   sometimes as H_x but the Hx form is more common.  We use HN for the 
   null hierarchy since it's neither endorsement, platform, or storage.

   The third element is the object ancestor.  As usual there are multiple
   incompatible definitions for how this is specified, for example the TPM
   docs mention things like snk = system non-duplicatable key, sdk = 
   system duplicatable key, etc, but the FAPI docs say it should be srk =
   system root key.

   Finally we have the only useful part of the whole string, the vendor or
   application ID, specified as <software>-<keyname>.  For the vendor/
   application we use the obvious "cryptlib", for the keyname we use the 
   storage ID that uniquely identifies a device-bound object.  This produces
   magic strings like:

	"/P_RSASHA256/HN/srk/cryptlib-C8B0670CC9AB"
   
   An alternative option, which takes advantage of the weird way that FAPI
   references keys and which would at least allow lookup by label, would be
   to turn the label into a part of the <keyname>

	HASH_FUNCTION_ATOMIC hashFunctionAtomic;

	getHashAtomicParameters( CRYPT_ALGO_SHA1, 0, &hashFunctionAtomic, NULL );
	hashFunctionAtomic( hashBuffer, CRYPT_MAX_HASHSIZE, label, labelLength );
	base64encode( keyID, 16, &keyIDlen, hashBuffer, 12, CRYPT_CERTTYPE_NONE );
	memcpy( string + algoStringLength, keyID, 16 );

   (with filtering of '+' and '/'), however this isn't necessary because 
   we're using the memory-mapped PKCS #15 keyset for indexing and lookup */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int tpmGetObjectPath( OUT_BUFFER( maxStringLength, *stringLength ) \
							char *string,
					  IN_LENGTH_SHORT_MIN( 32 ) \
							const int maxStringLength, 
					  OUT_LENGTH_SHORT_Z int *stringLength,
					  IN_ALGO const CRYPT_ALGO_TYPE algorithm,
					  IN_BUFFER( storageIDlen ) \
							const BYTE *storageID,
					  IN_LENGTH_FIXED( KEYID_SIZE ) \
							const int storageIDlen )
	{
	char storageIDstring[ 16 + 8 ];
	const char *algoString;
	int algoStringLength;

	assert( isWritePtr( string, maxStringLength ) );
	assert( isWritePtr( stringLength, sizeof( int ) ) );
	assert( isReadPtr( storageID, storageIDlen ) );

	REQUIRES( isEnumRange( algorithm, CRYPT_ALGO ) );
	REQUIRES( isShortIntegerRangeMin( maxStringLength, 32 ) );
	REQUIRES( storageIDlen == KEYID_SIZE );

	/* Clear return values */
	memset( string, 0, min( 16, maxStringLength ) );
	*stringLength = 0;

	/* Convert the first 48 bits / 6 bytes of the storageID into a hex 
	   string.  This size is used because it creates a string that isn't too 
	   long (12 bytes) while providing a very low probability of a collision,
	   1 in 1.4e14 */
	sprintf_s( storageIDstring, 16, "%02X%02X%02X%02X%02X%02X",
			   storageID[ 0 ], storageID[ 1 ], storageID[ 2 ], 
			   storageID[ 3 ], storageID[ 4 ], storageID[ 5 ] );

	/* Construct the required algorithm string.  For now we assume a single
	   private key, both because there's no way to tell how many are 
	   supported (see the long comment above) although it's likely to be a
	   very small number, and because there's no easy way to manage them via
	   labels since we need the label to create the key but there's no way
	   to know anything about the key until it's already been created */
	switch( algorithm )
		{
		case CRYPT_ALGO_RSA:
			/* RSA, default P_RSASHA256.  May also be P_RSASHA1, P_RSASHA2, 
			   and more specific stuff like P_RSA2048SHA1 and 
			   P_RSA2048SHA256, but mostly P_RSA seems to imply RSA-2048 */
			algoString = FAPI_RSAKEY_PATH CRYPTLIB_APP_STRING;
			break;

		case CRYPT_ALGO_ECDSA:
			/* ECDSA, default P_ECCP256.  May also be P_ECCP384, P_ECCP521 */
			algoString = FAPI_ECCKEY_PATH CRYPTLIB_APP_STRING;
			break;

		default:
			retIntError();
		}
	algoStringLength = strlen( algoString );
	if( algoStringLength < 1 || \
		algoStringLength + TPM_STORAGEID_STRING_LENGTH + 1 > maxStringLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Copy the string across, including the null terminator */
	ENSURES( rangeCheck( algoStringLength + TPM_STORAGEID_STRING_LENGTH + 1, 
						 1 + TPM_STORAGEID_STRING_LENGTH + 1, 
						 maxStringLength ) );
	memcpy( string, algoString, algoStringLength );
	memcpy( string + algoStringLength, storageIDstring, 
			TPM_STORAGEID_STRING_LENGTH + 1 );
	*stringLength = algoStringLength + TPM_STORAGEID_STRING_LENGTH + 1;

	return( CRYPT_OK );
	}

/* Get random data from the device */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getRandomFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
							  OUT_BUFFER_FIXED( length ) void *data,
							  IN_LENGTH_SHORT const int length,
							  STDC_UNUSED INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	FAPI_CONTEXT *fapiContext = \
			( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;
	TSS2_RC tssResult;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( data, length ) );
	assert( messageExtInfo == NULL );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( fapiContext != NULL );

	tssResult = pFapi_GetRandom( fapiContext, length, data );
	return( tpmMapError( tssResult, CRYPT_ERROR_FAILED ) );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Open and close a session with the TPM */

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	const DEV_STORAGE_FUNCTIONS *storageFunctions = \
					DATAPTR_GET( deviceInfoPtr->storageFunctions );
	FAPI_CONTEXT *fapiContext = \
			( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES_V( storageFunctions != NULL );

	/* If we're being called before the TPM driver initialisation was 
	   completed then there's nothing to do */
	if( !tpmInitialised )
		{
		deviceInfoPtr->contextHandle = NULL;
		CLEAR_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE | \
										  DEVICE_FLAG_LOGGEDIN | \
										  DEVICE_FLAG_NEEDSCLEANUP );
		}

	REQUIRES_V( fapiContext != NULL );

	/* Shut down the storage object if required.  This flushes any data from 
	   the keyset to the memory-mapped backing store.  The details are then 
	   sent back to the device by setting the CRYPT_IATTRIBUTE_COMMITNOTIFY 
	   attribute with the amount of data that was flushed */
	if( deviceInfoPtr->iCryptKeyset != CRYPT_ERROR )
		{
		krnlSendNotifier( deviceInfoPtr->iCryptKeyset, 
						  IMESSAGE_DECREFCOUNT );
		if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_NEEDSCLEANUP ) )
			{
			/* There's cleanup required, delete the storage object.  We don't 
			   force the change through to the backing store because the 
			   cleanup flag indicates that the initialistion process wasn't 
			   completed before it could be written to backing store */
			( void ) deleteDeviceStorageObject( FALSE, TRUE, storageFunctions,
												deviceInfoPtr->contextHandle );
			}
		deviceInfoPtr->iCryptKeyset = CRYPT_ERROR;
		}

	/* Shut down TPM access */
	pFapi_Finalize( &fapiContext );
	tpmInitialised = FALSE;
	deviceInfoPtr->contextHandle = NULL;

	CLEAR_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE | \
									  DEVICE_FLAG_LOGGEDIN | \
									  DEVICE_FLAG_NEEDSCLEANUP );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
						 IN_BUFFER( nameLength ) const char *name,
						 IN_LENGTH_SHORT const int nameLength )
	{
	const DEV_STORAGE_FUNCTIONS *storageFunctions = \
					DATAPTR_GET( deviceInfoPtr->storageFunctions );
	TPM_INFO *tpmInfo = deviceInfoPtr->deviceTPM;
	FAPI_CONTEXT *fapiContext;
	MESSAGE_DATA msgData;
	BYTE buffer[ 32 + 8 ];
	TSS2_RC tssResult;
	const int quality = 95;
	char *fapiInfoString;
	int fapiInfoStringLength, status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( name == NULL && nameLength == 0 );
	REQUIRES( storageFunctions != NULL );

	/* Initialise the TPM FAPI library.  The URI parameter must be NULL 
	   (FAPI version 0.94 Section 4.1) */
	if( pFapi_Initialize( &fapiContext, NULL ) != TSS2_RC_SUCCESS )
		{
		DEBUG_DIAG(( "Couldn't initialise FAPI library '" TPM_LIBNAME "'" ));
		return( CRYPT_ERROR_OPEN );
		}
	deviceInfoPtr->contextHandle = fapiContext;
	tpmInitialised = TRUE;

	/* Copy out the FAPI driver and device information so that the user can 
	   access it by name.  This also serves as a general-purpose 
	   everything-OK check.
	   
	   As with everything else involving FAPI, this doesn't work anything 
	   like you'd expect in the sense that it's vastly more work to get it
	   to do what you want than the API implies.  The documentation says 
	   that it returns a "string that identifies the versions of FAPI, TPM, 
	   configurations and other relevant information", but what it actually 
	   returns is 50-100kB of JSON, not a human-usable ID string like, for 
	   example the PKCS #11 C_GetInfo().  It could also in theory return a
	   base64-encoded JPG showing a picture of the TPM and FAPI stuff which
	   is compliant with the above vague spec.

	   In the huge-blob-of-JSON case the following code will return the 
	   start of the huge blob as the "device label", but there's not much 
	   else that we can report without including a complete JSON parser to 
	   break it all down, and in any case it'll only work for that one
	   implementation which chooses blob-of-JSON as its info string.  
	   However the version info part of the blob seems to be at the start so 
	   at least it'll be included in the CRYPT_MAX_TEXTSIZE characters that 
	   we report */
	tssResult = pFapi_GetInfo( fapiContext, &fapiInfoString );
	if( tssResult != TSS2_RC_SUCCESS )
		{
		DEBUG_DIAG(( "Couldn't get FAPI info for '" TPM_LIBNAME "'" ));
		shutdownFunction( deviceInfoPtr );
		return( CRYPT_ERROR_OPEN );
		}
	DEBUG_DIAG(( "Initialised TPM FAPI driver '%s'", fapiInfoString ));
	fapiInfoStringLength = min( strlen( fapiInfoString ), CRYPT_MAX_TEXTSIZE );
	REQUIRES( rangeCheck( fapiInfoStringLength, 1, CRYPT_MAX_TEXTSIZE ) );
	memcpy( tpmInfo->labelBuffer, fapiInfoString, fapiInfoStringLength );
	sanitiseString( tpmInfo->labelBuffer, CRYPT_MAX_TEXTSIZE, 
					fapiInfoStringLength );
	deviceInfoPtr->label = tpmInfo->labelBuffer;
	deviceInfoPtr->labelLen = strlen( tpmInfo->labelBuffer );

	/* Grab 256 bits of entropy and send it to the system device.  Since 
	   we're using a crypto hardware device we assume that it's good-quality 
	   entropy */
	status = getRandomFunction( deviceInfoPtr, buffer, 32, NULL );
	ENSURES( cryptStatusOK( status ) );
	setMessageData( &msgData, buffer, 32 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_SETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_ENTROPY );
	if( cryptStatusOK( status ) )
		{
		( void ) krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE,
								  ( MESSAGE_CAST ) &quality,
								  CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
		}
	zeroise( buffer, 32 );

	/* Open the PKCS #15 storage object used to store metadata for the keys 
	   in the TPM */
	status = openDeviceStorageObject( &deviceInfoPtr->iCryptKeyset, 
									  CRYPT_KEYOPT_NONE,
									  deviceInfoPtr->objectHandle,
									  storageFunctions, 
									  deviceInfoPtr->contextHandle,
									  FALSE, DEVICE_ERRINFO );
	if( cryptStatusError( status ) )
		{
		shutdownFunction( deviceInfoPtr );
		return( status );
		}

	/* The TPM is hardwired into the system and always present and ready for
	   use.  Technically we may not be logged in but since there's no way to
	   do this via FAPI we assume that the TPM has been activated 
	   externally */
	SET_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE | \
									DEVICE_FLAG_LOGGEDIN );

	return( CRYPT_OK );
	}

/* Handle device control functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int controlFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
							IN_BUFFER_OPT( dataLength ) void *data, 
							IN_LENGTH_SHORT_Z const int dataLength,
							STDC_UNUSED INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	TPM_INFO *tpmInfo = deviceInfoPtr->deviceTPM;
	FAPI_CONTEXT *fapiContext = \
			( FAPI_CONTEXT * ) deviceInfoPtr->contextHandle;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( isAttribute( type ) || isInternalAttribute( type ) );
	REQUIRES( fapiContext != NULL );

	/* Handle authorisation value changes.  These can only be set when the
	   TPM is initialised so all we an do at this point is record them for
	   the initialisation step */
	if( type == CRYPT_DEVINFO_SET_AUTHENT_USER )
		{
		REQUIRES( data != NULL );
		REQUIRES( rangeCheck( dataLength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( tpmInfo->authValueEh, data, dataLength );
		tpmInfo->authValueEhLen = dataLength;

		return( CRYPT_OK );
		}
	if( type == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		{
		REQUIRES( data != NULL );
		REQUIRES( rangeCheck( dataLength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( tpmInfo->authValueLockout, data, dataLength );
		tpmInfo->authValueLockoutLen = dataLength;

		return( CRYPT_OK );
		}

	/* Handle initialisation and zeroisation */
	if( type == CRYPT_DEVINFO_INITIALISE || \
		type == CRYPT_DEVINFO_ZEROISE )
		{
		BYTE authValueEh[ CRYPT_MAX_TEXTSIZE + 1 + 8 ];
		BYTE authValueLockout[ CRYPT_MAX_TEXTSIZE + 1 + 8 ];
		TSS2_RC tssResult;

		/* Make sure that we've got the two authentication values that we 
		   need */
		if( tpmInfo->authValueEhLen <= 0 )
			{
			retExt( CRYPT_ERROR_NOTINITED,
					( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
					  "TPM initialisation needs privacy authentication "
					  "value to be set" ) );
			}
		if( tpmInfo->authValueLockoutLen <= 0 )
			{
			retExt( CRYPT_ERROR_NOTINITED,
					( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
					  "TPM initialisation needs lockout authentication "
					  "value to be set" ) );
			}

		/* Convert the authentication values to null-terminated strings and 
		   provision the TPM */
		REQUIRES( rangeCheck( tpmInfo->authValueEhLen, 
							  1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( authValueEh, tpmInfo->authValueEh, tpmInfo->authValueEhLen );
		authValueEh[ tpmInfo->authValueEhLen ] = '\0';
		REQUIRES( rangeCheck( tpmInfo->authValueLockoutLen, 
							  1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( authValueLockout, tpmInfo->authValueLockout, 
				tpmInfo->authValueLockoutLen );
		authValueLockout[ tpmInfo->authValueLockoutLen ] = '\0';
		tssResult = pFapi_Provision( fapiContext, authValueEh, NULL, 
									 authValueLockout );
		if( tssResult != TSS2_RC_SUCCESS )
			return( tpmMapError( tssResult, CRYPT_ERROR_FAILED ) );

		/* Create an NV index, needed to store data in the TPM */
		tssResult = pFapi_CreateNv( fapiContext, FAPI_APPDATA_PATH, 
									"noda", 0, "", "" );
		if( tssResult != TSS2_RC_SUCCESS )
			return( tpmMapError( tssResult, CRYPT_ERROR_FAILED ) );

		return( CRYPT_OK );
		}

	/* Handle the commit notification for data held in the underlying 
	   storage object, indicating that the data has changed.  This is used 
	   for the system crypto object, which can have in-memory key data 
	   associated with it, to tell the crypto HAL to update its view of the
	   storage object */
	if( type == CRYPT_IATTRIBUTE_COMMITNOTIFY )
		{
		const DEV_STORAGE_FUNCTIONS *storageFunctions = \
						DATAPTR_GET( deviceInfoPtr->storageFunctions );

		REQUIRES( dataLength == CRYPT_UNUSED || dataLength == 0 || \
				  rangeCheck( dataLength, MIN_CRYPT_OBJECTSIZE, \
							  MAX_INTLENGTH ) );

		REQUIRES( storageFunctions != NULL );

		( void ) \
			storageFunctions->storageUpdateNotify( deviceInfoPtr->contextHandle,
												   dataLength );
		return( CRYPT_OK );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*						 	Storage Support Routines						*
*																			*
****************************************************************************/

/* Get a reference to built-in storage for keys and certificates.  This has 
   a PKCS #15 keyset mapped over the top of it.  The storage is an in-memory 
   buffer that can be committed to backing store when the update-notify 
   function is called to indicate that the buffer contents have been 
   updated */

static BYTE storage[ TPM_BUFFER_SIZE + 8 ] = { 0 };
static BOOLEAN storageInitialised = FALSE;

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int loadStorage( INOUT_PTR void *contextHandle )
	{
	FAPI_CONTEXT *fapiContext = ( FAPI_CONTEXT * ) contextHandle;
	TSS2_RC tssResult;
	void *appDataPtr;
	size_t appDataSize;

	REQUIRES( contextHandle != NULL );

	/* Try and read the data from backing store */
	tssResult = pFapi_GetAppData( fapiContext, FAPI_APPDATA_PATH,
								  ( uint8_t ** ) &appDataPtr, &appDataSize );
	if( tssResult == TSS2_RC_SUCCESS && appDataSize == 0 )
		{
		/* Instead of the expected TSS2_FAPI_RC_PATH_NOT_FOUND if there's no 
		   data present Fapi_GetAppData() returns TSS2_RC_SUCCESS with 
		   appDataSize set to zero, so we convert this to the expected 
		   TSS2_FAPI_RC_PATH_NOT_FOUND */
		tssResult = TSS2_FAPI_RC_PATH_NOT_FOUND;
		}
	if( tssResult != TSS2_RC_SUCCESS )
		{
		/* If there's no data present in the backing store, let the caller 
		   know */
		if( tssResult == TSS2_BASE_RC_PATH_NOT_FOUND || 
			tssResult == TSS2_FAPI_RC_PATH_NOT_FOUND )
			{
			memset( storage, 0, TPM_BUFFER_SIZE );
			storageInitialised = TRUE;
			return( OK_SPECIAL );
			}
		
		return( tpmMapError( tssResult, CRYPT_ERROR_OPEN ) );
		}
	if( appDataSize < 1 || appDataSize > TPM_BUFFER_SIZE )
		{
		pFapi_Free( appDataPtr );
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* Copy the data into the local buffer and free the memory that 
	   Fapi_GetAppData() allocated on read */
	memset( storage, 0, TPM_BUFFER_SIZE );
	REQUIRES( rangeCheck( appDataSize, 1, TPM_BUFFER_SIZE ) );
	memcpy( storage, appDataPtr, appDataSize );
	pFapi_Free( appDataPtr );

	return( CRYPT_OK );
	}

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int tpmGetStorage( INOUT_PTR void *contextHandle,
						  OUT_BUFFER_ALLOC_OPT( *storageSize ) \
								void **storageAddr,
						  OUT_LENGTH int *storageSize )
	{
	int status;

	assert( isWritePtr( storageAddr, sizeof( void * ) ) );
	assert( isWritePtr( storageSize, sizeof( int ) ) );

	REQUIRES( contextHandle != NULL );

	/* Clear return values */
	*storageAddr = NULL;
	*storageSize = 0;

	/* If the storage is already initialised, just return a reference to 
	   it */
	if( storageInitialised )
		{
		*storageAddr = storage;
		*storageSize = TPM_BUFFER_SIZE;

		return( CRYPT_OK );
		}

	/* Try and load the storage buffer from backing store */
	status = loadStorage( contextHandle );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );
	*storageAddr = storage;
	*storageSize = TPM_BUFFER_SIZE;

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int tpmStorageUpdateNotify( INOUT_PTR void *contextHandle,
								   IN_LENGTH_Z const int dataLength )
	{
	FAPI_CONTEXT *fapiContext = ( FAPI_CONTEXT * ) contextHandle;
	TSS2_RC tssResult;

	REQUIRES( contextHandle != NULL );
	REQUIRES( ( dataLength == CRYPT_UNUSED ) || \
			  isIntegerRange( dataLength ) );
	
	/* If the data in the in-memory buffer is no longer valid, for example 
	   due to a failed update attempt, re-fill the buffer with the original 
	   data from the backing store */
	if( dataLength == CRYPT_UNUSED )
		return( loadStorage( contextHandle ) );

	/* If the in-memory data is now empty, erase the backing store */
	if( dataLength == 0 )
		{
		tssResult = pFapi_Delete( fapiContext, FAPI_APPDATA_PATH );
		if( tssResult != TSS2_RC_SUCCESS )
			return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );
		memset( storage, 0, TPM_BUFFER_SIZE );
		storageInitialised = FALSE;

		return( CRYPT_OK );
		}

	/* Data from 0...dataLength has been updated, write it to backing store,
	   optionally erasing the remaining area.  cryptlib updates are atomic 
	   so the entire data block will be updated at once, there won't be any
	   random-access changes made to ranges within the data block */
	REQUIRES( rangeCheck( dataLength, 1, TPM_BUFFER_SIZE ) );
	memset( storage + dataLength, 0, TPM_BUFFER_SIZE - dataLength );
	tssResult = pFapi_SetAppData( fapiContext, FAPI_APPDATA_PATH, 
								  storage, dataLength );
	if( tssResult != TSS2_RC_SUCCESS )
		return( tpmMapError( tssResult, CRYPT_ERROR_WRITE ) );

	return( CRYPT_OK );
	}

/* Delete an item.  As with most things related to TPMs this is an extremely
   awkward operation because of the way TPM objects are addressed via 
   absolute paths that encode algorithm details and parameters.  To deal with 
   this we take advantage of the fact that we're working with a 
   (probabilistically) unique storageID and try and delete an object based 
   on that, stepping through the algorithms and parameters until we find 
   something deletable */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int tpmDeleteItem( INOUT_PTR void *contextHandle,
						  IN_BUFFER( storageIDlength ) \
								const void *storageID,
						  IN_LENGTH_FIXED( KEYID_SIZE ) \
								const int storageIDlength,
						  IN_INT_Z const int storageRef )
	{
	BYTE objectPath[ CRYPT_MAX_TEXTSIZE + 8 ];
	FAPI_CONTEXT *fapiContext = ( FAPI_CONTEXT * ) contextHandle;
	TSS2_RC tssResult;
	int objectPathLen, status;

	assert( isReadPtrDynamic( storageID, storageIDlength ) );

	REQUIRES( contextHandle != NULL );
	REQUIRES( storageIDlength == KEYID_SIZE );
	REQUIRES( storageRef >= 0 && storageRef < 16 );

	/* Try for a delete of an RSA object */
	status = tpmGetObjectPath( objectPath, CRYPT_MAX_TEXTSIZE, 
							   &objectPathLen, CRYPT_ALGO_RSA,
							   storageID, KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	tssResult = pFapi_Delete( fapiContext, objectPath );
	if( tssResult == TSS2_RC_SUCCESS )
		return( CRYPT_OK );

	/* No RSA object found, try again for an ECC one */
	status = tpmGetObjectPath( objectPath, CRYPT_MAX_TEXTSIZE, 
							   &objectPathLen, CRYPT_ALGO_ECDSA,
							   storageID, KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	tssResult = pFapi_Delete( fapiContext, objectPath );
	if( tssResult == TSS2_RC_SUCCESS )
		return( CRYPT_OK );

	/* It's either hidden under yet another path or not present */
	return( CRYPT_ERROR_NOTFOUND );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int tpmLookupItem( IN_BUFFER( storageIDlength ) \
								const void *storageID,
						  IN_LENGTH_SHORT const int storageIDlength,
						  OUT_INT_Z int *storageRef )
	{
	assert( isReadPtrDynamic( storageID, storageIDlength ) );
	assert( isWritePtr( storageRef, sizeof( int ) ) );

	REQUIRES( storageIDlength == KEYID_SIZE );

	/* TPMs have no concept of handles to objects, only absolute paths that
	   are applied each time the object is accessed, so we always return a 
	   dummy value as the storage reference */
	*storageRef = 1;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setDeviceTPM( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	static const DEV_STORAGE_FUNCTIONS storageFunctions = {
		tpmGetStorage, tpmStorageUpdateNotify, tpmDeleteItem, tpmLookupItem 
		};
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	/* Make sure that the TPM driver library is loaded */
	if( hTPM == NULL_INSTANCE )
		return( CRYPT_ERROR_OPEN );

	status = tpmInitCapabilities(); 
	REQUIRES( cryptStatusOK( status ) );

	FNPTR_SET( deviceInfoPtr->initFunction, initFunction );
	FNPTR_SET( deviceInfoPtr->shutdownFunction, shutdownFunction );
	FNPTR_SET( deviceInfoPtr->controlFunction, controlFunction );
	status = deviceInitStorage( deviceInfoPtr );
	ENSURES( cryptStatusOK( status ) );
	FNPTR_SET( deviceInfoPtr->getRandomFunction, getRandomFunction );
	status = tpmGetCapabilities( deviceInfoPtr );
	REQUIRES( cryptStatusOK( status ) );
	DATAPTR_SET( deviceInfoPtr->storageFunctions, 
				 ( void * ) &storageFunctions );
	deviceInfoPtr->noPubkeyOps = TRUE;
				/* See dev_storage.c:getItemFunction() */

	return( CRYPT_OK );
	}
#endif /* USE_TPM */
