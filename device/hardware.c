/****************************************************************************
*																			*
*					  cryptlib Generic Crypto HW Routines					*
*						Copyright Peter Gutmann 1998-2019					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "device.h"
  #include "hardware.h"
#else
  #include "context/context.h"
  #include "device/device.h"
  #include "device/hardware.h"
#endif /* Compiler-specific includes */

#ifdef USE_HARDWARE

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Initialise/zeroise the device.  This gets a bit complicated because the 
   device that we're initialising could be the internal crypto hardware 
   device if this is in use, so we have to perform a sleight-of-hand that
   allows it to be reset during use */

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN isCryptoHardwareDevice( const DEVICE_INFO *deviceInfoPtr )
	{					   
	CRYPT_KEYSET iHWKeyset;
	HARDWARE_INFO *hardwareInfo = deviceInfoPtr->deviceHardware;
	int status;

	assert( isReadPtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	/* If this is the crypto hardware device, there's no special handling
	   required */
	if( deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE )
		return( FALSE );

	/* It's not the crypto hardware device, check whether it's an alias for
	   it by comparing the keyset handle, which for an aliased device will
	   be a reference to the one used by the crypto hardware device */
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE, 
							  &iHWKeyset, CRYPT_IATTRIBUTE_HWSTORAGE );
	if( cryptStatusError( status ) )
		return( FALSE );
	
	return( iHWKeyset == hardwareInfo->iCryptKeyset ? TRUE : FALSE );
	}
#else
  #define isCryptoHardwareDevice( deviceInfoPtr )		FALSE
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initDevice( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
					   IN_BOOL const BOOLEAN isCryptoDeviceAlias,	
					   IN_BOOL const BOOLEAN isZeroise )
	{
	CRYPT_KEYSET iHWKeyset;
	HARDWARE_INFO *hardwareInfo = deviceInfoPtr->deviceHardware;
	const DEV_STORAGE_FUNCTIONS *storageFunctions = \
						DATAPTR_GET( deviceInfoPtr->storageFunctions );
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( isBooleanValue( isCryptoDeviceAlias ) );
	REQUIRES( isBooleanValue( isZeroise ) );
	REQUIRES( storageFunctions != NULL );

	/* If this is an alias to the crypto hardware device then we need to 
	   handle it specially since we're about to reinitialise the hardware
	   out from underneath it.  We perform this sleight-of-hand trick by 
	   notifying the crypto hardware device to reset its state, which 
	   reinitialises the storage, and then get a reference to the newly-
	   intialised storage from it */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( isCryptoDeviceAlias )
		{
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE, 
								  CRYPT_IATTRIBUTE_RESETNOTIFY );
		if( cryptStatusOK( status ) )
			status = getCryptoStorageObject( &hardwareInfo->iCryptKeyset );
		if( cryptStatusError( status ) )
			return( status );
		SET_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_LOGGEDIN );

		return( CRYPT_OK );
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	/* The only real difference between a zeroise and an initialise is that 
	   the zeroise only clears existing state and exits while the initialise 
	   resets the state with the device ready to be used again */
	if( isZeroise )
		{
		return( deleteDeviceStorageObject( TRUE, 
										   hardwareInfo->isFileKeyset,
										   storageFunctions,
										   deviceInfoPtr->contextHandle ) );
		}

	/* Initialise the device.  In addition to the logged-in flag we set the 
	   needs-cleanup flag to indicate that if the device is closed before 
	   performing further initialisation then the storage object should be 
	   removed */
	status = openDeviceStorageObject( &iHWKeyset, CRYPT_KEYOPT_CREATE,
									  deviceInfoPtr->objectHandle, 
									  storageFunctions, 
									  deviceInfoPtr->contextHandle,
									  TRUE, DEVICE_ERRINFO );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );
	deviceInfoPtr->iCryptKeyset = iHWKeyset;
	if( status == OK_SPECIAL )
		hardwareInfo->isFileKeyset = TRUE;
	SET_FLAG( deviceInfoPtr->flags, 
			  DEVICE_FLAG_LOGGEDIN | DEVICE_FLAG_NEEDSCLEANUP );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Close a previously-opened session with the device.  We have to have this
   before the initialisation function since it may be called by it if the 
   initialisation process fails */

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	HARDWARE_INFO *hardwareInfo = deviceInfoPtr->deviceHardware;
	const DEV_STORAGE_FUNCTIONS *storageFunctions = \
					DATAPTR_GET( deviceInfoPtr->storageFunctions );

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES_V( storageFunctions != NULL );

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
			( void ) deleteDeviceStorageObject( FALSE, 
												hardwareInfo->isFileKeyset,
												storageFunctions,
												deviceInfoPtr->contextHandle );
			}
		deviceInfoPtr->iCryptKeyset = CRYPT_ERROR;
		}
	CLEAR_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE | \
									  DEVICE_FLAG_LOGGEDIN | \
									  DEVICE_FLAG_NEEDSCLEANUP );
	}

/* Open a session with the device */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completeInit( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	CRYPT_KEYSET iCryptKeyset;
	HARDWARE_INFO *hardwareInfo = deviceInfoPtr->deviceHardware;
	const DEV_STORAGE_FUNCTIONS *storageFunctions = \
					DATAPTR_GET( deviceInfoPtr->storageFunctions );
	const DEV_GETRANDOMFUNCTION getRandomFunction = \
					( DEV_GETRANDOMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->getRandomFunction );
	MESSAGE_DATA msgData;
	BYTE buffer[ 32 + 8 ];
	const int quality = 95;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( storageFunctions != NULL );
	REQUIRES( getRandomFunction != NULL );

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

	/* Try and open the PKCS #15 storage object, either in the hardware if 
	   it provides secure storage or in a disk file if not.  If we can't 
	   open it it means that either it doesn't exist (i.e. persistent key 
	   storage isn't supported) or the device hasn't been initialised yet.  
	   This isn't a fatal error, although it does mean that some public-key 
	   operations will be restricted if they depend on storing key metadata 
	   in the storage object */
	status = openDeviceStorageObject( &iCryptKeyset, CRYPT_KEYOPT_NONE,
									  deviceInfoPtr->objectHandle,
									  storageFunctions, 
									  deviceInfoPtr->contextHandle,
									  TRUE, DEVICE_ERRINFO );
	if( cryptStatusOK( status ) || status == OK_SPECIAL )
		{
		deviceInfoPtr->iCryptKeyset = iCryptKeyset;
		if( status == OK_SPECIAL )
			hardwareInfo->isFileKeyset = TRUE;
		status = CRYPT_OK;
		}

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
						 STDC_UNUSED const char *name,
						 STDC_UNUSED const int nameLength )
	{
	int status;

	UNUSED_ARG( name );

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	/* Set up any internal objects to contain invalid handles */
	deviceInfoPtr->iCryptKeyset = CRYPT_ERROR;

	/* In some configurations the hardware device isn't a standard crypto
	   device but a HAL used to access custom or non-public algorithms and
	   mechanisms.  In this case we're being initialised at boot time and
	   won't be visible externally, so we don't perform any further 
	   initialisation beyond this point.  In particular we don't try and
	   call completeInit() to open the PKCS #15 storage object since keyset 
	   access won't be available yet.  
	   
	   Further down in the cryptlib initialisation process the hardware 
	   device will have its CRYPT_IATTRIBUTE_COMPLETEINIT attribute set, 
	   which signals that it can now call completeInit() since the other 
	   functionality that's required is now available */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE )
		{
		deviceInfoPtr->label = "Crypto HAL";
		deviceInfoPtr->labelLen = 10;
		SET_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE );

		ENSURES( sanityCheckDevice( deviceInfoPtr ) );

		return( CRYPT_OK );
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	/* Set up the device information.  Since this is a built-in hardware 
	   device it's always present and available */
	deviceInfoPtr->label = "Cryptographic hardware device";
	deviceInfoPtr->labelLen = 29;
	SET_FLAG( deviceInfoPtr->flags, 
			  DEVICE_FLAG_ACTIVE | DEVICE_FLAG_LOGGEDIN );

	/* Complete the initialisation process */
	status = completeInit( deviceInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckDevice( deviceInfoPtr ) );

	return( CRYPT_OK );
	}

/* Handle device control functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int controlFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
							IN_BUFFER_OPT( dataLength ) void *data, 
							IN_LENGTH_SHORT_Z const int dataLength,
							INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	HARDWARE_INFO *hardwareInfo = deviceInfoPtr->deviceHardware;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( data == NULL || isReadPtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isAttribute( type ) || isInternalAttribute( type ) );

	UNUSED_ARG( hardwareInfo );
	UNUSED_ARG( messageExtInfo );

	/* Handle user authorisation.  Since this is a built-in hardware device 
	   it's always available for use so these are just dummy routines, 
	   although they can be expanded to call down into the HAL for actual
	   authentication if any hardware with such a facility is ever used */
	if( type == CRYPT_DEVINFO_AUTHENT_USER || \
		type == CRYPT_DEVINFO_AUTHENT_SUPERVISOR )
		{
		/* Authenticate the user */
		/* ... */

		/* The device is now ready for use */
		SET_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_LOGGEDIN );		
		return( CRYPT_OK );
		}

	/* Handle authorisation value changes */
	if( type == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		{
		/* Set SO PIN */
		/* ... */

		return( CRYPT_OK );
		}
	if( type == CRYPT_DEVINFO_SET_AUTHENT_USER )
		{
		/* Set user PIN */
		/* ... */

		return( CRYPT_OK );
		}

	/* Handle initialisation and zeroisation */
	if( type == CRYPT_DEVINFO_INITIALISE || \
		type == CRYPT_DEVINFO_ZEROISE )
		{
		const BOOLEAN isCryptoDeviceAlias = \
							isCryptoHardwareDevice( deviceInfoPtr );
							/* Get device information before we clear it */

		/* Shut down any existing state if necessary in preparation for the 
		   zeroise/initialise.  Since this clears all state we manually 
		   reset the device-active flag since we're still active, just with
		   all information cleared */
		shutdownFunction( deviceInfoPtr );
		hwInitialise();
		SET_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE );

		/* Initialise the device */
		return( initDevice( deviceInfoPtr, isCryptoDeviceAlias,
							( type == CRYPT_DEVINFO_ZEROISE ) ? \
							  TRUE : FALSE ) );
		}

	/* Complete the object initialisation process.  This is handled as a
	   distinct operation for the system crypto object, which can't be
	   completely initialised when it's created because the cryptlib 
	   initialisation process hasn't completed yet */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( type == CRYPT_IATTRIBUTE_COMPLETEINIT )
		{
		int status;

		status = completeInit( deviceInfoPtr );
		if( cryptStatusError( status ) )
			{
			/* Since this function is called on object creation, and in this 
			   case on system init, if it fails there's no object to get 
			   extended error information from so we dump the error 
			   information as a diagnostic for debugging purposes */
			DEBUG_DIAG_ERRMSG(( "Hardware device init completion failed, "
								"status %s, error string:\n  '%s'", 
								getStatusName( status ),
								getErrorInfoString( DEVICE_ERRINFO ) ));
			}
		return( status );
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	/* Handle high-reliability time */
	if( type == CRYPT_IATTRIBUTE_TIME )
		{
		time_t *timePtr = ( time_t * ) data;

		UNUSED_ARG( timePtr );

		return( CRYPT_ERROR_NOTAVAIL );
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

		/* If we're in the middle of a reset/zeroise, we don't commit any 
		   data to storage but instead clear it */
		if( hardwareInfo->discardData )
			{
			return( deleteDeviceStorageObject( TRUE, 
											   hardwareInfo->isFileKeyset,
											   storageFunctions,
											   deviceInfoPtr->contextHandle ) );
			}

		( void ) \
			storageFunctions->storageUpdateNotify( deviceInfoPtr->contextHandle,
												   dataLength );
		return( CRYPT_OK );
		}

	/* Handle the reset notification when the device is initialised.  This
	   just closes the keyset, discarding what's written, and reloads it
	   from the storage object */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( type == CRYPT_IATTRIBUTE_RESETNOTIFY )
		{
		/* Close the keyset, discarding any data from it and clearing the 
		   underlying storage */
		hardwareInfo->discardData = TRUE;
		krnlSendNotifier( hardwareInfo->iCryptKeyset, 
						  IMESSAGE_DECREFCOUNT );
		hardwareInfo->discardData = FALSE;

		/* Redo the initialisation */
		return( completeInit( deviceInfoPtr ) );
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	retIntError();
	}

/* Get random data from the device.  The messageExtInfo parameter is used
   to handle recursive messages sent to the system device during the 
   randomness-polling process and isn't used here */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getRandomFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
							  OUT_BUFFER_FIXED( length ) void *buffer,
							  IN_LENGTH_SHORT const int length, 
							  INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	UNUSED_ARG( messageExtInfo );

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );

	/* Clear the return value and make sure that we fail the FIPS 140 tests
	   on the output if there's a problem */
	REQUIRES( isShortIntegerRangeNZ( length ) ); 
	zeroise( buffer, length );

	/* Fill the buffer with random data */
	return( hwGetRandom( buffer, length ) );
	}

/* Query the custom crypto HAL for encoding information for custom 
   algorithms and mechanisms that may be provided by the HAL.  This is just
   a wrapper that passes the call throug to the HAL */

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int catalogQueryFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
								 INOUT_PTR MESSAGE_CATALOGQUERY_INFO *queryInfo, 
								 IN_ENUM( CATALOGQUERY_ITEM ) \
											const CATALOGQUERY_ITEM_TYPE itemType )
	{
	return( hwCatalogQuery( queryInfo, itemType ) );
	}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Mechanisms for use with the hardware if it doesn't provide its own 
   mechanisms.  These aren't the full set supported by the system device 
   since functions like private key export aren't available.  The list is 
   sorted in order of frequency of use in order to make lookups a bit 
   faster */

static const MECHANISM_FUNCTION_INFO defaultMechanismFunctions[] = {
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
#if defined( USE_TLS ) && defined( USE_RSA_SUITES )
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1_RAW, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1_RAW, ( MECHANISM_FUNCTION ) importPKCS1 },
#endif /* USE_TLS && USE_RSA_SUITES */
#ifdef USE_PGP
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1_PGP, ( MECHANISM_FUNCTION ) exportPKCS1PGP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1_PGP, ( MECHANISM_FUNCTION ) importPKCS1PGP },
#endif /* USE_PGP */
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_CMS, ( MECHANISM_FUNCTION ) exportCMS },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_CMS, ( MECHANISM_FUNCTION ) importCMS },
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_PBKDF2, ( MECHANISM_FUNCTION ) derivePBKDF2 },
#if defined( USE_ENVELOPES ) && defined( USE_CMS )
	{ MESSAGE_DEV_KDF, MECHANISM_DERIVE_PBKDF2, ( MECHANISM_FUNCTION ) kdfPBKDF2 },
#endif /* USE_ENVELOPES && USE_CMS */
	{ MESSAGE_DEV_KDF, MECHANISM_DERIVE_HKDF, ( MECHANISM_FUNCTION ) kdfHKDF },
#if defined( USE_PGP ) || defined( USE_PGPKEYS )
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_PGP, ( MECHANISM_FUNCTION ) derivePGP },
#endif /* USE_PGP || USE_PGPKEYS */
#if defined( USE_TLS ) || defined( USE_SSH )
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_HOTP, ( MECHANISM_FUNCTION ) deriveHOTP },
#endif /* USE_TLS || USE_SSH */
#ifdef USE_TLS
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_TLS, ( MECHANISM_FUNCTION ) deriveTLS },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_TLS, ( MECHANISM_FUNCTION ) signTLS },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_TLS, ( MECHANISM_FUNCTION ) sigcheckTLS },
#endif /* USE_TLS */
#ifdef USE_CMP
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_CMP, ( MECHANISM_FUNCTION ) deriveCMP },
#endif /* USE_CMP */
#ifdef USE_OAEP
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_OAEP, ( MECHANISM_FUNCTION ) exportOAEP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_OAEP, ( MECHANISM_FUNCTION ) importOAEP },
#endif /* USE_OAEP */
#ifdef USE_PSS
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PSS, ( MECHANISM_FUNCTION ) signPSS},
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PSS, ( MECHANISM_FUNCTION ) sigcheckPSS },
#endif /* USE_PSS */
#ifdef USE_PKCS12
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_PKCS12, ( MECHANISM_FUNCTION ) derivePKCS12 },
#endif /* USE_PKCS12 */
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }, { MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Initialise the cryptographic hardware and its crypto capability 
   interface */

#define MAX_DEVICE_CAPABILITIES		32

static CAPABILITY_INFO_LIST capabilityInfoList[ MAX_DEVICE_CAPABILITIES ];

CHECK_RETVAL \
int deviceInitHardware( void )
	{
	const CAPABILITY_INFO *capabilityInfo;
	LOOP_INDEX i;
	int noCapabilities, status;

	/* Get the hardware capability information */
	status = hwGetCapabilities( &capabilityInfo, &noCapabilities );
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG_ERRMSG(( "Couldn't get native hardware capabilities, "
							"status %s", getStatusName( status ) ));
		return( status );
		}
	ENSURES( noCapabilities > 0 && \
			 noCapabilities <= MAX_DEVICE_CAPABILITIES );

	/* Build the list of available capabilities */
	memset( capabilityInfoList, 0, \
			sizeof( CAPABILITY_INFO_LIST ) * MAX_DEVICE_CAPABILITIES );
	LOOP_MED( i = 0, i < noCapabilities && \
					 capabilityInfo[ i ].cryptAlgo != CRYPT_ALGO_NONE, i++ )
		{
		const CAPABILITY_INFO *capabilityInfoPtr;

		ENSURES( LOOP_INVARIANT_MED( i, 0, noCapabilities - 1 ) );

		capabilityInfoPtr = &capabilityInfo[ i ];

		DEBUG_DIAG(( "Hardware driver reports support for %s algorithm, key "
					 "size %d...%d", capabilityInfoPtr->algoName, 
					 capabilityInfoPtr->minKeySize, 
					 capabilityInfoPtr->maxKeySize ));

		REQUIRES( sanityCheckCapability( capabilityInfoPtr ) );
		
		DATAPTR_SET( capabilityInfoList[ i ].info, \
					 ( void * ) capabilityInfoPtr );
		DATAPTR_SET( capabilityInfoList[ i ].next, NULL );
		if( i > 0 )
			{
			DATAPTR_SET( capabilityInfoList[ i - 1 ].next, 
						 &capabilityInfoList[ i ] );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < noCapabilities );

	/* Finally, patch in the generic-secret capability.  This is a bit of an 
	   odd capability that doesn't represent any encryption algorithm but is
	   used for authenticated encryption as an intermediate step when 
	   generating distinct encryption and authentication keys from a single 
	   shared-secret key */
	if( i < MAX_DEVICE_CAPABILITIES )
		{
		const CAPABILITY_INFO *capabilityInfoPtr = \
										getGenericSecretCapability();

		DEBUG_DIAG(( "Adding generic secret capability, key size %d...%d, "
					 "for authenticated encryption support", 
					 capabilityInfoPtr->minKeySize, 
					 capabilityInfoPtr->maxKeySize ));

		REQUIRES( sanityCheckCapability( capabilityInfoPtr ) );

		DATAPTR_SET( capabilityInfoList[ i ].info, \
					 ( void * ) capabilityInfoPtr );
		DATAPTR_SET( capabilityInfoList[ i ].next, NULL );
		if( i > 0 )
			{
			DATAPTR_SET( capabilityInfoList[ i - 1 ].next, 
						 &capabilityInfoList[ i ] );
			}
		}

	return( CRYPT_OK );
	}

void deviceEndHardware( void )
	{
	}

/* Set up the function pointers to the device methods.  This is called when 
   a hardware device object is created */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setDeviceHardware( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	static const DEV_STORAGE_FUNCTIONS storageFunctions = {
		hwGetStorage, hwStorageUpdateNotify, hwDeleteItem, hwLookupItem 
		};
	const MECHANISM_FUNCTION_INFO *mechanismFunctions;
	int mechanismFunctionCount, status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	FNPTR_SET( deviceInfoPtr->initFunction, initFunction );
	FNPTR_SET( deviceInfoPtr->shutdownFunction, shutdownFunction );
	FNPTR_SET( deviceInfoPtr->controlFunction, controlFunction );
	status = deviceInitGetSet( deviceInfoPtr );
	ENSURES( cryptStatusOK( status ) );
#ifndef CONFIG_NO_SELFTEST
	FNPTR_SET( deviceInfoPtr->selftestFunction, selftestDevice );
#endif /* !CONFIG_NO_SELFTEST */
	FNPTR_SET( deviceInfoPtr->getRandomFunction, getRandomFunction );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	FNPTR_SET( deviceInfoPtr->catalogQueryFunction, catalogQueryFunction );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	DATAPTR_SET( deviceInfoPtr->capabilityInfoList, capabilityInfoList );
	status = hwGetMechanisms( &mechanismFunctions, 
							  &mechanismFunctionCount );
	if( cryptStatusOK( status ) )
		{
		DATAPTR_SET( deviceInfoPtr->mechanismFunctions, 
					 ( void * ) mechanismFunctions );
		deviceInfoPtr->mechanismFunctionCount = mechanismFunctionCount;
		}
	else
		{
		/* The hardware doesn't support mechanism-level operations, fall 
		   back to the built-in cryptlib ones */
		DATAPTR_SET( deviceInfoPtr->mechanismFunctions, \
					 ( void * ) defaultMechanismFunctions );
		deviceInfoPtr->mechanismFunctionCount = \
						FAILSAFE_ARRAYSIZE( defaultMechanismFunctions, \
											MECHANISM_FUNCTION_INFO );
		}
	DATAPTR_SET( deviceInfoPtr->storageFunctions, 
				 ( void * ) &storageFunctions );

	return( CRYPT_OK );
	}
#endif /* USE_HARDWARE */
