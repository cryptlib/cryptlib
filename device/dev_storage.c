/****************************************************************************
*																			*
*						cryptlib Device Storage Routines					*
*						Copyright Peter Gutmann 1998-2025					*
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

/* This module provides storage support for crypto devices with minimal or
   no item lookup and access functionality beyond "read a block of memory"
   or "write a block of memory".  It does this by overlaying a PKCS #15
   keyset onto the block of memory and using the keyset to manage all
   storage, retrieval, and lookup functionality */

#if defined( USE_HARDWARE ) || defined( USE_TPM )

/****************************************************************************
*																			*
*						 		Storage Object Routines						*
*																			*
****************************************************************************/

/* Open and close the PKCS #15 storage object associated with a crypto HAL.  
   This is either mapped to storage inside the hardware device or stored on 
   disk if the device doesn't provide its own storage */

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )

static int getCryptoStorageObject( OUT_HANDLE_OPT CRYPT_KEYSET *iCryptKeyset )
	{
	CRYPT_KEYSET iHWKeyset;
	int status;

	assert( isWritePtr( iCryptKeyset, sizeof( CRYPT_KEYSET ) ) );

	/* Clear return value */
	*iCryptKeyset = CRYPT_ERROR;

	/* Get a reference to the crypto storage object from the crypto hardware
	   device */
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE, 
							  &iHWKeyset, CRYPT_IATTRIBUTE_HWSTORAGE );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( iHWKeyset, IMESSAGE_INCREFCOUNT );
	if( cryptStatusError( status ) )
		{
		/* Rather than returning some possible low-level permssion error or 
		   similar we report the problem as a CRYPT_ERROR_NOTINITED since 
		   the most likely issue is that the storage object isn't set up for 
		   use */
		return( CRYPT_ERROR_NOTINITED );
		}

	*iCryptKeyset = iHWKeyset;
	return( CRYPT_OK );
	}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

#ifdef USE_FILES

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int openDeviceFileStorageObject( OUT_HANDLE_OPT CRYPT_KEYSET *iCryptKeyset,
								 IN_BUFFER( fileNameLen ) \
									const char *fileName,
								 IN_LENGTH_SHORT_MIN( 3 ) \
									const int fileNameLen,
								 IN_ENUM_OPT( CRYPT_KEYOPT ) \
									const CRYPT_KEYOPT_TYPE options )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	char storageFilePath[ MAX_PATH_LENGTH + 8 ];
	int storageFilePathLen, status;

	assert( isWritePtr( iCryptKeyset, sizeof( CRYPT_KEYSET ) ) );
	assert( isReadPtrDynamic( fileName, fileNameLen ) );

	REQUIRES( isShortIntegerRangeMin( fileNameLen, 3 ) );
	REQUIRES( options == CRYPT_KEYOPT_NONE || \
			  options == CRYPT_KEYOPT_CREATE );

	/* Clear return value */
	*iCryptKeyset = CRYPT_ERROR;

	/* There's no in-memory storage available, use an on-disk file as an
	   alternative */
	status = fileBuildCryptlibPath( storageFilePath, MAX_PATH_LENGTH, 
									&storageFilePathLen, 
									fileName, fileNameLen, 
									( options == CRYPT_KEYOPT_CREATE ) ? \
									  BUILDPATH_CREATEPATH : \
									  BUILDPATH_GETPATH );
	if( cryptStatusError( status ) )
		return( status );
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.strArg1 = storageFilePath;
	createInfo.strArgLen1 = storageFilePathLen;
	if( options != CRYPT_KEYOPT_NONE )
		createInfo.arg2 = options;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_KEYSET );
	if( cryptStatusError( status ) )
		return( status );
	*iCryptKeyset = createInfo.cryptHandle;
	
	return( CRYPT_OK );
	}
#endif /* USE_FILES */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 7 ) ) \
int openDeviceStorageObject( OUT_HANDLE_OPT CRYPT_KEYSET *iCryptKeyset,
							 IN_ENUM_OPT( CRYPT_KEYOPT ) \
								const CRYPT_KEYOPT_TYPE options,
							 IN_HANDLE const CRYPT_DEVICE iCryptDevice,
							 const DEV_STORAGE_FUNCTIONS *storageFunctions,
							 IN_PTR_OPT void *contextHandle,
							 IN_BOOL const BOOLEAN allowFileStorage,
							 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_KEYSET iLocalKeyset DUMMY_INIT;
	CRYPT_KEYOPT_TYPE localOptions = options;
	ERROR_INFO localErrorInfo;
	void *storageObjectAddr;
	BOOLEAN isFileKeyset = FALSE;
	int storageObjectSize, status;

	assert( isWritePtr( iCryptKeyset, sizeof( CRYPT_KEYSET ) ) );
	assert( isReadPtr( storageFunctions, sizeof( DEV_STORAGE_FUNCTIONS ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( options == CRYPT_KEYOPT_NONE || \
			  options == CRYPT_KEYOPT_CREATE );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	REQUIRES( iCryptDevice == CRYPTO_OBJECT_HANDLE || \
			  isHandleRangeValid( iCryptDevice ) );
#else
	REQUIRES( isHandleRangeValid( iCryptDevice ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	REQUIRES( isBooleanValue( allowFileStorage ) );

	/* Clear return value */
	*iCryptKeyset = CRYPT_ERROR;

	/* If we've got a crypto HAL present then the internal HAL device will 
	   already have opened the storage object when it was instantiated at 
	   cryptlib initialisation time.  If this isn't the (implicit) internal 
	   HAL device but an explicitly-created external reference to the HAL 
	   then we don't want to open the storage object a second time but 
	   merely obtain a reference to the existing storage object from the 
	   internal HAL device */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( iCryptDevice != CRYPTO_OBJECT_HANDLE )
		{
		/* It's a second external device pointing to the same HAL as the 
		   internal HAL device, return a handle to the storage object from 
		   that rather than creating a new one */
		return( getCryptoStorageObject( iCryptKeyset ) );
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	/* Try and open/create the PKCS #15 storage object.  If the hardware 
	   device provides secure storage for this then we use that, otherwise 
	   we make it a plain file if filesystem I/O is available */
	clearErrorInfo( &localErrorInfo );
	status = storageFunctions->getStorage( contextHandle, 
										   &storageObjectAddr, 
										   &storageObjectSize );
	if( status == OK_SPECIAL )
		{
		/* If the device provides its own storage but this hasn't been 
		   initialised yet, indicated by a return value of OK_SPECIAL, then 
		   we can't open it as a storage object until it's explicitly 
		   initialised.  If the open option is CRYPT_KEYOPT_CREATE then
		   we're expecting to initialise anyway, but if then not we switch 
		   the open option to CRYPT_KEYOPT_CREATE now */
		if( options == CRYPT_KEYOPT_NONE )
			{
			DEBUG_DIAG(( "Built-in device storage is zeroised, cryptlib "
						 "will initialise the storage object" ));
			localOptions = CRYPT_KEYOPT_CREATE;
			}
		status = CRYPT_OK;
		}
	if( cryptStatusOK( status ) )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Create the PKCS #15 storage object.  What CRYPTO_OBJECT_HANDLE is
		   depends on whether CONFIG_CRYPTO_HW1 or CONFIG_CRYPTO_HW2 are
		   enabled or not (see the long comment in cryptkrn.h for how these
		   work), if they're enabled then it represents a distinct device
		   that abstracts a custom crypto HAL, if not then it's identical to
		   SYSTEM_OBJECT_HANDLE */
		setMessageCreateObjectIndirectInfo( &createInfo, storageObjectAddr, 
											storageObjectSize, 
											CRYPT_KEYSET_FILE, 
											&localErrorInfo );
		if( localOptions != CRYPT_KEYOPT_NONE )
			createInfo.arg2 = localOptions;
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								  &createInfo, OBJECT_TYPE_KEYSET );
		if( cryptStatusOK( status ) )
			iLocalKeyset = createInfo.cryptHandle;
		}
	else
		{
#ifdef USE_FILES
		/* If fallback to file storage is OK, try that */
		if( allowFileStorage )
			{
			status = openDeviceFileStorageObject( &iLocalKeyset, 
												  "CLKEYS", 6, options );
			if( cryptStatusOK( status ) )
				isFileKeyset = TRUE;
			}
#else
		status = CRYPT_ERROR_OPEN;
#endif /* USE_FILES */
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, errorInfo, &localErrorInfo,
					 "Couldn't open device storage object" ) );
		}

	/* Now that we've got the storage object we have to perform a somewhat 
	   awkward backreference-update of the keyset to give it the handle of 
	   the owning device since we need to create any contexts for keys 
	   fetched from the storage object via the hardware device rather than 
	   the default system device.  In theory we could also do this via a new 
	   get-owning-object message but we still need to signal to the keyset 
	   that it's a storage object rather than a standard keyset so this 
	   action serves a second purpose anyway and we may as well use it to 
	   explicitly set the owning-device handle at the same time.

	   Note that we don't set the storage object as a dependent object of 
	   the device because it's not necessarily constant across device 
	   sessions.  In particular if we initialise or zeroise the device then 
	   the storage object will be reset, but there's no way to switch 
	   dependent objects without destroying and recreating the parent.  In
	   addition it's not certain whether the storage-object keyset should
	   really be a dependent object or not, in theory it's nice because it
	   allows keyset-specific messages/accesses to be sent to the device and
	   automatically routed to the keyset (standard accesses will still go 
	   to the device, so for example a getItem() will be handled as a 
	   device-get rather than a keyset-get) but such unmediated access to 
	   the underlying keyset probably isn't a good idea anyway */
	status = krnlSendMessage( iLocalKeyset, IMESSAGE_SETATTRIBUTE,
							  ( MESSAGE_CAST ) &iCryptDevice, 
							  CRYPT_IATTRIBUTE_HWDEVICE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalKeyset, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptKeyset = iLocalKeyset;

	return( isFileKeyset ? OK_SPECIAL : CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int deleteDeviceStorageObject( IN_BOOL const BOOLEAN updateBackingStore,
							   IN_BOOL const BOOLEAN isFileKeyset,
							   const DEV_STORAGE_FUNCTIONS *storageFunctions,
							   IN_PTR_OPT void *contextHandle )
	{
	int status;

	assert( isReadPtr( storageFunctions, sizeof( DEV_STORAGE_FUNCTIONS ) ) );

	REQUIRES( isBooleanValue( updateBackingStore ) );
	REQUIRES( isBooleanValue( isFileKeyset ) );
#ifdef USE_FILES
	REQUIRES( ( isFileKeyset && !updateBackingStore ) || \
			  ( !isFileKeyset ) );
#else
	REQUIRES( !isFileKeyset );
#endif /* USE_FILES */

	/* Delete the storage object */
	if( !isFileKeyset )
		{
		void *storageObjectAddr;
		int storageObjectSize;

		/* Clear the storage and notify the HAL of the change if required */
		status = storageFunctions->getStorage( contextHandle,
											   &storageObjectAddr, 
											   &storageObjectSize );
		if( cryptStatusError( status ) && status != OK_SPECIAL )
			{
			/* Another shouldn't-occur situation, see the comment in
			   dev_getset.c:getHardwareReference() */
			DEBUG_DIAG(( "Reference to secure hardware storage not "
						 "available from HAL" ));
			return( CRYPT_ERROR_NOTFOUND );
			}
		ANALYSER_HINT( storageObjectAddr != NULL );
		zeroise( storageObjectAddr, storageObjectSize );
		if( updateBackingStore )
			{
			status = storageFunctions->storageUpdateNotify( contextHandle, 
															0 );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
#ifdef USE_FILES
	else
		{
		char storageFilePath[ MAX_PATH_LENGTH + 8 ];
		int storageFilePathLen;

		status = fileBuildCryptlibPath( storageFilePath, MAX_PATH_LENGTH, 
										&storageFilePathLen, "CLKEYS", 6, 
										BUILDPATH_GETPATH );
		if( cryptStatusError( status ) )
			return( status );
		fileErase( storageFilePath );
		}
#endif /* USE_FILES */

	return( CRYPT_OK );
	}

/* Persist context metadata to a storage object.  This takes a hardware-
   based context and persists metadata like keyIDs and other identification 
   information to the device's storage object so that it can be accessed
   later.
   
   The function looks a bit odd because there's no device to persist it to 
   given in the arguments, that's because it's being called from functions 
   working with context info rather than device info so the device info is 
   implicitly taken from the context info */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int persistContextMetadata( INOUT_PTR TYPECAST( CONTEXT_INFO * ) \
								struct CI *contextInfo,
							IN_BUFFER( storageIDlen ) \
								const BYTE *storageID,
						    IN_LENGTH_FIXED( KEYID_SIZE ) \
								const int storageIDlen )
	{
	CRYPT_DEVICE iCryptDevice;
	CONTEXT_INFO *contextInfoPtr = contextInfo;
	DEVICE_INFO *deviceInfoPtr;
	MESSAGE_KEYMGMT_INFO setkeyInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( contextInfo, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtr( storageID, storageIDlen ) );

	REQUIRES( storageIDlen == KEYID_SIZE );

	/* If it's a non-PKC context then there's nothing further to do */
	if( contextInfoPtr->type != CONTEXT_PKC )
		return( CRYPT_OK );

	/* As a variation of the above, if it's a public-key context then we 
	   don't want to persist it to the storage object because public-key
	   contexts are a bit of an anomaly, when generating our own keys we 
	   always have full private keys and when obtaining public keys from an 
	   external source they'll be in the form of certificates so there isn't 
	   really much need for persistent raw public keys.  At the moment the 
	   only time that they're used is for the self-test, and potentially 
	   polluting the (typically quite limited) crypto hardware storage with 
	   unneeded public keys doesn't seem like a good idea */
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY ) )
		return( CRYPT_OK );

	/* It's a PKC context, prepare to persist the key metadata to the 
	   underlying PKCS #15 storage object.  First we get the the device 
	   associated with this context */
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is the crypto object standing in for the system object then
	   don't go any further.  This is because the crypto object transparently 
	   handles all of the encryption operations normally performed by the 
	   system object and if we persisted objects created in it we'd both 
	   rapidly fill up the object storage and also be left with a collection 
	   of persistent objects that can't be accessed or cleared because 
	   they're associated with a hidden object */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( iCryptDevice == CRYPTO_OBJECT_HANDLE )
		return( CRYPT_OK );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	/* Set the storageID for the context.  This is used to connect the data
	   stored in the crypto device with context information stored in the
	   storage object */
	setMessageData( &msgData, ( MESSAGE_CAST ) storageID, storageIDlen );
	status = krnlSendMessage( contextInfoPtr->objectHandle, 
							  IMESSAGE_SETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_DEVICESTORAGEID );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the hardware information from the device information */
	status = krnlAcquireObject( iCryptDevice, OBJECT_TYPE_DEVICE, 
								( MESSAGE_PTR_CAST ) &deviceInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		krnlReleaseObject( iCryptDevice );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Since this is a dummy context that contains no actual keying 
	   information (the key data is held in hardware) we set it as 
	   KEYMGMT_ITEM_KEYMETADATA */
	setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0, NULL, 0, 
						   KEYMGMT_FLAG_NONE );
	setkeyInfo.cryptHandle = contextInfoPtr->objectHandle;
	status = krnlSendMessage( deviceInfoPtr->iCryptKeyset,
							  IMESSAGE_KEY_SETKEY, &setkeyInfo,
							  KEYMGMT_ITEM_KEYMETADATA );
	krnlReleaseObject( iCryptDevice );
	SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_PERSISTENT );

	return( status );
	}
#endif /* USE_HARDWARE || USE_TPM */
