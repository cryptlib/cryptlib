/****************************************************************************
*																			*
*						cryptlib Device Storage Routines					*
*						Copyright Peter Gutmann 1998-2021					*
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
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Get a reference to the cryptographic device object that underlies a 
   native cryptlib object.  This is used to connect a reference from a PKCS 
   #15 storage object to the corresponding device object via the hardware 
   storageID that's recorded in the PKCS #15 storage object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
static int getHardwareReference( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
								 OUT_BUFFER_FIXED_C( KEYID_SIZE ) \
									BYTE *storageID, 
								 IN_LENGTH_FIXED( KEYID_SIZE ) \
									const int storageIDlen,
								 OUT_INT_Z int *storageRef,
								 const DEV_STORAGE_FUNCTIONS *storageFunctions )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( storageID, storageIDlen ) );
	assert( isWritePtr( storageRef, sizeof( int ) ) );
	assert( isReadPtr( storageFunctions, sizeof( DEV_STORAGE_FUNCTIONS ) ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( storageIDlen == KEYID_SIZE );

	/* Clear return value */
	*storageRef = CRYPT_ERROR;

	/* Get the storage ID and map it to a storage reference */
	setMessageData( &msgData, storageID, KEYID_SIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_DEVICESTORAGEID );
	if( cryptStatusOK( status ) )
		{
		status = storageFunctions->lookupItem( storageID, msgData.length, 
											   storageRef );
		}
	if( cryptStatusError( status ) )
		{
		/* In theory this is an internal error but in practice we shouldn't
		   treat this as too fatal, what it really means is that the crypto
		   hardware (which we don't control and therefore can't do too much
		   about) is out of sync with the PKCS #15 storage object.  This can 
		   happen for example during the development process when the 
		   hardware is reinitialised but the storage object isn't, or from
		   any one of a number of other circumstances beyond our control.  
		   To deal with this we return a standard notfound error but also 
		   output a diagnostic message for developers to let them know that
		   they need to check hardware/storage object synchronisation */
		DEBUG_DIAG(( "Object held in PKCS #15 object store doesn't "
					 "correspond to anything known to the crypto HAL" ));
		return( CRYPT_ERROR_NOTFOUND );
		}

	return( CRYPT_OK );
	}

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

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int openFileStorageObject( OUT_HANDLE_OPT CRYPT_KEYSET *iCryptKeyset,
								  IN_ENUM_OPT( CRYPT_KEYOPT ) \
									const CRYPT_KEYOPT_TYPE options )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	char storageFilePath[ MAX_PATH_LENGTH + 8 ];
	int storageFilePathLen, status;

	/* There's no in-memory storage provided, use an on-disk file as an
	   alternative */
	status = fileBuildCryptlibPath( storageFilePath, MAX_PATH_LENGTH, 
									&storageFilePathLen, "CLKEYS", 6, 
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
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							 IMESSAGE_DEV_CREATEOBJECT,
							 &createInfo, OBJECT_TYPE_KEYSET ) );
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
	   we make it a plain file if this is enabled */
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
			status = openFileStorageObject( &iLocalKeyset, options );
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
			   getHardwareReference() */
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

/****************************************************************************
*																			*
*						Get/Set/Delete Item Routines						*
*																			*
****************************************************************************/

/* Instantiate an object in a device.  This works like the create-context
   function but instantiates a cryptlib object using data already contained
   in the device, for example a stored private key or a certificate.  If 
   we're not using a crypto HAL (in other words cryptlib's native crypto is
   enabled) and the value being read is a public key and there's a 
   certificate attached then the instantiated object is a native cryptlib 
   object rather than a device object with a native certificate object 
   attached because there doesn't appear to be any good reason to create the 
   public-key object in the device, and the cryptlib native object will 
   probably be faster anyway */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5, 8 ) ) \
static int getItemFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
							OUT_HANDLE_OPT CRYPT_HANDLE *iCryptContext,
							IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType,
							IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
							IN_BUFFER( keyIDlength ) const void *keyID, 
							IN_LENGTH_KEYID const int keyIDlength,
							IN_PTR_OPT void *auxInfo, 
							INOUT_LENGTH_SHORT_Z int *auxInfoLength,
							IN_FLAGS_Z( KEYMGMT ) const int flags )
	{
	CRYPT_CONTEXT iLocalContext;
	const DEV_STORAGE_FUNCTIONS *storageFunctions;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	BYTE storageID[ KEYID_SIZE + 8 ];
	int storageRef, status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isReadPtrDynamic( keyID, keyIDlength ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_PRIVATEKEY );
	REQUIRES( keyIDtype == CRYPT_KEYID_NAME || \
			  keyIDtype == CRYPT_KEYID_URI || \
			  keyIDtype == CRYPT_IKEYID_KEYID || \
			  keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			  keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER );
	REQUIRES( keyIDlength >= MIN_NAME_LENGTH && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );
	REQUIRES( auxInfo == NULL && *auxInfoLength == 0 );
	REQUIRES( isFlagRangeZ( flags, KEYMGMT ) );

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	storageFunctions = DATAPTR_GET( deviceInfoPtr->storageFunctions );
	REQUIRES( storageFunctions != NULL );

	/* Redirect the fetch down to the PKCS #15 storage object, which will
	   create either a dummy context that we have to connect to the actual
	   hardware or a native public-key/certificate object if it's a non-
	   private-key item and we're not using a crypto HAL for our crypto */
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_NOTINITED, 
				( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
				  "No storage object associated with this device" ) );
		}
	setMessageKeymgmtInfo( &getkeyInfo, keyIDtype, keyID, keyIDlength,
						   NULL, 0, flags );
	status = krnlSendMessage( deviceInfoPtr->iCryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo,
							  itemType );
	if( cryptStatusError( status ) )
		{
		retExtObjDirect( status, DEVICE_ERRINFO, 
						 deviceInfoPtr->iCryptKeyset );
		}
	iLocalContext = getkeyInfo.cryptHandle;

	/* If it's a public-key fetch and we're not using a crypto HAL, we've 
	   created a cryptlib native object and we're done */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( deviceInfoPtr->objectHandle != CRYPTO_OBJECT_HANDLE && \
		itemType != KEYMGMT_ITEM_PRIVATEKEY )
#else
	if( itemType != KEYMGMT_ITEM_PRIVATEKEY )
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
		{
		*iCryptContext = iLocalContext;
		return( CRYPT_OK );
		}

	/* Connect the dummy context that was created with the underlying 
	   hardware via the storageRef.  This is done by reading the
	   storageID from the context that was created from the P15 data and
	   mapping it to a storageRef used by the underlying hardware (in
	   some cases like TPMs the underlying hardware uses the storageID
	   directly so the storageRef may be just a dummy value).

	   When this final step has been completed we can move the context to 
	   the initialised state */
	status = getHardwareReference( iLocalContext, storageID, KEYID_SIZE, 
								   &storageRef, storageFunctions );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalContext, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, DEVICE_ERRINFO,
				  "Fetched item doesn't correspond to anything known to "
				  "the crypto hardware" ) );
		}
	status = krnlSendMessage( iLocalContext, IMESSAGE_SETATTRIBUTE,
							  &storageRef, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iLocalContext, IMESSAGE_SETATTRIBUTE, 
								  MESSAGE_VALUE_UNUSED, 
								  CRYPT_IATTRIBUTE_INITIALISED );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* The storage object only stores metadata associated with the context 
	   such as identification information and certificates, with all of the 
	   crypto being done in the device.  Because of this what we get back is 
	   a dummy private-key context with a data-only certificate attached, 
	   with the device taking care of all crypto operations.  However some 
	   devices may not be able to natively perform public-key operations, 
	   either because they only contain a private-key engine (some PKCS #11 
	   smart cards) or because their functionality is so hardcoded for one 
	   specific purpose that it's not possible to use them to do general-
	   purpose crypto (TPMs).

	   PKCS #11 handles this by not setting any public-key permissions on 
	   the read-back private-key object (they're automatically not set for 
	   newly-generated keys, both for PKCS #11 and hardware devices), 
	   however in the general hardware-device case it's not that simple 
	   because in some instances the device is needed to perform all 
	   operations, for example when it implements custom algorithms not 
	   handled by cryptlib, and in others it isn't.

	   To deal with this we mask off non-private-key ops on the read-back 
	   private-key object if required */
	if( deviceInfoPtr->noPubkeyOps )
		{
		static const int actionFlags = \
				MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL ) | \
				MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );

		status = krnlSendMessage( iLocalContext, IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &actionFlags, 
								  CRYPT_IATTRIBUTE_ACTIONPERMS );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iLocalContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	*iCryptContext = iLocalContext;
	return( CRYPT_OK );
	}

/* Add an object to a device.  This can only ever add a certificate
   (enforced by the kernel ACLs) so we don't have to perform any 
   special-case handling */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setItemFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
							IN_HANDLE const CRYPT_HANDLE iCryptHandle )
	{
	MESSAGE_KEYMGMT_INFO setkeyInfo;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isHandleRangeValid( iCryptHandle ) );

	/* Redirect the add down to the PKCS #15 storage object */
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_NOTINITED, 
				( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
				  "No storage object associated with this device" ) );
		}
	setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
						   NULL, 0, KEYMGMT_FLAG_NONE );
	setkeyInfo.cryptHandle = iCryptHandle;
	status = krnlSendMessage( deviceInfoPtr->iCryptKeyset,
							  IMESSAGE_KEY_SETKEY, &setkeyInfo,
							  KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		{
		retExtObjDirect( status, DEVICE_ERRINFO, 
						 deviceInfoPtr->iCryptKeyset );
		}

	return( CRYPT_OK );
	}

/* Delete an object in a device */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int deleteItemFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
							   IN_ENUM( KEYMGMT_ITEM ) \
									const KEYMGMT_ITEM_TYPE itemType,
							   IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
							   IN_BUFFER( keyIDlength ) const void *keyID, 
							   IN_LENGTH_KEYID const int keyIDlength )
	{
	const DEV_STORAGE_FUNCTIONS *storageFunctions;
	MESSAGE_KEYMGMT_INFO getkeyInfo, deletekeyInfo;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isReadPtrDynamic( keyID, keyIDlength ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_PRIVATEKEY );
	REQUIRES( keyIDtype == CRYPT_KEYID_NAME );
	REQUIRES( keyIDlength >= MIN_NAME_LENGTH && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );

	storageFunctions = DATAPTR_GET( deviceInfoPtr->storageFunctions );
	REQUIRES( storageFunctions != NULL );

	/* Perform the delete both from the PKCS #15 storage object and the
	   native storage.  This gets a bit complicated because all that we have
	   to identify the item is one of several types of keyID and the 
	   hardware device needs a storageID to identify it.  To deal with this 
	   we have to instantiate a dummy object via the keyID which then 
	   contains the storageID, from which we can get the storageRef.  
	   
	   In addition if we're not using a crypto HAL and the object that's 
	   stored isn't a private-key object then there's no associated 
	   cryptographic hardware object.  To handle this we try and instantiate 
	   a dummy private-key object in order to get the storageID, and if 
	   we're using a crypto HAL we fall back to trying for a public-key 
	   object if that fails.  If this succeeds, we use it to locate the 
	   underlying hardware object and delete it.  Finally, we delete the 
	   original PKCS #15 object */
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_NOTINITED, 
				( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
				  "No storage object associated with this device" ) );
		}
	setMessageKeymgmtInfo( &getkeyInfo, keyIDtype, keyID, keyIDlength,
						   NULL, 0, KEYMGMT_FLAG_NONE );
	status = krnlSendMessage( deviceInfoPtr->iCryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo,
							  KEYMGMT_ITEM_PRIVATEKEY );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( cryptStatusError( status ) && \
		deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE )
		{
		/* It's not a private-key object, try again with a public-key 
		   object */
		status = krnlSendMessage( hardwareInfo->iCryptKeyset,
								  IMESSAGE_KEY_GETKEY, &getkeyInfo,
								  KEYMGMT_ITEM_PUBLICKEY );
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	if( cryptStatusOK( status ) )
		{
		BYTE storageID[ KEYID_SIZE + 8 ];
		int storageRef;

		/* We've located the hardware object, get its hardware reference and 
		   delete it (we destroy the cryptlib-level object before we do this
		   since we're about to delete the corresponding hardware object out
		   from underneath it).  If this fails we continue anyway because we 
		   know that there's also a PKCS #15 object to delete */
		status = getHardwareReference( getkeyInfo.cryptHandle, storageID, 
									   KEYID_SIZE, &storageRef, 
									   storageFunctions );
		krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptStatusOK( status ) )
			{
			( void ) \
				storageFunctions->deleteItem( deviceInfoPtr->contextHandle, 
											  storageID, KEYID_SIZE, 
											  storageRef );
			}
		}
	setMessageKeymgmtInfo( &deletekeyInfo, keyIDtype, keyID, keyIDlength,
						   NULL, 0, KEYMGMT_FLAG_NONE );
	status = krnlSendMessage( deviceInfoPtr->iCryptKeyset,
							  IMESSAGE_KEY_DELETEKEY, &deletekeyInfo,
							  itemType );
	if( cryptStatusError( status ) )
		{
		retExtObjDirect( status, DEVICE_ERRINFO, 
						 deviceInfoPtr->iCryptKeyset );
		}

	return( CRYPT_OK );
	}

/* Get the sequence of certificates in a chain from a device.  Since these 
   functions operate only on certificates we can redirect them straight down 
   to the underlying storage object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
static int getFirstItemFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
								 OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertificate,
								 OUT_INT_Z_ERROR int *stateInfo,
								 IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
								 IN_BUFFER( keyIDlength ) const void *keyID, 
								 IN_LENGTH_KEYID const int keyIDlength,
								 IN_ENUM( KEYMGMT_ITEM ) \
									const KEYMGMT_ITEM_TYPE itemType,
								 IN_FLAGS_Z( KEYMGMT ) const int options )
	{
	MESSAGE_KEYMGMT_INFO getnextcertInfo;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtrDynamic( keyID, keyIDlength ) );
	assert( isWritePtr( stateInfo, sizeof( int ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( keyIDtype == CRYPT_IKEYID_KEYID );
	REQUIRES( isShortIntegerRangeMin( keyIDlength, 4 ) );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY );
	REQUIRES( isFlagRangeZ( options, KEYMGMT ) );

	/* Clear return values */
	*iCertificate = CRYPT_ERROR;
	*stateInfo = CRYPT_ERROR;

	/* Make sure that there's somewhere to fetch the item from */
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_NOTINITED, 
				( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
				  "No storage object associated with this device" ) );
		}

	/* Get the first certificate */
	setMessageKeymgmtInfo( &getnextcertInfo, keyIDtype, keyID, keyIDlength, 
						   stateInfo, sizeof( int ), options );
	status = krnlSendMessage( deviceInfoPtr->iCryptKeyset, 
							  IMESSAGE_KEY_GETFIRSTCERT, &getnextcertInfo, 
							  KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		{
		retExtObjDirect( status, DEVICE_ERRINFO, 
						 deviceInfoPtr->iCryptKeyset );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int getNextItemFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
								OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertificate,
								INOUT_PTR int *stateInfo, 
								IN_FLAGS_Z( KEYMGMT ) const int options )
	{
	MESSAGE_KEYMGMT_INFO getnextcertInfo;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isWritePtr( stateInfo, sizeof( int ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isHandleRangeValid( *stateInfo ) || *stateInfo == CRYPT_ERROR );
	REQUIRES( isFlagRangeZ( options, KEYMGMT ) );

	/* Clear return value */
	*iCertificate = CRYPT_ERROR;

	/* Make sure that there's somewhere to fetch the item from.  This can 
	   happen if the device is cleared/zeroised/reinitalised after the 
	   getFirstItem() call */
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_NOTINITED, 
				( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
				  "No storage object associated with this device" ) );
		}

	/* If the previous certificate was the last one, there's nothing left to 
	   fetch */
	if( *stateInfo == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Get the next certificate */
	setMessageKeymgmtInfo( &getnextcertInfo, CRYPT_KEYID_NONE, NULL, 0, 
						   stateInfo, sizeof( int ), options );
	status = krnlSendMessage( deviceInfoPtr->iCryptKeyset, 
							  IMESSAGE_KEY_GETNEXTCERT, &getnextcertInfo, 
							  KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		{
		retExtObjDirect( status, DEVICE_ERRINFO, 
						 deviceInfoPtr->iCryptKeyset );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device storage methods */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deviceInitStorage( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
	{
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	FNPTR_SET( deviceInfoPtr->getItemFunction, getItemFunction );
	FNPTR_SET( deviceInfoPtr->setItemFunction, setItemFunction );
	FNPTR_SET( deviceInfoPtr->deleteItemFunction, deleteItemFunction );
	FNPTR_SET( deviceInfoPtr->getFirstItemFunction, getFirstItemFunction );
	FNPTR_SET( deviceInfoPtr->getNextItemFunction, getNextItemFunction );

	return( CRYPT_OK );
	}
#endif /* USE_HARDWARE || USE_TPM */
