/****************************************************************************
*																			*
*					cryptlib Device Get/Set/Delete Routines					*
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

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4, 5 ) ) \
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

	/* Make sure that we've actually got an underlying keyset present */
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_NOTINITED, 
				( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
				  "No storage object associated with this device" ) );
		}

	/* If it's a passthrough device then we just pass the call on down to 
	   the underlying keyset */
	if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_PASSTHROUGH ) )
		{
		ENSURES( deviceInfoPtr->type == CRYPT_DEVICE_TPM );
	
		/* If the device hasn't been initialised yet then there won't be
		   a storage key set up for retrieving private keys */
		if( itemType == KEYMGMT_ITEM_PRIVATEKEY && \
			deviceInfoPtr->storageKeyLen <= 0 )
			{
			retExt( CRYPT_ERROR_NOTINITED, 
					( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
					  "Device storage key hasn't been initialised yet" ) );
			}

		setMessageKeymgmtInfo( &getkeyInfo, keyIDtype, keyID, keyIDlength,
							   NULL, 0, flags );
		if( itemType == KEYMGMT_ITEM_PRIVATEKEY )
			{
			/* If it's a private key then we need to use the storage key to
			   retrieve it */
			getkeyInfo.auxInfo = ( void * ) deviceInfoPtr->storageKey; 
			getkeyInfo.auxInfoLength = deviceInfoPtr->storageKeyLen;
			}
		status = krnlSendMessage( deviceInfoPtr->iCryptKeyset,
								  IMESSAGE_KEY_GETKEY, &getkeyInfo,
								  itemType );
		if( cryptStatusError( status ) )
			{
			/* If we get a wrong-key error then it's probably due to the 
			   storage key having changed, so we provide a custom error 
			   message for that */
			if( status == CRYPT_ERROR_WRONGKEY )
				{
				retExt( CRYPT_ERROR_WRONGKEY, 
						( CRYPT_ERROR_WRONGKEY, DEVICE_ERRINFO,
						  "Incorrect key used to retrieve item, possibly "
						  "due to the storage key having changed" ) );
				}
				
			retExtObjDirect( status, DEVICE_ERRINFO, 
							 deviceInfoPtr->iCryptKeyset );
			}
		*iCryptContext = getkeyInfo.cryptHandle;
		
		return( CRYPT_OK );
		}

	storageFunctions = DATAPTR_GET( deviceInfoPtr->storageFunctions );
	REQUIRES( storageFunctions != NULL );

	/* Redirect the fetch down to the PKCS #15 storage object, which will
	   create either a dummy context that we have to connect to the actual
	   hardware or a native public-key/certificate object if it's a non-
	   private-key item and we're not using a crypto HAL for our crypto */
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
	   either because they only contain a private-key engine (some older 
	   PKCS #11 smart cards) or because their functionality is so hardcoded 
	   for one specific purpose that it's not possible to use them to do 
	   general-purpose crypto (TPMs).

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

/* Add an object to a device.  This is usually a certificate (enforced by 
   kernel ACLs) but may be a private key for passthrough devices */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setItemFunction( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
							IN_HANDLE const CRYPT_HANDLE iCryptHandle,
							IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType )
 	{
	MESSAGE_KEYMGMT_INFO setkeyInfo;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( itemType == KEYMGMT_ITEM_PRIVATEKEY || \
			  itemType == KEYMGMT_ITEM_PUBLICKEY );

	/* Make sure that we've actually got an underlying keyset present */
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_NOTINITED, 
				( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
				  "No storage object associated with this device" ) );
		}

	/* If it's a passthrough device then we just pass the call on down to 
	   the underlying keyset, otherwise we redirect the call down to the 
	   PKCS #15 storage object */
	if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_PASSTHROUGH ) )
		{
		REQUIRES( deviceInfoPtr->type == CRYPT_DEVICE_TPM );
	
		/* If the device hasn't been initialised yet then there won't be
		   a storage key set up for retrieving private keys */
		if( itemType == KEYMGMT_ITEM_PRIVATEKEY && \
			deviceInfoPtr->storageKeyLen <= 0 )
			{
			retExt( CRYPT_ERROR_NOTINITED, 
					( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
					  "Device storage key hasn't been initialised yet" ) );
			}
		
		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
							   NULL, 0, KEYMGMT_FLAG_NONE );
		if( itemType == KEYMGMT_ITEM_PRIVATEKEY )
			{
			/* If it's a private key then we need to use the storage key to
			   set it */
			setkeyInfo.auxInfo = ( void * ) deviceInfoPtr->storageKey; 
			setkeyInfo.auxInfoLength = deviceInfoPtr->storageKeyLen;
			}
		}
	else
		{
		/* For anything other than a TPM the kernel ACLs will have ensured 
		   that we can only be given a public key/certificate */
		REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY );

		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
							   NULL, 0, KEYMGMT_FLAG_NONE );
		}
	setkeyInfo.cryptHandle = iCryptHandle;
	status = krnlSendMessage( deviceInfoPtr->iCryptKeyset,
							  IMESSAGE_KEY_SETKEY, &setkeyInfo,
							  itemType );
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

	/* Make sure that we've actually got an underlying keyset present */
	if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_NOTINITED, 
				( CRYPT_ERROR_NOTINITED, DEVICE_ERRINFO,
				  "No storage object associated with this device" ) );
		}

	/* If it's a passthrough device then we just pass the call on down to 
	   the underlying keyset.  We don't check for a storage key being set
	   up both because it's not needed and because it allows the caller to
	   clear out objects if the storage key is lost, for example due to
	   the TPM being re-provisioned */
	if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_PASSTHROUGH ) )
		{
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

	/* Make sure that we've actually got an underlying keyset present */
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

	/* Make sure that we've actually got an underlying keyset present.  
	   Beyond the usual sanity check this can in theory happen if the device 
	   is cleared/zeroised/reinitalised after the getFirstItem() call  */
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

/* Set up the function pointers to the device get/set/delete methods */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deviceInitGetSet( INOUT_PTR DEVICE_INFO *deviceInfoPtr )
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
