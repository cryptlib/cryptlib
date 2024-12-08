<<<<<<< HEAD
/****************************************************************************
*																			*
*						 cryptlib Crypto Device Routines					*
*						Copyright Peter Gutmann 1997-2022					*
*																			*
****************************************************************************/

#include "crypt.h"
#ifdef INC_ALL
  #include "capabil.h"
  #include "device.h"
  #include "objectfns.h"
#else
  #include "device/capabil.h"
  #include "device/device.h"
  #include "kernel/objectfns.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Sanity-check device data */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckDevice( IN_PTR const DEVICE_INFO *deviceInfoPtr )
	{
	assert( isReadPtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	/* Check general device data.  CRYPT_DEVICE_NONE is the system device so
	   we check with isEnumRangeOpt() rather than isEnumRange() */
	if( !isEnumRangeOpt( deviceInfoPtr->type, CRYPT_DEVICE ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: General info" ));
		return( FALSE );
		}
	if( !CHECK_FLAGS( deviceInfoPtr->flags, DEVICE_FLAG_NONE, 
					  DEVICE_FLAG_MAX ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: Flags" ));
		return( FALSE );
		}
	if( !isEmptyData( deviceInfoPtr->label, deviceInfoPtr->labelLen ) )
		{
		if( deviceInfoPtr->labelLen <= 0 || \
			deviceInfoPtr->labelLen > CRYPT_MAX_TEXTSIZE )
			{
			DEBUG_PUTS(( "sanityCheckDevice: Label" ));
			return( FALSE );
			}
		}
	if( !checkVarStruct( deviceInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: VarStruct" ));
		return( FALSE );
		}

	/* Check safe pointers.  We don't have to check the function pointers
	   because they're validated each time they're dereferenced */
	if( !DATAPTR_ISVALID( deviceInfoPtr->capabilityInfoList ) || \
		!DATAPTR_ISVALID( deviceInfoPtr->mechanismFunctions ) || \
		!rangeCheck( deviceInfoPtr->mechanismFunctionCount, 0, 50 ) || \
		!DATAPTR_ISVALID( deviceInfoPtr->createObjectFunctions ) || \
		!rangeCheck( deviceInfoPtr->createObjectFunctionCount, 0, 10 ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: Data pointers" ));
		return( FALSE );
		}

	/* Check associated handles */
	if( deviceInfoPtr->type == CRYPT_DEVICE_NONE )
		{
		if( deviceInfoPtr->objectHandle != SYSTEM_OBJECT_HANDLE || \
			deviceInfoPtr->ownerHandle != CRYPT_UNUSED )
			{
			DEBUG_PUTS(( "sanityCheckDevice: System device handles" ));
			return( FALSE );
			}
		}
	else
		{
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		if( !( deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE || \
			   isHandleRangeValid( deviceInfoPtr->objectHandle ) ) || \
			deviceInfoPtr->ownerHandle != DEFAULTUSER_OBJECT_HANDLE )
#else
		if( !isHandleRangeValid( deviceInfoPtr->objectHandle ) || \
			deviceInfoPtr->ownerHandle != DEFAULTUSER_OBJECT_HANDLE )
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
			{
			DEBUG_PUTS(( "sanityCheckDevice: Object handles" ));
			return( FALSE );
			}
		}

	/* Check function and data pointers */
	if( !DATAPTR_ISSET( deviceInfoPtr->capabilityInfoList ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: Capability function" ));
		return( FALSE );
		}

	/* Check error information */
	if( !isEnumRangeOpt( deviceInfoPtr->errorLocus, CRYPT_ATTRIBUTE ) || \
		!isEnumRangeOpt( deviceInfoPtr->errorType, CRYPT_ERRTYPE ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: Error info" ));
		return( FALSE );
		}

	/* Check subtype-specific data */
	switch( deviceInfoPtr->type )
		{
		case CRYPT_DEVICE_NONE:
			{
			const SYSTEMDEV_INFO *systemInfo = deviceInfoPtr->deviceSystem;

			assert( isReadPtr( systemInfo, sizeof( SYSTEMDEV_INFO ) ) );

			/* Check the CSPRNG data */
			if( !DATAPTR_ISSET( systemInfo->randomInfo ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: CSPRNG data" ));
				return( FALSE );
				}

			/* Check the nonce RNG data */
			if( systemInfo->nonceDataInitialised == FALSE )
				{
				if( !isEmptyData( systemInfo->nonceData, 
								  systemInfo->nonceHashSize ) )
					{
					DEBUG_PUTS(( "sanityCheckDevice: Spurious nonce RNG data" ));
					return( FALSE );
					}
				}
			else
				{
				if( systemInfo->nonceDataInitialised != TRUE || \
					!rangeCheck( systemInfo->nonceHashSize,
								 MIN_HASHSIZE, CRYPT_MAX_HASHSIZE ) || \
					isEmptyData( systemInfo->nonceData, 
								 systemInfo->nonceHashSize ) )
					{
					DEBUG_PUTS(( "sanityCheckDevice: Nonce RNG data" ));
					return( FALSE );
					}
				}

			break;
			}

#ifdef USE_PKCS11
		case CRYPT_DEVICE_PKCS11:
			{
			const PKCS11_INFO *pkcs11Info = deviceInfoPtr->devicePKCS11;

			assert( isReadPtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );

			/* Check general device information */
			if( pkcs11Info->minPinSize != 0 || pkcs11Info->maxPinSize != 0 )
				{
				if( pkcs11Info->minPinSize < 4 || \
				    pkcs11Info->minPinSize > pkcs11Info->maxPinSize || \
					pkcs11Info->maxPinSize > CRYPT_MAX_TEXTSIZE )
					{
					DEBUG_PUTS(( "sanityCheckDevice: PIN size" ));
					return( FALSE );
					}
				}

 			/* Check device type-specific information */
			if( pkcs11Info->deviceNo < 0 || \
				pkcs11Info->deviceNo > 16 )
				{
				DEBUG_PUTS(( "sanityCheckDevice: Device number" ));
				return( FALSE );
				}
			if( !isEmptyData( pkcs11Info->defaultSSOPin, \
							  pkcs11Info->defaultSSOPinLen ) )
				{
				if( !rangeCheck( pkcs11Info->defaultSSOPinLen, 
								 0, CRYPT_MAX_TEXTSIZE ) )
					{
					DEBUG_PUTS(( "sanityCheckDevice: SSO PIN size" ));
					return( FALSE );
					}
				}

			break;
			}
#endif /* USE_PKCS11 */

#ifdef USE_TPM
		case CRYPT_DEVICE_TPM:
			{
			const TPM_INFO *tpmInfo = deviceInfoPtr->deviceTPM;

			assert( isReadPtr( tpmInfo, sizeof( TPM_INFO ) ) );

			if( deviceInfoPtr->iCryptKeyset != CRYPT_ERROR && \
				!isHandleRangeValid( deviceInfoPtr->iCryptKeyset ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: Keyset information" ));
				return( FALSE );
				}
			if( !DATAPTR_ISVALID( deviceInfoPtr->storageFunctions ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: Storage functions" ));
				return( FALSE );
				}
			if( !rangeCheck( tpmInfo->authValueEhLen, \
							 0, CRYPT_MAX_TEXTSIZE ) || \
				!rangeCheck( tpmInfo->authValueLockoutLen, \
							 0, CRYPT_MAX_TEXTSIZE ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: TPM info" ));
				return( FALSE );
				}
			break;
			}
#endif /* USE_TPM */

#ifdef USE_CRYPTOAPI
		case CRYPT_DEVICE_CRYPTOAPI:
			{
			const CRYPTOAPI_INFO *cryptoapiInfo = deviceInfoPtr->deviceCryptoAPI;

			assert( isReadPtr( cryptoapiInfo, sizeof( CRYPTOAPI_INFO ) ) );

			/* Nothing to check */

			break;
			}
#endif /* USE_CRYPTOAPI */

#ifdef USE_HARDWARE
		case CRYPT_DEVICE_HARDWARE:
			{
			const HARDWARE_INFO *hardwareInfo = deviceInfoPtr->deviceHardware;

			assert( isReadPtr( hardwareInfo, sizeof( HARDWARE_INFO ) ) );

			if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
				{
				if( hardwareInfo->isFileKeyset != FALSE || \
					hardwareInfo->discardData != FALSE )
					{
					DEBUG_PUTS(( "sanityCheckDevice: Spurious keyset information" ));
					return( FALSE );
					}
				}
			else
				{
				if( !isHandleRangeValid( deviceInfoPtr->iCryptKeyset ) || \
					( hardwareInfo->isFileKeyset != TRUE && \
					  hardwareInfo->isFileKeyset != FALSE ) || \
					( hardwareInfo->discardData != TRUE && \
					  hardwareInfo->discardData != FALSE ) )
					{
					DEBUG_PUTS(( "sanityCheckDevice: Keyset information" ));
					return( FALSE );
					}
				}
			if( !DATAPTR_ISVALID( deviceInfoPtr->storageFunctions ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: Storage functions" ));
				return( FALSE );
				}

			break;
			}
#endif /* USE_HARDWARE */

		default:
			retIntError_Boolean();
		}

	return( TRUE );
	}

/* Check that device function pointers have been set up correctly.  This is a
   setup check not related to sanityCheckDevice() */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkDeviceFunctions( IN_PTR const DEVICE_INFO *deviceInfoPtr )
	{
	assert( isReadPtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	if( !FNPTR_ISSET( deviceInfoPtr->initFunction ) || \
		!FNPTR_ISSET( deviceInfoPtr->controlFunction ) || \
		!FNPTR_ISSET( deviceInfoPtr->shutdownFunction ) )
		{
		DEBUG_PUTS(( "checkDeviceFunctions: General functions" ));
		return( FALSE );
		}
	if( deviceInfoPtr->objectHandle == SYSTEM_OBJECT_HANDLE )
		{
		if( !FNPTR_ISNULL( deviceInfoPtr->getItemFunction ) || \
			!FNPTR_ISNULL( deviceInfoPtr->setItemFunction ) || \
			!FNPTR_ISNULL( deviceInfoPtr->deleteItemFunction ) || \
			!FNPTR_ISNULL( deviceInfoPtr->getFirstItemFunction ) || \
			!FNPTR_ISNULL( deviceInfoPtr->getNextItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->getRandomFunction ) )
			{
			DEBUG_PUTS(( "checkDeviceFunctions: System device functions" ));
			return( FALSE );
			}
		}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	else
		{
		if( deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE )
			{
			if( !FNPTR_ISSET( deviceInfoPtr->getItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->setItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->deleteItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->getFirstItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->getNextItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->getRandomFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->catalogQueryFunction ) )
				{
				DEBUG_PUTS(( "checkDeviceFunctions: Crypto device functions" ));
				return( FALSE );
				}
			}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	else
		{
		if( !FNPTR_ISSET( deviceInfoPtr->getItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->setItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->deleteItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->getFirstItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->getNextItemFunction ) || \
			!FNPTR_ISVALID( deviceInfoPtr->getRandomFunction ) )
			{
			DEBUG_PUTS(( "checkDeviceFunctions: Device data access functions" ));
			return( FALSE );
			}
		}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	
	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Process a crypto mechanism message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 5 ) ) \
static int processMechanismMessage( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
									IN_MESSAGE const MESSAGE_TYPE action,
									IN_ENUM( MECHANISM ) \
										const MECHANISM_TYPE mechanism,
									INOUT_PTR void *mechanismInfo,
									INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	CRYPT_DEVICE localCryptDevice = deviceInfoPtr->objectHandle;
	const MECHANISM_FUNCTION_INFO *mechanismFunctions;
	MECHANISM_FUNCTION mechanismFunction = NULL;
	LOOP_INDEX i;
	int refCount, status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( messageExtInfo, sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isMechanismActionMessage( action ) );
	REQUIRES( isEnumRange( mechanism, MECHANISM ) );
	REQUIRES( mechanismInfo != NULL );

	/* Find the function to handle this action and mechanism */
	mechanismFunctions = DATAPTR_GET( deviceInfoPtr->mechanismFunctions );
	if( mechanismFunctions != NULL )
		{
		LOOP_LARGE( i = 0,
					i < deviceInfoPtr->mechanismFunctionCount && \
						mechanismFunctions[ i ].action != MESSAGE_NONE, 
					i++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE( i, 0, \
										   deviceInfoPtr->mechanismFunctionCount - 1 ) );
			if( mechanismFunctions[ i ].action == action && \
				mechanismFunctions[ i ].mechanism == mechanism )
				{
				mechanismFunction = mechanismFunctions[ i ].function;
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK );
		ENSURES( i < deviceInfoPtr->mechanismFunctionCount );
		}
	if( mechanismFunction == NULL && \
		localCryptDevice != SYSTEM_OBJECT_HANDLE )
		{
		/* This isn't the system object, fall back to the system object and 
		   see if it can handle the mechanism.  We do it this way rather 
		   than sending the message through the kernel a second time because 
		   all the kernel checking of message parameters has already been 
		   done, this saves the overhead of a second, redundant kernel pass.  
		   This code was only ever used with Fortezza devices, with PKCS #11 
		   devices the support for various mechanisms is too patchy to allow 
		   us to rely on it so we always use system mechanisms which we know 
		   will get it right.
		   
		   Because it should never be used in normal use, we throw an 
		   exception if we get here inadvertently.  If this doesn't stop 
		   execution then the krnlAcquireObject() will since it will refuse 
		   to allow access to the system object */
		assert( INTERNAL_ERROR );
		setMessageObjectUnlocked( messageExtInfo );
		status = krnlSuspendObject( deviceInfoPtr->objectHandle, &refCount );
		ENSURES( cryptStatusOK( status ) );
		localCryptDevice = SYSTEM_OBJECT_HANDLE;
		status = krnlAcquireObject( SYSTEM_OBJECT_HANDLE, /* Will always fail */
									OBJECT_TYPE_DEVICE,
									( MESSAGE_PTR_CAST ) &deviceInfoPtr,
									CRYPT_ERROR_SIGNALLED );
		if( cryptStatusError( status ) )
			return( status );
		REQUIRES_OBJECT( mechanismFunctions != NULL,
						 deviceInfoPtr->objectHandle );
		LOOP_LARGE( i = 0, 
					i < deviceInfoPtr->mechanismFunctionCount && \
						mechanismFunctions[ i ].action != MESSAGE_NONE,
					i++ )
			{
			ENSURES_OBJECT( \
				LOOP_INVARIANT_LARGE( i, 0, \
									  deviceInfoPtr->mechanismFunctionCount - 1 ),
				deviceInfoPtr->objectHandle );
			if( mechanismFunctions[ i ].action == action && \
				mechanismFunctions[ i ].mechanism == mechanism )
				{
				mechanismFunction = mechanismFunctions[ i ].function;
				break;
				}
			}
		ENSURES_OBJECT( LOOP_BOUND_OK, deviceInfoPtr->objectHandle );
		ENSURES_OBJECT( i < deviceInfoPtr->mechanismFunctionCount,
						deviceInfoPtr->objectHandle );

		/* If this code was used then we'd need to release the system object
		   if we exit beyond this point */
		}
	if( mechanismFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* If the message has been sent to the system object, unlock it to allow 
	   it to be used by others and dispatch the message.  This is safe 
	   because the auxInfo for the system device is in a static, read-only 
	   segment and persists even if the system device is destroyed */
	if( localCryptDevice == SYSTEM_OBJECT_HANDLE )
		{
		setMessageObjectUnlocked( messageExtInfo );
		status = krnlSuspendObject( SYSTEM_OBJECT_HANDLE, &refCount );
		ENSURES( cryptStatusOK( status ) );
		assert( ( mechanism >= MECHANISM_SELFTEST_ENC && \
				  mechanism <= MECHANISM_SELFTEST_KDF && \
				  refCount <= 2 ) || \
				refCount == 1 );
				/* The system object can send itself a recursive 
				   selftest mechanism message */
		return( mechanismFunction( NULL, mechanismInfo ) );
		}

	/* Send the message to the device */
	return( mechanismFunction( deviceInfoPtr, mechanismInfo ) );
	}

/****************************************************************************
*																			*
*								Self-test Functions							*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Perform the algorithm self-test.  This returns two status values, the 
   overall status of calling the function as the standard return value and
   the status of the algorithm tests as a by-reference parameter */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int algorithmSelfTest( INOUT_PTR DATAPTR *capabilityInfoListHeadPtr,
							  OUT_STATUS int *testStatus )
	{
	DATAPTR capabilityInfoListHead = *capabilityInfoListHeadPtr;
	LOOP_INDEX_PTR CAPABILITY_INFO_LIST *capabilityInfoListPtr;
	CAPABILITY_INFO_LIST *capabilityInfoListPrevPtr = NULL;
	CAPABILITY_INFO_LIST savedCapabilityInfoListData;
	BOOLEAN algoTested = FALSE;

	assert( isWritePtr( capabilityInfoListHeadPtr, sizeof( DATAPTR ) ) );
	assert( isWritePtr( testStatus, sizeof( int ) ) );

	/* Clear return value */
	*testStatus = CRYPT_OK;

	/* Test each available capability */
	LOOP_MED( capabilityInfoListPtr = DATAPTR_GET( capabilityInfoListHead ), 
			  capabilityInfoListPtr != NULL,
			  capabilityInfoListPtr = DATAPTR_GET( capabilityInfoListPtr->next ) )
		{
		const CAPABILITY_INFO *capabilityInfoPtr = \
					DATAPTR_GET( capabilityInfoListPtr->info );
		int localStatus;

		REQUIRES( capabilityInfoPtr != NULL );
		REQUIRES( sanityCheckCapability( capabilityInfoPtr ) );
		REQUIRES( capabilityInfoPtr->selfTestFunction != NULL );

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* Perform the self-test for this algorithm type */
		DEBUG_DIAG(( "Self-test: %s", capabilityInfoPtr->algoName ));
		localStatus = capabilityInfoPtr->selfTestFunction();
		if( cryptStatusError( localStatus ) )
			{
			/* The self-test failed, remember the status if it's the first 
			   failure */
			if( cryptStatusOK( *testStatus ) )
				*testStatus = localStatus;

			/* Disable the algorithm that failed.  Since this unlinks it 
			   from the capability list, we have to save a copy of the 
			   pre-unlinking capability information in order for 
			   DATAPTR_GET( ...->next ) to work, and then point the
			   capabilityInfoListPtr to this temporary copy to allow the 
			   loop to continue.

			   In addition since we're working on a copy of the DATAPTR we 
			   have to reflect the change back up to the original */
			savedCapabilityInfoListData = *capabilityInfoListPtr;
			deleteSingleListElement( capabilityInfoListHead, 
									 capabilityInfoListPrevPtr, 
									 capabilityInfoListPtr,
									 CAPABILITY_INFO_LIST );
			capabilityInfoListPtr = &savedCapabilityInfoListData;
			*capabilityInfoListHeadPtr = capabilityInfoListHead;
			DEBUG_DIAG(( "Algorithm %s failed self-test", 
						 capabilityInfoPtr->algoName ));
			}
		else
			{
			algoTested = TRUE;

			/* Remember the last successfully-tested capability */
			capabilityInfoListPrevPtr = capabilityInfoListPtr;
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( algoTested ? CRYPT_OK : CRYPT_ERROR_NOTFOUND );
	}

/* Perform the mechanism self-test.  This is performed in addition to the 
   algorithm tests if the user requests a test of all algorithms.  
   
   Only low-level mechanism functionality is tested since the high-level 
   tests either produce non-constant results that can't be checked against a 
   fixed value or require the creation of multiple contexts to hold keys.
   For example to check the key wrap mechanisms the order of operations
   would be:

	create PKC context;
	create conventional context;
	load key into conventional context;
	wrap conventional context using PKC context;
	destroy conventional context;
	create conventional context;
	unwrap conventional context using PKC context;
	destroy conventional context;
	destroy PKC context;

   requiring a PKC and two conventional contexts for each test */

/* Perform a self-test */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int selftestDevice( INOUT_PTR DEVICE_INFO *deviceInfo,
					INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	MECHANISM_WRAP_INFO pkcWrapMechanismInfo;
	MECHANISM_SIGN_INFO signMechanismInfo;
	MECHANISM_DERIVE_INFO deriveMechanismInfo;
	MECHANISM_KDF_INFO kdfMechanismInfo;
	int status, testStatus;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfo ) );

	/* Perform an algorithm self-test.  This returns two status values, the
	   status of calling the self-test function and the status of the tests
	   that were performed.  The function call may succeed (status == 
	   CRYPT_OK) but one of the tests performed by the function may have 
	   failed (testStatus != CRYPT_OK), so we have to exit on either type of
	   error */
	status = algorithmSelfTest( &deviceInfo->capabilityInfoList, 
								&testStatus );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptStatusError( testStatus ) )
		return( testStatus );

	/* Since the mechanism self-tests can be quite lengthy and require 
	   recursive handling of messages by the system object (without actually 
	   requiring access to the system object state), if we're using the 
	   system object for the self-tests then we unlock it before running the 
	   tests to avoid it becoming a bottleneck */
	if( deviceInfo->objectHandle == SYSTEM_OBJECT_HANDLE )
		{
		int refCount;

		status = krnlSuspendObject( SYSTEM_OBJECT_HANDLE, &refCount );
		if( cryptStatusError( status ) )
			return( status );
		setMessageObjectUnlocked( messageExtInfo );
		}
	
	/* Perform the mechanism self-tests */
	setMechanismWrapInfo( &pkcWrapMechanismInfo, NULL, 0, NULL, 0, 
						  CRYPT_UNUSED, CRYPT_UNUSED );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE,
							  IMESSAGE_DEV_EXPORT, &pkcWrapMechanismInfo,
							  MECHANISM_SELFTEST_ENC );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismSignInfo( &signMechanismInfo, NULL, 0, CRYPT_UNUSED, 
						  CRYPT_UNUSED, CRYPT_UNUSED );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE,
							  IMESSAGE_DEV_SIGN, &signMechanismInfo,
							  MECHANISM_SELFTEST_SIG );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismDeriveInfo( &deriveMechanismInfo, NULL, 0, NULL, 0, 0, 
							NULL, 0, 0 );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE,
							  IMESSAGE_DEV_DERIVE, &deriveMechanismInfo,
							  MECHANISM_SELFTEST_DERIVE );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismKDFInfo( &kdfMechanismInfo, CRYPT_UNUSED, CRYPT_UNUSED, 0, 
						 NULL, 0 );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE,
							  IMESSAGE_DEV_KDF, &kdfMechanismInfo,
							  MECHANISM_SELFTEST_KDF );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}
#endif /* CONFIG_NO_SELFTEST */

/****************************************************************************
*																			*
*							Object Creation Functions						*
*																			*
****************************************************************************/

/* Create an object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int createObject( DEVICE_INFO *deviceInfoPtr,
						 IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE objectType,
						 INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
						 INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	CRYPT_DEVICE iCryptDevice = deviceInfoPtr->objectHandle;
	const CREATEOBJECT_FUNCTION_INFO *createObjectFunctions;
	CREATEOBJECT_FUNCTION createObjectFunction = NULL;
	const void *auxInfo = NULL;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( createInfo, sizeof( MESSAGE_CREATEOBJECT_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( isEnumRange( objectType, OBJECT_TYPE ) );

	/* Find the function to handle this object */
	createObjectFunctions = DATAPTR_GET( deviceInfoPtr->createObjectFunctions );
	if( createObjectFunctions != NULL )
		{
		LOOP_INDEX i;
			
		LOOP_MED( i = 0,
				  i < deviceInfoPtr->createObjectFunctionCount && \
					createObjectFunctions[ i ].type != OBJECT_TYPE_NONE,
				  i++ )
			{
			ENSURES( LOOP_INVARIANT_MED( i, 0, \
									     deviceInfoPtr->createObjectFunctionCount - 1 ) );
			if( createObjectFunctions[ i ].type == objectType )
				{
				createObjectFunction  = createObjectFunctions[ i ].function;
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK );
		ENSURES( i < deviceInfoPtr->createObjectFunctionCount );
		}
	if( createObjectFunction  == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Get any auxiliary information that we may need to create the object */
	if( objectType == OBJECT_TYPE_CONTEXT )
		{
		auxInfo = DATAPTR_GET( deviceInfoPtr->capabilityInfoList );

		ENSURES( DATAPTR_ISVALID( deviceInfoPtr->capabilityInfoList ) );
		}

	/* If the message has been sent to the system object, unlock it to allow 
	   it to be used by others and dispatch the message.  This is safe 
	   because the auxInfo for the system device is in a static, read-only 
	   segment and persists even if the system device is destroyed */
	if( deviceInfoPtr->objectHandle == SYSTEM_OBJECT_HANDLE )
		{
		int refCount;

		setMessageObjectUnlocked( messageExtInfo );
		status = krnlSuspendObject( SYSTEM_OBJECT_HANDLE, &refCount );
		ENSURES( cryptStatusOK( status ) );
		assert( refCount == 1 );
		status = createObjectFunction( createInfo, auxInfo,
									   CREATEOBJECT_FLAG_NONE );
		}
	else
		{
		int objectFlags = CREATEOBJECT_FLAG_DUMMY;

		/* If we're being created via the crypto object as a substitute for 
		   the system object then we need to indicate this to ensure that 
		   some of the restrictions enforced for objects created in external 
		   crypto devices are bypassed */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		if( deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE )
			objectFlags |= CREATEOBJECT_FLAG_CRYPTOBJ;
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

		/* Create a dummy object, with all details handled by the device.
		   Unlike the system device we don't unlock the device information 
		   before we call the create object function because there may be 
		   auxiliary information held in the device object that we need in 
		   order to create the object.  This is OK since we're not tying up 
		   the system device but only some auxiliary crypto device */
		status = createObjectFunction( createInfo, auxInfo, objectFlags );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make the newly-created object a dependent object of the device */
	return( krnlSendMessage( createInfo->cryptHandle, IMESSAGE_SETDEPENDENT, 
							 ( MESSAGE_CAST ) &iCryptDevice, 
							 SETDEP_OPTION_INCREF ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int createObjectIndirect( DEVICE_INFO *deviceInfoPtr,
								 IN_ENUM( OBJECT_TYPE ) \
									const OBJECT_TYPE objectType,
								 INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
								 INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	const CRYPT_DEVICE iCryptDevice = deviceInfoPtr->objectHandle;
#ifdef USE_CERTIFICATES
	int refCount;
#endif /* USE_CERTIFICATES */
	int value, status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( createInfo, sizeof( MESSAGE_CREATEOBJECT_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( isEnumRange( objectType, OBJECT_TYPE ) );

	switch( objectType )
		{
#if defined( USE_CERTIFICATES ) 
		case OBJECT_TYPE_CERTIFICATE:
			/* The message has been sent to the system object, unlock it to 
			   allow it to be used by others and dispatch the message.  This 
			   is safe because the auxInfo for the system device is in a 
			   static, read-only segment and persists even if the system 
			   device is destroyed */
			ENSURES( iCryptDevice == SYSTEM_OBJECT_HANDLE );
			setMessageObjectUnlocked( messageExtInfo );
			status = krnlSuspendObject( SYSTEM_OBJECT_HANDLE, &refCount );
			ENSURES( cryptStatusOK( status ) );
			assert( refCount == 1 );
			status = createCertificateIndirect( createInfo, NULL, 0 );
			break;
#endif /* USE_CERTIFICATES */

#if defined( USE_KEYSETS ) && \
	( defined( USE_HARDWARE ) || defined( USE_TPM ) )
		case OBJECT_TYPE_KEYSET:
			ENSURES( iCryptDevice == CRYPTO_OBJECT_HANDLE );
			status = createKeysetIndirect( createInfo, NULL, 0 );
			break;
#endif /* USE_KEYSETS && ( USE_HARDWARE || USE_TPM ) */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make the newly-created object a dependent object of the device.  
	   There's one special-case situation where we don't do this and that's 
	   when we're importing a certificate chain, which is a collection of 
	   individual certificate objects each of which have already been made 
	   dependent on the device.  We could detect this in one of two ways, 
	   either implicitly by reading the CRYPT_IATTRIBUTE_SUBTYPE attribute 
	   and assuming that if it's a SUBTYPE_CERT_CERTCHAIN that the owner 
	   will have been set, or simply by reading the depending user object.  
	   Explcitly checking for ownership seems to be the best approach */
	status = krnlSendMessage( createInfo->cryptHandle, 
							  IMESSAGE_GETDEPENDENT, &value, 
							  OBJECT_TYPE_USER );
	if( cryptStatusOK( status ) )
		{
		/* The object is already owned, don't try and set an owner */
		return( CRYPT_OK );
		}
	return( krnlSendMessage( createInfo->cryptHandle, IMESSAGE_SETDEPENDENT, 
							 ( MESSAGE_CAST ) &iCryptDevice, 
							 SETDEP_OPTION_INCREF ) );
	}

/****************************************************************************
*																			*
*								Device API Functions						*
*																			*
****************************************************************************/

/* Default object creation routines used when the device code doesn't set
   anything up */

static const CREATEOBJECT_FUNCTION_INFO defaultCreateFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext },
	{ OBJECT_TYPE_NONE, NULL }
	};

/* Handle a message sent to a device object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int deviceMessageFunction( INOUT_PTR TYPECAST( MESSAGE_FUNCTION_EXTINFO * ) \
									void *objectInfoPtr,
								  IN_MESSAGE const MESSAGE_TYPE message,
								  void *messageDataPtr,
								  IN_INT_SHORT_Z const int messageValue )
	{
	MESSAGE_FUNCTION_EXTINFO *messageExtInfo = \
						( MESSAGE_FUNCTION_EXTINFO * ) objectInfoPtr;
	DEVICE_INFO *deviceInfoPtr = \
						( DEVICE_INFO * ) messageExtInfo->objectInfoPtr;

	assert( isWritePtr( objectInfoPtr, sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( message == MESSAGE_DESTROY || \
			  sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isEnumRange( message, MESSAGE ) );
	REQUIRES( isShortIntegerRange( messageValue ) );

	/* Process the destroy object message */
	if( message == MESSAGE_DESTROY )
		{
		/* Shut down the device if required */
		if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE ) )
			{
			const DEV_SHUTDOWNFUNCTION shutdownFunction = \
						( DEV_SHUTDOWNFUNCTION ) \
						FNPTR_GET( deviceInfoPtr->shutdownFunction );

			if( shutdownFunction != NULL )
				shutdownFunction( deviceInfoPtr );
			}

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		REQUIRES( message == MESSAGE_GETATTRIBUTE || \
				  message == MESSAGE_GETATTRIBUTE_S || \
				  message == MESSAGE_SETATTRIBUTE || \
				  message == MESSAGE_SETATTRIBUTE_S );
		REQUIRES( isAttribute( messageValue ) || \
				  isInternalAttribute( messageValue ) );

		if( message == MESSAGE_GETATTRIBUTE )
			{
			return( getDeviceAttribute( deviceInfoPtr, 
										( int * ) messageDataPtr,
										messageValue, messageExtInfo ) );
			}
		if( message == MESSAGE_GETATTRIBUTE_S )
			{
			return( getDeviceAttributeS( deviceInfoPtr, 
										 ( MESSAGE_DATA * ) messageDataPtr,
										 messageValue, messageExtInfo ) );
			}
		if( message == MESSAGE_SETATTRIBUTE )
			{
			/* CRYPT_IATTRIBUTE_INITIALISED is purely a notification message 
			   with no parameters so we don't pass it down to the attribute-
			   handling code */
			if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
				return( CRYPT_OK );

			return( setDeviceAttribute( deviceInfoPtr, 
										 *( ( int * ) messageDataPtr ),
										 messageValue, messageExtInfo ) );
			}
		if( message == MESSAGE_SETATTRIBUTE_S )
			{
			const MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) messageDataPtr;

			return( setDeviceAttributeS( deviceInfoPtr, msgData->data, 
										 msgData->length, messageValue,
										 messageExtInfo ) );
			}

		retIntError();
		}

	/* Process action messages */
	if( isMechanismActionMessage( message ) )
		{
		return( processMechanismMessage( deviceInfoPtr, message, 
										 messageValue, messageDataPtr, 
										 messageExtInfo ) );
		}

	/* Process messages that check a device */
	if( message == MESSAGE_CHECK )
		{
		/* The check for whether this device type can contain an object that
		   can perform the requested operation has already been performed by
		   the kernel so there's nothing further to do here */
		REQUIRES( deviceInfoPtr->type == CRYPT_DEVICE_PKCS11 || \
				  deviceInfoPtr->type == CRYPT_DEVICE_CRYPTOAPI || \
				  deviceInfoPtr->type == CRYPT_DEVICE_TPM || \
				  deviceInfoPtr->type == CRYPT_DEVICE_HARDWARE );
		REQUIRES( messageValue == MESSAGE_CHECK_PKC_ENCRYPT_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_DECRYPT_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_SIGCHECK_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_SIGN_AVAIL );

		return( CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == MESSAGE_SELFTEST )
		{
		const DEV_SELFTESTFUNCTION selftestFunction = \
					( DEV_SELFTESTFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->selftestFunction );

		/* If the device doesn't have a self-test capability then there's 
		   not much that we can do */
		if( selftestFunction == NULL )
			return( CRYPT_OK );

		return( selftestFunction( deviceInfoPtr, messageExtInfo ) );
		}
	if( message == MESSAGE_KEY_GETKEY )
		{
		const DEV_GETITEMFUNCTION getItemFunction = \
					( DEV_GETITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->getItemFunction );
		MESSAGE_KEYMGMT_INFO *getkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( getItemFunction != NULL );

		/* Create a context or certificate via an object in the device */
		return( getItemFunction( deviceInfoPtr,
								 &getkeyInfo->cryptHandle, messageValue,
								 getkeyInfo->keyIDtype, getkeyInfo->keyID,
								 getkeyInfo->keyIDlength, getkeyInfo->auxInfo,
								 &getkeyInfo->auxInfoLength,
								 getkeyInfo->flags ) );
		}
	if( message == MESSAGE_KEY_SETKEY )
		{
		const DEV_SETITEMFUNCTION setItemFunction = \
					( DEV_SETITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->setItemFunction );
		MESSAGE_KEYMGMT_INFO *setkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( setItemFunction != NULL );

		/* Update the device with the certificate */
		return( setItemFunction( deviceInfoPtr, setkeyInfo->cryptHandle ) );
		}
	if( message == MESSAGE_KEY_DELETEKEY )
		{
		const DEV_DELETEITEMFUNCTION deleteItemFunction = \
					( DEV_DELETEITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->deleteItemFunction );
		MESSAGE_KEYMGMT_INFO *deletekeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( deleteItemFunction != NULL );

		/* Delete an object in the device */
		return( deleteItemFunction( deviceInfoPtr, messageValue, 
									deletekeyInfo->keyIDtype, 
									deletekeyInfo->keyID, 
									deletekeyInfo->keyIDlength ) );
		}
	if( message == MESSAGE_KEY_GETFIRSTCERT )
		{
		const DEV_GETFIRSTITEMFUNCTION getFirstItemFunction = \
					( DEV_GETFIRSTITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->getFirstItemFunction );
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( getFirstItemFunction != NULL );
		REQUIRES( getnextcertInfo->auxInfoLength == sizeof( int ) );
		REQUIRES( messageValue == KEYMGMT_ITEM_PUBLICKEY );

		/* Fetch a certificate in a certificate chain from the device */
		return( getFirstItemFunction( deviceInfoPtr, 
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->keyIDtype, getnextcertInfo->keyID,
						getnextcertInfo->keyIDlength, messageValue,
						getnextcertInfo->flags ) );
		}
	if( message == MESSAGE_KEY_GETNEXTCERT )
		{
		const DEV_GETNEXTITEMFUNCTION getNextItemFunction = \
					( DEV_GETNEXTITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->getNextItemFunction );
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( getNextItemFunction != NULL );
		REQUIRES( getnextcertInfo->auxInfoLength == sizeof( int ) );

		/* Fetch a certificate in a certificate chain from the device */
		return( getNextItemFunction( deviceInfoPtr,
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->flags ) );
		}
	if( message == MESSAGE_DEV_QUERYCAPABILITY )
		{
		const CAPABILITY_INFO_LIST *capabilityInfoListPtr = \
				DATAPTR_GET( deviceInfoPtr->capabilityInfoList );
		const void *capabilityInfoPtr;
		CRYPT_QUERY_INFO *queryInfo = ( CRYPT_QUERY_INFO * ) messageDataPtr;

		REQUIRES( capabilityInfoListPtr != NULL );

		/* Find the information for this algorithm and return an appropriate
		   subset of it to the caller */
		capabilityInfoPtr = findCapabilityInfo( capabilityInfoListPtr, 
												messageValue );
		if( capabilityInfoPtr == NULL )
			return( CRYPT_ERROR_NOTAVAIL );
		getCapabilityInfo( queryInfo, capabilityInfoPtr );

		return( CRYPT_OK );
		}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( message == MESSAGE_DEV_CATALOGQUERY )
		{
		const DEV_CATALOGQUERYFUNCTION catalogQueryFunction = \
					( DEV_CATALOGQUERYFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->catalogQueryFunction );
		MESSAGE_CATALOGQUERY_INFO *queryInfo = \
							( MESSAGE_CATALOGQUERY_INFO * ) messageDataPtr;

		REQUIRES( catalogQueryFunction != NULL );

		return( catalogQueryFunction( deviceInfoPtr, queryInfo, 
									  messageValue ) );
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	if( message == MESSAGE_DEV_CREATEOBJECT )
		{
		/* If the device can't have objects created within it, complain */
		if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_READONLY ) )
			return( CRYPT_ERROR_PERMISSION );

		return( createObject( deviceInfoPtr, messageValue, messageDataPtr,
							  messageExtInfo ) );
		}
	if( message == MESSAGE_DEV_CREATEOBJECT_INDIRECT )
		{
		/* If the device can't have objects created within it, complain */
		if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_READONLY ) )
			return( CRYPT_ERROR_PERMISSION );

		return( createObjectIndirect( deviceInfoPtr, messageValue, 
									  messageDataPtr, messageExtInfo ) );
		}

	retIntError();
	}

/* Open a device.  This is a common function called to create both the
   internal system device object and optional crypto object, and general 
   devices */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int openDevice( OUT_HANDLE_OPT CRYPT_DEVICE *iCryptDevice,
					   IN_HANDLE_OPT const CRYPT_USER iCryptOwner,
					   IN_ENUM_OPT( CRYPT_DEVICE ) \
							const CRYPT_DEVICE_TYPE deviceType,
					   IN_BUFFER_OPT( nameLength ) const char *name, 
					   IN_LENGTH_TEXT_Z const int nameLength,
					   OUT_PTR_PTR_OPT DEVICE_INFO **deviceInfoPtrPtr )
	{
	DEVICE_INFO *deviceInfoPtr;
	DEV_INITFUNCTION initFunction;
	OBJECT_SUBTYPE subType;
	static const MAP_TABLE subtypeMapTbl[] = {
		{ CRYPT_DEVICE_NONE, SUBTYPE_DEV_SYSTEM },
#ifdef USE_PKCS11
		{ CRYPT_DEVICE_PKCS11, SUBTYPE_DEV_PKCS11 },
#endif /* USE_PKCS11 */
#ifdef USE_TPM
		{ CRYPT_DEVICE_TPM, SUBTYPE_DEV_TPM },
#endif /* USE_TPM */
#ifdef USE_CRYPTOAPI
		{ CRYPT_DEVICE_CRYPTOAPI, SUBTYPE_DEV_CRYPTOAPI },
#endif /* USE_CRYPTOAPI */
#ifdef USE_HARDWARE
		{ CRYPT_DEVICE_HARDWARE, SUBTYPE_DEV_HARDWARE },
#endif /* USE_HARDWARE */
		{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
		};
	int value, storageSize, status;

	assert( isWritePtr( iCryptDevice, sizeof( CRYPT_DEVICE ) ) );
	assert( ( name == NULL && nameLength == 0 ) || \
			( isReadPtrDynamic( name, nameLength ) ) );
	assert( isWritePtr( deviceInfoPtrPtr, sizeof( DEVICE_INFO * ) ) );

	REQUIRES( ( deviceType == CRYPT_DEVICE_NONE && \
				iCryptOwner == CRYPT_UNUSED ) || \
			  ( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE ) || \
			  isHandleRangeValid( iCryptOwner ) );
	REQUIRES( isEnumRangeOpt( deviceType, CRYPT_DEVICE ) );
	REQUIRES( ( name == NULL && nameLength == 0 ) || \
			  ( name != NULL && \
			    nameLength >= MIN_NAME_LENGTH && \
				nameLength <= CRYPT_MAX_TEXTSIZE ) );

	/* Clear return values */
	*iCryptDevice = CRYPT_ERROR;
	*deviceInfoPtrPtr = NULL;

	/* Set up subtype-specific information */
	status = mapValue( deviceType, &value, subtypeMapTbl, 
					   FAILSAFE_ARRAYSIZE( subtypeMapTbl, MAP_TABLE ) );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_NOTAVAIL );
	subType = value;
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			storageSize = sizeof( SYSTEMDEV_INFO );
			break;

#ifdef USE_PKCS11
		case CRYPT_DEVICE_PKCS11:
			storageSize = sizeof( PKCS11_INFO );
			break;
#endif /* USE_PKCS11 */

#ifdef USE_TPM
		case CRYPT_DEVICE_TPM:
			storageSize = sizeof( TPM_INFO );
			break;
#endif /* USE_TPM */

#ifdef USE_CRYPTOAPI
		case CRYPT_DEVICE_CRYPTOAPI:
			storageSize = sizeof( CRYPTOAPI_INFO );
			break;
#endif /* USE_CRYPTOAPI */

#ifdef USE_HARDWARE
		case CRYPT_DEVICE_HARDWARE:
			storageSize = sizeof( HARDWARE_INFO );
			break;
#endif /* USE_HARDWARE */

		default:
			retIntError();
		}

	/* Create the device object and connect it to the device */
	status = krnlCreateObject( iCryptDevice, ( void ** ) &deviceInfoPtr,
							   sizeof( DEVICE_INFO ) + storageSize,
							   OBJECT_TYPE_DEVICE, subType,
							   CREATEOBJECT_FLAG_NONE, iCryptOwner,
							   ACTION_PERM_NONE_ALL, deviceMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( deviceInfoPtr != NULL );
	*deviceInfoPtrPtr = deviceInfoPtr;
	deviceInfoPtr->objectHandle = *iCryptDevice;
	deviceInfoPtr->ownerHandle = iCryptOwner;
	INIT_FLAGS( deviceInfoPtr->flags, DEVICE_FLAG_NONE );
	deviceInfoPtr->type = deviceType;
#if defined( USE_HARDWARE ) || defined( USE_TPM )
	deviceInfoPtr->iCryptKeyset = CRYPT_ERROR;
	DATAPTR_SET( deviceInfoPtr->storageFunctions, NULL );
#endif /* USE_HARDWARE || USE_TPM */
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			deviceInfoPtr->deviceSystem = \
							( SYSTEMDEV_INFO * ) deviceInfoPtr->storage;
			break;

#ifdef USE_PKCS11
		case CRYPT_DEVICE_PKCS11:
			deviceInfoPtr->devicePKCS11 = \
							( PKCS11_INFO * ) deviceInfoPtr->storage;
			break;
#endif /* USE_PKCS11 */

#ifdef USE_TPM
		case CRYPT_DEVICE_TPM:
			deviceInfoPtr->deviceTPM = \
							( TPM_INFO * ) deviceInfoPtr->storage;
			break;
#endif /* USE_TPM */

#ifdef USE_CRYPTOAPI
		case CRYPT_DEVICE_CRYPTOAPI:
			deviceInfoPtr->deviceCryptoAPI = \
							( CRYPTOAPI_INFO * ) deviceInfoPtr->storage;
			break;
#endif /* USE_CRYPTOAPI */

#ifdef USE_HARDWARE
		case CRYPT_DEVICE_HARDWARE:
			deviceInfoPtr->deviceHardware = \
							( HARDWARE_INFO * ) deviceInfoPtr->storage;
			break;
#endif /* USE_HARDWARE */

		default:
			retIntError();
		}
	deviceInfoPtr->storageSize = storageSize;

	/* Sanity check to make sure that the all-important system device is as 
	   it's supposed to be.  krnlCreateObject() doesn't allow creation of a
	   second system object but this is a secondary check of the types and 
	   subtypes used in this function */
	ENSURES( ( deviceType == CRYPT_DEVICE_NONE && \
			   subType == SUBTYPE_DEV_SYSTEM && \
			   *iCryptDevice == SYSTEM_OBJECT_HANDLE ) || \
			 ( deviceType != CRYPT_DEVICE_NONE && \
			   subType != SUBTYPE_DEV_SYSTEM && \
			   *iCryptDevice != SYSTEM_OBJECT_HANDLE ) );

	/* Set up access information for the device */
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			status = setDeviceSystem( deviceInfoPtr );
			break;

#ifdef USE_PKCS11
		case CRYPT_DEVICE_PKCS11:
			ENSURES( name != NULL && \
					 nameLength >= MIN_NAME_LENGTH && \
					 nameLength <= CRYPT_MAX_TEXTSIZE );
			status = setDevicePKCS11( deviceInfoPtr, name, nameLength );
			break;
#endif /* USE_PKCS11 */

#ifdef USE_TPM
		case CRYPT_DEVICE_TPM:
			status = setDeviceTPM( deviceInfoPtr );
			break;
#endif /* USE_TPM */

#ifdef USE_CRYPTOAPI
		case CRYPT_DEVICE_CRYPTOAPI:
			status = setDeviceCryptoAPI( deviceInfoPtr );
			break;
#endif /* USE_CRYPTOAPI */

#ifdef USE_HARDWARE
		case CRYPT_DEVICE_HARDWARE:
			status = setDeviceHardware( deviceInfoPtr );
			break;
#endif /* USE_HARDWARE */

		default:
			retIntError();
		}
	if( cryptStatusOK( status ) && \
		DATAPTR_GET( deviceInfoPtr->createObjectFunctions ) == NULL )
		{
		/* The device-specific code hasn't set up anything, use the default
		   create-object functions, which just creates encryption contexts
		   using the device capability information */
		DATAPTR_SET( deviceInfoPtr->createObjectFunctions, 
					 ( void * ) defaultCreateFunctions );
		deviceInfoPtr->createObjectFunctionCount = \
							FAILSAFE_ARRAYSIZE( defaultCreateFunctions, \
												CREATEOBJECT_FUNCTION_INFO );
		}
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( checkDeviceFunctions( deviceInfoPtr ) );

	/* Connect to the device */
	initFunction = ( DEV_INITFUNCTION ) \
				   FNPTR_GET( deviceInfoPtr->initFunction );
	REQUIRES( initFunction != NULL );
	status = initFunction( deviceInfoPtr, name, nameLength );
	if( cryptStatusError( status ) )
		{
		/* Since this function is called on object creation, if it fails 
		   there's no object to get extended error information from so we 
		   dump the error information as a diagnostic for debugging 
		   purposes */
#ifdef USE_PKCS11
		if( deviceType == CRYPT_DEVICE_PKCS11 )
			{
			DEBUG_DIAG_ERRMSG(( "PKCS #11 device open failed, status %s, error "
								"string:\n  '%s'", getStatusName( status ),
								getErrorInfoString( DEVICE_ERRINFO ) ));
			}
#endif /* USE_PKCS11 */
#ifdef USE_TPM
		if( deviceType == CRYPT_DEVICE_TPM )
			{
			DEBUG_DIAG_ERRMSG(( "TPM device open failed, status %s, error "
								"string:\n  '%s'", getStatusName( status ),
								getErrorInfoString( DEVICE_ERRINFO ) ));
			}
#endif /* USE_TPM */
#ifdef USE_HARDWARE
		if( deviceType == CRYPT_DEVICE_HARDWARE )
			{
			DEBUG_DIAG_ERRMSG(( "Hardware device open failed, status %s, error "
								"string:\n  '%s'", getStatusName( status ),
								getErrorInfoString( DEVICE_ERRINFO ) ));
			}
#endif /* USE_HARDWARE */
		return( status );
		}

	return( CRYPT_OK );
	}

/* Create a (non-system) device object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createDevice( INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
				  STDC_UNUSED const void *auxDataPtr, 
				  STDC_UNUSED const int auxValue )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfoPtr = NULL;
	int initStatus, status;

	assert( isWritePtr( createInfo, sizeof( MESSAGE_CREATEOBJECT_INFO ) ) );

	REQUIRES( auxDataPtr == NULL && auxValue == 0 );
	REQUIRES( isEnumRange( createInfo->arg1, CRYPT_DEVICE ) );
	REQUIRES( ( ( createInfo->arg1 == CRYPT_DEVICE_PKCS11 || \
				  createInfo->arg1 == CRYPT_DEVICE_CRYPTOAPI ) && \
				createInfo->strArg1 != NULL && \
				createInfo->strArgLen1 >= MIN_NAME_LENGTH && \
				createInfo->strArgLen1 <= CRYPT_MAX_TEXTSIZE ) || \
			  ( createInfo->arg1 != CRYPT_DEVICE_PKCS11 && \
				createInfo->arg1 != CRYPT_DEVICE_CRYPTOAPI && \
				createInfo->strArg1 == NULL && \
				createInfo->strArgLen1 == 0 ) );

	/* Wait for any async device driver binding to complete */
	if( !krnlWaitSemaphore( SEMAPHORE_DRIVERBIND ) )
		{
		/* The kernel is shutting down, bail out */
		DEBUG_DIAG(( "Exiting due to kernel shutdown" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Pass the call on to the lower-level open function */
	initStatus = openDevice( &iCryptDevice, createInfo->cryptOwner,
							 createInfo->arg1, createInfo->strArg1,
							 createInfo->strArgLen1, &deviceInfoPtr );
	if( cryptStatusError( initStatus ) )
		{
		/* If the create object failed, return immediately */
		if( deviceInfoPtr == NULL )
			return( initStatus );

		/* The init failed, make sure that the object gets destroyed when we
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptDevice, IMESSAGE_DESTROY );
		}

	/* We've finished setting up the object-type-specific information, tell 
	   the kernel that the object is ready for use */
	status = krnlSendMessage( iCryptDevice, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusOK( status ) && \
		createInfo->arg1 == CRYPT_DEVICE_CRYPTOAPI )
		{
		/* If it's a device that doesn't require an explicit login, move it
		   into the initialised state */
		status = krnlSendMessage( iCryptDevice, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_UNUSED,
								  CRYPT_IATTRIBUTE_INITIALISED );
		if( cryptStatusError( status ) )
			krnlSendNotifier( iCryptDevice, IMESSAGE_DESTROY );
		}
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptDevice;

	return( CRYPT_OK );
	}

/* Create the internal system device object.  This is somewhat special in
   that it can't be destroyed through a normal message (it can only be done
   from one place in the kernel) so if the open fails then we don't use the 
   normal signalling mechanism to destroy it but simply return an error code 
   to the caller (the cryptlib init process).  This causes the init to fail 
   and destroys the object when the kernel shuts down */

CHECK_RETVAL \
static int createSystemDeviceObject( void )
	{
	CRYPT_DEVICE iSystemObject;
	DEVICE_INFO *deviceInfoPtr;
	int initStatus, status;

	/* Pass the call on to the lower-level open function.  This device is
	   unique and has no owner or type.

	   Normally if an object init fails then we tell the kernel to destroy 
	   it by sending it a destroy message, which is processed after the 
	   object's status has been set to normal.  However we don't have the 
	   privileges to do this for the system object (or the default user 
	   object) so we just pass the error code back to the caller, which 
	   causes the cryptlib init to fail.
	   
	   In addition the init can fail in one of two ways, the object isn't
	   even created (deviceInfoPtr == NULL, nothing to clean up) in which 
	   case we bail out immediately, or the object is created but wasn't set 
	   up properly (deviceInfoPtr is allocated, but the object can't be 
	   used) in which case we bail out after we update its status.

	   A failure at this point is a bit problematic because it's not 
	   possible to inform the caller that the system object was successfully 
	   created but something went wrong after that.  That is, it's assumed
	   that create-object operations are atomic so that a failure status
	   indicates that all allocations and whatnot were rolled back, but 
	   since the system object can only be destroyed from within the kernel
	   once it's been created there's no way to roll back the creation of an
	   incomplete system object.  In fact it's not even clear what *could* 
	   cause a failure at this point apart from "circumstances beyond our 
	   control" (memory corruption, a coding error, or something similar).  
	   Because this is a can't-occur situation the best course of action for 
	   backing out of having a partially-initialised system object that's 
	   created at, and exists at, a level below what the standard system 
	   cleanup routines can handle is uncertain.
	   
	   At the moment we just exit.  This is somewhat ugly, but it's not 
	   really clear what other action we can take in the error handler for a 
	   can-never-occur error */
	initStatus = openDevice( &iSystemObject, CRYPT_UNUSED, CRYPT_DEVICE_NONE,
							 NULL, 0, &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	ENSURES( iSystemObject == SYSTEM_OBJECT_HANDLE );

	/* We've finished setting up the object-type-specific information, tell 
	   the kernel that the object is ready for use */
	status = krnlSendMessage( iSystemObject, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );

	/* The object has been initialised, move it into the initialised state */
	return( krnlSendMessage( iSystemObject, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_UNUSED,
							 CRYPT_IATTRIBUTE_INITIALISED ) );
	}

/* Create the crypto device object */

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )

CHECK_RETVAL \
static int createCryptoDeviceObject( void )
	{
	CRYPT_DEVICE iCryptoDeviceObject;
	DEVICE_INFO *deviceInfoPtr;
	int initStatus, status;

	/* Pass the call on to the lower-level function.  See the comments for 
	   createSystemDeviceObject() for error handling */
	initStatus = openDevice( &iCryptoDeviceObject, 
							 DEFAULTUSER_OBJECT_HANDLE, CRYPT_DEVICE_HARDWARE, 
							 NULL, 0, &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	ENSURES( iCryptoDeviceObject == CRYPTO_OBJECT_HANDLE );

	/* We've finished setting up the object-type-specific information, tell 
	   the kernel that the object is ready for use */
	status = krnlSendMessage( iCryptoDeviceObject, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );

	/* Exit without moving the object into the initialised state as we would
	   for other objects because it's created before the system 
	   initialisation has completed and so isn't completely initialised 
	   until the CRYPT_IATTRIBUTE_COMPLETEINIT attribute is explicitly set 
	   for it */
	return( CRYPT_OK );
	}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

/* Generic management function for this class of object.  Unlike the usual
   multilevel init process which is followed for other objects, the devices
   have an OR rather than an AND relationship since the devices are
   logically independent so we set a flag for each device type that's
   successfully initialised rather than recording an init level */

typedef CHECK_RETVAL int ( *DEVICEINIT_FUNCTION )( void );
typedef void ( *DEVICEND_FUNCTION )( void );
typedef struct {
	const DEVICEINIT_FUNCTION deviceInitFunction;
	const DEVICEND_FUNCTION deviceEndFunction;
	const int initFlag;
	} DEVICEINIT_INFO;
		
#define DEV_NONE_INITED			0x00
#define DEV_PKCS11_INITED		0x01
#define DEV_CRYPTOAPI_INITED	0x02
#define DEV_TPM_INITED			0x04
#define DEV_HARDWARE_INITED		0x08

CHECK_RETVAL \
int deviceManagementFunction( IN_ENUM( MANAGEMENT_ACTION ) \
								const MANAGEMENT_ACTION_TYPE action )
	{
	static const DEVICEINIT_INFO deviceInitTbl[] = {
#ifdef USE_PKCS11
		{ deviceInitPKCS11, deviceEndPKCS11, DEV_PKCS11_INITED },
#endif /* USE_PKCS11 */
#ifdef USE_TPM
		{ deviceInitTPM, deviceEndTPM, DEV_TPM_INITED },
#endif /* USE_TPM */
#ifdef USE_CRYPTOAPI
		{ deviceInitCryptoAPI, deviceEndCryptoAPI, DEV_CRYPTOAPI_INITED },
#endif /* USE_CRYPTOAPI */
#ifdef USE_HARDWARE 
  #if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		{ NULL, deviceEndHardware, DEV_HARDWARE_INITED },
  #else
		{ deviceInitHardware, deviceEndHardware, DEV_HARDWARE_INITED },
  #endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
#endif /* USE_HARDWARE */
		{ NULL, NULL, 0 }, { NULL, NULL, 0 }
		};
	static int initFlags = DEV_NONE_INITED;
	LOOP_INDEX i;
	int status;

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	REQUIRES( action == MANAGEMENT_ACTION_PRE_INIT || \
			  action == MANAGEMENT_ACTION_INIT || \
			  action == MANAGEMENT_ACTION_INIT_DEFERRED || \
			  action == MANAGEMENT_ACTION_PRE_SHUTDOWN || \
			  action == MANAGEMENT_ACTION_SHUTDOWN );
#else
	REQUIRES( action == MANAGEMENT_ACTION_PRE_INIT || \
			  action == MANAGEMENT_ACTION_INIT_DEFERRED || \
			  action == MANAGEMENT_ACTION_PRE_SHUTDOWN || \
			  action == MANAGEMENT_ACTION_SHUTDOWN );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	switch( action )
		{
		case MANAGEMENT_ACTION_PRE_INIT:
			initFlags = DEV_NONE_INITED;
			status = createSystemDeviceObject();
			if( cryptStatusError( status ) )
				{ 
				DEBUG_DIAG(( "System object creation failed" )); 
				return( status );
				}
			DEBUG_DIAG(( "Created system object" )); 
			return( CRYPT_OK );

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		case MANAGEMENT_ACTION_INIT:
			/* Since we're using the hardware device to provide our crypto
			   capabilities we need to initialise it now, not during the
			   deferred-init stage */
			status = deviceInitHardware();
			if( cryptStatusError( status ) )
				{
				DEBUG_DIAG(( "Crypto hardware initialisation failed" ));
				return( status );
				}
			initFlags |= DEV_HARDWARE_INITED;
			status = createCryptoDeviceObject();
			if( cryptStatusError( status ) )
				{ 
				DEBUG_DIAG(( "Crypto object creation failed" )); 
				return( status );
				}
			DEBUG_DIAG(( "Created crypto object" )); 
			return( CRYPT_OK );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

		case MANAGEMENT_ACTION_INIT_DEFERRED:
#ifndef CONFIG_FUZZ
			LOOP_SMALL( i = 0,
						i < FAILSAFE_ARRAYSIZE( deviceInitTbl, \
												DEVICEINIT_INFO ) && \
							deviceInitTbl[ i ].deviceInitFunction != NULL,
						i++ )
				{
				ENSURES( LOOP_INVARIANT_SMALL( i, 0, \
											   FAILSAFE_ARRAYSIZE( deviceInitTbl, \
																   DEVICEINIT_INFO ) - 1 ) );
				if( krnlIsExiting() )
					{
					/* The kernel is shutting down, exit */
					return( CRYPT_ERROR_PERMISSION );
					}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
				if( deviceInitTbl[ i ].deviceInitFunction == NULL )
					{
					/* If we're using the hardware device to provide our 
					   crypto capabilities then it'll already have been
					   initialised as an init action */
					continue;
					}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
				status = deviceInitTbl[ i ].deviceInitFunction();
				if( cryptStatusOK( status ) )
					initFlags |= deviceInitTbl[ i ].initFlag;
				}
			ENSURES( LOOP_BOUND_OK );
			ENSURES( i < FAILSAFE_ARRAYSIZE( deviceInitTbl, \
											 DEVICEINIT_INFO ) );
#endif /* !CONFIG_FUZZ */
			return( CRYPT_OK );

		case MANAGEMENT_ACTION_PRE_SHUTDOWN:
			/* In theory we could signal the background entropy poll to 
			   start wrapping up at this point, however if the background 
			   polling is being performed in a thread or task then the 
			   shutdown is already signalled via the kernel shutdown flag.  
			   If it's performed by forking off a process, as it is on Unix 
			   systems, there's no easy way to communicate with this process 
			   so the shutdown function just kill()s it.  Because of this we 
			   don't try and do anything here, although this call is left in 
			   place as a no-op in case it's needed in the future */
			return( CRYPT_OK );

		case MANAGEMENT_ACTION_SHUTDOWN:
			LOOP_MED( i = 0,
					  i < FAILSAFE_ARRAYSIZE( deviceInitTbl, \
											  DEVICEINIT_INFO ) && \
						  deviceInitTbl[ i ].deviceEndFunction != NULL,
					  i++ )
				{
				ENSURES( LOOP_INVARIANT_MED( i, 0, \
											 FAILSAFE_ARRAYSIZE( deviceInitTbl, \
																 DEVICEINIT_INFO ) - 1 ) );
				if( initFlags & deviceInitTbl[ i ].initFlag )
					deviceInitTbl[ i ].deviceEndFunction();
				}
			ENSURES( LOOP_BOUND_OK );
			ENSURES( i < FAILSAFE_ARRAYSIZE( deviceInitTbl, \
											 DEVICEINIT_INFO ) );
			return( CRYPT_OK );
		}

	retIntError();
	}
=======
/****************************************************************************
*																			*
*						 cryptlib Crypto Device Routines					*
*						Copyright Peter Gutmann 1997-2022					*
*																			*
****************************************************************************/

#include "crypt.h"
#ifdef INC_ALL
  #include "capabil.h"
  #include "device.h"
  #include "objectfns.h"
#else
  #include "device/capabil.h"
  #include "device/device.h"
  #include "kernel/objectfns.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Sanity-check device data */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckDevice( IN_PTR const DEVICE_INFO *deviceInfoPtr )
	{
	assert( isReadPtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	/* Check general device data.  CRYPT_DEVICE_NONE is the system device so
	   we check with isEnumRangeOpt() rather than isEnumRange() */
	if( !isEnumRangeOpt( deviceInfoPtr->type, CRYPT_DEVICE ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: General info" ));
		return( FALSE );
		}
	if( !CHECK_FLAGS( deviceInfoPtr->flags, DEVICE_FLAG_NONE, 
					  DEVICE_FLAG_MAX ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: Flags" ));
		return( FALSE );
		}
	if( !isEmptyData( deviceInfoPtr->label, deviceInfoPtr->labelLen ) )
		{
		if( deviceInfoPtr->labelLen <= 0 || \
			deviceInfoPtr->labelLen > CRYPT_MAX_TEXTSIZE )
			{
			DEBUG_PUTS(( "sanityCheckDevice: Label" ));
			return( FALSE );
			}
		}
	if( !checkVarStruct( deviceInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: VarStruct" ));
		return( FALSE );
		}

	/* Check safe pointers.  We don't have to check the function pointers
	   because they're validated each time they're dereferenced */
	if( !DATAPTR_ISVALID( deviceInfoPtr->capabilityInfoList ) || \
		!DATAPTR_ISVALID( deviceInfoPtr->mechanismFunctions ) || \
		!rangeCheck( deviceInfoPtr->mechanismFunctionCount, 0, 50 ) || \
		!DATAPTR_ISVALID( deviceInfoPtr->createObjectFunctions ) || \
		!rangeCheck( deviceInfoPtr->createObjectFunctionCount, 0, 10 ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: Data pointers" ));
		return( FALSE );
		}

	/* Check associated handles */
	if( deviceInfoPtr->type == CRYPT_DEVICE_NONE )
		{
		if( deviceInfoPtr->objectHandle != SYSTEM_OBJECT_HANDLE || \
			deviceInfoPtr->ownerHandle != CRYPT_UNUSED )
			{
			DEBUG_PUTS(( "sanityCheckDevice: System device handles" ));
			return( FALSE );
			}
		}
	else
		{
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		if( !( deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE || \
			   isHandleRangeValid( deviceInfoPtr->objectHandle ) ) || \
			deviceInfoPtr->ownerHandle != DEFAULTUSER_OBJECT_HANDLE )
#else
		if( !isHandleRangeValid( deviceInfoPtr->objectHandle ) || \
			deviceInfoPtr->ownerHandle != DEFAULTUSER_OBJECT_HANDLE )
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
			{
			DEBUG_PUTS(( "sanityCheckDevice: Object handles" ));
			return( FALSE );
			}
		}

	/* Check function and data pointers */
	if( !DATAPTR_ISSET( deviceInfoPtr->capabilityInfoList ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: Capability function" ));
		return( FALSE );
		}

	/* Check error information */
	if( !isEnumRangeOpt( deviceInfoPtr->errorLocus, CRYPT_ATTRIBUTE ) || \
		!isEnumRangeOpt( deviceInfoPtr->errorType, CRYPT_ERRTYPE ) )
		{
		DEBUG_PUTS(( "sanityCheckDevice: Error info" ));
		return( FALSE );
		}

	/* Check subtype-specific data */
	switch( deviceInfoPtr->type )
		{
		case CRYPT_DEVICE_NONE:
			{
			const SYSTEMDEV_INFO *systemInfo = deviceInfoPtr->deviceSystem;

			assert( isReadPtr( systemInfo, sizeof( SYSTEMDEV_INFO ) ) );

			/* Check the CSPRNG data */
			if( !DATAPTR_ISSET( systemInfo->randomInfo ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: CSPRNG data" ));
				return( FALSE );
				}

			/* Check the nonce RNG data */
			if( systemInfo->nonceDataInitialised == FALSE )
				{
				if( !isEmptyData( systemInfo->nonceData, 
								  systemInfo->nonceHashSize ) )
					{
					DEBUG_PUTS(( "sanityCheckDevice: Spurious nonce RNG data" ));
					return( FALSE );
					}
				}
			else
				{
				if( systemInfo->nonceDataInitialised != TRUE || \
					!rangeCheck( systemInfo->nonceHashSize,
								 MIN_HASHSIZE, CRYPT_MAX_HASHSIZE ) || \
					isEmptyData( systemInfo->nonceData, 
								 systemInfo->nonceHashSize ) )
					{
					DEBUG_PUTS(( "sanityCheckDevice: Nonce RNG data" ));
					return( FALSE );
					}
				}

			break;
			}

#ifdef USE_PKCS11
		case CRYPT_DEVICE_PKCS11:
			{
			const PKCS11_INFO *pkcs11Info = deviceInfoPtr->devicePKCS11;

			assert( isReadPtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );

			/* Check general device information */
			if( pkcs11Info->minPinSize != 0 || pkcs11Info->maxPinSize != 0 )
				{
				if( pkcs11Info->minPinSize < 4 || \
				    pkcs11Info->minPinSize > pkcs11Info->maxPinSize || \
					pkcs11Info->maxPinSize > CRYPT_MAX_TEXTSIZE )
					{
					DEBUG_PUTS(( "sanityCheckDevice: PIN size" ));
					return( FALSE );
					}
				}

 			/* Check device type-specific information */
			if( pkcs11Info->deviceNo < 0 || \
				pkcs11Info->deviceNo > 16 )
				{
				DEBUG_PUTS(( "sanityCheckDevice: Device number" ));
				return( FALSE );
				}
			if( !isEmptyData( pkcs11Info->defaultSSOPin, \
							  pkcs11Info->defaultSSOPinLen ) )
				{
				if( !rangeCheck( pkcs11Info->defaultSSOPinLen, 
								 0, CRYPT_MAX_TEXTSIZE ) )
					{
					DEBUG_PUTS(( "sanityCheckDevice: SSO PIN size" ));
					return( FALSE );
					}
				}

			break;
			}
#endif /* USE_PKCS11 */

#ifdef USE_TPM
		case CRYPT_DEVICE_TPM:
			{
			const TPM_INFO *tpmInfo = deviceInfoPtr->deviceTPM;

			assert( isReadPtr( tpmInfo, sizeof( TPM_INFO ) ) );

			if( deviceInfoPtr->iCryptKeyset != CRYPT_ERROR && \
				!isHandleRangeValid( deviceInfoPtr->iCryptKeyset ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: Keyset information" ));
				return( FALSE );
				}
			if( !DATAPTR_ISVALID( deviceInfoPtr->storageFunctions ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: Storage functions" ));
				return( FALSE );
				}
			if( !rangeCheck( tpmInfo->authValueEhLen, \
							 0, CRYPT_MAX_TEXTSIZE ) || \
				!rangeCheck( tpmInfo->authValueLockoutLen, \
							 0, CRYPT_MAX_TEXTSIZE ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: TPM info" ));
				return( FALSE );
				}
			break;
			}
#endif /* USE_TPM */

#ifdef USE_CRYPTOAPI
		case CRYPT_DEVICE_CRYPTOAPI:
			{
			const CRYPTOAPI_INFO *cryptoapiInfo = deviceInfoPtr->deviceCryptoAPI;

			assert( isReadPtr( cryptoapiInfo, sizeof( CRYPTOAPI_INFO ) ) );

			/* Nothing to check */

			break;
			}
#endif /* USE_CRYPTOAPI */

#ifdef USE_HARDWARE
		case CRYPT_DEVICE_HARDWARE:
			{
			const HARDWARE_INFO *hardwareInfo = deviceInfoPtr->deviceHardware;

			assert( isReadPtr( hardwareInfo, sizeof( HARDWARE_INFO ) ) );

			if( deviceInfoPtr->iCryptKeyset == CRYPT_ERROR )
				{
				if( hardwareInfo->isFileKeyset != FALSE || \
					hardwareInfo->discardData != FALSE )
					{
					DEBUG_PUTS(( "sanityCheckDevice: Spurious keyset information" ));
					return( FALSE );
					}
				}
			else
				{
				if( !isHandleRangeValid( deviceInfoPtr->iCryptKeyset ) || \
					( hardwareInfo->isFileKeyset != TRUE && \
					  hardwareInfo->isFileKeyset != FALSE ) || \
					( hardwareInfo->discardData != TRUE && \
					  hardwareInfo->discardData != FALSE ) )
					{
					DEBUG_PUTS(( "sanityCheckDevice: Keyset information" ));
					return( FALSE );
					}
				}
			if( !DATAPTR_ISVALID( deviceInfoPtr->storageFunctions ) )
				{
				DEBUG_PUTS(( "sanityCheckDevice: Storage functions" ));
				return( FALSE );
				}

			break;
			}
#endif /* USE_HARDWARE */

		default:
			retIntError_Boolean();
		}

	return( TRUE );
	}

/* Check that device function pointers have been set up correctly.  This is a
   setup check not related to sanityCheckDevice() */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkDeviceFunctions( IN_PTR const DEVICE_INFO *deviceInfoPtr )
	{
	assert( isReadPtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	if( !FNPTR_ISSET( deviceInfoPtr->initFunction ) || \
		!FNPTR_ISSET( deviceInfoPtr->controlFunction ) || \
		!FNPTR_ISSET( deviceInfoPtr->shutdownFunction ) )
		{
		DEBUG_PUTS(( "checkDeviceFunctions: General functions" ));
		return( FALSE );
		}
	if( deviceInfoPtr->objectHandle == SYSTEM_OBJECT_HANDLE )
		{
		if( !FNPTR_ISNULL( deviceInfoPtr->getItemFunction ) || \
			!FNPTR_ISNULL( deviceInfoPtr->setItemFunction ) || \
			!FNPTR_ISNULL( deviceInfoPtr->deleteItemFunction ) || \
			!FNPTR_ISNULL( deviceInfoPtr->getFirstItemFunction ) || \
			!FNPTR_ISNULL( deviceInfoPtr->getNextItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->getRandomFunction ) )
			{
			DEBUG_PUTS(( "checkDeviceFunctions: System device functions" ));
			return( FALSE );
			}
		}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	else
		{
		if( deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE )
			{
			if( !FNPTR_ISSET( deviceInfoPtr->getItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->setItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->deleteItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->getFirstItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->getNextItemFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->getRandomFunction ) || \
				!FNPTR_ISSET( deviceInfoPtr->catalogQueryFunction ) )
				{
				DEBUG_PUTS(( "checkDeviceFunctions: Crypto device functions" ));
				return( FALSE );
				}
			}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	else
		{
		if( !FNPTR_ISSET( deviceInfoPtr->getItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->setItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->deleteItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->getFirstItemFunction ) || \
			!FNPTR_ISSET( deviceInfoPtr->getNextItemFunction ) || \
			!FNPTR_ISVALID( deviceInfoPtr->getRandomFunction ) )
			{
			DEBUG_PUTS(( "checkDeviceFunctions: Device data access functions" ));
			return( FALSE );
			}
		}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	
	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Process a crypto mechanism message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 5 ) ) \
static int processMechanismMessage( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
									IN_MESSAGE const MESSAGE_TYPE action,
									IN_ENUM( MECHANISM ) \
										const MECHANISM_TYPE mechanism,
									INOUT_PTR void *mechanismInfo,
									INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	CRYPT_DEVICE localCryptDevice = deviceInfoPtr->objectHandle;
	const MECHANISM_FUNCTION_INFO *mechanismFunctions;
	MECHANISM_FUNCTION mechanismFunction = NULL;
	LOOP_INDEX i;
	int refCount, status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( messageExtInfo, sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isMechanismActionMessage( action ) );
	REQUIRES( isEnumRange( mechanism, MECHANISM ) );
	REQUIRES( mechanismInfo != NULL );

	/* Find the function to handle this action and mechanism */
	mechanismFunctions = DATAPTR_GET( deviceInfoPtr->mechanismFunctions );
	if( mechanismFunctions != NULL )
		{
		LOOP_LARGE( i = 0,
					i < deviceInfoPtr->mechanismFunctionCount && \
						mechanismFunctions[ i ].action != MESSAGE_NONE, 
					i++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE( i, 0, \
										   deviceInfoPtr->mechanismFunctionCount - 1 ) );
			if( mechanismFunctions[ i ].action == action && \
				mechanismFunctions[ i ].mechanism == mechanism )
				{
				mechanismFunction = mechanismFunctions[ i ].function;
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK );
		ENSURES( i < deviceInfoPtr->mechanismFunctionCount );
		}
	if( mechanismFunction == NULL && \
		localCryptDevice != SYSTEM_OBJECT_HANDLE )
		{
		/* This isn't the system object, fall back to the system object and 
		   see if it can handle the mechanism.  We do it this way rather 
		   than sending the message through the kernel a second time because 
		   all the kernel checking of message parameters has already been 
		   done, this saves the overhead of a second, redundant kernel pass.  
		   This code was only ever used with Fortezza devices, with PKCS #11 
		   devices the support for various mechanisms is too patchy to allow 
		   us to rely on it so we always use system mechanisms which we know 
		   will get it right.
		   
		   Because it should never be used in normal use, we throw an 
		   exception if we get here inadvertently.  If this doesn't stop 
		   execution then the krnlAcquireObject() will since it will refuse 
		   to allow access to the system object */
		assert( INTERNAL_ERROR );
		setMessageObjectUnlocked( messageExtInfo );
		status = krnlSuspendObject( deviceInfoPtr->objectHandle, &refCount );
		ENSURES( cryptStatusOK( status ) );
		localCryptDevice = SYSTEM_OBJECT_HANDLE;
		status = krnlAcquireObject( SYSTEM_OBJECT_HANDLE, /* Will always fail */
									OBJECT_TYPE_DEVICE,
									( MESSAGE_PTR_CAST ) &deviceInfoPtr,
									CRYPT_ERROR_SIGNALLED );
		if( cryptStatusError( status ) )
			return( status );
		REQUIRES_OBJECT( mechanismFunctions != NULL,
						 deviceInfoPtr->objectHandle );
		LOOP_LARGE( i = 0, 
					i < deviceInfoPtr->mechanismFunctionCount && \
						mechanismFunctions[ i ].action != MESSAGE_NONE,
					i++ )
			{
			ENSURES_OBJECT( \
				LOOP_INVARIANT_LARGE( i, 0, \
									  deviceInfoPtr->mechanismFunctionCount - 1 ),
				deviceInfoPtr->objectHandle );
			if( mechanismFunctions[ i ].action == action && \
				mechanismFunctions[ i ].mechanism == mechanism )
				{
				mechanismFunction = mechanismFunctions[ i ].function;
				break;
				}
			}
		ENSURES_OBJECT( LOOP_BOUND_OK, deviceInfoPtr->objectHandle );
		ENSURES_OBJECT( i < deviceInfoPtr->mechanismFunctionCount,
						deviceInfoPtr->objectHandle );

		/* If this code was used then we'd need to release the system object
		   if we exit beyond this point */
		}
	if( mechanismFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* If the message has been sent to the system object, unlock it to allow 
	   it to be used by others and dispatch the message.  This is safe 
	   because the auxInfo for the system device is in a static, read-only 
	   segment and persists even if the system device is destroyed */
	if( localCryptDevice == SYSTEM_OBJECT_HANDLE )
		{
		setMessageObjectUnlocked( messageExtInfo );
		status = krnlSuspendObject( SYSTEM_OBJECT_HANDLE, &refCount );
		ENSURES( cryptStatusOK( status ) );
		assert( ( mechanism >= MECHANISM_SELFTEST_ENC && \
				  mechanism <= MECHANISM_SELFTEST_KDF && \
				  refCount <= 2 ) || \
				refCount == 1 );
				/* The system object can send itself a recursive 
				   selftest mechanism message */
		return( mechanismFunction( NULL, mechanismInfo ) );
		}

	/* Send the message to the device */
	return( mechanismFunction( deviceInfoPtr, mechanismInfo ) );
	}

/****************************************************************************
*																			*
*								Self-test Functions							*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Perform the algorithm self-test.  This returns two status values, the 
   overall status of calling the function as the standard return value and
   the status of the algorithm tests as a by-reference parameter */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int algorithmSelfTest( INOUT_PTR DATAPTR *capabilityInfoListHeadPtr,
							  OUT_STATUS int *testStatus )
	{
	DATAPTR capabilityInfoListHead = *capabilityInfoListHeadPtr;
	LOOP_INDEX_PTR CAPABILITY_INFO_LIST *capabilityInfoListPtr;
	CAPABILITY_INFO_LIST *capabilityInfoListPrevPtr = NULL;
	CAPABILITY_INFO_LIST savedCapabilityInfoListData;
	BOOLEAN algoTested = FALSE;

	assert( isWritePtr( capabilityInfoListHeadPtr, sizeof( DATAPTR ) ) );
	assert( isWritePtr( testStatus, sizeof( int ) ) );

	/* Clear return value */
	*testStatus = CRYPT_OK;

	/* Test each available capability */
	LOOP_MED( capabilityInfoListPtr = DATAPTR_GET( capabilityInfoListHead ), 
			  capabilityInfoListPtr != NULL,
			  capabilityInfoListPtr = DATAPTR_GET( capabilityInfoListPtr->next ) )
		{
		const CAPABILITY_INFO *capabilityInfoPtr = \
					DATAPTR_GET( capabilityInfoListPtr->info );
		int localStatus;

		REQUIRES( capabilityInfoPtr != NULL );
		REQUIRES( sanityCheckCapability( capabilityInfoPtr ) );
		REQUIRES( capabilityInfoPtr->selfTestFunction != NULL );

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* Perform the self-test for this algorithm type */
		DEBUG_DIAG(( "Self-test: %s", capabilityInfoPtr->algoName ));
		localStatus = capabilityInfoPtr->selfTestFunction();
		if( cryptStatusError( localStatus ) )
			{
			/* The self-test failed, remember the status if it's the first 
			   failure */
			if( cryptStatusOK( *testStatus ) )
				*testStatus = localStatus;

			/* Disable the algorithm that failed.  Since this unlinks it 
			   from the capability list, we have to save a copy of the 
			   pre-unlinking capability information in order for 
			   DATAPTR_GET( ...->next ) to work, and then point the
			   capabilityInfoListPtr to this temporary copy to allow the 
			   loop to continue.

			   In addition since we're working on a copy of the DATAPTR we 
			   have to reflect the change back up to the original */
			savedCapabilityInfoListData = *capabilityInfoListPtr;
			deleteSingleListElement( capabilityInfoListHead, 
									 capabilityInfoListPrevPtr, 
									 capabilityInfoListPtr,
									 CAPABILITY_INFO_LIST );
			capabilityInfoListPtr = &savedCapabilityInfoListData;
			*capabilityInfoListHeadPtr = capabilityInfoListHead;
			DEBUG_DIAG(( "Algorithm %s failed self-test", 
						 capabilityInfoPtr->algoName ));
			}
		else
			{
			algoTested = TRUE;

			/* Remember the last successfully-tested capability */
			capabilityInfoListPrevPtr = capabilityInfoListPtr;
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( algoTested ? CRYPT_OK : CRYPT_ERROR_NOTFOUND );
	}

/* Perform the mechanism self-test.  This is performed in addition to the 
   algorithm tests if the user requests a test of all algorithms.  
   
   Only low-level mechanism functionality is tested since the high-level 
   tests either produce non-constant results that can't be checked against a 
   fixed value or require the creation of multiple contexts to hold keys.
   For example to check the key wrap mechanisms the order of operations
   would be:

	create PKC context;
	create conventional context;
	load key into conventional context;
	wrap conventional context using PKC context;
	destroy conventional context;
	create conventional context;
	unwrap conventional context using PKC context;
	destroy conventional context;
	destroy PKC context;

   requiring a PKC and two conventional contexts for each test */

/* Perform a self-test */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int selftestDevice( INOUT_PTR DEVICE_INFO *deviceInfo,
					INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	MECHANISM_WRAP_INFO pkcWrapMechanismInfo;
	MECHANISM_SIGN_INFO signMechanismInfo;
	MECHANISM_DERIVE_INFO deriveMechanismInfo;
	MECHANISM_KDF_INFO kdfMechanismInfo;
	int status, testStatus;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfo ) );

	/* Perform an algorithm self-test.  This returns two status values, the
	   status of calling the self-test function and the status of the tests
	   that were performed.  The function call may succeed (status == 
	   CRYPT_OK) but one of the tests performed by the function may have 
	   failed (testStatus != CRYPT_OK), so we have to exit on either type of
	   error */
	status = algorithmSelfTest( &deviceInfo->capabilityInfoList, 
								&testStatus );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptStatusError( testStatus ) )
		return( testStatus );

	/* Since the mechanism self-tests can be quite lengthy and require 
	   recursive handling of messages by the system object (without actually 
	   requiring access to the system object state), if we're using the 
	   system object for the self-tests then we unlock it before running the 
	   tests to avoid it becoming a bottleneck */
	if( deviceInfo->objectHandle == SYSTEM_OBJECT_HANDLE )
		{
		int refCount;

		status = krnlSuspendObject( SYSTEM_OBJECT_HANDLE, &refCount );
		if( cryptStatusError( status ) )
			return( status );
		setMessageObjectUnlocked( messageExtInfo );
		}
	
	/* Perform the mechanism self-tests */
	setMechanismWrapInfo( &pkcWrapMechanismInfo, NULL, 0, NULL, 0, 
						  CRYPT_UNUSED, CRYPT_UNUSED );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE,
							  IMESSAGE_DEV_EXPORT, &pkcWrapMechanismInfo,
							  MECHANISM_SELFTEST_ENC );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismSignInfo( &signMechanismInfo, NULL, 0, CRYPT_UNUSED, 
						  CRYPT_UNUSED, CRYPT_UNUSED );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE,
							  IMESSAGE_DEV_SIGN, &signMechanismInfo,
							  MECHANISM_SELFTEST_SIG );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismDeriveInfo( &deriveMechanismInfo, NULL, 0, NULL, 0, 0, 
							NULL, 0, 0 );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE,
							  IMESSAGE_DEV_DERIVE, &deriveMechanismInfo,
							  MECHANISM_SELFTEST_DERIVE );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismKDFInfo( &kdfMechanismInfo, CRYPT_UNUSED, CRYPT_UNUSED, 0, 
						 NULL, 0 );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE,
							  IMESSAGE_DEV_KDF, &kdfMechanismInfo,
							  MECHANISM_SELFTEST_KDF );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}
#endif /* CONFIG_NO_SELFTEST */

/****************************************************************************
*																			*
*							Object Creation Functions						*
*																			*
****************************************************************************/

/* Create an object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int createObject( DEVICE_INFO *deviceInfoPtr,
						 IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE objectType,
						 INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
						 INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	CRYPT_DEVICE iCryptDevice = deviceInfoPtr->objectHandle;
	const CREATEOBJECT_FUNCTION_INFO *createObjectFunctions;
	CREATEOBJECT_FUNCTION createObjectFunction = NULL;
	const void *auxInfo = NULL;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( createInfo, sizeof( MESSAGE_CREATEOBJECT_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( isEnumRange( objectType, OBJECT_TYPE ) );

	/* Find the function to handle this object */
	createObjectFunctions = DATAPTR_GET( deviceInfoPtr->createObjectFunctions );
	if( createObjectFunctions != NULL )
		{
		LOOP_INDEX i;
			
		LOOP_MED( i = 0,
				  i < deviceInfoPtr->createObjectFunctionCount && \
					createObjectFunctions[ i ].type != OBJECT_TYPE_NONE,
				  i++ )
			{
			ENSURES( LOOP_INVARIANT_MED( i, 0, \
									     deviceInfoPtr->createObjectFunctionCount - 1 ) );
			if( createObjectFunctions[ i ].type == objectType )
				{
				createObjectFunction  = createObjectFunctions[ i ].function;
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK );
		ENSURES( i < deviceInfoPtr->createObjectFunctionCount );
		}
	if( createObjectFunction  == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Get any auxiliary information that we may need to create the object */
	if( objectType == OBJECT_TYPE_CONTEXT )
		{
		auxInfo = DATAPTR_GET( deviceInfoPtr->capabilityInfoList );

		ENSURES( DATAPTR_ISVALID( deviceInfoPtr->capabilityInfoList ) );
		}

	/* If the message has been sent to the system object, unlock it to allow 
	   it to be used by others and dispatch the message.  This is safe 
	   because the auxInfo for the system device is in a static, read-only 
	   segment and persists even if the system device is destroyed */
	if( deviceInfoPtr->objectHandle == SYSTEM_OBJECT_HANDLE )
		{
		int refCount;

		setMessageObjectUnlocked( messageExtInfo );
		status = krnlSuspendObject( SYSTEM_OBJECT_HANDLE, &refCount );
		ENSURES( cryptStatusOK( status ) );
		assert( refCount == 1 );
		status = createObjectFunction( createInfo, auxInfo,
									   CREATEOBJECT_FLAG_NONE );
		}
	else
		{
		int objectFlags = CREATEOBJECT_FLAG_DUMMY;

		/* If we're being created via the crypto object as a substitute for 
		   the system object then we need to indicate this to ensure that 
		   some of the restrictions enforced for objects created in external 
		   crypto devices are bypassed */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		if( deviceInfoPtr->objectHandle == CRYPTO_OBJECT_HANDLE )
			objectFlags |= CREATEOBJECT_FLAG_CRYPTOBJ;
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

		/* Create a dummy object, with all details handled by the device.
		   Unlike the system device we don't unlock the device information 
		   before we call the create object function because there may be 
		   auxiliary information held in the device object that we need in 
		   order to create the object.  This is OK since we're not tying up 
		   the system device but only some auxiliary crypto device */
		status = createObjectFunction( createInfo, auxInfo, objectFlags );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make the newly-created object a dependent object of the device */
	return( krnlSendMessage( createInfo->cryptHandle, IMESSAGE_SETDEPENDENT, 
							 ( MESSAGE_CAST ) &iCryptDevice, 
							 SETDEP_OPTION_INCREF ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int createObjectIndirect( DEVICE_INFO *deviceInfoPtr,
								 IN_ENUM( OBJECT_TYPE ) \
									const OBJECT_TYPE objectType,
								 INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
								 INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	const CRYPT_DEVICE iCryptDevice = deviceInfoPtr->objectHandle;
#ifdef USE_CERTIFICATES
	int refCount;
#endif /* USE_CERTIFICATES */
	int value, status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( createInfo, sizeof( MESSAGE_CREATEOBJECT_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( isEnumRange( objectType, OBJECT_TYPE ) );

	switch( objectType )
		{
#if defined( USE_CERTIFICATES ) 
		case OBJECT_TYPE_CERTIFICATE:
			/* The message has been sent to the system object, unlock it to 
			   allow it to be used by others and dispatch the message.  This 
			   is safe because the auxInfo for the system device is in a 
			   static, read-only segment and persists even if the system 
			   device is destroyed */
			ENSURES( iCryptDevice == SYSTEM_OBJECT_HANDLE );
			setMessageObjectUnlocked( messageExtInfo );
			status = krnlSuspendObject( SYSTEM_OBJECT_HANDLE, &refCount );
			ENSURES( cryptStatusOK( status ) );
			assert( refCount == 1 );
			status = createCertificateIndirect( createInfo, NULL, 0 );
			break;
#endif /* USE_CERTIFICATES */

#if defined( USE_KEYSETS ) && \
	( defined( USE_HARDWARE ) || defined( USE_TPM ) )
		case OBJECT_TYPE_KEYSET:
			ENSURES( iCryptDevice == CRYPTO_OBJECT_HANDLE );
			status = createKeysetIndirect( createInfo, NULL, 0 );
			break;
#endif /* USE_KEYSETS && ( USE_HARDWARE || USE_TPM ) */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make the newly-created object a dependent object of the device.  
	   There's one special-case situation where we don't do this and that's 
	   when we're importing a certificate chain, which is a collection of 
	   individual certificate objects each of which have already been made 
	   dependent on the device.  We could detect this in one of two ways, 
	   either implicitly by reading the CRYPT_IATTRIBUTE_SUBTYPE attribute 
	   and assuming that if it's a SUBTYPE_CERT_CERTCHAIN that the owner 
	   will have been set, or simply by reading the depending user object.  
	   Explcitly checking for ownership seems to be the best approach */
	status = krnlSendMessage( createInfo->cryptHandle, 
							  IMESSAGE_GETDEPENDENT, &value, 
							  OBJECT_TYPE_USER );
	if( cryptStatusOK( status ) )
		{
		/* The object is already owned, don't try and set an owner */
		return( CRYPT_OK );
		}
	return( krnlSendMessage( createInfo->cryptHandle, IMESSAGE_SETDEPENDENT, 
							 ( MESSAGE_CAST ) &iCryptDevice, 
							 SETDEP_OPTION_INCREF ) );
	}

/****************************************************************************
*																			*
*								Device API Functions						*
*																			*
****************************************************************************/

/* Default object creation routines used when the device code doesn't set
   anything up */

static const CREATEOBJECT_FUNCTION_INFO defaultCreateFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext },
	{ OBJECT_TYPE_NONE, NULL }
	};

/* Handle a message sent to a device object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int deviceMessageFunction( INOUT_PTR TYPECAST( MESSAGE_FUNCTION_EXTINFO * ) \
									void *objectInfoPtr,
								  IN_MESSAGE const MESSAGE_TYPE message,
								  void *messageDataPtr,
								  IN_INT_SHORT_Z const int messageValue )
	{
	MESSAGE_FUNCTION_EXTINFO *messageExtInfo = \
						( MESSAGE_FUNCTION_EXTINFO * ) objectInfoPtr;
	DEVICE_INFO *deviceInfoPtr = \
						( DEVICE_INFO * ) messageExtInfo->objectInfoPtr;

	assert( isWritePtr( objectInfoPtr, sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( message == MESSAGE_DESTROY || \
			  sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isEnumRange( message, MESSAGE ) );
	REQUIRES( isShortIntegerRange( messageValue ) );

	/* Process the destroy object message */
	if( message == MESSAGE_DESTROY )
		{
		/* Shut down the device if required */
		if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_ACTIVE ) )
			{
			const DEV_SHUTDOWNFUNCTION shutdownFunction = \
						( DEV_SHUTDOWNFUNCTION ) \
						FNPTR_GET( deviceInfoPtr->shutdownFunction );

			if( shutdownFunction != NULL )
				shutdownFunction( deviceInfoPtr );
			}

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		REQUIRES( message == MESSAGE_GETATTRIBUTE || \
				  message == MESSAGE_GETATTRIBUTE_S || \
				  message == MESSAGE_SETATTRIBUTE || \
				  message == MESSAGE_SETATTRIBUTE_S );
		REQUIRES( isAttribute( messageValue ) || \
				  isInternalAttribute( messageValue ) );

		if( message == MESSAGE_GETATTRIBUTE )
			{
			return( getDeviceAttribute( deviceInfoPtr, 
										( int * ) messageDataPtr,
										messageValue, messageExtInfo ) );
			}
		if( message == MESSAGE_GETATTRIBUTE_S )
			{
			return( getDeviceAttributeS( deviceInfoPtr, 
										 ( MESSAGE_DATA * ) messageDataPtr,
										 messageValue, messageExtInfo ) );
			}
		if( message == MESSAGE_SETATTRIBUTE )
			{
			/* CRYPT_IATTRIBUTE_INITIALISED is purely a notification message 
			   with no parameters so we don't pass it down to the attribute-
			   handling code */
			if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
				return( CRYPT_OK );

			return( setDeviceAttribute( deviceInfoPtr, 
										 *( ( int * ) messageDataPtr ),
										 messageValue, messageExtInfo ) );
			}
		if( message == MESSAGE_SETATTRIBUTE_S )
			{
			const MESSAGE_DATA *msgData = ( MESSAGE_DATA * ) messageDataPtr;

			return( setDeviceAttributeS( deviceInfoPtr, msgData->data, 
										 msgData->length, messageValue,
										 messageExtInfo ) );
			}

		retIntError();
		}

	/* Process action messages */
	if( isMechanismActionMessage( message ) )
		{
		return( processMechanismMessage( deviceInfoPtr, message, 
										 messageValue, messageDataPtr, 
										 messageExtInfo ) );
		}

	/* Process messages that check a device */
	if( message == MESSAGE_CHECK )
		{
		/* The check for whether this device type can contain an object that
		   can perform the requested operation has already been performed by
		   the kernel so there's nothing further to do here */
		REQUIRES( deviceInfoPtr->type == CRYPT_DEVICE_PKCS11 || \
				  deviceInfoPtr->type == CRYPT_DEVICE_CRYPTOAPI || \
				  deviceInfoPtr->type == CRYPT_DEVICE_TPM || \
				  deviceInfoPtr->type == CRYPT_DEVICE_HARDWARE );
		REQUIRES( messageValue == MESSAGE_CHECK_PKC_ENCRYPT_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_DECRYPT_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_SIGCHECK_AVAIL || \
				  messageValue == MESSAGE_CHECK_PKC_SIGN_AVAIL );

		return( CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == MESSAGE_SELFTEST )
		{
		const DEV_SELFTESTFUNCTION selftestFunction = \
					( DEV_SELFTESTFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->selftestFunction );

		/* If the device doesn't have a self-test capability then there's 
		   not much that we can do */
		if( selftestFunction == NULL )
			return( CRYPT_OK );

		return( selftestFunction( deviceInfoPtr, messageExtInfo ) );
		}
	if( message == MESSAGE_KEY_GETKEY )
		{
		const DEV_GETITEMFUNCTION getItemFunction = \
					( DEV_GETITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->getItemFunction );
		MESSAGE_KEYMGMT_INFO *getkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( getItemFunction != NULL );

		/* Create a context or certificate via an object in the device */
		return( getItemFunction( deviceInfoPtr,
								 &getkeyInfo->cryptHandle, messageValue,
								 getkeyInfo->keyIDtype, getkeyInfo->keyID,
								 getkeyInfo->keyIDlength, getkeyInfo->auxInfo,
								 &getkeyInfo->auxInfoLength,
								 getkeyInfo->flags ) );
		}
	if( message == MESSAGE_KEY_SETKEY )
		{
		const DEV_SETITEMFUNCTION setItemFunction = \
					( DEV_SETITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->setItemFunction );
		MESSAGE_KEYMGMT_INFO *setkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( setItemFunction != NULL );

		/* Update the device with the certificate */
		return( setItemFunction( deviceInfoPtr, setkeyInfo->cryptHandle ) );
		}
	if( message == MESSAGE_KEY_DELETEKEY )
		{
		const DEV_DELETEITEMFUNCTION deleteItemFunction = \
					( DEV_DELETEITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->deleteItemFunction );
		MESSAGE_KEYMGMT_INFO *deletekeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( deleteItemFunction != NULL );

		/* Delete an object in the device */
		return( deleteItemFunction( deviceInfoPtr, messageValue, 
									deletekeyInfo->keyIDtype, 
									deletekeyInfo->keyID, 
									deletekeyInfo->keyIDlength ) );
		}
	if( message == MESSAGE_KEY_GETFIRSTCERT )
		{
		const DEV_GETFIRSTITEMFUNCTION getFirstItemFunction = \
					( DEV_GETFIRSTITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->getFirstItemFunction );
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( getFirstItemFunction != NULL );
		REQUIRES( getnextcertInfo->auxInfoLength == sizeof( int ) );
		REQUIRES( messageValue == KEYMGMT_ITEM_PUBLICKEY );

		/* Fetch a certificate in a certificate chain from the device */
		return( getFirstItemFunction( deviceInfoPtr, 
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->keyIDtype, getnextcertInfo->keyID,
						getnextcertInfo->keyIDlength, messageValue,
						getnextcertInfo->flags ) );
		}
	if( message == MESSAGE_KEY_GETNEXTCERT )
		{
		const DEV_GETNEXTITEMFUNCTION getNextItemFunction = \
					( DEV_GETNEXTITEMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->getNextItemFunction );
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;

		REQUIRES( getNextItemFunction != NULL );
		REQUIRES( getnextcertInfo->auxInfoLength == sizeof( int ) );

		/* Fetch a certificate in a certificate chain from the device */
		return( getNextItemFunction( deviceInfoPtr,
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->flags ) );
		}
	if( message == MESSAGE_DEV_QUERYCAPABILITY )
		{
		const CAPABILITY_INFO_LIST *capabilityInfoListPtr = \
				DATAPTR_GET( deviceInfoPtr->capabilityInfoList );
		const void *capabilityInfoPtr;
		CRYPT_QUERY_INFO *queryInfo = ( CRYPT_QUERY_INFO * ) messageDataPtr;

		REQUIRES( capabilityInfoListPtr != NULL );

		/* Find the information for this algorithm and return an appropriate
		   subset of it to the caller */
		capabilityInfoPtr = findCapabilityInfo( capabilityInfoListPtr, 
												messageValue );
		if( capabilityInfoPtr == NULL )
			return( CRYPT_ERROR_NOTAVAIL );
		getCapabilityInfo( queryInfo, capabilityInfoPtr );

		return( CRYPT_OK );
		}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( message == MESSAGE_DEV_CATALOGQUERY )
		{
		const DEV_CATALOGQUERYFUNCTION catalogQueryFunction = \
					( DEV_CATALOGQUERYFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->catalogQueryFunction );
		MESSAGE_CATALOGQUERY_INFO *queryInfo = \
							( MESSAGE_CATALOGQUERY_INFO * ) messageDataPtr;

		REQUIRES( catalogQueryFunction != NULL );

		return( catalogQueryFunction( deviceInfoPtr, queryInfo, 
									  messageValue ) );
		}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	if( message == MESSAGE_DEV_CREATEOBJECT )
		{
		/* If the device can't have objects created within it, complain */
		if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_READONLY ) )
			return( CRYPT_ERROR_PERMISSION );

		return( createObject( deviceInfoPtr, messageValue, messageDataPtr,
							  messageExtInfo ) );
		}
	if( message == MESSAGE_DEV_CREATEOBJECT_INDIRECT )
		{
		/* If the device can't have objects created within it, complain */
		if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_READONLY ) )
			return( CRYPT_ERROR_PERMISSION );

		return( createObjectIndirect( deviceInfoPtr, messageValue, 
									  messageDataPtr, messageExtInfo ) );
		}

	retIntError();
	}

/* Open a device.  This is a common function called to create both the
   internal system device object and optional crypto object, and general 
   devices */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int openDevice( OUT_HANDLE_OPT CRYPT_DEVICE *iCryptDevice,
					   IN_HANDLE_OPT const CRYPT_USER iCryptOwner,
					   IN_ENUM_OPT( CRYPT_DEVICE ) \
							const CRYPT_DEVICE_TYPE deviceType,
					   IN_BUFFER_OPT( nameLength ) const char *name, 
					   IN_LENGTH_TEXT_Z const int nameLength,
					   OUT_PTR_PTR_OPT DEVICE_INFO **deviceInfoPtrPtr )
	{
	DEVICE_INFO *deviceInfoPtr;
	DEV_INITFUNCTION initFunction;
	OBJECT_SUBTYPE subType;
	static const MAP_TABLE subtypeMapTbl[] = {
		{ CRYPT_DEVICE_NONE, SUBTYPE_DEV_SYSTEM },
#ifdef USE_PKCS11
		{ CRYPT_DEVICE_PKCS11, SUBTYPE_DEV_PKCS11 },
#endif /* USE_PKCS11 */
#ifdef USE_TPM
		{ CRYPT_DEVICE_TPM, SUBTYPE_DEV_TPM },
#endif /* USE_TPM */
#ifdef USE_CRYPTOAPI
		{ CRYPT_DEVICE_CRYPTOAPI, SUBTYPE_DEV_CRYPTOAPI },
#endif /* USE_CRYPTOAPI */
#ifdef USE_HARDWARE
		{ CRYPT_DEVICE_HARDWARE, SUBTYPE_DEV_HARDWARE },
#endif /* USE_HARDWARE */
		{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
		};
	int value, storageSize, status;

	assert( isWritePtr( iCryptDevice, sizeof( CRYPT_DEVICE ) ) );
	assert( ( name == NULL && nameLength == 0 ) || \
			( isReadPtrDynamic( name, nameLength ) ) );
	assert( isWritePtr( deviceInfoPtrPtr, sizeof( DEVICE_INFO * ) ) );

	REQUIRES( ( deviceType == CRYPT_DEVICE_NONE && \
				iCryptOwner == CRYPT_UNUSED ) || \
			  ( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE ) || \
			  isHandleRangeValid( iCryptOwner ) );
	REQUIRES( isEnumRangeOpt( deviceType, CRYPT_DEVICE ) );
	REQUIRES( ( name == NULL && nameLength == 0 ) || \
			  ( name != NULL && \
			    nameLength >= MIN_NAME_LENGTH && \
				nameLength <= CRYPT_MAX_TEXTSIZE ) );

	/* Clear return values */
	*iCryptDevice = CRYPT_ERROR;
	*deviceInfoPtrPtr = NULL;

	/* Set up subtype-specific information */
	status = mapValue( deviceType, &value, subtypeMapTbl, 
					   FAILSAFE_ARRAYSIZE( subtypeMapTbl, MAP_TABLE ) );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_NOTAVAIL );
	subType = value;
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			storageSize = sizeof( SYSTEMDEV_INFO );
			break;

#ifdef USE_PKCS11
		case CRYPT_DEVICE_PKCS11:
			storageSize = sizeof( PKCS11_INFO );
			break;
#endif /* USE_PKCS11 */

#ifdef USE_TPM
		case CRYPT_DEVICE_TPM:
			storageSize = sizeof( TPM_INFO );
			break;
#endif /* USE_TPM */

#ifdef USE_CRYPTOAPI
		case CRYPT_DEVICE_CRYPTOAPI:
			storageSize = sizeof( CRYPTOAPI_INFO );
			break;
#endif /* USE_CRYPTOAPI */

#ifdef USE_HARDWARE
		case CRYPT_DEVICE_HARDWARE:
			storageSize = sizeof( HARDWARE_INFO );
			break;
#endif /* USE_HARDWARE */

		default:
			retIntError();
		}

	/* Create the device object and connect it to the device */
	status = krnlCreateObject( iCryptDevice, ( void ** ) &deviceInfoPtr,
							   sizeof( DEVICE_INFO ) + storageSize,
							   OBJECT_TYPE_DEVICE, subType,
							   CREATEOBJECT_FLAG_NONE, iCryptOwner,
							   ACTION_PERM_NONE_ALL, deviceMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( deviceInfoPtr != NULL );
	*deviceInfoPtrPtr = deviceInfoPtr;
	deviceInfoPtr->objectHandle = *iCryptDevice;
	deviceInfoPtr->ownerHandle = iCryptOwner;
	INIT_FLAGS( deviceInfoPtr->flags, DEVICE_FLAG_NONE );
	deviceInfoPtr->type = deviceType;
#if defined( USE_HARDWARE ) || defined( USE_TPM )
	deviceInfoPtr->iCryptKeyset = CRYPT_ERROR;
	DATAPTR_SET( deviceInfoPtr->storageFunctions, NULL );
#endif /* USE_HARDWARE || USE_TPM */
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			deviceInfoPtr->deviceSystem = \
							( SYSTEMDEV_INFO * ) deviceInfoPtr->storage;
			break;

#ifdef USE_PKCS11
		case CRYPT_DEVICE_PKCS11:
			deviceInfoPtr->devicePKCS11 = \
							( PKCS11_INFO * ) deviceInfoPtr->storage;
			break;
#endif /* USE_PKCS11 */

#ifdef USE_TPM
		case CRYPT_DEVICE_TPM:
			deviceInfoPtr->deviceTPM = \
							( TPM_INFO * ) deviceInfoPtr->storage;
			break;
#endif /* USE_TPM */

#ifdef USE_CRYPTOAPI
		case CRYPT_DEVICE_CRYPTOAPI:
			deviceInfoPtr->deviceCryptoAPI = \
							( CRYPTOAPI_INFO * ) deviceInfoPtr->storage;
			break;
#endif /* USE_CRYPTOAPI */

#ifdef USE_HARDWARE
		case CRYPT_DEVICE_HARDWARE:
			deviceInfoPtr->deviceHardware = \
							( HARDWARE_INFO * ) deviceInfoPtr->storage;
			break;
#endif /* USE_HARDWARE */

		default:
			retIntError();
		}
	deviceInfoPtr->storageSize = storageSize;

	/* Sanity check to make sure that the all-important system device is as 
	   it's supposed to be.  krnlCreateObject() doesn't allow creation of a
	   second system object but this is a secondary check of the types and 
	   subtypes used in this function */
	ENSURES( ( deviceType == CRYPT_DEVICE_NONE && \
			   subType == SUBTYPE_DEV_SYSTEM && \
			   *iCryptDevice == SYSTEM_OBJECT_HANDLE ) || \
			 ( deviceType != CRYPT_DEVICE_NONE && \
			   subType != SUBTYPE_DEV_SYSTEM && \
			   *iCryptDevice != SYSTEM_OBJECT_HANDLE ) );

	/* Set up access information for the device */
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			status = setDeviceSystem( deviceInfoPtr );
			break;

#ifdef USE_PKCS11
		case CRYPT_DEVICE_PKCS11:
			ENSURES( name != NULL && \
					 nameLength >= MIN_NAME_LENGTH && \
					 nameLength <= CRYPT_MAX_TEXTSIZE );
			status = setDevicePKCS11( deviceInfoPtr, name, nameLength );
			break;
#endif /* USE_PKCS11 */

#ifdef USE_TPM
		case CRYPT_DEVICE_TPM:
			status = setDeviceTPM( deviceInfoPtr );
			break;
#endif /* USE_TPM */

#ifdef USE_CRYPTOAPI
		case CRYPT_DEVICE_CRYPTOAPI:
			status = setDeviceCryptoAPI( deviceInfoPtr );
			break;
#endif /* USE_CRYPTOAPI */

#ifdef USE_HARDWARE
		case CRYPT_DEVICE_HARDWARE:
			status = setDeviceHardware( deviceInfoPtr );
			break;
#endif /* USE_HARDWARE */

		default:
			retIntError();
		}
	if( cryptStatusOK( status ) && \
		DATAPTR_GET( deviceInfoPtr->createObjectFunctions ) == NULL )
		{
		/* The device-specific code hasn't set up anything, use the default
		   create-object functions, which just creates encryption contexts
		   using the device capability information */
		DATAPTR_SET( deviceInfoPtr->createObjectFunctions, 
					 ( void * ) defaultCreateFunctions );
		deviceInfoPtr->createObjectFunctionCount = \
							FAILSAFE_ARRAYSIZE( defaultCreateFunctions, \
												CREATEOBJECT_FUNCTION_INFO );
		}
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( checkDeviceFunctions( deviceInfoPtr ) );

	/* Connect to the device */
	initFunction = ( DEV_INITFUNCTION ) \
				   FNPTR_GET( deviceInfoPtr->initFunction );
	REQUIRES( initFunction != NULL );
	status = initFunction( deviceInfoPtr, name, nameLength );
	if( cryptStatusError( status ) )
		{
		/* Since this function is called on object creation, if it fails 
		   there's no object to get extended error information from so we 
		   dump the error information as a diagnostic for debugging 
		   purposes */
#ifdef USE_PKCS11
		if( deviceType == CRYPT_DEVICE_PKCS11 )
			{
			DEBUG_DIAG_ERRMSG(( "PKCS #11 device open failed, status %s, error "
								"string:\n  '%s'", getStatusName( status ),
								getErrorInfoString( DEVICE_ERRINFO ) ));
			}
#endif /* USE_PKCS11 */
#ifdef USE_TPM
		if( deviceType == CRYPT_DEVICE_TPM )
			{
			DEBUG_DIAG_ERRMSG(( "TPM device open failed, status %s, error "
								"string:\n  '%s'", getStatusName( status ),
								getErrorInfoString( DEVICE_ERRINFO ) ));
			}
#endif /* USE_TPM */
#ifdef USE_HARDWARE
		if( deviceType == CRYPT_DEVICE_HARDWARE )
			{
			DEBUG_DIAG_ERRMSG(( "Hardware device open failed, status %s, error "
								"string:\n  '%s'", getStatusName( status ),
								getErrorInfoString( DEVICE_ERRINFO ) ));
			}
#endif /* USE_HARDWARE */
		return( status );
		}

	return( CRYPT_OK );
	}

/* Create a (non-system) device object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createDevice( INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
				  STDC_UNUSED const void *auxDataPtr, 
				  STDC_UNUSED const int auxValue )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfoPtr = NULL;
	int initStatus, status;

	assert( isWritePtr( createInfo, sizeof( MESSAGE_CREATEOBJECT_INFO ) ) );

	REQUIRES( auxDataPtr == NULL && auxValue == 0 );
	REQUIRES( isEnumRange( createInfo->arg1, CRYPT_DEVICE ) );
	REQUIRES( ( ( createInfo->arg1 == CRYPT_DEVICE_PKCS11 || \
				  createInfo->arg1 == CRYPT_DEVICE_CRYPTOAPI ) && \
				createInfo->strArg1 != NULL && \
				createInfo->strArgLen1 >= MIN_NAME_LENGTH && \
				createInfo->strArgLen1 <= CRYPT_MAX_TEXTSIZE ) || \
			  ( createInfo->arg1 != CRYPT_DEVICE_PKCS11 && \
				createInfo->arg1 != CRYPT_DEVICE_CRYPTOAPI && \
				createInfo->strArg1 == NULL && \
				createInfo->strArgLen1 == 0 ) );

	/* Wait for any async device driver binding to complete */
	if( !krnlWaitSemaphore( SEMAPHORE_DRIVERBIND ) )
		{
		/* The kernel is shutting down, bail out */
		DEBUG_DIAG(( "Exiting due to kernel shutdown" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Pass the call on to the lower-level open function */
	initStatus = openDevice( &iCryptDevice, createInfo->cryptOwner,
							 createInfo->arg1, createInfo->strArg1,
							 createInfo->strArgLen1, &deviceInfoPtr );
	if( cryptStatusError( initStatus ) )
		{
		/* If the create object failed, return immediately */
		if( deviceInfoPtr == NULL )
			return( initStatus );

		/* The init failed, make sure that the object gets destroyed when we
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptDevice, IMESSAGE_DESTROY );
		}

	/* We've finished setting up the object-type-specific information, tell 
	   the kernel that the object is ready for use */
	status = krnlSendMessage( iCryptDevice, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusOK( status ) && \
		createInfo->arg1 == CRYPT_DEVICE_CRYPTOAPI )
		{
		/* If it's a device that doesn't require an explicit login, move it
		   into the initialised state */
		status = krnlSendMessage( iCryptDevice, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_UNUSED,
								  CRYPT_IATTRIBUTE_INITIALISED );
		if( cryptStatusError( status ) )
			krnlSendNotifier( iCryptDevice, IMESSAGE_DESTROY );
		}
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptDevice;

	return( CRYPT_OK );
	}

/* Create the internal system device object.  This is somewhat special in
   that it can't be destroyed through a normal message (it can only be done
   from one place in the kernel) so if the open fails then we don't use the 
   normal signalling mechanism to destroy it but simply return an error code 
   to the caller (the cryptlib init process).  This causes the init to fail 
   and destroys the object when the kernel shuts down */

CHECK_RETVAL \
static int createSystemDeviceObject( void )
	{
	CRYPT_DEVICE iSystemObject;
	DEVICE_INFO *deviceInfoPtr;
	int initStatus, status;

	/* Pass the call on to the lower-level open function.  This device is
	   unique and has no owner or type.

	   Normally if an object init fails then we tell the kernel to destroy 
	   it by sending it a destroy message, which is processed after the 
	   object's status has been set to normal.  However we don't have the 
	   privileges to do this for the system object (or the default user 
	   object) so we just pass the error code back to the caller, which 
	   causes the cryptlib init to fail.
	   
	   In addition the init can fail in one of two ways, the object isn't
	   even created (deviceInfoPtr == NULL, nothing to clean up) in which 
	   case we bail out immediately, or the object is created but wasn't set 
	   up properly (deviceInfoPtr is allocated, but the object can't be 
	   used) in which case we bail out after we update its status.

	   A failure at this point is a bit problematic because it's not 
	   possible to inform the caller that the system object was successfully 
	   created but something went wrong after that.  That is, it's assumed
	   that create-object operations are atomic so that a failure status
	   indicates that all allocations and whatnot were rolled back, but 
	   since the system object can only be destroyed from within the kernel
	   once it's been created there's no way to roll back the creation of an
	   incomplete system object.  In fact it's not even clear what *could* 
	   cause a failure at this point apart from "circumstances beyond our 
	   control" (memory corruption, a coding error, or something similar).  
	   Because this is a can't-occur situation the best course of action for 
	   backing out of having a partially-initialised system object that's 
	   created at, and exists at, a level below what the standard system 
	   cleanup routines can handle is uncertain.
	   
	   At the moment we just exit.  This is somewhat ugly, but it's not 
	   really clear what other action we can take in the error handler for a 
	   can-never-occur error */
	initStatus = openDevice( &iSystemObject, CRYPT_UNUSED, CRYPT_DEVICE_NONE,
							 NULL, 0, &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	ENSURES( iSystemObject == SYSTEM_OBJECT_HANDLE );

	/* We've finished setting up the object-type-specific information, tell 
	   the kernel that the object is ready for use */
	status = krnlSendMessage( iSystemObject, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );

	/* The object has been initialised, move it into the initialised state */
	return( krnlSendMessage( iSystemObject, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_UNUSED,
							 CRYPT_IATTRIBUTE_INITIALISED ) );
	}

/* Create the crypto device object */

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )

CHECK_RETVAL \
static int createCryptoDeviceObject( void )
	{
	CRYPT_DEVICE iCryptoDeviceObject;
	DEVICE_INFO *deviceInfoPtr;
	int initStatus, status;

	/* Pass the call on to the lower-level function.  See the comments for 
	   createSystemDeviceObject() for error handling */
	initStatus = openDevice( &iCryptoDeviceObject, 
							 DEFAULTUSER_OBJECT_HANDLE, CRYPT_DEVICE_HARDWARE, 
							 NULL, 0, &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	ENSURES( iCryptoDeviceObject == CRYPTO_OBJECT_HANDLE );

	/* We've finished setting up the object-type-specific information, tell 
	   the kernel that the object is ready for use */
	status = krnlSendMessage( iCryptoDeviceObject, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );

	/* Exit without moving the object into the initialised state as we would
	   for other objects because it's created before the system 
	   initialisation has completed and so isn't completely initialised 
	   until the CRYPT_IATTRIBUTE_COMPLETEINIT attribute is explicitly set 
	   for it */
	return( CRYPT_OK );
	}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

/* Generic management function for this class of object.  Unlike the usual
   multilevel init process which is followed for other objects, the devices
   have an OR rather than an AND relationship since the devices are
   logically independent so we set a flag for each device type that's
   successfully initialised rather than recording an init level */

typedef CHECK_RETVAL int ( *DEVICEINIT_FUNCTION )( void );
typedef void ( *DEVICEND_FUNCTION )( void );
typedef struct {
	const DEVICEINIT_FUNCTION deviceInitFunction;
	const DEVICEND_FUNCTION deviceEndFunction;
	const int initFlag;
	} DEVICEINIT_INFO;
		
#define DEV_NONE_INITED			0x00
#define DEV_PKCS11_INITED		0x01
#define DEV_CRYPTOAPI_INITED	0x02
#define DEV_TPM_INITED			0x04
#define DEV_HARDWARE_INITED		0x08

CHECK_RETVAL \
int deviceManagementFunction( IN_ENUM( MANAGEMENT_ACTION ) \
								const MANAGEMENT_ACTION_TYPE action )
	{
	static const DEVICEINIT_INFO deviceInitTbl[] = {
#ifdef USE_PKCS11
		{ deviceInitPKCS11, deviceEndPKCS11, DEV_PKCS11_INITED },
#endif /* USE_PKCS11 */
#ifdef USE_TPM
		{ deviceInitTPM, deviceEndTPM, DEV_TPM_INITED },
#endif /* USE_TPM */
#ifdef USE_CRYPTOAPI
		{ deviceInitCryptoAPI, deviceEndCryptoAPI, DEV_CRYPTOAPI_INITED },
#endif /* USE_CRYPTOAPI */
#ifdef USE_HARDWARE 
  #if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		{ NULL, deviceEndHardware, DEV_HARDWARE_INITED },
  #else
		{ deviceInitHardware, deviceEndHardware, DEV_HARDWARE_INITED },
  #endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
#endif /* USE_HARDWARE */
		{ NULL, NULL, 0 }, { NULL, NULL, 0 }
		};
	static int initFlags = DEV_NONE_INITED;
	LOOP_INDEX i;
	int status;

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	REQUIRES( action == MANAGEMENT_ACTION_PRE_INIT || \
			  action == MANAGEMENT_ACTION_INIT || \
			  action == MANAGEMENT_ACTION_INIT_DEFERRED || \
			  action == MANAGEMENT_ACTION_PRE_SHUTDOWN || \
			  action == MANAGEMENT_ACTION_SHUTDOWN );
#else
	REQUIRES( action == MANAGEMENT_ACTION_PRE_INIT || \
			  action == MANAGEMENT_ACTION_INIT_DEFERRED || \
			  action == MANAGEMENT_ACTION_PRE_SHUTDOWN || \
			  action == MANAGEMENT_ACTION_SHUTDOWN );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	switch( action )
		{
		case MANAGEMENT_ACTION_PRE_INIT:
			initFlags = DEV_NONE_INITED;
			status = createSystemDeviceObject();
			if( cryptStatusError( status ) )
				{ 
				DEBUG_DIAG(( "System object creation failed" )); 
				return( status );
				}
			DEBUG_DIAG(( "Created system object" )); 
			return( CRYPT_OK );

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		case MANAGEMENT_ACTION_INIT:
			/* Since we're using the hardware device to provide our crypto
			   capabilities we need to initialise it now, not during the
			   deferred-init stage */
			status = deviceInitHardware();
			if( cryptStatusError( status ) )
				{
				DEBUG_DIAG(( "Crypto hardware initialisation failed" ));
				return( status );
				}
			initFlags |= DEV_HARDWARE_INITED;
			status = createCryptoDeviceObject();
			if( cryptStatusError( status ) )
				{ 
				DEBUG_DIAG(( "Crypto object creation failed" )); 
				return( status );
				}
			DEBUG_DIAG(( "Created crypto object" )); 
			return( CRYPT_OK );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

		case MANAGEMENT_ACTION_INIT_DEFERRED:
#ifndef CONFIG_FUZZ
			LOOP_SMALL( i = 0,
						i < FAILSAFE_ARRAYSIZE( deviceInitTbl, \
												DEVICEINIT_INFO ) && \
							deviceInitTbl[ i ].deviceInitFunction != NULL,
						i++ )
				{
				ENSURES( LOOP_INVARIANT_SMALL( i, 0, \
											   FAILSAFE_ARRAYSIZE( deviceInitTbl, \
																   DEVICEINIT_INFO ) - 1 ) );
				if( krnlIsExiting() )
					{
					/* The kernel is shutting down, exit */
					return( CRYPT_ERROR_PERMISSION );
					}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
				if( deviceInitTbl[ i ].deviceInitFunction == NULL )
					{
					/* If we're using the hardware device to provide our 
					   crypto capabilities then it'll already have been
					   initialised as an init action */
					continue;
					}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
				status = deviceInitTbl[ i ].deviceInitFunction();
				if( cryptStatusOK( status ) )
					initFlags |= deviceInitTbl[ i ].initFlag;
				}
			ENSURES( LOOP_BOUND_OK );
			ENSURES( i < FAILSAFE_ARRAYSIZE( deviceInitTbl, \
											 DEVICEINIT_INFO ) );
#endif /* !CONFIG_FUZZ */
			return( CRYPT_OK );

		case MANAGEMENT_ACTION_PRE_SHUTDOWN:
			/* In theory we could signal the background entropy poll to 
			   start wrapping up at this point, however if the background 
			   polling is being performed in a thread or task then the 
			   shutdown is already signalled via the kernel shutdown flag.  
			   If it's performed by forking off a process, as it is on Unix 
			   systems, there's no easy way to communicate with this process 
			   so the shutdown function just kill()s it.  Because of this we 
			   don't try and do anything here, although this call is left in 
			   place as a no-op in case it's needed in the future */
			return( CRYPT_OK );

		case MANAGEMENT_ACTION_SHUTDOWN:
			LOOP_MED( i = 0,
					  i < FAILSAFE_ARRAYSIZE( deviceInitTbl, \
											  DEVICEINIT_INFO ) && \
						  deviceInitTbl[ i ].deviceEndFunction != NULL,
					  i++ )
				{
				ENSURES( LOOP_INVARIANT_MED( i, 0, \
											 FAILSAFE_ARRAYSIZE( deviceInitTbl, \
																 DEVICEINIT_INFO ) - 1 ) );
				if( initFlags & deviceInitTbl[ i ].initFlag )
					deviceInitTbl[ i ].deviceEndFunction();
				}
			ENSURES( LOOP_BOUND_OK );
			ENSURES( i < FAILSAFE_ARRAYSIZE( deviceInitTbl, \
											 DEVICEINIT_INFO ) );
			return( CRYPT_OK );
		}

	retIntError();
	}
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
