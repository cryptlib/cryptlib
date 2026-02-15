/****************************************************************************
*																			*
*					cryptlib Crypto Device Attribute Routines				*
*						Copyright Peter Gutmann 1997-2019					*
*																			*
****************************************************************************/

#include "crypt.h"
#ifdef INC_ALL
  #include "capabil.h"
  #include "device.h"
#else
  #include "device/capabil.h"
  #include "device/device.h"
#endif /* Compiler-specific includes */

/* When we get random data from a device we run the (practical) FIPS 140 
   tests over the output to make sure that it's really random, at least as 
   far as the tests can tell us.  If the data fails the test then we get 
   more and try again.  The following value defines how many times we retry 
   before giving up.  In test runs, a count of 2 failures is reached every 
   ~50,000 iterations, 5 is never reached (in fact with 1M tests, 3 is 
   never reached) */

#define NO_ENTROPY_FAILURES		5

/* The size of the random data sample that we use when constructing a random
   data block with no zero bytes for PKCS #1 padding.  This is a little 
   complex because we don't know how much data we'll need, although as a 
   rule of thumb it'll be size + ( size / 256 ) bytes.  However in a worst-
   case situation we could need to draw out megabytes of data.  To deal with
   this we copy out 256 bytes worth at a time (a typical value for a 2K bit 
   key) and keep going until we've filled the output requirements */

#define RANDOM_SAMPLE_SIZE		min( 256, CRYPT_MAX_PKCSIZE )

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitError( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  IN_ENUM( CRYPT_ERRTYPE ) const CRYPT_ERRTYPE_TYPE errorType, 
					  IN_ERROR const int status )
	{
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );
	REQUIRES( isEnumRange( errorType, CRYPT_ERRTYPE ) );
	REQUIRES( cryptStatusError( status ) );

	setObjectErrorInfo( deviceInfoPtr, errorLocus, errorType );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorInited( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( deviceInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT,
					   CRYPT_ERROR_INITED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorNotFound( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
							  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( deviceInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTFOUND ) );
	}

/****************************************************************************
*																			*
*							Read a Random-data Attribute					*
*																			*
****************************************************************************/

/* Get a random data block with FIPS 140 checking */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getRandomChecked( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
							 OUT_BUFFER_FIXED( length ) void *data,
							 IN_LENGTH_SHORT const int length,
							 INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	const DEV_GETRANDOMFUNCTION getRandomFunction = \
				( DEV_GETRANDOMFUNCTION ) \
				FNPTR_GET( deviceInfoPtr->getRandomFunction );
	LOOP_INDEX i;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( data, length ) );
	assert( messageExtInfo == NULL || \
			( isWritePtr( messageExtInfo, \
						  sizeof( MESSAGE_FUNCTION_EXTINFO ) ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( getRandomFunction != NULL );

	/* Get random data from the device and check it using the FIPS 140 
	   tests.  If it's less than MIN_KEYSIZE then we let it pass since the 
	   sample size is too small to be useful.  Samples this small are only 
	   ever drawn from the generator for use as padding with crypto keys 
	   that are always >= MIN_KEYSIZE which will themselves have been 
	   checked when they were read, so a problem with the generator will be 
	   detected even if we don't check small samples */
	LOOP_SMALL( i = 0, i < NO_ENTROPY_FAILURES, i++ )
		{
		int status;

		ENSURES( LOOP_INVARIANT_SMALL( i, 0, NO_ENTROPY_FAILURES - 1 ) );

		status = getRandomFunction( deviceInfoPtr, data, length, 
									messageExtInfo );
		if( cryptStatusOK( status ) && \
			( length < MIN_KEYSIZE || checkEntropy( data, length ) ) )
			return( CRYPT_OK );
		}
	ENSURES( LOOP_BOUND_OK );

	/* We couldn't get anything that passed the FIPS 140 tests, we can't
	   go any further */
	REQUIRES( isShortIntegerRangeNZ( length ) ); 
	zeroise( data, length );
	DEBUG_DIAG(( "Random data didn't pass FIPS 140 tests after %d "
				 "iterations", NO_ENTROPY_FAILURES ));
	assert( DEBUG_WARN );
	return( CRYPT_ERROR_RANDOM );
	}

/* Get a random data block with no zero bytes, for PKCS #1 padding */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getRandomNonzero( INOUT_PTR DEVICE_INFO *deviceInfoPtr, 
							 OUT_BUFFER_FIXED( length ) void *data,
							 IN_LENGTH_SHORT const int length )
	{
	BYTE randomBuffer[ RANDOM_SAMPLE_SIZE + 8 ], *outBuffer = data;
	LOOP_INDEX count;
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( data, length ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );

	/* The extraction of data is a little complex because we don't know how 
	   much data we'll need, so we copy out RANDOM_SAMPLE_SIZE bytes worth 
	   at a time and keep going until we've filled the output requirements */
	LOOP_LARGE_INITCHECK( count = 0, count < length )
		{
		LOOP_INDEX_ALT i;

		ENSURES( LOOP_INVARIANT_LARGE_XXX( count, 0, length - 1 ) );

		/* Copy as much as we can from the randomness pool */
		status = getRandomChecked( deviceInfoPtr, randomBuffer, 
								   RANDOM_SAMPLE_SIZE, NULL );
		if( cryptStatusError( status ) )
			{
			REQUIRES( isShortIntegerRangeNZ( length ) ); 
			zeroise( data, length );
			return( status );
			}
		LOOP_LARGE_ALT( i = 0, count < length && \
							   i < RANDOM_SAMPLE_SIZE, i++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE_ALT( i, 0, \
											   RANDOM_SAMPLE_SIZE - 1 ) );
			ENSURES( LOOP_INVARIANT_SECONDARY( count, 0, length - 1 ) );

			if( randomBuffer[ i ] != 0 )
				outBuffer[ count++ ] = randomBuffer[ i ];
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		}
	ENSURES( LOOP_BOUND_OK );
	FORALL( i, 0, length, \
			outBuffer[ i ] != 0 );
	zeroise( randomBuffer, RANDOM_SAMPLE_SIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get Attributes								*
*																			*
****************************************************************************/

/* Get a numeric/boolean attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int getDeviceAttribute( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
						OUT_INT_Z int *valuePtr, 
						IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( valuePtr, sizeof( int ) ) );
	assert( isWritePtr( messageExtInfo, \
			sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	switch( attribute )
		{
		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = deviceInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = deviceInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_DEVINFO_LOGGEDIN:
			if( TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_REMOVABLE ) )
				{
				const DEV_CONTROLFUNCTION controlFunction = \
							( DEV_CONTROLFUNCTION ) \
							FNPTR_GET( deviceInfoPtr->controlFunction );

				int status;

				REQUIRES( controlFunction != NULL );

				/* If it's a removable device then the user could implicitly 
				   log out by removing it so we have to perform an explicit 
				   check to see whether it's still there */
				status = controlFunction( deviceInfoPtr, 
									CRYPT_DEVINFO_LOGGEDIN, NULL, 0, NULL );
				if( cryptStatusError( status ) )
					return( status );
				assert( !isMessageObjectUnlocked( messageExtInfo ) );
				}
			*valuePtr = TEST_FLAG( deviceInfoPtr->flags, 
								   DEVICE_FLAG_LOGGEDIN ) ? TRUE : FALSE;
			return( CRYPT_OK );

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		case CRYPT_IATTRIBUTE_HWSTORAGE:
			REQUIRES( deviceInfoPtr->type == CRYPT_DEVICE_HARDWARE );

			*valuePtr = deviceInfoPtr->deviceHardware->iCryptKeyset;
			return( CRYPT_OK );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
		}

	retIntError();
	}

/* Get a string attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int getDeviceAttributeS( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
						 INOUT_PTR MESSAGE_DATA *msgData, 
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						 MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( msgData, sizeof( MESSAGE_DATA ) ) );
	assert( isWritePtr( messageExtInfo, \
			sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	switch( attribute )
		{
		case CRYPT_ATTRIBUTE_ERRORMESSAGE:
			{
#ifdef USE_ERRMSGS
			const ERROR_INFO *errorInfo = DEVICE_ERRINFO;

			if( errorInfo->errorStringLength > 0 )
				{
				return( attributeCopy( msgData, errorInfo->errorString,
									   errorInfo->errorStringLength ) );
				}
#endif /* USE_ERRMSGS */
			return( exitErrorNotFound( deviceInfoPtr,
									   CRYPT_ATTRIBUTE_ERRORMESSAGE ) );
			}

		case CRYPT_DEVINFO_LABEL:
			if( deviceInfoPtr->label == NULL )
				{
				return( exitErrorNotFound( deviceInfoPtr,
										   CRYPT_DEVINFO_LABEL ) );
				}
			return( attributeCopy( msgData, deviceInfoPtr->label,
								   deviceInfoPtr->labelLen ) );

		case CRYPT_IATTRIBUTE_RANDOM:
			{	
			const DEV_GETRANDOMFUNCTION getRandomFunction = \
						( DEV_GETRANDOMFUNCTION ) \
						FNPTR_GET( deviceInfoPtr->getRandomFunction );

			if( getRandomFunction == NULL )
				return( CRYPT_ERROR_RANDOM );
			return( getRandomChecked( deviceInfoPtr, msgData->data,
									  msgData->length, messageExtInfo ) );
			}

		case CRYPT_IATTRIBUTE_RANDOM_NZ:
			{
			const DEV_GETRANDOMFUNCTION getRandomFunction = \
						( DEV_GETRANDOMFUNCTION ) \
						FNPTR_GET( deviceInfoPtr->getRandomFunction );

			if( getRandomFunction == NULL )
				return( CRYPT_ERROR_RANDOM );
			return( getRandomNonzero( deviceInfoPtr, msgData->data,
									  msgData->length ) );
			}

		case CRYPT_IATTRIBUTE_RANDOM_NONCE:
			{
			const DEV_GETRANDOMFUNCTION getRandomFunction = \
						( DEV_GETRANDOMFUNCTION ) \
						FNPTR_GET( deviceInfoPtr->getRandomFunction );
			const DEV_CONTROLFUNCTION controlFunction = \
						( DEV_CONTROLFUNCTION ) \
						FNPTR_GET( deviceInfoPtr->controlFunction );

			REQUIRES( controlFunction != NULL );

			if( getRandomFunction == NULL )
				return( CRYPT_ERROR_RANDOM );

			return( controlFunction( deviceInfoPtr, 
									 CRYPT_IATTRIBUTE_RANDOM_NONCE,
									 msgData->data, msgData->length, 
									 messageExtInfo ) );
			}

		case CRYPT_IATTRIBUTE_TIME:
			{
			const DEV_CONTROLFUNCTION controlFunction = \
						( DEV_CONTROLFUNCTION ) \
						FNPTR_GET( deviceInfoPtr->controlFunction );
			time_t *timePtr = msgData->data;
			int status;

			REQUIRES( controlFunction != NULL );

			/* If the device doesn't contain a time source then we can't 
			   provide time information */
			if( !TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_TIME ) )
				return( CRYPT_ERROR_NOTAVAIL );

			/* Get the time from the device */
			status = controlFunction( deviceInfoPtr, CRYPT_IATTRIBUTE_TIME,
									  msgData->data, msgData->length, NULL );
			if( cryptStatusError( status ) )
				return( status );

			/* Perform a sanity check on the returned value, if it's too far 
			   out then we don't trust it */
			if( *timePtr <= MIN_TIME_VALUE )
				{
				*timePtr = 0;
				return( CRYPT_ERROR_NOTAVAIL );
				}

			return( CRYPT_OK );
			}
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Set Attributes								*
*																			*
****************************************************************************/

/* Set a numeric/boolean attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
int setDeviceAttribute( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
						IN_INT_Z const int value, 
						IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	const DEV_CONTROLFUNCTION controlFunction = \
				( DEV_CONTROLFUNCTION ) \
				FNPTR_GET( deviceInfoPtr->controlFunction );

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
			sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
#if defined( USE_HARDWARE ) || defined( USE_TPM )
	REQUIRES( ( attribute == CRYPT_IATTRIBUTE_COMMITNOTIFY && \
			    value == CRYPT_UNUSED ) || \
			  isIntegerRange( value ) );
#else
	REQUIRES( isIntegerRange( value ) );
#endif /* USE_HARDWARE || USE_TPM */
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );
	REQUIRES( controlFunction != NULL );

	/* Send the control information to the device */
	return( controlFunction( deviceInfoPtr, attribute, NULL, value, 
							 messageExtInfo ) );
	}

/* Set a string attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int setDeviceAttributeS( INOUT_PTR DEVICE_INFO *deviceInfoPtr,
						 IN_BUFFER( dataLength ) const void *data,
						 IN_LENGTH const int dataLength,
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						 MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	const DEV_CONTROLFUNCTION controlFunction = \
				( DEV_CONTROLFUNCTION ) \
				FNPTR_GET( deviceInfoPtr->controlFunction );
	int status;

	assert( isWritePtr( deviceInfoPtr, sizeof( DEVICE_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );
	assert( isWritePtr( messageExtInfo, \
			sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( dataLength ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );
	REQUIRES( controlFunction != NULL );

	/* If the user is logging on to the device we have to perform a bit of 
	   extra processing */
	if( attribute == CRYPT_DEVINFO_AUTHENT_USER || \
		attribute == CRYPT_DEVINFO_AUTHENT_SUPERVISOR )
		{
		const DEV_GETRANDOMFUNCTION getRandomFunction = \
					( DEV_GETRANDOMFUNCTION ) \
					FNPTR_GET( deviceInfoPtr->getRandomFunction );

		/* Make sure that a login is actually required for the device */
		if( !TEST_FLAG( deviceInfoPtr->flags, DEVICE_FLAG_NEEDSLOGIN ) )
			return( exitErrorInited( deviceInfoPtr, attribute ) );

		/* Send the logon information to the device */
		status = controlFunction( deviceInfoPtr, attribute,
								  ( void * ) data, dataLength, 
								  messageExtInfo );
		if( cryptStatusError( status ) )
			return( status );
		assert( !isMessageObjectUnlocked( messageExtInfo ) );

		/* The user has logged in, if the token has a hardware RNG grab 256 
		   bits of entropy and send it to the system device.  Since we have 
		   no idea how good this entropy is (it could be just a DES-based 
		   PRNG using a static key or even an LFSR, which some smart cards 
		   use) we don't set any entropy quality indication */
		if( getRandomFunction != NULL )
			{
			BYTE buffer[ 32 + 8 ];

			status = getRandomFunction( deviceInfoPtr, buffer, 32, NULL );
			if( cryptStatusOK( status ) )
				{
				MESSAGE_DATA msgData;

				setMessageData( &msgData, buffer, 32 );
				( void ) krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
										  IMESSAGE_SETATTRIBUTE_S, &msgData, 
										  CRYPT_IATTRIBUTE_ENTROPY );
				}
			zeroise( buffer, 32 );
			}

		return( CRYPT_OK );
		}

	/* Send the control information to the device */
	return( controlFunction( deviceInfoPtr, attribute, 
							 ( void * ) data, dataLength, messageExtInfo ) );
	}
