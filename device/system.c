<<<<<<< HEAD
/****************************************************************************
*																			*
*						cryptlib System Device Routines						*
*						Copyright Peter Gutmann 1995-2021					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "capabil.h"
  #include "device.h"
  #include "objectfns.h"
  #include "random.h"
#else
  #include "crypt.h"
  #include "device/capabil.h"
  #include "device/device.h"
  #include "kernel/objectfns.h"
  #include "random/random.h"
#endif /* Compiler-specific includes */

/* Mechanisms supported by the system device.  Since the mechanism space is 
   sparse, dispatching is handled by looking up the required mechanism in a 
   table of (action, mechanism, function) triples.  The table is sorted by 
   order of most-frequently-used mechanisms to speed things up, although the 
   overhead is vanishingly small anyway */

static const MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
#ifdef USE_PKC
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
  #if defined( USE_TLS ) && defined( USE_RSA_SUITES )
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1_RAW, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1_RAW, ( MECHANISM_FUNCTION ) importPKCS1 },
  #endif /* USE_TLS && USE_RSA_SUITES */
  #ifdef USE_OAEP
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_OAEP, ( MECHANISM_FUNCTION ) exportOAEP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_OAEP, ( MECHANISM_FUNCTION ) importOAEP },
  #endif /* USE_OAEP */
  #ifdef USE_PSS
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PSS, ( MECHANISM_FUNCTION ) signPSS },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PSS, ( MECHANISM_FUNCTION ) sigcheckPSS },
  #endif /* USE_PSS */
#endif /* USE_PKC */
#ifdef USE_PGP
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1_PGP, ( MECHANISM_FUNCTION ) exportPKCS1PGP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1_PGP, ( MECHANISM_FUNCTION ) importPKCS1PGP },
#endif /* USE_PGP */
#ifdef USE_INT_CMS
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_CMS, ( MECHANISM_FUNCTION ) exportCMS },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_CMS, ( MECHANISM_FUNCTION ) importCMS },
#endif /* USE_INT_CMS */
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
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_SSL, ( MECHANISM_FUNCTION ) deriveSSL },
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_TLS, ( MECHANISM_FUNCTION ) deriveTLS },
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_TLS12, ( MECHANISM_FUNCTION ) deriveTLS12 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_TLS, ( MECHANISM_FUNCTION ) signTLS },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_TLS, ( MECHANISM_FUNCTION ) sigcheckTLS },
#endif /* USE_TLS */
#ifdef USE_CMP
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_CMP, ( MECHANISM_FUNCTION ) deriveCMP },
#endif /* USE_CMP */
#ifdef USE_PKCS12
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_PKCS12, ( MECHANISM_FUNCTION ) derivePKCS12 },
#endif /* USE_PKCS12 */
#if defined( USE_KEYSETS ) && defined( USE_PKC )
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP, ( MECHANISM_FUNCTION ) exportPrivateKey },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP, ( MECHANISM_FUNCTION ) importPrivateKey },
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP_EXT, ( MECHANISM_FUNCTION ) exportPrivateKeyExt },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_EXT, ( MECHANISM_FUNCTION ) importPrivateKeyExt },
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP_PKCS8, ( MECHANISM_FUNCTION ) exportPrivateKeyPKCS8 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_PKCS8, ( MECHANISM_FUNCTION ) importPrivateKeyPKCS8 },
#endif /* USE_KEYSETS && USE_PKC */
#ifdef USE_PGPKEYS
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_PGP2, ( MECHANISM_FUNCTION ) importPrivateKeyPGP2 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_OPENPGP_OLD, ( MECHANISM_FUNCTION ) importPrivateKeyOpenPGPOld },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_OPENPGP, ( MECHANISM_FUNCTION ) importPrivateKeyOpenPGP },
#endif /* USE_PGPKEYS */
#ifndef CONFIG_NO_SELFTEST
	{ MESSAGE_DEV_EXPORT, MECHANISM_SELFTEST_ENC, ( MECHANISM_FUNCTION ) pkcWrapSelftest },
	{ MESSAGE_DEV_SIGN, MECHANISM_SELFTEST_SIG, ( MECHANISM_FUNCTION ) signSelftest },
	{ MESSAGE_DEV_DERIVE, MECHANISM_SELFTEST_DERIVE, ( MECHANISM_FUNCTION ) deriveSelftest },
	{ MESSAGE_DEV_KDF, MECHANISM_SELFTEST_KDF, ( MECHANISM_FUNCTION ) kdfSelftest },
#endif /* CONFIG_NO_SELFTEST */
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }, { MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Object creation functions supported by the system device.  These are
   sorted in order of frequency of use in order to make lookups a bit
   faster */

static const CREATEOBJECT_FUNCTION_INFO createObjectFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext },
#ifdef USE_CERTIFICATES
	{ OBJECT_TYPE_CERTIFICATE, createCertificate },
#endif /* USE_CERTIFICATES */
#ifdef USE_ENVELOPES
	{ OBJECT_TYPE_ENVELOPE, createEnvelope },
#endif /* USE_ENVELOPES */
#ifdef USE_SESSIONS
	{ OBJECT_TYPE_SESSION, createSession },
#endif /* USE_SESSIONS */
#ifdef USE_KEYSETS
	{ OBJECT_TYPE_KEYSET, createKeyset },
#endif /* USE_KEYSETS */
	{ OBJECT_TYPE_DEVICE, createDevice },
	{ OBJECT_TYPE_USER, createUser },
	{ OBJECT_TYPE_NONE, NULL }, { OBJECT_TYPE_NONE, NULL }
	};

/****************************************************************************
*																			*
*								Randomness Functions						*
*																			*
****************************************************************************/

/* Get random data.  We have to unlock the device around the randomness 
   fetch because background polling threads need to be able to send entropy
   data to it:

				System			Randomness
				------			----------
	getRand ------>|				|
			   [Suspend]			|
				   |--------------->|
				   |				|
				   |<===============| Entropy
				   |<===============| Entropy
				   |<===============| Entropy Quality
				   |				|
				   |<---------------|
			   [Resume]				|
   
   If the caller has specified that it's unlockable and the reference count
   is one or less (meaning that we've been sent the message directly), we 
   leave it unlocked.  Otherwise we re-lock it afterwards. 

   Note that there's a tiny chance of a race condition if the system object 
   is destroyed between the unlock and the acquisition of the randomness 
   mutex (which means that the randomInfo could be freed while we're getting 
   the random data), however there's no easy way around this short of using
   a complex multiple-mutex interlock, and in any case there's only so much 
   that we can do to help a user who pulls data structures out from under 
   active threads */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getRandomFunction( INOUT_PTR DEVICE_INFO *deviceInfo, 
							  OUT_BUFFER_FIXED( length ) void *buffer,
							  IN_LENGTH_SHORT const int length, 
							  INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	void *randomInfoPtr = DATAPTR_GET( deviceInfo->deviceSystem->randomInfo );
	int refCount, status;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( sanityCheckDevice( deviceInfo ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( randomInfoPtr != NULL );

	/* Clear the return value and make sure that we fail the FIPS 140 tests
	   on the output if there's a problem */
	REQUIRES( isShortIntegerRangeNZ( length ) ); 
	zeroise( buffer, length );

	/* If the system device is already unlocked (which can happen if this 
	   function is called in a loop, for example if multiple chunks of 
	   randomness are read) just return the randomness directly */
	if( messageExtInfo != NULL && isMessageObjectUnlocked( messageExtInfo ) )
		return( getRandomData( randomInfoPtr, buffer, length ) );

	/* Unlock the system device, get the data, and re-lock it if necessary.
	   This is necessary for two reasons, firstly because the background 
	   poll can take awhile and we don't want to block all messages to the
	   system object while it's in progress, and secondly so that the 
	   background polling thread can send entropy to the system object */
	status = krnlSuspendObject( deviceInfo->objectHandle, &refCount );
	if( cryptStatusError( status ) )
		return( status );
	status = getRandomData( randomInfoPtr, buffer, length );
	if( messageExtInfo == NULL || refCount > 1 )
		{
		int resumeStatus;

		/* The object isn't unlockable or it's been locked recursively, 
		   re-lock it */
		resumeStatus = krnlResumeObject( SYSTEM_OBJECT_HANDLE, refCount );
		if( cryptStatusError( resumeStatus ) )
			{
			/* We couldn't re-lock the system object, let the caller know.
			   Since this is a shouldn't-occur condition we also warn the 
			   user in the debug version */
			DEBUG_DIAG(( "Failed to re-lock system object" ));
			assert( DEBUG_WARN );
			if( messageExtInfo != NULL )
				setMessageObjectUnlocked( messageExtInfo );
			}
		}
	else
		{
		/* Tell the caller that we've left the object unlocked so they don't
		   have to do anything further with it */
		setMessageObjectUnlocked( messageExtInfo );
		}
	return( status );
	}

/* Get a random (but not necessarily cryptographically strong random) nonce.
   Some nonces can simply be fresh (for which a monotonically increasing
   sequence will do), some should be random (for which a hash of the
   sequence is adequate), and some need to be unpredictable.  In order to
   avoid problems arising from the inadvertent use of a nonce with the wrong
   properties we use unpredictable nonces in all cases, even where it isn't
   strictly necessary.

   This simple generator divides the nonce state into a public section of
   the same size as the hash output and a private section that contains 64
   bits of data from the crypto RNG, which influences the public section.
   The public and private sections are repeatedly hashed to produce the
   required amount of output.  Note that this leaks a small amount of
   information about the crypto RNG output since an attacker knows that
   public_state_n = hash( public_state_n - 1, private_state ) but this
   isn't a major weakness */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checksumNonceData( INOUT_PTR SYSTEMDEV_INFO *systemInfo )
	{
	const int oldChecksum = systemInfo->nonceChecksum;
	int newChecksum;

	assert( isWritePtr( systemInfo, sizeof( SYSTEMDEV_INFO ) ) );

	systemInfo->nonceChecksum = 0;
	newChecksum = checksumData( systemInfo, sizeof( SYSTEMDEV_INFO ) );
	systemInfo->nonceChecksum = newChecksum;

	return( ( oldChecksum == newChecksum ) ? TRUE : FALSE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getNonce( INOUT_PTR DEVICE_INFO *deviceInfo, 
					 OUT_BUFFER_FIXED( dataLength ) void *data, 
					 IN_LENGTH_SHORT const int dataLength )
	{
	SYSTEMDEV_INFO *systemInfo = deviceInfo->deviceSystem;
	HASH_FUNCTION_ATOMIC nonceHashFunction;
	BYTE *noncePtr = data;
	int nonceLength, status, LOOP_ITERATOR;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( data, dataLength ) );

	REQUIRES( isShortIntegerRangeNZ( dataLength ) );

	/* Handling of CRYPT_IATTRIBUTE_RANDOM_NONCE gets complicated because 
	   it may trigger an entropy poll the first time that it's called, for 
	   which the system device has to be unlocked so that it doesn't stall 
	   or block any subsequent messages to the device.  The normal process 
	   for this is:

		kSendMsg( GETATTR_S, IATTR_NONCE );
		system.c:getNonce() ->
			kSendMsg( GETATTR_S, IATTR_RANDOM );

		system.c:getRandomFunction() ->
			kSuspendObj( SYSTEM_DEVICE );

			random.c:getRandomData() ->			
				if( randomQual < 100 )
					slowPoll();
												kSendMsg( SETATTR_S, IATTR_ENTROPY );
												kSendMsg( SETATTR_S, IATTR_ENTROPY_QUAL );
			kResumeObj( SYSTEM_DEVICE );

	   In the presence of a second thread that sends a 
	   CRYPT_IATTRIBUTE_RANDOM_NONCE message to the system device we have:

		kSendMsg( GETATTR_S, IATTR_NONCE );		kSendMsg( GETATTR_S, IATTR_NONCE );
		system.c:getNonce() ->
			kSendMsg( GETATTR_S, IATTR_RANDOM );

		system.c:getRandomFunction() ->
			kSuspendObj( SYSTEM_DEVICE );
												system.c:getNonce() ->
													kSendMsg( GETATTR_S, IATTR_RANDOM );

	   At this point two threads are both in getNonce().  Since the system 
	   object is already unlocked, kSuspendObj() isn't called and the code 
	   path continues:

			random.c:getRandomData();			random.c:getRandomData();

	   random.c:getRandomData() uses MUTEX_RANDOM to enforce mutual 
	   exclusion, but before that the system device's randomness functions 
	   aren't protected.  This only affects CRYPT_IATTRIBUTE_RANDOM_NONCE 
	   and not the other get-randomness functions because they call directly 
	   into the randomness subsystem, but the nonce RNG is implemented in 
	   the system device which is unlocked at this point.

	   Dealing with this requires protecting the nonce initialisation with 
	   its own mutex */
	status = krnlEnterMutex( MUTEX_RANDOMNONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* If the nonce generator hasn't been initialised yet we set up the
	   hashing and get 64 bits of private nonce state.  What to do if the
	   attempt to initialise the state fails is somewhat debatable.  Since
	   nonces are only ever used in protocols alongside crypto keys and an
	   RNG failure will be detected when the key is generated we can
	   generally ignore a failure at this point.  
	   
	   However nonces are sometimes also used in non-crypto contexts (for 
	   example to generate certificate serial numbers) where this detection 
	   in the RNG won't happen.  On the other hand we shouldn't really abort 
	   processing just because we can't get some no-value nonce data so what 
	   we do is retry the fetch of nonce data (in case the system object was 
	   busy and the first attempt timed out) and if that fails too fall back 
	   to the system time.  
	   
	   This is no longer unpredictable, but the only location where 
	   unpredictability matters is when used in combination with crypto 
	   operations for which the absence of random data will be detected 
	   during key generation */
	if( !systemInfo->nonceDataInitialised )
		{
		HASH_FUNCTION_ATOMIC hashFunction;
		MESSAGE_DATA msgData;
		int hashSize;

		/* Get the 64-bit private portion of the nonce data, which follows
		   the public portion at the start of the buffer.  Note that we
		   have to set the nonceHashSize after we get the random data since
		   the device information is sanity-checked when we send the get-
		   random message to it and a nonceHashSize with no nonce data would 
		   fail the sanity check */
		getHashAtomicParameters( CRYPT_ALGO_SHA1, 0,
								 &hashFunction, &hashSize );
		setMessageData( &msgData, systemInfo->nonceData + hashSize, 
								  NONCERNG_PRIVATE_STATESIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM );
		if( cryptStatusError( status ) )
			{
			/* The fetch failed, retry it */
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM );
			}
		if( cryptStatusError( status ) )
			{
			const time_t theTime = getTime( GETTIME_NOFAIL );

			/* The second fetch failed as well, fall back on a last-resort
			   nonce seed value */
			memcpy( systemInfo->nonceData + hashSize, 
					&theTime, sizeof( time_t ) );
			}
		FNPTR_SET( systemInfo->nonceHashFunction, hashFunction );
		systemInfo->nonceHashSize = hashSize;
		systemInfo->nonceDataInitialised = TRUE;
		( void ) checksumNonceData( systemInfo );

		ENSURES_KRNLMUTEX( systemInfo->nonceHashSize >= MIN_HASHSIZE && \
						   systemInfo->nonceHashSize <= CRYPT_MAX_HASHSIZE,
						   MUTEX_RANDOMNONCE );
		ENSURES_KRNLMUTEX( isEmptyData( systemInfo->nonceData, 0 ), 
						   MUTEX_RANDOMNONCE );
		ENSURES_KRNLMUTEX( !isEmptyData( systemInfo->nonceData + \
										 systemInfo->nonceHashSize, 0 ),
						   MUTEX_RANDOMNONCE );
		}
	ENSURES( checksumNonceData( systemInfo ) );

	/* Shuffle the public state and copy it to the output buffer until it's
	   full */
	nonceHashFunction = ( HASH_FUNCTION_ATOMIC ) \
						FNPTR_GET( systemInfo->nonceHashFunction );
	ENSURES( nonceHashFunction != NULL );
	LOOP_LARGE_REV_INITCHECK( nonceLength = dataLength, nonceLength > 0 )
		{
		const int bytesToCopy = min( nonceLength, systemInfo->nonceHashSize );

		ENSURES( LOOP_INVARIANT_LARGE_REV_XXX( nonceLength, 1, dataLength ) );
				 /* nonceLength changes by number of bytes copied */

		/* Hash the state and copy the appropriate amount of data to the
		   output buffer */
		nonceHashFunction( systemInfo->nonceData, CRYPT_MAX_HASHSIZE, 
						   systemInfo->nonceData,
						   systemInfo->nonceHashSize + \
								NONCERNG_PRIVATE_STATESIZE );
		REQUIRES( boundsCheckZ( dataLength - nonceLength, bytesToCopy, 
								dataLength ) );
		memcpy( noncePtr, systemInfo->nonceData, bytesToCopy );

		/* Move on to the next block of the output buffer */
		noncePtr += bytesToCopy;
		nonceLength -= bytesToCopy;
		}
	ENSURES( LOOP_BOUND_LARGE_REV_OK );
	( void ) checksumNonceData( systemInfo );

	krnlExitMutex( MUTEX_RANDOMNONCE );

	return( CRYPT_OK );
	}

/* Perform a self-test of the device's algorithms and mechanisms */

#ifndef CONFIG_NO_SELFTEST

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int selftestFunction( INOUT_PTR DEVICE_INFO *deviceInfo,
							 INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	BYTE buffer[ 8 + 8 ];
	int status;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfo ) );

	/* The self-tests need randomness for some of their operations, in order
	   to pre-empt a lack of this from causing a failure somewhere deep down
	   in the crypto code we perform a dummy read of first the randomness 
	   source and then the nonce source to force a full initialisation of 
	   the randomness subsystem */
	status = getRandomFunction( deviceInfo, buffer, 8, NULL );
	if( cryptStatusError( status ) )
		return( status );
	zeroise( buffer, 8 );
	status = getNonce( deviceInfo, buffer, 8 );
	if( cryptStatusError( status ) )
		return( status );
	zeroise( buffer, 8 );

	return( selftestDevice( deviceInfo, messageExtInfo ) );
	}
#endif /* CONFIG_NO_SELFTEST */

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Initialise and shut down the system device */

CHECK_RETVAL \
static int initCapabilities( void );		/* Fwd.dec for fn.*/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initFunction( INOUT_PTR DEVICE_INFO *deviceInfo, 
						 STDC_UNUSED const char *name,
						 STDC_UNUSED const int nameLength )
	{
	void *randomInfoPtr;
	int status;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );

	REQUIRES( name == NULL && nameLength == 0 );

	/* Set up the capability information for this device */
	status = initCapabilities();
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the randomness information */
	randomInfoPtr = getBuiltinStorage( BUILTIN_STORAGE_RANDOM_INFO );
	ENSURES( randomInfoPtr != NULL );
	status = initRandomInfo( randomInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	DATAPTR_SET( deviceInfo->deviceSystem->randomInfo, randomInfoPtr );

	/* Complete the initialisation and mark the device as active */
	deviceInfo->label = "cryptlib system device";
	deviceInfo->labelLen = strlen( deviceInfo->label );
	SET_FLAG( deviceInfo->flags, DEVICE_FLAG_ACTIVE | \
								 DEVICE_FLAG_LOGGEDIN | \
								 DEVICE_FLAG_TIME );

	ENSURES( sanityCheckDevice( deviceInfo ) );

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR DEVICE_INFO *deviceInfo )
	{
	void *randomInfoPtr = DATAPTR_GET( deviceInfo->deviceSystem->randomInfo );

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );

	REQUIRES_V( randomInfoPtr != NULL );

	endRandomInfo( randomInfoPtr );
	DATAPTR_SET( deviceInfo->deviceSystem->randomInfo, NULL );
	}

/* Handle device control functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int controlFunction( INOUT_PTR DEVICE_INFO *deviceInfo,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
							IN_BUFFER_OPT( dataLength ) void *data, 
							IN_LENGTH_SHORT_Z const int dataLength,
							INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	int refCount, status;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( data == NULL || isReadPtrDynamic( data, dataLength ) );
	assert( type == CRYPT_IATTRIBUTE_TIME || \
			isWritePtr( messageExtInfo, 
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );
	
	REQUIRES( sanityCheckDevice( deviceInfo ) );
	REQUIRES( type == CRYPT_IATTRIBUTE_ENTROPY || \
			  type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY || \
			  type == CRYPT_IATTRIBUTE_RANDOM_POLL || \
			  type == CRYPT_IATTRIBUTE_RANDOM_NONCE || \
			  type == CRYPT_IATTRIBUTE_TIME );
	REQUIRES( ( ( type == CRYPT_IATTRIBUTE_ENTROPY || \
				  type == CRYPT_IATTRIBUTE_RANDOM_NONCE ) && \
				( data != NULL && isIntegerRangeNZ( dataLength ) ) ) || \
			  ( type == CRYPT_IATTRIBUTE_TIME && \
				data != NULL && dataLength == sizeof( time_t ) ) || \
			  ( type == CRYPT_IATTRIBUTE_RANDOM_POLL && \
				data == NULL && \
				isBooleanValue( dataLength ) ) || \
			  ( type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY && \
				( data == NULL && isShortIntegerRange( dataLength ) ) ) );

	/* Handle high-reliability time */
	if( type == CRYPT_IATTRIBUTE_TIME )
		{
		time_t *timePtr = ( time_t * ) data;

		*timePtr = getTime( GETTIME_NONE );
		return( CRYPT_OK );
		}

	/* All other control functions work with the randomness subsystem, which 
	   can both take awhile to complete and can inject content back into the
	   system device from another thread (in the case of a threaded 
	   slowpoll).  In order to avoid deadlock we have to unlock the system
	   device at this point, this is handled by having separate mutexes 
	   protecting the randomness subsystem and the nonce RNG.

	   See also the comment in getRandomFunction() about the possibility of a 
	   race condition, and the comment in getNonce() about the locking that's
	   used there */
	ENSURES( type == CRYPT_IATTRIBUTE_ENTROPY || \
			 type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY || \
			 type == CRYPT_IATTRIBUTE_RANDOM_POLL || \
			 type == CRYPT_IATTRIBUTE_RANDOM_NONCE );
	status = krnlSuspendObject( deviceInfo->objectHandle, &refCount );
	if( cryptStatusError( status ) )
		return( status );
	if( type != CRYPT_IATTRIBUTE_RANDOM_NONCE )
		{
		/* For nonces we don't leave the system object unlocked, see the 
		   comment further down in the handling of 
		   CRYPT_IATTRIBUTE_RANDOM_NONCE */
		setMessageObjectUnlocked( messageExtInfo );
		}

	/* Handle entropy addition.  Since this can take awhile, we do it with
	   the system object unlocked.  */
	if( type == CRYPT_IATTRIBUTE_ENTROPY )
		{
		void *randomInfoPtr = \
					DATAPTR_GET( deviceInfo->deviceSystem->randomInfo );

		REQUIRES( randomInfoPtr != NULL );

		return( addEntropyData( randomInfoPtr, data, dataLength ) );
		}
	if( type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY )
		{
		void *randomInfoPtr = \
					DATAPTR_GET( deviceInfo->deviceSystem->randomInfo );

		REQUIRES( randomInfoPtr != NULL );

		return( addEntropyQuality( randomInfoPtr, dataLength ) );
		}
	if( type == CRYPT_IATTRIBUTE_RANDOM_POLL )
		{
		/* Perform a slow or fast poll as required */
		if( dataLength == TRUE )
			slowPoll();
		else
			fastPoll();

		return( CRYPT_OK );
		}

	/* Handle nonces */
	if( type == CRYPT_IATTRIBUTE_RANDOM_NONCE )
		{
		int resumeStatus;

		/* The nonce attribute can be read from the self-test code which is called 
		   from within the system object.  If we were to leave the system object
		   unlocked then the self-test code, which also unlocks it, would attempt
		   to double-unlock it.  To deal with this we re-lock it after we've
		   retrieved the nonce */
		status = getNonce( deviceInfo, data, dataLength );
		resumeStatus = krnlResumeObject( SYSTEM_OBJECT_HANDLE, refCount );
		if( cryptStatusError( resumeStatus ) )
			{
			/* We couldn't re-lock the system object, let the caller know.
			   Since this is a shouldn't-occur condition we also warn the 
			   user in the debug version */
			DEBUG_DIAG(( "Failed to re-lock system object" ));
			assert( DEBUG_WARN );
			setMessageObjectUnlocked( messageExtInfo );
			}
		return( status );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*							Device Capability Routines						*
*																			*
****************************************************************************/

/* The cryptlib intrinsic capability list */

#define MAX_NO_CAPABILITIES		32

static const GETCAPABILITY_FUNCTION getCapabilityTable[] = {
#ifdef USE_3DES
	get3DESCapability,
#endif /* USE_3DES */
#ifdef USE_AES
	getAESCapability,
#endif /* USE_AES */
#ifdef USE_CAST
	getCASTCapability,
#endif /* USE_CAST */
#ifdef USE_DES
	getDESCapability,
#endif /* USE_DES */
#ifdef USE_IDEA
	getIDEACapability,
#endif /* USE_IDEA */
#ifdef USE_RC2
	getRC2Capability,
#endif /* USE_RC2 */
#ifdef USE_RC4
	getRC4Capability,
#endif /* USE_RC4 */
#ifdef USE_CHACHA20
	getChaCha20Capability,
#endif /* USE_RC4 */

#ifdef USE_MD5
	getMD5Capability,
#endif /* USE_MD5 */
	getSHA1Capability,
	getSHA2Capability,

	getHmacSHA1Capability,
	getHmacSHA2Capability,
#ifdef USE_POLY1305
	getPoly1305Capability,
#endif /* USE_POLY1305 */

#ifdef USE_DH
	getDHCapability,
#endif /* USE_DH */
#ifdef USE_DSA
	getDSACapability,
#endif /* USE_DSA */
#ifdef USE_ELGAMAL
	getElgamalCapability,
#endif /* USE_ELGAMAL */
#ifdef USE_RSA
	getRSACapability,
#endif /* USE_RSA */
#ifdef USE_ECDSA
	getECDSACapability,
#endif /* USE_ECDSA */
#ifdef USE_ECDH
	getECDHCapability,
#endif /* USE_ECDH */
#ifdef USE_EDDSA
//	getEDDSACapability,
#endif /* USE_EDDSA */
#ifdef USE_25519
//	get25519Capability,
#endif /* USE_25519 */

	getGenericSecretCapability,

	/* Vendors may want to use their own algorithms, which aren't part of the
	   general cryptlib suite.  The following provides the ability to include
	   vendor-specific algorithm capabilities defined in the file
	   vendalgo.c */
#ifdef USE_VENDOR_ALGOS
	#include "vendalgo.c"
#endif /* USE_VENDOR_ALGOS */

	/* End-of-list marker */
	NULL, NULL
	};

static CAPABILITY_INFO_LIST capabilityInfoList[ MAX_NO_CAPABILITIES ];

/* Initialise the capability information */

CHECK_RETVAL \
static int initCapabilities( void )
	{
	LOOP_INDEX i;

	/* Build the list of available capabilities */
	memset( capabilityInfoList, 0,
			sizeof( CAPABILITY_INFO_LIST ) * MAX_NO_CAPABILITIES );
	LOOP_LARGE( i = 0, 
				i < FAILSAFE_ARRAYSIZE( getCapabilityTable, \
										GETCAPABILITY_FUNCTION ) && \
					getCapabilityTable[ i ] != NULL,
				i++ )
		{
		const CAPABILITY_INFO *capabilityInfoPtr;

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( getCapabilityTable, \
														   GETCAPABILITY_FUNCTION ) - 1 ) );

		capabilityInfoPtr = getCapabilityTable[ i ]();
#ifndef CONFIG_FUZZ
		REQUIRES( sanityCheckCapability( capabilityInfoPtr ) );
#endif /* !CONFIG_FUZZ */

		DATAPTR_SET( capabilityInfoList[ i ].info, 
					 ( void * ) capabilityInfoPtr );
		DATAPTR_SET( capabilityInfoList[ i ].next, NULL );
		if( i > 0 )
			{
			DATAPTR_SET( capabilityInfoList[ i - 1 ].next, &capabilityInfoList[ i ] );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( getCapabilityTable, \
									 GETCAPABILITY_FUNCTION ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setDeviceSystem( INOUT_PTR DEVICE_INFO *deviceInfo )
	{
	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );

	FNPTR_SET( deviceInfo->initFunction, initFunction );
	FNPTR_SET( deviceInfo->shutdownFunction, shutdownFunction );
	FNPTR_SET( deviceInfo->controlFunction, controlFunction );
	FNPTR_SET( deviceInfo->getItemFunction, NULL );
	FNPTR_SET( deviceInfo->setItemFunction, NULL );
	FNPTR_SET( deviceInfo->deleteItemFunction, NULL );
	FNPTR_SET( deviceInfo->getFirstItemFunction, NULL );
	FNPTR_SET( deviceInfo->getNextItemFunction, NULL );
#ifndef CONFIG_NO_SELFTEST
	FNPTR_SET( deviceInfo->selftestFunction, selftestFunction );
#endif /* !CONFIG_NO_SELFTEST */
	FNPTR_SET( deviceInfo->getRandomFunction, getRandomFunction );
	DATAPTR_SET( deviceInfo->capabilityInfoList, capabilityInfoList );
	DATAPTR_SET( deviceInfo->createObjectFunctions, 
				 ( void * ) createObjectFunctions );
	deviceInfo->createObjectFunctionCount = \
		FAILSAFE_ARRAYSIZE( createObjectFunctions, CREATEOBJECT_FUNCTION_INFO );
	DATAPTR_SET( deviceInfo->mechanismFunctions, 
				 ( void * ) mechanismFunctions );
	deviceInfo->mechanismFunctionCount = \
		FAILSAFE_ARRAYSIZE( mechanismFunctions, MECHANISM_FUNCTION_INFO );

	return( CRYPT_OK );
	}
=======
/****************************************************************************
*																			*
*						cryptlib System Device Routines						*
*						Copyright Peter Gutmann 1995-2021					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "capabil.h"
  #include "device.h"
  #include "objectfns.h"
  #include "random.h"
#else
  #include "crypt.h"
  #include "device/capabil.h"
  #include "device/device.h"
  #include "kernel/objectfns.h"
  #include "random/random.h"
#endif /* Compiler-specific includes */

/* Mechanisms supported by the system device.  Since the mechanism space is 
   sparse, dispatching is handled by looking up the required mechanism in a 
   table of (action, mechanism, function) triples.  The table is sorted by 
   order of most-frequently-used mechanisms to speed things up, although the 
   overhead is vanishingly small anyway */

static const MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
#ifdef USE_PKC
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
  #if defined( USE_TLS ) && defined( USE_RSA_SUITES )
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1_RAW, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1_RAW, ( MECHANISM_FUNCTION ) importPKCS1 },
  #endif /* USE_TLS && USE_RSA_SUITES */
  #ifdef USE_OAEP
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_OAEP, ( MECHANISM_FUNCTION ) exportOAEP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_OAEP, ( MECHANISM_FUNCTION ) importOAEP },
  #endif /* USE_OAEP */
  #ifdef USE_PSS
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_PSS, ( MECHANISM_FUNCTION ) signPSS },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_PSS, ( MECHANISM_FUNCTION ) sigcheckPSS },
  #endif /* USE_PSS */
#endif /* USE_PKC */
#ifdef USE_PGP
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_PKCS1_PGP, ( MECHANISM_FUNCTION ) exportPKCS1PGP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_PKCS1_PGP, ( MECHANISM_FUNCTION ) importPKCS1PGP },
#endif /* USE_PGP */
#ifdef USE_INT_CMS
	{ MESSAGE_DEV_EXPORT, MECHANISM_ENC_CMS, ( MECHANISM_FUNCTION ) exportCMS },
	{ MESSAGE_DEV_IMPORT, MECHANISM_ENC_CMS, ( MECHANISM_FUNCTION ) importCMS },
#endif /* USE_INT_CMS */
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
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_SSL, ( MECHANISM_FUNCTION ) deriveSSL },
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_TLS, ( MECHANISM_FUNCTION ) deriveTLS },
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_TLS12, ( MECHANISM_FUNCTION ) deriveTLS12 },
	{ MESSAGE_DEV_SIGN, MECHANISM_SIG_TLS, ( MECHANISM_FUNCTION ) signTLS },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_SIG_TLS, ( MECHANISM_FUNCTION ) sigcheckTLS },
#endif /* USE_TLS */
#ifdef USE_CMP
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_CMP, ( MECHANISM_FUNCTION ) deriveCMP },
#endif /* USE_CMP */
#ifdef USE_PKCS12
	{ MESSAGE_DEV_DERIVE, MECHANISM_DERIVE_PKCS12, ( MECHANISM_FUNCTION ) derivePKCS12 },
#endif /* USE_PKCS12 */
#if defined( USE_KEYSETS ) && defined( USE_PKC )
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP, ( MECHANISM_FUNCTION ) exportPrivateKey },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP, ( MECHANISM_FUNCTION ) importPrivateKey },
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP_EXT, ( MECHANISM_FUNCTION ) exportPrivateKeyExt },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_EXT, ( MECHANISM_FUNCTION ) importPrivateKeyExt },
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP_PKCS8, ( MECHANISM_FUNCTION ) exportPrivateKeyPKCS8 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_PKCS8, ( MECHANISM_FUNCTION ) importPrivateKeyPKCS8 },
#endif /* USE_KEYSETS && USE_PKC */
#ifdef USE_PGPKEYS
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_PGP2, ( MECHANISM_FUNCTION ) importPrivateKeyPGP2 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_OPENPGP_OLD, ( MECHANISM_FUNCTION ) importPrivateKeyOpenPGPOld },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_OPENPGP, ( MECHANISM_FUNCTION ) importPrivateKeyOpenPGP },
#endif /* USE_PGPKEYS */
#ifndef CONFIG_NO_SELFTEST
	{ MESSAGE_DEV_EXPORT, MECHANISM_SELFTEST_ENC, ( MECHANISM_FUNCTION ) pkcWrapSelftest },
	{ MESSAGE_DEV_SIGN, MECHANISM_SELFTEST_SIG, ( MECHANISM_FUNCTION ) signSelftest },
	{ MESSAGE_DEV_DERIVE, MECHANISM_SELFTEST_DERIVE, ( MECHANISM_FUNCTION ) deriveSelftest },
	{ MESSAGE_DEV_KDF, MECHANISM_SELFTEST_KDF, ( MECHANISM_FUNCTION ) kdfSelftest },
#endif /* CONFIG_NO_SELFTEST */
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }, { MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Object creation functions supported by the system device.  These are
   sorted in order of frequency of use in order to make lookups a bit
   faster */

static const CREATEOBJECT_FUNCTION_INFO createObjectFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext },
#ifdef USE_CERTIFICATES
	{ OBJECT_TYPE_CERTIFICATE, createCertificate },
#endif /* USE_CERTIFICATES */
#ifdef USE_ENVELOPES
	{ OBJECT_TYPE_ENVELOPE, createEnvelope },
#endif /* USE_ENVELOPES */
#ifdef USE_SESSIONS
	{ OBJECT_TYPE_SESSION, createSession },
#endif /* USE_SESSIONS */
#ifdef USE_KEYSETS
	{ OBJECT_TYPE_KEYSET, createKeyset },
#endif /* USE_KEYSETS */
	{ OBJECT_TYPE_DEVICE, createDevice },
	{ OBJECT_TYPE_USER, createUser },
	{ OBJECT_TYPE_NONE, NULL }, { OBJECT_TYPE_NONE, NULL }
	};

/****************************************************************************
*																			*
*								Randomness Functions						*
*																			*
****************************************************************************/

/* Get random data.  We have to unlock the device around the randomness 
   fetch because background polling threads need to be able to send entropy
   data to it:

				System			Randomness
				------			----------
	getRand ------>|				|
			   [Suspend]			|
				   |--------------->|
				   |				|
				   |<===============| Entropy
				   |<===============| Entropy
				   |<===============| Entropy Quality
				   |				|
				   |<---------------|
			   [Resume]				|
   
   If the caller has specified that it's unlockable and the reference count
   is one or less (meaning that we've been sent the message directly), we 
   leave it unlocked.  Otherwise we re-lock it afterwards. 

   Note that there's a tiny chance of a race condition if the system object 
   is destroyed between the unlock and the acquisition of the randomness 
   mutex (which means that the randomInfo could be freed while we're getting 
   the random data), however there's no easy way around this short of using
   a complex multiple-mutex interlock, and in any case there's only so much 
   that we can do to help a user who pulls data structures out from under 
   active threads */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getRandomFunction( INOUT_PTR DEVICE_INFO *deviceInfo, 
							  OUT_BUFFER_FIXED( length ) void *buffer,
							  IN_LENGTH_SHORT const int length, 
							  INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	void *randomInfoPtr = DATAPTR_GET( deviceInfo->deviceSystem->randomInfo );
	int refCount, status;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( sanityCheckDevice( deviceInfo ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( randomInfoPtr != NULL );

	/* Clear the return value and make sure that we fail the FIPS 140 tests
	   on the output if there's a problem */
	REQUIRES( isShortIntegerRangeNZ( length ) ); 
	zeroise( buffer, length );

	/* If the system device is already unlocked (which can happen if this 
	   function is called in a loop, for example if multiple chunks of 
	   randomness are read) just return the randomness directly */
	if( messageExtInfo != NULL && isMessageObjectUnlocked( messageExtInfo ) )
		return( getRandomData( randomInfoPtr, buffer, length ) );

	/* Unlock the system device, get the data, and re-lock it if necessary.
	   This is necessary for two reasons, firstly because the background 
	   poll can take awhile and we don't want to block all messages to the
	   system object while it's in progress, and secondly so that the 
	   background polling thread can send entropy to the system object */
	status = krnlSuspendObject( deviceInfo->objectHandle, &refCount );
	if( cryptStatusError( status ) )
		return( status );
	status = getRandomData( randomInfoPtr, buffer, length );
	if( messageExtInfo == NULL || refCount > 1 )
		{
		int resumeStatus;

		/* The object isn't unlockable or it's been locked recursively, 
		   re-lock it */
		resumeStatus = krnlResumeObject( SYSTEM_OBJECT_HANDLE, refCount );
		if( cryptStatusError( resumeStatus ) )
			{
			/* We couldn't re-lock the system object, let the caller know.
			   Since this is a shouldn't-occur condition we also warn the 
			   user in the debug version */
			DEBUG_DIAG(( "Failed to re-lock system object" ));
			assert( DEBUG_WARN );
			if( messageExtInfo != NULL )
				setMessageObjectUnlocked( messageExtInfo );
			}
		}
	else
		{
		/* Tell the caller that we've left the object unlocked so they don't
		   have to do anything further with it */
		setMessageObjectUnlocked( messageExtInfo );
		}
	return( status );
	}

/* Get a random (but not necessarily cryptographically strong random) nonce.
   Some nonces can simply be fresh (for which a monotonically increasing
   sequence will do), some should be random (for which a hash of the
   sequence is adequate), and some need to be unpredictable.  In order to
   avoid problems arising from the inadvertent use of a nonce with the wrong
   properties we use unpredictable nonces in all cases, even where it isn't
   strictly necessary.

   This simple generator divides the nonce state into a public section of
   the same size as the hash output and a private section that contains 64
   bits of data from the crypto RNG, which influences the public section.
   The public and private sections are repeatedly hashed to produce the
   required amount of output.  Note that this leaks a small amount of
   information about the crypto RNG output since an attacker knows that
   public_state_n = hash( public_state_n - 1, private_state ) but this
   isn't a major weakness */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checksumNonceData( INOUT_PTR SYSTEMDEV_INFO *systemInfo )
	{
	const int oldChecksum = systemInfo->nonceChecksum;
	int newChecksum;

	assert( isWritePtr( systemInfo, sizeof( SYSTEMDEV_INFO ) ) );

	systemInfo->nonceChecksum = 0;
	newChecksum = checksumData( systemInfo, sizeof( SYSTEMDEV_INFO ) );
	systemInfo->nonceChecksum = newChecksum;

	return( ( oldChecksum == newChecksum ) ? TRUE : FALSE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getNonce( INOUT_PTR DEVICE_INFO *deviceInfo, 
					 OUT_BUFFER_FIXED( dataLength ) void *data, 
					 IN_LENGTH_SHORT const int dataLength )
	{
	SYSTEMDEV_INFO *systemInfo = deviceInfo->deviceSystem;
	HASH_FUNCTION_ATOMIC nonceHashFunction;
	BYTE *noncePtr = data;
	int nonceLength, status, LOOP_ITERATOR;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtrDynamic( data, dataLength ) );

	REQUIRES( isShortIntegerRangeNZ( dataLength ) );

	/* Handling of CRYPT_IATTRIBUTE_RANDOM_NONCE gets complicated because 
	   it may trigger an entropy poll the first time that it's called, for 
	   which the system device has to be unlocked so that it doesn't stall 
	   or block any subsequent messages to the device.  The normal process 
	   for this is:

		kSendMsg( GETATTR_S, IATTR_NONCE );
		system.c:getNonce() ->
			kSendMsg( GETATTR_S, IATTR_RANDOM );

		system.c:getRandomFunction() ->
			kSuspendObj( SYSTEM_DEVICE );

			random.c:getRandomData() ->			
				if( randomQual < 100 )
					slowPoll();
												kSendMsg( SETATTR_S, IATTR_ENTROPY );
												kSendMsg( SETATTR_S, IATTR_ENTROPY_QUAL );
			kResumeObj( SYSTEM_DEVICE );

	   In the presence of a second thread that sends a 
	   CRYPT_IATTRIBUTE_RANDOM_NONCE message to the system device we have:

		kSendMsg( GETATTR_S, IATTR_NONCE );		kSendMsg( GETATTR_S, IATTR_NONCE );
		system.c:getNonce() ->
			kSendMsg( GETATTR_S, IATTR_RANDOM );

		system.c:getRandomFunction() ->
			kSuspendObj( SYSTEM_DEVICE );
												system.c:getNonce() ->
													kSendMsg( GETATTR_S, IATTR_RANDOM );

	   At this point two threads are both in getNonce().  Since the system 
	   object is already unlocked, kSuspendObj() isn't called and the code 
	   path continues:

			random.c:getRandomData();			random.c:getRandomData();

	   random.c:getRandomData() uses MUTEX_RANDOM to enforce mutual 
	   exclusion, but before that the system device's randomness functions 
	   aren't protected.  This only affects CRYPT_IATTRIBUTE_RANDOM_NONCE 
	   and not the other get-randomness functions because they call directly 
	   into the randomness subsystem, but the nonce RNG is implemented in 
	   the system device which is unlocked at this point.

	   Dealing with this requires protecting the nonce initialisation with 
	   its own mutex */
	status = krnlEnterMutex( MUTEX_RANDOMNONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* If the nonce generator hasn't been initialised yet we set up the
	   hashing and get 64 bits of private nonce state.  What to do if the
	   attempt to initialise the state fails is somewhat debatable.  Since
	   nonces are only ever used in protocols alongside crypto keys and an
	   RNG failure will be detected when the key is generated we can
	   generally ignore a failure at this point.  
	   
	   However nonces are sometimes also used in non-crypto contexts (for 
	   example to generate certificate serial numbers) where this detection 
	   in the RNG won't happen.  On the other hand we shouldn't really abort 
	   processing just because we can't get some no-value nonce data so what 
	   we do is retry the fetch of nonce data (in case the system object was 
	   busy and the first attempt timed out) and if that fails too fall back 
	   to the system time.  
	   
	   This is no longer unpredictable, but the only location where 
	   unpredictability matters is when used in combination with crypto 
	   operations for which the absence of random data will be detected 
	   during key generation */
	if( !systemInfo->nonceDataInitialised )
		{
		HASH_FUNCTION_ATOMIC hashFunction;
		MESSAGE_DATA msgData;
		int hashSize;

		/* Get the 64-bit private portion of the nonce data, which follows
		   the public portion at the start of the buffer.  Note that we
		   have to set the nonceHashSize after we get the random data since
		   the device information is sanity-checked when we send the get-
		   random message to it and a nonceHashSize with no nonce data would 
		   fail the sanity check */
		getHashAtomicParameters( CRYPT_ALGO_SHA1, 0,
								 &hashFunction, &hashSize );
		setMessageData( &msgData, systemInfo->nonceData + hashSize, 
								  NONCERNG_PRIVATE_STATESIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM );
		if( cryptStatusError( status ) )
			{
			/* The fetch failed, retry it */
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM );
			}
		if( cryptStatusError( status ) )
			{
			const time_t theTime = getTime( GETTIME_NOFAIL );

			/* The second fetch failed as well, fall back on a last-resort
			   nonce seed value */
			memcpy( systemInfo->nonceData + hashSize, 
					&theTime, sizeof( time_t ) );
			}
		FNPTR_SET( systemInfo->nonceHashFunction, hashFunction );
		systemInfo->nonceHashSize = hashSize;
		systemInfo->nonceDataInitialised = TRUE;
		( void ) checksumNonceData( systemInfo );

		ENSURES_KRNLMUTEX( systemInfo->nonceHashSize >= MIN_HASHSIZE && \
						   systemInfo->nonceHashSize <= CRYPT_MAX_HASHSIZE,
						   MUTEX_RANDOMNONCE );
		ENSURES_KRNLMUTEX( isEmptyData( systemInfo->nonceData, 0 ), 
						   MUTEX_RANDOMNONCE );
		ENSURES_KRNLMUTEX( !isEmptyData( systemInfo->nonceData + \
										 systemInfo->nonceHashSize, 0 ),
						   MUTEX_RANDOMNONCE );
		}
	ENSURES( checksumNonceData( systemInfo ) );

	/* Shuffle the public state and copy it to the output buffer until it's
	   full */
	nonceHashFunction = ( HASH_FUNCTION_ATOMIC ) \
						FNPTR_GET( systemInfo->nonceHashFunction );
	ENSURES( nonceHashFunction != NULL );
	LOOP_LARGE_REV_INITCHECK( nonceLength = dataLength, nonceLength > 0 )
		{
		const int bytesToCopy = min( nonceLength, systemInfo->nonceHashSize );

		ENSURES( LOOP_INVARIANT_LARGE_REV_XXX( nonceLength, 1, dataLength ) );
				 /* nonceLength changes by number of bytes copied */

		/* Hash the state and copy the appropriate amount of data to the
		   output buffer */
		nonceHashFunction( systemInfo->nonceData, CRYPT_MAX_HASHSIZE, 
						   systemInfo->nonceData,
						   systemInfo->nonceHashSize + \
								NONCERNG_PRIVATE_STATESIZE );
		REQUIRES( boundsCheckZ( dataLength - nonceLength, bytesToCopy, 
								dataLength ) );
		memcpy( noncePtr, systemInfo->nonceData, bytesToCopy );

		/* Move on to the next block of the output buffer */
		noncePtr += bytesToCopy;
		nonceLength -= bytesToCopy;
		}
	ENSURES( LOOP_BOUND_LARGE_REV_OK );
	( void ) checksumNonceData( systemInfo );

	krnlExitMutex( MUTEX_RANDOMNONCE );

	return( CRYPT_OK );
	}

/* Perform a self-test of the device's algorithms and mechanisms */

#ifndef CONFIG_NO_SELFTEST

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int selftestFunction( INOUT_PTR DEVICE_INFO *deviceInfo,
							 INOUT_PTR MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	BYTE buffer[ 8 + 8 ];
	int status;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( messageExtInfo, \
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );

	REQUIRES( sanityCheckDevice( deviceInfo ) );

	/* The self-tests need randomness for some of their operations, in order
	   to pre-empt a lack of this from causing a failure somewhere deep down
	   in the crypto code we perform a dummy read of first the randomness 
	   source and then the nonce source to force a full initialisation of 
	   the randomness subsystem */
	status = getRandomFunction( deviceInfo, buffer, 8, NULL );
	if( cryptStatusError( status ) )
		return( status );
	zeroise( buffer, 8 );
	status = getNonce( deviceInfo, buffer, 8 );
	if( cryptStatusError( status ) )
		return( status );
	zeroise( buffer, 8 );

	return( selftestDevice( deviceInfo, messageExtInfo ) );
	}
#endif /* CONFIG_NO_SELFTEST */

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Initialise and shut down the system device */

CHECK_RETVAL \
static int initCapabilities( void );		/* Fwd.dec for fn.*/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initFunction( INOUT_PTR DEVICE_INFO *deviceInfo, 
						 STDC_UNUSED const char *name,
						 STDC_UNUSED const int nameLength )
	{
	void *randomInfoPtr;
	int status;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );

	REQUIRES( name == NULL && nameLength == 0 );

	/* Set up the capability information for this device */
	status = initCapabilities();
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the randomness information */
	randomInfoPtr = getBuiltinStorage( BUILTIN_STORAGE_RANDOM_INFO );
	ENSURES( randomInfoPtr != NULL );
	status = initRandomInfo( randomInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	DATAPTR_SET( deviceInfo->deviceSystem->randomInfo, randomInfoPtr );

	/* Complete the initialisation and mark the device as active */
	deviceInfo->label = "cryptlib system device";
	deviceInfo->labelLen = strlen( deviceInfo->label );
	SET_FLAG( deviceInfo->flags, DEVICE_FLAG_ACTIVE | \
								 DEVICE_FLAG_LOGGEDIN | \
								 DEVICE_FLAG_TIME );

	ENSURES( sanityCheckDevice( deviceInfo ) );

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR DEVICE_INFO *deviceInfo )
	{
	void *randomInfoPtr = DATAPTR_GET( deviceInfo->deviceSystem->randomInfo );

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );

	REQUIRES_V( randomInfoPtr != NULL );

	endRandomInfo( randomInfoPtr );
	DATAPTR_SET( deviceInfo->deviceSystem->randomInfo, NULL );
	}

/* Handle device control functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int controlFunction( INOUT_PTR DEVICE_INFO *deviceInfo,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
							IN_BUFFER_OPT( dataLength ) void *data, 
							IN_LENGTH_SHORT_Z const int dataLength,
							INOUT_PTR_OPT \
								MESSAGE_FUNCTION_EXTINFO *messageExtInfo )
	{
	int refCount, status;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( data == NULL || isReadPtrDynamic( data, dataLength ) );
	assert( type == CRYPT_IATTRIBUTE_TIME || \
			isWritePtr( messageExtInfo, 
						sizeof( MESSAGE_FUNCTION_EXTINFO ) ) );
	
	REQUIRES( sanityCheckDevice( deviceInfo ) );
	REQUIRES( type == CRYPT_IATTRIBUTE_ENTROPY || \
			  type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY || \
			  type == CRYPT_IATTRIBUTE_RANDOM_POLL || \
			  type == CRYPT_IATTRIBUTE_RANDOM_NONCE || \
			  type == CRYPT_IATTRIBUTE_TIME );
	REQUIRES( ( ( type == CRYPT_IATTRIBUTE_ENTROPY || \
				  type == CRYPT_IATTRIBUTE_RANDOM_NONCE ) && \
				( data != NULL && isIntegerRangeNZ( dataLength ) ) ) || \
			  ( type == CRYPT_IATTRIBUTE_TIME && \
				data != NULL && dataLength == sizeof( time_t ) ) || \
			  ( type == CRYPT_IATTRIBUTE_RANDOM_POLL && \
				data == NULL && \
				isBooleanValue( dataLength ) ) || \
			  ( type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY && \
				( data == NULL && isShortIntegerRange( dataLength ) ) ) );

	/* Handle high-reliability time */
	if( type == CRYPT_IATTRIBUTE_TIME )
		{
		time_t *timePtr = ( time_t * ) data;

		*timePtr = getTime( GETTIME_NONE );
		return( CRYPT_OK );
		}

	/* All other control functions work with the randomness subsystem, which 
	   can both take awhile to complete and can inject content back into the
	   system device from another thread (in the case of a threaded 
	   slowpoll).  In order to avoid deadlock we have to unlock the system
	   device at this point, this is handled by having separate mutexes 
	   protecting the randomness subsystem and the nonce RNG.

	   See also the comment in getRandomFunction() about the possibility of a 
	   race condition, and the comment in getNonce() about the locking that's
	   used there */
	ENSURES( type == CRYPT_IATTRIBUTE_ENTROPY || \
			 type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY || \
			 type == CRYPT_IATTRIBUTE_RANDOM_POLL || \
			 type == CRYPT_IATTRIBUTE_RANDOM_NONCE );
	status = krnlSuspendObject( deviceInfo->objectHandle, &refCount );
	if( cryptStatusError( status ) )
		return( status );
	if( type != CRYPT_IATTRIBUTE_RANDOM_NONCE )
		{
		/* For nonces we don't leave the system object unlocked, see the 
		   comment further down in the handling of 
		   CRYPT_IATTRIBUTE_RANDOM_NONCE */
		setMessageObjectUnlocked( messageExtInfo );
		}

	/* Handle entropy addition.  Since this can take awhile, we do it with
	   the system object unlocked.  */
	if( type == CRYPT_IATTRIBUTE_ENTROPY )
		{
		void *randomInfoPtr = \
					DATAPTR_GET( deviceInfo->deviceSystem->randomInfo );

		REQUIRES( randomInfoPtr != NULL );

		return( addEntropyData( randomInfoPtr, data, dataLength ) );
		}
	if( type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY )
		{
		void *randomInfoPtr = \
					DATAPTR_GET( deviceInfo->deviceSystem->randomInfo );

		REQUIRES( randomInfoPtr != NULL );

		return( addEntropyQuality( randomInfoPtr, dataLength ) );
		}
	if( type == CRYPT_IATTRIBUTE_RANDOM_POLL )
		{
		/* Perform a slow or fast poll as required */
		if( dataLength == TRUE )
			slowPoll();
		else
			fastPoll();

		return( CRYPT_OK );
		}

	/* Handle nonces */
	if( type == CRYPT_IATTRIBUTE_RANDOM_NONCE )
		{
		int resumeStatus;

		/* The nonce attribute can be read from the self-test code which is called 
		   from within the system object.  If we were to leave the system object
		   unlocked then the self-test code, which also unlocks it, would attempt
		   to double-unlock it.  To deal with this we re-lock it after we've
		   retrieved the nonce */
		status = getNonce( deviceInfo, data, dataLength );
		resumeStatus = krnlResumeObject( SYSTEM_OBJECT_HANDLE, refCount );
		if( cryptStatusError( resumeStatus ) )
			{
			/* We couldn't re-lock the system object, let the caller know.
			   Since this is a shouldn't-occur condition we also warn the 
			   user in the debug version */
			DEBUG_DIAG(( "Failed to re-lock system object" ));
			assert( DEBUG_WARN );
			setMessageObjectUnlocked( messageExtInfo );
			}
		return( status );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*							Device Capability Routines						*
*																			*
****************************************************************************/

/* The cryptlib intrinsic capability list */

#define MAX_NO_CAPABILITIES		32

static const GETCAPABILITY_FUNCTION getCapabilityTable[] = {
#ifdef USE_3DES
	get3DESCapability,
#endif /* USE_3DES */
#ifdef USE_AES
	getAESCapability,
#endif /* USE_AES */
#ifdef USE_CAST
	getCASTCapability,
#endif /* USE_CAST */
#ifdef USE_DES
	getDESCapability,
#endif /* USE_DES */
#ifdef USE_IDEA
	getIDEACapability,
#endif /* USE_IDEA */
#ifdef USE_RC2
	getRC2Capability,
#endif /* USE_RC2 */
#ifdef USE_RC4
	getRC4Capability,
#endif /* USE_RC4 */
#ifdef USE_CHACHA20
	getChaCha20Capability,
#endif /* USE_RC4 */

#ifdef USE_MD5
	getMD5Capability,
#endif /* USE_MD5 */
	getSHA1Capability,
	getSHA2Capability,

	getHmacSHA1Capability,
	getHmacSHA2Capability,
#ifdef USE_POLY1305
	getPoly1305Capability,
#endif /* USE_POLY1305 */

#ifdef USE_DH
	getDHCapability,
#endif /* USE_DH */
#ifdef USE_DSA
	getDSACapability,
#endif /* USE_DSA */
#ifdef USE_ELGAMAL
	getElgamalCapability,
#endif /* USE_ELGAMAL */
#ifdef USE_RSA
	getRSACapability,
#endif /* USE_RSA */
#ifdef USE_ECDSA
	getECDSACapability,
#endif /* USE_ECDSA */
#ifdef USE_ECDH
	getECDHCapability,
#endif /* USE_ECDH */
#ifdef USE_EDDSA
//	getEDDSACapability,
#endif /* USE_EDDSA */
#ifdef USE_25519
//	get25519Capability,
#endif /* USE_25519 */

	getGenericSecretCapability,

	/* Vendors may want to use their own algorithms, which aren't part of the
	   general cryptlib suite.  The following provides the ability to include
	   vendor-specific algorithm capabilities defined in the file
	   vendalgo.c */
#ifdef USE_VENDOR_ALGOS
	#include "vendalgo.c"
#endif /* USE_VENDOR_ALGOS */

	/* End-of-list marker */
	NULL, NULL
	};

static CAPABILITY_INFO_LIST capabilityInfoList[ MAX_NO_CAPABILITIES ];

/* Initialise the capability information */

CHECK_RETVAL \
static int initCapabilities( void )
	{
	LOOP_INDEX i;

	/* Build the list of available capabilities */
	memset( capabilityInfoList, 0,
			sizeof( CAPABILITY_INFO_LIST ) * MAX_NO_CAPABILITIES );
	LOOP_LARGE( i = 0, 
				i < FAILSAFE_ARRAYSIZE( getCapabilityTable, \
										GETCAPABILITY_FUNCTION ) && \
					getCapabilityTable[ i ] != NULL,
				i++ )
		{
		const CAPABILITY_INFO *capabilityInfoPtr;

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( getCapabilityTable, \
														   GETCAPABILITY_FUNCTION ) - 1 ) );

		capabilityInfoPtr = getCapabilityTable[ i ]();
#ifndef CONFIG_FUZZ
		REQUIRES( sanityCheckCapability( capabilityInfoPtr ) );
#endif /* !CONFIG_FUZZ */

		DATAPTR_SET( capabilityInfoList[ i ].info, 
					 ( void * ) capabilityInfoPtr );
		DATAPTR_SET( capabilityInfoList[ i ].next, NULL );
		if( i > 0 )
			{
			DATAPTR_SET( capabilityInfoList[ i - 1 ].next, &capabilityInfoList[ i ] );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( getCapabilityTable, \
									 GETCAPABILITY_FUNCTION ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setDeviceSystem( INOUT_PTR DEVICE_INFO *deviceInfo )
	{
	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );

	FNPTR_SET( deviceInfo->initFunction, initFunction );
	FNPTR_SET( deviceInfo->shutdownFunction, shutdownFunction );
	FNPTR_SET( deviceInfo->controlFunction, controlFunction );
	FNPTR_SET( deviceInfo->getItemFunction, NULL );
	FNPTR_SET( deviceInfo->setItemFunction, NULL );
	FNPTR_SET( deviceInfo->deleteItemFunction, NULL );
	FNPTR_SET( deviceInfo->getFirstItemFunction, NULL );
	FNPTR_SET( deviceInfo->getNextItemFunction, NULL );
#ifndef CONFIG_NO_SELFTEST
	FNPTR_SET( deviceInfo->selftestFunction, selftestFunction );
#endif /* !CONFIG_NO_SELFTEST */
	FNPTR_SET( deviceInfo->getRandomFunction, getRandomFunction );
	DATAPTR_SET( deviceInfo->capabilityInfoList, capabilityInfoList );
	DATAPTR_SET( deviceInfo->createObjectFunctions, 
				 ( void * ) createObjectFunctions );
	deviceInfo->createObjectFunctionCount = \
		FAILSAFE_ARRAYSIZE( createObjectFunctions, CREATEOBJECT_FUNCTION_INFO );
	DATAPTR_SET( deviceInfo->mechanismFunctions, 
				 ( void * ) mechanismFunctions );
	deviceInfo->mechanismFunctionCount = \
		FAILSAFE_ARRAYSIZE( mechanismFunctions, MECHANISM_FUNCTION_INFO );

	return( CRYPT_OK );
	}
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
