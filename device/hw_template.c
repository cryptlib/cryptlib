/****************************************************************************
*																			*
*					cryptlib Crypto HAL Template Routines					*
*					  Copyright Peter Gutmann 1998-2020						*
*																			*
****************************************************************************/

/* This module and the companion module hw_templalg.c are templates for use 
   when adding support for custom cryptographic hardware to cryptlib.  They
   implement dummy versions of the cryptographic operations that would be 
   provided by the custom hardware, with this file containing the general 
   HAL routines and the algorithm template file containing the algorithms.

   The best way to understand the algorithm implementation is to look at 
   equivalent cryto modules in the context subdirectory, context/ctx_aes.c 
   for a symmetric crypto module, context/ctx_rsa.c for an asymmetric-crypto 
   module, and context/ctx_sha2.c / context/hsha2.c for a hash/MAC module.

   Alongside the crypto context capabilities referenced above, the hardware
   device may also implement higher-level crypto mechanisms like key wrap/
   unwrap, sign/sig check, and KDF.  These are currently mapped to cryptlib-
   native mechanisms by code in hardware.c but can be overridden if 
   required to provide support for the custom crypto mechanisms.

   The hardware typically contains built-in storage for a fixed number of 
   keys and related data, referred to as personalities (from its original 
   use in Fortezza devices).  Personalities have two identifiers, a long-
   term storageID in the form of a fixed-length binary string, and an 
   ephemeral storageRef in the form of an integer value.  Personalities are 
   looked up by their long-term storageID, which is mapped to an empeheral 
   storageRef by the HAL that's then used to acccess the personality from 
   then on.  The operation works similar to opening a file (by storageID), 
   which returns a file handle (the storageRef) that's used in subsequent 
   operations.

   This module needs to implement the following functions:

	hwInitialise(): Initialise/zeroise the hardware.  "Initialise" in this 
		case is meant in the sense of "format c:"/"mkfs", not just 
		establishing a connection to the hardware in preparation for using 
		it, so it's only called in response to an explicit initialise/
		zeroise operation.

	hwGetCapabilities(): Get the CAPABILITY_INFO array of crypto
		capabilities provided by this module.

	hwGetMechanisms(): Get the MECHANISM_FUNCTION_INFO array of crypto
		mechanisms provided by this module, or CRYPT_ERROR_NOTFOUND if 
		cryptlib should provide crypto mechanism support.

	hwGetRandom(): Fill a buffer with random data to feed into cryptlib's
		random number generation system.

	hwCatalogQuery(): Return an encoding table used to encode any custom
		crypto algorithms or mechanisms provided by the HAL.  A typical 
		table would be an OID <-> algorithm ID mapping table.

	hwGetStorage(): Return a in-memory buffer backed by nonvolatile storage 
		for storing data like certificates.  If the module returns CRYPT_OK 
		then this indicates that the storage is initialised and ready for 
		use, for example by copying a pre-existing PKCS #15 image containing 
		things like trusted CA keys into it from the backing nonvolatile 
		storage or from cryptlib having previously initialised it.  If the 
		module returns OK_SPECIAL then the storage is not initialised and 
		cryptlib needs to initialise it.  If the module provides no storage, 
		it returns CRYPT_ERROR_NOTAVAIL and cryptlib will fall back to using 
		on-disk storage.

	hwStorageUpdateNotify(): Informs the HAL that the contents of the memory 
		buffer returned from hwGetStorage() have been replaced with an 
		updated form.  This can be used to initiate a flash program cycle 
		from the buffer contents to backing nonvolatile storage or similar.

		This function is passed an integer value by the caller.  Setting 
		this to CRYPT_UNUSED indicates that the data in the in-memory buffer 
		is no longer valid, for example due to a failed update attempt, and
		the HAL should re-fill it with the original data from backing 
		nonvolatile storage.  Setting this to 0 indicates that the in-memory 
		data is now empty, so the HAL should erase the backing store.  
		Finally, setting it to a nonzero positive value indicates that that 
		many bytes of data in the in-memory buffer have changed and need to 
		be written to nonvolatile backing storage.  cryptlib updates are 
		atomic so the entire data block up to the given byte count will be 
		updated at once, there won't be any random-access changes made to 
		subranges within the data block.

		Together, hwGetStorage() and hwStorageUpdateNotify() manage access 
		to internal nonvolatile storage.  hwGetStorage() copies data from 
		nonvolatile storage to a memory buffer for use by cryptlib, and 
		hwStorageUpdateNotify() notifies the HAL that the memory buffer 
		contents have been updated so that the changes can be processed and
		committed to nonvolatile storage if necessary.

	hwCloneNotify(): Notify the HAL that an object that has been cloned.  
		This is called for objects that have been cloned by cryptlib, 
		specifically conventional-encryption, hash, and MAC objects, which 
		are occasionally cloned into new objects to allow operations like 
		signing TLS handshakes where a partial hash of the messages to date 
		is signed via one object while the hashing continues in another 
		object to complete the handshake.

		hwCloneNotify() is called for the cloned personality to allocate a 
		new personality containing a copy of the state of the existing one.

	hwLookupItem(): Look up an item like a private key stored in the
		hardware.  This is a name-to-unique-value mapping function that 
		takes a long-term storageID string and returns an ephemeral integer 
		storageRef that can be used to refer to that key in the HAL.

	hwDeleteItem(): Delete an item like a public or private key referenced
		by storageRef stored in the hardware.

   For other changes that might be required, see the inline comments for
   what's needed at each stage */

#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "hardware.h"
  #include "hw_template.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "asn1_int.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "device/hardware.h"
  #include "device/hw_template.h"
  #include "enc_dec/asn1.h"			/* For OID/AlgoID handling */
  #include "enc_dec/asn1_ext.h"		/* For OID/AlgoID handling */
  #include "enc_dec/asn1_int.h"		/* For OID/AlgoID handling */
#endif /* Compiler-specific includes */

#ifdef USE_HARDWARE

/****************************************************************************
*																			*
*						Personality Management Routines						*
*																			*
****************************************************************************/

/* The following routines manage access to the personality storage and 
   represent an example implementation matching the sample PERSONALITY_INFO
   structure defined in hw_template.h.  The routines look up a personality 
   given its storageID, find a free personality slot to use when 
   instantiating a new personality (or in more high-level terms when loading 
   or generating a key for an encryption context), and delete a personality */

static PERSONALITY_INFO personalityInfo[ NO_PERSONALITIES ] = { 0 };

/* Look up a personality given a key ID */

static int lookupPersonality( const void *storageID, 
							  const int storageIDlength, int *storageRef )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( storageID, storageIDlength ) );
	assert( isWritePtr( storageRef, sizeof( int ) ) );

	REQUIRES( storageIDlength >= 4 && storageIDlength <= KEYID_SIZE );

	/* Clear return value */
	*storageRef = CRYPT_ERROR;

	/* Scan the personality table looking for one matching the given 
	   storageID */
	LOOP_MED( i = 0, i < NO_PERSONALITIES, i++ )
		{
		const PERSONALITY_INFO *personalityInfoPtr;

		ENSURES( LOOP_INVARIANT_MED( i, 0, NO_PERSONALITIES - 1 ) );

		personalityInfoPtr = &personalityInfo[ i ];
		if( !personalityInfoPtr->inUse )
			continue;
		if( !memcmp( personalityInfoPtr->storageID, storageID, storageIDlength ) )
			{
			*storageRef = i;
			return( CRYPT_OK );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_ERROR_NOTFOUND );
	}

/* Find a free personality */

int findFreePersonality( int *storageRef )
	{
	LOOP_INDEX i;

	assert( isWritePtr( storageRef, sizeof( int ) ) );

	/* Clear return value */
	*storageRef = CRYPT_ERROR;

	/* Scan the personality table looking for a free slot */
	LOOP_MED( i = 0, i < NO_PERSONALITIES, i++ )
		{
		PERSONALITY_INFO *personalityInfoPtr;

		ENSURES( LOOP_INVARIANT_MED( i, 0, NO_PERSONALITIES - 1 ) );

		personalityInfoPtr = &personalityInfo[ i ];
		if( !personalityInfoPtr->inUse )
			{
			zeroise( personalityInfoPtr, sizeof( PERSONALITY_INFO ) );
			*storageRef = i;
			return( CRYPT_OK );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_ERROR_OVERFLOW );
	}

/* Return a pointer to personality information */

void *getPersonality( const int storageRef )
	{
	REQUIRES_N( storageRef >= 0 && storageRef < NO_PERSONALITIES );

	return( &personalityInfo[ storageRef ] );
	}

/* Delete a personality */

void deletePersonality( const int storageRef )
	{
	PERSONALITY_INFO *personalityInfoPtr;

	REQUIRES_V( storageRef >= 0 && storageRef < NO_PERSONALITIES );

	if( storageRef < 0 || storageRef >= NO_PERSONALITIES )
		{
		retIntError_Void();
		}
	personalityInfoPtr = &personalityInfo[ storageRef ];
	zeroise( personalityInfoPtr, sizeof( PERSONALITY_INFO ) );
	}

/****************************************************************************
*																			*
*							Hardware External Interface						*
*																			*
****************************************************************************/

/* Get the mechanism information for this device */

int hwGetMechanisms( const MECHANISM_FUNCTION_INFO **mechanismFunctions, 
					 int *mechanismFunctionCount )
	{
	/* We don't implement any crypto mechanisms in the device so we tell 
	   cryptlib to fall back to the built-in mechanism implementation */
	*mechanismFunctions = NULL;
	*mechanismFunctionCount = 0;

	return( CRYPT_ERROR_NOTFOUND );
	}

/* Get random data from the hardware */

int hwGetRandom( void *buffer, const int length )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ], *bufPtr = buffer;
	static int counter = 0;
	int hashSize, i;

	assert( isWritePtrDynamic( buffer, length ) );

	REQUIRES( isBufsizeRangeNZ( length ) );

	/* Fill the buffer with random-ish data.  This gets a bit tricky because
	   we need to fool the entropy tests so we can't just fill it with a 
	   fixed (or even semi-random) pattern but have to set up a somewhat
	   kludgy PRNG */
	getHashAtomicParameters( CRYPT_ALGO_SHA2, 0, &hashFunctionAtomic, 
							 &hashSize );
	memset( hashBuffer, counter, hashSize );
	counter++;
	for( i = 0; i < length; i++ )
		{
		if( i % hashSize == 0 )
			{
			hashFunctionAtomic( hashBuffer, CRYPT_MAX_HASHSIZE, 
								hashBuffer, hashSize );
			}
		bufPtr[ i ] = hashBuffer[ i % hashSize ];
		}

	return( CRYPT_OK );
	}

/* Return an encoding table used to encode any custom crypto algorithms or 
   mechanisms provided by the HAL */

static const OID_INFO eccOIDinfoTbl[] = {
	/* Dummy OIDs, '1 2 3 4 5', '1 2 4 8 16', '1 3 5 7 9' */
	{ MKOID( "\x06\x04\x2A\x03\x04\x05" ), CRYPT_ECCCURVE_P256 },
#ifdef USE_SHA2_EXT
	{ MKOID( "\x06\x04\x2A\x04\x08\x10" ), CRYPT_ECCCURVE_P384 },
	{ MKOID( "\x06\x04\x2B\x05\x07\x09" ), CRYPT_ECCCURVE_P521 },
#endif /* USE_SHA2_EXT */
	{ NULL, 0 }, { NULL, 0 }
	};

static const ALGOID_INFO algoIDinfoTbl[] = {
	/* RSA and <hash>WithRSA */
#ifdef USE_RSA
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_NONE, ALGOID_ENCODING_PKCS1, ALGOID_CLASS_PKC,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" )
	  MKDESC( "rsaEncryption (1 2 840 113549 1 1 1)" ) },
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 32, ALGOID_CLASS_PKCSIG,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B" )
	  MKDESC( "sha256withRSAEncryption (1 2 840 113549 1 1 11)" ) },
#endif /* USE_RSA */

	/* ECDSA and ecdsaWith<hash> */
#if defined( USE_ECDSA ) || defined( USE_ECDH )
	{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_NONE, ALGOID_ENCODING_NONE, ALGOID_CLASS_PKC,
	  MKOID( "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01" )
	  MKDESC( "ecPublicKey (1 2 840 10045 2 1)" ) },
#endif /* USE_ECDSA || USE_ECDH */
#ifdef USE_ECDSA
	{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 32, ALGOID_CLASS_PKCSIG,
	  MKOID( "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02" )
	  MKDESC( "ecdsaWithSHA256 (1 2 840 10045 4 3 2)" ) },
  #ifdef USE_SHA2_EXT
	{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 48, ALGOID_CLASS_PKCSIG,
	  MKOID( "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x03" )
	  MKDESC( "ecdsaWithSHA384 (1 2 840 10045 4 3 3)" ) },
	{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 64, ALGOID_CLASS_PKCSIG,
	  MKOID( "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x04" )
	  MKDESC( "ecdsaWithSHA512 (1 2 840 10045 4 3 4)" ) },
  #endif /* USE_SHA2_EXT */
#endif /* USE_ECDSA */

	/* EDDSA */
#ifdef USE_EDDSA
	{ CRYPT_ALGO_EDDSA, CRYPT_ALGO_NONE, ALGOID_ENCODING_NONE, ALGOID_CLASS_PKC,
	  MKOID( "\x06\x03\x2B\x65\x70" )
	  MKDESC( "ed25519 (1 3 101 112)" ) },
#endif /* USE_25519 */

	/* Hash algorithms */
	{ CRYPT_ALGO_SHA2, CRYPT_ALGO_NONE, 32, ALGOID_CLASS_HASH,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01" )
	  MKDESC( "sha2-256 (2 16 840 1 101 3 4 2 1)" ) },
#ifdef USE_SHA2_EXT
	{ CRYPT_ALGO_SHA2, CRYPT_ALGO_NONE, 48, ALGOID_CLASS_HASH,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02" )
	  MKDESC( "sha2-384 (2 16 840 1 101 3 4 2 2)" ) },
	{ CRYPT_ALGO_SHA2, CRYPT_ALGO_NONE, 64, ALGOID_CLASS_HASH,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03" )
	  MKDESC( "sha2-512 (2 16 840 1 101 3 4 2 3)" ) },
#endif /* USE_SHA2_EXT */

	/* MAC algorithms */
	{ CRYPT_ALGO_HMAC_SHA2, CRYPT_ALGO_NONE, 32, ALGOID_CLASS_HASH,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x09" )
	  MKDESC( "hmacWithSHA256 (1 2 840 113549 2 9)" ) },
#ifdef USE_SHA2_EXT
	{ CRYPT_ALGO_HMAC_SHA2, CRYPT_ALGO_NONE, 48, ALGOID_CLASS_HASH,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x0A" )
	  MKDESC( "hmacWithSHA384 (1 2 840 113549 2 10)" ) },
	{ CRYPT_ALGO_HMAC_SHA2, CRYPT_ALGO_NONE, 64, ALGOID_CLASS_HASH,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x0B" )
	  MKDESC( "hmacWithSHA512 (1 2 840 113549 2 11)" ) },
#endif /* USE_SHA2_EXT */

	/* Encryption algorithms */
	{ CRYPT_ALGO_AES, CRYPT_MODE_ECB, 16, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x01" )
	  MKDESC( "aes128-ECB (2 16 840 1 101 3 4 1 1)" ) },
	{ CRYPT_ALGO_AES, CRYPT_MODE_ECB, 24, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x15" )
	  MKDESC( "aes192-ECB (2 16 840 1 101 3 4 1 21)" ) },
	{ CRYPT_ALGO_AES, CRYPT_MODE_ECB, 32, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x29" )
	  MKDESC( "aes256-ECB (2 16 840 1 101 3 4 1 41)" ) },
	{ CRYPT_ALGO_AES, CRYPT_MODE_CBC, 16, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x02" )
	  MKDESC( "aes128-CBC (2 16 840 1 101 3 4 1 2)" ) },
	{ CRYPT_ALGO_AES, CRYPT_MODE_CBC, 24, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x16" )
	  MKDESC( "aes192-CBC (2 16 840 1 101 3 4 1 22)" ) },
	{ CRYPT_ALGO_AES, CRYPT_MODE_CBC, 32, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2A" )
	  MKDESC( "aes256-CBC (2 16 840 1 101 3 4 1 42)" ) },
#ifdef USE_CFB
	{ CRYPT_ALGO_AES, CRYPT_MODE_CFB, 16, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x04" )
	  MKDESC( "aes128-CFB (2 16 840 1 101 3 4 1 4)" ) },
	{ CRYPT_ALGO_AES, CRYPT_MODE_CFB, 24, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x18" )
	  MKDESC( "aes192-CFB (2 16 840 1 101 3 4 1 24)" ) },
	{ CRYPT_ALGO_AES, CRYPT_MODE_CFB, 32, ALGOID_CLASS_CRYPT,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2C" )
	  MKDESC( "aes256-CFB (2 16 840 1 101 3 4 1 44)" ) },
#endif /* USE_CFB */

	{ CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0, ALGOID_CLASS_NONE, NULL MKDESC( "" ) },
		{ CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0, ALGOID_CLASS_NONE, NULL MKDESC( "" ) }
	};

int hwCatalogQuery( MESSAGE_CATALOGQUERY_INFO *queryInfo, 
					const CATALOGQUERY_ITEM_TYPE itemType )
	{
	/* By default we tell cryptlib to fall back to the built-in encoding 
	   tables */
	queryInfo->infoTable = NULL;
	queryInfo->infoNoEntries = 0;

	/* Return any custom encoding tables that we may implement */
	switch( itemType )
		{
		case CATALOGQUERY_ITEM_ALGOIDINFO:
			queryInfo->infoTable = algoIDinfoTbl;
			queryInfo->infoNoEntries = \
						FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO );

			return( CRYPT_OK );

		case CATALOGQUERY_ITEM_ECCINFO:
			queryInfo->infoTable = eccOIDinfoTbl;
			queryInfo->infoNoEntries = \
						FAILSAFE_ARRAYSIZE( eccOIDinfoTbl, OID_INFO );
			return( CRYPT_OK );
		}

	return( CRYPT_ERROR_NOTFOUND );
	}

/* Get a reference to built-in storage for keys and certificates.  This has 
   a PKCS #15 keyset mapped over the top of it.  The storage is typically an
   in-memory buffer that can be committed to backing store, which would be 
   done when the update-notify function is called to indicate that the 
   buffer contents have been updated */

#define STORAGE_SIZE	8192

static BYTE storage[ STORAGE_SIZE ] = { 0 };
static BOOLEAN storageInitialised = FALSE;

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int hwGetStorage( IN_PTR_OPT void *contextHandle,
				  OUT_BUFFER_ALLOC_OPT( *storageSize ) void **storageAddr,
				  OUT_LENGTH int *storageSize )
	{
	assert( isWritePtr( storageAddr, sizeof( void * ) ) );
	assert( isWritePtr( storageSize, sizeof( int ) ) );

	*storageAddr = storage;
	*storageSize = STORAGE_SIZE;

	/* Since the test code uses RAM storage which is cleared on each run, we
	   return OK_SPECIAL to tell cryptlib to initialise the storage on the
	   first call.  Note that this assumes that the storage will be 
	   initialised the first time that it's accessed */
	if( !storageInitialised )
		{
		storageInitialised = TRUE;
		return( OK_SPECIAL );
		}

	/* If for some reason the storage hasn't been initialised but it's a
	   subsequent call, we'll hand back still-not-initialised storage to the
	   caller, so we convert this case to an OK_SPECIAL return as well */
	if( !memcmp( storage, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) )
		return( OK_SPECIAL );
	
	return( CRYPT_OK );
	}

CHECK_RETVAL \
int hwStorageUpdateNotify( IN_PTR_OPT void *contextHandle,
						   IN_LENGTH_Z const int dataLength )
	{
	REQUIRES( ( dataLength == CRYPT_UNUSED ) || \
			  isIntegerRange( dataLength ) );

	/* The contents of the storage buffer have changed, commit them to 
	   backing store, for example by initiating a flash program cycle */

	/* If the data in the in-memory buffer is no longer valid, for example 
	   due to a failed update attempt, re-fill the buffer with the original 
	   data from the backing store */
	if( dataLength == CRYPT_UNUSED )
		{
		/* ... */
		
		return( CRYPT_OK );
		}

	/* If the in-memory data is now empty, erase the backing store */
	if( dataLength == 0 )
		{
		/* ... */
		memset( storage, 0, STORAGE_SIZE );
		storageInitialised = FALSE;

		return( CRYPT_OK );
		}

	/* Data from 0...dataLength has been updated, write it to backing store,
	   optionally erasing the remaining area.  cryptlib updates are atomic 
	   so the entire data block will be updated at once, there won't be any
	   random-access changes made to ranges within the data block */
	/* ... */
	memset( storage + dataLength, 0, STORAGE_SIZE - dataLength );

	return( CRYPT_OK );
	}

/* Clone an existing hardware object into a new object, replacing the 
   existing storage reference with the new one */

int hwCloneNotify( int *storageRef )
	{
	const PERSONALITY_INFO *originalPersonalityInfoPtr;
	PERSONALITY_INFO *clonedPersonalityInfoPtr;
	const int originalStorageRef = *storageRef;
	int newStorageRef, status;

	/* Clear the cloned storage reference to make sure that we don't try and 
	   delete it twice, once via the original and once via the cloned 
	   object */
	*storageRef = CRYPT_ERROR;

	/* Find a free personality that we can clone the existing one into */
	status = findFreePersonality( &newStorageRef );
	if( cryptStatusError( status ) )
		return( status );
	clonedPersonalityInfoPtr = getPersonality( newStorageRef );

	/* Clone the existing personality into the new one */
	originalPersonalityInfoPtr = getPersonality( originalStorageRef );
	memcpy( clonedPersonalityInfoPtr, originalPersonalityInfoPtr, 
			sizeof( PERSONALITY_INFO ) );
	*storageRef = newStorageRef;

	return( CRYPT_OK );
	}

/* Look up an item held in the hardware */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int hwLookupItem( IN_BUFFER( storageIDlength ) const void *storageID,
				  IN_LENGTH_SHORT const int storageIDlength,
				  OUT_INT_Z int *storageRef )
	{
	assert( isReadPtrDynamic( storageID, storageIDlength ) );
	assert( isWritePtr( storageRef, sizeof( int ) ) );

	REQUIRES( storageIDlength >= 4 && storageIDlength <= KEYID_SIZE );

	/* Clear return value */
	*storageRef = CRYPT_ERROR;

	return( lookupPersonality( storageID, storageIDlength, storageRef ) );
	}

/* Delete an item held in the hardware */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int hwDeleteItem( IN_PTR_OPT void *contextHandle,
				  IN_BUFFER( storageIDlength ) \
						const void *storageID,
				  IN_LENGTH_FIXED( KEYID_SIZE ) \
						const int storageIDlength,
				  IN_INT_Z const int storageRef )
	{
	assert( isReadPtrDynamic( storageID, storageIDlength ) );

	REQUIRES( contextHandle == NULL );
	REQUIRES( storageIDlength == KEYID_SIZE );
	REQUIRES( storageRef >= 0 && storageRef < NO_PERSONALITIES );

	deletePersonality( storageRef );
	return( CRYPT_OK );
	}

/* Initialise/zeroise the hardware, which for this device just consists of 
   clearing the hardware personalities */

int hwInitialise( void )
	{
	LOOP_INDEX i;

	LOOP_MED( i = 0, i < NO_PERSONALITIES, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, NO_PERSONALITIES - 1 ) );

		deletePersonality( i );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}
#endif /* USE_HARDWARE */
