<<<<<<< HEAD
/****************************************************************************
*																			*
*							Kernel Storage Regions							*
*						Copyright Peter Gutmann 1997-2020					*
*																			*
****************************************************************************/

#ifdef __STDC__
  #include <stddef.h>		/* For offsetof() */
#endif /* __STDC__ */
#include "crypt.h"

/* General storage includes */
#if defined( INC_ALL )
  #ifdef USE_CERTIFICATES
	#include "trustmgr_int.h"
  #endif /* USE_CERTIFICATES */
  #include "acl.h"
  #ifdef USE_TCP
	#include "tcp_int.h"
  #endif /* USE_TCP */
  #include "kernel.h"
  #include "user_int.h"
  #include "random_int.h"
  #ifdef USE_TLS
	#include "scorebrd_int.h"
  #endif /* USE_TLS */
#else
  #ifdef USE_CERTIFICATES
	#include "cert/trustmgr_int.h"		/* Trust information */
  #endif /* USE_CERTIFICATES */
  #ifdef USE_TCP
	#include "io/tcp_int.h"				/* Network socket pool */
  #endif /* USE_TCP */
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
  #include "misc/user_int.h"
  #include "random/random_int.h"
  #ifdef USE_TLS
	#include "session/scorebrd_int.h"	/* Session scoreboard */
  #endif /* USE_TLS */
#endif /* Compiler-specific includes */

/* Object-specific storage includes */
#if defined( INC_ALL )
  #include "context.h"
  #include "aes.h"
  #include "gcm.h"
  #include "sha.h"
  #include "sha2.h"
  #include "device.h"
  #ifdef USE_KEYSETS
	#include "keyset.h"
  #endif /* USE_KEYSETS */
  #include "user.h"
#else
  #include "context/context.h"
  #include "crypt/aes.h"
  #include "crypt/gcm.h"
  #include "crypt/sha.h"
  #include "crypt/sha2.h"
  #include "device/device.h"
  #ifdef USE_KEYSETS
	#include "keyset/keyset.h"
  #endif /* USE_KEYSETS */
  #include "misc/user.h"
#endif /* Compiler-specific includes */

/* Define the following to print a trace of the alloc/free operations */

#if !defined( NDEBUG ) && 0
  #define TRACE_DIAG( message ) \
		  DEBUG_DIAG( message )
#else
  #define TRACE_DIAG( message )
#endif /* NDEBUG */

/****************************************************************************
*																			*
*							Object-specific Storage							*
*																			*
****************************************************************************/

/* Alongside the global kernel storage in storage.c, cryptlib also reserves 
   static storage space for object data.  This makes it possible to create a 
   given number of commonly-used objects without having to use dynamic 
   allocation.  
   
   In addition to the general-purpose object storage we also allocate room 
   for a device object for the system device and a user object for the 
   default user object, since these are allocated at init time they're 
   always assigned to the system device and default user.
   
   For example for SSH we need two AES contexts and two HMAC-SHA2 contexts, 
   for TLS we need two AES context, two SHA-2 contexts (for hanshake hashes), 
   and two HMAC-SHA2 contexts, and for both we need a SHA-1 context for legacy 
   hashing before SHA-2 can be negotiated.  The full context list is:

	Selftest for object creation: AES.

	SSH: SHA1 + SHA2 to hash the handshake.
		 (DH + RSA for keyex)
		 AES x 2 + HMAC-SHA2 x 2 for the session.

	TLS: MD5 + SHA1 + SHA2 to hash the handshake.
		 (DH + RSA for keyex, RSA for certs)
		 SHA2 for the keyex hash.
		   SHA2 clone for initiator vs.responder hash.
		 AES x 2 + HMAC-SHA2 x 2 for the session.

	Envelopes: AES + SHA1 + SHA2 + HMAC-SHA2 from sessions should cover it.

	Keysets: AES + HMAC-SHA2 from sessions should cover it.

   The following values define how many blocks of storage we reserve for each 
   context type */

#define NO_AES_CONTEXTS			2
#define NO_SHA1_CONTEXTS		1
#define NO_SHA2_CONTEXTS		2
#define NO_HMAC_SHA2_CONTEXTS	2

/* Device and user objects, to store the system object, default user object,
   and optional crypto object.  Since each object has subtype-specific 
   storage following it we also allocate a block of storage for the subtype 
   that follows the object storage which isn't accessed directly but 
   implicitly follows the object storage */

typedef struct {
	DEVICE_INFO deviceInfo;
	SYSTEMDEV_INFO deviceInfoStorage;
	} SYSTEM_DEVICE_STORAGE;

typedef struct {
	USER_INFO userObjectInfo;
	} USER_OBJECT_STORAGE;

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
typedef struct {
	DEVICE_INFO deviceInfo;
	HARDWARE_INFO deviceInfoStorage;
	} CRYPTO_DEVICE_STORAGE;
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

/* Keyset objects, to store file keysets.  If we're using a separate crypto 
   object then we need an extra keyset since the hardware device that
   implements it uses a keyset for backing storage */

#ifdef USE_KEYSETS
typedef struct {
	KEYSET_INFO keysetInfo;
	FILE_INFO fileInfoStorage;
	} KEYSET_STORAGE;
#endif /* USE_KEYSETS */

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
  #define NO_KEYSET_OBJECTS	2
#else
  #define NO_KEYSET_OBJECTS	1
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

/* Context data alignment/padding specifiers, from cryptctx.c */

#define CONTEXT_INFO_ALIGN_SIZE	\
		roundUp( sizeof( CONTEXT_INFO ), CONTEXT_STORAGE_ALIGN_SIZE )

/* AES data alignment/padding specifiers, from ctx_aes.c */

#define AES_EKEY			aes_encrypt_ctx
#define AES_DKEY			aes_decrypt_ctx
#define AES_GCM_CTX			gcm_ctx
#define UNIT_SIZE			16
#define BYTE_SIZE( x )		( UNIT_SIZE * ( ( sizeof( x ) + UNIT_SIZE - 1 ) / UNIT_SIZE ) )
 #define KS_SIZE			( BYTE_SIZE( AES_EKEY ) + BYTE_SIZE( AES_DKEY ) + UNIT_SIZE )
typedef unsigned long _unit;
typedef struct {	
	_unit ksch[ ( KS_SIZE + sizeof( _unit ) - 1 ) / sizeof( _unit ) ];
	} AES_CTX;
#ifdef USE_GCM
  #define AES_KEYDATA_SIZE	( sizeof( AES_GCM_CTX ) + UNIT_SIZE )
#else
  #define AES_KEYDATA_SIZE	( sizeof( AES_CTX ) + UNIT_SIZE )
#endif /* USE_GCM */

/* SHA-1 data alignment/padding specifiers, from ctx_sha1.c */

#define SHA1_STATE_SIZE		sizeof( SHA_CTX )

/* SHA-2 data alignment/padding specifiers, from ctx_sha2.c */

#define SHA2_STATE_SIZE		sizeof( sha2_ctx )

/* HMAC-SHA2 data alignment/padding specifiers, from ctx_sha2.c */

typedef struct {
	sha2_ctx macState, initialMacState;
	} SHA2_MAC_STATE;
#define SHA2_MAC_STATE_SIZE		sizeof( SHA2_MAC_STATE )

/* Storage requirements for each context type.  There's no explicit subtype 
   alignment size included for AES since it uses its own alignment rather
   than the default CONTEXT_STORAGE_ALIGN_SIZE */

#define CONV_STORAGE( size ) \
		( CONTEXT_INFO_ALIGN_SIZE + sizeof( CONV_INFO ) + ( size ) )
#define HASH_STORAGE( size ) \
		( CONTEXT_INFO_ALIGN_SIZE + sizeof( HASH_INFO ) + ( size ) + CONTEXT_STORAGE_ALIGN_SIZE )
#define MAC_STORAGE( size ) \
		( CONTEXT_INFO_ALIGN_SIZE + sizeof( MAC_INFO ) + ( size ) + CONTEXT_STORAGE_ALIGN_SIZE )

typedef BYTE AES_STORAGE[ CONV_STORAGE( AES_KEYDATA_SIZE ) ];
typedef BYTE SHA1_STORAGE[ HASH_STORAGE( SHA1_STATE_SIZE ) ];
typedef BYTE SHA2_STORAGE[ HASH_STORAGE( SHA2_STATE_SIZE ) ];
typedef BYTE HMAC_SHA2_STORAGE[ MAC_STORAGE( SHA2_MAC_STATE_SIZE ) ];

/****************************************************************************
*																			*
*								Static Storage								*
*																			*
****************************************************************************/

/* cryptlib uses a preset amount of fixed storage for kernel data structures
   and built-in objects, which can be allocated statically at compile time
   rather than dynamically.  The following structure contains this fixed 
   storage, consisting of the kernel data, the object table, and any other 
   fixed storage blocks that might be needed.  This is allocated in non-
   pageable storage if the underlying OS supports it, but the fact that it's 
   all co-located in a few constantly-accessed pages also greatly reduces 
   its chances of being paged out anyway */

typedef struct {
	/* The kernel data */
	ALIGN_STRUCT_FIELD \
	KERNEL_DATA krnlData;

	/* The object table */
	ALIGN_STRUCT_FIELD \
	OBJECT_INFO objectTable[ MAX_NO_OBJECTS ];

	/* The randomness information */
	ALIGN_STRUCT_FIELD \
	RANDOM_INFO randomInfo;

	/* The certificate trust information */
#ifdef USE_CERTIFICATES
	TRUST_INFO_CONTAINER trustInfoContainer;	
#endif /* USE_CERTIFICATES */

	/* The network socket pool */
#ifdef USE_TCP
	SOCKET_INFO socketInfo[ SOCKETPOOL_SIZE ];
#endif /* USE_TCP */

	/* The session scoreboard */
#ifdef USE_TLS
	ALIGN_STRUCT_FIELD \
	SCOREBOARD_INFO scoreboardInfo;
#endif /* USE_TLS */

	/* The config option information.  This has a size defined by a complex
	   preprocessor expression (it's not a fixed struct) so we allocate it
	   as a byte array and let the caller manage it */
	BYTE optionInfo[ OPTION_INFO_SIZE ];

	/* Object-specific storage */
	ALIGN_STRUCT_FIELD \
	SYSTEM_DEVICE_STORAGE systemDeviceStorage[ 1 ];
	BOOLEAN systemDeviceStorageUsed[ 1 ];
	ALIGN_STRUCT_FIELD \
	USER_OBJECT_STORAGE userObjectStorage[ 1 ];
	BOOLEAN userObjectStorageUsed[ 1 ];
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	ALIGN_STRUCT_FIELD \
	CRYPTO_DEVICE_STORAGE cryptoDeviceStorage[ 1 ];
	BOOLEAN cryptoDeviceStorageUsed[ 1 ];
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
#ifdef USE_KEYSETS
	ALIGN_STRUCT_FIELD \
	KEYSET_STORAGE keysetStorage[ NO_KEYSET_OBJECTS ];
	BOOLEAN keysetStorageUsed[ NO_KEYSET_OBJECTS ];
#endif /* USE_KEYSETS */
	ALIGN_STRUCT_FIELD \
	AES_STORAGE aesStorage[ NO_AES_CONTEXTS ];
	BOOLEAN aesStorageUsed[ NO_AES_CONTEXTS ];
	ALIGN_STRUCT_FIELD \
	SHA1_STORAGE sha1Storage[ NO_SHA1_CONTEXTS ];
	BOOLEAN sha1StorageUsed[ NO_SHA1_CONTEXTS ];
	ALIGN_STRUCT_FIELD \
	SHA2_STORAGE sha2Storage[ NO_SHA2_CONTEXTS ];
	BOOLEAN sha2StorageUsed[ NO_SHA2_CONTEXTS ];
	ALIGN_STRUCT_FIELD \
	HMAC_SHA2_STORAGE hmacSha2Storage[ NO_HMAC_SHA2_CONTEXTS ];
	BOOLEAN hmacSha2StorageUsed[ NO_HMAC_SHA2_CONTEXTS ];
	} STORAGE_STRUCT;

static STORAGE_STRUCT systemStorage;

/****************************************************************************
*																			*
*							Static Storage Management						*
*																			*
****************************************************************************/

/* Initialise and destroy the built-in storage info */

void initBuiltinStorage( void )
	{
	( void ) lockMemory( &systemStorage, sizeof( STORAGE_STRUCT ) );
	memset( &systemStorage, 0, sizeof( STORAGE_STRUCT ) );

	/* Some of the fields in structures within the built-in storage block
	   need to be aligned to CPU-specific boundaries for CPUs that prefer
	   aligned accesses.  This is handled through the ALIGN_STRUCT_FIELD 
	   macro, in the debug build we perform a check that the fields are 
	   indeed aligned.  If they're not this isn't fatal, it just leads to
	   a slight inefficiency in access on some rare (possibly nonexistent) 
	   systems that require alignment but for which ALIGN_STRUCT_FIELD has 
	   no effect */
	assert( ALIGN_FIELD_CHECK( &systemStorage.krnlData ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.objectTable ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.randomInfo ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.systemDeviceStorage[ 0 ] ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.userObjectStorage[ 0 ] ) );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	assert( ALIGN_FIELD_CHECK( &systemStorage.cryptoDeviceStorage[ 0 ] ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
#ifdef USE_KEYSETS
	assert( ALIGN_FIELD_CHECK( &systemStorage.keysetStorage[ 0 ] ) );
#endif /* USE_KEYSETS */
	assert( ALIGN_FIELD_CHECK( &systemStorage.aesStorage[ 0 ] ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.sha1Storage[ 0 ] ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.sha2Storage[ 0 ] ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.hmacSha2Storage[ 0 ] ) );
	}

void destroyBuiltinStorage( void )
	{
	memset( &systemStorage, 0, sizeof( STORAGE_STRUCT ) );
	unlockMemory( &systemStorage, sizeof( STORAGE_STRUCT ), FALSE );
	}

/* When we start up and shut down the kernel, we need to clear the kernel
   data.  However, the init lock may have been set by an external management
   function, so we can't clear that part of the kernel data.  In addition,
   on shutdown the shutdown level value must stay set so that any threads
   still running will be forced to exit at the earliest possible instance,
   and remain set after the shutdown has completed.  To handle this, we use
   the following macro to clear only the appropriate area of the kernel data
   block */

void clearKernelData( void )
	{
	KERNEL_DATA *krnlDataPtr = &systemStorage.krnlData;

#ifdef __STDC__
	zeroise( ( BYTE * ) krnlDataPtr + offsetof( KERNEL_DATA, initLevel ), 
			 sizeof( KERNEL_DATA ) - offsetof( KERNEL_DATA, initLevel ) );
#else
	assert( &krnlDataPtr->endMarker - &krnlDataPtr->initLevel < sizeof( KERNEL_DATA ) ); 
	zeroise( ( void * ) &krnlDataPtr->initLevel, 
			 &krnlDataPtr->endMarker - &krnlDataPtr->initLevel );
#endif /* C89 compilers */
	}

/* Access functions for the built-in storage, the first for kernel-internal 
   storage, the second for general storage */

void *getSystemStorage( IN_ENUM( SYSTEM_STORAGE ) \
							const SYSTEM_STORAGE_TYPE storageType )
	{
	REQUIRES_N( isEnumRange( storageType, SYSTEM_STORAGE ) );

	switch( storageType )
		{
		case SYSTEM_STORAGE_KRNLDATA:
			return( &systemStorage.krnlData );

		case SYSTEM_STORAGE_OBJECT_TABLE:
			return( systemStorage.objectTable );

		default:
			retIntError_Null();
		}

	retIntError_Null();
	}

void *getBuiltinStorage( IN_ENUM( BUILTIN_STORAGE ) \
							const BUILTIN_STORAGE_TYPE storageType )
	{
	REQUIRES_N( isEnumRange( storageType, BUILTIN_STORAGE ) );

	switch( storageType )
		{
		case BUILTIN_STORAGE_RANDOM_INFO:
			return( &systemStorage.randomInfo );

#ifdef USE_CERTIFICATES
		case BUILTIN_STORAGE_TRUSTMGR:
			return( &systemStorage.trustInfoContainer );
#endif /* USE_CERTIFICATES */

#ifdef USE_TCP
		case BUILTIN_STORAGE_SOCKET_POOL:
			return( &systemStorage.socketInfo );
#endif /* USE_TCP */

#ifdef USE_TLS
		case BUILTIN_STORAGE_SCOREBOARD:
			return( &systemStorage.scoreboardInfo );
#endif /* USE_TLS */

		case BUILTIN_STORAGE_OPTION_INFO:
			return( &systemStorage.optionInfo );
		
		default:
			retIntError_Null();
		}

	retIntError_Null();
	}

/* Obtain and release context-specific storage from the built-in fixed 
   storage block.  Note that this function must be called with the 
   allocation mutex held */

CHECK_RETVAL_PTR \
void *getBuiltinObjectStorage( IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE type,
							   IN_ENUM( SUBTYPE ) const OBJECT_SUBTYPE subType,
							   IN_LENGTH_MIN( 32 ) const int size )
	{
	LOOP_INDEX i;

	REQUIRES_N( isValidType( type ) );
	REQUIRES_N( subType > SUBTYPE_NONE && subType <= SUBTYPE_LAST );
	REQUIRES_N( isBufsizeRangeMin( size, 32 ) );

	/* There's a small but nonzero chance that the storage sizes of two 
	   context subtype objects are the same, the following checks test for 
	   this */
	static_assert( HASH_STORAGE( SHA1_STATE_SIZE ) != HASH_STORAGE( SHA2_STATE_SIZE ),
				   "SHA1/SHA2 storage" );

	switch( type )
		{
		case OBJECT_TYPE_DEVICE:
			if( subType == SUBTYPE_DEV_SYSTEM )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( !systemStorage.systemDeviceStorageUsed[ i ] )
						{
						TRACE_DIAG(( "Allocated static system device "
									 "object #%d", i ));
						systemStorage.systemDeviceStorageUsed[ i ] = TRUE;
						return( &systemStorage.systemDeviceStorage[ i ] );
						}
					}
				ENSURES_N( LOOP_BOUND_OK );

				/* Since there should only be one system device, a failure 
				   to create it, meaning that it already exists, is an 
				   error */
				retIntError_Null();
				}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
			if( subType == SUBTYPE_DEV_HARDWARE )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( !systemStorage.cryptoDeviceStorageUsed[ i ] )
						{
						TRACE_DIAG(( "Allocated static crypto device "
									 "object #%d", i ));
						systemStorage.cryptoDeviceStorageUsed[ i ] = TRUE;
						return( &systemStorage.cryptoDeviceStorage[ i ] );
						}
					}
				ENSURES_N( LOOP_BOUND_OK );

				/* Since there should only be one crypto device, a failure 
				   to create it, meaning that it already exists, is an 
				   error */
				retIntError_Null();
				}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
			break;

		case OBJECT_TYPE_USER:
			if( subType == SUBTYPE_USER_SO )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( !systemStorage.userObjectStorageUsed[ i ] )
						{
						TRACE_DIAG(( "Allocated static user object "
									 "#%d", i ));
						systemStorage.userObjectStorageUsed[ i ] = TRUE;
						return( &systemStorage.userObjectStorage[ i ] );
						}
					}
				ENSURES_N( LOOP_BOUND_OK );
				}
			break;

#ifdef USE_KEYSETS
		case OBJECT_TYPE_KEYSET:
			if( subType == SUBTYPE_KEYSET_FILE )
				{
				LOOP_SMALL( i = 0, i < NO_KEYSET_OBJECTS, i++ )
					{
					ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
													 NO_KEYSET_OBJECTS - 1 ) );

					if( !systemStorage.keysetStorageUsed[ i ] )
						{
						TRACE_DIAG(( "Allocated static file keyset object "
									 "#%d", i ));
						systemStorage.keysetStorageUsed[ i ] = TRUE;
						return( &systemStorage.keysetStorage[ i ] );
						}
					}
				ENSURES_N( LOOP_BOUND_OK );
				}
			break;
#endif /* USE_KEYSETS */

		case OBJECT_TYPE_CONTEXT:
			if( subType == SUBTYPE_CTX_CONV )
				{
				if( size == CONV_STORAGE( AES_KEYDATA_SIZE ) )
					{
					LOOP_SMALL( i = 0, i < NO_AES_CONTEXTS, i++ )
						{
						ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
														 NO_AES_CONTEXTS - 1 ) );

						if( !systemStorage.aesStorageUsed[ i ] )
							{
							TRACE_DIAG(( "Allocated static AES object "
										 "#%d", i ));
							systemStorage.aesStorageUsed[ i ] = TRUE;
							return( &systemStorage.aesStorage[ i ] );
							}
						}
					ENSURES_N( LOOP_BOUND_OK );
					}
				break;
				}
			if( subType == SUBTYPE_CTX_HASH )
				{
				if( size == HASH_STORAGE( SHA1_STATE_SIZE ) )
					{
					LOOP_SMALL( i = 0, i < NO_SHA1_CONTEXTS, i++ )
						{
						ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
														 NO_SHA1_CONTEXTS - 1 ) );
	
						if( !systemStorage.sha1StorageUsed[ i ] )
							{
							TRACE_DIAG(( "Allocated static SHA1 object "
										 "#%d", i ));
							systemStorage.sha1StorageUsed[ i ] = TRUE;
							return( &systemStorage.sha1Storage[ i ] );
							}
						}
					ENSURES_N( LOOP_BOUND_OK );
					}
				if( size == HASH_STORAGE( SHA2_STATE_SIZE ) )
					{
					LOOP_SMALL( i = 0, i < NO_SHA2_CONTEXTS, i++ )
						{
						ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
														 NO_SHA2_CONTEXTS - 1 ) );

						if( !systemStorage.sha2StorageUsed[ i ] )
							{
							TRACE_DIAG(( "Allocated static SHA2 object "
										 "#%d", i ));
							systemStorage.sha2StorageUsed[ i ] = TRUE;
							return( &systemStorage.sha2Storage[ i ] );
							}
						}
					ENSURES_N( LOOP_BOUND_OK );
					}
				break;
				}
			if( subType == SUBTYPE_CTX_MAC )
				{
				if( size == MAC_STORAGE( SHA2_MAC_STATE_SIZE ) )
					{
					LOOP_SMALL( i = 0, i < NO_HMAC_SHA2_CONTEXTS, i++ )
						{
						ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
														 NO_HMAC_SHA2_CONTEXTS - 1 ) );

						if( !systemStorage.hmacSha2StorageUsed[ i ] )
							{
							TRACE_DIAG(( "Allocated static HMAC-SHA2 object "
										 "#%d", i ));
							systemStorage.hmacSha2StorageUsed[ i ] = TRUE;
							return( &systemStorage.hmacSha2Storage[ i ] );
							}
						}
					ENSURES_N( LOOP_BOUND_OK );
					}
				break;
				}
			break;

		default:
			/* It's a type for which there's no static storage allocated, 
			   let the caller allocate it */
			return( NULL );
		}

	/* It's a type for which there's no static storage allocated or all 
	   static storage blocks for this type and subtype have been allocated, 
	   let the caller allocate it */
	return( NULL );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int releaseBuiltinObjectStorage( IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE type,
								 IN_ENUM( SUBTYPE ) const OBJECT_SUBTYPE subType,
								 const void *address )
	{
	LOOP_INDEX i;

	assert( isReadPtr( address, 16 ) );

	REQUIRES( isValidType( type ) );
	REQUIRES( subType > SUBTYPE_NONE && subType <= SUBTYPE_LAST );

	switch( type )
		{
		case OBJECT_TYPE_DEVICE:
			if( subType == SUBTYPE_DEV_SYSTEM )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( address == &systemStorage.systemDeviceStorage[ i ] )
						{
						ENSURES( systemStorage.systemDeviceStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static system device object "
									 "#%d", i ));
						systemStorage.systemDeviceStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
			if( subType == SUBTYPE_DEV_HARDWARE )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( address == &systemStorage.cryptoDeviceStorage[ i ] )
						{
						ENSURES( systemStorage.cryptoDeviceStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static crypto device object "
									 "#%d", i ));
						systemStorage.cryptoDeviceStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
			break;

		case OBJECT_TYPE_USER:
			if( subType == SUBTYPE_USER_SO )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( address == &systemStorage.userObjectStorage[ i ] )
						{
						ENSURES( systemStorage.userObjectStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static user object #%d", i ));
						systemStorage.userObjectStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				}
			break;

#ifdef USE_KEYSETS
		case OBJECT_TYPE_KEYSET:
			if( subType == SUBTYPE_KEYSET_FILE )
				{
				LOOP_SMALL( i = 0, i < NO_KEYSET_OBJECTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_KEYSET_OBJECTS ) );

					if( address == &systemStorage.keysetStorage[ i ] )
						{
						ENSURES( systemStorage.keysetStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static file keyset object "
									 "#%d", i ));
						systemStorage.keysetStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				}
			break;
#endif /* USE_KEYSETS */

		case OBJECT_TYPE_CONTEXT:
			if( subType == SUBTYPE_CTX_CONV )
				{
				LOOP_SMALL( i = 0, i < NO_AES_CONTEXTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_AES_CONTEXTS - 1 ) );

					if( address == &systemStorage.aesStorage[ i ] )
						{
						ENSURES( systemStorage.aesStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static AES object #%d", i ));
						systemStorage.aesStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				break;
				}
			if( subType == SUBTYPE_CTX_HASH )
				{
				/* For the hash contexts we don't have any information beyond
				   the subtype, but at this point we can identify what's what 
				   based on the memory address */
				LOOP_SMALL( i = 0, i < NO_SHA1_CONTEXTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_SHA1_CONTEXTS - 1 ) );

					if( address == &systemStorage.sha1Storage[ i ] )
						{
						ENSURES( systemStorage.sha1StorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static SHA1 object #%d", i ));
						systemStorage.sha1StorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				LOOP_SMALL( i = 0, i < NO_SHA2_CONTEXTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_SHA2_CONTEXTS - 1 ) );

					if( address == &systemStorage.sha2Storage[ i ] )
						{
						ENSURES( systemStorage.sha2StorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static SHA2 object #%d", i ));
						systemStorage.sha2StorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				break;
				}
			if( subType == SUBTYPE_CTX_MAC )
				{
				LOOP_SMALL( i = 0, i < NO_HMAC_SHA2_CONTEXTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_HMAC_SHA2_CONTEXTS - 1 ) );

					if( address == &systemStorage.hmacSha2Storage[ i ] )
						{
						ENSURES( systemStorage.hmacSha2StorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static HMAC-SHA2 object "
									 "#%d", i ));
						systemStorage.hmacSha2StorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				break;
				}
			break;

		default:
			retIntError();
		}

	retIntError();
	}

/* Helper functions used when debugging.  These return the sizes of the 
   various data structures for use with fault-injection testing */

#ifndef NDEBUG

int getSystemStorageSize( IN_ENUM( SYSTEM_STORAGE ) \
								const SYSTEM_STORAGE_TYPE storageType )
	{
	REQUIRES( isEnumRange( storageType, SYSTEM_STORAGE ) );

	switch( storageType )
		{
		case SYSTEM_STORAGE_KRNLDATA:
			return( sizeof( KERNEL_DATA ) );

		case SYSTEM_STORAGE_OBJECT_TABLE:
			return( sizeof( OBJECT_INFO ) * MAX_NO_OBJECTS );

		default:
			retIntError();
		}

	retIntError();
	}

int getBuiltinStorageSize( IN_ENUM( BUILTIN_STORAGE ) \
								const BUILTIN_STORAGE_TYPE storageType )
	{
	REQUIRES( isEnumRange( storageType, BUILTIN_STORAGE ) );

	switch( storageType )
		{
		case BUILTIN_STORAGE_RANDOM_INFO:
			return( sizeof( RANDOM_INFO ) );

#ifdef USE_CERTIFICATES
		case BUILTIN_STORAGE_TRUSTMGR:
			return( sizeof( TRUST_INFO_CONTAINER ) );
#endif /* USE_CERTIFICATES */

#ifdef USE_TCP
		case BUILTIN_STORAGE_SOCKET_POOL:
			return( sizeof( SOCKET_INFO ) * SOCKETPOOL_SIZE );
#endif /* USE_TCP */

#ifdef USE_TLS
		case BUILTIN_STORAGE_SCOREBOARD:
			return( sizeof( SCOREBOARD_INFO ) );
#endif /* USE_TLS */

		case BUILTIN_STORAGE_OPTION_INFO:
			return( OPTION_INFO_SIZE );
		
		default:
			retIntError();
		}

	retIntError();
	}

int getBuiltinObjectStorageSize( IN_ENUM( OBJECT_TYPE ) \
									const OBJECT_TYPE type,
								 IN_ENUM( SUBTYPE ) \
									const OBJECT_SUBTYPE subType,
								 IN_LENGTH_MIN( 32 ) const int size )
	{
	REQUIRES( isValidType( type ) );
	REQUIRES( subType > SUBTYPE_NONE && subType <= SUBTYPE_LAST );
	REQUIRES( isBufsizeRangeMin( size, 32 ) );

	switch( type )
		{
		case OBJECT_TYPE_DEVICE:
			if( subType == SUBTYPE_DEV_SYSTEM )
				return( sizeof( SYSTEM_DEVICE_STORAGE ) ); 
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
			if( subType == SUBTYPE_DEV_HARDWARE )
				return( sizeof( CRYPTO_DEVICE_STORAGE ) ); 
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
			break;

		case OBJECT_TYPE_USER:
			return( sizeof( USER_OBJECT_STORAGE ) );

#ifdef USE_KEYSETS
		case OBJECT_TYPE_KEYSET:
			return( sizeof( KEYSET_STORAGE ) );
#endif /* USE_KEYSETS */

		case OBJECT_TYPE_CONTEXT:
			if( subType == SUBTYPE_CTX_CONV )
				return( sizeof( AES_STORAGE ) );
			if( subType == SUBTYPE_CTX_HASH )
				{
				if( size == HASH_STORAGE( SHA1_STATE_SIZE ) )
					return( sizeof( SHA1_STORAGE ) );
				else
					return( sizeof( SHA2_STORAGE ) );
				}
			if( subType == SUBTYPE_CTX_MAC )
				return( sizeof( HMAC_SHA2_STORAGE ) );
			break;

		default:
			retIntError();
		}

	retIntError();
	}
#endif /* !NDEBUG */
=======
/****************************************************************************
*																			*
*							Kernel Storage Regions							*
*						Copyright Peter Gutmann 1997-2020					*
*																			*
****************************************************************************/

#ifdef __STDC__
  #include <stddef.h>		/* For offsetof() */
#endif /* __STDC__ */
#include "crypt.h"

/* General storage includes */
#if defined( INC_ALL )
  #ifdef USE_CERTIFICATES
	#include "trustmgr_int.h"
  #endif /* USE_CERTIFICATES */
  #include "acl.h"
  #ifdef USE_TCP
	#include "tcp_int.h"
  #endif /* USE_TCP */
  #include "kernel.h"
  #include "user_int.h"
  #include "random_int.h"
  #ifdef USE_TLS
	#include "scorebrd_int.h"
  #endif /* USE_TLS */
#else
  #ifdef USE_CERTIFICATES
	#include "cert/trustmgr_int.h"		/* Trust information */
  #endif /* USE_CERTIFICATES */
  #ifdef USE_TCP
	#include "io/tcp_int.h"				/* Network socket pool */
  #endif /* USE_TCP */
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
  #include "misc/user_int.h"
  #include "random/random_int.h"
  #ifdef USE_TLS
	#include "session/scorebrd_int.h"	/* Session scoreboard */
  #endif /* USE_TLS */
#endif /* Compiler-specific includes */

/* Object-specific storage includes */
#if defined( INC_ALL )
  #include "context.h"
  #include "aes.h"
  #include "gcm.h"
  #include "sha.h"
  #include "sha2.h"
  #include "device.h"
  #ifdef USE_KEYSETS
	#include "keyset.h"
  #endif /* USE_KEYSETS */
  #include "user.h"
#else
  #include "context/context.h"
  #include "crypt/aes.h"
  #include "crypt/gcm.h"
  #include "crypt/sha.h"
  #include "crypt/sha2.h"
  #include "device/device.h"
  #ifdef USE_KEYSETS
	#include "keyset/keyset.h"
  #endif /* USE_KEYSETS */
  #include "misc/user.h"
#endif /* Compiler-specific includes */

/* Define the following to print a trace of the alloc/free operations */

#if !defined( NDEBUG ) && 0
  #define TRACE_DIAG( message ) \
		  DEBUG_DIAG( message )
#else
  #define TRACE_DIAG( message )
#endif /* NDEBUG */

/****************************************************************************
*																			*
*							Object-specific Storage							*
*																			*
****************************************************************************/

/* Alongside the global kernel storage in storage.c, cryptlib also reserves 
   static storage space for object data.  This makes it possible to create a 
   given number of commonly-used objects without having to use dynamic 
   allocation.  
   
   In addition to the general-purpose object storage we also allocate room 
   for a device object for the system device and a user object for the 
   default user object, since these are allocated at init time they're 
   always assigned to the system device and default user.
   
   For example for SSH we need two AES contexts and two HMAC-SHA2 contexts, 
   for TLS we need two AES context, two SHA-2 contexts (for hanshake hashes), 
   and two HMAC-SHA2 contexts, and for both we need a SHA-1 context for legacy 
   hashing before SHA-2 can be negotiated.  The full context list is:

	Selftest for object creation: AES.

	SSH: SHA1 + SHA2 to hash the handshake.
		 (DH + RSA for keyex)
		 AES x 2 + HMAC-SHA2 x 2 for the session.

	TLS: MD5 + SHA1 + SHA2 to hash the handshake.
		 (DH + RSA for keyex, RSA for certs)
		 SHA2 for the keyex hash.
		   SHA2 clone for initiator vs.responder hash.
		 AES x 2 + HMAC-SHA2 x 2 for the session.

	Envelopes: AES + SHA1 + SHA2 + HMAC-SHA2 from sessions should cover it.

	Keysets: AES + HMAC-SHA2 from sessions should cover it.

   The following values define how many blocks of storage we reserve for each 
   context type */

#define NO_AES_CONTEXTS			2
#define NO_SHA1_CONTEXTS		1
#define NO_SHA2_CONTEXTS		2
#define NO_HMAC_SHA2_CONTEXTS	2

/* Device and user objects, to store the system object, default user object,
   and optional crypto object.  Since each object has subtype-specific 
   storage following it we also allocate a block of storage for the subtype 
   that follows the object storage which isn't accessed directly but 
   implicitly follows the object storage */

typedef struct {
	DEVICE_INFO deviceInfo;
	SYSTEMDEV_INFO deviceInfoStorage;
	} SYSTEM_DEVICE_STORAGE;

typedef struct {
	USER_INFO userObjectInfo;
	} USER_OBJECT_STORAGE;

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
typedef struct {
	DEVICE_INFO deviceInfo;
	HARDWARE_INFO deviceInfoStorage;
	} CRYPTO_DEVICE_STORAGE;
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

/* Keyset objects, to store file keysets.  If we're using a separate crypto 
   object then we need an extra keyset since the hardware device that
   implements it uses a keyset for backing storage */

#ifdef USE_KEYSETS
typedef struct {
	KEYSET_INFO keysetInfo;
	FILE_INFO fileInfoStorage;
	} KEYSET_STORAGE;
#endif /* USE_KEYSETS */

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
  #define NO_KEYSET_OBJECTS	2
#else
  #define NO_KEYSET_OBJECTS	1
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

/* Context data alignment/padding specifiers, from cryptctx.c */

#define CONTEXT_INFO_ALIGN_SIZE	\
		roundUp( sizeof( CONTEXT_INFO ), CONTEXT_STORAGE_ALIGN_SIZE )

/* AES data alignment/padding specifiers, from ctx_aes.c */

#define AES_EKEY			aes_encrypt_ctx
#define AES_DKEY			aes_decrypt_ctx
#define AES_GCM_CTX			gcm_ctx
#define UNIT_SIZE			16
#define BYTE_SIZE( x )		( UNIT_SIZE * ( ( sizeof( x ) + UNIT_SIZE - 1 ) / UNIT_SIZE ) )
 #define KS_SIZE			( BYTE_SIZE( AES_EKEY ) + BYTE_SIZE( AES_DKEY ) + UNIT_SIZE )
typedef unsigned long _unit;
typedef struct {	
	_unit ksch[ ( KS_SIZE + sizeof( _unit ) - 1 ) / sizeof( _unit ) ];
	} AES_CTX;
#ifdef USE_GCM
  #define AES_KEYDATA_SIZE	( sizeof( AES_GCM_CTX ) + UNIT_SIZE )
#else
  #define AES_KEYDATA_SIZE	( sizeof( AES_CTX ) + UNIT_SIZE )
#endif /* USE_GCM */

/* SHA-1 data alignment/padding specifiers, from ctx_sha1.c */

#define SHA1_STATE_SIZE		sizeof( SHA_CTX )

/* SHA-2 data alignment/padding specifiers, from ctx_sha2.c */

#define SHA2_STATE_SIZE		sizeof( sha2_ctx )

/* HMAC-SHA2 data alignment/padding specifiers, from ctx_sha2.c */

typedef struct {
	sha2_ctx macState, initialMacState;
	} SHA2_MAC_STATE;
#define SHA2_MAC_STATE_SIZE		sizeof( SHA2_MAC_STATE )

/* Storage requirements for each context type.  There's no explicit subtype 
   alignment size included for AES since it uses its own alignment rather
   than the default CONTEXT_STORAGE_ALIGN_SIZE */

#define CONV_STORAGE( size ) \
		( CONTEXT_INFO_ALIGN_SIZE + sizeof( CONV_INFO ) + ( size ) )
#define HASH_STORAGE( size ) \
		( CONTEXT_INFO_ALIGN_SIZE + sizeof( HASH_INFO ) + ( size ) + CONTEXT_STORAGE_ALIGN_SIZE )
#define MAC_STORAGE( size ) \
		( CONTEXT_INFO_ALIGN_SIZE + sizeof( MAC_INFO ) + ( size ) + CONTEXT_STORAGE_ALIGN_SIZE )

typedef BYTE AES_STORAGE[ CONV_STORAGE( AES_KEYDATA_SIZE ) ];
typedef BYTE SHA1_STORAGE[ HASH_STORAGE( SHA1_STATE_SIZE ) ];
typedef BYTE SHA2_STORAGE[ HASH_STORAGE( SHA2_STATE_SIZE ) ];
typedef BYTE HMAC_SHA2_STORAGE[ MAC_STORAGE( SHA2_MAC_STATE_SIZE ) ];

/****************************************************************************
*																			*
*								Static Storage								*
*																			*
****************************************************************************/

/* cryptlib uses a preset amount of fixed storage for kernel data structures
   and built-in objects, which can be allocated statically at compile time
   rather than dynamically.  The following structure contains this fixed 
   storage, consisting of the kernel data, the object table, and any other 
   fixed storage blocks that might be needed.  This is allocated in non-
   pageable storage if the underlying OS supports it, but the fact that it's 
   all co-located in a few constantly-accessed pages also greatly reduces 
   its chances of being paged out anyway */

typedef struct {
	/* The kernel data */
	ALIGN_STRUCT_FIELD \
	KERNEL_DATA krnlData;

	/* The object table */
	ALIGN_STRUCT_FIELD \
	OBJECT_INFO objectTable[ MAX_NO_OBJECTS ];

	/* The randomness information */
	ALIGN_STRUCT_FIELD \
	RANDOM_INFO randomInfo;

	/* The certificate trust information */
#ifdef USE_CERTIFICATES
	TRUST_INFO_CONTAINER trustInfoContainer;	
#endif /* USE_CERTIFICATES */

	/* The network socket pool */
#ifdef USE_TCP
	SOCKET_INFO socketInfo[ SOCKETPOOL_SIZE ];
#endif /* USE_TCP */

	/* The session scoreboard */
#ifdef USE_TLS
	ALIGN_STRUCT_FIELD \
	SCOREBOARD_INFO scoreboardInfo;
#endif /* USE_TLS */

	/* The config option information.  This has a size defined by a complex
	   preprocessor expression (it's not a fixed struct) so we allocate it
	   as a byte array and let the caller manage it */
	BYTE optionInfo[ OPTION_INFO_SIZE ];

	/* Object-specific storage */
	ALIGN_STRUCT_FIELD \
	SYSTEM_DEVICE_STORAGE systemDeviceStorage[ 1 ];
	BOOLEAN systemDeviceStorageUsed[ 1 ];
	ALIGN_STRUCT_FIELD \
	USER_OBJECT_STORAGE userObjectStorage[ 1 ];
	BOOLEAN userObjectStorageUsed[ 1 ];
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	ALIGN_STRUCT_FIELD \
	CRYPTO_DEVICE_STORAGE cryptoDeviceStorage[ 1 ];
	BOOLEAN cryptoDeviceStorageUsed[ 1 ];
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
#ifdef USE_KEYSETS
	ALIGN_STRUCT_FIELD \
	KEYSET_STORAGE keysetStorage[ NO_KEYSET_OBJECTS ];
	BOOLEAN keysetStorageUsed[ NO_KEYSET_OBJECTS ];
#endif /* USE_KEYSETS */
	ALIGN_STRUCT_FIELD \
	AES_STORAGE aesStorage[ NO_AES_CONTEXTS ];
	BOOLEAN aesStorageUsed[ NO_AES_CONTEXTS ];
	ALIGN_STRUCT_FIELD \
	SHA1_STORAGE sha1Storage[ NO_SHA1_CONTEXTS ];
	BOOLEAN sha1StorageUsed[ NO_SHA1_CONTEXTS ];
	ALIGN_STRUCT_FIELD \
	SHA2_STORAGE sha2Storage[ NO_SHA2_CONTEXTS ];
	BOOLEAN sha2StorageUsed[ NO_SHA2_CONTEXTS ];
	ALIGN_STRUCT_FIELD \
	HMAC_SHA2_STORAGE hmacSha2Storage[ NO_HMAC_SHA2_CONTEXTS ];
	BOOLEAN hmacSha2StorageUsed[ NO_HMAC_SHA2_CONTEXTS ];
	} STORAGE_STRUCT;

static STORAGE_STRUCT systemStorage;

/****************************************************************************
*																			*
*							Static Storage Management						*
*																			*
****************************************************************************/

/* Initialise and destroy the built-in storage info */

void initBuiltinStorage( void )
	{
	( void ) lockMemory( &systemStorage, sizeof( STORAGE_STRUCT ) );
	memset( &systemStorage, 0, sizeof( STORAGE_STRUCT ) );

	/* Some of the fields in structures within the built-in storage block
	   need to be aligned to CPU-specific boundaries for CPUs that prefer
	   aligned accesses.  This is handled through the ALIGN_STRUCT_FIELD 
	   macro, in the debug build we perform a check that the fields are 
	   indeed aligned.  If they're not this isn't fatal, it just leads to
	   a slight inefficiency in access on some rare (possibly nonexistent) 
	   systems that require alignment but for which ALIGN_STRUCT_FIELD has 
	   no effect */
	assert( ALIGN_FIELD_CHECK( &systemStorage.krnlData ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.objectTable ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.randomInfo ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.systemDeviceStorage[ 0 ] ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.userObjectStorage[ 0 ] ) );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	assert( ALIGN_FIELD_CHECK( &systemStorage.cryptoDeviceStorage[ 0 ] ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
#ifdef USE_KEYSETS
	assert( ALIGN_FIELD_CHECK( &systemStorage.keysetStorage[ 0 ] ) );
#endif /* USE_KEYSETS */
	assert( ALIGN_FIELD_CHECK( &systemStorage.aesStorage[ 0 ] ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.sha1Storage[ 0 ] ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.sha2Storage[ 0 ] ) );
	assert( ALIGN_FIELD_CHECK( &systemStorage.hmacSha2Storage[ 0 ] ) );
	}

void destroyBuiltinStorage( void )
	{
	memset( &systemStorage, 0, sizeof( STORAGE_STRUCT ) );
	unlockMemory( &systemStorage, sizeof( STORAGE_STRUCT ), FALSE );
	}

/* When we start up and shut down the kernel, we need to clear the kernel
   data.  However, the init lock may have been set by an external management
   function, so we can't clear that part of the kernel data.  In addition,
   on shutdown the shutdown level value must stay set so that any threads
   still running will be forced to exit at the earliest possible instance,
   and remain set after the shutdown has completed.  To handle this, we use
   the following macro to clear only the appropriate area of the kernel data
   block */

void clearKernelData( void )
	{
	KERNEL_DATA *krnlDataPtr = &systemStorage.krnlData;

#ifdef __STDC__
	zeroise( ( BYTE * ) krnlDataPtr + offsetof( KERNEL_DATA, initLevel ), 
			 sizeof( KERNEL_DATA ) - offsetof( KERNEL_DATA, initLevel ) );
#else
	assert( &krnlDataPtr->endMarker - &krnlDataPtr->initLevel < sizeof( KERNEL_DATA ) ); 
	zeroise( ( void * ) &krnlDataPtr->initLevel, 
			 &krnlDataPtr->endMarker - &krnlDataPtr->initLevel );
#endif /* C89 compilers */
	}

/* Access functions for the built-in storage, the first for kernel-internal 
   storage, the second for general storage */

void *getSystemStorage( IN_ENUM( SYSTEM_STORAGE ) \
							const SYSTEM_STORAGE_TYPE storageType )
	{
	REQUIRES_N( isEnumRange( storageType, SYSTEM_STORAGE ) );

	switch( storageType )
		{
		case SYSTEM_STORAGE_KRNLDATA:
			return( &systemStorage.krnlData );

		case SYSTEM_STORAGE_OBJECT_TABLE:
			return( systemStorage.objectTable );

		default:
			retIntError_Null();
		}

	retIntError_Null();
	}

void *getBuiltinStorage( IN_ENUM( BUILTIN_STORAGE ) \
							const BUILTIN_STORAGE_TYPE storageType )
	{
	REQUIRES_N( isEnumRange( storageType, BUILTIN_STORAGE ) );

	switch( storageType )
		{
		case BUILTIN_STORAGE_RANDOM_INFO:
			return( &systemStorage.randomInfo );

#ifdef USE_CERTIFICATES
		case BUILTIN_STORAGE_TRUSTMGR:
			return( &systemStorage.trustInfoContainer );
#endif /* USE_CERTIFICATES */

#ifdef USE_TCP
		case BUILTIN_STORAGE_SOCKET_POOL:
			return( &systemStorage.socketInfo );
#endif /* USE_TCP */

#ifdef USE_TLS
		case BUILTIN_STORAGE_SCOREBOARD:
			return( &systemStorage.scoreboardInfo );
#endif /* USE_TLS */

		case BUILTIN_STORAGE_OPTION_INFO:
			return( &systemStorage.optionInfo );
		
		default:
			retIntError_Null();
		}

	retIntError_Null();
	}

/* Obtain and release context-specific storage from the built-in fixed 
   storage block.  Note that this function must be called with the 
   allocation mutex held */

CHECK_RETVAL_PTR \
void *getBuiltinObjectStorage( IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE type,
							   IN_ENUM( SUBTYPE ) const OBJECT_SUBTYPE subType,
							   IN_LENGTH_MIN( 32 ) const int size )
	{
	LOOP_INDEX i;

	REQUIRES_N( isValidType( type ) );
	REQUIRES_N( subType > SUBTYPE_NONE && subType <= SUBTYPE_LAST );
	REQUIRES_N( isBufsizeRangeMin( size, 32 ) );

	/* There's a small but nonzero chance that the storage sizes of two 
	   context subtype objects are the same, the following checks test for 
	   this */
	static_assert( HASH_STORAGE( SHA1_STATE_SIZE ) != HASH_STORAGE( SHA2_STATE_SIZE ),
				   "SHA1/SHA2 storage" );

	switch( type )
		{
		case OBJECT_TYPE_DEVICE:
			if( subType == SUBTYPE_DEV_SYSTEM )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( !systemStorage.systemDeviceStorageUsed[ i ] )
						{
						TRACE_DIAG(( "Allocated static system device "
									 "object #%d", i ));
						systemStorage.systemDeviceStorageUsed[ i ] = TRUE;
						return( &systemStorage.systemDeviceStorage[ i ] );
						}
					}
				ENSURES_N( LOOP_BOUND_OK );

				/* Since there should only be one system device, a failure 
				   to create it, meaning that it already exists, is an 
				   error */
				retIntError_Null();
				}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
			if( subType == SUBTYPE_DEV_HARDWARE )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( !systemStorage.cryptoDeviceStorageUsed[ i ] )
						{
						TRACE_DIAG(( "Allocated static crypto device "
									 "object #%d", i ));
						systemStorage.cryptoDeviceStorageUsed[ i ] = TRUE;
						return( &systemStorage.cryptoDeviceStorage[ i ] );
						}
					}
				ENSURES_N( LOOP_BOUND_OK );

				/* Since there should only be one crypto device, a failure 
				   to create it, meaning that it already exists, is an 
				   error */
				retIntError_Null();
				}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
			break;

		case OBJECT_TYPE_USER:
			if( subType == SUBTYPE_USER_SO )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( !systemStorage.userObjectStorageUsed[ i ] )
						{
						TRACE_DIAG(( "Allocated static user object "
									 "#%d", i ));
						systemStorage.userObjectStorageUsed[ i ] = TRUE;
						return( &systemStorage.userObjectStorage[ i ] );
						}
					}
				ENSURES_N( LOOP_BOUND_OK );
				}
			break;

#ifdef USE_KEYSETS
		case OBJECT_TYPE_KEYSET:
			if( subType == SUBTYPE_KEYSET_FILE )
				{
				LOOP_SMALL( i = 0, i < NO_KEYSET_OBJECTS, i++ )
					{
					ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
													 NO_KEYSET_OBJECTS - 1 ) );

					if( !systemStorage.keysetStorageUsed[ i ] )
						{
						TRACE_DIAG(( "Allocated static file keyset object "
									 "#%d", i ));
						systemStorage.keysetStorageUsed[ i ] = TRUE;
						return( &systemStorage.keysetStorage[ i ] );
						}
					}
				ENSURES_N( LOOP_BOUND_OK );
				}
			break;
#endif /* USE_KEYSETS */

		case OBJECT_TYPE_CONTEXT:
			if( subType == SUBTYPE_CTX_CONV )
				{
				if( size == CONV_STORAGE( AES_KEYDATA_SIZE ) )
					{
					LOOP_SMALL( i = 0, i < NO_AES_CONTEXTS, i++ )
						{
						ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
														 NO_AES_CONTEXTS - 1 ) );

						if( !systemStorage.aesStorageUsed[ i ] )
							{
							TRACE_DIAG(( "Allocated static AES object "
										 "#%d", i ));
							systemStorage.aesStorageUsed[ i ] = TRUE;
							return( &systemStorage.aesStorage[ i ] );
							}
						}
					ENSURES_N( LOOP_BOUND_OK );
					}
				break;
				}
			if( subType == SUBTYPE_CTX_HASH )
				{
				if( size == HASH_STORAGE( SHA1_STATE_SIZE ) )
					{
					LOOP_SMALL( i = 0, i < NO_SHA1_CONTEXTS, i++ )
						{
						ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
														 NO_SHA1_CONTEXTS - 1 ) );
	
						if( !systemStorage.sha1StorageUsed[ i ] )
							{
							TRACE_DIAG(( "Allocated static SHA1 object "
										 "#%d", i ));
							systemStorage.sha1StorageUsed[ i ] = TRUE;
							return( &systemStorage.sha1Storage[ i ] );
							}
						}
					ENSURES_N( LOOP_BOUND_OK );
					}
				if( size == HASH_STORAGE( SHA2_STATE_SIZE ) )
					{
					LOOP_SMALL( i = 0, i < NO_SHA2_CONTEXTS, i++ )
						{
						ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
														 NO_SHA2_CONTEXTS - 1 ) );

						if( !systemStorage.sha2StorageUsed[ i ] )
							{
							TRACE_DIAG(( "Allocated static SHA2 object "
										 "#%d", i ));
							systemStorage.sha2StorageUsed[ i ] = TRUE;
							return( &systemStorage.sha2Storage[ i ] );
							}
						}
					ENSURES_N( LOOP_BOUND_OK );
					}
				break;
				}
			if( subType == SUBTYPE_CTX_MAC )
				{
				if( size == MAC_STORAGE( SHA2_MAC_STATE_SIZE ) )
					{
					LOOP_SMALL( i = 0, i < NO_HMAC_SHA2_CONTEXTS, i++ )
						{
						ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
														 NO_HMAC_SHA2_CONTEXTS - 1 ) );

						if( !systemStorage.hmacSha2StorageUsed[ i ] )
							{
							TRACE_DIAG(( "Allocated static HMAC-SHA2 object "
										 "#%d", i ));
							systemStorage.hmacSha2StorageUsed[ i ] = TRUE;
							return( &systemStorage.hmacSha2Storage[ i ] );
							}
						}
					ENSURES_N( LOOP_BOUND_OK );
					}
				break;
				}
			break;

		default:
			/* It's a type for which there's no static storage allocated, 
			   let the caller allocate it */
			return( NULL );
		}

	/* It's a type for which there's no static storage allocated or all 
	   static storage blocks for this type and subtype have been allocated, 
	   let the caller allocate it */
	return( NULL );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int releaseBuiltinObjectStorage( IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE type,
								 IN_ENUM( SUBTYPE ) const OBJECT_SUBTYPE subType,
								 const void *address )
	{
	LOOP_INDEX i;

	assert( isReadPtr( address, 16 ) );

	REQUIRES( isValidType( type ) );
	REQUIRES( subType > SUBTYPE_NONE && subType <= SUBTYPE_LAST );

	switch( type )
		{
		case OBJECT_TYPE_DEVICE:
			if( subType == SUBTYPE_DEV_SYSTEM )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( address == &systemStorage.systemDeviceStorage[ i ] )
						{
						ENSURES( systemStorage.systemDeviceStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static system device object "
									 "#%d", i ));
						systemStorage.systemDeviceStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				}
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
			if( subType == SUBTYPE_DEV_HARDWARE )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( address == &systemStorage.cryptoDeviceStorage[ i ] )
						{
						ENSURES( systemStorage.cryptoDeviceStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static crypto device object "
									 "#%d", i ));
						systemStorage.cryptoDeviceStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				}
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
			break;

		case OBJECT_TYPE_USER:
			if( subType == SUBTYPE_USER_SO )
				{
				LOOP_SMALL( i = 0, i < 1, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 0 ) );

					if( address == &systemStorage.userObjectStorage[ i ] )
						{
						ENSURES( systemStorage.userObjectStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static user object #%d", i ));
						systemStorage.userObjectStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				}
			break;

#ifdef USE_KEYSETS
		case OBJECT_TYPE_KEYSET:
			if( subType == SUBTYPE_KEYSET_FILE )
				{
				LOOP_SMALL( i = 0, i < NO_KEYSET_OBJECTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_KEYSET_OBJECTS ) );

					if( address == &systemStorage.keysetStorage[ i ] )
						{
						ENSURES( systemStorage.keysetStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static file keyset object "
									 "#%d", i ));
						systemStorage.keysetStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				}
			break;
#endif /* USE_KEYSETS */

		case OBJECT_TYPE_CONTEXT:
			if( subType == SUBTYPE_CTX_CONV )
				{
				LOOP_SMALL( i = 0, i < NO_AES_CONTEXTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_AES_CONTEXTS - 1 ) );

					if( address == &systemStorage.aesStorage[ i ] )
						{
						ENSURES( systemStorage.aesStorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static AES object #%d", i ));
						systemStorage.aesStorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				break;
				}
			if( subType == SUBTYPE_CTX_HASH )
				{
				/* For the hash contexts we don't have any information beyond
				   the subtype, but at this point we can identify what's what 
				   based on the memory address */
				LOOP_SMALL( i = 0, i < NO_SHA1_CONTEXTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_SHA1_CONTEXTS - 1 ) );

					if( address == &systemStorage.sha1Storage[ i ] )
						{
						ENSURES( systemStorage.sha1StorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static SHA1 object #%d", i ));
						systemStorage.sha1StorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				LOOP_SMALL( i = 0, i < NO_SHA2_CONTEXTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_SHA2_CONTEXTS - 1 ) );

					if( address == &systemStorage.sha2Storage[ i ] )
						{
						ENSURES( systemStorage.sha2StorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static SHA2 object #%d", i ));
						systemStorage.sha2StorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				break;
				}
			if( subType == SUBTYPE_CTX_MAC )
				{
				LOOP_SMALL( i = 0, i < NO_HMAC_SHA2_CONTEXTS, i++ )
					{
					ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
												   NO_HMAC_SHA2_CONTEXTS - 1 ) );

					if( address == &systemStorage.hmacSha2Storage[ i ] )
						{
						ENSURES( systemStorage.hmacSha2StorageUsed[ i ] == TRUE );
						TRACE_DIAG(( "Freed static HMAC-SHA2 object "
									 "#%d", i ));
						systemStorage.hmacSha2StorageUsed[ i ] = FALSE;
						return( CRYPT_OK );
						}
					}
				ENSURES( LOOP_BOUND_OK );
				break;
				}
			break;

		default:
			retIntError();
		}

	retIntError();
	}

/* Helper functions used when debugging.  These return the sizes of the 
   various data structures for use with fault-injection testing */

#ifndef NDEBUG

int getSystemStorageSize( IN_ENUM( SYSTEM_STORAGE ) \
								const SYSTEM_STORAGE_TYPE storageType )
	{
	REQUIRES( isEnumRange( storageType, SYSTEM_STORAGE ) );

	switch( storageType )
		{
		case SYSTEM_STORAGE_KRNLDATA:
			return( sizeof( KERNEL_DATA ) );

		case SYSTEM_STORAGE_OBJECT_TABLE:
			return( sizeof( OBJECT_INFO ) * MAX_NO_OBJECTS );

		default:
			retIntError();
		}

	retIntError();
	}

int getBuiltinStorageSize( IN_ENUM( BUILTIN_STORAGE ) \
								const BUILTIN_STORAGE_TYPE storageType )
	{
	REQUIRES( isEnumRange( storageType, BUILTIN_STORAGE ) );

	switch( storageType )
		{
		case BUILTIN_STORAGE_RANDOM_INFO:
			return( sizeof( RANDOM_INFO ) );

#ifdef USE_CERTIFICATES
		case BUILTIN_STORAGE_TRUSTMGR:
			return( sizeof( TRUST_INFO_CONTAINER ) );
#endif /* USE_CERTIFICATES */

#ifdef USE_TCP
		case BUILTIN_STORAGE_SOCKET_POOL:
			return( sizeof( SOCKET_INFO ) * SOCKETPOOL_SIZE );
#endif /* USE_TCP */

#ifdef USE_TLS
		case BUILTIN_STORAGE_SCOREBOARD:
			return( sizeof( SCOREBOARD_INFO ) );
#endif /* USE_TLS */

		case BUILTIN_STORAGE_OPTION_INFO:
			return( OPTION_INFO_SIZE );
		
		default:
			retIntError();
		}

	retIntError();
	}

int getBuiltinObjectStorageSize( IN_ENUM( OBJECT_TYPE ) \
									const OBJECT_TYPE type,
								 IN_ENUM( SUBTYPE ) \
									const OBJECT_SUBTYPE subType,
								 IN_LENGTH_MIN( 32 ) const int size )
	{
	REQUIRES( isValidType( type ) );
	REQUIRES( subType > SUBTYPE_NONE && subType <= SUBTYPE_LAST );
	REQUIRES( isBufsizeRangeMin( size, 32 ) );

	switch( type )
		{
		case OBJECT_TYPE_DEVICE:
			if( subType == SUBTYPE_DEV_SYSTEM )
				return( sizeof( SYSTEM_DEVICE_STORAGE ) ); 
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
			if( subType == SUBTYPE_DEV_HARDWARE )
				return( sizeof( CRYPTO_DEVICE_STORAGE ) ); 
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
			break;

		case OBJECT_TYPE_USER:
			return( sizeof( USER_OBJECT_STORAGE ) );

#ifdef USE_KEYSETS
		case OBJECT_TYPE_KEYSET:
			return( sizeof( KEYSET_STORAGE ) );
#endif /* USE_KEYSETS */

		case OBJECT_TYPE_CONTEXT:
			if( subType == SUBTYPE_CTX_CONV )
				return( sizeof( AES_STORAGE ) );
			if( subType == SUBTYPE_CTX_HASH )
				{
				if( size == HASH_STORAGE( SHA1_STATE_SIZE ) )
					return( sizeof( SHA1_STORAGE ) );
				else
					return( sizeof( SHA2_STORAGE ) );
				}
			if( subType == SUBTYPE_CTX_MAC )
				return( sizeof( HMAC_SHA2_STORAGE ) );
			break;

		default:
			retIntError();
		}

	retIntError();
	}
#endif /* !NDEBUG */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
