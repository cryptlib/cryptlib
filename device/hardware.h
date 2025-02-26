/****************************************************************************
*																			*
*					cryptlib Generic Crypto HW Header						*
*					Copyright Peter Gutmann 1998-2020						*
*																			*
****************************************************************************/

#ifndef _HARDWARE_DEFINED

#define _HARDWARE_DEFINED

/* The access functions that must be provided by each HAL module */

int hwGetCapabilities( const CAPABILITY_INFO **capabilityInfo,
					   int *noCapabilities );
int hwGetMechanisms( const MECHANISM_FUNCTION_INFO **mechanismFunctions, 
					 int *mechanismFunctionCount );
int hwGetRandom( void *buffer, const int length );
int hwCatalogQuery( MESSAGE_CATALOGQUERY_INFO *queryInfo, 
					const CATALOGQUERY_ITEM_TYPE itemType );
CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int hwGetStorage( IN_PTR_OPT void *contextHandle,
				  OUT_BUFFER_ALLOC_OPT( *storageSize ) void **storageAddr,
				  OUT_LENGTH int *storageSize );
CHECK_RETVAL \
int hwStorageUpdateNotify( IN_PTR_OPT void *contextHandle,
						   IN_LENGTH_Z const int dataLength );
int hwCloneNotify( int *storageRef );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int hwLookupItem( IN_BUFFER( storageIDlength ) const void *storageID,
				  IN_LENGTH_SHORT const int storageIDlength,
				  OUT_INT_Z int *storageRef );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int hwDeleteItem( IN_PTR_OPT void *contextHandle,
				  IN_BUFFER( storageIDlength ) \
						const void *storageID,
				  IN_LENGTH_FIXED( KEYID_SIZE ) \
						const int storageIDlength,
				  IN_INT_Z const int storageRef );
int hwInitialise( void );
int hwSelfTest( void );

/* Helper functions in hardware.c that may be used by HAL modules */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int setPersonalityMapping( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						   IN_INT_Z const int keyHandle,
						   OUT_BUFFER_FIXED( storageIDlength ) \
								void *storageID, 
						   IN_LENGTH_FIXED( KEYID_SIZE ) \
								const int storageIDlength );
#if !defined( CONFIG_CRYPTO_HW1 ) && !defined( CONFIG_CRYPTO_HW2 )
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int generatePKCcomponents( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						   OUT_PTR void *keyInfo, 
						   IN_LENGTH_PKC_BITS const int keySizeBits );
#endif /* !CONFIG_CRYPTO_HW1 && !CONFIG_CRYPTO_HW1 */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getPKCinfo( const CONTEXT_INFO *contextInfoPtr, 
				OUT_PTR void *keyInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setPKCinfo( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
				const void *keyInfo );
CHECK_RETVAL \
int setConvInfo( IN_HANDLE const CRYPT_CONTEXT iCryptContext, 
				 IN_LENGTH_KEY const int keySize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int cleanupHardwareContext( INOUT_PTR CONTEXT_INFO *contextInfoPtr );

#endif /* _HARDWARE_DEFINED */
