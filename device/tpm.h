/****************************************************************************
*																			*
*						cryptlib TPM API Interface							*
*						Copyright Peter Gutmann 2020-2022					*
*																			*
****************************************************************************/

#ifdef USE_TPM

/* Include the TPM TSS2 headers */

#if defined( INC_ALL )
  #include "tss2_fapi.h"
  #include "tss2_mu.h"
#else
  #include "device/tss2_fapi.h"
  #include "device/tss2_mu.h"
#endif /* Compiler-specific includes */

/* There's no readily-available FAPI driver under Windows so we have to
   emulate the FAPI functions that are available under Unix.  This 
   capability also makes debugging easier when it's not necessary to reset 
   and reinitialise the TPM on each run */

#ifdef __WINDOWS__
  #define USE_TPM_EMULATION
#endif /* __WINDOWS__ */

/* The length of the storage ID string used in FAPI object paths, see the 
   long comment in device/tpm.c:tpmGetObjectPath() for details */
   
#define TPM_STORAGEID_STRING_LENGTH		12

/* Prototypes for TPM FAPI functions */

typedef TSS2_RC ( *FAPI_CREATEKEY )( FAPI_CONTEXT *context, char const *path, 
									 char const *type, 
									 char const *policyPath, 
									 char const *authValue );
typedef TSS2_RC ( *FAPI_CREATENV )( FAPI_CONTEXT *context, char const *path, 
									char const *type, size_t size, 
									char const *policyPath, 
									char const *authValue );
typedef TSS2_RC ( *FAPI_DECRYPT )( FAPI_CONTEXT *context, char const *keyPath, 
								   uint8_t const *cipherText, 
								   size_t cipherTextSize, uint8_t **plainText, 
								   size_t *plainTextSize );
typedef TSS2_RC ( *FAPI_DELETE )( FAPI_CONTEXT *context, 
								  char const *path );
typedef void ( *FAPI_FINALIZE )( FAPI_CONTEXT **context );
typedef void ( *FAPI_FREE )( void *ptr );
typedef TSS2_RC ( *FAPI_GETAPPDATA )( FAPI_CONTEXT *context,
									  char const *path,
									  uint8_t **appData,
									  size_t *appDataSize );
typedef TSS2_RC ( *FAPI_GETINFO )( FAPI_CONTEXT *context, char **info );
typedef TSS2_RC ( *FAPI_GETRANDOM )( FAPI_CONTEXT *context, size_t numBytes, 
									 uint8_t **data );
typedef TSS2_RC ( *FAPI_GETTPMBLOBS )( FAPI_CONTEXT *context, char const *path, 
									   uint8_t **tpm2bPublic, 
									   size_t *tpm2bPublicSize, 
									   uint8_t **tpm2bPrivate, 
									   size_t *tpm2bPrivateSize, 
									   char **policy );
typedef TSS2_RC ( *FAPI_INITIALIZE )( FAPI_CONTEXT **context, 
									  char const *uri );
typedef TSS2_RC ( *FAPI_PROVISION )( FAPI_CONTEXT *context, 
									 const char *authValueEh,
									 const char *authValueSh, 
									 const char *authValueLockout );
typedef TSS2_RC ( *FAPI_SETAPPDATA )( FAPI_CONTEXT *context,
									  char const *path,
									  uint8_t const *appData,
									  size_t appDataSize );
typedef TSS2_RC ( *FAPI_SIGN )( FAPI_CONTEXT *context, char const *keyPath, 
								char const *padding, uint8_t const *digest, 
								size_t digestSize, uint8_t **signature, 
								size_t *signatureSize, char **publicKey, 
								char **certificate );

/* Prototypes for additional TPM functions needed to augment the FAPI ones */

typedef TSS2_RC ( *TSS2_MU_TPM2B_PUBLIC_UNMARSHAL )( uint8_t const buffer[],
													 size_t buffer_size,
													 size_t *offset,
													 TPM2B_PUBLIC *dest );

/* Since the dynamically-loaded FAPI functions are accessed via function 
   pointers we have to convert them back into what look like standard 
   functions for the compiler to work with them unless we're using TPM
   emulation, in which case they actually are standard functions */

#ifdef USE_TPM_EMULATION

#define pFapi_CreateNv			Fapi_CreateNv
#define pFapi_Delete			Fapi_Delete
#define pFapi_Finalize			Fapi_Finalize
#define pFapi_Free				Fapi_Free
#define pFapi_GetAppData		Fapi_GetAppData
#define pFapi_GetInfo			Fapi_GetInfo
#define pFapi_GetRandom			Fapi_GetRandom	 
#define pFapi_Initialize		Fapi_Initialize
#define pFapi_Provision			Fapi_Provision 
#define pFapi_SetAppData		Fapi_SetAppData
#define pTss2_MU_TPM2B_PUBLIC_Unmarshal \
								Tss2_MU_TPM2B_PUBLIC_Unmarshal
#else

extern FAPI_CREATEKEY pFapi_CreateKey;
extern FAPI_DECRYPT pFapi_Decrypt;
extern FAPI_DELETE pFapi_Delete;
extern FAPI_FREE pFapi_Free;
extern FAPI_GETTPMBLOBS pFapi_GetTpmBlobs;
extern FAPI_SIGN pFapi_Sign;
extern TSS2_MU_TPM2B_PUBLIC_UNMARSHAL pTss2_MU_TPM2B_PUBLIC_Unmarshal;

#define Fapi_CreateKey		( *pFapi_CreateKey )
#define Fapi_CreateNv		( *pFapi_CreateNv )
#define Fapi_Decrypt		( *pFapi_Decrypt )
#define Fapi_Delete			( *pFapi_Delete )
#define Fapi_Finalize		( *pFapi_Finalize )
#define Fapi_Free			( *pFapi_Free )
#define Fapi_GetAppData		( *pFapi_GetAppData )
#define Fapi_GetInfo		( *pFapi_GetInfo )
#define Fapi_GetRandom		( *pFapi_GetRandom )
#define Fapi_GetTpmBlobs	( *pFapi_GetTpmBlobs )
#define Fapi_Initialize		( *pFapi_Initialize )
#define Fapi_Provision		( *pFapi_Provision )
#define Fapi_SetAppData		( *pFapi_SetAppData )
#define Fapi_Sign			( *pFapi_Sign )
#define Tss2_MU_TPM2B_PUBLIC_Unmarshal \
							( *pTss2_MU_TPM2B_PUBLIC_Unmarshal )

#endif /* USE_TPM_EMULATION */

/* Prototypes for functions in tpm.c */

CHECK_RETVAL \
int tpmMapError( const TSS2_RC tssResult, 
				 IN_ERROR const int defaultError );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int tpmGetObjectPath( OUT_BUFFER( maxStringLength, *stringLength ) \
							char *string,
					  IN_LENGTH_SHORT_MIN( 32 ) \
							const int maxStringLength, 
					  OUT_LENGTH_SHORT_Z int *stringLength,
					  IN_ALGO const CRYPT_ALGO_TYPE algorithm,
					  IN_BUFFER( storageIDlen ) \
							const BYTE *storageID,
					  IN_LENGTH_FIXED( KEYID_SIZE ) \
							const int storageIDlen );

/* Prototypes for functions in tpm_pkc.c */

CHECK_RETVAL \
int tpmInitCapabilities( void );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int tpmGetCapabilities( INOUT_PTR DEVICE_INFO *deviceInfoPtr );

#endif /* USE_TPM */
