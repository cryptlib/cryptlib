/****************************************************************************
*																			*
*						 Internal Mechanism Header File						*
*						Copyright Peter Gutmann 1992-2008					*
*																			*
****************************************************************************/

#ifndef _MECH_INT_DEFINED

#define _MECH_INT_DEFINED

#ifndef _DEVMECH_DEFINED
  #if defined( INC_ALL )
	#include "dev_mech.h"
  #else
	#include "mechs/dev_mech.h"
  #endif /* Compiler-specific includes */
#endif /* _DEVMECH_DEFINED */

/* Prototypes for functions in mech_int.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int adjustPKCS1Data( OUT_BUFFER_FIXED( outDataMaxLen ) BYTE *outData, 
					 IN_LENGTH_SHORT_MIN( CRYPT_MAX_PKCSIZE ) \
						const int outDataMaxLen, 
					 IN_BUFFER( inLen ) const BYTE *inData, 
					 IN_LENGTH_SHORT const int inLen, 
					 IN_LENGTH_SHORT const int keySize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int getPkcAlgoParams( IN_HANDLE const CRYPT_CONTEXT pkcContext,
					  OUT_OPT_ALGO_Z CRYPT_ALGO_TYPE *pkcAlgo, 
					  OUT_LENGTH_PKC_Z int *pkcKeySize );
#if defined( USE_OAEP ) || defined( USE_PSS )
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int mgf1( OUT_BUFFER_FIXED( maskLen ) void *mask, 
		  IN_LENGTH_PKC const int maskLen, 
		  IN_BUFFER( seedLen ) const void *seed, 
		  IN_LENGTH_PKC const int seedLen,
		  IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
		  IN_LENGTH_HASH_Z const int hashParam );
#endif /* USE_OAEP || USE_PSS */
CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int getHashAlgoParams( IN_HANDLE const CRYPT_CONTEXT hashContext,
					   OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo, 
					   OUT_OPT_LENGTH_HASH_Z int *hashParam );

/* Prototypes for kernel-internal access functions.  This is a bit of an odd 
   place to have them but we need to have a prototype visible to both the
   mechanism code where they're called and the kernel code */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int extractKeyData( IN_HANDLE const CRYPT_CONTEXT iCryptContext, 
					OUT_BUFFER_FIXED( keyDataLen ) void *keyData, 
					IN_LENGTH_SHORT_MIN( MIN_KEYSIZE ) const int keyDataLen, 
					IN_BUFFER( accessKeyLen ) const char *accessKey, 
					IN_LENGTH_FIXED( 7 ) const int accessKeyLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int importPrivateKeyData( IN_BUFFER( privKeyDataLen ) const void *privKeyData, 
						  IN_LENGTH_SHORT_MIN( 32 ) const int privKeyDataLen,
						  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						  IN_ENUM( KEYFORMAT ) \
							const KEYFORMAT_TYPE formatType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 6 ) ) \
int exportPrivateKeyData( OUT_BUFFER_OPT( privKeyDataMaxLength, \
										  *privKeyDataLength ) \
							void *privKeyData, 
						  IN_LENGTH_SHORT_Z const int privKeyDataMaxLength,
						  OUT_LENGTH_SHORT_Z int *privKeyDataLength,
						  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						  IN_ENUM( KEYFORMAT ) \
							const KEYFORMAT_TYPE formatType,
						  IN_BUFFER( accessKeyLen ) const char *accessKey, 
						  IN_LENGTH_FIXED( 11 ) const int accessKeyLen );

#endif /* _MECH_INT_DEFINED */
