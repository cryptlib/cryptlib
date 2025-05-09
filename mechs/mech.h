/****************************************************************************
*																			*
*					  Signature/Keyex Mechanism Header File					*
*						Copyright Peter Gutmann 1992-2020					*
*																			*
****************************************************************************/

#ifndef _MECHANISM_DEFINED

#define _MECHANISM_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #else
	#include "io/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/****************************************************************************
*																			*
*							ASN.1 Constants and Macros						*
*																			*
****************************************************************************/

/* CMS version numbers for various objects.  They're monotonically increasing
   because it was thought that this was enough to distinguish the record
   types (see the note about CMS misdesign above).  This was eventually fixed
   but the odd version numbers remain, except for PWRI which was done right */

enum { KEYTRANS_VERSION, SIGNATURE_VERSION, KEYTRANS_EX_VERSION,
	   SIGNATURE_EX_VERSION, KEK_VERSION, PWRI_VERSION = 0 };

/* Context-specific tags for the RecipientInfo record.  KeyTrans has no tag
   (actually it has an implied 0 tag because of CMS misdesign, so the other
   tags start at 1) */

enum { CTAG_RI_KEYAGREE = 1, CTAG_RI_KEK, CTAG_RI_PASSWORD, CTAG_RI_OTHER };

/****************************************************************************
*																			*
*							Mechanism Function Prototypes					*
*																			*
****************************************************************************/

/* The data formats for key exchange/transport and signature types.  These
   are an extension of the externally-visible cryptlib formats and are needed
   for things like X.509 signatures and various secure session protocols
   that wrap stuff other than straight keys up using a KEK.  Note the non-
   orthogonal handling of reading/writing CMS signatures, this is needed
   because creating a CMS signature involves adding assorted additional data
   like iAndS and signed attributes that present too much information to
   pass into a basic writeSignature() call */

typedef enum {
	KEYEX_NONE,			/* No recipient type */
	KEYEX_CMS,			/* iAndS + algoID + OCTET STRING */
	KEYEX_CMS_OAEP,		/* As CMS but using OAEP not PKCS #1 */
	KEYEX_CRYPTLIB,		/* keyID + algoID + OCTET STRING */
	KEYEX_CRYPTLIB_OAEP,/* As Cryptlib but using OAEP not PKCS #1 */
	KEYEX_PGP,			/* PGP keyID + MPI */
	KEYEX_LAST			/* Last possible recipient type */
	} KEYEX_TYPE;

typedef enum {
	SIGNATURE_NONE,		/* No signature type */
	SIGNATURE_RAW,		/* BIT STRING */
	SIGNATURE_X509,		/* algoID + BIT STRING */
	SIGNATURE_CMS,		/* sigAlgoID + OCTET STRING (write) */
						/* iAndS + hAlgoID + sAlgoID + OCTET STRING (read) */
	SIGNATURE_CMS_PSS,	/* As CMS but using PSS not PKCS #1 */
	SIGNATURE_CRYPTLIB,	/* keyID + hashAlgoID + sigAlgoID + OCTET STRING */
	SIGNATURE_PGP,		/* PGP MPIs */
	SIGNATURE_SSH,		/* SSHv2 sig.record */
	SIGNATURE_TLS,		/* Raw signature data (no encapsulation) with dual hash */
	SIGNATURE_TLS12,	/* As TLS but with PKCS #1 format */
	SIGNATURE_TLS13,	/* As TLS but with RSA-PSS format */
	SIGNATURE_LAST		/* Last possible signature type */
	} SIGNATURE_TYPE;

/* Signature read/write methods for the different format types.  Specifying
   input ranges gets a bit complicated because the functions are polymorphic 
   so we have to provide the lowest common denominator of all functions */

typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *READSIG_FUNCTION )( INOUT_PTR STREAM *stream, 
								   OUT_PTR QUERY_INFO *queryInfo );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
		int ( *WRITESIG_FUNCTION )( INOUT_PTR STREAM *stream,
									IN_HANDLE_OPT \
										const CRYPT_CONTEXT iSignContext,
									IN_ENUM_OPT( CRYPT_ALGO ) \
										const CRYPT_ALGO_TYPE hashAlgo,
									IN_INT_SHORT_Z const int hashParam,
									IN_ENUM_OPT( CRYPT_ALGO ) \
										const CRYPT_ALGO_TYPE signAlgo,
									IN_BUFFER( signatureLength ) \
										const BYTE *signature,
									IN_LENGTH_SHORT_MIN( 40 ) \
										const int signatureLength );

CHECK_RETVAL_PTR \
READSIG_FUNCTION getReadSigFunction( IN_ENUM( SIGNATURE ) \
										const SIGNATURE_TYPE sigType );
CHECK_RETVAL_PTR \
WRITESIG_FUNCTION getWriteSigFunction( IN_ENUM( SIGNATURE ) \
										const SIGNATURE_TYPE sigType );

/* Key exchange read/write methods for the different format types.  Specifying
   input ranges gets a bit complicated because the functions are polymorphic 
   so we have to provide the lowest common denominator of all functions */

typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *READKEYTRANS_FUNCTION )( INOUT_PTR STREAM *stream, 
										OUT_PTR QUERY_INFO *queryInfo );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
		int ( *WRITEKEYTRANS_FUNCTION )( INOUT_PTR STREAM *stream,
										 IN_HANDLE const CRYPT_CONTEXT iCryptContext,
										 IN_BUFFER( encryptedKeyLength ) \
											const BYTE *encryptedKey, 
										 IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
											const int encryptedKeyLength,
										 IN_BUFFER_OPT( auxInfoLength ) \
											const void *auxInfo,
										 IN_LENGTH_SHORT_Z \
											const int auxInfoLength );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *READKEK_FUNCTION )( INOUT_PTR STREAM *stream, 
								   OUT_PTR QUERY_INFO *queryInfo );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
		int ( *WRITEKEK_FUNCTION )( STREAM *stream,
									IN_HANDLE const CRYPT_CONTEXT iCryptContext,
									IN_BUFFER_OPT( encryptedKeyLength ) \
										const BYTE *encryptedKey, 
									IN_LENGTH_SHORT_Z \
										const int encryptedKeyLength );

CHECK_RETVAL_PTR \
READKEYTRANS_FUNCTION getReadKeytransFunction( IN_ENUM( KEYEX ) \
												const KEYEX_TYPE keyexType );
CHECK_RETVAL_PTR \
WRITEKEYTRANS_FUNCTION getWriteKeytransFunction( IN_ENUM( KEYEX ) \
													const KEYEX_TYPE keyexType );
CHECK_RETVAL_PTR \
READKEK_FUNCTION getReadKekFunction( IN_ENUM( KEYEX ) \
										const KEYEX_TYPE keyexType );
CHECK_RETVAL_PTR \
WRITEKEK_FUNCTION getWriteKekFunction( IN_ENUM( KEYEX ) \
										const KEYEX_TYPE keyexType );

/* Prototypes for keyex functions in keyex_int.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 7 ) ) \
int exportConventionalKey( OUT_BUFFER_OPT( encryptedKeyMaxLength, \
										   *encryptedKeyLength ) \
								void *encryptedKey, 
						   IN_LENGTH_SHORT_Z const int encryptedKeyMaxLength,
						   OUT_LENGTH_BOUNDED_SHORT_Z( encryptedKeyMaxLength ) \
								int *encryptedKeyLength,
						   IN_HANDLE_OPT \
								const CRYPT_CONTEXT iSessionKeyContext,
						   IN_HANDLE const CRYPT_CONTEXT iExportContext,
						   IN_ENUM( KEYEX ) const KEYEX_TYPE keyexType,
						   INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 9 ) ) \
int exportPublicKey( OUT_BUFFER_OPT( encryptedKeyMaxLength, \
									 *encryptedKeyLength ) \
						void *encryptedKey, 
					 IN_LENGTH_SHORT_Z const int encryptedKeyMaxLength,
					 OUT_LENGTH_BOUNDED_SHORT_Z( encryptedKeyMaxLength ) \
						int *encryptedKeyLength,
					 IN_HANDLE const CRYPT_CONTEXT iSessionKeyContext,
					 IN_HANDLE const CRYPT_CONTEXT iExportContext,
					 IN_BUFFER_OPT( auxInfoLength ) const void *auxInfo, 
					 IN_LENGTH_SHORT_Z const int auxInfoLength,
					 IN_ENUM( KEYEX ) const KEYEX_TYPE keyexType,
					 INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
int importConventionalKey( IN_BUFFER( encryptedKeyLength ) \
								const void *encryptedKey, 
						   IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
								const int encryptedKeyLength,
						   IN_HANDLE const CRYPT_CONTEXT iSessionKeyContext,
						   IN_HANDLE const CRYPT_CONTEXT iImportContext,
						   IN_ENUM( KEYEX ) const KEYEX_TYPE keyexType,
						   INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 7 ) ) \
int importPublicKey( IN_BUFFER( encryptedKeyLength ) const void *encryptedKey, 
					 IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
						const int encryptedKeyLength,
					 IN_HANDLE_OPT const CRYPT_CONTEXT iSessionKeyContext,
					 IN_HANDLE const CRYPT_CONTEXT iImportContext,
					 OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iReturnedContext, 
					 IN_ENUM( KEYEX ) const KEYEX_TYPE keyexType,
					 INOUT_PTR ERROR_INFO *errorInfo );

/* Prototypes for signature functions in sign_cms.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 11 ) ) \
int createSignatureCMS( OUT_BUFFER_OPT( sigMaxLength, *signatureLength ) \
							void *signature, 
						IN_LENGTH_SHORT_Z const int sigMaxLength, 
						OUT_LENGTH_BOUNDED_SHORT_Z( sigMaxLength ) \
							int *signatureLength,
						IN_HANDLE const CRYPT_CONTEXT signContext,
						IN_HANDLE const CRYPT_CONTEXT iHashContext,
						IN_BOOL const BOOLEAN useDefaultAuthAttr,
						IN_HANDLE_OPT const CRYPT_CERTIFICATE iAuthAttr,
						IN_HANDLE_OPT const CRYPT_SESSION iTspSession,
						IN_ENUM( SIGNATURE ) \
							const SIGNATURE_TYPE signatureType,
						IN_BOOL const BOOLEAN useSmimeSig,
						INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 7 ) ) \
int checkSignatureCMS( IN_BUFFER( signatureLength ) const void *signature, 
					   IN_DATALENGTH const int signatureLength,
					   IN_HANDLE const CRYPT_CONTEXT sigCheckContext,
					   IN_HANDLE const CRYPT_CONTEXT iHashContext,
					   OUT_OPT_HANDLE_OPT CRYPT_CERTIFICATE *iExtraData,
					   IN_HANDLE const CRYPT_HANDLE iSigCheckKey,
					   INOUT_PTR ERROR_INFO *errorInfo );

/* Prototypes for signature functions in sign_pgp.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 9 ) ) \
int createSignaturePGP( OUT_BUFFER_OPT( sigMaxLength, *signatureLength ) \
							void *signature, 
						IN_LENGTH_SHORT_Z const int sigMaxLength, 
						OUT_LENGTH_BOUNDED_SHORT_Z( sigMaxLength ) \
							int *signatureLength, 
						IN_HANDLE const CRYPT_CONTEXT iSignContext,
						IN_HANDLE const CRYPT_CONTEXT iHashContext,
						IN_BUFFER_OPT( sigAttributeLength ) \
							const void *sigAttributes,
						IN_LENGTH_SHORT_Z const int sigAttributeLength,
						IN_RANGE( PGP_SIG_NONE, PGP_SIG_LAST - 1 ) \
							const int sigType,
						INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int checkSignaturePGP( IN_BUFFER( signatureLength ) const void *signature, 
					   IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength,
					   IN_HANDLE const CRYPT_CONTEXT sigCheckContext,
					   IN_HANDLE const CRYPT_CONTEXT iHashContext,
					   INOUT_PTR ERROR_INFO *errorInfo );

/* Prototypes for common low-level signature functions in sign_int.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 8 ) ) \
int createSignature( OUT_BUFFER_OPT( sigMaxLength, *signatureLength ) \
						void *signature, 
					 IN_LENGTH_SHORT_Z const int sigMaxLength, 
					 OUT_LENGTH_BOUNDED_SHORT_Z( sigMaxLength ) \
						int *signatureLength, 
					 IN_HANDLE const CRYPT_CONTEXT iSignContext,
					 IN_HANDLE const CRYPT_CONTEXT iHashContext,
					 IN_HANDLE_OPT const CRYPT_CONTEXT iHashContext2,
					 IN_ENUM( SIGNATURE ) \
						const SIGNATURE_TYPE signatureType,
					 INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 7 ) ) \
int checkSignature( IN_BUFFER( signatureLength ) const void *signature, 
					IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength,
					IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
					IN_HANDLE const CRYPT_CONTEXT iHashContext,
					IN_HANDLE_OPT const CRYPT_CONTEXT iHashContext2,
					IN_ENUM( SIGNATURE ) \
						const SIGNATURE_TYPE signatureType,
					INOUT_PTR ERROR_INFO *errorInfo );

/* Prototypes for functions in keyex_rw.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int getCmsKeyIdentifier( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						 OUT_BUFFER( keyIDMaxLength, *keyIDlength ) \
							BYTE *keyID, 
						 IN_LENGTH_SHORT_MIN( 32 ) \
							const int keyIDMaxLength,
						 OUT_LENGTH_BOUNDED_Z( keyIDMaxLength ) \
							int *keyIDlength );

/* Prototypes for functions in sign_rw.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readPgpOnepassSigPacket( INOUT_PTR STREAM *stream, 
							 INOUT_PTR QUERY_INFO *queryInfo );

/* Prototypes for functions in obj_qry.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getPgpPacketInfo( INOUT_PTR STREAM *stream, 
					  OUT_PTR QUERY_INFO *queryInfo,
					  const QUERYOBJECT_TYPE objectTypeHint );

#endif /* _MECHANISM_DEFINED */
