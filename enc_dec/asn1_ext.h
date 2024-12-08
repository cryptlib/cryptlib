<<<<<<< HEAD
/****************************************************************************
*																			*
*				ASN.1 Supplementary Constants and Structures				*
*						Copyright Peter Gutmann 1992-2019					*
*																			*
****************************************************************************/

#ifndef _ASN1OID_DEFINED

#define _ASN1OID_DEFINED

/* Additional information required when reading a CMS header.  This is
   pointed to by the extraInfo member of the ASN.1 OID_INFO structure and
   contains CMS version number information */

typedef struct {
	const int minVersion;	/* Minimum version number for content type */
	const int maxVersion;	/* Maximum version number for content type */
	} CMS_CONTENT_INFO;

#ifdef USE_INT_ASN1

/****************************************************************************
*																			*
*									ASN.1 OIDs								*
*																			*
****************************************************************************/

/* The cryptlib (strictly speaking DDS) OID arc is as follows:

	1 3 6 1 4 1 3029 = dds
					 1 = algorithm
					   1 = symmetric encryption
						 1 = blowfishECB
						 2 = blowfishCBC
						 3 = blowfishCFB
						 4 = blowfishOFB
					   2 = public-key encryption
						 1 = elgamal
					   3 = hash (placeholder)
					   4 = MAC (placeholder)
					 2 = mechanism (placeholder)
					 3 = attribute
					   1 = PKIX fixes
						 1 = cryptlibPresenceCheck
						 2 = pkiBoot
						 (3 unused)
						 4 = cRLExtReason
						 5 = keyFeatures
					   2 = CMS (placeholder)
					 4 = content-type
					   1 = cryptlib
						 1 = cryptlibConfigData
						 2 = cryptlibUserIndex
						 3 = cryptlibUserInfo
						 4 = cryptlibRtcsRequest
						 5 = cryptlibRtcsResponse
						 6 = cryptlibRtcsResponseExt
					 x36 xDD x24 x36 = TSA policy ('snooze policy, "Anything 
									   that arrives, we sign").
					 x58 x59 x5A x5A x59 = XYZZY cert policy */

/* Attribute OIDs */

#define OID_ESS_CERTID		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0C" )
							/* 1 2 840 113549 1 9 16 2 12 */
#define OID_TSP_TSTOKEN		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0E" )
							/* 1 2 840 113549 1 9 16 2 14 */
#define OID_PKCS9_FRIENDLYNAME MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x14" )
							/* 1 2 840 113549 1 9 20 */
#define OID_PKCS9_LOCALKEYID MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x15" )
							/* 1 2 840 113549 1 9 21 */
#define OID_PKCS9_X509CERTIFICATE MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x16\x01" )
							/* 1 2 840 113549 1 9 22 1 */
#define OID_CRYPTLIB_PRESENCECHECK MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x01" )
							/* 1 3 6 1 4 1 3029 3 1 1 */

/* The PKCS #9 OID for cert extensions in a certification request, from the
   CMMF draft.  Naturally MS had to define their own incompatible OID for
   this, so we check for this as well */

#define OID_PKCS9_EXTREQ	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0E" )
							/* 1 2 840 113549 1 9 14 */
#define OID_MS_EXTREQ		MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0E" )
							/* 1 3 6 1 4 1 311 2 1 14 */

/* Envelope content-type OIDs */

#define OID_CMS_DATA		MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01" )
							/* 1 2 840 113549 1 7 1 */
#define OID_CMS_SIGNEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" )
							/* 1 2 840 113549 1 7 2 */
#define OID_CMS_ENVELOPEDDATA MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03" )
							/* 1 2 840 113549 1 7 3 */
#define OID_CMS_DIGESTEDDATA MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05" )
							/* 1 2 840 113549 1 7 5 */
#define OID_CMS_ENCRYPTEDDATA MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06" )
							/* 1 2 840 113549 1 7 6 */
#define OID_CMS_AUTHDATA	MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x02" )
							/* 1 2 840 113549 1 9 16 1 2 */
#define OID_CMS_COMPRESSEDDATA MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x09" )
							/* 1 2 840 113549 1 9 16 1 9 */
#define OID_CMS_AUTHENVDATA	MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x17" )
							/* 1 2 840 113549 1 9 16 1 23 */

/* PKI content-type OIDs */

#define OID_TSP_TSTINFO		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x04" )
							/* 1 2 840 113549 1 9 16 1 4 */
#define OID_SCVP_CERTVALREQUEST MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x0A" )
							/* 1 2 840 113549 1 9 16 1 10 */
#define OID_SCVP_CERTVALRESPONSE MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x0B" )
							/* 1 2 840 113549 1 9 16 1 11 */
#define OID_SCVP_VALPOLREQUEST MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x0C" )
							/* 1 2 840 113549 1 9 16 1 12 */
#define OID_SCVP_VALPOLRESPONSE MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x0D" )
							/* 1 2 840 113549 1 9 16 1 13 */
#define OID_CRYPTLIB_RTCSREQ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x04" )
							/* 1 3 6 1 4 1 3029 4 1 4 */
#define OID_CRYPTLIB_RTCSRESP MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x05" )
							/* 1 3 6 1 4 1 3029 4 1 5 */
#define OID_CRYPTLIB_RTCSRESP_EXT MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x06" )
							/* 1 3 6 1 4 1 3029 4 1 6 */
#define OID_OCSP_RESPONSE_OCSP MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01" )
							/* 1 3 6 1 5 5 7 48 1 1 */

/* Misc content-type OIDs */

#define OID_PKCS15_CONTENTTYPE MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0F\x03\x01" )
							/* 1 2 840 113549 1 15 3 1 */
#define OID_MS_SPCINDIRECTDATACONTEXT MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x04" )
							/* 1 3 6 1 4 1 311 2 1 4 */
#define OID_PKIBOOT			MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x02" )
							/* 1 3 6 1 4 1 3029 3 1 2 */
#define OID_CRYPTLIB_CONTENTTYPE MKOID( "\x06\x09\x2B\x06\x01\x04\x01\x97\x55\x04\x01" )
							/* 1 3 6 1 4 1 3029 4 1 */
#define OID_CRYPTLIB_CONFIGDATA MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x01" )
							/* 1 3 6 1 4 1 3029 4 1 1 */
#define OID_CRYPTLIB_USERINDEX MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x02" )
							/* 1 3 6 1 4 1 3029 4 1 2 */
#define OID_CRYPTLIB_USERINFO MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x03" )
							/* 1 3 6 1 4 1 3029 4 1 3 */
#define OID_NS_CERTSEQ		MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x02\x05" )
							/* 2 16 840 1 113730 2 5 */

/* PKCS #12 OIDs */

#define OID_PKCS12_PBEWITHSHAAND3KEYTRIPLEDESCBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x03" )
							/* 1 2 840 113549 1 12 1 3 */
#define OID_PKCS12_PBEWITHSHAAND2KEYTRIPLEDESCBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x04" )
							/* 1 2 840 113549 1 12 1 4 */
#define OID_PKCS12_PBEWITHSHAAND40BITRC2CBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x06" )
							/* 1 2 840 113549 1 12 1 6 */
#define OID_PKCS12_SHROUDEDKEYBAG MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x02" )
							/* 1 2 840 113549 1 12 10 1 2 */
#define OID_PKCS12_CERTBAG MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x03" )
							/* 1 2 840 113549 1 12 10 1 3 */

/* Policy OIDs */

#define OID_RPKI_POLICY		MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x0E\x02" )
							/* 1 3 6 1 5 5 7 14 2 */
#define OID_SCVP_DEFAULTCHECKPOLICY MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x11\x03" )
							/* 1 3 6 1 5 5 7 17 3 */
#define OID_SCVP_DEFAULTWANTBACK MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x01" )
							/* 1 3 6 1 5 5 7 18 1 */
#define OID_SCVP_DEFAULTVALPOLICY MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x13\x01" )
							/* 1 3 6 1 5 5 7 19 1 */
#define OID_TSP_POLICY		MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x97\x55\x36\xDD\x24\x36" )
							/* 1 3 6 1 4 1 3029 x36 xDD x24 x36 */
#define OID_CRYPTLIB_XYZZYCERT	MKOID( "\x06\x0C\x2B\x06\x01\x04\x01\x97\x55\x58\x59\x5A\x5A\x59" )
							/* 1 3 6 1 4 1 3029 x58 x59 x5A x5A x59 */
#define OID_ANYPOLICY		MKOID( "\x06\x04\x55\x1D\x20\x00" )
							/* 2 5 29 32 0 */

/* Misc OIDs */

#define OID_PBKDF2			MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C" )
							/* 1 2 840 113549 1 5 12 */
#define OID_PBES2			MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0D" )
							/* 1 2 840 113549 1 5 13 */
#define OID_ZLIB			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x08" )
							/* 1 2 840 113549 1 9 16 3 8 */
#define OID_PWRIKEK			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x09" )
							/* 1 2 840 113549 1 9 16 3 9 */

/****************************************************************************
*																			*
*							ASN.1 Support Functions							*
*																			*
****************************************************************************/

/* Additional specifiers for algorithm classes and encoding formats.  This
   allows us to differentiate between RSA-for-encryption and RSA-for-signing
   and similar cases where the algorithm alone isn't enough */

typedef enum {
	ALGOID_CLASS_NONE,		/* No AlgoID class */
	ALGOID_CLASS_CRYPT,		/* Encryption algorithms */
	ALGOID_CLASS_HASH,		/* Hash/MAC algorithm */
	ALGOID_CLASS_AUTHENC,	/* Authenticated-encryption algorithm */
	ALGOID_CLASS_PKC,		/* Generic PKC algorithm */
	ALGOID_CLASS_PKCSIG,	/* PKC signature algorithm (+ hash algorithm) */
	ALGOID_CLASS_LAST		/* Last possible AlgoID class */
	} ALGOID_CLASS_TYPE;

typedef enum {
	ALGOID_ENCODING_NONE,	/* No encoding type */
	ALGOID_ENCODING_PKCS1,	/* PKCS #1 */
	ALGOID_ENCODING_OAEP,	/* OAEP */
	ALGOID_ENCODING_PSS,	/* PSS */
	ALGOID_ENCODING_LAST	/* Last possible encoding type */
	} ALGOID_ENCODING_TYPE;

typedef struct {
	/* Hash algorithm information, used with signature algorithms, e.g. 
	   sha1withRSAEncryption, hash/MAC algorithms, e.g. HMAC-SHA2/512,
	   and exotic padding schemes like OAEP and PSS */
	CRYPT_ALGO_TYPE hashAlgo;
	int hashParam;

	/* Encryption algorithm information, used with conventional encryption
	   algorithms */
	CRYPT_MODE_TYPE cryptMode;
	int cryptKeySize;

	/* Nonstandard encoding schemes like OAEP and PSS in place of standard
	   PKCS #1 */
	ALGOID_ENCODING_TYPE encodingType;

	/* Encoding-specific details, extra data length.  This is required 
	   because sometimes the algoID parameters are too complex to be 
	   represented here and have to be supplied by the caller, e.g. for the 
	   ECC algorithms, in which case we add the extraLength value to the 
	   algoID length, details to be added by the caller */
	int extraLength;
	} ALGOID_PARAMS;

#define initAlgoIDparams( params ) \
		memset( ( params ), 0, sizeof( ALGOID_PARAMS ) )
#define initAlgoIDparamsHash( params, algo, param ) \
		memset( ( params ), 0, sizeof( ALGOID_PARAMS ) ); \
		( params )->hashAlgo = algo; \
		( params )->hashParam = param
#define initAlgoIDparamsCrypt( params, mode, size ) \
		memset( ( params ), 0, sizeof( ALGOID_PARAMS ) ); \
		( params )->cryptMode = mode; \
		( params )->cryptKeySize = size

/* AlgorithmIdentifier routines */

CHECK_RETVAL_BOOL \
BOOLEAN checkAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					 IN_MODE_OPT const CRYPT_MODE_TYPE cryptMode );
CHECK_RETVAL_LENGTH_SHORT \
int sizeofAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo );
CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 2 ) ) \
int sizeofAlgoIDex( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					const ALGOID_PARAMS *algoIDparams );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoID( INOUT_PTR STREAM *stream, 
				 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
				 IN_TAG const int tag );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeAlgoIDex( INOUT_PTR STREAM *stream, 
				   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
				   const ALGOID_PARAMS *algoIDparams,
				   IN_TAG const int tag );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2) ) \
int readAlgoID( INOUT_PTR STREAM *stream, 
				OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
				IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readAlgoIDexTag( INOUT_PTR STREAM *stream, 
					 OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
					 OUT_PTR ALGOID_PARAMS *algoIDparams,
					 IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type,
					 IN_TAG const int tag );

#define readAlgoIDex( stream, cryptAlgo, algoIDparams, type ) \
		readAlgoIDexTag( stream, cryptAlgo, algoIDparams, type, DEFAULT_TAG ) 

/* Alternative versions that read/write various algorithm ID types (algo and
   mode only or full details depending on the presence of algoIDparams) from 
   contexts */

CHECK_RETVAL_LENGTH \
int sizeofContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext );
CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 2 ) ) \
int sizeofContextAlgoIDex( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						   const ALGOID_PARAMS *algoIDparams );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int readContextAlgoID( INOUT_PTR STREAM *stream, 
					   OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
					   OUT_OPT QUERY_INFO *queryInfo, 
					   IN_TAG const int tag,
					   IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeContextAlgoID( INOUT_PTR STREAM *stream, 
						IN_HANDLE const CRYPT_CONTEXT iCryptContext );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeContextAlgoIDex( INOUT_PTR STREAM *stream, 
						  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						  const ALGOID_PARAMS *algoIDparams );
CHECK_RETVAL_LENGTH \
int sizeofCryptContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCryptContextAlgoID( INOUT_PTR STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext );

/* Read/write a non-crypto algorithm identifier, used for things like 
   content types.  This just wraps the given OID up in the 
   AlgorithmIdentifier and writes it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readGenericAlgoID( INOUT_PTR STREAM *stream, 
					   IN_BUFFER( oidLength ) const BYTE *oid, 
					   IN_LENGTH_OID const int oidLength );
RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeGenericAlgoID( INOUT_PTR STREAM *stream, 
						IN_BUFFER( oidLength ) const BYTE *oid, 
						IN_LENGTH_OID const int oidLength );

/* ECC OID support routines */

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL_LENGTH \
int sizeofECCOID( IN_ENUM( CRYPT_ECCCURVE ) \
					const CRYPT_ECCCURVE_TYPE curveType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readECCOID( INOUT_PTR STREAM *stream, 
				OUT_OPT CRYPT_ECCCURVE_TYPE *curveType,
				OUT_INT_Z int *fieldSize );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeECCOID( INOUT_PTR STREAM *stream, 
				 IN_ENUM( CRYPT_ECCCURVE ) \
					const CRYPT_ECCCURVE_TYPE curveType );

#endif /* USE_ECDH || USE_ECDSA */

/* Message digest support routines */

CHECK_RETVAL_LENGTH_SHORT \
int sizeofMessageDigest( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo, 
						 IN_LENGTH_HASH const int hashSize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readMessageDigest( INOUT_PTR STREAM *stream, 
					   OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo,
					   OUT_BUFFER( hashMaxLen, *hashSize ) void *hash, 
					   IN_LENGTH_HASH const int hashMaxLen, 
					   OUT_LENGTH_BOUNDED_Z( hashMaxLen ) int *hashSize );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeMessageDigest( INOUT_PTR STREAM *stream, 
						IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						IN_BUFFER( hashSize ) const void *hash, 
						IN_LENGTH_HASH const int hashSize );

/* Generic secret support routines.  These functions encode and decode the 
   information needed to recreate the encryption and MAC contexts derived
   from the generic secret */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) \
int getGenericSecretParams( IN_HANDLE const CRYPT_CONTEXT iGenericContext,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iMacContext,
							const QUERY_INFO *queryInfo );
CHECK_RETVAL \
int setGenericSecretParams( IN_HANDLE const CRYPT_CONTEXT iGenericSecret,
							IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							IN_HANDLE const CRYPT_CONTEXT iMacContext,
							IN_ALGO const CRYPT_ALGO_TYPE kdfAlgo );

/* Read/write CMS headers.  The readCMSheader() flags are:

	READCMS_FLAG_AUTHENC: The content uses authenticated encryption, which
			has a different set of permitted content-encryption algorithms 
			than standard encryption.

	READCMS_FLAG_DEFINITELENGTH: Try and obtain a definite length from 
			somewhere in the CMS header rather than returning CRYPT_UNUSED
			for the length, return an error if there's no definite length
			available.  Note that this changes processing in the calling
			code because it can no longer use the length to determine 
			whether it should perform EOC checks if there's an indefinite
			length somwwhere in the header.

	READCMS_FLAG_DEFINITELENGTH_OPT: As READCMS_FLAG_DEFINITELENGTH but 
			return a length of CRYPT_UNUSED if there's no definite length
			information available.

	READCMS_FLAG_INNERHEADER: This is an inner header, the content wrapper
			can be an OCTET STRING as well as the more usual SEQUENCE.

	READCMS_FLAG_WRAPPERONLY: Only read the outer SEQUENCE, OID, [0] wrapper
			without reading the final layer of inner encapsulation, used
			when one CMS content type is redundantly nested directly inside 
			another (Microsoft did this for PKCS #12) */

#define READCMS_FLAG_NONE			0x00	/* No CMS read flag */
#define READCMS_FLAG_INNERHEADER	0x01	/* Inner CMS header */
#define READCMS_FLAG_AUTHENC		0x02	/* Content uses auth.enc */
#define READCMS_FLAG_WRAPPERONLY	0x04	/* Only read wrapper */
#define READCMS_FLAG_DEFINITELENGTH	0x08	/* Try and get definite len */
#define READCMS_FLAG_DEFINITELENGTH_OPT 0x10/* Opt.try and get def.len */
#define READCMS_FLAG_MAX			0x1F	/* Maximum possible flag value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCMSheader( INOUT_PTR STREAM *stream, 
				   IN_ARRAY( noOidInfoEntries ) \
						const OID_INFO *oidInfo, 
				   IN_RANGE( 1, 50 ) const int noOidInfoEntries, 
				   OUT_OPT_INT_Z int *selectionID,
				   OUT_OPT_LENGTH_INDEF long *dataSize, 
				   IN_FLAGS_Z( READCMS ) const int flags );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCMSheader( INOUT_PTR STREAM *stream, 
					IN_BUFFER( contentOIDlength ) \
						const BYTE *contentOID, 
					IN_LENGTH_OID const int contentOIDlength,
					IN_LENGTH_INDEF const long dataSize, 
					IN_BOOL const BOOLEAN isInnerHeader );
CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofCMSencrHeader( IN_BUFFER( contentOIDlength ) \
							const BYTE *contentOID, 
						 IN_LENGTH_OID const int contentOIDlength,
						 IN_LENGTH_INDEF const long dataSize, 
						 IN_HANDLE const CRYPT_CONTEXT iCryptContext );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCMSencrHeader( INOUT_PTR STREAM *stream, 
					   IN_ARRAY( noOidInfoEntries ) \
							const OID_INFO *oidInfo,
					   IN_RANGE( 1, 50 ) const int noOidInfoEntries, 
					   OUT_OPT_INT_Z int *selectionID,
					   OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
					   OUT_OPT QUERY_INFO *queryInfo,
					   IN_FLAGS_Z( READCMS ) const int flags );
RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCMSencrHeader( INOUT_PTR STREAM *stream, 
						IN_BUFFER( contentOIDlength ) \
							const BYTE *contentOID, 
						IN_LENGTH_OID const int contentOIDlength,
						IN_LENGTH_INDEF const long dataSize,
						IN_HANDLE const CRYPT_CONTEXT iCryptContext );

#endif /* USE_INT_ASN1 */
#endif /* _ASN1OID_DEFINED */
=======
/****************************************************************************
*																			*
*				ASN.1 Supplementary Constants and Structures				*
*						Copyright Peter Gutmann 1992-2019					*
*																			*
****************************************************************************/

#ifndef _ASN1OID_DEFINED

#define _ASN1OID_DEFINED

/* Additional information required when reading a CMS header.  This is
   pointed to by the extraInfo member of the ASN.1 OID_INFO structure and
   contains CMS version number information */

typedef struct {
	const int minVersion;	/* Minimum version number for content type */
	const int maxVersion;	/* Maximum version number for content type */
	} CMS_CONTENT_INFO;

#ifdef USE_INT_ASN1

/****************************************************************************
*																			*
*									ASN.1 OIDs								*
*																			*
****************************************************************************/

/* The cryptlib (strictly speaking DDS) OID arc is as follows:

	1 3 6 1 4 1 3029 = dds
					 1 = algorithm
					   1 = symmetric encryption
						 1 = blowfishECB
						 2 = blowfishCBC
						 3 = blowfishCFB
						 4 = blowfishOFB
					   2 = public-key encryption
						 1 = elgamal
					   3 = hash (placeholder)
					   4 = MAC (placeholder)
					 2 = mechanism (placeholder)
					 3 = attribute
					   1 = PKIX fixes
						 1 = cryptlibPresenceCheck
						 2 = pkiBoot
						 (3 unused)
						 4 = cRLExtReason
						 5 = keyFeatures
					   2 = CMS (placeholder)
					 4 = content-type
					   1 = cryptlib
						 1 = cryptlibConfigData
						 2 = cryptlibUserIndex
						 3 = cryptlibUserInfo
						 4 = cryptlibRtcsRequest
						 5 = cryptlibRtcsResponse
						 6 = cryptlibRtcsResponseExt
					 x36 xDD x24 x36 = TSA policy ('snooze policy, "Anything 
									   that arrives, we sign").
					 x58 x59 x5A x5A x59 = XYZZY cert policy */

/* Attribute OIDs */

#define OID_ESS_CERTID		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0C" )
							/* 1 2 840 113549 1 9 16 2 12 */
#define OID_TSP_TSTOKEN		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0E" )
							/* 1 2 840 113549 1 9 16 2 14 */
#define OID_PKCS9_FRIENDLYNAME MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x14" )
							/* 1 2 840 113549 1 9 20 */
#define OID_PKCS9_LOCALKEYID MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x15" )
							/* 1 2 840 113549 1 9 21 */
#define OID_PKCS9_X509CERTIFICATE MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x16\x01" )
							/* 1 2 840 113549 1 9 22 1 */
#define OID_CRYPTLIB_PRESENCECHECK MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x01" )
							/* 1 3 6 1 4 1 3029 3 1 1 */

/* The PKCS #9 OID for cert extensions in a certification request, from the
   CMMF draft.  Naturally MS had to define their own incompatible OID for
   this, so we check for this as well */

#define OID_PKCS9_EXTREQ	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0E" )
							/* 1 2 840 113549 1 9 14 */
#define OID_MS_EXTREQ		MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0E" )
							/* 1 3 6 1 4 1 311 2 1 14 */

/* Envelope content-type OIDs */

#define OID_CMS_DATA		MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01" )
							/* 1 2 840 113549 1 7 1 */
#define OID_CMS_SIGNEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" )
							/* 1 2 840 113549 1 7 2 */
#define OID_CMS_ENVELOPEDDATA MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03" )
							/* 1 2 840 113549 1 7 3 */
#define OID_CMS_DIGESTEDDATA MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05" )
							/* 1 2 840 113549 1 7 5 */
#define OID_CMS_ENCRYPTEDDATA MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06" )
							/* 1 2 840 113549 1 7 6 */
#define OID_CMS_AUTHDATA	MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x02" )
							/* 1 2 840 113549 1 9 16 1 2 */
#define OID_CMS_COMPRESSEDDATA MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x09" )
							/* 1 2 840 113549 1 9 16 1 9 */
#define OID_CMS_AUTHENVDATA	MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x17" )
							/* 1 2 840 113549 1 9 16 1 23 */

/* PKI content-type OIDs */

#define OID_TSP_TSTINFO		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x04" )
							/* 1 2 840 113549 1 9 16 1 4 */
#define OID_SCVP_CERTVALREQUEST MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x0A" )
							/* 1 2 840 113549 1 9 16 1 10 */
#define OID_SCVP_CERTVALRESPONSE MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x0B" )
							/* 1 2 840 113549 1 9 16 1 11 */
#define OID_SCVP_VALPOLREQUEST MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x0C" )
							/* 1 2 840 113549 1 9 16 1 12 */
#define OID_SCVP_VALPOLRESPONSE MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x0D" )
							/* 1 2 840 113549 1 9 16 1 13 */
#define OID_CRYPTLIB_RTCSREQ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x04" )
							/* 1 3 6 1 4 1 3029 4 1 4 */
#define OID_CRYPTLIB_RTCSRESP MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x05" )
							/* 1 3 6 1 4 1 3029 4 1 5 */
#define OID_CRYPTLIB_RTCSRESP_EXT MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x06" )
							/* 1 3 6 1 4 1 3029 4 1 6 */
#define OID_OCSP_RESPONSE_OCSP MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01" )
							/* 1 3 6 1 5 5 7 48 1 1 */

/* Misc content-type OIDs */

#define OID_PKCS15_CONTENTTYPE MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0F\x03\x01" )
							/* 1 2 840 113549 1 15 3 1 */
#define OID_MS_SPCINDIRECTDATACONTEXT MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x04" )
							/* 1 3 6 1 4 1 311 2 1 4 */
#define OID_PKIBOOT			MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x02" )
							/* 1 3 6 1 4 1 3029 3 1 2 */
#define OID_CRYPTLIB_CONTENTTYPE MKOID( "\x06\x09\x2B\x06\x01\x04\x01\x97\x55\x04\x01" )
							/* 1 3 6 1 4 1 3029 4 1 */
#define OID_CRYPTLIB_CONFIGDATA MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x01" )
							/* 1 3 6 1 4 1 3029 4 1 1 */
#define OID_CRYPTLIB_USERINDEX MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x02" )
							/* 1 3 6 1 4 1 3029 4 1 2 */
#define OID_CRYPTLIB_USERINFO MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x03" )
							/* 1 3 6 1 4 1 3029 4 1 3 */
#define OID_NS_CERTSEQ		MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x02\x05" )
							/* 2 16 840 1 113730 2 5 */

/* PKCS #12 OIDs */

#define OID_PKCS12_PBEWITHSHAAND3KEYTRIPLEDESCBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x03" )
							/* 1 2 840 113549 1 12 1 3 */
#define OID_PKCS12_PBEWITHSHAAND2KEYTRIPLEDESCBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x04" )
							/* 1 2 840 113549 1 12 1 4 */
#define OID_PKCS12_PBEWITHSHAAND40BITRC2CBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x06" )
							/* 1 2 840 113549 1 12 1 6 */
#define OID_PKCS12_SHROUDEDKEYBAG MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x02" )
							/* 1 2 840 113549 1 12 10 1 2 */
#define OID_PKCS12_CERTBAG MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x03" )
							/* 1 2 840 113549 1 12 10 1 3 */

/* Policy OIDs */

#define OID_RPKI_POLICY		MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x0E\x02" )
							/* 1 3 6 1 5 5 7 14 2 */
#define OID_SCVP_DEFAULTCHECKPOLICY MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x11\x03" )
							/* 1 3 6 1 5 5 7 17 3 */
#define OID_SCVP_DEFAULTWANTBACK MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x01" )
							/* 1 3 6 1 5 5 7 18 1 */
#define OID_SCVP_DEFAULTVALPOLICY MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x13\x01" )
							/* 1 3 6 1 5 5 7 19 1 */
#define OID_TSP_POLICY		MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x97\x55\x36\xDD\x24\x36" )
							/* 1 3 6 1 4 1 3029 x36 xDD x24 x36 */
#define OID_CRYPTLIB_XYZZYCERT	MKOID( "\x06\x0C\x2B\x06\x01\x04\x01\x97\x55\x58\x59\x5A\x5A\x59" )
							/* 1 3 6 1 4 1 3029 x58 x59 x5A x5A x59 */
#define OID_ANYPOLICY		MKOID( "\x06\x04\x55\x1D\x20\x00" )
							/* 2 5 29 32 0 */

/* Misc OIDs */

#define OID_PBKDF2			MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C" )
							/* 1 2 840 113549 1 5 12 */
#define OID_PBES2			MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0D" )
							/* 1 2 840 113549 1 5 13 */
#define OID_ZLIB			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x08" )
							/* 1 2 840 113549 1 9 16 3 8 */
#define OID_PWRIKEK			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x09" )
							/* 1 2 840 113549 1 9 16 3 9 */

/****************************************************************************
*																			*
*							ASN.1 Support Functions							*
*																			*
****************************************************************************/

/* Additional specifiers for algorithm classes and encoding formats.  This
   allows us to differentiate between RSA-for-encryption and RSA-for-signing
   and similar cases where the algorithm alone isn't enough */

typedef enum {
	ALGOID_CLASS_NONE,		/* No AlgoID class */
	ALGOID_CLASS_CRYPT,		/* Encryption algorithms */
	ALGOID_CLASS_HASH,		/* Hash/MAC algorithm */
	ALGOID_CLASS_AUTHENC,	/* Authenticated-encryption algorithm */
	ALGOID_CLASS_PKC,		/* Generic PKC algorithm */
	ALGOID_CLASS_PKCSIG,	/* PKC signature algorithm (+ hash algorithm) */
	ALGOID_CLASS_LAST		/* Last possible AlgoID class */
	} ALGOID_CLASS_TYPE;

typedef enum {
	ALGOID_ENCODING_NONE,	/* No encoding type */
	ALGOID_ENCODING_PKCS1,	/* PKCS #1 */
	ALGOID_ENCODING_OAEP,	/* OAEP */
	ALGOID_ENCODING_PSS,	/* PSS */
	ALGOID_ENCODING_LAST	/* Last possible encoding type */
	} ALGOID_ENCODING_TYPE;

typedef struct {
	/* Hash algorithm information, used with signature algorithms, e.g. 
	   sha1withRSAEncryption, hash/MAC algorithms, e.g. HMAC-SHA2/512,
	   and exotic padding schemes like OAEP and PSS */
	CRYPT_ALGO_TYPE hashAlgo;
	int hashParam;

	/* Encryption algorithm information, used with conventional encryption
	   algorithms */
	CRYPT_MODE_TYPE cryptMode;
	int cryptKeySize;

	/* Nonstandard encoding schemes like OAEP and PSS in place of standard
	   PKCS #1 */
	ALGOID_ENCODING_TYPE encodingType;

	/* Encoding-specific details, extra data length.  This is required 
	   because sometimes the algoID parameters are too complex to be 
	   represented here and have to be supplied by the caller, e.g. for the 
	   ECC algorithms, in which case we add the extraLength value to the 
	   algoID length, details to be added by the caller */
	int extraLength;
	} ALGOID_PARAMS;

#define initAlgoIDparams( params ) \
		memset( ( params ), 0, sizeof( ALGOID_PARAMS ) )
#define initAlgoIDparamsHash( params, algo, param ) \
		memset( ( params ), 0, sizeof( ALGOID_PARAMS ) ); \
		( params )->hashAlgo = algo; \
		( params )->hashParam = param
#define initAlgoIDparamsCrypt( params, mode, size ) \
		memset( ( params ), 0, sizeof( ALGOID_PARAMS ) ); \
		( params )->cryptMode = mode; \
		( params )->cryptKeySize = size

/* AlgorithmIdentifier routines */

CHECK_RETVAL_BOOL \
BOOLEAN checkAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					 IN_MODE_OPT const CRYPT_MODE_TYPE cryptMode );
CHECK_RETVAL_LENGTH_SHORT \
int sizeofAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo );
CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 2 ) ) \
int sizeofAlgoIDex( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					const ALGOID_PARAMS *algoIDparams );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoID( INOUT_PTR STREAM *stream, 
				 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
				 IN_TAG const int tag );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeAlgoIDex( INOUT_PTR STREAM *stream, 
				   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
				   const ALGOID_PARAMS *algoIDparams,
				   IN_TAG const int tag );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2) ) \
int readAlgoID( INOUT_PTR STREAM *stream, 
				OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
				IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readAlgoIDexTag( INOUT_PTR STREAM *stream, 
					 OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
					 OUT_PTR ALGOID_PARAMS *algoIDparams,
					 IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type,
					 IN_TAG const int tag );

#define readAlgoIDex( stream, cryptAlgo, algoIDparams, type ) \
		readAlgoIDexTag( stream, cryptAlgo, algoIDparams, type, DEFAULT_TAG ) 

/* Alternative versions that read/write various algorithm ID types (algo and
   mode only or full details depending on the presence of algoIDparams) from 
   contexts */

CHECK_RETVAL_LENGTH \
int sizeofContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext );
CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 2 ) ) \
int sizeofContextAlgoIDex( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						   const ALGOID_PARAMS *algoIDparams );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int readContextAlgoID( INOUT_PTR STREAM *stream, 
					   OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
					   OUT_OPT QUERY_INFO *queryInfo, 
					   IN_TAG const int tag,
					   IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeContextAlgoID( INOUT_PTR STREAM *stream, 
						IN_HANDLE const CRYPT_CONTEXT iCryptContext );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeContextAlgoIDex( INOUT_PTR STREAM *stream, 
						  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						  const ALGOID_PARAMS *algoIDparams );
CHECK_RETVAL_LENGTH \
int sizeofCryptContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCryptContextAlgoID( INOUT_PTR STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext );

/* Read/write a non-crypto algorithm identifier, used for things like 
   content types.  This just wraps the given OID up in the 
   AlgorithmIdentifier and writes it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readGenericAlgoID( INOUT_PTR STREAM *stream, 
					   IN_BUFFER( oidLength ) const BYTE *oid, 
					   IN_LENGTH_OID const int oidLength );
RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeGenericAlgoID( INOUT_PTR STREAM *stream, 
						IN_BUFFER( oidLength ) const BYTE *oid, 
						IN_LENGTH_OID const int oidLength );

/* ECC OID support routines */

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL_LENGTH \
int sizeofECCOID( IN_ENUM( CRYPT_ECCCURVE ) \
					const CRYPT_ECCCURVE_TYPE curveType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readECCOID( INOUT_PTR STREAM *stream, 
				OUT_OPT CRYPT_ECCCURVE_TYPE *curveType,
				OUT_INT_Z int *fieldSize );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeECCOID( INOUT_PTR STREAM *stream, 
				 IN_ENUM( CRYPT_ECCCURVE ) \
					const CRYPT_ECCCURVE_TYPE curveType );

#endif /* USE_ECDH || USE_ECDSA */

/* Message digest support routines */

CHECK_RETVAL_LENGTH_SHORT \
int sizeofMessageDigest( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo, 
						 IN_LENGTH_HASH const int hashSize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readMessageDigest( INOUT_PTR STREAM *stream, 
					   OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo,
					   OUT_BUFFER( hashMaxLen, *hashSize ) void *hash, 
					   IN_LENGTH_HASH const int hashMaxLen, 
					   OUT_LENGTH_BOUNDED_Z( hashMaxLen ) int *hashSize );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeMessageDigest( INOUT_PTR STREAM *stream, 
						IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						IN_BUFFER( hashSize ) const void *hash, 
						IN_LENGTH_HASH const int hashSize );

/* Generic secret support routines.  These functions encode and decode the 
   information needed to recreate the encryption and MAC contexts derived
   from the generic secret */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) \
int getGenericSecretParams( IN_HANDLE const CRYPT_CONTEXT iGenericContext,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iMacContext,
							const QUERY_INFO *queryInfo );
CHECK_RETVAL \
int setGenericSecretParams( IN_HANDLE const CRYPT_CONTEXT iGenericSecret,
							IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							IN_HANDLE const CRYPT_CONTEXT iMacContext,
							IN_ALGO const CRYPT_ALGO_TYPE kdfAlgo );

/* Read/write CMS headers.  The readCMSheader() flags are:

	READCMS_FLAG_AUTHENC: The content uses authenticated encryption, which
			has a different set of permitted content-encryption algorithms 
			than standard encryption.

	READCMS_FLAG_DEFINITELENGTH: Try and obtain a definite length from 
			somewhere in the CMS header rather than returning CRYPT_UNUSED
			for the length, return an error if there's no definite length
			available.  Note that this changes processing in the calling
			code because it can no longer use the length to determine 
			whether it should perform EOC checks if there's an indefinite
			length somwwhere in the header.

	READCMS_FLAG_DEFINITELENGTH_OPT: As READCMS_FLAG_DEFINITELENGTH but 
			return a length of CRYPT_UNUSED if there's no definite length
			information available.

	READCMS_FLAG_INNERHEADER: This is an inner header, the content wrapper
			can be an OCTET STRING as well as the more usual SEQUENCE.

	READCMS_FLAG_WRAPPERONLY: Only read the outer SEQUENCE, OID, [0] wrapper
			without reading the final layer of inner encapsulation, used
			when one CMS content type is redundantly nested directly inside 
			another (Microsoft did this for PKCS #12) */

#define READCMS_FLAG_NONE			0x00	/* No CMS read flag */
#define READCMS_FLAG_INNERHEADER	0x01	/* Inner CMS header */
#define READCMS_FLAG_AUTHENC		0x02	/* Content uses auth.enc */
#define READCMS_FLAG_WRAPPERONLY	0x04	/* Only read wrapper */
#define READCMS_FLAG_DEFINITELENGTH	0x08	/* Try and get definite len */
#define READCMS_FLAG_DEFINITELENGTH_OPT 0x10/* Opt.try and get def.len */
#define READCMS_FLAG_MAX			0x1F	/* Maximum possible flag value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCMSheader( INOUT_PTR STREAM *stream, 
				   IN_ARRAY( noOidInfoEntries ) \
						const OID_INFO *oidInfo, 
				   IN_RANGE( 1, 50 ) const int noOidInfoEntries, 
				   OUT_OPT_INT_Z int *selectionID,
				   OUT_OPT_LENGTH_INDEF long *dataSize, 
				   IN_FLAGS_Z( READCMS ) const int flags );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCMSheader( INOUT_PTR STREAM *stream, 
					IN_BUFFER( contentOIDlength ) \
						const BYTE *contentOID, 
					IN_LENGTH_OID const int contentOIDlength,
					IN_LENGTH_INDEF const long dataSize, 
					IN_BOOL const BOOLEAN isInnerHeader );
CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofCMSencrHeader( IN_BUFFER( contentOIDlength ) \
							const BYTE *contentOID, 
						 IN_LENGTH_OID const int contentOIDlength,
						 IN_LENGTH_INDEF const long dataSize, 
						 IN_HANDLE const CRYPT_CONTEXT iCryptContext );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCMSencrHeader( INOUT_PTR STREAM *stream, 
					   IN_ARRAY( noOidInfoEntries ) \
							const OID_INFO *oidInfo,
					   IN_RANGE( 1, 50 ) const int noOidInfoEntries, 
					   OUT_OPT_INT_Z int *selectionID,
					   OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
					   OUT_OPT QUERY_INFO *queryInfo,
					   IN_FLAGS_Z( READCMS ) const int flags );
RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCMSencrHeader( INOUT_PTR STREAM *stream, 
						IN_BUFFER( contentOIDlength ) \
							const BYTE *contentOID, 
						IN_LENGTH_OID const int contentOIDlength,
						IN_LENGTH_INDEF const long dataSize,
						IN_HANDLE const CRYPT_CONTEXT iCryptContext );

#endif /* USE_INT_ASN1 */
#endif /* _ASN1OID_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
