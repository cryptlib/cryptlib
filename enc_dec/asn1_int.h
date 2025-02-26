/****************************************************************************
*																			*
*							Internal ASN.1 Header File						*
*						Copyright Peter Gutmann 1992-2018					*
*																			*
****************************************************************************/

#ifndef _ASN1INT_DEFINED

#define _ASN1INT_DEFINED

/* We need an additional guard for USE_INT_ASN1 since this header uses types
   that aren't defined if USE_INT_ASN1 isn't defined */

#ifdef USE_INT_ASN1

/* A table mapping OIDs to algorithm types, used in asn1_oid.c.  The 
   debugText field isn't ever displayed or accessed, it's present purely to
   provide a human-readable tag visible in a debugger that identifies which
   of the many ALGOID_INFO entries this is */

typedef struct {
	const CRYPT_ALGO_TYPE algorithm;	/* The basic algorithm */
	const int subAlgo;					/* Algorithm subtype or mode */
	const int parameter;				/* Encoding format or key/hash size */
	const ALGOID_CLASS_TYPE algoClass;	/* Algorithm class */
	const BYTE *oid;					/* The OID for this algorithm */
#ifndef NDEBUG
	const char *debugText;				/* Debug text for this OID */
#endif /* !NDEBUG */
	} ALGOID_INFO;

#ifndef NDEBUG
  #define MKDESC( debugText )		, debugText
#else
  #define MKDESC( debugText )
#endif /* !NDEBUG */

/* Prototypes for functions in asn1_algenc.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCryptAlgoParams( INOUT_PTR STREAM *stream, 
						 INOUT_PTR QUERY_INFO *queryInfo,
						 IN_LENGTH_Z const int startOffset );

/* Prototypes for functions in asn1_ext.c */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 2 ) ) \
BOOLEAN sanityCheckAlgoIDparams( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								 const ALGOID_PARAMS *algoIDparams );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Prototypes for functions in asn1_oid.c */

#define ALGOTOOID_REQUIRE_VALID		TRUE
#define ALGOTOOID_CHECK_VALID		FALSE

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int oidToAlgorithm( IN_BUFFER( oidLength ) const BYTE *oid, 
					IN_LENGTH_OID const int oidLength,
					OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
					OUT_PTR ALGOID_PARAMS *algoIDparams,
					IN_ENUM( ALGOID_CLASS ) const ALGOID_CLASS_TYPE type );
CHECK_RETVAL_PTR \
const BYTE *algorithmToOID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							IN_PTR_OPT const ALGOID_PARAMS *algoIDparams,
							IN_BOOL const BOOLEAN checkValid );
#endif /* USE_INT_ASN1 */

#endif /* _ASN1INT_DEFINED */
