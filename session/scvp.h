<<<<<<< HEAD
/****************************************************************************
*																			*
*							SCVP Definitions Header File					*
*						Copyright Peter Gutmann 2005-2020					*
*																			*
****************************************************************************/

#ifndef _SCVP_DEFINED

#define _SCVP_DEFINED

#ifdef USE_SCVP

/* Various SCVP constants */

#define SCVP_NONCE_SIZE			16

/* SCVP protocol-specific flags that augment the general session flags.  These
   are:

	PFLAG_VALPOLICY: The ValidationPolicy information has been read from the 
		server */

#define SCVP_PFLAG_NONE			0x00	/* No protocol-specific flags */
#define SCVP_PFLAG_VALPOLICY	0x01	/* Got ValidationPolicy from server */
#define SCVP_PFLAG_MAX			0x3F	/* Maximum possible flag value */

/* SCVP wantBack flags */

#define SCVP_WANTBACK_FLAG_NONE	0x000	/* No wantBack */
#define SCVP_WANTBACK_FLAG_BESTCERTPATH \
								0x001	/* Full certificate chain for request */
#define SCVP_WANTBACK_FLAG_REVOCATIONINFO \
								0x002	/* Revocation status for all certificates */
#define SCVP_WANTBACK_FLAG_PUBLICKEYINFO \
								0x004	/* SPKI for the certificate */
#define SCVP_WANTBACK_FLAG_RELAYEDRESPONSES \
								0x008	/* SCVP input that created this output */
#define SCVP_WANTBACK_FLAG_CERT	0x010	/* The certificate in the request */
#define SCVP_WANTBACK_FLAG_ALLCERTPATHS \
								0x020	/* Multiple chains for request */
#define SCVP_WANTBACK_FLAG_EEREVOCATIONINFO \
								0x040	/* Revocation status for the EE certificate */
#define SCVP_WANTBACK_FLAG_CAREVOCATIONINFO \
								0x080	/* Revocation status for the CA certificates */
#define SCVP_WANTBACK_FLAG_MAX	0x0FF	/* Maximum possible wantBack value */

/* SCVP HTTP content types */

#define SCVP_CONTENTTYPE_REQUEST		"application/scvp-cv-request"
#define SCVP_CONTENTTYPE_REQUEST_LEN	27
#define SCVP_CONTENTTYPE_RESPONSE		"application/scvp-cv-response"
#define SCVP_CONTENTTYPE_RESPONSE_LEN	28
#define SCVP_CONTENTTYPE_VPREQUEST		"application/scvp-cp-request"
#define SCVP_CONTENTTYPE_VPREQUEST_LEN	27
#define SCVP_CONTENTTYPE_VPRESPONSE		"application/scvp-cp-response"
#define SCVP_CONTENTTYPE_VPRESPONSE_LEN	28

/* Context-specific tags for the SCVP request, response, and query */

enum { CTAG_RQ_REQUESTORREF, CTAG_RQ_REQUESTNONCE, CTAG_RQ_REQUESTORNAME, 
	   CTAG_RQ_RESPONDERNAME, CTAG_RQ_REQUESTEXTENSIONS, 
	   CTAG_RQ_SIGNATUREALG, CTAG_RQ_HASHALG, CTAG_RQ_REQUESTORTEXT };

enum { CTAG_RR_REQUESTHASH, CTAG_RR_FULLREQUEST };

enum { CTAG_RP_RESPVALIDATIONPOLICY, CTAG_RP_REQUESTREF, 
	   CTAG_RP_REQUESTORREF, CTAG_RP_REQUESTORNAME, CTAG_RP_REPLYOBJECTS,
	   CTAG_RP_RESPNONCE, CTAG_RP_SERVERCONTEXTINFO, 
	   CTAG_RP_CVRESPONSEEXTENSIONS, CTAG_RP_REQUESTORTEXT };

enum { CTAG_QR_UNUSED, CTAG_QR_WANTBACK };

/* SCVP response status codes */

enum { SCVP_STATUS_OKAY, SCVP_STATUS_SKIPUNRECOGNIZEDITEMS, 
	   SCVP_STATUS_TOOBUSY = 10, SCVP_STATUS_INVALIDREQUEST, 
	   SCVP_STATUS_INTERNALERROR, SCVP_STATUS_BADSTRUCTURE = 20, 
	   SCVP_STATUS_UNSUPPORTEDVERSION, SCVP_STATUS_ABORTUNRECOGNIZEDITEMS,
	   SCVP_STATUS_UNRECOGNIZEDSIGKEY, SCVP_STATUS_BADSIGNATUREORMAC,
	   SCVP_STATUS_UNABLETODECODE, SCVP_STATUS_NOTAUTHORIZED, 
	   SCVP_STATUS_UNSUPPORTEDCHECKS, SCVP_STATUS_UNSUPPORTEDWANTBACKS,
	   SCVP_STATUS_UNSUPPORTEDSIGNATUREORMAC, 
	   SCVP_STATUS_INVALIDSIGNATUREORMAC, 
	   SCVP_STATUS_PROTECTEDRESPONSEUNSUPPORTED, 
	   SCVP_STATUS_UNRECOGNIZEDRESPONDERNAME, SCVP_STATUS_RELAYINGLOOP = 40,
	   SCVP_STATUS_UNRECOGNIZEDVALPOL = 50, SCVP_STATUS_UNRECOGNIZEDVALALG,
	   SCVP_STATUS_FULLREQUESTINRESPONSEUNSUPPORTED, 
	   SCVP_STATUS_FULLPOLRESPONSEUNSUPPORTED, 
	   SCVP_STATUS_INHIBITPOLICYMAPPINGUNSUPPORTED, 
	   SCVP_STATUS_REQUIREEXPLICITPOLICYUNSUPPORTED, 
	   SCVP_STATUS_INHIBITANYPOLICYUNSUPPORTED, 
	   SCVP_STATUS_VALIDATIONTIMEUNSUPPORTED, 
	   SCVP_STATUS_UNRECOGNIZEDCRITQUERYEXT = 63, 
	   SCVP_STATUS_UNRECOGNIZEDCRITREQUESTEXT };

/* SCVP reply status codes */

typedef enum { 
	SCVP_REPLYSTATUS_SUCCESS, 
		SCVP_REPLYSTATUS_NONE = SCVP_REPLYSTATUS_SUCCESS /* _SUCCESS = 0 = _NONE */,
	SCVP_REPLYSTATUS_MALFORMEDPKC, 
	SCVP_REPLYSTATUS_MALFORMEDAC, 
	SCVP_REPLYSTATUS_UNAVAILABLEVALIDATIONTIME, 
	SCVP_REPLYSTATUS_REFERENCECERTHASHFAIL, 
	SCVP_REPLYSTATUS_CERTPATHCONSTRUCTFAIL, 
	SCVP_REPLYSTATUS_CERTPATHNOTVALID, 
	SCVP_REPLYSTATUS_CERTPATHNOTVALIDNOW, 
	SCVP_REPLYSTATUS_WANTBACKUNSATISFIED,
	SCVP_REPLYSTATUS_LAST
	} SCVP_REPLYSTATUS_TYPE;

/* SCVP protocol state information.  This is passed around various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	/* SCVP status information determined by the server, the reply status 
	   and any wantback items that may have been requested */
	SCVP_REPLYSTATUS_TYPE scvpReplyStatus;
	CRYPT_CERTIFICATE iWantbackCertPath;

	/* Identification/state variable information.  In order to accommodate 
	   nonstandard implementations, we allow for nonces that are slightly 
	   larger than the required size */
	BUFFER( CRYPT_MAX_HASHSIZE, nonceSize ) \
	BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];
	int nonceSize;

	/* The checks and wantBack information that the server has to return to 
	   the client */
	BUFFER( MAX_OID_SIZE, checksSize ) \
	BYTE checks[ MAX_OID_SIZE + 8 ];
	int checksSize;
	int wantBacks;

	/* The sizes of various wantBack entries */
	int wbCertSize, wbBestCertPathSize, wbTotalSize;

	/* The request hash, used to detect manipulation of the plaintext 
	   request */
	BUFFER( CRYPT_MAX_HASHSIZE, requestHashSize ) \
	BYTE requestHash[ CRYPT_MAX_HASHSIZE + 8 ];
	int requestHashSize;
	CRYPT_ALGO_TYPE requestHashAlgo;
	} SCVP_PROTOCOL_INFO;

/* Prototypes for functions in scvp.c */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionSCVP( IN_PTR const SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSCVPProtocolInfo( IN_PTR \
										const SCVP_PROTOCOL_INFO *protocolInfo );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initSCVPprotocolInfo( OUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
						  IN_PTR const SESSION_INFO *sessionInfoPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void destroySCVPprotocolInfo( INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int calculateRequestHash( INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
						  IN_BUFFER( requestDataLength ) \
								const void *requestData,
						  IN_LENGTH const int requestDataLength );
CHECK_RETVAL_LENGTH \
int sizeofValidationPolicy( void );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readValidationPolicy( INOUT_PTR STREAM *stream,
						  INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeValidationPolicy( INOUT_PTR STREAM *stream );
CHECK_RETVAL_LENGTH \
int sizeofCertRef( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert );
CHECK_RETVAL_LENGTH \
int sizeofCertRefs( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readCertRef( INOUT_PTR STREAM *stream, 
				 OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCryptCert,
				 INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readCertRefs( INOUT_PTR STREAM *stream, 
				  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCryptCert,
				  INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCertRef( INOUT_PTR STREAM *stream,
				  IN_HANDLE const CRYPT_CERTIFICATE iCryptCert );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCertRefs( INOUT_PTR STREAM *stream,
				   IN_HANDLE const CRYPT_CERTIFICATE iCryptCert );

/* Prototypes for functions in scvp_cli/scvp_svr.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void initSCVPclientProcessing( SESSION_INFO *sessionInfoPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void initSCVPserverProcessing( SESSION_INFO *sessionInfoPtr );

#endif /* USE_SCVP */

#endif /* _SCVP_DEFINED */
=======
/****************************************************************************
*																			*
*							SCVP Definitions Header File					*
*						Copyright Peter Gutmann 2005-2020					*
*																			*
****************************************************************************/

#ifndef _SCVP_DEFINED

#define _SCVP_DEFINED

#ifdef USE_SCVP

/* Various SCVP constants */

#define SCVP_NONCE_SIZE			16

/* SCVP protocol-specific flags that augment the general session flags.  These
   are:

	PFLAG_VALPOLICY: The ValidationPolicy information has been read from the 
		server */

#define SCVP_PFLAG_NONE			0x00	/* No protocol-specific flags */
#define SCVP_PFLAG_VALPOLICY	0x01	/* Got ValidationPolicy from server */
#define SCVP_PFLAG_MAX			0x3F	/* Maximum possible flag value */

/* SCVP wantBack flags */

#define SCVP_WANTBACK_FLAG_NONE	0x000	/* No wantBack */
#define SCVP_WANTBACK_FLAG_BESTCERTPATH \
								0x001	/* Full certificate chain for request */
#define SCVP_WANTBACK_FLAG_REVOCATIONINFO \
								0x002	/* Revocation status for all certificates */
#define SCVP_WANTBACK_FLAG_PUBLICKEYINFO \
								0x004	/* SPKI for the certificate */
#define SCVP_WANTBACK_FLAG_RELAYEDRESPONSES \
								0x008	/* SCVP input that created this output */
#define SCVP_WANTBACK_FLAG_CERT	0x010	/* The certificate in the request */
#define SCVP_WANTBACK_FLAG_ALLCERTPATHS \
								0x020	/* Multiple chains for request */
#define SCVP_WANTBACK_FLAG_EEREVOCATIONINFO \
								0x040	/* Revocation status for the EE certificate */
#define SCVP_WANTBACK_FLAG_CAREVOCATIONINFO \
								0x080	/* Revocation status for the CA certificates */
#define SCVP_WANTBACK_FLAG_MAX	0x0FF	/* Maximum possible wantBack value */

/* SCVP HTTP content types */

#define SCVP_CONTENTTYPE_REQUEST		"application/scvp-cv-request"
#define SCVP_CONTENTTYPE_REQUEST_LEN	27
#define SCVP_CONTENTTYPE_RESPONSE		"application/scvp-cv-response"
#define SCVP_CONTENTTYPE_RESPONSE_LEN	28
#define SCVP_CONTENTTYPE_VPREQUEST		"application/scvp-cp-request"
#define SCVP_CONTENTTYPE_VPREQUEST_LEN	27
#define SCVP_CONTENTTYPE_VPRESPONSE		"application/scvp-cp-response"
#define SCVP_CONTENTTYPE_VPRESPONSE_LEN	28

/* Context-specific tags for the SCVP request, response, and query */

enum { CTAG_RQ_REQUESTORREF, CTAG_RQ_REQUESTNONCE, CTAG_RQ_REQUESTORNAME, 
	   CTAG_RQ_RESPONDERNAME, CTAG_RQ_REQUESTEXTENSIONS, 
	   CTAG_RQ_SIGNATUREALG, CTAG_RQ_HASHALG, CTAG_RQ_REQUESTORTEXT };

enum { CTAG_RR_REQUESTHASH, CTAG_RR_FULLREQUEST };

enum { CTAG_RP_RESPVALIDATIONPOLICY, CTAG_RP_REQUESTREF, 
	   CTAG_RP_REQUESTORREF, CTAG_RP_REQUESTORNAME, CTAG_RP_REPLYOBJECTS,
	   CTAG_RP_RESPNONCE, CTAG_RP_SERVERCONTEXTINFO, 
	   CTAG_RP_CVRESPONSEEXTENSIONS, CTAG_RP_REQUESTORTEXT };

enum { CTAG_QR_UNUSED, CTAG_QR_WANTBACK };

/* SCVP response status codes */

enum { SCVP_STATUS_OKAY, SCVP_STATUS_SKIPUNRECOGNIZEDITEMS, 
	   SCVP_STATUS_TOOBUSY = 10, SCVP_STATUS_INVALIDREQUEST, 
	   SCVP_STATUS_INTERNALERROR, SCVP_STATUS_BADSTRUCTURE = 20, 
	   SCVP_STATUS_UNSUPPORTEDVERSION, SCVP_STATUS_ABORTUNRECOGNIZEDITEMS,
	   SCVP_STATUS_UNRECOGNIZEDSIGKEY, SCVP_STATUS_BADSIGNATUREORMAC,
	   SCVP_STATUS_UNABLETODECODE, SCVP_STATUS_NOTAUTHORIZED, 
	   SCVP_STATUS_UNSUPPORTEDCHECKS, SCVP_STATUS_UNSUPPORTEDWANTBACKS,
	   SCVP_STATUS_UNSUPPORTEDSIGNATUREORMAC, 
	   SCVP_STATUS_INVALIDSIGNATUREORMAC, 
	   SCVP_STATUS_PROTECTEDRESPONSEUNSUPPORTED, 
	   SCVP_STATUS_UNRECOGNIZEDRESPONDERNAME, SCVP_STATUS_RELAYINGLOOP = 40,
	   SCVP_STATUS_UNRECOGNIZEDVALPOL = 50, SCVP_STATUS_UNRECOGNIZEDVALALG,
	   SCVP_STATUS_FULLREQUESTINRESPONSEUNSUPPORTED, 
	   SCVP_STATUS_FULLPOLRESPONSEUNSUPPORTED, 
	   SCVP_STATUS_INHIBITPOLICYMAPPINGUNSUPPORTED, 
	   SCVP_STATUS_REQUIREEXPLICITPOLICYUNSUPPORTED, 
	   SCVP_STATUS_INHIBITANYPOLICYUNSUPPORTED, 
	   SCVP_STATUS_VALIDATIONTIMEUNSUPPORTED, 
	   SCVP_STATUS_UNRECOGNIZEDCRITQUERYEXT = 63, 
	   SCVP_STATUS_UNRECOGNIZEDCRITREQUESTEXT };

/* SCVP reply status codes */

typedef enum { 
	SCVP_REPLYSTATUS_SUCCESS, 
		SCVP_REPLYSTATUS_NONE = SCVP_REPLYSTATUS_SUCCESS /* _SUCCESS = 0 = _NONE */,
	SCVP_REPLYSTATUS_MALFORMEDPKC, 
	SCVP_REPLYSTATUS_MALFORMEDAC, 
	SCVP_REPLYSTATUS_UNAVAILABLEVALIDATIONTIME, 
	SCVP_REPLYSTATUS_REFERENCECERTHASHFAIL, 
	SCVP_REPLYSTATUS_CERTPATHCONSTRUCTFAIL, 
	SCVP_REPLYSTATUS_CERTPATHNOTVALID, 
	SCVP_REPLYSTATUS_CERTPATHNOTVALIDNOW, 
	SCVP_REPLYSTATUS_WANTBACKUNSATISFIED,
	SCVP_REPLYSTATUS_LAST
	} SCVP_REPLYSTATUS_TYPE;

/* SCVP protocol state information.  This is passed around various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	/* SCVP status information determined by the server, the reply status 
	   and any wantback items that may have been requested */
	SCVP_REPLYSTATUS_TYPE scvpReplyStatus;
	CRYPT_CERTIFICATE iWantbackCertPath;

	/* Identification/state variable information.  In order to accommodate 
	   nonstandard implementations, we allow for nonces that are slightly 
	   larger than the required size */
	BUFFER( CRYPT_MAX_HASHSIZE, nonceSize ) \
	BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];
	int nonceSize;

	/* The checks and wantBack information that the server has to return to 
	   the client */
	BUFFER( MAX_OID_SIZE, checksSize ) \
	BYTE checks[ MAX_OID_SIZE + 8 ];
	int checksSize;
	int wantBacks;

	/* The sizes of various wantBack entries */
	int wbCertSize, wbBestCertPathSize, wbTotalSize;

	/* The request hash, used to detect manipulation of the plaintext 
	   request */
	BUFFER( CRYPT_MAX_HASHSIZE, requestHashSize ) \
	BYTE requestHash[ CRYPT_MAX_HASHSIZE + 8 ];
	int requestHashSize;
	CRYPT_ALGO_TYPE requestHashAlgo;
	} SCVP_PROTOCOL_INFO;

/* Prototypes for functions in scvp.c */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionSCVP( IN_PTR const SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSCVPProtocolInfo( IN_PTR \
										const SCVP_PROTOCOL_INFO *protocolInfo );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initSCVPprotocolInfo( OUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
						  IN_PTR const SESSION_INFO *sessionInfoPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void destroySCVPprotocolInfo( INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int calculateRequestHash( INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
						  IN_BUFFER( requestDataLength ) \
								const void *requestData,
						  IN_LENGTH const int requestDataLength );
CHECK_RETVAL_LENGTH \
int sizeofValidationPolicy( void );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readValidationPolicy( INOUT_PTR STREAM *stream,
						  INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeValidationPolicy( INOUT_PTR STREAM *stream );
CHECK_RETVAL_LENGTH \
int sizeofCertRef( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert );
CHECK_RETVAL_LENGTH \
int sizeofCertRefs( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readCertRef( INOUT_PTR STREAM *stream, 
				 OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCryptCert,
				 INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readCertRefs( INOUT_PTR STREAM *stream, 
				  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCryptCert,
				  INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCertRef( INOUT_PTR STREAM *stream,
				  IN_HANDLE const CRYPT_CERTIFICATE iCryptCert );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCertRefs( INOUT_PTR STREAM *stream,
				   IN_HANDLE const CRYPT_CERTIFICATE iCryptCert );

/* Prototypes for functions in scvp_cli/scvp_svr.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void initSCVPclientProcessing( SESSION_INFO *sessionInfoPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void initSCVPserverProcessing( SESSION_INFO *sessionInfoPtr );

#endif /* USE_SCVP */

#endif /* _SCVP_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
