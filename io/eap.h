/****************************************************************************
*																			*
*								cryptlib EAP Header							*
*						Copyright Peter Gutmann 2016-2017					*
*																			*
****************************************************************************/

#ifndef _EAP_DEFINED

#define _EAP_DEFINED

#if defined( INC_ALL )
  #include "stream_int.h"
#else
  #include "io/stream_int.h"
#endif /* Compiler-specific includes */

/* Define the following to send the ID at the outer layer as "anonymous"
   with the actual ID protected inside the tunnel.  This is suggested in
   RFC 2865 but may not be handled by all servers.  In particular it needs
   to be synced at the RADIUS and EAP level, so this affects both
   eap_wr.c:writeRADIUSMessage() and eap.c:activateEAPClient() */

#define USE_ANONYMOUS_ID /**/

/* Define the following to dump packet contents for RADIUS packets, RADIUS
   TLVs, or EAP packets inside RADIUS TLVs.  For example for PEAP, 
   DEBUG_TRACE_RADIUS will dump RADIUS( EAP( PEAP ) ), DEBUG_TRACE_RADIUSTLV 
   will dump EAP( PEAP ), and DEBUG_TRACE_RADIUSEAP will dump PEAP */

#define DEBUG_TRACE_RADIUS 
#define DEBUG_TRACE_RADIUSTLV 
/* #define DEBUG_TRACE_RADIUSEAP */

/****************************************************************************
*																			*
*								EAP Packet Types							*
*																			*
****************************************************************************/

/* EAP packet types, from
   https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml */

typedef enum {
	EAP_TYPE_NONE,

	/* RFC 3748 (1-4) */
	EAP_TYPE_REQUEST, EAP_TYPE_RESPONSE, EAP_TYPE_SUCCESS, EAP_TYPE_FAILURE,

	/* RFC 6696 (5-6) */
	EAP_TYPE_INITIATE, EAP_TYPE_FINISH,

	/* The EAP type value is a single byte, so values up to 255 are valid 
	   (EAP_TYPE_LAST is one larger than the highest possible value) */
	EAP_TYPE_LAST = 256
	} EAP_TYPE;

/* EAP packet subtypes, from
   https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml */

typedef enum {
	EAP_SUBTYPE_NONE,
	
	/* RFC 3748 (1-8) */
	EAP_SUBTYPE_IDENTITY, EAP_SUBTYPE_NOTIFICATION, EAP_SUBTYPE_NAK,
	EAP_SUBTYPE_MD5_CHALLENGE, EAP_SUBTYPE_OTP, EAP_SUBTYPE_GTC,
	EAP_SUBTYPE_reserved_1, EAP_SUBTYPE_reserved_2,

	/* Miscellaneous obsolete PKC types (9-12) */
	EAP_SUBTYPE_RSA, EAP_SUBTYPE_DSS, EAP_SUBTYPE_KEA, 
	EAP_SUBTYPE_KEA_VALIDATE,

	/* EAP-TLS, RFC 5216 (13) */
	EAP_SUBTYPE_EAP_TLS,

	/* Vendor-specific subtypes (14-17) */
	EAP_SUBTYPE_AXENT, EAP_SUBTYPE_SECURID, EAP_SUBTYPE_ARCOT, 
	EAP_SUBTYPE_CISCO,

	/* EAP-SIM, RFC 4186 (18) */
	EAP_SUBTYPE_EAP_SIM,

	/* More miscellaneous types (19-20) */
	EAP_SUBTYPE_SRP_SHA1, EAP_SUBTYPE_reserved_3,

	/* EAP-TTLS, RFC 4281 (21) */
	EAP_SUBTYPE_EAP_TTLS,

	/* More vendor-specific subtypes (22-31) */
	EAP_SUBTYPE_REMOTEACCESS, EAP_SUBTYPE_EAP_AKA, EAP_SUBTYPE_3COM, 
	EAP_SUBTYPE_PEAP, EAP_SUBTYPE_MS_EAP, EAP_SUBTYPE_MAKE, 
	EAP_SUBTYPE_CRYPTOCARD, EAP_SUBTYPE_EAP_MSCHAPV2, EAP_SUBTYPE_DYNAMID,
	EAP_SUBTYPE_ROBEAP,

	/* POTP, RFC 4793 (32) */
	EAP_SUBTYPE_POTP,

	/* More vendor-specific subtypes (33-42) */
	EAP_SUBTYPE_MS_TLV, EAP_SUBTYPE_SENTRINET, EAP_SUBTYPE_ACTIONTEC,
	EAP_SUBTYPE_COGENT, EAP_SUBTYPE_AIRFORTRESS, EAP_SUBTYPE_HTTPDIGEST,
	EAP_SUBTYPE_SECURESUITE, EAP_SUBTYPE_DEVICECONNECT, EAP_SUBTYPE_SPEKE,
	EAP_SUBTYPE_MOBAC,

	/* EAP-FAST, RFC 4851 (43) */
	EAP_SUBTYPE_EAP_FAST,

	/* More vendor-specific subtypes (44-46) */
	EAP_SUBTYPE_EAP_ZONELABS, EAP_SUBTYPE_EAP_LINK, EAP_SUBTYPE_EAP_PAX,

	/* More standardised EAP subtypes (47-55) */
	EAP_SUBTYPE_EAP_PSK, EAP_SUBTYPE_EAP_SAKE, EAP_SUBTYPE_EAP_IKEV2, 
	EAP_SUBTYPE_EAP_AKAPLUS, EAP_SUBTYPE_EAP_GPSK, EAP_SUBTYPE_EAP_PWD,
	EAP_SUBTYPE_EAP_EKE, EAP_SUBTYPE_PT_EAP, EAP_SUBTYPE_TEAP,

	/* The EAP subtype value is a single byte, so values up to 255 are valid 
	   (EAP_SUBTYPE_LAST is one larger than the highest possible value) */
	EAP_SUBTYPE_LAST = 256
	} EAP_SUBTYPE_TYPE;

/* EAP-TLS/TTLS/PEAP flags.  Note that these are values sent as part of an EAP
   packet encapsulated inside a RADIUS packet and not related to the EAP_INFO
   eapFlags field */

#define EAPTLS_FLAG_NONE		0x00	/* No EAP-TLS flag */
#define EAPTLS_FLAG_VERSION		0x00	/* Version, always 0 */
#define EAPTLS_FLAG_START		0x20	/* Start of EAP-TLS/TTLS exchange */
#define EAPTLS_FLAG_MOREFRAGS	0x40	/* More fragments follow */
#define EAPTLS_FLAG_HASLENGTH	0x80	/* Length field follows */
#define EAPTLS_FLAG_MAX			0xF0	/* Maximum possible flag value */

/****************************************************************************
*																			*
*								RADIUS Packet Types							*
*																			*
****************************************************************************/

/* RADIUS packet types, from
   https://www.iana.org/assignments/radius-types/radius-types.xhtml */

typedef enum {
	RADIUS_TYPE_NONE,
	
	/* RFC 2865 (1-5) */
	RADIUS_TYPE_REQUEST, RADIUS_TYPE_ACCEPT, RADIUS_TYPE_REJECT, 
	RADIUS_TYPE_ACC_REQ, RADIUS_TYPE_ACC_RESP,

	/* RFC 3575 (6-10) */
	RADIUS_TYPE_ACC_STATUS, RADIUS_TYPE_PW_REQ, RADIUS_TYPE_PW_ACK, 
	RADIUS_TYPE_PW_REJ, RADIUS_TYPE_ACC_MSG,

	/* RFC 2865 (11-13) */
	RADIUS_TYPE_CHALLENGE, RADIUS_TYPE_STATUSSVR, RADIUS_TYPE_STATUSCLI,

	/* RFC 3575 again (21- */
	RADIUS_TYPE_FREE_REQ = 21, RADIUS_TYPE_FREE_RESP, RADIUS_TYPE_QRY_REQ,
	RADIUS_TYPE_QRY_RESP, RADIUS_TYPE_RECLAIM, RADIUS_TYPE_REBOOT_REQ,
	RADIUS_TYPE_REBOOT_RESP, RADIUS_TYPE_RESERVED, RADIUS_TYPE_NEXTPASS,
	RADIUS_TYPE_NEWPIN, RADIUS_TYPE_TERMINATE, RADIUS_TYPE_EXPIRED,
	RADIUS_TYPE_EVT_REQ, RADIUS_TYPE_EVT_RESP, RADIUS_TYPE_DISCONN_REQ = 40,
	RADIUS_TYPE_DISCONN_ACK, RADIUS_TYPE_DISCONN_NAK, RADIUS_TYPE_COA_REQ,
	RADIUS_TYPE_COA_ACK, RADIUS_TYPE_COA_NAK, RADIUS_TYPE_ADDR_ALLOC = 50,
	RADIUS_TYPE_ADD_RELEASE, RADIUS_TYPE_ERROR,

	/* The RADIUS type value is a single byte, so values up to 255 are valid 
	   (EAP_SUBTYPE_LAST is one larger than the highest possible value) */
	RADIUS_TYPE_LAST = 256
	} RADIUS_TYPE;

/* RADIUS packet subtypes, from
   https://www.iana.org/assignments/radius-types/radius-types.xhtml */

typedef enum {
	RADIUS_SUBTYPE_NONE,

	/* RFC 2865 (1-39) */
	RADIUS_SUBTYPE_USERNAME, RADIUS_SUBTYPE_PASSWORD, RADIUS_SUBTYPE_CHAP,
	RADIUS_SUBTYPE_IPADDRESS, RADIUS_SUBTYPE_PORT, 
	RADIUS_SUBTYPE_SERVICETYPE, RADIUS_SUBTYPE_FRAMED_PROTOCOL,
	RADIUS_SUBTYPE_FRAMED_IPADDRESS, RADIUS_SUBTYPE_FRAMED_NETMASK,
	RADIUS_SUBTYPE_FRAMED_ROUTING, RADIUS_SUBTYPE_FILTERID,
	RADIUS_SUBTYPE_FRAMED_MTU, RADIUS_SUBTYPE_FRAMED_COMPRESSION,
	RADIUS_SUBTYPE_LOGIN_IPADDRESS, RADIUS_SUBTYPE_LOGIN_SERVICE, 
	RADIUS_SUBTYPE_LOGIN_PORT, RADIUS_SUBTYPE_reserved_1,
	RADIUS_SUBTYPE_REPLYMESSAGE, RADIUS_SUBTYPE_CALLBACK_NUMBER,
	RADIUS_SUBTYPE_CALLBACK_ID, RADIUS_SUBTYPE_reserved_2, 
	RADIUS_SUBTYPE_FRAMED_ROUTE, RADIUS_SUBTYPE_FRAMED_IPX,
	RADIUS_SUBTYPE_STATE, RADIUS_SUBTYPE_CLASS, 
	RADIUS_SUBTYPE_VENDORSPECIFIC, RADIUS_SUBTYPE_SESSIONTIMEOUT,
	RADIUS_SUBTYPE_IDLETIMEOUT, RADIUS_SUBTYPE_TERMINATION,
	RADIUS_SUBTYPE_CALLED_STATIONID, RADIUS_SUBTYPE_CALLING_STATIONID,
	RADIUS_SUBTYPE_NAS_IDENTIFIER, RADIUS_SUBTYPE_PROXYSTATE,
	RADIUS_SUBTYPE_LOGIN_LATSERVICE, RADIUS_SUBTYPE_LOGIN_LATNODE, 
	RADIUS_SUBTYPE_LOGIN_LATGROUP, RADIUS_SUBTYPE_FRAMED_APPLETALKLINK,
	RADIUS_SUBTYPE_FRAMED_APPLETALKNETWORK, 
	RADIUS_SUBTYPE_FRAMED_APPLETALK_ZONE,

	/* RFC 2866 (40-51) */
	RADIUS_SUBTYPE_ACCT_STATUS, RADIUS_SUBTYPE_ACCT_DELAYTIME,
	RADIUS_SUBTYPE_ACCT_INPUT, RADIUS_SUBTYPE_ACCT_OUTPUT, 
	RADIUS_SUBTYPE_ACCT_ID, RADIUS_SUBTYPE_ACCT_AUTHENTIC,
	RADIUS_SUBTYPE_ACCT_TIME, RADIUS_SUBTYPE_ACCT_INPUTPACKETS,
	RADIUS_SUBTYPE_ACCT_OUTPUTPACKETS, RADIUS_SUBTYPE_ACCT_CAUSE,
	RADIUS_SUBTYPE_ACCT_MULTISESSIONID, RADIUS_SUBTYPE_ACCT_LINKCOUNT,

	/* RFC 2869 (52-55) */
	RADIUS_SUBTYPE_ACCT_INPUTGIGAWORDS, RADIUS_SUBTYPE_ACCT_OUTPUTGIGAWORDS,
	RADIUS_SUBTYPE_reserved_3, RADIUS_SUBTYPE_ACCT_EVENTTIME,

	/* RFC 4675 (56-59) */
	RADIUS_SUBTYPE_EGRESSVLANID, RADIUS_SUBTYPE_INGRESSFILTERS, 
	RADIUS_SUBTYPE_EGRESSVLANNAME, RADIUS_SUBTYPE_USERPRIORITY,

	/* RFC 2865 (60-63) */
	RADIUS_SUBTYPE_CHAPCHALLENGE, RADIUS_SUBTYPE_PORTTYPE,
	RADIUS_SUBTYPE_PORTLIMIT, RADIUS_SUBTYPE_LOGINPORT,

	/* RFC 2867-2869 (64-91) */
	RADIUS_SUBTYPE_TUNNEL_TYPE, RADIUS_SUBTYPE_TUNNEL_MEDIUMTYPE,
	RADIUS_SUBTYPE_TUNNEL_CLIENTENDPOINT, 
	RADIUS_SUBTYPE_TUNNEL_SERVERENDPOINT, 
	RADIUS_SUBTYPE_ACCT_TUNNEL_CONNECTION, RADIUS_SUBTYPE_TUNNEL_PASSWORD,
	RADIUS_SUBTYPE_ARAP_PASSWORD, RADIUS_SUBTYPE_ARAP_FEATURES,
	RADIUS_SUBTYPE_ARAP_ZONE, RADIUS_SUBTYPE_ARAP_SECURITY,
	RADIUS_SUBTYPE_ARAP_SECURITYDATA, RADIUS_SUBTYPE_PASSWORDRETRY,
	RADIUS_SUBTYPE_PROMPT, RADIUS_SUBTYPE_CONNECTINFO, 
	RADIUS_SUBTYPE_CONFIGTOKEN, RADIUS_SUBTYPE_EAPMESSAGE,
	RADIUS_SUBTYPE_MESSAGEAUTH, RADIUS_SUBTYPE_TUNNEL_GROUPID,
	RADIUS_SUBTYPE_TUNNEL_ASSIGNMENT, RADIUS_SUBTYPE_TUNNEL_PREFERENCE,
	RADIUS_SUBTYPE_ARAP_CHALLRESP, RADIUS_SUBTYPE_ACCT_INTERVAL,
	RADIUS_SUBTYPE_ACCT_PACKETSLOST, RADIUS_SUBTYPE_PORTID, 
	RADIUS_SUBTYPE_FRAMED_POOL, RADIUS_SUBTYPE_CUI, 
	RADIUS_SUBTYPE_TUNNEL_CLIENTAUTH, RADIUS_SUBTYPE_TUNNEL_SERVERAUTH,

	/* RFC 4848, 7155 (92-94) */
	RADIUS_SUBTYPE_NAS_FILTER_RULE, 	RADIUS_SUBTYPE_reserved4, 
	RADIUS_SUBTYPE_ORIG_LINE_INFO,

	/* RFC 3162 (95-100) */
	RADIUS_SUBTYPE_NAS_IPV6_ADDR, RADIUS_SUBTYPE_FRAMED_INTERFACE,
	RADIUS_SUBTYPE_FRAMED_IPV6_PREFIX, RADIUS_SUBTYPE_LOGIN_IPV6_HOST,
	RADIUS_SUBTYPE_FRAMED_IPV6_ROUTE, RADIUS_SUBTYPE_FRAMED_IPV6_POOL,

	/* RFC 3576, 4072 (101-102) */
	RADIUS_SUBTYPE_ERROR_CAUSE, RADIUS_SUBTYPE_EAP_KEYNAME,

	/* RFC 5090 (103-122 */
	RADIUS_SUBTYPE_DIGEST_RESPONSE, RADIUS_SUBTYPE_DIGEST_REALM,
	RADIUS_SUBTYPE_DIGEST_NONE, RADIUS_SUBTYPE_DIGEST_RESPONSE_AUTH,
	RADIUS_SUBTYPE_DIGEST_NEXTNONE, RADIUS_SUBTYPE_DIGEST_METHOD,
	RADIUS_SUBTYPE_DIGEST_URI, RADIUS_SUBTYPE_DIGEST_QOP,
	RADIUS_SUBTYPE_DIGEST_ALGO, RADIUS_SUBTYPE_DIGEST_BODYHASH,
	RADIUS_SUBTYPE_DIGEST_CNONCE, RADIUS_SUBTYPE_DIGEST_NONCECT,
	RADIUS_SUBTYPE_DIGEST_USERNAME, RADIUS_SUBTYPE_DIGEST_OPAQUE,
	RADIUS_SUBTYPE_DIGEST_AUTHPARAM, RADIUS_SUBTYPE_DIGEST_AKAAUTS,
	RADIUS_SUBTYPE_DIGEST_DOMAIN, RADIUS_SUBTYPE_DIGEST_STALE,
	RADIUS_SUBTYPE_DIGEST_HA1, RADIUS_SUBTYPE_DIGEST_SIPAOR,

	/* Another 150-odd values from various RFCs (123-190) */

	/* The RADIUS subtype value is a single byte, so values up to 255 are 
	   valid (RADIUS_SUBTYPE_LAST is one larger than the highest possible 
	   value) */
	RADIUS_SUBTYPE_LAST = 256
	} RADIUS_SUBTYPE_TYPE;

/* Vendor IDs for vendor-specific attribute data returned via getMetadata().
   If this isn't set, getMetadata() will return the contents of the last
   vendor-specific attribute read.  If set, getMetadata() will skip any
   vendor-specific attributes until the ones with vendor-ID 
   VENDORSPECIFIC_VENDORID1 or VENDORSPECIFIC_VENDORID2 (if defined) are 
   encountered and return those, see
   https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers */

#ifndef VENDORSPECIFIC_VENDORID1
  #define VENDORSPECIFIC_VENDORID1	2910
  #define VENDORSPECIFIC_VENDORID2	41912
#endif /* VENDORSPECIFIC_VENDORID */

/****************************************************************************
*																			*
*								EAP Constants								*
*																			*
****************************************************************************/

/* The position of various fields within the EAP header: The packet type, 
   the nonce value, the length field, and the optional subtype for Request/
   Response packets */

#define EAP_TYPE_OFFSET			0
#define EAP_NONCE_OFFSET		1
#define EAP_LENGTH_OFFSET		( 1 + 1 )
#define EAP_SUBTYPE_OFFSET		( 1 + 1 + UINT16_SIZE )

/* EAP header lengths, the basic (minimal) size header and the extended 
   header for a Request/Response packet */

#define EAP_HEADER_LENGTH		( 1 + 1 + UINT16_SIZE )
#define EAP_EXT_HEADER_LENGTH	( EAP_HEADER_LENGTH + 1 )

/* The state of an EAP packet read, or at least of its extraction from 
   RADIUS' multiple levels of fragmentation */

typedef enum {
	EAP_STATE_NONE,				/* No EAP state */
	EAP_STATE_PROCESSMESSAGE,	/* Process read EAP message */
	EAP_STATE_CONTINUEREAD,		/* Read more data from EAP message */
	EAP_STATE_SENDACK,			/* Send EAP ACK to continue exchange */
	EAP_STATE_DUMMYREAD,		/* Dummy read, e.g. of EAP ACK */
	EAP_STATE_FINISHED,			/* Finished with either Accept or Reject */
	EAP_STATE_LAST				/* Last possible EAP state */
	} EAP_STATE_TYPE;

/* EAP flags */

#define EAP_FLAG_NONE			0x00	/* No EAP flag */
#define EAP_FLAG_CLIENTWAKEUP	0x01	/* Dummy wakeup packet from client */
#define EAP_FLAG_FRAGMENTED		0x02	/* More EAP packet fragments follow */
#define EAP_FLAG_EAPACK			0x04	/* EAP ACK from client */
#define EAP_FLAG_MAX			0x07	/* Maximum possible flag value */

/****************************************************************************
*																			*
*								RADIUS Constants								*
*																			*
****************************************************************************/

/* The size of the RADIUS nonce (= Authenticator) */

#define RADIUS_NONCE_SIZE		16

/* The position of various fields within RADIUS and RADIUS TLV headers */

#define RADIUS_LENGTH_OFFSET	( 1 + 1 )
#define RADIUS_TLV_HEADER_SIZE	( 1 + 1 )

/* RADIUS data sizes, the maximum size of a TLV being 255 bytes - 
   ( type + length ) */

#define RADIUS_HEADER_SIZE		( 1 + 1 + UINT16_SIZE + RADIUS_NONCE_SIZE )
#define RADIUS_MIN_PACKET_SIZE	RADIUS_HEADER_SIZE
#define RADIUS_MAX_PACKET_SIZE	4096
#define RADIUS_MIN_TLV_SIZE		0
#define RADIUS_MAX_TLV_SIZE		( 255 - ( 1 + 1 ) )

/* The maximum size of the additional information that can be returned by 
   the server over RADIUS channel.  This isn't a carved-in-stone value but
   merely the maximum amount that we provide storage for */

#define MAX_EXTRADATA_SIZE		( MAX_ATTRIBUTE_SIZE / 2 )

/* Magic values passed to the RADIUS write function to denote special-case
   message types */

#define RADIUS_DATA_CHALLENGE	"CHALLENGE"
#define RADIUS_DATA_CHALLENGE_LEN 9

#define RADIUS_DATA_ACCESSACCEPT "ACCESSACCEPT"
#define RADIUS_DATA_ACCESSACCEPT_LEN 12

#define RADIUS_DATA_EAPACK		"EAPACK"
#define RADIUS_DATA_EAPACK_LEN	6

/****************************************************************************
*																			*
*								EAP Data Structures							*
*																			*
****************************************************************************/

/* State information for an EAP-over-RADIUS exchange */

typedef struct {
	/* The EAP state.  The EAP subtype is stored as two values, the current
	   subtype from the read data and the long-term subtype in packets 
	   written.  The EAP length is the length of the overall EAP message, 
	   which may be fragmented across multiple RADIUS TLVs, so it's not the 
	   length of data currently available but the length of the EAP packet 
	   once fragment reassembly has been done */
	EAP_STATE_TYPE eapState;		/* EAP packet read state */
	EAP_TYPE eapType;				/* EAP type */
	EAP_SUBTYPE_TYPE eapSubtypeRead, eapSubtypeWrite;
									/* EAP subtype */
	int eapLength;					/* EAP length */
	int eapFlags;					/* EAP subtype flags */
	int eapCtr;						/* EAP counter (=ID) */

	/* When reading payload data from the multiple levels of encapsulation
	   present in EAP-over-RADIUS, the caller may only read part of the
	   payload.  To deal with resuming a read later, we record the position
	   at which the read was interrupted for later resumption */
	int eapRemainderLength;			/* Remaining data to be read */

	/* The RADIUS state */
	int radiusType;					/* RADIUS type */
	int radiusLength;				/* RADIUS length */
	int radiusCtr;					/* RADIUS counter (=ID) */
	BUFFER_FIXED( RADIUS_NONCE_SIZE ) \
	BYTE radiusNonce[ RADIUS_NONCE_SIZE + 8 ];
									/* RADIUS nonce (= Authenticator) */

	/* The RADIUS State value (a RADIUS attribute, not related to the 
	   general RADIUS state) used to link requests and responses */
	BUFFER( CRYPT_MAX_HASHSIZE, radiusStateNonceSize ) \
	BYTE radiusStateNonce[ CRYPT_MAX_HASHSIZE + 8 ];
	int radiusStateNonceSize;

	/* RADIUS authentication information */
	BUFFER( CRYPT_MAX_TEXTSIZE, userNameLength ) \
	BYTE userName[ CRYPT_MAX_TEXTSIZE + 8 ];
	int userNameLength;
	BUFFER( CRYPT_MAX_TEXTSIZE, passwordLength ) \
	BYTE password[ CRYPT_MAX_TEXTSIZE + 8 ];
	int passwordLength;

	/* Additional information that may be returned by the server over the 
	   RADIUS channel in response to a valid authentication.  This should be
	   communicated inside the EAP-over-RADIUS secure tunnel but for no sane
	   reason is sent outside the tunnel so that everyone gets to share 
	   things like MPPE keys */
	BUFFER( MAX_EXTRADATA_SIZE, extraDataLength ) \
	BYTE extraData[ MAX_EXTRADATA_SIZE + 8 ];
	int extraDataLength;
	} EAP_INFO;

/* When writing EAP packets we need to pass around a sizeable collection of
   values that encode the type, subtype, parameters, options, and other
   information.  To reduce the number of parameters passed to the functions
   that do this, we store them all in a single structure */

typedef struct {
	int type;						/* EAP type */
	EAP_SUBTYPE_TYPE subType;		/* EAP subtype */
	int paramOpt;					/* Optional parameter */
	} EAP_PARAMS;

#define setEAPParamsExt( params, paramType, paramSubtype, paramOptions ) \
	memset( ( params ), 0, sizeof( EAP_PARAMS ) ); \
	( params )->type = paramType; \
	( params )->subType = paramSubtype; \
	( params )->paramOpt = paramOptions; 

#define setEAPParams( params, paramType, paramSubtype ) \
		setEAPParamsExt( params, paramType, paramSubtype, CRYPT_UNUSED )

/****************************************************************************
*																			*
*							EAP Function Prototypes							*
*																			*
****************************************************************************/

/* Prototypes for functions in eap.c */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckNetStreamEAP( IN_PTR const NET_STREAM_INFO *netStream );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
CHECK_RETVAL_PTR_NONNULL \
const char *getEAPPacketName( IN_BYTE const int packetType );
CHECK_RETVAL_PTR_NONNULL \
const char *getEAPSubtypeName( IN_BYTE const int packetType );
CHECK_RETVAL_PTR_NONNULL \
const char *getRADIUSPacketName( IN_BYTE const int packetType );
CHECK_RETVAL_PTR_NONNULL \
const char *getRADIUSSubtypeName( IN_BYTE const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int radiusMD5MacBuffer( OUT_BUFFER_FIXED( 16 ) BYTE *macValue,
						IN_LENGTH_FIXED( 16 ) const int macLength,
						IN_BUFFER( dataLength ) const void *data,
						IN_LENGTH_SHORT const int dataLength,
						IN_BUFFER( keyDataLength ) const void *keyData, 
						IN_LENGTH_SHORT const int keyDataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int radiusMD5HashBuffer( OUT_BUFFER_FIXED( 16 ) BYTE *hashValue,
						 IN_LENGTH_FIXED( 16 ) const int hashLength,
						 IN_BUFFER( dataLength ) const void *data,
						 IN_LENGTH_SHORT const int dataLength,
						 IN_BUFFER( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT const int keyDataLength );

/* Prototypes for functions in eap_rd.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readRADIUSMessage( INOUT_PTR STREAM *stream,
					   INOUT_PTR EAP_INFO *eapInfo,
					   IN_BOOL const BOOLEAN isRequest );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readRADIUSPingResponse( INOUT_PTR STREAM *stream,
							INOUT_PTR EAP_INFO *eapInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5, 6 ) ) \
int processRADIUSTLVs( INOUT_PTR STREAM *stream,
					   INOUT_PTR EAP_INFO *eapInfo,
					   OUT_BUFFER_OPT( dataMaxLength, *bytesCopied ) \
							void *data, 
					   IN_DATALENGTH_Z const int dataMaxLength, 
					   OUT_DATALENGTH_Z int *bytesCopied,
					   INOUT_PTR ERROR_INFO *errorInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerEAPread( INOUT_PTR NET_STREAM_INFO *netStream );

/* Prototypes for functions in eap_wr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int writeRADIUSMessage( INOUT_PTR STREAM *stream,
						INOUT_PTR EAP_INFO *eapInfo,
						const EAP_PARAMS *eapParams,
						IN_BUFFER( dataLength ) const void *data,
						IN_LENGTH_SHORT const int dataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeRADIUSPing( INOUT_PTR STREAM *stream,
					 INOUT_PTR EAP_INFO *eapInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sendEAPACK( INOUT_PTR STREAM *stream, 
				INOUT_PTR EAP_INFO *eapInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int resendLastMessage( NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerEAPwrite( INOUT_PTR NET_STREAM_INFO *netStream );

#endif /* _EAP_DEFINED */
