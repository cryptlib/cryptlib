/****************************************************************************
*																			*
*				  cryptlib TLS Extension Read/Write Code					*
*					Copyright Peter Gutmann 1998-2024						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "tls.h"
  #include "tls_ext.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/tls.h"
  #include "session/tls_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/* The maximum size for a single extension */

#define MAX_EXTENSION_SIZE	8192

/****************************************************************************
*																			*
*							TLS Extension Definitions						*
*																			*
****************************************************************************/

/* TLS extension information.  Further types are defined at
   http://www.iana.org/assignments/tls-extensiontype-values.

   We specify distinct minimum and maximum lengths for client- and server-
   side use (so minLengthClient is the minimum length that a client can 
   send).  A value of CRYPT_ERROR means that this extension isn't valid when 
   sent by the client or server */

typedef struct {
	const int type;					/* Extension type */
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	const char *description;		/* Text description for error messages */
#endif /* USE_ERRMSGS || !NDEBUG */
	const int minLengthClient, minLengthServer;	/* Min.length */
	const int maxLength;			/* Max.length */
	} EXT_CHECK_INFO;

static const EXT_CHECK_INFO extCheckInfoTbl[] = {
	/* Server name indication (SNI), RFC 4366/RFC 6066:

		uint16		listLen
			byte	nameType
			uint16	nameLen
			byte[]	name */
	{ TLS_EXT_SNI, DESCRIPTION( "server name indication" ) 
	  1, 0, MAX_EXTENSION_SIZE },

#ifndef CONFIG_CONSERVE_MEMORY
	/* Maximum fragment length, RFC 4366/RFC 6066:

		byte		fragmentLength */
	{ TLS_EXT_MAX_FRAGMENT_LENTH, DESCRIPTION( "fragment length" )
	  1, 1, 1 },

	/* Client certificate URL.  This dangerous extension allows a client to 
	   direct a server to grope around in arbitrary external (and untrusted) 
	   URLs trying to locate certificates, provinding a convenient mechanism 
	   for bounce attacks and all manner of similar firewall/trusted-host 
	   subversion problems:

		byte		chainType
		uint16		urlAndHashList
			uint16	urlLen
			byte[]	url
			byte	hashPresent
			byte[20] hash			-- If hashPresent flag set */
	{ TLS_EXT_CLIENT_CERTIFICATE_URL, DESCRIPTION( "client certificate URL" ) 
	  1 + UINT16_SIZE + UINT16_SIZE + MIN_URL_SIZE + 1, CRYPT_ERROR, MAX_EXTENSION_SIZE },

	/* Trusted CA certificate(s), RFC 4366/RFC 6066.  This allows a client 
	   to specify which CA certificates it trusts and by extension which 
	   server certificates it trusts, supposedly to reduce handshake 
	   messages in constrained clients.  Since the server usually has only a 
	   single certificate signed by a single CA, specifying the CAs that the 
	   client trusts doesn't serve much purpose:

		uint16		caList
			byte	idType
			[ choice of keyHash, certHash, or DN, another 
			  ASN.1-as-TLS structure ] */
	{ TLS_EXT_TRUSTED_CA_KEYS, DESCRIPTION( "trusted CA" )
	  UINT16_SIZE + 1, CRYPT_ERROR, MAX_EXTENSION_SIZE },

	/* Truncate the HMAC to a nonstandard 80 bits rather than the de facto 
	   IPsec cargo-cult standard of 96 bits, RFC 3546/4366/6066.  
	   
	   In 2017, fourteen years after it was standardised, it was first 
	   noticed that none of the three publicly-available TLS implementations 
	   that support this could interoperate (they'd all implemented it 
	   differently), indicating that this capability has never actually been 
	   used by anyone, so we don't bother supporting it */
	{ TLS_EXT_TRUNCATED_HMAC, DESCRIPTION( "truncated HMAC" )
	  0, 0, 0 },

	/* OCSP status request, RFC 4366/RFC 6066.  Another bounce-attack 
	   enabler, this time on both the server and an OCSP responder.  Both 
	   the responder list and the extensions list may have length zero:

		byte		statusType
		uint16		ocspResponderList	-- May be length 0
			uint16	responderLength
			byte[]	responder
		uint16	extensionLength			-- May be length 0
			byte[]	extensions */
	{ TLS_EXT_STATUS_REQUEST, DESCRIPTION( "OCSP status request" )
	  1 + UINT16_SIZE + UINT16_SIZE, CRYPT_ERROR, MAX_EXTENSION_SIZE },

	/* User mapping.  Used with a complex RFC 4680 mechanism (the extension 
	   itself is in RFC 4681):

		byte		mappingLength
		byte[]		mapping */
	{ TLS_EXT_USER_MAPPING, DESCRIPTION( "user-mapping" )
	  1 + 1, CRYPT_ERROR, 1 + 255 },

	/* Authorisation extenions.  From an experimental RFC for adding 
	   additional authorisation data to the TLS handshake, RFC 5878:

		byte		authzFormatsList
			byte	authzFormatType

	   with the additional authorisation data being carried in the 
	   SupplementalData handshake message */
	{ TLS_EXT_CLIENT_AUTHZ, DESCRIPTION( "client-authz" )
	  1 + 1, CRYPT_ERROR, 1 + 255 },
	{ TLS_EXT_SERVER_AUTHZ, DESCRIPTION( "server-authz" )
	  CRYPT_ERROR, 1 + 1, 1 + 255 },

	/* OpenPGP key.  From an experimental (later informational) RFC with 
	   support for OpenPGP keys, RFC 5081/6091:

		byte		certTypeListLength
		byte[]		certTypeList */
	{ TLS_EXT_CERTTYPE, DESCRIPTION( "cert-type (OpenPGP keying)" )
	  1 + 1, CRYPT_ERROR, 1 + 255 },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* Supported groups, formerly ECC curve IDs, RFC 4492 modified by RFC 
	   5246/TLS 1.2 and again by RFC 8446/TLS 1.3 where it was renamed:

		uint16		namedGroupListLength
		uint16[]	namedGroup */
	{ TLS_EXT_SUPPORTED_GROUPS, DESCRIPTION( "supported groups" )
	  UINT16_SIZE + UINT16_SIZE, CRYPT_ERROR, 512 },

	/* Supported ECC point formats, RFC 4492 modified by RFC 5246/TLS 1.2:

		byte		pointFormatListLength
		byte[]		pointFormat */
	{ TLS_EXT_EC_POINT_FORMATS, DESCRIPTION( "ECDH/ECDSA point format" )
	  1 + 1, 1 + 1, 255 },

#ifndef CONFIG_CONSERVE_MEMORY
	/* SRP user name, RFC 5054:

		byte		userNameLength
		byte[]		userName */
	{ TLS_EXT_SRP, DESCRIPTION( "SRP username" )
	  1 + 1, CRYPT_ERROR, 1 + 255 },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* Signature algorithms, RFC 5246/TLS 1.2:

		uint16		algorithmListLength
			byte	hashAlgo
			byte	sigAlgo */
	{ TLS_EXT_SIGNATURE_ALGORITHMS, DESCRIPTION( "signature algorithm" )
	  UINT16_SIZE + 1 + 1, CRYPT_ERROR, 512 },

#ifndef CONFIG_CONSERVE_MEMORY
	/* DTLS for SRTP keying, RFC 5764:

		uint16		srtpProtectionProfileListLength
			uint16	srtpProtectionProfile
			byte[]	srtp_mki */
	{ TLS_EXT_USE_SRP, DESCRIPTION( "DTLS SRTP keying" )
	  UINT16_SIZE + UINT16_SIZE + 1, CRYPT_ERROR, 512 },

	/* DTLS heartbeat, RFC 6520:

		byte		heartBeatMode */
	{ TLS_EXT_HEARTBEAT, DESCRIPTION( "DTLS heartbeat" )
	  1, 1, 1 },

	/* TLS ALPN, RFC 7301:
		uint16		protocolNameListLength
			uint8	protocolNameLength
			byte[]	protocolName */
	{ TLS_EXT_ALPN, DESCRIPTION( "ALPN" )
	  UINT16_SIZE + 1 + 1, CRYPT_ERROR, 512 },

	/* OCSP status request v2, RFC 6961.  See the comment for 
	   TLS_EXT_STATUS_REQUEST:

		byte		statusType
		uint16		requestLength
			uint16	ocspResponderList	-- May be length 0
				uint16	responderLength
				byte[]	responder
			uint16	extensionLength		-- May be length 0
				byte[]	extensions */
	{ TLS_EXT_STATUS_REQUEST_V2, DESCRIPTION( "OCSP status request v2" )
	  1 + UINT16_SIZE + UINT16_SIZE + UINT16_SIZE, CRYPT_ERROR, MAX_EXTENSION_SIZE },

	/* Certificate transparency timestamp, RFC 6962.  This is another
	   Trusted-CA-certificate level of complexity extension, the client
	   sends an empty request and the server responds with an ASN.1-as-TLS
	   extension, a SignedCertificateTimestampList:

		uint16		signedCertTimestampListLength
			uint16	serialisedSignedCertTimestampLength
				byte[]	[ X.509 level of complexity ]

	   Decoding what all of this requires from the RFC is excessively
	   complex (the spec is vague and ambiguous in several locations, with
	   details of what's required scattered all over the RFC in a mixture of
	   ASN.1 and TLS notation), but requiring a length of 64 bytes seems
	   sound */
	{ TLS_EXT_CERT_TRANSPARENCY, DESCRIPTION( "certificate transparency" )
	  0, UINT16_SIZE + UINT16_SIZE + 64, MAX_EXTENSION_SIZE },

	/* Raw client/server public keys, RFC 7250:

		uint8		certificateTypeLength
			byte[]	certificateTypes */
	{ TLS_EXT_RAWKEY_CLIENT, DESCRIPTION( "client raw public key" )
	  1 + 1, 1 + 1, 64 },
	{ TLS_EXT_RAWKEY_SERVER, DESCRIPTION( "server raw public key" )
	  1 + 1, 1 + 1, 64 },

	/* Client hello padding, RFC 7685.  Used to work around buggy servers 
	   that can't handle client hellos of a certain size:

		uint16		paddingLength
			byte[]	padding */
	{ TLS_EXT_PADDING, DESCRIPTION( "client hello padding" )
	  UINT16_SIZE, CRYPT_ERROR, MAX_EXTENSION_SIZE },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* Encrypt-then-MAC, RFC 7366 */
	{ TLS_EXT_ENCTHENMAC, DESCRIPTION( "encrypt-then-MAC" )
	  0, 0, 0 },

	/* Extended Master Secret, RFC 7627 */
	{ TLS_EXT_EMS, DESCRIPTION( "extended master secret" )
	  0, 0, 0 },

#ifndef CONFIG_CONSERVE_MEMORY
	/* Token binding, RFC 8472:

		byte		majorVersion
		byte		minorVersion
		byte		parameterLength
			byte[]	parameters */
	{ TLS_EXT_TOKENBIND, DESCRIPTION( "token binding" )
	  1 + 1 + 1 + 1, 1 + 1 + 1 + 1, 128 },

	/* Cached information, RFC 7924.  Used by clients to notify the server 
	   that they already have information like the server's certificate 
	   chain, allowing the server to reduce the size of the handshake by
	   not sending it:

		uint16		cachedInfoLength
			byte[]	cachedInfo */
	{ TLS_EXT_CACHED_INFO, DESCRIPTION( "cached information" )
	   UINT16_SIZE + 1, UINT16_SIZE + 1, MAX_EXTENSION_SIZE },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* TLS 1.2 LTS, RFC xxxx */
	{ TLS_EXT_TLS12LTS, DESCRIPTION( "TLS 1.2 LTS" )
	  0, 0, 0 },

#ifndef CONFIG_CONSERVE_MEMORY
	/* Certificate compression, RFC 8879.  This allows the specification of a
	   compression algorithm to compress certificates, meaning an 
	   implementation has to integrate all of zlib et al in order to save 20
	   bytes in a mostly-uncompressible certificate:

		byte		compressionAlgoListLength
			byte	compressionAlgos */
	{ TLS_EXT_COMPRESS_CERT, DESCRIPTION( "compress certificate" )
	  1 + 1, 1 + 1, 128 },

	/* Record size limit, RFC 8449.  Allows limiting the maximum record size 
	   to less than the default 16K, invented by people for whom the
	   TLS_EXT_MAX_FRAGMENT_LENTH extension that everything ignored wasn't
	   cromulent enough so they created a new one for everything to ignore.

		uint16		recordSizeLimit */
	{ TLS_EXT_RECORD_SIZE_LIMIT, DESCRIPTION( "record size limit" )
	  UINT16_SIZE, UINT16_SIZE, UINT16_SIZE },

	/* Secure password exchange, RFC 8492.  A Dan Harkins special that tries
	   to push Dragonfly into TLS:

		byte	passwordName[] */
	{ TLS_EXT_PWD_PROTECT, DESCRIPTION( "password with protected username" )
	  1, CRYPT_ERROR, 255 },
	{ TLS_EXT_PWD_CLEAR, DESCRIPTION( "password with clear username" )
	  1, CRYPT_ERROR, 255 },
	{ TLS_EXT_PASSWORD_SALT, DESCRIPTION( "password salt" )
	  CRYPT_ERROR, 1, MAX_EXTENSION_SIZE },

	/* Server identity pinning, RFC 8672.  Uses the server as a decryption 
	   oracle for a ticket held by the client in order to prove its 
	   identity, another ASN.1-as-TLS extension with lots of optional 
	   fields */
	{ TLS_EXT_TICKET_PINNING, DESCRIPTION( "ticket pinning" )
	  0, 4, MAX_EXTENSION_SIZE },

	/* Certificate-based authentication with external PSK, RFC 8773 */
	{ TLS_EXT_CERT_WITH_PSK, DESCRIPTION( "certificate authentication with external PSK" )
	  0, 0, 0 },

	/* Delegated credentials, RFC 9345.  A mechanism for allowing a server to 
	   issue its own credentials based on a CA-issued certificate without 
	   having to get a full certificate each time.  The contents are 
	   essentially a certificate but encoded in TLS format and with custom
	   signature-handling rules because why use a standard when you can 
	   reinvent it badly yourself? */
	{ TLS_EXT_DELEGATED_CREDENIALS, DESCRIPTION( "delegated credentials" )
	  UINT16_SIZE + UINT16_SIZE, 32, MAX_EXTENSION_SIZE },

	/* Session ticket, RFC 4507/5077.  The client can send a zero-length 
	   session ticket to indicate that it supports the extension but doesn't 
	   have a session ticket yet, and the server can send a zero-length 
	   ticket to indicate that it'll send the client a new ticket later in 
	   the handshake.  Confusing this even more, the specification says that 
	   the client sends "a zero-length ticket" but the server sends "a 
	   zero-length extension".  The original specification, RFC 4507, was 
	   later updated by a second version, RFC 5077, that makes explicit (via 
	   Appendix A) the fact that there's no "ticket length" field in the 
	   extension, so that the entire extension consists of the opaque ticket 
	   data:

		byte[]		sessionTicket (implicit size) */
	{ TLS_EXT_SESSIONTICKET, DESCRIPTION( "session ticket" )
	  0, 0, MAX_EXTENSION_SIZE },

	/* Middlebox security protocol, ETSI TS 103 523-2.  A means of getting 
	   TLS through middleboxes */
	{ TLS_EXT_TLMSP, DESCRIPTION( "TLMSP" )
	  5, 5, MAX_EXTENSION_SIZE },
	{ TLS_EXT_TLMSP_PROXYING, DESCRIPTION( "TLMSP proxying" )
	  4, 4, 4 },
	{ TLS_EXT_TLMSP_DELEGATE, DESCRIPTION( "TLMSP delegation" )
	  4 + 1 + 1, 4 + 1 + 1, MAX_EXTENSION_SIZE },

	/* DTLS-SRTP encrypted key transport, RFC 8870.  Used to distribute SRTP
	   keys to conference-call participants */
	{ TLS_EXT_SUPPORTED_EKT_CIPHERS, DESCRIPTION( "DTLS-SRTP encrypted key transport" )
	  1, 1, 255 },

	/* Monster list of TLS 1.3 extensions, which act to reinvent the TLS 
	   protocol in the form of extensions:

	   Pre-shared key:
		complex[]	pskInfo				-- Client: Complex nested structure
		uint16		pskIdentity			-- Server

	   Early data:

	   Supported versions:
		byte		versionListLength	-- Client
			uint16[] versionList
		uint16		version				-- Server

	   Cookie:
		uint16		cookieLength
			byte[]	cookie

	   Key exchange modes:
		byte		keyexModesLength
			byte[]	keyexModes

	   Certificate authorities:
		uint16		caDNListLength
			byte[]	caDNList

	   OID filters:
		uint16		oidFilterListLength
			byte	oidLength
				byte[] oid
			uint16	extensionsLength	-- May be 0
				byte extensions

	   Post-handshake auth:

	   Certificate signature algorithms:
		uint16		algorithmListLength
			byte	hashAlgo
			byte	sigAlgo

	   Key share:
		uint16		keyShareListLength	-- Client, may be 0
			byte[]	keyShareList
		complex		keyShare			-- Server 

	  The description has a version designator without the string "TLS" 
	  since the code that prints it adds this before it prints the 
	  description */
	{ TLS_EXT_PRESHARED_KEY, DESCRIPTION( "1.3 pre-shared key" )
	  40, UINT16_SIZE, MAX_EXTENSION_SIZE },
	  /* If this is used then it has to be the last extension present (RFC 
	     8446 section 4.2), a TLS 1.3 kludge arising from the way binders 
		 are computed (RFC 8446 section 4.2.11.2) */
	{ TLS_EXT_EARLY_DATA, DESCRIPTION( "1.3 early data" )
	  0, 0, 0 },
#endif /* CONFIG_CONSERVE_MEMORY */

	{ TLS_EXT_SUPPORTED_VERSIONS, DESCRIPTION( "1.3 supported versions" )
	  1 + UINT16_SIZE, UINT16_SIZE, 64 },

#ifndef CONFIG_CONSERVE_MEMORY
	{ TLS_EXT_COOKIE, DESCRIPTION( "1.3 cookie" )
	  UINT16_SIZE + 1, UINT16_SIZE + 1, MAX_EXTENSION_SIZE },
	{ TLS_EXT_PSK_KEYEX_MODES, DESCRIPTION( "1.3 key exchange modes" )
	  1, CRYPT_ERROR, 128 },
	{ TLS_EXT_CAS, DESCRIPTION( "1.3 certificate authorities" )
	  UINT16_SIZE, UINT16_SIZE, MAX_EXTENSION_SIZE },
	{ TLS_EXT_OID_FILTERS, DESCRIPTION( "1.3 OID filters" )
	  UINT16_SIZE + 1 + 1 + UINT16_SIZE, UINT16_SIZE + 1 + 1 + UINT16_SIZE, MAX_EXTENSION_SIZE },
	{ TLS_EXT_POST_HS_AUTH, DESCRIPTION( "1.3 post-handshake auth" )
	  0, CRYPT_ERROR, 0 },
	{ TLS_EXT_SIG_ALGOS_CERT, DESCRIPTION( "1.3 certificate signature algorithms" )
	  UINT16_SIZE + 1 + 1, UINT16_SIZE + 1 + 1, 512 },
	{ TLS_EXT_KEY_SHARE, DESCRIPTION( "1.3 key share" )
	  UINT16_SIZE, UINT16_SIZE + UINT16_SIZE + 32, MAX_EXTENSION_SIZE },
#endif /* CONFIG_CONSERVE_MEMORY */

#ifndef CONFIG_CONSERVE_MEMORY
	/* Certificate transparency information, RFC 6962.  The draft never 
	   actually manages to define what's in this extension apart from 
	   specifying that the client send an empty extension so we just set 
	   the limits to a generic 1...MAX */
	{ TLS_EXT_TRANSPARENCY_INFO, DESCRIPTION( "certificate transparency information" )
	  0, 1, MAX_EXTENSION_SIZE },

	/* Connection ID for DTLS, RFC 9146.  Used to select an SA for DTLS over 
	   source address or port changes:

		byte cid[] */
	{ TLS_EXT_CONNECTION_ID_OLD, DESCRIPTION( "connection ID (deprecated)" )
	  0, 0, 255 },
	{ TLS_EXT_CONNECTION_ID, DESCRIPTION( "connection ID" )
	  0, 0, 255 },

	/* DTLS-SRTP unknown-key-share-attack protection, RFC 8844:

		byte hash[] */
	{ TLS_EXT_EXTERNAL_ID_HASH, DESCRIPTION( "DTLS-SRTP external ID hash" )
	  0, 0, 32 },
	{ TLS_EXT_EXTERNAL_SESSION_ID, DESCRIPTION( "DTLS-SRTP external session ID" )
	  20, 20, 255 },

	/* DTLS for QUIC, RFC 9001.  An opaque blob defined as "whatever QUIC 
	   needs" */
	{ TLS_EXT_QUIC_PARAMETERS, DESCRIPTION( "DTLS for QUIC parameters" )
	  0, 0, MAX_EXTENSION_SIZE },

	/* TLS session ticket request, RFC 9149.  Contains a count of the number
	   of tickets requested (client) or sent (server) */
	{ TLS_EXT_TICKET_REQUEST, DESCRIPTION( "ticket request" )
	  1 + 1, 1, 1 + 1 },

	/* DANE information, RFC 9102.  Used to communicate DANE information to
	   authenticate a server in place of or alongside the usual 
	   certificate */
	{ TLS_EXT_DNSSEC_CHAIN, DESCRIPTION( "DNSSEC chain" )
	  UINT16_SIZE, UINT16_SIZE + 1, MAX_EXTENSION_SIZE },

	/* ECH.  Too complex to explain here:

		byte	type
		uint16	hpkeKDF
		uint16	hpkeAEAD
		byte	configID
		uint16	encLen		-- May be 0
			byte[] enc
		uint16	dataLen
			byte[] data

	   There are other possibilities when the server is responding to an ECH 
	   but since we don't send these we'll never see them */
	{ TLS_EXT_ECH_OUTER, DESCRIPTION( "encrypted client hello outer" )
	  1 + UINT16_SIZE, CRYPT_ERROR, MAX_EXTENSION_SIZE },
	{ TLS_EXT_ECH, DESCRIPTION( "encrypted client hello" )
	  1 + UINT16_SIZE + UINT16_SIZE + 1 + UINT16_SIZE + UINT16_SIZE + 1, 
	  CRYPT_ERROR, MAX_EXTENSION_SIZE },
#endif /* CONFIG_CONSERVE_MEMORY */

	/* Secure renegotiation indication, RFC 5746:

		byte renegotiated_connection[]
	
	   See the comment below for why we (apparently) support this even 
	   though we don't do renegotiation.  We give the length as one, 
	   corresponding to zero-length content, the one is for the single-byte 
	   length field in the extension itself, set to a value of zero.  It can 
	   in theory be larger as part of the secure renegotiation process but 
	   this would be an indication of an attack since we don't do 
	   renegotiation */
	{ TLS_EXT_SECURE_RENEG, DESCRIPTION( "secure renegotiation" )
	  1, 1, 1 },

	/* End-of-list marker */
	{ CRYPT_ERROR, DESCRIPTION( NULL ) 0 }, 
		{ CRYPT_ERROR, DESCRIPTION( NULL ) 0 }
	};

/* Get information on an extension that's needed for basic validity 
   checking */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 3, 4, 5 ) ) \
int getExtensionInfo( IN_RANGE( 0, 65536 ) const int type,
					  IN_BOOL const BOOLEAN isServer,
					  OUT_LENGTH_SHORT_Z int *minLength,
					  OUT_LENGTH_SHORT_Z int *maxLength,
					  OUT_PTR_PTR_OPT const char **description )
	{
	const EXT_CHECK_INFO *extCheckInfoPtr = NULL;
	LOOP_INDEX i;

	REQUIRES( type >= 0 && type <= 65536 );
	REQUIRES( isBooleanValue( isServer ) );

	assert( isWritePtr( minLength, sizeof( int ) ) );
	assert( isWritePtr( maxLength, sizeof( int ) ) );
	assert( isReadPtr( description, sizeof( char * ) ) );

	/* Clear return values */
	*minLength = *maxLength = 0;
	*description = NULL;

	/* Try and find the extension in the extension table */
	LOOP_LARGE( i = 0,
				i < FAILSAFE_ARRAYSIZE( extCheckInfoTbl, \
										EXT_CHECK_INFO ) && \
					extCheckInfoTbl[ i ].type != CRYPT_ERROR,
			    i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( extCheckInfoTbl, \
														   EXT_CHECK_INFO ) - 1 ) );

		if( extCheckInfoTbl[ i ].type == type )
			{
			extCheckInfoPtr = &extCheckInfoTbl[ i ];
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( extCheckInfoTbl, EXT_CHECK_INFO ) ); 
	if( extCheckInfoPtr == NULL )
		{
		/* It's an unrecognised extension, we're done */
		return( OK_SPECIAL );
		}

	/* Return information on the extension to the caller */
	*minLength = isServer ? extCheckInfoPtr->minLengthClient : \
							extCheckInfoPtr->minLengthServer;
	*maxLength = extCheckInfoPtr->maxLength;
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	*description = extCheckInfoPtr->description;
#endif /* USE_ERRMSGS || !NDEBUG */

	return( CRYPT_OK );
	}	

/****************************************************************************
*																			*
*								Read/Write Extensions						*
*																			*
****************************************************************************/

/* SNI:

	uint16		listLen
		byte	nameType
		uint16	nameLen
		byte[]	name 

   If we're the client and we sent this extension to the server then the 
   server may respond with a zero-length server-name extension for no 
   immediately obvious purpose (if the server doesn't recognise the name 
   then it's required to send an 'unrecognised-name' alert so any non-alert 
   return means that the value was accepted, but for some reason it's 
   required to send a zero-length response anyway) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readSNI( INOUT_PTR STREAM *stream, 
			 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
			 IN_LENGTH_SHORT_Z const int extLength,
			 IN_BOOL const BOOLEAN isServer )
	{
	BYTE nameBuffer[ MAX_DNS_SIZE + 8 ];
	int listLen, nameLen, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isShortIntegerRange( extLength ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* If we're the client then the server should have sent us an empty
	   extension */
	if( !isServer )
		return( ( extLength != 0 ) ? CRYPT_ERROR_BADDATA : CRYPT_OK );

	/* Remember that we've seen the server-name extension so that we can 
	   send a zero-length reply to the client */
	handshakeInfo->flags |= HANDSHAKE_FLAG_NEEDSNIRESPONSE;

	/* Read the extension wrapper */
	status = listLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( listLen != extLength - UINT16_SIZE || \
		listLen < 1 + UINT16_SIZE || \
		listLen >= MAX_EXTENSION_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Read the name type and length, with a special-case allowance for 
	   "::1" as the name, which is shorter than the minimum allowed DNS 
	   name */
	if( sgetc( stream ) != 0 )	/* Name type 0 = hostname */
		return( CRYPT_ERROR_BADDATA );
	status = nameLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( nameLen != listLen - ( 1 + UINT16_SIZE ) || \
		( nameLen < MIN_DNS_SIZE && nameLen != 3 ) || \
		nameLen > MAX_DNS_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Read the SNI and hash it so that we can use it, alongside the 
	   sessionID, for scoreboard lookup */
	REQUIRES( rangeCheck( nameLen, 1, MAX_DNS_SIZE ) );
	status = sread( stream, nameBuffer, nameLen );
	if( cryptStatusError( status ) )
		return( status );
	if( nameLen == 3 && memcmp( nameBuffer, "::1", 3 ) )
		{
		/* If the name length is less than MIN_DNS_SIZE then the only 
		   allowed value is "::1" */
		return( CRYPT_ERROR_BADDATA );
		}
	hashData( handshakeInfo->hashedSNI, KEYID_SIZE, nameBuffer, nameLen );
	handshakeInfo->hashedSNIpresent = TRUE;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSNI( INOUT_PTR STREAM *stream,
			  const SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *serverNamePtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME );
	URL_INFO urlInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( serverNamePtr != NULL );

	/* Extract the server FQDN from the overall server name value */
	status = sNetParseURL( &urlInfo, serverNamePtr->value, 
						   serverNamePtr->valueLength, URL_TYPE_HTTPS );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the server name */
	writeUint16( stream, 1 + UINT16_SIZE + urlInfo.hostLen );
	sputc( stream, 0 );		/* Type = DNS name */
	writeUint16( stream, urlInfo.hostLen );
	return( swrite( stream, urlInfo.host, urlInfo.hostLen ) );
	}

/* TLS 1.3 Supported Versions.  This is the actual supported protocol 
   version for TLS 1.3, which always claims to be TLS 1.2 in the proper TLS 
   version fields:

	byte			listLen		-- Client only, server = single entry
		uint16[]	versions 

   This requires some complex juggling to fit what we allow in between 
   max( configured_min_version, explicitly_selected_min_version ) and 
   max_version */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readSupportedVersions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   IN_LENGTH_SHORT_Z const int extLength )
	{
	const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );
	int noVersionEntries = 1;	/* Server sends a single entry */
	int value, status;
	LOOP_INDEX i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isShortIntegerRange( extLength ) );
	REQUIRES( protocolInfo != NULL );

	/* The client sends a list of versions, the server sends a single 
	   version, so if we're the server we need to read the length field 
	   before the version information */
	if( isServer( sessionInfoPtr ) )
		{
		status = value = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( value != extLength - 1 || \
			value < UINT16_SIZE || value > ( UINT16_SIZE * 8 ) || \
			value % UINT16_SIZE != 0 )
			return( CRYPT_ERROR_BADDATA );
		noVersionEntries = value / UINT16_SIZE;
		}
	LOOP_SMALL( i = 0, i < noVersionEntries, i++ )
		{
		int version;

		ENSURES( LOOP_INVARIANT_SMALL( i, 0, noVersionEntries - 1 ) );
	
		/* Get the major version and minor version.  The major version is 
		   always TLS_MAJOR_VERSION, however as part of a misguided attempt 
		   to force "resiliency" Google sends RFC 8701 ("GREASE") garbage 
		   values on each connect rather than just as required for testing 
		   purposes.  To deal with this we implement a degreaser that skips 
		   these values */
		status = value = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		version = value >> 8;
		if( version != TLS_MAJOR_VERSION )
			{
			/* If it's an RFC 8701 / GREASE value, skip it */
			if( checkGREASE( value ) )
				continue;

			return( CRYPT_ERROR_BADDATA );
			}

		/* Get the minor version, the value that we're interested in */
		version = value & 0xFF;
		if( version < TLS_MINOR_VERSION_SSL || \
			version > TLS_MINOR_VERSION_TLS13 + 2 )
			return( CRYPT_ERROR_BADDATA );
		
		/* If we're using TLS 1.3 and the peer has proposed it, switch the
		   version that we're using to that.  This overrides the version
		   negotiation in processVersionInfo(), which stops at TLS 1.2 even
		   for TLS 1.3 since this always pretends to be TLS 1.2.
		   
		   There is one additional case in which we can't do TLS 1.3 and 
		   that's if the client didn't indicate any TLS 1.3 suites in their
		   cipher suite list even if their supported versions indicated TLS 
		   1.3 */
#ifdef USE_TLS13
		if( version != TLS_MINOR_VERSION_TLS13 || \
			protocolInfo->maxVersion < TLS_MINOR_VERSION_TLS13 || \
			sessionInfoPtr->sessionTLS->maxVersion < TLS_MINOR_VERSION_TLS13 || \
			( isServer( sessionInfoPtr ) && !handshakeInfo->tls13OK ) )
			{
			/* It's not TLS 1.3 or we don't support TLS 1.3, continue.  We
			   check both protocolInfo->maxVersion and sessionTLS->maxVersion
			   because the former is the compile-time hardcoded maximum 
			   version while the latter is the user-settable runtime maximum
			   version */
			continue;
			}
		DEBUG_PRINT(( "%s offered TLS 1.%d in extension, switching to "
					  "TLS 1.%d.\n", 
					  isServer( sessionInfoPtr ) ? "Client" : "Server",
					  version - 1, version - 1 ));
		sessionInfoPtr->version = TLS_MINOR_VERSION_TLS13;
#endif /* USE_TLS13 */
		}
	ENSURES( LOOP_BOUND_OK );

	/* Repeat the version check from tls_rd.c:processVersionInfo() now that
	   we know what version we're really dealing with rather than the faked
	   TLS 1.2 in the outer wrapper */
#ifdef USE_TLS13
	if( sessionInfoPtr->version < sessionInfoPtr->sessionTLS->minVersion )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid version number 3.%d, should be at least "
				  "3.%d", sessionInfoPtr->version, 
				  sessionInfoPtr->sessionTLS->minVersion ) );
		}

#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSupportedVersions( INOUT_PTR STREAM *stream,
							const SESSION_INFO *sessionInfoPtr,
							IN_RANGE( TLS_MINOR_VERSION_TLS, \
									  TLS_MINOR_VERSION_TLS13 ) \
								const int minVersion )
	{
	STREAM localStream;
	BYTE buffer[ 16 + 8 ];
	int endPos;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( minVersion >= TLS_MINOR_VERSION_TLS && \
			  minVersion <= TLS_MINOR_VERSION_TLS13 );

	/* Assemble the version information in a local buffer */
	sMemOpen( &localStream, buffer, 16 );
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		writeUint16( &localStream, ( TLS_MAJOR_VERSION << 8 ) | \
									 TLS_MINOR_VERSION_TLS13 );
		}
#endif /* USE_TLS13 */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		writeUint16( &localStream, ( TLS_MAJOR_VERSION << 8 ) | \
									 TLS_MINOR_VERSION_TLS12 );
		}
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS11 && \
		minVersion <= TLS_MINOR_VERSION_TLS11 )
		{
		writeUint16( &localStream, ( TLS_MAJOR_VERSION << 8 ) | \
									 TLS_MINOR_VERSION_TLS11 );
		}
	if( minVersion <= TLS_MINOR_VERSION_TLS )
		{
		writeUint16( &localStream, ( TLS_MAJOR_VERSION << 8 ) | \
									 TLS_MINOR_VERSION_TLS );
		}
	endPos = stell( &localStream );
	sMemDisconnect( &localStream );
	ENSURES( rangeCheck( endPos, 2, 16 ) );

	/* Write the assembled version information */
	sputc( stream, endPos );
	return( swrite( stream, buffer, endPos ) );
	}

/* Preferred (or at least supported) keyex groups, formerly ECC named curves.  
   For the pre-TLS 1.3 case this is a somewhat problematic extension because 
   it applies to any use of ECC, so if (for some reason) the server wants to 
   use a P256 ECDH key with a P521 ECDSA signing key then it has to verify 
   that the client reports that it supports both P256 and P521.  Since our 
   limiting factor is the ECDSA key that we use for signing, we require that 
   the client report support for the curve that matches our signing key.  
   Support for the corresponding ECDH curve is automatic since we support 
   all curves for ECDH that are supported for ECDSA.  However we also have
   to make sure that the corresponding SHA-2 fashion statement is available,
   since we can't sign, for example, SHA2-256 with P521.

   This one-size-fits-all mess leads to a second problem and that's if we're 
   using a non-ECC server key.  In this case we have a preferred curve for 
   ECDH (keyex) but not for ECDSA (server signing key), leading to the 
   following set of possibilities:

				  Private key
	Keyex		ECDSA			RSA			Result
	------		-----			---			------
	DH			-				Yes		->	DH + RSA
	ECDH (any)	-				Yes		->	ECDH + RSA
	ECDH (any)	Yes + match		-		->	ECDH + ECDSA
	25519		-				Yes		->	25519 + RSA
	25519		Yes + match		-		->	25519 + ECDSA

   What this means in terms of matching is that if a non-ECC server key is
   present then we match any curve that we support for the ECC keyex part, 
   if an ECC server key is present then we look for a match for the server 
   key for the signing part and also apply that to the keyex part.

   For TLS 1.3, alongside changing the name from named curves to supported
   groups since it now includes DH values, the interpretation was changed so 
   that there's now a separate extension for signature algorithms so that 
   this applies purely to keyex groups.  However this isn't useful when 
   sending the thing as a client because we have no idea whether we'll be 
   talking TLS 1.3 (which has the signature algorithms extension) or TLS 
   not-1.3 (which doesn't) at that point.
   
   In addition since a TLS 1.3 client encodes the keyex algorithm in the 
   key_share extension that's stuffed into the client hello there's no point 
   in sending this extension because all it can do is duplicate the 
   information already present in the key_share extension, which is non-
   negotiable since it's required for the keyex to work.  TLS 1.3 also 
   requires (RFC 8446 section 4.2.8.0) that "Clients MUST NOT offer any 
   KeyShareEntry values for groups not listed in the client's 
   supported_groups extension", so we have to send this extension even 
   though there's no point to it (the PSK extensions work similarly, 
   clients have to send psk_key_exchange_modes in order to send a 
   pre_shared_key extension, another "fix" for a problem that probably 
   doesn't exist in which the client can advertise support for which PSK 
   modes it supports even though the PSK data is then included right next 
   to the modes data).
   
   Complicating the mess even further is the fact that, since TLS 1.3 allows 
   extensions to be sent in any order and the same information is 
   distributed across two of them, we may not know what groups are indicated 
   when we see the keyex or vice versa, or whether we're even going to be 
   running TLS 1.3 at the end of it all because the actual TLS version is 
   another can-appear-anywhere extension (admittedly it'd be odd to send TLS 
   1.3 keyex extensions but not request TLS 1.3 but there's bound to be 
   someone who has a special use-case that requires it).

   To try and reconcile this chaos we apply the following flow, showing 
   the behaviour with both the keyex first and preferred-groups first:

	keyex1.3 first:
		store 1.3 preferred group + keyex;	
			// keyex1.3 is TLS 1.3 only so it must be a 1.3 preferred group

	preferred_groups:
		store preferred group;
		if( no 1.3 preferred group from keyex && TLS 1.3 group )
			store 1.3 preferred group;
			set 1.3-preferred flag = TRUE;

		Finally:
		if( 1.3 preferred group not set )
			set 1.3 preferred group = preferred group;	
					// TLS 1.3 is a superset of TLS 1.2

	keyex1.3 second:
		if( 1.3 preferred group seen && \
			1.3 preferred group != new preferred group )
			warn;
		store 1.3 preferred group + keyex;	
			// keyex1.3 is TLS 1.3 only so it must be a 1.3 preferred group

	Once hello is processed:
		if( 1.3-preferred flag == TRUE )
			set preferred group = 1.3 preferred group;
		set 1.3 preferred group = NULL;
   
   As part of the overloading of the former named curves extension, TLS 1.3
   now sends DHE group identifiers in the supported groups extension a la
   SSH circa 1996.  However TLS 1.3 has ECC as MTI so it's unlikely that
   anything will do DHE when ECDHE is mandatory, so we omit sending the DHE
   identifiers in order to avoid also sending the DHE keyex values stuffed
   into an extension only to have them discarded by the server.
   
   Because of all this we treat it as having the pre-1.3 semantics:

	uint16		supportedGroupListLength
	uint16[]	supportedGroup */

static const TLS_GROUP_INFO groupInfoTbl[] = {
#if defined( USE_25519 ) && defined( PREFER_25519 ) 
	{ TLS_GROUP_X25519, CRYPT_ALGO_25519, CRYPT_ECCCURVE_NONE,
	  DESCRIPTION( "X25519" ) bitsToBytes( 256 ), 
	  TLS_MINOR_VERSION_TLS13, TRUE },
#endif /* USE_25519 && PREFER_25519 */
	{ TLS_GROUP_SECP256R1, CRYPT_ALGO_ECDH, CRYPT_ECCCURVE_P256,
	  DESCRIPTION( "ECDH P256" ) bitsToBytes( 256 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
	{ TLS_GROUP_BRAINPOOLP256R1, CRYPT_ALGO_ECDH, 
	  CRYPT_ECCCURVE_BRAINPOOL_P256, 
	  DESCRIPTION( "Brainpool P256" ) bitsToBytes( 256 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
#ifdef USE_SHA2_EXT
	{ TLS_GROUP_SECP384R1, CRYPT_ALGO_ECDH, CRYPT_ECCCURVE_P384, 
	  DESCRIPTION( "ECDH P384" ) bitsToBytes( 384 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE  },
	{ TLS_GROUP_SECP521R1, CRYPT_ALGO_ECDH, CRYPT_ECCCURVE_P521, 
	  DESCRIPTION( "ECDH P521" ) bitsToBytes( 521 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
	{ TLS_GROUP_BRAINPOOLP384R1, CRYPT_ALGO_ECDH, 
	  CRYPT_ECCCURVE_BRAINPOOL_P384, 
	  DESCRIPTION( "Brainpool P384" ) bitsToBytes( 384 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
	{ TLS_GROUP_BRAINPOOLP512R1, CRYPT_ALGO_ECDH, 
	  CRYPT_ECCCURVE_BRAINPOOL_P512,
	  DESCRIPTION( "Brainpool P512" ) bitsToBytes( 512 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
#endif /* USE_SHA2_EXT */
	{ TLS_GROUP_FFDHE2048, CRYPT_ALGO_DH, CRYPT_ECCCURVE_NONE, 
	  DESCRIPTION( "DH 2048" ) bitsToBytes( 2048 ), 
	  TLS_MINOR_VERSION_TLS13, FALSE  },
	{ TLS_GROUP_FFDHE3072, CRYPT_ALGO_DH, CRYPT_ECCCURVE_NONE, 
	  DESCRIPTION( "DH 3072" ) bitsToBytes( 3072 ), 
	  TLS_MINOR_VERSION_TLS13, FALSE },
/*	{ TLS_GROUP_FFDHE4096, CRYPT_ALGO_DH,	// Pointlessly large group 
	  CRYPT_ECCCURVE_NONE,
	  DESCRIPTION( "FFDHE4096" ) bitsToBytes( 4096 ), 
	  TLS_MINOR_VERSION_TLS11, FALSE }, */
#if defined( USE_25519 ) && !defined( PREFER_25519 ) 
	{ TLS_GROUP_X25519, CRYPT_ALGO_25519, CRYPT_ECCCURVE_NONE, 
	  DESCRIPTION( "X25519" ) bitsToBytes( 256 ), 
	  TLS_MINOR_VERSION_TLS13, TRUE },
#endif /* USE_25519 && !PREFER_25519 */
	{ TLS_GROUP_NONE, 0 }, { TLS_GROUP_NONE, 0 }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getTLSGroupInfo( OUT_PTR_PTR const TLS_GROUP_INFO **groupInfoPtrPtr,
					 OUT_INT_Z int *noGroupInfoEntries )
	{
	assert( isReadPtr( groupInfoPtrPtr, sizeof( TLS_GROUP_INFO * ) ) );
	assert( isWritePtr( noGroupInfoEntries, sizeof( int ) ) );

	*groupInfoPtrPtr = groupInfoTbl;
	*noGroupInfoEntries = FAILSAFE_ARRAYSIZE( groupInfoTbl, TLS_GROUP_INFO );

	return( CRYPT_OK );
	}

CHECK_RETVAL_PTR \
const TLS_GROUP_INFO *getTLSGroupInfoEntry( IN_ENUM( TLS_GROUP ) \
												const TLS_GROUP_TYPE groupType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( groupType, TLS_GROUP ) );

	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( groupInfoTbl, TLS_GROUP_INFO ) && \
					groupInfoTbl[ i ].tlsGroupID != TLS_GROUP_NONE,
				i++ )
		{
		ENSURES_N( \
			LOOP_INVARIANT_SMALL( i, 0, 
								  FAILSAFE_ARRAYSIZE( groupInfoTbl, \
													  TLS_GROUP_INFO ) - 1 ) );

		if( groupInfoTbl[ i ].tlsGroupID == groupType )
			return( &groupInfoTbl[ i ] );
		}
	ENSURES_N( LOOP_BOUND_OK );

	retIntError_Null();
	}


CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readSupportedGroups( INOUT_PTR STREAM *stream, 
						 INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
						 IN_LENGTH_SHORT_Z const int extLength,
						 OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	const TLS_GROUP_INFO *preferredGroupInfoPtr = NULL;
#ifdef USE_TLS13
	const TLS_GROUP_INFO *preferredTls13GroupInfoPtr = NULL;
#endif /* USE_TLS13 */
	int serverKeySize DUMMY_INIT, listLen, status;
#ifdef CONFIG_SUITEB_TESTS 
	int curvesSeen = 0;
#endif /* CONFIG_SUITEB_TESTS */
	LOOP_INDEX i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*extErrorInfoSet = FALSE;

	/* Read and check the supported groups list header */
	status = listLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( listLen != extLength - UINT16_SIZE || \
		listLen < UINT16_SIZE || listLen > ( 32 * UINT16_SIZE ) || \
		( listLen % UINT16_SIZE ) != 0 )
		return( CRYPT_ERROR_BADDATA );

	/* If there's no server private key present (so we're using PSK suites), 
	   skip the extension */
	if( sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		handshakeInfo->disableECC = TRUE;
		return( sSkip( stream, listLen, MAX_INTLENGTH_SHORT ) );
		}

	/* Get the size of the server's signing key */
	status = krnlSendMessage( sessionInfoPtr->privateKey,
							  IMESSAGE_GETATTRIBUTE, &serverKeySize,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the list of supported groups, recording the most preferred 
	   one */
	LOOP_EXT( i = 0, i < listLen / UINT16_SIZE, i++, 
			  ( 32 * UINT16_SIZE ) + 1 )
		{
		const TLS_GROUP_INFO *groupInfoPtr;
		int value;
		LOOP_INDEX_ALT groupInfoIndex;

		ENSURES( LOOP_INVARIANT_EXT( i, 0, ( listLen / UINT16_SIZE ) - 1, 
									 ( 32 * UINT16_SIZE ) + 1 ) );

		status = value = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( !isEnumRange( value, TLS_GROUP ) )
			{
			/* We don't print "Client" or "Server" for this since it's 
			   already been printed for the extension as a whole */
			DEBUG_PRINT(( "Offered unknown keyex group %d (%X), "
						  "continuing.\n", value, value ));
			continue;	/* Unrecognised keyex type type */
			}
		LOOP_SMALL_ALT( ( groupInfoIndex = 0, groupInfoPtr = NULL ),
						groupInfoIndex < FAILSAFE_ARRAYSIZE( groupInfoTbl, \
															 TLS_GROUP_INFO ) && \
							groupInfoTbl[ groupInfoIndex ].tlsGroupID != TLS_GROUP_NONE,
						groupInfoIndex++ )
			{
			ENSURES( \
				LOOP_INVARIANT_SMALL_ALT( groupInfoIndex, 0, 
										  FAILSAFE_ARRAYSIZE( groupInfoTbl, \
															  TLS_GROUP_INFO ) - 1 ) );

			if( groupInfoTbl[ groupInfoIndex ].tlsGroupID == value )
				{
				groupInfoPtr = &groupInfoTbl[ groupInfoIndex ];
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		if( groupInfoPtr == NULL )
			{
			DEBUG_PRINT(( "Offered unsupported keyex group %d (%X), "
						  "continuing.\n", value, value ));
			continue;	/* Unrecognised keyex type */
			}
		DEBUG_PRINT(( "Offered keyex group %d (%s).\n", value, 
					  groupInfoPtr->description ));
#ifdef CONFIG_SUITEB
		if( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
			{
			const int suiteBinfo = \
						sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;

			/* Suite B only allows P256 and P384.  At the 128-bit level both 
			   P256 and P384 are allowed, at the 256-bit level only P384 is 
			   allowed */
			if( curveID != CRYPT_ECCCURVE_P256 && \
				curveID != CRYPT_ECCCURVE_P384 )
				continue;
			if( suiteBinfo == TLS_PFLAG_SUITEB_256 && \
				curveID == CRYPT_ECCCURVE_P256 )
				continue;
  #ifdef CONFIG_SUITEB_TESTS 
			if( suiteBTestValue == SUITEB_TEST_BOTHCURVES )
				{
				/* We're checking whether the client sends both curve IDs, 
				   remember which ones we've seen so far */
				if( curveID == CRYPT_ECCCURVE_P256 )
					curvesSeen |= 1;
				if( curveID == CRYPT_ECCCURVE_P384 )
					curvesSeen |= 2;
				}
  #endif /* CONFIG_SUITEB_TESTS */
			}
#endif /* CONFIG_SUITEB */

		/* If we're not using an ECC server key then any curve that we 
		   support is OK, otherwise we have to make sure that the requested 
		   curve matches the key */
		if( sessionInfoPtr->privateKeyAlgo == CRYPT_ALGO_ECDSA && \
			groupInfoPtr->keySize != serverKeySize )
			continue;

		/* We've got a matching algorithm and/or curve and there's not 
		   already a better one selected, remember it.  Note that this will 
		   select the client's preferred algorithm rather than our one, so 
		   if the client proposes 25519 before they propose P256 then that's 
		   what'll get selected rather than the MTI P256 */
		if( preferredGroupInfoPtr == NULL && \
			groupInfoTbl[ i ].minTlsVersion <= TLS_MINOR_VERSION_TLS12 )
			{
			DEBUG_PRINT(( "  Set preferred keyex group to %s.\n", 
						  groupInfoPtr->description ));
			preferredGroupInfoPtr = groupInfoPtr;
			}
#ifdef USE_TLS13
		if( preferredTls13GroupInfoPtr == NULL && \
			groupInfoTbl[ i ].minTlsVersion >= TLS_MINOR_VERSION_TLS13 && \
			sessionInfoPtr->sessionTLS->maxVersion >= TLS_MINOR_VERSION_TLS13 )
			{
			DEBUG_PRINT(( "  Set preferred TLS 1.3 keyex group to %s.\n", 
						  groupInfoPtr->description ));
			preferredTls13GroupInfoPtr = groupInfoPtr;
			
			/* If this is the first keyex group we've seen, remember that we
			   prefer the TLS 1.3 one once we finally know whether we're doing
			   TLS 1.3 or not */
			if( preferredGroupInfoPtr == NULL )
				handshakeInfo->keyexTls13Preferred = TRUE;
			}
#endif /* USE_TLS13 */
		}
	ENSURES( LOOP_BOUND_OK );
#ifdef CONFIG_SUITEB_TESTS 
	/* If we're checking for the presence of both P256 and P384 as supported 
	   elliptic curves and we don't see them, complain */
	if( suiteBTestValue == SUITEB_TEST_BOTHCURVES && curvesSeen != 3 )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Supported elliptic curves extension should have "
				  "contained both P256 and P384 but didn't" ) );
		}
#endif /* CONFIG_SUITEB_TESTS */

	/* If we've got TLS 1.3 enabled but couldn't find a TLS 1.3-specific 
	   group, set the TLS 1.3 group to the same as the TLS classic group.
	   This is required because TLS 1.3 pretends to be TLS 1.2 so we don't
	   know at this point whether we're actually using TLS 1.3 or not */
#ifdef USE_TLS13
	if( preferredTls13GroupInfoPtr == NULL )
		preferredTls13GroupInfoPtr = preferredGroupInfoPtr;
#endif /* USE_TLS13 */

	/* If we couldn't find a curve that we have in common with the other 
	   side, disable the use of ECC algorithms */
	if( preferredGroupInfoPtr == NULL )
		handshakeInfo->disableECC = TRUE;
	else
		{
		handshakeInfo->keyexGroupInfo = preferredGroupInfoPtr;
#ifdef USE_TLS13
		handshakeInfo->keyexTls13GroupInfo = preferredTls13GroupInfoPtr;
#endif /* USE_TLS13 */
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSupportedGroups( INOUT_PTR STREAM *stream,
						  const SESSION_INFO *sessionInfoPtr )
	{
	BYTE groupList[ 32 + 8 ];
	int groupIndex = 0;
	LOOP_INDEX i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

#ifdef CONFIG_SUITEB
	if( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
		{
		static const BYTE eccCurveSuiteB128Info[] = {
			TLS_GROUP_SECP256R1, 
			TLS_GROUP_SECP384R1, 
				TLS_GROUP_NONE, TLS_GROUP_NONE 
			};
		static const BYTE eccCurveSuiteB256Info[] = {
			0, TLS_GROUP_SECP384R1, 0, 0 
			};
		const int suiteBinfo = \
				sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;

		if( suiteBinfo == TLS_PFLAG_SUITEB_128 )
			{
			eccCurveInfoPtr = eccCurveSuiteB128Info;
			eccCurveInfoLen = 2;
			}
		else				
			{
			eccCurveInfoPtr = eccCurveSuiteB256Info;
			eccCurveInfoLen = 1;
			}
  #ifdef CONFIG_SUITEB_TESTS 
		/* In some cases for test purposes we have to send invalid ECC
		   information */
		if( suiteBTestValue == SUITEB_TEST_CLIINVALIDCURVE )
			{
			static const BYTE eccCurveSuiteBInvalidInfo[] = {
				0, TLS_GROUP_SECP521R1, 
				0, TLS_GROUP_SECP192R1, 
				0, 0 
				};

			eccCurveInfoPtr = eccCurveSuiteBInvalidInfo;
			eccCurveInfoLen = 2;
			}
  #endif /* CONFIG_SUITEB_TESTS  */
		}
#endif /* CONFIG_SUITEB */

	/* When writing supported groups, we accept some values like DH on the 
	   server but don't advertise them in the client.  We also have to be
	   careful to only advertise groups that this version of TLS supports */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( groupInfoTbl, TLS_GROUP_INFO ) && \
				  groupInfoTbl[ i ].tlsGroupID != TLS_GROUP_NONE,
			  i++ )
		{
		if( !groupInfoTbl[ i ].clientAdvertise || \
			groupInfoTbl[ i ].minTlsVersion > \
					sessionInfoPtr->sessionTLS->maxVersion )
			continue;
		groupList[ groupIndex++ ] = \
			intToByte( groupInfoTbl[ i ].tlsGroupID >> 8 );
		groupList[ groupIndex++ ] = \
			intToByte( groupInfoTbl[ i ].tlsGroupID & 0xFF );
		ENSURES( groupIndex <= 32 );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( isShortIntegerRangeNZ( groupIndex ) );

	writeUint16( stream, groupIndex );
	return( swrite( stream, groupList, groupIndex ) );
	}

/* Signature and hash algorithms sent by the client to the server, a 
   combinatorial explosion of { hash, sig } algorithm pairs (they're 
   called SignatureAndHashAlgorithm in the spec but are actually encoded 
   as HashAndSignatureAlgorithm).  This is used both for extensions and for 
   the TLS 1.2 / 1.3 signature format.

   The background for the chaos described below is that TLS 1.2 and even 
   more so TLS 1.3 started the move from a straighforward cipher-suite 
   system with a few cipher suites that everyone used and many more that 
   everyone ignored, which told you exactly what you were getting at every 
   point in the process, to an IPsec-style a la carte mess where every 
   single thing was variable and negotiable.  TLS 1.3 made it even worse 
   with its 1RTT design, which means that there's no way to actually 
   negotiate anything in advance because you've only got one message each 
   way to get things done, thus the need to either guess which options the 
   other side is using, run several crypto operations in parallel and then 
   keep the one the other side commits to, or just deal with the general 
   mess that this comment is about by using universal defaults like SHA-256 
   as much as possible.

   Initially this complex and confusing extension was added in TLS 1.2 with 
   weird requirements attached to it, for example if the client indicates 
   hash algorithm X then the server (RFC 5246 section 7.4.2) has to somehow 
   produce a certificate chain signed only using that hash algorithm, as if 
   a particular algorithm choice for TLS use could somehow dictate what 
   algorithms the CA and certificate-processing library that's being used 
   will provide (in addition the spec is rather confused on this issue, 
   giving it first as a MUST and then a paragraph later as a SHOULD).  
   
   This also made some certificate signature algorithms like RSA-PSS 
   impossible even if the hash algorithm used is supported by both the TLS 
   and certificate library, because TLS before 1.3 only allowed the 
   specification of PKCS #1 v1.5 signatures.  
   
   What's worse, it creates a situation from which there's no recovery 
   because in the case of a problem all that the server can say is "failed", 
   but not "try again using this algorithm", while returning certificates or 
   a signature with the server's available algorithm (ignoring the 
   requirement to summarily abort the handshake in the case of a mismatch) 
   at least tells the client what the problem is.

   To avoid this mess we assume that everyone can do SHA-256, the TLS 1.2 
   default.  A poll of TLS implementers in early 2011 indicated that 
   everyone else ignores this requirement as well (one implementer described
   the requirement as "that is not just shooting yourself in the foot, that 
   is shooting 'the whole nine yards' (the entire ammunition belt) in your 
   foot"), so we're pretty safe here.

   Writing it is just as bad because we both have to emit the values in
   preferred-algorithm order and some combinations aren't available, so 
   instead of simply iterating down two lists we have to exhaustively
   enumerate each possible algorithm combination.

   The whole thing was made even messier in terms of encoding the values by 
   the TLS 1.3 UI refresh, which despite the claim that "values have been 
   allocated to align with TLS 1.2's encoding" (section 4.2.3) actually 
   encodes the values in what looks like reverse order to TLS 1.2, with the 
   signature type first and the hash second (rsa_pss_rsae_xxx), or with new 
   values invented for where the hash seems to be (rsa_pss_pss_xxx) due to 
   having to encode RSA-PSS twice, once when the certificate it's used with 
   contains the OID rsaEncryption (TLS_SIGHASHALGO_RSAPSSoid1_XXX) and a 
   second time when it contains the OID RSASSA-PSS 
   (TLS_SIGHASHALGO_RSAPSSoid2_XXX).  To deal with this mess we build the 
   TLS 1.2 values from their component algorithm identifiers with 
   MK_SIGHASHID() while using predefined magic values for the TLS 1.3 values.

   But wait, there's more!  Although the client (usually) sends this 
   extension in its hello, the server doesn't send it so the client has no 
   way to know which signature algorithm to expect until it's already 
   processing the signature.  This means that in order to process the 
   signature we first need to process the signature before we can process
   the signature.  To get around this catch-22, we indicate that we only
   support the universal-standard SHA-256, the same as the hash that's
   used in the overall cipher suites.  
   
   For the same reason we ignore the arbitrary requirement (RFC 8446 section 
   4.2.3 that "[if] the client has not sent a 'signature_algorithms' 
   extension, then the server MUST abort the handshake" since it's up to the 
   client to decide to handle our signature, not the server to refuse to 
   even use it.  Since we assume the universal default of SHA-256 for 
   signatures above, we can just default to SHA-256 if we're the server and 
   we don't get sent the extension and everything will keep working.

   TLS 1.3 requires (RFC 8446 section 4.2.3 and again in 4.4.3) that even if 
   PKCS #1 v1.5 signing is indicated in this extension, this only applies to 
   signatures in certificates even if the PKCS #1 v1.5 indication is present 
   in the signature_algorithms rather than signature_algorithm_certificates 
   extension.  Message signing, e.g. for cert_verify, has to make the 
   RSA-PSS fashion statement.

   Speaking of RSA-PSS, TLS 1.3 may or may not require (RFC 8446 section 
   4.2.3, which type of signature is being referred to is ambiguous) that
   the PSS parameters in the certificate be used in the signature.  
   Specifically, the text says "If the corresponding public key's parameters 
   are present, then the parameters in the signature MUST be identical to 
   those in the public key" which means that either TLS is telling CAs how 
   to create their certificates again or it's requiring that an 
   implementation dig down into certificates to extract low-level PSS 
   parameters for use in signing.  For sanity's sake we ignore this 
   requirement.

   Again with RSA-PSS, TLS 1.3 requires (RFC 8446 section 4.2.3) that a TLS 
   1.2 implementation accept an RSA-PSS signature if the client advertises
   this for TLS 1.3 purposes even though TLS 1.2 doesn't do RSA-PSS
   signatures (RFC 5246 section 7.4.2).

   We disallow SHA1 (except for DSA where it's needed due to the hardcoding
   into the signature format) since the whole point of TLS 1.2 was to move 
   away from it, and a poll on the ietf-tls list indicated that all known 
   implementations (all two of them at the time the poll was carried out) 
   work fine with this configuration.

   This extension should really be called dogs_breakfast, not 
   signature_algorithms.  In particular this one is an implicit dog's
   breakfast, while pre_shared_key is an explicit dog's breakfast:

	uint16		algorithmListLength
		byte	hashAlgo
		byte	sigAlgo */

typedef struct {
	CRYPT_ALGO_TYPE sigAlgo, hashAlgo;
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	const char *description;
#endif /* USE_ERRMSGS || !NDEBUG */
	int tlsSigHashID;
	} SIG_HASH_INFO;

#define MK_SIGHASHID( sig, hash )	( ( ( hash ) << 8 ) | ( sig ) )

static const SIG_HASH_INFO sigHashInfo[] = {
	/* RSA */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHAng, 
	  DESCRIPTION( "RSA with SHAng" )
	  MK_SIGHASHID( TLS_SIGALGO_RSA, 255 ) },
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA with SHA2" )
	  MK_SIGHASHID( TLS_SIGALGO_RSA, TLS_HASHALGO_SHA2 ) },
  #if defined( USE_SHA2_EXT ) && 0	/* See long comment at top */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA with SHA2-384" )
	  MK_SIGHASHID( TLS_SIGALGO_RSA, TLS_HASHALGO_SHA384 ) },
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA with SHA2-512" )
	  MK_SIGHASHID( TLS_SIGALGO_RSA, TLS_HASHALGO_SHA512 ) },
  #endif /* USE_SHA2_EXT */
#ifdef USE_PSS
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA-PSS with SHA2 option 1" )
	  TLS_SIGHASHALGO_RSAPSSoid1_SHA2 },
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA-PSS with SHA2 option 2" )
	  TLS_SIGHASHALGO_RSAPSSoid2_SHA2 },
  #if defined( USE_SHA2_EXT ) && 0	/* See long comment at top */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA-PSS with SHA2-384 option 1" )
	  TLS_SIGHASHALGO_RSAPSSoid1_SHA384 },
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA-PSS with SHA2-384 option 2" )
	  TLS_SIGHASHALGO_RSAPSSoid2_SHA384 },
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA-PSS with SHA2-512 option 1" )
	  TLS_SIGHASHALGO_RSAPSSoid1_SHA512 },
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "RSA-PSS with SHA2-512 option 2" )
	  TLS_SIGHASHALGO_RSAPSSoid2_SHA512 },
  #endif /* USE_SHA2_EXT */
#endif /* USE_PSS */

	/* DSA */
#ifdef USE_DSA
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "DSA with SHA1" )
	  MK_SIGHASHID( TLS_SIGALGO_DSA, TLS_HASHALGO_SHA2 ) },
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA1, 
	  DESCRIPTION( "DSA with SHA2" )
	  MK_SIGHASHID( TLS_SIGALGO_DSA, TLS_HASHALGO_SHA1 ) },
#endif /* USE_DSA */

	/* ECDSA */
#ifdef USE_ECDSA
	{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHAng, 
	  DESCRIPTION( "ECDSA with SHAng" )
	  MK_SIGHASHID( TLS_SIGALGO_ECDSA, 255 ) },
#ifdef CONFIG_SUITEB
	{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "DSA with SHA2-384" )
	  MK_SIGHASHID( TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA384 ) },
#endif /* CONFIG_SUITEB */
	{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "ECDSA with SHA2" )
	  MK_SIGHASHID( TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA2 ) },
#if 0	/* 2/11/11 Disabled option for SHA1 after poll on ietf-tls list */
	{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA1, 
	  MK_SIGHASHID( TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA1 ) },
#endif /* 0 */
#endif /* USE_ECDSA */

	/* Ed25519 */
#ifdef USE_ED25519
	/* The usual special-snowflake situation, since Ed25519 wants to sign 
	   the entire message it hardcodes SHA2-512, however what we're signing 
	   is a concatenation of a SHA-2 hash and some other stuff so the 
	   algorithm that we check for is straight SHA-2 */
	{ CRYPT_ALGO_ED25519, CRYPT_ALGO_SHA2, 
	  DESCRIPTION( "Ed25519" )
	  TLS_SIGHASHALGO_ED25519 },
#endif /* USE_ED25519 */
	{ CRYPT_ALGO_NONE, CRYPT_ALGO_NONE }, 
		{ CRYPT_ALGO_NONE, CRYPT_ALGO_NONE }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readSignatureAlgos( INOUT_PTR STREAM *stream, 
						INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						IN_LENGTH_SHORT_Z const int extLength,
						OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
#ifdef CONFIG_SUITEB
	static const MAP_TABLE curveSizeTbl[] = {
		{ bitsToBytes( 256 ), TLS_HASHALGO_SHA2 },
		{ bitsToBytes( 384 ), TLS_HASHALGO_SHA384 },
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	const int suiteBinfo = sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;
	int keySize, hashType, LOOP_ITERATOR;
  #ifdef CONFIG_SUITEB_TESTS 
	int hashesSeen = 0;
  #endif /* CONFIG_SUITEB_TESTS */
#endif /* CONFIG_SUITEB */
	BOOLEAN serverKeyOK = FALSE;
	int listLen, status;
	LOOP_INDEX i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*extErrorInfoSet = FALSE;

	/* Read and check the signature algorithm list header */
	status = listLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( listLen != extLength - UINT16_SIZE || \
		listLen < UINT16_SIZE || listLen > ( 32 * UINT16_SIZE ) || \
		( listLen % UINT16_SIZE ) != 0 )
		return( CRYPT_ERROR_BADDATA );

	/* If we're not using TLS 1.2+ or there's no server private key present 
	   (so we're using PSK suites), skip the extension */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 || \
		sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;
		return( sSkip( stream, listLen, MAX_INTLENGTH_SHORT ) );
		}

	/* Read the hash and signature algorithms */
	LOOP_MED( i = 0, i < listLen / UINT16_SIZE, i++ )
		{
		const SIG_HASH_INFO *sigHashInfoPtr;
		int value;
		LOOP_INDEX_ALT sigHashInfoIndex;

		ENSURES( LOOP_INVARIANT_MED( i, 0, \
									 ( listLen / UINT16_SIZE ) - 1 ) );

		status = value = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( !isEnumRange( value, TLS_SIGHASHALGO ) )
			{
			/* We don't print "Client" or "Server" for this since it's 
			   already been printed for the extension as a whole */
			DEBUG_PRINT(( "Offered unknown signature/hash algorithm %X, "
						  "continuing.\n", value ));
			continue;	/* Unrecognised algorithm type */
			}
		LOOP_SMALL_ALT( ( sigHashInfoIndex = 0, sigHashInfoPtr = NULL ),
						sigHashInfoIndex < FAILSAFE_ARRAYSIZE( sigHashInfo, \
															   SIG_HASH_INFO ) && \
							sigHashInfo[ sigHashInfoIndex ].sigAlgo != CRYPT_ALGO_NONE,
						sigHashInfoIndex++ )
			{
			ENSURES( \
				LOOP_INVARIANT_SMALL_ALT( sigHashInfoIndex, 0, 
										  FAILSAFE_ARRAYSIZE( sigHashInfo, \
															  SIG_HASH_INFO ) - 1 ) );

			if( sigHashInfo[ sigHashInfoIndex ].tlsSigHashID == value && \
				( sigHashInfo[ sigHashInfoIndex ].tlsSigHashID & 0xFF ) != 0xFF )
				{
				sigHashInfoPtr = &sigHashInfo[ sigHashInfoIndex ];
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		if( sigHashInfoPtr == NULL )
			{
			DEBUG_PRINT(( "Offered unsupported signature/hash algorithm %X, "
						  "continuing.\n", value, value ));
			continue;
			}
		DEBUG_PRINT(( "Offered signature/hash algorithm %X (%s).\n", 
					  value, sigHashInfoPtr->description ));

		/* Check whether the server can handle the proposed signature 
		   algorithm.  We don't have to check the hash algorithm for the 
		   reason in the comment earlier or the ECDSA curve type because we
		   only support P256 with SHA256 */
		if( sigHashInfoPtr->sigAlgo == sessionInfoPtr->privateKeyAlgo )
			serverKeyOK = TRUE;
		}
	ENSURES( LOOP_BOUND_OK );
	DEBUG_PRINT_COND( !serverKeyOK, 
					  ( "Warning: No offered signature/hash algorithm "
					    "matched our private key algorithm %s.\n", 
						getAlgoName( sessionInfoPtr->privateKeyAlgo ) ) );

	/* For the more strict handling requirements in Suite B only 256- or 
	   384-bit algorithms are allowed at the 128-bit level and only 384-bit 
	   algorithms are allowed at the 256-bit level */
#ifdef CONFIG_SUITEB
	/* If we're not running in Suite B mode then there are no additional
	   checks required */
	if( !suiteBinfo )
		{
		handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;

		return( sSkip( stream, listLen, MAX_INTLENGTH_SHORT ) );
		}

	/* Get the size of the server's signing key to try and match the 
	   client's preferred hash size */
	status = krnlSendMessage( sessionInfoPtr->privateKey, 
							  IMESSAGE_GETATTRIBUTE, &keySize,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );
	status = mapValue( keySize, &hashType, curveSizeTbl, 
					   FAILSAFE_ARRAYSIZE( curveSizeTbl, MAP_TABLE ) );
	if( cryptStatusError( status ) )
		{
		/* Suite B only allows P256 and P384 keys (checked by the higher-
		   level code when we add the server key) so we should never get to 
		   this situation */
		return( status );
		}
	handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_NONE;

	/* Read the hash and signature algorithms and choose the best one to 
	   use */
	LOOP_EXT_REV_CHECKINC( listLen > 0, listLen -= 1 + 1, 64 + 1 )
		{
		int hashAlgo, sigAlgo;

		ENSURES( LOOP_INVARIANT_EXT_REV_XXX( listLen, 1, MAX_INTLENGTH_SHORT, 
											 64 + 1 ) );

		/* Read the hash and signature algorithm and make sure that it's one 
		   that we can use.  At the 128-bit level both SHA256 and SHA384 are 
		   allowed, at the 256-bit level only SHA384 is allowed */
		hashAlgo = sgetc( stream );			/* Hash algorithm */
		status = sigAlgo = sgetc( stream );	/* Sig.algorithm */
		if( cryptStatusError( status ) )
			return( status );
		if( sigAlgo != TLS_SIGALGO_ECDSA || \
			( hashAlgo != TLS_HASHALGO_SHA2 && \
			  hashAlgo != TLS_HASHALGO_SHA384 ) )
			continue;
		if( suiteBinfo == TLS_PFLAG_SUITEB_256 && \
			hashAlgo != TLS_HASHALGO_SHA384 )
			continue;
  #ifdef CONFIG_SUITEB_TESTS 
		if( suiteBTestValue == SUITEB_TEST_BOTHSIGALGOS )
			{
			/* We're checking whether the client sends both hash algorithm 
			   IDs, remember which ones we've seen so far */
			if( hashAlgo == TLS_HASHALGO_SHA2 )
				hashesSeen |= 1;
			if( hashAlgo == TLS_HASHALGO_SHA384 )
				hashesSeen |= 2;
			}
  #endif /* CONFIG_SUITEB_TESTS */

		/* In addition to the general validity checks, the hash type also has
		   to match the server's key size */
		if( hashType != hashAlgo )
			continue;

		/* We've found one that we can use, set the appropriate variant.  
		   Note that since SHA384 is just a variant of SHA2, we always 
		   choose this if it's available.  Even if the order given is 
		   { SHA384, SHA256 } the parameter value for the original SHA384 
		   will remain set when SHA256 is subsequently read */
		handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;
		if( hashAlgo == TLS_HASHALGO_SHA384 )
			handshakeInfo->keyexSigHashAlgoParam = bitsToBytes( 384 );
		}
	ENSURES( LOOP_BOUND_EXT_REV_OK( 64 + 1 ) );

	/* For Suite B the client must send either SHA256 or SHA384 as an 
	   option */
	if( handshakeInfo->keyexSigHashAlgo == CRYPT_ALGO_NONE )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Signature algorithms extension should have "
				  "contained %sP384/SHA384 but didn't",
				  ( suiteBinfo != TLS_PFLAG_SUITEB_256 ) ? \
					"P256/SHA256 and/or " : "" ) );
		}
#ifdef CONFIG_SUITEB_TESTS 
	/* If we're checking for the presence of both SHA256 and SHA384 as 
	   supported hash algorithms and we don't see them, complain */
	if( suiteBTestValue == SUITEB_TEST_BOTHSIGALGOS && hashesSeen != 3 )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Signature algortithms extension should have contained "
				  "both P256/SHA256 and P384/SHA384 but didn't" ) );
		}
#endif /* CONFIG_SUITEB_TESTS */

	return( CRYPT_OK );
#else
	handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;

	return( CRYPT_OK );
#endif /* CONFIG_SUITEB */
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeSignatureAlgos( STREAM *stream )
	{
	BYTE algoList[ 32 + 8 ];
	LOOP_INDEX i;
	int algoIndex = 0;

	/* Determine which signature and hash algorithms are available for use */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( sigHashInfo, SIG_HASH_INFO ) && \
				  sigHashInfo[ i ].sigAlgo != CRYPT_ALGO_NONE,
			  i++ )
		{
		CRYPT_ALGO_TYPE sigAlgo;
		int LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( sigHashInfo, \
														 SIG_HASH_INFO ) - 1 ) );

		/* If the given signature algorithm isn't enabled, skip any further
		   occurrences of this algorithm */
		sigAlgo = sigHashInfo[ i ].sigAlgo;
		if( !algoAvailable( sigAlgo ) )
			{
			LOOP_MED_CHECKINC_ALT( i < FAILSAFE_ARRAYSIZE( sigHashInfo, \
														   SIG_HASH_INFO ) && \
										sigHashInfo[ i ].sigAlgo == sigAlgo,
								   i++ )
				{
				ENSURES( LOOP_INVARIANT_MED_XXX_ALT( i, 0, 
													 FAILSAFE_ARRAYSIZE( sigHashInfo, \
																		 SIG_HASH_INFO ) - 1 ) );
				}
			ENSURES( LOOP_BOUND_OK_ALT );
			ENSURES( i < FAILSAFE_ARRAYSIZE( sigHashInfo, SIG_HASH_INFO ) );
			i--;	/* Adjust for increment also done in outer loop */

			continue;
			}

		/* If the hash algorithm isn't enabled, skip this entry */
		if( ( sigHashInfo[ i ].tlsSigHashID & 0xFF ) == 0xFF || \
			!algoAvailable( sigHashInfo[ i ].hashAlgo ) )
			continue;

		/* Add the TLS IDs for this signature and hash algorithm combination.  
		   Although the record is called SignatureAndHashAlgorithm, what's 
		   written first is the hash algorithm and not the signature 
		   algorithm */
		algoList[ algoIndex++ ] = \
			intToByte( sigHashInfo[ i ].tlsSigHashID >> 8 );
		algoList[ algoIndex++ ] = \
			intToByte( sigHashInfo[ i ].tlsSigHashID & 0xFF );
		ENSURES( algoIndex <= 32 );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( sigHashInfo, SIG_HASH_INFO ) );
	ENSURES( isShortIntegerRangeNZ( algoIndex ) );

	/* Write the combination of hash and signature algorithms */
	writeUint16( stream, algoIndex );
	return( swrite( stream, algoList, algoIndex ) );
	}
#endif /* USE_TLS */
