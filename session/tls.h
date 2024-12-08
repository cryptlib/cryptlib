<<<<<<< HEAD
/****************************************************************************
*																			*
*							TLS Definitions Header File						*
*						Copyright Peter Gutmann 1998-2021					*
*																			*
****************************************************************************/

#ifndef _TLS_DEFINED

#define _TLS_DEFINED

#if defined( INC_ALL )
  #include "scorebrd.h"
#else
  #include "session/scorebrd.h"
#endif /* _STREAM_DEFINED */

#ifdef USE_TLS

/****************************************************************************
*																			*
*								TLS Constants								*
*																			*
****************************************************************************/

/* Default TLS port */

#define TLS_PORT					443

/* TLS constants */

#define ID_SIZE						1	/* ID byte */
#define LENGTH_SIZE					3	/* 24 bits */
#define SEQNO_SIZE					8	/* 64 bits */
#define VERSIONINFO_SIZE			2	/* 0x03, 0x0n */
#define ALERTINFO_SIZE				2	/* level + description */
#define TLS_HEADER_SIZE				5	/* Type, version, length */
#define TLS_NONCE_SIZE				32	/* Size of client/svr nonce */
#define TLS_SECRET_SIZE				48	/* Size of premaster/master secret */
#define MD5MAC_SIZE					16	/* Size of MD5 proto-HMAC/dual hash */
#define SHA1MAC_SIZE				20	/* Size of SHA-1 proto-HMAC/dual hash */
#define SHA2MAC_SIZE				32	/* Size of SHA-2 HMAC hash */
#define GCMICV_SIZE					16	/* Size of GCM (and Poly1305) ICV */
#define GCM_SALT_SIZE				4	/* Size of implicit portion of 
										   TLS 1.2 GCM IV */
#define GCM_IV_SIZE					12	/* Overall size of GCM IV */
#define BERNSTEIN_IV_SIZE			12	/* Overall size of Bernstein suite IV */
#define TLS_HASHEDMAC_SIZE			12	/* Size of TLS PRF( MD5 + SHA1 ) */
#define SESSIONID_SIZE				16	/* Size of session ID */
#define MIN_SESSIONID_SIZE			4	/* Min.allowed session ID size */
#define MAX_SESSIONID_SIZE			32	/* Max.allowed session ID size */
#define MAX_KEYBLOCK_SIZE			( ( 64 + 32 + 16 ) * 2 )
										/* HMAC-SHA2 + AES-256 key + AES IV */
#ifdef USE_TLS13
  /* TLS 1.3's camouflage double-wrapping means that the minimum packet size 
     can be 3 bytes for an Alert packet, the two-byte payload followed by 
	 the single-byte type, see session/tls_rd.c:recoverPacketDataTLS13() for 
	 how this piece of cleverness works */
  #define MIN_PACKET_SIZE			3	/* Minimum TLS packet size */
#else
  #define MIN_PACKET_SIZE			4	/* Minimum TLS packet size */
#endif /* USE_TLS13 */
  /* TLS 1.3 has the same problem with maximum packet sizes, the maximum 
	 size is still 16384 bytes but now there's an invisible real-packet-type
	 byte appended to the data that's not actually there but is still 
	 present, so with TLS 1.3 MAX_PACKET_SIZE is actually 16385 even if only
	 16384 bytes of data are allowed.  To deal with this the code 
	 dynamically adds an extra byte to the allowed length if TLS 1.3 is in
	 effect */
#define MAX_PACKET_SIZE				16384	/* Maximum TLS packet size */
#define MAX_CIPHERSUITES			200	/* Max.allowed cipher suites */
#ifdef USE_DH1024
  #define TLS_DH_KEYSIZE			128	/* Size of server DH key */
#else
  #define TLS_DH_KEYSIZE			192	/* Size of server DH key */
#endif /* USE_DH1024 */

/* TLS packet/buffer size information.  The extra packet size is somewhat 
   large because it can contains the packet header (5 bytes), IV 
   (0/8/16 bytes), MAC/ICV (12/16/20 bytes), and cipher block padding (up to 
   256 bytes) */

#define EXTRA_PACKET_SIZE			512	

/* By default cryptlib uses DH key agreement, it's also possible to use ECDH 
   key agreement but we disable ECDH by default in order to stick to the
   safer DH.  To use ECDH key agreement in preference to DH, uncomment the 
   following */

/* #define PREFER_ECC //*/
#if ( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) ) && \
	defined( PREFER_ECC ) 
  #pragma message( "  Building with ECC preferred for TLS." )
#endif /* Notify preferred ECC use */
#if defined( PREFER_ECC ) && \
	!( defined( USE_ECDH ) && defined( USE_ECDSA ) )
  #error PREFER_ECC can only be used with ECDH and ECDSA enabled
#endif /* PREFER_ECC && !( USE_ECDH && USE_ECDSA ) */

/* TLS protocol-specific flags that augment the general session flags:

	FLAG_ALERTSENT: Whether we've already sent a close-alert.  Keeping track 
		of this is necessary because we're required to send a close alert 
		when shutting down to prevent a truncation attack, however lower-
		level code may have already sent an alert so we have to remember not 
		to send it twice.

	FLAG_BERNSTEIN: Uses the Bernstein protocol suite instead of the usual 
		CBC.  This is an AEAD exactly like GCM, but the IETF managed to make 
		it incompatible with the standard AEAD use so it needs custom 
		handling.

	FLAG_DISABLE_CERTVERIFY: Disable checking of the server certificate 
	FLAG_DISABLE_NAMEVERIFY: and/or host name.  By default we check both of
		these, but because of all of the problems surrounding certificates 
		we allow the checking to be disabled.

	FLAG_CHECKREHANDSHAKE: The header-read got a handshake packet instead of 
		a data packet, when the body-read decrypts the payload it should 
		check for a rehandshake request in the payload.

	FLAG_CLIAUTHSKIPPED: The client saw an auth-request from the server and 
		responded with a no-certificates alert, if we later get a close 
		alert from the server then we provide additional error information 
		indicating that this may be due to the lack of a client certificate.

	FLAG_EMS: Use extended Master Secret to protect handshake messages.

	FLAG_ENCTHENMAC: Use encrypt-then-MAC rather than the standard 
		MAC-then-encrypt.

	FLAG_GCM: The encryption used is GCM and not the usual CBC, which 
		unifies encryption and MACing into a single operation.
	
	FLAG_MANUAL_CERTCHECK: Interrupt the handshake (returning 
		CRYPT_ERROR_RESOURCE) to allow the caller to check the peer's 
		cerificate.

	FLAG_RESUMED: TLS session is resumed.

	FLAG_SUITEB_128: Enforce Suite B semantics on top of the standard TLS 
	FLAG_SUITEB_256: 1.2 + ECC + AES-GCM ones.  _128 = P256 + P384, 
		_256 = P384 only.

	FLAG_TLS12LTS: TLS 1.2 LTS session with enhanced crypto protection */

#define TLS_PFLAG_NONE				0x0000	/* No protocol-specific flags */
#define TLS_PFLAG_ALERTSENT			0x0001	/* Close alert sent */
#define TLS_PFLAG_CLIAUTHSKIPPED	0x0002	/* Client auth-req.skipped */
#define TLS_PFLAG_GCM				0x0004	/* Encryption uses GCM, not CBC */
#define TLS_PFLAG_BERNSTEIN			0x0008	/* Encryption uses Bernstein suite */
#define TLS_PFLAG_SUITEB_128		0x0010	/* Enforce Suite B 128-bit semantics */
#define TLS_PFLAG_SUITEB_256		0x0020	/* Enforce Suite B 256-bit semantics */
#define TLS_PFLAG_CHECKREHANDSHAKE	0x0040	/* Check decrypted pkt.for rehandshake */
#define TLS_PFLAG_MANUAL_CERTCHECK	0x0080	/* Interrupt handshake for cert.check */
#define TLS_PFLAG_DISABLE_NAMEVERIFY 0x0100	/* Disable host name verification */
#define TLS_PFLAG_DISABLE_CERTVERIFY 0x0200	/* Disable certificate verification */
#define TLS_PFLAG_ENCTHENMAC		0x0400	/* Use encrypt-then-MAC */
#define TLS_PFLAG_EMS				0x0800	/* Use extended Master Secret */
#define TLS_PFLAG_TLS12LTS			0x1000	/* Use TLS 1.2 LTS profile */
#define TLS_PFLAG_SERVER_SNI		0x2000	/* Apply server key switching for SNI */
#define TLS_PFLAG_RESUMED_SESSION	0x4000	/* Session is resumed */
#define TLS_PFLAG_MAX				0x7FFF	/* Maximum possible flag value */

/* Some of the flags above denote extended TLS facilities that need to be
   preserved across session resumptions.  The following value defines the 
   flags that need to be preserved across resumes */

#define TLS_RESUMEDSESSION_FLAGS	( TLS_PFLAG_EMS | TLS_PFLAG_ENCTHENMAC | \
									  TLS_PFLAG_TLS12LTS )

/* Symbolic defines for static analysis checking */

#define TLS_FLAG_NONE				TLS_PFLAG_NONE
#define TLS_FLAG_MAX				TLS_PFLAG_MAX

/* Suite B consists of two subclasses, the 128-bit security level (AES-128 
   with P256 and SHA2-256) and the 192-bit security level (AES-256 with P384 
   and SHA2-384), in order to identify generic use of Suite B we provide a
   pseudo-value that combines the 128-bit and 192-bit subclasses */

#define TLS_PFLAG_SUITEB			( TLS_PFLAG_SUITEB_128 | \
									  TLS_PFLAG_SUITEB_256 )

/* The TLS minimmum version number is encoded as a CRYPT_TLSOPTION_MINVER_xxx
   value, the following mask allows the version to be extracted from the TLS
   option value */

#define TLS_MINVER_MASK				( CRYPT_TLSOPTION_MINVER_SSLV3 | \
									  CRYPT_TLSOPTION_MINVER_TLS10 | \
									  CRYPT_TLSOPTION_MINVER_TLS11 | \
									  CRYPT_TLSOPTION_MINVER_TLS12 | \
									  CRYPT_TLSOPTION_MINVER_TLS13 )

/* TLS message types */

#define TLS_MSG_NONE				0
#define TLS_MSG_CHANGE_CIPHER_SPEC	20
#define TLS_MSG_ALERT				21
#define TLS_MSG_HANDSHAKE			22
#define TLS_MSG_APPLICATION_DATA	23

#define TLS_MSG_FIRST				TLS_MSG_CHANGE_CIPHER_SPEC
#define TLS_MSG_LAST				TLS_MSG_APPLICATION_DATA

/* Special expected packet-type values that are passed to readHSPacketTLS() 
   to handle situations where special-case handling is required for read
   packets:

	TLS_MSG_FIRST_HANDSHAKE: The first handshake packet from the client or 
		server is treated specially in that the version number information 
		is taken from this packet.
		
	TLS_MSG_FIRST_ENCRHANDSHAKE: The attempt to read the first encrypted 
		handshake packet may be met with a TCP close from the peer if it 
		handles errors badly, in which case we provide a special-case error 
		message that indicates more than just "connection closed" 
		
	TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE: TLS 1.3 stuffs encrypted handshake
		messages inside application-data packets so alongside the
		TLS_MSG_FIRST_ENCRHANDSHAKE semantics this also looks for
		application-data rather than handshake packets.
		
	TLS_MSG_TLS13_HELLORETRY: Some TLS 1.3 implementations send a bogus
		Change Cipherspec between the two Client Hellos (see the comment in
		session/tls13_hs.c:processHelloRetry()) so alongside the expected 
		TLS_MSG_HANDSHAKE this also allows an unexpected  
		TLS_MSG_CHANGE_CIPHER_SPEC */

#define TLS_MSG_FIRST_HANDSHAKE		0xFC
#define TLS_MSG_FIRST_ENCRHANDSHAKE	0xFD
#define TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE	0xFE
#define TLS_MSG_TLS13_HELLORETRY	0xFF
#define TLS_MSG_LAST_SPECIAL		TLS_MSG_TLS13_HELLORETRY
#define TLS_MSG_V2HANDSHAKE			0x80

/* TLS handshake message subtypes */

#define TLS_HAND_NONE				0
#define TLS_HAND_CLIENT_HELLO		1
#define TLS_HAND_SERVER_HELLO		2
#define TLS_HAND_NEW_SESSION_TICKET	4
#define TLS_HAND_END_OF_EARLY_DATA	5
#define TLS_HAND_ENCRYPTED_EXTENSIONS 8
#define TLS_HAND_CERTIFICATE		11
#define TLS_HAND_SERVER_KEYEXCHANGE	12
#define TLS_HAND_SERVER_CERTREQUEST	13
#define TLS_HAND_SERVER_HELLODONE	14
#define TLS_HAND_CERTVERIFY			15
#define TLS_HAND_CLIENT_KEYEXCHANGE	16
#define TLS_HAND_FINISHED			20
#define TLS_HAND_SUPPLEMENTAL_DATA	23
#define TLS_HAND_KEY_UPDATE			24

#define TLS_HAND_FIRST				TLS_HAND_CLIENT_HELLO
#define TLS_HAND_LAST				TLS_HAND_KEY_UPDATE

/* TLS alert levels and types, from
   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6 */

#define TLS_ALERTLEVEL_WARNING				1
#define TLS_ALERTLEVEL_FATAL				2

#define TLS_ALERT_CLOSE_NOTIFY				0
#define TLS_ALERT_UNEXPECTED_MESSAGE		10
#define TLS_ALERT_BAD_RECORD_MAC			20
#define TLS_ALERT_DECRYPTION_FAILED			21
#define TLS_ALERT_RECORD_OVERFLOW			22
#define TLS_ALERT_DECOMPRESSION_FAILURE		30
#define TLS_ALERT_HANDSHAKE_FAILURE			40
#define TLS_ALERT_NO_CERTIFICATE			41
#define TLS_ALERT_BAD_CERTIFICATE			42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE	43
#define TLS_ALERT_CERTIFICATE_REVOKED		44
#define TLS_ALERT_CERTIFICATE_EXPIRED		45
#define TLS_ALERT_CERTIFICATE_UNKNOWN		46
#define TLS_ALERT_ILLEGAL_PARAMETER			47
#define TLS_ALERT_UNKNOWN_CA				48
#define TLS_ALERT_ACCESS_DENIED				49
#define TLS_ALERT_DECODE_ERROR				50
#define TLS_ALERT_DECRYPT_ERROR				51
#define TLS_ALERT_TOO_MANY_CIDS				52
#define TLS_ALERT_EXPORT_RESTRICTION		60
#define TLS_ALERT_PROTOCOL_VERSION			70
#define TLS_ALERT_INSUFFICIENT_SECURITY		71
#define TLS_ALERT_INTERNAL_ERROR			80
#define TLS_ALERT_INAPPROPRIATE_FALLBACK	86
#define TLS_ALERT_USER_CANCELLED			90
#define TLS_ALERT_NO_RENEGOTIATION			100
#define TLS_ALERT_MISSING_EXTENSION			109
#define TLS_ALERT_UNSUPPORTED_EXTENSION		110
#define TLS_ALERT_CERTIFICATE_UNOBTAINABLE	111
#define TLS_ALERT_UNRECOGNIZED_NAME			112
#define TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE 113
#define TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE 114
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY		115
#define TLS_ALERT_CERTIFICATE_REQUIRED		116
#define TLS_ALERT_NO_APPLICATION_PROTOCOL	120

#define TLS_ALERT_FIRST						TLS_ALERT_CLOSE_NOTIFY
#define TLS_ALERT_LAST						TLS_ALERT_UNKNOWN_PSK_IDENTITY

/* TLS supplemental data subtypes */

#define TLS_SUPPDATA_USERMAPPING			0

/* TLS cipher suites, from
   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4 */

typedef enum {
	/* SSLv3 cipher suites (0-10) */
	SSL_NULL_WITH_NULL, SSL_RSA_WITH_NULL_MD5, SSL_RSA_WITH_NULL_SHA,
	SSL_RSA_EXPORT_WITH_RC4_40_MD5, SSL_RSA_WITH_RC4_128_MD5, 
	SSL_RSA_WITH_RC4_128_SHA, SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	SSL_RSA_WITH_IDEA_CBC_SHA, SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSL_RSA_WITH_DES_CBC_SHA,
		/* First valid suite if RSA + 3DES enabled */
	SSL_RSA_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) DH cipher suites (11-22) */
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_DSS_WITH_DES_CBC_SHA,
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_RSA_WITH_DES_CBC_SHA, TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DHE_DSS_WITH_DES_CBC_SHA,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_RSA_WITH_DES_CBC_SHA,
		/* First valid suite if RSA disabled, 3DES enabled */
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) anon-DH cipher suites (23-27) */
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, TLS_DH_anon_WITH_RC4_128_MD5,
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_anon_WITH_DES_CBC_SHA,
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) reserved cipher suites (28-29, used for Fortezza in
	   SSLv3) */
	TLS_reserved_1, TLS_reserved_2,

	/* TLS with Kerberos (RFC 2712) suites (30-43) */
	TLS_KRB5_WITH_DES_CBC_SHA, TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
	TLS_KRB5_WITH_RC4_128_SHA, TLS_KRB5_WITH_IDEA_CBC_SHA,
	TLS_KRB5_WITH_DES_CBC_MD5, TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
	TLS_KRB5_WITH_RC4_128_MD5, TLS_KRB5_WITH_IDEA_CBC_MD5,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA, TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, TLS_KRB5_EXPORT_WITH_RC4_40_MD5,

	/* Formerly reserved (44-46), later assigned to PSK-with-NULL suites 
	   (RFC 4785) */
	TLS_PSK_WITH_NULL_SHA, TLS_DHE_PSK_WITH_NULL_SHA, 
	TLS_RSA_PSK_WITH_NULL_SHA,

	/* TLS 1.1 (RFC 4346) cipher suites (47-58) */
	TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DH_DSS_WITH_AES_128_CBC_SHA,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
		/* First valid suite if RSA + 3DES disabled */
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DH_anon_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA, TLS_DH_DSS_WITH_AES_256_CBC_SHA,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DH_anon_WITH_AES_256_CBC_SHA,

	/* TLS 1.2 (RFC 5246) cipher suites (59-61) */
	TLS_RSA_WITH_NULL_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA256,

	/* TLS 1.2 (RFC 5246) DH cipher suites (62-64), continued at 103 */
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256, TLS_DH_RSA_WITH_AES_128_CBC_SHA256, 
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, 

	/* Camellia (RFC 4132) AES-128 suites (65-70) */
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA, 
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA, TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA, 
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA, TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,

	/* Unknown/reserved suites (71-103) */

	/* More TLS 1.2 (RFC 5246) DH cipher suites (103-109) */
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 103, TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256, TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLS_DH_anon_WITH_AES_128_CBC_SHA256,
	TLS_DH_anon_WITH_AES_256_CBC_SHA256,

	/* Unknown suites (110-131) */

	/* Camellia (RFC 4132) AES-256 suites (132-137) */
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 132,
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA, TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA, TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,

	/* TLS-PSK (RFC 4279) cipher suites (138-149) */
	TLS_PSK_WITH_RC4_128_SHA, TLS_PSK_WITH_3DES_EDE_CBC_SHA, 
	TLS_PSK_WITH_AES_128_CBC_SHA, TLS_PSK_WITH_AES_256_CBC_SHA, 
	TLS_DHE_PSK_WITH_RC4_128_SHA, TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA, TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
	TLS_RSA_PSK_WITH_RC4_128_SHA, TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA, TLS_RSA_PSK_WITH_AES_256_CBC_SHA,

	/* SEED (RFC 4162) suites (150-155) */
	TLS_RSA_WITH_SEED_CBC_SHA, TLS_DH_DSS_WITH_SEED_CBC_SHA,
	TLS_DH_RSA_WITH_SEED_CBC_SHA, TLS_DHE_DSS_WITH_SEED_CBC_SHA,
	TLS_DHE_RSA_WITH_SEED_CBC_SHA, TLS_DH_anon_WITH_SEED_CBC_SHA,

	/* TLS 1.2 (RFC 5288) GCM cipher suites (156-167) */
	TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256, TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256, TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_anon_WITH_AES_128_GCM_SHA256, TLS_DH_anon_WITH_AES_256_GCM_SHA384,

	/* TLS 1.2 (RFC 5487) PSK cipher suites (168-185) */
	TLS_PSK_WITH_AES_128_GCM_SHA256, TLS_PSK_WITH_AES_256_GCM_SHA384,
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256, TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
	TLS_PSK_WITH_AES_128_CBC_SHA256, TLS_PSK_WITH_AES_256_CBC_SHA384,
	TLS_PSK_WITH_NULL_SHA256, TLS_PSK_WITH_NULL_SHA384,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
	TLS_DHE_PSK_WITH_NULL_SHA256, TLS_DHE_PSK_WITH_NULL_SHA384,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256, TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
	TLS_RSA_PSK_WITH_NULL_SHA256, TLS_RSA_PSK_WITH_NULL_SHA384,

	/* TLS 1.2 (RFC 5932) Camellia cipher suites (186-197) */
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256, TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256, TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256, TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256, TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256, TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,

	/* TLS secure-rengotiation signalling cipher suite, RFC 5746 */
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 255,

	/* TLS fallback signalling cpiher suite, RFC 7507, stuffed into a gap in 
	   the range starting at 22016/0x5600 */
	TLS_FALLBACK_SCSV = 22016,

	/* TLS 1.3 symmetric-only suites, RFC 8446 (0x1301-0x1305, 4865-4869) */
	TLS_AES_128_GCM_SHA256 = 4865, TLS_AES_256_GCM_SHA384, 
	TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_8_SHA256,

	/* TLS-ECC (RFC 4492) cipher suites.  For some unknown reason these 
	   start above 49152/0xC000, so the range is 49153...49177 */
	TLS_ECDH_ECDSA_WITH_NULL_SHA = 49153, TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_NULL_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_RSA_WITH_NULL_SHA, TLS_ECDH_RSA_WITH_RC4_128_SHA,
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_NULL_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_anon_WITH_NULL_SHA, TLS_ECDH_anon_WITH_RC4_128_SHA,
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA,

	/* TLS-SRP (RFC 5054) cipher suites, following the pattern from 
	   above at 49178/0xC01A...49186 */
	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA, TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA, TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA, TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,

	/* TLS-ECC (RFC 5289) SHA-2 cipher suites, following the pattern from 
	   above at 49187/0xC023...49194 */
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,

	/* TLS-ECC (RFC 5289) GCM cipher suites, following the pattern from above
	   at 49195/0xC02B...49202 */
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,

	/* TLS-ECC (RFC 5489) PSK cipher suites, following the pattern from above
	   at 49203/0xC033...49211 */
	TLS_ECDHE_PSK_WITH_RC4_128_SHA, TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_PSK_WITH_NULL_SHA, TLS_ECDHE_PSK_WITH_NULL_SHA256,
    TLS_ECDHE_PSK_WITH_NULL_SHA384,

	/* Endless vanity suites, Aria, Camellia, etc */

	/* TLS Bernstein protocol suite (RFC 7905), following the pattern from 
	   above at 52392/0xCCA8...52398/0xCCAE */
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52392,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, 
	TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
	TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,

	TLS_LAST_SUITE
	} TLS_CIPHERSUITE_TYPE;

/* The first cipher suite that we'll even consider.  If RSA + 3DES is enabled
   (RSA is disabled by default) it's the one and only SSLv3 3DES suite, if
   only 3DES is enabled it's the last TLS 1.0 suite, and if neither are enabled
   it's a TLS 1.1 AES suite */

#if defined( USE_RSA_SUITES )
  #define TLS_FIRST_VALID_SUITE		SSL_RSA_WITH_3DES_EDE_CBC_SHA
#else
  #if defined( USE_3DES )
	#define TLS_FIRST_VALID_SUITE	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  #else
	#define TLS_FIRST_VALID_SUITE	TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  #endif /* USE_3DES */
#endif /* USE_RSA_SUITES */

/* TLS extension types, from 
   http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */

typedef enum {
	TLS_EXT_SNI,				/* 0: Name of virtual server to contact (SNI) */
	TLS_EXT_MAX_FRAGMENT_LENTH,	/* 1: Max.fragment length if smaller than 2^14 bytes */
	TLS_EXT_CLIENT_CERTIFICATE_URL,	/* 2: Location for server to find client certificate */
	TLS_EXT_TRUSTED_CA_KEYS,	/* 3: Indication of which CAs clients trust */
	TLS_EXT_TRUNCATED_HMAC,		/* 4: Use 80-bit truncated HMAC */
	TLS_EXT_STATUS_REQUEST,		/* 5: OCSP status request from server */
	TLS_EXT_USER_MAPPING,		/* 6: RFC 4681 mapping of user name to account */
	TLS_EXT_CLIENT_AUTHZ,		/* 7: RFC 5878 authorisation exts */
	TLS_EXT_SERVER_AUTHZ,		/* 8: RFC 5878 authorisation exts */
	TLS_EXT_CERTTYPE,			/* 9: RFC 5081/6091 OpenPGP key support */
	TLS_EXT_SUPPORTED_GROUPS,	/* 10: RFC 8446 Supported Groups, formerly
									   RFC 4492 ECC elliptic curve types */
	TLS_EXT_EC_POINT_FORMATS,	/* 11: RFC 4492 ECDH/ECDSA support */
	TLS_EXT_SRP,				/* 12: RFC 5054 SRP support */
	TLS_EXT_SIGNATURE_ALGORITHMS,/* 13: RFC 5246 TLSv1.2 */
	TLS_EXT_USE_SRP,			/* 14: RFC 5764 DTLS for SRTP keying */
	TLS_EXT_HEARTBEAT,			/* 15: RFC 6520 DTLS heartbeat */
	TLS_EXT_ALPN,				/* 16: RFC 7301 Application layer protocol negotiation */
	TLS_EXT_STATUS_REQUEST_V2,	/* 17: RFC 6961 OCSP status request from server */
	TLS_EXT_CERT_TRANSPARENCY,	/* 18: RFC 6962 Certificate transparency timestamp */
	TLS_EXT_RAWKEY_CLIENT,		/* 19: RFC 7250 Raw client public key */
	TLS_EXT_RAWKEY_SERVER,		/* 20: RFC 7250 Raw server public key */
	TLS_EXT_PADDING,			/* 21: RFC 7685 Padding */
	TLS_EXT_ENCTHENMAC,			/* 22: RFC 7366 Encrypt-then-MAC */
	TLS_EXT_EMS,				/* 23: RFC 7627 Extended master secret */
	TLS_EXT_TOKENBIND,			/* 24: Draft, Token binding */
	TLS_EXT_CACHED_INFO,		/* 25: RFC 7924 Cached info */
	TLS_EXT_TLS12LTS,			/* 26: Draft, TLS 1.2 LTS */
	TLS_EXT_COMPRESS_CERT,		/* 27: RFC 8879 Certificate compression */
	TLS_EXT_RECORD_SIZE_LIMIT,	/* 28: RFC 8449 Record size limit */
	TLS_EXT_PWD_PROTECT,		/* 29: RFC 8492 Password, protected username */
	TLS_EXT_PWD_CLEAR,			/* 30: RFC 8492 Password, visible username */
	TLS_EXT_PASSWORD_SALT,		/* 31: RFC 8492 Password salt */
	TLS_EXT_TICKET_PINNING,		/* 32: RFC 8672 Server identity pinning */
	TLS_EXT_CERT_WITH_PSK,		/* 33: RFC 8773 TLS 1.3 Certificate-based auth with PSK */
	TLS_EXT_DELEGATED_CREDENIALS, /* 34: Draft, Delegated credentials */
	TLS_EXT_SESSIONTICKET,		/* 35: RFC 4507 Session ticket */
	TLS_EXT_TLMSP,				/* 36: ETSI TS 103 523-2, Middlebox */
	TLS_EXT_TLMSP_PROXYING,		/* 37: ETSI TS 103 523-2, Security */
	TLS_EXT_TLMSP_DELEGATE,		/* 38: ETSI TS 103 523-2, Protocol */
	TLS_EXT_SUPPORTED_EKT_CIPHERS, /* 39: RFC 8870, Encrypted key trasport */
		/* 40 unused */
	TLS_EXT_PRESHARED_KEY = 41,	/* 41: RFC 8446 TLS 1.3 pre-shared key */
	TLS_EXT_EARLY_DATA,			/* 42: RFC 8446 TLS 1.3 early data */
	TLS_EXT_SUPPORTED_VERSIONS,	/* 43: RFC 8446 TLS 1.3 supported versions */
	TLS_EXT_COOKIE,				/* 44: RFC 8446 TLS 1.3 cookie */
	TLS_EXT_PSK_KEYEX_MODES,	/* 45: RFC 8446 TLS 1.3 key exchange modes */
		/* 46 unused */
	TLS_EXT_CAS = 47,			/* 47: RFC 8446 TLS 1.3 certificate authorities */
	TLS_EXT_OID_FILTERS,		/* 48: RFC 8446 TLS 1.3 OID filters */
	TLS_EXT_POST_HS_AUTH,		/* 49: RFC 8446 TLS 1.3 post-handshake auth */
	TLS_EXT_SIG_ALGOS_CERT,		/* 50: RFC 8446 TLS 1.3 certificate signature algos */
	TLS_EXT_KEY_SHARE,			/* 51: RFC 8446 TLS 1.3 key share */
	TLS_EXT_TRANSPARENCY_INFO,	/* 52: Draft, Certificate transparency info */
	TLS_EXT_CONNECTION_ID_OLD,	/* 53: Draft, DTLS connection ID, deprecated */
	TLS_EXT_CONNECTION_ID,		/* 54: Draft, DTLS connection ID */
	TLS_EXT_EXTERNAL_ID_HASH,	/* 55: RFC 8844, DTLS-SRTP external ID hash */
	TLS_EXT_EXTERNAL_SESSION_ID,/* 56: RFC 8844, DTLS-SRTP external session ID */
	TLS_EXT_QUIC_PARAMETERS,	/* 57: RFC 9001, DTLS for QUIC */
	TLS_EXT_TICKET_REQUEST,		/* 58: Draft, TLS 1.3 ticket request */
	TLS_EXT_DNSSEC_CHAIN,		/* 59: Draft, DANE authentication information */
	TLS_EXT_LAST,
		/* 60....65280 unused */

	/* The secure-renegotiation extension, for some unknown reason, is given
	   a value of 65281 / 0xFF01, so we define it outside the usual 
	   extension range in order for the standard range-checking to be a bit
	   more sensible.
	   
	   Once secure-renegotiation started this, others followed, so now we've
	   got several special-snowflake values that we need to accommodate */
	TLS_EXT_ECH_OUTER = 64768,	/* ECH draft */
	TLS_EXT_ECH = 65037,		/* ECH draft */
	TLS_EXT_SECURE_RENEG = 65281/* RFC 5746 secure renegotiation */
	} TLS_EXT_TYPE;

/* TLS certificate types */

typedef enum {
	TLS_CERTTYPE_NONE, TLS_CERTTYPE_RSA, TLS_CERTTYPE_DSA, 
	TLS_CERTTYPE_DUMMY1 /* RSA+DH */, TLS_CERTTYPE_DUMMY2 /* DSA+DH */,
	TLS_CERTTYPE_DUMMY3 /* RSA+EDH */, TLS_CERTTYPE_DUMMY4 /* DSA+EDH */,
	TLS_CERTTYPE_ECDSA = 64, TLS_CERTTYPE_LAST
	} TLS_CERTTYPE_TYPE;

/* TLS signature and hash algorithm identifiers */

enum {
	TLS_SIGALGO_NONE, TLS_SIGALGO_RSA, TLS_SIGALGO_DSA, TLS_SIGALGO_ECDSA,
	TLS_SIGALGO_LAST 
	};

enum {
	TLS_HASHALGO_NONE, TLS_HASHALGO_MD5, TLS_HASHALGO_SHA1, 
	TLS_HASHALGO_DUMMY1 /* SHA2-224 */, TLS_HASHALGO_SHA2, 
	TLS_HASHALGO_SHA384, TLS_HASHALGO_SHA512, 
	TLS_HASHALGO_LAST 
	};

/* TLS 1.3 combined signature+hash identifiers.  See the comment in 
   session/tls_ext.c for why there are two lots of identifiers for 
   RSA-PSS */

enum {
	/* TLS classic IDs */
	TLS_SIGHASHALGO_RSAPKCS1_SHA2 = 0x0401, TLS_SIGHASHALGO_DSA_SHA2, 
	TLS_SIGHASHALGO_ECDSA_SHA2,
	TLS_SIGHASHALGO_RSAPKCS1_SHA384 = 0x0501, TLS_SIGHASHALGO_DSA_SHA384, 
	TLS_SIGHASHALGO_ECDSA_SHA384,
	TLS_SIGHASHALGO_RSAPKCS1_SHA512 = 0x0601, TLS_SIGHASHALGO_DSA_SHA512,
	TLS_SIGHASHALGO_ECDSA_SHA512,

	/* TLS 1.3 IDs */
	TLS_SIGHASHALGO_RSAPSSoid1_SHA2 = 0x0804, 
	TLS_SIGHASHALGO_RSAPSSoid1_SHA384,
	TLS_SIGHASHALGO_RSAPSSoid1_SHA512,
	TLS_SIGHASHALGO_ED25519, TLS_SIGHASHALGO_ED448, 
	TLS_SIGHASHALGO_RSAPSSoid2_SHA2, TLS_SIGHASHALGO_RSAPSSoid2_SHA384,
	TLS_SIGHASHALGO_RSAPSSoid2_SHA512,
	TLS_SIGHASHALGO_LAST
	};

/* TLS group type identifiers */

typedef enum {
	TLS_GROUP_NONE, 
	
	/* ECC groups */
	TLS_GROUP_SECT163K1, TLS_GROUP_SECT163R1, TLS_GROUP_SECT163R2, 
	TLS_GROUP_SECT193R1, TLS_GROUP_SECT193R2, TLS_GROUP_SECT233K1, 
	TLS_GROUP_SECT233R1, TLS_GROUP_SECT239K1, TLS_GROUP_SECT283K1, 
	TLS_GROUP_SECT283R1, TLS_GROUP_SECT409K1, TLS_GROUP_SECT409R1, 
	TLS_GROUP_SECT571K1, TLS_GROUP_SECT571R1, TLS_GROUP_SECP160K1, 
	TLS_GROUP_SECP160R1, TLS_GROUP_SECP160R2, TLS_GROUP_SECP192K1, 
	TLS_GROUP_SECP192R1, TLS_GROUP_SECP224K1, TLS_GROUP_SECP224R1, 
	TLS_GROUP_SECP256K1, 
	TLS_GROUP_SECP256R1 /* P256 */, 
	TLS_GROUP_SECP384R1 /* P384 */, 
	TLS_GROUP_SECP521R1 /* P521 */,
	TLS_GROUP_BRAINPOOLP256R1, TLS_GROUP_BRAINPOOLP384R1, 
	TLS_GROUP_BRAINPOOLP512R1,
	TLS_GROUP_X25519, TLS_GROUP_X448,
	TLS_GROUP_FFDHE2048 = 256, TLS_GROUP_FFDHE3072,
	TLS_GROUP_FFDHE4096, TLS_GROUP_FFDHE6144, TLS_GROUP_FFDHE8192,
	TLS_GROUP_LAST
	} TLS_GROUP_TYPE;

#define isECCGroup( group ) \
		( ( group ) > TLS_GROUP_NONE && ( group ) < TLS_GROUP_FFDHE2048 )

/* TLS 1.3 PSK modes */

typedef enum {
	TLS_PSK_STANDARD,	/* Equivalent to TLS < 1.3 session resumption */
	TLS_PSK_DHE,		/* Session resumption with (EC)DH */
	TLS_PSK_LAST
	} TLS_PSK_TYPE;

/* TLS major and minor version numbers */

#define TLS_MAJOR_VERSION		3
#define TLS_MINOR_VERSION_SSL	0
#define TLS_MINOR_VERSION_TLS	1
#define TLS_MINOR_VERSION_TLS11	2
#define TLS_MINOR_VERSION_TLS12	3
#define TLS_MINOR_VERSION_TLS13	4

/* TLS downgrade-protection magic values for the server random */

#define TLS_DOWNGRADEID_PREFIX	"DOWNGRD"
#define TLS_DOWNGRADEID_PREFIX_SIZE	7
#define TLS_DOWNGRADEID_TLS12	TLS_DOWNGRADEID_PREFIX "\x01"
#define TLS_DOWNGRADEID_TLS11	TLS_DOWNGRADEID_PREFIX "\x00"
#define TLS_DOWNGRADEID_SIZE	8
#define TLS_DOWNGRADEID_OFFSET	( TLS_NONCE_SIZE - TLS_DOWNGRADEID_SIZE )

/* TLS 1.3 magic value to denote that a Server Hello is actually a Hello 
   Retry Request */

#define TLS_HELLORETRY_MAGIC	"\xCF\x21\xAD\x74\xE5\x9A\x61\x11" \
								"\xBE\x1D\x8C\x02\x1E\x65\xB8\x91" \
								"\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E" \
								"\x07\x9E\x09\xE2\xC8\xA8\x33\x9C"
#define TLS_HELLORETRY_MAGIC_SIZE 32

/* TLS cipher suite fallback options, see the comment in TLS_HANDSHAKE_INFO
   for details */

typedef enum {
	TLS_FALLBACK_NONE,				/* No fallback type */
	TLS_FALLBACK_ECC,				/* Fallback to ECC suite */
	TLS_FALLBACK_TLS13,				/* Fallback to TLS 1.3 suite */
	TLS_FALLBACK_LAST
	} TLS_FALLBACK_TYPE;

/* Special-case actions that need to be taken in response to a client hello */

typedef enum {
	TLSHELLO_ACTION_NONE,			/* No special action */
	TLSHELLO_ACTION_RESUMEDSESSION,	/* Session is resumed from previous */
#ifdef USE_TLS13
	TLSHELLO_ACTION_RETRY,			/* Send TLS 1.3 HelloRetryRequest */
#endif /* USE_TLS13 */
	TLSHELLO_ACTION_LAST
	} TLSHELLO_ACTION_TYPE;

/* TLS cipher suite flags.  These are:

	CIPHERSUITE_BERNSTEIN: Suite uses the Bernstein algorithm suite.

	CIPHERSUITE_PSK: Suite is a TLS-PSK suite and is used only if we're
		using TLS-PSK.

	CIPHERSUITE_DH:	Suite is a DH suite.

	CIPHERSUITE_ECC: Suite is an ECC suite and is used only if ECC is
		enabled.

	CIPHERSUITE_GCM: Encryption uses GCM instead of the usual CBC.

	CIPHERSUITE_TLS12: Suite is a TLS 1.2 suite and is only sent if
		TLS 1.2 is enabled.

	CIPHERSUITE_TLS13: Suite is a TLS 1.3 suite and is only sent if
		TLS 1.3 is enabled */

#define CIPHERSUITE_FLAG_NONE	0x00	/* No suite */
#define CIPHERSUITE_FLAG_PSK	0x01	/* TLS-PSK suite */
#define CIPHERSUITE_FLAG_DH		0x02	/* DH suite */
#define CIPHERSUITE_FLAG_TLS12	0x04	/* TLS 1.2 suite */
#define CIPHERSUITE_FLAG_TLS13	0x08	/* TLS 1.3 suite */
#define CIPHERSUITE_FLAG_GCM	0x10	/* GCM instead of CBC */
#define CIPHERSUITE_FLAG_BERNSTEIN 0x20	/* Bernstein suite */
#define CIPHERSUITE_FLAG_MAX	0x3F	/* Maximum possible flag value */

typedef struct {
	/* The TLS cipher suite.  The debugText field isn't used in error 
	   messages but is enabled if their use is defined because of the way 
	   the DESCRIPTION() macro that sets it works */
	const int cipherSuite;
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	const char *debugText;
#endif /* USE_ERRMSGS || !NDEBUG */

	/* cryptlib algorithms for the cipher suite */
	const CRYPT_ALGO_TYPE keyexAlgo, authAlgo, cryptAlgo, macAlgo;

	/* Auxiliary information for the suite */
	const int macParam, cryptKeySize, macBlockSize;
	const int flags;
	} CIPHERSUITE_INFO;

/* Handshake flags.  These are:

	HANDSHAKE_HASEXTENSIONS: Hello has TLS extensions.

	HANDSHAKE_ISGOOGLE: Peer is Google Chrome, used to work around Chrome 
						bugs.

	HANDSHAKE_NEEDEMSRESPONSE: Server needs to respond to EMS.

	HANDSHAKE_NEEDETMRESPONSE: Server needs to respond to encThenMAC.

	HANDSHAKE_NEEDRENEGRESPONSE: Server needs to respond to renegotiation 
								 indication.

	HANDSHAKE_NEEDSNIRESPONSE: Server needs to respond to SNI.

	HANDSHAKE_NEEDTLS12LTSRESPONSE: Server needs to respond to TLS-LTS.

	HANDSHAKE_RETRIEDCLIENTHELLO: Whether client hello retry done */

#define HANDSHAKE_FLAG_NONE				0x00	/* No flag value */
#define HANDSHAKE_FLAG_HASEXTENSIONS	0x01	/* Hello has extensions */
#define HANDSHAKE_FLAG_NEEDSNIRESPONSE	0x02	/* Response to SNI needed */
#define HANDSHAKE_FLAG_NEEDRENEGRESPONSE 0x04	/* Response to reneg.needed */
#define HANDSHAKE_FLAG_NEEDETMRESPONSE	0x08	/* Response to EtM needed */
#define HANDSHAKE_FLAG_NEEDEMSRESPONSE	0x10	/* Response to EMS needed */
#define HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE 0x20/* Response to TLS-LTS needed */
#ifdef USE_TLS13
#define HANDSHAKE_FLAG_RETRIEDCLIENTHELLO 0x40	/* Client Hello Retry needed */
#define HANDSHAKE_FLAG_ISGOOGLE			0x80	/* Peer is Google Chrome */
#define HANDSHAKE_FLAG_MAX				0xFF	/* Maximum possible flag value */
#else
#define HANDSHAKE_FLAG_MAX				0x3F	/* Maximum possible flag value */
#endif /* USE_TLS13 */

/* The maximum size of the list of cipher suites, used to allocate storage 
   and for bounds checking, see session/tls_suites.c for the contents of the 
   suite lists */

#define NO_SUITES_STD		16		/* DH + PSK */
#if defined( USE_ECDH ) 
  #define NO_SUITES_ECDH	8 
#else
  #define NO_SUITES_ECDH	0 
#endif /* USE_ECDH */
#if defined( USE_GCM ) 
  #define NO_SUITES_GCM		8 
#else
  #define NO_SUITES_GCM		0 
#endif /* USE_GCM */
#if defined( USE_CHACHA20 )
  #define NO_SUITES_CHACHA20 8 
#else
  #define NO_SUITES_CHACHA20 0 
#endif /* USE_CHACHA20 */
#ifdef USE_RSA_SUITES
  #define NO_SUITES_RSA		8 
#else
  #define NO_SUITES_RSA		0 
#endif /* USE_RSA_SUITES */

#define MAX_NO_SUITES		( NO_SUITES_STD + NO_SUITES_ECDH + \
							  NO_SUITES_GCM + NO_SUITES_CHACHA20 + \
							  NO_SUITES_RSA )

/* Check for the presence of a TLS signalling suite */

#define isSignallingSuite( suite ) \
		( ( suite ) == TLS_FALLBACK_SCSV || \
		  ( suite ) == TLS_EMPTY_RENEGOTIATION_INFO_SCSV )

/* Check for an RFC 8701 / GREASE garbage value.  This is, by design, an 
   invalid value for whatever it's being used for but one that we have to 
   accept because Google Chrome inserts them wherever it can in the Client
   Hello.  GREASE values always have the high byte match the low byte with 
   the low nibbles of each byte being 0x0A, so 0x0A0A, 0x1A1A, ..., 0xFAFA */

#define checkGREASE( value ) \
		( ( ( value ) >> 8 ) == ( ( value ) & 0xFF ) && \
		  ( ( value ) & 0x0F0F ) == 0x0A0A ) 

/* If we're configured to only use Suite B algorithms, we override the
   algoAvailable() check to report that only Suite B algorithms are
   available */

#ifdef CONFIG_SUITEB

#if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
  #pragma message( "  Building with Suite B algorithms only." )
#endif /* Notify Suite B use */

#define algoAvailable( algo ) \
		( ( ( algo ) == CRYPT_ALGO_AES || ( algo ) == CRYPT_ALGO_ECDSA || \
			( algo ) == CRYPT_ALGO_ECDH || ( algo ) == CRYPT_ALGO_SHA2 || \
			( algo ) == CRYPT_ALGO_HMAC_SHA2 ) ? TRUE : FALSE )

  /* Special configuration defines to enable nonstandard behaviour for 
     Suite B tests */
  #ifdef CONFIG_SUITEB_TESTS 
	typedef enum {
		SUITEB_TEST_NONE,			/* No special test behaviour */

		/* RFC 5430bis tests */
		SUITEB_TEST_CLIINVALIDCURVE,/* Client sends non-Suite B curve */
		SUITEB_TEST_SVRINVALIDCURVE,/* Server sends non-Suite B curve */
		SUITEB_TEST_BOTHCURVES,		/* Client must send P256 and P384 as supp.curves */
		SUITEB_TEST_BOTHSIGALGOS,	/* Client must send SHA256 and SHA384 as sig.algos */

		SUITEB_TEST_LAST
		} SUITEB_TEST_VALUE;

	extern SUITEB_TEST_VALUE suiteBTestValue;
	extern BOOLEAN suiteBTestClientCert;
  #endif /* CONFIG_SUITEB_TESTS */
#endif /* Suite B algorithms only */

/* The following macro can be used to enable dumping of PDUs to disk.  As a
   safeguard, this only works in the Win32 debug version to prevent it from
   being accidentally enabled in any release version */

#if defined( __WIN32__ ) && defined( USE_ERRMSGS ) && !defined( NDEBUG )
  #define DEBUG_DUMP_TLS( buffer1, buffer1size, buffer2, buffer2size ) \
		  debugDumpTLS( sessionInfoPtr, buffer1, buffer1size, buffer2, buffer2size )

  STDC_NONNULL_ARG( ( 1, 2 ) ) \
  void debugDumpTLS( const SESSION_INFO *sessionInfoPtr,
					 IN_BUFFER( buffer1size ) const void *buffer1, 
					 IN_LENGTH_SHORT const int buffer1size,
					 IN_BUFFER_OPT( buffer2size ) const void *buffer2, 
					 IN_LENGTH_SHORT_Z const int buffer2size );
#else
  #define DEBUG_DUMP_TLS( buffer1, buffer1size, buffer2, buffer2size )
#endif /* Win32 debug */

/****************************************************************************
*																			*
*								TLS Structures								*
*																			*
****************************************************************************/

/* TLS handshake state information.  This is passed around various 
   subfunctions that handle individual parts of the handshake */

struct TH;

typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
	int ( *TLS_HANDSHAKE_FUNCTION )( INOUT_PTR SESSION_INFO *sessionInfoPtr,
									 INOUT_PTR struct TH *handshakeInfo );

typedef struct TH {
	/* Client and server dual-hash/hash contexts */
	CRYPT_CONTEXT md5context, sha1context, sha2context;
#ifdef CONFIG_SUITEB
	CRYPT_CONTEXT sha384context;
#endif /* CONFIG_SUITEB */

	/* Client and server nonces, session ID, and hashed SNI (which is used
	   alongside the session ID for scoreboard lookup) */
	BUFFER_FIXED( TLS_NONCE_SIZE ) \
	BYTE clientNonce[ TLS_NONCE_SIZE + 8 ];
	BUFFER_FIXED( TLS_NONCE_SIZE ) \
	BYTE serverNonce[ TLS_NONCE_SIZE + 8 ];
	BUFFER( MAX_SESSIONID_SIZE, sessionIDlength ) \
	BYTE sessionID[ MAX_SESSIONID_SIZE + 8 ];
	int sessionIDlength;
	BYTE hashedSNI[ KEYID_SIZE + 8 ];
	BOOLEAN hashedSNIpresent;

	/* Client/server hello hash, the hash of the Client Hello and Server 
	   Hello, and session hash, the hash of all messages from Client Hello 
	   to Client Keyex (TLS 1.2) or the last message before the current one
	   (TLS 1.3).
	   
	   We use two different strategies for the hashing, for the Client/
	   Server Hello hash, which are just the first two messages and both 
	   available at the same time, we use direct hash access via 
	   getHashParameters()/hashFunction().  For the session hash, which is
	   an ongoing hash of all messages exchanged, we use a hash context and,
	   for the case of TLS 1.3 which keeps peeling off copies of it to 
	   inject into the endless PRF churn that it applies, clone it and copy
	   the hash value from the cloned copy.  This means that the first two
	   messages, namely the Client and Server Hello, are hashed twice, once 
	   via direct access to get the hello hash and once via the context as 
	   part of the ongoing session hash.

	   In addition the sessionHashContext below isn't what's used for the
	   ongoing hash operation because, depending on the TLS classic version 
	   in use we could be using MD5+SHA1 or SHA2, so the way the hashing is 
	   done is to run as many of the different algorithms as required in 
	   parallel and then clone the one being used into sessionHashContext 
	   via session/tls_sign.c:createSessionHash() when it's time to create 
	   the handshake signature in session/tls_sign.c:createCertVerify() and
	   checkCertVerify().

	   For TLS 1.3 which does things differently we don't clone the ongoing 
	   hash state into sessionHashContext but instead use it to hash some 
	   magic values and the current transcript hash to get the hash value
	   that's then signed.

	   In theory we could just use the hash context and clone-and-copy
	   strategy in all cases, but since TLS 1.2 and TLS 1.3 handle things
	   somewhat differently the simpler strategy is to use direct access for
	   the hello hash, the context for the session hash, and then handle TLS
	   1.3's PRF churn separately as a special case of the latter */
	BUFFER( 16, CRYPT_MAX_HASHSIZE ) \
	BYTE helloHash[ CRYPT_MAX_HASHSIZE + 8 ];
	CRYPT_CONTEXT sessionHashContext;
	BUFFER( 16, CRYPT_MAX_HASHSIZE ) \
	BYTE sessionHash[ CRYPT_MAX_HASHSIZE + 8 ];
	int helloHashSize, sessionHashSize;

	/* Premaster/master secret */
	BUFFER( CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE, premasterSecretSize ) \
	BYTE premasterSecret[ CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE + 8 ];
	int premasterSecretSize;

#ifdef USE_TLS13
	/* For TLS 1.3, which does its keyex via values stuffed into extensions 
	   in the client and server hello, we need to store the keyex data for 
	   later when it's actually used.  Since this can get rather large, we 
	   overload the use of the premaster secret storage, which isn't used at
	   this point */
	int tls13KeyexGroup;		/* TLS_GROUP_xxx value for keyex data */
	#define tls13KeyexValue			premasterSecret
	#define tls13KeyexValueLen		premasterSecretSize

	/* TLS 1.3 also creates a huge explosion of secret data that needs to be
	   passed around different functions, for which we again reuse the
	   premaster secret storage */
	#define tls13MasterSecret		premasterSecret
	#define tls13MasterSecretLen	CRYPT_MAX_HASHSIZE
	#define tls13ClientSecret		premasterSecret + CRYPT_MAX_HASHSIZE
	#define tls13ClientSecretLen	CRYPT_MAX_HASHSIZE
	#define tls13ServerSecret		premasterSecret + ( 2 * CRYPT_MAX_HASHSIZE )
	#define tls13ServerSecretLen	CRYPT_MAX_HASHSIZE

	/* There's even more stuff that needs to be stored for TLS 1.3, for which
	   we reuse further existing storage locations.  This is safe because the
	   session hash is only created and used after the certificate verify has
	   been completed */
	#define tls13CertContext		sessionHash
	#define tls13CertContextLen		sessionHashSize

	/* Since we don't know at the time that we're reading the cipher suites
	   whether we'll be doing TLS 1.3 or not, we have to bookmark the 
	   required TLS 1.3 suite in case we later need to use it */
	const void *tls13SuiteInfoPtr;/* TLS 1.3 suite information */

	/* When a TLS 1.3 client guess incorrectly at what the server wants, it 
	   needs to re-send the Client Hello with a different guess.  To deal 
	   with this we need to re-hash the original Client Hello and Server 
	   Hello along with the re-sent second Client Hello and Server Hello to
	   get the hello hash.  To do this we need to record the sizes of the 
	   first Client and Server Hello */
	int originalClientHelloLength, originalServerHelloLength;
#endif /* USE_TLS13 */

	/* Encryption/security information.  Since for TLS 1.3 we have to guess 
	   which keyex mechanism the other side is using we need two (EC)DH
	   contexts on the client, one for each guessed algorithm.  The 
	   encryption algorithm (cryptAlgo) and integrity algorithm 
	   (integrityAlgo) are stored with the session information, although the 
	   optional integrity-algorithm parameters are stored here */
	CRYPT_CONTEXT dhContext;	/* (EC)DH context for (EC)DHE */
#ifdef USE_TLS13
	CRYPT_CONTEXT dhContextAlt;	/* Alternative ECDH context for TLS 1.3 */
#endif /* USE_TLS13 */
	int cipherSuite;			/* Selected cipher suite */
	CRYPT_ALGO_TYPE keyexAlgo, authAlgo;/* Selected cipher suite algos */
	int integrityAlgoParam;		/* Optional param.for integrity algo */
	CRYPT_ALGO_TYPE keyexSigHashAlgo;/* Algo.for keyex authentication */
	int keyexSigHashAlgoParam;	/* Optional params.for keyex hash */
	int cryptKeysize;			/* Size of session key */

	/* Other information */
	int clientOfferedVersion;	/* Prot.vers.originally offered by client */
	int originalVersion;		/* Original version set by the user before
								   it was modified based on what the peer
								   requested */
	int flags;					/* HANDSHAKE_FLAG_x flags */
	int failAlertType;			/* Alert type to send on failure */

	/* ECC-related information.  Since ECC algorithms have a huge pile of
	   parameters we need to parse any extensions that the client sends in 
	   order to locate any additional information required to handle them.  
	   In the worst case these can retroactively modify the already-
	   negotiated cipher suites, disabling the use of ECC algorithms after 
	   they were agreed on via cipher suites.  To handle this we remember
	   both the preferred mainstream suite and a pointer to the preferred
	   ECC suite in 'eccSuiteInfoPtr', if it later turns out that the use
	   of ECC is OK we reset the crypto parameters using the save ECC suite
	   pointer.
	   
	   If the use of ECC isn't retroactively disabled then the eccCurveID 
	   and sendECCPointExtn values indicate which curve to use and whether 
	   the server needs to respond with a point-extension indicator */
	BOOLEAN disableECC;			/* Extn.disabled use of ECC suites */
	CRYPT_ECCCURVE_TYPE eccCurveID;	/* cryptlib ID of ECC curve to use */
	BOOLEAN sendECCPointExtn;	/* Whether svr.has to respond with ECC point ext.*/
	const void *eccSuiteInfoPtr;/* ECC suite information */

	/* Another side-effect of the post-modification of suites via 
	   information in extensions is that depending on what the client 
	   advertises we may have to fall back through successive alternatives 
	   while parsing the suites.  Typical behaviour for a standard client
	   hello is to record the main suite and bookmark ECC and TLS 1.3
	   alternatives, however if there's no main suite present that what's
	   recorded is the ECC suite, and if that's not present the TLS 1.3
	   suite.  In order to figure out what's what, we need to record whether
	   the fallback to alternative suites has been triggered */
	TLS_FALLBACK_TYPE fallbackType;

	/* The packet data stream.  Since TLS can encapsulate multiple handshake
	   packets within a single TLS packet, the stream has to be persistent
	   across the different handshake functions to allow the continuation of
	   packets */
	STREAM stream;				/* Packet data stream */

	/* Function pointers to handshaking functions.  These are set up as 
	   required depending on whether the session is client or server */
	FNPTR beginHandshake, exchangeKeys;
	} TLS_HANDSHAKE_INFO;

/****************************************************************************
*																			*
*								TLS Functions								*
*																			*
****************************************************************************/

/* Prototypes for functions in tls.c */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionTLS( IN_PTR const SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckTLSHandshakeInfo( IN_PTR \
										const TLS_HANDSHAKE_INFO *handshakeInfo );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
int readUint24( INOUT_PTR STREAM *stream );
STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint24( INOUT_PTR STREAM *stream, IN_LENGTH_Z const int length );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int readEcdhValue( INOUT_PTR STREAM *stream,
				   OUT_BUFFER( valueMaxLen, *valueLen ) void *value,
				   IN_LENGTH_SHORT_MIN( 64 ) const int valueMaxLen,
				   OUT_LENGTH_BOUNDED_Z( valueMaxLen ) int *valueLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readTLSCertChain( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT_PTR STREAM *stream,
					  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertChain, 
					  IN_BOOL const BOOLEAN isServer );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeTLSCertChain( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					   INOUT_PTR STREAM *stream );

/* Prototypes for functions in tls_cert.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int checkHostNameTLS( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
					  INOUT_BUFFER_FIXED( serverNameLength ) void *serverName,
					  IN_LENGTH_DNS const int serverNameLength,
					  OUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkTLSCertificateInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr );

/* Prototypes for functions in tls_crypt.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int encryptData( const SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER( dataMaxLength, *dataLength ) \
					BYTE *data, 
				 IN_DATALENGTH const int dataMaxLength,
				 OUT_DATALENGTH_Z int *dataLength,
				 IN_DATALENGTH const int payloadLength );
				 /* This one's a bit tricky, the input is 
				    { data, payloadLength } which is padded (if necessary) 
					and the padded length returned in '*dataLength' */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int decryptData( SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER_FIXED( dataLength ) \
					BYTE *data, 
				 IN_DATALENGTH const int dataLength, 
				 OUT_DATALENGTH_Z int *processedDataLength );
				/* This one's also tricky, the entire data block will be 
				   processed but only 'processedDataLength' bytes of result 
				   are valid output */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				  INOUT_BUFFER( dataMaxLength, *dataLength ) void *data,
				  IN_DATALENGTH const int dataMaxLength, 
				  OUT_DATALENGTH_Z int *dataLength,
				  IN_DATALENGTH const int payloadLength, 
				  IN_BYTE const int type );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) const void *data, 
				 IN_DATALENGTH const int dataLength, 
				 IN_DATALENGTH_Z const int payloadLength, 
				 IN_BYTE const int type, 
				 IN_BOOL const BOOLEAN noReportError );
#ifdef USE_GCM
CHECK_RETVAL \
int macDataTLSGCM( IN_HANDLE const CRYPT_CONTEXT iCryptContext, 
				   IN_INT_Z const long seqNo, 
				   IN_RANGE( TLS_MINOR_VERSION_TLS, \
							 TLS_MINOR_VERSION_TLS13 ) const int version,
				   IN_LENGTH_Z const int payloadLength, 
				   IN_BYTE const int type );
#endif /* USE_GCM */
#ifdef USE_CHACHA20
CHECK_RETVAL \
int initCryptBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_BOOL const BOOLEAN isRead );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLSBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_BUFFER( dataMaxLength, *dataLength ) \
								void *data, 
						   IN_DATALENGTH const int dataMaxLength, 
						   OUT_DATALENGTH_Z int *dataLength,
						   IN_DATALENGTH const int payloadLength, 
						   IN_BYTE const int type );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLSBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  IN_BUFFER( dataLength ) const void *data, 
						  IN_DATALENGTH const int dataLength, 
						  IN_DATALENGTH_Z const int payloadLength, 
						  IN_BYTE const int type );
#endif /* USE_CHACHA20 */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int hashHSPacketRead( IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT_PTR STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int hashHSPacketWrite( IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo, 
					   INOUT_PTR STREAM *stream,
					   IN_DATALENGTH_Z const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) ) \
int completeTLSHashedMAC( IN_HANDLE const CRYPT_CONTEXT md5context,
						  IN_HANDLE const CRYPT_CONTEXT sha1context, 
						  OUT_BUFFER( hashValuesMaxLen, *hashValuesLen ) \
								BYTE *hashValues, 
						  IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
						  OUT_LENGTH_BOUNDED_Z( hashValuesMaxLen ) \
								int *hashValuesLen,
						  IN_BUFFER( labelLength ) const char *label, 
						  IN_RANGE( 1, 64 ) const int labelLength, 
						  IN_BUFFER( masterSecretLen ) const BYTE *masterSecret, 
						  IN_LENGTH_SHORT const int masterSecretLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4, 5, 7 ) ) \
int completeTLS12HashedMAC( IN_HANDLE const CRYPT_CONTEXT sha2context,
							OUT_BUFFER( hashValuesMaxLen, *hashValuesLen ) \
								BYTE *hashValues, 
							IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
							OUT_LENGTH_BOUNDED_Z( hashValuesMaxLen ) \
								int *hashValuesLen,
							IN_BUFFER( labelLength ) const char *label, 
							IN_RANGE( 1, 64 ) const int labelLength, 
							IN_BUFFER( masterSecretLen ) const BYTE *masterSecret, 
							IN_LENGTH_SHORT const int masterSecretLen,
							IN_BOOL const BOOLEAN fullSizeMAC );

/* Prototypes for functions in tls_ext.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readExtensions( INOUT_PTR STREAM *stream, 
					INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					OUT_ENUM_OPT( TLSHELLO_ACTION ) \
							TLSHELLO_ACTION_TYPE *actionType,
					IN_LENGTH_SHORT const int length );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeClientExtensions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeServerExtensions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );

/* Prototypes for functions in tls_hello.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int processHelloTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT_PTR STREAM *stream, 
					 OUT_ENUM_OPT( TLSHELLO_ACTION ) \
							TLSHELLO_ACTION_TYPE *actionType,
					 IN_BOOL const BOOLEAN isServer );

/* Prototypes for functions in tls_hscomplete.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int completeHandshakeTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_BOOL const BOOLEAN isClient,
						  IN_BOOL const BOOLEAN isResumedSession );

/* Prototypes for functions in tls_keymgmt.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void destroySecurityContextsTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initHandshakeCryptInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void destroyHandshakeCryptInfo( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initSecurityContextsTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int cloneHashContext( IN_HANDLE const CRYPT_CONTEXT hashContext,
					  OUT_HANDLE_OPT CRYPT_CONTEXT *clonedHashContext );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createDHcontextTLS( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
						IN_ALGO const CRYPT_ALGO_TYPE dhAlgo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initDHcontextTLS( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
					  IN_BUFFER_OPT( keyDataLength ) const void *keyData, 
					  IN_LENGTH_SHORT_Z const int keyDataLength,
					  IN_HANDLE_OPT const CRYPT_CONTEXT iServerKeyTemplate,
					  IN_ENUM_OPT( CRYPT_ECCCURVE ) \
							const CRYPT_ECCCURVE_TYPE eccCurve,
					  IN_BOOL const BOOLEAN isTLSLTS );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int completeTLSKeyex( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					  INOUT_PTR STREAM *stream, 
					  IN_BOOL const BOOLEAN isECC,
					  IN_BOOL const BOOLEAN isTLSLTS,
					  INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int createSharedPremasterSecret( OUT_BUFFER( premasterSecretMaxLength, \
											 *premasterSecretLength ) \
									void *premasterSecret, 
								 IN_LENGTH_SHORT_MIN( 16 ) \
									const int premasterSecretMaxLength, 
								 OUT_LENGTH_BOUNDED_Z( premasterSecretMaxLength ) \
									int *premasterSecretLength,
								 IN_BUFFER( sharedSecretLength ) \
									const void *sharedSecret, 
								 IN_LENGTH_TEXT const int sharedSecretLength,
								 IN_BUFFER_OPT( otherSecretLength ) \
									const void *otherSecret, 
								 IN_LENGTH_PKC_Z const int otherSecretLength,
								 IN_BOOL const BOOLEAN isEncodedValue );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int wrapPremasterSecret( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
						 IN_LENGTH_SHORT_MIN( 16 ) const int dataMaxLength, 
						 OUT_LENGTH_BOUNDED_Z( dataMaxLength ) \
							int *dataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int unwrapPremasterSecret( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   IN_BUFFER( dataLength ) const void *data, 
						   IN_LENGTH_SHORT_MIN( 16 ) const int dataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int initCryptoTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
				   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
				   OUT_BUFFER_FIXED( masterSecretSize ) void *masterSecret,
				   IN_LENGTH_SHORT_MIN( 16 ) const int masterSecretSize,
				   IN_BOOL const BOOLEAN isClient,
				   IN_BOOL const BOOLEAN isResumedSession );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int loadExplicitIV( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR STREAM *stream, 
					OUT_INT_SHORT_Z int *ivLength );
#ifdef USE_EAP
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int addDerivedKeydata( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					   IN_BUFFER( masterSecretSize ) void *masterSecret,
					   IN_LENGTH_SHORT_MIN( 16 ) const int masterSecretSize,
					   IN_ENUM( CRYPT_SUBPROTOCOL ) \
							const CRYPT_SUBPROTOCOL_TYPE type );
#endif /* USE_EAP */

/* Prototypes for functions in tls_rd.c */

#ifdef USE_ERRMSGS
CHECK_RETVAL_PTR_NONNULL \
const char *getTLSPacketName( IN_BYTE const int packetType );
CHECK_RETVAL_PTR_NONNULL \
const char *getTLSHSPacketName( IN_BYTE const int packetType );
#else
  #define getTLSPacketName( x )		"<Unknown>"
  #define getTLSHSPacketName( x )	"<Unknown>"
#endif /* USE_ERRMSGS */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processVersionInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						INOUT_PTR STREAM *stream, 
						OUT_OPT int *clientVersion,
						IN_BOOL const BOOLEAN generalCheckOnly );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkPacketHeaderTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR STREAM *stream, 
						  OUT_DATALENGTH_Z int *packetLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkHSPacketHeader( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR STREAM *stream, 
						 OUT_DATALENGTH_Z int *packetLength, 
						 IN_RANGE( TLS_HAND_FIRST, \
								   TLS_HAND_LAST ) const int packetType, 
						 IN_LENGTH_SHORT_Z const int minSize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int unwrapPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_BUFFER( dataMaxLength, \
								   *dataLength ) void *data, 
					 IN_DATALENGTH const int dataMaxLength, 
					 OUT_DATALENGTH_Z int *dataLength,
					 IN_RANGE( TLS_HAND_FIRST, \
							   TLS_HAND_LAST ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int readHSPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR_OPT TLS_HANDSHAKE_INFO *handshakeInfo, 
					 OUT_DATALENGTH_Z int *packetLength, 
					 IN_RANGE( TLS_MSG_FIRST, \
							   TLS_MSG_LAST_SPECIAL ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int refreshHSStream( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );

/* Prototypes for functions in tls_sign.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCertWhitelist( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
						IN_BOOL const BOOLEAN isServer );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int createSessionHash( IN_PTR const SESSION_INFO *sessionInfoPtr,
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void destroySessionHash( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int createCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					  INOUT_PTR STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					 INOUT_PTR STREAM *stream, 
					 IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
						const int sigLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int createKeyexSignature( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  INOUT_PTR STREAM *stream, 
						  IN_BUFFER( keyDataLength ) const void *keyData, 
						  IN_LENGTH_SHORT const int keyDataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 7 ) ) \
int checkKeyexSignature( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 INOUT_PTR STREAM *stream, 
						 IN_BUFFER( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT const int keyDataLength,
						 IN_BOOL const BOOLEAN isECC,
						 INOUT_PTR ERROR_INFO *errorInfo );

/* Prototypes for functions in tls_suites.c */

#ifndef CONFIG_SUITEB

CHECK_RETVAL \
int getCipherSuiteInfo( OUT_PTR \
							const CIPHERSUITE_INFO ***cipherSuiteInfoPtrPtrPtr,
						OUT_INT_Z int *noSuiteEntries );
#else

#define getCipherSuiteInfo( infoPtr, noEntries, isServer ) \
		getSuiteBCipherSuiteInfo( infoPtr, noEntries, isServer, suiteBinfo )

CHECK_RETVAL \
int getSuiteBCipherSuiteInfo( OUT_PTR \
								const CIPHERSUITE_INFO ***cipherSuiteInfoPtrPtrPtr,
							  OUT_INT_Z int *noSuiteEntries,
							  IN_BOOL const BOOLEAN isServer,
							  IN_FLAGS_Z( TLS ) const int suiteBinfo );

#endif /* CONFIG_SUITEB */

/* Prototypes for functions in tls_svr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int convertSNISessionID( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER_FIXED( idBufferLength ) BYTE *idBuffer,
						 IN_LENGTH_FIXED( KEYID_SIZE ) const int idBufferLength );

/* Prototypes for functions in tls_wr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int wrapPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				   INOUT_PTR STREAM *stream, 
				   IN_LENGTH_Z const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sendPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				   INOUT_PTR STREAM *stream, 
				   IN_BOOL const BOOLEAN sendOnly );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int openPacketStreamTLS( OUT_PTR STREAM *stream, 
						 IN_PTR const SESSION_INFO *sessionInfoPtr, 
						 IN_DATALENGTH_OPT const int bufferSize, 
						 IN_RANGE( TLS_MSG_FIRST, \
								   TLS_MSG_LAST ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int continuePacketStreamTLS( INOUT_PTR STREAM *stream, 
							 IN_PTR const SESSION_INFO *sessionInfoPtr, 
							 IN_RANGE( TLS_HAND_FIRST, \
									   TLS_HAND_LAST ) const int packetType,
							 OUT_LENGTH_SHORT_Z int *packetOffset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completePacketStreamTLS( INOUT_PTR STREAM *stream, 
							 IN_LENGTH_Z const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int continueHSPacketStream( INOUT_PTR STREAM *stream, 
							IN_RANGE( TLS_HAND_FIRST, \
									  TLS_HAND_LAST ) const int packetType,
							OUT_LENGTH_SHORT_Z int *packetOffset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completeHSPacketStream( INOUT_PTR STREAM *stream, 
							IN_LENGTH const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				  IN_BUFFER( headerLength ) const void *header, 
				  IN_DATALENGTH const int headerLength,
				  OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void sendCloseAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 IN_BOOL const BOOLEAN alertReceived );
STDC_NONNULL_ARG( ( 1 ) ) \
void sendHandshakeFailAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 IN_RANGE( TLS_ALERT_FIRST, \
									   TLS_ALERT_LAST ) const int alertType );
#ifdef USE_TLS13

/* Prototypes for functions in tls13_crypt.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initCryptGCMTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					   IN_BOOL const BOOLEAN isRead );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createSessionHashTLS13( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						    IN_HANDLE const CRYPT_CONTEXT iHashContext,
							const BOOLEAN isServerVerify );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int createFinishedTLS13( OUT_BUFFER( finishedValueMaxLen, \
									 *finishedValueLen ) \
							void *finishedValue,
						 IN_LENGTH_SHORT_MIN( 20 ) \
							const int finishedValueMaxLen,
						 OUT_LENGTH_BOUNDED_SHORT_Z( finishedValueMaxLen ) \
							 int *finishedValueLen,
						 IN_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 IN_HANDLE const CRYPT_CONTEXT iHashContext,
						 IN_BOOL const BOOLEAN isServerFinished );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int loadHSKeysTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int loadAppdataKeysTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );

/* Prototypes for functions in tls13_hs.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void initProcessingTLS13( TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_BOOL const BOOLEAN isServer );

/* Prototypes for functions in tls13_keyex.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readKeyexTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					INOUT_PTR STREAM *stream, 
					IN_LENGTH_SHORT_Z const int extLength,
					OUT_BOOL BOOLEAN *extErrorInfoSet );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeKeyexTLS13( INOUT_PTR STREAM *stream,
					 const TLS_HANDSHAKE_INFO *handshakeInfo,
					 IN_BOOL const BOOLEAN isServer );

/* Prototypes for functions in tls_rd.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int unwrapPacketTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   INOUT_BUFFER( dataMaxLength, \
									 *dataLength ) void *data, 
					   IN_DATALENGTH const int dataMaxLength, 
					   OUT_DATALENGTH_Z int *dataLength,
					   OUT_RANGE( TLS_HAND_NONE, TLS_HAND_LAST ) \
							int *actualPacketType,
					   IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
							const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processAlertTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   IN_BUFFER( dataLength ) const void *data, 
					   IN_DATALENGTH const int dataLength,
					   OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo );

/* Prototypes for functions in tls_wr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int wrapPacketTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR STREAM *stream, 
					 IN_LENGTH_Z const int offset,
					 IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
						const int packetType );
#endif /* USE_TLS13 */

/* Prototypes for session mapping functions */

STDC_NONNULL_ARG( ( 1 ) ) \
void initTLSclientProcessing( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void initTLSserverProcessing( TLS_HANDSHAKE_INFO *handshakeInfo );

#endif /* USE_TLS */

#endif /* _TLS_DEFINED */
=======
/****************************************************************************
*																			*
*							TLS Definitions Header File						*
*						Copyright Peter Gutmann 1998-2021					*
*																			*
****************************************************************************/

#ifndef _TLS_DEFINED

#define _TLS_DEFINED

#if defined( INC_ALL )
  #include "scorebrd.h"
#else
  #include "session/scorebrd.h"
#endif /* _STREAM_DEFINED */

#ifdef USE_TLS

/****************************************************************************
*																			*
*								TLS Constants								*
*																			*
****************************************************************************/

/* Default TLS port */

#define TLS_PORT					443

/* TLS constants */

#define ID_SIZE						1	/* ID byte */
#define LENGTH_SIZE					3	/* 24 bits */
#define SEQNO_SIZE					8	/* 64 bits */
#define VERSIONINFO_SIZE			2	/* 0x03, 0x0n */
#define ALERTINFO_SIZE				2	/* level + description */
#define TLS_HEADER_SIZE				5	/* Type, version, length */
#define TLS_NONCE_SIZE				32	/* Size of client/svr nonce */
#define TLS_SECRET_SIZE				48	/* Size of premaster/master secret */
#define MD5MAC_SIZE					16	/* Size of MD5 proto-HMAC/dual hash */
#define SHA1MAC_SIZE				20	/* Size of SHA-1 proto-HMAC/dual hash */
#define SHA2MAC_SIZE				32	/* Size of SHA-2 HMAC hash */
#define GCMICV_SIZE					16	/* Size of GCM (and Poly1305) ICV */
#define GCM_SALT_SIZE				4	/* Size of implicit portion of 
										   TLS 1.2 GCM IV */
#define GCM_IV_SIZE					12	/* Overall size of GCM IV */
#define BERNSTEIN_IV_SIZE			12	/* Overall size of Bernstein suite IV */
#define TLS_HASHEDMAC_SIZE			12	/* Size of TLS PRF( MD5 + SHA1 ) */
#define SESSIONID_SIZE				16	/* Size of session ID */
#define MIN_SESSIONID_SIZE			4	/* Min.allowed session ID size */
#define MAX_SESSIONID_SIZE			32	/* Max.allowed session ID size */
#define MAX_KEYBLOCK_SIZE			( ( 64 + 32 + 16 ) * 2 )
										/* HMAC-SHA2 + AES-256 key + AES IV */
#ifdef USE_TLS13
  /* TLS 1.3's camouflage double-wrapping means that the minimum packet size 
     can be 3 bytes for an Alert packet, the two-byte payload followed by 
	 the single-byte type, see session/tls_rd.c:recoverPacketDataTLS13() for 
	 how this piece of cleverness works */
  #define MIN_PACKET_SIZE			3	/* Minimum TLS packet size */
#else
  #define MIN_PACKET_SIZE			4	/* Minimum TLS packet size */
#endif /* USE_TLS13 */
  /* TLS 1.3 has the same problem with maximum packet sizes, the maximum 
	 size is still 16384 bytes but now there's an invisible real-packet-type
	 byte appended to the data that's not actually there but is still 
	 present, so with TLS 1.3 MAX_PACKET_SIZE is actually 16385 even if only
	 16384 bytes of data are allowed.  To deal with this the code 
	 dynamically adds an extra byte to the allowed length if TLS 1.3 is in
	 effect */
#define MAX_PACKET_SIZE				16384	/* Maximum TLS packet size */
#define MAX_CIPHERSUITES			200	/* Max.allowed cipher suites */
#ifdef USE_DH1024
  #define TLS_DH_KEYSIZE			128	/* Size of server DH key */
#else
  #define TLS_DH_KEYSIZE			192	/* Size of server DH key */
#endif /* USE_DH1024 */

/* TLS packet/buffer size information.  The extra packet size is somewhat 
   large because it can contains the packet header (5 bytes), IV 
   (0/8/16 bytes), MAC/ICV (12/16/20 bytes), and cipher block padding (up to 
   256 bytes) */

#define EXTRA_PACKET_SIZE			512	

/* By default cryptlib uses DH key agreement, it's also possible to use ECDH 
   key agreement but we disable ECDH by default in order to stick to the
   safer DH.  To use ECDH key agreement in preference to DH, uncomment the 
   following */

/* #define PREFER_ECC //*/
#if ( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) ) && \
	defined( PREFER_ECC ) 
  #pragma message( "  Building with ECC preferred for TLS." )
#endif /* Notify preferred ECC use */
#if defined( PREFER_ECC ) && \
	!( defined( USE_ECDH ) && defined( USE_ECDSA ) )
  #error PREFER_ECC can only be used with ECDH and ECDSA enabled
#endif /* PREFER_ECC && !( USE_ECDH && USE_ECDSA ) */

/* TLS protocol-specific flags that augment the general session flags:

	FLAG_ALERTSENT: Whether we've already sent a close-alert.  Keeping track 
		of this is necessary because we're required to send a close alert 
		when shutting down to prevent a truncation attack, however lower-
		level code may have already sent an alert so we have to remember not 
		to send it twice.

	FLAG_BERNSTEIN: Uses the Bernstein protocol suite instead of the usual 
		CBC.  This is an AEAD exactly like GCM, but the IETF managed to make 
		it incompatible with the standard AEAD use so it needs custom 
		handling.

	FLAG_DISABLE_CERTVERIFY: Disable checking of the server certificate 
	FLAG_DISABLE_NAMEVERIFY: and/or host name.  By default we check both of
		these, but because of all of the problems surrounding certificates 
		we allow the checking to be disabled.

	FLAG_CHECKREHANDSHAKE: The header-read got a handshake packet instead of 
		a data packet, when the body-read decrypts the payload it should 
		check for a rehandshake request in the payload.

	FLAG_CLIAUTHSKIPPED: The client saw an auth-request from the server and 
		responded with a no-certificates alert, if we later get a close 
		alert from the server then we provide additional error information 
		indicating that this may be due to the lack of a client certificate.

	FLAG_EMS: Use extended Master Secret to protect handshake messages.

	FLAG_ENCTHENMAC: Use encrypt-then-MAC rather than the standard 
		MAC-then-encrypt.

	FLAG_GCM: The encryption used is GCM and not the usual CBC, which 
		unifies encryption and MACing into a single operation.
	
	FLAG_MANUAL_CERTCHECK: Interrupt the handshake (returning 
		CRYPT_ERROR_RESOURCE) to allow the caller to check the peer's 
		cerificate.

	FLAG_RESUMED: TLS session is resumed.

	FLAG_SUITEB_128: Enforce Suite B semantics on top of the standard TLS 
	FLAG_SUITEB_256: 1.2 + ECC + AES-GCM ones.  _128 = P256 + P384, 
		_256 = P384 only.

	FLAG_TLS12LTS: TLS 1.2 LTS session with enhanced crypto protection */

#define TLS_PFLAG_NONE				0x0000	/* No protocol-specific flags */
#define TLS_PFLAG_ALERTSENT			0x0001	/* Close alert sent */
#define TLS_PFLAG_CLIAUTHSKIPPED	0x0002	/* Client auth-req.skipped */
#define TLS_PFLAG_GCM				0x0004	/* Encryption uses GCM, not CBC */
#define TLS_PFLAG_BERNSTEIN			0x0008	/* Encryption uses Bernstein suite */
#define TLS_PFLAG_SUITEB_128		0x0010	/* Enforce Suite B 128-bit semantics */
#define TLS_PFLAG_SUITEB_256		0x0020	/* Enforce Suite B 256-bit semantics */
#define TLS_PFLAG_CHECKREHANDSHAKE	0x0040	/* Check decrypted pkt.for rehandshake */
#define TLS_PFLAG_MANUAL_CERTCHECK	0x0080	/* Interrupt handshake for cert.check */
#define TLS_PFLAG_DISABLE_NAMEVERIFY 0x0100	/* Disable host name verification */
#define TLS_PFLAG_DISABLE_CERTVERIFY 0x0200	/* Disable certificate verification */
#define TLS_PFLAG_ENCTHENMAC		0x0400	/* Use encrypt-then-MAC */
#define TLS_PFLAG_EMS				0x0800	/* Use extended Master Secret */
#define TLS_PFLAG_TLS12LTS			0x1000	/* Use TLS 1.2 LTS profile */
#define TLS_PFLAG_SERVER_SNI		0x2000	/* Apply server key switching for SNI */
#define TLS_PFLAG_RESUMED_SESSION	0x4000	/* Session is resumed */
#define TLS_PFLAG_MAX				0x7FFF	/* Maximum possible flag value */

/* Some of the flags above denote extended TLS facilities that need to be
   preserved across session resumptions.  The following value defines the 
   flags that need to be preserved across resumes */

#define TLS_RESUMEDSESSION_FLAGS	( TLS_PFLAG_EMS | TLS_PFLAG_ENCTHENMAC | \
									  TLS_PFLAG_TLS12LTS )

/* Symbolic defines for static analysis checking */

#define TLS_FLAG_NONE				TLS_PFLAG_NONE
#define TLS_FLAG_MAX				TLS_PFLAG_MAX

/* Suite B consists of two subclasses, the 128-bit security level (AES-128 
   with P256 and SHA2-256) and the 192-bit security level (AES-256 with P384 
   and SHA2-384), in order to identify generic use of Suite B we provide a
   pseudo-value that combines the 128-bit and 192-bit subclasses */

#define TLS_PFLAG_SUITEB			( TLS_PFLAG_SUITEB_128 | \
									  TLS_PFLAG_SUITEB_256 )

/* The TLS minimmum version number is encoded as a CRYPT_TLSOPTION_MINVER_xxx
   value, the following mask allows the version to be extracted from the TLS
   option value */

#define TLS_MINVER_MASK				( CRYPT_TLSOPTION_MINVER_SSLV3 | \
									  CRYPT_TLSOPTION_MINVER_TLS10 | \
									  CRYPT_TLSOPTION_MINVER_TLS11 | \
									  CRYPT_TLSOPTION_MINVER_TLS12 | \
									  CRYPT_TLSOPTION_MINVER_TLS13 )

/* TLS message types */

#define TLS_MSG_NONE				0
#define TLS_MSG_CHANGE_CIPHER_SPEC	20
#define TLS_MSG_ALERT				21
#define TLS_MSG_HANDSHAKE			22
#define TLS_MSG_APPLICATION_DATA	23

#define TLS_MSG_FIRST				TLS_MSG_CHANGE_CIPHER_SPEC
#define TLS_MSG_LAST				TLS_MSG_APPLICATION_DATA

/* Special expected packet-type values that are passed to readHSPacketTLS() 
   to handle situations where special-case handling is required for read
   packets:

	TLS_MSG_FIRST_HANDSHAKE: The first handshake packet from the client or 
		server is treated specially in that the version number information 
		is taken from this packet.
		
	TLS_MSG_FIRST_ENCRHANDSHAKE: The attempt to read the first encrypted 
		handshake packet may be met with a TCP close from the peer if it 
		handles errors badly, in which case we provide a special-case error 
		message that indicates more than just "connection closed" 
		
	TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE: TLS 1.3 stuffs encrypted handshake
		messages inside application-data packets so alongside the
		TLS_MSG_FIRST_ENCRHANDSHAKE semantics this also looks for
		application-data rather than handshake packets.
		
	TLS_MSG_TLS13_HELLORETRY: Some TLS 1.3 implementations send a bogus
		Change Cipherspec between the two Client Hellos (see the comment in
		session/tls13_hs.c:processHelloRetry()) so alongside the expected 
		TLS_MSG_HANDSHAKE this also allows an unexpected  
		TLS_MSG_CHANGE_CIPHER_SPEC */

#define TLS_MSG_FIRST_HANDSHAKE		0xFC
#define TLS_MSG_FIRST_ENCRHANDSHAKE	0xFD
#define TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE	0xFE
#define TLS_MSG_TLS13_HELLORETRY	0xFF
#define TLS_MSG_LAST_SPECIAL		TLS_MSG_TLS13_HELLORETRY
#define TLS_MSG_V2HANDSHAKE			0x80

/* TLS handshake message subtypes */

#define TLS_HAND_NONE				0
#define TLS_HAND_CLIENT_HELLO		1
#define TLS_HAND_SERVER_HELLO		2
#define TLS_HAND_NEW_SESSION_TICKET	4
#define TLS_HAND_END_OF_EARLY_DATA	5
#define TLS_HAND_ENCRYPTED_EXTENSIONS 8
#define TLS_HAND_CERTIFICATE		11
#define TLS_HAND_SERVER_KEYEXCHANGE	12
#define TLS_HAND_SERVER_CERTREQUEST	13
#define TLS_HAND_SERVER_HELLODONE	14
#define TLS_HAND_CERTVERIFY			15
#define TLS_HAND_CLIENT_KEYEXCHANGE	16
#define TLS_HAND_FINISHED			20
#define TLS_HAND_SUPPLEMENTAL_DATA	23
#define TLS_HAND_KEY_UPDATE			24

#define TLS_HAND_FIRST				TLS_HAND_CLIENT_HELLO
#define TLS_HAND_LAST				TLS_HAND_KEY_UPDATE

/* TLS alert levels and types, from
   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6 */

#define TLS_ALERTLEVEL_WARNING				1
#define TLS_ALERTLEVEL_FATAL				2

#define TLS_ALERT_CLOSE_NOTIFY				0
#define TLS_ALERT_UNEXPECTED_MESSAGE		10
#define TLS_ALERT_BAD_RECORD_MAC			20
#define TLS_ALERT_DECRYPTION_FAILED			21
#define TLS_ALERT_RECORD_OVERFLOW			22
#define TLS_ALERT_DECOMPRESSION_FAILURE		30
#define TLS_ALERT_HANDSHAKE_FAILURE			40
#define TLS_ALERT_NO_CERTIFICATE			41
#define TLS_ALERT_BAD_CERTIFICATE			42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE	43
#define TLS_ALERT_CERTIFICATE_REVOKED		44
#define TLS_ALERT_CERTIFICATE_EXPIRED		45
#define TLS_ALERT_CERTIFICATE_UNKNOWN		46
#define TLS_ALERT_ILLEGAL_PARAMETER			47
#define TLS_ALERT_UNKNOWN_CA				48
#define TLS_ALERT_ACCESS_DENIED				49
#define TLS_ALERT_DECODE_ERROR				50
#define TLS_ALERT_DECRYPT_ERROR				51
#define TLS_ALERT_TOO_MANY_CIDS				52
#define TLS_ALERT_EXPORT_RESTRICTION		60
#define TLS_ALERT_PROTOCOL_VERSION			70
#define TLS_ALERT_INSUFFICIENT_SECURITY		71
#define TLS_ALERT_INTERNAL_ERROR			80
#define TLS_ALERT_INAPPROPRIATE_FALLBACK	86
#define TLS_ALERT_USER_CANCELLED			90
#define TLS_ALERT_NO_RENEGOTIATION			100
#define TLS_ALERT_MISSING_EXTENSION			109
#define TLS_ALERT_UNSUPPORTED_EXTENSION		110
#define TLS_ALERT_CERTIFICATE_UNOBTAINABLE	111
#define TLS_ALERT_UNRECOGNIZED_NAME			112
#define TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE 113
#define TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE 114
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY		115
#define TLS_ALERT_CERTIFICATE_REQUIRED		116
#define TLS_ALERT_NO_APPLICATION_PROTOCOL	120

#define TLS_ALERT_FIRST						TLS_ALERT_CLOSE_NOTIFY
#define TLS_ALERT_LAST						TLS_ALERT_UNKNOWN_PSK_IDENTITY

/* TLS supplemental data subtypes */

#define TLS_SUPPDATA_USERMAPPING			0

/* TLS cipher suites, from
   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4 */

typedef enum {
	/* SSLv3 cipher suites (0-10) */
	SSL_NULL_WITH_NULL, SSL_RSA_WITH_NULL_MD5, SSL_RSA_WITH_NULL_SHA,
	SSL_RSA_EXPORT_WITH_RC4_40_MD5, SSL_RSA_WITH_RC4_128_MD5, 
	SSL_RSA_WITH_RC4_128_SHA, SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	SSL_RSA_WITH_IDEA_CBC_SHA, SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSL_RSA_WITH_DES_CBC_SHA,
		/* First valid suite if RSA + 3DES enabled */
	SSL_RSA_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) DH cipher suites (11-22) */
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_DSS_WITH_DES_CBC_SHA,
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_RSA_WITH_DES_CBC_SHA, TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DHE_DSS_WITH_DES_CBC_SHA,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_RSA_WITH_DES_CBC_SHA,
		/* First valid suite if RSA disabled, 3DES enabled */
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) anon-DH cipher suites (23-27) */
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, TLS_DH_anon_WITH_RC4_128_MD5,
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_anon_WITH_DES_CBC_SHA,
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) reserved cipher suites (28-29, used for Fortezza in
	   SSLv3) */
	TLS_reserved_1, TLS_reserved_2,

	/* TLS with Kerberos (RFC 2712) suites (30-43) */
	TLS_KRB5_WITH_DES_CBC_SHA, TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
	TLS_KRB5_WITH_RC4_128_SHA, TLS_KRB5_WITH_IDEA_CBC_SHA,
	TLS_KRB5_WITH_DES_CBC_MD5, TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
	TLS_KRB5_WITH_RC4_128_MD5, TLS_KRB5_WITH_IDEA_CBC_MD5,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA, TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, TLS_KRB5_EXPORT_WITH_RC4_40_MD5,

	/* Formerly reserved (44-46), later assigned to PSK-with-NULL suites 
	   (RFC 4785) */
	TLS_PSK_WITH_NULL_SHA, TLS_DHE_PSK_WITH_NULL_SHA, 
	TLS_RSA_PSK_WITH_NULL_SHA,

	/* TLS 1.1 (RFC 4346) cipher suites (47-58) */
	TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DH_DSS_WITH_AES_128_CBC_SHA,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
		/* First valid suite if RSA + 3DES disabled */
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DH_anon_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA, TLS_DH_DSS_WITH_AES_256_CBC_SHA,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DH_anon_WITH_AES_256_CBC_SHA,

	/* TLS 1.2 (RFC 5246) cipher suites (59-61) */
	TLS_RSA_WITH_NULL_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA256,

	/* TLS 1.2 (RFC 5246) DH cipher suites (62-64), continued at 103 */
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256, TLS_DH_RSA_WITH_AES_128_CBC_SHA256, 
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, 

	/* Camellia (RFC 4132) AES-128 suites (65-70) */
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA, 
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA, TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA, 
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA, TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,

	/* Unknown/reserved suites (71-103) */

	/* More TLS 1.2 (RFC 5246) DH cipher suites (103-109) */
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 103, TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256, TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLS_DH_anon_WITH_AES_128_CBC_SHA256,
	TLS_DH_anon_WITH_AES_256_CBC_SHA256,

	/* Unknown suites (110-131) */

	/* Camellia (RFC 4132) AES-256 suites (132-137) */
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 132,
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA, TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA, TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,

	/* TLS-PSK (RFC 4279) cipher suites (138-149) */
	TLS_PSK_WITH_RC4_128_SHA, TLS_PSK_WITH_3DES_EDE_CBC_SHA, 
	TLS_PSK_WITH_AES_128_CBC_SHA, TLS_PSK_WITH_AES_256_CBC_SHA, 
	TLS_DHE_PSK_WITH_RC4_128_SHA, TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA, TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
	TLS_RSA_PSK_WITH_RC4_128_SHA, TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA, TLS_RSA_PSK_WITH_AES_256_CBC_SHA,

	/* SEED (RFC 4162) suites (150-155) */
	TLS_RSA_WITH_SEED_CBC_SHA, TLS_DH_DSS_WITH_SEED_CBC_SHA,
	TLS_DH_RSA_WITH_SEED_CBC_SHA, TLS_DHE_DSS_WITH_SEED_CBC_SHA,
	TLS_DHE_RSA_WITH_SEED_CBC_SHA, TLS_DH_anon_WITH_SEED_CBC_SHA,

	/* TLS 1.2 (RFC 5288) GCM cipher suites (156-167) */
	TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256, TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256, TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_anon_WITH_AES_128_GCM_SHA256, TLS_DH_anon_WITH_AES_256_GCM_SHA384,

	/* TLS 1.2 (RFC 5487) PSK cipher suites (168-185) */
	TLS_PSK_WITH_AES_128_GCM_SHA256, TLS_PSK_WITH_AES_256_GCM_SHA384,
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256, TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
	TLS_PSK_WITH_AES_128_CBC_SHA256, TLS_PSK_WITH_AES_256_CBC_SHA384,
	TLS_PSK_WITH_NULL_SHA256, TLS_PSK_WITH_NULL_SHA384,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
	TLS_DHE_PSK_WITH_NULL_SHA256, TLS_DHE_PSK_WITH_NULL_SHA384,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256, TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
	TLS_RSA_PSK_WITH_NULL_SHA256, TLS_RSA_PSK_WITH_NULL_SHA384,

	/* TLS 1.2 (RFC 5932) Camellia cipher suites (186-197) */
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256, TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256, TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256, TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256, TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256, TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,

	/* TLS secure-rengotiation signalling cipher suite, RFC 5746 */
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 255,

	/* TLS fallback signalling cpiher suite, RFC 7507, stuffed into a gap in 
	   the range starting at 22016/0x5600 */
	TLS_FALLBACK_SCSV = 22016,

	/* TLS 1.3 symmetric-only suites, RFC 8446 (0x1301-0x1305, 4865-4869) */
	TLS_AES_128_GCM_SHA256 = 4865, TLS_AES_256_GCM_SHA384, 
	TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_8_SHA256,

	/* TLS-ECC (RFC 4492) cipher suites.  For some unknown reason these 
	   start above 49152/0xC000, so the range is 49153...49177 */
	TLS_ECDH_ECDSA_WITH_NULL_SHA = 49153, TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_NULL_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_RSA_WITH_NULL_SHA, TLS_ECDH_RSA_WITH_RC4_128_SHA,
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_NULL_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_anon_WITH_NULL_SHA, TLS_ECDH_anon_WITH_RC4_128_SHA,
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA,

	/* TLS-SRP (RFC 5054) cipher suites, following the pattern from 
	   above at 49178/0xC01A...49186 */
	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA, TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA, TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA, TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,

	/* TLS-ECC (RFC 5289) SHA-2 cipher suites, following the pattern from 
	   above at 49187/0xC023...49194 */
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,

	/* TLS-ECC (RFC 5289) GCM cipher suites, following the pattern from above
	   at 49195/0xC02B...49202 */
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,

	/* TLS-ECC (RFC 5489) PSK cipher suites, following the pattern from above
	   at 49203/0xC033...49211 */
	TLS_ECDHE_PSK_WITH_RC4_128_SHA, TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_PSK_WITH_NULL_SHA, TLS_ECDHE_PSK_WITH_NULL_SHA256,
    TLS_ECDHE_PSK_WITH_NULL_SHA384,

	/* Endless vanity suites, Aria, Camellia, etc */

	/* TLS Bernstein protocol suite (RFC 7905), following the pattern from 
	   above at 52392/0xCCA8...52398/0xCCAE */
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52392,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 
	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, 
	TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
	TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,

	TLS_LAST_SUITE
	} TLS_CIPHERSUITE_TYPE;

/* The first cipher suite that we'll even consider.  If RSA + 3DES is enabled
   (RSA is disabled by default) it's the one and only SSLv3 3DES suite, if
   only 3DES is enabled it's the last TLS 1.0 suite, and if neither are enabled
   it's a TLS 1.1 AES suite */

#if defined( USE_RSA_SUITES )
  #define TLS_FIRST_VALID_SUITE		SSL_RSA_WITH_3DES_EDE_CBC_SHA
#else
  #if defined( USE_3DES )
	#define TLS_FIRST_VALID_SUITE	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  #else
	#define TLS_FIRST_VALID_SUITE	TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  #endif /* USE_3DES */
#endif /* USE_RSA_SUITES */

/* TLS extension types, from 
   http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */

typedef enum {
	TLS_EXT_SNI,				/* 0: Name of virtual server to contact (SNI) */
	TLS_EXT_MAX_FRAGMENT_LENTH,	/* 1: Max.fragment length if smaller than 2^14 bytes */
	TLS_EXT_CLIENT_CERTIFICATE_URL,	/* 2: Location for server to find client certificate */
	TLS_EXT_TRUSTED_CA_KEYS,	/* 3: Indication of which CAs clients trust */
	TLS_EXT_TRUNCATED_HMAC,		/* 4: Use 80-bit truncated HMAC */
	TLS_EXT_STATUS_REQUEST,		/* 5: OCSP status request from server */
	TLS_EXT_USER_MAPPING,		/* 6: RFC 4681 mapping of user name to account */
	TLS_EXT_CLIENT_AUTHZ,		/* 7: RFC 5878 authorisation exts */
	TLS_EXT_SERVER_AUTHZ,		/* 8: RFC 5878 authorisation exts */
	TLS_EXT_CERTTYPE,			/* 9: RFC 5081/6091 OpenPGP key support */
	TLS_EXT_SUPPORTED_GROUPS,	/* 10: RFC 8446 Supported Groups, formerly
									   RFC 4492 ECC elliptic curve types */
	TLS_EXT_EC_POINT_FORMATS,	/* 11: RFC 4492 ECDH/ECDSA support */
	TLS_EXT_SRP,				/* 12: RFC 5054 SRP support */
	TLS_EXT_SIGNATURE_ALGORITHMS,/* 13: RFC 5246 TLSv1.2 */
	TLS_EXT_USE_SRP,			/* 14: RFC 5764 DTLS for SRTP keying */
	TLS_EXT_HEARTBEAT,			/* 15: RFC 6520 DTLS heartbeat */
	TLS_EXT_ALPN,				/* 16: RFC 7301 Application layer protocol negotiation */
	TLS_EXT_STATUS_REQUEST_V2,	/* 17: RFC 6961 OCSP status request from server */
	TLS_EXT_CERT_TRANSPARENCY,	/* 18: RFC 6962 Certificate transparency timestamp */
	TLS_EXT_RAWKEY_CLIENT,		/* 19: RFC 7250 Raw client public key */
	TLS_EXT_RAWKEY_SERVER,		/* 20: RFC 7250 Raw server public key */
	TLS_EXT_PADDING,			/* 21: RFC 7685 Padding */
	TLS_EXT_ENCTHENMAC,			/* 22: RFC 7366 Encrypt-then-MAC */
	TLS_EXT_EMS,				/* 23: RFC 7627 Extended master secret */
	TLS_EXT_TOKENBIND,			/* 24: Draft, Token binding */
	TLS_EXT_CACHED_INFO,		/* 25: RFC 7924 Cached info */
	TLS_EXT_TLS12LTS,			/* 26: Draft, TLS 1.2 LTS */
	TLS_EXT_COMPRESS_CERT,		/* 27: RFC 8879 Certificate compression */
	TLS_EXT_RECORD_SIZE_LIMIT,	/* 28: RFC 8449 Record size limit */
	TLS_EXT_PWD_PROTECT,		/* 29: RFC 8492 Password, protected username */
	TLS_EXT_PWD_CLEAR,			/* 30: RFC 8492 Password, visible username */
	TLS_EXT_PASSWORD_SALT,		/* 31: RFC 8492 Password salt */
	TLS_EXT_TICKET_PINNING,		/* 32: RFC 8672 Server identity pinning */
	TLS_EXT_CERT_WITH_PSK,		/* 33: RFC 8773 TLS 1.3 Certificate-based auth with PSK */
	TLS_EXT_DELEGATED_CREDENIALS, /* 34: Draft, Delegated credentials */
	TLS_EXT_SESSIONTICKET,		/* 35: RFC 4507 Session ticket */
	TLS_EXT_TLMSP,				/* 36: ETSI TS 103 523-2, Middlebox */
	TLS_EXT_TLMSP_PROXYING,		/* 37: ETSI TS 103 523-2, Security */
	TLS_EXT_TLMSP_DELEGATE,		/* 38: ETSI TS 103 523-2, Protocol */
	TLS_EXT_SUPPORTED_EKT_CIPHERS, /* 39: RFC 8870, Encrypted key trasport */
		/* 40 unused */
	TLS_EXT_PRESHARED_KEY = 41,	/* 41: RFC 8446 TLS 1.3 pre-shared key */
	TLS_EXT_EARLY_DATA,			/* 42: RFC 8446 TLS 1.3 early data */
	TLS_EXT_SUPPORTED_VERSIONS,	/* 43: RFC 8446 TLS 1.3 supported versions */
	TLS_EXT_COOKIE,				/* 44: RFC 8446 TLS 1.3 cookie */
	TLS_EXT_PSK_KEYEX_MODES,	/* 45: RFC 8446 TLS 1.3 key exchange modes */
		/* 46 unused */
	TLS_EXT_CAS = 47,			/* 47: RFC 8446 TLS 1.3 certificate authorities */
	TLS_EXT_OID_FILTERS,		/* 48: RFC 8446 TLS 1.3 OID filters */
	TLS_EXT_POST_HS_AUTH,		/* 49: RFC 8446 TLS 1.3 post-handshake auth */
	TLS_EXT_SIG_ALGOS_CERT,		/* 50: RFC 8446 TLS 1.3 certificate signature algos */
	TLS_EXT_KEY_SHARE,			/* 51: RFC 8446 TLS 1.3 key share */
	TLS_EXT_TRANSPARENCY_INFO,	/* 52: Draft, Certificate transparency info */
	TLS_EXT_CONNECTION_ID_OLD,	/* 53: Draft, DTLS connection ID, deprecated */
	TLS_EXT_CONNECTION_ID,		/* 54: Draft, DTLS connection ID */
	TLS_EXT_EXTERNAL_ID_HASH,	/* 55: RFC 8844, DTLS-SRTP external ID hash */
	TLS_EXT_EXTERNAL_SESSION_ID,/* 56: RFC 8844, DTLS-SRTP external session ID */
	TLS_EXT_QUIC_PARAMETERS,	/* 57: RFC 9001, DTLS for QUIC */
	TLS_EXT_TICKET_REQUEST,		/* 58: Draft, TLS 1.3 ticket request */
	TLS_EXT_DNSSEC_CHAIN,		/* 59: Draft, DANE authentication information */
	TLS_EXT_LAST,
		/* 60....65280 unused */

	/* The secure-renegotiation extension, for some unknown reason, is given
	   a value of 65281 / 0xFF01, so we define it outside the usual 
	   extension range in order for the standard range-checking to be a bit
	   more sensible.
	   
	   Once secure-renegotiation started this, others followed, so now we've
	   got several special-snowflake values that we need to accommodate */
	TLS_EXT_ECH_OUTER = 64768,	/* ECH draft */
	TLS_EXT_ECH = 65037,		/* ECH draft */
	TLS_EXT_SECURE_RENEG = 65281/* RFC 5746 secure renegotiation */
	} TLS_EXT_TYPE;

/* TLS certificate types */

typedef enum {
	TLS_CERTTYPE_NONE, TLS_CERTTYPE_RSA, TLS_CERTTYPE_DSA, 
	TLS_CERTTYPE_DUMMY1 /* RSA+DH */, TLS_CERTTYPE_DUMMY2 /* DSA+DH */,
	TLS_CERTTYPE_DUMMY3 /* RSA+EDH */, TLS_CERTTYPE_DUMMY4 /* DSA+EDH */,
	TLS_CERTTYPE_ECDSA = 64, TLS_CERTTYPE_LAST
	} TLS_CERTTYPE_TYPE;

/* TLS signature and hash algorithm identifiers */

enum {
	TLS_SIGALGO_NONE, TLS_SIGALGO_RSA, TLS_SIGALGO_DSA, TLS_SIGALGO_ECDSA,
	TLS_SIGALGO_LAST 
	};

enum {
	TLS_HASHALGO_NONE, TLS_HASHALGO_MD5, TLS_HASHALGO_SHA1, 
	TLS_HASHALGO_DUMMY1 /* SHA2-224 */, TLS_HASHALGO_SHA2, 
	TLS_HASHALGO_SHA384, TLS_HASHALGO_SHA512, 
	TLS_HASHALGO_LAST 
	};

/* TLS 1.3 combined signature+hash identifiers.  See the comment in 
   session/tls_ext.c for why there are two lots of identifiers for 
   RSA-PSS */

enum {
	/* TLS classic IDs */
	TLS_SIGHASHALGO_RSAPKCS1_SHA2 = 0x0401, TLS_SIGHASHALGO_DSA_SHA2, 
	TLS_SIGHASHALGO_ECDSA_SHA2,
	TLS_SIGHASHALGO_RSAPKCS1_SHA384 = 0x0501, TLS_SIGHASHALGO_DSA_SHA384, 
	TLS_SIGHASHALGO_ECDSA_SHA384,
	TLS_SIGHASHALGO_RSAPKCS1_SHA512 = 0x0601, TLS_SIGHASHALGO_DSA_SHA512,
	TLS_SIGHASHALGO_ECDSA_SHA512,

	/* TLS 1.3 IDs */
	TLS_SIGHASHALGO_RSAPSSoid1_SHA2 = 0x0804, 
	TLS_SIGHASHALGO_RSAPSSoid1_SHA384,
	TLS_SIGHASHALGO_RSAPSSoid1_SHA512,
	TLS_SIGHASHALGO_ED25519, TLS_SIGHASHALGO_ED448, 
	TLS_SIGHASHALGO_RSAPSSoid2_SHA2, TLS_SIGHASHALGO_RSAPSSoid2_SHA384,
	TLS_SIGHASHALGO_RSAPSSoid2_SHA512,
	TLS_SIGHASHALGO_LAST
	};

/* TLS group type identifiers */

typedef enum {
	TLS_GROUP_NONE, 
	
	/* ECC groups */
	TLS_GROUP_SECT163K1, TLS_GROUP_SECT163R1, TLS_GROUP_SECT163R2, 
	TLS_GROUP_SECT193R1, TLS_GROUP_SECT193R2, TLS_GROUP_SECT233K1, 
	TLS_GROUP_SECT233R1, TLS_GROUP_SECT239K1, TLS_GROUP_SECT283K1, 
	TLS_GROUP_SECT283R1, TLS_GROUP_SECT409K1, TLS_GROUP_SECT409R1, 
	TLS_GROUP_SECT571K1, TLS_GROUP_SECT571R1, TLS_GROUP_SECP160K1, 
	TLS_GROUP_SECP160R1, TLS_GROUP_SECP160R2, TLS_GROUP_SECP192K1, 
	TLS_GROUP_SECP192R1, TLS_GROUP_SECP224K1, TLS_GROUP_SECP224R1, 
	TLS_GROUP_SECP256K1, 
	TLS_GROUP_SECP256R1 /* P256 */, 
	TLS_GROUP_SECP384R1 /* P384 */, 
	TLS_GROUP_SECP521R1 /* P521 */,
	TLS_GROUP_BRAINPOOLP256R1, TLS_GROUP_BRAINPOOLP384R1, 
	TLS_GROUP_BRAINPOOLP512R1,
	TLS_GROUP_X25519, TLS_GROUP_X448,
	TLS_GROUP_FFDHE2048 = 256, TLS_GROUP_FFDHE3072,
	TLS_GROUP_FFDHE4096, TLS_GROUP_FFDHE6144, TLS_GROUP_FFDHE8192,
	TLS_GROUP_LAST
	} TLS_GROUP_TYPE;

#define isECCGroup( group ) \
		( ( group ) > TLS_GROUP_NONE && ( group ) < TLS_GROUP_FFDHE2048 )

/* TLS 1.3 PSK modes */

typedef enum {
	TLS_PSK_STANDARD,	/* Equivalent to TLS < 1.3 session resumption */
	TLS_PSK_DHE,		/* Session resumption with (EC)DH */
	TLS_PSK_LAST
	} TLS_PSK_TYPE;

/* TLS major and minor version numbers */

#define TLS_MAJOR_VERSION		3
#define TLS_MINOR_VERSION_SSL	0
#define TLS_MINOR_VERSION_TLS	1
#define TLS_MINOR_VERSION_TLS11	2
#define TLS_MINOR_VERSION_TLS12	3
#define TLS_MINOR_VERSION_TLS13	4

/* TLS downgrade-protection magic values for the server random */

#define TLS_DOWNGRADEID_PREFIX	"DOWNGRD"
#define TLS_DOWNGRADEID_PREFIX_SIZE	7
#define TLS_DOWNGRADEID_TLS12	TLS_DOWNGRADEID_PREFIX "\x01"
#define TLS_DOWNGRADEID_TLS11	TLS_DOWNGRADEID_PREFIX "\x00"
#define TLS_DOWNGRADEID_SIZE	8
#define TLS_DOWNGRADEID_OFFSET	( TLS_NONCE_SIZE - TLS_DOWNGRADEID_SIZE )

/* TLS 1.3 magic value to denote that a Server Hello is actually a Hello 
   Retry Request */

#define TLS_HELLORETRY_MAGIC	"\xCF\x21\xAD\x74\xE5\x9A\x61\x11" \
								"\xBE\x1D\x8C\x02\x1E\x65\xB8\x91" \
								"\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E" \
								"\x07\x9E\x09\xE2\xC8\xA8\x33\x9C"
#define TLS_HELLORETRY_MAGIC_SIZE 32

/* TLS cipher suite fallback options, see the comment in TLS_HANDSHAKE_INFO
   for details */

typedef enum {
	TLS_FALLBACK_NONE,				/* No fallback type */
	TLS_FALLBACK_ECC,				/* Fallback to ECC suite */
	TLS_FALLBACK_TLS13,				/* Fallback to TLS 1.3 suite */
	TLS_FALLBACK_LAST
	} TLS_FALLBACK_TYPE;

/* Special-case actions that need to be taken in response to a client hello */

typedef enum {
	TLSHELLO_ACTION_NONE,			/* No special action */
	TLSHELLO_ACTION_RESUMEDSESSION,	/* Session is resumed from previous */
#ifdef USE_TLS13
	TLSHELLO_ACTION_RETRY,			/* Send TLS 1.3 HelloRetryRequest */
#endif /* USE_TLS13 */
	TLSHELLO_ACTION_LAST
	} TLSHELLO_ACTION_TYPE;

/* TLS cipher suite flags.  These are:

	CIPHERSUITE_BERNSTEIN: Suite uses the Bernstein algorithm suite.

	CIPHERSUITE_PSK: Suite is a TLS-PSK suite and is used only if we're
		using TLS-PSK.

	CIPHERSUITE_DH:	Suite is a DH suite.

	CIPHERSUITE_ECC: Suite is an ECC suite and is used only if ECC is
		enabled.

	CIPHERSUITE_GCM: Encryption uses GCM instead of the usual CBC.

	CIPHERSUITE_TLS12: Suite is a TLS 1.2 suite and is only sent if
		TLS 1.2 is enabled.

	CIPHERSUITE_TLS13: Suite is a TLS 1.3 suite and is only sent if
		TLS 1.3 is enabled */

#define CIPHERSUITE_FLAG_NONE	0x00	/* No suite */
#define CIPHERSUITE_FLAG_PSK	0x01	/* TLS-PSK suite */
#define CIPHERSUITE_FLAG_DH		0x02	/* DH suite */
#define CIPHERSUITE_FLAG_TLS12	0x04	/* TLS 1.2 suite */
#define CIPHERSUITE_FLAG_TLS13	0x08	/* TLS 1.3 suite */
#define CIPHERSUITE_FLAG_GCM	0x10	/* GCM instead of CBC */
#define CIPHERSUITE_FLAG_BERNSTEIN 0x20	/* Bernstein suite */
#define CIPHERSUITE_FLAG_MAX	0x3F	/* Maximum possible flag value */

typedef struct {
	/* The TLS cipher suite.  The debugText field isn't used in error 
	   messages but is enabled if their use is defined because of the way 
	   the DESCRIPTION() macro that sets it works */
	const int cipherSuite;
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	const char *debugText;
#endif /* USE_ERRMSGS || !NDEBUG */

	/* cryptlib algorithms for the cipher suite */
	const CRYPT_ALGO_TYPE keyexAlgo, authAlgo, cryptAlgo, macAlgo;

	/* Auxiliary information for the suite */
	const int macParam, cryptKeySize, macBlockSize;
	const int flags;
	} CIPHERSUITE_INFO;

/* Handshake flags.  These are:

	HANDSHAKE_HASEXTENSIONS: Hello has TLS extensions.

	HANDSHAKE_ISGOOGLE: Peer is Google Chrome, used to work around Chrome 
						bugs.

	HANDSHAKE_NEEDEMSRESPONSE: Server needs to respond to EMS.

	HANDSHAKE_NEEDETMRESPONSE: Server needs to respond to encThenMAC.

	HANDSHAKE_NEEDRENEGRESPONSE: Server needs to respond to renegotiation 
								 indication.

	HANDSHAKE_NEEDSNIRESPONSE: Server needs to respond to SNI.

	HANDSHAKE_NEEDTLS12LTSRESPONSE: Server needs to respond to TLS-LTS.

	HANDSHAKE_RETRIEDCLIENTHELLO: Whether client hello retry done */

#define HANDSHAKE_FLAG_NONE				0x00	/* No flag value */
#define HANDSHAKE_FLAG_HASEXTENSIONS	0x01	/* Hello has extensions */
#define HANDSHAKE_FLAG_NEEDSNIRESPONSE	0x02	/* Response to SNI needed */
#define HANDSHAKE_FLAG_NEEDRENEGRESPONSE 0x04	/* Response to reneg.needed */
#define HANDSHAKE_FLAG_NEEDETMRESPONSE	0x08	/* Response to EtM needed */
#define HANDSHAKE_FLAG_NEEDEMSRESPONSE	0x10	/* Response to EMS needed */
#define HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE 0x20/* Response to TLS-LTS needed */
#ifdef USE_TLS13
#define HANDSHAKE_FLAG_RETRIEDCLIENTHELLO 0x40	/* Client Hello Retry needed */
#define HANDSHAKE_FLAG_ISGOOGLE			0x80	/* Peer is Google Chrome */
#define HANDSHAKE_FLAG_MAX				0xFF	/* Maximum possible flag value */
#else
#define HANDSHAKE_FLAG_MAX				0x3F	/* Maximum possible flag value */
#endif /* USE_TLS13 */

/* The maximum size of the list of cipher suites, used to allocate storage 
   and for bounds checking, see session/tls_suites.c for the contents of the 
   suite lists */

#define NO_SUITES_STD		16		/* DH + PSK */
#if defined( USE_ECDH ) 
  #define NO_SUITES_ECDH	8 
#else
  #define NO_SUITES_ECDH	0 
#endif /* USE_ECDH */
#if defined( USE_GCM ) 
  #define NO_SUITES_GCM		8 
#else
  #define NO_SUITES_GCM		0 
#endif /* USE_GCM */
#if defined( USE_CHACHA20 )
  #define NO_SUITES_CHACHA20 8 
#else
  #define NO_SUITES_CHACHA20 0 
#endif /* USE_CHACHA20 */
#ifdef USE_RSA_SUITES
  #define NO_SUITES_RSA		8 
#else
  #define NO_SUITES_RSA		0 
#endif /* USE_RSA_SUITES */

#define MAX_NO_SUITES		( NO_SUITES_STD + NO_SUITES_ECDH + \
							  NO_SUITES_GCM + NO_SUITES_CHACHA20 + \
							  NO_SUITES_RSA )

/* Check for the presence of a TLS signalling suite */

#define isSignallingSuite( suite ) \
		( ( suite ) == TLS_FALLBACK_SCSV || \
		  ( suite ) == TLS_EMPTY_RENEGOTIATION_INFO_SCSV )

/* Check for an RFC 8701 / GREASE garbage value.  This is, by design, an 
   invalid value for whatever it's being used for but one that we have to 
   accept because Google Chrome inserts them wherever it can in the Client
   Hello.  GREASE values always have the high byte match the low byte with 
   the low nibbles of each byte being 0x0A, so 0x0A0A, 0x1A1A, ..., 0xFAFA */

#define checkGREASE( value ) \
		( ( ( value ) >> 8 ) == ( ( value ) & 0xFF ) && \
		  ( ( value ) & 0x0F0F ) == 0x0A0A ) 

/* If we're configured to only use Suite B algorithms, we override the
   algoAvailable() check to report that only Suite B algorithms are
   available */

#ifdef CONFIG_SUITEB

#if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
  #pragma message( "  Building with Suite B algorithms only." )
#endif /* Notify Suite B use */

#define algoAvailable( algo ) \
		( ( ( algo ) == CRYPT_ALGO_AES || ( algo ) == CRYPT_ALGO_ECDSA || \
			( algo ) == CRYPT_ALGO_ECDH || ( algo ) == CRYPT_ALGO_SHA2 || \
			( algo ) == CRYPT_ALGO_HMAC_SHA2 ) ? TRUE : FALSE )

  /* Special configuration defines to enable nonstandard behaviour for 
     Suite B tests */
  #ifdef CONFIG_SUITEB_TESTS 
	typedef enum {
		SUITEB_TEST_NONE,			/* No special test behaviour */

		/* RFC 5430bis tests */
		SUITEB_TEST_CLIINVALIDCURVE,/* Client sends non-Suite B curve */
		SUITEB_TEST_SVRINVALIDCURVE,/* Server sends non-Suite B curve */
		SUITEB_TEST_BOTHCURVES,		/* Client must send P256 and P384 as supp.curves */
		SUITEB_TEST_BOTHSIGALGOS,	/* Client must send SHA256 and SHA384 as sig.algos */

		SUITEB_TEST_LAST
		} SUITEB_TEST_VALUE;

	extern SUITEB_TEST_VALUE suiteBTestValue;
	extern BOOLEAN suiteBTestClientCert;
  #endif /* CONFIG_SUITEB_TESTS */
#endif /* Suite B algorithms only */

/* The following macro can be used to enable dumping of PDUs to disk.  As a
   safeguard, this only works in the Win32 debug version to prevent it from
   being accidentally enabled in any release version */

#if defined( __WIN32__ ) && defined( USE_ERRMSGS ) && !defined( NDEBUG )
  #define DEBUG_DUMP_TLS( buffer1, buffer1size, buffer2, buffer2size ) \
		  debugDumpTLS( sessionInfoPtr, buffer1, buffer1size, buffer2, buffer2size )

  STDC_NONNULL_ARG( ( 1, 2 ) ) \
  void debugDumpTLS( const SESSION_INFO *sessionInfoPtr,
					 IN_BUFFER( buffer1size ) const void *buffer1, 
					 IN_LENGTH_SHORT const int buffer1size,
					 IN_BUFFER_OPT( buffer2size ) const void *buffer2, 
					 IN_LENGTH_SHORT_Z const int buffer2size );
#else
  #define DEBUG_DUMP_TLS( buffer1, buffer1size, buffer2, buffer2size )
#endif /* Win32 debug */

/****************************************************************************
*																			*
*								TLS Structures								*
*																			*
****************************************************************************/

/* TLS handshake state information.  This is passed around various 
   subfunctions that handle individual parts of the handshake */

struct TH;

typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
	int ( *TLS_HANDSHAKE_FUNCTION )( INOUT_PTR SESSION_INFO *sessionInfoPtr,
									 INOUT_PTR struct TH *handshakeInfo );

typedef struct TH {
	/* Client and server dual-hash/hash contexts */
	CRYPT_CONTEXT md5context, sha1context, sha2context;
#ifdef CONFIG_SUITEB
	CRYPT_CONTEXT sha384context;
#endif /* CONFIG_SUITEB */

	/* Client and server nonces, session ID, and hashed SNI (which is used
	   alongside the session ID for scoreboard lookup) */
	BUFFER_FIXED( TLS_NONCE_SIZE ) \
	BYTE clientNonce[ TLS_NONCE_SIZE + 8 ];
	BUFFER_FIXED( TLS_NONCE_SIZE ) \
	BYTE serverNonce[ TLS_NONCE_SIZE + 8 ];
	BUFFER( MAX_SESSIONID_SIZE, sessionIDlength ) \
	BYTE sessionID[ MAX_SESSIONID_SIZE + 8 ];
	int sessionIDlength;
	BYTE hashedSNI[ KEYID_SIZE + 8 ];
	BOOLEAN hashedSNIpresent;

	/* Client/server hello hash, the hash of the Client Hello and Server 
	   Hello, and session hash, the hash of all messages from Client Hello 
	   to Client Keyex (TLS 1.2) or the last message before the current one
	   (TLS 1.3).
	   
	   We use two different strategies for the hashing, for the Client/
	   Server Hello hash, which are just the first two messages and both 
	   available at the same time, we use direct hash access via 
	   getHashParameters()/hashFunction().  For the session hash, which is
	   an ongoing hash of all messages exchanged, we use a hash context and,
	   for the case of TLS 1.3 which keeps peeling off copies of it to 
	   inject into the endless PRF churn that it applies, clone it and copy
	   the hash value from the cloned copy.  This means that the first two
	   messages, namely the Client and Server Hello, are hashed twice, once 
	   via direct access to get the hello hash and once via the context as 
	   part of the ongoing session hash.

	   In addition the sessionHashContext below isn't what's used for the
	   ongoing hash operation because, depending on the TLS classic version 
	   in use we could be using MD5+SHA1 or SHA2, so the way the hashing is 
	   done is to run as many of the different algorithms as required in 
	   parallel and then clone the one being used into sessionHashContext 
	   via session/tls_sign.c:createSessionHash() when it's time to create 
	   the handshake signature in session/tls_sign.c:createCertVerify() and
	   checkCertVerify().

	   For TLS 1.3 which does things differently we don't clone the ongoing 
	   hash state into sessionHashContext but instead use it to hash some 
	   magic values and the current transcript hash to get the hash value
	   that's then signed.

	   In theory we could just use the hash context and clone-and-copy
	   strategy in all cases, but since TLS 1.2 and TLS 1.3 handle things
	   somewhat differently the simpler strategy is to use direct access for
	   the hello hash, the context for the session hash, and then handle TLS
	   1.3's PRF churn separately as a special case of the latter */
	BUFFER( 16, CRYPT_MAX_HASHSIZE ) \
	BYTE helloHash[ CRYPT_MAX_HASHSIZE + 8 ];
	CRYPT_CONTEXT sessionHashContext;
	BUFFER( 16, CRYPT_MAX_HASHSIZE ) \
	BYTE sessionHash[ CRYPT_MAX_HASHSIZE + 8 ];
	int helloHashSize, sessionHashSize;

	/* Premaster/master secret */
	BUFFER( CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE, premasterSecretSize ) \
	BYTE premasterSecret[ CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE + 8 ];
	int premasterSecretSize;

#ifdef USE_TLS13
	/* For TLS 1.3, which does its keyex via values stuffed into extensions 
	   in the client and server hello, we need to store the keyex data for 
	   later when it's actually used.  Since this can get rather large, we 
	   overload the use of the premaster secret storage, which isn't used at
	   this point */
	int tls13KeyexGroup;		/* TLS_GROUP_xxx value for keyex data */
	#define tls13KeyexValue			premasterSecret
	#define tls13KeyexValueLen		premasterSecretSize

	/* TLS 1.3 also creates a huge explosion of secret data that needs to be
	   passed around different functions, for which we again reuse the
	   premaster secret storage */
	#define tls13MasterSecret		premasterSecret
	#define tls13MasterSecretLen	CRYPT_MAX_HASHSIZE
	#define tls13ClientSecret		premasterSecret + CRYPT_MAX_HASHSIZE
	#define tls13ClientSecretLen	CRYPT_MAX_HASHSIZE
	#define tls13ServerSecret		premasterSecret + ( 2 * CRYPT_MAX_HASHSIZE )
	#define tls13ServerSecretLen	CRYPT_MAX_HASHSIZE

	/* There's even more stuff that needs to be stored for TLS 1.3, for which
	   we reuse further existing storage locations.  This is safe because the
	   session hash is only created and used after the certificate verify has
	   been completed */
	#define tls13CertContext		sessionHash
	#define tls13CertContextLen		sessionHashSize

	/* Since we don't know at the time that we're reading the cipher suites
	   whether we'll be doing TLS 1.3 or not, we have to bookmark the 
	   required TLS 1.3 suite in case we later need to use it */
	const void *tls13SuiteInfoPtr;/* TLS 1.3 suite information */

	/* When a TLS 1.3 client guess incorrectly at what the server wants, it 
	   needs to re-send the Client Hello with a different guess.  To deal 
	   with this we need to re-hash the original Client Hello and Server 
	   Hello along with the re-sent second Client Hello and Server Hello to
	   get the hello hash.  To do this we need to record the sizes of the 
	   first Client and Server Hello */
	int originalClientHelloLength, originalServerHelloLength;
#endif /* USE_TLS13 */

	/* Encryption/security information.  Since for TLS 1.3 we have to guess 
	   which keyex mechanism the other side is using we need two (EC)DH
	   contexts on the client, one for each guessed algorithm.  The 
	   encryption algorithm (cryptAlgo) and integrity algorithm 
	   (integrityAlgo) are stored with the session information, although the 
	   optional integrity-algorithm parameters are stored here */
	CRYPT_CONTEXT dhContext;	/* (EC)DH context for (EC)DHE */
#ifdef USE_TLS13
	CRYPT_CONTEXT dhContextAlt;	/* Alternative ECDH context for TLS 1.3 */
#endif /* USE_TLS13 */
	int cipherSuite;			/* Selected cipher suite */
	CRYPT_ALGO_TYPE keyexAlgo, authAlgo;/* Selected cipher suite algos */
	int integrityAlgoParam;		/* Optional param.for integrity algo */
	CRYPT_ALGO_TYPE keyexSigHashAlgo;/* Algo.for keyex authentication */
	int keyexSigHashAlgoParam;	/* Optional params.for keyex hash */
	int cryptKeysize;			/* Size of session key */

	/* Other information */
	int clientOfferedVersion;	/* Prot.vers.originally offered by client */
	int originalVersion;		/* Original version set by the user before
								   it was modified based on what the peer
								   requested */
	int flags;					/* HANDSHAKE_FLAG_x flags */
	int failAlertType;			/* Alert type to send on failure */

	/* ECC-related information.  Since ECC algorithms have a huge pile of
	   parameters we need to parse any extensions that the client sends in 
	   order to locate any additional information required to handle them.  
	   In the worst case these can retroactively modify the already-
	   negotiated cipher suites, disabling the use of ECC algorithms after 
	   they were agreed on via cipher suites.  To handle this we remember
	   both the preferred mainstream suite and a pointer to the preferred
	   ECC suite in 'eccSuiteInfoPtr', if it later turns out that the use
	   of ECC is OK we reset the crypto parameters using the save ECC suite
	   pointer.
	   
	   If the use of ECC isn't retroactively disabled then the eccCurveID 
	   and sendECCPointExtn values indicate which curve to use and whether 
	   the server needs to respond with a point-extension indicator */
	BOOLEAN disableECC;			/* Extn.disabled use of ECC suites */
	CRYPT_ECCCURVE_TYPE eccCurveID;	/* cryptlib ID of ECC curve to use */
	BOOLEAN sendECCPointExtn;	/* Whether svr.has to respond with ECC point ext.*/
	const void *eccSuiteInfoPtr;/* ECC suite information */

	/* Another side-effect of the post-modification of suites via 
	   information in extensions is that depending on what the client 
	   advertises we may have to fall back through successive alternatives 
	   while parsing the suites.  Typical behaviour for a standard client
	   hello is to record the main suite and bookmark ECC and TLS 1.3
	   alternatives, however if there's no main suite present that what's
	   recorded is the ECC suite, and if that's not present the TLS 1.3
	   suite.  In order to figure out what's what, we need to record whether
	   the fallback to alternative suites has been triggered */
	TLS_FALLBACK_TYPE fallbackType;

	/* The packet data stream.  Since TLS can encapsulate multiple handshake
	   packets within a single TLS packet, the stream has to be persistent
	   across the different handshake functions to allow the continuation of
	   packets */
	STREAM stream;				/* Packet data stream */

	/* Function pointers to handshaking functions.  These are set up as 
	   required depending on whether the session is client or server */
	FNPTR beginHandshake, exchangeKeys;
	} TLS_HANDSHAKE_INFO;

/****************************************************************************
*																			*
*								TLS Functions								*
*																			*
****************************************************************************/

/* Prototypes for functions in tls.c */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionTLS( IN_PTR const SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckTLSHandshakeInfo( IN_PTR \
										const TLS_HANDSHAKE_INFO *handshakeInfo );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
int readUint24( INOUT_PTR STREAM *stream );
STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint24( INOUT_PTR STREAM *stream, IN_LENGTH_Z const int length );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int readEcdhValue( INOUT_PTR STREAM *stream,
				   OUT_BUFFER( valueMaxLen, *valueLen ) void *value,
				   IN_LENGTH_SHORT_MIN( 64 ) const int valueMaxLen,
				   OUT_LENGTH_BOUNDED_Z( valueMaxLen ) int *valueLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readTLSCertChain( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT_PTR STREAM *stream,
					  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertChain, 
					  IN_BOOL const BOOLEAN isServer );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeTLSCertChain( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					   INOUT_PTR STREAM *stream );

/* Prototypes for functions in tls_cert.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int checkHostNameTLS( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
					  INOUT_BUFFER_FIXED( serverNameLength ) void *serverName,
					  IN_LENGTH_DNS const int serverNameLength,
					  OUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkTLSCertificateInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr );

/* Prototypes for functions in tls_crypt.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int encryptData( const SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER( dataMaxLength, *dataLength ) \
					BYTE *data, 
				 IN_DATALENGTH const int dataMaxLength,
				 OUT_DATALENGTH_Z int *dataLength,
				 IN_DATALENGTH const int payloadLength );
				 /* This one's a bit tricky, the input is 
				    { data, payloadLength } which is padded (if necessary) 
					and the padded length returned in '*dataLength' */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int decryptData( SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER_FIXED( dataLength ) \
					BYTE *data, 
				 IN_DATALENGTH const int dataLength, 
				 OUT_DATALENGTH_Z int *processedDataLength );
				/* This one's also tricky, the entire data block will be 
				   processed but only 'processedDataLength' bytes of result 
				   are valid output */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				  INOUT_BUFFER( dataMaxLength, *dataLength ) void *data,
				  IN_DATALENGTH const int dataMaxLength, 
				  OUT_DATALENGTH_Z int *dataLength,
				  IN_DATALENGTH const int payloadLength, 
				  IN_BYTE const int type );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) const void *data, 
				 IN_DATALENGTH const int dataLength, 
				 IN_DATALENGTH_Z const int payloadLength, 
				 IN_BYTE const int type, 
				 IN_BOOL const BOOLEAN noReportError );
#ifdef USE_GCM
CHECK_RETVAL \
int macDataTLSGCM( IN_HANDLE const CRYPT_CONTEXT iCryptContext, 
				   IN_INT_Z const long seqNo, 
				   IN_RANGE( TLS_MINOR_VERSION_TLS, \
							 TLS_MINOR_VERSION_TLS13 ) const int version,
				   IN_LENGTH_Z const int payloadLength, 
				   IN_BYTE const int type );
#endif /* USE_GCM */
#ifdef USE_CHACHA20
CHECK_RETVAL \
int initCryptBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_BOOL const BOOLEAN isRead );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLSBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_BUFFER( dataMaxLength, *dataLength ) \
								void *data, 
						   IN_DATALENGTH const int dataMaxLength, 
						   OUT_DATALENGTH_Z int *dataLength,
						   IN_DATALENGTH const int payloadLength, 
						   IN_BYTE const int type );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLSBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  IN_BUFFER( dataLength ) const void *data, 
						  IN_DATALENGTH const int dataLength, 
						  IN_DATALENGTH_Z const int payloadLength, 
						  IN_BYTE const int type );
#endif /* USE_CHACHA20 */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int hashHSPacketRead( IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT_PTR STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int hashHSPacketWrite( IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo, 
					   INOUT_PTR STREAM *stream,
					   IN_DATALENGTH_Z const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) ) \
int completeTLSHashedMAC( IN_HANDLE const CRYPT_CONTEXT md5context,
						  IN_HANDLE const CRYPT_CONTEXT sha1context, 
						  OUT_BUFFER( hashValuesMaxLen, *hashValuesLen ) \
								BYTE *hashValues, 
						  IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
						  OUT_LENGTH_BOUNDED_Z( hashValuesMaxLen ) \
								int *hashValuesLen,
						  IN_BUFFER( labelLength ) const char *label, 
						  IN_RANGE( 1, 64 ) const int labelLength, 
						  IN_BUFFER( masterSecretLen ) const BYTE *masterSecret, 
						  IN_LENGTH_SHORT const int masterSecretLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4, 5, 7 ) ) \
int completeTLS12HashedMAC( IN_HANDLE const CRYPT_CONTEXT sha2context,
							OUT_BUFFER( hashValuesMaxLen, *hashValuesLen ) \
								BYTE *hashValues, 
							IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
							OUT_LENGTH_BOUNDED_Z( hashValuesMaxLen ) \
								int *hashValuesLen,
							IN_BUFFER( labelLength ) const char *label, 
							IN_RANGE( 1, 64 ) const int labelLength, 
							IN_BUFFER( masterSecretLen ) const BYTE *masterSecret, 
							IN_LENGTH_SHORT const int masterSecretLen,
							IN_BOOL const BOOLEAN fullSizeMAC );

/* Prototypes for functions in tls_ext.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readExtensions( INOUT_PTR STREAM *stream, 
					INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					OUT_ENUM_OPT( TLSHELLO_ACTION ) \
							TLSHELLO_ACTION_TYPE *actionType,
					IN_LENGTH_SHORT const int length );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeClientExtensions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeServerExtensions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );

/* Prototypes for functions in tls_hello.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int processHelloTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT_PTR STREAM *stream, 
					 OUT_ENUM_OPT( TLSHELLO_ACTION ) \
							TLSHELLO_ACTION_TYPE *actionType,
					 IN_BOOL const BOOLEAN isServer );

/* Prototypes for functions in tls_hscomplete.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int completeHandshakeTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_BOOL const BOOLEAN isClient,
						  IN_BOOL const BOOLEAN isResumedSession );

/* Prototypes for functions in tls_keymgmt.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void destroySecurityContextsTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initHandshakeCryptInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void destroyHandshakeCryptInfo( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initSecurityContextsTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int cloneHashContext( IN_HANDLE const CRYPT_CONTEXT hashContext,
					  OUT_HANDLE_OPT CRYPT_CONTEXT *clonedHashContext );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createDHcontextTLS( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
						IN_ALGO const CRYPT_ALGO_TYPE dhAlgo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initDHcontextTLS( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
					  IN_BUFFER_OPT( keyDataLength ) const void *keyData, 
					  IN_LENGTH_SHORT_Z const int keyDataLength,
					  IN_HANDLE_OPT const CRYPT_CONTEXT iServerKeyTemplate,
					  IN_ENUM_OPT( CRYPT_ECCCURVE ) \
							const CRYPT_ECCCURVE_TYPE eccCurve,
					  IN_BOOL const BOOLEAN isTLSLTS );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int completeTLSKeyex( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					  INOUT_PTR STREAM *stream, 
					  IN_BOOL const BOOLEAN isECC,
					  IN_BOOL const BOOLEAN isTLSLTS,
					  INOUT_PTR ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int createSharedPremasterSecret( OUT_BUFFER( premasterSecretMaxLength, \
											 *premasterSecretLength ) \
									void *premasterSecret, 
								 IN_LENGTH_SHORT_MIN( 16 ) \
									const int premasterSecretMaxLength, 
								 OUT_LENGTH_BOUNDED_Z( premasterSecretMaxLength ) \
									int *premasterSecretLength,
								 IN_BUFFER( sharedSecretLength ) \
									const void *sharedSecret, 
								 IN_LENGTH_TEXT const int sharedSecretLength,
								 IN_BUFFER_OPT( otherSecretLength ) \
									const void *otherSecret, 
								 IN_LENGTH_PKC_Z const int otherSecretLength,
								 IN_BOOL const BOOLEAN isEncodedValue );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int wrapPremasterSecret( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
						 IN_LENGTH_SHORT_MIN( 16 ) const int dataMaxLength, 
						 OUT_LENGTH_BOUNDED_Z( dataMaxLength ) \
							int *dataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int unwrapPremasterSecret( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   IN_BUFFER( dataLength ) const void *data, 
						   IN_LENGTH_SHORT_MIN( 16 ) const int dataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int initCryptoTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
				   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
				   OUT_BUFFER_FIXED( masterSecretSize ) void *masterSecret,
				   IN_LENGTH_SHORT_MIN( 16 ) const int masterSecretSize,
				   IN_BOOL const BOOLEAN isClient,
				   IN_BOOL const BOOLEAN isResumedSession );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int loadExplicitIV( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR STREAM *stream, 
					OUT_INT_SHORT_Z int *ivLength );
#ifdef USE_EAP
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int addDerivedKeydata( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					   IN_BUFFER( masterSecretSize ) void *masterSecret,
					   IN_LENGTH_SHORT_MIN( 16 ) const int masterSecretSize,
					   IN_ENUM( CRYPT_SUBPROTOCOL ) \
							const CRYPT_SUBPROTOCOL_TYPE type );
#endif /* USE_EAP */

/* Prototypes for functions in tls_rd.c */

#ifdef USE_ERRMSGS
CHECK_RETVAL_PTR_NONNULL \
const char *getTLSPacketName( IN_BYTE const int packetType );
CHECK_RETVAL_PTR_NONNULL \
const char *getTLSHSPacketName( IN_BYTE const int packetType );
#else
  #define getTLSPacketName( x )		"<Unknown>"
  #define getTLSHSPacketName( x )	"<Unknown>"
#endif /* USE_ERRMSGS */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processVersionInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						INOUT_PTR STREAM *stream, 
						OUT_OPT int *clientVersion,
						IN_BOOL const BOOLEAN generalCheckOnly );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkPacketHeaderTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR STREAM *stream, 
						  OUT_DATALENGTH_Z int *packetLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkHSPacketHeader( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR STREAM *stream, 
						 OUT_DATALENGTH_Z int *packetLength, 
						 IN_RANGE( TLS_HAND_FIRST, \
								   TLS_HAND_LAST ) const int packetType, 
						 IN_LENGTH_SHORT_Z const int minSize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int unwrapPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_BUFFER( dataMaxLength, \
								   *dataLength ) void *data, 
					 IN_DATALENGTH const int dataMaxLength, 
					 OUT_DATALENGTH_Z int *dataLength,
					 IN_RANGE( TLS_HAND_FIRST, \
							   TLS_HAND_LAST ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int readHSPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR_OPT TLS_HANDSHAKE_INFO *handshakeInfo, 
					 OUT_DATALENGTH_Z int *packetLength, 
					 IN_RANGE( TLS_MSG_FIRST, \
							   TLS_MSG_LAST_SPECIAL ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int refreshHSStream( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );

/* Prototypes for functions in tls_sign.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCertWhitelist( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
						IN_BOOL const BOOLEAN isServer );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int createSessionHash( IN_PTR const SESSION_INFO *sessionInfoPtr,
					   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void destroySessionHash( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int createCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					  INOUT_PTR STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkCertVerify( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					 INOUT_PTR STREAM *stream, 
					 IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
						const int sigLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int createKeyexSignature( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  INOUT_PTR STREAM *stream, 
						  IN_BUFFER( keyDataLength ) const void *keyData, 
						  IN_LENGTH_SHORT const int keyDataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 7 ) ) \
int checkKeyexSignature( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 INOUT_PTR STREAM *stream, 
						 IN_BUFFER( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT const int keyDataLength,
						 IN_BOOL const BOOLEAN isECC,
						 INOUT_PTR ERROR_INFO *errorInfo );

/* Prototypes for functions in tls_suites.c */

#ifndef CONFIG_SUITEB

CHECK_RETVAL \
int getCipherSuiteInfo( OUT_PTR \
							const CIPHERSUITE_INFO ***cipherSuiteInfoPtrPtrPtr,
						OUT_INT_Z int *noSuiteEntries );
#else

#define getCipherSuiteInfo( infoPtr, noEntries, isServer ) \
		getSuiteBCipherSuiteInfo( infoPtr, noEntries, isServer, suiteBinfo )

CHECK_RETVAL \
int getSuiteBCipherSuiteInfo( OUT_PTR \
								const CIPHERSUITE_INFO ***cipherSuiteInfoPtrPtrPtr,
							  OUT_INT_Z int *noSuiteEntries,
							  IN_BOOL const BOOLEAN isServer,
							  IN_FLAGS_Z( TLS ) const int suiteBinfo );

#endif /* CONFIG_SUITEB */

/* Prototypes for functions in tls_svr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int convertSNISessionID( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER_FIXED( idBufferLength ) BYTE *idBuffer,
						 IN_LENGTH_FIXED( KEYID_SIZE ) const int idBufferLength );

/* Prototypes for functions in tls_wr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int wrapPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				   INOUT_PTR STREAM *stream, 
				   IN_LENGTH_Z const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sendPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				   INOUT_PTR STREAM *stream, 
				   IN_BOOL const BOOLEAN sendOnly );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int openPacketStreamTLS( OUT_PTR STREAM *stream, 
						 IN_PTR const SESSION_INFO *sessionInfoPtr, 
						 IN_DATALENGTH_OPT const int bufferSize, 
						 IN_RANGE( TLS_MSG_FIRST, \
								   TLS_MSG_LAST ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int continuePacketStreamTLS( INOUT_PTR STREAM *stream, 
							 IN_PTR const SESSION_INFO *sessionInfoPtr, 
							 IN_RANGE( TLS_HAND_FIRST, \
									   TLS_HAND_LAST ) const int packetType,
							 OUT_LENGTH_SHORT_Z int *packetOffset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completePacketStreamTLS( INOUT_PTR STREAM *stream, 
							 IN_LENGTH_Z const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int continueHSPacketStream( INOUT_PTR STREAM *stream, 
							IN_RANGE( TLS_HAND_FIRST, \
									  TLS_HAND_LAST ) const int packetType,
							OUT_LENGTH_SHORT_Z int *packetOffset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completeHSPacketStream( INOUT_PTR STREAM *stream, 
							IN_LENGTH const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				  IN_BUFFER( headerLength ) const void *header, 
				  IN_DATALENGTH const int headerLength,
				  OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void sendCloseAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 IN_BOOL const BOOLEAN alertReceived );
STDC_NONNULL_ARG( ( 1 ) ) \
void sendHandshakeFailAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 IN_RANGE( TLS_ALERT_FIRST, \
									   TLS_ALERT_LAST ) const int alertType );
#ifdef USE_TLS13

/* Prototypes for functions in tls13_crypt.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initCryptGCMTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					   IN_BOOL const BOOLEAN isRead );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createSessionHashTLS13( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						    IN_HANDLE const CRYPT_CONTEXT iHashContext,
							const BOOLEAN isServerVerify );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int createFinishedTLS13( OUT_BUFFER( finishedValueMaxLen, \
									 *finishedValueLen ) \
							void *finishedValue,
						 IN_LENGTH_SHORT_MIN( 20 ) \
							const int finishedValueMaxLen,
						 OUT_LENGTH_BOUNDED_SHORT_Z( finishedValueMaxLen ) \
							 int *finishedValueLen,
						 IN_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 IN_HANDLE const CRYPT_CONTEXT iHashContext,
						 IN_BOOL const BOOLEAN isServerFinished );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int loadHSKeysTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int loadAppdataKeysTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );

/* Prototypes for functions in tls13_hs.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void initProcessingTLS13( TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_BOOL const BOOLEAN isServer );

/* Prototypes for functions in tls13_keyex.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readKeyexTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					INOUT_PTR STREAM *stream, 
					IN_LENGTH_SHORT_Z const int extLength,
					OUT_BOOL BOOLEAN *extErrorInfoSet );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeKeyexTLS13( INOUT_PTR STREAM *stream,
					 const TLS_HANDSHAKE_INFO *handshakeInfo,
					 IN_BOOL const BOOLEAN isServer );

/* Prototypes for functions in tls_rd.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int unwrapPacketTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   INOUT_BUFFER( dataMaxLength, \
									 *dataLength ) void *data, 
					   IN_DATALENGTH const int dataMaxLength, 
					   OUT_DATALENGTH_Z int *dataLength,
					   OUT_RANGE( TLS_HAND_NONE, TLS_HAND_LAST ) \
							int *actualPacketType,
					   IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
							const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processAlertTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   IN_BUFFER( dataLength ) const void *data, 
					   IN_DATALENGTH const int dataLength,
					   OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo );

/* Prototypes for functions in tls_wr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int wrapPacketTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR STREAM *stream, 
					 IN_LENGTH_Z const int offset,
					 IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
						const int packetType );
#endif /* USE_TLS13 */

/* Prototypes for session mapping functions */

STDC_NONNULL_ARG( ( 1 ) ) \
void initTLSclientProcessing( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void initTLSserverProcessing( TLS_HANDSHAKE_INFO *handshakeInfo );

#endif /* USE_TLS */

#endif /* _TLS_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
