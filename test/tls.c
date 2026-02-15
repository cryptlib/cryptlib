/****************************************************************************
*																			*
*								cryptlib TLS Routines						*
*						Copyright Peter Gutmann 1998-2022					*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

/* Various features can be disabled by configuration options, in order to 
   handle this we need to include the cryptlib config file so that we can 
   selectively disable some tests.
   
   Note that this checking isn't perfect, if cryptlib is built in release
   mode but we include config.h here in debug mode then the defines won't
   match up because the use of debug mode enables extra options that won't
   be enabled in the release-mode cryptlib */
#include "misc/config.h"
#ifndef NDEBUG
  #include <limits.h>			/* Needed for analyse.h */
  #include "misc/analyse.h"		/* Needed for fault.h */
  #include "misc/fault.h"
#endif /* !NDEBUG */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

#if defined( __MVS__ )
  /* MVS control section (CSECT) names default to the file name and can't
	 match any symbol name either in the file or in another file or library 
	 (e.g. write.c vs. write()).  Because of this we have to explicitly 
	 name the csect's so that they don't conflict with external symbol
	 names */
  #pragma csect( CODE, "testTLSC" )
  #pragma csect( STATIC, "testTLSS" )
  #pragma csect( TEST, "testTLST" )
#endif /* __MVS__ */

/* TLS gets a bit complicated because in the presence of the session cache 
   every session after the first one will be a resumed session.  To deal 
   with this, the VC++ 6 and VS 32-bit debug builds disable the client-side 
   session cache while every other version just ends up going through a 
   series of session resumes.
   
   Note that changing the follow requires an equivalent change in 
   session/tls_cli.c */

#if defined( __WINDOWS__ ) && defined( _MSC_VER ) && \
	( _MSC_VER == 1200 || _MSC_VER == 1929 ) && \
	!defined( NDEBUG ) && 1
  #define NO_SESSION_CACHE
#endif /* VC++ 6.0 / VS 32-bit debug build */

/* We can run the TLS self-test with a large variety of options, rather than 
   using dozens of boolean option flags to control them all we define various 
   test classes that exercise each option type.
   
   Two of the tests aren't run as part of the normal self-test since their 
   use of random threads results in somewhat nondeterministic behaviour that 
   would require extensive extra locking to resolve.  TLS_TEST_DUALTHREAD 
   starts the TLS server with one thread and has the server session return 
   control to the caller for the password check.  The initial server thread 
   then exits and a second thread takes over for the rest of the connect.

   TLS_TEST_MULTITHREAD is just a multithreaded client and server test. 
   This is even more nondeterministic, with thread pileups possible due to 
   the lack of extensive locking on the client side.

   For TLS_TEST_CLIENTCERT against the Windows interop server, the test 
   server client-auth key needs to be converted to PKCS #15 format since it 
   uses a too-short password in the original Microsoft-provided file.  To do 
   this, in mechs/mech_drv.c, initDSP() add the following kludge:

	*( ( int * ) &keyLength ) = 1;

   and then use the following code:

	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;

	cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
					 "r:/woodgrove.p12", CRYPT_KEYOPT_READONLY );
	cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME, 
 						TEXT( "test" ), TEXT( "11" ) );
	cryptKeysetClose( cryptKeyset );
	cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
					 TEST_PRIVKEY_TMP_FILE, CRYPT_KEYOPT_CREATE );
	cryptAddPrivateKey( cryptKeyset, cryptContext, TEST_PRIVKEY_PASSWORD );
	cryptKeysetClose( cryptKeyset );
	cryptDestroyContext( cryptContext );
	} */

typedef enum {
	TLS_TEST_NONE,				/* No TLS test type */
	TLS_TEST_NORMAL,			/* Standard TLS test */
	TLS_TEST_BULKTRANSER,		/* Bulk data transfer */
	TLS_TEST_CLIENTCERT,		/* User auth.with client certificate */
	TLS_TEST_CLIENTCERT_MANUAL,	/* User auth.client certificate manual verif.*/
	TLS_TEST_SNI,				/* Server certificate switching via SNI */
	TLS_TEST_FORCEVER_CLI,		/* Force use of given TLS version on client */
	TLS_TEST_FORCEVER_SVR,		/* Force use of given TLS version on server */
	TLS_TEST_WHITELIST,			/* Server certificate in whitelist */
	TLS_TEST_WHITELIST_FAIL,	/* Server certificate not in whitelist */
	TLS_TEST_PSK,				/* User auth.with shared key */
	TLS_TEST_PSK_SVRONLY,		/* Client = no PSK, server = TLS-PSK */
	TLS_TEST_PSK_CLIONLY,		/* Client = TLS-PSK, server = no PSK */
	TLS_TEST_PSK_WRONGKEY,		/* User auth.with incorrect shared key */
	TLS_TEST_ECC,				/* Use ECC instead of RSA/DH */
	TLS_TEST_ECC_P384,			/* Use ECC P384 instead of P256 */
	TLS_TEST_ED25519,			/* Use Ed25519 instead of RSA/DH */
	TLS_TEST_STARTTLS,			/* Local client socket speaking STARTTLS/STLS/AUTH TLS */
	TLS_TEST_LOCALSERVER,		/* Local server socket */
	TLS_TEST_RESUME,			/* Session resumption */
	TLS_TEST_DUALTHREAD,		/* Two-phase connect via different threads */
	TLS_TEST_MULTITHREAD,		/* Multiple server threads */
	TLS_TEST_WRONGSERVER,		/* Error handling on connecting to non-TLS server */
	TLS_TEST_WEBSOCKETS,		/* WebSockets over TLS */
	TLS_TEST_EAPTTLS,			/* EAP-TTLS */
	TLS_TEST_BADSSL_DH512,		/* BadSSL tests */
	TLS_TEST_BADSSL_DH1024,
	TLS_TEST_BADSSL_DH2048,
	TLS_TEST_BADSSL_DHSMALLSUBGROUP,
	TLS_TEST_BADSSL_DHCOMPOSITE,
	TLS_TEST_BADSSL_STATICRSA,
	TLS_TEST_BADSSL_RSA2048,
	TLS_TEST_BADSSL_ECC256,
	TLS_TEST_BADSSL_CBC,
	TLS_TEST_BADSSL_RC4MD5,
	TLS_TEST_BADSSL_RC4,
	TLS_TEST_BADSSL_3DES,
	TLS_TEST_BADSSL_NOCN,
	TLS_TEST_BADSSL_NOSUBJECT,
	TLS_TEST_BADSSL_LONGNAME1,
	TLS_TEST_BADSSL_LONGNAME2,
	TLS_TEST_CORRUPT_HANDSHAKE,	/* Detect corruption of handshake data */
	TLS_TEST_CORRUPT_DATA,		/* Detect corruption of payload data */
	TLS_TEST_CORRUPT_MAC,		/* Detect corruption of payload MAC */
	TLS_TEST_CORRUPT_FINISHED,	/* Detect corruption of finished MAC */
	TLS_TEST_CORRUPT_IV,		/* Detect corruption of IV */
	TLS_TEST_WRONGCERT,			/* Detect wrong key for server */
	TLS_TEST_BADSIG_HASH,		/* Detect corruption of signed DH params */
	TLS_TEST_BADSIG_SIG,		/* Detect corruption of DH signature */
	TLS_TEST_BADSIG_DATA,		/* Detect corruption of signed DH params */
	TLS_TEST_LAST				/* Last possible TLS test type */
	} TLS_TEST_TYPE;

#if defined( TEST_SESSION ) || defined( TEST_SESSION_LOOPBACK )

/****************************************************************************
*																			*
*								TLS Test Data								*
*																			*
****************************************************************************/

/* If we're using local sockets, we have to pull in the sockets defines.  
   We only use this on systems where there's fixed, known support for the
   various functions that we need */

#if defined( __WINDOWS__ ) || defined( __linux__ )
  #define USE_TCP
  #define STDC_NONNULL()
  #define NET_STREAM_INFO	void *
  #define USE_TCP
  #include <ctype.h>		/* isspace() */
  #if defined( __linux__ )
	#include <unistd.h>		/* close() */
  #endif /* Linux */
  #include <limits.h>		/* Needed for analyse.h */
  #include "misc/analyse.h"	/* For values in tcp.h fn. prototypes */
  #if defined( __WINDOWS__ ) && !defined( _WINSOCK2API_ )
	/* Under Windows we already have the networking headers present via 
	   windows.h so we need to disable their re-inclusion via tcp.h and 
	   only include the portability defines */
	#define _WINSOCK2API_
	#define _WS2TCPIP_H_
	#if defined( _MSC_VER ) && ( _MSC_VER >= 1930 )
	  #define _WINDNS_INCLUDED_
	#endif /* VS 2022 and newer */
  #endif /* Disable inclusion of Windows networking headers */
  #include "io/tcp.h"
  #define USE_LOCAL_SOCKETS
#endif /* Windows || Linux */

/* There are various servers running that we can use for testing, the 
   following remapping allows us to switch between them, check using
   https://www.ssllabs.com/ssltest/index.html or 
   https://pentest-tools.com/network-vulnerability-scanning/ssl-tls-scanner.

   OpenSSL can also be used to test things, e.g:

	openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
	openssl s_server -key key.pem -cert cert.pem -no_ssl3 -no_tls1 -www -debug

   will run a basic server that echoes crypto info on connect, as well as 
   printing basic debug information on the server.

   Notes:

	Server 1: Local loopback.
	Server 2-4: Generic test servers at google.com (formerly amazon.com), 
			  paypal.com, redhat.com.  There have to be three distinct 
			  servers in order to force a full handshake rather than just 
			  pulling a previous session out of the session cache.  
			  
			  In late 2014 Amazon disabled SSLv3 on all of its servers, 
			  Paypal disabled it in early 2015 and then disabled TLS 1.0 in 
			  2019, Google disabled it in mid 2016, Red Hat disabled TLS 1.1
			  in 2019 and Google in 2024 partially (it seems to depend on
			  which location you connect to or possibly the availability of
			  ECDH in the client hello, which isn't actually valid in TLS 
			  1.1 or 1.0 which also works) which is what these servers were 
			  used to test, so eventually we'll use any number of US banks, 
			  which will hopefully keep supporting insecure modes more or 
			  less forever, see the entries around #45 for samples.  Use:
			  
				openssl s_client -connect <server>:443 -tls1
				openssl s_client -connect <server>:443 -tls1_1

			  to check for support of older protocols, however note that
			  getting the error "tls_setup_handshake:no protocols available"
			  means that it's not enabled in OpenSSL, not that the server
			  doesn't support it.  This can be addressed by adding to 
			  /etc/ssl/openssl.cnf:
			  
				openssl_conf = openssl_init

				[openssl_init]
				ssl_conf = ssl_configuration

				[ssl_configuration]
				system_default = tls_system_default

				[tls_system_default]
				MinProtocol = TLSv1.0
				CipherString = DEFAULT@SECLEVEL=0

			  (the last entry is required to re-enable SHA-1, without that 
			  the MinProtocol will have no effect).
			  
			  Use:

				https://www.ssllabs.com/ssltest/

			  to check for cipher suites supported.
			  
			  In addition as part of the deprecation of SHA-1 in early 2016 
			  Comodo, used by the Red Hat server, switched its CA certs to 
			  SHA-384, so we need to enable the use of the extended SHA-2 
			  hash functions to deal with this.
	Server 5: ~40K data returned.  Returns an incorrect certificate for the
			  server when using TLS, although when accessed from a web
			  browser it works as expected.
	Server 6: Sends zero-length blocks (actually a POP server).  This server
			  is accessible under two names, pop.web.de and pop3.web.de,
			  but the certificate is for pop3.web.de.  In addition the
			  certificate has the host name in both the CN and 
			  altName.domainName, allowing both code paths to be tested.
	Server 7: Novell GroupWise, requires CRYPT_OPTION_CERT_COMPLIANCELEVEL = 
			  CRYPT_COMPLIANCELEVEL_OBLIVIOUS due to b0rken certs.
	Server 8: (Causes MAC failure during handshake when called from PMail, 
			   works OK when called here).
	Server 9: Can only do crippled crypto (not even conventional crippled 
			  crypto but RC4-56) and instead of sending an alert for this 
			  just drops the connection (this may be caused by the NetApp 
			  NetCache it's using).  This site is also running an Apache 
			  server that claims it's optimised for MSIE, and that the page 
			  won't work properly for non-MSIE browsers.  The mind 
			  boggles...
	Server 10: Server ("Hitachi Web Server 02-00") can only do SSL, when 
			   cryptlib is set to perform a TLS handshake (i.e. cryptlib is 
			   told to expect TLS but falls back to SSL), goes through the 
			   full handshake, then returns a handshake failure alert.  The 
			   same occurs for other apps (e.g. MSIE) when TLS is enabled.
	Server 11: Buggy older IIS that can only do crippled crypto and drops 
			   the connection as soon as it sees the client hello 
			   advertising strong crypto only.
	Server 12: Newer IIS (certificate is actually for akamai.net, so the TLS 
			   may not be Microsoft's at all).
	Server 13: IBM (Websphere?).
	Server 14: Server is running TLS with SSL disabled, drops connection 
			   when it sees an SSL handshake.  MSIE in its default config 
			   (TLS disabled) can't connect to this server.
	Server 15: GnuTLS.
	Server 16: GnuTLS test server with TLS 1.1.
	Server 17: Can only do SSLv2, server hangs when sent an SSLv3 handshake.
	Server 18: Can't handle TLS 1.1 handshake (drops connection).  In 
			   addition the server returns a certificate chain leading up
			   to a Verisign MD2 root that gets rejected due to the use of
			   MD2.
	Server 19: Can't handle TLS 1.1 handshake (drops connection).  Both of 
			   these servers are sitting behind NetApp NetCaches (see also 
			   server #9), which could be the cause of the problem.
	Server 20: Generic OpenSSL server.
	Server 21: Crippled crypto using NS Server 3.6.
	Server 22: Apache with Thawte certs, requires 
			   CRYPT_OPTION_CERT_COMPLIANCELEVEL = 
			   CRYPT_COMPLIANCELEVEL_REDUCED due to b0rken certs.
	Server 23: Supports TLS-ext, max-fragment-size extension, session 
			   tickets, TLS 1.2, and assorted other odds and ends, but 
			   not ECC or GCM, reports info on connect in handy text 
			   format.  Will also perform client-auth verification if the 
			   client sends a client-auth message, accepting any cert and 
			   using it to verify the handshake-data signature.  Uses the
			   1024-bit DH value from RFC 2409, see also server 46.
	Server 24: GnuTLS server supporting all sorts of oddities (PGP certs, 
			   SRP, compression, TLS-ext, and others, see 
			   http://www.gnu.org/software/gnutls/server.html for details), 
			   reports info on connect in HTML table format.  Note that this 
			   server claims to support TLS 1.2 but returns a TLS 1.1 server 
			   hello in response to a TLS 1.2 handshake request for several 
			   different TLS 1.2 client implementations.
	Server 25: Supports SNI extension and reports info on connect, can 
			   connect to either alice.sni.velox.ch or carol.sni.velox.ch.
			   A connect to the default sni.velox.ch will return a 
			   certificate-mismatch error.
	Server 26: Certicom server using ECDSA P256.  Returns a server cert with  
			   a bizarro X9.62 OID with implied sub-parameters that can't be 
			   handled (at least in a sane manner) by the AlgoID read code.
	Server 27: RedHat server using NSS for ECC support for ECDSA P256.  This 
			   server doesn't support any non-ECC suites, making it useful 
			   for testing handling of the ECC-only case.  Vanished some 
			   time in 2020.
	Server 28: Certicom umbrella server (see #26) that also does TLS 1.2 
			   under very restricted circumstances (see below) and GCM.  
			   Details at https://tls.secg.org/, transaction log at 
			   https://tls.secg.org/index1.php?action=https_log (this log 
			   rolls over fairly quickly, requiring opening the last several 
			   entries and matching cipher suites to see which one was 
			   yours).  Note that this server claims to support TLS 1.2 but 
			   returns a TLS 1.1 server hello in response to a TLS 1.2 
			   handshake request unless you report DHE_DSS as your only 
			   available cipher suite.  A more standard combination like 
			   RSA or DHE_RSA results in the server returning a TLS 1.1 
			   response, and an attempt to force matters with a TLS 1.2-only 
			   cipher suite like DHE_AES_GCM returns an alert message with 
			   the version number set to SSLv3, i.e. { 3, 0 }.  This server
			   also has a certificate in which the CN is a combination of
			   the server FQDN and further text, requiring a match on the
			   altName even though the first part of the DN would also
			   match.
	Server 29: Microsoft interop test server that does TLS 1.2, ECC, and 
			   unlike GnuTLS and Certicom/SECG it actually really does TLS 
			   1.2.  This is the generic interface with all cipher suites, 
			   see Server #30 and #31 for variants.  This server also claims 
			   to support GCM (although only with ECC, not with RSA/DSA) but 
			   in practice closes the connection when sent a client hello 
			   with this cipher suite.  Went away some time in 2019.  
	Server 30: As Server #29 but restricted to 256-bit ECC only, this server 
			   does actually support GCM.  Requires 
			   CRYPT_OPTION_CERT_COMPLIANCELEVEL = 
			   CRYPT_COMPLIANCELEVEL_OBLIVIOUS due to b0rken certs.
	Server 31: As server #29 but restricted to 384-bit ECC only, however it 
			   closes the connection when sent a SHA-384 cipher suite.
	Server 32: As Server #29 but tests rehandshake handling.  This is 
			   actually meant to test RSA client authentication, i.e. 
			   TLS_TEST_CLIENTCERT, but Windows implements this by 
			   performning a standard handshake without client-auth and then 
			   immediately performing a rehandshake with client-auth, which 
			   can be used to test the ability to handle a rehandshake 
			   request.  In practice the Windows server hangs waiting for 
			   the rehandshake, so eventually we exit with a read timeout 
			   error.
	Server 33: RSA interop server, this requires a complex pre-approval 
			   application process to enable access which makes it not worth 
			   the bother, it's only listed here for completeness.
	Server 34: Encrypt-then-MAC extension support.
	Server 35: DHE-PSK support via PolarSSL, name = gutman, 
			   PSK = 0x0123456789abcdef.
	Server 36: Returns a certificate with "outlook.com" in the CN, requires
			   matching the altName to find "smtp.office365.com".
	Server 37: Returns (deliberately) invalid DH parameters to test whether
			   clients check these.
	Server 38: As #37, 768-bit DH.
	Server 39: As #37, but valid 2048-bit DH.
	Server 40: As #37, but valid 2048-bit DH with 2048-bit DSA.
	Server 41: As #37, but valid 2048-bit DH with 1024-bit DSA.
	Server 42: As #37, but invalid (non-prime) 1024-bit DH.
	Server 43: Checks for SKIP-TLS vulnerability.
	Server 44: MiTLS reference implementation, but doesn't seem to implement
			   much out of the ordinary.
	Server 45: Remaining SSLv3 server in 2016, SSLv3 disabled 2017.
	Server 46: As server 23 but with the 2048-bit DH value from RFC 3526.
	Server 47: Rejects any connect attempt where extensions are present.
			   Alternative server is 
			   https://preprod.connect.elemica.com:5443.
	Server 48: nmap.org deliberately-insecure test server, however even this
			   doesn't do SSLv3 any more.
	Server 49: WebSockets local loopback.
	Server 50: WebSockets echo test server, direct access.  Note that this 
			   returns a certificate chain with a broken GoDaddy certificate
			   with RSA e = 3, which will need a safety check in kg_rsa.c
			   disabled.
	Server 51: WebSockets echo test server, URL access.  See #50 for the
			   GoDaddy certificate issue.
	Server 52: WebSockets AMQP test server.  See #50 for the GoDaddy 
			   certificate issue.
	Server 53: EAPlab EAP public test server, see
			   https://eaplab.supplicants.net/.
	Server 54: IronWiFi EAP public test server, see 
			   https://www.ironwifi.com/captive-portal-demos/.
	Server 55: IronWiFi EAP private demo test server.
	Server 56: FreeRADIUS local test server. 
	Server 57: Reported to cause SIGFPE's in some builds of (OpenSSL's) 
			   BN_div(), but unable to reproduce across multiple cryptlib
			   platforms.
	Server 58: Sends a CertificateRequest larger than the maximum packet 
			   size.
	Server 59: Refuses a handshake with anything less than TLS 1.2 but then
			   uses a certificate with RSA exponent 3.
	Server 60: Sends an Illegal Parameter TLS alert on connect.
	Server 61: Will negotiate SHA-384 on connect if it's enabled.
	Server 62: Rejects TLS 1.0, works with TLS 1.1, drops the connection
			   with TLS 1.2.  According to Qualys SSLLabs only supports TLS 
			   1.2 and 1.1 with ECDHE_RSA_xxx and RSA_xxx suites.
	Server 63: Redirected to via HTTP from Server 62, now allows TLS 1.0
			   and 1.1 but the same behaviour as Server 62 for TLS 1.2.  Has
			   a certificate from a completely different CA to Server 62.
			   According to Qualys SSLLabs only supports ECDHE_RSA_xxx and 
			   RSA_xxx cipher suites.
	Server 64: Sends a Handshake Failed TLS alert on connect.  According to
			   Qualys SSLLabs hosted by cloudflaressl.com.
	Server 65: Sends the DH keyex value with g being 255 zero bytes followed 
			   by 0x02.  According to Qualys SSLLabs hosted by 
			   cloudflaressl.com.
	Server 66: Sends 27kB certificate request packet.
	Server 67: OpenSSL s_server test system.
	Server 68: Rejects any attempt to connect with a handshake failure alert.
	Server 69: Returns a certificate chain with an 8,192-bit key.
	Server 70: Reported to cause problems but cryptlib connects OK.
	Server 71: As of 2025 the only known server that does Ed25519 signing.
	Server 72: Server that still does TLS 1.1 */

#define SSL_SERVER_NO	48	/* Probably extinct, this was last known one */
#define TLS_SERVER_NO	4	/* No longer does TLS 1.0 */
#define TLS11_SERVER_NO	72	/* See note about Google in the 2-4 range */
#define TLS12_SERVER_NO	23	/* Options = #23, #24, #28, #29/30/31
							   (but see above for #24, #28, and some of 
							   #29) */
#define TLS13_SERVER_NO	12
#define WS_SERVER_NO	50
#define EAP_SERVER_NO	56
#if ( TLS_SERVER_NO == TLS11_SERVER_NO ) || \
	( TLS_SERVER_NO == TLS12_SERVER_NO ) || \
	( TLS_SERVER_NO == TLS13_SERVER_NO ) || \
	( TLS11_SERVER_NO == TLS12_SERVER_NO ) || \
	( TLS11_SERVER_NO == TLS13_SERVER_NO ) || \
	( TLS12_SERVER_NO == TLS13_SERVER_NO )
  #error TLS/TLS11/TLS12/TLS13 servers must be distinct to avoid tests being skipped due to session cacheing
#endif /* Make sure that servers are distinct */

#if 0
  /* Defines to allow testing of problem servers */
  #undef TLS_SERVER_NO
  #undef TLS11_SERVER_NO
  #undef TLS12_SERVER_NO
  #undef TLS13_SERVER_NO
  #define TLS_SERVER_NO		70
  #define TLS11_SERVER_NO	TLS_SERVER_NO
  #define TLS12_SERVER_NO	TLS_SERVER_NO
  #define TLS13_SERVER_NO	TLS_SERVER_NO
#endif /* 0 */

#if ( TLS_SERVER_NO == 35 )
  #undef TLS_USER_NAME
  #undef TLS_PASSWORD
  #define TLS_USER_NAME		"gutman"
  #define TLS_PASSWORD		"\x01\x23\x45\x67\x89\xab\xcd\xef"
#endif /* DHE-PSK test server */

static const struct {
	const C_STR name;
	const C_STR path;
	const C_STR userName;
	const C_STR password;
	} tlsInfo[] = {
	{ NULL, NULL },
	/*  1 */ { TEXT( LOCAL_HOST_NAME ), "/" },
	/*  2X	 { TEXT( "https://www.amazon.com" ), "/" }, */
	/*  2 */ { TEXT( "https://www.google.com" ), "/" },
	/*  3X	 { TEXT( "https://www.paypal.com" ), "/" }, */
	/*	3 */ { TEXT( "https://www.amazon.com" ), "/" }, 
	/*  4 */ { TEXT( "https://www.google.com" ), "/" }, 
	/*  5 */ { TEXT( "https://www.cs.berkeley.edu" ), "/~daw/people/crypto.html" },
	/*  6 */ { TEXT( "pop.web.de:995" ), "/" },
	/*  7 */ { TEXT( "imap4-gw.uni-regensburg.de:993" ), "/" },
	/*  8 */ { TEXT( "securepop.t-online.de:995" ), "/" },
	/*  9 */ { TEXT( "https://homedir.wlv.ac.uk" ), "/" },
	/* 10 */ { TEXT( "https://www.horaso.com:20443" ), "/" },
	/* 11 */ { TEXT( "https://homedir.wlv.ac.uk" ), "/" },
	/* 12 */ { TEXT( "https://www.microsoft.com" ), "/" },
	/* 13 */ { TEXT( "https://alphaworks.ibm.com/" ), "/" },
	/* 14 */ { TEXT( "https://webmount.turbulent.ca/" ), "/" },
	/* 15 */ { TEXT( "https://www.gnutls.org/" ), "/" },
	/* 16 */ { TEXT( "https://www.gnutls.org:5555/" ), "/" },
	/* 17 */ { TEXT( "https://www.networksolutions.com/" ), "/" },
	/* 18 */ { TEXT( "https://olb.westpac.com.au/" ), "/" },
	/* 19 */ { TEXT( "https://www.hertz.com/" ), "/" },
	/* 20 */ { TEXT( "https://www.openssl.org/" ), "/" },
	/* 21 */ { TEXT( "https://secureads.ft.com/" ), "/" },
	/* 22 */ { TEXT( "https://mail.maine.edu/" ), "/" },
	/* 23 */ { TEXT( "https://www.mikestoolbox.org/" ), "/" },
	/* 24 */ { TEXT( "https://test.gnutls.org:5556/" ), "/" },
	/* 25 */ { TEXT( "https://sni.velox.ch/" ), "/" },
	/* 26 */ { TEXT( "https://tls.secg.org:40023/connect.php" ), "/" },
	/* 27 */ { TEXT( "https://ecc.fedora.redhat.com" ), "/" },
	/* 28 */ { TEXT( "https://tls.secg.org/" ), "/" },
	/* 29 */ { TEXT( "https://tls.woodgrovebank.com:25000/" ), "/" },
	/* 30 */ { TEXT( "https://tls.woodgrovebank.com:25002/" ), "/" },
	/* 31 */ { TEXT( "https://tls.woodgrovebank.com:25003/" ), "/" },
	/* 32 */ { TEXT( "https://tls.woodgrovebank.com:25005/" ), "/" },
	/* 33 */ { TEXT( "https://203.166.62.199/" ), "/" },
	/* 34 */ { TEXT( "https://eid.vx4.net" ), "/" },
	/* 35 */ { TEXT( "https://beta.polarssl.org:4433" ), "/" },
	/* 36 */ { TEXT( "https://smtp.office365.com" ), "/" },
	/* 37 */ { TEXT( "https://demo.cmrg.net/" ), "/" },
	/* 38 */ { TEXT( "https://dh768.tlsfun.de/" ), "/" },
	/* 39 */ { TEXT( "https://dh2048.tlsfun.de/" ), "/" },
	/* 40 */ { TEXT( "https://dh2048-dsa.tlsfun.de/" ), "/" },
	/* 41 */ { TEXT( "https://dh2048-dsa1024.tlsfun.de/" ), "/" },
	/* 42 */ { TEXT( "https://dh1024nop.tlsfun.de/" ), "/" },
	/* 43 */ { TEXT( "https://ht.vc:6443" ), "/" },
	/* 44 */ { TEXT( "https://mitls.org/" ), "/" },
	/* 45 */ { TEXT( "https://firstus.org/" ), "/" },
	/* 46 */ { TEXT( "https://www.mikestoolbox.org/" ), "/" },
	/* 47 */ { TEXT( "https://connect.elemica.com:5443" ), "/" },
	/* 48 */ { TEXT( "https://www.insecure.org/nmap/" ), "/" },
	/* 49 */ { TEXT( "wss://" LOCAL_HOST_NAME ), "/" },
	/* 50 */ { TEXT( "wss://echo.websocket.org" ), "/" },
	/* 51 */ { TEXT( "wss://demos.kaazing.com/echo" ), "/" },
	/* 52 */ { TEXT( "wss://demos.kaazing.com/amqp" ), "/" },
	/* 53 */ { TEXT( "radius.supplicants.net:1812" ), "/", "eaplab@r1.supplicants.net", "????" },
	/* 54 */ { TEXT( "130.211.138.166:7197" ), "/", "demouser", "????" },
	/* 55 */ { TEXT( "35.197.133.220:11315" ), "/", "test", "test" },
	/* 56 */ { TEXT( "192.168.1.36:1812" ), "/", "test", "test" },
	/* 57 */ { TEXT( "excalibur.mudcovered.org.uk" ), "/" },
	/* 58 */ { TEXT( "testacig.ariba.com" ), "/as2/as2" },
	/* 59 */ { TEXT( "api.livevox.com" ), "/" },
	/* 60 */ { TEXT( "pp-us-b2bws.royalcanin.com" ), "/ipbaspx20-cs/as2server.aspx" },
	/* 61 */ { TEXT( "b2bqa.cat.com" ), "/" },
	/* 62 */ { TEXT( "www.ibocentral.com" ), "/" },
	/* 63 */ { TEXT( "www.ibocity.com" ), "/" },
	/* 64 */ { TEXT( "as2.edi-connect.com" ), "/" },
	/* 65 */ { TEXT( "www.messagexchange.com" ), "/" },
	/* 66 */ { TEXT( "wmprod.arroweuropeconnects.com" ), "/" },
	/* 67 */ { TEXT( "odroid.n2.lan:4433" ), "/" },
	/* 68 */ { TEXT( "ca.silabs.com" ), "/Device-Root-CA-chain.pem" },
	/* 69 */ { TEXT( "80.228.241.47:6619" ), "/" },
	/* 70 */ { TEXT( "as2.aldi-nord.ondemand.services" ), "/" },
	/* 71 */ { TEXT( "ed25519-test.germancoding.com" ), "/" },
	/* 72 */ { TEXT( "www.trinity.ie" ), "/" },
	{ NULL, NULL }
	};

static const struct {
	const TLS_TEST_TYPE testType;
	const C_STR path;
	const BOOLEAN result;
	} badSslInfo[] = {
	{ TLS_TEST_BADSSL_DH512, TEXT( "https://dh512.badssl.com/" ), FALSE },
	{ TLS_TEST_BADSSL_DH1024, 
	  TEXT( "https://dh1024.badssl.com/" ), TRUE },
	{ TLS_TEST_BADSSL_DH2048, 
	  TEXT( "https://dh2048.badssl.com/" ), TRUE },
	{ TLS_TEST_BADSSL_DHSMALLSUBGROUP, 
	  TEXT( "https://dh-small-subgroup.badssl.com/" ), FALSE },
	{ TLS_TEST_BADSSL_DHCOMPOSITE, 
	  TEXT( "https://dh-composite.badssl.com/" ), FALSE },
#ifdef USE_RSA_SUITES
	{ TLS_TEST_BADSSL_STATICRSA, 
	  TEXT( "https://static-rsa.badssl.com/" ), TRUE },
	{ TLS_TEST_BADSSL_RSA2048, 
	  TEXT( "https://rsa2048.badssl.com/" ), TRUE },
#else
	{ TLS_TEST_BADSSL_STATICRSA, 
	  TEXT( "https://static-rsa.badssl.com/" ), FALSE },
	{ TLS_TEST_BADSSL_RSA2048, 
	  TEXT( "https://rsa2048.badssl.com/" ), FALSE },
#endif /* USE_RSA_SUITES */
#if defined( USE_ECDSA ) && defined( USE_ECDH )
	/* However see comment before the include of config.h, this doesn't work 
	   with mixed debug/release builds */
	{ TLS_TEST_BADSSL_ECC256, TEXT( "https://ecc256.badssl.com/" ), TRUE },
#else
	{ TLS_TEST_BADSSL_ECC256, TEXT( "https://ecc256.badssl.com/" ), FALSE },
#endif /* USE_ECDSA && USE_ECDH */
	{ TLS_TEST_BADSSL_CBC, TEXT( "https://cbc.badssl.com/" ), TRUE },
	{ TLS_TEST_BADSSL_RC4MD5, TEXT( "https://rc4-md5.badssl.com/" ), FALSE },
	{ TLS_TEST_BADSSL_RC4, TEXT( "https://rc4.badssl.com/" ), FALSE },
	{ TLS_TEST_BADSSL_3DES, TEXT( "https://3des.badssl.com/" ), TRUE },
	{ TLS_TEST_BADSSL_NOCN, 
	  TEXT( "https://no-common-name.badssl.com/" ), TRUE },
#ifdef USE_CERTLEVEL_PKIX_FULL
	{ TLS_TEST_BADSSL_NOSUBJECT, 
	  TEXT( "https://no-subject.badssl.com" ), TRUE },		/* Name is in altName */
#else
	{ TLS_TEST_BADSSL_NOSUBJECT, 
	  TEXT( "https://no-subject.badssl.com" ), FALSE },		/* Name is in altName */
#endif /* USE_CERTLEVEL_PKIX_FULL */
	{ TLS_TEST_BADSSL_LONGNAME1, 
	  TEXT( "https://long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com/" ), TRUE },
	{ TLS_TEST_BADSSL_LONGNAME2, 
	  TEXT( "https://longextendedsubdomainnamewithoutdashesinordertotestwordwrapping.badssl.com/" ), TRUE },
	{ 0, NULL }
	};

/* Various servers used for STARTTLS/STLS/AUTH TLS testing.  Notes:

	Server 1: SMTP: mailbox.ucsd.edu:25, requires a client certificate.
	Server 2: POP: pop.cae.wisc.edu:1110, OK.
	Server 3: SMTP: smtpauth.cae.wisc.edu:25, requires a client certificate.
	Server 4: SMTP: send.columbia.edu:25, returns invalid certificate (lower 
			  compliance level to fix).
	Server 5: POP: pop3.myrealbox.com:110, returns invalid certificate 
			  (lower compliance level to fix).
	Server 6: Encrypted POP: securepop.t-online.de:995, direct TLS connect.
	Server 7: FTP: ftp.windsorchapel.net:21, sends redundant client 
			  certificate request with invalid length.
	Server 8: POP: webmail.chm.tu-dresden.de:110, another GroupWise server 
			  (see the server comments above) with b0rken certs.

			  To test FTP with TLS manually: Disable auto-login with FTP, 
			  then send an RFC 2389 FEAT command to check security 
			  facilities.  If this is supported, one of the responses will 
			  be either AUTH SSL or AUTH TLS, use this to turn on TLS.  If 
			  FEAT isn't supported, AUTH TLS should usually work:

				ftp -n ftp.windsorchapel.net
				quote feat
				quote auth ssl

			  or just:

				telnet ftp.windsorchapel.net 21
				auth ssl

	Server 9: SMTP: mailer.gwdg.de:25, sends each TLS message as a discrete 
			  packet, providing a nice test of cryptlib's on-demand buffer 
			  refill.
	Server 10: Encrypted POP: mrdo.vosn.net:995, direct TLS connect, sends 
			   a CA certificate which is also used for encryption, but with 
			   no keyUsage flags set.
	Server 11: POP: pop.gmail.com:995.  Formerly STARTTLS, now requires a 
			   direct TLS connect.
	Server 12: POP: mail.rochester.edu:995, direct TLS connect (also sends 
			   zero-length packets as a kludge for pre-TLS 1.1 chosen-IV 
			   attacks).
	Server 13: SMTP: smtp.umn.edu:465, direct TLS connect.
	Server 14: POP3: pop3.live.com:995, direct TLS connect, returns a 
			   malformed certificate.  Can also be accessed via 
			   smtp.live.com, port 25 or 587.
	Server 15: Same as TLS server no.62 */	

#define STARTTLS_SERVER_NO	11

typedef enum { PROTOCOL_NONE, PROTOCOL_SMTP, PROTOCOL_SMTP_DIRECT, 
			   PROTOCOL_POP, PROTOCOL_IMAP, PROTOCOL_POP_DIRECT, 
			   PROTOCOL_FTP
			 } PROTOCOL_TYPE;

static const struct {
	const C_STR name;
	const int port;
	PROTOCOL_TYPE protocol;
	} starttlsInfo[] = {
	{ NULL, 0 },
	/*  1 */ { TEXT( "mailbox.ucsd.edu" ), 25, PROTOCOL_SMTP },
	/*  2 */ { TEXT( "pop.cae.wisc.edu" ), 1110, PROTOCOL_POP },
	/*  3 */ { TEXT( "smtpauth.cae.wisc.edu" ), 25, PROTOCOL_SMTP },
	/*  4 */ { TEXT( "send.columbia.edu" ), 25, PROTOCOL_SMTP },
	/*  5 */ { TEXT( "pop3.myrealbox.com" ), 110, PROTOCOL_POP },
	/*  6 */ { TEXT( "securepop.t-online.de" ), 995, PROTOCOL_POP_DIRECT },
	/*  7 */ { TEXT( "ftp.windsorchapel.net" ), 21, PROTOCOL_FTP },
	/*  8 */ { TEXT( "webmail.chm.tu-dresden.de" ), 110, PROTOCOL_POP },
	/*  9 */ { TEXT( "mailer.gwdg.de" ), 25, PROTOCOL_SMTP },
	/* 10 */ { TEXT( "mrdo.vosn.net" ), 995, PROTOCOL_POP_DIRECT },
	/* 11 */ { TEXT( "pop.gmail.com" ), 995, PROTOCOL_POP_DIRECT },
	/* 12 */ { TEXT( "mail.rochester.edu" ), 995, PROTOCOL_POP_DIRECT },
	/* 13 */ { TEXT( "smtp.umn.edu" ), 465, PROTOCOL_SMTP_DIRECT },
	/* 14 */ { TEXT( "pop3.live.com" ), 995, PROTOCOL_POP_DIRECT },
	/* 15 */ { TEXT( "216.27.43.34" ), 21, PROTOCOL_FTP },
	{ NULL, 0 }
	};

/* Special-case handling for buggy/broken/odd servers */

#if ( SSL_SERVER_NO == 7 ) || ( TLS12_SERVER_NO == 30 ) || \
	( TLS12_SERVER_NO == 31 ) || ( STARTTLS_SERVER_NO == 8 )
  #define BROKEN_SERVER_INVALID_CERT
  #if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
 	#pragma message( "  Building with reduced compliance level for buggy TLS server." )
  #endif /* Notify reduced compliance level */
#endif /* Broken servers */
#if ( SSL_SERVER_NO == 3 )
  #define IS_HIGHVOLUME_SERVER
#endif /* Servers with high result volume */

/* If we're testing dual-thread handling of sessions, we need to provide a 
   forward declaration of the threading function since it's called from 
   within the TLS connect code */

#if defined( WINDOWS_THREADS )
  static unsigned __stdcall tlsServerDualThread2( void *dummy );
#elif defined( UNIX_THREADS )
  static void *tlsServerDualThread2( void *dummy );
#endif /* WINDOWS_THREADS */

/* Large buffer size to test bulk data transfer capability for secure
   sessions */

#if defined( __MSDOS16__ ) || defined( __WIN16__ )
  #define BULKDATA_BUFFER_SIZE	20000L
#elif defined( __WINDOWS__ ) && defined( _MSC_VER ) && ( _MSC_VER == 1200 ) && \
	  !defined( NDEBUG ) && 1
  #define BULKDATA_BUFFER_SIZE	300000L
  #define USE_TIMING			/* Report data-transfer time */
#else
  #define BULKDATA_BUFFER_SIZE	300000L
#endif /* 16-bit VC++ */

static int checksumData( const void *data, const int dataLength )
	{
	const BYTE *dataPtr = data;
	int sum1 = 0, sum2 = 0, i;

	/* Calculate a 16-bit Fletcher-like checksum of the data (it doesn't 
	   really matter if it's not exactly right, as long as the behaviour is 
	   the same for all data) */
	for( i = 0; i < dataLength; i++ )
		{
		sum1 += dataPtr[ i ];
		sum2 += sum1;
		}

	return( sum2 & 0xFFFF );
	}

static BOOLEAN handleBulkBuffer( BYTE *buffer, const BOOLEAN isInit )
	{
	int checkSum, i;

	/* If we're initialising the buffer, fill it with [0...256]* followed by 
	   a checksum of the buffer contents */
	if( isInit )
		{
		for( i = 0; i < BULKDATA_BUFFER_SIZE - 2; i++ )
			buffer[ i ] = i & 0xFF;
		checkSum = checksumData( buffer, BULKDATA_BUFFER_SIZE - 2 );
		buffer[ BULKDATA_BUFFER_SIZE - 2 ] = ( checkSum >> 8 ) & 0xFF;
		buffer[ BULKDATA_BUFFER_SIZE - 1 ] = checkSum & 0xFF;

		return( TRUE );
		}

	/* We're being sent an initialised buffer, make sure that it's OK */
	for( i = 0; i < BULKDATA_BUFFER_SIZE - 2; i++ )
		{
		if( buffer[ i ] != ( i & 0xFF )	)
			return( FALSE );
		}
	checkSum = checksumData( buffer, BULKDATA_BUFFER_SIZE - 2 );
	if( buffer[ BULKDATA_BUFFER_SIZE - 2 ] != ( ( checkSum >> 8 ) & 0xFF ) || \
		buffer[ BULKDATA_BUFFER_SIZE - 1 ] != ( checkSum & 0xFF ) )
		return( FALSE );

	return( TRUE );
	}

/****************************************************************************
*																			*
*								Local Socket Handling						*
*																			*
****************************************************************************/

/* Testing this capability fully requires a lot of OS-specific juggling so 
   unless we're running under Windows or Linux we just supply the handle to 
   stdin, which will return a read/write error during the connect.  This 
   checks that the handle has been assigned corectly without requiring a lot 
   of OS-specific socket handling code.  Otherwise, we use a (very cut-down) 
   set of socket calls to set up a minimal socket.  Since there's very little 
   error-checking done, we don't treat a  failure as fatal */

#ifdef USE_LOCAL_SOCKETS

static BOOLEAN initSockets( void )
	{
  #ifdef __WINDOWS__
	WSADATA wsaData;

	if( WSAStartup( 2, &wsaData ) )
		{
		fprintf( outputStream, "Couldn't initialise sockets interface, line "
				 "%d.\n", __LINE__ );
		return( FALSE );
		}
  #endif /* __WINDOWS__ */

	return( TRUE );
	}

static void endSockets( const SOCKET netSocket )
	{
	if( netSocket != 0 )
		closesocket( netSocket );

	/* In theory we should be calling WSACleanup() at this point, however */
  #ifdef __WINDOWS__
	WSACleanup();
  #endif /* __WINDOWS__ */
	}

/* Hand a socket over to cryptlib */

static int setSocket( const CRYPT_SESSION cryptSession,
					  const SOCKET netSocket )
	{
  #if defined( _MSC_VER ) && defined( _M_X64 )
	return( cryptSetAttribute( cryptSession, CRYPT_SESSINFO_NETWORKSOCKET, 
							   ( int ) netSocket ) );
  #else
	return( cryptSetAttribute( cryptSession, CRYPT_SESSINFO_NETWORKSOCKET, 
							   netSocket ) );
  #endif /* 64-bit Windows */
	}

/* Set up a client user-defined socket by negotiating through a STARTTLS */

static int readLine( SOCKET netSocket, BYTE *buffer, const int bufSize )
	{
	int bufPos, status = CRYPT_OK;

	for( bufPos = 0; \
		 status >= 0 && bufPos < bufSize && \
			( bufPos < 1 || buffer[ bufPos -1 ] != '\n' );
		 bufPos++ )
		{
		status = recv( netSocket, buffer + bufPos, 1, 0 );
		}
	while( bufPos > 1 && isspace( buffer[ bufPos - 1 ] ) )
		bufPos--;
	buffer[ min( bufPos, 56 ) ] = '\0';

	return( bufPos );
	}

static SOCKET negotiateSTARTTLS( int *protocol )
	{
	SOCKET netSocket;
	struct sockaddr_in serverAddr;
	struct hostent *hostInfo;
	BYTE buffer[ 1024 ];
	int bufPos, status;

	fputs( "Negotiating SMTP/POP/IMAP/FTP session through to TLS start...\n", 
		   outputStream );
	*protocol = starttlsInfo[ STARTTLS_SERVER_NO ].protocol;

	/* Look up the server's IP address */
	hostInfo = gethostbyname( starttlsInfo[ STARTTLS_SERVER_NO ].name );
	if( hostInfo == NULL )
		{
		fprintf( outputStream, "Couldn't resolve hostname %s, line %d.\n", 
				 starttlsInfo[ STARTTLS_SERVER_NO ].name, __LINE__ );
		return( CRYPT_ERROR_FAILED );
		}

	/* Create a network socket to connect */
	netSocket = socket( PF_INET, SOCK_STREAM, 0 );
	if( netSocket == INVALID_SOCKET )
		{
		fprintf( outputStream, "Couldn't create socket, line %d.\n", 
				 __LINE__ );
		return( CRYPT_ERROR_FAILED );
		}

	/* Connect to a generally-available server to test STARTTLS/STLS
	   functionality */
	memset( &serverAddr, 0, sizeof( struct sockaddr_in ) );
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr = *( ( struct in_addr * ) hostInfo->h_addr_list[ 0 ] );
	serverAddr.sin_port = htons( ( u_short ) starttlsInfo[ STARTTLS_SERVER_NO ].port );
	status = connect( netSocket, ( struct sockaddr * ) &serverAddr,
					  sizeof( struct sockaddr_in ) );
	if( status == SOCKET_ERROR )
		{
		closesocket( netSocket );
		fprintf( outputStream, "Couldn't connect socket, line %d.\n", 
				 __LINE__ );
		return( CRYPT_OK );		/* Signal non-fatal error */
		}

	/* If it's a direct connect, there's nothing left to do */
	if( *protocol == PROTOCOL_POP_DIRECT )
		{
		*protocol = PROTOCOL_POP;
		return( netSocket );
		}
	if( *protocol == PROTOCOL_SMTP_DIRECT )
		{
		*protocol = PROTOCOL_SMTP;
		return( netSocket );
		}

	/* Perform (very crude) SMTP/POP/IMAP negotiation to switch to TLS */
	bufPos = readLine( netSocket, buffer, 1024 );
	if( bufPos < 3 || ( strncmp( buffer, "220", 3 ) && \
						strncmp( buffer, "+OK", 3 ) && \
						strncmp( buffer, "OK", 2 ) ) )
		{
		closesocket( netSocket );
		fprintf( outputStream, "Got response '%s', line %d.\n", buffer, 
				 __LINE__ );
		return( CRYPT_OK );		/* Signal non-fatal error */
		}
	fprintf( outputStream, "  Server said: '%s'\n", buffer );
	assert( ( *protocol == PROTOCOL_SMTP && !strncmp( buffer, "220", 3 ) ) || \
			( *protocol == PROTOCOL_POP && !strncmp( buffer, "+OK", 3 ) ) || \
			( *protocol == PROTOCOL_IMAP && !strncmp( buffer, "OK", 2 ) ) || \
			( *protocol == PROTOCOL_FTP && !strncmp( buffer, "220", 3 ) ) || \
			*protocol == PROTOCOL_NONE );
	switch( *protocol )
		{
		case PROTOCOL_POP:
			send( netSocket, "STLS\r\n", 6, 0 );
			fputs( "  We said: 'STLS'", outputStream );
			break;

		case PROTOCOL_IMAP:
			/* It's possible for some servers that we may need to explicitly 
			   send a CAPABILITY command first to enable STARTTLS:
				a001 CAPABILITY
				> CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED
				> OK CAPABILITY completed */
			send( netSocket, "a001 STARTTLS\r\n", 15, 0 );
			fputs( "  We said: 'STARTTLS'", outputStream );
			break;

		case PROTOCOL_SMTP:
			send( netSocket, "EHLO foo.bar.com\r\n", 18, 0 );
			fputs( "  We said: 'EHLO foo.bar.com'", outputStream );
			do
				{
				bufPos = readLine( netSocket, buffer, 1024 );
				if( bufPos < 3 || strncmp( buffer, "250", 3 ) )
					{
					closesocket( netSocket );
					fprintf( outputStream, "Got response '%s', line %d.\n", 
							 buffer, __LINE__ );
					return( CRYPT_OK );		/* Signal non-fatal error */
					}
				fprintf( outputStream, "  Server said: '%s'\n", buffer );
				}
			while( !strncmp( buffer, "250-", 4 ) );
			send( netSocket, "STARTTLS\r\n", 10, 0 );
			fputs( "  We said: 'STARTTLS'", outputStream );
			break;

		case PROTOCOL_FTP:
			send( netSocket, "AUTH TLS\r\n", 10, 0 );
			fputs( "  We said: 'AUTH TLS'", outputStream );
			break;

		default:
			assert( FALSE );
		}
	bufPos = readLine( netSocket, buffer, 1024 );
	if( bufPos < 3 || ( strncmp( buffer, "220", 3 ) && \
						strncmp( buffer, "+OK", 3 ) && \
						strncmp( buffer, "OK", 2 ) && \
						strncmp( buffer, "234", 3 ) ) )
		{
		fprintf( outputStream, "Got response '%s', line %d.\n", buffer, 
				 __LINE__ );
		return( CRYPT_OK );		/* Signal non-fatal error */
		}
	fprintf( outputStream, "  Server said: '%s'\n", buffer );
	return( netSocket );
	}

/* Set up a server using user-defined sockets */

static SOCKET createServerSocket( void )
	{
	SOCKET netSocket;
	struct sockaddr_in serverInfo;
	int status;

	fputs( "Creating user-defined local server socket...\n", outputStream );

	/* Connect to a generally-available server to test STARTTLS/STLS
	   functionality */
	memset( &serverInfo, 0, sizeof( struct sockaddr_in ) );
	serverInfo.sin_family = AF_INET;
#ifdef __WINDOWS__
	serverInfo.sin_port = htons( 443 );
#else
	serverInfo.sin_port = htons( 4443 );
#endif /* OS-specific port handling */
	serverInfo.sin_addr.s_addr = inet_addr( "127.0.0.1" );
	netSocket = socket( PF_INET, SOCK_STREAM, 0 );
	if( netSocket == INVALID_SOCKET )
		{
		fprintf( outputStream, "Couldn't create socket, line %d.\n", 
				 __LINE__ );
		return( CRYPT_ERROR_FAILED );
		}
	status = bind( netSocket, ( struct sockaddr* ) &serverInfo, 
				   sizeof( struct sockaddr_in ) );
	if( status == SOCKET_ERROR )
		{
		closesocket( netSocket );
		fprintf( outputStream, "Couldn't bind to 127.0.0.1, line %d.\n", 
				 __LINE__ );
		return( CRYPT_OK );		/* Signal non-fatal error */
		}
	status = listen( netSocket, 5 );
	if( status == SOCKET_ERROR )
		{
		closesocket( netSocket );
		fprintf( outputStream, "Couldn't listen on local socket, line %d.\n", 
				 __LINE__ );
		return( CRYPT_OK );		/* Signal non-fatal error */
		}
	return( netSocket );
	}

static SOCKET connectServerSocket( SOCKET netSocket )
	{
	SOCKET connectedSocket;
	SOCKADDR_STORAGE clientAddr;
	SIZE_TYPE clientAddrLen = sizeof( SOCKADDR_STORAGE );
	const int trueValue = 1;

	connectedSocket = accept( netSocket, ( struct sockaddr * ) &clientAddr,
							  &clientAddrLen);
	closesocket( netSocket );
	if( connectedSocket == SOCKET_ERROR )
		{
		fprintf( outputStream, "Error receiving incoming connection on local "
				 "socket, line %d.\n", __LINE__ );
		return( CRYPT_ERROR_FAILED );
		}
	setsockopt( connectedSocket, DISABLE_NAGLE_LEVEL, DISABLE_NAGLE_OPTION, 
				( void * ) &trueValue, sizeof( int ) );

	return( connectedSocket );
	}
#else

static int setPseudoSocket( const CRYPT_SESSION cryptSession )
	{
#if defined( DDNAME_IO )
	/* The fileno() function doesn't work for DDNAMEs */
	return( cryptSetAttribute( cryptSession, CRYPT_SESSINFO_NETWORKSOCKET, 
							   0 ) );
#elif defined( __WIN16__ ) || defined( _WIN32_WCE )
	return( cryptSetAttribute( cryptSession, CRYPT_SESSINFO_NETWORKSOCKET, 
							   1 ) );
#else
	return( cryptSetAttribute( cryptSession, CRYPT_SESSINFO_NETWORKSOCKET, 
							   fileno( stdin ) ) );
#endif /* System-specific pseudo-socket handling */
	}

#endif /* #ifdef USE_LOCAL_SOCKETS */

/****************************************************************************
*																			*
*									TLS Test Code							*
*																			*
****************************************************************************/

/* Establish an TLS session */

static int connectTLS( const CRYPT_SESSION_TYPE sessionType,
					   const TLS_TEST_TYPE testType, const int version,
					   const int sessionID, const BOOLEAN localSession )
	{
	CRYPT_SESSION cryptSession;
	const BOOLEAN isServer = ( sessionType == CRYPT_SESSION_TLS_SERVER ) ? \
							   TRUE : FALSE;
	const BOOLEAN isErrorTest = ( testType >= TLS_TEST_CORRUPT_HANDSHAKE && \
								  testType < TLS_TEST_LAST ) ? \
								  TRUE : FALSE;
	const char *versionStr[] = { "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" };
	const int tlsServerNo = ( testType == TLS_TEST_WEBSOCKETS ) ? WS_SERVER_NO : \
							( testType == TLS_TEST_EAPTTLS ) ? EAP_SERVER_NO : \
							( version == 0 ) ? SSL_SERVER_NO : \
							( version == 1 ) ? TLS_SERVER_NO : \
							( version == 2 ) ? TLS11_SERVER_NO : \
							( version == 3 ) ? TLS12_SERVER_NO : \
											   TLS13_SERVER_NO;
	const C_STR serverName = ( testType == TLS_TEST_STARTTLS ) ? \
								starttlsInfo[ STARTTLS_SERVER_NO ].name : \
							 ( testType == TLS_TEST_WRONGSERVER ) ? \
								"www.openssh.com:22" : \
							 tlsInfo[ tlsServerNo ].name;
	BYTE *bulkBuffer = NULL;	/* Needed for bogus uninit-value warnings */
#ifdef USE_LOCAL_SOCKETS
	SOCKET netSocket DUMMY_INIT;
#endif /* USE_LOCAL_SOCKETS */
#ifdef USE_TIMING
	HIRES_TIME timeVal;
#endif /* USE_TIMING */
	char buffer[ FILEBUFFER_SIZE ];
#ifdef BROKEN_SERVER_INVALID_CERT
	int complianceLevel;
#endif /* TLS servers with b0rken certs */
	int bytesCopied, protocol = PROTOCOL_SMTP, status;

	/* If it's a BadSSL test then the test type determines the server name */
	if( testType >= TLS_TEST_BADSSL_DH512 && \
		testType <= TLS_TEST_BADSSL_LONGNAME2 )
		{
		int i;

		for( i = 0; badSslInfo[ i ].testType != 0; i++ )
			{
			if( badSslInfo[ i ].testType == testType )
				{
				serverName = badSslInfo[ i ].path;
				break;
				}
			}
		if( badSslInfo[ i ].testType == 0 )
			return( FALSE );
		}

	/* If this is a local session, synchronise the client and server */
	if( localSession )
		{
		if( isServer )
			{
			/* Acquire the init mutex */
			acquireMutex();
			}
		else
			{
			/* We're the client, wait for the server to finish initialising */
			if( waitMutex() == CRYPT_ERROR_TIMEOUT )
				{
				fprintf( outputStream, "Timed out waiting for server to "
						 "initialise, line %d.\n", __LINE__ );
				return( FALSE );
				}
			}
		}

	/* If this is the dual-thread server test and we're the second server 
	   thread, skip the portions that have already been handled by the first 
	   thread */
#ifdef WINDOWS_THREADS
	if( isServer && testType == TLS_TEST_DUALTHREAD && sessionID == 0 )
		goto dualThreadContinue;
#endif /* WINDOWS_THREADS */

	if( sessionID != CRYPT_UNUSED )
		fprintf( outputStream, "%02d: ", sessionID );
	fprintf( outputStream, 
			 "%sTesting %s%s session%s...\n", isServer ? "SVR: " : "",
			 localSession ? "local " : "", versionStr[ version ],
			 ( testType == TLS_TEST_CLIENTCERT ) ? " with client certs" : \
			 ( testType == TLS_TEST_CLIENTCERT_MANUAL ) ? " with manual verification of client cert" : \
			 ( testType == TLS_TEST_SNI ) ? " with SNI-based server key selection" : \
			 ( testType == TLS_TEST_FORCEVER_CLI || \
			   testType == TLS_TEST_FORCEVER_SVR ) ? " with forced TLS version" : \
			 ( testType == TLS_TEST_WHITELIST || \
			   testType == TLS_TEST_WHITELIST_FAIL ) ? " using server cert whitelist" : \
			 ( testType == TLS_TEST_STARTTLS || \
			   testType == TLS_TEST_LOCALSERVER ) ? " with local socket" : \
			 ( testType == TLS_TEST_BULKTRANSER ) ? " for bulk data transfer" : \
			 ( testType == TLS_TEST_PSK ) ? " with shared key" : \
			 ( testType == TLS_TEST_PSK_CLIONLY ) ? " with client-only PSK" : \
			 ( testType == TLS_TEST_PSK_SVRONLY ) ? " with server-only PSK" : \
			 ( testType == TLS_TEST_ECC ) ? " with P256 ECC crypto" : \
			 ( testType == TLS_TEST_ECC_P384 ) ? " with P384 ECC crypto" : \
			 ( testType == TLS_TEST_ED25519 ) ? " with Ed25519 crypto" : \
			 ( testType == TLS_TEST_WRONGSERVER ) ? " connecting to wrong server" : \
			 ( testType == TLS_TEST_WEBSOCKETS ) ? " with WebSockets" : \
			 ( testType == TLS_TEST_EAPTTLS ) ? " with EAP-TTLS" : \
			 ( testType >= TLS_TEST_BADSSL_DH512 && \
			   testType <= TLS_TEST_BADSSL_LONGNAME2 ) ? " with BadSSL checking" : \
			 isErrorTest ? " with checking for error handling" : "" );
#ifndef NO_SESSION_CACHE
	if( isServer )
		{
		fputs( "  Warning: Session cache is active, subsequent sessions won't "
			   "use\n  the full handshake.\n", outputStream );
		}
#endif /* NO_SESSION_CACHE */
	if( !isServer && !localSession )
		fprintf( outputStream, "  Remote host: %s.\n", serverName );

	/* Create the TLS session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, sessionType );
	if( status == CRYPT_ERROR_PARAM3 )	/* TLS session access not available */
		{
		if( isServer && localSession )
			releaseMutex();	/* Make sure client doesn't hang */
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateSession() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		if( isServer && localSession )
			releaseMutex();	/* Make sure client doesn't hang */
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, 
								version );
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		if( version == 0 )
			{
			fputs( "  (Couldn't enable use of SSLv3, continuing on the "
				   "assumption that it's\n   disabled in this build).\n\n", 
				   outputStream );
			if( isServer && localSession )
				releaseMutex();	/* Make sure client doesn't hang */
			return( TRUE );
			}
		if( version == 1 )
			{
			fputs( "  (Couldn't enable use of TLSv1.0, continuing on the "
				   "assumption that it's\n   disabled in this build).\n\n", 
				   outputStream );
			if( isServer && localSession )
				releaseMutex();	/* Make sure client doesn't hang */
			return( TRUE );
			}
		fprintf( outputStream, "cryptSetAttribute() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		if( isServer && localSession )
			releaseMutex();	/* Make sure client doesn't hang */
		return( FALSE );
		}
#if defined( CONFIG_FAULTS ) && !defined( NDEBUG )
	if( isServer && isErrorTest )
		{
		cryptSetFaultType( ( testType == TLS_TEST_CORRUPT_HANDSHAKE ) ? \
							 FAULT_SESSION_CORRUPT_HANDSHAKE : \
						   ( testType == TLS_TEST_CORRUPT_DATA ) ? \
							 FAULT_SESSION_CORRUPT_DATA : \
						   ( testType == TLS_TEST_CORRUPT_MAC ) ? \
							 FAULT_SESSION_CORRUPT_MAC : \
						   ( testType == TLS_TEST_CORRUPT_FINISHED ) ? \
							 FAULT_SESSION_TLS_CORRUPT_FINISHED : \
						   ( testType == TLS_TEST_CORRUPT_IV ) ? \
							 FAULT_SESSION_TLS_CORRUPT_IV : \
						   ( testType == TLS_TEST_WRONGCERT ) ? \
							 FAULT_SESSION_WRONGCERT : \
						   ( testType == TLS_TEST_BADSIG_HASH ) ? \
							 FAULT_BADSIG_HASH : \
						   ( testType == TLS_TEST_BADSIG_SIG ) ? \
							 FAULT_BADSIG_SIG : \
						   ( testType == TLS_TEST_BADSIG_DATA ) ? \
							 FAULT_BADSIG_DATA : \
							 FAULT_NONE );
		}
#endif /* CONFIG_FAULTS && Debug */

	/* If we're doing a bulk data transfer, set up the necessary buffer */
	if( testType == TLS_TEST_BULKTRANSER )
		{
		if( ( bulkBuffer = malloc( BULKDATA_BUFFER_SIZE ) ) == NULL )
			{
			cryptDestroySession( cryptSession );
			fprintf( outputStream, "Failed to allocated %ld bytes, "
					 "line %d.\n", BULKDATA_BUFFER_SIZE, __LINE__ );
			if( isServer && localSession )
				releaseMutex();	/* Make sure client doesn't hang */
			return( FALSE );
			}
		if( isServer )
			handleBulkBuffer( bulkBuffer, TRUE );
		}

	/* Set up all of the information needed for the session */
	if( isServer )
		{
		CRYPT_CONTEXT privateKey;

		if( testType != TLS_TEST_LOCALSERVER )
			{
			if( !setLocalConnect( cryptSession, 443 ) )
				{
				cryptDestroySession( cryptSession );
				if( localSession )
					releaseMutex();	/* Make sure client doesn't hang */
				return( FALSE );
				}
			}
		if( testType == TLS_TEST_SNI )
			{
			/* Set the wrong key as the primary server key to verify the 
			   SNI-based server key switching.  Note that we have to do this
			   before setting the actual server key below in order to check
			   the ability to switch keys based on the SNI */
			char filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
			wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
			void *fileNamePtr = filenameBuffer;

			filenameFromTemplate( filenameBuffer, 
								  SERVER_PRIVKEY_FILE_TEMPLATE, 3 );
#ifdef UNICODE_STRINGS
			mbstowcs( wcBuffer, filenameBuffer, 
					  strlen( filenameBuffer ) + 1 );
			fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_TLS_OPTIONS,
										CRYPT_TLSOPTION_SERVER_SNI );
			if( cryptStatusOK( status ) )
				{
				status = getPrivateKey( &privateKey, fileNamePtr,
										USER_PRIVKEY_LABEL,
										TEST_PRIVKEY_PASSWORD );
				}
			if( cryptStatusOK( status ) )
				{
				status = cryptSetAttribute( cryptSession,
											CRYPT_SESSINFO_PRIVATEKEY,
											privateKey );
				cryptDestroyContext( privateKey );
				}
			}
		if( cryptStatusOK( status ) && \
			( testType == TLS_TEST_FORCEVER_SVR ) )
			{
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_TLS_OPTIONS,
										( version == 2 ) ? \
										  CRYPT_TLSOPTION_MINVER_TLS11 : \
										( version == 3 ) ? \
										  CRYPT_TLSOPTION_MINVER_TLS12 : \
										  CRYPT_TLSOPTION_MINVER_TLS13 );
			}
		if( cryptStatusOK( status ) && \
			( testType != TLS_TEST_PSK && \
			  testType != TLS_TEST_PSK_SVRONLY && \
			  testType != TLS_TEST_DUALTHREAD ) )
			{
			char filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
			wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
			const void *fileNamePtr = filenameBuffer;

			/* We don't add a private key if we're doing TLS-PSK, to test 
			   TLS-PSK's abiltiy to work without a PKC */
			switch( testType )
				{
				case TLS_TEST_ECC:
					filenameFromTemplate( filenameBuffer, 
										  SERVER_ECPRIVKEY_FILE_TEMPLATE, 
										  256 );
					break;

				case TLS_TEST_ECC_P384:
					filenameFromTemplate( filenameBuffer, 
										  SERVER_ECPRIVKEY_FILE_TEMPLATE, 
										  384 );
					break;

				case TLS_TEST_ED25519:
					filenameFromTemplate( filenameBuffer, 
										  SERVER_PRIVKEY_FILE_TEMPLATE, 
										  25519 );
					break;

				default:
					filenameFromTemplate( filenameBuffer, 
										  SERVER_PRIVKEY_FILE_TEMPLATE, 1 );
					break;
				}
#ifdef UNICODE_STRINGS
			mbstowcs( wcBuffer, filenameBuffer, 
					  strlen( filenameBuffer ) + 1 );
			fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
			status = getPrivateKey( &privateKey, fileNamePtr,
									USER_PRIVKEY_LABEL,
									TEST_PRIVKEY_PASSWORD );
			if( cryptStatusOK( status ) )
				{
				status = cryptSetAttribute( cryptSession,
											CRYPT_SESSINFO_PRIVATEKEY,
											privateKey );
				cryptDestroyContext( privateKey );
				}
			}
		if( cryptStatusOK( status ) && testType == TLS_TEST_CLIENTCERT )
			{
			CRYPT_KEYSET cryptKeyset;

			status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
								CRYPT_KEYOPT_READONLY );
			if( cryptStatusError( status ) )
				{
				cryptDestroySession( cryptSession );
				fprintf( outputStream, "SVR: Client certificate keyset open "
						 "failed with error code %d, line %d.\n", status, 
						 __LINE__ );
				if( localSession )
					releaseMutex();	/* Make sure client doesn't hang */
				return( FALSE );
				}
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_KEYSET,
										cryptKeyset );
			cryptKeysetClose( cryptKeyset );
			}
		if( cryptStatusOK( status ) && testType == TLS_TEST_CLIENTCERT_MANUAL )
			{
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_TLS_OPTIONS,
										CRYPT_TLSOPTION_MANUAL_CERTCHECK );
			}
		if( cryptStatusOK( status ) && testType == TLS_TEST_LOCALSERVER )
			{
#ifdef USE_LOCAL_SOCKETS
			/* Try and set up a local server socket.  Since the socket type 
			   can be unsigned, we have to force it to signed to perform the
			   error check on it.
			   
			   We don't treat most types of failure as fatal since there are 
			   a great many minor things that can go wrong that we don't 
			   want to have to handle without writing half an MUA */
			if( !initSockets() )
				{
				cryptDestroySession( cryptSession );
				if( localSession )
					releaseMutex();	/* Make sure client doesn't hang */
				return( FALSE );
				}
			netSocket = createServerSocket();
			if( ( signed ) netSocket <= 0 )
				{
				cryptDestroySession( cryptSession );
				endSockets( 0 );
				if( localSession )
					releaseMutex();	/* Make sure client doesn't hang */
				if( netSocket == CRYPT_OK )
					{
					fputs( "This is a nonfatal error (a great many other "
						   "things can go wrong while\nsetting up the server "
						   "socket).\n\n", outputStream );
					return( TRUE );
					}
				return( FALSE );
				}

			/* We can't send the socket to cryptlib at this point because 
			   it's only a generic listening socket, not the connected 
			   socket that's created from the listening socket, so we have 
			   to defer that until later */
#else
			status = setPseudoSocket( cryptSession );
#endif /* OS-specific local socket handling */
			}
		}
	else
		{
		/* We're the client */
		if( testType == TLS_TEST_STARTTLS )
			{
#ifdef USE_LOCAL_SOCKETS
			/* Try and negotiate a STARTTLS session.  Since the socket type 
			   can be unsigned, we have to force it to signed to perform the
			   error check on it.
			   
			   We don't treat most types of failure as fatal since there are 
			   a great many minor things that can go wrong that we don't 
			   want to have to handle without writing half an MUA */
			if( !initSockets() )
				{
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			netSocket = negotiateSTARTTLS( &protocol );
			if( ( signed ) netSocket <= 0 )
				{
				cryptDestroySession( cryptSession );
				endSockets( 0 );
				if( netSocket == CRYPT_OK )
					{
					fputs( "This is a nonfatal error (a great many other "
						   "things can go wrong while\nnegotiating through "
						   "to the TLS upgrade).\n\n", outputStream );
					return( TRUE );
					}
				return( FALSE );
				}
			status = setSocket( cryptSession, netSocket );
#else
			status = setPseudoSocket( cryptSession );
#endif /* OS-specific local socket handling */
			}
		else
			{
			if( localSession || \
				( paramStrlen( serverName ) == strlen( TEXT( LOCAL_HOST_NAME ) ) && \
				  !memcmp( serverName, TEXT( LOCAL_HOST_NAME ), \
						   paramStrlen( serverName ) ) ) )
				{
				if( !setLocalConnect( cryptSession, 443 ) )
					{
					cryptDestroySession( cryptSession );
					if( testType == TLS_TEST_BULKTRANSER )
						free( bulkBuffer );
					return( FALSE );
					}
				if( LOCAL_HOST_NAME[ 0 ] != 'l' )
					{
					/* We're performing a connect to the local host under a 
					   name other than "localhost", disable host-name
					   verification */
					cryptSetAttribute( cryptSession, CRYPT_SESSINFO_TLS_OPTIONS,
									   CRYPT_TLSOPTION_DISABLE_NAMEVERIFY );
					}
				}
			else
				{
				status = cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_SERVER_NAME, serverName,
								paramStrlen( serverName ) );
				}
			}
		if( cryptStatusOK( status ) && \
			( testType == TLS_TEST_FORCEVER_CLI ) )
			{
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_TLS_OPTIONS,
										( version == 2 ) ? \
										  CRYPT_TLSOPTION_MINVER_TLS11 : \
										( version == 3 ) ? \
										  CRYPT_TLSOPTION_MINVER_TLS12 : \
										  CRYPT_TLSOPTION_MINVER_TLS13 );
			}
		if( cryptStatusOK( status ) && \
			( testType == TLS_TEST_CLIENTCERT || \
			  testType == TLS_TEST_CLIENTCERT_MANUAL ) )
			{
			CRYPT_CONTEXT privateKey;
			char filenameBuffer[ FILENAME_BUFFER_SIZE ];

			/* Depending on which server we're testing against we need to 
			   use different private keys */
#if ( TLS12_SERVER_NO == 30 && 0 )
			getPrivateKey( &privateKey, TLS_CLI_PRIVKEY_FILE, 
				"cc47650c403654f6fe439e5c88a2e6c2_66335081-ee61-4aa8-862d-a423d58",
				TEST_PRIVKEY_PASSWORD );
#else
			filenameFromTemplate( filenameBuffer, 
								  USER_PRIVKEY_FILE_TEMPLATE, 1 );
			status = getPrivateKey( &privateKey, filenameBuffer, 
									USER_PRIVKEY_LABEL, 
									TEST_PRIVKEY_PASSWORD );
#endif /* Different keys for different servers */
			if( cryptStatusOK( status ) )
				{
				CRYPT_KEYSET cryptKeyset;
				int localStatus;

				status = cryptSetAttribute( cryptSession,
								CRYPT_SESSINFO_PRIVATEKEY, privateKey );

				/* In addition to adding the key to the session, we also try 
				   adding it to the server's key database in case it's not 
				   present yet */
				localStatus = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
								CRYPT_KEYOPT_NONE );
				if( cryptStatusOK( localStatus ) )
					{
					localStatus = cryptAddPublicKey( cryptKeyset, 
													 privateKey );
					cryptKeysetClose( cryptKeyset );
					if( cryptStatusError( localStatus ) && \
						localStatus != CRYPT_ERROR_DUPLICATE )
						{
						/* The key isn't already present (or we'd get a
						   CRYPT_ERROR_DUPLICATE), but also couldn't be 
						   added, there's some sort of problem */
						cryptDestroySession( cryptSession );
						fprintf( outputStream, "Attempt to add client "
								 "certificate to server access-control "
								 "database failed\n  with error code %d, "
								 "line %d.\n", localStatus, __LINE__ );
						return( FALSE );
						}
					}
				cryptDestroyContext( privateKey );
				}
			}
		if( cryptStatusOK( status ) && \
			( testType == TLS_TEST_WHITELIST || \
			  testType == TLS_TEST_WHITELIST_FAIL ) )
			{
			CRYPT_CONTEXT publicKey;
			CRYPT_KEYSET cryptKeyset;
			char filenameBuffer[ FILENAME_BUFFER_SIZE ];
			char commonName[ CRYPT_MAX_TEXTSIZE + 1 ];
#ifdef UNICODE_STRINGS
			wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
			void *fileNamePtr = filenameBuffer;
			int length DUMMY_INIT;

			/* Get the certificate that'll be used by the server */
			filenameFromTemplate( filenameBuffer, 
								  SERVER_PRIVKEY_FILE_TEMPLATE, 1 );
#ifdef UNICODE_STRINGS
			mbstowcs( wcBuffer, filenameBuffer, 
					  strlen( filenameBuffer ) + 1 );
			fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
			status = getPublicKey( &publicKey, fileNamePtr,
								   USER_PRIVKEY_LABEL );
			if( cryptStatusOK( status ) )
				{
				status = cryptGetAttributeString( publicKey, 
												  CRYPT_CERTINFO_COMMONNAME,
												  commonName, &length );
				}
			if( cryptStatusError( status ) )
				{
				cryptDestroySession( cryptSession );
				fprintf( outputStream, "Couldn't get server key for "
						 "whitelist, error code %d, line %d.\n", status, 
						 __LINE__ );
				return( FALSE );
				}
			commonName[ length ] = '\0';

			/* Open the whitelist keyset */
			status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
								CRYPT_KEYOPT_NONE );
			if( cryptStatusError( status ) )
				{
				cryptDestroySession( cryptSession );
				fprintf( outputStream, "Server certificate keyset open "
						 "failed with error code %d, line %d.\n", status, 
						 __LINE__ );
				return( FALSE );
				}
			if( testType == TLS_TEST_WHITELIST )
				{
				/* We're using the keyset as a whitelist to enable access 
				   for this server, add its certificate.  If it's already
				   present from a previous run then this isn't an error  */
				status = cryptAddPublicKey( cryptKeyset, publicKey );
				if( status == CRYPT_ERROR_DUPLICATE )
					status = CRYPT_OK;
				}
			else
				{
				/* We're using the keyset as an empty whitelist to block 
				   access for this server, delete its certificate in case 
				   it's already present from a previous run */
				status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, 
										 commonName );
				if( status == CRYPT_ERROR_NOTFOUND )
					status = CRYPT_OK;
				}
			if( cryptStatusError( status ) )
				{
				cryptDestroySession( cryptSession );
				fprintf( outputStream, "Server certificate keyset open "
						 "failed with error code %d, line %d.\n", status, 
						 __LINE__ );
				return( FALSE );
				}
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_KEYSET,
										cryptKeyset );
			cryptKeysetClose( cryptKeyset );
			}
#if 0	/* Optional proxy for net access */
		status = cryptSetAttributeString( CRYPT_UNUSED,
								CRYPT_OPTION_NET_HTTP_PROXY, "[Autodetect]",
								12 );
#endif /* 0 */
		}
	if( cryptStatusOK( status ) && \
		( testType == TLS_TEST_PSK || \
		  ( isServer && testType == TLS_TEST_PSK_SVRONLY ) || \
		  ( !isServer && testType == TLS_TEST_PSK_CLIONLY ) ) )
		{
		/* If we're testing the no-PSK handling, only the server is 
		   expecting TLS-PSK, so the client isn't supplied with a 
		   password */
		if( cryptStatusOK( status ) && isServer && testType == TLS_TEST_PSK )
			{
			/* If we're testing PSK, add several preceding usernames and 
			   passwords */
			cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_USERNAME, TEXT( "before1" ),
								paramStrlen( TEXT( "before1" ) ) );
			cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_PASSWORD, TEXT( "before1" ),
								paramStrlen( TEXT( "before1" ) ) );
			cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_USERNAME, TEXT( "before2" ),
								paramStrlen( TEXT( "before2" ) ) );
			cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_PASSWORD, TEXT( "before2" ),
								paramStrlen( TEXT( "before2" ) ) );
			}
		status = cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_USERNAME, TLS_USER_NAME,
								paramStrlen( TLS_USER_NAME ) );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_PASSWORD, TLS_PASSWORD,
								paramStrlen( TLS_PASSWORD ) );
			}
		if( cryptStatusOK( status ) && isServer && testType == TLS_TEST_PSK )
			{
			/* If we're testing PSK, add several succeeding usernames and
			   passwords */
			cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_USERNAME, TEXT( "after1" ),
								paramStrlen( TEXT( "after1" ) ) );
			cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_PASSWORD, TEXT( "after1" ),
								paramStrlen( TEXT( "after1" ) ) );
			cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_USERNAME, TEXT( "after2" ),
								paramStrlen( TEXT( "after2" ) ) );
			cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_PASSWORD, TEXT( "after2" ),
								paramStrlen( TEXT( "after2" ) ) );
			}
		}
	if( cryptStatusOK( status ) && \
		testType == TLS_TEST_WEBSOCKETS )
		{
#if WS_SERVER_NO != 49
		/* The use of WebSockets can be selected implicitly via a "wss://" 
		   URL or explicitly by setting the CRYPT_SESSINFO_SUBPROTOCOL 
		   attribute, for non-loopback tests we use ixplicit selection but
		   for the loopback tests, where we're just connecting to 
		   "localhost", we have to explicitly select WebSockets */
		if( localSession )
			{
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
										CRYPT_SUBPROTOCOL_WEBSOCKETS );
			}
#endif /* Loopback websockets server */
#if WS_SERVER_NO != 50 && WS_SERVER_NO != 51 && WS_SERVER_NO != 52
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSession,
											  CRYPT_SESSINFO_TLS_WSPROTOCOL, 
											  "mqtt", 4 );
			}
#endif /* WebSockets servers that don't acknowledge the protocol type */
		}
	if( cryptStatusOK( status ) && \
		testType == TLS_TEST_EAPTTLS )
		{
#if EAP_SERVER_NO == 56
		/* The local test server uses a self-signed cert with a generic host 
		   name, so we have to disable certificate name verification in 
		   order to continue */
		cryptSetAttribute( cryptSession, CRYPT_SESSINFO_TLS_OPTIONS, 
						   CRYPT_TLSOPTION_DISABLE_NAMEVERIFY );
#endif /* EAP_SERVER_NO == 56 */
		status = cryptSetAttribute( cryptSession, 
							CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
							CRYPT_SUBPROTOCOL_EAPTTLS );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSession,
							CRYPT_SESSINFO_USERNAME, 
							tlsInfo[ EAP_SERVER_NO ].userName,
							paramStrlen( tlsInfo[ EAP_SERVER_NO ].userName ) );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSession,
							CRYPT_SESSINFO_PASSWORD, 
							tlsInfo[ EAP_SERVER_NO ].password,
							paramStrlen( tlsInfo[ EAP_SERVER_NO ].password ) );
			}
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		if( testType == TLS_TEST_STARTTLS || \
			( isServer && testType == TLS_TEST_LOCALSERVER ) )
			{
#ifdef USE_LOCAL_SOCKETS
			endSockets( netSocket );
#else
			/* Creating a socket in a portable manner is too difficult so 
			   we've passed in a stdio handle, this should return an error 
			   since it's not a blocking socket */
			return( TRUE );
#endif /* USE_LOCAL_SOCKETS */
			}
		fprintf( outputStream, "cryptSetAttribute/AttributeString() "
				 "failed with error code %d, line %d.\n", status, 
				 __LINE__ );
		if( testType == TLS_TEST_BULKTRANSER )
			free( bulkBuffer );
		if( isServer && localSession )
			releaseMutex();	/* Make sure client doesn't hang */
		return( FALSE );
		}
#ifdef BROKEN_SERVER_INVALID_CERT
	fputs( "(Setting certificate compliance level to oblivious to deal with "
		   "broken server).", outputStream );
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   &complianceLevel );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
#endif /* TLS servers with b0rken certs */
#ifdef BROKEN_SERVER_WRONG_CERT
	fputs( "(Disabling certificate name checking to deal with broken "
		   "server).", outputStream );
	cryptSetAttribute( cryptSession, CRYPT_SESSINFO_TLS_OPTIONS, 
					   CRYPT_TLSOPTION_DISABLE_NAMEVERIFY );
#endif /* TLS servers with the wrong cert for the domain */
	if( localSession )
		{
		/* If we're running a local loopback test, display additional 
		   information indicating when the session is activated, since 
		   the multithreaded tests may not get to this point until long 
		   after the threads are started */
		if( sessionID != CRYPT_UNUSED )
			fprintf( outputStream, "%02d: ", sessionID );
		fprintf( outputStream, "%sActivating %s session...\n", 
				 isServer ? "SVR: " : "", versionStr[ version ] );

		/* For the loopback test we also increase the connection timeout to 
		   a higher-than-normal level, since this gives us more time for 
		   tracing through the code when debugging */
		cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_CONNECTTIMEOUT, 
						   120 );

		if( isServer )
			{
			/* Tell the client that we're ready to go */
			releaseMutex();

			/* Connect the server socket and send it to the session before 
			   activating it.  This is a bit of a problem during the 
			   loopback testing because we're in a race condition with the 
			   client, we can't activate the session until the client has 
			   connected, but we can't call connectServerSocket() before 
			   releasing the mutex since it's a blocking call.  To deal 
			   with this we have the client sleep for awhile after the mutex 
			   is released in the hope that the server gets into 
			   connectServerSocket() before the client has time to set up 
			   its session and connect */
			if( testType == TLS_TEST_LOCALSERVER )
				{
#ifdef USE_LOCAL_SOCKETS
				netSocket = connectServerSocket( netSocket );
				if( ( signed ) netSocket <= 0 )
					{
					cryptDestroySession( cryptSession );
					endSockets( 0 );
					return( FALSE );
					}
				status = setSocket( cryptSession, netSocket );
				if( cryptStatusError( status ) )
					{
					cryptDestroySession( cryptSession );
					endSockets( 0 );
					return( FALSE );
					}
#endif /* USE_LOCAL_SOCKETS */
				}
			}
		else
			{
			/* See the comment above */
			if( testType == TLS_TEST_LOCALSERVER )
				delayThread( 1 );
			}
		}

	/* Activate the session and see what we got */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
#ifdef BROKEN_SERVER_INVALID_CERT
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   complianceLevel );
#endif /* TLS server with b0rken certs */
	if( isServer && testType != TLS_TEST_PSK_CLIONLY && \
					testType != TLS_TEST_PSK_SVRONLY )
		{
		/* We don't check the return status for this since the session may 
		   be disconnected before we get the client info, which would cause 
		   us to bail out before we display the error info */
		if( sessionID != CRYPT_UNUSED )
			fprintf( outputStream, "%02d: ", sessionID );
		printConnectInfo( cryptSession );

		/* If we're testing the ability to switch certificates using SNI, 
		   print the certificate that was selected for the connection */
		if( testType == TLS_TEST_SNI )
			{
			CRYPT_CERTIFICATE serverCert;

			/* The selected certificate is read via the rather odd attribute
			   CRYPT_SESSINFO_REQUEST because CRYPT_SESSINFO_RESPONSE is 
			   already used for the client cert */
			status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_REQUEST,
										&serverCert );
			if( cryptStatusOK( status ) )
				{
				fprintf( outputStream, "SVR: Certificate selected via SNI "
						 "is:\n" );
				printCertInfo( serverCert );
				cryptDestroyCert( serverCert );
				}
			}
		}
	if( isServer && testType == TLS_TEST_CLIENTCERT_MANUAL && \
		status == CRYPT_ENVELOPE_RESOURCE )
		{
		CRYPT_CERTIFICATE cryptCertChain;

		/* Allow the auth.and complete the handshake */
		fputs( "SVR: Manually verifying client certificate...\n", 
			   outputStream );
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
									&cryptCertChain );
		if( cryptStatusOK( status ) )
			{
			/* In a real-world situation we'd check the certificate at this
			   point, for now we just destroy it again and tell the server
			   to continue */
			cryptDestroyCert( cryptCertChain );
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_AUTHRESPONSE, TRUE );
			}
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_ACTIVE, TRUE );
			}
		}
#ifdef WINDOWS_THREADS
	if( isServer && testType == TLS_TEST_DUALTHREAD && \
		status == CRYPT_ENVELOPE_RESOURCE )
		{
		static CRYPT_SESSION localCryptSession = 0;
		unsigned threadID;

		/* Start a second thread to complete the handshake and exit */
		localCryptSession = cryptSession;
		_beginthreadex( NULL, 0, tlsServerDualThread2, NULL, 0, &threadID );
		return( TRUE );

		/* The second thread continues from here */
dualThreadContinue:
		assert( localSession > 0 );
		cryptSession = localCryptSession;

		/* Allow the auth.and complete the handshake */
		fputs( "SVR: Confirming authentication to client...", 
			   outputStream );
		status = cryptSetAttribute( cryptSession,
									CRYPT_SESSINFO_AUTHRESPONSE, TRUE );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_ACTIVE, TRUE );
			}
		}
#endif /* WINDOWS_THREADS */
	if( cryptStatusError( status ) )
		{
		char strBuffer[ 128 ];

		if( testType == TLS_TEST_STARTTLS || \
			( isServer && testType == TLS_TEST_LOCALSERVER ) )
			{
#ifdef USE_LOCAL_SOCKETS
			endSockets( netSocket );
#else
			/* If we're using a dummy local socket, we'll get a R/W error at 
			   this point since it's not connected to anything, so we 
			   intercept it before it gets any further */
			if( status == CRYPT_ERROR_READ || status == CRYPT_ERROR_WRITE )
				{
				cryptDestroySession( cryptSession );
				return( TRUE );
				}
#endif /* USE_LOCAL_SOCKETS */
			}
		if( sessionID != CRYPT_UNUSED )
			fprintf( outputStream, "%02d: ", sessionID );
		sprintf( strBuffer, "%sAttempt to activate %s%s session",
				 isServer ? "SVR: " : "", localSession ? "local " : "",
				 versionStr[ version ] );
		printExtError( cryptSession, strBuffer, status, __LINE__ );
		if( testType == TLS_TEST_BULKTRANSER )
			free( bulkBuffer );
		if( !isServer && isServerDown( cryptSession, status ) )
			{
			cryptDestroySession( cryptSession );
			fputs( "  (Server could be down, faking it and "
				   "continuing...)\n\n", outputStream );
			return( CRYPT_ERROR_FAILED );
			}
		cryptDestroySession( cryptSession );
		if( isErrorTest || testType == TLS_TEST_PSK_CLIONLY || \
			testType == TLS_TEST_PSK_SVRONLY || \
			testType == TLS_TEST_WHITELIST_FAIL )
			{
			if( isErrorTest )
				{
				if( isServer )
					{
					/* The corrupt-handshake test is detected by the server 
					   before the client even though the server has sent out
					   a corrupted message because the client sends their 
					   Finished message first, and that contains the overall
					   handshake MAC which is different for the client.  In
					   addition this can be reported as a CRYPT_ERROR_BADDATA
					   depending on where the corruption is caught */
					if( testType == TLS_TEST_CORRUPT_HANDSHAKE && \
						status != CRYPT_ERROR_SIGNATURE && \
						status != CRYPT_ERROR_BADDATA )
						{
						fprintf( outputStream, "Test returned status %d, "
								 "should have been %d or %d.\n", status, 
								 CRYPT_ERROR_SIGNATURE, 
								 CRYPT_ERROR_BADDATA );
						return( FALSE );
						}
					}
				else
					{
					if( testType != TLS_TEST_CORRUPT_HANDSHAKE && \
						testType != TLS_TEST_CORRUPT_FINISHED && \
						testType != TLS_TEST_CORRUPT_IV && \
						testType != TLS_TEST_CORRUPT_MAC && \
						status != CRYPT_ERROR_SIGNATURE && \
						status != CRYPT_ERROR_BADDATA )
						{
						fprintf( outputStream, "Test returned status %d, "
								 "should have been %d or %d.\n", status, 
								 CRYPT_ERROR_SIGNATURE,
								 CRYPT_ERROR_BADDATA );
						return( FALSE );
						}
					}
				}

			/* These tests are supposed to fail, so if this happens then the 
			   overall test has succeeded */
			fputs( "  (This test checks error handling, so the failure "
				   "response is correct).\n\n", outputStream );
			return( TRUE );
			}
		if( ( testType == TLS_TEST_NORMAL || \
			  testType == TLS_TEST_STARTTLS ) && ( version == 0 ) )
			{
			fputs( "  (This test checks SSLv3 functionality, which fewer and "
				   "fewer servers\n   support, assuming that the test "
				   "failure was due to SSLv3 support being\n   disabled on "
				   "the server).\n\n", outputStream );
			return( TRUE );
			}

		return( FALSE );
		}

	/* The error tests should cause handshake failures, so getting to this 
	   point is an error */
	if( isErrorTest && testType != TLS_TEST_CORRUPT_DATA )
		{
		cryptDestroySession( cryptSession );
		fputs( "  (This test should have led to a handshake failure but "
			   "didn't, test has\n   failed).\n", outputStream );
		return( FALSE );
		}

	/* The CLIONLY/SVRONLY test is supposed to fail, if this doesn't happen 
	   then there's a problem */
#ifdef NO_SESSION_CACHE
	if( testType == TLS_TEST_PSK_CLIONLY || \
		testType == TLS_TEST_PSK_SVRONLY )
		{
		cryptDestroySession( cryptSession );
		fprintf( outputStream, "%sTLS-PSK handshake without password should "
				 "have failed but succeeded,\nline %d.\n",
				 isServer ? "SVR: " : "", __LINE__  );
		return( FALSE );
		}
#endif /* NO_SESSION_CACHE */

	/* If we're testing session resumption and there's a server key present 
	   then we didn't actually resume the session */
#ifndef NO_SESSION_CACHE
	if( testType == TLS_TEST_RESUME )
		{
		CRYPT_CONTEXT serverKey;

		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
									&serverKey );
		if( cryptStatusOK( status ) )
			{
			cryptDestroyContext( serverKey );
			cryptDestroySession( cryptSession );
			fprintf( outputStream, "%sSession resumption didn't actually "
					 "resume a previous session, line %d.\n", 
					 isServer ? "SVR: " : "", __LINE__  );
			return( FALSE );
			}
		}
#endif /* !NO_SESSION_CACHE */

	/* Report the session security info */
	if( testType != TLS_TEST_MULTITHREAD )
		{
		const BOOLEAN isFirstSession = \
			( testType == TLS_TEST_NORMAL && version == 0 ) ? TRUE : FALSE;
		int actualVersion;

#ifdef NO_SESSION_CACHE
		if( !printSecurityInfo( cryptSession, isServer,
				( testType != TLS_TEST_PSK && testType != TLS_TEST_RESUME ), 
				( !isServer && testType != TLS_TEST_PSK && \
							   testType != TLS_TEST_RESUME ),
				( isServer && ( testType == TLS_TEST_CLIENTCERT || \
								testType == TLS_TEST_CLIENTCERT_MANUAL ) ) ) )
			{
			cryptDestroySession( cryptSession );
			if( testType == TLS_TEST_BULKTRANSER )
				free( bulkBuffer );
			return( FALSE );
			}
#else
		if( !printSecurityInfo( cryptSession, isServer, isFirstSession,
								!isServer && isFirstSession, FALSE ) )
			{
			cryptDestroySession( cryptSession );
			if( testType == TLS_TEST_BULKTRANSER )
				free( bulkBuffer );
			return( FALSE );
			}
#endif /* NO_SESSION_CACHE */
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_VERSION,
									&actualVersion );
		if( cryptStatusOK( status ) && actualVersion != version )
			{
			fprintf( outputStream, "%sWarning: Expected to connect using %s "
					 "but actually connected using %s.\n", 
					 isServer ? "SVR: " : "", versionStr[ version ],
					 versionStr[ actualVersion ] );
			}
		}
#ifdef NO_SESSION_CACHE
	if( ( !localSession && !isServer && testType != TLS_TEST_PSK ) ||
		( localSession && isServer && \
		  ( testType == TLS_TEST_CLIENTCERT || \
			testType == TLS_TEST_CLIENTCERT_MANUAL ) ) )
#else
	if( !localSession && !isServer && testType != TLS_TEST_PSK )
#endif /* NO_SESSION_CACHE */
		{
		CRYPT_CERTIFICATE cryptCertificate;

		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
									&cryptCertificate );
		if( cryptStatusError( status ) )
			{
			cryptDestroySession( cryptSession );
			fprintf( outputStream, "%sCouldn't get %s certificate, "
					 "status %d, line %d.\n", isServer ? "SVR: " : "", 
					 isServer ? "client" : "server", status, __LINE__ );
			if( testType == TLS_TEST_BULKTRANSER )
				free( bulkBuffer );
			return( FALSE );
			}
		fputs( localSession ? "SVR: Client certificate details are:\n" : \
							  "Server certificate details are:\n", 
							  outputStream );
		printCertChainInfo( cryptCertificate );
		cryptDestroyCert( cryptCertificate );
		}
	if( isServer && testType == TLS_TEST_PSK )
		{
		C_CHR userNameBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];
		int length;

		status = cryptGetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME,
										  userNameBuffer, &length );
		if( cryptStatusError( status ) )
			{
			cryptDestroySession( cryptSession );
			fprintf( outputStream, "SVR: Couldn't read client user name, "
					 "status %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
#ifdef UNICODE_STRINGS
		userNameBuffer[ length / sizeof( wchar_t ) ] = TEXT( '\0' );
		fprintf( outputStream, "SVR: Client user name = '%S'.\n", 
				 userNameBuffer );
#else
		userNameBuffer[ length ] = '\0';
		fprintf( outputStream, "SVR: Client user name = '%s'.\n", 
				 userNameBuffer );
#endif /* UNICODE_STRINGS */
#ifdef NO_SESSION_CACHE
		if( length != ( int ) paramStrlen( TLS_USER_NAME ) || \
			memcmp( userNameBuffer, TLS_USER_NAME, \
					paramStrlen( TLS_USER_NAME ) ) )
			{
			cryptDestroySession( cryptSession );
			fprintf( outputStream, "SVR: User name was '%s', should have "
					 "been '%s', line %d.\n", userNameBuffer, TLS_USER_NAME, 
					 __LINE__ );
			return( FALSE );
			}
#else
		if( length < 8 || memcmp( userNameBuffer, "[Resumed", 8 ) )
			{
			cryptDestroySession( cryptSession );
			fprintf( outputStream, "SVR: User name was '%s', should have "
					 "been an indication that\n     the session was "
					 "resumed, line %d.\n", userNameBuffer, __LINE__ );
			return( FALSE );
			}
#endif /* NO_SESSION_CACHE */
		}

	/* Send data over the TLS link.  If we're doing a bulk transfer we use 
	   fully asynchronous I/O to verify the timeout handling in the session 
	   code */
#if defined( IS_HIGHVOLUME_SERVER )
	/* This server has a large amount of data on it, used to test high-
	   latency bulk transfers, so we set a larger timeout for the read */
	status = cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_READTIMEOUT,
								15 );
#elif defined USE_TIMING
	status = cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_READTIMEOUT,
								5 );
#else
	status = cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_READTIMEOUT,
								( testType == TLS_TEST_BULKTRANSER ) ? 0 : 5 );
#endif /* IS_HIGHVOLUME_SERVER */
	if( cryptStatusError( status ) )
		{
		if( testType == TLS_TEST_BULKTRANSER )
			free( bulkBuffer );
		printExtError( cryptSession, isServer ? \
					   "SVR: Session timeout set" : "Session timeout set", 
					   status, __LINE__ );
		cryptDestroySession( cryptSession );
		return( FALSE );
		}
	if( testType == TLS_TEST_BULKTRANSER )
		{
#ifdef USE_TIMING
		int timeMS;

		timeVal = timeDiff( 0 );
#endif /* USE_TIMING */
		if( isServer )
			{
			long byteCount = 0;

			do
				{
				status = cryptPushData( cryptSession, bulkBuffer + byteCount,
										BULKDATA_BUFFER_SIZE - byteCount,
										&bytesCopied );
				byteCount += bytesCopied;
				}
			while( ( cryptStatusOK( status ) || \
					 status == CRYPT_ERROR_TIMEOUT ) && \
				   byteCount < BULKDATA_BUFFER_SIZE );
			if( cryptStatusError( status ) )
				{
				printExtError( cryptSession,
							   "SVR: Send of bulk data to client", status,
							   __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) )
				{
				printExtError( cryptSession,
							   "SVR: Flush of bulk data to client", status,
							   __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			if( byteCount != BULKDATA_BUFFER_SIZE )
				{
				cryptDestroySession( cryptSession );
				fprintf( outputStream, "Only sent %ld of %ld bytes, "
						 "line %d.\n", byteCount, BULKDATA_BUFFER_SIZE, 
						 __LINE__ );
				return( FALSE );
				}
			}
		else
			{
			long byteCount = 0;

			do
				{
				status = cryptPopData( cryptSession, bulkBuffer + byteCount,
									   BULKDATA_BUFFER_SIZE - byteCount,
									   &bytesCopied );
				byteCount += bytesCopied;
				}
			while( ( cryptStatusOK( status ) || \
					 status == CRYPT_ERROR_TIMEOUT ) && \
				   byteCount < BULKDATA_BUFFER_SIZE );
			if( cryptStatusError( status ) )
				{
				char strBuffer[ 256 ];

				sprintf( strBuffer, "Read of bulk data from server aborted "
									"after %ld of %ld bytes were read\n(last "
									"read = %d bytes), transfer",
									byteCount, BULKDATA_BUFFER_SIZE,
									bytesCopied );
				printExtError( cryptSession, strBuffer, status, __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			if( byteCount != BULKDATA_BUFFER_SIZE )
				{
				cryptDestroySession( cryptSession );
				fprintf( outputStream, "Only received %ld of %ld bytes, "
						 "line %d.\n", byteCount, BULKDATA_BUFFER_SIZE, 
						 __LINE__ );
				return( FALSE );
				}
			if( !handleBulkBuffer( bulkBuffer, FALSE ) )
				{
				cryptDestroySession( cryptSession );
				fprintf( outputStream, "Received buffer contents don't "
						 "match sent buffer contents, line %d.", __LINE__ );
				return( FALSE );
				}
			}
#ifdef USE_TIMING
		timeVal = timeDiff( timeVal ); 
		fprintf( outputStream, "Time for %s transfer: ", 
				 isServer ? "server-to-client" : "client-to-server" );
		timeMS = timeDisplay( timeVal );
		fprintf( outputStream, "Data rate = %d kBytes/second.\n", 
				 ( int ) ( BULKDATA_BUFFER_SIZE / timeMS ) );
#endif /* USE_TIMING */
		free( bulkBuffer );
		}
	else
		{
		/* It's a standard transfer, send/receive and HTTP request/response. 
		   We clean up if we exit due to an error, if we're running a local 
		   loopback test the client and server threads can occasionally lose 
		   sync, which isn't a fatal error but can turn into a 
		   CRYPT_ERROR_INCOMPLETE once all the tests are finished */
		if( isServer )
			{
			BYTE textBuffer[ 1024 ];
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( resume )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 819 )
#endif /* IBM medium iron */
			const char serverReply[] = \
				"HTTP/1.0 200 OK\n"
				"Date: Fri, 7 June 2022 20:02:07 GMT\n"
				"Server: cryptlib TLS test\n"
				"Content-Type: text/html\n"
				"Connection: Close\n"
				"\n"
				"<!DOCTYPE HTML SYSTEM \"html.dtd\">\n"
				"<html>\n"
				"<head>\n"
				"<title>cryptlib %s test page</title>\n"
				"<body>\n"
				"Test message from the cryptlib %s server.<p>\n"
				"</body>\n"
				"</html>\n";
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */
			int bytesToSend;

			/* Print the text of the request from the client */
			status = cryptPopData( cryptSession, buffer, FILEBUFFER_SIZE,
								   &bytesCopied );
			if( cryptStatusError( status ) )
				{
				printExtError( cryptSession, "SVR: Attempt to read data "
							   "from client", status, __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			buffer[ bytesCopied ] = '\0';
#if defined( __MVS__ ) || defined( __VMCMS__ )
			bufferToEbcdic( buffer, buffer );
#endif /* EBCDIC systems */
			if( testType != TLS_TEST_MULTITHREAD )
				{
				fprintf( outputStream, "---- Client sent %d bytes ----\n", 
						 bytesCopied );
				fputs( buffer, outputStream );
				fputs( "---- End of output ----\n", outputStream );
				}

			/* Send a reply */
			bytesToSend = sprintf( textBuffer, serverReply, 
								   versionStr[ version ], 
								   versionStr[ version ] );
			status = cryptPushData( cryptSession, textBuffer, bytesToSend, 
									&bytesCopied );
			if( cryptStatusOK( status ) )
				status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) || bytesCopied != bytesToSend )
				{
				printExtError( cryptSession, "Attempt to send data to "
							   "client", status, __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}

			/* Wait for the data to be flushed through to the client before 
			   we close the session */
			delayThread( 1 );
			}
		else
			{
			BYTE fetchString[ 256 ];
			int fetchStringLen;

			/* Send a fetch request to the server */
			if( testType == TLS_TEST_STARTTLS )
				{
				switch( protocol )
					{
					case PROTOCOL_SMTP:
						strcpy( fetchString, "EHLO foo.bar.com\r\n" );
						break;

					case PROTOCOL_POP:
						strcpy( fetchString, "CAPA\r\n" );
						break;

					case PROTOCOL_IMAP:
						strcpy( fetchString, "a003 CAPABILITY\r\n" );
						break;

					default:
						strcpy( fetchString, "USER test\r\n" );
					}
				fetchStringLen = strlen( fetchString );
				}
			else
				{
				if( testType == TLS_TEST_EAPTTLS )
					{
					BYTE eapChallenge[ 64 ];
					int eapChallengeLength;

					status = cryptGetAttributeString( cryptSession, 
													  CRYPT_SESSINFO_TLS_EAPCHALLENGE, 
													  eapChallenge, &eapChallengeLength );
					if( cryptStatusError( status ) )
						{
						printExtError( cryptSession, "Attempt to read EAP "
									   "challenge from session", status, __LINE__ );
						cryptDestroySession( cryptSession );
						return( FALSE );
						}
#if 0
					status = createTTLSAVPMSCHAPv2( fetchString, &fetchStringLen,
									tlsInfo[ EAP_SERVER_NO ].userName,
									paramStrlen( tlsInfo[ EAP_SERVER_NO ].userName ),
									tlsInfo[ EAP_SERVER_NO ].password,
									paramStrlen( tlsInfo[ EAP_SERVER_NO ].password ),
									eapChallenge );
#else
					fetchStringLen = 0;	/* Dummy value */
#endif /* 0 */
					}
				else
					{
					const char *hostName = tlsInfo[ tlsServerNo ].name;

					/* Skip any URL decoration if necessary */					
					if( !memcmp( hostName, "https://", 8 ) )
						hostName += 8;
					
					/* We default to an HTTP 1.1 request even though the 1.0 
					   form would be simpler because some servers will treat 
					   the 1.0 form as an error and only return a short error
					   string */
#if 0
					sprintf( fetchString, "GET %s HTTP/1.0\r\n\r\n",
							 tlsInfo[ tlsServerNo ].path );
#else
					sprintf( fetchString, 
							 "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
							 tlsInfo[ tlsServerNo ].path, hostName );
#endif /* 1 */
					fetchStringLen = strlen( fetchString );
					}
				}
#if defined( __MVS__ ) || defined( __VMCMS__ )
			bufferToAscii( fetchString, fetchString );
#endif /* EBCDIC systems */
			status = cryptPushData( cryptSession, fetchString,
									fetchStringLen, &bytesCopied );
			if( cryptStatusOK( status ) )
				status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) || bytesCopied != fetchStringLen )
				{
				printExtError( cryptSession, "Attempt to send data to "
							   "server", status, __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}

			/* Print the text of the reply from the server */
			status = cryptPopData( cryptSession, buffer, FILEBUFFER_SIZE,
								   &bytesCopied );
			if( cryptStatusError( status ) )
				{
				printExtError( cryptSession, "Attempt to read data from "
							   "server", status, __LINE__ );
				cryptDestroySession( cryptSession );
				if( isErrorTest )
					{
					/* These tests are supposed to fail, so if this happens 
					   then the overall test has succeeded */
					fputs( "  (This test checks error handling, so the "
						   "failure response is correct).\n\n", outputStream );
					return( TRUE );
					}

				return( FALSE );
				}

			/* The error tests should cause protocol failures, so getting to 
			   this point is an error */
			if( isErrorTest )
				{
				cryptDestroySession( cryptSession );
				fputs( "  (This test should have led to a protocol failure "
					   "but didn't, test has\n   failed).\n", outputStream );
				return( FALSE );
				}

			if( bytesCopied == 0 && testType != TLS_TEST_STARTTLS )
				{
				/* We've set a 5s timeout, we should get at least some 
				   data, however we allow this for the STARTTLS tests since 
				   the servers can exhibit all sorts of odd behaviour that 
				   we can't do much about with the partial client that we 
				   have here */
				cryptDestroySession( cryptSession );
				fputs( "Server returned no data in response to our request.", 
					   outputStream );
				return( FALSE );
				}
			buffer[ min( bytesCopied, 4096 ) ] = '\0';
#if defined( __MVS__ ) || defined( __VMCMS__ )
			bufferToEbcdic( buffer, buffer );
#endif /* EBCDIC systems */
			if( testType != TLS_TEST_MULTITHREAD )
				{
				fprintf( outputStream, "---- Server sent %d bytes ----\n", 
						 bytesCopied );
				fputs( buffer, outputStream );
				if( bytesCopied > 4096 )
					{
					fprintf( outputStream, "  (Further %d bytes data "
							 "omitted)\n", bytesCopied - 4096 );
					}
				fputs( "---- End of output ----\n", outputStream );
				}

			/* If it's the EAP test, we need to acknowledge the server's 
			   response */
			if( testType == TLS_TEST_EAPTTLS )
				{
				status = cryptSetAttribute( cryptSession, 
											CRYPT_SESSINFO_AUTHRESPONSE, 
											TRUE );
				if( cryptStatusError( status ) )
					{
					printExtError( cryptSession, "Attempt to acknowledge "
								   "EAP auth", status, __LINE__ );
					cryptDestroySession( cryptSession );
					return( FALSE );
					}
				}

#ifdef IS_HIGHVOLUME_SERVER
			/* If we're reading a lot of data, more may have arrived in the 
			   meantime */
			status = cryptPopData( cryptSession, buffer, FILEBUFFER_SIZE,
								   &bytesCopied );
			if( cryptStatusError( status ) )
				{
				if( status == CRYPT_ERROR_READ )
					{
					/* Since this is HTTP, the other side can close the 
					   connection with no further warning, even though TLS 
					   says you shouldn't really do this */
					fputs( "Remote system closed connection.", 
						   outputStream );
					}
				else
					{
					printExtError( cryptSession, "Attempt to read data from "
								   "server", status, __LINE__ );
					cryptDestroySession( cryptSession );
					return( FALSE );
					}
				}
			else
				{
				buffer[ bytesCopied ] = '\0';
#if defined( __MVS__ ) || defined( __VMCMS__ )
				bufferToEbcdic( buffer, buffer );
#endif /* EBCDIC systems */
				if( testType != TLS_TEST_MULTITHREAD )
					{
					fprintf( outputStream, "---- Server sent further %d "
							 "bytes ----\n", bytesCopied );
					fputs( buffer, outputStream );
					fputs( "---- End of output ----\n", outputStream );
					}
				}
#endif /* IS_HIGHVOLUME_SERVER */

			/* If it's a chatty protocol, exchange some more pleasantries */
			if( testType == TLS_TEST_STARTTLS )
				{
				switch( protocol )
					{
					case PROTOCOL_SMTP:
						strcpy( fetchString, "QUIT\r\n" );
						break;

					case PROTOCOL_POP:
						strcpy( fetchString, "USER test\r\n" );
						break;

					case PROTOCOL_IMAP:
						strcpy( fetchString, "a004 LOGIN test\r\n" );
						break;

					default:
						strcpy( fetchString, "QUIT\r\n" );
					}
				fetchStringLen = strlen( fetchString );
#if defined( __MVS__ ) || defined( __VMCMS__ )
				bufferToAscii( fetchString, fetchString );
#endif /* EBCDIC systems */
				status = cryptPushData( cryptSession, fetchString,
										fetchStringLen, &bytesCopied );
				if( cryptStatusOK( status ) )
					status = cryptFlushData( cryptSession );
				if( cryptStatusError( status ) || bytesCopied != fetchStringLen )
					{
					printExtError( cryptSession, "Attempt to send data to "
								   "server", status, __LINE__ );
					cryptDestroySession( cryptSession );
					return( FALSE );
					}
				status = cryptPopData( cryptSession, buffer, FILEBUFFER_SIZE,
									   &bytesCopied );
				if( cryptStatusError( status ) )
					{
					printExtError( cryptSession, "Attempt to read data from "
								   "server", status, __LINE__ );
					cryptDestroySession( cryptSession );
					return( FALSE );
					}
				buffer[ bytesCopied ] = '\0';
#if defined( __MVS__ ) || defined( __VMCMS__ )
				bufferToEbcdic( buffer, buffer );
#endif /* EBCDIC systems */
				if( testType != TLS_TEST_MULTITHREAD )
					{
					fprintf( outputStream, "---- Server sent %d bytes ----\n", 
							 bytesCopied );
					fputs( buffer, outputStream );
					fputs( "---- End of output ----\n", outputStream );
					}
				}
			}
		}

	/* Clean up */
	status = cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptDestroySession() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
#ifdef USE_LOCAL_SOCKETS
	if( testType == TLS_TEST_STARTTLS || \
		( isServer && testType == TLS_TEST_LOCALSERVER ) )
		{
		endSockets( netSocket );
		}
#endif /* USE_LOCAL_SOCKETS */

	if( sessionID != CRYPT_UNUSED )
		fprintf( outputStream, "%02d: ", sessionID );
	fprintf( outputStream, "%s%s session succeeded.\n", 
			 isServer ? "SVR: " : "", versionStr[ version ] );
	if( testType != TLS_TEST_MULTITHREAD )
		fputc( '\n', outputStream );
	return( TRUE );
	}

/* SSLv3 tests */

int testSessionSSL( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_NORMAL, 0, CRYPT_UNUSED, FALSE ) );
	}
int testSessionSSLLocalSocket( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_STARTTLS, 0, CRYPT_UNUSED, FALSE ) );
	}
int testSessionSSLClientCert( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_CLIENTCERT, 0, CRYPT_UNUSED, FALSE ) );
	}

int testSessionSSLServer( void )
	{
	int status;

	createMutex();
	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_NORMAL, 0, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}
int testSessionSSLServerCached( void )
	{
	int status;

	/* Run the server twice to check session cacheing.  Testing this 
	   requires manual reconnection with a browser to localhost since it's 
	   too complex to handle easily via a loopback test.  Note that with 
	   MSIE this will require three lots of connects rather than two, 
	   because it handles an unknown certificate by doing a resume, which 
	   consumes two lots of sessions, and then the third one is the actual 
	   session resume */
	createMutex();
	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_NORMAL, 0, CRYPT_UNUSED, FALSE );
	if( status > 0 )
		status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_NORMAL, 0, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}
int testSessionSSLServerClientCert( void )
	{
	int status;

	createMutex();
	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_CLIENTCERT, 0, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}

/* TLS 1.0 tests */

int testSessionTLS( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_NORMAL, 1, CRYPT_UNUSED, FALSE ) );
	}
int testSessionTLSLocalSocket( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_STARTTLS, 1, CRYPT_UNUSED, FALSE ) );
	}
int testSessionTLSSharedKey( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_PSK, 1, CRYPT_UNUSED, FALSE ) );
	}

int testSessionTLSServer( void )
	{
	int status;

	createMutex();
	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_NORMAL, 1, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}
int testSessionTLSServerSharedKey( void )
	{
	int status;

	createMutex();
	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_PSK, 1, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}
int testSessionTLSEAPTTLS( void )
	{
	/* This is required alongside testSessionTLS12EAPTTLS() because many 
	   FreeRADIUS implementations don't understand TLS 1.2 or even TLS 1.1, 
	   resulting in a string of "Unknown TLS version [length 00xx]" errors */
	return( connectTLS( CRYPT_SESSION_SSL, TLS_TEST_EAPTTLS, 1, CRYPT_UNUSED, FALSE ) );
	}

/* TLS 1.1 tests */

int testSessionTLS11( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_NORMAL, 2, CRYPT_UNUSED, FALSE ) );
	}
int testSessionTLS11Server( void )
	{
	int status;

	createMutex();
	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_NORMAL, 2, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}

/* TLS 1.2 tests */

int testSessionTLS12( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_NORMAL, 3, CRYPT_UNUSED, FALSE ) );
	}
int testSessionTLS12ClientCert( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_CLIENTCERT, 3, CRYPT_UNUSED, FALSE ) );
	}
int testSessionTLS12Server( void )
	{
	int status;

	createMutex();

	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_NORMAL, 3, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}
int testSessionTLS12ServerEccKey( void )
	{
	int status;

	createMutex();

	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_ECC, 3, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}
int testSessionTLS12ServerClientCertManual( void )
	{
	int status;

	createMutex();

	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_CLIENTCERT_MANUAL, 3, CRYPT_UNUSED, TRUE );
	destroyMutex();

	return( status );
	}
int testSessionTLS12ServerWhitelist( void )
	{
	int status;

	createMutex();

	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_WHITELIST, 3, CRYPT_UNUSED, TRUE );
	destroyMutex();

	return( status );
	}
int testSessionTLS12WrongServer( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_WRONGSERVER, 3, CRYPT_UNUSED, FALSE ) );
	}
int testSessionTLS12WebSockets( void )
	{
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_WEBSOCKETS, 3, CRYPT_UNUSED, FALSE ) );
	}
int testSessionTLS12WebSocketsServer( void )
	{
	int status;

	createMutex();
	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_WEBSOCKETS, 3, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}
int testSessionTLS12EAPTTLS( void )
	{
	/* See the comment in testSessionTLSEAPTTLS() above */
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_EAPTTLS, 3, CRYPT_UNUSED, FALSE ) );
	}
int testSessionTLS12EAPTTLSServer( void )
	{
	int status;

	createMutex();
	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_EAPTTLS, 3, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
	}

/* TLS 1.3 tests */

int testSessionTLS13( void )
	{
#ifdef USE_TLS13
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_NORMAL, 4, CRYPT_UNUSED, FALSE ) );
#else
	return( TRUE );
#endif /* USE_TLS13 */
	}
int testSessionTLS13ClientCert( void )
	{
#ifdef USE_TLS13
	return( connectTLS( CRYPT_SESSION_TLS, TLS_TEST_CLIENTCERT, 4, CRYPT_UNUSED, FALSE ) );
#else
	return( TRUE );
#endif /* USE_TLS13 */
	}
int testSessionTLS13Server( void )
	{
#ifdef USE_TLS13
	int status;

	createMutex();

	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_NORMAL, 4, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
#else
	return( TRUE );
#endif /* USE_TLS13 */
	}
int testSessionTLS13ServerEccKey( void )
	{
#if defined( USE_TLS13 ) && defined( USE_ECDSA )
	int status;

	createMutex();

	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_ECC, 4, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
#else
	return( TRUE );
#endif /* USE_TLS13 && USE_ECDSA */
	}
int testSessionTLS13ServerEccKeyP384( void )
	{
#if defined( USE_TLS13 ) && defined( USE_ECDSA )
	int status;

	createMutex();

	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_ECC_P384, 4, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
#else
	return( TRUE );
#endif /* USE_TLS13 && USE_ECDSA */
	}
int testSessionTLS13ServerEd25519Key( void )
	{
#if defined( USE_TLS13 ) && defined( USE_ED25519 )
	int status;

	createMutex();

	status = connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_ED25519, 4, CRYPT_UNUSED, FALSE );
	destroyMutex();

	return( status );
#else
	return( TRUE );
#endif /* USE_TLS13 && USE_ED25519 */
	}

int testSessionTLSBadSSL( void )
	{
	FILE *origOutputStream = outputStream;
	int i;

	fputs( "Running BadSSL tests...\n", outputStream );
	outputStream = fopen( DEVNULL, "w" );
	assert( outputStream != NULL );

	for( i = 0; badSslInfo[ i ].testType != 0; i++ )
		{
		int status;

		fprintf( origOutputStream, "Testing %s.\n", badSslInfo[ i ].path );

		/* With a debug build of cryptlib, TLS_TEST_BADSSL_DHSMALLSUBGROUP 
		   will raise an assertion, so we only run it on non-debug builds */
#ifndef NDEBUG
		if( badSslInfo[ i ].testType == TLS_TEST_BADSSL_DHSMALLSUBGROUP )
			{
			fputs( "Skipping TLS_TEST_BADSSL_DHSMALLSUBGROUP in debug "
				   "build.", outputStream );
			continue;
			}
#endif /* NDEBUG */
		status = connectTLS( CRYPT_SESSION_TLS, badSslInfo[ i ].testType, 3, 
							 CRYPT_UNUSED, FALSE );
		if( status != badSslInfo[ i ].result )
			{
			/* If ECDH/ECDSA aren't enabled then the ECC P256 test will fail */
			if( cryptStatusError( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) || \
				cryptStatusError( cryptQueryCapability( CRYPT_ALGO_ECDH, NULL ) ) )
				{
				if( badSslInfo[ i ].testType == TLS_TEST_BADSSL_ECC256 )
					continue;
				}

#ifndef USE_GCM
			/* This site seems to have a bug in the 
			   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 suite, producing a Bad
			   record MAC alert when a CBC suite (rather than GCM) is used, 
			   so we ignore errors when GCM isn't enabled */
			if( badSslInfo[ i ].testType == TLS_TEST_BADSSL_RSA2048 || \
				badSslInfo[ i ].testType == TLS_TEST_BADSSL_NOCN || \
				badSslInfo[ i ].testType == TLS_TEST_BADSSL_NOSUBJECT || \
				badSslInfo[ i ].testType == TLS_TEST_BADSSL_LONGNAME1 || \
				badSslInfo[ i ].testType == TLS_TEST_BADSSL_LONGNAME2 )
				continue;
#endif /* USE_GCM */

			/* As of late 2021, https://no-common-name.badssl.com has gone 
			   away, possibly due to the custom cert it uses expiring and no
			   replacement being readily available, see the issue tracker at
			   https://github.com/chromium/badssl.com around problems 
			   replacing expired certs */
			if( badSslInfo[ i ].testType == TLS_TEST_BADSSL_NOCN && \
				status == CRYPT_ERROR_FAILED )
				continue;

			fclose( outputStream );
			outputStream = origOutputStream;
			fprintf( outputStream, "BadSSL test '%s' failed,\ngot result "
					 "%d, should have been %d.\n", badSslInfo[ i ].path,
					 status, badSslInfo[ i ].result );
			return( FALSE );
			}
		}
	fclose( outputStream );
	outputStream = origOutputStream;

	fprintf( outputStream, "BadSSL tests succeeded.\n\n" );
	return( TRUE );
	}

/* Perform a client/server loopback test */

#ifdef TEST_SESSION_LOOPBACK

#ifdef WINDOWS_THREADS
  static unsigned __stdcall sslServerThread( void *arg )
#else
  static void *sslServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

	connectTLS( CRYPT_SESSION_TLS_SERVER, argValue, 0, CRYPT_UNUSED, 
				TRUE );
	THREAD_EXIT();
	}

static int sslClientServer( const TLS_TEST_TYPE testType )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = testType, status;

	/* If this is a test that requires a database keyset, make sure that one 
	   is available */
	if( testType == TLS_TEST_CLIENTCERT && \
		!checkDatabaseKeysetAvailable() )
		{
		fputs( "Skipping test due to unavailability of database "
			   "keysets.\n\n", outputStream );
		return( TRUE );
		}

	/* Start the server */
	createMutex();
#ifdef WINDOWS_THREADS
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, sslServerThread, &arg, 0, 
										 &threadID );
#else
	pthread_create( &hThread, NULL, sslServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 1000 );

	/* Connect to the local server */
	status = connectTLS( CRYPT_SESSION_TLS, testType, 0, CRYPT_UNUSED, 
						 TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
int testSessionSSLClientServer( void )
	{
	return( sslClientServer( TLS_TEST_NORMAL ) );
	}
int testSessionSSLClientCertClientServer( void )
	{
	return( sslClientServer( TLS_TEST_CLIENTCERT ) );
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall tlsServerThread( void *arg )
#else
  static void *tlsServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

	connectTLS( CRYPT_SESSION_TLS_SERVER, argValue, 1, CRYPT_UNUSED, 
				TRUE );
	THREAD_EXIT();
	}

static int tlsClientServer( const TLS_TEST_TYPE testType )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = testType, status;

	/* If this is a test that requires a database keyset, make sure that one 
	   is available */
	if( testType == TLS_TEST_CLIENTCERT && \
		!checkDatabaseKeysetAvailable() )
		{
		fputs( "Skipping test due to unavailability of database "
			   "keysets.\n\n", outputStream );
		return( TRUE );
		}

	/* If the session cache bypasses the operation in the test, skip it */
#ifndef NO_SESSION_CACHE
	if( testType == TLS_TEST_PSK )
		{
		fputs( "Skipping test due to session cache bypassing shared-key "
			   "check.\n\n", outputStream );
		return( TRUE );
		}
#endif /* NO_SESSION_CACHE */

	/* Start the server */
	createMutex();
#ifdef WINDOWS_THREADS
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, tlsServerThread, &arg, 0, 
										 &threadID );
#else
	pthread_create( &hThread, NULL, tlsServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 1000 );

	/* Connect to the local server */
	status = connectTLS( CRYPT_SESSION_TLS, testType, 1, CRYPT_UNUSED, 
						 TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
int testSessionTLSClientServer( void )
	{
	return( tlsClientServer( TLS_TEST_NORMAL ) );
	}
int testSessionTLSSharedKeyClientServer( void )
	{
	return( tlsClientServer( TLS_TEST_PSK ) );
	}
int testSessionTLSNoSharedKeyClientServer( void )
	{
	if( !tlsClientServer( TLS_TEST_PSK_CLIONLY ) )
		return( FALSE );
	return( tlsClientServer( TLS_TEST_PSK_SVRONLY ) );
	}
int testSessionTLSBulkTransferClientServer( void )
	{
	return( tlsClientServer( TLS_TEST_BULKTRANSER ) );
	}
int testSessionTLSLocalServerSocketClientServer( void )
	{
#ifdef WINDOWS_THREADS
	return( tlsClientServer( TLS_TEST_LOCALSERVER ) );
#else
	/* On some Unix systems the client fails with an ECONNREFUSED which 
	   means that the server thread is stuck in the accept() in 
	   connectServerSocket(), so it never exits and the client ends up
	   waiting forever in waitForThread() for the server thread stuck in
	   accept().  To deal with this we skip the test, since there's no way
	   to tell which systems will hang and which won't */
	return( TRUE );
#endif /* WINDOWS_THREADS */
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall tls11ServerThread( void *arg )
#else
  static void *tls11ServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

	connectTLS( CRYPT_SESSION_TLS_SERVER, argValue, 2, CRYPT_UNUSED, 
				TRUE );
	THREAD_EXIT();
	}

static int tls11ClientServer( const TLS_TEST_TYPE testType )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = testType, status;

	/* If this is a test that requires a database keyset, make sure that one 
	   is available */
	if( testType == TLS_TEST_CLIENTCERT && \
		!checkDatabaseKeysetAvailable() )
		{
		fputs( "Skipping test due to unavailability of database "
			   "keysets.\n\n", outputStream );
		return( TRUE );
		}

	/* Start the server */
	createMutex();
#ifdef WINDOWS_THREADS
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, tls11ServerThread, &arg, 0, 
										 &threadID );
#else
	pthread_create( &hThread, NULL, tls11ServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 1000 );

	/* Connect to the local server */
	status = connectTLS( CRYPT_SESSION_TLS, testType, 2, CRYPT_UNUSED, 
						 TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
int testSessionTLS11ClientServer( void )
	{
	return( tls11ClientServer( TLS_TEST_NORMAL ) );
	}
int testSessionTLS11ClientCertClientServer( void )
	{
	return( tls11ClientServer( TLS_TEST_CLIENTCERT ) );
	}
int testSessionTLS11ResumeClientServer( void )
	{
	/* Note that this function has to be called after one of the standard 
	   TLS-connect functions has been called, since it checks for the 
	   ability to resume a previously-cached session */
	return( tls11ClientServer( TLS_TEST_RESUME ) );
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall tls12ServerThread( void *arg )
#else
  static void *tls12ServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

	connectTLS( CRYPT_SESSION_TLS_SERVER, argValue, 3, CRYPT_UNUSED, 
				TRUE );
	THREAD_EXIT();
	}

static int tls12ClientServer( const TLS_TEST_TYPE testType )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = testType, status;

	/* If this is a test that requires a database keyset, make sure that one 
	   is available */
	if( ( testType == TLS_TEST_CLIENTCERT || \
		  testType == TLS_TEST_WHITELIST || \
		  testType == TLS_TEST_WHITELIST_FAIL ) && \
		!checkDatabaseKeysetAvailable() )
		{
		fputs( "Skipping test due to unavailability of database "
			   "keysets.\n\n", outputStream );
		return( TRUE );
		}

	/* If this is a test the uses WebSockets, make sure that they're enabled */
#ifndef USE_WEBSOCKETS
	if( testType == TLS_TEST_WEBSOCKETS )
		{
		fputs( "Skipping test due to unavailability of WebSockets.\n\n", 
			   outputStream );
		return( TRUE );
		}
#endif /* USE_WEBSOCKETS */

	/* Start the server */
	createMutex();
#ifdef WINDOWS_THREADS
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, tls12ServerThread, &arg, 0, 
										 &threadID );
#else
	pthread_create( &hThread, NULL, tls12ServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 1000 );

	/* Connect to the local server */
	status = connectTLS( CRYPT_SESSION_TLS, testType, 3, CRYPT_UNUSED, 
						 TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
int testSessionTLS12ClientServer( void )
	{
	return( tls12ClientServer( TLS_TEST_NORMAL ) );
	}
int testSessionTLS12ClientServerEccKey( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_ECDSA, \
							  NULL ) == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "ECC is disabled in this build of cryptlib, skipping TLS ECC "
			   "test.\n\n", outputStream );
		return( TRUE );
		}
	return( tls12ClientServer( TLS_TEST_ECC ) );
	}
int testSessionTLS12ClientServerEcc384Key( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_ECDSA, \
							  NULL ) == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "ECC is disabled in this build of cryptlib, skipping TLS ECC "
			   "test.\n\n", outputStream );
		return( TRUE );
		}
	return( tls12ClientServer( TLS_TEST_ECC_P384 ) );
	}
int testSessionTLS12ClientCertClientServer( void )
	{
	return( tls12ClientServer( TLS_TEST_CLIENTCERT ) );
	}
int testSessionTLS12ClientCertManualClientServer( void )
	{
	return( tls12ClientServer( TLS_TEST_CLIENTCERT_MANUAL ) );
	}
int testSessionTLS12SNIClientServer( void )
	{
	return( tls12ClientServer( TLS_TEST_SNI ) );
	}
int testSessionTLS12WhitelistClientServer( void )
	{
	return( tls12ClientServer( TLS_TEST_WHITELIST ) );
	}
int testSessionTLS12WhitelistFailClientServer( void )
	{
	return( tls12ClientServer( TLS_TEST_WHITELIST_FAIL ) );
	}
int testSessionTLS12WebSocketsClientServer( void )
	{
	return( tls12ClientServer( TLS_TEST_WEBSOCKETS ) );
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall tls13ServerThread( void *arg )
#else
  static void *tls13ServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

	connectTLS( CRYPT_SESSION_TLS_SERVER, argValue, 4, CRYPT_UNUSED, 
				TRUE );
	THREAD_EXIT();
	}

#ifdef USE_TLS13

static int tls13ClientServer( const TLS_TEST_TYPE testType )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = testType, status;

	/* If this is a test that requires a database keyset, make sure that one 
	   is available */
	if( testType == TLS_TEST_CLIENTCERT && \
		!checkDatabaseKeysetAvailable() )
		{
		fputs( "Skipping test due to unavailability of database "
			   "keysets.\n\n", outputStream );
		return( TRUE );
		}

	/* Start the server */
	createMutex();
#ifdef WINDOWS_THREADS
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, tls13ServerThread, &arg, 0, 
										 &threadID );
#else
	pthread_create( &hThread, NULL, tls13ServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 1000 );

	/* Connect to the local server */
	status = connectTLS( CRYPT_SESSION_TLS, testType, 4, CRYPT_UNUSED, 
						 TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
#endif /* USE_TLS13 */
int testSessionTLS13ClientServer( void )
	{
#ifdef USE_TLS13
	return( tls13ClientServer( TLS_TEST_NORMAL ) );
#else
	return( TRUE );
#endif /* USE_TLS13 */
	}
int testSessionTLS13ClientServerEccKey( void )
	{
#ifdef USE_TLS13
	return( tls13ClientServer( TLS_TEST_ECC ) );
#else
	return( TRUE );
#endif /* USE_TLS13 */
	}
int testSessionTLS13ClientServerEd25519Key( void )
	{
#ifdef USE_TLS13
	return( tls13ClientServer( TLS_TEST_ED25519 ) );
#else
	return( TRUE );
#endif /* USE_TLS13 */
	}
int testSessionTLS13ClientCertClientServer( void )
	{
#ifdef USE_TLS13
	return( tls13ClientServer( TLS_TEST_CLIENTCERT ) );
#else
	return( TRUE );
#endif /* USE_TLS13 */
	}
int testSessionTLS13ForceTLS13ClientServer( void )
	{
#ifdef USE_TLS13
	int status;

	status = tls13ClientServer( TLS_TEST_FORCEVER_CLI );
	if( status == TRUE )
		status = tls13ClientServer( TLS_TEST_FORCEVER_SVR );
	return( status );
#else
	return( TRUE );
#endif /* USE_TLS13 */
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall tlsServerDualThread2( void *arg )
#else
  static void *tlsServerDualThread2( void *arg )
#endif /* Windows vs. Unix threads */
	{
	connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_DUALTHREAD, 1, 0, TRUE );
	THREAD_EXIT();
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall tlsServerDualThread1( void *arg )
#else
  static void *tlsServerDualThread1( void *arg )
#endif /* Windows vs. Unix threads */
	{
	connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_DUALTHREAD, 1, 
				CRYPT_UNUSED, TRUE );
	THREAD_EXIT();
	}

int testSessionTLSClientServerDualThread( void )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int status;

	/* Start the server */
	createMutex();
#ifdef WINDOWS_THREADS
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, tlsServerDualThread1,
										 NULL, 0, &threadID );
#else
	pthread_create( &hThread, NULL, tlsServerDualThread1, NULL );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 1000 );

	/* Connect to the local server */
	status = connectTLS( CRYPT_SESSION_TLS, TLS_TEST_PSK, 1, CRYPT_UNUSED, 
						 TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall tlsServerMultiThread( void *arg )
#else
  static void *tlsServerMultiThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	int threadID = *( ( int * ) arg );

	connectTLS( CRYPT_SESSION_TLS_SERVER, TLS_TEST_MULTITHREAD, 1, threadID, 
				TRUE );
	THREAD_EXIT();
	}
#ifdef WINDOWS_THREADS
  static unsigned __stdcall tlsClientMultiThread( void *arg )
#else
  static void *tlsClientMultiThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	int threadID = *( ( int * ) arg );

	connectTLS( CRYPT_SESSION_TLS, TLS_TEST_MULTITHREAD, 1, threadID, 
				TRUE );
	THREAD_EXIT();
	}

int testSessionTLSClientServerMultiThread( void )
	{
	return( multiThreadDispatch( tlsClientMultiThread, 
								 tlsServerMultiThread, MAX_NO_THREADS ) );
	}

int testSessionTLSClientServerDebugCheck( void )
	{
#if defined( CONFIG_FAULTS ) && !defined( NDEBUG )
	cryptSetFaultType( FAULT_NONE );

	/* SSLv3 tests */
	if( !tlsClientServer( TLS_TEST_CORRUPT_HANDSHAKE ) )
		return( FALSE );	/* Detect corruption of handshake data */
	if( !tlsClientServer( TLS_TEST_CORRUPT_DATA ) )
		return( FALSE );	/* Detect corruption of payload data */
	if( !tlsClientServer( TLS_TEST_CORRUPT_MAC ) )
		return( FALSE );	/* Detect corruption of IV */
	if( !tlsClientServer( TLS_TEST_CORRUPT_FINISHED ) )
		return( FALSE );	/* Detect corruption of IV */
	if( !tlsClientServer( TLS_TEST_WRONGCERT ) )
		return( FALSE );	/* Detect wrong key for server */
	if( !tlsClientServer( TLS_TEST_BADSIG_HASH ) )
		return( FALSE );	/* Detect corruption of signed DH params */
	if( !tlsClientServer( TLS_TEST_BADSIG_SIG ) )
		return( FALSE );	/* Detect corruption of DH signature */
	if( !tlsClientServer( TLS_TEST_BADSIG_DATA ) )
		return( FALSE );	/* Detect corruption of signed DH params */

	/* TLS 1.0 tests */
	if( !tlsClientServer( TLS_TEST_CORRUPT_HANDSHAKE ) )
		return( FALSE );	/* Detect corruption of handshake data */
	if( !tlsClientServer( TLS_TEST_CORRUPT_DATA ) )
		return( FALSE );	/* Detect corruption of payload data */
	if( !tlsClientServer( TLS_TEST_CORRUPT_MAC ) )
		return( FALSE );	/* Detect corruption of IV */
	if( !tlsClientServer( TLS_TEST_CORRUPT_FINISHED ) )
		return( FALSE );	/* Detect corruption of IV */
	if( !tlsClientServer( TLS_TEST_WRONGCERT ) )
		return( FALSE );	/* Detect wrong key for server */
	if( !tlsClientServer( TLS_TEST_BADSIG_HASH ) )
		return( FALSE );	/* Detect corruption of signed DH params */
	if( !tlsClientServer( TLS_TEST_BADSIG_SIG ) )
		return( FALSE );	/* Detect corruption of DH signature */
	if( !tlsClientServer( TLS_TEST_BADSIG_DATA ) )
		return( FALSE );	/* Detect corruption of signed DH params */

	/* TLS 1.2 tests */
	if( !tls12ClientServer( TLS_TEST_CORRUPT_HANDSHAKE ) )
		return( FALSE );	/* Detect corruption of handshake data */
	if( !tls12ClientServer( TLS_TEST_CORRUPT_DATA ) )
		return( FALSE );	/* Detect corruption of payload data */
	if( !tls12ClientServer( TLS_TEST_CORRUPT_MAC ) )
		return( FALSE );	/* Detect corruption of IV */
	if( !tls12ClientServer( TLS_TEST_CORRUPT_FINISHED ) )
		return( FALSE );	/* Detect corruption of IV */
	if( !tls12ClientServer( TLS_TEST_CORRUPT_IV ) )
		return( FALSE );	/* Detect corruption of IV */
	if( !tls12ClientServer( TLS_TEST_WRONGCERT ) )
		return( FALSE );	/* Detect wrong key for server */
	if( !tls12ClientServer( TLS_TEST_BADSIG_HASH ) )
		return( FALSE );	/* Detect corruption of signed DH params */
	if( !tls12ClientServer( TLS_TEST_BADSIG_SIG ) )
		return( FALSE );	/* Detect corruption of DH signature */
	if( !tls12ClientServer( TLS_TEST_BADSIG_DATA ) )
		return( FALSE );	/* Detect corruption of signed DH params */
	cryptSetFaultType( FAULT_NONE );
#endif /* CONFIG_FAULTS && Debug */
	return( TRUE );
	}
#endif /* TEST_SESSION_LOOPBACK */

#endif /* TEST_SESSION || TEST_SESSION_LOOPBACK */
