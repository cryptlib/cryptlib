<<<<<<< HEAD
/****************************************************************************
*																			*
*							cryptlib EAP Test Code							*
*						Copyright Peter Gutmann 2016-2023					*
*																			*
****************************************************************************/

/* Under Windows debug mode everything is enabled by default when building 
   cryptlib, so we also enable the required options here.  Under Unix it'll
   need to be enabled manually by adding '-DUSE_EAP -DUSE_DES' to the build 
   command.  Note that this needs to be done via the build process even if
   it's already defined in config.h since that only applies to cryptlib, not
   to this module */

#if defined( _MSC_VER ) && !defined( NDEBUG )
  #define USE_EAP
#endif /* Windows debug build */

#include <stdlib.h>
#include <string.h>
#if !( defined( _WIN32 ) || defined( _WIN64 ) )
  #include <locale.h>
#endif /* !Windows */
#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/* Enable the following for the EAP loopback tests */

#if 1
  #define TEST_SESSION_LOOPBACK
#else
  #undef TEST_SESSION_LOOPBACK
#endif /* 0 */

/* EAP subprotocol and authentication types */

typedef enum { PROTOCOL_EAPTTLS, PROTOCOL_PEAP, PROTOCOL_PEAP_LOOPBACK, 
			   PROTOCOL_PEAP_NPS, PROTOCOL_PEAP_NPS_LOOPBACK, 
			   PROTOCOL_LAST } PROTOCOL_TYPE; 
typedef enum { AUTH_PAP, AUTH_CHAP, AUTH_MSCHAPV2, AUTH_LAST } AUTH_TYPE;

/* The maximum size of the buffer to hold the authentication data sent over
   the EAP subprotocol tunnel */

#define EAP_PEAP_BUFFER_SIZE		256

/* Additional debugging suppport when we're built in debug mode */

#ifdef NDEBUG
  #define DEBUG_PUTS( x )
  #define DEBUG_PRINT( x )
  #define DEBUG_DUMPHEX( x, xLen )
  #define DEBUG_DUMPHEX_ALL( x, xLen )
#else
  #define DEBUG_PUTS( x )			printf( "%s\n", x )
  #define DEBUG_PRINT( x )			printf x
  #define DEBUG_DUMPHEX				dumpHexDataPart
  #define DEBUG_DUMPHEX_ALL			dumpHexData
#endif /* NDEBUG */

#ifdef USE_EAP

/* Prototypes for functions in eap_peap.c */

int completePEAPhandshake( const CRYPT_SESSION cryptSession,
						   const char *user, const char *password );
int completePEAPhandshakeServer( const CRYPT_SESSION cryptSession,
								 const char *user, 
								 const char *password );

/* Prototypes for functions in eap_ttls.c */

int completeEAPTTLShandshake( const CRYPT_SESSION cryptSession,
							  const char *user, 
							  const char *password,
							  const AUTH_TYPE authType );

/* EAP test types */

typedef enum { TEST_NORMAL, TEST_WRONGUSER, TEST_WRONGPASSWORD, 
			   TEST_LAST } TEST_TYPE;

/* Text descriptions of the different sub-protocols and authentication 
   types.  These must match the corresponding PROTOCOL_xxx/AUTH_xxx values */

static const char *protocolName[] = {
	"EAP-TTLS", "PEAP", "<<<Unknown>>>", "<<<Unknown>>>"
	};
static const char *authName[] = {
	"PAP", "CHAP", "MSCHAPv2", "<<<Unknown>>>", "<<<Unknown>>>"
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Create an EAP-over-TLS session */

static int createEAPsession( CRYPT_SESSION *cryptEAPSession, 
							 const char *server,
							 const char *user, const char *password,
							 const PROTOCOL_TYPE protocolType,
							 const BOOLEAN localSession )
	{
	CRYPT_SESSION cryptSession;
	const BOOLEAN isServer = ( server == NULL ) ? TRUE : FALSE;
	int status;

	/* Clear return value */
	*cryptEAPSession = -1;

	/* Create the TLS session and set the client/server parameters as
	   appropriate */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 isServer ? CRYPT_SESSION_TLS_SERVER : \
											CRYPT_SESSION_TLS );
	if( cryptStatusError( status ) )
		return( status );
	if( isServer )
		{
		CRYPT_CONTEXT privateKey;
		char filenameBuffer[ FILENAME_BUFFER_SIZE ];

		if( localSession )
			{
			if( !setLocalConnect( cryptSession, 1812 ) )
				{
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			}
		else
			{
			/* Set a slightly different port to allow running on devices 
			   that already have a RADIUS server active */
			cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT, 
							   1814 );
			}
		filenameFromTemplate( filenameBuffer, SERVER_PRIVKEY_FILE_TEMPLATE, 
							  1 );
		status = getPrivateKey( &privateKey, filenameBuffer, 
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_PRIVATEKEY, 
										privateKey );
			cryptDestroyContext( privateKey );
			}
		}
	else
		{
		status = cryptSetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_SERVER_NAME, 
										  server, strlen( server ) );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	/* Select EAP-TTLS or PEAP as required */
	switch( protocolType )
		{
		case PROTOCOL_EAPTTLS:
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
										CRYPT_SUBPROTOCOL_EAPTTLS );
			break;

		case PROTOCOL_PEAP:
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
										CRYPT_SUBPROTOCOL_PEAP );
			break;

		default:
			status = CRYPT_ERROR_PARAM5;
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	/* Set the authentication information */
	status = cryptSetAttributeString( cryptSession, 
									  CRYPT_SESSINFO_USERNAME, 
									  user, strlen( user ) );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_PASSWORD, 
										  password, strlen( password ) );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	*cryptEAPSession = cryptSession;
	return( CRYPT_OK );
	}

/* Get any additional data that may have been provided by the server */

static int getExtraData( const CRYPT_SESSION cryptSession,
						 BYTE *data, int *dataLen, const int dataMaxLen )
	{
	int extraDataLength, status;

	/* Get any extra data that may be present */
	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPDATA, 
									  NULL, &extraDataLength );
	if( cryptStatusError( status ) )
		return( status );
	if( extraDataLength > dataMaxLen )
		return( CRYPT_ERROR_OVERFLOW );
	return( cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPDATA, 
									 data, dataLen ) );
	}

/****************************************************************************
*																			*
*							EAP Client Test Functions						*
*																			*
****************************************************************************/

/* Test an EAP subprotocol, either EAP-TTLS (PAP, CHAP, or MSCHAPv2) or PEAP 
   (MSCHAPv2), with various EAP authentication types and correct or 
   incorrect parameters */

static int testEAPSubprotocol( const PROTOCOL_TYPE protocolType, 
							   const AUTH_TYPE authType,
							   const TEST_TYPE testType,
							   const BOOLEAN localSession )
	{
	CRYPT_SESSION cryptSession;
	const char *serverName, *password;
	const char *user = "test321";
	const char *radiusSecret = "dummy";
	const PROTOCOL_TYPE localProtocolType = \
							( protocolType == PROTOCOL_PEAP_LOOPBACK || \
							  protocolType == PROTOCOL_PEAP_NPS || \
							  protocolType == PROTOCOL_PEAP_NPS_LOOPBACK ) ? \
							  PROTOCOL_PEAP : protocolType; 
	BYTE dataBuffer[ 128 ];
	int dataLength, status, extraDataStatus;

	/* Make sure that a valid test has been selected */
	switch( protocolType )
		{
		case PROTOCOL_EAPTTLS:
			/* XU4, EAP-TTLS on FreeRADIUS */
			serverName = "odroid.xu4.lan:1812";
			password = "testing123";
			break;

		case PROTOCOL_PEAP:
			/* N2, PEAP on FreeRADIUS.  This sometimes produces an "MSCHAPv2 
			   response is incorrect" error on the first run, re-running it
			   a few times makes it work */
			serverName = "odroid.n2.lan:1812";
			password = "testing123";
			break;

		case PROTOCOL_PEAP_LOOPBACK:
			/* Loopback PEAP test */
			serverName = "localhost:1812";
			password = "testing123";
			break;

		case PROTOCOL_PEAP_NPS:
			/* NPS, PEAP on NPS with password-complexity requirements that 
			   disallow the use of the standard test password */
#if 0
			serverName = "101.100.138.250:1812";
			password = "Slipper520#Couch";
#else
			serverName = "10.0.0.15:1812";
			password = "test";
#endif /* 1 */
			break;

		case PROTOCOL_PEAP_NPS_LOOPBACK:
			serverName = "localhost:1812";
			password = "test";
			break;

		default:
			puts( "Invalid protocol type." );
			return( FALSE );
		}

	if( authType < AUTH_PAP || authType >= AUTH_LAST )
		{
		puts( "Invalid auth type." );
		return( FALSE );
		}

	/* Set up the required test parameters */
	switch( testType )
		{
		case TEST_NORMAL:
			break;

		case TEST_WRONGUSER:
			user = "wrongUsername";
			break;

		case TEST_WRONGPASSWORD:
			password = "wrongPassword";
			break;

		default:
			puts( "Invalid test type." );
			return( FALSE );
		}

	/* Run a self-test of the EAP crypto to verify that it's working OK */
	if( !testEAPCrypto() )
		return( FALSE );

	/* Report what we're doing */
	printf( "Connecting to %s using %s/%s, user = %s, password = %s,\n"
			"  RADIUS secret = %s.\n", serverName, 
			protocolName[ localProtocolType ], authName[ authType ], user, 
			password, radiusSecret );

	/* If this is a local session, wait for the server to finish initialising */
	if( localSession && waitMutex() == CRYPT_ERROR_TIMEOUT )
		{
		fprintf( outputStream, "Timed out waiting for server to initialise, "
				 "line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Create the EAP session */
	status = createEAPsession( &cryptSession, serverName, user, 
							   radiusSecret, localProtocolType, FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to create EAP session failed, status %d.\n", 
				status );
		return( FALSE );
		}

	/* No 2.x version of FreeRADIUS and no 3.x version before about 3.10
	   supported TLS 1.2 or even 1.1, returning weird errors if newer 
	   versions of TLS were attempted.  To deal with this, undefine the 
	   following, which forces use of TLS 1.0 in order to deal with older
	   FreeRADIUS implementations */
#if 0
	cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, 1 );
#endif /* 0 */

	/* Disable name verification to allow the test server's self-signed RFC 
	   1918 address cert to work */
	cryptSetAttribute( cryptSession, CRYPT_SESSINFO_TLS_OPTIONS, 
					   CRYPT_TLSOPTION_DISABLE_NAMEVERIFY );

	/* Activate the EAP-TTLS or PEAP tunnel.  cryptlib sends the identity
	   in the outermost RADIUS tunnel as "anonymous" as required by several
	   usage documents, this is allowed by default by FreeRADIUS but not 
	   Windows NPS which will need to have the "Enable Identity Privacy" 
	   setting enabled, see
	   https://learn.microsoft.com/en-us/archive/blogs/wsnetdoc/peap-identity-privacy-support-in-windows-7-and-windows-server-2008-r2 
	   https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff919512(v=ws.10) */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		const int networkStatus = status;
		int errorMessageLength;

		printf( "Session activation failed with error code %d.\n", status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );
		if( networkStatus == CRYPT_ERROR_TIMEOUT && \
			!strcmp( password, radiusSecret ) )
			{
			/* EAP-over-RADIUS requires that all RADIUS messages contain a 
			   Message-Authenticator attribute, with packets with an 
			   incorrect HMAC-MD5 authentication value being silently 
			   dropped.  If the authenticator is also the user's password, 
			   an incorrect password will result in no response from the 
			   server until a timeout is triggered rather than an incorrect-
			   password response.  
			   
			   This totally stupid behaviour is mandated in RFC 3579, 
			   section 3.2: "[The Message-Authenticator] MUST be used in any 
			   Access-Request, Access-Accept, Access-Reject or Access-
			   Challenge that includes an EAP-Message attribute.  A RADIUS 
			   server receiving an Access-Request with a Message-
			   Authenticator attribute present MUST calculate the correct 
			   value of the Message-Authenticator and silently discard the 
			   packet if it does not match the value sent".  
			   
			   To deal with this, we report a CRYPT_ERROR_TIMEOUT as a 
			   possible incorrect password */
			puts( "  The network timeout may be due to an incorrect "
				  "password rather than an\n  actual networking problem, "
				  "since RADIUS silently drops packets\n  authenticated "
				  "with incorrect passwords rather than returning an "
				  "error\n  response.  In other words no response will be "
				  "received from the server if\n  an incorrect password is "
				  "used.\n" );
			}
 		cryptDestroySession( cryptSession );
		return( FALSE );
		}

	/* At this point PEAP and EAP-TTLS diverge, so we complete the handshake
	   as required */
	if( localProtocolType == PROTOCOL_PEAP )
		{
		/* PEAP uses a format that Microsoft invented, parts of which are
		   probably implementation bugs from Windows 2000, we can't continue 
		   with the standard EAP process but have to move to a PEAP-specific 
		   one.  PEAP, or specifically Microsoft's PEAPv0 which is what 
		   everything uses, is really only defined for MSCHAPv2, so the 
		   following function continues with authType == MSCHAPv2 implied */
		status = completePEAPhandshake( cryptSession, user, password );
		}
	else
		{
		status = completeEAPTTLShandshake( cryptSession, user, password, 
										   authType );
		}
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		const int networkStatus = status;
		int errorMessageLength;

		printf( "%s authentication failed with error code %d.\n", 
				protocolName[ localProtocolType ], status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );

		/* Restore the previous status value */
		status = networkStatus;
		}

	/* Display any extra data that the server may have sent */
	extraDataStatus = getExtraData( cryptSession, dataBuffer, &dataLength, 
									512 );
	if( cryptStatusOK( extraDataStatus ) )
		{
		printf( "Server sent %d bytes additional data:\n  ", dataLength );
		DEBUG_DUMPHEX_ALL( dataBuffer, dataLength );
		printf( ".\n" );
		}

	/* Clean up */
	cryptDestroySession( cryptSession );
	printf( "Client authentication status = %d.\n", status );

	return( TRUE );
	}

int testEAP( void )
	{
#if 0
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_WRONGUSER, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_WRONGPASSWORD, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_CHAP, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_MSCHAPV2, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_MSCHAPV2, TEST_WRONGPASSWORD, FALSE );
#endif /* EAP-TTLS */
#if 1
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_WRONGUSER, FALSE );
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_WRONGPASSWORD, FALSE );
#endif /* PEAP */
#if 0
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_WRONGUSER, FALSE );
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_WRONGPASSWORD, FALSE );
#endif /* PEAP to Windows NPS */

	return( TRUE );
	}

/****************************************************************************
*																			*
*							EAP Server Test Functions						*
*																			*
****************************************************************************/

#ifdef TEST_SESSION_LOOPBACK

static int eapServer( const PROTOCOL_TYPE protocolType, 
					  const AUTH_TYPE authType, 
					  const BOOLEAN localSession )
	{
	CRYPT_SESSION cryptSession;
	const char *password;
	const char *user = "test321";
	const char *radiusSecret = "dummy";
	const PROTOCOL_TYPE localProtocolType = \
							( protocolType == PROTOCOL_PEAP_NPS ) ? \
							  PROTOCOL_PEAP : protocolType; 
	int status;

	/* Make sure that a valid test has been selected */
	switch( protocolType )
		{
		case PROTOCOL_EAPTTLS:
			password = "testing123";
			break;

		case PROTOCOL_PEAP:
			password = "testing123";
			break;

		case PROTOCOL_PEAP_NPS:
			password = "test";
			break;

		default:
			puts( "Invalid protocol type." );
			return( FALSE );
		}

	if( authType < AUTH_PAP || authType >= AUTH_LAST )
		{
		puts( "Invalid auth type." );
		return( FALSE );
		}

	/* Report what we're doing */
	printf( "Running server using %s/%s, user = %s, password = %s,\n"
			"  RADIUS secret = %s.\n", 
			protocolName[ localProtocolType ], authName[ authType ], user, 
			password, radiusSecret );

	/* If this is a local session, acquire the init mutex */
	if( localSession )
		acquireMutex();

	/* Create the EAP session */
	status = createEAPsession( &cryptSession, NULL, user, radiusSecret, 
							   localProtocolType, localSession );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to create EAP server session failed, status %d.\n", 
				status );
		return( FALSE );
		}

	/* If this is a local session, tell the client that we're ready to go */
	if( localSession )
		releaseMutex();

	/* Activate the EAP-TTLS or PEAP tunnel */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		int errorMessageLength;

		printf( "SVR: Session activation failed with error code %d.\n", status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );
 		cryptDestroySession( cryptSession );
		return( FALSE );
		}

	/* At this point PEAP and EAP-TTLS diverge, so we complete the handshake
	   as required */
	if( localProtocolType == PROTOCOL_PEAP )
		{
		status = completePEAPhandshakeServer( cryptSession, user, password );
		}
#if 0	/* EAP-TTLS isn't implemented yet */
	else
		{
		status = completeEAPTTLShandshake( cryptSession, user, password, 
										   authType );
		}
#endif /* 0 */
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		const int networkStatus = status;
		int errorMessageLength;

		printf( "%s authentication failed with error code %d.\n", 
				protocolName[ localProtocolType ], status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );

		/* Restore the previous status value */
		status = networkStatus;
		}

	/* Clean up */
	cryptDestroySession( cryptSession );
	printf( "Server authentication status = %d.\n", status );

	return( TRUE );
	}

int testEAPServer( void )
	{
	return( eapServer( PROTOCOL_PEAP, AUTH_MSCHAPV2, FALSE ) );
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall eapServerThread( void *arg )
#else
  static void *eapServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

	eapServer( argValue, AUTH_MSCHAPV2, TRUE );
	THREAD_EXIT();
	}

int testEAPClientServer( void )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = PROTOCOL_PEAP, status;

	/* Start the server */
	createMutex();
#ifdef WINDOWS_THREADS
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, eapServerThread, &arg, 0, 
										 &threadID );
#else
	pthread_create( &hThread, NULL, eapServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 2000 );	/* Server can take while to start */

	/* Connect to the local server */
	status = testEAPSubprotocol( PROTOCOL_PEAP_LOOPBACK, AUTH_MSCHAPV2, 
								 TEST_NORMAL, TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
#endif /* TEST_SESSION_LOOPBACK */
#endif /* USE_EAP */
=======
/****************************************************************************
*																			*
*							cryptlib EAP Test Code							*
*						Copyright Peter Gutmann 2016-2023					*
*																			*
****************************************************************************/

/* Under Windows debug mode everything is enabled by default when building 
   cryptlib, so we also enable the required options here.  Under Unix it'll
   need to be enabled manually by adding '-DUSE_EAP -DUSE_DES' to the build 
   command.  Note that this needs to be done via the build process even if
   it's already defined in config.h since that only applies to cryptlib, not
   to this module */

#if defined( _MSC_VER ) && !defined( NDEBUG )
  #define USE_EAP
#endif /* Windows debug build */

#include <stdlib.h>
#include <string.h>
#if !( defined( _WIN32 ) || defined( _WIN64 ) )
  #include <locale.h>
#endif /* !Windows */
#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/* Enable the following for the EAP loopback tests */

#if 1
  #define TEST_SESSION_LOOPBACK
#else
  #undef TEST_SESSION_LOOPBACK
#endif /* 0 */

/* EAP subprotocol and authentication types */

typedef enum { PROTOCOL_EAPTTLS, PROTOCOL_PEAP, PROTOCOL_PEAP_LOOPBACK, 
			   PROTOCOL_PEAP_NPS, PROTOCOL_PEAP_NPS_LOOPBACK, 
			   PROTOCOL_LAST } PROTOCOL_TYPE; 
typedef enum { AUTH_PAP, AUTH_CHAP, AUTH_MSCHAPV2, AUTH_LAST } AUTH_TYPE;

/* The maximum size of the buffer to hold the authentication data sent over
   the EAP subprotocol tunnel */

#define EAP_PEAP_BUFFER_SIZE		256

/* Additional debugging suppport when we're built in debug mode */

#ifdef NDEBUG
  #define DEBUG_PUTS( x )
  #define DEBUG_PRINT( x )
  #define DEBUG_DUMPHEX( x, xLen )
  #define DEBUG_DUMPHEX_ALL( x, xLen )
#else
  #define DEBUG_PUTS( x )			printf( "%s\n", x )
  #define DEBUG_PRINT( x )			printf x
  #define DEBUG_DUMPHEX				dumpHexDataPart
  #define DEBUG_DUMPHEX_ALL			dumpHexData
#endif /* NDEBUG */

#ifdef USE_EAP

/* Prototypes for functions in eap_peap.c */

int completePEAPhandshake( const CRYPT_SESSION cryptSession,
						   const char *user, const char *password );
int completePEAPhandshakeServer( const CRYPT_SESSION cryptSession,
								 const char *user, 
								 const char *password );

/* Prototypes for functions in eap_ttls.c */

int completeEAPTTLShandshake( const CRYPT_SESSION cryptSession,
							  const char *user, 
							  const char *password,
							  const AUTH_TYPE authType );

/* EAP test types */

typedef enum { TEST_NORMAL, TEST_WRONGUSER, TEST_WRONGPASSWORD, 
			   TEST_LAST } TEST_TYPE;

/* Text descriptions of the different sub-protocols and authentication 
   types.  These must match the corresponding PROTOCOL_xxx/AUTH_xxx values */

static const char *protocolName[] = {
	"EAP-TTLS", "PEAP", "<<<Unknown>>>", "<<<Unknown>>>"
	};
static const char *authName[] = {
	"PAP", "CHAP", "MSCHAPv2", "<<<Unknown>>>", "<<<Unknown>>>"
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Create an EAP-over-TLS session */

static int createEAPsession( CRYPT_SESSION *cryptEAPSession, 
							 const char *server,
							 const char *user, const char *password,
							 const PROTOCOL_TYPE protocolType,
							 const BOOLEAN localSession )
	{
	CRYPT_SESSION cryptSession;
	const BOOLEAN isServer = ( server == NULL ) ? TRUE : FALSE;
	int status;

	/* Clear return value */
	*cryptEAPSession = -1;

	/* Create the TLS session and set the client/server parameters as
	   appropriate */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 isServer ? CRYPT_SESSION_TLS_SERVER : \
											CRYPT_SESSION_TLS );
	if( cryptStatusError( status ) )
		return( status );
	if( isServer )
		{
		CRYPT_CONTEXT privateKey;
		char filenameBuffer[ FILENAME_BUFFER_SIZE ];

		if( localSession )
			{
			if( !setLocalConnect( cryptSession, 1812 ) )
				{
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			}
		else
			{
			/* Set a slightly different port to allow running on devices 
			   that already have a RADIUS server active */
			cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT, 
							   1814 );
			}
		filenameFromTemplate( filenameBuffer, SERVER_PRIVKEY_FILE_TEMPLATE, 
							  1 );
		status = getPrivateKey( &privateKey, filenameBuffer, 
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_PRIVATEKEY, 
										privateKey );
			cryptDestroyContext( privateKey );
			}
		}
	else
		{
		status = cryptSetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_SERVER_NAME, 
										  server, strlen( server ) );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	/* Select EAP-TTLS or PEAP as required */
	switch( protocolType )
		{
		case PROTOCOL_EAPTTLS:
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
										CRYPT_SUBPROTOCOL_EAPTTLS );
			break;

		case PROTOCOL_PEAP:
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
										CRYPT_SUBPROTOCOL_PEAP );
			break;

		default:
			status = CRYPT_ERROR_PARAM5;
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	/* Set the authentication information */
	status = cryptSetAttributeString( cryptSession, 
									  CRYPT_SESSINFO_USERNAME, 
									  user, strlen( user ) );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_PASSWORD, 
										  password, strlen( password ) );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroySession( cryptSession );
		return( status );
		}

	*cryptEAPSession = cryptSession;
	return( CRYPT_OK );
	}

/* Get any additional data that may have been provided by the server */

static int getExtraData( const CRYPT_SESSION cryptSession,
						 BYTE *data, int *dataLen, const int dataMaxLen )
	{
	int extraDataLength, status;

	/* Get any extra data that may be present */
	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPDATA, 
									  NULL, &extraDataLength );
	if( cryptStatusError( status ) )
		return( status );
	if( extraDataLength > dataMaxLen )
		return( CRYPT_ERROR_OVERFLOW );
	return( cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPDATA, 
									 data, dataLen ) );
	}

/****************************************************************************
*																			*
*							EAP Client Test Functions						*
*																			*
****************************************************************************/

/* Test an EAP subprotocol, either EAP-TTLS (PAP, CHAP, or MSCHAPv2) or PEAP 
   (MSCHAPv2), with various EAP authentication types and correct or 
   incorrect parameters */

static int testEAPSubprotocol( const PROTOCOL_TYPE protocolType, 
							   const AUTH_TYPE authType,
							   const TEST_TYPE testType,
							   const BOOLEAN localSession )
	{
	CRYPT_SESSION cryptSession;
	const char *serverName, *password;
	const char *user = "test321";
	const char *radiusSecret = "dummy";
	const PROTOCOL_TYPE localProtocolType = \
							( protocolType == PROTOCOL_PEAP_LOOPBACK || \
							  protocolType == PROTOCOL_PEAP_NPS || \
							  protocolType == PROTOCOL_PEAP_NPS_LOOPBACK ) ? \
							  PROTOCOL_PEAP : protocolType; 
	BYTE dataBuffer[ 128 ];
	int dataLength, status, extraDataStatus;

	/* Make sure that a valid test has been selected */
	switch( protocolType )
		{
		case PROTOCOL_EAPTTLS:
			/* XU4, EAP-TTLS on FreeRADIUS */
			serverName = "odroid.xu4.lan:1812";
			password = "testing123";
			break;

		case PROTOCOL_PEAP:
			/* N2, PEAP on FreeRADIUS.  This sometimes produces an "MSCHAPv2 
			   response is incorrect" error on the first run, re-running it
			   a few times makes it work */
			serverName = "odroid.n2.lan:1812";
			password = "testing123";
			break;

		case PROTOCOL_PEAP_LOOPBACK:
			/* Loopback PEAP test */
			serverName = "localhost:1812";
			password = "testing123";
			break;

		case PROTOCOL_PEAP_NPS:
			/* NPS, PEAP on NPS with password-complexity requirements that 
			   disallow the use of the standard test password */
#if 0
			serverName = "101.100.138.250:1812";
			password = "Slipper520#Couch";
#else
			serverName = "10.0.0.15:1812";
			password = "test";
#endif /* 1 */
			break;

		case PROTOCOL_PEAP_NPS_LOOPBACK:
			serverName = "localhost:1812";
			password = "test";
			break;

		default:
			puts( "Invalid protocol type." );
			return( FALSE );
		}

	if( authType < AUTH_PAP || authType >= AUTH_LAST )
		{
		puts( "Invalid auth type." );
		return( FALSE );
		}

	/* Set up the required test parameters */
	switch( testType )
		{
		case TEST_NORMAL:
			break;

		case TEST_WRONGUSER:
			user = "wrongUsername";
			break;

		case TEST_WRONGPASSWORD:
			password = "wrongPassword";
			break;

		default:
			puts( "Invalid test type." );
			return( FALSE );
		}

	/* Run a self-test of the EAP crypto to verify that it's working OK */
	if( !testEAPCrypto() )
		return( FALSE );

	/* Report what we're doing */
	printf( "Connecting to %s using %s/%s, user = %s, password = %s,\n"
			"  RADIUS secret = %s.\n", serverName, 
			protocolName[ localProtocolType ], authName[ authType ], user, 
			password, radiusSecret );

	/* If this is a local session, wait for the server to finish initialising */
	if( localSession && waitMutex() == CRYPT_ERROR_TIMEOUT )
		{
		fprintf( outputStream, "Timed out waiting for server to initialise, "
				 "line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Create the EAP session */
	status = createEAPsession( &cryptSession, serverName, user, 
							   radiusSecret, localProtocolType, FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to create EAP session failed, status %d.\n", 
				status );
		return( FALSE );
		}

	/* No 2.x version of FreeRADIUS and no 3.x version before about 3.10
	   supported TLS 1.2 or even 1.1, returning weird errors if newer 
	   versions of TLS were attempted.  To deal with this, undefine the 
	   following, which forces use of TLS 1.0 in order to deal with older
	   FreeRADIUS implementations */
#if 0
	cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, 1 );
#endif /* 0 */

	/* Disable name verification to allow the test server's self-signed RFC 
	   1918 address cert to work */
	cryptSetAttribute( cryptSession, CRYPT_SESSINFO_TLS_OPTIONS, 
					   CRYPT_TLSOPTION_DISABLE_NAMEVERIFY );

	/* Activate the EAP-TTLS or PEAP tunnel.  cryptlib sends the identity
	   in the outermost RADIUS tunnel as "anonymous" as required by several
	   usage documents, this is allowed by default by FreeRADIUS but not 
	   Windows NPS which will need to have the "Enable Identity Privacy" 
	   setting enabled, see
	   https://learn.microsoft.com/en-us/archive/blogs/wsnetdoc/peap-identity-privacy-support-in-windows-7-and-windows-server-2008-r2 
	   https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff919512(v=ws.10) */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		const int networkStatus = status;
		int errorMessageLength;

		printf( "Session activation failed with error code %d.\n", status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );
		if( networkStatus == CRYPT_ERROR_TIMEOUT && \
			!strcmp( password, radiusSecret ) )
			{
			/* EAP-over-RADIUS requires that all RADIUS messages contain a 
			   Message-Authenticator attribute, with packets with an 
			   incorrect HMAC-MD5 authentication value being silently 
			   dropped.  If the authenticator is also the user's password, 
			   an incorrect password will result in no response from the 
			   server until a timeout is triggered rather than an incorrect-
			   password response.  
			   
			   This totally stupid behaviour is mandated in RFC 3579, 
			   section 3.2: "[The Message-Authenticator] MUST be used in any 
			   Access-Request, Access-Accept, Access-Reject or Access-
			   Challenge that includes an EAP-Message attribute.  A RADIUS 
			   server receiving an Access-Request with a Message-
			   Authenticator attribute present MUST calculate the correct 
			   value of the Message-Authenticator and silently discard the 
			   packet if it does not match the value sent".  
			   
			   To deal with this, we report a CRYPT_ERROR_TIMEOUT as a 
			   possible incorrect password */
			puts( "  The network timeout may be due to an incorrect "
				  "password rather than an\n  actual networking problem, "
				  "since RADIUS silently drops packets\n  authenticated "
				  "with incorrect passwords rather than returning an "
				  "error\n  response.  In other words no response will be "
				  "received from the server if\n  an incorrect password is "
				  "used.\n" );
			}
 		cryptDestroySession( cryptSession );
		return( FALSE );
		}

	/* At this point PEAP and EAP-TTLS diverge, so we complete the handshake
	   as required */
	if( localProtocolType == PROTOCOL_PEAP )
		{
		/* PEAP uses a format that Microsoft invented, parts of which are
		   probably implementation bugs from Windows 2000, we can't continue 
		   with the standard EAP process but have to move to a PEAP-specific 
		   one.  PEAP, or specifically Microsoft's PEAPv0 which is what 
		   everything uses, is really only defined for MSCHAPv2, so the 
		   following function continues with authType == MSCHAPv2 implied */
		status = completePEAPhandshake( cryptSession, user, password );
		}
	else
		{
		status = completeEAPTTLShandshake( cryptSession, user, password, 
										   authType );
		}
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		const int networkStatus = status;
		int errorMessageLength;

		printf( "%s authentication failed with error code %d.\n", 
				protocolName[ localProtocolType ], status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );

		/* Restore the previous status value */
		status = networkStatus;
		}

	/* Display any extra data that the server may have sent */
	extraDataStatus = getExtraData( cryptSession, dataBuffer, &dataLength, 
									512 );
	if( cryptStatusOK( extraDataStatus ) )
		{
		printf( "Server sent %d bytes additional data:\n  ", dataLength );
		DEBUG_DUMPHEX_ALL( dataBuffer, dataLength );
		printf( ".\n" );
		}

	/* Clean up */
	cryptDestroySession( cryptSession );
	printf( "Client authentication status = %d.\n", status );

	return( TRUE );
	}

int testEAP( void )
	{
#if 0
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_WRONGUSER, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_PAP, TEST_WRONGPASSWORD, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_CHAP, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_MSCHAPV2, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_EAPTTLS, AUTH_MSCHAPV2, TEST_WRONGPASSWORD, FALSE );
#endif /* EAP-TTLS */
#if 1
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_WRONGUSER, FALSE );
	testEAPSubprotocol( PROTOCOL_PEAP, AUTH_MSCHAPV2, TEST_WRONGPASSWORD, FALSE );
#endif /* PEAP */
#if 0
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_NORMAL, FALSE );
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_WRONGUSER, FALSE );
	testEAPSubprotocol( PROTOCOL_PEAP_NPS, AUTH_MSCHAPV2, TEST_WRONGPASSWORD, FALSE );
#endif /* PEAP to Windows NPS */

	return( TRUE );
	}

/****************************************************************************
*																			*
*							EAP Server Test Functions						*
*																			*
****************************************************************************/

#ifdef TEST_SESSION_LOOPBACK

static int eapServer( const PROTOCOL_TYPE protocolType, 
					  const AUTH_TYPE authType, 
					  const BOOLEAN localSession )
	{
	CRYPT_SESSION cryptSession;
	const char *password;
	const char *user = "test321";
	const char *radiusSecret = "dummy";
	const PROTOCOL_TYPE localProtocolType = \
							( protocolType == PROTOCOL_PEAP_NPS ) ? \
							  PROTOCOL_PEAP : protocolType; 
	int status;

	/* Make sure that a valid test has been selected */
	switch( protocolType )
		{
		case PROTOCOL_EAPTTLS:
			password = "testing123";
			break;

		case PROTOCOL_PEAP:
			password = "testing123";
			break;

		case PROTOCOL_PEAP_NPS:
			password = "test";
			break;

		default:
			puts( "Invalid protocol type." );
			return( FALSE );
		}

	if( authType < AUTH_PAP || authType >= AUTH_LAST )
		{
		puts( "Invalid auth type." );
		return( FALSE );
		}

	/* Report what we're doing */
	printf( "Running server using %s/%s, user = %s, password = %s,\n"
			"  RADIUS secret = %s.\n", 
			protocolName[ localProtocolType ], authName[ authType ], user, 
			password, radiusSecret );

	/* If this is a local session, acquire the init mutex */
	if( localSession )
		acquireMutex();

	/* Create the EAP session */
	status = createEAPsession( &cryptSession, NULL, user, radiusSecret, 
							   localProtocolType, localSession );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to create EAP server session failed, status %d.\n", 
				status );
		return( FALSE );
		}

	/* If this is a local session, tell the client that we're ready to go */
	if( localSession )
		releaseMutex();

	/* Activate the EAP-TTLS or PEAP tunnel */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		int errorMessageLength;

		printf( "SVR: Session activation failed with error code %d.\n", status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );
 		cryptDestroySession( cryptSession );
		return( FALSE );
		}

	/* At this point PEAP and EAP-TTLS diverge, so we complete the handshake
	   as required */
	if( localProtocolType == PROTOCOL_PEAP )
		{
		status = completePEAPhandshakeServer( cryptSession, user, password );
		}
#if 0	/* EAP-TTLS isn't implemented yet */
	else
		{
		status = completeEAPTTLShandshake( cryptSession, user, password, 
										   authType );
		}
#endif /* 0 */
	if( cryptStatusError( status ) )
		{
		char errorMessage[ 512 ];
		const int networkStatus = status;
		int errorMessageLength;

		printf( "%s authentication failed with error code %d.\n", 
				protocolName[ localProtocolType ], status );
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_ATTRIBUTE_ERRORMESSAGE,
										  errorMessage, &errorMessageLength );
		if( cryptStatusOK( status ) )
			{
			errorMessage[ errorMessageLength ] = '\0';
			printf( "  Error message = %s'%s'.\n",
					( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
					errorMessage );
			}
		else
			puts( "  No extended error information available." );

		/* Restore the previous status value */
		status = networkStatus;
		}

	/* Clean up */
	cryptDestroySession( cryptSession );
	printf( "Server authentication status = %d.\n", status );

	return( TRUE );
	}

int testEAPServer( void )
	{
	return( eapServer( PROTOCOL_PEAP, AUTH_MSCHAPV2, FALSE ) );
	}

#ifdef WINDOWS_THREADS
  static unsigned __stdcall eapServerThread( void *arg )
#else
  static void *eapServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

	eapServer( argValue, AUTH_MSCHAPV2, TRUE );
	THREAD_EXIT();
	}

int testEAPClientServer( void )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = PROTOCOL_PEAP, status;

	/* Start the server */
	createMutex();
#ifdef WINDOWS_THREADS
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, eapServerThread, &arg, 0, 
										 &threadID );
#else
	pthread_create( &hThread, NULL, eapServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 2000 );	/* Server can take while to start */

	/* Connect to the local server */
	status = testEAPSubprotocol( PROTOCOL_PEAP_LOOPBACK, AUTH_MSCHAPV2, 
								 TEST_NORMAL, TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
#endif /* TEST_SESSION_LOOPBACK */
#endif /* USE_EAP */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
