<<<<<<< HEAD
/****************************************************************************
*																			*
*					cryptlib SCEP Session Test Routines						*
*					Copyright Peter Gutmann 1998-2021						*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */
#ifndef NDEBUG
  #include <limits.h>			/* Needed for analyse.h */
  #include "misc/analyse.h"		/* Needed for fault.h */
  #include "misc/fault.h"
#endif /* !NDEBUG */

/* Define the following to test the use of custom attributes via the pkiUser
   object */

/* #define TEST_CUSTOM_ATTRIBUTE */

/* We can run the SCEP self-test with a large variety of options, rather 
   than using dozens of boolean option flags to control them all we define 
   various test classes that exercise each option type */

typedef enum {
	SCEP_TEST_NONE,				/* No SCEP test type */
	SCEP_TEST_NORMAL,			/* Standard SCEP test */
	SCEP_TEST_SIGONLY,			/* Get certificate for sig-only algorithm */
	SCEP_TEST_CACERT,			/* Get CA cert instead of std.one */
	SCEP_TEST_CUSTOMEXT,		/* Add custom extension to request */
	SCEP_TEST_RENEW,			/* Renew existing certificate */
	SCEP_TEST_RENEW_SIGONLY,	/* Renew sig-only existing certificate */
	SCEP_TEST_CORRUPT_TRANSACTIONID, /* Detect corruption of transaction ID */
	SCEP_TEST_CORRUPT_TRANSIDVALUE, /* Detect corruption of trans.ID data */
	SCEP_TEST_CORRUPT_MESSAGETYPE, /* Detect corruption of message type */
	SCEP_TEST_CORRUPT_NONCE,	/* Detect corruption of sender/recipNonce */
	SCEP_TEST_CORRUPT_AUTHENTICATOR, /* Detect corruption of password */
	SCEP_TEST_LAST				/* Last possible CMP test type */
	} SCEP_TEST_TYPE;

#if defined( TEST_SESSION ) || defined( TEST_SESSION_LOOPBACK )

/****************************************************************************
*																			*
*								SCEP Test Data								*
*																			*
****************************************************************************/

/* There were various SCEP test servers available at some point, although 
   most of them are either semi- or entirely nonfunctional or vanished years
   ago.  The following mappings can be used to test different ones.  
   Implementation peculiarities below, an additional list of issues from the
   EJBCA folks is at
   https://download.primekey.com/docs/EJBCA-Enterprise/6_8_0/adminguide.html#Tested%20devices

	#1 - cryptlib: None.

	#2 - cryptlib ECC: None.

	#3 - SSH (www.ssh.com/support/testzone/pki.html): Invalid CA 
	     certificates, and disappeared some years ago.  Continued as Insta-
		 Certifier, see #7 below.

	#4 - OpenSCEP (openscep.othello.ch): Seems to be permanently unavailable.

	#5 - Entrust (freecerts.entrust.com/vpncerts/cep.htm): Only seems to be
		 set up to handle Cisco gear, and no longer available.

	#6 - EJBCA (see EJBCA note below): Server has vanished.
	
	#7 - Insta-Certifier: Information originally at 
		 http://www.certificate.fi/resources/demos/demo.htm, then at
		 http://security.insta.fi/solutions-en/product/productid=24167486.
		 This apparently implements SCEP as per the -09 draft from 2003 and
		 based on the appearance of the web page hasn't changed since it was
		 the SSH server in #2, so it doesn't really interoperate with any
		 version of SCEP from about the last ten years (no GetCACaps, no
		 POST, etc).  If necessary this behaviour can be forced by adding:

			scepInfo->flags |= SCEP_PFLAG_GOTCACAPS;
			sendPostAsGet = TRUE;

		 to the start of clientTransact() in session/scep_cli.c but this 
		 isn't recommended since it breaks correct functioning with any 
		 standard SCEP server.  Seems to have gone away as of 2018.

	#8 - Microsoft NDES (see NDES note below): Reverted to a fresh install 
		 with no content several years ago, but used to return an invalid CA 
		 certificate.  The code sets the compliance level to 
		 CRYPT_COMPLIANCELEVEL_OBLIVIOUS to handle this.  GetCACaps 
		 (via http://qa4-mdm3.qa4.imdmdemo.com/certsrv/mscep/?operation=GetCACaps) 
		 is implemented but broken, returns a zero-length response.  No 
		 longer available.
	
	#9 - Windows Server 2003 (see NDES note below): Closes the connection on 
		 seeing GetCACaps.  No longer available.

	#10 - Windows Server 2008 (see NDES note below): Returns an invalid CA 
		  certificate (keyUsage is set to keyEncipherment but not 
		  digitalSignature).  The code sets the compliance level to 
		  CRYPT_COMPLIANCELEVEL_OBLIVIOUS to handle this.  No longer 
		  available.

	#11 - Windows Server 2008 (upgraded form of #8, see NDES note below): 
		  Sends two certificates, one with keyUsage = digitalSignature, one 
		  with keyUsage = keyEncipherment, so CA certificate fetch must be 
		  implicit so that the SCEP code can sort out which certificate to 
		  use at what point.

		  When used with a implicit GetCACert (caCertUrl = "default") it 
		  closes the connection after the request has completed ('No data was 
		  read because the remote system closed the connection (recv() == 
		  0)'), when an explicit fetch is performed it doesn't get a chance 
		  to do this but then the certificate(s) that are returned can't be 
		  used.  No longer available.

	#12 - Private vendor: Uses an auth key that changes every 10-15 minutes,
		  obtained via 
		  https://jen.nuk9.com/pkiclient.exe?operation=GetChallengePassword&subject=CommonNameToBeUsed  
		  in this case 
		  https://jen.nuk9.com/pkiclient.exe?operation=GetChallengePassword&subject=Test%20SCEP%20PKI%20user
		  No longer available.

	#13 - Redwax test server: Built around Apache running mod_scep, sends an 
		  invalid CA certificate chain in response to GetCACert:

		  28   15:       SEQUENCE {
		  30    9:         OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
		  41    2:         [0] {
		  43    0:           OCTET STRING
		         :             Error: Object has zero length.
		         :           }
		         :         }
	
		  https://interop.redwax.eu/rs/scep/
	
	#14: Alternative Redwax test server that fixes the above issue.
	
	#15 - openXpki test server.  Fails with an internal server error if AES 
	      is used.  No longer available.

	#16: EJBCA test server (see EJBCA note below).

   NDES passwords are only valid for 60 minutes, are single-use, and you 
   can only set five of them per hour,
   https://social.technet.microsoft.com/wiki/contents/articles/9063.active-directory-certificate-services-ad-cs-network-device-enrollment-service-ndes.aspx#Password_and_Password_Cache
   so the password needs to be updated on each run and carefully managed on
   the server.  An alternative is UseSinglePassword mode which uses a fixed
   password for all certificates and requires complex server configuration 
   including registry hacks.

   EJBCA handles users/entities as single-use, so once a 
   certificate has been issued any further requests are rejected with an HTTP
   "Bad Request" (rather than an SCEP-level error), see
   https://download.primekey.com/docs/EJBCA-Enterprise/6_8_0/adminguide.html#Level%20of%20SCEP%20support
   To deal with this we allow EJBCA user names to be changed on each run */

#define EJBCA_USERNAME		"test1"

#define SCEP_NO		1

typedef struct {
	const char *name;
	const C_CHR *url, *user, *password;
	const C_CHR *caCertUrl;
		/* A URL for the caCertUrl fetches the CA certificate from this location 
		   before starting the SCEP session, NULL reads it from a file, and the 
		   string "default" use the built-in GetCACert capability to read it 
		   automatically */
	} SCEP_INFO;

static const SCEP_INFO scepInfo[] = {
	{ NULL },	/* Dummy so index == SCEP_NO */
	{ /*  1 */ "cryptlib", TEXT( "http://" LOCAL_HOST_NAME "/pkiclient.exe" ), NULL, NULL, 
/*				TEXT( "http://" LOCAL_HOST_NAME "/pkiclient.exe?operation=GetCACert&message=*" ) }, */
				TEXT( "default" ) },
				/* We have to implicitly get the certificate via the 
				   client's built-in GetCACert because if we do an explicit 
				   fetch from the caCertUrl via an HTTP keyset then the 
				   server won't have time to recycle before the next request 
				   comes in.  See also the comment in scepServerThread() on 
				   mutex management for the explicit HTTP fetch */
	{ /*  2 */ "cryptlib ECC", TEXT( "http://" LOCAL_HOST_NAME "/pkiclient.exe" ), NULL, NULL, 
				TEXT( "default" ) },
	{ /*  3 */ "SSH", TEXT( "http://pki.ssh.com:8080/scep/pkiclient.exe" ), 
				TEXT( "ssh" ), TEXT( "ssh" ),
				TEXT( "http://pki.ssh.com:8080/scep/pkiclient.exe?operation=GetCACert&message=test-ca1.ssh.com" ) },
	{ /*  4 */ "OpenSCEP", TEXT( "http://openscep.othello.ch/pkiclient.exe" ), 
				TEXT( "????" ), TEXT( "????" ), 
				NULL },
	{ /*  5 */ "Entrust", TEXT( "http://vpncerts.entrust.com/pkiclient.exe" ), 
				TEXT( "????" ), TEXT( "????" ), 
				NULL },
	{ /*  6 */ "EJBCA", TEXT( "http://q-rl-xp:8080/ejbca/publicweb/apply/scep/pkiclient.exe" ),
				TEXT( "test2" ), TEXT( "test2" ),
				TEXT( "http://q-rl-xp:8080/ejbca/publicweb/webdist/certdist?cmd=nscacert&issuer=O=Test&+level=1" ) },
	{ /*  7 */ "Insta-Certifier", TEXT( "http://pki.certificate.fi:8082/scep/" ), 
				TEXT( "user" ), TEXT( "scep" ), 
				TEXT( "http://pki.certificate.fi:8082/scep/?operation=GetCACert&message=Insta%20Demo%20CA" ) },
	{ /*  8 */ "Microsoft NDES", TEXT( "http://qa4-mdm3.qa4.imdmdemo.com" ), 
				TEXT( "cryptlibtest" ), TEXT( "password!1" ), 
				TEXT( "http://qa4-mdm3.qa4.imdmdemo.com/certsrv/mscep/?operation=GetCACert&message=qa" ) },
	{ /*  9 */ "Win Server 2003", TEXT( "http://202.93.162.4/certsrv/mscep/mscep.dll" ), 
				TEXT( "test" ), TEXT( "BF51DFAA61874412" ), "default" },
	{ /* 10 */ "Win Server 2008, explicit GetCACert", TEXT( "http://142.176.86.157" ), 
				TEXT( "cryptlibtest" ), TEXT( "password!1" ), 
				TEXT( "http://142.176.86.157/certsrv/mscep/?operation=GetCACert&message=qa" ) },
	{ /* 11 */ "Win Server 2008, implicit GetCACert", TEXT( "http://202.93.162.4/certsrv/mscep/mscep.dll" ), 
				TEXT( "test" ), TEXT( "00654F176111B253DD996EEA67BBF16D" ), 
				TEXT( "default" ) },
	{ /* 12 */ "Private vendor", TEXT( "http://jen.nuk9.com/pkiclient.exe" ), 
				TEXT( "user" ), TEXT( "STNDRUhGNXBLamU5TE5QWERwb2RicFdnUGVNOHNaTWtLZlo4cEpEazdkWT0sMTgzODY=" ), 
				TEXT( "default" ) },
	{ /* 13 */ "Redwax interop server", TEXT( "http://interop.redwax.eu/test/simple/scep" ), 
				TEXT( "test" ), TEXT( "test" ), 
				TEXT( "default" ) },
	{ /* 14 */ "Redwax alternative server", TEXT( "http://scep.redwax.webweaving.org" ),
				TEXT( "test" ), TEXT( "test" ), 
				TEXT( "default" ) },
	{ /* 15 */ "openXpki test server", TEXT( "http://84.103.205.141/scep" ), 
				TEXT( "test" ), TEXT( "SecretChallenge" ), 
				TEXT( "default" ) },
	{ /* 16 */ "EJBCA test server", TEXT( "http://84.103.205.141:8080/ejbca/publicweb/apply/scep/pkiclient.exe" ),
				TEXT( EJBCA_USERNAME ), TEXT( "test" ),
				TEXT( "default" ) }
	};

/* SCEP requires that its CA certificates be usable for decryption of request
   messages and signing of response messages.  Some SCEP CAs don't have the
   appropriate keyUsage bits for this set, in which case we have to process 
   the certificates in oblivious mode in order to use them */

#if ( SCEP_NO == 6 ) || ( SCEP_NO == 7 ) || ( SCEP_NO == 8 ) || \
	( SCEP_NO == 9 )
  #define SCEP_BROKEN_CA_CERT
#endif /* Insta-Certifier, Windows Server */

/* Certificate request data for the certificate from the SCEP server.  Note 
   that we have to set the CN to the PKI user CN, for CMP ir's we just omit 
   the DN entirely and have the server provide it for us but since SCEP uses 
   PKCS #10 requests we need to provide a DN, and since we provide it it has 
   to match the PKI user DN */

static const CERT_DATA scepRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
#if ( SCEP_NO == 14 )	
	/* EJBCA requires that the request CN == SCEP username in its default config */
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( EJBCA_USERNAME ) },
#else
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test SCEP PKI user" ) },
#endif /* SCEP_NO == 14 */

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* PKI user data to authorise the issuing of the various certs */

static const CERT_DATA scepPkiUserData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test SCEP PKI user" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Add a PKI user to the certificate store */

static int addPKIUser( const CRYPT_KEYSET cryptCertStore,
					   const CERT_DATA *pkiUserData,
					   const BOOLEAN isSCEP, 
					   const BOOLEAN testErrorChecking )
	{
	CRYPT_CERTIFICATE cryptPKIUser;
	CRYPT_SESSION cryptSession;
	C_CHR userID[ CRYPT_MAX_TEXTSIZE + 1 ], issuePW[ CRYPT_MAX_TEXTSIZE + 1 ];
	int length, status;

	puts( "-- Adding new PKI user information --" );

	/* Create the PKI user object and add the user's identification
	   information */
	status = cryptCreateCert( &cryptPKIUser, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_PKIUSER );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptPKIUser, pkiUserData, __LINE__ ) )
		return( FALSE );
#ifdef TEST_CUSTOM_ATTRIBUTE
	if( isSCEP && pkiUserData == scepPkiUserData )
		{
		const char *extensionData = "\x0C\x04Test";

		status = cryptAddCertExtension( cryptPKIUser, "1.2.3.4.5", FALSE, 
										extensionData, 6 );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
#endif /* TEST_CUSTOM_ATTRIBUTE */

	/* Add the user info to the certificate store */
	status = cryptCAAddItem( cryptCertStore, cryptPKIUser );
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		C_CHR userIdentifier[ CRYPT_MAX_TEXTSIZE + 1 ];

		/* Get the name of the duplicate user.  Since this may be just a
		   template we fall back to higher-level DN components if there's
		   no CN present */
		status = cryptGetAttributeString( cryptPKIUser,
										  CRYPT_CERTINFO_COMMONNAME,
										  userIdentifier, &length );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			status = cryptGetAttributeString( cryptPKIUser,
											  CRYPT_CERTINFO_ORGANISATIONALUNITNAME,
											  userIdentifier, &length );
			}
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			status = cryptGetAttributeString( cryptPKIUser,
											  CRYPT_CERTINFO_ORGANISATIONNAME,
											  userIdentifier, &length );
			}
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( cryptPKIUser, "cryptGetAttribute()",
								  status, __LINE__ ) );
			}
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		userIdentifier[ length ] = TEXT( '\0' );

		/* The PKI user info was already present, for SCEP this isn't a
		   problem since we can just re-use the existing info, but for CMP
		   we can only authorise a single certificate issue per user so we 
		   have to delete the existing user info and try again */
		if( isSCEP )
			{
			/* The PKI user info is already present from a previous run, get
			   the existing info */
			puts( "PKI user information is already present from a previous "
				  "run, reusing existing\n  PKI user data..." );
			cryptDestroyCert( cryptPKIUser );
			status = cryptCAGetItem( cryptCertStore, &cryptPKIUser,
									 CRYPT_CERTTYPE_PKIUSER, CRYPT_KEYID_NAME,
									 userIdentifier );
			}
		else
			{
			puts( "PKI user information is already present from a previous "
				  "run, deleting existing\n  PKI user data..." );
			status = cryptCADeleteItem( cryptCertStore, CRYPT_CERTTYPE_PKIUSER,
										CRYPT_KEYID_NAME, userIdentifier );
			if( cryptStatusError( status ) )
				{
				return( extErrorExit( cryptCertStore, "cryptCADeleteItem()",
									  status, __LINE__ ) );
				}
			status = cryptCAAddItem( cryptCertStore, cryptPKIUser );
			}
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertStore, "cryptCAAdd/GetItem()", status,
							  __LINE__ ) );
		}

	/* Display the information for the new user */
	if( !printCertInfo( cryptPKIUser ) )
		return( FALSE );
	status = cryptGetAttributeString( cryptPKIUser,
									  CRYPT_CERTINFO_PKIUSER_ID,
									  userID, &length );
	if( cryptStatusOK( status ) )
		{
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		userID[ length ] = '\0';
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									issuePW, &length );
		}
	if( cryptStatusOK( status ) )
		{
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		issuePW[ length ] = '\0';
		}
	else
		{
		return( extErrorExit( cryptPKIUser, "cryptGetAttribute()", status,
							  __LINE__ ) );
		}
	puts( "-- New PKI user information ends --\n" );

	/* If we're not testing the error-checking capability of the user
	   identifiers, we're done */
	if( !testErrorChecking )
		{
		cryptDestroyCert( cryptPKIUser );
		return( TRUE );
		}

	/* Make sure that the error-checking in the user information works via a
	   dummy CMP client session.  We have to check both passwords to reduce 
	   false positives since it's just a simple integrity check meant to 
	   catch typing errors rather than a cryptographically strong check */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 CRYPT_SESSION_CMP );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( userID[ 2 ] >= TEXT( 'A' ) && userID[ 2 ] < TEXT( 'Z' ) )
		userID[ 2 ]++;
	else
		userID[ 2 ] = TEXT( 'A' );
	if( issuePW[ 8 ] >= TEXT( 'A' ) && issuePW[ 8 ] < TEXT( 'Z' ) )
		issuePW[ 8 ]++;
	else
		issuePW[ 8 ] = TEXT( 'A' );
	status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_USERNAME,
									  userID, paramStrlen( userID ) );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_PASSWORD,
										  issuePW, paramStrlen( issuePW ) );
		}
	if( cryptStatusOK( status ) )
		{
		puts( "Integrity check of user ID and password failed to catch "
			  "errors in the data.\n(This check isn't foolproof and is "
			  "intended only to catch typing errors when\nentering the "
			  "data.  Try running the test again to see if the problem "
			  "still\noccurs)." );
		return( FALSE );
		}
	cryptDestroySession( cryptSession );

	/* Clean up */
	cryptDestroyCert( cryptPKIUser );
	return( TRUE );
	}

/* Get information on a PKI user */

int pkiGetUserInfo( C_STR userID, C_STR issuePW, C_STR revPW, 
					const C_STR userName )
	{
	CRYPT_KEYSET cryptCertStore;
	CRYPT_CERTIFICATE cryptPKIUser;
	int length, status;

	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations.  First we get the PkiUser
	   object */
	status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE_STORE, 
							  CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		puts( "No certificate store available, aborting CMP/SCEP test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCAGetItem( cryptCertStore, &cryptPKIUser,
							 CRYPT_CERTTYPE_PKIUSER, CRYPT_KEYID_NAME,
							 userName );
	cryptKeysetClose( cryptCertStore );
	if( cryptStatusError( status ) )
		{
		/* Only report error info if it's not a basic presence check */
		if( userID != NULL )
			extErrorExit( cryptCertStore, "cryptCAGetItem()", status, __LINE__ );
		return( FALSE );
		}

	/* If it's a presence check only, we're done */
	if( userID == NULL )
		{
		cryptDestroyCert( cryptPKIUser );
		return( TRUE );
		}

	/* Then we extract the information from the PkiUser object */
	status = cryptGetAttributeString( cryptPKIUser,
									  CRYPT_CERTINFO_PKIUSER_ID,
									  userID, &length );
	if( cryptStatusOK( status ) )
		{
		userID[ length ] = '\0';
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									issuePW, &length );
		}
	if( cryptStatusOK( status ) )
		issuePW[ length ] = '\0';
	if( cryptStatusOK( status ) && revPW != NULL )
		{
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_REVPASSWORD,
									revPW, &length );
		if( cryptStatusOK( status ) )
			revPW[ length ] = '\0';
		}
	cryptDestroyCert( cryptPKIUser );
	if( cryptStatusError( status ) )
		{
		extErrorExit( cryptPKIUser, "cryptGetAttribute()", status,
					  __LINE__ );
		return( FALSE );
		}

	/* We've got what we need, tell the user what we're doing */
	printf( "Using user name %s, password %s.\n", userID, issuePW );
	return( TRUE );
	}

/* Set up objects and information needed by a server-side PKI session */

int pkiServerInit( CRYPT_CONTEXT *cryptPrivateKey, 
				   CRYPT_KEYSET *cryptCertStore, const C_STR keyFileName,
				   const C_STR keyLabel, const CERT_DATA *pkiUserData,
				   const CERT_DATA *pkiUserAltData, 
				   const CERT_DATA *pkiUserCAData, 
				   const CERT_DATA *pkiUserRAData, 
				   const char *protocolName )
	{
	const BOOLEAN isSCEP = !strcmp( protocolName, "SCEP" ) ? TRUE : FALSE;
	int status;

	/* Get the certificate store to use with the session.  Before we use the 
	   store we perform a cleanup action to remove any leftover requests from
	   previous runs */
	status = cryptKeysetOpen( cryptCertStore, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE_STORE, 
							  CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		printf( "SVR: No certificate store available, aborting %s server "
				"test.\n\n", protocolName );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		status = cryptKeysetOpen( cryptCertStore, CRYPT_UNUSED,
								  CRYPT_KEYSET_DATABASE_STORE, 
								  CERTSTORE_KEYSET_NAME,
								  CRYPT_KEYOPT_NONE );
		}
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptKeysetOpen() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCACertManagement( NULL, CRYPT_CERTACTION_CLEANUP, 
									*cryptCertStore, CRYPT_UNUSED, 
									CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: CA certificate store cleanup failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the EE and CA PKI users */
	puts( "Creating PKI users..." );
	if( !addPKIUser( *cryptCertStore, pkiUserData, isSCEP, !isSCEP ) )
		return( FALSE );
	if( pkiUserAltData != NULL && \
		!addPKIUser( *cryptCertStore, pkiUserAltData, isSCEP, FALSE ) )
		return( FALSE );
	if( pkiUserCAData != NULL && \
		!addPKIUser( *cryptCertStore, pkiUserCAData, isSCEP, FALSE ) )
		return( FALSE );
	if( pkiUserRAData != NULL && \
		!addPKIUser( *cryptCertStore, pkiUserRAData, isSCEP, FALSE ) )
		return( FALSE );

	/* Get the CA's private key */
	status = getPrivateKey( cryptPrivateKey, keyFileName,
							keyLabel, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: CA private key read failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*								SCEP Routines Test							*
*																			*
****************************************************************************/

/* Get an SCEP CA certificate */

static int getScepCACert( const C_STR caCertUrl,
						  CRYPT_CERTIFICATE *cryptCACert )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_HTTP,
							  caCertUrl, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPublicKey( cryptKeyset, cryptCACert, CRYPT_KEYID_NAME,
									TEXT( "[None]" ) );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptKeyset, "cryptGetPublicKey()",
							  status, __LINE__ ) );
		}

	return( TRUE );
	}

/* Perform a SCEP test */

static int connectSCEP( const BOOLEAN localSession,
						const SCEP_TEST_TYPE testType,
						const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CERTIFICATE cryptRequest DUMMY_INIT, cryptResponse;
	CRYPT_CERTIFICATE cryptCACert DUMMY_INIT;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext, cryptRenewalKey DUMMY_INIT;
#if ( SCEP_NO == 1 )
	C_CHR userID[ 64 ], password[ 64 ];
	const C_STR userPtr;
	const C_STR passwordPtr;
	BYTE caKeyFingerprint[ 20 ];
	int caKeyFingerprintSize = 0;
#else
	const C_STR userPtr = scepInfo[ SCEP_NO ].user;
	const C_STR passwordPtr = scepInfo[ SCEP_NO ].password;
#endif /* cryptlib SCEP server */
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	const BOOLEAN isErrorTest = ( testType >= SCEP_TEST_CORRUPT_TRANSACTIONID && \
								  testType < SCEP_TEST_LAST ) ? \
								  TRUE : FALSE;
	BOOLEAN addCACert = ( testType == SCEP_TEST_CACERT ) ? FALSE : TRUE;
#ifdef SCEP_BROKEN_CA_CERT
	int complianceValue;
#endif /* SCEP servers with broken CA certificates */
	int retryCount = 0, status;

	printf( "Testing %s %sSCEP session", scepInfo[ SCEP_NO ].name,
			( testType == SCEP_TEST_RENEW || \
			  testType == SCEP_TEST_RENEW_SIGONLY ) ? \
			  "renewed-certificate " : "" );
	if( addCACert )
		{
		printf( " with CA certificate read" );
		if( cryptAlgo != CRYPT_ALGO_RSA )
			printf( "\n  and signature-only algorithm" );
		}
	printf( "...\n" );

	/* Wait for the server to finish initialising */
	if( localSession && waitMutex() == CRYPT_ERROR_TIMEOUT )
		{
		printf( "Timed out waiting for server to initialise, line %d.\n", 
				__LINE__ );
		return( FALSE );
		}

#if ( SCEP_NO == 1 )
	/* If we're doing a loopback test, make sure that the required user info
	   is present.  If it isn't, the CA auditing will detect a request from
	   a nonexistant user and refuse to issue a certificate */
	if( !pkiGetUserInfo( NULL, NULL, NULL, TEXT( "Test SCEP PKI user" ) ) )
		{
		puts( "CA certificate store doesn't contain the PKI user "
			  "information needed to\nauthenticate certificate issue "
			  "operations, can't perform SCEP test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
#endif /* cryptlib SCEP server */

#ifdef SCEP_BROKEN_CA_CERT
	/* Some SCEP server's CA certificates are broken so we have to turn 
	   down the compliance level to allow them to be used */
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   &complianceValue );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
#endif /* SCEP servers with broken CA certificates */

	/* Get the issuing CA's certificate if required */
	if( addCACert )
		{
		if( scepInfo[ SCEP_NO ].caCertUrl != NULL )
			{
			if( !strcmp( scepInfo[ SCEP_NO ].caCertUrl, "default" ) )
				addCACert = FALSE;
			else
				{
				if( !getScepCACert( scepInfo[ SCEP_NO ].caCertUrl, 
									&cryptCACert ) )
					return( FALSE );
				}
			}
		else
			{
			status = importCertFromTemplate( &cryptCACert, 
											 SCEP_CA_FILE_TEMPLATE, SCEP_NO );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't get SCEP CA certificate, status = %d, "
						"line %d.\n", status, __LINE__ );
				return( FALSE );
				}
			}
		}

	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations */
#if ( SCEP_NO == 1 )
	status = pkiGetUserInfo( userID, password, NULL,
							 TEXT( "Test SCEP PKI user" ) );
	if( !status || status == CRYPT_ERROR_NOTAVAIL )
		{
		if( addCACert )
			cryptDestroyCert( cryptCACert );

		/* If certificate store operations aren't available, exit but 
		   continue with other tests, otherwise abort the tests */
		return( ( status == CRYPT_ERROR_NOTAVAIL ) ? TRUE : FALSE );
		}
	userPtr = userID;
	passwordPtr = password;
#endif /* cryptlib SCEP server */

	/* Get the certificate used to authenticate the renewal if required */
	if( testType == SCEP_TEST_RENEW || \
		testType == SCEP_TEST_RENEW_SIGONLY )
		{
		filenameFromTemplate( filenameBuffer, SCEP_PRIVKEY_FILE_TEMPLATE, 
							  ( testType == SCEP_TEST_RENEW ) ? 1 : 2 );
		status = getPrivateKey( &cryptRenewalKey, filenameBuffer, 
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't get SCEP-issued certificate for renewal, "
					"status = %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}

#if ( SCEP_NO == 1 )
	/* Get the CA certificate fingerprint */
	if( !addCACert )
		{
		char filenameBuffer[ FILENAME_BUFFER_SIZE ];

		filenameFromTemplate( filenameBuffer, SCEPCA_PRIVKEY_FILE_TEMPLATE, 
							  ( cryptAlgo == CRYPT_ALGO_RSA ) ? 1 : 2 );
		status = getPublicKey( &cryptCACert, filenameBuffer,
							   USER_PRIVKEY_LABEL );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't get SCEP CA certificate, status = %d, "
					"line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	status = cryptGetAttributeString( cryptCACert, 
									  CRYPT_CERTINFO_FINGERPRINT_SHA1,
									  caKeyFingerprint, 
									  &caKeyFingerprintSize );
	if( cryptStatusError( status ) )
		{
		if( !addCACert )
			cryptDestroyCert( cryptCACert );
		printf( "Couldn't get SCEP CA certificate fingerprint, status = %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCACert )
		cryptDestroyCert( cryptCACert );
#endif /* cryptlib SCEP server */

	/* Create the SCEP session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP );
	if( status == CRYPT_ERROR_PARAM3 )	/* SCEP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that the SCEP client's checking for invalid transactionIDs
	   works (this is an obscure problem caused by the SCEP protocol, see 
	   the SCEP client code comments for more information) */
	if( testType == SCEP_TEST_NORMAL )
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME,
										  TEXT( "abc@def" ), 
										  paramStrlen( TEXT( "abc@def" ) ) );
		if( cryptStatusOK( status ) )
			{
			printf( "Addition of invalid SCEP user information wasn't detected, "
					"line %d.\n", __LINE__ );
			return( FALSE );
			}
		}

	/* Set up the user and server information */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_CMP_REQUESTTYPE,
								( testType == SCEP_TEST_RENEW || \
								  testType == SCEP_TEST_RENEW_SIGONLY ) ? \
								  CRYPT_REQUESTTYPE_CERTIFICATE : \
								  CRYPT_REQUESTTYPE_INITIALISATION );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME,
										  userPtr, paramStrlen( userPtr ) );
		}
	if( cryptStatusOK( status ) && testType != SCEP_TEST_RENEW )
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_PASSWORD,
										  passwordPtr, 
										  paramStrlen( passwordPtr ) );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_SERVER_NAME,
									scepInfo[ SCEP_NO ].url,
									paramStrlen( scepInfo[ SCEP_NO ].url ) );
		}
	if( addCACert )
		{
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_CACERTIFICATE,
										cryptCACert );
			}
		cryptDestroyCert( cryptCACert );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Addition of SCEP user/server information failed with error "
				"code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the PKCS #10 request.  For standard SCEP this is unsigned 
	   since we need to add the SCEP challengePassword to it before we send 
	   it to the server, however for a SCEP renewal it's signed since 
	   there's no challengePassword and the request is authenticated by being
	   signed with the previously-issued SCEP certificate */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 USER_PRIVKEY_LABEL,
							 paramStrlen( USER_PRIVKEY_LABEL ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusOK( status ) )
		{
		status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED,
								  CRYPT_CERTTYPE_CERTREQUEST );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptRequest,
									CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, 
									cryptContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptRequest, scepRequestData, __LINE__ ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusOK( status ) && ( testType == SCEP_TEST_CUSTOMEXT ) )
		{
		const char *extensionData = "\x0C\x04Test";

		status = cryptAddCertExtension( cryptRequest, "1.2.3.4.5", FALSE, 
										extensionData, 6 );
		}
	if( cryptStatusOK( status ) && \
		( testType == SCEP_TEST_RENEW || \
		  testType == SCEP_TEST_RENEW_SIGONLY ) )
		status = cryptSignCert( cryptRequest, cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Creation of PKCS #10 request failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Set up the private key and request */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_PRIVATEKEY,
								( testType == SCEP_TEST_RENEW || \
								  testType == SCEP_TEST_RENEW_SIGONLY ) ? \
								  cryptRenewalKey : cryptContext );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_REQUEST,
									cryptRequest );
		}
	cryptDestroyCert( cryptRequest );
	if( testType == SCEP_TEST_RENEW || testType == SCEP_TEST_RENEW_SIGONLY )
		cryptDestroyContext( cryptRenewalKey );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* If we've explicitly fetched the issuing CA's certificate via an HTTP
	   request then the server session has already been run, so we need to
	   wait for it to recycle before we continue */
	if( localSession && addCACert && \
		scepInfo[ SCEP_NO ].caCertUrl != NULL && \
		waitMutex() == CRYPT_ERROR_TIMEOUT )
		{
		printf( "Timed out waiting for server to initialise, line %d.\n", 
				__LINE__ );
		return( FALSE );
		}

#if defined( CONFIG_FAULTS ) && !defined( NDEBUG )
	/* If we're testing fault handling, inject the appropriate fault type */
	if( isErrorTest )
		{
		cryptSetFaultType( ( testType == SCEP_TEST_CORRUPT_TRANSACTIONID ) ? \
							 FAULT_CORRUPT_ID : \
						   ( testType == SCEP_TEST_CORRUPT_TRANSIDVALUE ) ? \
							 FAULT_SESSION_SCEP_CORRUPT_TRANSIDVALUE : \
						   ( testType == SCEP_TEST_CORRUPT_MESSAGETYPE ) ? \
							 FAULT_SESSION_SCEP_CORRUPT_MESSAGETYPE : \
						   ( testType == SCEP_TEST_CORRUPT_NONCE ) ? \
							 FAULT_SESSION_CORRUPT_NONCE : \
						   ( testType == SCEP_TEST_CORRUPT_AUTHENTICATOR ) ? \
							 FAULT_CORRUPT_AUTHENTICATOR : \
						   	 FAULT_NONE );
		}
#endif /* CONFIG_FAULTS && Debug */

	/* Activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	while( status == CRYPT_ENVELOPE_RESOURCE && retryCount < 5 )
		{
		/* The server has indicated that the certificate-issue operation is 
		   pending, try again in case it works this time */
		printExtError( cryptSession, "Attempt to activate SCEP client "
					   "session", status, __LINE__ );
		puts( "  (Retrying operation after 10 seconds in case certificate "
			  "issue is now approved...)" );
		delayThread( 10 );
		printf( "Retrying, attempt #%d.\n", ++retryCount );
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, 
									TRUE );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "Attempt to activate SCEP client "
					   "session", status, __LINE__ );
		if( isErrorTest )
			{
			/* These tests are supposed to fail, so if this happens then the 
			   overall test has succeeded */
			cryptDestroySession( cryptSession );
			puts( "  (This test checks error handling, so the failure "
				  "response is correct).\n" );
			return( TRUE );
			}
		if( isServerDown( cryptSession, status ) )
			{
			fputs( "  (Server could be down, faking it and "
				   "continuing...)\n", outputStream );
			cryptDestroySession( cryptSession );
			return( CRYPT_ERROR_FAILED );
			}
		if( status == CRYPT_ENVELOPE_RESOURCE )
			{
			puts( "Status is still marked as pending, the server may "
				  "require manual approval\n  of the certificate-issue "
				  "process.\n" );
			}
		cryptDestroySession( cryptSession );
		return( FALSE );
		}
	if( isErrorTest )
		{
		cryptDestroySession( cryptSession );
		puts( "  (This test should have led to a failure but "
			  "didn't, test has failed).\n" );
		return( FALSE );
		}

#ifdef SCEP_BROKEN_CA_CERT
	/* Restore normal certificate checking */
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   complianceValue );
#endif /* SCEP servers with broken CA certificates */

	/* Print the session security information */
	printFingerprint( cryptSession, FALSE );

	/* Obtain the response information, the newly-issued certificate and the 
	   CA certificate if it wasn't added explicitly but fetched as part of
	   the SCEP protocol run */
	status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
								&cryptResponse );
	if( cryptStatusOK( status ) && \
		( testType == SCEP_TEST_NORMAL || \
		  testType == SCEP_TEST_SIGONLY ) )
		{
		CRYPT_CERTIFICATE cryptResponseCopy;

		/* Try and read back a second copy of the same object.  This tests 
		   an internal processing condition in which the object being read 
		   back needs to be made external the first time but not the 
		   second */
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
									&cryptResponseCopy );
		if( cryptStatusOK( status ) )
			cryptDestroyCert( cryptResponseCopy );
		}
	if( cryptStatusOK( status ) && !addCACert )
		{
		status = cryptGetAttribute( cryptSession, 
									CRYPT_SESSINFO_CACERTIFICATE,
									&cryptCACert );
		}
	cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#if ( SCEP_NO != 1 )
	puts( "Returned certificate details are:" );
	printCertInfo( cryptResponse );
	if( !addCACert )
		{
		puts( "Returned CA certificate details are:" );
		printCertInfo( cryptCACert );
		}
#endif /* Keep the cryptlib results on one screen */

	/* Make sure that we got back what we asked for */
	if( testType == SCEP_TEST_NORMAL )
		{
		C_CHR attributeData[ 64 ];
		int attributeLength, i;

		for( i = 0; 
			 scepRequestData[ i ].type != CRYPT_ATTRIBUTE_NONE; 
			 i++ )
			{
			if( scepRequestData[ i ].componentType != IS_STRING )
				continue;
			status = cryptGetAttributeString( cryptResponse, 
											  scepRequestData[ i ].type, 
											  attributeData, 
											  &attributeLength );
			if( cryptStatusOK( status ) && \
				memcmp( scepRequestData[ i ].stringValue, attributeData,
						attributeLength ) )
				status = CRYPT_ERROR_BADDATA;
			if( cryptStatusError( status ) )
				{
				printf( "Attribute #%d in request wasn't returned in "
						"certificate, line %d.\n", i, __LINE__ );
				return( FALSE );
				}
			}
		}

	/* Save the key and certificate for later, in particular for the 
	   initialisation test where the certificate is reused to sign the
	   message in the renewal test */
	filenameFromTemplate( filenameBuffer, SCEP_PRIVKEY_FILE_TEMPLATE, 
						  ( testType == SCEP_TEST_NORMAL ) ? 1 : \
						  ( testType == SCEP_TEST_SIGONLY ) ? 2 : \
						  ( testType == SCEP_TEST_RENEW ) ? 3 : \
						  ( testType == SCEP_TEST_RENEW_SIGONLY ) ? 4 : 5 );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_FILE, filenameBuffer,
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPublicKey( cryptKeyset, cryptResponse );
		cryptKeysetClose( cryptKeyset );
		}
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't save SCEP certificate to file, error code %d, "
				"line %d.\n", status, __LINE__ );
		return(	FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptResponse );
	if( !addCACert )
		cryptDestroyCert( cryptCACert );
	puts( "SCEP client session succeeded.\n" );
	return( TRUE );
	}

int testSessionSCEP( void )
	{
	return( connectSCEP( FALSE, SCEP_TEST_NORMAL, CRYPT_ALGO_RSA ) );
	}

int testSessionSCEPCACert( void )
	{
	return( connectSCEP( FALSE, SCEP_TEST_CACERT, CRYPT_ALGO_RSA ) );
	}

enum { MUTEX_NONE, MUTEX_ACQUIRE, MUTEX_ACQUIRE_REACQUIRE };

static int scepServer( const int mutexBehaviour,
					   const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT cryptCAKey;
	CRYPT_KEYSET cryptCertStore;
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int status;

	/* Acquire the init mutex */
	if( mutexBehaviour == MUTEX_ACQUIRE || \
		mutexBehaviour == MUTEX_ACQUIRE_REACQUIRE )
		acquireMutex();

	printf( "SVR: Testing SCEP server session%s...\n",
			( mutexBehaviour == MUTEX_ACQUIRE_REACQUIRE ) ? \
				" (GetCACert portion)" : \
			( mutexBehaviour == MUTEX_NONE ) ? \
				" following GetCACert" : "" );

	/* Perform a test create of a SCEP server session to verify that we can
	   do this test */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP_SERVER );
	if( status == CRYPT_ERROR_PARAM3 )	/* SCEP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptDestroySession( cryptSession );

	/* Set up the server-side objects */
	filenameFromTemplate( filenameBuffer, SCEPCA_PRIVKEY_FILE_TEMPLATE, 
						  ( cryptAlgo == CRYPT_ALGO_RSA ) ? 1 : 2 );
	if( !pkiServerInit( &cryptCAKey, &cryptCertStore, filenameBuffer,
						USER_PRIVKEY_LABEL, scepPkiUserData, NULL, NULL, 
						NULL, "SCEP" ) )
		return( FALSE );

	/* Create the SCEP session and add the CA key and certificate store */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP_SERVER );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_PRIVATEKEY, cryptCAKey );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_KEYSET, cryptCertStore );
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptSession, "SVR: cryptSetAttribute()",
							  status, __LINE__ ) );
		}

	/* Tell the client that we're ready to go */
	releaseMutex();

	/* Activate the session */
	status = activatePersistentServerSession( cryptSession, FALSE );
	if( cryptStatusError( status ) )
		{
		cryptKeysetClose( cryptCertStore );
		cryptDestroyContext( cryptCAKey );
		return( extErrorExit( cryptSession, "SVR: Attempt to activate SCEP "
							  "server session", status, __LINE__ ) );
		}

	/* If we're running a second server session, reacquire the mutex for
	   the client to wait on */
	if( mutexBehaviour == MUTEX_ACQUIRE_REACQUIRE )
		acquireMutex();

	/* Clean up */
	cryptDestroySession( cryptSession );
	cryptKeysetClose( cryptCertStore );
	cryptDestroyContext( cryptCAKey );

	if( mutexBehaviour == MUTEX_ACQUIRE_REACQUIRE )
		puts( "SVR: SCEP session (GetCACert portion) succeeded." );
	else
		puts( "SVR: SCEP session succeeded.\n" );
	return( TRUE );
	}

int testSessionSCEPServer( void )
	{
	int status;

	createMutex();
	status = scepServer( MUTEX_ACQUIRE, CRYPT_ALGO_RSA );
	destroyMutex();

	return( status );
	}

/* Perform a client/server loopback test */

#ifdef TEST_SESSION_LOOPBACK

#ifdef WINDOWS_THREADS
  static unsigned __stdcall scepServerThread( void *arg )
#else
  static void *scepServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

#if 0
	/* If we do an explicit GetCACert via an HTTP keyset before the main 
	   SCEP session then we have to run the server twice, however this leads 
	   to the problems covered in the comment for the first entry in 
	   scepInfo[] above */
	scepServer( MUTEX_ACQUIRE_REACQUIRE, argValue );
	scepServer( MUTEX_NONE, argValue );
#else
	scepServer( MUTEX_ACQUIRE, argValue );
#endif /* 0 */
	THREAD_EXIT();
	}

static int scepClientServer( const SCEP_TEST_TYPE testType,
							 const CRYPT_ALGO_TYPE cryptAlgo )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = cryptAlgo, status;

	/* This is a test that requires a database keyset, make sure that one 
	   is available */
	if( !checkDatabaseKeysetAvailable() )
		{
		fputs( "Skipping test due to unavailability of database "
			   "keysets.\n\n", outputStream );
		return( TRUE );
		}

#if ( SCEP_NO != 1 )
	/* Because the code has to handle so many CA-specific peculiarities, we
	   can only perform this test when the CA being used is the cryptlib
	   CA */
	puts( "Error: The local SCEP session test only works with SCEP_NO == 1." );
	return( FALSE );
#endif /* cryptlib CA */

	/* Start the server and wait for it to initialise */
	createMutex();
#ifdef __WINDOWS__
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, scepServerThread,
										 &arg, 0, &threadID );
#else
	pthread_create( &hThread, NULL, scepServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 1000 );

	/* Connect to the local server */
	status = connectSCEP( TRUE, testType, cryptAlgo );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}

int testSessionSCEPClientServer( void )
	{
	return( scepClientServer( SCEP_TEST_NORMAL, CRYPT_ALGO_RSA ) );
	}

int testSessionSCEPSigonlyClientServer( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "ECC algorithm support appears to be disabled, skipping "
			   "SCEP processing of\nECDSA certificates.\n\n", outputStream );
		return( TRUE );
		}

	return( scepClientServer( SCEP_TEST_SIGONLY, CRYPT_ALGO_ECDSA ) );
	}

int testSessionSCEPCustomExtClientServer( void )
	{
	int oldValue, status;

	/* Since we're creating a certificate with custom attributes, we have to 
	   enable the setting of unrecognised attribute types around the cert-
	   issue operation */
	status = cryptGetAttribute( CRYPT_UNUSED, 
								CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, 
								&oldValue );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( CRYPT_UNUSED, 
									CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, 
									TRUE );
		}
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't enable use of custom attributes for SCEP test." );
		return( FALSE );
		}
	status = scepClientServer( SCEP_TEST_CUSTOMEXT, CRYPT_ALGO_RSA );
	cryptSetAttribute( CRYPT_UNUSED, 
					   CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, oldValue );

	return( status );
	}

int testSessionSCEPSHA2ClientServer( void )
	{
	int value, status;

	/* Switch the hash algorithm to SHA-2 */
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
								&value );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH,
					   CRYPT_ALGO_SHA2 );
	status = scepClientServer( SCEP_TEST_NORMAL, CRYPT_ALGO_RSA );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, value );

	return( status );
	}

int testSessionSCEPCACertClientServer( void )
	{
	return( scepClientServer( SCEP_TEST_CACERT, CRYPT_ALGO_RSA ) );
	}

int testSessionSCEPRenewClientServer( void )
	{
	return( scepClientServer( SCEP_TEST_RENEW, CRYPT_ALGO_RSA ) );
	}

int testSessionSCEPRenewSigonlyClientServer( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "ECC algorithm support appears to be disabled, skipping "
			   "SCEP processing of\nECDSA certificates.\n\n", outputStream );
		return( TRUE );
		}

	return( scepClientServer( SCEP_TEST_RENEW_SIGONLY, CRYPT_ALGO_ECDSA ) );
	}

int testSessionSCEPClientServerDebugCheck( void )
	{
#if defined( CONFIG_FAULTS ) && !defined( NDEBUG )
	cryptSetFaultType( FAULT_NONE );
	if( !scepClientServer( SCEP_TEST_CORRUPT_TRANSACTIONID, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of transaction ID */
	if( !scepClientServer( SCEP_TEST_CORRUPT_TRANSIDVALUE, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of trans.ID data */
	if( !scepClientServer( SCEP_TEST_CORRUPT_MESSAGETYPE, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of message type */
	if( !scepClientServer( SCEP_TEST_CORRUPT_NONCE, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of sender/recipNonce */
	if( !scepClientServer( SCEP_TEST_CORRUPT_AUTHENTICATOR, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of password */
	cryptSetFaultType( FAULT_NONE );
#endif /* CONFIG_FAULTS && Debug */
	return( TRUE );
	}
#endif /* TEST_SESSION_LOOPBACK */

#endif /* TEST_SESSION || TEST_SESSION_LOOPBACK */
=======
/****************************************************************************
*																			*
*					cryptlib SCEP Session Test Routines						*
*					Copyright Peter Gutmann 1998-2021						*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */
#ifndef NDEBUG
  #include <limits.h>			/* Needed for analyse.h */
  #include "misc/analyse.h"		/* Needed for fault.h */
  #include "misc/fault.h"
#endif /* !NDEBUG */

/* Define the following to test the use of custom attributes via the pkiUser
   object */

/* #define TEST_CUSTOM_ATTRIBUTE */

/* We can run the SCEP self-test with a large variety of options, rather 
   than using dozens of boolean option flags to control them all we define 
   various test classes that exercise each option type */

typedef enum {
	SCEP_TEST_NONE,				/* No SCEP test type */
	SCEP_TEST_NORMAL,			/* Standard SCEP test */
	SCEP_TEST_SIGONLY,			/* Get certificate for sig-only algorithm */
	SCEP_TEST_CACERT,			/* Get CA cert instead of std.one */
	SCEP_TEST_CUSTOMEXT,		/* Add custom extension to request */
	SCEP_TEST_RENEW,			/* Renew existing certificate */
	SCEP_TEST_RENEW_SIGONLY,	/* Renew sig-only existing certificate */
	SCEP_TEST_CORRUPT_TRANSACTIONID, /* Detect corruption of transaction ID */
	SCEP_TEST_CORRUPT_TRANSIDVALUE, /* Detect corruption of trans.ID data */
	SCEP_TEST_CORRUPT_MESSAGETYPE, /* Detect corruption of message type */
	SCEP_TEST_CORRUPT_NONCE,	/* Detect corruption of sender/recipNonce */
	SCEP_TEST_CORRUPT_AUTHENTICATOR, /* Detect corruption of password */
	SCEP_TEST_LAST				/* Last possible CMP test type */
	} SCEP_TEST_TYPE;

#if defined( TEST_SESSION ) || defined( TEST_SESSION_LOOPBACK )

/****************************************************************************
*																			*
*								SCEP Test Data								*
*																			*
****************************************************************************/

/* There were various SCEP test servers available at some point, although 
   most of them are either semi- or entirely nonfunctional or vanished years
   ago.  The following mappings can be used to test different ones.  
   Implementation peculiarities below, an additional list of issues from the
   EJBCA folks is at
   https://download.primekey.com/docs/EJBCA-Enterprise/6_8_0/adminguide.html#Tested%20devices

	#1 - cryptlib: None.

	#2 - cryptlib ECC: None.

	#3 - SSH (www.ssh.com/support/testzone/pki.html): Invalid CA 
	     certificates, and disappeared some years ago.  Continued as Insta-
		 Certifier, see #7 below.

	#4 - OpenSCEP (openscep.othello.ch): Seems to be permanently unavailable.

	#5 - Entrust (freecerts.entrust.com/vpncerts/cep.htm): Only seems to be
		 set up to handle Cisco gear, and no longer available.

	#6 - EJBCA (see EJBCA note below): Server has vanished.
	
	#7 - Insta-Certifier: Information originally at 
		 http://www.certificate.fi/resources/demos/demo.htm, then at
		 http://security.insta.fi/solutions-en/product/productid=24167486.
		 This apparently implements SCEP as per the -09 draft from 2003 and
		 based on the appearance of the web page hasn't changed since it was
		 the SSH server in #2, so it doesn't really interoperate with any
		 version of SCEP from about the last ten years (no GetCACaps, no
		 POST, etc).  If necessary this behaviour can be forced by adding:

			scepInfo->flags |= SCEP_PFLAG_GOTCACAPS;
			sendPostAsGet = TRUE;

		 to the start of clientTransact() in session/scep_cli.c but this 
		 isn't recommended since it breaks correct functioning with any 
		 standard SCEP server.  Seems to have gone away as of 2018.

	#8 - Microsoft NDES (see NDES note below): Reverted to a fresh install 
		 with no content several years ago, but used to return an invalid CA 
		 certificate.  The code sets the compliance level to 
		 CRYPT_COMPLIANCELEVEL_OBLIVIOUS to handle this.  GetCACaps 
		 (via http://qa4-mdm3.qa4.imdmdemo.com/certsrv/mscep/?operation=GetCACaps) 
		 is implemented but broken, returns a zero-length response.  No 
		 longer available.
	
	#9 - Windows Server 2003 (see NDES note below): Closes the connection on 
		 seeing GetCACaps.  No longer available.

	#10 - Windows Server 2008 (see NDES note below): Returns an invalid CA 
		  certificate (keyUsage is set to keyEncipherment but not 
		  digitalSignature).  The code sets the compliance level to 
		  CRYPT_COMPLIANCELEVEL_OBLIVIOUS to handle this.  No longer 
		  available.

	#11 - Windows Server 2008 (upgraded form of #8, see NDES note below): 
		  Sends two certificates, one with keyUsage = digitalSignature, one 
		  with keyUsage = keyEncipherment, so CA certificate fetch must be 
		  implicit so that the SCEP code can sort out which certificate to 
		  use at what point.

		  When used with a implicit GetCACert (caCertUrl = "default") it 
		  closes the connection after the request has completed ('No data was 
		  read because the remote system closed the connection (recv() == 
		  0)'), when an explicit fetch is performed it doesn't get a chance 
		  to do this but then the certificate(s) that are returned can't be 
		  used.  No longer available.

	#12 - Private vendor: Uses an auth key that changes every 10-15 minutes,
		  obtained via 
		  https://jen.nuk9.com/pkiclient.exe?operation=GetChallengePassword&subject=CommonNameToBeUsed  
		  in this case 
		  https://jen.nuk9.com/pkiclient.exe?operation=GetChallengePassword&subject=Test%20SCEP%20PKI%20user
		  No longer available.

	#13 - Redwax test server: Built around Apache running mod_scep, sends an 
		  invalid CA certificate chain in response to GetCACert:

		  28   15:       SEQUENCE {
		  30    9:         OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
		  41    2:         [0] {
		  43    0:           OCTET STRING
		         :             Error: Object has zero length.
		         :           }
		         :         }
	
		  https://interop.redwax.eu/rs/scep/
	
	#14: Alternative Redwax test server that fixes the above issue.
	
	#15 - openXpki test server.  Fails with an internal server error if AES 
	      is used.  No longer available.

	#16: EJBCA test server (see EJBCA note below).

   NDES passwords are only valid for 60 minutes, are single-use, and you 
   can only set five of them per hour,
   https://social.technet.microsoft.com/wiki/contents/articles/9063.active-directory-certificate-services-ad-cs-network-device-enrollment-service-ndes.aspx#Password_and_Password_Cache
   so the password needs to be updated on each run and carefully managed on
   the server.  An alternative is UseSinglePassword mode which uses a fixed
   password for all certificates and requires complex server configuration 
   including registry hacks.

   EJBCA handles users/entities as single-use, so once a 
   certificate has been issued any further requests are rejected with an HTTP
   "Bad Request" (rather than an SCEP-level error), see
   https://download.primekey.com/docs/EJBCA-Enterprise/6_8_0/adminguide.html#Level%20of%20SCEP%20support
   To deal with this we allow EJBCA user names to be changed on each run */

#define EJBCA_USERNAME		"test1"

#define SCEP_NO		1

typedef struct {
	const char *name;
	const C_CHR *url, *user, *password;
	const C_CHR *caCertUrl;
		/* A URL for the caCertUrl fetches the CA certificate from this location 
		   before starting the SCEP session, NULL reads it from a file, and the 
		   string "default" use the built-in GetCACert capability to read it 
		   automatically */
	} SCEP_INFO;

static const SCEP_INFO scepInfo[] = {
	{ NULL },	/* Dummy so index == SCEP_NO */
	{ /*  1 */ "cryptlib", TEXT( "http://" LOCAL_HOST_NAME "/pkiclient.exe" ), NULL, NULL, 
/*				TEXT( "http://" LOCAL_HOST_NAME "/pkiclient.exe?operation=GetCACert&message=*" ) }, */
				TEXT( "default" ) },
				/* We have to implicitly get the certificate via the 
				   client's built-in GetCACert because if we do an explicit 
				   fetch from the caCertUrl via an HTTP keyset then the 
				   server won't have time to recycle before the next request 
				   comes in.  See also the comment in scepServerThread() on 
				   mutex management for the explicit HTTP fetch */
	{ /*  2 */ "cryptlib ECC", TEXT( "http://" LOCAL_HOST_NAME "/pkiclient.exe" ), NULL, NULL, 
				TEXT( "default" ) },
	{ /*  3 */ "SSH", TEXT( "http://pki.ssh.com:8080/scep/pkiclient.exe" ), 
				TEXT( "ssh" ), TEXT( "ssh" ),
				TEXT( "http://pki.ssh.com:8080/scep/pkiclient.exe?operation=GetCACert&message=test-ca1.ssh.com" ) },
	{ /*  4 */ "OpenSCEP", TEXT( "http://openscep.othello.ch/pkiclient.exe" ), 
				TEXT( "????" ), TEXT( "????" ), 
				NULL },
	{ /*  5 */ "Entrust", TEXT( "http://vpncerts.entrust.com/pkiclient.exe" ), 
				TEXT( "????" ), TEXT( "????" ), 
				NULL },
	{ /*  6 */ "EJBCA", TEXT( "http://q-rl-xp:8080/ejbca/publicweb/apply/scep/pkiclient.exe" ),
				TEXT( "test2" ), TEXT( "test2" ),
				TEXT( "http://q-rl-xp:8080/ejbca/publicweb/webdist/certdist?cmd=nscacert&issuer=O=Test&+level=1" ) },
	{ /*  7 */ "Insta-Certifier", TEXT( "http://pki.certificate.fi:8082/scep/" ), 
				TEXT( "user" ), TEXT( "scep" ), 
				TEXT( "http://pki.certificate.fi:8082/scep/?operation=GetCACert&message=Insta%20Demo%20CA" ) },
	{ /*  8 */ "Microsoft NDES", TEXT( "http://qa4-mdm3.qa4.imdmdemo.com" ), 
				TEXT( "cryptlibtest" ), TEXT( "password!1" ), 
				TEXT( "http://qa4-mdm3.qa4.imdmdemo.com/certsrv/mscep/?operation=GetCACert&message=qa" ) },
	{ /*  9 */ "Win Server 2003", TEXT( "http://202.93.162.4/certsrv/mscep/mscep.dll" ), 
				TEXT( "test" ), TEXT( "BF51DFAA61874412" ), "default" },
	{ /* 10 */ "Win Server 2008, explicit GetCACert", TEXT( "http://142.176.86.157" ), 
				TEXT( "cryptlibtest" ), TEXT( "password!1" ), 
				TEXT( "http://142.176.86.157/certsrv/mscep/?operation=GetCACert&message=qa" ) },
	{ /* 11 */ "Win Server 2008, implicit GetCACert", TEXT( "http://202.93.162.4/certsrv/mscep/mscep.dll" ), 
				TEXT( "test" ), TEXT( "00654F176111B253DD996EEA67BBF16D" ), 
				TEXT( "default" ) },
	{ /* 12 */ "Private vendor", TEXT( "http://jen.nuk9.com/pkiclient.exe" ), 
				TEXT( "user" ), TEXT( "STNDRUhGNXBLamU5TE5QWERwb2RicFdnUGVNOHNaTWtLZlo4cEpEazdkWT0sMTgzODY=" ), 
				TEXT( "default" ) },
	{ /* 13 */ "Redwax interop server", TEXT( "http://interop.redwax.eu/test/simple/scep" ), 
				TEXT( "test" ), TEXT( "test" ), 
				TEXT( "default" ) },
	{ /* 14 */ "Redwax alternative server", TEXT( "http://scep.redwax.webweaving.org" ),
				TEXT( "test" ), TEXT( "test" ), 
				TEXT( "default" ) },
	{ /* 15 */ "openXpki test server", TEXT( "http://84.103.205.141/scep" ), 
				TEXT( "test" ), TEXT( "SecretChallenge" ), 
				TEXT( "default" ) },
	{ /* 16 */ "EJBCA test server", TEXT( "http://84.103.205.141:8080/ejbca/publicweb/apply/scep/pkiclient.exe" ),
				TEXT( EJBCA_USERNAME ), TEXT( "test" ),
				TEXT( "default" ) }
	};

/* SCEP requires that its CA certificates be usable for decryption of request
   messages and signing of response messages.  Some SCEP CAs don't have the
   appropriate keyUsage bits for this set, in which case we have to process 
   the certificates in oblivious mode in order to use them */

#if ( SCEP_NO == 6 ) || ( SCEP_NO == 7 ) || ( SCEP_NO == 8 ) || \
	( SCEP_NO == 9 )
  #define SCEP_BROKEN_CA_CERT
#endif /* Insta-Certifier, Windows Server */

/* Certificate request data for the certificate from the SCEP server.  Note 
   that we have to set the CN to the PKI user CN, for CMP ir's we just omit 
   the DN entirely and have the server provide it for us but since SCEP uses 
   PKCS #10 requests we need to provide a DN, and since we provide it it has 
   to match the PKI user DN */

static const CERT_DATA scepRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
#if ( SCEP_NO == 14 )	
	/* EJBCA requires that the request CN == SCEP username in its default config */
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( EJBCA_USERNAME ) },
#else
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test SCEP PKI user" ) },
#endif /* SCEP_NO == 14 */

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* PKI user data to authorise the issuing of the various certs */

static const CERT_DATA scepPkiUserData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test SCEP PKI user" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Add a PKI user to the certificate store */

static int addPKIUser( const CRYPT_KEYSET cryptCertStore,
					   const CERT_DATA *pkiUserData,
					   const BOOLEAN isSCEP, 
					   const BOOLEAN testErrorChecking )
	{
	CRYPT_CERTIFICATE cryptPKIUser;
	CRYPT_SESSION cryptSession;
	C_CHR userID[ CRYPT_MAX_TEXTSIZE + 1 ], issuePW[ CRYPT_MAX_TEXTSIZE + 1 ];
	int length, status;

	puts( "-- Adding new PKI user information --" );

	/* Create the PKI user object and add the user's identification
	   information */
	status = cryptCreateCert( &cryptPKIUser, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_PKIUSER );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptPKIUser, pkiUserData, __LINE__ ) )
		return( FALSE );
#ifdef TEST_CUSTOM_ATTRIBUTE
	if( isSCEP && pkiUserData == scepPkiUserData )
		{
		const char *extensionData = "\x0C\x04Test";

		status = cryptAddCertExtension( cryptPKIUser, "1.2.3.4.5", FALSE, 
										extensionData, 6 );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
#endif /* TEST_CUSTOM_ATTRIBUTE */

	/* Add the user info to the certificate store */
	status = cryptCAAddItem( cryptCertStore, cryptPKIUser );
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		C_CHR userIdentifier[ CRYPT_MAX_TEXTSIZE + 1 ];

		/* Get the name of the duplicate user.  Since this may be just a
		   template we fall back to higher-level DN components if there's
		   no CN present */
		status = cryptGetAttributeString( cryptPKIUser,
										  CRYPT_CERTINFO_COMMONNAME,
										  userIdentifier, &length );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			status = cryptGetAttributeString( cryptPKIUser,
											  CRYPT_CERTINFO_ORGANISATIONALUNITNAME,
											  userIdentifier, &length );
			}
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			status = cryptGetAttributeString( cryptPKIUser,
											  CRYPT_CERTINFO_ORGANISATIONNAME,
											  userIdentifier, &length );
			}
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( cryptPKIUser, "cryptGetAttribute()",
								  status, __LINE__ ) );
			}
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		userIdentifier[ length ] = TEXT( '\0' );

		/* The PKI user info was already present, for SCEP this isn't a
		   problem since we can just re-use the existing info, but for CMP
		   we can only authorise a single certificate issue per user so we 
		   have to delete the existing user info and try again */
		if( isSCEP )
			{
			/* The PKI user info is already present from a previous run, get
			   the existing info */
			puts( "PKI user information is already present from a previous "
				  "run, reusing existing\n  PKI user data..." );
			cryptDestroyCert( cryptPKIUser );
			status = cryptCAGetItem( cryptCertStore, &cryptPKIUser,
									 CRYPT_CERTTYPE_PKIUSER, CRYPT_KEYID_NAME,
									 userIdentifier );
			}
		else
			{
			puts( "PKI user information is already present from a previous "
				  "run, deleting existing\n  PKI user data..." );
			status = cryptCADeleteItem( cryptCertStore, CRYPT_CERTTYPE_PKIUSER,
										CRYPT_KEYID_NAME, userIdentifier );
			if( cryptStatusError( status ) )
				{
				return( extErrorExit( cryptCertStore, "cryptCADeleteItem()",
									  status, __LINE__ ) );
				}
			status = cryptCAAddItem( cryptCertStore, cryptPKIUser );
			}
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertStore, "cryptCAAdd/GetItem()", status,
							  __LINE__ ) );
		}

	/* Display the information for the new user */
	if( !printCertInfo( cryptPKIUser ) )
		return( FALSE );
	status = cryptGetAttributeString( cryptPKIUser,
									  CRYPT_CERTINFO_PKIUSER_ID,
									  userID, &length );
	if( cryptStatusOK( status ) )
		{
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		userID[ length ] = '\0';
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									issuePW, &length );
		}
	if( cryptStatusOK( status ) )
		{
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		issuePW[ length ] = '\0';
		}
	else
		{
		return( extErrorExit( cryptPKIUser, "cryptGetAttribute()", status,
							  __LINE__ ) );
		}
	puts( "-- New PKI user information ends --\n" );

	/* If we're not testing the error-checking capability of the user
	   identifiers, we're done */
	if( !testErrorChecking )
		{
		cryptDestroyCert( cryptPKIUser );
		return( TRUE );
		}

	/* Make sure that the error-checking in the user information works via a
	   dummy CMP client session.  We have to check both passwords to reduce 
	   false positives since it's just a simple integrity check meant to 
	   catch typing errors rather than a cryptographically strong check */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 CRYPT_SESSION_CMP );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( userID[ 2 ] >= TEXT( 'A' ) && userID[ 2 ] < TEXT( 'Z' ) )
		userID[ 2 ]++;
	else
		userID[ 2 ] = TEXT( 'A' );
	if( issuePW[ 8 ] >= TEXT( 'A' ) && issuePW[ 8 ] < TEXT( 'Z' ) )
		issuePW[ 8 ]++;
	else
		issuePW[ 8 ] = TEXT( 'A' );
	status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_USERNAME,
									  userID, paramStrlen( userID ) );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_PASSWORD,
										  issuePW, paramStrlen( issuePW ) );
		}
	if( cryptStatusOK( status ) )
		{
		puts( "Integrity check of user ID and password failed to catch "
			  "errors in the data.\n(This check isn't foolproof and is "
			  "intended only to catch typing errors when\nentering the "
			  "data.  Try running the test again to see if the problem "
			  "still\noccurs)." );
		return( FALSE );
		}
	cryptDestroySession( cryptSession );

	/* Clean up */
	cryptDestroyCert( cryptPKIUser );
	return( TRUE );
	}

/* Get information on a PKI user */

int pkiGetUserInfo( C_STR userID, C_STR issuePW, C_STR revPW, 
					const C_STR userName )
	{
	CRYPT_KEYSET cryptCertStore;
	CRYPT_CERTIFICATE cryptPKIUser;
	int length, status;

	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations.  First we get the PkiUser
	   object */
	status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE_STORE, 
							  CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		puts( "No certificate store available, aborting CMP/SCEP test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCAGetItem( cryptCertStore, &cryptPKIUser,
							 CRYPT_CERTTYPE_PKIUSER, CRYPT_KEYID_NAME,
							 userName );
	cryptKeysetClose( cryptCertStore );
	if( cryptStatusError( status ) )
		{
		/* Only report error info if it's not a basic presence check */
		if( userID != NULL )
			extErrorExit( cryptCertStore, "cryptCAGetItem()", status, __LINE__ );
		return( FALSE );
		}

	/* If it's a presence check only, we're done */
	if( userID == NULL )
		{
		cryptDestroyCert( cryptPKIUser );
		return( TRUE );
		}

	/* Then we extract the information from the PkiUser object */
	status = cryptGetAttributeString( cryptPKIUser,
									  CRYPT_CERTINFO_PKIUSER_ID,
									  userID, &length );
	if( cryptStatusOK( status ) )
		{
		userID[ length ] = '\0';
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									issuePW, &length );
		}
	if( cryptStatusOK( status ) )
		issuePW[ length ] = '\0';
	if( cryptStatusOK( status ) && revPW != NULL )
		{
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_REVPASSWORD,
									revPW, &length );
		if( cryptStatusOK( status ) )
			revPW[ length ] = '\0';
		}
	cryptDestroyCert( cryptPKIUser );
	if( cryptStatusError( status ) )
		{
		extErrorExit( cryptPKIUser, "cryptGetAttribute()", status,
					  __LINE__ );
		return( FALSE );
		}

	/* We've got what we need, tell the user what we're doing */
	printf( "Using user name %s, password %s.\n", userID, issuePW );
	return( TRUE );
	}

/* Set up objects and information needed by a server-side PKI session */

int pkiServerInit( CRYPT_CONTEXT *cryptPrivateKey, 
				   CRYPT_KEYSET *cryptCertStore, const C_STR keyFileName,
				   const C_STR keyLabel, const CERT_DATA *pkiUserData,
				   const CERT_DATA *pkiUserAltData, 
				   const CERT_DATA *pkiUserCAData, 
				   const CERT_DATA *pkiUserRAData, 
				   const char *protocolName )
	{
	const BOOLEAN isSCEP = !strcmp( protocolName, "SCEP" ) ? TRUE : FALSE;
	int status;

	/* Get the certificate store to use with the session.  Before we use the 
	   store we perform a cleanup action to remove any leftover requests from
	   previous runs */
	status = cryptKeysetOpen( cryptCertStore, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE_STORE, 
							  CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		printf( "SVR: No certificate store available, aborting %s server "
				"test.\n\n", protocolName );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		status = cryptKeysetOpen( cryptCertStore, CRYPT_UNUSED,
								  CRYPT_KEYSET_DATABASE_STORE, 
								  CERTSTORE_KEYSET_NAME,
								  CRYPT_KEYOPT_NONE );
		}
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptKeysetOpen() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCACertManagement( NULL, CRYPT_CERTACTION_CLEANUP, 
									*cryptCertStore, CRYPT_UNUSED, 
									CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: CA certificate store cleanup failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the EE and CA PKI users */
	puts( "Creating PKI users..." );
	if( !addPKIUser( *cryptCertStore, pkiUserData, isSCEP, !isSCEP ) )
		return( FALSE );
	if( pkiUserAltData != NULL && \
		!addPKIUser( *cryptCertStore, pkiUserAltData, isSCEP, FALSE ) )
		return( FALSE );
	if( pkiUserCAData != NULL && \
		!addPKIUser( *cryptCertStore, pkiUserCAData, isSCEP, FALSE ) )
		return( FALSE );
	if( pkiUserRAData != NULL && \
		!addPKIUser( *cryptCertStore, pkiUserRAData, isSCEP, FALSE ) )
		return( FALSE );

	/* Get the CA's private key */
	status = getPrivateKey( cryptPrivateKey, keyFileName,
							keyLabel, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: CA private key read failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*								SCEP Routines Test							*
*																			*
****************************************************************************/

/* Get an SCEP CA certificate */

static int getScepCACert( const C_STR caCertUrl,
						  CRYPT_CERTIFICATE *cryptCACert )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_HTTP,
							  caCertUrl, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPublicKey( cryptKeyset, cryptCACert, CRYPT_KEYID_NAME,
									TEXT( "[None]" ) );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptKeyset, "cryptGetPublicKey()",
							  status, __LINE__ ) );
		}

	return( TRUE );
	}

/* Perform a SCEP test */

static int connectSCEP( const BOOLEAN localSession,
						const SCEP_TEST_TYPE testType,
						const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CERTIFICATE cryptRequest DUMMY_INIT, cryptResponse;
	CRYPT_CERTIFICATE cryptCACert DUMMY_INIT;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext, cryptRenewalKey DUMMY_INIT;
#if ( SCEP_NO == 1 )
	C_CHR userID[ 64 ], password[ 64 ];
	const C_STR userPtr;
	const C_STR passwordPtr;
	BYTE caKeyFingerprint[ 20 ];
	int caKeyFingerprintSize = 0;
#else
	const C_STR userPtr = scepInfo[ SCEP_NO ].user;
	const C_STR passwordPtr = scepInfo[ SCEP_NO ].password;
#endif /* cryptlib SCEP server */
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	const BOOLEAN isErrorTest = ( testType >= SCEP_TEST_CORRUPT_TRANSACTIONID && \
								  testType < SCEP_TEST_LAST ) ? \
								  TRUE : FALSE;
	BOOLEAN addCACert = ( testType == SCEP_TEST_CACERT ) ? FALSE : TRUE;
#ifdef SCEP_BROKEN_CA_CERT
	int complianceValue;
#endif /* SCEP servers with broken CA certificates */
	int retryCount = 0, status;

	printf( "Testing %s %sSCEP session", scepInfo[ SCEP_NO ].name,
			( testType == SCEP_TEST_RENEW || \
			  testType == SCEP_TEST_RENEW_SIGONLY ) ? \
			  "renewed-certificate " : "" );
	if( addCACert )
		{
		printf( " with CA certificate read" );
		if( cryptAlgo != CRYPT_ALGO_RSA )
			printf( "\n  and signature-only algorithm" );
		}
	printf( "...\n" );

	/* Wait for the server to finish initialising */
	if( localSession && waitMutex() == CRYPT_ERROR_TIMEOUT )
		{
		printf( "Timed out waiting for server to initialise, line %d.\n", 
				__LINE__ );
		return( FALSE );
		}

#if ( SCEP_NO == 1 )
	/* If we're doing a loopback test, make sure that the required user info
	   is present.  If it isn't, the CA auditing will detect a request from
	   a nonexistant user and refuse to issue a certificate */
	if( !pkiGetUserInfo( NULL, NULL, NULL, TEXT( "Test SCEP PKI user" ) ) )
		{
		puts( "CA certificate store doesn't contain the PKI user "
			  "information needed to\nauthenticate certificate issue "
			  "operations, can't perform SCEP test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
#endif /* cryptlib SCEP server */

#ifdef SCEP_BROKEN_CA_CERT
	/* Some SCEP server's CA certificates are broken so we have to turn 
	   down the compliance level to allow them to be used */
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   &complianceValue );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
#endif /* SCEP servers with broken CA certificates */

	/* Get the issuing CA's certificate if required */
	if( addCACert )
		{
		if( scepInfo[ SCEP_NO ].caCertUrl != NULL )
			{
			if( !strcmp( scepInfo[ SCEP_NO ].caCertUrl, "default" ) )
				addCACert = FALSE;
			else
				{
				if( !getScepCACert( scepInfo[ SCEP_NO ].caCertUrl, 
									&cryptCACert ) )
					return( FALSE );
				}
			}
		else
			{
			status = importCertFromTemplate( &cryptCACert, 
											 SCEP_CA_FILE_TEMPLATE, SCEP_NO );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't get SCEP CA certificate, status = %d, "
						"line %d.\n", status, __LINE__ );
				return( FALSE );
				}
			}
		}

	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations */
#if ( SCEP_NO == 1 )
	status = pkiGetUserInfo( userID, password, NULL,
							 TEXT( "Test SCEP PKI user" ) );
	if( !status || status == CRYPT_ERROR_NOTAVAIL )
		{
		if( addCACert )
			cryptDestroyCert( cryptCACert );

		/* If certificate store operations aren't available, exit but 
		   continue with other tests, otherwise abort the tests */
		return( ( status == CRYPT_ERROR_NOTAVAIL ) ? TRUE : FALSE );
		}
	userPtr = userID;
	passwordPtr = password;
#endif /* cryptlib SCEP server */

	/* Get the certificate used to authenticate the renewal if required */
	if( testType == SCEP_TEST_RENEW || \
		testType == SCEP_TEST_RENEW_SIGONLY )
		{
		filenameFromTemplate( filenameBuffer, SCEP_PRIVKEY_FILE_TEMPLATE, 
							  ( testType == SCEP_TEST_RENEW ) ? 1 : 2 );
		status = getPrivateKey( &cryptRenewalKey, filenameBuffer, 
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't get SCEP-issued certificate for renewal, "
					"status = %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}

#if ( SCEP_NO == 1 )
	/* Get the CA certificate fingerprint */
	if( !addCACert )
		{
		char filenameBuffer[ FILENAME_BUFFER_SIZE ];

		filenameFromTemplate( filenameBuffer, SCEPCA_PRIVKEY_FILE_TEMPLATE, 
							  ( cryptAlgo == CRYPT_ALGO_RSA ) ? 1 : 2 );
		status = getPublicKey( &cryptCACert, filenameBuffer,
							   USER_PRIVKEY_LABEL );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't get SCEP CA certificate, status = %d, "
					"line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	status = cryptGetAttributeString( cryptCACert, 
									  CRYPT_CERTINFO_FINGERPRINT_SHA1,
									  caKeyFingerprint, 
									  &caKeyFingerprintSize );
	if( cryptStatusError( status ) )
		{
		if( !addCACert )
			cryptDestroyCert( cryptCACert );
		printf( "Couldn't get SCEP CA certificate fingerprint, status = %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCACert )
		cryptDestroyCert( cryptCACert );
#endif /* cryptlib SCEP server */

	/* Create the SCEP session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP );
	if( status == CRYPT_ERROR_PARAM3 )	/* SCEP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that the SCEP client's checking for invalid transactionIDs
	   works (this is an obscure problem caused by the SCEP protocol, see 
	   the SCEP client code comments for more information) */
	if( testType == SCEP_TEST_NORMAL )
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME,
										  TEXT( "abc@def" ), 
										  paramStrlen( TEXT( "abc@def" ) ) );
		if( cryptStatusOK( status ) )
			{
			printf( "Addition of invalid SCEP user information wasn't detected, "
					"line %d.\n", __LINE__ );
			return( FALSE );
			}
		}

	/* Set up the user and server information */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_CMP_REQUESTTYPE,
								( testType == SCEP_TEST_RENEW || \
								  testType == SCEP_TEST_RENEW_SIGONLY ) ? \
								  CRYPT_REQUESTTYPE_CERTIFICATE : \
								  CRYPT_REQUESTTYPE_INITIALISATION );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME,
										  userPtr, paramStrlen( userPtr ) );
		}
	if( cryptStatusOK( status ) && testType != SCEP_TEST_RENEW )
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_PASSWORD,
										  passwordPtr, 
										  paramStrlen( passwordPtr ) );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_SERVER_NAME,
									scepInfo[ SCEP_NO ].url,
									paramStrlen( scepInfo[ SCEP_NO ].url ) );
		}
	if( addCACert )
		{
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_CACERTIFICATE,
										cryptCACert );
			}
		cryptDestroyCert( cryptCACert );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Addition of SCEP user/server information failed with error "
				"code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the PKCS #10 request.  For standard SCEP this is unsigned 
	   since we need to add the SCEP challengePassword to it before we send 
	   it to the server, however for a SCEP renewal it's signed since 
	   there's no challengePassword and the request is authenticated by being
	   signed with the previously-issued SCEP certificate */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 USER_PRIVKEY_LABEL,
							 paramStrlen( USER_PRIVKEY_LABEL ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusOK( status ) )
		{
		status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED,
								  CRYPT_CERTTYPE_CERTREQUEST );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptRequest,
									CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, 
									cryptContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptRequest, scepRequestData, __LINE__ ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusOK( status ) && ( testType == SCEP_TEST_CUSTOMEXT ) )
		{
		const char *extensionData = "\x0C\x04Test";

		status = cryptAddCertExtension( cryptRequest, "1.2.3.4.5", FALSE, 
										extensionData, 6 );
		}
	if( cryptStatusOK( status ) && \
		( testType == SCEP_TEST_RENEW || \
		  testType == SCEP_TEST_RENEW_SIGONLY ) )
		status = cryptSignCert( cryptRequest, cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Creation of PKCS #10 request failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Set up the private key and request */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_PRIVATEKEY,
								( testType == SCEP_TEST_RENEW || \
								  testType == SCEP_TEST_RENEW_SIGONLY ) ? \
								  cryptRenewalKey : cryptContext );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_REQUEST,
									cryptRequest );
		}
	cryptDestroyCert( cryptRequest );
	if( testType == SCEP_TEST_RENEW || testType == SCEP_TEST_RENEW_SIGONLY )
		cryptDestroyContext( cryptRenewalKey );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* If we've explicitly fetched the issuing CA's certificate via an HTTP
	   request then the server session has already been run, so we need to
	   wait for it to recycle before we continue */
	if( localSession && addCACert && \
		scepInfo[ SCEP_NO ].caCertUrl != NULL && \
		waitMutex() == CRYPT_ERROR_TIMEOUT )
		{
		printf( "Timed out waiting for server to initialise, line %d.\n", 
				__LINE__ );
		return( FALSE );
		}

#if defined( CONFIG_FAULTS ) && !defined( NDEBUG )
	/* If we're testing fault handling, inject the appropriate fault type */
	if( isErrorTest )
		{
		cryptSetFaultType( ( testType == SCEP_TEST_CORRUPT_TRANSACTIONID ) ? \
							 FAULT_CORRUPT_ID : \
						   ( testType == SCEP_TEST_CORRUPT_TRANSIDVALUE ) ? \
							 FAULT_SESSION_SCEP_CORRUPT_TRANSIDVALUE : \
						   ( testType == SCEP_TEST_CORRUPT_MESSAGETYPE ) ? \
							 FAULT_SESSION_SCEP_CORRUPT_MESSAGETYPE : \
						   ( testType == SCEP_TEST_CORRUPT_NONCE ) ? \
							 FAULT_SESSION_CORRUPT_NONCE : \
						   ( testType == SCEP_TEST_CORRUPT_AUTHENTICATOR ) ? \
							 FAULT_CORRUPT_AUTHENTICATOR : \
						   	 FAULT_NONE );
		}
#endif /* CONFIG_FAULTS && Debug */

	/* Activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	while( status == CRYPT_ENVELOPE_RESOURCE && retryCount < 5 )
		{
		/* The server has indicated that the certificate-issue operation is 
		   pending, try again in case it works this time */
		printExtError( cryptSession, "Attempt to activate SCEP client "
					   "session", status, __LINE__ );
		puts( "  (Retrying operation after 10 seconds in case certificate "
			  "issue is now approved...)" );
		delayThread( 10 );
		printf( "Retrying, attempt #%d.\n", ++retryCount );
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, 
									TRUE );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "Attempt to activate SCEP client "
					   "session", status, __LINE__ );
		if( isErrorTest )
			{
			/* These tests are supposed to fail, so if this happens then the 
			   overall test has succeeded */
			cryptDestroySession( cryptSession );
			puts( "  (This test checks error handling, so the failure "
				  "response is correct).\n" );
			return( TRUE );
			}
		if( isServerDown( cryptSession, status ) )
			{
			fputs( "  (Server could be down, faking it and "
				   "continuing...)\n", outputStream );
			cryptDestroySession( cryptSession );
			return( CRYPT_ERROR_FAILED );
			}
		if( status == CRYPT_ENVELOPE_RESOURCE )
			{
			puts( "Status is still marked as pending, the server may "
				  "require manual approval\n  of the certificate-issue "
				  "process.\n" );
			}
		cryptDestroySession( cryptSession );
		return( FALSE );
		}
	if( isErrorTest )
		{
		cryptDestroySession( cryptSession );
		puts( "  (This test should have led to a failure but "
			  "didn't, test has failed).\n" );
		return( FALSE );
		}

#ifdef SCEP_BROKEN_CA_CERT
	/* Restore normal certificate checking */
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   complianceValue );
#endif /* SCEP servers with broken CA certificates */

	/* Print the session security information */
	printFingerprint( cryptSession, FALSE );

	/* Obtain the response information, the newly-issued certificate and the 
	   CA certificate if it wasn't added explicitly but fetched as part of
	   the SCEP protocol run */
	status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
								&cryptResponse );
	if( cryptStatusOK( status ) && \
		( testType == SCEP_TEST_NORMAL || \
		  testType == SCEP_TEST_SIGONLY ) )
		{
		CRYPT_CERTIFICATE cryptResponseCopy;

		/* Try and read back a second copy of the same object.  This tests 
		   an internal processing condition in which the object being read 
		   back needs to be made external the first time but not the 
		   second */
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
									&cryptResponseCopy );
		if( cryptStatusOK( status ) )
			cryptDestroyCert( cryptResponseCopy );
		}
	if( cryptStatusOK( status ) && !addCACert )
		{
		status = cryptGetAttribute( cryptSession, 
									CRYPT_SESSINFO_CACERTIFICATE,
									&cryptCACert );
		}
	cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#if ( SCEP_NO != 1 )
	puts( "Returned certificate details are:" );
	printCertInfo( cryptResponse );
	if( !addCACert )
		{
		puts( "Returned CA certificate details are:" );
		printCertInfo( cryptCACert );
		}
#endif /* Keep the cryptlib results on one screen */

	/* Make sure that we got back what we asked for */
	if( testType == SCEP_TEST_NORMAL )
		{
		C_CHR attributeData[ 64 ];
		int attributeLength, i;

		for( i = 0; 
			 scepRequestData[ i ].type != CRYPT_ATTRIBUTE_NONE; 
			 i++ )
			{
			if( scepRequestData[ i ].componentType != IS_STRING )
				continue;
			status = cryptGetAttributeString( cryptResponse, 
											  scepRequestData[ i ].type, 
											  attributeData, 
											  &attributeLength );
			if( cryptStatusOK( status ) && \
				memcmp( scepRequestData[ i ].stringValue, attributeData,
						attributeLength ) )
				status = CRYPT_ERROR_BADDATA;
			if( cryptStatusError( status ) )
				{
				printf( "Attribute #%d in request wasn't returned in "
						"certificate, line %d.\n", i, __LINE__ );
				return( FALSE );
				}
			}
		}

	/* Save the key and certificate for later, in particular for the 
	   initialisation test where the certificate is reused to sign the
	   message in the renewal test */
	filenameFromTemplate( filenameBuffer, SCEP_PRIVKEY_FILE_TEMPLATE, 
						  ( testType == SCEP_TEST_NORMAL ) ? 1 : \
						  ( testType == SCEP_TEST_SIGONLY ) ? 2 : \
						  ( testType == SCEP_TEST_RENEW ) ? 3 : \
						  ( testType == SCEP_TEST_RENEW_SIGONLY ) ? 4 : 5 );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_FILE, filenameBuffer,
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPublicKey( cryptKeyset, cryptResponse );
		cryptKeysetClose( cryptKeyset );
		}
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't save SCEP certificate to file, error code %d, "
				"line %d.\n", status, __LINE__ );
		return(	FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptResponse );
	if( !addCACert )
		cryptDestroyCert( cryptCACert );
	puts( "SCEP client session succeeded.\n" );
	return( TRUE );
	}

int testSessionSCEP( void )
	{
	return( connectSCEP( FALSE, SCEP_TEST_NORMAL, CRYPT_ALGO_RSA ) );
	}

int testSessionSCEPCACert( void )
	{
	return( connectSCEP( FALSE, SCEP_TEST_CACERT, CRYPT_ALGO_RSA ) );
	}

enum { MUTEX_NONE, MUTEX_ACQUIRE, MUTEX_ACQUIRE_REACQUIRE };

static int scepServer( const int mutexBehaviour,
					   const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT cryptCAKey;
	CRYPT_KEYSET cryptCertStore;
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int status;

	/* Acquire the init mutex */
	if( mutexBehaviour == MUTEX_ACQUIRE || \
		mutexBehaviour == MUTEX_ACQUIRE_REACQUIRE )
		acquireMutex();

	printf( "SVR: Testing SCEP server session%s...\n",
			( mutexBehaviour == MUTEX_ACQUIRE_REACQUIRE ) ? \
				" (GetCACert portion)" : \
			( mutexBehaviour == MUTEX_NONE ) ? \
				" following GetCACert" : "" );

	/* Perform a test create of a SCEP server session to verify that we can
	   do this test */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP_SERVER );
	if( status == CRYPT_ERROR_PARAM3 )	/* SCEP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptDestroySession( cryptSession );

	/* Set up the server-side objects */
	filenameFromTemplate( filenameBuffer, SCEPCA_PRIVKEY_FILE_TEMPLATE, 
						  ( cryptAlgo == CRYPT_ALGO_RSA ) ? 1 : 2 );
	if( !pkiServerInit( &cryptCAKey, &cryptCertStore, filenameBuffer,
						USER_PRIVKEY_LABEL, scepPkiUserData, NULL, NULL, 
						NULL, "SCEP" ) )
		return( FALSE );

	/* Create the SCEP session and add the CA key and certificate store */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP_SERVER );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_PRIVATEKEY, cryptCAKey );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_KEYSET, cryptCertStore );
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptSession, "SVR: cryptSetAttribute()",
							  status, __LINE__ ) );
		}

	/* Tell the client that we're ready to go */
	releaseMutex();

	/* Activate the session */
	status = activatePersistentServerSession( cryptSession, FALSE );
	if( cryptStatusError( status ) )
		{
		cryptKeysetClose( cryptCertStore );
		cryptDestroyContext( cryptCAKey );
		return( extErrorExit( cryptSession, "SVR: Attempt to activate SCEP "
							  "server session", status, __LINE__ ) );
		}

	/* If we're running a second server session, reacquire the mutex for
	   the client to wait on */
	if( mutexBehaviour == MUTEX_ACQUIRE_REACQUIRE )
		acquireMutex();

	/* Clean up */
	cryptDestroySession( cryptSession );
	cryptKeysetClose( cryptCertStore );
	cryptDestroyContext( cryptCAKey );

	if( mutexBehaviour == MUTEX_ACQUIRE_REACQUIRE )
		puts( "SVR: SCEP session (GetCACert portion) succeeded." );
	else
		puts( "SVR: SCEP session succeeded.\n" );
	return( TRUE );
	}

int testSessionSCEPServer( void )
	{
	int status;

	createMutex();
	status = scepServer( MUTEX_ACQUIRE, CRYPT_ALGO_RSA );
	destroyMutex();

	return( status );
	}

/* Perform a client/server loopback test */

#ifdef TEST_SESSION_LOOPBACK

#ifdef WINDOWS_THREADS
  static unsigned __stdcall scepServerThread( void *arg )
#else
  static void *scepServerThread( void *arg )
#endif /* Windows vs. Unix threads */
	{
	const int argValue = *( ( int * ) arg );

#if 0
	/* If we do an explicit GetCACert via an HTTP keyset before the main 
	   SCEP session then we have to run the server twice, however this leads 
	   to the problems covered in the comment for the first entry in 
	   scepInfo[] above */
	scepServer( MUTEX_ACQUIRE_REACQUIRE, argValue );
	scepServer( MUTEX_NONE, argValue );
#else
	scepServer( MUTEX_ACQUIRE, argValue );
#endif /* 0 */
	THREAD_EXIT();
	}

static int scepClientServer( const SCEP_TEST_TYPE testType,
							 const CRYPT_ALGO_TYPE cryptAlgo )
	{
	THREAD_HANDLE hThread;
#ifdef __WINDOWS__
	unsigned threadID;
#endif /* __WINDOWS__ */
	int arg = cryptAlgo, status;

	/* This is a test that requires a database keyset, make sure that one 
	   is available */
	if( !checkDatabaseKeysetAvailable() )
		{
		fputs( "Skipping test due to unavailability of database "
			   "keysets.\n\n", outputStream );
		return( TRUE );
		}

#if ( SCEP_NO != 1 )
	/* Because the code has to handle so many CA-specific peculiarities, we
	   can only perform this test when the CA being used is the cryptlib
	   CA */
	puts( "Error: The local SCEP session test only works with SCEP_NO == 1." );
	return( FALSE );
#endif /* cryptlib CA */

	/* Start the server and wait for it to initialise */
	createMutex();
#ifdef __WINDOWS__
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, scepServerThread,
										 &arg, 0, &threadID );
#else
	pthread_create( &hThread, NULL, scepServerThread, &arg );
#endif /* Windows vs. Unix threads */
	THREAD_SLEEP( 1000 );

	/* Connect to the local server */
	status = connectSCEP( TRUE, testType, cryptAlgo );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}

int testSessionSCEPClientServer( void )
	{
	return( scepClientServer( SCEP_TEST_NORMAL, CRYPT_ALGO_RSA ) );
	}

int testSessionSCEPSigonlyClientServer( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "ECC algorithm support appears to be disabled, skipping "
			   "SCEP processing of\nECDSA certificates.\n\n", outputStream );
		return( TRUE );
		}

	return( scepClientServer( SCEP_TEST_SIGONLY, CRYPT_ALGO_ECDSA ) );
	}

int testSessionSCEPCustomExtClientServer( void )
	{
	int oldValue, status;

	/* Since we're creating a certificate with custom attributes, we have to 
	   enable the setting of unrecognised attribute types around the cert-
	   issue operation */
	status = cryptGetAttribute( CRYPT_UNUSED, 
								CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, 
								&oldValue );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( CRYPT_UNUSED, 
									CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, 
									TRUE );
		}
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't enable use of custom attributes for SCEP test." );
		return( FALSE );
		}
	status = scepClientServer( SCEP_TEST_CUSTOMEXT, CRYPT_ALGO_RSA );
	cryptSetAttribute( CRYPT_UNUSED, 
					   CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, oldValue );

	return( status );
	}

int testSessionSCEPSHA2ClientServer( void )
	{
	int value, status;

	/* Switch the hash algorithm to SHA-2 */
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
								&value );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH,
					   CRYPT_ALGO_SHA2 );
	status = scepClientServer( SCEP_TEST_NORMAL, CRYPT_ALGO_RSA );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, value );

	return( status );
	}

int testSessionSCEPCACertClientServer( void )
	{
	return( scepClientServer( SCEP_TEST_CACERT, CRYPT_ALGO_RSA ) );
	}

int testSessionSCEPRenewClientServer( void )
	{
	return( scepClientServer( SCEP_TEST_RENEW, CRYPT_ALGO_RSA ) );
	}

int testSessionSCEPRenewSigonlyClientServer( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "ECC algorithm support appears to be disabled, skipping "
			   "SCEP processing of\nECDSA certificates.\n\n", outputStream );
		return( TRUE );
		}

	return( scepClientServer( SCEP_TEST_RENEW_SIGONLY, CRYPT_ALGO_ECDSA ) );
	}

int testSessionSCEPClientServerDebugCheck( void )
	{
#if defined( CONFIG_FAULTS ) && !defined( NDEBUG )
	cryptSetFaultType( FAULT_NONE );
	if( !scepClientServer( SCEP_TEST_CORRUPT_TRANSACTIONID, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of transaction ID */
	if( !scepClientServer( SCEP_TEST_CORRUPT_TRANSIDVALUE, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of trans.ID data */
	if( !scepClientServer( SCEP_TEST_CORRUPT_MESSAGETYPE, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of message type */
	if( !scepClientServer( SCEP_TEST_CORRUPT_NONCE, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of sender/recipNonce */
	if( !scepClientServer( SCEP_TEST_CORRUPT_AUTHENTICATOR, CRYPT_ALGO_RSA ) )
		return( FALSE );	/* Detect corruption of password */
	cryptSetFaultType( FAULT_NONE );
#endif /* CONFIG_FAULTS && Debug */
	return( TRUE );
	}
#endif /* TEST_SESSION_LOOPBACK */

#endif /* TEST_SESSION || TEST_SESSION_LOOPBACK */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
