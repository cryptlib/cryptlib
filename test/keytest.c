/****************************************************************************
*																			*
*					cryptlib Test Key Generation Routines					*
*					  Copyright Peter Gutmann 1995-2024						*
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

/* Generate test keys for CA and security protocol use.  This enables 
   various special-case extensions such as extKeyUsages or protocol-specific 
   AIA entries, as well as using a validity period of 5 years instead of the 
   usual 1 year to avoid problems when users run the self-test on very old 
   copies of the code.  The keys generated into /test/keys are:

	File define			File			Description
	-----------			----			-----------
   CA:
	CA_PRIVKEY_FILE		ca.p15			RSA root CA key.
		CMP_CA_FILE		cmp_ca1.der		Written as side-effect of the above.
	ECCCA_PRIVKEY_FILE	ca_ecc.p15		ECDSA root CA key.
	EDCA_PRIVKEY_FILE	ca_ed.p15		Ed25519 root CA key.

   SSH:
	SSH_PRIVKEY_FILE	ssh1.p15		Raw SSH RSA key.
	SSH_PRIVKEY_FILE	ssh2.p15		Raw SSH DSA key.
	SSH_PRIVKEY_FILE	ssh3.p15		Raw SSH ECDSA key.
	SSH_PRIVKEY_FILE	ssh4.p15		Raw SSH Ed25519 key.

   TLS:
	SERVER_PRIVKEY_FILE	server1.p15		TLS RSA server key + root CA cert, 
										server cert has CN = localhost, OCSP 
										AIA.
	SERVER_PRIVKEY_FILE	server2.p15		As server2.p15 but with a different 
										RSA key, used to check that use of 
										the wrong key is detected.
	SERVER_PRIVKEY_FILE	server3.p15		As server1.p15, RSA key but with a 
										different FQDN, used to check that 
										use of the wrong certificate for 
										that host is detected.
	SERVER_PRIVKEY_FILE	serverp256.p15	As server1 but P256 ECDSA key.	
	SERVER_PRIVKEY_FILE	serverp384.p15	As server1 but P384 ECDSA key.	
	SERVER_PRIVKEY_FILE	serverp521.p15	As server1 but P521 ECDSA key.	
	SERVER_PRIVKEY_FILE	server25519.p15	As server1 but Ed25519 key.	

   Intermed.CA:
	ICA_PRIVKEY_FILE	ca_int.p15		Intermediate CA RSA key + previous 
										root CA cert, pathlen = 0.
	ECCICA_PRIVKEY_FILE ca_iecc.p15		Intermediate CA ECDSA key + previous 
										root CA cert, pathlen = 0.
   SCEP:
	SCEPCA_PRIVKEY_FILE	ca_scep1.p15	SCEP RSA CA key + root CA cert, SCEP 
										CA keyUsage allows encryption + 
										signing.
		SCEP_CA_FILE	scep_ca1.der	Written as side-effect of the above.
	SCEPCA_PRIVKEY_FILE	ca_scep2.p15	SCEP ECDSA CA key + root CA cert, 
										SCEP CA keyUsage allows signing.
		SCEP_CA_FILE	scep_ca2.der	Written as side-effect of the above.

   TSP:
	TSA_PRIVKEY_FILE	tsa.p15			TSA RSA server key + root CA cert, 
										TSA cert has TSP extKeyUsage.
   User:
	USER_PRIVKEY_FILE	user1.p15		User RSA key + root CA cert, user 
										cert has email address.
	USER_PRIVKEY_FILE	user2.p15		(Via template): User RSA key using 
										SHA256 + root CA cert, user cert has 
										email address.  Used to test auto-
										upgrade of enveloping algorithms to 
										SHA256.  Note that since 3.4.3 the 
										default algorithm is now SHA256 
										anyway so this test is a no-op, but 
										the functionality is left in place 
										to test future upgrades to new hash 
										algorithms.
	USER_PRIVKEY_FILE	user3.p15		(Via template): User key + 
										intermediate CA cert + root CA cert,
										i.e. long certificate chain.
										

   Other keys written by the self-test process (outside of this module) are:

	CMP_PRIVKEY_FILE	cmp*.p15		Created during the CMP self-test.
	DUAL_PRIVKEY_FILE	dual.p15		For test of signature + encryption 
										cert in same file in 
										testDoubleCertFile().
	OCSP_CA_FILE		ocspca.der		Written by the testCertManagement() 
										code.
	PNPCA_PRIVKEY_FILE	pnp_ca.p15		Created during the PnP PKI self-test,
	PNP_PRIVKEY_FILE	pnp_user.p15	_ca is for a CA cert request, _user 
										is for a user cert request.
	RENEW_PRIVKEY_FILE	renewed.p15		For test of update of older cert with
										newer one in testRenewedCertFile().
	TEST_PRIVKEY_FILE	test.p15		Generic test key file */

#define VALIDITY_TIME_YEARS				5

/* Define the following to add a policy to the CA and intermediate CA 
   certificates */

#define USE_POLICY

/* This isn't part of the standard self-test so we only enable it for 
   Windows debug builds */

#if !defined( NDEBUG ) && defined( _MSC_VER )

/****************************************************************************
*																			*
*						Certificate Data for Test Keys						*
*																			*
****************************************************************************/

static const CERT_DATA cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and CA" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Certification Division" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Himself" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* CA key usage */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_PATHLENCONSTRAINT, IS_NUMERIC, 1 },
#ifdef USE_POLICY
	{ CRYPT_CERTINFO_CERTPOLICYID, IS_STRING, 0, "1 3 6 1 4 1 3029 88 89 90 90 89" },
#endif /* USE_POLICY */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA serverCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Server cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "localhost" ) },

	/* Additional identification information for when we connect by IP 
	   address.  This is mostly required for Windows braindamage where 
	   "localhost" will be mapped to ::1 by the OS but to 127.0.0.1 for test 
	   clients like browsers, making it necessary to connect via explicit
	   IP address */
	{ CRYPT_CERTINFO_IPADDRESS, IS_STRING, 16, "\x00\x00\x00\x00\x00\x00\x00\x00"
											   "\x00\x00\x00\x00\x00\x00\x00\x01" },
	{ CRYPT_CERTINFO_IPADDRESS, IS_STRING, 4, "\x7F\x00\x00\x01" },

	/* Add an OCSP AIA entry */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_AUTHORITYINFO_OCSP },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://localhost" ) },
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};
static const CERT_DATA serverCertRequestWrongNameData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Server cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "wrong-host-name" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA iCACertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Intermediate CA cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's Spare CA" ) },

	/* Set the CA key usage extensions */
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYCERTSIGN },
#if 0	/* Implied because parent CA has pathLen = 1 */
	{ CRYPT_CERTINFO_PATHLENCONSTRAINT, IS_NUMERIC, 0 },
#endif /* 0 */
#ifdef USE_POLICY
	{ CRYPT_CERTINFO_CERTPOLICYID, IS_STRING, 0, "1 3 6 1 4 1 3029 88 89 90 90 89" },
#endif /* USE_POLICY */
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA scepCACertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "SCEP CA cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's SCEP CA" ) },

	/* Set the CA as well as generic sign+encrypt key usage extensions */
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYCERTSIGN | \
										   CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
										   CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA scepCAECCCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "SCEP CA cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's SCEP CA" ) },

	/* Set the CA as well as generic sign key usage extensions */
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYCERTSIGN | \
										   CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA tsaCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "TSA Cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's TSA" ) },

	/* Set the TSP extended key usage */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_TIMESTAMPING, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA userCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },
	{ CRYPT_CERTINFO_EMAIL, IS_STRING, 0, TEXT( "dave@wetaburgers.com" ) },
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },	/* Re-select subject DN */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Create a standalone private key + certificate */

static int createCAKeyFile( const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	const time_t validity = time( NULL ) + \
							( 86400L * 365 * VALIDITY_TIME_YEARS );
	int status;

	/* Create a self-signed CA certificate */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
										  CA_PRIVKEY_LABEL,
										  paramStrlen( CA_PRIVKEY_LABEL ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( !addCertFields( cryptCert, cACertData, __LINE__ ) )
		return( CRYPT_ERROR_FAILED );

	/* Make it valid for VALIDITY_TIME_YEARS instead of the default 1 year to 
	   avoid problems when users run the self-test with very old copies of the 
	   code */
	cryptSetAttributeString( cryptCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Open the keyset, update it with the certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  ( cryptAlgo == CRYPT_ALGO_ECDSA ) ? \
								ECCCA_PRIVKEY_FILE : \
							  ( cryptAlgo == CRYPT_ALGO_ED25519 ) ? \
								EDCA_PRIVKEY_FILE : CA_PRIVKEY_FILE, 
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptAddPrivateKey( cryptKeyset, cryptContext, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Save the certificate to disk for use in request/response protocols */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		BYTE certBuffer[ BUFFER_SIZE ];
		char filenameBuffer[ FILENAME_BUFFER_SIZE ];
		int length;

		status = cryptExportCert( certBuffer, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
		if( cryptStatusError( status ) )
			return( status );
		filenameFromTemplate( filenameBuffer, CMP_CA_FILE_TEMPLATE, 1 );
		if( ( filePtr = fopen( filenameBuffer, "wb" ) ) != NULL )
			{
			int count;

			count = fwrite( certBuffer, 1, length, filePtr );
			fclose( filePtr );
			if( count < length )
				{
				remove( filenameBuffer );
				puts( "Warning: Couldn't save CA certificate to disk, "
					  "this will cause later\n         tests to fail.  "
					  "Press a key to continue." );
				getchar();
				}
			}
		}

	cryptDestroyCert( cryptCert );
	cryptDestroyContext( cryptContext );
	cryptKeysetClose( cryptKeyset );

	return( CRYPT_OK );
	}

/* Create a raw SSH private key */

static int createSSHKeyFile( const CRYPT_ALGO_TYPE cryptAlgo,
							 const int keyNo )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int status;

	/* Create a private key */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
										  USER_PRIVKEY_LABEL,
										  paramStrlen( USER_PRIVKEY_LABEL ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Open the keyset, add the key, and close it */
	filenameFromTemplate( filenameBuffer, SSH_PRIVKEY_FILE_TEMPLATE, keyNo );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  filenameBuffer, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptAddPrivateKey( cryptKeyset, cryptContext, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		return( status );
	cryptDestroyContext( cryptContext );
	cryptKeysetClose( cryptKeyset );

	return( CRYPT_OK );
	}

/* Create a pseudo-certificate file, used to test embedded versions of 
   cryptlib running an TLS server when it's built with 
   CONFIG_NO_CERTIFICATES */

static int createPseudoCertificateFile( void )
	{
	CRYPT_CONTEXT cryptContext, cryptCAKey;
	CRYPT_CERTIFICATE cryptCertChain;
	FILE *filePtr;
	BYTE certBuffer[ BUFFER_SIZE ], *certBufPtr = certBuffer;
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int certBufSize = BUFFER_SIZE, status;

	/* Load a fixed RSA private key */
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptContext ) )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, ICA_PRIVKEY_FILE,
							USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certificate chain for the TLS server key */
	status = cryptCreateCert( &cryptCertChain, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCertChain,
							CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
		}
	cryptDestroyContext( cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCertChain, serverCertRequestData, __LINE__ ) )
		return( CRYPT_ERROR_FAILED );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCertChain, cryptCAKey );
	cryptDestroyContext( cryptCAKey );
	if( cryptStatusError( status ) )
		return( status );

	/* Export the chain as an TLS certificate chain.  We can't use 
	   CRYPT_IFORMAT_TLS for this since it's is a cryptlib-internal format,
	   so we have to manually assemble the TLS chain ourselves */
	status = cryptSetAttribute( cryptCertChain, 
								CRYPT_CERTINFO_CURRENT_CERTIFICATE,
								CRYPT_CURSOR_FIRST );
	if( cryptStatusError( status ) )
		return( status );
	do
		{
		int length;

		/* Export the certificate, leaving room for the 24-bit length at the
		   start */
		status = cryptExportCert( certBufPtr + 3, certBufSize - 3, &length, 
								  CRYPT_CERTFORMAT_CERTIFICATE, 
								  cryptCertChain );
		if( cryptStatusError( status ) )
			return( status );

		/* Add in the 24-bit length required by TLS */
		certBufPtr[ 0 ] = 0;
		certBufPtr[ 1 ] = ( length >> 8 );
		certBufPtr[ 2 ] = ( length & 0xFF );
		certBufPtr += 3 + length;
		certBufSize -= 3 + length;
		}
	while( cryptSetAttribute( cryptCertChain,
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
							  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
	cryptDestroyCert( cryptCertChain );

	/* Write the TLS-format certificate chain to disk */
	filenameFromTemplate( filenameBuffer, PSEUDOCERT_FILE_TEMPLATE, 1 );
	if( ( filePtr = fopen( filenameBuffer, "wb" ) ) != NULL )
		{
		const int length = BUFFER_SIZE - certBufSize;
		int count;

		count = fwrite( certBuffer, 1, length, filePtr );
		fclose( filePtr );
		if( count < length )
			{
			remove( filenameBuffer );
			puts( "Warning: Couldn't save TLS chain to disk, "
				  "this will cause later\n         tests to fail.  "
				  "Press a key to continue." );
			getchar();
			}
		}

	return( CRYPT_OK );
	}

/* Build a certificate chain without the root certificate.  This gets quite 
   complicated to do, we can't just delete the root with:

	cryptSetAttribute( certificate, CRYPT_CERTINFO_CURRENT_CERTIFICATE, 
					   CRYPT_CURSOR_FIRST );
	cryptDeleteAttribute( certificate, CRYPT_CERTINFO_CURRENT_CERTIFICATE );

   because the chain is locked against updates, and we can't use a 
   temporary keyset file to assemble the chain via:

	cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
					 TEST_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	cryptSetAttribute( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE, 
					   CRYPT_CURSOR_FIRST );
	cryptExportCert( buffer, BUFFER_SIZE, &certSize, 
					 CRYPT_CERTFORMAT_CERTIFICATE, certChain );
	cryptImportCert( buffer, certSize, CRYPT_UNUSED, &certificate );
	cryptSetAttribute( certificate, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptAddPublicKey( cryptKeyset, certificate );
	cryptSetAttribute( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE, 
					   CRYPT_CURSOR_NEXT );
	cryptExportCert( buffer, BUFFER_SIZE, &certSize, 
					 CRYPT_CERTFORMAT_CERTIFICATE, certChain );
	cryptImportCert( buffer, certSize, CRYPT_UNUSED, &certificate );
	cryptSetAttribute( certificate, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptAddPublicKey( cryptKeyset, certificate );
	cryptKeysetClose( cryptKeyset );
	cryptDestroyCert( certificate );

   because the leaf certificate is an EE certificate and therefore can't be 
   made explicitly trusted.  Because of this we have to create a pesudo-
   encoding of a certificate chain by copying a fixed-size indefinite-length-
   encoding header into a buffer:

	   0 NDEF: SEQUENCE {
	   2    9:   OBJECT IDENTIFIER signedData (1 2 840 113549 1 7 2)
	  13 NDEF:   [0] {
	  15 NDEF:     SEQUENCE {
	  17    1:       INTEGER 1
	  20   11:       SET {
	  22    9:         SEQUENCE {
	  24    5:           OBJECT IDENTIFIER sha1 (1 3 14 3 2 26)
	  31    0:           NULL
	         :           }
	         :         }
	  33   11:       SEQUENCE {
	  35    9:         OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
	         :         }
	  46 NDEF:       [0] {
   
   and then appending the certificates to it, which on import becomes a 
   canonicalised certificate chain */

static BYTE certChainHeader[] = { 
	0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 
	0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0, 0x80, 0x30,
	0x80, 0x02, 0x01, 0x01, 0x31, 0x0B, 0x30, 0x09, 
	0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05,
	0x00, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 
	0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA0, 0x80
	};

static int writeCertChainNoRoot( void )
	{
	CRYPT_CERTIFICATE certChain;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int bufPos, certSize, status;

	/* Get the complete certificate chain */
	filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 3 );
	status = getPublicKey( &certChain, filenameBuffer, USER_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		return( status );

	/* Export the required individual certificates from the chain and write
	   them into a new pseudo-chain that we can import */
	memcpy( buffer, certChainHeader, 48 );
	bufPos = 48;
	cryptSetAttribute( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE, 
					   CRYPT_CURSOR_FIRST );
	status = cryptExportCert( buffer + bufPos, BUFFER_SIZE - bufPos, 
							  &certSize, CRYPT_CERTFORMAT_CERTIFICATE, 
							  certChain );
	if( cryptStatusOK( status ) )
		{
		bufPos += certSize;
		cryptSetAttribute( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE, 
						   CRYPT_CURSOR_NEXT );
		status = cryptExportCert( buffer + bufPos, BUFFER_SIZE - bufPos, 
								  &certSize, CRYPT_CERTFORMAT_CERTIFICATE, 
								  certChain );
		}
	if( cryptStatusOK( status ) )
		{
		/* Add the 2-byte EOCs */
		bufPos += certSize;
		memset( buffer + bufPos, 0, 4 * 2 );
		bufPos += 4 * 2;
		}
	cryptDestroyCert( certChain );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the data as a new certificate chain, re-export it to 
	   canonicalise it, and finally write the results to the output file */
	status = cryptImportCert( buffer, bufPos, CRYPT_UNUSED, &certChain );
	if( cryptStatusOK( status ) )
		{
		status = cryptExportCert( buffer, BUFFER_SIZE, &certSize, 
								  CRYPT_CERTFORMAT_CERTCHAIN, certChain );
		}
	cryptDestroyCert( certChain );
	if( cryptStatusError( status ) )
		return( status );
	filenameFromTemplate( filenameBuffer, CHAINTEST_FILE_TEMPLATE, 
						  CHAINTEST_CHAIN_NOROOT );
	if( ( filePtr = fopen( filenameBuffer, "wb" ) ) != NULL )
		{
		int count;

		count = fwrite( buffer, 1, certSize, filePtr );
		fclose( filePtr );
		if( count < certSize )
			{
			remove( filenameBuffer );
			puts( "Warning: Couldn't save certificate chain to disk, "
				  "this will cause later\n         tests to fail.  "
				  "Press a key to continue." );
			getchar();
			}
		}

	return( CRYPT_OK );
	}

static int writeCertChain( const CERT_DATA *certRequestData,
						   const C_STR keyFileName,
						   const C_STR certFileName,
						   const BOOLEAN writeLongChain,
						   const CRYPT_ALGO_TYPE cryptAlgo,
						   const int keySize )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey, cryptKey;
	const BOOLEAN isECC = ( cryptAlgo == CRYPT_ALGO_ECDSA ) ? TRUE : FALSE;
	int status;

	/* Generate a key to certify.  We can't just reuse the built-in test key
	   because this has already been used as the CA key and the keyset code
	   won't allow it to be added to a keyset as both a CA key and user key,
	   so we have to generate a new one */
	status = cryptCreateContext( &cryptKey, CRYPT_UNUSED, cryptAlgo );
	if( cryptStatusOK( status ) && keySize != CRYPT_USE_DEFAULT )
		{
		status = cryptSetAttribute( cryptKey, CRYPT_CTXINFO_KEYSIZE, 
									keySize );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptKey, CRYPT_CTXINFO_LABEL,
										  USER_PRIVKEY_LABEL,
										  paramStrlen( USER_PRIVKEY_LABEL ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Test key generation failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the CA/intermediate CA's key.  Since we're explicitly handling 
	   RSA vs. ECC CA keys we use getPrivateKey() rather than 
	   getCAPrivateKey(), which would automatically select the key type for 
	   us.  
	   
	   The length of the chain is determined by the number of certs attached 
	   to the CAs certificate, so handling long vs. short chains is pretty 
	   simple */
	if( writeLongChain )
		{
		status = getPrivateKey( &cryptCAKey, isECC ? \
									ECCICA_PRIVKEY_FILE : ICA_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		}
	else
		{
		status = getPrivateKey( &cryptCAKey, isECC ? \
									ECCCA_PRIVKEY_FILE : CA_PRIVKEY_FILE,
								CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the keyset and add the private key to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keyFileName, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptKey,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Create the certificate chain for the new key */
	status = cryptCreateCert( &cryptCertChain, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCertChain,
							CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptKey );
		}
	cryptDestroyContext( cryptKey );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCertChain, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		const time_t validity = \
						time( NULL ) + ( 86400L * 365 * VALIDITY_TIME_YEARS );

		/* Make it valid for VALIDITY_TIME_YEARS years instead of 1 to avoid 
		   problems when users run the self-test with very old copies of the 
		   code */
		status = cryptSetAttributeString( cryptCertChain,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCertChain, cryptCAKey );
	cryptDestroyContext( cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Certificate chain creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptCertChain );
		return( FALSE );
		}

	/* Add the certificate chain to the file */
	status = cryptAddPublicKey( cryptKeyset, cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	if( certFileName != NULL )
		{
		FILE *filePtr;
		BYTE certBuffer[ BUFFER_SIZE ];
		int length;

		/* Save the certificate to disk for use in request/response 
		   protocols */
		status = cryptExportCert( certBuffer, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, 
								  cryptCertChain );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptExportCert() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		if( ( filePtr = fopen( convertFileName( certFileName ), \
							   "wb" ) ) != NULL )
			{
			int count;

			count = fwrite( certBuffer, 1, length, filePtr );
			fclose( filePtr );
			if( count < length )
				{
				remove( convertFileName( certFileName ) );
				fputs( "Warning: Couldn't save certificate chain to disk, "
					   "this will cause later\n         tests to fail.  "
					   "Press a key to continue.\n", outputStream );
				getchar();
				}
			}
		}
	cryptDestroyCert( cryptCertChain );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*								Test Key Generation							*
*																			*
****************************************************************************/

/* Create the cryptlib test keys */

int createTestKeys( void )
	{
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	char altFilenameBuffer[ FILENAME_BUFFER_SIZE ];
	int status;

	puts( "Creating custom key files and associated certificate files..." );

	if( cryptQueryCapability( CRYPT_ALGO_ECDSA, \
							  NULL ) == CRYPT_ERROR_NOTAVAIL || \
		cryptQueryCapability( CRYPT_ALGO_ED25519, \
							  NULL ) == CRYPT_ERROR_NOTAVAIL )
		{
		puts( "Error: ECDSA and Ed25519 must be enabled to create the "
			  "custom key files." );
		return( FALSE );
		}

	printf( "CA root key + CMP request certificate... " );
	status = createCAKeyFile( CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nECC CA root key... " );
		status = createCAKeyFile( CRYPT_ALGO_ECDSA );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nEd25519 CA root key... " );
		status = createCAKeyFile( CRYPT_ALGO_ED25519 );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSSH RSA server key... " );
		status = createSSHKeyFile( CRYPT_ALGO_RSA, 1 );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSSH DSA server key... " );
		status = createSSHKeyFile( CRYPT_ALGO_DSA, 2 );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSSH ECC server key... " );
		status = createSSHKeyFile( CRYPT_ALGO_ECDSA, 3 );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSSH Ed25519 server key... " );
		status = createSSHKeyFile( CRYPT_ALGO_ED25519, 4 );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTLS RSA server key... " );

		filenameFromTemplate( filenameBuffer, SERVER_PRIVKEY_FILE_TEMPLATE, 1 );
		if( !writeCertChain( serverCertRequestData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_RSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTLS RSA alternative server key... " );

		filenameFromTemplate( filenameBuffer, SERVER_PRIVKEY_FILE_TEMPLATE, 2 );
		if( !writeCertChain( serverCertRequestData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_RSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTLS RSA wrong-hostname server key... " );

		filenameFromTemplate( filenameBuffer, SERVER_PRIVKEY_FILE_TEMPLATE, 3 );
		if( !writeCertChain( serverCertRequestWrongNameData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_RSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTLS ECC P256 server key... " );

		filenameFromTemplate( filenameBuffer, SERVER_ECPRIVKEY_FILE_TEMPLATE, 256 );
		if( !writeCertChain( serverCertRequestData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_ECDSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTLS ECC P384 server key... " );

		filenameFromTemplate( filenameBuffer, SERVER_ECPRIVKEY_FILE_TEMPLATE, 384 );
		if( !writeCertChain( serverCertRequestData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_ECDSA, 48 /* P384 */ ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTLS ECC P521 server key... " );

		filenameFromTemplate( filenameBuffer, SERVER_ECPRIVKEY_FILE_TEMPLATE, 521 );
		if( !writeCertChain( serverCertRequestData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_ECDSA, 66 /* P521 */ ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTLS Ed25519 server key... " );

		filenameFromTemplate( filenameBuffer, SERVER_PRIVKEY_FILE_TEMPLATE, 25519 );
		if( !writeCertChain( serverCertRequestData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_ED25519, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nIntermediate CA key... " );
		if( !writeCertChain( iCACertRequestData, ICA_PRIVKEY_FILE, NULL, 
							 FALSE, CRYPT_ALGO_RSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nIntermediate ECC CA key... " );
		if( !writeCertChain( iCACertRequestData, ECCICA_PRIVKEY_FILE, NULL, 
							 FALSE, CRYPT_ALGO_ECDSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSCEP CA key + SCEP request certificate... " );
		filenameFromTemplate( filenameBuffer, SCEPCA_PRIVKEY_FILE_TEMPLATE, 1 );
		filenameFromTemplate( altFilenameBuffer, SCEP_CA_FILE_TEMPLATE, 1 );
		if( !writeCertChain( scepCACertRequestData, filenameBuffer, 
							 altFilenameBuffer, FALSE, CRYPT_ALGO_RSA, 
							 CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSCEP ECC CA key + SCEP request certificate... " );
		filenameFromTemplate( filenameBuffer, SCEPCA_PRIVKEY_FILE_TEMPLATE, 2 );
		filenameFromTemplate( altFilenameBuffer, SCEP_CA_FILE_TEMPLATE, 2 );
		if( !writeCertChain( scepCAECCCertRequestData, filenameBuffer,
							 altFilenameBuffer, FALSE, CRYPT_ALGO_ECDSA, 
							 CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTSA key... " );
		if( !writeCertChain( tsaCertRequestData, TSA_PRIVKEY_FILE, NULL, 
							 FALSE, CRYPT_ALGO_RSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nUser key... " );
		filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 1 );
		if( !writeCertChain( userCertRequestData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_RSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		int hashAlgo = CRYPT_ALGO_NONE;

		/* The following is currently redundant since the default hash is 
		   SHA-256 anyway, see the comment with the filenames above for 
		   details */
		printf( "done.\nUser key using SHA256... " );
		filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 2 );
		status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
									&hashAlgo );
		if( cryptStatusOK( status ) )
			{
			cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
							   CRYPT_ALGO_SHA2 );
			}
		if( !writeCertChain( userCertRequestData, filenameBuffer, NULL, 
							 FALSE, CRYPT_ALGO_RSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		if( hashAlgo != CRYPT_ALGO_NONE )
			{
			cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
							   hashAlgo );
			}
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nUser key (long chain)... " );
		filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 3 );
		if( !writeCertChain( userCertRequestData, filenameBuffer, NULL, 
							 TRUE, CRYPT_ALGO_RSA, CRYPT_USE_DEFAULT ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		CRYPT_CERTIFICATE certificate;

		printf( "done.\nCertificate chain test data... " );

		/* Leaf certificate */
		filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 3 );
		status = getPublicKey( &certificate, filenameBuffer, 
							   USER_PRIVKEY_LABEL );
		if( cryptStatusOK( status ) )
			{
			filenameFromTemplate( filenameBuffer, CHAINTEST_FILE_TEMPLATE, 
								  CHAINTEST_LEAF );
			status = exportCertFile( filenameBuffer, certificate, 
									 CRYPT_CERTFORMAT_CERTIFICATE );
			cryptDestroyCert( certificate );
			}

		/* Issuer (= intermediate CA) certificate */
		if( cryptStatusOK( status ) )
			{
			status = getPublicKey( &certificate, ICA_PRIVKEY_FILE, 
								   USER_PRIVKEY_LABEL );
			}
		if( cryptStatusOK( status ) )
			{
			filenameFromTemplate( filenameBuffer, CHAINTEST_FILE_TEMPLATE, 
								  CHAINTEST_ISSUER );
			status = exportCertFile( filenameBuffer, certificate, 
									 CRYPT_CERTFORMAT_CERTIFICATE );
			cryptDestroyCert( certificate );
			}

		/* Root certificate */
		if( cryptStatusOK( status ) )
			{
			status = getPublicKey( &certificate, CA_PRIVKEY_FILE, 
								   CA_PRIVKEY_LABEL );
			}
		if( cryptStatusOK( status ) )
			{
			filenameFromTemplate( filenameBuffer, CHAINTEST_FILE_TEMPLATE, 
								  CHAINTEST_ROOT );
			status = exportCertFile( filenameBuffer, certificate, 
									 CRYPT_CERTFORMAT_CERTIFICATE );
			cryptDestroyCert( certificate );
			}

		/* Full certificate chain */
		if( cryptStatusOK( status ) )
			{
			filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 3 );
			status = getPublicKey( &certificate, filenameBuffer, 
								   USER_PRIVKEY_LABEL );
			}
		if( cryptStatusOK( status ) )
			{
			filenameFromTemplate( filenameBuffer, CHAINTEST_FILE_TEMPLATE, 
								  CHAINTEST_CHAIN );
			status = exportCertFile( filenameBuffer, certificate, 
									 CRYPT_CERTFORMAT_CERTCHAIN );
			cryptDestroyCert( certificate );
			}

		/* Certificate chain without root certificate */
		if( cryptStatusOK( status ) )
			status = writeCertChainNoRoot();

		/* Certificate chain without leaf certificate */
		if( cryptStatusOK( status ) )
			{
			status = getPublicKey( &certificate, ICA_PRIVKEY_FILE, 
								   USER_PRIVKEY_LABEL );
			}
		if( cryptStatusOK( status ) )
			{
			filenameFromTemplate( filenameBuffer, CHAINTEST_FILE_TEMPLATE, 
								  CHAINTEST_CHAIN_NOLEAF );
			status = exportCertFile( filenameBuffer, certificate, 
									 CRYPT_CERTFORMAT_CERTCHAIN );
			cryptDestroyCert( certificate );
			}
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTLS pseudo-certificate chain... " );
		status = createPseudoCertificateFile();
		}
	if( cryptStatusError( status ) )
		{
		puts( "\nCustom key file create failed.\n" );
		return( FALSE );
		}
	puts( "done." );

	puts( "Custom key file creation succeeded.\n\n" );
	return( TRUE );
	}
#endif /* Windows debug mode */
