/****************************************************************************
*																			*
*					  cryptlib Self-test Utility Routines					*
*						Copyright Peter Gutmann 1997-2019					*
*																			*
****************************************************************************/

#include <ctype.h>
#include "cryptlib.h"
#include "test/test.h"

/* Various features can be disabled by configuration options, in order to 
   handle this we need to include the cryptlib config file so that we can 
   selectively disable some tests.
   
   Note that this checking isn't perfect, if cryptlib is built in release
   mode but we include misc/config.h here in debug mode then the defines 
   won't match up because the use of debug mode enables extra options that 
   won't be enabled in the release-mode cryptlib.  The checkLibraryIsDebug()
   function can be used to detect this debug/release mismatch and warn about
   self-test failures if one is found */
#include "misc/config.h"	/* For algorithm usage */
#include "misc/consts.h"	/* For DEFAULT_CRYPT_ALGO */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */
#ifdef HAS_WIDECHAR
  #include <wchar.h>
#endif /* HAS_WIDECHAR */
#ifndef NDEBUG
  #include "misc/config.h"
#endif /* NDEBUG */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Get a CA private key */

int getCAPrivateKey( CRYPT_CONTEXT *cryptContext, 
					 const BOOLEAN isIntermediateCA )
	{
	const char *privKeyLabel = isIntermediateCA ? \
							   USER_PRIVKEY_LABEL : CA_PRIVKEY_LABEL;

	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RSA, NULL ) ) )
		{
		return( getPrivateKey( cryptContext, 
							   isIntermediateCA ? ICA_PRIVKEY_FILE : \
												  CA_PRIVKEY_FILE,
							   privKeyLabel, TEST_PRIVKEY_PASSWORD ) );
		}

	return( getPrivateKey( cryptContext, 
						   isIntermediateCA ? ECCICA_PRIVKEY_FILE : \
											  ECCCA_PRIVKEY_FILE,
						   privKeyLabel, TEST_PRIVKEY_PASSWORD ) );
	}

/* Add a collection of fields to a certificate */

int addCertFields( const CRYPT_CERTIFICATE certificate,
				   const CERT_DATA *certData, const int lineNo )
	{
	CRYPT_ATTRIBUTE_TYPE prevAttribute = CRYPT_ATTRIBUTE_NONE;
	int i;

	for( i = 0; certData[ i ].type != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		BYTE buffer[ 256 ];
		int value, status;

		memset( buffer, '*', 256 );
		switch( certData[ i ].componentType )
			{
			case IS_NUMERIC:
				status = cryptSetAttribute( certificate,
											certData[ i ].type, 
											certData[ i ].numericValue );
				if( cryptStatusError( status ) )
					{
					fprintf( outputStream, "cryptSetAttribute() for entry "
							 "%d, field ID %d, numeric value %d, \n  failed "
							 "with error code %d, line %d.\n", i + 1, 
							 certData[ i ].type, certData[ i ].numericValue,
							 status, lineNo );
#ifdef USE_CERTLEVEL_PKIX_FULL
					if( certData[ i ].numericValue == CRYPT_CERTINFO_EXCLUDEDSUBTREES )
						{
						fprintf( outputStream, "This may be due to a "
								 "mismatch between the self-test code, "
								 "built with a\n" "compliance level of "
								 "CRYPT_COMPLIANCELEVEL_PKIX_FULL, and "
								 "cryptlib, probably\n" "built with "
								 "CRYPT_COMPLIANCELEVEL_STANDARD, which "
								 "doesn't recognise this\n" "attribute.\n" );
						}
#endif /* USE_CERTLEVEL_PKIX_FULL */
					break;
					}
				status = cryptGetAttribute( certificate, 
											certData[ i ].type, &value );
				if( ( status == CRYPT_ERROR_NOTINITED || \
					  cryptStatusOK( status ) ) && \
					value != certData[ i ].numericValue && \
					certData[ i ].type == CRYPT_ATTRIBUTE_CURRENT )
					{
					/* It's a selection component, we may have been 
					   selecting an entry in a not-yet-created attribute 
					   (that'll be created on-demand) so when we try and 
					   read back the current attribute we'll get back either
					   a non-inited error or whatever was last selected 
					   that's actually present */
					status = CRYPT_OK;
					break;
					}
				if( cryptStatusError( status ) )
					{
					fprintf( outputStream, "Read back of numeric attribute "
							 "for entry %d, field ID %d, failed, status %d, "
							 "line %d.\n", i + 1, certData[ i ].type, status,
							 lineNo );
					status = CRYPT_ERROR_FAILED;
					}
				if( value != certData[ i ].numericValue )
					{
					fprintf( outputStream, "Read back of numeric attribute "
							 "for entry %d, field ID %d, failed,\n  got %d, "
							 "expected %d, line %d.\n", i + 1, 
							 certData[ i ].type, value, 
							 certData[ i ].numericValue, lineNo );
					status = CRYPT_ERROR_FAILED;
					}
				break;

			case IS_STRING:
				{
				int valueLength = certData[ i ].numericValue ? \
									certData[ i ].numericValue : \
									paramStrlen( certData[ i ].stringValue );

				status = cryptSetAttributeString( certificate, 
												  certData[ i ].type, 
												  certData[ i ].stringValue,
												  valueLength );
				if( cryptStatusError( status ) )
					{
#if defined( _MSC_VER ) && ( _MSC_VER == 1200 ) && !defined( NDEBUG )
					if( status == CRYPT_ERROR_INVALID && \
						paramStrlen( certData[ i ].stringValue ) == 2 && \
						!memcmp( certData[ i ].stringValue, "NZ", 2 ) )
						{
						/* Warn about BoundsChecker-induced Heisenbugs */
						fputs( "                         ********************\n", 
							   outputStream );
						fputs( "If you're running this under BoundsChecker "
							   "you need to disable it to complete\nthe test "
							   "since it causes errors in the certificate "
							   "string-checking code.  The\nfollowing error "
							   "is caused by BoundsChecker, not by the "
							   "self-test failing.\n", outputStream );
						fputs( "                         ********************\n", 
							   outputStream );
						}
#endif /* VC++ 6 */
					fprintf( outputStream, "cryptSetAttributeString() for "
							 "entry %d, field ID %d,\n  string value '%s', "
							 "failed with error code %d, line %d.\n", i + 1, 
							 certData[ i ].type,
							 ( char * ) certData[ i ].stringValue, status,
							 lineNo );
					break;
					}
				status = cryptGetAttributeString( certificate, 
												  certData[ i ].type, buffer, 
												  &value );
				if( status == CRYPT_ERROR_NOTFOUND && \
					certData[ i ].type == CRYPT_CERTINFO_RFC822NAME )
					{
					/* Adding this attribute from testAltnameCert() tests 
					   the implicit selection of the subjectAltName when an
					   email address is added and the subjectName is 
					   otherwise selected, since the selection of the
					   subjectAltName is invisible and only occurs while the
					   email address is being added, it can't be read back 
					   without explicitly selecting the subjectAltName */
					status = CRYPT_OK;
					break;
					}
				if( cryptStatusOK( status ) && \
					certData[ i ].type == CRYPT_CERTINFO_OTHERNAME_TYPEID && \
					!memcmp( certData[ i ].stringValue, "1 3 6 1 4", 9 ) )
					{
					/* This attribute is set as a text OID but read back in 
					   binary form, so its effective content and length 
					   changes across the set/get operation */
					break;
					}
				if( cryptStatusError( status ) )
					{
					fprintf( outputStream, "Read back of string attribute "
							 "for entry %d, field ID %d, failed, status %d, "
							 "line %d.\n", i + 1, certData[ i ].type, status,
							 lineNo );
					status = CRYPT_ERROR_FAILED;
					break;
					}
				if( value != valueLength || \
					memcmp( certData[ i ].stringValue, buffer, valueLength ) )
					{
					/* If we're setting a multivalued attribute then when we 
					   try and read it back we'll get the first instance, 
					   not the one that we've just set.  We could handle this
					   by walking down the CRYPT_ATTRIBUTE_CURRENT_INSTANCE 
					   list but since this is a basic self-test it's easier 
					   to just hardcode the specific check and skip it */
					if( certData[ i ].type == CRYPT_CERTINFO_RFC822NAME && \
						prevAttribute == CRYPT_CERTINFO_RFC822NAME )
						break;
					if( certData[ i ].type == CRYPT_CERTINFO_IPADDRESS && \
						prevAttribute == CRYPT_CERTINFO_IPADDRESS )
						break;
					buffer[ valueLength ] = '\0';
					fprintf( outputStream, "Read back of string attribute "
							 "for entry %d, field ID %d, failed,\n  got '%s', "
							 "expected '%s', line %d.\n", i + 1, 
							 certData[ i ].type, buffer, 
							 ( char * ) certData[ i ].stringValue, lineNo );
					status = CRYPT_ERROR_FAILED;
					break;
					}
				break;
				}

#ifdef HAS_WIDECHAR
			case IS_WCSTRING:
				status = cryptSetAttributeString( certificate,
							certData[ i ].type, certData[ i ].stringValue,
							wcslen( certData[ i ].stringValue ) * sizeof( wchar_t ) );
				if( cryptStatusError( status ) )
					{
					fprintf( outputStream, "cryptSetAttributeString() for "
							 "entry %d, field ID %d,\n  wcString value '%s', "
							 "failed with error code %d, line %d.\n", i + 1, 
							 certData[ i ].type,
							 ( char * ) certData[ i ].stringValue, status,
							 lineNo );
					}
				break;
#endif /* HAS_WIDECHAR */

			case IS_TIME:
				status = cryptSetAttributeString( certificate,
							certData[ i ].type, &certData[ i ].timeValue,
							sizeof( time_t ) );
				if( cryptStatusError( status ) )
					{
					fprintf( outputStream, "cryptSetAttributeString() for "
							 "entry %d, field ID %d,\n  time value 0x"
							 TIMET_FORMAT ", failed with error code %d, "
							 "line %d.\n", i + 1, certData[ i ].type, 
							 certData[ i ].timeValue, status, lineNo );
					break;
					}
				status = cryptGetAttributeString( certificate, 
												  certData[ i ].type, buffer, 
												  &value );
				if( cryptStatusError( status ) )
					{
					fprintf( outputStream, "Read back of time attribute "
							 "for entry %d, field ID %d, failed, status %d, "
							 "line %d.\n", i + 1, certData[ i ].type, status,
							 lineNo );
					status = CRYPT_ERROR_FAILED;
					}
				if( value != sizeof( time_t ) || \
					memcmp( &certData[ i ].timeValue, buffer, 
							sizeof( time_t ) ) )
					{
					fprintf( outputStream, "Read back of time attribute "
							 "for entry %d, field ID %d, returned different "
							 "attribute value, line %d.\n", i + 1, 
							 certData[ i ].type, lineNo );
					status = CRYPT_ERROR_FAILED;
					}
				break;

			default:
				assert( FALSE );
				return( FALSE );
			}
		if( cryptStatusError( status ) )
			{
			printErrorAttributeInfo( certificate );
			return( FALSE );
			}
		prevAttribute = certData[ i ].type;
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Certificate Dump Routines						*
*																			*
****************************************************************************/

/* Check whether a string may be a Unicode string */

static BOOLEAN isUnicode( const BYTE *value, const int length )
	{
	wchar_t wcValue[ 16 + 4 ];

	/* If it's an odd length or too short to reliably guess, report it as 
	   non-Unicode */
	if( ( length % sizeof( wchar_t ) ) || length <= sizeof( wchar_t ) * 2 )
		return( FALSE );

	/* If the first four characters are ASCII then it's unlikely that it'll
	   be Unicode */
	if( isprint( value[ 0 ] ) && isprint( value[ 1 ] ) && \
		isprint( value[ 2 ] ) && isprint( value[ 3 ] ) )
		return( FALSE );

	/* We need at least three widechars for the next check */
	if( length <= sizeof( wchar_t ) * 3 )
		return( FALSE );

	/* Copy the byte-aligned value into a local wchar_t-aligned buffer for
	   analysis */
	memcpy( wcValue, value, min( length, 16 ) );

	/* Check whether the first 3 widechars have identical high bytes.  This
	   isn't totally reliable (e.g. "tanaka" will give a false positive, 
	   { 0x0160, 0x0069, 0x006B } will give a false negative) but it's close
	   enough */
	if( ( wcValue[ 0 ] & 0xFF00 ) == ( wcValue[ 1 ] & 0xFF00 ) && \
		( wcValue[ 0 ] & 0xFF00 ) == ( wcValue[ 2 ] & 0xFF00 ) )
		return( TRUE );

	return( FALSE );
	}

/* The following function performs many attribute accesses, rather than using
   huge numbers of status checks we use the following macro to check each 
   access */

#define CHK( function ) \
		status = function; \
		if( cryptStatusError( status ) ) \
			return( certInfoErrorExit( #function, status, __LINE__ ) )

static int certInfoErrorExit( const char *functionCall, const int status,
							  const int line )
	{
	fprintf( outputStream, "\n%s failed with status %d, line %d.\n", 
			 functionCall, status, line );
	return( FALSE );
	}

/* Print a DN or altName */

static int printComponent( const CRYPT_CERTIFICATE certificate,
						   const CRYPT_ATTRIBUTE_TYPE component,
						   const char *prefixString )
	{
	char buffer[ 1024 + 1 ];
	int length, status;

	status = cryptGetAttributeString( certificate, component, NULL, 
									  &length );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_NOTAVAIL && \
			component == CRYPT_CERTINFO_DN )
			{
			/* Report this special-case condition explicitly */
			fputs( "  (Name contains characters that prevent it from being "
				   "represented as a\n   text string).\n", outputStream ); 
			}
		return( FALSE );
		}
	if( length > 1024 )
		{
		/* This should never happen since the longest permitted component 
		   string has 128 characters, but we check for it just in case */
		fputs( "  (Name is too long to display, > 1K characters).\n", 
			   outputStream ); 
		return( FALSE );
		}
	status = cryptGetAttributeString( certificate, component, buffer, 
									  &length );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( isUnicode( buffer, length ) )
		{
		wchar_t wcBuffer[ 1024 + 1 ];

		/* Copy the byte-aligned value into a local wchar_t-aligned buffer 
		   for display */
		memcpy( wcBuffer, buffer, length );
		wcBuffer[ length / sizeof( wchar_t ) ] = TEXT( '\0' );
		fprintf( outputStream, "  %s = %S.\n", prefixString, wcBuffer ); 
		return( TRUE );
		}
	buffer[ length ] = '\0'; 
	fprintf( outputStream, "  %s = %s.\n", prefixString, buffer ); 
	
	return( TRUE );
	}

static int printComponents( const CRYPT_CERTIFICATE certificate,
							const CRYPT_ATTRIBUTE_TYPE component,
							const char *prefixString )
	{
	int status;

	/* Try and print the component if it's present */
	if( !printComponent( certificate, component, prefixString ) )
		return( FALSE );

	/* If it's not a DN or altName component, we're done */
	if( !( component >= CRYPT_CERTINFO_COUNTRYNAME && \
		   component <= CRYPT_CERTINFO_COMMONNAME ) && \
		!( component >= CRYPT_CERTINFO_OTHERNAME_TYPEID && \
		   component <= CRYPT_CERTINFO_REGISTEREDID ) )
		return( TRUE );

	/* Check for further components, for multivalued components in altNames */
	CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_INSTANCE, 
							component ) );
	while( cryptSetAttribute( certificate,
							  CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
							  CRYPT_CURSOR_NEXT ) == CRYPT_OK )
		{
		char buffer[ 64 ];

		sprintf( buffer, "  + %s", prefixString );
		if( !printComponent( certificate, component, buffer ) )
			return( FALSE );
		}
	return( TRUE );
	}

static void printDN( const CRYPT_CERTIFICATE certificate )
	{
	printComponents( certificate, CRYPT_CERTINFO_DN, "DN string" );
	printComponents( certificate, CRYPT_CERTINFO_COUNTRYNAME, "C" );
	printComponents( certificate, CRYPT_CERTINFO_STATEORPROVINCENAME, "S" );
	printComponents( certificate, CRYPT_CERTINFO_LOCALITYNAME, "L" );
	printComponents( certificate, CRYPT_CERTINFO_ORGANIZATIONNAME, "O" );
	printComponents( certificate, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, "OU" );
	printComponents( certificate, CRYPT_CERTINFO_COMMONNAME, "CN" );
	}

static void printAltName( const CRYPT_CERTIFICATE certificate )
	{
	int status;

	printComponents( certificate, CRYPT_CERTINFO_RFC822NAME, "Email" );
	printComponents( certificate, CRYPT_CERTINFO_DNSNAME, "DNSName" );
	printComponents( certificate, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER, "EDI Nameassigner" );
	printComponents( certificate, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME, "EDI Partyname" );
	printComponents( certificate, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, "URL" );
	printComponents( certificate, CRYPT_CERTINFO_IPADDRESS, "IP" );
	printComponents( certificate, CRYPT_CERTINFO_REGISTEREDID, "Registered ID" );
	status = cryptSetAttribute( certificate, CRYPT_CERTINFO_DIRECTORYNAME,
								CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "  altName DN is:\n" );
		printDN( certificate );
		}
	}

/* Print multivalued attributes */

static void printCertPolicy( const CRYPT_CERTIFICATE certificate )
	{
	char buffer[ 1024 ];
	int length, status;

	status = cryptGetAttributeString( certificate,
					CRYPT_CERTINFO_CERTPOLICYID, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		buffer[ length ] = '\0';
		fprintf( outputStream, 
				 "  certificatePolicies.policyInformation.policyIdentifier = %s.\n", 
				 buffer );
		}
	status = cryptGetAttributeString( certificate,
					CRYPT_CERTINFO_CERTPOLICY_CPSURI, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		buffer[ length ] = '\0';
		fprintf( outputStream, 
				 "  certificatePolicies.policyInformation.cpsURI = %s.\n", 
				 buffer );
		}
	status = cryptGetAttributeString( certificate,
					CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		buffer[ length ] = '\0';
		fprintf( outputStream, 
				 "  certificatePolicies.policyInformation.organisation = %s.\n", 
				 buffer );
		}
	status = cryptGetAttributeString( certificate,
					CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		buffer[ length ] = '\0';
		fprintf( outputStream, 
				 "  certificatePolicies.policyInformation.explicitText = %s.\n", 
				 buffer );
		}
	}

/* Print the information in a certificate */

int printCertInfo( const CRYPT_CERTIFICATE certificate )
	{
	CRYPT_CERTTYPE_TYPE certType;
	char buffer[ 1024 ];
	int length, value, status;

	CHK( cryptGetAttribute( certificate, CRYPT_CERTINFO_CERTTYPE, &value ) );
	certType = value;

	/* Display the issuer and subject DN */
	if( certType != CRYPT_CERTTYPE_CERTREQUEST && \
		certType != CRYPT_CERTTYPE_REQUEST_CERT && \
		certType != CRYPT_CERTTYPE_REQUEST_REVOCATION && \
		certType != CRYPT_CERTTYPE_RTCS_REQUEST && \
		certType != CRYPT_CERTTYPE_RTCS_RESPONSE && \
		certType != CRYPT_CERTTYPE_OCSP_REQUEST && \
		certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		certType != CRYPT_CERTTYPE_PKIUSER )
		{
		fputs( "Certificate object issuer name is:\n", outputStream );
		CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_ISSUERNAME ) );
		printDN( certificate );
		if( cryptStatusOK( \
				cryptGetAttribute( certificate,
								   CRYPT_CERTINFO_ISSUERALTNAME, &value ) ) )
			{
			CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
									CRYPT_CERTINFO_ISSUERALTNAME ) );
			printAltName( certificate );
			}
		}
	if( certType != CRYPT_CERTTYPE_CRL && \
		certType != CRYPT_CERTTYPE_REQUEST_REVOCATION && \
		certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		certType != CRYPT_CERTTYPE_RTCS_REQUEST && \
		certType != CRYPT_CERTTYPE_RTCS_RESPONSE && \
		certType != CRYPT_CERTTYPE_OCSP_REQUEST && \
		certType != CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		fputs( "Certificate object subject name is:\n", outputStream );
		CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_SUBJECTNAME ) );
		printDN( certificate );
		if( cryptStatusOK( \
				cryptGetAttribute( certificate,
								   CRYPT_CERTINFO_SUBJECTALTNAME, &value ) ) )
			{
			CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
									CRYPT_CERTINFO_SUBJECTALTNAME ) );
			printAltName( certificate );
			}
		}

	/* Display the validity information */
#ifndef _WIN32_WCE
	if( certType == CRYPT_CERTTYPE_CERTCHAIN ||
		certType == CRYPT_CERTTYPE_CERTIFICATE || \
		certType == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		time_t validFrom, validTo;

		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_VALIDFROM,
									  &validFrom, &length ) );
		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_VALIDTO,
									  &validTo, &length ) );
		fprintf( outputStream, "Certificate is valid from %s to %s.\n", 
				 getTimeString( validFrom, 0 ),
				 getTimeString( validTo, 1 ) );
		}
	if( certType == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		time_t thisUpdate, nextUpdate;

		status = cryptGetAttributeString( certificate, CRYPT_CERTINFO_THISUPDATE,
										  &thisUpdate, &length );
		if( cryptStatusOK( status ) )
			{
			/* RTCS basic responses only return a minimal valid/not valid
			   status so failing to find a time isn't an error */
			status = cryptGetAttributeString( certificate,
											  CRYPT_CERTINFO_NEXTUPDATE,
											  &nextUpdate, &length );
			if( cryptStatusOK( status ) )
				{
				fprintf( outputStream, "OCSP source CRL time %s,\n  next "
						 "update %s.\n", getTimeString( thisUpdate, 0 ), 
						 getTimeString( nextUpdate, 1 ) );
				}
			else
				{
				fprintf( outputStream, "OCSP source CRL time %s.\n", 
						 getTimeString( thisUpdate, 0 ) );
				}
			}
		}
	if( certType == CRYPT_CERTTYPE_CRL )
		{
		time_t thisUpdate, nextUpdate;

		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_THISUPDATE,
									  &thisUpdate, &length ) );
		status = cryptGetAttributeString( certificate, CRYPT_CERTINFO_NEXTUPDATE,
										  &nextUpdate, &length );
		if( cryptStatusOK( status ) )
			{
			fprintf( outputStream, "CRL time %s,\n  next update %s.\n", 
					 getTimeString( thisUpdate, 0 ), 
					 getTimeString( nextUpdate, 1 ) );
			}
		else
			{
			fprintf( outputStream, "CRL time %s.\n", 
					 getTimeString( thisUpdate, 0 ) );
			}
		}
#endif /* _WIN32_WCE */
	if( certType == CRYPT_CERTTYPE_CRL || \
		certType == CRYPT_CERTTYPE_RTCS_RESPONSE || \
		certType == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		int noEntries = 0;

		/* Count and display the entries */
		if( cryptSetAttribute( certificate, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
							   CRYPT_CURSOR_FIRST ) == CRYPT_OK )
			{
			fputs( "Revocation/validity list information:\n", outputStream );
			do
				{
#ifndef _WIN32_WCE
				time_t timeStamp = 0;
#endif /* _WIN32_WCE */
				int revStatus DUMMY_INIT, revReason, certStatus DUMMY_INIT;
				BOOLEAN hasRevTime = FALSE, hasRevReason = FALSE;

				noEntries++;

				/* Extract response-specific status information */
				if( certType == CRYPT_CERTTYPE_RTCS_RESPONSE )
					{
					CHK( cryptGetAttribute( certificate,
								CRYPT_CERTINFO_CERTSTATUS, &certStatus ) );
					}
				if( certType == CRYPT_CERTTYPE_OCSP_RESPONSE )
					{
					CHK( cryptGetAttribute( certificate,
								CRYPT_CERTINFO_REVOCATIONSTATUS, &revStatus ) );
					}
#ifndef _WIN32_WCE
				if( certType == CRYPT_CERTTYPE_CRL || \
					( certType == CRYPT_CERTTYPE_OCSP_RESPONSE && \
					  revStatus == CRYPT_OCSPSTATUS_REVOKED ) )
					{
					/* Optional field, may not be present */
					status = cryptGetAttribute( certificate,
								CRYPT_CERTINFO_CRLREASON, &revReason );
					if( cryptStatusOK( status ) )
						hasRevReason = TRUE;
					}
				if( certType == CRYPT_CERTTYPE_CRL || \
					( certType == CRYPT_CERTTYPE_OCSP_RESPONSE && \
					  revStatus == CRYPT_OCSPSTATUS_REVOKED ) || \
					( certType == CRYPT_CERTTYPE_RTCS_RESPONSE && \
					  certStatus == CRYPT_CERTSTATUS_NOTVALID ) )
					{
					CHK( cryptGetAttributeString( certificate,
								CRYPT_CERTINFO_REVOCATIONDATE, &timeStamp,
								&length ) );
					hasRevTime = TRUE;
					}
#endif /* _WIN32_WCE */

				/* Make sure that we don't print excessive amounts of
				   information */
				if( noEntries >= 20 )
					{
					/* Once we reach a count of 20, we print a warning 
					   message and skip printing further output */
					if( noEntries == 20 )
						{
						fputs( "  (Further entries exist, but won't be "
							   "printed).\n", outputStream );
						}
					continue;
					}

				/* Print details status info */
				switch( certType )
					{
					case CRYPT_CERTTYPE_RTCS_RESPONSE:
						fprintf( outputStream, "  Certificate status = %d (%s).\n",
								 certStatus,
								 ( certStatus == CRYPT_CERTSTATUS_VALID ) ? \
									"valid" : \
								 ( certStatus == CRYPT_CERTSTATUS_NOTVALID ) ? \
									"not valid" : \
								 ( certStatus == CRYPT_CERTSTATUS_NONAUTHORITATIVE ) ? \
									"only non-authoritative response available" : \
									"unknown" );
						break;

					case CRYPT_CERTTYPE_OCSP_RESPONSE:
						fprintf( outputStream, "  Entry %d, revocation status = %d "
								 "(%s)", noEntries, revStatus,
								 ( revStatus == CRYPT_OCSPSTATUS_NOTREVOKED ) ? \
									"not revoked" : \
								 ( revStatus == CRYPT_OCSPSTATUS_REVOKED ) ? \
									"revoked" : "unknown" );
						if( hasRevTime )
							{
							fprintf( outputStream, ", rev.time %s",
									 getTimeString( timeStamp, 0 ) );
							}
						if( hasRevReason )
							{
							fprintf( outputStream, ", revocation reason %d", 
									 revReason );
							}
						fprintf( outputStream, ".\n" );
						break;

					case CRYPT_CERTTYPE_CRL:
						fprintf( outputStream, "  Entry %d, revocation "
								 "time %s", noEntries, 
								 getTimeString( timeStamp, 0 ) );
						if( hasRevReason )
							{
							fprintf( outputStream, ", revocation reason %d", 
									 revReason );
							}
						fprintf( outputStream, ".\n" );
						break;

					default:
						assert( 0 );
					}
				}
			while( cryptSetAttribute( certificate,
									  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
									  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
			}
		fprintf( outputStream, "Revocation/validity list has %d entr%s.\n", 
				 noEntries, ( noEntries == 1 ) ? "y" : "ies" );
		}

	/* Display the self-signed status and fingerprint */
	if( cryptStatusOK( cryptGetAttribute( certificate,
									CRYPT_CERTINFO_SELFSIGNED, &value ) ) )
		{
		fprintf( outputStream, "Certificate object is %sself-signed.\n",
				 value ? "" : "not " );
		}
	if( certType == CRYPT_CERTTYPE_CERTIFICATE || \
		certType == CRYPT_CERTTYPE_CERTCHAIN )
		{
		CHK( cryptGetAttributeString( certificate, 
									  CRYPT_CERTINFO_FINGERPRINT_SHA1,
									  buffer, &length ) );
		fprintf( outputStream, "Certificate fingerprint =\n" );
		printHex( "  ", buffer, length );
		}

	/* List the attribute types */
	if( !displayAttributes( certificate ) )
		return( FALSE );

	/* Display common attributes */
	if( cryptStatusError( \
			cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_GROUP,
							   CRYPT_CURSOR_FIRST ) ) )
		{
		fputs( "  (No extensions/attributes).\n", outputStream );
		return( TRUE );
		}
	fputs( "Some of the common extensions/attributes are:\n", outputStream );
	if( certType == CRYPT_CERTTYPE_CRL )
		{
		time_t theTime;

		CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_GROUP,
								CRYPT_CURSOR_FIRST ) );
		status = cryptGetAttribute( certificate, CRYPT_CERTINFO_CRLNUMBER,
									&value );
		if( cryptStatusOK( status ) && value )
			fprintf( outputStream, "  crlNumber = %d.\n", value );
		status = cryptGetAttribute( certificate, CRYPT_CERTINFO_DELTACRLINDICATOR,
									&value );
		if( cryptStatusOK( status ) && value )
			fprintf( outputStream, "  deltaCRLIndicator = %d.\n", value );
		status = cryptGetAttribute( certificate, CRYPT_CERTINFO_CRLREASON,
									&value );
		if( cryptStatusOK( status ) && value )
			fprintf( outputStream, "  crlReason = %d.\n", value );
		status = cryptGetAttributeString( certificate,
								CRYPT_CERTINFO_INVALIDITYDATE, &theTime, &length );
#ifndef _WIN32_WCE
		if( cryptStatusOK( status ) )
			{
			fprintf( outputStream, "  invalidityDate = %s.\n", 
					 getTimeString( theTime, 0 ) );
			}
#endif /* _WIN32_WCE */
		if( cryptStatusOK( \
				cryptGetAttribute( certificate,
								   CRYPT_CERTINFO_ISSUINGDIST_FULLNAME, &value ) ) )
			{
			CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
									CRYPT_CERTINFO_ISSUINGDIST_FULLNAME ) );
			fputs( "  issuingDistributionPoint is:\n", outputStream );
			printDN( certificate );
			printAltName( certificate );
			}
		return( TRUE );
		}
#ifndef _WIN32_WCE
	if( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		time_t signingTime;

		status = cryptGetAttributeString( certificate,
										  CRYPT_CERTINFO_CMS_SIGNINGTIME,
										  &signingTime, &length );
		if( cryptStatusOK( status ) )
			{
			fprintf( outputStream, "Signing time %s.\n", 
					 getTimeString( signingTime, 0 ) );
			}
		return( TRUE );
		}
#endif /* _WIN32_WCE */
	if( certType == CRYPT_CERTTYPE_PKIUSER )
		{
		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_PKIUSER_ID,
									  buffer, &length ) );
		buffer[ length ] ='\0';
		fprintf( outputStream, "  PKI user ID = %s.\n", buffer );
		CHK( cryptGetAttributeString( certificate,
									  CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									  buffer, &length ) );
		buffer[ length ] ='\0';
		fprintf( outputStream, "  PKI user issue password = %s.\n", 
				 buffer );
		CHK( cryptGetAttributeString( certificate,
									  CRYPT_CERTINFO_PKIUSER_REVPASSWORD,
									  buffer, &length ) );
		buffer[ length ] ='\0';
		fprintf( outputStream, "  PKI user revocation password = %s.\n", 
				 buffer );
		return( TRUE );
		}
	status = cryptGetAttribute( certificate,
								CRYPT_CERTINFO_KEYUSAGE, &value );
	if( cryptStatusOK( status ) && value )
		{
		static const struct { int flag; const char *name; } usageNames[] = {
			{ CRYPT_KEYUSAGE_DIGITALSIGNATURE, "digSig" },
			{ CRYPT_KEYUSAGE_NONREPUDIATION, "nonRep" },
			{ CRYPT_KEYUSAGE_KEYENCIPHERMENT, "keyEnc" },
			{ CRYPT_KEYUSAGE_DATAENCIPHERMENT, "dataEnc" },
			{ CRYPT_KEYUSAGE_KEYAGREEMENT, "keyAgree" },
			{ CRYPT_KEYUSAGE_KEYCERTSIGN, "certSign" },
			{ CRYPT_KEYUSAGE_CRLSIGN, "crlSign" },
			{ CRYPT_KEYUSAGE_ENCIPHERONLY, "encOnly" },
			{ CRYPT_KEYUSAGE_DECIPHERONLY, "decOnly" },
			{ CRYPT_KEYUSAGE_NONE, NULL }
			};
		BOOLEAN printedUsage = FALSE;
		int i;

		fprintf( outputStream, "  keyUsage = %02X (", value );
		for( i = 0; usageNames[ i ].flag != CRYPT_KEYUSAGE_NONE; i++ )
			{
			if( usageNames[ i ].flag & value )
				{
				if( printedUsage )
					fprintf( outputStream, ", " );
				fprintf( outputStream, "%s", usageNames[ i ].name );
				printedUsage = TRUE;
				}
			}
		fputs( ").\n", outputStream );
		}
	status = cryptGetAttribute( certificate,
								CRYPT_CERTINFO_EXTKEYUSAGE, &value );
	if( cryptStatusOK( status ) && value )
		{
		BOOLEAN firstTime = TRUE;

		fprintf( outputStream, "  extKeyUsage types = " );
		CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_GROUP,
								CRYPT_CERTINFO_EXTKEYUSAGE ) );
		do
			{
			CHK( cryptGetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
									&value ) );
			fprintf( outputStream, "%s%d", firstTime ? "" : ", ", value );
			firstTime = FALSE;
			}
		while( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		fprintf( outputStream, ".\n" );
		}
	status = cryptGetAttribute( certificate, CRYPT_CERTINFO_CA, &value );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "  basicConstraints.cA = %s.\n", 
				 value ? "True" : "False" );
		}
	status = cryptGetAttribute( certificate, CRYPT_CERTINFO_PATHLENCONSTRAINT,
								&value );
	if( cryptStatusOK( status ) && value )
		{
		fprintf( outputStream, "  basicConstraints.pathLenConstraint = %d.\n", 
				 value );
		}
	status = cryptGetAttributeString( certificate,
							CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "  subjectKeyIdentifier =\n" );
		printHex( "  ", buffer, length );
		}
	status = cryptGetAttributeString( certificate,
							CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "  authorityKeyIdentifier =\n" );
		printHex( "  ", buffer, length );
		}
	if( cryptStatusOK( \
			cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
							   CRYPT_CERTINFO_CERTPOLICYID ) ) )
		{
		fputs( "  certPolicy is/are:\n", outputStream );
		do
			{
			printCertPolicy( certificate );
			}
		while( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		}
	if( cryptStatusOK( \
			cryptGetAttribute( certificate,
							   CRYPT_CERTINFO_CRLDIST_FULLNAME, &value ) ) )
		{
		CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_CRLDIST_FULLNAME ) );
		fputs( "  crlDistributionPoint is/are:\n", outputStream );
		do
			{
			printDN( certificate );
			printAltName( certificate );
			}
		while( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		}

	return( TRUE );
	}

int printCertChainInfo( const CRYPT_CERTIFICATE certChain )
	{
	int value, count, status;

	/* Make sure that it really is a certificate chain */
	CHK( cryptGetAttribute( certChain, CRYPT_CERTINFO_CERTTYPE, &value ) );
	if( value != CRYPT_CERTTYPE_CERTCHAIN )
		{
		printCertInfo( certChain );
		return( TRUE );
		}

	/* Display info on each certificate in the chain.  This uses the cursor
	   mechanism to select successive certificates in the chain from the 
	   leaf up to the root */
	count = 0;
	CHK( cryptSetAttribute( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
							CRYPT_CURSOR_FIRST ) );
	do
		{
		fprintf( outputStream, "Certificate %d\n-------------\n", count++ );
		printCertInfo( certChain );
		fputs( "\n", outputStream );
		}
	while( cryptSetAttribute( certChain,
			CRYPT_CERTINFO_CURRENT_CERTIFICATE, CRYPT_CURSOR_NEXT ) == CRYPT_OK );

	/* Reset the cursor position in the chain */
	CHK( cryptSetAttribute( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
							CRYPT_CURSOR_FIRST ) );

	return( TRUE );
	}
