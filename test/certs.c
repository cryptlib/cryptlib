/****************************************************************************
*																			*
*					cryptlib Certificate Handling Test Routines				*
*						Copyright Peter Gutmann 1997-2023					*
*																			*
****************************************************************************/

/* Various features can be disabled by configuration options, in order to 
   handle this we need to include the cryptlib config file so that we can 
   selectively disable some tests.
   
   Note that this checking isn't perfect, if cryptlib is built in release
   mode but we include config.h here in debug mode then the defines won't
   match up because the use of debug mode enables extra options that won't
   be enabled in the release-mode cryptlib */
#include "misc/config.h"

#include <limits.h>
#include "cryptlib.h"
#include "test/test.h"

/* Go through the config a second time.  This gets a bit messy because some
   of the settings in misc/config.h can change cryptlib.h for cryptlib-
   internal use, but then that relies on misc/os_detect.h which we can't
   include here but have to define the necessary values in test.h.  Because
   of this we have to include misc/config.h a second time to pick up the
   changed values in test.h */
#undef _CONFIG_DEFINED
#include "misc/config.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* Certificate times.  Note that this value must be greater than the value
   defined by the kernel as MIN_TIME_VALUE, the minimum allowable 
   (backdated) timestamp value.

   Unlike every other system on the planet, the Mac Classic takes the time_t 
   epoch as 1904 rather than 1970 (even VMS, MVS, VM/CMS, the AS/400, Tandem 
   NSK, and God knows what other sort of strangeness stick to 1970 as the 
   time_t epoch) so we have to add an offset of 2082844800L to adjust for 
   this.  ANSI and ISO C are very careful to avoid specifying what the epoch 
   actually is, so it's legal to do this in the same way that it's legal for 
   Microsoft to break Kerberos because the standard doesn't say they can't */

#define ONE_YEAR_TIME	( 365 * 86400L )
#if defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __MRC__ )
  #define CERTTIME_DATETEST	( ( ( 2024 - 1970 ) * ONE_YEAR_TIME ) + 2082844800L )
#else
  #define CERTTIME_DATETEST	( ( 2024 - 1970 ) * ONE_YEAR_TIME )
#endif /* Macintosh-specific weird epoch */
#if ( ULONG_MAX > 0xFFFFFFFFUL ) || defined( _M_X64 )
  #define SYSTEM_64BIT
#else
  #define SYSTEM_32BIT
#endif /* From misc/os_spec.h, for consts.h include */
#include "misc/consts.h"
#if defined( _MSC_VER )
  /* The following check must be on a separate line since some compilers
     will try, and fail, to evaluate the time-related expression if it's
	 combined with the _MSC_VER check even if _MSC_VER isn't defined */
  #if CERTTIME_DATETEST <= MIN_TIME_VALUE
	/* CERTTIME_DATETEST is defined as a compile-time expression based on 
	   __DATE__ if possible, otherwise a static define, the guard above is
	   to test the static define.  The compile-time expression is checked
	   for in testCACert() */
	#error CERTTIME_DATETEST must be > MIN_TIME_VALUE
  #endif /* CERTTIME_DATETEST <= MIN_TIME_VALUE */
#endif /* Safety check of time test value against MIN_TIME_VALUE */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Set the trust setting for the root CA in a certificate chain.  This is 
   required for the self-test in order to allow signature checks for chains 
   signed by arbitrary CAs to work */

int setRootTrust( const CRYPT_CERTIFICATE cryptCertChain,
				  BOOLEAN *oldTrustValue, const BOOLEAN newTrustValue )
	{
	int status;

	status = cryptSetAttribute( cryptCertChain,
								CRYPT_CERTINFO_CURRENT_CERTIFICATE,
								CRYPT_CURSOR_LAST );
	if( cryptStatusError( status ) )
		return( status );
	if( oldTrustValue != NULL )
		{
		status = cryptGetAttribute( cryptCertChain, 
									CRYPT_CERTINFO_TRUSTED_IMPLICIT,
									oldTrustValue );
		if( cryptStatusError( status ) )
			return( status );
		}
	return( cryptSetAttribute( cryptCertChain,
							   CRYPT_CERTINFO_TRUSTED_IMPLICIT,
							   newTrustValue ) );
	}

/* Set the compliance level to maximum to enable all possible PKIX 
   weirdness */

static int setComplianceLevelMax( int *oldComplianceLevel )
	{
	int status;

	/* Try and set the compliance level to maximum */
	( void ) cryptGetAttribute( CRYPT_UNUSED, 
								CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
								oldComplianceLevel );
	status = cryptSetAttribute( CRYPT_UNUSED, 
								CRYPT_OPTION_CERT_COMPLIANCELEVEL,
								CRYPT_COMPLIANCELEVEL_PKIX_FULL );
	if( cryptStatusOK( status ) )
		return( TRUE );
	if( status != CRYPT_ERROR_PARAM3 )
		{
		/* General failure setting the compliance level */
		printf( "Attempt to set compliance level to "
				"CRYPT_COMPLIANCELEVEL_PKIX_FULL failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* The maximum level of PKIX weirdness that cryptlib will allow is less 
	   than CRYPT_COMPLIANCELEVEL_PKIX_FULL, we can't perform this test so 
	   we just skip it */
	fputs( "  (Couldn't set compliance level to "
		   "CRYPT_COMPLIANCELEVEL_PKIX_FULL, probably\n   because "
		   "cryptlib has been configured not to use this level, "
		   "skipping\n   test...).\n", outputStream );
	return( CRYPT_ERROR_NOTAVAIL );
	}
static void resetComplianceLevel( const int complianceLevel )
	{
	( void ) cryptSetAttribute( CRYPT_UNUSED, 
								CRYPT_OPTION_CERT_COMPLIANCELEVEL,
								complianceLevel );
	}

/* Export a certificate in a given format and make sure that the resulting 
   size is consistent with the calculated size */

static int checkExportCert( const CRYPT_CERTIFICATE cryptCert,
							const BOOLEAN isCertChain,
							const CRYPT_CERTFORMAT_TYPE format,
							const C_STR formatDescription )
	{
	BYTE buffer[ 4096 ];
	int calcSize, actualSize, status;

	status = cryptExportCert( NULL, 0, &calcSize, format, cryptCert );
	if( cryptStatusOK( status ) )
		{
		status = cryptExportCert( buffer, 4096, &actualSize, format, 
								  cryptCert );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Certificate%s export in %s format failed\n  "
				 "with status %d, line %d.\n", isCertChain ? " chain" : "", 
				 formatDescription, status, __LINE__ );
		return( FALSE );
		}
	if( calcSize != actualSize )
		{
		fprintf( outputStream, "Certificate%s export in %s format failed,\n  "
				 "calculated size was %d but actual size was %d, line %d.\n", 
				 isCertChain ? " chain" : "", formatDescription, 
				 calcSize, actualSize, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*						Certificate Creation Routines Test					*
*																			*
****************************************************************************/

BYTE certBuffer[ BUFFER_SIZE ];

/* Create a series of self-signed certs */

static const CERT_DATA certData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Self-signed X.509v3 certificate (technically it'd be an X.509v1, but
	   cryptlib automatically adds some required standard attributes so it
	   becomes an X.509v3 certificate) */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testBasicCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int certificateLength DUMMY_INIT, value, status;

#if defined( _MSC_VER ) && ( _MSC_VER <= 800 )
	time_t testTime = time( NULL ), newTime;

	newTime = mktime( localtime( &testTime ) );
	if( newTime == testTime )
		{
		puts( "Illogical local/GMT time detected.  VC++ 1.5x occasionally "
			  "exhibits a bug in\nits time zone handling in which it thinks "
			  "that the local time zone is GMT and\nGMT itself is some "
			  "negative offset from the current time.  This upsets\n"
			  "cryptlibs certificate date validity checking, since "
			  "certificates appear to\nhave inconsistent dates.  Deleting "
			  "all the temporary files and rebuilding\ncryptlib after "
			  "restarting your machine may fix this.\n" );
		return( FALSE );
		}
#endif /* VC++ 1.5 bug check */

	fputs( "Testing certificate creation/export...\n", outputStream );

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, certData, __LINE__ ) )
		return( FALSE );

	/* Delete a component and replace it with something else */
	status = cryptDeleteAttribute( cryptCert, CRYPT_CERTINFO_COMMONNAME );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptDeleteAttribute()", status,
							  __LINE__ ) );
		}
	cryptSetAttributeString( cryptCert,
				CRYPT_CERTINFO_COMMONNAME, TEXT( "Dave Taylor" ),
				paramStrlen( TEXT( "Dave Taylor" ) ) );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Set the certificate usage to untrusted for any purpose, which should 
	   result in the signature check failing */
	cryptSetAttribute( cryptCert, CRYPT_CERTINFO_TRUSTED_USAGE,
					   CRYPT_KEYUSAGE_NONE );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		puts( "Untrusted certificate signature check succeeded, should "
			  "have failed." );
		return( FALSE );
		}
	cryptDeleteAttribute( cryptCert, CRYPT_CERTINFO_TRUSTED_USAGE );

	/* Export the certificate.  We perform a length check using a null 
	   buffer to make sure that this facility is working as required */
	status = cryptExportCert( NULL, 0, &value, CRYPT_CERTFORMAT_CERTIFICATE,
							  cryptCert );
	if( cryptStatusOK( status ) )
		{
		status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	if( value != certificateLength )
		{
		puts( "Exported certificate size != actual data size." );
		return( FALSE );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( "cert", certBuffer, certificateLength );

	/* Export the chain in the various text formats to make sure that each
	   one works correctly */
	if( !checkExportCert( cryptCert, FALSE, 
						  CRYPT_CERTFORMAT_TEXT_CERTIFICATE,
						  "CRYPT_CERTFORMAT_TEXT_CERTIFICATE" ) )
		return( FALSE );
	if( !checkExportCert( cryptCert, FALSE, 
						  CRYPT_CERTFORMAT_TEXT_CERTCHAIN,
						  "CRYPT_CERTFORMAT_TEXT_CERTCHAIN" ) )
		return( FALSE );
	if( !checkExportCert( cryptCert, FALSE, 
						  CRYPT_CERTFORMAT_XML_CERTIFICATE,
						  "CRYPT_CERTFORMAT_XML_CERTIFICATE" ) )
		return( FALSE );
	if( !checkExportCert( cryptCert, FALSE, 
						  CRYPT_CERTFORMAT_XML_CERTCHAIN,
						  "CRYPT_CERTFORMAT_XML_CERTCHAIN" ) )
		return( FALSE );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		int errorType, errorLocus DUMMY_INIT;

		extErrorExit( cryptCert, "cryptCheckCert()", status, __LINE__ );
		status = cryptGetAttribute( cryptCert, CRYPT_ATTRIBUTE_ERRORTYPE,
									&errorType );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetAttribute( cryptCert, 
										CRYPT_ATTRIBUTE_ERRORLOCUS, 
										&errorLocus );
			}
		if( cryptStatusOK( status ) && \
			errorType == CRYPT_ERRTYPE_CONSTRAINT && \
			errorLocus == CRYPT_CERTINFO_VALIDFROM )
			{
			puts( "  (If this test was run within +/- 12 hours of a "
				  "daylight savings time (DST)\n   switchover then this is "
				  "a false positive caused by problems in\n   performing "
				  "date calculations using the C standard libraries on days "
				  "that\n   have 23 or 25 hours due to hours missing or "
				  "being repeated.  This problem\n   will correct itself "
				  "once the time is more than 12 hours away from the DST\n"
				  "   switchover, and only affects the certificate-creation "
				  "self-test)." );
			}

		return( FALSE );
		}
	cryptDestroyCert( cryptCert );

	/* Clean up */
	fputs( "Certificate creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

static const CERT_DATA cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers and CA" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Himself" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Certification Division" ) },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* Start date set to a fixed value to check for problems in date/time
	   conversion routines */
	{ CRYPT_CERTINFO_VALIDFROM, IS_TIME, 0, NULL, CERTTIME_DATETEST },

	/* CA extensions.  Policies are very much CA-specific and currently
	   undefined, so we use a dummy OID for a nonexistant private org for
	   now */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_PATHLENCONSTRAINT, IS_NUMERIC, 0 },
	{ CRYPT_CERTINFO_CERTPOLICYID, IS_STRING, 0, 
	  TEXT( "1 3 6 1 4 1 9999 1" ) },
		/* Blank line needed due to bug in Borland C++ parser */
	{ CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT, IS_STRING, 0, 
	  TEXT( "This policy isn't worth the paper it's not printed on." ) },
	{ CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION, IS_STRING, 0, 
	  TEXT( "Honest Joe's used cars and certification authority" ) },
	{ CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS, IS_NUMERIC, 1 },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testCACert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	const time_t invalidStartTime = MIN_TIME_VALUE; 
	const time_t invalidEndTime = MAX_TIME_VALUE;
	const time_t currentTime = time( NULL );
	time_t startTime, endTime DUMMY_INIT;
	int certificateLength DUMMY_INIT, value, status;

	fputs( "Testing CA certificate creation/export...\n", outputStream );

	/* The following check has to be in C code rather than as a #ifdef 
	   because CERTTIME_DATETEST is calculated from __DATE__ and may not be
	   an expression that can be resolved by the preprocessor */
	if( CERTTIME_DATETEST <= MIN_TIME_VALUE )
		{
		fputs( "Error: CERTTIME_DATETEST must be > MIN_TIME_VALUE.", 
			   outputStream );
		return( FALSE );
		}

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Test the ability to handle conversion of 32 <-> 64-bit time_t 
	   values in Win32 (but not Win64, where they're always 64-bit) */
#if defined( __WINDOWS__ ) && defined( _WIN32 ) && defined( _MSC_VER ) && \
	!defined( _M_X64 )
	{
	const __int64 time64 = CERTTIME_DATETEST;
	const unsigned int time32 = CERTTIME_DATETEST;

	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDFROM,
									  &time64, sizeof( time64 ) );
	if( cryptStatusOK( status ) )
		{
		cryptDeleteAttribute( cryptCert, CRYPT_CERTINFO_VALIDFROM );
		status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDFROM,
										  &time32, sizeof( time32 ) );
		cryptDeleteAttribute( cryptCert, CRYPT_CERTINFO_VALIDFROM );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Automatic 64 <-> 32-bit time_t correction failed, "
				"line %d.\n", __LINE__ );
		return( FALSE );
		}
	}
#endif /* Win32 with VC++ */

	/* Test the ability to reject invalid dates */
	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDFROM,
									  &invalidStartTime, sizeof( time_t ) );
	if( status != CRYPT_ERROR_PARAM3 )
		{
		printf( "Rejection of out-of-range time_t at MIN_TIME_VALUE %lX "
				"failed, line %d.\n", ( long ) MIN_TIME_VALUE, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDFROM,
									  &invalidEndTime, sizeof( time_t ) );
	if( status != CRYPT_ERROR_PARAM3 )
		{
		printf( "Rejection of out-of-range time_t at MAX_TIME_VALUE %lX "
				"failed, line %d.\n", ( long ) MAX_TIME_VALUE, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, cACertData, __LINE__ ) )
		return( FALSE );

	/* Since we're using a fixed time value for the start time in order to
	   be able to check that the time conversion succeeded and the end time
	   defaults to a year after the start time, we can end up with a 
	   certificate that's expired if we're too far past the start time.  To
	   deal with this we keep adding a year's worth to the end time until
	   it's no longer past the current time.  The add-loop is necessary due 
	   to the problems with performing maths with time_t's */
	endTime = CERTTIME_DATETEST + ONE_YEAR_TIME;
	while( currentTime > endTime - 86400 )
		endTime += ONE_YEAR_TIME;
	if( endTime != CERTTIME_DATETEST + ONE_YEAR_TIME )
		{
		status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDTO,
										  &endTime, sizeof( time_t ) );
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( cryptCert, "cryptSetAttributeString()", 
								  status, __LINE__ ) );
			}
		}

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the certificate, this time with base64 encoding to make sure 
	   that this works.  As before, we perform a length check using a null
	   buffer to make sure that this facility is working as required */
	status = cryptExportCert( NULL, 0, &value,
							  CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		{
		status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
								  CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptCert );
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	if( value != certificateLength )
		{
		puts( "Exported certificate size != actual data size." );
		return( FALSE );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( "cert_ca", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created.  We make the second
	   parameter to the check function the certificate (rather than 
	   CRYPT_UNUSED as done for the basic self-signed certificate) to check 
	   that this option works as required, and then retry with CRYPT_UNUSED 
	   to check the other possibility (although it's already been checked in 
	   the basic certificate above) */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDFROM,
									  &startTime, &value );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDTO,
										  &endTime, &value );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Certificate time read failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( startTime != CERTTIME_DATETEST )
		{
		printf( "Warning: Certificate start time is wrong, got " 
				TIMET_FORMAT ", should be %lX.\n         This is probably "
				"due to problems in the system time handling routines.\n",
				startTime, CERTTIME_DATETEST );
		}
	cryptDestroyCert( cryptCert );
#if defined( __WINDOWS__ ) || defined( __linux__ ) || defined( sun )
	if( ( startTime != CERTTIME_DATETEST && \
		  ( startTime - CERTTIME_DATETEST != 3600 && \
			startTime - CERTTIME_DATETEST != -3600 ) ) )
		{
		/* If the time is off by exactly one hour this isn't a problem
		   because the best we can do is get the time adjusted for DST
		   now rather than DST when the certificate was created, a problem 
		   that is more or less undecidable.  In addition we don't 
		   automatically abort for arbitrary systems since date problems 
		   usually arise from incorrectly configured time zone info or bugs 
		   in the system date-handling routines or who knows what, aborting 
		   on every random broken system would lead to a flood of 
		   unnecessary "bug" reports */
		return( FALSE );
		}
#endif /* System with known-good time handling */

	/* Clean up */
	fputs( "CA certificate creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

static const CERT_DATA xyzzyCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* XYZZY certificate */
	{ CRYPT_CERTINFO_XYZZY, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static int xyzzyCert( const BOOLEAN useAltAlgo,
					  const int hashSize )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int certificateLength, value, status;

	fprintf( outputStream, "Testing %sXYZZY certificate "
			 "creation/export%s...\n", useAltAlgo ? "DSA " : "",
			 ( hashSize == 48 ) ? " with SHA2-384" : \
			 ( hashSize == 64 ) ? " with SHA2-512" : "" );

	/* Create the public/private key contexts */
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASHPARAM, 
								&value );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( useAltAlgo )
		{
		status = loadDSAContexts( CRYPT_UNUSED, &pubKeyContext, 
								  &privKeyContext );
		if( status == CRYPT_ERROR_NOTAVAIL )
			return( exitUnsupportedAlgo( CRYPT_ALGO_DSA, "DSA signing" ) );
		if( !status )
			return( FALSE );
		}
	else
		{
		if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
			{
			fputs( "No PKC algorithm available for test.\n", outputStream );
			return( FALSE );
			}
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, xyzzyCertData, __LINE__ ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	if( hashSize != 0 && hashSize != value )
		{
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASHPARAM, 
						   hashSize );
		}
	status = cryptSignCert( cryptCert, privKeyContext );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASHPARAM, value );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Export the certificate */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( useAltAlgo ? "cert_xyzzy_dsa" : \
			   ( hashSize == 48 ) ? "cert_xyzzy_sha384" : \
			   ( hashSize == 64 ) ? "cert_xyzzy_sha512" : "cert_xyzzy", 
			   certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	cryptDestroyCert( cryptCert );

	/* Clean up */
	fprintf( outputStream, "%sXYZZY certificate creation succeeded.\n\n",
			 useAltAlgo ? "DSA " : "" );
	return( TRUE );
	}

int testXyzzyCert( void )
	{
	if( !xyzzyCert( FALSE, 0 ) )
		return( FALSE );
	if( !xyzzyCert( TRUE, 0 ) )
		return( FALSE );
#ifdef USE_SHA2_EXT
	if( !xyzzyCert( FALSE, 48 ) )
		return( FALSE );
	if( !xyzzyCert( FALSE, 64 ) )
		return( FALSE );
#endif /* USE_SHA2_EXT */
	return( TRUE );
	}

#ifdef HAS_WIDECHAR

static const wchar_t unicodeStr1[] = {	/* Full 16-bit Unicode */
	0x0414, 0x043E, 0x0432, 0x0435, 0x0440, 0x044F, 0x0439, 0x002C,
	0x0020, 0x043D, 0x043E, 0x0020, 0x043F, 0x0440, 0x043E, 0x0432,
	0x0435, 0x0440, 0x044F, 0x0439, 0x0000 
	};				/* "Doveryay, no proveryay" */
static const wchar_t unicodeStr2[] = {	/* Single non-8859-1 char */
	0x004D, 0x0061, 0x0072, 0x0074, 0x0069, 0x006E, 0x0061, 0x0020,
	0x0160, 0x0069, 0x006B, 0x006F, 0x0076, 0x006E, 0x00E1, 0x0000 
	};				/* "Martina Sikovna" */
#ifdef USE_UTF8
static const BYTE utf8EncodedStr1[] = {
	0xC3, 0x98, 0xC3, 0x86, 0xC3, 0x85, 0xC3, 0xA6, 
	0xC3, 0xB8, 0xC3, 0xA5, 0xC3, 0xBE, 0x00 
	};				/* O-stroke, AE, A-ring, ae, o-stroke, a-ring, thorn,
					   UTF-8 forms of 8859-1 characters */
static const BYTE utf8EncodedStr2[] = {
	0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87, 0x00 
	};				/* "Chinese" */
#else
static const wchar_t unicodeStr3[] = {	/* ASCII as Unicode */
	0x0053, 0x0074, 0x0061, 0x0074, 0x0065, 0x0020, 0x006E, 0x0061, 
	0x006D, 0x0065, 0x0000 };
#endif /* USE_UTF8 */

static const CERT_DATA textStringCertData[] = {
	/* Identification information: A latin-1 string (0xF6 = 'ö', 0xD8 = 
	   'Ø'), an obviously Unicode string, either a UTF-8 string or an 
	   explicit ASCII-in-Unicode string, a less-obviously Unicode string 
	   (only the 0x160 value is larger than 8 bits), either another UTF-8 
	   string or an implicit ASCII-in-Unicode string, and an ASCII string */
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "H\xF6rr \xD8sterix" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_WCSTRING, 0, unicodeStr1 },
#ifdef USE_UTF8
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, utf8EncodedStr1 },
#else
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_WCSTRING, 0, 
	  L"Dave's Unicode-aware CA with very long string" },
#endif /* USE_UTF8 */
	{ CRYPT_CERTINFO_LOCALITYNAME, IS_WCSTRING, 0, unicodeStr2 },
#ifdef USE_UTF8
	{ CRYPT_CERTINFO_STATEORPROVINCENAME, IS_STRING, 0, utf8EncodedStr2 },
#else
	{ CRYPT_CERTINFO_STATEORPROVINCENAME, IS_WCSTRING, 0, unicodeStr3 },
#endif /* USE_UTF8 */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "GB" ) },

	/* Another XYZZY certificate */
	{ CRYPT_CERTINFO_XYZZY, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testTextStringCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int certificateLength, i, status;

	fputs( "Testing complex string type certificate creation/export...\n", 
		   outputStream );

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, textStringCertData, __LINE__ ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Export the certificate */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n",
			 certificateLength );
	debugDump( "cert_string", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Make sure that we can read back what we've written and that it was
	   correctly converted back to the original string value */
	for( i = 0; textStringCertData[ i ].type != CRYPT_CERTINFO_XYZZY; i++ )
		{
		const CRYPT_ATTRIBUTE_TYPE attribute = textStringCertData[ i ].type;
		BYTE buffer[ 256 ];
		int length;

		status = cryptGetAttributeString( cryptCert, attribute, buffer, 
										  &length );
		if( cryptStatusError( status ) )
			{
			printf( "Attempt to read back DN value %d failed with error "
					"code %d, line %d.\n", attribute, status, __LINE__ );
			return( FALSE );
			}
		if( textStringCertData[ i ].componentType == IS_WCSTRING )
			{
#ifdef HAS_WIDECHAR
			const int wstrLen = wcslen( textStringCertData[ i ].stringValue ) * \
								sizeof( wchar_t );
			if( wstrLen != length || \
				memcmp( buffer, textStringCertData[ i ].stringValue, length ) )
				{
				if( attribute == CRYPT_CERTINFO_ORGANIZATIONNAME )
					{
					/* This is an ASCII string disguised as Unicode, which 
					   cryptlib correctly canonicalises back to ASCII */
					continue;
					}
#ifdef USE_UTF8
				if( attribute == CRYPT_CERTINFO_ORGANIZATIONALUNITNAME || \
					attribute == CRYPT_CERTINFO_LOCALITYNAME )
					{
					/* On UTF8 systems these Unicode strings will be 
					   converted to UTF8 */
					continue;
					}
#else
				if( attribute == CRYPT_CERTINFO_STATEORPROVINCENAME )
					{
					/* On non-UTF8 systems this is another ASCII string 
					   disguised as Unicode */
					continue;
					}
#endif /* USE_UTF8 */
				printf( "Widechar DN value %d read from certificate with value\n", 
						attribute );
				printHex( "  ", buffer, length );
				printf( "doesn't match value\n" );
				printHex( "  ", textStringCertData[ i ].stringValue, wstrLen );
				printf( "that was written, line %d.\n", __LINE__ );
				return( FALSE );
				}
#endif /* HAS_WIDECHAR */
			}
		else
			{
			const int strLen = paramStrlen( textStringCertData[ i ].stringValue );
			if( strLen != length || \
				memcmp( buffer, textStringCertData[ i ].stringValue, length ) )
				{
#ifdef USE_UTF8
				if( attribute == CRYPT_CERTINFO_COMMONNAME )
					{
					/* This is an 8-bit string that cryptlib canonicalises 
					   into something representable in a certificate, 
					   typically UTF-8 (since there's no way to tell what 
					   the host system uses as its native 8-bit character 
					   system) so the encoded form as read doesn't match 
					   what's written */
					continue;
					}
				if( attribute == CRYPT_CERTINFO_STATEORPROVINCENAME )
					{
					/* This is a UTF-8 string that cryptlib canonicalises 
					   into something useful on the local system, typically
					   Unicode, which is often 32-bit on Unix systems, to 
					   the encoded form as read doesn't match what's 
					   written */
					continue;
					}
#endif /* USE_UTF8 */
				printf( "DN value %d read from certificate with value\n", 
						attribute );
				printHex( "  ", buffer, length );
				printf( "doesn't match value\n" );
				printHex( "  ", textStringCertData[ i ].stringValue, strLen );
				printf( "that was written, line %d.\n", __LINE__ );
				return( FALSE );
				}
			}
		}
	cryptDestroyCert( cryptCert );

	/* Clean up */
	fputs( "Complex string type certificate creation succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}
#else

int testTextStringCert( void )
	{
	return( TRUE );
	}
#endif /* Unicode-aware systems */

static const CERT_DATA complexCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "US" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers and Netscape CA" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "TLS Certificates" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, 
	  TEXT( "Robert';DROP TABLE certificates;--" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dean@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "drew@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "donn@wetas-r-us.com" ) },	/* Multiple email addresses */
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, 
	  TEXT( "http://www.wetas-r-us.com" ) },

	/* Oddball altName components.  Note that the otherName.value must be a
	   DER-encoded ASN.1 object */
	{ CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER, IS_STRING, 0, 
	  TEXT( "EDI Name Assigner" ) },
	{ CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME, IS_STRING, 0, 
	  TEXT( "EDI Party Name" ) },
	{ CRYPT_CERTINFO_OTHERNAME_TYPEID, IS_STRING, 0, 
	  TEXT( "1 3 6 1 4 1 9999 2" ) },
	{ CRYPT_CERTINFO_OTHERNAME_VALUE, IS_STRING, 10, "\x04\x08" "12345678" },

#ifdef USE_CERTLEVEL_PKIX_FULL
	/* Path constraint */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_EXCLUDEDSUBTREES },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "CZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Brother's CA" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "TLS Certificates" ) },
#endif /* USE_CERTLEVEL_PKIX_FULL */

	/* CRL distribution points */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_CRLDIST_FULLNAME },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, 
	  TEXT( "http://www.revocations.com/crls/" ) },

	/* SubjectInfoAccess */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, 
	  TEXT( "http://192.168.1.1:8080/timesheet.asp?userid=1234;DROP%20TABLE%20USERS" ) },

#ifdef USE_CERT_OBSOLETE
	/* Add a vendor-specific extension, in this case a Thawte strong extranet
	   extension */
	{ CRYPT_CERTINFO_STRONGEXTRANET_ZONE, IS_NUMERIC, 0x99 },
	{ CRYPT_CERTINFO_STRONGEXTRANET_ID, IS_STRING, 0, TEXT( "EXTRA1" ) },
#endif /* USE_CERT_OBSOLETE */

#ifdef USE_CERTLEVEL_PKIX_PARTIAL
	/* Misc funnies */
	{ CRYPT_CERTINFO_OCSP_NOCHECK, IS_NUMERIC, CRYPT_UNUSED },
#endif /* USE_CERTLEVEL_PKIX_PARTIAL */

#ifdef USE_CUSTOM_CONFIG_1
	/* Custom attribute handling */
#if 1
	{ CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_POLICY, IS_STRING, 0, 
	  TEXT( "1 3 6 1 4 1 16334 509 2 1" ) },	/* NG policy 1 */
	{ CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST, IS_NUMERIC, 1, NULL },	
	{ CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CATEGORY_POLICY1, IS_STRING, 0, 
	  TEXT( "Policy 1 text" ) },
	{ CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CATEGORY_POLICY2, IS_STRING, 16, 
	  "\x01\x02\x04\x08\x10\x20\x40\x80\x80\x40\x20\x10\x08\x04\x02\x01" },
#endif
	{ CRYPT_CERTINFO_SUBJECTDIR_OBJECTCLASS, IS_STRING, 0, 
	  TEXT( "1 2 840 113556 1 3 23" ) },		/* Exchange container */
#endif /* USE_CUSTOM_CONFIG_1 */

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static int complexCert( const BOOLEAN selfSigned )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	C_CHR buffer1[ 64 ], buffer2[ 64 ];
	int certificateLength, complianceLevel;
	int length1 DUMMY_INIT, length2 DUMMY_INIT, status;

	fprintf( outputStream, 
			 "Testing %scomplex certificate creation/export...\n", 
			 selfSigned ? "self-signed " : "" );

	/* To encode/decode some of the fields we have to set the compliance 
	   level to maximum */
	status = setComplianceLevelMax( &complianceLevel );
	if( !status )
		return( FALSE );

	/* Create the public/private key contexts and get the private key used 
	   to sign the certificate.  See the comment in testCRL() for the 
	   chicken-and-egg problem with the use of a CA private key, for now we 
	   resolve this by using the test in testCertChain(), with this test 
	   used solely to manually test USE_CUSTOM_CONFIG handling */
	if( selfSigned )
		{
		if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
			{
			fputs( "No PKC algorithm available for test.\n", 
				   outputStream );
			resetComplianceLevel( complianceLevel );
			return( FALSE );
			}
		}
	else
		{
		if( !loadPkcContexts( &pubKeyContext, NULL ) )
			{
			fputs( "No PKC algorithm available for test.\n", 
				   outputStream );
			resetComplianceLevel( complianceLevel );
			return( FALSE );
			}
		status = getCAPrivateKey( &privKeyContext, FALSE );
		if( cryptStatusError( status ) )
			{
			resetComplianceLevel( complianceLevel );
			cryptDestroyContext( pubKeyContext );
			return( status );
			}
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, complexCertData, __LINE__ ) )
		return( FALSE );
	if( selfSigned )
		{
		status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SELFSIGNED, TRUE );
		if( cryptStatusError( status ) )
			{
			resetComplianceLevel( complianceLevel );
			return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
								  __LINE__ ) );
			}
		}

	/* Add an OID, read it back, and make sure that the OID en/decoding 
	   worked correctly */
	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_CERTPOLICYID, 
									  TEXT( "1 2 3 4 5" ), 
									  paramStrlen( TEXT( "1 2 3 4 5" ) ) );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert, 
										  CRYPT_CERTINFO_CERTPOLICYID, 
										  buffer1, &length1 );
		}
	if( cryptStatusOK( status ) )
		status = cryptDeleteAttribute( cryptCert, CRYPT_CERTINFO_CERTPOLICYID );
	if( cryptStatusOK( status ) && \
		( length1 != ( int ) paramStrlen( TEXT( "1 2 3 4 5" ) ) || \
		  memcmp( buffer1, TEXT( "1 2 3 4 5" ), length1 ) ) )
		{
		printf( "Error in OID en/decoding, line %d.\n", __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Add a non-CA basicConstraint, delete it, and re-add it as CA
	   constraint */
	status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_CA, FALSE );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	status = cryptDeleteAttribute( cryptCert,
								   CRYPT_CERTINFO_BASICCONSTRAINTS );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCert, "cryptDeleteAttribute()", status,
							  __LINE__ ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_CA, TRUE );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}

	/* Add a disabled attribute and make sure that it's detected.  This can 
	   be done in one of two ways, either directly by the kernel with a 
	   permission error or by the certificate-processing code with a not-
	   available error if we go in indirectly, for example using the 
	   attribute cursor */
#ifndef USE_CERT_OBSOLETE
	status = cryptSetAttribute( cryptCert, 
								CRYPT_CERTINFO_STRONGEXTRANET_ZONE, 1 );
	if( status != CRYPT_ERROR_PARAM2 )
		{
		printf( "Addition of disabled attribute %d wasn't detected, "
				"line %d.\n", CRYPT_CERTINFO_STRONGEXTRANET_ZONE, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}
#endif /* USE_CERT_OBSOLETE */
#ifndef USE_CERTLEVEL_PKIX_FULL
	status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT, 
								CRYPT_CERTINFO_EXCLUDEDSUBTREES );
	if( status != CRYPT_ERROR_PARAM3 )
		{
		printf( "Indirect addition of disabled attribute %d wasn't "
				"detected, line %d.\n", CRYPT_CERTINFO_EXCLUDEDSUBTREES, 
				__LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}
#endif /* USE_CERTLEVEL_PKIX_FULL */

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	if( selfSigned )
		destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		{
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Make sure that GeneralName component selection is working properly */
	cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
					   CRYPT_CERTINFO_SUBJECTALTNAME );
	status = cryptGetAttributeString( cryptCert,
						CRYPT_CERTINFO_RFC822NAME, buffer1, &length1 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert,
						CRYPT_CERTINFO_RFC822NAME, buffer2, &length2 );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to read and re-read email address failed, line "
				"%d.\n", __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}
#ifdef UNICODE_STRINGS
	buffer1[ length1 / sizeof( wchar_t ) ] = TEXT( '\0' );
	buffer2[ length2 / sizeof( wchar_t ) ] = TEXT( '\0' );
#else
	buffer1[ length1 ] = '\0';
	buffer2[ length2 ] = '\0';
#endif /* UNICODE_STRINGS */
	if( ( length1 != ( int ) paramStrlen( TEXT( "dave@wetas-r-us.com" ) ) ) || \
		( length1 != length2 ) || \
		memcmp( buffer1, TEXT( "dave@wetas-r-us.com" ), length1 ) || \
		memcmp( buffer2, TEXT( "dave@wetas-r-us.com" ), length2 ) )
		{
		printf( "Email address on read #1 = '%s',\n  read #2 = '%s', should "
				"have been '%s', line %d.\n", buffer1, buffer2,
				"dave@wetas-r-us.com", __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Export the certificate */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( selfSigned ? "cert_complex" : "cert_complex_ca", certBuffer, 
			   certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, 
							 selfSigned ? CRYPT_UNUSED : privKeyContext );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	if( !selfSigned )
		destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	resetComplianceLevel( complianceLevel );
	fprintf( outputStream, "%somplex certificate creation succeeded.\n\n",
			 selfSigned ? "Self-signed c" : "C" );
	return( TRUE );
	}

int testComplexCert( void )
	{
	return( complexCert( TRUE ) );
	}
int testComplexCertCAIssued( void )
	{
	return( complexCert( FALSE ) );
	}

static const CERT_DATA altnameCertData1[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "US" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Subject O" ) },

	/* Subject altName in the middle of the subjectName.  We add two
	   attributes, the first to check the imlicit creation and selection of 
	   the altName, the second to check its implicit selection */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, 
	  TEXT( "http://www.wetas-r-us.com" ) },

	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Subject OU" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Subject CN" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA altnameCertData2[] = {
	/* Identification information for subject DN */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "US" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Subject O" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Subject OU" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Subject CN" ) },

	/* Select altName DN */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTALTNAME },

	/* Identification information for altName DN */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "US" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Altname O" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Altname OU" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Altname CN" ) },

	/* Select subject DN */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },

	/* Back to an altName, implicitly selected */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dave@wetas-r-us.com" ) },

	/* Subject DN value again */
	{ CRYPT_CERTINFO_LOCALITYNAME, IS_STRING, 0, TEXT( "Subject L" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA altnameCertData3[] = {
	/* Straight to the altName as the first attribute */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dave@wetas-r-us.com" ) },

	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "US" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Subject O" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Subject OU" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Subject CN" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static int testAltnameHandling( const CERT_DATA *altnameCertData,
								const char *fileName )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int certificateLength, status;

	fputs( "Testing automatic handling of certificate altnames...\n", 
		   outputStream );

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add the certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, altnameCertData, __LINE__ ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the certificate */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( fileName, certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	cryptDestroyCert( cryptCert );

	/* Clean up */
	fputs( "Certificate altname handling succeeded.\n\n", outputStream );
	return( TRUE );
	}

int testAltnameCert( void )
	{
	if( !testAltnameHandling( altnameCertData1, "cert_altname1" ) )
		return( FALSE );
	if( !testAltnameHandling( altnameCertData2, "cert_altname2" ) )
		return( FALSE );
	if( !testAltnameHandling( altnameCertData3, "cert_altname3" ) )
		return( FALSE );
	return( TRUE );
	}

int testCertExtension( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	BYTE buffer[ 16 ];
	const char *extensionData = "\x0C\x04Test";
	int certificateLength, value, length, status;

	fputs( "Testing certificate with nonstd.extension creation/export...\n",
		   outputStream );

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_CA, TRUE );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, certData, __LINE__ ) )
		return( FALSE );

	/* Add a nonstandard critical extension */
	status = cryptAddCertExtension( cryptCert, "1.2.3.4.5", TRUE, extensionData, 6 );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptAddCertExtension()", status,
							  __LINE__ ) );
		}

	/* Sign the certificate.  Since we're adding a nonstandard extension we
	   have to set the CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES flag to
	   make sure that cryptlib will sign it */
	status = cryptGetAttribute( CRYPT_UNUSED,
								CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, 
								&value );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptSetAttribute( CRYPT_UNUSED,
					   CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, TRUE );
	status = cryptSignCert( cryptCert, privKeyContext );
	cryptSetAttribute( CRYPT_UNUSED,
					   CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, value );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the certificate and make sure that we can read what we 
	   created */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( "cert_extension", certBuffer, certificateLength );
	cryptDestroyCert( cryptCert );
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Check the certificate.  Since it contains an unrecognised critical 
	   extension it should be rejected, but accepted at a lowered compliance 
	   level */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		printf( "Certificate with unrecognised critical extension was "
				"accepted when it should\nhave been rejected, line %d.\n",
				__LINE__ );
		return( FALSE );
		}
	( void ) cryptGetAttribute( CRYPT_UNUSED, 
								CRYPT_OPTION_CERT_COMPLIANCELEVEL, &value );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   CRYPT_COMPLIANCELEVEL_REDUCED );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   value );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Read back the nonstandard extension and make sure that it's what we
	   originally wrote */
	status = cryptGetCertExtension( cryptCert, "1.2.3.4.5", &value, buffer,
									16, &length );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptGetCertExtension()", status,
							  __LINE__ ) );
		}
	if( value != TRUE || length != 6 || memcmp( extensionData, buffer, 6 ) )
		{
		printf( "Recovered nonstandard extension data differs from what was "
				"written, line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	fputs( "Certificate with nonstd.extension creation succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

int testCustomDNCert( void )
	{
#ifdef USE_CERT_DNSTRING
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	const C_STR customDN = \
				TEXT( "cn=Dave Taylor + sn=12345, ou=Org.Unit 2\\=1, " )
				TEXT( "ou=Org.Unit 2, ou=Org.Unit 1, " )
				TEXT( "o=Dave's Big Organisation, c=PT" );
	const C_STR invalidDnStrings[] = {
		TEXT( "abc\x01\x64" ) TEXT( "def" ),/* Invalid chars */
		TEXT( "cn=" ),				/* No value */
		TEXT( "cn=\\" ),			/* No escaped char */
		TEXT( "c\\n=x" ),			/* Escape in type */
		TEXT( "cn+x" ),				/* Spurious '+' */
		TEXT( "cn,x" ),				/* Spurious ',' */
		TEXT( "cn=z=y" ),			/* Spurious '=' */
		TEXT( "cn=x," ),			/* Spurious ',' */
		TEXT( "xyz=x" ),			/* Unknown type */
		NULL
		};
	char buffer[ BUFFER_SIZE ];
	int certificateLength, length, i, status;

	fputs( "Testing certificate with custom DN creation/export...\n", 
		   outputStream );

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_CA, TRUE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_SELFSIGNED, 
									TRUE );
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}

	/* Make sure that invalid DN strings are detected */
	for( i = 0; invalidDnStrings[ i ] != NULL; i++ )
		{
		status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_DN,
										  invalidDnStrings[ i ], 
										  paramStrlen( invalidDnStrings[ i ] ) );
		if( cryptStatusOK( status ) )
			{
			printf( "Addition of invalid DN string '%s' wasn't detected, "
					"line %d.\n", invalidDnStrings[ i ], __LINE__ );
			return( FALSE );
			}
		}

	/* Add the custom DN in string form */
	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_DN,
									  customDN, paramStrlen( customDN ) );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttributeString()", status,
							  __LINE__ ) );
		}

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the certificate and make sure that we can read what we 
	   created */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( "cert_customdn", certBuffer, certificateLength );
	cryptDestroyCert( cryptCert );
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Read back the custom DN and make sure that it's what we originally
	   wrote */
	status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_DN,
									  buffer, &length );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptGetAttributeString()", status,
							  __LINE__ ) );
		}
	if( length != ( int ) paramStrlen( customDN ) || \
		memcmp( customDN, buffer, length ) )
		{
		printf( "Recovered custom DN differs from what was written, line "
				"%d.\n", __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	fputs( "Certificate with custom DN creation succeeded.\n\n", 
		   outputStream );
#else
	fputs( "Skipping custom DN certificate creation/export test because "
		   "support for\nthis capability has been disabled via the cryptlib "
		   "config options.\n\n", outputStream );
#endif /* USE_CERT_DNSTRING */
	return( TRUE );
	}

int testCertAttributeHandling( void )
	{
#ifdef USE_CERT_DNSTRING
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	const C_STR customDN = \
				TEXT( "cn=Dave Taylor, ou=Org.Unit 3, ou=Org.Unit 2, " )
				TEXT( "ou=Org.Unit 1, o=Dave's Big Organisation, c=PT" );
	const C_STR email = TEXT( "dave@example.com" );
	const char *errorString = "(Generic attribute get/set/select error)";
	char buffer[ BUFFER_SIZE ];
	int length, value, status;

	fputs( "Testing certificate attribute handling...\n", outputStream );

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_SELFSIGNED, TRUE );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}

	/* Add the custom DN in string form and an altName component */
	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_DN,
									  customDN, paramStrlen( customDN ) );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_EMAIL,
										  email, paramStrlen( email ) );
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttributeString()", status,
							  __LINE__ ) );
		}

	/* Sign the certificate */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );

	/* Make sure that the attribute-manipulation routines work as 
	   intended */
	status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_SUBJECTALTNAME );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
									&value );
		if( cryptStatusError( status ) || \
			value != CRYPT_CERTINFO_SUBJECTALTNAME )
			{
			errorString = "Current attribute != subject altName after "
						  "subject altName was selected";
			status = -1;
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_EMAIL,
										  buffer, &length );
		if( cryptStatusError( status ) )
			errorString = "Fetch of email address from altName failed";
		}
	if( cryptStatusOK( status ) )
		{
		/* Should fail since we've now selected the DN in the altName */
		status = cryptGetAttributeString( cryptCert, 
										  CRYPT_CERTINFO_ORGANISATIONALUNITNAME,
										  buffer, &length );
		if( cryptStatusOK( status ) )
			{
			errorString = "OU was returned after altName was selected";
			status = -1;
			}
		else
			status = CRYPT_OK;
		}
	if( cryptStatusError( status ) )
		{
		printf( "%s, line %d.\n", errorString, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_SUBJECTNAME );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
									&value );
		if( cryptStatusError( status ) || \
			value != CRYPT_CERTINFO_SUBJECTNAME )
			{
			errorString = "Current attribute != subject DN after subject DN "
						  "was selected";
			status = -1;
			}
		}
#if 0	/* The following should in theory fail but doesn't because of the 
		   auto-selection of the subject altName when no other GeneralName 
		   is selected.  This is required in order for reads of commonly-
		   used fields like email addresses to work without the user having
		   to explicitly select the subject altName (which they're likely
		   unaware of) first.  This result is slightly non-orthogonal, but 
		   given the choice of enforcing strict orthogonality in a facility
		   that most users will never use vs. making something that's widely
		   used work as expected, the latter is the preferable option */
	if( cryptStatusOK( status ) )
		{
		/* Should fail since the subject DN is the currently selected 
		   attribute */
		status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_EMAIL,
										  buffer, &length );
		if( cryptStatusOK( status ) )
			{
			errorString = "email from altName was returned after subject DN was selected";
			status = -1;
			}
		else
			status = CRYPT_OK;
		}
#endif /* 0 */
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert, 
										  CRYPT_CERTINFO_ORGANISATIONALUNITNAME,
										  buffer, &length );
		if( cryptStatusError( status ) )
			errorString = "Fetch of first OU failed";
		}
	if( cryptStatusOK( status ) )
		{
		/* Should fail since there's no current attribute */
		status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
									CRYPT_CURSOR_NEXT );
		if( cryptStatusOK( status ) )
			{
			errorString = "CURSOR_NEXT succeeded when no attribute selected";
			status = -1;
			}
		else
			status = CRYPT_OK;
		}
	if( cryptStatusOK( status ) )
		{
		/* Should fail since there's no attribute instance selected */
		status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
									CRYPT_CURSOR_NEXT );
		if( cryptStatusOK( status ) )
			{
			errorString = "CURSOR_NEXT succeeded when no attribute instance selected";
			status = -1;
			}
		else
			status = CRYPT_OK;
		}
	if( cryptStatusError( status ) )
		{
		printf( "%s, line %d.\n", errorString, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttributeString( cryptCert, 
									  CRYPT_CERTINFO_ORGANISATIONALUNITNAME,
									  buffer, &length );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
									CRYPT_CERTINFO_ORGANISATIONALUNITNAME );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
									&value );
		if( cryptStatusError( status ) || \
			value != CRYPT_CERTINFO_ORGANISATIONALUNITNAME )
			{
			errorString = "Current instance != OU after OU was selected";
			status = -1;
			}
		}
	if( cryptStatusOK( status ) )
		{
		/* Should fail since there's no current attribute */
		status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
									CRYPT_CURSOR_NEXT );
		if( cryptStatusOK( status ) )
			{
			errorString = "CURSOR_NEXT succeeded when no attribute selected";
			status = -1;
			}
		else
			status = CRYPT_OK;
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
									CRYPT_CURSOR_NEXT );
		if( cryptStatusError( status ) )
			errorString = "Move to second OU failed";
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert, 
										  CRYPT_CERTINFO_ORGANISATIONALUNITNAME,
										  buffer, &length );
		if( cryptStatusError( status ) )
			errorString = "Fetch of second OU failed";
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
									CRYPT_CURSOR_LAST );
		if( cryptStatusError( status ) )
			errorString = "Move to last (third) OU failed";
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert, 
										  CRYPT_CERTINFO_ORGANISATIONALUNITNAME,
										  buffer, &length );
		if( cryptStatusError( status ) )
			errorString = "Fetch of third OU failed";
		}
	if( cryptStatusError( status ) )
		{
		printf( "%s, line %d.\n", errorString, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	fputs( "Certificate attribute handling succeeded.\n\n", outputStream );
#else
	fputs( "Skipping certificate attribute handling test because support "
		   "for the\nrequired custom DN creation has been disabled via the "
		   "cryptlib config\noptions.\n\n", outputStream );
#endif /* USE_CERT_DNSTRING */
	return( TRUE );
	}

#ifdef USE_CERT_OBSOLETE

static const CERT_DATA setCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers and Temple of SET" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "SET Commerce Division" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Cousin Bob" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* Add the SET extensions */
	{ CRYPT_CERTINFO_SET_CERTIFICATETYPE, IS_NUMERIC, CRYPT_SET_CERTTYPE_RCA },
	{ CRYPT_CERTINFO_SET_CERTCARDREQUIRED, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT, IS_STRING, 20, 
	  TEXT( "12345678900987654321" ) },
	{ CRYPT_CERTINFO_SET_MERID, IS_STRING, 0, TEXT( "Wetaburger Vendor" ) },
	{ CRYPT_CERTINFO_SET_MERACQUIRERBIN, IS_STRING, 0, TEXT( "123456" ) },
	{ CRYPT_CERTINFO_SET_MERCHANTLANGUAGE, IS_STRING, 0, TEXT( "English" ) },
	{ CRYPT_CERTINFO_SET_MERCHANTNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers and SET Merchant" ) },
	{ CRYPT_CERTINFO_SET_MERCHANTCITY, IS_STRING, 0, TEXT( "Eketahuna" ) },
	{ CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME, IS_STRING, 0, 
	  TEXT( "New Zealand" ) },
	{ CRYPT_CERTINFO_SET_MERCOUNTRY, IS_NUMERIC, 554 },		/* ISO 3166 */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};
#endif /* USE_CERT_DNSTRING */

int testSETCert( void )
	{
#ifdef USE_CERT_OBSOLETE
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	fputs( "Testing SET certificate creation/export...\n", outputStream );

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, setCertData, __LINE__ ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the certificate */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( "cert_set", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	fputs( "SET certificate creation succeeded.\n\n", outputStream );
#else
	fputs( "Skipping SET certificate creation/export test because support "
		   "for this\ncertificate type has been disabled via the cryptlib "
		   "config options.\n\n", outputStream );
#endif /* USE_CERT_OBSOLETE */
	return( TRUE );
	}

static const CERT_DATA attributeCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, 
	  TEXT( "NI" ) },		/* Ni! Ni! Ni! */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers and Attributes" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Attribute Management" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's Mum" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testAttributeCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptAuthorityKey;
	int certificateLength, status;

	fputs( "Testing attribute certificate creation/export...\n", 
		   outputStream );

	/* Get the authority's private key */
	status = getCAPrivateKey( &cryptAuthorityKey, FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Authority private key read failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_ATTRIBUTE_CERT );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components.  We don't add any attributes because 
	   these hadn't been defined yet (at least not as of the JTC1 SC21/ITU-T 
	   Q.17/7 draft of July 1997) */
	if( !addCertFields( cryptCert, attributeCertData, __LINE__ ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, cryptAuthorityKey );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the certificate */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate is %d bytes long.\n", 
			 certificateLength );
	debugDump( "cert_attribute", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptAuthorityKey );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyContext( cryptAuthorityKey );
	fputs( "Attribute certificate creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Test certification request code.  These create a basic certificate 
   request, a more complex certificate request with all extensions encoded 
   as attributes of an extensionReq, and a request with a separate PKCS #9
   attribute alongside the other attributes in the extensionReq */

static const CERT_DATA certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "PT" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA complexCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, 
	  TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },

	/* TLS server and client authentication */
	{ CRYPT_CERTINFO_EXTKEY_SERVERAUTH, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_EXTKEY_CLIENTAUTH, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA certRequestAttrib1Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "PT" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Subject altName encoded as an extensionReq */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, 
	  TEXT( "http://www.wetas-r-us.com" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA certRequestAttrib2Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "PT" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* PKCS #9 attribute that isn't encoded as an extensionReq */
	{ CRYPT_CERTINFO_CHALLENGEPASSWORD, IS_STRING, 0, TEXT( "password" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA certRequestAttrib3Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "PT" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Subject altName encoded as an extensionReq */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, 
	  TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },

	/* PKCS #9 attribute that isn't encoded as an extensionReq */
	{ CRYPT_CERTINFO_CHALLENGEPASSWORD, IS_STRING, 0, TEXT( "password" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static int createRequest( void *certificateData, 
						  const int certificateDataMaxSize, 
						  int *certificateDataSize, 
						  const BOOLEAN isCRMF,
						  const char *description, 
						  const CERT_DATA *certInfo,
						  const CRYPT_CONTEXT pubKeyContext,
						  const CRYPT_CONTEXT privKeyContext,
						  const char *fileName )
	{
	CRYPT_CERTIFICATE cryptCert;
	int dummy, status;

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  isCRMF ? CRYPT_CERTTYPE_REQUEST_CERT : \
									   CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptCert, certInfo, __LINE__ ) )
		return( FALSE );

	/* Sign the certification request and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptSignCert()", status,
							  __LINE__ ) );
		}
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed we don't need to pass in
	   a signature check key (but see further down for checks using a key).
	   Note that at this point there's no public-key object associated with 
	   the request since it's a freshly-created object that's implicitly
	   signed, so the check merely checks the details on a known-OK object */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Export the certificate */
	status = cryptExportCert( certificateData, certificateDataMaxSize,  
							  certificateDataSize, CRYPT_CERTFORMAT_CERTIFICATE, 
							  cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported %s is %d bytes long.\n", description, 
			 *certificateDataSize );
	debugDump( fileName, certBuffer, *certificateDataSize );

	/* Make sure that an export in an illogical format is disallowed */
	status = cryptExportCert( NULL, 0, &dummy, CRYPT_CERTFORMAT_CERTCHAIN, 
							  cryptCert );
	if( cryptStatusError( status ) )
		{
		status = cryptExportCert( NULL, 0, &dummy, 
								  CRYPT_CERTFORMAT_TEXT_CERTCHAIN, 
								  cryptCert );
		}
	if( cryptStatusError( status ) )
		{
		status = cryptExportCert( NULL, 0, &dummy, 
								  CRYPT_CERTFORMAT_XML_CERTCHAIN, 
								  cryptCert );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "Attempt to export certificate request in illogical format "
				"succeeded when it\n  should have failed, line %d.\n", 
				__LINE__ );
		return( FALSE );
		}

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int checkRequest( const void *certificateData, 
						 const int certificateDataSize, 
						 const CRYPT_CONTEXT pubKeyContext )
	{
	CRYPT_CERTIFICATE cryptCert;
	int status;

	/* Make sure that we can read what we created */
	status = cryptImportCert( certificateData, certificateDataSize, 
							  CRYPT_UNUSED, &cryptCert );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Check the signature on the request.  We do this twice, once with the
	   checking object given as CRYPT_UNUSED since it's a self-signed 
	   object, the second time with the checking object explicitly 
	   specified.  Since the request has been imported rather than being
	   a fresly-created known-good object, there's a public-key context
	   associated with it that can verify the signature.  In the case of the
	   explicitly-given public key object, this is checked against the public
	   key associated with the request */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		status = cryptCheckCert( cryptCert, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCert, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	cryptDestroyCert( cryptCert );

	return( TRUE );
	}

static int createCertRequest( const char *description, 
							  const CRYPT_ALGO_TYPE cryptAlgo,
							  const CERT_DATA *certInfo,
							  const char *fileName )
	{
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int certificateLength, status;

	fprintf( outputStream, "Testing %s creation/export...\n", description );

	/* Create the public/private key contexts */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, 
								  &privKeyContext ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_DSA:
			status = loadDSAContexts( CRYPT_UNUSED, &pubKeyContext, 
									  &privKeyContext );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				return( exitUnsupportedAlgo( CRYPT_ALGO_DSA, 
						"DSA signing" ) );
				}
			if( !status )
				return( FALSE );
			break;

		case CRYPT_ALGO_ECDSA:
			status = loadECDSAContexts( CRYPT_UNUSED, &pubKeyContext, 
										&privKeyContext );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				return( exitUnsupportedAlgo( CRYPT_ALGO_ECDSA, 
						"ECDSA signing" ) );
				}
			if( !status )
				return( FALSE );
			break;

		default:
			return( FALSE );
		}

	/* Create the request and export it */
	if( !createRequest( certBuffer, BUFFER_SIZE, &certificateLength, 
						FALSE, description, certInfo, pubKeyContext, 
						privKeyContext, fileName ) )
		return( FALSE );

	/* Check that the request can be recovered from the request data */
	if( !checkRequest( certBuffer, certificateLength, pubKeyContext ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	fprintf( outputStream, "Creation of %s succeeded.\n\n", description );
	return( TRUE );
	}

int testCertRequest( void )
	{
	const CRYPT_ALGO_TYPE cryptAlgo = getDefaultPkcAlgo();
	char buffer[ 64 ];

	if( cryptAlgo == CRYPT_ALGO_NONE )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}
	sprintf( buffer, "%s certification request", algoName( cryptAlgo ) );
	if( !createCertRequest( buffer, cryptAlgo, certRequestData, 
							"certreq_default" ) )
		return( FALSE );
	if( cryptAlgo != CRYPT_ALGO_DSA && \
		cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_DSA, NULL ) ) && \
		!createCertRequest( "DSA certification request", CRYPT_ALGO_DSA,
							certRequestData, "certreq_alt1" ) )
		return( FALSE );
	if( cryptAlgo != CRYPT_ALGO_ECDSA && \
		cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) && \
		!createCertRequest( "ECDSA certification request", CRYPT_ALGO_ECDSA,
							certRequestData, "certreq_alt2" ) )
		return( FALSE );

	return( TRUE );
	}

int testComplexCertRequest( void )
	{
	return( createCertRequest( "complex certification request", 
							   getDefaultPkcAlgo(), complexCertRequestData,
							   "certreq_complex" ) );
	}

int testCertRequestAttrib( void )
	{
	if( !createCertRequest( "cert.request with non-encapsulated attributes", 
							getDefaultPkcAlgo(), certRequestAttrib1Data, 
							"certreq_attrib1" ) )
		return( FALSE );	/* extReq attribute */
	if( !createCertRequest( "cert.request with encapsulated attributes", 
							getDefaultPkcAlgo(), certRequestAttrib2Data, 
							"certreq_attrib2" ) )
		return( FALSE );	/* Non-extReq attribute */
	return( createCertRequest( "cert.request with both types of attributes", 
							   getDefaultPkcAlgo(), certRequestAttrib3Data, 
							   "certreq_attrib3" ) );
	}						/* Both types of attributes */

/* Test CRMF certification request code */

static int crmfRequest( const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int certificateLength, status;

	fprintf( outputStream, "Testing CRMF %s certification request "
			 "creation/export...\n", algoName( cryptAlgo ) );

	/* Create the en/decryption contexts */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_DSA:
			status = loadDSAContexts( CRYPT_UNUSED, &pubKeyContext, 
									  &privKeyContext );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				return( exitUnsupportedAlgo( CRYPT_ALGO_DSA, 
											 "DSA signing" ) );
				}
			if( !status )
				return( FALSE );
			break;

		case CRYPT_ALGO_ECDSA:
			if( !loadECDSAContexts( CRYPT_UNUSED, &pubKeyContext, 
									&privKeyContext ) )
				return( FALSE );
			break;

		default:
			if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, 
								  &privKeyContext ) )
				return( FALSE );
		}

	/* Create the request and export it */
	if( !createRequest( certBuffer, BUFFER_SIZE, &certificateLength, 
						TRUE, "certification request", certRequestData, 
						pubKeyContext, privKeyContext, 
						( cryptAlgo == CRYPT_ALGO_DSA ) ? "req_crmf_dsa" : \
						( cryptAlgo == CRYPT_ALGO_ECDSA ) ? "req_crmf_ecdsa" : \
															"req_crmf_rsa" ) )
		return( FALSE );

	/* Check that the request can be recovered from the request data */
	if( !checkRequest( certBuffer, certificateLength, pubKeyContext ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	fputs( "CRMF certification request creation succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

int testCRMFRequest( void )
	{
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RSA, NULL ) ) && \
		!crmfRequest( CRYPT_ALGO_RSA ) )
		return( FALSE );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_DSA, NULL ) ) && \
		!crmfRequest( CRYPT_ALGO_DSA ) )
		return( FALSE );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) && \
		!crmfRequest( CRYPT_ALGO_ECDSA ) )
		return( FALSE );
	return( TRUE );
	}

int testComplexCRMFRequest( void )
	{
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int certificateLength;

	fputs( "Testing complex CRMF certification request "
		   "creation/export...\n", outputStream );

	/* Create the public/private key contexts */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}

	/* Create the request and export it */
	if( !createRequest( certBuffer, BUFFER_SIZE, &certificateLength, 
						TRUE, "certification request", complexCertRequestData, 
						pubKeyContext, privKeyContext, "req_crmf_complex" ) )
		return( FALSE );

	/* Check that the request can be recovered from the request data */
	if( !checkRequest( certBuffer, certificateLength, pubKeyContext ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	fputs( "Complex CRMF certification request creation succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

/* Test CRL code.  This one represents a bit of a chicken-and-egg problem
   since we need a CA certificate to create the CRL, but we can't read this 
   until the private key file read has been tested, and that requires 
   testing of the certificate management.  At the moment we just assume that 
   private key file reads work for this test */

static int testCRLExt( const CRYPT_CONTEXT cryptCAKey,
					   const BOOLEAN hasEntries )
	{
	CRYPT_CERTIFICATE cryptCRL;
	int certificateLength, status;

	fprintf( outputStream, "Testing %sCRL creation/export...\n", 
			 hasEntries ? "" : "empty " );

	/* Create the CRL */
	status = cryptCreateCert( &cryptCRL, CRYPT_UNUSED, CRYPT_CERTTYPE_CRL );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add a certificate to revoke if requires.  In this case the CA is 
	   revoking its own key */
	if( hasEntries )
		{
		status = cryptSetAttribute( cryptCRL, CRYPT_CERTINFO_CERTIFICATE,
									cryptCAKey );
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( cryptCRL, "cryptSetAttribute()", status,
								  __LINE__ ) );
			}
		}

	/* Sign the CRL */
	status = cryptSignCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCRL, "cryptSignCert()", status,
							  __LINE__ ) );
		}

	/* Print information on what we've got */
	if( !printCertInfo( cryptCRL ) )
		return( FALSE );

	/* Check the signature.  Since we have the CA private key handy, we
	   use that to check the signature */
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCRL, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Export the CRL */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCRL );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCRL, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported CRL is %d bytes long.\n", 
			 certificateLength );
	debugDump( hasEntries ? "crl" : "crl_empty", certBuffer, 
			   certificateLength );

	/* Destroy the CRL */
	status = cryptDestroyCert( cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCRL );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCRL, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	if( hasEntries )
		{
		/* IF the CRL has entries, perform the check the other way round, 
		   using the CRL to check the certificate that signed it, which is
		   also what's being revoked in the CRL */
		status = cryptCheckCert( cryptCAKey, cryptCRL );
		if( status != CRYPT_ERROR_INVALID )
			{
			fprintf( outputStream, "Revoked certificate in CRL wasn't "
					 "reported as being revoked, line %d.\n", __LINE__ );
			return( FALSE );
			}
		}

	cryptDestroyCert( cryptCRL );

	fputs( "CRL creation succeeded.\n\n", outputStream );

	return( TRUE );
	}

static int checkCRL( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCRL;
	int status;

	/* Import the certificate and a CRL indicating that it's revoked and 
	   make sure that it's reported as revoked */
	status = importCertFile( &cryptCert, REV_CERT_FILE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Import of certificate to revoke failed, "
				 "status = %d.\n", status );
		return( FALSE );
		}
	status = importCertFile( &cryptCRL, REV_CRL_FILE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Import of CRL to check certificate failed, "
				 "status = %d.\n", status );
		cryptDestroyCert( cryptCert );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptCRL );
	if( cryptStatusError( status ) )
		{
		/* CRYPT_ERROR_INVALID means the certificate has been revoked, 
		   anything else is an error */
		if( status != CRYPT_ERROR_INVALID )
			{
			fprintf( outputStream, "CRL check failed, status = %d.\n", 
					 status );
			printErrorAttributeInfo( cryptCert );
			}
		}
	else
		fputs( "CRL check passed, should have failed.\n", outputStream ); 
	cryptDestroyCert( cryptCert );
	cryptDestroyCert( cryptCRL );

	return( ( status == CRYPT_ERROR_INVALID ) ? TRUE : FALSE );
	}

int testCRL( void )
	{
	CRYPT_CONTEXT cryptCAKey;
	int status;

	/* Get the CA's private key */
	status = getCAPrivateKey( &cryptCAKey, FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Test CRL creation, first an emptry CRL, then one with a revoked 
	   certificate */
	status = testCRLExt( cryptCAKey, FALSE );
	if( status == TRUE )
		status = testCRLExt( cryptCAKey, TRUE );
	cryptDestroyContext( cryptCAKey );
	if( status != TRUE )
		return( status );

	/* Finally, verify that a (third-party) revoked certificate is correctly 
	   reported as being revoked.  This has a serial number with the high
	   bit set, so a leading zero once encoded, which tests cryptlib's 
	   ability to compare an encoded vs. raw integer value */
	return( checkCRL() );
	}

/* Test complex CRL code */

static const CERT_DATA complexCRLData[] = {
	/* Next update time */
	{ CRYPT_CERTINFO_NEXTUPDATE, IS_TIME, 0, NULL, CERTTIME_DATETEST + ONE_YEAR_TIME },

	/* CRL number and delta CRL indicator */
#ifdef CONFIG_CUSTOM_1
	{ CRYPT_CERTINFO_CRLNUMBER, IS_STRING, 16, 
	  "\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x12\x34\x56\x78\x9A\xBC\xDE\xF0" },
	{ CRYPT_CERTINFO_DELTACRLINDICATOR, IS_STRING, 16, 
	  "\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x12\x34\x56\x78\x9A\xBC\xDE\xF1" },
#else
	{ CRYPT_CERTINFO_CRLNUMBER, IS_NUMERIC, 1 },
	{ CRYPT_CERTINFO_DELTACRLINDICATOR, IS_NUMERIC, 2 },
#endif /* CONFIG_CUSTOM_1 */

	/* Issuing distribution points */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_ISSUINGDIST_FULLNAME },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, 
	  TEXT( "http://www.wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testComplexCRL( void )
	{
	CRYPT_CERTIFICATE cryptCRL, cryptRevokeCert DUMMY_INIT;
	CRYPT_CONTEXT cryptCAKey;
	time_t revocationTime;
	int certificateLength, revocationReason DUMMY_INIT, complianceLevel;
	int dummy, status;

	fputs( "Testing complex CRL creation/export...\n", outputStream );

	/* To encode/decode some of the fields we have to set the compliance 
	   level to maximum */
	status = setComplianceLevelMax( &complianceLevel );
	if( !status )
		return( FALSE );

	/* Get the CA's private key */
	status = getCAPrivateKey( &cryptCAKey, FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Create the CRL */
	status = cryptCreateCert( &cryptCRL, CRYPT_UNUSED, CRYPT_CERTTYPE_CRL );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Add some CRL components with per-entry attributes.  In this case the
	   CA is revoking its own key because it was compromised (would you trust
	   this CRL?) and some keys from test certs */
	if( !addCertFields( cryptCRL, complexCRLData, __LINE__ ) )
		{
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCRL, CRYPT_CERTINFO_CERTIFICATE,
								cryptCAKey );
	if( cryptStatusOK( status ) )
		{
		/* The CA key was compromised */
		status = cryptSetAttribute( cryptCRL,
									CRYPT_CERTINFO_CRLREASON,
									CRYPT_CRLREASON_CACOMPROMISE );
		}
	if( cryptStatusOK( status ) )
		{
		status = importCertFromTemplate( &cryptRevokeCert,
										 CRLCERT_FILE_TEMPLATE, 1 );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCRL, CRYPT_CERTINFO_CERTIFICATE,
									cryptRevokeCert );
		cryptDestroyCert( cryptRevokeCert );
		}
	if( cryptStatusOK( status ) )
		{
		/* Hold certificate, call issuer for details */
		status = cryptSetAttribute( cryptCRL,
									CRYPT_CERTINFO_CRLREASON,
									CRYPT_CRLREASON_CERTIFICATEHOLD );
		if( cryptStatusOK( status ) )
			{
#ifdef USE_CERTLEVEL_PKIX_FULL
			status = cryptSetAttribute( cryptCRL,
										CRYPT_CERTINFO_HOLDINSTRUCTIONCODE,
										CRYPT_HOLDINSTRUCTION_CALLISSUER );
#else
			status = cryptSetAttribute( cryptCRL, 
										CRYPT_CERTINFO_HOLDINSTRUCTIONCODE, 
										CRYPT_HOLDINSTRUCTION_CALLISSUER );
			if( status != CRYPT_ERROR_PARAM2 )
				{
				printf( "Addition of disabled attribute %d wasn't "
						"detected, line %d.\n", 
						CRYPT_CERTINFO_HOLDINSTRUCTIONCODE, __LINE__ );
				resetComplianceLevel( complianceLevel );
				return( FALSE );
				}
			status = CRYPT_OK;
#endif /* USE_CERTLEVEL_PKIX_FULL */
			}
		}
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCRL, "cryptSetAttribute(), certificate "
							  "#1", status, __LINE__ ) );
		}
	status = importCertFromTemplate( &cryptRevokeCert,
									 CRLCERT_FILE_TEMPLATE, 2 );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCRL, CRYPT_CERTINFO_CERTIFICATE,
									cryptRevokeCert );
		cryptDestroyCert( cryptRevokeCert );
		}
	if( cryptStatusOK( status ) )
		{
		const time_t invalidityDate = CERTTIME_DATETEST - ( ONE_YEAR_TIME / 12 );

		/* The private key was invalid some time ago.  We can't go back too 
		   far because the cryptlib kernel won't allow suspiciously old 
		   dates */
		status = cryptSetAttributeString( cryptCRL,
					CRYPT_CERTINFO_INVALIDITYDATE, &invalidityDate,
					sizeof( time_t ) );
		}
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCRL, "cryptSetAttribute(), certificate "
							  "#2", status, __LINE__ ) );
		}

	/* Sign the CRL */
	status = cryptSignCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCRL, "cryptSignCert()", status,
							  __LINE__ ) );
		}

	/* Print information on what we've got */
	if( !printCertInfo( cryptCRL ) )
		{
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Check the signature.  Since we have the CA private key handy, we
	   use that to check the signature */
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCRL, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Export the CRL */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCRL );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCRL, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported CRL is %d bytes long.\n", 
			 certificateLength );
	debugDump( "crl_complex", certBuffer, certificateLength );

	/* Destroy the CRL */
	status = cryptDestroyCert( cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCRL );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCRL, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Check the newly-revoked CA key agains the CRL */
	status = cryptCheckCert( cryptCAKey, cryptCRL );
	if( status != CRYPT_ERROR_INVALID )
		{
		printf( "Revoked certificate wasn't reported as being revoked, "
				"line %d.\n", __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}
	status = cryptGetAttributeString( cryptCRL, CRYPT_CERTINFO_REVOCATIONDATE,
									  &revocationTime, &dummy );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( cryptCRL, CRYPT_CERTINFO_CRLREASON,
									&revocationReason );
		}
	if( cryptStatusError( status ) )
		{
		resetComplianceLevel( complianceLevel );
		return( extErrorExit( cryptCRL, "cryptGetAttribute()", status,
							  __LINE__ ) );
		}
	if( revocationReason != CRYPT_CRLREASON_CACOMPROMISE )
		{
		printf( "Revocation reason was %d, should have been %d, line %d.\n",
				revocationReason, CRYPT_CRLREASON_CACOMPROMISE, __LINE__ );
		resetComplianceLevel( complianceLevel );
		return( FALSE );
		}

	/* Clean up */
	resetComplianceLevel( complianceLevel );
	cryptDestroyCert( cryptCRL );
	cryptDestroyContext( cryptCAKey );
	fputs( "CRL creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Test revocation request code */

static const CERT_DATA revRequestData[] = {
	/* Revocation reason */
	{ CRYPT_CERTINFO_CRLREASON, IS_NUMERIC, CRYPT_CRLREASON_SUPERSEDED },

	/* Invalidity date */
	{ CRYPT_CERTINFO_INVALIDITYDATE, IS_TIME, 0, NULL, CERTTIME_DATETEST - ( ONE_YEAR_TIME / 12 ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testRevRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptRequest;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	fputs( "Testing revocation request creation/export...\n", outputStream );

	filenameFromTemplate( buffer, CERT_FILE_TEMPLATE, 1 );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate file for revocation request test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED, &cryptCert );
	if( cryptStatusError( status ) )
		{
		fputs( "Certificate import failed, skipping test of revocation "
			   "request...\n", outputStream );
		return( TRUE );
		}

	/* Create the certificate object and add the certificate details and
	   revocation info */
	status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_REQUEST_REVOCATION );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptRequest, CRYPT_CERTINFO_CERTIFICATE,
								cryptCert );
	cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptRequest, "cryptSetAttribute()", status,
							  __LINE__ ) );
		}
	if( !addCertFields( cryptRequest, revRequestData, __LINE__ ) )
		return( FALSE );

	/* Print information on what we've got */
	if( !printCertInfo( cryptRequest ) )
		return( FALSE );

#if 0	/* CMP doesn't currently allow revocation requests to be signed, so
		   it's treated like CMS attributes as a series of uninitialised
		   attributes */
	/* Export the certificate */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptRequest );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptRequest, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported revocation request is %d bytes "
			 "long.\n", certificateLength );
	debugDump( "req_rev", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptRequest );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
#endif /* 0 */
	cryptDestroyCert( cryptRequest );

	/* Clean up */
	fputs( "Revocation request creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Test certificate chain creation */

static const CERT_DATA certRequestNoDNData[] = {
	/* Identification information for an empty-DN certificate.  There's no 
	   DN, only a subject altName.  This type of identifier is only possible 
	   with a CA-signed certificate since it contains an empty DN */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, 
	  TEXT( "dave@wetas-r-us.com" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static int createChain( CRYPT_CERTIFICATE *cryptCertChain,
						const CRYPT_CONTEXT cryptCAKey,
						const BOOLEAN useEmptyDN, 
						const BOOLEAN createCAcert, 
						const BOOLEAN reportError )
	{
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	/* Create the certificate chain */
	status = cryptCreateCert( cryptCertChain, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create a simple certificate request to turn into the end-user 
	   certificate */
	if( !loadPkcContexts( &pubKeyContext, &privKeyContext ) )
		{
		fputs( "No PKC algorithm available for test.\n", outputStream );
		return( FALSE );
		}
	status = cryptSetAttribute( *cryptCertChain,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) )
		{
		if( !addCertFields( *cryptCertChain, useEmptyDN ? \
							certRequestNoDNData : certRequestData, 
							__LINE__ ) )
			return( FALSE );
		}
	if( cryptStatusOK( status ) && createCAcert )
		{
		status = cryptSetAttribute( *cryptCertChain,
									CRYPT_CERTINFO_CA, TRUE );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( *cryptCertChain,
										CRYPT_CERTINFO_KEYUSAGE, 
										CRYPT_KEYUSAGE_KEYCERTSIGN | \
										CRYPT_KEYUSAGE_CRLSIGN );
			}
		}
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Certificate creation failed with "
				 "status %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Sign the leaf of the certificate chain */
	status = cryptSignCert( *cryptCertChain, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		/* If we're trying to create a CA certificate then this should fail 
		   due to the parent CA having a path length constraint of zero */
		if( createCAcert )
			{
			int errorType, errorLocus DUMMY_INIT;

			status = cryptGetAttribute( *cryptCertChain, 
										CRYPT_ATTRIBUTE_ERRORTYPE,
										&errorType );
			if( cryptStatusOK( status ) )
				{
				status = cryptGetAttribute( *cryptCertChain, 
											CRYPT_ATTRIBUTE_ERRORLOCUS, 
											&errorLocus );
				}
			if( cryptStatusError( status ) || \
				errorType != CRYPT_ERRTYPE_ISSUERCONSTRAINT || \
				errorLocus != CRYPT_CERTINFO_PATHLENCONSTRAINT )
				{
				cryptDestroyCert( *cryptCertChain );
				fprintf( outputStream, "Path length constraint violation "
						 "didn't report error type %d, locus %d,\n  "
						 "line %d.\n", errorType, errorLocus, __LINE__ );
				return( FALSE );
				}
			}
		cryptDestroyCert( *cryptCertChain );
		if( !reportError )
			{
			/* This is a text that's expected to fail, return a special-case 
			   error code */
			return( -1 );
			}
		return( extErrorExit( *cryptCertChain, "cryptSignCert()", status,
							  __LINE__ ) );
		}

	return( TRUE );
	}

int testCertChain( void )
	{
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey;
	int certificateLength, complianceLevel, value, status;

	fputs( "Testing certificate chain creation/export...\n", outputStream );

	/* Get the CA's private key */
	status = getCAPrivateKey( &cryptCAKey, FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create a new certificate chain */
	status = createChain( &cryptCertChain, cryptCAKey, FALSE, FALSE, TRUE );
	if( status != TRUE )
		return( FALSE );

	/* Check the signature.  Since the chain counts as self-signed, we don't
	   have to supply a sig.check key.  Since the DIY CA certificate isn't 
	   trusted we have to force cryptlib to treat it as explicitly trusted 
	   when we try to verify the chain */
	status = setRootTrust( cryptCertChain, &value, 1 );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertChain, "Setting certificate chain "
							  "trusted", status, __LINE__ ) );
		}
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	setRootTrust( cryptCertChain, NULL, value );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertChain, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Try the other way of verifying the chain, by making the signing key
	   implicitly trusted */
	status = cryptSetAttribute( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
								TRUE );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertChain, "Setting chain signing key "
							  "trusted", status, __LINE__ ) );
		}
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	cryptSetAttribute( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, FALSE );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertChain, "cryptCheckCert()", status,
							  __LINE__ ) );
		}

	/* Finally, make sure that the non-trusted chain doesn't verify */
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		printf( "Certificate chain verified OK even though it wasn't "
				"trusted, line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Export the certificate chain */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTCHAIN, cryptCertChain );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertChain, "cryptExportCert()", status,
							  __LINE__ ) );
		}
	fprintf( outputStream, "Exported certificate chain is %d bytes long.\n", 
			 certificateLength );
	debugDump( "cert_chain", certBuffer, certificateLength );

	/* Export the chain in the various text formats to make sure that each
	   one works correctly */
	if( !checkExportCert( cryptCertChain, TRUE, 
						  CRYPT_CERTFORMAT_TEXT_CERTIFICATE,
						  "CRYPT_CERTFORMAT_TEXT_CERTIFICATE" ) )
		return( FALSE );
	if( !checkExportCert( cryptCertChain, TRUE, 
						  CRYPT_CERTFORMAT_TEXT_CERTCHAIN,
						  "CRYPT_CERTFORMAT_TEXT_CERTCHAIN" ) )
		return( FALSE );
	if( !checkExportCert( cryptCertChain, TRUE, 
						  CRYPT_CERTFORMAT_XML_CERTIFICATE,
						  "CRYPT_CERTFORMAT_XML_CERTIFICATE" ) )
		return( FALSE );
	if( !checkExportCert( cryptCertChain, TRUE, 
						  CRYPT_CERTFORMAT_XML_CERTCHAIN,
						  "CRYPT_CERTFORMAT_XML_CERTCHAIN" ) )
		return( FALSE );

	/* Destroy the certificate chain */
	status = cryptDestroyCert( cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCertChain );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	fprintf( outputStream, "Checking signatures... " );
	status = setRootTrust( cryptCertChain, &value, 1 );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertChain, "Setting certificate chain "
							  "trusted", status, __LINE__ ) );
		}
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	setRootTrust( cryptCertChain, NULL, value );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptCertChain, "cryptCheckCert()", status,
							  __LINE__ ) );
		}
	fputs( "signatures verified.\n", outputStream );

	/* Display info on each certificate in the chain */
	if( !printCertChainInfo( cryptCertChain ) )
		return( FALSE );

	/* Create a second certificate chain with a null DN.  For this to 
	   succeed we have to set the compliance level to 
	   CRYPT_COMPLIANCELEVEL_PKIX_FULL */
	cryptDestroyCert( cryptCertChain );
	status = createChain( &cryptCertChain, cryptCAKey, TRUE, FALSE, FALSE );
	if( status != -1 )
		{
		fprintf( outputStream, "Attempt to create certificate with null "
				 "DN %s, line %d.\n",
				 ( status == FALSE ) ? \
					"failed" : "succeeded when it should have failed",
				 __LINE__ );
		return( FALSE );
		}
	status = setComplianceLevelMax( &complianceLevel );
	if( !status )
		return( FALSE );
	if( status != CRYPT_ERROR_NOTAVAIL )
		{
		status = createChain( &cryptCertChain, cryptCAKey, TRUE, FALSE, TRUE );
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   value );
		if( status != TRUE )
			{
			puts( "  (This may be because the internal compliance-level "
				  "handling is wrong)." );
			resetComplianceLevel( complianceLevel );
			return( FALSE );
			}
		status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
								  CRYPT_CERTFORMAT_CERTCHAIN, cryptCertChain );
		cryptDestroyCert( cryptCertChain );
		if( cryptStatusError( status ) )
			{
			resetComplianceLevel( complianceLevel );
			return( extErrorExit( cryptCertChain, "cryptExportCert()", 
								  status, __LINE__ ) );
			}
		debugDump( "cert_chain_nulldn", certBuffer, certificateLength );
		status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
								  &cryptCertChain );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptImportCert() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			resetComplianceLevel( complianceLevel );
			return( FALSE );
			}
		}

	/* Clean up */
	resetComplianceLevel( complianceLevel );
	cryptDestroyCert( cryptCertChain );
	cryptDestroyContext( cryptCAKey );
	fputs( "Certificate chain creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Test CA certificate constraints */

int testCAConstraints( void )
	{
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey;
	int value, status;

	fputs( "Testing CA constraint enforcement...\n", outputStream );

	/* Get the (intermediate) CA's private key and make sure that the path 
	   length constraint is zero.  This should be inherited from the parent 
	   (root) CA, which has a path length constraint of 1 */
	status = getCAPrivateKey( &cryptCAKey, TRUE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( cryptCAKey, CRYPT_CERTINFO_PATHLENCONSTRAINT,
								&value );
	if( cryptStatusError( status ) || value != 0 )
		{
		fprintf( outputStream, "CA path length != 0, line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Create a certificate chain containing a CA certificate.  This should 
	   fail due to the path length being exceeded */
	status = createChain( &cryptCertChain, cryptCAKey, FALSE, TRUE, FALSE );
	if( status != -1 )
		{
		fprintf( outputStream, "CA cert creation with path length 0 "
				 "succeeded, should have failed, line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Perform the same operation with an EE certificate.  This should 
	   succeed */
	status = createChain( &cryptCertChain, cryptCAKey, FALSE, FALSE, TRUE );
	if( status != TRUE )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCertChain );
	cryptDestroyContext( cryptCAKey );
	fputs( "CA constraint enforcement test succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Test CMS attribute code.  This doesn't actually test much since this
   object type is just a basic data container used for the extended signing
   functions */

static const CERT_DATA cmsAttributeData[] = {
	/* Content type and an S/MIME capability */
	{ CRYPT_CERTINFO_CMS_CONTENTTYPE, IS_NUMERIC, CRYPT_CONTENT_SIGNEDDATA },
	{ CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testCMSAttributes( void )
	{
	CRYPT_CERTIFICATE cryptAttributes;
	int status;

	fputs( "Testing CMS attribute creation...\n", outputStream );

	/* Create the CMS attribute container */
	status = cryptCreateCert( &cryptAttributes, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add some CMS attribute components */
	if( !addCertFields( cryptAttributes, cmsAttributeData, __LINE__ ) )
		return( FALSE );

	/* Print information on what we've got */
	if( !printCertInfo( cryptAttributes ) )
		return( FALSE );

	/* Destroy the attributes.  We can't do much more than this at this
	   stage since the attributes are only used internally by other
	   functions */
	status = cryptDestroyCert( cryptAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	fputs( "CMS attribute creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Test RTCS request/response code.  This test routine itself doesn't
   actually test much since this object type is just a basic data container
   used for RTCS sessions, however the shared initRTCS() routine is used by
   the RTCS session code to test the rest of the functionality.
   
   initRTCS() is also called by the RTCS session code, which is why it's
   declared non-static */

int initRTCS( CRYPT_CERTIFICATE *cryptRTCSRequest, 
			  const CRYPT_CERTIFICATE cryptCert, 
			  const BOOLEAN multipleCerts )
	{
	CRYPT_CERTIFICATE cryptErrorObject;
	C_CHR rtcsURL[ 512 ];
	int count DUMMY_INIT, status;

	/* Select the RTCS responder location from the EE certificate and read 
	   the URL/FQDN value (this isn't used but is purely for display to the 
	   user) */
	status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_AUTHORITYINFO_RTCS );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert,
								CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
								rtcsURL, &count );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			status = cryptGetAttributeString( cryptCert,
								CRYPT_CERTINFO_DNSNAME, rtcsURL, &count );
			}
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			puts( "RTCS responder URL not present in certificate, server "
				  "name must be provided\n  externally." );
			}
		else
			{
			printf( "Attempt to read RTCS responder URL failed with error "
					"code %d, line %d.\n", status, __LINE__ );
			printErrorAttributeInfo( cryptCert );
			return( FALSE );
			}
		}
	else
		{
#ifdef UNICODE_STRINGS
		rtcsURL[ count / sizeof( wchar_t ) ] = TEXT( '\0' );
		fprintf( outputStream, "RTCS responder URL = %sS.\n", rtcsURL );
#else
		rtcsURL[ count ] = '\0';
		fprintf( outputStream, "RTCS responder URL = %s.\n", rtcsURL );
#endif /* UNICODE_STRINGS */
		}

	/* Create the RTCS request container */
	status = cryptCreateCert( cryptRTCSRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_RTCS_REQUEST );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptErrorObject = *cryptRTCSRequest;

	/* Add the request components */
	status = cryptSetAttribute( *cryptRTCSRequest,
								CRYPT_CERTINFO_CERTIFICATE, cryptCert );
	if( status == CRYPT_ERROR_PARAM3 )
		cryptErrorObject = cryptCert;
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptErrorObject, "cryptSetAttribute()",
							  status, __LINE__ ) );
		}

	/* If we're doing a query with multiple certs, add another certificate.  
	   To keep things simple and avoid having to stockpile a whole 
	   collection of certificates for each responder we just use a random 
	   certificate for which we expect an 'unknown' response */
	if( multipleCerts )
		{
		CRYPT_CERTIFICATE cryptSecondCert;

		status = importCertFromTemplate( &cryptSecondCert, 
										 CERT_FILE_TEMPLATE, 1 );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( *cryptRTCSRequest,
										CRYPT_CERTINFO_CERTIFICATE, 
										cryptSecondCert );
			if( status == CRYPT_ERROR_PARAM3 )
				cryptErrorObject = cryptSecondCert;
			}
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( cryptErrorObject, "cryptSetAttribute()",
								  status, __LINE__ ) );
			}
		cryptDestroyCert( cryptSecondCert );
		}

	return( TRUE );
	}

int testRTCSReqResp( void )
	{
	CRYPT_CERTIFICATE cryptRTCSRequest, cryptCert;
	int status;

	fputs( "Testing RTCS request creation...\n", outputStream );

	/* Import the EE certificate for the RTCS request */
	status = importCertFromTemplate( &cryptCert, RTCS_FILE_TEMPLATE, 
									 1 );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptImportCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the RTCS request using the certs and print information on what
	   we've got */
	if( !initRTCS( &cryptRTCSRequest, cryptCert, FALSE ) )
		return( FALSE );
	cryptDestroyCert( cryptCert );
	if( !printCertInfo( cryptRTCSRequest ) )
		return( FALSE );

	/* Destroy the request.  We can't do much more than this at this stage
	   since the request is only used internally by the RTCS session code */
	status = cryptDestroyCert( cryptRTCSRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	fputs( "RTCS request creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Test OCSP request/response code.  This test routine itself doesn't
   actually test much since this object type is just a basic data container
   used for OCSP sessions, however the shared initOCSP() routine is used by
   the OCSP session code to test the rest of the functionality */

int initOCSP( CRYPT_CERTIFICATE *cryptOCSPRequest, 
			  CRYPT_CERTIFICATE *cert1, CRYPT_CERTIFICATE *cert2,
			  const int number, const BOOLEAN ocspv2, 
			  const BOOLEAN revokedCert, const BOOLEAN multipleCerts,
			  const CRYPT_SIGNATURELEVEL_TYPE sigLevel,
			  const CRYPT_CONTEXT privKeyContext )
	{
	CRYPT_CERTIFICATE cryptOCSPEE = CRYPT_UNUSED, cryptOCSPEE2 = CRYPT_UNUSED;
	CRYPT_CERTIFICATE cryptOCSPCA DUMMY_INIT, cryptErrorObject;
	C_CHR ocspURL[ 512 ];
	int count DUMMY_INIT, status;

	assert( ( cert1 == NULL && cert2 == NULL ) || \
			( cert1 != NULL && cert2 != NULL ) );
	assert( !ocspv2 );

	/* Clear return values */
	if( cert1 != NULL )
		*cert1 = *cert2 = CRYPT_UNUSED;

	/* Import the OCSP CA (if required) and EE certs */
	if( !ocspv2 )
		{
		status = importCertFromTemplate( &cryptOCSPCA,
										 OCSP_CA_FILE_TEMPLATE, number );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "CA cryptImportCert() failed with "
					 "error code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	status = importCertFromTemplate( &cryptOCSPEE, revokedCert ? \
						OCSP_EEREV_FILE_TEMPLATE: OCSP_EEOK_FILE_TEMPLATE,
						number );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "EE cryptImportCert() failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Select the OCSP responder location from the EE certificate and read 
	   the URL/FQDN value (this isn't used but is purely for display to the 
	   user) */
	status = cryptSetAttribute( cryptOCSPEE, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_AUTHORITYINFO_OCSP );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptOCSPEE,
							CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
							ocspURL, &count );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			status = cryptGetAttributeString( cryptOCSPEE,
							CRYPT_CERTINFO_DNSNAME, ocspURL, &count );
			}
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			fputs( "OCSP responder URL not present in certificate, server "
				   "name must be provided\n  externally.\n", outputStream );
			}
		else
			{
			printf( "Attempt to read OCSP responder URL failed with error "
					"code %d, line %d.\n", status, __LINE__ );
			printErrorAttributeInfo( cryptOCSPEE );
			return( FALSE );
			}
		}
	else
		{
#ifdef UNICODE_STRINGS
		ocspURL[ count / sizeof( wchar_t ) ] = TEXT( '\0' );
		fprintf( outputStream, "OCSP responder URL = %S.\n", ocspURL );
#else
		ocspURL[ count ] = '\0';
		fprintf( outputStream, "OCSP responder URL = %s.\n", ocspURL );
#endif /* UNICODE_STRINGS */
		}

	/* Create the OCSP request container */
	status = cryptCreateCert( cryptOCSPRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_OCSP_REQUEST );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptErrorObject = *cryptOCSPRequest;

	/* Add the request components.  Note that if we're using v1 we have to
	   add the CA certificate first since it's needed to generate the 
	   request ID for the EE certificate */
	if( !ocspv2 )
		{
		status = cryptSetAttribute( *cryptOCSPRequest,
							CRYPT_CERTINFO_CACERTIFICATE, cryptOCSPCA );
		if( status == CRYPT_ERROR_PARAM3 )
			cryptErrorObject = cryptOCSPCA;
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( *cryptOCSPRequest,
									CRYPT_CERTINFO_CERTIFICATE, cryptOCSPEE );
		if( status == CRYPT_ERROR_PARAM3 )
			cryptErrorObject = cryptOCSPEE;
		}
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptErrorObject, "cryptSetAttribute()",
							  status, __LINE__ ) );
		}

	/* If we're doing a query with multiple certs, add another certificate.  
	   To keep things simple and avoid having to stockpile a whole 
	   collection of certificates for each responder we just use a random 
	   certificate for which we expect an 'unknown' response */
	if( multipleCerts )
		{
		status = importCertFromTemplate( &cryptOCSPEE2, CERT_FILE_TEMPLATE, 1 );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( *cryptOCSPRequest,
										CRYPT_CERTINFO_CERTIFICATE, cryptOCSPEE2 );
			if( status == CRYPT_ERROR_PARAM3 )
				cryptErrorObject = cryptOCSPEE2;
			}
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( *cryptOCSPRequest, "cryptSetAttribute()",
								  status, __LINE__ ) );
			}
		}

	/* If we have a signing key, create a signed request */
	if( privKeyContext != CRYPT_UNUSED )
		{
		status = cryptSetAttribute( *cryptOCSPRequest,
							CRYPT_CERTINFO_SIGNATURELEVEL, sigLevel );
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( *cryptOCSPRequest, "cryptSetAttribute()",
								  status, __LINE__ ) );
			}
		status = cryptSignCert( *cryptOCSPRequest, privKeyContext );
		if( status == CRYPT_ERROR_PARAM3 )
			cryptErrorObject = privKeyContext;
		if( cryptStatusError( status ) )
			{
			return( extErrorExit( cryptErrorObject, "cryptSignCert()",
								  status, __LINE__ ) );
			}
		}

	/* Clean up */
	if( !ocspv2 )
		cryptDestroyCert( cryptOCSPCA );
	if( cert1 == NULL )
		{
		cryptDestroyCert( cryptOCSPEE );
		if( cryptOCSPEE != CRYPT_UNUSED )
			cryptDestroyCert( cryptOCSPEE2 );
		}
	else
		{
		/* Return the certificates to the caller */
		*cert1 = cryptOCSPEE;
		*cert2 = cryptOCSPEE2;
		}

	return( TRUE );
	}

int testOCSPReqResp( void )
	{
	CRYPT_CERTIFICATE cryptOCSPRequest;
	CRYPT_CONTEXT cryptPrivateKey;
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int status;

	fputs( "Testing OCSP request creation...\n", outputStream );

	/* Create the OCSP request using the certs and print information on what
	   we've got */
	if( !initOCSP( &cryptOCSPRequest, NULL, NULL, 1, FALSE, FALSE, FALSE,
				   CRYPT_SIGNATURELEVEL_NONE, CRYPT_UNUSED ) )
		return( FALSE );
	fputs( "OCSPv1 succeeded.\n", outputStream );
	if( !printCertInfo( cryptOCSPRequest ) )
		return( FALSE );

	/* Destroy the request.  We can't do much more than this at this stage
	   since the request is only used internally by the OCSP session code */
	status = cryptDestroyCert( cryptOCSPRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

#if 0	/* OCSPv2 is still in too much of a state of flux to implement this */
	/* Try again with a v2 request.  This only differs from the v1 request in
	   the way the ID generation is handled so we don't bother printing any
	   information on the request */
	if( !initOCSP( &cryptOCSPRequest, NULL, NULL, 1, TRUE, FALSE, FALSE,
				   CRYPT_SIGNATURELEVEL_NONE, CRYPT_UNUSED ) )
		return( FALSE );
	fputs( "OCSPv2 succeeded.\n", outputStream );
	cryptDestroyCert( cryptOCSPRequest );
#endif

	/* Finally, create a signed request, first without and then with signing
	   certs */
	filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 1 );
	status = getPrivateKey( &cryptPrivateKey, filenameBuffer,
							USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "User private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !initOCSP( &cryptOCSPRequest, NULL, NULL, 1, FALSE, FALSE, FALSE,
				   CRYPT_SIGNATURELEVEL_NONE, cryptPrivateKey ) )
		return( FALSE );
	cryptDestroyCert( cryptOCSPRequest );
	fputs( "Signed OCSP request succeeded.\n", outputStream );
	if( !initOCSP( &cryptOCSPRequest, NULL, NULL, 1, FALSE, FALSE, FALSE,
				   CRYPT_SIGNATURELEVEL_SIGNERCERT, cryptPrivateKey ) )
		return( FALSE );
	cryptDestroyCert( cryptOCSPRequest );
	fputs( "Signed OCSP request with single signing certificate "
		   "succeeded.\n", outputStream );
	if( !initOCSP( &cryptOCSPRequest, NULL, NULL, 1, FALSE, FALSE, FALSE,
				   CRYPT_SIGNATURELEVEL_ALL, cryptPrivateKey ) )
		return( FALSE );
	cryptDestroyCert( cryptOCSPRequest );
	fputs( "Signed OCSP request with signing certificate chain "
		   "succeeded.\n", outputStream );
	cryptDestroyContext( cryptPrivateKey );

	fputs( "OCSP request creation succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Test PKI user information creation.  This doesn't actually test much
   since this object type is just a basic data container used to hold user
   information in a certificate store */

static const CERT_DATA pkiUserData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test PKI user" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA pkiUserExtData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, 
	  TEXT( "Test extended PKI user" ) },

	/* TLS server and client authentication */
	{ CRYPT_CERTINFO_EXTKEY_SERVERAUTH, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_EXTKEY_CLIENTAUTH, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA pkiUserCAData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test CA PKI user" ) },

	/* CA extensions */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA pkiUserRAData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, 
	  TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, 
	  TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test RA PKI user" ) },

	/* RA flag */
	{ CRYPT_CERTINFO_PKIUSER_RA, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

#define PKIUSER_NAME_INDEX	3	/* Index of name in CERT_DATA info */

static int testPKIUserCreate( const CERT_DATA *pkiUserInfo )
	{
	CRYPT_CERTIFICATE cryptPKIUser;
	int status;

	/* Create the PKI user object and add the user's identification
	   information */
	status = cryptCreateCert( &cryptPKIUser, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_PKIUSER );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptPKIUser, pkiUserInfo, __LINE__ ) )
		{
		printf( "Couldn't create PKI user info for user '%s', line %d.\n",
				( char * ) pkiUserInfo[ PKIUSER_NAME_INDEX ].stringValue, 
				__LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptPKIUser );

	return( TRUE );
	}

int testPKIUser( void )
	{
	fputs( "Testing PKI user information creation...\n", outputStream );
	if( !testPKIUserCreate( pkiUserData ) )
		return( FALSE );
	if( !testPKIUserCreate( pkiUserExtData ) )
		return( FALSE );
	if( !testPKIUserCreate( pkiUserCAData ) )
		return( FALSE );
	if( !testPKIUserCreate( pkiUserRAData ) )
		return( FALSE );
	fputs( "PKI user information creation succeeded.\n\n", outputStream );
	return( TRUE );
	}
