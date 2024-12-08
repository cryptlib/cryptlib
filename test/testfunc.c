<<<<<<< HEAD
/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2016					*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

/* Needed for feature-test macros */
#include "misc/config.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* Whether the database interface is working or not.  This is used when 
   opportunistically calling checkCreateDatabaseKeysets(), if it fails the
   first time then it's not going to start working on subsequent calls */

static int databaseNotWorking = FALSE;

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The tests that use databases and certificate stores require that the user 
   set up a suitable ODBC data source (at least when running under Windows), 
   to automate this process we try and create the data source if it isn't 
   present.
   
   This is complicated by the fact that the universal default MSJET database 
   driver doesn't have a 64-bit version so it's not possible to use it under 
   Vista/Windows 7 x64.  To work around this we fall back to the SQL Server
   driver, which replaces MSJET on x64 systems */

#if defined( _MSC_VER ) && defined( _WIN32 ) && !defined( _WIN32_WCE )

#define DATABASE_AUTOCONFIG

#include <odbcinst.h>

/* Default MS Access database */

#define DRIVER_NAME				TEXT( "Microsoft Access Driver (*.MDB)" )
#define DATABASE_ATTR_NAME		"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"DBQ="
#define DATABASE_ATTR_CREATE	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"CREATE_DB="
#define DATABASE_ATTR_TAIL		DATABASE_KEYSET_NAME_ASCII ".mdb#"
#define CERTSTORE_ATTR_NAME		"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"DBQ="
#define CERTSTORE_ATTR_CREATE	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"CREATE_DB="
#define CERTSTORE_ATTR_TAIL		CERTSTORE_KEYSET_NAME_ASCII ".mdb#"

/* Alternative 1, SQL Server */

#define DRIVER_NAME_ALT_1			TEXT( "SQL Server" )
#define DATABASE_ATTR_NAME_ALT_1	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Server=localhost#" \
									"Database="
#define DATABASE_ATTR_CREATE_ALT_1	""
#define DATABASE_ATTR_TAIL_ALT_1	DATABASE_KEYSET_NAME_ASCII "#"
#define CERTSTORE_ATTR_NAME_ALT_1	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Server=localhost#" \
									"Database="
#define CERTSTORE_ATTR_CREATE_ALT_1	""
#define CERTSTORE_ATTR_TAIL_ALT_1	CERTSTORE_KEYSET_NAME_ASCII "#"

/* Alternative 2, SQLite */

#define DRIVER_NAME_ALT_2			TEXT( "SQLite3 ODBC Driver" )
#define DATABASE_ATTR_NAME_ALT_2	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Database="
#define DATABASE_ATTR_CREATE_ALT_2	""
#define DATABASE_ATTR_TAIL_ALT_2	DATABASE_KEYSET_NAME_ASCII "#"
#define CERTSTORE_ATTR_NAME_ALT_2	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Database="
#define CERTSTORE_ATTR_CREATE_ALT_2	""
#define CERTSTORE_ATTR_TAIL_ALT_2	CERTSTORE_KEYSET_NAME_ASCII "#"

typedef enum { ODBC_SOURCE_ACCESS, ODBC_SOURCE_SQLSERVER, 
			   ODBC_SOURCE_SQLITE } ODBC_SOURCE_TYPE;

static void buildDBString( char *buffer, const char *attrName,
						   const char *attrTail, const char *path )
	{
	const int attrNameSize = strlen( attrName );
	const int attrTailSize = strlen( attrTail );
	const int pathSize = strlen( path );
	int dbStringLen, i;

	/* Build up the data-source control string */
	memcpy( buffer, attrName, attrNameSize + 1 );
	memcpy( buffer + attrNameSize, path, pathSize );
	if( attrTailSize > 0 )
		{
		memcpy( buffer + attrNameSize + pathSize, attrTail, 
				attrTailSize );
		}
	buffer[ attrNameSize + pathSize + attrTailSize ] = '\0';

	/* Finally, convert the strings to the weird embedded-null strings 
	   required by SQLConfigDataSource() */
	dbStringLen = strlen( buffer );
	for( i = 0; i < dbStringLen; i++ )
		{
		if( buffer[ i ] == '#' )
			buffer[ i ] = '\0';
		}
	}

static void reportSqlError( const ODBC_SOURCE_TYPE sourceType )
	{
	DWORD dwErrorCode;
	WORD errorMessageLen;
	char errorMessage[ 256 ];
		
	if( SQLInstallerError( 1, &dwErrorCode, errorMessage, 256, 
						   &errorMessageLen ) != SQL_NO_DATA )
		{
		fprintf( outputStream, "SQLConfigDataSource() returned error "
				 "code %d,\n  message '%s'.\n", dwErrorCode, errorMessage );
#if defined( _M_X64 )
		if( sourceType == ODBC_SOURCE_ACCESS )
			{
			fputs( "  (This is probably because there's no appropriate "
				   "64-bit driver present,\n  retrying the create with "
				   "an alternative driver...).\n", outputStream );
			}
#endif /* _M_X64 */
		}
	else
		{
		fputs( "SQLConfigDataSource() failed, no additional information "
			   "available.\n", outputStream );
		}
	}

static BOOLEAN createDatabase( const char *driverName,
							   const char *keysetName, 
							   const char *nameString, 
							   const char *createString, 
							   const char *trailerString,
							   const ODBC_SOURCE_TYPE sourceType )
	{
	char tempPathBuffer[ 512 ];
	char attrBuffer[ 1024 ];
#ifdef UNICODE_STRINGS
	wchar_t wcAttrBuffer[ 1024 ];
#endif /* UNICODE_STRINGS */
	int status;

	if( !GetTempPath( 512, tempPathBuffer ) )
		strcpy( tempPathBuffer, "C:\\Temp\\" );

	/* Try and create the DSN.  For the default Access driver his is a two-
	   step process, first we create the DSN and then the underlying file 
	   that contains the database.  For SQL Server it's simpler, the database
	   server already exists so all we have to do is create the database */
	switch( sourceType )
		{
		case ODBC_SOURCE_ACCESS:
			fprintf( outputStream, "Database keyset '%s' not found, "
					 "attempting to create data source\n  (ODBC - MS "
					 "Access)...\n", keysetName );
			break;

		case ODBC_SOURCE_SQLSERVER:
			fprintf( outputStream, "Attempting to create keyset '%s' using "
					 "alternative data source\n  (ODBC - SQL Server)...\n", 
					 keysetName );
			fputs( "  (Autoconfiguration of SQL Server data sources rather than "
				   "having them\n  configured manually by an administrator can "
				   "be erratic, if cryptlib\n  hangs while trying to access the "
				   "certificate database then you need to\n  configure the SQL "
				   "Server data source manually).\n", outputStream );
			break;

		case ODBC_SOURCE_SQLITE:
			fprintf( outputStream, "Database keyset '%s' not found, "
					 "attempting to create data source\n  (ODBC - "
					 "SQLite)...\n", keysetName );
			break;
		}
	buildDBString( attrBuffer, nameString, trailerString, tempPathBuffer );
#ifdef UNICODE_STRINGS
	mbstowcs( wcAttrBuffer, attrBuffer, strlen( attrBuffer ) + 1 );
	status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, driverName, 
								  wcAttrBuffer );
#else
	status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, driverName, 
								  attrBuffer );
#endif /* UNICODE_STRINGS */
	if( status != 1 )
		{
		reportSqlError( sourceType );
		return( FALSE );
		}
	if( sourceType != ODBC_SOURCE_ACCESS )
		{
		/* The server already exists and we're done */
		return( TRUE );
		}
	buildDBString( attrBuffer, createString, trailerString, tempPathBuffer );
#ifdef UNICODE_STRINGS
	mbstowcs( wcAttrBuffer, attrBuffer, strlen( attrBuffer ) + 1 );
	status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, driverName, 
								  wcAttrBuffer );
#else
	status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, driverName, 
								  attrBuffer );
#endif /* UNICODE_STRINGS */
	if( status != 1 )
		{
		reportSqlError( sourceType );
		return( FALSE );
		}

	return( TRUE );
	}

static void checkCreateDatabaseKeyset( void )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Check whether the test certificate database can be opened.  This can 
	   return a CRYPT_ARGERROR_PARAM3 as a normal condition since a freshly-
	   created database is empty and therefore can't be identified as a 
	   certificate database until data is written to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		return;
		}
	if( status != CRYPT_ERROR_OPEN )
		return;

	/* Create the database keyset, first MS Access */
	status = createDatabase( DRIVER_NAME, DATABASE_KEYSET_NAME_ASCII,
							 DATABASE_ATTR_NAME, DATABASE_ATTR_CREATE, 
							 DATABASE_ATTR_TAIL, ODBC_SOURCE_ACCESS );
	if( status == FALSE )
		{
		/* The create with the default MS Access driver failed, fall back to 
		   the SQL Server alternative */
		status = createDatabase( DRIVER_NAME_ALT_1, 
								 DATABASE_KEYSET_NAME_ASCII,
								 DATABASE_ATTR_NAME_ALT_1, 
								 DATABASE_ATTR_CREATE_ALT_1, 
								 DATABASE_ATTR_TAIL_ALT_1, 
								 ODBC_SOURCE_SQLSERVER );
		}
	if( status == FALSE )
		{
		/* The create failed as well, try SQLite */
		status = createDatabase( DRIVER_NAME_ALT_2, 
								 DATABASE_KEYSET_NAME_ASCII,
								 DATABASE_ATTR_NAME_ALT_2,
								 DATABASE_ATTR_CREATE_ALT_2,
								 DATABASE_ATTR_TAIL_ALT_2, 
								 ODBC_SOURCE_SQLITE );
		}
	fputs( ( status == TRUE ) ? "Data source creation succeeded.\n" : \
		   "Data source creation failed.\n\nYou need to create the "
		   "keyset data source as described in the cryptlib manual\n"
		   "for the database keyset tests to run.\n", outputStream );
	}

static void checkCreateDatabaseCertstore( void )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Check whether the test certificate store database can be opened.  
	   This can return a CRYPT_ARGERROR_PARAM3 as a normal condition since a 
	   freshly-created database is empty and therefore can't be identified 
	   as a certificate store until data is written to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE_STORE, 
							  CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		return;
		}
	if( status != CRYPT_ERROR_OPEN )
		return;

	/* Create the database keyset */
	status = createDatabase( DRIVER_NAME, CERTSTORE_KEYSET_NAME_ASCII,
							 CERTSTORE_ATTR_NAME, CERTSTORE_ATTR_CREATE, 
							 CERTSTORE_ATTR_TAIL, FALSE );
	if( status == FALSE )
		{
		/* The create with the default MS Access driver failed, fall back to
		   the SQL Server alternative */
		status = createDatabase( DRIVER_NAME_ALT_1, CERTSTORE_KEYSET_NAME_ASCII,
								 CERTSTORE_ATTR_NAME_ALT_1, 
								 CERTSTORE_ATTR_CREATE_ALT_1, 
								 CERTSTORE_ATTR_TAIL_ALT_1, TRUE );
		}
	if( status == FALSE )
		{
		/* The create failed as well, try SQLite */
		status = createDatabase( DRIVER_NAME_ALT_2, CERTSTORE_KEYSET_NAME_ASCII,
								 CERTSTORE_ATTR_NAME_ALT_2,
								 CERTSTORE_ATTR_CREATE_ALT_2,
								 CERTSTORE_ATTR_TAIL_ALT_2, TRUE );
		}
	fputs( ( status == TRUE ) ? "Data source creation succeeded.\n" : \
		   "Data source creation failed.\n\nYou need to create the "
		   "certificate store data source as described in the\n"
		   "cryptlib manual for the certificate management tests to "
		   "run.\n", outputStream );
	}

void checkCreateDatabaseKeysets( void )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Create the databases */
	checkCreateDatabaseKeyset();
	checkCreateDatabaseCertstore();

	/* Create the keysets within the database */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
							  CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "Database keyset created within database "
				 "'%s'.\n", DATABASE_KEYSET_NAME );
		cryptKeysetClose( cryptKeyset );
		}
	else
		{
		/* The create failed, force a call to checkDatabaseKeysetAvailable()
		   which marks the database keysets as unavailable for testing 
		   purposes */
		( void ) checkDatabaseKeysetAvailable();
		databaseNotWorking = TRUE;
		if( status == CRYPT_ERROR_DUPLICATE )
			{
			fprintf( outputStream, "Database '%s' already contains a keyset, "
					 "this may lead to self-test\nerrors due to the presence "
					 "of certificates from previous test runs.\n",
					 DATABASE_KEYSET_NAME );
			}
		else
			{
			fprintf( outputStream, "Error %d creating keyset within '%s' "
					 "database.\n", status, DATABASE_KEYSET_NAME );
			}
		}
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
							  CRYPT_KEYSET_DATABASE_STORE, 
							  CERTSTORE_KEYSET_NAME, 
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "Certificate store keyset created within "
				 "database '%s'.\n", CERTSTORE_KEYSET_NAME );
		cryptKeysetClose( cryptKeyset );
		}
	else
		{
		/* The create failed, force a call to checkDatabaseKeysetAvailable()
		   which marks the database keysets as unavailable for testing 
		   purposes */
		( void ) checkDatabaseKeysetAvailable();
		databaseNotWorking = TRUE;
		if( status == CRYPT_ERROR_DUPLICATE )
			{
			fprintf( outputStream, "Database '%s' already contains a "
					 "certificate store, this may lead to\nself-test errors "
					 "due to the presence of certificates from previous "
					 "test\nruns.\n", CERTSTORE_KEYSET_NAME );
			}
		else
			{
			fprintf( outputStream, "Error %d creating keyset within '%s' "
					 "database.\n", status, CERTSTORE_KEYSET_NAME );
			}
		}
	fprintf( outputStream, "\n" );
	}
#endif /* Win32 with VC++ */

/****************************************************************************
*																			*
*							Test Low-level Functions						*
*																			*
****************************************************************************/

#ifdef TEST_SELFTEST

/* Test the cryptlib self-test routines */

BOOLEAN testSelfTest( void )
	{
	int value, status;

	/* Perform the self-test.  First we write the value to true to force a
	   self-test, then we read it back to see whether it succeeded */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK, 
								TRUE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Attempt to perform cryptlib algorithm "
				 "self-test failed with error code %d, line %d.\n", status, 
				 __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK, 
								&value );
	if( cryptStatusError( status ) || value != TRUE )
		{
		/* Unfortunately all that we can report at this point is that the
		   self-test failed, we can't try each algorithm individually
		   because the self-test has disabled the failed one(s) */
		fprintf( outputStream, "cryptlib algorithm self-test failed, line "
				 "%d.\n", __LINE__ );
		return( FALSE );
		}
	fputs( "cryptlib algorithm self-test succeeded.\n\n", outputStream );

	return( TRUE );
	}
#else

BOOLEAN testSelfTest( void )
	{
	fputs( "Skipping test of self-test routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_SELFTEST */

#ifdef TEST_LOWLEVEL

/* Test the low-level encryption routines */

BOOLEAN testLowLevel( void )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	BOOLEAN algosEnabled;

	/* Test the conventional encryption routines */
	algosEnabled = FALSE;
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) )
			{
			if( !testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				return( FALSE );
			algosEnabled = TRUE;
			}
		}
	if( !algosEnabled )
		{
		fputs( "(No conventional-encryption algorithms enabled).\n",
			   outputStream );
		}

	/* Test the public-key encryption routines */
	algosEnabled = FALSE;
	for( cryptAlgo = CRYPT_ALGO_FIRST_PKC;
		 cryptAlgo <= CRYPT_ALGO_LAST_PKC; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) )
			{
			if( !testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				return( FALSE );
			algosEnabled = TRUE;
			}
		}
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RSA, NULL ) ) )
		{
		if( !testRSAMinimalKey() )
			return( FALSE );
		if( !testRSALargeKey() )
			return( FALSE );
		}
	if( !algosEnabled )
		fputs( "(No public-key algorithms enabled).\n", outputStream );

	/* Test the hash routines */
	algosEnabled = FALSE;
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) )
			{
			if( !testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				return( FALSE );
			algosEnabled = TRUE;
			}
		}
	if( !algosEnabled )
		fputs( "(No hash algorithms enabled).\n", outputStream );

	/* Test the MAC routines */
	algosEnabled = FALSE;
	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) )
			{
			if( !testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				return( FALSE );
			algosEnabled = TRUE;
			}
		}
	if( !algosEnabled )
		fputs( "(No MAC algorithms enabled).\n", outputStream );
	printf( "\n" );

	/* Test the handling of persistent objects */
	if( !testPersistentObjects() )
		return( FALSE );

	return( TRUE );
	}
#else

BOOLEAN testLowLevel( void )
	{
	fputs( "Skipping test of low-level encryption routines...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_LOWLEVEL */

/****************************************************************************
*																			*
*					Test Randomness, Config, and Device Functions			*
*																			*
****************************************************************************/

#ifdef TEST_RANDOM

/* Test the randomness-gathering routines */

BOOLEAN testRandom( void )
	{
	if( !testRandomRoutines() )
		{
		fputs( "The self-test will proceed without using a strong random "
			   "number source.\n\n", outputStream );

		/* Kludge the randomness routines so we can continue the self-tests */
		cryptAddRandom( "xyzzy", 5 );
		}

	return( TRUE );
	}
#else

BOOLEAN testRandom( void )
	{
	fputs( "Skipping test of randomness routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_RANDOM */

#ifdef TEST_CONFIG

/* The names of the configuration options we check for */

static struct {
	const CRYPT_ATTRIBUTE_TYPE option;	/* Option */
	const char *name;					/* Option name */
	const BOOLEAN isNumeric;			/* Whether it's a numeric option */
	} configOption[] = {
	{ CRYPT_OPTION_INFO_DESCRIPTION, "CRYPT_OPTION_INFO_DESCRIPTION", FALSE },
	{ CRYPT_OPTION_INFO_COPYRIGHT, "CRYPT_OPTION_INFO_COPYRIGHT", FALSE },
	{ CRYPT_OPTION_INFO_MAJORVERSION, "CRYPT_OPTION_INFO_MAJORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_MINORVERSION, "CRYPT_OPTION_INFO_MINORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_STEPPING, "CRYPT_OPTION_INFO_STEPPING", TRUE },

	{ CRYPT_OPTION_ENCR_ALGO, "CRYPT_OPTION_ENCR_ALGO", TRUE },
	{ CRYPT_OPTION_ENCR_HASH, "CRYPT_OPTION_ENCR_HASH", TRUE },
	{ CRYPT_OPTION_ENCR_MAC, "CRYPT_OPTION_ENCR_MAC", TRUE },
	{ CRYPT_OPTION_ENCR_HASHPARAM, "CRYPT_OPTION_ENCR_HASHPARAM", TRUE },

	{ CRYPT_OPTION_PKC_ALGO, "CRYPT_OPTION_PKC_ALGO", TRUE },
	{ CRYPT_OPTION_PKC_KEYSIZE, "CRYPT_OPTION_PKC_KEYSIZE", TRUE },
	{ CRYPT_OPTION_PKC_FORMAT, "CRYPT_OPTION_PKC_FORMAT", TRUE },

	{ CRYPT_OPTION_KEYING_ALGO, "CRYPT_OPTION_KEYING_ALGO", TRUE },
	{ CRYPT_OPTION_KEYING_ITERATIONS, "CRYPT_OPTION_KEYING_ITERATIONS", TRUE },

	{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, "CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES", TRUE },
	{ CRYPT_OPTION_CERT_VALIDITY, "CRYPT_OPTION_CERT_VALIDITY", TRUE },
	{ CRYPT_OPTION_CERT_UPDATEINTERVAL, "CRYPT_OPTION_CERT_UPDATEINTERVAL", TRUE },
	{ CRYPT_OPTION_CERT_COMPLIANCELEVEL, "CRYPT_OPTION_CERT_COMPLIANCELEVEL", TRUE },
	{ CRYPT_OPTION_CERT_REQUIREPOLICY, "CRYPT_OPTION_CERT_REQUIREPOLICY", TRUE },

	{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, "CRYPT_OPTION_CMS_DEFAULTATTRIBUTES", TRUE },

	{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, "CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE", TRUE },
	{ CRYPT_OPTION_KEYS_LDAP_FILTER, "CRYPT_OPTION_KEYS_LDAP_FILTER", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "CRYPT_OPTION_KEYS_LDAP_CACERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, "CRYPT_OPTION_KEYS_LDAP_CERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, "CRYPT_OPTION_KEYS_LDAP_CRLNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "CRYPT_OPTION_KEYS_LDAP_EMAILNAME", FALSE },

	{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, "CRYPT_OPTION_DEVICE_PKCS11_DVR01", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, "CRYPT_OPTION_DEVICE_PKCS11_DVR02", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, "CRYPT_OPTION_DEVICE_PKCS11_DVR03", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, "CRYPT_OPTION_DEVICE_PKCS11_DVR04", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, "CRYPT_OPTION_DEVICE_PKCS11_DVR05", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, "CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY", TRUE },

	{ CRYPT_OPTION_NET_SOCKS_SERVER, "CRYPT_OPTION_NET_SOCKS_SERVER", FALSE },
	{ CRYPT_OPTION_NET_SOCKS_USERNAME, "CRYPT_OPTION_NET_SOCKS_USERNAME", FALSE },
	{ CRYPT_OPTION_NET_HTTP_PROXY, "CRYPT_OPTION_NET_HTTP_PROXY", FALSE },
	{ CRYPT_OPTION_NET_CONNECTTIMEOUT, "CRYPT_OPTION_NET_CONNECTTIMEOUT", TRUE },
	{ CRYPT_OPTION_NET_READTIMEOUT, "CRYPT_OPTION_NET_READTIMEOUT", TRUE },
	{ CRYPT_OPTION_NET_WRITETIMEOUT, "CRYPT_OPTION_NET_WRITETIMEOUT", TRUE },

	{ CRYPT_OPTION_MISC_ASYNCINIT, "CRYPT_OPTION_MISC_ASYNCINIT", TRUE },
	{ CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, "CRYPT_OPTION_MISC_SIDECHANNELPROTECTION", TRUE },

	{ CRYPT_ATTRIBUTE_NONE, NULL, 0 }
	};

/* Test the configuration options routines */

BOOLEAN testConfig( void )
	{
	int i, value, status;

	/* Display each configuration option */
	for( i = 0; configOption[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		C_CHR buffer[ 256 ];
		int length;

		if( configOption[ i ].isNumeric )
			{
			status = cryptGetAttribute( CRYPT_UNUSED, 
										configOption[ i ].option, &value );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "%s appears to be "
						 "disabled/unavailable in this build.\n", 
						 configOption[ i ].name );
				continue;
				}
			fprintf( outputStream, "%s = %d.\n", configOption[ i ].name, 
					 value );
			continue;
			}
		status = cryptGetAttributeString( CRYPT_UNUSED, 
										  configOption[ i ].option,
										  buffer, &length );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "%s appears to be disabled/unavailable "
					 "in this build.\n", configOption[ i ].name );
			continue;
			}
		assert( length < 256 );
#ifdef UNICODE_STRINGS
		buffer[ length / sizeof( wchar_t ) ] = TEXT( '\0' );
		fprintf( outputStream, "%s = %S.\n", configOption[ i ].name, 
				 buffer );
#else
		buffer[ length ] = '\0';
		fprintf( outputStream, "%s = %s.\n", configOption[ i ].name, 
				 buffer );
#endif /* UNICODE_STRINGS */
		}
	fprintf( outputStream, "\n" );

	/* Make sure that setting options that affect other options works */
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
								&value );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
									CRYPT_ALGO_SHA1 );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASHPARAM, 
									&value );
		}
	if( cryptStatusOK( status ) && value != 20 )
		{
		fputs( "Setting CRYPT_OPTION_ENCR_HASH didn't change corresponding "
			   "CRYPT_OPTION_ENCR_HASHPARAM.\n", outputStream );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
									CRYPT_ALGO_SHA2 );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASHPARAM, 
									&value );
		}
	if( cryptStatusOK( status ) && value != 32 )
		{
		fputs( "Setting CRYPT_OPTION_ENCR_HASH didn't change corresponding "
			   "CRYPT_OPTION_ENCR_HASHPARAM.\n", outputStream );
		return( FALSE );
		}
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, value );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't set/reset CRYPT_OPTION_ENCR_HASH, "
				 "error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}
#else

BOOLEAN testConfig( void )
	{
	fputs( "Skipping display of config options...\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_CONFIG */

#ifdef TEST_DEVICE

/* Test the crypto device routines */

BOOLEAN testDevice( void )
	{
	int status;

	status = testDevices();
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Handling for crypto devices doesn't appear to be enabled "
			   "in this build of\ncryptlib.\n", outputStream );
		return( TRUE );
		}
	if( !status )
		return( FALSE );

	return( TRUE );
	}
#else

BOOLEAN testDevice( void )
	{
	fputs( "Skipping test of crypto device routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_DEVICE */

/****************************************************************************
*																			*
*							Test Mid/High-level Functions					*
*																			*
****************************************************************************/

#ifdef TEST_MIDLEVEL

/* Test the mid-level routines */

static const TEST_FUNCTION_INFO midLevelTestInfo[] = { 
	MK_TESTFUNC( testLargeBufferEncrypt ), 
	MK_TESTFUNC( testDeriveKey ), 
	MK_TESTFUNC( testConventionalExportImport ),
	MK_TESTFUNC( testMACExportImport ),
	MK_TESTFUNC_COND_ALGO( testKeyExportImport, CRYPT_ALGO_RSA ),
	MK_TESTFUNC( testSignData ),
	MK_TESTFUNC( testKeygen ),
	MK_TESTFUNC( testMidLevelDebugCheck ),
	{ NULL }
	};

BOOLEAN testMidLevel( void )
	{
	return( runTests( midLevelTestInfo ) );
	}
#else

BOOLEAN testMidLevel( void )
	{
	fputs( "Skipping test of mid-level encryption routines...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_MIDLEVEL */

#ifdef TEST_HIGHLEVEL

/* Test the high-level routines (these are similar to the mid-level routines 
   but rely on things like certificate management to work) */

static const TEST_FUNCTION_INFO highLevelTestInfo[] = { 
	MK_TESTFUNC_COND_ALGO( testKeyExportImportCMS, CRYPT_ALGO_RSA ),
	MK_TESTFUNC_COND_ALGO( testSignDataCMS, CRYPT_ALGO_RSA ),
	{ NULL }
	};

BOOLEAN testHighLevel( void )
	{
	return( runTests( highLevelTestInfo ) );
	}
#else

BOOLEAN testHighLevel( void )
	{
	fputs( "Skipping test of high-level routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_HIGHLEVEL */

/****************************************************************************
*																			*
*								Test Certificates							*
*																			*
****************************************************************************/

#ifdef TEST_CERT

/* Test the certificate routines */

static const TEST_FUNCTION_INFO certTestInfo[] = { 
	MK_TESTFUNC( testBasicCert ),
	MK_TESTFUNC( testCACert ),
	MK_TESTFUNC( testXyzzyCert ),
	MK_TESTFUNC( testTextStringCert ),
	MK_TESTFUNC( testComplexCert ),
	MK_TESTFUNC( testAltnameCert ),
	MK_TESTFUNC( testCertExtension ),
	MK_TESTFUNC( testCustomDNCert ),
	MK_TESTFUNC( testSETCert ),
	MK_TESTFUNC_COND_EMULATED( testAttributeCert ),
	MK_TESTFUNC( testCertRequest ),
	MK_TESTFUNC( testComplexCertRequest ),
	MK_TESTFUNC( testCertRequestAttrib ),
	MK_TESTFUNC( testCRMFRequest ),
	MK_TESTFUNC( testComplexCRMFRequest ),
	MK_TESTFUNC_COND_EMULATED( testCRL ),
	MK_TESTFUNC_COND_EMULATED( testComplexCRL ),
	MK_TESTFUNC( testRevRequest ),
	MK_TESTFUNC_COND_EMULATED( testCertChain ),
	MK_TESTFUNC_COND_EMULATED( testCAConstraints ),
	MK_TESTFUNC( testCMSAttributes ),
	MK_TESTFUNC_COND_EMULATED( testOCSPReqResp ),
	MK_TESTFUNC_COND_EMULATED( testCertImport ),
	MK_TESTFUNC_COND_EMULATED( testCertImportECC ),
	MK_TESTFUNC_COND_EMULATED( testCertReqImport ),
	MK_TESTFUNC_COND_EMULATED( testCRLImport ),
	MK_TESTFUNC_COND_EMULATED( testCertChainImport ),
	MK_TESTFUNC_COND_EMULATED( testOCSPImport ),
	MK_TESTFUNC_COND_EMULATED( testBase64CertImport ),
	MK_TESTFUNC_COND_EMULATED( testBase64CertChainImport ),
	MK_TESTFUNC_COND_EMULATED( testMiscImport ),
	MK_TESTFUNC_COND_EMULATED( testNonchainCert ),
	MK_TESTFUNC_COND_EMULATED( testCertComplianceLevel ),
	MK_TESTFUNC_COND_EMULATED( testCertChainHandling ),
	MK_TESTFUNC_COND_EMULATED( testPKCS1Padding ),
#if 0	/* This takes a while to run and produces a lot of output that won't
		   be meaningful to anyone other than cryptlib developers so it's
		   disabled by default */
	MK_TESTFUNC( testPathProcessing ),
#endif /* 0 */
	{ NULL }
	};

BOOLEAN testCert( void )
	{
	return( runTests( certTestInfo ) );
	}
#else

BOOLEAN testCert( void )
	{
	fputs( "Skipping test of certificate routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_CERT */

#ifdef TEST_CERTPROCESS

/* Test the certificate processing and CA certificate management 
   functionality.  A side-effect of the certificate-management 
   functionality is that the OCSP EE test certificates are written 
   to the test data directory */

static const TEST_FUNCTION_INFO certMgmtTestInfo[] = { 
	MK_TESTFUNC( testCertProcess ),
	{ NULL }
	};

BOOLEAN testCertMgmt( void )
	{
	int status;

	status = runTests( certMgmtTestInfo );
	if( !status )
		return( FALSE );
	status = testCertManagement();
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Handling for CA certificate stores doesn't appear to be "
			   "enabled in this\nbuild of cryptlib, skipping the test of "
			   "the certificate management routines.\n", outputStream );
		}
	else
		{
		if( !status )
			return( FALSE );
		}

	return( TRUE );
	}
#else

BOOLEAN testCertMgmt( void )
	{
	fputs( "Skipping test of certificate handling/CA management...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_CERTPROCESS */

/****************************************************************************
*																			*
*								Test Keysets								*
*																			*
****************************************************************************/

#ifdef TEST_KEYSET

/* Test the file and database keyset read routines */

static const TEST_FUNCTION_INFO keysetFileTestInfo[] = { 
	MK_TESTFUNC_COND_EMULATED( testGetPGPPublicKey ),
	MK_TESTFUNC_COND_EMULATED( testGetPGPPrivateKey ),
	/* None of the write tests beyond this point will succeed if a custom
	   crypto HAL is in use because pkcs15_set.c:setItemFunction() checks,
	   whether it's tied to crypto hardware and won't try and write it to 
	   a file if it is (this operation would fail since the key components
	   aren't available outside the HAL) */
	MK_TESTFUNC( testReadWriteFileKey ),
	MK_TESTFUNC_COND_ALGO( testReadWriteAltFileKey, CRYPT_ALGO_3DES ),
	MK_TESTFUNC_COND_ALGO( testReadWritePGPFileKey, CRYPT_ALGO_RSA ),
	MK_TESTFUNC( testImportFileKey ),
	MK_TESTFUNC( testReadFilePublicKey ),
	MK_TESTFUNC( testDeleteFileKey ),
	MK_TESTFUNC( testUpdateFileCert ),
	MK_TESTFUNC( testReadFileCert ),
	MK_TESTFUNC( testReadFileCertPrivkey ),
	MK_TESTFUNC( testWriteFileCertChain ),
	MK_TESTFUNC( testReadFileCertChain ),
	MK_TESTFUNC( testAddTrustedCert ),
#if 0	/* This changes the global config file and is disabled by default */
	MK_TESTFUNC( testAddGloballyTrustedCert ),
#endif /* 0 */
	MK_TESTFUNC( testWriteFileLongCertChain ),
	MK_TESTFUNC( testSingleStepFileCert ),
	MK_TESTFUNC( testSingleStepAltFileCert ),
	MK_TESTFUNC( testDoubleCertFile ),
	MK_TESTFUNC( testRenewedCertFile ),
	MK_TESTFUNC( testReadOldKey ),
	MK_TESTFUNC( testReadCorruptedKey ),
	MK_TESTFUNC_COND_EMULATED( testReadAltFileKey ),
	MK_TESTFUNC( testReadMiscFile ),
	{ NULL }
	};

BOOLEAN testKeysetFile( void )
	{
	return( runTests( keysetFileTestInfo ) );
	}

BOOLEAN testKeysetDatabase( void )
	{
	int status;

  #ifdef DATABASE_AUTOCONFIG
	checkCreateDatabaseKeysets();
  #endif /* DATABASE_AUTOCONFIG */
	if( !checkDatabaseKeysetAvailable() )
		{
		fputs( "Certificate database isn't available, skipping the test of "
			   "the certificate\ndatabase routines.\n\n", outputStream );
		}
	else
		{
		status = testWriteCert();
		if( !status )
			return( FALSE );
		if( status == CRYPT_ERROR_NOTAVAIL )
			{
			fputs( "Handling for certificate databases doesn't appear to be "
				   "enabled in this\nbuild of cryptlib, skipping the test "
				   "of the certificate database routines.\n\n", 
				   outputStream );
			}
		else
			{
			/* The write succeeded, try and read back what we've written */
			if( !testReadCert() )
				return( FALSE );
			if( !testKeysetQuery() )
				return( FALSE );
			}
		}

	/* For the following tests we may have read access but not write access,
	   so we test a read of known-present certs before trying a write -
	   unlike the local keysets we don't need to add a certificate before we 
	   can try reading it */
	status = testReadCertLDAP();
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Handling for LDAP certificate directories doesn't appear to "
			   "be enabled in\nthis build of cryptlib, skipping the test of "
			   "the certificate directory\nroutines.\n\n", outputStream );
		}
	else
		{
		/* LDAP access can fail if the directory doesn't use the standard
		   du jour, so we don't treat a failure as a fatal error */
		if( status )
			{
			/* LDAP writes are even worse than LDAP reads, so we don't
			   treat failures here as fatal either */
			( void ) testWriteCertLDAP();
			}
		}
	status = testReadCertURL();
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Handling for fetching certificates from web pages doesn't "
			   "appear to be\nenabled in this build of cryptlib, skipping "
			   "the test of the HTTP routines.\n\n", outputStream );
		}
	else
		{
		/* Being able to read a certificate from a web page is rather 
		   different from access to an HTTP certificate store so we don't 
		   treat an error here as fatal */
		if( status )
			( void ) testReadCertHTTP();
		}

	return( TRUE );
	}
#else

BOOLEAN testKeysetFile( void )
	{
	fputs( "Skipping test of file keyset read routines...\n\n", 
		   outputStream );
	return( TRUE );
	}

BOOLEAN testKeysetDatabase( void )
	{
	fputs( "Skipping test of database keyset read routines...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_KEYSET */

/****************************************************************************
*																			*
*								Test Enveloping								*
*																			*
****************************************************************************/

#ifdef TEST_ENVELOPE

/* Test the enveloping routines.  Define SLOW_TESTS to run the iterated 
   tests, which take quite awhile to run */

 #if defined( CRYPTLIB_TEST_BUILD ) 
  #pragma message( "Disabling slow iterated enveloping test." )
#else
  #define	SLOW_TESTS
#endif /* Slow tests enabled */

static const TEST_FUNCTION_INFO envelopeTestInfo[] = { 
	MK_TESTFUNC( testEnvelopeData ),
	MK_TESTFUNC( testEnvelopeDataLargeBuffer ),
#ifdef SLOW_TESTS
	MK_TESTFUNC( testEnvelopeDataVariable ),
	MK_TESTFUNC( testEnvelopeDataMultiple ),
#endif /* SLOW_TESTS */
	MK_TESTFUNC( testEnvelopeCompress ),
	MK_TESTFUNC_COND_ALGO( testPGPEnvelopeCompressedDataImport, CRYPT_ALGO_RSA ),
	MK_TESTFUNC( testEnvelopeSessionCrypt ),
	MK_TESTFUNC( testEnvelopeSessionCryptLargeBuffer ),
#ifdef SLOW_TESTS
	MK_TESTFUNC( testEnvelopeSessionCryptVariable ),
	MK_TESTFUNC( testEnvelopeSessionCryptMultiple ),
#endif /* SLOW_TESTS */
	MK_TESTFUNC( testEnvelopeCrypt ),
	MK_TESTFUNC( testEnvelopePasswordCrypt ),
	MK_TESTFUNC( testEnvelopePasswordCryptBoundary ),
	MK_TESTFUNC( testEnvelopePasswordCryptImport ),
	MK_TESTFUNC( testPGPEnvelopePasswordCryptImport ),
	MK_TESTFUNC( testEnvelopePKCCrypt ),
	MK_TESTFUNC( testEnvelopePKCCryptAlgo ),
	MK_TESTFUNC( testPGPEnvelopePKCCryptImport ),
#ifdef SLOW_TESTS
	MK_TESTFUNC( testEnvelopePKCIterated ),
#endif /* SLOW_TESTS */
	MK_TESTFUNC( testEnvelopeSign ),
	MK_TESTFUNC( testEnvelopeSignAlgos ),
	MK_TESTFUNC( testEnvelopeSignHashUpgrade ),
	MK_TESTFUNC( testEnvelopeSignOverflow ),
	MK_TESTFUNC( testEnvelopeSignIndef ),
#ifdef SLOW_TESTS
	MK_TESTFUNC( testEnvelopeSignIterated ),
#endif /* SLOW_TESTS */
	MK_TESTFUNC( testPGPEnvelopeSignedDataImport ),
	MK_TESTFUNC( testEnvelopeAuthenticate ),
	MK_TESTFUNC( testEnvelopeAuthEnc ),
	MK_TESTFUNC( testCMSEnvelopePKCCrypt ),
	MK_TESTFUNC( testCMSEnvelopePKCCryptDoubleCert ),
	MK_TESTFUNC( testCMSEnvelopePKCCryptImport ),
	MK_TESTFUNC( testCMSEnvelopeSign ),
	MK_TESTFUNC( testCMSEnvelopeDualSign ),
	MK_TESTFUNC( testCMSEnvelopeDetachedSig ),
	MK_TESTFUNC( testPGPEnvelopeDetachedSig ),
	MK_TESTFUNC( testCMSEnvelopeRefCount ),
	MK_TESTFUNC( testCMSEnvelopeSignedDataImport ),
	MK_TESTFUNC( testEnvelopeCMSDebugCheck ),
	MK_TESTFUNC( testEnvelopePGPDebugCheck ),
	{ NULL }
	};

BOOLEAN testEnveloping( void )
	{
	return( runTests( envelopeTestInfo ) );
	}
#else

BOOLEAN testEnveloping( void )
	{
	fputs( "Skipping test of enveloping routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_ENVELOPE */

/****************************************************************************
*																			*
*								Test Sessions								*
*																			*
****************************************************************************/

#ifdef TEST_SESSION

/* Test the session routines */

static const TEST_FUNCTION_INFO sessionTestInfo[] = { 
	MK_TESTFUNC( testSessionAttributes ),
	MK_TESTFUNC( testSessionSSH ),
	MK_TESTFUNC( testSessionSSHPubkeyAuth ),
	MK_TESTFUNC( testSessionSSHPortforward ),
	MK_TESTFUNC( testSessionSSHExec ),
	MK_TESTFUNC( testSessionSSL ),
	MK_TESTFUNC( testSessionSSLLocalSocket ),
	MK_TESTFUNC( testSessionTLS ),
	MK_TESTFUNC( testSessionTLSLocalSocket ),
	MK_TESTFUNC( testSessionTLS11 ),
	MK_TESTFUNC( testSessionTLS12 ),
#if 0	/* The MS test server used for the general TLS 1.2 tests requires 
		   fairly extensive custom configuration of client certs and the
		   ability to do rehandshakes due to the oddball way that SChannel
		   handles client auth so we disable this test until another server 
		   that does TLS 1.2 client auth less awkwardly appears */
	MK_TESTFUNC( testSessionTLS12ClientCert ),
#endif /* 0 */
	MK_TESTFUNC( testSessionTLS13 ),
	MK_TESTFUNC( testSessionTLSBadSSL ),
	MK_TESTFUNC( testSessionOCSP ),
	MK_TESTFUNC( testSessionTSP ),
	MK_TESTFUNC( testSessionEnvTSP ),
	MK_TESTFUNC( testSessionCMP ),
	{ NULL }
	};

BOOLEAN testSessions( void )
	{
	int status;

	status = testSessionUrlParse();
	if( !status )
		return( FALSE );
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Network access doesn't appear to be enabled in this build "
			   "of cryptlib,\nskipping the test of the secure session "
			   "routines.\n", outputStream );
		return( TRUE );
		}
	if( !checkNetworkAccess() )
		{
		fputs( "Couldn't perform a test connect to a well-known site "
			   "(Amazon.com) which\nindicates that external network access "
			   "isn't available.  Is this machine\nsituated behind a "
			   "firewall?\n", outputStream );
		return( FALSE );
		}
	return( runTests( sessionTestInfo ) );
	}
#else

BOOLEAN testSessions( void )
	{
	fputs( "Skipping test of session routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_SESSION */

#ifdef TEST_SESSION_LOOPBACK

/* Test loopback client/server sessions.  These require a threaded OS and 
   are aliased to no-ops on non-threaded systems.  In addition there can be 
   synchronisation problems between the two threads if the server is delayed 
   for some reason, resulting in the client waiting for a socket that isn't 
   opened yet.  This isn't easy to fix without a lot of explicit intra-
   thread synchronisation, if there's a problem it's easier to just re-run 
   the tests */

BOOLEAN testSessionsLoopback( void )
	{
  #ifdef DATABASE_AUTOCONFIG
	if( !databaseNotWorking )
		{
		/* The databaseOK flag is default-true in that, in the absence of
		   further evidence, we at least try and work with a database 
		   keyset, however if an earlier attempt to work with one has failed
		   then we don't try and create one again now */
		checkCreateDatabaseKeysets();	/* Needed for PKI tests */
		}
  #endif /* DATABASE_AUTOCONFIG */
	if( !testSessionSSHClientServer() )
		return( FALSE );
	if( !testSessionSSHClientServerDsaKey() )
		return( FALSE );
	if( !testSessionSSHClientServerEccKey() )
		return( FALSE );
	if( !testSessionSSHClientServerFingerprint() )
		return( FALSE );
	if( !testSessionSSHClientServerPubkeyAuth() )
		return( FALSE );
	if( !testSessionSSHClientServerPubkeyAuthWrongKey() )
		return( FALSE );
	if( !testSessionSSHClientServerPubkeyAuthWrongName() )
		return( FALSE );
	if( !testSessionSSHClientServerPubkeyAuthPassword() )
		return( FALSE );
	if( !testSessionSSHClientServerPreauth() )
		return( FALSE );
	if( !testSessionSSHClientServerPreauthMissing() )
		return( FALSE );
	if( !testSessionSSHClientServerPreauthWrong() )
		return( FALSE );
	if( !testSessionSSHClientServerPortForward() )
		return( FALSE );
	if( !testSessionSSHClientServerExec() )
		return( FALSE );
	if( !testSessionSSHClientServerMultichannel() )
		return( FALSE );
	if( !testSessionSSHClientServerDebugCheck() )
		return( FALSE );
	if( !testSessionSSLClientServer() )
		return( FALSE );
	if( !testSessionSSLClientCertClientServer() )
		return( FALSE );
	if( !testSessionTLSClientServer() )
		return( FALSE );
	if( !testSessionTLSSharedKeyClientServer() )
		return( FALSE );
	if( !testSessionTLSNoSharedKeyClientServer() )
		return( FALSE );
	if( !testSessionTLSBulkTransferClientServer() )
		return( FALSE );
	if( !testSessionTLSLocalServerSocketClientServer() )
		return( FALSE );
	if( !testSessionTLS11ClientServer() )
		return( FALSE );
	if( !testSessionTLS11ClientCertClientServer() )
		return( FALSE );
	if( !testSessionTLS12ClientServer() )
		return( FALSE );
	if( !testSessionTLS12ClientCertClientServer() )
		return( FALSE );
	if( !testSessionTLS12ClientCertManualClientServer() )
		return( FALSE );
	if( !testSessionTLS12WebSocketsClientServer() )
		return( FALSE );
	if( !testSessionTLSClientServerDebugCheck() )
		return( FALSE );
	if( !testSessionHTTPCertstoreClientServer() )
		return( FALSE );
	if( !testSessionRTCSClientServer() )
		return( FALSE );
	if( !testSessionOCSPClientServer() )
		return( FALSE );
	if( !testSessionOCSPMulticertClientServer() )
		return( FALSE );
	if( !testSessionTSPClientServer() )
		return( FALSE );
	if( !testSessionTSPClientServerPersistent() )
		return( FALSE );
	if( !testSessionSCEPClientServer() )
		return( FALSE );
	if( !testSessionSCEPSigonlyClientServer() )
		return( FALSE );
	if( !testSessionSCEPCACertClientServer() )
		return( FALSE );
	if( !testSessionSCEPRenewClientServer() )
		return( FALSE );
	if( !testSessionSCEPRenewSigonlyClientServer() )
		return( FALSE );
	if( !testSessionSCEPSHA2ClientServer() )
		return( FALSE );
	if( !testSessionSCEPClientServerDebugCheck() )
		return( FALSE );
	if( !testSessionCMPClientServer() )
		return( FALSE );
	if( !testSessionCMPAltAlgoClientServer() )
		return( FALSE );
	if( !testSessionCMPSHA2ClientServer() )
		return( FALSE );
	if( !testSessionCMPPKIBootClientServer() )
		return( FALSE );
	if( !testSessionPNPPKIClientServer() )
		return( FALSE );
	if( !testSessionPNPPKICAClientServer() )
		return( FALSE );
	if( !testSessionPNPPKIIntermedCAClientServer() )
		return( FALSE );
#if 0	/* Full RA functionality not completely implemented yet */
	if( !testSessionCMPRAClientServer() )
		return( FALSE );
#endif /* 0 */
#if defined( _MSC_VER ) && ( _MSC_VER == VS_LATEST_VERSION ) && \
	!defined( NDEBUG ) && !defined( _M_X64 ) && 1
	/* Causes CRYPT_ERROR_INCOMPLETE on cryptEnd() due to the error-induced 
	   early-out resulting in the server thread waiting for further client 
	   requests while the client finishes and calls cryptEnd() */
	if( !testSessionCMPFailClientServer() )
		return( FALSE );
	fputs( "Warning: This test will cause a CRYPT_ERROR_INCOMPLETE on "
		   "cryptEnd() due to\n         an early-out thread exit, this is "
		   "not an actual error.\n", outputStream );
#endif /* 1 */
	if( !testSessionCMPClientServerDebugCheck() )
		return( FALSE );

	/* The final set of loopback tests, which spawn a large number of 
	   threads, can be somewhat alarming due to the amount of message spew 
	   that they produce so we only run them if explicitly enabled */
#if defined( __WINDOWS__ ) && 0
	{
	char name[ MAX_COMPUTERNAME_LENGTH + 1 ];
	int length = MAX_COMPUTERNAME_LENGTH + 1;

	if( GetComputerName( name, &length ) && length == 8 && \
		!memcmp( name, "LENOVOX1", length ) )
		{
		if( !testSessionSSHClientServerDualThread() )
			return( FALSE );
		if( !testSessionSSHClientServerMultiThread() )
			return( FALSE );
		if( !testSessionTLSClientServerMultiThread() )
			return( FALSE );
		}
	}
#endif /* __WINDOWS__ && !WinCE */
	return( TRUE );
	}
#else

BOOLEAN testSessionsLoopback( void )
	{
	fputs( "Skipping test of loopback session routines...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_SESSION_LOOPBACK */

/****************************************************************************
*																			*
*								Test Users									*
*																			*
****************************************************************************/

#ifdef TEST_USER

/* Test the user routines */

BOOLEAN testUsers( void )
	{
	if( !testUser() )
		return( FALSE );

	return( TRUE );
	}
#else

BOOLEAN testUsers( void )
	{
	fputs( "Skipping test of user routines...\n\n", outputStream );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Test Memory Fault-injection						*
*																			*
****************************************************************************/

/* Test error-handling code paths by forcing memory-allocation faults at
   every location in which cryptlib allocates memory.  Note that this test
   can only be run if all of the cryptlib self-tests complete successfully,
   since it injects memory faults until the self-tests report success */

/*#define TEST_MEMFAULT	/* Undefine to perform memory-fault tests */

#ifdef TEST_MEMFAULT

#if !defined( TEST_SELFTEST ) || !defined( TEST_CERT ) || \
	!defined( TEST_HIGHLEVEL )
  #error Need to enable all tests for fault-allocation test.
#endif /* Defines to indicate that all tests are enabled */

BOOLEAN testInit( void )
	{
	int status;

	status = cryptInit();
	return( cryptStatusError( status ) ? FALSE : TRUE );
	}

#define FAULT_STARTFUNCTION	0
#define FAULT_STARTINDEX	0

typedef int ( *FUNCTION_PTR )( void );
typedef struct {
	FUNCTION_PTR function;
	const char *functionName;
	} FUNCTION_TBL;

#define MK_FN( function )	{ function, #function }

static const FUNCTION_TBL functionTbl[] = {
	MK_FN( testInit ),
	MK_FN( testSelfTest ),
	MK_FN( testLowLevel ),
	MK_FN( testRandom ),
	MK_FN( testConfig ),
	MK_FN( testDevice ),
	MK_FN( testMidLevel ),
	MK_FN( testCert ),
	MK_FN( testKeysetFile ),
	MK_FN( testKeysetDatabase ),
	MK_FN( testCertMgmt ),
	MK_FN( testHighLevel ),
	MK_FN( testEnveloping ),
	MK_FN( testSessions ),
	MK_FN( NULL )
	};

static void testMemFault( void )
	{
	int functionIndex;

	/* Since we don't want to have tons of diagnostic output interspersed
	   with the mem-fault output, we redirect the diagnostic output to
	   /dev/null */
	outputStream = fopen( "nul:", "w" );
	assert( outputStream != NULL );

	puts( "Testing memory fault injection..." );
	for( functionIndex = FAULT_STARTFUNCTION; 
		 functionTbl[ functionIndex ].function != NULL; 
		 functionIndex++ )
		{
		int memFaultIndex;

		for( memFaultIndex = FAULT_STARTINDEX; memFaultIndex < 10000; 
			 memFaultIndex++ )
			{
			int status;

			/* If we're testing something other than the cryptInit() 
			   functionality then we need to initialise cryptlib first */
			if( functionIndex != 0 )
				{
				/* Since we've already tested the init functionality, we 
				   don't want to fault the init any more */
				cryptSetMemFaultCount( 10000 );
				status = cryptInit();
				assert( cryptStatusOK( status ) );
				}

			/* Tell the debug-allocator to return an out-of-memory condition 
			   after the given number of allocations */
			printf( "%s: %d.\r", functionTbl[ functionIndex ].functionName, 
					memFaultIndex );
			cryptSetMemFaultCount( memFaultIndex );

			/* Call the test function, with a memory fault at the given 
			   memory allocation number */
			status = functionTbl[ functionIndex ].function();
			if( status != TRUE )
				{
				if( functionIndex != 0 )
					cryptEnd();
				continue;
				}
			cryptEnd();
			break;
			}
		assert( memFaultIndex < 10000 );
		putchar( '\n' );
		}
	}
#endif /* TEST_MEMFAULT	*/
#endif /* TEST_USER */
=======
/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2016					*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

/* Needed for feature-test macros */
#include "misc/config.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* Whether the database interface is working or not.  This is used when 
   opportunistically calling checkCreateDatabaseKeysets(), if it fails the
   first time then it's not going to start working on subsequent calls */

static int databaseNotWorking = FALSE;

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The tests that use databases and certificate stores require that the user 
   set up a suitable ODBC data source (at least when running under Windows), 
   to automate this process we try and create the data source if it isn't 
   present.
   
   This is complicated by the fact that the universal default MSJET database 
   driver doesn't have a 64-bit version so it's not possible to use it under 
   Vista/Windows 7 x64.  To work around this we fall back to the SQL Server
   driver, which replaces MSJET on x64 systems */

#if defined( _MSC_VER ) && defined( _WIN32 ) && !defined( _WIN32_WCE )

#define DATABASE_AUTOCONFIG

#include <odbcinst.h>

/* Default MS Access database */

#define DRIVER_NAME				TEXT( "Microsoft Access Driver (*.MDB)" )
#define DATABASE_ATTR_NAME		"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"DBQ="
#define DATABASE_ATTR_CREATE	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"CREATE_DB="
#define DATABASE_ATTR_TAIL		DATABASE_KEYSET_NAME_ASCII ".mdb#"
#define CERTSTORE_ATTR_NAME		"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"DBQ="
#define CERTSTORE_ATTR_CREATE	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
								"DESCRIPTION=cryptlib test key database#" \
								"CREATE_DB="
#define CERTSTORE_ATTR_TAIL		CERTSTORE_KEYSET_NAME_ASCII ".mdb#"

/* Alternative 1, SQL Server */

#define DRIVER_NAME_ALT_1			TEXT( "SQL Server" )
#define DATABASE_ATTR_NAME_ALT_1	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Server=localhost#" \
									"Database="
#define DATABASE_ATTR_CREATE_ALT_1	""
#define DATABASE_ATTR_TAIL_ALT_1	DATABASE_KEYSET_NAME_ASCII "#"
#define CERTSTORE_ATTR_NAME_ALT_1	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Server=localhost#" \
									"Database="
#define CERTSTORE_ATTR_CREATE_ALT_1	""
#define CERTSTORE_ATTR_TAIL_ALT_1	CERTSTORE_KEYSET_NAME_ASCII "#"

/* Alternative 2, SQLite */

#define DRIVER_NAME_ALT_2			TEXT( "SQLite3 ODBC Driver" )
#define DATABASE_ATTR_NAME_ALT_2	"DSN=" DATABASE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Database="
#define DATABASE_ATTR_CREATE_ALT_2	""
#define DATABASE_ATTR_TAIL_ALT_2	DATABASE_KEYSET_NAME_ASCII "#"
#define CERTSTORE_ATTR_NAME_ALT_2	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "#" \
									"DESCRIPTION=cryptlib test key database#" \
									"Database="
#define CERTSTORE_ATTR_CREATE_ALT_2	""
#define CERTSTORE_ATTR_TAIL_ALT_2	CERTSTORE_KEYSET_NAME_ASCII "#"

typedef enum { ODBC_SOURCE_ACCESS, ODBC_SOURCE_SQLSERVER, 
			   ODBC_SOURCE_SQLITE } ODBC_SOURCE_TYPE;

static void buildDBString( char *buffer, const char *attrName,
						   const char *attrTail, const char *path )
	{
	const int attrNameSize = strlen( attrName );
	const int attrTailSize = strlen( attrTail );
	const int pathSize = strlen( path );
	int dbStringLen, i;

	/* Build up the data-source control string */
	memcpy( buffer, attrName, attrNameSize + 1 );
	memcpy( buffer + attrNameSize, path, pathSize );
	if( attrTailSize > 0 )
		{
		memcpy( buffer + attrNameSize + pathSize, attrTail, 
				attrTailSize );
		}
	buffer[ attrNameSize + pathSize + attrTailSize ] = '\0';

	/* Finally, convert the strings to the weird embedded-null strings 
	   required by SQLConfigDataSource() */
	dbStringLen = strlen( buffer );
	for( i = 0; i < dbStringLen; i++ )
		{
		if( buffer[ i ] == '#' )
			buffer[ i ] = '\0';
		}
	}

static void reportSqlError( const ODBC_SOURCE_TYPE sourceType )
	{
	DWORD dwErrorCode;
	WORD errorMessageLen;
	char errorMessage[ 256 ];
		
	if( SQLInstallerError( 1, &dwErrorCode, errorMessage, 256, 
						   &errorMessageLen ) != SQL_NO_DATA )
		{
		fprintf( outputStream, "SQLConfigDataSource() returned error "
				 "code %d,\n  message '%s'.\n", dwErrorCode, errorMessage );
#if defined( _M_X64 )
		if( sourceType == ODBC_SOURCE_ACCESS )
			{
			fputs( "  (This is probably because there's no appropriate "
				   "64-bit driver present,\n  retrying the create with "
				   "an alternative driver...).\n", outputStream );
			}
#endif /* _M_X64 */
		}
	else
		{
		fputs( "SQLConfigDataSource() failed, no additional information "
			   "available.\n", outputStream );
		}
	}

static BOOLEAN createDatabase( const char *driverName,
							   const char *keysetName, 
							   const char *nameString, 
							   const char *createString, 
							   const char *trailerString,
							   const ODBC_SOURCE_TYPE sourceType )
	{
	char tempPathBuffer[ 512 ];
	char attrBuffer[ 1024 ];
#ifdef UNICODE_STRINGS
	wchar_t wcAttrBuffer[ 1024 ];
#endif /* UNICODE_STRINGS */
	int status;

	if( !GetTempPath( 512, tempPathBuffer ) )
		strcpy( tempPathBuffer, "C:\\Temp\\" );

	/* Try and create the DSN.  For the default Access driver his is a two-
	   step process, first we create the DSN and then the underlying file 
	   that contains the database.  For SQL Server it's simpler, the database
	   server already exists so all we have to do is create the database */
	switch( sourceType )
		{
		case ODBC_SOURCE_ACCESS:
			fprintf( outputStream, "Database keyset '%s' not found, "
					 "attempting to create data source\n  (ODBC - MS "
					 "Access)...\n", keysetName );
			break;

		case ODBC_SOURCE_SQLSERVER:
			fprintf( outputStream, "Attempting to create keyset '%s' using "
					 "alternative data source\n  (ODBC - SQL Server)...\n", 
					 keysetName );
			fputs( "  (Autoconfiguration of SQL Server data sources rather than "
				   "having them\n  configured manually by an administrator can "
				   "be erratic, if cryptlib\n  hangs while trying to access the "
				   "certificate database then you need to\n  configure the SQL "
				   "Server data source manually).\n", outputStream );
			break;

		case ODBC_SOURCE_SQLITE:
			fprintf( outputStream, "Database keyset '%s' not found, "
					 "attempting to create data source\n  (ODBC - "
					 "SQLite)...\n", keysetName );
			break;
		}
	buildDBString( attrBuffer, nameString, trailerString, tempPathBuffer );
#ifdef UNICODE_STRINGS
	mbstowcs( wcAttrBuffer, attrBuffer, strlen( attrBuffer ) + 1 );
	status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, driverName, 
								  wcAttrBuffer );
#else
	status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, driverName, 
								  attrBuffer );
#endif /* UNICODE_STRINGS */
	if( status != 1 )
		{
		reportSqlError( sourceType );
		return( FALSE );
		}
	if( sourceType != ODBC_SOURCE_ACCESS )
		{
		/* The server already exists and we're done */
		return( TRUE );
		}
	buildDBString( attrBuffer, createString, trailerString, tempPathBuffer );
#ifdef UNICODE_STRINGS
	mbstowcs( wcAttrBuffer, attrBuffer, strlen( attrBuffer ) + 1 );
	status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, driverName, 
								  wcAttrBuffer );
#else
	status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, driverName, 
								  attrBuffer );
#endif /* UNICODE_STRINGS */
	if( status != 1 )
		{
		reportSqlError( sourceType );
		return( FALSE );
		}

	return( TRUE );
	}

static void checkCreateDatabaseKeyset( void )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Check whether the test certificate database can be opened.  This can 
	   return a CRYPT_ARGERROR_PARAM3 as a normal condition since a freshly-
	   created database is empty and therefore can't be identified as a 
	   certificate database until data is written to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		return;
		}
	if( status != CRYPT_ERROR_OPEN )
		return;

	/* Create the database keyset, first MS Access */
	status = createDatabase( DRIVER_NAME, DATABASE_KEYSET_NAME_ASCII,
							 DATABASE_ATTR_NAME, DATABASE_ATTR_CREATE, 
							 DATABASE_ATTR_TAIL, ODBC_SOURCE_ACCESS );
	if( status == FALSE )
		{
		/* The create with the default MS Access driver failed, fall back to 
		   the SQL Server alternative */
		status = createDatabase( DRIVER_NAME_ALT_1, 
								 DATABASE_KEYSET_NAME_ASCII,
								 DATABASE_ATTR_NAME_ALT_1, 
								 DATABASE_ATTR_CREATE_ALT_1, 
								 DATABASE_ATTR_TAIL_ALT_1, 
								 ODBC_SOURCE_SQLSERVER );
		}
	if( status == FALSE )
		{
		/* The create failed as well, try SQLite */
		status = createDatabase( DRIVER_NAME_ALT_2, 
								 DATABASE_KEYSET_NAME_ASCII,
								 DATABASE_ATTR_NAME_ALT_2,
								 DATABASE_ATTR_CREATE_ALT_2,
								 DATABASE_ATTR_TAIL_ALT_2, 
								 ODBC_SOURCE_SQLITE );
		}
	fputs( ( status == TRUE ) ? "Data source creation succeeded.\n" : \
		   "Data source creation failed.\n\nYou need to create the "
		   "keyset data source as described in the cryptlib manual\n"
		   "for the database keyset tests to run.\n", outputStream );
	}

static void checkCreateDatabaseCertstore( void )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Check whether the test certificate store database can be opened.  
	   This can return a CRYPT_ARGERROR_PARAM3 as a normal condition since a 
	   freshly-created database is empty and therefore can't be identified 
	   as a certificate store until data is written to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE_STORE, 
							  CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		return;
		}
	if( status != CRYPT_ERROR_OPEN )
		return;

	/* Create the database keyset */
	status = createDatabase( DRIVER_NAME, CERTSTORE_KEYSET_NAME_ASCII,
							 CERTSTORE_ATTR_NAME, CERTSTORE_ATTR_CREATE, 
							 CERTSTORE_ATTR_TAIL, FALSE );
	if( status == FALSE )
		{
		/* The create with the default MS Access driver failed, fall back to
		   the SQL Server alternative */
		status = createDatabase( DRIVER_NAME_ALT_1, CERTSTORE_KEYSET_NAME_ASCII,
								 CERTSTORE_ATTR_NAME_ALT_1, 
								 CERTSTORE_ATTR_CREATE_ALT_1, 
								 CERTSTORE_ATTR_TAIL_ALT_1, TRUE );
		}
	if( status == FALSE )
		{
		/* The create failed as well, try SQLite */
		status = createDatabase( DRIVER_NAME_ALT_2, CERTSTORE_KEYSET_NAME_ASCII,
								 CERTSTORE_ATTR_NAME_ALT_2,
								 CERTSTORE_ATTR_CREATE_ALT_2,
								 CERTSTORE_ATTR_TAIL_ALT_2, TRUE );
		}
	fputs( ( status == TRUE ) ? "Data source creation succeeded.\n" : \
		   "Data source creation failed.\n\nYou need to create the "
		   "certificate store data source as described in the\n"
		   "cryptlib manual for the certificate management tests to "
		   "run.\n", outputStream );
	}

void checkCreateDatabaseKeysets( void )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Create the databases */
	checkCreateDatabaseKeyset();
	checkCreateDatabaseCertstore();

	/* Create the keysets within the database */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
							  CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "Database keyset created within database "
				 "'%s'.\n", DATABASE_KEYSET_NAME );
		cryptKeysetClose( cryptKeyset );
		}
	else
		{
		/* The create failed, force a call to checkDatabaseKeysetAvailable()
		   which marks the database keysets as unavailable for testing 
		   purposes */
		( void ) checkDatabaseKeysetAvailable();
		databaseNotWorking = TRUE;
		if( status == CRYPT_ERROR_DUPLICATE )
			{
			fprintf( outputStream, "Database '%s' already contains a keyset, "
					 "this may lead to self-test\nerrors due to the presence "
					 "of certificates from previous test runs.\n",
					 DATABASE_KEYSET_NAME );
			}
		else
			{
			fprintf( outputStream, "Error %d creating keyset within '%s' "
					 "database.\n", status, DATABASE_KEYSET_NAME );
			}
		}
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
							  CRYPT_KEYSET_DATABASE_STORE, 
							  CERTSTORE_KEYSET_NAME, 
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "Certificate store keyset created within "
				 "database '%s'.\n", CERTSTORE_KEYSET_NAME );
		cryptKeysetClose( cryptKeyset );
		}
	else
		{
		/* The create failed, force a call to checkDatabaseKeysetAvailable()
		   which marks the database keysets as unavailable for testing 
		   purposes */
		( void ) checkDatabaseKeysetAvailable();
		databaseNotWorking = TRUE;
		if( status == CRYPT_ERROR_DUPLICATE )
			{
			fprintf( outputStream, "Database '%s' already contains a "
					 "certificate store, this may lead to\nself-test errors "
					 "due to the presence of certificates from previous "
					 "test\nruns.\n", CERTSTORE_KEYSET_NAME );
			}
		else
			{
			fprintf( outputStream, "Error %d creating keyset within '%s' "
					 "database.\n", status, CERTSTORE_KEYSET_NAME );
			}
		}
	fprintf( outputStream, "\n" );
	}
#endif /* Win32 with VC++ */

/****************************************************************************
*																			*
*							Test Low-level Functions						*
*																			*
****************************************************************************/

#ifdef TEST_SELFTEST

/* Test the cryptlib self-test routines */

BOOLEAN testSelfTest( void )
	{
	int value, status;

	/* Perform the self-test.  First we write the value to true to force a
	   self-test, then we read it back to see whether it succeeded */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK, 
								TRUE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Attempt to perform cryptlib algorithm "
				 "self-test failed with error code %d, line %d.\n", status, 
				 __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK, 
								&value );
	if( cryptStatusError( status ) || value != TRUE )
		{
		/* Unfortunately all that we can report at this point is that the
		   self-test failed, we can't try each algorithm individually
		   because the self-test has disabled the failed one(s) */
		fprintf( outputStream, "cryptlib algorithm self-test failed, line "
				 "%d.\n", __LINE__ );
		return( FALSE );
		}
	fputs( "cryptlib algorithm self-test succeeded.\n\n", outputStream );

	return( TRUE );
	}
#else

BOOLEAN testSelfTest( void )
	{
	fputs( "Skipping test of self-test routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_SELFTEST */

#ifdef TEST_LOWLEVEL

/* Test the low-level encryption routines */

BOOLEAN testLowLevel( void )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	BOOLEAN algosEnabled;

	/* Test the conventional encryption routines */
	algosEnabled = FALSE;
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) )
			{
			if( !testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				return( FALSE );
			algosEnabled = TRUE;
			}
		}
	if( !algosEnabled )
		{
		fputs( "(No conventional-encryption algorithms enabled).\n",
			   outputStream );
		}

	/* Test the public-key encryption routines */
	algosEnabled = FALSE;
	for( cryptAlgo = CRYPT_ALGO_FIRST_PKC;
		 cryptAlgo <= CRYPT_ALGO_LAST_PKC; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) )
			{
			if( !testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				return( FALSE );
			algosEnabled = TRUE;
			}
		}
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RSA, NULL ) ) )
		{
		if( !testRSAMinimalKey() )
			return( FALSE );
		if( !testRSALargeKey() )
			return( FALSE );
		}
	if( !algosEnabled )
		fputs( "(No public-key algorithms enabled).\n", outputStream );

	/* Test the hash routines */
	algosEnabled = FALSE;
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) )
			{
			if( !testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				return( FALSE );
			algosEnabled = TRUE;
			}
		}
	if( !algosEnabled )
		fputs( "(No hash algorithms enabled).\n", outputStream );

	/* Test the MAC routines */
	algosEnabled = FALSE;
	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		{
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) )
			{
			if( !testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				return( FALSE );
			algosEnabled = TRUE;
			}
		}
	if( !algosEnabled )
		fputs( "(No MAC algorithms enabled).\n", outputStream );
	printf( "\n" );

	/* Test the handling of persistent objects */
	if( !testPersistentObjects() )
		return( FALSE );

	return( TRUE );
	}
#else

BOOLEAN testLowLevel( void )
	{
	fputs( "Skipping test of low-level encryption routines...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_LOWLEVEL */

/****************************************************************************
*																			*
*					Test Randomness, Config, and Device Functions			*
*																			*
****************************************************************************/

#ifdef TEST_RANDOM

/* Test the randomness-gathering routines */

BOOLEAN testRandom( void )
	{
	if( !testRandomRoutines() )
		{
		fputs( "The self-test will proceed without using a strong random "
			   "number source.\n\n", outputStream );

		/* Kludge the randomness routines so we can continue the self-tests */
		cryptAddRandom( "xyzzy", 5 );
		}

	return( TRUE );
	}
#else

BOOLEAN testRandom( void )
	{
	fputs( "Skipping test of randomness routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_RANDOM */

#ifdef TEST_CONFIG

/* The names of the configuration options we check for */

static struct {
	const CRYPT_ATTRIBUTE_TYPE option;	/* Option */
	const char *name;					/* Option name */
	const BOOLEAN isNumeric;			/* Whether it's a numeric option */
	} configOption[] = {
	{ CRYPT_OPTION_INFO_DESCRIPTION, "CRYPT_OPTION_INFO_DESCRIPTION", FALSE },
	{ CRYPT_OPTION_INFO_COPYRIGHT, "CRYPT_OPTION_INFO_COPYRIGHT", FALSE },
	{ CRYPT_OPTION_INFO_MAJORVERSION, "CRYPT_OPTION_INFO_MAJORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_MINORVERSION, "CRYPT_OPTION_INFO_MINORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_STEPPING, "CRYPT_OPTION_INFO_STEPPING", TRUE },

	{ CRYPT_OPTION_ENCR_ALGO, "CRYPT_OPTION_ENCR_ALGO", TRUE },
	{ CRYPT_OPTION_ENCR_HASH, "CRYPT_OPTION_ENCR_HASH", TRUE },
	{ CRYPT_OPTION_ENCR_MAC, "CRYPT_OPTION_ENCR_MAC", TRUE },
	{ CRYPT_OPTION_ENCR_HASHPARAM, "CRYPT_OPTION_ENCR_HASHPARAM", TRUE },

	{ CRYPT_OPTION_PKC_ALGO, "CRYPT_OPTION_PKC_ALGO", TRUE },
	{ CRYPT_OPTION_PKC_KEYSIZE, "CRYPT_OPTION_PKC_KEYSIZE", TRUE },
	{ CRYPT_OPTION_PKC_FORMAT, "CRYPT_OPTION_PKC_FORMAT", TRUE },

	{ CRYPT_OPTION_KEYING_ALGO, "CRYPT_OPTION_KEYING_ALGO", TRUE },
	{ CRYPT_OPTION_KEYING_ITERATIONS, "CRYPT_OPTION_KEYING_ITERATIONS", TRUE },

	{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, "CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES", TRUE },
	{ CRYPT_OPTION_CERT_VALIDITY, "CRYPT_OPTION_CERT_VALIDITY", TRUE },
	{ CRYPT_OPTION_CERT_UPDATEINTERVAL, "CRYPT_OPTION_CERT_UPDATEINTERVAL", TRUE },
	{ CRYPT_OPTION_CERT_COMPLIANCELEVEL, "CRYPT_OPTION_CERT_COMPLIANCELEVEL", TRUE },
	{ CRYPT_OPTION_CERT_REQUIREPOLICY, "CRYPT_OPTION_CERT_REQUIREPOLICY", TRUE },

	{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, "CRYPT_OPTION_CMS_DEFAULTATTRIBUTES", TRUE },

	{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, "CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE", TRUE },
	{ CRYPT_OPTION_KEYS_LDAP_FILTER, "CRYPT_OPTION_KEYS_LDAP_FILTER", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "CRYPT_OPTION_KEYS_LDAP_CACERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, "CRYPT_OPTION_KEYS_LDAP_CERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, "CRYPT_OPTION_KEYS_LDAP_CRLNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "CRYPT_OPTION_KEYS_LDAP_EMAILNAME", FALSE },

	{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, "CRYPT_OPTION_DEVICE_PKCS11_DVR01", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, "CRYPT_OPTION_DEVICE_PKCS11_DVR02", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, "CRYPT_OPTION_DEVICE_PKCS11_DVR03", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, "CRYPT_OPTION_DEVICE_PKCS11_DVR04", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, "CRYPT_OPTION_DEVICE_PKCS11_DVR05", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, "CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY", TRUE },

	{ CRYPT_OPTION_NET_SOCKS_SERVER, "CRYPT_OPTION_NET_SOCKS_SERVER", FALSE },
	{ CRYPT_OPTION_NET_SOCKS_USERNAME, "CRYPT_OPTION_NET_SOCKS_USERNAME", FALSE },
	{ CRYPT_OPTION_NET_HTTP_PROXY, "CRYPT_OPTION_NET_HTTP_PROXY", FALSE },
	{ CRYPT_OPTION_NET_CONNECTTIMEOUT, "CRYPT_OPTION_NET_CONNECTTIMEOUT", TRUE },
	{ CRYPT_OPTION_NET_READTIMEOUT, "CRYPT_OPTION_NET_READTIMEOUT", TRUE },
	{ CRYPT_OPTION_NET_WRITETIMEOUT, "CRYPT_OPTION_NET_WRITETIMEOUT", TRUE },

	{ CRYPT_OPTION_MISC_ASYNCINIT, "CRYPT_OPTION_MISC_ASYNCINIT", TRUE },
	{ CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, "CRYPT_OPTION_MISC_SIDECHANNELPROTECTION", TRUE },

	{ CRYPT_ATTRIBUTE_NONE, NULL, 0 }
	};

/* Test the configuration options routines */

BOOLEAN testConfig( void )
	{
	int i, value, status;

	/* Display each configuration option */
	for( i = 0; configOption[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		C_CHR buffer[ 256 ];
		int length;

		if( configOption[ i ].isNumeric )
			{
			status = cryptGetAttribute( CRYPT_UNUSED, 
										configOption[ i ].option, &value );
			if( cryptStatusError( status ) )
				{
				fprintf( outputStream, "%s appears to be "
						 "disabled/unavailable in this build.\n", 
						 configOption[ i ].name );
				continue;
				}
			fprintf( outputStream, "%s = %d.\n", configOption[ i ].name, 
					 value );
			continue;
			}
		status = cryptGetAttributeString( CRYPT_UNUSED, 
										  configOption[ i ].option,
										  buffer, &length );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "%s appears to be disabled/unavailable "
					 "in this build.\n", configOption[ i ].name );
			continue;
			}
		assert( length < 256 );
#ifdef UNICODE_STRINGS
		buffer[ length / sizeof( wchar_t ) ] = TEXT( '\0' );
		fprintf( outputStream, "%s = %S.\n", configOption[ i ].name, 
				 buffer );
#else
		buffer[ length ] = '\0';
		fprintf( outputStream, "%s = %s.\n", configOption[ i ].name, 
				 buffer );
#endif /* UNICODE_STRINGS */
		}
	fprintf( outputStream, "\n" );

	/* Make sure that setting options that affect other options works */
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
								&value );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
									CRYPT_ALGO_SHA1 );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASHPARAM, 
									&value );
		}
	if( cryptStatusOK( status ) && value != 20 )
		{
		fputs( "Setting CRYPT_OPTION_ENCR_HASH didn't change corresponding "
			   "CRYPT_OPTION_ENCR_HASHPARAM.\n", outputStream );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, 
									CRYPT_ALGO_SHA2 );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASHPARAM, 
									&value );
		}
	if( cryptStatusOK( status ) && value != 32 )
		{
		fputs( "Setting CRYPT_OPTION_ENCR_HASH didn't change corresponding "
			   "CRYPT_OPTION_ENCR_HASHPARAM.\n", outputStream );
		return( FALSE );
		}
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_HASH, value );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't set/reset CRYPT_OPTION_ENCR_HASH, "
				 "error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}
#else

BOOLEAN testConfig( void )
	{
	fputs( "Skipping display of config options...\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_CONFIG */

#ifdef TEST_DEVICE

/* Test the crypto device routines */

BOOLEAN testDevice( void )
	{
	int status;

	status = testDevices();
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Handling for crypto devices doesn't appear to be enabled "
			   "in this build of\ncryptlib.\n", outputStream );
		return( TRUE );
		}
	if( !status )
		return( FALSE );

	return( TRUE );
	}
#else

BOOLEAN testDevice( void )
	{
	fputs( "Skipping test of crypto device routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_DEVICE */

/****************************************************************************
*																			*
*							Test Mid/High-level Functions					*
*																			*
****************************************************************************/

#ifdef TEST_MIDLEVEL

/* Test the mid-level routines */

static const TEST_FUNCTION_INFO midLevelTestInfo[] = { 
	MK_TESTFUNC( testLargeBufferEncrypt ), 
	MK_TESTFUNC( testDeriveKey ), 
	MK_TESTFUNC( testConventionalExportImport ),
	MK_TESTFUNC( testMACExportImport ),
	MK_TESTFUNC_COND_ALGO( testKeyExportImport, CRYPT_ALGO_RSA ),
	MK_TESTFUNC( testSignData ),
	MK_TESTFUNC( testKeygen ),
	MK_TESTFUNC( testMidLevelDebugCheck ),
	{ NULL }
	};

BOOLEAN testMidLevel( void )
	{
	return( runTests( midLevelTestInfo ) );
	}
#else

BOOLEAN testMidLevel( void )
	{
	fputs( "Skipping test of mid-level encryption routines...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_MIDLEVEL */

#ifdef TEST_HIGHLEVEL

/* Test the high-level routines (these are similar to the mid-level routines 
   but rely on things like certificate management to work) */

static const TEST_FUNCTION_INFO highLevelTestInfo[] = { 
	MK_TESTFUNC_COND_ALGO( testKeyExportImportCMS, CRYPT_ALGO_RSA ),
	MK_TESTFUNC_COND_ALGO( testSignDataCMS, CRYPT_ALGO_RSA ),
	{ NULL }
	};

BOOLEAN testHighLevel( void )
	{
	return( runTests( highLevelTestInfo ) );
	}
#else

BOOLEAN testHighLevel( void )
	{
	fputs( "Skipping test of high-level routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_HIGHLEVEL */

/****************************************************************************
*																			*
*								Test Certificates							*
*																			*
****************************************************************************/

#ifdef TEST_CERT

/* Test the certificate routines */

static const TEST_FUNCTION_INFO certTestInfo[] = { 
	MK_TESTFUNC( testBasicCert ),
	MK_TESTFUNC( testCACert ),
	MK_TESTFUNC( testXyzzyCert ),
	MK_TESTFUNC( testTextStringCert ),
	MK_TESTFUNC( testComplexCert ),
	MK_TESTFUNC( testAltnameCert ),
	MK_TESTFUNC( testCertExtension ),
	MK_TESTFUNC( testCustomDNCert ),
	MK_TESTFUNC( testSETCert ),
	MK_TESTFUNC_COND_EMULATED( testAttributeCert ),
	MK_TESTFUNC( testCertRequest ),
	MK_TESTFUNC( testComplexCertRequest ),
	MK_TESTFUNC( testCertRequestAttrib ),
	MK_TESTFUNC( testCRMFRequest ),
	MK_TESTFUNC( testComplexCRMFRequest ),
	MK_TESTFUNC_COND_EMULATED( testCRL ),
	MK_TESTFUNC_COND_EMULATED( testComplexCRL ),
	MK_TESTFUNC( testRevRequest ),
	MK_TESTFUNC_COND_EMULATED( testCertChain ),
	MK_TESTFUNC_COND_EMULATED( testCAConstraints ),
	MK_TESTFUNC( testCMSAttributes ),
	MK_TESTFUNC_COND_EMULATED( testOCSPReqResp ),
	MK_TESTFUNC_COND_EMULATED( testCertImport ),
	MK_TESTFUNC_COND_EMULATED( testCertImportECC ),
	MK_TESTFUNC_COND_EMULATED( testCertReqImport ),
	MK_TESTFUNC_COND_EMULATED( testCRLImport ),
	MK_TESTFUNC_COND_EMULATED( testCertChainImport ),
	MK_TESTFUNC_COND_EMULATED( testOCSPImport ),
	MK_TESTFUNC_COND_EMULATED( testBase64CertImport ),
	MK_TESTFUNC_COND_EMULATED( testBase64CertChainImport ),
	MK_TESTFUNC_COND_EMULATED( testMiscImport ),
	MK_TESTFUNC_COND_EMULATED( testNonchainCert ),
	MK_TESTFUNC_COND_EMULATED( testCertComplianceLevel ),
	MK_TESTFUNC_COND_EMULATED( testCertChainHandling ),
	MK_TESTFUNC_COND_EMULATED( testPKCS1Padding ),
#if 0	/* This takes a while to run and produces a lot of output that won't
		   be meaningful to anyone other than cryptlib developers so it's
		   disabled by default */
	MK_TESTFUNC( testPathProcessing ),
#endif /* 0 */
	{ NULL }
	};

BOOLEAN testCert( void )
	{
	return( runTests( certTestInfo ) );
	}
#else

BOOLEAN testCert( void )
	{
	fputs( "Skipping test of certificate routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_CERT */

#ifdef TEST_CERTPROCESS

/* Test the certificate processing and CA certificate management 
   functionality.  A side-effect of the certificate-management 
   functionality is that the OCSP EE test certificates are written 
   to the test data directory */

static const TEST_FUNCTION_INFO certMgmtTestInfo[] = { 
	MK_TESTFUNC( testCertProcess ),
	{ NULL }
	};

BOOLEAN testCertMgmt( void )
	{
	int status;

	status = runTests( certMgmtTestInfo );
	if( !status )
		return( FALSE );
	status = testCertManagement();
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Handling for CA certificate stores doesn't appear to be "
			   "enabled in this\nbuild of cryptlib, skipping the test of "
			   "the certificate management routines.\n", outputStream );
		}
	else
		{
		if( !status )
			return( FALSE );
		}

	return( TRUE );
	}
#else

BOOLEAN testCertMgmt( void )
	{
	fputs( "Skipping test of certificate handling/CA management...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_CERTPROCESS */

/****************************************************************************
*																			*
*								Test Keysets								*
*																			*
****************************************************************************/

#ifdef TEST_KEYSET

/* Test the file and database keyset read routines */

static const TEST_FUNCTION_INFO keysetFileTestInfo[] = { 
	MK_TESTFUNC_COND_EMULATED( testGetPGPPublicKey ),
	MK_TESTFUNC_COND_EMULATED( testGetPGPPrivateKey ),
	/* None of the write tests beyond this point will succeed if a custom
	   crypto HAL is in use because pkcs15_set.c:setItemFunction() checks,
	   whether it's tied to crypto hardware and won't try and write it to 
	   a file if it is (this operation would fail since the key components
	   aren't available outside the HAL) */
	MK_TESTFUNC( testReadWriteFileKey ),
	MK_TESTFUNC_COND_ALGO( testReadWriteAltFileKey, CRYPT_ALGO_3DES ),
	MK_TESTFUNC_COND_ALGO( testReadWritePGPFileKey, CRYPT_ALGO_RSA ),
	MK_TESTFUNC( testImportFileKey ),
	MK_TESTFUNC( testReadFilePublicKey ),
	MK_TESTFUNC( testDeleteFileKey ),
	MK_TESTFUNC( testUpdateFileCert ),
	MK_TESTFUNC( testReadFileCert ),
	MK_TESTFUNC( testReadFileCertPrivkey ),
	MK_TESTFUNC( testWriteFileCertChain ),
	MK_TESTFUNC( testReadFileCertChain ),
	MK_TESTFUNC( testAddTrustedCert ),
#if 0	/* This changes the global config file and is disabled by default */
	MK_TESTFUNC( testAddGloballyTrustedCert ),
#endif /* 0 */
	MK_TESTFUNC( testWriteFileLongCertChain ),
	MK_TESTFUNC( testSingleStepFileCert ),
	MK_TESTFUNC( testSingleStepAltFileCert ),
	MK_TESTFUNC( testDoubleCertFile ),
	MK_TESTFUNC( testRenewedCertFile ),
	MK_TESTFUNC( testReadOldKey ),
	MK_TESTFUNC( testReadCorruptedKey ),
	MK_TESTFUNC_COND_EMULATED( testReadAltFileKey ),
	MK_TESTFUNC( testReadMiscFile ),
	{ NULL }
	};

BOOLEAN testKeysetFile( void )
	{
	return( runTests( keysetFileTestInfo ) );
	}

BOOLEAN testKeysetDatabase( void )
	{
	int status;

  #ifdef DATABASE_AUTOCONFIG
	checkCreateDatabaseKeysets();
  #endif /* DATABASE_AUTOCONFIG */
	if( !checkDatabaseKeysetAvailable() )
		{
		fputs( "Certificate database isn't available, skipping the test of "
			   "the certificate\ndatabase routines.\n\n", outputStream );
		}
	else
		{
		status = testWriteCert();
		if( !status )
			return( FALSE );
		if( status == CRYPT_ERROR_NOTAVAIL )
			{
			fputs( "Handling for certificate databases doesn't appear to be "
				   "enabled in this\nbuild of cryptlib, skipping the test "
				   "of the certificate database routines.\n\n", 
				   outputStream );
			}
		else
			{
			/* The write succeeded, try and read back what we've written */
			if( !testReadCert() )
				return( FALSE );
			if( !testKeysetQuery() )
				return( FALSE );
			}
		}

	/* For the following tests we may have read access but not write access,
	   so we test a read of known-present certs before trying a write -
	   unlike the local keysets we don't need to add a certificate before we 
	   can try reading it */
	status = testReadCertLDAP();
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Handling for LDAP certificate directories doesn't appear to "
			   "be enabled in\nthis build of cryptlib, skipping the test of "
			   "the certificate directory\nroutines.\n\n", outputStream );
		}
	else
		{
		/* LDAP access can fail if the directory doesn't use the standard
		   du jour, so we don't treat a failure as a fatal error */
		if( status )
			{
			/* LDAP writes are even worse than LDAP reads, so we don't
			   treat failures here as fatal either */
			( void ) testWriteCertLDAP();
			}
		}
	status = testReadCertURL();
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Handling for fetching certificates from web pages doesn't "
			   "appear to be\nenabled in this build of cryptlib, skipping "
			   "the test of the HTTP routines.\n\n", outputStream );
		}
	else
		{
		/* Being able to read a certificate from a web page is rather 
		   different from access to an HTTP certificate store so we don't 
		   treat an error here as fatal */
		if( status )
			( void ) testReadCertHTTP();
		}

	return( TRUE );
	}
#else

BOOLEAN testKeysetFile( void )
	{
	fputs( "Skipping test of file keyset read routines...\n\n", 
		   outputStream );
	return( TRUE );
	}

BOOLEAN testKeysetDatabase( void )
	{
	fputs( "Skipping test of database keyset read routines...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_KEYSET */

/****************************************************************************
*																			*
*								Test Enveloping								*
*																			*
****************************************************************************/

#ifdef TEST_ENVELOPE

/* Test the enveloping routines.  Define SLOW_TESTS to run the iterated 
   tests, which take quite awhile to run */

 #if defined( CRYPTLIB_TEST_BUILD ) 
  #pragma message( "Disabling slow iterated enveloping test." )
#else
  #define	SLOW_TESTS
#endif /* Slow tests enabled */

static const TEST_FUNCTION_INFO envelopeTestInfo[] = { 
	MK_TESTFUNC( testEnvelopeData ),
	MK_TESTFUNC( testEnvelopeDataLargeBuffer ),
#ifdef SLOW_TESTS
	MK_TESTFUNC( testEnvelopeDataVariable ),
	MK_TESTFUNC( testEnvelopeDataMultiple ),
#endif /* SLOW_TESTS */
	MK_TESTFUNC( testEnvelopeCompress ),
	MK_TESTFUNC_COND_ALGO( testPGPEnvelopeCompressedDataImport, CRYPT_ALGO_RSA ),
	MK_TESTFUNC( testEnvelopeSessionCrypt ),
	MK_TESTFUNC( testEnvelopeSessionCryptLargeBuffer ),
#ifdef SLOW_TESTS
	MK_TESTFUNC( testEnvelopeSessionCryptVariable ),
	MK_TESTFUNC( testEnvelopeSessionCryptMultiple ),
#endif /* SLOW_TESTS */
	MK_TESTFUNC( testEnvelopeCrypt ),
	MK_TESTFUNC( testEnvelopePasswordCrypt ),
	MK_TESTFUNC( testEnvelopePasswordCryptBoundary ),
	MK_TESTFUNC( testEnvelopePasswordCryptImport ),
	MK_TESTFUNC( testPGPEnvelopePasswordCryptImport ),
	MK_TESTFUNC( testEnvelopePKCCrypt ),
	MK_TESTFUNC( testEnvelopePKCCryptAlgo ),
	MK_TESTFUNC( testPGPEnvelopePKCCryptImport ),
#ifdef SLOW_TESTS
	MK_TESTFUNC( testEnvelopePKCIterated ),
#endif /* SLOW_TESTS */
	MK_TESTFUNC( testEnvelopeSign ),
	MK_TESTFUNC( testEnvelopeSignAlgos ),
	MK_TESTFUNC( testEnvelopeSignHashUpgrade ),
	MK_TESTFUNC( testEnvelopeSignOverflow ),
	MK_TESTFUNC( testEnvelopeSignIndef ),
#ifdef SLOW_TESTS
	MK_TESTFUNC( testEnvelopeSignIterated ),
#endif /* SLOW_TESTS */
	MK_TESTFUNC( testPGPEnvelopeSignedDataImport ),
	MK_TESTFUNC( testEnvelopeAuthenticate ),
	MK_TESTFUNC( testEnvelopeAuthEnc ),
	MK_TESTFUNC( testCMSEnvelopePKCCrypt ),
	MK_TESTFUNC( testCMSEnvelopePKCCryptDoubleCert ),
	MK_TESTFUNC( testCMSEnvelopePKCCryptImport ),
	MK_TESTFUNC( testCMSEnvelopeSign ),
	MK_TESTFUNC( testCMSEnvelopeDualSign ),
	MK_TESTFUNC( testCMSEnvelopeDetachedSig ),
	MK_TESTFUNC( testPGPEnvelopeDetachedSig ),
	MK_TESTFUNC( testCMSEnvelopeRefCount ),
	MK_TESTFUNC( testCMSEnvelopeSignedDataImport ),
	MK_TESTFUNC( testEnvelopeCMSDebugCheck ),
	MK_TESTFUNC( testEnvelopePGPDebugCheck ),
	{ NULL }
	};

BOOLEAN testEnveloping( void )
	{
	return( runTests( envelopeTestInfo ) );
	}
#else

BOOLEAN testEnveloping( void )
	{
	fputs( "Skipping test of enveloping routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_ENVELOPE */

/****************************************************************************
*																			*
*								Test Sessions								*
*																			*
****************************************************************************/

#ifdef TEST_SESSION

/* Test the session routines */

static const TEST_FUNCTION_INFO sessionTestInfo[] = { 
	MK_TESTFUNC( testSessionAttributes ),
	MK_TESTFUNC( testSessionSSH ),
	MK_TESTFUNC( testSessionSSHPubkeyAuth ),
	MK_TESTFUNC( testSessionSSHPortforward ),
	MK_TESTFUNC( testSessionSSHExec ),
	MK_TESTFUNC( testSessionSSL ),
	MK_TESTFUNC( testSessionSSLLocalSocket ),
	MK_TESTFUNC( testSessionTLS ),
	MK_TESTFUNC( testSessionTLSLocalSocket ),
	MK_TESTFUNC( testSessionTLS11 ),
	MK_TESTFUNC( testSessionTLS12 ),
#if 0	/* The MS test server used for the general TLS 1.2 tests requires 
		   fairly extensive custom configuration of client certs and the
		   ability to do rehandshakes due to the oddball way that SChannel
		   handles client auth so we disable this test until another server 
		   that does TLS 1.2 client auth less awkwardly appears */
	MK_TESTFUNC( testSessionTLS12ClientCert ),
#endif /* 0 */
	MK_TESTFUNC( testSessionTLS13 ),
	MK_TESTFUNC( testSessionTLSBadSSL ),
	MK_TESTFUNC( testSessionOCSP ),
	MK_TESTFUNC( testSessionTSP ),
	MK_TESTFUNC( testSessionEnvTSP ),
	MK_TESTFUNC( testSessionCMP ),
	{ NULL }
	};

BOOLEAN testSessions( void )
	{
	int status;

	status = testSessionUrlParse();
	if( !status )
		return( FALSE );
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		fputs( "Network access doesn't appear to be enabled in this build "
			   "of cryptlib,\nskipping the test of the secure session "
			   "routines.\n", outputStream );
		return( TRUE );
		}
	if( !checkNetworkAccess() )
		{
		fputs( "Couldn't perform a test connect to a well-known site "
			   "(Amazon.com) which\nindicates that external network access "
			   "isn't available.  Is this machine\nsituated behind a "
			   "firewall?\n", outputStream );
		return( FALSE );
		}
	return( runTests( sessionTestInfo ) );
	}
#else

BOOLEAN testSessions( void )
	{
	fputs( "Skipping test of session routines...\n\n", outputStream );
	return( TRUE );
	}
#endif /* TEST_SESSION */

#ifdef TEST_SESSION_LOOPBACK

/* Test loopback client/server sessions.  These require a threaded OS and 
   are aliased to no-ops on non-threaded systems.  In addition there can be 
   synchronisation problems between the two threads if the server is delayed 
   for some reason, resulting in the client waiting for a socket that isn't 
   opened yet.  This isn't easy to fix without a lot of explicit intra-
   thread synchronisation, if there's a problem it's easier to just re-run 
   the tests */

BOOLEAN testSessionsLoopback( void )
	{
  #ifdef DATABASE_AUTOCONFIG
	if( !databaseNotWorking )
		{
		/* The databaseOK flag is default-true in that, in the absence of
		   further evidence, we at least try and work with a database 
		   keyset, however if an earlier attempt to work with one has failed
		   then we don't try and create one again now */
		checkCreateDatabaseKeysets();	/* Needed for PKI tests */
		}
  #endif /* DATABASE_AUTOCONFIG */
	if( !testSessionSSHClientServer() )
		return( FALSE );
	if( !testSessionSSHClientServerDsaKey() )
		return( FALSE );
	if( !testSessionSSHClientServerEccKey() )
		return( FALSE );
	if( !testSessionSSHClientServerFingerprint() )
		return( FALSE );
	if( !testSessionSSHClientServerPubkeyAuth() )
		return( FALSE );
	if( !testSessionSSHClientServerPubkeyAuthWrongKey() )
		return( FALSE );
	if( !testSessionSSHClientServerPubkeyAuthWrongName() )
		return( FALSE );
	if( !testSessionSSHClientServerPubkeyAuthPassword() )
		return( FALSE );
	if( !testSessionSSHClientServerPreauth() )
		return( FALSE );
	if( !testSessionSSHClientServerPreauthMissing() )
		return( FALSE );
	if( !testSessionSSHClientServerPreauthWrong() )
		return( FALSE );
	if( !testSessionSSHClientServerPortForward() )
		return( FALSE );
	if( !testSessionSSHClientServerExec() )
		return( FALSE );
	if( !testSessionSSHClientServerMultichannel() )
		return( FALSE );
	if( !testSessionSSHClientServerDebugCheck() )
		return( FALSE );
	if( !testSessionSSLClientServer() )
		return( FALSE );
	if( !testSessionSSLClientCertClientServer() )
		return( FALSE );
	if( !testSessionTLSClientServer() )
		return( FALSE );
	if( !testSessionTLSSharedKeyClientServer() )
		return( FALSE );
	if( !testSessionTLSNoSharedKeyClientServer() )
		return( FALSE );
	if( !testSessionTLSBulkTransferClientServer() )
		return( FALSE );
	if( !testSessionTLSLocalServerSocketClientServer() )
		return( FALSE );
	if( !testSessionTLS11ClientServer() )
		return( FALSE );
	if( !testSessionTLS11ClientCertClientServer() )
		return( FALSE );
	if( !testSessionTLS12ClientServer() )
		return( FALSE );
	if( !testSessionTLS12ClientCertClientServer() )
		return( FALSE );
	if( !testSessionTLS12ClientCertManualClientServer() )
		return( FALSE );
	if( !testSessionTLS12WebSocketsClientServer() )
		return( FALSE );
	if( !testSessionTLSClientServerDebugCheck() )
		return( FALSE );
	if( !testSessionHTTPCertstoreClientServer() )
		return( FALSE );
	if( !testSessionRTCSClientServer() )
		return( FALSE );
	if( !testSessionOCSPClientServer() )
		return( FALSE );
	if( !testSessionOCSPMulticertClientServer() )
		return( FALSE );
	if( !testSessionTSPClientServer() )
		return( FALSE );
	if( !testSessionTSPClientServerPersistent() )
		return( FALSE );
	if( !testSessionSCEPClientServer() )
		return( FALSE );
	if( !testSessionSCEPSigonlyClientServer() )
		return( FALSE );
	if( !testSessionSCEPCACertClientServer() )
		return( FALSE );
	if( !testSessionSCEPRenewClientServer() )
		return( FALSE );
	if( !testSessionSCEPRenewSigonlyClientServer() )
		return( FALSE );
	if( !testSessionSCEPSHA2ClientServer() )
		return( FALSE );
	if( !testSessionSCEPClientServerDebugCheck() )
		return( FALSE );
	if( !testSessionCMPClientServer() )
		return( FALSE );
	if( !testSessionCMPAltAlgoClientServer() )
		return( FALSE );
	if( !testSessionCMPSHA2ClientServer() )
		return( FALSE );
	if( !testSessionCMPPKIBootClientServer() )
		return( FALSE );
	if( !testSessionPNPPKIClientServer() )
		return( FALSE );
	if( !testSessionPNPPKICAClientServer() )
		return( FALSE );
	if( !testSessionPNPPKIIntermedCAClientServer() )
		return( FALSE );
#if 0	/* Full RA functionality not completely implemented yet */
	if( !testSessionCMPRAClientServer() )
		return( FALSE );
#endif /* 0 */
#if defined( _MSC_VER ) && ( _MSC_VER == VS_LATEST_VERSION ) && \
	!defined( NDEBUG ) && !defined( _M_X64 ) && 1
	/* Causes CRYPT_ERROR_INCOMPLETE on cryptEnd() due to the error-induced 
	   early-out resulting in the server thread waiting for further client 
	   requests while the client finishes and calls cryptEnd() */
	if( !testSessionCMPFailClientServer() )
		return( FALSE );
	fputs( "Warning: This test will cause a CRYPT_ERROR_INCOMPLETE on "
		   "cryptEnd() due to\n         an early-out thread exit, this is "
		   "not an actual error.\n", outputStream );
#endif /* 1 */
	if( !testSessionCMPClientServerDebugCheck() )
		return( FALSE );

	/* The final set of loopback tests, which spawn a large number of 
	   threads, can be somewhat alarming due to the amount of message spew 
	   that they produce so we only run them if explicitly enabled */
#if defined( __WINDOWS__ ) && 0
	{
	char name[ MAX_COMPUTERNAME_LENGTH + 1 ];
	int length = MAX_COMPUTERNAME_LENGTH + 1;

	if( GetComputerName( name, &length ) && length == 8 && \
		!memcmp( name, "LENOVOX1", length ) )
		{
		if( !testSessionSSHClientServerDualThread() )
			return( FALSE );
		if( !testSessionSSHClientServerMultiThread() )
			return( FALSE );
		if( !testSessionTLSClientServerMultiThread() )
			return( FALSE );
		}
	}
#endif /* __WINDOWS__ && !WinCE */
	return( TRUE );
	}
#else

BOOLEAN testSessionsLoopback( void )
	{
	fputs( "Skipping test of loopback session routines...\n\n", 
		   outputStream );
	return( TRUE );
	}
#endif /* TEST_SESSION_LOOPBACK */

/****************************************************************************
*																			*
*								Test Users									*
*																			*
****************************************************************************/

#ifdef TEST_USER

/* Test the user routines */

BOOLEAN testUsers( void )
	{
	if( !testUser() )
		return( FALSE );

	return( TRUE );
	}
#else

BOOLEAN testUsers( void )
	{
	fputs( "Skipping test of user routines...\n\n", outputStream );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Test Memory Fault-injection						*
*																			*
****************************************************************************/

/* Test error-handling code paths by forcing memory-allocation faults at
   every location in which cryptlib allocates memory.  Note that this test
   can only be run if all of the cryptlib self-tests complete successfully,
   since it injects memory faults until the self-tests report success */

/*#define TEST_MEMFAULT	/* Undefine to perform memory-fault tests */

#ifdef TEST_MEMFAULT

#if !defined( TEST_SELFTEST ) || !defined( TEST_CERT ) || \
	!defined( TEST_HIGHLEVEL )
  #error Need to enable all tests for fault-allocation test.
#endif /* Defines to indicate that all tests are enabled */

BOOLEAN testInit( void )
	{
	int status;

	status = cryptInit();
	return( cryptStatusError( status ) ? FALSE : TRUE );
	}

#define FAULT_STARTFUNCTION	0
#define FAULT_STARTINDEX	0

typedef int ( *FUNCTION_PTR )( void );
typedef struct {
	FUNCTION_PTR function;
	const char *functionName;
	} FUNCTION_TBL;

#define MK_FN( function )	{ function, #function }

static const FUNCTION_TBL functionTbl[] = {
	MK_FN( testInit ),
	MK_FN( testSelfTest ),
	MK_FN( testLowLevel ),
	MK_FN( testRandom ),
	MK_FN( testConfig ),
	MK_FN( testDevice ),
	MK_FN( testMidLevel ),
	MK_FN( testCert ),
	MK_FN( testKeysetFile ),
	MK_FN( testKeysetDatabase ),
	MK_FN( testCertMgmt ),
	MK_FN( testHighLevel ),
	MK_FN( testEnveloping ),
	MK_FN( testSessions ),
	MK_FN( NULL )
	};

static void testMemFault( void )
	{
	int functionIndex;

	/* Since we don't want to have tons of diagnostic output interspersed
	   with the mem-fault output, we redirect the diagnostic output to
	   /dev/null */
	outputStream = fopen( "nul:", "w" );
	assert( outputStream != NULL );

	puts( "Testing memory fault injection..." );
	for( functionIndex = FAULT_STARTFUNCTION; 
		 functionTbl[ functionIndex ].function != NULL; 
		 functionIndex++ )
		{
		int memFaultIndex;

		for( memFaultIndex = FAULT_STARTINDEX; memFaultIndex < 10000; 
			 memFaultIndex++ )
			{
			int status;

			/* If we're testing something other than the cryptInit() 
			   functionality then we need to initialise cryptlib first */
			if( functionIndex != 0 )
				{
				/* Since we've already tested the init functionality, we 
				   don't want to fault the init any more */
				cryptSetMemFaultCount( 10000 );
				status = cryptInit();
				assert( cryptStatusOK( status ) );
				}

			/* Tell the debug-allocator to return an out-of-memory condition 
			   after the given number of allocations */
			printf( "%s: %d.\r", functionTbl[ functionIndex ].functionName, 
					memFaultIndex );
			cryptSetMemFaultCount( memFaultIndex );

			/* Call the test function, with a memory fault at the given 
			   memory allocation number */
			status = functionTbl[ functionIndex ].function();
			if( status != TRUE )
				{
				if( functionIndex != 0 )
					cryptEnd();
				continue;
				}
			cryptEnd();
			break;
			}
		assert( memFaultIndex < 10000 );
		putchar( '\n' );
		}
	}
#endif /* TEST_MEMFAULT	*/
#endif /* TEST_USER */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
