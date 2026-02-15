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

/* Define the following if cryptlib has been built without keyset support,
   this loads a fixed key and attaches a pseudo-certificate to it */

/* #define USE_PSEUDOCERTIFICATES */
#if ( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) ) && \
	defined( USE_PSEUDOCERTIFICATES ) 
  #pragma message( "Building with pseudocertificate support" )
#endif /* Notify pseudocertificate use */

/* The keys used with the test code have associated certs that expire at
   some point.  The following value defines the number of days before the
   expiry at which we start printing warnings */

#if defined( _MSC_VER ) && ( _MSC_VER == VS_LATEST_VERSION ) && !defined( NDEBUG )
  #define EXPIRY_WARN_DAYS		90
#else
  #define EXPIRY_WARN_DAYS		30
#endif /* VS debug/development, give some advance warning */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Windows CE doesn't have a remove() function */

#if defined( _WIN32_WCE ) && _WIN32_WCE < 500

int remove( const char *pathname )
	{
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];

	mbstowcs( wcBuffer, pathname, strlen( pathname ) + 1 );
	DeleteFile( wcBuffer );

	return( 0 );
	}
#endif /* WinCE < 5.x */

/****************************************************************************
*																			*
*							General Checking Functions						*
*																			*
****************************************************************************/

/* Windows-specific file accessibility check */

#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE ) 

#pragma comment( lib, "advapi32" )

static int checkFileAccessibleACL( const char *fileName )
	{
	BYTE sidBuffer[ 1024 ];
	SECURITY_DESCRIPTOR *pSID = ( void * ) sidBuffer;
	GENERIC_MAPPING gMapping;
	PRIVILEGE_SET psPrivilege;
	HANDLE hThreadToken;
	DWORD dwPrivilegeLength = sizeof( PRIVILEGE_SET );
	DWORD cbNeeded, dwGrantedAccess;
	BOOL fStatus; 

	if( !GetFileSecurity( fileName, ( OWNER_SECURITY_INFORMATION | \
									   GROUP_SECURITY_INFORMATION | \
									   DACL_SECURITY_INFORMATION ), 
						   pSID, 1024, &cbNeeded ) )
		{
		/* We can't access file security information (presumably due to
		   insufficient permissions), there's a problem */
		return( FALSE );
		}
	if( !ImpersonateSelf( SecurityImpersonation ) )
		return( TRUE );
	if( !OpenThreadToken( GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hThreadToken ) )
		{
		RevertToSelf();
		return( TRUE );
		}
	if( !AccessCheck( pSID, hThreadToken, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE, 
					  &gMapping, &psPrivilege, &dwPrivilegeLength,
					  &dwGrantedAccess, &fStatus ) )
		{
		const DWORD dwLastError = GetLastError();

		RevertToSelf();
		CloseHandle( hThreadToken );

		/* If it's FAT32 then there's nothing further to check */
		if( dwLastError == ERROR_NO_SECURITY_ON_OBJECT || \
			dwLastError == ERROR_NOT_SUPPORTED )
			return( TRUE );

		return( FALSE );
		}
	RevertToSelf();
	CloseHandle( hThreadToken );

	return( fStatus ? TRUE : FALSE );	/* Deal with type conversion */
	}
#endif /* Windows versions with ACLs */

/* Check that a file is accessible.  This is a generic sanity check to make
   sure that access to keyset files is functioning */

int checkFileAccess( void )
	{
	CRYPT_KEYSET cryptKeyset;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int length, failedFileNo = 0, status;

	/* First, check that the file actually exists so that we can return an
	   appropriate error message.  Note that we have to use permanent files,
	   not ones created by self-test runs like the generic 
	   TEST_PRIVKEY_FILE, since these may have not exist if an earlier self-
	   test run fails */
	if( ( filePtr = fopen( convertFileName( CA_PRIVKEY_FILE ),
						   "rb" ) ) == NULL )
		failedFileNo = 1;
	else
		fclose( filePtr );
	if( failedFileNo == 0 )
		{
		filenameFromTemplate( buffer, MISC_PRIVKEY_FILE_TEMPLATE, 1 );
		if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
			failedFileNo = 2;
		else
			fclose( filePtr );
		}
	if( failedFileNo > 0 )
		{
		fprintf( outputStream, "Couldn't access cryptlib keyset file '%s'.  "
				 "Please make sure\nthat all the cryptlib files have been "
				 "installed correctly, and the cryptlib\nself-test is being "
				 "run from the correct directory.\n", 
				( failedFileNo == 1 ) ? \
				  CA_PRIVKEY_FILE : ( char * ) buffer );	/* For gcc */
		return( FALSE );
		}

	/* Now check for accessibility problems due to filesystem permissions.
	   This can sometimes occur in odd situations for private-key files 
	   (which are set up with fairly restrictive ACLs) when the files have 
	   been copied from one filesystem to another with a different user,
	   so the ACLs grant access to the user on the source filesystem rather
	   than the destination filesystem (this requires a somewhat messed-
	   up copy, since the copier will have had access but the current 
	   requester won't).

	   We check for access to two files, the CA private-key file that ships
	   with cryptlib and the user private-key file that's created when
	   cryptlib is run */
#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE ) 
	if( !checkFileAccessibleACL( CA_PRIVKEY_FILE ) )
		failedFileNo = 1;
	else
		{
		filenameFromTemplate( buffer, MISC_PRIVKEY_FILE_TEMPLATE, 1 );
		if( !checkFileAccessibleACL( buffer ) )
			failedFileNo = 2;
		}
	if( failedFileNo > 0 )
		{
		fprintf( outputStream, "Couldn't access %s cryptlib keyset file "
				 "'%s'\nfor read/write/delete.  This is probably due to a "
				 "filesystem ACL issue\nin which the current user has "
				 "insufficient permissions to perform the\nrequired file "
				 "access.\n",
				( failedFileNo == 1 ) ? \
				  "pre-generated" : "test-run generated",
				( failedFileNo == 1 ) ? \
				  CA_PRIVKEY_FILE : ( char * ) buffer );	/* For gcc */
		return( FALSE );
		}
#endif /* Windows versions with ACLs */

	/* Now read the test files and see if there's any problem due to data 
	   conversion evident */
	filenameFromTemplate( buffer, TESTDATA_FILE_TEMPLATE, 1 );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		fputs( "Couldn't open binary data test file to check for data "
			   "conversion problems.\n", outputStream );
		return( FALSE );
		}
	length = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( length != 16 || \
		memcmp( buffer, \
				"\x30\x82\x02\x56\x30\x82\x02\x52\x0D\x0A\x08\x40\x0A\x74\x71\x7A", 16 ) )
		{
		fputs( "Binary data is corrupt, probably due to being unzipped or "
			   "copied onto the\nsystem in a mode that tries to translate "
			   "text data during processing/copying.\n", outputStream );
		return( FALSE );
		}
#ifdef __UNIX__
	filenameFromTemplate( buffer, TESTDATA_FILE_TEMPLATE, 2 );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		fputs( "Couldn't open text data test file to check for data "
			   "conversion problems.\n", outputStream );
		return( FALSE );
		}
	length = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( length != 10 || memcmp( buffer, "test\ntest\n" , 10 ) )
		{
		fputs( "Text data is still in CRLF-delimited format, probably due "
			   "to being unzipped\nwithout the '-a' option to translate "
			   "text files for Unix systems.\n", outputStream );
		return( FALSE );
		}
#endif /* __UNIX__ */

	/* The file exists and is accessible and was copied/installed correctly, 
	   now try and open it using the cryptlib file access functions.  This
	   is a bit of a catch-22 because we're trying to at least open a keyset
	   before the self-test has verified the correct functioning of the
	   keyset-access code, but in almost all cases it's working OK and this
	   provides a useful general sanity-check, since the keyset code would
	   fail in any case when we get to it in the self-test */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  CA_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		/* If file keyset access isn't available, the inability to access
		   the keyset isn't an error */
		if( status == CRYPT_ERROR_NOTAVAIL )
			return( TRUE );

		fprintf( outputStream, "Couldn't access cryptlib keyset file '%s' "
				 "even though the file\nexists and is readable.  Please "
				 "make sure that the cryptlib self-test is\nbeing run from "
				 "the correct directory.\n", CA_PRIVKEY_FILE );
		return( FALSE );
		}
	cryptKeysetClose( cryptKeyset );

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Import/Export Functions							*
*																			*
****************************************************************************/

/* Read data from a file */

int readFileData( const char *fileName, const char *description,
				  BYTE *buffer, const int bufSize, const int minFileSize,
				  const BOOLEAN silent )
	{
	FILE *filePtr;
	int count;

	if( ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		{
		fprintf( outputStream, "Couldn't open file %s.\n", 
				 description );
		return( 0 );
		}
	if( !silent )
		fprintf( outputStream, "Reading from file %s.\n", description );
	count = fread( buffer, 1, bufSize, filePtr );
	fclose( filePtr );
	if( count >= bufSize )
		{
		fputs( "The data buffer size is too small for the data.  To fix this, "
			   "either increase\nthe BUFFER_SIZE value in " __FILE__ " and "
			   "recompile the code, or use the\ntest code with dynamically-"
			   "allocated buffers.\n", outputStream );
		return( 0 );		/* Skip this test and continue */
		}
	if( count < minFileSize )
		{
		fprintf( outputStream, "Read of file %s failed, only read %d bytes, "
				 "at least %d required.\n", fileName, count, minFileSize );
		return( 0 );		/* Skip this test and continue */
		}
	if( !silent )
		fprintf( outputStream, "%s has size %d bytes.\n", description, count );
	return( count );
	}

/* Import a certificate object */

int importCertFile( CRYPT_CERTIFICATE *cryptCert, const C_STR fileName )
	{
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count;

	if( ( filePtr = fopen( convertFileName( fileName ), "rb" ) ) == NULL )
		return( CRYPT_ERROR_OPEN );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
    if( count == BUFFER_SIZE )	/* Item too large for buffer */
		return( CRYPT_ERROR_OVERFLOW );

	/* Import the certificate */
	return( cryptImportCert( buffer, count, CRYPT_UNUSED, cryptCert ) );
	}

int importCertFromTemplate( CRYPT_CERTIFICATE *cryptCert,
							const C_STR fileTemplate, const int number )
	{
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */

	filenameFromTemplate( filenameBuffer, fileTemplate, number );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
	return( importCertFile( cryptCert, wcBuffer ) );
#else
	return( importCertFile( cryptCert, filenameBuffer ) );
#endif /* UNICODE_STRINGS */
	}

/* Export a certificate to a file in the given format */

int exportCertFile( const char *fileName, 
					const CRYPT_CERTIFICATE certificate,
					const CRYPT_CERTFORMAT_TYPE formatType )
	{
	FILE *filePtr;
	BYTE certBuffer[ BUFFER_SIZE ];
	int certLength, count, status;

	/* Export the certificate in the requested format */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certLength, 
							  formatType, certificate );
	if( cryptStatusError( status ) )
		return( status );

	/* Write it to a file */
	filePtr = fopen( fileName, "wb" );
	if( filePtr == NULL )
		return( CRYPT_ERROR_OPEN );
	count = fwrite( certBuffer, 1, certLength, filePtr );
	fclose( filePtr );
	if( count != certLength )
		return( CRYPT_ERROR_WRITE );

	return( CRYPT_OK );
	}

/* Read a key from a key file */

#ifndef USE_PSEUDOCERTIFICATES

int getPublicKey( CRYPT_CONTEXT *cryptContext, const C_STR keysetName,
				  const C_STR keyName )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Read the key from the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't open keyset '%s', status %d, "
				 "line %d.\n", keysetName, status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetPublicKey( cryptKeyset, cryptContext, CRYPT_KEYID_NAME,
								keyName );
	if( cryptStatusError( status ) )
		printExtError( cryptKeyset, "cryptGetPublicKey", status, __LINE__ );
	cryptKeysetClose( cryptKeyset );
	return( status );
	}

int getPrivateKey( CRYPT_CONTEXT *cryptContext, const C_STR keysetName,
				   const C_STR keyName, const C_STR password )
	{
	CRYPT_KEYSET cryptKeyset;
	time_t validFrom;
#ifndef _WIN32_WCE
	time_t validTo;
#endif /* _WIN32_WCE */
	int dummy, status;

	/* Read the key from the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptGetPrivateKey( cryptKeyset, cryptContext, CRYPT_KEYID_NAME,
								 keyName, password );
	if( cryptStatusError( status ) )
		printExtError( cryptKeyset, "cryptGetPrivateKey", status, __LINE__ );
	cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		return( status );

	/* If the key has a certificate attached, make sure that it's still 
	   valid before we hand it back to the self-test functions, which will 
	   report the problem as being with the self-test rather than with the 
	   certificate.  We check not just the expiry date but also the expiry 
	   interval to make sure that we don't get false positives on short-
	   validity certificates */
	status = cryptGetAttributeString( *cryptContext,
					CRYPT_CERTINFO_VALIDFROM, &validFrom, &dummy );
	if( cryptStatusError( status ) )
		{
		/* There's no certificate there, this isn't an error */
		return( CRYPT_OK );
		}
#ifndef _WIN32_WCE
	status = cryptGetAttributeString( *cryptContext,
					CRYPT_CERTINFO_VALIDTO, &validTo, &dummy );
	if( cryptStatusError( status ) )
		return( status );
	if( ( validTo - validFrom > ( 86400 * EXPIRY_WARN_DAYS ) ) && \
		validTo - time( NULL ) <= ( 86400 * EXPIRY_WARN_DAYS ) )
		{
		const time_t currentTime = time( NULL );

		fputs( "                         ********************\n", 
			   outputStream );
		if( validTo <= currentTime )
			{
			fputs( "Warning: This key has expired.  Certificate-related "
				   "operations will fail or\n         result in error "
				   "messages from the test code.\n", outputStream );
			}
		else
			{
			if( validTo - currentTime <= 86400 )
				{
				fputs( "Warning: This key expires today.  Certificate-"
					   "related operations may fail\n         or result in "
					   "error messages from the test code.\n", outputStream );
				}
			else
				{
				fprintf( outputStream, "Warning: This key will expire in " 
						 TIMET_FORMAT " days.  Certificate-related "
						 "operations\n         may fail or result in error "
						 "messages from the test code.\n",
						( validTo - currentTime ) / 86400 );
				}
			}
		fputs( "                         ********************\nHit a key...", 
			   outputStream );
		getchar();
		fputs( "\r", outputStream );
		}
#endif /* _WIN32_WCE */
	return( CRYPT_OK );
	}
#else

/* Import a certificate as a raw data object and attach it to a context as a 
   pseudo-certificate */

C_RET cryptCreateAttachedCert( C_IN CRYPT_CONTEXT cryptContext,
							   C_IN void C_PTR certObject,
							   C_IN int certObjectLength );

static int addPseudoCertificate( const CRYPT_CONTEXT cryptContext,
								 const int certNo )
	{
	FILE *filePtr;
	BYTE certBuffer[ BUFFER_SIZE ];
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int length = 0;

	filenameFromTemplate( filenameBuffer, PSEUDOCERT_FILE_TEMPLATE, certNo );
	if( ( filePtr = fopen( filenameBuffer, "rb" ) ) == NULL )
		return( CRYPT_ERROR_OPEN );
	length = fread( certBuffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
    if( length <= 16 || length >= BUFFER_SIZE )
		return( CRYPT_ERROR_READ );
	return( cryptCreateAttachedCert( cryptContext, certBuffer, length ) );
	}

int getPublicKey( CRYPT_CONTEXT *cryptContext, const C_STR keysetName,
				  const C_STR keyName )
	{
	/* Load a fixed RSA public key and attached the pseudo-certificate */
	if( !loadRSAContexts( CRYPT_UNUSED, cryptContext, NULL ) )
		return( CRYPT_ERROR_NOTAVAIL );
	return( addPseudoCertificate( *cryptContext, 1 ) );
	}

int getPrivateKey( CRYPT_CONTEXT *cryptContext, const C_STR keysetName,
				   const C_STR keyName, const C_STR password )
	{
	/* Load a fixed RSA public key and attached the pseudo-certificate */
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, cryptContext ) )
		return( CRYPT_ERROR_NOTAVAIL );
	return( addPseudoCertificate( *cryptContext, 1 ) );
	}
#endif /* USE_PSEUDOCERTIFICATES */

/****************************************************************************
*																			*
*							Key File Access Routines						*
*																			*
****************************************************************************/

/* Key file and password-handling access routines */

const C_STR getKeyfileName( const KEYFILE_TYPE type,
							const BOOLEAN isPrivKey )
	{
	static char filenameBuffer[ FILENAME_BUFFER_SIZE ];

	switch( type )
		{
		case KEYFILE_X509:
			filenameFromTemplate( filenameBuffer, 
								  USER_PRIVKEY_FILE_TEMPLATE, 1 );
			return( filenameBuffer );
		case KEYFILE_X509_ALT:
			filenameFromTemplate( filenameBuffer, 
								  USER_PRIVKEY_FILE_TEMPLATE, 2 );
			return( filenameBuffer );
		case KEYFILE_PGP:
		case KEYFILE_PGP_SPECIAL:
			return( isPrivKey ? PGP_PRIVKEY_FILE : PGP_PUBKEY_FILE );
		case KEYFILE_OPENPGP_HASH:
			return( isPrivKey ? OPENPGP_PRIVKEY_HASH_FILE : \
								OPENPGP_PUBKEY_HASH_FILE );
		case KEYFILE_OPENPGP_HASH_ALT:
			return( isPrivKey ? OPENPGP_PRIVKEY_HASH_ALT_FILE : \
								OPENPGP_PUBKEY_HASH_ALT_FILE );
		case KEYFILE_OPENPGP_AES:
		case KEYFILE_OPENPGP_AES_KEYID:
			return( isPrivKey ? OPENPGP_PRIVKEY_AES_FILE : \
								OPENPGP_PUBKEY_AES_FILE );
		case KEYFILE_OPENPGP_CAST:
			return( OPENPGP_PRIVKEY_CAST_FILE );
		case KEYFILE_OPENPGP_RSA:
			return( isPrivKey ? OPENPGP_PRIVKEY_RSA_FILE : \
								OPENPGP_PUBKEY_RSA_FILE );
		case KEYFILE_OPENPGP_MULT:
			return( OPENPGP_PUBKEY_MULT_FILE );
		case KEYFILE_OPENPGP_PARTIAL:
			return( OPENPGP_PRIVKEY_PART_FILE );
		case KEYFILE_NAIPGP:
			return( isPrivKey ? NAIPGP_PRIVKEY_FILE : NAIPGP_PUBKEY_FILE );
		case KEYFILE_OPENPGP_BOUNCYCASTLE:
			return( OPENPGP_PRIVKEY_BC_FILE );
		case KEYFILE_OPENPGP_ECC1:
			return( isPrivKey ? OPENPGP_PRIVKEY_ECC1_FILE : \
								OPENPGP_PUBKEY_ECC1_FILE );
		case KEYFILE_OPENPGP_ECC2:
			return( isPrivKey ? OPENPGP_PRIVKEY_ECC2_FILE : \
								OPENPGP_PUBKEY_ECC2_FILE );
		}
	assert( 0 );
	return( TEXT( "notfound" ) );
	}

const C_STR getKeyfilePassword( const KEYFILE_TYPE type )
	{
	switch( type )
		{
		case KEYFILE_X509:
		case KEYFILE_X509_ALT:
			return( TEST_PRIVKEY_PASSWORD );
		case KEYFILE_PGP:
		case KEYFILE_OPENPGP_HASH:
		case KEYFILE_OPENPGP_RSA:
		case KEYFILE_OPENPGP_ECC1:
		case KEYFILE_OPENPGP_ECC2:
			return( TEXT( "test1" ) );
		case KEYFILE_NAIPGP:
			return( TEXT( "test10" ) );
		case KEYFILE_OPENPGP_AES:
		case KEYFILE_OPENPGP_AES_KEYID:
			return( TEXT( "testkey" ) );
		case KEYFILE_OPENPGP_CAST:
		case KEYFILE_OPENPGP_BOUNCYCASTLE:
			return( TEXT( "test" ) );
		case KEYFILE_OPENPGP_PARTIAL:
			return( TEXT( "def" ) );
		}
	assert( 0 );
	return( TEXT( "notfound" ) );
	}

const C_STR getKeyfileUserID( const KEYFILE_TYPE type,
							  const BOOLEAN isPrivKey )
	{
	/* If possible we specify user IDs for keys in the middle of the keyset
	   to make sure that we test the ability to correctly handle multiple
	   keys */
	switch( type )
		{
		case KEYFILE_X509:
		case KEYFILE_X509_ALT:
			return( USER_PRIVKEY_LABEL );
		case KEYFILE_PGP:
		case KEYFILE_OPENPGP_BOUNCYCASTLE:
			return( TEXT( "test" ) );
		case KEYFILE_PGP_SPECIAL:
			return( TEXT( "suzuki" ) );
		case KEYFILE_NAIPGP:
			return( isPrivKey ? TEXT( "test" ) : TEXT( "test cryptlib" ) );
		case KEYFILE_OPENPGP_HASH:
		case KEYFILE_OPENPGP_RSA:
		case KEYFILE_OPENPGP_ECC1:
		case KEYFILE_OPENPGP_ECC2:
			return( TEXT( "test1" ) );
		case KEYFILE_OPENPGP_MULT:
			return( TEXT( "NXX2502" ) );
		case KEYFILE_OPENPGP_AES:
			return( TEXT( "Max Mustermann" ) );
		case KEYFILE_OPENPGP_AES_KEYID:
			return( TEXT( "0xB97CA167C29E7D18" ) );
		case KEYFILE_OPENPGP_CAST:
			return( TEXT( "Trond" ) );
		}
	assert( 0 );
	return( TEXT( "notfound" ) );
	}
