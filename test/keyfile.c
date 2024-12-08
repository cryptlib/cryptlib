<<<<<<< HEAD
/****************************************************************************
*																			*
*						cryptlib File Keyset Test Routines					*
*						Copyright Peter Gutmann 1995-2009					*
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

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* External flags that indicate that the key read/update routines worked OK.
   This is set by earlier self-test code, if it isn't set some of the tests
   are disabled */

extern int keyReadOK, doubleCertOK;

#ifdef TEST_KEYSET

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the label for the key stored for an algorithm */

static const C_STR getAlgoLabel( const CRYPT_ALGO_TYPE cryptAlgo )
	{
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			return( RSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_DSA:
			return( DSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_ELGAMAL:
			return( ELGAMAL_PRIVKEY_LABEL );

		case CRYPT_ALGO_ECDSA:
			return( ECDSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_ECDH:
			return( ECDSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_EDDSA:
			return( EDDSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_25519:
			return( CURVE25519_PRIVKEY_LABEL );
		}

	return( TEXT( "<Unknown>" ) );
	}

/* Load a private-key context for a particular algorithm */

static int loadPrivateKeyContext( CRYPT_CONTEXT *cryptContext,
								  const CRYPT_ALGO_TYPE cryptAlgo )
	{
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			return( loadRSAContexts( CRYPT_UNUSED, NULL, cryptContext ) );

		case CRYPT_ALGO_DSA:
			return( loadDSAContexts( CRYPT_UNUSED, NULL, cryptContext ) );

		case CRYPT_ALGO_ELGAMAL:
			return( loadElgamalContexts( NULL, cryptContext ) );

		case CRYPT_ALGO_ECDSA:
			return( loadECDSAContexts( CRYPT_UNUSED, NULL, cryptContext ) );
		}

	fprintf( outputStream, "Algorithm %d not available, line %d.\n", 
			 cryptAlgo, __LINE__ );
	return( FALSE );
	}

/* Make sure that an item read from a keyset is a certificate */

static int checkCertPresence( const CRYPT_HANDLE cryptHandle,
							  const char *certTypeName,
							  const CRYPT_CERTTYPE_TYPE certType )
	{
	int value, status;

	/* Make sure that what we've got is a certificate */
	status = cryptGetAttribute( cryptHandle, CRYPT_CERTINFO_CERTTYPE, 
								&value );
	if( cryptStatusError( status ) || value != certType )
		{
		fprintf( outputStream, "Returned object isn't a %s, line %d.\n", 
				 certTypeName, __LINE__ );
		return( FALSE );
		}

	/* The test that follows requires an encryption-capable algorithm, if 
	   the algorithm can't be used for encryption then we skip it */
	status = cryptGetAttribute( cryptHandle, CRYPT_CTXINFO_ALGO, &value );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't read algorithm from certificate, "
				 "line %d.\n", __LINE__ );
		return( FALSE );
		}
	if( value != CRYPT_ALGO_RSA )
		{
		fputs( "(Skipping certificate use test since algorithm can't be used "
			   "for encryption).\n\n", outputStream );
		return( TRUE );
		}

	/* Make sure that we can't use the read key (the certificate constrains 
	   it from being used externally) */
	status = testCrypt( cryptHandle, cryptHandle, value, NULL, FALSE, TRUE );
	if( status != CRYPT_ERROR_NOTAVAIL && status != CRYPT_ERROR_PERMISSION )
		{
		fputs( "Attempt to perform external operation on context with "
			   "internal-only action\npermissions succeeded.\n", 
			   outputStream );
		return( FALSE );
		}

	return( TRUE );
	}

/* Copy a source file to a destination file, corrupting a given byte in the 
   process.  This is used to test the ability of the keyset-processing code 
   to detect data manipulation in keyset data */

static int copyModifiedFile( const C_STR srcFileName, 
							 const C_STR destFileName, const int bytePos )
	{
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count = 0;

	/* Read the source file into the data buffer */
	if( ( filePtr = fopen( convertFileName( srcFileName ), "rb" ) ) != NULL )
		{
		count = fread( buffer, 1, BUFFER_SIZE, filePtr );
		if( count >= BUFFER_SIZE )
			count = 0;
		fclose( filePtr );
		}
	if( count <= 0 )
		return( FALSE );

	/* Corrupt a specific byte in the file */
	buffer[ bytePos ] ^= 0xFF;

	/* Write the changed result to the output buffer */
	if( ( filePtr = fopen( convertFileName( destFileName ), "wb" ) ) != NULL )
		{
		int writeCount;

		writeCount = fwrite( buffer, 1, count, filePtr );
		if( writeCount != count )
			count = 0;
		fclose( filePtr );
		}
	
	return( ( count > 0 ) ? TRUE : FALSE );
	}

/****************************************************************************
*																			*
*							PGP Key Read/Write Tests						*
*																			*
****************************************************************************/

/* Get a public key from a PGP keyring */

static int getPGPPublicKey( const KEYFILE_TYPE keyFileType,
							const C_STR keyFileTemplate,
							const BOOLEAN useWildcardName,
							const char *description )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	char fileName[ BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	const C_STR keysetName = getKeyfileName( keyFileType, FALSE );
	int status;

	/* If this is the first file read, check that the file actually exists
	   so that we can return an appropriate error message */
	if( keyFileType == KEYFILE_PGP )
		{
		if( ( filePtr = fopen( convertFileName( keysetName ),
							   "rb" ) ) == NULL )
			return( CRYPT_ERROR_FAILED );
		fclose( filePtr );
		keyReadOK = FALSE;
		}

	/* If the caller has overridden the keyfile to use, use the caller-
	   supplied name */
	if( keyFileTemplate != NULL )
		{
		filenameFromTemplate( fileName, keyFileTemplate, 1 );
#ifdef UNICODE_STRINGS
		mbstowcs( wcBuffer, fileName, strlen( fileName ) + 1 );
		keysetName = wcBuffer;
#else
		keysetName = fileName;
#endif /* UNICODE_STRINGS */
		}

	fprintf( outputStream, "Testing %s public key read...\n", description );

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error code %d, "
				 "line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  The read of the special-case PGP keyring tests the 
	   ability to handle over-long key packet groups so this should return
	   a not-found error due to the packets being skipped */
	if( useWildcardName )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME, "[none]" );
		}
	else
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME,
									getKeyfileUserID( keyFileType, FALSE ) );
		}
	if( ( keyFileType == KEYFILE_PGP_SPECIAL && \
		  status != CRYPT_ERROR_NOTFOUND ) || \
		( keyFileType != KEYFILE_PGP_SPECIAL && \
		  cryptStatusError( status ) ) )
		{
		printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* PGP public keyrings can be arbitrarily large, to deal with the 
	   inability to retain the entire keyring in memory we re-scan the 
	   keyring for each key read.  To make sure this works OK we read a key
	   multiple times for one of the tests */
	if( keyFileType == KEYFILE_OPENPGP_AES && useWildcardName == FALSE )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME,
									getKeyfileUserID( keyFileType, FALSE ) );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey() re-read", 
						   status, __LINE__ );
			return( FALSE );
			}
		cryptDestroyContext( cryptContext );
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME,
									getKeyfileUserID( keyFileType, FALSE ) );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey() second re-read", 
						   status, __LINE__ );
			return( FALSE );
			}
		cryptDestroyContext( cryptContext );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Read of public key from %s keyring "
			 "succeeded.\n\n", description );
	return( TRUE );
	}

int testGetPGPPublicKey( void )
	{
	/* See testGetPGPPrivateKey() for the descriptions of the files */
	if( !getPGPPublicKey( KEYFILE_PGP, NULL, FALSE, "PGP" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_PGP, NULL, TRUE, "PGP with wildcard name" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_HASH, NULL, FALSE, "OpenPGP (GPG/hashed key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_HASH, NULL, TRUE, "OpenPGP with wildcard name" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_AES, NULL, FALSE, "OpenPGP (GPG/AES-256 key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_AES_KEYID, NULL, FALSE, "OpenPGP (GPG/AES-256 key) by keyID" ) )
		return( FALSE );
#if 0	/* The key in this file has an S2K iteration count of 3.5M and will 
		   be rejected by cryptlib's anti-DoS sanity checks */
	if( !getPGPPublicKey( KEYFILE_OPENPGP_CAST, NULL, FALSE, "OpenPGP (GPG/CAST5 key)" ) )
		return( FALSE );
#endif /* 0 */
	if( !getPGPPublicKey( KEYFILE_OPENPGP_RSA, NULL, FALSE, "OpenPGP (GPG/RSA key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_MULT, NULL, FALSE, "OpenPGP (multiple subkeys)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_NAIPGP, NULL, FALSE, "OpenPGP (NAI)" ) )
		return( FALSE );
#if 0	/* This file is nearly 100K long and consists of endless strings of 
		   userIDs and signatures for the same identity, so it's rejected by
		   cryptlib's sanity-check code */
	if( !getPGPPublicKey( KEYFILE_PGP_SPECIAL, PGPKEY_FILE_TEMPLATE, FALSE, "Complex PGP key" ) )
		return( FALSE );
#endif /* 0 */
#if 0	/* Not fully supported yet */
	if( !getPGPPublicKey( KEYFILE_OPENPGP_ECC, NULL, FALSE, "OpenPGP (ECC)" ) )
		return( FALSE );
#endif /* 0 */
	return( TRUE );
	}

/* Get a private key from a PGP keyring */

static int getPGPPrivateKey( const KEYFILE_TYPE keyFileType,
							 const BOOLEAN useWildcardName,
							 const char *description )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const C_STR keysetName = getKeyfileName( keyFileType, TRUE );
	const C_STR password = getKeyfilePassword( keyFileType );
	int status;

	fprintf( outputStream, "Testing %s private key read...\n", 
			 description );

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  First we try it without a password, if that fails we
	   retry it with the password - this tests a lot of the private-key get
	   functionality including things like key cacheing */
	if( useWildcardName )
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
									 CRYPT_KEYID_NAME, "[none]", NULL );
		}
	else
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
									 CRYPT_KEYID_NAME,
									 getKeyfileUserID( keyFileType, TRUE ), 
									 NULL );
		}
	if( status == CRYPT_ERROR_WRONGKEY )
		{
		/* We need a password for this private key */
		if( useWildcardName )
			{
			status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
										 CRYPT_KEYID_NAME, "[none]", 
										 password );
			}
		else
			{
			status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
										 CRYPT_KEYID_NAME,
										 getKeyfileUserID( keyFileType, TRUE ), 
										 password );
			}
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can use the key that we've read.  We can only do this 
	   with PGP 2.x keys, OpenPGP's peculiar multi-keys identify two (or more) 
	   keys with the same label and we can't specify (at this level) which 
	   key we want to use (the enveloping code can be more specific and so 
	   doesn't run into this problem) */
	if( keyFileType == KEYFILE_PGP )
		{
		int value;

		status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, 
									&value );
		if( cryptStatusOK( status ) )
			{
			status = testCrypt( cryptContext, cryptContext, value, NULL, 
								FALSE, FALSE );
			}
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* The public and private key reads worked, remember this for later when
	   we use the keys in other tests */
	keyReadOK = TRUE;

	fprintf( outputStream, "Read of private key from %s keyring "
			 "succeeded.\n\n", description );
	return( TRUE );
	}

int testGetPGPPrivateKey( void )
	{
	/* PGP 2.x file, RSA with IDEA, secring.pgp */
#ifdef USE_PGP2
	if( !getPGPPrivateKey( KEYFILE_PGP, FALSE, "PGP" ) )
		return( FALSE );
#endif /* USE_PGP2 */

	/* OpenPGP file, DSA+Elgamal with 3DES, sec_hash.gpg.  Create with:

		gpg --gen-key --homedir . --s2k-cipher-algo 3des

	   Select DSA+Elgamal, size 1024 bits, key does not expire, 
	   name = Test1, email = test1@test.org, comment blank, 
	   password = test1 */
#ifdef USE_3DES
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_HASH, FALSE, "OpenPGP (GPG/hashed key)" ) )
		return( FALSE );
#endif /* USE_3DES */

	/* OpenPGP file, DSA+Elgamal with AES, sec_aes.skr */
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_AES, FALSE, "OpenPGP (GPG/AES-256 key)" ) )
		return( FALSE );
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_AES, TRUE, "OpenPGP with wildcard name" ) )
		return( FALSE );

#if 0	/* The key in this file has an S2K iteration count of 3.5M and will 
		   be rejected by cryptlib's anti-DoS sanity checks */
	/* OpenPGP file, DSA+Elgamal with CAST5, sec_cast.gpg */
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_CAST, FALSE, "OpenPGP (GPG/CAST5 key)" ) )
		return( FALSE );
#endif /* 0 */
	
	/* OpenPGP file, RSA+RSA with 3DES and SHA256, sec_rsa.gpg.  Create with:

		gpg --gen-key --homedir . --s2k-cipher-algo 3des --s2k-digest-algo sha256

	   Select RSA, size 2048 bits, key does not expire, name = Test1, 
	   email = test1@test.org, comment blank, password = test1 */
#ifdef USE_3DES
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_RSA, FALSE, "OpenPGP (GPG/RSA key)" ) )
		return( FALSE );
#endif /* USE_3DES */

	/* OpenPGP file, RSA with IDEA, sec_nai.skr */
#ifdef USE_PGP2
	if( !getPGPPrivateKey( KEYFILE_NAIPGP, FALSE, "OpenPGP (NAI)" ) )
		return( FALSE );
#endif /* USE_PGP2 */

	/* OpenPGP, RSA p and q swapped, sec_bc.gpg.  Create using 
	   BouncyCastle */
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_BOUNCYCASTLE, FALSE, "OpenPGP (RSA p,q swapped)" ) )
		return( FALSE );

	/* OpenPGP, ECC keys, sec_ecc.gpg.  Create using a development release 
	   of GPG 2.x (which involves installing about a dozen dependency 
	   libraries and apps), then:

		gpg2 --expert --full-gen-key

	   Select ECC, NIST P256, key does not expire, name = Test1,
	   email = test1@test.org, comment blank, password = test1 */
#if 0	/* Not fully supported yet */
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_ECC, FALSE, "OpenPGP (ECC)" ) )
		return( FALSE );
#endif /* 0 */

	return( TRUE );
	}

/****************************************************************************
*																			*
*							PKCS #12 Key Read/Write Tests					*
*																			*
****************************************************************************/

#ifdef USE_PKCS12	/* Disabled by default */

/* The Primekey CA generates ridiculous multilevel fragmented PKCS #12 files 
   with fragmentation across multiple levels of encoding, a fragmented OCTET 
   STRING containing encapsulated inner content which in turn contains 
   another fragmented OCTET STRING.  Dumping the outer level of encoding 
   gives:

      0 NDEF: SEQUENCE {
      2    1:   INTEGER 3
      5 NDEF:   SEQUENCE {
      7    9:     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
     18 NDEF:     [0] {
     20 NDEF:       OCTET STRING {
     22 1000:         OCTET STRING
            :           30 80 30 80 06 09 2A 86 48 86 F7 0D 01 07 01 A0
            :           80 24 80 04 82 01 41 30 82 01 3D 30 82 01 39 06
            :                       [ Bytes skipped ]
   1026 1000:         OCTET STRING
            :           E0 7B 81 49 22 7D C2 81 9D CE A3 CA 0E 95 8F D1
            :           F1 88 10 93 93 A2 4B AE 08 1B FB 84 84 EB 62 3D
            :                       [ Bytes skipped ]

   [...]

   The inner content there starts with 30 80 30 80, trying to decode this
   gives:

      0 NDEF: SEQUENCE {
      2    1:   INTEGER 3
      5 NDEF:   SEQUENCE {
      7    9:     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
     18 NDEF:     [0] {
     20 NDEF:       OCTET STRING {
     22 1000:         OCTET STRING, encapsulates {
     26 NDEF:           SEQUENCE {
     28 NDEF:             SEQUENCE {
     30    9:               OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
     41 NDEF:               [0] {
     43 NDEF:                 OCTET STRING {
     45  321:                   OCTET STRING, encapsulates {
     49  317:                     SEQUENCE {
     53  313:                       SEQUENCE {
     57   11:                         OBJECT IDENTIFIER
            :                           pkcs-12-pkcs-8ShroudedKeyBag (1 2 840 113549 1 12 10 1 2)
     70  201:                         [0] {
   [...]
            :                           }
    274   94:                         SET {
   [...]
            :                           }
            :                         }
            :                       }
            :                     }
            :                   }
            :                 }
            :               }
    376 NDEF:             SEQUENCE {
    378    9:               OBJECT IDENTIFIER encryptedData (1 2 840 113549 1 7 6)
    389 NDEF:               [0] {
    391 NDEF:                 SEQUENCE {
    393    1:                   INTEGER 0
    396 NDEF:                   SEQUENCE {
    398    9:                     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
    409   41:                     SEQUENCE {
    411   10:                       OBJECT IDENTIFIER pbeWithSHAAnd40BitRC2-CBC (1 2 840 113549 1 12 1 6)
    423   27:                       SEQUENCE {
    425   20:                         OCTET STRING F3 D4 AC 2B 22 0B 5E 38 F2 D2 08 87 62 03 C0 5D 15 C4 F6 44
    447    3:                         INTEGER 51200
            :                         }
            :                       }
    452 NDEF:                     [0] {
    454 1000:                       OCTET STRING
            :                         1B 68 1C AC 26 0C B1 9C 68 64 EB 25 D0 21 2A 85
            :                         58 16 B6 1F C1 B7 23 A1 7B E9 4E 4C 71 7D 8A F1
            :                         D4 B5 25 EE 84 53 07 FC FA 3C 9B DB A7 E8 68 F1
            :                         8B C8 9E 4D 81 D8 0C 6C 81 73 00 79 FC 7D B4 82
            :                         A6 F3 7B D0 74 8D FE 55 4E B1 07 6F B9 B1 08 55
            :                         20 69 A1 C8 F8 AF 3F 81 65 1A A5 18 3B 2C A3 3B
            :                         A5 0B 05 4B 53 C3 F8 93 D3 86 61 90 BC 63 C0 97
            :                         63 CA 15 E5 5A 0A 7B 0F 35 FC 13 75 50 35 5C 97
            :                                 [ Another 872 bytes skipped ]
   1458   19:                       [APPLICATION 30] 2D 04 04 82 03 E8 9F 86 78 18 75 E7 66 77 C3 A0 F4 03 17

   After offset 1458 we hit the OCTET STRING fragment somewhere which means 
   that any data beyond that point appears corrupted because there's 
   fragmentation data overlaid on the content.

   To deal with this, we read the file, de-envelope the contents, re-
   envelope without the gratuitous fragmentation, and then write that as a 
   PKCS #12.  However because of the inner fragmentation we still end up
   with:

   0 NDEF: SEQUENCE {
   2    1:   INTEGER 3
   5 5875:   SEQUENCE {
   9    9:     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
  20 5860:     [0] {
  24 5856:       OCTET STRING, encapsulates {
  28 NDEF:         SEQUENCE {
  30 NDEF:           SEQUENCE {
  32    9:             OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
  43 NDEF:             [0] {
  45 NDEF:               OCTET STRING {
  47  321:                 OCTET STRING, encapsulates {
  51  317:                   SEQUENCE {
  55  313:                     SEQUENCE {
  59   11:                       OBJECT IDENTIFIER pkcs-12-pkcs-8ShroudedKeyBag (1 2 840 113549 1 12 10 1 2)
  72  201:                       [0] {
   [...]
         :                         }
 276   94:                       SET {
   [...]
         :                         }
         :                       }
         :                     }
         :                   }
         :                 }
         :               }
         :             }
 378 NDEF:           SEQUENCE {
 380    9:             OBJECT IDENTIFIER encryptedData (1 2 840 113549 1 7 6)
 391 NDEF:             [0] {
 393 NDEF:               SEQUENCE {
 395    1:                 INTEGER 0
 398 NDEF:                 SEQUENCE {
 400    9:                   OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
 411   41:                   SEQUENCE {
 413   10:                     OBJECT IDENTIFIER pbeWithSHAAnd40BitRC2-CBC (1 2 840 113549 1 12 1 6)
 425   27:                     SEQUENCE {
 427   20:                       OCTET STRING F3 D4 AC 2B 22 0B 5E 38 F2 D2 08 87 62 03 C0 5D 15 C4 F6 44
 449    3:                       INTEGER 51200
         :                       }
         :                     }
 454 NDEF:                   [0] {
 456 1000:                     OCTET STRING
         :                       1B 68 1C AC 26 0C B1 9C 68 64 EB 25 D0 21 2A 85
         :                       58 16 B6 1F C1 B7 23 A1 7B E9 4E 4C 71 7D 8A F1
         :                                       [ Bytes skipped ]
1460 1000:                     OCTET STRING
         :                       9F 86 78 18 75 E7 66 77 C3 A0 F4 03 17 60 2A AB
         :                       4B CF 37 F5 B4 D8 B6 AF BD 38 15 E8 77 D3 3E A5
         :                                       [ Bytes skipped ]
2464 1000:                     OCTET STRING
         :                       DA D3 E4 A3 C0 DE AB 83 E9 0B FD 2C F8 52 39 EB
         :                       1A 4F 7B 84 31 0B B3 7A 11 77 CE 84 99 2F 04 A9
         :                                       [ Bytes skipped ]
3468 1000:                     OCTET STRING
         :                       1B 2B 63 67 2C 3A AA EE D1 A7 01 9E D8 4F C5 1C
         :                       34 C4 74 C5 C3 DB 3C A9 1D 6E A8 A8 99 AE C6 19
         :                                       [ Bytes skipped ]
4472 1000:                     OCTET STRING
         :                       0C CC C5 AE 60 80 D0 2A EC B3 2B F8 A0 61 51 B7
         :                       D2 7A 91 B7 72 93 86 D5 AE B7 75 41 1A E2 63 B6
         :                                       [ Bytes skipped ]
5476  392:                     OCTET STRING
         :                       88 15 C9 EC 22 D9 23 7F 0F 9E 34 73 6A 0F 9B 9D
         :                       77 21 E2 81 E3 72 7D 63 77 16 7F C3 23 87 35 C2
         :                                       [ Bytes skipped ]
         :                     }
         :                   }
         :                 }
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
         :   } 

   This means that we have to perform a second level of defragmentation to 
   process the inner fragmented data.  We do this by rewriting the 
   fragmented portion as DER in a somewhat brute-force pattern-matching 
   manner, this doesn't fix up all of the lengths (there are three used
   close to the start of the data) but it's good enough to make it readable
   since cryptlib stops reading once it's processed the payload, only
   dumpasn1 continues and complains about mismatches in the length.
   
   Handling by other implementations varies, in particular PKCS #12 files 
   have a MAC attached at the end which will be invalidated so cryptlib 
   strips it, it's optional in the standard but whether an implementation 
   will actually allow it to be optional is anyone's guess.  However since 
   the conversion code also can't fix up the various internal length values 
   the resulting file also won't be valid for any parser that does strict 
   checking of nested data values.  Windows accepts the phase-1 processed 
   file, without the MAC, but not the phase-2 processed file ("Invalid 
   file"), probably because the internal length values don't match up.  
   Firefox doesn't accept the phase-1 processed file ("Failed to decode the 
   file") and accepts the phase-2 one but reports an incorrect password 
   ("Password incorrect").

   To convert it into a valid file, import the phase 2 output into cryptlib, 
   then write it as a PKCS #15 or PKCS #12 which will clean up the format 
   and produce the correctly-formatted file */

static int rewriteBorkenKeyFile1( const char *filename )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	FILE *filePtr;
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
	BYTE buffer[ BUFFER_SIZE ];
	const int filenameLength = strlen( filename );
	int length, status;

	fprintf( outputStream, "Converting broken PKCS #12 file %s, "
			 "phase 1...\n", filename ); 

	/* Read the source file into the data buffer */
	if( ( filePtr = fopen( filename, "rb" ) ) == NULL )
		{
		fprintf( outputStream, "Error: Couldn't open source keyset %s.\n", 
				 filename ); 
		return( FALSE );
		}
	length = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( length <= 0 || length >= BUFFER_SIZE )
		{
		fprintf( outputStream, "Error: %s is larger than %d bytes.\n", 
				 filename, BUFFER_SIZE ); 
		return( FALSE );
		}

	/* Make sure that we've got a fragmented PKCS #12 file */
	if( memcmp( filename + filenameLength - 4, ".p12", 4 ) || \
		memcmp( buffer, "\x30\x80\x02\x01\x03", 5 ) )
		{
		fprintf( outputStream, "Error: %s doesn't appear to be a "
				 "fragmented PKCS #12 file.\n", filename ); 
		return( FALSE );
		}

	/* De-envelope the fragmented data */
	status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED, 
								  CRYPT_FORMAT_AUTO );
	if( cryptStatusOK( status ) )
		{
		status = cryptPushData( cryptEnvelope, buffer + 5, length - 5, 
								&length );
		}
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptEnvelope );
	if( cryptStatusOK( status ) )
		{
		status = cryptPopData( cryptEnvelope, buffer, BUFFER_SIZE, 
							   &length );
		}
	cryptDestroyEnvelope( cryptEnvelope );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Error: Couldn't de-envelope fragmented "
				 "data.\n" ); 
		return( FALSE );
		}

	/* Re-envelope the data in non-fragmented form */
	status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED, 
								  CRYPT_FORMAT_CRYPTLIB );
	if( cryptStatusOK( status ) )
		{
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE, length );
		status = cryptPushData( cryptEnvelope, buffer, length, &length );
		}
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptEnvelope );
	if( cryptStatusOK( status ) )
		{
		status = cryptPopData( cryptEnvelope, buffer, BUFFER_SIZE, 
							   &length );
		}
	cryptDestroyEnvelope( cryptEnvelope );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Error: Couldn't re-envelope non-fragmented "
				 "data.\n" ); 
		return( FALSE );
		}

	/* Modify the filename from xxx.p12 to xxx_der1.p12.  This assumes that 
	   the filename has a specific form, which it does for the test keysets 
	   and which in any case has been checked earlier */
	memcpy( filenameBuffer, filename, filenameLength - 4 );
	memcpy( filenameBuffer + filenameLength - 4, "_der.p12", 8 + 1 );

	/* Write the non-fragmented enveloped data to the new filename.  We omit
	   the authentication gunk at the end of the data, which isn't used and
	   possibly (depending on how the fragmentation is interpreted) won't 
	   match the new data anyway */
	if( ( filePtr = fopen( filenameBuffer, "rb" ) ) != NULL )
		{
		fclose( filePtr );
		fprintf( outputStream, "Error: Destination keyset %s already "
				 "exists.\n", filenameBuffer ); 
		return( FALSE );
		}
	if( ( filePtr = fopen( filenameBuffer, "wb" ) ) == NULL )
		{
		fprintf( outputStream, "Error: Couldn't open destination keyset "
				 "%s.\n", filenameBuffer ); 
		return( FALSE );
		}
	fwrite( "\x30\x80\x02\x01\x03", 1, 5, filePtr );	/* Header */
	length = fwrite( buffer, 1, length, filePtr );
	fwrite( "\x00\x00", 1, 2, filePtr );				/* EOC */
	fclose( filePtr );
	if( length <= 0 )
		{
		fprintf( outputStream, "Error: Couldn't write destination keyset "
				 "%s.\n", filenameBuffer ); 
		return( FALSE );
		}

	return( TRUE );
	}

static int readLength( const BYTE *buffer, int *length )
	{
	if( *buffer < 0x80 )
		{
		*length = *buffer;
		return( 1 );
		}
	if( *buffer == 0x81 )
		{
		*length = buffer[ 1 ];
		return( 2 );
		}
	*length = buffer[ 1 ] << 8 | buffer[ 2 ];
	return( 3 );
	}

static int rewriteBorkenKeyFile2( const char *filename )
	{
	FILE *filePtr;
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
	BYTE buffer[ BUFFER_SIZE ], fragmentBuffer[ BUFFER_SIZE ];
	const int filenameLength = strlen( filename );
	int fragmentLength, fragmentTotalLength = 0;
	int totalLength, length, bufPos, dataStartPos;

	fprintf( outputStream, "Converting broken PKCS #12 file %s, "
			 "phase 2...\n", filename ); 

	/* Read the source file into the data buffer */
	if( ( filePtr = fopen( filename, "rb" ) ) == NULL )
		{
		fprintf( outputStream, "Error: Couldn't open source keyset %s.\n", 
				 filename ); 
		return( FALSE );
		}
	totalLength = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( totalLength <= 0 || totalLength >= BUFFER_SIZE )
		{
		fprintf( outputStream, "Error: %s is larger than %d bytes.\n", 
				 filename, BUFFER_SIZE ); 
		return( FALSE );
		}

	/* Make sure that we've got a fragmented PKCS #12 file */
	if( memcmp( filename + filenameLength - 4, ".p12", 4 ) || \
		memcmp( buffer, "\x30\x80\x02\x01\x03", 5 ) )
		{
		fprintf( outputStream, "Error: %s doesn't appear to be a "
				 "fragmented PKCS #12 file.\n", filename ); 
		return( FALSE );
		}

	/* Scan the file for the byte string A0 80 30 80 02 01 00 30, 
	   corresponding to:

		[0] {
			SEQUENCE {
				INTEGER 0,
				SEQUENCE {

	   which we need to convert into their definite-length equivalents */
	for( dataStartPos = 256; dataStartPos < totalLength - 1024; 
		 dataStartPos++ )
		{
		if( buffer[ dataStartPos ] != 0xA0 || \
			buffer[ dataStartPos + 1 ] != 0x80 )
			continue;
		if( !memcmp( buffer + dataStartPos, 
					 "\xA0\x80\x30\x80\x02\x01\x00\x30", 8 ) )
			break;
		}
	if( dataStartPos >= totalLength - 1024 )
		{
		fprintf( outputStream, "Error: Couldn't find indefinite-length "
				 "encrypted data in file.\n" ); 
		return( FALSE );
		}

	/* We're about to shorten the file length by quite a bit as we remove 
	   all of the fragmentation, and we also need to adjust the lengths
	   we're about to encode for the MAC trailer data.  Since we don't care
	   about the trailer and can afford to lose some of it, we estimate
	   losing about 16 bytes from the overall length even if that includes
	   some of the trailer */
	totalLength -= 16;
	#define TRAILER_SIZE	6

	/* Rewrite the initial indefinite SEQUENCE to its definite form */
	bufPos = dataStartPos + 1;
	memmove( buffer + bufPos + 3, buffer + bufPos + 1,	/* Remove 0x80 */
			 totalLength - bufPos );
	length = totalLength - ( bufPos + 11 + TRAILER_SIZE );
	buffer[ bufPos ] = 0x82;
	buffer[ bufPos + 1 ] = length >> 8;
	buffer[ bufPos + 2 ] = length & 0xFF;
	bufPos += 4;
	memmove( buffer + bufPos + 2, buffer + bufPos,	/* Remove 0x80 */
			 totalLength - bufPos );
	length = totalLength - ( bufPos + 11 + TRAILER_SIZE );
	buffer[ bufPos ] = 0x82;
	buffer[ bufPos + 1 ] = length >> 8;
	buffer[ bufPos + 2 ] = length & 0xFF;
	bufPos += 7; 
	memmove( buffer + bufPos + 2, buffer + bufPos,	/* Remove 0x80 */
			 totalLength - bufPos );
	length = totalLength - ( bufPos + 11 + TRAILER_SIZE );
	buffer[ bufPos ] = 0x82;
	buffer[ bufPos + 1 ] = length >> 8;
	buffer[ bufPos + 2 ] = length & 0xFF;

	/* Scan the file for the byte string A0 80 04 82 03 E8, corresponding to 
	   an indefinite-length [0] and the first 1024-byte fragment */
	for( dataStartPos = bufPos; dataStartPos < totalLength - 1024; 
		 dataStartPos++ )
		{
		if( buffer[ dataStartPos ] != 0xA0 || \
			buffer[ dataStartPos + 1 ] != 0x80 )
			continue;
		if( !memcmp( buffer + dataStartPos, "\xA0\x80\x04\x82\x03\xE8", 6 ) )
			break;
		}
	if( dataStartPos >= totalLength - 1024 )
		{
		fprintf( outputStream, "Error: Couldn't find fragmented payload "
				 "data in file.\n" ); 
		return( FALSE );
		}
	bufPos = dataStartPos + 2;	/* Skip A0 80 */

	/* Process each fragment and copy the contents across into the fragment 
	   assembly buffer */
	while( bufPos < totalLength - 14 )	/* 7 x EOCs */
		{
		if( buffer[ bufPos++ ] != 0x04 )
			{
			fprintf( outputStream, "Error: Lost fragment synchronisation "
					 "at position %d.\n", bufPos - 1 ); 
			return( FALSE );
			}
		bufPos += readLength( buffer + bufPos, &fragmentLength );
		memcpy( fragmentBuffer, buffer + bufPos, fragmentLength );
		fragmentTotalLength += fragmentLength;
		bufPos += fragmentLength;
		}

	/* Add the definite-length header and copy the data into place behind it */
	buffer[ dataStartPos ] = 0x80;
	buffer[ dataStartPos + 1 ] = 0x82;
	buffer[ dataStartPos + 2 ] = fragmentTotalLength >> 8;
	buffer[ dataStartPos + 3 ] = fragmentTotalLength;
	dataStartPos += 4;
	memcpy( buffer + dataStartPos, fragmentBuffer, fragmentTotalLength );

	/* Add five lots of EOCs, down from the seven that we stared with since 
	   we've converted some of the data to definite-length */
	memcpy( buffer + dataStartPos + fragmentTotalLength, 
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 
			4 );
	fragmentTotalLength += 4;

	/* Modify the filename from xxx.p12 to xxx_der2.p12.  This assumes that 
	   the filename has a specific form, which it does for the test keysets 
	   and which in any case has been checked earlier */
	memcpy( filenameBuffer, filename, filenameLength - 4 );
	memcpy( filenameBuffer + filenameLength - 4, "_der.p12", 8 + 1 );

	/* Write the non-fragmented enveloped data to the new filename.  We omit
	   the authentication gunk at the end of the data, which isn't used and
	   possibly (depending on how the fragmentation is interpreted) won't 
	   match the new data anyway */
	if( ( filePtr = fopen( filenameBuffer, "rb" ) ) != NULL )
		{
		fclose( filePtr );
		fprintf( outputStream, "Error: Destination keyset %s already "
				 "exists.\n", filenameBuffer ); 
		return( FALSE );
		}
	if( ( filePtr = fopen( filenameBuffer, "wb" ) ) == NULL )
		{
		fprintf( outputStream, "Error: Couldn't open destination keyset "
				 "%s.\n", filenameBuffer ); 
		return( FALSE );
		}
	totalLength = fwrite( buffer, 1, dataStartPos + fragmentTotalLength, 
						  filePtr );
	fclose( filePtr );
	if( totalLength <= 0 )
		{
		fprintf( outputStream, "Error: Couldn't write destination keyset "
				 "%s.\n", filenameBuffer ); 
		return( FALSE );
		}

	return( TRUE );
	}

/* Get a key from a PKCS #12 file.  Because of the security problems
   associated with this format, the code only checks the data format but
   doesn't try to read or use the keys.  If anyone wants this, they'll
   have to add the code themselves.  Your security warranty is automatically 
   void when you implement this */

static int borkenKeyImport( const int fileNo )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const C_STR userID;
	const C_STR password;
	BYTE buffer[ BUFFER_SIZE ];
	int status;

	/* Set up the file access information:
	
		Keyset #1 = CryptoAPI via OpenSSL, privKey with ID data and 3DES, 
			then anonymous cert with RC2/40.
		Keyset #2 = CryptoAPI, privKey with ID data and 3DES, then 
			anonymous cert with RC2/40.  The private key is identified via a 
			GUID which we can't do much with so we pass in the special-case 
			userID "[none]" meaning "return the first key that we find".
		Keyset #3 = Unknown source, cert chain in plaintext with ID data, 
			then privKey with ID data and 3DES.  The userID for the private 
			key is the single hex byte 0x8C, again we use "[none]" for this.
		Keyset #4 = OpenSSL, anonymous cert with RC2/40, then privKey with 
			ID data and 3DES.
		Keyset #5 = Unknown source (possibly OpenSSL), anonymous cert with
			RC2/40, then privKey with ID data and 3DES.  Unlike keyset #4
			the ID data doesn't include a userID, so we again have to resort
			to "[none]" to read it.
		Keyset #6 = Unknown source, from some CA that generates the private 
			key for you rather than allowing you to generate it, possibly 
			Buypass based on the encoding bug in the EncryptedContentInfo, 
			see below.  Contains mostly indefinite-length encodings of data, 
			currently not readable, see the comments in keyset/pkcs12_rd.c 
			for more details.  Even if this were readable, it encodes the 
			EncryptedContentInfo.encryptedContent as if it were declared as 
			"[0] EXPLICIT OCTET STRING" instead of
			"[0] IMPLICIT OCTET STRING", so the encoding is 
			"[0] { OCTET STRING { ...", which we can't even auto-detect since
			there's a 1/256 chance that any encrypted data block will appear
			to contain an OCTET STRING tag.
		Keyset #7 = Nexus 4 phone, DSA cert and private key.
		Keyset #8 = EJBCA, ECDSA cert and private key in no documented format
			(the code reads it from reverse-engineering the DER dump).
		Keyset #9 = Windows, ECDSA cert and private key, as above, created
			by importing and exporting Keyset #8 to/from Windows.
		Keyset #10 = Unknown source, RSA cert and private key.  In this case
			the certificate is unencrypted so we can at least read this.
		Keyset #11 = Norwegian CA, complete certificate chain with labels
			for subsequent certs that don't match the private-key label.
		Keyset #12 = OpenSSL, possibly the same type as #6.
		Keyset #13 = Unknown source and not a PKCS #12 but some weird mutant
			that turns into something PKCS #15-like after the outer PKCS #12 
			wrappers */
	switch( fileNo )
		{
		case 1:
			userID = TEXT( "test pkcs#12" );
			password = TEXT( "test" );
			break;

		case 2:
			userID = TEXT( "[none]" );		/* Label = GUID */
			password = TEXT( "<unknown>" );	/* Unknown, RC2=2C 28 14 C4 01 */
			break;
	
		case 3:
			userID = TEXT( "[none]" );		/* No label, ID = 0x8C */
			password = TEXT( "7OPWKMIX" );
			break;

		case 4:
			userID = TEXT( "server" );
			password = TEXT( "cryptlib" );
			break;

		case 5:
			userID = TEXT( "[none]" );		/* No label, ID = hash */
			password = TEXT( "password" );
			break;

		case 6:
			userID = TEXT( "SignLabel" );
			password = TEXT( "vpsign" );

			/* See comment above */
			return( TRUE );

		case 7:
			userID = TEXT( "ClientDSA" );
			password = TEXT( "nexus4" );
			break;

		case 8:
			userID = TEXT( "CMG" );
			password = TEXT( "skylight" );
			break;

		case 9:
			userID = TEXT( "[none]" );		/* Label = GUID */
			password = TEXT( "test" );
			break;

		case 10:
			userID = TEXT( "RSA private key" );
			password = TEXT( "test" );
			break;

		case 11:
			userID = TEXT( "[none]" );		/* Label = GUID */
			password = TEXT( "test" );
			break;

		case 12:
			userID = TEXT( "[none]" );
			password = TEXT( "1234" );
			break;

		case 13:
			userID = TEXT( "[none]" );
			password = TEXT( "yz7nWwC5Re7mAjA6" );
			break;

		default:
			assert( 0 );
			return( FALSE );
		}

	/* Open the file keyset.  Note that we print the usual test message only
	   after we try and open the keyset, in order to avoid a cascade of PKCS 
	   #12 file non-opened messages */
	filenameFromTemplate( buffer, PKCS12_FILE_TEMPLATE, fileNo );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  buffer, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) && status == CRYPT_ERROR_NOTAVAIL )
		{
		/* If support for this isn't enabled, just exit quietly */
		return( TRUE );
		}
	fprintf( outputStream, "Testing PKCS #12 file #%d import...\n", fileNo ); 
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the key, first the private key, which should work, and then 
	   opportunistically the public key, which typically won't work if it's
	   encrypted (!!) */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 userID, password );
	if( cryptStatusError( status ) )
		{
		switch( fileNo )
			{
			case 1:
				/* This file has a 512-bit key and will give a 
				   CRYPT_ERROR_NOSECURE on import */
				if( status == CRYPT_ERROR_NOSECURE )
					status = CRYPT_OK;
				break;

			case  2:
				/* This file has an unknown password, although the cracked 
				   RC2/40 key for it is 2C 28 14 C4 01 */
				if( status == CRYPT_ERROR_WRONGKEY )
					status = CRYPT_OK;
				break;

			case 3:
				/* This file contains an invalid private key, specifically
				   ( q * u ) mod p != 1 (!!!) */
				if( status == CRYPT_ERROR_INVALID )
					status = CRYPT_OK;
				break;
			
			case 10:
			case 11:
				/* More unknown-password keys */
				if( status == CRYPT_ERROR_WRONGKEY )
					status = CRYPT_OK;
				break;

			case 12:
				/* Contains multiple levels of fragmentation which, unless 
				   rewritten in nonfragmented form (see the comment at the
				   start of this section) leads to a decryption failure */
				if( status == CRYPT_ERROR_WRONGKEY )
					status = CRYPT_OK;
				break;
			}
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		}
	else
		{
		/* Make sure that we got a certificate alongside the private key */
		if( !checkCertPresence( cryptContext, "private key with certificate", 
								CRYPT_CERTTYPE_CERTIFICATE ) )
			return( FALSE );
		cryptDestroyContext( cryptContext );
		}
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								userID );
	if( cryptStatusError( status ) )
		{
		switch( fileNo )
			{
			case 1:
			case 2:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8:
			case 9:
			case 12:
			case 13:
				/* All of these files encrypt the certificate so that it 
				   can't be read using cryptGetPublicKey() */
				status = CRYPT_OK;
			}
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		}
	else
		cryptDestroyCert( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Read of key from PKCS #12 file #%d "
			 "succeeded.\n\n", fileNo ); 
	return( TRUE );
	}

int testReadAltFileKey( void )
	{
#ifdef USE_3DES
	int i;

	/* Optionally rewrite the broken Primekey-created multiple-fragmented 
	   PKCS #12 into an unfragmented form */
  #if 0
	rewriteBorkenKeyFile1( "test/keys/pkcs12_12_orig.p12" );
	rewriteBorkenKeyFile2( "test/keys/pkcs12_12_orig_der.p12" );
	/* Copy pkcs12_12_orig_der.p12 to pkcs12_12.p12 */
	borkenKeyImport( 12 );
  #endif /* 0 */

	for( i = 1; i <= 13; i++ )
		{
		if( !borkenKeyImport( i ) )
			return( FALSE );
		}
#else
	fputs( "Skipping alternative key file read since 3DES isn't "
		   "available.\n\n", outputStream );
#endif /* USE_3DES */

	return( TRUE );
	}
#else

int testReadAltFileKey( void )
	{
	fputs( "Skipping alternative key file read.\n\n", outputStream );
	return( TRUE );
	}
#endif /* USE_PKCS12 */

/****************************************************************************
*																			*
*						Public/Private Key Read/Write Tests					*
*																			*
****************************************************************************/

/* Read/write a private key from a file */

static int readFileKey( const CRYPT_ALGO_TYPE cryptAlgo,
						const CRYPT_FORMAT_TYPE formatType,
						const BOOLEAN useWildcardRead )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const char *keyFileDescr = \
			( formatType == CRYPT_FORMAT_NONE ) ? "alternative " : \
			( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "";
	int status;

	fprintf( outputStream, "Testing %s private key read from %skey "
			 "file%s...\n", algoName( cryptAlgo ), keyFileDescr,
			 useWildcardRead ? " using wildcard ID" : "" );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  ( formatType == CRYPT_FORMAT_NONE ) ? \
								TEST_PRIVKEY_ALT_FILE : \
							  ( formatType == CRYPT_FORMAT_PGP ) ? \
								TEST_PRIVKEY_PGP_FILE : TEST_PRIVKEY_FILE,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		if( ( formatType != CRYPT_FORMAT_CRYPTLIB ) && \
			( status == CRYPT_ERROR_NOTAVAIL ) )
			{
			/* If the format isn't supported, this isn't a problem */
			fputs( "Read of RSA private key from alternative key file "
				   "skipped as this format is\ndisabled.\n\n", 
				   outputStream );
			return( TRUE );
			}
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	if( formatType == CRYPT_FORMAT_PGP )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME, useWildcardRead ? \
										TEXT( "[none]" ) : getAlgoLabel( cryptAlgo ) );
		}
	else
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, useWildcardRead ? \
										TEXT( "[none]" ) : getAlgoLabel( cryptAlgo ),
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can use the read key unless its a PGP key, for 
	   which we only have the public key */
	if( cryptAlgo == CRYPT_ALGO_RSA && formatType != CRYPT_FORMAT_PGP )
		{
		status = testCrypt( cryptContext, cryptContext, cryptAlgo, NULL, 
							FALSE, FALSE );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Read of %s private key from %skey file "
			 "succeeded.\n\n", algoName( cryptAlgo ), keyFileDescr );
	return( TRUE );
	}

static int writeFileKey( const CRYPT_ALGO_TYPE cryptAlgo, 
						 const CRYPT_FORMAT_TYPE formatType,
						 const BOOLEAN createFile,
						 const BOOLEAN generateKey )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT privateKeyContext;
	const char *keyFileDescr = \
			( formatType == CRYPT_FORMAT_NONE ) ? "alternative " : \
			( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "";
	int status;

	fprintf( outputStream, "Testing %s private key write to %skey "
			 "file...\n", algoName( cryptAlgo ), keyFileDescr );

	/* Create the private key context */
	if( generateKey )
		{
		status = cryptCreateContext( &privateKeyContext, CRYPT_UNUSED, 
									 cryptAlgo );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( privateKeyContext, 
											  CRYPT_CTXINFO_LABEL, 
											  getAlgoLabel( cryptAlgo ), 
											  paramStrlen( getAlgoLabel( cryptAlgo ) ) );
			}
		if( cryptStatusOK( status ) )
			status = cryptGenerateKey( privateKeyContext );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	else
		{
		if( !loadPrivateKeyContext( &privateKeyContext, cryptAlgo ) )
			return( FALSE );
		}

	/* Create/open the file keyset.  For the first call (with RSA) we create
	   a new keyset, for subsequent calls we update the existing keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  ( formatType == CRYPT_FORMAT_NONE ) ? \
								TEST_PRIVKEY_ALT_FILE : \
							  ( formatType == CRYPT_FORMAT_PGP ) ? \
								TEST_PRIVKEY_PGP_FILE : TEST_PRIVKEY_FILE,
								createFile ? CRYPT_KEYOPT_CREATE : \
											 CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( privateKeyContext );
		if( ( formatType != CRYPT_FORMAT_CRYPTLIB ) && \
			( status == CRYPT_ERROR_NOTAVAIL ) )
			{
			/* If the format isn't supported, this isn't a problem */
			fputs( "Write of RSA private key to alternative key file "
				   "skipped as this format is\ndisabled.\n\n", 
				   outputStream );
			return( CRYPT_ERROR_NOTAVAIL );
			}
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Write the key to the file */
	if( formatType == CRYPT_FORMAT_PGP )
		status = cryptAddPublicKey( cryptKeyset, privateKeyContext );
	else
		{
		status = cryptAddPrivateKey( cryptKeyset, privateKeyContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( privateKeyContext );
	fprintf( outputStream, "Write of %s private key to %skey file "
			 "succeeded.\n\n", algoName( cryptAlgo ), keyFileDescr );
	return( TRUE );
	}

int testReadWriteFileKey( void )
	{
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RSA, NULL ) ) ) 
		{
		if( !writeFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_CRYPTLIB, TRUE, FALSE ) )
			return( FALSE );
		if( !readFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_CRYPTLIB, FALSE ) )
			return( FALSE );
		if( !readFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_CRYPTLIB, TRUE ) )
			return( FALSE );
		if( !writeFileKey( CRYPT_ALGO_DSA, CRYPT_FORMAT_CRYPTLIB, FALSE, FALSE ) )
			return( FALSE );
		}
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_DSA, NULL ) ) ) 
		{
		if( !readFileKey( CRYPT_ALGO_DSA, CRYPT_FORMAT_CRYPTLIB, FALSE ) )
			return( FALSE );
		}
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ELGAMAL, NULL ) ) ) 
		{
		if( !writeFileKey( CRYPT_ALGO_ELGAMAL, CRYPT_FORMAT_CRYPTLIB, FALSE, FALSE ) )
			return( FALSE );
		if( !readFileKey( CRYPT_ALGO_ELGAMAL, CRYPT_FORMAT_CRYPTLIB, FALSE ) )
			return( FALSE );
		}
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) )
		{
		if( !writeFileKey( CRYPT_ALGO_ECDSA, CRYPT_FORMAT_CRYPTLIB, FALSE, FALSE ) )
			return( FALSE );
		if( !readFileKey( CRYPT_ALGO_ECDSA, CRYPT_FORMAT_CRYPTLIB, FALSE ) )
			return( FALSE );
		}
	return( TRUE );
	}

int testReadWriteAltFileKey( void )
	{
#ifdef USE_3DES
	int status;

	/* We use CRYPT_FORMAT_NONE to denote the alternative format to the 
	   standard PKCS #15.  This requires the use of 3DES so we make its use
	   conditional on 3DES being enabled */
	status = writeFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_NONE, TRUE, FALSE );
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		/* Alternative keyset access not available */
		return( TRUE );
		}
	if( status != TRUE )
		return( FALSE );
	return( readFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_NONE, FALSE ) );
#else
	fputs( "Skipping alternative key file test since 3DES isn't "
		   "available.\n\n", outputStream );
	return( TRUE );
#endif /* USE_3DES */
	}

int testReadWritePGPFileKey( void )
	{
	/* To display the written keyring data:

		gpg --list-sigs --keyring .\test.pgp
		gpg --check-sigs --keyring .\test.pgp
		gpg --list-keys --keyring .\test.pgp */
	if( !writeFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_PGP, TRUE, FALSE ) )
		return( FALSE );
	return( readFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_PGP, FALSE ) );
	}

#if 0	/* Disabled until we can get valid third-party PKCS #15 test data */

static int fileKeyImport( const int fileNo )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	BYTE buffer[ BUFFER_SIZE ];
	int status;

	fprintf( outputStream, "Testing PKCS #15 file #%d import...\n", fileNo );

	/* Open the file keyset */
	filenameFromTemplate( buffer, P15_FILE_TEMPLATE, fileNo );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  buffer, CRYPT_KEYOPT_READONLY );
	if( fileNo == 1 && status == CRYPT_ERROR_OVERFLOW )
		{
		/* Depending on the setting of MAX_PKCS15_OBJECTS this keyset may 
		   contain too many keys to be read, if we get an overflow error we
		   continue normally */
		fprintf( outputStream, "Keyset contains too many items to read, "
				 "line %d.\n  (This is an expected condition, "
				 "continuing...).\n", __LINE__ );
		return( TRUE );
		}
	if( fileNo == 2 && status == CRYPT_ERROR_BADDATA )
		{
		/* This test file is from a pre-release implementation and may not
		   necessarily be correct so we don't complain in the case of 
		   errors */
		fputs( "Skipping keyset containing specil-case data values.\n\n", 
			   outputStream );
		return( TRUE );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	if( fileNo == 1 )
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, TEXT( "John Smith 0" ),
									 TEXT( "password" ) );
		}
	else
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, TEXT( "key and chain" ),
									 TEXT( "password" ) );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* 0 */

int testImportFileKey( void )
	{
#if 0	/* Disabled until we can get valid third-party PKCS #15 test data */
	int i;

	for( i = 1; i <= 1; i++ )
		{
		if( !fileKeyImport( i ) )
			return( FALSE );
		}
#endif /* 0 */

	return( TRUE );
	}

/* Read only the public key/certificate/certificate chain portion of a 
   keyset */

int testReadFilePublicKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int cryptAlgo, status;

	fputs( "Testing public key read from key file...\n", outputStream );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the public key from the file and make sure that it really is a
	   public-key context */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								RSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, &cryptAlgo );
	if( cryptStatusError( status ) || \
		cryptAlgo < CRYPT_ALGO_FIRST_PKC || cryptAlgo > CRYPT_ALGO_LAST_PKC )
		{
		fputs( "Returned object isn't a public-key context.\n", outputStream );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( cryptContext );

	fputs( "Read of public key from key file succeeded.\n\n", outputStream );
	return( TRUE );
	}

static int readCert( const char *certTypeName,
					 const CRYPT_CERTTYPE_TYPE certType,
					 const BOOLEAN readPrivateKey )
	{
	CRYPT_KEYSET cryptKeyset;
	int value, status;

	fprintf( outputStream, "Testing %s read from key file...\n", 
			 certTypeName );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the certificate from the file and make sure that it really is a
	   certificate */
	if( readPrivateKey )
		{
		CRYPT_CONTEXT cryptContext;

		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
									 TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		if( !checkCertPresence( cryptContext, certTypeName, certType ) )
			return( FALSE );
		cryptDestroyContext( cryptContext );
		}
	else
		{
		CRYPT_CERTIFICATE cryptCert;

		status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NAME,
									( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? \
									RSA_PRIVKEY_LABEL : USER_PRIVKEY_LABEL );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		status = cryptGetAttribute( cryptCert, CRYPT_CERTINFO_CERTTYPE, &value );
		if( cryptStatusError( status ) || value != certType )
			{
			fprintf( outputStream, "Returned object isn't a %s, line %d.\n", 
					 certTypeName, __LINE__ );
			return( FALSE );
			}
		cryptDestroyCert( cryptCert );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Read of %s from key file succeeded.\n\n", 
			 certTypeName );
	return( TRUE );
	}

int testReadFileCert( void )
	{
	return( readCert( "certificate", CRYPT_CERTTYPE_CERTIFICATE, FALSE ) );
	}
int testReadFileCertPrivkey( void )
	{
	return( readCert( "private key with certificate", CRYPT_CERTTYPE_CERTIFICATE, TRUE ) );
	}
int testReadFileCertChain( void )
	{
	return( readCert( "certificate chain", CRYPT_CERTTYPE_CERTCHAIN, FALSE ) );
	}

/* Test the ability to read older versions of PKCS #15 keysets */

static int readOldKey( const int version )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const char *keysetName;
	char fileName[ BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	int status;

	/* Open the keyset corresponding to the given cryptlib version */
	filenameFromTemplate( fileName, P15_OLD_FILE_TEMPLATE, version );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, fileName, strlen( fileName ) + 1 );
	keysetName = wcBuffer;
#else
	keysetName = fileName;
#endif /* UNICODE_STRINGS */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
							  fileName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() for version 3%d failed "
				 "with error code %d, line %d.\n", version, status, 
				 __LINE__ );
		return( FALSE );
		}

	/* Fetch the private key */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, USER_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		fprintf( outputStream, "cryptGetPrivateKey() for version 3%d failed "
				 "with error code %d, line %d.\n", version, status, 
				 __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );
	cryptKeysetClose( cryptKeyset );

	return( TRUE );
	}

int testReadOldKey( void )
	{
	int i;

	fputs( "Testing read of older key formats...\n", outputStream );

	/* Test each keyset from 3.4.7 to 3.4.0.  Note that as of 3.4.6 we don't 
	   test the 3.4.0 keyset, which was based on an RFC draft that didn't 
	   MAC the EncryptedContentInfo.ContentEncryptionAlgorithmIdentifier and 
	   used a 128-bit HMAC-SHA1 key instead of a 160-bit one.  Versions from 
	   3.4.1 to 3.4.5 contained a workaround which MAC'd the data in a 3.4.0-
	   compatible manner if the original MAC calculation failed, however 
	   this was removed in 3.4.6 when 3.4.0 was more than a decade old */
	for( i = 47; i >= 41; i-- )
		{
		if( !readOldKey( i ) )
			return( FALSE );
		}

	fputs( "Read of older key formats succeeded.\n\n", outputStream );

	return( TRUE );
	}

/* Test the ability to detect key data corruption/modification */

int testReadCorruptedKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int i, status;

	fputs( "Testing detection of key corruption in key file...\n", 
		   outputStream );
	for( i = 0; i < 4; i++ )
		{
		/* Copy the file to a temporary one, corrupting a data byte in the 
		   process */
		status = copyModifiedFile( TEST_PRIVKEY_FILE, TEST_PRIVKEY_TMP_FILE, 
								   256 );
		if( !status )
			{
			fprintf( outputStream, "Couldn't copy keyset to temporary file, "
					 "line %d.\n", __LINE__ );
			return( FALSE );
			}

		/* Try and read the key.  The open should succeed, the read should 
		   fail */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
								  CRYPT_KEYSET_FILE, TEST_PRIVKEY_TMP_FILE, 
								  CRYPT_KEYOPT_READONLY );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptKeysetOpen() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
									 TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) )
			{
			cryptDestroyContext( cryptContext );
			fprintf( outputStream, "Read of corrupted key succeeded when it "
					 "should have failed, line %d.\n", __LINE__ );
			return( FALSE );
			}
		cryptKeysetClose( cryptKeyset );
		}
	fputs( "Detection of key corruption succeeded.\n\n", outputStream );

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Certificate Read/Write Tests					*
*																			*
****************************************************************************/

/* Update a keyset to contain a certificate */

int testAddTrustedCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE trustedCert;
	int value, status;

	fputs( "Testing trusted certificate add to key file...\n", 
		   outputStream );

	/* Read the CA root certificate.  We have to make it explicitly non-
	   trusted since something else may have made it trusted previously */
	status = importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	if( cryptStatusError( status ) )
		{
		fputs( "Couldn't read certificate from file, skipping test of trusted "
			   "certificate write...\n\n", outputStream );
		return( TRUE );
		}
	status = cryptGetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
								&value );
	if( cryptStatusOK( status ) && value )
		{
		cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
						   FALSE );
		}

	/* Open the keyset, update it with the trusted certificate, and close it.
	   Before we make the certificate trusted, we try adding it as a standard 
	   certificate, which should fail */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "cryptAddPublicKey() of non-trusted "
				 "certificate succeeded when it should have failed, "
				 "line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, value );
	cryptDestroyCert( trustedCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Trusted certificate add to key file succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

int testAddGloballyTrustedCert( void )
	{
	CRYPT_CERTIFICATE trustedCert;
	int status;

	fputs( "Testing globally trusted certificate add...\n", outputStream );

	/* Read the CA root certificate and make it trusted */
	status = importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	if( cryptStatusError( status ) )
		{
		fputs( "Couldn't read certificate from file, skipping test of trusted "
			   "certificate write...\n\n", outputStream );
		return( TRUE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );

	/* Update the config file with the globally trusted certificate */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED,
								FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Globally trusted certificate add failed "
				 "with error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Make the certificate untrusted and update the config again */
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, FALSE );
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED,
								FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Globally trusted certificate delete failed "
				 "with error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Globally trusted certificate add succeeded.\n\n", outputStream );
	return( TRUE );
	}

static const CERT_DATA cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and CA" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Himself" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Certification Division" ) },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* CA key usage */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_PATHLENCONSTRAINT, IS_NUMERIC, 1 },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testUpdateFileCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT publicKeyContext, privateKeyContext;
	int status;

	fputs( "Testing certificate update to key file...\n", outputStream );

	/* Create a self-signed CA certificate using the in-memory key (which is
	   the same as the one in the keyset) */
	if( !loadRSAContexts( CRYPT_UNUSED, &publicKeyContext, &privateKeyContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, publicKeyContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCert, cACertData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, privateKeyContext );
	destroyContexts( CRYPT_UNUSED, publicKeyContext, privateKeyContext );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Certificate creation failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the keyset, update it with the certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Certificate update to key file succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Update a keyset to contain a certificate chain */

static int writeFileCertChain( const CERT_DATA *certRequestData,
							   const C_STR keyFileName,
							   const BOOLEAN writeLongChain )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey, cryptKey;
	int status;

	fprintf( outputStream, "Testing %scert chain write to key file ...\n",
			 writeLongChain ? "long " : "" );

	/* Generate a key to certify.  We can't just reuse the built-in test key
	   because this has already been used as the CA key and the keyset code
	   won't allow it to be added to a keyset as both a CA key and user key,
	   so we have to generate a new one */
	status = cryptCreateContext( &cryptKey, CRYPT_UNUSED, CRYPT_ALGO_RSA );
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
		status = getPrivateKey( &cryptCAKey, ICA_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		}
	else
		{
		status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
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
	cryptDestroyCert( cryptCertChain );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Certificate chain write to key file succeeded.\n\n", 
		   outputStream );

	return( TRUE );
	}

static const CERT_DATA certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },
	{ CRYPT_CERTINFO_EMAIL, IS_STRING, 0, TEXT( "dave@wetaburgers.com" ) },
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },	/* Re-select subject DN */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testWriteFileCertChain( void )
	{
	return( writeFileCertChain( certRequestData, TEST_PRIVKEY_FILE, 
								FALSE ) );
	}

int testWriteFileLongCertChain( void )
	{
	return( writeFileCertChain( certRequestData, TEST_PRIVKEY_FILE, 
								TRUE ) );
	}

/* Delete a key from a file */

int testDeleteFileKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	fputs( "Testing delete from key file...\n", outputStream );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Delete the key from the file.  Since we don't need the DSA key any
	   more we use it as the key to delete */
	status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
							 DSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptDeletePrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								DSA_PRIVKEY_LABEL );
	if( cryptStatusOK( status ) )
		{
		cryptDestroyContext( cryptContext );
		fputs( "cryptDeleteKey() claimed the key was deleted but it's still "
			   "present.\n", outputStream );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Delete from key file succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Change the password for a key in a file */

int testChangeFileKeyPassword( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	fputs( "Testing change of key password for key file...\n", 
		   outputStream );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the key using the old password, delete it, and write it back
	   using the new password.  To keep things simple we just use the same
	   password (since the key will be used again later), the test of the
	   delete function earlier on has already confirmed that the old key
	   and password will be deleted so there's no chance of a false positive */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
								 RSA_PRIVKEY_LABEL );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "password change", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Password change for key in key file succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

/* Write a key and certificate to a file in a single operation */

static int writeSingleStepFileCert( const CRYPT_ALGO_TYPE cryptAlgo,
									const BOOLEAN useAltKeyFile,
									const BOOLEAN useCombinedKeyCert )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert DUMMY_INIT;
	CRYPT_CONTEXT cryptContext;
	const C_STR userName = useCombinedKeyCert ? \
						   USER_PRIVKEY_LABEL : getAlgoLabel( cryptAlgo );
	int status;

	fprintf( outputStream, "Testing single-step %s key+certificate write to "
			 "%skey file...\n", algoName( cryptAlgo ), 
			 useAltKeyFile ? "alternative " : "" );

	if( useCombinedKeyCert )
		{
		char filenameBuffer[ FILENAME_BUFFER_SIZE ];

		assert( cryptAlgo == CRYPT_ALGO_RSA );

		/* Read a combined private key + certificate object */
		filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 1 );
		status = getPrivateKey( &cryptContext, filenameBuffer, 
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Private key + certificate read failed "
					 "with error code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	else
		{
		/* Create a self-signed CA certificate */
		if( !loadPrivateKeyContext( &cryptContext, cryptAlgo ) )
			return( FALSE );
		status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
								  CRYPT_CERTTYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptCreateCert() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptSetAttribute( cryptCert,
									CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, 
									cryptContext );
		if( cryptStatusOK( status ) && \
			!addCertFields( cryptCert, cACertData, __LINE__ ) )
			return( FALSE );
		if( cryptStatusOK( status ) )
			status = cryptSignCert( cryptCert, cryptContext );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Certificate creation failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			cryptDestroyCert( status );
			return( FALSE );
			}
		}

	/* Open the keyset, write the key and certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
					useAltKeyFile ? TEST_PRIVKEY_ALT_FILE : TEST_PRIVKEY_FILE,
					CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		if( !useCombinedKeyCert )
			cryptDestroyCert( cryptCert );
		if( useAltKeyFile && status == CRYPT_ERROR_NOTAVAIL )
			{
			/* If the format isn't supported, this isn't a problem */
			fputs( "Single-step update to alternative key file "
				   "skipped as this form is\ndisabled.\n\n", 
				   outputStream );
			return( CRYPT_ERROR_NOTAVAIL );
			}
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		/* The alternative format can't store RSA keys unless they contain
		   additional, unused parameters, so we don't treat this as a
		   fatal error */
		if( useAltKeyFile && useCombinedKeyCert && \
			status == CRYPT_ERROR_NOTAVAIL )
			{
			fprintf( outputStream, "%s key+certificate doesn't contain "
					 "additional unused parameters required\n  by the "
					 "alternative format and can't be written to the "
					 "keyset.\n", algoName( cryptAlgo ) );
			fputs( "  (This is an expected result since this test verifies "
				   "handling of\n   this key type).\n\n", outputStream );

			cryptDestroyContext( cryptContext );
			cryptKeysetClose( cryptKeyset );

			return( TRUE );
			}

		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	if( !useCombinedKeyCert )
		{
		status = cryptAddPublicKey( cryptKeyset, cryptCert );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptAddPublic/PrivateKey()", 
						   status, __LINE__ );
			return( FALSE );
			}
		cryptDestroyCert( cryptCert );
		}
	cryptDestroyContext( cryptContext );

	/* Try and read the key+certificate back before we close the keyset.  
	   This ensures that the in-memory data has been updated correctly */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
								 CRYPT_KEYID_NAME, userName,
								 TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		printExtError( cryptKeyset, 
					   "private key read from in-memory cached keyset data", 
					   status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset, which flushes the in-memory changes to disk.  The
	   cacheing of data in memory ensures that all keyset updates are atomic,
	   so that it's nearly impossible to corrupt a private key keyset during
	   an update */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Try and read the key+certificate back from disk rather than the 
	   cached, in-memory version */
	status = getPrivateKey( &cryptContext, 
							useAltKeyFile ? \
								TEST_PRIVKEY_ALT_FILE : TEST_PRIVKEY_FILE,
							userName, TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, 
					   "private key read from on-disk keyset data", 
					   status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Single-step %s key+certificate write to %skey "
			 "file succeeded.\n\n", algoName( cryptAlgo ), 
			 useAltKeyFile ? "alternative " : "" );
	return( TRUE );
	}

int testSingleStepFileCert( void )
	{
	if( !writeSingleStepFileCert( CRYPT_ALGO_RSA, FALSE, FALSE ) )
		return( FALSE );
	if( !writeSingleStepFileCert( CRYPT_ALGO_RSA, FALSE, TRUE ) )
		return( FALSE );
	if( !writeSingleStepFileCert( CRYPT_ALGO_DSA, FALSE, FALSE ) )
		return( FALSE );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) && \
		!writeSingleStepFileCert( CRYPT_ALGO_ECDSA, FALSE, FALSE ) )
		return( FALSE );
	return( TRUE );
	}

int testSingleStepAltFileCert( void )
	{
#ifdef USE_3DES
	int status;

	/* Note that the combined key + cert test has to come first since this
	   will fail and leave no keyset written, while the standard test will
	   leave the keyset available for later */
	status = writeSingleStepFileCert( CRYPT_ALGO_RSA, TRUE, TRUE );
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		/* Alternative keyset access not available */
		return( TRUE );
		}
	if( status != TRUE )
		return( FALSE );
	if( !writeSingleStepFileCert( CRYPT_ALGO_RSA, TRUE, FALSE ) )
		return( FALSE );
#else
	fputs( "Skipping alternative key file single-step test since 3DES "
		   "isn't available.\n\n", outputStream );
#endif /* USE_3DES */
	return( TRUE );
	}

/* Write two keys and certs (signature + encryption) with the same DN to a
   file */

int testDoubleCertFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptSigCert, cryptEncryptCert;
	CRYPT_CONTEXT cryptCAKey, cryptSigContext, cryptEncryptContext;
	int status;

	fputs( "Testing separate signature+encryption certificate write to key "
		   "file...\n", outputStream );
	doubleCertOK = FALSE;

	/* Get the CA's key */
	status = getCAPrivateKey( &cryptCAKey, FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Generate two keys to certify.  We can't just use the built-in test key
	   because cryptlib will detect it being added to the keyset a second time
	   (if we reuse it for both keys) and because the label is a generic one
	   that doesn't work if there are two keys */
	status = cryptCreateContext( &cryptSigContext, CRYPT_UNUSED,
								 CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSigContext,
							CRYPT_CTXINFO_LABEL, DUAL_SIGNKEY_LABEL,
							paramStrlen( DUAL_SIGNKEY_LABEL ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptSigContext );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Test key generation failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCreateContext( &cryptEncryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptEncryptContext,
							CRYPT_CTXINFO_LABEL, DUAL_ENCRYPTKEY_LABEL,
							paramStrlen( DUAL_ENCRYPTKEY_LABEL ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptEncryptContext );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Test key generation failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the certs containing the keys.  In order to avoid clashes with
	   other keys with the same CN in the public-key database, we give the
	   certs abnormal CNs.  This isn't necessary for cryptlib to manage them,
	   but because later code tries to delete leftover certs from previous
	   runs with the generic name used in the self-tests, which would also
	   delete these certs */
	status = cryptCreateCert( &cryptSigCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSigCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptSigContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptSigCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteAttribute( cryptSigCert,
									   CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSigCert,
					CRYPT_CERTINFO_COMMONNAME, TEXT( "Dave Smith (Dual)" ),
					paramStrlen( TEXT( "Dave Smith (Dual)" ) ) );
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSigCert,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_KEYUSAGE_DIGITALSIGNATURE );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptSigCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Signature certificate creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptSigCert );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptEncryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptEncryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptEncryptContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptEncryptCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteAttribute( cryptEncryptCert,
									   CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptEncryptCert,
					CRYPT_CERTINFO_COMMONNAME, TEXT( "Dave Smith (Dual)" ),
					paramStrlen( TEXT( "Dave Smith (Dual)" ) ) );
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptEncryptCert,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_KEYUSAGE_KEYENCIPHERMENT );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptEncryptCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Encryption certificate creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptEncryptCert );
		return( FALSE );
		}
	cryptDestroyContext( cryptCAKey );

	/* Open the keyset, write the keys and certificates, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  DUAL_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptSigContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptEncryptContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptSigCert );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptEncryptCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Write the two certs to a public-key database if there's one available
	   (because it may not be present, we fail quietly if access to this
	   keyset type isn't available or the keyset isn't present, it'll be
	   picked up later by other tests).

	   This certificate write is needed later to test the encryption vs. 
	   signature certificate handling.  Since they may have been added 
	   earlier we try and delete them first (we can't use the existing 
	   version since the issuerAndSerialNumber won't match the ones in the 
	   private-key keyset) */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_NONE );
	if( status != CRYPT_ERROR_PARAM3 && status != CRYPT_ERROR_OPEN )
		{
		C_CHR name[ CRYPT_MAX_TEXTSIZE + 1 ];
		int length;

		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptKeysetOpen() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			if( status == CRYPT_ERROR_OPEN )
				return( CRYPT_ERROR_FAILED );
			return( FALSE );
			}
		status = cryptGetAttributeString( cryptSigCert, 
										  CRYPT_CERTINFO_COMMONNAME,
										  name, &length );
		if( cryptStatusError( status ) )
			return( FALSE );
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		name[ length ] = TEXT( '\0' );
		do
			status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, name );
		while( cryptStatusOK( status ) );
		if( status != CRYPT_ERROR_NOTFOUND )
			{
			/* Deletion of the existing keys failed for some reason, we can't
			   continue */
			return( extErrorExit( cryptKeyset, "cryptDeleteKey()",
								  status, __LINE__ ) );
			}
		status = cryptAddPublicKey( cryptKeyset, cryptSigCert );
		if( status != CRYPT_ERROR_NOTFOUND )
			{
			/* We can get a notfound if a database keyset is defined but
			   hasn't been initialised yet so the necessary tables don't
			   exist, it can be opened but an attempt to add a key will
			   return a not found error since it's the table itself rather
			   than any item within it that isn't being found */
			if( cryptStatusOK( status ) )
				status = cryptAddPublicKey( cryptKeyset, cryptEncryptCert );
			if( cryptStatusError( status ) )
				{
				return( extErrorExit( cryptKeyset, "cryptAddPublicKey()",
									  status, __LINE__ ) );
				}

			/* The double-certificate keyset is set up, remember this for 
			   later tests */
			doubleCertOK = TRUE;
			}
		cryptKeysetClose( cryptKeyset );
		}

	/* Clean up */
	cryptDestroyContext( cryptSigContext );
	cryptDestroyContext( cryptEncryptContext );
	cryptDestroyCert( cryptSigCert );
	cryptDestroyCert( cryptEncryptCert );

	/* Try and read the keys+certs back */
	status = getPrivateKey( &cryptSigContext, DUAL_PRIVKEY_FILE,
							DUAL_SIGNKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptSigContext );
	if( cryptStatusOK( status ) )
		{
		status = getPrivateKey( &cryptEncryptContext, DUAL_PRIVKEY_FILE,
								DUAL_ENCRYPTKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		cryptDestroyContext( cryptEncryptContext );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	fputs( "Separate signature+encryption certificate write to key file "
		   "succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Write a key and two certs of different validity periods to a file */

#ifndef _WIN32_WCE	/* Windows CE doesn't support ANSI C time functions */

int testRenewedCertFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptOldCert, cryptNewCert;
	CRYPT_CONTEXT cryptCAKey, cryptContext;
	time_t writtenValidTo = 0 /* Dummy */, readValidTo;
	int dummy, status;

	fputs( "Testing renewed certificate write to key file...\n", 
		   outputStream );

	/* Get the CA's key and the key to certify */
	status = getCAPrivateKey( &cryptCAKey, FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptContext ) )
		return( FALSE );

	/* Create the certs containing the keys */
	status = cryptCreateCert( &cryptOldCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptOldCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptOldCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		time_t validity = time( NULL );

		/* Valid for one month ending tomorrow (we can't make it already-
		   expired or cryptlib will complain) */
		validity += 86400;
		cryptSetAttributeString( cryptOldCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		validity -= ( 86400 * 31 );
		status = cryptSetAttributeString( cryptOldCert,
					CRYPT_CERTINFO_VALIDFROM, &validity, sizeof( time_t ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptOldCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Signature certificate creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptOldCert );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptNewCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptNewCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptNewCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		time_t validity = time( NULL );

		/* Valid for one month starting yesterday (it's actually valid for
		   one month + one day to sidestep the one-month sanity check in the
		   private key read code that warns of about-to-expire keys) */
		validity -= 86400;
		cryptSetAttributeString( cryptNewCert,
					CRYPT_CERTINFO_VALIDFROM, &validity, sizeof( time_t ) );
		validity += ( 86400 * 32 );
		status = cryptSetAttributeString( cryptNewCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		writtenValidTo = validity;
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptNewCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Encryption certificate creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptNewCert );
		return( FALSE );
		}
	cryptDestroyContext( cryptCAKey );

	/* First, open the keyset, write the key and certificates (using an
	   in-memory update), and close it.  This tests the ability to use
	   information cached in memory to handle the update */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptOldCert );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptNewCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, 
					   "cryptAddPublicKey() (in-memory update)", 
					   status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Then try again, but this time perform an on-disk update, closing the
	   keyset between the first and second update.  This tests the ability
	   to recover the information needed to handle the update from data in
	   the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptOldCert );
	if( cryptStatusOK( status ) )
		status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Keyset creation in preparation for on-disk "
				 "update failed with error code %d, line %d.\n", status, 
				 __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptNewCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey() (on-disk update)", 
					   status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( cryptContext );
	cryptDestroyCert( cryptOldCert );
	cryptDestroyCert( cryptNewCert );

	/* Try and read the (newest) key+certificate back */
	status = getPrivateKey( &cryptContext, RENEW_PRIVKEY_FILE,
							RSA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttributeString( cryptContext,
					CRYPT_CERTINFO_VALIDTO, &readValidTo, &dummy );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptContext, "cryptGetAttributeString",
							  status, __LINE__ ) );
		}
	if( writtenValidTo != readValidTo )
		{
		const int diff = ( int ) ( readValidTo - writtenValidTo );
		const char *units = ( diff % 60 ) ? "seconds" : "minutes";

		fprintf( outputStream, "Returned certificate != latest valid "
				 "certificate, diff.= %d %s, line %d.\n", 
				 ( diff % 60 ) ? diff : diff / 60, units, __LINE__ );
		if( diff == 3600 || diff == -3600 )
			{
			/* See the comment on DST issues in testcert.c */
			fputs( "  (This is probably due to a difference between DST at "
				   "certificate creation and DST\n   now, and isn't a "
				   "serious problem).\n\n", outputStream );
			}
		else
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	fputs( "Renewed certificate write to key file succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

#else

int testRenewedCertFile( void )
	{
	/* Since the renewal is time-based, we can't easily test this under
	   WinCE */
	return( TRUE );
	}
#endif /* WinCE */

/* Test reading various non-cryptlib PKCS #15 files */

int testReadMiscFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	void *fileNamePtr = filenameBuffer;
	int status;

	fputs( "Testing miscellaneous key file read...\n", outputStream );

	filenameFromTemplate( filenameBuffer, MISC_PRIVKEY_FILE_TEMPLATE, 1 );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
	fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  fileNamePtr, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't open/scan keyset, status %d, "
				 "line %d.\n", status, __LINE__ );
		return( FALSE );
		}
#if 0
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
								 CRYPT_KEYID_NAME, 
								 TEXT( "56303156793b318327b25a84808f2cb311c55b0b" ), 
								 TEXT( "PASSWORD" ) );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
#endif /* 0 */
	cryptKeysetClose( cryptKeyset );

	fputs( "Miscellaneous key file read succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Generic test routines used for debugging */

void xxxPrivKeyRead( const char *fileName, const char *keyName, 
					 const char *password )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  fileName, CRYPT_KEYOPT_READONLY );
	assert( cryptStatusOK( status ) );

	/* Read the key from the file */
	if( password == NULL )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext,
									CRYPT_KEYID_NAME, keyName );
		}
	else
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, keyName, password );
		}
	assert( cryptStatusOK( status ) );

	cryptKeysetClose( cryptKeyset );
	}

void xxxPubKeyRead( const char *fileName, const char *keyName )
	{
	xxxPrivKeyRead( fileName, keyName, NULL );
	}
#endif /* TEST_KEYSET */
=======
/****************************************************************************
*																			*
*						cryptlib File Keyset Test Routines					*
*						Copyright Peter Gutmann 1995-2009					*
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

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* External flags that indicate that the key read/update routines worked OK.
   This is set by earlier self-test code, if it isn't set some of the tests
   are disabled */

extern int keyReadOK, doubleCertOK;

#ifdef TEST_KEYSET

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the label for the key stored for an algorithm */

static const C_STR getAlgoLabel( const CRYPT_ALGO_TYPE cryptAlgo )
	{
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			return( RSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_DSA:
			return( DSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_ELGAMAL:
			return( ELGAMAL_PRIVKEY_LABEL );

		case CRYPT_ALGO_ECDSA:
			return( ECDSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_ECDH:
			return( ECDSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_EDDSA:
			return( EDDSA_PRIVKEY_LABEL );

		case CRYPT_ALGO_25519:
			return( CURVE25519_PRIVKEY_LABEL );
		}

	return( TEXT( "<Unknown>" ) );
	}

/* Load a private-key context for a particular algorithm */

static int loadPrivateKeyContext( CRYPT_CONTEXT *cryptContext,
								  const CRYPT_ALGO_TYPE cryptAlgo )
	{
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			return( loadRSAContexts( CRYPT_UNUSED, NULL, cryptContext ) );

		case CRYPT_ALGO_DSA:
			return( loadDSAContexts( CRYPT_UNUSED, NULL, cryptContext ) );

		case CRYPT_ALGO_ELGAMAL:
			return( loadElgamalContexts( NULL, cryptContext ) );

		case CRYPT_ALGO_ECDSA:
			return( loadECDSAContexts( CRYPT_UNUSED, NULL, cryptContext ) );
		}

	fprintf( outputStream, "Algorithm %d not available, line %d.\n", 
			 cryptAlgo, __LINE__ );
	return( FALSE );
	}

/* Make sure that an item read from a keyset is a certificate */

static int checkCertPresence( const CRYPT_HANDLE cryptHandle,
							  const char *certTypeName,
							  const CRYPT_CERTTYPE_TYPE certType )
	{
	int value, status;

	/* Make sure that what we've got is a certificate */
	status = cryptGetAttribute( cryptHandle, CRYPT_CERTINFO_CERTTYPE, 
								&value );
	if( cryptStatusError( status ) || value != certType )
		{
		fprintf( outputStream, "Returned object isn't a %s, line %d.\n", 
				 certTypeName, __LINE__ );
		return( FALSE );
		}

	/* The test that follows requires an encryption-capable algorithm, if 
	   the algorithm can't be used for encryption then we skip it */
	status = cryptGetAttribute( cryptHandle, CRYPT_CTXINFO_ALGO, &value );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't read algorithm from certificate, "
				 "line %d.\n", __LINE__ );
		return( FALSE );
		}
	if( value != CRYPT_ALGO_RSA )
		{
		fputs( "(Skipping certificate use test since algorithm can't be used "
			   "for encryption).\n\n", outputStream );
		return( TRUE );
		}

	/* Make sure that we can't use the read key (the certificate constrains 
	   it from being used externally) */
	status = testCrypt( cryptHandle, cryptHandle, value, NULL, FALSE, TRUE );
	if( status != CRYPT_ERROR_NOTAVAIL && status != CRYPT_ERROR_PERMISSION )
		{
		fputs( "Attempt to perform external operation on context with "
			   "internal-only action\npermissions succeeded.\n", 
			   outputStream );
		return( FALSE );
		}

	return( TRUE );
	}

/* Copy a source file to a destination file, corrupting a given byte in the 
   process.  This is used to test the ability of the keyset-processing code 
   to detect data manipulation in keyset data */

static int copyModifiedFile( const C_STR srcFileName, 
							 const C_STR destFileName, const int bytePos )
	{
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count = 0;

	/* Read the source file into the data buffer */
	if( ( filePtr = fopen( convertFileName( srcFileName ), "rb" ) ) != NULL )
		{
		count = fread( buffer, 1, BUFFER_SIZE, filePtr );
		if( count >= BUFFER_SIZE )
			count = 0;
		fclose( filePtr );
		}
	if( count <= 0 )
		return( FALSE );

	/* Corrupt a specific byte in the file */
	buffer[ bytePos ] ^= 0xFF;

	/* Write the changed result to the output buffer */
	if( ( filePtr = fopen( convertFileName( destFileName ), "wb" ) ) != NULL )
		{
		int writeCount;

		writeCount = fwrite( buffer, 1, count, filePtr );
		if( writeCount != count )
			count = 0;
		fclose( filePtr );
		}
	
	return( ( count > 0 ) ? TRUE : FALSE );
	}

/****************************************************************************
*																			*
*							PGP Key Read/Write Tests						*
*																			*
****************************************************************************/

/* Get a public key from a PGP keyring */

static int getPGPPublicKey( const KEYFILE_TYPE keyFileType,
							const C_STR keyFileTemplate,
							const BOOLEAN useWildcardName,
							const char *description )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	char fileName[ BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	const C_STR keysetName = getKeyfileName( keyFileType, FALSE );
	int status;

	/* If this is the first file read, check that the file actually exists
	   so that we can return an appropriate error message */
	if( keyFileType == KEYFILE_PGP )
		{
		if( ( filePtr = fopen( convertFileName( keysetName ),
							   "rb" ) ) == NULL )
			return( CRYPT_ERROR_FAILED );
		fclose( filePtr );
		keyReadOK = FALSE;
		}

	/* If the caller has overridden the keyfile to use, use the caller-
	   supplied name */
	if( keyFileTemplate != NULL )
		{
		filenameFromTemplate( fileName, keyFileTemplate, 1 );
#ifdef UNICODE_STRINGS
		mbstowcs( wcBuffer, fileName, strlen( fileName ) + 1 );
		keysetName = wcBuffer;
#else
		keysetName = fileName;
#endif /* UNICODE_STRINGS */
		}

	fprintf( outputStream, "Testing %s public key read...\n", description );

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error code %d, "
				 "line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  The read of the special-case PGP keyring tests the 
	   ability to handle over-long key packet groups so this should return
	   a not-found error due to the packets being skipped */
	if( useWildcardName )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME, "[none]" );
		}
	else
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME,
									getKeyfileUserID( keyFileType, FALSE ) );
		}
	if( ( keyFileType == KEYFILE_PGP_SPECIAL && \
		  status != CRYPT_ERROR_NOTFOUND ) || \
		( keyFileType != KEYFILE_PGP_SPECIAL && \
		  cryptStatusError( status ) ) )
		{
		printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* PGP public keyrings can be arbitrarily large, to deal with the 
	   inability to retain the entire keyring in memory we re-scan the 
	   keyring for each key read.  To make sure this works OK we read a key
	   multiple times for one of the tests */
	if( keyFileType == KEYFILE_OPENPGP_AES && useWildcardName == FALSE )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME,
									getKeyfileUserID( keyFileType, FALSE ) );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey() re-read", 
						   status, __LINE__ );
			return( FALSE );
			}
		cryptDestroyContext( cryptContext );
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME,
									getKeyfileUserID( keyFileType, FALSE ) );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey() second re-read", 
						   status, __LINE__ );
			return( FALSE );
			}
		cryptDestroyContext( cryptContext );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Read of public key from %s keyring "
			 "succeeded.\n\n", description );
	return( TRUE );
	}

int testGetPGPPublicKey( void )
	{
	/* See testGetPGPPrivateKey() for the descriptions of the files */
	if( !getPGPPublicKey( KEYFILE_PGP, NULL, FALSE, "PGP" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_PGP, NULL, TRUE, "PGP with wildcard name" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_HASH, NULL, FALSE, "OpenPGP (GPG/hashed key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_HASH, NULL, TRUE, "OpenPGP with wildcard name" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_AES, NULL, FALSE, "OpenPGP (GPG/AES-256 key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_AES_KEYID, NULL, FALSE, "OpenPGP (GPG/AES-256 key) by keyID" ) )
		return( FALSE );
#if 0	/* The key in this file has an S2K iteration count of 3.5M and will 
		   be rejected by cryptlib's anti-DoS sanity checks */
	if( !getPGPPublicKey( KEYFILE_OPENPGP_CAST, NULL, FALSE, "OpenPGP (GPG/CAST5 key)" ) )
		return( FALSE );
#endif /* 0 */
	if( !getPGPPublicKey( KEYFILE_OPENPGP_RSA, NULL, FALSE, "OpenPGP (GPG/RSA key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_MULT, NULL, FALSE, "OpenPGP (multiple subkeys)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_NAIPGP, NULL, FALSE, "OpenPGP (NAI)" ) )
		return( FALSE );
#if 0	/* This file is nearly 100K long and consists of endless strings of 
		   userIDs and signatures for the same identity, so it's rejected by
		   cryptlib's sanity-check code */
	if( !getPGPPublicKey( KEYFILE_PGP_SPECIAL, PGPKEY_FILE_TEMPLATE, FALSE, "Complex PGP key" ) )
		return( FALSE );
#endif /* 0 */
#if 0	/* Not fully supported yet */
	if( !getPGPPublicKey( KEYFILE_OPENPGP_ECC, NULL, FALSE, "OpenPGP (ECC)" ) )
		return( FALSE );
#endif /* 0 */
	return( TRUE );
	}

/* Get a private key from a PGP keyring */

static int getPGPPrivateKey( const KEYFILE_TYPE keyFileType,
							 const BOOLEAN useWildcardName,
							 const char *description )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const C_STR keysetName = getKeyfileName( keyFileType, TRUE );
	const C_STR password = getKeyfilePassword( keyFileType );
	int status;

	fprintf( outputStream, "Testing %s private key read...\n", 
			 description );

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  First we try it without a password, if that fails we
	   retry it with the password - this tests a lot of the private-key get
	   functionality including things like key cacheing */
	if( useWildcardName )
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
									 CRYPT_KEYID_NAME, "[none]", NULL );
		}
	else
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
									 CRYPT_KEYID_NAME,
									 getKeyfileUserID( keyFileType, TRUE ), 
									 NULL );
		}
	if( status == CRYPT_ERROR_WRONGKEY )
		{
		/* We need a password for this private key */
		if( useWildcardName )
			{
			status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
										 CRYPT_KEYID_NAME, "[none]", 
										 password );
			}
		else
			{
			status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
										 CRYPT_KEYID_NAME,
										 getKeyfileUserID( keyFileType, TRUE ), 
										 password );
			}
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can use the key that we've read.  We can only do this 
	   with PGP 2.x keys, OpenPGP's peculiar multi-keys identify two (or more) 
	   keys with the same label and we can't specify (at this level) which 
	   key we want to use (the enveloping code can be more specific and so 
	   doesn't run into this problem) */
	if( keyFileType == KEYFILE_PGP )
		{
		int value;

		status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, 
									&value );
		if( cryptStatusOK( status ) )
			{
			status = testCrypt( cryptContext, cryptContext, value, NULL, 
								FALSE, FALSE );
			}
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* The public and private key reads worked, remember this for later when
	   we use the keys in other tests */
	keyReadOK = TRUE;

	fprintf( outputStream, "Read of private key from %s keyring "
			 "succeeded.\n\n", description );
	return( TRUE );
	}

int testGetPGPPrivateKey( void )
	{
	/* PGP 2.x file, RSA with IDEA, secring.pgp */
#ifdef USE_PGP2
	if( !getPGPPrivateKey( KEYFILE_PGP, FALSE, "PGP" ) )
		return( FALSE );
#endif /* USE_PGP2 */

	/* OpenPGP file, DSA+Elgamal with 3DES, sec_hash.gpg.  Create with:

		gpg --gen-key --homedir . --s2k-cipher-algo 3des

	   Select DSA+Elgamal, size 1024 bits, key does not expire, 
	   name = Test1, email = test1@test.org, comment blank, 
	   password = test1 */
#ifdef USE_3DES
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_HASH, FALSE, "OpenPGP (GPG/hashed key)" ) )
		return( FALSE );
#endif /* USE_3DES */

	/* OpenPGP file, DSA+Elgamal with AES, sec_aes.skr */
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_AES, FALSE, "OpenPGP (GPG/AES-256 key)" ) )
		return( FALSE );
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_AES, TRUE, "OpenPGP with wildcard name" ) )
		return( FALSE );

#if 0	/* The key in this file has an S2K iteration count of 3.5M and will 
		   be rejected by cryptlib's anti-DoS sanity checks */
	/* OpenPGP file, DSA+Elgamal with CAST5, sec_cast.gpg */
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_CAST, FALSE, "OpenPGP (GPG/CAST5 key)" ) )
		return( FALSE );
#endif /* 0 */
	
	/* OpenPGP file, RSA+RSA with 3DES and SHA256, sec_rsa.gpg.  Create with:

		gpg --gen-key --homedir . --s2k-cipher-algo 3des --s2k-digest-algo sha256

	   Select RSA, size 2048 bits, key does not expire, name = Test1, 
	   email = test1@test.org, comment blank, password = test1 */
#ifdef USE_3DES
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_RSA, FALSE, "OpenPGP (GPG/RSA key)" ) )
		return( FALSE );
#endif /* USE_3DES */

	/* OpenPGP file, RSA with IDEA, sec_nai.skr */
#ifdef USE_PGP2
	if( !getPGPPrivateKey( KEYFILE_NAIPGP, FALSE, "OpenPGP (NAI)" ) )
		return( FALSE );
#endif /* USE_PGP2 */

	/* OpenPGP, RSA p and q swapped, sec_bc.gpg.  Create using 
	   BouncyCastle */
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_BOUNCYCASTLE, FALSE, "OpenPGP (RSA p,q swapped)" ) )
		return( FALSE );

	/* OpenPGP, ECC keys, sec_ecc.gpg.  Create using a development release 
	   of GPG 2.x (which involves installing about a dozen dependency 
	   libraries and apps), then:

		gpg2 --expert --full-gen-key

	   Select ECC, NIST P256, key does not expire, name = Test1,
	   email = test1@test.org, comment blank, password = test1 */
#if 0	/* Not fully supported yet */
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_ECC, FALSE, "OpenPGP (ECC)" ) )
		return( FALSE );
#endif /* 0 */

	return( TRUE );
	}

/****************************************************************************
*																			*
*							PKCS #12 Key Read/Write Tests					*
*																			*
****************************************************************************/

#ifdef USE_PKCS12	/* Disabled by default */

/* The Primekey CA generates ridiculous multilevel fragmented PKCS #12 files 
   with fragmentation across multiple levels of encoding, a fragmented OCTET 
   STRING containing encapsulated inner content which in turn contains 
   another fragmented OCTET STRING.  Dumping the outer level of encoding 
   gives:

      0 NDEF: SEQUENCE {
      2    1:   INTEGER 3
      5 NDEF:   SEQUENCE {
      7    9:     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
     18 NDEF:     [0] {
     20 NDEF:       OCTET STRING {
     22 1000:         OCTET STRING
            :           30 80 30 80 06 09 2A 86 48 86 F7 0D 01 07 01 A0
            :           80 24 80 04 82 01 41 30 82 01 3D 30 82 01 39 06
            :                       [ Bytes skipped ]
   1026 1000:         OCTET STRING
            :           E0 7B 81 49 22 7D C2 81 9D CE A3 CA 0E 95 8F D1
            :           F1 88 10 93 93 A2 4B AE 08 1B FB 84 84 EB 62 3D
            :                       [ Bytes skipped ]

   [...]

   The inner content there starts with 30 80 30 80, trying to decode this
   gives:

      0 NDEF: SEQUENCE {
      2    1:   INTEGER 3
      5 NDEF:   SEQUENCE {
      7    9:     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
     18 NDEF:     [0] {
     20 NDEF:       OCTET STRING {
     22 1000:         OCTET STRING, encapsulates {
     26 NDEF:           SEQUENCE {
     28 NDEF:             SEQUENCE {
     30    9:               OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
     41 NDEF:               [0] {
     43 NDEF:                 OCTET STRING {
     45  321:                   OCTET STRING, encapsulates {
     49  317:                     SEQUENCE {
     53  313:                       SEQUENCE {
     57   11:                         OBJECT IDENTIFIER
            :                           pkcs-12-pkcs-8ShroudedKeyBag (1 2 840 113549 1 12 10 1 2)
     70  201:                         [0] {
   [...]
            :                           }
    274   94:                         SET {
   [...]
            :                           }
            :                         }
            :                       }
            :                     }
            :                   }
            :                 }
            :               }
    376 NDEF:             SEQUENCE {
    378    9:               OBJECT IDENTIFIER encryptedData (1 2 840 113549 1 7 6)
    389 NDEF:               [0] {
    391 NDEF:                 SEQUENCE {
    393    1:                   INTEGER 0
    396 NDEF:                   SEQUENCE {
    398    9:                     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
    409   41:                     SEQUENCE {
    411   10:                       OBJECT IDENTIFIER pbeWithSHAAnd40BitRC2-CBC (1 2 840 113549 1 12 1 6)
    423   27:                       SEQUENCE {
    425   20:                         OCTET STRING F3 D4 AC 2B 22 0B 5E 38 F2 D2 08 87 62 03 C0 5D 15 C4 F6 44
    447    3:                         INTEGER 51200
            :                         }
            :                       }
    452 NDEF:                     [0] {
    454 1000:                       OCTET STRING
            :                         1B 68 1C AC 26 0C B1 9C 68 64 EB 25 D0 21 2A 85
            :                         58 16 B6 1F C1 B7 23 A1 7B E9 4E 4C 71 7D 8A F1
            :                         D4 B5 25 EE 84 53 07 FC FA 3C 9B DB A7 E8 68 F1
            :                         8B C8 9E 4D 81 D8 0C 6C 81 73 00 79 FC 7D B4 82
            :                         A6 F3 7B D0 74 8D FE 55 4E B1 07 6F B9 B1 08 55
            :                         20 69 A1 C8 F8 AF 3F 81 65 1A A5 18 3B 2C A3 3B
            :                         A5 0B 05 4B 53 C3 F8 93 D3 86 61 90 BC 63 C0 97
            :                         63 CA 15 E5 5A 0A 7B 0F 35 FC 13 75 50 35 5C 97
            :                                 [ Another 872 bytes skipped ]
   1458   19:                       [APPLICATION 30] 2D 04 04 82 03 E8 9F 86 78 18 75 E7 66 77 C3 A0 F4 03 17

   After offset 1458 we hit the OCTET STRING fragment somewhere which means 
   that any data beyond that point appears corrupted because there's 
   fragmentation data overlaid on the content.

   To deal with this, we read the file, de-envelope the contents, re-
   envelope without the gratuitous fragmentation, and then write that as a 
   PKCS #12.  However because of the inner fragmentation we still end up
   with:

   0 NDEF: SEQUENCE {
   2    1:   INTEGER 3
   5 5875:   SEQUENCE {
   9    9:     OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
  20 5860:     [0] {
  24 5856:       OCTET STRING, encapsulates {
  28 NDEF:         SEQUENCE {
  30 NDEF:           SEQUENCE {
  32    9:             OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
  43 NDEF:             [0] {
  45 NDEF:               OCTET STRING {
  47  321:                 OCTET STRING, encapsulates {
  51  317:                   SEQUENCE {
  55  313:                     SEQUENCE {
  59   11:                       OBJECT IDENTIFIER pkcs-12-pkcs-8ShroudedKeyBag (1 2 840 113549 1 12 10 1 2)
  72  201:                       [0] {
   [...]
         :                         }
 276   94:                       SET {
   [...]
         :                         }
         :                       }
         :                     }
         :                   }
         :                 }
         :               }
         :             }
 378 NDEF:           SEQUENCE {
 380    9:             OBJECT IDENTIFIER encryptedData (1 2 840 113549 1 7 6)
 391 NDEF:             [0] {
 393 NDEF:               SEQUENCE {
 395    1:                 INTEGER 0
 398 NDEF:                 SEQUENCE {
 400    9:                   OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
 411   41:                   SEQUENCE {
 413   10:                     OBJECT IDENTIFIER pbeWithSHAAnd40BitRC2-CBC (1 2 840 113549 1 12 1 6)
 425   27:                     SEQUENCE {
 427   20:                       OCTET STRING F3 D4 AC 2B 22 0B 5E 38 F2 D2 08 87 62 03 C0 5D 15 C4 F6 44
 449    3:                       INTEGER 51200
         :                       }
         :                     }
 454 NDEF:                   [0] {
 456 1000:                     OCTET STRING
         :                       1B 68 1C AC 26 0C B1 9C 68 64 EB 25 D0 21 2A 85
         :                       58 16 B6 1F C1 B7 23 A1 7B E9 4E 4C 71 7D 8A F1
         :                                       [ Bytes skipped ]
1460 1000:                     OCTET STRING
         :                       9F 86 78 18 75 E7 66 77 C3 A0 F4 03 17 60 2A AB
         :                       4B CF 37 F5 B4 D8 B6 AF BD 38 15 E8 77 D3 3E A5
         :                                       [ Bytes skipped ]
2464 1000:                     OCTET STRING
         :                       DA D3 E4 A3 C0 DE AB 83 E9 0B FD 2C F8 52 39 EB
         :                       1A 4F 7B 84 31 0B B3 7A 11 77 CE 84 99 2F 04 A9
         :                                       [ Bytes skipped ]
3468 1000:                     OCTET STRING
         :                       1B 2B 63 67 2C 3A AA EE D1 A7 01 9E D8 4F C5 1C
         :                       34 C4 74 C5 C3 DB 3C A9 1D 6E A8 A8 99 AE C6 19
         :                                       [ Bytes skipped ]
4472 1000:                     OCTET STRING
         :                       0C CC C5 AE 60 80 D0 2A EC B3 2B F8 A0 61 51 B7
         :                       D2 7A 91 B7 72 93 86 D5 AE B7 75 41 1A E2 63 B6
         :                                       [ Bytes skipped ]
5476  392:                     OCTET STRING
         :                       88 15 C9 EC 22 D9 23 7F 0F 9E 34 73 6A 0F 9B 9D
         :                       77 21 E2 81 E3 72 7D 63 77 16 7F C3 23 87 35 C2
         :                                       [ Bytes skipped ]
         :                     }
         :                   }
         :                 }
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
         :   } 

   This means that we have to perform a second level of defragmentation to 
   process the inner fragmented data.  We do this by rewriting the 
   fragmented portion as DER in a somewhat brute-force pattern-matching 
   manner, this doesn't fix up all of the lengths (there are three used
   close to the start of the data) but it's good enough to make it readable
   since cryptlib stops reading once it's processed the payload, only
   dumpasn1 continues and complains about mismatches in the length.
   
   Handling by other implementations varies, in particular PKCS #12 files 
   have a MAC attached at the end which will be invalidated so cryptlib 
   strips it, it's optional in the standard but whether an implementation 
   will actually allow it to be optional is anyone's guess.  However since 
   the conversion code also can't fix up the various internal length values 
   the resulting file also won't be valid for any parser that does strict 
   checking of nested data values.  Windows accepts the phase-1 processed 
   file, without the MAC, but not the phase-2 processed file ("Invalid 
   file"), probably because the internal length values don't match up.  
   Firefox doesn't accept the phase-1 processed file ("Failed to decode the 
   file") and accepts the phase-2 one but reports an incorrect password 
   ("Password incorrect").

   To convert it into a valid file, import the phase 2 output into cryptlib, 
   then write it as a PKCS #15 or PKCS #12 which will clean up the format 
   and produce the correctly-formatted file */

static int rewriteBorkenKeyFile1( const char *filename )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	FILE *filePtr;
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
	BYTE buffer[ BUFFER_SIZE ];
	const int filenameLength = strlen( filename );
	int length, status;

	fprintf( outputStream, "Converting broken PKCS #12 file %s, "
			 "phase 1...\n", filename ); 

	/* Read the source file into the data buffer */
	if( ( filePtr = fopen( filename, "rb" ) ) == NULL )
		{
		fprintf( outputStream, "Error: Couldn't open source keyset %s.\n", 
				 filename ); 
		return( FALSE );
		}
	length = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( length <= 0 || length >= BUFFER_SIZE )
		{
		fprintf( outputStream, "Error: %s is larger than %d bytes.\n", 
				 filename, BUFFER_SIZE ); 
		return( FALSE );
		}

	/* Make sure that we've got a fragmented PKCS #12 file */
	if( memcmp( filename + filenameLength - 4, ".p12", 4 ) || \
		memcmp( buffer, "\x30\x80\x02\x01\x03", 5 ) )
		{
		fprintf( outputStream, "Error: %s doesn't appear to be a "
				 "fragmented PKCS #12 file.\n", filename ); 
		return( FALSE );
		}

	/* De-envelope the fragmented data */
	status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED, 
								  CRYPT_FORMAT_AUTO );
	if( cryptStatusOK( status ) )
		{
		status = cryptPushData( cryptEnvelope, buffer + 5, length - 5, 
								&length );
		}
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptEnvelope );
	if( cryptStatusOK( status ) )
		{
		status = cryptPopData( cryptEnvelope, buffer, BUFFER_SIZE, 
							   &length );
		}
	cryptDestroyEnvelope( cryptEnvelope );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Error: Couldn't de-envelope fragmented "
				 "data.\n" ); 
		return( FALSE );
		}

	/* Re-envelope the data in non-fragmented form */
	status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED, 
								  CRYPT_FORMAT_CRYPTLIB );
	if( cryptStatusOK( status ) )
		{
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE, length );
		status = cryptPushData( cryptEnvelope, buffer, length, &length );
		}
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptEnvelope );
	if( cryptStatusOK( status ) )
		{
		status = cryptPopData( cryptEnvelope, buffer, BUFFER_SIZE, 
							   &length );
		}
	cryptDestroyEnvelope( cryptEnvelope );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Error: Couldn't re-envelope non-fragmented "
				 "data.\n" ); 
		return( FALSE );
		}

	/* Modify the filename from xxx.p12 to xxx_der1.p12.  This assumes that 
	   the filename has a specific form, which it does for the test keysets 
	   and which in any case has been checked earlier */
	memcpy( filenameBuffer, filename, filenameLength - 4 );
	memcpy( filenameBuffer + filenameLength - 4, "_der.p12", 8 + 1 );

	/* Write the non-fragmented enveloped data to the new filename.  We omit
	   the authentication gunk at the end of the data, which isn't used and
	   possibly (depending on how the fragmentation is interpreted) won't 
	   match the new data anyway */
	if( ( filePtr = fopen( filenameBuffer, "rb" ) ) != NULL )
		{
		fclose( filePtr );
		fprintf( outputStream, "Error: Destination keyset %s already "
				 "exists.\n", filenameBuffer ); 
		return( FALSE );
		}
	if( ( filePtr = fopen( filenameBuffer, "wb" ) ) == NULL )
		{
		fprintf( outputStream, "Error: Couldn't open destination keyset "
				 "%s.\n", filenameBuffer ); 
		return( FALSE );
		}
	fwrite( "\x30\x80\x02\x01\x03", 1, 5, filePtr );	/* Header */
	length = fwrite( buffer, 1, length, filePtr );
	fwrite( "\x00\x00", 1, 2, filePtr );				/* EOC */
	fclose( filePtr );
	if( length <= 0 )
		{
		fprintf( outputStream, "Error: Couldn't write destination keyset "
				 "%s.\n", filenameBuffer ); 
		return( FALSE );
		}

	return( TRUE );
	}

static int readLength( const BYTE *buffer, int *length )
	{
	if( *buffer < 0x80 )
		{
		*length = *buffer;
		return( 1 );
		}
	if( *buffer == 0x81 )
		{
		*length = buffer[ 1 ];
		return( 2 );
		}
	*length = buffer[ 1 ] << 8 | buffer[ 2 ];
	return( 3 );
	}

static int rewriteBorkenKeyFile2( const char *filename )
	{
	FILE *filePtr;
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
	BYTE buffer[ BUFFER_SIZE ], fragmentBuffer[ BUFFER_SIZE ];
	const int filenameLength = strlen( filename );
	int fragmentLength, fragmentTotalLength = 0;
	int totalLength, length, bufPos, dataStartPos;

	fprintf( outputStream, "Converting broken PKCS #12 file %s, "
			 "phase 2...\n", filename ); 

	/* Read the source file into the data buffer */
	if( ( filePtr = fopen( filename, "rb" ) ) == NULL )
		{
		fprintf( outputStream, "Error: Couldn't open source keyset %s.\n", 
				 filename ); 
		return( FALSE );
		}
	totalLength = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( totalLength <= 0 || totalLength >= BUFFER_SIZE )
		{
		fprintf( outputStream, "Error: %s is larger than %d bytes.\n", 
				 filename, BUFFER_SIZE ); 
		return( FALSE );
		}

	/* Make sure that we've got a fragmented PKCS #12 file */
	if( memcmp( filename + filenameLength - 4, ".p12", 4 ) || \
		memcmp( buffer, "\x30\x80\x02\x01\x03", 5 ) )
		{
		fprintf( outputStream, "Error: %s doesn't appear to be a "
				 "fragmented PKCS #12 file.\n", filename ); 
		return( FALSE );
		}

	/* Scan the file for the byte string A0 80 30 80 02 01 00 30, 
	   corresponding to:

		[0] {
			SEQUENCE {
				INTEGER 0,
				SEQUENCE {

	   which we need to convert into their definite-length equivalents */
	for( dataStartPos = 256; dataStartPos < totalLength - 1024; 
		 dataStartPos++ )
		{
		if( buffer[ dataStartPos ] != 0xA0 || \
			buffer[ dataStartPos + 1 ] != 0x80 )
			continue;
		if( !memcmp( buffer + dataStartPos, 
					 "\xA0\x80\x30\x80\x02\x01\x00\x30", 8 ) )
			break;
		}
	if( dataStartPos >= totalLength - 1024 )
		{
		fprintf( outputStream, "Error: Couldn't find indefinite-length "
				 "encrypted data in file.\n" ); 
		return( FALSE );
		}

	/* We're about to shorten the file length by quite a bit as we remove 
	   all of the fragmentation, and we also need to adjust the lengths
	   we're about to encode for the MAC trailer data.  Since we don't care
	   about the trailer and can afford to lose some of it, we estimate
	   losing about 16 bytes from the overall length even if that includes
	   some of the trailer */
	totalLength -= 16;
	#define TRAILER_SIZE	6

	/* Rewrite the initial indefinite SEQUENCE to its definite form */
	bufPos = dataStartPos + 1;
	memmove( buffer + bufPos + 3, buffer + bufPos + 1,	/* Remove 0x80 */
			 totalLength - bufPos );
	length = totalLength - ( bufPos + 11 + TRAILER_SIZE );
	buffer[ bufPos ] = 0x82;
	buffer[ bufPos + 1 ] = length >> 8;
	buffer[ bufPos + 2 ] = length & 0xFF;
	bufPos += 4;
	memmove( buffer + bufPos + 2, buffer + bufPos,	/* Remove 0x80 */
			 totalLength - bufPos );
	length = totalLength - ( bufPos + 11 + TRAILER_SIZE );
	buffer[ bufPos ] = 0x82;
	buffer[ bufPos + 1 ] = length >> 8;
	buffer[ bufPos + 2 ] = length & 0xFF;
	bufPos += 7; 
	memmove( buffer + bufPos + 2, buffer + bufPos,	/* Remove 0x80 */
			 totalLength - bufPos );
	length = totalLength - ( bufPos + 11 + TRAILER_SIZE );
	buffer[ bufPos ] = 0x82;
	buffer[ bufPos + 1 ] = length >> 8;
	buffer[ bufPos + 2 ] = length & 0xFF;

	/* Scan the file for the byte string A0 80 04 82 03 E8, corresponding to 
	   an indefinite-length [0] and the first 1024-byte fragment */
	for( dataStartPos = bufPos; dataStartPos < totalLength - 1024; 
		 dataStartPos++ )
		{
		if( buffer[ dataStartPos ] != 0xA0 || \
			buffer[ dataStartPos + 1 ] != 0x80 )
			continue;
		if( !memcmp( buffer + dataStartPos, "\xA0\x80\x04\x82\x03\xE8", 6 ) )
			break;
		}
	if( dataStartPos >= totalLength - 1024 )
		{
		fprintf( outputStream, "Error: Couldn't find fragmented payload "
				 "data in file.\n" ); 
		return( FALSE );
		}
	bufPos = dataStartPos + 2;	/* Skip A0 80 */

	/* Process each fragment and copy the contents across into the fragment 
	   assembly buffer */
	while( bufPos < totalLength - 14 )	/* 7 x EOCs */
		{
		if( buffer[ bufPos++ ] != 0x04 )
			{
			fprintf( outputStream, "Error: Lost fragment synchronisation "
					 "at position %d.\n", bufPos - 1 ); 
			return( FALSE );
			}
		bufPos += readLength( buffer + bufPos, &fragmentLength );
		memcpy( fragmentBuffer, buffer + bufPos, fragmentLength );
		fragmentTotalLength += fragmentLength;
		bufPos += fragmentLength;
		}

	/* Add the definite-length header and copy the data into place behind it */
	buffer[ dataStartPos ] = 0x80;
	buffer[ dataStartPos + 1 ] = 0x82;
	buffer[ dataStartPos + 2 ] = fragmentTotalLength >> 8;
	buffer[ dataStartPos + 3 ] = fragmentTotalLength;
	dataStartPos += 4;
	memcpy( buffer + dataStartPos, fragmentBuffer, fragmentTotalLength );

	/* Add five lots of EOCs, down from the seven that we stared with since 
	   we've converted some of the data to definite-length */
	memcpy( buffer + dataStartPos + fragmentTotalLength, 
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 
			4 );
	fragmentTotalLength += 4;

	/* Modify the filename from xxx.p12 to xxx_der2.p12.  This assumes that 
	   the filename has a specific form, which it does for the test keysets 
	   and which in any case has been checked earlier */
	memcpy( filenameBuffer, filename, filenameLength - 4 );
	memcpy( filenameBuffer + filenameLength - 4, "_der.p12", 8 + 1 );

	/* Write the non-fragmented enveloped data to the new filename.  We omit
	   the authentication gunk at the end of the data, which isn't used and
	   possibly (depending on how the fragmentation is interpreted) won't 
	   match the new data anyway */
	if( ( filePtr = fopen( filenameBuffer, "rb" ) ) != NULL )
		{
		fclose( filePtr );
		fprintf( outputStream, "Error: Destination keyset %s already "
				 "exists.\n", filenameBuffer ); 
		return( FALSE );
		}
	if( ( filePtr = fopen( filenameBuffer, "wb" ) ) == NULL )
		{
		fprintf( outputStream, "Error: Couldn't open destination keyset "
				 "%s.\n", filenameBuffer ); 
		return( FALSE );
		}
	totalLength = fwrite( buffer, 1, dataStartPos + fragmentTotalLength, 
						  filePtr );
	fclose( filePtr );
	if( totalLength <= 0 )
		{
		fprintf( outputStream, "Error: Couldn't write destination keyset "
				 "%s.\n", filenameBuffer ); 
		return( FALSE );
		}

	return( TRUE );
	}

/* Get a key from a PKCS #12 file.  Because of the security problems
   associated with this format, the code only checks the data format but
   doesn't try to read or use the keys.  If anyone wants this, they'll
   have to add the code themselves.  Your security warranty is automatically 
   void when you implement this */

static int borkenKeyImport( const int fileNo )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const C_STR userID;
	const C_STR password;
	BYTE buffer[ BUFFER_SIZE ];
	int status;

	/* Set up the file access information:
	
		Keyset #1 = CryptoAPI via OpenSSL, privKey with ID data and 3DES, 
			then anonymous cert with RC2/40.
		Keyset #2 = CryptoAPI, privKey with ID data and 3DES, then 
			anonymous cert with RC2/40.  The private key is identified via a 
			GUID which we can't do much with so we pass in the special-case 
			userID "[none]" meaning "return the first key that we find".
		Keyset #3 = Unknown source, cert chain in plaintext with ID data, 
			then privKey with ID data and 3DES.  The userID for the private 
			key is the single hex byte 0x8C, again we use "[none]" for this.
		Keyset #4 = OpenSSL, anonymous cert with RC2/40, then privKey with 
			ID data and 3DES.
		Keyset #5 = Unknown source (possibly OpenSSL), anonymous cert with
			RC2/40, then privKey with ID data and 3DES.  Unlike keyset #4
			the ID data doesn't include a userID, so we again have to resort
			to "[none]" to read it.
		Keyset #6 = Unknown source, from some CA that generates the private 
			key for you rather than allowing you to generate it, possibly 
			Buypass based on the encoding bug in the EncryptedContentInfo, 
			see below.  Contains mostly indefinite-length encodings of data, 
			currently not readable, see the comments in keyset/pkcs12_rd.c 
			for more details.  Even if this were readable, it encodes the 
			EncryptedContentInfo.encryptedContent as if it were declared as 
			"[0] EXPLICIT OCTET STRING" instead of
			"[0] IMPLICIT OCTET STRING", so the encoding is 
			"[0] { OCTET STRING { ...", which we can't even auto-detect since
			there's a 1/256 chance that any encrypted data block will appear
			to contain an OCTET STRING tag.
		Keyset #7 = Nexus 4 phone, DSA cert and private key.
		Keyset #8 = EJBCA, ECDSA cert and private key in no documented format
			(the code reads it from reverse-engineering the DER dump).
		Keyset #9 = Windows, ECDSA cert and private key, as above, created
			by importing and exporting Keyset #8 to/from Windows.
		Keyset #10 = Unknown source, RSA cert and private key.  In this case
			the certificate is unencrypted so we can at least read this.
		Keyset #11 = Norwegian CA, complete certificate chain with labels
			for subsequent certs that don't match the private-key label.
		Keyset #12 = OpenSSL, possibly the same type as #6.
		Keyset #13 = Unknown source and not a PKCS #12 but some weird mutant
			that turns into something PKCS #15-like after the outer PKCS #12 
			wrappers */
	switch( fileNo )
		{
		case 1:
			userID = TEXT( "test pkcs#12" );
			password = TEXT( "test" );
			break;

		case 2:
			userID = TEXT( "[none]" );		/* Label = GUID */
			password = TEXT( "<unknown>" );	/* Unknown, RC2=2C 28 14 C4 01 */
			break;
	
		case 3:
			userID = TEXT( "[none]" );		/* No label, ID = 0x8C */
			password = TEXT( "7OPWKMIX" );
			break;

		case 4:
			userID = TEXT( "server" );
			password = TEXT( "cryptlib" );
			break;

		case 5:
			userID = TEXT( "[none]" );		/* No label, ID = hash */
			password = TEXT( "password" );
			break;

		case 6:
			userID = TEXT( "SignLabel" );
			password = TEXT( "vpsign" );

			/* See comment above */
			return( TRUE );

		case 7:
			userID = TEXT( "ClientDSA" );
			password = TEXT( "nexus4" );
			break;

		case 8:
			userID = TEXT( "CMG" );
			password = TEXT( "skylight" );
			break;

		case 9:
			userID = TEXT( "[none]" );		/* Label = GUID */
			password = TEXT( "test" );
			break;

		case 10:
			userID = TEXT( "RSA private key" );
			password = TEXT( "test" );
			break;

		case 11:
			userID = TEXT( "[none]" );		/* Label = GUID */
			password = TEXT( "test" );
			break;

		case 12:
			userID = TEXT( "[none]" );
			password = TEXT( "1234" );
			break;

		case 13:
			userID = TEXT( "[none]" );
			password = TEXT( "yz7nWwC5Re7mAjA6" );
			break;

		default:
			assert( 0 );
			return( FALSE );
		}

	/* Open the file keyset.  Note that we print the usual test message only
	   after we try and open the keyset, in order to avoid a cascade of PKCS 
	   #12 file non-opened messages */
	filenameFromTemplate( buffer, PKCS12_FILE_TEMPLATE, fileNo );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  buffer, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) && status == CRYPT_ERROR_NOTAVAIL )
		{
		/* If support for this isn't enabled, just exit quietly */
		return( TRUE );
		}
	fprintf( outputStream, "Testing PKCS #12 file #%d import...\n", fileNo ); 
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Get the key, first the private key, which should work, and then 
	   opportunistically the public key, which typically won't work if it's
	   encrypted (!!) */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 userID, password );
	if( cryptStatusError( status ) )
		{
		switch( fileNo )
			{
			case 1:
				/* This file has a 512-bit key and will give a 
				   CRYPT_ERROR_NOSECURE on import */
				if( status == CRYPT_ERROR_NOSECURE )
					status = CRYPT_OK;
				break;

			case  2:
				/* This file has an unknown password, although the cracked 
				   RC2/40 key for it is 2C 28 14 C4 01 */
				if( status == CRYPT_ERROR_WRONGKEY )
					status = CRYPT_OK;
				break;

			case 3:
				/* This file contains an invalid private key, specifically
				   ( q * u ) mod p != 1 (!!!) */
				if( status == CRYPT_ERROR_INVALID )
					status = CRYPT_OK;
				break;
			
			case 10:
			case 11:
				/* More unknown-password keys */
				if( status == CRYPT_ERROR_WRONGKEY )
					status = CRYPT_OK;
				break;

			case 12:
				/* Contains multiple levels of fragmentation which, unless 
				   rewritten in nonfragmented form (see the comment at the
				   start of this section) leads to a decryption failure */
				if( status == CRYPT_ERROR_WRONGKEY )
					status = CRYPT_OK;
				break;
			}
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		}
	else
		{
		/* Make sure that we got a certificate alongside the private key */
		if( !checkCertPresence( cryptContext, "private key with certificate", 
								CRYPT_CERTTYPE_CERTIFICATE ) )
			return( FALSE );
		cryptDestroyContext( cryptContext );
		}
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								userID );
	if( cryptStatusError( status ) )
		{
		switch( fileNo )
			{
			case 1:
			case 2:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8:
			case 9:
			case 12:
			case 13:
				/* All of these files encrypt the certificate so that it 
				   can't be read using cryptGetPublicKey() */
				status = CRYPT_OK;
			}
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		}
	else
		cryptDestroyCert( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Read of key from PKCS #12 file #%d "
			 "succeeded.\n\n", fileNo ); 
	return( TRUE );
	}

int testReadAltFileKey( void )
	{
#ifdef USE_3DES
	int i;

	/* Optionally rewrite the broken Primekey-created multiple-fragmented 
	   PKCS #12 into an unfragmented form */
  #if 0
	rewriteBorkenKeyFile1( "test/keys/pkcs12_12_orig.p12" );
	rewriteBorkenKeyFile2( "test/keys/pkcs12_12_orig_der.p12" );
	/* Copy pkcs12_12_orig_der.p12 to pkcs12_12.p12 */
	borkenKeyImport( 12 );
  #endif /* 0 */

	for( i = 1; i <= 13; i++ )
		{
		if( !borkenKeyImport( i ) )
			return( FALSE );
		}
#else
	fputs( "Skipping alternative key file read since 3DES isn't "
		   "available.\n\n", outputStream );
#endif /* USE_3DES */

	return( TRUE );
	}
#else

int testReadAltFileKey( void )
	{
	fputs( "Skipping alternative key file read.\n\n", outputStream );
	return( TRUE );
	}
#endif /* USE_PKCS12 */

/****************************************************************************
*																			*
*						Public/Private Key Read/Write Tests					*
*																			*
****************************************************************************/

/* Read/write a private key from a file */

static int readFileKey( const CRYPT_ALGO_TYPE cryptAlgo,
						const CRYPT_FORMAT_TYPE formatType,
						const BOOLEAN useWildcardRead )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const char *keyFileDescr = \
			( formatType == CRYPT_FORMAT_NONE ) ? "alternative " : \
			( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "";
	int status;

	fprintf( outputStream, "Testing %s private key read from %skey "
			 "file%s...\n", algoName( cryptAlgo ), keyFileDescr,
			 useWildcardRead ? " using wildcard ID" : "" );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  ( formatType == CRYPT_FORMAT_NONE ) ? \
								TEST_PRIVKEY_ALT_FILE : \
							  ( formatType == CRYPT_FORMAT_PGP ) ? \
								TEST_PRIVKEY_PGP_FILE : TEST_PRIVKEY_FILE,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		if( ( formatType != CRYPT_FORMAT_CRYPTLIB ) && \
			( status == CRYPT_ERROR_NOTAVAIL ) )
			{
			/* If the format isn't supported, this isn't a problem */
			fputs( "Read of RSA private key from alternative key file "
				   "skipped as this format is\ndisabled.\n\n", 
				   outputStream );
			return( TRUE );
			}
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	if( formatType == CRYPT_FORMAT_PGP )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext, 
									CRYPT_KEYID_NAME, useWildcardRead ? \
										TEXT( "[none]" ) : getAlgoLabel( cryptAlgo ) );
		}
	else
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, useWildcardRead ? \
										TEXT( "[none]" ) : getAlgoLabel( cryptAlgo ),
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can use the read key unless its a PGP key, for 
	   which we only have the public key */
	if( cryptAlgo == CRYPT_ALGO_RSA && formatType != CRYPT_FORMAT_PGP )
		{
		status = testCrypt( cryptContext, cryptContext, cryptAlgo, NULL, 
							FALSE, FALSE );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Read of %s private key from %skey file "
			 "succeeded.\n\n", algoName( cryptAlgo ), keyFileDescr );
	return( TRUE );
	}

static int writeFileKey( const CRYPT_ALGO_TYPE cryptAlgo, 
						 const CRYPT_FORMAT_TYPE formatType,
						 const BOOLEAN createFile,
						 const BOOLEAN generateKey )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT privateKeyContext;
	const char *keyFileDescr = \
			( formatType == CRYPT_FORMAT_NONE ) ? "alternative " : \
			( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "";
	int status;

	fprintf( outputStream, "Testing %s private key write to %skey "
			 "file...\n", algoName( cryptAlgo ), keyFileDescr );

	/* Create the private key context */
	if( generateKey )
		{
		status = cryptCreateContext( &privateKeyContext, CRYPT_UNUSED, 
									 cryptAlgo );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( privateKeyContext, 
											  CRYPT_CTXINFO_LABEL, 
											  getAlgoLabel( cryptAlgo ), 
											  paramStrlen( getAlgoLabel( cryptAlgo ) ) );
			}
		if( cryptStatusOK( status ) )
			status = cryptGenerateKey( privateKeyContext );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	else
		{
		if( !loadPrivateKeyContext( &privateKeyContext, cryptAlgo ) )
			return( FALSE );
		}

	/* Create/open the file keyset.  For the first call (with RSA) we create
	   a new keyset, for subsequent calls we update the existing keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  ( formatType == CRYPT_FORMAT_NONE ) ? \
								TEST_PRIVKEY_ALT_FILE : \
							  ( formatType == CRYPT_FORMAT_PGP ) ? \
								TEST_PRIVKEY_PGP_FILE : TEST_PRIVKEY_FILE,
								createFile ? CRYPT_KEYOPT_CREATE : \
											 CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( privateKeyContext );
		if( ( formatType != CRYPT_FORMAT_CRYPTLIB ) && \
			( status == CRYPT_ERROR_NOTAVAIL ) )
			{
			/* If the format isn't supported, this isn't a problem */
			fputs( "Write of RSA private key to alternative key file "
				   "skipped as this format is\ndisabled.\n\n", 
				   outputStream );
			return( CRYPT_ERROR_NOTAVAIL );
			}
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Write the key to the file */
	if( formatType == CRYPT_FORMAT_PGP )
		status = cryptAddPublicKey( cryptKeyset, privateKeyContext );
	else
		{
		status = cryptAddPrivateKey( cryptKeyset, privateKeyContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( privateKeyContext );
	fprintf( outputStream, "Write of %s private key to %skey file "
			 "succeeded.\n\n", algoName( cryptAlgo ), keyFileDescr );
	return( TRUE );
	}

int testReadWriteFileKey( void )
	{
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_RSA, NULL ) ) ) 
		{
		if( !writeFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_CRYPTLIB, TRUE, FALSE ) )
			return( FALSE );
		if( !readFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_CRYPTLIB, FALSE ) )
			return( FALSE );
		if( !readFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_CRYPTLIB, TRUE ) )
			return( FALSE );
		if( !writeFileKey( CRYPT_ALGO_DSA, CRYPT_FORMAT_CRYPTLIB, FALSE, FALSE ) )
			return( FALSE );
		}
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_DSA, NULL ) ) ) 
		{
		if( !readFileKey( CRYPT_ALGO_DSA, CRYPT_FORMAT_CRYPTLIB, FALSE ) )
			return( FALSE );
		}
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ELGAMAL, NULL ) ) ) 
		{
		if( !writeFileKey( CRYPT_ALGO_ELGAMAL, CRYPT_FORMAT_CRYPTLIB, FALSE, FALSE ) )
			return( FALSE );
		if( !readFileKey( CRYPT_ALGO_ELGAMAL, CRYPT_FORMAT_CRYPTLIB, FALSE ) )
			return( FALSE );
		}
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) )
		{
		if( !writeFileKey( CRYPT_ALGO_ECDSA, CRYPT_FORMAT_CRYPTLIB, FALSE, FALSE ) )
			return( FALSE );
		if( !readFileKey( CRYPT_ALGO_ECDSA, CRYPT_FORMAT_CRYPTLIB, FALSE ) )
			return( FALSE );
		}
	return( TRUE );
	}

int testReadWriteAltFileKey( void )
	{
#ifdef USE_3DES
	int status;

	/* We use CRYPT_FORMAT_NONE to denote the alternative format to the 
	   standard PKCS #15.  This requires the use of 3DES so we make its use
	   conditional on 3DES being enabled */
	status = writeFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_NONE, TRUE, FALSE );
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		/* Alternative keyset access not available */
		return( TRUE );
		}
	if( status != TRUE )
		return( FALSE );
	return( readFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_NONE, FALSE ) );
#else
	fputs( "Skipping alternative key file test since 3DES isn't "
		   "available.\n\n", outputStream );
	return( TRUE );
#endif /* USE_3DES */
	}

int testReadWritePGPFileKey( void )
	{
	/* To display the written keyring data:

		gpg --list-sigs --keyring .\test.pgp
		gpg --check-sigs --keyring .\test.pgp
		gpg --list-keys --keyring .\test.pgp */
	if( !writeFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_PGP, TRUE, FALSE ) )
		return( FALSE );
	return( readFileKey( CRYPT_ALGO_RSA, CRYPT_FORMAT_PGP, FALSE ) );
	}

#if 0	/* Disabled until we can get valid third-party PKCS #15 test data */

static int fileKeyImport( const int fileNo )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	BYTE buffer[ BUFFER_SIZE ];
	int status;

	fprintf( outputStream, "Testing PKCS #15 file #%d import...\n", fileNo );

	/* Open the file keyset */
	filenameFromTemplate( buffer, P15_FILE_TEMPLATE, fileNo );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  buffer, CRYPT_KEYOPT_READONLY );
	if( fileNo == 1 && status == CRYPT_ERROR_OVERFLOW )
		{
		/* Depending on the setting of MAX_PKCS15_OBJECTS this keyset may 
		   contain too many keys to be read, if we get an overflow error we
		   continue normally */
		fprintf( outputStream, "Keyset contains too many items to read, "
				 "line %d.\n  (This is an expected condition, "
				 "continuing...).\n", __LINE__ );
		return( TRUE );
		}
	if( fileNo == 2 && status == CRYPT_ERROR_BADDATA )
		{
		/* This test file is from a pre-release implementation and may not
		   necessarily be correct so we don't complain in the case of 
		   errors */
		fputs( "Skipping keyset containing specil-case data values.\n\n", 
			   outputStream );
		return( TRUE );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	if( fileNo == 1 )
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, TEXT( "John Smith 0" ),
									 TEXT( "password" ) );
		}
	else
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, TEXT( "key and chain" ),
									 TEXT( "password" ) );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* 0 */

int testImportFileKey( void )
	{
#if 0	/* Disabled until we can get valid third-party PKCS #15 test data */
	int i;

	for( i = 1; i <= 1; i++ )
		{
		if( !fileKeyImport( i ) )
			return( FALSE );
		}
#endif /* 0 */

	return( TRUE );
	}

/* Read only the public key/certificate/certificate chain portion of a 
   keyset */

int testReadFilePublicKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int cryptAlgo, status;

	fputs( "Testing public key read from key file...\n", outputStream );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the public key from the file and make sure that it really is a
	   public-key context */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								RSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, &cryptAlgo );
	if( cryptStatusError( status ) || \
		cryptAlgo < CRYPT_ALGO_FIRST_PKC || cryptAlgo > CRYPT_ALGO_LAST_PKC )
		{
		fputs( "Returned object isn't a public-key context.\n", outputStream );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( cryptContext );

	fputs( "Read of public key from key file succeeded.\n\n", outputStream );
	return( TRUE );
	}

static int readCert( const char *certTypeName,
					 const CRYPT_CERTTYPE_TYPE certType,
					 const BOOLEAN readPrivateKey )
	{
	CRYPT_KEYSET cryptKeyset;
	int value, status;

	fprintf( outputStream, "Testing %s read from key file...\n", 
			 certTypeName );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the certificate from the file and make sure that it really is a
	   certificate */
	if( readPrivateKey )
		{
		CRYPT_CONTEXT cryptContext;

		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
									 TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		if( !checkCertPresence( cryptContext, certTypeName, certType ) )
			return( FALSE );
		cryptDestroyContext( cryptContext );
		}
	else
		{
		CRYPT_CERTIFICATE cryptCert;

		status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NAME,
									( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? \
									RSA_PRIVKEY_LABEL : USER_PRIVKEY_LABEL );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		status = cryptGetAttribute( cryptCert, CRYPT_CERTINFO_CERTTYPE, &value );
		if( cryptStatusError( status ) || value != certType )
			{
			fprintf( outputStream, "Returned object isn't a %s, line %d.\n", 
					 certTypeName, __LINE__ );
			return( FALSE );
			}
		cryptDestroyCert( cryptCert );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Read of %s from key file succeeded.\n\n", 
			 certTypeName );
	return( TRUE );
	}

int testReadFileCert( void )
	{
	return( readCert( "certificate", CRYPT_CERTTYPE_CERTIFICATE, FALSE ) );
	}
int testReadFileCertPrivkey( void )
	{
	return( readCert( "private key with certificate", CRYPT_CERTTYPE_CERTIFICATE, TRUE ) );
	}
int testReadFileCertChain( void )
	{
	return( readCert( "certificate chain", CRYPT_CERTTYPE_CERTCHAIN, FALSE ) );
	}

/* Test the ability to read older versions of PKCS #15 keysets */

static int readOldKey( const int version )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const char *keysetName;
	char fileName[ BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	int status;

	/* Open the keyset corresponding to the given cryptlib version */
	filenameFromTemplate( fileName, P15_OLD_FILE_TEMPLATE, version );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, fileName, strlen( fileName ) + 1 );
	keysetName = wcBuffer;
#else
	keysetName = fileName;
#endif /* UNICODE_STRINGS */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
							  fileName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() for version 3%d failed "
				 "with error code %d, line %d.\n", version, status, 
				 __LINE__ );
		return( FALSE );
		}

	/* Fetch the private key */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, USER_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		fprintf( outputStream, "cryptGetPrivateKey() for version 3%d failed "
				 "with error code %d, line %d.\n", version, status, 
				 __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );
	cryptKeysetClose( cryptKeyset );

	return( TRUE );
	}

int testReadOldKey( void )
	{
	int i;

	fputs( "Testing read of older key formats...\n", outputStream );

	/* Test each keyset from 3.4.7 to 3.4.0.  Note that as of 3.4.6 we don't 
	   test the 3.4.0 keyset, which was based on an RFC draft that didn't 
	   MAC the EncryptedContentInfo.ContentEncryptionAlgorithmIdentifier and 
	   used a 128-bit HMAC-SHA1 key instead of a 160-bit one.  Versions from 
	   3.4.1 to 3.4.5 contained a workaround which MAC'd the data in a 3.4.0-
	   compatible manner if the original MAC calculation failed, however 
	   this was removed in 3.4.6 when 3.4.0 was more than a decade old */
	for( i = 47; i >= 41; i-- )
		{
		if( !readOldKey( i ) )
			return( FALSE );
		}

	fputs( "Read of older key formats succeeded.\n\n", outputStream );

	return( TRUE );
	}

/* Test the ability to detect key data corruption/modification */

int testReadCorruptedKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int i, status;

	fputs( "Testing detection of key corruption in key file...\n", 
		   outputStream );
	for( i = 0; i < 4; i++ )
		{
		/* Copy the file to a temporary one, corrupting a data byte in the 
		   process */
		status = copyModifiedFile( TEST_PRIVKEY_FILE, TEST_PRIVKEY_TMP_FILE, 
								   256 );
		if( !status )
			{
			fprintf( outputStream, "Couldn't copy keyset to temporary file, "
					 "line %d.\n", __LINE__ );
			return( FALSE );
			}

		/* Try and read the key.  The open should succeed, the read should 
		   fail */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
								  CRYPT_KEYSET_FILE, TEST_PRIVKEY_TMP_FILE, 
								  CRYPT_KEYOPT_READONLY );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptKeysetOpen() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
									 TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) )
			{
			cryptDestroyContext( cryptContext );
			fprintf( outputStream, "Read of corrupted key succeeded when it "
					 "should have failed, line %d.\n", __LINE__ );
			return( FALSE );
			}
		cryptKeysetClose( cryptKeyset );
		}
	fputs( "Detection of key corruption succeeded.\n\n", outputStream );

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Certificate Read/Write Tests					*
*																			*
****************************************************************************/

/* Update a keyset to contain a certificate */

int testAddTrustedCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE trustedCert;
	int value, status;

	fputs( "Testing trusted certificate add to key file...\n", 
		   outputStream );

	/* Read the CA root certificate.  We have to make it explicitly non-
	   trusted since something else may have made it trusted previously */
	status = importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	if( cryptStatusError( status ) )
		{
		fputs( "Couldn't read certificate from file, skipping test of trusted "
			   "certificate write...\n\n", outputStream );
		return( TRUE );
		}
	status = cryptGetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
								&value );
	if( cryptStatusOK( status ) && value )
		{
		cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
						   FALSE );
		}

	/* Open the keyset, update it with the trusted certificate, and close it.
	   Before we make the certificate trusted, we try adding it as a standard 
	   certificate, which should fail */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusOK( status ) )
		{
		fprintf( outputStream, "cryptAddPublicKey() of non-trusted "
				 "certificate succeeded when it should have failed, "
				 "line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, value );
	cryptDestroyCert( trustedCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Trusted certificate add to key file succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

int testAddGloballyTrustedCert( void )
	{
	CRYPT_CERTIFICATE trustedCert;
	int status;

	fputs( "Testing globally trusted certificate add...\n", outputStream );

	/* Read the CA root certificate and make it trusted */
	status = importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	if( cryptStatusError( status ) )
		{
		fputs( "Couldn't read certificate from file, skipping test of trusted "
			   "certificate write...\n\n", outputStream );
		return( TRUE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );

	/* Update the config file with the globally trusted certificate */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED,
								FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Globally trusted certificate add failed "
				 "with error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Make the certificate untrusted and update the config again */
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, FALSE );
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED,
								FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Globally trusted certificate delete failed "
				 "with error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Globally trusted certificate add succeeded.\n\n", outputStream );
	return( TRUE );
	}

static const CERT_DATA cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and CA" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Himself" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Certification Division" ) },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* CA key usage */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_PATHLENCONSTRAINT, IS_NUMERIC, 1 },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testUpdateFileCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT publicKeyContext, privateKeyContext;
	int status;

	fputs( "Testing certificate update to key file...\n", outputStream );

	/* Create a self-signed CA certificate using the in-memory key (which is
	   the same as the one in the keyset) */
	if( !loadRSAContexts( CRYPT_UNUSED, &publicKeyContext, &privateKeyContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptCreateCert() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, publicKeyContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCert, cACertData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, privateKeyContext );
	destroyContexts( CRYPT_UNUSED, publicKeyContext, privateKeyContext );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Certificate creation failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the keyset, update it with the certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Certificate update to key file succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Update a keyset to contain a certificate chain */

static int writeFileCertChain( const CERT_DATA *certRequestData,
							   const C_STR keyFileName,
							   const BOOLEAN writeLongChain )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey, cryptKey;
	int status;

	fprintf( outputStream, "Testing %scert chain write to key file ...\n",
			 writeLongChain ? "long " : "" );

	/* Generate a key to certify.  We can't just reuse the built-in test key
	   because this has already been used as the CA key and the keyset code
	   won't allow it to be added to a keyset as both a CA key and user key,
	   so we have to generate a new one */
	status = cryptCreateContext( &cryptKey, CRYPT_UNUSED, CRYPT_ALGO_RSA );
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
		status = getPrivateKey( &cryptCAKey, ICA_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		}
	else
		{
		status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
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
	cryptDestroyCert( cryptCertChain );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Certificate chain write to key file succeeded.\n\n", 
		   outputStream );

	return( TRUE );
	}

static const CERT_DATA certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },
	{ CRYPT_CERTINFO_EMAIL, IS_STRING, 0, TEXT( "dave@wetaburgers.com" ) },
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },	/* Re-select subject DN */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testWriteFileCertChain( void )
	{
	return( writeFileCertChain( certRequestData, TEST_PRIVKEY_FILE, 
								FALSE ) );
	}

int testWriteFileLongCertChain( void )
	{
	return( writeFileCertChain( certRequestData, TEST_PRIVKEY_FILE, 
								TRUE ) );
	}

/* Delete a key from a file */

int testDeleteFileKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	fputs( "Testing delete from key file...\n", outputStream );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Delete the key from the file.  Since we don't need the DSA key any
	   more we use it as the key to delete */
	status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
							 DSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptDeletePrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								DSA_PRIVKEY_LABEL );
	if( cryptStatusOK( status ) )
		{
		cryptDestroyContext( cryptContext );
		fputs( "cryptDeleteKey() claimed the key was deleted but it's still "
			   "present.\n", outputStream );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Delete from key file succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Change the password for a key in a file */

int testChangeFileKeyPassword( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	fputs( "Testing change of key password for key file...\n", 
		   outputStream );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Read the key using the old password, delete it, and write it back
	   using the new password.  To keep things simple we just use the same
	   password (since the key will be used again later), the test of the
	   delete function earlier on has already confirmed that the old key
	   and password will be deleted so there's no chance of a false positive */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
								 RSA_PRIVKEY_LABEL );
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "password change", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	fputs( "Password change for key in key file succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

/* Write a key and certificate to a file in a single operation */

static int writeSingleStepFileCert( const CRYPT_ALGO_TYPE cryptAlgo,
									const BOOLEAN useAltKeyFile,
									const BOOLEAN useCombinedKeyCert )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert DUMMY_INIT;
	CRYPT_CONTEXT cryptContext;
	const C_STR userName = useCombinedKeyCert ? \
						   USER_PRIVKEY_LABEL : getAlgoLabel( cryptAlgo );
	int status;

	fprintf( outputStream, "Testing single-step %s key+certificate write to "
			 "%skey file...\n", algoName( cryptAlgo ), 
			 useAltKeyFile ? "alternative " : "" );

	if( useCombinedKeyCert )
		{
		char filenameBuffer[ FILENAME_BUFFER_SIZE ];

		assert( cryptAlgo == CRYPT_ALGO_RSA );

		/* Read a combined private key + certificate object */
		filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 1 );
		status = getPrivateKey( &cryptContext, filenameBuffer, 
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Private key + certificate read failed "
					 "with error code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	else
		{
		/* Create a self-signed CA certificate */
		if( !loadPrivateKeyContext( &cryptContext, cryptAlgo ) )
			return( FALSE );
		status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
								  CRYPT_CERTTYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptCreateCert() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptSetAttribute( cryptCert,
									CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, 
									cryptContext );
		if( cryptStatusOK( status ) && \
			!addCertFields( cryptCert, cACertData, __LINE__ ) )
			return( FALSE );
		if( cryptStatusOK( status ) )
			status = cryptSignCert( cryptCert, cryptContext );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "Certificate creation failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			cryptDestroyCert( status );
			return( FALSE );
			}
		}

	/* Open the keyset, write the key and certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
					useAltKeyFile ? TEST_PRIVKEY_ALT_FILE : TEST_PRIVKEY_FILE,
					CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		if( !useCombinedKeyCert )
			cryptDestroyCert( cryptCert );
		if( useAltKeyFile && status == CRYPT_ERROR_NOTAVAIL )
			{
			/* If the format isn't supported, this isn't a problem */
			fputs( "Single-step update to alternative key file "
				   "skipped as this form is\ndisabled.\n\n", 
				   outputStream );
			return( CRYPT_ERROR_NOTAVAIL );
			}
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		/* The alternative format can't store RSA keys unless they contain
		   additional, unused parameters, so we don't treat this as a
		   fatal error */
		if( useAltKeyFile && useCombinedKeyCert && \
			status == CRYPT_ERROR_NOTAVAIL )
			{
			fprintf( outputStream, "%s key+certificate doesn't contain "
					 "additional unused parameters required\n  by the "
					 "alternative format and can't be written to the "
					 "keyset.\n", algoName( cryptAlgo ) );
			fputs( "  (This is an expected result since this test verifies "
				   "handling of\n   this key type).\n\n", outputStream );

			cryptDestroyContext( cryptContext );
			cryptKeysetClose( cryptKeyset );

			return( TRUE );
			}

		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	if( !useCombinedKeyCert )
		{
		status = cryptAddPublicKey( cryptKeyset, cryptCert );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptAddPublic/PrivateKey()", 
						   status, __LINE__ );
			return( FALSE );
			}
		cryptDestroyCert( cryptCert );
		}
	cryptDestroyContext( cryptContext );

	/* Try and read the key+certificate back before we close the keyset.  
	   This ensures that the in-memory data has been updated correctly */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
								 CRYPT_KEYID_NAME, userName,
								 TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		cryptKeysetClose( cryptKeyset );
		printExtError( cryptKeyset, 
					   "private key read from in-memory cached keyset data", 
					   status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset, which flushes the in-memory changes to disk.  The
	   cacheing of data in memory ensures that all keyset updates are atomic,
	   so that it's nearly impossible to corrupt a private key keyset during
	   an update */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Try and read the key+certificate back from disk rather than the 
	   cached, in-memory version */
	status = getPrivateKey( &cryptContext, 
							useAltKeyFile ? \
								TEST_PRIVKEY_ALT_FILE : TEST_PRIVKEY_FILE,
							userName, TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, 
					   "private key read from on-disk keyset data", 
					   status, __LINE__ );
		return( FALSE );
		}

	fprintf( outputStream, "Single-step %s key+certificate write to %skey "
			 "file succeeded.\n\n", algoName( cryptAlgo ), 
			 useAltKeyFile ? "alternative " : "" );
	return( TRUE );
	}

int testSingleStepFileCert( void )
	{
	if( !writeSingleStepFileCert( CRYPT_ALGO_RSA, FALSE, FALSE ) )
		return( FALSE );
	if( !writeSingleStepFileCert( CRYPT_ALGO_RSA, FALSE, TRUE ) )
		return( FALSE );
	if( !writeSingleStepFileCert( CRYPT_ALGO_DSA, FALSE, FALSE ) )
		return( FALSE );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) && \
		!writeSingleStepFileCert( CRYPT_ALGO_ECDSA, FALSE, FALSE ) )
		return( FALSE );
	return( TRUE );
	}

int testSingleStepAltFileCert( void )
	{
#ifdef USE_3DES
	int status;

	/* Note that the combined key + cert test has to come first since this
	   will fail and leave no keyset written, while the standard test will
	   leave the keyset available for later */
	status = writeSingleStepFileCert( CRYPT_ALGO_RSA, TRUE, TRUE );
	if( status == CRYPT_ERROR_NOTAVAIL )
		{
		/* Alternative keyset access not available */
		return( TRUE );
		}
	if( status != TRUE )
		return( FALSE );
	if( !writeSingleStepFileCert( CRYPT_ALGO_RSA, TRUE, FALSE ) )
		return( FALSE );
#else
	fputs( "Skipping alternative key file single-step test since 3DES "
		   "isn't available.\n\n", outputStream );
#endif /* USE_3DES */
	return( TRUE );
	}

/* Write two keys and certs (signature + encryption) with the same DN to a
   file */

int testDoubleCertFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptSigCert, cryptEncryptCert;
	CRYPT_CONTEXT cryptCAKey, cryptSigContext, cryptEncryptContext;
	int status;

	fputs( "Testing separate signature+encryption certificate write to key "
		   "file...\n", outputStream );
	doubleCertOK = FALSE;

	/* Get the CA's key */
	status = getCAPrivateKey( &cryptCAKey, FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Generate two keys to certify.  We can't just use the built-in test key
	   because cryptlib will detect it being added to the keyset a second time
	   (if we reuse it for both keys) and because the label is a generic one
	   that doesn't work if there are two keys */
	status = cryptCreateContext( &cryptSigContext, CRYPT_UNUSED,
								 CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSigContext,
							CRYPT_CTXINFO_LABEL, DUAL_SIGNKEY_LABEL,
							paramStrlen( DUAL_SIGNKEY_LABEL ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptSigContext );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Test key generation failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptCreateContext( &cryptEncryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptEncryptContext,
							CRYPT_CTXINFO_LABEL, DUAL_ENCRYPTKEY_LABEL,
							paramStrlen( DUAL_ENCRYPTKEY_LABEL ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptEncryptContext );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Test key generation failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the certs containing the keys.  In order to avoid clashes with
	   other keys with the same CN in the public-key database, we give the
	   certs abnormal CNs.  This isn't necessary for cryptlib to manage them,
	   but because later code tries to delete leftover certs from previous
	   runs with the generic name used in the self-tests, which would also
	   delete these certs */
	status = cryptCreateCert( &cryptSigCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSigCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptSigContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptSigCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteAttribute( cryptSigCert,
									   CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSigCert,
					CRYPT_CERTINFO_COMMONNAME, TEXT( "Dave Smith (Dual)" ),
					paramStrlen( TEXT( "Dave Smith (Dual)" ) ) );
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSigCert,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_KEYUSAGE_DIGITALSIGNATURE );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptSigCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Signature certificate creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptSigCert );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptEncryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptEncryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptEncryptContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptEncryptCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteAttribute( cryptEncryptCert,
									   CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptEncryptCert,
					CRYPT_CERTINFO_COMMONNAME, TEXT( "Dave Smith (Dual)" ),
					paramStrlen( TEXT( "Dave Smith (Dual)" ) ) );
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptEncryptCert,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_KEYUSAGE_KEYENCIPHERMENT );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptEncryptCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Encryption certificate creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptEncryptCert );
		return( FALSE );
		}
	cryptDestroyContext( cryptCAKey );

	/* Open the keyset, write the keys and certificates, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  DUAL_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptSigContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptEncryptContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptSigCert );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptEncryptCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Write the two certs to a public-key database if there's one available
	   (because it may not be present, we fail quietly if access to this
	   keyset type isn't available or the keyset isn't present, it'll be
	   picked up later by other tests).

	   This certificate write is needed later to test the encryption vs. 
	   signature certificate handling.  Since they may have been added 
	   earlier we try and delete them first (we can't use the existing 
	   version since the issuerAndSerialNumber won't match the ones in the 
	   private-key keyset) */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_DATABASE, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_NONE );
	if( status != CRYPT_ERROR_PARAM3 && status != CRYPT_ERROR_OPEN )
		{
		C_CHR name[ CRYPT_MAX_TEXTSIZE + 1 ];
		int length;

		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptKeysetOpen() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			if( status == CRYPT_ERROR_OPEN )
				return( CRYPT_ERROR_FAILED );
			return( FALSE );
			}
		status = cryptGetAttributeString( cryptSigCert, 
										  CRYPT_CERTINFO_COMMONNAME,
										  name, &length );
		if( cryptStatusError( status ) )
			return( FALSE );
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		name[ length ] = TEXT( '\0' );
		do
			status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, name );
		while( cryptStatusOK( status ) );
		if( status != CRYPT_ERROR_NOTFOUND )
			{
			/* Deletion of the existing keys failed for some reason, we can't
			   continue */
			return( extErrorExit( cryptKeyset, "cryptDeleteKey()",
								  status, __LINE__ ) );
			}
		status = cryptAddPublicKey( cryptKeyset, cryptSigCert );
		if( status != CRYPT_ERROR_NOTFOUND )
			{
			/* We can get a notfound if a database keyset is defined but
			   hasn't been initialised yet so the necessary tables don't
			   exist, it can be opened but an attempt to add a key will
			   return a not found error since it's the table itself rather
			   than any item within it that isn't being found */
			if( cryptStatusOK( status ) )
				status = cryptAddPublicKey( cryptKeyset, cryptEncryptCert );
			if( cryptStatusError( status ) )
				{
				return( extErrorExit( cryptKeyset, "cryptAddPublicKey()",
									  status, __LINE__ ) );
				}

			/* The double-certificate keyset is set up, remember this for 
			   later tests */
			doubleCertOK = TRUE;
			}
		cryptKeysetClose( cryptKeyset );
		}

	/* Clean up */
	cryptDestroyContext( cryptSigContext );
	cryptDestroyContext( cryptEncryptContext );
	cryptDestroyCert( cryptSigCert );
	cryptDestroyCert( cryptEncryptCert );

	/* Try and read the keys+certs back */
	status = getPrivateKey( &cryptSigContext, DUAL_PRIVKEY_FILE,
							DUAL_SIGNKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptSigContext );
	if( cryptStatusOK( status ) )
		{
		status = getPrivateKey( &cryptEncryptContext, DUAL_PRIVKEY_FILE,
								DUAL_ENCRYPTKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		cryptDestroyContext( cryptEncryptContext );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	fputs( "Separate signature+encryption certificate write to key file "
		   "succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Write a key and two certs of different validity periods to a file */

#ifndef _WIN32_WCE	/* Windows CE doesn't support ANSI C time functions */

int testRenewedCertFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptOldCert, cryptNewCert;
	CRYPT_CONTEXT cryptCAKey, cryptContext;
	time_t writtenValidTo = 0 /* Dummy */, readValidTo;
	int dummy, status;

	fputs( "Testing renewed certificate write to key file...\n", 
		   outputStream );

	/* Get the CA's key and the key to certify */
	status = getCAPrivateKey( &cryptCAKey, FALSE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "CA private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptContext ) )
		return( FALSE );

	/* Create the certs containing the keys */
	status = cryptCreateCert( &cryptOldCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptOldCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptOldCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		time_t validity = time( NULL );

		/* Valid for one month ending tomorrow (we can't make it already-
		   expired or cryptlib will complain) */
		validity += 86400;
		cryptSetAttributeString( cryptOldCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		validity -= ( 86400 * 31 );
		status = cryptSetAttributeString( cryptOldCert,
					CRYPT_CERTINFO_VALIDFROM, &validity, sizeof( time_t ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptOldCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Signature certificate creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptOldCert );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptNewCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptNewCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
		}
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptNewCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		time_t validity = time( NULL );

		/* Valid for one month starting yesterday (it's actually valid for
		   one month + one day to sidestep the one-month sanity check in the
		   private key read code that warns of about-to-expire keys) */
		validity -= 86400;
		cryptSetAttributeString( cryptNewCert,
					CRYPT_CERTINFO_VALIDFROM, &validity, sizeof( time_t ) );
		validity += ( 86400 * 32 );
		status = cryptSetAttributeString( cryptNewCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		writtenValidTo = validity;
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptNewCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Encryption certificate creation failed with "
				 "error code %d, line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptNewCert );
		return( FALSE );
		}
	cryptDestroyContext( cryptCAKey );

	/* First, open the keyset, write the key and certificates (using an
	   in-memory update), and close it.  This tests the ability to use
	   information cached in memory to handle the update */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetOpen() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptOldCert );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptNewCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, 
					   "cryptAddPublicKey() (in-memory update)", 
					   status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Then try again, but this time perform an on-disk update, closing the
	   keyset between the first and second update.  This tests the ability
	   to recover the information needed to handle the update from data in
	   the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
		}
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptOldCert );
	if( cryptStatusOK( status ) )
		status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Keyset creation in preparation for on-disk "
				 "update failed with error code %d, line %d.\n", status, 
				 __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptNewCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey() (on-disk update)", 
					   status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptKeysetClose() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( cryptContext );
	cryptDestroyCert( cryptOldCert );
	cryptDestroyCert( cryptNewCert );

	/* Try and read the (newest) key+certificate back */
	status = getPrivateKey( &cryptContext, RENEW_PRIVKEY_FILE,
							RSA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Private key read failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttributeString( cryptContext,
					CRYPT_CERTINFO_VALIDTO, &readValidTo, &dummy );
	if( cryptStatusError( status ) )
		{
		return( extErrorExit( cryptContext, "cryptGetAttributeString",
							  status, __LINE__ ) );
		}
	if( writtenValidTo != readValidTo )
		{
		const int diff = ( int ) ( readValidTo - writtenValidTo );
		const char *units = ( diff % 60 ) ? "seconds" : "minutes";

		fprintf( outputStream, "Returned certificate != latest valid "
				 "certificate, diff.= %d %s, line %d.\n", 
				 ( diff % 60 ) ? diff : diff / 60, units, __LINE__ );
		if( diff == 3600 || diff == -3600 )
			{
			/* See the comment on DST issues in testcert.c */
			fputs( "  (This is probably due to a difference between DST at "
				   "certificate creation and DST\n   now, and isn't a "
				   "serious problem).\n\n", outputStream );
			}
		else
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	fputs( "Renewed certificate write to key file succeeded.\n\n", 
		   outputStream );
	return( TRUE );
	}

#else

int testRenewedCertFile( void )
	{
	/* Since the renewal is time-based, we can't easily test this under
	   WinCE */
	return( TRUE );
	}
#endif /* WinCE */

/* Test reading various non-cryptlib PKCS #15 files */

int testReadMiscFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	void *fileNamePtr = filenameBuffer;
	int status;

	fputs( "Testing miscellaneous key file read...\n", outputStream );

	filenameFromTemplate( filenameBuffer, MISC_PRIVKEY_FILE_TEMPLATE, 1 );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
	fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  fileNamePtr, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "Couldn't open/scan keyset, status %d, "
				 "line %d.\n", status, __LINE__ );
		return( FALSE );
		}
#if 0
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
								 CRYPT_KEYID_NAME, 
								 TEXT( "56303156793b318327b25a84808f2cb311c55b0b" ), 
								 TEXT( "PASSWORD" ) );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
#endif /* 0 */
	cryptKeysetClose( cryptKeyset );

	fputs( "Miscellaneous key file read succeeded.\n\n", outputStream );
	return( TRUE );
	}

/* Generic test routines used for debugging */

void xxxPrivKeyRead( const char *fileName, const char *keyName, 
					 const char *password )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  fileName, CRYPT_KEYOPT_READONLY );
	assert( cryptStatusOK( status ) );

	/* Read the key from the file */
	if( password == NULL )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptContext,
									CRYPT_KEYID_NAME, keyName );
		}
	else
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, keyName, password );
		}
	assert( cryptStatusOK( status ) );

	cryptKeysetClose( cryptKeyset );
	}

void xxxPubKeyRead( const char *fileName, const char *keyName )
	{
	xxxPrivKeyRead( fileName, keyName, NULL );
	}
#endif /* TEST_KEYSET */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
