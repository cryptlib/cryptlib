/****************************************************************************
*																			*
*						Public-key ID Generation Routines					*
*						Copyright Peter Gutmann 1992-2020					*
*																			*
****************************************************************************/

#include <stdio.h>
#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "context/context.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

#if defined( USE_INT_ASN1 ) && defined( USE_PKC )

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Calculate a keyID from an encoded SubjectPublicKeyInfo record */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int calculateFlatKeyID( IN_BUFFER( keyInfoSize ) const void *keyInfo,
							   IN_LENGTH_SHORT_MIN( 16 ) const int keyInfoSize,
							   OUT_BUFFER_FIXED( keyIdLen ) BYTE *keyID,
							   IN_LENGTH_SHORT_MIN( KEYID_SIZE ) const int keyIdLen,
							   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
#ifdef CONFIG_CUSTOM_1
	STREAM stream;
	void *nakedKeyInfo DUMMY_INIT;
	int nakedKeyInfoLength DUMMY_INIT, dummy, status;
#endif /* CONFIG_CUSTOM_1 */

	assert( isReadPtrDynamic( keyInfo, keyInfoSize ) );
	assert( isWritePtrDynamic( keyID, keyIdLen ) );

	REQUIRES( isShortIntegerRangeMin( keyInfoSize, 16 ) );
	REQUIRES( keyIdLen == KEYID_SIZE || keyIdLen == 32 );
	REQUIRES( isHashAlgo( hashAlgo ) );

	/* Get the hash algorithm information */
	getHashAtomicParameters( hashAlgo, 0, &hashFunctionAtomic, NULL );

	/* Hash the key info to get the key ID */
#ifndef CONFIG_CUSTOM_1
	hashFunctionAtomic( keyID, keyIdLen, keyInfo, keyInfoSize );
#else
	/* Alternative (insecure) method specified in RFC 2459 / 3280 that 
	   strips the algorithm metadata before hashing, allowing key 
	   substitution attacks */
	sMemConnect( &stream, keyInfo, keyInfoSize );
	readSequence( &stream, &dummy );
	readUniversal( &stream );
	status = readBitStringHole( &stream, &dummy, 16, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = sMemGetDataBlockRemaining( &stream, &nakedKeyInfo, 
											&nakedKeyInfoLength );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	hashFunctionAtomic( keyID, keyIdLen, nakedKeyInfo, nakedKeyInfoLength );
#endif /* CONFIG_CUSTOM_1 */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*				KeyID-from-Encoded-Data Calculation Routines				*
*																			*
****************************************************************************/

#ifdef USE_DEVICES

/* Instantiate static context data from raw encoded public-key data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int createStaticContext( OUT_PTR CONTEXT_INFO *staticContextInfo,
								OUT_PTR PKC_INFO *contextData,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								const CAPABILITY_INFO *capabilityInfoPtr,
								IN_BUFFER( publicKeyDataLength ) \
									const void *publicKeyData,
								IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
									const int publicKeyDataLength )
	{
	CAP_READPUBKEY_FUNCTION readPublicKeyFunction;
	STREAM stream;
	int status;

	assert( isWritePtr( staticContextInfo, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( contextData, sizeof( PKC_INFO ) ) );
	assert( isReadPtrDynamic( publicKeyData, publicKeyDataLength ) );

	REQUIRES( ( isEccAlgo( cryptAlgo ) && \
				isShortIntegerRangeMin( publicKeyDataLength, 
										MIN_PKCSIZE_ECCPOINT ) ) || \
			  ( !isEccAlgo( cryptAlgo ) && \
				isShortIntegerRangeMin( publicKeyDataLength,
										MIN_PKCSIZE ) ) );

	/* Clear return values */
	memset( staticContextInfo, 0, sizeof( CONTEXT_INFO ) );
	memset( contextData, 0, sizeof( PKC_INFO ) );

	/* Explicitly call the native public-key read function rather than the 
	   one associated with the capability info.  This is required because 
	   we're potentially working with a device context and we want to read
	   the public-key data into a native-context form in order to calculate
	   the key IDs for it */
	switch( cryptAlgo )
		{
#ifdef USE_DH
		case CRYPT_ALGO_DH:
			readPublicKeyFunction = readPublicKeyDlpFunction;
			break;
#endif /* USE_DH */

		case CRYPT_ALGO_RSA:
			readPublicKeyFunction = readPublicKeyRsaFunction;
			break;

#ifdef USE_DSA
		case CRYPT_ALGO_DSA:
			readPublicKeyFunction = readPublicKeyDlpFunction;
			break;
#endif /* USE_DSA */

#ifdef USE_ELGAMAL
		case CRYPT_ALGO_ELGAMAL:
			readPublicKeyFunction = readPublicKeyDlpFunction;
			break;
#endif /* USE_ELGAMAL */

#ifdef USE_ECDH
		case CRYPT_ALGO_ECDH:
			readPublicKeyFunction = readPublicKeyEccFunction;
			break;
#endif /* USE_ECDH */

#ifdef USE_ECDSA
		case CRYPT_ALGO_ECDSA:
			readPublicKeyFunction = readPublicKeyEccFunction;
			break;
#endif /* USE_ECDSA */

#if defined( USE_25519 ) || defined( USE_ED25519 )
		case CRYPT_ALGO_25519:
		case CRYPT_ALGO_ED25519:
			readPublicKeyFunction = readPublicKey25519Function;
			break;
#endif /* USE_25519 || USE_ED25519 */

		default:
			retIntError();
		}
	ENSURES( capabilityInfoPtr != NULL );

	/* Initialise a static context to read the key data into */
	status = staticInitContext( staticContextInfo, CONTEXT_PKC,
								capabilityInfoPtr, contextData,
								sizeof( PKC_INFO ), NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the key data into the static context and calculate the keyIDs.
	   We can do this now that the data is in a native context rather than
	   being present only in raw encoded form */
	sMemConnect( &stream, publicKeyData, publicKeyDataLength );
	status = readPublicKeyFunction( &stream, staticContextInfo, cryptAlgo, 
									KEYFORMAT_CERT, FALSE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		staticDestroyContext( staticContextInfo );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Calculate a keyID when the only key data present is a raw encoded
   SubjectPublicKeyInfo record.  This occurs when the object is a device
   object and we don't have access to the key components.

   This is a bit more complicated than the standard keyID calculation 
   because while the hash-of-SPKI form is rather easier to calculate, the 
   other oddball forms aren't since they first require breaking down the 
   SPKI into its components via a native object and then re-encoding them in 
   the various ways that we need to calculate the other forms of keyID */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculatePGPKeyID( INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo );

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculateKeyIDFromEncoded( INOUT_PTR CONTEXT_INFO *contextInfoPtr,
									  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
									  OUT_BUFFER_OPT_FIXED( 32 ) BYTE *keyID,
									  IN_LENGTH_SHORT_Z const int keyIDlength, 
									  IN_ALGO const CRYPT_ALGO_TYPE hashAlgo )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
						DATAPTR_GET( contextInfoPtr->capabilityInfo );
	CONTEXT_INFO staticContextInfo;
	PKC_INFO staticContextData, *publicKey = contextInfoPtr->ctxPKC;
	const BOOLEAN isPgpAlgo = \
		( cryptAlgo == CRYPT_ALGO_RSA || cryptAlgo == CRYPT_ALGO_DSA || \
		  cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? TRUE : FALSE;
	void *keyIDptr = ( keyID != NULL ) ? keyID : publicKey->keyID;
	const int keyIDsize = ( keyID != NULL ) ? keyIDlength : KEYID_SIZE;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( keyID == NULL || isWritePtr( keyID, keyIDlength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isPkcAlgo( cryptAlgo ) );
	REQUIRES( ( keyID == NULL && keyIDlength == 0 ) || \
			  ( keyID != NULL && keyIDlength == 32 ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* Calculate the keyID for the pre-encoded key data */
	status = calculateFlatKeyID( publicKey->publicKeyInfo, 
								 publicKey->publicKeyInfoSize, 
								 keyIDptr, keyIDsize, hashAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're just being asked for a standalone keyID, we're done */
	if( keyID != NULL )
		return( CRYPT_OK );

	/* At this point we're (technically) done, however a few special-case
	   situations require further processing: 

	   If the keys are held externally (e.g. in a crypto device) then 
	   there's no way to tell what the nominal keysize for the context 
	   should be.  In order to determine this we have to parse the key
	   data in order to extract the specific component that defines the
	   key's nominal length.

	   PGP keyIDs present a similar problem because we would in theory 
	   need to decode the flattened key data and then re-encode it in the 
	   format needed to generate the PGP IDs */
	if( !( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) || \
		   isPgpAlgo ) )
		return( CRYPT_OK );

	/* If we're not using PGP algorithms and the key size has already been
	   set by device-specific code then there's nothing further to do */
#if !defined( USE_PGP ) && !defined( USE_PGPKEYS )
	if( contextInfoPtr->ctxPKC->keySizeBits != 0 )
		return( CRYPT_OK );
#endif /* !USE_PGP && !USE_PGPKEYS */

	/* Process the pre-encoded key data to get the key size and PGP IDs.
	   While it would be possible to do this with a lot of customised 
	   duplication of code from other parts of key_rd.c and from key_wr.c 
	   it's easier to just create a static public-key context from the 
	   encoded key data and let the standard key-setup and keyID code take 
	   care of it.  On the downside, it requires creation of a static (if 
	   not a full) public-key context just for this purpose */
	status = createStaticContext( &staticContextInfo, &staticContextData, 
								  cryptAlgo, capabilityInfoPtr,
								  publicKey->publicKeyInfo, 
								  publicKey->publicKeyInfoSize );
	if( cryptStatusError( status ) )
		return( status );
#if defined( USE_PGP ) || defined( USE_PGPKEYS )
	if( isPgpAlgo )
		{
		status = calculatePGPKeyID( &staticContextInfo, cryptAlgo );
		if( cryptStatusError( status ) )
			{
			staticDestroyContext( &staticContextInfo );
			return( status );
			}
		}
#endif /* USE_PGP || USE_PGPKEYS */

	/* If it's a non-native context, explicitly set the key size.  For 
	   native contexts this is done by the init-key function but for non-
	   native contexts this function is never called since there are no key 
	   components present to initialise.  Because of this we have to 
	   explicitly copy the key size information from the static native 
	   context that we've created */
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
		contextInfoPtr->ctxPKC->keySizeBits = staticContextData.keySizeBits;

	/* If it's a PGP algorithm, copy across any relevant PGP keyIDs */
#if defined( USE_PGP ) || defined( USE_PGPKEYS )
	if( isPgpAlgo )
		{
		if( TEST_FLAG( staticContextData.flags, 
					   PKCINFO_FLAG_PGPKEYID_SET ) )
			{
			memcpy( publicKey->pgp2KeyID, staticContextData.pgp2KeyID, 
					PGP_KEYID_SIZE );
			SET_FLAG( contextInfoPtr->ctxPKC->flags, 
					  PKCINFO_FLAG_PGPKEYID_SET );
			}
		if( TEST_FLAG( staticContextData.flags, 
					   PKCINFO_FLAG_OPENPGPKEYID_SET ) )
			{
			memcpy( publicKey->openPgpKeyID, staticContextData.openPgpKeyID, 
					PGP_KEYID_SIZE );
			SET_FLAG( contextInfoPtr->ctxPKC->flags, 
					  PKCINFO_FLAG_OPENPGPKEYID_SET );
			}
		}
#endif /* USE_PGP  || USE_PGPKEYS */
	staticDestroyContext( &staticContextInfo );

	return( CRYPT_OK );
	}
#endif /* USE_DEVICES */

/****************************************************************************
*																			*
*							KeyID Calculation Routines						*
*																			*
****************************************************************************/

/* Generate a PGP keyID */

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculateOpenPGPKeyID( INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
						DATAPTR_GET( contextInfoPtr->capabilityInfo );
	PKC_INFO *publicKey = contextInfoPtr->ctxPKC;
	HASH_FUNCTION hashFunction;
	HASHINFO hashInfo;
	STREAM stream;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 50 + 8 ];
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ], packetHeader[ 64 + 8 ];
	int hashSize, length, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( isPkcAlgo( cryptAlgo ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* Generate an OpenPGP key ID.  Note that the creation date isn't 
	   necessarily present if the key came from a non-PGP source, in which 
	   case the date will have a value of zero.  This leads to problems 
	   because PGP hashes the creation date into the key ID, which means
	   that mixing keys from PGP and non-PGP sources leads to them being
	   identified with different IDs even though they're the same key.

	   There's no easy fix for this, the best that we can do is leave the 
	   date as an all-zero value, which at least produces a constant ID:

		byte		ctb = 0x99
		byte[2]		length
		-- Key data --
		byte		version = 4
		byte[4]		key generation time 
		byte		algorithm
		byte[]		key data */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 4 ) + 50 );
	status = capabilityInfoPtr->writePublicKeyFunction( &stream, 
							contextInfoPtr, cryptAlgo, KEYFORMAT_PGP, 
							"public_key", 10 );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}
	length = stell( &stream );
	REQUIRES_SC( isIntegerRangeNZ( length ) );
	packetHeader[ 0 ] = 0x99;
	packetHeader[ 1 ] = intToByte( length >> 8 );
	packetHeader[ 2 ] = intToByte( length );

	/* Hash the data needed to generate the OpenPGP keyID */
	getHashParameters( CRYPT_ALGO_SHA1, 0, &hashFunction, &hashSize );
	hashFunction( hashInfo, NULL, 0, packetHeader, 1 + 2, 
				  HASH_STATE_START );
	hashFunction( hashInfo, hash, CRYPT_MAX_HASHSIZE, buffer, length, 
				  HASH_STATE_END );
	memcpy( publicKey->openPgpKeyID, hash + hashSize - PGP_KEYID_SIZE, 
			PGP_KEYID_SIZE );
	sMemClose( &stream );
	SET_FLAG( contextInfoPtr->ctxPKC->flags, 
			  PKCINFO_FLAG_OPENPGPKEYID_SET );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculatePGPKeyID( INOUT_PTR CONTEXT_INFO *contextInfoPtr,
							  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( isPkcAlgo( cryptAlgo ) );

	/* If it's an RSA key, we need to calculate the PGP 2 key ID alongside 
	   the cryptlib one */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
		BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 50 + 8 ];
		int length;

		status = exportBignum( buffer, CRYPT_MAX_PKCSIZE, &length,
							   &pkcInfo->rsaParam_n );
		if( cryptStatusError( status ) )
			return( status );
		if( length > PGP_KEYID_SIZE )
			{
			memcpy( pkcInfo->pgp2KeyID, 
					buffer + length - PGP_KEYID_SIZE, PGP_KEYID_SIZE );
			SET_FLAG( contextInfoPtr->ctxPKC->flags, 
					  PKCINFO_FLAG_PGPKEYID_SET );
			}
		}

	/* If the OpenPGP ID is already set by having the key loaded from a PGP
	   keyset, we're done */
	if( TEST_FLAG( contextInfoPtr->ctxPKC->flags, 
				   PKCINFO_FLAG_OPENPGPKEYID_SET ) )
		return( CRYPT_OK );

	/* If it's a non-PGP algorithm then we can't do anything with it */
	if( cryptAlgo != CRYPT_ALGO_RSA && cryptAlgo != CRYPT_ALGO_DSA && \
		cryptAlgo != CRYPT_ALGO_ELGAMAL && cryptAlgo != CRYPT_ALGO_ECDSA )
		return( CRYPT_OK );

	/* Finally, set the OpenPGP key ID */
	return( calculateOpenPGPKeyID( contextInfoPtr, cryptAlgo ) );
	}
#endif /* USE_PGP || USE_PGPKEYS */

/* Generate a keyID for a PKCS #3 key, which differs slightly from the 
   FIPS 186/X9.42 standard format in that there's no q value present, so we
   have to write a dummy zero value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePKCS3Key( INOUT_PTR STREAM *stream, 
						  const PKC_INFO *dlpKey,
						  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const DH_DOMAINPARAMS *domainParams = dlpKey->domainParams;
	const BIGNUM *p = ( domainParams != NULL ) ? \
					  &domainParams->p : &dlpKey->dlpParam_p;
	const BIGNUM *g = ( domainParams != NULL ) ? \
					  &domainParams->g : &dlpKey->dlpParam_g;
	const int parameterSize = sizeofShortObject( \
											sizeofBignum( p ) + \
											3 +		/* INTEGER value 0 */
											sizeofBignum( g ) );
	const int componentSize = sizeofBignum( &dlpKey->dlpParam_y );
	ALGOID_PARAMS algoIDparams;
	int totalSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( dlpKey, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( dlpKey ) );
	REQUIRES( isDlpAlgo( cryptAlgo ) );

	/* Implement a cut-down version of writeDlpSubjectPublicKey(), writing a 
	   zero value for q */
	initAlgoIDparams( &algoIDparams );
	algoIDparams.extraLength = parameterSize;
	status = totalSize = sizeofAlgoIDex( cryptAlgo, &algoIDparams );
	if( cryptStatusError( status ) )
		return( status );
	totalSize += sizeofShortObject( componentSize + 1 );
	writeSequence( stream, totalSize );
	writeAlgoIDex( stream, cryptAlgo, &algoIDparams, DEFAULT_TAG );
	writeBignum( stream, p );
	swrite( stream, "\x02\x01\x00", 3 );	/* Integer value 0 */
	writeBignum( stream, g );
	writeBitStringHole( stream, componentSize, DEFAULT_TAG );
	return( writeBignum( stream, &dlpKey->dlpParam_y ) );
	}

/* Generate an X.509 key ID, which is the SHA-1 hash of the 
   SubjectPublicKeyInfo.  There are about half a dozen incompatible ways of 
   generating X.509 keyIdentifiers, the following is conformant with the 
   PKIX specification ("use whatever you like as long as it's unique") but 
   differs slightly from one common method that hashes the SubjectPublicKey 
   without the BIT STRING encapsulation.  The problem with that method is 
   that some DLP-based algorithms use a single integer as the 
   SubjectPublicKey, leading to potential key ID clashes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculateKeyID( INOUT_PTR CONTEXT_INFO *contextInfoPtr,
						   OUT_BUFFER_OPT_FIXED( 32 ) BYTE *keyID,
						   IN_LENGTH_SHORT_Z const int keyIDlength, 
						   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	PKC_INFO *publicKey = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
						DATAPTR_GET( contextInfoPtr->capabilityInfo );
	STREAM stream;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 50 + 8 ];
	void *keyIDptr = ( keyID != NULL ) ? keyID : publicKey->keyID;
	const int keyIDsize = ( keyID != NULL ) ? keyIDlength : KEYID_SIZE;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( keyID == NULL || isWritePtr( keyID, keyIDlength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( ( keyID == NULL && keyIDlength == 0 ) || \
			  ( keyID != NULL && keyIDlength == 32 ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( capabilityInfoPtr != NULL );

	cryptAlgo = capabilityInfoPtr->cryptAlgo;

	/* If the public key info is present in pre-encoded form, calculate the
	   key ID directly from that */
	if( publicKey->publicKeyInfo != NULL )
		{
#ifdef USE_DEVICES
		return( calculateKeyIDFromEncoded( contextInfoPtr, cryptAlgo, 
										   keyID, keyIDlength, hashAlgo ) );
#else
		retIntError();
#endif /* USE_DEVICES */
		}

	/* Write the public key fields to a buffer and hash them to get the key
	   ID */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 4 ) + 50 );
	if( isDlpAlgo( cryptAlgo ) && BN_is_zero( &publicKey->dlpParam_q ) )
		{
		/* OpenPGP Elgamal keys and TLS/SSH DH keys don't have a q 
		   parameter, which makes it impossible to write them in the X.509 
		   format.  If this situation occurs we write them in a cut-down
		   version of the format, which is OK because the X.509 keyIDs are 
		   explicit and not implicitly generated from the key data like the
		   OpenPGP one */
		status = writePKCS3Key( &stream, publicKey, cryptAlgo );
		}
	else
		{
		status = capabilityInfoPtr->writePublicKeyFunction( &stream, 
								contextInfoPtr, cryptAlgo, KEYFORMAT_CERT, 
								"public_key", 10 );
		}
	if( cryptStatusOK( status ) )
		{
		status = calculateFlatKeyID( buffer, stell( &stream ), 
									 keyIDptr, keyIDsize, hashAlgo );
		}
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're just being asked for a standalone keyID, we're done */
	if( keyID != NULL )
		return( CRYPT_OK );

#if defined( USE_PGP ) || defined( USE_PGPKEYS )
	return( calculatePGPKeyID( contextInfoPtr, cryptAlgo ) );
#else
	return( CRYPT_OK );
#endif /* USE_PGP || USE_PGPKEYS */
	}

/****************************************************************************
*																			*
*							Context Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initKeyID( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_V( sanityCheckContext( contextInfoPtr ) );
	REQUIRES_V( contextInfoPtr->type == CONTEXT_PKC );

	/* Set the access method pointers */
	FNPTR_SET( pkcInfo->calculateKeyIDFunction, calculateKeyID );
	}
#else

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculateKeyIDDummy( INOUT_PTR CONTEXT_INFO *contextInfoPtr,
								IN_ALGO const CRYPT_ALGO_TYPE hashAlgo )
	{
	PKC_INFO *publicKey = contextInfoPtr->ctxPKC;
	MESSAGE_DATA msgData;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( isHashAlgo( hashAlgo ) );

	/* If we're not using ASN.1 then we can't calculate keyIDs, but then no 
	   code that requires keyIDs is actually enabled so we just set a dummy
	   value for the ID */
	setMessageData( &msgData, publicKey->keyID, KEYID_SIZE );
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
							 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void initKeyID( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_V( sanityCheckContext( contextInfoPtr ) );
	REQUIRES_V( contextInfoPtr->type == CONTEXT_PKC );

	/* Set the access method pointers */
	FNPTR_SET( pkcInfo->calculateKeyIDFunction, calculateKeyIDDummy );
	}
#endif /* USE_INT_ASN1 && USE_PKC */

