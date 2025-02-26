/****************************************************************************
*																			*
*					cryptlib PKCS #12 Object-Read Routines					*
*						Copyright Peter Gutmann 1997-2016					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "keyset.h"
  #include "pkcs12.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs12.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS12

/* OID information used to read a PKCS #12 keyset */

static const OID_INFO keyCertBagOIDinfo[] = {
	{ OID_PKCS12_SHROUDEDKEYBAG, TRUE },
	{ OID_PKCS12_CERTBAG, FALSE },
	{ NULL, 0 }, { NULL, 0 }
	};

/* OID information used to read decrypted PKCS #12 objects */

static const OID_INFO certOIDinfo[] = {
	{ OID_PKCS9_X509CERTIFICATE, 0 },
	{ NULL, 0 }, { NULL, 0 }
	};

/* Protection algorithms used for encrypted keys and certificates, and a 
   mapping from PKCS #12 to cryptlib equivalents.  Beyond these there are
   also 40- and 128-bit RC4 and 128-bit RC2, but nothing seems to use
   them.  40-bit RC2 is used by Windows to, uhh, "protect" public
   certificates so we have to support it in order to be able to read
   certificates (see the comment in keymgmt/pkcs12.c for details on how
   the 40-bit RC2 key is handled).
   
   Alongside the standard Microsoft-invented PKCS #12 stuff there's also a
   mutant form that uses PKCS #15-like key derivation that appeared around
   2020 or so which we also have to accommodate, this has PBKDF2 as its
   algorithm OID and from then on goes into PKCS #15-style content */

enum { PKCS12_ALGO_NONE, PKCS12_ALGO_3DES_192, PKCS12_ALGO_3DES_128, 
	   PKCS12_ALGO_RC2_40, PKCS12_ALGO_SPECIAL };

typedef struct {
	const CRYPT_ALGO_TYPE cryptAlgo;
	const int keySize;
	} PKCS12_ALGO_MAP;

static const PKCS12_ALGO_MAP algoMap3DES_192 = { CRYPT_ALGO_3DES, bitsToBytes( 192 ) };
static const PKCS12_ALGO_MAP algoMap3DES_128 = { CRYPT_ALGO_3DES, bitsToBytes( 128 ) };
static const PKCS12_ALGO_MAP algoMapRC2_40 = { CRYPT_ALGO_RC2, bitsToBytes( 40 ) };

static const OID_INFO encryptionOIDinfo[] = {
	{ OID_PKCS12_PBEWITHSHAAND3KEYTRIPLEDESCBC, PKCS12_ALGO_3DES_192, 
	  &algoMap3DES_192 },
	{ OID_PKCS12_PBEWITHSHAAND2KEYTRIPLEDESCBC, PKCS12_ALGO_3DES_128,
	  &algoMap3DES_128 },
	{ OID_PKCS12_PBEWITHSHAAND40BITRC2CBC, PKCS12_ALGO_RC2_40,
	  &algoMapRC2_40 },
	{ OID_PBES2, PKCS12_ALGO_SPECIAL, NULL },
	{ NULL, 0 }, { NULL, 0 }
	};

/* PKCS #12 attributes.  This is a subset of the full range that can be 
   used, we skip any that we don't care about using a wildcard OID match */

enum { PKCS12_ATTRIBUTE_NONE, PKCS12_ATTRIBUTE_LABEL, PKCS12_ATTRIBUTE_ID };

static const OID_INFO attributeOIDinfo[] = {
	{ OID_PKCS9_FRIENDLYNAME, PKCS12_ATTRIBUTE_LABEL },
	{ OID_PKCS9_LOCALKEYID, PKCS12_ATTRIBUTE_ID },
	{ WILDCARD_OID, PKCS12_ATTRIBUTE_NONE },
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read protection algorithm information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readProtAlgoInfo( INOUT_PTR STREAM *stream, 
							 OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
							 OUT_INT_SHORT_Z int *keySize )
	{
	const OID_INFO *oidInfoPtr;
	const PKCS12_ALGO_MAP *algoMapInfoPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( keySize, sizeof( int ) ) );

	/* Clear return values */
	*cryptAlgo = CRYPT_ALGO_NONE;
	*keySize = 0;

	/* Read the wrapper and the protection algorithm OID and extract the
	   protection information parameters for it */
	readSequence( stream, NULL );
	status = readOIDEx( stream, encryptionOIDinfo, 
						FAILSAFE_ARRAYSIZE( encryptionOIDinfo, OID_INFO ), 
						&oidInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( oidInfoPtr->selectionID == PKCS12_ALGO_SPECIAL )
		{
		/* It's the kludged PKCS #15-style protection mechanism, skip the
		   PBKDF2 wrapper and indicate that we have to handle it 
		   specially */
		readSequence( stream, NULL );
		readSequence( stream, NULL );
		status = readFixedOID( stream, OID_PBKDF2, 
							   sizeofOID( OID_PBKDF2 ) );
		return( cryptStatusError( status ) ? status : OK_SPECIAL );
		}
	algoMapInfoPtr = oidInfoPtr->extraInfo;
	*cryptAlgo = algoMapInfoPtr->cryptAlgo;
	*keySize = algoMapInfoPtr->keySize;

	return( CRYPT_OK );
	}

/* Read key-derivation information.  Because of the kludging on of PKCS #15-
   style key derivation around 2020 there are two different functions used 
   to read these, one in the standard PKCS #12 style, the other in the PKCS 
   #15 style */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readKeyDerivationInfoP12( INOUT_PTR STREAM *stream, 
									 INOUT_PTR PKCS12_OBJECT_INFO *pkcs12objectInfo )
	{
	long intValue;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12objectInfo, sizeof( PKCS12_OBJECT_INFO ) ) );

	/* Read the wrapper and salt value */
	readSequence( stream, NULL );
	status = readOctetString( stream, pkcs12objectInfo->salt, 
							  &pkcs12objectInfo->saltSize, 
							  1, CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the iteration count and make sure that it's within a sensible
	   range */
	status = readShortInteger( stream, &intValue );
	if( cryptStatusError( status ) )
		return( status );
	if( intValue < 1 || intValue > MAX_KEYSETUP_ITERATIONS )
		return( CRYPT_ERROR_BADDATA );
	ENSURES( isIntegerRange( intValue ) );
	pkcs12objectInfo->iterations = ( int ) intValue;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readKeyDerivationInfoP15( INOUT_PTR STREAM *stream, 
									 INOUT_PTR PKCS12_OBJECT_INFO *pkcs12objectInfo )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	QUERY_INFO queryInfo;
	ALGOID_PARAMS algoIDparams;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12objectInfo, sizeof( PKCS12_OBJECT_INFO ) ) );

	/* Read the wrapper, salt, and iteration count.  This is identical to 
	   the PKCS #12 form so we read it using the PKCS #12 function, then
	   continue with the extra PKCS #15 fields */
	status = readKeyDerivationInfoP12( stream, pkcs12objectInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Continue with the PKCS #15-style parameters, the optional key size 
	   and PRF algorithm */
	if( peekTag( stream ) == BER_INTEGER )
		{
		long intValue;

		status = readShortInteger( stream, &intValue );
		if( cryptStatusError( status ) )
			return( status );
		if( intValue < MIN_KEYSIZE || intValue > CRYPT_MAX_KEYSIZE )
			return( CRYPT_ERROR_BADDATA );
		ENSURES( isIntegerRange( intValue ) );
		pkcs12objectInfo->keySize = ( int ) intValue;
		}
	status = readAlgoIDex( stream, &cryptAlgo, &algoIDparams, 
						   ALGOID_CLASS_HASH );
	if( cryptStatusError( status ) )
		return( status );
	pkcs12objectInfo->prfAlgo = cryptAlgo;
	pkcs12objectInfo->prfAlgoParams = algoIDparams.hashParam;

	/* Finally, read the encryption algorithm information.  We use the query
	   form since at this point we're just scanning the file rather than 
	   trying to do anything with the contents */
	status = readContextAlgoID( stream, NULL, &queryInfo, DEFAULT_TAG, 
								ALGOID_CLASS_CRYPT );
	if( cryptStatusError( status ) )
		return( status );
	pkcs12objectInfo->cryptAlgo = queryInfo.cryptAlgo;
	if( queryInfo.cryptMode != CRYPT_MODE_CBC )
		{
		/* PKCS #12 implies CBC mode, in theory we could see other modes 
		   here but they're not defined for PKCS #12 use */
		return( CRYPT_ERROR_BADDATA );
		}
	ENSURES( rangeCheck( queryInfo.ivLength, 1, CRYPT_MAX_IVSIZE ) );
	memcpy( pkcs12objectInfo->iv, queryInfo.iv, queryInfo.ivLength ); 
	pkcs12objectInfo->ivSize = queryInfo.ivLength;

	/* Remember that this is PKCS #15-style processing, not PKCS #12 */
	pkcs12objectInfo->isPKCS15 = TRUE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read PKCS #12 Object Information					*
*																			*
****************************************************************************/

/* Read an object's attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readObjectAttributes( INOUT_PTR STREAM *stream, 
								 INOUT_PTR PKCS12_INFO *pkcs12info )
	{
	int endPos, length, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12info, sizeof( PKCS12_INFO ) ) );

	/* Determine how big the collection of attributes is */
	status = readSet( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );

	/* Read the collection of attributes */
	LOOP_MED_WHILE( stell( stream ) < endPos )
		{
		BYTE stringBuffer[ ( CRYPT_MAX_TEXTSIZE * 2 ) + 8 ];
		int attributeType, stringLength, destIndex;
		LOOP_INDEX_ALT srcIndex;

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* Read the outer wrapper and determine the attribute type based on
		   the OID */
		readSequence( stream, NULL );
		status = readOID( stream, attributeOIDinfo, 
						  FAILSAFE_ARRAYSIZE( attributeOIDinfo, OID_INFO ), 
						  &attributeType );
		if( cryptStatusError( status ) )
			return( status );

		/* Read the wrapper around the attribute payload */
		status = readSet( stream, &length );
		if( cryptStatusError( status ) )
			return( status );

		switch( attributeType )
			{
			case PKCS12_ATTRIBUTE_NONE:
				/* It's a don't-care attribute, skip it */
				if( length > 0 )
					status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
				break;

			case PKCS12_ATTRIBUTE_LABEL:
				/* Read the label, translating it from Unicode.  We assume
				   that it's just widechar ASCII/latin-1 (which always seems
				   to be the case), which avoids OS-specific i18n 
				   headaches */
				status = readCharacterString( stream, stringBuffer, 
									CRYPT_MAX_TEXTSIZE * 2, &stringLength,
									BER_STRING_BMP );
				if( cryptStatusError( status ) )
					break;
				LOOP_LARGE_ALT( srcIndex = destIndex = 0, 
								srcIndex < stringLength, 
								( srcIndex +=2, destIndex++ ) )
					{
					ENSURES( LOOP_INVARIANT_LARGE_ALT( destIndex, 0, 
													   stringLength - 1 ) );
					ENSURES( LOOP_INVARIANT_SECONDARY( srcIndex, 0, 
													   stringLength - 1 ) );

					pkcs12info->label[ destIndex ] = \
								stringBuffer[ srcIndex + 1 ];
					}
				ENSURES( LOOP_BOUND_OK_ALT );
				pkcs12info->labelLength = destIndex;
				break;

			case PKCS12_ATTRIBUTE_ID:
				/* It's a binary-blob ID value, usually a 32-bit little-
				   endian integer, remember it in case it's needed later 
				   (this is the sole vaguely-useful ID that PKCS #12
				   provides, and can sometimes be used to match
				   certificates to their corresponding private keys) */
				status = readOctetString( stream, pkcs12info->id, 
										  &pkcs12info->idLength, 
										  1, CRYPT_MAX_HASHSIZE );
				break;

			default:
				retIntError();
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

/* Read object information.  The standard unencrypted object is always a
   certificate, the encrypted object can be a certificate as well, or a 
   private key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readObjectInfo( INOUT_PTR STREAM *stream, 
						   OUT_PTR PKCS12_OBJECT_INFO *pkcs12objectInfo,
						   INOUT_PTR ERROR_INFO *errorInfo )
	{
	long length;
	int payloadOffset DUMMY_INIT;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12objectInfo, sizeof( PKCS12_OBJECT_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( errorInfo != NULL );

	/* Clear return values */
	memset( pkcs12objectInfo, 0, sizeof( PKCS12_OBJECT_INFO ) );

	/* Read the inner portion of the redundantly-nested object types and
	   remember the payload details within it */
	status = readCMSheader( stream, certOIDinfo, 
							FAILSAFE_ARRAYSIZE( certOIDinfo, OID_INFO ), 
							NULL, &length, READCMS_FLAG_INNERHEADER | \
										   READCMS_FLAG_DEFINITELENGTH );
	if( cryptStatusOK( status ) && \
		( !isShortIntegerRangeMin( length, MIN_OBJECT_SIZE ) ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		{
		payloadOffset = stell( stream );
		ENSURES( isIntegerRangeNZ( payloadOffset ) );
		status = sSkip( stream, length, SSKIP_MAX );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid certificate payload data" ) );
		}
	pkcs12objectInfo->payloadOffset = payloadOffset;
	pkcs12objectInfo->payloadSize = length;

	return( CRYPT_OK );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN isIncorrectNestedContent( INOUT_PTR STREAM *stream, 
										 IN_LENGTH_SHORT const int contentLength )
	{
	STREAM localStream;
	void *dataPtr;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_B( isShortIntegerRangeNZ( contentLength ) );

	/* The incorrect nested content is always an OCTET STRING, so if we
	   don't find that then there's nothing further to check */
	if( peekTag( stream ) != BER_OCTETSTRING )
		{
		/* Since we're reading encrypted data, we could encounter anything 
		   at this point, including things that obviously aren't valid 
		   ASN.1.  This means that the stream error state will be set, so
		   we have to explicitly clear the error state before we continue */
		sClearError( stream );
		return( FALSE );
		}

	/* We've found what could be an OCTET STRING, check if it's a valid 
	   encoding for one and whether it fits exactly inside the content */
	status = sMemGetDataBlock( stream, &dataPtr, 8 );
	if( cryptStatusError( status ) )
		return( FALSE );
	sMemConnect( &localStream, dataPtr, 8 );
	status = readOctetStringHole( &localStream, &length, MIN_OBJECT_SIZE, 
								  DEFAULT_TAG );
	sMemDisconnect( &localStream );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( sizeofObject( length ) != contentLength )
		return( FALSE );

	return( TRUE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readEncryptedObjectInfo( INOUT_PTR STREAM *stream, 
									OUT_PTR \
										PKCS12_OBJECT_INFO *pkcs12objectInfo,
									IN_BOOL const BOOLEAN isEncryptedCert,
									INOUT_PTR ERROR_INFO *errorInfo )
	{
#ifdef USE_ERRMSGS
	const char *objectName = isEncryptedCert ? "encrypted certificate" : \
											   "encrypted private key";
#endif /* USE_ERRMSGS */
	int payloadOffset DUMMY_INIT, payloadLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12objectInfo, sizeof( PKCS12_OBJECT_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isBooleanValue( isEncryptedCert ) );
	REQUIRES( errorInfo != NULL );

	/* Clear return values */
	memset( pkcs12objectInfo, 0, sizeof( PKCS12_OBJECT_INFO ) );

	/* Read the encryption algorithm information */
	status = readProtAlgoInfo( stream, &pkcs12objectInfo->cryptAlgo,
							   &pkcs12objectInfo->keySize );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s protection algorithm", objectName ) );
		}
	
	/* Read the key-derivation parameters.  Because of the kludging on of
	   PKCS #15-style key derivation around 2020 there are two different 
	   functions used to read these, one in the standard PKCS #12 style,
	   the other in the PKCS #15 style */
	if( status == OK_SPECIAL )
		status = readKeyDerivationInfoP15( stream, pkcs12objectInfo );
	else
		status = readKeyDerivationInfoP12( stream, pkcs12objectInfo );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s protection parameters", objectName ) );
		}

	/* Read the start of the encrypted content.  This has a variety of 
	   encapsulations depending on how its hidden inside the PKCS #12 
	   object so we read it as a generic object.  readGenericHole()
	   disallows indefinite-length encodings so we know that the returned 
	   payload length will have a definite value */
	status = readGenericHole( stream, &payloadLength, MIN_OBJECT_SIZE, 
							  DEFAULT_TAG );
	if( cryptStatusOK( status ) && isEncryptedCert && \
		( payloadLength % 4 ) == 0 && \
		isIncorrectNestedContent( stream, payloadLength ) )
		{
		/* Some CAs incorrectly interpret the content encoding as being
		   [0] EXPLICIT OCTET STRING instead of [0] IMPLICIT OCTET STRING.
		   This is tricky to detect since 1/256 encrypted data blocks will
		   look, to a peekTag(), like an OCTET STRING.  To detect this we
		   first take advantage of the fact that it only occurs for 
		   encrypted certificates and that the length will be a multiple 
		   of four bytes (either a cipher block size multiple of 8 or 16
		   bytes wrapped in a four-byte tag+length header), and if those
		   conditions are met check for an encapsulated OCTET STRING.  If
		   we find one, we dig one level further down into the data to get
		   the actual content */
		DEBUG_DIAG(( "Compensating for invalid content encoding of "
					 "OCTET STRING inside [0] data" ));
		status = readOctetStringHole( stream, &payloadLength, 
									  MIN_OBJECT_SIZE, DEFAULT_TAG );
		}
	if( cryptStatusOK( status ) )
		{
		payloadOffset = stell( stream );
		ENSURES( isIntegerRangeNZ( payloadOffset ) );
		status = sSkip( stream, payloadLength, SSKIP_MAX );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s payload data", objectName ) );
		}
	pkcs12objectInfo->payloadOffset = payloadOffset;
	pkcs12objectInfo->payloadSize = payloadLength;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read PKCS #12 Keys								*
*																			*
****************************************************************************/

/* Read a single object in a keyset */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int pkcs12ReadObject( INOUT_PTR STREAM *stream, 
					  OUT_PTR PKCS12_INFO *pkcs12info, 
					  IN_BOOL const BOOLEAN isEncryptedCert,
					  INOUT_PTR ERROR_INFO *errorInfo )
	{
	PKCS12_OBJECT_INFO localPkcs12ObjectInfo, *pkcs12ObjectInfoPtr;
	STREAM objectStream;
	BOOLEAN isPrivateKey = FALSE;
	void *objectData;
	int objectLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12info, sizeof( PKCS12_INFO ) ) );
	
	REQUIRES( isBooleanValue( isEncryptedCert ) );
	REQUIRES( errorInfo != NULL );

	/* Clear return values */
	memset( pkcs12info, 0, sizeof( PKCS12_INFO ) );

	/* Read the current object's data */
	status = readRawObjectAlloc( stream, &objectData, &objectLength,
								 MIN_OBJECT_SIZE, MAX_INTLENGTH_SHORT - 1 );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't read PKCS #12 object data" ) );
		}
	ANALYSER_HINT( objectData != NULL );

	/* Read the object information from the in-memory object data.  First we 
	   have to find out what it is that we're dealing with, caused by yet 
	   more PKCS #12 braindamage in which the same object types can be 
	   encapsulated in different ways in different locations.  The nesting 
	   is:

			Data
				SEQUENCE OF
					ShroundedKeyBag | CertBag	<- Current position
			
			EncryptedData
				Data (= Certificate)			<- Current position

	   with the current level being either the ShroundedKeyBag/CertBag or
	   Data.  If we're expecting Data (denoted by the isEncryptedCert flag
	   being set, the PKCS #12 braindamage leads to counterintuitive 
	   control-flag naming) then we read it as is, if we're expecting some
	   other content-type then we have to analyse it to see what we've got */
	sMemConnect( &objectStream, objectData, objectLength );
	if( isEncryptedCert )
		{
		/* We're reading a public certificate held within CMS EncryptedData, 
		   skip the encapsulation to get to the encryption information */
		readSequence( &objectStream, NULL );
		status = readFixedOID( &objectStream, OID_CMS_DATA, 
							   sizeofOID( OID_CMS_DATA ) );
		}
	else
		{
		int isEncryptedPrivateKey;

		/* We're reading either a private key held within a ShroudedKeyBag 
		   or a certificate within a CertBag, see what we've got.  As usual
		   with PKCS #12 there are complications, in this case because 
		   certificates are stored within a redundantly nested 
		   X509Certificate object within a CertBag object, so we have to 
		   read the outer CMS header with the READCMS_FLAG_WRAPPERONLY flag 
		   set to avoid reading the start of the inner header, which is then 
		   read by the second readCMSheader() call.  Since this skips the
		   normal read of the inner header, we have to explicitly read it if
		   it's not a CertBag */
		status = readCMSheader( &objectStream, keyCertBagOIDinfo, 
								FAILSAFE_ARRAYSIZE( keyCertBagOIDinfo, \
													OID_INFO ),
								&isEncryptedPrivateKey, NULL, 
								READCMS_FLAG_WRAPPERONLY );
		if( !cryptStatusError( status ) && isEncryptedPrivateKey )
			{
			isPrivateKey = TRUE;
			status = readSequence( &objectStream, NULL );
			}
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &objectStream );
		clFree( "readObject", objectData );
		retExt( status, 
				( status, errorInfo, 
				  "Invalid PKCS #12 object header" ) );
		}

	/* Read the object data, either as an encrypted object if it's a private 
	   key or an encrypted certificate, or as plain data if it's a standard 
	   certificate */
	if( isEncryptedCert || isPrivateKey )
		{
		status = readEncryptedObjectInfo( &objectStream, 
										  &localPkcs12ObjectInfo, 
										  isEncryptedCert, errorInfo );
		}
	else
		{
		status = readObjectInfo( &objectStream, &localPkcs12ObjectInfo, 
								 errorInfo );
		}
	if( cryptStatusOK( status ) && stell( &objectStream ) < objectLength )
		{
		/* There are object attributes present, read these as well.  Note 
		   that these apply to the overall set of objects, so we read them
		   into the general information rather than the per-object 
		   information */
		status = readObjectAttributes( &objectStream, pkcs12info );
		}
	sMemDisconnect( &objectStream );
	if( cryptStatusError( status ) )
		{
		clFree( "readObject", objectData );
		retExt( status, 
				( status, errorInfo, "Invalid %s information",
				  isPrivateKey ? "private key" : "certificate" ) );
		}

	/* Remember the encoded object data */
	if( isEncryptedCert )
		pkcs12info->flags = PKCS12_FLAG_ENCCERT;
	else
		{
		if( isPrivateKey )
			pkcs12info->flags = PKCS12_FLAG_PRIVKEY;
		else
			pkcs12info->flags = PKCS12_FLAG_CERT;
		}
	pkcs12ObjectInfoPtr = isPrivateKey ? &pkcs12info->keyInfo : \
										 &pkcs12info->certInfo;
	memcpy( pkcs12ObjectInfoPtr, &localPkcs12ObjectInfo, 
			sizeof( PKCS12_OBJECT_INFO ) );
	pkcs12ObjectInfoPtr->data = objectData;
	pkcs12ObjectInfoPtr->dataSize = objectLength;
	ENSURES( boundsCheck( pkcs12ObjectInfoPtr->payloadOffset, 
						  pkcs12ObjectInfoPtr->payloadSize,
						  pkcs12ObjectInfoPtr->dataSize ) );

	return( CRYPT_OK );
	}
#endif /* USE_PKCS12 */
