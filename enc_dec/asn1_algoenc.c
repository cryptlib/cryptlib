<<<<<<< HEAD
/****************************************************************************
*																			*
*				ASN.1 Encryption Algorithm Identifier Routines				*
*						Copyright Peter Gutmann 1992-2018					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "asn1_int.h"
#else
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/asn1_int.h"
#endif /* Compiler-specific includes */

#ifdef USE_INT_ASN1

/****************************************************************************
*																			*
*								AuthEnc Routines							*
*																			*
****************************************************************************/

/* In addition to the standard AlgorithmIdentifiers there's also the RFC 
   6476 generic-secret pseudo-algorithm used for key-diversification 
   purposes:

	SEQUENCE {
		prf ::= [ 0 ] SEQUENCE {				-- Present if HMAC != SHA1
			pbkdf2			OBJECT IDENTIFIER,
			SEQUENCE {
				salt		OCTET STRING SIZE(0),
				iterationCount INTEGER (1),
				prf			AlgorithmIdentifier	-- HMAC-SHA2, etc
				}
			} DEFAULT PBKDF2,
		encAlgo				AlgorithmIdentifier,
		macAlgo				AlgorithmIdentifier	-- HMAC-SHA1, HMAC-SHA2, etc
		} 

   The KDF parameter values are salt and iteration-count are read and 
   written as blobs consisting of an OCTET STRING SIZE(0) + INTEGER(1) */

#define FIXEDPARAM_DATA			MKDATA( "\x04\x00\x02\x01\x01" )
#define FIXEDPARAM_DATA_SIZE	5

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readAuthEncParamData( INOUT_PTR STREAM *stream,
								 OUT_DATALENGTH_Z int *offset,
								 OUT_LENGTH_BOUNDED_Z( maxLength ) \
									int *length,
								 IN_TAG_ENCODED const int tag,
								 IN_LENGTH_SHORT const int maxLength )
	{
	const int paramStart = stell( stream );
	int paramLength DUMMY_INIT, tagValue, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( offset, sizeof( int ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES_S( tag >= 1 && tag < MAX_TAG );
	REQUIRES_S( isShortIntegerRangeNZ( maxLength ) );
	REQUIRES_S( isIntegerRangeNZ( paramStart ) );

	/* Clear return values */
	*offset = *length = 0;

	/* Get the start and length of the parameter data */
	status = tagValue = readTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( tagValue != tag )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	status = readUniversalData( stream );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, paramStart, 
											  &paramLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that it appears valid */
	if( paramLength < 8 || paramLength > maxLength )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	*offset = paramStart;
	*length = paramLength;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readGenericSecretParams( INOUT_PTR STREAM *stream,
									INOUT_PTR QUERY_INFO *queryInfo,
									IN_LENGTH_Z const int startOffset )
	{
	int tag, length, objectSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isShortIntegerRange( startOffset ) );

	/* The caller needs a copy of the KFD, encryption and MAC parameters to 
	   use when creating the encryption and MAC contexts, so we record the 
	   positions within the encoded parameter data */
	status = readSequence( stream, NULL );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 0 ) )
		{
		/* Read the optional KDF parameters */
		status = calculateStreamObjectLength( stream, startOffset, 
											  &objectSize );
		if( cryptStatusError( status ) )
			return( status );
		status = readAuthEncParamData( stream,
							&queryInfo->kdfParamStart, 
							&queryInfo->kdfParamLength, MAKE_CTAG( 0 ), 
							AUTHENCPARAM_MAX_SIZE - objectSize );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the encryption and MAC algorithm parameters */
	status = calculateStreamObjectLength( stream, startOffset, 
										  &objectSize );
	if( cryptStatusError( status ) )
		return( status );
	status = readAuthEncParamData( stream,
							&queryInfo->encParamStart, 
							&queryInfo->encParamLength, BER_SEQUENCE,
							AUTHENCPARAM_MAX_SIZE - objectSize );
	if( cryptStatusError( status ) )
		return( status );
	status = calculateStreamObjectLength( stream, startOffset, 
										  &objectSize );
	if( cryptStatusError( status ) )
		return( status );
	status = readAuthEncParamData( stream,
							&queryInfo->macParamStart, 
							&queryInfo->macParamLength, BER_SEQUENCE,
							AUTHENCPARAM_MAX_SIZE - objectSize );
	if( cryptStatusError( status ) )
		return( status );

	/* The encryption/MAC parameter positions are taken from the start of 
	   the encoded data, not from the start of the stream so we need to
	   adjust the position by the offset from the start */
	queryInfo->kdfParamStart -= startOffset;
	queryInfo->encParamStart -= startOffset;
	queryInfo->macParamStart -= startOffset;

	/* For AuthEnc data we need to MAC the encoded parameter data after 
	   we've processed it, so we save a copy for the caller */
	status = calculateStreamObjectLength( stream, startOffset, 
										  &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length <= 16 || length > AUTHENCPARAM_MAX_SIZE )
		return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );
	status = sseek( stream, startOffset );
	if( cryptStatusOK( status ) )
		status = sread( stream, queryInfo->authEncParamData, length );
	if( cryptStatusOK( status ) )
		queryInfo->authEncParamLength = length;
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeGenericSecretParams( INOUT_PTR STREAM *stream,
									 IN_HANDLE const CRYPT_CONTEXT iCryptContext,
									 IN_BUFFER( oidSize ) const BYTE *oid,
									 IN_LENGTH_OID const int oidSize )
	{
	MESSAGE_DATA msgData;
	BYTE kdfData[ AUTHENCPARAM_MAX_SIZE + 8 ];
	BYTE encAlgoData[ AUTHENCPARAM_MAX_SIZE + 8 ];
	BYTE macAlgoData[ AUTHENCPARAM_MAX_SIZE + 8 ];
	int kdfDataSize = 0, encAlgoDataSize, macAlgoDataSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( oid, oidSize ) && \
			oidSize == sizeofOID( oid ) );

	REQUIRES_S( isHandleRangeValid( iCryptContext ) );
	REQUIRES_S( oidSize >= MIN_OID_SIZE && oidSize <= MAX_OID_SIZE );

	/* Get the encoded parameters for the optional KDF data and encryption 
	   and MAC contexts that will be derived from the generic-secret 
	   context */
	setMessageData( &msgData, kdfData, AUTHENCPARAM_MAX_SIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KDFPARAMS );
	if( cryptStatusOK( status ) )	
		{
		/* The KDF data is optional so it may not be present */
		kdfDataSize = msgData.length;
		}
	setMessageData( &msgData, encAlgoData, AUTHENCPARAM_MAX_SIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_ENCPARAMS );
	if( cryptStatusError( status ) )
		return( status );
	encAlgoDataSize = msgData.length;
	setMessageData( &msgData, macAlgoData, AUTHENCPARAM_MAX_SIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_MACPARAMS );
	if( cryptStatusError( status ) )
		return( status );
	macAlgoDataSize = msgData.length;

	/* Write the pre-encoded AuthEnc parameter data */
	writeSequence( stream, oidSize + \
						   sizeofObject( kdfDataSize + \
										 encAlgoDataSize + \
										 macAlgoDataSize ) );
	swrite( stream, oid, oidSize );
	writeSequence( stream, kdfDataSize + encAlgoDataSize + \
						   macAlgoDataSize );
	if( kdfDataSize > 0 )
		swrite( stream, kdfData, kdfDataSize );
	swrite( stream, encAlgoData, encAlgoDataSize );
	return( swrite( stream, macAlgoData, macAlgoDataSize ) );
	}

/* Set generic secret parameters for a context.  This encodes the 
   information needed to recreate the encryption and MAC contexts derived
   from the generic secret and stores the encoded information with the
   generic-secret context */

CHECK_RETVAL \
static int setKDFParams( IN_HANDLE const CRYPT_CONTEXT iGenericSecret,
						 IN_ALGO const CRYPT_ALGO_TYPE kdfAlgo )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE kdfParamData[ CRYPT_MAX_TEXTSIZE + 8 ];
	int kdfAlgoIDsize, kdfParamDataSize DUMMY_INIT, status;

	REQUIRES( isHandleRangeValid( iGenericSecret ) );
	REQUIRES( isMacAlgo( kdfAlgo ) && kdfAlgo != CRYPT_ALGO_HMAC_SHA1 );

	/* Get the KDF algoID size */
	status = kdfAlgoIDsize = sizeofAlgoID( kdfAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* We're using a non-default MAC algorithm, send the custom KDF 
	   parameters to the context:

		KdfParams ::= [ 0 ] SEQUENCE {			-- 3.4.3 - 3.4.4.1
			salt			OCTET STRING SIZE(0),
			iterationCount	INTEGER (1),
			prf				AlgorithmIdentifier
			} 

		KdfParams ::= [ 0 ] SEQUENCE {			-- Present if HMAC != SHA1
			pbkdf2			OBJECT IDENTIFIER,
			SEQUENCE {
				salt		OCTET STRING SIZE(0),
				iterationCount INTEGER (1),
				prf			AlgorithmIdentifier	-- HMAC-SHA2, etc
				}
			} */
	sMemOpen( &stream, kdfParamData, CRYPT_MAX_TEXTSIZE );
#if 0	/* 28/4/19 Erroneously written in 3.4.3 - 3.4.4.1 for CMS envelopes */
	writeConstructed( &stream, FIXEDPARAM_DATA_SIZE + kdfAlgoIDsize, 0 );
	swrite( &stream, FIXEDPARAM_DATA, FIXEDPARAM_DATA_SIZE );
	status = writeAlgoID( &stream, kdfAlgo );
	if( cryptStatusOK( status ) )
		kdfParamDataSize = stell( &stream );
	sMemDisconnect( &stream );
#else
	writeConstructed( &stream, sizeofOID( OID_PBKDF2 ) + \
							   sizeofShortObject( FIXEDPARAM_DATA_SIZE + \
												  kdfAlgoIDsize ), 0 );
	writeOID( &stream, OID_PBKDF2 );
	writeSequence( &stream, FIXEDPARAM_DATA_SIZE + kdfAlgoIDsize );
	swrite( &stream, FIXEDPARAM_DATA, FIXEDPARAM_DATA_SIZE );
	status = writeAlgoID( &stream, kdfAlgo, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		kdfParamDataSize = stell( &stream );
	sMemDisconnect( &stream );
#endif /* 0 */
	if( cryptStatusError( status ) )
		return( status );

	/* Send the encoded parameter information to the generic-secret 
	   context */
	setMessageData( &msgData, kdfParamData, kdfParamDataSize );
	return( krnlSendMessage( iGenericSecret, IMESSAGE_SETATTRIBUTE_S, 
							 &msgData, CRYPT_IATTRIBUTE_KDFPARAMS ) );
	}

CHECK_RETVAL \
int setGenericSecretParams( IN_HANDLE const CRYPT_CONTEXT iGenericSecret,
							IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							IN_HANDLE const CRYPT_CONTEXT iMacContext,
							IN_ALGO const CRYPT_ALGO_TYPE kdfAlgo )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	ALGOID_PARAMS algoIDparams;
	BYTE algorithmParamData[ CRYPT_MAX_TEXTSIZE + 8 ];
	int hashAlgorithm, hashSize DUMMY_INIT;
	int algorithmParamDataSize DUMMY_INIT, status;

	REQUIRES( isHandleRangeValid( iGenericSecret ) );
	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isHandleRangeValid( iMacContext ) );
	REQUIRES( isMacAlgo( kdfAlgo ) );

	/* Set the KDF parameters if required */
	if( kdfAlgo != CRYPT_ALGO_HMAC_SHA1 )
		{
		status = setKDFParams( iGenericSecret, kdfAlgo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Set the encryption algorithm parameter data from the encryption 
	   context */
	sMemOpen( &stream, algorithmParamData, CRYPT_MAX_TEXTSIZE );
	status = writeCryptContextAlgoID( &stream, iCryptContext );
	if( cryptStatusOK( status ) )
		algorithmParamDataSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, algorithmParamData, 
						algorithmParamDataSize );
		status = krnlSendMessage( iGenericSecret, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_ENCPARAMS );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Set the MAC algorithm parameter data from the MAC context.  The 
	   extended hash algorithms can have various different hash sizes, to 
	   get the exact variant that's being used we have to query the block 
	   size */
	sMemOpen( &stream, algorithmParamData, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( iMacContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iMacContext, IMESSAGE_GETATTRIBUTE,
								  &hashSize, CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		initAlgoIDparamsHash( &algoIDparams, hashAlgorithm, hashSize );
		status = writeContextAlgoIDex( &stream, iMacContext, &algoIDparams );
		}
	if( cryptStatusOK( status ) )
		algorithmParamDataSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, algorithmParamData, 
						algorithmParamDataSize );
		status =  krnlSendMessage( iGenericSecret, IMESSAGE_SETATTRIBUTE_S, 
								   &msgData, CRYPT_IATTRIBUTE_MACPARAMS );
		}
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}

/* Get generic secret parameters from a context.  This recreates the 
   encryption and MAC contexts from the encoded parameter information stored
   with the generic-secret context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) \
int getGenericSecretParams( IN_HANDLE const CRYPT_CONTEXT iGenericContext,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iMacContext,
							const QUERY_INFO *queryInfo )
	{
	CRYPT_CONTEXT iAuthEncCryptContext, iAuthEncMacContext;
	CRYPT_ALGO_TYPE kdfAlgo DUMMY_INIT;
	MECHANISM_KDF_INFO mechanismInfo;
	STREAM stream;
	int kdfParam DUMMY_INIT, status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( iMacContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isReadPtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isHandleRangeValid( iGenericContext ) );

	/* Clear return values */
	*iCryptContext = *iMacContext = CRYPT_ERROR;

	/* Recover the KDF information if it's present.  Early implementations
	   erroneously omitted the PBKDF2 AlgorithmIdentifier for the CMS code 
	   so we allow for versions with or without this value.  Since the 
	   entries are skipped anyway it just means that there's two additional 
	   values to skip:

		KdfParams ::= [ 0 ] SEQUENCE {			-- 3.4.3 - 3.4.4.1
			salt			OCTET STRING SIZE(0),
			iterationCount	INTEGER (1),
			prf				AlgorithmIdentifier
			} 

		KdfParams ::= [ 0 ] SEQUENCE {			-- Present if HMAC != SHA1
			pbkdf2			OBJECT IDENTIFIER,
			SEQUENCE {
				salt		OCTET STRING SIZE(0),
				iterationCount INTEGER (1),
				prf			AlgorithmIdentifier	-- HMAC-SHA2, etc
				}
			} */
	if( queryInfo->kdfParamLength > 0 )
		{
		ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;
		BYTE fixedParamBuffer[ FIXEDPARAM_DATA_SIZE + 8 ];

		REQUIRES( boundsCheck( queryInfo->kdfParamStart,
							   queryInfo->kdfParamLength,
							   queryInfo->authEncParamLength ) );
		sMemConnect( &stream, 
					 queryInfo->authEncParamData + queryInfo->kdfParamStart,
					 queryInfo->kdfParamLength  );
		readConstructed( &stream, NULL, 0 );
		if( peekTag( &stream ) == BER_OBJECT_IDENTIFIER )
			{
			readUniversal( &stream );		/* pbkdf2 OID */
			readSequence( &stream, NULL );
			}
		status = sread( &stream, fixedParamBuffer, FIXEDPARAM_DATA_SIZE );
		if( cryptStatusOK( status ) &&		/* OCTET STRING + INTEGER */
			memcmp( fixedParamBuffer, FIXEDPARAM_DATA, \
					FIXEDPARAM_DATA_SIZE ) )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status ) )
			{								/* HMAC algorithm */
			status = readAlgoIDex( &stream, &kdfAlgo, &algoIDparams,  
								   ALGOID_CLASS_HASH );
			}
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		kdfParam = algoIDparams.hashParam;
		}
	else
		{
		/* The PBKDF2 default KDF is HMAC-SHA1 */
		kdfAlgo = CRYPT_ALGO_HMAC_SHA1;
		kdfParam = 20;
		}

	/* Recreate the encryption and MAC contexts used for the authenticated 
	   encryption from the algorithm parameter data stored with the generic-
	   secret context */
	REQUIRES( boundsCheck( queryInfo->encParamStart, queryInfo->encParamLength,
						   queryInfo->authEncParamLength ) );
	sMemConnect( &stream, queryInfo->authEncParamData + queryInfo->encParamStart, 
				 queryInfo->encParamLength );
	status = readContextAlgoID( &stream, &iAuthEncCryptContext, NULL, 
								DEFAULT_TAG, ALGOID_CLASS_CRYPT );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( boundsCheck( queryInfo->macParamStart, queryInfo->macParamLength,
						   queryInfo->authEncParamLength ) );
	sMemConnect( &stream, queryInfo->authEncParamData + queryInfo->macParamStart, 
				 queryInfo->macParamLength );
	status = readContextAlgoID( &stream, &iAuthEncMacContext, NULL, 
								DEFAULT_TAG, ALGOID_CLASS_HASH );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iAuthEncCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Derive the encryption and MAC keys from the generic-secret key */
	setMechanismKDFInfo( &mechanismInfo, iAuthEncCryptContext, 
						 iGenericContext, kdfAlgo, "encryption", 10 );
	mechanismInfo.hashParam = kdfParam;
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_KDF,
							  &mechanismInfo, MECHANISM_DERIVE_PBKDF2 );
	if( cryptStatusOK( status ) )
		{
		setMechanismKDFInfo( &mechanismInfo, iAuthEncMacContext, 
							 iGenericContext, kdfAlgo, "authentication", 14 );
		mechanismInfo.hashParam = kdfParam;
		status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_KDF,
								  &mechanismInfo, MECHANISM_DERIVE_PBKDF2 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iAuthEncCryptContext, IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( iAuthEncMacContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* MAC the AuthEnc parameter data alongside the payload data to prevent 
	   an attacker from manipulating the algorithm parameters to cause 
	   corruption that won't be detected by the MAC on the payload data */
	status = krnlSendMessage( iAuthEncMacContext, IMESSAGE_CTX_HASH,
							  ( MESSAGE_CAST ) queryInfo->authEncParamData,
							  queryInfo->authEncParamLength );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iAuthEncCryptContext, IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( iAuthEncMacContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	*iCryptContext = iAuthEncCryptContext;
	*iMacContext = iAuthEncMacContext;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					EncryptionAlgorithmIdentifier Routines					*
*																			*
****************************************************************************/

/* EncryptionAlgorithmIdentifier parameters:

	aesXcbc: AES FIPS

		iv				OCTET STRING SIZE (16)

	aesXcfb: AES FIPS

		SEQUENCE {
			iv			OCTET STRING SIZE (16),
			noOfBits	INTEGER (128)
			}

	cast5cbc: RFC 2144
		SEQUENCE {
			iv			OCTET STRING DEFAULT 0,
			keyLen		INTEGER (128)
			}

	rc2CBC: RFC 2311
		SEQUENCE {
			rc2Param	INTEGER (58),	-- 128 bit key
			iv			OCTET STRING SIZE (8)
			}

	rc4: NULL

   Because of the somewhat haphazard nature of encryption
   AlgorithmIdentifier definitions we can only handle the following
   algorithm/mode combinations:

	AES ECB, CBC, CFB
	CAST128 CBC
	DES ECB, CBC, CFB
	3DES ECB, CBC, CFB
	RC2 ECB, CBC
	RC4 */

/* Magic value to denote 128-bit RC2 keys */

#define RC2_KEYSIZE_MAGIC		58

/* Get the size of an EncryptionAlgorithmIdentifier record */

CHECK_RETVAL_LENGTH \
int sizeofCryptContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	STREAM nullStream;
	int status;

	REQUIRES( isHandleRangeValid( iCryptContext ) );

	/* Determine how large the algoID and associated parameters are.  
	   Because this is a rather complex operation the easiest way to do it 
	   is to write to a null stream and get its size */
	sMemNullOpen( &nullStream );
	status = writeCryptContextAlgoID( &nullStream, iCryptContext );
	if( cryptStatusOK( status ) )
		status = stell( &nullStream );
	sMemClose( &nullStream );

	return( status );
	}

 /* Read an EncryptionAlgorithmIdentifier/DigestAlgorithmIdentifier */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCryptAlgoParams( INOUT_PTR STREAM *stream, 
						 INOUT_PTR QUERY_INFO *queryInfo,
						 IN_LENGTH_Z const int startOffset )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES_S( isShortIntegerRange( startOffset ) );

	/* Read the algorithm-specific parameters.  In theory we should do
	   something with some of the values like the IV size parameter, but
	   since the standard never explains what to do if it's something other
	   than the algorithm block size (Left pad? Right pad? Sign-extend?
	   Repeat the data?) it's safer not to do anything ("Never check for an
	   error that you don't know how to handle").  In any case there are no
	   known cases of these strange values ever being used, probably because
	   all existing software would break, so we make sure that they're 
	   present but otherwise ignore them */
	switch( queryInfo->cryptAlgo )
		{
#ifdef USE_3DES
		case CRYPT_ALGO_3DES:
#endif /* USE_3DES */
		case CRYPT_ALGO_AES:
#ifdef USE_DES
		case CRYPT_ALGO_DES:
#endif /* USE_DES */
			{
			const int minIVsize = \
						( queryInfo->cryptAlgo == CRYPT_ALGO_AES ) ? \
						  16 : MIN_IVSIZE;

			if( queryInfo->cryptMode == CRYPT_MODE_ECB )
				{
				/* The NULL parameter has already been read in
				   readAlgoIDparams() */
				return( CRYPT_OK );
				}
			if( queryInfo->cryptMode == CRYPT_MODE_CBC )
				{
				return( readOctetString( stream, queryInfo->iv,
										 &queryInfo->ivLength, minIVsize, 
										 CRYPT_MAX_IVSIZE ) );
				}
			readSequence( stream, NULL );
			readOctetString( stream, queryInfo->iv, &queryInfo->ivLength,
							 minIVsize, CRYPT_MAX_IVSIZE );
			return( readShortInteger( stream, NULL ) );
			}

#ifdef USE_CAST
		case CRYPT_ALGO_CAST:
			readSequence( stream, NULL );
			readOctetString( stream, queryInfo->iv, &queryInfo->ivLength,
							 MIN_IVSIZE, CRYPT_MAX_IVSIZE );
			return( readShortInteger( stream, NULL ) );
#endif /* USE_CAST */

#ifdef USE_RC2
		case CRYPT_ALGO_RC2:
			/* In theory we should check that the parameter value ==
			   RC2_KEYSIZE_MAGIC (corresponding to a 128-bit key) but in
			   practice this doesn't really matter, we just use whatever we
			   find inside the PKCS #1 padding */
			readSequence( stream, NULL );
			if( queryInfo->cryptMode != CRYPT_MODE_CBC )
				return( readShortInteger( stream, NULL ) );
			readShortInteger( stream, NULL );
			return( readOctetString( stream, queryInfo->iv,
									 &queryInfo->ivLength,
									 MIN_IVSIZE, CRYPT_MAX_IVSIZE ) );
#endif /* USE_RC2 */

#ifdef USE_RC4
		case CRYPT_ALGO_RC4:
			/* The NULL parameter has already been read in
			   readAlgoIDparams() */
			return( CRYPT_OK );
#endif /* USE_RC4 */

		case CRYPT_IALGO_GENERIC_SECRET:
			return( readGenericSecretParams( stream, queryInfo, 
											 startOffset ) );
		}

	retIntError();
	}

/* Write an EncryptionAlgorithmIdentifier record */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCryptContextAlgoID( INOUT_PTR STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	ALGOID_PARAMS algoIDparams;
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];
	const BYTE *oid;
	int algorithm, mode = CRYPT_MODE_NONE;	/* enum vs.int */
	int keySize = 0, oidSize, ivSize = 0, sizeofIV = 0, paramSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isHandleRangeValid( iCryptContext ) );

	/* Extract the information that we need to write the
	   AlgorithmIdentifier */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && !isSpecialAlgo( algorithm ) )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &mode, CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) && !isStreamCipher( algorithm ) && \
			needsIV( mode ) )
			{
			MESSAGE_DATA msgData;

			setMessageData( &msgData, iv, CRYPT_MAX_IVSIZE );
			status = krnlSendMessage( iCryptContext, 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_CTXINFO_IV );
			if( cryptStatusOK( status ) )
				{
				ivSize = msgData.length;
				sizeofIV = sizeofShortObject( ivSize );
				}
			}
		}
	if( cryptStatusOK( status ) && \
		( isParameterisedConvAlgo( algorithm ) || \
		  isSpecialAlgo( algorithm ) ) )
		{
		/* Some algorithms are parameterised so we have to extract 
		   additional information to deal with them */
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "Couldn't extract information needed to write "
					 "AlgoID" ));
		assert( DEBUG_WARN );
		return( status );
		}

	ENSURES_S( isConvAlgo( algorithm ) || isSpecialAlgo( algorithm ) );

	/* Get the OID for this algorithm */
	initAlgoIDparamsCrypt( &algoIDparams, mode, keySize );
	oid = algorithmToOID( algorithm, &algoIDparams, ALGOTOOID_CHECK_VALID );
	if( oid == NULL )
		{
		/* Some algorithm+mode combinations can't be encoded using the
		   available PKCS #7 / CMS OIDs, the best that we can do in this 
		   case is alert the user in debug mode and return a 
		   CRYPT_ERROR_NOTAVAIL */
		DEBUG_DIAG(( "Tried to write non-PKCS #7 / CMS algorithm ID" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	oidSize = sizeofOID( oid );
	ENSURES_S( oidSize >= MIN_OID_SIZE && oidSize <= MAX_OID_SIZE );

	/* Write the algorithm-specific parameters */
	switch( algorithm )
		{
#ifdef USE_3DES
		case CRYPT_ALGO_3DES:
#endif /* USE_3DES */
		case CRYPT_ALGO_AES:
#ifdef USE_DES
		case CRYPT_ALGO_DES:
#endif /* USE_DES */
			{
			const int noBits = ( algorithm == CRYPT_ALGO_AES ) ? 128 : 64;

			ANALYSER_HINT( ivSize > 0 && ivSize < CRYPT_MAX_IVSIZE );

			paramSize = \
				( mode == CRYPT_MODE_ECB ) ? sizeofNull() : \
				( mode == CRYPT_MODE_CBC ) ? sizeofIV : \
				  sizeofShortObject( sizeofIV + sizeofShortInteger( noBits ) );
			writeSequence( stream, oidSize + paramSize );
			swrite( stream, oid, oidSize );
			if( mode == CRYPT_MODE_ECB )
				return( writeNull( stream, DEFAULT_TAG ) );
			if( mode == CRYPT_MODE_CBC )
				return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
			writeSequence( stream, sizeofIV + sizeofShortInteger( noBits ) );
			writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
			return( writeShortInteger( stream, noBits, DEFAULT_TAG ) );
			}

#ifdef USE_CAST
		case CRYPT_ALGO_CAST:
			REQUIRES( ivSize == 8 );

			paramSize = sizeofIV + sizeofShortInteger( 128 );
			writeSequence( stream, oidSize + \
								   sizeofShortObject( paramSize ) );
			swrite( stream, oid, oidSize );
			writeSequence( stream, paramSize );
			writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
			return( writeShortInteger( stream, 128, DEFAULT_TAG ) );
#endif /* USE_CAST */

#ifdef USE_RC2
		case CRYPT_ALGO_RC2:
			paramSize = ( ( mode == CRYPT_MODE_ECB ) ? 0 : sizeofIV ) + \
						sizeofShortInteger( RC2_KEYSIZE_MAGIC );
			writeSequence( stream, oidSize + \
								   sizeofShortObject( paramSize ) );
			swrite( stream, oid, oidSize );
			writeSequence( stream, paramSize );
			if( mode != CRYPT_MODE_CBC )
				{
				return( writeShortInteger( stream, RC2_KEYSIZE_MAGIC,
										   DEFAULT_TAG ) );
				}
			writeShortInteger( stream, RC2_KEYSIZE_MAGIC, DEFAULT_TAG );
			return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
#endif /* USE_RC2 */

#ifdef USE_RC4
		case CRYPT_ALGO_RC4:
			writeSequence( stream, oidSize + sizeofNull() );
			swrite( stream, oid, oidSize );
			return( writeNull( stream, DEFAULT_TAG ) );
#endif /* USE_RC4 */

		case CRYPT_IALGO_GENERIC_SECRET:
			return( writeGenericSecretParams( stream, iCryptContext, 
											  oid, oidSize ) );
		}

	retIntError();
	}
#endif /* USE_INT_ASN1 */
=======
/****************************************************************************
*																			*
*				ASN.1 Encryption Algorithm Identifier Routines				*
*						Copyright Peter Gutmann 1992-2018					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "asn1_int.h"
#else
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/asn1_int.h"
#endif /* Compiler-specific includes */

#ifdef USE_INT_ASN1

/****************************************************************************
*																			*
*								AuthEnc Routines							*
*																			*
****************************************************************************/

/* In addition to the standard AlgorithmIdentifiers there's also the RFC 
   6476 generic-secret pseudo-algorithm used for key-diversification 
   purposes:

	SEQUENCE {
		prf ::= [ 0 ] SEQUENCE {				-- Present if HMAC != SHA1
			pbkdf2			OBJECT IDENTIFIER,
			SEQUENCE {
				salt		OCTET STRING SIZE(0),
				iterationCount INTEGER (1),
				prf			AlgorithmIdentifier	-- HMAC-SHA2, etc
				}
			} DEFAULT PBKDF2,
		encAlgo				AlgorithmIdentifier,
		macAlgo				AlgorithmIdentifier	-- HMAC-SHA1, HMAC-SHA2, etc
		} 

   The KDF parameter values are salt and iteration-count are read and 
   written as blobs consisting of an OCTET STRING SIZE(0) + INTEGER(1) */

#define FIXEDPARAM_DATA			MKDATA( "\x04\x00\x02\x01\x01" )
#define FIXEDPARAM_DATA_SIZE	5

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readAuthEncParamData( INOUT_PTR STREAM *stream,
								 OUT_DATALENGTH_Z int *offset,
								 OUT_LENGTH_BOUNDED_Z( maxLength ) \
									int *length,
								 IN_TAG_ENCODED const int tag,
								 IN_LENGTH_SHORT const int maxLength )
	{
	const int paramStart = stell( stream );
	int paramLength DUMMY_INIT, tagValue, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( offset, sizeof( int ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES_S( tag >= 1 && tag < MAX_TAG );
	REQUIRES_S( isShortIntegerRangeNZ( maxLength ) );
	REQUIRES_S( isIntegerRangeNZ( paramStart ) );

	/* Clear return values */
	*offset = *length = 0;

	/* Get the start and length of the parameter data */
	status = tagValue = readTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( tagValue != tag )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	status = readUniversalData( stream );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, paramStart, 
											  &paramLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that it appears valid */
	if( paramLength < 8 || paramLength > maxLength )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	*offset = paramStart;
	*length = paramLength;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readGenericSecretParams( INOUT_PTR STREAM *stream,
									INOUT_PTR QUERY_INFO *queryInfo,
									IN_LENGTH_Z const int startOffset )
	{
	int tag, length, objectSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isShortIntegerRange( startOffset ) );

	/* The caller needs a copy of the KFD, encryption and MAC parameters to 
	   use when creating the encryption and MAC contexts, so we record the 
	   positions within the encoded parameter data */
	status = readSequence( stream, NULL );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 0 ) )
		{
		/* Read the optional KDF parameters */
		status = calculateStreamObjectLength( stream, startOffset, 
											  &objectSize );
		if( cryptStatusError( status ) )
			return( status );
		status = readAuthEncParamData( stream,
							&queryInfo->kdfParamStart, 
							&queryInfo->kdfParamLength, MAKE_CTAG( 0 ), 
							AUTHENCPARAM_MAX_SIZE - objectSize );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the encryption and MAC algorithm parameters */
	status = calculateStreamObjectLength( stream, startOffset, 
										  &objectSize );
	if( cryptStatusError( status ) )
		return( status );
	status = readAuthEncParamData( stream,
							&queryInfo->encParamStart, 
							&queryInfo->encParamLength, BER_SEQUENCE,
							AUTHENCPARAM_MAX_SIZE - objectSize );
	if( cryptStatusError( status ) )
		return( status );
	status = calculateStreamObjectLength( stream, startOffset, 
										  &objectSize );
	if( cryptStatusError( status ) )
		return( status );
	status = readAuthEncParamData( stream,
							&queryInfo->macParamStart, 
							&queryInfo->macParamLength, BER_SEQUENCE,
							AUTHENCPARAM_MAX_SIZE - objectSize );
	if( cryptStatusError( status ) )
		return( status );

	/* The encryption/MAC parameter positions are taken from the start of 
	   the encoded data, not from the start of the stream so we need to
	   adjust the position by the offset from the start */
	queryInfo->kdfParamStart -= startOffset;
	queryInfo->encParamStart -= startOffset;
	queryInfo->macParamStart -= startOffset;

	/* For AuthEnc data we need to MAC the encoded parameter data after 
	   we've processed it, so we save a copy for the caller */
	status = calculateStreamObjectLength( stream, startOffset, 
										  &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length <= 16 || length > AUTHENCPARAM_MAX_SIZE )
		return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );
	status = sseek( stream, startOffset );
	if( cryptStatusOK( status ) )
		status = sread( stream, queryInfo->authEncParamData, length );
	if( cryptStatusOK( status ) )
		queryInfo->authEncParamLength = length;
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeGenericSecretParams( INOUT_PTR STREAM *stream,
									 IN_HANDLE const CRYPT_CONTEXT iCryptContext,
									 IN_BUFFER( oidSize ) const BYTE *oid,
									 IN_LENGTH_OID const int oidSize )
	{
	MESSAGE_DATA msgData;
	BYTE kdfData[ AUTHENCPARAM_MAX_SIZE + 8 ];
	BYTE encAlgoData[ AUTHENCPARAM_MAX_SIZE + 8 ];
	BYTE macAlgoData[ AUTHENCPARAM_MAX_SIZE + 8 ];
	int kdfDataSize = 0, encAlgoDataSize, macAlgoDataSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( oid, oidSize ) && \
			oidSize == sizeofOID( oid ) );

	REQUIRES_S( isHandleRangeValid( iCryptContext ) );
	REQUIRES_S( oidSize >= MIN_OID_SIZE && oidSize <= MAX_OID_SIZE );

	/* Get the encoded parameters for the optional KDF data and encryption 
	   and MAC contexts that will be derived from the generic-secret 
	   context */
	setMessageData( &msgData, kdfData, AUTHENCPARAM_MAX_SIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KDFPARAMS );
	if( cryptStatusOK( status ) )	
		{
		/* The KDF data is optional so it may not be present */
		kdfDataSize = msgData.length;
		}
	setMessageData( &msgData, encAlgoData, AUTHENCPARAM_MAX_SIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_ENCPARAMS );
	if( cryptStatusError( status ) )
		return( status );
	encAlgoDataSize = msgData.length;
	setMessageData( &msgData, macAlgoData, AUTHENCPARAM_MAX_SIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_MACPARAMS );
	if( cryptStatusError( status ) )
		return( status );
	macAlgoDataSize = msgData.length;

	/* Write the pre-encoded AuthEnc parameter data */
	writeSequence( stream, oidSize + \
						   sizeofObject( kdfDataSize + \
										 encAlgoDataSize + \
										 macAlgoDataSize ) );
	swrite( stream, oid, oidSize );
	writeSequence( stream, kdfDataSize + encAlgoDataSize + \
						   macAlgoDataSize );
	if( kdfDataSize > 0 )
		swrite( stream, kdfData, kdfDataSize );
	swrite( stream, encAlgoData, encAlgoDataSize );
	return( swrite( stream, macAlgoData, macAlgoDataSize ) );
	}

/* Set generic secret parameters for a context.  This encodes the 
   information needed to recreate the encryption and MAC contexts derived
   from the generic secret and stores the encoded information with the
   generic-secret context */

CHECK_RETVAL \
static int setKDFParams( IN_HANDLE const CRYPT_CONTEXT iGenericSecret,
						 IN_ALGO const CRYPT_ALGO_TYPE kdfAlgo )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE kdfParamData[ CRYPT_MAX_TEXTSIZE + 8 ];
	int kdfAlgoIDsize, kdfParamDataSize DUMMY_INIT, status;

	REQUIRES( isHandleRangeValid( iGenericSecret ) );
	REQUIRES( isMacAlgo( kdfAlgo ) && kdfAlgo != CRYPT_ALGO_HMAC_SHA1 );

	/* Get the KDF algoID size */
	status = kdfAlgoIDsize = sizeofAlgoID( kdfAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* We're using a non-default MAC algorithm, send the custom KDF 
	   parameters to the context:

		KdfParams ::= [ 0 ] SEQUENCE {			-- 3.4.3 - 3.4.4.1
			salt			OCTET STRING SIZE(0),
			iterationCount	INTEGER (1),
			prf				AlgorithmIdentifier
			} 

		KdfParams ::= [ 0 ] SEQUENCE {			-- Present if HMAC != SHA1
			pbkdf2			OBJECT IDENTIFIER,
			SEQUENCE {
				salt		OCTET STRING SIZE(0),
				iterationCount INTEGER (1),
				prf			AlgorithmIdentifier	-- HMAC-SHA2, etc
				}
			} */
	sMemOpen( &stream, kdfParamData, CRYPT_MAX_TEXTSIZE );
#if 0	/* 28/4/19 Erroneously written in 3.4.3 - 3.4.4.1 for CMS envelopes */
	writeConstructed( &stream, FIXEDPARAM_DATA_SIZE + kdfAlgoIDsize, 0 );
	swrite( &stream, FIXEDPARAM_DATA, FIXEDPARAM_DATA_SIZE );
	status = writeAlgoID( &stream, kdfAlgo );
	if( cryptStatusOK( status ) )
		kdfParamDataSize = stell( &stream );
	sMemDisconnect( &stream );
#else
	writeConstructed( &stream, sizeofOID( OID_PBKDF2 ) + \
							   sizeofShortObject( FIXEDPARAM_DATA_SIZE + \
												  kdfAlgoIDsize ), 0 );
	writeOID( &stream, OID_PBKDF2 );
	writeSequence( &stream, FIXEDPARAM_DATA_SIZE + kdfAlgoIDsize );
	swrite( &stream, FIXEDPARAM_DATA, FIXEDPARAM_DATA_SIZE );
	status = writeAlgoID( &stream, kdfAlgo, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		kdfParamDataSize = stell( &stream );
	sMemDisconnect( &stream );
#endif /* 0 */
	if( cryptStatusError( status ) )
		return( status );

	/* Send the encoded parameter information to the generic-secret 
	   context */
	setMessageData( &msgData, kdfParamData, kdfParamDataSize );
	return( krnlSendMessage( iGenericSecret, IMESSAGE_SETATTRIBUTE_S, 
							 &msgData, CRYPT_IATTRIBUTE_KDFPARAMS ) );
	}

CHECK_RETVAL \
int setGenericSecretParams( IN_HANDLE const CRYPT_CONTEXT iGenericSecret,
							IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							IN_HANDLE const CRYPT_CONTEXT iMacContext,
							IN_ALGO const CRYPT_ALGO_TYPE kdfAlgo )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	ALGOID_PARAMS algoIDparams;
	BYTE algorithmParamData[ CRYPT_MAX_TEXTSIZE + 8 ];
	int hashAlgorithm, hashSize DUMMY_INIT;
	int algorithmParamDataSize DUMMY_INIT, status;

	REQUIRES( isHandleRangeValid( iGenericSecret ) );
	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isHandleRangeValid( iMacContext ) );
	REQUIRES( isMacAlgo( kdfAlgo ) );

	/* Set the KDF parameters if required */
	if( kdfAlgo != CRYPT_ALGO_HMAC_SHA1 )
		{
		status = setKDFParams( iGenericSecret, kdfAlgo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Set the encryption algorithm parameter data from the encryption 
	   context */
	sMemOpen( &stream, algorithmParamData, CRYPT_MAX_TEXTSIZE );
	status = writeCryptContextAlgoID( &stream, iCryptContext );
	if( cryptStatusOK( status ) )
		algorithmParamDataSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, algorithmParamData, 
						algorithmParamDataSize );
		status = krnlSendMessage( iGenericSecret, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_ENCPARAMS );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Set the MAC algorithm parameter data from the MAC context.  The 
	   extended hash algorithms can have various different hash sizes, to 
	   get the exact variant that's being used we have to query the block 
	   size */
	sMemOpen( &stream, algorithmParamData, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( iMacContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iMacContext, IMESSAGE_GETATTRIBUTE,
								  &hashSize, CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		initAlgoIDparamsHash( &algoIDparams, hashAlgorithm, hashSize );
		status = writeContextAlgoIDex( &stream, iMacContext, &algoIDparams );
		}
	if( cryptStatusOK( status ) )
		algorithmParamDataSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, algorithmParamData, 
						algorithmParamDataSize );
		status =  krnlSendMessage( iGenericSecret, IMESSAGE_SETATTRIBUTE_S, 
								   &msgData, CRYPT_IATTRIBUTE_MACPARAMS );
		}
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}

/* Get generic secret parameters from a context.  This recreates the 
   encryption and MAC contexts from the encoded parameter information stored
   with the generic-secret context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) \
int getGenericSecretParams( IN_HANDLE const CRYPT_CONTEXT iGenericContext,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iMacContext,
							const QUERY_INFO *queryInfo )
	{
	CRYPT_CONTEXT iAuthEncCryptContext, iAuthEncMacContext;
	CRYPT_ALGO_TYPE kdfAlgo DUMMY_INIT;
	MECHANISM_KDF_INFO mechanismInfo;
	STREAM stream;
	int kdfParam DUMMY_INIT, status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( iMacContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isReadPtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isHandleRangeValid( iGenericContext ) );

	/* Clear return values */
	*iCryptContext = *iMacContext = CRYPT_ERROR;

	/* Recover the KDF information if it's present.  Early implementations
	   erroneously omitted the PBKDF2 AlgorithmIdentifier for the CMS code 
	   so we allow for versions with or without this value.  Since the 
	   entries are skipped anyway it just means that there's two additional 
	   values to skip:

		KdfParams ::= [ 0 ] SEQUENCE {			-- 3.4.3 - 3.4.4.1
			salt			OCTET STRING SIZE(0),
			iterationCount	INTEGER (1),
			prf				AlgorithmIdentifier
			} 

		KdfParams ::= [ 0 ] SEQUENCE {			-- Present if HMAC != SHA1
			pbkdf2			OBJECT IDENTIFIER,
			SEQUENCE {
				salt		OCTET STRING SIZE(0),
				iterationCount INTEGER (1),
				prf			AlgorithmIdentifier	-- HMAC-SHA2, etc
				}
			} */
	if( queryInfo->kdfParamLength > 0 )
		{
		ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;
		BYTE fixedParamBuffer[ FIXEDPARAM_DATA_SIZE + 8 ];

		REQUIRES( boundsCheck( queryInfo->kdfParamStart,
							   queryInfo->kdfParamLength,
							   queryInfo->authEncParamLength ) );
		sMemConnect( &stream, 
					 queryInfo->authEncParamData + queryInfo->kdfParamStart,
					 queryInfo->kdfParamLength  );
		readConstructed( &stream, NULL, 0 );
		if( peekTag( &stream ) == BER_OBJECT_IDENTIFIER )
			{
			readUniversal( &stream );		/* pbkdf2 OID */
			readSequence( &stream, NULL );
			}
		status = sread( &stream, fixedParamBuffer, FIXEDPARAM_DATA_SIZE );
		if( cryptStatusOK( status ) &&		/* OCTET STRING + INTEGER */
			memcmp( fixedParamBuffer, FIXEDPARAM_DATA, \
					FIXEDPARAM_DATA_SIZE ) )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status ) )
			{								/* HMAC algorithm */
			status = readAlgoIDex( &stream, &kdfAlgo, &algoIDparams,  
								   ALGOID_CLASS_HASH );
			}
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		kdfParam = algoIDparams.hashParam;
		}
	else
		{
		/* The PBKDF2 default KDF is HMAC-SHA1 */
		kdfAlgo = CRYPT_ALGO_HMAC_SHA1;
		kdfParam = 20;
		}

	/* Recreate the encryption and MAC contexts used for the authenticated 
	   encryption from the algorithm parameter data stored with the generic-
	   secret context */
	REQUIRES( boundsCheck( queryInfo->encParamStart, queryInfo->encParamLength,
						   queryInfo->authEncParamLength ) );
	sMemConnect( &stream, queryInfo->authEncParamData + queryInfo->encParamStart, 
				 queryInfo->encParamLength );
	status = readContextAlgoID( &stream, &iAuthEncCryptContext, NULL, 
								DEFAULT_TAG, ALGOID_CLASS_CRYPT );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( boundsCheck( queryInfo->macParamStart, queryInfo->macParamLength,
						   queryInfo->authEncParamLength ) );
	sMemConnect( &stream, queryInfo->authEncParamData + queryInfo->macParamStart, 
				 queryInfo->macParamLength );
	status = readContextAlgoID( &stream, &iAuthEncMacContext, NULL, 
								DEFAULT_TAG, ALGOID_CLASS_HASH );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iAuthEncCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Derive the encryption and MAC keys from the generic-secret key */
	setMechanismKDFInfo( &mechanismInfo, iAuthEncCryptContext, 
						 iGenericContext, kdfAlgo, "encryption", 10 );
	mechanismInfo.hashParam = kdfParam;
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_KDF,
							  &mechanismInfo, MECHANISM_DERIVE_PBKDF2 );
	if( cryptStatusOK( status ) )
		{
		setMechanismKDFInfo( &mechanismInfo, iAuthEncMacContext, 
							 iGenericContext, kdfAlgo, "authentication", 14 );
		mechanismInfo.hashParam = kdfParam;
		status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_KDF,
								  &mechanismInfo, MECHANISM_DERIVE_PBKDF2 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iAuthEncCryptContext, IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( iAuthEncMacContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* MAC the AuthEnc parameter data alongside the payload data to prevent 
	   an attacker from manipulating the algorithm parameters to cause 
	   corruption that won't be detected by the MAC on the payload data */
	status = krnlSendMessage( iAuthEncMacContext, IMESSAGE_CTX_HASH,
							  ( MESSAGE_CAST ) queryInfo->authEncParamData,
							  queryInfo->authEncParamLength );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iAuthEncCryptContext, IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( iAuthEncMacContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	*iCryptContext = iAuthEncCryptContext;
	*iMacContext = iAuthEncMacContext;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					EncryptionAlgorithmIdentifier Routines					*
*																			*
****************************************************************************/

/* EncryptionAlgorithmIdentifier parameters:

	aesXcbc: AES FIPS

		iv				OCTET STRING SIZE (16)

	aesXcfb: AES FIPS

		SEQUENCE {
			iv			OCTET STRING SIZE (16),
			noOfBits	INTEGER (128)
			}

	cast5cbc: RFC 2144
		SEQUENCE {
			iv			OCTET STRING DEFAULT 0,
			keyLen		INTEGER (128)
			}

	rc2CBC: RFC 2311
		SEQUENCE {
			rc2Param	INTEGER (58),	-- 128 bit key
			iv			OCTET STRING SIZE (8)
			}

	rc4: NULL

   Because of the somewhat haphazard nature of encryption
   AlgorithmIdentifier definitions we can only handle the following
   algorithm/mode combinations:

	AES ECB, CBC, CFB
	CAST128 CBC
	DES ECB, CBC, CFB
	3DES ECB, CBC, CFB
	RC2 ECB, CBC
	RC4 */

/* Magic value to denote 128-bit RC2 keys */

#define RC2_KEYSIZE_MAGIC		58

/* Get the size of an EncryptionAlgorithmIdentifier record */

CHECK_RETVAL_LENGTH \
int sizeofCryptContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	STREAM nullStream;
	int status;

	REQUIRES( isHandleRangeValid( iCryptContext ) );

	/* Determine how large the algoID and associated parameters are.  
	   Because this is a rather complex operation the easiest way to do it 
	   is to write to a null stream and get its size */
	sMemNullOpen( &nullStream );
	status = writeCryptContextAlgoID( &nullStream, iCryptContext );
	if( cryptStatusOK( status ) )
		status = stell( &nullStream );
	sMemClose( &nullStream );

	return( status );
	}

 /* Read an EncryptionAlgorithmIdentifier/DigestAlgorithmIdentifier */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCryptAlgoParams( INOUT_PTR STREAM *stream, 
						 INOUT_PTR QUERY_INFO *queryInfo,
						 IN_LENGTH_Z const int startOffset )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES_S( isShortIntegerRange( startOffset ) );

	/* Read the algorithm-specific parameters.  In theory we should do
	   something with some of the values like the IV size parameter, but
	   since the standard never explains what to do if it's something other
	   than the algorithm block size (Left pad? Right pad? Sign-extend?
	   Repeat the data?) it's safer not to do anything ("Never check for an
	   error that you don't know how to handle").  In any case there are no
	   known cases of these strange values ever being used, probably because
	   all existing software would break, so we make sure that they're 
	   present but otherwise ignore them */
	switch( queryInfo->cryptAlgo )
		{
#ifdef USE_3DES
		case CRYPT_ALGO_3DES:
#endif /* USE_3DES */
		case CRYPT_ALGO_AES:
#ifdef USE_DES
		case CRYPT_ALGO_DES:
#endif /* USE_DES */
			{
			const int minIVsize = \
						( queryInfo->cryptAlgo == CRYPT_ALGO_AES ) ? \
						  16 : MIN_IVSIZE;

			if( queryInfo->cryptMode == CRYPT_MODE_ECB )
				{
				/* The NULL parameter has already been read in
				   readAlgoIDparams() */
				return( CRYPT_OK );
				}
			if( queryInfo->cryptMode == CRYPT_MODE_CBC )
				{
				return( readOctetString( stream, queryInfo->iv,
										 &queryInfo->ivLength, minIVsize, 
										 CRYPT_MAX_IVSIZE ) );
				}
			readSequence( stream, NULL );
			readOctetString( stream, queryInfo->iv, &queryInfo->ivLength,
							 minIVsize, CRYPT_MAX_IVSIZE );
			return( readShortInteger( stream, NULL ) );
			}

#ifdef USE_CAST
		case CRYPT_ALGO_CAST:
			readSequence( stream, NULL );
			readOctetString( stream, queryInfo->iv, &queryInfo->ivLength,
							 MIN_IVSIZE, CRYPT_MAX_IVSIZE );
			return( readShortInteger( stream, NULL ) );
#endif /* USE_CAST */

#ifdef USE_RC2
		case CRYPT_ALGO_RC2:
			/* In theory we should check that the parameter value ==
			   RC2_KEYSIZE_MAGIC (corresponding to a 128-bit key) but in
			   practice this doesn't really matter, we just use whatever we
			   find inside the PKCS #1 padding */
			readSequence( stream, NULL );
			if( queryInfo->cryptMode != CRYPT_MODE_CBC )
				return( readShortInteger( stream, NULL ) );
			readShortInteger( stream, NULL );
			return( readOctetString( stream, queryInfo->iv,
									 &queryInfo->ivLength,
									 MIN_IVSIZE, CRYPT_MAX_IVSIZE ) );
#endif /* USE_RC2 */

#ifdef USE_RC4
		case CRYPT_ALGO_RC4:
			/* The NULL parameter has already been read in
			   readAlgoIDparams() */
			return( CRYPT_OK );
#endif /* USE_RC4 */

		case CRYPT_IALGO_GENERIC_SECRET:
			return( readGenericSecretParams( stream, queryInfo, 
											 startOffset ) );
		}

	retIntError();
	}

/* Write an EncryptionAlgorithmIdentifier record */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCryptContextAlgoID( INOUT_PTR STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	ALGOID_PARAMS algoIDparams;
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];
	const BYTE *oid;
	int algorithm, mode = CRYPT_MODE_NONE;	/* enum vs.int */
	int keySize = 0, oidSize, ivSize = 0, sizeofIV = 0, paramSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isHandleRangeValid( iCryptContext ) );

	/* Extract the information that we need to write the
	   AlgorithmIdentifier */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && !isSpecialAlgo( algorithm ) )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &mode, CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) && !isStreamCipher( algorithm ) && \
			needsIV( mode ) )
			{
			MESSAGE_DATA msgData;

			setMessageData( &msgData, iv, CRYPT_MAX_IVSIZE );
			status = krnlSendMessage( iCryptContext, 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_CTXINFO_IV );
			if( cryptStatusOK( status ) )
				{
				ivSize = msgData.length;
				sizeofIV = sizeofShortObject( ivSize );
				}
			}
		}
	if( cryptStatusOK( status ) && \
		( isParameterisedConvAlgo( algorithm ) || \
		  isSpecialAlgo( algorithm ) ) )
		{
		/* Some algorithms are parameterised so we have to extract 
		   additional information to deal with them */
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
		}
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "Couldn't extract information needed to write "
					 "AlgoID" ));
		assert( DEBUG_WARN );
		return( status );
		}

	ENSURES_S( isConvAlgo( algorithm ) || isSpecialAlgo( algorithm ) );

	/* Get the OID for this algorithm */
	initAlgoIDparamsCrypt( &algoIDparams, mode, keySize );
	oid = algorithmToOID( algorithm, &algoIDparams, ALGOTOOID_CHECK_VALID );
	if( oid == NULL )
		{
		/* Some algorithm+mode combinations can't be encoded using the
		   available PKCS #7 / CMS OIDs, the best that we can do in this 
		   case is alert the user in debug mode and return a 
		   CRYPT_ERROR_NOTAVAIL */
		DEBUG_DIAG(( "Tried to write non-PKCS #7 / CMS algorithm ID" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	oidSize = sizeofOID( oid );
	ENSURES_S( oidSize >= MIN_OID_SIZE && oidSize <= MAX_OID_SIZE );

	/* Write the algorithm-specific parameters */
	switch( algorithm )
		{
#ifdef USE_3DES
		case CRYPT_ALGO_3DES:
#endif /* USE_3DES */
		case CRYPT_ALGO_AES:
#ifdef USE_DES
		case CRYPT_ALGO_DES:
#endif /* USE_DES */
			{
			const int noBits = ( algorithm == CRYPT_ALGO_AES ) ? 128 : 64;

			ANALYSER_HINT( ivSize > 0 && ivSize < CRYPT_MAX_IVSIZE );

			paramSize = \
				( mode == CRYPT_MODE_ECB ) ? sizeofNull() : \
				( mode == CRYPT_MODE_CBC ) ? sizeofIV : \
				  sizeofShortObject( sizeofIV + sizeofShortInteger( noBits ) );
			writeSequence( stream, oidSize + paramSize );
			swrite( stream, oid, oidSize );
			if( mode == CRYPT_MODE_ECB )
				return( writeNull( stream, DEFAULT_TAG ) );
			if( mode == CRYPT_MODE_CBC )
				return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
			writeSequence( stream, sizeofIV + sizeofShortInteger( noBits ) );
			writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
			return( writeShortInteger( stream, noBits, DEFAULT_TAG ) );
			}

#ifdef USE_CAST
		case CRYPT_ALGO_CAST:
			REQUIRES( ivSize == 8 );

			paramSize = sizeofIV + sizeofShortInteger( 128 );
			writeSequence( stream, oidSize + \
								   sizeofShortObject( paramSize ) );
			swrite( stream, oid, oidSize );
			writeSequence( stream, paramSize );
			writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
			return( writeShortInteger( stream, 128, DEFAULT_TAG ) );
#endif /* USE_CAST */

#ifdef USE_RC2
		case CRYPT_ALGO_RC2:
			paramSize = ( ( mode == CRYPT_MODE_ECB ) ? 0 : sizeofIV ) + \
						sizeofShortInteger( RC2_KEYSIZE_MAGIC );
			writeSequence( stream, oidSize + \
								   sizeofShortObject( paramSize ) );
			swrite( stream, oid, oidSize );
			writeSequence( stream, paramSize );
			if( mode != CRYPT_MODE_CBC )
				{
				return( writeShortInteger( stream, RC2_KEYSIZE_MAGIC,
										   DEFAULT_TAG ) );
				}
			writeShortInteger( stream, RC2_KEYSIZE_MAGIC, DEFAULT_TAG );
			return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
#endif /* USE_RC2 */

#ifdef USE_RC4
		case CRYPT_ALGO_RC4:
			writeSequence( stream, oidSize + sizeofNull() );
			swrite( stream, oid, oidSize );
			return( writeNull( stream, DEFAULT_TAG ) );
#endif /* USE_RC4 */

		case CRYPT_IALGO_GENERIC_SECRET:
			return( writeGenericSecretParams( stream, iCryptContext, 
											  oid, oidSize ) );
		}

	retIntError();
	}
#endif /* USE_INT_ASN1 */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
