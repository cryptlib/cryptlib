/****************************************************************************
*																			*
*						Key Exchange Read/Write Routines					*
*						Copyright Peter Gutmann 1992-2019					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp_rw.h"
  #include "mech.h"
#else
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/misc_rw.h"
  #include "enc_dec/pgp_rw.h"
  #include "mechs/mech.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for the KEK record */

enum { CTAG_KK_DA };

/* Context-specific tags for the KeyTrans record */

enum { CTAG_KT_SKI };

#ifdef USE_INT_CMS

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get a CMS key identifier.  This gets a bit complicated because in theory 
   we're supposed to use the sKID from a certificate but if we're using a 
   raw public key then there's no sKID present.  To deal with this we try 
   for an sKID if the object that we've been passed is a certificate, if 
   that fails or if it's a raw context then we use the keyID */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int getCmsKeyIdentifier( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						 OUT_BUFFER( keyIDMaxLength, *keyIDlength ) \
							BYTE *keyID, 
						 IN_LENGTH_SHORT_MIN( 32 ) const int keyIDMaxLength,
						 OUT_LENGTH_BOUNDED_Z( keyIDMaxLength ) \
							int *keyIDlength )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtrDynamic( keyID, keyIDMaxLength ) );
	assert( isWritePtr( keyIDlength, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isShortIntegerRangeMin( keyIDMaxLength, 32 ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( keyIDMaxLength ) ); 
	memset( keyID, 0, min( 16, keyIDMaxLength ) );
	*keyIDlength = 0;

	/* If it's a certificate, try for an sKID */
	setMessageData( &msgData, keyID, keyIDMaxLength );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
	if( cryptStatusOK( status ) )
		{
		*keyIDlength = msgData.length;
		return( CRYPT_OK );
		}

	/* Use the keyID */
	setMessageData( &msgData, keyID, keyIDMaxLength );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusError( status ) )
		return( status );
	*keyIDlength = msgData.length;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Conventionally-Encrypted Key Routines					*
*																			*
****************************************************************************/

/* Read/write a PBKDF2 key derivation record:

	SEQUENCE {
		algorithm					AlgorithmIdentifier (pkcs-5 12),
		params SEQUENCE {
			salt					OCTET STRING,
			iterationCount			INTEGER (1..MAX),
			keyLength				INTEGER OPTIONAL,
			prf						AlgorithmIdentifier DEFAULT hmacWithSHA1
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readKeyDerivationInfo( INOUT_PTR STREAM *stream, 
								  OUT_PTR QUERY_INFO *queryInfo )
	{
	long endPos, value;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the outer wrapper and key derivation algorithm OID */
	readConstructed( stream, NULL, CTAG_KK_DA );
	status = readFixedOID( stream, OID_PBKDF2, sizeofOID( OID_PBKDF2 ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the PBKDF2 parameters, limiting the salt and iteration count to
	   sane values */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	readOctetString( stream, queryInfo->salt, &queryInfo->saltLength, 
					 2, CRYPT_MAX_HASHSIZE );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value < 1 || value > MAX_KEYSETUP_ITERATIONS )
		return( CRYPT_ERROR_BADDATA );
	ENSURES( isIntegerRange( value ) );
	queryInfo->keySetupIterations = ( int ) value;
	queryInfo->keySetupAlgo = CRYPT_ALGO_HMAC_SHA1;
	if( stell( stream ) < endPos && \
		sPeek( stream ) == BER_INTEGER )
		{
		/* There's an optional key length that may override the default 
		   key size present, read it.  Note that we compare the upper
		   bound to MAX_WORKING_KEYSIZE rather than CRYPT_MAX_KEYSIZE,
		   since this is a key used directly with an encryption algorithm
		   rather than a generic keying value that may be hashed down to 
		   size */
		status = readShortInteger( stream, &value );
		if( cryptStatusError( status ) )
			return( status );
		if( value < MIN_KEYSIZE || value > MAX_WORKING_KEYSIZE )
			return( CRYPT_ERROR_BADDATA );
		ENSURES( isShortIntegerRange( value ) );
		queryInfo->keySize = ( int ) value;
		}
	if( stell( stream ) < endPos )
		{
		CRYPT_ALGO_TYPE prfAlgo;
		ALGOID_PARAMS algoIDparams;
	
		/* There's a non-default hash algorithm ID present, read it */
		status = readAlgoIDex( stream, &prfAlgo, &algoIDparams, 
							   ALGOID_CLASS_HASH );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->keySetupAlgo = prfAlgo;
		queryInfo->keySetupParam = algoIDparams.hashParam;
		}

	/* Make sure that we've read everything present */
	if( stell( stream ) != endPos )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeKeyDerivationInfo( INOUT_PTR STREAM *stream,
								   IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	MESSAGE_DATA msgData;
	BYTE salt[ CRYPT_MAX_HASHSIZE + 8 ];
	int saltLength, keySetupIterations, derivationInfoSize;
	int prfAlgo DUMMY_INIT, prfAlgoSize DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( isHandleRangeValid( iCryptContext ) );

	/* Get the key derivation information */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &keySetupIterations,
							  CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &prfAlgo, CRYPT_CTXINFO_KEYING_ALGO );
		}
	if( cryptStatusOK( status ) && isParameterisedMacAlgo( prfAlgo ) )
		{
#if 0	/* In theory this could be controlled by the 
		   CRYPT_OPTION_ENCR_HASHPARAM option but it's unclear whether this
		   should affect the keying setup, or how it would get across to a
		   context as a hypothetical CRYPT_CTXINFO_KEYING_ALGO_XXXX, so for 
		   now we assume that a configured SHA2 means SHA2-256 */
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &prfAlgoSize, 
								  CRYPT_CTXINFO_KEYING_ALGO_XXXX );
#else
		prfAlgoSize = 32;
#endif /* 0 */
		}
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, salt, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_KEYING_SALT );
	if( cryptStatusError( status ) )
		return( status );
	saltLength = msgData.length;
	derivationInfoSize = sizeofShortObject( saltLength ) + \
						 sizeofShortInteger( keySetupIterations );
	if( prfAlgo != CRYPT_ALGO_HMAC_SHA1 )
		{
		int prfAlgoIDsize;

		if( isParameterisedMacAlgo( prfAlgo ) )
			{
			ALGOID_PARAMS algoIDparams;

			initAlgoIDparamsHash( &algoIDparams, prfAlgo, prfAlgoSize );
			status = prfAlgoIDsize = \
						sizeofAlgoIDex( prfAlgo, &algoIDparams );
			}
		else
			status = prfAlgoIDsize = sizeofAlgoID( prfAlgo );
		if( cryptStatusError( status ) )
			return( status );
		derivationInfoSize += prfAlgoIDsize;
		}

	/* Write the PBKDF2 information */
	writeConstructed( stream, sizeofOID( OID_PBKDF2 ) + \
							  sizeofShortObject( derivationInfoSize ), 
					  CTAG_KK_DA );
	writeOID( stream, OID_PBKDF2 );
	writeSequence( stream, derivationInfoSize );
	writeOctetString( stream, salt, saltLength, DEFAULT_TAG );
	status = writeShortInteger( stream, keySetupIterations, DEFAULT_TAG );
	if( cryptStatusOK( status ) && prfAlgo != CRYPT_ALGO_HMAC_SHA1 )
		{
		if( isParameterisedMacAlgo( prfAlgo ) )
			{
			ALGOID_PARAMS algoIDparams;

			initAlgoIDparamsHash( &algoIDparams, prfAlgo, prfAlgoSize );
			status = writeAlgoIDex( stream, prfAlgo, &algoIDparams, 
									DEFAULT_TAG );
			}
		else
			status = writeAlgoID( stream, prfAlgo, DEFAULT_TAG );
		}
	zeroise( salt, CRYPT_MAX_HASHSIZE );
	return( status );
	}

/* Read/write CMS KEK data.  This is the weird Spyrus key wrap that was 
   slipped into CMS, nothing seems to support this so we don't either */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCmsKek( INOUT_PTR STREAM *stream, 
					   OUT_PTR QUERY_INFO *queryInfo )
	{
	long value;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the header */
	readConstructed( stream, NULL, CTAG_RI_KEK );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != KEK_VERSION )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_ERROR_NOTAVAIL );
	}

#if 0	/* 21/4/06 Disabled since it was never used */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeCmsKek( INOUT_PTR STREAM *stream, 
						IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						IN_BUFFER( encryptedKeyLength ) const BYTE *encryptedKey, 
						IN_LENGTH_SHORT_MIN( MIN_KEYSIZE ) \
							const int encryptedKeyLength )
	{
	STREAM localStream;
	MESSAGE_DATA msgData;
	BYTE kekInfo[ 128 + 8 ], label[ CRYPT_MAX_TEXTSIZE + 8 ];
	const int algoIdInfoSize = \
				sizeofContextAlgoID( iCryptContext, ALGOID_ENCODING_NONE );
	int kekInfoSize, labelSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( encryptedKey, encryptedKeyLength ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isShortIntegerRangeMin( encryptedKeyLength, MIN_KEYSIZE ) );

	if( cryptStatusError( algoIdInfoSize ) )
		return( algoIdInfoSize  );

	/* Get the label */
	setMessageData( &msgData, label, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		return( status );
	labelSize = msgData.length;

	/* Determine the size of the KEK info.  To save evaluating it twice in a
	   row and because it's short, we just write it to local buffers */
	sMemOpen( &localStream, kekInfo, 128 );
	writeSequence( &localStream, sizeofOID( OID_PWRIKEK ) + algoIdInfoSize );
	writeOID( &localStream, OID_PWRIKEK );
	status = writeContextCryptAlgoID( &localStream, iCryptContext );
	if( cryptStatusOK( status ) )
		kekInfoSize = stell( &localStream );
	sMemDisconnect( &localStream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( kekInfoSize ) );

	/* Write the algorithm identifiers and encrypted key */
	writeConstructed( stream, sizeofShortInteger( KEK_VERSION ) + \
					  sizeofShortObject( \
							sizeofShortObject( labelSize ) ) + \
					  kekInfoSize + sizeofShortObject( encryptedKeyLength ),
					  CTAG_RI_KEKRI );
	writeShortInteger( stream, KEK_VERSION, DEFAULT_TAG );
	writeSequence( stream, sizeofShortObject( labelSize ) );
	writeOctetString( stream, label, labelSize, DEFAULT_TAG );
	swrite( stream, kekInfo, kekInfoSize );
	return( writeOctetString( stream, encryptedKey, encryptedKeyLength,
							  DEFAULT_TAG ) );
	}
#endif /* 0 */

/* Read/write cryptlib KEK data:

	[3] SEQUENCE {
		version						INTEGER (0),
		keyDerivationAlgorithm	[0]	AlgorithmIdentifier OPTIONAL,
		keyEncryptionAlgorithm		AlgorithmIdentifier,
		encryptedKey				OCTET STRING
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCryptlibKek( INOUT_PTR STREAM *stream, 
							OUT_PTR QUERY_INFO *queryInfo )
	{
	QUERY_INFO keyDerivationQueryInfo DUMMY_INIT_STRUCT;
	const int startPos = stell( stream );
	BOOLEAN hasDerivationInfo = FALSE;
	long value;
	int tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* If it's a CMS KEK, read it as such */
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( tag == CTAG_RI_KEK )
		return( readCmsKek( stream, queryInfo ) );

	/* Read the header */
	readConstructed( stream, NULL, CTAG_RI_PASSWORD );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != PWRI_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the optional KEK derivation info and KEK algorithm info */
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( tag == MAKE_CTAG( CTAG_KK_DA ) )
		{
		status = readKeyDerivationInfo( stream, &keyDerivationQueryInfo );
		if( cryptStatusError( status ) )
			return( status );
		hasDerivationInfo = TRUE;
		}
	readSequence( stream, NULL );
	status = readFixedOID( stream, OID_PWRIKEK, sizeofOID( OID_PWRIKEK ) );
	if( cryptStatusOK( status ) )
		{
		status = readContextAlgoID( stream, NULL, queryInfo, DEFAULT_TAG,
									ALGOID_CLASS_CRYPT );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If there's key-derivation information available, copy it across to 
	   the overall query information */
	if( hasDerivationInfo )
		{
		REQUIRES( rangeCheck( keyDerivationQueryInfo.saltLength, 1, 
							  CRYPT_MAX_HASHSIZE ) );
		memcpy( queryInfo->salt, keyDerivationQueryInfo.salt,
				keyDerivationQueryInfo.saltLength );
		queryInfo->saltLength = keyDerivationQueryInfo.saltLength;
		queryInfo->keySetupIterations = \
						keyDerivationQueryInfo.keySetupIterations;
		queryInfo->keySetupAlgo = keyDerivationQueryInfo.keySetupAlgo;
		queryInfo->keySetupParam = \
						keyDerivationQueryInfo.keySetupParam;
		if( keyDerivationQueryInfo.keySize > 0 )
			{
			/* How to handle the optional keysize value from the key-
			   derivation information is a bit unclear, for example what 
			   should we do if the encryption algorithm is AES-256 but the 
			   keysize is 128 bits?  At the moment this problem is resolved
			   by the fact that nothing seems to use the keysize value */
			queryInfo->keySize = keyDerivationQueryInfo.keySize;
			}
		}

	/* Finally, read the start of the encrypted key */
	status = readOctetStringHole( stream, &queryInfo->dataLength, 
								  MIN_KEYSIZE, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, startPos, 
											  &queryInfo->dataStart );
		}
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( isIntegerRangeNZ( queryInfo->dataStart ) );

	/* Make sure that the remaining key data is present */
	return( sSkip( stream, queryInfo->dataLength, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeCryptlibKek( STREAM *stream, 
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							 IN_BUFFER( encryptedKeyLength ) \
								const BYTE *encryptedKey, 
							 IN_LENGTH_SHORT_MIN( MIN_KEYSIZE ) \
								const int encryptedKeyLength )
	{
	STREAM localStream;
	BYTE derivationInfo[ CRYPT_MAX_HASHSIZE + 32 + 8 ], kekInfo[ 128 + 8 ];
	BOOLEAN hasKeyDerivationInfo = TRUE;
	const int algoIdInfoSize = sizeofCryptContextAlgoID( iCryptContext );
	int derivationInfoSize = 0, kekInfoSize DUMMY_INIT, value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( encryptedKey, encryptedKeyLength ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isShortIntegerRangeMin( encryptedKeyLength, MIN_KEYSIZE ) );

	if( cryptStatusError( algoIdInfoSize ) )
		return( algoIdInfoSize  );

	/* If it's a non-password-derived key and there's a label attached,
	   write it as a KEKRI with a PWRI algorithm identifier as the key
	   encryption algorithm */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( status == CRYPT_ERROR_NOTINITED )
		{
		hasKeyDerivationInfo = FALSE;

#if 0	/* 21/4/06 Disabled since it was never used */
		MESSAGE_DATA msgData;

		/* There's no password-derivation information present, see if there's
		   a label present */
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_LABEL );
		if( cryptStatusOK( status ) )
			{
			/* There's a label present, write it as a PWRI within a KEKRI */
			return( writeCmsKek( stream, iCryptContext, encryptedKey,
								 encryptedKeyLength ) );
			}
#endif /* 0 */
		}

	/* Determine the size of the derivation info and KEK info.  To save
	   evaluating it twice in a row and because it's short, we just write
	   it to local buffers */
	if( hasKeyDerivationInfo )
		{
		sMemOpen( &localStream, derivationInfo, CRYPT_MAX_HASHSIZE + 32 );
		status = writeKeyDerivationInfo( &localStream, iCryptContext );
		if( cryptStatusOK( status ) )
			derivationInfoSize = stell( &localStream );
		sMemDisconnect( &localStream );
		if( cryptStatusError( status ) )
			return( status );
		ENSURES( isShortIntegerRangeNZ( derivationInfoSize ) );
		}
	sMemOpen( &localStream, kekInfo, 128 );
	writeSequence( &localStream, sizeofOID( OID_PWRIKEK ) + algoIdInfoSize );
	writeOID( &localStream, OID_PWRIKEK );
	status = writeCryptContextAlgoID( &localStream, iCryptContext );
	if( cryptStatusOK( status ) )
		kekInfoSize = stell( &localStream );
	sMemDisconnect( &localStream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( kekInfoSize ) );

	/* Write the algorithm identifiers and encrypted key */
	writeConstructed( stream, sizeofShortInteger( PWRI_VERSION ) + \
							  derivationInfoSize + kekInfoSize + \
							  sizeofShortObject( encryptedKeyLength ),
					  CTAG_RI_PASSWORD );
	writeShortInteger( stream, PWRI_VERSION, DEFAULT_TAG );
	if( derivationInfoSize > 0 )
		swrite( stream, derivationInfo, derivationInfoSize );
	swrite( stream, kekInfo, kekInfoSize );
	return( writeOctetString( stream, encryptedKey, encryptedKeyLength,
							  DEFAULT_TAG ) );
	}

#ifdef USE_PGP

/* Read/write PGP KEK data.

	SKE:
		byte	ctb = PGP_PACKET_SKE
		byte[]	length
		byte	version = PGP_VERSION_OPENPGP
		byte	cryptAlgo
		byte	stringToKey specifier, 0, 1, or 3
		byte[]	stringToKey data
				0x00: byte		hashAlgo
				0x01: byte[8]	salt
				0x03: byte		iterations */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgpKek( INOUT_PTR STREAM *stream, 
					   OUT_PTR QUERY_INFO *queryInfo )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Make sure that the packet header is in order */
	status = getPgpPacketInfo( stream, queryInfo, QUERYOBJECT_KEYEX );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the encryption algorithm information */
	status = readPgpAlgo( stream, &queryInfo->cryptAlgo, 
						  &queryInfo->cryptParam, PGP_ALGOCLASS_PWCRYPT );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the S2K information */
	return( readPgpS2K( stream, &queryInfo->keySetupAlgo, 
						&queryInfo->keySetupParam, queryInfo->salt,  
						PGP_SALTSIZE, &queryInfo->saltLength,
						&queryInfo->keySetupIterations ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writePgpKek( INOUT_PTR STREAM *stream, 
						IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						STDC_UNUSED const BYTE *encryptedKey, 
						STDC_UNUSED const int encryptedKeyLength )
	{
	BYTE salt[ CRYPT_MAX_HASHSIZE + 8 ];
	int hashAlgo DUMMY_INIT, kekCryptAlgo DUMMY_INIT;	/* int vs.enum */
	int pgpKekCryptAlgo, pgpHashAlgo DUMMY_INIT, keySetupIterations;
	LOOP_INDEX count;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( encryptedKey == NULL && encryptedKeyLength == 0 );

	/* Get the key derivation information */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &keySetupIterations, 
							  CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &hashAlgo, CRYPT_CTXINFO_KEYING_ALGO );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &kekCryptAlgo, CRYPT_CTXINFO_ALGO );
		}
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, salt, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_KEYING_SALT );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = cryptlibToPgpAlgo( kekCryptAlgo, &pgpKekCryptAlgo );
	if( cryptStatusOK( status ) )
		status = cryptlibToPgpAlgo( hashAlgo, &pgpHashAlgo );
	ENSURES( cryptStatusOK( status ) );

	/* Calculate the PGP "iteration count" from the value used to derive
	   the key.  The "iteration count" is actually a count of how many bytes
	   are hashed, this is because the "iterated hashing" treats the salt +
	   password as an infinitely-repeated sequence of values and hashes the
	   resulting string for PGP-iteration-count bytes worth.  Instead of
	   being written directly the count is encoded in a complex manner that
	   saves a whole byte, so before we can write it we have to encode it
	   into the base + exponent form expected by PGP.  This has a default
	   base of 16 + the user-supplied base value, we can set this to zero
	   since the iteration count used by cryptlib is always a multiple of
	   16, the remainder is just log2 of what's left of the iteration
	   count */
	REQUIRES( keySetupIterations % 16 == 0 );
	keySetupIterations /= 32;	/* Remove fixed offset before log2 op.*/
	LOOP_MED( count = 0, keySetupIterations > 0,
			  ( count++, keySetupIterations >>= 1 ) )
		{
		ENSURES( LOOP_INVARIANT_MED_XXX( count, 0, 64 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	count <<= 4;				/* Exponent comes first */
	ENSURES( count >= 0 && count <= 0xFF );

	/* Write the SKE packet */
	pgpWritePacketHeader( stream, PGP_PACKET_SKE, 
						  PGP_VERSION_SIZE + PGP_ALGOID_SIZE + 1 + \
							PGP_ALGOID_SIZE + PGP_SALTSIZE + 1 );
	sputc( stream, PGP_VERSION_OPENPGP );
	sputc( stream, pgpKekCryptAlgo );
	sputc( stream, 3 );		/* S2K = salted, iterated hash */
	sputc( stream, pgpHashAlgo );
	swrite( stream, salt, PGP_SALTSIZE );
	return( sputc( stream, count ) );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*						Public-key Encrypted Key Routines					*
*																			*
****************************************************************************/

/* Read/write CMS key transport data:

	SEQUENCE {
		version						INTEGER (0),
		issuerAndSerial				IssuerAndSerialNumber,
		algorithm					AlgorithmIdentifier,
		encryptedKey				OCTET STRING
		} */

#ifdef USE_OAEP

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 2 ) ) \
static int getOAEPParams( const CRYPT_CONTEXT iHashContext,
						  OUT_PTR ALGOID_PARAMS *algoIDparams )
	{
	int value;	/* enum vs. int */
	int hashParam DUMMY_INIT, status;

	assert( isWritePtr( algoIDparams, sizeof( ALGOID_PARAMS ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );

	/* Clear return value */
	memset( algoIDparams, 0, sizeof( ALGOID_PARAMS ) );

	/* OAEP requires an additional parameter, the hash algorithm to use.  
	   Actually it requires numerous additional parameters because in OAEP 
	   absolutely everything is parameterised, but at the moment the only 
	   one that's really used is the hash algorithm */
	status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
							  IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_OPTION_ENCR_HASH );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, &hashParam, 
								  CRYPT_OPTION_ENCR_HASHPARAM );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the necessary parameters for OAEP */
	initAlgoIDparamsHash( algoIDparams, value, hashParam );
	algoIDparams->encodingType = ALGOID_ENCODING_OAEP;
	return( sizeofContextAlgoIDex( iHashContext, algoIDparams ) );
	}
#endif /* USE_OAEP */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCmsKeytrans( INOUT_PTR STREAM *stream, 
							OUT_PTR QUERY_INFO *queryInfo )
	{
	ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;
	const int startPos = stell( stream );
	long value;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the header and version number */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != KEYTRANS_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the key ID and PKC algorithm information.  Since we're recording 
	   the position of the issuerAndSerialNumber as a blob we have to use
	   getStreamObjectLength() to get the overall blob data size */
	status = getStreamObjectLength( stream, &length, 16 );
	if( cryptStatusOK( status ) && !isShortIntegerRangeNZ( length ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, startPos, 
											  &queryInfo->iAndSStart );
		}
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( isIntegerRangeNZ( queryInfo->iAndSStart ) );
	queryInfo->iAndSLength = length;
	status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDex( stream, &queryInfo->cryptAlgo, &algoIDparams, 
							   ALGOID_CLASS_PKC );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( algoIDparams.encodingType != ALGOID_ENCODING_NONE )
		{
		queryInfo->cryptAlgoEncoding = algoIDparams.encodingType;
		queryInfo->hashAlgo = algoIDparams.hashAlgo;
		queryInfo->hashParam = algoIDparams.hashParam;
		}

	/* Finally, read the start of the encrypted key */
	status = readOctetStringHole( stream, &queryInfo->dataLength, 
								  MIN_PKCSIZE, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, startPos, 
											  &queryInfo->dataStart );
		}
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( isIntegerRangeNZ( queryInfo->dataStart ) );

	/* Make sure that the remaining key data is present */
	return( sSkip( stream, queryInfo->dataLength, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int writeKeytransCMS( INOUT_PTR STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							 IN_BUFFER( encryptedKeyLength ) \
								const BYTE *encryptedKey, 
							 IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
								const int encryptedKeyLength,
							 IN_BUFFER( auxInfoLength ) const void *auxInfo, 
							 IN_LENGTH_SHORT const int auxInfoLength,
							 IN_BOOL const BOOLEAN isOAEP )
	{
#ifdef USE_OAEP
	ALGOID_PARAMS algoIDparams;
#endif /* USE_OAEP */
	int algoIdInfoSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( encryptedKey, encryptedKeyLength ) );
	assert( isReadPtrDynamic( auxInfo, auxInfoLength ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isShortIntegerRangeMin( encryptedKeyLength, MIN_PKCSIZE ) );
	REQUIRES( isShortIntegerRangeNZ( auxInfoLength ) );
	REQUIRES( isBooleanValue( isOAEP ) );

#ifdef USE_OAEP
	if( isOAEP )
		{
		status = algoIdInfoSize = \
					getOAEPParams( iCryptContext, &algoIDparams );
		}
	else
#endif /* USE_OAEP */
		{
		status = algoIdInfoSize = \
					sizeofContextAlgoID( iCryptContext );
		}
	if( cryptStatusError( status ) )
		return( status );

	writeSequence( stream, sizeofShortInteger( KEYTRANS_VERSION ) + \
						   auxInfoLength + algoIdInfoSize + \
						   sizeofShortObject( encryptedKeyLength ) );
	writeShortInteger( stream, KEYTRANS_VERSION, DEFAULT_TAG );
	swrite( stream, auxInfo, auxInfoLength );
#ifdef USE_OAEP
	if( isOAEP )
		writeContextAlgoIDex( stream, iCryptContext, &algoIDparams );
	else
#endif /* USE_OAEP */
		writeContextAlgoID( stream, iCryptContext );
	return( writeOctetString( stream, encryptedKey, encryptedKeyLength, 
							  DEFAULT_TAG ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int writeCmsKeytrans( INOUT_PTR STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							 IN_BUFFER( encryptedKeyLength ) \
								const BYTE *encryptedKey, 
							 IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
								const int encryptedKeyLength,
							 IN_BUFFER( auxInfoLength ) const void *auxInfo, 
							 IN_LENGTH_SHORT const int auxInfoLength )
	{
	return( writeKeytransCMS( stream, iCryptContext, encryptedKey, 
							  encryptedKeyLength, auxInfo, auxInfoLength, 
							  FALSE ) );
	}

#ifdef USE_OAEP

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int writeCmsKeytransOAEP( INOUT_PTR STREAM *stream,
								 IN_HANDLE const CRYPT_CONTEXT iCryptContext,
								 IN_BUFFER( encryptedKeyLength ) \
									const BYTE *encryptedKey, 
								 IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
									const int encryptedKeyLength,
								 IN_BUFFER( auxInfoLength ) const void *auxInfo, 
								 IN_LENGTH_SHORT const int auxInfoLength )
	{
	return( writeKeytransCMS( stream, iCryptContext, encryptedKey, 
							  encryptedKeyLength, auxInfo, auxInfoLength, 
							  TRUE ) );
	}
#endif /* USE_OAEP */

/* Read/write cryptlib key transport data:

	SEQUENCE {
		version						INTEGER (2),
		keyID					[0]	SubjectKeyIdentifier,
		algorithm					AlgorithmIdentifier,
		encryptedKey				OCTET STRING
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCryptlibKeytrans( INOUT_PTR STREAM *stream, 
								 OUT_PTR QUERY_INFO *queryInfo )
	{
	ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;
	const int startPos = stell( stream );
	long value;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the header and version number */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != KEYTRANS_EX_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the key ID and PKC algorithm information */
	status = readOctetStringTag( stream, queryInfo->keyID, 
								 &queryInfo->keyIDlength, 8, 
								 CRYPT_MAX_HASHSIZE, CTAG_KT_SKI );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDex( stream, &queryInfo->cryptAlgo, &algoIDparams, 
							   ALGOID_CLASS_PKC );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( algoIDparams.encodingType != ALGOID_ENCODING_NONE )
		{
		queryInfo->cryptAlgoEncoding = algoIDparams.encodingType;
		queryInfo->hashAlgo = algoIDparams.hashAlgo;
		queryInfo->hashParam = algoIDparams.hashParam;
		}

	/* Finally, read the start of the encrypted key */
	status = readOctetStringHole( stream, &queryInfo->dataLength, 
								  MIN_KEYSIZE, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, startPos, 
											  &queryInfo->dataStart );
		}
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( isIntegerRangeNZ( queryInfo->dataStart ) );

	/* Make sure that the remaining key data is present */
	return( sSkip( stream, queryInfo->dataLength, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeKeytransCryptlib( INOUT_PTR STREAM *stream,
								  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
								  IN_BUFFER( encryptedKeyLength ) \
									const BYTE *encryptedKey, 
								  IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
									const int encryptedKeyLength,
								  IN_BOOL const BOOLEAN isOAEP )
	{
#ifdef USE_OAEP
	ALGOID_PARAMS algoIDparams;
#endif /* USE_OAEP */
	BYTE keyID[ 128 + 8 ];
	int algoIdInfoSize, keyIDlength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( encryptedKey, encryptedKeyLength ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isShortIntegerRangeMin( encryptedKeyLength, MIN_PKCSIZE ) );
	REQUIRES( isBooleanValue( isOAEP ) );

#ifdef USE_OAEP
	if( isOAEP )
		{
		status = algoIdInfoSize = \
					getOAEPParams( iCryptContext, &algoIDparams );
		}
	else
#endif /* USE_OAEP */
		{
		status = algoIdInfoSize = \
					sizeofContextAlgoID( iCryptContext );
		}
	if( cryptStatusError( status ) )
		return( status );

	status = getCmsKeyIdentifier( iCryptContext, keyID, 128, &keyIDlength );
	if( cryptStatusError( status ) )
		return( status );
	writeSequence( stream, sizeofShortInteger( KEYTRANS_EX_VERSION ) + \
						   sizeofShortObject( keyIDlength ) + algoIdInfoSize + \
						   sizeofShortObject( encryptedKeyLength ) );
	writeShortInteger( stream, KEYTRANS_EX_VERSION, DEFAULT_TAG );
	writeOctetString( stream, keyID, keyIDlength, CTAG_KT_SKI );
#ifdef USE_OAEP
	if( isOAEP )
		writeContextAlgoIDex( stream, iCryptContext, &algoIDparams );
	else
#endif /* USE_OAEP */
		writeContextAlgoID( stream, iCryptContext );
	return( writeOctetString( stream, encryptedKey, encryptedKeyLength, 
							  DEFAULT_TAG ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeCryptlibKeytrans( INOUT_PTR STREAM *stream,
								  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
								  IN_BUFFER( encryptedKeyLength ) \
									const BYTE *encryptedKey, 
								  IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
									const int encryptedKeyLength,
								  STDC_UNUSED const void *auxInfo,
								  STDC_UNUSED const int auxInfoLength )
	{
	REQUIRES( auxInfo == NULL && auxInfoLength == 0 );

	return( writeKeytransCryptlib( stream, iCryptContext, encryptedKey, 
								   encryptedKeyLength, FALSE ) );
	}

#ifdef USE_OAEP

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeCryptlibKeytransOAEP( INOUT_PTR STREAM *stream,
									  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
									  IN_BUFFER( encryptedKeyLength ) \
										const BYTE *encryptedKey, 
									  IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
										const int encryptedKeyLength,
									  STDC_UNUSED const void *auxInfo,
									  STDC_UNUSED const int auxInfoLength )
	{
	REQUIRES( auxInfo == NULL && auxInfoLength == 0 );

	return( writeKeytransCryptlib( stream, iCryptContext, encryptedKey, 
								   encryptedKeyLength, TRUE ) );
	}
#endif /* USE_OAEP */

#ifdef USE_PGP

/* Read/write PGP key transport data:

	PKE:
		byte	ctb = PGP_PACKET_PKE
		byte[]	length
		byte	version = PGP_VERSION_PGP2 or 3 (= OpenPGP, not the expected PGP3)
		byte[8]	keyID
		byte	PKC algo
		mpi(s)	encrypted session key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgpKeytrans( INOUT_PTR STREAM *stream, 
							OUT_PTR QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	int objectSize DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Make sure that the packet header is in order */
	status = getPgpPacketInfo( stream, queryInfo, QUERYOBJECT_KEYEX );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the PGP key ID and algorithm */
	REQUIRES( rangeCheck( PGP_KEYID_SIZE, 1, PGP_KEYID_SIZE ) );
	status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->keyIDlength = PGP_KEYID_SIZE;
	status = readPgpAlgo( stream, &queryInfo->cryptAlgo, NULL, 
						  PGP_ALGOCLASS_PKCCRYPT );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the RSA-encrypted key, recording the position and length of the 
	   raw RSA-encrypted integer value.  We have to be careful how we handle 
	   this because readInteger16Ubits() returns the canonicalised form of
	   the values (with leading zeroes truncated) so an stell() before the 
	   read doesn't necessarily represent the start of the payload:

		startPos	dataStart		 stell()
			|			|				|
			v			v <-- dataLen ->v
		+---+---------+-+---------------+
		|	|		  |0|///////////////| Stream
		+---+---------+-+---------------+ 
					  ^
					  |
					  + Before readInteger16Ubits() */
	if( queryInfo->cryptAlgo == CRYPT_ALGO_RSA )
		{
		status = readInteger16Ubits( stream, NULL, &queryInfo->dataLength,
									 MIN_PKCSIZE, CRYPT_MAX_PKCSIZE,
									 BIGNUM_CHECK_VALUE_PKC );
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, startPos, 
												  &objectSize );
			}
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->dataStart = objectSize - queryInfo->dataLength;
		REQUIRES( isIntegerRangeNZ( queryInfo->dataStart ) );
		}
	else
		{
		const int dataStartPos = stell( stream );
		int dummy;

		REQUIRES( isBufsizeRange( dataStartPos ) );
		REQUIRES( queryInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL );

		/* Read the Elgamal-encrypted key, recording the position and
		   combined lengths of the MPI pair.  Again, we can't use the length
		   returned by readInteger16Ubits() to determine the overall size 
		   but have to calculate it from the position in the stream */
		status = readInteger16Ubits( stream, NULL, &dummy, MIN_PKCSIZE,
									 CRYPT_MAX_PKCSIZE, 
									 BIGNUM_CHECK_VALUE_PKC );
		if( cryptStatusOK( status ) )
			{
			status = readInteger16Ubits( stream, NULL, &dummy, MIN_PKCSIZE,
										 CRYPT_MAX_PKCSIZE,
										 BIGNUM_CHECK_VALUE_PKC );
			}
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, dataStartPos, 
												  &queryInfo->dataLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		REQUIRES( isIntegerRangeNZ( queryInfo->dataLength ) );
		queryInfo->dataStart = dataStartPos - startPos;
		}

	/* Make sure that we've read the entire object.  This check is necessary 
	   to detect corrupted length values, which can result in reading past 
	   the end of the object */
	status = calculateStreamObjectLength( stream, startPos, &objectSize );
	if( cryptStatusError( status ) || objectSize != queryInfo->size )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writePgpKeytrans( INOUT_PTR STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							 IN_BUFFER( encryptedKeyLength ) \
								const BYTE *encryptedKey, 
							 IN_LENGTH_SHORT_MIN( MIN_PKCSIZE ) \
								const int encryptedKeyLength,
							 STDC_UNUSED const void *auxInfo, 
							 STDC_UNUSED const int auxInfoLength )
	{
	BYTE keyID[ PGP_KEYID_SIZE + 8 ];
	int algorithm, pgpAlgo, status;	/* int vs.enum */

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( encryptedKey, encryptedKeyLength ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( isShortIntegerRangeMin( encryptedKeyLength, MIN_PKCSIZE ) );
	REQUIRES( auxInfo == NULL && auxInfoLength == 0 );

	/* Get the key information */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, keyID, PGP_KEYID_SIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = cryptlibToPgpAlgo( algorithm, &pgpAlgo );
	ENSURES( cryptStatusOK( status ) );

	/* Write the PKE packet */
	pgpWritePacketHeader( stream, PGP_PACKET_PKE,
						  PGP_VERSION_SIZE + PGP_KEYID_SIZE + PGP_ALGOID_SIZE + \
						  ( ( algorithm == CRYPT_ALGO_RSA ) ? \
							sizeofInteger16U( encryptedKeyLength ) : \
							encryptedKeyLength ) );
	sputc( stream, 3 );		/* Version = 3 (OpenPGP) */
	swrite( stream, keyID, PGP_KEYID_SIZE );
	sputc( stream, pgpAlgo );
	return( ( algorithm == CRYPT_ALGO_RSA ) ? \
			writeInteger16Ubits( stream, encryptedKey, encryptedKeyLength ) :
			swrite( stream, encryptedKey, encryptedKeyLength ) );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*					Key Exchange Read/Write Access Function					*
*																			*
****************************************************************************/

typedef struct {
	const KEYEX_TYPE type;
	const READKEYTRANS_FUNCTION function;
	} KEYTRANS_READ_INFO;
static const KEYTRANS_READ_INFO keytransReadTable[] = {
	{ KEYEX_CMS, readCmsKeytrans },
	{ KEYEX_CRYPTLIB, readCryptlibKeytrans },
#ifdef USE_PGP
	{ KEYEX_PGP, readPgpKeytrans },
#endif /* USE_PGP */
	{ KEYEX_NONE, NULL }, { KEYEX_NONE, NULL }
	};

typedef struct {
	const KEYEX_TYPE type;
	const WRITEKEYTRANS_FUNCTION function;
	} KEYTRANS_WRITE_INFO;
static const KEYTRANS_WRITE_INFO keytransWriteTable[] = {
	{ KEYEX_CMS, writeCmsKeytrans },
#ifdef USE_OAEP
	{ KEYEX_CMS_OAEP, writeCmsKeytransOAEP },
#endif /* USE_OAEP */
	{ KEYEX_CRYPTLIB, writeCryptlibKeytrans },
#ifdef USE_OAEP
	{ KEYEX_CRYPTLIB_OAEP, writeCryptlibKeytransOAEP },
#endif /* USE_OAEP */
#ifdef USE_PGP
	{ KEYEX_PGP, writePgpKeytrans },
#endif /* USE_PGP */
	{ KEYEX_NONE, NULL }, { KEYEX_NONE, NULL }
	};

typedef struct {
	const KEYEX_TYPE type;
	const READKEK_FUNCTION function;
	} KEK_READ_INFO;
static const KEK_READ_INFO kekReadTable[] = {
	{ KEYEX_CMS, readCryptlibKek },
	{ KEYEX_CRYPTLIB, readCryptlibKek },
#ifdef USE_PGP
	{ KEYEX_PGP, readPgpKek },
#endif /* USE_PGP */
	{ KEYEX_NONE, NULL }, { KEYEX_NONE, NULL }
	};

typedef struct {
	const KEYEX_TYPE type;
	const WRITEKEK_FUNCTION function;
	} KEK_WRITE_INFO;
static const KEK_WRITE_INFO kekWriteTable[] = {
	{ KEYEX_CMS, writeCryptlibKek },
	{ KEYEX_CRYPTLIB, writeCryptlibKek },
#ifdef USE_PGP
	{ KEYEX_PGP, writePgpKek },
#endif /* USE_PGP */
	{ KEYEX_NONE, NULL }, { KEYEX_NONE, NULL }
	};

CHECK_RETVAL_PTR \
READKEYTRANS_FUNCTION getReadKeytransFunction( IN_ENUM( KEYEX ) \
												const KEYEX_TYPE keyexType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( keyexType, KEYEX ) );

	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( keytransReadTable, \
										KEYTRANS_READ_INFO ) && \
					keytransReadTable[ i ].type != KEYEX_NONE,
				i++ )
		{
		ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
										 FAILSAFE_ARRAYSIZE( keytransReadTable, \
															 KEYTRANS_READ_INFO ) - 1 ) );

		if( keytransReadTable[ i ].type == keyexType )
			return( keytransReadTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( keytransReadTable, KEYTRANS_READ_INFO ) );

	return( NULL );
	}
CHECK_RETVAL_PTR \
WRITEKEYTRANS_FUNCTION getWriteKeytransFunction( IN_ENUM( KEYEX ) \
													const KEYEX_TYPE keyexType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( keyexType, KEYEX ) );

	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( keytransWriteTable, \
										KEYTRANS_WRITE_INFO ) && \
					keytransWriteTable[ i ].type != KEYEX_NONE,
				i++ )
		{
		ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
										 FAILSAFE_ARRAYSIZE( keytransWriteTable, \
															 KEYTRANS_WRITE_INFO ) - 1 ) );

		if( keytransWriteTable[ i ].type == keyexType )
			return( keytransWriteTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( keytransWriteTable, KEYTRANS_WRITE_INFO ) );

	return( NULL );
	}
CHECK_RETVAL_PTR \
READKEK_FUNCTION getReadKekFunction( IN_ENUM( KEYEX ) \
										const KEYEX_TYPE keyexType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( keyexType, KEYEX ) );

	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( kekReadTable, KEK_READ_INFO ) && \
					kekReadTable[ i ].type != KEYEX_NONE,
				i++ )
		{
		ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
										 FAILSAFE_ARRAYSIZE( kekReadTable, \
															 KEK_READ_INFO ) - 1 ) );

		if( kekReadTable[ i ].type == keyexType )
			return( kekReadTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( kekReadTable, KEK_READ_INFO ) );
		
	return( NULL );
	}
CHECK_RETVAL_PTR \
WRITEKEK_FUNCTION getWriteKekFunction( IN_ENUM( KEYEX ) \
										const KEYEX_TYPE keyexType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( keyexType, KEYEX ) );

	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( kekWriteTable, KEK_WRITE_INFO ) && \
					kekWriteTable[ i ].type != KEYEX_NONE,
				i++ )
		{
		ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
										 FAILSAFE_ARRAYSIZE( kekWriteTable, \
															 KEK_WRITE_INFO ) - 1 ) );

		if( kekWriteTable[ i ].type == keyexType )
			return( kekWriteTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( kekWriteTable, KEK_WRITE_INFO ) );

	return( NULL );
	}
#endif /* USE_INT_CMS */
