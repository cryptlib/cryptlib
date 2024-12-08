<<<<<<< HEAD
/****************************************************************************
*																			*
*					cryptlib Signature Mechanism Routines					*
*					  Copyright Peter Gutmann 1992-2018						*
*																			*
****************************************************************************/

#ifdef INC_ALL
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "mech_int.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "mechs/mech_int.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Utility Routines - ASN.1 Replacement				*
*																			*
****************************************************************************/

/* If we're building cryptlib without ASN.1 support then we still need some
   minimal ASN.1 functionality in order to encode and decode MessageDigest
   records in signatures.  The following bare-bones functions provide this
   support, these are extremely cut-down versions of code normally found in 
   asn1_rd.c and asn1_ext.c */

#ifndef USE_INT_ASN1

#define readTag					sgetc
#define writeTag				sputc
#define sizeofShortObject( length )	( 1 + 1 + ( length ) )
#define BER_OCTETSTRING			0x04
#define BER_NULL				0x05
#define BER_OBJECT_IDENTIFIER	0x06
#define BER_SEQUENCE			0x30
#define MIN_OID_SIZE			5
#define MAX_OID_SIZE			32
#define MKOID( value )			( ( const BYTE * ) value )
#define sizeofOID( oid )		( 1 + 1 + byteToInt( oid[ 1 ] ) )
#define sizeofNull()			( 1 + 1 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readRawObject( INOUT_PTR STREAM *stream, 
						  OUT_BUFFER( bufferMaxLength, *bufferLength ) \
								BYTE *buffer,
						  IN_LENGTH_SHORT_MIN( 16 ) \
								const int bufferMaxLength, 
						  OUT_LENGTH_BOUNDED_Z( bufferMaxLength ) \
								int *bufferLength, 
						  IN_TAG_ENCODED const int tag )
	{
	int objectTag, length, offset = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( buffer, bufferMaxLength ) );
	assert( isWritePtr( bufferLength, sizeof( int ) ) );

	REQUIRES_S( isShortIntegerRangeMin( bufferMaxLength, 16 ) );
	REQUIRES_S( tag == BER_SEQUENCE );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( bufferMaxLength ) ); 
	memset( buffer, 0, min( 16, bufferMaxLength ) );
	*bufferLength = 0;

	/* Read the identifier field and length.  We need to remember each byte 
	   as it's read so we can't just call readLengthValue() for the length, 
	   but since we only need to handle lengths that can be encoded in one 
	   byte this isn't a problem */
	status = objectTag = readTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( objectTag != BER_SEQUENCE )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	buffer[ offset++ ] = intToByte( objectTag );
	status = length = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length <= 0 || length > 0x7F )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	buffer[ offset++ ] = intToByte( length );
	if( offset + length > bufferMaxLength )
		return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );

	/* Read in the rest of the data */
	*bufferLength = offset + length;
	return( sread( stream, buffer + offset, length ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeHeader( INOUT_PTR STREAM *stream, 
						IN_TAG_ENCODED const int tag,
						IN_LENGTH_SHORT const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( tag >= BER_OCTETSTRING && tag <= BER_SEQUENCE );
	REQUIRES_S( length >= 0 && length <= 255 );

	writeTag( stream, tag );
	return( sputc( stream, length ) );
	}

CHECK_RETVAL_PTR \
static const BYTE *getOID( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						   IN_LENGTH_HASH const int hashSize )
	{
	REQUIRES_N( isHashAlgo( hashAlgo ) );
	REQUIRES_N( hashSize == 0 || \
				( hashSize >= MIN_HASHSIZE && \
				  hashSize <= CRYPT_MAX_HASHSIZE ) );

	if( hashAlgo == CRYPT_ALGO_SHA1 )
		return( MKOID( "\x06\x05\x2B\x0E\x03\x02\x1A" ) );
	if( hashAlgo != CRYPT_ALGO_SHA2 )
		retIntError_Null();

	switch( hashSize )
		{
		case 0:
		case 32:
			return( MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01" ) );

#ifdef USE_SHA2_EXT
		case 48:
			return( MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02" ) );

		case 64:
			return( MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03" ) );
#endif /* USE_SHA2_EXT */

		default:
			retIntError_Null();
		}

	retIntError_Null();
	}

CHECK_RETVAL_LENGTH_SHORT \
static int sizeofAlgoIDex( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						   IN_RANGE( 0, 999 ) const int subAlgo )
	{
	const BYTE *oid = getOID( hashAlgo, subAlgo );

	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( subAlgo == 0 || \
			  ( subAlgo >= MIN_HASHSIZE && subAlgo <= CRYPT_MAX_HASHSIZE ) );
	REQUIRES( oid != NULL );

	return( sizeofShortObject( sizeofOID( oid ) + sizeofNull() ) );
	}

CHECK_RETVAL_LENGTH_SHORT \
static int sizeofMessageDigest( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo, 
								IN_LENGTH_HASH const int hashSize )
	{
	int algoInfoSize, hashInfoSize;

	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );

	algoInfoSize = sizeofAlgoIDex( hashAlgo, hashSize );
	hashInfoSize = sizeofShortObject( hashSize );
	ENSURES( isShortIntegerRangeMin( algoInfoSize, 8 ) );
	ENSURES( isShortIntegerRangeMin( hashInfoSize, hashSize ) );

	return( sizeofShortObject( algoInfoSize + hashInfoSize ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
static int readMessageDigest( INOUT_PTR STREAM *stream, 
							  OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo,
							  OUT_BUFFER( hashMaxLen, *hashSize ) void *hash, 
							  IN_LENGTH_HASH const int hashMaxLen, 
							  OUT_LENGTH_BOUNDED_Z( hashMaxLen ) int *hashSize )
	{
	BYTE buffer[ 8 + 8 ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( hashAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtrDynamic( hash, hashMaxLen ) );
	assert( isWritePtr( hashSize, sizeof( int ) ) );

	REQUIRES_S( hashMaxLen >= MIN_HASHSIZE && hashMaxLen <= 8192 );

	/* Clear the return values */
	REQUIRES_S( isShortIntegerRangeNZ( hashMaxLen ) ); 
	memset( hash, 0, min( 16, hashMaxLen ) );
	*hashSize = 0;

	/* As used here this function doesn't actually read the message digest 
	   but is merely used as a check for corrupted recovered signature data
	   in order to return a CRYPT_ERROR_BADDATA rather than a generic 
	   CRYPT_ERROR_SIGNATURE.  Because of this we don't need to emulate a 
	   lot of asn1_rd.c code but can just perform a minimal check that things
	   look OK:

		SEQUENCE {
			SEQUENCE {
				algo		OBJECT IDENTIFIER,
				algoParams	ANY DEFINED BY algo
				}
			OCTET STRING hash
			} */
	status = sread( stream, buffer, 8 );
	if( cryptStatusError( status ) ) 
		return( status );
	if( buffer[ 0 ] != BER_SEQUENCE || \
		buffer[ 1 ] < 2 + 3 + 2 + MIN_HASHSIZE || \
		buffer[ 1 ] > 32 + CRYPT_MAX_HASHSIZE )
		return( CRYPT_ERROR_BADDATA );
	if( buffer[ 2 ] != BER_SEQUENCE || \
		buffer[ 3 ] < 3 + 2 + MIN_HASHSIZE || \
		buffer[ 3 ] > 32 + CRYPT_MAX_HASHSIZE )
		return( CRYPT_ERROR_BADDATA );
	if( buffer[ 4 ] != BER_OBJECT_IDENTIFIER || \
		buffer[ 5 ] < MIN_OID_SIZE ||
		buffer[ 5 ] > MAX_OID_SIZE )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeMessageDigest( INOUT_PTR STREAM *stream, 
							   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							   IN_BUFFER( hashSize ) const void *hash, 
							   IN_LENGTH_HASH const int hashSize )
	{
	const BYTE *oid = getOID( hashAlgo, hashSize );
	
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( hash, hashSize ) );

	REQUIRES_S( isHashAlgo( hashAlgo ) );
	REQUIRES_S( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );

	/* writeSequence() */
	writeHeader( stream, BER_SEQUENCE, 
				 sizeofAlgoIDex( hashAlgo, hashSize ) + \
					sizeofShortObject( hashSize ) );

	/* writeAlgoIDex() */
	writeHeader( stream, BER_SEQUENCE, sizeofOID( oid ) + sizeofNull() );
	swrite( stream, oid, sizeofOID( oid ) );
	writeHeader( stream, BER_NULL, 0 );

	/* writeOctetString() */
	writeHeader( stream, BER_OCTETSTRING, hashSize );
	return( swrite( stream, hash, hashSize ) );
	}
#endif /* !USE_INT_ASN1 */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Unlike PKCS #1 encryption there isn't any minimum-height requirement for 
   the PKCS #1 signature padding, however we require a set minimum number of 
   bytes of 0xFF padding because if they're not present then there's 
   something funny going on.  For a given key size we require that all but
   ( 3 bytes PKCS #1 formatting + ( 2 + 15 + 2 ) bytes ASN.1 wrapper + 
     CRYPT_MAX_HASHSIZE bytes hash ) be 0xFF padding */

#define getMinPadBytes( length ) \
		( ( length ) - ( 3 + 19 + CRYPT_MAX_HASHSIZE ) )

/* Encode/decode PKCS #1 signature formatting */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int encodePKCS1( INOUT_PTR STREAM *stream, 
						IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						IN_BUFFER( hashSize ) const void *hash, 
						IN_LENGTH_HASH const int hashSize,
						IN_LENGTH_PKC const int length )
	{
	LOOP_INDEX i;
	int payloadSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( hash, hashSize ) );

	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );
	REQUIRES( length >= MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );

	/* Encode the signature payload using the PKCS #1 format:

		[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] */
	status = payloadSize = sizeofMessageDigest( hashAlgo, hashSize );
	ENSURES( !cryptStatusError( status ) );
	sputc( stream, 0 );
	sputc( stream, 1 );
	LOOP_EXT( i = 0, i < length - ( payloadSize + 3 ), i++,
			  CRYPT_MAX_PKCSIZE )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, length - ( payloadSize + 4 ),
									 CRYPT_MAX_PKCSIZE ) );

		sputc( stream, 0xFF );
		}
	ENSURES( LOOP_BOUND_OK );
	sputc( stream, 0 );

	return( writeMessageDigest( stream, hashAlgo, hash, hashSize ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int decodePKCS1( INOUT_PTR STREAM *stream, 
						IN_LENGTH_PKC const int length )
	{
	LOOP_INDEX i;
	int ch;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( length >= MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );

	/* Decode the payload using the PKCS #1 format:

		[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ]

	   Note that some implementations may have bignum code that zero-
	   truncates the RSA data, which would remove the leading zero from the 
	   PKCS #1 padding and produce a CRYPT_ERROR_BADDATA error.  It's the 
	   responsibility of the lower-level crypto layer to reformat the data 
	   to return a correctly-formatted result if necessary */
	if( sgetc( stream ) != 0 || sgetc( stream ) != 1 )
		{
		/* No [ 0 ][ 1 ] at start */
		return( CRYPT_ERROR_BADDATA );
		}
	LOOP_EXT( ( i = 2, ch = 0xFF ), 
			  ( i < length - MIN_HASHSIZE ) && ( ch == 0xFF ), 
			  i++, CRYPT_MAX_PKCSIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 2, length - ( MIN_HASHSIZE + 1 ),
									 CRYPT_MAX_PKCSIZE + 1 ) );

		ch = sgetc( stream );
		if( cryptStatusError( ch ) )
			return( CRYPT_ERROR_BADDATA );
		}
	ENSURES( LOOP_BOUND_OK );
	if( ch != 0 || i < getMinPadBytes( length ) || \
		i >= length - MIN_HASHSIZE )
		{
		/* No [ 0 ] at end or insufficient/excessive 0xFF padding */
		return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

/* Compare the ASN.1-encoded hash value in the signature with the hash 
   information that we've been given.  We have to be very careful how we 
   handle this because we don't want to allow an attacker to inject random 
   data into gaps in the encoding, which would allow for signature forgery 
   if small exponents are used (although cryptlib disallows any exponents 
   that make this easy).  The obvious approach of using 
   checkObjectEncoding() doesn't work because an attacker can still encode 
   the signature in a form that's syntactically valid ASN.1, just not the 
   correct ASN.1 for a MessageDigest record.  To avoid having to have every 
   function that handles reading the hash value be anal-retentive about 
   every data element that it reads, we take the hash value that we've been 
   given and encode it correctly as a MessageDigest record and then do a 
   straight memcmp() of the encoded form rather than trying to validity-
   check the externally-supplied value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int compareHashInfo( INOUT_PTR STREAM *stream, 
							IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							IN_BUFFER( hashSize ) const void *hash, 
							IN_LENGTH_HASH const int hashSize )
	{
	CRYPT_ALGO_TYPE dummyHashAlgo;
	STREAM mdStream;
	BYTE encodedMD[ 32 + CRYPT_MAX_HASHSIZE + 8 ];
	BYTE recreatedMD[ 32 + CRYPT_MAX_HASHSIZE + 8 ];
	BYTE dummyHashBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int encodedMdLength, recreatedMdLength DUMMY_INIT;
	int dummyHashSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( hash, hashSize ) );

	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );

	/* Read the encoded hash data as a blob and make sure that that's all
	   of the data */
	status = readRawObject( stream, encodedMD, 32 + CRYPT_MAX_HASHSIZE, 
							&encodedMdLength, BER_SEQUENCE );
	if( cryptStatusError( status ) )
		return( status );
	if( sMemDataLeft( stream ) != 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Write the supplied hash information into an encoded blob */
	sMemOpen( &mdStream, recreatedMD, 32 + CRYPT_MAX_HASHSIZE );
	status = writeMessageDigest( &mdStream, hashAlgo, hash, hashSize );
	if( cryptStatusOK( status ) )
		recreatedMdLength = stell( &mdStream );
	sMemDisconnect( &mdStream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( recreatedMdLength ) );

	/* Compare the two encoded blobs.  What to return in this case is a bit
	   complex because if the data that precedes the hash value is corrupted 
	   then we should really return a CRYPT_ERROR_BADDATA, but because we're 
	   doing an encode-and-compare rather than a read/decode, everything 
	   gets converted into the same error code, namely a 
	   CRYPT_ERROR_SIGNATURE.  
	   
	   To deal with this we first perform a redundant read of the encoded 
	   ASN.1 portion, allowing us to return a CRYPT_ERROR_BADDATA in most 
	   cases where the problem is a corrupted/invalid encoding rather than 
	   a generic CRYPT_ERROR_SIGNATURE */
	sMemConnect( &mdStream, encodedMD, encodedMdLength );
	status = readMessageDigest( &mdStream, &dummyHashAlgo, dummyHashBuffer, 
								CRYPT_MAX_HASHSIZE, &dummyHashSize );
	sMemDisconnect( &mdStream );
	if( cryptStatusError( status ) )
		return( status );
	if( encodedMdLength != recreatedMdLength || \
		compareDataConstTime( encodedMD, recreatedMD, 
							  encodedMdLength ) != TRUE )
		status = CRYPT_ERROR_SIGNATURE;

	zeroise( encodedMD, 32 + CRYPT_MAX_HASHSIZE );
	zeroise( recreatedMD, 32 + CRYPT_MAX_HASHSIZE );
	zeroise( dummyHashBuffer, CRYPT_MAX_HASHSIZE );

	return( status );
	}

/* Make sure that the recovered signature data matches the data that we 
   originally signed, performed as a pairwise consistency check on the 
   private-key signing operation.

   Note that this check doesn't work for EdDSA because of braindamage in the
   way it works, see among others section 9.1 of "Attacking Deterministic 
   Signature Schemes Using Fault Attacks" by Poddebniak, Somorovsky, 
   Schinzel, Lochter and Rösler, and "Ed25519 leaks private key if public 
   key is incorrect", https://github.com/jedisct1/libsodium/issues/170/ */

static int checkRecoveredSignature( IN_HANDLE const CRYPT_CONTEXT iSignContext,
									IN_BUFFER( preSigDataLen ) \
										const void *preSigData,
									IN_LENGTH_PKC const int preSigDataLen,
									IN_BUFFER( sigLen ) \
										const void *signature,
									IN_LENGTH_PKC const int sigLen )
	{
	BYTE recoveredSignature[ CRYPT_MAX_PKCSIZE + 8 ];
	int status;

	assert( isReadPtrDynamic( preSigData, preSigDataLen ) );
	assert( isReadPtrDynamic( signature, sigLen ) );

	REQUIRES( preSigDataLen >= MIN_PKCSIZE && \
			  preSigDataLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( sigLen >= MIN_PKCSIZE && sigLen <= CRYPT_MAX_PKCSIZE );

	/* Recover the original signature data, unless we're in the unlikely 
	   situation that the key isn't valid for signature checking */
	REQUIRES( rangeCheck( sigLen, 1, CRYPT_MAX_PKCSIZE ) );
	memcpy( recoveredSignature, signature, sigLen );
	status = krnlSendMessage( iSignContext, IMESSAGE_CTX_SIGCHECK, 
							  recoveredSignature, sigLen );
	if( status == CRYPT_ERROR_PERMISSION || status == CRYPT_ERROR_NOTAVAIL )
		{
		/* The key can't be used for signature checking, there's not much 
		   that we can do.  This typically occurs for limited devices
		   like smart cards accessed via PKCS #11 or TPMs, which can only 
		   do private-key ops.  For native (software) contexts, which is the
		   ones that we care about, anything that can perform a private-key 
		   op can also perform the corresponding public-key op */
		return( CRYPT_OK );
		}
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_FAILED );

	/* Make sure that the recovered data matches the original data */
	if( preSigDataLen != sigLen || \
		compareDataConstTime( preSigData, recoveredSignature, 
							  sigLen ) != TRUE )
		{
		DEBUG_DIAG(( "Signature consistency check failed" ));
		assert( DEBUG_WARN );
		status = CRYPT_ERROR_FAILED;
		}
	zeroise( recoveredSignature, CRYPT_MAX_PKCSIZE );

	return( status );
	}

/****************************************************************************
*																			*
*								Signature Mechanisms 						*
*																			*
****************************************************************************/

/* Perform signing.  There are several variations of this that are handled 
   through common signature mechanism functions */

typedef enum { SIGN_NONE, SIGN_PKCS1, SIGN_TLS, SIGN_LAST } SIGN_TYPE;

/* Perform PKCS #1 signing/sig.checking */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sign( INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo, 
				 IN_ENUM( SIGN ) const SIGN_TYPE type )
	{
	CRYPT_ALGO_TYPE hashAlgo DUMMY_INIT;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_TLS
	BYTE hash2[ CRYPT_MAX_HASHSIZE + 8 ];
#endif /* USE_TLS */
	BYTE preSigData[ CRYPT_MAX_PKCSIZE + 8 ];
	BOOLEAN_INT sideChannelProtectionLevel DUMMY_INIT;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int hashSize, length, status;
#ifdef USE_TLS
	LOOP_INDEX i;
	int hashSize2 DUMMY_INIT; 
#endif /* USE_TLS */

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	REQUIRES( isEnumRange( type, SIGN ) );

	/* Clear return value */
	if( mechanismInfo->signature != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		memset( mechanismInfo->signature, 0,
				mechanismInfo->signatureLength );
		}

	/* Get various algorithm and config parameters */
	status = getPkcAlgoParams( mechanismInfo->signContext, NULL,
							   &length );
	if( cryptStatusOK( status ) )
		{
		status = getHashAlgoParams( mechanismInfo->hashContext,
									&hashAlgo, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, 
								  &sideChannelProtectionLevel,
								  CRYPT_OPTION_MISC_SIDECHANNELPROTECTION );
		}
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( length > MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );
	CFI_CHECK_UPDATE( "getPkcAlgoParams" );

	/* If this is just a length check, we're done */
	if( mechanismInfo->signature == NULL )
		{
		mechanismInfo->signatureLength = length;

		ENSURES( CFI_CHECK_SEQUENCE_1( "getPkcAlgoParams" ) );

		return( CRYPT_OK );
		}

	/* Get the hash data and determine the encoded payload size */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
#ifdef USE_TLS
	if( type == SIGN_TLS )
		{
		setMessageData( &msgData, hash2, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( mechanismInfo->hashContext2,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) )
			return( status );
		hashSize2 = msgData.length;
		}
#endif /* USE_TLS */
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* Encode the payload as required */
	sMemOpen( &stream, mechanismInfo->signature, length );
	switch( type )
		{
		case SIGN_PKCS1:
			status = encodePKCS1( &stream, hashAlgo, hash, hashSize, 
								  length );
			CFI_CHECK_UPDATE( "encodePKCS1" );
			break;

#ifdef USE_TLS
		case SIGN_TLS:
			/* TLS 1.0/1.1 signatures must be MD5 + SHA1 */
			REQUIRES( hashAlgo == CRYPT_ALGO_MD5 );
			REQUIRES( hashSize == 16 && hashSize2 == 20 );

			/* Encode the payload using the PKCS #1 TLS format:

				[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ MD5 hash ][ SHA1 hash ] */
			sputc( &stream, 0 );
			sputc( &stream, 1 );
			LOOP_EXT( i = 0, i < length - ( hashSize + hashSize2 + 3 ), i++,
					  CRYPT_MAX_PKCSIZE )
				{
				ENSURES( LOOP_INVARIANT_EXT( i, 0,
											 length - ( hashSize + hashSize2 + 4 ),
											 CRYPT_MAX_PKCSIZE ) );

				sputc( &stream, 0xFF );
				}
			ENSURES( LOOP_BOUND_OK );
			sputc( &stream, 0 );
			swrite( &stream, hash, hashSize );
			status = swrite( &stream, hash2, hashSize2 );
			CFI_CHECK_UPDATE( "encodePKCS1" );
			break;
#endif /* USE_TLS */

		default:
			retIntError();
		}
	ENSURES( cryptStatusError( status ) || stell( &stream ) == length );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}

	/* If we're using side-channel protection remember a copy of the 
	   signature data for later so that we can check it against the 
	   recovered signature data */
	if( sideChannelProtectionLevel > 0 )
		{
		REQUIRES( rangeCheck( length, 1, CRYPT_MAX_PKCSIZE ) );
		memcpy( preSigData, mechanismInfo->signature, length );
		}

	/* Sign the data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGN, mechanismInfo->signature,
							  length );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}
	mechanismInfo->signatureLength = length;
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGN" );

	/* If we're using side-channel protection check that the signature 
	   verifies */
	if( sideChannelProtectionLevel > 0 )
		{
		status = checkRecoveredSignature( mechanismInfo->signContext, 
										  preSigData, length,
										  mechanismInfo->signature, length );
		zeroise( preSigData, CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) )
			{
			REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
			zeroise( mechanismInfo->signature, 
					 mechanismInfo->signatureLength );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "checkRecoveredSignature" );

	ENSURES( CFI_CHECK_SEQUENCE_5( "getPkcAlgoParams", 
								   "IMESSAGE_GETATTRIBUTE_S", "encodePKCS1", 
								   "IMESSAGE_CTX_SIGN", 
								   "checkRecoveredSignature" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sigcheck( INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo, 
					 IN_ENUM( SIGN ) const SIGN_TYPE type )
	{
	CRYPT_ALGO_TYPE contextHashAlgo DUMMY_INIT;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, hashSize DUMMY_INIT, status;

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );
	
	REQUIRES( isEnumRange( type, SIGN ) );

	/* Get various algorithm parameters */
	status = getPkcAlgoParams( mechanismInfo->signContext, NULL,
							   &length );
	if( cryptStatusOK( status ) )
		{
		status = getHashAlgoParams( mechanismInfo->hashContext,
									&contextHashAlgo, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( mechanismInfo->hashContext, 
								  IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusOK( status ) )
			hashSize = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( length > MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );
	CFI_CHECK_UPDATE( "getPkcAlgoParams" );

	/* Format the input data as required for the signatue check to work */
	status = adjustPKCS1Data( decryptedSignature, CRYPT_MAX_PKCSIZE,
					mechanismInfo->signature, mechanismInfo->signatureLength,
					length );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "adjustPKCS1Data" );

	/* Recover the signed data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGCHECK, decryptedSignature,
							  length );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGCHECK" );

	/* Decode the payload as required */
	sMemConnect( &stream, decryptedSignature, length );
	switch( type )
		{
		case SIGN_PKCS1:
			/* The payload is an ASN.1-encoded hash, process it very 
			   carefully */
			status = decodePKCS1( &stream, length );
			if( cryptStatusError( status ) )
				break;
			status = compareHashInfo( &stream, contextHashAlgo, hash, 
									  hashSize );
			CFI_CHECK_UPDATE( "compareHashInfo" );
			break;

#ifdef USE_TLS
		case SIGN_TLS:
			{
			BYTE hash2[ CRYPT_MAX_HASHSIZE + 8 ];

			REQUIRES( contextHashAlgo == CRYPT_ALGO_MD5 );

			/* The payload is [ MD5 hash ][ SHA1 hash ] */
			status = decodePKCS1( &stream, length );
			if( cryptStatusError( status ) )
				break;
			status = sread( &stream, hash, 16 );
			if( cryptStatusOK( status ) )
				status = sread( &stream, hash2, 20 );
			if( cryptStatusError( status ) )
				break;

			/* Make sure that's all that there is.  This is checked in 
			   compareHashInfo() for standard signatures but we have to 
			   perform the check explicitly for TLS-style signatures */
			if( sMemDataLeft( &stream ) != 0 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}

			/* Make sure that the two hash values match */
			setMessageData( &msgData, hash, 16 );
			status = krnlSendMessage( mechanismInfo->hashContext, 
									  IMESSAGE_COMPARE, &msgData, 
									  MESSAGE_COMPARE_HASH );
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, hash2, 20 );
				status = krnlSendMessage( mechanismInfo->hashContext2, 
										  IMESSAGE_COMPARE, &msgData, 
										  MESSAGE_COMPARE_HASH );
				}
			if( cryptStatusError( status ) )
				{
				/* The compare-hash operations return a generic CRYPT_OK/
				   CRYPT_ERROR, convert it to a more specific error code for 
				   the operation that we're performing */
				status = CRYPT_ERROR_SIGNATURE;
				}

			/* Clean up */
			zeroise( hash2, CRYPT_MAX_HASHSIZE );
			CFI_CHECK_UPDATE( "compareHashInfo" );
			break;
			}
#endif /* USE_TLS */

		default:
			retIntError();
		}
	sMemDisconnect( &stream );

	/* Clean up */
	zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );
	zeroise( hash, CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( CFI_CHECK_SEQUENCE_4( "getPkcAlgoParams", 
								   "adjustPKCS1Data", "IMESSAGE_CTX_SIGCHECK", 
								   "compareHashInfo" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int signPKCS1( STDC_UNUSED void *dummy, 
			   INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED_ARG_OPT( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	return( sign( mechanismInfo, SIGN_PKCS1 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int sigcheckPKCS1( STDC_UNUSED void *dummy, 
				   INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED_ARG_OPT( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	return( sigcheck( mechanismInfo, SIGN_PKCS1 ) );
	}

#ifdef USE_TLS

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int signTLS( STDC_UNUSED void *dummy, 
			 INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED_ARG_OPT( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	return( sign( mechanismInfo, SIGN_TLS ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int sigcheckTLS( STDC_UNUSED void *dummy, 
				 INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED_ARG_OPT( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	return( sigcheck( mechanismInfo, SIGN_TLS ) );
	}
#endif /* USE_TLS */

/****************************************************************************
*																			*
*							PSS Signature Mechanisms						*
*																			*
****************************************************************************/

#ifdef USE_PSS

/* Trim leading bits in the PSS padding to match the RSA modulus size.  The 
   RFC requires that we "set the leftmost 8 * emLen - emBits bits of the 
   leftmost octet in maskedDB to zero", where "emLen = ceil( ( modulus 
   length in bits - 1 ) / 8 )" and emBits = "(intended) length in bits of an 
   encoded message EM", which is probably the same as the modulus length in 
   bits.  The intended effect seems to be to trim the PSS padding to one 
   less than the modulus size in bits.
   
   This serves no cryptographic purpose apart from being incredibly awkward 
   to implement, both because clues on what's required are scattered all 
   over the RFC and because it assumes that we have the length in bits of 
   the modulus available.  This is only present as a low-level internal 
   value that's not accessible externally so we have to extract the public
   key as an SPKI, parse it to find the modulus, and then count the bits in 
   it */

CHECK_RETVAL_LENGTH_SHORT \
static int getKeysizeBits( const CRYPT_CONTEXT iCryptContext )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE pubkeyBuffer[ ( CRYPT_MAX_PKCSIZE * 3 ) + 8 ];
	BYTE nBuffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int nLength, nMSB, bitCount, status;

	REQUIRES( isHandleRangeValid( iCryptContext ) );

	/* Read the public key as an SPKI from the PKC context and extract the n 
	   value from it */
	setMessageData( &msgData, pubkeyBuffer, CRYPT_MAX_PKCSIZE * 3 );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, msgData.data, msgData.length );
	readSequence( &stream, NULL );		/* SEQUENCE { */
	readUniversal( &stream );				/* AlgoID */
	readBitStringHole( &stream, NULL, 64, DEFAULT_TAG );/* BIT STRING */
	readSequence( &stream, NULL );				/* SEQUENCE { */
	status = readInteger( &stream, nBuffer, CRYPT_MAX_PKCSIZE, &nLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Count the number of leading zero bits.  There are all sorts of clever
	   hacks to do this faster than a simple scan, but for eight bits in a
	   non-critical code path it's not worth the complexity */
	nMSB = byteToInt( nBuffer[ 0 ] );
	if( nMSB == 0 )
		{
		/* This shouldn't happen since readInteger() performs leading-zero 
		   truncation */
		assert( DEBUG_WARN );
		bitCount = 8;
		}
	else
		{
		int LOOP_ITERATOR;

		LOOP_SMALL( bitCount = 0, 
					( nMSB & 0x80 ) == 0, 
					( bitCount++, nMSB <<= 1 ) )
			{
			ENSURES( LOOP_INVARIANT_SMALL( bitCount, 0, 7 ) );
			}
		ENSURES( LOOP_BOUND_OK );
		}

	return( ( nLength * 8 ) - bitCount );
	}

#define trimLeadingBits( data, dataLenBytes, pkcSizeBits ) \
		data[ 0 ] &= 0xFF >> ( ( bytesToBits( dataLenBytes ) + 1 ) - ( pkcSizeBits ) )

/* Generate the mHash value by hashing '0x00 x 8 || hash || salt' */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 6 ) ) \
static int generateMHash( OUT_BUFFER_FIXED( mHashMaxLen ) BYTE *mHash, 
						  IN_LENGTH_HASH const int mHashMaxLen, 
						  IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						  IN_BUFFER( hashSize ) const void *hash, 
						  IN_LENGTH_HASH const int hashSize,
						  IN_BUFFER( saltLen ) const void *salt, 
						  IN_LENGTH_PKC const int saltLen )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	BYTE mData[ 8 + CRYPT_MAX_HASHSIZE + CRYPT_MAX_HASHSIZE + 8 ];
	int hashFunctionSize;

	assert( isWritePtrDynamic( mHash, mHashMaxLen ) );
	assert( isReadPtrDynamic( hash, hashSize ) );
	assert( isReadPtrDynamic( salt, saltLen ) );

	REQUIRES( mHashMaxLen >= MIN_HASHSIZE && \
			  mHashMaxLen <= CRYPT_MAX_HASHSIZE );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );
	REQUIRES( saltLen >= MIN_HASHSIZE && saltLen <= CRYPT_MAX_HASHSIZE );

	getHashAtomicParameters( hashAlgo, hashSize, &hashFunctionAtomic, 
							 &hashFunctionSize );
	ENSURES( hashSize == hashFunctionSize );
	ENSURES( 8 + hashSize + saltLen <= \
			 8 + CRYPT_MAX_HASHSIZE + CRYPT_MAX_HASHSIZE );

	/* mHash = hash( 00 x 8 || hash || salt ) */
	memset( mData, 0, 8 );
	REQUIRES( isShortIntegerRangeNZ( hashSize ) ); 
	memcpy( mData + 8, hash, hashSize );
	REQUIRES( isShortIntegerRangeNZ( saltLen ) ); 
	memcpy( mData + 8 + hashSize, salt, saltLen );
	hashFunctionAtomic( mHash, mHashMaxLen, mData, 8 + hashSize + saltLen );

	zeroise( mData, 8 + CRYPT_MAX_HASHSIZE + CRYPT_MAX_HASHSIZE );
	
	return( CRYPT_OK );
	}

/* Generate/recover a PSS data block:

							  Hash( message )
									|
									v
			+-------------------+-------+-------+
	   M' =	|	  00 x 8		| hash	| salt	|---+
			+-------------------+-------+-------+	|
											|		v
											|	  Hash
											v		|
			+---------------------------+-------+	|
	   DB =	|		00 ... 00 01		| salt	|	|
			+---------------------------+-------+	|
							|						|
							v						|
						   xor <------- MGF() ------+
							|						|
							v						v
			+-----------------------------------+------+---+
	   EM =	|#				maskedDB			| mHash|xDB|
			+-----------------------------------+------+---+
							|						|
							v						|
						   xor <------- MGF() ------+---+
							|							|
							v							|
			+---------------------------+-------+		|
	   DB =	|		00 ... 00 01		| salt	|		|
			+---------------------------+-------+		|
											|			|
											|			|
											v			|
			+-------------------+-------+-------+		|
	   M' =	|	  00 x 8		| hash	| salt	|---+	|
			+-------------------+-------+-------+	|	|
													v	|
												 Hash()	|
													|	|
													v	v
												   Compare 
   # = Leading zeroes trimmed */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 6 ) ) \
static int generatePssDataBlock( OUT_BUFFER_FIXED( dataMaxLen ) BYTE *data, 
								 IN_LENGTH_PKC const int dataMaxLen, 
								 IN_BUFFER( saltLen ) const void *salt, 
								 IN_LENGTH_PKC const int saltLen,
								 IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								 IN_BUFFER( hashSize ) const void *hash, 
								 IN_RANGE( MIN_KEYSIZE, CRYPT_MAX_KEYSIZE ) \
									const int hashSize,
								 IN_RANGE( bytesToBits( MIN_PKCSIZE ),
										   bytesToBits( CRYPT_MAX_PKCSIZE ) ) \
									const int pkcSizeBits )
	{
	BYTE mHash[ CRYPT_MAX_HASHSIZE + 8 ], dbMask[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE *db;
	LOOP_INDEX i;
	int dbLen, dbSaltPos, status;

	assert( isWritePtrDynamic( data, dataMaxLen ) );
	assert( isReadPtrDynamic( hash, hashSize ) );
	assert( isReadPtrDynamic( salt, saltLen ) );

	REQUIRES( dataMaxLen >= MIN_PKCSIZE && dataMaxLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( saltLen >= MIN_HASHSIZE && saltLen <= CRYPT_MAX_HASHSIZE );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );
	REQUIRES( hashSize + saltLen + 8 <= dataMaxLen );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( pkcSizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  pkcSizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	REQUIRES( pkcSizeBits > bytesToBits( dataMaxLen ) - 8 && \
			  pkcSizeBits <= bytesToBits( dataMaxLen ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLen ) ); 
	memset( data, 0, min( 16, dataMaxLen ) );

	/* Get the hash of the salted message hash */
	status = generateMHash( mHash, CRYPT_MAX_HASHSIZE, hashAlgo, hash, 
							hashSize, salt, saltLen );
	if( cryptStatusError( status ) )
		return( status );

	/* Calculate the size and position of the various data quantities */
	db = data;
	dbLen = dataMaxLen - ( hashSize + 1 );
	dbSaltPos = dbLen - saltLen;

	ENSURES( dbSaltPos > 16 && \
			 dbSaltPos < CRYPT_MAX_PKCSIZE - ( MIN_HASHSIZE * 2 ) );
	ENSURES( dbSaltPos + saltLen + hashSize + 1 == dataMaxLen );

	/* dbMask = MGF1( hash, hashSize ) */
	status = mgf1( dbMask, dataMaxLen, mHash, hashSize, hashAlgo, hashSize );
	ENSURES( cryptStatusOK( status ) );	/* Can only be an internal error */

	/* db = 00 .. 00 01 || salt */
	REQUIRES( boundsCheck( dbSaltPos, saltLen, dbLen ) );
	memset( db, 0, dbSaltPos );
	db[ dbSaltPos - 1 ] = 0x01;
	REQUIRES( isShortIntegerRangeNZ( saltLen ) ); 
	memcpy( db + dbSaltPos, salt, saltLen );

	/* db = db ^ dbMask */
	LOOP_EXT( i = 0, i < dbLen, i++, CRYPT_MAX_PKCSIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, dbLen - 1,
									 CRYPT_MAX_PKCSIZE + 1 ) );

		db[ i ] ^= dbMask[ i ];
		}
	ENSURES( LOOP_BOUND_OK );

	/* data = db || mHash || 0xBC */
	REQUIRES( boundsCheck( dbLen, hashSize + 1, dataMaxLen ) );
	memcpy( data + dbLen, mHash, hashSize );
	data[ dbLen + hashSize ] = 0xBC;

	/* Trim the data block down to size */
	trimLeadingBits( data, dataMaxLen, pkcSizeBits );

	zeroise( mHash, CRYPT_MAX_HASHSIZE );
	zeroise( dbMask, CRYPT_MAX_PKCSIZE );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 7 ) ) \
static int recoverPssDataBlock( OUT_BUFFER( mHashMaxLen, *mHashLen ) \
									BYTE *mHash, 
								IN_LENGTH_HASH const int mHashMaxLen, 
								OUT_LENGTH_BOUNDED_Z( mHashMaxLen ) \
									int *mHashLen, 
								IN_BUFFER( dataLen ) const void *data, 
								IN_LENGTH_PKC const int dataLen, 
								IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								IN_BUFFER( hashSize) const void *hash, 
								IN_LENGTH_HASH const int hashSize,
								IN_RANGE( bytesToBits( MIN_PKCSIZE ),
										  bytesToBits( CRYPT_MAX_PKCSIZE ) ) \
									const int pkcSizeBits )
	{
	BYTE db[ CRYPT_MAX_PKCSIZE + 8 ], dbMask[ CRYPT_MAX_PKCSIZE + 8 ];
	LOOP_INDEX i;
	int dbLen, padLen, status;

	assert( isWritePtrDynamic( mHash, mHashMaxLen ) );
	assert( isWritePtr( mHashLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( data, dataLen ) );
	assert( isReadPtrDynamic( hash, hashSize ) );

	REQUIRES( mHashMaxLen >= MIN_HASHSIZE && mHashMaxLen >= hashSize && \
			  mHashMaxLen <= CRYPT_MAX_HASHSIZE );
	REQUIRES( dataLen >= MIN_PKCSIZE && dataLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize * 2 < dataLen && \
			  hashSize <= CRYPT_MAX_HASHSIZE );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( pkcSizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  pkcSizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	REQUIRES( pkcSizeBits > bytesToBits( dataLen ) - 8 && \
			  pkcSizeBits <= bytesToBits( dataLen ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( mHashMaxLen ) ); 
	memset( mHash, 0, min( 16, mHashMaxLen ) );
	*mHashLen = 0;

	/* Clear DB.  This is required because when we trim the leading bits of 
	   db ^ dbMask we're working on a subset of the input data, so that 
	   while the full length of the input data is dataLen bytes the amount 
	   of valid data in db is only dbLen bytes.  To deal with this we could
	   adjust both dbLen and pkcSizeBits by bytesToBits( dataLen - dbLen )
	   but it's easier to just set all bytes of DB to zero, thus making the
	   entire range up to dataLen valid */
	memset( db, 0, CRYPT_MAX_PKCSIZE );

	/* Calculate the size and position of the various data quantities */
	dbLen = dataLen - ( hashSize + 1 );
	padLen = dbLen - hashSize;

	ENSURES( dbLen + hashSize + 1 == dataLen );
	ENSURES( padLen > 16 && padLen + ( 2 * hashSize ) + 1 == dataLen && \
			 padLen < CRYPT_MAX_PKCSIZE - ( MIN_HASHSIZE * 2 ) );

	/* dbMask = MGF1( hash, hashSize ) */
	status = mgf1( dbMask, dbLen, ( BYTE * ) data + dbLen, hashSize, 
				   hashAlgo, hashSize );
	ENSURES( cryptStatusOK( status ) );	/* Can only be an internal error */

	/* db = db ^ dbMask */
	REQUIRES( rangeCheck( dbLen, 1, CRYPT_MAX_PKCSIZE ) );
	memcpy( db, data, dbLen );
	LOOP_EXT( i = 0, i < dbLen, i++, CRYPT_MAX_PKCSIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, dbLen - 1,
									 CRYPT_MAX_PKCSIZE + 1 ) );

		db[ i ] ^= dbMask[ i ];
		}
	ENSURES( LOOP_BOUND_OK );

	/* Trim the data block down to size */
	trimLeadingBits( db, dataLen, pkcSizeBits );

	/* The block is now: 

		[ 0x00 padding ][ 0x01 ][ salt ][ mHash ][ 0xDB ]
		 ------------- DB -------------  ---- data -----

	   Check that the constant parts are as expected */
	REQUIRES( isShortIntegerRangeNZ( padLen ) ); 
	memset( dbMask, 0, padLen );
	dbMask[ padLen - 1 ] = 0x01;
	if( memcmp( db, dbMask, padLen ) || \
		( ( const BYTE * ) data )[ dataLen - 1 ] != 0xBC )
		return( CRYPT_ERROR_BADDATA );

	/* Now that we've got the salt, we can regenerate mHash and return it to 
	   the caller to verify against the copy of mHash stored in the 
	   signature */
	status = generateMHash( mHash, mHashMaxLen, hashAlgo, hash, hashSize,
						    db + padLen, hashSize );
	if( cryptStatusOK( status ) )
		*mHashLen = hashSize;
	return( status );
	}

/* Perform PSS signing/sig.checking */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int signPSS( STDC_UNUSED void *dummy, 
			 INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	CRYPT_ALGO_TYPE hashAlgo DUMMY_INIT;
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], salt[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE preSigData[ CRYPT_MAX_PKCSIZE + 8 ];
	BOOLEAN_INT sideChannelProtectionLevel DUMMY_INIT;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, keySizeBits DUMMY_INIT, hashSize, status;

	UNUSED_ARG_OPT( dummy );
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	/* Clear return value */
	if( mechanismInfo->signature != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		memset( mechanismInfo->signature, 0,
				mechanismInfo->signatureLength );
		}

	/* Get various algorithm and config parameters */
	status = getPkcAlgoParams( mechanismInfo->signContext, NULL,
							   &length );
	if( cryptStatusOK( status ) )
		{
		status = getHashAlgoParams( mechanismInfo->hashContext,
									&hashAlgo, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, 
								  &sideChannelProtectionLevel,
								  CRYPT_OPTION_MISC_SIDECHANNELPROTECTION );
		}
	if( cryptStatusOK( status ) )
		status = keySizeBits = getKeysizeBits( mechanismInfo->signContext );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( length > MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );
	CFI_CHECK_UPDATE( "getPkcAlgoParams" );

	/* If this is just a length check, we're done */
	if( mechanismInfo->signature == NULL )
		{
		mechanismInfo->signatureLength = length;

		ENSURES( CFI_CHECK_SEQUENCE_1( "getPkcAlgoParams" ) );

		return( CRYPT_OK );
		}

	/* Get the hash data and salt.  The salt data doesn't have to be 
	   cryptographically strong, in fact technically it doesn't even need to 
	   be random since this just changes the security level to that of a
	   deterministic alternative like full-domain hashing (FDH), so we use
	   the nonce RNG to get the value */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
	setMessageData( &msgData, salt, hashSize );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* Encode the payload */
	status = generatePssDataBlock( mechanismInfo->signature, length, 
								   salt, hashSize, hashAlgo, hash, hashSize, 
								   keySizeBits );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}
	CFI_CHECK_UPDATE( "generatePssDataBlock" );

	/* If we're using side-channel protection remember a copy of the 
	   signature data for later so that we can check it against the 
	   recovered signature data */
	if( sideChannelProtectionLevel > 0 )
		{
		REQUIRES( rangeCheck( length, 1, CRYPT_MAX_PKCSIZE ) );
		memcpy( preSigData, mechanismInfo->signature, length );
		}

	/* Sign the data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGN, mechanismInfo->signature,
							  length );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}
	mechanismInfo->signatureLength = length;
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGN" );

	/* If we're using side-channel protection check that the signature 
	   verifies */
	if( sideChannelProtectionLevel > 0 )
		{
		status = checkRecoveredSignature( mechanismInfo->signContext, 
										  preSigData, length,
										  mechanismInfo->signature, length );
		zeroise( preSigData, CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) )
			{
			REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
			zeroise( mechanismInfo->signature, 
					 mechanismInfo->signatureLength );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "checkRecoveredSignature" );

	ENSURES( CFI_CHECK_SEQUENCE_5( "getPkcAlgoParams", 
								   "IMESSAGE_GETATTRIBUTE_S", 
								   "generatePssDataBlock", 
								   "IMESSAGE_CTX_SIGN", 
								   "checkRecoveredSignature" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int sigcheckPSS( STDC_UNUSED void *dummy, 
				 INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	CRYPT_ALGO_TYPE hashAlgo DUMMY_INIT;
	MESSAGE_DATA msgData;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ], mHash[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, keySizeBits DUMMY_INIT, hashSize DUMMY_INIT, mHashLength;
	int status;

	UNUSED_ARG_OPT( dummy );
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );
	
	/* Get various algorithm parameters */
	status = getPkcAlgoParams( mechanismInfo->signContext, NULL,
							   &length );
	if( cryptStatusOK( status ) )
		{
		status = getHashAlgoParams( mechanismInfo->hashContext,
									&hashAlgo, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( mechanismInfo->hashContext, 
								  IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusOK( status ) )
			hashSize = msgData.length;
		}
	if( cryptStatusOK( status ) )
		status = keySizeBits = getKeysizeBits( mechanismInfo->signContext );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( length > MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );
	CFI_CHECK_UPDATE( "getPkcAlgoParams" );

	/* Format the input data as required for the signatue check to work */
	status = adjustPKCS1Data( decryptedSignature, CRYPT_MAX_PKCSIZE,
					mechanismInfo->signature, mechanismInfo->signatureLength,
					length );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "adjustPKCS1Data" );

	/* Recover the signed data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGCHECK, decryptedSignature,
							  length );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGCHECK" );

	/* Decode the payload and compare the calculated mHash value with the 
	   value in the signature data */
	status = recoverPssDataBlock( mHash, CRYPT_MAX_HASHSIZE, 
								  &mHashLength, decryptedSignature, length, 
								  hashAlgo, hash, hashSize, 
								  keySizeBits );
	if( cryptStatusError( status ) )
		{
		zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );
		zeroise( hash, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	CFI_CHECK_UPDATE( "recoverPssDataBlock" );
	if( mHashLength != hashSize || \
		compareDataConstTime( decryptedSignature + length - ( hashSize + 1 ), 
							   mHash, mHashLength ) != TRUE )
		{
		/* Exit after the cleanup step */
		status = CRYPT_ERROR_SIGNATURE;
		}

	/* Clean up */
	zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );
	zeroise( hash, CRYPT_MAX_HASHSIZE );
	zeroise( mHash, CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( CFI_CHECK_SEQUENCE_4( "getPkcAlgoParams", 
								   "adjustPKCS1Data", "IMESSAGE_CTX_SIGCHECK", 
								   "recoverPssDataBlock" ) );

	return( CRYPT_OK );
	}
#endif /* USE_PSS */

/****************************************************************************
*																			*
*							Signature Self-test Functions 					*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Test signature mechanisms */

typedef enum {
	TEST_NONE,				/* No data block manipulation type */
	TEST_NORMAL,			/* Standard test */
	TEST_CORRUPT_START,		/* Corrupt starting byte */
	TEST_CORRUPT_BLOCKTYPE,	/* Corrupt block type */
	TEST_CORRUPT_PADDING,	/* Corrupt padding data */
	TEST_CORRUPT_END,		/* Corrupt ending byte */
	TEST_CORRUPT_OID,		/* Corrupt encoded OID data */
	TEST_CORRUPT_HASH,		/* Corrupt hash value */
#ifdef USE_PSS
	TEST_CORRUPT_MASKEDDB,	/* Corrupt masked DB */
	TEST_CORRUPT_SALT,		/* Corrupt PSS salt */
	TEST_CORRUPT_MHASH,		/* Corrupt PSS mHash */
	TEST_CORRUPT_BC,		/* Corrupt PSS 0xBC value */
#endif /* USE_PSS */
	TEST_LAST				/* Last possible manipulation type */
	} TEST_TYPE;

static void manipulateDataBlock( INOUT_BUFFER_FIXED( length ) BYTE *buffer,
								 IN_LENGTH_PKC const int length,
								 IN_LENGTH_PKC const int payloadStart,
								 IN_ENUM( TEST ) const TEST_TYPE testType )
	{
	assert( isWritePtr( buffer, length ) );

	REQUIRES_V( length >= 128 && length <= CRYPT_MAX_PKCSIZE );
	REQUIRES_V( payloadStart >= 20 && payloadStart < length );
	REQUIRES_V( isEnumRange( testType, TEST ) );

	switch( testType )
		{
		case TEST_NORMAL:
			/* Standard test */
			break;

		case TEST_CORRUPT_START:
			/* Corrupt the PKCS #1 leading zero */
			buffer[ 0 ]++;
			break;

		case TEST_CORRUPT_BLOCKTYPE:
			/* Corrupt the PKCS #1 block type */
			buffer[ 1 ]++;
			break;

		case TEST_CORRUPT_PADDING:
			/* Corrupt the PKCS #1 padding.  This is already at 0xFF so we 
			   decrement rather than increment the value */
			assert( buffer[ 30 ] == 0xFF );
			buffer[ 30 ]--;
			break;

		case TEST_CORRUPT_END:
			/* Corrupt the PKCS #1 trailing zero.  The location is a bit 
			   complex to evaluate since the hash value is preceded by a
			   variable-length OID, the following are the values for SHA-2
			   and SHA-1.  Note that the SHA-2 value works for all sizes of
			   the hash since the OIDs are the same size */
#if defined( DEFAULT_ALGO_SHA2 )
			assert( buffer[ payloadStart - 20 ] == 0 );
			buffer[ payloadStart - 20 ]++;
#elif defined( DEFAULT_ALGO_SHA1 )
			assert( buffer[ payloadStart - 14 ] == 0 );
			buffer[ payloadStart - 14 ]++;
#else
	#error Need to set magic value for default hash algorithm in PKCS #1 test
#endif /* DEFAULT_ALGO_xxx */
			break;

		case TEST_CORRUPT_OID:
			/* Corrupt the OID/ASN.1 data that precedes the hash value, see 
			   above for the magic values used.  For SHA-2 we corrupt the '3'
			   in ( 2 16 840 1 101 3 4 2 1 ) */
#ifdef DEFAULT_ALGO_SHA2
			assert( buffer[ payloadStart - 8 ] == 0x03 );
			buffer[ payloadStart - 6 ]++;
#else
			buffer[ payloadStart - 10 ]++;
#endif /* DEFAULT_ALGO_xxx */
			break;

		case TEST_CORRUPT_HASH:
			/* Corrupt the hash value.  This is preceded by 0x04 0x20 as the 
			   OCTET STRING wrapper */
			assert( buffer[ payloadStart - 2 ] == 0x04 );
			buffer[ payloadStart + 8 ]++;
			break;

#ifdef USE_PSS
		case TEST_CORRUPT_MASKEDDB:
			/* Corrupt the masked DB, specifically the portion corresponding 
			   to the padding */
			buffer[ 30 ]--;
			break;

		case TEST_CORRUPT_SALT:
			/* Corrupt the salt value */
			buffer[ payloadStart + 8 ]++;
			break;

		case TEST_CORRUPT_MHASH:
			/* Corrupt the mHash value.  This is dependent on the hash 
			   algorithm type, the following is the value for SHA-1 */
			buffer[ payloadStart + 20 + 8 ]++;
			break;

		case TEST_CORRUPT_BC:
			/* Corrupt the 0xBC byte at the end of the data */
			assert( buffer[ length - 1 ] == 0xBC );
			buffer[ length - 1 ]++;
			break;
#endif /* USE_PSS */

		default:
			retIntError_Void();
		}
	}

CHECK_RETVAL \
static int testPKCS1( IN_ENUM( TEST ) const TEST_TYPE testType )
	{
#if CRYPT_MAX_PKCSIZE >= bitsToBytes( 2048 )
	/* SHA-256 test value from FIPS 180-2 */
	const BYTE hash[] = \
		{ 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 
		  0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24, 
		  0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 
		  0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55 };
 	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	STREAM stream;
	int length = 256, status;

	static_assert( CRYPT_MAX_PKCSIZE >= 256, "CRYPT_MAX_PKCSIZE size" );

	REQUIRES( isEnumRange( testType, TEST ) );

	/* Create the PKCS #1 signature block */
	sMemOpen( &stream, buffer, length );
	status = encodePKCS1( &stream, DEFAULT_HASH_ALGO, hash, 
						  DEFAULT_HASH_PARAM, length );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Manipulate the data as required */
	manipulateDataBlock( buffer, length, length - DEFAULT_HASH_PARAM, 
						 testType );

	/* Verify the signature block and make sure that we got back what we 
	   put in */
	sMemConnect( &stream, buffer, length );
	status = decodePKCS1( &stream, length );
	if( cryptStatusError( status ) )
		return( status );
	return( compareHashInfo( &stream, DEFAULT_HASH_ALGO, hash, 
							 DEFAULT_HASH_PARAM ) );
#else
  #if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
	#pragma message( "  Skipping PKCS #1 self-test since CRYPT_MAX_PKCSIZE < 2048 bits." )
  #endif /* Notify skipping of PKCS #1 test */
	return( CRYPT_OK );
#endif /* 2048-bit bignums */
	}

#ifdef USE_PSS

CHECK_RETVAL \
static int testPSS( IN_ENUM( TEST ) const TEST_TYPE testType )
	{
	#define PSS_BUFSIZE		256
	/* PSS test data from NIST RSA-PSS test vectors */
	static const BYTE message[] = \
			{ 0x37, 0xB6, 0x6A, 0xE0, 0x44, 0x58, 0x43, 0x35, 
			  0x3D, 0x47, 0xEC, 0xB0, 0xB4, 0xFD, 0x14, 0xC1, 
			  0x10, 0xE6, 0x2D, 0x6A };
	static const BYTE sha1Salt[] = \
			{ 0xE3, 0xB5, 0xD5, 0xD0, 0x02, 0xC1, 0xBC, 0xE5, 
			  0x0C, 0x2B, 0x65, 0xEF, 0x88, 0xA1, 0x88, 0xD8, 
			  0x3B, 0xCE, 0x7E, 0x61 };
	static const BYTE sha1EM[] = \
			{ 0x06, 0xE4, 0x67, 0x2E, 0x83, 0x6A, 0xD1, 0x21, 
			  0xBA, 0x24, 0x4B, 0xED, 0x65, 0x76, 0xB8, 0x67,
			  0xD9, 0xA4, 0x47, 0xC2, 0x8A, 0x6E, 0x66, 0xA5, 
			  0xB8, 0x7D, 0xEE, 0x7F, 0xBC, 0x7E, 0x65, 0xAF,
			  0x50, 0x57, 0xF8, 0x6F, 0xAE, 0x89, 0x84, 0xD9, 
			  0xBA, 0x7F, 0x96, 0x9A, 0xD6, 0xFE, 0x02, 0xA4,
			  0xD7, 0x5F, 0x74, 0x45, 0xFE, 0xFD, 0xD8, 0x5B, 
			  0x6D, 0x3A, 0x47, 0x7C, 0x28, 0xD2, 0x4B, 0xA1,
			  0xE3, 0x75, 0x6F, 0x79, 0x2D, 0xD1, 0xDC, 0xE8, 
			  0xCA, 0x94, 0x44, 0x0E, 0xCB, 0x52, 0x79, 0xEC,
			  0xD3, 0x18, 0x3A, 0x31, 0x1F, 0xC8, 0x96, 0xDA, 
			  0x1C, 0xB3, 0x93, 0x11, 0xAF, 0x37, 0xEA, 0x4A,
			  0x75, 0xE2, 0x4B, 0xDB, 0xFD, 0x5C, 0x1D, 0xA0, 
			  0xDE, 0x7C, 0xEC, 0xDF, 0x1A, 0x89, 0x6F, 0x9D,
			  0x8B, 0xC8, 0x16, 0xD9, 0x7C, 0xD7, 0xA2, 0xC4, 
			  0x3B, 0xAD, 0x54, 0x6F, 0xBE, 0x8C, 0xFE, 0xBC };
	/* Arbitrary values for non-SHA1 tests, these being the first two hash
	   values from the SHA2-512 self-test */
	static const BYTE salt64[] = \
			{ 0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD, 
			  0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6D, 0x80, 0x07, 
			  0xD6, 0x20, 0xE4, 0x05, 0x0B, 0x57, 0x15, 0xDC, 
			  0x83, 0xF4, 0xA9, 0x21, 0xD3, 0x6C, 0xE9, 0xCE, 
			  0x47, 0xD0, 0xD1, 0x3C, 0x5D, 0x85, 0xF2, 0xB0, 
			  0xFF, 0x83, 0x18, 0xD2, 0x87, 0x7E, 0xEC, 0x2F, 
			  0x63, 0xB9, 0x31, 0xBD, 0x47, 0x41, 0x7A, 0x81, 
			  0xA5, 0x38, 0x32, 0x7A, 0xF9, 0x27, 0xDA, 0x3E };
	static const BYTE message64[] = \
			{ 0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
			  0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
			  0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
			  0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
			  0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
			  0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
			  0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
			  0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F };
	BYTE buffer[ PSS_BUFSIZE + 8 ], outMessage[ CRYPT_MAX_HASHSIZE + 8 ];
	int outLen DUMMY_INIT, status;

	REQUIRES( isEnumRange( testType, TEST ) );

	/* SHA-1.  We restrict the data size to a fixed 128 bytes rather than 
	   the full PSS_BUFSIZE for this test because the NIST test vectors also 
	   use 128 bytes */
	memset( buffer, '*', PSS_BUFSIZE );
	status = generatePssDataBlock( buffer, 128, sha1Salt, 20, 
								   CRYPT_ALGO_SHA1, message, 20, 1021 );
	if( cryptStatusOK( status ) && memcmp( buffer, sha1EM, 128 ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusOK( status ) )
		{
		manipulateDataBlock( buffer, 128, 128 - ( 20 + 20 + 1 ), testType );
		status = recoverPssDataBlock( outMessage, CRYPT_MAX_HASHSIZE, 
									  &outLen, buffer, 128, 
									  CRYPT_ALGO_SHA1, message, 20, 1021 );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( outLen != 20 || \
		memcmp( buffer + 128 - ( 20 + 1 ), outMessage, outLen ) )
		return( CRYPT_ERROR_SIGNATURE );

	/* SHA-2 */
	memset( buffer, '*', PSS_BUFSIZE );
	status = generatePssDataBlock( buffer, PSS_BUFSIZE, salt64, 32, 
								   CRYPT_ALGO_SHA2, message64, 32, 2045 );
	if( cryptStatusOK( status ) )
		{
		manipulateDataBlock( buffer, PSS_BUFSIZE, 
							 PSS_BUFSIZE - ( 32 + 32 + 1 ), testType );
		status = recoverPssDataBlock( outMessage, CRYPT_MAX_HASHSIZE, 
									  &outLen, buffer, PSS_BUFSIZE, 
									  CRYPT_ALGO_SHA2, message64, 32, 2045 );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( outLen != 32 || \
		memcmp( buffer + PSS_BUFSIZE - ( 32 + 1 ), outMessage, outLen ) )
		return( CRYPT_ERROR_SIGNATURE );

	/* SHA-2 512-bit */
#ifdef USE_SHA2_EXT
	memset( buffer, '*', PSS_BUFSIZE );
	status = generatePssDataBlock( buffer, PSS_BUFSIZE, salt64, 64, 
								   CRYPT_ALGO_SHA2, message64, 64, 2045 );
	if( cryptStatusOK( status ) )
		{
		manipulateDataBlock( buffer, PSS_BUFSIZE, 
							 PSS_BUFSIZE - ( 64 + 64 + 1 ), testType );
		status = recoverPssDataBlock( outMessage, CRYPT_MAX_HASHSIZE, 
									  &outLen, buffer, PSS_BUFSIZE, 
									  CRYPT_ALGO_SHA2, message64, 64, 2045 );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( outLen != 64 || \
		memcmp( buffer + PSS_BUFSIZE - ( 64 + 1 ), outMessage, outLen ) )
		return( CRYPT_ERROR_SIGNATURE );
#endif /* USE_SHA2_EXT */

	return( CRYPT_OK );
	}
#endif /* USE_PSS */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int signSelftest( STDC_UNUSED void *dummy, 
				  STDC_UNUSED MECHANISM_SIGN_INFO *mechanismInfo )
	{
	int status;

	UNUSED_ARG_OPT( dummy );
	UNUSED_ARG( mechanismInfo );

	status = testPKCS1( TEST_NORMAL );
	if( cryptStatusError( status ) )
		{
		DEBUG_PRINT(( "Mechanism self-test for PKCS1 sig/sigcheck "
					  "mechanism failed.\n" ));
		return( status );
		}
	status = testPKCS1( TEST_CORRUPT_START );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPKCS1( TEST_CORRUPT_BLOCKTYPE );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPKCS1( TEST_CORRUPT_PADDING );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPKCS1( TEST_CORRUPT_END );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPKCS1( TEST_CORRUPT_OID );
	else
		status = CRYPT_OK;	/* Force following tests to fail */
	if( status == CRYPT_ERROR_NOTAVAIL )
		status = testPKCS1( TEST_CORRUPT_HASH );
	else
		status = CRYPT_OK;	/* Force following tests to fail */
	if( status != CRYPT_ERROR_SIGNATURE )
		{
		DEBUG_PRINT(( "Data corruption self-test for PKCS1 sig/sigcheck "
					  "mechanism failed.\n" ));
		return( status );
		}
#ifdef USE_PSS
	status = testPSS( TEST_NORMAL );
	if( cryptStatusError( status ) )
		{
		DEBUG_PRINT(( "Mechanism self-test for PSS sig/sigcheck "
					  "mechanism failed.\n" ));
		return( status );
		}
	status = testPSS( TEST_CORRUPT_START );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPSS( TEST_CORRUPT_MASKEDDB );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPSS( TEST_CORRUPT_MHASH );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPSS( TEST_CORRUPT_BC );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPSS( TEST_CORRUPT_SALT );
	else
		status = CRYPT_OK;	/* Force following tests to fail */
	if( status != CRYPT_ERROR_SIGNATURE )
		{
		DEBUG_PRINT(( "Data corruption self-test for PSS sig/sigcheck "
					  "mechanism failed.\n" ));
		return( status );
		}
#endif /* USE_PSS */

	return( CRYPT_OK );
	}
#endif /* CONFIG_NO_SELFTEST */
=======
/****************************************************************************
*																			*
*					cryptlib Signature Mechanism Routines					*
*					  Copyright Peter Gutmann 1992-2018						*
*																			*
****************************************************************************/

#ifdef INC_ALL
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "mech_int.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "mechs/mech_int.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Utility Routines - ASN.1 Replacement				*
*																			*
****************************************************************************/

/* If we're building cryptlib without ASN.1 support then we still need some
   minimal ASN.1 functionality in order to encode and decode MessageDigest
   records in signatures.  The following bare-bones functions provide this
   support, these are extremely cut-down versions of code normally found in 
   asn1_rd.c and asn1_ext.c */

#ifndef USE_INT_ASN1

#define readTag					sgetc
#define writeTag				sputc
#define sizeofShortObject( length )	( 1 + 1 + ( length ) )
#define BER_OCTETSTRING			0x04
#define BER_NULL				0x05
#define BER_OBJECT_IDENTIFIER	0x06
#define BER_SEQUENCE			0x30
#define MIN_OID_SIZE			5
#define MAX_OID_SIZE			32
#define MKOID( value )			( ( const BYTE * ) value )
#define sizeofOID( oid )		( 1 + 1 + byteToInt( oid[ 1 ] ) )
#define sizeofNull()			( 1 + 1 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readRawObject( INOUT_PTR STREAM *stream, 
						  OUT_BUFFER( bufferMaxLength, *bufferLength ) \
								BYTE *buffer,
						  IN_LENGTH_SHORT_MIN( 16 ) \
								const int bufferMaxLength, 
						  OUT_LENGTH_BOUNDED_Z( bufferMaxLength ) \
								int *bufferLength, 
						  IN_TAG_ENCODED const int tag )
	{
	int objectTag, length, offset = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( buffer, bufferMaxLength ) );
	assert( isWritePtr( bufferLength, sizeof( int ) ) );

	REQUIRES_S( isShortIntegerRangeMin( bufferMaxLength, 16 ) );
	REQUIRES_S( tag == BER_SEQUENCE );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( bufferMaxLength ) ); 
	memset( buffer, 0, min( 16, bufferMaxLength ) );
	*bufferLength = 0;

	/* Read the identifier field and length.  We need to remember each byte 
	   as it's read so we can't just call readLengthValue() for the length, 
	   but since we only need to handle lengths that can be encoded in one 
	   byte this isn't a problem */
	status = objectTag = readTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( objectTag != BER_SEQUENCE )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	buffer[ offset++ ] = intToByte( objectTag );
	status = length = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length <= 0 || length > 0x7F )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	buffer[ offset++ ] = intToByte( length );
	if( offset + length > bufferMaxLength )
		return( sSetError( stream, CRYPT_ERROR_OVERFLOW ) );

	/* Read in the rest of the data */
	*bufferLength = offset + length;
	return( sread( stream, buffer + offset, length ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeHeader( INOUT_PTR STREAM *stream, 
						IN_TAG_ENCODED const int tag,
						IN_LENGTH_SHORT const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( tag >= BER_OCTETSTRING && tag <= BER_SEQUENCE );
	REQUIRES_S( length >= 0 && length <= 255 );

	writeTag( stream, tag );
	return( sputc( stream, length ) );
	}

CHECK_RETVAL_PTR \
static const BYTE *getOID( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						   IN_LENGTH_HASH const int hashSize )
	{
	REQUIRES_N( isHashAlgo( hashAlgo ) );
	REQUIRES_N( hashSize == 0 || \
				( hashSize >= MIN_HASHSIZE && \
				  hashSize <= CRYPT_MAX_HASHSIZE ) );

	if( hashAlgo == CRYPT_ALGO_SHA1 )
		return( MKOID( "\x06\x05\x2B\x0E\x03\x02\x1A" ) );
	if( hashAlgo != CRYPT_ALGO_SHA2 )
		retIntError_Null();

	switch( hashSize )
		{
		case 0:
		case 32:
			return( MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01" ) );

#ifdef USE_SHA2_EXT
		case 48:
			return( MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02" ) );

		case 64:
			return( MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03" ) );
#endif /* USE_SHA2_EXT */

		default:
			retIntError_Null();
		}

	retIntError_Null();
	}

CHECK_RETVAL_LENGTH_SHORT \
static int sizeofAlgoIDex( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						   IN_RANGE( 0, 999 ) const int subAlgo )
	{
	const BYTE *oid = getOID( hashAlgo, subAlgo );

	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( subAlgo == 0 || \
			  ( subAlgo >= MIN_HASHSIZE && subAlgo <= CRYPT_MAX_HASHSIZE ) );
	REQUIRES( oid != NULL );

	return( sizeofShortObject( sizeofOID( oid ) + sizeofNull() ) );
	}

CHECK_RETVAL_LENGTH_SHORT \
static int sizeofMessageDigest( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo, 
								IN_LENGTH_HASH const int hashSize )
	{
	int algoInfoSize, hashInfoSize;

	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );

	algoInfoSize = sizeofAlgoIDex( hashAlgo, hashSize );
	hashInfoSize = sizeofShortObject( hashSize );
	ENSURES( isShortIntegerRangeMin( algoInfoSize, 8 ) );
	ENSURES( isShortIntegerRangeMin( hashInfoSize, hashSize ) );

	return( sizeofShortObject( algoInfoSize + hashInfoSize ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
static int readMessageDigest( INOUT_PTR STREAM *stream, 
							  OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo,
							  OUT_BUFFER( hashMaxLen, *hashSize ) void *hash, 
							  IN_LENGTH_HASH const int hashMaxLen, 
							  OUT_LENGTH_BOUNDED_Z( hashMaxLen ) int *hashSize )
	{
	BYTE buffer[ 8 + 8 ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( hashAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtrDynamic( hash, hashMaxLen ) );
	assert( isWritePtr( hashSize, sizeof( int ) ) );

	REQUIRES_S( hashMaxLen >= MIN_HASHSIZE && hashMaxLen <= 8192 );

	/* Clear the return values */
	REQUIRES_S( isShortIntegerRangeNZ( hashMaxLen ) ); 
	memset( hash, 0, min( 16, hashMaxLen ) );
	*hashSize = 0;

	/* As used here this function doesn't actually read the message digest 
	   but is merely used as a check for corrupted recovered signature data
	   in order to return a CRYPT_ERROR_BADDATA rather than a generic 
	   CRYPT_ERROR_SIGNATURE.  Because of this we don't need to emulate a 
	   lot of asn1_rd.c code but can just perform a minimal check that things
	   look OK:

		SEQUENCE {
			SEQUENCE {
				algo		OBJECT IDENTIFIER,
				algoParams	ANY DEFINED BY algo
				}
			OCTET STRING hash
			} */
	status = sread( stream, buffer, 8 );
	if( cryptStatusError( status ) ) 
		return( status );
	if( buffer[ 0 ] != BER_SEQUENCE || \
		buffer[ 1 ] < 2 + 3 + 2 + MIN_HASHSIZE || \
		buffer[ 1 ] > 32 + CRYPT_MAX_HASHSIZE )
		return( CRYPT_ERROR_BADDATA );
	if( buffer[ 2 ] != BER_SEQUENCE || \
		buffer[ 3 ] < 3 + 2 + MIN_HASHSIZE || \
		buffer[ 3 ] > 32 + CRYPT_MAX_HASHSIZE )
		return( CRYPT_ERROR_BADDATA );
	if( buffer[ 4 ] != BER_OBJECT_IDENTIFIER || \
		buffer[ 5 ] < MIN_OID_SIZE ||
		buffer[ 5 ] > MAX_OID_SIZE )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeMessageDigest( INOUT_PTR STREAM *stream, 
							   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							   IN_BUFFER( hashSize ) const void *hash, 
							   IN_LENGTH_HASH const int hashSize )
	{
	const BYTE *oid = getOID( hashAlgo, hashSize );
	
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( hash, hashSize ) );

	REQUIRES_S( isHashAlgo( hashAlgo ) );
	REQUIRES_S( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );

	/* writeSequence() */
	writeHeader( stream, BER_SEQUENCE, 
				 sizeofAlgoIDex( hashAlgo, hashSize ) + \
					sizeofShortObject( hashSize ) );

	/* writeAlgoIDex() */
	writeHeader( stream, BER_SEQUENCE, sizeofOID( oid ) + sizeofNull() );
	swrite( stream, oid, sizeofOID( oid ) );
	writeHeader( stream, BER_NULL, 0 );

	/* writeOctetString() */
	writeHeader( stream, BER_OCTETSTRING, hashSize );
	return( swrite( stream, hash, hashSize ) );
	}
#endif /* !USE_INT_ASN1 */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Unlike PKCS #1 encryption there isn't any minimum-height requirement for 
   the PKCS #1 signature padding, however we require a set minimum number of 
   bytes of 0xFF padding because if they're not present then there's 
   something funny going on.  For a given key size we require that all but
   ( 3 bytes PKCS #1 formatting + ( 2 + 15 + 2 ) bytes ASN.1 wrapper + 
     CRYPT_MAX_HASHSIZE bytes hash ) be 0xFF padding */

#define getMinPadBytes( length ) \
		( ( length ) - ( 3 + 19 + CRYPT_MAX_HASHSIZE ) )

/* Encode/decode PKCS #1 signature formatting */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int encodePKCS1( INOUT_PTR STREAM *stream, 
						IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						IN_BUFFER( hashSize ) const void *hash, 
						IN_LENGTH_HASH const int hashSize,
						IN_LENGTH_PKC const int length )
	{
	LOOP_INDEX i;
	int payloadSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( hash, hashSize ) );

	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );
	REQUIRES( length >= MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );

	/* Encode the signature payload using the PKCS #1 format:

		[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] */
	status = payloadSize = sizeofMessageDigest( hashAlgo, hashSize );
	ENSURES( !cryptStatusError( status ) );
	sputc( stream, 0 );
	sputc( stream, 1 );
	LOOP_EXT( i = 0, i < length - ( payloadSize + 3 ), i++,
			  CRYPT_MAX_PKCSIZE )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, length - ( payloadSize + 4 ),
									 CRYPT_MAX_PKCSIZE ) );

		sputc( stream, 0xFF );
		}
	ENSURES( LOOP_BOUND_OK );
	sputc( stream, 0 );

	return( writeMessageDigest( stream, hashAlgo, hash, hashSize ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int decodePKCS1( INOUT_PTR STREAM *stream, 
						IN_LENGTH_PKC const int length )
	{
	LOOP_INDEX i;
	int ch;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( length >= MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );

	/* Decode the payload using the PKCS #1 format:

		[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ]

	   Note that some implementations may have bignum code that zero-
	   truncates the RSA data, which would remove the leading zero from the 
	   PKCS #1 padding and produce a CRYPT_ERROR_BADDATA error.  It's the 
	   responsibility of the lower-level crypto layer to reformat the data 
	   to return a correctly-formatted result if necessary */
	if( sgetc( stream ) != 0 || sgetc( stream ) != 1 )
		{
		/* No [ 0 ][ 1 ] at start */
		return( CRYPT_ERROR_BADDATA );
		}
	LOOP_EXT( ( i = 2, ch = 0xFF ), 
			  ( i < length - MIN_HASHSIZE ) && ( ch == 0xFF ), 
			  i++, CRYPT_MAX_PKCSIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 2, length - ( MIN_HASHSIZE + 1 ),
									 CRYPT_MAX_PKCSIZE + 1 ) );

		ch = sgetc( stream );
		if( cryptStatusError( ch ) )
			return( CRYPT_ERROR_BADDATA );
		}
	ENSURES( LOOP_BOUND_OK );
	if( ch != 0 || i < getMinPadBytes( length ) || \
		i >= length - MIN_HASHSIZE )
		{
		/* No [ 0 ] at end or insufficient/excessive 0xFF padding */
		return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

/* Compare the ASN.1-encoded hash value in the signature with the hash 
   information that we've been given.  We have to be very careful how we 
   handle this because we don't want to allow an attacker to inject random 
   data into gaps in the encoding, which would allow for signature forgery 
   if small exponents are used (although cryptlib disallows any exponents 
   that make this easy).  The obvious approach of using 
   checkObjectEncoding() doesn't work because an attacker can still encode 
   the signature in a form that's syntactically valid ASN.1, just not the 
   correct ASN.1 for a MessageDigest record.  To avoid having to have every 
   function that handles reading the hash value be anal-retentive about 
   every data element that it reads, we take the hash value that we've been 
   given and encode it correctly as a MessageDigest record and then do a 
   straight memcmp() of the encoded form rather than trying to validity-
   check the externally-supplied value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int compareHashInfo( INOUT_PTR STREAM *stream, 
							IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							IN_BUFFER( hashSize ) const void *hash, 
							IN_LENGTH_HASH const int hashSize )
	{
	CRYPT_ALGO_TYPE dummyHashAlgo;
	STREAM mdStream;
	BYTE encodedMD[ 32 + CRYPT_MAX_HASHSIZE + 8 ];
	BYTE recreatedMD[ 32 + CRYPT_MAX_HASHSIZE + 8 ];
	BYTE dummyHashBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int encodedMdLength, recreatedMdLength DUMMY_INIT;
	int dummyHashSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( hash, hashSize ) );

	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );

	/* Read the encoded hash data as a blob and make sure that that's all
	   of the data */
	status = readRawObject( stream, encodedMD, 32 + CRYPT_MAX_HASHSIZE, 
							&encodedMdLength, BER_SEQUENCE );
	if( cryptStatusError( status ) )
		return( status );
	if( sMemDataLeft( stream ) != 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Write the supplied hash information into an encoded blob */
	sMemOpen( &mdStream, recreatedMD, 32 + CRYPT_MAX_HASHSIZE );
	status = writeMessageDigest( &mdStream, hashAlgo, hash, hashSize );
	if( cryptStatusOK( status ) )
		recreatedMdLength = stell( &mdStream );
	sMemDisconnect( &mdStream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( recreatedMdLength ) );

	/* Compare the two encoded blobs.  What to return in this case is a bit
	   complex because if the data that precedes the hash value is corrupted 
	   then we should really return a CRYPT_ERROR_BADDATA, but because we're 
	   doing an encode-and-compare rather than a read/decode, everything 
	   gets converted into the same error code, namely a 
	   CRYPT_ERROR_SIGNATURE.  
	   
	   To deal with this we first perform a redundant read of the encoded 
	   ASN.1 portion, allowing us to return a CRYPT_ERROR_BADDATA in most 
	   cases where the problem is a corrupted/invalid encoding rather than 
	   a generic CRYPT_ERROR_SIGNATURE */
	sMemConnect( &mdStream, encodedMD, encodedMdLength );
	status = readMessageDigest( &mdStream, &dummyHashAlgo, dummyHashBuffer, 
								CRYPT_MAX_HASHSIZE, &dummyHashSize );
	sMemDisconnect( &mdStream );
	if( cryptStatusError( status ) )
		return( status );
	if( encodedMdLength != recreatedMdLength || \
		compareDataConstTime( encodedMD, recreatedMD, 
							  encodedMdLength ) != TRUE )
		status = CRYPT_ERROR_SIGNATURE;

	zeroise( encodedMD, 32 + CRYPT_MAX_HASHSIZE );
	zeroise( recreatedMD, 32 + CRYPT_MAX_HASHSIZE );
	zeroise( dummyHashBuffer, CRYPT_MAX_HASHSIZE );

	return( status );
	}

/* Make sure that the recovered signature data matches the data that we 
   originally signed, performed as a pairwise consistency check on the 
   private-key signing operation.

   Note that this check doesn't work for EdDSA because of braindamage in the
   way it works, see among others section 9.1 of "Attacking Deterministic 
   Signature Schemes Using Fault Attacks" by Poddebniak, Somorovsky, 
   Schinzel, Lochter and Rösler, and "Ed25519 leaks private key if public 
   key is incorrect", https://github.com/jedisct1/libsodium/issues/170/ */

static int checkRecoveredSignature( IN_HANDLE const CRYPT_CONTEXT iSignContext,
									IN_BUFFER( preSigDataLen ) \
										const void *preSigData,
									IN_LENGTH_PKC const int preSigDataLen,
									IN_BUFFER( sigLen ) \
										const void *signature,
									IN_LENGTH_PKC const int sigLen )
	{
	BYTE recoveredSignature[ CRYPT_MAX_PKCSIZE + 8 ];
	int status;

	assert( isReadPtrDynamic( preSigData, preSigDataLen ) );
	assert( isReadPtrDynamic( signature, sigLen ) );

	REQUIRES( preSigDataLen >= MIN_PKCSIZE && \
			  preSigDataLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( sigLen >= MIN_PKCSIZE && sigLen <= CRYPT_MAX_PKCSIZE );

	/* Recover the original signature data, unless we're in the unlikely 
	   situation that the key isn't valid for signature checking */
	REQUIRES( rangeCheck( sigLen, 1, CRYPT_MAX_PKCSIZE ) );
	memcpy( recoveredSignature, signature, sigLen );
	status = krnlSendMessage( iSignContext, IMESSAGE_CTX_SIGCHECK, 
							  recoveredSignature, sigLen );
	if( status == CRYPT_ERROR_PERMISSION || status == CRYPT_ERROR_NOTAVAIL )
		{
		/* The key can't be used for signature checking, there's not much 
		   that we can do.  This typically occurs for limited devices
		   like smart cards accessed via PKCS #11 or TPMs, which can only 
		   do private-key ops.  For native (software) contexts, which is the
		   ones that we care about, anything that can perform a private-key 
		   op can also perform the corresponding public-key op */
		return( CRYPT_OK );
		}
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_FAILED );

	/* Make sure that the recovered data matches the original data */
	if( preSigDataLen != sigLen || \
		compareDataConstTime( preSigData, recoveredSignature, 
							  sigLen ) != TRUE )
		{
		DEBUG_DIAG(( "Signature consistency check failed" ));
		assert( DEBUG_WARN );
		status = CRYPT_ERROR_FAILED;
		}
	zeroise( recoveredSignature, CRYPT_MAX_PKCSIZE );

	return( status );
	}

/****************************************************************************
*																			*
*								Signature Mechanisms 						*
*																			*
****************************************************************************/

/* Perform signing.  There are several variations of this that are handled 
   through common signature mechanism functions */

typedef enum { SIGN_NONE, SIGN_PKCS1, SIGN_TLS, SIGN_LAST } SIGN_TYPE;

/* Perform PKCS #1 signing/sig.checking */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sign( INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo, 
				 IN_ENUM( SIGN ) const SIGN_TYPE type )
	{
	CRYPT_ALGO_TYPE hashAlgo DUMMY_INIT;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_TLS
	BYTE hash2[ CRYPT_MAX_HASHSIZE + 8 ];
#endif /* USE_TLS */
	BYTE preSigData[ CRYPT_MAX_PKCSIZE + 8 ];
	BOOLEAN_INT sideChannelProtectionLevel DUMMY_INIT;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int hashSize, length, status;
#ifdef USE_TLS
	LOOP_INDEX i;
	int hashSize2 DUMMY_INIT; 
#endif /* USE_TLS */

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	REQUIRES( isEnumRange( type, SIGN ) );

	/* Clear return value */
	if( mechanismInfo->signature != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		memset( mechanismInfo->signature, 0,
				mechanismInfo->signatureLength );
		}

	/* Get various algorithm and config parameters */
	status = getPkcAlgoParams( mechanismInfo->signContext, NULL,
							   &length );
	if( cryptStatusOK( status ) )
		{
		status = getHashAlgoParams( mechanismInfo->hashContext,
									&hashAlgo, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, 
								  &sideChannelProtectionLevel,
								  CRYPT_OPTION_MISC_SIDECHANNELPROTECTION );
		}
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( length > MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );
	CFI_CHECK_UPDATE( "getPkcAlgoParams" );

	/* If this is just a length check, we're done */
	if( mechanismInfo->signature == NULL )
		{
		mechanismInfo->signatureLength = length;

		ENSURES( CFI_CHECK_SEQUENCE_1( "getPkcAlgoParams" ) );

		return( CRYPT_OK );
		}

	/* Get the hash data and determine the encoded payload size */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
#ifdef USE_TLS
	if( type == SIGN_TLS )
		{
		setMessageData( &msgData, hash2, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( mechanismInfo->hashContext2,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) )
			return( status );
		hashSize2 = msgData.length;
		}
#endif /* USE_TLS */
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* Encode the payload as required */
	sMemOpen( &stream, mechanismInfo->signature, length );
	switch( type )
		{
		case SIGN_PKCS1:
			status = encodePKCS1( &stream, hashAlgo, hash, hashSize, 
								  length );
			CFI_CHECK_UPDATE( "encodePKCS1" );
			break;

#ifdef USE_TLS
		case SIGN_TLS:
			/* TLS 1.0/1.1 signatures must be MD5 + SHA1 */
			REQUIRES( hashAlgo == CRYPT_ALGO_MD5 );
			REQUIRES( hashSize == 16 && hashSize2 == 20 );

			/* Encode the payload using the PKCS #1 TLS format:

				[ 0 ][ 1 ][ 0xFF padding ][ 0 ][ MD5 hash ][ SHA1 hash ] */
			sputc( &stream, 0 );
			sputc( &stream, 1 );
			LOOP_EXT( i = 0, i < length - ( hashSize + hashSize2 + 3 ), i++,
					  CRYPT_MAX_PKCSIZE )
				{
				ENSURES( LOOP_INVARIANT_EXT( i, 0,
											 length - ( hashSize + hashSize2 + 4 ),
											 CRYPT_MAX_PKCSIZE ) );

				sputc( &stream, 0xFF );
				}
			ENSURES( LOOP_BOUND_OK );
			sputc( &stream, 0 );
			swrite( &stream, hash, hashSize );
			status = swrite( &stream, hash2, hashSize2 );
			CFI_CHECK_UPDATE( "encodePKCS1" );
			break;
#endif /* USE_TLS */

		default:
			retIntError();
		}
	ENSURES( cryptStatusError( status ) || stell( &stream ) == length );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}

	/* If we're using side-channel protection remember a copy of the 
	   signature data for later so that we can check it against the 
	   recovered signature data */
	if( sideChannelProtectionLevel > 0 )
		{
		REQUIRES( rangeCheck( length, 1, CRYPT_MAX_PKCSIZE ) );
		memcpy( preSigData, mechanismInfo->signature, length );
		}

	/* Sign the data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGN, mechanismInfo->signature,
							  length );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}
	mechanismInfo->signatureLength = length;
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGN" );

	/* If we're using side-channel protection check that the signature 
	   verifies */
	if( sideChannelProtectionLevel > 0 )
		{
		status = checkRecoveredSignature( mechanismInfo->signContext, 
										  preSigData, length,
										  mechanismInfo->signature, length );
		zeroise( preSigData, CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) )
			{
			REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
			zeroise( mechanismInfo->signature, 
					 mechanismInfo->signatureLength );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "checkRecoveredSignature" );

	ENSURES( CFI_CHECK_SEQUENCE_5( "getPkcAlgoParams", 
								   "IMESSAGE_GETATTRIBUTE_S", "encodePKCS1", 
								   "IMESSAGE_CTX_SIGN", 
								   "checkRecoveredSignature" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sigcheck( INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo, 
					 IN_ENUM( SIGN ) const SIGN_TYPE type )
	{
	CRYPT_ALGO_TYPE contextHashAlgo DUMMY_INIT;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, hashSize DUMMY_INIT, status;

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );
	
	REQUIRES( isEnumRange( type, SIGN ) );

	/* Get various algorithm parameters */
	status = getPkcAlgoParams( mechanismInfo->signContext, NULL,
							   &length );
	if( cryptStatusOK( status ) )
		{
		status = getHashAlgoParams( mechanismInfo->hashContext,
									&contextHashAlgo, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( mechanismInfo->hashContext, 
								  IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusOK( status ) )
			hashSize = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( length > MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );
	CFI_CHECK_UPDATE( "getPkcAlgoParams" );

	/* Format the input data as required for the signatue check to work */
	status = adjustPKCS1Data( decryptedSignature, CRYPT_MAX_PKCSIZE,
					mechanismInfo->signature, mechanismInfo->signatureLength,
					length );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "adjustPKCS1Data" );

	/* Recover the signed data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGCHECK, decryptedSignature,
							  length );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGCHECK" );

	/* Decode the payload as required */
	sMemConnect( &stream, decryptedSignature, length );
	switch( type )
		{
		case SIGN_PKCS1:
			/* The payload is an ASN.1-encoded hash, process it very 
			   carefully */
			status = decodePKCS1( &stream, length );
			if( cryptStatusError( status ) )
				break;
			status = compareHashInfo( &stream, contextHashAlgo, hash, 
									  hashSize );
			CFI_CHECK_UPDATE( "compareHashInfo" );
			break;

#ifdef USE_TLS
		case SIGN_TLS:
			{
			BYTE hash2[ CRYPT_MAX_HASHSIZE + 8 ];

			REQUIRES( contextHashAlgo == CRYPT_ALGO_MD5 );

			/* The payload is [ MD5 hash ][ SHA1 hash ] */
			status = decodePKCS1( &stream, length );
			if( cryptStatusError( status ) )
				break;
			status = sread( &stream, hash, 16 );
			if( cryptStatusOK( status ) )
				status = sread( &stream, hash2, 20 );
			if( cryptStatusError( status ) )
				break;

			/* Make sure that's all that there is.  This is checked in 
			   compareHashInfo() for standard signatures but we have to 
			   perform the check explicitly for TLS-style signatures */
			if( sMemDataLeft( &stream ) != 0 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}

			/* Make sure that the two hash values match */
			setMessageData( &msgData, hash, 16 );
			status = krnlSendMessage( mechanismInfo->hashContext, 
									  IMESSAGE_COMPARE, &msgData, 
									  MESSAGE_COMPARE_HASH );
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, hash2, 20 );
				status = krnlSendMessage( mechanismInfo->hashContext2, 
										  IMESSAGE_COMPARE, &msgData, 
										  MESSAGE_COMPARE_HASH );
				}
			if( cryptStatusError( status ) )
				{
				/* The compare-hash operations return a generic CRYPT_OK/
				   CRYPT_ERROR, convert it to a more specific error code for 
				   the operation that we're performing */
				status = CRYPT_ERROR_SIGNATURE;
				}

			/* Clean up */
			zeroise( hash2, CRYPT_MAX_HASHSIZE );
			CFI_CHECK_UPDATE( "compareHashInfo" );
			break;
			}
#endif /* USE_TLS */

		default:
			retIntError();
		}
	sMemDisconnect( &stream );

	/* Clean up */
	zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );
	zeroise( hash, CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( CFI_CHECK_SEQUENCE_4( "getPkcAlgoParams", 
								   "adjustPKCS1Data", "IMESSAGE_CTX_SIGCHECK", 
								   "compareHashInfo" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int signPKCS1( STDC_UNUSED void *dummy, 
			   INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED_ARG_OPT( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	return( sign( mechanismInfo, SIGN_PKCS1 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int sigcheckPKCS1( STDC_UNUSED void *dummy, 
				   INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED_ARG_OPT( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	return( sigcheck( mechanismInfo, SIGN_PKCS1 ) );
	}

#ifdef USE_TLS

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int signTLS( STDC_UNUSED void *dummy, 
			 INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED_ARG_OPT( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	return( sign( mechanismInfo, SIGN_TLS ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int sigcheckTLS( STDC_UNUSED void *dummy, 
				 INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	UNUSED_ARG_OPT( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );

	return( sigcheck( mechanismInfo, SIGN_TLS ) );
	}
#endif /* USE_TLS */

/****************************************************************************
*																			*
*							PSS Signature Mechanisms						*
*																			*
****************************************************************************/

#ifdef USE_PSS

/* Trim leading bits in the PSS padding to match the RSA modulus size.  The 
   RFC requires that we "set the leftmost 8 * emLen - emBits bits of the 
   leftmost octet in maskedDB to zero", where "emLen = ceil( ( modulus 
   length in bits - 1 ) / 8 )" and emBits = "(intended) length in bits of an 
   encoded message EM", which is probably the same as the modulus length in 
   bits.  The intended effect seems to be to trim the PSS padding to one 
   less than the modulus size in bits.
   
   This serves no cryptographic purpose apart from being incredibly awkward 
   to implement, both because clues on what's required are scattered all 
   over the RFC and because it assumes that we have the length in bits of 
   the modulus available.  This is only present as a low-level internal 
   value that's not accessible externally so we have to extract the public
   key as an SPKI, parse it to find the modulus, and then count the bits in 
   it */

CHECK_RETVAL_LENGTH_SHORT \
static int getKeysizeBits( const CRYPT_CONTEXT iCryptContext )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE pubkeyBuffer[ ( CRYPT_MAX_PKCSIZE * 3 ) + 8 ];
	BYTE nBuffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int nLength, nMSB, bitCount, status;

	REQUIRES( isHandleRangeValid( iCryptContext ) );

	/* Read the public key as an SPKI from the PKC context and extract the n 
	   value from it */
	setMessageData( &msgData, pubkeyBuffer, CRYPT_MAX_PKCSIZE * 3 );
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, msgData.data, msgData.length );
	readSequence( &stream, NULL );		/* SEQUENCE { */
	readUniversal( &stream );				/* AlgoID */
	readBitStringHole( &stream, NULL, 64, DEFAULT_TAG );/* BIT STRING */
	readSequence( &stream, NULL );				/* SEQUENCE { */
	status = readInteger( &stream, nBuffer, CRYPT_MAX_PKCSIZE, &nLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Count the number of leading zero bits.  There are all sorts of clever
	   hacks to do this faster than a simple scan, but for eight bits in a
	   non-critical code path it's not worth the complexity */
	nMSB = byteToInt( nBuffer[ 0 ] );
	if( nMSB == 0 )
		{
		/* This shouldn't happen since readInteger() performs leading-zero 
		   truncation */
		assert( DEBUG_WARN );
		bitCount = 8;
		}
	else
		{
		int LOOP_ITERATOR;

		LOOP_SMALL( bitCount = 0, 
					( nMSB & 0x80 ) == 0, 
					( bitCount++, nMSB <<= 1 ) )
			{
			ENSURES( LOOP_INVARIANT_SMALL( bitCount, 0, 7 ) );
			}
		ENSURES( LOOP_BOUND_OK );
		}

	return( ( nLength * 8 ) - bitCount );
	}

#define trimLeadingBits( data, dataLenBytes, pkcSizeBits ) \
		data[ 0 ] &= 0xFF >> ( ( bytesToBits( dataLenBytes ) + 1 ) - ( pkcSizeBits ) )

/* Generate the mHash value by hashing '0x00 x 8 || hash || salt' */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 6 ) ) \
static int generateMHash( OUT_BUFFER_FIXED( mHashMaxLen ) BYTE *mHash, 
						  IN_LENGTH_HASH const int mHashMaxLen, 
						  IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						  IN_BUFFER( hashSize ) const void *hash, 
						  IN_LENGTH_HASH const int hashSize,
						  IN_BUFFER( saltLen ) const void *salt, 
						  IN_LENGTH_PKC const int saltLen )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	BYTE mData[ 8 + CRYPT_MAX_HASHSIZE + CRYPT_MAX_HASHSIZE + 8 ];
	int hashFunctionSize;

	assert( isWritePtrDynamic( mHash, mHashMaxLen ) );
	assert( isReadPtrDynamic( hash, hashSize ) );
	assert( isReadPtrDynamic( salt, saltLen ) );

	REQUIRES( mHashMaxLen >= MIN_HASHSIZE && \
			  mHashMaxLen <= CRYPT_MAX_HASHSIZE );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );
	REQUIRES( saltLen >= MIN_HASHSIZE && saltLen <= CRYPT_MAX_HASHSIZE );

	getHashAtomicParameters( hashAlgo, hashSize, &hashFunctionAtomic, 
							 &hashFunctionSize );
	ENSURES( hashSize == hashFunctionSize );
	ENSURES( 8 + hashSize + saltLen <= \
			 8 + CRYPT_MAX_HASHSIZE + CRYPT_MAX_HASHSIZE );

	/* mHash = hash( 00 x 8 || hash || salt ) */
	memset( mData, 0, 8 );
	REQUIRES( isShortIntegerRangeNZ( hashSize ) ); 
	memcpy( mData + 8, hash, hashSize );
	REQUIRES( isShortIntegerRangeNZ( saltLen ) ); 
	memcpy( mData + 8 + hashSize, salt, saltLen );
	hashFunctionAtomic( mHash, mHashMaxLen, mData, 8 + hashSize + saltLen );

	zeroise( mData, 8 + CRYPT_MAX_HASHSIZE + CRYPT_MAX_HASHSIZE );
	
	return( CRYPT_OK );
	}

/* Generate/recover a PSS data block:

							  Hash( message )
									|
									v
			+-------------------+-------+-------+
	   M' =	|	  00 x 8		| hash	| salt	|---+
			+-------------------+-------+-------+	|
											|		v
											|	  Hash
											v		|
			+---------------------------+-------+	|
	   DB =	|		00 ... 00 01		| salt	|	|
			+---------------------------+-------+	|
							|						|
							v						|
						   xor <------- MGF() ------+
							|						|
							v						v
			+-----------------------------------+------+---+
	   EM =	|#				maskedDB			| mHash|xDB|
			+-----------------------------------+------+---+
							|						|
							v						|
						   xor <------- MGF() ------+---+
							|							|
							v							|
			+---------------------------+-------+		|
	   DB =	|		00 ... 00 01		| salt	|		|
			+---------------------------+-------+		|
											|			|
											|			|
											v			|
			+-------------------+-------+-------+		|
	   M' =	|	  00 x 8		| hash	| salt	|---+	|
			+-------------------+-------+-------+	|	|
													v	|
												 Hash()	|
													|	|
													v	v
												   Compare 
   # = Leading zeroes trimmed */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 6 ) ) \
static int generatePssDataBlock( OUT_BUFFER_FIXED( dataMaxLen ) BYTE *data, 
								 IN_LENGTH_PKC const int dataMaxLen, 
								 IN_BUFFER( saltLen ) const void *salt, 
								 IN_LENGTH_PKC const int saltLen,
								 IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								 IN_BUFFER( hashSize ) const void *hash, 
								 IN_RANGE( MIN_KEYSIZE, CRYPT_MAX_KEYSIZE ) \
									const int hashSize,
								 IN_RANGE( bytesToBits( MIN_PKCSIZE ),
										   bytesToBits( CRYPT_MAX_PKCSIZE ) ) \
									const int pkcSizeBits )
	{
	BYTE mHash[ CRYPT_MAX_HASHSIZE + 8 ], dbMask[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE *db;
	LOOP_INDEX i;
	int dbLen, dbSaltPos, status;

	assert( isWritePtrDynamic( data, dataMaxLen ) );
	assert( isReadPtrDynamic( hash, hashSize ) );
	assert( isReadPtrDynamic( salt, saltLen ) );

	REQUIRES( dataMaxLen >= MIN_PKCSIZE && dataMaxLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( saltLen >= MIN_HASHSIZE && saltLen <= CRYPT_MAX_HASHSIZE );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize <= CRYPT_MAX_HASHSIZE );
	REQUIRES( hashSize + saltLen + 8 <= dataMaxLen );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( pkcSizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  pkcSizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	REQUIRES( pkcSizeBits > bytesToBits( dataMaxLen ) - 8 && \
			  pkcSizeBits <= bytesToBits( dataMaxLen ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLen ) ); 
	memset( data, 0, min( 16, dataMaxLen ) );

	/* Get the hash of the salted message hash */
	status = generateMHash( mHash, CRYPT_MAX_HASHSIZE, hashAlgo, hash, 
							hashSize, salt, saltLen );
	if( cryptStatusError( status ) )
		return( status );

	/* Calculate the size and position of the various data quantities */
	db = data;
	dbLen = dataMaxLen - ( hashSize + 1 );
	dbSaltPos = dbLen - saltLen;

	ENSURES( dbSaltPos > 16 && \
			 dbSaltPos < CRYPT_MAX_PKCSIZE - ( MIN_HASHSIZE * 2 ) );
	ENSURES( dbSaltPos + saltLen + hashSize + 1 == dataMaxLen );

	/* dbMask = MGF1( hash, hashSize ) */
	status = mgf1( dbMask, dataMaxLen, mHash, hashSize, hashAlgo, hashSize );
	ENSURES( cryptStatusOK( status ) );	/* Can only be an internal error */

	/* db = 00 .. 00 01 || salt */
	REQUIRES( boundsCheck( dbSaltPos, saltLen, dbLen ) );
	memset( db, 0, dbSaltPos );
	db[ dbSaltPos - 1 ] = 0x01;
	REQUIRES( isShortIntegerRangeNZ( saltLen ) ); 
	memcpy( db + dbSaltPos, salt, saltLen );

	/* db = db ^ dbMask */
	LOOP_EXT( i = 0, i < dbLen, i++, CRYPT_MAX_PKCSIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, dbLen - 1,
									 CRYPT_MAX_PKCSIZE + 1 ) );

		db[ i ] ^= dbMask[ i ];
		}
	ENSURES( LOOP_BOUND_OK );

	/* data = db || mHash || 0xBC */
	REQUIRES( boundsCheck( dbLen, hashSize + 1, dataMaxLen ) );
	memcpy( data + dbLen, mHash, hashSize );
	data[ dbLen + hashSize ] = 0xBC;

	/* Trim the data block down to size */
	trimLeadingBits( data, dataMaxLen, pkcSizeBits );

	zeroise( mHash, CRYPT_MAX_HASHSIZE );
	zeroise( dbMask, CRYPT_MAX_PKCSIZE );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 7 ) ) \
static int recoverPssDataBlock( OUT_BUFFER( mHashMaxLen, *mHashLen ) \
									BYTE *mHash, 
								IN_LENGTH_HASH const int mHashMaxLen, 
								OUT_LENGTH_BOUNDED_Z( mHashMaxLen ) \
									int *mHashLen, 
								IN_BUFFER( dataLen ) const void *data, 
								IN_LENGTH_PKC const int dataLen, 
								IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								IN_BUFFER( hashSize) const void *hash, 
								IN_LENGTH_HASH const int hashSize,
								IN_RANGE( bytesToBits( MIN_PKCSIZE ),
										  bytesToBits( CRYPT_MAX_PKCSIZE ) ) \
									const int pkcSizeBits )
	{
	BYTE db[ CRYPT_MAX_PKCSIZE + 8 ], dbMask[ CRYPT_MAX_PKCSIZE + 8 ];
	LOOP_INDEX i;
	int dbLen, padLen, status;

	assert( isWritePtrDynamic( mHash, mHashMaxLen ) );
	assert( isWritePtr( mHashLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( data, dataLen ) );
	assert( isReadPtrDynamic( hash, hashSize ) );

	REQUIRES( mHashMaxLen >= MIN_HASHSIZE && mHashMaxLen >= hashSize && \
			  mHashMaxLen <= CRYPT_MAX_HASHSIZE );
	REQUIRES( dataLen >= MIN_PKCSIZE && dataLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( hashSize >= MIN_HASHSIZE && hashSize * 2 < dataLen && \
			  hashSize <= CRYPT_MAX_HASHSIZE );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( pkcSizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			  pkcSizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	REQUIRES( pkcSizeBits > bytesToBits( dataLen ) - 8 && \
			  pkcSizeBits <= bytesToBits( dataLen ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( mHashMaxLen ) ); 
	memset( mHash, 0, min( 16, mHashMaxLen ) );
	*mHashLen = 0;

	/* Clear DB.  This is required because when we trim the leading bits of 
	   db ^ dbMask we're working on a subset of the input data, so that 
	   while the full length of the input data is dataLen bytes the amount 
	   of valid data in db is only dbLen bytes.  To deal with this we could
	   adjust both dbLen and pkcSizeBits by bytesToBits( dataLen - dbLen )
	   but it's easier to just set all bytes of DB to zero, thus making the
	   entire range up to dataLen valid */
	memset( db, 0, CRYPT_MAX_PKCSIZE );

	/* Calculate the size and position of the various data quantities */
	dbLen = dataLen - ( hashSize + 1 );
	padLen = dbLen - hashSize;

	ENSURES( dbLen + hashSize + 1 == dataLen );
	ENSURES( padLen > 16 && padLen + ( 2 * hashSize ) + 1 == dataLen && \
			 padLen < CRYPT_MAX_PKCSIZE - ( MIN_HASHSIZE * 2 ) );

	/* dbMask = MGF1( hash, hashSize ) */
	status = mgf1( dbMask, dbLen, ( BYTE * ) data + dbLen, hashSize, 
				   hashAlgo, hashSize );
	ENSURES( cryptStatusOK( status ) );	/* Can only be an internal error */

	/* db = db ^ dbMask */
	REQUIRES( rangeCheck( dbLen, 1, CRYPT_MAX_PKCSIZE ) );
	memcpy( db, data, dbLen );
	LOOP_EXT( i = 0, i < dbLen, i++, CRYPT_MAX_PKCSIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, dbLen - 1,
									 CRYPT_MAX_PKCSIZE + 1 ) );

		db[ i ] ^= dbMask[ i ];
		}
	ENSURES( LOOP_BOUND_OK );

	/* Trim the data block down to size */
	trimLeadingBits( db, dataLen, pkcSizeBits );

	/* The block is now: 

		[ 0x00 padding ][ 0x01 ][ salt ][ mHash ][ 0xDB ]
		 ------------- DB -------------  ---- data -----

	   Check that the constant parts are as expected */
	REQUIRES( isShortIntegerRangeNZ( padLen ) ); 
	memset( dbMask, 0, padLen );
	dbMask[ padLen - 1 ] = 0x01;
	if( memcmp( db, dbMask, padLen ) || \
		( ( const BYTE * ) data )[ dataLen - 1 ] != 0xBC )
		return( CRYPT_ERROR_BADDATA );

	/* Now that we've got the salt, we can regenerate mHash and return it to 
	   the caller to verify against the copy of mHash stored in the 
	   signature */
	status = generateMHash( mHash, mHashMaxLen, hashAlgo, hash, hashSize,
						    db + padLen, hashSize );
	if( cryptStatusOK( status ) )
		*mHashLen = hashSize;
	return( status );
	}

/* Perform PSS signing/sig.checking */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int signPSS( STDC_UNUSED void *dummy, 
			 INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	CRYPT_ALGO_TYPE hashAlgo DUMMY_INIT;
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], salt[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE preSigData[ CRYPT_MAX_PKCSIZE + 8 ];
	BOOLEAN_INT sideChannelProtectionLevel DUMMY_INIT;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, keySizeBits DUMMY_INIT, hashSize, status;

	UNUSED_ARG_OPT( dummy );
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	/* Clear return value */
	if( mechanismInfo->signature != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		memset( mechanismInfo->signature, 0,
				mechanismInfo->signatureLength );
		}

	/* Get various algorithm and config parameters */
	status = getPkcAlgoParams( mechanismInfo->signContext, NULL,
							   &length );
	if( cryptStatusOK( status ) )
		{
		status = getHashAlgoParams( mechanismInfo->hashContext,
									&hashAlgo, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, 
								  &sideChannelProtectionLevel,
								  CRYPT_OPTION_MISC_SIDECHANNELPROTECTION );
		}
	if( cryptStatusOK( status ) )
		status = keySizeBits = getKeysizeBits( mechanismInfo->signContext );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( length > MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );
	CFI_CHECK_UPDATE( "getPkcAlgoParams" );

	/* If this is just a length check, we're done */
	if( mechanismInfo->signature == NULL )
		{
		mechanismInfo->signatureLength = length;

		ENSURES( CFI_CHECK_SEQUENCE_1( "getPkcAlgoParams" ) );

		return( CRYPT_OK );
		}

	/* Get the hash data and salt.  The salt data doesn't have to be 
	   cryptographically strong, in fact technically it doesn't even need to 
	   be random since this just changes the security level to that of a
	   deterministic alternative like full-domain hashing (FDH), so we use
	   the nonce RNG to get the value */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( mechanismInfo->hashContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
	setMessageData( &msgData, salt, hashSize );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* Encode the payload */
	status = generatePssDataBlock( mechanismInfo->signature, length, 
								   salt, hashSize, hashAlgo, hash, hashSize, 
								   keySizeBits );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}
	CFI_CHECK_UPDATE( "generatePssDataBlock" );

	/* If we're using side-channel protection remember a copy of the 
	   signature data for later so that we can check it against the 
	   recovered signature data */
	if( sideChannelProtectionLevel > 0 )
		{
		REQUIRES( rangeCheck( length, 1, CRYPT_MAX_PKCSIZE ) );
		memcpy( preSigData, mechanismInfo->signature, length );
		}

	/* Sign the data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGN, mechanismInfo->signature,
							  length );
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
		zeroise( mechanismInfo->signature, mechanismInfo->signatureLength );
		return( status );
		}
	mechanismInfo->signatureLength = length;
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGN" );

	/* If we're using side-channel protection check that the signature 
	   verifies */
	if( sideChannelProtectionLevel > 0 )
		{
		status = checkRecoveredSignature( mechanismInfo->signContext, 
										  preSigData, length,
										  mechanismInfo->signature, length );
		zeroise( preSigData, CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) )
			{
			REQUIRES( isShortIntegerRangeNZ( mechanismInfo->signatureLength ) ); 
			zeroise( mechanismInfo->signature, 
					 mechanismInfo->signatureLength );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "checkRecoveredSignature" );

	ENSURES( CFI_CHECK_SEQUENCE_5( "getPkcAlgoParams", 
								   "IMESSAGE_GETATTRIBUTE_S", 
								   "generatePssDataBlock", 
								   "IMESSAGE_CTX_SIGN", 
								   "checkRecoveredSignature" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int sigcheckPSS( STDC_UNUSED void *dummy, 
				 INOUT_PTR MECHANISM_SIGN_INFO *mechanismInfo )
	{
	CRYPT_ALGO_TYPE hashAlgo DUMMY_INIT;
	MESSAGE_DATA msgData;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ], mHash[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, keySizeBits DUMMY_INIT, hashSize DUMMY_INIT, mHashLength;
	int status;

	UNUSED_ARG_OPT( dummy );
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_SIGN_INFO ) ) );
	
	/* Get various algorithm parameters */
	status = getPkcAlgoParams( mechanismInfo->signContext, NULL,
							   &length );
	if( cryptStatusOK( status ) )
		{
		status = getHashAlgoParams( mechanismInfo->hashContext,
									&hashAlgo, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( mechanismInfo->hashContext, 
								  IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusOK( status ) )
			hashSize = msgData.length;
		}
	if( cryptStatusOK( status ) )
		status = keySizeBits = getKeysizeBits( mechanismInfo->signContext );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( length > MIN_PKCSIZE && length <= CRYPT_MAX_PKCSIZE );
	CFI_CHECK_UPDATE( "getPkcAlgoParams" );

	/* Format the input data as required for the signatue check to work */
	status = adjustPKCS1Data( decryptedSignature, CRYPT_MAX_PKCSIZE,
					mechanismInfo->signature, mechanismInfo->signatureLength,
					length );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "adjustPKCS1Data" );

	/* Recover the signed data */
	status = krnlSendMessage( mechanismInfo->signContext,
							  IMESSAGE_CTX_SIGCHECK, decryptedSignature,
							  length );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGCHECK" );

	/* Decode the payload and compare the calculated mHash value with the 
	   value in the signature data */
	status = recoverPssDataBlock( mHash, CRYPT_MAX_HASHSIZE, 
								  &mHashLength, decryptedSignature, length, 
								  hashAlgo, hash, hashSize, 
								  keySizeBits );
	if( cryptStatusError( status ) )
		{
		zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );
		zeroise( hash, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	CFI_CHECK_UPDATE( "recoverPssDataBlock" );
	if( mHashLength != hashSize || \
		compareDataConstTime( decryptedSignature + length - ( hashSize + 1 ), 
							   mHash, mHashLength ) != TRUE )
		{
		/* Exit after the cleanup step */
		status = CRYPT_ERROR_SIGNATURE;
		}

	/* Clean up */
	zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );
	zeroise( hash, CRYPT_MAX_HASHSIZE );
	zeroise( mHash, CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( CFI_CHECK_SEQUENCE_4( "getPkcAlgoParams", 
								   "adjustPKCS1Data", "IMESSAGE_CTX_SIGCHECK", 
								   "recoverPssDataBlock" ) );

	return( CRYPT_OK );
	}
#endif /* USE_PSS */

/****************************************************************************
*																			*
*							Signature Self-test Functions 					*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Test signature mechanisms */

typedef enum {
	TEST_NONE,				/* No data block manipulation type */
	TEST_NORMAL,			/* Standard test */
	TEST_CORRUPT_START,		/* Corrupt starting byte */
	TEST_CORRUPT_BLOCKTYPE,	/* Corrupt block type */
	TEST_CORRUPT_PADDING,	/* Corrupt padding data */
	TEST_CORRUPT_END,		/* Corrupt ending byte */
	TEST_CORRUPT_OID,		/* Corrupt encoded OID data */
	TEST_CORRUPT_HASH,		/* Corrupt hash value */
#ifdef USE_PSS
	TEST_CORRUPT_MASKEDDB,	/* Corrupt masked DB */
	TEST_CORRUPT_SALT,		/* Corrupt PSS salt */
	TEST_CORRUPT_MHASH,		/* Corrupt PSS mHash */
	TEST_CORRUPT_BC,		/* Corrupt PSS 0xBC value */
#endif /* USE_PSS */
	TEST_LAST				/* Last possible manipulation type */
	} TEST_TYPE;

static void manipulateDataBlock( INOUT_BUFFER_FIXED( length ) BYTE *buffer,
								 IN_LENGTH_PKC const int length,
								 IN_LENGTH_PKC const int payloadStart,
								 IN_ENUM( TEST ) const TEST_TYPE testType )
	{
	assert( isWritePtr( buffer, length ) );

	REQUIRES_V( length >= 128 && length <= CRYPT_MAX_PKCSIZE );
	REQUIRES_V( payloadStart >= 20 && payloadStart < length );
	REQUIRES_V( isEnumRange( testType, TEST ) );

	switch( testType )
		{
		case TEST_NORMAL:
			/* Standard test */
			break;

		case TEST_CORRUPT_START:
			/* Corrupt the PKCS #1 leading zero */
			buffer[ 0 ]++;
			break;

		case TEST_CORRUPT_BLOCKTYPE:
			/* Corrupt the PKCS #1 block type */
			buffer[ 1 ]++;
			break;

		case TEST_CORRUPT_PADDING:
			/* Corrupt the PKCS #1 padding.  This is already at 0xFF so we 
			   decrement rather than increment the value */
			assert( buffer[ 30 ] == 0xFF );
			buffer[ 30 ]--;
			break;

		case TEST_CORRUPT_END:
			/* Corrupt the PKCS #1 trailing zero.  The location is a bit 
			   complex to evaluate since the hash value is preceded by a
			   variable-length OID, the following are the values for SHA-2
			   and SHA-1.  Note that the SHA-2 value works for all sizes of
			   the hash since the OIDs are the same size */
#if defined( DEFAULT_ALGO_SHA2 )
			assert( buffer[ payloadStart - 20 ] == 0 );
			buffer[ payloadStart - 20 ]++;
#elif defined( DEFAULT_ALGO_SHA1 )
			assert( buffer[ payloadStart - 14 ] == 0 );
			buffer[ payloadStart - 14 ]++;
#else
	#error Need to set magic value for default hash algorithm in PKCS #1 test
#endif /* DEFAULT_ALGO_xxx */
			break;

		case TEST_CORRUPT_OID:
			/* Corrupt the OID/ASN.1 data that precedes the hash value, see 
			   above for the magic values used.  For SHA-2 we corrupt the '3'
			   in ( 2 16 840 1 101 3 4 2 1 ) */
#ifdef DEFAULT_ALGO_SHA2
			assert( buffer[ payloadStart - 8 ] == 0x03 );
			buffer[ payloadStart - 6 ]++;
#else
			buffer[ payloadStart - 10 ]++;
#endif /* DEFAULT_ALGO_xxx */
			break;

		case TEST_CORRUPT_HASH:
			/* Corrupt the hash value.  This is preceded by 0x04 0x20 as the 
			   OCTET STRING wrapper */
			assert( buffer[ payloadStart - 2 ] == 0x04 );
			buffer[ payloadStart + 8 ]++;
			break;

#ifdef USE_PSS
		case TEST_CORRUPT_MASKEDDB:
			/* Corrupt the masked DB, specifically the portion corresponding 
			   to the padding */
			buffer[ 30 ]--;
			break;

		case TEST_CORRUPT_SALT:
			/* Corrupt the salt value */
			buffer[ payloadStart + 8 ]++;
			break;

		case TEST_CORRUPT_MHASH:
			/* Corrupt the mHash value.  This is dependent on the hash 
			   algorithm type, the following is the value for SHA-1 */
			buffer[ payloadStart + 20 + 8 ]++;
			break;

		case TEST_CORRUPT_BC:
			/* Corrupt the 0xBC byte at the end of the data */
			assert( buffer[ length - 1 ] == 0xBC );
			buffer[ length - 1 ]++;
			break;
#endif /* USE_PSS */

		default:
			retIntError_Void();
		}
	}

CHECK_RETVAL \
static int testPKCS1( IN_ENUM( TEST ) const TEST_TYPE testType )
	{
#if CRYPT_MAX_PKCSIZE >= bitsToBytes( 2048 )
	/* SHA-256 test value from FIPS 180-2 */
	const BYTE hash[] = \
		{ 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 
		  0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24, 
		  0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 
		  0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55 };
 	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	STREAM stream;
	int length = 256, status;

	static_assert( CRYPT_MAX_PKCSIZE >= 256, "CRYPT_MAX_PKCSIZE size" );

	REQUIRES( isEnumRange( testType, TEST ) );

	/* Create the PKCS #1 signature block */
	sMemOpen( &stream, buffer, length );
	status = encodePKCS1( &stream, DEFAULT_HASH_ALGO, hash, 
						  DEFAULT_HASH_PARAM, length );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Manipulate the data as required */
	manipulateDataBlock( buffer, length, length - DEFAULT_HASH_PARAM, 
						 testType );

	/* Verify the signature block and make sure that we got back what we 
	   put in */
	sMemConnect( &stream, buffer, length );
	status = decodePKCS1( &stream, length );
	if( cryptStatusError( status ) )
		return( status );
	return( compareHashInfo( &stream, DEFAULT_HASH_ALGO, hash, 
							 DEFAULT_HASH_PARAM ) );
#else
  #if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
	#pragma message( "  Skipping PKCS #1 self-test since CRYPT_MAX_PKCSIZE < 2048 bits." )
  #endif /* Notify skipping of PKCS #1 test */
	return( CRYPT_OK );
#endif /* 2048-bit bignums */
	}

#ifdef USE_PSS

CHECK_RETVAL \
static int testPSS( IN_ENUM( TEST ) const TEST_TYPE testType )
	{
	#define PSS_BUFSIZE		256
	/* PSS test data from NIST RSA-PSS test vectors */
	static const BYTE message[] = \
			{ 0x37, 0xB6, 0x6A, 0xE0, 0x44, 0x58, 0x43, 0x35, 
			  0x3D, 0x47, 0xEC, 0xB0, 0xB4, 0xFD, 0x14, 0xC1, 
			  0x10, 0xE6, 0x2D, 0x6A };
	static const BYTE sha1Salt[] = \
			{ 0xE3, 0xB5, 0xD5, 0xD0, 0x02, 0xC1, 0xBC, 0xE5, 
			  0x0C, 0x2B, 0x65, 0xEF, 0x88, 0xA1, 0x88, 0xD8, 
			  0x3B, 0xCE, 0x7E, 0x61 };
	static const BYTE sha1EM[] = \
			{ 0x06, 0xE4, 0x67, 0x2E, 0x83, 0x6A, 0xD1, 0x21, 
			  0xBA, 0x24, 0x4B, 0xED, 0x65, 0x76, 0xB8, 0x67,
			  0xD9, 0xA4, 0x47, 0xC2, 0x8A, 0x6E, 0x66, 0xA5, 
			  0xB8, 0x7D, 0xEE, 0x7F, 0xBC, 0x7E, 0x65, 0xAF,
			  0x50, 0x57, 0xF8, 0x6F, 0xAE, 0x89, 0x84, 0xD9, 
			  0xBA, 0x7F, 0x96, 0x9A, 0xD6, 0xFE, 0x02, 0xA4,
			  0xD7, 0x5F, 0x74, 0x45, 0xFE, 0xFD, 0xD8, 0x5B, 
			  0x6D, 0x3A, 0x47, 0x7C, 0x28, 0xD2, 0x4B, 0xA1,
			  0xE3, 0x75, 0x6F, 0x79, 0x2D, 0xD1, 0xDC, 0xE8, 
			  0xCA, 0x94, 0x44, 0x0E, 0xCB, 0x52, 0x79, 0xEC,
			  0xD3, 0x18, 0x3A, 0x31, 0x1F, 0xC8, 0x96, 0xDA, 
			  0x1C, 0xB3, 0x93, 0x11, 0xAF, 0x37, 0xEA, 0x4A,
			  0x75, 0xE2, 0x4B, 0xDB, 0xFD, 0x5C, 0x1D, 0xA0, 
			  0xDE, 0x7C, 0xEC, 0xDF, 0x1A, 0x89, 0x6F, 0x9D,
			  0x8B, 0xC8, 0x16, 0xD9, 0x7C, 0xD7, 0xA2, 0xC4, 
			  0x3B, 0xAD, 0x54, 0x6F, 0xBE, 0x8C, 0xFE, 0xBC };
	/* Arbitrary values for non-SHA1 tests, these being the first two hash
	   values from the SHA2-512 self-test */
	static const BYTE salt64[] = \
			{ 0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD, 
			  0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6D, 0x80, 0x07, 
			  0xD6, 0x20, 0xE4, 0x05, 0x0B, 0x57, 0x15, 0xDC, 
			  0x83, 0xF4, 0xA9, 0x21, 0xD3, 0x6C, 0xE9, 0xCE, 
			  0x47, 0xD0, 0xD1, 0x3C, 0x5D, 0x85, 0xF2, 0xB0, 
			  0xFF, 0x83, 0x18, 0xD2, 0x87, 0x7E, 0xEC, 0x2F, 
			  0x63, 0xB9, 0x31, 0xBD, 0x47, 0x41, 0x7A, 0x81, 
			  0xA5, 0x38, 0x32, 0x7A, 0xF9, 0x27, 0xDA, 0x3E };
	static const BYTE message64[] = \
			{ 0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
			  0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
			  0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
			  0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
			  0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
			  0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
			  0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
			  0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F };
	BYTE buffer[ PSS_BUFSIZE + 8 ], outMessage[ CRYPT_MAX_HASHSIZE + 8 ];
	int outLen DUMMY_INIT, status;

	REQUIRES( isEnumRange( testType, TEST ) );

	/* SHA-1.  We restrict the data size to a fixed 128 bytes rather than 
	   the full PSS_BUFSIZE for this test because the NIST test vectors also 
	   use 128 bytes */
	memset( buffer, '*', PSS_BUFSIZE );
	status = generatePssDataBlock( buffer, 128, sha1Salt, 20, 
								   CRYPT_ALGO_SHA1, message, 20, 1021 );
	if( cryptStatusOK( status ) && memcmp( buffer, sha1EM, 128 ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusOK( status ) )
		{
		manipulateDataBlock( buffer, 128, 128 - ( 20 + 20 + 1 ), testType );
		status = recoverPssDataBlock( outMessage, CRYPT_MAX_HASHSIZE, 
									  &outLen, buffer, 128, 
									  CRYPT_ALGO_SHA1, message, 20, 1021 );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( outLen != 20 || \
		memcmp( buffer + 128 - ( 20 + 1 ), outMessage, outLen ) )
		return( CRYPT_ERROR_SIGNATURE );

	/* SHA-2 */
	memset( buffer, '*', PSS_BUFSIZE );
	status = generatePssDataBlock( buffer, PSS_BUFSIZE, salt64, 32, 
								   CRYPT_ALGO_SHA2, message64, 32, 2045 );
	if( cryptStatusOK( status ) )
		{
		manipulateDataBlock( buffer, PSS_BUFSIZE, 
							 PSS_BUFSIZE - ( 32 + 32 + 1 ), testType );
		status = recoverPssDataBlock( outMessage, CRYPT_MAX_HASHSIZE, 
									  &outLen, buffer, PSS_BUFSIZE, 
									  CRYPT_ALGO_SHA2, message64, 32, 2045 );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( outLen != 32 || \
		memcmp( buffer + PSS_BUFSIZE - ( 32 + 1 ), outMessage, outLen ) )
		return( CRYPT_ERROR_SIGNATURE );

	/* SHA-2 512-bit */
#ifdef USE_SHA2_EXT
	memset( buffer, '*', PSS_BUFSIZE );
	status = generatePssDataBlock( buffer, PSS_BUFSIZE, salt64, 64, 
								   CRYPT_ALGO_SHA2, message64, 64, 2045 );
	if( cryptStatusOK( status ) )
		{
		manipulateDataBlock( buffer, PSS_BUFSIZE, 
							 PSS_BUFSIZE - ( 64 + 64 + 1 ), testType );
		status = recoverPssDataBlock( outMessage, CRYPT_MAX_HASHSIZE, 
									  &outLen, buffer, PSS_BUFSIZE, 
									  CRYPT_ALGO_SHA2, message64, 64, 2045 );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( outLen != 64 || \
		memcmp( buffer + PSS_BUFSIZE - ( 64 + 1 ), outMessage, outLen ) )
		return( CRYPT_ERROR_SIGNATURE );
#endif /* USE_SHA2_EXT */

	return( CRYPT_OK );
	}
#endif /* USE_PSS */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int signSelftest( STDC_UNUSED void *dummy, 
				  STDC_UNUSED MECHANISM_SIGN_INFO *mechanismInfo )
	{
	int status;

	UNUSED_ARG_OPT( dummy );
	UNUSED_ARG( mechanismInfo );

	status = testPKCS1( TEST_NORMAL );
	if( cryptStatusError( status ) )
		{
		DEBUG_PRINT(( "Mechanism self-test for PKCS1 sig/sigcheck "
					  "mechanism failed.\n" ));
		return( status );
		}
	status = testPKCS1( TEST_CORRUPT_START );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPKCS1( TEST_CORRUPT_BLOCKTYPE );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPKCS1( TEST_CORRUPT_PADDING );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPKCS1( TEST_CORRUPT_END );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPKCS1( TEST_CORRUPT_OID );
	else
		status = CRYPT_OK;	/* Force following tests to fail */
	if( status == CRYPT_ERROR_NOTAVAIL )
		status = testPKCS1( TEST_CORRUPT_HASH );
	else
		status = CRYPT_OK;	/* Force following tests to fail */
	if( status != CRYPT_ERROR_SIGNATURE )
		{
		DEBUG_PRINT(( "Data corruption self-test for PKCS1 sig/sigcheck "
					  "mechanism failed.\n" ));
		return( status );
		}
#ifdef USE_PSS
	status = testPSS( TEST_NORMAL );
	if( cryptStatusError( status ) )
		{
		DEBUG_PRINT(( "Mechanism self-test for PSS sig/sigcheck "
					  "mechanism failed.\n" ));
		return( status );
		}
	status = testPSS( TEST_CORRUPT_START );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPSS( TEST_CORRUPT_MASKEDDB );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPSS( TEST_CORRUPT_MHASH );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPSS( TEST_CORRUPT_BC );
	if( status == CRYPT_ERROR_BADDATA )
		status = testPSS( TEST_CORRUPT_SALT );
	else
		status = CRYPT_OK;	/* Force following tests to fail */
	if( status != CRYPT_ERROR_SIGNATURE )
		{
		DEBUG_PRINT(( "Data corruption self-test for PSS sig/sigcheck "
					  "mechanism failed.\n" ));
		return( status );
		}
#endif /* USE_PSS */

	return( CRYPT_OK );
	}
#endif /* CONFIG_NO_SELFTEST */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
