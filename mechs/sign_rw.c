/****************************************************************************
*																			*
*						  Signature Read/Write Routines						*
*						Copyright Peter Gutmann 1992-2020					*
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

/* The minimum size of a signature */

#if defined( USE_DSA )
  #define MIN_SIGNATURE_SIZE	( 18 + 18 )
#elif defined( USE_ECDSA )
  #define MIN_SIGNATURE_SIZE	MIN_PKCSIZE_ECCPOINT
#else
  #define MIN_SIGNATURE_SIZE	MIN_PKCSIZE
#endif /* Algorithm-specific minimum signature sizes */

/* Context-specific tags for the SignerInfo record */

enum { CTAG_SI_SKI };

/****************************************************************************
*																			*
*							X.509 Signature Routines						*
*																			*
****************************************************************************/

#ifdef USE_INT_ASN1

/* Read/write raw signatures */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRawSignature( INOUT_PTR STREAM *stream, 
							 OUT_PTR QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the start of the signature */
	status = readBitStringHole( stream, &queryInfo->dataLength, 
								MIN_SIGNATURE_SIZE, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, startPos, 
											  &queryInfo->dataStart );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, queryInfo->dataLength, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeRawSignature( INOUT_PTR STREAM *stream, 
							  STDC_UNUSED const CRYPT_CONTEXT iSignContext,
							  STDC_UNUSED const CRYPT_ALGO_TYPE hashAlgo,
							  STDC_UNUSED IN_LENGTH_HASH const int hashParam,
							  STDC_UNUSED const CRYPT_ALGO_TYPE signAlgo,
							  IN_BUFFER( signatureLength ) const BYTE *signature,
							  IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );
			/* Other parameters aren't used for this format */

	REQUIRES( isShortIntegerRangeMin( signatureLength, 40 ) );

	/* Write the BIT STRING wrapper and signature */
	writeBitStringHole( stream, signatureLength, DEFAULT_TAG );
	return( writeRawObject( stream, signature, signatureLength ) );
	}

/* Read/write X.509 signatures */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readX509Signature( INOUT_PTR STREAM *stream, 
							  OUT_PTR QUERY_INFO *queryInfo )
	{
	ALGOID_PARAMS algoIDparams;
	const int startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the signature/hash algorithm information followed by the start
	   of the signature */
	status = readAlgoIDex( stream, &queryInfo->cryptAlgo, &algoIDparams,
						   ALGOID_CLASS_PKCSIG );
	if( cryptStatusOK( status ) )
		{
		status = readBitStringHole( stream, &queryInfo->dataLength, 
									MIN_SIGNATURE_SIZE, DEFAULT_TAG );
		}
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, startPos, 
											  &queryInfo->dataStart );
		}
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->hashAlgo = algoIDparams.hashAlgo;
	queryInfo->hashParam = algoIDparams.hashParam; 

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, queryInfo->dataLength, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeX509Signature( INOUT_PTR STREAM *stream,
							   IN_HANDLE const CRYPT_CONTEXT iSignContext,
							   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							   IN_LENGTH_HASH_Z const int hashParam,
							   STDC_UNUSED const CRYPT_ALGO_TYPE signAlgo,
							   IN_BUFFER( signatureLength ) const BYTE *signature,
							   IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength )
	{
	ALGOID_PARAMS algoIDparams;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );
			/* Other parameters aren't used for this format */

	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashParam >= MIN_HASHSIZE && \
			  hashParam <= CRYPT_MAX_HASHSIZE );
	REQUIRES( isShortIntegerRangeMin( signatureLength, 40 ) );

	/* Write the hash+signature algorithm identifier followed by the BIT
	   STRING wrapper and signature */
	initAlgoIDparamsHash( &algoIDparams, hashAlgo, hashParam );
	writeContextAlgoIDex( stream, iSignContext, &algoIDparams );
	writeBitStringHole( stream, signatureLength, DEFAULT_TAG );
	return( writeRawObject( stream, signature, signatureLength ) );
	}
#endif /* USE_INT_ASN1 */

/****************************************************************************
*																			*
*							CMS Signature Routines							*
*																			*
****************************************************************************/

#ifdef USE_INT_CMS

/* Read/write PKCS #7/CMS (issuerAndSerialNumber) signatures */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCmsSignature( INOUT_PTR STREAM *stream, 
							 OUT_PTR QUERY_INFO *queryInfo )
	{
	ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;
	const int startPos = stell( stream );
	long value, endPos;
	int tag, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	status = getStreamObjectLength( stream, &length, 16 );
	if( cryptStatusError( status ) )
		return( status );
	endPos = startPos + length;
	ENSURES( isIntegerRangeNZ( endPos ) );

	/* Read the header */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != SIGNATURE_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the issuer and serial number and hash algorithm ID.  Since we're 
	   recording the position of the issuerAndSerialNumber as a blob we have 
	   to use getStreamObjectLength() to get the overall blob data size */
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
	queryInfo->iAndSLength = length;
	status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDex( stream, &queryInfo->hashAlgo, &algoIDparams, 
							   ALGOID_CLASS_HASH );
		}
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->hashParam = algoIDparams.hashParam;

	/* Read the authenticated attributes if there are any present */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 0 ) )
		{
		status = getStreamObjectLength( stream, &length, 8 );
		if( cryptStatusOK( status ) && !isShortIntegerRangeNZ( length ) )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, startPos,
												  &queryInfo->attributeStart );
			}
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->attributeLength = length;
		status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the CMS/cryptlib signature algorithm and the start of the 
	   signature.  CMS separates the signature algorithm from the hash 
	   algorithm so we read it as ALGOID_CLASS_PKC and not 
	   ALGOID_CLASS_PKCSIG.  Unfortunately some buggy implementations get 
	   this wrong and write an algorithm+hash algoID, to get around this the
	   decoding table contains an alternative interpretation of the
	   ALGOID_CLASS_PKCSIG information pretending to be an 
	   ALGOID_CLASS_PKC.  This broken behaviour was codified in RFC 5652
	   (section 10.1.2, "SignatureAlgorithmIdentifier") so it's now part
	   of the standard */
	status = readAlgoIDex( stream, &queryInfo->cryptAlgo, &algoIDparams,
						   ALGOID_CLASS_PKC );
	if( cryptStatusOK( status ) )
		{
		status = readOctetStringHole( stream, &queryInfo->dataLength, 
									  MIN_SIGNATURE_SIZE, DEFAULT_TAG );
		}
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, startPos,
											  &queryInfo->dataStart );
		}
	if( cryptStatusOK( status ) )
		{
		status = sSkip( stream, queryInfo->dataLength, 
						MAX_INTLENGTH_SHORT );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( algoIDparams.encodingType != ALGOID_ENCODING_NONE )
		{
		/* If an alternative encoding is being used, record this and make
		   sure that the additional hash parameters specified for it match
		   the hash parameters that we read earlier on */
		queryInfo->cryptAlgoEncoding = algoIDparams.encodingType;
		if( queryInfo->hashAlgo != algoIDparams.hashAlgo || \
			queryInfo->hashParam != algoIDparams.hashParam )
			return( CRYPT_ERROR_BADDATA );
		}

	/* Read the unauthenticated attributes if there are any present */
	if( stell( stream ) < endPos && \
		checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 1 ) )
		{
		status = getStreamObjectLength( stream, &length, 8 );
		if( cryptStatusOK( status ) && !isShortIntegerRangeNZ( length ) )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, startPos,
										&queryInfo->unauthAttributeStart );
			}
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->unauthAttributeLength = length;
		status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* Make sure that we've read everything present */
	if( stell( stream ) != endPos )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeSignature( INOUT_PTR STREAM *stream,
						   IN_HANDLE const CRYPT_CONTEXT iSignContext,
						   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						   IN_LENGTH_HASH const int hashParam,
						   STDC_UNUSED const CRYPT_ALGO_TYPE signAlgo,
						   IN_BUFFER( signatureLength ) const BYTE *signature,
						   IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength,
						   IN_BOOL const BOOLEAN usePSS )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );
			/* Other parameters aren't used for this format */

	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashParam >= MIN_HASHSIZE && hashParam <= CRYPT_MAX_HASHSIZE );
	REQUIRES( isShortIntegerRangeMin( signatureLength, 40 ) );
	REQUIRES( isBooleanValue( usePSS ) );

	/* Write the signature algorithm identifier and signature data.  The
	   handling of CMS signatures is non-orthogonal to readCmsSignature()
	   because creating a CMS signature involves adding assorted additional
	   data like iAndS and signed attributes that present too much
	   information to pass into a basic writeSignature() call */
#ifdef USE_PSS
	if( usePSS )
		{
		ALGOID_PARAMS algoIDparams;

		initAlgoIDparamsHash( &algoIDparams, hashAlgo, hashParam );
		algoIDparams.encodingType = ALGOID_ENCODING_PSS;
		writeAlgoIDex( stream, CRYPT_ALGO_RSA, &algoIDparams, DEFAULT_TAG );
		}
	else
#endif /* USE_PSS */
		writeContextAlgoID( stream, iSignContext );
	return( writeOctetString( stream, signature, signatureLength, DEFAULT_TAG ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeCmsSignature( INOUT_PTR STREAM *stream,
							  IN_HANDLE const CRYPT_CONTEXT iSignContext,
							  IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							  IN_LENGTH_HASH const int hashParam,
							  IN_ALGO const CRYPT_ALGO_TYPE signAlgo,
							  IN_BUFFER( signatureLength ) const BYTE *signature,
							  IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength )
	{
	return( writeSignature( stream, iSignContext, hashAlgo, hashParam, 
							signAlgo, signature, signatureLength, FALSE ) );
	}

#ifdef USE_PSS 

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeCmsSignaturePSS( INOUT_PTR STREAM *stream,
								 IN_HANDLE const CRYPT_CONTEXT iSignContext,
								 IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								 IN_LENGTH_HASH const int hashParam,
								 IN_ALGO const CRYPT_ALGO_TYPE signAlgo,
								 IN_BUFFER( signatureLength ) const BYTE *signature,
								 IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength )
	{
	return( writeSignature( stream, iSignContext, hashAlgo, hashParam, 
							signAlgo, signature, signatureLength, TRUE ) );
	}
#endif /* USE_PSS */

/* Read/write cryptlib/CMS (keyID) signatures */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCryptlibSignature( INOUT_PTR STREAM *stream, 
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

	/* Read the header */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != SIGNATURE_EX_VERSION )
		return( CRYPT_ERROR_BADDATA );

	/* Read the key ID and hash algorithm identifier */
	status = readOctetStringTag( stream, queryInfo->keyID, 
								 &queryInfo->keyIDlength, 8, 
								 CRYPT_MAX_HASHSIZE, CTAG_SI_SKI );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDex( stream, &queryInfo->hashAlgo, &algoIDparams,
							   ALGOID_CLASS_HASH );
		}
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->hashParam = algoIDparams.hashParam;

	/* Read the CMS/cryptlib signature algorithm and the start of the 
	   signature.  CMS separates the signature algorithm from the hash
	   algorithm so we we use ALGOID_CLASS_PKC rather than 
	   ALGOID_CLASS_PKCSIG */
	status = readAlgoID( stream, &queryInfo->cryptAlgo, ALGOID_CLASS_PKC );
	if( cryptStatusOK( status ) )
		{
		status = readOctetStringHole( stream, &queryInfo->dataLength, 
									  MIN_SIGNATURE_SIZE, DEFAULT_TAG );
		}
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, startPos,
											  &queryInfo->dataStart );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, queryInfo->dataLength, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeCryptlibSignature( INOUT_PTR STREAM *stream,
								   IN_HANDLE const CRYPT_CONTEXT iSignContext,
								   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								   STDC_UNUSED IN_LENGTH_HASH const int hashParam,
								   STDC_UNUSED const CRYPT_ALGO_TYPE signAlgo,
								   IN_BUFFER( signatureLength ) \
									const BYTE *signature,
								   IN_LENGTH_SHORT_MIN( 40 ) \
									const int signatureLength )
	{
	BYTE keyID[ 128 + 8 ];
	const int signAlgoIdSize = sizeofContextAlgoID( iSignContext );
	const int hashAlgoIdSize = sizeofAlgoID( hashAlgo );
	int keyIDlength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );
			/* Other parameters aren't used for this format */

	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( isShortIntegerRangeMin( signatureLength, 40 ) );

	if( cryptStatusError( signAlgoIdSize ) )
		return( signAlgoIdSize );
	if( cryptStatusError( hashAlgoIdSize ) )
		return( hashAlgoIdSize );

	/* Get the key ID */
	status = getCmsKeyIdentifier( iSignContext, keyID, 128, &keyIDlength );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the header */
	writeSequence( stream, sizeofShortInteger( SIGNATURE_EX_VERSION ) + \
				   sizeofObject( keyIDlength ) + \
				   signAlgoIdSize + hashAlgoIdSize + \
				   sizeofObject( signatureLength ) );

	/* Write the version, key ID and algorithm identifier */
	writeShortInteger( stream, SIGNATURE_EX_VERSION, DEFAULT_TAG );
	writeOctetString( stream, keyID, keyIDlength, CTAG_SI_SKI );
	writeAlgoID( stream, hashAlgo, DEFAULT_TAG );
	writeContextAlgoID( stream, iSignContext );
	return( writeOctetString( stream, signature, signatureLength, DEFAULT_TAG ) );
	}
#endif /* USE_INT_CMS */

/****************************************************************************
*																			*
*							PGP Signature Routines							*
*																			*
****************************************************************************/

#ifdef USE_PGP

/* Read a PGP type-and-value packet and check whether it's one of ours */

#define NAME_STRING			"issuerAndSerialNumber"
#define NAME_STRING_LENGTH	21

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readTypeAndValue( INOUT_PTR STREAM *stream, 
							 INOUT_PTR QUERY_INFO *queryInfo,
							 IN_LENGTH_Z const int startPos )
	{
	BYTE nameBuffer[ 32 + 8 ];
	int nameLength, valueLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );
	REQUIRES( startPos < stell( stream ) );

	/* Skip the flags */
	status = sSkip( stream, UINT32_SIZE, UINT32_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the attribute length information and make sure that it looks 
	   valid */
	nameLength = readUint16( stream );
	status = valueLength = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( nameLength < 1 || nameLength > 255 || \
		!isShortIntegerRangeNZ( valueLength ) )
		{
		/* The RFC is, as usual, silent on what's a sane size for a type-
		   and-value pair, so we define our own, hopefully sensible, 
		   limits */
		return( CRYPT_ERROR_BADDATA );
		}
	if( nameLength != NAME_STRING_LENGTH || \
		valueLength < 16 || valueLength > 2048 )
		{
		/* This is a somewhat different check to the above one in that out-
		   of-range (but plausible) sizes are skipped rather than being 
		   counted as an error */
		return( sSkip( stream, nameLength + valueLength, 
					   MAX_INTLENGTH_SHORT ) );
		}

	/* Read the name and check whether it's one that we recognise */
	status = sread( stream, nameBuffer, NAME_STRING_LENGTH );
	if( cryptStatusError( status ) )
		return( status );
	if( !memcmp( nameBuffer, NAME_STRING, NAME_STRING_LENGTH ) )
		{
		/* It's an issuerAndSerialNumber, remember it for later */
		status = calculateStreamObjectLength( stream, startPos,
											  &queryInfo->iAndSStart );
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->iAndSLength = valueLength;
		}
	return( sSkip( stream, valueLength, MAX_INTLENGTH_SHORT ) );
	}

/* Read signature subpackets.  In theory we could do something with the 
   isAuthenticated flag but at the moment we don't rely on any attributes 
   that require authentication.  The most that an attacker can do by 
   changing the keyID/iAndS field is cause the signature check to fail, 
   which they can do just as easily by flipping a bit */

#define MAX_STANDARD_SUBPACKET		( 32 + 1 )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readSignatureSubpackets( INOUT_PTR STREAM *stream, 
									INOUT_PTR QUERY_INFO *queryInfo,
									IN_LENGTH_SHORT const int length, 
									IN_DATALENGTH_Z const int startPos,
									IN_BOOL const BOOLEAN isAuthenticated )
	{
	BOOLEAN subPacketSeen[ MAX_STANDARD_SUBPACKET + 8 ] = { FALSE };
	const int endPos = stell( stream ) + length;
	LOOP_INDEX noSubpackets;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	static_assert( MAX_STANDARD_SUBPACKET == PGP_SUBPACKET_LAST,
				   "MAX_STANDARD_SUBPACKET define != PGP_SUBPACKET_LAST enum" );
				   /* PGP_SUBPACKET_LAST is an enum so we can't use it to 
				      specify an array size */

	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( isBufsizeRange( startPos ) );
	REQUIRES( startPos < stell( stream ) );
	REQUIRES( isBooleanValue( isAuthenticated ) );
	REQUIRES( endPos >= length && endPos < MAX_BUFFER_SIZE );

	LOOP_MED( noSubpackets = 0, 
			  noSubpackets < 30 && stell( stream ) < endPos,
			  noSubpackets++ )
		{
		BOOLEAN isCritical = FALSE;
		int subpacketLength, type DUMMY_INIT, status;

		ENSURES( LOOP_INVARIANT_MED( noSubpackets, 0, 29 ) );

		/* Read the subpacket length and type */
		status = pgpReadShortLength( stream, &subpacketLength, 
									 PGP_CTB_OPENPGP );
		if( cryptStatusOK( status ) && subpacketLength < 1 )
			{
			/* We must have at least a packet-type indicator present */
			status = CRYPT_ERROR_BADDATA;
			}
		if( cryptStatusOK( status ) )
			status = type = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( type & 0x80 )
			{
			/* The MSB, which acts as a critical flag, is set, extract the 
			   type */
			isCritical = TRUE;
			type &= 0x7F;
			}

		/* If it's an unrecognised subpacket with the critical flag set,
		   reject the signature.  The range check isn't complete since there
		   are a few holes in the range, but since the holes presumably exist
		   because of deprecated subpacket types any new packets will be 
		   added at the end so it's safe to use */
		if( isCritical && type > PGP_SUBPACKET_LAST )
			return( CRYPT_ERROR_NOTAVAIL );

		/* If this is a duplicate subpacket, reject the signature.  The 
		   standard makes a PKI-style mess of this by stating (RFC 4880 
		   section 5.2.4.1) that "It is certainly possible for a signature 
		   to contain conflicting information in subpackets [...] an 
		   implementation SHOULD use the last subpacket in the signature, 
		   but MAY use any conflict resolution scheme that makes more 
		   sense".  Since "take some arbitrary implementation-defined 
		   action" makes next to no sense, we define our conflict resolution 
		   scheme to be to reject the signature data for being malformed.
		   
		   There are two possible exceptions for this, one is for "Notation 
		   Data" (type 20) type-and-value pairs which can have multiple
		   entries so we exclude that from the duplicate-checking, and
		   the second is the post-4880 "Intended Recipient Fingerprint"
		   (type 35), a somewhat artificial mechanism used to prevent 
		   forwarding of encrypted signed messages to a third party where
		   an attacker somehow obtains the 'SIGN( message )' part of 
		   'ENC( SIGN( message ) )' and forwards it to a different 
		   recipient.  Since these are draft-specification packets outside 
		   the range of MAX_STANDARD_SUBPACKET we don't need special-case 
		   handling for them yet */
		if( type >= 0 && type < MAX_STANDARD_SUBPACKET )
			{
			if( subPacketSeen[ type ] && \
				type != PGP_SUBPACKET_TYPEANDVALUE )
				{
				DEBUG_DIAG(( "Encountered duplicate subpacket type %d", 
							 type ));
				return( CRYPT_ERROR_INVALID );
				}
			subPacketSeen[ type ] = TRUE;
			}

		switch( type )
			{
			case PGP_SUBPACKET_TIME:
				/* Make sure that the length is valid */
				if( subpacketLength != 1 + UINT32_SIZE )
					return( CRYPT_ERROR_BADDATA );

				status = sSkip( stream, UINT32_SIZE, UINT32_SIZE );
				break;

			case PGP_SUBPACKET_KEYID:
				/* Make sure that the length is valid */
				if( subpacketLength != 1 + PGP_KEYID_SIZE )
					return( CRYPT_ERROR_BADDATA );

				/* If it's a key ID and we haven't already set this from a 
				   preceding one-pass signature packet (which can happen 
				   with detached signatures), set it now */
				if( queryInfo->keyIDlength <= 0 )
					{
					status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
					queryInfo->keyIDlength = PGP_KEYID_SIZE;
					}
				else
					{
					BYTE keyID[ PGP_KEYID_SIZE + 8 ];

					/* We've already got the ID, make sure that it matches 
					   the one that we're seeing now.  This is necessary 
					   because the information in the one-pass signature 
					   packet isn't authenticated while the second copy here 
					   is */
					status = sread( stream, keyID, PGP_KEYID_SIZE );
					if( cryptStatusOK( status ) && \
						( queryInfo->keyIDlength != PGP_KEYID_SIZE || \
						  memcmp( queryInfo->keyID, keyID, \
								  PGP_KEYID_SIZE ) ) )
						status = CRYPT_ERROR_INVALID;
					}
				break;

			case PGP_SUBPACKET_TYPEANDVALUE:
				/* It's a type-and-value packet (in PGP terminology notation 
				   data), check whether it's one of ours */
				status = readTypeAndValue( stream, queryInfo, startPos );
				break;

			default:
				/* It's something else, skip it and continue.  The -1 is for 
				   the packet type, which we've already read */
				if( subpacketLength > 1 )
					{
					status = sSkip( stream, subpacketLength - 1, 
									MAX_INTLENGTH_SHORT );
					}
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );
	if( noSubpackets >= 30 )
		{
		/* If we've found this many packets in a row all supposedly 
		   belonging to the same signature then there's something wrong */
		DEBUG_DIAG(( "Encountered more than %d subpackets for a single "
					 "signature", noSubpackets ));
		assert_nofuzz( DEBUG_WARN );
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* Make sure that the mandatory fields are present in the subpacket 
	   data.  We also need to check for the presence of the keyID but this
	   can be in either the authenticated or unauthenticated attributes so
	   it has to be checked by the calling function */
	if( isAuthenticated && !subPacketSeen[ PGP_SUBPACKET_TIME ] )
		return( CRYPT_ERROR_INVALID );

	return( CRYPT_OK );
	}

/* Signature info:

	byte	ctb = PGP_PACKET_SIGNATURE_ONEPASS
	byte[]	length
	byte	version = 3 (= OpenPGP, not the expected PGP3)
	byte	sigType
	byte	hashAlgo
	byte	sigAlgo
	byte[8]	keyID
	byte	1 
	
   This just repeats everything that's already present in the signature 
   itself (with the pubkey and hash algorithm bytes swapped):

	  [	byte	version = 4 ]
		byte	sigType
		byte	sigAlgo
		byte	hashAlgo
	  [ hashedSubpacketData including 'Issuer' = keyID ]
	  [ unhashedSubpacketData ]

   So the only thing that we actually need is the hashAlgo, it's up to the
   higher-level code to decide what it wants to do with the redundant
   information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readPgpOnepassSigPacket( INOUT_PTR STREAM *stream, 
							 INOUT_PTR QUERY_INFO *queryInfo )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	/* Make sure that the packet header is in order */
	status = getPgpPacketInfo( stream, queryInfo, QUERYOBJECT_SIGNATURE );
	if( cryptStatusError( status ) )
		return( status );
	if( queryInfo->size < 1 + 1 + 1 + 1 + PGP_KEYID_SIZE + 1 )
		return( CRYPT_ERROR_BADDATA );

	/* Skip the signature type and get the hash algorithm and signature 
	   algorithms */
	status = sgetc( stream );	/* Skip signature type */
	if( !cryptStatusError( status ) )
		{
		status = readPgpAlgo( stream, &queryInfo->hashAlgo, 
							  &queryInfo->hashParam, 
							  PGP_ALGOCLASS_HASH );
		}
	if( cryptStatusOK( status ) )
		{
		status = readPgpAlgo( stream, &queryInfo->cryptAlgo, 
							  &queryInfo->cryptParam, 
							  PGP_ALGOCLASS_SIGN );
		}
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->type = CRYPT_OBJECT_SIGNATURE;

	/* Get the PGP key ID and make sure that this isn't a nested signature */
	status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->keyIDlength = PGP_KEYID_SIZE;
	return( ( sgetc( stream ) != 1 ) ? CRYPT_ERROR_BADDATA : CRYPT_OK );
	}

/* Read/write PGP signatures.

		byte	ctb = PGP_PACKET_SIGNATURE
		byte[]	length
	v3:	byte	version = PGP_VER_3	v4: byte	version = PGP_VERSION_OPENPGP
		byte	infoLen = 5				byte	sigType
			byte	sigType				byte	sigAlgo
			byte[4]	sig.time			byte	hashAlgo
		byte[8]	keyID					uint16	length of auth.attributes
		byte	sigAlgo					byte[]	authenticated attributes
		byte	hashAlgo				uint16	length of unauth.attributes
		byte[2]	hash check				byte[]	unauthenticated attributes
		mpi(s)	signature							-- Contains keyID
										byte[2]	hash check
										mpi(s)	signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgp2SigInfo( INOUT_PTR STREAM *stream, 
							INOUT_PTR QUERY_INFO *queryInfo,
							IN_DATALENGTH_Z const int startPos )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );
	REQUIRES( startPos < stell( stream ) );

	/* Read PGP 2.x additional signature information */
	status = length = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 5 )
		return( CRYPT_ERROR_BADDATA );
	status = calculateStreamObjectLength( stream, startPos,
										  &queryInfo->attributeStart );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->attributeLength = 5;
	status = sSkip( stream, 5, 5 );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the signer keyID and signature and hash algorithms */
	status = sread( stream, queryInfo->keyID, PGP_KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->keyIDlength = PGP_KEYID_SIZE;
	status = readPgpAlgo( stream, &queryInfo->cryptAlgo, 
						  &queryInfo->cryptParam, PGP_ALGOCLASS_SIGN );
	if( cryptStatusOK( status ) )
		{
		status = readPgpAlgo( stream, &queryInfo->hashAlgo, 
							  &queryInfo->hashParam, 
							  PGP_ALGOCLASS_HASH );
		}
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readOpenPgpSigInfo( INOUT_PTR STREAM *stream, 
							   INOUT_PTR QUERY_INFO *queryInfo,
							   IN_DATALENGTH_Z const int startPos )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );
	REQUIRES( startPos < stell( stream ) );

	/* Remember the extra data to be hashed and read the signature and hash 
	   algorithms.  Since the extra data starts at the version byte that 
	   we've already read, we add an offset of 1 to the start position, as 
	   well as including it in the overall length calculation */
	status = calculateStreamObjectLength( stream, startPos + 1,
										  &queryInfo->attributeStart );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->attributeLength = PGP_VERSION_SIZE + 1 + \
								 PGP_ALGOID_SIZE + PGP_ALGOID_SIZE;
	status = sgetc( stream );	/* Skip signature type */
	if( !cryptStatusError( status ) )
		{
		status = readPgpAlgo( stream, &queryInfo->cryptAlgo, 
							  &queryInfo->cryptParam, 
							  PGP_ALGOCLASS_SIGN );
		}
	if( cryptStatusOK( status ) )
		{
		status = readPgpAlgo( stream, &queryInfo->hashAlgo, 
							  &queryInfo->hashParam, 
							  PGP_ALGOCLASS_HASH );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Process the authenticated attributes */
	status = length = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length < 0 || length > 2048 )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->attributeLength += UINT16_SIZE + length;
	if( length > 0 )
		{
		status = readSignatureSubpackets( stream, queryInfo, length,
										  startPos, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the unauthenticated attributes */
	status = calculateStreamObjectLength( stream, startPos,
										  &queryInfo->unauthAttributeStart );
	if( cryptStatusError( status ) )
		return( status );
	status = length = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length < 0 || length > 2048 )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->unauthAttributeLength = UINT16_SIZE + length;
	if( length > 0 )
		{
		status = readSignatureSubpackets( stream, queryInfo, length, 
										  startPos, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check the the presence of required attributes.  The mandatory ones 
	   per the RFC are checked when the authenticated attributes are being
	   read, however the keyID, which is required to check the signature,
	   can be present in either the authenticated or unauthenticated
	   attributes depending on the mood of the implementer, so we have to
	   check for it outside the attribute-read code */
	if( queryInfo->keyIDlength <= 0 )
		return( CRYPT_ERROR_INVALID );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgpSignature( INOUT_PTR STREAM *stream, 
							 OUT_PTR QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Make sure that the packet header is in order */
	status = getPgpPacketInfo( stream, queryInfo, QUERYOBJECT_SIGNATURE );
	if( cryptStatusError( status ) )
		return( status );
	if( queryInfo->size < 16 )
		return( CRYPT_ERROR_BADDATA );

	/* Read the signing attributes and skip the hash check */
	if( queryInfo->version == PGP_VERSION_2 )
		status = readPgp2SigInfo( stream, queryInfo, startPos );
	else
		status = readOpenPgpSigInfo( stream, queryInfo, startPos );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, 2, 2 );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the signature, recording the position and length of the raw RSA 
	   signature data.  We have to be careful how we handle this because 
	   readInteger16Ubits() returns the canonicalised form of the values 
	   (with leading zeroes truncated) so an stell() before the read doesn't 
	   necessarily represent the start of the payload:

		startPos	dataStart		 stell()
			|			|				|
			v			v <-- length -->v
		+---+-----------+---------------+
		|	|			|///////////////| Stream
		+---+-----------+---------------+ */
	if( queryInfo->cryptAlgo == CRYPT_ALGO_RSA )
		{
		int objectSize DUMMY_INIT;

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
		}
	else
		{
		const int dataStartPos = stell( stream );
		int dummy;

		REQUIRES( isBufsizeRangeNZ( dataStartPos ) );
		REQUIRES( queryInfo->cryptAlgo == CRYPT_ALGO_DSA );

		/* Read the DSA signature, recording the position and combined 
		   lengths of the MPI pair.  Again, we can't use the length returned 
		   by readInteger16Ubits() to determine the overall size but have to 
		   calculate it from the position in the stream */
		status = readInteger16Ubits( stream, NULL, &dummy, 16, 20, 
									 BIGNUM_CHECK_VALUE );
		if( cryptStatusOK( status ) )
			{
			status = readInteger16Ubits( stream, NULL, &dummy, 16, 20,
										 BIGNUM_CHECK_VALUE );
			}
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, dataStartPos,
												  &queryInfo->dataLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		queryInfo->dataStart = dataStartPos - startPos;
		}

	/* Make sure that we've read the entire object.  This check is necessary 
	   to detect corrupted length values, which can result in reading past 
	   the end of the object */
	if( ( stell( stream ) - startPos ) != queryInfo->size )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writePgpSignature( INOUT_PTR STREAM *stream,
							  STDC_UNUSED const CRYPT_CONTEXT iSignContext,
							  STDC_UNUSED const CRYPT_ALGO_TYPE hashAlgo,
							  STDC_UNUSED IN_LENGTH_HASH const int hashParam,
							  IN_ALGO const CRYPT_ALGO_TYPE signAlgo,
							  IN_BUFFER( signatureLength ) const BYTE *signature,
							  IN_LENGTH_SHORT_MIN( MIN_SIGNATURE_SIZE + 1 ) \
								const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );
			/* Other parameters aren't used for this format */

	REQUIRES( isPkcAlgo( signAlgo ) );
	REQUIRES( isShortIntegerRangeMin( signatureLength, 
									  MIN_SIGNATURE_SIZE ) );

	/* If it's a DLP/ECDLP algorithm then we've already specified the low-
	   level signature routines' output format as PGP so there's no need for 
	   further processing.  The handling of PGP signatures is non-orthogonal 
	   to readPgpSignature() because creating a PGP signature involves 
	   adding assorted additional data like key IDs and authenticated 
	   attributes, which present too much information to pass into a basic 
	   writeSignature() call */
	if( isDlpAlgo( signAlgo ) || isEccAlgo( signAlgo ) )
		return( swrite( stream, signature, signatureLength ) );

	/* Write the signature as a PGP MPI */
	return( writeInteger16Ubits( stream, signature, signatureLength ) );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*						Miscellaneous Signature Routines					*
*																			*
****************************************************************************/

#ifdef USE_SSH

/* Read/write SSH signatures.  SSH signature data is treated as a blob
   encoded as an SSH string rather than properly-formatted data so we don't
   encode/decode it as SSH MPIs */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readSshSignature( INOUT_PTR STREAM *stream, 
							 OUT_PTR QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	BYTE buffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the signature record size and algorithm information */
	readUint32( stream );
	status = readString32( stream, buffer, CRYPT_MAX_TEXTSIZE, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length == 7 )
		{
		/* If it's a string of length 7 then it's a conventional signature 
		   algorithm */
		if( !memcmp( buffer, "ssh-rsa", 7 ) )
			queryInfo->cryptAlgo = CRYPT_ALGO_RSA;
		else
			{
			if( !memcmp( buffer, "ssh-dss", 7 ) )
				queryInfo->cryptAlgo = CRYPT_ALGO_DSA;
			else
				return( CRYPT_ERROR_BADDATA );
			}
		queryInfo->hashAlgo = CRYPT_ALGO_SHA1;
		}
	else
		{
		if( length == 12 )
			{
			if( memcmp( buffer, "rsa-sha2-256", 12 ) )
				return( CRYPT_ERROR_BADDATA );
			queryInfo->cryptAlgo = CRYPT_ALGO_RSA;
			queryInfo->hashAlgo = CRYPT_ALGO_SHA2;
			}
		else
			{
			/* It's probably an ECC signature algorithm.  We don't bother 
			   checking the exact type since this is implicitly specified by 
			   the signature-check key */
			if( length < 19 )		/* "ecdsa-sha2-nistXXXX" */
				return( CRYPT_ERROR_BADDATA );
			if( memcmp( buffer, "ecdsa-sha2-nist", 15 ) )
				return( CRYPT_ERROR_BADDATA );
			queryInfo->cryptAlgo = CRYPT_ALGO_ECDSA;
			queryInfo->hashAlgo = CRYPT_ALGO_SHA2;
			}
		}

	/* Read the start of the signature */
	status = length = readUint32( stream );
	if( cryptStatusError( status ) )
		return( status );
	switch( queryInfo->cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			if( length < MIN_PKCSIZE || length > CRYPT_MAX_PKCSIZE )
				return( CRYPT_ERROR_BADDATA );
			break;

		case CRYPT_ALGO_DSA:
			if( length != ( 20 + 20 ) )
				return( CRYPT_ERROR_BADDATA );
			break;
		
		case CRYPT_ALGO_ECDSA:
			if( length < MIN_PKCSIZE_ECCPOINT || \
				length > MAX_PKCSIZE_ECCPOINT )
				return( CRYPT_ERROR_BADDATA );
			break;

		default:
			retIntError();
		}
	status = calculateStreamObjectLength( stream, startPos,
										  &queryInfo->dataStart );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->dataLength = length;

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, length, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeSshSignature( INOUT_PTR STREAM *stream,
#ifdef USE_ECDSA
							  const CRYPT_CONTEXT iSignContext,
#else
							  STDC_UNUSED const CRYPT_CONTEXT iSignContext,
#endif /* !USE_ECDSA */
							  const CRYPT_ALGO_TYPE hashAlgo,
							  STDC_UNUSED IN_LENGTH_HASH const int hashParam,
							  IN_ALGO const CRYPT_ALGO_TYPE signAlgo,
							  IN_BUFFER( signatureLength ) const BYTE *signature,
							  IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );
			/* Other parameters aren't used for this format */

	REQUIRES( hashAlgo == CRYPT_ALGO_SHA1 || hashAlgo == CRYPT_ALGO_SHA2 );
	REQUIRES( signAlgo == CRYPT_ALGO_RSA || signAlgo == CRYPT_ALGO_DSA || \
			  signAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( isShortIntegerRangeMin( signatureLength, ( 20 + 20 ) ) );

#ifdef USE_ECDSA
	/* ECC signatures require all sorts of calisthenics that aren't 
	   necessary for standard signatures, specifically we have to encode the
	   curve type in the algorithm name.  See the long comment in 
	   session/ssh.c on the possible problems that the following can run 
	   into */
	if( signAlgo == CRYPT_ALGO_ECDSA )
		{
		const char *algoName;
		int keySize, algoNameLen, status;

		status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE, 
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		switch( keySize )
			{
			case bitsToBytes( 256 ):
				algoName = "ecdsa-sha2-nistp256";
				algoNameLen = 19;
				break;

#ifdef USE_SHA2_EXT
			case bitsToBytes( 384 ):
				algoName = "ecdsa-sha2-nistp384";
				algoNameLen = 19;
				break;

			case bitsToBytes( 521 ):
				algoName = "ecdsa-sha2-nistp521";
				algoNameLen = 19;
				break;
#endif /* USE_SHA2_EXT */

			default:
				retIntError();
			}

		writeUint32( stream, sizeofString32( algoNameLen ) + \
							 sizeofString32( signatureLength ) );
		writeString32( stream, algoName, algoNameLen );
		return( writeString32( stream, signature, signatureLength ) );
		}
#endif /* USE_ECDSA */

	/* Write a non-ECC signature */
	if( hashAlgo == CRYPT_ALGO_SHA1 )
		{
		writeUint32( stream, sizeofString32( 7 ) + \
							 sizeofString32( signatureLength ) );
		writeString32( stream, ( signAlgo == CRYPT_ALGO_RSA ) ? \
							   "ssh-rsa" : "ssh-dss", 7 );
		}
	else
		{
		REQUIRES( signAlgo == CRYPT_ALGO_RSA && \
				  hashAlgo == CRYPT_ALGO_SHA2 );

		writeUint32( stream, sizeofString32( 12 ) + \
							 sizeofString32( signatureLength ) );
		writeString32( stream, "rsa-sha2-256", 12 );
		}
	return( writeString32( stream, signature, signatureLength ) );
	}
#endif /* USE_SSH */

#ifdef USE_TLS

/* Read/write TLS signatures.  This is just a raw signature without any
   encapsulation */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readTlsSignature( INOUT_PTR STREAM *stream, 
							 OUT_PTR QUERY_INFO *queryInfo )
	{
	const int startPos = stell( stream );
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the start of the signature */
	status = length = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length < min( MIN_PKCSIZE, MIN_PKCSIZE_ECCPOINT ) || \
		length > CRYPT_MAX_PKCSIZE )
		return( CRYPT_ERROR_BADDATA );
	status = calculateStreamObjectLength( stream, startPos,
										  &queryInfo->dataStart );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->dataLength = length;

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, length, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeTlsSignature( INOUT_PTR STREAM *stream,
							  STDC_UNUSED const CRYPT_CONTEXT iSignContext,
							  STDC_UNUSED const CRYPT_ALGO_TYPE hashAlgo,
							  STDC_UNUSED IN_LENGTH_HASH const int hashParam,
							  STDC_UNUSED const CRYPT_ALGO_TYPE signAlgo,
							  IN_BUFFER( signatureLength ) const BYTE *signature,
							  IN_LENGTH_SHORT_MIN( MIN_SIGNATURE_SIZE + 1 ) \
								const int signatureLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );
			/* Other parameters aren't used for this format */

	REQUIRES( isShortIntegerRangeMin( signatureLength, 
									  MIN_SIGNATURE_SIZE ) );

	writeUint16( stream, signatureLength );
	return( swrite( stream, signature, signatureLength ) );
	}

/* Read/write TLS 1.2 signatures, which specify a hash algorithm before the 
   signature and use PKCS #1 formatting instead of TLS's raw dual-hash.
   TLS 1.3 then made a complete dog's breakfast of this, see the long 
   comment in tls_ext.c:readSignatureAlgos() for more details and to
   understand what's going on for the TLS 1.3 entries below */

typedef struct {
	const int sigHashAlgoID;
	const CRYPT_ALGO_TYPE sigAlgo, hashAlgo;
	const int hashParam;
	const ALGOID_ENCODING_TYPE encodingType;
	} TLS_SIGHASH_INFO;

static const TLS_SIGHASH_INFO sigHashInfo[] = {
	/* RSA */
	{ /* RSA + MD5 */ 0x0101, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_MD5, bitsToBytes( 128 ) },
	{ /* RSA + SHA1 */ 0x0201, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA1, bitsToBytes( 160 ) },
	{ /* RSA + SHA2 */ 0x0401, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
#ifdef USE_SHA2_EXT
	{ /* RSA + SHA384 */ 0x0501, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 384 ) },
	{ /* RSA + SHA512 */ 0x0601, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 512 ) },
#endif /* USE_SHA2_EXT */
#if defined( USE_TLS13 ) && defined( USE_PSS )
	{ /* RSA-PSS + SHA2 */ 0x0804, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 256 ), ALGOID_ENCODING_PSS },
	{ /* RSA-PSS + SHA2 */ 0x0809, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 256 ), ALGOID_ENCODING_PSS },
  #ifdef USE_SHA2_EXT
	{ /* RSA-PSS + SHA384 */ 0x0805, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 384 ), ALGOID_ENCODING_PSS },
	{ /* RSA-PSS + SHA384 */ 0x080A, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 384 ), ALGOID_ENCODING_PSS },
	{ /* RSA-PSS + SHA512 */ 0x0806, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 512 ), ALGOID_ENCODING_PSS },
	{ /* RSA-PSS + SHA512 */ 0x0809, CRYPT_ALGO_RSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 512 ), ALGOID_ENCODING_PSS },
  #endif /* USE_SHA2_EXT */
#endif /* USE_TLS13 && USE_PSS */

	/* DSA */
#ifdef USE_DSA
	{ /* DSA + SHA1 */ 0x0202, CRYPT_ALGO_DSA,
	  CRYPT_ALGO_SHA1, bitsToBytes( 160 ) },
	{ /* DSA + SHA2 */ 0x0402, CRYPT_ALGO_DSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
#endif /* USE_DSA */

	/* ECDSA */
#ifdef USE_ECDSA
	{ /* ECDSA + SHA1 */ 0x0203, CRYPT_ALGO_ECDSA,
	  CRYPT_ALGO_SHA1, bitsToBytes( 160 ) },
	{ /* ECDSA + SHA2 */ 0x0403, CRYPT_ALGO_ECDSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
  #ifdef USE_SHA2_EXT
	{ /* ECDSA + SHA384 */ 0x0503, CRYPT_ALGO_ECDSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 384 ) },
	{ /* ECDSA + SHA512 */ 0x0603, CRYPT_ALGO_ECDSA,
	  CRYPT_ALGO_SHA2, bitsToBytes( 512 ) },  
  #endif /* USE_SHA2_EXT */
#endif /* USE_ECDSA */

	{ CRYPT_ERROR, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE }, 
		{ CRYPT_ERROR, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readTls12Signature( INOUT_PTR STREAM *stream, 
							   OUT_PTR QUERY_INFO *queryInfo )
	{
	const TLS_SIGHASH_INFO *sigHashInfoPtr = NULL;
	const int startPos = stell( stream );
	LOOP_INDEX i;
	int sigHashAlgoID, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isBufsizeRange( startPos ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the hash and signature algorithm data */
	status = sigHashAlgoID = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( sigHashInfo, TLS_SIGHASH_INFO ) && \
					sigHashInfo[ i ].sigHashAlgoID != CRYPT_ERROR, 
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( sigHashInfo, \
														 TLS_SIGHASH_INFO ) - 1 ) );

		if( sigHashInfo[ i ].sigHashAlgoID == sigHashAlgoID )
			{
			sigHashInfoPtr = &sigHashInfo[ i ];
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( sigHashInfo, TLS_SIGHASH_INFO ) );
	if( sigHashInfoPtr == NULL )
		return( CRYPT_ERROR_NOTAVAIL );
	queryInfo->cryptAlgo = sigHashInfoPtr->sigAlgo;
	queryInfo->hashAlgo = sigHashInfoPtr->hashAlgo;
	queryInfo->hashParam = sigHashInfoPtr->hashParam;
	queryInfo->cryptAlgoEncoding = sigHashInfoPtr->encodingType;

	/* Read the start of the signature */
	status = length = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length < min( MIN_PKCSIZE, MIN_PKCSIZE_ECCPOINT ) || \
		length > CRYPT_MAX_PKCSIZE )
		return( CRYPT_ERROR_BADDATA );
	status = calculateStreamObjectLength( stream, startPos,
										  &queryInfo->dataStart );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->dataLength = length;

	/* Make sure that the remaining signature data is present */
	return( sSkip( stream, length, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
static int writeTls1XSignature( INOUT_PTR STREAM *stream,
								IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								IN_LENGTH_HASH_Z const int hashParam,
								IN_ALGO const CRYPT_ALGO_TYPE signAlgo,
								IN_BUFFER( signatureLength ) const BYTE *signature,
								IN_LENGTH_SHORT_MIN( MIN_SIGNATURE_SIZE + 1 ) \
									const int signatureLength,
								IN_BOOL const BOOLEAN useRSAPSS )
	{
	const TLS_SIGHASH_INFO *sigHashInfoPtr = NULL;
	const ALGOID_ENCODING_TYPE encodingType = useRSAPSS ? \
					ALGOID_ENCODING_PSS : ALGOID_ENCODING_NONE;
	LOOP_INDEX i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );

	REQUIRES( hashAlgo == CRYPT_ALGO_SHA1 || hashAlgo == CRYPT_ALGO_SHA2 );
	REQUIRES( hashParam == 0 || \
			  ( hashParam >= MIN_HASHSIZE && \
				hashParam <= CRYPT_MAX_HASHSIZE ) );
	REQUIRES( isShortIntegerRangeMin( signatureLength, 
									  MIN_SIGNATURE_SIZE ) );
	REQUIRES( isBooleanValue( useRSAPSS ) );

	/* Write the signature and hash algorithm data */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( sigHashInfo, TLS_SIGHASH_INFO ) && \
					sigHashInfo[ i ].sigHashAlgoID != CRYPT_ERROR, 
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( sigHashInfo, \
														 TLS_SIGHASH_INFO ) - 1 ) );

		if( sigHashInfo[ i ].sigAlgo == signAlgo && \
			sigHashInfo[ i ].hashAlgo == hashAlgo && \
			sigHashInfo[ i ].hashParam == hashParam && \
			sigHashInfo[ i ].encodingType == encodingType )
			{
			sigHashInfoPtr = &sigHashInfo[ i ];
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( sigHashInfo, TLS_SIGHASH_INFO ) );
	ENSURES( sigHashInfoPtr != NULL );
	writeUint16( stream, sigHashInfoPtr->sigHashAlgoID );

	/* Write the signature itself */
	writeUint16( stream, signatureLength );
	return( swrite( stream, signature, signatureLength ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeTls12Signature( INOUT_PTR STREAM *stream,
								STDC_UNUSED const CRYPT_CONTEXT iSignContext,
								IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								IN_LENGTH_HASH_Z const int hashParam,
								IN_ALGO const CRYPT_ALGO_TYPE signAlgo,
								IN_BUFFER( signatureLength ) const BYTE *signature,
								IN_LENGTH_SHORT_MIN( MIN_SIGNATURE_SIZE + 1 ) \
									const int signatureLength )
	{
	return( writeTls1XSignature( stream, hashAlgo, hashParam, signAlgo, 
								 signature, signatureLength, FALSE ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int writeTls13Signature( INOUT_PTR STREAM *stream,
								STDC_UNUSED const CRYPT_CONTEXT iSignContext,
								IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
								IN_LENGTH_HASH_Z const int hashParam,
								IN_ALGO const CRYPT_ALGO_TYPE signAlgo,
								IN_BUFFER( signatureLength ) const BYTE *signature,
								IN_LENGTH_SHORT_MIN( MIN_SIGNATURE_SIZE + 1 ) \
									const int signatureLength )
	{
	/* TLS 1.3 is the same as TLS 1.2 but we have to use RSA-PSS for RSA
	   signatures because it's more trendy */
	return( writeTls1XSignature( stream, hashAlgo, hashParam, signAlgo, 
								 signature, signatureLength, 
								 ( signAlgo == CRYPT_ALGO_RSA ) ? \
								   TRUE : FALSE ) );
	}
#endif /* USE_TLS */

/****************************************************************************
*																			*
*					Signature Read/Write Access Functions					*
*																			*
****************************************************************************/

typedef struct {
	const SIGNATURE_TYPE type;
	const READSIG_FUNCTION function;
	} SIG_READ_INFO;
static const SIG_READ_INFO sigReadTable[] = {
#ifdef USE_INT_ASN1
	{ SIGNATURE_RAW, readRawSignature },
	{ SIGNATURE_X509, readX509Signature },
#endif /* USE_INT_ASN1 */
#ifdef USE_INT_CMS 
	{ SIGNATURE_CMS, readCmsSignature },
  #ifdef USE_PSS
	{ SIGNATURE_CMS_PSS, readCmsSignature },
  #endif /* USE_PSS */
	{ SIGNATURE_CRYPTLIB, readCryptlibSignature },
#endif /* USE_INT_CMS */
#ifdef USE_PGP
	{ SIGNATURE_PGP, readPgpSignature },
#endif /* USE_PGP */
#ifdef USE_SSH
	{ SIGNATURE_SSH, readSshSignature },
#endif /* USE_SSH */
#ifdef USE_TLS
	{ SIGNATURE_TLS, readTlsSignature },
	{ SIGNATURE_TLS12, readTls12Signature },
	{ SIGNATURE_TLS13, readTls12Signature },	/* One size fits all */
#endif /* USE_TLS */
	{ SIGNATURE_NONE, NULL }, { SIGNATURE_NONE, NULL }
	};

typedef struct {
	const SIGNATURE_TYPE type;
	const WRITESIG_FUNCTION function;
	} SIG_WRITE_INFO;
static const SIG_WRITE_INFO sigWriteTable[] = {
#ifdef USE_INT_ASN1
	{ SIGNATURE_RAW, writeRawSignature },
	{ SIGNATURE_X509, writeX509Signature },
#endif /* USE_INT_ASN1 */
#ifdef USE_INT_CMS 
	{ SIGNATURE_CMS, writeCmsSignature },
  #ifdef USE_PSS
	{ SIGNATURE_CMS_PSS, writeCmsSignaturePSS },
  #endif /* USE_PSS */
	{ SIGNATURE_CRYPTLIB, writeCryptlibSignature },
#endif /* USE_INT_CMS */
#ifdef USE_PGP
	{ SIGNATURE_PGP, writePgpSignature },
#endif /* USE_PGP */
#ifdef USE_SSH
	{ SIGNATURE_SSH, writeSshSignature },
#endif /* USE_SSH */
#ifdef USE_TLS
	{ SIGNATURE_TLS, writeTlsSignature },
	{ SIGNATURE_TLS12, writeTls12Signature },
	{ SIGNATURE_TLS13, writeTls13Signature },
#endif /* USE_TLS */
	{ SIGNATURE_NONE, NULL }, { SIGNATURE_NONE, NULL }
	};

CHECK_RETVAL_PTR \
READSIG_FUNCTION getReadSigFunction( IN_ENUM( SIGNATURE ) \
										const SIGNATURE_TYPE sigType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( sigType, SIGNATURE ) );

	LOOP_SMALL( i = 0,
				i < FAILSAFE_ARRAYSIZE( sigReadTable, SIG_READ_INFO ) && \
					sigReadTable[ i ].type != SIGNATURE_NONE,
				i++ )
		{
		ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
										 FAILSAFE_ARRAYSIZE( sigReadTable, \
															 SIG_READ_INFO ) - 1 ) );

		if( sigReadTable[ i ].type == sigType )
			return( sigReadTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( sigReadTable, SIG_READ_INFO ) );

	return( NULL );
	}
CHECK_RETVAL_PTR \
WRITESIG_FUNCTION getWriteSigFunction( IN_ENUM( SIGNATURE ) \
										const SIGNATURE_TYPE sigType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( sigType, SIGNATURE ) );

	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( sigWriteTable, SIG_WRITE_INFO ) && \
					sigWriteTable[ i ].type != SIGNATURE_NONE,
				i++ )
		{
		ENSURES_N( LOOP_INVARIANT_SMALL( i, 0, 
										 FAILSAFE_ARRAYSIZE( sigWriteTable, \
															 SIG_WRITE_INFO ) - 1 ) );

		if( sigWriteTable[ i ].type == sigType )
			return( sigWriteTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( sigWriteTable, SIG_WRITE_INFO ) );

	return( NULL );
	}
