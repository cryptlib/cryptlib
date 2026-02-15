/****************************************************************************
*																			*
*							PGP Signature Routines							*
*						Copyright Peter Gutmann 1993-2024					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "pgp_rw.h"
  #include "mech.h"
#else
  #include "crypt.h"
  #include "enc_dec/pgp_rw.h"
  #include "mechs/mech.h"
#endif /* Compiler-specific includes */

#ifdef USE_PGP

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Write a PGP signature packet header:

		-- Start of hashed data --
		byte	version = 4
		byte	sigType
		byte	sigAlgo
		byte	hashAlgo
		uint16	length of auth.attributes
		byte[]	authenticated attributes
		-- End of hashed data --
		uint16	length of unauth.attributes = 0
	  [	byte[2]	hash check ]
	  [	mpi(s)	signature  ]

   See the comment in createSignaturePGP() for the use of this function */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int writePgpSigPacketHeader( OUT_BUFFER_OPT( dataMaxLen, *dataLen ) \
										void *data, 
									IN_LENGTH_SHORT_Z const int dataMaxLen,
									OUT_LENGTH_BOUNDED_SHORT_Z( dataMaxLen ) \
										int *dataLen,
									IN_HANDLE const CRYPT_CONTEXT iSignContext,
									IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
									IN_BUFFER_OPT( sigAttributeLength ) \
										const void *sigAttributes,
									IN_LENGTH_SHORT_Z \
										const int sigAttributeLength,
									IN_RANGE( PGP_SIG_NONE, PGP_SIG_LAST - 1 ) \
										const int sigType,
									IN_LENGTH_SHORT_Z const int iAndSlength )
	{
	STREAM stream;
	MESSAGE_DATA msgData;
	BYTE keyID[ PGP_KEYID_SIZE + 8 ];
	BYTE iAndSHeader[ 64 + 8 ];
	const time_t currentTime = getTime( GETTIME_NOFAIL_MINUTES );
	int signAlgo, pgpHashAlgo, pgpSignAlgo;		/* int vs.enum */
	int iAndSHeaderLength = 0, length, status;

	assert( ( data == NULL && dataMaxLen == 0 ) || \
			isWritePtrDynamic( data, dataMaxLen ) );
	assert( isWritePtr( dataLen, sizeof( int ) ) );
	assert( ( sigAttributes == NULL && sigAttributeLength == 0 ) || \
			isReadPtrDynamic( sigAttributes, sigAttributeLength ) );

	REQUIRES( ( data == NULL && dataMaxLen == 0 ) || \
			  ( data != NULL && \
				isShortIntegerRangeMin( dataMaxLen, \
										MIN_CRYPT_OBJECTSIZE ) ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( ( sigAttributes == NULL && sigAttributeLength == 0 ) || \
			  ( sigAttributes != NULL && \
			    isShortIntegerRangeNZ( sigAttributeLength ) ) );
	REQUIRES( isEnumRangeOpt( sigType, PGP_SIG ) );
	REQUIRES( isShortIntegerRange( iAndSlength ) );

	/* Clear return value */
	*dataLen = 0;

	/* Get the signature information */
	if( cryptStatusError( cryptlibToPgpAlgo( hashAlgo, &pgpHashAlgo ) ) )
		return( CRYPT_ARGERROR_NUM2 );
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE,
							  &signAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM1 : status );
	if( cryptStatusError( cryptlibToPgpAlgo( signAlgo, &pgpSignAlgo ) ) )
		return( CRYPT_ARGERROR_NUM1 );
	setMessageData( &msgData, keyID, PGP_KEYID_SIZE );
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEYID_OPENPGP );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM1 : status );
	INJECT_FAULT( CORRUPT_ID, CORRUPT_ID_PGP_1 );

	/* Write the issuerAndSerialNumber packet header if necessary.  Since
	   this is a variable-length packet we need to pre-encode it before we
	   can write the main packet data:

		byte[]		length
		byte		subpacketType = PGP_SUBPACKET_TYPEANDVALUE
		uint32		flags = 0
		uint16		typeLength = 21
		uint16		valueLength
		byte[]		type = "issuerAndSerialNumber"
	  [	byte[]		value ] */
	if( iAndSlength > 0 )
		{
		STREAM headerStream;

		sMemOpen( &headerStream, iAndSHeader, 64 );
		pgpWriteLength( &headerStream, \
						1 + UINT32_SIZE + UINT16_SIZE + UINT16_SIZE + \
						21 + iAndSlength );
		sputc( &headerStream, PGP_SUBPACKET_TYPEANDVALUE );
		writeUint32( &headerStream, 0 );
		writeUint16( &headerStream, 21 );
		writeUint16( &headerStream, iAndSlength );
		status = swrite( &headerStream, "issuerAndSerialNumber", 21 );
		if( cryptStatusOK( status ) )
			iAndSHeaderLength = stell( &headerStream );
		sMemDisconnect( &headerStream );

		ENSURES( cryptStatusOK( status ) );
		ENSURES( isShortIntegerRangeNZ( iAndSHeaderLength ) );
		}

	/* Write the general header information */
	sMemOpenOpt( &stream, data, dataMaxLen );
	sputc( &stream, PGP_VERSION_OPENPGP );
	sputc( &stream, sigType );
	sputc( &stream, pgpSignAlgo );
	status = sputc( &stream, pgpHashAlgo );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}

	/* Write the authenticated attributes:

		uint16		authAttrLength
		byte		subpacketLength = 1 + UINT32_SIZE
		byte		ID = PGP_SUBPACKET_TIME
		uint32		time
		byte		subpacketLength = 1 + PGP_KEYID_SIZE
		byte		ID = PGP_SUBPACKET_KEYID
		byte[8]		signerID
	  [ byte[]		signed attributes ]
	  [	byte[]		typeAndValue packet for iAndS ]
	
	   The signer ID is optional, but if we omit it GPG fails the signature 
	   check so we always include it.  This also handles a highly unlikely
	   fault attack on algorithms like EdDSA which allows recovery of the
	   secret scalar value d from two signatures on the same data using
	   different public keys, the inclusion of the key-based signerID means
	   that the same message won't be signed by the two different public 
	   keys */
	length = ( 1 + 1 + UINT32_SIZE ) + ( 1 + 1 + PGP_KEYID_SIZE ) + \
			 sigAttributeLength;
	if( iAndSlength > 0 )
		length += iAndSHeaderLength + iAndSlength;
	writeUint16( &stream, length );
	sputc( &stream, 1 + UINT32_SIZE );		/* Time */
	sputc( &stream, PGP_SUBPACKET_TIME );
	writeUint32Time( &stream, currentTime );
	sputc( &stream, 1 + PGP_KEYID_SIZE );	/* Signer ID */
	sputc( &stream, PGP_SUBPACKET_KEYID );
	status = swrite( &stream, keyID, PGP_KEYID_SIZE );
	if( cryptStatusOK( status ) && sigAttributeLength > 0 )
		status = swrite( &stream, sigAttributes, sigAttributeLength );
	if( cryptStatusOK( status ) && iAndSlength > 0 )
		{									/* TypeAndValue */
		status = swrite( &stream, iAndSHeader, iAndSHeaderLength );
		if( cryptStatusOK( status ) )
			{
			status = exportAttributeToStream( &stream, iSignContext,
								CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
			}
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}

	/* Write the unauthenticated attributes:

		uint16		unauthAttrLength = 0 */
	status = writeUint16( &stream, 0 );
	if( cryptStatusOK( status ) )
		*dataLen = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Create/Check a PGP Signature					*
*																			*
****************************************************************************/

/* Create a PGP signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 9 ) ) \
int createSignaturePGP( OUT_BUFFER_OPT( sigMaxLength, *signatureLength ) \
							void *signature, 
						IN_LENGTH_SHORT_Z const int sigMaxLength, 
						OUT_LENGTH_BOUNDED_SHORT_Z( sigMaxLength ) \
							int *signatureLength, 
						IN_HANDLE const CRYPT_CONTEXT iSignContext,
						IN_PTR const SIG_DATA_INFO *sigDataInfo,
						IN_BUFFER_OPT( sigAttributeLength ) \
							const void *sigAttributes,
						IN_LENGTH_SHORT_Z const int sigAttributeLength,
						IN_RANGE( PGP_SIG_NONE, PGP_SIG_LAST - 1 ) \
							const int sigType,
						INOUT_PTR ERROR_INFO *errorInfo )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE signatureData[ CRYPT_MAX_PKCSIZE + 128 + 8 ];
	BYTE extraData[ 1024 + 8 ], *extraDataPtr = extraData;
	BYTE extraTrailer[ 8 + 8 ];
	int extraDataLength = 1024, extraTrailerLength DUMMY_INIT;
	int signatureDataLength, iAndSlength = 0, totalLength DUMMY_INIT;
	int status;

	assert( ( signature == NULL && sigMaxLength == 0 ) || \
			isWritePtrDynamic( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( isReadPtr( sigDataInfo, sizeof( SIG_DATA_INFO ) ) );
	assert( ( sigAttributes == NULL && sigAttributeLength == 0 ) || \
			isReadPtrDynamic( sigAttributes, sigAttributeLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( ( signature == NULL && sigMaxLength == 0 ) || \
			  ( signature != NULL && \
				isShortIntegerRangeMin( sigMaxLength, \
										MIN_CRYPT_OBJECTSIZE ) ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( sanityCheckSigDataInfo( sigDataInfo, SIGNATURE_PGP, TRUE ) && \
			  sigDataInfo->data == NULL );
	REQUIRES( ( sigAttributes == NULL && sigAttributeLength == 0 ) || \
			  ( sigAttributes != NULL && \
			    isShortIntegerRangeNZ( sigAttributeLength ) ) );
	REQUIRES( isEnumRangeOpt( sigType, PGP_SIG ) );

	/* Clear return value */
	*signatureLength = 0;

	/* Check whether there's an issuerAndSerialNumber present */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) )
		iAndSlength = msgData.length;

	/* If it's a length check only, determine how large the signature data
	   will be and exit */
	if( signature == NULL )
		{
		status = writePgpSigPacketHeader( NULL, 0, &extraDataLength, 
										  iSignContext, 
										  sigDataInfo->hashAlgo, 
										  sigAttributes, sigAttributeLength,
										  sigType, iAndSlength );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo,
					  "Couldn't write PGP signature packet header" ) );
			}
		status = createSignature( NULL, 0, &signatureDataLength, 
								  iSignContext, sigDataInfo, 
								  SIGNATURE_PGP, errorInfo );
		if( cryptStatusError( status ) )
			return( status );
		*signatureLength = 1 + pgpSizeofLength( extraDataLength + 2 + \
												signatureDataLength ) + \
						   extraDataLength + 2 + signatureDataLength;

		ENSURES( isShortIntegerRangeNZ( *signatureLength ) );

		return( CRYPT_OK );
		}

	/* If there's an issuerAndSerialNumber present, allocate a larger buffer 
	   for it if necessary (this virtually never occurs, the iAndS would need
	   to be over 1kB long).  Note that we can't use a dynBuf for this 
	   because we're allocating a buffer larger than just the attribute in 
	   order to hold the additional PGP signature data, not the 
	   same size as the attribute which is what dynCreate() does */
	if( iAndSlength > extraDataLength - 128 )
		{
		extraDataLength = 128 + iAndSlength;
		REQUIRES( isShortIntegerRangeNZ( extraDataLength ) );
		if( ( extraDataPtr = clDynAlloc( "createSignaturePGP", \
										 extraDataLength ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		}

	/* Complete the hashing and create the signature.  In theory this could
	   get ugly because there could be multiple one-pass signature packets
	   present, however PGP handles multiple signatures by nesting them so
	   this isn't a problem.

	   PGP processes the authenticated attributes in an odd way, first
	   hashing part of the packet from the version number to the end of the
	   authenticated attributes, then hashing some more (out-of-band) stuff, 
	   and finally signing the result of the overall hashing.  Because of 
	   this complex way of handling things we can't write the signature 
	   packet in one go but instead have to write the part that we can 
	   create now, hash the portion that's hashed (all but the last 16 bits, 
	   the length of the unathenticated attributes), and then go back and 
	   assemble the whole thing including the length and signature later on 
	   from the pre-hashed data and the length, hash check, and signature */
	status = writePgpSigPacketHeader( extraData, extraDataLength, 
									  &extraDataLength, iSignContext,
									  sigDataInfo->hashAlgo, 
									  sigAttributes, sigAttributeLength, 
									  sigType, iAndSlength );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sigDataInfo->hashContext, 
								  IMESSAGE_CTX_HASH, extraData, 
								  extraDataLength - UINT16_SIZE );
		if( status == CRYPT_ERROR_COMPLETE )
			{
			/* Unlike standard signatures PGP requires that the hashing not 
			   be wrapped up before the signature is generated because it 
			   needs to hash in further data before it can generate the 
			   signature.  Since completing the hashing is likely to be a 
			   common error we specifically check for this and return an
			   appropriate error code */
			status = CRYPT_ARGERROR_NUM2;
			}
		}
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( extraDataLength ) ); 
		zeroise( extraDataPtr, extraDataLength );
		if( extraDataPtr != extraData )
			clFree( "createSignaturePGP", extraDataPtr );
		retExt( status,
				( status, errorInfo,
				  "Couldn't write PGP signature packet header" ) );
		}
	INJECT_FAULT( ENVELOPE_CORRUPT_AUTHATTR, 
				  ENVELOPE_CORRUPT_AUTHATTR_PGP_1 );

	/* Hash in even more stuff at the end.  This is a complex jumble of 
	   items comprising a version number, an 0xFF, and another length.  
	   This was motivated by a concern that something that meant one thing 
	   in a version n sig could mean something different when interpreted as 
	   a version n+1 sig.  For this reason a hash-convention version (v4) 
	   was added, along with a disambiguator 0xFF that will never be found 
	   at that position in older (v3) hash-convention sigs (the 0x04 is in 
	   fact redundant but may be needed at some point if the hash 
	   convention moves to a v5 format).  The length has something to do 
	   with parsing the packet from the end so that out-of-band data doesn't 
	   run into payload data, but no-one can quite remember why it's 
	   actually there */
	sMemOpen( &stream, extraTrailer, 8 );
	sputc( &stream, 0x04 );
	sputc( &stream, 0xFF );
	status = writeUint32( &stream, extraDataLength - UINT16_SIZE );
	if( cryptStatusOK( status ) )
		extraTrailerLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sigDataInfo->hashContext, 
								  IMESSAGE_CTX_HASH, 
								  extraTrailer, extraTrailerLength );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sigDataInfo->hashContext, 
								  IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( sigDataInfo->hashContext, 
								  IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( extraDataLength ) ); 
		zeroise( extraDataPtr, extraDataLength );
		if( extraDataPtr != extraData )
			clFree( "createSignaturePGP", extraDataPtr );
		retExt( status,
				( status, errorInfo,
				  "Couldn't hash additional PGP signature packet data" ) );
		}
	ENSURES( isShortIntegerRangeNZ( extraTrailerLength ) );

	/* We've finally finished with all the hashing, create the signature */
	status = createSignature( signatureData, CRYPT_MAX_PKCSIZE + 128, 
							  &signatureDataLength, iSignContext, 
							  sigDataInfo, SIGNATURE_PGP, errorInfo );
	if( cryptStatusOK( status ) )
		{
		totalLength = 1 + \
					  pgpSizeofLength( extraDataLength + 2 + \
									   signatureDataLength ) + \
					  extraDataLength + 2 + signatureDataLength;
		if( totalLength + 64 > sigMaxLength )
			status = CRYPT_ERROR_OVERFLOW;
		}
	if( cryptStatusError( status ) )
		{
		REQUIRES( isShortIntegerRangeNZ( extraDataLength ) ); 
		zeroise( extraDataPtr, extraDataLength );
		if( extraDataPtr != extraData )
			clFree( "createSignaturePGP", extraDataPtr );
		return( status );
		}

	/* Write the signature packet:

	  [	signature packet header ]
		byte[2]	hash check
		mpi		signature

	  Since we've already had to write half the packet earlier on in order
	  to hash it we copy this pre-encoded information across and add the 
	  header and trailer around it */
	sMemOpen( &stream, signature, totalLength + 64 );
	pgpWritePacketHeader( &stream, PGP_PACKET_SIGNATURE,
						  extraDataLength + 2 + signatureDataLength );
	swrite( &stream, extraData, extraDataLength );
	swrite( &stream, hash, 2 );			/* Hash check */
	status = swrite( &stream, signatureData, signatureDataLength );
	if( cryptStatusOK( status ) )
		*signatureLength = stell( &stream );
	sMemDisconnect( &stream );
	REQUIRES( isShortIntegerRangeNZ( extraDataLength ) ); 
	zeroise( extraDataPtr, extraDataLength );
	zeroise( signatureData, CRYPT_MAX_PKCSIZE + 128 );
	if( extraDataPtr != extraData )
		clFree( "createSignaturePGP", extraDataPtr );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Couldn't write PGP signature packet" ) );
		}
	ENSURES( isShortIntegerRangeNZ( *signatureLength ) );

	return( CRYPT_OK );
	}

/* Check a PGP signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 5 ) ) \
int checkSignaturePGP( IN_BUFFER( signatureLength ) const void *signature, 
					   IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength,
					   IN_HANDLE const CRYPT_CONTEXT sigCheckContext,
					   IN_PTR const SIG_DATA_INFO *sigDataInfo,
					   INOUT_PTR ERROR_INFO *errorInfo )
	{
	const READSIG_FUNCTION readSigFunction = getReadSigFunction( SIGNATURE_PGP );
	QUERY_INFO queryInfo;
	STREAM stream;
	MESSAGE_DATA msgData;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	BYTE keyID[ PGP_KEYID_SIZE + 8 ];
	int status;

	assert( isReadPtrDynamic( signature, signatureLength ) );
	assert( isReadPtr( sigDataInfo, sizeof( SIG_DATA_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	
	REQUIRES( isShortIntegerRangeMin( signatureLength, 40 ) );
	REQUIRES( isHandleRangeValid( sigCheckContext ) );
	REQUIRES( sanityCheckSigDataInfo( sigDataInfo, SIGNATURE_PGP, TRUE ) && \
			  sigDataInfo->data == NULL );

	/* Make sure that the requested signature format is available */
	if( readSigFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Determine whether there are any authenticated attributes attached to
	   the signature */
	sMemConnect( &stream, signature, signatureLength );
	status = readSigFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		retExt( status,
				( status, errorInfo,
				  "Couldn't read PGP signature" ) );
		}
	CFI_CHECK_UPDATE( "readSigFunction" );

	/* Get information from the sig-check key.  We have to do this after 
	   reading the signature since what we're fetching is signature-format-
	   dependent */
	setMessageData( &msgData, keyID, PGP_KEYID_SIZE );
	status = krnlSendMessage( sigCheckContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, 
							  ( queryInfo.version == PGP_VERSION_2 ) ? \
								CRYPT_IATTRIBUTE_KEYID_PGP2 : \
								CRYPT_IATTRIBUTE_KEYID_OPENPGP );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM1 : status );

	/* After hashing the content, PGP also hashes in extra authenticated
	   attributes, see the earlier comment in createSignaturePGP() */
	REQUIRES( boundsCheck( queryInfo.attributeStart, 
						   queryInfo.attributeLength, queryInfo.size ) );
	status = krnlSendMessage( sigDataInfo->hashContext, IMESSAGE_CTX_HASH,
							  ( BYTE * ) signature + queryInfo.attributeStart,
							  queryInfo.attributeLength );
	if( cryptStatusOK( status ) && queryInfo.attributeLength != 5 )
		{
		BYTE buffer[ 8 + 8 ];
		int length DUMMY_INIT;

		/* In addition to the standard authenticated attributes OpenPGP
		   hashes in even more stuff at the end, see the comments for 
		   createSignaturePGP() */
		sMemOpen( &stream, buffer, 8 );
		sputc( &stream, 0x04 );
		sputc( &stream, 0xFF );
		status = writeUint32( &stream, queryInfo.attributeLength );
		if( cryptStatusOK( status ) )
			length = stell( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusOK( status ) )
			{
			ENSURES( isShortIntegerRangeNZ( length ) );
			status = krnlSendMessage( sigDataInfo->hashContext, 
									  IMESSAGE_CTX_HASH, buffer, length );
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sigDataInfo->hashContext, 
								  IMESSAGE_CTX_HASH, "", 0 );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		retExt( status,
				( status, errorInfo,
				  "Couldn't hash PGP authenticated attributes" ) );
		}
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_HASH" );

	/* Check the signature */
	status = checkSignature( signature, signatureLength, sigCheckContext,
							 sigDataInfo, SIGNATURE_PGP, errorInfo );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}
	CFI_CHECK_UPDATE( "checkSignature" );

	/* If there's a keyID present with the signature, make sure that the key 
	   that we've used to verify the signature is the one that should have 
	   signed it.  We do this after the signature check since we don't know
	   that the keyID is valid until after we've checked the signature */
	if(	queryInfo.keyIDlength != 0 && \
		( queryInfo.keyIDlength != PGP_KEYID_SIZE || \
		  memcmp( queryInfo.keyID, keyID, PGP_KEYID_SIZE ) ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo,
				  "Key used to verify signature doesn't match signer "
				  "key ID" ) );
		}
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );
	CFI_CHECK_UPDATE( "PGP_KEYID" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "readSigFunction", "IMESSAGE_CTX_HASH", 
								   "checkSignature", "PGP_KEYID" ) );

	return( CRYPT_OK );
	}
#endif /* USE_PGP */
