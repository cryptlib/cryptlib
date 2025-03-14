/****************************************************************************
*																			*
*							X.509/PKI Signature Routines					*
*						Copyright Peter Gutmann 1993-2019					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "mech.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/misc_rw.h"
  #include "mechs/mech.h"
#endif /* Compiler-specific includes */

#ifdef USE_CERTIFICATES

/****************************************************************************
*																			*
*							X.509-style Signature Functions 				*
*																			*
****************************************************************************/

/* Create/check an X.509-style signature.  These work with objects of the
   form:

	signedObject ::= SEQUENCE {
		object				ANY,
		signatureAlgorithm	AlgorithmIdentifier,
		signature			BIT STRING
		}

   This is complicated by a variety of b0rken PKI protocols that couldn't
   quite manage a cut & paste of two lines of text, adding all sorts of
   unnecessary extra tagging and wrappers to the signature.  These odds and
   ends are specified in the formatInfo structure */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 10 ) ) \
int createX509signature( OUT_BUFFER( signedObjectMaxLength, \
									 *signedObjectLength ) \
							void *signedObject, 
						 IN_DATALENGTH const int signedObjectMaxLength, 
						 OUT_LENGTH_BOUNDED_Z( signedObjectMaxLength ) \
							int *signedObjectLength,
						 IN_BUFFER( objectLength ) const void *object, 
						 IN_DATALENGTH const int objectLength,
						 IN_HANDLE const CRYPT_CONTEXT iSignContext,
						 IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						 IN_LENGTH_HASH const int hashParam,
						 IN_PTR_OPT const X509SIG_FORMATINFO *formatInfo,
						 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT iHashContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	BYTE dataSignature[ CRYPT_MAX_PKCSIZE + 128 + 8 ];
	int signatureLength, totalSigLength, status;

	assert( isWritePtrDynamic( signedObject, signedObjectMaxLength ) );
	assert( isWritePtr( signedObjectLength, sizeof( int ) ) );
	assert( isReadPtr( object, objectLength ) && \
			cryptStatusOK( checkCertObjectEncoding( object, objectLength ) ) );
	assert( formatInfo == NULL || \
			isReadPtr( formatInfo, sizeof( X509SIG_FORMATINFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isBufsizeRangeMin( signedObjectMaxLength, \
								 MIN_CRYPT_OBJECTSIZE ) );
	REQUIRES( isBufsizeRangeNZ( objectLength ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashParam >= MIN_HASHSIZE && \
			  hashParam <= CRYPT_MAX_HASHSIZE );
	REQUIRES( formatInfo == NULL || \
			  ( ( formatInfo->tag >= 0 && \
				  formatInfo->tag < MAX_CTAG_VALUE ) && \
				isShortIntegerRange( formatInfo->extraLength ) ) );

	/* Clear return values */
	REQUIRES( isIntegerRangeNZ( signedObjectMaxLength ) ); 
	memset( signedObject, 0, min( 16, signedObjectMaxLength ) );
	*signedObjectLength = 0;

	/* Hash the data to be signed */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iHashContext = createInfo.cryptHandle;
	if( isParameterisedHashAlgo( hashAlgo ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &hashParam, 
								  CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
								  ( MESSAGE_CAST ) object, objectLength );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, errorInfo,
				  "Couldn't hash X.509 data to sign" ) );
		}

	/* Create the signature and calculate the overall length of the payload, 
	   optional signature wrapper, and signature data */
	status = createSignature( dataSignature, CRYPT_MAX_PKCSIZE + 128, 
							  &signatureLength, iSignContext, iHashContext, 
							  CRYPT_UNUSED, SIGNATURE_X509, errorInfo );
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	if( formatInfo == NULL )
		totalSigLength = signatureLength;
	else
		{
		/* It's a nonstandard format, figure out the size due to the 
		   additional signature wrapper and other odds and ends */
		totalSigLength = \
				sizeofShortObject( signatureLength + formatInfo->extraLength );
		if( formatInfo->isExplicit )
			totalSigLength = sizeofShortObject( totalSigLength );
		}
	ENSURES( isShortIntegerRangeMin( totalSigLength, 40 ) );

	/* Make sure that there's enough room for the signed object in the 
	   output buffer.  This will be checked by the stream handling anyway 
	   but we make it explicit here */
	if( sizeofObject( objectLength + totalSigLength ) > signedObjectMaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Write the outer SEQUENCE wrapper and copy the payload into place 
	   behind it.  We don't check for an error at the end of each group of 
	   writes to allow for a single retExtErr() exit at the end */
	sMemOpen( &stream, signedObject, signedObjectMaxLength );
	writeSequence( &stream, objectLength + totalSigLength );
	swrite( &stream, object, objectLength );

	/* If it's a nonstandard (b0rken PKI protocol) signature then we have to 
	   kludge in a variety of additional wrappers and other junk around the 
	   signature */
	if( formatInfo != NULL )
		{
		if( formatInfo->isExplicit )
			{
			writeConstructed( &stream, 
							  sizeofObject( signatureLength + \
											formatInfo->extraLength ),
							  formatInfo->tag );
			writeSequence( &stream, 
						   signatureLength + formatInfo->extraLength );
			}
		else
			{
			writeConstructed( &stream, 
							  signatureLength + formatInfo->extraLength,
							  formatInfo->tag );
			}
		}

	/* Finally, append the signature */
	status = swrite( &stream, dataSignature, signatureLength );
	if( cryptStatusOK( status ) )
		*signedObjectLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Couldn't write X.509 signature" ) );
		}
	ENSURES( isIntegerRangeNZ( *signedObjectLength ) );

	assert( ( formatInfo != NULL && formatInfo->extraLength > 0 ) || \
			cryptStatusOK( checkCertObjectEncoding( signedObject, 
													*signedObjectLength ) ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int checkX509signature( IN_BUFFER( signedObjectLength ) const void *signedObject, 
						IN_DATALENGTH const int signedObjectLength,
						IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
						IN_PTR_OPT const X509SIG_FORMATINFO *formatInfo,
						INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_ALGO_TYPE signAlgo;
	CRYPT_CONTEXT iHashContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	ALGOID_PARAMS algoIDparams;
	void *objectPtr DUMMY_INIT_PTR, *sigPtr;
	long length;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int sigCheckAlgo, sigLength, status;	/* int vs.enum */

	assert( isReadPtrDynamic( signedObject, signedObjectLength ) );
	assert( formatInfo == NULL || \
			isReadPtr( formatInfo, sizeof( X509SIG_FORMATINFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isBufsizeRangeNZ( signedObjectLength ) );
	REQUIRES( isHandleRangeValid( iSigCheckContext ) );
	REQUIRES( formatInfo == NULL || \
			  ( ( formatInfo->tag >= 0 && \
				  formatInfo->tag < MAX_CTAG_VALUE ) && \
				isShortIntegerRange( formatInfo->extraLength ) ) );

	/* Make sure that the signing parameters are in order */
	status = krnlSendMessage( iSigCheckContext, IMESSAGE_GETATTRIBUTE,
							  &sigCheckAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

	/* Check the start of the object and record the start and size of the
	   encapsulated signed object.  We have to use the long-length form of
	   the length functions to handle mega-CRLs */
	sMemConnect( &stream, signedObject, signedObjectLength );
	readLongSequence( &stream, NULL );						/* SignedObject */
	status = getLongStreamObjectLength( &stream, &length );	/* Object */
	if( cryptStatusOK( status ) && !isShortIntegerRangeNZ( length ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		status = sMemGetDataBlock( &stream, &objectPtr, length );
	if( cryptStatusOK( status ) )
		status = sSkip( &stream, length, SSKIP_MAX );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		retExt( status,
				( status, errorInfo,
				  "Invalid X.509 signed data" ) );
		}
	CFI_CHECK_UPDATE( "getLongStreamObjectLength" );

	/* If it's a broken signature, process the extra encapsulation */
	if( formatInfo != NULL )
		{
		if( formatInfo->isExplicit )
			{
			readConstructed( &stream, NULL, formatInfo->tag );
			status = readSequence( &stream, NULL );
			}
		else
			status = readConstructed( &stream, NULL, formatInfo->tag );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			retExt( status,
					( status, errorInfo,
					  "Couldn't read X.509 signature" ) );
			}
		}

	/* Remember the location and size of the signature data */
	status = sMemGetDataBlockRemaining( &stream, &sigPtr, &sigLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	status = readAlgoIDex( &stream, &signAlgo, &algoIDparams,
						   ALGOID_CLASS_PKCSIG );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Invalid X.509 signature algorithm information" ) );
		}
	ANALYSER_HINT( sigPtr != NULL );
	CFI_CHECK_UPDATE( "readAlgoIDex" );

	/* If the signature algorithm isn't what we expected the best that we 
	   can do is report a signature error */
	if( sigCheckAlgo != signAlgo )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, errorInfo,
				  "Signature algorithm %s used for data doesn't match "
				  "signature algorithm %s used in X.509 signature", 
				  getAlgoName( sigCheckAlgo ), 
				  getAlgoName( signAlgo ) ) );
		}

	/* Create a hash context from the algorithm identifier of the
	   signature */
	setMessageCreateObjectInfo( &createInfo, algoIDparams.hashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iHashContext = createInfo.cryptHandle;
	if( isParameterisedHashAlgo( algoIDparams.hashAlgo ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_SETATTRIBUTE,
								  &algoIDparams.hashParam, 
								  CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	/* Hash the signed data and check the signature on the object */
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
							  objectPtr, length );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
								  "", 0 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, errorInfo,
				  "Couldn't hash X.509 signed data" ) );
		}
	status = checkSignature( sigPtr, sigLength, iSigCheckContext,
							 iHashContext, CRYPT_UNUSED,
							 SIGNATURE_X509, errorInfo );
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkSignature" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "IMESSAGE_GETATTRIBUTE", 
								   "getLongStreamObjectLength", "readAlgoIDex", 
								   "checkSignature" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							PKI Protocol Signature Functions 				*
*																			*
****************************************************************************/

/* The various PKIX certificate management protocols are built using the 
   twin design guidelines that nothing should use a standard style of 
   signature and no two protocols should use the same nonstandard format, 
   the only way to handle these (without creating dozens of new signature 
   types, each with their own special-case handling) is to process most of 
   the signature information at the protocol level and just check the raw 
   signature here */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 6 ) ) \
int createRawSignature( OUT_BUFFER( sigMaxLength, *signatureLength ) \
							void *signature, 
						IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
							const int sigMaxLength, 
						OUT_LENGTH_BOUNDED_Z( sigMaxLength ) \
							int *signatureLength, 
						IN_HANDLE const CRYPT_CONTEXT iSignContext,
						IN_HANDLE const CRYPT_CONTEXT iHashContext,
						INOUT_PTR ERROR_INFO *errorInfo )
	{
	assert( isWritePtrDynamic( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isShortIntegerRangeMin( sigMaxLength, MIN_CRYPT_OBJECTSIZE ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );

	return( createSignature( signature, sigMaxLength, signatureLength, 
							 iSignContext, iHashContext, CRYPT_UNUSED,
							 SIGNATURE_RAW, errorInfo ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int checkRawSignature( IN_BUFFER( signatureLength ) const void *signature, 
					   IN_LENGTH_SHORT const int signatureLength,
					   IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
					   IN_HANDLE const CRYPT_CONTEXT iHashContext,
					   INOUT_PTR ERROR_INFO *errorInfo )
	{
	assert( isReadPtrDynamic( signature, signatureLength ) );

	REQUIRES( isShortIntegerRangeNZ( signatureLength ) );
	REQUIRES( isHandleRangeValid( iSigCheckContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );

	return( checkSignature( signature, signatureLength, iSigCheckContext,
							iHashContext, CRYPT_UNUSED, SIGNATURE_RAW,
							errorInfo ) );
	}
#endif /* USE_CERTIFICATES */
