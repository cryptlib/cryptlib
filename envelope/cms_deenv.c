/****************************************************************************
*																			*
*					  cryptlib De-enveloping Routines						*
*					 Copyright Peter Gutmann 1996-2025						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "envelope.h"
#else
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/* The maximum number of data items in a CMS header or trailer, or at 
   least the maximum number of iterations in the state machine loop in
   processPreamble() and processPostamble().  Note that in the code this
   is enforced per call rather than per CMS header/trailer because a
   caller who breaks apart the processing across multiple calls to
   processPreamble()/processPostamble() gets a new MAX_DATA_ITEMS loop
   each time.  This isn't a problem, it's merely a sanity-check to
   make sure that we don't iterate endlessly on malformed headers rather 
   than being a hard limit */

#define MAX_DATA_ITEMS		( MAX_ENV_ITEMS	+ 8 )

#ifdef USE_CMS

/* OID information used to read enveloped data.  SignedData has versions 
   { 1, 3, 4, 5 } but the last two are weirdo types (RFC 5652 section 5.1)
   that quite probably don't actually exist and that in any case we don't 
   know what to do with (version 5 in particular is OCSP responses stuffed
   into the CRLs field for CAdES signatures as per RFC 5940), and similarly 
   AuthenticatedData has { 0, 1, 3 } of which the last two are more weirdo 
   types (RFC 5652 section 9.1) that may not exist and that we can't 
   handle */

static const CMS_CONTENT_INFO oidInfoSignedData = { 1, 3 };
static const CMS_CONTENT_INFO oidInfoEnvelopedData = { 0, 4 };
static const CMS_CONTENT_INFO oidInfoEncryptedData = { 0, 2 };
static const CMS_CONTENT_INFO oidInfoCompressedData = { 0, 0 };
static const CMS_CONTENT_INFO oidInfoAuthData = { 0, 0 };
static const CMS_CONTENT_INFO oidInfoAuthEnvData = { 0, 0 };

static const OID_INFO envelopeOIDinfo[] = {
	{ OID_CMS_DATA, ACTION_NONE },
	{ OID_CMS_SIGNEDDATA, ACTION_SIGN, &oidInfoSignedData },
	{ OID_CMS_ENVELOPEDDATA, ACTION_KEYEXCHANGE, &oidInfoEnvelopedData },
	{ OID_CMS_ENCRYPTEDDATA, ACTION_CRYPT, &oidInfoEncryptedData },
	{ OID_CMS_COMPRESSEDDATA, ACTION_COMPRESS, &oidInfoCompressedData },
	{ OID_CMS_AUTHDATA, ACTION_MAC, &oidInfoAuthData },
	{ OID_CMS_AUTHENVDATA, ACTION_xxx, &oidInfoAuthEnvData },
	{ OID_TSP_TSTINFO, ACTION_NONE },
	{ OID_MS_SPCINDIRECTDATACONTEXT, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSREQ, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSRESP, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSRESP_EXT, ACTION_NONE },
	{ OID_SCVP_CERTVALREQUEST, ACTION_NONE },
	{ OID_SCVP_CERTVALRESPONSE, ACTION_NONE },
	{ OID_SCVP_VALPOLREQUEST, ACTION_NONE },
	{ OID_SCVP_VALPOLRESPONSE, ACTION_NONE },
	{ NULL, 0 }, { NULL, 0 }
	};

static const OID_INFO nestedContentOIDinfo[] = {
	{ OID_CMS_DATA, CRYPT_CONTENT_DATA },
	{ OID_CMS_SIGNEDDATA, CRYPT_CONTENT_SIGNEDDATA },
	{ OID_CMS_ENVELOPEDDATA, CRYPT_CONTENT_ENVELOPEDDATA },
	{ OID_CMS_ENCRYPTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA },
	{ OID_CMS_COMPRESSEDDATA, CRYPT_CONTENT_COMPRESSEDDATA },
	{ OID_CMS_AUTHDATA, CRYPT_CONTENT_AUTHDATA },
	{ OID_CMS_AUTHENVDATA, CRYPT_CONTENT_AUTHENVDATA },
	{ OID_TSP_TSTINFO, CRYPT_CONTENT_TSTINFO },
	{ OID_MS_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT },
	{ OID_CRYPTLIB_RTCSREQ, CRYPT_CONTENT_RTCSREQUEST },
	{ OID_CRYPTLIB_RTCSRESP, CRYPT_CONTENT_RTCSRESPONSE },
	{ OID_CRYPTLIB_RTCSRESP_EXT, CRYPT_CONTENT_RTCSRESPONSE_EXT },
	{ OID_SCVP_CERTVALREQUEST, CRYPT_CONTENT_SCVPCERTVALREQUEST },
	{ OID_SCVP_CERTVALRESPONSE, CRYPT_CONTENT_SCVPCERTVALRESPONSE },
	{ OID_SCVP_VALPOLREQUEST, CRYPT_CONTENT_SCVPVALPOLREQUEST },
	{ OID_SCVP_VALPOLRESPONSE, CRYPT_CONTENT_SCVPVALPOLRESPONSE },
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Sanity-check the envelope state */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheckEnvCMSDenv( const ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Check the general envelope state */
	if( !sanityCheckEnvelope( envelopeInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckEnvCMSDenv: Envelope check" ));
		return( FALSE );
		}

	/* Make sure that the general envelope state is in order */
	if( !TEST_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_ISDEENVELOPE ) )
		{
		DEBUG_PUTS(( "sanityCheckEnvCMSDenv: General info" ));
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*						Content-list Processing Routines					*
*																			*
****************************************************************************/

/* Add information on different object types to a content-list entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int initExternalContentInfo( CONTENT_LIST *contentListItem,
									IN_ENUM( CONTENT ) \
										const CONTENT_TYPE contentType,
									const QUERY_INFO *queryInfo )
	{
	CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;

	assert( isWritePtr( contentListItem, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( contentType == CONTENT_AUTHENC || \
			  contentType == CONTENT_CRYPT );

	contentListItem->envInfo = CRYPT_ENVINFO_SESSIONKEY;

	/* If it's authenticated encrypted data, remember the optional KDF and 
	   encryption and MAC algorithm parameters */
	if( contentType == CONTENT_AUTHENC )
		{
		CONTENT_AUTHENC_INFO *authEncInfo = &contentListItem->clAuthEncInfo;

		authEncInfo->authEncAlgo = queryInfo->cryptAlgo;
		authEncInfo->authEncKeysize = queryInfo->keySize;
		REQUIRES( rangeCheck( queryInfo->authEncParamLength, 8, 
							  AUTHENCPARAM_MAX_SIZE ) );
		memcpy( authEncInfo->authEncParamData, queryInfo->authEncParamData,
				queryInfo->authEncParamLength );
		authEncInfo->authEncParamLength = queryInfo->authEncParamLength;
		if( queryInfo->kdfParamLength > 0 )
			{
			REQUIRES( boundsCheck( queryInfo->kdfParamStart,
								   queryInfo->kdfParamLength,
								   queryInfo->authEncParamLength ) );
			authEncInfo->kdfParamStart = queryInfo->kdfParamStart;
			authEncInfo->kdfParamLength = queryInfo->kdfParamLength;
			}
		REQUIRES( boundsCheck( queryInfo->encParamStart,
							   queryInfo->encParamLength,
							   queryInfo->authEncParamLength ) );
		authEncInfo->encParamStart = queryInfo->encParamStart;
		authEncInfo->encParamLength = queryInfo->encParamLength;
		REQUIRES( boundsCheck( queryInfo->macParamStart,
							   queryInfo->macParamLength,
							   queryInfo->authEncParamLength ) );
		authEncInfo->macParamStart = queryInfo->macParamStart;
		authEncInfo->macParamLength = queryInfo->macParamLength;

		ENSURES( sanityCheckContentList( contentListItem ) );

		return( CRYPT_OK );
		}

	/* It's conventionally encrypted data, remember the encryption algorithm 
	   parameters */
	encrInfo->cryptAlgo = queryInfo->cryptAlgo;
	encrInfo->cryptMode = queryInfo->cryptMode;
	encrInfo->keySize = queryInfo->keySize;
	if( queryInfo->ivLength > 0 )
		{
		REQUIRES( rangeCheck( queryInfo->ivLength, 1, CRYPT_MAX_HASHSIZE ) );
							  /* saltOrIV is CRYPT_MAX_HASHSIZE, not 
							     CRYPT_MAX_IVSIZE since it can also contain 
							     a salt */
		REQUIRES( rangeCheck( queryInfo->ivLength, 1, CRYPT_MAX_IVSIZE ) );
							  /* We check the source as well since it's a 
							     different-sized buffer */
		memcpy( encrInfo->saltOrIV, queryInfo->iv, queryInfo->ivLength );
		encrInfo->saltOrIVsize = queryInfo->ivLength;
		}

	ENSURES( sanityCheckContentList( contentListItem ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int initPkcContentInfo( CONTENT_LIST *contentListItem,
							   const QUERY_INFO *queryInfo,
							   IN_BUFFER( objectSize ) const void *object, 
							   IN_LENGTH_SHORT const int objectSize )
	{
	const BYTE *objectPtr = object;	/* For pointer maths */

	assert( isWritePtr( contentListItem, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( queryInfo, sizeof( QUERY_INFO ) ) );
	assert( isReadPtrDynamic( object, objectSize ) );

	REQUIRES( isShortIntegerRangeNZ( objectSize ) );

	/* Remember the details of the enveloping information that we require 
	   to continue */
	if( queryInfo->type == CRYPT_OBJECT_PKCENCRYPTED_KEY )
		contentListItem->envInfo = CRYPT_ENVINFO_PRIVATEKEY;
	else
		{
		contentListItem->envInfo = CRYPT_ENVINFO_SIGNATURE;
		contentListItem->clSigInfo.hashAlgo = queryInfo->hashAlgo;
		contentListItem->clSigInfo.hashParam = queryInfo->hashParam;
		}
	if( queryInfo->formatType == CRYPT_FORMAT_CMS )
		{
		REQUIRES( boundsCheck( queryInfo->iAndSStart, queryInfo->iAndSLength, 
							   objectSize ) );
		contentListItem->issuerAndSerialNumber = objectPtr + queryInfo->iAndSStart;
		contentListItem->issuerAndSerialNumberSize = queryInfo->iAndSLength;
		}
	else
		{
		REQUIRES( rangeCheck( queryInfo->keyIDlength, 1, 
							  CRYPT_MAX_HASHSIZE ) );
		memcpy( contentListItem->keyID, queryInfo->keyID,
				queryInfo->keyIDlength );
		contentListItem->keyIDsize = queryInfo->keyIDlength;
		}
	REQUIRES( boundsCheck( queryInfo->dataStart, queryInfo->dataLength, 
						   objectSize ) );
	contentListItem->payload = objectPtr + queryInfo->dataStart;
	contentListItem->payloadSize = queryInfo->dataLength;
	if( queryInfo->type == CRYPT_OBJECT_SIGNATURE && \
		queryInfo->formatType == CRYPT_FORMAT_CMS && \
		queryInfo->unauthAttributeStart > 0 )
		{
		CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;

		REQUIRES( boundsCheck( queryInfo->unauthAttributeStart,
							   queryInfo->unauthAttributeLength, 
							   objectSize ) );
		sigInfo->extraData2 = objectPtr + queryInfo->unauthAttributeStart;
		sigInfo->extraData2Length = queryInfo->unauthAttributeLength;
		}

	ENSURES( sanityCheckContentList( contentListItem ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int initEncKeyContentInfo( CONTENT_LIST *contentListItem,
								  const QUERY_INFO *queryInfo,
								  IN_BUFFER( objectSize ) const void *object, 
								  IN_LENGTH_SHORT const int objectSize )
	{
	CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;
	const BYTE *objectPtr = object;	/* For pointer maths */

	assert( isWritePtr( contentListItem, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( queryInfo, sizeof( QUERY_INFO ) ) );
	assert( isReadPtrDynamic( object, objectSize ) );

	REQUIRES( isShortIntegerRangeNZ( objectSize ) );

	/* Remember the details of the enveloping information that we require 
	   to continue */
	if( queryInfo->keySetupAlgo != CRYPT_ALGO_NONE )
		{
		contentListItem->envInfo = CRYPT_ENVINFO_PASSWORD;
		encrInfo->keySetupAlgo = queryInfo->keySetupAlgo;
		encrInfo->keySetupParam = queryInfo->keySetupParam;
		encrInfo->keySetupIterations = queryInfo->keySetupIterations;
		if( queryInfo->keySize > 0 )
			encrInfo->keySize = queryInfo->keySize;
		if( queryInfo->saltLength > 0 )
			{
			REQUIRES( rangeCheck( queryInfo->saltLength, 1, 
								  CRYPT_MAX_HASHSIZE ) );
			memcpy( encrInfo->saltOrIV, queryInfo->salt,
					queryInfo->saltLength );
			encrInfo->saltOrIVsize = queryInfo->saltLength;
			}
		}
	else
		contentListItem->envInfo = CRYPT_ENVINFO_KEY;
	encrInfo->cryptAlgo = queryInfo->cryptAlgo;
	encrInfo->cryptMode = queryInfo->cryptMode;
	REQUIRES( boundsCheck( queryInfo->dataStart, queryInfo->dataLength, 
						   objectSize ) );
	contentListItem->payload = objectPtr + queryInfo->dataStart;
	contentListItem->payloadSize = queryInfo->dataLength;

	ENSURES( sanityCheckContentList( contentListItem ) );

	return( CRYPT_OK );
	}

/* Add information about an object to an envelope's content information list.  
   The content information can be supplied in one of two ways, either 
   implicitly via the data in the stream or explicitly via a QUERY_INFO
   structure */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int addContentListItem( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr,
							   INOUT_PTR_OPT STREAM *stream, 
							   IN_PTR_OPT \
								const QUERY_INFO *externalQueryInfo,
							   OUT_LENGTH_SHORT_Z int *itemSize,
							   const QUERYOBJECT_TYPE objectTypeHint )
	{
	const CONTENT_LIST *contentListPtr = \
					DATAPTR_GET( envelopeInfoPtr->contentList );
	QUERY_INFO queryInfo;
	CONTENT_LIST *contentListItem;
	void *contentListObjectPtr = NULL;
	CONTENT_TYPE contentType;
	const BOOLEAN infoProvidedExternally = \
					( externalQueryInfo != NULL ) ? TRUE : FALSE;
	int objectSize = 0, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( ( stream == NULL && \
			  isReadPtr( externalQueryInfo, sizeof( QUERY_INFO ) ) ) || \
			( isWritePtr( stream, sizeof( STREAM ) ) && \
			  externalQueryInfo == NULL ) );
	assert( isWritePtr( itemSize, sizeof( int ) ) );
	assert( contentListPtr == NULL || \
			isReadPtr( contentListPtr, sizeof( CONTENT_LIST ) ) );

	REQUIRES( ( stream == NULL && externalQueryInfo != NULL ) || \
			  ( stream != NULL && externalQueryInfo == NULL ) );
	REQUIRES( isEnumRange( objectTypeHint, QUERYOBJECT ) );
	REQUIRES( DATAPTR_ISVALID( envelopeInfoPtr->contentList ) );

	/* Clear return values */
	*itemSize = 0;

	/* Make sure that there's room to add another list item */
	if( !moreContentItemsPossible( contentListPtr ) )
		{
		/* This is a recoverable error in the data-handling state so we have
		   to make it fatal for metadata handling */
		envelopeInfoPtr->errorState = CRYPT_ERROR_OVERFLOW;
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* Find the size of the object, allocate a buffer for it, and copy it
	   across */
	if( !infoProvidedExternally )
		{
		/* See what we've got.  This call verifies that all of the object 
		   data is present in the stream so in theory we don't have to check 
		   the following reads, but we check them anyway just to be sure */
		status = queryAsn1Object( stream, &queryInfo, objectTypeHint );
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_ERROR_OVERFLOW )
				{
				/* This is a recoverable error in the data-handling state so 
				   we have to make it fatal for metadata handling */
				envelopeInfoPtr->errorState = CRYPT_ERROR_OVERFLOW;
				}
			return( status );
			}
		if( !isShortIntegerRangeMin( queryInfo.size, 8 ) )
			{
			/* This is a recoverable error in the data-handling state so we 
			   have to make it fatal for metadata handling */
			envelopeInfoPtr->errorState = CRYPT_ERROR_OVERFLOW;
			return( CRYPT_ERROR_OVERFLOW );
			}
		ENSURES( isShortIntegerRangeNZ( queryInfo.size ) );
		objectSize = queryInfo.size;

		/* If it's a valid but unrecognised object type that was added after 
		   this version of cryptlib was released, skip it and continue.  
		   Alternatively, we could just add it to the content list as an 
		   unrecognised object type, but this would lead to confusion for 
		   the caller when non-object-types appear when they query the 
		   current component */
		if( queryInfo.type == CRYPT_OBJECT_NONE )
			{
			SET_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_ATTRSKIPPED );
			status = sSkip( stream, objectSize, SSKIP_MAX );
			if( cryptStatusError( status ) )
				return( status );
			*itemSize = objectSize;

			return( CRYPT_OK );
			}

		/* Read the object data into memory */
		REQUIRES( isShortIntegerRangeNZ( objectSize ) );
		if( ( contentListObjectPtr = clAlloc( "addContentListItem", \
											  objectSize ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		REQUIRES_PTR( rangeCheck( objectSize, 1, MAX_INTLENGTH_SHORT ),
					  contentListObjectPtr );
		status = sread( stream, contentListObjectPtr, objectSize );
		if( cryptStatusError( status ) )
			{
			clFree( "addContentListItem", contentListObjectPtr );
			return( status );
			}
		}
	else
		{
		/* The query information has been provided externally, use that.  
		   This is just a container for the information so the object
		   sizes is typically 0 */
		if( !isShortIntegerRange( externalQueryInfo->size ) )
			{
			/* This is a recoverable error in the data-handling state so 
			   we have to make it fatal for metadata handling */
			envelopeInfoPtr->errorState = CRYPT_ERROR_OVERFLOW;
			return( CRYPT_ERROR_OVERFLOW );
			}
		memcpy( &queryInfo, externalQueryInfo, sizeof( QUERY_INFO ) );
		}
	ENSURES( infoProvidedExternally || isIntegerRangeNZ( queryInfo.size ) );
			 /* If the query information is supplied externally then it's a 
			    template that doesn't correspond to any actual data */

	/* Determine the type of content that we're working with */
	if( queryInfo.type == CRYPT_OBJECT_SIGNATURE )
		contentType = CONTENT_SIGNATURE;
	else
		{
		if( isSpecialAlgo( queryInfo.cryptAlgo ) )
			contentType = CONTENT_AUTHENC;
		else
			contentType = CONTENT_CRYPT;
		}

	/* Allocate memory for the new content list item and copy information on
	   the item across.  After this point contentListObjectPtr is part of the
	   contentListItem so will be freed when that is freed */
	status = createContentListItem( &contentListItem, 
					envelopeInfoPtr->memPoolState, contentType, 
					queryInfo.formatType, contentListObjectPtr, 
					objectSize );
	if( cryptStatusError( status ) )
		{
		if( contentListObjectPtr != NULL )
			clFree( "addContentListItem", contentListObjectPtr );
		return( status );
		}
	if( infoProvidedExternally )
		{
		/* It's externally-supplied encryption algorithm details from an
		   encrypted data header, either standard encrypted data or 
		   authenticated encrypted data */
		status = initExternalContentInfo( contentListItem, contentType, 
										  &queryInfo );
		if( cryptStatusError( status ) )
			{
			deleteContentListItem( envelopeInfoPtr->memPoolState, 
								   contentListItem );
			return( status );
			}
		}
	else
		{
		/* Remember the details of the enveloping information that we 
		   require to continue */
		switch( queryInfo.type )
			{
			case CRYPT_OBJECT_PKCENCRYPTED_KEY:
			case CRYPT_OBJECT_SIGNATURE:
				status = initPkcContentInfo( contentListItem, &queryInfo,
											 contentListObjectPtr, 
											 objectSize );
				break;
				
			case CRYPT_OBJECT_ENCRYPTED_KEY:
				status = initEncKeyContentInfo( contentListItem, &queryInfo,
												contentListObjectPtr, 
												objectSize );
				break;
				
			default:
				retIntError();
			}
		if( cryptStatusError( status ) )
			{
			deleteContentListItem( envelopeInfoPtr->memPoolState, 
								   contentListItem );
			return( status );
			}
		}
	status = appendContentListItem( envelopeInfoPtr, contentListItem );
	if( cryptStatusError( status ) )
		{
		deleteContentListItem( envelopeInfoPtr->memPoolState, 
							   contentListItem );
		return( status );
		}
	ENSURES( isIntegerRange( queryInfo.size ) );
	*itemSize = ( int ) queryInfo.size;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Header Processing Routines						*
*																			*
****************************************************************************/

/* Process the outer CMS envelope header */

CHECK_RETVAL_BOOL \
static BOOLEAN checkActionCompatibility( IN_ENUM_OPT( ACTION ) \
											const ACTION_TYPE existingUsage,
										 IN_ENUM_OPT( ACTION ) \
											const ACTION_TYPE newAction )
	{
	const ACTION_TYPE newUsage = \
				( newAction == ACTION_KEYEXCHANGE || \
				  newAction == ACTION_xxx ) ? ACTION_CRYPT : newAction;
				/* Action -> usage mapping */

	REQUIRES_B( isEnumRangeOpt( existingUsage, ACTION ) );
	REQUIRES_B( isEnumRangeOpt( newAction, ACTION ) );
	
	/* If there's no existing action set or it's a no-op change, we're 
	   done */
	if( existingUsage == ACTION_NONE || existingUsage == newUsage )
		return( TRUE );
	
	/* There's an existing action already set, for example a signing action 
	   if the caller has provided a hash action for a detached signature,
	   make sure that the new action is compatible with it */
	switch( existingUsage )
		{
		case ACTION_CRYPT:
		case ACTION_MAC:
			/* In the current code this will never be reached because a pre-
			   set usage can only be ACTION_NONE or ACTION_SIGN, the 
			   following is here just to handle possible future changes and
			   will need to be cross-checked against all possible usage
			   combinations */
			if( newUsage == ACTION_KEYEXCHANGE || \
				newUsage == ACTION_xxx )
				return( TRUE );
			break;
		
		case ACTION_SIGN:
		case ACTION_COMPRESS:
			/* We can't change horses in mid-stream */ 
			break;

		default:
			retIntError_Boolean();
		}
	
	return( FALSE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processEnvelopeHeader( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr, 
								  INOUT_PTR STREAM *stream, 
								  OUT_ENUM_OPT( DEENVSTATE ) DEENV_STATE *state )
	{
	int status, action;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( state, sizeof( DEENV_STATE ) ) );

	/* Clear return value */
	*state = DEENVSTATE_NONE;

	/* Read the outer CMS header */
	status = readCMSheader( stream, envelopeOIDinfo,
							FAILSAFE_ARRAYSIZE( envelopeOIDinfo, OID_INFO ),
							&action, &envelopeInfoPtr->payloadSize, 
							READCMS_FLAG_NONE );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the new action is compatible with any possible 
	   existing action */
	if( !checkActionCompatibility( envelopeInfoPtr->usage, action ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, ENVELOPE_ERRINFO,
				  "CMS envelope header doesn't match the existing "
				  "%s usage set for the envelope", 
				  ( envelopeInfoPtr->usage == ACTION_SIGN ) ? \
				    "signing" : \
				  ( envelopeInfoPtr->usage == ACTION_COMPRESS ) ? \
				    "compression" : "encryption/authentication" ) );
		}

	/* Determine the next state to continue processing */
	switch( action )
		{
		case ACTION_NONE:
			/* Since we're going straight to the data payload there's no 
			   nested content type so we explicitly set it to "data" */
			envelopeInfoPtr->contentType = CRYPT_CONTENT_DATA;
			*state = DEENVSTATE_DATA;
			break;

		case ACTION_KEYEXCHANGE:
			envelopeInfoPtr->usage = ACTION_CRYPT;
			*state = DEENVSTATE_SET_ENCR;
			break;

		case ACTION_xxx:
			/* Authenticated encryption is a variant of a standard encrypted 
			   envelope */
			envelopeInfoPtr->usage = ACTION_CRYPT;
			SET_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_AUTHENC );
			*state = DEENVSTATE_SET_ENCR;
			break;

		case ACTION_CRYPT:
			envelopeInfoPtr->usage = ACTION_CRYPT;
			*state = DEENVSTATE_ENCRCONTENT;
			break;

		case ACTION_MAC:
			/* MACd envelopes have key exchange information at the start 
			   just like ACTION_KEYEXCHANGE but the later processing is 
			   different so we treat them as a special case here */
			envelopeInfoPtr->usage = ACTION_MAC;
			*state = DEENVSTATE_SET_ENCR;
			break;

		case ACTION_COMPRESS:
			/* With compressed data all that we need to do is check that the 
			   fixed AlgorithmIdentifier is present and set up the 
			   decompression stream, after which we go straight to the 
			   content */
			status = readGenericAlgoID( stream, OID_ZLIB, 
										sizeofOID( OID_ZLIB ) ); 
			if( cryptStatusError( status ) )
				return( status );
			envelopeInfoPtr->usage = ACTION_COMPRESS;
#ifdef USE_COMPRESSION
			if( inflateInit( &envelopeInfoPtr->zStream ) != Z_OK )
				return( CRYPT_ERROR_MEMORY );
			SET_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_ZSTREAMINITED );
			*state = DEENVSTATE_CONTENT;
#else
			return( CRYPT_ERROR_NOTAVAIL );
#endif /* USE_COMPRESSION */
			break;

		case ACTION_SIGN:
			envelopeInfoPtr->usage = ACTION_SIGN;
			*state = DEENVSTATE_SET_HASH;
			break;

		default:
			retIntError();
		}

	return( CRYPT_OK );
	}

/* Process the encrypted content header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processEncryptionHeader( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr, 
									INOUT_PTR STREAM *stream )
	{
	const ACTION_LIST *actionListPtr = \
				DATAPTR_GET( envelopeInfoPtr->actionList );
	QUERY_INFO queryInfo;
	int contentType, dummy, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( DATAPTR_ISVALID( envelopeInfoPtr->actionList ) );

	/* Read the encrypted content header */
	status = readCMSencrHeader( stream, nestedContentOIDinfo, 
						FAILSAFE_ARRAYSIZE( nestedContentOIDinfo, OID_INFO ),
						&contentType, NULL, &queryInfo,
						TEST_FLAG( envelopeInfoPtr->flags, \
								   ENVELOPE_FLAG_AUTHENC ) ? \
							READCMS_FLAG_AUTHENC : READCMS_FLAG_NONE );
	if( cryptStatusError( status ) )
		return( status );
	envelopeInfoPtr->contentType = contentType;
	envelopeInfoPtr->payloadSize = queryInfo.size;

	/* We've reached encrypted data, we can't go any further until we can 
	   either recover the session key from a key exchange object or are fed 
	   the session key directly.  The key can only be added once the session-
	   key content-list item below exists, so there can't be any actions 
	   present at this point */
	REQUIRES( actionListPtr == NULL );

	/* Since the content can be indefinite-length we clear the size field to 
	   give it a sensible setting */
	queryInfo.size = 0;
	return( addContentListItem( envelopeInfoPtr, NULL, &queryInfo, 
								&dummy, QUERYOBJECT_KEYEX ) );
	}

/* Process the hash or MAC object header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processHashHeader( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr, 
							  INOUT_PTR STREAM *stream,
							  IN_BOOL const BOOLEAN isHash )
	{
	CRYPT_CONTEXT iHashContext;
	LOOP_INDEX_PTR ACTION_LIST *actionListPtr;
	int hashAlgo DUMMY_INIT, hashParam = 0;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( isBooleanValue( isHash ) );

	/* Create the hash/MAC object from the data */
	status = readContextAlgoID( stream, &iHashContext, NULL, DEFAULT_TAG,
								isHash ? ALGOID_CLASS_HASH : \
										 ALGOID_CLASS_MAC );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && \
		( isParameterisedHashAlgo( hashAlgo ) || \
		  isParameterisedMacAlgo( hashAlgo ) ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &hashParam, CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Check whether an identical hash/MAC action is already present.  If it 
	   was added by being supplied externally for a detached signature then 
	   this is OK, otherwise it's an error arising from a duplicate entry in 
	   the set of digest/MAC algorithms in the envelope header.
	   
	   There's a second potential problem which we check for later, the 
	   presence of two hash algorithms with the same block size when signed
	   attributes are used.  Since the MessageDigest attribute that contains
	   them has no type information associated with it, there's no way to
	   tell which algorithm was meant.  This is handled separately, since
	   the problem only occurs when we lose type information via the signed
	   attributes */
	LOOP_MED( actionListPtr = DATAPTR_GET( envelopeInfoPtr->actionList ), 
			  actionListPtr != NULL, 
			  actionListPtr = DATAPTR_GET( actionListPtr->next ) )
		{
		CRYPT_ALGO_TYPE actionHashAlgo DUMMY_INIT;
		int actionHashParam = 0, value;

		REQUIRES( sanityCheckActionList( actionListPtr ) );

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		status = krnlSendMessage( actionListPtr->iCryptHandle,
								  IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) )
			{
			actionHashAlgo = value;		/* int vs.enum */
			if( isParameterisedHashAlgo( actionHashAlgo ) || \
				isParameterisedMacAlgo( actionHashAlgo ) )
				{
				status = krnlSendMessage( actionListPtr->iCryptHandle, 
										  IMESSAGE_GETATTRIBUTE, 
										  &actionHashParam, 
										  CRYPT_CTXINFO_BLOCKSIZE );
				}
			}
		if( cryptStatusError( status ) )
			{
			/* In theory this could also be an ENSURES() since we've just 
			   created the objects via processHashHeader(), but that was 
			   outside this function so technically we don't know that and
			   are treating them as generic external parameters */
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		if( actionHashAlgo == hashAlgo && actionHashParam == hashParam )
			{
			/* There's a duplicate action present, destroy the one that 
			   we've just created.  If it was added explicitly by the caller 
			   then we're done */
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			if( TEST_FLAG( actionListPtr->flags, 
						   ACTION_FLAG_ADDEDEXTERNALLY ) )
				return( CRYPT_OK );

			/* There's a duplicate entry in the envelope header, this is an 
			   error */
			return( CRYPT_ERROR_DUPLICATE );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	/* We didn't find any duplicates, append the new hash/MAC action to the 
	   action list and remember that hashing/MACing is now active */
	status = addAction( envelopeInfoPtr, isHash ? ACTION_HASH : ACTION_MAC, 
						iHashContext );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	SET_FLAG( envelopeInfoPtr->dataFlags, ENVDATA_FLAG_HASHACTIONSACTIVE );
	
	actionListPtr = DATAPTR_GET( envelopeInfoPtr->actionList );
	ENSURES( actionListPtr != NULL && \
			 ( actionListPtr->action == ACTION_HASH || \
			   actionListPtr->action == ACTION_MAC ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Trailer Processing Routines						*
*																			*
****************************************************************************/

/* Process EOCs that separate the payload from the trailer.  
   envelope/decode:processSegment() has already consumed the EOC at the end
   of the last segment of the payload so what's left is the encapsulation 
   above that */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processPayloadEOCs( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr, 
							   INOUT_PTR STREAM *stream )
	{
	const int noEOCs = ( envelopeInfoPtr->usage == ACTION_CRYPT ) ? 1 : 2;
	LOOP_INDEX i;
	int status;
	
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( envelopeInfoPtr->usage != ACTION_CRYPT || \
			  TEST_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_AUTHENC ) );
			  /* AuthEnv = 1 EOC, SignedData or AuthData = 2 EOCs */

	/* If the payload has an indefinite-length encoding, make sure that the
	   required EOCs are present */
	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
		{
		LOOP_SMALL( i = 0, i < noEOCs, i++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL( i, 0, noEOCs - 1 ) );

			status = checkEOC( stream );
			if( status != TRUE )
				{
				return( cryptStatusError( status ) ? \
						status : CRYPT_ERROR_BADDATA );
				}
			}
		ENSURES( LOOP_BOUND_OK );

		return( CRYPT_OK );
		}

	/* If the data was encoded using a mixture of definite and indefinite 
	   encoding there may be EOC's present even though the length is known 
	   so we skip them if necessary */
	if( ( status = checkEOC( stream ) ) == TRUE )
		status = checkEOC( stream );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}

/* Check for a possible soft error when reading data.  This is necessary 
   because if we're performing a standard data push then the caller expects 
   to get a CRYPT_OK status with a bytes-copied count, but if they've got as 
   far as the trailer data then they'll get a CRYPT_ERROR_UNDERFLOW unless 
   we special-case the handling of the return status.
   
   This is complicated by the fact that we have to distinguish a 
   CRYPT_ERROR_UNDERFLOW due to running out of input from a 
   CRYPT_ERROR_UNDERFLOW incurred for any other reason such as parsing the 
   input data.  It isn't actually possible to reliably do this without
   instrumenting every function all the way down, so we make a best-effort
   attempt by reporting a non-flush underflow as a soft error and a flush
   underflow as a hard error */

CHECK_RETVAL_BOOL \
static BOOLEAN checkSoftError( IN_ERROR const int status, 
							   IN_BOOL const BOOLEAN isFlush )
	{
	REQUIRES_B( cryptStatusError( status ) );
	REQUIRES_B( isBooleanValue( isFlush ) );

	/* If it's not a flush and we've run out of data, report it as a soft 
	   error */
	if( !isFlush && status == CRYPT_ERROR_UNDERFLOW )
		return( TRUE );
		
	return( FALSE );
	}

/* Complete processing of the authenticated payload for hashed, MACd, 
   signed, and authenticated encrypted data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completePayloadProcessing( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr )
	{
	const ENV_PROCESSEXTRADATA_FUNCTION processExtraDataFunction = \
				( ENV_PROCESSEXTRADATA_FUNCTION ) \
				FNPTR_GET( envelopeInfoPtr->processExtraDataFunction );

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( processExtraDataFunction != NULL );

	/* When we reach this point there may still be unhashed data left in the 
	   buffer.  It won't have been hashed yet because the hashing is 
	   performed when the data is copied out, after unwrapping and 
	   deblocking and whatnot, so we hash it before we wrap up the 
	   hashing (the exception to this is authenticated encrypted data which
	   is MACd before decryption, but that's handled internally by the data-
	   decoding process) */
	if( envelopeInfoPtr->dataLeft > 0 )
		{
		int status;

		status = processExtraDataFunction( envelopeInfoPtr, 
						envelopeInfoPtr->buffer, envelopeInfoPtr->dataLeft );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Wrap up the hashing */
	return( processExtraDataFunction( envelopeInfoPtr, "", 0 ) );
	}

/* Process the signed data trailer */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processSignedTrailer( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr, 
								 INOUT_PTR STREAM *stream, 
								 INOUT_ENUM_OPT( DEENVSTATE ) \
									DEENV_STATE *state,
								 IN_BOOL const BOOLEAN isFlush )
	{
	DEENV_STATE newState;
	int tag, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( state, sizeof( DEENV_STATE ) ) );

	REQUIRES( isBooleanValue( isFlush ) );
	REQUIRES( envelopeInfoPtr->usage == ACTION_SIGN );

	/* Read the SignedData EOC's if necessary */
	status = processPayloadEOCs( envelopeInfoPtr, stream );
	if( cryptStatusError( status ) )
		{
		return( checkSoftError( status, isFlush ) ? \
				OK_SPECIAL : status );
		}

	/* Check whether there's a certificate chain to follow */
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		{
		return( checkSoftError( status, isFlush ) ? \
				OK_SPECIAL : status );
		}
	newState = ( tag == MAKE_CTAG( 0 ) ) ? \
			   DEENVSTATE_CERTSET : DEENVSTATE_SET_SIG;
	if( tag == MAKE_CTAG( 1 ) )
		{
		/* These have never been encountered so all we do for now is warn in
		   debug mode and fail with a bad-data error further down.  They can
		   also be encountered after DEENVSTATE_CERTSET but again we just
		   report a bad-data error there */
		DEBUG_DIAG(( "CRLs encountered in CMS SignedData" ));
		assert_nofuzz( DEBUG_WARN );
		}

	/* If we've seen all of the signed data, complete the hashing */
	if( !TEST_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_DETACHED_SIG ) )
		{
		status = completePayloadProcessing( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Move on to the next state */
	*state = newState;
	return( CRYPT_OK );
	}

/* Process the MACd data trailer.  Note that some data-formatting errors 
   encountered at this level may be converted into an authentication-failure 
   status by the calling code to avoid truncation attacks, see the comment
   in processPostable() for more details */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processMacTrailer( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr, 
							  INOUT_PTR STREAM *stream, 
							  OUT_BOOL BOOLEAN *failedMAC,
							  IN_BOOL const BOOLEAN isFlush )
	{
	const ACTION_LIST *actionListPtr;
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	int hashSize, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( failedMAC, sizeof( BOOLEAN ) ) );

	REQUIRES( isBooleanValue( isFlush ) );
	REQUIRES( envelopeInfoPtr->usage == ACTION_MAC || \
			  ( envelopeInfoPtr->usage == ACTION_CRYPT && \
				TEST_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_AUTHENC ) ) );
				
  	/* Clear return value */
	*failedMAC = FALSE;

	/* Read the AuthenticatedData EOCs if necessary */
	status = processPayloadEOCs( envelopeInfoPtr, stream );
	if( cryptStatusError( status ) )
		{
		/* processPayloadEOCs() can't return anything that would be 
		   converted to a fatal error */
		return( checkSoftError( status, isFlush ) ? \
				OK_SPECIAL : status );
		}

	/* Read the MAC value that follows the payload */
	status = readOctetString( stream, hash, &hashSize, MIN_HASHSIZE, 
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_OVERFLOW )
			{
			/* This is a recoverable error in the data-handling state so we 
			   convert it to a non-recoverable one to let the caller handle
			   it as such */
			status = CRYPT_ERROR_BADDATA;
			}
		return( checkSoftError( status, isFlush ) ? \
				OK_SPECIAL : status );
		}

	/* Complete the payload processing and compare the read MAC value with 
	   the calculated one */
	status = completePayloadProcessing( envelopeInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, hash, hashSize );
	actionListPtr = findAction( envelopeInfoPtr, ACTION_MAC );
	ENSURES( actionListPtr != NULL );
	REQUIRES( sanityCheckActionList( actionListPtr ) );
	status = krnlSendMessage( actionListPtr->iCryptHandle, IMESSAGE_COMPARE, 
							  &msgData, MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		/* Unlike signatures a failed MAC check (reported as a CRYPT_ERROR
		   comparison result) is detected immediately rather than after the
		   payload processing has completed.  However if we bail out now 
		   then any later checks of things like signature metadata will fail 
		   because the envelope regards processing as still being incomplete 
		   so we have to continue processing data until we at least get the 
		   envelope to the finished state */
		assert( status == CRYPT_ERROR );
		*failedMAC = TRUE;
		}

	return( CRYPT_OK );
	}

/* Process any remaining EOCs.  This gets a bit complicated because there 
   can be a variable number of EOCs depending on where definite and 
   indefinite encodings were used so we look for at least one EOC and at 
   most a number that depends on the data type being processed */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processEOCTrailer( IN_PTR const ENVELOPE_INFO *envelopeInfoPtr,
							  INOUT_PTR STREAM *stream,
							  IN_BOOL const BOOLEAN isFlush )
	{
	LOOP_INDEX i;
	int noEOCs;

	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isBooleanValue( isFlush ) );

	/* Consume any EOCs up to the maximum amount possible.  In theory we 
	   could be rather liberal with trailing EOCs since it's not really 
	   necessary for the caller to push in every last one, however if we
	   assume that seeing at least one EOC is enough to signal the end of
	   all content this can lead to problems if adding the EOCs occurs
	   over a pushData boundary.  What can happen here is that the code will 
	   see the start of the string of EOCs on the first push, record the 
	   end-of-data-reached state, and then report a CRYPT_ERROR_COMPLETE 
	   when the remainder of the string of EOCs are pushed the next time
	   round.  To avoid this problem we have to be pedantic and require
	   that callers push all EOCs */
	switch( envelopeInfoPtr->usage )
		{
		case ACTION_NONE:
			noEOCs = 2;
			break;

		case ACTION_CRYPT:
			/* Authenticated encryption is a special case since there's a 
			   MAC value present after the data, so the EOCs for the 
			   EncryptedContentInfo encapsulation have already been consumed 
			   in getting to the MAC value, leaving those for the 
			   AuthEnvelopedData, [0] and ContentInfo */
			if( TEST_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_AUTHENC ) )
				noEOCs = 3;
			else
				noEOCs = 4;
			break;

		case ACTION_SIGN:
		case ACTION_MAC:
			noEOCs = 3;
			break;

		case ACTION_COMPRESS:
			noEOCs = 5;
			break;

		default:
			retIntError();
		}
	LOOP_SMALL( i = 0, i < noEOCs, i++ )
		{
		int value;

		ENSURES( LOOP_INVARIANT_SMALL( i, 0, noEOCs - 1 ) );

		value = checkEOC( stream );
		if( cryptStatusError( value ) )
			{
			return( checkSoftError( value, isFlush ) ? \
					OK_SPECIAL : value );
			}
		if( value == FALSE )
			return( CRYPT_ERROR_BADDATA );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Process Envelope Preamble/Postamble					*
*																			*
****************************************************************************/

/* Process the non-data portions of an envelope.  This is a complex event-
   driven state machine, but instead of reading along a (hypothetical
   Turing-machine) tape someone has taken the tape and cut it into bits and
   keeps feeding them to us and saying "See what you can do with this" (and
   occasionally "Where's the bloody spoons?").  The following code implements
   this state machine:

			Keyex / MAC / XXXX
	NONE ----------------------------------------> SET_ENCR 
													  |
													  v
			Sign				+------------------ ENCR <----+
		 --------> SET_HASH		|					  | |Keyex|	
						|		|					  |	+-----+
						|		|(MAC)				  |(Non-MAC)
			Sessionkey	|		|					  v
		 --------------------------------------> ENCRCONTENT
						|		|					  |	
						v		|					  |
				+----> HASH	   MAC					  |
				|Hash |	|		|					  |
				+-----+	|		|					  |
						 \	   /					  |
			Copr.		  v	  v						  |
		 --------------> CONTENT					  |
							+-------+	+-------------+
									|	|
			Data					v	v
		 -------------------------> DATA
									  |
									  v
									DONE

	If type == Sign and detached-sig, CONTENT transitions directly to DONE */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int processPreamble( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	int remainder, streamPos = 0;
	LOOP_INDEX noHeaderItems;
	int value, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	
	REQUIRES( sanityCheckEnvCMSDenv( envelopeInfoPtr ) );

	/* We could have come back to here from a previous attempt, in which 
	   case we need to clear any residual error message from then */
	clearErrorInfo( ENVELOPE_ERRINFO );

	/* We can end up with no data left in the envelope buffer if we've 
	   previously processed data that didn't get us out of the preamble and 
	   the caller performs a flush, so we explicitly check for an underflow 
	   here */
	if( envelopeInfoPtr->bufPos <= 0 )
		return( CRYPT_ERROR_UNDERFLOW );

	sMemConnect( &stream, envelopeInfoPtr->buffer, envelopeInfoPtr->bufPos );

	/* If we haven't started doing anything yet try and read the outer
	   header fields */
	if( state == DEENVSTATE_NONE )
		{
		status = processEnvelopeHeader( envelopeInfoPtr, &stream, &state );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			if( status == CRYPT_ERROR_UNDERFLOW )
				{
				/* This is a (probably) recoverable error, don't set the 
				   extended error information */
				return( status );
				}
			retExtErr( status,
					   ( status, ENVELOPE_ERRINFO, ENVELOPE_ERRINFO,
						 "Invalid CMS envelope header" ) );
			}

		/* Remember how far we got */
		streamPos = stell( &stream );
		ENSURES( isBufsizeRangeNZ( streamPos ) );
		}

	/* Keep consuming information until we either run out of input or reach 
	   the data payload */
	static_assert( MAX_DATA_ITEMS < FAILSAFE_ITERATIONS_MED, \
				   "MAX_DATA_ITEMS" );
	LOOP_MED( noHeaderItems = 0, 
			  cryptStatusOK( status ) && state != DEENVSTATE_DONE && \
					noHeaderItems < MAX_DATA_ITEMS, 
			  noHeaderItems++ )
		{
		ENSURES( LOOP_INVARIANT_MED( noHeaderItems, \
									 0, MAX_DATA_ITEMS - 1 ) );

		switch( state )
			{
			/* Read the start of the SET OF RecipientInfo/SET OF 
			   DigestAlgorithmIdentifier */
			case DEENVSTATE_SET_ENCR:
			case DEENVSTATE_SET_HASH:
				{
				const BOOLEAN isEncr = ( state == DEENVSTATE_SET_ENCR ) ? \
										 TRUE : FALSE;
#ifdef USE_ERRMSGS
				const char *errorString = isEncr ? \
							"Invalid SET OF RecipientInfo header" : \
							"Invalid SET OF DigestAlgorithmIdentifier header";
				const int errorStringLength = isEncr ? 35 : 47;
#endif /* USE_ERRMSGS */
				int setLength;

				/* Read the SET tag and length.  readSetI() allows either a 
				   nonzero definite length or an indefinite length */
				status = readSetI( &stream, &setLength );
				if( cryptStatusError( status ) )
					{
					if( status == CRYPT_ERROR_OVERFLOW )
						{
						/* This is a recoverable error in the data-handling 
						   state so we have to make it fatal for metadata 
						   handling */
						envelopeInfoPtr->errorState = CRYPT_ERROR_OVERFLOW;
						}
					setErrorString( ENVELOPE_ERRINFO, errorString, 
									errorStringLength );
					break;
					}
				if( setLength == CRYPT_UNUSED )
					{
					/* An indefinite-length set doesn't tell us how many
					   items are present so we have to explicitly check for
					   an EOC following the SET OF, which would indicate an
					   empty set.  checkEOC() leaves the stream untouched if
					   there's no EOC present so it's safe to use here */
					status = value = checkEOC( &stream );
					if( cryptStatusError( status ) )
						break;
					if( value == TRUE )
						{
						setErrorString( ENVELOPE_ERRINFO, errorString, 
										errorStringLength );
						status = CRYPT_ERROR_BADDATA;
						break;
						}
					status = CRYPT_OK;
					}
				envelopeInfoPtr->hdrSetLength = setLength;

				/* Remember where we are and move on to the next state.  
				   Some implementations use the indefinite-length encoding 
				   for this so if there's no length given (setLength == 
				   CRYPT_UNUSED) we have to look for the EOC after each 
				   entry read */
				streamPos = stell( &stream );
				ENSURES( isBufsizeRangeNZ( streamPos ) );
				state = isEncr ? DEENVSTATE_ENCR : DEENVSTATE_HASH;
				break;
				}

			/* Read and remember a key exchange object from a RecipientInfo */
			case DEENVSTATE_ENCR:
				{
				int contentItemLength;

				/* If it's an indefinite-length SET OF then we may have 
				   reached the end of the set of items */
				if( envelopeInfoPtr->hdrSetLength == CRYPT_UNUSED )
					{
					status = value = checkEOC( &stream );
					if( cryptStatusError( status ) )
						break;
					if( value == TRUE )
						{
						streamPos = stell( &stream );
						ENSURES( isBufsizeRangeNZ( streamPos ) );
						state = ( envelopeInfoPtr->usage == ACTION_MAC ) ? \
								  DEENVSTATE_MAC : DEENVSTATE_ENCRCONTENT;
						status = CRYPT_OK;
						break;
						}
					}

				/* Add the object to the content information list */
				status = addContentListItem( envelopeInfoPtr, &stream, NULL, 
											 &contentItemLength, 
											 QUERYOBJECT_KEYEX );
				if( cryptStatusError( status ) )
					{
					setErrorString( ENVELOPE_ERRINFO, 
									"Invalid RecipientInfo key exchange "
									"information", 46 );
					break;
					}

				/* Remember where we are and move on to the next state if
				   necessary */
				streamPos = stell( &stream );
				ENSURES( isBufsizeRangeNZ( streamPos ) );
				if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
					{
					if( !rangeCheck( contentItemLength, 1, \
									 envelopeInfoPtr->hdrSetLength ) )
						{
						status = CRYPT_ERROR_BADDATA;
						break;
						}
					REQUIRES( !checkOverflowSub( envelopeInfoPtr->hdrSetLength, 
												 contentItemLength ) );
					envelopeInfoPtr->hdrSetLength -= contentItemLength;
					if( envelopeInfoPtr->hdrSetLength <= 0 )
						{
						state = ( envelopeInfoPtr->usage == ACTION_MAC ) ? \
								  DEENVSTATE_MAC : DEENVSTATE_ENCRCONTENT;
						}
					}
				break;
				}

			/* Read the encrypted content information */
			case DEENVSTATE_ENCRCONTENT:
				/* If we skipped processing any key exchange actions because 
				   we didn't know what to do with them, make sure that we 
				   can actually continue beyond this point */
				if( TEST_FLAG( envelopeInfoPtr->flags, 
							   ENVELOPE_FLAG_ATTRSKIPPED ) )
					{
					status = checkContinueDeenv( envelopeInfoPtr );
					if( cryptStatusError( status ) )
						{
						setErrorString( ENVELOPE_ERRINFO, 
										"Couldn't continue to encrypted "
										"payload processing due to absence "
										"of usable key exchange "
										"information", 
										99 );
						break;
						}
					}

				/* Start processing the encrypted data */
				status = processEncryptionHeader( envelopeInfoPtr, &stream );
				if( cryptStatusError( status ) )
					{
					/* We may get non-data-related errors like 
					   CRYPT_ERROR_WRONGKEY so we only set extended error 
					   information if it's a data-related error */
					if( isDataError( status ) )
						{
						setErrorString( ENVELOPE_ERRINFO, 
										"Invalid EncryptedContentInfo "
										"content header", 43 );
						}
					break;
					}

				/* Remember where we are and move on to the next state */
				streamPos = stell( &stream );
				ENSURES( isBufsizeRangeNZ( streamPos ) );
				state = DEENVSTATE_DATA;
				REQUIRES( DATAPTR_ISVALID( envelopeInfoPtr->actionList ) );
				if( DATAPTR_ISNULL( envelopeInfoPtr->actionList ) )
					{
					/* If we haven't got a session key to decrypt the data 
					   that follows then we can't go beyond this point */
					status = CRYPT_ENVELOPE_RESOURCE;
					break;
					}
				break;

			/* Read and remember a MAC object from a MACAlgorithmIdentifier
			   record */
			case DEENVSTATE_MAC:
				status = processHashHeader( envelopeInfoPtr, &stream, FALSE );
				if( cryptStatusError( status ) )
					{
					setErrorString( ENVELOPE_ERRINFO, 
									"Invalid AuthenticatedData content "
									"header", 40 );
					break;
					}

				/* Remember where we are and move on to the next state */
				streamPos = stell( &stream );
				ENSURES( isBufsizeRangeNZ( streamPos ) );
				state = DEENVSTATE_CONTENT;

				/* If we skipped processing any key exchange actions because 
				   we didn't know what to do with them, make sure that we 
				   can actually continue beyond this point */
				if( TEST_FLAG( envelopeInfoPtr->flags, 
							   ENVELOPE_FLAG_ATTRSKIPPED ) )
					{
					status = checkContinueDeenv( envelopeInfoPtr );
					if( cryptStatusError( status ) )
						{
						setErrorString( ENVELOPE_ERRINFO, 
										"Couldn't continue to MAC'd payload "
										"processing due to absence of "
										"usable key exchange information", 
										95 );
						break;
						}
					}
				break;

			/* Read and remember a hash object from a 
			   DigestAlgorithmIdentifier record */
			case DEENVSTATE_HASH:
				/* If it's an indefinite-length SET OF then we may have 
				   reached the end of the set of items */
				if( envelopeInfoPtr->hdrSetLength == CRYPT_UNUSED )
					{
					status = value = checkEOC( &stream );
					if( cryptStatusError( status ) )
						break;
					if( value == TRUE )
						{
						streamPos = stell( &stream );
						ENSURES( isBufsizeRangeNZ( streamPos ) );
						state = DEENVSTATE_CONTENT;
						status = CRYPT_OK;
						break;
						}
					}

				status = processHashHeader( envelopeInfoPtr, &stream, TRUE );
				if( cryptStatusError( status ) )
					{
					setErrorString( ENVELOPE_ERRINFO, 
									"Invalid SignedData content header", 
									33 );
					break;
					}

				/* Remember where we are and move on to the next state if
				   necessary */
				if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
					{
					int hashInfoLength;

					status = streamOffsetFromPosition( &stream, streamPos, 
													   &hashInfoLength );
					if( cryptStatusError( status ) )
						break;
					if( hashInfoLength < 0 || \
						hashInfoLength > envelopeInfoPtr->hdrSetLength )
						{
						status = CRYPT_ERROR_BADDATA;
						break;
						}
					REQUIRES( !checkOverflowSub( envelopeInfoPtr->hdrSetLength, 
												 hashInfoLength ) );
					envelopeInfoPtr->hdrSetLength -= hashInfoLength;
					if( envelopeInfoPtr->hdrSetLength <= 0 )
						state = DEENVSTATE_CONTENT;
					}
				streamPos = stell( &stream );
				ENSURES( isBufsizeRangeNZ( streamPos ) );
				break;

			/* Read the encapsulated content header */
			case DEENVSTATE_CONTENT:
				{
				int contentType;

				status = \
					readCMSheader( &stream, nestedContentOIDinfo,
								   FAILSAFE_ARRAYSIZE( nestedContentOIDinfo, 
													   OID_INFO ),
								   &contentType, &envelopeInfoPtr->payloadSize, 
								   READCMS_FLAG_INNERHEADER );
				if( cryptStatusError( status ) )
					{
					if( envelopeInfoPtr->usage == ACTION_CRYPT )
						{
						setErrorString( ENVELOPE_ERRINFO, 
										"Invalid EncryptedContentInfo "
										"content header", 43 );
						}
					else
						{
						setErrorString( ENVELOPE_ERRINFO, 
										"Invalid EncapsulatedContentInfo "
										"content header", 46 );
						}
					break;
					}
				envelopeInfoPtr->contentType = contentType;

				/* If the caller has told us earlier that this is a detached 
				   signature then  there can't be any content present */
				if( TEST_FLAG( envelopeInfoPtr->flags, \
							   ENVELOPE_FLAG_DETACHED_SIG ) && \
					envelopeInfoPtr->payloadSize != 0 )
					{
					setErrorString( ENVELOPE_ERRINFO, 
									"Detached signature contains spurious "
									"signed content", 51 );
					status = CRYPT_ERROR_BADDATA;
					break;
					}

				/* If there's no content included and it's not an attributes-
				   only message then this is a detached signature with the 
				   content supplied anderswhere */
				if( envelopeInfoPtr->payloadSize == 0 && \
					envelopeInfoPtr->usage == ACTION_SIGN && \
					!TEST_FLAG( envelopeInfoPtr->flags, 
								ENVELOPE_FLAG_ATTRONLY ) )
					{
					SET_FLAG( envelopeInfoPtr->flags, 
							  ENVELOPE_FLAG_DETACHED_SIG );
					}

				/* Remember where we are and move on to the next state */
				streamPos = stell( &stream );
				ENSURES( isBufsizeRangeNZ( streamPos ) );
				state = ( envelopeInfoPtr->payloadSize == 0 && \
						  TEST_FLAG( envelopeInfoPtr->flags,
									 ENVELOPE_FLAG_DETACHED_SIG | \
									 ENVELOPE_FLAG_ATTRONLY ) ) ? \
						DEENVSTATE_DONE : DEENVSTATE_DATA;

				/* If this is MACd data and we haven't loaded a key to MAC 
				   the data that follows then we can't go beyond this point */
				if( envelopeInfoPtr->usage == ACTION_MAC )
					{
					const ACTION_LIST *actionListPtr = \
									DATAPTR_GET( envelopeInfoPtr->actionList );

					REQUIRES( DATAPTR_ISVALID( envelopeInfoPtr->actionList ) );
					if( actionListPtr == NULL )
						{
						status = CRYPT_ENVELOPE_RESOURCE;
						break;
						}
					REQUIRES( actionListPtr->action == ACTION_MAC );
					if( !checkContextCapability( actionListPtr->iCryptHandle,
												 MESSAGE_CHECK_MAC ) )
						{
						status = CRYPT_ENVELOPE_RESOURCE;
						break;
						}
					}
				break;
				}

			/* Start the decryption process if necessary */
			case DEENVSTATE_DATA:
				{
				const ENV_SYNCDEENVELOPEDATA_FUNCTION syncDeenvelopeDataFunction = \
						( ENV_SYNCDEENVELOPEDATA_FUNCTION ) \
						FNPTR_GET( envelopeInfoPtr->syncDeenvelopeDataFunction );

				REQUIRES( syncDeenvelopeDataFunction != NULL );

				/* Synchronise the data stream processing to the start of 
				   the encrypted data and move back to the start of the data
				   stream */
				status = syncDeenvelopeDataFunction( envelopeInfoPtr, &stream );
				if( cryptStatusError( status ) )
					{
					/* If we get a CRYPT_ERROR_SIGNATURE at this point then 
					   it's because we're using authenticated encryption and 
					   data corruption was detected via a mechanism like a 
					   block padding check failure long before we get to the 
					   MAC verification stage, in which case we pass the 
					   error on up unaltered */
					if( status == CRYPT_ERROR_SIGNATURE )
						{
						setErrorString( ENVELOPE_ERRINFO, 
										"Decrypted data corruption "
										"detected, block padding check "
										"failed", 62 );
						break;
						}

					setErrorString( ENVELOPE_ERRINFO, 
									"Couldn't synchronise envelope state "
									"prior to data payload processing", 68 );
					break;
					}

				/* The data has now been resynchronised with the start of 
				   stream, and we're done */
				streamPos = 0;	
				state = DEENVSTATE_DONE;

				ENSURES( checkActions( envelopeInfoPtr ) );

				break;
				}

			default:
				retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	sMemDisconnect( &stream );
	if( state != DEENVSTATE_DONE && cryptStatusOK( status ) && \
		noHeaderItems >= MAX_DATA_ITEMS )
		{
		/* Technically this would be an overflow but that's a recoverable
		   error so we make it a BADDATA, which is really what it is */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, ENVELOPE_ERRINFO, 
				  "Encountered more than %d envelope header items",
				  noHeaderItems ) );
		}
	envelopeInfoPtr->deenvState = state;

	/* At this point we may have a success or an error status, but we need 
	   to continue with cleanup functions before we exit on error */

	ENSURES( isBufsizeRange( streamPos ) && \
			 envelopeInfoPtr->bufPos - streamPos >= 0 );

	/* Consume the input that we've processed so far by moving everything 
	   past the current position down to the start of the envelope buffer */
	REQUIRES( !checkOverflowSub( envelopeInfoPtr->bufPos, streamPos ) );
	remainder = envelopeInfoPtr->bufPos - streamPos;
	REQUIRES( isBufsizeRange( remainder ) && \
			  streamPos + remainder <= envelopeInfoPtr->bufSize );
	if( remainder > 0 && streamPos > 0 )
		{
		REQUIRES( boundsCheck( streamPos, remainder, 
							   envelopeInfoPtr->bufSize ) );
		memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + streamPos,
				 remainder );
		}
	envelopeInfoPtr->bufPos = remainder;
	ENSURES( sanityCheckEnvCMSDenv( envelopeInfoPtr ) );
	if( cryptStatusError( status ) )
		return( status );

	/* If all went OK but we're still not out of the header information,
	   return an underflow error */
	return( ( state != DEENVSTATE_DONE ) ? \
			CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1 ) ) \
static int processPostamble( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr,
							 IN_BOOL const BOOLEAN isFlush )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	const BOOLEAN hasAuthTrailer = \
		   envelopeInfoPtr->usage == ACTION_MAC || \
		   ( envelopeInfoPtr->usage == ACTION_CRYPT && \
			 TEST_FLAG( envelopeInfoPtr->flags, \
						ENVELOPE_FLAG_AUTHENC ) ) ? TRUE : FALSE; 
	BOOLEAN failedMAC = FALSE;
	LOOP_INDEX noTrailerItems;
	int remainder, streamPos = 0, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( sanityCheckEnvCMSDenv( envelopeInfoPtr ) );
	REQUIRES( isBooleanValue( isFlush ) );

	/* We could have come back to here from a previous attempt, in which 
	   case we need to clear any residual error message from then */
	clearErrorInfo( ENVELOPE_ERRINFO );

	/* If that's all that there is, return */
	if( state == DEENVSTATE_NONE && \
		!( envelopeInfoPtr->usage == ACTION_SIGN || \
		   hasAuthTrailer ) && \
		envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		{
		/* Definite-length data with no trailer, there's nothing left to 
		   process */
		envelopeInfoPtr->deenvState = DEENVSTATE_DONE;
		return( CRYPT_OK );
		}

	/* If there's not enough data left in the stream to do anything, don't 
	   try and go any further */
	REQUIRES( !checkOverflowSub( envelopeInfoPtr->bufPos, 
								 envelopeInfoPtr->dataLeft ) );
	if( envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft < 2 )
		{
		/* If this is a flush and there's an authentication trailer present
		   then a truncation is a signature-check failure not just a 
		   standard underflow.  This is somewhat different to signed data, 
		   for authenticated data the verification step happens in the 
		   trailer so a truncated trailer would produce a (relatively 
		   benign) CRYPT_ERROR_UNDERFLOW while for signed data the trailer
		   doesn't produce a verification result, it comes from the caller
		   checking the CRYPT_ENVINFO_SIGNATURE_RESULT.
		   
		   In theory we could try and apply the same thing for signatures in 
		   order to catch broken code that ignores checking the signature on 
		   signed data, but to do it cleanly requires catching every 
		   possible truncation location below, and if something isn't 
		   checking the signatures on signed data then it can just as easily 
		   ignore a CRYPT_ERROR_INCOMPLETE or similar on truncated 
		   signatures */
		if( isFlush && hasAuthTrailer && state == DEENVSTATE_NONE )
			return( CRYPT_ERROR_SIGNATURE );

		return( checkSoftError( CRYPT_ERROR_UNDERFLOW, isFlush ) ? \
				OK_SPECIAL : CRYPT_ERROR_UNDERFLOW );
		}

	/* Start reading the trailer data from the end of the payload */
	sMemConnect( &stream, envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft );

	/* If we haven't started doing anything yet figure out what we should be
	   looking for */
	if( state == DEENVSTATE_NONE )
		{
		switch( envelopeInfoPtr->usage )
			{
			case ACTION_SIGN:
				status = processSignedTrailer( envelopeInfoPtr, &stream, 
											   &state, isFlush );
				break;

			case ACTION_CRYPT:
				/* If it's conventional encrypted data, just look for EOCs */
				if( !TEST_FLAG( envelopeInfoPtr->flags, 
								ENVELOPE_FLAG_AUTHENC ) )
					{
					state = DEENVSTATE_EOC;
					break;
					}
				/* Fall through for authenticated encrypted data */
				STDC_FALLTHROUGH;

			case ACTION_MAC:
				/* The error handling here gets a bit tricky in that an 
				   attacker could truncate the data and turn a fatal
				   CRYPT_ERROR_SIGNATURE into a more benign 
				   CRYPT_ERROR_UNDERFLOW, which may be ignored by the caller
				   if all of the payload data was successfully recovered.  
				   On the other hand this could be a genuine underflow with
				   the caller still to push in the MAC trailer data, so we
				   can't just unconditionally convert an underflow error 
				   into a CRYPT_ERROR_SIGNATURE.  At best we can convert a
				   CRYPT_ERROR_BADDATA or an underflow (or indeed any kind
				   of error) on an explicit flush into a signature error, 
				   but unfortunately we have to leave the 
				   CRYPT_ERROR_UNDERFLOW on a non-flush because we don't 
				   know whether the caller has more data to push.  Note that 
				   this differs from the failedMAC == TRUE behaviour in that 
				   we return the signature error immediately, since we can't 
				   go any further as we could for a pure MAC failure with 
				   the data-processing state still OK */
				status = processMacTrailer( envelopeInfoPtr, &stream, 
											&failedMAC, isFlush );
				if( cryptStatusError( status ) )
					{
					if( isFlush || status == CRYPT_ERROR_BADDATA )
						status = CRYPT_ERROR_SIGNATURE;
					}
				else
					{
					state = \
						( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
						DEENVSTATE_EOC : DEENVSTATE_DONE;
					}
				break;

			default:
				/* Just look for EOCs */
				state = DEENVSTATE_EOC;
				break;
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			if( status == OK_SPECIAL )
				{
				/* If we got an explicit soft-fail error status, let the 
				   caller know */
				return( status );
				}
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Invalid CMS signed/MACd data trailer" ) );
			}

		/* Remember how far we got.  This could still be position 0 if we're 
		   just looking for EOC's */
		streamPos = stell( &stream );
		ENSURES( isBufsizeRange( streamPos ) );
		}

	/* Keep consuming information until we run out of input or reach the end
	   of the data */
	LOOP_MED( noTrailerItems = 0,
			  state != DEENVSTATE_DONE && noTrailerItems < MAX_DATA_ITEMS,
			  noTrailerItems++ )
		{
		ENSURES( LOOP_INVARIANT_MED( noTrailerItems, 0, MAX_DATA_ITEMS - 1 ) );

		/* Read the certificate chain */
		if( state == DEENVSTATE_CERTSET )
			{
			int certSetLength;

			/* Read the certificate chain into the auxiliary buffer.  We 
			   can't import it yet at this point because we need the 
			   SignerInfo to definitively identify the leaf certificate.  
			   Usually there's only one leaf but there will be more than one 
			   if there are multiple signatures present or if the sending 
			   application decides to shovel in assorted (non-relevant) 
			   certificates */
			status = getStreamObjectLength( &stream, &certSetLength, 
											MIN_CRYPT_OBJECTSIZE );
			if( cryptStatusError( status ) )
				{
				if( checkSoftError( status, isFlush ) )
					{
					status = OK_SPECIAL;
					break;
					}
				if( status == CRYPT_ERROR_OVERFLOW )
					{
					/* This is a recoverable error in the data-handling 
					   state so we have to make it fatal for metadata 
					   handling */
					envelopeInfoPtr->errorState = CRYPT_ERROR_OVERFLOW;
					}
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid CertificateSet signing "
								"certificate chain header", 55 );
				break;
				}

			/* Allocate the buffer for the certificate chain and read it in.
			   We know that the entire chain is present to read because 
			   getStreamObjectLength() guarantees this */
			REQUIRES( envelopeInfoPtr->auxBuffer == NULL );
			REQUIRES( isShortIntegerRangeNZ( certSetLength ) );
			if( ( envelopeInfoPtr->auxBuffer = \
					clAlloc( "processPostamble", certSetLength ) ) == NULL )
				{
				status = CRYPT_ERROR_MEMORY;
				break;
				}
			envelopeInfoPtr->auxBufSize = certSetLength;
			REQUIRES( rangeCheck( envelopeInfoPtr->auxBufSize, \
								  1, MAX_INTLENGTH_SHORT ) );
			status = sread( &stream, envelopeInfoPtr->auxBuffer,
							envelopeInfoPtr->auxBufSize );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			ENSURES( isBufsizeRangeNZ( streamPos ) );
			state = DEENVSTATE_SET_SIG;
			}

		/* Read the start of the SET OF Signature */
		if( state == DEENVSTATE_SET_SIG )
			{
			int setLength, value;

			/* Read the SET tag and length */
			status = readSetI( &stream, &setLength );
			if( cryptStatusError( status ) )
				{
				if( checkSoftError( status, isFlush ) )
					{
					status = OK_SPECIAL;
					break;
					}
				if( status == CRYPT_ERROR_OVERFLOW )
					{
					/* This is a recoverable error in the data-handling 
					   state so we have to make it fatal for metadata 
					   handling */
					envelopeInfoPtr->errorState = CRYPT_ERROR_OVERFLOW;
					}
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid SET OF SignerInfo header", 32 );
				break;
				}
			if( setLength == CRYPT_UNUSED )
				{
				/* An indefinite-length set doesn't tell us how many items 
				   are present so we have to explicitly check for an EOC 
				   following the SET OF, which would indicate an empty set.  
				   checkEOC() leaves the stream untouched if there's no EOC 
				   present so it's safe to use here */
				status = value = checkEOC( &stream );
				if( cryptStatusError( status ) )
					break;
				if( value == TRUE )
					{
					setErrorString( ENVELOPE_ERRINFO, 
									"Invalid SET OF SignerInfo header", 32 );
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				status = CRYPT_OK;
				}
			envelopeInfoPtr->hdrSetLength = setLength;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given then we have to look for the EOC 
			   after each entry read */
			streamPos = stell( &stream );
			ENSURES( isBufsizeRangeNZ( streamPos ) );
			state = DEENVSTATE_SIG;
			}

		/* Read and remember a signature object from a Signature record */
		if( state == DEENVSTATE_SIG )
			{
			int contentItemLength, value;

			/* If it's a standard data push, make sure that there's enough 
			   data left to continue.  Checking at this point means that we 
			   can provide special-case soft-error handling before we try 
			   and read the signature data in addContentListItem() */
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED && \
				sMemDataLeft( &stream ) < envelopeInfoPtr->hdrSetLength && \
				checkSoftError( CRYPT_ERROR_UNDERFLOW, isFlush ) )
				{
				status = OK_SPECIAL;
				break;
				}

			/* If it's an indefinite-length SET OF then we may have reached 
			   the end of the set of items */
			if( envelopeInfoPtr->hdrSetLength == CRYPT_UNUSED )
				{
				status = value = checkEOC( &stream );
				if( cryptStatusError( status ) )
					{
					if( checkSoftError( value, isFlush ) )
						status = OK_SPECIAL;
					break;
					}				
				if( value == TRUE )
					{
					streamPos = stell( &stream );
					ENSURES( isBufsizeRangeNZ( streamPos ) );
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							  DEENVSTATE_EOC : DEENVSTATE_DONE;
					status = CRYPT_OK;
					break;
					}
				}

			/* Add the object to the content information list */
			status = addContentListItem( envelopeInfoPtr, &stream, NULL,
										 &contentItemLength, 
										 QUERYOBJECT_SIGNATURE );
			if( cryptStatusError( status ) )
				{
				if( checkSoftError( status, isFlush ) )
					status = OK_SPECIAL;
				else
					{
					setErrorString( ENVELOPE_ERRINFO, 
									"Invalid SignerInfo signature record", 
									35 );
					}
				break;
				}

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = stell( &stream );
			ENSURES( isBufsizeRangeNZ( streamPos ) );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				if( !rangeCheck( contentItemLength, 1, \
								 envelopeInfoPtr->hdrSetLength ) )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				REQUIRES( !checkOverflowSub( envelopeInfoPtr->hdrSetLength, 
											 contentItemLength ) );
				envelopeInfoPtr->hdrSetLength -= contentItemLength;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					{
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
					}
				}
			}

		/* Handle end-of-contents octets.  Note that this and other EOC 
		   processing don't consume every possible EOC down to the last 
		   byte, there are lots of different combinations possible with
		   mixed definite/indefinite-length encodings, most of which are
		   never used, and as long as we find some EOCs there's no point
		   in accounting for each one */
		if( state == DEENVSTATE_EOC )
			{
			status = processEOCTrailer( envelopeInfoPtr, &stream, isFlush );
			if( cryptStatusError( status ) )
				{
				if( status == OK_SPECIAL )
					{
					/* If we got an explicit soft-fail error status then we 
					   treat it as a standard data push with status == 
					   CRYPT_OK and the byte count indicating how much data 
					   was copied in */
					break;
					}
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid EOC trailer", 19 );
				break;
				}

			/* We're done */
			streamPos = stell( &stream );
			ENSURES( isBufsizeRangeNZ( streamPos ) );
			state = DEENVSTATE_DONE;
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	sMemDisconnect( &stream );
	if( state != DEENVSTATE_DONE && cryptStatusOK( status ) && \
		noTrailerItems >= MAX_DATA_ITEMS )
		{
		/* We can only go once through the loop on a MAC check so we 
		   shouldn't get here with a failed MAC */
		ENSURES( !failedMAC );

		/* Technically this would be an overflow but that's a recoverable
		   error so we make it a BADDATA, which is really what it is */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, ENVELOPE_ERRINFO, 
				  "Encountered more than %d envelope trailer items",
				  noTrailerItems ) );
		}
	envelopeInfoPtr->deenvState = state;
	ENSURES( isBufsizeRange( streamPos ) );

	/* Consume the input that we've processed so far by moving everything 
	   past the current position down to the start of the memory buffer:

									 bufPos
										| bufSize
										v	v
		+-----------+-------+-----------+---+
		|  dataLeft	|		|			|	|
		+-----------+-------+-----------+---+
					|<--+-->|<-- rem -->|
						|
					streamPos */
	REQUIRES( !checkOverflowAdd( envelopeInfoPtr->dataLeft, streamPos ) );
	REQUIRES( !checkOverflowSub( envelopeInfoPtr->bufPos,
								 envelopeInfoPtr->dataLeft + streamPos ) );
	remainder = envelopeInfoPtr->bufPos - \
				( envelopeInfoPtr->dataLeft + streamPos );
	REQUIRES( isBufsizeRange( remainder ) && \
			  envelopeInfoPtr->dataLeft + streamPos + \
					remainder <= envelopeInfoPtr->bufPos );
	if( remainder > 0 && streamPos > 0 )
		{
		REQUIRES( boundsCheck( envelopeInfoPtr->dataLeft + streamPos,
							   remainder, envelopeInfoPtr->bufPos ) );
		memmove( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft + streamPos,
				 remainder );	/* Add checked above */
		}
	REQUIRES( !checkOverflowAdd( envelopeInfoPtr->dataLeft, remainder ) );
	envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + remainder;
	ENSURES( sanityCheckEnvCMSDenv( envelopeInfoPtr ) );
	if( failedMAC )
		{
		/* If the MAC check failed then this overrides any other status */
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, ENVELOPE_ERRINFO, 
				  "MAC value doesn't match calculated MAC" ) );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If we skipped processing any signature actions because we didn't know 
	   what to do with them, make sure that we can actually continue beyond 
	   this point */
	if( state == DEENVSTATE_DONE && \
		envelopeInfoPtr->usage == ACTION_SIGN && \
		TEST_FLAG( envelopeInfoPtr->flags, ENVELOPE_FLAG_ATTRSKIPPED ) )
		{
		status = checkContinueDeenv( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't verify signed data due to absence of "
					  "usable signature information" ) );
			}
		}

	ENSURES( checkActions( envelopeInfoPtr ) );
			 /* sanityCheckEnvCMSDenv() done earlier */

	/* If all went OK but we're still not out of the trailer information, 
	   return an underflow error */
	return( ( state != DEENVSTATE_DONE ) ? CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initCMSDeenveloping( INOUT_PTR ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES_V( TEST_FLAG( envelopeInfoPtr->flags, 
						   ENVELOPE_FLAG_ISDEENVELOPE ) );

	/* Set the access method pointers */
	FNPTR_SET( envelopeInfoPtr->processPreambleFunction, processPreamble );
	FNPTR_SET( envelopeInfoPtr->processPostambleFunction, processPostamble );
	FNPTR_SET( envelopeInfoPtr->checkAlgoFunction, cmsCheckAlgo );

	/* Set up the processing state information */
	envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
	}
#endif /* USE_CMS */
