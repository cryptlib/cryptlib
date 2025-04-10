/****************************************************************************
*																			*
*						Certificate Validity (RTCS) Routines				*
*						Copyright Peter Gutmann 1996-2016					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_CERTVAL

/* Mapping of cryptlib certificate status types to and from RTCS validity 
   codes */

static const MAP_TABLE certStatusToEnumMapTbl[] = {
	{ 0, CRYPT_CERTSTATUS_VALID },
	{ 1, CRYPT_CERTSTATUS_NOTVALID },
	{ 2, CRYPT_CERTSTATUS_NONAUTHORITATIVE },
	{ 3, CRYPT_CERTSTATUS_UNKNOWN },
	{ CRYPT_ERROR, 0 }, 
		{ CRYPT_ERROR, 0 }
	};

static const MAP_TABLE enumToCertStatusMapTbl[] = {
	{ CRYPT_CERTSTATUS_VALID, 0 },
	{ CRYPT_CERTSTATUS_NOTVALID, 1 },
	{ CRYPT_CERTSTATUS_NONAUTHORITATIVE, 2 },
	{ CRYPT_CERTSTATUS_UNKNOWN, 3 },
	{ CRYPT_ERROR, 0 }, 
		{ CRYPT_ERROR, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the validity info */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckValInfo( IN_PTR const VALIDITY_INFO *validityInfo )
	{
	assert( isReadPtr( validityInfo, sizeof( VALIDITY_INFO ) ) );

	if( validityInfo == NULL )
		{
		DEBUG_PUTS(( "sanityCheckValInfo: Missing revocation info" ));
		return( FALSE );
		}

	/* Check validity information */
	if( validityInfo->isValid != TRUE && \
		validityInfo->isValid != FALSE )
		{
		DEBUG_PUTS(( "sanityCheckValInfo: Validity status" ));
		return( FALSE );
		}
	if( !isEnumRange( validityInfo->extStatus, CRYPT_CERTSTATUS ) )
		{
		DEBUG_PUTS(( "sanityCheckValInfo: Extended validity status" ));
		return( FALSE );
		}

	/* Check ID data */
	if( checksumData( validityInfo->data, 
					  KEYID_SIZE ) != validityInfo->dCheck )
		{
		DEBUG_PUTS(( "sanityCheckValInfo: ID" ));
		return( FALSE );
		}

	/* Check safe pointers */
	if( !DATAPTR_ISVALID( validityInfo->attributes ) || \
		!DATAPTR_ISVALID( validityInfo->prev ) || \
		!DATAPTR_ISVALID( validityInfo->next ) )
		{
		DEBUG_PUTS(( "sanityCheckValInfo: Safe pointers" ));
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*					Add/Delete/Check Validity Information					*
*																			*
****************************************************************************/

/* Find an entry in a validity information list */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 2 ) ) \
static const VALIDITY_INFO *findValidityEntry( IN_DATAPTR const DATAPTR listHead,
											   IN_BUFFER( valueLength ) \
													const void *value,
											   IN_LENGTH_FIXED( KEYID_SIZE ) \
													const int valueLength )
	{
	LOOP_INDEX_PTR VALIDITY_INFO *listPtr;
	const int vCheck = checksumData( value, valueLength );

	assert( isReadPtrDynamic( value, valueLength ) );

	REQUIRES_N( valueLength == KEYID_SIZE );

	/* Check whether this entry is present in the list */
	LOOP_LARGE( listPtr = DATAPTR_GET( listHead ),
				listPtr != NULL, 
				listPtr = DATAPTR_GET( listPtr->next ) )
		{
		REQUIRES_N( sanityCheckValInfo( listPtr ) );

		ENSURES_N( LOOP_INVARIANT_LARGE_GENERIC() );

		if( listPtr->dCheck == vCheck && \
			!memcmp( listPtr->data, value, valueLength ) )
			return( listPtr );
		}
	ENSURES_N( LOOP_BOUND_OK );

	return( NULL );
	}

/* Add an entry to a validity information list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int addValidityEntry( INOUT_PTR_DATAPTR DATAPTR *listHeadPtr,
					  OUT_OPT_PTR_COND VALIDITY_INFO **newEntryPosition,
					  IN_BUFFER( valueLength ) const void *value, 
					  IN_LENGTH_FIXED( KEYID_SIZE ) const int valueLength )
	{
	DATAPTR listHead = *listHeadPtr;
	VALIDITY_INFO *listHeadElement = NULL, *newElement;

	assert( isWritePtr( listHeadPtr, sizeof( DATAPTR ) ) );
	assert( newEntryPosition == NULL || \
			isWritePtr( newEntryPosition, sizeof( VALIDITY_INFO * ) ) );
	assert( isReadPtrDynamic( value, valueLength ) );

	REQUIRES( DATAPTR_ISVALID_PTR( listHeadPtr ) );
	REQUIRES( valueLength == KEYID_SIZE );

	/* Clear return value */
	if( newEntryPosition != NULL )
		*newEntryPosition = NULL;

	/* Make sure that this entry isn't already present */
	if( DATAPTR_ISSET( listHead ) )
		{
		if( findValidityEntry( listHead, value, valueLength ) != NULL )
			{
			/* If we found an entry that matches the one being added then 
			   we can't add it again */
			return( CRYPT_ERROR_DUPLICATE );
			}

		/* Remember the first list element so that we can link in the new
		   element */
		listHeadElement = DATAPTR_GET( listHead );
		ENSURES( listHeadElement != NULL );
		}

	/* Allocate memory for the new element and copy the information across */
	REQUIRES( isShortIntegerRangeNZ( sizeof( VALIDITY_INFO ) ) );
	if( ( newElement = ( VALIDITY_INFO * ) \
			clAlloc( "addValidityEntry", sizeof( VALIDITY_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( VALIDITY_INFO ) );
	REQUIRES( rangeCheck( valueLength, 1, KEYID_SIZE ) );
	memcpy( newElement->data, value, valueLength );
	newElement->dCheck = checksumData( value, valueLength );
	DATAPTR_SET( newElement->attributes, NULL );
	DATAPTR_SET( newElement->prev, NULL );
	DATAPTR_SET( newElement->next, NULL );

	/* Set the status to invalid/unknown by default, this means that any 
	   entries that we can't do anything with automatically get the correct 
	   status associated with them */
	newElement->isValid = FALSE;
	newElement->extStatus = CRYPT_CERTSTATUS_UNKNOWN;

	ENSURES( sanityCheckValInfo( newElement ) );

	/* Insert the new element into the list */
	insertDoubleListElement( listHeadPtr, listHeadElement, newElement, 
							 VALIDITY_INFO );
	if( newEntryPosition != NULL )
		*newEntryPosition = newElement;

	return( CRYPT_OK );
	}

/* Delete a validity information list */

STDC_NONNULL_ARG( ( 1 ) ) \
void deleteValidityEntries( INOUT_PTR_DATAPTR DATAPTR *listHeadPtr )
	{
	DATAPTR listHead = *listHeadPtr;
	LOOP_INDEX_PTR VALIDITY_INFO *validityListCursor;

	assert( isWritePtr( listHeadPtr, sizeof( DATAPTR ) ) );

	/* If the list was empty, return now */
	if( DATAPTR_ISNULL( listHead ) )
		return;

	/* Destroy any remaining list items */
	LOOP_LARGE_INITCHECK( validityListCursor = DATAPTR_GET( listHead ),
						  validityListCursor != NULL )
		{
		VALIDITY_INFO *itemToFree = validityListCursor;

		REQUIRES_V( sanityCheckValInfo( itemToFree ) );

		ENSURES_V( LOOP_INVARIANT_LARGE_GENERIC() );

		validityListCursor = DATAPTR_GET( validityListCursor->next );
		if( DATAPTR_ISSET( itemToFree->attributes ) )
			deleteAttributes( &itemToFree->attributes );
		zeroise( itemToFree, sizeof( VALIDITY_INFO ) );
		clFree( "deleteValidityEntries", itemToFree );
		}
	ENSURES_V( LOOP_BOUND_OK );

	DATAPTR_SET_PTR( listHeadPtr, NULL );
	}

/* Copy a validity information list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int copyValidityEntries( INOUT_PTR_DATAPTR DATAPTR *destListHeadPtr,
						 IN_DATAPTR const DATAPTR srcList )
	{
	LOOP_INDEX_PTR const VALIDITY_INFO *srcListCursor;
	VALIDITY_INFO *destListCursor = NULL;

	assert( isWritePtr( destListHeadPtr, sizeof( DATAPTR ) ) );

	REQUIRES( DATAPTR_ISSET( srcList ) );

	/* Copy all validation entries from source to destination */
	LOOP_LARGE( srcListCursor = DATAPTR_GET( srcList ), 
				srcListCursor != NULL,
				srcListCursor = DATAPTR_GET( srcListCursor->next ) )
		{
		VALIDITY_INFO *newElement;

		REQUIRES( sanityCheckValInfo( srcListCursor ) );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		/* Allocate the new entry and copy the data from the existing one
		   across.  We don't copy the attributes because there aren't any
		   that should be carried from request to response */
		REQUIRES( isShortIntegerRangeNZ( sizeof( VALIDITY_INFO ) ) );
		if( ( newElement = ( VALIDITY_INFO * ) \
					clAlloc( "copyValidityEntries", \
							 sizeof( VALIDITY_INFO ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( newElement, srcListCursor, sizeof( VALIDITY_INFO ) );
		DATAPTR_SET( newElement->attributes, NULL );
		DATAPTR_SET( newElement->prev, NULL );
		DATAPTR_SET( newElement->next, NULL );

		/* Set the status to invalid/unknown by default, this means that any
		   entries that we can't do anything with automatically get the
		   correct status associated with them */
		newElement->isValid = FALSE;
		newElement->extStatus = CRYPT_CERTSTATUS_UNKNOWN;

		ENSURES( sanityCheckValInfo( newElement ) );

		/* Link the new element into the list */
		insertDoubleListElement( destListHeadPtr, destListCursor, newElement, 
								 VALIDITY_INFO );
		destListCursor = newElement;
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

/* Prepare the entries in a certificate validity list prior to encoding 
   them */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) \
int prepareValidityEntries( IN_DATAPTR_OPT const DATAPTR listHead, 
							OUT_PTR_PTR_xCOND VALIDITY_INFO **errorEntry,
							OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	LOOP_INDEX_PTR const VALIDITY_INFO *validityEntry;

	assert( isWritePtr( errorEntry, sizeof( VALIDITY_INFO * ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( DATAPTR_ISVALID( listHead ) );

	/* Clear return values */
	*errorEntry = NULL;
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* If the validity list is empty then there's nothing to do */
	if( DATAPTR_ISNULL( listHead ) )
		return( CRYPT_OK );

	/* Check the attributes for each entry in a validation list */
	LOOP_LARGE( validityEntry = DATAPTR_GET( listHead ), 
				validityEntry != NULL, 
				validityEntry = DATAPTR_GET( validityEntry->next ) )
		{
		int status;

		REQUIRES( sanityCheckValInfo( validityEntry ) );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		/* If there's nothing to check, skip this entry */
		if( DATAPTR_ISNULL( validityEntry->attributes ) )
			continue;

		status = checkAttributes( ATTRIBUTE_CERTIFICATE,
								  validityEntry->attributes,
								  errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			/* Remember the entry that caused the problem */
			*errorEntry = ( VALIDITY_INFO * ) validityEntry;
			return( status );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

/* Check the entries in an RTCS response object against a certificate store.  
   The semantics for this one are a bit odd, the source information for the 
   check is from a request but the destination information is in a response.  
   Since we don't have a copy-and-verify function we do the checking from 
   the response even though technically it's the request data that's being 
   checked */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkRTCSResponse( INOUT_PTR CERT_INFO *certInfoPtr,
					   IN_HANDLE const CRYPT_KEYSET iCryptKeyset )
	{
	const CERT_VAL_INFO *valInfo = certInfoPtr->cCertVal;
	LOOP_INDEX_PTR VALIDITY_INFO *validityInfo;
	BOOLEAN isInvalid = FALSE;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );
	REQUIRES( isHandleRangeValid( iCryptKeyset ) );

	/* Walk down the list of validity entries fetching status information
	   on each one from the certificate store */
	LOOP_LARGE( validityInfo = DATAPTR_GET( valInfo->validityInfo ), 
				validityInfo != NULL, 
				validityInfo = DATAPTR_GET( validityInfo->next ) )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		int status;

		REQUIRES( sanityCheckValInfo( validityInfo ) );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		/* Determine the validity of the object.  Since all that we're 
		   interested in is a yes/no answer we tell the keyset to perform a 
		   check only */
		setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID,
							   validityInfo->data, KEYID_SIZE, NULL, 0,
							   KEYMGMT_FLAG_CHECK_ONLY );
		status = krnlSendMessage( iCryptKeyset, IMESSAGE_KEY_GETKEY,
								  &getkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
		if( cryptStatusOK( status ) )
			{
			/* The certificate is present and OK */
			validityInfo->isValid = TRUE;
			validityInfo->extStatus = CRYPT_CERTSTATUS_VALID;
			}
		else
			{
			/* The certificate isn't present/OK, record the fact that we've 
			   seen at least one invalid certificate */
			validityInfo->isValid = FALSE;
			validityInfo->extStatus = CRYPT_CERTSTATUS_NOTVALID;
			isInvalid = TRUE;
			}
		}
	ENSURES( LOOP_BOUND_OK );

	/* If at least one certificate was invalid indicate this to the caller.  
	   Note that if there are multiple certificates present in the query 
	   then it's up to the caller to step through the list to find out which 
	   ones were invalid */
	if( isInvalid )
		{
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
				  "Certificate is present in database of valid "
				  "certificates" ) );
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read RTCS Information						*
*																			*
****************************************************************************/

/* Read RTCS resquest entries:

	Entry ::= SEQUENCE {
		certHash		OCTET STRING SIZE(20),
		legacyID		IssuerAndSerialNumber OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRtcsRequestEntry( INOUT_PTR STREAM *stream, 
								 INOUT_PTR_DATAPTR DATAPTR *listHeadPtr )
	{
	BYTE idBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int endPos, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( listHeadPtr, sizeof( DATAPTR ) ) );

	/* Determine the overall size of the entry */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeNZ( endPos ) );

	/* Read the certificate ID */
	status = readOctetString( stream, idBuffer, &length,
							  KEYID_SIZE, KEYID_SIZE );
	if( cryptStatusOK( status ) && \
		stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		/* Skip the legacy ID */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Add the entry to the validity information list */
	return( addValidityEntry( listHeadPtr, NULL, idBuffer, KEYID_SIZE ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readRTCSRequestEntries( INOUT_PTR STREAM *stream, 
							INOUT_PTR_DATAPTR DATAPTR *listHeadPtr,
							INOUT_PTR ERROR_INFO *errorInfo )
	{
	LOOP_INDEX noRequestEntries;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( listHeadPtr, sizeof( DATAPTR ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the outer wrapper */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the SEQUENCE OF request information */
	LOOP_LARGE( noRequestEntries = 0,
				length > 0 && noRequestEntries < 100, 
				noRequestEntries++ )
		{
		const int innerStartPos = stell( stream );
		int objectSize DUMMY_INIT;

		REQUIRES( isIntegerRangeNZ( innerStartPos ) );

		ENSURES( LOOP_INVARIANT_LARGE( noRequestEntries, 0, 99 ) );

		status = readRtcsRequestEntry( stream, listHeadPtr );
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, innerStartPos, 
												  &objectSize );
			}
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo, 
					  "Invalid RTCS request entry #%d", noRequestEntries ) );
			}
		length -= objectSize;
		}
	ENSURES( LOOP_BOUND_OK );
	if( noRequestEntries >= 100 )
		{
		/* We allow reasonable numbers of entries in a request, but one with 
		   more than a hundred entries has something wrong with it */
		DEBUG_DIAG(( "RTCS request contains more than %d entries", 100 ));
		assert_nofuzz( DEBUG_WARN );
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, errorInfo, 
				  "RTCS request contains more than %d entries", 100 ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Write RTCS Information						*
*																			*
****************************************************************************/

/* Write RTCS resquest entries */

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1 ) ) \
static int sizeofRtcsRequestEntry( STDC_UNUSED const VALIDITY_INFO *rtcsEntry )
	{
	assert( isReadPtr( rtcsEntry, sizeof( VALIDITY_INFO ) ) );

	return( sizeofShortObject( sizeofShortObject( KEYID_SIZE ) ) );
	}

CHECK_RETVAL_LENGTH_SHORT \
int sizeofRtcsRequestEntries( IN_DATAPTR const DATAPTR rtcsEntries )
	{
	LOOP_INDEX_PTR VALIDITY_INFO *validityInfo;
	int requestInfoLength = 0, status;

	REQUIRES( DATAPTR_ISVALID( rtcsEntries ) );

	/* Determine how big the encoded RTCS request will be */
	LOOP_LARGE( validityInfo = DATAPTR_GET( rtcsEntries ), 
				validityInfo != NULL,
				validityInfo = DATAPTR_GET( validityInfo->next ) )
		{
		int requestEntrySize;
		
		REQUIRES( sanityCheckValInfo( validityInfo ) );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		status = requestEntrySize = \
					sizeofRtcsRequestEntry( validityInfo );
		if( cryptStatusError( status ) )
			return( status );
		requestInfoLength += requestEntrySize;
		}
	ENSURES( LOOP_BOUND_OK );

	return( requestInfoLength );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRtcsRequestEntry( INOUT_PTR STREAM *stream, 
								  const VALIDITY_INFO *rtcsEntry )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( rtcsEntry, sizeof( VALIDITY_INFO ) ) );

	/* Write the header and ID information */
	writeSequence( stream, sizeofObject( KEYID_SIZE ) );
	return( writeOctetString( stream, rtcsEntry->data, KEYID_SIZE,
							  DEFAULT_TAG ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeRtcsRequestEntries( INOUT_PTR STREAM *stream, 
							 IN_DATAPTR const DATAPTR rtcsEntries )
	{
	LOOP_INDEX_PTR VALIDITY_INFO *validityInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Write the SEQUENCE OF validity information */
	LOOP_LARGE( validityInfo = DATAPTR_GET( rtcsEntries ), 
				validityInfo != NULL,
				validityInfo = DATAPTR_GET( validityInfo->next ) )
		{
		REQUIRES( sanityCheckValInfo( validityInfo ) );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		status = writeRtcsRequestEntry( stream, validityInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

/* Read RTCS response entries:

	Entry ::= SEQUENCE {				-- Basic response
		certHash		OCTET STRING SIZE(20),
		status			BOOLEAN
		}

	Entry ::= SEQUENCE {				-- Full response
		certHash		OCTET STRING SIZE(20),
		status			ENUMERATED,
		statusInfo		ANY DEFINED BY status OPTIONAL,
		extensions	[0]	Extensions OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5, 6 ) ) \
static int readRtcsResponseEntry( INOUT_PTR STREAM *stream, 
								  INOUT_PTR_DATAPTR DATAPTR *listHeadPtr,
								  IN_BOOL const BOOLEAN isFullResponse,
								  INOUT_PTR ERROR_INFO *errorInfo,
								  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
								  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	VALIDITY_INFO *newEntry;
	BYTE idBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int endPos, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( listHeadPtr, sizeof( DATAPTR ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( isBooleanValue( isFullResponse ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Determine the overall size of the entry */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeNZ( endPos ) );

	/* Read the ID information */
	status = readOctetString( stream, idBuffer, &length, \
							  KEYID_SIZE, KEYID_SIZE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, "Couldn't read ID information" ) );
		}

	/* Add the entry to the validity information list */
	status = addValidityEntry( listHeadPtr, &newEntry, idBuffer, 
							   KEYID_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the status information and record the valid/not-valid status  */
	if( isFullResponse )
		{
		int value;

		status = readEnumerated( stream, &value );
		if( cryptStatusOK( status ) && \
			( value < CRYPT_CERTSTATUS_NONE || \
			  value > CRYPT_CERTSTATUS_LAST + 10 ) )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status ) )
			{
			status = mapValue( value, &value, certStatusToEnumMapTbl, 
							   FAILSAFE_ARRAYSIZE( certStatusToEnumMapTbl, 
												   MAP_TABLE ) );
			}
		if( cryptStatusOK( status ) )
			{
			newEntry->extStatus = value;
			newEntry->isValid = \
						( newEntry->extStatus == CRYPT_CERTSTATUS_VALID ) ? \
						TRUE : FALSE;
			}
		}
	else
		{
		status = readBoolean( stream, &newEntry->isValid );
		if( cryptStatusOK( status ) )
			{
			newEntry->extStatus = ( newEntry->isValid == TRUE ) ? \
						CRYPT_CERTSTATUS_VALID : CRYPT_CERTSTATUS_NOTVALID;
			}
		}
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read RTCS status information" ) );
		}

	/* If there are no extensions present, we're done */
	if( stell( stream ) > endPos - MIN_ATTRIBUTE_SIZE )
		return( CRYPT_OK );

	/* Read the extensions.  Since these are per-entry extensions we read
	   the wrapper here and read the extensions themselves as
	   CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_RTCS to make sure
	   that they're processed as required */
	status = readConstructed( stream, &length, 0 );
	if( cryptStatusOK( status ) && length > 0 )
		{
		status = readAttributes( stream, &newEntry->attributes,
								 CRYPT_CERTTYPE_NONE, length, errorInfo,
								 errorLocus, errorType );
		}
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 5 ) ) \
int readRTCSResponseEntries( INOUT_PTR STREAM *stream, 
							 INOUT_PTR_DATAPTR DATAPTR *listHeadPtr,
							 INOUT_PTR ERROR_INFO *errorInfo,
							 OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	LOOP_INDEX noResponseEntries;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( listHeadPtr, sizeof( DATAPTR ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Read the SEQUENCE OF response information */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
#if 0	/* 11/9/17 See below */
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeNZ( endPos ) );
#endif /* 0 */
	LOOP_LARGE( noResponseEntries = 0,
				length > 0 && noResponseEntries < 100,
				noResponseEntries++ )
		{
		ERROR_INFO localErrorInfo;
		const int innerStartPos = stell( stream );
		int objectSize DUMMY_INIT;

		REQUIRES( isIntegerRangeNZ( innerStartPos ) );

		ENSURES( LOOP_INVARIANT_LARGE( noResponseEntries, 0, 99 ) );

		clearErrorInfo( &localErrorInfo );
		status = readRtcsResponseEntry( stream, listHeadPtr, FALSE,
										&localErrorInfo, errorLocus, 
										errorType );
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, innerStartPos, 
												  &objectSize );
			}
		if( cryptStatusError( status ) )
			{
			retExtErr( status,
					   ( status, errorInfo, &localErrorInfo,
						 "Invalid RTCS response entry #%d", 
						 noResponseEntries ) );
			}
		length -= objectSize;
		}
	ENSURES( LOOP_BOUND_OK );
	if( noResponseEntries >= 100 )
		{
		/* We allow reasonable numbers of entries in a response, but one with 
		   more than a hundred entries has something wrong with it */
		DEBUG_DIAG(( "RTCS response contains more than %d entries", 100 ));
		assert_nofuzz( DEBUG_WARN );
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, errorInfo, 
				  "RTCS response contains more than %d entries", 
				  100 ) );
		}

#if 0	/* 11/9/17 Since we always send basic requests/responses, there are 
				   no attributes to read */
	/* Read the extensions if there are any present */
	if( stell( stream ) < endPos )
		{
		status = readAttributes( stream, &certInfoPtr->attributes,
								 CRYPT_CERTTYPE_RTCS_RESPONSE, 
								 endPos - stell( stream ), errorInfo, 
								 &certInfoPtr->errorLocus, 
								 &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* 0 */

	return( CRYPT_OK );
	}

/* Write RTCS response entries */

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1 ) ) \
static int sizeofRtcsResponseEntry( INOUT_PTR VALIDITY_INFO *rtcsEntry,
									IN_BOOL const BOOLEAN isFullResponse )
	{
	int status;

	assert( isWritePtr( rtcsEntry, sizeof( VALIDITY_INFO ) ) );

	REQUIRES( isBooleanValue( isFullResponse ) );

	/* If it's a basic response then the size is fairly easy to calculate */
	if( !isFullResponse )
		{
		return( sizeofShortObject( sizeofShortObject( KEYID_SIZE ) + \
								   sizeofBoolean() ) );
		}

	/* Remember the encoded attribute size for later when we write the
	   attributes */
	status = rtcsEntry->attributeSize = \
					sizeofAttributes( rtcsEntry->attributes,
									  CRYPT_CERTTYPE_NONE );
	if( cryptStatusError( status ) )
		return( status );

	return( sizeofShortObject( sizeofShortObject( KEYID_SIZE ) + \
							   sizeofEnumerated( 1 ) + \
							   ( ( rtcsEntry->attributeSize ) ? \
								 sizeofShortObject( rtcsEntry->attributeSize ) : 0 ) ) );
	}

CHECK_RETVAL_LENGTH_SHORT \
int sizeofRtcsResponseEntries( IN_DATAPTR const DATAPTR rtcsEntries,
							   IN_BOOL const BOOLEAN isExtendedResponse )
	{
	LOOP_INDEX_PTR VALIDITY_INFO *validityInfo;
	int responseInfoLength = 0, status;

	REQUIRES( DATAPTR_ISVALID( rtcsEntries ) );

	REQUIRES( isBooleanValue( isExtendedResponse ) );

	/* Determine how big the encoded RTCS responses will be */
	LOOP_LARGE( validityInfo = DATAPTR_GET( rtcsEntries ), 
				validityInfo != NULL,
				validityInfo = DATAPTR_GET( validityInfo->next ) )
		{
		int responseEntrySize;
		
		REQUIRES( sanityCheckValInfo( validityInfo ) );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		status = responseEntrySize = \
						sizeofRtcsResponseEntry( validityInfo, 
												 isExtendedResponse );
		if( cryptStatusError( status ) )
			return( status );
		responseInfoLength += responseEntrySize;
		}
	ENSURES( LOOP_BOUND_OK );

	return( responseInfoLength );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRtcsResponseEntry( INOUT_PTR STREAM *stream, 
								   IN_PTR const VALIDITY_INFO *rtcsEntry,
								   IN_BOOL const BOOLEAN isExtendedResponse )
	{
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( rtcsEntry, sizeof( VALIDITY_INFO ) ) );
	
	REQUIRES( isBooleanValue( isExtendedResponse ) );

	/* If it's a basic response then it's a straightforward fixed-length
	   object */
	if( !isExtendedResponse )
		{
		writeSequence( stream, sizeofObject( KEYID_SIZE ) +
							   sizeofBoolean() );
		writeOctetString( stream, rtcsEntry->data, KEYID_SIZE, DEFAULT_TAG );
		return( writeBoolean( stream, rtcsEntry->isValid, DEFAULT_TAG ) );
		}

	/* Write an extended response */
	status = mapValue( rtcsEntry->extStatus, &value, enumToCertStatusMapTbl, 
					   FAILSAFE_ARRAYSIZE( enumToCertStatusMapTbl, 
										   MAP_TABLE ) );
	ENSURES( cryptStatusOK( status ) );
	writeSequence( stream, sizeofObject( KEYID_SIZE ) + sizeofEnumerated( 1 ) );
	writeOctetString( stream, rtcsEntry->data, KEYID_SIZE, DEFAULT_TAG );
	status = writeEnumerated( stream, value, DEFAULT_TAG );
	if( cryptStatusError( status ) || rtcsEntry->attributeSize <= 0 )
		return( status );

	/* Write the per-entry extensions.  Since these are per-entry extensions
	   we write them as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_RTCS
	   to make sure that they're processed as required */
	return( writeAttributes( stream, rtcsEntry->attributes,
							 CRYPT_CERTTYPE_NONE, rtcsEntry->attributeSize ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeRtcsResponseEntries( INOUT_PTR STREAM *stream, 
							  IN_DATAPTR const DATAPTR rtcsEntries,
							  IN_BOOL const BOOLEAN isExtendedResponse )
	{
	LOOP_INDEX_PTR VALIDITY_INFO *validityInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isBooleanValue( isExtendedResponse ) );

	/* Write the SEQUENCE OF validity information */
	LOOP_LARGE( validityInfo = DATAPTR_GET( rtcsEntries ), 
				validityInfo != NULL,
				validityInfo = DATAPTR_GET( validityInfo->next ) )
		{
		REQUIRES( sanityCheckValInfo( validityInfo ) );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		status = writeRtcsResponseEntry( stream, validityInfo, 
										 isExtendedResponse );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}
#endif /* USE_CERTVAL */
