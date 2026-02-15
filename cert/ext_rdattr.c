/****************************************************************************
*																			*
*					Certificate Attribute Data Read Routines				*
*						Copyright Peter Gutmann 1996-2020					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

/* Define the following to print a trace of the certificate fields being 
   parsed, useful for debugging broken certificates */

#if !defined( NDEBUG ) && 0
  #if defined( _MSC_VER )
	/* Disable the 'conditional expression is constant warning' that occurs 
	   because 'stackPos' may be hardcoded to 0 in the TRACE_FIELDTYPE()
	   macro below */
	#pragma warning( disable: 4127 )
  #endif /* VC++ */
  #define getDescription( attributeInfoPtr ) \
		  ( ( attributeInfoPtr ) != NULL && \
		    ( attributeInfoPtr )->description != NULL ) ? \
			( attributeInfoPtr )->description : "(unknown blob attribute)"
  #define TRACE_FIELDTYPE( attributeInfoPtr, stackPos ) \
		  { \
		  int i; \
		  \
		  DEBUG_PRINT(( "%4d:", stell( stream ) )); \
		  for( i = 0; i < stackPos; i++ ) \
			  DEBUG_PRINT(( "  " )); \
		  DEBUG_PUTS(( getDescription( attributeInfoPtr ) )); \
		  }
  #define TRACE_DEBUG	DEBUG_PRINT
#else
  #define TRACE_FIELDTYPE( attributeInfoPtr, stackPos )
  #define TRACE_DEBUG( x )
#endif /* NDEBUG */

#ifdef USE_CERTIFICATES

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the tag for a field from the attribute field definition.  This 
   function and the readExplicitTag() that follow are only called once from 
   readAttribute() but are used to try and make that function less complex 
   than it already is */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int getFieldTag( INOUT_PTR STREAM *stream, 
						IN_PTR const ATTRIBUTE_INFO *attributeInfoPtr,
						OUT_TAG_Z int *tag )
	{
	int status, value;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( tag, sizeof( int ) ) );

	/* Clear return value.  This is actually a bit difficult to do because 
	   the output can have both positive values (tags) and small negative 
	   values (field codes), setting the output to -1000 is invalid for 
	   both types */
	*tag = -1000;

	/* Check whether the field is tagged */
	status = getFieldEncodedTag( attributeInfoPtr, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value != CRYPT_UNUSED )
		{
		/* It's a tagged field, return the encoded form */
		*tag = value;

		return( CRYPT_OK );
		}

	/* It's a non-tagged field, the tag is the same as the field type */
	value = attributeInfoPtr->fieldType;
	if( value == FIELDTYPE_TEXTSTRING )
		{
		static const MAP_TABLE mapTbl[] = {
			{ BER_STRING_BMP, 0 },
			{ BER_STRING_IA5, 0 },
			{ BER_STRING_ISO646, 0 },
			{ BER_STRING_PRINTABLE, 0 },
			{ BER_STRING_T61, 0 },
			{ BER_STRING_UTF8, 0 },
			{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
			};
		int dummy;

		/* This is a variable-tag field that can have one of a number of 
		   tags.  To handle this we peek ahead into the stream to see if an 
		   acceptable tag is present and if not set the value to a non-
		   matching tag value.  To perform the check we use a map table and 
		   ignore the mapped-to value */
		status = value = peekTag( stream );
		if( cryptStatusError( status ) )
			return( status );
		status = mapValue( value, &dummy, mapTbl, 
						   FAILSAFE_ARRAYSIZE( mapTbl, MAP_TABLE ) );
		if( cryptStatusError( status ) )
			{
			/* There was no match for any of the allowed types, change the 
			   tag value from what we've read from the stream to make sure 
			   that it results in a non-match when the caller uses it */
			value = BER_ID_RESERVED;
			}
		}
	if( value == FIELDTYPE_BLOB_BITSTRING || \
		value == FIELDTYPE_BLOB_SEQUENCE )
		{
		/* This is a typed blob that's read as a blob but still has a type
		   for type-checking purposes */
		value = ( value == FIELDTYPE_BLOB_BITSTRING ) ? \
				BER_BITSTRING : BER_SEQUENCE;
		}

	ENSURES( ( value == FIELDTYPE_ALGOID ) || \
			 ( ( value == FIELDTYPE_BLOB_ANY || value == FIELDTYPE_DN ) && \
			   !( attributeInfoPtr->encodingFlags & FL_OPTIONAL ) ) || \
			 ( value >= BER_ID_RESERVED && value <= MAX_TAG ) );
			 /* A FIELDTYPE_BLOB_ANY or FIELDTYPE_DN can't be optional 
			    fields because with no type information for them available 
				there's no way to check whether we've encountered them or 
				not, this has been verified during the startup check.  
				BER_ID_RESERVED is used to indicate that an invalid tag was 
				read so it's valid at this point */
	*tag = value;

	return( CRYPT_OK );
	}

/* Read an explicit tag that wraps the actual item that we're after */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readExplicitTag( INOUT_PTR STREAM *stream, 
							IN_PTR const ATTRIBUTE_INFO *attributeInfoPtr, 
							OUT_TAG_Z int *tag )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( tag, sizeof( int ) ) );

	REQUIRES( attributeInfoPtr->encodingFlags & FL_EXPLICIT );
	REQUIRES( attributeInfoPtr->fieldEncodedType >= 0 && \
			  attributeInfoPtr->fieldEncodedType < MAX_TAG );

	/* Clear return value */
	*tag = 0;

	/* Read the explicit wrapper */
	status = readConstructed( stream, NULL, 
							  attributeInfoPtr->fieldEncodedType );
	if( cryptStatusError( status ) )
		return( status );

	/* We've processed the explicit wrappper, we're now on the actual tag */
	*tag = attributeInfoPtr->fieldType;

	return( CRYPT_OK );
	}

/* Find the end of an item (either primitive or constructed) in the attribute
   table.  This is used by both the identified-item routines and by the 
   SET/SEQUENCE routines so it's made non-static.
   
   Sometimes we may have already entered a constructed object (for example 
   when an attribute has a version number so we don't know until we've 
   started processing it that we can't do anything with it), if this is the
   case then the depth parameter indicates how many nesting levels we have 
   to undo so we initialise the start-depth to this value rather than zero */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int findItemEnd( IN_PTR_PTR const ATTRIBUTE_INFO **attributeInfoPtrPtr,
				 IN_RANGE( 0, 2 ) const int depth )
	{
	LOOP_INDEX_PTR const ATTRIBUTE_INFO *attributeInfoPtr;
	int currentDepth = depth;

	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( depth >= 0 && depth <= 2 );

	/* Skip to the end of the (potentially) constructed item by recording the
	   nesting level and continuing until either it reaches zero or we reach
	   the end of the item */
	LOOP_MED( attributeInfoPtr = *attributeInfoPtrPtr, 
			  !( attributeInfoPtr->typeInfoFlags & FL_ATTR_ATTREND ),
			  attributeInfoPtr++ )
		{
		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* If it's a SEQUENCE/SET, increment the depth; if it's an end-of-
		   constructed-item marker, decrement it by the appropriate amount 
		   (decodeNestingLevel() is only nonzero at the end of a constructed
		   item) */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
			attributeInfoPtr->fieldType == BER_SET )
			currentDepth++;
		else
			{
			currentDepth -= \
					decodeNestingLevel( attributeInfoPtr->encodingFlags );
			}
		if( currentDepth <= 0 )
			break;
		}
	ENSURES( LOOP_BOUND_OK );

	/* We return the next-to-last entry by stopping when we find the 
	   FL_ATTR_ATTREND flag since we're going to move on to the next entry 
	   once we return */
	*attributeInfoPtrPtr = attributeInfoPtr;

	return( CRYPT_OK );
	}

/* Add a default value for an attribute field */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5, 6 ) ) \
static int addDefaultValue( INOUT_PTR DATAPTR_ATTRIBUTE *attributePtrPtr,
							IN_PTR const ATTRIBUTE_INFO *attributeInfoPtr, 
							IN_FLAGS( ATTR ) const int flags, 
							INOUT_PTR ERROR_INFO *errorInfo,
							OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	CRYPT_ATTRIBUTE_TYPE dummy1;
	CRYPT_ERRTYPE_TYPE dummy2;
	int status;

	assert( isWritePtr( attributePtrPtr, sizeof( DATAPTR_ATTRIBUTE ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( isFlagRangeZ( flags, ATTR ) );

	/* Add the default value for this attribute field.  The error message if
	   this fails will be a bit misleading since we're not actually reading
	   the default data that we're adding, but then again this should be a
	   can-never-occur condition since we're adding known-valid data */
	status = addAttributeField( attributePtrPtr, attributeInfoPtr->fieldID, 
								CRYPT_ATTRIBUTE_NONE, 
								attributeInfoPtr->parameter, flags, TRUE,
								errorInfo, &dummy1, &dummy2 );
	if( cryptStatusError( status ) )
		{
		return( readAttributeErrorReturn( errorLocus, errorType, errorInfo, 
										  attributeInfoPtr, 0, 
										  "default data", status ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Identified Item Management Routines					*
*																			*
****************************************************************************/

/* Given a pointer to a set of SEQUENCE { type, value } entries, return a
   pointer to the { value } entry appropriate for the data in the stream.  
   If the entry contains user data in the { value } portion then the 
   returned pointer points to this, if it contains a fixed value or isn't 
   present at all then the returned pointer points to the { type } portion */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int findIdentifiedItem( INOUT_PTR STREAM *stream,
							   OUT_PTR_PTR \
									const ATTRIBUTE_INFO **attributeInfoPtrPtr,
							   IN_PTR const ATTRIBUTE_INFO *attributeInfoPtr )
	{
	BYTE oid[ MAX_OID_SIZE + 8 ];
	int oidLength, sequenceLength, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( attributeInfoPtr->encodingFlags & FL_IDENTIFIER );

	/* Clear return value */
	*attributeInfoPtrPtr = NULL;

	/* Skip the header and read the OID */
	readSequence( stream, &sequenceLength );
	status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
							 BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	sequenceLength -= oidLength;
	if( !isShortIntegerRange( sequenceLength ) )
		return( CRYPT_ERROR_BADDATA );

	/* Walk down the list of entries trying to match the read OID to an 
	   allowed value.  Unfortunately we can't use the attributeInfoSize 
	   bounds check limit here because we don't know how far through the 
	   attribute table we already are, so we have to use a generic large 
	   value */
	LOOP_LARGE_WHILE( attributeInfoPtr->encodingFlags & FL_IDENTIFIER )
		{
		const BYTE *oidPtr;

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		/* Skip the SEQUENCE and OID.  The fact that an OID follows the
		   entry with the FL_IDENTIFIER field in the encoding table unless 
		   it's the final catch-all blob entry has been verified during the 
		   startup check */
		attributeInfoPtr++;
		oidPtr = attributeInfoPtr->oid;

		/* If this is a non-encoded blob field then we've hit a don't-care 
		   value (usually the last in a series of type-and-value pairs) 
		   which ensures that additional types added after the encoding 
		   table was defined don't get processed as errors.  In that case 
		   we skip the field and continue */
		if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB_ANY && \
			( attributeInfoPtr->encodingFlags & FL_NONENCODING ) )
			{
			/* If there's a value attached to the type, skip it */
			if( sequenceLength > 0 )
				{
				status = sSkip( stream, sequenceLength, 
								MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return( status );
				}

			*attributeInfoPtrPtr = attributeInfoPtr;
			return( CRYPT_OK );
			}
		ENSURES( oidPtr != NULL );

		/* Skip to the payload data unless this is a field like a version 
		   number which isn't used to encode user-supplied information */
		if( !( attributeInfoPtr->encodingFlags & FL_NONENCODING ) )
			attributeInfoPtr++;

		/* If the OID matches, return a pointer to the value entry */
		if( matchOID( oid, oidLength, oidPtr ) )
			{
			/* If this is a fixed field and there's a value attached, skip
			   it */
			if( ( attributeInfoPtr->encodingFlags & FL_NONENCODING ) && \
				sequenceLength > 0 )
				{
				status = sSkip( stream, sequenceLength, 
								MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return( status );
				}

			*attributeInfoPtrPtr = attributeInfoPtr;
			return( CRYPT_OK );
			}

		/* The OID doesn't match, skip the value entry and continue.  We set 
		   the current nesting depth parameter to 1 since we've already 
		   entered the SEQUENCE above */
		status = findItemEnd( &attributeInfoPtr, 1 );
		if( cryptStatusError( status ) )
			return( status );
		attributeInfoPtr++;		/* Move to start of next item */
		}
	ENSURES( LOOP_BOUND_OK );

	/* We've reached the end of the set of entries without matching the OID 
	   (including a possible catch-all value at the end), this is an error */
	return( CRYPT_ERROR_BADDATA );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5, 6, 7, 8 ) ) \
static int processIdentifiedItem( INOUT_PTR STREAM *stream, 
								  INOUT_PTR DATAPTR_ATTRIBUTE *attributePtrPtr,
								  IN_FLAGS( ATTR ) const int flags, 
								  IN_PTR const SETOF_STACK *setofStack,
								  IN_PTR \
									const ATTRIBUTE_INFO **attributeInfoPtrPtr,
								  INOUT_PTR ERROR_INFO *errorInfo,
								  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
								  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	const SETOF_STATE_INFO *setofInfoPtr;
	const ATTRIBUTE_INFO *attributeInfoPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributePtrPtr, sizeof( DATAPTR_ATTRIBUTE ) ) );
	assert( isReadPtr( setofStack, sizeof( SETOF_STACK ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

assert( ( flags & ~( ATTR_FLAG_CRITICAL ) ) == 0 );
	REQUIRES( isFlagRangeZ( flags, ATTR ) );

	setofInfoPtr = setofTOS( setofStack );
	ENSURES( setofInfoPtr != NULL );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Search for the identified item from the start of the set of items.  
	   The 0-th value is the SET OF/SEQUENCE OF so we start the search at 
	   the next entry, which is the first FL_IDENTIFIER */
	attributeInfoPtr = setofGetAttributeInfo( setofInfoPtr );
	ENSURES( attributeInfoPtr != NULL && \
			 ( attributeInfoPtr->encodingFlags & FL_SETOF ) );
	status = findIdentifiedItem( stream, &attributeInfoPtr, 
								 attributeInfoPtr + 1 );
	if( cryptStatusError( status ) )
		{
		return( readAttributeErrorReturn( errorLocus, errorType, errorInfo, 
									attributeInfoPtr, 0, 
									"type-and-value pair", status ) );
		}
	*attributeInfoPtrPtr = attributeInfoPtr;

	/* If it's a subtyped field, tell the caller to restart the decoding
	   using the new attribute information.  This is typically used where
	   the { type, value } combinations that we're processing are
	   { OID, GeneralName } so the process consists of locating the entry 
	   that corresponds to the OID and then continuing the decoding with
	   the subtyped attribute information entry that points to the 
	   GeneralName decoding table */
	if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED )
		return( OK_SPECIAL );

	/* If it's not a special-case, non-encoding field, we're done */
	if( !( attributeInfoPtr->encodingFlags & FL_NONENCODING ) )
		return( CRYPT_OK );

	/* If the { type, value } pair has a fixed value then the information 
	   being conveyed is its presence and not its contents so we add an 
	   attribute corresponding to its ID and continue.  The addition of the 
	   attribute is a bit tricky, some of the fixed type-and-value pairs can 
	   have multiple entries denoting things like { algorithm, weak key }, 
	   { algorithm, average key }, { algorithm, strong key }, however all 
	   that we're interested in is the strong key so we ignore the value and 
	   only use the type (in his ordo est ordinem non servare).  Since the 
	   same type can be present multiple times with different values we 
	   ignore data duplicate errors and continue.  If we're processing a 
	   blob field type then we've ended up at a generic catch-any value and 
	   can't do much with it */
	if( attributeInfoPtr->fieldType != FIELDTYPE_BLOB_ANY )
		{
		/* Add the field type, discarding warnings about duplicates */
		TRACE_FIELDTYPE( attributeInfoPtr, 0 );
		status = addAttributeField( attributePtrPtr, 
									attributeInfoPtr->fieldID, 
									CRYPT_ATTRIBUTE_NONE, CRYPT_UNUSED, 
									flags, TRUE, errorInfo, errorLocus, 
									errorType );
		if( cryptStatusError( status ) && status != CRYPT_ERROR_INITED )
			return( CRYPT_ERROR_BADDATA );
		}

	/* Reset the attribute information position in preparation for 
	   processing the next value and tell the caller to continue using the 
	   reset attribute information */
	attributeInfoPtr = setofGetAttributeInfo( setofInfoPtr );
	ENSURES( attributeInfoPtr != NULL );
	*attributeInfoPtrPtr = attributeInfoPtr + 1;
	return( OK_SPECIAL );
	}

/* Read a sequence of identifier fields of the form { oid, value OPTIONAL }.
   This is used to read both SEQUENCE OF (via FIELDTYPE_IDENTIFIER) and 
   CHOICE (via FIELDTYPE_CHOICE), with SEQUENCE OF allowing multiple entries 
   and CHOICE allowing only a single entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6, 7, 8 ) ) \
static int readIdentifierFields( INOUT_PTR STREAM *stream, 
								 INOUT_PTR DATAPTR_ATTRIBUTE *attributePtrPtr,
								 IN_PTR_PTR \
									const ATTRIBUTE_INFO **attributeInfoPtrPtr, 
								 IN_FLAGS( ATTR ) const int flags,
								 IN_ATTRIBUTE_OPT \
									const CRYPT_ATTRIBUTE_TYPE fieldID, 
								 INOUT_PTR ERROR_INFO *errorInfo,
								 OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
								 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr;
	const BOOLEAN isChoice = ( fieldID != CRYPT_ATTRIBUTE_NONE ) ? \
							 TRUE : FALSE;
	LOOP_INDEX noIdentifierFields;
	int count = 0, tag, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributePtrPtr, sizeof( DATAPTR_ATTRIBUTE ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

assert( ( flags == ATTR_FLAG_NONE ) || ( flags == ATTR_FLAG_CRITICAL ) );
	REQUIRES( isFlagRangeZ( flags, ATTR ) );
	REQUIRES( ( fieldID == CRYPT_ATTRIBUTE_NONE ) || \
			  isValidExtension( fieldID ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	LOOP_MED( noIdentifierFields = 0,
			  checkStatusPeekTag( stream, status, tag ) && \
				tag == BER_OBJECT_IDENTIFIER && noIdentifierFields < 32,
			  noIdentifierFields++ )
		{
		BYTE oid[ MAX_OID_SIZE + 8 ];
		BOOLEAN addField = TRUE;
		int oidLength, LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_MED( noIdentifierFields, 0, 31 ) );

		/* The fact that the FIELDTYPE_IDENTIFIER field is present and 
		   associated with an OID in the encoding table has been verified 
		   during the startup check */
		attributeInfoPtr = *attributeInfoPtrPtr;
		ENSURES( attributeInfoPtr != NULL && \
				 attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER && \
				 attributeInfoPtr->oid != NULL );

		/* Read the OID and walk down the list of possible OIDs up to the end
		   of the group of alternatives trying to match it to an allowed
		   value */
		status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			{
			return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 0, "OID", 
									status ) );
			}
		LOOP_MED_WHILE_ALT( !matchOID( oid, oidLength, attributeInfoPtr->oid ) )
			{
			ENSURES( LOOP_INVARIANT_MED_ALT_GENERIC() );

			/* If we've reached the end of the list and the OID wasn't
			   matched, exit.  We can't use readAttributeErrorReturn() at 
			   this point because we've reached the end of the set of 
			   identified items */
			if( ( attributeInfoPtr->encodingFlags & FL_SEQEND_MASK ) || \
				( attributeInfoPtr->typeInfoFlags & FL_ATTR_ATTREND ) )
				return( CRYPT_ERROR_BADDATA );

			attributeInfoPtr++;

			/* If this is a blob field then we've hit a don't-care value 
			   which ensures that additional types added after the encoding 
			   table was defined don't get processed as errors.  In this 
			   case we skip the field and continue */
			if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB_ANY )
				{
				addField = FALSE;
				break;
				}

			/* The fact that the FIELDTYPE_IDENTIFIER field is present and 
			   associated with an OID in the encoding table has been verified 
			   during the startup check */
			ENSURES( attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER && \
					 attributeInfoPtr->oid != NULL );
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		TRACE_FIELDTYPE( attributeInfoPtr, 0 );
		if( addField == TRUE )
			{
			/* The OID matches, add this field as an identifier field.  This
			   will catch duplicate OIDs since we can't add the same 
			   identifier field twice */
			if( isChoice == TRUE )
				{
				/* If there's a field value present then this is a CHOICE of
				   attributes whose value is the field value so we add it with
				   this value */
				status = addAttributeField( attributePtrPtr, fieldID, 
											CRYPT_ATTRIBUTE_NONE,
											attributeInfoPtr->fieldID,  
											flags, TRUE, errorInfo, 
											errorLocus, errorType );
				}
			else
				{
				/* It's a standard field */
				status = addAttributeField( attributePtrPtr, 
											attributeInfoPtr->fieldID, 
											CRYPT_ATTRIBUTE_NONE, 
											CRYPT_UNUSED, flags, TRUE, 
											errorInfo, errorLocus, errorType );
				}
			if( cryptStatusError( status ) )
				return( status );
			}
		count++;

		/* If there's more than one OID present in a CHOICE, it's an error */
		if( isChoice == TRUE && count > 1 )
			{
			return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 0, 
									"duplicate data", 
									CRYPT_ERROR_BADDATA ) );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( noIdentifierFields >= 32 )
		{
		/* If we've found this many identifier fields then there's something 
		   wrong */
		return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, *attributeInfoPtrPtr, 0, 
									"excessive identifier fields", 
									CRYPT_ERROR_BADDATA ) );
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* If we haven't seen any fields, this is an error */
	if( count <= 0 )
		{
		return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, *attributeInfoPtrPtr, 0, 
									"missing identifier fields", 
									CRYPT_ERROR_BADDATA ) );
		}

	/* We've processed the non-data field(s), move on to the next field.
	   We move to the last valid non-data field rather than the start of the
	   field following it since the caller needs to be able to check whether
	   there are more fields to follow using the current field's flags.
	   Unfortunately we can't use the attributeInfoSize bounds check limit 
	   here because we don't know how far through the attribute table we 
	   already are, so we have to use a generic value */
	LOOP_MED( attributeInfoPtr = *attributeInfoPtrPtr, 
			  !( attributeInfoPtr->encodingFlags & FL_SEQEND_MASK ) && \
					!( attributeInfoPtr->typeInfoFlags & FL_ATTR_ATTREND ),
			  attributeInfoPtr++ )
		{
		ENSURES( LOOP_INVARIANT_MED_GENERIC() );
		}
	ENSURES( LOOP_BOUND_OK );
	*attributeInfoPtrPtr = attributeInfoPtr;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Attribute Field Read Routines					*
*																			*
****************************************************************************/

/* Read the contents of an attribute field.  This uses the readXXXData() 
   variants of the read functions because the field that we're reading may 
   be tagged so we process the tag at a higher level and only read the 
   contents here */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6, 7, 8 ) ) \
static int readAttributeField( INOUT_PTR STREAM *stream, 
							   INOUT_PTR DATAPTR_ATTRIBUTE *attributePtrPtr,
							   IN_PTR const ATTRIBUTE_INFO *attributeInfoPtr,
							   IN_ATTRIBUTE_OPT \
									const CRYPT_ATTRIBUTE_TYPE subtypeParent, 
							   IN_FLAGS( ATTR ) const int flags, 
							   INOUT_PTR ERROR_INFO *errorInfo,
							   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
							   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	CRYPT_ATTRIBUTE_TYPE fieldID, subFieldID;
	DATAPTR_DN dn;
	BYTE buffer[ 512 + 8 ];
	const void *dataPtr = NULL;
	time_t timeVal;
	int dataLength = 0, dataFlags = ATTR_FLAG_NONE;
	int value DUMMY_INIT, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributePtrPtr, sizeof( DATAPTR_ATTRIBUTE ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( ( subtypeParent == CRYPT_ATTRIBUTE_NONE ) || \
			  ( subtypeParent > CRYPT_CERTINFO_FIRST && \
				subtypeParent < CRYPT_CERTINFO_LAST ) );
assert( ( flags & ~( ATTR_FLAG_NONE | ATTR_FLAG_CRITICAL | \
					 ATTR_FLAG_MULTIVALUED ) ) == 0 );
	REQUIRES( isFlagRangeZ( flags, ATTR ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Set up the field identifiers depending on whether it's a normal field
	   or a subfield of a parent field */
	if( subtypeParent == CRYPT_ATTRIBUTE_NONE )
		{
		fieldID = attributeInfoPtr->fieldID;
		subFieldID = CRYPT_ATTRIBUTE_NONE;
		}
	else
		{
		fieldID = subtypeParent;
		subFieldID = attributeInfoPtr->fieldID;
		}

	/* Read the field as appropriate */
	switch( attributeInfoPtr->fieldType )
		{
		case BER_INTEGER:
			{
			long longValue;

			status = readShortIntegerData( stream, &longValue );
			if( cryptStatusError( status ) )
				break;
			if( !isIntegerRange( longValue ) )
				{
				status = CRYPT_ERROR_OVERFLOW;
				break;
				}
			value = ( int ) longValue;
			break;
			}

		case BER_ENUMERATED:
			status = readEnumeratedData( stream, &value );
			break;

		case BER_BITSTRING:
			status = readBitStringData( stream, &value );
			break;

		case BER_BOOLEAN:
			{
			BOOLEAN boolean;

			status = readBooleanData( stream, &boolean );
			if( cryptStatusOK( status ) )
				value = boolean ? 1 : 0;
			break;
			}

		case BER_NULL:
			/* NULL values have no associated data so we explicitly set the 
			   value to CRYPT_UNUSED to ensure that this is returned on any 
			   attempt to read the attribute data */
			value = CRYPT_UNUSED;
			break;

		case BER_TIME_GENERALIZED:
		case BER_TIME_UTC:
			/* Normally we'd use readTime() but the tag has already been 
			   read at a higher level so we call the type-specific read 
			   function directly */
			if( attributeInfoPtr->fieldType == BER_TIME_GENERALIZED )
				status = readGeneralizedTimeData( stream, &timeVal );
			else
				status = readUTCTimeData( stream, &timeVal );
			if( cryptStatusError( status ) )
				break;
			dataPtr = &timeVal;
			dataLength = sizeof( time_t );
			break;

		case BER_STRING_BMP:
		case BER_STRING_IA5:
		case BER_STRING_ISO646:
		case BER_STRING_NUMERIC:
		case BER_STRING_PRINTABLE:
		case BER_STRING_T61:
		case BER_STRING_UTF8:
		case BER_OCTETSTRING:
		case FIELDTYPE_BLOB_ANY:
		case FIELDTYPE_BLOB_BITSTRING:
		case FIELDTYPE_BLOB_SEQUENCE:
		case FIELDTYPE_TEXTSTRING:
			/* If it's a string type or a blob read it in as a blob, the 
			   only difference being that for a true blob we read the tag 
			   and length as well.  We read the data to a maximum length of 
			   512 bytes, the text strings all top out at either 200 or 255 
			   bytes but BLOB_ANY and FIELDTYPE_BLOB_SEQUENCE can go up to 
			   MAX_ATTRIBUTE_SIZE.

			   This is however modified by two special cases.  Firstly, 
			   readRawObject() as used to read blobs only allows lengths up 
			   to 256 bytes, however as of 2020 a case of a field that goes
			   beyond this size has never been encountered.  Secondly, CAs 
			   really like to overrun CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT 
			   beyond its limit of 200 characters with overlong legal 
			   disclaimers so this handles those as well */
			if( isBlobField( attributeInfoPtr->fieldType ) )
				{
				int tag;
				
				/* Reading in blob fields is somewhat difficult since these
				   are typically used to read SET/SEQUENCE OF kitchen-sink
				   values and so won't have a consistent tag that we can pass
				   to readRawObject().  To get around this we peek ahead into
				   the stream to get the tag and then pass that down to 
				   readRawObject().  Note that this requires that the blob 
				   have an internal structure (with its own { tag, length }
				   data) since the caller has already stripped off the 
				   encapsulating tag and length */
				status = tag = peekTag( stream );
				if( !cryptStatusError( status ) )
					{
					ANALYSER_HINT( isValidTag( tag ) );	
								   /* Guaranteed by peekTag() */
					status = readRawObject( stream, buffer, 512, 
											&dataLength, tag );
					}
				}
			else
				{
				if( isEncodingAlias( attributeInfoPtr->fieldType, 
									 attributeInfoPtr->fieldEncodedType ) ) 
					{
					/* It's an aliased encoding, specifically an INTEGER 
					   hole */
					status = readIntegerData( stream, buffer, 512, 
											  &dataLength );
					}
				else
					{
					status = readOctetStringData( stream, buffer, &dataLength, 
												  1, 512 );
					}
				}
			if( cryptStatusError( status ) )
				break;

			/* There are enough broken certificates out there with 
			   enormously long disclaimers in the certificate policy 
			   explicit text field that we have to specifically check for 
			   them here and truncate the text at a valid length in order 
			   to get it past the attribute validity checking code */
			if( fieldID == CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT && \
				dataLength > 200 )
				dataLength = 200;

			/* We set the payload-blob flag when adding the data even for
			   string data because users typically cram any old rubbish into 
			   the strings and not setting the blob flag would cause them to
			   be rejected */
			dataPtr = buffer;
			dataFlags = ATTR_FLAG_BLOB_PAYLOAD;
			break;

		case BER_OBJECT_IDENTIFIER:
			/* If it's an OID then we need to reassemble the entire OID 
			   since this is the form expected by addAttributeFieldString() */
			buffer[ 0 ] = BER_OBJECT_IDENTIFIER;	/* Add skipped tag */
			status = readEncodedOID( stream, buffer + 1, MAX_OID_SIZE - 1, 
									 &dataLength, NO_TAG );
			if( cryptStatusError( status ) )
				break;
			dataPtr = buffer;
			dataLength++;		/* Include the skipped tag */
			break;

		case FIELDTYPE_DN:
			/* Read the DN */
			status = readDN( stream, &dn );
			if( cryptStatusError( status ) )
				break;

			/* Some buggy certificates can include zero-length DNs, which we 
			   skip */
			if( DATAPTR_ISNULL( dn ) )
				return( CRYPT_OK );

			/* We're being asked to instantiate the field containing the DN,
			   create the attribute field and fill in the DN value.  Since 
			   the value that we're passing in is actually a DN_PTR rather 
			   than a standard string value we set the size field to the 
			   pseudo-length of a DN_PTR_STORAGE value to keep the static/
			   runtime code checks happy */
			dataPtr = &dn;
			dataLength = sizeof( DATAPTR_DN );
			break;

		case FIELDTYPE_ALGOID:
			/* The algorithmID field type is currently only used for the
			   rarely-seen RFC 6211 cmsAlgorithmProtection attribute where
			   it's used to copy the hash algorithm and optionally signature
			   and MAC algorithm from the metadata into the signed 
			   attributes to protect against algorithm-substitution attacks.
			   Since these attributes are virtually never seen, there's no
			   hash algorithm used by cryptlib that the attack would apply 
			   to, and in any case the hash algorithms that are used aren't
			   parameterised, we ignore the algorithm parameters field.
			   
			   There is one thing that we don't check which is the annoying
			   case of identical signature and hash algprithms but different 
			   signature format types, specifically PKCS #1 vs. PSS, which 
			   there's no way to record.  However this shouldn't be an issue 
			   because swapping one for the other will cause an immediate
			   signature check failure.  
			   
			   The one possible attack that's still available is one that
			   takes advantage of the use of unauthenticated PSS parameters
			   to attack the PSS signature format, but even that is 
			   mitigated since we check the MGF and hash algorithm and the
			   remaining PSS parameters are fixed and determined by the hash
			   algorithm used */
			{
			CRYPT_ALGO_TYPE cryptAlgo;
			ALGOID_PARAMS algoIDparams;
			const int tag = attributeInfoPtr->fieldEncodedType;

			status = readAlgoIDexTag( stream, &cryptAlgo, &algoIDparams,
									  attributeInfoPtr->parameter,
									  ( tag == CRYPT_UNUSED ) ? \
									    DEFAULT_TAG : tag );
			if( cryptStatusError( status ) )
				break;
			value = cryptAlgo;	/* int vs. enum */
/*			valueExt = algoIDparams->encodingType converted to CRYPT_PKCFORMAT_TYPE */
			break;
			}

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		{
		return( readAttributeErrorReturn( errorLocus, errorType, errorInfo, 
										  attributeInfoPtr, 0, "data", 
										  status ) );
		}

	/* If it's an integer value, add the data for this attribute field */
	if( dataPtr == NULL )
		{
		return( addAttributeField( attributePtrPtr, fieldID, subFieldID, 
								   value, flags, TRUE, errorInfo, 
								   errorLocus, errorType ) );
		}
	ENSURES( isShortIntegerRangeNZ( dataLength ) );

	/* It's binary data, add it as a string value */ 
	status = addAttributeFieldString( attributePtrPtr, fieldID, subFieldID, 
									  dataPtr, dataLength, 
									  flags | dataFlags, TRUE, errorInfo, 
									  errorLocus, errorType );
	if( cryptStatusError( status ) && \
		attributeInfoPtr->fieldType == FIELDTYPE_DN )
		{
		/* There was an error adding a newly-created DN, make sure that we 
		   clean up before exiting */
		deleteDN( &dn );
		}
			
	return( status );
	}

/****************************************************************************
*																			*
*								Attribute Read Routines						*
*																			*
****************************************************************************/

/* Skip additional entries that may be present at the end of an attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int skipAdditionalEntries( INOUT_PTR STREAM *stream, 
								  INOUT_PTR ERROR_INFO *errorInfo,
								  IN_LENGTH const int endPos )
	{
	LOOP_INDEX noAdditionalEntries;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isIntegerRangeNZ( endPos ) );

	LOOP_SMALL( noAdditionalEntries = 0, 
				stell( stream ) < endPos && noAdditionalEntries < 5,
				noAdditionalEntries++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( noAdditionalEntries, 0, 4 ) );

		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			{
			/* We can't use readAttributeErrorReturn() here because we've 
			   moved through all of the attributeInfoPtr entries so we just
			   return a generic error message */
			retExt( status,
					( status, errorInfo, 
					  "Couldn't read additional trailing fields in "
					  "attribute" ) );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( noAdditionalEntries >= 5 )
		{
		/* There's a suspiciously large amount of extra data, treat it as an 
		   error.  As before we have to return a generic error message */
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, errorInfo, 
				  "Encountered more than %d additional trailing fields in "
				  "attribute", noAdditionalEntries ) );
		}

	return( CRYPT_OK );
	}

/* Read an attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6, 7, 8 ) ) \
int readAttribute( INOUT_PTR STREAM *stream, 
				   INOUT_PTR DATAPTR_ATTRIBUTE *attributePtrPtr,
				   IN_PTR const ATTRIBUTE_INFO *attributeInfoPtr, 
				   IN_LENGTH_SHORT_Z const int attributeLength, 
				   IN_BOOL const BOOLEAN criticalFlag, 
				   INOUT_PTR ERROR_INFO *errorInfo,
				   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
				   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType )
	{
	SETOF_STACK setofStack;
	SETOF_STATE_INFO *setofInfoPtr;
	const int endPos = stell( stream ) + attributeLength;
#ifdef USE_RPKI
	CRYPT_ATTRIBUTE_TYPE fieldID = attributeInfoPtr->fieldID;
	int maxAttributeFields;
#else
	const int maxAttributeFields = min( 5 + ( attributeLength / 3 ), 256 );
#endif /* USE_RPKI */
	BOOLEAN attributeContinues = TRUE;
	int flags = criticalFlag ? ATTR_FLAG_CRITICAL : ATTR_FLAG_NONE;
	LOOP_INDEX attributeFieldsProcessed;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributePtrPtr, sizeof( DATAPTR_ATTRIBUTE ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );
	
	REQUIRES( isShortIntegerRange( attributeLength ) );
	REQUIRES( isBooleanValue( criticalFlag ) );
	REQUIRES( isIntegerRangeMin( endPos, attributeLength ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Set an upper limit for how many attribute fields we should be seeing 
	   before we report a problem.  We have to apply special-case handling
	   for a few problem attributes that get used as general-purpose list
	   fields with arbitrary numbers of entries that exceed normal sanity-
	   check limits.

	   Another potential problem is CDN certificates with altNames that 
	   contain one of every site the CDN supports or one of every domain the 
	   parent company owns.  This causes additional problems with the 
	   failsafe loop bound because the altName contains large numbers of non-
	   present fields so attributeFieldsProcessed is never incremented even 
	   though we go through the loop, resulting in large numbers of passes 
	   through the loop until the failsafe check is triggered.  Google at 
	   one point had certificates that required the limit to be raised from 
	   min( ..., 256 ) to min( ..., 512 ) and the use of LOOP_MAX(), but 
	   these certificates have now expired and been redone in a more sane 
	   manner */
#ifdef USE_RPKI
	if( fieldID == FIELDID_FOLLOWS )
		fieldID = attributeInfoPtr[ 1 ].fieldID; 
	if( fieldID == CRYPT_CERTINFO_AUTONOMOUSSYSIDS || \
		fieldID == CRYPT_CERTINFO_IPADDRESSBLOCKS )
		{
		/* CRYPT_CERTINFO_IPADDRESSBLOCKS and 
		   CRYPT_CERTINFO_AUTONOMOUSSYSIDS are an end-run around the 
		   nonexistence of attribute certificates that turn standard 
		   certificates into arbitrary-length capability lists, with each
		   entry being as small as three bytes.  To deal with this we have
		   to apply a special scaling factor to the upper-bound check */
		maxAttributeFields = 5 + ( attributeLength / 3 );
		}
#endif /* USE_RPKI */

	/* Initialise the SET/SEQUENCE OF state stack */
	setofStackInit( &setofStack );
	setofInfoPtr = setofTOS( &setofStack );
	ENSURES( setofInfoPtr != NULL );

	/* Process each field in the attribute.  This is a simple (well, 
	   conceptually simple but practically complex since it has to deal with 
	   the product of PKI standards committees) FSM driven by the encoding 
	   table and the data that we encounter.  The various states and 
	   associated actions are indicated by the comment tags */
	LOOP_LARGE( attributeFieldsProcessed = 0,
				( attributeContinues || !setofStackIsEmpty( &setofStack ) ) && \
					stell( stream ) < endPos && \
					attributeFieldsProcessed < maxAttributeFields,
				attributeFieldsProcessed++ /* Also changed in loop body */ )
		{
		BOOLEAN endOfSet, skippedOptional = FALSE;
		int tag, peekedTag, value;

		ENSURES( LOOP_INVARIANT_LARGE_XXX( attributeFieldsProcessed, 0, 
										   maxAttributeFields - 1 ) );
				 /* The attributeFieldsProcessed increment is occasionally reset 
				    in the case of non-present optional attributes */

		/* Inside a SET/SET OF/SEQUENCE/SEQUENCE OF: Check for the end of the
		   item/collection of items.  This must be the first action taken
		   since reaching the end of a SET/SEQUENCE pre-empts all other
		   parsing actions */
		if( !setofStackIsEmpty( &setofStack ) )
			{
			/* If we've reached the end of the collection of items, exit */
			status = setofCheckEnd( stream, &setofStack, &attributeInfoPtr );
			if( cryptStatusError( status ) && status != OK_SPECIAL )
				return( status );
			setofInfoPtr = setofTOS( &setofStack );
			ENSURES( setofInfoPtr != NULL );
			if( status == OK_SPECIAL )
				{
				/* We've reached the end of the collection.  Resetting the 
				   status at this point is actually a dead assignment but 
				   the code flow to see this is sufficiently complex that we 
				   clear it anyway for hygiene reasons */
				status = CRYPT_OK;
				ANALYSER_HINT_DEADSTORE_OK( status );
				goto continueDecoding;
				}

			/* If we're looking for a new item, find the encoding table entry 
			   that it corresponds to.  This takes a pointer to the start of 
			   a set of SEQUENCE { type, value } entries and returns a 
			   pointer to the appropriate value entry.

			   The test for the start of a new item is a bit complex since 
			   we could currently be on the next item flagged as an 
			   identifier (if we're pointing at the end of the previous 
			   item) or at the start of the next attribute (if we're 
			   pointing at the end of the attribute) */
			if( ( attributeInfoPtr->encodingFlags & FL_IDENTIFIER ) || \
				( attributeInfoPtr->typeInfoFlags & FL_ATTR_ATTRSTART ) )
				{
				status = processIdentifiedItem( stream, attributePtrPtr, 
												flags, &setofStack, 
												&attributeInfoPtr, errorInfo,
												errorLocus, errorType );
				if( cryptStatusError( status ) )
					{
					if( status == OK_SPECIAL )
						{
						/* We've switched to a new encoding table, continue
						   from there.  As before, we reset the status even
						   though it's techically not necessary */
						status = CRYPT_OK;
						ANALYSER_HINT_DEADSTORE_OK( status );
						continue;
						}
					return( status );
					}
				}
			}

		/* Subtyped field: Switch to the new encoding table */
		if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED )
			{
			/* Save the current encoding table state prior to switching to 
			   the subtype */
			setofPushSubtyped( setofInfoPtr, attributeInfoPtr );

			/* Switch to the subtype encoding table */
			TRACE_DEBUG(( "Switching to 'generalName' subType encoding "
						  "table.\n" ));
			attributeInfoPtr = attributeInfoPtr->extraData;
			ENSURES( attributeInfoPtr != NULL );
			}

		/* CHOICE (of object identifiers): Read a single OID from a
		   selection defined in a subtable.
		   Identifier field: Read a sequence of one or more { oid, value }
		   fields and continue */
		if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE || \
			attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER )
			{
			if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
				{
				const ATTRIBUTE_INFO *extraDataPtr = \
											attributeInfoPtr->extraData;
						/* Needed because ->extraData is read-only */

				/* This has already been verified during the startup check */
				ENSURES( extraDataPtr != NULL );
				
				status = readIdentifierFields( stream, attributePtrPtr,
										&extraDataPtr, flags, 
										attributeInfoPtr->fieldID, errorInfo,
										errorLocus, errorType );
				}
			else
				{
				status = readIdentifierFields( stream, attributePtrPtr,
										&attributeInfoPtr, flags, 
										CRYPT_ATTRIBUTE_NONE, errorInfo,
										errorLocus, errorType );
				}
			if( cryptStatusError( status ) )
				{
				return( readAttributeErrorReturn( errorLocus, errorType,
									errorInfo, attributeInfoPtr, 0, "data", 
									status ) );
				}
			setofSetNonemptyOpt( setofInfoPtr, &setofStack );	/* Seen set entry */
			goto continueDecoding;
			}

		/* Non-encoding field: Skip it and continue */
		if( attributeInfoPtr->encodingFlags & FL_NONENCODING )
			{
			/* Read the data and continue.  We don't check its value for the 
			   reasons given under the SET OF handling code above (value 
			   check) and optional field code below (error locus set) */
			TRACE_FIELDTYPE( attributeInfoPtr, setofStack.stackPos );
			if( attributeInfoPtr->fieldType == BER_NULL )
				{
				/* If the field is an ASN.1 NULL then the length is zero,
				   so we can't read it with readUniversal() which requires 
				   that data be present */
				status = readNull( stream );
				}
			else
				status = readUniversal( stream );
			if( cryptStatusError( status ) )
				{
				return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 0, 
									"nonencoding data", status ) );
				}
			setofSetNonemptyOpt( setofInfoPtr, &setofStack );	/* Seen set entry */
			goto continueDecoding;
			}

		/* Get the tag for the field */
		status = getFieldTag( stream, attributeInfoPtr, &tag );
		if( cryptStatusError( status ) )
			return( status );

		/* Optional field: Check whether it's present and if it isn't, move
		   on to the next field */
		if( ( attributeInfoPtr->encodingFlags & FL_OPTIONAL ) && \
			checkStatusPeekTag( stream, status, peekedTag ) && \
			peekedTag != tag )
			{
			/* If it's a field with a default value, add that value.  This
			   isn't needed for cryptlib's own use since it knows the default
			   values for fields but can cause confusion for the caller if 
			   all fields in an attribute have default values because the
			   attribute will appear to disappear when it's read in as no
			   fields are ever added */
			if( attributeInfoPtr->encodingFlags & FL_DEFAULT )
				{
				status = addDefaultValue( attributePtrPtr, attributeInfoPtr, 
										  flags, errorInfo, errorLocus, 
										  errorType );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* Skip to the end of the item and remember that we've skipped 
			   optional attribute fields.  This is important because at this
			   point the attributeInfoPtr will be pointing to the end of the
			   skipped fields, in other words fields that we never looked at, 
			   and so the only valid operation on it is advancing to the 
			   next field */
			status = findItemEnd( &attributeInfoPtr, 0 );
			if( cryptStatusError( status ) )
				return( status );
			skippedOptional = TRUE;
			
			/* Since this was a (non-present) optional attribute it 
			   shouldn't be counted in the total when we continue decoding,
			   so we adjust the fields-processed value to account for this */
			if( attributeFieldsProcessed > 0 )
				attributeFieldsProcessed--;

			goto continueDecoding;
			}
		if( cryptStatusError( status ) )
			return( status );	/* Residual error from peekTag() */

		/* Print a trace of what we're processing.  Everything before this
		   point does its own special-case tracing so we don't trace before 
		   we get here to avoid displaying duplicate/misleading 
		   information */
		TRACE_FIELDTYPE( attributeInfoPtr, setofStack.stackPos );

		/* Explicitly tagged field: Read the explicit wrapper and make sure
		   that it matches what we're expecting (the read is done here, the
		   match is done further down) */
		if( attributeInfoPtr->encodingFlags & FL_EXPLICIT )
			{
			REQUIRES( tag == MAKE_CTAG( attributeInfoPtr->fieldEncodedType ) );
					  /* Always constructed */

			status = readExplicitTag( stream, attributeInfoPtr, &tag );
			if( cryptStatusError( status ) )
				{
				return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 0, 
									"data wrapper", status ) );
				}
			}

		/* Blob field, DN, or AlgorithmIdentifier: We don't try and 
		   interpret blobs in any way, and DNs and AlgorithmIdentifiers are 
		   composite structures read as a complete unit by the lower-level 
		   code */
		if( isBlobField( attributeInfoPtr->fieldType ) || \
			attributeInfoPtr->fieldType == FIELDTYPE_DN || \
			attributeInfoPtr->fieldType == FIELDTYPE_ALGOID )
			{
			status = readAttributeField( stream, attributePtrPtr,
										 attributeInfoPtr,
										 setofInfoPtr->subtypeParent,
										 flags | setofInfoPtr->inheritedAttrFlags,
										 errorInfo, errorLocus, errorType );
			if( cryptStatusError( status ) )
				{
				/* Adding complex attributes such as DNs can return specific
				   error codes that report the exact parameter that was 
				   wrong so we convert a parameter error into a more general 
				   bad data status */
				return( cryptArgError( status ) ? \
						CRYPT_ERROR_BADDATA : status );
				}
			setofSetNonemptyOpt( setofInfoPtr, &setofStack );	/* Seen set entry */
			goto continueDecoding;
			}

		/* Standard field: Read the tag for the field and make sure that it
		   matches what we're expecting */
		status = value = peekTag( stream );
		if( cryptStatusError( status ) || value != tag )
			{
			return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 0, "tag",
									cryptStatusError( status ) ? \
										status : CRYPT_ERROR_BADDATA ) );
			}
		setofSetNonemptyOpt( setofInfoPtr, &setofStack );	/* Seen set entry */

		/* SET/SET OF/SEQUENCE/SEQUENCE OF start: Record its details, stack 
		   the current processing state at the start of the SET/SEQUENCE, 
		   and continue */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
			attributeInfoPtr->fieldType == BER_SET )
			{
			status = setofBegin( &setofStack, &setofInfoPtr, stream, 
								 attributeInfoPtr, endPos );
			if( cryptStatusError( status ) )
				{
				return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 0, 
									"SET/SEQUENCE wrapper", status ) );
				}
			goto continueDecoding;
			}
		ENSURES( !( attributeInfoPtr->encodingFlags & FL_SETOF ) );

		/* We've checked the tag, skip it.  We do this at this level rather
		   than in readAttributeField() because it doesn't know about 
		   context-specific tagging requirements */
		status = readTag( stream );
		if( cryptStatusError( status ) )
			return( status );

		/* Standard field, read the field data */
		status = readAttributeField( stream, attributePtrPtr,
									 attributeInfoPtr,
									 setofInfoPtr->subtypeParent,
									 flags | setofInfoPtr->inheritedAttrFlags,
									 errorInfo, errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			/* Adding invalid attribute data can return detailed error codes
			   that report the exact parameter that was wrong so we convert 
			   a parameter error into a more general bad data status */
			return( cryptArgError( status ) ? \
					CRYPT_ERROR_BADDATA : status );
			}

		/* Move on to the next field */
continueDecoding:
		attributeContinues = \
					( attributeInfoPtr->typeInfoFlags & FL_ATTR_ATTREND ) ? \
					FALSE : TRUE;
		endOfSet = ( attributeInfoPtr->encodingFlags & FL_SETOF_END ) && \
				   !skippedOptional ? TRUE : FALSE;
		attributeInfoPtr++;

		/* If this is the end of either the current SEQUENCE/SET or of the 
		   overall attribute encoding information but we're still inside a 
		   SET OF/SEQUENCE OF and there's more attribute data present, go 
		   back to the restart point and try again */
		if( ( endOfSet || !attributeContinues ) && \
			!setofStackIsEmpty( &setofStack ) )
			{
			status = setofCheckRestart( stream, setofInfoPtr, 
										&attributeInfoPtr );
			if( cryptStatusError( status ) )
				{
				/* If there was a problem other than the end of SET OF/
				   SEQUENCE OF being reached, exit */
				if( status != OK_SPECIAL )
					return( status );
				}
			else
				{
				/* We're still inside the SET OF/SEQUENCE OF, continue 
				   processing */
				attributeContinues = TRUE;
				}
			}
		}
	ENSURES( LOOP_BOUND_OK );

	/* If we got stuck in a loop trying to decode an attribute, complain and 
	   exit.  At this point we could have encountered either a certificate-
	   parsing error or a CRYPT_ERROR_INTERNAL internal error, since we 
	   can't tell without human intervention we treat it as a certificate 
	   error rather than throwing a retIntError() exception */
	if( attributeFieldsProcessed >= maxAttributeFields )
		{
		DEBUG_DIAG(( "Processed more than %d fields in attribute, decoder "
					 "may be stuck", maxAttributeFields ));
		assert( DEBUG_WARN );
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, errorInfo, 
				  "Encountered more than %d fields in an attribute", 
				  maxAttributeFields ) );
		}

	/* Handle the special case of (a) the encoded data ending but fields with
	   default values being present or (b) the encoded data continuing but no 
	   more decoding information being present */
	if( attributeContinues )
		{
		/* If there are default fields to follow, add the default value, see
		   the comment on the handling of default fields above for more 
		   details.  For now we only add the first field since the only 
		   attributes where this case can occur have a single default value 
		   as the next possible entry, burrowing down further causes 
		   complications due to default values present in optional 
		   sequences */
		if( attributeInfoPtr->encodingFlags & FL_DEFAULT )
			{
			status = addDefaultValue( attributePtrPtr, attributeInfoPtr, 
									  flags, errorInfo, errorLocus, 
									  errorType );
			if( cryptStatusError( status ) )
				return( status );
			}
		
		return( CRYPT_OK );
		}

	/* Some attributes have a SEQUENCE OF fields of no great use (e.g. 
	   Microsoft's extensive crlDistributionPoints lists providing redundant 
	   pointers to the same inaccessible site-internal servers, although 
	   these are already handled above), if there's any extraneous data left 
	   then we just skip it */
	if( stell( stream ) < endPos )
		{
		DEBUG_DIAG(( "Skipping extraneous data at end of attribute" ));
		assert_nofuzz( DEBUG_WARN );
		status = skipAdditionalEntries( stream, errorInfo, endPos );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}
#endif /* USE_CERTIFICATES */
