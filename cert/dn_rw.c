/****************************************************************************
*																			*
*						Certificate DN Read/Write Routines					*
*						Copyright Peter Gutmann 1996-2015					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "dn.h"
#else
  #include "cert/cert.h"
  #include "cert/dn.h"
#endif /* Compiler-specific includes */

#ifdef USE_CERTIFICATES

/****************************************************************************
*																			*
*									Read a DN								*
*																			*
****************************************************************************/

/* Parse an AVA.  This determines the AVA type and leaves the stream pointer
   at the start of the data value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readAVABitstring( INOUT_PTR STREAM *stream, 
							 OUT_LENGTH_SHORT_Z int *length, 
							 OUT_TAG_ENCODED_Z int *stringTag )
	{
	long streamPos;
	int bitStringLength, innerTag, innerLength DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );
	assert( isWritePtr( stringTag, sizeof( int ) ) );

	/* Clear return values */
	*length = 0;
	*stringTag = 0;

	/* Bitstrings are used for uniqueIdentifiers, however these usually 
	   encapsulate something else:

		BIT STRING {
			IA5String 'xxxxx'
			}

	   so we try and dig one level deeper to find the encapsulated string if 
	   there is one.  This gets a bit complicated because we have to 
	   speculatively try and decode the inner content and if that fails 
	   assume that it's raw bitstring data.  First we read the bitstring 
	   wrapper and remember where the bitstring data starts */
	status = readBitStringHole( stream, &bitStringLength, 2, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	streamPos = stell( stream );
	REQUIRES( isShortIntegerRangeNZ( streamPos ) );

	/* Then we try and read any inner content */
	status = innerTag = peekTag( stream );
	if( !cryptStatusError( status ) )
		{ 
		ANALYSER_HINT( isValidTag( innerTag ) );	/* Guaranteed by peekTag() */
		status = readGenericHole( stream, &innerLength, 1, innerTag );
		}
	if( !cryptStatusError( status ) && \
		bitStringLength == sizeofObject( innerLength ) )
		{
		/* There was inner content present, treat it as the actual type and 
		   value of the bitstring.  This assumes that the inner content is
		   a string data type, which always seems to be the case (in any 
		   event it's not certain what we should be returning to the user if
		   we find, for example, a SEQUENCE with further encapsulated 
		   content at this point) */
		*stringTag = innerTag;
		*length = innerLength;

		return( CRYPT_OK );
		}

	/* We couldn't identify any (obvious) inner content, it must be raw
	   bitstring data.  Unfortunately we have no idea what format this is
	   in, it could in fact really be raw binary data but never actually 
	   seems to be this, it's usually ASCII text so we mark it as such and 
	   let the string-read routines sort it out */
	sClearError( stream );
	sseek( stream, streamPos );
	*stringTag = BER_STRING_IA5;
	*length = bitStringLength;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int readAVA( INOUT_PTR STREAM *stream, 
					OUT_INT_Z int *type, 
					OUT_LENGTH_SHORT_Z int *length, 
					OUT_TAG_ENCODED_Z int *stringTag )
	{
	const DN_COMPONENT_INFO *dnComponentInfo;
	BYTE oid[ MAX_OID_SIZE + 8 ];
	int oidLength, tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( type, sizeof( int ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );
	assert( isWritePtr( stringTag, sizeof( int ) ) );

	/* Clear return values */
	*type = 0;
	*length = 0;
	*stringTag = 0;

	/* Read the start of the AVA and determine the type from the 
	   AttributeType field.  If we find something that we don't recognise we 
	   indicate it as a non-component type that can be read or written but 
	   not directly accessed by the user (although it can still be accessed 
	   using the cursor functions) */
	readSequence( stream, NULL );
	status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
							 BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	dnComponentInfo = findDNInfoByOID( oid, oidLength );
	if( dnComponentInfo == NULL )
		{
		/* If we don't recognise the component type at all, skip it */
		status = readUniversal( stream );
		return( cryptStatusError( status ) ? status : OK_SPECIAL );
		}
	*type = dnComponentInfo->type;

	/* We've reached the data value, make sure that it's in order.  When we
	   read the wrapper around the string type with readGenericHole() we have 
	   to allow a minimum length of zero instead of one because of broken 
	   AVAs with zero-length strings */
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( isValidTag( tag ) );	/* Guaranteed by peekTag() */
	if( tag == BER_BITSTRING )
		return( readAVABitstring( stream, length, stringTag ) );
	*stringTag = tag;
	return( readGenericHoleZ( stream, length, 0, tag ) );
	}

/* Read an RDN/DN component */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRDNcomponent( INOUT_PTR STREAM *stream, 
							 INOUT_PTR DATAPTR_DN *dnPtr,
							 IN_LENGTH_SHORT const int rdnDataLeft )
	{	
	CRYPT_ERRTYPE_TYPE dummy;
	ERROR_INFO localErrorInfo;
	BYTE stringBuffer[ MAX_ATTRIBUTE_SIZE + 8 ];
	void *value;
	const int rdnStart = stell( stream );
	int type, valueLength, valueStringType, stringTag;
	int flags = DN_FLAG_NOCHECK, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dnPtr, sizeof( DATAPTR_DN ) ) );

	REQUIRES( isShortIntegerRangeNZ( rdnDataLeft ) );
	REQUIRES( isShortIntegerRangeNZ( rdnStart ) );

	/* Read the type information for this AVA */
	status = readAVA( stream, &type, &valueLength, &stringTag );
	if( cryptStatusError( status ) )
		{
		/* If this is an unrecognised AVA, don't try and process it (the
		   content will already have been skipped in readAVA()) */
		if( status == OK_SPECIAL )
			return( CRYPT_OK );

		return( status );
		}

	/* Make sure that the string is a valid type for a DirectoryString.  We 
	   don't allow Universal strings since no-one in their right mind uses
	   those.
	   
	   Alongside DirectoryString values we also allow IA5Strings, from the
	   practice of stuffing email addresses into DNs */
	if( stringTag != BER_STRING_PRINTABLE && stringTag != BER_STRING_T61 && \
		stringTag != BER_STRING_BMP && stringTag != BER_STRING_UTF8 && \
		stringTag != BER_STRING_IA5 )
		return( CRYPT_ERROR_BADDATA );

	/* Make sure that the string is a valid length (zero-lenth strings are
	   checked for below).  This is defined in a series of ub-XXX-name 
	   values in the standard which are recorded in the DN_COMPONENT_INFO,
	   however since most implementations and CAs ignore these values we
	   only enforce a general large upper limit of 128 bytes */
	if( valueLength > 256 )
		return( CRYPT_ERROR_OVERFLOW );

	/* Skip broken AVAs with zero-length strings */
	if( valueLength <= 0 )
		return( CRYPT_OK );

	/* Record the string contents, avoiding moving it into a buffer */
	status = sMemGetDataBlock( stream, &value, valueLength );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, valueLength, MAX_INTLENGTH_SHORT );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( value != NULL );

	/* If there's room for another AVA, mark this one as being continued.  The
	   +10 value is the minimum length for an AVA: SEQUENCE { OID, value } 
	   (2-bytes SEQUENCE + 5 bytes OID + 2 bytes (tag + length) + 1 byte min-
	   length data) */
	if( rdnDataLeft >= ( stell( stream ) - rdnStart ) + 10 )
		flags |= DN_FLAG_CONTINUED;

	/* Convert the string into the local character set */
	status = copyFromAsn1String( stringBuffer, MAX_ATTRIBUTE_SIZE, 
								 &valueLength, &valueStringType, value, 
								 valueLength, stringTag );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the DN component to the DN.  If we hit a non-memory related error
	   we turn it into a generic CRYPT_ERROR_BADDATA error since the other
	   codes are somewhat too specific for this case, something like 
	   CRYPT_ERROR_INITED or an arg error isn't too useful for the caller.  
	   Since this is a low-level operation there isn't any useful additional 
	   error information to return */
	clearErrorInfo( &localErrorInfo );
	status = insertDNstring( dnPtr, type, stringBuffer, valueLength,
							 valueStringType, flags, &localErrorInfo, 
							 &dummy );
	return( ( cryptStatusError( status ) && \
			  status != CRYPT_ERROR_MEMORY ) ? \
			CRYPT_ERROR_BADDATA : status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readDNComponent( INOUT_PTR STREAM *stream, 
							INOUT_PTR DATAPTR_DN *dnPtr )
	{
	LOOP_INDEX noComponents;
	int rdnLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dnPtr, sizeof( DATAPTR_DN ) ) );

	/* Read the start of the RDN */
	status = readSet( stream, &rdnLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Read each RDN component */
	LOOP_MED( noComponents = 0, rdnLength > 0 && noComponents < 32,
			  noComponents++ )
		{
		const int rdnStart = stell( stream );
		int objectSize DUMMY_INIT;

		REQUIRES( isShortIntegerRangeNZ( rdnStart ) );

		ENSURES( LOOP_INVARIANT_MED( noComponents, 0, 31 ) );

		status = readRDNcomponent( stream, dnPtr, rdnLength );
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, rdnStart, 
												  &objectSize );
			}
		if( cryptStatusError( status ) )
			return( status );
		rdnLength -= objectSize;
		}
	ENSURES( LOOP_BOUND_OK );
	if( rdnLength < 0 || noComponents >= 32 )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

/* Read a DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readDN( INOUT_PTR STREAM *stream, 
			OUT_DATAPTR_COND DATAPTR_DN *dnPtr )
	{
	DATAPTR_DN dn;
	LOOP_INDEX noComponents;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dnPtr, sizeof( DATAPTR_DN ) ) );

	/* Clear return value */
	DATAPTR_SET_PTR( dnPtr, NULL );

	/* Read the encoded DN into the local copy of the DN (in other words 
	   into the dn, not the externally-visible dnPtr) */
	status = readSequenceZ( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length <= 0 )
		{
		/* Some buggy certificates include zero-length DNs, which we skip */
		return( CRYPT_OK );
		}
	DATAPTR_SET( dn, NULL );
	LOOP_MED( noComponents = 0, length > 0 && noComponents < 32,
			  noComponents++ )
		{
		const int innerStartPos = stell( stream );
		int objectSize DUMMY_INIT;

		REQUIRES( isShortIntegerRangeNZ( innerStartPos ) );

		ENSURES( LOOP_INVARIANT_MED( noComponents, 0, 31 ) );

		status = readDNComponent( stream, &dn );
		if( cryptStatusOK( status ) )
			{
			status = calculateStreamObjectLength( stream, innerStartPos, 
												  &objectSize );
			}
		if( cryptStatusError( status ) )
			break;
		length -= objectSize;
		}
	ENSURES( LOOP_BOUND_OK );
	if( cryptStatusError( status ) || \
		length < 0 || noComponents >= 32 )
		{
		/* Delete the local copy of the DN read so far if necessary */
		if( DATAPTR_ISSET( dn ) )
			deleteDN( &dn );
		return( cryptStatusError( status ) ? status : CRYPT_ERROR_BADDATA );
		}

	/* Copy the local copy of the DN back to the caller */
	*dnPtr = dn;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*									Write a DN								*
*																			*
****************************************************************************/

/* Perform the pre-encoding processing for a DN.  Note that sizeofDN() takes
   a slightly anomalous const parameter that isn't because the pre-encoding 
   process required to determine the DN's size modifies portions of the DN 
   component values related to the encoding process */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int preEncodeDN( INOUT_PTR DN_COMPONENT *dnComponentPtr, 
						OUT_LENGTH_SHORT_Z int *length )
	{
	int size = 0, LOOP_ITERATOR;

	assert( isWritePtr( dnComponentPtr, sizeof( DN_COMPONENT ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( sanityCheckDNComponent( dnComponentPtr ) );
	REQUIRES( DATAPTR_ISNULL( dnComponentPtr->prev ) );

	/* Clear return value */
	*length = 0;

	/* Walk down the DN pre-encoding each AVA */
	LOOP_MED_CHECKINC( dnComponentPtr != NULL,
					   dnComponentPtr = DATAPTR_GET( dnComponentPtr->next ) )
		{
		DN_COMPONENT *rdnStartPtr = dnComponentPtr;
		int LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* Calculate the size of every AVA in this RDN */
		LOOP_MED_CHECKINC_ALT( dnComponentPtr != NULL,
							   dnComponentPtr = DATAPTR_GET( dnComponentPtr->next ) )
			{
			const DN_COMPONENT_INFO *dnComponentInfo;
			int dnStringLength, status;

			REQUIRES( sanityCheckDNComponent( dnComponentPtr ) );

			ENSURES( LOOP_INVARIANT_MED_ALT_GENERIC() );

			/* If we've already performed an encoding pass on this RDN, 
			   continue.  This occurs because any DN write follows the
			   pattern { sizeofDN(), writeDN() } so we only need to perform
			   the encoding check the first time */
			if( dnComponentPtr->encodedAVAdataSize > 0 )
				{
				if( !TEST_FLAG( dnComponentPtr->flags, DN_FLAG_CONTINUED ) )
					break;
				continue;
				}

			dnComponentInfo = dnComponentPtr->typeInfo;
			status = getAsn1StringInfo( dnComponentPtr->value, 
										dnComponentPtr->valueLength,
										&dnComponentPtr->valueStringType, 
										&dnComponentPtr->asn1EncodedStringType,
										&dnStringLength, TRUE );
			if( cryptStatusError( status ) )
				return( status );
			dnComponentPtr->encodedAVAdataSize = \
										sizeofOID( dnComponentInfo->oid ) + \
										sizeofShortObject( dnStringLength );
			dnComponentPtr->encodedRDNdataSize = 0;
			rdnStartPtr->encodedRDNdataSize += \
						sizeofShortObject( dnComponentPtr->encodedAVAdataSize );
			if( !TEST_FLAG( dnComponentPtr->flags, DN_FLAG_CONTINUED ) )
				break;
			}
		ENSURES( LOOP_BOUND_OK_ALT );

		/* Calculate the overall size of the RDN */
		size += sizeofShortObject( rdnStartPtr->encodedRDNdataSize );

		/* If the inner loop terminated because it reached the end of the DN 
		   then we need to explicitly exit the outer loop as well before it
		   tries to follow the 'next' link in the dnComponentPtr */
		if( dnComponentPtr == NULL )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	*length = size;

	return( CRYPT_OK );
	}

CHECK_RETVAL_LENGTH \
int sizeofDN( IN_DATAPTR_OPT const DATAPTR_DN dn )
	{
	DN_COMPONENT *dnComponentList;
	int length, status;

	REQUIRES( DATAPTR_ISVALID( dn ) );

	/* Null DNs produce a zero-length SEQUENCE */
	if( DATAPTR_ISNULL( dn ) )
		return( sizeofObject( 0 ) );

	dnComponentList = DATAPTR_GET( dn );
	ENSURES( dnComponentList != NULL );
	REQUIRES( sanityCheckDNComponent( dnComponentList ) );
	status = preEncodeDN( dnComponentList, &length );
	if( cryptStatusError( status ) )
		return( status );
	return( sizeofObject( length ) );
	}

/* Write a DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeDN( INOUT_PTR STREAM *stream, 
			 IN_DATAPTR const DATAPTR_DN dn,
			 IN_TAG const int tag )
	{
	DN_COMPONENT *dnComponentList;
	LOOP_INDEX_PTR DN_COMPONENT *dnComponentPtr;
	int size, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( DATAPTR_ISVALID( dn ) );
	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );

	/* Special case for empty DNs */
	if( DATAPTR_ISNULL( dn ) )
		return( writeConstructed( stream, 0, tag ) );

	/* Perform pre-encoding actions for the DN, which determines string-type
	   information and the overall encoded length of the DN */
	dnComponentList = DATAPTR_GET( dn );
	ENSURES( dnComponentList != NULL );
	REQUIRES( sanityCheckDNComponent( dnComponentList ) );
	status = preEncodeDN( dnComponentList, &size );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the DN */
	writeConstructed( stream, size, tag );
	LOOP_MED( dnComponentPtr = dnComponentList, 
			  dnComponentPtr != NULL,
			  dnComponentPtr = DATAPTR_GET( dnComponentPtr->next ) )
		{
		const DN_COMPONENT_INFO *dnComponentInfo;
		BYTE dnString[ MAX_ATTRIBUTE_SIZE + 8 ];
		int dnStringLength;

		REQUIRES( sanityCheckDNComponent( dnComponentPtr ) );

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* Write the RDN wrapper */
		dnComponentInfo = dnComponentPtr->typeInfo;
		if( dnComponentPtr->encodedRDNdataSize > 0 )
			{
			/* If it's the start of an RDN, write the RDN header */
			writeSet( stream, dnComponentPtr->encodedRDNdataSize );
			}
		writeSequence( stream, dnComponentPtr->encodedAVAdataSize );
		status = swrite( stream, dnComponentInfo->oid, 
						 sizeofOID( dnComponentInfo->oid ) );
		if( cryptStatusError( status ) )
			return( status );

		/* Convert the string to an ASN.1-compatible format and write it
		   out */
		status = copyToAsn1String( dnString, MAX_ATTRIBUTE_SIZE, 
								   &dnStringLength, dnComponentPtr->value,
								   dnComponentPtr->valueLength,
								   dnComponentPtr->valueStringType );
		if( cryptStatusError( status ) )
			return( status );
		if( dnComponentPtr->asn1EncodedStringType == BER_STRING_IA5 && \
			!dnComponentInfo->ia5OK )
			{
			/* If an IA5String isn't allowed in this instance, use a
			   T61String instead */
			dnComponentPtr->asn1EncodedStringType = BER_STRING_T61;
			}
		status = writeCharacterString( stream, dnString, dnStringLength,
									   dnComponentPtr->asn1EncodedStringType );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}
#endif /* USE_CERTIFICATES */
