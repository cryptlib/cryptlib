/****************************************************************************
*																			*
*					Certificate DN String Read/Write Routines				*
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

/* The ability to specify free-form DNs means that users can create 
   arbitrarily garbled and broken DNs (the creation of weird nonstandard DNs 
   is pretty much the main reason why the DN-string capability exists).  
   This includes DNs that can't be easily handled through normal cryptlib 
   facilities, for example ones where the CN component consists of illegal 
   characters or is in a form that isn't usable as a search key for 
   functions like cryptGetPublicKey().  Because of these problems this 
   functionality is disabled by default, if users want to use this oddball-
   DN facility it's up to them to make sure that the resulting DN 
   information works with whatever environment they're intending to use it 
   in */

#if defined( USE_CERTIFICATES ) && defined( USE_CERT_DNSTRING )

#if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
  #pragma message( "  Building with string-form DNs enabled." )
#endif /* Warn about special features enabled */

/****************************************************************************
*																			*
*							Read a String-form DN							*
*																			*
****************************************************************************/

/* Check whether a string can be represented as a textual DN string */

static BOOLEAN isTextString( IN_BUFFER( stringLength ) const BYTE *string, 
							 IN_LENGTH_ATTRIBUTE const int stringLength )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( string, stringLength ) );

	REQUIRES_B( stringLength > 0 && stringLength <= MAX_ATTRIBUTE_SIZE );

	/* Make sure that there are no control characters in the string.  We 
	   allow high-bit-set characters in order to support latin-1 strings,
	   see also the comment at the start of this section about the general
	   caveat-emptor philosophy for this interface */
	LOOP_LARGE( i = 0, i < stringLength, i++ )
		{
		ENSURES_B( LOOP_INVARIANT_LARGE( i, 0, stringLength - 1 ) );

		if( ( string[ i ] & 0x7F ) < ' ' )
			return( FALSE );
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( TRUE );
	}

/* Read a DN in string form */

typedef struct {
	BUFFER_FIXED( labelLen ) \
	const BYTE *label;
	BUFFER_FIXED( textLen ) \
	const BYTE *text;
	int labelLen, textLen;	/* DN component label and value */
	BOOLEAN isContinued;	/* Whether there are further AVAs in this RDN */
	} DN_STRING_INFO;

#define MAX_DNSTRING_COMPONENTS 32

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static BOOLEAN parseDNString( OUT_ARRAY( MAX_DNSTRING_COMPONENTS ) \
									DN_STRING_INFO *dnStringInfo,
							  OUT_RANGE( 0, MAX_DNSTRING_COMPONENTS ) \
									int *dnStringInfoIndex,
							  IN_BUFFER( stringLength ) const BYTE *string, 
							  IN_LENGTH_ATTRIBUTE const int stringLength )
	{
	int stringPos;
	LOOP_INDEX stringInfoIndex;

	assert( isWritePtr( dnStringInfo, sizeof( DN_STRING_INFO ) * \
									  MAX_DNSTRING_COMPONENTS ) );
	assert( isReadPtrDynamic( string, stringLength ) );

	REQUIRES_B( stringLength > 0 && stringLength <= MAX_ATTRIBUTE_SIZE );

	/* Clear return values */
	memset( dnStringInfo, 0,
			sizeof( DN_STRING_INFO ) * MAX_DNSTRING_COMPONENTS );
	*dnStringInfoIndex = 0;

	/* Make sure that the string is can be rendered as a text string */
	if( !isTextString( string, stringLength ) )
		return( FALSE );

	/* Verify that a DN string is of the form:

		dnString ::= assignment '\0' | assignment ',' assignment
		assignment ::= label '=' text */
	LOOP_EXT( ( stringPos = 0, stringInfoIndex = 0 ),
			  stringPos < stringLength && \
				stringInfoIndex < MAX_DNSTRING_COMPONENTS, 
			  stringInfoIndex++, MAX_DNSTRING_COMPONENTS + 1 )
		{
		DN_STRING_INFO *dnStringInfoPtr = &dnStringInfo[ stringInfoIndex ];
		LOOP_INDEX_ALT i;

		ENSURES_B( LOOP_INVARIANT_EXT( stringInfoIndex, 0, 
									   MAX_DNSTRING_COMPONENTS - 1,
									   MAX_DNSTRING_COMPONENTS + 1 ) );
		ENSURES_B( LOOP_INVARIANT_SECONDARY( stringPos, 0, stringLength - 1 ) );

		/* Check for label '=' ... */
		LOOP_LARGE_ALT( i = stringPos, i < stringLength, i++ )
			{
			int ch;

			ENSURES_B( LOOP_INVARIANT_LARGE_ALT( i, stringPos, 
												 stringLength - 1 ) );

			ch = byteToInt( string[ i ] );
			if( ch == '\\' || ch == '+' || ch == ',' )
				{
				/* The label component can't have special characters in it */
				return( FALSE );
				}
			if( ch == '=' )
				break;
			}
		ENSURES_B( LOOP_BOUND_OK_ALT );
		if( i <= stringPos || i >= stringLength - 1 )	/* -1 for '=' */
			{
			/* The label component is empty */
			return( FALSE );
			}
		ENSURES_B( boundsCheckZ( stringPos, i - stringPos, stringLength ) );
		dnStringInfoPtr->label = string + stringPos;
		dnStringInfoPtr->labelLen = i - stringPos;
		stringPos = i + 1;		/* Skip text + '=' */

		/* Check for ... text { EOT | ',' ... | '+' ... } */
		LOOP_LARGE_ALT( i = stringPos, 
						i < stringLength && i < MAX_ATTRIBUTE_SIZE,
						i++ /* Also incremented in loop body */ )
			{
			int ch;

			ENSURES_B( LOOP_INVARIANT_LARGE_XXX_ALT( i, 0, stringLength - 1 ) );
					   /* i may skip additional characters due to escapes */

			/* Check for invalid data */
			ch = byteToInt( string[ i ] );
			if( ch == '=' )
				{
				/* Spurious '=' */
				return( FALSE );
				}
			if( ch == '\\' )
				{
				if( i >= stringLength - 1 )
					{
					/* Missing escaped character */
					return( FALSE );
					}

				/* It's an escaped character that isn't subject to the usual
				   checks, skip it and continue */
				i++;
				continue;
				}

			/* If this isn't a continuation symbol, continue */
			if( ch != ',' && ch != '+' )
				continue;

			/* We've reached a continuation symbol, make sure that there's 
			   room for at least another 'x=y' after this point */
			if( i >= stringLength - 3 )
				return( FALSE );

			break;
			}
		ENSURES_B( LOOP_BOUND_OK );
		ENSURES_B( boundsCheck( stringPos, i - stringPos, stringLength ) );
		dnStringInfoPtr->text = string + stringPos;
		dnStringInfoPtr->textLen = i - stringPos;
		if( string[ i ] == ',' || string[ i ] == '+' )
			{
			/* Skip the final ',' or '+' and remember whether this is a 
			   continued RDN */
			if( string[ i ] == '+' )
				dnStringInfoPtr->isContinued = TRUE;
			i++;
			}
		stringPos = i;			/* Skip text + optional ','/'+' */

		/* Strip leading and trailing whitespace on the label and text */
		dnStringInfoPtr->labelLen = \
				strStripWhitespace( ( const char ** ) &dnStringInfoPtr->label,
									dnStringInfoPtr->label, 
									dnStringInfoPtr->labelLen );
		dnStringInfoPtr->textLen = \
				strStripWhitespace( ( const char ** ) &dnStringInfoPtr->text,
									dnStringInfoPtr->text, 
									dnStringInfoPtr->textLen );
		if( dnStringInfoPtr->labelLen < 1 || \
			dnStringInfoPtr->labelLen > MAX_ATTRIBUTE_SIZE || \
			dnStringInfoPtr->textLen < 1 || \
			dnStringInfoPtr->textLen > MAX_ATTRIBUTE_SIZE )
			return( FALSE );
		}
	ENSURES_B( LOOP_BOUND_OK );
	if( stringInfoIndex <= 0 || stringInfoIndex >= MAX_DNSTRING_COMPONENTS )
		return( FALSE );
	*dnStringInfoIndex = stringInfoIndex;

	return( TRUE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readDNstring( INOUT_PTR_DATAPTR DATAPTR_DN *dnPtr,
				  IN_BUFFER( stringLength ) const BYTE *string, 
				  IN_LENGTH_ATTRIBUTE const int stringLength )
	{
	DN_STRING_INFO dnStringInfo[ MAX_DNSTRING_COMPONENTS + 8 ];
	DATAPTR_DN dn;
	DN_COMPONENT *dnComponentList = NULL, *dnComponentListCursor;
	int stringInfoIndex, LOOP_ITERATOR;

	assert( isWritePtr( dnPtr, sizeof( DATAPTR_DN ) ) );
	assert( isReadPtrDynamic( string, stringLength ) );

	REQUIRES( stringLength > 0 && stringLength <= MAX_ATTRIBUTE_SIZE );

	/* Clear return value */
	DATAPTR_SET_PTR( dnPtr, NULL );

	/* We have to perform the text string to DN translation in two stages
	   thanks to the backwards encoding required by RFC 1779.  First we 
	   parse it forwards to separate out the RDN components, then we move 
	   through the parsed information backwards adding it to the RDN (with 
	   special handling for multi-AVA RDNs as for writeDNstring()).  Overall 
	   this isn't so bad because it means that we can perform a general 
	   firewall check to make sure that the DN string is well-formed and 
	   then leave the decoding as a separate pass */
	if( !parseDNString( dnStringInfo, &stringInfoIndex, string, 
						stringLength ) )
		return( CRYPT_ARGERROR_STR1 );

	/* parseDNString() returns the number of entries parsed, since we're
	   using zero-based indexing we have to decrement the value returned to
	   provide the actual index into the dnStringInfo[] array */
	stringInfoIndex--;

	DATAPTR_SET( dn, NULL );
	LOOP_MED_REV_CHECKINC( stringInfoIndex >= 0, stringInfoIndex-- )
		{
		const DN_STRING_INFO *dnStringInfoPtr;
		BOOLEAN isContinued = TRUE;
		int LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_MED_REV_XXX( stringInfoIndex, 0, 
											 MAX_DNSTRING_COMPONENTS ) );

		/* Find the start of the RDN */
		LOOP_MED_REV_CHECKINC_ALT( stringInfoIndex > 0 && \
									dnStringInfo[ stringInfoIndex - 1 ].isContinued,
								   stringInfoIndex-- )
			{
			ENSURES( LOOP_INVARIANT_MED_REV_XXX_ALT( stringInfoIndex, 1, 
													 MAX_DNSTRING_COMPONENTS ) );
			}
		ENSURES( LOOP_BOUND_MED_REV_OK_ALT );
		dnStringInfoPtr = &dnStringInfo[ stringInfoIndex ];

		LOOP_MED_WHILE_ALT( isContinued )
			{
			CRYPT_ERRTYPE_TYPE dummy;
			const DN_COMPONENT_INFO *dnComponentInfo;
			ERROR_INFO localErrorInfo;
			BYTE textBuffer[ MAX_ATTRIBUTE_SIZE + 8 ];
			CRYPT_ATTRIBUTE_TYPE type;
			LOOP_INDEX_ALT2 i;
			int textIndex = 0, valueStringType, dummy1, dummy2, status;

			ENSURES( LOOP_INVARIANT_MED_ALT_GENERIC() );

			/* Look up the DN component information */
			dnComponentInfo = findDNInfoByLabel( dnStringInfoPtr->label, 
												 dnStringInfoPtr->labelLen );
			if( dnComponentInfo == NULL )
				{
				if( DATAPTR_ISSET( dn ) )
					deleteDN( &dn );
				return( CRYPT_ARGERROR_STR1 );
				}
			type = dnComponentInfo->type;

			/* Convert the text to canonical form, removing any escapes for
			   special characters */
			LOOP_EXT_ALT2( i = 0, i < dnStringInfoPtr->textLen, 
						   i++ /* Also incremented in loop body */,
						   MAX_ATTRIBUTE_SIZE )
				{
				int ch;

				ENSURES( LOOP_INVARIANT_EXT_XXX_ALT2( i, 0, 
													  dnStringInfoPtr->textLen - 1,
													  MAX_ATTRIBUTE_SIZE ) );
						 /* i may skip additional characters due to escapes */

				ch = byteToInt( dnStringInfoPtr->text[ i ] );
				if( ch == '\\' )
					{
					/* Skip '\\' */
					i++;
					if( i >= dnStringInfoPtr->textLen )
						{
						if( DATAPTR_ISSET( dn ) )
							deleteDN( &dn );
						return( CRYPT_ARGERROR_STR1 );
						}
					ch = byteToInt( dnStringInfoPtr->text[ i ] );
					}
				textBuffer[ textIndex++ ] = intToByte( ch );
				}
			ENSURES( LOOP_BOUND_OK_ALT2 );
			ENSURES( isShortIntegerRangeNZ( textIndex ) );

			/* The value is coming from an external source, make sure that 
			   it's representable as a certificate string type.  All that 
			   we care about here is the validity so we ignore the returned 
			   encoding information */
			status = getAsn1StringInfo( textBuffer, textIndex, 
										&valueStringType, &dummy1, &dummy2, 
										FALSE );
			if( cryptStatusError( status ) )
				{
				if( DATAPTR_ISSET( dn ) )
					deleteDN( &dn );
				return( CRYPT_ARGERROR_STR1 );
				}

			/* Add the AVA to the DN.  Since this is a low-level operation 
			   there isn't any useful additional error information to 
			   return */
			clearErrorInfo( &localErrorInfo );
			if( type == CRYPT_CERTINFO_COUNTRYNAME )
				{
				/* If it's a country code force it to uppercase as per ISO 
				   3166 */
				if( textIndex != 2 )
					{
					if( DATAPTR_ISSET( dn ) )
						deleteDN( &dn );
					return( CRYPT_ARGERROR_STR1 );
					}
				textBuffer[ 0 ] = intToByte( toUpper( textBuffer[ 0 ] ) );
				textBuffer[ 1 ] = intToByte( toUpper( textBuffer[ 1 ] ) );
				}
			status = insertDNstring( &dn, type, textBuffer, textIndex, 
									 valueStringType,
									 ( dnStringInfoPtr->isContinued ) ? \
										DN_FLAG_CONTINUED | DN_FLAG_NOCHECK :
										DN_FLAG_NOCHECK, &localErrorInfo, 
										&dummy );
			if( cryptStatusError( status ) )
				{
				if( DATAPTR_ISSET( dn ) )
					deleteDN( &dn );
				return( status );
				}

			/* Move on to the next AVA */
			isContinued = dnStringInfoPtr->isContinued;
			dnStringInfoPtr++;
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		}
	ENSURES( LOOP_BOUND_MED_REV_OK );

	/* We're done, lock the DN against further updates */
	LOOP_LARGE( dnComponentListCursor = dnComponentList,
				dnComponentListCursor != NULL,
				dnComponentListCursor = DATAPTR_GET( dnComponentListCursor->next ) )
		{
		REQUIRES( sanityCheckDNComponent( dnComponentListCursor ) );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		SET_FLAG( dnComponentListCursor->flags, DN_FLAG_LOCKED );
		}
	ENSURES( LOOP_BOUND_OK );

	/* Copy the local copy of the DN back to the caller */
	*dnPtr = dn;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Write a String-form DN							*
*																			*
****************************************************************************/

/* Write a DN in string form */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeAVAString( INOUT_PTR STREAM *stream,
						   const DN_COMPONENT *dnComponentPtr )
	{
	const DN_COMPONENT_INFO *componentInfoPtr = dnComponentPtr->typeInfo;
	LOOP_INDEX i;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( dnComponentPtr, sizeof( DN_COMPONENT ) ) );

	REQUIRES( sanityCheckDNComponent( dnComponentPtr ) );

	/* Print the current AVA */
	swrite( stream, componentInfoPtr->name, componentInfoPtr->nameLen );
	status = sputc( stream, '=' );
	if( cryptStatusError( status ) )
		return( status );
	LOOP_LARGE( i = 0, i < dnComponentPtr->valueLength, i++ )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, dnComponentPtr->valueLength - 1 ) );

		ch = byteToInt( ( ( BYTE * ) dnComponentPtr->value )[ i ] );
		if( ch == ',' || ch == '=' || ch == '+' || ch == ';' || \
			ch == '\\' || ch == '"' )
			{
			sputc( stream, '\\' );
			}
		status = sputc( stream, ch );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeDNstring( INOUT_PTR STREAM *stream, 
				   const DATAPTR_DN dn )
	{
	const DN_COMPONENT *prevElementPtr;
	LOOP_INDEX_PTR const DN_COMPONENT *dnComponentListPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( DATAPTR_ISVALID( dn ) );

	/* Special case for empty DNs */
	if( DATAPTR_ISNULL( dn ) )
		return( CRYPT_OK );

	dnComponentListPtr = DATAPTR_GET( dn );
	ENSURES( dnComponentListPtr != NULL );
	REQUIRES( sanityCheckDNComponent( dnComponentListPtr ) );

	/* Find the end of the DN string.  We have to print the RDNs backwards
	   because of ISODE's JANET memorial backwards encoding.  This also 
	   provides a convenient location to check that the DN data is actually
	   representable as a text string.

	   Some string types can't be represented as text strings which means 
	   that we can't send them directly to the output.  The details of what 
	   to do here are a bit complex, in theory we could send them out as 
	   UTF-8 but few environments are going to expect this as a returned 
	   type, particularly when the existing expectation is for oddball 
	   characters in text strings to be latin-1.  The least ugly solution 
	   seems to be to just return an indicator that this string can't be 
	   represented */
	LOOP_MED( prevElementPtr = dnComponentListPtr,
			  dnComponentListPtr != NULL,
			  ( prevElementPtr = dnComponentListPtr,
				dnComponentListPtr = DATAPTR_GET( dnComponentListPtr->next ) ) )
		{
		REQUIRES( sanityCheckDNComponent( dnComponentListPtr ) );

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* Make sure that the DN component is representable as a text 
		   string.  Exactly what we should return if this check fails is a
		   bit uncertain since there's no error code that it really
		   corresponds to, CRYPT_ERROR_NOTAVAIL appears to be the least
		   inappropriate one to use.
		   
		   An alternative is to return a special-case string like "(DN 
		   can't be represented in string form)" but this then looks (from 
		   the return status) as if it was actually representable, requiring 
		   special-case checks for valid-but-not-valid returned data, so the 
		   error status is probably the best option */
		if( !isTextString( dnComponentListPtr->value, 
						   dnComponentListPtr->valueLength ) )
			return( CRYPT_ERROR_NOTAVAIL );
		}
	ENSURES( LOOP_BOUND_OK );

	LOOP_MED_INITCHECK( dnComponentListPtr = prevElementPtr, 
						dnComponentListPtr != NULL )
		{
		const DN_COMPONENT *dnComponentCursor, *dnComponentPrev;
		LOOP_INDEX_ALT i;

		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		/* Find the start of the RDN */
		LOOP_MED_ALT( dnComponentPrev = DATAPTR_GET( dnComponentListPtr->prev ),
					  dnComponentPrev != NULL && \
							TEST_FLAG( dnComponentPrev->flags, DN_FLAG_CONTINUED ),
					  ( dnComponentListPtr = dnComponentPrev,
							dnComponentPrev = DATAPTR_GET( dnComponentPrev->prev ) ) )
			{
			ENSURES( LOOP_INVARIANT_MED_ALT_GENERIC() );
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		dnComponentCursor = dnComponentListPtr;
		dnComponentListPtr = dnComponentPrev;

		/* Print the current RDN.  The loop checks and controls are 
		   sufficiently non-amenable to implementation as a standard loop 
		   that we just use a dummy counter i that guarantees that the loop 
		   is double-indexed */
		LOOP_MED_ALT( i = 0, i < 50, i++ )
			{
			ENSURES( LOOP_INVARIANT_MED_ALT( i, 0, 49 ) );

			status = writeAVAString( stream, dnComponentCursor );
			if( cryptStatusError( status ) )
				return( status );

			/* If this is the last AVA in the RDN, we're done */
			if( !TEST_FLAG( dnComponentCursor->flags, DN_FLAG_CONTINUED ) )
				break;

			/* There are more AVAs in this RDN, print a continuation 
			   indicator and move on to the next AVA */
			status = swrite( stream, " + ", 3 );
			if( cryptStatusError( status ) )
				return( status );
			dnComponentCursor = DATAPTR_GET( dnComponentCursor->next );
			ENSURES( dnComponentCursor != NULL );
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		ENSURES( i < 50 );

		/* If there are more components to come print an RDN separator */
		if( dnComponentListPtr != NULL )
			{
			status = swrite( stream, ", ", 2 );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}
#endif /* USE_CERTIFICATES && USE_CERT_DNSTRING */

