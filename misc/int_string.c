/****************************************************************************
*																			*
*						  cryptlib Internal String API						*
*						Copyright Peter Gutmann 1992-2025					*
*																			*
****************************************************************************/

#include "crypt.h"

/****************************************************************************
*																			*
*						General-purpose String Functions					*
*																			*
****************************************************************************/

/* Perform various string-processing operations */

CHECK_RETVAL_STRINGOP STDC_NONNULL_ARG( ( 1 ) ) \
int strFindCh( IN_BUFFER( strLen ) const char *str, 
			   IN_LENGTH_SHORT const int strLen, 
			   IN_CHAR const int findCh )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( str, strLen ) );

	REQUIRES_EXT( isShortIntegerRangeNZ( strLen ), -1 );
	REQUIRES_EXT( findCh >= 0 && findCh <= 0x7F, -1 );

	LOOP_MAX( i = 0, i < strLen, i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, strLen - 1 ), -1 );

		if( str[ i ] == findCh )
			return( i );
		}
	ENSURES_EXT( LOOP_BOUND_OK, -1 );

	return( -1 );
	}

CHECK_RETVAL_STRINGOP STDC_NONNULL_ARG( ( 1, 3 ) ) \
int strFindStr( IN_BUFFER( strLen ) const char *str, 
				IN_LENGTH_SHORT const int strLen, 
				IN_BUFFER( findStrLen ) const char *findStr, 
				IN_LENGTH_SHORT const int findStrLen )
	{
	int findCh;
	LOOP_INDEX i;

	assert( isReadPtrDynamic( str, strLen ) );
	assert( isReadPtrDynamic( findStr, findStrLen ) );

	REQUIRES_EXT( isShortIntegerRangeNZ( strLen ), -1 );
	REQUIRES_EXT( isShortIntegerRangeNZ( findStrLen ), -1 );

	/* If the string to find is larger than the string being searched, we 
	   can never have a match */
	if( findStrLen > strLen )
		return( -1 );

	/* Get the first character of the search string for a quick-reject 
	   match */
	findCh = toUpper( byteToInt( findStr[ 0 ] ) );
	REQUIRES_EXT( findCh >= 0 && findCh <= 0x7F, -1 );

	LOOP_MAX( i = 0, i <= strLen - findStrLen, i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, strLen - findStrLen ), -1 );

		if( toUpper( byteToInt( str[ i ] ) ) == findCh && \
			strSame( str + i, findStr, findStrLen ) )
			return( i );
		}
	ENSURES_EXT( LOOP_BOUND_OK, -1 );

	return( -1 );
	}

CHECK_RETVAL_STRINGOP STDC_NONNULL_ARG( ( 1, 3 ) ) \
int strFilter( IN_BUFFER( strLen ) const char *str,
			   IN_LENGTH_SHORT const int strLen,
			   IN_BUFFER( filterStrLen ) const char *filterStr,
			   IN_LENGTH_SHORT const int filterStrLen )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( str, strLen ) );
	assert( isReadPtrDynamic( filterStr, filterStrLen ) );

	REQUIRES_EXT( rangeCheck( strLen, 1, 512 ), 0 );
	REQUIRES_EXT( rangeCheck( filterStrLen, 1, 32 ), 0 );

	/* Search through str looking for the presence of any character in
	   filterStr.  This is an n^2 algorithm but both strings are short,
	   filterStr in particular being only a handful of characters */
	LOOP_LARGE( i = 0, i < strLen, i++ )
		{
		LOOP_INDEX_ALT j;

		ENSURES_EXT( LOOP_INVARIANT_LARGE( i, 0, strLen - 1 ), 0 );

		LOOP_MED_ALT( j = 0, j < filterStrLen, j++ )
			{
			ENSURES_EXT( LOOP_INVARIANT_MED_ALT( j, 0, \
												 filterStrLen - 1 ), 0 );

			if( str[ i ] == filterStr[ j ] )
				return( i );
			}
		ENSURES_EXT( LOOP_BOUND_OK_ALT, 0 );
		}
	ENSURES_EXT( LOOP_BOUND_OK, 0 );

	/* No excluded character present */
	return( -1 );
	}

CHECK_RETVAL_STRINGOP STDC_NONNULL_ARG( ( 1 ) ) \
int strSkipWhitespace( IN_BUFFER( strLen ) const char *str, 
					   IN_LENGTH_SHORT const int strLen )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( str, strLen ) );

	REQUIRES_EXT( isShortIntegerRangeNZ( strLen ), -1 );

	LOOP_MAX( i = 0, 
			  i < strLen && ( str[ i ] == ' ' || str[ i ] == '\t' ), 
			  i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, strLen - 1 ), -1 );
		}
	ENSURES_EXT( LOOP_BOUND_OK, -1 );

	return( ( i < strLen ) ? i : -1 );
	}

CHECK_RETVAL_STRINGOP STDC_NONNULL_ARG( ( 1 ) ) \
int strSkipNonWhitespace( IN_BUFFER( strLen ) const char *str, 
						  IN_LENGTH_SHORT const int strLen )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( str, strLen ) );

	REQUIRES_EXT( isShortIntegerRangeNZ( strLen ), -1 );

	/* This differs slightly from strSkipWhitespace() in that EOL is also 
	   counted as whitespace so there's never an error condition unless
	   we don't find anything at all */
	LOOP_MAX( i = 0, 
			  i < strLen && str[ i ] != ' ' && str[ i ] != '\t', 
			  i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, strLen - 1 ), -1 );
		}
	ENSURES_EXT( LOOP_BOUND_OK, -1 );

	return( i > 0 ? i : -1 );
	}

CHECK_RETVAL_STRINGOP STDC_NONNULL_ARG( ( 1, 2 ) ) \
int strStripWhitespace( OUT_PTR_PTR_COND const char **newStringPtr, 
						IN_BUFFER( strLen ) const char *string, 
						IN_LENGTH_SHORT const int strLen )
	{
	LOOP_INDEX startPos;
	int endPos;

	assert( isReadPtr( newStringPtr, sizeof( char * ) ) );
	assert( isReadPtrDynamic( string, strLen ) );

	REQUIRES_EXT( isShortIntegerRangeNZ( strLen ), -1 );

	/* Clear return value */
	*newStringPtr = NULL;

	/* Skip leading and trailing whitespace.  We also count nulls as 
	   trailing "whitespace" because some lower-level drivers and libraries 
	   that we talk to may pad out buffers with nulls on the assumption 
	   that the caller is using strlen() to find the end of the string in
	   them */
	LOOP_MAX( startPos = 0,
			  startPos < strLen && \
				( string[ startPos ] == ' ' || string[ startPos ] == '\t' ),
			  startPos++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX( startPos, 0, strLen - 1 ), -1 );
		}
	ENSURES_EXT( LOOP_BOUND_OK, -1 );
	if( startPos >= strLen )
		return( -1 );
	if( string[ startPos ] == '\0' )
		{
		/* We're about to walk backwards through the string looking for, 
		   among other things, a '\0', so we can't be starting the string
		   at a '\0' both because we don't allow it as leading "whitespace" 
		   and because, worst-case, it could lead to an empty string if
		   there's only more whitespace following it */
		return( -1 );
		}
	ENSURES_EXT( rangeCheck( startPos, 0, strLen - 1 ), -1 );
	LOOP_MAX_REV( endPos = strLen,
				  endPos > startPos && \
					( string[ endPos - 1 ] == ' ' || \
					  string[ endPos - 1 ] == '\t' || \
					  string[ endPos - 1 ] == '\0' ),
				  endPos-- )
		{
		ENSURES_EXT( LOOP_INVARIANT_REV( endPos, startPos + 1, strLen ), -1 );
		}
	ENSURES_EXT( LOOP_BOUND_MAX_REV_OK, -1 );

	ENSURES_EXT( !checkOverflowSub( endPos, startPos ), -1 );
	ENSURES_EXT( rangeCheck( endPos - startPos, 1, strLen ), -1 );

	*newStringPtr = string + startPos;
	return( endPos - startPos );
	}

/****************************************************************************
*																			*
*						Special-purpose String Functions					*
*																			*
****************************************************************************/

/* Extract a substring from a string.  This converts:

	 string				startOffset							 strLen
		|					|									|
		v					v									v
		+-------------------+---------------+-------------------+
		|	Processed data	|	Whitespace	|	Remaining data	|
		+-------------------+---------------+-------------------+

   into:

	 newStr				 length
		|					|
		v					v
		+-------------------+
		|	Remaining data	|
		+-------------------+ 

   The order of the parameters is a bit unusual, normally we'd use 
   { str, strLen } but this makes things a bit confusing for the caller, for
   whom it's more logical to group the parameters based on the overall
   operation being performed, which to extract a substring beginning at
   startOffset is { str, startOffset, strLen } */

CHECK_RETVAL_STRINGOP STDC_NONNULL_ARG( ( 1, 2 ) ) \
int strExtract( OUT_PTR_PTR_COND const char **newStringPtr, 
				IN_BUFFER( strLen ) const char *string,
				IN_LENGTH_SHORT_Z const int startOffset,
				IN_LENGTH_SHORT const int strLen )
	{
	const int newLen = strLen - startOffset;

	assert( isReadPtr( newStringPtr, sizeof( char * ) ) );
	assert( isReadPtrDynamic( string, strLen ) );

	REQUIRES_EXT( !checkOverflowSub( strLen, startOffset ), -1 );
	REQUIRES_EXT( isShortIntegerRangeNZ( strLen ), -1 );
	REQUIRES_EXT( isShortIntegerRange( startOffset ) && \
				  startOffset <= strLen, -1 );
				  /* May be zero if we're extracting from the start of the 
				     string; may be equal to strLen if it's the entire
					 remaining string */

	/* Clear return value */
	*newStringPtr = NULL;

	if( !isShortIntegerRangeNZ( newLen ) || newLen > strLen )
		return( -1 );
	return( strStripWhitespace( newStringPtr, string + startOffset, newLen ) );
	}

/* Parse a numeric or hex string into an integer value.  There are two 
   variants of this, one which processes a fixed-length string and one which
   parses the value out of a longer string and processes that.

   Safe conversion of a numeric string gets a bit problematic because atoi() 
   can't indicate an error except by returning 0, which is indistinguishable 
   from a zero numeric value.  To handle this we have to perform the 
   conversion ourselves */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int strGetNumeric( IN_BUFFER( strLen ) const char *str, 
				   IN_LENGTH_SHORT const int strLen, 
				   OUT_INT_Z int *numericValue, 
				   IN_RANGE( 0, 100 ) const int minValue, 
				   IN_RANGE( minValue, MAX_INTLENGTH ) const int maxValue )
	{
	LOOP_INDEX i;
	int value;

	assert( isReadPtrDynamic( str, strLen ) );
	assert( isWritePtr( numericValue, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeNZ( strLen ) );
	REQUIRES( minValue >= 0 && minValue < maxValue && \
			  maxValue <= MAX_INTLENGTH );

	/* Clear return value */
	*numericValue = 0;

	/* Make sure that the value is within the range 'n' ... 'nnnnnnn' */
	if( strLen < 1 || strLen > 7 )
		return( CRYPT_ERROR_BADDATA );

	/* Process the numeric string.  The second checkOverflowAdd() isn't 
	   really necessary because we know that value < MAX_INTLENGTH / 10, 
	   which means that value <= MAX_INTLENGTH / 10 - 1, so 
	   value * 10 <= MAX_INTLENGTH - 10, therefore 
	   value * 10 < MAX_INTLENGTH - 9, so value * 10 < MAX_INTLENGTH - ch, 
	   however we leave it in to make the condition explicit and because the 
	   more checks we have the harder it is for gcc to find an excuse to 
	   remove them (see the comments in the checkOverflowXYZ() functions in 
	   misc/safety.h) */
	LOOP_SMALL( ( i = 0, value = 0 ), i < strLen, i++ )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_SMALL( i, 0, strLen - 1 ) );

		ch = byteToInt( str[ i ] ) - '0';
		if( ch < 0 || ch > 9 )
			return( CRYPT_ERROR_BADDATA );
		if( checkOverflowMul( value, 10 ) )
			return( CRYPT_ERROR_BADDATA );
		value *= 10;
		if( checkOverflowAdd( value, ch ) )
			return( CRYPT_ERROR_BADDATA );
		value += ch;
		if( !isIntegerRange( value ) )
			return( CRYPT_ERROR_BADDATA );
		}
	ENSURES( LOOP_BOUND_OK );

	/* Make sure that the final value is within the specified range */
	if( value < minValue || value > maxValue )
		return( CRYPT_ERROR_BADDATA );

	*numericValue = value;
	return( CRYPT_OK );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 3 ) ) \
int strParseNumeric( IN_BUFFER( strMaxLen ) const char *str, 
					 IN_LENGTH_SHORT const int strMaxLen, 
					 OUT_INT_Z int *numericValue, 
					 IN_RANGE( 0, 100 ) const int minValue, 
					 IN_RANGE( minValue, MAX_INTLENGTH ) const int maxValue )
	{
	LOOP_INDEX numericStrLen;
	int status;
	
	assert( isReadPtrDynamic( str, strMaxLen ) );
	assert( isWritePtr( numericValue, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeNZ( strMaxLen ) );
	REQUIRES( minValue >= 0 && minValue < maxValue && \
			  maxValue <= MAX_INTLENGTH );

	/* Clear return value */
	*numericValue = 0;

	/* Figure out which substring portion of the string is the numeric 
	   value.  We limit the number of characters that we handle to 5, 
	   regardless of the size of the input string, because we should never 
	   be dealing with more than that many digits in a string */
	LOOP_SMALL( numericStrLen = 0, 
				numericStrLen < strMaxLen && numericStrLen < 6 && \
					isDigit( byteToInt( str[ numericStrLen ] ) ),
				numericStrLen++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( numericStrLen, 0, strMaxLen - 1 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	if( numericStrLen < 1 || numericStrLen > 5 )
		return( CRYPT_ERROR_BADDATA );

	/* Process the extracted numeric string */
	status = strGetNumeric( str, numericStrLen, numericValue, minValue, 
							maxValue );
	if( cryptStatusError( status ) )
		return( status );

	/* Let the caller know how much of the string we processed */
	return( numericStrLen );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int strGetHex( IN_BUFFER( strLen ) const char *str, 
			   IN_LENGTH_SHORT const int strLen, 
			   OUT_INT_Z int *numericValue, 
			   IN_RANGE( 0, 100 ) const int minValue, 
			   IN_RANGE( minValue, 0xFFFF ) const int maxValue )
	{
	const int strMaxLen = ( maxValue > 0xFFF ) ? 4 : \
						  ( maxValue > 0xFF ) ? 3 : \
						  ( maxValue > 0xF ) ? 2 : 1;
	LOOP_INDEX digitIndex;
	int value = 0;

	assert( isReadPtrDynamic( str, strLen ) );
	assert( isWritePtr( numericValue, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeNZ( strLen ) );
	REQUIRES( minValue >= 0 && minValue < maxValue && maxValue <= 0xFFFF );

	/* Clear return value */
	*numericValue = 0;

	/* Make sure that the length is sensible for the value that we're 
	   reading */
	if( strLen < 1 || strLen > strMaxLen )
		return( CRYPT_ERROR_BADDATA );

	/* Process the numeric string.  We don't have to perform the same level 
	   of overflow checking as we do in strGetNumeric() because the maximum
	   value is capped to fit into an int.
	   
	   The 'digitIndex < 4' check in the loop is redundant since we've 
	   already checked it via the code flow that leads to the comparison to
	   strMaxLen, it's included below to make it explicit what the hard
	   limit is */
	LOOP_SMALL( digitIndex = 0, digitIndex < strLen && \
								digitIndex < 4, digitIndex++ )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_SMALL( digitIndex, 0, strLen - 1 ) );
	
		ch = toLower( byteToInt( str[ digitIndex ] ) );
		if( !isXDigit( ch ) || checkOverflowShift( value, 4 ) )
			return( CRYPT_ERROR_BADDATA );
		value = ( value << 4 ) | \
				( ( ch <= '9' ) ? ch - '0' : ch - ( 'a' - 10 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	if( digitIndex > 4 || value < minValue || value > maxValue )
		return( CRYPT_ERROR_BADDATA );

	*numericValue = value;

	return( CRYPT_OK );
	}

/* Determine whether a string is printable or not, used when checking whether
   it should be displayed to the caller as a text string or a hex dump */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN strIsPrintable( IN_BUFFER( strLen ) const void *str, 
						IN_LENGTH_SHORT const int strLen )
	{
	const BYTE *strPtr = str;
	LOOP_INDEX i;

	assert( isReadPtrDynamic( str, strLen ) );

	REQUIRES_B( isShortIntegerRangeNZ( strLen ) );

	LOOP_MAX( i = 0, i < strLen, i++ )
		{
		int ch;

		ENSURES_B( LOOP_INVARIANT_MAX( i, 0, strLen - 1 ) );

		ch = byteToInt( strPtr[ i ] );
		if( !isValidTextChar( ch ) )
			return( FALSE );
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( TRUE );
	}

/* Sanitise a string before passing it back to the user.  This is used to
   clear potential problem characters (for example control characters)
   from strings passed back from untrusted sources (nec verbum verbo 
   curabis reddere fidus interpres - Horace).
   
   This function assumes that the string is in ASCII form rather than some
   exotic character set, since this is used for processing text error
   messages sent to us by remote systems we can reasonably assume that 
   they should be be, well, text error messages so that we're within our
   rights to filter out non-text data.
   
   The function returns a pointer to the string to allow it to be used in 
   the form printf( "..%s..", sanitiseString( string, strLen ) ).  In 
   addition it formats the data to fit a fixed-length buffer, if the string 
   is longer than the indicated buffer size then it appends a '[...]' at the 
   end of the buffer to indicate that further data was truncated.   The 
   transformation applied is as follows:

	  buffer					strMaxLen
		|							|
		v							v
		+---------------------------+		.								.
		|							|  ==>	.								.
		+---------------------------+		.								.
		.							.		.								.
		|---------------|			.		|---------------|\0|			.
		.				^			.		.								.
		|--------------------------------|	|-----------------------|[...]\0|
						|				 ^
						+---- strLen ----+

   so "Error string of arbitrary length..." with a buffer size of 20 would 
   become "Error string o[...]" */

STDC_NONNULL_ARG( ( 1 ) ) \
char *sanitiseString( INOUT_BUFFER_FIXED( strMaxLen ) void *string, 
					  IN_LENGTH_SHORT const int strMaxLen, 
					  IN_LENGTH_SHORT const int strLen )
	{
	BYTE *strPtr = string;	/* See comment below */
	const int strDataLen = min( strLen, strMaxLen );
	LOOP_INDEX i;

	assert( isWritePtrDynamic( string, strMaxLen ) );

	REQUIRES_EXT( isShortIntegerRangeNZ( strLen ), "(Internal error)" );
	REQUIRES_EXT( isShortIntegerRangeNZ( strMaxLen ), "(Internal error)" );

	/* Remove any potentially unsafe characters from the string, effectively
	   converting it from a 'BYTE *' to a 'char *'.  This is also the reason
	   why the function prototype declares it as a 'void *', if it's declared
	   as a 'BYTE *' then the conversion process gives compilers and static
	   analysers headaches */
	LOOP_MAX( i = 0, i < strDataLen, i++ )
		{
		int ch;

		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, strDataLen - 1 ),
					 "(Internal error)" );

		ch = byteToInt( strPtr[ i ] );
		if( !isValidTextChar( ch ) )
			strPtr[ i ] = '.';
		}
	ENSURES_EXT( LOOP_BOUND_OK, "(Internal error)" );

	/* If there was more input than we could fit into the buffer and there's 
	   room for a continuation indicator, add this to the output string (we
	   silently truncate if the available space is eight characters or less 
	   since it would replace most of the string with the truncation 
	   indicator).  We check for strLen >= strMaxLen rather than > strMaxLen 
	   because we need an extra byte for the '\0', since the case of 
	   strLen == strMaxLen wouldn't leave us any room */
	if( ( strLen >= strMaxLen ) && ( strMaxLen > 8 ) )
		{
		REQUIRES_EXT( boundsCheck( strMaxLen - 6, 5, strMaxLen ),
					  "(Internal error)" );
		memcpy( strPtr + strMaxLen - 6, "[...]", 5 );	/* Extra -1 for '\0' */
		}

	/* Terminate the string to allow it to be used in printf()-style
	   functions */
	if( strLen < strMaxLen )
		strPtr[ strLen ] = '\0';
	else
		strPtr[ strMaxLen - 1 ] = '\0';

	/* We've converted the string from BYTE * to char * so it can be 
	   returned as a standard text string */
	return( ( char * ) strPtr );
	}

/****************************************************************************
*																			*
*							Character Functions								*
*																			*
****************************************************************************/

/* Replacements for the booby-trapped isxxx() and toxxx() macros/functions, 
   see the long comment in misc/os_spec.h for details */

CHECK_RETVAL_BOOL \
BOOLEAN isAlpha( IN_BYTE const int ch )
	{
	/* Make sure that we've been passed valid input.  This should never
	   occur since we get called after byteToInt() so we warn in debug
	   mode */
	if( !rangeCheck( ch, 0, 0xFF ) )
		{
		assert( DEBUG_WARN );
		return( FALSE );
		}

	return( ( ch >= 'A' && ch <= 'Z' ) || \
			( ch >= 'a' && ch <= 'z' ) ? TRUE : FALSE );
	}

CHECK_RETVAL_BOOL \
BOOLEAN isAlNum( IN_BYTE const int ch )
	{
	/* Make sure that we've been passed valid input.  This should never
	   occur since we get called after byteToInt() so we warn in debug
	   mode */
	if( !rangeCheck( ch, 0, 0xFF ) )
		{
		assert( DEBUG_WARN );
		return( FALSE );
		}

	return( ( ch >= 'A' && ch <= 'Z' ) || \
			( ch >= 'a' && ch <= 'z' ) || \
			( ch >= '0' && ch <= '9' ) ? TRUE : FALSE );
	}

CHECK_RETVAL_BOOL \
BOOLEAN isPrint( IN_BYTE const int ch )
	{
	/* Make sure that we've been passed valid input.  This should never
	   occur since we get called after byteToInt() so we warn in debug
	   mode */
	if( !rangeCheck( ch, 0, 0xFF ) )
		{
		assert( DEBUG_WARN );
		return( FALSE );
		}

	return( ( ch >= 0x20 && ch <= 0x7E ) ? TRUE : FALSE );
	}

CHECK_RETVAL_BOOL \
BOOLEAN isDigit( IN_BYTE const int ch )
	{
	/* Make sure that we've been passed valid input.  This should never
	   occur since we get called after byteToInt() so we warn in debug
	   mode */
	if( !rangeCheck( ch, 0, 0xFF ) )
		{
		assert( DEBUG_WARN );
		return( FALSE );
		}

	return( ( ch >= '0' && ch <= '9' ) ? TRUE : FALSE );
	}

CHECK_RETVAL_BOOL \
BOOLEAN isXDigit( IN_BYTE const int ch )
	{
	/* Make sure that we've been passed valid input.  This should never
	   occur since we get called after byteToInt() so we warn in debug
	   mode */
	if( !rangeCheck( ch, 0, 0xFF ) )
		{
		assert( DEBUG_WARN );
		return( FALSE );
		}

	return( ( ch >= '0' && ch <= '9' ) || \
			( ch >= 'A' && ch <= 'F' ) || \
			( ch >= 'a' && ch <= 'f' ) ? TRUE : FALSE );
	}

CHECK_RETVAL_RANGE_NOERROR( 0, 0xFF ) \
int toLower( IN_BYTE const int ch )
	{
	if( !rangeCheck( ch, 0, 0xFF ) )
		{
		assert( DEBUG_WARN );
		return( byteToInt( ch ) );
		}

	return( ( ch >= 'A' && ch <= 'Z' ) ? ( ch | 0x20 ) : ch );
	}

CHECK_RETVAL_RANGE_NOERROR( 0, 0xFF ) \
int toUpper( IN_BYTE const int ch )
	{
	if( !rangeCheck( ch, 0, 0xFF ) )
		{
		assert( DEBUG_WARN );
		return( byteToInt( ch ) );
		}

	return( ( ch >= 'a' && ch <= 'z' ) ? ( ch & ~0x20 ) : ch );
	}

/****************************************************************************
*																			*
*							String Function Support							*
*																			*
****************************************************************************/

/* Match a given substring against a string in a case-insensitive manner,
   see the long comment in misc/os_spec.h for details.  When calling these 
   functions to compare against a literal string, the literal is the second 
   value, e.g. strSame( string, "[Autodetect]", 12 ) */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
BOOLEAN strSame( IN_STRING_LEN( length ) const char *src, 
				 IN_STRING_LEN( length ) const char *dest, 
				 IN_LENGTH_ATTRIBUTE const int length )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( src, length ) );
	assert( isReadPtrDynamic( dest, length ) );

	if( !rangeCheck( length, 1, MAX_ATTRIBUTE_SIZE ) )
		{
		/* Invalid length.  With a sufficiently malformed string, which we
		   shouldn't be seeing since we're using mostly constant or fixed-
		   length strings, we can still over-read, but it's better than over-
		   writing */
		assert( DEBUG_WARN );
		return( FALSE );
		}

	LOOP_MAX( i = 0, i < length, i++ )
		{
		const int srcCh = toUpper( byteToInt( src[ i ] ) );
		const int destCh = toUpper( byteToInt( dest[ i ] ) );

		ENSURES_B( LOOP_INVARIANT_MAX( i, 0, length - 1 ) );

		if( srcCh != destCh )
			return( FALSE );
		if( srcCh == '\0' )
			{
			/* If we've run out of characters to match without hitting the 
			   end of the string, it's a mis-match.  Note that this also 
			   checks destCh since we wouldn't have got here if they weren't 
			   the same */
			return( FALSE );
			}
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( TRUE );
	}

#ifdef USE_DNSSRV

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
BOOLEAN strSameZ( IN_STRING const char *src, IN_STRING const char *dest )
	{
	const int length = strnlen_s( src, MAX_ATTRIBUTE_SIZE );

	assert( isReadPtr( src, 1 ) );
	assert( isReadPtr( dest, 1 ) );

	if( length != strnlen_s( dest, MAX_ATTRIBUTE_SIZE ) )
		return( FALSE );	/* Lengths differ */
	return( strSame( src, dest, length ) );
	}
#endif /* USE_DNSSRV */

/****************************************************************************
*																			*
*						TR 24731 Safe stdlib Extensions						*
*																			*
****************************************************************************/

#ifndef __STDC_LIB_EXT1__

/* Minimal wrappers for the TR 24731 functions to map them to older stdlib 
   equivalents.  Because of potential issues when comparing a (signed)
   literal value -1 to the unsigned size_t we explicitly check for both
   '( size_t ) -1' as well as a general check for a negative return value.
   
   We can't really emulate mbstowcs_s() properly via mbstowcs() because 
   'count' is the number of widechars to store in the destination buffer 
   (up to 'dstmax'), not a byte count.  The real mbstowcs_s() converts 
   'count' characters to widechars and stores them in 'dst' until 
   'dstmax' is reached, while mbstowcs() just keeps going until it hits a 
   null terminator.

   However we're only called from two locations, one is in 
   io/net_proxy.c:findProxyUrl() for Windows autoproxy handling where we 
   need to use Unicode strings but also know that the real mbstowcs_s() is 
   present so the call will never end up here, the other is from 
   cert/dn_string:getASN1StringInfo() where we're being called as an 
   emulation of the nonexistent mbstrlen() so 'dst' is always NULL (checked
   for with a REQUIRES() statement on the input).  In this case we're not 
   writing anything to the output and the caller will check the range of 
   'retVal' when they receive it.
	   
   This is complicated by the totally stupid semantics of the function which 
   state that:
	   
	If [destination] pwcs is a null pointer, mbstowcs() shall return the 
	length required to convert the entire array regardless of the value of 
	[size] n.
		
   This means that if the destination is a nonnull pointer then the size 
   argument is applied, if not then it's completely ignored.  To deal with 
   this braindamage have to copy the input to a buffer, null-terminate it,
   and then pass it to mbstowcs.
	   
   This is in theory a bit of a problem because we don't know how big the 
   buffer needs to be, however because of the way that we're called (see 
   above) the call can only come from the certificate code and that caps 
   almost all strings at CRYPT_MAX_TEXTSIZE except for a few exceptions like 
   CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT which are supposed to be 
   CRYPT_MAX_TEXTSIZE except that many CAs ignore this so are capped at 200 
   characters instead (see cert/ext_def.c and 
   cert/ext_rdattr.c:readAttributeField() which hard-limits the 
   CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT to 200 characters, discarding the 
   rest).  So an output size of 512 wchar_t's is more than enough.
   
   However even this probably isn't the best solution, so instead we have
   to hand-assemble it from mbrtowc().  Note though that as of cryptlib
   3.4.9.4 this function isn't called any more (see
   cert/ext_rdattr.c:readAttributeField()), but is present only to record 
   its functionality */

RETVAL_RANGE( -1, 0 ) STDC_NONNULL_ARG( ( 1, 4 ) ) \
int mbstowcs_s( OUT_PTR size_t *retval, 
				OUT_BUFFER_OPT_FIXED( dstmax ) wchar_t *dst, 
				IN_LENGTH_SHORT_Z size_t dstmax, 
				IN_BUFFER( count ) const char *src, 
				IN_LENGTH_SHORT size_t count )
	{
#if 0
	BYTE buffer[ 512 + 1 + 8 ];
	size_t wcCopied;
#else
	mbstate_t mbState = { 0 };
	size_t offset;
	int wcCount = 0, LOOP_ITERATOR;
#endif /* 0 */

	assert( isWritePtr( retval, sizeof( size_t ) ) );
	assert( dst == NULL );
	assert( isReadPtrDynamic( src, count ) );

	static_assert( 1000 - 1 < FAILSAFE_ITERATIONS_LARGE,
				   "mbstowcs_s() loop bound" );

	REQUIRES_EXT( dst == NULL, -1 );
	REQUIRES_EXT( dstmax == 0, -1 );
	REQUIRES_EXT( isShortIntegerRangeNZ( count ), -1 );

	/* Clear return value */
	*retval = 0;

#if 0
	if( count > 512 )
		return( -1 );
	REQUIRES_EXT( rangeCheck( count, 1, 512 ), -1 );
	memcpy( buffer, src, count );
	buffer[ count ] = '\0';
	wcCopied = mbstowcs( NULL, buffer, count );
	if( ( wcCopied == ( size_t ) -1 ) || ( wcCopied <= 0 ) || \
		wcCopied >= 512 )
		return( -1 );
	*retval = wcCopied;
#else
	if( count >= 1000 )
		return( -1 );
	LOOP_LARGE_INITCHECK( offset = 0, offset < count )
		{
		size_t bytesConsumed;
		
		ENSURES_EXT( LOOP_INVARIANT_LARGE_XXX( offset, 0, count - 1 ), -1 );
		
		REQUIRES_EXT( !checkOverflowSub( count, offset ), -1 );
		bytesConsumed = mbrtowc( NULL, src + offset, count - offset, 
								 &mbState );
		if( bytesConsumed == 0 )
			{
			/* We've found an embedded nul character, this shouldn't be 
			   present so we report it as an error */
			return( -1 );
			}
		if( bytesConsumed == ( size_t ) -1 || \
			bytesConsumed == ( size_t ) -2 )
			{
			/* The error return, and the other error return.  We can't 
			   easily compare for < 0 because we don't know what size a 
			   size_t is, so can't cast it to a signed equivalent */
			return( -1 );
			}
		REQUIRES_EXT( !checkOverflowAdd( offset, bytesConsumed ), -1 );
		offset += bytesConsumed;
		wcCount++;
		}
	ENSURES_EXT( LOOP_BOUND_OK, -1 );
	*retval = wcCount;
#endif /* 0 */

	return( 0 );
	}

#ifdef __WINCE__

RETVAL_RANGE( -1, 0 ) \
int wcstombs_s( OUT_PTR size_t *retval, 
				OUT_BUFFER_FIXED( dstmax ) char *dst, 
				IN_LENGTH_SHORT size_t dstmax, 
				IN_BUFFER( count * sizeof( wchar_t ) ) \
					const wchar_t *src, 
				IN_LENGTH_SHORT size_t count )
	{
	size_t bytesCopied;

	assert( isWritePtr( retval, sizeof( size_t ) ) );
	assert( isWritePtrDynamic( dst, dstmax ) );
			/* For wcstombs_s() args */
	assert( isReadPtrDynamic( src, count * sizeof( wchar_t ) ) );
			/* For wcstombs() args */

	REQUIRES_EXT( isShortIntegerRangeNZ( dstmax ), -1 );
	REQUIRES_EXT( ( isShortIntegerRangeNZ( count ) && \
					count <= dstmax ), -1 );

	/* Clear return value */
	*retval = 0;

	/* As is the case for mbstowcs_s() above, this is only used under Windows
	   for which we have the full wcstombs_s() present and never call this 
	   function, and in one location for Windows CE which is extinct, it's 
	   just left here for consistency.  In addition it would need updating 
	   to use the same technique as the mbstowcs_s() emulation, but since 
	   it's dead code there's no point to updating it any more */
	bytesCopied = wcstombs( dst, src, count );
	if( ( bytesCopied == ( size_t ) -1 ) || ( bytesCopied <= 0 ) )
		return( -1 );
	*retval = bytesCopied;
	return( 0 );
	}
#endif /* __WINCE__ */
#endif /* !__STDC_LIB_EXT1__ */

/****************************************************************************
*																			*
*								Self-test Functions							*
*																			*
****************************************************************************/

/* Test code for the above functions */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL \
BOOLEAN testIntString( void )
	{
	BYTE buffer[ 16 + 8 ];
	const char *stringPtr;
	int stringLen, value;

	/* Test strFindCh() */
	if( strFindCh( "abcdefgh", 8, 'a' ) != 0 || \
		strFindCh( "abcdefgh", 8, 'd' ) != 3 || \
		strFindCh( "abcdefgh", 8, 'h' ) != 7 || \
		strFindCh( "abcdefgh", 8, 'x' ) != -1 )
		return( FALSE );

	/* Test strFindStr() */
	if( strFindStr( "abcdefgh", 8, "abc", 3 ) != 0 || \
		strFindStr( "abcDEFgh", 8, "def", 3 ) != 3 || \
		strFindStr( "ABCdefGH", 8, "DEF", 3 ) != 3 || \
		strFindStr( "abcdefgh", 8, "fgh", 3 ) != 5 || \
		strFindStr( "abcdefgh", 8, "ghi", 3 ) != -1 || \
		strFindStr( "abcdefgh", 8, "abcdefghi", 9 ) != -1 )
		return( FALSE );

	/* Test strSkipWhitespace() */
	if( strSkipWhitespace( "abcdefgh", 8 ) != 0 || \
		strSkipWhitespace( " abcdefgh", 9 ) != 1 || \
		strSkipWhitespace( " \t abcdefgh", 11 ) != 3 || \
		strSkipWhitespace( " x abcdefgh", 11 ) != 1 || \
		strSkipWhitespace( "  \t ", 4 ) != -1 )
		return( FALSE );

	/* Test strSkipNonWhitespace() */
	if( strSkipNonWhitespace( "abcdefgh", 8 ) != 8 || \
		strSkipNonWhitespace( " abcdefgh", 9 ) != -1 || \
		strSkipNonWhitespace( "abcdefgh ", 9 ) != 8 || \
		strSkipNonWhitespace( "abcdefgh x ", 11 ) != 8 )
		return( FALSE );

	/* Test strStripWhitespace() */
	stringLen = strStripWhitespace( &stringPtr, "abcdefgh", 8 );
	if( stringLen != 8 || memcmp( stringPtr, "abcdefgh", 8 ) )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, "abcdefgh\0\0", 10 );
	if( stringLen != 8 || memcmp( stringPtr, "abcdefgh", 8 ) )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, "abcdefgh\0 \0", 11 );
	if( stringLen != 8 || memcmp( stringPtr, "abcdefgh", 8 ) )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, " abcdefgh", 9 );
	if( stringLen != 8 || memcmp( stringPtr, "abcdefgh", 8 ) )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, "abcdefgh ", 9 );
	if( stringLen != 8 || memcmp( stringPtr, "abcdefgh", 8 ) )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, " abcdefgh ", 10 );
	if( stringLen != 8 || memcmp( stringPtr, "abcdefgh", 8 ) )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, " x abcdefgh ", 12 );
	if( stringLen != 10 || memcmp( stringPtr, "x abcdefgh", 10 ) )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, " abcdefgh x ", 12 );
	if( stringLen != 10 || memcmp( stringPtr, "abcdefgh x", 10 ) )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, "\0" "abcdefgh\0", 10 );
	if( stringLen != -1 || stringPtr != NULL )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, " \0" "abcdefgh\0", 11 );
	if( stringLen != -1 || stringPtr != NULL )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, "  \t ", 4 );
	if( stringLen != -1 || stringPtr != NULL )
		return( FALSE );
	stringLen = strStripWhitespace( &stringPtr, "\0\0\0\0", 4 );
	if( stringLen != -1 || stringPtr != NULL )
		return( FALSE );

	/* Test strExtract() */
	stringLen = strExtract( &stringPtr, "abcdefgh", 4, 8 );
	if( stringLen != 4 || memcmp( stringPtr, "efgh", 4 ) )
		return( FALSE );
	stringLen = strExtract( &stringPtr, "abcd  efgh", 4, 10 );
	if( stringLen != 4 || memcmp( stringPtr, "efgh", 4 ) )
		return( FALSE );
	stringLen = strExtract( &stringPtr, "abcd  efgh  ", 4, 12 );
	if( stringLen != 4 || memcmp( stringPtr, "efgh", 4 ) )
		return( FALSE );
	stringLen = strExtract( &stringPtr, "abcd  efgh  ij  ", 4, 16 );
	if( stringLen != 8 || memcmp( stringPtr, "efgh  ij", 8 ) )
		return( FALSE );

	/* Test strGetNumeric() */
	if( strGetNumeric( "0", 1, &value, 0, 10 ) != CRYPT_OK || value != 0 || \
		strGetNumeric( "00", 2, &value, 0, 10 ) != CRYPT_OK || value != 0 || \
		strGetNumeric( "1234", 4, &value, 0, 2000 ) != CRYPT_OK || value != 1234 || \
		strGetNumeric( "1234x", 5, &value, 0, 2000 ) != CRYPT_ERROR_BADDATA || value != 0 || \
		strGetNumeric( "x1234", 5, &value, 0, 2000 ) != CRYPT_ERROR_BADDATA || value != 0 || \
		strGetNumeric( "1000", 4, &value, 0, 1000 ) != CRYPT_OK || value != 1000 || \
		strGetNumeric( "1001", 4, &value, 0, 1000 ) != CRYPT_ERROR_BADDATA || value != 0 )
		return( FALSE );

	/* Test strParseNumeric() */
	if( strParseNumeric( "0", 1, &value, 0, 10 ) != 1 || value != 0 || \
		strParseNumeric( "00", 2, &value, 0, 10 ) != 2 || value != 0 || \
		strParseNumeric( "1234", 4, &value, 0, 2000 ) != 4 || value != 1234 || \
		strParseNumeric( "1234x", 5, &value, 0, 2000 ) != 4 || value != 1234 || \
		strParseNumeric( "1234.0", 6, &value, 0, 2000 ) != 4 || value != 1234 || \
		strParseNumeric( ".1000", 5, &value, 0, 1000 ) != CRYPT_ERROR_BADDATA || value != 0 || \
		strParseNumeric( "1001-0", 6, &value, 0, 2000 ) != 4 || value != 1001 )
		return( FALSE );

	/* Test strGetHex() */
	if( strGetHex( "0", 1, &value, 0, 1000 ) != CRYPT_OK || value != 0 || \
		strGetHex( "1234", 4, &value, 0, 0x2000 ) != CRYPT_OK || value != 0x1234 || \
		strGetHex( "1234x", 5, &value, 0, 0x2000 ) != CRYPT_ERROR_BADDATA || value != 0 || \
		strGetHex( "x1234", 5, &value, 0, 0x2000 ) != CRYPT_ERROR_BADDATA || value != 0 || \
		strGetHex( "12EE", 4, &value, 0, 0x12EE ) != CRYPT_OK || value != 0x12EE || \
		strGetHex( "12EF", 4, &value, 0, 0x12EE ) != CRYPT_ERROR_BADDATA || value != 0 )
		return( FALSE );

	/* Test sanitiseString() */
	memcpy( buffer, "abcdefgh", 8 );
	stringPtr = sanitiseString( buffer, 16, 8 );
	if( memcmp( stringPtr, "abcdefgh", 9 ) )
		return( FALSE );
	memcpy( buffer, "abc\x12" "efgh", 8 );
	stringPtr = sanitiseString( buffer, 16, 8 );
	if( memcmp( stringPtr, "abc.efgh", 9 ) )
		return( FALSE );
	memcpy( buffer, "abcdefgh", 8 );
	stringPtr = sanitiseString( buffer, 7, 8 );
	if( memcmp( stringPtr, "abcdef", 7 ) )
		return( FALSE );
	memcpy( buffer, "abcdefgh", 8 );
	stringPtr = sanitiseString( buffer, 8, 8 );
	if( memcmp( stringPtr, "abcdefg", 8 ) )
		return( FALSE );
	memcpy( buffer, "abcdefghij", 10 );
	stringPtr = sanitiseString( buffer, 9, 10 );
	if( memcmp( stringPtr, "abc[...]", 9 ) )
		return( FALSE );
	memcpy( buffer, "abcdefghij", 10 );
	stringPtr = sanitiseString( buffer, 10, 10 );
	if( memcmp( stringPtr, "abcd[...]", 10 ) )
		return( FALSE );
	memcpy( buffer, "abcdefghij", 10 );
	stringPtr = sanitiseString( buffer, 11, 10 );
	if( memcmp( stringPtr, "abcdefghij", 11 ) )
		return( FALSE );

	/* Test isxxx()/toxxx().  0xC0 = 8859-1 A-grave, 0xE0 = 8859-1 a-grave. 
	   We can't test completely out-of-range values because they'll 
	   assert() in debug mode */
	if( !isAlpha( 'A' ) || !isAlpha( 'a' ) || \
		isAlpha( '(' ) || isAlpha( '[' ) || isAlpha( '{' ) || \
		isAlpha( 0xC0 ) || isAlpha( 0xE0 ) )
		return( FALSE );
	if( !isAlNum( 'A' ) || !isAlNum( 'a' ) || !isAlNum( '0' ) || \
		isAlNum( '(' ) || isAlNum( '[' ) || isAlNum( '{' ) || \
		isAlNum( 0xC0 ) || isAlNum( 0xE0 ) )
		return( FALSE );
	if( !isPrint( ' ' ) || !isPrint( '+' ) || !isPrint( '~' ) || \
		isPrint( '\t' ) || isPrint( '\0' ) || isPrint( 0x7F ) || \
		isPrint( 0xC0 ) || isPrint( 0xE0 ) )
		return( FALSE );
	if( !isDigit( '0' ) || !isDigit( '9' ) || \
		isDigit( '/' ) || isDigit( ':' ) || isDigit( 'k' ) )
		return( FALSE );
	if( !isXDigit( '0' ) || !isXDigit( '9' ) || !isXDigit( 'a' ) || \
		!isXDigit( 'A' ) || !isXDigit( 'F' ) || \
		isXDigit( '/' ) || isXDigit( ':' ) || isXDigit( '@' ) || \
		isXDigit( 'G' ) || isXDigit( 'g' ) )
		return( FALSE );
	if( toLower( 'A' ) != 'a' || toLower( 'Z' ) != 'z' || \
		toLower( '0' ) != '0' || toLower( 0xC0 ) != 0xC0 || \
		toLower( 0xE0 ) != 0xE0 )
		return( FALSE );
	if( toUpper( 'a' ) != 'A' || toUpper( 'z' ) != 'Z' || \
		toUpper( '0' ) != '0' || toUpper( 0xC0 ) != 0xC0 || \
		toUpper( 0xE0 ) != 0xE0 )
		return( FALSE );

	/* Test strSame() */
	if( !strSame( "abcdefgh", "abcdefgh", 8 ) || \
		!strSame( "ABCdefgh", "abcdefgh", 8 ) || \
		!strSame( "abcdefgh", "abc", 3 ) || \
		strSame( "abcdefgh", "abc", 8 ) || \
		strSame( "abc", "abc", 8 ) || \
		strSame( "abc", "abd", 3 ) || strSame( "ab", "abc", 3 ) )
		return( FALSE );

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
