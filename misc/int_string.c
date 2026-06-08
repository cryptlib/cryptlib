/****************************************************************************
*																			*
*						  cryptlib Internal String API						*
*						Copyright Peter Gutmann 1992-2025					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

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
	const int findCh = toUpper( findStr[ 0 ] );
	LOOP_INDEX i;

	assert( isReadPtrDynamic( str, strLen ) );
	assert( isReadPtrDynamic( findStr, findStrLen ) );

	REQUIRES_EXT( isShortIntegerRangeNZ( strLen ), -1 );
	REQUIRES_EXT( isShortIntegerRangeNZ( findStrLen ), -1 );
	REQUIRES_EXT( findCh >= 0 && findCh <= 0x7F, -1 );

	/* If the string to find is larger than the string being searched, we 
	   can never have a match */
	if( findStrLen > strLen )
		return( -1 );

	LOOP_MAX( i = 0, i <= strLen - findStrLen, i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, strLen - findStrLen ), -1 );

		if( toUpper( str[ i ] ) == findCh && \
			!strCompare( str + i, findStr, findStrLen ) )
			return( i );
		}
	ENSURES_EXT( LOOP_BOUND_OK, -1 );

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
	ENSURES_EXT( rangeCheck( startPos, 0, strLen - 1 ), -1 );
	*newStringPtr = string + startPos;
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
	LOOP_LARGE( ( i = 0, value = 0 ), i < strLen, i++ )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, strLen - 1 ) );

		ch = byteToInt( str[ i ] ) - '0';
		if( ch < 0 || ch > 9 )
			return( CRYPT_ERROR_BADDATA );
		if( checkOverflowMul( value, 10 ) )
			return( CRYPT_ERROR_BADDATA );
		value *= 10;
		if( checkOverflowAdd( value, ch ) )
			return( CRYPT_ERROR_BADDATA );
		value += ch;
		ENSURES( isIntegerRange( value ) );
		}
	ENSURES( LOOP_BOUND_OK );

	/* Make sure that the final value is within the specified range */
	if( value < minValue || value > maxValue )
		return( CRYPT_ERROR_BADDATA );

	*numericValue = value;
	return( CRYPT_OK );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 3 ) ) \
int strParseNumeric( IN_BUFFER( strLen ) const char *str, 
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
	   value */
	LOOP_LARGE( numericStrLen = 0, 
				numericStrLen < strMaxLen && \
					isDigit( str[ numericStrLen ] ),
				numericStrLen++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( numericStrLen, 0, strMaxLen - 1 ) );
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

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int strGetHex( IN_BUFFER( strLen ) const char *str, 
			   IN_LENGTH_SHORT const int strLen, 
			   OUT_INT_Z int *numericValue, 
			   IN_RANGE( 0, 100 ) const int minValue, 
			   IN_RANGE( minValue, 0xFFFF ) const int maxValue )
	{
	const int strMaxLen = ( maxValue > 0xFFF ) ? 4 : \
						  ( maxValue > 0xFF ) ? 3 : \
						  ( maxValue > 0xF ) ? 2 : 1;
	LOOP_INDEX i;
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
	   value is capped to fit into an int */
	LOOP_MAX( i = 0, i < strLen, i++ )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_MAX( i, 0, strLen - 1 ) );
	
		ch = toLower( str[ i ] );
		if( !isXDigit( ch ) )
			return( CRYPT_ERROR_BADDATA );
		value = ( value << 4 ) | \
				( ( ch <= '9' ) ? ch - '0' : ch - ( 'a' - 10 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	if( value < minValue || value > maxValue )
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
   become "Error string [...]" */

STDC_NONNULL_ARG( ( 1 ) ) \
char *sanitiseString( INOUT_BUFFER( strMaxLen, strLen ) void *string, 
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
	   silently truncate if the string is eight characters or less since it 
	   would replace most of the string with the truncation indicator).  We 
	   check for strLen >= strMaxLen rather than > strMaxLen because we need 
	   an extra byte for the '\0', since the case of strLen == strMaxLen 
	   wouldn't leave us any room */
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
*						TR 24731 Safe stdlib Extensions						*
*																			*
****************************************************************************/

#ifndef __STDC_LIB_EXT1__

/* Minimal wrappers for the TR 24731 functions to map them to older stdlib 
   equivalents.  Because of potential issues when comparing a (signed)
   literal value -1 to the unsigned size_t we explicitly check for both
   '( size_t ) -1' as well as a general check for a negative return value */

RETVAL_RANGE( -1, 0 ) \
int mbstowcs_s( OUT_PTR size_t *retval, 
				OUT_BUFFER_FIXED( dstmax ) wchar_t *dst, 
				IN_LENGTH_SHORT size_t dstmax, 
				IN_BUFFER( len ) const char *src, 
				IN_LENGTH_SHORT size_t count )
	{
	size_t bytesCopied;

	assert( isWritePtr( retval, sizeof( size_t ) ) );
	assert( dst == NULL );
	assert( isReadPtrDynamic( src, count ) );

	REQUIRES_EXT( dst == NULL, -1 );	/* See comment below */
	REQUIRES_EXT( isShortIntegerRangeNZ( dstmax ), -1 );
	REQUIRES_EXT( ( isShortIntegerRangeNZ( count ) && \
					count <= dstmax ), -1 );

	/* Clear return value */
	*retval = 0;

	/* We can't really emulate mbstowcs_s() properly because 'count' is the 
	   number of widechars to store in the destination buffer (up to 
	   'dstmax'), not a byte count.  The real mbstowcs_s() converts 'count' 
	   characters to widechars and stores them in 'dst' until 'dstmax' is 
	   reached, while mbstowcs() just keeps going until it hits a null 
	   terminator.
	   
	   However we're only called from two locations, one is in 
	   io/net_proxy.c:findProxyUrl() for Windows autoproxy handling where we 
	   need to use Unicode strings but also know that the real mbstowcs_s() 
	   is present so the call will never end up here, the other is from 
	   cert/dn_string:getASN1StringInfo() where we're being called as an 
	   emulation of the nonexistent mbstrlen() so 'dst' is always NULL (thus
	   the REQUIRES() statement above).  In this case we're not writing 
	   anything to the output and the caller will check the range of 
	   'retVal' when they receive it */
	bytesCopied = mbstowcs( dst, src, count );
	if( ( bytesCopied == ( size_t ) -1 ) || ( bytesCopied <= 0 ) )
		return( -1 );
	*retval = bytesCopied;
	return( 0 );
	}

#ifdef __WINCE__

RETVAL_RANGE( -1, 0 ) \
int wcstombs_s( OUT_PTR size_t *retval, 
				OUT_BUFFER_FIXED( dstmax ) char *dst, 
				IN_LENGTH_SHORT size_t dstmax, 
				IN_BUFFER( len) const wchar_t *src, 
				IN_LENGTH_SHORT size_t count )
	{
	size_t bytesCopied;

	assert( isWritePtr( retval, sizeof( size_t ) ) );
	assert( isWritePtrDynamic( dst, dstmax ) );
	assert( isReadPtrDynamic( src, count ) );

	REQUIRES_EXT( isShortIntegerRangeNZ( dstmax ), -1 );
	REQUIRES_EXT( ( isShortIntegerRangeNZ( count ) && \
					count <= dstmax ), -1 );

	/* Clear return value */
	*retval = 0;

	/* As is the case for mbstowcs_s() above, this is only used under Windows
	   for which we have the full wcstombs_s() present and never call this 
	   function, and in one location for Windows CE which is extinct, it's 
	   just left here for consistency */
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
	stringLen = strStripWhitespace( &stringPtr, "  \t ", 4 );
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

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
