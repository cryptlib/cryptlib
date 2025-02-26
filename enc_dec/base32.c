/****************************************************************************
*																			*
*					 cryptlib Base32 En/Decoding Routines					*
*						Copyright Peter Gutmann 1998-2018					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

#if defined( USE_TLS ) || defined( USE_SSH )

/* En/decode tables for text representations of binary keys, from RFC 4648.  
   Unlike cryptlib's PKI userID encoding, which predates the RFC, this uses
   the confusing I and O but doesn't make use of 8 and 9 to replace them.
   For the two mask tables, only positions 4...7 are used */

static const char codeTable[] = \
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567____";	/* RFC 4648 */
static const int hiMask[] = \
			{ 0x00, 0x00, 0x00, 0x00, 0x0F, 0x07, 0x03, 0x01, 0x00, 0x00 };
static const int loMask[] = 		/* ------- Used ------- */
			{ 0x00, 0x00, 0x00, 0x00, 0x80, 0xC0, 0xE0, 0xF0, 0x00, 0x00 };
									/* ------- Used ------- */

/****************************************************************************
*																			*
*								Base32 Decoding Functions					*
*																			*
****************************************************************************/

/* Check whether a text string is a valid Base32 value */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN isBase32Value( IN_BUFFER( encValLength ) const char *encVal, 
					   IN_LENGTH_SHORT_MIN( 16 ) const int encValLength )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( encVal, encValLength ) );

	REQUIRES_B( isShortIntegerRangeMin( encValLength, 16 ) );

	/* Check whether an input string is a valid Base32 value.  Since this is
	   being used for TOTP, it has to be an even multiple of 8 characters,
	   corresponding to 40 bits, and a minimum of 80 bits */
	if( encValLength != 16 && encValLength != 24 && encValLength != 32 )
		return( FALSE );
	LOOP_MED_INITCHECK( i = 0, i < encValLength )
		{
		int ch;

		ENSURES_B( LOOP_INVARIANT_MED( i, 0, encValLength - 1 ) );

		ch = byteToInt( encVal[ i++ ] );
		if( !isAlnum( ch ) || ch == '0' || ch == '1' || ch == '8' || \
			ch == '9' )
			return( FALSE );
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( TRUE );
	}

/* Decode a Base32 text representation of a binary string */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int decodeBase32Value( OUT_BUFFER( valueMaxLen, *valueLen ) BYTE *value, 
					   IN_LENGTH_SHORT_MIN( 32 ) const int valueMaxLen, 
					   OUT_LENGTH_BOUNDED_Z( valueMaxLen ) int *valueLen,
					   IN_BUFFER( encValLength ) const char *encVal, 
					   IN_LENGTH_SHORT_MIN( 16 ) const int encValLength )
	{
	LOOP_INDEX i;
	int byteCount = 0, bitCount = 0;

	assert( isWritePtrDynamic( value, valueMaxLen ) );
	assert( isWritePtr( valueLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( encVal, encValLength ) );

	REQUIRES( isShortIntegerRangeMin( valueMaxLen, 32 ) );
	REQUIRES( isShortIntegerRangeMin( encValLength, 16 ) && \
			  valueMaxLen > ( ( encValLength  * 5 ) / 8 ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( valueMaxLen ) ); 
	memset( value, 0, min( 16, valueMaxLen ) );
	*valueLen = 0;

	/* Make sure that the input has a reasonable length (this should have 
	   been checked by the caller using isBase32Value(), so we throw an
	   exception if the check fails).  We return CRYPT_ERROR_BADDATA rather 
	   than the more obvious CRYPT_ERROR_OVERFLOW since something returned 
	   from this low a level should be a consistent error code indicating 
	   that there's a problem with the Base32 value as a whole */
	if( encValLength != 16 && encValLength != 24 && encValLength != 32 )
		{
		DEBUG_DIAG(( "Base32 value has invalid length" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_BADDATA );
		}

	REQUIRES( isBase32Value( encVal, encValLength ) );

	/* Decode the value into binary */
	LOOP_LARGE( i = 0, i < encValLength, i++ )
		{
		int ch;
		LOOP_INDEX_ALT chunkValue;

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, encValLength - 1 ) );

		ch = toUpper( byteToInt( encVal[ i ] ) );
		if( !isAlnum( ch ) || ch == '0' || ch == '1' || ch == '8' || \
			ch == '9' )
			return( CRYPT_ERROR_BADDATA );
		LOOP_MED_ALT( chunkValue = 0, chunkValue < 0x20, chunkValue++ )
			{
			ENSURES( LOOP_INVARIANT_MED_ALT( chunkValue, 0, 0x1F ) );

			if( codeTable[ chunkValue ] == ch )
				break;
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		if( chunkValue >= 0x20 )
			return( CRYPT_ERROR_BADDATA );

		/* Extract the next 5-bit chunk and convert it to text form */
		if( bitCount < 3 )
			{
			/* Everything's present in one byte, shift it up into position */
			value[ byteCount ] |= chunkValue << ( 3 - bitCount );
			}
		else
			{
			if( bitCount == 3 )
				{
				/* It's the 5 LSBs */
				value[ byteCount ] |= chunkValue;
				}
			else
				{
				/* The data spans two bytes, shift the bits from the high
				   byte down and the bits from the low byte up */
				value[ byteCount ] |= \
							intToByte( ( chunkValue >> ( bitCount - 3 ) ) & \
										 hiMask[ bitCount ] );
				value[ byteCount + 1 ] = \
							intToByte( ( chunkValue << ( 11 - bitCount ) ) & \
										 loMask[ bitCount ] );
				}
			}

		/* Advance by 5 bits */
		bitCount += 5;
		if( bitCount >= 8 )
			{
			bitCount -= 8;
			byteCount++;
			}
		ENSURES( bitCount >= 0 && bitCount < 8 );
		ENSURES( byteCount >= 0 && byteCount < 64 );
		}
	ENSURES( LOOP_BOUND_OK );

	/* Return the decoded value length to the caller */
	if( bitCount > 0 )
		byteCount++;	/* More bits in the last partial byte */
	ENSURES( byteCount >= 10 && byteCount <= valueMaxLen );
	*valueLen = byteCount;

	return( CRYPT_OK );
	}
#endif /* USE_TLS || USE_SSH */
