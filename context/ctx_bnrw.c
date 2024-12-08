<<<<<<< HEAD
/****************************************************************************
*																			*
*					cryptlib Bignum Import/Export Routines					*
*						Copyright Peter Gutmann 1995-2015					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
#else
  #include "context/context.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKC

/****************************************************************************
*																			*
*								Utility Routines 							*
*																			*
****************************************************************************/

/* Dump a bignum as a C structure, used for hardcoding constant values like
   DLP and ECDLP domain parameters from their bignum representations */

#if defined( DEBUG_DIAGNOSTIC_ENABLE ) && !defined( NDEBUG )

#if BN_BITS2 == 64
  #define BNULONG_FORMAT	"0x%016llXULL"
  #define BNULONG_PER_LINE	2
#else
  #define BNULONG_FORMAT	"0x%08X"
  #define BNULONG_PER_LINE	4
#endif /* 64- vs 32-bit */

void printBignum( const BIGNUM *bignum, const char *label )
	{
	const BN_ULONG *data = bignum->d;
	LOOP_INDEX i;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );
	assert( isReadPtr( label, 2 ) );

	DEBUG_PRINT(( "\t/* %s */\n\t", label ));
	DEBUG_PRINT(( "{ %d, FALSE, BN_FLG_STATIC_DATA, {\n\t", 
				  bignum->top ));
	LOOP_EXT( i = 0, i < bignum->top, i++, BIGNUM_ALLOC_WORDS )
		{
		ENSURES_V( LOOP_INVARIANT_EXT( i, 0, bignum->top - 1,
									   BIGNUM_ALLOC_WORDS ) );

		DEBUG_PRINT(( BNULONG_FORMAT, data[ i ] ));
		if( i < bignum->top - 1 )
			{
			DEBUG_PRINT(( ", " ));
			if( i > 0 && !( ( i + 1 ) & ( BNULONG_PER_LINE - 1 ) ) )
				DEBUG_PRINT(( "\n\t" ));
			}
		}
	ENSURES_V( LOOP_BOUND_OK );
	DEBUG_PRINT(( " } },\n" ));
	}
#endif /* DEBUG_DIAGNOSTIC_ENABLE && Debug */

/****************************************************************************
*																			*
*								Bignum Import Routines 						*
*																			*
****************************************************************************/

/* Check that an imported bignum value is valid */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkBignum( const BIGNUM *bignum,
						IN_LENGTH_PKC const int minLength, 
						IN_LENGTH_PKC const int maxLength, 
						IN_PTR_OPT const BIGNUM *maxRange,
						IN_ENUM_OPT( BIGNUM_CHECK ) \
							const BIGNUM_CHECK_TYPE checkType )
	{
	int bignumLengthBits, status;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );
	assert( maxRange == NULL || isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum ) );
	REQUIRES( minLength > 0 && minLength <= maxLength && \
			  maxLength <= CRYPT_MAX_PKCSIZE );
	REQUIRES( maxRange == NULL || sanityCheckBignum( maxRange ) );
	REQUIRES( isEnumRangeOpt( checkType, BIGNUM_CHECK ) );

	/* The following should never happen because BN_bin2bn() works with 
	   unsigned values but we perform the check anyway just in case someone 
	   messes with the underlying bignum code */
	ENSURES( !( BN_is_negative( bignum ) ) )

	/* A zero- or one-valued bignum on the other hand is an error because we 
	   should never find zero or one in a PKC-related value.  This check is 
	   somewhat redundant with the one that follows, we place it here to 
	   make it explicit and because the cost is near zero */
	if( BN_cmp_word( bignum, 1 ) <= 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Check that the bignum value falls within the allowed length range.  
	   Before we do the general length check we perform a more specific 
	   check for the case where the length is below the minimum allowed but 
	   still looks at least vaguely valid, in which case we report it as a 
	   too-short key rather than a bad data error.
	   
	   Note that we check the length in bits rather than bytes since the 
	   latter is rounded up, so a length that passes the check based on
	   its rounded-up byte-length value can then fail a later check based 
	   on its actual length in bits */
	status = bignumLengthBits = BN_num_bits( bignum );
	if( cryptStatusError( status ) )
		return( status );
	switch( checkType )
		{
		case BIGNUM_CHECK_NONE:
		case BIGNUM_CHECK_VALUE:
			/* No specific weak-key check for this value */
			break;

		case BIGNUM_CHECK_VALUE_PKC:
			if( isShortPKCKey( bitsToBytes( bignumLengthBits ) ) )
				return( CRYPT_ERROR_NOSECURE );
			break;

		case BIGNUM_CHECK_VALUE_ECC:
			if( isShortECCKey( bitsToBytes( bignumLengthBits ) ) )
				return( CRYPT_ERROR_NOSECURE );
			break;

		default:
			retIntError();
		}

	/* Check that the value is within range.  We have to be a bit careful
	   here when doing a bit-length based comparison because the minimum
	   length that can be specified as a byte is 8 bits, so if minLength == 1
	   then we allow any bit-length >= 2 bits, used for DH g values */
	if( minLength == 1 )
		{
		if( bignumLengthBits < 2 || \
			bignumLengthBits > bytesToBits( maxLength ) )
			return( CRYPT_ERROR_BADDATA );
		}
	else
		{
		if( bignumLengthBits < bytesToBits( minLength ) || \
			bignumLengthBits > bytesToBits( maxLength ) )
			return( CRYPT_ERROR_BADDATA );
		}

	/* Finally, if the caller has supplied a maximum-range bignum value, 
	   make sure that the value that we've read is less than this */
	if( maxRange != NULL && BN_cmp( bignum, maxRange ) >= 0 )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

/* Import a bignum from a buffer.  This is a low-level internal routine also
   used by the OpenSSL bignum code, the non-cryptlib-style API is for 
   compatibility purposes */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 3 ) ) \
BIGNUM *BN_bin2bn( IN_BUFFER( length ) const BYTE *buffer, 
				   IN_LENGTH_PKC_Z const int length, 
				   OUT_PTR BIGNUM *bignum )
	{
	int index = 0, bnStatus = BN_STATUS;
	LOOP_INDEX byteCount, wordIndex;

	assert( length == 0 || isReadPtrDynamic( buffer, length ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES_N( length >= 0 && length <= CRYPT_MAX_PKCSIZE );
	REQUIRES_N( sanityCheckBignum( bignum ) );

	/* Clear return value */
	BN_clear( bignum );

	/* Bignums with value zero are special-cased since they have a length of
	   zero */
	if( length <= 0 )
		return( bignum );

	/* Walk down the bignum a word at a time adding the data bytes */
	bignum->top = ( ( length - 1 ) / BN_BYTES ) + 1;
	LOOP_EXT_REV( ( byteCount = length, wordIndex = bignum->top - 1 ), 
				  byteCount > 0 && wordIndex >= 0, wordIndex--, 
				  BIGNUM_ALLOC_WORDS )
		{
		BN_ULONG value = 0;
		int noBytes = ( ( byteCount - 1 ) % BN_BYTES ) + 1;
		int LOOP_ITERATOR_ALT;

		ENSURES_N( LOOP_INVARIANT_REV( wordIndex, 0, bignum->top - 1 ) )
		ENSURES_N( LOOP_INVARIANT_SECONDARY( byteCount, 1, length ) );

		byteCount -= noBytes;
		LOOP_EXT_REV_CHECKINC_ALT( noBytes > 0, noBytes--, BN_BYTES + 1 )
			{
			ENSURES_N( LOOP_INVARIANT_EXT_REV_XXX_ALT( noBytes, 1, BN_BYTES,
													   BN_BYTES + 1 ) );

			value = ( value << 8 ) | buffer[ index++ ];
			}
		ENSURES_N( LOOP_BOUND_EXT_REV_OK_ALT( BN_BYTES + 1 ) );
		bignum->d[ wordIndex ] = value;
		}
	ENSURES_N( LOOP_BOUND_EXT_REV_OK( BIGNUM_ALLOC_WORDS ) );
	ENSURES_N( wordIndex == -1 && byteCount == 0 );

	/* Now that we've imported the raw data value, convert it to 
	   normalised form */
	CK( BN_normalise( bignum ) );
	if( bnStatusError( bnStatus ) )
		return( NULL );

	ENSURES_N( sanityCheckBignum( bignum ) );

	return( bignum );
	}

/* Convert a byte string to a BIGNUM value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int importBignum( INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignumPtr, 
				  IN_BUFFER( length ) const void *buffer, 
				  IN_LENGTH_SHORT const int length,
				  IN_LENGTH_PKC const int minLength, 
				  IN_RANGE( 1, CRYPT_MAX_PKCSIZE + DLP_OVERFLOW_SIZE ) \
					const int maxLength,
				  IN_PTR_OPT TYPECAST( BIGNUM * ) \
					const struct BN *maxRangePtr,
				  IN_ENUM_OPT( BIGNUM_CHECK ) \
					const BIGNUM_CHECK_TYPE checkType )
	{
	BIGNUM *bignum = ( BIGNUM * ) bignumPtr;
	BIGNUM *maxRange = ( BIGNUM * ) maxRangePtr;
	int status;

	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );
	assert( isReadPtrDynamic( buffer, length ) );
	assert( maxRange == NULL || isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum ) );
	REQUIRES( isShortIntegerRange( length ) );
	REQUIRES( minLength > 0 && minLength <= maxLength && \
			  maxLength <= CRYPT_MAX_PKCSIZE );
	REQUIRES( maxRange == NULL || sanityCheckBignum( maxRange ) );
	REQUIRES( isEnumRangeOpt( checkType, BIGNUM_CHECK ) );

	/* Make sure that we've been given valid input.  This should already 
	   have been checked by the caller using far more specific checks than 
	   the very generic values that we use here, but we perform the check 
	   anyway just to be sure */
	if( length < 1 )
		return( CRYPT_ERROR_BADDATA );
	switch( checkType )
		{
		case BIGNUM_CHECK_NONE:
		case BIGNUM_CHECK_VALUE:
			/* No specific length check for this value */
			break;

		case BIGNUM_CHECK_VALUE_PKC:
			if( length > CRYPT_MAX_PKCSIZE )
				return( CRYPT_ERROR_BADDATA );
			break;

		case BIGNUM_CHECK_VALUE_ECC:
			if( length > CRYPT_MAX_PKCSIZE_ECC )
				return( CRYPT_ERROR_BADDATA );
			break;

		default:
			retIntError();
		}

	/* Check that the bignum data appears valid if required */
	if( checkType != BIGNUM_CHECK_NONE )
		{
		/* Perform a debug-mode check for suspicious bignum data */
		assert_nofuzz( checkEntropyInteger( buffer, length ) );
		}

	/* Convert the byte string into a bignum.  Since the only thing that 
	   this does is format a string of bytes as a BN_ULONGs, the only
	   failure that can occur is a CRYPT_ERROR_INTERNAL */
	if( BN_bin2bn( buffer, length, bignum ) == NULL )
		{
		BN_clear( bignum );
		return( CRYPT_ERROR_INTERNAL );
		}

	/* Check the bignum value that we've just imported */
	status = checkBignum( bignum, minLength, maxLength, maxRange, 
						  checkType );
	if( cryptStatusError( status ) )
		{
		BN_clear( bignum );
		return( status );
		}

	ENSURES( sanityCheckBignum( bignum ) );

	return( CRYPT_OK );
	}

/* Verify that a bignum value corresponds to encoded bignum data */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
BOOLEAN verifyBignumImport( TYPECAST( const BIGNUM * ) \
								const struct BN *bignumPtr, 
							IN_BUFFER( length ) const void *buffer, 
							IN_LENGTH_SHORT const int length )
	{
	const BIGNUM *bignum = ( BIGNUM * ) bignumPtr;
	const BYTE *bufPtr = buffer;
	int index = 0;
	LOOP_INDEX byteCount, wordIndex;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );
	assert( isReadPtrDynamic( buffer, length ) );

	REQUIRES_B( sanityCheckBignum( bignum ) );
	REQUIRES_B( isShortIntegerRange( length ) );

	/* Walk down the bignum a word at a time verifying that the data bytes 
	   correspond to the bignum words.  We can't check bignum->top since the
	   bignum is normalised on import, so it may not correspond exactly to 
	   the data length in bytes */
	LOOP_EXT_REV( ( byteCount = length, wordIndex = bignum->top - 1 ), 
				  byteCount > 0 && wordIndex >= 0, wordIndex--, 
				  BIGNUM_ALLOC_WORDS )
		{
		BN_ULONG value = 0;
		int noBytes = ( ( byteCount - 1 ) % BN_BYTES ) + 1;
		int LOOP_ITERATOR_ALT;

		ENSURES_B( LOOP_INVARIANT_REV( wordIndex, 0, bignum->top - 1 ) );
		ENSURES_B( LOOP_INVARIANT_SECONDARY( byteCount, 1, length ) );

		byteCount -= noBytes;
		LOOP_EXT_REV_CHECKINC_ALT( noBytes > 0, noBytes--, BN_BYTES + 1 )
			{
			ENSURES_B( LOOP_INVARIANT_EXT_REV_XXX_ALT( noBytes, 1, BN_BYTES,
													   BN_BYTES + 1 ) );

			value = ( value << 8 ) | bufPtr[ index++ ];
			}
		ENSURES_B( LOOP_BOUND_EXT_REV_OK_ALT( BN_BYTES + 1 ) );
		if( bignum->d[ wordIndex ] != value )
			{
			DEBUG_DIAG(( "Bignum data memory corruption detected at word %d", 
						 wordIndex ));
			return( FALSE );
			}
		}
	ENSURES_B( LOOP_BOUND_OK );
	ENSURES_B( wordIndex == -1 && byteCount == 0 );

	ENSURES_B( sanityCheckBignum( bignum ) );

	return( TRUE );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

/* Convert a byte string to an ECC point */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int importECCPoint( INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignumPtr1, 
					INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignumPtr2, 
				    IN_BUFFER( length ) const void *buffer, 
				    IN_LENGTH_SHORT const int length,
					IN_LENGTH_PKC const int minLength, 
					IN_LENGTH_PKC const int maxLength, 
					IN_LENGTH_PKC const int fieldSize,
					IN_PTR_OPT TYPECAST( const BIGNUM * ) \
						const struct BN *maxRangePtr,
					IN_ENUM( BIGNUM_CHECK ) \
						const BIGNUM_CHECK_TYPE checkType )
	{
	const BYTE *eccPointData = buffer;
	BIGNUM *bignum1 = ( BIGNUM * ) bignumPtr1;
	BIGNUM *bignum2 = ( BIGNUM * ) bignumPtr2;
	BIGNUM *maxRange = ( BIGNUM * ) maxRangePtr;
	int status;

	assert( isWritePtr( bignum1, sizeof( BIGNUM ) ) );
	assert( isWritePtr( bignum2, sizeof( BIGNUM ) ) );
	assert( isReadPtrDynamic( buffer, length ) );
	assert( maxRange == NULL || isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum1 ) );
	REQUIRES( sanityCheckBignum( bignum2 ) );
	REQUIRES( minLength > 0 && minLength <= maxLength && \
			  maxLength <= CRYPT_MAX_PKCSIZE_ECC );
	REQUIRES( fieldSize >= MIN_PKCSIZE_ECC && \
			  fieldSize <= CRYPT_MAX_PKCSIZE_ECC );
	REQUIRES( maxRange == NULL || sanityCheckBignum( maxRange ) );
	REQUIRES( isEnumRangeOpt( checkType, BIGNUM_CHECK ) );

	/* Make sure that we've been given valid input.  This should already 
	   have been checked by the caller using far more specific checks than 
	   the very generic values that we use here, but we perform the check 
	   anyway just to be sure */
	if( length < MIN_PKCSIZE_ECCPOINT_THRESHOLD || \
		length > MAX_PKCSIZE_ECCPOINT )
		return( CRYPT_ERROR_BADDATA );

	/* Decode the ECC point data.  At this point we run into another 
	   artefact of the chronic indecisiveness of the ECC standards authors, 
	   because of the large variety of ways in which ECC data can be encoded 
	   there's no single way of representing a point.  The only encoding 
	   that's actually of any practical use is the straight (x, y) 
	   coordinate form with no special-case encoding or other tricks, 
	   denoted by an 0x04 byte at the start of the data:

		+---+---------------+---------------+
		|ID	|		qx		|		qy		|
		+---+---------------+---------------+
			|<- fldSize --> |<- fldSize --> |

	   There's also a hybrid form that combines the patent encumbrance of 
	   point compression with the size of the uncompressed form that we 
	   could in theory allow for, but it's unlikely that anyone's going to
	   be crazy enough to use this */
	if( length != 1 + ( fieldSize * 2 ) )
		return( CRYPT_ERROR_BADDATA );
	if( eccPointData[ 0 ] != 0x04 )
		return( CRYPT_ERROR_BADDATA );
	eccPointData++;		/* Skip format type byte */
	status = importBignum( bignum1, eccPointData, fieldSize,
						   minLength, maxLength, maxRange, checkType );
	if( cryptStatusError( status ) )
		return( status );
	status = importBignum( bignum2, eccPointData + fieldSize, fieldSize, 
						   minLength, maxLength, maxRange, checkType );
	if( cryptStatusError( status ) )
		{
		BN_clear( bignum1 );
		return( status );
		}

	ENSURES( sanityCheckBignum( bignum1 ) );
	ENSURES( sanityCheckBignum( bignum2 ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
BOOLEAN verifyECCPointImport( TYPECAST( const BIGNUM * ) \
									const struct BN *bignumPtr1,
							  TYPECAST( const BIGNUM * ) \
									const struct BN *bignumPtr2,	 
							  IN_BUFFER( length ) const void *buffer, 
							  IN_LENGTH_SHORT const int length,
							  IN_LENGTH_PKC const int fieldSize )
	{
	const BIGNUM *bignum1 = ( BIGNUM * ) bignumPtr1;
	const BIGNUM *bignum2 = ( BIGNUM * ) bignumPtr2;
	const BYTE *eccPointData = buffer;

	assert( isReadPtr( bignum1, sizeof( BIGNUM ) ) );
	assert( isReadPtr( bignum2, sizeof( BIGNUM ) ) );
	assert( isReadPtrDynamic( buffer, length ) );

	REQUIRES_B( sanityCheckBignum( bignum1 ) );
	REQUIRES_B( sanityCheckBignum( bignum2 ) );
	REQUIRES_B( isShortIntegerRange( length ) );
	REQUIRES_B( fieldSize >= MIN_PKCSIZE_ECC && \
				fieldSize <= CRYPT_MAX_PKCSIZE_ECC );

	if( eccPointData[ 0 ] != 0x04 )
		return( FALSE );
	if( !verifyBignumImport( bignumPtr1, eccPointData + 1, fieldSize ) )
		return( FALSE );
	if( !verifyBignumImport( bignumPtr2, eccPointData + 1 + fieldSize, 
							 fieldSize ) )
		return( FALSE );

	return( TRUE );
	}
#endif /* USE_ECDH || USE_ECDSA */

/****************************************************************************
*																			*
*								Bignum Export Routines 						*
*																			*
****************************************************************************/

/* Export a bignum to a buffer.  This is a low-level internal routine also
   used by the OpenSSL bignum code, the non-cryptlib-style API is for 
   compatibility purposes */

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1, 2 ) ) \
int BN_bn2bin( const BIGNUM *bignum, BYTE *buffer )
	{
	const int length = BN_num_bytes( bignum );
	int index = 0;
	LOOP_INDEX byteCount, wordIndex;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum ) );
	REQUIRES( length >= 0 && length <= CRYPT_MAX_PKCSIZE );

	/* Walk down the bignum a word at a time extracting the data bytes */
	LOOP_EXT_REV( ( byteCount = length, wordIndex = bignum->top - 1 ),
				  byteCount > 0 && wordIndex >= 0, wordIndex--, 
				  BIGNUM_ALLOC_WORDS )
		{
		const BN_ULONG value = bignum->d[ wordIndex ];
		int noBytes = ( ( byteCount - 1 ) % BN_BYTES ) + 1;
		int LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_REV( wordIndex, 0, bignum->top - 1 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( byteCount, 1, length ) );

		byteCount -= noBytes;
		LOOP_EXT_REV_CHECKINC_ALT( noBytes > 0, noBytes--, BN_BYTES + 1 )
			{
			const int shiftAmount = ( noBytes - 1 ) * 8;

			ENSURES( LOOP_INVARIANT_EXT_REV_XXX_ALT( noBytes, 1, BN_BYTES,
													 BN_BYTES + 1 ) );

			buffer[ index++ ] = intToByte( value >> shiftAmount );
			}
		ENSURES( LOOP_BOUND_EXT_REV_OK_ALT( BN_BYTES + 1 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( wordIndex == -1 && byteCount == 0 );

	return( length );
	}

/* Convert a BIGNUM value to a byte string */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int exportBignum( OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				  IN_LENGTH_SHORT_MIN( 16 ) const int dataMaxLength, 
				  OUT_LENGTH_BOUNDED_Z( dataMaxLength ) int *dataLength,
				  IN_PTR TYPECAST( BIGNUM * ) const struct BN *bignumPtr )
	{
	BIGNUM *bignum = ( BIGNUM * ) bignumPtr;
	int length, result;

	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 16 ) );
	REQUIRES( sanityCheckBignum( bignum ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* Make sure that the result will fit into the output buffer */
	length = BN_num_bytes( bignum );
	ENSURES( length > 0 && length <= CRYPT_MAX_PKCSIZE );
	if( length > dataMaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Export the bignum into the output buffer */
	result = BN_bn2bin( bignum, data );
	ENSURES( result == length );
	*dataLength = length;

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

/* Convert an ECC point to a byte string */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 4, 5 ) ) \
int exportECCPoint( OUT_BUFFER_OPT( dataMaxLength, *dataLength ) void *data, 
					IN_LENGTH_SHORT_Z const int dataMaxLength, 
					OUT_LENGTH_BOUNDED_PKC_Z( dataMaxLength ) int *dataLength,
					IN_PTR TYPECAST( BIGNUM * ) const struct BN *bignumPtr1, 
					IN_PTR TYPECAST( BIGNUM * ) const struct BN *bignumPtr2,
					IN_LENGTH_PKC const int fieldSize )
	{
	BIGNUM *bignum1 = ( BIGNUM * ) bignumPtr1;
	BIGNUM *bignum2 = ( BIGNUM * ) bignumPtr2;
	BYTE *bufPtr = data;
	int length, result;

	assert( data == NULL || isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( isReadPtr( bignum1, sizeof( BIGNUM ) ) );
	assert( isReadPtr( bignum2, sizeof( BIGNUM ) ) );

	REQUIRES( ( data == NULL && dataMaxLength == 0 ) || \
			  ( data != NULL && \
				isShortIntegerRangeMin( dataMaxLength, 16 ) ) );
	REQUIRES( sanityCheckBignum( bignum1 ) );
	REQUIRES( sanityCheckBignum( bignum2 ) );
	REQUIRES( fieldSize >= MIN_PKCSIZE_ECC && \
			  fieldSize <= CRYPT_MAX_PKCSIZE_ECC );

	/* Clear return values */
	if( data != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
		memset( data, 0, min( 16, dataMaxLength ) );
		}
	*dataLength = 0;

	/* If it's just an encoding-length check then there's nothing to do */
	if( data == NULL )
		{
		*dataLength = 1 + ( fieldSize * 2 );
		return( CRYPT_OK );
		}

	/* Encode the ECC point data, which consists of the Q coordinates 
	   stuffed into a byte string with an encoding-specifier byte 0x04 at 
	   the start:

		+---+---------------+---------------+
		|ID	|		qx		|		qy		|
		+---+---------------+---------------+
			|<-- fldSize -> |<- fldSize --> | */
	if( 1 + ( fieldSize * 2 ) > dataMaxLength )
		return( CRYPT_ERROR_OVERFLOW );
	*bufPtr++ = 0x04;
	REQUIRES( rangeCheck( fieldSize, MIN_PKCSIZE_ECC, 
						  CRYPT_MAX_PKCSIZE_ECC ) );
	memset( bufPtr, 0, fieldSize * 2 );
	length = BN_num_bytes( bignum1 );
	ENSURES( length > 0 && length <= fieldSize );
	result = BN_bn2bin( bignum1, bufPtr + ( fieldSize - length ) );
	ENSURES( result == length );
	bufPtr += fieldSize;
	length = BN_num_bytes( bignum2 );
	ENSURES( length > 0 && length <= fieldSize );
	result = BN_bn2bin( bignum2, bufPtr + ( fieldSize - length ) );
	ENSURES( result == length );
	*dataLength = 1 + ( fieldSize * 2 );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */

#endif /* USE_PKC */
=======
/****************************************************************************
*																			*
*					cryptlib Bignum Import/Export Routines					*
*						Copyright Peter Gutmann 1995-2015					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
#else
  #include "context/context.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKC

/****************************************************************************
*																			*
*								Utility Routines 							*
*																			*
****************************************************************************/

/* Dump a bignum as a C structure, used for hardcoding constant values like
   DLP and ECDLP domain parameters from their bignum representations */

#if defined( DEBUG_DIAGNOSTIC_ENABLE ) && !defined( NDEBUG )

#if BN_BITS2 == 64
  #define BNULONG_FORMAT	"0x%016llXULL"
  #define BNULONG_PER_LINE	2
#else
  #define BNULONG_FORMAT	"0x%08X"
  #define BNULONG_PER_LINE	4
#endif /* 64- vs 32-bit */

void printBignum( const BIGNUM *bignum, const char *label )
	{
	const BN_ULONG *data = bignum->d;
	LOOP_INDEX i;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );
	assert( isReadPtr( label, 2 ) );

	DEBUG_PRINT(( "\t/* %s */\n\t", label ));
	DEBUG_PRINT(( "{ %d, FALSE, BN_FLG_STATIC_DATA, {\n\t", 
				  bignum->top ));
	LOOP_EXT( i = 0, i < bignum->top, i++, BIGNUM_ALLOC_WORDS )
		{
		ENSURES_V( LOOP_INVARIANT_EXT( i, 0, bignum->top - 1,
									   BIGNUM_ALLOC_WORDS ) );

		DEBUG_PRINT(( BNULONG_FORMAT, data[ i ] ));
		if( i < bignum->top - 1 )
			{
			DEBUG_PRINT(( ", " ));
			if( i > 0 && !( ( i + 1 ) & ( BNULONG_PER_LINE - 1 ) ) )
				DEBUG_PRINT(( "\n\t" ));
			}
		}
	ENSURES_V( LOOP_BOUND_OK );
	DEBUG_PRINT(( " } },\n" ));
	}
#endif /* DEBUG_DIAGNOSTIC_ENABLE && Debug */

/****************************************************************************
*																			*
*								Bignum Import Routines 						*
*																			*
****************************************************************************/

/* Check that an imported bignum value is valid */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkBignum( const BIGNUM *bignum,
						IN_LENGTH_PKC const int minLength, 
						IN_LENGTH_PKC const int maxLength, 
						IN_PTR_OPT const BIGNUM *maxRange,
						IN_ENUM_OPT( BIGNUM_CHECK ) \
							const BIGNUM_CHECK_TYPE checkType )
	{
	int bignumLengthBits, status;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );
	assert( maxRange == NULL || isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum ) );
	REQUIRES( minLength > 0 && minLength <= maxLength && \
			  maxLength <= CRYPT_MAX_PKCSIZE );
	REQUIRES( maxRange == NULL || sanityCheckBignum( maxRange ) );
	REQUIRES( isEnumRangeOpt( checkType, BIGNUM_CHECK ) );

	/* The following should never happen because BN_bin2bn() works with 
	   unsigned values but we perform the check anyway just in case someone 
	   messes with the underlying bignum code */
	ENSURES( !( BN_is_negative( bignum ) ) )

	/* A zero- or one-valued bignum on the other hand is an error because we 
	   should never find zero or one in a PKC-related value.  This check is 
	   somewhat redundant with the one that follows, we place it here to 
	   make it explicit and because the cost is near zero */
	if( BN_cmp_word( bignum, 1 ) <= 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Check that the bignum value falls within the allowed length range.  
	   Before we do the general length check we perform a more specific 
	   check for the case where the length is below the minimum allowed but 
	   still looks at least vaguely valid, in which case we report it as a 
	   too-short key rather than a bad data error.
	   
	   Note that we check the length in bits rather than bytes since the 
	   latter is rounded up, so a length that passes the check based on
	   its rounded-up byte-length value can then fail a later check based 
	   on its actual length in bits */
	status = bignumLengthBits = BN_num_bits( bignum );
	if( cryptStatusError( status ) )
		return( status );
	switch( checkType )
		{
		case BIGNUM_CHECK_NONE:
		case BIGNUM_CHECK_VALUE:
			/* No specific weak-key check for this value */
			break;

		case BIGNUM_CHECK_VALUE_PKC:
			if( isShortPKCKey( bitsToBytes( bignumLengthBits ) ) )
				return( CRYPT_ERROR_NOSECURE );
			break;

		case BIGNUM_CHECK_VALUE_ECC:
			if( isShortECCKey( bitsToBytes( bignumLengthBits ) ) )
				return( CRYPT_ERROR_NOSECURE );
			break;

		default:
			retIntError();
		}

	/* Check that the value is within range.  We have to be a bit careful
	   here when doing a bit-length based comparison because the minimum
	   length that can be specified as a byte is 8 bits, so if minLength == 1
	   then we allow any bit-length >= 2 bits, used for DH g values */
	if( minLength == 1 )
		{
		if( bignumLengthBits < 2 || \
			bignumLengthBits > bytesToBits( maxLength ) )
			return( CRYPT_ERROR_BADDATA );
		}
	else
		{
		if( bignumLengthBits < bytesToBits( minLength ) || \
			bignumLengthBits > bytesToBits( maxLength ) )
			return( CRYPT_ERROR_BADDATA );
		}

	/* Finally, if the caller has supplied a maximum-range bignum value, 
	   make sure that the value that we've read is less than this */
	if( maxRange != NULL && BN_cmp( bignum, maxRange ) >= 0 )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

/* Import a bignum from a buffer.  This is a low-level internal routine also
   used by the OpenSSL bignum code, the non-cryptlib-style API is for 
   compatibility purposes */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 3 ) ) \
BIGNUM *BN_bin2bn( IN_BUFFER( length ) const BYTE *buffer, 
				   IN_LENGTH_PKC_Z const int length, 
				   OUT_PTR BIGNUM *bignum )
	{
	int index = 0, bnStatus = BN_STATUS;
	LOOP_INDEX byteCount, wordIndex;

	assert( length == 0 || isReadPtrDynamic( buffer, length ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES_N( length >= 0 && length <= CRYPT_MAX_PKCSIZE );
	REQUIRES_N( sanityCheckBignum( bignum ) );

	/* Clear return value */
	BN_clear( bignum );

	/* Bignums with value zero are special-cased since they have a length of
	   zero */
	if( length <= 0 )
		return( bignum );

	/* Walk down the bignum a word at a time adding the data bytes */
	bignum->top = ( ( length - 1 ) / BN_BYTES ) + 1;
	LOOP_EXT_REV( ( byteCount = length, wordIndex = bignum->top - 1 ), 
				  byteCount > 0 && wordIndex >= 0, wordIndex--, 
				  BIGNUM_ALLOC_WORDS )
		{
		BN_ULONG value = 0;
		int noBytes = ( ( byteCount - 1 ) % BN_BYTES ) + 1;
		int LOOP_ITERATOR_ALT;

		ENSURES_N( LOOP_INVARIANT_REV( wordIndex, 0, bignum->top - 1 ) )
		ENSURES_N( LOOP_INVARIANT_SECONDARY( byteCount, 1, length ) );

		byteCount -= noBytes;
		LOOP_EXT_REV_CHECKINC_ALT( noBytes > 0, noBytes--, BN_BYTES + 1 )
			{
			ENSURES_N( LOOP_INVARIANT_EXT_REV_XXX_ALT( noBytes, 1, BN_BYTES,
													   BN_BYTES + 1 ) );

			value = ( value << 8 ) | buffer[ index++ ];
			}
		ENSURES_N( LOOP_BOUND_EXT_REV_OK_ALT( BN_BYTES + 1 ) );
		bignum->d[ wordIndex ] = value;
		}
	ENSURES_N( LOOP_BOUND_EXT_REV_OK( BIGNUM_ALLOC_WORDS ) );
	ENSURES_N( wordIndex == -1 && byteCount == 0 );

	/* Now that we've imported the raw data value, convert it to 
	   normalised form */
	CK( BN_normalise( bignum ) );
	if( bnStatusError( bnStatus ) )
		return( NULL );

	ENSURES_N( sanityCheckBignum( bignum ) );

	return( bignum );
	}

/* Convert a byte string to a BIGNUM value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int importBignum( INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignumPtr, 
				  IN_BUFFER( length ) const void *buffer, 
				  IN_LENGTH_SHORT const int length,
				  IN_LENGTH_PKC const int minLength, 
				  IN_RANGE( 1, CRYPT_MAX_PKCSIZE + DLP_OVERFLOW_SIZE ) \
					const int maxLength,
				  IN_PTR_OPT TYPECAST( BIGNUM * ) \
					const struct BN *maxRangePtr,
				  IN_ENUM_OPT( BIGNUM_CHECK ) \
					const BIGNUM_CHECK_TYPE checkType )
	{
	BIGNUM *bignum = ( BIGNUM * ) bignumPtr;
	BIGNUM *maxRange = ( BIGNUM * ) maxRangePtr;
	int status;

	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );
	assert( isReadPtrDynamic( buffer, length ) );
	assert( maxRange == NULL || isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum ) );
	REQUIRES( isShortIntegerRange( length ) );
	REQUIRES( minLength > 0 && minLength <= maxLength && \
			  maxLength <= CRYPT_MAX_PKCSIZE );
	REQUIRES( maxRange == NULL || sanityCheckBignum( maxRange ) );
	REQUIRES( isEnumRangeOpt( checkType, BIGNUM_CHECK ) );

	/* Make sure that we've been given valid input.  This should already 
	   have been checked by the caller using far more specific checks than 
	   the very generic values that we use here, but we perform the check 
	   anyway just to be sure */
	if( length < 1 )
		return( CRYPT_ERROR_BADDATA );
	switch( checkType )
		{
		case BIGNUM_CHECK_NONE:
		case BIGNUM_CHECK_VALUE:
			/* No specific length check for this value */
			break;

		case BIGNUM_CHECK_VALUE_PKC:
			if( length > CRYPT_MAX_PKCSIZE )
				return( CRYPT_ERROR_BADDATA );
			break;

		case BIGNUM_CHECK_VALUE_ECC:
			if( length > CRYPT_MAX_PKCSIZE_ECC )
				return( CRYPT_ERROR_BADDATA );
			break;

		default:
			retIntError();
		}

	/* Check that the bignum data appears valid if required */
	if( checkType != BIGNUM_CHECK_NONE )
		{
		/* Perform a debug-mode check for suspicious bignum data */
		assert_nofuzz( checkEntropyInteger( buffer, length ) );
		}

	/* Convert the byte string into a bignum.  Since the only thing that 
	   this does is format a string of bytes as a BN_ULONGs, the only
	   failure that can occur is a CRYPT_ERROR_INTERNAL */
	if( BN_bin2bn( buffer, length, bignum ) == NULL )
		{
		BN_clear( bignum );
		return( CRYPT_ERROR_INTERNAL );
		}

	/* Check the bignum value that we've just imported */
	status = checkBignum( bignum, minLength, maxLength, maxRange, 
						  checkType );
	if( cryptStatusError( status ) )
		{
		BN_clear( bignum );
		return( status );
		}

	ENSURES( sanityCheckBignum( bignum ) );

	return( CRYPT_OK );
	}

/* Verify that a bignum value corresponds to encoded bignum data */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
BOOLEAN verifyBignumImport( TYPECAST( const BIGNUM * ) \
								const struct BN *bignumPtr, 
							IN_BUFFER( length ) const void *buffer, 
							IN_LENGTH_SHORT const int length )
	{
	const BIGNUM *bignum = ( BIGNUM * ) bignumPtr;
	const BYTE *bufPtr = buffer;
	int index = 0;
	LOOP_INDEX byteCount, wordIndex;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );
	assert( isReadPtrDynamic( buffer, length ) );

	REQUIRES_B( sanityCheckBignum( bignum ) );
	REQUIRES_B( isShortIntegerRange( length ) );

	/* Walk down the bignum a word at a time verifying that the data bytes 
	   correspond to the bignum words.  We can't check bignum->top since the
	   bignum is normalised on import, so it may not correspond exactly to 
	   the data length in bytes */
	LOOP_EXT_REV( ( byteCount = length, wordIndex = bignum->top - 1 ), 
				  byteCount > 0 && wordIndex >= 0, wordIndex--, 
				  BIGNUM_ALLOC_WORDS )
		{
		BN_ULONG value = 0;
		int noBytes = ( ( byteCount - 1 ) % BN_BYTES ) + 1;
		int LOOP_ITERATOR_ALT;

		ENSURES_B( LOOP_INVARIANT_REV( wordIndex, 0, bignum->top - 1 ) );
		ENSURES_B( LOOP_INVARIANT_SECONDARY( byteCount, 1, length ) );

		byteCount -= noBytes;
		LOOP_EXT_REV_CHECKINC_ALT( noBytes > 0, noBytes--, BN_BYTES + 1 )
			{
			ENSURES_B( LOOP_INVARIANT_EXT_REV_XXX_ALT( noBytes, 1, BN_BYTES,
													   BN_BYTES + 1 ) );

			value = ( value << 8 ) | bufPtr[ index++ ];
			}
		ENSURES_B( LOOP_BOUND_EXT_REV_OK_ALT( BN_BYTES + 1 ) );
		if( bignum->d[ wordIndex ] != value )
			{
			DEBUG_DIAG(( "Bignum data memory corruption detected at word %d", 
						 wordIndex ));
			return( FALSE );
			}
		}
	ENSURES_B( LOOP_BOUND_OK );
	ENSURES_B( wordIndex == -1 && byteCount == 0 );

	ENSURES_B( sanityCheckBignum( bignum ) );

	return( TRUE );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

/* Convert a byte string to an ECC point */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int importECCPoint( INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignumPtr1, 
					INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignumPtr2, 
				    IN_BUFFER( length ) const void *buffer, 
				    IN_LENGTH_SHORT const int length,
					IN_LENGTH_PKC const int minLength, 
					IN_LENGTH_PKC const int maxLength, 
					IN_LENGTH_PKC const int fieldSize,
					IN_PTR_OPT TYPECAST( const BIGNUM * ) \
						const struct BN *maxRangePtr,
					IN_ENUM( BIGNUM_CHECK ) \
						const BIGNUM_CHECK_TYPE checkType )
	{
	const BYTE *eccPointData = buffer;
	BIGNUM *bignum1 = ( BIGNUM * ) bignumPtr1;
	BIGNUM *bignum2 = ( BIGNUM * ) bignumPtr2;
	BIGNUM *maxRange = ( BIGNUM * ) maxRangePtr;
	int status;

	assert( isWritePtr( bignum1, sizeof( BIGNUM ) ) );
	assert( isWritePtr( bignum2, sizeof( BIGNUM ) ) );
	assert( isReadPtrDynamic( buffer, length ) );
	assert( maxRange == NULL || isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum1 ) );
	REQUIRES( sanityCheckBignum( bignum2 ) );
	REQUIRES( minLength > 0 && minLength <= maxLength && \
			  maxLength <= CRYPT_MAX_PKCSIZE_ECC );
	REQUIRES( fieldSize >= MIN_PKCSIZE_ECC && \
			  fieldSize <= CRYPT_MAX_PKCSIZE_ECC );
	REQUIRES( maxRange == NULL || sanityCheckBignum( maxRange ) );
	REQUIRES( isEnumRangeOpt( checkType, BIGNUM_CHECK ) );

	/* Make sure that we've been given valid input.  This should already 
	   have been checked by the caller using far more specific checks than 
	   the very generic values that we use here, but we perform the check 
	   anyway just to be sure */
	if( length < MIN_PKCSIZE_ECCPOINT_THRESHOLD || \
		length > MAX_PKCSIZE_ECCPOINT )
		return( CRYPT_ERROR_BADDATA );

	/* Decode the ECC point data.  At this point we run into another 
	   artefact of the chronic indecisiveness of the ECC standards authors, 
	   because of the large variety of ways in which ECC data can be encoded 
	   there's no single way of representing a point.  The only encoding 
	   that's actually of any practical use is the straight (x, y) 
	   coordinate form with no special-case encoding or other tricks, 
	   denoted by an 0x04 byte at the start of the data:

		+---+---------------+---------------+
		|ID	|		qx		|		qy		|
		+---+---------------+---------------+
			|<- fldSize --> |<- fldSize --> |

	   There's also a hybrid form that combines the patent encumbrance of 
	   point compression with the size of the uncompressed form that we 
	   could in theory allow for, but it's unlikely that anyone's going to
	   be crazy enough to use this */
	if( length != 1 + ( fieldSize * 2 ) )
		return( CRYPT_ERROR_BADDATA );
	if( eccPointData[ 0 ] != 0x04 )
		return( CRYPT_ERROR_BADDATA );
	eccPointData++;		/* Skip format type byte */
	status = importBignum( bignum1, eccPointData, fieldSize,
						   minLength, maxLength, maxRange, checkType );
	if( cryptStatusError( status ) )
		return( status );
	status = importBignum( bignum2, eccPointData + fieldSize, fieldSize, 
						   minLength, maxLength, maxRange, checkType );
	if( cryptStatusError( status ) )
		{
		BN_clear( bignum1 );
		return( status );
		}

	ENSURES( sanityCheckBignum( bignum1 ) );
	ENSURES( sanityCheckBignum( bignum2 ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
BOOLEAN verifyECCPointImport( TYPECAST( const BIGNUM * ) \
									const struct BN *bignumPtr1,
							  TYPECAST( const BIGNUM * ) \
									const struct BN *bignumPtr2,	 
							  IN_BUFFER( length ) const void *buffer, 
							  IN_LENGTH_SHORT const int length,
							  IN_LENGTH_PKC const int fieldSize )
	{
	const BIGNUM *bignum1 = ( BIGNUM * ) bignumPtr1;
	const BIGNUM *bignum2 = ( BIGNUM * ) bignumPtr2;
	const BYTE *eccPointData = buffer;

	assert( isReadPtr( bignum1, sizeof( BIGNUM ) ) );
	assert( isReadPtr( bignum2, sizeof( BIGNUM ) ) );
	assert( isReadPtrDynamic( buffer, length ) );

	REQUIRES_B( sanityCheckBignum( bignum1 ) );
	REQUIRES_B( sanityCheckBignum( bignum2 ) );
	REQUIRES_B( isShortIntegerRange( length ) );
	REQUIRES_B( fieldSize >= MIN_PKCSIZE_ECC && \
				fieldSize <= CRYPT_MAX_PKCSIZE_ECC );

	if( eccPointData[ 0 ] != 0x04 )
		return( FALSE );
	if( !verifyBignumImport( bignumPtr1, eccPointData + 1, fieldSize ) )
		return( FALSE );
	if( !verifyBignumImport( bignumPtr2, eccPointData + 1 + fieldSize, 
							 fieldSize ) )
		return( FALSE );

	return( TRUE );
	}
#endif /* USE_ECDH || USE_ECDSA */

/****************************************************************************
*																			*
*								Bignum Export Routines 						*
*																			*
****************************************************************************/

/* Export a bignum to a buffer.  This is a low-level internal routine also
   used by the OpenSSL bignum code, the non-cryptlib-style API is for 
   compatibility purposes */

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1, 2 ) ) \
int BN_bn2bin( const BIGNUM *bignum, BYTE *buffer )
	{
	const int length = BN_num_bytes( bignum );
	int index = 0;
	LOOP_INDEX byteCount, wordIndex;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum ) );
	REQUIRES( length >= 0 && length <= CRYPT_MAX_PKCSIZE );

	/* Walk down the bignum a word at a time extracting the data bytes */
	LOOP_EXT_REV( ( byteCount = length, wordIndex = bignum->top - 1 ),
				  byteCount > 0 && wordIndex >= 0, wordIndex--, 
				  BIGNUM_ALLOC_WORDS )
		{
		const BN_ULONG value = bignum->d[ wordIndex ];
		int noBytes = ( ( byteCount - 1 ) % BN_BYTES ) + 1;
		int LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_REV( wordIndex, 0, bignum->top - 1 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( byteCount, 1, length ) );

		byteCount -= noBytes;
		LOOP_EXT_REV_CHECKINC_ALT( noBytes > 0, noBytes--, BN_BYTES + 1 )
			{
			const int shiftAmount = ( noBytes - 1 ) * 8;

			ENSURES( LOOP_INVARIANT_EXT_REV_XXX_ALT( noBytes, 1, BN_BYTES,
													 BN_BYTES + 1 ) );

			buffer[ index++ ] = intToByte( value >> shiftAmount );
			}
		ENSURES( LOOP_BOUND_EXT_REV_OK_ALT( BN_BYTES + 1 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( wordIndex == -1 && byteCount == 0 );

	return( length );
	}

/* Convert a BIGNUM value to a byte string */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int exportBignum( OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				  IN_LENGTH_SHORT_MIN( 16 ) const int dataMaxLength, 
				  OUT_LENGTH_BOUNDED_Z( dataMaxLength ) int *dataLength,
				  IN_PTR TYPECAST( BIGNUM * ) const struct BN *bignumPtr )
	{
	BIGNUM *bignum = ( BIGNUM * ) bignumPtr;
	int length, result;

	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 16 ) );
	REQUIRES( sanityCheckBignum( bignum ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* Make sure that the result will fit into the output buffer */
	length = BN_num_bytes( bignum );
	ENSURES( length > 0 && length <= CRYPT_MAX_PKCSIZE );
	if( length > dataMaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Export the bignum into the output buffer */
	result = BN_bn2bin( bignum, data );
	ENSURES( result == length );
	*dataLength = length;

	return( CRYPT_OK );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

/* Convert an ECC point to a byte string */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 4, 5 ) ) \
int exportECCPoint( OUT_BUFFER_OPT( dataMaxLength, *dataLength ) void *data, 
					IN_LENGTH_SHORT_Z const int dataMaxLength, 
					OUT_LENGTH_BOUNDED_PKC_Z( dataMaxLength ) int *dataLength,
					IN_PTR TYPECAST( BIGNUM * ) const struct BN *bignumPtr1, 
					IN_PTR TYPECAST( BIGNUM * ) const struct BN *bignumPtr2,
					IN_LENGTH_PKC const int fieldSize )
	{
	BIGNUM *bignum1 = ( BIGNUM * ) bignumPtr1;
	BIGNUM *bignum2 = ( BIGNUM * ) bignumPtr2;
	BYTE *bufPtr = data;
	int length, result;

	assert( data == NULL || isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( isReadPtr( bignum1, sizeof( BIGNUM ) ) );
	assert( isReadPtr( bignum2, sizeof( BIGNUM ) ) );

	REQUIRES( ( data == NULL && dataMaxLength == 0 ) || \
			  ( data != NULL && \
				isShortIntegerRangeMin( dataMaxLength, 16 ) ) );
	REQUIRES( sanityCheckBignum( bignum1 ) );
	REQUIRES( sanityCheckBignum( bignum2 ) );
	REQUIRES( fieldSize >= MIN_PKCSIZE_ECC && \
			  fieldSize <= CRYPT_MAX_PKCSIZE_ECC );

	/* Clear return values */
	if( data != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
		memset( data, 0, min( 16, dataMaxLength ) );
		}
	*dataLength = 0;

	/* If it's just an encoding-length check then there's nothing to do */
	if( data == NULL )
		{
		*dataLength = 1 + ( fieldSize * 2 );
		return( CRYPT_OK );
		}

	/* Encode the ECC point data, which consists of the Q coordinates 
	   stuffed into a byte string with an encoding-specifier byte 0x04 at 
	   the start:

		+---+---------------+---------------+
		|ID	|		qx		|		qy		|
		+---+---------------+---------------+
			|<-- fldSize -> |<- fldSize --> | */
	if( 1 + ( fieldSize * 2 ) > dataMaxLength )
		return( CRYPT_ERROR_OVERFLOW );
	*bufPtr++ = 0x04;
	REQUIRES( rangeCheck( fieldSize, MIN_PKCSIZE_ECC, 
						  CRYPT_MAX_PKCSIZE_ECC ) );
	memset( bufPtr, 0, fieldSize * 2 );
	length = BN_num_bytes( bignum1 );
	ENSURES( length > 0 && length <= fieldSize );
	result = BN_bn2bin( bignum1, bufPtr + ( fieldSize - length ) );
	ENSURES( result == length );
	bufPtr += fieldSize;
	length = BN_num_bytes( bignum2 );
	ENSURES( length > 0 && length <= fieldSize );
	result = BN_bn2bin( bignum2, bufPtr + ( fieldSize - length ) );
	ENSURES( result == length );
	*dataLength = 1 + ( fieldSize * 2 );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */

#endif /* USE_PKC */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
