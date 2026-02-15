/****************************************************************************
*																			*
*				Miscellaneous (Non-ASN.1) Read/Write Routines				*
*						Copyright Peter Gutmann 1992-2022					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "bn.h"
  #include "misc_rw.h"
#else
  #include "crypt.h"
  #include "bn/bn.h"
  #include "enc_dec/misc_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Read large integer data */

typedef enum {
	LENGTH_NONE,		/* No length type */
	LENGTH_8,			/* Byte string, 8-bit length (used in TLS) */
	LENGTH_16U,			/* Unsigned int, 16-bit length */
	LENGTH_16U_BITS,	/* Unsigned int, 16-bit length, length in bits */
	LENGTH_32,			/* Signed int, 32-bit length */
	LENGTH_LAST			/* Last possible length type */
	} LENGTH_TYPE;

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int readInteger( INOUT_PTR STREAM *stream, 
						OUT_BUFFER_OPT( maxLength, \
										*integerLength ) void *integer, 
						OUT_LENGTH_BOUNDED_Z( maxLength ) int *integerLength,
						IN_LENGTH_PKC const int minLength, 
						IN_LENGTH_PKC const int maxLength,
						IN_ENUM( LENGTH ) const LENGTH_TYPE lengthType,
						IN_ENUM_OPT( BIGNUM_CHECK ) \
							const BIGNUM_CHECK_TYPE checkType )
	{
	int length, i, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( integer == NULL || isWritePtrDynamic( integer, maxLength ) );
	assert( isWritePtr( integerLength, sizeof( int ) ) );

	REQUIRES_S( ( checkType == BIGNUM_CHECK_VALUE_FIXEDLEN && \
				  minLength >= MIN_PKCSIZE_BERNSTEIN && \
				  minLength == maxLength ) || \
				( minLength > 0 && minLength < maxLength && \
				  maxLength <= CRYPT_MAX_PKCSIZE ) );
	REQUIRES_S( isEnumRange( lengthType, LENGTH ) );
	REQUIRES_S( isEnumRangeOpt( checkType, BIGNUM_CHECK ) );

	/* Clear return values */
	if( integer != NULL )
		{
		REQUIRES( rangeCheck( maxLength, 1, CRYPT_MAX_PKCSIZE ) ); 
		memset( integer, 0, min( 16, maxLength ) );
		}
	*integerLength = 0;

	/* Read the length and make sure that it's within range, with a 2-byte 
	   allowance for extra zero-padding (the exact length will be checked 
	   later after the padding is stripped) */
	if( lengthType == LENGTH_16U || lengthType == LENGTH_16U_BITS )
		status = length = readUint16( stream );
	else
		status = length = readUint32( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( lengthType == LENGTH_16U_BITS )
		length = bitsToBytes( length );

	/* Check that the bignum value falls within the allowed length range.  
	   Before we do the general length check we perform a more specific 
	   check for the case where the length is below the minimum allowed but 
	   still looks at least vaguely valid, in which case we report it as a 
	   too-short key rather than a bad data error */
	switch( checkType )
		{
		case BIGNUM_CHECK_NONE:
		case BIGNUM_CHECK_VALUE:
			/* No specific weak-key check for this value */
			break;

		case BIGNUM_CHECK_VALUE_PKC:
			if( isShortPKCKey( length ) )
				return( CRYPT_ERROR_NOSECURE );
			break;

		case BIGNUM_CHECK_VALUE_ECC:
			if( isShortECCKey( length ) )
				return( CRYPT_ERROR_NOSECURE );
			break;

		case BIGNUM_CHECK_VALUE_FIXEDLEN:
			if( length != minLength )
				return( CRYPT_ERROR_NOSECURE );
			break;
		
		default:
			retIntError();
		}
	if( length < minLength || length > maxLength + 2 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* If it's a fixed-length encoding then there's nothing further to do */
	if( checkType == BIGNUM_CHECK_VALUE_FIXEDLEN )
		{
		*integerLength = length;
		if( integer == NULL )
			return( sSkip( stream, length, MAX_INTLENGTH_SHORT ) );
		REQUIRES_S( rangeCheck( length, 1, maxLength ) );
		return( sread( stream, integer, length ) );
		}

	/* If we're reading a signed integer then the sign bit can't be set 
	   since this would produce a negative value.  This differs from the 
	   ASN.1 code, where the incorrect setting of the sign bit is so common 
	   that we always treat integers as unsigned */
	if( lengthType == LENGTH_32 && ( sPeek( stream ) & 0x80 ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Skip up to 8 bytes of possible leading-zero padding and repeat the 
	   length check once the zero-padding has been adjusted */
	LOOP_SMALL( i = 0, length > 0 && sPeek( stream ) == 0 && i < 8, 
				( i++, length-- ) )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 7 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( length, 1, 
										   CRYPT_MAX_PKCSIZE + 2 ) );
				 /* maxLength <= CRYPT_MAX_PKCSIZE, length is checked 
				    against 'maxLength + 2' above */

		status = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );
	if( i >= 8 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Repeat the earlier check on the adjusted value */
	switch( checkType )
		{
		case BIGNUM_CHECK_NONE:
		case BIGNUM_CHECK_VALUE:
			/* No specific weak-key check for this value */
			break;

		case BIGNUM_CHECK_VALUE_PKC:
			if( isShortPKCKey( length ) )
				return( CRYPT_ERROR_NOSECURE );
			break;

		case BIGNUM_CHECK_VALUE_ECC:
			if( isShortECCKey( length ) )
				return( CRYPT_ERROR_NOSECURE );
			break;

		default:
			retIntError();
		}
	if( length < minLength || length > maxLength )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );

	/* Read the value */
	*integerLength = length;
	if( integer == NULL )
		return( sSkip( stream, length, MAX_INTLENGTH_SHORT ) );
	REQUIRES_S( rangeCheck( length, 1, maxLength ) );
	status = sread( stream, integer, length );
	if( cryptStatusError( status ) )
		return( status );

	/* Check that the data appears valid if required */
	if( checkType != BIGNUM_CHECK_NONE )
		{
		/* Perform a debug-mode check for suspicious bignum data */
		assert_notest( checkEntropyInteger( integer, length ) );
		}
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Data Read Routines							*
*																			*
****************************************************************************/

/* Read 16- and 32-bit integer values */

RETVAL_RANGE( 0, 0xFFFF ) STDC_NONNULL_ARG( ( 1 ) ) \
int readUint16( INOUT_PTR STREAM *stream )
	{
	BYTE buffer[ UINT16_SIZE + 8 ];
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sread( stream, buffer, UINT16_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	value = ( byteToInt( buffer[ 0 ] ) << 8 ) | byteToInt( buffer[ 1 ] );
	if( !isIntegerRange( value ) || value > 0xFFFFL )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( value );
	}

RETVAL_RANGE( 0, INT_MAX ) STDC_NONNULL_ARG( ( 1 ) ) \
int readUint32( INOUT_PTR STREAM *stream )
	{
	BYTE buffer[ UINT32_SIZE + 8 ];
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sread( stream, buffer, UINT32_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( buffer[ 0 ] & 0x80 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	value = ( byteToInt( buffer[ 0 ] ) << 24 ) | \
			( byteToInt( buffer[ 1 ] ) << 16 ) | \
			( byteToInt( buffer[ 2 ] ) << 8 ) | \
			  byteToInt( buffer[ 3 ] );
	if( !isIntegerRange( value ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( value );
	}

/* Read 32-bit time values */

RETVAL_RANGE( 0, INT_MAX ) STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readUint32Time( INOUT_PTR STREAM *stream, 
					OUT_PTR time_t *timeVal )
	{
	BYTE buffer[ UINT32_SIZE + 8 ];
	time_t value;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( timeVal, sizeof( time_t ) ) );

	/* Clear return value */
	*timeVal = 0;

	/* Read the time, with a check for overflow on systems with 32-bit 
	   time_t's.  This is a bit of a problem because if we simply reject 
	   the value we'll Y2038 ourselves (although the value would be
	   rejected later anyway when it fails a time range check), so we
	   clamp it to MAX_TIME_VALUE and let the user know in debug mode.
	   Fortunately many 32-bit systems switched to a 64-bit time_t so
	   it'll likely only affect a small remnant, mostly RTOSes, and in
	   any case the only place where it's currently used is when reading 
	   creation times of PGP keys which are unlikely to be used on 
	   VxWorks */
	status = sread( stream, buffer, UINT32_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( sizeof( time_t ) <= 4 && ( buffer[ 0 ] & 0x80 ) )
		{
		assert( DEBUG_WARN );
		*timeVal = MAX_TIME_VALUE;
		return( CRYPT_OK );
		}
	value = ( ( ( time_t ) buffer[ 0 ] ) << 24 ) | \
			( ( ( time_t ) buffer[ 1 ] ) << 16 ) | \
			( ( ( time_t ) buffer[ 2 ] ) << 8 ) | \
				( time_t ) buffer[ 3 ];
	if( value < MIN_STORED_TIME_VALUE || value >= MAX_TIME_VALUE )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	*timeVal = value;

	return( CRYPT_OK );
	}

/* Read 64-bit integer values */

#ifdef USE_WEBSOCKETS

RETVAL_RANGE( 0, INT_MAX ) STDC_NONNULL_ARG( ( 1 ) ) \
int readUint64( INOUT_PTR STREAM *stream )
	{
	BYTE buffer[ ( UINT64_SIZE / 2 ) + 8 ];
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* This is never a 64-bit value but always an overprovisioned int/long, 
	   so we verify that the top four bytes are zero and then read it as
	   a Uint32 */
	status = sread( stream, buffer, UINT64_SIZE / 2 );
	if( cryptStatusError( status ) )
		return( status );
	if( memcmp( buffer, "\x00\x00\x00\x00", UINT64_SIZE / 2 ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readUint32( stream ) );
	}
#endif /* USE_WEBSOCKETS */

/* Read a string preceded by a 32-bit length */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readData32( INOUT_PTR STREAM *stream, 
					   OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
					   IN_LENGTH_SHORT const int dataMaxLength, 
					   OUT_LENGTH_BOUNDED_Z( dataMaxLength ) int *dataLength,
					   IN_BOOL const BOOLEAN includeLengthField,
					   IN_BOOL const BOOLEAN zeroLengthOK )
	{
	BYTE *dataPtr = data;
	const int headerSize = includeLengthField ? UINT32_SIZE : 0;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES_S( isShortIntegerRangeNZ( dataMaxLength ) );
	REQUIRES_S( isBooleanValue( includeLengthField ) );
	REQUIRES_S( isBooleanValue( zeroLengthOK ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	status = length = readUint32( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length <= 0 )
		{
		/* Zero length value */
		if( !zeroLengthOK )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		if( includeLengthField )
			{
			if( dataMaxLength < UINT32_SIZE )
				return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
			memset( data, 0, UINT32_SIZE );
			*dataLength = UINT32_SIZE;
			}
		return( CRYPT_OK );
		}
	if( !isShortIntegerRangeNZ( length ) )
		{
		/* Avoid integer-overflow warning in the following check */
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	if( headerSize + length > dataMaxLength )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	if( includeLengthField )
		{
		dataPtr[ 0 ] = intToByte( length >> 24 );
		dataPtr[ 1 ] = intToByte( length >> 16 );
		dataPtr[ 2 ] = intToByte( length >> 8 );
		dataPtr[ 3 ] = intToByte( length );
		}
	*dataLength = headerSize + length;
	REQUIRES_S( boundsCheckZ( headerSize, length, dataMaxLength ) );
	return( sread( stream, dataPtr + headerSize, length ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int readString32( INOUT_PTR STREAM *stream, 
				  OUT_BUFFER( stringMaxLength, \
							  *stringLength ) void *string, 
				  IN_LENGTH_SHORT const int stringMaxLength, 
				  OUT_LENGTH_BOUNDED_Z( stringMaxLength ) int *stringLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( string, stringMaxLength ) );
	assert( isWritePtr( stringLength, sizeof( int ) ) );

	REQUIRES_S( isShortIntegerRangeNZ( stringMaxLength ) );

	/* Read the string, limiting the size to the maximum buffer size */
	return( readData32( stream, string, stringMaxLength, stringLength, 
						FALSE, FALSE ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int readString32Opt( INOUT_PTR STREAM *stream, 
					 OUT_BUFFER( stringMaxLength, \
								 *stringLength ) void *string, 
					 IN_LENGTH_SHORT const int stringMaxLength, 
					 OUT_LENGTH_BOUNDED_Z( stringMaxLength ) \
						int *stringLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( string, stringMaxLength ) );
	assert( isWritePtr( stringLength, sizeof( int ) ) );

	REQUIRES_S( isShortIntegerRangeNZ( stringMaxLength ) );

	/* Read the string, limiting the size to the maximum buffer size, and 
	   with zero-length strings allowed */
	return( readData32( stream, string, stringMaxLength, stringLength, 
						FALSE, TRUE ) );
	}

/* Read a raw object preceded by a 32-bit length */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int readRawObject32( INOUT_PTR STREAM *stream, 
					 OUT_BUFFER( bufferMaxLength, *bufferLength ) \
						void *buffer, 
					 IN_LENGTH_SHORT_MIN( UINT32_SIZE + 1 ) \
						const int bufferMaxLength, 
					 OUT_LENGTH_BOUNDED_Z( bufferMaxLength ) \
						int *bufferLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( buffer, bufferMaxLength ) );
	assert( isWritePtr( bufferLength, sizeof( int ) ) );

	REQUIRES_S( isShortIntegerRangeMin( bufferMaxLength, UINT32_SIZE + 1 ) );

	/* Read the string, limiting the size to the maximum buffer size */
	return( readData32( stream, buffer, bufferMaxLength, bufferLength, 
						TRUE, FALSE ) );
	}

/* Read a universal type and discard it, used to skip unknown or unwanted
   types.  Since it's only used to skip short no-op fields, we limit the
   maximum length to MAX_INTLENGTH_SHORT */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int readUniversal( INOUT_PTR STREAM *stream, 
						  IN_ENUM( LENGTH ) const LENGTH_TYPE lengthType )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES_S( lengthType == LENGTH_8 || lengthType == LENGTH_16U || \
				lengthType == LENGTH_32 );

	/* Read the length and skip the data */
	switch( lengthType )
		{
		case LENGTH_8:
			/* There's no readUint8() since it's not used anywhere 
			   except here, but in any case all we need is to check
			   that the read length value isn't an error */
			status = length = sgetc( stream );
			if( cryptStatusError( status ) )
				return( status );
			break;

		case LENGTH_16U:
			status = length = readUint16( stream );
			break;

		case LENGTH_32:
			status = length = readUint32( stream );
			break;

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	if( length <= 0 )
		return( CRYPT_OK );		/* Zero-length data */
	if( !isShortIntegerRangeNZ( length ) )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( sSkip( stream, length, MAX_INTLENGTH_SHORT ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int readUniversal8( INOUT_PTR STREAM *stream )
	{
	return( readUniversal( stream, LENGTH_8 ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int readUniversal16( INOUT_PTR STREAM *stream )
	{
	return( readUniversal( stream, LENGTH_16U ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int readUniversal32( INOUT_PTR STREAM *stream )
	{
	return( readUniversal( stream, LENGTH_32 ) );
	}

/* Read (large) integers in various formats */

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int readInteger16U( INOUT_PTR STREAM *stream, 
					OUT_BUFFER_OPT( maxLength, \
									*integerLength ) void *integer, 
					OUT_LENGTH_BOUNDED_Z( maxLength ) \
						int *integerLength, 
					IN_LENGTH_PKC const int minLength, 
					IN_LENGTH_PKC const int maxLength,
					IN_ENUM_OPT( BIGNUM_CHECK ) \
						const BIGNUM_CHECK_TYPE checkType )
	{
	return( readInteger( stream, integer, integerLength, minLength,
						 maxLength, LENGTH_16U, checkType ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int readInteger16Ubits( INOUT_PTR STREAM *stream, 
						OUT_BUFFER_OPT( maxLength, \
										*integerLength ) void *integer, 
						OUT_LENGTH_BOUNDED_Z( maxLength ) \
							int *integerLength, 
						IN_LENGTH_PKC const int minLength, 
						IN_LENGTH_PKC const int maxLength,
						IN_ENUM_OPT( BIGNUM_CHECK ) \
							const BIGNUM_CHECK_TYPE checkType )
	{
	return( readInteger( stream, integer, integerLength, minLength,
						 maxLength, LENGTH_16U_BITS, checkType ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int readInteger32( INOUT_PTR STREAM *stream, 
				   OUT_BUFFER_OPT( maxLength, \
								   *integerLength ) void *integer, 
				   OUT_LENGTH_BOUNDED_Z( maxLength  ) int *integerLength, 
				   IN_LENGTH_PKC const int minLength, 
				   IN_LENGTH_PKC const int maxLength,
				   IN_ENUM_OPT( BIGNUM_CHECK ) \
						const BIGNUM_CHECK_TYPE checkType )
	{
	return( readInteger( stream, integer, integerLength, minLength,
						 maxLength, LENGTH_32, checkType ) );
	}

#ifdef USE_PKC

/* Read integers as bignums in various formats */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readBignumInteger( INOUT_PTR STREAM *stream, 
							  INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignum,
							  IN_LENGTH_PKC const int minLength, 
							  IN_LENGTH_PKC const int maxLength,
							  IN_PTR_OPT TYPECAST( BIGNUM * ) \
									const struct BN *maxRange, 
							  IN_ENUM( LENGTH ) const LENGTH_TYPE lengthType,
							  IN_ENUM_OPT( BIGNUM_CHECK ) \
									const BIGNUM_CHECK_TYPE checkType )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );
	assert( maxRange == NULL || isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES_S( ( checkType == BIGNUM_CHECK_VALUE_FIXEDLEN && \
				  minLength >= MIN_PKCSIZE_BERNSTEIN && \
				  minLength == maxLength ) || \
				( minLength > 0 && minLength < maxLength && \
				  maxLength <= CRYPT_MAX_PKCSIZE ) );
	REQUIRES_S( isEnumRange( lengthType, LENGTH ) );
	REQUIRES_S( isEnumRangeOpt( checkType, BIGNUM_CHECK ) );

	/* Read the integer data */
	status = readInteger( stream, buffer, &length, minLength, maxLength, 
						  lengthType, checkType );
	if( cryptStatusError( status ) )
		return( status );

	/* Convert the value to a bignum.  Note that we use the checkType
	   parameter for both readInteger() and importBignum(), since the 
	   former merely checks the byte count while the latter actually parses 
	   and processes the bignum */
#if defined( USE_25519 ) || defined( USE_ED25519 )
	if( checkType == BIGNUM_CHECK_VALUE_FIXEDLEN )
		status = import25519ByteString( bignum, buffer, length );
	else
#endif /* USE_25519 || USE_ED25519 */
		{
		status = importBignum( bignum, buffer, length, minLength, maxLength, 
							   maxRange, checkType );
		}
	if( cryptStatusError( status ) )
		status = sSetError( stream, status );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readBignumInteger16U( INOUT_PTR STREAM *stream, 
						  INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignum, 
						  IN_LENGTH_PKC const int minLength, 
						  IN_LENGTH_PKC const int maxLength, 
						  IN_PTR_OPT TYPECAST( BIGNUM * ) \
								const struct BN *maxRange,
						  IN_ENUM_OPT( BIGNUM_CHECK ) \
								const BIGNUM_CHECK_TYPE checkType )
	{
	return( readBignumInteger( stream, bignum, minLength, maxLength,
							   maxRange, LENGTH_16U, checkType ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readBignumInteger16Ubits( INOUT_PTR STREAM *stream, 
							  INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignum, 
							  IN_LENGTH_PKC_BITS const int minBits,
							  IN_LENGTH_PKC_BITS const int maxBits,
							  IN_PTR_OPT TYPECAST( BIGNUM * ) \
								const struct BN *maxRange,
							  IN_ENUM_OPT( BIGNUM_CHECK ) \
								const BIGNUM_CHECK_TYPE checkType )
	{
	return( readBignumInteger( stream, bignum, bitsToBytes( minBits ),
							   bitsToBytes( maxBits ), maxRange, 
							   LENGTH_16U_BITS, checkType ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readBignumInteger32( INOUT_PTR STREAM *stream, 
						 INOUT_PTR TYPECAST( BIGNUM * ) struct BN *bignum, 
						 IN_LENGTH_PKC const int minLength, 
						 IN_LENGTH_PKC const int maxLength, 
						 IN_PTR_OPT TYPECAST( BIGNUM * ) \
							const struct BN *maxRange,
						 IN_ENUM_OPT( BIGNUM_CHECK ) \
							const BIGNUM_CHECK_TYPE checkType )
	{
	return( readBignumInteger( stream, bignum, minLength, maxLength, 
							   maxRange, LENGTH_32, checkType ) );
	}
#endif /* USE_PKC */

/****************************************************************************
*																			*
*								Data Write Routines							*
*																			*
****************************************************************************/

/* Write 16-, 32- and 64-bit integer values */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint16( INOUT_PTR STREAM *stream, 
				 IN_RANGE( 0, 0xFFFF ) const int value )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isIntegerRange( value ) && value <= 0xFFFFL );

	sputc( stream, intToByte( value >> 8 ) );
	return( sputc( stream, intToByte( value ) ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint32( INOUT_PTR STREAM *stream, IN_INT_Z const long value )
	{
	BYTE buffer[ UINT32_SIZE + 8 ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isIntegerRange( value ) );

	buffer[ 0 ] = intToByte( value >> 24 );
	buffer[ 1 ] = intToByte( value >> 16 );
	buffer[ 2 ] = intToByte( value >> 8 );
	buffer[ 3 ] = intToByte( value );
	return( swrite( stream, buffer, UINT32_SIZE ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint64( INOUT_PTR STREAM *stream, IN_INT_Z const long value )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isIntegerRange( value ) );

	/* Unlike readUint64() this is used in TLS to write sequence numbers so
	   we always make it available */
	swrite( stream, "\x00\x00\x00\x00", UINT64_SIZE / 2 );
	return( writeUint32( stream, value ) );
	}

/* Write 32-bit time values.  This differs slightly from the standard
   writeUint32() in that it doesn't check that the input value is within an
   integer range */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint32Time( INOUT_PTR STREAM *stream, const time_t timeVal )
	{
	BYTE buffer[ UINT32_SIZE + 8 ];

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( timeVal >= MIN_TIME_VALUE );

	buffer[ 0 ] = intToByte( timeVal >> 24 );
	buffer[ 1 ] = intToByte( timeVal >> 16 );
	buffer[ 2 ] = intToByte( timeVal >> 8 );
	buffer[ 3 ] = intToByte( timeVal );
	return( swrite( stream, buffer, UINT32_SIZE ) );
	}

/* Write a string preceded by a 32-bit length */

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeString32( INOUT_PTR STREAM *stream, 
				   IN_BUFFER( stringLength ) const void *string, 
				   IN_LENGTH_SHORT const int stringLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( string, stringLength ) );

	REQUIRES_S( isIntegerRangeNZ( stringLength ) );

	writeUint32( stream, stringLength );
	return( swrite( stream, string, stringLength ) );
	}

/* Write large integers in various formats */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeInteger( INOUT_PTR STREAM *stream, 
						 IN_BUFFER( integerLength ) const void *integer, 
						 IN_LENGTH_PKC const int integerLength,
						 IN_ENUM( LENGTH ) const LENGTH_TYPE lengthType )
	{
	const BYTE *intPtr = integer;
	int length = integerLength, LOOP_ITERATOR;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( integer, integerLength ) );

	REQUIRES_S( integerLength > 0 && integerLength <= CRYPT_MAX_PKCSIZE );
	REQUIRES_S( isEnumRange( lengthType, LENGTH ) );

	/* Integers may be passed to us from higher-level code with leading 
	   zeroes as part of the encoding.  Before we write them out we strip
	   out any superfluous leading zeroes that may be present */
	LOOP_LARGE_REV_CHECKINC( length > 0 && *intPtr == 0, ( length--, intPtr++ ) )
		{
		ENSURES_S( LOOP_INVARIANT_LARGE_REV_XXX( length, 1, CRYPT_MAX_PKCSIZE ) );

		/* In theory this could be a problem since quietly changing the 
		   length of a low-level internal value before writing it will cause 
		   problems with higher-level code that doesn't expect to have the 
		   data length of internal components changed, however in practice it
		   only occurs with PGP signatures which are just a raw integer
		   value, so we don't invoke any kind of warning */
		/* assert( DEBUG_WARN ); */
		}
	ENSURES_S( LOOP_BOUND_LARGE_REV_OK );
	ENSURES_S( length > 0 );

	switch( lengthType )
		{
		case LENGTH_16U:
			status = writeUint16( stream, length );
			break;

		case LENGTH_16U_BITS:
			status = writeUint16( stream, bytesToBits( length ) );
			break;

		case LENGTH_32:
			{
			const int leadingOneBit = ( *intPtr & 0x80 ) ? 1 : 0;

			status = writeUint32( stream, length + leadingOneBit );
			if( cryptStatusOK( status ) && leadingOneBit )
				status = sputc( stream, 0 );	/* MPIs are signed values */
			break;
			}

		default:
			retIntError_Stream( stream );
		}
	if( cryptStatusError( status ) )
		return( status );
	return( swrite( stream, intPtr, length ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeInteger16U( INOUT_PTR STREAM *stream, 
					 IN_BUFFER( integerLength ) const void *integer, 
					 IN_LENGTH_PKC const int integerLength )
	{
	return( writeInteger( stream, integer, integerLength, LENGTH_16U ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeInteger16Ubits( INOUT_PTR STREAM *stream, 
						 IN_BUFFER( integerLength ) const void *integer, 
						 IN_LENGTH_PKC const int integerLength )
	{
	return( writeInteger( stream, integer, integerLength, LENGTH_16U_BITS ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeInteger32( INOUT_PTR STREAM *stream, 
					IN_BUFFER( integerLength ) const void *integer, 
					IN_LENGTH_PKC const int integerLength )
	{
	return( writeInteger( stream, integer, integerLength, LENGTH_32 ) );
	}

#ifdef USE_PKC

/* Write integers from bignums in various formats */

CHECK_RETVAL_RANGE( UINT32_SIZE, MAX_INTLENGTH_SHORT ) STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofBignumInteger32( const void *bignum )
	{
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	return( UINT32_SIZE + BN_high_bit( ( BIGNUM * ) bignum ) + \
						  BN_num_bytes( bignum ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeBignumInteger( INOUT_PTR STREAM *stream, 
							   TYPECAST( BIGNUM * ) const struct BN *bignum,
							   IN_ENUM( LENGTH ) const LENGTH_TYPE lengthType )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int bnLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES_S( isEnumRange( lengthType, LENGTH ) );

	status = exportBignum( buffer, CRYPT_MAX_PKCSIZE, &bnLength, bignum );
	ENSURES_S( cryptStatusOK( status ) );
	ENSURES_S( bnLength > 0 && bnLength <= CRYPT_MAX_PKCSIZE );
	if( lengthType == LENGTH_16U_BITS )
		{
		int bitCount;

		/* We can't call down to writeInteger() from here because we need to 
		   write a precise length in bits rather than a value reconstructed 
		   from the byte count.  This also means that we can't easily 
		   perform the leading-zero truncation that writeInteger() does 
		   without a lot of low-level fiddling that duplicates code in
		   writeInteger() */
		status = bitCount = BN_num_bits( bignum );
		if( cryptStatusError( status ) )
			return( status );
		writeUint16( stream, bitCount );
		status = swrite( stream, buffer, bnLength );
		}
	else
		status = writeInteger( stream, buffer, bnLength, lengthType );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeBignumInteger16U( INOUT_PTR STREAM *stream, 
						   TYPECAST( BIGNUM * ) const struct BN *bignum )
	{
	return( writeBignumInteger( stream, bignum, LENGTH_16U ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeBignumInteger16Ubits( INOUT_PTR STREAM *stream, 
							   TYPECAST( BIGNUM * ) const struct BN *bignum )
	{
	return( writeBignumInteger( stream, bignum, LENGTH_16U_BITS ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeBignumInteger32( INOUT_PTR STREAM *stream, 
						  TYPECAST( BIGNUM * ) const struct BN *bignum )
	{
	return( writeBignumInteger( stream, bignum, LENGTH_32 ) );
	}
#endif /* USE_PKC */
