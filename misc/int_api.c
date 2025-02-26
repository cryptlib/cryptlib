/****************************************************************************
*																			*
*							cryptlib Internal API							*
*						Copyright Peter Gutmann 1992-2022					*
*																			*
****************************************************************************/

/* A generic module that implements a rug under which all problems not
   solved elsewhere are swept */

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "stream.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* Emit a warning if TRUE was redefined.  We can't do this in the header 
   where the check is performed because it would produce a warning for every
   single file */

#if ( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) ) && \
	defined( TRUE_REDEFINED )
  #pragma message( "Warning: TRUE has been defined externally, redefining for cryptlib use." )
#endif /* TRUE_REDEFINED */

/* Perform the FIPS-140 statistical checks that are feasible on a byte
   string.  The full suite of tests assumes that an infinite source of
   values (and time) is available, the following is a scaled-down version
   used to sanity-check keys and other short random data blocks.  Note that
   this check requires at least 64 bits of data in order to produce useful
   results */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkNontrivialKey( IN_BUFFER( dataLength ) const BYTE *data, 
								   IN_LENGTH_SHORT_MIN( MIN_KEYSIZE ) \
										const int dataLength )
	{
	LOOP_INDEX i;
	int count = 0;

	REQUIRES_B( isShortIntegerRangeMin( dataLength, MIN_KEYSIZE ) );

	/* Check that it's not just a text string */
	LOOP_LARGE( i = 0, i < dataLength, i++	)
		{
		ENSURES_B( LOOP_INVARIANT_LARGE( i, 0, dataLength - 1 ) );

		if( !isAlnum( data[ i ] ) )
			break;
		}
	ENSURES_B( LOOP_BOUND_OK );
	if( i >= dataLength )
		return( FALSE );

	/* Check for a run of more than 64 bits of identical or near-identical 
	   values.  This isn't detected by checkEntropy() because it looks at
	   the overall entropy, not localised blocks of low entropy.
	   
	   The lower bound of 64 bits of identical values is for the fixed DH 
	   values which have all ones in the MSB and LSB */
	LOOP_LARGE( i = 1, i < dataLength, i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 1, dataLength - 1 ) );
		
		if( abs( data[ i ] - data[ i - 1 ] ) <= 8 )
			{
			count++;
			if( count > 8 )
				return( FALSE );
			}
		else
			{
			count = 0;
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkEntropy( IN_BUFFER( dataLength ) const BYTE *data, 
					  IN_LENGTH_SHORT_MIN( MIN_KEYSIZE ) const int dataLength )
	{
	const int delta = ( dataLength < 16 ) ? 1 : 0;
	LOOP_INDEX i;
	int bitCount[ 8 + 8 ], noOnes;

	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES_B( isShortIntegerRangeMin( dataLength, MIN_KEYSIZE ) );

	/* Make sure that we haven't been given an obviously non-random key */
	if( !checkNontrivialKey( data, dataLength ) )
		return( FALSE );

	memset( bitCount, 0, sizeof( int ) * 8 );
	LOOP_LARGE( i = 0, i < dataLength, i++ )
		{
		int value;

		ENSURES_B( LOOP_INVARIANT_LARGE( i, 0, dataLength - 1 ) );

		value = byteToInt( data[ i ] );
		bitCount[ value & 3 ]++;
		bitCount[ ( value >> 2 ) & 3 ]++;
		bitCount[ ( value >> 4 ) & 3 ]++;
		bitCount[ ( value >> 6 ) & 3 ]++;
		}
	ENSURES_B( LOOP_BOUND_OK );

	/* Monobit test: Make sure that at least 1/4 of the bits are ones and 1/4
	   are zeroes */
	noOnes = bitCount[ 1 ] + bitCount[ 2 ] + ( 2 * bitCount[ 3 ] );
	if( noOnes < dataLength * 2 || noOnes > dataLength * 6 )
		{
		zeroise( bitCount, sizeof( int ) * 8 );
		return( FALSE );
		}

	/* Poker test (almost): Make sure that each bit pair is present at least
	   1/16 of the time.  The FIPS 140 version uses 4-bit values but the
	   numer of samples available from the keys is far too small for this so
	   we can only use 2-bit values.

	   This isn't precisely 1/16, for short samples (< 128 bits) we adjust
	   the count by one because of the small sample size and for odd-length
	   data we're getting four more samples so the actual figure is slightly
	   less than 1/16 */
	if( ( bitCount[ 0 ] + delta < dataLength / 2 ) || \
		( bitCount[ 1 ] + delta < dataLength / 2 ) || \
		( bitCount[ 2 ] + delta < dataLength / 2 ) || \
		( bitCount[ 3 ] + delta < dataLength / 2 ) )
		{
		zeroise( bitCount, sizeof( int ) * 8 );
		return( FALSE );
		}

	zeroise( bitCount, sizeof( int ) * 8 );
	return( TRUE );
	}

/* Check a bignum for suspicious patterns.  This is very vaguely-defined and 
   is only enabled in debug mode to prevent false positives, for now all that
   we do is the basic entropy check applied to all keys */

#ifndef NDEBUG

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkEntropyInteger( IN_BUFFER( length ) const BYTE *buffer, 
							 IN_LENGTH_PKC_Z const int length )
	{
	assert( isReadPtrDynamic( buffer, length ) );

	REQUIRES( length >= 0 && length <= CRYPT_MAX_PKCSIZE );

	/* If the data amount is too small to be able to draw any conclusions 
	   from it, don't try and perform any checking */
	if( length < MIN_KEYSIZE )
		return( TRUE );

	/* Perform a basic entropy check */
	if( !checkEntropy( buffer, length ) )
		return( FALSE );

	/* Optional further checks here */

	return( TRUE );
	}
#endif /* !NDEBUG */

/* Check whether a block of 64 bits of data is all-zeroes, typically used 
   for sanity-check functions that check contexts for validity.  
   
   Note that the length value provided to this function isn't the length of
   the data being provided, which is fixed at 8 bytes, but the length value
   that the caller has for the data.  If it's nonzero then we don't check
   the data contents, only if it's zero do we go on to check whether the
   data is also zero */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN isEmptyData( IN_BUFFER_C( 8 ) const BYTE data[ 8 ],
					 IN_LENGTH_SHORT_Z const int dataLengthValue )
	{
	assert( isReadPtr( data, 8 ) );

	REQUIRES_B( isShortIntegerRange( dataLengthValue ) );

	/* Perform a quick-reject check before calling the more expensive
	   memcmp() */
	if( dataLengthValue != 0 || data[ 0 ] != 0x00 )
		return( FALSE );

	/* Check whether the first 64 bits are zero */
	return( memcmp( data, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) ? \
			FALSE : TRUE );
	}

/* Perform a bounds check on pointers to blocks of memory, verifying that an
   inner block of memory is contained entirely within an outer block of 
   memory */

CHECK_RETVAL_BOOL \
BOOLEAN pointerBoundsCheck( IN_PTR_OPT const void *data,
							IN_LENGTH_Z const int dataLength,
							IN_PTR_OPT const void *innerData,
							IN_LENGTH_SHORT_Z const int innerDataLength )
	{
	REQUIRES_B( isIntegerRange( dataLength ) );
	REQUIRES_B( isShortIntegerRange( innerDataLength ) );

	/* Check for general problems with the parameters */
	if( ( data != NULL && dataLength <= 0 ) || \
		( data == NULL && dataLength > 0 ) )
		return( FALSE );
	if( ( innerData != NULL && innerDataLength <= 0 ) || \
		( innerData == NULL && innerDataLength > 0 ) )
		return( FALSE );

	assert( data == NULL || isReadPtrDynamic( data, dataLength ) );
	assert( innerData == NULL || \
			isReadPtrDynamic( innerData, innerDataLength ) );
	
	/* If there's no data present then there's nothing to check, although 
	   we do have to make sure that there's then no inner data present 
	   either */
	if( data == NULL )
		{
		if( innerData != NULL || innerDataLength != 0 )
			return( FALSE );

		return( TRUE );
		}

	/* If there's no inner data present then there's nothing to check */
	if( innerData == NULL )
		{
		/* This is already checked in the general parameter check above, but
		   we make it explicit here as well */
		REQUIRES_B( innerDataLength == 0 );

		return( TRUE );
		}

	/* Make sure that the inner data is contained within the outer data */
	if( innerData < data || \
		( ( BYTE * ) innerData + innerDataLength > \
										( BYTE * ) data + dataLength ) )
		return( FALSE );

	return( TRUE );
	}

/* Helper function used to check that a sequence of CFI tokens have been 
   processed in order.  This is used both to ensure that inline macros to
   perform the CFI checking don't get too complex and to reduce the chances
   of a compiler being able to turn the CFI check into a compile-time 
   constant expression.
   
   This function isn't decorated with attributes because it both takes and 
   produces arbitrary-range integers */

CFI_CHECK_TYPE cfiCheckSequence( const CFI_CHECK_TYPE initValue, 
								 const CFI_CHECK_TYPE label1Value,
								 const CFI_CHECK_TYPE label2Value, 
								 const CFI_CHECK_TYPE label3Value )
	{
	CFI_CHECK_TYPE cfiCheckValue = initValue;

	cfiCheckValue = ( cfiCheckValue << 5 ) + label1Value;
	if( label2Value != ( CFI_CHECK_TYPE ) -1 )
		cfiCheckValue = ( cfiCheckValue << 5 ) + label2Value;
	if( label3Value != ( CFI_CHECK_TYPE ) -1 )
		cfiCheckValue = ( cfiCheckValue << 5 ) + label3Value;

	return( cfiCheckValue );
	}

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib semantics (these will already have been done by
   the caller, this is just a backup check).  There are two forms for this
   function, one that takes a MESSAGE_DATA parameter containing all of the 
   result parameters in one place and the other that takes distinct result
   parameters, typically because they've been passed down through several
   levels of function call beyond the point where they were in a 
   MESSAGE_DATA */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int attributeCopyParams( OUT_BUFFER_OPT( destMaxLength, \
										 *destLength ) void *dest, 
						 IN_LENGTH_SHORT_Z const int destMaxLength, 
						 OUT_LENGTH_BOUNDED_SHORT_Z( destMaxLength ) \
							int *destLength, 
						 IN_BUFFER_OPT( sourceLength ) const void *source, 
						 IN_LENGTH_SHORT_Z const int sourceLength )
	{
	assert( ( dest == NULL && destMaxLength == 0 ) || \
			( isWritePtrDynamic( dest, destMaxLength ) ) );
	assert( isWritePtr( destLength, sizeof( int ) ) );
	assert( ( source == NULL && sourceLength == 0 ) || \
			isReadPtrDynamic( source, sourceLength ) );

	REQUIRES( ( dest == NULL && destMaxLength == 0 ) || \
			  ( dest != NULL && \
				isShortIntegerRangeNZ( destMaxLength ) ) );
	REQUIRES( ( source == NULL && sourceLength == 0 ) || \
			  ( source != NULL && \
			    isShortIntegerRangeNZ( sourceLength ) ) );

	/* Clear return values */
	*destLength = 0;
	if( dest != NULL )
		memset( dest, 0, min( 16, destMaxLength ) );

	if( sourceLength <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	ENSURES( source != NULL );
	if( dest != NULL )
		{
		assert( isReadPtrDynamic( source, sourceLength ) );

		if( sourceLength > destMaxLength || \
			!isWritePtrDynamic( dest, sourceLength ) )
			return( CRYPT_ERROR_OVERFLOW );
		REQUIRES( rangeCheck( sourceLength, 1, destMaxLength ) );
		memcpy( dest, source, sourceLength );
		}
	*destLength = sourceLength;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int attributeCopy( INOUT_PTR MESSAGE_DATA *msgData, 
				   IN_BUFFER( attributeLength ) const void *attribute, 
				   IN_LENGTH_SHORT_Z const int attributeLength )
	{
	assert( isWritePtr( msgData, sizeof( MESSAGE_DATA ) ) );
	assert( attributeLength == 0 || \
			isReadPtrDynamic( attribute, attributeLength ) );

	REQUIRES( isShortIntegerRange( attributeLength ) );

	return( attributeCopyParams( msgData->data, msgData->length, 
								 &msgData->length, attribute, 
								 attributeLength ) );
	}

/* Check whether a given algorithm is available */

CHECK_RETVAL_BOOL \
BOOLEAN algoAvailable( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_QUERY_INFO queryInfo;

	REQUIRES_B( isEnumRange( cryptAlgo, CRYPT_ALGO ) );

	/* Short-circuit check for always-available algorithms.  The kernel 
	   won't initialise without the symmetric and hash algorithms being 
	   present (and SHA-x implies HMAC-SHAx) so it's safe to hardcode them 
	   in here */
	if( cryptAlgo == CRYPT_ALGO_AES || \
		cryptAlgo == CRYPT_ALGO_SHA1 || \
		cryptAlgo == CRYPT_ALGO_HMAC_SHA1 || \
		cryptAlgo == CRYPT_ALGO_SHA2 || \
		cryptAlgo == CRYPT_ALGO_HMAC_SHA2 || \
		cryptAlgo == CRYPT_ALGO_RSA )
		return( TRUE );
#ifdef USE_3DES
	if( cryptAlgo == CRYPT_ALGO_3DES )
		return( TRUE );
#endif /* USE_3DES */
		
	return( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									IMESSAGE_DEV_QUERYCAPABILITY, &queryInfo,
									cryptAlgo ) ) ? TRUE : FALSE );
	}

/* For a given hash algorithm pair, check whether the first is stronger than 
   the second.  The order is:

	SNAng > SHA2 > SHA-1 > all others */

CHECK_RETVAL_BOOL \
BOOLEAN isStrongerHash( IN_ALGO const CRYPT_ALGO_TYPE algorithm1,
						IN_ALGO const CRYPT_ALGO_TYPE algorithm2 )
	{
	static const CRYPT_ALGO_TYPE algoPrecedence[] = {
		CRYPT_ALGO_SHAng, CRYPT_ALGO_SHA2, CRYPT_ALGO_SHA1, 
		CRYPT_ALGO_NONE, CRYPT_ALGO_NONE };
	LOOP_INDEX algo1index, algo2index;

	REQUIRES_B( isHashAlgo( algorithm1 ) );
	REQUIRES_B( isHashAlgo( algorithm2 ) );

	/* Find the relative positions on the scale of the two algorithms */
	LOOP_SMALL( algo1index = 0, 
				algo1index < FAILSAFE_ARRAYSIZE( algoPrecedence, \
												 CRYPT_ALGO_TYPE ) && \
						algoPrecedence[ algo1index ] != algorithm1,
				algo1index++ )
		{
		ENSURES_B( LOOP_INVARIANT_SMALL( algo1index, 0, 
										 FAILSAFE_ARRAYSIZE( algoPrecedence, \
															 CRYPT_ALGO_TYPE ) - 1 ) );

		/* If we've reached an unrated algorithm, it can't be stronger than 
		   the other one */
		if( algoPrecedence[ algo1index ] == CRYPT_ALGO_NONE )
			return( FALSE );
		}
	ENSURES_B( LOOP_BOUND_OK );
	ENSURES_B( algo1index < FAILSAFE_ARRAYSIZE( algoPrecedence, \
												CRYPT_ALGO_TYPE ) );
	LOOP_SMALL( algo2index = 0, 
				algo2index < FAILSAFE_ARRAYSIZE( algoPrecedence, \
												 CRYPT_ALGO_TYPE ) && \
						algoPrecedence[ algo2index ] != algorithm2,
				algo2index++ )
		{
		ENSURES_B( LOOP_INVARIANT_SMALL( algo2index, 0, 
										 FAILSAFE_ARRAYSIZE( algoPrecedence, \
															 CRYPT_ALGO_TYPE ) - 1 ) );

		/* If we've reached an unrated algorithm, it's weaker than the other 
		   one */
		if( algoPrecedence[ algo2index ] == CRYPT_ALGO_NONE )
			return( TRUE );
		}
	ENSURES_B( LOOP_BOUND_OK );
	ENSURES_B( algo2index < FAILSAFE_ARRAYSIZE( algoPrecedence, \
												CRYPT_ALGO_TYPE ) );

	/* If the first algorithm has a smaller index than the second, it's a
	   stronger algorithm */
	return( ( algo1index < algo2index ) ? TRUE : FALSE );
	}

/* Return a random small positive integer.  This is used to perform 
   lightweight randomisation of various algorithms in order to make DoS 
   attacks harder.  Because of this the values don't have to be 
   cryptographically strong, so all that we do is cache the data from 
   CRYPT_IATTRIBUTE_RANDOM_NONCE and pull out a small integer's worth on 
   each call.  For the same reason, we don't care that the function isn't
   thread-safe */

#define RANDOM_BUFFER_SIZE	64

CHECK_RETVAL_RANGE_NOERROR( 0, 32767 ) \
int getRandomInteger( void )
	{
	static BYTE nonceData[ RANDOM_BUFFER_SIZE + 8 ];
	static int nonceIndex = 0;
	int returnValue, status;

	REQUIRES_EXT( !( nonceIndex & 1 ), 0 );

	/* Initialise/reinitialise the nonce data if necessary.  See the long 
	   comment for getNonce() in system.c for the reason why we don't bail 
	   out on error but continue with a lower-quality generator */
	if( nonceIndex <= 0 )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, nonceData, RANDOM_BUFFER_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( ( int ) getTime( GETTIME_NOFAIL ) & 0x7FFF );
		}

	/* Extract the next random integer value from the buffered data */
	returnValue = ( byteToInt( nonceData[ nonceIndex ] ) << 8 ) | \
					byteToInt( nonceData[ nonceIndex + 1 ] );
	nonceIndex = ( nonceIndex + 2 ) % RANDOM_BUFFER_SIZE;
	ENSURES_EXT( nonceIndex >= 0 && nonceIndex < RANDOM_BUFFER_SIZE, 0 );

	/* Return the value constrained to lie within the range 0...32767 */
	return( returnValue & 0x7FFF );
	}

/* Map one value to another, used to map values from one representation 
   (e.g. PGP algorithms or HMAC algorithms) to another (cryptlib algorithms
   or the underlying hash used for the HMAC algorithm) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int mapValue( IN_INT_SHORT_Z const int srcValue,
			  OUT_INT_SHORT_Z int *destValue,
			  IN_ARRAY( mapTblSize ) const MAP_TABLE *mapTbl,
			  IN_RANGE( 1, 100 ) const int mapTblSize )
	{
	LOOP_INDEX i;

	assert( isWritePtr( destValue, sizeof( int ) ) );
	assert( isReadPtr( mapTbl, mapTblSize * sizeof( MAP_TABLE ) ) );

	REQUIRES( isShortIntegerRange( srcValue ) );
	REQUIRES( mapTblSize > 0 && mapTblSize < 100 );
	REQUIRES( mapTbl[ mapTblSize ].source == CRYPT_ERROR );

	/* Clear return value */
	*destValue = 0;

	/* Convert the hash algorithm into the equivalent HMAC algorithm */
	LOOP_LARGE( i = 0, 
				i < mapTblSize && mapTbl[ i ].source != CRYPT_ERROR, 
				i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, mapTblSize - 1 ) );

		if( mapTbl[ i ].source == srcValue )
			{
			*destValue = mapTbl[ i ].destination;

			return( CRYPT_OK );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < mapTblSize );

	return( CRYPT_ERROR_NOTAVAIL );
	}

#ifdef USE_ERRMSGS

/* Map an object type to a string description of the type, used for printing
   diagnostic messages.  Note that the end-of-table delimiter is 0, not 
   CRYPT_ERROR, since one of the object types whose name we need to look up 
   is status values */

CHECK_RETVAL_PTR_NONNULL STDC_NONNULL_ARG( ( 1 ) ) \
const char *getObjectName( IN_ARRAY( objectNameInfoSize ) \
								const OBJECT_NAME_INFO *objectNameInfo,
						   IN_LENGTH_SHORT const int objectNameInfoSize,
						   const int objectType )
	{
	LOOP_INDEX i;

	assert( isReadPtr( objectNameInfo, 
					   sizeof( OBJECT_NAME_INFO ) * objectNameInfoSize ) );

	REQUIRES_EXT( isShortIntegerRange( objectNameInfoSize ),
				  "<Internal error>" );

	LOOP_LARGE( i = 0,
				i < objectNameInfoSize && \
					objectNameInfo[ i ].objectType != objectType && \
					objectNameInfo[ i ].objectType != 0,
				i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_LARGE( i, 0, objectNameInfoSize - 1 ),
					 "<Internal error>" );
		}
	ENSURES_EXT( LOOP_BOUND_OK, "<Internal error>" );
	ENSURES_EXT( i < objectNameInfoSize, "<Internal error>" );

	return( objectNameInfo[ i ].objectName );
	}
#endif /* USE_ERRMSGS */

/****************************************************************************
*																			*
*							Checksum/Hash Functions							*
*																			*
****************************************************************************/

/* Calculate a 16-bit Fletcher-like checksum for a block of data.  This 
   isn't a true Fletcher checksum but this isn't a big deal since all we 
   need is consistent results for identical data, the value itself is never 
   communicated externally.  In cases where it's used in critical checks 
   it's merely used as a quick pre-check for a full hash-based check, so it 
   doesn't have to be perfect.  In addition it's not in any way 
   cryptographically secure for the same reason, there's no particular need 
   for it to be secure.  If a requirement for at least some sort of 
   unpredictability did arise then something like Pearson hashing could be 
   substituted transparently */

RETVAL_RANGE( MAX_ERROR, 0x7FFFFFFF ) STDC_NONNULL_ARG( ( 1 ) ) \
int checksumData( IN_BUFFER( dataLength ) const void *data, 
				  IN_DATALENGTH const int dataLength )
	{
	const BYTE *dataPtr = data;
	LOOP_INDEX i;
	int sum1 = 1, sum2 = 0;

	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( data != NULL );
	REQUIRES( isBufsizeRangeNZ( dataLength ) )

	LOOP_MAX( i = 0, i < dataLength, i++ )
		{
		ENSURES( LOOP_INVARIANT_MAX( i, 0, dataLength - 1 ) );

		sum1 += dataPtr[ i ];
		sum2 += sum1;
		}
	ENSURES( LOOP_BOUND_OK );

#if defined( SYSTEM_16BIT )
	return( sum2 & 0x7FFF );
#else
	return( ( ( sum2 & 0x7FFF ) << 16 ) | ( sum1 & 0xFFFF ) );
#endif /* 16- vs. 32-bit systems */
	}

/* Calculate the hash of a block of data.  We use SHA-1 because it's the 
   built-in default, but any algorithm will do since we're only using it
   to transform a variable-length value to a fixed-length one for easy
   comparison purposes */

STDC_NONNULL_ARG( ( 1, 3 ) ) \
void hashData( OUT_BUFFER_FIXED( hashMaxLength ) BYTE *hash, 
			   IN_LENGTH_HASH const int hashMaxLength, 
			   IN_BUFFER( dataLength ) const void *data, 
			   IN_DATALENGTH const int dataLength )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int hashSize;

	assert( isWritePtrDynamic( hash, hashMaxLength ) );
	assert( hashMaxLength >= MIN_HASHSIZE && \
			hashMaxLength <= CRYPT_MAX_HASHSIZE );
	assert( isReadPtrDynamic( data, dataLength ) );
	assert( isBufsizeRangeNZ( dataLength ) );

	/* Get the hash algorithm information if necessary */
	getHashAtomicParameters( CRYPT_ALGO_SHA1, 0, &hashFunctionAtomic, 
							 &hashSize );

	/* Error handling: If there's a problem, return a zero hash.  We use 
	   this strategy since this is a void function and so the usual 
	   REQUIRES() predicate won't be effective.  Note that this can lead to 
	   a false-positive match if we're called multiple times with invalid 
	   input, in theory we could fill the return buffer with nonce data to 
	   ensure that we never get a false-positive match but since this is a 
	   should-never-occur condition anyway it's not certain whether forcing 
	   a match or forcing a non-match is the preferred behaviour */
	if( data == NULL || !isBufsizeRangeNZ( dataLength ) || \
		hashMaxLength < MIN_HASHSIZE || hashMaxLength > hashSize || \
		hashMaxLength > CRYPT_MAX_HASHSIZE || hashFunctionAtomic == NULL )
		{
		if( hashMaxLength < MIN_HASHSIZE || \
			hashMaxLength > CRYPT_MAX_HASHSIZE )
			{
			/* This is a shouldn't-occur on top of a shouldn't-occur, the 
			   best that we can do is zero at least 64 bits */
			memset( hash, 0, 8 );
			}
		else
			{
			REQUIRES_V( isShortIntegerRangeNZ( hashMaxLength ) ); 
			memset( hash, 0, hashMaxLength );
			}
		retIntError_Void();
		}

	/* Hash the data and copy as many bytes as the caller has requested to
	   the output.  Typically they'll require only a subset of the full 
	   amount since all that we're doing is transforming a variable-length
	   value to a fixed-length value for easy comparison purposes */
	hashFunctionAtomic( hashBuffer, hashSize, data, dataLength );
	REQUIRES_V( rangeCheck( hashMaxLength, 1, hashSize ) );
	memcpy( hash, hashBuffer, hashMaxLength );
	REQUIRES_V( isShortIntegerRangeNZ( hashSize ) ); 
	zeroise( hashBuffer, hashSize );
	}

/* Compare two blocks of memory in a time-independent manner.  This is used 
   to avoid potential timing attacks on memcmp(), which bails out as soon as
   it finds a mismatch.  Note that we explicitly return TRUE or FALSE since
   calling functions explicitly check for a return value of TRUE rather than 
   just zero/non-zero */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
BOOLEAN compareDataConstTime( IN_BUFFER( length ) const void *src,
							  IN_BUFFER( length ) const void *dest,
							  IN_LENGTH_SHORT const int length )
	{
	const BYTE *srcPtr = src, *destPtr = dest;
	LOOP_INDEX i;
	int value = 0;

	assert( isReadPtrDynamic( src, length ) );
	assert( isReadPtrDynamic( dest, length ) );

	REQUIRES_B( isShortIntegerRangeNZ( length ) );

	/* Compare the two values in a time-independent manner */
	LOOP_MAX( i = 0, i < length, i++ )
		{
		ENSURES( LOOP_INVARIANT_MAX( i, 0, length - 1 ) );

		value |= srcPtr[ i ] ^ destPtr[ i ];
		}
	ENSURES( LOOP_BOUND_OK );

	return( value ? FALSE : TRUE );
	}

/****************************************************************************
*																			*
*							Stream Export/Import Routines					*
*																			*
****************************************************************************/

/* Export attribute or certificate data to a stream.  In theory we would
   have to export this via a dynbuf and then write it to the stream but we 
   can save some overhead by writing it directly to the stream's buffer.
   
   Some attributes have a user-defined size (e.g. 
   CRYPT_IATTRIBUTE_RANDOM_NONCE) so we allow the caller to specify an 
   optional length parameter indicating how much of the attribute should be 
   exported */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exportAttr( INOUT_PTR STREAM *stream, 
					   IN_HANDLE const CRYPT_HANDLE cryptHandle,
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attributeType,
					   IN_LENGTH_INDEF const int length )
							/* Declared as LENGTH_INDEF because SHORT_INDEF
							   doesn't make sense */
	{
	MESSAGE_DATA msgData;
	void *dataPtr = NULL;
	int attrLength = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );

	REQUIRES( cryptHandle == SYSTEM_OBJECT_HANDLE || \
			  isHandleRangeValid( cryptHandle ) );
	REQUIRES( isAttribute( attributeType ) || \
			  isInternalAttribute( attributeType ) );
	REQUIRES( ( length == CRYPT_UNUSED ) || \
			  isShortIntegerRangeMin( length, 8 ) );

	/* Get access to the stream buffer if required */
	if( !sIsNullStream( stream ) )
		{
		if( length != CRYPT_UNUSED )
			{
			/* It's an explicit-length attribute, make sure that there's 
			   enough room left in the stream for it */
			attrLength = length;
			status = sMemGetDataBlock( stream, &dataPtr, length );
			}
		else
			{
			/* It's an implicit-length attribute whose maximum length is 
			   defined by the stream size */
			status = sMemGetDataBlockRemaining( stream, &dataPtr, 
												&attrLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Export the attribute directly into the stream buffer */
	setMessageData( &msgData, dataPtr, 
					min( attrLength, MAX_INTLENGTH_SHORT - 1 ) );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, attributeType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length, SSKIP_MAX );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportAttributeToStream( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr, 
							 IN_HANDLE const CRYPT_HANDLE cryptHandle,
							 IN_ATTRIBUTE \
								const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( cryptHandle ) );
	REQUIRES( isAttribute( attributeType ) || \
			  isInternalAttribute( attributeType ) );

	return( exportAttr( streamPtr, cryptHandle, attributeType, \
						CRYPT_UNUSED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportVarsizeAttributeToStream( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr,
									IN_HANDLE const CRYPT_HANDLE cryptHandle,
									IN_LENGTH_FIXED( CRYPT_IATTRIBUTE_RANDOM_NONCE ) \
										const CRYPT_ATTRIBUTE_TYPE attributeType,
									IN_RANGE( 8, 1024 ) \
										const int attributeDataLength )
	{
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );

	REQUIRES( cryptHandle == SYSTEM_OBJECT_HANDLE );
	REQUIRES( attributeType == CRYPT_IATTRIBUTE_RANDOM_NONCE );
	REQUIRES( attributeDataLength >= 8 && \
			  attributeDataLength <= MAX_ATTRIBUTE_SIZE );

	return( exportAttr( streamPtr, cryptHandle, attributeType, 
						attributeDataLength ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportCertToStream( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr,
						IN_HANDLE const CRYPT_CERTIFICATE cryptCertificate,
						IN_ENUM( CRYPT_CERTFORMAT ) \
							const CRYPT_CERTFORMAT_TYPE certFormatType )
	{
	MESSAGE_DATA msgData;
	STREAM *stream = streamPtr;
	void *dataPtr = NULL;
	int length = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );

	REQUIRES( isHandleRangeValid( cryptCertificate ) );
	REQUIRES( isEnumRange( certFormatType, CRYPT_CERTFORMAT ) );

	/* Get access to the stream buffer if required */
	if( !sIsNullStream( stream ) )
		{
		status = sMemGetDataBlockRemaining( stream, &dataPtr, &length );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Export the certificate directly into the stream buffer */
	setMessageData( &msgData, dataPtr, length );
	status = krnlSendMessage( cryptCertificate, IMESSAGE_CRT_EXPORT,
							  &msgData, certFormatType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length, SSKIP_MAX );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 7 ) ) \
int importCertFromStream( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr,
						  OUT_HANDLE_OPT CRYPT_CERTIFICATE *cryptCertificate,
						  IN_HANDLE const CRYPT_USER iCryptOwner,
						  IN_ENUM( CRYPT_CERTTYPE ) \
							const CRYPT_CERTTYPE_TYPE certType, 
						  IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
							const int certDataLength,
						  IN_FLAGS_Z( KEYMGMT ) const int options,
						  INOUT_PTR ERROR_INFO *errorInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM *stream = streamPtr;
	void *dataPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( isWritePtr( cryptCertificate, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( iCryptOwner ) );
	REQUIRES( isEnumRange( certType, CRYPT_CERTTYPE ) );
	REQUIRES( isShortIntegerRangeMin( certDataLength, \
									  MIN_CRYPT_OBJECTSIZE ) );
	REQUIRES( isFlagRangeZ( options, KEYMGMT ) && \
			  ( options & ~KEYMGMT_FLAG_DATAONLY_CERT ) == 0 );

	/* Clear return value */
	*cryptCertificate = CRYPT_ERROR;

	/* Get access to the stream buffer and skip over the certificate data */
	status = sMemGetDataBlock( stream, &dataPtr, certDataLength );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, certDataLength, SSKIP_MAX );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the certificate directly from the stream buffer */
	setMessageCreateObjectIndirectInfoEx( &createInfo, dataPtr, 
						certDataLength, certType,
						( options & KEYMGMT_FLAG_DATAONLY_CERT ) ? \
							KEYMGMT_FLAG_DATAONLY_CERT : KEYMGMT_FLAG_NONE,
						errorInfo );
	createInfo.cryptOwner = iCryptOwner;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );

	*cryptCertificate = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Public-key Import Routines						*
*																			*
****************************************************************************/

#ifdef USE_INT_ASN1

/* Read a public key from an X.509 SubjectPublicKeyInfo record, creating the
   context necessary to contain it in the process.  This is used by a variety
   of modules including certificate-management, keysets, and crypto devices */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkKeyLength( INOUT_PTR STREAM *stream,
						   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
						   IN_BOOL const BOOLEAN hasAlgoParameters )
	{
	const long startPos = stell( stream );
	int keyLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isPkcAlgo( cryptAlgo ) );
	REQUIRES( isBooleanValue( hasAlgoParameters ) );
	REQUIRES( isIntegerRangeNZ( startPos ) );

	/* ECC algorithms are a complete mess to handle because of the arbitrary
	   manner in which the algorithm parameters can be represented.  To deal
	   with this we skip the parameters and read the public key value, which 
	   is a point on a curve stuffed in a variety of creative ways into an 
	   BIT STRING.  Since this contains two values (the x and y coordinates) 
	   we divide the lengths used by two to get an approximation of the 
	   nominal key size */
	if( isEccAlgo( cryptAlgo ) )
		{
		readUniversal( stream );	/* Skip algorithm parameters */
		status = readBitStringHole( stream, &keyLength, 
									MIN_PKCSIZE_ECCPOINT_THRESHOLD, 
									DEFAULT_TAG );
		if( cryptStatusOK( status ) && isShortECCKey( keyLength / 2 ) )
			status = CRYPT_ERROR_NOSECURE;
		if( cryptStatusError( status ) )
			return( status );

		return( sseek( stream, startPos ) );
		}

	/* Read the key component that defines the nominal key size, either the 
	   first algorithm parameter or the first public-key component */
	if( hasAlgoParameters )
		{
		readSequence( stream, NULL );
		status = readGenericHole( stream, &keyLength, MIN_PKCSIZE_THRESHOLD, 
								  BER_INTEGER );
		}
	else
		{
		readBitStringHole( stream, NULL, MIN_PKCSIZE_THRESHOLD, DEFAULT_TAG );
		readSequence( stream, NULL );
		status = readGenericHole( stream, &keyLength, MIN_PKCSIZE_THRESHOLD, 
								  BER_INTEGER );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Check whether the nominal keysize is within the range defined as 
	   being a weak key */
	if( isShortPKCKey( keyLength ) )
		return( CRYPT_ERROR_NOSECURE );

	return( sseek( stream, startPos ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int iCryptReadSubjectPublicKey( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr, 
								OUT_HANDLE_OPT CRYPT_CONTEXT *iPubkeyContext,
								IN_HANDLE const CRYPT_DEVICE iCreatorHandle, 
								IN_BOOL const BOOLEAN deferredLoad )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_CONTEXT iCryptContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	STREAM *stream = streamPtr;
	ALGOID_PARAMS algoIDparams;
	void *spkiPtr DUMMY_INIT_PTR;
	const int startPos = stell( stream );
	int spkiLength, status;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( iPubkeyContext, sizeof( CRYPT_CONTEXT ) ) );

#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	REQUIRES( iCreatorHandle == SYSTEM_OBJECT_HANDLE || \
			  iCreatorHandle == CRYPTO_OBJECT_HANDLE || \
			  isHandleRangeValid( iCreatorHandle ) );
#else
	REQUIRES( iCreatorHandle == SYSTEM_OBJECT_HANDLE || \
			  isHandleRangeValid( iCreatorHandle ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
	REQUIRES( isBooleanValue( deferredLoad ) );
	REQUIRES( isIntegerRange( startPos ) );

	/* Clear return value */
	*iPubkeyContext = CRYPT_ERROR;

	/* Pre-parse the SubjectPublicKeyInfo, both to ensure that it's (at 
	   least generally) valid before we go to the extent of creating an 
	   encryption context to contain it and to get access to the 
	   SubjectPublicKeyInfo data and algorithm information.  Because all 
	   sorts of bizarre tagging exist due to things like CRMF we read the 
	   wrapper as a generic hole rather than the more obvious SEQUENCE */
	status = getStreamObjectLength( stream, &spkiLength, 16 );
	if( cryptStatusOK( status ) )
		status = sMemGetDataBlock( stream, &spkiPtr, spkiLength );
	if( cryptStatusOK( status ) )
		{
		status = readGenericHole( stream, NULL, 
								  MIN_PKCSIZE_ECCPOINT_THRESHOLD, 
								  DEFAULT_TAG );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = readAlgoIDex( stream, &cryptAlgo, &algoIDparams, 
						   ALGOID_CLASS_PKC );
	if( cryptStatusError( status ) )
		return( status );

	/* Perform minimal key-length checking.  We need to do this at this 
	   point (rather than having it done implicitly in the 
	   SubjectPublicKeyInfo read code) because a too-short key (or at least 
	   too-short key data) will result in the kernel rejecting the 
	   SubjectPublicKeyInfo before it can be processed, leading to a rather 
	   misleading CRYPT_ERROR_BADDATA return status rather than the correct 
	   CRYPT_ERROR_NOSECURE */
	status = checkKeyLength( stream, cryptAlgo,
							 ( algoIDparams.extraLength > 0 ) ? \
							   TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Skip the remainder of the key components in the stream, first the
	   algorithm parameters (if there are any) and then the public-key 
	   data */
	if( algoIDparams.extraLength > 0 )
		readUniversal( stream );
	status = readUniversal( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Since we're doing a direct import of a memory block, make sure that 
	   the claimed object length as given in the wrapper matches the actual 
	   payload length */
	if( stell( stream ) - startPos != spkiLength )
		return( CRYPT_ERROR_BADDATA );

	/* Create the public-key context and send the key data to it */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( iCreatorHandle, IMESSAGE_DEV_CREATEOBJECT, 
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iCryptContext = createInfo.cryptHandle;
	setMessageData( &msgData, spkiPtr, spkiLength );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, deferredLoad ? \
								CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL : \
								CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		if( status == CRYPT_ARGERROR_STR1 || \
			status == CRYPT_ARGERROR_NUM1 )
			{
			/* If the key data was rejected by the kernel before it got to 
			   the SubjectPublicKeyInfo read code (see the comment above) 
			   then it'll be rejected with an argument-error code, which we
			   have to convert to a bad-data error before returning it to 
			   the caller */
			return( CRYPT_ERROR_BADDATA );
			}
		if( cryptArgError( status ) )
			{
			DEBUG_DIAG(( "Public-key load returned argError status %d",
						 status ));
			assert( DEBUG_WARN );
			status = CRYPT_ERROR_BADDATA;
			}
		return( status );
		}
	*iPubkeyContext = iCryptContext;
	assert( !checkContextCapability( iCryptContext, 
									 MESSAGE_CHECK_PKC_PRIVATE ) );

	return( CRYPT_OK );
	}
#endif /* USE_INT_ASN1 */

/****************************************************************************
*																			*
*							Safe Text-line Read Functions					*
*																			*
****************************************************************************/

#if defined( USE_HTTP ) || defined( USE_BASE64 ) || defined( USE_SSH )

/* Read a line of text data ending in an EOL.  If we get more data than will 
   fit into the read buffer we discard it until we find an EOL.  As a 
   secondary concern we want to strip leading, trailing, and repeated 
   whitespace.  Leading whitespace is handled by setting the seen-whitespace 
   flag to true initially, this treats any whitespace at the start of the 
   line as superfluous and strips it.  Stripping of repeated whitespace is 
   also handled by the seenWhitespace flag, and stripping of trailing 
   whitespace is handled by walking back through any final whitespace once we 
   see the EOL. 
   
   We optionally handle continued lines denoted by the MIME convention of a 
   semicolon as the last non-whitespace character by setting the 
   seenContinuation flag if we see a semicolon as the last non-whitespace 
   character.

   Finally, we also need to handle generic DoS attacks.  If we see more than
   MAX_LINE_LENGTH characters in a line we bail out */

#define MAX_LINE_LENGTH		4096

/* The extra level of indirection provided by this function is necessary 
   because the the extended error information isn't accessible from outside 
   the stream code so we can't set it in formatTextLineError() in the usual 
   manner via a retExt().  Instead we call retExtFn() directly and then pass 
   the result down to the stream layer via an ioctl */

CHECK_RETVAL_ERROR STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int exitTextLineError( INOUT_PTR STREAM *stream,
							  FORMAT_STRING const char *format, 
							  const int value1, const int value2,
							  OUT_OPT_BOOL BOOLEAN *localError,
							  IN_ERROR const int status )
	{
	ERROR_INFO localErrorInfo;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( format, 4 ) );
	assert( localError == NULL || \
			isReadPtr( localError, sizeof( BOOLEAN ) ) );

	REQUIRES( cryptStatusError( status ) );

	/* If the stream doesn't support extended error information, we're 
	   done */
	if( localError == NULL )
		return( status );

	/* The CRYPT_ERROR_BADDATA is a dummy code used in order to be able to 
	   call retExtFn() to format the error string */
	clearErrorInfo( &localErrorInfo );
	*localError = TRUE;
#ifdef USE_ERRMSGS
	( void ) retExtFn( CRYPT_ERROR_BADDATA, &localErrorInfo, format, 
					   value1, value2 );	/* Fill in localErrorInfo */
#endif /* USE_ERRMSGS */
	sioctlSetString( stream, STREAM_IOCTL_ERRORINFO, &localErrorInfo, 
					 sizeof( ERROR_INFO ) );

	return( status );
	}

CHECK_RETVAL_RANGE( 0, 255 ) STDC_NONNULL_ARG( ( 1 ) ) \
static int networkReadCharFunction( INOUT_PTR TYPECAST( STREAM * ) \
										struct ST *streamPtr )
	{
	STREAM *stream = streamPtr;
	BYTE ch;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* This readChar function is necessary because sgetc() only works on 
	   file and memory streams, so we emulate a network-stream sgetc()
	   here */
	status = sread( stream, &ch, 1 );
	return( cryptStatusError( status ) ? status : byteToInt( ch ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int readTextLine( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr,
				  OUT_BUFFER( lineBufferMaxLen, *lineBufferSize ) \
						char *lineBuffer,
				  IN_LENGTH_SHORT_MIN( 16 ) const int lineBufferMaxLen, 
				  OUT_RANGE( 0, lineBufferMaxLen ) int *lineBufferSize, 
				  OUT_OPT_BOOL BOOLEAN *localError,
				  IN_PTR_OPT READCHAR_FUNCTION readCharFunctionOpt, 
				  IN_ENUM_OPT( READTEXT ) const READTEXT_TYPE options )
	{
	READCHAR_FUNCTION readCharFunction = \
		( readCharFunctionOpt != NULL ) ? readCharFunctionOpt : \
		( streamPtr->type == STREAM_TYPE_NETWORK ) ? \
		  networkReadCharFunction : sgetc;
	BOOLEAN seenWhitespace, seenContinuation = FALSE;
	LOOP_INDEX totalChars;
	int bufPos = 0;

	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( lineBuffer, lineBufferMaxLen ) );
	assert( isWritePtr( lineBufferSize, sizeof( int ) ) );
	assert( localError == NULL || \
			isWritePtr( localError, sizeof( BOOLEAN ) ) );

	REQUIRES( isShortIntegerRangeMin( lineBufferMaxLen, 16 ) );
	REQUIRES( isEnumRangeOpt( options, READTEXT ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( lineBufferMaxLen ) ); 
	memset( lineBuffer, 0, min( 16, lineBufferMaxLen ) );
	*lineBufferSize = 0;
	if( localError != NULL )
		*localError = FALSE;

	/* Set the seen-whitespace flag initially to strip leading whitespace */
	seenWhitespace = TRUE;

	/* Read up to MAX_LINE_LENGTH chars.  Anything longer than this is 
	   probably a DoS */
	LOOP_MAX( totalChars = 0, totalChars < MAX_LINE_LENGTH, totalChars++ )
		{
		int ch, status, LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_MAX( totalChars, 0, MAX_LINE_LENGTH - 1 ) );

		/* Get the next input character */
		status = ch = readCharFunction( streamPtr );
		if( cryptStatusError( status ) )
			{
			/* Now we run into a special-case condition where some software 
			   may forget to end a line, or the final line in a longer 
			   message, with an EOL, in which case we get a 
			   CRYPT_ERROR_UNDERFLOW to indicate that we've run out of data
			   rather than encountering an EOL.  To deal with this, if we've
			   read at least 3 characters of text, we treat a 
			   CRYPT_ERROR_UNDERFLOW as if there was an EOL at this point */
			if( status == CRYPT_ERROR_UNDERFLOW && bufPos >= 3 )
				{
				/* Since we've run out of data in the stream it'll be in the
				   error state, so we need to reset it before continuing 
				   since we're emulating a valid read of an EOL */
				sClearError( streamPtr );
				ch = '\n';
				}
			else
				{
				/* It's some other type of error or there's nothing to 
				   return, it's a real error */
				return( status );
				}
			}                 

		/* If it's an EOL and we're returning raw data, don't perform any 
		   further processing such as stripping of trailing whitespace */
		if( options == READTEXT_RAW && ch == '\n' )
			break;

		/* If it's an EOL or a continuation marker, strip trailing 
		   whitespace */
		if( ch == '\n' || \
			( options == READTEXT_MULTILINE && ch == ';' ) )
			{
			/* Strip trailing whitespace.  At this point it's all been
			   canonicalised so we don't need to check for anything other 
			   than spaces */
			LOOP_LARGE_REV_CHECKINC_ALT( bufPos > 0 && \
											lineBuffer[ bufPos - 1 ] == ' ',
										 bufPos-- )
				{
				ENSURES( LOOP_INVARIANT_LARGE_REV_XXX_ALT( bufPos, 1, 
														   totalChars ) );
						 /* totalChars is the overall number of characters 
						    seen which is always the same or larger than 
							bufPos, the number of characters stored */
				}
			ENSURES( LOOP_BOUND_LARGE_REV_OK_ALT );
			}

		/* Process EOL */
		if( ch == '\n' )
			{
			/* If we've seen a continuation marker, the line continues on 
			   the next one */
			if( seenContinuation )
				{
				seenContinuation = FALSE;
				continue;
				}

			/* We're done */
			break;
			}

		/* Ignore any additional decoration that may accompany EOLs */
		if( ch == '\r' )
			continue;

		/* If we're over the maximum buffer size and we're not returning the 
		   raw input data, discard any further input until we either hit EOL 
		   or exceed the DoS threshold at MAX_LINE_LENGTH */
		if( bufPos >= lineBufferMaxLen )
			{
			/* If we've run off into the weeds (for example we're reading 
			   binary data following the text header), bail out */
			if( !isValidTextChar( ch ) )
				{
				return( exitTextLineError( streamPtr, "Invalid character "
										   "0x%02X at position %d", ch, 
										   totalChars, localError,
										   CRYPT_ERROR_BADDATA ) );
				}
			if( options == READTEXT_RAW )
				{
				/* We've been asked to return all input but there's not 
				   enough room for it */
				return( exitTextLineError( streamPtr, "Text line too long, "
										   "more than %d characters", 
										   lineBufferMaxLen, 0, localError, 
										   CRYPT_ERROR_OVERFLOW ) );
				}
			continue;
			}

		/* Process whitespace if necessary.  We can't use isspace() for this 
		   because it includes all sorts of extra control characters that we 
		   don't want to allow */
		if( options != READTEXT_RAW && ( ch == ' ' || ch == '\t' ) )
			{
			if( seenWhitespace )
				{
				/* Ignore leading and repeated whitespace */
				continue;
				}
			ch = ' ';	/* Canonicalise whitespace */
			}

		/* Process any remaining chars */
		if( !isValidTextChar( ch ) )
			{
			return( exitTextLineError( streamPtr, "Invalid character "
									   "0x%02X at position %d", ch, 
									   totalChars, localError,
									   CRYPT_ERROR_BADDATA ) );
			}
		lineBuffer[ bufPos++ ] = intToByte( ch );
		ENSURES( bufPos > 0 && bufPos <= totalChars + 1 && \
				 bufPos < MAX_LINE_LENGTH );
				 /* The 'totalChars + 1' is because totalChars is the loop
				    iterator and won't have been incremented yet at this 
					point */

		/* Update the state variables.  If the character that we've just 
		   processed was whitespace or if we've seen a continuation 
		   character or we're processing whitespace after having seen a 
		   continuation character (which makes it effectively leading 
		   whitespace to be stripped), remember this */
		seenWhitespace = ( ch == ' ' ) ? TRUE : FALSE;
		seenContinuation = ( options == READTEXT_MULTILINE ) && \
						   ( ch == ';' || \
						     ( seenContinuation && seenWhitespace ) ) ? \
						   TRUE : FALSE;
		}
	ENSURES( LOOP_BOUND_OK );
	if( totalChars >= MAX_LINE_LENGTH )
		{
		return( exitTextLineError( streamPtr, "Text line too long, more "
								   "than %d characters", MAX_LINE_LENGTH, 0, 
								   localError, CRYPT_ERROR_OVERFLOW ) );
		}
	*lineBufferSize = bufPos;

	return( CRYPT_OK );
	}
#endif /* USE_HTTP || USE_BASE64 || USE_SSH */

/****************************************************************************
*																			*
*								Self-test Functions							*
*																			*
****************************************************************************/

/* Test code for the above functions */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#if defined( USE_HTTP ) || defined( USE_BASE64 ) || defined( USE_SSH )

#include "io/stream.h"

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static BOOLEAN testReadLine( IN_BUFFER( dataInLength ) char *dataIn,
							 IN_LENGTH_SHORT_MIN( 2 ) const int dataInLength, 
							 IN_BUFFER( dataOutLength ) char *dataOut,
							 IN_LENGTH_SHORT_MIN( 1 ) const int dataOutLength,
							 IN_ENUM_OPT( READTEXT ) const READTEXT_TYPE options,
							 IN_BOOL const BOOLEAN testTruncation )
	{
	STREAM stream;
	BYTE buffer[ 32 + 8 ];
	int length, status;

	assert( isReadPtrDynamic( dataIn, dataInLength ) );
	assert( isReadPtrDynamic( dataOut, dataOutLength ) );

	REQUIRES_B( isShortIntegerRangeMin( dataInLength, 2 ) );
	REQUIRES_B( isShortIntegerRangeMin( dataOutLength, 1 ) && \
				dataOutLength <= 32 );
	REQUIRES_B( isEnumRangeOpt( options, READTEXT ) );
	REQUIRES_B( isBooleanValue( testTruncation ) );

	/* The self-test code tests, among other things, truncation of overly 
	   long input lines, in which case we give the buffer size as 
	   'dataOutLength', the potential truncation point, rather than the 
	   actual buffer size */
	memset( buffer, '*', 32 );	/* Pollute the data buffer */
	sMemPseudoConnect( &stream, dataIn, dataInLength );
	status = readTextLine( &stream, buffer, 
						   testTruncation ? dataOutLength : 32, &length, 
						   NULL, NULL, options );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( length != dataOutLength || memcmp( buffer, dataOut, dataOutLength ) )
		return( FALSE );
	sMemDisconnect( &stream );

	return( TRUE );
	}
#endif /* USE_HTTP || USE_BASE64 || USE_SSH */

#if defined( USE_BASE64 ) 

static BOOLEAN testBase64( void )
	{
	const char *base64string = "aaaaaaaaaaaaaaaaaaaaaaaa";
	BYTE buffer[ 20 + 8 ];
	LOOP_INDEX inLength;
	int outLength, decodedOutLength, status;

	LOOP_MED( inLength = 10, inLength < 24, inLength++ )
		{
		ENSURES( LOOP_INVARIANT_MED( inLength, 10, 23 ) );

		/* Skip non-decodable lengths */
		if( inLength == 13 || inLength == 17 || inLength == 21 )
			continue;

		/* Verify that the calculated decoded-length value matches the 
		   actual decoded length */
		status = base64decodeLen( base64string, inLength, 
								  &decodedOutLength );
		if( cryptStatusError( status ) )
			return( FALSE );
		status = base64decode( buffer, 20, &outLength, base64string, 
							   inLength, CRYPT_CERTFORMAT_NONE );
		if( cryptStatusError( status ) )
			return( FALSE );
		if( outLength != decodedOutLength )
			return( FALSE );
		}
	ENSURES_B(  LOOP_BOUND_OK );

	return( TRUE );
	}
#endif /* USE_BASE64 */

CHECK_RETVAL_BOOL \
BOOLEAN testIntAPI( void )
	{
	static_assert( MIN_KEYSIZE <= 10,
				   "MIN_KEYSIZE is larger than entropy test vector size" );

	/* Test the non-trivial key check code */
	if( !checkNontrivialKey( "\x2E\x19\x76\x57\xDB\x30\xE6\x26\x83\x76", 10 ) || \
		!checkNontrivialKey( "\x14\xF3\x3C\x5A\xB8\x63\x13\xFB\x5B\xAF", 10 ) || \
		!checkNontrivialKey( "\x7B\xE0\xE4\x14\x5C\x7C\x2C\x07\x02\xD9", 10 ) || \
		!checkNontrivialKey( "\xD3\x9C\x16\x37\xAD\x12\x19\xA2\x5E\x8C", 10 ) || \
		!checkNontrivialKey( "\x7F\x6B\x30\xAD\x02\x83\x96\xF9\x52\xF6", 10 ) || \
		!checkNontrivialKey( "\x79\x92\xF9\xD1\x75\x43\x56\x87\x65\x61", 10 ) || \
		!checkNontrivialKey( "\x62\xAF\x14\xCF\x1F\x5F\xA7\xC6\x5B\x45", 10 ) || \
		!checkNontrivialKey( "\xAE\x57\xF3\x63\x45\x03\x2E\x6B\x59\xDE", 10 ) )
		return( FALSE );
	if( checkNontrivialKey( "abcdefghij", 10 ) || \
		checkNontrivialKey( "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5", 10 ) || \
		checkNontrivialKey( "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A", 10 ) || \
		checkNontrivialKey( "\x2E\x19\x76\x57\xDB\x30\xE6\x26\x83\x76"
							"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
							"\x14\xF3\x3C\x5A\xB8\x63\x13\xFB\x5B\xAF", 30 ) )
		return( FALSE );

	/* Test the entropy-check code */
	if( !checkEntropy( "\x2E\x19\x76\x57\xDB\x30\xE6\x26\x83\x76", 10 ) || \
		!checkEntropy( "\x14\xF3\x3C\x5A\xB8\x63\x13\xFB\x5B\xAF", 10 ) || \
		!checkEntropy( "\x7B\xE0\xE4\x14\x5C\x7C\x2C\x07\x02\xD9", 10 ) || \
		!checkEntropy( "\xD3\x9C\x16\x37\xAD\x12\x19\xA2\x5E\x8C", 10 ) || \
		!checkEntropy( "\x7F\x6B\x30\xAD\x02\x83\x96\xF9\x52\xF6", 10 ) || \
		!checkEntropy( "\x79\x92\xF9\xD1\x75\x43\x56\x87\x65\x61", 10 ) || \
		!checkEntropy( "\x62\xAF\x14\xCF\x1F\x5F\xA7\xC6\x5B\x45", 10 ) || \
		!checkEntropy( "\xAE\x57\xF3\x63\x45\x03\x2E\x6B\x59\xDE", 10 ) )
		return( FALSE );
	if( checkEntropy( "\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A\xA5\x5A", 10 ) )
		return( FALSE );

	/* Test the hash algorithm-strength code */
	if( isStrongerHash( CRYPT_ALGO_SHA1, CRYPT_ALGO_SHA2 ) || \
		!isStrongerHash( CRYPT_ALGO_SHA2, CRYPT_ALGO_SHA1 ) || \
		isStrongerHash( CRYPT_ALGO_MD5, CRYPT_ALGO_SHA2 ) || \
		!isStrongerHash( CRYPT_ALGO_SHA2, CRYPT_ALGO_MD5 ) )
		return( FALSE );

	/* Test the checksumming code */
	if( checksumData( "12345678", 8 ) != checksumData( "12345678", 8 ) || \
		checksumData( "12345678", 8 ) == checksumData( "12345778", 8 ) || \
		checksumData( "12345678", 8 ) == checksumData( "12345\xB7" "78", 8 ) || \
		checksumData( "12345678", 8 ) == checksumData( "12345\x00" "78", 8 ) )
		return( FALSE );

	/* Test the base64 code */
#if defined( USE_BASE64 ) 
	if( !testBase64() )
		return( FALSE );
#endif /* USE_BASE64 */

	/* Test the text-line read code */
#if defined( USE_HTTP ) || defined( USE_BASE64 ) || defined( USE_SSH )
	if( !testReadLine( "abcdefgh\n", 9, "abcdefgh", 8, READTEXT_NONE, 
					   FALSE ) || \
		!testReadLine( "abcdefghijklmnopq\n", 18, 
					   "abcdefghijklmnop", 16, READTEXT_NONE, TRUE ) || \
		!testReadLine( " abcdefgh\n", 10, "abcdefgh", 8, READTEXT_NONE, 
					   FALSE ) || \
		!testReadLine( "abcdefgh \n", 10, "abcdefgh", 8, READTEXT_NONE, 
					   FALSE ) || \
		!testReadLine( " ab cdefgh \n", 12, "ab cdefgh", 9, 
					   READTEXT_NONE, FALSE ) || \
		!testReadLine( "   ab   cdefgh   \n", 18, "ab cdefgh", 9, 
					   READTEXT_NONE, FALSE ) )
		return( FALSE );
	if( !testReadLine( "abcdefgh", 8, "abcdefgh", 8, READTEXT_NONE, 
					   FALSE ) || \
		!testReadLine( " abcdefgh", 9, "abcdefgh", 8, READTEXT_NONE, 
					   FALSE ) || \
		!testReadLine( "abcdefgh ", 9, "abcdefgh", 8, READTEXT_NONE, 
					   FALSE ) )
		return( FALSE );
	if( !testReadLine( "abcdefgh", 8, "abcdefgh", 8, READTEXT_RAW, 
					   FALSE ) || \
		!testReadLine( " abcdefgh", 9, " abcdefgh", 9, READTEXT_RAW, 
					   FALSE ) || \
		!testReadLine( "abcdefgh ", 9, "abcdefgh ", 9, READTEXT_RAW, 
					   FALSE ) || \
		!testReadLine( "   ab   cdefgh   ", 17, "   ab   cdefgh   ", 17, 
					   READTEXT_RAW, FALSE ) )
		return( FALSE );
	if( !testReadLine( "abcdefgh\r\n", 10, "abcdefgh", 8, 
					   READTEXT_NONE, FALSE ) || \
		!testReadLine( "abcdefgh\r\r\n", 11, "abcdefgh", 8, 
					   READTEXT_NONE, FALSE ) )
		return( FALSE );
	if( testReadLine( "   \t   \n", 8, "", 1, READTEXT_NONE, FALSE ) || \
		testReadLine( "abc\x12" "efgh\n", 9, "", 1, READTEXT_NONE, 
					  FALSE ) || \
		testReadLine( "abc\x12" "efgh\n", 9, "", 1, READTEXT_RAW, 
					  FALSE ) || \
		testReadLine( "  ", 2, "", 1, READTEXT_NONE, FALSE ) )
		return( FALSE );
	if( !testReadLine( "abcdefgh;\nabc\n", 14, 
					   "abcdefgh;", 9, READTEXT_NONE, FALSE ) || \
		!testReadLine( "abcdefgh;\nabc\n", 14, 
					   "abcdefgh;abc", 12, READTEXT_MULTILINE, FALSE ) || \
		!testReadLine( "abcdefgh; \n abc\n", 16, 
					   "abcdefgh;abc", 12, READTEXT_MULTILINE, FALSE ) || \
		!testReadLine( "abcdefgh ; \n abc\n", 17, 
					   "abcdefgh;abc", 12, READTEXT_MULTILINE, 
					   FALSE ) || \
		!testReadLine( "abcdefgh;abc\nabc\n", 17, 
					   "abcdefgh;abc", 12, READTEXT_MULTILINE, FALSE ) )
		return( FALSE );
	if( testReadLine( "abcdefgh;\n", 10, "", 1, READTEXT_MULTILINE, 
					  FALSE ) || \
		testReadLine( "abcdefgh;\n\n", 11, "", 1, READTEXT_MULTILINE, 
					  FALSE ) || \
		testReadLine( "abcdefgh;\n \n", 12, "", 1, READTEXT_MULTILINE, 
					  FALSE ) )
		return( FALSE );
#endif /* USE_HTTP || USE_BASE64 || USE_SSH */

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
