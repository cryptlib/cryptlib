/****************************************************************************
*																			*
*						cryptlib Bignum Support Routines					*
*						Copyright Peter Gutmann 1995-2025					*
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

/* The vast numbers of iterated and/or recursive calls to bignum code means 
   that any diagnostic print routines produce an enormous increase in 
   runtime.  To deal with this we define a conditional value that can be used 
   to control printing of output.  In addition where possible the diagnostic 
   code itself tries to minimise the conditions under which it produces 
   output.
   
   We also define a few static variables that are used to record the size 
   limits reached by various bignum operations, in this case the highest-
   used entry in a BN_CTX.  We start at 28 to avoid outputting too many
   noise values */

#if !defined( NDEBUG ) && defined( USE_ERRMSGS )
static const BOOLEAN diagOutput = FALSE;
static int bnCtxMaxIndex = 28;
#endif /* Debug build with USE_ERRMSGS */

/* If we're not using dynamically-allocated bignums then we need to convert 
   the bn_expand() macros that are used throughout the bignum code into 
   no-ops.  The following value represents dummy non-null location that can 
   be used in the bn_expand() macros.  It's not used for anything except to 
   provide a dummy address for the macro to refer to */

#ifndef BN_ALLOC
int nonNullAddress;
#endif /* BN_ALLOC */

/* If we're debugging the bignum allocation code then the clBnAlloc() macro
   points to the following function */

#ifdef USE_BN_DEBUG_MALLOC

void *clBnAllocFn( const char *fileName, const char *fnName,
				   const int lineNo, size_t size )
	{
	printf( "BNDEBUG: %s:%s:%d %lu bytes.\n", fileName, fnName, 
			lineNo, size );
	return( malloc( size ) );
	}
#endif /* USE_BN_DEBUG_MALLOC */

/* Warn if we're using non-power-of-2 bignum allocations, see bn/bn.h for
   how this check works */

#if ( BIGNUM_ALLOC_WORDS_EXT2 == ( BIGNUM_ALLOC_WORDS * 6 ) ) && \
	( defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ ) )
  #pragma message( "  Building with non-power-of-2 BIGNUM_ALLOC_WORDS workaround." )
#endif /* Non-power-of-2 bignum alloc */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Determine the maximum size (in words) that a particular bignum can be */

CHECK_RETVAL_LENGTH_SHORT_NOERROR STDC_NONNULL_ARG( ( 1 ) ) \
int getBNMaxSize( const BIGNUM *bignum )
	{
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	return( ( bignum->flags & BN_FLG_ALLOC_EXT ) ? BIGNUM_ALLOC_WORDS_EXT : \
			( bignum->flags & BN_FLG_ALLOC_EXT2 ) ? BIGNUM_ALLOC_WORDS_EXT2 : \
			BIGNUM_ALLOC_WORDS );
	}

/* Make sure that a bignum/BN_CTX's metadata is valid */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckBignum( const BIGNUM *bignum )
	{
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	if( bignum->top < 0 || bignum->top > getBNMaxSize( bignum ) )
		return( FALSE );
	if( bignum->neg != TRUE && bignum->neg != FALSE )
		return( FALSE );
	if( bignum->flags < BN_FLG_NONE || bignum->flags > BN_FLG_MAX )
		return( FALSE );
	if( !( bignum->flags & BN_FLG_SCRATCH ) )
		{
		const int bnMaxSize = getBNMaxSize( bignum );
#ifndef NDEBUG
		LOOP_INDEX i;
#endif /* Debug mode */

		/* Make sure that the bignum is normalised, in other words that it 
		   ends at the top word, or at least that at least one zero word 
		   follows the top one since the full check is expensive */
		if( ( bignum->top >= 1 && bignum->d[ bignum->top - 1 ] == 0 ) || \
			( bignum->top < bnMaxSize && bignum->d[ bignum->top ] != 0 ) )
			return( FALSE );
#ifndef NDEBUG
		/* The loop bound is set at bnMaxSize + 1 because we may be checking
		   all-zero bignums for which we iterate through every item in the
		   array */
		LOOP_EXT( i = bignum->top, i < bnMaxSize, i++, bnMaxSize + 1 )
			{
			ENSURES_B( LOOP_INVARIANT_EXT( i, bignum->top, bnMaxSize - 1,
										   bnMaxSize + 1 ) );

			assert( bignum->d[ i ] == 0 );
			}
		ENSURES_B( LOOP_BOUND_OK );
#endif /* Debug mode */
		}

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckBNCTX( const BN_CTX *bnCTX )
	{
	assert( isReadPtr( bnCTX, sizeof( BN_CTX ) ) );

	if( bnCTX->bnArrayMax < 0 || bnCTX->bnArrayMax >= BN_CTX_ARRAY_SIZE )
		return( FALSE );
	if( bnCTX->stackPos < 0 || bnCTX->stackPos >= BN_CTX_ARRAY_SIZE )
		return( FALSE );

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckBNMontCTX( const BN_MONT_CTX *bnMontCTX )
	{
	assert( isReadPtr( bnMontCTX, sizeof( BN_MONT_CTX ) ) );

	if( !sanityCheckBignum( &bnMontCTX->R ) || \
		!sanityCheckBignum( &bnMontCTX->N ) )
		return( FALSE );
	if( bnMontCTX->flags != 0 && bnMontCTX->flags != BN_FLG_MALLOCED )
		return( FALSE );

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*						 Miscellaneous Bignum Routines						*
*																			*
****************************************************************************/

/* Allocate/initialise/clear/free bignums.  The original OpenSSL bignum code 
   allocates storage on-demand, which results in both lots of kludgery to 
   deal with array bounds and buffer sizes moving around and huge numbers 
   of memory-allocation/reallocation calls as bignum data sizes creep slowly 
   upwards until some sort of steady state is reached, whereupon the bignum 
   is destroyed and a new one allocated and the whole cycle begins anew.

   To avoid all of this memory-thrashing we use a fixed-size memory block 
   for each bignum, which is unfortunately somewhat wasteful but saves a 
   lot of memory allocation/reallocation and accompanying heap fragmentation 
   (see also the BN_CTX code comments further down).

   A useful side-effect of the elimination of dynamic memory allocation is 
   that the large number of null pointer dereferences on allocation failure 
   in the OpenSSL bignum code are never triggered because there's always 
   memory allocated for the bignum */

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_clear( INOUT_PTR BIGNUM *bignum )
	{
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	/* We can end up here with bignums that don't pass a sanity check, 
	   either because they're in an error path and in an inconsistent state
	   or because of data corruption.  This means that we can't rely on
	   their contents to tell us what to do, but we can still at least 
	   zeroise them */
	if( !sanityCheckBignum( bignum ) )
		{
		memset( bignum, 0, sizeof( BIGNUM ) );
		return;
		}

	if( !( bignum->flags & BN_FLG_STATIC_DATA ) )
		{
		const int bnMaxSize = getBNMaxSize( bignum );

		DEBUG_PRINT_COND( diagOutput && bignum->top > 64, \
						  ( "BN max.size = %d words.\n", bignum->top ) );
		REQUIRES_V( isShortIntegerRangeNZ( bnMaxSize ) ); 
		zeroise( bignum->d, bnWordsToBytes( bnMaxSize ) );
		bignum->top = bignum->neg = 0;
		bignum->flags &= ~( BN_FLG_CONSTTIME | BN_FLG_SCRATCH );
		}
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_init( OUT_PTR BIGNUM *bignum )
	{
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	memset( bignum, 0, sizeof( BIGNUM ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
static void BN_init_ext( INOUT_PTR void *bignumExtPtr, 
						 IN_BOOL const BOOLEAN isExt2Bignum )
	{
	assert( isWritePtr( bignumExtPtr, sizeof( BIGNUM_EXT ) ) );

	REQUIRES_V( isBooleanValue( isExt2Bignum ) );

	if( isExt2Bignum )
		{
		BIGNUM_EXT2 *bignum = bignumExtPtr;

		memset( bignum, 0, sizeof( BIGNUM_EXT2 ) );
		bignum->flags = BN_FLG_ALLOC_EXT2;
		}
	else
		{
		BIGNUM_EXT *bignum = bignumExtPtr;

		memset( bignum, 0, sizeof( BIGNUM_EXT ) );
		bignum->flags = BN_FLG_ALLOC_EXT;
		}
	}

CHECK_RETVAL_PTR \
BIGNUM *BN_new( void )
	{
	BIGNUM *bignum;

	REQUIRES_N( isShortIntegerRangeNZ( sizeof( BIGNUM ) ) );
	bignum = clAlloc( "BN_new", sizeof( BIGNUM ) );
	if( bignum == NULL )
		return( NULL );
	BN_init( bignum );
	bignum->flags = BN_FLG_MALLOCED;

	return( bignum );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_free( INOUT_PTR BIGNUM *bignum )
	{
	const int flags = bignum->flags;
	
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	/* We can end up here with bignums that don't pass a sanity check, 
	   either because they're in an error path and in an inconsistent state
	   or because of data corruption.  This means that we can't free them
	   because they may not be malloc()'d memory (most bignums are 
	   statically allocated anyway), but we can at least clear them */
	if( !sanityCheckBignum( bignum ) )
		{
		BN_clear( bignum );
		return;
		} 

	BN_clear( bignum );
	if( flags & BN_FLG_MALLOCED )
		clFree( "BN_free", bignum );
	}

#if defined( USE_ECDH ) || defined( USE_ECDSA )

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void EC_POINT_init( INOUT_PTR EC_POINT *ecPoint, 
					IN_PTR const EC_GROUP *ecGroup )
	{
	assert( isWritePtr( ecPoint, sizeof( EC_POINT ) ) );
	assert( isReadPtr( ecGroup, sizeof( EC_GROUP ) ) );

	memset( ecPoint, 0, sizeof( EC_POINT ) );
	ecPoint->meth = ecGroup->meth;
	ENSURES_V( ecPoint->meth != NULL && \
			   ecPoint->meth->point_init != NULL );
	ecPoint->meth->point_init( ecPoint ); 
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void EC_POINT_clear( EC_POINT *ecPoint )
	{
	assert( isWritePtr( ecPoint, sizeof( EC_POINT ) ) );

	if( ecPoint->meth != NULL && \
		ecPoint->meth->point_finish != NULL )
		ecPoint->meth->point_finish( ecPoint );
	memset( ecPoint, 0, sizeof( EC_POINT ) );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void EC_GROUP_init( INOUT_PTR EC_GROUP *ecGroup, 
					IN_PTR const EC_METHOD *ecMethod )
	{
	assert( isWritePtr( ecGroup, sizeof( EC_GROUP ) ) );
	assert( isReadPtr( ecMethod, sizeof( EC_METHOD ) ) );

	memset( ecGroup, 0, sizeof( EC_GROUP ) );
	ecGroup->meth = ecMethod;
	BN_init( &ecGroup->order );
	BN_init( &ecGroup->cofactor );
	ENSURES_V( ecMethod->group_init != NULL );
	ecMethod->group_init( ecGroup );
	}
	
STDC_NONNULL_ARG( ( 1 ) ) \
void EC_GROUP_clear( INOUT_PTR EC_GROUP *ecGroup )
	{
	assert( isWritePtr( ecGroup, sizeof( EC_GROUP ) ) );

	if( ecGroup->meth != NULL && \
		ecGroup->meth->group_finish != NULL )
		ecGroup->meth->group_finish( ecGroup );
	EC_EX_DATA_free_all_data( &ecGroup->extra_data );
	if( EC_GROUP_VERSION( ecGroup ) && ecGroup->mont_data != NULL )
		{
		BN_MONT_CTX_free( ecGroup->mont_data );
		ecGroup->mont_data = NULL;
		}
	if( ecGroup->generator != NULL )
		{
		EC_POINT_free( ecGroup->generator );
		ecGroup->generator = NULL;
		}
	if( ecGroup->seed != NULL )
		{
		OPENSSL_free( ecGroup->seed );
		ecGroup->seed = NULL;
		}
	memset( ecGroup, 0, sizeof( EC_GROUP ) );
	}
#endif /* USE_ECDH || USE_ECDSA */

/* Duplicate, swap bignums */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
BIGNUM *BN_dup( const BIGNUM *bignum )
	{
	BIGNUM *newBignum;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	newBignum = BN_new();
	if( newBignum == NULL ) 
		return( NULL );
	if( BN_copy( newBignum, bignum ) == NULL )
		{
		BN_free( newBignum );

		return( NULL );
		}

	return( newBignum );
	}

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
BIGNUM *BN_copy( INOUT_PTR BIGNUM *destBignum, 
				 IN_PTR const BIGNUM *srcBignum )
	{
	assert( isWritePtr( destBignum, sizeof( BIGNUM ) ) );
	assert( isReadPtr( srcBignum, sizeof( BIGNUM ) ) );

	REQUIRES_N( destBignum != srcBignum );
	REQUIRES_N( sanityCheckBignum( destBignum ) );
	REQUIRES_N( sanityCheckBignum( srcBignum ) );
	REQUIRES_N( !( destBignum->flags & BN_FLG_STATIC_DATA ) );
	REQUIRES_N( getBNMaxSize( destBignum ) >= srcBignum->top );

	/* Clear out the destination bignum, a general sanitation measure in 
	   case there's un-cleared data left in it from previous operations */
	BN_clear( destBignum );

	/* Copy most of the bignum fields.  We don't copy the maximum-size field
	   or anything but a subset of the flags field since these may differ 
	   for the two bignums (the flags field will be things like 
	   BN_FLG_MALLOCED, BN_FLG_STATIC_DATA, and BN_FLG_ALLOC_EXT) */
	if( srcBignum->top == 0 )
		{
		/* The source bignum may be zero, in which case there's no data to
		   copy */
		REQUIRES_N( BN_is_zero( srcBignum ) );
		( void ) BN_zero( destBignum );
		}
	else
		{
		REQUIRES_N( isShortIntegerRangeNZ( bnWordsToBytes( srcBignum->top ) ) );
		memcpy( destBignum->d, srcBignum->d, bnWordsToBytes( srcBignum->top ) );
		}
	destBignum->flags |= srcBignum->flags & BN_FLG_COPY_MASK;
	destBignum->top = srcBignum->top;
	destBignum->neg = srcBignum->neg;

	return( destBignum );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void BN_swap( INOUT_PTR BIGNUM *bignum1, INOUT_PTR BIGNUM *bignum2 )
	{
	BIGNUM tmp;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( bignum1, sizeof( BIGNUM ) ) );
	assert( isWritePtr( bignum2, sizeof( BIGNUM ) ) );

	REQUIRES_V( bignum1 != bignum2 );
	REQUIRES_V( !( bignum1->flags & ( BN_FLG_STATIC_DATA | \
									  BN_FLG_ALLOC_EXT | \
									  BN_FLG_ALLOC_EXT2 ) ) );
	REQUIRES_V( !( bignum2->flags & ( BN_FLG_STATIC_DATA | \
									  BN_FLG_ALLOC_EXT | \
									  BN_FLG_ALLOC_EXT2 ) ) );

	BN_init( &tmp );
	CKPTR( BN_copy( &tmp, bignum1 ) );
	CKPTR( BN_copy( bignum1, bignum2 ) );
	CKPTR( BN_copy( bignum2, &tmp ) );
	BN_clear( &tmp );

	ENSURES_V( bnStatusOK( bnStatus ) );
	}

/* A constant-time version of the above.  We can either use an incredibly 
   complicated Rube-Goldberg kludge or perform a dummy set of operations 
   that take about the same time as the actual swap.  This isn't absolutely
   constant-time but the few extra cycles are buried in the noise of the
   other operations, and it's only called a single time from the even
   noisier EC multiply code bn/ec_mult.c:ec_mul_consttime().  Timing tests 
   indicate no measurable difference across the two, and indeed no
   measurable difference whether it's a constant-time swap or not */

#if defined( USE_ECDSA ) || defined( USE_ECDH )

STDC_NONNULL_ARG( ( 2, 3 ) ) \
void BN_consttime_swap( const BN_ULONG condition, 
						INOUT_PTR BIGNUM *bignum1, 
						INOUT_PTR BIGNUM *bignum2, 
						STDC_UNUSED const int nwords )
	{
	BIGNUM tmp;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( bignum1, sizeof( BIGNUM ) ) );
	assert( isWritePtr( bignum2, sizeof( BIGNUM ) ) );

	/* If we're doing the swap, pass the call on to the actual function */
	if( condition )
		{
		BN_swap( bignum1, bignum2 );
		return;
		}

	/* We're not doing the swap, perform the equivalent dummy operations:
	   bignum1 copied twice, bignum1 copied once, but in any case since 
	   they're always of the same size we're down to dealing with things 
	   like cache latency for the read */
	REQUIRES_V( bignum1 != bignum2 );
	REQUIRES_V( !( bignum1->flags & ( BN_FLG_STATIC_DATA | \
									  BN_FLG_ALLOC_EXT | \
									  BN_FLG_ALLOC_EXT2 ) ) );
	REQUIRES_V( !( bignum2->flags & ( BN_FLG_STATIC_DATA | \
									  BN_FLG_ALLOC_EXT | \
									  BN_FLG_ALLOC_EXT2 ) ) );

	BN_init( &tmp );
	CKPTR( BN_copy( &tmp, bignum1 ) );
	CKPTR( BN_copy( &tmp, bignum2 ) );
	CKPTR( BN_copy( &tmp, bignum1 ) );
	BN_clear( &tmp );

	ENSURES_V( bnStatusOK( bnStatus ) );
	}
#endif /* USE_ECDSA || USE_ECDH */

/* Get a copy of a bignum with different flags from the original, used for 
   constant-time ops in BN_mod_inverse_no_branch() to create a read-only 
   copy of a bignum that's processed using a constant-time algorithm.  This 
   really shouldn't be called BN_with_flags() but it's necessary for 
   compatibility with the OpenSSL original.
   
   This is only called from two locations in BN_mod_inverse_no_branch() with
   fixed parameters (destBignum = BN_clear()d, flags = BN_FLG_CONSTTIME) so 
   we can make certain assumptions about how it'll be used in the checks 
   below */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
BIGNUM *BN_with_flags( INOUT_PTR BIGNUM *destBignum, 
					   IN_PTR const BIGNUM *srcBignum,
					   const int flags )
	{
	assert( isWritePtr( destBignum, sizeof( BIGNUM ) ) );
	assert( isReadPtr( srcBignum, sizeof( BIGNUM ) ) );

	REQUIRES_N( destBignum != srcBignum );
	REQUIRES_N( sanityCheckBignum( destBignum ) );
	REQUIRES_N( sanityCheckBignum( srcBignum ) );
	REQUIRES_N( destBignum->flags == 0 );
	REQUIRES_N( getBNMaxSize( destBignum ) == getBNMaxSize( srcBignum ) );
	REQUIRES_N( flags == BN_FLG_CONSTTIME );
	
	if( !BN_copy( destBignum, srcBignum ) )
		return( NULL );
	destBignum->flags = flags;

	ENSURES_B( sanityCheckBignum( destBignum ) );

	return( destBignum );
	}

/* Get a bignum with the value 1 */

CHECK_RETVAL_PTR \
const BIGNUM *BN_value_one( void )
	{
	static const BIGNUM bignum = { 1, FALSE, BN_FLG_STATIC_DATA, 
								   { 1, 0, 0, 0 } };

	/* Catch problems arising from changes to bignum struct layout */
	assert( bignum.top == 1 );
	assert( bignum.neg == FALSE );
	assert( bignum.flags == BN_FLG_STATIC_DATA );
	assert( bignum.d[ 0 ] == 1 && bignum.d[ 1 ] == 0 && bignum.d[ 2 ] == 0 );

	return( &bignum );
	}

/****************************************************************************
*																			*
*						 Manipulate Bignum Values/Data						*
*																			*
****************************************************************************/

/* Get/set a bignum as a word value */

STDC_NONNULL_ARG( ( 1 ) ) \
BN_ULONG BN_get_word( const BIGNUM *bignum )
	{
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES_EXT( sanityCheckBignum( bignum ), BN_NAN );

	/* If the result won't fit in a word, return a NaN indicator */
	if( bignum->top > 1 )
		return( BN_NAN );

	/* Bignums with the value zero have a length of zero so we don't try and
	   read a data value from them */
	if( bignum->top < 1 )
		return( 0 );

	return( bignum->d[ 0 ] );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN BN_set_word( INOUT_PTR BIGNUM *bignum, const BN_ULONG word )
	{
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES_B( sanityCheckBignum( bignum ) );
	REQUIRES_B( !( bignum->flags & BN_FLG_STATIC_DATA ) );

	BN_clear( bignum );
	bignum->d[ 0 ] = word;
	bignum->top = word ? 1 : 0;

	return( TRUE );
	}

/* Count the number of bits used in a word and in a bignum.  The former is 
   the classic log2 problem for which there are about a million clever hacks 
   (including stuffing them into IEEE-754 64-bit floats and fiddling with 
   the bit-representation of those) but they're all endianness/word-size/
   whatever-dependent and since this is never called in time-critical code 
   we just use a straight loop, which works everywhere */

CHECK_RETVAL_LENGTH_SHORT \
int BN_num_bits_word( const BN_ULONG word )
	{
	BN_ULONG value = word;
	LOOP_INDEX i;

	LOOP_LARGE( i = 0, i < 128 && value > 0, i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 127 ) );

		value >>= 1;
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < 128 );

	return( i );
	}

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1 ) ) \
int BN_num_bits( const BIGNUM *bignum )
	{
	const int lastWordIndex = bignum->top - 1;
	int bits, status;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( bignum ) );

	/* Bignums with value zero are special-cased since they have a length of
	   zero */
	if( bignum->top <= 0 )
		return( 0 );

	status = bits = BN_num_bits_word( bignum->d[ lastWordIndex ] );
	if( cryptStatusError( status ) )
		return( status );
	return( ( lastWordIndex * BN_BITS2 ) + bits );
	}

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1 ) ) \
int BN_num_bytes( const BIGNUM *bignum )
	{
	int bits, status;
	
	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	/* Sanity-checked in BN_num_bits() */
	
	status = bits = BN_num_bits( bignum );
	if( cryptStatusError( status ) )
		return( status );
	return( ( bits + 7 ) / 8 );
	}

/* Bit-manipulation operations */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN BN_set_bit( INOUT_PTR BIGNUM *bignum, 
					IN_RANGE( 0, bytesToBits( CRYPT_MAX_PKCSIZE * 2 ) ) \
						int bitNo )
	{
	const int wordIndex = bitNo / BN_BITS2;
	const int bitIndex = bitNo % BN_BITS2;

	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES_B( sanityCheckBignum( bignum ) );
	REQUIRES_B( !( bignum->flags & BN_FLG_STATIC_DATA ) );
	REQUIRES_B( bitNo >= 0 && \
				bitNo < bnWordsToBits( getBNMaxSize( bignum ) ) );

	/* If we're extending the bignum, clear the words up to where we insert 
	   the bit.
	   
	   Note that the use of the unified BIGNUM type to also represent a 
	   BIGNUM_EXT/BIGNUM_EXT2 can result in false-positive warnings from 
	   bounds-checking applications that apply the d[] array size from a 
	   BIGNUM to the much larger array in a BIGNUM_EXT/BIGNUM_EXT2 */
	if( bignum->top < wordIndex + 1 )
		{
		const int iterationBound = getBNMaxSize( bignum );
		LOOP_INDEX index;

		REQUIRES_B( wordIndex < getBNMaxSize( bignum ) );
		LOOP_EXT( index = bignum->top, index < wordIndex + 1, index++, 
				  iterationBound )
			{
			ENSURES_B( LOOP_INVARIANT_EXT( index, bignum->top, wordIndex,
										   iterationBound ) );

			bignum->d[ index ] = 0;
			}
		ENSURES_B( LOOP_BOUND_OK );
		bignum->top = wordIndex + 1;
		}

	/* Set the appropriate bit location.  Since we're dealing with a 
	   BN_ULONG here checkOverflowShift() isn't useful */
	bignum->d[ wordIndex ] |= ( BN_ULONG ) 1 << bitIndex;

	ENSURES_B( sanityCheckBignum( bignum ) );

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN BN_is_bit_set( const BIGNUM *bignum, /* See comment */ int bitNo )
	{
	const int wordIndex = bitNo / BN_BITS2;
	const int bitIndex = bitNo % BN_BITS2;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES_B( sanityCheckBignum( bignum ) );
	REQUIRES_B( bitNo < bnWordsToBits( getBNMaxSize( bignum ) ) );
				/* See comment below */

	/* The OpenSSL bignum code occasionally calls this with negative values 
	   for the bit to check (e.g. the Montgomery modexp code, which contains 
	   a comment that explicitly says it'll be calling this function with 
	   negative bit values) so we have to special-case this condition */
	if( bitNo < 0 )
		return( 0 );

	/* Bits off the end of the bignum are always zero */
	if( wordIndex >= bignum->top )
		return( 0 );

	/* Since we're dealing with a BN_ULONG here checkOverflowShift() isn't 
	   useful */
	return( ( bignum->d[ wordIndex ] & ( ( BN_ULONG ) 1 << bitIndex ) ) ? \
			TRUE : FALSE );
	}

CHECK_RETVAL_RANGE( 0, 1 ) STDC_NONNULL_ARG( ( 1 ) ) \
int BN_high_bit( const BIGNUM *bignum )
	{
	BN_ULONG highWord;
	int noBytes, highByte, shiftAmount, status;

	assert( isReadPtr( bignum, sizeof( BIGNUM ) ) );

	/* Sanity-checked in BN_num_bytes() */

	status = noBytes = BN_num_bytes( bignum );
	if( cryptStatusError( status ) )
		return( status );
	noBytes--;	/* Convert length to index of the high word */

	/* Bignums with value zero are special-cased since they have a length of
	   zero */
	if( noBytes < 0 )
		return( 0 );

	/* Extract the topmost nonzero byte in the bignum.  The masking before 
	   the cast to int may be required for 64-bit BN_ULONGs, which could 
	   result in a value larger than INT_MAX */
	shiftAmount = ( noBytes % BN_BYTES ) * 8;
	highWord = bignum->d[ noBytes / BN_BYTES ];
	highByte = ( int ) ( ( highWord >> shiftAmount ) & 0xFF );

	return( ( highByte & 0x80 ) ? 1 : 0 );
	}

/* Set the sign flag on a bignum.  This is almost universally ignored by the
   OpenSSL code, which manipulates the sign value directly */

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_set_negative( INOUT_PTR BIGNUM *bignum, const int isNegative )
	{
	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	REQUIRES_V( sanityCheckBignum( bignum ) );
	REQUIRES_V( !( bignum->flags & BN_FLG_STATIC_DATA ) );
	REQUIRES_V( !( BN_is_zero( bignum ) && isNegative ) );

	bignum->neg = isNegative ? TRUE : FALSE;
	}

/* A bignum operation may have reduced the magnitude of the bignum value,
   in which case bignum->top will be left pointing to the head of a long
   string of zeroes.  The following function normalises the representation,
   leaving bignum->top pointing to the first nonzero entry */

RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN BN_normalise( INOUT_PTR BIGNUM *bignum )
	{
	const int iterationBound = getBNMaxSize( bignum );
	const int oldTop = bignum->top;
	int LOOP_ITERATOR;

	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );

	/* We can't call the full sanityCheckBignum() at this point because by
	   definition it won't be normalised and so will fail the check */
	REQUIRES_B( bignum->top >= 0 && bignum->top <= getBNMaxSize( bignum ) );
	REQUIRES_B( !( bignum->flags & BN_FLG_STATIC_DATA ) );

	/* If it's a zero-magnitude bignum then there's nothing to do.  Note 
	   that we can't use BN_is_zero() here because the bignum is 
	   denormalised, so bignum->top >= 1 with bignum->d all zero would be
	   reported as a zero bignum */
	if( bignum->top <= 0 )
		{
		ENSURES_B( sanityCheckBignum( bignum ) );

		return( TRUE );
		}

	/* Note that the use of the unified BIGNUM type to also represent a 
	   BIGNUM_EXT/BIGNUM_EXT2 can result in false-positive warnings from 
	   bounds-checking applications that apply the d[] array size from a 
	   BIGNUM to the much larger array in a BIGNUM_EXT/BIGNUM_EXT2 */
	LOOP_EXT_REV_CHECKINC( bignum->top > 0, bignum->top--, \
						   iterationBound )
		{
		ENSURES_B( LOOP_INVARIANT_REV( bignum->top, 1, oldTop ) );

		if( bignum->d[ bignum->top - 1 ] != 0 )
			break;
		}
	ENSURES_B( LOOP_BOUND_EXT_REV_OK( iterationBound ) );

	ENSURES_B( sanityCheckBignum( bignum ) );

	return( TRUE );
	}

/* When we're working with a bignum's internal data, we may end up reducing 
   its magnitude, typically via an operation like BN_op( out, in1, in2 ) 
   where 'out' contained a previous value larger than 'in1 op in2'.  In
   order to deal with this we need to clear any leftover data that wasn't
   replaced by the operation being performed */

RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN clear_top( INOUT_PTR BIGNUM *bignum, 
						  IN_RANGE( 0, BIGNUM_ALLOC_WORDS_EXT2 ) \
								const int oldTop,
						  IN_BOOL const BOOLEAN normalise )
	{
	const int iterationBound = getBNMaxSize( bignum );
	LOOP_INDEX i;

	assert( isWritePtr( bignum, sizeof( BIGNUM ) ) );
	
	/* We can't call the full sanityCheckBignum() at this point because 
	   there's potentially leftover data beyond bignum->top, which is the 
	   whole reason why this function is being called in the first place */
	REQUIRES_B( bignum->top >= 0 && bignum->top <= getBNMaxSize( bignum ) );
	REQUIRES_B( oldTop >= 0 && oldTop <= getBNMaxSize( bignum ) );
	REQUIRES_B( !( bignum->flags & BN_FLG_STATIC_DATA ) );
	REQUIRES_B( isBooleanValue( normalise ) );

	/* If we've overwritten any previous contents, we're done */
	if( oldTop <= bignum->top )
		{
		if( normalise )
			return( BN_normalise( bignum ) );
		return( TRUE );
		}

	/* Clear any previous bignum data content */
	LOOP_EXT( i = bignum->top, i < oldTop, i++, iterationBound )
		{
		ENSURES_B( LOOP_INVARIANT_EXT( i, bignum->top, oldTop - 1,
									   iterationBound ) );

		bignum->d[ i ] = 0;
		}
	ENSURES_B( LOOP_BOUND_OK );

	/* If we're also normalising the value, do so now */
	if( normalise )
		return( BN_normalise( bignum ) );

	ENSURES_B( sanityCheckBignum( bignum ) );

	return( TRUE );
	}

RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN BN_clear_top( INOUT_PTR BIGNUM *bignum, 
					  IN_RANGE( 0, BIGNUM_ALLOC_WORDS_EXT2 ) \
							const int oldTop )
	{
	return( clear_top( bignum, oldTop, FALSE ) );
	}

RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN BN_clear_top_normalise( INOUT_PTR BIGNUM *bignum, 
								IN_RANGE( 0, BIGNUM_ALLOC_WORDS_EXT2 ) \
									const int oldTop )
	{
	return( clear_top( bignum, oldTop, TRUE ) );
	}

/****************************************************************************
*																			*
*							BN_CTX Support Routines 						*
*																			*
****************************************************************************/

/* The BN_CTX code up until about 2000 (or cryptlib 3.21) used to be just an 
   array of BN_CTX_NUM = 32 BIGNUMs.  After that it was replaced by an 
   awkward pool/stack combination that makes something relatively 
   straightforward quite complex.  What's needed is a way of stacking and
   unstacking blocks of BN_CTX_get()s in nested functions:

	BN_foo()
		BN_CTX_start();
		foo_a = BN_CTX_get();
		foo_b = BN_CTX_get();
		foo_c = BN_CTX_get();
		BN_bar()
			BN_CTX_start();
			bar_a = BN_CTX_get();
			bar_b = BN_CTX_get();
			BN_CTX_end();
		BN_CTX_end();

   where the first BN_CTX_end() frees up the BNs grabbed in BN_bar() and the
   second frees up the ones grabbed in BN_foo().  This is why we have the
   stack alongside the bignum array, every time we increase the nesting depth
   by calling BN_CTX_start() we remember the stack position that we need to 
   unwind to when BN_CTX_end() is called.

   All of the complex stack/pool manipulations in the original code, 
   possibly meant to "optimise" the strategy of allocating a single fixed-
   size block of values, actually have a negative effect on memory use 
   because the bookkeeping overhead of dozens of tiny little allocations is 
   more than just allocating the fixed-size block.  Since we can measure the 
   deepest that the allocation ever goes we just use a fixed-size array of 
   bignums set to BN_CTX_ARRAY_SIZE.
   
   The init and end functions just set up and clear a BN_CTX */

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_CTX_init( OUT_PTR BN_CTX *bnCTX )
	{
	LOOP_INDEX i;

	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	memset( bnCTX, 0, sizeof( BN_CTX ) );
	LOOP_MED( i = 0, i < BN_CTX_ARRAY_SIZE, i++ )
		{
		ENSURES_V( LOOP_INVARIANT_MED( i, 0, BN_CTX_ARRAY_SIZE - 1 ) );

		BN_init( &bnCTX->bnArray[ i ] );
		}
	ENSURES_V( LOOP_BOUND_OK );
	ENSURES_V( i == BN_CTX_ARRAY_SIZE );
	LOOP_MED( i = 0, i < BN_CTX_EXTARRAY_SIZE, i++ )
		{
		ENSURES_V( LOOP_INVARIANT_MED( i, 0, BN_CTX_EXTARRAY_SIZE - 1 ) );

		BN_init_ext( &bnCTX->bnExtArray[ i ], FALSE );
		}
	ENSURES_V( LOOP_BOUND_OK );
	ENSURES_V( i == BN_CTX_EXTARRAY_SIZE );
	LOOP_MED( i = 0, i < BN_CTX_EXT2ARRAY_SIZE, i++ )
		{
		ENSURES_V( LOOP_INVARIANT_MED( i, 0, BN_CTX_EXT2ARRAY_SIZE - 1 ) );

		BN_init_ext( &bnCTX->bnExt2Array[ i ], TRUE );
		}
	ENSURES_V( LOOP_BOUND_OK );
	ENSURES_V( i == BN_CTX_EXT2ARRAY_SIZE );
	ENSURES_V( sanityCheckBNCTX( bnCTX ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_CTX_final( INOUT_PTR BN_CTX *bnCTX )
	{
	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	/* We perform the sanity check as an assert() rather than an ENSURES_V() 
	   because we want to catch programming errors resulting in random 
	   garbage being left in bignums but don't want to abort the BN_CTX 
	   cleanup in release code due to a random bit flip */
	assert( sanityCheckBNCTX( bnCTX ) );

	/* Clear the overall BN_CTX */
	zeroise( bnCTX, sizeof( BN_CTX ) );

	/* The various bignums were cleared when the BN_CTX was zeroised, we now 
	   have to reset them to their initial state so that they can be 
	   reused */
	BN_CTX_init( bnCTX );
	DEBUG_PRINT_COND( diagOutput, ( "EXT_MUL1 freed.\nEXT_MUL2 freed.\n" ));
	DEBUG_PRINT_COND( diagOutput, ( "EXT_MONT freed.\n" ));
	}

/* The start and badly-named end functions (it should be finish()) remember 
   the current stack position and unwind to the last stack position */

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_CTX_start( INOUT_PTR BN_CTX *bnCTX )
	{
	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	REQUIRES_V( sanityCheckBNCTX( bnCTX ) );

	/* Advance one stack frame */
	REQUIRES_V( bnCTX->stackPos < BN_CTX_ARRAY_SIZE - 1 );
	REQUIRES_V( !checkOverflowInc( bnCTX->stackPos ) );
	bnCTX->stackPos++;
	ENSURES_V( bnCTX->stackPos < BN_CTX_ARRAY_SIZE );
	bnCTX->stack[ bnCTX->stackPos ] = bnCTX->stack[ bnCTX->stackPos - 1 ];

	ENSURES_V( sanityCheckBNCTX( bnCTX ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_CTX_end( INOUT_PTR BN_CTX *bnCTX )
	{
	int stackPosStart, stackPosEnd; 
	LOOP_INDEX i;

	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	REQUIRES_V( sanityCheckBNCTX( bnCTX ) );
	REQUIRES_V( bnCTX->stackPos >= 1 );
				/* Ensure BN_CTX_start() has been called, sanityCheckBNCTX()
				   checks for a general >= 0 but we need >= 1 to unstack */
	REQUIRES_V( bnCTX->stack[ bnCTX->stackPos - 1 ] <= \
						bnCTX->stack[ bnCTX->stackPos ] );

	/* Get the range of bignums that need to be unstacked */
	stackPosStart = bnCTX->stack[ bnCTX->stackPos - 1 ];
	ENSURES_V( stackPosStart >= 0 && stackPosStart < BN_CTX_ARRAY_SIZE );
	stackPosEnd = bnCTX->stack[ bnCTX->stackPos ];
	ENSURES_V( stackPosEnd >= 0 && stackPosEnd < BN_CTX_ARRAY_SIZE );

	/* Only enable the following when required, the bignum code performs
	   a huge number of stackings and un-stackings for which the following
	   produces an enormous increase in runtime */
#if 0	
	DEBUG_PRINT(( "bnCTX unstacking from %d to %d.\n", stackPosStart, 
				  stackPosEnd ));
#endif /* 0 */

	/* Clear each bignum in the current stack frame.  We perform the sanity 
	   check as an assert() rather than an ENSURES_V() because we want to 
	   catch programming errors resulting in random garbage being left in
	   bignums but don't want to abort the BN_CTX cleanup in release code 
	   due to a random bit flip */
	LOOP_EXT( i = stackPosStart, i < stackPosEnd, i++, BN_CTX_ARRAY_SIZE )
		{
		ENSURES_V( LOOP_INVARIANT_EXT( i, stackPosStart, stackPosEnd - 1,
									   BN_CTX_ARRAY_SIZE ) );
		assert( sanityCheckBignum( &bnCTX->bnArray[ i ] ) );
		BN_clear( &bnCTX->bnArray[ i ] );
		}
	ENSURES_V( LOOP_BOUND_OK );

	/* Unwind the stack by one frame */
	bnCTX->stack[ bnCTX->stackPos ] = 0;
	REQUIRES_V( !checkOverflowDec( bnCTX->stackPos ) );
	bnCTX->stackPos--;

	ENSURES_V( sanityCheckBNCTX( bnCTX ) );
	}

/* Peel another bignum off the BN_CTX array */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
BIGNUM *BN_CTX_get( INOUT_PTR BN_CTX *bnCTX )
	{
	BIGNUM *bignum;
	int arrayIndex;

	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	if( bnCTX->bnArrayMax >= BN_CTX_ARRAY_SIZE )
		{
		assert( DEBUG_WARN );
		DEBUG_PRINT(( "bnCTX array size overflow.\n" ));

		return( NULL );
		}

	REQUIRES_N( sanityCheckBNCTX( bnCTX ) );

	/* Get the element at the previous top-of-stack */
	arrayIndex = bnCTX->stack[ bnCTX->stackPos ];
	REQUIRES_N( rangeCheck( arrayIndex, 0, BN_CTX_ARRAY_SIZE - 2 ) );
	bignum = &bnCTX->bnArray[ arrayIndex ];
	ENSURES_N( sanityCheckBignum( bignum ) && BN_is_zero( bignum ) );

	/* Advance the top-of-stack element by one, and increase the last-used 
	   position if it exceeds the existing one */
	arrayIndex++;
	bnCTX->stack[ bnCTX->stackPos ] = arrayIndex;
	if( arrayIndex > bnCTX->bnArrayMax )
		{
		/* Note that the following prints the count of entries used 
		   (1-based), not the position of the last entry (0-based) */
		DEBUG_PRINT_COND( arrayIndex > bnCtxMaxIndex, \
						  ( "BN_CTX highest-used now %d of %d.\n", 
							arrayIndex, BN_CTX_ARRAY_SIZE ) );
		DEBUG_OP( bnCtxMaxIndex = max( arrayIndex, bnCtxMaxIndex ) );
		bnCTX->bnArrayMax = arrayIndex;
		}

	ENSURES_N( sanityCheckBNCTX( bnCTX ) );

	/* Return the new element at the top of the stack */
	return( bignum );
	}

/* The bignum multiplication code requires a few temporary values that grow 
   to an enormous size, rather than resizing every bignum that we use to 
   deal with this we return fixed extra-size bignums when this is explicitly 
   required */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
BIGNUM *BN_CTX_get_ext( INOUT_PTR BN_CTX *bnCTX, 
						IN_ENUM( BIGNUM_EXT ) const BIGNUM_EXT_TYPE bnExtType )
	{
	BIGNUM *bignum = NULL;

	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	REQUIRES_N( isEnumRange( bnExtType, BIGNUM_EXT ) );

	switch( bnExtType )
		{
		case BIGNUM_EXT_MONT:
			DEBUG_PRINT_COND( diagOutput, ( "EXT_MONT acquired.\n" ));
			bignum = ( BIGNUM * ) &bnCTX->bnExtArray[ 0 ];
			break;

		case BIGNUM_EXT_MUL1:
			DEBUG_PRINT_COND( diagOutput, ( "EXT_MUL1 acquired.\n" ));
			bignum = ( BIGNUM * ) &bnCTX->bnExt2Array[ 0 ];
			break;

		case BIGNUM_EXT_MUL2:
			DEBUG_PRINT_COND( diagOutput, ( "EXT_MUL2 acquired.\n" ));
			bignum = ( BIGNUM * ) &bnCTX->bnExt2Array[ 1 ];
			break;
		}
	ENSURES_N( bignum != NULL );
	ENSURES_N( sanityCheckBignum( bignum ) );
			   /* We can't also check that BN_is_zero( bignum ) because we 
			      may be getting it for the purpose of clearing it, from 
				  BN_CTX_end_ext() */
	ENSURES_N( !( BN_get_flags( bignum, BN_FLG_INUSE ) == BN_FLG_INUSE ) );

	/* Mark the bignum as in-use to catch double-allocs */
	BN_set_flags( bignum, BN_FLG_INUSE );

	return( bignum );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_CTX_end_ext( INOUT_PTR BN_CTX *bnCTX, 
					 IN_ENUM( BIGNUM_EXT ) const BIGNUM_EXT_TYPE bnExtType )
	{
	BIGNUM *bignum;

	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	/* Perform the standard context cleanup */
	BN_CTX_end( bnCTX );

	ENSURES_V( bnExtType == BIGNUM_EXT_MUL1 || \
			   bnExtType == BIGNUM_EXT_MONT );
			   /* BIGNUM_EXT_MUL1 releases both MUL1 and also MUL2 as 
			      required - it's only used in one location in BN_mul(),
			      and is never explicitly released by passing in
			      BIGNUM_EXT_MUL2 since MUL1 covers both values */

	/* Clear the extended-size bignums, with a check for double-frees.  In 
	   the case of BIGNUM_EXT_MUL1 we're releasing both _MUL1 and _MUL2, but
	   only _MUL1 may have been used, so we don't check for _MUL2 being in 
	   use */
	if( bnExtType == BIGNUM_EXT_MUL1 )
		{
		bignum = ( BIGNUM * ) &bnCTX->bnExt2Array[ 0 ];
		ENSURES_V( BN_get_flags( bignum, BN_FLG_INUSE ) == BN_FLG_INUSE );
		bignum->flags &= ~BN_FLG_INUSE;
		BN_clear( bignum );
		DEBUG_PRINT_COND( diagOutput, ( "EXT_MUL1 cleared.\n" ));
		bignum = ( BIGNUM * ) &bnCTX->bnExt2Array[ 1 ];
		bignum->flags &= ~BN_FLG_INUSE;
		BN_clear( bignum );
		DEBUG_PRINT_COND( diagOutput, ( "EXT_MUL2 cleared.\n" ));
		}
	else
		{
		bignum = ( BIGNUM * ) &bnCTX->bnExtArray[ 0 ];
		ENSURES_V( BN_get_flags( bignum, BN_FLG_INUSE ) == BN_FLG_INUSE );
		bignum->flags &= ~BN_FLG_INUSE;
		BN_clear( bignum );
		DEBUG_PRINT_COND( diagOutput, ( "EXT_MONT cleared.\n" ));
		}
	}

/* Dynamically allocate a BN_CTX, only needed by the ECC code */

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL_PTR \
BN_CTX *BN_CTX_new( void )
	{
	BN_CTX *bnCTX;

	REQUIRES_N( isIntegerRangeNZ( sizeof( BN_CTX ) ) );
	bnCTX = clAlloc( "BN_CTX_new", sizeof( BN_CTX ) );
	if( bnCTX == NULL )
		return( NULL );
	BN_CTX_init( bnCTX );
	ENSURES_N_PTR( sanityCheckBNCTX( bnCTX ), bnCTX );

	return( bnCTX );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_CTX_free( INOUT_PTR BN_CTX *bnCTX )
	{
	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	REQUIRES_V_PTR( sanityCheckBNCTX( bnCTX ), bnCTX );

	BN_CTX_final( bnCTX );
	clFree( "BN_CTX_free", bnCTX );
	}
#endif /* ECDH || ECDSA */

/****************************************************************************
*																			*
*							BN_MONT_CTX Support Routines 					*
*																			*
****************************************************************************/

/* Initialise/clear a BN_MONT_CTX */

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_MONT_CTX_init( OUT_PTR BN_MONT_CTX *bnMontCTX )
	{
	assert( isWritePtr( bnMontCTX, sizeof( BN_MONT_CTX ) ) );

	memset( bnMontCTX, 0, sizeof( BN_MONT_CTX ) );
	BN_init( &bnMontCTX->R );
	BN_init( &bnMontCTX->N );

	ENSURES_V( sanityCheckBNMontCTX( bnMontCTX ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_MONT_CTX_free( INOUT_PTR BN_MONT_CTX *bnMontCTX )
	{
	assert( isWritePtr( bnMontCTX, sizeof( BN_MONT_CTX ) ) );

	/* We perform the sanity check as an assert() rather than an ENSURES_V() 
	   because we want to catch programming errors resulting in random 
	   garbage being left in bignums but don't want to abort the BN_MONT_CTX 
	   cleanup in release code due to a random bit flip */
	assert( sanityCheckBNMontCTX( bnMontCTX ) );

	BN_clear( &bnMontCTX->R );
	BN_clear( &bnMontCTX->N );
#if defined( USE_ECDH ) || defined( USE_ECDSA )
	if( bnMontCTX->flags & BN_FLG_MALLOCED )
		clFree( "BN_MONT_CTX_free", bnMontCTX );
#endif /* ECDH || ECDSA */
	}

/* Set parameters for a Montgomery context.  This computes the constant R 
   used to convert a bignum into the Montgomery form aR mod N and records
   R and N */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
BOOLEAN BN_MONT_CTX_set( INOUT_PTR BN_MONT_CTX *bnMontCTX, 
						 IN_PTR const BIGNUM *mod, 
						 INOUT_PTR BN_CTX *bnCTX )
	{
	BIGNUM *R, *modWord;
	const int modBits = BN_num_bits( mod );
	const int Nbits = roundUp( modBits, BN_BITS2 );
	const int flags = bnMontCTX->flags;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( bnMontCTX, sizeof( BN_MONT_CTX ) ) );
	assert( isReadPtr( mod, sizeof( BIGNUM ) ) );
	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	REQUIRES_B( sanityCheckBignum( mod ) && !BN_is_zero( mod ) && \
				!BN_is_negative( mod ) && BN_is_odd( mod ) );
	REQUIRES_B( sanityCheckBNCTX( bnCTX ) );
	REQUIRES_B( BN_cmp( &bnMontCTX->N, mod ) );	/* Ensure not already set */
	REQUIRES_B( !cryptStatusError( modBits ) );

	/* Clear the Montgomery context entries and record the modulus.  We need
	   to preserve the flags around the init since this records details such
	   as whether the context is dynamically allocated */
	BN_MONT_CTX_init( bnMontCTX );
	bnMontCTX->flags = flags;
	CKPTR( BN_copy( &bnMontCTX->N, mod ) );
	if( bnStatusError( bnStatus ) )
		return( FALSE );

	BN_CTX_start( bnCTX );

	/* Get the temporaries that we'll be working with.  We borrow the 
	   modWord bignum from the bnMontCTX since we won't be setting it until 
	   right at the end */
	R = BN_CTX_get_ext( bnCTX, BIGNUM_EXT_MONT );
	if( R == NULL )
		{
		/* The BN_CTX_get_ext() failed, use a standard BN_CTX_end() to clean 
		   up */
		BN_CTX_end( bnCTX );
		return( FALSE );
		}
	modWord = &bnMontCTX->R;

	/* Set up the auxiliary modulus R as a value one larger than a bignum 
	   word and modWord as a bignum containing the low word of the modulus 
	   (this fulfils the requirement that R > N, or in this case 
	   R > modWord).  
	   
	   modWord can't be zero, or more generally even otherwise the modulus 
	   would be composite, we make the check explicit otherwise the 
	   following modular inverse operation won't work */
	CK( BN_zero( R ) );
	CK( BN_set_bit( R, BN_BITS2 ) );
	CK( BN_set_word( modWord, mod->d[ 0 ] ) );
	if( bnStatusError( bnStatus ) )
		{
		BN_CTX_end_ext( bnCTX, BIGNUM_EXT_MONT );
		return( FALSE );
		}
	ENSURES_B( BN_is_odd( modWord ) );
	if( BN_is_one( modWord ) )
		{
		/* When modWord is 1, the modular inverse is zero, so instead we 
		   have to explicitly set R to all one bits */
		CK( BN_set_word( R, BN_MASK2 ) );
		}
	else
		{
		/* R = R^-1 mod modWord, shifted left one word (i.e. multiplied by 
		   the initial R value) to make word-based divides easier */
		CKPTR( BN_mod_inverse( R, R, modWord, bnCTX ) );
		ENSURES_B( !BN_is_zero( R ) );
		CK( BN_lshift( R, R, BN_BITS2 ) );
		CK( BN_sub_word( R, 1 ) );
		CK( BN_div( R, NULL, R, modWord, bnCTX ) );
		}
	if( bnStatusError( bnStatus ) )
		{
		BN_CTX_end_ext( bnCTX, BIGNUM_EXT_MONT );
		return( FALSE );
		}

	/* Record the least significant word of R */
	bnMontCTX->n0 = R->d[ 0 ];

	/* Set up the value R used for conversion to aR mod N form.  This 
	   temporarily expands the value to an extremely large size so it's done 
	   via an extended bignum */
	CK( BN_zero( R ) );
	CK( BN_set_bit( R, Nbits * 2 ) );
	CK( BN_mod( &bnMontCTX->R, R, &bnMontCTX->N, bnCTX ) );

	BN_CTX_end_ext( bnCTX, BIGNUM_EXT_MONT );
	if( bnStatusError( bnStatus ) )
		return( FALSE );

	ENSURES_B( sanityCheckBNMontCTX( bnMontCTX ) );

	return( TRUE );
	}

/* Convert values to/from Montgomery form.  Note that BN_from_montgomery()
   modifies its input value as part of the conversion process, this is done
   because it saves allocating a temporary bignum only to throw it away 
   again as soon as the conversion is complete, and is safe because the only
   values passed to it are themselves temporaries output from other
   calculations */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
BOOLEAN BN_to_montgomery( INOUT_PTR BIGNUM *ret, 
						  IN_PTR const BIGNUM *a,
						  IN_PTR const BN_MONT_CTX *bnMontCTX,
						  INOUT_PTR BN_CTX *bnCTX )
	{
	assert( isWritePtr( ret, sizeof( BIGNUM ) ) );
	assert( isReadPtr( a, sizeof( BIGNUM ) ) );
	assert( isReadPtr( bnMontCTX, sizeof( BN_MONT_CTX ) ) );
	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	/* This is just a wrapper for BN_mod_mul_montgomery() */
	return( BN_mod_mul_montgomery( ret, a, &bnMontCTX->R, bnMontCTX, 
								   bnCTX ) );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
BOOLEAN BN_from_montgomery( INOUT_PTR BIGNUM *ret, 
							INOUT_PTR BIGNUM *aTmp,
							IN_PTR const BN_MONT_CTX *bnMontCTX,
							INOUT_PTR BN_CTX *bnCTX )
	{
	const BIGNUM *N = &bnMontCTX->N;
	BIGNUM *aTmpExt = NULL;
	BN_ULONG *aData, carry = 0;
	const int nLen = N->top, iterationBound = getBNMaxSize( N );
	LOOP_INDEX i;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( ret, sizeof( BIGNUM ) ) );
	assert( isWritePtr( aTmp, sizeof( BIGNUM ) ) );
	assert( isReadPtr( bnMontCTX, sizeof( BN_MONT_CTX ) ) );
	assert( isWritePtr( bnCTX, sizeof( BN_CTX ) ) );

	REQUIRES_B( sanityCheckBignum( ret ) );
	REQUIRES_B( sanityCheckBignum( aTmp ) && !BN_is_zero( aTmp ) && \
				!BN_is_negative( aTmp ) );
	REQUIRES_B( ret != aTmp );
	REQUIRES_B( !( ret->flags & BN_FLG_STATIC_DATA ) );
	REQUIRES_B( sanityCheckBNMontCTX( bnMontCTX ) );
	REQUIRES_B( sanityCheckBNCTX( bnCTX ) );

	/* If the values get very large then we need to use an extended bignum 
	   as a temporary */
	if( nLen * 2 > getBNMaxSize( aTmp ) )
		{
		BN_CTX_start( bnCTX );
		aTmpExt = BN_CTX_get_ext( bnCTX, BIGNUM_EXT_MONT );
		if( aTmpExt == NULL )
			{
			/* The BN_CTX_get_ext() failed, use a standard BN_CTX_end() to 
			   clean up */
			BN_CTX_end( bnCTX );
			return( FALSE );
			}
		if( BN_copy( aTmpExt, aTmp ) == NULL )
			{
			BN_CTX_end_ext( bnCTX, BIGNUM_EXT_MONT );
			return( FALSE );
			}
		aTmp = aTmpExt;
		}
	BN_set_flags( aTmp, BN_FLG_SCRATCH );
	aData = aTmp->d;

	/* Perform the same operation that's used in BN_sqr() (see the long 
	   comment there for an explanation of what's going on), but in modified 
	   form to make it constant-time */
	LOOP_EXT( i = 0, i < nLen, i++, iterationBound )
		{
		const BN_ULONG aDataVal = aData[ nLen + i ];
		BN_ULONG tmp;

		ENSURES_B( LOOP_INVARIANT_EXT( i, 0, nLen - 1,
									   iterationBound ) );

		tmp = bn_mul_add_words( aData + i, N->d, nLen, 
								aData[ i ] * bnMontCTX->n0 ) + carry + aDataVal;
		aData[ nLen + i ] = tmp;

		/* Compute the carry for the next round.  The convoluted logic 
		   expression is required in order to perform the operation in a
		   branch-free manner if possible (depending on what the compiler 
		   does for code generation */
		carry = ( carry | ( tmp != aDataVal ) ) & ( tmp <= aDataVal );
		}
	ENSURES_B( LOOP_BOUND_OK );

	/* Perform the final transformation using a constant-time operation in 
	   which, if there's a borrow due to the subtraction, we copy out the 
	   computed result, otherwise we perform a dummy copy of the same data 
	   into an unused memory location.  In theory there's a one or two-cycle
	   difference due to the branch but this shouldn't be measurable among
	   all the other noise */
	BN_clear( ret );
	REQUIRES_B( nLen <= getBNMaxSize( ret ) );
	ret->top = nLen;
	if( bn_sub_words( ret->d, aData + nLen, N->d, nLen ) - carry != 0 )
		{
		/* There was a borrow, perform the actual copy */
		REQUIRES_B( isShortIntegerRangeNZ( bnWordsToBytes( nLen ) ) );
		memcpy( ret->d, aData + nLen, bnWordsToBytes( nLen ) );
		}
	else
		{
		/* Perform a dummy copy that takes the same time as the real one */
		REQUIRES_B( isShortIntegerRangeNZ( bnWordsToBytes( nLen ) ) );
		memcpy( aData, aData + nLen, bnWordsToBytes( nLen ) );
		}
	CK( BN_normalise( ret ) );
		/* Error exit after cleanup below */

	BN_clear( aTmp );
	if( aTmpExt != NULL )
		BN_CTX_end_ext( bnCTX, BIGNUM_EXT_MONT );

	if( bnStatusError( bnStatus ) )
		return( FALSE );

	ENSURES_B( sanityCheckBignum( ret ) );

	return( TRUE );
	}

/* Dynamically allocate a BN_MONT_CTX, only needed by the ECC code */

#if defined( USE_ECDH ) || defined( USE_ECDSA )

CHECK_RETVAL_PTR \
BN_MONT_CTX *BN_MONT_CTX_new( void )
	{
	BN_MONT_CTX *bnMontCTX;

	REQUIRES_N( isShortIntegerRangeNZ( sizeof( BN_MONT_CTX ) ) );
	bnMontCTX = clAlloc( "BN_MONT_CTX_new", sizeof( BN_MONT_CTX ) );
	if( bnMontCTX == NULL )
		return( NULL );
	BN_MONT_CTX_init( bnMontCTX );
	bnMontCTX->flags = BN_FLG_MALLOCED;
	ENSURES_N_PTR( sanityCheckBNMontCTX( bnMontCTX ), bnMontCTX );

	return( bnMontCTX );
	}
#else

CHECK_RETVAL_PTR \
BN_MONT_CTX *BN_MONT_CTX_new( void )
	{
	assert( DEBUG_WARN );
	return( NULL );
	}
#endif /* ECDH || ECDSA */

/****************************************************************************
*																			*
*							BN_RECP_CTX Support Routines 					*
*																			*
****************************************************************************/

/* Initialise/clear a BN_RECP_CTX */

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_RECP_CTX_init( OUT_PTR BN_RECP_CTX *bnRecpCTX )
	{
	assert( isWritePtr( bnRecpCTX, sizeof( BN_RECP_CTX ) ) );

	memset( bnRecpCTX, 0, sizeof( BN_RECP_CTX ) );

	BN_init( &bnRecpCTX->N );
	BN_init( &bnRecpCTX->Nr );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void BN_RECP_CTX_free( INOUT_PTR BN_RECP_CTX *bnRecpCTX )
	{
	assert( isWritePtr( bnRecpCTX, sizeof( BN_RECP_CTX ) ) );

	/* We perform the sanity check as an assert() rather than an ENSURES_V() 
	   because we want to catch programming errors resulting in random 
	   garbage being left in bignums but don't want to abort the BN_CTX 
	   cleanup in release code  due to a random bit flip */
	assert( sanityCheckBignum( &bnRecpCTX->N ) );
	assert( sanityCheckBignum( &bnRecpCTX->Nr ) );

	BN_clear( &bnRecpCTX->N );
	BN_clear( &bnRecpCTX->Nr );
	}

/* Initialise a BN_RECP_CTX.  The BN_CTX isn't used for anything, we keep it
   just to preserve the original function signature */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
BOOLEAN BN_RECP_CTX_set( INOUT_PTR BN_RECP_CTX *bnRecpCTX, 
						 IN_PTR const BIGNUM *d, 
						 STDC_UNUSED const BN_CTX *bnCTX )
	{
	int bnStatus = BN_STATUS;

	assert( isWritePtr( bnRecpCTX, sizeof( BN_RECP_CTX ) ) );
	assert( isReadPtr( d, sizeof( BIGNUM ) ) );

	UNUSED_ARG_OPT( bnCTX );

	/* Clear context fields.  This should already have been done through an 
	   earlier call to BN_RECP_CTX_init(), but given that this is OpenSSL, 
	   we're extra conservative */
	BN_RECP_CTX_init( bnRecpCTX );

	/* N = bignum, Nr = 0 */
	CKPTR( BN_copy( &bnRecpCTX->N, d ) );
	CK( BN_zero( &bnRecpCTX->Nr ) );
	if( bnStatusError( bnStatus ) )
		return( FALSE );

	/* Initialise metadata fields */
	bnRecpCTX->num_bits = BN_num_bits( d );
	ENSURES_B( !cryptStatusError( bnRecpCTX->num_bits ) );

	return( TRUE );
	}

/****************************************************************************
*																			*
*								Self-test Routines							*
*																			*
****************************************************************************/

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL \
BOOLEAN testIntBN( void )
	{
	if( !bnmathSelfTest() )
		return( FALSE );

	return( TRUE );
	}
#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#endif /* USE_PKC */
