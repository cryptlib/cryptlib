<<<<<<< HEAD
/****************************************************************************
*																			*
*					cryptlib Internal Mechanism Routines					*
*					  Copyright Peter Gutmann 1992-2019						*
*																			*
****************************************************************************/

#ifdef INC_ALL
  #include "crypt.h"
  #include "mech_int.h"
#else
  #include "crypt.h"
  #include "mechs/mech_int.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*									PKC Routines							*
*																			*
****************************************************************************/

/* The length of the input data for PKCS #1 transformations is usually
   determined by the key size but sometimes we can be passed data that has 
   been zero-padded (for example data coming from an ASN.1 INTEGER in which 
   the high bit is a sign bit) making it longer than the key size, or that 
   has leading zero byte(s) making it shorter than the key size.  The best 
   place to handle this is somewhat uncertain, it's an encoding issue so it 
   probably shouldn't be visible to the raw crypto routines but putting it 
   at the mechanism layer removes the algorithm-independence of that layer 
   and putting it at the mid-level sign/key-exchange routine layer both 
   removes the algorithm-independence and requires duplication of the code 
   for signatures and encryption.  The best place to put it seems to be at 
   the mechanism layer since an encoding issue really shouldn't be visible 
   at the crypto layer and because it would require duplicating the handling 
   every time a new PKC implementation is plugged in.

   The intent of the size adjustment is to make the data size match the key
   length.  If it's longer we try to strip leading zero bytes.  If it's 
   shorter we pad it with zero bytes to match the key size.  The result is
   either the data adjusted to match the key size or CRYPT_ERROR_BADDATA if
   this isn't possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int adjustPKCS1Data( OUT_BUFFER_FIXED( outDataMaxLen ) BYTE *outData, 
					 IN_LENGTH_SHORT_MIN( CRYPT_MAX_PKCSIZE ) \
						const int outDataMaxLen, 
					 IN_BUFFER( inLen ) const BYTE *inData, 
					 IN_LENGTH_SHORT const int inLen, 
					 IN_LENGTH_SHORT const int keySize )
	{
	int length, LOOP_ITERATOR;

	assert( isWritePtrDynamic( outData, outDataMaxLen ) );
	assert( isReadPtrDynamic( inData, inLen ) );

	REQUIRES( isShortIntegerRangeMin( outDataMaxLen, CRYPT_MAX_PKCSIZE ) );
	REQUIRES( isShortIntegerRangeNZ( inLen ) && inLen <= outDataMaxLen && \
			  inLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( keySize >= MIN_PKCSIZE && keySize <= CRYPT_MAX_PKCSIZE );
	REQUIRES( outData != inData );

	/* Make sure that the result will fit in the output buffer.  This has 
	   already been checked by the kernel mechanism ACL and by the 
	   REQUIRES() predicate above but we make the check explicit here */
	if( keySize > outDataMaxLen )
		return( CRYPT_ERROR_OVERFLOW );

	/* Find the start of the data payload.  If it's suspiciously short, 
	   don't try and process it */
	LOOP_EXT_REV( length = inLen, length >= MIN_PKCSIZE - 8 && *inData == 0,
				  ( length--, inData++ ), CRYPT_MAX_PKCSIZE )
		{
		ENSURES( LOOP_INVARIANT_REV( length, MIN_PKCSIZE - 8, inLen ) );
		}
	ENSURES( LOOP_BOUND_EXT_REV_OK( CRYPT_MAX_PKCSIZE ) );
	if( length < MIN_PKCSIZE - 8 || length > keySize )
		return( CRYPT_ERROR_BADDATA );

	/* If it's of the correct size, exit */
	if( length == keySize )
		{
		REQUIRES( rangeCheck( keySize, 1, outDataMaxLen ) );
		memcpy( outData, inData, keySize );
		return( CRYPT_OK );
		}
	ENSURES( length < keySize );

	/* We've adjusted the size to account for zero-padding during encoding,
	   now we have to move the data into a fixed-length format to match the
	   key size.  To do this we copy the payload into the output buffer with
	   enough leading-zero bytes to bring the total size up to the key size */
	REQUIRES( boundsCheck( keySize - length, length, outDataMaxLen ) );
	memset( outData, 0, keySize );
	memcpy( outData + ( keySize - length ), inData, length );

	return( CRYPT_OK );
	}

/* Get PKC algorithm parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int getPkcAlgoParams( IN_HANDLE const CRYPT_CONTEXT pkcContext,
					  OUT_OPT_ALGO_Z CRYPT_ALGO_TYPE *pkcAlgo, 
					  OUT_LENGTH_PKC_Z int *pkcKeySize )
	{
	assert( ( pkcAlgo == NULL ) || \
			isWritePtr( pkcAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( pkcKeySize, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( pkcContext ) );

	/* Clear return values */
	if( pkcAlgo != NULL )
		*pkcAlgo = CRYPT_ALGO_NONE;
	*pkcKeySize = 0;

	/* Get various PKC algorithm parameters */
	if( pkcAlgo != NULL )
		{
		int algorithm, status;

		status = krnlSendMessage( pkcContext, IMESSAGE_GETATTRIBUTE, 
								  &algorithm, CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		*pkcAlgo = algorithm;	/* int vs.enum */
		}
	return( krnlSendMessage( pkcContext, IMESSAGE_GETATTRIBUTE, 
							 pkcKeySize, CRYPT_CTXINFO_KEYSIZE ) );
	}

/****************************************************************************
*																			*
*									Hash Routines							*
*																			*
****************************************************************************/

/* OAEP/PSS mask generation function MGF1 */

#if defined( USE_OAEP ) || defined( USE_PSS )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int mgf1( OUT_BUFFER_FIXED( maskLen ) void *mask, 
		  IN_LENGTH_PKC const int maskLen, 
		  IN_BUFFER( seedLen ) const void *seed, 
		  IN_LENGTH_PKC const int seedLen,
		  IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
		  IN_LENGTH_HASH_Z const int hashParam )
	{
	HASH_FUNCTION hashFunction;
	HASHINFO hashInfo;
	BYTE countBuffer[ 4 + 8 ], maskBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE *maskOutPtr = mask;
	LOOP_INDEX maskIndex;
	int hashSize, blockCount = 0;

	assert( isWritePtrDynamic( mask, maskLen ) );
	assert( isReadPtrDynamic( seed, seedLen ) );

	REQUIRES( maskLen >= 20 && maskLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( seedLen >= 20 && seedLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( ( hashParam == 0 ) || \
			  ( hashParam >= MIN_HASHSIZE && \
				hashParam <= CRYPT_MAX_HASHSIZE ) );

	getHashParameters( hashAlgo, hashParam, &hashFunction, &hashSize );

	/* Set up the block counter buffer.  This will never have more than the
	   last few bits set (8 bits = 5120 bytes of mask for the smallest hash,
	   SHA-1) so we only change the last byte */
	memset( countBuffer, 0, 4 );

	/* Produce enough blocks of output to fill the mask */
	LOOP_MED( maskIndex = 0, maskIndex < maskLen, 
			  ( maskIndex += hashSize, maskOutPtr += hashSize ) )
		{
		const int noMaskBytes = min( hashSize, maskLen - maskIndex );

		ENSURES( LOOP_INVARIANT_MED_XXX( maskIndex, 0, maskLen - 1 ) );
				 /* maskIndex is incremented by the number of output bytes */

		/* Calculate hash( seed || counter ) */
		countBuffer[ 3 ] = ( BYTE ) blockCount++;
		hashFunction( hashInfo, NULL, 0, seed, seedLen, HASH_STATE_START );
		hashFunction( hashInfo, maskBuffer, hashSize, countBuffer, 4, 
					  HASH_STATE_END );
		REQUIRES( boundsCheckZ( maskIndex, noMaskBytes, maskLen ) );
		memcpy( maskOutPtr, maskBuffer, noMaskBytes );
		}
	ENSURES( LOOP_BOUND_OK );
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( maskBuffer, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_OAEP || USE_PSS */

/* Get hash algorithm parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int getHashAlgoParams( IN_HANDLE const CRYPT_CONTEXT hashContext,
					   OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo, 
					   OUT_OPT_LENGTH_HASH_Z int *hashParam )
	{
	int value, status;

	assert( isWritePtr( hashAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( ( hashParam == NULL ) || \
			isWritePtr( hashParam, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( hashContext ) );

	/* Clear return values */
	*hashAlgo = CRYPT_ALGO_NONE;
	if( hashParam != NULL )
		*hashParam = 0;

	/* Get various PKC algorithm parameters */
	status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE, 
							  &value, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	*hashAlgo = value;	/* int vs.enum */
	if( hashParam != NULL )
		{
		status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE, 
								  hashParam, CRYPT_CTXINFO_BLOCKSIZE );
		}
	return( status );
	}
=======
/****************************************************************************
*																			*
*					cryptlib Internal Mechanism Routines					*
*					  Copyright Peter Gutmann 1992-2019						*
*																			*
****************************************************************************/

#ifdef INC_ALL
  #include "crypt.h"
  #include "mech_int.h"
#else
  #include "crypt.h"
  #include "mechs/mech_int.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*									PKC Routines							*
*																			*
****************************************************************************/

/* The length of the input data for PKCS #1 transformations is usually
   determined by the key size but sometimes we can be passed data that has 
   been zero-padded (for example data coming from an ASN.1 INTEGER in which 
   the high bit is a sign bit) making it longer than the key size, or that 
   has leading zero byte(s) making it shorter than the key size.  The best 
   place to handle this is somewhat uncertain, it's an encoding issue so it 
   probably shouldn't be visible to the raw crypto routines but putting it 
   at the mechanism layer removes the algorithm-independence of that layer 
   and putting it at the mid-level sign/key-exchange routine layer both 
   removes the algorithm-independence and requires duplication of the code 
   for signatures and encryption.  The best place to put it seems to be at 
   the mechanism layer since an encoding issue really shouldn't be visible 
   at the crypto layer and because it would require duplicating the handling 
   every time a new PKC implementation is plugged in.

   The intent of the size adjustment is to make the data size match the key
   length.  If it's longer we try to strip leading zero bytes.  If it's 
   shorter we pad it with zero bytes to match the key size.  The result is
   either the data adjusted to match the key size or CRYPT_ERROR_BADDATA if
   this isn't possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int adjustPKCS1Data( OUT_BUFFER_FIXED( outDataMaxLen ) BYTE *outData, 
					 IN_LENGTH_SHORT_MIN( CRYPT_MAX_PKCSIZE ) \
						const int outDataMaxLen, 
					 IN_BUFFER( inLen ) const BYTE *inData, 
					 IN_LENGTH_SHORT const int inLen, 
					 IN_LENGTH_SHORT const int keySize )
	{
	int length, LOOP_ITERATOR;

	assert( isWritePtrDynamic( outData, outDataMaxLen ) );
	assert( isReadPtrDynamic( inData, inLen ) );

	REQUIRES( isShortIntegerRangeMin( outDataMaxLen, CRYPT_MAX_PKCSIZE ) );
	REQUIRES( isShortIntegerRangeNZ( inLen ) && inLen <= outDataMaxLen && \
			  inLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( keySize >= MIN_PKCSIZE && keySize <= CRYPT_MAX_PKCSIZE );
	REQUIRES( outData != inData );

	/* Make sure that the result will fit in the output buffer.  This has 
	   already been checked by the kernel mechanism ACL and by the 
	   REQUIRES() predicate above but we make the check explicit here */
	if( keySize > outDataMaxLen )
		return( CRYPT_ERROR_OVERFLOW );

	/* Find the start of the data payload.  If it's suspiciously short, 
	   don't try and process it */
	LOOP_EXT_REV( length = inLen, length >= MIN_PKCSIZE - 8 && *inData == 0,
				  ( length--, inData++ ), CRYPT_MAX_PKCSIZE )
		{
		ENSURES( LOOP_INVARIANT_REV( length, MIN_PKCSIZE - 8, inLen ) );
		}
	ENSURES( LOOP_BOUND_EXT_REV_OK( CRYPT_MAX_PKCSIZE ) );
	if( length < MIN_PKCSIZE - 8 || length > keySize )
		return( CRYPT_ERROR_BADDATA );

	/* If it's of the correct size, exit */
	if( length == keySize )
		{
		REQUIRES( rangeCheck( keySize, 1, outDataMaxLen ) );
		memcpy( outData, inData, keySize );
		return( CRYPT_OK );
		}
	ENSURES( length < keySize );

	/* We've adjusted the size to account for zero-padding during encoding,
	   now we have to move the data into a fixed-length format to match the
	   key size.  To do this we copy the payload into the output buffer with
	   enough leading-zero bytes to bring the total size up to the key size */
	REQUIRES( boundsCheck( keySize - length, length, outDataMaxLen ) );
	memset( outData, 0, keySize );
	memcpy( outData + ( keySize - length ), inData, length );

	return( CRYPT_OK );
	}

/* Get PKC algorithm parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int getPkcAlgoParams( IN_HANDLE const CRYPT_CONTEXT pkcContext,
					  OUT_OPT_ALGO_Z CRYPT_ALGO_TYPE *pkcAlgo, 
					  OUT_LENGTH_PKC_Z int *pkcKeySize )
	{
	assert( ( pkcAlgo == NULL ) || \
			isWritePtr( pkcAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( pkcKeySize, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( pkcContext ) );

	/* Clear return values */
	if( pkcAlgo != NULL )
		*pkcAlgo = CRYPT_ALGO_NONE;
	*pkcKeySize = 0;

	/* Get various PKC algorithm parameters */
	if( pkcAlgo != NULL )
		{
		int algorithm, status;

		status = krnlSendMessage( pkcContext, IMESSAGE_GETATTRIBUTE, 
								  &algorithm, CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		*pkcAlgo = algorithm;	/* int vs.enum */
		}
	return( krnlSendMessage( pkcContext, IMESSAGE_GETATTRIBUTE, 
							 pkcKeySize, CRYPT_CTXINFO_KEYSIZE ) );
	}

/****************************************************************************
*																			*
*									Hash Routines							*
*																			*
****************************************************************************/

/* OAEP/PSS mask generation function MGF1 */

#if defined( USE_OAEP ) || defined( USE_PSS )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int mgf1( OUT_BUFFER_FIXED( maskLen ) void *mask, 
		  IN_LENGTH_PKC const int maskLen, 
		  IN_BUFFER( seedLen ) const void *seed, 
		  IN_LENGTH_PKC const int seedLen,
		  IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
		  IN_LENGTH_HASH_Z const int hashParam )
	{
	HASH_FUNCTION hashFunction;
	HASHINFO hashInfo;
	BYTE countBuffer[ 4 + 8 ], maskBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE *maskOutPtr = mask;
	LOOP_INDEX maskIndex;
	int hashSize, blockCount = 0;

	assert( isWritePtrDynamic( mask, maskLen ) );
	assert( isReadPtrDynamic( seed, seedLen ) );

	REQUIRES( maskLen >= 20 && maskLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( seedLen >= 20 && seedLen <= CRYPT_MAX_PKCSIZE );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( ( hashParam == 0 ) || \
			  ( hashParam >= MIN_HASHSIZE && \
				hashParam <= CRYPT_MAX_HASHSIZE ) );

	getHashParameters( hashAlgo, hashParam, &hashFunction, &hashSize );

	/* Set up the block counter buffer.  This will never have more than the
	   last few bits set (8 bits = 5120 bytes of mask for the smallest hash,
	   SHA-1) so we only change the last byte */
	memset( countBuffer, 0, 4 );

	/* Produce enough blocks of output to fill the mask */
	LOOP_MED( maskIndex = 0, maskIndex < maskLen, 
			  ( maskIndex += hashSize, maskOutPtr += hashSize ) )
		{
		const int noMaskBytes = min( hashSize, maskLen - maskIndex );

		ENSURES( LOOP_INVARIANT_MED_XXX( maskIndex, 0, maskLen - 1 ) );
				 /* maskIndex is incremented by the number of output bytes */

		/* Calculate hash( seed || counter ) */
		countBuffer[ 3 ] = ( BYTE ) blockCount++;
		hashFunction( hashInfo, NULL, 0, seed, seedLen, HASH_STATE_START );
		hashFunction( hashInfo, maskBuffer, hashSize, countBuffer, 4, 
					  HASH_STATE_END );
		REQUIRES( boundsCheckZ( maskIndex, noMaskBytes, maskLen ) );
		memcpy( maskOutPtr, maskBuffer, noMaskBytes );
		}
	ENSURES( LOOP_BOUND_OK );
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( maskBuffer, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}
#endif /* USE_OAEP || USE_PSS */

/* Get hash algorithm parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int getHashAlgoParams( IN_HANDLE const CRYPT_CONTEXT hashContext,
					   OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo, 
					   OUT_OPT_LENGTH_HASH_Z int *hashParam )
	{
	int value, status;

	assert( isWritePtr( hashAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( ( hashParam == NULL ) || \
			isWritePtr( hashParam, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( hashContext ) );

	/* Clear return values */
	*hashAlgo = CRYPT_ALGO_NONE;
	if( hashParam != NULL )
		*hashParam = 0;

	/* Get various PKC algorithm parameters */
	status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE, 
							  &value, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	*hashAlgo = value;	/* int vs.enum */
	if( hashParam != NULL )
		{
		status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE, 
								  hashParam, CRYPT_CTXINFO_BLOCKSIZE );
		}
	return( status );
	}
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
