/****************************************************************************
*																			*
*			cryptlib Curve25519 Key Generation/Checking Routines			*
*					Copyright Peter Gutmann 2023-2025						*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "keygen.h"
  #include "ecx.h"
#else
  #include "context/context.h"
  #include "context/keygen.h"
  #include "crypt/ecx.h"
#endif /* Compiler-specific includes */

/* The size of the Curve25519 components */

#define CURVE25519_SIZE		32

#if defined( USE_X25519 ) || defined( USE_ED25519 )

/****************************************************************************
*																			*
*							Utility Functions								*
*																			*
****************************************************************************/

/* Clamp a Curve25519 private value.  Clearing the three low bits means that
   the scalar is a multiple of the cofactor, so that applying the scalar to
   any group element produces an element in the prime order subgroup.  The
   LSBs are cleared to ensure that the number is a multiple of 8, the MSB is
   cleared to make sure it wasn't wrapped around the modulus, and setting the 
   second-MSB was apparently done to hijack implementations that looked for 
   the first 1-bit and were therefore variable-time.  
   
   This means that the clamped key actually only has 251 random bits and 
   isn't uniformly random mod the 253-bit prime L, but this shouldn't make 
   any difference to security */

STDC_NONNULL_ARG( ( 1 ) ) \
static void clampCurve25519( INOUT_BUFFER_FIXED( CURVE25519_SIZE ) \
								BYTE buffer[ CURVE25519_SIZE ] )
	{
	assert( isWritePtr( buffer, CURVE25519_SIZE ) );

	/* Clamp the value */
	buffer[ 0 ] &= 0xF8;					/* 3 LSBs = 0 */
	buffer[ CURVE25519_SIZE - 1 ] &= 0x7F;	/* MSB = 0 */
	buffer[ CURVE25519_SIZE - 1 ] |= 0x40;	/* 2nd-MSB = 1 */
	}

/* Check the magnitude of a Curve25519 value.  The value is in little-endian 
   form so we can't process it with standard bignum routines but have to 
   perform an explicit check on the bytes.  We do this by counting the number 
   of zero bytes at the (little-endian) top of the value and rejecting it if 
   there's more than 80 bits worth */

#define NO_CHECK_BYTES		bitsToBytes( 80 )

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkMagnitude25519( IN_BUFFER( CURVE25519_SIZE ) \
										const BYTE *value,
									IN_BOOL const BOOLEAN isPublicValue )
	{
	LOOP_INDEX i;

	assert( isReadPtr( value, CURVE25519_SIZE ) );
	
	REQUIRES_B( isBooleanValue( isPublicValue ) );
	
	/* Walk down the value checking for a non-zero byte.  For a private 
	   value this is just a straight check of a scalar */
	if( !isPublicValue )
		{
		LOOP_MED_REV( i = CURVE25519_SIZE - 1, \
					  i >= CURVE25519_SIZE - NO_CHECK_BYTES, i-- )
			{
			ENSURES_B( \
				LOOP_INVARIANT_REV( i, CURVE25519_SIZE - NO_CHECK_BYTES, 
									CURVE25519_SIZE - 1 ) );

			if( value[ i ] != 0 )
				return( TRUE );
			}
		ENSURES_B( LOOP_BOUND_MED_REV_OK );
	
		return( FALSE );
		}

	/* For a public value it's more complicated because we're dealing with a
	   point, which is encoded into 256 bits as 255 bits of y in little-
	   endian form followed by 1 bit of the x sign bit.  The spec says (RFC 
	   8032 section 3.1) that this is an "encoding of y concatenated with 
	   one bit that is 1 if x is negative and 0 if x is not negative" which 
	   would imply that it's the last bit in the bit string, however 
	   implementations actually use the MSB of the last byte which is what 
	   we mask off here.  This is confirmed by RFC 7748 which says (section 
	   5) "implementations of X25519 MUST mask the most significant bit in 
	   the final byte" */
	if( ( value[ CURVE25519_SIZE - 1 ] & 0x7F ) != 0 )
		return( TRUE );
	LOOP_MED_REV( i = CURVE25519_SIZE - 2, \
				  i >= CURVE25519_SIZE - NO_CHECK_BYTES, i-- )
		{
		ENSURES_B( \
			LOOP_INVARIANT_REV( i, CURVE25519_SIZE - NO_CHECK_BYTES, 
								CURVE25519_SIZE - 2 ) );

		if( value[ i ] != 0 )
			return( TRUE );
		}
	ENSURES_B( LOOP_BOUND_MED_REV_OK );
	
	return( FALSE );
	}

/****************************************************************************
*																			*
*							Generate an X25519 Key							*
*																			*
****************************************************************************/

/* Generate the X25519 private and public values */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateX25519PrivateValue( INOUT_PTR PKC_INFO *pkcInfo )
	{
	BERNSTEIN_KEY_INFO *bernsteinKey;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Generate the X25519 private value and clamp it.  Because of the use 
	   of the Bernstein special-snowflake encoding we can't use 
	   generateBignum() to do this for us but have to hand-assemble 
	   everything ourselves */
	setMessageData( &msgData, bernsteinKey->privKey, CURVE25519_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	clampCurve25519( bernsteinKey->privKey );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateX25519PublicValue( INOUT_PTR PKC_INFO *pkcInfo )
	{
	BERNSTEIN_KEY_INFO *bernsteinKey;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Calculate the public value from the private value.  This function 
	   doesn't have a return value so there's not much that we can do in
	   terms of checking its status, but we can pass the public value to 
	   checkMagnitude25519() to check that no failure-mode behaviour 
	   (typically it would produce an all-zero result) was triggered */
	( void ) ossl_x25519_public_from_private( bernsteinKey->pubKey, 
											  bernsteinKey->privKey );
	if( !checkMagnitude25519( bernsteinKey->pubKey, TRUE ) )
		{
		zeroise( bernsteinKey->pubKey, CURVE25519_SIZE );
		return( CRYPT_ERROR_FAILED );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Generate an Ed25519 Key							*
*																			*
****************************************************************************/

/* Create the Ed25519 s value, the intermediate step used to both create the 
   public key and when generating a signature, and convert it to the public 
   key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int ed25519PrivateToS( INOUT_PTR PKC_INFO *pkcInfo,
							  OUT_BUFFER_OPT_FIXED( CURVE25519_SIZE ) \
								BYTE *returnedSValue )	
	{
	BERNSTEIN_KEY_INFO *bernsteinKey;
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	BYTE s[ CRYPT_MAX_HASHSIZE + 8 ];

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );
	assert( returnedSValue == NULL || \
			isWritePtr( returnedSValue, CURVE25519_SIZE ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Hash the private key with SHA-512 and discard half of it, then clamp 
	   the rest to create the scalar s.  The spec says to use "the lower 32 
	   bytes" but never explains which end of the value is the lower one but 
	   all the Bernstein stuff is little-endian so it must be the first 32 
	   bytes:
	   
		h = SHA512( privKey )[ 0...31 ];
		s = clamp( h );
	   
	   This is used both to derive the public key and during the signing 
	   process, so we keep a copy */
	getHashAtomicParameters( CRYPT_ALGO_SHA2, 64, &hashFunctionAtomic, NULL );
	hashFunctionAtomic( s, CRYPT_MAX_HASHSIZE, bernsteinKey->privKey, 
						CURVE25519_SIZE );
	clampCurve25519( s );

	/* If we're doing a consistency check that the s value can be derived 
	   from the private key, return the value to the caller */
	if( returnedSValue != NULL )
		memcpy( returnedSValue, s, CURVE25519_SIZE );
	else
		memcpy( bernsteinKey->s, s, CURVE25519_SIZE );
	zeroise( s, CRYPT_MAX_HASHSIZE );
	
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int ed25519SToPublic( INOUT_PTR PKC_INFO *pkcInfo,
							 OUT_BUFFER_OPT_FIXED( CURVE25519_SIZE ) \
								BYTE *returnedPubKey )
	{
	BERNSTEIN_KEY_INFO *bernsteinKey;
	BYTE pubKey[ CURVE25519_SIZE + 8 ];

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );
	assert( returnedPubKey == NULL || \
			isWritePtr( returnedPubKey, CURVE25519_SIZE ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Calculate the Ed25519 public value from the private value, with the 
	   first two steps already done in ed25519PrivateToS():
	
		h = SHA512( privKey )[ 0...31 ];
		s = clamp( h );
		A = [s]B */
	if( clib_ed25519_public_from_private( pubKey, bernsteinKey->s ) != TRUE )
		return( CRYPT_ERROR_FAILED );

	/* If we're doing a consistency check that the public key can be derived
	   from the private key, return the value to the caller */
	if( returnedPubKey != NULL )
		memcpy( returnedPubKey, pubKey, CURVE25519_SIZE );
	else
		{
		/* We're setting up the public key, store the value in context 
		   storage */
		memcpy( bernsteinKey->pubKey, pubKey, CURVE25519_SIZE );
		}
	zeroise( pubKey, CURVE25519_SIZE );

	return( CRYPT_OK );
	}

/* Generate the Ed25519 private and public values */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateEd25519PrivateValue( INOUT_PTR PKC_INFO *pkcInfo )
	{
	BERNSTEIN_KEY_INFO *bernsteinKey;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Generate the Ed25519 private value.  The spec (RFC 8032 section 
	   5.1.5) just sets the key to 32 random bytes with no clamping as for 
	   Curve25519.  Because of the use of the Bernstein special-snowflake 
	   encoding we can't use generateBignum() to do this for us but have to 
	   hand-assemble everything ourselves */
	setMessageData( &msgData, bernsteinKey->privKey, CURVE25519_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the Ed25519 s value which used both to derive the public key 
	   and during the signing process */
	status = ed25519PrivateToS( pkcInfo, NULL );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateEd25519PublicValue( INOUT_PTR PKC_INFO *pkcInfo )
	{
	int status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* This is just a straight conversion of the intermediate s value to 
	   public-key form */
	status = ed25519SToPublic( pkcInfo, NULL );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Check a Curve25519 Key							*
*																			*
****************************************************************************/

/* Check a Curve25519 public value.  This is a bit of a tricky one because 
   djb says for 25519 values there's nothing to check 
   (see https://cr.yp.to/ecdh.html), however we check that the overall 
   magnitude isn't too small and perform other worthwhile checks */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkCurve25519PublicValue( INOUT_PTR PKC_INFO *pkcInfo,
									   IN_ALGO \
										const CRYPT_ALGO_TYPE cryptAlgo )
	{
	BERNSTEIN_KEY_INFO *bernsteinKey;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_25519 || \
			  cryptAlgo == CRYPT_ALGO_ED25519 );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Check that the magnitude of the 25519 public value seems OK */
	if( !checkMagnitude25519( bernsteinKey->pubKey, TRUE ) )
		return( CRYPT_ARGERROR_STR1 );

	/* In theory Ed25519 public keys have an additional checking step while 
	   Curve25519 ones don't and in fact are required to accept all manner of
	   garbage, e.g. (RFC 7748 section 5) "Implementations MUST accept non-
	   canonical values", however we apply the same checks to both since 
	   there's no reason we should be accepting questionable stuff like non-
	   canonical encodings, values of small order, and so on */
	if( ( cryptAlgo == CRYPT_ALGO_25519 && \
		  clib_x25519_pubkey_verify( bernsteinKey->pubKey ) != TRUE ) || \
		( cryptAlgo == CRYPT_ALGO_ED25519 && \
		  clib_ed25519_pubkey_verify( bernsteinKey->pubKey ) != TRUE ) )
		{
		DEBUG_DIAG(( "25519 public key is invalid/has small order" ));
		return( CRYPT_ARGERROR_STR1 );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* An externally-callable helper function used by context/ctx_x25519.c that 
   checks the X25519 public value using the same checks as 
   checkCurve25519PublicValue() */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkX25519PublicValue( IN_BUFFER( CURVE25519_SIZE ) \
									const void *pubValue,
								IN_LENGTH_FIXED( CURVE25519_SIZE )
									const int pubValueLength )
	{
	assert( isReadPtr( pubValue, pubValueLength ) );

	REQUIRES_B( pubValueLength == CURVE25519_SIZE );

	if( !checkMagnitude25519( pubValue, TRUE ) )
		return( FALSE );
	if( clib_x25519_pubkey_verify( pubValue ) != TRUE ) 
		return( FALSE );

	return( TRUE );
	}

/* Perform validity checks on the private key.  This is the same magnitude 
   check as the public value check, but also checks that it has the correct
   shape as per generateCurve25519PrivateValue() */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkCurve25519PrivateKey( INOUT_PTR PKC_INFO *pkcInfo,
									  IN_ALGO \
										const CRYPT_ALGO_TYPE cryptAlgo )
	{
	BERNSTEIN_KEY_INFO *bernsteinKey;
	BYTE buffer[ CURVE25519_SIZE + 8 ];
	int status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_25519 || \
			  cryptAlgo == CRYPT_ALGO_ED25519 );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Check that the magnitude of the value seems OK */
	if( !checkMagnitude25519( bernsteinKey->privKey, FALSE ) )
		return( CRYPT_ARGERROR_STR1 );

	/* If it's a Curve25519 key, make sure that it's appropriate clamped */
	if( cryptAlgo == CRYPT_ALGO_25519 && \
		( ( bernsteinKey->privKey[ 0 ] & ~0xF8 ) || \
		  ( bernsteinKey->privKey[ CURVE25519_SIZE - 1 ] & ~0x7F ) || \
		  !( bernsteinKey->privKey[ CURVE25519_SIZE - 1 ] & 0x40 ) ) )
		{
		return( CRYPT_ARGERROR_STR1 );
		}

	/* Finally, make sure that the public-key value corresponds to the 
	   private key, or in the case of Ed25519 the intermediate s value
	   that's derived from the private key */
	if( cryptAlgo == CRYPT_ALGO_25519 )
		{
		/* This function has a void return so there's nothing to check */
		( void ) ossl_x25519_public_from_private( buffer, 
												  bernsteinKey->privKey );
		status = CRYPT_OK;
		}
	else
		{
		/* For the Ed25519 derivation we have to go through the whole chain
		   from private key to s to public key */
		status = ed25519PrivateToS( pkcInfo, buffer );
		if( cryptStatusOK( status ) && \
			compareDataConstTime( buffer, bernsteinKey->s, \
								  CURVE25519_SIZE ) != TRUE )
			status = CRYPT_ERROR_FAILED;
		if( cryptStatusOK( status ) )
			status = ed25519SToPublic( pkcInfo, buffer );
		}
	if( cryptStatusOK( status ) )
		{
		/* Make sure that the public key matches the value recreated from 
		   the private key.  Although this is a public value it could be a
		   faulted public value so we use the sensitive-data constant-time
		   compare for it */
		if( compareDataConstTime( buffer, bernsteinKey->pubKey, 
								  CURVE25519_SIZE ) != TRUE )
			status = CRYPT_ERROR_FAILED;
		}

	/* Clean up */
	zeroise( buffer, CURVE25519_SIZE );

	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "25519 private key is invalid" ));
		return( CRYPT_ARGERROR_STR1 );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Generate/Initialise a Curve25519 Key				*
*																			*
****************************************************************************/

/* Generate and check a Curve25519/Ed25519 key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int generate25519Key( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 || \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ED25519 );

	/* Generate the private value */
	if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 )
		status = generateX25519PrivateValue( pkcInfo );
	else
		status = generateEd25519PrivateValue( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );
	pkcInfo->keySizeBits = bytesToBits( CURVE25519_SIZE );

	/* Calculate the public value */
	if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 )
		status = generateX25519PublicValue( pkcInfo );
	else
		status = generateEd25519PublicValue( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Checksum the context storage to try and detect faults.  Since we're
	   setting the checksum at this point there's no need to check the 
	   return value */
	( void ) checksumContextData( pkcInfo, TRUE );

	/* Make sure that the generated values are valid */
	status = checkCurve25519PublicValue( pkcInfo,
										 capabilityInfoPtr->cryptAlgo );
	if( cryptStatusOK( status ) )
		{
		status = checkCurve25519PrivateKey( pkcInfo, \
											capabilityInfoPtr->cryptAlgo );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that what we generated is still valid */
	if( cryptStatusError( \
			checksumContextData( pkcInfo, TRUE ) ) )
		{
		DEBUG_DIAG(( "Generated 25519 key memory corruption detected" ));
		return( CRYPT_ERROR_FAILED );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Initialise and check a Curve25519/Ed25519 key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initCheck25519Key( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	BERNSTEIN_KEY_INFO *bernsteinKey;
	static const BYTE zeroValue[ CURVE25519_SIZE + 8 ] = { 0 };
	const BOOLEAN isPrivateKey = TEST_FLAG( contextInfoPtr->flags,
											CONTEXT_FLAG_ISPUBLICKEY ) ? \
								 FALSE : TRUE;
	BOOLEAN generatedPrivateValue = FALSE;
	int	status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 || \
			  capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ED25519 );
	REQUIRES( pkcInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	bernsteinKey = pkcInfo->bernsteinKey;

	/* Make sure that the necessary key parameters have been initialised.  
	   In theory we need a pubic key present but Ed25519 generates the 
	   public key on the fly from the private key so it's not really a
	   problem if it's missing, and X25519 keys function as both public and 
	   private keys so we don't require a privKey parameter */
	if( isPrivateKey && capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ED25519 )
		{
		if( !memcmp( bernsteinKey->privKey, zeroValue, CURVE25519_SIZE ) )
			return( CRYPT_ARGERROR_STR1 );
		if( !memcmp( bernsteinKey->s, zeroValue, CURVE25519_SIZE ) )
			{
			status = ed25519PrivateToS( pkcInfo, NULL );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* If it's an X25519 key and there's no private value present, generate 
	   one now.  This is needed because all X25519 keys are effectively 
	   private keys.  We also update the context flags to reflect this 
	   change in status */
	if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 && \
		!memcmp( bernsteinKey->privKey, zeroValue, CURVE25519_SIZE ) )
		{
		status = generateX25519PrivateValue( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		CLEAR_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY );
		generatedPrivateValue = TRUE;
		}

	/* Calculate the public value if required */
	if( !memcmp( bernsteinKey->pubKey, zeroValue, CURVE25519_SIZE ) || \
		generatedPrivateValue )
		{
		if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 )
			status = generateX25519PublicValue( pkcInfo );
		else
			status = generateEd25519PublicValue( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	pkcInfo->keySizeBits = bytesToBits( CURVE25519_SIZE );

	/* Make sure that the public value is valid */
	status = checkCurve25519PublicValue( pkcInfo,
										 capabilityInfoPtr->cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the private value is valid if required */
	if( isPrivateKey || generatedPrivateValue )
		{
		status = checkCurve25519PrivateKey( pkcInfo, 
											capabilityInfoPtr->cryptAlgo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Checksum the context storage to try and detect faults.  Since we're 
	   setting the checksum at this point there's no need to check the 
	   return value.  Note that this isn't the TOCTOU issue that it appears 
	   to be because the bignum values are read by the calling code from 
	   their stored form a second time and compared to the values that we're 
	   checksumming here */
	( void ) checksumContextData( pkcInfo, 
								  ( isPrivateKey || generatedPrivateValue ) ? \
								    TRUE : FALSE );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}
#endif /* USE_X25519 || USE_ED25519 */
