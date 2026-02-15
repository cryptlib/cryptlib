/****************************************************************************
*																			*
*			cryptlib Curve25519 Key Generation/Checking Routines			*
*					Copyright Peter Gutmann 2023-2024						*
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

#if defined( USE_25519 ) || defined( USE_ED25519 )

/****************************************************************************
*																			*
*							Utility Functions								*
*																			*
****************************************************************************/

/* Clamp a Curve25519 private value.  Clearing the three low bits means that
   the scalar is a multiple of the cofactor, so that applying the scalar to
   any group element produces an element in the prime order subgroup.  The
   MSB is cleared to ensure that the number is a multiple of 8 and wasn't 
   wrapped around the modulus, and setting the second-MSB was apparently done
   to hijack implementations that looked for the first 1-bit and were 
   therefore variable-time.  
   
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
   of zero bytes at the start of the value and rejecting it if there's more 
   than 80 bits worth */

#define NO_CHECK_BYTES		bitsToBytes( 80 )

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkMagnitude25519( IN_BUFFER( CURVE25519_SIZE ) \
										const BYTE *value,
									IN_BOOL const BOOLEAN isPublicValue )
	{
	LOOP_INDEX i;
	
	/* Walk down the value checking for a non-zero byte.  For a private 
	   value this is just a straight check of a scalar */
	if( !isPublicValue )
		{
		LOOP_MED_REV( i = CURVE25519_SIZE - 1, \
					  i > CURVE25519_SIZE - NO_CHECK_BYTES, i-- )
			{
			ENSURES( LOOP_INVARIANT_REV( i, CURVE25519_SIZE - ( NO_CHECK_BYTES - 1 ), 
										 CURVE25519_SIZE - 1 ) );

			if( value[ i ] != 0 )
				return( TRUE );
			}
		ENSURES( LOOP_BOUND_MED_REV_OK );
	
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
				  i > CURVE25519_SIZE - NO_CHECK_BYTES, i-- )
		{
		ENSURES( LOOP_INVARIANT_REV( i, CURVE25519_SIZE - ( NO_CHECK_BYTES - 1 ), 
									 CURVE25519_SIZE - 2 ) );

		if( value[ i ] != 0 )
			return( TRUE );
		}
	ENSURES( LOOP_BOUND_MED_REV_OK );
	
	return( FALSE );
	}

/****************************************************************************
*																			*
*							Generate a Curve25519 Key						*
*																			*
****************************************************************************/

/* Generate the Curve25519 private and public values */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateCurve25519PrivateValue( INOUT_PTR PKC_INFO *pkcInfo )
	{
	MESSAGE_DATA msgData;
	BYTE privKey[ CURVE25519_SIZE + 8 ];
	int status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Generate the Curve25519 private value and clamp it.  Because of the 
	   use of the Bernstein special-snowflake encoding we can't use
	   generateBignum() to do this for us but have to hand-assemble 
	   everything ourselves */
	setMessageData( &msgData, privKey, CURVE25519_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	clampCurve25519( privKey );

	/* Store the value in bignum storage */
	status = import25519ByteString( &pkcInfo->curve25519Param_priv, privKey, 
									CURVE25519_SIZE );
	zeroise( privKey, CURVE25519_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateCurve25519PublicValue( INOUT_PTR PKC_INFO *pkcInfo )
	{
	BYTE privKey[ CURVE25519_SIZE + 8 ], pubKey[ CURVE25519_SIZE + 8 ];
	int privKeySize, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Get the private value in special-snowflake form */
	status = export25519ByteString( privKey, CURVE25519_SIZE, &privKeySize, 
									&pkcInfo->curve25519Param_priv );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( privKeySize == CURVE25519_SIZE );

	/* Calculate the public value from the private value.  This function 
	   doesn't have a return value so there's not much that we can do in
	   terms of checking its status */
	( void ) ossl_x25519_public_from_private( pubKey, privKey );
	zeroise( privKey, CURVE25519_SIZE );

	/* Store the value in bignum storage */
	status = import25519ByteString( &pkcInfo->curve25519Param_pub, pubKey, 
									CURVE25519_SIZE );
	zeroise( pubKey, CURVE25519_SIZE );
	if( cryptStatusError( status ) )
		return( status );

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
static int ed25519PrivateToS( INOUT_PTR PKC_INFO *pkcInfo )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	BYTE privKey[ CURVE25519_SIZE + 8 ], s[ CRYPT_MAX_HASHSIZE + 8 ];
	int privKeySize, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	/* Get the private key */
	status = export25519ByteString( privKey, CURVE25519_SIZE, &privKeySize, 
									&pkcInfo->curve25519Param_priv );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( privKeySize == CURVE25519_SIZE );

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
	hashFunctionAtomic( s, CRYPT_MAX_HASHSIZE, privKey, CURVE25519_SIZE );
	clampCurve25519( s );
	status = import25519ByteString( &pkcInfo->curve25519Param_s, s, 
									CURVE25519_SIZE );
	zeroise( privKey, CURVE25519_SIZE );
	zeroise( s, CRYPT_MAX_HASHSIZE );
	
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int ed25519SToPublic( INOUT_PTR PKC_INFO *pkcInfo,
							 OUT_BUFFER_OPT_FIXED( CURVE25519_SIZE ) \
								BYTE *returnedPubKey )
	{
	BYTE s[ CURVE25519_SIZE + 8 ], pubKey[ CURVE25519_SIZE + 8 ];
	int sSize, osslStatus, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );
	assert( returnedPubKey == NULL || \
			isWritePtr( returnedPubKey, CURVE25519_SIZE ) );

	/* Get the value s which is derived from the private key and used to 
	   create the public key */
	status = export25519ByteString( s, CURVE25519_SIZE, &sSize, 
									&pkcInfo->curve25519Param_s );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( sSize == CURVE25519_SIZE );

	/* Calculate the Ed25519 public value from the private value, with the 
	   first two steps already done in ed25519PrivateToS():
	
		h = SHA512( privKey )[ 0...31 ];
		s = clamp( h );
		A = [s]B */
	osslStatus = clib_ed25519_public_from_private( pubKey, s );
	zeroise( s, CURVE25519_SIZE );
	if( !osslStatus )
		return( CRYPT_ERROR_FAILED );

	/* If we're doing a consistency check that the public key can be derived
	   from the private key, return the value to the caller */
	if( returnedPubKey != NULL )
		memcpy( returnedPubKey, pubKey, CURVE25519_SIZE );
	else
		{
		/* We're setting up the public key, store the value in bignum storage */
		status = import25519ByteString( &pkcInfo->curve25519Param_pub, pubKey, 
										CURVE25519_SIZE );
		}
	zeroise( pubKey, CURVE25519_SIZE );

	return( status );
	}

/* Generate the Ed25519 private and public values */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateEd25519PrivateValue( INOUT_PTR PKC_INFO *pkcInfo )
	{
	MESSAGE_DATA msgData;
	BYTE privKey[ CURVE25519_SIZE + 8 ];
	int status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Generate the Ed25519 private value.  The spec (RFC 8032 section 
	   5.1.5) just sets the key to 32 random bytes with no clamping as for 
	   Curve25519.  Because of the use of the Bernstein special-snowflake 
	   encoding we can't use generateBignum() to do this for us but have to 
	   hand-assemble everything ourselves */
	setMessageData( &msgData, privKey, CURVE25519_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );

	/* Store the value in bignum storage */
	status = import25519ByteString( &pkcInfo->curve25519Param_priv, privKey, 
									CURVE25519_SIZE );
	zeroise( privKey, CURVE25519_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the Ed25519 s value which used both to derive the public key 
	   and during the signing process */
	status = ed25519PrivateToS( pkcInfo );
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
	BYTE pubKey[ CURVE25519_SIZE + 8 ];
	int pubKeySize, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_25519 || \
			  cryptAlgo == CRYPT_ALGO_ED25519 );

	/* Get the public value in special-snowflake form */
	status = export25519ByteString( pubKey, CURVE25519_SIZE, &pubKeySize, 
									&pkcInfo->curve25519Param_pub );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( pubKeySize == CURVE25519_SIZE );

	/* Check that the magnitude of the 25519 public value seems OK */
	if( !checkMagnitude25519( pubKey, TRUE ) )
		{
		zeroise( pubKey, CURVE25519_SIZE );
		return( CRYPT_ARGERROR_STR1 );
		}

	/* In theory Ed25519 public keys have an additional checking step while 
	   Curve25519 ones don't and in fact are required to accept all manner of
	   garbage, e.g. (RFC 7748 section 5) "Implementations MUST accept non-
	   canonical values", however we apply the same checks to both since 
	   there's no reason we should be accepting questionable stuff like non-
	   canonical encodings, values of small order, and so on.
	   
	   In the case of Curve25519 keys we need to use two checking functions, 
	   clib_x25519_pubkey_verify() which checks for canonical encoding and
	   is25519SmallOrder() which checks for the obvious, while for Ed25519 
	   clib_ed25519_pubkey_verify() performs both checks */
	if( ( cryptAlgo == CRYPT_ALGO_25519 && \
		  ( clib_x25519_pubkey_verify( pubKey ) != TRUE || \
		    is25519SmallOrder( pubKey ) ) ) || \
		( cryptAlgo == CRYPT_ALGO_ED25519 && \
		  clib_ed25519_pubkey_verify( pubKey ) != TRUE ) )
		{
		DEBUG_DIAG(( "25519 public key is invalid/has small order" ));
		zeroise( pubKey, CURVE25519_SIZE );
		return( CRYPT_ARGERROR_STR1 );
		}

	/* Clean up */
	zeroise( pubKey, CURVE25519_SIZE );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Perform validity checks on the private key.  This is the same magnitude 
   check as the public value check, but also checks that it has the correct
   shape as per generateCurve25519PrivateValue() */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkCurve25519PrivateKey( INOUT_PTR PKC_INFO *pkcInfo,
									  IN_ALGO \
										const CRYPT_ALGO_TYPE cryptAlgo )
	{
	BYTE privKey[ CURVE25519_SIZE + 8 ];
	BYTE pubKey[ CURVE25519_SIZE + 8 ], buffer[ CURVE25519_SIZE + 8 ];
	int privKeySize, pubKeySize DUMMY_INIT, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( cryptAlgo == CRYPT_ALGO_25519 || \
			  cryptAlgo == CRYPT_ALGO_ED25519 );

	/* Get the private and public values in special-snowflake form */
	status = export25519ByteString( privKey, CURVE25519_SIZE, &privKeySize, 
									&pkcInfo->curve25519Param_priv );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( privKeySize == CURVE25519_SIZE );

	/* Check that the magnitude of the value seems OK */
	if( !checkMagnitude25519( privKey, FALSE ) )
		{
		zeroise( privKey, CURVE25519_SIZE );
		return( CRYPT_ARGERROR_STR1 );
		}

	/* If it's a Curve25519 key, make sure that it's appropriate clamped */
	if( cryptAlgo == CRYPT_ALGO_25519 && \
		( ( privKey[ 0 ] & ~0xF8 ) || \
		  ( privKey[ CURVE25519_SIZE - 1 ] & ~0x7F ) || \
		  !( privKey[ CURVE25519_SIZE - 1 ] & 0x40 ) ) )
		{
		zeroise( privKey, CURVE25519_SIZE );
		return( CRYPT_ARGERROR_STR1 );
		}

	/* Finally, make sure that the public-key value corresponds to the 
	   private key, or in the case of Ed25519 the intermediate s value
	   that's derived from the private key */
	if( cryptAlgo == CRYPT_ALGO_25519 )
		{
		/* This function has a void return so there's nothing to check */
		( void ) ossl_x25519_public_from_private( buffer, privKey );
		}
	else
		status = ed25519SToPublic( pkcInfo, buffer );
	if( cryptStatusOK( status ) )
		{
		status = export25519ByteString( pubKey, CURVE25519_SIZE, 
										&pubKeySize, 
										&pkcInfo->curve25519Param_pub );
		}
	if( cryptStatusOK( status ) )
		{
		/* Make sure that the public key matches the value recreated from 
		   the private key */
		ENSURES( pubKeySize == CURVE25519_SIZE );
		if( memcmp( buffer, pubKey, CURVE25519_SIZE ) )
			status = CRYPT_ARGERROR_STR1;
		}

	/* Clean up */
	zeroise( privKey, CURVE25519_SIZE );
	zeroise( pubKey, CURVE25519_SIZE );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( status );
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
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* Generate the private value */
	if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 )
		status = generateCurve25519PrivateValue( pkcInfo );
	else
		status = generateEd25519PrivateValue( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Calculate the public value */
	if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 )
		status = generateCurve25519PublicValue( pkcInfo );
	else
		status = generateEd25519PublicValue( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Checksum the bignums to try and detect fault attacks.  Since we're
	   setting the checksum at this point there's no need to check the 
	   return value */
	( void ) checksumContextData( pkcInfo, capabilityInfoPtr->cryptAlgo, 
								  TRUE );

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
			checksumContextData( pkcInfo, capabilityInfoPtr->cryptAlgo, 
								 TRUE ) ) )
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
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const BOOLEAN isPrivateKey = TEST_FLAG( contextInfoPtr->flags,
											CONTEXT_FLAG_ISPUBLICKEY ) ? \
								 FALSE : TRUE;
	BOOLEAN generatedPrivateValue = FALSE;
	int	status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* Make sure that the necessary key parameters have been initialised.  
	   In theory we need a pubic key present but Ed25519 generates the 
	   public key on the fly from the private key so it's not really a
	   problem if it's missing */
	if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_ED25519 && isPrivateKey )
		{
		if( BN_is_zero( &pkcInfo->curve25519Param_priv ) )
			return( CRYPT_ARGERROR_STR1 );
		if( BN_is_zero( &pkcInfo->curve25519Param_s ) )
			{
			status = ed25519PrivateToS( pkcInfo );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* If it's an ECDH key and there's no public value present, generate one 
	   now.  This is needed because all ECDH keys are effectively private 
	   keys.  We also update the context flags to reflect this change in 
	   status */
	if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 && \
		BN_is_zero( &pkcInfo->curve25519Param_priv ) )
		{
		status = generateCurve25519PrivateValue( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		CLEAR_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY );
		generatedPrivateValue = TRUE;
		}

	/* Calculate the public value if required */
	if( BN_is_zero( &pkcInfo->curve25519Param_pub ) || \
		generatedPrivateValue )
		{
		if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_25519 )
			status = generateCurve25519PublicValue( pkcInfo );
		else
			status = generateEd25519PublicValue( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

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

	/* Checksum the bignums to try and detect fault attacks.  Since we're 
	   setting the checksum at this point there's no need to check the 
	   return value.  Note that this isn't the TOCTOU issue that it appears 
	   to be because the bignum values are read by the calling code from 
	   their stored form a second time and compared to the values that we're 
	   checksumming here */
	( void ) checksumContextData( pkcInfo, capabilityInfoPtr->cryptAlgo,
								  ( isPrivateKey || generatedPrivateValue ) ? \
								    TRUE : FALSE );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}
#endif /* USE_25519 || USE_ED25519 */
