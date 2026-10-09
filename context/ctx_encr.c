/****************************************************************************
*																			*
*					cryptlib Encryption Context Action Routines				*
*						Copyright Peter Gutmann 1992-2025					*
*																			*
****************************************************************************/

/* "Modern cryptography is nothing more than a mathematical framework for
	debating the implications of various paranoid delusions"
												- Don Alvarez */

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#ifdef INC_ALL
  #include "context.h"
#else
  #include "context/context.h"
#endif /* Compiler-specific includes */

/* The number of bytes of data that we check to make sure that the 
   encryption operation succeeded.  See the comment in encryptDataConv() 
   before changing this */

#define ENCRYPT_CHECKSIZE	16

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Perform a validity check on keying/state information in a context, used 
   to defend against side-channel attacks */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkContextStateData( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
					DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const void *keyingInfo = DATAPTR_GET( contextInfoPtr->keyingInfo );
	int status = CRYPT_OK;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_B( sanityCheckContext( contextInfoPtr ) );
	REQUIRES_B( contextInfoPtr->type == CONTEXT_CONV || \
				contextInfoPtr->type == CONTEXT_MAC || \
				contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES_B( capabilityInfoPtr != NULL );
	REQUIRES_B( keyingInfo != NULL );

	/* If it's a context with the keying information held externally then we 
	   can't check it */
	if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
		return( TRUE );

	/* Make sure that the keying information hasn't been corrupted */
	switch( contextInfoPtr->type )
		{
		case CONTEXT_CONV:
			{
			const CONV_INFO *convInfo = ( const CONV_INFO * ) keyingInfo;

			if( checksumData( convInfo->key, convInfo->keyDataSize ) != \
												convInfo->keyDataChecksum )
				status = CRYPT_ERROR_FAILED;
			break;
			}

		case CONTEXT_MAC:
			{
			const MAC_INFO *macInfo = ( const MAC_INFO * ) keyingInfo;

			if( checksumData( macInfo->macInfo, macInfo->macInfoSize ) != \
												macInfo->macInfoChecksum )
				status = CRYPT_ERROR_FAILED;
			break;
			}
		
		case CONTEXT_PKC:
			{
			PKC_INFO *pkcInfo = ( PKC_INFO * ) keyingInfo;

			status = checksumContextData( pkcInfo, 
						TEST_FLAG( contextInfoPtr->flags, 
								   CONTEXT_FLAG_ISPUBLICKEY ) ? FALSE : TRUE );
			break;
			}

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "%s key memory corruption detected for object %d", 
					 capabilityInfoPtr->algoName, 
					 contextInfoPtr->objectHandle ));
		assert( DEBUG_WARN );
		return( FALSE );
		}

	return( TRUE );
	}

/* Recover from an en/decryption failure.  This replaces the data being en/
   decrypted/signed/verified with appropriate values to ensure that no 
   plaintext or other sensitive information is leaked even if the caller
   ignores the return code */

STDC_NONNULL_ARG( ( 1 ) ) \
static void sanitiseFailedData( INOUT_BUFFER_FIXED( dataLength ) void *data, 
								IN_LENGTH const int dataLength,
								IN_MESSAGE const MESSAGE_TYPE message,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	void *dataPtr = data;
	int length = dataLength, status;

	assert( isWritePtrDynamic( data, dataLength ) );

	REQUIRES_V( isIntegerRangeNZ( dataLength ) );
	REQUIRES_V( message >= MESSAGE_CTX_ENCRYPT && message <= MESSAGE_CTX_HASH );
	REQUIRES_V( isEnumRange( cryptAlgo, CRYPT_ALGO ) );

	/* If it's a PKC algorithm then the input may be structured data so we 
	   have to extract the reference to the actual data being processed from
	   it.  This gets a bit complicated because the output length is 
	   typically cleared during processing until the final output is actually
	   available.  To deal with this we use the maximum length possible for 
	   the fixed-size buffers.
	   
	   Another thing that we have to be careful about is how we got here in 
	   the first place.  If it's an internal error then it may be because 
	   there's something wrong with the data that we're trying to clear, or 
	   it could be one of the many other things that would trigger an 
	   exception, so we can't just exclude any CRYPT_ERROR_INTERNAL paths
	   because most of them won't affect what we're doing here, and in fact
	   many of them will make it important that we do sanitise the data.
	   
	   This is another shouldn't-happen catch-22 situation, we should never
	   get here and if we do it's not clear what the best way to handle a
	   stacked should-never-happen situation is.  To deal with this we catch
	   the only CRYPT_ERROR_INTERNAL conditions that could have brought us 
	   here and that we can't handle, a data-size error in the data that 
	   we're going to sanitise, via the general isIntegerRangeNZ() check on
	   the length and then specific checks for structured data */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_DH:
		case CRYPT_ALGO_ECDH:
#ifdef USE_X25519
		case CRYPT_ALGO_25519:
#endif /* USE_X25519 */
#ifdef USE_MLKEM
		case CRYPT_ALGO_MLKEM:
#endif /* USE_MLKEM */
			{
			KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) data;

			REQUIRES_V( dataLength == sizeof( KEYAGREE_PARAMS ) );

			if( message == MESSAGE_CTX_ENCRYPT )
				{
				static_assert( sizeof( keyAgreeParams->publicValue ) >= \
														KEYAGREE_DATA_SIZE,
							   "KEYAGREE_PARAMS publicValue size" );

				/* ML-KEM, as usual for a PQC, does things in a bizarre way, 
				   outputting the wrapped key as the publicValue and the 
				   shared secret as the wrappedKey.  The important one to
				   sanitised is the wrapped key, which is what gets 
				   communicated to the other side */
				dataPtr = keyAgreeParams->publicValue;
				}
			else
				{
				static_assert( sizeof( keyAgreeParams->wrappedKey ) >= \
														KEYAGREE_DATA_SIZE,
							   "KEYAGREE_PARAMS wrappedKey size" );

				dataPtr = keyAgreeParams->wrappedKey;
				}
			length = KEYAGREE_DATA_SIZE;
			break;
			}
			
		case CRYPT_ALGO_DSA:
#ifdef USE_ELGAMAL
		case CRYPT_ALGO_ELGAMAL:
#endif /* USE_ELGAMAL */
		case CRYPT_ALGO_ECDSA:
#ifdef USE_ED25519
		case CRYPT_ALGO_ED25519:
#endif /* USE_ED25519 */
			{
			DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) data;

			static_assert( sizeof( dlpParams->outParam ) >= DLP_DATA_SIZE,
						   "DLP_PARAMS wrappedKey size" );

			REQUIRES_V( dataLength == sizeof( DLP_PARAMS ) );

			dataPtr = dlpParams->outParam;
			length = DLP_DATA_SIZE;
			break;
			}

		default:
			/* It's either a conventional algorithm or RSA, which need no 
			   special handling */
			break;
		}

	/* If it's a failed en/decrypt then we replace the data with random 
	   noise.  On encrypt this means that the plaintext is replaced with 
	   non-decryptable garbage that looks encrypted.  On decrypt this means 
	   that the plaintext is also replaced with garbage, for decryption of 
	   data this doesn't really matter but for decryption of keying material 
	   it means that we continue with junk keys that don't reveal anything 
	   to an attacker */
	if( message == MESSAGE_CTX_ENCRYPT || message == MESSAGE_CTX_DECRYPT )
		{
		MESSAGE_DATA msgData;

		/* The largest amount of nonce data that we can get is 
		   MAX_INTLENGTH_SHORT, so we limit the request to that and fill the
		   rest of the buffer with fixed nonzero data.  Presumably the first
		   MAX_INTLENGTH_SHORT bytes of random garbage will be a sufficient 
		   clue that something went wrong */
		setMessageData( &msgData, dataPtr, 
						min( length, MAX_INTLENGTH_SHORT ) );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			{
			/* The attempt to fill with random garbage failed, fall back to
			   fixed, but non-zero, data */
			REQUIRES_V( isIntegerRangeNZ( length ) ); 
			memset( dataPtr, '*', length );
			}
		else
			{
			/* We got the random data, if there's even more to overwrite just
			   use fixed data for the rest */
			if( length > MAX_INTLENGTH_SHORT )
				{
				REQUIRES_V( checkOverflowSub( length, MAX_INTLENGTH_SHORT ) );
				REQUIRES_V( isIntegerRangeNZ( length - MAX_INTLENGTH_SHORT ) ); 
				memset( ( BYTE * ) dataPtr + MAX_INTLENGTH_SHORT, '*',
						length - MAX_INTLENGTH_SHORT );
				}
			}
		}
	else
		{
		/* It's a failed sign/signature verify, clear the output to ensure
		   that nothing is leaked */
		REQUIRES_V( isIntegerRangeNZ( length ) ); 
		memset( dataPtr, 0, length );
		}
	}

/****************************************************************************
*																			*
*								Encrypt Data								*
*																			*
****************************************************************************/

/* Encrypt a block of data using a conventional cipher */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptDataConv( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
							INOUT_BUFFER_FIXED( dataLength ) void *data, 
							IN_LENGTH const int dataLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
					DATAPTR_GET( contextInfoPtr->capabilityInfo );
	const CONV_INFO *convInfo = DATAPTR_GET_CONV( contextInfoPtr );
	CTX_ENCRYPT_FUNCTION encryptFunction;
	const int savedDataLength = min( dataLength, ENCRYPT_CHECKSIZE );
	BYTE savedData[ ENCRYPT_CHECKSIZE + 8 ];
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_CONV );
	REQUIRES( !needsKey( contextInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( dataLength ) );
	REQUIRES( capabilityInfoPtr != NULL );
	REQUIRES( convInfo != NULL );
	REQUIRES( isStreamCipher( capabilityInfoPtr->cryptAlgo ) || \
			  !needsIV( convInfo->mode ) ||
			  TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_IV_SET ) );

	/* Get function pointers for the context */
	encryptFunction = ( CTX_ENCRYPT_FUNCTION ) \
					  FNPTR_GET( contextInfoPtr->encryptFunction );
	REQUIRES( encryptFunction != NULL );

	/* Save a copy of the plaintext, and encrypt it */
	REQUIRES( rangeCheck( savedDataLength, 1, ENCRYPT_CHECKSIZE ) );
	memcpy( savedData, data, savedDataLength );
	status = encryptFunction( contextInfoPtr, data, dataLength );
	if( cryptStatusError( status ) )
		{
		REQUIRES( rangeCheck( savedDataLength, 1, ENCRYPT_CHECKSIZE ) );
		zeroise( savedData, savedDataLength );
		return( status );
		}

	/* Check for a catastrophic failure of the encryption.  A check of
	   a single block unfortunately isn't completely foolproof for ciphers 
	   in CBC mode because of the way that the IV is applied to the input.  
	   For the CBC encryption operation:
					
		out = enc( in ^ IV )
						
	   if out == IV the operation turns into a no-op.  Consider the simple 
	   case where IV == in, so IV ^ in == 0.  Then out = enc( 0 ) == IV, 
	   with the input appearing again at the output.  
	   
	   In fact for a 64-bit block cipher this can occur during normal 
	   operation once every 2^32 blocks.  Although the chances of this 
	   happening are fairly low (the collision would have to occur on the 
	   first encrypted block in a message since that's the one that we 
	   check), we skip the check if we're encrypting a single block in CBC 
	   mode.
	   
	   We also skip the check if we've got less than 64 bits of data to
	   compare in any mode, again because of the chance of a false 
	   positive */
	if( dataLength >= 8 && \
		!( convInfo->mode == CRYPT_MODE_CBC && \
		   capabilityInfoPtr->blockSize == dataLength ) && \
		compareDataConstTime( savedData, data, savedDataLength ) == TRUE )
		status = CRYPT_ERROR_FAILED;

	REQUIRES( rangeCheck( savedDataLength, 1, ENCRYPT_CHECKSIZE ) );
	zeroise( savedData, savedDataLength );
	return( status );
	}

/* Encrypt a block of data using a PKC */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int encryptDataPKC( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						   INOUT_BUFFER_FIXED( dataLength ) void *data, 
						   IN_LENGTH_SHORT const int dataLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
					DATAPTR_GET( contextInfoPtr->capabilityInfo );
	CTX_ENCRYPT_FUNCTION encryptFunction;
	BYTE savedData[ ENCRYPT_CHECKSIZE + 8 ];
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );
	REQUIRES( !needsKey( contextInfoPtr ) );
	REQUIRES( isShortIntegerRangeNZ( dataLength ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* Get function pointers for the context */
	encryptFunction = ( CTX_ENCRYPT_FUNCTION ) \
					  FNPTR_GET( contextInfoPtr->encryptFunction );
	REQUIRES( encryptFunction != NULL );

	/* Handle algorithm-specific encryption requirements */
	switch( capabilityInfoPtr->cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			REQUIRES( dataLength >= MIN_PKCSIZE && \
					  dataLength <= CRYPT_MAX_PKCSIZE );

			/* Save a copy of the plaintext, and encrypt it */
			memcpy( savedData, data, ENCRYPT_CHECKSIZE );
			status = encryptFunction( contextInfoPtr, data, dataLength );
			if( cryptStatusError( status ) )
				{
				zeroise( savedData, ENCRYPT_CHECKSIZE );
				return( status );
				}

			/* Check for a catastrophic failure of the encryption */
			if( compareDataConstTime( savedData, data, \
									  ENCRYPT_CHECKSIZE ) == TRUE )
				status = CRYPT_ERROR_FAILED;

			zeroise( savedData, ENCRYPT_CHECKSIZE );
			return( status );

		case CRYPT_ALGO_DH:
		case CRYPT_ALGO_ECDH:
#ifdef USE_X25519
		case CRYPT_ALGO_25519:
#endif /* USE_X25519 */
#ifdef USE_MLKEM
		case CRYPT_ALGO_MLKEM:
#endif /* USE_MLKEM */
			/* Key agreement algorithms are a special case since they don't 
			   actually encrypt the data.  ML-KEM is a special case in that
			   although it's applied as a reverse-RSA the caller doesn't 
			   control the secret being wrapped so it works like a keyex
			   algorithm even though it's actually a key wrap */
			REQUIRES( dataLength == sizeof( KEYAGREE_PARAMS ) );

			return( encryptFunction( contextInfoPtr, data, dataLength ) );

#ifdef USE_ELGAMAL
		case CRYPT_ALGO_ELGAMAL:
			{
			/* DLP algorithms have composite parameters and are handled 
			   differently from standard algorithms */
			const DLP_PARAMS *dlpParams = ( DLP_PARAMS * ) data;

			REQUIRES( dataLength == sizeof( DLP_PARAMS ) );

			/* Save a copy of the plaintext, and encrypt it */
			REQUIRES( dlpParams->inLen1 >= ENCRYPT_CHECKSIZE );
			memcpy( savedData, dlpParams->inParam1, ENCRYPT_CHECKSIZE );
			status = encryptFunction( contextInfoPtr, data, dataLength );
			if( cryptStatusError( status ) )
				{
				zeroise( savedData, ENCRYPT_CHECKSIZE );
				return( status );
				}

			/* Check for a catastrophic failure of the encryption */
			if( !memcmp( savedData, dlpParams->outParam, 
						 ENCRYPT_CHECKSIZE ) )
				status = CRYPT_ERROR_FAILED;

			zeroise( savedData, ENCRYPT_CHECKSIZE );
			return( status );
			}
#endif /* USE_ELGAMAL */

		default:
			retIntError();
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Encrypt Data								*
*																			*
****************************************************************************/

/* Process an action message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int processActionMessage( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
						  IN_MESSAGE const MESSAGE_TYPE message,
						  INOUT_BUFFER_FIXED( dataLength ) void *data, 
						  IN_LENGTH_Z const int dataLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = \
					DATAPTR_GET( contextInfoPtr->capabilityInfo );
	PKC_INFO *pkcInfo DUMMY_INIT_PTR;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( ( message == MESSAGE_CTX_HASH && \
			  ( dataLength == 0 || \
			    isReadPtrDynamic( data, dataLength ) ) ) || \
			isWritePtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( message >= MESSAGE_CTX_ENCRYPT && message <= MESSAGE_CTX_HASH );
	REQUIRES( isIntegerRange( dataLength ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* Get subtype-specific storage if required */
	if( contextInfoPtr->type == CONTEXT_PKC )
		{
		pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
		REQUIRES( pkcInfo != NULL );
		}

	switch( message )
		{
		case MESSAGE_CTX_ENCRYPT:
			if( !checkContextStateData( contextInfoPtr ) )
				return( CRYPT_ERROR_FAILED );
			if( contextInfoPtr->type == CONTEXT_PKC )
				{
				status = encryptDataPKC( contextInfoPtr, data, dataLength );
				if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
					clearTempBignums( pkcInfo );
				}
			else
				status = encryptDataConv( contextInfoPtr, data, dataLength );
			if( cryptStatusOK( status ) && \
				!checkContextStateData( contextInfoPtr ) )
				status = CRYPT_ERROR_FAILED;
			if( cryptStatusError( status ) )
				{
				/* We shouldn't have a length of zero but if we do then it'll
				   trigger an error condition from the encrypt function, end
				   up here, and trigger a second one in the sanitise data
				   function */
				assert_nofuzz( DEBUG_WARN );
				if( dataLength > 0 )
					{
					sanitiseFailedData( data, dataLength, message, 
										capabilityInfoPtr->cryptAlgo );
					}
				}
			break;

		case MESSAGE_CTX_DECRYPT:
			{
			const CTX_ENCRYPT_FUNCTION decryptFunction = \
						( CTX_ENCRYPT_FUNCTION ) \
						FNPTR_GET( contextInfoPtr->decryptFunction );

			REQUIRES( decryptFunction != NULL );
			REQUIRES( !needsKey( contextInfoPtr ) );

			if( !checkContextStateData( contextInfoPtr ) )
				return( CRYPT_ERROR_FAILED );
			status = decryptFunction( contextInfoPtr, data, dataLength );
			if( contextInfoPtr->type == CONTEXT_PKC && \
				!TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
				{
				ANALYSER_HINT( pkcInfo != NULL );
				clearTempBignums( pkcInfo );
				}
			if( cryptStatusOK( status ) && \
				!checkContextStateData( contextInfoPtr ) )
				status = CRYPT_ERROR_FAILED;
			if( cryptStatusError( status ) )
				{
				/* We shouldn't have a length of zero but if we do then it'll
				   trigger an error condition from the encrypt function, end
				   up here, and trigger a second one in the sanitise data
				   function */
				assert_nofuzz( DEBUG_WARN );
				if( dataLength > 0 )
					{
					sanitiseFailedData( data, dataLength, message, 
										capabilityInfoPtr->cryptAlgo );
					}
				}
			break;
			}

		case MESSAGE_CTX_SIGN:
			if( !checkContextStateData( contextInfoPtr ) )
				return( CRYPT_ERROR_FAILED );
			status = capabilityInfoPtr->signFunction( contextInfoPtr,
													  data, dataLength );
			if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
				{
				/* We can do this unconditionally since a sign operation 
				   can only be used with a PKC context */
				clearTempBignums( pkcInfo );
				}
			if( cryptStatusOK( status ) && \
				!checkContextStateData( contextInfoPtr ) )
				status = CRYPT_ERROR_FAILED;
			if( cryptStatusError( status ) )
				{
				assert( DEBUG_WARN );
				sanitiseFailedData( data, dataLength, message, 
									capabilityInfoPtr->cryptAlgo );
				}
			break;

		case MESSAGE_CTX_SIGCHECK:
			if( !checkContextStateData( contextInfoPtr ) )
				return( CRYPT_ERROR_FAILED );
			status = capabilityInfoPtr->sigCheckFunction( contextInfoPtr,
														  data, dataLength );
			if( !TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_DUMMY ) )
				{
				/* We can do this unconditionally since a sign operation 
				   can only be used with a PKC context */
				clearTempBignums( pkcInfo );
				}
			if( cryptStatusOK( status ) && \
				!checkContextStateData( contextInfoPtr ) )
				status = CRYPT_ERROR_FAILED;
			if( cryptStatusError( status ) && !isDataError( status ) )
				{
				assert( DEBUG_WARN );
				sanitiseFailedData( data, dataLength, message, 
									capabilityInfoPtr->cryptAlgo );
				}
			break;

		case MESSAGE_CTX_HASH:
			{
			/* We don't check the state for hashes since there's not much 
			   that can be done in terms of an attack, we'll just produce a
			   random hash value that can't be verified */
			if( contextInfoPtr->type == CONTEXT_MAC && \
				!checkContextStateData( contextInfoPtr ) )
				return( CRYPT_ERROR_FAILED );

			/* If we've already completed the hashing/MACing then we can't 
			   continue */
			if( TEST_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_DONE ) )
				return( CRYPT_ERROR_COMPLETE );

			status = capabilityInfoPtr->encryptFunction( contextInfoPtr,
														 data, dataLength );
			if( cryptStatusOK( status ) && \
				contextInfoPtr->type == CONTEXT_MAC )
				{
				MAC_INFO *macInfo = DATAPTR_GET_MAC( contextInfoPtr );

				REQUIRES( macInfo != NULL );

				/* The hash/MAC operation always updates the hash/MAC state 
				   so instead of re-checking the checksum as we do for 
				   conventional contexts we need to recalculate the it for 
				   the next access */
				macInfo->macInfoChecksum = checksumData( macInfo->macInfo, 
														 macInfo->macInfoSize );
				}
			if( cryptStatusError( status ) )
				{
				assert( DEBUG_WARN );
				break;
				}
			if( dataLength > 0 )
				{
				/* Usually the MAC initialisation happens when we load the 
				   key, but if we've deleted the MAC value to process 
				   another piece of data then it'll happen on-demand so we 
				   have to set the flag here */
				SET_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_HASH_INITED );
				}
			else
				{
				/* Usually a hash of zero bytes is used to wrap up an
				   ongoing hash operation, however it can also be the only 
				   operation if a zero-byte string is being hashed.  To 
				   handle this we have to set the inited flag as well as the 
				   done flag */
				SET_FLAG( contextInfoPtr->flags,
						  CONTEXT_FLAG_HASH_DONE | CONTEXT_FLAG_HASH_INITED );
				}
			break;
			}

		default:
			retIntError();
		}

	return( status );
	}
