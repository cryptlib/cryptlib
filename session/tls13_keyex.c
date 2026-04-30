/****************************************************************************
*																			*
*					cryptlib TLS 1.3 Keyex Management						*
*					Copyright Peter Gutmann 2019-2025						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "tls.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS13

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Create the DH/ECDH/25519/ML-KEM contexts needed on the client side for 
   TLS 1.3's guessed keyex */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createKeyexContextsTLS13( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	
  #if 0	/* See comment in session/tls_keyex.c:writeSupportedGroups() */
	status = createKeyexContextTLS( &handshakeInfo->keyexContext, 
									CRYPT_ALGO_DH );
	if( cryptStatusOK( status ) )
		{
		/* Indicate that we're using the nonstandard DH keys required
		   by TLS 1.3 */
		static const int dhKeySize = bitsToBytes( 2048 ) | 1;

		status = krnlSendMessage( handshakeInfo->keyexContext, 
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &dhKeySize, 
								  CRYPT_IATTRIBUTE_KEY_DLPPARAM );
		}
	if( cryptStatusError( status ) )
		return( status );
  #endif /* 0 */

	/* Create the ECDH context and generate a fresh keyex value into it */
	if( algoAvailable( CRYPT_ALGO_ECDH ) )
		{
		status = createKeyexContextTLS( &handshakeInfo->keyexEcdhContext, 
										CRYPT_ALGO_ECDH );
		if( cryptStatusOK( status ) )
			{
			static const int ecdhKeyType = CRYPT_ECCCURVE_P256;

			status = krnlSendMessage( handshakeInfo->keyexEcdhContext, 
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &ecdhKeyType, 
									  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Create the X25519 context and generate a fresh keyex value into it */
#ifdef USE_X25519
	if( algoAvailable( CRYPT_ALGO_25519 ) )
		{
		status = createKeyexContextTLS( &handshakeInfo->keyex25519Context, 
										CRYPT_ALGO_25519 );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( handshakeInfo->keyex25519Context, 
									  IMESSAGE_SETATTRIBUTE, 
									  MESSAGE_VALUE_TRUE, 
									  CRYPT_IATTRIBUTE_KEY_IMPLICIT );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_X25519 */

	/* If we're using ML-KEM (which is used with 25519), create yet another 
	   context for that.  Since this works as a kind of reverse-RSA we need 
	   to generate a key into it that we then send to the server to wrap a 
	   secret key to send back to the client */
#ifdef USE_MLKEM
	if( algoAvailable( CRYPT_ALGO_MLKEM ) )
		{
		status = createKeyexContextTLS( &handshakeInfo->keyexAltContext, 
										CRYPT_ALGO_MLKEM );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendNotifier( handshakeInfo->keyexAltContext, 
									   IMESSAGE_CTX_GENKEY );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_MLKEM */

	return( CRYPT_OK );
	}

/* Set up the server-side DH/ECDH/25519/ML-KEM crypto */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initTLS13Keyex( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   const TLS_GROUP_INFO *groupInfoPtr )
	{
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( groupInfoPtr, sizeof( TLS_GROUP_INFO ) ) );

	/* Create the keyex contexts as required */
	status = createKeyexContextTLS( &handshakeInfo->keyexContext, 
									groupInfoPtr->algorithm );
#ifdef USE_MLKEM
	if( cryptStatusOK( status ) && \
		isPQCGroup( groupInfoPtr->tlsGroupID ) )
		{
		status = createKeyexContextTLS( &handshakeInfo->keyexAltContext, 
										CRYPT_ALGO_MLKEM );
		}
#endif /* USE_MLKEM */
	if( cryptStatusError( status ) )
		return( status );

	/* Initialised the keyex contexts */
	switch( groupInfoPtr->algorithm )
		{
		case CRYPT_ALGO_DH:
			{
			/* For DH we have to indicate that we're using the nonstandard 
			   parameters required by TLS 1.3, which we do by setting the 
			   LSB of the key size */
			const int keyexParam = groupInfoPtr->keySize | 1;

			status = krnlSendMessage( handshakeInfo->keyexContext,
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &keyexParam,
									  CRYPT_IATTRIBUTE_KEY_DLPPARAM );
			break;
			}

		case CRYPT_ALGO_ECDH:
			status = krnlSendMessage( handshakeInfo->keyexContext,
								IMESSAGE_SETATTRIBUTE, 
								( MESSAGE_CAST ) &groupInfoPtr->eccCurveID,
								CRYPT_IATTRIBUTE_KEY_ECCPARAM );
			break;

#ifdef USE_X25519
		case CRYPT_ALGO_25519:
			status = krnlSendMessage( handshakeInfo->keyexContext,
									  IMESSAGE_SETATTRIBUTE, 
									  MESSAGE_VALUE_TRUE, 
									  CRYPT_IATTRIBUTE_KEY_IMPLICIT );
  #ifdef USE_MLKEM
			/* ML-KEM is an add-on to 25519 so it's handled under the 25519
			   option */
			if( cryptStatusOK( status ) && \
				isPQCGroup( groupInfoPtr->tlsGroupID ) )
				{
				MESSAGE_DATA msgData;
				
				/* For X25519MLKEM768 the overall keyex value is:
				
					uint16			keyexLength = 1216
					byte[ 1184 ]	mlkemPubKey
					byte[ 32 ]		25519PubValue
						
				   so we load the data portion corresponding to the ML-KEM 
				   public key.  There's no encapsulation for the ML-KEM + 
				   25519 data, it's just stored as a raw blob, so we have to 
				   hardcode in the position and length */
				setMessageData( &msgData, 
								handshakeInfo->tls13KeyexValue + UINT16_SIZE, 
								MLKEM_PUBKEY_SIZE );
				status = krnlSendMessage( handshakeInfo->keyexAltContext,
										  IMESSAGE_SETATTRIBUTE_S, 
										  &msgData,  
										  CRYPT_IATTRIBUTE_KEY_TLS );
				}
  #endif /* USE_MLKEM */
			break;
#endif /* USE_X25519 */

		default:
			retIntError();
		}

	return( status );
	}

/* Handle the case where the peer didn't match any of our keyex values */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int handleNonmatchedKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
								  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
								  IN_BOOL const BOOLEAN isGoogle,
								  OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( extErrorInfoSet, sizeof( BOOLEAN ) ) );

	REQUIRES( isBooleanValue( isGoogle ) );

	/* Clear return values */
	*extErrorInfoSet = FALSE;

	if( !isServer( sessionInfoPtr ) )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "Server doesn't support any of our offered keyex types" ) );
		}

	/* Google Chrome doesn't send any MTI keyexes in its first client hello, 
	   which forces a retry on every connect.  If this isn't already a 
	   retry, tell the caller to add an extra round trip and more crypto 
	   computations for make benefit Google braindamage */
	if( !( handshakeInfo->flags & HANDSHAKE_FLAG_RETRIEDCLIENTHELLO ) )
		{
		DEBUG_PRINT(( "Client didn't send any supported keyex type, "
					  "forcing handshake retry.\n" ));
		if( isGoogle )
			{
			/* Warn the caller to brace themselves for further Google
			   braindamage elsewhere in the handshake */
			handshakeInfo->flags |= HANDSHAKE_FLAG_ISGOOGLE;
			}
		return( OK_SPECIAL );
		}

	*extErrorInfoSet = TRUE;
	if( isGoogle )
		{
		/* We can fingerprint Google Chrome via the GREASE braindamage 
		   mentioned in the extensions code, it also doesn't send an MTI 
		   P256 keyex in its client hello so once we've fallen we can't get 
		   up any more */
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "Google Chrome doesn't support the mandatory ECDH P256 "
				  "key exchange in its client handshake, can't continue" ) );
		}
	retExt( CRYPT_ERROR_NOTAVAIL,
			( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
			  "Couldn't find a supported keyex type in client's handshake "
			  "message" ) );
	}

/****************************************************************************
*																			*
*							Read/Write Keyex Information					*
*																			*
****************************************************************************/

/* Write the DH/ECDH/25519 keyex.  This isn't used for ML-KEM, which as for
   anything post-magic requires its own special-snowflake processing */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeKeyexData( INOUT_PTR STREAM *stream,
						   IN_HANDLE const CRYPT_CONTEXT keyexContext,
						   IN_ENUM( TLS_GROUP ) \
								const TLS_GROUP_TYPE tlsGroupType,
						   IN_LENGTH_SHORT_MIN( 32 ) const int keyDataSize )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( keyexContext ) );
	REQUIRES( isEnumRange( tlsGroupType, TLS_GROUP ) );
	REQUIRES( isShortIntegerRangeMin( keyDataSize, 32 ) );

	/* Perform Phase 1 of the DH/ECDH/25519 keyex.  We don't short-circuit
	   this for size-check null streams because the keyex data typically has 
	   special-case formatting requirements that we can't easily replicate
	   here, and in any case it's just copying out a pregenerated value so
	   no actual crypto is being performed */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	status = krnlSendMessage( keyexContext, IMESSAGE_CTX_ENCRYPT, 
							  &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the group type and keyex data */
	writeUint16( stream, tlsGroupType );
	if( isECCGroup( tlsGroupType ) )
		{
		/* It's an ECDH/25519 keyex value with a fixed length, write it as 
		   is */
		writeUint16( stream, keyAgreeParams.publicValueLen );
		status = swrite( stream, keyAgreeParams.publicValue,
						 keyAgreeParams.publicValueLen );
		}
	else
		{
		/* It's a variable-length DH keyex value, write it as a fixed-length 
		   value */
		writeUint16( stream, keyDataSize );
		status = writeFixedsizeValue( stream, keyAgreeParams.publicValue,
									  keyAgreeParams.publicValueLen, 
									  keyDataSize );
		}
	zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );

	return( status );
	}

#ifdef USE_MLKEM 

/* Write the ML-KEM keyex, which is actually an ML-KEM + 25519 keyex crammed 
   together in one data block with no structure, written in the reverse order 
   that the group name gives it as.  In addition because of the reverse-RSA
   nature of ML-KEM the client-side keyex isn't actually a keyex but the 
   ML-KEM public key that the server encrypts with */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeKeyexMlkem( INOUT_PTR STREAM *stream,
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							IN_BOOL const BOOLEAN isServer )
	{
	const CRYPT_CONTEXT keyexContext = isServer ? \
			handshakeInfo->keyexContext : handshakeInfo->keyex25519Context;
			/* At this point the client is still guessing what the server 
			   wants so there's no main keyex context set and we have to
			   explicitly select the 25519 one */
	KEYAGREE_PARAMS keyAgreeParams25519;
	KEYAGREE_PARAMS keyAgreeParamsMlkem DUMMY_INIT_STRUCT;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isBooleanValue( isServer ) );

	/* If it's just a size check then don't perform the expensive crypto 
	   operations but just write a dummy data block of the same size as
	   the output from the crypto, with the 25519 keyex data providing the
	   dummy block */
	if( sIsNullStream( stream ) )
		{
		memset( &keyAgreeParams25519, 0, sizeof( KEYAGREE_PARAMS  ) );
		return( swrite( stream, &keyAgreeParams25519,
						UINT16_SIZE + UINT16_SIZE + \
						( isServer ? MLKEM_WRAPPEDKEY_SIZE : \
									 MLKEM_PUBKEY_SIZE ) + \
						X25519_PUBKEY_SIZE ) );
		}

	/* Perform Phase 1 of the 25519 keyex and, if necessary, the ML-KEM 
	   keyex.  ML-KEM is a special case because for the client the ML-KEM 
	   part isn't a keyex but the public-key value for the reverse-RSA key 
	   exchange, so we only perform the keyex if we're the server */
	memset( &keyAgreeParams25519, 0, sizeof( KEYAGREE_PARAMS ) );
	status = krnlSendMessage( keyexContext, IMESSAGE_CTX_ENCRYPT, 
							  &keyAgreeParams25519, 
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusOK( status ) && isServer )
		{
		memset( &keyAgreeParamsMlkem, 0, sizeof( KEYAGREE_PARAMS ) );
		status = krnlSendMessage( handshakeInfo->keyexAltContext, 
								  IMESSAGE_CTX_ENCRYPT, 
								  &keyAgreeParamsMlkem, 
								  sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the combined ML-KEM + 25519 keyex */
	writeUint16( stream, TLS_GROUP_X25519MLKEM768 );
	if( isServer )
		{
		/* Write the ML-KEM keyex and then tack the 25519 portion onto the 
		   end of the ML-KEM part */
		writeUint16( stream, keyAgreeParamsMlkem.publicValueLen + \
							 X25519_PUBKEY_SIZE );
		status = swrite( stream, keyAgreeParamsMlkem.publicValue,
						 keyAgreeParamsMlkem.publicValueLen );

		/* Remember the secret key value for later */
		REQUIRES( rangeCheck( keyAgreeParamsMlkem.wrappedKeyLen, 
							  1, CRYPT_MAX_HASHSIZE ) );
		memcpy( handshakeInfo->tls13PqcSecretValue, 
				keyAgreeParamsMlkem.wrappedKey, 
				keyAgreeParamsMlkem.wrappedKeyLen );
		handshakeInfo->tls13PqcSecretValueLen = \
				keyAgreeParamsMlkem.wrappedKeyLen;
		}
	else	
		{
		/* Write the ML-KEM public key and then tack the 25519 portion onto 
		   the end of the ML-KEM key */
		writeUint16( stream, MLKEM_PUBKEY_SIZE + X25519_PUBKEY_SIZE );
		status = exportAttributeToStream( stream, 
										  handshakeInfo->keyexAltContext,
										  CRYPT_IATTRIBUTE_KEY_TLS );
		}
	if( cryptStatusOK( status ) )
		{
		status = swrite( stream, keyAgreeParams25519.publicValue,
						 keyAgreeParams25519.publicValueLen );
		}
	zeroise( &keyAgreeParams25519, sizeof( KEYAGREE_PARAMS ) );
	zeroise( &keyAgreeParamsMlkem, sizeof( KEYAGREE_PARAMS ) );

	return( status );
	}
#endif /* USE_MLKEM */

/* The TLS 1.3 keyex is stuffed inside an extension in the client/server 
   hello (in fact most of TLS 1.3 is assembled from extensions).  This is an 
   ugly "optimisation" for TLS 1.3 where we have to guess any keyex 
   mechanisms that the server supports and send one of each that we think 
   might be required, with the server choosing the one that it deems the 
   most cromulent.  
   
   This saves 1RTT at the expense of a whole lot of extra crypto computation 
   on the client, and to make things even worse since we're taking guesses 
   at what's required we have to send this even if we're doing a PSK-based
   session resume because we don't know at this point whether the server 
   will allow the resume or not.  This pretty much defeats the whole point 
   of doing a resume since all of the crypto is still done whether it's 
   needed or not.

   As if all that wasn't already bad enough, the addition of post-magic
   cryptography to the list means that the extension becomes enormous due
   to the size of the post-magic keyex, so we need to make special
   accommodations for the length sanity-checks.  It also complicates the
   checking process because the initial length constraint is the maximum 
   size of a post-magic keyex while the later length constraint, once we've
   filtered out unknown keyex types to leave only the ones that we deal 
   with, is the maximum size of a conventional keyex.

  [	uint16			keyexListLength		-- Client only ]
		uint16		namedGroup
		uint16		keyexLength
	DH:
			byte[]	y
	ECDH:
			byte[]	ecPoint
	25519:
			byte[]	pubValue
	25519MLKEM768
			byte[]	mlkemPubValue
			byte[]	25519PubValue

   For DH the keyex is the Y value padded out with zeroes to the length of 
   p for no known reason, for ECDH it's the ECC point in X9.62 format, for 
   25519 it's the 32-byte public value, and for 25519MLKEM768 it's the 1184-
   byte MLKEM-768 public value followed by the 32-byte 25519 public value 
   (that is, the order of the data fields is the reverse of the name for
   the fields) */

#define MAX_TOTAL_KEYEX_SIZE	8192
#define MAX_KEYEX_SIZE			2048
#define MAX_KEYEX_VALUES		8

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readKeyexTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					INOUT_PTR STREAM *stream, 
					IN_LENGTH_SHORT_Z const int extLength,
					OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	CRYPT_ECCCURVE_TYPE clientECDHcurve = CRYPT_ECCCURVE_NONE;
	const TLS_GROUP_INFO *groupInfo, *groupInfoPtr;
	BOOLEAN isECDHAvailable, isX25519Available, isGoogle = FALSE;
	BOOLEAN seenKeyex = FALSE;
	int keyexListLen = extLength, groupIndex = 99, endPos;
	int noGroupInfoEntries, status;
	LOOP_INDEX noKeyexValues;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( extErrorInfoSet, sizeof( BOOLEAN ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*extErrorInfoSet = FALSE;

	/* Get the TLS group information */
	status = getTLSGroupInfo( &groupInfo, &noGroupInfoEntries );
	ENSURES( cryptStatusOK( status ) );

	/* Check which algorithms we have available and get any required 
	   parameters.  If we're the client then we'll have a preconfigured set 
	   of contexts available which modifies the algorithm choice while the
	   server accepts anything that the client sends */
	isECDHAvailable = algoAvailable( CRYPT_ALGO_ECDH ) ? TRUE : FALSE;
	isX25519Available = algoAvailable( CRYPT_ALGO_25519 ) ? TRUE : FALSE;
	if( !isServer( sessionInfoPtr ) )
		{
#if 0	/* See comment in session/tls_keyex.c:writeSupportedGroups() */
		/* Get the DH keysize and ECDH curve type */
		status = krnlSendMessage( handshakeInfo->keyexContext,
								  IMESSAGE_GETATTRIBUTE, &clientDHkeySize,
								  CRYPT_CTXINFO_KEYSIZE );
#endif /* 0 */
		if( handshakeInfo->keyexEcdhContext == CRYPT_ERROR )
			isECDHAvailable = FALSE;
		else
			{
			int eccParam;	/* int vs. enum */
			
			status = krnlSendMessage( handshakeInfo->keyexEcdhContext,
									  IMESSAGE_GETATTRIBUTE, &eccParam,
									  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
			if( cryptStatusOK( status ) )
				clientECDHcurve = eccParam;	/* int vs. enum */
			else
				isECDHAvailable = FALSE;
			}
#ifdef USE_X25519
		if( handshakeInfo->keyex25519Context == CRYPT_ERROR )
			isX25519Available = FALSE;
#else
		isX25519Available = FALSE;
#endif /* USE_X25519 */
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If we're the server, the client will send us a list of keyex values 
	   so first we need to read and check the list header.  If we're the 
	   client then there's a single value of the same length as the 
	   extension.
	   
	   The maximum length for the sanity-check is a bit hard to determine,
	   typically it'd be well under 1kB for a few 256-bit ECC values from
	   P256 and 25519, however post-magic crypto values can get quite large
	   so we allow a much larger value as MAX_TOTAL_KEYEX_SIZE */
	if( isServer( sessionInfoPtr ) )
		{
		status = keyexListLen = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( extLength < UINT16_SIZE || \
			keyexListLen != extLength - UINT16_SIZE )
			return( CRYPT_ERROR_BADDATA );
		}
	if( keyexListLen < UINT16_SIZE + UINT16_SIZE + 32 || \
		keyexListLen > MAX_TOTAL_KEYEX_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Iterate through the keyex values:
	
		uint16	namedGroup
		uint16	keyexLength
		byte[]	keyexData */
	REQUIRES( !checkOverflowAdd( stell( stream ), keyexListLen ) );
	endPos = stell( stream ) + keyexListLen;
	ENSURES( isIntegerRangeMin( endPos, keyexListLen ) );
	LOOP_SMALL( noKeyexValues = 0, 
				stell( stream ) < endPos - 16 && \
					noKeyexValues < MAX_KEYEX_VALUES, 
				noKeyexValues++ )
		{
		int keyexStartPos DUMMY_INIT, keyexLength DUMMY_INIT;
		int keyexCheckStatus, namedGroup;
		LOOP_INDEX_ALT newGroupIndex;

		ENSURES( LOOP_INVARIANT_SMALL( noKeyexValues, 0, 7 ) );

		/* Read the group ID and keyex data length, remembering where the 
		   keyex data (including the length value) starts */
		status = namedGroup = readUint16( stream );
		if( !cryptStatusError( status ) )
			{
			keyexStartPos = stell( stream );
			status = keyexLength = readUint16( stream );
			}
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "%s sent keyex using group %d (%X), length %d",
					  isServer( sessionInfoPtr ) ? "Client" : "Server",
					  namedGroup, namedGroup, keyexLength ));
		if( keyexLength < 32 || keyexLength > MAX_KEYEX_SIZE )
			{
			/* It's an invalid value, make sure that it's not just Google
			   braindamage.  We check for a length value 1...31 since to get
			   here it must have been < 32.  We also remember that this is
			   Google in order to provide more useful messages about Google
			   braindamage later */
			if( checkGREASE( namedGroup ) && \
				keyexLength >= 1 && keyexLength < 32 )
				{
				status = sSkip( stream, keyexLength, MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return( status );
				isGoogle = TRUE;
				DEBUG_PRINT(( ".\n" ));
				continue;
				}

			return( CRYPT_ERROR_BADDATA );
			}

		/* Check whether this is a more-preferred group than what we've 
		   currently got.  First, we find its position in the preferred-
		   groups array */
		LOOP_MED_ALT( ( newGroupIndex = 0, groupInfoPtr = NULL ), 
					  newGroupIndex < noGroupInfoEntries && \
							groupInfo[ newGroupIndex ].tlsGroupID != TLS_GROUP_NONE,
					  newGroupIndex++ )
			{
			ENSURES( LOOP_INVARIANT_MED_ALT( newGroupIndex, 0, 
											 noGroupInfoEntries - 1 ) );
			
			if( groupInfo[ newGroupIndex ].tlsGroupID == namedGroup )
				{
				groupInfoPtr = &groupInfo[ newGroupIndex ];
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		ENSURES( newGroupIndex <= noGroupInfoEntries );
		DEBUG_PRINT_COND( groupInfoPtr != NULL,
						  ( ", recognised as %s.\n",
							groupInfoPtr->description ) );

		/* If we didn't find a match or haven't found something more 
		   preferred than what we've already got, continue */
		if( groupInfoPtr == NULL || newGroupIndex > groupIndex )
			{
			DEBUG_PRINT_COND( groupInfoPtr == NULL,
							  ( ".\n  Skipping unrecognised keyex using "
							    "%d (%X).\n", namedGroup, namedGroup ) );
			DEBUG_PRINT_COND( groupInfoPtr != NULL,
							  ( "  Skipping less-preferred keyex using "
							    "%s.\n", groupInfoPtr->description ) );
			status = sSkip( stream, keyexLength, MAX_INTLENGTH_SHORT );
			if( cryptStatusError( status ) )
				return( status );
			continue;
			}

		/* Perform any additional algorithm-specific checks: The algorithm 
		   must be available, and the returned keyex has to match what we 
		   sent */
		keyexCheckStatus = CRYPT_OK;
		switch( groupInfoPtr->algorithm )
			{
			case CRYPT_ALGO_ECDH:
				if( !isECDHAvailable )
					{
					keyexCheckStatus = CRYPT_ERROR_NOTAVAIL;
					break;
					}
				if( !isServer( sessionInfoPtr ) && \
					groupInfoPtr->eccCurveID != clientECDHcurve )
					{
					keyexCheckStatus = CRYPT_ERROR_BADDATA;
					break;
					}
				break;
			
			case CRYPT_ALGO_25519:
				if( !isX25519Available )
					{
					keyexCheckStatus = CRYPT_ERROR_NOTAVAIL;
					break;
					}
				if( isPQCGroup( groupInfoPtr->tlsGroupID ) && \
					!algoAvailable( CRYPT_ALGO_MLKEM ) )
					{
					/* The post-magic hybrids require the availability of 
					   two different algorithms */
					keyexCheckStatus = CRYPT_ERROR_NOTAVAIL;
					break;
					}
				break;
			}
		if( cryptStatusError( keyexCheckStatus ) )
			{
			DEBUG_PRINT_COND( groupInfoPtr != NULL,
							  ( "  Skipping keyex using %s %s.\n", 
							    groupInfoPtr->description,
							    ( keyexCheckStatus == CRYPT_ERROR_NOTAVAIL ) ? \
								  "due to algorithm unavailability" : \
								  "since it's not what we asked for" ) );
			status = sSkip( stream, keyexLength, MAX_INTLENGTH_SHORT );
			if( cryptStatusError( status ) )
				return( status );
			continue;
			}

		/* We've filtered out any oversized post-magic keyexes at this point, 
		   check the length validity again against the keyexes that we 
		   understand.  The extra UINT16_SIZE in the check is for the length 
		   field that precedes the keyex data */
		ENSURES( keyexLength >= 32 && keyexLength <= MAX_KEYEX_SIZE );
		REQUIRES( !checkOverflowAdd( UINT16_SIZE, keyexLength ) );
		if( UINT16_SIZE + keyexLength > KEYEX_SECRET_STORAGE_SIZE )
			return( CRYPT_ERROR_BADDATA );

		/* Because of TLS 1.3's stupid splitting of keyex information across 
		   two different extensions we can in theory get preferred keyex 
		   data (via the keyex extension) that differs from the preferred 
		   keyex group (via the supported-groups extension).  Since what 
		   matters is the actual keyex that we get, we allow it to override 
		   the supported-groups value but also warn that this has happened */
		DEBUG_PRINT_COND( handshakeInfo->keyexTls13PrefGroupInfo != NULL && \
						  handshakeInfo->keyexTls13PrefGroupInfo != groupInfoPtr,
						  ( "  Warning: %s advertised their preferred "
						    "group as %s but we prefer %s.\n",
							isServer( sessionInfoPtr ) ? "Client" : "Server",
						    handshakeInfo->keyexTls13PrefGroupInfo->description,
						    groupInfoPtr->description ) );

		/* We've finally go through all the formalities, report what we've 
		   got and remember the keyex group information */
		DEBUG_PRINT_COND( seenKeyex || \
						  handshakeInfo->keyexTls13PrefGroupInfo == NULL || \
						  handshakeInfo->keyexTls13PrefGroupInfo == groupInfoPtr,
						  ( "  Setting keyex to %s, length %d.\n",
						    groupInfoPtr->description, keyexLength ) );
		DEBUG_PRINT_COND( !seenKeyex && \
						  handshakeInfo->keyexTls13GroupInfo != NULL && \
						  handshakeInfo->keyexTls13PrefGroupInfo != groupInfoPtr,
						  ( "  Replacing %s keyex with more preferred %s, "
							"length %d.\n",
						    handshakeInfo->keyexTls13GroupInfo->description,
						    groupInfoPtr->description, keyexLength ) );
		if( isServer( sessionInfoPtr ) )
			{
			/* We're the server, at this point we don't know whether we'll be
			   continuing with TLS classic or TLS 1.3 so we save the keyex 
			   group as the TLS 1.3 group until we can resolve the situation
			   after we've read all of the other extensions */
			handshakeInfo->keyexTls13GroupInfo = groupInfoPtr;
			}
		else
			{
			/* We're the client, there's only one keyex group possible because
			   we asked for it */
			handshakeInfo->keyexGroupInfo = groupInfoPtr;
			}

		/* Make sure that we've got enough data present to continue */
		switch( groupInfoPtr->algorithm )
			{
			case CRYPT_ALGO_DH:
				if( keyexLength < groupInfoPtr->keySize )
					return( CRYPT_ERROR_UNDERFLOW );
				break;
					
			case CRYPT_ALGO_ECDH:
				if( keyexLength < 1 + groupInfoPtr->keySize + \
									  groupInfoPtr->keySize )
					return( CRYPT_ERROR_UNDERFLOW );
				break;

#ifdef USE_X25519
			case CRYPT_ALGO_25519:
  #ifdef USE_MLKEM
				/* ML-KEM is an add-on to 25519 so it's handled under the 
				   25519 option */
				if( isPQCGroup( groupInfoPtr->tlsGroupID ) )
					{
					/* Because of the weird reverse-RSA mechanism used for 
					   ML-KEM the data quantities have different sizes 
					   depending on whether we're the client or server */
					const int mlkemDataSize = isServer( sessionInfoPtr ) ? \
								MLKEM_PUBKEY_SIZE : MLKEM_WRAPPEDKEY_SIZE;
					
					if( keyexLength < mlkemDataSize + X25519_PUBKEY_SIZE )
						return( CRYPT_ERROR_UNDERFLOW );
					}
				else
  #endif /* USE_MLKEM */
					{
					if( keyexLength < groupInfoPtr->keySize )
						return( CRYPT_ERROR_UNDERFLOW );
					}
				break;
#endif /* USE_X25519 */

			default:
				retIntError();
			}

		/* Remember the keyex data including the uint16 value at the start */
		REQUIRES( !checkOverflowAdd( keyexLength, UINT16_SIZE ) );
		keyexLength += UINT16_SIZE;				/* 16-bit length */
		status = sseek( stream, keyexStartPos );
		if( cryptStatusOK( status ) )
			{
			REQUIRES( rangeCheck( keyexLength, UINT16_SIZE + 1, 
								  KEYEX_SECRET_STORAGE_SIZE ) );
			status = sread( stream, handshakeInfo->tls13KeyexValue, 
							keyexLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->tls13KeyexValueLen = keyexLength;
		seenKeyex = TRUE;

		/* Remember the most-preferred value that we've just selected */
		groupIndex = newGroupIndex;
		}
	ENSURES( LOOP_BOUND_OK );
	if( noKeyexValues >= MAX_KEYEX_VALUES )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Excessive number (more than %d) of keyex values "
				  "encountered", noKeyexValues ) );
		}

	/* If we didn't match anything that we can use then we can't continue */
	if( !seenKeyex )
		{
		return( handleNonmatchedKeyex( sessionInfoPtr, handshakeInfo, 
									   isGoogle, extErrorInfoSet ) );
		}
	DEBUG_PRINT_COND( handshakeInfo->keyexGroupInfo != NULL,
					  ( "Final keyex set to %s.\n", 
					    handshakeInfo->keyexGroupInfo->description ) );
	DEBUG_PRINT_COND( handshakeInfo->keyexTls13GroupInfo != NULL,
					  ( "Final TLS 1.3 keyex set to %s.\n", 
					    handshakeInfo->keyexTls13GroupInfo->description ) );
	groupInfoPtr = isServer( sessionInfoPtr ) ? \
						handshakeInfo->keyexTls13GroupInfo : \
						handshakeInfo->keyexGroupInfo;
	handshakeInfo->keyexAlgo = groupInfoPtr->algorithm;

	/* If we're fuzzing, we don't do any of the crypto stuff */
	FUZZ_SKIP_REMAINDER();

	/* If we're the server then we now have the parameters that we need to 
	   set up the DH/ECDH/25519/ML-KEM crypto */
	if( isServer( sessionInfoPtr ) )
		return( initTLS13Keyex( handshakeInfo, groupInfoPtr ) );

	/* We're the client, destroy any contexts from the guessed keyex that 
	   we don't need and move what's left up to make it the actual keyex 
	   context */
	if( groupInfoPtr->algorithm != CRYPT_ALGO_DH && \
		handshakeInfo->keyexContext != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->keyexContext, 
						  IMESSAGE_DECREFCOUNT );
		}
	if( groupInfoPtr->algorithm == CRYPT_ALGO_ECDH )
		handshakeInfo->keyexContext = handshakeInfo->keyexEcdhContext;
	else
		{
		if( isECDHAvailable )
			{
			krnlSendNotifier( handshakeInfo->keyexEcdhContext, 
							  IMESSAGE_DECREFCOUNT );
			}
		}
	handshakeInfo->keyexEcdhContext = CRYPT_ERROR;
#ifdef USE_X25519
	if( groupInfoPtr->algorithm == CRYPT_ALGO_25519 )
		handshakeInfo->keyexContext = handshakeInfo->keyex25519Context;
	else
		{
		if( isX25519Available )
			{
			krnlSendNotifier( handshakeInfo->keyex25519Context, 
							  IMESSAGE_DECREFCOUNT );
			}
		}
	handshakeInfo->keyex25519Context = CRYPT_ERROR;
#endif /* USE_X25519 */
#ifdef USE_MLKEM
	if( !isPQCGroup( groupInfoPtr->tlsGroupID ) && \
		handshakeInfo->keyexAltContext != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->keyexAltContext, 
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->keyexAltContext = CRYPT_ERROR;
		}
#endif /* USE_MLKEM */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeKeyexTLS13( INOUT_PTR STREAM *stream,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					 IN_BOOL const BOOLEAN isServer )
	{
	int ecdhKeySize DUMMY_INIT, ecdhKeyShareSize = 0;
	int x25519KeyShareSize = 0, mlkemKeyShareSize = 0;
	int status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( isServer ) );
#ifdef USE_X25519
	REQUIRES( handshakeInfo->keyexContext != CRYPT_ERROR || \
			  handshakeInfo->keyexEcdhContext != CRYPT_ERROR || \
			  handshakeInfo->keyex25519Context != CRYPT_ERROR );
#else
	REQUIRES( handshakeInfo->keyexContext != CRYPT_ERROR || \
			  handshakeInfo->keyexEcdhContext != CRYPT_ERROR );
#endif /* USE_X25519 */

	/* If we're the server then we're just responding to the client's keyex 
	   with a single keyex value.  Note that the keyDataSize value is a 
	   dummy parameter for the keyex groups that send fixed-size data values
	   (ECDH, 25519) so we don't have to special-case things for groups with
	   variable-size values (DH) */
	if( isServer )
		{
		const TLS_GROUP_INFO *groupInfoPtr = \
						handshakeInfo->keyexGroupInfo;

#if defined( USE_MLKEM ) 
		if( groupInfoPtr->tlsGroupID == TLS_GROUP_X25519MLKEM768 )
			{
			return( writeKeyexMlkem( stream, handshakeInfo, TRUE ) );
			}
#endif /* USE_MLKEM */
		return( writeKeyexData( stream, handshakeInfo->keyexContext, 
								groupInfoPtr->tlsGroupID, 
								groupInfoPtr->keySize ) );
		}

	/* Get the key size for context types that can have varying key lengths.  
	   Because of the unecessary zero-padding requirements we can at least 
	   precompute all of the length values without having to actually look 
	   at the data */
#if 0	/* See comment in session/tls_keyex.c:writeSupportedGroups() */
	if( handshakeInfo->keyexContext != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->keyexContext, 
								  IMESSAGE_GETATTRIBUTE, &dhKeySize,
								  CRYPT_CTXINFO_KEYSIZE );
		}
#endif /* 0 */
	if( handshakeInfo->keyexEcdhContext != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->keyexEcdhContext, 
								  IMESSAGE_GETATTRIBUTE, &ecdhKeySize,
								  CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* We're the client, calculate the size of the encoded form.  The two
	   UINT16 values added to each length are:

		uint16		namedGroup
		uint16		keyexLength

	   followed by the keyex data */
#if 0	/* See comment in session/tls_keyex.c:writeSupportedGroups() */
	if( handshakeInfo->keyexContext != CRYPT_ERROR )
		dhKeyShareSize = UINT16_SIZE + UINT16_SIZE + dhKeySize;
#endif /* 0 */
	if( handshakeInfo->keyexEcdhContext != CRYPT_ERROR )
		{
		ecdhKeyShareSize = UINT16_SIZE + UINT16_SIZE + \
						   1 + ecdhKeySize + ecdhKeySize;
		}
#ifdef USE_X25519
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR )
		{
		x25519KeyShareSize = UINT16_SIZE + UINT16_SIZE + \
							 X25519_PUBKEY_SIZE;
		}
#endif /* USE_X25519 */
#ifdef USE_MLKEM
	if( handshakeInfo->keyexAltContext != CRYPT_ERROR )
		{
		/* The ML-KEM keyex is the ML-KEM public key followed by another 
		   copy of the 25519 keyex value */
		mlkemKeyShareSize = UINT16_SIZE + UINT16_SIZE + \
							MLKEM_PUBKEY_SIZE + X25519_PUBKEY_SIZE;
		}
#endif /* USE_MLKEM */
	ENSURES( isShortIntegerRangeMin( ecdhKeyShareSize + \
									 x25519KeyShareSize + \
									 mlkemKeyShareSize, 32 ) );

	/* Write the keyex wrapper */
	REQUIRES( !checkOverflowAdd3( ecdhKeyShareSize, x25519KeyShareSize,
								  mlkemKeyShareSize ) );
	writeUint16( stream, ecdhKeyShareSize + x25519KeyShareSize + \
						 mlkemKeyShareSize );

	/* Write the DH key share */
#if 0	/* See comment in session/tls_keyex.c:writeSupportedGroups() */
	if( handshakeInfo->keyexContext != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->keyexContext, 
								 TLS_GROUP_FFDHE2048, dhKeySize );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* 0 */

	/* Write the ECDH/25519/MLKEM key shares in preferred-keyex order.  The 
	   keyDataSize value is a dummy parameter for the keyex groups that send 
	   fixed-size data values (ECDH, 25519, ML-KEM) so we don't have to 
	   special-case things for groups with variable-size values (DH) */
#if defined( USE_MLKEM ) && defined( PREFER_MLKEM )
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR && \
		handshakeInfo->keyexAltContext != CRYPT_ERROR )
		{
		status = writeKeyexMlkem( stream, handshakeInfo, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_MLKEM && PREFER_MLKEM */
#if defined( USE_X25519 ) && defined( PREFER_X25519 )
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->keyex25519Context, 
								 TLS_GROUP_X25519, X25519_PUBKEY_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_X25519 && PREFER_X25519 */
	if( handshakeInfo->keyexEcdhContext != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->keyexEcdhContext, 
								 TLS_GROUP_SECP256R1, 
								 1 + ecdhKeySize + ecdhKeySize );
		if( cryptStatusError( status ) )
			return( status );
		}
#if defined( USE_X25519 ) && !defined( PREFER_X25519 )
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->keyex25519Context, 
								 TLS_GROUP_X25519, X25519_PUBKEY_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_X25519 && !PREFER_X25519 */
#if defined( USE_MLKEM ) && !defined( PREFER_MLKEM )
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR && \
		handshakeInfo->keyexAltContext != CRYPT_ERROR )
		{
		status = writeKeyexMlkem( stream, handshakeInfo, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_MLKEM && PREFER_MLKEM */

	return( CRYPT_OK );
	}
#endif /* USE_TLS13 */
