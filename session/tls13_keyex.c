/****************************************************************************
*																			*
*					cryptlib TLS 1.3 Keyex Management						*
*					Copyright Peter Gutmann 2019-2024						*
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
*								Read/Write Keyex Data						*
*																			*
****************************************************************************/

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

   For DH the keyex is the Y value padded out with zeroes to the length of 
   p for no known reason, for ECDH it's the ECC point in X9.62 format with
   a standard 16-bit length as opposed to TLS classic's 8-bit length, and
   for 25519 it's the 32-bit public value */

#define MAX_TOTAL_KEYEX_SIZE	8192
#define MAX_KEYEX_SIZE			2048

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readKeyexTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					INOUT_PTR STREAM *stream, 
					IN_LENGTH_SHORT_Z const int extLength,
					OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	CRYPT_ECCCURVE_TYPE clientECDHcurve = CRYPT_ECCCURVE_NONE;
	const TLS_GROUP_INFO *groupInfo, *groupInfoPtr;
	const BOOLEAN seenPreferredGroups = \
			( handshakeInfo->keyexTls13GroupInfo != NULL ) ? TRUE : FALSE;
	BOOLEAN isECDHAvailable, is25519Available, isGoogle = FALSE;
	BOOLEAN seenKeyex = FALSE;
	int keyexListLen = extLength, groupIndex = 99, endPos;
	int noGroupInfoEntries, status;
	LOOP_INDEX i;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

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
	is25519Available = algoAvailable( CRYPT_ALGO_25519 ) ? TRUE : FALSE;
	if( !isServer( sessionInfoPtr ) )
		{
#if 0	/* See comment in session/tls_ext_rw.c:writeSupportedGroups() */
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
#ifdef USE_25519
		if( handshakeInfo->keyex25519Context == CRYPT_ERROR )
			is25519Available = FALSE;
#else
		is25519Available = FALSE;
#endif /* USE_25519 */
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
		if( keyexListLen != extLength - UINT16_SIZE )
			return( CRYPT_ERROR_BADDATA );
		}
	if( keyexListLen < UINT16_SIZE + UINT16_SIZE + 32 || \
		keyexListLen > MAX_TOTAL_KEYEX_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Iterate through the keyex values */
	endPos = stell( stream ) + keyexListLen;
	ENSURES( isIntegerRangeMin( endPos, keyexListLen ) );
	LOOP_SMALL( i = 0, stell( stream ) < endPos - 16 && i < 8, i++ )
		{
		int keyexStartPos DUMMY_INIT, keyexLength DUMMY_INIT;
		int keyexCheckStatus, namedGroup;
		LOOP_INDEX_ALT newGroupIndex;

		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 7 ) );

		/* Read the group ID and keyex data length */
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
		LOOP_SMALL_ALT( ( newGroupIndex = 0, groupInfoPtr = NULL ), 
						newGroupIndex < noGroupInfoEntries && \
							groupInfo[ newGroupIndex ].tlsGroupID != TLS_GROUP_NONE,
						newGroupIndex++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL_ALT( newGroupIndex, 0, 
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
			
#ifdef USE_25519
			case CRYPT_ALGO_25519:
				if( !is25519Available )
					{
					keyexCheckStatus = CRYPT_ERROR_NOTAVAIL;
					break;
					}
				break;
#endif /* USE_25519 */
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

		/* We've now filtered out any oversized post-magic keyexes, check the
		   length validity again against standard keyexes.  The extra 
		   UINT16_SIZE in the check is for the length field that precedes the
		   keyex data */
		if( UINT16_SIZE + keyexLength > CRYPT_MAX_PKCSIZE + \
										CRYPT_MAX_TEXTSIZE )
			return( CRYPT_ERROR_BADDATA );

		/* Because of TLS 1.3's stupid splitting of keyex information across 
		   two different extensions we can in theory get preferred keyex 
		   data (via the keyex extension) that differs from the preferred 
		   keyex group (via the supported-groups extension).  Since what 
		   matters is the actual keyex that we get, we allow it to override 
		   the supported-groups value but also warn that this has happened */
		if( seenPreferredGroups )
			{
			DEBUG_PRINT_COND( handshakeInfo->keyexTls13GroupInfo != groupInfoPtr,
							  ( "  Warning: %s sent more-preferred keyex %s "
							    "but advertised preferred keyex group %s.\n",
								isServer( sessionInfoPtr ) ? "Client" : "Server",
							    groupInfoPtr->description, 
							    handshakeInfo->keyexTls13GroupInfo->description ) );
			}

		/* Remember the keyex data including the length value at the start */
		DEBUG_PRINT_COND( handshakeInfo->keyexTls13GroupInfo == NULL || \
						  ( seenPreferredGroups && \
						    handshakeInfo->keyexTls13GroupInfo == groupInfoPtr ),
						  ( "  Setting keyex to %s, length %d.\n",
						    groupInfoPtr->description, keyexLength ) );
		DEBUG_PRINT_COND( !( handshakeInfo->keyexTls13GroupInfo == NULL || \
							 ( seenPreferredGroups && \
							   handshakeInfo->keyexTls13GroupInfo == groupInfoPtr ) ),
						  ( "  Replacing %s keyex with more preferred %s, "
							"length %d.\n",
						    handshakeInfo->keyexTls13GroupInfo->description,
						    groupInfoPtr->description, keyexLength ) );
		handshakeInfo->keyexTls13GroupInfo = groupInfoPtr;
		keyexLength += UINT16_SIZE;				/* 16-bit length */
		status = sseek( stream, keyexStartPos );
		if( cryptStatusOK( status ) )
			{
			REQUIRES( rangeCheck( keyexLength, 1, 
								  CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE ) );
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

	/* If we didn't match anything that we can use then we can't continue */
	if( !seenKeyex )
		{
		/* Google Chrome doesn't send any MTI keyexes in its first client
		   hello, which forces a retry on every connect.  If this isn't 
		   already a retry, tell the caller to add an extra round trip and
		   more crypto computations for make benefit Google braindamage */
		if( isServer( sessionInfoPtr ) && \
			!( handshakeInfo->flags & HANDSHAKE_FLAG_RETRIEDCLIENTHELLO ) )
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
			   P256 keyex in its client hello so once we've fallen we can't 
			   get up any more */
			retExt( CRYPT_ERROR_NOTAVAIL,
					( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
					  "Google Chrome doesn't support the mandatory ECDH "
					  "P256 key exchange in its client handshake, can't "
					  "continue" ) );
			}
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "Couldn't find a supported keyex type in %s's handshake "
				  "message",
				  isServer( sessionInfoPtr ) ? "client" : "server" ) );
		}
	DEBUG_PRINT_COND( handshakeInfo->keyexGroupInfo != NULL,
					  ( "Final keyex set to %s.\n", 
					    handshakeInfo->keyexGroupInfo->description ) );
	DEBUG_PRINT_COND( handshakeInfo->keyexTls13GroupInfo != NULL,
					  ( "Final TLS 1.3 keyex set to %s.\n", 
					    handshakeInfo->keyexTls13GroupInfo->description ) );
	groupInfoPtr = handshakeInfo->keyexTls13GroupInfo;
	handshakeInfo->keyexAlgo = groupInfoPtr->algorithm;

	/* If we're fuzzing, we don't do any of the crypto stuff */
	FUZZ_SKIP_REMAINDER();

	/* If we're the server then we now have the parameters that we need to 
	   set up the DH/ECDH/25519 crypto */
	if( isServer( sessionInfoPtr ) )
		{
		status = createKeyexContextTLS( &handshakeInfo->keyexContext, 
										groupInfoPtr->algorithm );
		if( cryptStatusError( status ) )
			return( status );
		switch( groupInfoPtr->algorithm )
			{
			case CRYPT_ALGO_DH:
				{
				/* For DH we have to indicate that we're using the 
				   nonstandard parameters required by TLS 1.3 */
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

#ifdef USE_25519
			case CRYPT_ALGO_25519:
				status = krnlSendMessage( handshakeInfo->keyexContext,
										  IMESSAGE_SETATTRIBUTE, 
										  MESSAGE_VALUE_TRUE, 
										  CRYPT_IATTRIBUTE_KEY_IMPLICIT );
				break;

#endif /* USE_25519 */

			default:
				retIntError();
			}

		return( status );
		}

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
#ifdef USE_25519
	if( groupInfoPtr->algorithm == CRYPT_ALGO_25519 )
		handshakeInfo->keyexContext = handshakeInfo->keyex25519Context;
	else
		{
		if( is25519Available )
			{
			krnlSendNotifier( handshakeInfo->keyex25519Context, 
							  IMESSAGE_DECREFCOUNT );
			}
		}
	handshakeInfo->keyex25519Context = CRYPT_ERROR;
#endif /* USE_25519 */
	handshakeInfo->keyexEcdhContext = CRYPT_ERROR;

	return( CRYPT_OK );
	}

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

	/* Perform Phase 1 of the DH/ECDH/25519 keyex */
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

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeKeyexTLS13( INOUT_PTR STREAM *stream,
					 const TLS_HANDSHAKE_INFO *handshakeInfo,
					 IN_BOOL const BOOLEAN isServer )
	{
	int ecdhKeySize DUMMY_INIT, ecdhKeyShareSize = 0;
	int x25519KeyShareSize = 0, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( isServer ) );
#ifdef USE_25519
	REQUIRES( handshakeInfo->keyexContext != CRYPT_ERROR || \
			  handshakeInfo->keyexEcdhContext != CRYPT_ERROR || \
			  handshakeInfo->keyex25519Context != CRYPT_ERROR );
#else
	REQUIRES( handshakeInfo->keyexContext != CRYPT_ERROR || \
			  handshakeInfo->keyexEcdhContext != CRYPT_ERROR );
#endif /* USE_25519 */

	/* Get the key size for context types that can have varying key lengths.  
	   Because of the unecessary zero-padding requirements we can at least 
	   precompute all of the length values without having to actually look 
	   at the data */
#if 0	/* See comment in session/tls_ext_rw.c:writeSupportedGroups() */
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

	/* If we're the server then we're just responding to the client's keyex 
	   with a single keyex value.  Note that the keyDataSize value is a 
	   dummy parameter for the keyex groups that send fixed-size data values
	   (ECDH, 25519) so we don't have to special-case things for groups with
	   variable-size values (DH) */
	if( isServer )
		{
		const TLS_GROUP_INFO *groupInfoPtr = \
						handshakeInfo->keyexGroupInfo;

		return( writeKeyexData( stream, handshakeInfo->keyexContext, 
								groupInfoPtr->tlsGroupID, 
								groupInfoPtr->keySize ) );
		}

	/* We're the client, calculate the size of the encoded form.  The two
	   UINT16 values added to each length are:

		uint16		namedGroup
		uint16		keyexLength

	   followed by the keyex data */
#if 0	/* See comment in session/tls_ext_rw.c:writeSupportedGroups() */
	if( handshakeInfo->keyexContext != CRYPT_ERROR )
		dhKeyShareSize = UINT16_SIZE + UINT16_SIZE + dhKeySize;
#endif /* 0 */
	if( handshakeInfo->keyexEcdhContext != CRYPT_ERROR )
		{
		ecdhKeyShareSize = UINT16_SIZE + UINT16_SIZE + \
						   1 + ecdhKeySize + ecdhKeySize;
		}
#ifdef USE_25519
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR )
		x25519KeyShareSize = UINT16_SIZE + UINT16_SIZE + 32;
#endif /* USE_25519 */
	ENSURES( isShortIntegerRangeMin( ecdhKeyShareSize + \
									 x25519KeyShareSize, 32 ) );

	/* We're the client and potentially sending a list of keyex values,
	   write the keyex wrapper */
	writeUint16( stream, ecdhKeyShareSize + x25519KeyShareSize );

	/* Write the DH key share */
#if 0	/* See comment in session/tls_ext_rw.c:writeSupportedGroups() */
	if( handshakeInfo->keyexContext != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->keyexContext, 
								 TLS_GROUP_FFDHE2048, dhKeySize );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* 0 */

	/* Write the ECDH/25519 key shares in preferred-keyex order.  Note that 
	   the keyDataSize value is a dummy parameter for the keyex groups that 
	   send fixed-size data values (ECDH, 25519) so we don't have to special-
	   case things for groups with variable-size values (DH) */
#if defined( USE_25519 ) && defined( PREFER_25519 )
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->keyex25519Context, 
								 TLS_GROUP_X25519, 32 );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_25519 && PREFER_25519 */
	if( handshakeInfo->keyexEcdhContext != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->keyexEcdhContext, 
								 TLS_GROUP_SECP256R1, 
								 1 + ecdhKeySize + ecdhKeySize );
		if( cryptStatusError( status ) )
			return( status );
		}
#if defined( USE_25519 ) && !defined( PREFER_25519 )
	if( handshakeInfo->keyex25519Context != CRYPT_ERROR )
		{
		status = writeKeyexData( stream, handshakeInfo->keyex25519Context, 
								 TLS_GROUP_X25519, 32 );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_25519 && !PREFER_25519 */

	return( CRYPT_OK );
	}
#endif /* USE_TLS13 */
