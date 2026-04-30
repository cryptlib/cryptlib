/****************************************************************************
*																			*
*						cryptlib TLS Keyex Management						*
*					 Copyright Peter Gutmann 1998-2025						*
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

#ifdef USE_TLS

/* Notify if custom preferences for algorithm use */

#if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
  #ifdef PREFER_ECC
	#pragma message( "  Building with ECC preferred for TLS." )
  #endif /* Notify preferred ECC use */
  #ifdef PREFER_X25519
	#pragma message( "  Building with X25519 preferred for TLS." )
  #endif /* Notify preferred X25519 use */
  #ifdef PREFER_MLKEM 
	#pragma message( "  Building with ML-KEM preferred for TLS." )
  #endif /* Notify preferred ML-KEM use */
#endif /* Compilers with message support */

/****************************************************************************
*																			*
*								Init Functions								*
*																			*
****************************************************************************/

/* Load a DH/ECDH/25519/ML-KEM key into a context.  Note that 
   initDHcontextTLS() doesn't handle 25519 or ML-KEM since this is a TLS 1.3 
   algorithm and that handles its keyex by stuffing the data into the 
   client/server hello rather than sending a proper client/server keyex 
   message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createKeyexContextTLS( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
						   IN_ALGO const CRYPT_ALGO_TYPE keyexAlgo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );

	REQUIRES( keyexAlgo == CRYPT_ALGO_DH || keyexAlgo == CRYPT_ALGO_ECDH || \
			  keyexAlgo == CRYPT_ALGO_25519 || \
			  keyexAlgo == CRYPT_ALGO_MLKEM );

	/* If we're fuzzing the input then we don't need to go through any of 
	   the following crypto calisthenics */
	FUZZ_SKIP_REMAINDER();

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	/* Create the keyex context.  We have to use distinct algorithm-specific 
	   labels because for client-side TLS 1.3 we need to create multiple 
	   contexts when we're guessing at what algorithm the other side might 
	   want */
	setMessageCreateObjectInfo( &createInfo, keyexAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	switch( keyexAlgo )
		{
		case CRYPT_ALGO_DH:
			setMessageData( &msgData, "TLS DH key agreement key", 24 );
			break;
		
		case CRYPT_ALGO_ECDH:
			setMessageData( &msgData, "TLS ECDH key agreement key", 26 );
			break;
		
		case CRYPT_ALGO_25519:
			setMessageData( &msgData, "TLS 25519 key agreement key", 27 );
			break;

		case CRYPT_ALGO_MLKEM:
			setMessageData( &msgData, "TLS ML-KEM key agreement key", 28 );
			break;

		default:
			retIntError();
		}
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initKeyexContextTLS( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
						 IN_BUFFER_OPT( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT_Z const int keyDataLength,
						 IN_HANDLE_OPT \
							const CRYPT_CONTEXT iServerKeyTemplate,
						 IN_ENUM_OPT( CRYPT_ECCCURVE ) \
							const CRYPT_ECCCURVE_TYPE eccCurve,
						 IN_BOOL const BOOLEAN isTLSLTS )
	{
	CRYPT_CONTEXT keyexContext;
	int keySize = TLS_DH_KEYSIZE, status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( ( keyData == NULL && keyDataLength == 0 ) || \
			isReadPtrDynamic( keyData, keyDataLength ) );

	REQUIRES( ( keyData == NULL && keyDataLength == 0 ) || \
			  ( keyData != NULL && \
				isShortIntegerRangeNZ( keyDataLength ) ) );
	REQUIRES( iServerKeyTemplate == CRYPT_UNUSED || \
			  isHandleRangeValid( iServerKeyTemplate ) );
	REQUIRES( isEnumRangeOpt( eccCurve, CRYPT_ECCCURVE ) );
	REQUIRES( isBooleanValue( isTLSLTS ) );

	/* If we're fuzzing the input then we don't need to go through any of 
	   the following crypto calisthenics */
	FUZZ_SKIP_REMAINDER();

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	/* If we're loading a built-in DH key, match the key size to the server 
	   authentication key size.  If there's no server key present then we 
	   default to the TLS_DH_KEYSIZE-byte key (the default value set earlier 
	   for the keySize variable) because we don't know how much processing 
	   power the client has */
	if( keyData == NULL && iServerKeyTemplate != CRYPT_UNUSED && \
		eccCurve == CRYPT_ECCCURVE_NONE )
		{
		status = krnlSendMessage( iServerKeyTemplate, IMESSAGE_GETATTRIBUTE,
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Create the DH/ECDH context.  This is never 25519 or ML-KEM for the 
	   reason given in the comment at the start of this section */
	status = createKeyexContextTLS( &keyexContext, 
									( eccCurve != CRYPT_ECCCURVE_NONE ) ? \
									  CRYPT_ALGO_ECDH : CRYPT_ALGO_DH );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the key into the context.  If we're being given externally-
	   supplied DH/ECDH key components, load them, otherwise use the built-
	   in key */
	if( keyData != NULL )
		{
		MESSAGE_DATA msgData;

		/* If we're the client we'll have been sent DH/ECDH key components 
		   by the server */
		setMessageData( &msgData, ( MESSAGE_CAST ) keyData, keyDataLength ); 
		status = krnlSendMessage( keyexContext, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, 
								  isTLSLTS ? CRYPT_IATTRIBUTE_KEY_TLS_EXT : \
											 CRYPT_IATTRIBUTE_KEY_TLS );
		}
	else
		{
#ifdef USE_ECDH 
		/* If we've been given ECC parameter information then we're using
		   ECDH */
		if( eccCurve != CRYPT_ECCCURVE_NONE )
			{
			const int eccParams = eccCurve;	/* int vs. enum */

			status = krnlSendMessage( keyexContext, IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &eccParams, 
									  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
			}
		else
#endif /* USE_ECDH */
			{
			/* We're loading a standard DH key of the appropriate size */
			status = krnlSendMessage( keyexContext, IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &keySize, 
									  CRYPT_IATTRIBUTE_KEY_DLPPARAM );
			}
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( keyexContext, IMESSAGE_DECREFCOUNT );
		if( keyData == NULL )
			{
			/* If we got an error loading a known-good, fixed-format key 
			   then we report the problem as an internal error rather than 
			   (say) a bad-data error */
			retIntError();
			}
		return( status );
		}
	*iCryptContext = keyexContext;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read/Write Preferred Groups						*
*																			*
****************************************************************************/

/* Preferred (or at least supported) keyex groups, formerly ECC named curves.  
   For the pre-TLS 1.3 case this is a somewhat problematic extension because 
   it applies to any use of ECC, so if (for some reason) the server wants to 
   use a P256 ECDH key with a P521 ECDSA signing key then it has to verify 
   that the client reports that it supports both P256 and P521.  Since our 
   limiting factor is the ECDSA key that we use for signing, we require that 
   the client report support for the curve that matches our signing key.  
   Support for the corresponding ECDH curve is automatic since we support 
   all curves for ECDH that are supported for ECDSA.  However we also have
   to make sure that the corresponding SHA-2 fashion statement is available,
   since we can't sign, for example, SHA2-256 with P521.

   This one-size-fits-all mess leads to a second problem and that's if we're 
   using a non-ECC server key.  In this case we have a preferred curve for 
   ECDH (keyex) but not for ECDSA (server signing key), leading to the 
   following set of possibilities:

				  Private key
	Keyex		ECDSA			RSA			Result
	------		-----			---			------
	DH			-				Yes		->	DH + RSA
	ECDH (any)	-				Yes		->	ECDH + RSA
	ECDH (any)	Yes + match		-		->	ECDH + ECDSA
	25519		-				Yes		->	25519 + RSA
	25519		Yes + match		-		->	25519 + ECDSA

   What this means in terms of matching is that if a non-ECC server key is
   present then we match any curve that we support for the ECC keyex part, 
   if an ECC server key is present then we look for a match for the server 
   key for the signing part and also apply that to the keyex part.

   For TLS 1.3, alongside changing the name from named curves to supported
   groups since it now includes DH values, the interpretation was changed so 
   that there's now a separate extension for signature algorithms so that 
   this applies purely to keyex groups.  However this isn't useful when 
   sending the thing as a client because we have no idea whether we'll be 
   talking TLS 1.3 (which has the signature algorithms extension) or TLS 
   not-1.3 (which doesn't) at that point.
   
   In addition since a TLS 1.3 client encodes the keyex algorithm in the 
   key_share extension that's stuffed into the client hello there's no point 
   in sending this extension because all it can do is duplicate the 
   information already present in the key_share extension, which is non-
   negotiable since it's required for the keyex to work.  TLS 1.3 also 
   requires (RFC 8446 section 4.2.8.0) that "Clients MUST NOT offer any 
   KeyShareEntry values for groups not listed in the client's 
   supported_groups extension", so we have to send this extension even 
   though there's no point to it (the PSK extensions work similarly, 
   clients have to send psk_key_exchange_modes in order to send a 
   pre_shared_key extension, another "fix" for a problem that probably 
   doesn't exist in which the client can advertise support for which PSK 
   modes it supports even though the PSK data is then included right next 
   to the modes data).
   
   Complicating the mess even further is the fact that, since TLS 1.3 allows 
   extensions to be sent in any order and the same information is 
   distributed across two of them, we may not know what groups are indicated 
   when we see the keyex or vice versa, or whether we're even going to be 
   running TLS 1.3 at the end of it all because the actual TLS version is 
   another can-appear-anywhere extension (admittedly it'd be odd to send TLS 
   1.3 keyex extensions but not request TLS 1.3 but there's bound to be 
   someone who has a special use-case that requires it).

   To try and reconcile this chaos we apply the following flow, showing 
   the behaviour with both the keyex first and preferred-groups first:

	keyex1.3 first:
		store 1.3 preferred group + keyex;	
			// keyex1.3 is TLS 1.3 only so it must be a 1.3 preferred group

	preferred_groups:
		store preferred group;
		if( no 1.3 preferred group from keyex && TLS 1.3 group )
			store 1.3 preferred group;
			set 1.3-preferred flag = TRUE;

		Finally:
		if( 1.3 preferred group not set )
			set 1.3 preferred group = preferred group;	
					// TLS 1.3 is a superset of TLS 1.2

	keyex1.3 second:
		if( 1.3 preferred group seen && \
			1.3 preferred group != new preferred group )
			warn;
		store 1.3 preferred group + keyex;	
			// keyex1.3 is TLS 1.3 only so it must be a 1.3 preferred group

	Once hello is processed:
		if( 1.3-preferred flag == TRUE )
			set preferred group = 1.3 preferred group;
		set 1.3 preferred group = NULL;
   
   As part of the overloading of the former named curves extension, TLS 1.3
   now sends DHE group identifiers in the supported groups extension a la
   SSH circa 1996.  However TLS 1.3 has ECC as MTI so it's unlikely that
   anything will do DHE when ECDHE is mandatory, so we omit sending the DHE
   identifiers in order to avoid also sending the DHE keyex values stuffed
   into an extension only to have them discarded by the server.
   
   Because of all this we treat it as having the pre-1.3 semantics:

	uint16		supportedGroupListLength
	uint16[]	supportedGroup */

static const TLS_GROUP_INFO groupInfoTbl[] = {
#if defined( USE_MLKEM ) && defined( PREFER_MLKEM )
	/* ML-KEM is actually a composite consisting of 25519+ML-KEM, we
	   identify it as 25519, which is what's doing all the work, and then
	   check for isPQCGroup( tlsGroupID ) to see whether we need to add
	   ML-KEM as well.  Also the key size value isn't really correct since
	   it's either MLKEM_PUBKEY_SIZE or MLKEM_WRAPPEDKEY_SIZE depending on
	   the situation but this doesn't matter here because the composite
	   nature of the data value and the fact that there's no structure to
	   it means that the code that works with it has to hardcode in the
	   correct length information explicitly */
	{ TLS_GROUP_X25519MLKEM768, CRYPT_ALGO_25519 /*CRYPT_ALGO_MLKEM*/, CRYPT_ECCCURVE_NONE,
	  DESCRIPTION( "X25519/MLKEM768" ) MLKEM_PUBKEY_SIZE + X25519_PUBKEY_SIZE, 
	  TLS_MINOR_VERSION_TLS13, TRUE },
#endif /* USE_MLKEM && PREFER_MLKEM */
#if defined( USE_X25519 ) && defined( PREFER_X25519 ) 
	{ TLS_GROUP_X25519, CRYPT_ALGO_25519, CRYPT_ECCCURVE_NONE,
	  DESCRIPTION( "X25519" ) bitsToBytes( 256 ), 
	  TLS_MINOR_VERSION_TLS13, TRUE },
#endif /* USE_X25519 && PREFER_X25519 */
	{ TLS_GROUP_SECP256R1, CRYPT_ALGO_ECDH, CRYPT_ECCCURVE_P256,
	  DESCRIPTION( "ECDH P256" ) bitsToBytes( 256 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
	{ TLS_GROUP_BRAINPOOLP256R1, CRYPT_ALGO_ECDH, 
	  CRYPT_ECCCURVE_BRAINPOOL_P256, 
	  DESCRIPTION( "Brainpool P256" ) bitsToBytes( 256 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
#ifdef USE_SHA2_EXT
	{ TLS_GROUP_SECP384R1, CRYPT_ALGO_ECDH, CRYPT_ECCCURVE_P384, 
	  DESCRIPTION( "ECDH P384" ) bitsToBytes( 384 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE  },
	{ TLS_GROUP_SECP521R1, CRYPT_ALGO_ECDH, CRYPT_ECCCURVE_P521, 
	  DESCRIPTION( "ECDH P521" ) bitsToBytes( 521 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
	{ TLS_GROUP_BRAINPOOLP384R1, CRYPT_ALGO_ECDH, 
	  CRYPT_ECCCURVE_BRAINPOOL_P384, 
	  DESCRIPTION( "Brainpool P384" ) bitsToBytes( 384 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
	{ TLS_GROUP_BRAINPOOLP512R1, CRYPT_ALGO_ECDH, 
	  CRYPT_ECCCURVE_BRAINPOOL_P512,
	  DESCRIPTION( "Brainpool P512" ) bitsToBytes( 512 ), 
	  TLS_MINOR_VERSION_TLS12, TRUE },
#endif /* USE_SHA2_EXT */
	{ TLS_GROUP_FFDHE2048, CRYPT_ALGO_DH, CRYPT_ECCCURVE_NONE, 
	  DESCRIPTION( "DH 2048" ) bitsToBytes( 2048 ), 
	  TLS_MINOR_VERSION_TLS13, FALSE  },
	{ TLS_GROUP_FFDHE3072, CRYPT_ALGO_DH, CRYPT_ECCCURVE_NONE, 
	  DESCRIPTION( "DH 3072" ) bitsToBytes( 3072 ), 
	  TLS_MINOR_VERSION_TLS13, FALSE },
/*	{ TLS_GROUP_FFDHE4096, CRYPT_ALGO_DH,	// Pointlessly large group 
	  CRYPT_ECCCURVE_NONE,
	  DESCRIPTION( "FFDHE4096" ) bitsToBytes( 4096 ), 
	  TLS_MINOR_VERSION_TLS11, FALSE }, */
#if defined( USE_MLKEM ) && !defined( PREFER_MLKEM )
	{ TLS_GROUP_X25519MLKEM768, CRYPT_ALGO_25519 /*CRYPT_ALGO_MLKEM*/, CRYPT_ECCCURVE_NONE,
	  DESCRIPTION( "X25519/MLKEM768" ) MLKEM_PUBKEY_SIZE + X25519_PUBKEY_SIZE, 
	  TLS_MINOR_VERSION_TLS13, TRUE },
#endif /* USE_MLKEM && !PREFER_MLKEM */
#if defined( USE_X25519 ) && !defined( PREFER_X25519 ) 
	{ TLS_GROUP_X25519, CRYPT_ALGO_25519, CRYPT_ECCCURVE_NONE, 
	  DESCRIPTION( "X25519" ) bitsToBytes( 256 ), 
	  TLS_MINOR_VERSION_TLS13, TRUE },
#endif /* USE_X25519 && !PREFER_X25519 */
	{ TLS_GROUP_NONE, 0 }, { TLS_GROUP_NONE, 0 }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getTLSGroupInfo( OUT_PTR_PTR const TLS_GROUP_INFO **groupInfoPtrPtr,
					 OUT_INT_Z int *noGroupInfoEntries )
	{
	assert( isReadPtr( groupInfoPtrPtr, sizeof( TLS_GROUP_INFO * ) ) );
	assert( isWritePtr( noGroupInfoEntries, sizeof( int ) ) );

	*groupInfoPtrPtr = groupInfoTbl;
	*noGroupInfoEntries = FAILSAFE_ARRAYSIZE( groupInfoTbl, TLS_GROUP_INFO );

	return( CRYPT_OK );
	}

CHECK_RETVAL_PTR \
const TLS_GROUP_INFO *getTLSGroupInfoEntry( IN_ENUM( TLS_GROUP ) \
												const TLS_GROUP_TYPE groupType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( groupType, TLS_GROUP ) );

	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( groupInfoTbl, TLS_GROUP_INFO ) && \
					groupInfoTbl[ i ].tlsGroupID != TLS_GROUP_NONE,
			  i++ )
		{
		ENSURES_N( \
			LOOP_INVARIANT_MED( i, 0, 
								FAILSAFE_ARRAYSIZE( groupInfoTbl, \
													TLS_GROUP_INFO ) - 1 ) );

		if( groupInfoTbl[ i ].tlsGroupID == groupType )
			return( &groupInfoTbl[ i ] );
		}
	ENSURES_N( LOOP_BOUND_OK );

	retIntError_Null();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readSupportedGroups( INOUT_PTR STREAM *stream, 
						 INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
						 IN_LENGTH_SHORT_Z const int extLength,
						 OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	const TLS_GROUP_INFO *preferredGroupInfoPtr = NULL;
#ifdef USE_TLS13
	const TLS_GROUP_INFO *preferredTls13GroupInfoPtr = NULL;
#endif /* USE_TLS13 */
	int serverKeySize DUMMY_INIT, listLen, status;
#ifdef CONFIG_SUITEB_TESTS 
	int curvesSeen = 0;
#endif /* CONFIG_SUITEB_TESTS */
	LOOP_INDEX noSupportedGroups;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( extErrorInfoSet, sizeof( BOOLEAN ) ) );

	REQUIRES( isServer( sessionInfoPtr ) );
	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*extErrorInfoSet = FALSE;

	/* We're the server, the caller has guaranteed that we've got a minimum-
	   length extension present */
	ENSURES( isShortIntegerRangeMin( extLength, 
									 UINT16_SIZE + UINT16_SIZE ) );

	/* Read and check the supported groups list header */
	status = listLen = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( !checkOverflowSub( extLength, UINT16_SIZE ) );
	if( listLen != extLength - UINT16_SIZE || \
		listLen < UINT16_SIZE || listLen > ( 32 * UINT16_SIZE ) || \
		( listLen % UINT16_SIZE ) != 0 )
		return( CRYPT_ERROR_BADDATA );

	/* If there's no server private key present (so we're using PSK suites), 
	   skip the extension */
	if( sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		handshakeInfo->disableECC = TRUE;
		return( sSkip( stream, listLen, MAX_INTLENGTH_SHORT ) );
		}

	/* Get the size of the server's signing key */
	status = krnlSendMessage( sessionInfoPtr->privateKey,
							  IMESSAGE_GETATTRIBUTE, &serverKeySize,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the list of supported groups, recording the most preferred 
	   one */
	REQUIRES( !checkOverflowDiv( listLen, UINT16_SIZE ) );
	LOOP_EXT( noSupportedGroups = 0, 
			  noSupportedGroups < listLen / UINT16_SIZE, 
			  noSupportedGroups++, ( 32 * UINT16_SIZE ) + 1 )
		{
		const TLS_GROUP_INFO *groupInfoPtr;
		int value;
		LOOP_INDEX_ALT groupInfoIndex;

		ENSURES( LOOP_INVARIANT_EXT( noSupportedGroups, 0, 
									 ( listLen / UINT16_SIZE ) - 1, 
									 ( 32 * UINT16_SIZE ) + 1 ) );

		status = value = readUint16( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( !isEnumRange( value, TLS_GROUP ) )
			{
			/* We don't print "Client" or "Server" for this since it's 
			   already been printed for the extension as a whole */
			DEBUG_PRINT(( "Offered unknown keyex group %d (%X), "
						  "continuing.\n", value, value ));
			continue;	/* Unrecognised keyex type type */
			}
		LOOP_MED_ALT( ( groupInfoIndex = 0, groupInfoPtr = NULL ),
					  groupInfoIndex < FAILSAFE_ARRAYSIZE( groupInfoTbl, \
														   TLS_GROUP_INFO ) && \
							groupInfoTbl[ groupInfoIndex ].tlsGroupID != TLS_GROUP_NONE,
					  groupInfoIndex++ )
			{
			ENSURES( \
				LOOP_INVARIANT_MED_ALT( groupInfoIndex, 0, 
										FAILSAFE_ARRAYSIZE( groupInfoTbl, \
															TLS_GROUP_INFO ) - 1 ) );

			if( groupInfoTbl[ groupInfoIndex ].tlsGroupID == value )
				{
				groupInfoPtr = &groupInfoTbl[ groupInfoIndex ];
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		if( groupInfoPtr == NULL )
			{
			DEBUG_PRINT(( "  Skipping unsupported keyex group %d (%X).\n", 
						 value, value ));
			continue;	/* Unrecognised keyex type */
			}
		if( !algoAvailable( groupInfoPtr->algorithm ) )
			{
			DEBUG_PRINT(( "Skipping keyex group %d (%s) due to algorithm "
						  "unavailability.\n", value, 
						  groupInfoPtr->description ));
			continue;	/* Algorithm unavailable */
			}
		if( isPQCGroup( groupInfoPtr->tlsGroupID ) && \
			!algoAvailable( CRYPT_ALGO_MLKEM ) )
			{
			DEBUG_PRINT(( "Skipping keyex group %d (%s) due to secondary "
						  "algorithm ML-KEM unavailability.\n", value, 
						  groupInfoPtr->description ));
			continue;	/* Secondary algorithm unavailable */
			}
		DEBUG_PRINT(( "Offered keyex group %d (%s).\n", value, 
					  groupInfoPtr->description ));
#ifdef CONFIG_SUITEB
		if( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
			{
			const int suiteBinfo = \
						sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;

			/* Suite B only allows P256 and P384.  At the 128-bit level both 
			   P256 and P384 are allowed, at the 256-bit level only P384 is 
			   allowed */
			if( groupInfoPtr->eccCurveID != CRYPT_ECCCURVE_P256 && \
				groupInfoPtr->eccCurveID != CRYPT_ECCCURVE_P384 )
				continue;
			if( suiteBinfo == TLS_PFLAG_SUITEB_256 && \
				groupInfoPtr->eccCurveID == CRYPT_ECCCURVE_P256 )
				continue;
  #ifdef CONFIG_SUITEB_TESTS 
			if( suiteBTestValue == SUITEB_TEST_BOTHCURVES )
				{
				/* We're checking whether the client sends both curve IDs, 
				   remember which ones we've seen so far */
				if( groupInfoPtr->eccCurveID == CRYPT_ECCCURVE_P256 )
					curvesSeen |= 1;
				if( groupInfoPtr->eccCurveID == CRYPT_ECCCURVE_P384 )
					curvesSeen |= 2;
				}
  #endif /* CONFIG_SUITEB_TESTS */
			}
#endif /* CONFIG_SUITEB */

		/* If we're not using an ECC server key then any curve that we 
		   support is OK, otherwise we have to make sure that the requested 
		   curve matches the key */
		if( sessionInfoPtr->privateKeyAlgo == CRYPT_ALGO_ECDSA && \
			groupInfoPtr->keySize != serverKeySize )
			continue;

		/* Because we can have both TLS classic and TLS 1.3 preferred groups 
		   and won't know which one we need to use until we know whether 
		   we're talking classic or 1.3, we record the most-preferred group 
		   here for later use when we process the keyex, if we haven't 
		   already done so */
#ifdef USE_TLS13
		if( handshakeInfo->keyexTls13PrefGroupInfo == NULL )
			handshakeInfo->keyexTls13PrefGroupInfo = groupInfoPtr;
#endif /* USE_TLS13 */

		/* We've got a matching algorithm and/or curve and there's not 
		   already a better one selected, remember it.  Note that this will 
		   select the client's preferred algorithm rather than our one, so 
		   if the client proposes 25519 before they propose P256 then that's 
		   what'll get selected rather than the MTI P256 */
		if( preferredGroupInfoPtr == NULL && \
			groupInfoPtr->minTlsVersion <= TLS_MINOR_VERSION_TLS12 )
			{
			DEBUG_PRINT(( "  Set preferred keyex group to %s.\n", 
						  groupInfoPtr->description ));
			preferredGroupInfoPtr = groupInfoPtr;
			}
#ifdef USE_TLS13
		if( preferredTls13GroupInfoPtr == NULL && \
			groupInfoPtr->minTlsVersion >= TLS_MINOR_VERSION_TLS13 && \
			sessionInfoPtr->sessionTLS->maxVersion >= TLS_MINOR_VERSION_TLS13 )
			{
			DEBUG_PRINT(( "  Set preferred TLS 1.3 keyex group to %s.\n", 
						  groupInfoPtr->description ));
			preferredTls13GroupInfoPtr = groupInfoPtr;
			
			/* If this is the first keyex group we've seen, remember that we
			   prefer the TLS 1.3 one once we finally know whether we're doing
			   TLS 1.3 or not */
			if( preferredGroupInfoPtr == NULL )
				handshakeInfo->keyexTls13Preferred = TRUE;
			}
#endif /* USE_TLS13 */
		}
	ENSURES( LOOP_BOUND_OK );
	if( noSupportedGroups >= 32 )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Excessive number (more than %d) of supported groups "
				  "values encountered", noSupportedGroups ) );
		}
#ifdef CONFIG_SUITEB_TESTS 
	/* If we're checking for the presence of both P256 and P384 as supported 
	   elliptic curves and we don't see them, complain */
	if( suiteBTestValue == SUITEB_TEST_BOTHCURVES && curvesSeen != 3 )
		{
		*extErrorInfoSet = TRUE;
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Supported elliptic curves extension should have "
				  "contained both P256 and P384 but didn't" ) );
		}
#endif /* CONFIG_SUITEB_TESTS */

	/* If we've got TLS 1.3 enabled but couldn't find a TLS 1.3-specific 
	   group, set the TLS 1.3 group to the same as the TLS classic group.
	   This is required because TLS 1.3 pretends to be TLS 1.2 so we don't
	   know at this point whether we're actually using TLS 1.3 or not */
#ifdef USE_TLS13
	if( preferredTls13GroupInfoPtr == NULL )
		preferredTls13GroupInfoPtr = preferredGroupInfoPtr;
#endif /* USE_TLS13 */

	/* If there are no TLS 1.3 groups then we must be processing a 
	   TLS_EXT_ELLIPTIC_CURVES extension rather than a 
	   TLS_EXT_SUPPORTED_GROUPS one, in which case it's specifically 
	   signalling the use of ECC.  If we don't find any matching suites then 
	   we can't do ECC */
#ifdef USE_TLS13
	if( preferredTls13GroupInfoPtr == NULL && \
		preferredGroupInfoPtr == NULL )
#else
	if( preferredGroupInfoPtr == NULL )
#endif /* USE_TLS13 */
		{
		handshakeInfo->disableECC = TRUE;

		return( CRYPT_OK );
		}
	   
	/* We've got something that we can work with, either the TLS 1.2 
	   interpretation TLS_EXT_ELLIPTIC_CURVES or the TLS 1.3 interpretation 
	   TLS_EXT_SUPPORTED_GROUPS, remember them for later once we've sorted
	   out whether we're doing 1.2 or 1.3 */
	handshakeInfo->keyexGroupInfo = preferredGroupInfoPtr;
#ifdef USE_TLS13
	handshakeInfo->keyexTls13GroupInfo = preferredTls13GroupInfoPtr;
#endif /* USE_TLS13 */
		
	/* We've finally found at least one keyex group that we can work with */
#ifdef USE_TLS13
	ENSURES( handshakeInfo->keyexGroupInfo != NULL || \
			 handshakeInfo->keyexTls13GroupInfo != NULL );
	ENSURES( !( handshakeInfo->keyexTls13Preferred && \
				handshakeInfo->keyexTls13GroupInfo == NULL ) );
#else
	ENSURES( handshakeInfo->keyexGroupInfo != NULL );
#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSupportedGroups( INOUT_PTR STREAM *stream,
						  const SESSION_INFO *sessionInfoPtr )
	{
	STREAM localStream;
	BYTE buffer[ 32 + 8 ];
	LOOP_INDEX i;
	int endPos, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

#ifdef CONFIG_SUITEB
	if( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB )
		{
		static const BYTE eccCurveSuiteB128Info[] = {
			TLS_GROUP_SECP256R1, 
			TLS_GROUP_SECP384R1, 
				TLS_GROUP_NONE, TLS_GROUP_NONE 
			};
		static const BYTE eccCurveSuiteB256Info[] = {
			0, TLS_GROUP_SECP384R1, 0, 0 
			};
		const int suiteBinfo = \
				sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;

		if( suiteBinfo == TLS_PFLAG_SUITEB_128 )
			{
			eccCurveInfoPtr = eccCurveSuiteB128Info;
			eccCurveInfoLen = 2;
			}
		else				
			{
			eccCurveInfoPtr = eccCurveSuiteB256Info;
			eccCurveInfoLen = 1;
			}
  #ifdef CONFIG_SUITEB_TESTS 
		/* In some cases for test purposes we have to send invalid ECC
		   information */
		if( suiteBTestValue == SUITEB_TEST_CLIINVALIDCURVE )
			{
			static const BYTE eccCurveSuiteBInvalidInfo[] = {
				0, TLS_GROUP_SECP521R1, 
				0, TLS_GROUP_SECP192R1, 
				0, 0 
				};

			eccCurveInfoPtr = eccCurveSuiteBInvalidInfo;
			eccCurveInfoLen = 2;
			}
  #endif /* CONFIG_SUITEB_TESTS  */
		}
#endif /* CONFIG_SUITEB */

	/* When writing supported groups, we accept some values like DH on the 
	   server but don't advertise them in the client.  We also have to be
	   careful to only advertise groups that this version of TLS supports */
	sMemOpen( &localStream, buffer, 32 );
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( groupInfoTbl, TLS_GROUP_INFO ) && \
				  groupInfoTbl[ i ].tlsGroupID != TLS_GROUP_NONE,
			  i++ )
		{
		if( !groupInfoTbl[ i ].clientAdvertise || \
			groupInfoTbl[ i ].minTlsVersion > \
					sessionInfoPtr->sessionTLS->maxVersion )
			continue;

		status = writeUint16( &localStream, groupInfoTbl[ i ].tlsGroupID );
		if( cryptStatusError( status ) )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( cryptStatusOK( status ) );
	endPos = stell( &localStream );
	sMemDisconnect( &localStream );
	ENSURES( rangeCheck( endPos, 2, 32 ) );

	writeUint16( stream, endPos );
	return( swrite( stream, buffer, endPos ) );
	}

/****************************************************************************
*																			*
*								Keyex Functions								*
*																			*
****************************************************************************/

/* Complete the post-magic keyex */

#if defined( USE_TLS13 ) && defined( USE_MLKEM )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int completeTLS13PqcKeyex( INOUT_PTR \
									TLS_HANDSHAKE_INFO *handshakeInfo,
								  INOUT_PTR STREAM *stream, 
								  IN_BOOL const BOOLEAN isServer,
								  INOUT_PTR ERROR_INFO *errorInfo )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	const int mlkemDataLength = isServer ? MLKEM_PUBKEY_SIZE : \
										   MLKEM_WRAPPEDKEY_SIZE;
	int length, status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isBooleanValue( isServer ) );

	/* Read the header.  This is the only structure element that the 
	   composite field has, and since part of it can contain either the 
	   ML-KEM public key or the ML-KEM wrapped value, which have different
	   sizes, we have to adjust what we check for as the mlkemDataLength
	   value:

		uint16						keyexLen
			byte[ 1184 / 1088 ]		mlkemPubKey / mlkemPubValue 
			byte[ 32 ]				25519PubValue */
	status = length = readUint16( stream );
	if( cryptStatusOK( status ) && \
		length != mlkemDataLength + X25519_PUBKEY_SIZE )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		return( status );

	/* If we're the server then we've already got the secret key from the 
	   ML-KEM process, if we're the client then we have to unwrap it from 
	   the keyex data.  This has no structure so we have to hardcode in the
	   location and size */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	REQUIRES( rangeCheck( mlkemDataLength, 1, KEYAGREE_DATA_SIZE ) );
	status = sread( stream, &keyAgreeParams.publicValue, mlkemDataLength );
	if( cryptStatusError( status ) )
		return( status );
#ifndef CONFIG_FUZZ
	keyAgreeParams.publicValueLen = mlkemDataLength;
	if( !isServer )
		{
		/* Unwrap the server's ML-KEM secret value from the reverse-RSA 
		   process.  Since it's emulating a standard (EC)DH keyex we report
		   problems in the same form as for the standard keyex */
		status = krnlSendMessage( handshakeInfo->keyexAltContext, 
								  IMESSAGE_CTX_DECRYPT, &keyAgreeParams, 
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			retExt( status,
					( status, errorInfo, 
					  "Invalid ML-KEM phase 2 key agreement value" ) );
			}

		/* Remember the secret key value for later */
		REQUIRES( rangeCheck( keyAgreeParams.wrappedKeyLen, 
							  1, CRYPT_MAX_HASHSIZE ) );
		memcpy( handshakeInfo->tls13PqcSecretValue, 
				keyAgreeParams.wrappedKey, keyAgreeParams.wrappedKeyLen );
		handshakeInfo->tls13PqcSecretValueLen = keyAgreeParams.wrappedKeyLen;
		}
#else
	handshakeInfo->tls13PqcSecretValueLen = 32;
#endif /* CONFIG_FUZZ */

	/* Now we've got through to the, again, implicitly-located and -sized 
	   25519 keyex data, process that */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	status = sread( stream, &keyAgreeParams.publicValue, X25519_PUBKEY_SIZE );
	if( cryptStatusError( status ) )
		return( status );
#ifndef CONFIG_FUZZ
	keyAgreeParams.publicValueLen = X25519_PUBKEY_SIZE;
	status = krnlSendMessage( handshakeInfo->keyexContext, 
							  IMESSAGE_CTX_DECRYPT, &keyAgreeParams, 
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		{
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		retExt( status,
				( status, errorInfo, 
				  "Invalid 25519 phase 2 key agreement value" ) );
		}
#else
	keyAgreeParams.wrappedKeyLen = 32;
#endif /* CONFIG_FUZZ */
		
	/* Finally, glue the two values together to form the premaster secret */
	REQUIRES( !checkOverflowAdd( handshakeInfo->tls13PqcSecretValueLen,
								 keyAgreeParams.wrappedKeyLen ) );
	REQUIRES( rangeCheck( handshakeInfo->tls13PqcSecretValueLen + \
								keyAgreeParams.wrappedKeyLen, 
						  1, KEYEX_SECRET_STORAGE_SIZE ) );
	memcpy( handshakeInfo->premasterSecret, 
			handshakeInfo->tls13PqcSecretValue,
			handshakeInfo->tls13PqcSecretValueLen );
	memcpy( handshakeInfo->premasterSecret + \
					handshakeInfo->tls13PqcSecretValueLen,
			keyAgreeParams.wrappedKey, keyAgreeParams.wrappedKeyLen );
	handshakeInfo->premasterSecretSize = handshakeInfo->tls13PqcSecretValueLen + \
										 keyAgreeParams.wrappedKeyLen;
	zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	DEBUG_DUMP_DATA_LABEL( isServer ? "Server keyex output:" : \
									  "Client keyex output:",
						   handshakeInfo->premasterSecret, 
						   handshakeInfo->premasterSecretSize );

	return( CRYPT_OK );
	}
#endif /* USE_TLS13 && USE_MLKEM */

/* Complete the keyex */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 6 ) ) \
int completeTLSKeyex( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					  INOUT_PTR STREAM *stream, 
					  IN_BOOL const BOOLEAN isServer,
					  IN_BOOL const BOOLEAN isTLSLTS,
					  IN_BOOL const BOOLEAN isTLS13,
					  INOUT_PTR ERROR_INFO *errorInfo )
	{
	KEYAGREE_PARAMS keyAgreeParams;
	const char *keyTypeName;
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( isServer ) );
	REQUIRES( isBooleanValue( isTLSLTS ) );
	REQUIRES( isBooleanValue( isTLS13 ) );

	/* TLS 1.3 with post-magic crypto requires special handling */
#if defined( USE_TLS13 ) && defined( USE_MLKEM )
	if( isTLS13 && \
		isPQCGroup( handshakeInfo->keyexGroupInfo->tlsGroupID ) )
		{
		return( completeTLS13PqcKeyex( handshakeInfo, stream, isServer,
									   errorInfo ) );
		}
#endif /* USE_TLS13 && USE_MLKEM */

	/* Read the DH/ECDH/25519 key agreement parameters:

		DH:
			uint16	yLen
			byte[]	y
		ECDH, TLS 1.2
			uint8	ecPointLen	-- NB uint8 not uint16
			byte[]	ecPoint
		ECDH, TLS 1.3
			uint16	ecPointLen	
			byte[]	ecPoint 
		25519:
			uint16	x25519PubValueLen
			byte[]	x25519PubValue

	   Note the anomalous use of of an 8-bit length for ECDH, this is from
	   classic TLS which used this for no known reason.  TLS 1.3 went to a
	   standard 16-bit length */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	switch( handshakeInfo->keyexAlgo )
		{
		case CRYPT_ALGO_DH:
			keyTypeName = "DH";
			status = readInteger16U( stream, keyAgreeParams.publicValue,
									 &keyAgreeParams.publicValueLen,
									 MIN_PKCSIZE, CRYPT_MAX_PKCSIZE, 
									 BIGNUM_CHECK_VALUE_PKC );
			break;

		case CRYPT_ALGO_ECDH:
			keyTypeName = "ECDH";
#ifdef USE_TLS13
			if( isTLS13 )
				{
				status = readInteger16U( stream, keyAgreeParams.publicValue,
										 &keyAgreeParams.publicValueLen,
										 MIN_PKCSIZE_ECCPOINT, 
										 MAX_PKCSIZE_ECCPOINT, 
										 BIGNUM_CHECK_VALUE_ECC );
				if( cryptStatusOK( status ) && \
					isShortECCKey( keyAgreeParams.publicValueLen / 2 ) )
					status = CRYPT_ERROR_NOSECURE;
				}
			else
#endif /* USE_TLS13 */
			status = readEcdhValue( stream, keyAgreeParams.publicValue,
									CRYPT_MAX_PKCSIZE, 
									&keyAgreeParams.publicValueLen );
			break;

#ifdef USE_X25519
		case CRYPT_ALGO_25519:
			keyTypeName = "25519";
			status = readInteger16U( stream, keyAgreeParams.publicValue,
									 &keyAgreeParams.publicValueLen,
									 MIN_PKCSIZE_BERNSTEIN, 
									 MAX_PKCSIZE_BERNSTEIN, 
									 BIGNUM_CHECK_VALUE_FIXEDLEN );
			break;
#endif /* USE_X25519 */

		default: 
			retIntError();		
		}
	if( cryptStatusError( status ) )
		{
		/* Some misconfigured peers may use very short keys, we perform a 
		   special-case check for these and return a more specific message 
		   than the generic bad-data error */
		if( status == CRYPT_ERROR_NOSECURE )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, errorInfo, 
					  "Insecure %s key used in key exchange",
					  keyTypeName ) );
			}

		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid %s phase 2 key agreement data",
				  keyTypeName ) );
		}

	/* If we're fuzzing the input then we don't need to go through any of 
	   the following crypto calisthenics.  In addition we can exit now 
	   because the remaining fuzzable code is common with the client and
	   has already been tested there */
	FUZZ_EXIT();

	/* Perform phase 2 of the (EC)DH key agreement */
	status = krnlSendMessage( handshakeInfo->keyexContext, 
							  IMESSAGE_CTX_DECRYPT, &keyAgreeParams, 
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		{
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		retExt( status,
				( status, errorInfo, 
				  "Invalid %s phase 2 key agreement value",
				  keyTypeName ) );
		}

	/* The output of the ECDH operation is an ECC point but for no known
	   reason TLS only uses the x coordinate and not the full point in its 
	   crypto computations (RFC 4492 section 5.10 / RFC 8446 section 7.4.2) 
	   even though it transmits the full point in the handshake.  To work 
	   around this we have to rewrite the point as a standalone x 
	   coordinate, which is relatively easy because we're using the 
	   uncompressed point format: 

		+---+---------------+---------------+
		|04	|		qx		|		qy		|
		+---+---------------+---------------+
			|<- fldSize --> |<- fldSize --> | */
	if( handshakeInfo->keyexAlgo == CRYPT_ALGO_ECDH && !isTLSLTS )
		{
		const int xCoordLen = ( keyAgreeParams.wrappedKeyLen - 1 ) / 2;

		REQUIRES( keyAgreeParams.wrappedKeyLen >= MIN_PKCSIZE_ECCPOINT && \
				  keyAgreeParams.wrappedKeyLen <= MAX_PKCSIZE_ECCPOINT && \
				  ( keyAgreeParams.wrappedKeyLen & 1 ) == 1 && \
				  keyAgreeParams.wrappedKey[ 0 ] == 0x04 );
		REQUIRES( boundsCheck( 1, xCoordLen, CRYPT_MAX_PKCSIZE ) );
		memmove( keyAgreeParams.wrappedKey, 
				 keyAgreeParams.wrappedKey + 1, xCoordLen );
		keyAgreeParams.wrappedKeyLen = xCoordLen;
		}

	/* Remember the premaster secret, the output of the (EC)DH operation */
	REQUIRES( rangeCheck( keyAgreeParams.wrappedKeyLen, 1,
						  KEYEX_SECRET_STORAGE_SIZE ) );
	memcpy( handshakeInfo->premasterSecret, keyAgreeParams.wrappedKey,
			keyAgreeParams.wrappedKeyLen );
	handshakeInfo->premasterSecretSize = keyAgreeParams.wrappedKeyLen;
	zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	DEBUG_DUMP_DATA_LABEL( isServer ? "Server keyex output:" : \
									  "Client keyex output:",
						   handshakeInfo->premasterSecret, 
						   handshakeInfo->premasterSecretSize );

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
