/****************************************************************************
*																			*
*					cryptlib TLS Client/Server Hello Management				*
*					  Copyright Peter Gutmann 1998-2024						*
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

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Process a session ID */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processSessionID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							 INOUT_PTR STREAM *stream )
	{
	BYTE sessionID[ MAX_SESSIONID_SIZE + 8 ];
	int sessionIDlength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Get the session ID information */
	status = sessionIDlength = sgetc( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid session ID information" ) );
		}
	if( sessionIDlength <= 0 )
		{
		/* No session ID, we're done */
		return( CRYPT_OK );
		}
	if( sessionIDlength < MIN_SESSIONID_SIZE || \
		sessionIDlength > MAX_SESSIONID_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid session ID length %d, should be %d...%d", 
				  sessionIDlength, MIN_SESSIONID_SIZE, 
				  MAX_SESSIONID_SIZE ) );
		}
	REQUIRES( rangeCheck( sessionIDlength, 1, MAX_SESSIONID_SIZE ) );
	status = sread( stream, sessionID, sessionIDlength );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid session ID data" ) );
		}

	/* It's a potentially resumed session, remember the details and let the 
	   caller know */
	REQUIRES( rangeCheck( sessionIDlength, 1, MAX_SESSIONID_SIZE ) );
	memcpy( handshakeInfo->sessionID, sessionID, sessionIDlength );
	handshakeInfo->sessionIDlength = sessionIDlength;

	return( OK_SPECIAL );
	}

#ifdef CONFIG_SUITEB

/* For Suite B the first suite must be ECDHE/AES128-GCM/SHA256 or 
   ECDHE/AES256-GCM/SHA384 depending on the security level and the second
   suite, at the 128-bit security level, must be ECDHE/AES256-GCM/SHA384.  
   This is one of those pedantic checks that requires vastly more work to 
   support its nitpicking than the whole check is worth (since the same 
   thing is checked anyway when we check the suite strength), but it's 
   required by the spec */

CHECK_RETVAL STDC_NONNULL_ARG( ( 4 ) ) \
static int checkSuiteBSuiteSelection( IN_RANGE( TLS_FIRST_VALID_SUITE, \
												TLS_LAST_SUITE - 1 ) \
										const int cipherSuite,
									  IN_FLAGS( TLS_PFLAG ) const int flags,
									  IN_BOOL const BOOLEAN isFirstSuite,
									  INOUT_PTR ERROR_INFO *errorInfo )
	{
	const char *precedenceString = isFirstSuite ? "First" : "Second";
	const char *suiteName = NULL;

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( cipherSuite >= TLS_FIRST_VALID_SUITE && \
			  cipherSuite < TLS_LAST_SUITE );
	REQUIRES( ( flags & ~( TLS_PFLAG_SUITEB ) ) == 0 );
	REQUIRES( isBooleanValue( isFirstSuite ) );

	if( isFirstSuite )
		{
		switch( flags )
			{
			case TLS_PFLAG_SUITEB_128:
				if( cipherSuite != TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 )
					suiteName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
				break;

			case TLS_PFLAG_SUITEB_256:
				if( cipherSuite != TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 )
					suiteName = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
				break;

			default:
				retIntError();
			}
		}
	else
		{
		switch( flags )
			{
			case TLS_PFLAG_SUITEB_128:
				if( cipherSuite != TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 )
					suiteName = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
				break;

			case TLS_PFLAG_SUITEB_256:
				/* For the 256-bit level there are no further requirements */
				break;

			default:
				retIntError();
			}
		}
	if( suiteName != NULL )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, errorInfo, 
				  "%s cipher suite for Suite B at the %d-bit security "
				  "level must be %s", precedenceString, 
				  ( flags == TLS_PFLAG_SUITEB_128 ) ? 128 : 256, 
				  suiteName ) );
		}

	/* At the 256-bit level there's an additional requirement that the 
	   client not offer any P256 cipher suites, or specifically that it not
	   offer the one P256 cipher suite allowed for Suite B (whether it can 
	   offer non-Suite B P256 cipher suites is left ambiguous) */
	if( flags == TLS_PFLAG_SUITEB_256 && \
		cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, errorInfo, 
				  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite "
				  "can't be offered at the 256-bit security level" ) );
		}

	return( CRYPT_OK );
	}
#endif /* CONFIG_SUITEB */

/****************************************************************************
*																			*
*							Negotiate a Cipher Suite						*
*																			*
****************************************************************************/

/* Set up the crypto information based on the cipher suite */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int setSuiteInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 const CIPHERSUITE_INFO *cipherSuiteInfoPtr )
	{
	CRYPT_QUERY_INFO queryInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( cipherSuiteInfoPtr, sizeof( CIPHERSUITE_INFO ) ) );

	/* TLS 1.3 cipher suites only specify symmetric algorithms with the 
	   details of PKC algorithms stuffed into extensions so we only set the 
	   PKC information if it's present.  In particular the keyexAlgo is set
	   when we read the other side's keyex and the authAlgo is set either 
	   when we receive the other side's certificate chain if we're the client
	   or based on our private key if we're the server.
	   
	   See the enormous comment in tls_ext_rw.c:readSignatureAlgos() for why 
	   we hardcode SHA-256 as the keyex signature hash algorithm for TLS 1.2 
	   and above */
	handshakeInfo->cipherSuite = cipherSuiteInfoPtr->cipherSuite;
	handshakeInfo->cipherSuiteFlags = cipherSuiteInfoPtr->flags;
	if( cipherSuiteInfoPtr->keyexAlgo != CRYPT_ALGO_NONE )
		{
		handshakeInfo->keyexAlgo = cipherSuiteInfoPtr->keyexAlgo;
		handshakeInfo->authAlgo = cipherSuiteInfoPtr->authAlgo;
		}
	handshakeInfo->cryptKeysize = cipherSuiteInfoPtr->cryptKeySize;
	sessionInfoPtr->cryptAlgo = cipherSuiteInfoPtr->cryptAlgo;
	sessionInfoPtr->integrityAlgo = cipherSuiteInfoPtr->macAlgo;
	handshakeInfo->integrityAlgoParam = cipherSuiteInfoPtr->macParam;
	sessionInfoPtr->authBlocksize = cipherSuiteInfoPtr->macBlockSize;
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		/* Default to SHA-256 as per the comment above */
		handshakeInfo->keyexSigHashAlgoParam = bitsToBytes( 256 );
		handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;

		/* Check whether we're the server and using ECDSA, in which case we 
		   need to match the hash algorithm to the key size to make the 
		   appropriate fashion statement */
#ifdef USE_SHA2_EXT
		if( isServer( sessionInfoPtr ) && \
			sessionInfoPtr->privateKeyAlgo == CRYPT_ALGO_ECDSA )
			{
			int privateKeySize;

			status = krnlSendMessage( sessionInfoPtr->privateKey, 
									  IMESSAGE_GETATTRIBUTE, 
									  &privateKeySize, 
									  CRYPT_CTXINFO_KEYSIZE );
			if( cryptStatusError( status ) )
				return( status );
			if( privateKeySize == bitsToBytes( 521 ) )
				handshakeInfo->keyexSigHashAlgoParam = bitsToBytes( 512 );
			else
				{
				if( privateKeySize == bitsToBytes( 384 ) )
					handshakeInfo->keyexSigHashAlgoParam = bitsToBytes( 384 );
				}
			}
#endif /* USE_SHA2_EXT */
		}
	if( cipherSuiteInfoPtr->flags & \
		( CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_BERNSTEIN ) )
		{
		/* The AEAD ciphers are stream ciphers with special-case requirements */
		sessionInfoPtr->cryptBlocksize = 1;
		if( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_GCM )
			SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM );
		else
			SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_BERNSTEIN );
		}
	else
		{
		/* It's a standard cipher, get the block size */
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_QUERYCAPABILITY, &queryInfo,
								  sessionInfoPtr->cryptAlgo );
		if( cryptStatusError( status ) )
			return( status );
		sessionInfoPtr->cryptBlocksize = queryInfo.blockSize;
		}
	DEBUG_PRINT(( "Cipher suite set to %s.\n", 
				  cipherSuiteInfoPtr->debugText ));

	return( CRYPT_OK );
	}

/* Handle a signalling cipher suite */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int handleSignallingSuite( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
								  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
								  IN_RANGE( TLS_FIRST_VALID_SUITE, \
											TLS_LAST_SUITE ) \
										const int cipherSuite )
	{
	const PROTOCOL_INFO *protocolInfo = \
				DATAPTR_GET( sessionInfoPtr->protocolInfo );

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isSignallingSuite( cipherSuite ) );
	REQUIRES( protocolInfo != NULL );

	switch( cipherSuite )
		{
		case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
			/* If the client is signalling its support for secure 
			   renegotiation, remember that we have to acknowledge this in 
			   our response.  In theory this shouldn't be necessary since 
			   the renegotiation information is handled through a TLS 
			   extension, but OpenSSL uses an SCSV instead of the extension 
			   for no obvious reason */
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->flags |= HANDSHAKE_FLAG_NEEDRENEGRESPONSE;
			break;

		case TLS_FALLBACK_SCSV:
			/* If the client has fallen back to a lower version and has 
			   indicated this to us, and if this version is lower than what 
			   we'd normally be using, abort the handshake with an insecure-
			   fallback alert */
			if( isServer( sessionInfoPtr ) && \
				handshakeInfo->clientOfferedVersion < \
											protocolInfo->maxVersion )
				{
				handshakeInfo->failAlertType = \
									TLS_ALERT_INAPPROPRIATE_FALLBACK;
				retExt( CRYPT_ERROR_NOSECURE,
						( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
						  "Client attempted insecure falback from protocol "
						  "version %d to version %d",
						  protocolInfo->maxVersion,
						  handshakeInfo->clientOfferedVersion ) );
				}
			break;
		}

	return( CRYPT_OK );
	}

/* Choose the best cipher suite from a list of suites */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processCipherSuite( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
							   INOUT_PTR STREAM *stream, 
							   IN_RANGE( 1, MAX_CIPHERSUITES ) \
									const int noSuites )
	{
	const CIPHERSUITE_INFO **cipherSuiteInfo;
	const PROTOCOL_INFO *protocolInfo;
	const BOOLEAN isServer = isServer( sessionInfoPtr ) ? TRUE : FALSE;
	BOOLEAN allowDH = algoAvailable( CRYPT_ALGO_DH ) ? TRUE : FALSE;
	BOOLEAN allowECDH = algoAvailable( CRYPT_ALGO_ECDH ) ? TRUE : FALSE;
	BOOLEAN allowECDSA = ( allowECDH && algoAvailable( CRYPT_ALGO_ECDSA ) ) ? \
						   TRUE : FALSE;
	BOOLEAN allowRSA = algoAvailable( CRYPT_ALGO_RSA ) ? TRUE : FALSE;
	const BOOLEAN allowTLS12 = \
		( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 ) ? TRUE : FALSE;
	BOOLEAN allowTLS13 = FALSE;
	const int tlsMinVersion = sessionInfoPtr->sessionTLS->minVersion;
	int suiteIndex = 999, eccSuiteIndex = 999, tls13SuiteIndex = 999;
	int suiteRunSuite = 999, suiteRunCount DUMMY_INIT;
	int cipherSuiteInfoSize, invalidSuiteCount = 0, status;
	LOOP_INDEX i;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( noSuites > 0 && noSuites <= MAX_CIPHERSUITES );

	/* Check whether TLS 1.3 is enabled.  We can't check the session 
	   information as we do for TLS 1.2 because TLS 1.3 identifies as TLS 
	   1.2 in the version information, so we have to check whether we
	   can do at least TLS 1.2 (via the version information) and then 
	   whether we've been configured to allow TLS 1.3 in case it's enabled 
	   later in the handshake process */
	protocolInfo = DATAPTR_GET( sessionInfoPtr->protocolInfo );
	ENSURES( protocolInfo != NULL );
	if( allowTLS12 && protocolInfo->maxVersion >= TLS_MINOR_VERSION_TLS13 )
		allowTLS13 = TRUE;

	/* Get the information for the supported cipher suites */
	status = getCipherSuiteInfo( &cipherSuiteInfo, &cipherSuiteInfoSize );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're the server then our choice of possible suites is constrained 
	   by the server key that we're using as well as various other factors 
	   such as what we've been configured to accept from the client, figure 
	   out what we can use */
	if( isServer )
		{
		if( sessionInfoPtr->privateKey == CRYPT_ERROR )
			{
			/* There's no server private key present, we're limited to PSK
			   suites.  Note that we still allow DH because alongside the
			   pure PSK suites we also allow DH + PSK ones */
			allowECDSA = allowRSA = FALSE;
			}
		else
			{
			/* To be usable for DH/ECDH/25519 the server key has to be 
			   signature-capable */
			if( !checkContextCapability( sessionInfoPtr->privateKey,
										 MESSAGE_CHECK_PKC_SIGN ) )
				allowDH = allowECDH = FALSE;

			/* To be usable for ECC or RSA the server key has to itself be 
			   an ECC or RSA key.  Note that we can't extend this check to
			   TLS 1.3 suites or TLS 1.3-only algorithms like Ed25519 for 
			   the reason given in the comment for the long set of allowXYZ 
			   checks below */
			if( sessionInfoPtr->privateKeyAlgo != CRYPT_ALGO_ECDSA )
				allowECDSA = FALSE;
			if( sessionInfoPtr->privateKeyAlgo != CRYPT_ALGO_RSA )
				allowRSA = FALSE;
			}
		}

	LOOP_EXT( i = 0, i < noSuites, i++, MAX_CIPHERSUITES + 1 )
		{
		const CIPHERSUITE_INFO *cipherSuiteInfoPtr = NULL;
		LOOP_INDEX_ALT newSuiteIndex;
		int newSuite;

		ENSURES( LOOP_INVARIANT_EXT( i, 0, noSuites - 1, 
									 MAX_CIPHERSUITES + 1 ) );

		/* Get the cipher suite information */
		status = newSuite = readUint16( stream );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Invalid cipher suite information" ) );
			}

		/* If it's an obviously non-valid suite, continue */
		if( newSuite < TLS_FIRST_VALID_SUITE || newSuite >= TLS_LAST_SUITE )
			continue;

		/* If it's a signalling suite, handle it specially */
		if( isSignallingSuite( newSuite ) )
			{
			status = handleSignallingSuite( sessionInfoPtr, handshakeInfo, 
											newSuite );
			if( cryptStatusError( status ) )
				return( status );

			/* Signalling suites aren't standard cipher suites so we don't 
			   try and process them as such */
			DEBUG_PRINT(( "  Skipping SCSV signalling cipher suite %d "
						  "(%X).\n", newSuite, newSuite ));
			continue;
			}

		/* Check for a run of consecutive suites, a sign that we're being
		   scanned */
		if( suiteRunSuite == 999 )
			{
			suiteRunSuite = newSuite;
			suiteRunCount = 0;
			}
		else
			{
			/* Check whether we're in a run */
			if( newSuite == suiteRunSuite + 1 )
				{
				suiteRunCount++;

				/* If we've seen more than 20 consecutive suites, assume
				   we're being scanned, there should never be that many 
				   sensible suites next to each other.  Suites listed at
				   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4,
				   suites that we should never really see are 0x03, 0x06, 
				   0x08, 0x0E, 0x11, 0x14, 0x17-2E, 0x34, 0x3A-3B, 
				   0x46-66, 0x6C-6D, 0x72-83, 0x89-8A, 0x9B, 0xA2-A7,
				   0xB0-B1, 0xB4-B5, 0xB8-B9, 0xBB-BC, 0xBF, 0xC5, 0xC8-FE,
				   0xC001-C002, 0xC006-C007, C00B-C00C, 0xC010-C011, 
				   0xC015-C019, 0xC033, 0xC039-0xC03B, 0xC046-C047,
				   (0xC03C-0xC09B = Aria+Camellia suites, 0xC09C-0xC0AF = 
				   CCM suites), 0xC0B4-C0FF, 0xCC00-CCA7, 0xCCAF-CCFF.
				   The longest run of plausible suites is 0xC023-0xC032 =
				   15 suites (and even seeing that as a run would be very
				   strange) so 20 is a good margin */
				if( isServer && suiteRunCount > 20 && \
					!( handshakeInfo->flags & HANDSHAKE_FLAG_ISSCANNER ) )
					{
					DEBUG_PRINT(( "  More than %d consecutive suites seen "
								  "in client handshake, enabling scanner "
								  "mode.\n", suiteRunCount - 1 ));
					handshakeInfo->flags |= HANDSHAKE_FLAG_ISSCANNER;
					}
				}
			else
				suiteRunCount = 0;
			suiteRunSuite = newSuite;
			}

		/* When resuming a cached session the client is required to offer
		   as one of its suites the original suite that was used.  There's
		   no good reason for this requirement (it's probable that the spec
		   is intending that there be at least one cipher suite and that if
		   there's only one it should really be the one originally
		   negotiated) and it complicates implementation of shared-secret
		   key sessions so we don't perform this check */

		/* Try and find the information for the proposed cipher suite */
		LOOP_EXT_ALT( newSuiteIndex = 0, 
					  newSuiteIndex < cipherSuiteInfoSize && \
						cipherSuiteInfo[ newSuiteIndex ]->cipherSuite != SSL_NULL_WITH_NULL,
					  newSuiteIndex++, MAX_CIPHERSUITES + 1 )
			{
			ENSURES( LOOP_INVARIANT_EXT_ALT( newSuiteIndex, 0, 
											 cipherSuiteInfoSize - 1,
											 MAX_CIPHERSUITES + 1 ) );

			if( cipherSuiteInfo[ newSuiteIndex ]->cipherSuite == newSuite )
				{
				cipherSuiteInfoPtr = cipherSuiteInfo[ newSuiteIndex ];
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		ENSURES( newSuiteIndex < cipherSuiteInfoSize );
#ifdef CONFIG_SUITEB
		if( ( sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB ) && \
			( i == 0 || i == 1 ) )
			{
			status = checkSuiteBSuiteSelection( \
							( cipherSuiteInfoPtr == NULL ) ? \
								TLS_FIRST_VALID_SUITE /* Dummy value */ : \
								cipherSuiteInfoPtr->cipherSuite,
							sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB,
							( i == 0 ) ? TRUE : FALSE, SESSION_ERRINFO );
			if( cryptStatusError( status ) )
				return( status );
			}
#endif /* CONFIG_SUITEB */
		if( cipherSuiteInfoPtr == NULL )
			{
			/* It's an unrecognised suite, perform an additional check 
			   whether it's in an unassigned/reserved position, which 
			   typically indicates that we're being scanned.  Suites
			   listed at
			   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4 */
			if( ( newSuite >= 0x47 && newSuite <= 0x4F ) || \
				( newSuite >= 0x50 && newSuite <= 0x66 ) || \
				( newSuite >= 0x72 && newSuite <= 0x83 ) || \
				( newSuite >= 0xCC00 && newSuite <= 0xCCA7 ) )
				{
				invalidSuiteCount++;

				/* If we've seen more than a certain number of these then 
				   we're probably being scanned since a legitimate client is
				   unlikely to be requesting a large number of reserved
				   suites, enable scanner mode */
				if( isServer && invalidSuiteCount > 8 && \
					!( handshakeInfo->flags & HANDSHAKE_FLAG_ISSCANNER ) )
					{
					DEBUG_PRINT(( "  More than %d invalid suites seen in "
								  "client handshake, enabling scanner "
								  "mode.\n", invalidSuiteCount - 1 ));
					handshakeInfo->flags |= HANDSHAKE_FLAG_ISSCANNER;
					}
				}

			DEBUG_PRINT(( "  Skipping unknown cipher suite %d (%X).\n", 
						  newSuite, newSuite ));
			continue;
			}
		DEBUG_PRINT(( "Offered suite: %s.\n", 
					  cipherSuiteInfoPtr->debugText ));

		/* Perform a short-circuit check, if the new suite is inherently 
		   less-preferred than what we've already got then there's no point 
		   to performing any of the remaining checks since it'll never be
		   selected.  Because of the cipher-suite backtracking that may be 
		   required later on we have to perform three separate classes of 
		   checks, one for standard suites, one for ECC ones, and one for
		   TLS 1.3 ones */
		if( isEccAlgo( cipherSuiteInfoPtr->keyexAlgo ) )
			{
			if( newSuiteIndex > eccSuiteIndex )
				{
				DEBUG_PRINT(( "  Rejected less-preferred ECC suite %s.\n", 
							  cipherSuiteInfoPtr->debugText ));
				continue;
				}
			}
		else
			{
			if( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_TLS13 )
				{
				if( newSuiteIndex > tls13SuiteIndex )
					{
					DEBUG_PRINT(( "  Rejected less-preferred TLS 1.3 suite "
								  "%s.\n", cipherSuiteInfoPtr->debugText ));
					continue;
					}
				}
			else
				{
				if( newSuiteIndex > suiteIndex )
					{
					DEBUG_PRINT(( "  Rejected less-preferred suite %s.\n", 
								  cipherSuiteInfoPtr->debugText ));
					continue;
					}
				}
			}

		/* Make sure that the required algorithms are available.  If we're
		   using TLS-PSK then there's no authentication algorithm because 
		   the exchange is authenticated using the PSK.  We don't have to 
		   check the keyex algorithm because that's handled via the 
		   algorithm-class check below except for RSA, which is implicitly
		   checked by the fact that it's also used for the (checked) 
		   authentication algorithm */
		if( cipherSuiteInfoPtr->authAlgo != CRYPT_ALGO_NONE && \
			!algoAvailable( cipherSuiteInfoPtr->authAlgo ) )
			{
			DEBUG_PRINT(( "  Rejected unavailable-auth: %s.\n", 
						  cipherSuiteInfoPtr->debugText ));
			continue;
			}
		if( !algoAvailable( cipherSuiteInfoPtr->cryptAlgo ) )
			{
			DEBUG_PRINT(( "  Rejected unavailable-crypt: %s.\n", 
						  cipherSuiteInfoPtr->debugText ));
			continue;
			}
		if( !algoAvailable( cipherSuiteInfoPtr->macAlgo ) )
			{
			DEBUG_PRINT(( "  Rejected unavailable-MAC: %s.\n", 
						  cipherSuiteInfoPtr->debugText ));
			continue;
			}

		/* If it's a suite that's disabled because of external constraints 
		   then we can't use it.  Note that this only applies to TLS classic
		   suites, since TLS 1.3 switched to an IPsec-style a la carte mess
		   we don't know whether something like TLS_AES_128_GCM_SHA256 comes
		   with ECDSA or not as we would with 
		   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
		if( !allowDH && cipherSuiteInfoPtr->keyexAlgo == CRYPT_ALGO_DH )
			{
			/* We can't do DH */
			DEBUG_PRINT(( "  Rejected DH suite %s.\n", 
						  cipherSuiteInfoPtr->debugText ));
			continue;
			}
		if( !allowECDH && cipherSuiteInfoPtr->keyexAlgo == CRYPT_ALGO_ECDH )
			{
			/* We can't do ECDH */
			DEBUG_PRINT(( "  Rejected ECDH suite %s.\n", 
						  cipherSuiteInfoPtr->debugText ));
			continue;
			}
		if( !allowRSA && \
			( cipherSuiteInfoPtr->keyexAlgo == CRYPT_ALGO_RSA || \
			  cipherSuiteInfoPtr->authAlgo == CRYPT_ALGO_RSA ) )
			{
			/* The server doesn't have an RSA private key */
			DEBUG_PRINT(( "  Rejected RSA suite %s as server key is "
						  "non-RSA.\n", cipherSuiteInfoPtr->debugText ));
			continue;
			}
		if( !allowECDSA && cipherSuiteInfoPtr->authAlgo == CRYPT_ALGO_ECDSA )
			{
			/* The server doesn't have an ECDSA private key */
			DEBUG_PRINT(( "  Rejected ECC suite %s as server key is "
						  "non-ECDSA.\n", cipherSuiteInfoPtr->debugText ));
			continue;
			}
		if( !allowTLS12 && \
			( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_TLS12 ) )
			{
			/* We can't do TLS 1.2 */
			DEBUG_PRINT(( "  Rejected TLS 1.2 suite %s as we don't do "
						  "TLS 1.2.\n", cipherSuiteInfoPtr->debugText ));
			continue;
			}
		if( !allowTLS13 && \
			( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_TLS13 ) )
			{
			/* We can't do TLS 1.3 */
			DEBUG_PRINT(( "  Rejected TLS 1.3 suite %s as we don't to "
						  "TLS 1.3.\n", cipherSuiteInfoPtr->debugText ));
			continue;
			}
		if( tlsMinVersion >= TLS_MINOR_VERSION_TLS12 && \
			!( cipherSuiteInfoPtr->flags & ( CIPHERSUITE_FLAG_TLS12 | \
											 CIPHERSUITE_FLAG_TLS13 ) ) )
			{
			/* It's not a TLS 1.2/TLS 1.3 suite */
			DEBUG_PRINT(( "  Rejected non-TLS 1.%d suite %s.\n", 
						  ( tlsMinVersion >= TLS_MINOR_VERSION_TLS13 ) ? \
							3 : 2, cipherSuiteInfoPtr->debugText ));
			continue;
			}
#ifdef USE_TLS13
		if( tlsMinVersion >= TLS_MINOR_VERSION_TLS13 && \
			!( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_TLS13 ) )
			{
			/* It's not a TLS 1.3 suite */
			DEBUG_PRINT(( "  Rejected non-TLS 1.3 suite %s.\n", 
						  cipherSuiteInfoPtr->debugText ));
			continue;
			}
#endif /* USE_TLS13 */

		/* If we're being scanned by a security scanner and it's a suite 
		   that will trigger a bogus vulnerability report, don't respond to 
		   it.  This typically won't be triggered because we can't 
		   fingerprint the scanner until we see the extensions, which follow
		   the cipher suites */
		if( ( handshakeInfo->flags & HANDSHAKE_FLAG_ISSCANNER ) && \
			( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_TRIGGER ) )
			{
			DEBUG_PRINT(( "  Skipping suite %s to avoid triggering a bogus "
						  "vulnerability warning from a scanner.\n", 
						  cipherSuiteInfoPtr->debugText ));
			continue;
			}

		/* If we're only able to do basic TLS-PSK because there's no private 
		   key present and the suite requires a private key then we can't 
		   use this suite */
		if( isServer && sessionInfoPtr->privateKey == CRYPT_ERROR && \
			( cipherSuiteInfoPtr->keyexAlgo != CRYPT_ALGO_NONE && \
			  !isKeyexAlgo( cipherSuiteInfoPtr->keyexAlgo ) ) ) 
			continue;

		/* If the new suite is more preferred (i.e. with a lower index) than 
		   the existing one, use that.  The presence of the ECC suites 
		   significantly complicates this process because the ECC curve 
		   information sent later on in the handshake can retroactively 
		   disable an already-negotiated ECC cipher suite, forcing a fallback 
		   to a non-ECC suite (this soft-fail fallback is also nasty for the
		   user since they can't guarantee that they're actually using ECC
		   if they ask for it).  Similarly, the fact that we may be moving to
		   TLS 1.3 later means that we could switch suites there as well.

		   To handle this we keep track of all three of the most-preferred 
		   suite, the most preferred ECC suite, and the most-preferred 
		   TLS 1.3 suite so that we can switch later if necessary */
		if( isEccAlgo( cipherSuiteInfoPtr->keyexAlgo ) )
			{
			if( newSuiteIndex < eccSuiteIndex )
				{
				eccSuiteIndex = newSuiteIndex;
				DEBUG_PRINT(( "  Accepted ECC suite %s.\n", 
							  cipherSuiteInfoPtr->debugText ));
				}
			}
		else
			{
			if( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_TLS13 )
				{
				if( newSuiteIndex < tls13SuiteIndex )
					{
					tls13SuiteIndex = newSuiteIndex;
					DEBUG_PRINT(( "  Accepted TLS 1.3 suite %s.\n", 
								  cipherSuiteInfoPtr->debugText ));
					}
				}
			else
				{
				if( newSuiteIndex < suiteIndex )
					{
					suiteIndex = newSuiteIndex;
					DEBUG_PRINT(( "  Accepted suite %s.\n", 
								  cipherSuiteInfoPtr->debugText ));
					}
				}
			}
		}
	ENSURES( LOOP_BOUND_OK );

	/* Remember whether we've seen any TLS 1.3 suites, which means that 
	   handling of further TLS 1.3 things stuffed into extensions later on 
	   is OK */
#ifdef USE_TLS13
	if( tls13SuiteIndex < cipherSuiteInfoSize )
		handshakeInfo->tls13OK = TRUE;
#endif /* USE_TLS13 */

	/* If the only matching suite that we found was an ECC one, set it to 
	   the primary suite (which can then be retroactively knocked out as per 
	   the comment earlier) */
	if( suiteIndex >= cipherSuiteInfoSize )
		{
		suiteIndex = eccSuiteIndex;
		eccSuiteIndex = 999;
		handshakeInfo->fallbackType = TLS_FALLBACK_ECC;
		DEBUG_PRINT(( "  No standard suites available, falling back to ECC "
					  "suites.\n" ));
		}

	/* Fall back a second time if necessary, this time to a TLS 1.3 suite */
#ifdef USE_TLS13
	if( suiteIndex >= cipherSuiteInfoSize )
		{
		suiteIndex = tls13SuiteIndex;
		tls13SuiteIndex = 999;
		handshakeInfo->fallbackType = TLS_FALLBACK_TLS13;
		DEBUG_PRINT(( "  No standard or ECC suites available, falling back "
					  "to TLS 1.3 suites.\n" ));
		}
#endif /* USE_TLS13 */

	/* If we couldn't find anything to use, exit.  This leads to problems 
	   because ECC and even more so TLS 1.3 suites can be knocked out later
	   because the full details of what's required are specified in 
	   extensions that we won't see until much later, at which point the 
	   error message will be non-representative of the real problem, but
	   there's not much that we can do at this point.
	
	   The range comparison is actually for whether it's still set to the 
	   original value of 999 but some source code analysis tools think that 
	   it's an index check so we compare to the upper bound of the array 
	   size instead */
	if( suiteIndex >= cipherSuiteInfoSize )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "No encryption mechanism compatible with the remote "
				  "system could be found" ) );
		}

	/* We got a cipher suite that we can handle, set up the crypto information */
	REQUIRES( rangeCheck( suiteIndex, 0, cipherSuiteInfoSize - 1 ) );
	status = setSuiteInfo( sessionInfoPtr, handshakeInfo,
						   cipherSuiteInfo[ suiteIndex ] );
	if( cryptStatusError( status ) )
		return( status );

	/* If we found ECC or TLS 1.3 suites and they're not already selected due 
	   to there being no other suites available, remember them in case we 
	   later find out that we can use them */
	if( eccSuiteIndex < cipherSuiteInfoSize )
		{
		REQUIRES( allowECDH );

		handshakeInfo->eccSuiteInfoPtr = cipherSuiteInfo[ eccSuiteIndex ];
		DEBUG_PRINT(( "Alternative ECC suite bookmarked as: %s.\n", 
					  cipherSuiteInfo[ eccSuiteIndex ]->debugText ));
		}
#ifdef USE_TLS13
	if( tls13SuiteIndex < cipherSuiteInfoSize )
		{
		handshakeInfo->tls13SuiteInfoPtr = cipherSuiteInfo[ tls13SuiteIndex ];
		DEBUG_PRINT(( "Alternative TLS 1.3 suite bookmarked as: %s.\n", 
					  cipherSuiteInfo[ tls13SuiteIndex ]->debugText ));
		}
#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Process Client/Server Hello 						*
*																			*
****************************************************************************/

/* Process the client/server hello:

		byte		ID = TLS_HAND_CLIENT_HELLO / TLS_HAND_SERVER_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		byte[32]	nonce
		byte		sessIDlen		-- May receive nonzero len +
		byte[]		sessID			-- <len> bytes data

			Client						Server
		uint16		suiteLen		-
		uint16[]	suites			uint16		suite
		byte		coprLen = 1		-
		byte		copr = 0		byte		copr = 0 
	  [	uint16	extListLen			-- RFC 3546/RFC 4366/RFC 6066
			byte	extType
			uint16	extLen
			byte[]	extData ] */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int processHelloTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT_PTR STREAM *stream, 
					 OUT_ENUM_OPT( TLSHELLO_ACTION ) \
							TLSHELLO_ACTION_TYPE *actionType,
					 IN_BOOL const BOOLEAN isServer )
	{
	BOOLEAN potentiallyResumedSession = FALSE;
	int endPos, length, suiteLength, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( actionType, sizeof( TLSHELLO_ACTION_TYPE ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* Clear return value */
	*actionType = TLSHELLO_ACTION_NONE;

	/* Check the header and version information */
	if( isServer )
		{
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  TLS_HAND_CLIENT_HELLO,
									  VERSIONINFO_SIZE + TLS_NONCE_SIZE + \
										1 + ( UINT16_SIZE * 2 ) + 1 + 1 );
		}
	else
		{
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  TLS_HAND_SERVER_HELLO,
									  VERSIONINFO_SIZE + TLS_NONCE_SIZE + \
										1 + UINT16_SIZE + 1 );
		}
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	status = processVersionInfo( sessionInfoPtr, stream, &value, FALSE );
	if( cryptStatusError( status ) )
		return( status );
	if( isServer )
		handshakeInfo->clientOfferedVersion = value;
	else
		sessionInfoPtr->version = value;

	/* Since we now know which protocol version we're using, we can turn off
	   any hashing that we don't require any more */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		if( handshakeInfo->md5context != CRYPT_ERROR )
			{
			krnlSendNotifier( handshakeInfo->md5context,
							  IMESSAGE_DECREFCOUNT );
			handshakeInfo->md5context = CRYPT_ERROR;
			krnlSendNotifier( handshakeInfo->sha1context,
							  IMESSAGE_DECREFCOUNT );
			handshakeInfo->sha1context = CRYPT_ERROR;
			}
		}
	else
		{
		if( handshakeInfo->sha2context != CRYPT_ERROR )
			{
			krnlSendNotifier( handshakeInfo->sha2context,
							  IMESSAGE_DECREFCOUNT );
			handshakeInfo->sha2context = CRYPT_ERROR;
			}
#ifdef CONFIG_SUITEB
		if( handshakeInfo->sha384context != CRYPT_ERROR )
			{
			krnlSendNotifier( handshakeInfo->sha384context,
							  IMESSAGE_DECREFCOUNT );
			handshakeInfo->sha384context = CRYPT_ERROR;
			}
#endif /* CONFIG_SUITEB */
		}

	/* Process the nonce and session ID */
	REQUIRES( rangeCheck( TLS_NONCE_SIZE, 1, TLS_NONCE_SIZE ) );
	status = sread( stream, isServer ? \
						handshakeInfo->clientNonce : \
						handshakeInfo->serverNonce, TLS_NONCE_SIZE );
	if( cryptStatusOK( status ) )
		status = processSessionID( sessionInfoPtr, handshakeInfo, stream );
	if( cryptStatusError( status ) )
		{
		if( status != OK_SPECIAL )
			return( status );

		/* This is potentially a resumed session */
		potentiallyResumedSession = TRUE;
		}
	if( !isServer && \
		!memcmp( handshakeInfo->serverNonce + TLS_DOWNGRADEID_OFFSET, 
				 TLS_DOWNGRADEID_PREFIX, TLS_DOWNGRADEID_PREFIX_SIZE ) )
		{
		/* The server has sent a nonce with a downgrade-protection value
		   present, make sure that the ID value matches the TLS version that
		   we asked for.  For example if we asked for TLS 1.3 and got back
		   the value for TLS 1.2 then we know that there's been a downgrade
		   attack.

		   The ID relies on arbitrarily-chosen magic values, 1 for TLS 1.2 
		   and 0 for TLS 1.1 or below.  Conversely, TLS 1.3 isn't signalled 
		   at all */
		if( ( sessionInfoPtr->version == TLS_MINOR_VERSION_TLS12 && \
			  handshakeInfo->serverNonce[ TLS_NONCE_SIZE - 1 ] != 1 ) || \
			( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 && \
			  handshakeInfo->serverNonce[ TLS_NONCE_SIZE - 1 ] != 0 ) )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
					  "Downgrade protection in server hello indicates a "
					  "dowgrade from negotiated TLS 1.%d", 
					  sessionInfoPtr->version - 1 ) );
			}
		}

	/* Process the cipher suite information */
	if( isServer )
		{
		/* We're reading the client hello, the packet contains a
		   selection of suites preceded by a suite count */
		status = suiteLength = readUint16( stream );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid cipher suite information" ) );
			}
		if( suiteLength < UINT16_SIZE || \
			suiteLength > ( UINT16_SIZE * MAX_CIPHERSUITES ) || \
			( suiteLength % UINT16_SIZE ) != 0 )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid cipher suite length %d, should be %d...%d", 
					  suiteLength, UINT16_SIZE, 
					  UINT16_SIZE * MAX_CIPHERSUITES ) );
			}
		suiteLength /= UINT16_SIZE;
		}
	else
		{
		/* The server has sent a single quite in response to our hello */
		suiteLength = 1;
		}
	status = processCipherSuite( sessionInfoPtr, handshakeInfo, stream,
								 suiteLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the compression suite information.  Since we don't implement
	   compression all that we need to do is check that the format is valid
	   and then skip the suite information */
	if( isServer )
		{
		/* We're reading the client hello, the packet contains a selection 
		   of suites preceded by a suite count */
		status = suiteLength = sgetc( stream );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid compression suite information" ) );
			}
		if( suiteLength < 1 || suiteLength > 20 )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid compression suite length %d, should be "
					  "1...20", suiteLength ) );
			}
		}
	else
		{
		/* The server has sent a single quite in response to our hello */
		suiteLength = 1;
		}
	status = sSkip( stream, suiteLength, MAX_INTLENGTH_SHORT );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid compression algorithm information" ) );
		}

	/* If there's extra data present at the end of the packet, check for TLS
	   extension data */
	if( endPos - stell( stream ) > 0 )
		{
		const int extensionLength = endPos - stell( stream );

		if( !isShortIntegerRangeMin( extensionLength, UINT16_SIZE ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "TLS hello contains %d bytes extraneous data", 
					  extensionLength ) );
			}
		status = readExtensions( stream, sessionInfoPtr, handshakeInfo, 
								 actionType, extensionLength );
		if( cryptStatusError( status ) )
			{
			/* In the case of TLS 1.3 where the keyex is handled via data 
			   stuffed into extensions we can end up with no usable keyex 
			   information present, in which case we have to tell the client 
			   to guess again (seriously! That's how the protocol works) */
#ifdef USE_TLS13
			if( status != OK_SPECIAL )
				return( status );

			ENSURES( *actionType == TLSHELLO_ACTION_RETRY );
#else
			return( status );
#endif /* USE_TLS13 */
			}
		handshakeInfo->flags |= HANDSHAKE_FLAG_HASEXTENSIONS;
		}

	/* If we're the server, perform any special-case handling required by 
	   the fact that the selection of an ECC cipher suite can be 
	   retroactively modified by TLS extensions that disable its use 
	   again */
	if( isServer )
		{
		if( handshakeInfo->disableECC )
			{
			/* If the only available suite is an ECC one but it's been 
			   disabled through an incompatible choice of client-selected 
			   algorithm parameters then we can't continue */
			if( isEccAlgo( handshakeInfo->keyexAlgo ) )
				{
				retExt( CRYPT_ERROR_NOTAVAIL,
						( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
						  "Client specified use of an ECC cipher suite but "
						  "didn't provide any compatible ECC parameters" ) );
				}
			}
		else
			{
			/* If the client has chosen an ECC suite and it hasn't 
			   subsequently been disabled by an incompatible choice of 
			   client-selected parameters, and conversely it hasn't already
			   been set because no standard suites were available, switch to 
			   the ECC suite.
			   
			   If PREFER_ECC is set then we unconditionally prefer ECC 
			   suites, if not then we only prefer them if a non-PFS keyex 
			   algorithm has been selected */
#ifdef PREFER_ECC
			if( handshakeInfo->fallbackType != TLS_FALLBACK_ECC && \
				handshakeInfo->eccSuiteInfoPtr != NULL )
#else
			if( handshakeInfo->fallbackType != TLS_FALLBACK_ECC && \
				handshakeInfo->eccSuiteInfoPtr != NULL && \
				!isKeyexAlgo( handshakeInfo->keyexAlgo ) )
#endif /* PREFER_ECC */
				{
				status = setSuiteInfo( sessionInfoPtr, handshakeInfo, 
									   handshakeInfo->eccSuiteInfoPtr );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* If we're using an ECC cipher suite (either due to it being 
			   the only suite available or because it was selected above) 
			   and there's no ECC group selected by the client, default to 
			   P256.  This is pretty much the universal default in any case,
			   in fact 25% of servers on the Internet will run with P256 
			   even if the client explicitly says they don't support it, see
			   "In search of CurveSwap: Measuring elliptic curve 
			   implementations in the wild" by Valenta, Sullivan, Sanso and 
			   Heninger */
			if( handshakeInfo->keyexAlgo == CRYPT_ALGO_ECDH && \
				handshakeInfo->keyexGroupInfo == NULL )
				{
				handshakeInfo->keyexGroupInfo = \
						getTLSGroupInfoEntry( TLS_GROUP_SECP256R1 );
				ENSURES( handshakeInfo->keyexGroupInfo != NULL );
				}
			}
		
		/* If we're using TLS 1.3, fix up the various issues arising from 
		   the fact that we don't know until we're finished processing all
		   of the extensions that it really is TLS 1.3 and not TLS 1.2 */
#ifdef USE_TLS13
		if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
			{
			DEBUG_PRINT(( "Performing TLS 1.3 fixups:\n" ));
			
			/* If we're using TLS 1.3, switch to the TLS 1.3 suite unless 
			   we've already fallen back to it because no other options were 
			   available */
			if( handshakeInfo->fallbackType != TLS_FALLBACK_TLS13 )				
				{
				if( handshakeInfo->tls13SuiteInfoPtr == NULL )
					{
					retExt( CRYPT_ERROR_NOTAVAIL,
							( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
							  "Client specified use of TLS 1.3 but did't "
							  "offer any TLS 1.3 cipher suites" ) );
					}
				DEBUG_PRINT(( "  Setting cipher suite to %s.\n",
							  handshakeInfo->tls13SuiteInfoPtr->debugText ));
				status = setSuiteInfo( sessionInfoPtr, handshakeInfo, 
									   handshakeInfo->tls13SuiteInfoPtr );
				if( cryptStatusError( status ) )
					return( status );
				} 

			/* If we got offered both TLS classic and TLS 1.3 keyex groups
			   and the TLS 1.3 option is the preferred one, switch to that
			   now */
			if( handshakeInfo->keyexTls13Preferred )
				{
				REQUIRES( handshakeInfo->keyexTls13GroupInfo != NULL );
				DEBUG_PRINT_COND( handshakeInfo->keyexGroupInfo != NULL,
								  ( "  Replacing %s keyex with more preferred "
								    "TLS 1.3 %s.\n",
								    handshakeInfo->keyexGroupInfo->description,
								    handshakeInfo->keyexTls13GroupInfo->description ) );
				handshakeInfo->keyexGroupInfo = \
							handshakeInfo->keyexTls13GroupInfo;
				}
			handshakeInfo->keyexTls13GroupInfo = NULL;

			/* If we're using a TLS 1.3 suite then the keyex authentication
			   algorithm isn't set by the cipher suite like it is for TLS 
			   classic, so we have to set it explicitly based on the server 
			   key being used */
			if( handshakeInfo->authAlgo == CRYPT_ALGO_NONE && \
				sessionInfoPtr->privateKey != CRYPT_ERROR )
				handshakeInfo->authAlgo = sessionInfoPtr->privateKeyAlgo;
			}
#endif /* USE_TLS13 */
		}

	/* If we're the server and the client requested a TLS 1.2-only extension
	   and we're not talking TLS 1.2, disable it */
	if( isServer && sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		{
		CLEAR_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS );
		handshakeInfo->flags &= ~HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE;
		}

	/* If we're the server and we're being scanned, make sure that we don't
	   agree to anything that will trigger the scanner.  If we can detect 
	   this in advance then we simply skip the suite in processCipherSuite(),
	   but if the detection is done via extensions, which follow the cipher
	   suites, then we can't do it at that point and have to reject the
	   handshake attempt here.  This works because the triggering suites are
	   all less-preferred ones so if the following check passes then the 
	   only suites offered were triggering ones */
	if( isServer && ( handshakeInfo->flags & HANDSHAKE_FLAG_ISSCANNER ) && \
		( handshakeInfo->cipherSuiteFlags & CIPHERSUITE_FLAG_TRIGGER ) )
		{
		DEBUG_PRINT(( "  Aborting handshake to avoid triggering a bogus "
					  "vulnerability warning from a scanner.\n" ));
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "No encryption mechanism compatible with the remote "
				  "system could be found" ) );
		}

	/* If we've eventually ended up with a GCM suite, typically in 
	   conjunction with an ECC suite, turn off encrypt-then-MAC in case it 
	   was selected */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		CLEAR_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_ENCTHENMAC );
		if( isServer )
			handshakeInfo->flags &= ~HANDSHAKE_FLAG_NEEDETMRESPONSE;
		}

	/* If we're using TLS 1.3 and the peer didn't send any keyex data and
	   we're not allowing a retry of the Client Hello, we can't continue */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 && \
		handshakeInfo->tls13KeyexValueLen <= 0 && \
		*actionType != TLSHELLO_ACTION_RETRY )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "%s specified use of TLS 1.3 but did't provide "
				  "any keyex data", isServer ? "Server" : "Client" ) );
		}
#endif /* USE_TLS13 */

	/* If we're using Suite B and the MAC algorithm is an extended 
	   HMAC-SHA-2 algorithm (which means that the hash algorithm will also 
	   be extended SHA-2), replace the straight SHA2 context with the 
	   extended version */
#ifdef CONFIG_SUITEB
	if( sessionInfoPtr->integrityAlgo == CRYPT_ALGO_HMAC_SHA2 && \
		handshakeInfo->integrityAlgoParam == bitsToBytes( 384 ) )
		{
		krnlSendNotifier( handshakeInfo->sha2context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->sha2context = handshakeInfo->sha384context;
		handshakeInfo->sha384context = CRYPT_ERROR;
		}
#endif /* CONFIG_SUITEB */

	/* If we need to get the client to retry the Client Hello, let the 
	   caller know */
#ifdef USE_TLS13
	if( *actionType == TLSHELLO_ACTION_RETRY )
		return( OK_SPECIAL );
#endif /* USE_TLS13 */

	/* If it's a resumed session let the caller know.  The check is version-
	   dependent since TLS 1.3 handles session resumption differently but 
	   fakes standard TLS session resumption mechanisms to appear like 
	   TLS 1.2 */
	if( sessionInfoPtr->version <= TLS_MINOR_VERSION_TLS12 && \
		potentiallyResumedSession )
		{
		*actionType = TLSHELLO_ACTION_RESUMEDSESSION;
		return( OK_SPECIAL );
		}

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
