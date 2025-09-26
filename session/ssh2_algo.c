/****************************************************************************
*																			*
*				cryptlib SSHv2 Algorithm Information Processing				*
*						Copyright Peter Gutmann 1998-2021					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH

/* Tables mapping SSHv2 algorithm names to cryptlib algorithm IDs, in 
   preferred algorithm order. 

   ECC support by SSH implementations is rather hit-and-miss.  If we were to 
   advertise ECC only (which we never do), some servers will respond with 
   RSA/DSA keys (even though they're not specified as being supported), and 
   others will respond with an empty host key.
   
   In addition the algorithms aren't just algorithm values but a combination 
   of the algorithm, the key size, and the hash algorithm, with 
   CRYPT_ALGO_ECDH/CRYPT_ALGO_ECDSA being the default P256 curve with 
   SHA-256.  Because the curve types are tied to the oddball SHA-2 hash 
   variants (we can't just use SHA-256 for every curve), we don't support 
   P384 and P512 because we'd have to support an entirely new (and 64-bit-
   only) hash algorithm for each of the curves.

   Some algorithms also have additional parameters, specifically the OpenSSH-
   invented EtM variants for which the numeric parameter is a flag indicating
   whether EtM is being used.

   SSH has multiple ways to specify the same keyex algorithm, either
   negotiated via "diffie-hellman-group-exchange-sha256" and 
   "diffie-hellman-group-exchange-sha1" or explicitly as
   "diffie-hellman-group14-sha256" and "diffie-hellman-group14-sha1".  
   We distinguish between DH + SHA1/SHA256 and DH + SHA1/SHA256 via the
   addition of an algorithm parameter, which contains the DH key size for 
   the selected fixed group.  
   
   We don't support the 1024-bit DH group even though it's mandatory because
   it's too obvious a target for an offline attack and (more annoyingly)
   vulnerability scanners will report it as insecure whether it really is or
   not.  Unfortunately this presents a problem with assorted Cisco security 
   appliances which are secure by executive fiat rather than by design, 
   supporting only "diffie-hellman-group1-sha1", and not even the mandatory-
   to-support "diffie-hellman-group14-sha1" let alone the group-exchange 
   suites.

   Another issue exists around the use of OpenSSH fashion-statement 
   mechanisms like EtM (at least as specified by OpenSSH) and ChaCha20-
   Poly1305, which are vulnerable to the Terrapin attack.  We aren't 
   vulnerable because we either don't support the vulnerable mechanism 
   (ChaCha20) or only enable it for testing and fuzzing (EtM).  However if 
   these are ever added and enabled then the OpenSSH countermeasures to the 
   OpenSSH-created vulnerability have to be applied, see
   https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=1.55
   section 1.10.

		"Once again, the Wellington Police have come up with a perfect
		solution to the problem / That's right - by removing the solution we
		had to another problem / The fact that if we hadn't put that sign up
		in the first place none of this would've happened is irrelevant.
		What matters is that we've identified the problem / That we caused /
		Job well done / Good result"
			- "Wellington Paranormal".

   Specifically, with "kex-strict-c-v00@openssh.com" (client) and
   "kex-strict-s-v00@openssh.com" (server) exchanged in the SSH2_MSG_KEXINIT 
   we have to (1) retroactively check whether there were any messages before 
   the KEXINIT, (2) check whether any optional messages are added during the 
   keyex, not just the obvious SSH2_MSG_DEBUG and SSH2_MSG_IGNORE but 
   anything not relevant to the crypto exchange, and since there are 
   multiple different paths through the negotiation possible that no message 
   not strictly part of the appropriate flow is present, and (3) that we 
   keep these checks up until both sides have successfully exchanged their 
   SSH2_MSG_NEWKEYS.

   We actually do a lot of this already since we implement the handshake as 
   a ladder diagram rather than a state machine and so enforce flow-dependent
   messages, but there's still a lot of scope for getting things wrong and 
   since we're not vulnerable in the first place there doesn't seem much 
   point to adding a vulnerable mechanism and then having to patch around the
   vulnerability that we've just added */

static const ALGO_STRING_INFO algoStringKeyexTbl[] = {
#if defined( USE_ECDH ) && defined( PREFER_ECC )
	{ "ecdh-sha2-nistp256", 18, CRYPT_ALGO_ECDH, CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
#endif /* USE_ECDH && PREFER_ECC */
	{ "diffie-hellman-group-exchange-sha256", 36, CRYPT_ALGO_DH, CRYPT_ALGO_SHA2 },
	{ "diffie-hellman-group-exchange-sha1", 34, CRYPT_ALGO_DH, CRYPT_ALGO_SHA1 },
	{ "diffie-hellman-group14-sha256", 29, CRYPT_ALGO_DH, CRYPT_ALGO_SHA2, bitsToBytes( 2048 ) },
	{ "diffie-hellman-group14-sha1", 27, CRYPT_ALGO_DH, CRYPT_ALGO_SHA1, bitsToBytes( 2048 ) },
#if defined( USE_ECDH ) && !defined( PREFER_ECC ) 
	{ "ecdh-sha2-nistp256", 18, CRYPT_ALGO_ECDH, CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
#endif /* USE_ECDH && !PREFER_ECC */
	{ NULL, 0, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0 }, 
		{ NULL, 0, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0 }
	};
static const ALGO_STRING_INFO algoStringKeyexNoECCTbl[] = {
	{ "diffie-hellman-group-exchange-sha256", 36, CRYPT_ALGO_DH, CRYPT_ALGO_SHA2 },
	{ "diffie-hellman-group-exchange-sha1", 34, CRYPT_ALGO_DH, CRYPT_ALGO_SHA1 },
	{ "diffie-hellman-group14-sha256", 29, CRYPT_ALGO_DH, CRYPT_ALGO_SHA2, bitsToBytes( 2048 ) },
	{ "diffie-hellman-group14-sha1", 27, CRYPT_ALGO_DH, CRYPT_ALGO_SHA1, bitsToBytes( 2048 ) },
	{ NULL, 0, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0 }, 
		{ NULL, 0, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0 }
	};

static const ALGO_STRING_INFO algoStringPubkeyTbl[] = {
#if defined( USE_ECDSA ) && defined( PREFER_ECC )
	{ "ecdsa-sha2-nistp256", 19, CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
#endif /* USE_ECDSA && PREFER_ECC */
	{ "rsa-sha2-256", 12, CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2 },
	{ "ssh-rsa", 7, CRYPT_ALGO_RSA, CRYPT_ALGO_SHA1 },
#ifdef USE_DSA
	{ "ssh-dss", 7, CRYPT_ALGO_DSA, CRYPT_ALGO_SHA1 },
#endif /* USE_DSA */
#if defined( USE_ECDSA ) && !defined( PREFER_ECC )
	{ "ecdsa-sha2-nistp256", 19, CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
#endif /* USE_ECDSA && !PREFER_ECC */
	{ NULL, 0, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0 }, 
		{ NULL, 0, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 0 }
	};

static const ALGO_STRING_INFO algoStringEncrTbl[] = {
	{ "aes128-cbc", 10, CRYPT_ALGO_AES, CRYPT_MODE_CBC, bitsToBytes( 128 ) },
	{ "aes256-cbc", 10, CRYPT_ALGO_AES, CRYPT_MODE_CBC, bitsToBytes( 256 ) },
#ifdef USE_SSH_CTR
	{ "aes128-ctr", 10, CRYPT_ALGO_AES, CRYPT_MODE_ECB, bitsToBytes( 128 ) },
	{ "aes256-ctr", 10, CRYPT_ALGO_AES, CRYPT_MODE_ECB, bitsToBytes( 256 ) },
#endif /* USE_SSH_CTR */
#ifdef USE_3DES
	{ "3des-cbc", 8, CRYPT_ALGO_3DES, CRYPT_MODE_CBC, bitsToBytes( 192 ) },
#endif /* USE_3DES */
	{ NULL, 0, CRYPT_ALGO_NONE }, { NULL, 0, CRYPT_ALGO_NONE }
	};

static const ALGO_STRING_INFO algoStringMACTbl[] = {
	{ "hmac-sha2-256", 13, CRYPT_ALGO_HMAC_SHA2 },
#ifdef USE_SSH_OPENSSH
	{ "hmac-sha2-256-etm@openssh.com", 29, CRYPT_ALGO_HMAC_SHA2, 0, TRUE },
#endif /* USE_SSH_OPENSSH */
	{ "hmac-sha1", 9, CRYPT_ALGO_HMAC_SHA1 },
#ifdef USE_SSH_OPENSSH
	{ "hmac-sha1-etm@openssh.com", 25, CRYPT_ALGO_HMAC_SHA1, 0, TRUE },
#endif /* USE_SSH_OPENSSH */
	{ NULL, 0, CRYPT_ALGO_NONE }, { NULL, 0, CRYPT_ALGO_NONE }
	};

static const ALGO_STRING_INFO algoStringCoprTbl[] = {
	{ "none", 4, CRYPT_ALGO_AES /* Always-valid placeholder */ },
	{ NULL, 0, CRYPT_ALGO_NONE }, { NULL, 0, CRYPT_ALGO_NONE }
	};

/* A grand unified version of the above, used to write algorithm names */

static const ALGO_STRING_INFO algoStringMapTbl[] = {
	/* Keyex algorithms */
	{ "diffie-hellman-group-exchange-sha256", 36, CRYPT_ALGO_DH, CRYPT_ALGO_SHA2 },
	{ "diffie-hellman-group-exchange-sha1", 34, CRYPT_ALGO_DH, CRYPT_ALGO_SHA1 },
	{ "diffie-hellman-group14-sha256", 29, CRYPT_ALGO_DH, CRYPT_ALGO_SHA2, bitsToBytes( 2048 ) },
	{ "diffie-hellman-group14-sha1", 27, CRYPT_ALGO_DH, CRYPT_ALGO_SHA1, bitsToBytes( 2048 ) },
#ifdef USE_ECDH
	{ "ecdh-sha2-nistp256", 18, CRYPT_ALGO_ECDH, CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
#endif /* USE_ECDH */

	/* Signature algorithms */
	{ "rsa-sha2-256", 12, CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2 },
	{ "ssh-rsa", 7, CRYPT_ALGO_RSA, CRYPT_ALGO_SHA1 },
#ifdef USE_DSA
	{ "ssh-dss", 7, CRYPT_ALGO_DSA, CRYPT_ALGO_SHA1 },
#endif /* USE_DSA */
#ifdef USE_ECDSA
	{ "ecdsa-sha2-nistp256", 19, CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, bitsToBytes( 256 ) },
#endif /* USE_ECDSA */

	/* Encryption algorithms */
	{ "aes128-cbc", 10, CRYPT_ALGO_AES, CRYPT_MODE_CBC, bitsToBytes( 128 ) },
	{ "aes256-cbc", 10, CRYPT_ALGO_AES, CRYPT_MODE_CBC, bitsToBytes( 256 ) },
#ifdef USE_SSH_CTR
	{ "aes128-ctr", 10, CRYPT_ALGO_AES, CRYPT_MODE_ECB, bitsToBytes( 128 ) },
	{ "aes256-ctr", 10, CRYPT_ALGO_AES, CRYPT_MODE_ECB, bitsToBytes( 256 ) },
#endif /* USE_SSH_CTR */
#ifdef USE_3DES
	{ "3des-cbc", 8, CRYPT_ALGO_3DES, CRYPT_MODE_CBC, bitsToBytes( 192 ) },
#endif /* USE_3DES */

	/* MAC algorithms */
	{ "hmac-sha2-256", 13, CRYPT_ALGO_HMAC_SHA2 },
#ifdef USE_SSH_OPENSSH
	{ "hmac-sha2-256-etm@openssh.com", 29, CRYPT_ALGO_HMAC_SHA2, 0, TRUE },
#endif /* USE_SSH_OPENSSH */
	{ "hmac-sha1", 9, CRYPT_ALGO_HMAC_SHA1 },
#ifdef USE_SSH_OPENSSH
	{ "hmac-sha1-etm@openssh.com", 25, CRYPT_ALGO_HMAC_SHA1, 0, TRUE },
#endif /* USE_SSH_OPENSSH */

	{ NULL, 0, CRYPT_ALGO_NONE }, { NULL, 0, CRYPT_ALGO_NONE }
	};

/****************************************************************************
*																			*
*							Read Algorithm Information						*
*																			*
****************************************************************************/

/* Convert an SSH algorithm list to a cryptlib ID in preferred-algorithm 
   order.  For some bizarre reason the algorithm information is communicated 
   as a comma-delimited list stuffed inside what's otherwise a binary 
   protocol, so we have to unpack and pack them into this cumbersome format 
   alongside just choosing which algorithm to use.  
   
   In addition the algorithm selection mechanism differs depending on whether 
   we're the client or the server, and what set of algorithms we're matching.  
   Unlike TLS, which uses the offered-suites/chosen-suites mechanism, in SSH 
   both sides offer a selection of cipher suites and then the server chooses 
   the first one that appears on both it and the client's list, with special-
   case handling for the keyex and signature algorithms if the match isn't 
   the first one on the list.  This means that the client can choose as it 
   pleases from the server's list if it waits for the server hello (see the 
   comment in the client/server hello handling code on the annoying nature 
   of this portion of the SSH handshake) but the server has to perform a 
   complex double-match of its own vs.the client's list.  The cases that we 
   need to handle are:

	BEST_MATCH: Get the best matching algorithm (that is, the one 
		corresponding to the strongest crypto mechanism), used by the client 
		to match the server.

	FIRST_MATCH: Get the first matching algorithm, used by the server to 
		match the client.

	FIRST_MATCH_WARN: Get the first matching algorithm and warn if it isn't 
		the first one on the list of possible algorithms, used by the server 
		to match the client for the keyex and public-key algorithms.

   This is a sufficiently complex and screwball function that we need to
   define a composite structure to pass all of the control information in
   and out */

typedef enum {
	GETALGO_NONE,			/* No match action */
	GETALGO_FIRST_MATCH,	/* Get first matching algorithm */
	GETALGO_FIRST_MATCH_WARN,/* Get first matching algo, warn if not first */
	GETALGO_BEST_MATCH,		/* Get best matching algorithm */
	GETALGO_LAST			/* Last possible match action */
	} GETALGO_TYPE;

typedef struct {
	/* Match information passed in by the caller */
	ARRAY_FIXED( noAlgoInfoEntries ) \
	const ALGO_STRING_INFO *algoInfo;/* Algorithm selection information */
	int noAlgoInfoEntries;
	CRYPT_ALGO_TYPE preferredAlgo;	/* Preferred algo for first-match */
	GETALGO_TYPE getAlgoType;		/* Type of match to perform */
	BOOLEAN allowECC;				/* Whether to allow ECC algos */
	BOOLEAN allowExtIndicator;		/* Whether to allow extension indicator */

	/* Information returned by the read-algorithm function */
	CRYPT_ALGO_TYPE algo;			/* Matched algorithm */
	CRYPT_ALGO_TYPE subAlgo;		/* Sub-algorithm (e.g. hash for keyex) */
	int parameter;					/* Optional algorithm parameter */
	BOOLEAN prefAlgoMismatch;		/* First match != preferredAlgo */
	BOOLEAN extensionIndicator;		/* Whether extension indicator was found */
	} ALGOSTRING_INFO;

#if defined( USE_ECDH ) || defined( USE_ECDSA )
  #define ALLOW_ECC		TRUE
#else
  #define ALLOW_ECC		FALSE
#endif /* USE_ECDH || USE_ECDSA */

#define MAX_NO_SUBSTRINGS		32	/* Max.no of algorithm substrings */
#define MAX_SUBSTRING_SIZE		128	/* Max.size of each substring */

#define setAlgoStringInfo( algoStringInfo, algoStrInfo, algoStrInfoEntries, getType ) \
	{ \
	memset( ( algoStringInfo ), 0, sizeof( ALGOSTRING_INFO ) ); \
	( algoStringInfo )->algoInfo = ( algoStrInfo ); \
	( algoStringInfo )->noAlgoInfoEntries = ( algoStrInfoEntries ); \
	( algoStringInfo )->preferredAlgo = CRYPT_ALGO_NONE; \
	( algoStringInfo )->getAlgoType = ( getType ); \
	( algoStringInfo )->allowECC = ALLOW_ECC; \
	( algoStringInfo )->allowExtIndicator = FALSE; \
	}
#define setAlgoStringInfoEx( algoStringInfo, algoStrInfo, algoStrInfoEntries, prefAlgo, getType ) \
	{ \
	memset( ( algoStringInfo ), 0, sizeof( ALGOSTRING_INFO ) ); \
	( algoStringInfo )->algoInfo = ( algoStrInfo ); \
	( algoStringInfo )->noAlgoInfoEntries = ( algoStrInfoEntries ); \
	( algoStringInfo )->preferredAlgo = ( prefAlgo ); \
	( algoStringInfo )->getAlgoType = ( getType ); \
	( algoStringInfo )->allowECC = ALLOW_ECC; \
	( algoStringInfo )->allowExtIndicator = FALSE; \
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readAlgoStringEx( INOUT_PTR STREAM *stream, 
							 INOUT_PTR ALGOSTRING_INFO *algoStringInfo,
							 INOUT_PTR ERROR_INFO *errorInfo )
	{
	const ALGO_STRING_INFO *algoInfoPtr;
	BOOLEAN foundMatch = FALSE;
	void *string DUMMY_INIT_PTR;
	int stringLen, substringLen, algoIndex = 999;
	LOOP_INDEX stringPos, noStrings;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( algoStringInfo, sizeof( ALGOSTRING_INFO ) ) );
	assert( isReadPtrDynamic( algoStringInfo->algoInfo, \
							  sizeof( ALGO_STRING_INFO ) * \
									algoStringInfo->noAlgoInfoEntries ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( ( algoStringInfo->getAlgoType == GETALGO_BEST_MATCH && \
				algoStringInfo->preferredAlgo == CRYPT_ALGO_NONE ) || \
			  ( algoStringInfo->getAlgoType == GETALGO_FIRST_MATCH ) ||
			  ( algoStringInfo->getAlgoType == GETALGO_FIRST_MATCH_WARN && \
				isEnumRangeExternal( algoStringInfo->preferredAlgo, CRYPT_ALGO ) ) );
			  /* FIRST_MATCH uses CRYPT_ALGO_NONE on the first match of an
				 algorithm pair and the first algorithm chosen on the second
				 match */
	REQUIRES( algoStringInfo->noAlgoInfoEntries > 0 && \
			  algoStringInfo->noAlgoInfoEntries < 20 );
	REQUIRES( isBooleanValue( algoStringInfo->allowECC ) );
	REQUIRES( isBooleanValue( algoStringInfo->allowExtIndicator ) );

	/* Get the string length and data and make sure that it's valid */
	status = stringLen = readUint32( stream );
	if( !cryptStatusError( status ) && \
		!isShortIntegerRangeMin( stringLen, SSH2_MIN_ALGOID_SIZE ) )
		{
		/* Quick-reject check for an obviously-invalid string */
		status = CRYPT_ERROR_BADDATA;
		}
	if( !cryptStatusError( status ) )
		status = sMemGetDataBlock( stream, &string, stringLen );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, stringLen, MAX_INTLENGTH_SHORT );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid algorithm ID string" ) );
		}
	ENSURES( isShortIntegerRangeMin( stringLen, SSH2_MIN_ALGOID_SIZE ) );
	ANALYSER_HINT( string != NULL );

	/* Walk down the string looking for a recognised algorithm.  Since our
	   preference may not match the other side's preferences we have to walk
	   down the entire list to find our preferred choice:

		  stringPos			stringLen
			   |			   |
			   v			   v
		"algo1,algo2,algo3,algoN"
			   ^   ^		   ^
			   |   |		   |
			   |substrLen	   |
			   +- subStrMaxLen +

	   This works by walking an index stringPos down the string, with each 
	   substring delimited by { stringPos, subStringLen }, which is checked
	   against the table of algorithm names */
	LOOP_MED( ( noStrings = 0, stringPos = 0 ),
			  noStrings < MAX_NO_SUBSTRINGS && \
					stringPos <= stringLen - SSH2_MIN_ALGOID_SIZE,
			  ( noStrings++, stringPos += substringLen + 1 ) )
		{
		const ALGO_STRING_INFO *matchedAlgoInfo = NULL;
		const BYTE *substringPtr = ( BYTE * ) string + stringPos;
		const int substringMaxLen = stringLen - stringPos;
		BOOLEAN algoMatched = TRUE;
		int currentAlgoIndex, LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_MED( noStrings, 0, MAX_NO_SUBSTRINGS - 1 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( stringPos, 0, 
										   stringLen - SSH2_MIN_ALGOID_SIZE ) );

		/* Find the length of the next algorithm name */
		LOOP_LARGE_ALT( substringLen = 0,
						substringLen < MAX_SUBSTRING_SIZE && \
							substringLen < substringMaxLen && \
							substringPtr[ substringLen ] != ',',
						substringLen++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE_ALT( substringLen, 0, 
											   MAX_SUBSTRING_SIZE - 1 ) );
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		if( substringLen >= MAX_SUBSTRING_SIZE )
			{
			retExt( CRYPT_ERROR_OVERFLOW,
					( CRYPT_ERROR_OVERFLOW, errorInfo, 
					  "Excessively long (more than %d characters) SSH "
					  "algorithm string encountered", substringLen ) );
			}
		if( substringLen < SSH2_MIN_ALGOID_SIZE || \
			substringLen > CRYPT_MAX_TEXTSIZE )
			{
			/* Empty or too-short algorithm name (or excessively long one), 
			   continue.  Note that even with an (invalid) zero-length 
			   substring we'll still progress down the string since the loop
			   increment is the substring length plus one */
			continue;
			}

		/* Check for the presence of the special-case extension-info 
		   indicator if required.  At the moment we only respond to a 
		   client-side extension indicator so we don't need to distinguish 
		   between which type we look for */
#ifdef USE_SSH_EXTENDED
		if( algoStringInfo->allowExtIndicator )
			{
			if( substringLen == 10 && \
				!memcmp( substringPtr, "ext-info-c", 10 ) )
				{
				algoStringInfo->extensionIndicator = TRUE;

				/* If we've already found matching algorithm information, 
				   we're done */
				if( foundMatch )
					break;

				continue;
				}

			/* If we've already found a match then all that we're looking 
			   for is the extension information indicator */
			if( foundMatch )
				continue;
			}
#endif /* USE_SSH_EXTENDED */

		/* Check whether it's something that we can handle */
		LOOP_MED_ALT( currentAlgoIndex = 0, 
					  currentAlgoIndex < algoStringInfo->noAlgoInfoEntries && \
						algoStringInfo->algoInfo[ currentAlgoIndex ].name != NULL,
					  currentAlgoIndex++ )
			{
			const ALGO_STRING_INFO *algoStringInfoPtr;

			ENSURES( LOOP_INVARIANT_MED_ALT( currentAlgoIndex, 0, 
											 algoStringInfo->noAlgoInfoEntries - 1 ) );

			algoStringInfoPtr = &algoStringInfo->algoInfo[ currentAlgoIndex ];
			if( algoStringInfoPtr->nameLen == substringLen && \
				!memcmp( algoStringInfoPtr->name, substringPtr, substringLen ) )
				{
				matchedAlgoInfo = algoStringInfoPtr;
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		ENSURES( currentAlgoIndex < algoStringInfo->noAlgoInfoEntries );
		if( matchedAlgoInfo == NULL )
			{
			/* Unrecognised algorithm name, remember to warn the caller if 
			   we have to match the first algorithm on the list, then move 
			   on to the next name */
			if( algoStringInfo->getAlgoType == GETALGO_FIRST_MATCH_WARN )
				algoStringInfo->prefAlgoMismatch = TRUE;
			continue;
			}
		DEBUG_PRINT(( "Offered suite: %s.\n", matchedAlgoInfo->name ));

		/* If it's an actual algorithm (rather than an authenticaiton 
		   mechanism name, for which there's no algorithm type), make sure 
		   that the required algorithms and optional sub-algorithms are 
		   available */
		if( matchedAlgoInfo->algo != CRYPT_ALGO_NONE )
			{
			if( !algoAvailable( matchedAlgoInfo->algo ) )
				algoMatched = FALSE;

			/* We don't check the sub-algorithm type for the conventional 
			   algorithms because in this case it's an encryption mode, not 
			   an algorithm */
			if( !isConvAlgo( matchedAlgoInfo->algo ) && \
				matchedAlgoInfo->subAlgo != CRYPT_ALGO_NONE && \
				!algoAvailable( matchedAlgoInfo->subAlgo ) )
				algoMatched = FALSE;
			}

		/* If this is an ECC algorithm and the use of ECC algorithms has 
		   been prevented by external conditions such as the server key
		   not being an ECC key, we can't use it even if ECC algorithms in
		   general are available */
		if( algoMatched && !algoStringInfo->allowECC && \
			isEccAlgo( matchedAlgoInfo->algo ) )
			algoMatched = FALSE;

		/* If the matched algorithm isn't available, remember to warn the 
		   caller if we have to match the first algorithm on the list, then 
		   move on to the next name */
		if( !algoMatched )
			{
			if( algoStringInfo->getAlgoType == GETALGO_FIRST_MATCH_WARN )
				algoStringInfo->prefAlgoMismatch = TRUE;
			continue;
			}

		switch( algoStringInfo->getAlgoType )
			{
			case GETALGO_BEST_MATCH:
				/* If we're looking for the best (highest-ranked algorithm)
				   match, see whether the current match ranks higher than
				   the existing one */
				if( currentAlgoIndex < algoIndex )
					{
					algoIndex = currentAlgoIndex;
					if( algoIndex <= 0 )
						foundMatch = TRUE;	/* Gruener werd's net */
					DEBUG_PRINT(( "Accepted suite: %s.\n", 
								  matchedAlgoInfo->name ));
					}
				break;

			case GETALGO_FIRST_MATCH:
				/* If we've found an acceptable algorithm, remember it and
				   exit */
				if( algoStringInfo->preferredAlgo == CRYPT_ALGO_NONE || \
					algoStringInfo->preferredAlgo == matchedAlgoInfo->algo )
					{
					algoIndex = currentAlgoIndex;
					foundMatch = TRUE;
					DEBUG_PRINT(( "Accepted suite: %s.\n", 
								  matchedAlgoInfo->name ));
					}
				break;

			case GETALGO_FIRST_MATCH_WARN:
				/* If we found the algorithm that we're after, remember it
				   and exit */
				if( algoStringInfo->preferredAlgo != matchedAlgoInfo->algo )
					{
					/* We didn't match the first algorithm on the list, warn
					   the caller */
					algoStringInfo->prefAlgoMismatch = TRUE;
					DEBUG_PRINT(( "Accepted suite: %s.\n", 
								  matchedAlgoInfo->name ));
					}
				algoIndex = currentAlgoIndex;
				foundMatch = TRUE;
				break;

			default:
				retIntError();
			}

		/* If we've found a match, we're done unless we're looking for an 
		   extension-info indicator, in which case we have to parse the 
		   entire string */
		if( foundMatch && !algoStringInfo->allowExtIndicator )
			break;	
		}
	ENSURES( LOOP_BOUND_OK );
	if( noStrings >= MAX_NO_SUBSTRINGS )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, errorInfo, 
				  "Excessive number (more than %d) of SSH algorithm "
				  "strings encountered", noStrings ) );
		}
	if( algoIndex > 50 )	/* Initialisated to 999 at start */
		{
		char algoString[ 256 + 8 ];
		const int algoStringLen = min( stringLen, \
									   min( MAX_ERRMSG_SIZE - 80, 256 ) );

		REQUIRES( algoStringLen > 0 && \
				  algoStringLen <= min( MAX_ERRMSG_SIZE - 80, 256 ) );

		/* We couldn't find anything to use, tell the caller what was
		   available */
		REQUIRES( rangeCheck( algoStringLen, 1, 256 ) );
		memcpy( algoString, string, algoStringLen );
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, errorInfo, 
				  "No algorithm compatible with the remote system's "
				  "selection was found: '%s'", 
				  sanitiseString( algoString, 256, stringLen ) ) );
		}

	/* We found a more-preferred algorithm than the default, go with that */
	algoInfoPtr = &algoStringInfo->algoInfo[ algoIndex ];
	algoStringInfo->algo = algoInfoPtr->algo;
	algoStringInfo->subAlgo = algoInfoPtr->subAlgo;
	algoStringInfo->parameter = algoInfoPtr->parameter;
	DEBUG_PRINT(( "Final accepted suite: %s.\n", algoInfoPtr->name ));

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 6 ) ) \
int readAlgoString( INOUT_PTR STREAM *stream, 
					IN_ARRAY( noAlgoStringEntries ) \
						const ALGO_STRING_INFO *algoInfo,
					IN_RANGE( 1, 100 ) const int noAlgoStringEntries, 
					OUT_INT_SHORT_Z int *algoParam, 
					IN_BOOL const BOOLEAN useFirstMatch, 
					INOUT_PTR ERROR_INFO *errorInfo )
	{
	ALGOSTRING_INFO algoStringInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( algoInfo, sizeof( ALGO_STRING_INFO ) * \
								 noAlgoStringEntries ) );
	assert( isWritePtr( algoParam, sizeof( int ) ) );

	REQUIRES( noAlgoStringEntries > 0 && noAlgoStringEntries <= 100 );
	REQUIRES( isBooleanValue( useFirstMatch ) );

	/* Clear return value */
	*algoParam = CRYPT_ERROR;

	setAlgoStringInfo( &algoStringInfo, algoInfo, noAlgoStringEntries, 
					   useFirstMatch ? GETALGO_FIRST_MATCH : \
									   GETALGO_BEST_MATCH );
	status = readAlgoStringEx( stream, &algoStringInfo, errorInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Algorithm strings usually encode an algorithm type, however SSH also
	   encodes authentication mechanisms, which don't correspond to any
	   actual algorithm, in string form.  In this case the returned 
	   algorithm type is CRYPT_ALGO_NONE and the subAlgorithm contains the
	   authentication mechanism type */
	if( algoStringInfo.algo == CRYPT_ALGO_NONE )
		*algoParam = algoStringInfo.subAlgo;
	else
		*algoParam = algoStringInfo.algo;

	return( CRYPT_OK );
	}

/* Algorithms used to protect data packets are used in pairs, one for
   incoming and the other for outgoing data.  To keep things simple we
   always force these to be the same, first reading the algorithm for one
   direction and then making sure that the one for the other direction
   matches this.  All implementations seem to do this anyway, many aren't
   even capable of supporting asymmetric algorithm choices */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5, 6, 9 ) ) \
static int readAlgoStringPair( INOUT_PTR STREAM *stream, 
							   IN_ARRAY( noAlgoStringEntries ) \
									const ALGO_STRING_INFO *algoInfo,
							   IN_RANGE( 1, 100 ) const int noAlgoStringEntries,
							   OUT_ALGO_Z CRYPT_ALGO_TYPE *algo, 
							   OUT_ENUM_OPT( CRYPT_MODE ) CRYPT_MODE_TYPE *mode,
							   OUT_INT_SHORT_Z int *parameter,
							   IN_BOOL const BOOLEAN isServer,
							   IN_BOOL const BOOLEAN allowAsymmetricAlgos,
							   INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_ALGO_TYPE pairPreferredAlgo;
	ALGOSTRING_INFO algoStringInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( algoInfo, sizeof( ALGO_STRING_INFO ) * \
								 noAlgoStringEntries ) );
	assert( isWritePtr( algo, sizeof( CRYPT_ALGO_TYPE ) ) );

	REQUIRES( noAlgoStringEntries > 0 && noAlgoStringEntries <= 100 );
	REQUIRES( isBooleanValue( isServer ) );
	REQUIRES( isBooleanValue( allowAsymmetricAlgos ) );

	/* Clear return values */
	*algo = CRYPT_ALGO_NONE;
	*mode = CRYPT_MODE_NONE;
	*parameter = 0;

	/* Get the first algorithm */
	setAlgoStringInfo( &algoStringInfo, algoInfo, noAlgoStringEntries, 
					   isServer ? GETALGO_FIRST_MATCH : \
								  GETALGO_BEST_MATCH );
	status = readAlgoStringEx( stream, &algoStringInfo, errorInfo );
	if( cryptStatusError( status ) )
		return( status );
	pairPreferredAlgo = algoStringInfo.algo;

	/* Get the matched second algorithm.  Some buggy implementations request
	   mismatched algorithms (at the moment this is only for compression 
	   algorithms) but have no problems in accepting the same algorithm in 
	   both directions, so if we're talking to one of these then we ignore 
	   an algorithm mismatch */
	setAlgoStringInfoEx( &algoStringInfo, algoInfo, noAlgoStringEntries,
						 pairPreferredAlgo, GETALGO_FIRST_MATCH );
	status = readAlgoStringEx( stream, &algoStringInfo, errorInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( pairPreferredAlgo != algoStringInfo.algo && !allowAsymmetricAlgos )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Client algorithm %s doesn't match server algorithm %s "
				  "in algorithm pair", getAlgoName( pairPreferredAlgo ), 
				  getAlgoName( algoStringInfo.algo ) ) );
		}
	*algo = algoStringInfo.algo;
	*mode = ( CRYPT_MODE_TYPE ) algoStringInfo.subAlgo;
	*parameter = algoStringInfo.parameter;

	return( status );
	}

/****************************************************************************
*																			*
*							Write Algorithm Information						*
*																			*
****************************************************************************/

/* Write a cryptlib algorithm ID as an SSH algorithm name */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoStringEx( INOUT_PTR STREAM *stream, 
					   IN_ALGO const CRYPT_ALGO_TYPE algo,
					   IN_INT_SHORT_Z const int subAlgo,
					   IN_INT_SHORT_OPT const int parameter,
					   IN_ENUM_OPT( SSH_ALGOSTRINGINFO ) \
							const SSH_ALGOSTRINGINFO_TYPE algoStringInfo )
	{
	LOOP_INDEX algoIndex;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( isEnumRangeExternal( algo, CRYPT_ALGO ) );
	REQUIRES( isEnumRangeExternalOpt( subAlgo, CRYPT_ALGO ) || \
			  isEnumRange( subAlgo, CRYPT_MODE ) );
	REQUIRES( ( isConvAlgo( algo ) && isShortIntegerRange( parameter ) ) || \
			  ( isMacAlgo( algo ) && \
				( ( parameter == TRUE ) || ( parameter == FALSE ) ) ) || \
			  ( parameter == CRYPT_UNUSED ) );
	REQUIRES( isEnumRangeOpt( algoStringInfo, SSH_ALGOSTRINGINFO ) );

	/* Locate the name for this algorithm and optional sub-algoritihm and 
	   encode it as an SSH string */
	LOOP_MED( algoIndex = 0, 
			  algoIndex < FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
											  ALGO_STRING_INFO ) && \
					algoStringMapTbl[ algoIndex ].algo != CRYPT_ALGO_NONE && \
					algoStringMapTbl[ algoIndex ].algo != algo,
			  algoIndex++ )
		{
		ENSURES( LOOP_INVARIANT_MED( algoIndex, 0, 
									 FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
														 ALGO_STRING_INFO ) - 1 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( algoIndex < FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
											 ALGO_STRING_INFO ) );
	ENSURES( algoStringMapTbl[ algoIndex ].algo == algo );

	/* If there are two algorithm groups (which occurs for the 
	   schizophrenically-specified keyex algorithms) then we may need to 
	   write the name from the second group rather than the first.  The
	   handling of this is somewhat ugly since it hardcodes knowledge of the
	   algorithm table, but there's no generalised way to do this without
	   adding a pile of extra complexity */
	if( algoStringInfo == SSH_ALGOSTRINGINFO_EXTINFO_ALTDHALGOS )
		{
		REQUIRES( algoIndex + 2 < FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
													  ALGO_STRING_INFO ) );
		REQUIRES( algoStringMapTbl[ algoIndex ].algo == \
						algoStringMapTbl[ algoIndex + 2 ].algo );
		REQUIRES( algoStringMapTbl[ algoIndex ].subAlgo == \
						algoStringMapTbl[ algoIndex + 2 ].subAlgo );
		algoIndex += 2;
		}

	/* If there's a sub-algorithm or parameter, find the entry for that */
	if( subAlgo != CRYPT_ALGO_NONE )
		{
		LOOP_MED_CHECKINC( algoIndex < FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
														   ALGO_STRING_INFO ) && \
								algoStringMapTbl[ algoIndex ].algo != CRYPT_ALGO_NONE && \
								algoStringMapTbl[ algoIndex ].algo == algo && \
								algoStringMapTbl[ algoIndex ].subAlgo != subAlgo,
						   algoIndex++ )
			{
			ENSURES( LOOP_INVARIANT_MED_XXX( algoIndex, 0, 
											 FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
																 ALGO_STRING_INFO ) - 1 ) );
			}
		ENSURES( LOOP_BOUND_OK );
		ENSURES( algoIndex < FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
												 ALGO_STRING_INFO ) );
		ENSURES( algoStringMapTbl[ algoIndex ].algo == algo && \
				 algoStringMapTbl[ algoIndex ].subAlgo == subAlgo );
		}
	if( parameter != CRYPT_UNUSED )
		{
		LOOP_MED_CHECKINC( algoIndex < FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
														   ALGO_STRING_INFO ) && \
								algoStringMapTbl[ algoIndex ].algo != CRYPT_ALGO_NONE && \
								algoStringMapTbl[ algoIndex ].algo == algo && \
								algoStringMapTbl[ algoIndex ].parameter != parameter,
						   algoIndex++ )
			{
			ENSURES( LOOP_INVARIANT_MED_XXX( algoIndex, 0, 
											 FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
																 ALGO_STRING_INFO ) - 1 ) );
			}
		ENSURES( LOOP_BOUND_OK );
		ENSURES( algoIndex < FAILSAFE_ARRAYSIZE( algoStringMapTbl, \
												 ALGO_STRING_INFO ) );
		ENSURES( algoStringMapTbl[ algoIndex ].algo == algo && \
				 algoStringMapTbl[ algoIndex ].parameter == parameter );
		}

	/* If we're writing an extension negotiation indicator then we need to 
	   append it to the algorithm ID.  This is always a client-side indicator
	   since we don't implement server-side extensions yet */
#ifdef USE_SSH_EXTENDED
	if( algoStringInfo == SSH_ALGOSTRINGINFO_EXTINFO || \
		algoStringInfo == SSH_ALGOSTRINGINFO_EXTINFO_ALTDHALGOS )
		{
		writeUint32( stream, algoStringMapTbl[ algoIndex ].nameLen + 11 );
		swrite( stream, algoStringMapTbl[ algoIndex ].name, 
				algoStringMapTbl[ algoIndex ].nameLen );
		return( swrite( stream, ",ext-info-c", 11 ) );
		}
#endif /* USE_SSH_EXTENDED */

	return( writeString32( stream, algoStringMapTbl[ algoIndex ].name, 
						   algoStringMapTbl[ algoIndex ].nameLen ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoString( INOUT_PTR STREAM *stream, 
					 IN_ALGO const CRYPT_ALGO_TYPE algo )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( isEnumRangeExternal( algo, CRYPT_ALGO ) );

	return( writeAlgoStringEx( stream, algo, CRYPT_ALGO_NONE, 
							   CRYPT_UNUSED, SSH_ALGOSTRINGINFO_NONE ) );
	}

/* Write a list of algorithms */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeAlgoList( INOUT_PTR STREAM *stream, 
				   IN_ARRAY( noAlgoStringInfoEntries ) \
						const ALGO_STRING_INFO *algoStringInfoTbl,
				   IN_RANGE( 1, 10 ) const int noAlgoStringInfoEntries )
	{
	int availAlgoIndex[ 16 + 8 ];
	LOOP_INDEX algoIndex;
	int noAlgos = 0, length = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( algoStringInfoTbl, sizeof( ALGO_STRING_INFO ) * \
										  noAlgoStringInfoEntries ) );

	REQUIRES( noAlgoStringInfoEntries > 0 && noAlgoStringInfoEntries <= 10 );

	/* Walk down the list of algorithms remembering the encoded name of each
	   one that's available for use */
	LOOP_SMALL( algoIndex = 0,
				algoIndex < noAlgoStringInfoEntries && \
					algoStringInfoTbl[ algoIndex ].algo != CRYPT_ALGO_NONE,
				algoIndex++ )
		{
		const ALGO_STRING_INFO *algoStringInfo = \
									&algoStringInfoTbl[ algoIndex ];

		ENSURES( LOOP_INVARIANT_SMALL( algoIndex, 0, 
									   noAlgoStringInfoEntries - 1 ) );

		/* Make sure that this algorithm is available for use */
		if( !algoAvailable( algoStringInfo->algo ) )
			continue;

		/* Make sure that any required sub-algorithms are available */
		if( algoStringInfo->subAlgo != CRYPT_ALGO_NONE && \
			!algoAvailable( algoStringInfo->subAlgo ) )
			continue;

		/* Remember the algorithm details */
		REQUIRES( noAlgos >= 0 && noAlgos < 16 );
		availAlgoIndex[ noAlgos++ ] = algoIndex;
		length += algoStringInfo->nameLen;
		if( noAlgos > 1 )
			length++;			/* Room for comma delimiter */
		}
	ENSURES( LOOP_BOUND_OK );

	/* Make sure that we'll be writing at least one algorithm */
	ENSURES( boundsCheck( noAlgos, 1, 15 ) );

	/* Encode the list of available algorithms into a comma-separated string */
	status = writeUint32( stream, length );
	LOOP_MED( algoIndex = 0, 
			  algoIndex < noAlgos && cryptStatusOK( status ),
			  algoIndex++ )
		{
		const ALGO_STRING_INFO *algoStringInfo;

		ENSURES( LOOP_INVARIANT_MED( algoIndex, 0, noAlgos - 1 ) );

		algoStringInfo = &algoStringInfoTbl[ availAlgoIndex[ algoIndex ] ];
		if( algoIndex > 0 )
			sputc( stream, ',' );	/* Add comma delimiter */
		status = swrite( stream, algoStringInfo->name,
						 algoStringInfo->nameLen );
		}
	ENSURES( LOOP_BOUND_OK );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoClassList( INOUT_PTR STREAM *stream, 
						IN_ENUM( SSH_ALGOCLASS ) \
							const SSH_ALGOCLASS_TYPE algoClass )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isEnumRange( algoClass, SSH_ALGOCLASS ) );

	/* Write the appropriate algorithm list for this algorithm class */
	switch( algoClass )
		{
		case SSH_ALGOCLASS_KEYEX:
			return( writeAlgoList( stream, algoStringKeyexTbl, 
								   FAILSAFE_ARRAYSIZE( algoStringKeyexTbl, \
													   ALGO_STRING_INFO ) ) );

		case SSH_ALGOCLASS_KEYEX_NOECC:
			return( writeAlgoList( stream, algoStringKeyexNoECCTbl,
								   FAILSAFE_ARRAYSIZE( algoStringKeyexNoECCTbl, \
													   ALGO_STRING_INFO ) ) );

		case SSH_ALGOCLASS_ENCR:
			return( writeAlgoList( stream, algoStringEncrTbl, 
								   FAILSAFE_ARRAYSIZE( algoStringEncrTbl, \
													   ALGO_STRING_INFO ) ) );

		case SSH_ALGOCLASS_SIGN:
			return( writeAlgoList( stream, algoStringPubkeyTbl, 
								   FAILSAFE_ARRAYSIZE( algoStringPubkeyTbl, \
													   ALGO_STRING_INFO ) ) );

		case SSH_ALGOCLASS_MAC:
			return( writeAlgoList( stream, algoStringMACTbl,
								   FAILSAFE_ARRAYSIZE( algoStringMACTbl, \
													   ALGO_STRING_INFO ) ) );

		case SSH_ALGOCLASS_COPR:
			return( writeAlgoList( stream, algoStringCoprTbl,
								   FAILSAFE_ARRAYSIZE( algoStringCoprTbl, \
													   ALGO_STRING_INFO ) ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*						Process Client/Server Hello							*
*																			*
****************************************************************************/

/* Process a client/server hello packet.  This function is placed here 
   because it consists primarily of reading and processing algorithm 
   information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int processHelloSSH( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo, 
					 OUT_LENGTH_SHORT_Z int *keyexLength,
					 IN_BOOL const BOOLEAN isServer )
	{
	CRYPT_ALGO_TYPE dummyAlgo;
	CRYPT_MODE_TYPE mode, dummyMode;
	STREAM stream;
	ALGOSTRING_INFO algoStringInfo;
	BOOLEAN preferredAlgoMismatch = FALSE, guessedKeyex = FALSE;
	int length, useETM DUMMY_INIT, dummyParameter, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( keyexLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( isServer ) );

	/* Clear return value */
	*keyexLength = 0;

	/* Process the client/server hello:

		byte		type = SSH_MSG_KEXINIT
		byte[16]	cookie
		string		keyex algorithms
		string		pubkey algorithms
		string		client_crypto algorithms
		string		server_crypto algorithms
		string		client_mac algorithms
		string		server_mac algorithms
		string		client_compression algorithms
		string		server_compression algorithms
		string		client_language
		string		server_language
		boolean		first_keyex_packet_follows
		uint32		reserved

	   The cookie isn't explicitly processed since it's done implicitly when 
	   the hello message is hashed */
	status = length = \
				readHSPacketSSH2( sessionInfoPtr, SSH_MSG_KEXINIT, 128 );
	if( cryptStatusError( status ) )
		return( status );
	*keyexLength = length;
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = sSkip( &stream, SSH2_COOKIE_SIZE, SSH2_COOKIE_SIZE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Read the keyex algorithm information.  Since this is the first 
	   algorithm list read, we also allow the extension indicator at this 
	   point */
	if( isServer )
		{
		int pkcAlgo;

		setAlgoStringInfoEx( &algoStringInfo, algoStringKeyexTbl, 
							 FAILSAFE_ARRAYSIZE( algoStringKeyexTbl, \
												 ALGO_STRING_INFO ),
							 CRYPT_ALGO_DH, GETALGO_FIRST_MATCH_WARN );

		/* By default the use of ECC algorithms is enabled if support for
		   them is present, however if the server key is a non-ECC key then 
		   it can't be used with an ECC keyex so we have to explicitly
		   disable it (technically it is possible to mix ECDH with RSA but
		   this is more likely an error than anything deliberate) */
		status = krnlSendMessage( sessionInfoPtr->privateKey, 
								  IMESSAGE_GETATTRIBUTE, &pkcAlgo,
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) || !isEccAlgo( pkcAlgo ) )
			algoStringInfo.allowECC = FALSE;
#ifdef USE_SSH_EXTENDED
		algoStringInfo.allowExtIndicator = TRUE;
#endif /* USE_SSH_EXTENDED */
		}
	else
		{
		setAlgoStringInfo( &algoStringInfo, algoStringKeyexTbl, 
						   FAILSAFE_ARRAYSIZE( algoStringKeyexTbl, \
											   ALGO_STRING_INFO ),
						   GETALGO_BEST_MATCH );
		}
	status = readAlgoStringEx( &stream, &algoStringInfo, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	handshakeInfo->keyexAlgo = algoStringInfo.algo;
	if( algoStringInfo.prefAlgoMismatch )
		{
		/* We didn't get a match for our first choice, remember that we have
		   to discard any guessed keyex that may follow */
		preferredAlgoMismatch = TRUE;
		}
	if( algoStringInfo.algo == CRYPT_ALGO_DH )
		{
		handshakeInfo->exchangeHashAlgo = algoStringInfo.subAlgo;
		if( algoStringInfo.parameter > 0 )
			{
			/* It's an explicit DH key like group14, remember the key size */
			handshakeInfo->requestedServerKeySize = algoStringInfo.parameter;
			handshakeInfo->isFixedDH = TRUE;
			}
		else
			{
			/* We're using negotiated rather than explicit DH keys, we need 
			   to negotiate the keyex key before we can perform the 
			   exchange */
			handshakeInfo->requestedServerKeySize = SSH2_DEFAULT_KEYSIZE;
			}
		}
	if( algoStringInfo.algo == CRYPT_ALGO_ECDH )
		{
		/* If we're using an ECDH cipher suite then we need to switch to the
		   appropriate hash algorithm for the keyex hashing */
		handshakeInfo->isECDH = TRUE;
		handshakeInfo->exchangeHashAlgo = algoStringInfo.subAlgo;
		}
#ifdef USE_SSH_EXTENDED
	if( algoStringInfo.extensionIndicator )
		handshakeInfo->sendExtInfo = TRUE;
#endif /* USE_SSH_EXTENDED */

	/* Read the pubkey (signature) algorithm information */
	if( isServer )
		{
		setAlgoStringInfoEx( &algoStringInfo, 
							 handshakeInfo->algoStringPubkeyTbl,
							 handshakeInfo->algoStringPubkeyTblNoEntries,
							 handshakeInfo->pubkeyAlgo, 
							 GETALGO_FIRST_MATCH_WARN );
		}
	else
		{
		setAlgoStringInfo( &algoStringInfo, 
						   handshakeInfo->algoStringPubkeyTbl,
						   handshakeInfo->algoStringPubkeyTblNoEntries,
						   GETALGO_BEST_MATCH );
		}
	status = readAlgoStringEx( &stream, &algoStringInfo, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( isServer && handshakeInfo->pubkeyAlgo != algoStringInfo.algo )
		{
		sMemDisconnect( &stream );
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Client requested pubkey algorithm %s when we "
				  "advertised %s", getAlgoName( algoStringInfo.algo ), 
				  getAlgoName( handshakeInfo->pubkeyAlgo ) ) );
		}
	handshakeInfo->pubkeyAlgo = algoStringInfo.algo;
	handshakeInfo->hashAlgo = algoStringInfo.subAlgo;
	if( algoStringInfo.prefAlgoMismatch )
		{
		/* We didn't get a match for our first choice, remember that we have
		   to discard any guessed keyex that may follow */
		preferredAlgoMismatch = TRUE;
		}

	/* Read the encryption and MAC algorithm information */
	status = readAlgoStringPair( &stream, algoStringEncrTbl,
								 FAILSAFE_ARRAYSIZE( algoStringEncrTbl, \
													 ALGO_STRING_INFO ),
								 &sessionInfoPtr->cryptAlgo, &mode,
								 &handshakeInfo->cryptKeysize, isServer, 
								 FALSE, SESSION_ERRINFO );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoStringPair( &stream, algoStringMACTbl,
									 FAILSAFE_ARRAYSIZE( algoStringMACTbl, \
														 ALGO_STRING_INFO ),
									 &sessionInfoPtr->integrityAlgo, 
									 &dummyMode, &useETM, isServer, 
									 FALSE, SESSION_ERRINFO );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );

		/* Some implementations don't support the mandatory-to-implement SSH 
		   encryption/MAC algorithms, in which case we let the caller know 
		   that they're broken */
		if( status == CRYPT_ERROR_NOTAVAIL && \
			TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_NOMTI ) )
			{
			retExtAdditional( status, 
							  ( status, SESSION_ERRINFO,
								", the server doesn't support the mandatory-"
								"to-implement SSH algorithms" ) );
			}
		return( status );
		}
#ifdef USE_SSH_OPENSSH
	if( useETM )
		{
		/* The other side has specified the nonstandard encrypt-then-MAC 
		   rather than the default MAC-then-encrypt */
		SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_ETM );
		}
#endif /* USE_SSH_OPENSSH */
#ifdef USE_SSH_CTR
	if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_AES && \
		mode == CRYPT_MODE_ECB )
		{
		/* If the indicated mode is ECB, which we use to synthesise CTR 
		   mode, remember that we're using CTR mode encryption */
		SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_CTR );
		}
#endif /* USE_SSH_CTR */

	/* Read the remaining algorithm information.  The final reserved value 
	   should always be zero but we don't specifically check for this since 
	   at some point in the future it may become non-zero */
	status = readAlgoStringPair( &stream, algoStringCoprTbl, 
								 FAILSAFE_ARRAYSIZE( algoStringCoprTbl, \
													 ALGO_STRING_INFO ),
								 &dummyAlgo, &dummyMode, &dummyParameter, 
								 isServer, 
								 TEST_FLAG( sessionInfoPtr->protocolFlags, 
											SSH_PFLAG_ASYMMCOPR ) ? \
									TRUE : FALSE, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	readUniversal32( &stream );
	status = readUniversal32( &stream );		/* Language string pair */
	if( cryptStatusOK( status ) )
		{
		int value;

		status = value = sgetc( &stream );
		if( !cryptStatusError( status ) && value != 0 )
			guessedKeyex = TRUE;
		}
	if( cryptStatusOK( status ) )
		status = readUint32( &stream );			/* Reserved value */
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Invalid %s hello language string/trailer data",
				  isServer ? "client" : "server" ) );
		}

	/* If we're using an alternative exchange hash algorithm, switch the 
	   contexts around to using the alternative one for hashing from now 
	   on */
	if( handshakeInfo->exchangeHashAlgo == CRYPT_ALGO_SHA2 )
		{
		const CRYPT_CONTEXT tempContext = handshakeInfo->iExchangeHashContext;

		handshakeInfo->iExchangeHashContext = \
				handshakeInfo->iExchangeHashAltContext;
		handshakeInfo->iExchangeHashAltContext = tempContext;
		}

	/* If there's a guessed keyex following this packet and we didn't match
	   the first-choice keyex/pubkey algorithm, tell the caller to skip it */
	if( guessedKeyex && preferredAlgoMismatch )
		return( OK_SPECIAL );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Miscellaneous Functions							*
*																			*
****************************************************************************/

/* Read and check a public key:

   RSA/DSA:
	string		[ server key/certificate ]
		string	"ssh-rsa"	"ssh-dss"
		mpint	e			p			
		mpint	n			q
		mpint				g
		mpint				y

   ECDSA:
	string		[ server key/certificate ]
		string	"ecdsa-sha2-*"
		string	"*"				-- The "*" portion from the above field
		string	Q */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int checkReadPublicKey( INOUT_PTR STREAM *stream,
						OUT_ALGO_Z CRYPT_ALGO_TYPE *pubkeyAlgo,
						OUT_INT_SHORT_Z int *keyDataStart,
						INOUT_PTR ERROR_INFO *errorInfo )
	{
	int algoParam DUMMY_INIT, dummy, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( keyDataStart, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Clear return values */
	*pubkeyAlgo = CRYPT_ALGO_NONE;
	*keyDataStart = 0;

	/* Read the algorithm ID information.  Note that this will allow some
	   invalid encodings since the public-key algorithms table lists both
	   public-key algorithms and also later kludged-on combinations that
	   encode both the public-key algorithm and a hash algorithm to go with
	   it, these are valid as signature algorithm specifiers but not as 
	   public-key-data algorithm specifiers.  To strictly enforce this
	   we'd need a separate encoding table that only contains the public-
	   key-data algorithm specifiers */
	status = readUint32( stream );	/* Server key data size */
	if( !cryptStatusError( status ) )
		{
		status = readAlgoString( stream, algoStringPubkeyTbl, 
								 FAILSAFE_ARRAYSIZE( algoStringPubkeyTbl, \
													 ALGO_STRING_INFO ), 
								 &algoParam, TRUE, errorInfo );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the public-key data */
	streamBookmarkSet( stream, *keyDataStart  );
	switch( algoParam )
		{
		case CRYPT_ALGO_RSA:
			/* RSA e, n */
			readInteger32( stream, NULL, &dummy, 1, CRYPT_MAX_PKCSIZE,
						   BIGNUM_CHECK_VALUE );
			status = readInteger32( stream, NULL, &dummy, MIN_PKCSIZE, 
									CRYPT_MAX_PKCSIZE, 
									BIGNUM_CHECK_VALUE_PKC );
			break;

#ifdef USE_DSA
		case CRYPT_ALGO_DSA:
			/* DSA p, q, g, y */
			status = readInteger32( stream, NULL, &dummy, MIN_PKCSIZE, 
									CRYPT_MAX_PKCSIZE, 
									BIGNUM_CHECK_VALUE_PKC );
			if( cryptStatusError( status ) )
				break;
			readInteger32( stream, NULL, &dummy, 1, CRYPT_MAX_PKCSIZE, 
						   BIGNUM_CHECK_VALUE );
			readInteger32( stream, NULL, &dummy, 1, CRYPT_MAX_PKCSIZE,
						   BIGNUM_CHECK_VALUE );
			status = readInteger32( stream, NULL, &dummy, MIN_PKCSIZE, 
									CRYPT_MAX_PKCSIZE, 
									BIGNUM_CHECK_VALUE_PKC );
			break;
#endif /* USE_DSA */

#ifdef USE_ECDSA
		case CRYPT_ALGO_ECDSA:
			readUniversal32( stream );		/* Skip field size */
			status = readInteger32( stream, NULL, &dummy, 
									MIN_PKCSIZE_ECCPOINT, 
									MAX_PKCSIZE_ECCPOINT,
									BIGNUM_CHECK_VALUE_ECC );
			break;
#endif /* USE_ECDSA */

		default:
			retIntError();
		}

	if( cryptStatusOK( status ) )
		*pubkeyAlgo = algoParam;	/* int vs. enum */
	return( status );
	}

/* Initialise algorithm information */

STDC_NONNULL_ARG( ( 1 ) ) \
void initHandshakeAlgos( INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	/* Most of the SSH <-> cryptlib mapping tables are fixed, however the 
	   pubkey table table is pointed to by the handshakeInfo and may
	   later be changed dynamically on the server depending on the server's 
	   key type */
	handshakeInfo->algoStringPubkeyTbl = algoStringPubkeyTbl;
	handshakeInfo->algoStringPubkeyTblNoEntries = \
			FAILSAFE_ARRAYSIZE( algoStringPubkeyTbl, ALGO_STRING_INFO );
	}
#endif /* USE_SSH */
