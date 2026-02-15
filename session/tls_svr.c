/****************************************************************************
*																			*
*							cryptlib TLS Server								*
*					   Copyright Peter Gutmann 1998-2021					*
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

/* Determine whether the server needs to request client certificates/client
   authentication.  This is normally determined by whether an access-control
   keyset is available, but for the Suite B tests in which any test 
   certificate is regarded as being acceptable it can be overridden with a
   self-test flag */

#ifdef CONFIG_SUITEB_TESTS 
#define clientCertAuthRequired( sessionInfoPtr ) \
		( sessionInfoPtr->cryptKeyset != CRYPT_ERROR || suiteBTestClientCert )
#else
#define clientCertAuthRequired( sessionInfoPtr ) \
		( sessionInfoPtr->cryptKeyset != CRYPT_ERROR || \
		  TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_MANUAL_CERTCHECK ) )
#endif /* CONFIG_SUITEB_TESTS */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read the client certificate chain and make sure that the certificate 
   being presented is valid for access */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readCheckClientCerts( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
								 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
								 INOUT_PTR STREAM *stream )
	{
#ifdef CONFIG_SUITEB
	int length;
#endif /* CONFIG_SUITEB */
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Read the client certificate chain */
	status = readTLSCertChain( sessionInfoPtr, handshakeInfo, stream, 
							   &sessionInfoPtr->iKeyexAuthContext, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Check whether the client certificate is present the permitted-
	   certificates whitelist (if there is one).  Checking whether the 
	   certificate is known to us at this point opens us up to a theoretical 
	   account-enumeration attack in which an attacker who has obtained a 
	   copy of every certificate in the world can throw them at us one after 
	   the other and then use timing measurements to see which ones get past 
	   this point.  OTOH deferring the "is this certificate known to us" 
	   check until after we process the keyex opens us up to a DoS attack 
	   since the attacker can force us to perform a DH keyex rather than 
	   rejecting the handshake at this point.  We could further flip things 
	   around and first read the certificate, then read and cache the keyex 
	   data, then try and verify the keyex data using the client signature, 
	   and only then actually use it, but this greatly complicates the code 
	   and given the practical nonexistence of client certificates just adds 
	   a pile of needless complexity for a mechanism that's virtually never 
	   used anyway.  Because of this we do a quick-reject check here and 
	   don't even go into a keyex unless we recognise the certificate */
#ifndef CONFIG_SUITEB_TESTS 
	status = checkCertWhitelist( sessionInfoPtr, 
								 sessionInfoPtr->iKeyexAuthContext, TRUE );
	if( cryptStatusError( status ) )
		return( status );
#endif /* !CONFIG_SUITEB_TESTS */

	/* Make sure that the key is of the appropriate size for the Suite B 
	   security level.  At the 128-bit level both P256 and P384 are allowed, 
	   at the 256-bit level only P384 is allowed */
#ifdef CONFIG_SUITEB
	status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
							  IMESSAGE_GETATTRIBUTE, &length,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		{
		const int suiteBtype = \
						sessionInfoPtr->protocolFlags & TLS_PFLAG_SUITEB;

		if( suiteBtype == TLS_PFLAG_SUITEB_256 )
			{
			if( length != bitsToBytes( 384 ) )
				{
				retExt( CRYPT_ERROR_INVALID,
						( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
						  "Client Suite B certificate uses %d-bit key at "
						  "256-bit security level, should use 384-bit key", 
						  bytesToBits( length ) ) );
				}
			}
		else
			{
			if( length != bitsToBytes( 256 ) && \
				length != bitsToBytes( 384 ) )
				{
				retExt( CRYPT_ERROR_INVALID,
						( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
						  "Client Suite B certificate uses %d-bit key at "
						  "128-bit security level, should use 256- or "
						  "384-bit key", bytesToBits( length ) ) );
				}
			}
		}
#endif /* CONFIG_SUITEB */

	return( CRYPT_OK );
	}

/* Write the certificate request:

	  [	byte		ID = TLS_HAND_SERVER_CERTREQUEST ]
	  [	uint24		len				-- Written by caller ]
		byte		certTypeLen
		byte[]		certType = { RSA, DSA, ECDSA }
	  [	uint16	sigHashListLen		-- TLS 1.2 ]
	  [		byte	hashAlgoID		-- TLS 1.2 ]
	  [		byte	sigAlgoID		-- TLS 1.2 ]
		uint16		caNameListLen = 0
	  [		uint16	caNameLen		-- Omitted due to zero length ]
	  [		byte[]	caName			-- Omitted due to zero length ]

   This message is a real mess, it originally had a rather muddled 
   certificate-type indicator (which included things like "Ephemeral DH 
   signed with RSA") and an equally ambiguous CA list that many 
   implementations either left empty or filled with the name of every CA 
   that they'd ever heard of, see the special-case handling in 
   processCertRequest() in session/tls_cli.c for the calisthenics required 
   to deal with this.  
   
   TLS 1.2 added a means of indicating which signature and hash algorithms 
   were acceptable, which is kind of essential because the explosion of hash 
   algorithms in 1.2 means that a server would have to run parallel hashes 
   of every handshake message for every possible hash algorithm until the 
   client sends their certificate-verify message (!!).  In other words 
   although it was planned as a means of indicating the server's 
   capabilities, it actually acts as a mechanism for keeping the client-auth 
   process manageable */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCertRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							 INOUT_PTR STREAM *stream )
	{
	const BOOLEAN rsaAvailable = algoAvailable( CRYPT_ALGO_RSA ) ? \
								 TRUE : FALSE;
	const BOOLEAN dsaAvailable = algoAvailable( CRYPT_ALGO_DSA ) ? \
								 TRUE : FALSE;
	const BOOLEAN ecdsaAvailable = algoAvailable( CRYPT_ALGO_ECDSA ) ? \
								   TRUE : FALSE;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( rsaAvailable ) );

	/* Write the certificate type */
	status = sputc( stream, ( rsaAvailable ? 1 : 0 ) + \
							( dsaAvailable ? 1 : 0 ) + \
							( ecdsaAvailable ? 1 : 0 ) );
	if( rsaAvailable )
		status = sputc( stream, TLS_CERTTYPE_RSA );
	if( dsaAvailable )
		status = sputc( stream, TLS_CERTTYPE_DSA );
	if( ecdsaAvailable )
		status = sputc( stream, TLS_CERTTYPE_ECDSA );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the list of accepted signature and hash algorithms if required.  
	   In theory we could write the full list of algorithms, but thanks to 
	   TLS' braindamaged way of handling certificate-based authentication 
	   (see the comment above) this would make the certificate-
	   authentication process unmanageable.  To get around this we only 
	   allow one single algorithm, the SHA-2 default for TLS 1.2+ */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		writeUint16( stream, ( rsaAvailable ? 2 : 0 ) + \
							 ( dsaAvailable ? 2 : 0 ) + \
							 ( ecdsaAvailable ? 2 : 0 ) );
		if( rsaAvailable )
			{
			sputc( stream, TLS_HASHALGO_SHA2 );
			status = sputc( stream, TLS_SIGALGO_RSA );
			}
		if( dsaAvailable )
			{
			sputc( stream, TLS_HASHALGO_SHA2 );
			status = sputc( stream, TLS_SIGALGO_DSA );
			}
		if( ecdsaAvailable )
			{
			sputc( stream, TLS_HASHALGO_SHA2 );
			status = sputc( stream, TLS_SIGALGO_ECDSA );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the CA name list.  Since all we care about is whether a 
	   certificate is present in the authentication database, we don't try 
	   and write a list of every imaginable CA that the client will most 
	   likely ignore anyway */ 
	return( writeUint16( stream, 0 ) );
	}

/* Calculate an ID for use with the session scoreboard from the session ID 
   and the SNI.  This prevents an attacker from taking advantage of virtual 
   hosting with a shared session cache to redirect a connection from one 
   domain to another, which a purely session ID-based lookup would allow */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int convertSNISessionID( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER_FIXED( idBufferLength ) BYTE *idBuffer,
						 IN_LENGTH_FIXED( KEYID_SIZE ) const int idBufferLength )
	{
	STREAM sniStream;
	BYTE sniInfo[ UINT16_SIZE + MAX_SESSIONID_SIZE + \
				  UINT16_SIZE + KEYID_SIZE + 8 ];
	int sniInfoLength, status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtrDynamic( idBuffer, idBufferLength ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( idBufferLength == KEYID_SIZE );

	/* Clear return value */
	REQUIRES( idBufferLength == KEYID_SIZE );
	memset( idBuffer, 0, idBufferLength );

	/* Write the session ID and hashed SNI to a buffer for hashing */
	sMemOpen( &sniStream, sniInfo, UINT16_SIZE + MAX_SESSIONID_SIZE + \
								   UINT16_SIZE + KEYID_SIZE );
	writeUint16( &sniStream, handshakeInfo->sessionIDlength );
	swrite( &sniStream, handshakeInfo->sessionID, 
			handshakeInfo->sessionIDlength );
	writeUint16( &sniStream, KEYID_SIZE );
	status = swrite( &sniStream, handshakeInfo->hashedSNI, KEYID_SIZE );
	ENSURES_SCN( !cryptStatusError( status ), sniStream );
	sniInfoLength = stell( &sniStream );
	REQUIRES_SCN( isShortIntegerRangeNZ( sniInfoLength ), sniStream );

	/* Generate the final ID from the combined session ID and SNI */
	hashData( idBuffer, idBufferLength, sniInfo, sniInfoLength );
	sMemClose( &sniStream );

	return( CRYPT_OK );
	}

/* Process an attempt to resume a previous session */
 
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int processSessionResume( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
								 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
								 INOUT_PTR \
									SCOREBOARD_ENTRY_INFO *scoreboardEntryInfo,
								 OUT_INT_Z int *resumedSessionID )
	{
	BYTE sessionIDbuffer[ KEYID_SIZE + 8 ];
	void *scoreboardInfoPtr = \
				DATAPTR_GET( sessionInfoPtr->sessionTLS->scoreboardInfoPtr );
	const BYTE *sessionIDptr = handshakeInfo->sessionID;
	int sessionIDlength = handshakeInfo->sessionIDlength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( scoreboardEntryInfo, sizeof( SCOREBOARD_ENTRY_INFO ) ) );
	assert( isWritePtr( resumedSessionID, sizeof( int ) ) );

	REQUIRES( scoreboardInfoPtr != NULL );

	/* Clear return values */
	memset( scoreboardEntryInfo, 0, sizeof( SCOREBOARD_ENTRY_INFO ) );
	*resumedSessionID = CRYPT_ERROR;

	/* If there's an SNI present, generate a pseudo-session ID that includes 
	   it.  This is used for the session cache lookup, but the original 
	   session ID is sent back to the client.  The same operation is 
	   performed when the session ID is added to the cache */
	if( handshakeInfo->hashedSNIpresent )
		{
		status = convertSNISessionID( handshakeInfo, sessionIDbuffer,
									  KEYID_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		sessionIDptr = sessionIDbuffer;
		sessionIDlength = KEYID_SIZE;
		}

	/* The client has sent us a sessionID in an attempt to resume a previous 
	   session, see if it's in the session cache.  We can short-circuit the 
	   lookup by checking that it's one of ours first, and also don't do the 
	   check for TLS 1.3 which uses a different session resumption 
	   mechanism */
	if( sessionIDlength == SESSIONID_SIZE && \
		sessionInfoPtr->version <= TLS_MINOR_VERSION_TLS12 )
		{
		*resumedSessionID = \
					lookupScoreboardEntry( scoreboardInfoPtr, 
										   SCOREBOARD_KEY_SESSIONID_SVR, 
										   sessionIDptr, sessionIDlength, 
										   scoreboardEntryInfo );
		}

	return( CRYPT_OK );
	}

/* Check for an SNI in the Client Hello, which affects the server key
   that we're going to use, which in turn affects a lot of the crypto
   that's negotiated in the Client Hello.  To deal with this catch-22
   we have to process the Client Hello twice, the first time to find the
   SNI at the end which affects the server key used, and then the second
   time as normal with the appropriate server key selected:

		byte		ID = TLS_HAND_CLIENT_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		byte[32]	nonce
		byte		sessIDlen
		byte[]		sessID
		uint16		suiteLen
		uint16[]	suite
		byte		coprLen
		byte[]		copr
		uint16	extListLen
			byte	extType
			uint16	extLen
			byte[]	extData 

   Handling of error conditions for this is a bit unusual because we're just
   using it as a pre-scan of the Client Hello whose only action is to
   transparently swap out keys rather than explicitly performing any data
   processing.  In particular we don't want to report an error at this point
   because the most that we can say is that something in the Client Hello 
   isn't right, rather than the detailed diagnostics available from the 
   actual Client Hello-processing code.

   Because of this, we simply return if there's an error, with the actual
   processing code providing diagnostics and error handling */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void checkSNI( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					  INOUT_PTR STREAM *stream )
	{
	const ATTRIBUTE_LIST *attributeListCursor;
	ERROR_INFO localErrorInfo;
	BYTE nameBuffer[ MAX_DNS_SIZE + 8 ];
	LOOP_INDEX noExtensions;
	int length, endPos, nameLength = 0, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Check the overall packet header to make sure that we're processing
	   what's probably a TLS client hello */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_CLIENT_HELLO,
								  VERSIONINFO_SIZE + TLS_NONCE_SIZE + \
									1 + ( UINT16_SIZE * 2 ) + 1 + 1 );
	if( cryptStatusError( status ) )
		return;
	endPos = stell( stream ) + length;
	ENSURES_V( isIntegerRangeMin( endPos, length ) );
	status = processVersionInfo( sessionInfoPtr, stream, NULL, TRUE );
	if( cryptStatusError( status ) )
		return;

	/* Skip everything up to the extensions */
	status = sSkip( stream, TLS_NONCE_SIZE, MAX_INTLENGTH_SHORT );
	if( cryptStatusOK( status ) )
		status = readUniversal8( stream );	/* Session ID */
	if( cryptStatusOK( status ) )
		status = readUniversal16( stream );	/* Cipher suites */
	if( cryptStatusOK( status ) )
		status = readUniversal8( stream );	/* Compression algos */
	if( cryptStatusError( status ) )
		return;

	/* If there are no extensions present then we're done */
	if( endPos - stell( stream ) <= ( UINT16_SIZE * 3 ) )
		return;

	/* We've got extensions, read each one looking for an SNI:

		uint16		extListLen
			uint16	extType
			uint16	extLen
			byte[]	extData */
	status = readUint16( stream );
	if( cryptStatusError( status ) )
		return;
	LOOP_MED( noExtensions = 0,
			  noExtensions < 32 && stell( stream ) < endPos,
			  noExtensions++ )
		{
		int type;

		ENSURES_V( LOOP_INVARIANT_MED( noExtensions, 0, 32 - 1 ) );

		/* Read the extension and, if it's not an SNI, skip it */
		type = readUint16( stream );
		status = length = readUint16( stream );
		if( cryptStatusError( status ) || \
			!isShortIntegerRange( length ) )
			return;
		if( type != TLS_EXT_SNI )
			{
			if( length > 0 )
				{
				status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return;
				}
			continue;
			}

		/* We've found an SNI extension:

			uint16		listLen
				byte	nameType
				uint16	nameLen
				byte[]	name

		   extract the name from it */
		status = length = readUint16( stream );
		if( cryptStatusError( status ) || \
			length < 1 + UINT16_SIZE || \
			length > 1 + UINT16_SIZE + MAX_DNS_SIZE )
			return;
		if( sgetc( stream ) != 0 )	/* Name type 0 = hostname */
			return;
		status = nameLength = readUint16( stream );
		if( cryptStatusError( status ) || \
			nameLength < MIN_DNS_SIZE || nameLength > MAX_DNS_SIZE )
			return;
		REQUIRES_V( rangeCheck( nameLength, 1, MAX_DNS_SIZE ) );
		status = sread( stream, nameBuffer, nameLength );
		if( cryptStatusError( status ) )
			return;
		nameBuffer[ min( nameLength, MAX_DNS_SIZE - 1 ) ] = '\0';
		break;
		}
	ENSURES_V( LOOP_BOUND_OK );

	/* If there was no SNI present, we're done */
	if( nameLength <= 0 )
		return;		/* Success return */
	DEBUG_PRINT(( "Client indicated SNI = '%s'.\n", nameBuffer ));

	/* Check whether the SNI matches the primary server key */
	clearErrorInfo( &localErrorInfo );
	status = checkHostNameTLS( sessionInfoPtr->privateKey, nameBuffer, 
							   nameLength, &localErrorInfo );
	if( cryptStatusOK( status ) )
		return;		/* Success return */

	/* If we're fuzzing there's not need to switch keys */
	FUZZ_SKIP_REMAINDER_V();

	/* It doesn't match the primary key, check for matches against any other
	   keys that may be present */
	LOOP_MED( attributeListCursor = \
						findSessionInfo( sessionInfoPtr, \
										 CRYPT_SESSINFO_PRIVATEKEY ), 
			  attributeListCursor != NULL,
			  attributeListCursor = \
						findSessionInfoNext( attributeListCursor, \
											 CRYPT_SESSINFO_PRIVATEKEY ) )
		{
		CRYPT_HANDLE iTempHandle;
		ATTRIBUTE_LIST *privateKeyPtr = \
						( ATTRIBUTE_LIST * ) attributeListCursor;

		ENSURES_V( LOOP_INVARIANT_MED_GENERIC() );

		/* Check whether the SNI matches this key */
		clearErrorInfo( &localErrorInfo );
		status = checkHostNameTLS( privateKeyPtr->intValue, nameBuffer, 
								   nameLength, &localErrorInfo );
		if( cryptStatusError( status ) )
			continue;

		/* We've got a match, swap the primary server key and this one so 
		   that the Client Hello SNI matches what's needed.  This leads to 
		   an unfortunate need to modify a const value since attribute data 
		   is normally read-pnly */
		iTempHandle = sessionInfoPtr->privateKey;
		sessionInfoPtr->privateKey = privateKeyPtr->intValue;
		privateKeyPtr->intValue = iTempHandle;
		DEBUG_PRINT(( "Switched server certificates to match client's "
					  "SNI.\n" ));
		
		return;
		}
	ENSURES_V( LOOP_BOUND_OK );

	/* At this point we haven't found a match for the SNI in which case we 
	   continue with the default key, with the client able to decide whether 
	   it wants to go with that or not */
	DEBUG_PRINT(( "Couldn't find a server certificate matching client's "
				  "SNI.\n" ));
	}

/****************************************************************************
*																			*
*							Handle Client/Server Keyex						*
*																			*
****************************************************************************/

/* Process the client key exchange packet:

		byte		ID = TLS_HAND_CLIENT_KEYEXCHANGE
		uint24		len
	   DH:
		uint16		yLen
		byte[]		y
	   DH-PSK:
		uint16		userIDLen
		byte[]		userID
		uint16		yLen
		byte[]		y
	   ECDH:
		uint8		ecPointLen		-- NB uint8 not uint16
		byte[]		ecPoint
	   PSK:
		uint16		userIDLen
		byte[]		userID 
	   RSA:
	  [ uint16		encKeyLen		-- Disabled by default ]
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x0n } || byte[46] random ) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processDHKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						   INOUT_PTR STREAM *stream, 
						   IN_PTR_OPT const ATTRIBUTE_LIST *passwordInfoPtr )
	{
	BYTE keyexValue[ CRYPT_MAX_PKCSIZE + 8 ];
	int keyexValueLen, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( passwordInfoPtr == NULL || \
			isReadPtr( passwordInfoPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* Complete the DH keyex */
	status = completeTLSKeyex( handshakeInfo, stream, 
							   TEST_FLAG( sessionInfoPtr->protocolFlags, \
										  TLS_PFLAG_TLS12LTS ) ?  TRUE : FALSE, 
							   FALSE, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is a straight keyex then we're done */
	if( passwordInfoPtr == NULL )
		return( CRYPT_OK );

	/* It's a keyex with PSK, create the premaster secret from the PSK and
	   the keyex value.  Since the keyex value is stored as the premaster
	   secret, which is also the output parameter, we have to copy it to a
	   temporary before we perform the operation */
	REQUIRES( rangeCheck( handshakeInfo->premasterSecretSize, 1, 
						  CRYPT_MAX_PKCSIZE ) );
	memcpy( keyexValue, handshakeInfo->premasterSecret,
			handshakeInfo->premasterSecretSize );
	keyexValueLen = handshakeInfo->premasterSecretSize;
	status = createSharedPremasterSecret( \
							handshakeInfo->premasterSecret,
							CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE,
							&handshakeInfo->premasterSecretSize,
							passwordInfoPtr->value,
							passwordInfoPtr->valueLength, 
							keyexValue, keyexValueLen,
							TEST_FLAG( passwordInfoPtr->flags,
									   ATTR_FLAG_ENCODEDVALUE ) ? \
								TRUE : FALSE );
	zeroise( keyexValue, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Couldn't create master secret from shared secret/"
				  "password value" ) );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processPSKKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							INOUT_PTR STREAM *stream )
	{
	const ATTRIBUTE_LIST *attributeListPtr;
	LOOP_INDEX_PTR const ATTRIBUTE_LIST *attributeListCursor;
	const BOOLEAN isKeyex = \
				isKeyexAlgo( handshakeInfo->keyexAlgo ) ? TRUE : FALSE;
	BYTE userID[ CRYPT_MAX_TEXTSIZE + 8 ];
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( !isEccAlgo( handshakeInfo->keyexAlgo ) );

	/* Read the client user ID and make sure that it's a valid user.  
	   Handling non-valid users is somewhat problematic, we can either bail 
	   out immediately or invent a fake password for the (non-)user and 
	   continue with that.  The problem with this is that it doesn't really 
	   help hide whether the user is valid or not due to the fact that we're 
	   still vulnerable to a timing attack because it takes considerably 
	   longer to generate the random password than it does to read a fixed 
	   password string from memory, so an attacker can tell from the timing 
	   whether the username is valid or not.  In addition usability research 
	   on real-world users indicates that this actually reduces security 
	   while having little to no tangible benefit.  Because of this we don't 
	   try and fake out the valid/invalid user name indication but just exit 
	   immediately if an invalid name is found */
	length = readUint16( stream );
	if( length < 1 || length > CRYPT_MAX_TEXTSIZE || \
		cryptStatusError( sread( stream, userID, length ) ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid client user ID" ) );
		}
	attributeListPtr = findSessionInfoEx( sessionInfoPtr,
										  CRYPT_SESSINFO_USERNAME, 
										  userID, length );
	if( attributeListPtr == NULL )
		{
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "Unknown user name '%s'", 
				  sanitiseString( userID, CRYPT_MAX_TEXTSIZE, 
								  length ) ) );
		}

	/* Move on to the associated password */
	attributeListPtr = DATAPTR_GET( attributeListPtr->next );
	ENSURES( attributeListPtr != NULL && \
			 attributeListPtr->attributeID == CRYPT_SESSINFO_PASSWORD );

	/* Delete any other username/password pairs that may be present so that
	   the caller knows which set was used to authenticate.  These are 
	   present in the attribute list as:

		username - password - ... - username - password - ... 
	
	   so to delete them we repeatedly look for a username attribute and 
	   then delete that and the following attribute */
	LOOP_LARGE_INITCHECK( attributeListCursor = \
							findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME ), 
						  attributeListCursor != NULL )
		{
		ATTRIBUTE_LIST *userNamePtr = ( ATTRIBUTE_LIST * ) attributeListCursor;
		ATTRIBUTE_LIST *passwordPtr = DATAPTR_GET( userNamePtr->next );

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		ENSURES( passwordPtr != NULL && \
				 passwordPtr->attributeID == CRYPT_SESSINFO_PASSWORD );
		REQUIRES( DATAPTR_ISVALID( passwordPtr->next ) );

		/* Try and find the next username/password pair after the current one */
		attributeListCursor = findSessionInfoNext( passwordPtr, 
												   CRYPT_SESSINFO_USERNAME );

		/* If this is a non-matching username/password pair, delete it */
		if( passwordPtr != attributeListPtr )
			{
			deleteSessionInfo( sessionInfoPtr, userNamePtr );
			deleteSessionInfo( sessionInfoPtr, passwordPtr );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	/* If it's PSK with DH, perform the keyex with the PSK added */
	if( isKeyex )
		{
		return( processDHKeyex( sessionInfoPtr, handshakeInfo, stream, 
								attributeListPtr ) );
		}

	/* If we're fuzzing the input then we don't need to go through any of 
	   the following crypto calisthenics.  In addition we can exit now 
	   because the remaining fuzzable code is common with the client and
	   has already been tested there */
	FUZZ_EXIT();

	/* We're using straight PSK, the premaster secret is derived from the 
	   user password */
	status = createSharedPremasterSecret( \
						handshakeInfo->premasterSecret,
						CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE,
						&handshakeInfo->premasterSecretSize, 
						attributeListPtr->value,
						attributeListPtr->valueLength, NULL, 0,
						TEST_FLAG( attributeListPtr->flags, 
								   ATTR_FLAG_ENCODEDVALUE ) ? \
							TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Couldn't create master secret from shared secret/password "
				  "value" ) );
		}

	return( CRYPT_OK );
	}

#ifdef USE_RSA_SUITES

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processRSAKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							INOUT_PTR STREAM *stream )
	{
	BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = readInteger16U( stream, wrappedKey, &length, MIN_PKCSIZE, 
							 CRYPT_MAX_PKCSIZE, BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusError( status ) )
		{
		/* Some misconfigured clients may use very short keys, we perform a 
		   special-case check for these and return a more specific message 
		   than the generic bad-data */
		if( status == CRYPT_ERROR_NOSECURE )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
					  "Insecure RSA key used in key exchange" ) );
			}

		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid RSA encrypted key data" ) );
		}

	/* If we're fuzzing the input then we don't need to go through any of 
	   the following crypto calisthenics.  In addition we can exit now 
	   because the remaining fuzzable code is common with the client and
	   has already been tested there */
	FUZZ_EXIT();

	/* Decrypt the pre-master secret */
	return( unwrapPremasterSecret( sessionInfoPtr, handshakeInfo, 
								   wrappedKey, length ) );
	}
#endif /* USE_RSA_SUITES */

/* Process the client's keyex.  This demultuplexing function sorts out which 
   type of keyex we're using and passes control to the appropriate keyex-
   specific function to handle it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 INOUT_PTR STREAM *stream )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* If we're using any form of PSK (either raw PSK or PSK with DH) then 
	   the keyex is handled specially */
	if( handshakeInfo->authAlgo == CRYPT_ALGO_NONE )
		return( processPSKKeyex( sessionInfoPtr, handshakeInfo, stream ) );

	/* If we're using DH/ECDH, perform the necessary keyex operations.  Note
	   that there's no handling for newer algorithms like 25519 because 
	   they're TLS 1.3-only */
	switch( handshakeInfo->keyexAlgo ) 
		{
		case CRYPT_ALGO_DH:
			/* This option is special-cased because we could be using DH with
			   PSK */
			return( processDHKeyex( sessionInfoPtr, handshakeInfo, 
									stream, NULL ) );

		case CRYPT_ALGO_ECDH:
			return( completeTLSKeyex( handshakeInfo, stream, 
								TEST_FLAG( sessionInfoPtr->protocolFlags, \
										   TLS_PFLAG_TLS12LTS ) ? \
									TRUE : FALSE, FALSE, SESSION_ERRINFO ) );
#ifdef USE_RSA_SUITES
		case CRYPT_ALGO_RSA:
			return( processRSAKeyex( sessionInfoPtr, handshakeInfo, stream ) );
#endif /* USE_RSA_SUITES */

		default:
			retIntError();
		}

	retIntError();
	}

/* Build the server key exchange packet:

	  [	byte		ID = TLS_HAND_SERVER_KEYEXCHANGE ]
	  [	uint24		len				-- Written by caller ]
	   DH:
		uint16		dh_pLen
		byte[]		dh_p
	  [ uint16		dh_qLen
		byte[]		dh_q			-- TLS LTS ]
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
	  [	byte		hashAlgoID		-- TLS 1.2 ]
	  [	byte		sigAlgoID		-- TLS 1.2 ]
		uint16		signatureLen
		byte[]		signature
	   DH-PSK:
		uint16		pskIdentityHintLen = 0
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
	   ECDH-PSK: (Not present)
	   ECDH:
		byte		curveType
		uint16		namedCurve
		uint8		ecPointLen		-- NB uint8 not uint16
		byte[]		ecPoint
	  [	byte		hashAlgoID		-- TLS 1.2 ]
	  [	byte		sigAlgoID		-- TLS 1.2 ]
		uint16		signatureLen
		byte[]		signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int createServerKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							  INOUT_PTR STREAM *stream )
	{
	const BOOLEAN isPSK = ( handshakeInfo->authAlgo == CRYPT_ALGO_NONE ) ? \
						  TRUE : FALSE;
	KEYAGREE_PARAMS keyAgreeParams;
	void *keyData;
	int keyDataOffset, keyDataLength DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* Perform phase 1 of the DH/ECDH key agreement process */
	memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	status = krnlSendMessage( handshakeInfo->keyexContext, 
							  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams, 
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		{
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		return( status );
		}

	/* Write an empty PSK identity hint (whatever that's supposed to be) if
	   it's a PSK suite.  Perhaps we should always write "nan-demo 
	   kaimasen" */
	if( isPSK )
		{
		status = writeUint16( stream, 0 );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			return( status );
			}
		}

	/* Write the DH/ECDH key parameters and public value */
	keyDataOffset = stell( stream );
	ENSURES( isIntegerRangeNZ( keyDataOffset ) );
	status = exportAttributeToStream( stream, handshakeInfo->keyexContext,
								TEST_FLAG( sessionInfoPtr->protocolFlags, 
										   TLS_PFLAG_TLS12LTS ) ? \
								CRYPT_IATTRIBUTE_KEY_TLS_EXT : 
								CRYPT_IATTRIBUTE_KEY_TLS );
	if( cryptStatusOK( status ) )
		{
		if( isEccAlgo( handshakeInfo->keyexAlgo ) )
			{
			sputc( stream, keyAgreeParams.publicValueLen );
			status = swrite( stream, keyAgreeParams.publicValue,
							 keyAgreeParams.publicValueLen );
			}
		else
			{
			status = writeInteger16U( stream, keyAgreeParams.publicValue, 
									  keyAgreeParams.publicValueLen );
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, keyDataOffset,
											  &keyDataLength );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		return( status );
		}

	/* If we're using a PSK suite then the exchange is authenticated via the 
	   PSK and we're done */
	if( isPSK )
		{
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		return( CRYPT_OK );
		}

	/* Non-PSK suites authenticate the exchange by signing it */
	status = sMemGetDataBlockAbs( stream, keyDataOffset, &keyData, 
								  keyDataLength );
	if( cryptStatusOK( status ) )
		{
		ANALYSER_HINT( keyData != NULL );

		INJECT_FAULT( BADSIG_DATA, SESSION_BADSIG_DATA_TLS_1 );
		status = createKeyexSignature( sessionInfoPtr, handshakeInfo, stream, 
									   keyData, keyDataLength );
		INJECT_FAULT( BADSIG_DATA, SESSION_BADSIG_DATA_TLS_2 );
		}
	zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );

	return( status );
	}

/****************************************************************************
*																			*
*							Server-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int beginServerHandshake( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
								 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	SCOREBOARD_ENTRY_INFO scoreboardEntryInfo DUMMY_INIT_STRUCT;
	MESSAGE_DATA msgData;
	TLSHELLO_ACTION_TYPE actionType;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	const int serverVersion = sessionInfoPtr->version;
	int packetOffset, clientHelloLength, serverHelloLength DUMMY_INIT;
	int resumedSessionID = CRYPT_ERROR, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Read and process the Client Hello */
	status = readHSPacketTLS( sessionInfoPtr, handshakeInfo, 
							  &clientHelloLength, TLS_MSG_FIRST_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
#ifndef CONFIG_FUZZ
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_SERVER_SNI ) )
#endif /* CONFIG_FUZZ */
		{
		/* There are multiple server keys present due to SNI-based 
		   switching, check for an SNI in the Client Hello and swap in the 
		   appropriate server key to match it.  We have to do this before
		   calling processHelloTLS() because that needs to match up the
		   crypto information offered in the Client Hello to the server's
		   key.
		   
		   This function doesn't return a status since all it does is 
		   transparently swap out the server key if required */
		sMemConnect( stream, sessionInfoPtr->receiveBuffer,
					 clientHelloLength );
		( void ) checkSNI( sessionInfoPtr, stream );
		sMemDisconnect( stream );
		}
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, clientHelloLength );
	status = processHelloTLS( sessionInfoPtr, handshakeInfo, stream, 
							  &actionType, TRUE );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		{
		if( status != OK_SPECIAL )
			return( status );

		/* Reset the special-case status value.  This is techically a dead
		   assignment but we do it anyway for hygiene reasons */
		status = CRYPT_OK;
		ANALYSER_HINT_DEADSTORE_OK( status );

#ifdef USE_TLS13
		ENSURES( ( sessionInfoPtr->version <= TLS_MINOR_VERSION_TLS12 && \
				   actionType == TLSHELLO_ACTION_RESUMEDSESSION ) || \
				 ( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 && \
				   actionType == TLSHELLO_ACTION_RETRY ) );
#else
		ENSURES( sessionInfoPtr->version <= TLS_MINOR_VERSION_TLS12 && \
				 actionType == TLSHELLO_ACTION_RESUMEDSESSION );
#endif /* USE_TLS13 */

		if( actionType == TLSHELLO_ACTION_RESUMEDSESSION )
			{
			status = processSessionResume( sessionInfoPtr, handshakeInfo, 
										   &scoreboardEntryInfo, 
										   &resumedSessionID );
			if( cryptStatusError( status ) )
				return( status );
#ifdef CONFIG_SUITEB_TESTS 
			resumedSessionID = CRYPT_ERROR;	/* Disable for Suite B tests */
#endif /* CONFIG_SUITEB_TESTS */
			}
		}
	CFI_CHECK_UPDATE( "processHelloTLS" );

	/* If we're fuzzing the input then we can skip all data writes to 
	   minimise the overhead during fuzz testing */
	FUZZ_SKIP_REMAINDER();

	/* Handle session resumption if we're using standard TLS.  Under TLS 1.3
	   session resumption is handled completely differently and the session 
	   ID is just a dummy value */
	if( sessionInfoPtr->version <= TLS_MINOR_VERSION_TLS12 )
		{
		/* If it's a new session or the session data has expired from the 
		   cache, generate a new session ID */
		if( cryptStatusError( resumedSessionID ) )
			{
			setMessageData( &msgData, handshakeInfo->sessionID, 
							SESSIONID_SIZE );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusError( status ) )
				return( status );
			handshakeInfo->sessionIDlength = SESSIONID_SIZE;
			}
		else
			{
			/* We're resuming a previous session, if extended TLS facilities 
			   were in use then make sure that the resumed session uses the 
			   same facilities.  This check preents downgrade attacks where 
			   additional security features are disabled by a MITM */
			if( !TEST_FLAGS( sessionInfoPtr->protocolFlags, 
							 TLS_RESUMEDSESSION_FLAGS, 
							 scoreboardEntryInfo.metaData ) )
				{
				retExt( CRYPT_ERROR_INVALID,
						( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
						  "Session with options %X was resumed with options "
						  "%X.\n", scoreboardEntryInfo.metaData,
						  GET_FLAGS( sessionInfoPtr->protocolFlags,
									 TLS_RESUMEDSESSION_FLAGS ) ) );
				}

			/* Remember the premaster secret for the resumed session */
			status = attributeCopyParams( handshakeInfo->premasterSecret, 
										  TLS_SECRET_SIZE,
										  &handshakeInfo->premasterSecretSize,
										  scoreboardEntryInfo.data, 
										  scoreboardEntryInfo.dataSize );
			ENSURES( cryptStatusOK( status ) );
			}
		}
	CFI_CHECK_UPDATE( "resumedSession" );

	/* If we're using TLS 1.3 then we can disable a pile of TLS classic 
	   extensions that aren't used in TLS 1.3 */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		handshakeInfo->flags &= \
				~( HANDSHAKE_FLAG_NEEDRENEGRESPONSE | \
				   HANDSHAKE_FLAG_NEEDETMRESPONSE | \
				   HANDSHAKE_FLAG_NEEDEMSRESPONSE | \
				   HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE );
		handshakeInfo->sendECCPointExtn = FALSE;
		}
#endif /* USE_TLS13 */

	/* Get the nonce that's used to randomise all crypto operations and set 
	   up the server DH/ECDH context if necessary */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 && \
		actionType == TLSHELLO_ACTION_RETRY )
		{
		static_assert( TLS_NONCE_SIZE == TLS_HELLORETRY_MAGIC_SIZE,
					   "TLS_HELLORETRY_MAGIC_SIZE" );

		/* Set the nonce magic value that converts a Server Hello into a 
		   Hello Retry Request and remember that this is a Hello Retry 
		   Request rather than a Server Hello */
		REQUIRES( TLS_HELLORETRY_MAGIC_SIZE == TLS_NONCE_SIZE );
		memcpy( handshakeInfo->serverNonce, TLS_HELLORETRY_MAGIC, 
				TLS_HELLORETRY_MAGIC_SIZE );

		/* Record that we're retrying the client hello.  This both modifies 
		   the Server Hello that we're about to send and indicates that 
		   we've already given the client a second chance when reading the
		   new Client Hello, and no further ones are allowed */
		handshakeInfo->flags |= HANDSHAKE_FLAG_RETRIEDCLIENTHELLO;
		}
	else
#endif /* USE_TLS13 */
		{
		setMessageData( &msgData, handshakeInfo->serverNonce, 
						TLS_NONCE_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		}
	if( cryptStatusOK( status ) && serverVersion >= TLS_MINOR_VERSION_TLS12 )
		{
		/* Set the downgrade-protection value based on the (apparent) 
		   requested protocol version.  The client can use this to detect 
		   downgrade attacks by comparing the version it requested, e.g. 
		   TLS 1.2, with the value it gets back.  If it gets TLS 1.1 then 
		   it knows there's been a downgrade attack */
#ifdef USE_TLS13
		if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS13 )
			{
			memcpy( handshakeInfo->serverNonce + TLS_DOWNGRADEID_OFFSET, 
					( sessionInfoPtr->version == TLS_MINOR_VERSION_TLS12 ) ? \
					  TLS_DOWNGRADEID_TLS12 : TLS_DOWNGRADEID_TLS11, 
					TLS_DOWNGRADEID_SIZE );
			}
#else
		if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
			{
			memcpy( handshakeInfo->serverNonce + TLS_DOWNGRADEID_OFFSET, 
					TLS_DOWNGRADEID_TLS11, TLS_DOWNGRADEID_SIZE );
			}
#endif /* USE_TLS13 */
		}
	if( cryptStatusOK( status ) && isKeyexAlgo( handshakeInfo->keyexAlgo ) && \
		sessionInfoPtr->version <= TLS_MINOR_VERSION_TLS12 )
		{
		/* For TLS 1.3 the keyex setup is stuffed into the client/server 
		   hello so the DH contexts have already been set up as a side-effect
		   of processing the client hello */
		REQUIRES( ( isEccAlgo( handshakeInfo->keyexAlgo ) && \
					handshakeInfo->keyexGroupInfo != NULL ) || \
				  !isEccAlgo( handshakeInfo->keyexAlgo ) );
		status = initKeyexContextTLS( &handshakeInfo->keyexContext, NULL, 0,
						( handshakeInfo->authAlgo != CRYPT_ALGO_NONE ) ? \
							sessionInfoPtr->privateKey : CRYPT_UNUSED,
						isEccAlgo( handshakeInfo->keyexAlgo ) ? \
							handshakeInfo->keyexGroupInfo->eccCurveID : \
							CRYPT_ECCCURVE_NONE,
						TEST_FLAG( sessionInfoPtr->protocolFlags,
								   TLS_PFLAG_TLS12LTS ) ? TRUE : FALSE );
		}
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "initDHcontextTLS" );

	/* Build the Server Hello, Certificate, optional Certificate Request, 
	   and Hello Done packets:

		byte		ID = TLS_HAND_SERVER_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		byte[32]	nonce
		byte		sessIDlen
			byte[]	sessID
		uint16		suite
		byte		copr = 0
	  [	uint16	extListLen		-- RFC 3546/RFC 4366/RFC 6066
			byte	extType
			uint16	extLen
			byte[]	extData ] 
		...

	   We have to be careful how we handle extensions because the RFC makes 
	   the rather optimistic assumption that implementations can handle the 
	   presence of unexpected data at the end of the hello packet, to avoid 
	   problems with this we avoid sending extensions unless they're in 
	   response to extensions already sent by the client */
	status = openPacketStreamTLS( stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
								  TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	status = continueHSPacketStream( stream, TLS_HAND_SERVER_HELLO, 
									 &packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	sputc( stream, TLS_MAJOR_VERSION );
	sputc( stream, min( sessionInfoPtr->version, 
						TLS_MINOR_VERSION_TLS12 ) );
	swrite( stream, handshakeInfo->serverNonce, TLS_NONCE_SIZE );
	sputc( stream, handshakeInfo->sessionIDlength );
	if( handshakeInfo->sessionIDlength > 0 )
		{
		swrite( stream, handshakeInfo->sessionID, 
				handshakeInfo->sessionIDlength );
		}
	INJECT_FAULT( SESSION_CORRUPT_HANDSHAKE, 
				  SESSION_CORRUPT_HANDSHAKE_TLS_1 );
	writeUint16( stream, handshakeInfo->cipherSuite ); 
	status = sputc( stream, 0 );	/* No compression */
	if( cryptStatusOK( status ) && \
		( handshakeInfo->flags & HANDSHAKE_FLAG_HASEXTENSIONS ) )
		{
		status = writeServerExtensions( stream, sessionInfoPtr, 
										handshakeInfo );
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, TLS_HEADER_SIZE,
											  &serverHelloLength );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "serverHello" );

	/* TLS 1.2 LTS and TLS 1.3 hash the Client and Server Hello and verify 
	   them before the overall handshake hash is completed so we hash them
	   now */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS ) || \
		sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		HASH_FUNCTION hashFunction;
		HASHINFO hashInfo;
		int hashSize;

		/* Hash the Client and Server Hello messages.  We can only be using 
		   SHA2-256 at this point due to the LTS/TLS 1.3 cipher suite 
		   negotiation so we hardcode that into the hashing */
		getHashParameters( CRYPT_ALGO_SHA2, bitsToBytes( 256 ), &hashFunction, 
						   &hashSize );
		hashFunction( hashInfo, NULL, 0, sessionInfoPtr->receiveBuffer, 
					  clientHelloLength, HASH_STATE_START );
		hashFunction( hashInfo, handshakeInfo->helloHash, CRYPT_MAX_HASHSIZE, 
					  sessionInfoPtr->sendBuffer + TLS_HEADER_SIZE, 
					  serverHelloLength, HASH_STATE_END );
		handshakeInfo->helloHashSize = hashSize;
		DEBUG_DUMP_DATA_LABEL( "Client/Server hello hash (server):",
							   handshakeInfo->helloHash, 
							   handshakeInfo->helloHashSize );
		}

	/* If we're talking TLS 1.3, which is an entirely different protocol to
	   standard TLS, we can't continue with this code line */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		status = sendPacketTLS( sessionInfoPtr, stream, FALSE );
		INJECT_FAULT( SESSION_CORRUPT_HANDSHAKE, 
					  SESSION_CORRUPT_HANDSHAKE_TLS_2 );
		if( cryptStatusOK( status ) )
			status = hashHSPacketWrite( handshakeInfo, stream, 0 );
		sMemDisconnect( stream );
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->originalClientHelloLength = clientHelloLength;
		handshakeInfo->originalServerHelloLength = serverHelloLength;
		ENSURES( CFI_CHECK_SEQUENCE_4( "processHelloTLS", "resumedSession", 
									   "initDHcontextTLS", "serverHello" ) );

		return( CRYPT_OK );
		}
#endif /* USE_TLS13 */

	/* TLS 1.2 LTS implicitly enables various other crypto options, now that
	   we've got past the initial negotiations, enable those too */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS ) )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_EMS );
		if( !TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  TLS_PFLAG_ENCTHENMAC );
			}
		}
	CFI_CHECK_UPDATE( "TLS12LTS" );

	/* If it's a resumed session then the Server Hello is followed 
	   immediately by the Change Cipherspec, which is sent by the shared 
	   handshake completion code */
	if( !cryptStatusError( resumedSessionID ) )
		{
		status = completePacketStreamTLS( stream, 0 );
		if( cryptStatusOK( status ) )
			status = hashHSPacketWrite( handshakeInfo, stream, 0 );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		CFI_CHECK_UPDATE( "resumedSession" );

		/* Tell the caller that it's a resumed session, leaving the stream
		   open in order to write the change cipherspec message that follows 
		   the server hello in a resumed session */
		DEBUG_PRINT_BEGIN();
		DEBUG_PUTS(( "Resuming session with client based on sessionID =" ));
		DEBUG_DUMP_DATA( handshakeInfo->sessionID, 
						 handshakeInfo->sessionIDlength );
		DEBUG_PRINT_END();

		ENSURES( CFI_CHECK_SEQUENCE_6( "processHelloTLS", "resumedSession", 
									   "initDHcontextTLS", "serverHello", 
									   "TLS12LTS", "resumedSession" ) );
		return( OK_SPECIAL );
		}
	CFI_CHECK_UPDATE( "nonResumedSession" );

	/*	...	(optional Server Supplemental Data)
		byte		ID = TLS_HAND_SUPPLEMENTAL_DATA
		uint24		len
		uint16		type
		uint16		len
		byte[]		value
		... */

	/*	...
		(optional Server Certificate Chain)
		... */
	if( handshakeInfo->authAlgo != CRYPT_ALGO_NONE )
		{
		INJECT_FAULT( SESSION_WRONGCERT, SESSION_WRONGCERT_TLS_1 );
		status = writeTLSCertChain( sessionInfoPtr, handshakeInfo, stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		INJECT_FAULT( SESSION_WRONGCERT, SESSION_WRONGCERT_TLS_2 );
		}
	CFI_CHECK_UPDATE( "writeTLSCertChain" );

	/*	...			(optional Server Keyex) */
	if( isKeyexAlgo( handshakeInfo->keyexAlgo ) )
		{
		status = continueHSPacketStream( stream, TLS_HAND_SERVER_KEYEXCHANGE, 
										 &packetOffset );
		if( cryptStatusOK( status ) )
			{
			status = createServerKeyex( sessionInfoPtr, handshakeInfo, 
										stream );
			}
		if( cryptStatusOK( status ) )
			status = completeHSPacketStream( stream, packetOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "createServerKeyex" );

	/*	...			(optional Certificate Request)
		byte		ID = TLS_HAND_SERVER_CERTREQUEST
		uint24		len
		byte		certTypeLen
		byte[]		certType = { RSA, DSA, ECDSA }
	  [	uint16	sigHashListLen		-- TLS 1.2 ]
	  [		byte	hashAlgoID		-- TLS 1.2 ]
	  [		byte	sigAlgoID		-- TLS 1.2 ]
		uint16		caNameListLen = 4
			uint16	caNameLen = 2
			byte[]	caName = { 0x30, 0x00 }
		... */
	if( clientCertAuthRequired( sessionInfoPtr ) )
		{
		status = continueHSPacketStream( stream, TLS_HAND_SERVER_CERTREQUEST, 
										 &packetOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		status = writeCertRequest( sessionInfoPtr, stream );
		if( cryptStatusOK( status ) )
			status = completeHSPacketStream( stream, packetOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "writeCertRequest" );

	/*	...
		byte		ID = TLS_HAND_SERVER_HELLODONE
		uint24		len = 0 */
	status = continueHSPacketStream( stream, TLS_HAND_SERVER_HELLODONE, 
									 &packetOffset );
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "completeHSPacketStream" );

	/* Send the combined server packets to the client.  We perform the 
	   assorted hashing of the packets in between the network ops where 
	   it's effectively free */
	status = sendPacketTLS( sessionInfoPtr, stream, FALSE );
	INJECT_FAULT( SESSION_CORRUPT_HANDSHAKE, SESSION_CORRUPT_HANDSHAKE_TLS_2 );
	if( cryptStatusOK( status ) )
		status = hashHSPacketWrite( handshakeInfo, stream, 0 );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "sendPacketTLS" );

	ENSURES( CFI_CHECK_SEQUENCE_12( "processHelloTLS", "resumedSession", 
									"initDHcontextTLS", "serverHello", 
									"TLS12LTS", "resumedSession",
									"nonResumedSession", "writeTLSCertChain", 
									"createServerKeyex", "writeCertRequest",
									"completeHSPacketStream", "sendPacketTLS" ) );
	return( CRYPT_OK );
	}

/* Exchange keys with the client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int exchangeServerKeys( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Read the response from the client and, if we're expecting a client 
	   certificate, make sure that it's present */
	status = readHSPacketTLS( sessionInfoPtr, handshakeInfo, &length,
							  TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	if( clientCertAuthRequired( sessionInfoPtr ) )
		{
		/* Read the client certificate chain and make sure that the 
		   certificate being presented is valid for access */
		status = readCheckClientCerts( sessionInfoPtr, handshakeInfo, 
									   stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}

		/* Read the next packet(s) if necessary */
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "readCheckClientCerts" );

	/* Process the client key exchange packet */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_CLIENT_KEYEXCHANGE, 
								  UINT16_SIZE + 1 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	status = processKeyex( sessionInfoPtr, handshakeInfo, stream );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "processKeyex" );

	/* Create the session hash if required */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_EMS ) || \
		clientCertAuthRequired( sessionInfoPtr ) )
		{
		status = createSessionHash( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "createSessionHash" );

	/* If we're expecting a client certificate, process the client 
	   certificate verify */
	if( clientCertAuthRequired( sessionInfoPtr ) )
		{
		/* Read the next packet(s) if necessary */
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Process the client certificate verify packet:

			byte		ID = TLS_HAND_CERTVERIFY
			uint24		len
			byte[]		signature */
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  TLS_HAND_CERTVERIFY, 
									  min( MIN_PKCSIZE_ECCPOINT, 
										   MIN_PKCSIZE ) );
		if( cryptStatusOK( status ) )
			{
			status = checkCertVerify( sessionInfoPtr, handshakeInfo, stream, 
									  length );
			destroySessionHash( handshakeInfo );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}
	sMemDisconnect( stream );
	CFI_CHECK_UPDATE( "checkCertVerify" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "readCheckClientCerts", "processKeyex", 
								   "createSessionHash", "checkCertVerify" ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initTLSserverProcessing( TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	FNPTR_SET( handshakeInfo->beginHandshake, beginServerHandshake );
	FNPTR_SET( handshakeInfo->exchangeKeys, exchangeServerKeys );
	}
#endif /* USE_TLS */
