/****************************************************************************
*																			*
*						cryptlib SSHv2 Session Management					*
*						Copyright Peter Gutmann 1998-2025					*
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

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Initialise crypto-related handshake information */

STDC_NONNULL_ARG( ( 1 ) ) \
void initHandshakeCrypt( INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	/* Set the initial hash algorithm used to authenticate the handshake.  
	   This will usually be overridden later by SHA-2 if the peer indicates
	   support for it */
	handshakeInfo->exchangeHashAlgo = CRYPT_ALGO_SHA1;

	initHandshakeAlgos( handshakeInfo );
	}

/* Hash the SSH ID strings that are exchanged as pre-handshake out-of-band 
   data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int hashHandshakeStrings( INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo,
						  IN_BUFFER( clientStringLength ) \
								const void *clientString,
						  IN_LENGTH_SHORT const int clientStringLength,
						  IN_BUFFER( serverStringLength ) \
								const void *serverString,
						  IN_LENGTH_SHORT const int serverStringLength )
	{
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( clientString, clientStringLength ) );
	assert( isReadPtrDynamic( serverString, serverStringLength ) );

	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeNZ( clientStringLength ) );
	REQUIRES( isShortIntegerRangeNZ( serverStringLength ) );

	/* If we're fuzzing then there's no crypto active */
	FUZZ_SKIP_REMAINDER();

	/* SSH hashes the handshake ID strings for integrity-protection purposes, 
	   first the client string and then the server string, encoded as SSH 
	   string values.  In addition since the handshake can retroactively 
	   switch to a different hash algorithm mid-exchange we have to 
	   speculatively hash the messages with alternative algorithms in case 
	   the other side decides to switch */
	status = hashAsString( handshakeInfo->iExchangeHashContext, 
						   clientString, clientStringLength );
	if( cryptStatusOK( status ) )
		{
		status = hashAsString( handshakeInfo->iExchangeHashContext,
							   serverString, serverStringLength );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( handshakeInfo->iExchangeHashAltContext == CRYPT_ERROR )
		return( CRYPT_OK );
	status = hashAsString( handshakeInfo->iExchangeHashAltContext, 
						   clientString, clientStringLength );
	if( cryptStatusOK( status ) )
		{
		status = hashAsString( handshakeInfo->iExchangeHashAltContext,
							   serverString, serverStringLength );
		}
	return( status );
	}

/* Check either the other side's encoded keyex value or the decoded (EC)DH 
   public value to make sure that the size is valid */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
int checkKeyexValueLength( const SSH_HANDSHAKE_INFO *handshakeInfo,
						   IN_PTR_OPT const KEYAGREE_PARAMS *keyAgreeParams,
						   IN_ENUM( KEYEX_CHECK ) \
								const KEYEX_CHECK_TYPE checkType,
						   INOUT_PTR ERROR_INFO *errorInfo )
	{
	const char *errorInfoString; 
	int lengthToCheck, extraLength, keyexSize;
	
	assert( isReadPtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( keyAgreeParams == NULL || \
			isReadPtr( keyAgreeParams, sizeof( KEYAGREE_PARAMS ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );
	REQUIRES( isEnumRange( checkType, KEYEX_CHECK ) );
	REQUIRES( ( ( checkType == KEYEX_CHECK_PHASE1 || \
				  checkType == KEYEX_CHECK_PHASE2 ) && \
				  keyAgreeParams == NULL ) || \
			  ( checkType == KEYEX_CHECK_MPI && \
				keyAgreeParams != NULL ) ); 

	/* Select the appropriate parameters to check */
	switch( checkType )
		{
		case KEYEX_CHECK_MPI:
			ANALYSER_HINT( keyAgreeParams != NULL );
			lengthToCheck = keyAgreeParams->publicValueLen;
			extraLength = 0;
			errorInfoString = "phase 1 MPI";
			break;
		
		case KEYEX_CHECK_PHASE1:
			lengthToCheck = handshakeInfo->clientKeyexValueLength;
			extraLength = LENGTH_SIZE;
			errorInfoString = "phase 1 keyex";
			break;

		case KEYEX_CHECK_PHASE2:
			lengthToCheck = handshakeInfo->serverKeyexValueLength;
			extraLength = LENGTH_SIZE;
			errorInfoString = "phase 2 keyex";
			break;
		
		default:
			retIntError();
		}

	/* Perform the appropriate algorithm-specific check */
	if( handshakeInfo->isECDH )
		{
		if( isBernsteinAlgo( handshakeInfo->keyexAlgo ) )
			{
			if( isValidBernsteinDHsize( lengthToCheck, 
										handshakeInfo->serverKeySize, 
										extraLength ) )
				return( CRYPT_OK );
			keyexSize = extractBernsteinDHsize( lengthToCheck, extraLength );
			}
		else
			{
			if( isValidECDHsize( lengthToCheck, 
								 handshakeInfo->serverKeySize, 
								 extraLength ) )
				return( CRYPT_OK );
			keyexSize = extractECDHsize( lengthToCheck, extraLength );
			}
		}
	else
		{
		if( isValidDHsize( lengthToCheck, handshakeInfo->serverKeySize, 
						   extraLength ) )
			return( CRYPT_OK );
		keyexSize = extractDHsize( lengthToCheck, extraLength );
		}

	retExt( CRYPT_ERROR_BADDATA,
			( CRYPT_ERROR_BADDATA, errorInfo, 
			  "Invalid %s %s size, expected %d (%d), "
			  "got %d (%d)", handshakeInfo->isECDH ? "ECDH" : "DH",
			  errorInfoString, handshakeInfo->serverKeySize, 
			  handshakeInfo->serverKeySize * 8, 
			  keyexSize, keyexSize * 8 ) );
	}

/* Check whether a packet trace conforms to the strict KEX requirements.
   The handshake packet flow that cryptlib allows is:

	Client: Read SSH_MSG_KEXINIT
			Write SSH_MSG_KEXINIT
				(Write SSH_MSG_KEX_DH_GEX_REQUEST(_OLD)
				 Read SSH_MSG_KEX_DH_GEX_GROUP)
			Write SSH_MSG_KEXDH_INIT / SSH_MSG_KEX_DH_GEX_INIT
			Read SSH_MSG_KEXDH_REPLY / SSH_MSG_KEX_DH_GEX_REPLY
			Write SSH_MSG_NEWKEYS
			Read SSH_MSG_NEWKEYS
	Server: Write SSH_MSG_KEXINIT
			Read SSH_MSG_KEXINIT
				(Read SSH_MSG_KEX_DH_GEX_REQUEST(_OLD)
				 Write SSH_MSG_KEX_DH_GEX_GROUP)
			Read SSH_MSG_KEXDH_INIT / SSH_MSG_KEX_DH_GEX_INIT
			Write SSH_MSG_KEXDH_REPLY / SSH_MSG_KEX_DH_GEX_REPLY
			Write SSH_MSG_NEWKEYS
			Read SSH_MSG_NEWKEYS 

   However this is complicated by the fact that some values are overloaded 
   for multiple message types:

	30: SSH_MSG_KEXDH_INIT, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_HYBRID_INIT,
		SSH_MSG_KEX_DH_GEX_REQUEST_OLD
	31: SSH_MSG_KEXDH_REPLY, SSH_MSG_KEX_ECDH_REPLY, SSH_MSG_KEX_HYBRID_REPLY,
		SSH_MSG_KEX_DH_GEX_GROUP
	32: SSH_MSG_KEX_DH_GEX_INIT
	33: SSH_MSG_KEX_DH_GEX_REPLY
	34: SSH_MSG_KEX_DH_GEX_REQUEST

   This makes checking difficult because after we've seen the 
   SSH_MSG_KEXINIT we'll see (server-side) a 30 but don't know whether it's 
   a SSH_MSG_xxx_INIT or an SSH_MSG_KEX_DH_GEX_REQUEST_OLD, or (client-side) 
   a 31 but don't know whether it's a SSH_MSG_xxx_REPLY or 
   SSH_MSG_KEX_DH_GEX_GROUP.  We could look ahead one packet and modify our
   view of what we're seeing based on that, but a much simpler way to do it
   is to have an allowlist of permitted traces and check the submitted trace
   against that.
   
   Note that the following could in theory be replaced by a simple loop that 
   just looks for packets < 30 or > 34 bracketed by the INIT/NEWKEYS since 
   the protocol ladder-diagram implementation enforces the correct packet 
   sequencing, but we perform the full check as belt-and-suspenders as well 
   as an exercise in documenting the message flow.
   
   In a way, this is *really* strict KEX */

typedef struct {
	BUFFER_FIXED( traceLength ) \
	const BYTE trace[ 6 ];
	const int traceLength;
	} KEYEX_TRACE_INFO;
	
static const KEYEX_TRACE_INFO clientKeyexTrace[] = {
	/* Trace of allowable packets as read by the client.  The first one 
	   covers all of the 20, 31 variants (DH, ECDH, hybrid), the remainder
	   the negotiated DH variants 20, 31, 33 */
	{ { SSH_MSG_KEXINIT, SSH_MSG_KEXDH_REPLY, SSH_MSG_NEWKEYS }, 3 },
	{ { SSH_MSG_KEXINIT, SSH_MSG_KEX_DH_GEX_GROUP, SSH_MSG_KEX_DH_GEX_REPLY, SSH_MSG_NEWKEYS }, 4 },
		{ { 0 }, 0 }, { { 0 }, 0 }
	};
static const KEYEX_TRACE_INFO serverKeyexTrace[] = {
	/* Trace of allowable packets as read by the server.  The first one
	   covers all of the 20, 30 variants (DH, ECDH, hybrid), the remainder
	   the negotiated DH variants 20, 34, 32 or 20, 30, 32 */
	{ { SSH_MSG_KEXINIT, SSH_MSG_KEXDH_INIT, SSH_MSG_NEWKEYS }, 3 },
	{ { SSH_MSG_KEXINIT, SSH_MSG_KEX_DH_GEX_REQUEST, SSH_MSG_KEX_DH_GEX_INIT, SSH_MSG_NEWKEYS }, 4 },
	{ { SSH_MSG_KEXINIT, SSH_MSG_KEX_DH_GEX_REQUEST_OLD, SSH_MSG_KEX_DH_GEX_INIT, SSH_MSG_NEWKEYS }, 4 },
		{ { 0 }, 0 }, { { 0 }, 0 }
	};

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkStrictKEX( IN_BUFFER( packetTraceLen ) const BYTE *packetTrace,
						IN_LENGTH_SHORT const int packetTraceLen,
						IN_BOOL const BOOLEAN isServer )
	{
	const KEYEX_TRACE_INFO *keyexTraceTbl = isServer ? \
				serverKeyexTrace : clientKeyexTrace;
	const int keyexTraceTblSize = isServer ? \
				FAILSAFE_ARRAYSIZE( serverKeyexTrace, KEYEX_TRACE_INFO ) : \
				FAILSAFE_ARRAYSIZE( clientKeyexTrace, KEYEX_TRACE_INFO );
	LOOP_INDEX i;
	
	assert( isReadPtrDynamic( packetTrace, packetTraceLen ) );
	
	REQUIRES_B( isShortIntegerRangeNZ( packetTraceLen ) );
	REQUIRES_B( isBooleanValue( isServer ) );
	
	/* We need at least three packets in the trace */
	if( packetTraceLen < 3 )
		return( FALSE );

	/* Check whether the packet trace matches one of the permitted ones */
	LOOP_SMALL( i = 0, i < keyexTraceTblSize && \
					   keyexTraceTbl[ i ].traceLength != 0, i++ )
		{
		ENSURES_B( LOOP_INVARIANT_SMALL( i, 0, keyexTraceTblSize - 1 ) );
		
		if( keyexTraceTbl[ i ].traceLength != packetTraceLen )
			continue;
		if( !memcmp( keyexTraceTbl[ i ].trace, packetTrace, 
					 packetTraceLen ) )
			{
			DEBUG_PRINT(( "Strict KEX check passed.\n" ));
			return( TRUE );
			}
		}
	ENSURES_B( LOOP_BOUND_OK );

	DEBUG_PRINT(( "Strict KEX violation detected.\n" ));
	return( FALSE );
	}

/****************************************************************************
*																			*
*							Extension Functions								*
*																			*
****************************************************************************/

#ifdef USE_SSH_EXTENDED

/* Read/write extension information packets:

	byte		type = SSH_MSG_EXT_INFO
	uint32		no_extensions
		string	name
		string	value (binary data) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readExtensionsSSH( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					   INOUT_PTR STREAM *stream )
	{
	LOOP_INDEX i;
	int noExtensions, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );

	/* Get the number of extensions present and make sure that it's valid */
	status = noExtensions = readUint32( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid SSH extension information" ) );
		}
	if( noExtensions < 1 || noExtensions > 16 )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid SSH extension count %d, should be 1...16", 
				  noExtensions ) );
		}

	/* Process the extensions */
	LOOP_MED( i = 0, i < noExtensions, i++ )
		{
		BYTE nameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
		void *dataPtr = NULL;
		int nameLength, dataLength;

		ENSURES( LOOP_INVARIANT_MED( i, 0, noExtensions - 1 ) );

		/* Read the extension name */
		status = readString32( stream, nameBuffer, CRYPT_MAX_TEXTSIZE, 
							   &nameLength );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Invalid SSH extension name for extension %d", i ) );
			}

		/* Read the extension data.  This may in theory be of zero length 
		   for some extensions, although currently all zero-length 
		   extensions consist of a redundant 'y' or 'n' to back up the 
		   presence of the extension itself */
		status = dataLength = readUint32( stream );
		if( !cryptStatusError( status ) && \
			!isShortIntegerRange( dataLength ) )
			status = CRYPT_ERROR_BADDATA;
		if( !cryptStatusError( status ) && dataLength > 0 )
			{
			/* Get a pointer to the data payload */
			status = sMemGetDataBlock( stream, &dataPtr, dataLength );
			if( cryptStatusOK( status ) )
				{
				status = sSkip( stream, dataLength, 
								MAX_INTLENGTH_SHORT );
				}
			}
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid extension data for extension %d, '%s'", i,
					  sanitiseString( nameBuffer, CRYPT_MAX_TEXTSIZE, 
									  nameLength ) ) );
			}
		DEBUG_PRINT(( "Read extension %d, '%s', length %d.\n", i,
					  sanitiseString( nameBuffer, CRYPT_MAX_TEXTSIZE, 
									  nameLength ), 
					  dataLength ));
		DEBUG_DUMP_DATA_COND( dataPtr != NULL, ( dataPtr, dataLength ) );

		/* Process the extension data.  For now there's nothing much to do 
		   here, the only extension that really affects us is 
		   "server-sig-algs" which in theory is required before using RSA 
		   with SHA-2 signatures for client auth, however the presence of
		   a SHA-2 capability on the server always seems to imply SHA-2 
		   client signature handling so it's not clear whether the extra
		   parsing and processing is really worth it, particularly since
		   using RSA-with-SHA2 when SHA2 is indicated always seems to work
		   while using it only when "server-sig-algs" is present means that 
		   it'll only work on the subset of servers that implement 
		   extensions */
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeExtensionsSSH( INOUT_PTR STREAM *stream )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Write the total extension count.  See the comment for the 
	   no-flow-control extension for why we only write this if basic SSH
	   functionality is enabled.
	   
	   Note that this entire code block is currently only enabled if 
	   USE_SSH_EXTENDED is set, so the #ifdef check below is present for 
	   future use */
#ifndef USE_SSH_EXTENDED 
	writeUint32( stream, 2 );
#else
	writeUint32( stream, 1 );
#endif /* USE_SSH_EXTENDED */

	/* Write the server signature algorithms extension */
	status = writeString32( stream, "server-sig-algs", 15 );
	if( cryptStatusOK( status ) )
		status = writeAlgoClassList( stream, SSH_ALGOCLASS_SIGN );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the no-flow-control extension.  This is a real pain to deal 
	   with, the RFC requires, for no obvious reason, that "Implementations 
	   MUST refuse to open more than one simultaneous channel when this 
	   extension is in effect", but then bizarrely adds that "Nevertheless, 
	   server implementations SHOULD support clients opening more than one 
	   non-simultaneous channel".  This confusion will no doubt lead to more
	   or less arbitrary behaviour among implementations, rather than having
	   to fingerprint and identify issues in who knows how many different
	   versions we only send this extension if USE_SSH_EXTENDED isn't 
	   defined, in which case we only allow a single channel no matter 
	   what */
#ifndef USE_SSH_EXTENDED 
	writeString32( stream, "no-flow-control", 15 );
	status = writeString32( stream, "p", 1 );
#endif /* !USE_SSH_EXTENDED */
	
	return( status );
	}
#endif /* USE_SSH_EXTENDED */

/****************************************************************************
*																			*
*						Pre-Authentication Functions						*
*																			*
****************************************************************************/

/* Create a pre-authentication challenge value to send to the client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int createPreauthChallengeResponse( INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo,
									const SESSION_ATTRIBUTE_LIST *attributeListPtr )
	{
	MESSAGE_DATA msgData;
	BYTE nonce[ SSH_PREAUTH_NONCE_SIZE + 8 ];
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( attributeListPtr, \
					   sizeof( SESSION_ATTRIBUTE_LIST ) ) );

	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );

	/* Get the challenge nonce and base64-encode it */
	setMessageData( &msgData, nonce, SSH_PREAUTH_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusOK( status ) )
		{
		status = base64encode( handshakeInfo->challenge, SSH_PREAUTH_MAX_SIZE, 
							   &handshakeInfo->challengeLength, nonce, 
							   SSH_PREAUTH_NONCE_SIZE, CRYPT_CERTTYPE_NONE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Compute the expected response to our challenge */
	return( createPreauthResponse( handshakeInfo, attributeListPtr ) );
	}

/* Create a pre-authentication response value to send to the server or check
   against the client's value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int createPreauthResponse( INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo,
						   const SESSION_ATTRIBUTE_LIST *attributeListPtr )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	MAC_FUNCTION_ATOMIC macFunctionAtomic;
	STREAM stream;
	BYTE keyData[ CRYPT_MAX_HASHSIZE + CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE key[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE rawResponse[ CRYPT_MAX_HASHSIZE + 8 ];
	int keyDataLength DUMMY_INIT;
	int hashSize, status;

	/* The preauth nonce is a truncated SHA-256 hash */
	static_assert( SSH_PREAUTH_NONCE_SIZE <= 32,
				   "SSH_PREAUTH_NONCE_SIZE larger than SHA-256 hash" );

	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( attributeListPtr, \
					   sizeof( SESSION_ATTRIBUTE_LIST ) ) );

	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeNZ( handshakeInfo->challengeLength ) );

	/* Format the information that we need to hash to get the HMAC key:
	
		string	challenge
		string	preAuthSecret */
	sMemOpen( &stream, keyData, CRYPT_MAX_HASHSIZE + CRYPT_MAX_TEXTSIZE );
	writeString32( &stream, handshakeInfo->challenge, 
				   handshakeInfo->challengeLength );
	status = writeString32( &stream, attributeListPtr->value, 
							attributeListPtr->valueLength );
	if( cryptStatusOK( status ) )
		status = keyDataLength = stell( &stream );
	sMemDisconnect( &stream );
	ENSURES( !cryptStatusError( status ) );
	ENSURES( isShortIntegerRangeNZ( keyDataLength ) );

	/* Hash the information into an HMAC key */
	getHashAtomicParameters( CRYPT_ALGO_SHA2, 0, &hashFunctionAtomic, 
							 &hashSize );
	hashFunctionAtomic( key, CRYPT_MAX_HASHSIZE, keyData, keyDataLength );
	zeroise( keyData, CRYPT_MAX_HASHSIZE + CRYPT_MAX_TEXTSIZE );

	/* Hash the challenge into the response:

		rawResponse = HMAC( key, challenge );
		response = base64( rawResponse ); */
	getMacAtomicFunction( CRYPT_ALGO_HMAC_SHA2, &macFunctionAtomic );
	macFunctionAtomic( rawResponse, CRYPT_MAX_HASHSIZE, hashSize,
					   key, hashSize, handshakeInfo->challenge, 
					   handshakeInfo->challengeLength );
	zeroise( key, CRYPT_MAX_HASHSIZE );
	status = base64encode( handshakeInfo->response, SSH_PREAUTH_MAX_SIZE, 
						   &handshakeInfo->responseLength, rawResponse, 
						   SSH_PREAUTH_NONCE_SIZE, CRYPT_CERTTYPE_NONE );
	zeroise( rawResponse, CRYPT_MAX_HASHSIZE );
	ENSURES( handshakeInfo->responseLength == SSH_PREAUTH_NONCE_ENCODEDSIZE );

	return( status );
	}

/* Check that a pre-authentication response is valid */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkPreauthResponse( INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo,
						  INOUT_PTR ERROR_INFO *errorInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );
	REQUIRES( handshakeInfo->responseLength == \
										SSH_PREAUTH_NONCE_ENCODEDSIZE && \
			  handshakeInfo->receivedResponseLength == \
										SSH_PREAUTH_NONCE_ENCODEDSIZE );
			  /* Guaranteed from createPreauthResponse() / checked in 
			     readSSHID() */

	/* Make sure that the response from the client matches the one that we
	   calculated.  The error message reports the expected and actual 
	   values, the actual value is public and the expected value is an
	   HMAC of another public value used to cut down on door-knocking
	   attacks that shouldn't end up ever being seen by an attacker so there
	   shouldn't be any problem with including it in an error message */
	if( compareDataConstTime( handshakeInfo->response,
							  handshakeInfo->receivedResponse,
							  SSH_PREAUTH_NONCE_ENCODEDSIZE ) != TRUE )
		{
		retExtSan( CRYPT_ERROR_SIGNATURE, 
				   ( CRYPT_ERROR_SIGNATURE, errorInfo, 
					 "Client sent invalid response '%s' to our challenge, "
					 "should have been '%s'",
					 handshakeInfo->receivedResponse, 
						SSH_PREAUTH_NONCE_ENCODEDSIZE,
					 handshakeInfo->response, 
						SSH_PREAUTH_NONCE_ENCODEDSIZE, NULL, 0 ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Process a control message received during the processBodyFunction() */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int processControlMessage( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								  IN_DATALENGTH_Z const int payloadLength )
	{
	SSH_INFO *sshInfo = DATAPTR_GET( sessionInfoPtr->sessionInfo );
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos;
	STREAM stream;
	int localPayloadLength = payloadLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isBufsizeRange( payloadLength ) );
	REQUIRES( sshInfo != NULL );

	/* Putty 0.59 erroneously sent zero-length SSH_MSG_IGNORE packets, if 
	   we find one of these then we convert it into a valid packet.  Writing 
	   into the buffer at this position is safe because we've got padding 
	   and at least sessionInfoPtr->authBlocksize bytes of MAC following the 
	   current position.  We can also modify the localPayloadLength value 
	   for the same reason */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, 
				   SSH_PFLAG_ZEROLENIGNORE ) && \
		sshInfo->packetType == SSH_MSG_IGNORE && localPayloadLength == 0 )
		{
		REQUIRES( boundsCheckZ( sessionInfoPtr->receiveBufPos, UINT32_SIZE,
								sessionInfoPtr->receiveBufSize ) );
		memset( bufPtr, 0, UINT32_SIZE );
		localPayloadLength = UINT32_SIZE;
		}

	/* Make sure that the message length is valid.  This will be caught 
	   anyway when we try and process the channel control message (and the
	   excessive-length check has already been performed by the packet-read 
	   code) but checking it here avoids an assertion in the debug build 
	   when we connect the stream, as well as just being good programming 
	   practice */
	if( localPayloadLength <= 0 || \
		checkOverflowSub( sessionInfoPtr->receiveBufEnd, \
						  sessionInfoPtr->receiveBufPos ) || \
		localPayloadLength > sessionInfoPtr->receiveBufEnd - \
							 sessionInfoPtr->receiveBufPos )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid session control message payload length %d for "
				  "%s (%d), should be 1...%d", localPayloadLength, 
				  getSSHPacketName( sshInfo->packetType ), 
				  sshInfo->packetType, sessionInfoPtr->receiveBufEnd - \
									   sessionInfoPtr->receiveBufPos ) );
		}

	/* Process the control message and reset the receive buffer indicators 
	   to clear it */
	ENSURES( boundsCheckZ( sessionInfoPtr->receiveBufPos, localPayloadLength,
						   sessionInfoPtr->receiveBufEnd ) );
	sMemConnect( &stream, bufPtr, localPayloadLength );
	status = processChannelControlMessage( sessionInfoPtr, &stream );
	sMemDisconnect( &stream );
	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos;
	sessionInfoPtr->pendingPacketLength = 0;

	return( status );
	}

/* Read data over the SSH link */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readHeaderFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   OUT_ENUM_OPT( READINFO ) \
									READSTATE_INFO *readInfo )
	{
	SSH_INFO *sshInfo = DATAPTR_GET( sessionInfoPtr->sessionInfo );
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos;
#ifdef USE_SSH_OPENSSH
	const BOOLEAN useETM = \
			TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_ETM ) ? \
			TRUE : FALSE;
#endif /* USE_SSH_OPENSSH */
	int length, extraLength, removedDataLength = ID_SIZE + PADLENGTH_SIZE;
	int partialPayloadLength, payloadBytesRead, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	static_assert( SSH_HEADER_REMAINDER_SIZE >= ID_SIZE + \
						PADLENGTH_SIZE + SSH2_MIN_PADLENGTH_SIZE,
				   "SSH header size read" );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sshInfo != NULL );

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* Make sure that there's room left to handle the speculative read */
	REQUIRES( !checkOverflowSub( sessionInfoPtr->receiveBufSize, 128 ) );
	if( sessionInfoPtr->receiveBufPos >= \
								sessionInfoPtr->receiveBufSize - 128 )
		return( 0 );

	/* Try and read the header data from the remote system */
	REQUIRES( sessionInfoPtr->receiveBufPos == sessionInfoPtr->receiveBufEnd );
	status = readPacketHeaderSSH2( sessionInfoPtr, SSH_MSG_CHANNEL_DATA,
								   &length, &extraLength, &payloadBytesRead, 
								   sshInfo, readInfo, SSH_PROTOSTATE_DATA );
	if( cryptStatusError( status ) )
		{
		/* OK_SPECIAL means that we got a soft timeout before the entire 
		   header was read, so we return zero bytes read to tell the 
		   calling code that there's nothing more to do */
		if( status == OK_SPECIAL ) 
			return( 0 );

		return( status );
		}

	/* All errors from this point are fatal crypto errors */
	*readInfo = READINFO_FATAL_CRYPTO;

	ENSURES( isBufsizeRangeMin( length, \
								ID_SIZE + PADLENGTH_SIZE + \
									SSH2_MIN_PADLENGTH_SIZE ) && \
			 length <= sessionInfoPtr->receiveBufSize - \
					   sessionInfoPtr->receiveBufPos );
#ifdef USE_SSH_OPENSSH
	REQUIRES( !useETM || payloadBytesRead <= CRYPT_MAX_IVSIZE );
	status = checkMacSSHIncremental( sessionInfoPtr->iAuthInContext, 
							sshInfo->readSeqNo, 
							useETM ? sshInfo->encryptedHeaderBuffer : 
							bufPtr, payloadBytesRead, payloadBytesRead, 
							length, MAC_START, extraLength );
#else
	status = checkMacSSHIncremental( sessionInfoPtr->iAuthInContext, 
							sshInfo->readSeqNo, 
							bufPtr, payloadBytesRead, payloadBytesRead, 
							length, MAC_START, extraLength );
#endif /* USE_SSH_OPENSSH */
	if( cryptStatusError( status ) )
		{
		/* We don't return an extended status at this point because we
		   haven't completed the message MAC calculation/check yet so 
		   any errors will be cryptlib-internal ones */
		return( status );
		}

	/* If it's channel data, strip the encapsulation, which allows us to
	   process the payload directly without having to move it around in
	   the buffer:

	  [	uint32		length (excluding MAC size)	- Processed in rPHSSH2() ]
		byte		padLen
		byte		SSH_MSG_CHANNEL_DATA
			uint32	recipient channel
			uint32	dataLength	| string	data
			byte[]	data		|
	  [ byte[]		padding ]
	  [	byte[]		MAC ] */
	if( sshInfo->packetType == SSH_MSG_CHANNEL_DATA )
		{
		STREAM stream;
		int payloadLength DUMMY_INIT;

		ENSURES( boundsCheckZ( sessionInfoPtr->receiveBufPos, 
							   payloadBytesRead, 
							   sessionInfoPtr->receiveBufSize ) );

		sMemConnect( &stream, bufPtr, payloadBytesRead );

		/* Skip the type, padding length, and channel number and make sure 
		   that the payload length matches the packet length */
		status = sSkip( &stream, PADLENGTH_SIZE + ID_SIZE + UINT32_SIZE,
						PADLENGTH_SIZE + ID_SIZE + UINT32_SIZE );
		if( cryptStatusOK( status ) )
			status = payloadLength = readUint32( &stream );
		if( !cryptStatusError( status ) )
			status = removedDataLength = stell( &stream );
		if( cryptStatusError( status ) )
			{
			/* If we don't know how valid the length information is we can't
			   report much more than a general formatting error */
			sMemDisconnect( &stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid data packet length information for "
					  "SSH_MSG_CHANNEL_DATA (94)" ) );
			}
		if(	checkOverflowAdd( removedDataLength, sshInfo->padLength ) || \
			checkOverflowSub( length, 
							  removedDataLength + sshInfo->padLength ) || \
			payloadLength != length - ( removedDataLength + \
										sshInfo->padLength ) )
			{
			sMemDisconnect( &stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid data packet payload length %d for "
					  "SSH_MSG_CHANNEL_DATA (94), should be %d", 
					  payloadLength,
					  length - ( removedDataLength + sshInfo->padLength ) ) );
			}

		/* Errors are back to standard fatal errors */
		*readInfo = READINFO_FATAL;

		/* Move back to the start of the payload and process the channel 
		   data header, required in order to handle window size updates.  
		   This consists of the channel number and yet another length value,
		   present at the start of the payload which is encoded as an SSH
		   string (uint32 length + data).  This value has already been
		   checked above, and is only accepted if it matches the outer
		   length value.
		   
		   This is important because the data hasn't been verified by the 
		   MAC yet, since we need to process the header in order to find out 
		   where the MAC is.  This means that the channel number is 
		   processed unverified, but this shouldn't be a major issue since 
		   at most an attacker can corrupt the value, and it will end up 
		   being mapped to an invalid channel with a high probability 
		   (unless we're using the disabled-by-default extremely brittle CTR 
		   mode that allows arbitrary attacker manipulation of the data).
		   
		   processChannelControlMessage() can return OK_SPECIAL in some
		   cases (SSH_MSG_GLOBAL_REQUEST where the message is handled
		   internally, SSH_MSG_CHANNEL_EXTENDED_DATA) but we're working with
		   SSH_MSG_CHANNEL_DATA for which an OK_SPECIAL return shouldn't
		   happen */
		sseek( &stream, PADLENGTH_SIZE + ID_SIZE );
		status = processChannelControlMessage( sessionInfoPtr, &stream );
		sMemDisconnect( &stream );	/* Read SSH_MSG_CHANNEL_DATA header */
		ENSURES( status != OK_SPECIAL );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Errors are back to standard fatal errors */
	*readInfo = READINFO_FATAL;

	/* Move the remainder down to the start of the buffer.  The general idea
	   is to remove all of the header data so that only the payload remains
	   in the buffer, avoiding the need to move it down afterwards:

			 rBufPos
				|
				v				|<-- pPayloadLen -->|
		+-------+---------------+-------------------+-------+
		|		|				|///////////////////|		|
		+-------+---------------+-------------------+-------+
				^<-removedDLen->|
				|
			 bufPtr
	   
	   This is complicated by the fact that (unlike TLS) all of the data 
	   (including the header in standard non-EtM processing) is encrypted 
	   and MAC'd so we can't just read that separately but have to process 
	   it as part of the payload, remove it, and remember anything that's 
	   left for later */
	REQUIRES( isShortIntegerRangeNZ( removedDataLength ) );
	REQUIRES( !checkOverflowSub( payloadBytesRead, removedDataLength ) );
	partialPayloadLength = payloadBytesRead - removedDataLength;
	ENSURES( partialPayloadLength > 0 && \
			 removedDataLength + partialPayloadLength <= \
				sessionInfoPtr->receiveBufSize - sessionInfoPtr->receiveBufPos && \
			 removedDataLength + partialPayloadLength < MAX_BUFFER_SIZE );
	REQUIRES( boundsCheck( sessionInfoPtr->receiveBufPos + removedDataLength, 
						   partialPayloadLength, 
						   sessionInfoPtr->receiveBufSize ) );
	memmove( bufPtr, bufPtr + removedDataLength, partialPayloadLength );

	/* Determine how much data we'll be expecting, adjusted for the fixed
	   information that we've removed and the (implicitly present) MAC data */
	REQUIRES( !checkOverflowAdd( length, extraLength ) );
	REQUIRES( !checkOverflowSub( length + extraLength, removedDataLength ) );
	sessionInfoPtr->pendingPacketLength = \
			sessionInfoPtr->pendingPacketRemaining = \
					( length + extraLength ) - removedDataLength;
	ENSURES( isBufsizeRangeNZ( sessionInfoPtr->pendingPacketLength ) );
	sshInfo->partialPacketDataLength = partialPayloadLength;

	/* Indicate that we got some payload as part of the header */
	*readInfo = READINFO_HEADERPAYLOAD;
	return( partialPayloadLength );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processBodyFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo )
	{
	SSH_INFO *sshInfo = DATAPTR_GET( sessionInfoPtr->sessionInfo );
	BYTE *dataRemainingPtr;
#ifdef USE_SSH_OPENSSH
	const BOOLEAN useETM = \
			TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_ETM ) ? \
			TRUE : FALSE;
#endif /* USE_SSH_OPENSSH */
	int dataRemainingSize, dataLength, payloadLength, status = CRYPT_OK;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sshInfo != NULL );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	REQUIRES( !checkOverflowAdd( sessionInfoPtr->receiveBufPos,
								 sshInfo->partialPacketDataLength ) );
	REQUIRES( !checkOverflowSub( sessionInfoPtr->pendingPacketLength,
								 sshInfo->partialPacketDataLength ) );
	dataRemainingSize = sessionInfoPtr->pendingPacketLength - \
								sshInfo->partialPacketDataLength;
	dataRemainingPtr = sessionInfoPtr->receiveBuffer + \
					   sessionInfoPtr->receiveBufPos + \
					   sshInfo->partialPacketDataLength;
	REQUIRES( !checkOverflowSub( dataRemainingSize,
								 sessionInfoPtr->authBlocksize ) );
	REQUIRES( boundsCheck( sessionInfoPtr->receiveBufPos + \
											sshInfo->partialPacketDataLength,
						   dataRemainingSize, sessionInfoPtr->receiveBufEnd ) );
	dataLength = dataRemainingSize - sessionInfoPtr->authBlocksize;
	ENSURES( dataRemainingSize >= sessionInfoPtr->authBlocksize && \
			 dataLength >= 0 && dataLength < dataRemainingSize );


	/* All errors processing the payload are fatal, and for the following 
	   operations specifically fatal crypto errors */
	*readInfo = READINFO_FATAL_CRYPTO;

	/* Decrypt the packet in the buffer and MAC the payload.  The length may
	   be zero if the entire message fits into the already-processed fixed-
	   length header portion, e.g. for channel-close messages that only 
	   contain a channel number:
																Key:
			Processed in header read							+--+
		recBufPos |												|  | Processed
			|<----v----- pendingPacketLength ---------->|		+--+
			v<- pPDL -->|								|		+--+
		----+-----------+-----------------------+-------+--		|//| Encrypted
			|			|///////////////////////|\\\\\\\|		+--+
		----+-----------+-----------------------+-------+--		+--+
						|<---- dataLength ----->|		|		|\\| MAC
						|<------- dataRemaining ------->|		+--+ */
	if( dataLength > 0 )
		{
#ifdef USE_SSH_OPENSSH
		if( useETM )
			{
			/* EtM processing, MAC the ciphertext */
			status = checkMacSSHIncremental( sessionInfoPtr->iAuthInContext, 0,
											 dataRemainingPtr, dataRemainingSize, 
											 dataLength, 0, MAC_END, 
											 sessionInfoPtr->authBlocksize );
			}
#endif /* USE_SSH_OPENSSH */
		if( cryptStatusOK( status ) )
			{
#ifdef USE_SSH_CTR
			if( TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_CTR ) )
				{
				status = ctrModeCrypt( sessionInfoPtr->iCryptInContext,
									   sshInfo->readCTR, 
									   sessionInfoPtr->cryptBlocksize,
									   dataRemainingPtr, dataLength );
				}
			else
#endif /* USE_SSH_CTR */
			status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
									  IMESSAGE_CTX_DECRYPT, dataRemainingPtr,
									  dataLength );
			}
#ifdef USE_SSH_OPENSSH
		if( cryptStatusOK( status ) && !useETM )
#else
		if( cryptStatusOK( status ) )
#endif /* USE_SSH_OPENSSH */
			{
			/* Standard processing, MAC the plaintext */
			status = checkMacSSHIncremental( sessionInfoPtr->iAuthInContext, 0,
											 dataRemainingPtr, dataRemainingSize, 
											 dataLength, 0, MAC_END, 
											 sessionInfoPtr->authBlocksize );
			}
		}
	else
		{
		status = checkMacSSHIncremental( sessionInfoPtr->iAuthInContext, 0, 
										 dataRemainingPtr, dataRemainingSize, 
										 0, 0, MAC_END, 
										 sessionInfoPtr->authBlocksize );
		}
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad message MAC for %s (%d) packet, length %d",
				  getSSHPacketName( sshInfo->packetType ),
				  sshInfo->packetType,
				  sshInfo->partialPacketDataLength + dataLength ) );
		}

	/* Errors are back to standard fatal errors */
	*readInfo = READINFO_FATAL;

	/* Strip the padding and MAC and update the state information */
	REQUIRES( !checkOverflowAdd( sshInfo->padLength,
								 sessionInfoPtr->authBlocksize ) );
	REQUIRES( !checkOverflowSub( sessionInfoPtr->pendingPacketLength,
								 sshInfo->padLength + \
										sessionInfoPtr->authBlocksize ) );
	payloadLength = sessionInfoPtr->pendingPacketLength - \
					( sshInfo->padLength + sessionInfoPtr->authBlocksize );
	if( checkOverflowInc( sshInfo->readSeqNo ) )
		{
		/* This is a should-never-occur condition so in theory we could just
		   make it an ENSURES() condition */
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Packet read sequence number overflow reading %s (%d) "
				  "packet, length %d", 
				  getSSHPacketName( sshInfo->packetType ),
				  sshInfo->packetType,
				  sshInfo->partialPacketDataLength + dataLength ) );
		}
	sshInfo->readSeqNo++;
	ENSURES( isBufsizeRange( payloadLength ) && \
			 payloadLength < sessionInfoPtr->pendingPacketLength );
			 /* payloadLength must always be < pendingPacketLength because 
			    of the stripped padding */
	DEBUG_PRINT(( "Read %s (%d) packet, length %d.\n", 
				  getSSHPacketName( sshInfo->packetType ), 
				  sshInfo->packetType, payloadLength ));
	DEBUG_DUMP_DATA( sessionInfoPtr->receiveBuffer + \
					 sessionInfoPtr->receiveBufPos, payloadLength );

	/* If it's not plain data (which was handled at the readHeaderFunction()
	   stage), handle it as a control message */
	if( sshInfo->packetType != SSH_MSG_CHANNEL_DATA )
		{
		status = processControlMessage( sessionInfoPtr, payloadLength );
		if( cryptStatusError( status ) )
			{
			/* If we got an OK_SPECIAL status then the packet was handled
			   internally and we can try again.  If it was a message that
			   the user has to respond to it's also not a fatal error
			   condition and they can continue afterwards */
			if( status == OK_SPECIAL || status == CRYPT_ENVELOPE_RESOURCE )
				{
				sshInfo->partialPacketDataLength = 0;
				*readInfo = READINFO_NOOP;
				}
			return( status );
			}
		}
	sshInfo->partialPacketDataLength = 0;

	*readInfo = READINFO_NONE;
	return( payloadLength );
	}

/* Write data over the SSH link */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
static int preparePacketFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	const SSH_INFO *sshInfo = DATAPTR_GET( sessionInfoPtr->sessionInfo );
	STREAM stream;
	const int dataLength = sessionInfoPtr->sendBufPos - \
						   ( SSH2_HEADER_SIZE + SSH2_PAYLOAD_HEADER_SIZE );
	int length DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sshInfo != NULL );
	REQUIRES( !TEST_FLAG( sessionInfoPtr->flags, 
						  SESSION_FLAG_SENDCLOSED ) );
	REQUIRES( !checkOverflowSub( sessionInfoPtr->sendBufPos, 
								 SSH2_HEADER_SIZE + \
										SSH2_PAYLOAD_HEADER_SIZE ) );
	ENSURES( isBufsizeRangeNZ( dataLength ) && \
			 dataLength < sessionInfoPtr->sendBufPos );

	/* Wrap up the payload ready for sending:

		byte		SSH_MSG_CHANNEL_DATA
		uint32		channel_no
		string		data

	   Since this is wrapping in-place data, we first open a write stream to
	   add the header, then open a read stream covering the full buffer in
	   preparation for wrapping the packet */
	status = openPacketStreamSSHEx( &stream, sessionInfoPtr, 
									SSH2_PAYLOAD_HEADER_SIZE,
									SSH_MSG_CHANNEL_DATA );
	if( cryptStatusError( status ) )
		return( status );
	writeUint32( &stream, getCurrentChannelNo( sessionInfoPtr, \
											   CHANNEL_WRITE ) );
	INJECT_FAULT( SESSION_SSH_CORRUPT_CHANNEL_DATA, 
				  SESSION_SSH_CORRUPT_CHANNEL_DATA_1 );
	status = writeUint32( &stream, dataLength );
	sMemDisconnect( &stream );
	ENSURES( cryptStatusOK( status ) );
	sMemConnect( &stream, sessionInfoPtr->sendBuffer,
				 sessionInfoPtr->sendBufSize );
	REQUIRES( !checkOverflowAdd( SSH2_HEADER_SIZE + SSH2_PAYLOAD_HEADER_SIZE, 
								 dataLength ) );
	status = sSkip( &stream, SSH2_HEADER_SIZE + SSH2_PAYLOAD_HEADER_SIZE + \
							 dataLength, SSKIP_MAX );
	if( cryptStatusOK( status ) )
		status = wrapPacketSSH2( sessionInfoPtr, &stream, 0, FALSE );
	if( cryptStatusOK( status ) )
		status = length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isBufsizeRangeNZ( length ) );
	INJECT_FAULT( SESSION_CORRUPT_DATA, SESSION_CORRUPT_DATA_SSH_1 );

	/* If there's control data enqueued to be written, try and append it to
	   the existing data to be sent.  This may or may not append it 
	   (depending on whether there's room in the send buffer) so we may end
	   up here more than once */
	if( sshInfo->response.type > 0 )
		{
		int length2;

		status = length2 = appendChannelData( sessionInfoPtr, length );
		if( !cryptStatusError( status  ) )
			{
			REQUIRES( !checkOverflowAdd( length, length2 ) );
			length += length2;
			}
		}

	return( length );
	}

/* Close a previously-opened SSH session */

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	BOOLEAN isFatalError;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES_V( sanityCheckSessionSSH( sessionInfoPtr ) );

	/* If the error condition on the stream is fatal, don't try and perform
	   any shutdown actions */
	status = sioctlGet( &sessionInfoPtr->stream, STREAM_IOCTL_ISFATALERROR, 
						&isFatalError, sizeof( BOOLEAN ) );
	if( cryptStatusError( status ) || isFatalError )
		return;

	/* If we haven't entered the secure state yet (i.e. we're still in the
	   middle of the handshake) then this is an abnormal termination, send 
	   a disconnect indication:

		byte		SSH_MSG_DISCONNECT
		uint32		reason_code = SSH_DISCONNECT_PROTOCOL_ERROR
		string		description = "Handshake failed"
		string		language_tag = "" */
	if( !TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_WRITE ) )
		{
		STREAM stream;

		status = openPacketStreamSSH( &stream, sessionInfoPtr, 
									  SSH_MSG_DISCONNECT );
		if( cryptStatusError( status ) )
			{
			sNetDisconnect( &sessionInfoPtr->stream );
			return;
			}
		writeUint32( &stream, SSH_DISCONNECT_PROTOCOL_ERROR );
		writeString32( &stream, "Handshake failed", 16 );
		status = writeUint32( &stream, 0 );		/* No language tag */
		if( cryptStatusOK( status ) )
			status = wrapPlaintextPacketSSH2( sessionInfoPtr, &stream, 0 );
		if( cryptStatusOK( status ) )
			{
			const int length = stell( &stream );
			void *dataPtr;

			REQUIRES_V( isBufsizeRangeNZ( length ) );

			/* Since there's nothing much that we can do at this point in 
			   response to an error except continue and close the network
			   session, we don't check for errors */
			status = sMemGetDataBlockAbs( &stream, 0, &dataPtr, length );
			if( cryptStatusOK( status ) )
				{
				( void ) sendCloseNotification( sessionInfoPtr, dataPtr, 
												length );
				}
			}
		sMemDisconnect( &stream );
		return;
		}

	/* Close all remaining channels.  Since this is just a cleanup of a 
	   network session that's about to be closed anyway we ignore any errors 
	   that we encounter at this point (a typical error would be the link 
	   going down, in which case the only useful response is to take down 
	   the network session anyway) */
	( void ) closeChannel( sessionInfoPtr, TRUE );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

/* Set up access to the SSH session processing */

STDC_NONNULL_ARG( ( 1 ) ) \
void initSSH2processing( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Set the access method pointers */
	FNPTR_SET( sessionInfoPtr->readHeaderFunction, readHeaderFunction );
	FNPTR_SET( sessionInfoPtr->processBodyFunction, processBodyFunction );
	FNPTR_SET( sessionInfoPtr->preparePacketFunction, preparePacketFunction );
	FNPTR_SET( sessionInfoPtr->shutdownFunction, shutdownFunction );
	}
#endif /* USE_SSH */
