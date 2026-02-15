/****************************************************************************
*																			*
*						cryptlib TLS Session Read Routines					*
*						Copyright Peter Gutmann 1998-2025					*
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

#ifdef USE_ERRMSGS

/* Get a string description of overall and handshake packet types, used for 
   diagnostic error messages */

CHECK_RETVAL_PTR_NONNULL \
const char *getTLSPacketName( IN_BYTE const int packetType )
	{
	static const OBJECT_NAME_INFO packetNameInfo[] = {
		{ TLS_MSG_CHANGE_CIPHER_SPEC, "change_cipher_spec" },
		{ TLS_MSG_ALERT, "alert" },
		{ TLS_MSG_HANDSHAKE, "handshake (encrypted)" },
			/* We denote this one as an encrypted handshake packet rather 
			   than a straight handshake packet because handshake messages 
			   are identified via getTLSHSPacketName(), it's only when we're 
			   encrypting the handshake messages that we can no longer dump 
			   the inner contents, so if we ever get a handshake packet 
			   dumped using getTLSPacketName() then it has to be encrypted */
		{ TLS_MSG_APPLICATION_DATA, "application_data" },
		{ TLS_MSG_NONE, "<Unknown type>" },
			{ TLS_MSG_NONE, "<Unknown type>" }
		};

	REQUIRES_EXT( ( packetType >= 0 && packetType <= 0xFF ),
				  "<Internal error>" );

	return( getObjectName( packetNameInfo,
						   FAILSAFE_ARRAYSIZE( packetNameInfo, \
											   OBJECT_NAME_INFO ),
						   packetType ) );
	}

CHECK_RETVAL_PTR_NONNULL \
const char *getTLSHSPacketName( IN_BYTE const int packetType )
	{
	static const OBJECT_NAME_INFO packetNameInfo[] = {
		{ TLS_HAND_CLIENT_HELLO, "client_hello" },
		{ TLS_HAND_SERVER_HELLO, "server_hello" },
		{ TLS_HAND_NEW_SESSION_TICKET, "new_session_ticket" },
		{ TLS_HAND_END_OF_EARLY_DATA, "end_of_early_data" },
		{ TLS_HAND_ENCRYPTED_EXTENSIONS, "encrypted_extensions" },
		{ TLS_HAND_CERTIFICATE, "certificate" },
		{ TLS_HAND_SERVER_KEYEXCHANGE, "server_key_exchange" },
		{ TLS_HAND_SERVER_CERTREQUEST, "certificate_request" },
		{ TLS_HAND_SERVER_HELLODONE, "server_hello_done" },
		{ TLS_HAND_CERTVERIFY, "certificate_verify" },
		{ TLS_HAND_CLIENT_KEYEXCHANGE, "client_key_exchange" },
		{ TLS_HAND_FINISHED, "finished" },
		{ TLS_HAND_SUPPLEMENTAL_DATA, "supplemental_data" },
		{ TLS_HAND_KEY_UPDATE, "key_updated" },
		{ TLS_HAND_NONE, "<Unknown type>" },
			{ TLS_HAND_NONE, "<Unknown type>" }
		};

	REQUIRES_EXT( ( packetType >= 0 && packetType <= 0xFF ),
				  "<Internal error>" );

	return( getObjectName( packetNameInfo,
						   FAILSAFE_ARRAYSIZE( packetNameInfo, \
											   OBJECT_NAME_INFO ),
						   packetType ) );
	}
#endif /* USE_ERRMSGS */

/* Process version information.  This is always called with sufficient data 
   in the input stream so we don't have to worry about special-casing error
   reporting for stream read errors.
   
   Handling of version numbering in the TLS protocol is complex and messy 
   (or at least the way that some implementations do it is complex and 
   messy), the client and server hellos have two version numbers, one in the 
   overall TLS message wrapper and a second one in the client/server hello 
   itself.  Many browsers send a meaningless version number in the overall 
   wrapper that bears no relation to the version in the hello message 
   contents, so for the initial message we skip the outer version (or at 
   least just check that it's approximately valid) and use the inner version 
   number given in the hello message itself.  For subsequent messages, where 
   the wrapper version number seems to make sense, we ensure that the 
   version number matches.
   
   In addition to this TLS 1.3 always pretends to be TLS 1.2 and then sends
   the real version in the TLS_EXT_SUPPORTED_VERSIONS extension, so although
   the code below is written to process TLS versions 1.3 and above it should
   never actually get invoked for this */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processVersionInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						INOUT_PTR STREAM *stream, 
						OUT_OPT int *clientVersion,
						IN_BOOL const BOOLEAN generalCheckOnly )
	{
	int version, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( clientVersion == NULL || \
			isWritePtr( clientVersion, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( generalCheckOnly ) );

	/* Clear return value */
	if( clientVersion != NULL )
		*clientVersion = CRYPT_ERROR;

	/* Check the major version number */
	status = version = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( version != TLS_MAJOR_VERSION )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid major version number %d, should be 3", 
				  version ) );
		}

	/* Check the minor version number.  If we've already got the version
	   established, make sure that it matches the existing one, otherwise
	   determine which version we'll be using */
	status = version = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( clientVersion == NULL )
		{
		/* If it's the first message in the exchange then the outer version
		   number is meaningless and often doesn't correspond to the inner 
		   version number in the client/server hello, so all we do is check 
		   that it's generally within range */
		if( generalCheckOnly )
			{
			if( version < TLS_MINOR_VERSION_SSL || \
				version > TLS_MINOR_VERSION_TLS12 + 2 )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid version number 3.%d, should be "
						  "3.0...3.%d", version, 
						  TLS_MINOR_VERSION_TLS12 + 2 ) );
				}
			return( CRYPT_OK );
			}

		/* It's a subsequent message in the exchange then the version number 
		   has to match what we're expecting unless we're using TLS 1.3 
		   special-snowflake processing where the version is given as TLS 
		   1.2 */
#ifdef USE_TLS13
		if( version != sessionInfoPtr->version && \
			!( version == TLS_MINOR_VERSION_TLS12 && \
			   sessionInfoPtr->version == TLS_MINOR_VERSION_TLS13 ) )
#else
		if( version != sessionInfoPtr->version ) 
#endif /* USE_TLS13 */
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid version number 3.%d, should be 3.%d", 
					  version, sessionInfoPtr->version ) );
			}
		return( CRYPT_OK );
		}
	DEBUG_PRINT(( "%s offered protocol version 3.%d (TLS 1.%d).\n", 
				  isServer( sessionInfoPtr ) ? "Client" : "Server", 
				  version, version - 1 ));
	switch( version )
		{
		case TLS_MINOR_VERSION_SSL:
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
					  "%s requested use of obsolete SSL version 3, we can "
					  "only do TLS", 
					  isServer( sessionInfoPtr ) ? "Client" : "Server" ) );

		case TLS_MINOR_VERSION_TLS:
			/* If the other side can't do TLS 1.1, fall back to TLS 1.0 */
			if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS11 )
				sessionInfoPtr->version = TLS_MINOR_VERSION_TLS;
			break;

		case TLS_MINOR_VERSION_TLS11:
			/* If the other side can't do TLS 1.2, fall back to TLS 1.1 */
			if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
				sessionInfoPtr->version = TLS_MINOR_VERSION_TLS11;
			break;

		case TLS_MINOR_VERSION_TLS12:
			/* If the other side can't do TLS 1.3, fall back to TLS 1.2.  
			   Since TLS 1.3 pretends to be TLS 1.2 (see the comment at the
			   start) this means that at this point we always appear to fall
			   back to TLS 1.2 */
			if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
				sessionInfoPtr->version = TLS_MINOR_VERSION_TLS12;
			break;

#ifdef USE_TLS13	/* See comment at the start for why this shouldn't occur */
		case TLS_MINOR_VERSION_TLS13:
			/* If the other side can't do post-TLS 1.3, fall back to 
			   TLS 1.3 */
			if( sessionInfoPtr->version > TLS_MINOR_VERSION_TLS13 )
				sessionInfoPtr->version = TLS_MINOR_VERSION_TLS13;
			break;
#endif /* USE_TLS13 */

		default:
			/* This code formerly checked, if we were the server, whether 
			   the client had offered a vaguely sensible version, in
			   which case we'd fall back to the highest version that we
			   supported.  However TLS 1.3 enshrined the fact that the
			   maximum possible version was TLS 1.2 with the real version
			   in the hoosegow hidden (or at least stuffed into an 
			   extension), so we don't allow anything above TLS 1.2,
			   thus making us bug-compatible with the implementations whose 
			   bugs TLS 1.3 has written into the standard */
#if 0
			if( isServer( sessionInfoPtr ) && \
				version <= TLS_MINOR_VERSION_TLS12 + 2 )
				{
#ifdef USE_TLS13
				sessionInfoPtr->version = TLS_MINOR_VERSION_TLS13;
#else
				sessionInfoPtr->version = TLS_MINOR_VERSION_TLS12;
#endif /* USE_TLS13 */
				break;
				}
#endif /* 0 */

			/* It's nothing that we can handle */
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid protocol version 3.%d", version ) );
		}
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Accepted protocol version: 3.%d (TLS 1.%d).\n", 
				  sessionInfoPtr->version, sessionInfoPtr->version - 1 ));
#ifdef USE_TLS13
	DEBUG_PRINT_COND( sessionInfoPtr->version == TLS_MINOR_VERSION_TLS12,
					  ( "  (This may also be TLS 1.3 pretending to be "
					    "TLS 1.2)\n" ) );
#endif /* USE_TLS13 */
	DEBUG_PRINT_END();

	/* If there's a requirement for a minimum version, make sure that it's
	   been met.  See the comment at the start for the mess created by
	   TLS 1.3 pretending to be TLS 1.2, which means that if the minimum
	   version is 1.3 then we have to accept 1.2 as if it was 1.3 */
	if( sessionInfoPtr->sessionTLS->minVersion > 0 )
		{
#ifdef USE_TLS13
		if( version < sessionInfoPtr->sessionTLS->minVersion && \
			version != TLS_MINOR_VERSION_TLS12 )
#else
		if( version < sessionInfoPtr->sessionTLS->minVersion )
#endif /* USE_TLS13 */
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid version number 3.%d, should be at least "
					  "3.%d", version, 
					  sessionInfoPtr->sessionTLS->minVersion ) );
			}
		}

	*clientVersion = version;

	return( CRYPT_OK );
	}

/* Process something that isn't a TLS packet when we're expecting a 
   connection to/from a TLS server/client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processUnexpectedProtocol( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
									  IN_BUFFER( headerSize ) \
											const BYTE *headerBuffer,
									  IN_LENGTH_SHORT const int headerSize )
	{
	BYTE dataBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
#ifdef USE_ERRMSGS
	char hexTextBuffer[  CRYPT_MAX_TEXTSIZE + 8 ];
	const char *peerName = isServer( sessionInfoPtr ) ? "Server" : "Client";
#endif /* USE_ERRMSGS */
	int dataBytes = TLS_HEADER_SIZE, bytesCopied, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( headerBuffer, headerSize ) );

	REQUIRES( isShortIntegerRangeNZ( headerSize ) );

	/* First, check whether the other side is using the obsolete SSLv2 
	   protocol */
	if( headerBuffer[ 0 ] == TLS_MSG_V2HANDSHAKE )
		{
		retExt( CRYPT_ERROR_NOSECURE,
				( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
				  "%s sent handshake for the obsolete SSLv2 protocol", 
				  peerName ) );
		}

	/* It's something other than an obsolete TLS message, try and read a bit 
	   more of the message from the other side, since TLS_HEADER_SIZE only 
	   provides the initial status code for something like SMTP or FTP that's
	   typically used with TLS but none of the possible accompanying text */
	memcpy( dataBuffer, headerBuffer, TLS_HEADER_SIZE );
	sessionInfoPtr->readTimeout = 1;
	sioctlSet( &sessionInfoPtr->stream, STREAM_IOCTL_PARTIALREAD, TRUE );
	REQUIRES( boundsCheck( TLS_HEADER_SIZE, \
						   CRYPT_MAX_TEXTSIZE - TLS_HEADER_SIZE, \
						   CRYPT_MAX_TEXTSIZE ) );
	status = bytesCopied = \
		sread( &sessionInfoPtr->stream, dataBuffer + TLS_HEADER_SIZE,
			   CRYPT_MAX_TEXTSIZE - TLS_HEADER_SIZE );
	if( !cryptStatusError( status ) )
		{
		/* This can't overflow, being at most CRYPT_MAX_TEXTSIZE */
		dataBytes += bytesCopied;
		}

	/* Try and detect whether the other side is talking something that's
	   associated with TLS, typically SMTP, POP3, IMAP, or FTP.  In theory 
	   we could check for more explicit indications of one of these 
	   protocols ("220" for SMTP and FTP, "+OK" for POP3 and "OK" for IMAP) 
	   but there's a danger of mis-identifying the other protocol and 
	   returning a message that's worse than a generic bad-data, so for now 
	   we just report the text that was sent and let the user figure it 
	   out.
	   
	   We check for 8 bytes of printable data rather than 'dataBytes' bytes
	   since we don't want to turn a mostly-text string into a hex dump
	   just because of an embedded control character, and sanitiseString() 
	   will clean it up as required */
	if( strIsPrintable( dataBuffer, min( dataBytes, 8 ) ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "%s sent ASCII text string '%s...', is this the "
				  "correct address/port?", peerName,
				  sanitiseString( dataBuffer, CRYPT_MAX_TEXTSIZE, 
								  dataBytes ) ) );
		}

	/* It's something else, just provide a hex dump */
#ifdef USE_ERRMSGS
	formatHexData( hexTextBuffer, CRYPT_MAX_TEXTSIZE, dataBuffer, 
				   dataBytes );
#endif /* USE_ERRMSGS */
	retExt( CRYPT_ERROR_BADDATA,
			( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
			  "%s sent binary data '%s', is this the correct "
			  "address/port?", peerName, hexTextBuffer ) );
	}

/* TLS 1.3 changed the format of the packet contents so that it's no longer 
   just the plaintext but a mix of other stuff:

	byte[]	plaintext
	byte	contentType		-- Real record type, not outer camouflage value
  [	byte[]	padding	= 0x00	-- Remainder of packet ] 

   The padding is another TLS 1.3 clever trick, instead of using a length
   field to make the size explicit the recipient has to scan backwards from 
   the end of the packet until it hits a non-zero byte, the actual content-
   type value, and discard everything beyond that point, see RFC 8446 
   section 5.4.  So what we have to do is unpack:

	+---------------+----+--------------+
	|///////////////|type|		pad		|
	+---------------+----+--------------+

   by walking backwards from the end of the packet.
   
   I'm sure there's no oracle or other vulnerability being enabled by this
   piece of cleverness */

#ifdef USE_TLS13

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int recoverPacketDataTLS13( IN_BUFFER( dataLength ) const BYTE *data,
							IN_DATALENGTH_MIN( UINT16_SIZE + 1 ) \
								const int dataLength,
							OUT_LENGTH_BOUNDED_Z( dataLength ) \
								int *payloadLength, 
							OUT_RANGE( TLS_HAND_NONE, TLS_HAND_LAST ) \
								int *packetType )
	{
	LOOP_INDEX i;

	assert( isReadPtr( data, dataLength ) );
	assert( isWritePtr( payloadLength, sizeof( int ) ) );
	assert( isWritePtr( packetType, sizeof( int ) ) );

	REQUIRES( isIntegerRangeMin( dataLength, 1 + 1 ) );
			  /* Min. 1 byte content, 1 byte contentType */

	/* Clear return values */
	*payloadLength = CRYPT_ERROR;
	*packetType = TLS_HAND_NONE;

	/* Find the end of the zero padding.  We need at least one byte of 
	   content followed by the one-byte content-type value for a total of
	   2 bytes */
	LOOP_EXT_REV( i = dataLength - 1, i >= 2 && data[ i ] == 0, i--, 
				  MAX_PACKET_SIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_REV( i, 2, dataLength - 1 ) );
		}
	ENSURES( LOOP_BOUND_EXT_REV_OK( MAX_PACKET_SIZE + 1 ) );
	if( i < 2 )
		return( CRYPT_ERROR_BADDATA );

	/* Return the actual (not outer-packet camouflage) content-type and 
	   actual payload length */
	*packetType = data[ i ];
	*payloadLength = i;

	return( CRYPT_OK );
	}
#endif /* USE_TLS13 */

/****************************************************************************
*																			*
*								Check a Packet								*
*																			*
****************************************************************************/

/* Check that the header of a TLS packet is in order:

	byte	type
	byte[2]	vers = { 0x03, 0x0n }
	uint16	length
  [ byte[]	iv	- TLS 1.1/1.2 ]

  This is always called with sufficient data in the input stream that we 
  don't have to worry about special-casing error reporting for stream read
  errors.

  If this is the initial hello packet then we request a dummy version 
  information read since the peer's version isn't known yet this point.  The 
  actual version information is taken from the hello packet data, not from 
  the TLS wrapper */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int checkPacketHeader( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							  INOUT_PTR STREAM *stream,
							  OUT_LENGTH_BOUNDED_Z( maxLength ) \
									int *packetLength, 
							  IN_RANGE( TLS_MSG_FIRST, TLS_MSG_LAST ) \
									const int packetType, 
							  IN_DATALENGTH_Z const int minLength, 
							  IN_DATALENGTH const int maxLength,
							  const BOOLEAN isFirstMessage )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	const int ivLength = \
		( TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) && \
		  ( sessionInfoPtr->version == TLS_MINOR_VERSION_TLS11 || \
			sessionInfoPtr->version == TLS_MINOR_VERSION_TLS12 ) ) ? \
		tlsInfo->ivSize : 0;
	int value, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( packetLength, sizeof( int ) ) );

	REQUIRES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );
	REQUIRES( ( packetType == TLS_MSG_APPLICATION_DATA && \
				minLength == 0 ) || \
			  isBufsizeRangeNZ( minLength ) );
	REQUIRES( isBufsizeRangeNZ( maxLength ) && maxLength >= minLength );
	REQUIRES( isBooleanValue( isFirstMessage ) );

	/* Clear return value */
	*packetLength = 0;

	/* Check the packet type */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value != packetType )
		{
		/* There is one special case in which a mismatch is allowed and 
		   that's when we're expecting a data packet and we instead get a
		   handshake packet, which may be a rehandshake request from the 
		   server.  Unfortunately we can't tell that at this point because 
		   the packet is encrypted, so all that we can do is set a flag 
		   indicating that when we process the actual payload we need to 
		   check for a re-handshake */
		if( packetType == TLS_MSG_APPLICATION_DATA && \
			value == TLS_MSG_HANDSHAKE && !isServer( sessionInfoPtr ) )
			{
			/* Tell the body-read code to check for a rehandshake (via a
			   hello_request) in the decrypted packet payload */
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  TLS_PFLAG_CHECKREHANDSHAKE );
			}
		else
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Unexpected %s (%d) packet, expected %s (%d)", 
					  getTLSPacketName( value ), value, 
					  getTLSPacketName( packetType ), packetType ) );
			}
		}

	/* Process the version information.  Alongside not requiring a version 
	   number match on the first message exchanged we also allow this for
	   alert packets, since version-intolerant servers can send back alerts
	   with lower-then-expected version numbers */
	status = processVersionInfo( sessionInfoPtr, stream, NULL,
						( isFirstMessage || packetType == TLS_MSG_ALERT ) ? \
						  TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the packet length */
	status = length = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) )
		{
		/* This can't overflow, ivLength and authBlockSize are a few dozen 
		   bytes and minLength / MAX_PACKET_SIZE are a few kB to tens of 
		   kB */
		if( length < ivLength + minLength + \
						sessionInfoPtr->authBlocksize || \
			length > ivLength + MAX_PACKET_SIZE + \
						sessionInfoPtr->authBlocksize + 256 || \
			length > maxLength )
			status = CRYPT_ERROR_BADDATA;
		}
	else
		{
		if( length < minLength || length > MAX_PACKET_SIZE || \
			length > maxLength )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid packet length %d for %s (%d) packet", 
				  length, getTLSPacketName( packetType ), 
				  packetType ) );
		}

	/* Load the TLS 1.1/1.2 explicit IV if necessary */
	if( ivLength > 0 )
		{
		int ivSize;

		status = loadExplicitIV( sessionInfoPtr, stream, &ivSize );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Error loading TLS explicit IV" ) );
			}
		length -= ivSize;
		ENSURES( length >= minLength + sessionInfoPtr->authBlocksize && \
				 length <= maxLength );
		}
	*packetLength = length;

	return( CRYPT_OK );
	}

/* Check that the header of a TLS packet and TLS handshake packet is in 
   order.  This is always called with sufficient data in the input stream so 
   we don't have to worry about special-casing error reporting for stream 
   read errors, however for the handshake packet read we do need to check 
   the length because several of these can be encapsulated within a single 
   TLS packet so we can't check the exact space requirements in advance */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkPacketHeaderTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR STREAM *stream, 
						  OUT_DATALENGTH_Z int *packetLength )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( packetLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	return( checkPacketHeader( sessionInfoPtr, stream, packetLength,
							   TLS_MSG_APPLICATION_DATA, 0, 
							   sessionInfoPtr->receiveBufSize, FALSE ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkHSPacketHeader( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 INOUT_PTR STREAM *stream, 
						 OUT_DATALENGTH_Z int *packetLength, 
						 IN_RANGE( TLS_HAND_FIRST, \
								   TLS_HAND_LAST ) const int packetType, 
						 IN_LENGTH_SHORT_Z const int minSize )
	{
	int type, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( packetLength, sizeof( int ) ) );
	
	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( packetType >= TLS_HAND_FIRST && packetType <= TLS_HAND_LAST );
	REQUIRES( isShortIntegerRange( minSize ) );
			  /* May be zero for change cipherspec */

	/* Clear return value */
	*packetLength = 0;

	/* Make sure that there's enough data left in the stream to safely read
	   the header from it.  This will be caught anyway by the checks below, 
	   but performing the check here makes the error reporting a bit more 
	   precise */
	if( sMemDataLeft( stream ) < 1 + LENGTH_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid handshake packet header" ) );
		}

	/*	byte		ID = type
		uint24		length */
	status = type = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( type != packetType )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid handshake packet %s (%d), expected %s (%d)", 
				  getTLSHSPacketName( type ), type, 
				  getTLSHSPacketName( packetType ), packetType ) );
		}
	status = length = readUint24( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length < minSize || length > MAX_PACKET_SIZE || \
		length > sMemDataLeft( stream ) )
		{
		const int dataLeft = sMemDataLeft( stream );
		
		/* Some servers may send insanely-long certificate request packets
		   containing every known CA in existence, which end up being so big 
		   that the're fragmented across multiple TLS packets (see the 
		   comment in processCertRequest() in tls_cli.c).  If we encounter 
		   one of these then we allow up to a full extra encapsulated packet 
		   which will be handled specially by the caller */
		REQUIRES( !checkOverflowAdd( dataLeft, MAX_PACKET_SIZE - 512 ) );
		if( type == TLS_HAND_SERVER_CERTREQUEST && \
			length >= minSize && \
			length < dataLeft + ( MAX_PACKET_SIZE - 512 ) )
			{
			*packetLength = length;
			DEBUG_PRINT_BEGIN();
			DEBUG_PRINT(( "Read over-long %s (%d) handshake packet, "
						  "length %d.\n", getTLSHSPacketName( type ), type, 
						  length ));
			DEBUG_PRINT(( "  First fragment of length %d follows.\n",
						  dataLeft ));
			DEBUG_DUMP_DATA( sessionInfoPtr->receiveBuffer + stell( stream ), 
							 dataLeft );
			DEBUG_PRINT_END();

			return( CRYPT_OK );
			}

		/* The complex expression for the maximum length is because dataLeft 
		   may be zero, or at least less than minSize, which means that the 
		   error message would give a range like "128...32" */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid length %d for %s (%d) handshake packet, should "
				  "be %d...%d", length, getTLSHSPacketName( type ), 
				  type, minSize, 
				  ( dataLeft < minSize ) ? \
					MAX_PACKET_SIZE : min( MAX_PACKET_SIZE, dataLeft ) ) );
		}
	*packetLength = length;
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Read %s (%d) handshake packet, length %ld.\n", 
				  getTLSHSPacketName( type ), type, length ));
	DEBUG_DUMP_DATA( sessionInfoPtr->receiveBuffer + stell( stream ), 
					 length );
	DEBUG_PRINT_END();

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read/Unwrap a Packet						*
*																			*
****************************************************************************/

/* Unwrap a TLS data packet.  There are three forms of this, the first for
   standard MAC-then-encrypt:

			  data
				|------------			  MAC'd
				v======================== Encrypted
	+-----+-----+-----------+-----+-----+
	| hdr |(IV)	|	data	| MAC | pad |
	+-----+-----+-----------+-----+-----+
				|<---- dataMaxLen ----->|
				|<- dLen -->|

   The second for encrypt-then-MAC and the Bernstein algorithm suite (the
   Bernstein suite uses an implicit rather than explicit IV so the IV field
   is only present for EtM):

			  data
				|==================		  Encrypted
	------------v------------------		  MAC'd
	+-----+-----+-----------+-----+-----+
	| hdr |(IV)	|	data	| pad | MAC |
	+-----+-----+-----------+-----+-----+
				|<---- dataMaxLen ----->|
				|<- dLen -->|

   And the third for GCM, with the explicit IV being present for TLS 1.2 GCM
   but not TLS 1.3 GCM:

			  data
				|
	------		v================		AuthEnc'd
	+-----+-----+---------------+-----+
	| hdr |(IV)	|	data		| ICV |
	+-----+-----+---------------+-----+
				|<--- dataMaxLen ---->|
				|<--- dLen ---->|

   These are sufficiently different that we use three distinct functions to
   do the job.  These decrypt the data, remove the padding if necessary, 
   check and remove the MAC/ICV, and return the payload length.  Processing 
   of the header and IV have already been performed during the packet header 
   read.
   
   In addition to the standard TLS unwrap we also provide a special-snowflake
   one for TLS 1.3 which uses an incompatible format that's really clever */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int unwrapPacketTLSStd( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							   INOUT_BUFFER( dataMaxLength, \
											 *dataLength ) void *data, 
							   IN_DATALENGTH const int dataMaxLength, 
							   OUT_DATALENGTH_Z int *dataLength,
							   IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
									const int packetType )
	{
	BYTE dummyDataBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	BOOLEAN badDecrypt = FALSE;
	int length = dataMaxLength, payloadLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( dataMaxLength >= sessionInfoPtr->authBlocksize && \
			  dataMaxLength <= MAX_PACKET_SIZE + \
							   sessionInfoPtr->authBlocksize + 256 && \
			  dataMaxLength < MAX_BUFFER_SIZE );
	REQUIRES( ( dataMaxLength % sessionInfoPtr->cryptBlocksize ) == 0 );
	REQUIRES( packetType >= TLS_HAND_FIRST && packetType <= TLS_HAND_LAST );

	/* Clear return value */
	*dataLength = 0;

	/* Decrypt the packet in the buffer.  We allow zero-length blocks (once
	   the padding is stripped) because some versions of OpenSSL send these 
	   as a kludge to work around pre-TLS 1.1 chosen-IV attacks */
	status = decryptData( sessionInfoPtr, data, length, &length );
	if( cryptStatusError( status ) )
		{
		if( status != CRYPT_ERROR_BADDATA )
			return( status );

		/* There's been a padding error, don't exit immediately but record 
		   that there was a problem for after we've done the MAC'ing.  
		   Delaying the error reporting until then helps prevent timing 
		   attacks of the kind described by Brice Canvel, Alain Hiltgen,
		   Serge Vaudenay, and Martin Vuagnoux in "Password Interception 
		   in a SSL/TLS Channel", Crypto'03, LNCS No.2729, p.583.  These 
		   are close to impossible in most cases because we delay sending 
		   the close notify over a much longer period than the MAC vs.non-
		   MAC time difference and because it requires repeatedly connecting
		   with a fixed-format secret such as a password at the same 
		   location in the packet (which MS Outlook does however manage to 
		   do), but we take this step anyway just to be safe */
		badDecrypt = TRUE;
		length = min( dataMaxLength, 
					  MAX_PACKET_SIZE + sessionInfoPtr->authBlocksize );
		}
	payloadLength = length - sessionInfoPtr->authBlocksize;
	if( payloadLength < 0 || payloadLength > MAX_PACKET_SIZE )
		{
		/* This is a bit of an odd situation and can really only occur if 
		   we've been sent a malformed packet for which removing the padding
		   reduces the remaining data size to less than the minimum required
		   to store a MAC.  In order to avoid being used as a timing oracle
		   we create a minimum-length dummy MAC value and use that as the 
		   MAC for a zero-length packet, with the same error suppression as 
		   for a bad decrypt */
		data = dummyDataBuffer;
		length = sessionInfoPtr->authBlocksize;
		payloadLength = 0;
		REQUIRES( rangeCheck( length, 1, CRYPT_MAX_HASHSIZE ) );
		memset( data, 0, length );
		badDecrypt = TRUE;
		}

	/* MAC the decrypted data.  The badDecrypt flag suppresses the reporting
	   of a MAC error due to an earlier bad decrypt, which has already been
	   reported by decryptData() */
	status = checkMacTLS( sessionInfoPtr, data, length, payloadLength, 
						  packetType, badDecrypt );
	if( badDecrypt )
		{
		/* Report the delayed decrypt error, held to this point to make 
		   timing attacks more difficult */
		return( CRYPT_ERROR_BADDATA );
		}
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Read %s (%d) packet, length %d.\n", 
				  getTLSPacketName( packetType ), packetType, 
				  payloadLength ));
	DEBUG_DUMP_DATA( data, payloadLength );
	DEBUG_PRINT_END();

	*dataLength = payloadLength;
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int unwrapPacketTLSMAC( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							   INOUT_BUFFER( dataMaxLength, \
											 *dataLength ) void *data, 
							   IN_DATALENGTH const int dataMaxLength, 
							   OUT_DATALENGTH_Z int *dataLength,
							   IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
									const int packetType )
	{
#ifdef USE_POLY1305
	const BOOLEAN isBernsteinSuite = \
					TEST_FLAG( sessionInfoPtr->protocolFlags, \
							   TLS_PFLAG_BERNSTEIN ) ? TRUE : FALSE;
#endif /* USE_POLY1305 */
	int length = dataMaxLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( dataMaxLength >= sessionInfoPtr->authBlocksize && \
			  dataMaxLength <= MAX_PACKET_SIZE + \
							   sessionInfoPtr->authBlocksize + 256 && \
			  dataMaxLength < MAX_BUFFER_SIZE );
	REQUIRES( ( ( dataMaxLength - sessionInfoPtr->authBlocksize ) % \
				sessionInfoPtr->cryptBlocksize ) == 0 );
	REQUIRES( packetType >= TLS_HAND_FIRST && packetType <= TLS_HAND_LAST );

	/* Clear return value */
	*dataLength = 0;

#ifdef USE_POLY1305
	if( isBernsteinSuite )
		{
		/* Set up the Bernstein algorithm suite to decrypt the packet */
		status = initCryptBernstein( sessionInfoPtr, TRUE );
		if( cryptStatusError( status ) )
			return( status );

		/* MAC the encrypted data */
		status = checkMacTLSBernstein( sessionInfoPtr, data, length, 
									  length - sessionInfoPtr->authBlocksize, 
									  packetType);
		if( cryptStatusError( status ) )
			return( status );
		}
	else
#endif /* USE_POLY1305 */
		{
		/* MAC the encrypted data */
		status = checkMacTLS( sessionInfoPtr, data, length, 
							  length - sessionInfoPtr->authBlocksize, 
							  packetType, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Decrypt the packet in the buffer */
	status = decryptData( sessionInfoPtr, data, 
						  length - sessionInfoPtr->authBlocksize, &length );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Read %s (%d) packet, length %d.\n", 
				  getTLSPacketName( packetType ), packetType, length ));
	DEBUG_DUMP_DATA( data, length );
	DEBUG_PRINT_END();

	*dataLength = length;
	return( CRYPT_OK );
	}

#ifdef USE_GCM

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int unwrapPacketTLSGCM( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							   INOUT_BUFFER( dataMaxLength, \
											 *dataLength ) void *data, 
							   IN_DATALENGTH const int dataMaxLength, 
							   OUT_DATALENGTH_Z int *dataLength,
							   IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
									const int packetType )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	int length = dataMaxLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( dataMaxLength >= sessionInfoPtr->authBlocksize && \
			  dataMaxLength <= MAX_PACKET_SIZE + \
							   sessionInfoPtr->authBlocksize + 256 && \
			  dataMaxLength < MAX_BUFFER_SIZE );
	REQUIRES( packetType >= TLS_HAND_FIRST && packetType <= TLS_HAND_LAST );

	/* Clear return value */
	*dataLength = 0;

	/* Set up the TLS 1.3 GCM IV if required, this works differently to the
	   TLS classic IV */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		status = initCryptGCMTLS13( sessionInfoPtr, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_TLS13 */

	/* Shorten the packet by the size of the ICV.  The odd length check that
	   follows is because TLS 1.3 has an additional byte containing the 
	   actual packet type (see tls_rd.c:recoverPacketDataTLS13()) at the end 
	   of the data */
	length -= sessionInfoPtr->authBlocksize;	/* Checked for overflow above */
	if( length < 0 || \
		length > MAX_PACKET_SIZE + \
			( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ? 1 : 0 ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid payload length %d for %s (%d) packet", length, 
				  getTLSPacketName( packetType ), packetType ) );
		}

	/* Process the packet metadata as GCM AAD */
	status = macDataTLSGCM( sessionInfoPtr->iCryptInContext, 
							tlsInfo->readSeqNo, sessionInfoPtr->version, 
							length, packetType );
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->readSeqNo++;

	/* Decrypt the packet in the buffer */
	status = decryptData( sessionInfoPtr, data, length, &length );
	if( cryptStatusError( status ) )
		{
		/* The ICV check has been performed as part of the decryption, so 
		   we're done */
		return( status );
		}
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Read %s (%d) packet, length %d.\n", 
				  getTLSPacketName( packetType ), packetType, length ));
	DEBUG_DUMP_DATA( data, length );
	DEBUG_PRINT_END();

	/* Tell the caller what the final data size is */
	*dataLength = length;

	return( CRYPT_OK );
	}
#endif /* USE_GCM */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int unwrapPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_BUFFER( dataMaxLength, \
								   *dataLength ) void *data, 
					 IN_DATALENGTH const int dataMaxLength, 
					 OUT_DATALENGTH_Z int *dataLength,
					 IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
							const int packetType )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( dataMaxLength >= sessionInfoPtr->authBlocksize && \
			  dataMaxLength <= MAX_PACKET_SIZE + \
							   sessionInfoPtr->authBlocksize + 256 && \
			  dataMaxLength < MAX_BUFFER_SIZE );
	REQUIRES( packetType >= TLS_HAND_FIRST && packetType <= TLS_HAND_LAST );

	/* Clear return value */
	*dataLength = 0;

	/* Make sure that the length is a multiple of the block cipher size */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		const int encryptedDataSize = \
					TEST_FLAG( sessionInfoPtr->protocolFlags, 
							   TLS_PFLAG_ENCTHENMAC ) ? \
					dataMaxLength - sessionInfoPtr->authBlocksize : \
					dataMaxLength;

		if( ( encryptedDataSize % sessionInfoPtr->cryptBlocksize ) != 0 )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid encrypted packet length %d relative to cipher "
					  "block size %d for %s (%d) packet", dataMaxLength, 
					  sessionInfoPtr->cryptBlocksize, 
					  getTLSPacketName( packetType ), packetType ) );
			}
		}

	/* Unwrap the data based on the type of processing that we're using */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, \
				   TLS_PFLAG_ENCTHENMAC | TLS_PFLAG_BERNSTEIN ) )
		{
		status = unwrapPacketTLSMAC( sessionInfoPtr, data, dataMaxLength, 
									 dataLength, packetType );
		}
	else
		{
#ifdef USE_GCM
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
			{
			status = unwrapPacketTLSGCM( sessionInfoPtr, data, dataMaxLength, 
										 dataLength, packetType );
			}
		else
#endif /* USE_GCM */
			{
			status = unwrapPacketTLSStd( sessionInfoPtr, data, dataMaxLength, 
										 dataLength, packetType );
			}
		}

	return( status );
	}

#ifdef USE_TLS13

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int unwrapPacketTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   INOUT_BUFFER( dataMaxLength, \
									 *dataLength ) void *data, 
					   IN_DATALENGTH const int dataMaxLength, 
					   OUT_DATALENGTH_Z int *dataLength,
					   OUT_RANGE( TLS_HAND_NONE, TLS_HAND_LAST ) \
							int *actualPacketType,
					   IN_RANGE( TLS_HAND_FIRST, TLS_HAND_LAST ) \
							const int packetType )
	{
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) && \
			TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( isWritePtr( actualPacketType, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( dataMaxLength >= sessionInfoPtr->authBlocksize && \
			  dataMaxLength <= MAX_PACKET_SIZE + \
							   sessionInfoPtr->authBlocksize + 256 && \
			  dataMaxLength < MAX_BUFFER_SIZE );
	REQUIRES( packetType >= TLS_HAND_FIRST && packetType <= TLS_HAND_LAST );
	REQUIRES( sessionInfoPtr->cryptBlocksize == 1 );

	/* Clear return value */
	*dataLength = 0;

	/* Unwrap the data based on the type of processing that we're using */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_BERNSTEIN ) )
		{
		status = unwrapPacketTLSMAC( sessionInfoPtr, data, dataMaxLength, 
									 &length, packetType );
		}
	else
		{
		ENSURES( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) );

		status = unwrapPacketTLSGCM( sessionInfoPtr, data, dataMaxLength, 
									 &length, packetType );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Recover the actual payload of the packet.  The packet type is always
	   TLS_MSG_HANDSHAKE during the handshake process but we check it just
	   in case */
	status = recoverPacketDataTLS13( sessionInfoPtr->receiveBuffer, length, 
									 &length, actualPacketType );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Read %s (%d) packet, length %d.\n", 
				  getTLSPacketName( packetType ), packetType, length ));
	DEBUG_DUMP_DATA( data, length );
	DEBUG_PRINT_END();

	*dataLength = length;
	return( CRYPT_OK );
	}
#endif /* USE_TLS13 */

/* Read a TLS handshake packet.  Since the data transfer phase has its own 
   read/write code we can perform some special-case handling based on this */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int readHSPacketPayload( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								INOUT_PTR_OPT TLS_HANDSHAKE_INFO *handshakeInfo, 
								IN_DATALENGTH const int payloadLength,
								IN_RANGE( TLS_MSG_FIRST, TLS_MSG_LAST ) \
									const int packetType )
	{
	STREAM stream;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( ( handshakeInfo == NULL ) || \
			isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( payloadLength > 0 && \
			  payloadLength <= MAX_PACKET_SIZE + \
							   sessionInfoPtr->authBlocksize + 256 );
	REQUIRES( packetType >= TLS_MSG_FIRST && packetType <= TLS_MSG_LAST );

	/* Read the packet payload */
	REQUIRES( rangeCheck( payloadLength, \
						  1, sessionInfoPtr->receiveBufSize ) );
	status = length = \
		sread( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
			   payloadLength );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	sessionInfoPtr->receiveBufPos = 0;
	sessionInfoPtr->receiveBufEnd = length;

	/* If we timed out during the handshake phase, treat it as a hard 
	   timeout error */
	if( length != payloadLength )
		{
		retExt( CRYPT_ERROR_TIMEOUT,
				( CRYPT_ERROR_TIMEOUT, SESSION_ERRINFO, 
				  "Timed out reading packet data for %s (%d) packet, only "
				  "got %d of %d bytes", getTLSPacketName( packetType ), 
				  packetType, length, payloadLength ) );
		}

	/* If we're not hashing the payload, we're done */
	if( handshakeInfo == NULL )
		return( CRYPT_OK );

	/* Hash the payload data that we've just read */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = hashHSPacketRead( handshakeInfo, &stream );
	sMemDisconnect( &stream );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int readHSPacketTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR_OPT TLS_HANDSHAKE_INFO *handshakeInfo, 
					 OUT_DATALENGTH_Z int *packetLength, 
					 IN_RANGE( TLS_MSG_FIRST, TLS_MSG_LAST_SPECIAL ) \
							const int packetType )
	{
	STREAM stream;
	BYTE headerBuffer[ TLS_HEADER_SIZE + CRYPT_MAX_IVSIZE + 8 ];
	int localPacketType = \
			( packetType == TLS_MSG_FIRST_HANDSHAKE || \
			  packetType == TLS_MSG_FIRST_ENCRHANDSHAKE || \
			  packetType == TLS_MSG_TLS13_HELLORETRY ) ? \
			  TLS_MSG_HANDSHAKE : \
			( packetType == TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE ) ? \
			  TLS_MSG_APPLICATION_DATA : packetType;
	int firstByte, bytesToRead, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( ( handshakeInfo == NULL ) || \
			isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( packetLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( handshakeInfo == NULL || \
			  sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( ( packetType >= TLS_MSG_FIRST && \
				packetType <= TLS_MSG_LAST ) || \
			  ( packetType == TLS_MSG_FIRST_HANDSHAKE || \
				packetType == TLS_MSG_FIRST_ENCRHANDSHAKE || \
				packetType == TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE || \
				packetType == TLS_MSG_TLS13_HELLORETRY ) );
	REQUIRES( sessionInfoPtr->receiveBufStartOfs >= TLS_HEADER_SIZE && \
			  sessionInfoPtr->receiveBufStartOfs < \
							TLS_HEADER_SIZE + CRYPT_MAX_IVSIZE );

	/* Clear return value */
	*packetLength = 0;

	/* Read and process the header */
	status = readFixedHeaderAtomic( sessionInfoPtr, headerBuffer,
									sessionInfoPtr->receiveBufStartOfs );
	if( cryptStatusError( status ) )
		{
		/* Some implementations handle crypto failures badly, simply closing 
		   the connection rather than returning an alert message as they're 
		   supposed to.  In particular IIS, due to the separation of 
		   protocol and transport layers, has the HTTP server layer close 
		   the connection before any error-handling at the TLS protocol 
		   layer can take effect.  To deal with this problem, if this is the 
		   first packet for which encryption has been turned on then we 
		   assume that a closed connection is due to a crypto problem rather 
		   than a networking problem */
		if( status == CRYPT_ERROR_READ && \
			( packetType == TLS_MSG_FIRST_ENCRHANDSHAKE || \
			  packetType == TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE ) )
			{
			retExtErr( CRYPT_ERROR_WRONGKEY,
					   ( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						 SESSION_ERRINFO, 
						 "Other side unexpectedly closed the connection, "
						 "probably due to incorrect encryption keys being "
						 "negotiated during the handshake" ) );
			}
		return( status );
		}
	firstByte = byteToInt( headerBuffer[ 0 ] );

	/* Check for a TLS alert message */
	if( firstByte == TLS_MSG_ALERT )
		{
		return( processAlert( sessionInfoPtr, headerBuffer, 
							  sessionInfoPtr->receiveBufStartOfs, NULL ) );
		}

	/* Decode and process the TLS packet header.  If this is the first 
	   packet sent by the other side then we check for various special-case 
	   conditions and handle them specially.  Since the first byte is 
	   supposed to be a TLS_MSG_HANDSHAKE (value 22 or 0x16) which in 
	   ASCII would be a SYN we can quickly weed out use of non-encrypted
	   protocols like SMTP, POP3, IMAP, and FTP that are often used with 
	   TLS, as well as the presence of the obsolete SSLv2 protocol */
	if( ( packetType == TLS_MSG_FIRST_HANDSHAKE && \
		  firstByte != TLS_MSG_HANDSHAKE ) || \
		( packetType == TLS_MSG_TLS13_FIRST_ENCRHANDSHAKE && \
		  firstByte != TLS_MSG_APPLICATION_DATA ) )
		{
		return( processUnexpectedProtocol( sessionInfoPtr, headerBuffer, 
										   TLS_HEADER_SIZE ) );
		}
	if( packetType == TLS_MSG_TLS13_HELLORETRY && \
		firstByte == TLS_MSG_CHANGE_CIPHER_SPEC )
		{
		/* We're processing a TLS 1.3 Hello Retry for which some 
		   implementations send a bogus Change Cipherspec first, read this 
		   as a no-op */
		localPacketType = TLS_MSG_CHANGE_CIPHER_SPEC;
		}
	ENSURES( localPacketType >= TLS_MSG_FIRST && \
			 localPacketType <= TLS_MSG_LAST );
	sMemConnect( &stream, headerBuffer, sessionInfoPtr->receiveBufStartOfs );
	status = checkPacketHeader( sessionInfoPtr, &stream, &bytesToRead, 
						localPacketType, 
						( localPacketType == TLS_MSG_CHANGE_CIPHER_SPEC ) ? \
							1 : MIN_PACKET_SIZE,
						sessionInfoPtr->receiveBufSize,
						( packetType == TLS_MSG_FIRST_HANDSHAKE ) ? \
							TRUE : FALSE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the payload packet(s).  If this is a bogus Change Cipherspec 
	   then we disable hashing the packet since it's not supposed to be 
	   there */
	status = readHSPacketPayload( sessionInfoPtr, 
				( packetType == TLS_MSG_TLS13_HELLORETRY && \
				  localPacketType == TLS_MSG_CHANGE_CIPHER_SPEC ) ? \
				  NULL : handshakeInfo, 
				bytesToRead, localPacketType );
	if( cryptStatusError( status ) )
		return( status );
	*packetLength = bytesToRead;
	DEBUG_DUMP_TLS( headerBuffer, sessionInfoPtr->receiveBufStartOfs,
					sessionInfoPtr->receiveBuffer, bytesToRead );

	return( CRYPT_OK );
	}

/* Read the next handshake stream packet */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int refreshHSStream( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* If there's still data present in the stream, there's nothing left
	   to do */
	length = sMemDataLeft( stream );
	if( length > 0 )
		{
		/* We need enough data to contain at least a handshake packet header 
		   in order to continue */
		if( !isBufsizeRangeMin( length, 1 + LENGTH_SIZE ) )
			{
			sMemDisconnect( stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid remaining handshake packet data length %d", 
					  length ) );
			}

		return( CRYPT_OK );
		}

	/* Refill the stream */
	sMemDisconnect( stream );
	status = readHSPacketTLS( sessionInfoPtr, handshakeInfo, &length,
							  TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );

	return( CRYPT_OK );
	}		

/****************************************************************************
*																			*
*								Process TLS Alerts							*
*																			*
****************************************************************************/

/* TLS alert information, from 
   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6 */

typedef struct {
	const int type;				/* TLS alert type */
#ifdef USE_ERRMSGS
	const char *message;		/* Description string */
	const int messageLength;
#endif /* USE_ERRMSGS */
	const int cryptlibError;	/* Equivalent cryptlib error status */
	} ALERT_INFO;

#ifdef USE_ERRMSGS
  #define ALERT_TEXT( text, textLen )	text, textLen,
#else
  #define ALERT_TEXT( text, textLen )
#endif /* NDEBUG */

static const ALERT_INFO alertInfo[] = {
	{ TLS_ALERT_CLOSE_NOTIFY, 
	  ALERT_TEXT( "Close notify", 12 ) CRYPT_ERROR_COMPLETE },
	{ TLS_ALERT_UNEXPECTED_MESSAGE, 
	  ALERT_TEXT( "Unexpected message", 18 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_BAD_RECORD_MAC, 
	  ALERT_TEXT( "Bad record MAC", 14 ) CRYPT_ERROR_SIGNATURE },
	{ TLS_ALERT_DECRYPTION_FAILED, 
	  ALERT_TEXT( "Decryption failed", 17 ) CRYPT_ERROR_WRONGKEY },
	{ TLS_ALERT_RECORD_OVERFLOW, 
	  ALERT_TEXT( "Record overflow", 15 ) CRYPT_ERROR_OVERFLOW },
	{ TLS_ALERT_DECOMPRESSION_FAILURE, 
	  ALERT_TEXT( "Decompression failure", 21 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_HANDSHAKE_FAILURE, 
	  ALERT_TEXT( "Handshake failure", 17 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_NO_CERTIFICATE, 
	  ALERT_TEXT( "No certificate", 14 ) CRYPT_ERROR_PERMISSION },
	{ TLS_ALERT_BAD_CERTIFICATE, 
	  ALERT_TEXT( "Bad certificate", 15 ) CRYPT_ERROR_INVALID },
	{ TLS_ALERT_UNSUPPORTED_CERTIFICATE, 
	  ALERT_TEXT( "Unsupported certificate", 23 ) CRYPT_ERROR_INVALID },
	{ TLS_ALERT_CERTIFICATE_REVOKED, 
	  ALERT_TEXT( "Certificate revoked", 19 ) CRYPT_ERROR_INVALID },
	{ TLS_ALERT_CERTIFICATE_EXPIRED, 
	  ALERT_TEXT( "Certificate expired", 19 ) CRYPT_ERROR_INVALID },
	{ TLS_ALERT_CERTIFICATE_UNKNOWN, 
	  ALERT_TEXT( "Certificate unknown", 19 ) CRYPT_ERROR_INVALID },
	{ TLS_ALERT_ILLEGAL_PARAMETER, 
	  ALERT_TEXT( "Illegal parameter", 17 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_UNKNOWN_CA, 
	  ALERT_TEXT( "Unknown CA", 10 ) CRYPT_ERROR_INVALID },
	{ TLS_ALERT_ACCESS_DENIED, 
	  ALERT_TEXT( "Access denied", 13 ) CRYPT_ERROR_PERMISSION },
	{ TLS_ALERT_DECODE_ERROR, 
	  ALERT_TEXT( "Decode error", 12 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_DECRYPT_ERROR, 
	  ALERT_TEXT( "Decrypt error", 13 ) CRYPT_ERROR_WRONGKEY },
	{ TLS_ALERT_EXPORT_RESTRICTION, 
	  ALERT_TEXT( "Export restriction", 18 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_PROTOCOL_VERSION, 
	  ALERT_TEXT( "Protocol version", 16 ) CRYPT_ERROR_NOTAVAIL },
	{ TLS_ALERT_INSUFFICIENT_SECURITY, 
	  ALERT_TEXT( "Insufficient security", 21 ) CRYPT_ERROR_NOSECURE },
	{ TLS_ALERT_INTERNAL_ERROR, 
	  ALERT_TEXT( "Internal error", 14 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_INAPPROPRIATE_FALLBACK, 
	  ALERT_TEXT( "Inappropriate fallback", 22 ) CRYPT_ERROR_NOSECURE },
	{ TLS_ALERT_USER_CANCELLED, 
	  ALERT_TEXT( "User cancelled", 14 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_NO_RENEGOTIATION, 
	  ALERT_TEXT( "No renegotiation", 16 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_MISSING_EXTENSION, 
	  ALERT_TEXT( "Missing extension", 17 ) CRYPT_ERROR_NOTFOUND },
	{ TLS_ALERT_UNSUPPORTED_EXTENSION, 
	  ALERT_TEXT( "Unsupported extension", 21 ) CRYPT_ERROR_NOTAVAIL },
	{ TLS_ALERT_CERTIFICATE_UNOBTAINABLE, 
	  ALERT_TEXT( "Certificate unobtainable", 24 ) CRYPT_ERROR_NOTFOUND },
	{ TLS_ALERT_UNRECOGNIZED_NAME, 
	  ALERT_TEXT( "Unrecognized name", 17 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE, 
	  ALERT_TEXT( "Bad certificate status response", 31 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE, 
	  ALERT_TEXT( "Bad certificate hash value", 26 ) CRYPT_ERROR_FAILED },
	{ TLS_ALERT_UNKNOWN_PSK_IDENTITY, 
	  ALERT_TEXT( "Unknown PSK identity", 20 ) CRYPT_ERROR_NOTFOUND },
	{ TLS_ALERT_CERTIFICATE_REQUIRED, 
	  ALERT_TEXT( "Certificate required", 20 ) CRYPT_ERROR_PERMISSION },
	{ TLS_ALERT_NO_APPLICATION_PROTOCOL, 
	  ALERT_TEXT( "No application protocol", 23 ) CRYPT_ERROR_PERMISSION },
	{ CRYPT_ERROR, ALERT_TEXT( NULL, 0 ) CRYPT_ERROR }, 
		{ CRYPT_ERROR, ALERT_TEXT( NULL, 0 ) CRYPT_ERROR }
	};

/* Process an alert packet.  IIS often just drops the connection rather than 
   sending an alert when it encounters a problem.  In addition when 
   communicating with IIS the only error indication that we sometimes get 
   will be a "Connection closed by remote host" rather than a TLS-level 
   error message, see the comment in readHSPacketTLS() for the reason for 
   this.  Also, when it encounters an unknown certificate MSIE will complete 
   the handshake and then close the connection (via a proper close alert in 
   this case rather than just closing the connection), wait while the user 
   clicks OK several times, and then restart the connection via a TLS 
   resume.  Netscape-derived browsers in contrast just hope that the session 
   won't time out while waiting for the user to click OK.  As a result 
   cryptlib sees a closed connection and aborts the session setup process 
   when talking to MSIE, requiring a second call to the session setup to 
   continue with the resumed session */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processAlertData( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							 IN_BUFFER( dataLength ) const BYTE *data, 
							 IN_DATALENGTH const int dataLength,
							 OUT_ENUM_OPT( READINFO ) \
								READSTATE_INFO *readInfo )
	{
	int type;
	LOOP_INDEX i;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );
	assert( readInfo == NULL || \
			isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( dataLength == ALERTINFO_SIZE );

	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Read alert (%d) handshake packet, length %d.\n", 
				  TLS_MSG_ALERT, dataLength ));
	DEBUG_DUMP_DATA( data, dataLength );
	DEBUG_PRINT_END();

	/* Make sure that we've got a valid alert message */
	if( data[ 0 ] != TLS_ALERTLEVEL_WARNING && \
		data[ 0 ] != TLS_ALERTLEVEL_FATAL )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid alert message level %d, expected %d or %d", 
				  data[ 0 ], TLS_ALERTLEVEL_WARNING, 
				  TLS_ALERTLEVEL_FATAL ) );
		}

	/* Everything seems OK so far, we're back to standard fatal errors 
	   again */
	if( readInfo != NULL )
		*readInfo = READINFO_FATAL;

	/* Tell the other side that we're going away */
	sendCloseAlert( sessionInfoPtr, TRUE );
	SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_SENDCLOSED );

	/* Process the alert information.  In theory we should also make the 
	   session non-resumable if the other side goes away without sending a 
	   close alert, but this leads to too many problems with non-resumable 
	   sessions if we do so.  For example many protocols do their own 
	   end-of-data indication (e.g. "Connection: close" in HTTP and BYE in 
	   SMTP) and so don't bother with a close alert.  In other cases 
	   implementations just drop the connection without sending a close 
	   alert, carried over from many early Unix protocols that used a 
	   connection close to signify end-of-data, which has caused problems 
	   ever since for newer protocols that want to keep the connection open.  
	   This behaviour is nearly universal for some protocols tunneled over 
	   TLS, for example vsftpd by default disables close-alert handling
	   because the author was unable to find an FTP client anywhere that 
	   uses it (see the manpage entry for "strict_ssl_write_shutdown").  
	   Other implementations still send their alert but then immediately 
	   close the connection.  Because of this haphazard approach to closing 
	   connections many implementations allow a session to be resumed even 
	   if no close alert is sent.  In order to be compatible with this 
	   behaviour, we do the same (thus perpetuating the problem).
	   
	   If required this can be fixed by calling deleteSessionCacheEntry() 
	   if the connection is closed without a close alert having been sent */
	type = data[ 1 ];
	LOOP_MED( i = 0,
			  i < FAILSAFE_ARRAYSIZE( alertInfo, ALERT_INFO ) && \
					alertInfo[ i ].type != CRYPT_ERROR && \
					alertInfo[ i ].type != type,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0,
									 FAILSAFE_ARRAYSIZE( alertInfo, \
														 ALERT_INFO ) - 1 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( alertInfo, ALERT_INFO ) );
	if( alertInfo[ i ].type == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Unknown alert message type %d at alert level %d", 
				  type, data[ 0 ] ) );
		}
	retExt( alertInfo[ i ].cryptlibError,
			( alertInfo[ i ].cryptlibError, SESSION_ERRINFO, 
			  ( sessionInfoPtr->version == TLS_MINOR_VERSION_SSL ) ? \
				"Received SSL alert message: %s" : \
				"Received TLS alert message: %s", 
				alertInfo[ i ].message ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processAlert( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				  IN_BUFFER( headerLength ) const void *header, 
				  IN_DATALENGTH const int headerLength,
				  OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo )
	{
	STREAM stream;
	BYTE buffer[ 256 + 8 ];
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( header, headerLength ) );
	assert( readInfo == NULL || \
			isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( headerLength ) );

	/* Alerts are fatal errors */
	if( readInfo != NULL )
		*readInfo = READINFO_FATAL;

	/* Process the alert packet header */
	sMemConnect( &stream, header, headerLength );
	status = checkPacketHeader( sessionInfoPtr, &stream, &length, 
								TLS_MSG_ALERT, ALERTINFO_SIZE,
								sessionInfoPtr->receiveBufSize, FALSE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISSECURE_READ ) )
		{
		if( length < ALERTINFO_SIZE || length > 256 )
			status = CRYPT_ERROR_BADDATA;
		}
	else
		{
		if( length != ALERTINFO_SIZE )
			status = CRYPT_ERROR_BADDATA;
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid alert message length %d", length ) );
		}

	/* Read and process the alert packet */
	REQUIRES( rangeCheck( length, 1, 256 ) );
	status = sread( &sessionInfoPtr->stream, buffer, length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	if( status != length )
		{
		/* If we timed out before we could get all of the alert data, bail
		   out without trying to perform any further processing.  We're 
		   about to shut down the session anyway so there's no point in 
		   potentially stalling for ages trying to find a lost byte */
		sendCloseAlert( sessionInfoPtr, TRUE );
		SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_SENDCLOSED );
		retExt( CRYPT_ERROR_TIMEOUT, 
				( CRYPT_ERROR_TIMEOUT, SESSION_ERRINFO, 
				  "Timed out reading alert message, only got %d of %d "
				  "bytes", status, length ) );
		}
	if( TEST_FLAG( sessionInfoPtr->flags, 
				   SESSION_FLAG_ISSECURE_READ ) && \
		( length > ALERTINFO_SIZE || \
		  isStreamCipher( sessionInfoPtr->cryptAlgo ) || \
		  isSpecialStreamCipher( sessionInfoPtr->cryptAlgo ) ) )
		{
		/* All errors beyond this point are fatal crypto errors */
		if( readInfo != NULL )
			*readInfo = READINFO_FATAL_CRYPTO;

		/* We only try and decrypt if the alert information is big enough to 
		   be encrypted, i.e. it contains the fixed-size data + padding.  
		   This situation can occur if there's an error moving from the non-
		   secure to the secure state.  However, if it's a stream cipher the 
		   ciphertext and plaintext are the same size so we always have to 
		   try the decryption.

		   Before calling unwrapPacketTLS() we set the receive-buffer end-
		   position indicator if it hasn't already been set as part of a
		   read of other data.  This isn't otherwise explicitly used but is 
		   required for a sanity check in the unwrap code */
		if( sessionInfoPtr->receiveBufEnd <= 0 )
			sessionInfoPtr->receiveBufEnd = length;
		status = unwrapPacketTLS( sessionInfoPtr, buffer, length, &length, 
								  TLS_MSG_ALERT );
		if( cryptStatusError( status ) )
			{
			sendCloseAlert( sessionInfoPtr, TRUE );
			SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_SENDCLOSED );
			return( status );
			}

		/* Repeat the length check from earlier now that we've unwrapped the
		   encrypted data */
		if( length != ALERTINFO_SIZE )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid alert message length %d", length ) );
			}
		}

	/* We've got the alert data, process it */
	return( processAlertData( sessionInfoPtr, buffer, length, readInfo ) );
	}

#ifdef USE_TLS13

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processAlertTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   IN_BUFFER( dataLength ) const void *data, 
					   IN_DATALENGTH const int dataLength,
					   OUT_ENUM_OPT( READINFO ) READSTATE_INFO *readInfo )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );
	assert( readInfo == NULL || \
			isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	/* TLS 1.3 hides the alert packet inside an encrypted application data
	   packet (!!) so we just pass the contents on as is since it's already
	   been unwrapped */
	return( processAlertData( sessionInfoPtr, data, dataLength, readInfo ) );
	}
#endif /* USE_TLS13 */
#endif /* USE_TLS */
