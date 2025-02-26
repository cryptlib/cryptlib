/****************************************************************************
*																			*
*					  cryptlib SSHv2 Session Read Routines					*
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

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Get a string description of a packet type, used for diagnostic error
   messages */

#ifdef USE_ERRMSGS

CHECK_RETVAL_PTR_NONNULL \
const char *getSSHPacketName( IN_RANGE( 0, SSH_MSG_SPECIAL_LAST ) \
									const int packetType )
	{
	static const OBJECT_NAME_INFO packetNameInfo[] = {
		{ SSH_MSG_DISCONNECT, "SSH_MSG_DISCONNECT" },
		{ SSH_MSG_IGNORE, "SSH_MSG_IGNORE" },
		{ SSH_MSG_UNIMPLEMENTED, "SSH_MSG_UNIMPLEMENTED" },
		{ SSH_MSG_DEBUG, "SSH_MSG_DEBUG" },
		{ SSH_MSG_SERVICE_REQUEST, "SSH_MSG_SERVICE_REQUEST" },
		{ SSH_MSG_SERVICE_ACCEPT, "SSH_MSG_SERVICE_ACCEPT" },
		{ SSH_MSG_EXT_INFO, "SSH_MSG_EXT_INFO" },
		{ SSH_MSG_KEXINIT, "SSH_MSG_KEXINIT" },
		{ SSH_MSG_NEWKEYS, "SSH_MSG_NEWKEYS" },
		{ SSH_MSG_KEXDH_INIT, 
		  "SSH_MSG_KEXDH_INIT/SSH_MSG_KEX_DH_GEX_REQUEST_OLD/SSH_MSG_KEX_ECDH_INIT" },
		{ SSH_MSG_KEXDH_REPLY, 
		  "SSH_MSG_KEXDH_REPLY/SSH_MSG_KEX_DH_GEX_GROUP/SSH_MSG_KEX_ECDH_REPLY" },
		{ SSH_MSG_KEX_DH_GEX_INIT, "SSH_MSG_KEX_DH_GEX_INIT" },
		{ SSH_MSG_KEX_DH_GEX_REPLY, "SSH_MSG_KEX_DH_GEX_REPLY" },
		{ SSH_MSG_KEX_DH_GEX_REQUEST, "SSH_MSG_KEX_DH_GEX_REQUEST" },
		{ SSH_MSG_USERAUTH_REQUEST, "SSH_MSG_USERAUTH_REQUEST" },
		{ SSH_MSG_USERAUTH_FAILURE, "SSH_MSG_USERAUTH_FAILURE" },
		{ SSH_MSG_USERAUTH_SUCCESS, "SSH_MSG_USERAUTH_SUCCESS" },
		{ SSH_MSG_USERAUTH_BANNER, "SSH_MSG_USERAUTH_BANNER" },
		{ SSH_MSG_USERAUTH_INFO_REQUEST, "SSH_MSG_USERAUTH_INFO_REQUEST" },
		{ SSH_MSG_USERAUTH_INFO_RESPONSE, "SSH_MSG_USERAUTH_INFO_RESPONSE" },
		{ SSH_MSG_GLOBAL_REQUEST, "SSH_MSG_GLOBAL_REQUEST" },
		{ SSH_MSG_GLOBAL_SUCCESS, "SSH_MSG_GLOBAL_SUCCESS" },
		{ SSH_MSG_GLOBAL_FAILURE, "SSH_MSG_GLOBAL_FAILURE" },
		{ SSH_MSG_CHANNEL_OPEN, "SSH_MSG_CHANNEL_OPEN" },
		{ SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 
		  "SSH_MSG_CHANNEL_OPEN_CONFIRMATION" },
		{ SSH_MSG_CHANNEL_OPEN_FAILURE, "SSH_MSG_CHANNEL_OPEN_FAILURE" },
		{ SSH_MSG_CHANNEL_WINDOW_ADJUST, "SSH_MSG_CHANNEL_WINDOW_ADJUST" },
		{ SSH_MSG_CHANNEL_DATA, "SSH_MSG_CHANNEL_DATA" },
		{ SSH_MSG_CHANNEL_EXTENDED_DATA, "SSH_MSG_CHANNEL_EXTENDED_DATA" },
		{ SSH_MSG_CHANNEL_EOF, "SSH_MSG_CHANNEL_EOF" },
		{ SSH_MSG_CHANNEL_CLOSE, "SSH_MSG_CHANNEL_CLOSE" },
		{ SSH_MSG_CHANNEL_REQUEST, "SSH_MSG_CHANNEL_REQUEST" },
		{ SSH_MSG_CHANNEL_SUCCESS, "SSH_MSG_CHANNEL_SUCCESS" },
		{ SSH_MSG_CHANNEL_FAILURE, "SSH_MSG_CHANNEL_FAILURE" },

		/* Special-case packet types that aren't read from the wire but that
		   we can get passed as pseudo-expected packet types to denote that 
		   one of a range of types is expected/permitted */
		{ SSH_MSG_SPECIAL_USERAUTH, 
		  "SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE or "
		  "SSH_MSG_EXT_INFO" },
		{ SSH_MSG_SPECIAL_USERAUTH_PAM, 
		  "SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, "
		  "SSH_MSG_USERAUTH_INFO_REQUEST, or SSH_MSG_EXT_INFO" },
		{ SSH_MSG_SPECIAL_CHANNEL, 
		  "SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE "
		  "or SSH_MSG_GLOBAL_REQUEST" },
		{ SSH_MSG_SPECIAL_REQUEST, 
		  "SSH_MSG_GLOBAL_REQUEST or SSH_MSG_CHANNEL_REQUEST" },
		{ SSH_MSG_SPECIAL_SERVICEACCEPT,
		  "SSH_MSG_SERVICE_ACCEPT or SSH_MSG_EXT_INFO" }, 

		{ SSH_MSG_NONE, "<Unknown type>" },
			{ SSH_MSG_NONE, "<Unknown type>" }
		};

	REQUIRES_EXT( ( packetType >= 0 && packetType <= SSH_MSG_SPECIAL_LAST ),
				  "Internal error" );

	return( getObjectName( packetNameInfo,
						   FAILSAFE_ARRAYSIZE( packetNameInfo, \
											   OBJECT_NAME_INFO ),
						   packetType ) );
	}
#endif /* USE_ERRMSGS */

/****************************************************************************
*																			*
*								Check a Packet								*
*																			*
****************************************************************************/

/* Processing handshake data can run into a number of special-case 
   conditions due to buggy SSH implementations, we handle these in a special
   function to avoid cluttering up the main packet-read code */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int checkHandshakePacketStatus( INOUT_PTR SESSION_INFO *sessionInfoPtr,
									   IN_RANGE( MAX_ERROR, CRYPT_OK ) \
											const int headerStatus,
									   IN_BUFFER( headerLength ) const BYTE *header, 
									   IN_LENGTH_SHORT_MIN( MIN_PACKET_SIZE ) \
											const int headerLength,
									   IN_RANGE( SSH_MSG_DISCONNECT, 
												 SSH_MSG_SPECIAL_REQUEST ) \
											const int expectedType )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( header, headerLength ) );
	
	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( headerStatus == CRYPT_ERROR_READ || \
			  cryptStatusOK( headerStatus ) );
	REQUIRES( isShortIntegerRangeMin( headerLength, MIN_PACKET_SIZE ) );
	REQUIRES( expectedType >= SSH_MSG_DISCONNECT && \
			  expectedType < SSH_MSG_SPECIAL_LAST );

	/* If the other side has simply dropped the connection, see if we can 
	   get further details on what went wrong */
	if( headerStatus == CRYPT_ERROR_READ )
		{
		/* Some servers just close the connection in response to a bad 
		   password rather than returning an error, if it looks like this 
		   has occurred then we return a more informative error than the 
		   low-level networking one */
		if( !isServer( sessionInfoPtr ) && \
			( expectedType == SSH_MSG_SPECIAL_USERAUTH || \
			  expectedType == SSH_MSG_SPECIAL_USERAUTH_PAM ) )
			{
			retExt( headerStatus,
					( headerStatus, SESSION_ERRINFO, 
					  "Remote server has closed the connection, possibly "
					  "in response to an incorrect password or other "
					  "authentication value" ) );
			}

		/* Some versions of CuteFTP simply drop the connection with no
		   diagnostics or error information when they get the phase 2 keyex
		   packet, the best that we can do is tell the user to hassle the
		   CuteFTP vendor about this */
		if( isServer( sessionInfoPtr ) && \
			TEST_FLAG( sessionInfoPtr->protocolFlags, 
					   SSH_PFLAG_CUTEFTP ) && \
			expectedType == SSH_MSG_NEWKEYS )
			{
			retExt( headerStatus,
					( headerStatus, SESSION_ERRINFO, 
					  "CuteFTP client has aborted the handshake due to a "
					  "CuteFTP bug, please contact the CuteFTP vendor" ) );
			}

		return( CRYPT_OK );
		}
	ENSURES( cryptStatusOK( headerStatus ) );

	/* Versions of SSH derived from the original SSH code base can sometimes
	   dump raw text strings (that is, strings not encapsulated in SSH
	   packets such as error packets) onto the connection if something
	   unexpected occurs.  Normally this would result in a bad data or MAC
	   error since they decrypt to garbage so we try and catch them here */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, 
					SSH_PFLAG_TEXTDIAGS ) && \
		header[ 0 ] == 'F' && \
		( !memcmp( header, "FATAL: ", 7 ) || \
		  !memcmp( header, "FATAL ERROR:", 12 ) ) )
		{
		BOOLEAN isTextDataError;
		int length, status;

		/* Copy across what we've got so far.  Since this is a fatal error,
		   we use the receive buffer to contain the data since we don't need
		   it for any further processing */
		memcpy( sessionInfoPtr->receiveBuffer, header, 
				MIN_PACKET_SIZE );

		/* Read the rest of the error message */
		status = readTextLine( &sessionInfoPtr->stream, 
							   sessionInfoPtr->receiveBuffer + MIN_PACKET_SIZE, 
							   min( MAX_ERRMSG_SIZE - 128, \
									sessionInfoPtr->receiveBufSize - 128 ), 
							   &length, &isTextDataError, NULL, 
							   READTEXT_NONE );
		if( cryptStatusError( status ) )
			{
			/* If we encounter an error reading the rest of the data we just 
			   go with what we've already got */
			length = 0;
			}
		sessionInfoPtr->receiveBuffer[ MIN_PACKET_SIZE + length ] = '\0';

		/* Report the error as a problem with the remote software.  Since
		   the other side has bailed out, we mark the channel as closed to
		   prevent any attempt to try and perform a standard shutdown.
		   "The great thing about a conversation like this, you only have
		   to have it once" - Gabriel, "The Prophecy" */
		SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_SENDCLOSED );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Remote SSH software has crashed, diagnostic was: '%s'",
				  sanitiseString( sessionInfoPtr->receiveBuffer, 
								  MAX_ERRMSG_SIZE - 64, 
								  MIN_PACKET_SIZE + length ) ) );
		}

	/* No (obviously) buggy behaviour detected */
	return( CRYPT_OK );
	}

/* Perform a preliminary check whether a packet is valid for a particular
   situation */

CHECK_RETVAL \
static int checkPacketValid( IN_BYTE const int packetType, 
							 IN_ENUM( SSH_PROTOSTATE ) \
								const SSH_PROTOSTATE_TYPE protocolState )
	{
	static const int validHSPacketTbl[] = {
		/* General messages */
		SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_DEBUG,
		/* Handshake-only messages */
		SSH_MSG_SERVICE_REQUEST, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_EXT_INFO, 
		SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS, SSH_MSG_KEXDH_INIT, 
		SSH_MSG_KEXDH_REPLY, SSH_MSG_KEX_DH_GEX_REQUEST_OLD, 
		SSH_MSG_KEX_DH_GEX_GROUP, SSH_MSG_KEX_DH_GEX_INIT, 
		SSH_MSG_KEX_DH_GEX_REPLY, SSH_MSG_KEX_DH_GEX_REQUEST, 
		/* Dual-use messages */
		SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 
		SSH_MSG_CHANNEL_OPEN_FAILURE,
		CRYPT_ERROR, CRYPT_ERROR };
	static const int validAuthPacketTbl[] = {
		/* General messages */
		SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_DEBUG,
		/* Auth-only messages */
		SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_FAILURE, 
		SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_BANNER, 
		SSH_MSG_USERAUTH_INFO_REQUEST, 
		SSH_MSG_USERAUTH_INFO_RESPONSE,
		/* Dual-use messages */
		SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 
		SSH_MSG_CHANNEL_OPEN_FAILURE,
		/* Data-only messages that can be seen during the auth phase from 
		   some servers */
		SSH_MSG_GLOBAL_REQUEST, SSH_MSG_CHANNEL_WINDOW_ADJUST,
		CRYPT_ERROR, CRYPT_ERROR };
	static const int validDataPacketTbl[] = {
		/* General messages */
		SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_DEBUG,
		/* Special-case rehandshake message */
		SSH_MSG_KEXINIT,
		/* Data-only messages */
		SSH_MSG_GLOBAL_REQUEST, SSH_MSG_GLOBAL_SUCCESS, 
		SSH_MSG_GLOBAL_FAILURE,
		/* Dual-use messages */
		SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 
		SSH_MSG_CHANNEL_OPEN_FAILURE,
		/* More data-only messages */
		SSH_MSG_CHANNEL_WINDOW_ADJUST, SSH_MSG_CHANNEL_DATA,
		SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_EOF,
		SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_REQUEST,
		SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_FAILURE,
		CRYPT_ERROR, CRYPT_ERROR };
	const int *validPacketTbl = \
			( protocolState == SSH_PROTOSTATE_HANDSHAKE ) ? validHSPacketTbl : \
			( protocolState == SSH_PROTOSTATE_AUTH ) ? validAuthPacketTbl : \
													   validDataPacketTbl;
	const int validPacketTblSize = \
			( protocolState == SSH_PROTOSTATE_HANDSHAKE ) ? \
			  FAILSAFE_ARRAYSIZE( validHSPacketTbl, int ) : \
			( protocolState == SSH_PROTOSTATE_AUTH ) ? \
			  FAILSAFE_ARRAYSIZE( validAuthPacketTbl, int ) : \
			  FAILSAFE_ARRAYSIZE( validDataPacketTbl, int );
	LOOP_INDEX i;

	REQUIRES( packetType >= 0 && packetType <= 0xFF );
	REQUIRES( isEnumRange( protocolState, SSH_PROTOSTATE ) );

	/* Make sure that the packet is valid */
	LOOP_MED( i = 0, i < validPacketTblSize && \
					 validPacketTbl[ i ] != packetType && \
					 validPacketTbl[ i ] != CRYPT_ERROR, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, validPacketTblSize - 1 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < validPacketTblSize );
	if( validPacketTbl[ i ] == CRYPT_ERROR )
		return( CRYPT_ERROR_BADDATA );
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read/Unwrap a Packet						*
*																			*
****************************************************************************/

/* Get the reason why the peer closed the connection */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getDisconnectInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					   INOUT_PTR STREAM *stream )
	{
	static const MAP_TABLE errorMapTbl[] = {
		/* A mapping of SSH error codes that have cryptlib equivalents to
		   the equivalent cryptlib codes.  If there's no mapping available,
		   we use a default of CRYPT_ERROR_READ */
		{ SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT, CRYPT_ERROR_PERMISSION },
		{ SSH_DISCONNECT_MAC_ERROR, CRYPT_ERROR_SIGNATURE },
		{ SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, CRYPT_ERROR_NOTAVAIL },
		{ SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, CRYPT_ERROR_NOTAVAIL },
		{ SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, CRYPT_ERROR_WRONGKEY },
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	char errorString[ MAX_ERRMSG_SIZE + 8 ];
	int errorCode, clibStatus, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );

	/* Peer is disconnecting, find out why:

	  [	byte	SSH_MSG_DISCONNECT ]
		uint32	reason
		string	description
		string	language_tag */
	errorCode = readUint32( stream );
	if( cryptStatusError( errorCode ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid disconnect status information in disconnect "
				  "message" ) );
		}
	status = readString32Opt( stream, errorString, MAX_ERRMSG_SIZE - 64, 
							  &length );
	if( cryptStatusOK( status ) && length > 0 )
		{
		/* The string is always present but may have a zero length so we 
		   have to check for both its presence and a nonzero size */
		sanitiseString( errorString, MAX_ERRMSG_SIZE - 64, length );
		}
	else
		{
		memcpy( errorString, "<No details available>", 22 + 1 );
		}
	DEBUG_PRINT(( "Processing disconnect message, reason %d, "
				  "description '%s'.\n", errorCode, errorString ));

	/* Try and map the SSH status to an equivalent cryptlib one */
	if( errorCode <= SSH_DISCONNECT_NONE || errorCode >= SSH_DISCONNECT_LAST )
		{
		/* Return a general error code */
		clibStatus = CRYPT_ERROR_READ;
		}
	else
		{
		status = mapValue( errorCode, &clibStatus, errorMapTbl,
						   FAILSAFE_ARRAYSIZE( errorMapTbl, MAP_TABLE ) );
		if( cryptStatusError( status ) )
			{
			/* We couldn't find anything appropriate, return a general error 
			   code */
			clibStatus = CRYPT_ERROR_READ;
			}
		}
	retExt( clibStatus,
			( clibStatus, SESSION_ERRINFO, 
			  "Received disconnect message: %s", errorString ) );
	}

/* Read, decrypt if necessary, and check the start of a packet header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5, 6, 7 ) ) \
int readPacketHeaderSSH2( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  IN_RANGE( SSH_MSG_DISCONNECT, \
									SSH_MSG_SPECIAL_LAST - 1 ) \
								const int expectedType, 
						  OUT_LENGTH_Z int *packetLength,
						  OUT_DATALENGTH_Z int *packetExtraLength,
						  OUT_LENGTH_SHORT_Z int *payloadBytesRead,
						  INOUT_PTR SSH_INFO *sshInfo,
						  INOUT_PTR READSTATE_INFO *readInfo,
						  IN_ENUM( SSH_PROTOSTATE ) \
							const SSH_PROTOSTATE_TYPE protocolState )
	{
	STREAM stream;
	const BOOLEAN isHandshake = \
			( protocolState == SSH_PROTOSTATE_HANDSHAKE  || \
			  protocolState == SSH_PROTOSTATE_AUTH ) ? TRUE : FALSE;
	const BOOLEAN isSecureRead = \
			TEST_FLAG( sessionInfoPtr->flags, \
					   SESSION_FLAG_ISSECURE_READ ) ? TRUE : FALSE;
	const BOOLEAN useETM = \
			TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_ETM ) ? \
			TRUE : FALSE;
	const int headerByteCount = isSecureRead && useETM ? \
			LENGTH_SIZE + MIN_PACKET_SIZE : MIN_PACKET_SIZE;
	int length, extraLength = 0, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( packetLength, sizeof( int ) ) );
	assert( isWritePtr( packetExtraLength, sizeof( int ) ) );
	assert( isWritePtr( sshInfo, sizeof( SSH_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( expectedType >= SSH_MSG_DISCONNECT && \
			  expectedType < SSH_MSG_SPECIAL_LAST );
	REQUIRES( isEnumRange( protocolState, SSH_PROTOSTATE ) );

	/* Clear return values */
	*packetLength = 0;
	*packetExtraLength = 0;
	*payloadBytesRead = 0;
	*readInfo = READINFO_NONE;

	/* Make sure that the header buffers declared in session.h are big 
	   enough to hold the data that we need to read into them.  It can't 
	   be declared using LENGTH_SIZE and MIN_PACKET_SIZE because these 
	   aren't visible outside the SSH code */
	static_assert( LENGTH_SIZE + MIN_PACKET_SIZE <= CRYPT_MAX_IVSIZE,
				   "Packet header size" );

	/* SSH encrypts everything but the MAC (including the packet length in
	   the standard non-EtM processing mode) so we need to speculatively 
	   read ahead for the minimum packet size and decrypt that in order to 
	   figure out what to do:

		uint32		length (excluding MAC size)
		byte		padLen
		byte		type
		byte[]		data 
		byte[]		pad
		byte[]		MAC*/
	if( isHandshake )
		{
		/* Processing handshake data can run into a number of special-case
		   conditions due to buggy SSH implementations, to handle these we
		   check the return code as well as the returned data to see if we
		   need to process it specially */
		status = readFixedHeaderAtomic( sessionInfoPtr, 
										sshInfo->headerBuffer, 
										headerByteCount );
		if( status == CRYPT_ERROR_READ || cryptStatusOK( status ) )
			{
			const int localStatus = \
				checkHandshakePacketStatus( sessionInfoPtr, status, 
											sshInfo->headerBuffer, 
											headerByteCount, expectedType );
			if( cryptStatusError( localStatus ) )
				status = localStatus;
			}
		}
	else
		{
		status = readFixedHeader( sessionInfoPtr, sshInfo->headerBuffer, 
								  headerByteCount );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If we're in the data-processing stage (i.e. it's a post-handshake
	   data packet read) exception conditions need to be handled specially 
	   if they occur.  In addition if we're still in the handshake stage 
	   but with encryption enabled (also covered by isSecureRead), the same 
	   conditions apply */
	if( isSecureRead )
		*readInfo = READINFO_FATAL_CRYPTO;
	else
		*readInfo = READINFO_FATAL;

	/* The MAC size isn't included in the packet length so we have to add it 
	   manually if required */
	if( isSecureRead )
		extraLength = sessionInfoPtr->authBlocksize;

	/* Decrypt the header if necessary.  If we're using EtM then the length 
	   at the start is sent unencrypted so we have to adjust which portion 
	   of the message we decrypt */
	if( isSecureRead )
		{
		void *payloadPtr = useETM ? sshInfo->headerBuffer + LENGTH_SIZE : \
									sshInfo->headerBuffer;

		/* If we're using EtM then we have to preserve a copy of the 
		   ciphertext so that we can MAC it later */
#ifdef USE_SSH_OPENSSH
		if( useETM )
			{
			memcpy( sshInfo->encryptedHeaderBuffer, payloadPtr, 
					MIN_PACKET_SIZE );
			}
#endif /* USE_SSH_OPENSSH */
#ifdef USE_SSH_CTR
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_CTR ) )
			{
			status = ctrModeCrypt( sessionInfoPtr->iCryptInContext,
								   sshInfo->readCTR, 
								   sessionInfoPtr->cryptBlocksize,
								   payloadPtr, MIN_PACKET_SIZE );
			}
		else
#endif /* USE_SSH_CTR */
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_CTX_DECRYPT, payloadPtr,
								  MIN_PACKET_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the packet header.  The dual minimum-length checks actually
	   simplify to the following:

		Non-secure mode: length < SSH2_HEADER_REMAINDER_SIZE (extraLength = 0).
			In this case there's no MAC being used, so all that we need to
			guarantee is that the packet is at least as long as the
			(remaining) data that we've already read.

		Secure mode: length < ID_SIZE + PADLENGTH_SIZE + \
			SSH2_MIN_PADLENGTH_SIZE.  In this case there's an (implicit) MAC
			present so the packet (length + extraLength) will always be
			larger than the (remaining) data that we've already read.  For
			this case we need to check that the data payload is at least as
			long as the minimum-length packet */
	sMemConnect( &stream, sshInfo->headerBuffer, headerByteCount );
	status = length = readUint32( &stream );
	static_assert( SSH_HEADER_REMAINDER_SIZE == MIN_PACKET_SIZE - \
												LENGTH_SIZE, \
				   "Header length calculation" );
	if( cryptStatusError( status ) || \
		!isBufsizeRangeMin( length, ID_SIZE + PADLENGTH_SIZE + \
										SSH2_MIN_PADLENGTH_SIZE ) || \
		length + extraLength < SSH_HEADER_REMAINDER_SIZE || \
		length + extraLength >= sessionInfoPtr->receiveBufSize )
		{
		sMemDisconnect( &stream );
		if( isSecureRead && \
			length + extraLength >= sessionInfoPtr->receiveBufSize )
			{
			/* Some implementations, for example Chilkat before 9.5.0.94, 
			   ignore the max_packet_size value set in the 
			   SSH_MSG_CHANNEL_OPEN / SSH_MSG_CHANNEL_OPEN_CONFIRMATION 
			   exchange (for the Chilkat case see the setting for 
			   UploadChunkSize in 
			   https://www.chilkatsoft.com/refdoc/csSFtpRef.html) so we 
			   provide a special-case error message for this situation */
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "%s sent packet of length %d, exceeding the "
					  "permitted max_packet_size value %d", 
					  isServer( sessionInfoPtr ) ? "Client" : "Server",
					  length, sessionInfoPtr->receiveBufSize - extraLength ) );
			}
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid packet length %d, should be %d...%d", 
				  cryptStatusError( length ) ? 0 : length,
				  ID_SIZE + PADLENGTH_SIZE + SSH2_MIN_PADLENGTH_SIZE,
				  sessionInfoPtr->receiveBufSize - extraLength ) );
		}
	if( isSecureRead )
		{
		const int encryptedLength = useETM ? length : LENGTH_SIZE + length;

		if( encryptedLength % sessionInfoPtr->cryptBlocksize != 0 )
			{
			sMemDisconnect( &stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid packet payload length %d, isn't a multiple of "
					  "cipher block size %d", encryptedLength, 
					  sessionInfoPtr->cryptBlocksize ) );
			}
		}

	/* Peek ahead into the stream to extract the pad length and type 
	   information.  We have to leave this in place in the stream because 
	   it's going to be read into the session buffer on so we can't read it 
	   from the stream above but have to manually extract it here */
	static_assert( LENGTH_SIZE + 1 + ID_SIZE <= MIN_PACKET_SIZE,
				   "Header length calculation" );
	sshInfo->padLength = sshInfo->headerBuffer[ LENGTH_SIZE ];
	sshInfo->packetType = sshInfo->headerBuffer[ LENGTH_SIZE + 1 ];
	if( sshInfo->padLength < SSH2_MIN_PADLENGTH_SIZE || \
		sshInfo->padLength > 255 ) 
		{
		sMemDisconnect( &stream );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid%s packet padding length %d, should be %d...%d", 
				  isHandshake ? " handshake" : "", 
				  sshInfo->padLength, SSH2_MIN_PADLENGTH_SIZE, 255 ) );
		}
	if( 1 + ID_SIZE + sshInfo->padLength > length )
		{
		sMemDisconnect( &stream );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "%sacket payload size %d exceeds packet length %d",
				  isHandshake ? "Handshake p" : "P",
				  1 + ID_SIZE + sshInfo->padLength, length ) );
		}

	/* Perform a basic validity check for the packet type */
	status = checkPacketValid( sshInfo->packetType, protocolState );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Invalid%s packet %s (%d), expected %s (%d)", 
				  isHandshake ? " handshake" : "", 
				  getSSHPacketName( sshInfo->packetType ), sshInfo->packetType,
				  getSSHPacketName( expectedType ), expectedType ) );
		}

	/* We've passed the crypto stage, errors are still fatal but no longer
	   fatal crypto errors */
	if( isSecureRead )
		*readInfo = READINFO_FATAL;

	/* Move the body of the header (excluding the length at the start) from 
	   the header buffer into the session buffer so that we can work with 
	   it */
	ENSURES( ( isHandshake && sessionInfoPtr->receiveBufPos == 0 ) || \
			 !isHandshake );
	ENSURES( boundsCheckZ( sessionInfoPtr->receiveBufPos, 
						   headerByteCount - LENGTH_SIZE, 
						   sessionInfoPtr->receiveBufSize ) );
	status = sread( &stream, sessionInfoPtr->receiveBuffer + \
							 sessionInfoPtr->receiveBufPos, 
					headerByteCount - LENGTH_SIZE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	*packetLength = length;
	*packetExtraLength = extraLength;
	*payloadBytesRead = headerByteCount - LENGTH_SIZE;

	return( CRYPT_OK );
	}

/* Read an SSH handshake packet.  This function is only used during the 
   handshake phase (the data transfer phase has its own read/write code) so 
   we can perform some special-case handling based on this.  In particular 
   we know that packets will always be read into the start of the receive 
   buffer so we don't have to perform special buffer-space-remaining 
   calculations */

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1 ) ) \
static int readHSPacket( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 IN_RANGE( SSH_MSG_DISCONNECT, \
								   SSH_MSG_SPECIAL_REQUEST ) int expectedType,
						 IN_RANGE( 1, 1024 ) const int minPacketSize,
						 OUT_PTR READSTATE_INFO *readInfo,
						 IN_ENUM( SSH_PROTOSTATE ) \
							const SSH_PROTOSTATE_TYPE protocolState )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	const BOOLEAN isSecureRead = \
			TEST_FLAG( sessionInfoPtr->flags, \
					   SESSION_FLAG_ISSECURE_READ ) ? TRUE : FALSE;
	const BOOLEAN useETM = \
			TEST_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_ETM ) ? \
			TRUE : FALSE;
	int length DUMMY_INIT, minPacketLength = minPacketSize;
	LOOP_INDEX noPackets;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( expectedType >= SSH_MSG_DISCONNECT && \
			  expectedType < SSH_MSG_SPECIAL_LAST );
	REQUIRES( minPacketSize >= 1 && minPacketSize <= 1024 );
	REQUIRES( protocolState == SSH_PROTOSTATE_HANDSHAKE || \
			  protocolState == SSH_PROTOSTATE_AUTH );

	/* Errors in reading handshake packets are fatal */
	*readInfo = READINFO_FATAL;

	/* Alongside the expected handshake packets the server can send us all 
	   sorts of no-op messages ranging from explicit no-ops 
	   (SSH_MSG_IGNORE) through to general chattiness (SSH_MSG_DEBUG, 
	   SSH_MSG_USERAUTH_BANNER).  Because we can receive any quantity of 
	   these at any time we have to run the receive code in a (bounds-
	   checked) loop to strip them out (Quo usque tandem abutere, Catilina, 
	   patientia nostra?) */
	LOOP_SMALL( ( noPackets = 0, sshInfo->packetType = SSH_MSG_IGNORE ),
				( sshInfo->packetType == SSH_MSG_IGNORE || \
				  sshInfo->packetType == SSH_MSG_DEBUG || \
				  sshInfo->packetType == SSH_MSG_USERAUTH_BANNER ) && \
				noPackets <= 3, 
				noPackets++ )
		{
		int payloadLengthRead, extraLength, status;

		ENSURES( LOOP_INVARIANT_SMALL( noPackets, 0, 4 ) );

		/* Read the SSH handshake packet header:

			uint32		length (excluding MAC size)
			byte		padLen
			byte		type
			byte[]		data
			byte[]		padding
			byte[]		MAC

		  The reason why the length and padding length precede the packet 
		  type and other information is that these two fields are part of 
		  the SSH transport layer while the type and payload are seen as 
		  part of the connection layer, although the different RFCs tend to 
		  mix them up quite thoroughly */
		REQUIRES( sessionInfoPtr->receiveBufPos == 0 && \
				  sessionInfoPtr->receiveBufEnd == 0 );
		status = readPacketHeaderSSH2( sessionInfoPtr, expectedType, &length,
									   &extraLength, &payloadLengthRead, 
									   sshInfo, readInfo, protocolState );
		if( cryptStatusError( status ) )
			return( status );
		ENSURES( !checkOverflowAdd( length, extraLength ) );
		ENSURES( length + extraLength >= payloadLengthRead && \
				 length + extraLength < sessionInfoPtr->receiveBufSize );
				 /* Guaranteed by readPacketHeaderSSH2() */

		/* Read the remainder of the handshake-packet message.  The change 
		   cipherspec message has length 0 so we only perform the read if 
		   there's packet data present */
		if( length + extraLength > payloadLengthRead )
			{
			const int remainingLength = length + extraLength - \
										payloadLengthRead;
			int readLength;				/* Range checked above */

			REQUIRES( isBufsizeRange( remainingLength ) );

			/* Because this code is called conditionally we can't make the
			   read part of the fixed-header read but have to do independent
			   handling of shortfalls due to read timeouts */
			status = readLength = \
				sread( &sessionInfoPtr->stream,
					   sessionInfoPtr->receiveBuffer + \
						payloadLengthRead, remainingLength );
			if( cryptStatusError( status ) )
				{
				sNetGetErrorInfo( &sessionInfoPtr->stream,
								  &sessionInfoPtr->errorInfo );
				return( status );
				}
			if( readLength != remainingLength )
				{
				retExt( CRYPT_ERROR_TIMEOUT,
						( CRYPT_ERROR_TIMEOUT, SESSION_ERRINFO, 
						  "Timeout during handshake packet remainder read, "
						  "only got %d of %d bytes", readLength,
						  remainingLength ) );
				}
			status = CRYPT_OK;	/* status is a byte count */
			}

		/* Decrypt and MAC the packet if required */
		if( isSecureRead )
			{
			const int encryptedPayloadLength = length - payloadLengthRead;

			/* Errors in this section are fatal crypto errors */
			*readInfo = READINFO_FATAL_CRYPTO;

			/* If we're using EtM then we have to MAC the encrypted payload 
			   before we decrypt it, first the header data and then the
			   remaining payload data */
#ifdef USE_SSH_OPENSSH
			if( useETM )
				{
				status = checkMacSSHIncremental( sessionInfoPtr->iAuthInContext,
										sshInfo->readSeqNo, 
										sshInfo->encryptedHeaderBuffer,
										MIN_PACKET_SIZE, MIN_PACKET_SIZE, 
										length, MAC_START, extraLength );
				if( cryptStatusOK( status ) )
					{
					status = checkMacSSHIncremental( sessionInfoPtr->iAuthInContext,
										0, sessionInfoPtr->receiveBuffer + \
												payloadLengthRead, 
										sessionInfoPtr->receiveBufSize,
										encryptedPayloadLength, 0, 
										MAC_END, extraLength );
					}

				/* Drop through to the following code, which in the case of 
				   an error forces an exit via the non-EtM MAC check further 
				   down */
				}
#endif /* USE_SSH_OPENSSH */

			/* Decrypt the remainder of the packet except for the MAC.
			   Sometimes the payload can be zero-length so we have to check
			   for this before we try the decrypt */
			if( cryptStatusOK( status ) && length > payloadLengthRead )
				{
#ifdef USE_SSH_CTR
				if( TEST_FLAG( sessionInfoPtr->protocolFlags, 
							   SSH_PFLAG_CTR ) )
					{
					status = ctrModeCrypt( sessionInfoPtr->iCryptInContext,
										   sshInfo->readCTR, 
										   sessionInfoPtr->cryptBlocksize,
										   sessionInfoPtr->receiveBuffer + \
												payloadLengthRead,
										   encryptedPayloadLength );
					}
				else
#endif /* USE_SSH_CTR */
				status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
										  IMESSAGE_CTX_DECRYPT,
										  sessionInfoPtr->receiveBuffer + \
												payloadLengthRead,
										  encryptedPayloadLength );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* MAC the decrypted payload if we're using standard SSH 
			   processing */
			if( !useETM )
				{
				status = checkMacSSH( sessionInfoPtr->iAuthInContext,
									  sshInfo->readSeqNo,
									  sessionInfoPtr->receiveBuffer, 
									  length + extraLength, length, 
									  extraLength );
				}
			if( cryptStatusError( status ) )
				{
				/* If we're expecting a service control packet after a change
				   cipherspec packet and don't get it then it's more likely
				   that the problem is due to the wrong key being used than
				   data corruption so we return a wrong key error instead of 
				   bad data */
				if( expectedType == SSH_MSG_SERVICE_REQUEST || \
					expectedType == SSH_MSG_SERVICE_ACCEPT )
					{
					retExt( CRYPT_ERROR_WRONGKEY,
							( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
							  "Bad message MAC for %s (%d) packet, length %d, "
							  "probably due to an incorrect key being used "
							  "to generate the MAC", 
							  getSSHPacketName( sshInfo->packetType ), 
							  sshInfo->packetType, length ) );
					}
				retExt( CRYPT_ERROR_SIGNATURE,
						( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
						  "Bad message MAC for %s packet, length %d", 
						  getSSHPacketName( sshInfo->packetType ), 
						  length ) );
				}

			/* Errors are back to normal fatal errors */
			*readInfo = READINFO_FATAL;
			}
		sshInfo->readSeqNo++;
		DEBUG_PRINT(( "Read %s (%d) packet, length %d.\n", 
					  getSSHPacketName( sshInfo->packetType ), 
					  sshInfo->packetType,
					  length - ( 1 + ID_SIZE + sshInfo->padLength ) ));
		DEBUG_DUMP_DATA( sessionInfoPtr->receiveBuffer + 1 + ID_SIZE, 
						 length - ( 1 + ID_SIZE + sshInfo->padLength ) );
		DEBUG_DUMP_SSH( sessionInfoPtr->receiveBuffer, length, TRUE );

		/* The SSH protocol spec is extremely lax about which packets can 
		   appear where, with interoperability relying on the fact that most
		   implementations only send them in stereotyped patterns, with
		   interesting breakage being possible if you send a valid but
		   unexpected packet to some servers.  For example global requests
		   can be sent at any time (e.g. a channel open during the keyex),
		   and the other side is expected to deal with them in this state.  
		   Currently no-one sends global requests during the handshake and
		   only OpenSSH sends global requests in the middle of the auth
		   process (the client sends an auth request and gets back a global
		   request rather than the expected auth response), so we check for 
		   this special case and turn it into a no-op.
		   
		   (In theory we're supposed to turn it into an 
		   SSH_MSG_REQUEST_FAILURE response, but the OpenSSH server doesn't 
		   seem to mind if it doesn't get a response and it keeps the logic 
		   simpler).
		   
		   We also check for other out-of-place packets that may turn up and
		   return an error if we find them.  Again, the spec is extremely
		   vague on what's valid where so we can't be as strict as we'd like
		   to in case there's some oddball implementation out there that 
		   inserts them in unexpected but technically valid locations */
		if( protocolState == SSH_PROTOSTATE_AUTH && \
			expectedType == SSH_MSG_SPECIAL_CHANNEL && \
			sshInfo->packetType == SSH_MSG_GLOBAL_REQUEST )
			{
			/* Turn a bogus global request in the middle of the auth process
			   into a no-op */
			sshInfo->packetType = SSH_MSG_IGNORE;
			}
		if( sshInfo->packetType == SSH_MSG_USERAUTH_BANNER && \
			( protocolState != SSH_PROTOSTATE_AUTH || \
			  isServer( sessionInfoPtr ) ) )
			{
			/* A banner message can only be sent by the server during the
			   authentication process.  The protocol-state check has already
			   been enforced earlier by checkPacketValid() but we make it
			   explicit here */
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Received unexpected %s packet, length %d", 
					  getSSHPacketName( sshInfo->packetType ), length ) );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( noPackets > 3 )
		{
		/* We have to be a bit careful here in case this is a strange
		   implementation that sends large numbers of no-op packets as cover
		   traffic.  Complaining after 3 consecutive no-ops seems to be a 
		   safe tradeoff between catching DoSes and handling cover traffic */
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "%s sent an excessive number of consecutive no-op "
				  "packets, it may be stuck in a loop",
				  isServer( sessionInfoPtr ) ? "Client" : "Server" ) );
		}

	/* Adjust the length to account for the fixed-size fields, remember
	   where the data starts, and make sure that there's some payload
	   present (there should always be at least one byte, the packet type) */
	length -= PADLENGTH_SIZE + sshInfo->padLength;
	if( sshInfo->packetType == SSH_MSG_DISCONNECT )
		{
		/* If we're expecting a standard data packet and we instead get a 
		   disconnect packet due to an error then the length can be less 
		   than the mimimum length of the expected packet.  To make sure 
		   that we don't bail out with a spurious length check failure we 
		   adjust the minPacketLength to the minimum packet length of a 
		   disconnect packet */
		minPacketLength = ID_SIZE + UINT32_SIZE + \
						  sizeofString32( 0 ) + sizeofString32( 0 );
		}
	if( !isShortIntegerRangeMin( length, minPacketLength ) || \
		length > sessionInfoPtr->receiveBufSize - EXTRA_PACKET_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid length %d for %s (%d) packet, should be %d...%d", 
				  length, getSSHPacketName( sshInfo->packetType ), 
				  sshInfo->packetType, minPacketLength,
				  min( sessionInfoPtr->receiveBufSize - EXTRA_PACKET_SIZE,
					   MAX_INTLENGTH_SHORT ) ) );
		}

	/* Although the packet type is theoretically part of the packet data we
	   strip it since it's already reported in the sshInfo, leaving only the
	   actual payload data in place */
	length -= ID_SIZE;

	/* Move the data that's left beyond the header down in the buffer to get 
	   rid of the header information.  This isn't as inefficient as it seems 
	   since it's only used for the short handshake messages */
	if( length > 0 )
		{
		REQUIRES( rangeCheck( length, PADLENGTH_SIZE + ID_SIZE, 
							  sessionInfoPtr->receiveBufSize ) );
		memmove( sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBuffer + PADLENGTH_SIZE + ID_SIZE, 
				 length );
		}

	/* If the other side has gone away, report the details */
	if( sshInfo->packetType == SSH_MSG_DISCONNECT )
		{
		STREAM stream;
		int status;

		if( length <= 0 )
			return( CRYPT_ERROR_BADDATA );
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		status = getDisconnectInfo( sessionInfoPtr, &stream );
		sMemDisconnect( &stream );
		return( status );
		}

	/* Make sure that we either got what we asked for or one of the allowed
	   special-case packets.  When deciding among valid alternatives we 
	   leave the most obvious choice as the default to look for, which makes
	   the error message more meaningful if none of the choices are found */
	switch( expectedType )
		{
		case SSH_MSG_SPECIAL_USERAUTH_PAM:
			/* PAM authentication can go through multiple iterations of back-
			   and-forth negotiation, for this case an information-request is 
			   also a valid response, otherwise the responses are as for
			   SSH_MSG_SPECIAL_USERAUTH below */
			if( sshInfo->packetType == SSH_MSG_USERAUTH_INFO_REQUEST )
				{
				expectedType = SSH_MSG_USERAUTH_INFO_REQUEST;
				break;
				}
			STDC_FALLTHROUGH;

		case SSH_MSG_SPECIAL_USERAUTH:
			/* If we're reading a response to a user authentication message
			   then getting a failure response is valid (even if it's not
			   what we're expecting) since it's an indication that an
			   incorrect password was used rather than that there was some
			   general type of failure.
			   
			   In addition to getting a success/failure status we can also
			   get an additional extension information message alongside the 
			   one sent earlier for SSH_MSG_SPECIAL_SERVICEACCEPT, because 
			   the server may want to send additional extension information 
			   after authentication */
			expectedType = \
				( sshInfo->packetType == SSH_MSG_EXT_INFO ) ? \
					SSH_MSG_EXT_INFO : \
				( sshInfo->packetType == SSH_MSG_USERAUTH_FAILURE ) ? \
					SSH_MSG_USERAUTH_FAILURE : \
					SSH_MSG_USERAUTH_SUCCESS;
			break;

		case SSH_MSG_SPECIAL_CHANNEL:
			/* If we're reading a response to a channel open message then
			   getting a failure response is valid (even if it's not what
			   we're expecting) since it's an indication that the channel
			   open (for example a port-forwarding operation) failed rather
			   than that there was some general type of failure */
			expectedType = \
				( sshInfo->packetType == SSH_MSG_CHANNEL_OPEN_FAILURE ) ? \
					SSH_MSG_CHANNEL_OPEN_FAILURE : \
					SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
			break;

		case SSH_MSG_SPECIAL_REQUEST:
			/* If we're at the end of the handshake phase we can get either
			   a global or a channel request to tell us what to do next */
			if( sshInfo->packetType != SSH_MSG_GLOBAL_REQUEST && \
				sshInfo->packetType != SSH_MSG_CHANNEL_REQUEST )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid handshake packet %s (%d), expected "
						  "SSH_MSG_GLOBAL_REQUEST (80) or "
						  "SSH_MSG_CHANNEL_REQUEST (98)", 
						  getSSHPacketName( sshInfo->packetType ),
						  sshInfo->packetType ) );
				}
			expectedType = sshInfo->packetType;
			break;

		case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
			/* The ephemeral DH key exchange spec was changed halfway
			   through to try and work around problems with key negotiation,
			   because of this we can see two different types of ephemeral
			   DH request, although they're functionally identical */
			if( sshInfo->packetType == SSH_MSG_KEX_DH_GEX_REQUEST )
				expectedType = SSH_MSG_KEX_DH_GEX_REQUEST;
			break;

		case SSH_MSG_SPECIAL_SERVICEACCEPT:
			/* This should be a service accept message but may be an 
			   extension-info message if the other side is using 
			   extensions */
			expectedType = \
				( sshInfo->packetType == SSH_MSG_EXT_INFO ) ? \
					SSH_MSG_EXT_INFO : SSH_MSG_SERVICE_ACCEPT;
			break;
		}
	if( sshInfo->packetType != expectedType )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid handshake packet %s (%d), expected %s (%d)", 
				  getSSHPacketName( sshInfo->packetType ), sshInfo->packetType,
				  getSSHPacketName( expectedType ), expectedType ) );
		}

	return( length );
	}

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1 ) ) \
int readHSPacketSSH2( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					  IN_RANGE( SSH_MSG_DISCONNECT, \
								SSH_MSG_SPECIAL_LAST - 1 ) \
							int expectedType,
					  IN_RANGE( 1, 1024 ) const int minPacketSize )
	{
	READSTATE_INFO readInfo;
	int status;

	status = readHSPacket( sessionInfoPtr, expectedType, minPacketSize,
						   &readInfo, SSH_PROTOSTATE_HANDSHAKE );
	if( cryptStatusOK( status ) && readInfo == READINFO_FATAL_CRYPTO )
		{
		/* We have to explicitly handle crypto failures at this point 
		   because we're not being called from the higher-level session
		   read handlers that do this for us */
		registerCryptoFailure();
		}
	return( status );
	}

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1 ) ) \
int readAuthPacketSSH2( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						IN_RANGE( SSH_MSG_DISCONNECT, \
								  SSH_MSG_SPECIAL_LAST - 1 ) \
							int expectedType,
						IN_RANGE( 1, 1024 ) const int minPacketSize )
	{
	READSTATE_INFO readInfo;
	int status;

	status = readHSPacket( sessionInfoPtr, expectedType, minPacketSize,
						   &readInfo, SSH_PROTOSTATE_AUTH );
	if( cryptStatusOK( status ) && readInfo == READINFO_FATAL_CRYPTO )
		{
		/* We have to explicitly handle crypto failures at this point 
		   because we're not being called from the higher-level session
		   read handlers that do this for us */
		registerCryptoFailure();
		}
	return( status );
	}
#endif /* USE_SSH */
