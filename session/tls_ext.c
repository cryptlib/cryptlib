/****************************************************************************
*																			*
*					cryptlib TLS Extension Management						*
*					Copyright Peter Gutmann 1998-2024						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "tls.h"
  #include "tls_ext.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/tls.h"
  #include "session/tls_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/* The maximum number of extensions that we allow before getting 
   suspicious */

#define MAX_EXTENSIONS		32

/* In addition to the variable-format extenions above we also support the 
   secure-renegotiation extension.  This is a strange extension to support 
   because cryptlib doesn't do renegotiation, but we have to send it at the 
   client side in order to avoid being attacked via a (non-cryptlib) server 
   that's vulnerable, and we have to process it on the server side in order 
   to not appear to be a vulnerable server (sigh) */

#define RENEG_EXT_SIZE	5
#define RENEG_EXT_DATA	"\xFF\x01\x00\x01\x00"

/* More handling of non-vulnerabilities, many security scanners will report
   everthing they've ever heard of as a vulnerability whether it really is
   one or not.  The following are extensions sent by some scanners, which we
   detect and disable things that are reported as vulnerabilities when we're
   scanned.

	sslscan: Scan fails with the scanner closing the connetion.

	sslyze: Scan fails, cryptlib reports 'No encryption mechanism compatible 
			with the remote system could be found'

	testssl: Sends an extension ID 13172 length 0 on connect */

#define SCANNER_FINGERPRINT_TESTSSL		13172

/****************************************************************************
*																			*
*							Read TLS Extensions								*
*																			*
****************************************************************************/

/* Read a single extension.  The internal structure of some of these things 
   shows that they were created by ASN.1 people... */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6, 7 ) ) \
static int readExtension( INOUT_PTR STREAM *stream, 
						  INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						  IN_RANGE( 0, 65536 ) const int type,
						  IN_LENGTH_SHORT_Z const int extLength,
						  OUT_ENUM_OPT( TLSHELLO_ACTION ) \
								TLSHELLO_ACTION_TYPE *actionType,
						  OUT_BOOL BOOLEAN *extErrorInfoSet )
	{
	int value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( actionType, sizeof( TLSHELLO_ACTION_TYPE ) ) );

	REQUIRES( type >= 0 && type <= 65536 );
	REQUIRES( isShortIntegerRange( extLength ) );

	/* Clear return values */
	*actionType = TLSHELLO_ACTION_NONE;
	*extErrorInfoSet = FALSE;

	switch( type )
		{
		case TLS_EXT_SNI:
			/* Read and process the SNI */
			return( readSNI( stream, handshakeInfo, extLength, 
							 isServer( sessionInfoPtr ) ? \
								TRUE : FALSE ) );

		case TLS_EXT_MAX_FRAGMENT_LENTH:
			{
/*			static const int fragmentTbl[] = \
					{ 0, 512, 1024, 2048, 4096, 8192, 16384, 16384 }; */

			/* Response: If fragment-size == 3...5, send same to peer.  Note 
			   that we also allow a fragment-size value of 5, which isn't 
			   specified in the standard but should probably be present 
			   since it would otherwise result in a missing value between 
			   4096 and the default of 16384:

				byte		fragmentLength */
			status = value = sgetc( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( value < 1 || value > 5 )
				return( CRYPT_ERROR_BADDATA );

/*			sessionInfoPtr->maxPacketSize = fragmentTbl[ value ]; */
			return( CRYPT_OK );
			}

		case TLS_EXT_SUPPORTED_GROUPS:
			{
			/* If we're using pure PSK then there's no ECC information 
			   (or a private key in general) available.  In theory we could
			   be using PSK + ECDH but that's unlikely so we assume that the
			   absence of a private key means no ECC */
			if( sessionInfoPtr->privateKey == CRYPT_ERROR )
				{
				handshakeInfo->disableECC = TRUE;
				return( sSkip( stream, extLength, MAX_INTLENGTH_SHORT ) );
				}

			/* Read and process the list of supported groups */
			return( readSupportedGroups( stream, sessionInfoPtr, 
										 handshakeInfo, extLength, 
										 extErrorInfoSet ) );
			}

		case TLS_EXT_EC_POINT_FORMATS:
			/* We don't really need to process this extension because every 
			   implementation is required to support uncompressed points (it 
			   also seems to be the universal standard that everyone uses by 
			   default anyway) so all that we do is treat the presence of 
			   the overall extension as an indicator that we should send 
			   back our own one in the server hello:

				byte		pointFormatListLength
				byte[]		pointFormat */
			if( extLength > 0 )
				{
				status = sSkip( stream, extLength, MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* If we're the server, remember that we have to echo the 
			   extension back to the client */
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->sendECCPointExtn = TRUE;

			return( CRYPT_OK );

		case TLS_EXT_SIGNATURE_ALGORITHMS:
			/* Read and process the list of signature algorithms */
			return( readSignatureAlgos( stream, sessionInfoPtr, 
										handshakeInfo, extLength, 
										extErrorInfoSet ) );

		case TLS_EXT_SECURE_RENEG:
			/* If we get a nonzero length for this extension (the '1' is the 
			   initial length byte at the start) then it's an indication of 
			   an attack.  The status code to return here is a bit 
			   uncertain, but CRYPT_ERROR_INVALID seems to be the least
			   inappropriate */
			if( extLength != 1 || sgetc( stream ) != 0 )
				return( CRYPT_ERROR_INVALID );

			/* If we're the server, remember that we have to echo the 
			   extension back to the client */
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->flags |= HANDSHAKE_FLAG_NEEDRENEGRESPONSE;

			return( CRYPT_OK );

		case TLS_EXT_ENCTHENMAC:
			if( extLength != 0 )
				return( CRYPT_ERROR_INVALID );

			/* Turn on encrypt-then-MAC and, if we're the server, rememeber 
			   that we have to echo the extension back to the client */
			SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_ENCTHENMAC );
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->flags |= HANDSHAKE_FLAG_NEEDETMRESPONSE;
			
			return( CRYPT_OK );

		case TLS_EXT_EMS:
			if( extLength != 0 )
				return( CRYPT_ERROR_INVALID );

			/* Turn on extended master secret handling */
			SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_EMS );
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->flags |= HANDSHAKE_FLAG_NEEDEMSRESPONSE;
			return( CRYPT_OK );

		case TLS_EXT_TLS12LTS:
			if( extLength != 0 )
				return( CRYPT_ERROR_INVALID );

			/* Turn on TLS 1.2 LTS use.  This option implicitly includes 
			   encrypt-then-MAC and extended master secret, but we can't set 
			   these yet since that would result in us sending spurious 
			   response extensions if LTS was present in a request but the 
			   others weren't */
			SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS );
			if( isServer( sessionInfoPtr ) )
				handshakeInfo->flags |= HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE;
			return( CRYPT_OK );

		case TLS_EXT_SUPPORTED_VERSIONS:
			/* Read and process the version information */
			return( readSupportedVersions( stream, sessionInfoPtr, 
										   handshakeInfo, extLength ) );

#ifdef USE_TLS13
		case TLS_EXT_KEY_SHARE:
			/* If we're using pure PSK then we can't do anything with the
			   keyex data */
			if( isServer( sessionInfoPtr ) && \
				sessionInfoPtr->privateKey == CRYPT_ERROR )
				{
				DEBUG_PRINT(( "Server is using pure PSK, ignoring keyex "
							  "extension.\n" ));
				handshakeInfo->disableECC = TRUE;
				return( sSkip( stream, extLength, MAX_INTLENGTH_SHORT ) );
				}

			/* If the peer didn't offer any TLS 1.3 suites then we can't do 
			   anything with a TLS 1.3 keyex that goes with them */
			if( !handshakeInfo->tls13OK ) 
				return( sSkip( stream, extLength, MAX_INTLENGTH_SHORT ) );
			
			/* Read and process the keyex information */
			status = readKeyexTLS13( sessionInfoPtr, handshakeInfo, stream, 
									 extLength, extErrorInfoSet );
			if( status == OK_SPECIAL )
				{
				/* The client sent an incorrect keyex guess, tell them to 
				   try again.  We set this unconditionally at this point 
				   because we won't know until we see the supported_versions 
				   extension, which may be after this one, whether we're
				   doing TLS 1.3 or not */
				*actionType = TLSHELLO_ACTION_RETRY;
				status = CRYPT_OK;
				}
			return( status );
#endif /* USE_TLS13 */

		case SCANNER_FINGERPRINT_TESTSSL:
			/* Value sent by the testssl scanner */
			if( isServer( sessionInfoPtr ) && extLength == 0 )
				{
				DEBUG_PRINT(( "Scanning attempt by testssl detected.\n" ));
				handshakeInfo->flags |= HANDSHAKE_FLAG_ISSCANNER;
				return( CRYPT_OK );
				}
			/* Fall through */

		default:
			/* If it's an RFC 8701 / GREASE value, skip it */
			if( checkGREASE( type ) && extLength == 0 )
				return( CRYPT_OK );

			/* Default: Ignore the extension */
			if( extLength > 0 )
				{
				status = sSkip( stream, extLength, MAX_INTLENGTH_SHORT );
				if( cryptStatusError( status ) )
					return( status );
				}

			return( CRYPT_OK );
		}

	retIntError();
	}

/* Read TLS extensions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readExtensions( INOUT_PTR STREAM *stream, 
					INOUT_PTR SESSION_INFO *sessionInfoPtr, 
					INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
					OUT_ENUM_OPT( TLSHELLO_ACTION ) \
							TLSHELLO_ACTION_TYPE *actionType,
					IN_LENGTH_SHORT const int length )
	{
	const int endPos = stell( stream ) + length;
	LOOP_INDEX noExtensions;
	int extensionSeen[ MAX_EXTENSIONS + 8 ];
	int extListLen, extensionSeenLast = 0;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( actionType, sizeof( TLSHELLO_ACTION_TYPE ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );
	REQUIRES( isShortIntegerRangeMin( endPos, length ) );

	/* Clear return value */
	*actionType = TLSHELLO_ACTION_NONE;

	/* Read the extension header and make sure that it's valid:

		uint16		extListLen
			uint16	extType
			uint16	extLen
			byte[]	extData 

	   We can get zero-length extensions so we can't take the precaution of 
	   requiring at least one byte of payload data as a sanity check */
	if( length < UINT16_SIZE + UINT16_SIZE + UINT16_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "TLS hello contains %d bytes extraneous data", length ) );
		}
	status = extListLen = readUint16( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid TLS extension information" ) );
		}
	if( extListLen != length - UINT16_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid TLS extension data length %d, should be %d",
				  extListLen, length - UINT16_SIZE ) );
		}

	/* Process the extensions */
	LOOP_MED( noExtensions = 0,
			  noExtensions < MAX_EXTENSIONS && stell( stream ) < endPos, 
			  noExtensions++ )
		{
		TLSHELLO_ACTION_TYPE localActionType;
		BOOLEAN extErrorInfoSet;
		const char *description;
		int type, extLen DUMMY_INIT, minLength, maxLength;

		ENSURES( LOOP_INVARIANT_MED( noExtensions, 0, MAX_EXTENSIONS - 1 ) );

		/* Read the header for the next extension and get the extension-
		   checking information.  The length check at this point is just a
		   generic sanity check, more specific checking is done once we've 
		   got the extension type-specific information */
		type = readUint16( stream );
		status = extLen = readUint16( stream );
		if( cryptStatusError( status ) || \
			!isShortIntegerRange( extLen ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid TLS extension list item header" ) );
			}

		/* Try and get information about this extension */
		status = getExtensionInfo( type, isServer( sessionInfoPtr ) ? \
										 TRUE : FALSE, &minLength, 
								   &maxLength, &description );
		ENSURES( cryptStatusOK( status ) || status == OK_SPECIAL );

		/* Perform any necessary initial checking of the extension */
		if( cryptStatusOK( status ) )
			{
			LOOP_INDEX_ALT i;

			if( minLength == CRYPT_ERROR )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Received disallowed TLS %s extension from %s", 
						  description, isServer( sessionInfoPtr ) ? \
									   "server" : "client" ) );
				}
			if( extLen < minLength || extLen > maxLength )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid TLS %s extension length %d, should be "
						  "%d...%d", description, extLen, minLength, 
						  maxLength ) );
				}

			/* Make sure that we haven't already seen this extension.  Note 
			   that we only perform this check for known extensions, since 
			   we don't know whether new/unknown extensions may be allowed 
			   in duplicate form or not */
			LOOP_EXT_ALT( i = 0, i < extensionSeenLast && \
								 i < MAX_EXTENSIONS, i++, MAX_EXTENSIONS )
				{
				ENSURES( LOOP_INVARIANT_EXT_ALT( i, 0, MAX_EXTENSIONS - 1, \
												 MAX_EXTENSIONS ) );

				if( extensionSeen[ i ] == type )
					{
					retExt( CRYPT_ERROR_BADDATA,
							( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
							  "Duplicate TLS %s extension encountered", 
							  description ) );
					}
				}
			ENSURES( LOOP_BOUND_OK_ALT );
			ENSURES( i <= MAX_EXTENSIONS );
			extensionSeen[ extensionSeenLast++ ] = type;
			}
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT_COND( description != NULL,
						  ( "Read extension TLS %s (%d), length %d.\n",
							description, type, extLen ) );
		DEBUG_PRINT_COND( description == NULL,
						  ( "Read unknown extension %d / 0x%X, length %d.\n",
							type, type, extLen ) );
		DEBUG_DUMP_STREAM( stream, stell( stream ), extLen );
		DEBUG_PRINT_END();

		/* Process the extension data */
		status = readExtension( stream, sessionInfoPtr, handshakeInfo, 
								type, extLen, &localActionType, 
								&extErrorInfoSet );
		if( cryptStatusError( status ) )
			{
			/* If it's an internal error then we can't rely on the value of the 
			   by-reference parameters */
			if( isInternalError( status ) )
				return( status );

			/* If the extended error information has already been set, we're
			   done */
			if( extErrorInfoSet )
				return( status );

			/* Return general error information */
			if( description != NULL )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid TLS %s extension data", 
						  description ) );
				}
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid TLS extension data for extension "
					  "type %d", type ) );
			}

		/* In the case of TLS 1.3 where the keyex is handled via data 
		   stuffed into extensions we can end up with no usable keyex 
		   information present, in which case we have to tell the client 
		   to guess again (seriously! That's how the protocol works) */
#ifdef USE_TLS13
		if( localActionType == TLSHELLO_ACTION_RETRY )
			{
			ENSURES( isServer( sessionInfoPtr ) );

			*actionType = TLSHELLO_ACTION_RETRY;
			}
#endif /* USE_TLS13 */
		}
	ENSURES( LOOP_BOUND_OK );
	if( noExtensions >= MAX_EXTENSIONS )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Excessive number (more than %d) of TLS extensions "
				  "encountered", noExtensions ) );
		}

	/* If we haven't negotiated TLS 1.3 and the client has forced a hello 
	   retry which only exists in TLS 1.3, report the failure as a keyex
	   read problem.  We have to perform the check at this point because the 
	   version negotiation can follow the keyex so we don't know which keyex 
	   actions we should be permitting until after we've already processed 
	   them */
#ifdef USE_TLS13
	if( ( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS13 ) && \
		( *actionType == TLSHELLO_ACTION_RETRY ) )
		{
		DEBUG_PRINT(( "Client forced TLS 1.3 handshake retry but protocol "
					  "version is only TLS 1.%d.\n",
					  sessionInfoPtr->version - 1));
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "Couldn't find a supported keyex type in %s's handshake "
				  "message",
				  isServer( sessionInfoPtr ) ? "client" : "server" ) );
		}
#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Write TLS Extensions							*
*																			*
****************************************************************************/

/* Length information for the extensions */

typedef struct {
	int serverNameHdrLen, serverNameExtLen;
	int supportedVersionsHdrLen, supportedVersionsExtLen;
	int sigHashHdrLen, sigHashExtLen;
	int supportedGroupsHdrLen, supportedGroupsExtLen;
	int pointFormatHdrLen, pointFormatExtLen;
	int pskModeHdrLen, pskModeExtLen;
	int keyexHdrLen, keyexExtLen;
	} EXT_SIZE_INFO;

/* Calculate the size of the extensions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int sizeofExtensions( const SESSION_INFO *sessionInfoPtr,
							 const TLS_HANDSHAKE_INFO *handshakeInfo,
							 IN_RANGE( TLS_MINOR_VERSION_TLS, \
									   TLS_MINOR_VERSION_TLS13 ) \
								const int tlsMinVersion,
							 OUT_PTR EXT_SIZE_INFO *extSizeInfo )
	{
	STREAM nullStream;
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( extSizeInfo, sizeof( EXT_SIZE_INFO ) ) );

	REQUIRES( tlsMinVersion >= TLS_MINOR_VERSION_TLS && \
			  tlsMinVersion <= TLS_MINOR_VERSION_TLS13 );

	/* Clear return value */
	memset( extSizeInfo, 0, sizeof( EXT_SIZE_INFO ) );

	/* Determine the overall length of the extension data, first the server 
	   name indication (SNI) if it's present (it may not be if we're using
	   a raw network socket) */
	if( findSessionInfo( sessionInfoPtr,
						 CRYPT_SESSINFO_SERVER_NAME ) != NULL )
		{
		extSizeInfo->serverNameHdrLen = UINT16_SIZE + UINT16_SIZE;
		sMemNullOpen( &nullStream );
		status = writeSNI( &nullStream, sessionInfoPtr );
		if( cryptStatusOK( status ) )
			{
			extSizeInfo->serverNameExtLen = stell( &nullStream );
			REQUIRES( \
				isShortIntegerRangeNZ( extSizeInfo->serverNameExtLen ) );
			}
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Anything beyond this point is TLS 1.2+ so we don't go any further if 
	   we're on an earlier version */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS12 )
		return( CRYPT_OK );

	/* TLS 1.3 supported versions.  We write this even for TLS 1.2 because 
	   of the overlap between the two */
	extSizeInfo->supportedVersionsHdrLen = UINT16_SIZE + UINT16_SIZE;
	sMemNullOpen( &nullStream );
	status = writeSupportedVersions( &nullStream, sessionInfoPtr, 
									 tlsMinVersion );
	if( cryptStatusOK( status ) )
		{
		extSizeInfo->supportedVersionsExtLen = stell( &nullStream );
		REQUIRES( \
			isShortIntegerRangeNZ( extSizeInfo->supportedVersionsExtLen ) );
		}
	sMemClose( &nullStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Signature and hash algorithms */
	extSizeInfo->sigHashHdrLen = UINT16_SIZE + UINT16_SIZE;
	sMemNullOpen( &nullStream );
	status = writeSignatureAlgos( &nullStream );
	if( cryptStatusOK( status ) )
		{
		extSizeInfo->sigHashExtLen = stell( &nullStream );
		REQUIRES( isShortIntegerRangeNZ( extSizeInfo->sigHashExtLen ) );
		}
	sMemClose( &nullStream );
	if( cryptStatusError( status ) )
		return( status );

	/* ECC information.  This is only sent if we're proposing ECC suites in 
	   the client hello, in theory we could also write it for TLS 1.3 with 
	   only DHE groups but that has ECC as MTI so we'll always have ECC 
	   suites enabled */
	if( algoAvailable( CRYPT_ALGO_ECDH ) || \
		algoAvailable( CRYPT_ALGO_25519 ) )
		{
		extSizeInfo->supportedGroupsHdrLen = UINT16_SIZE + UINT16_SIZE;
		sMemNullOpen( &nullStream );
		status = writeSupportedGroups( &nullStream, sessionInfoPtr );
		if( cryptStatusOK( status ) )
			{
			extSizeInfo->supportedGroupsExtLen = stell( &nullStream );
			REQUIRES( \
				isShortIntegerRangeNZ( extSizeInfo->supportedGroupsExtLen ) );
			}
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );

		/* The point-format extension is fixed-length so we just hardcode 
		   the length information here */
		extSizeInfo->pointFormatHdrLen = UINT16_SIZE + UINT16_SIZE;
		extSizeInfo->pointFormatExtLen = 1 + 1;
		}

	/* Anything beyond this point is TLS 1.3+ so we don't go any further if 
	   we're on an earlier version */
	if( sessionInfoPtr->version < TLS_MINOR_VERSION_TLS13 )
		return( CRYPT_OK );

#ifdef USE_TLS13
	/* PSK modes, TLS 1.3's version of session resumption */
	extSizeInfo->pskModeHdrLen = UINT16_SIZE + UINT16_SIZE;
	extSizeInfo->pskModeExtLen = 1 + 1;

	/* Keyex inforation, which in TLS 1.3 is stuffed into an extension in 
	   the client hello rather than being sent as an actual keyex */
	extSizeInfo->keyexHdrLen = UINT16_SIZE + UINT16_SIZE;
	sMemNullOpen( &nullStream );
	status = writeKeyexTLS13( &nullStream, handshakeInfo, FALSE );
	if( cryptStatusOK( status ) )
		{
		extSizeInfo->keyexExtLen = stell( &nullStream );
		REQUIRES( isShortIntegerRangeNZ( extSizeInfo->keyexExtLen ) );
		}
	sMemClose( &nullStream );
	if( cryptStatusError( status ) )
		return( status );
#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}

/* Write a TLS extension header */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeExtensionHdr( INOUT_PTR STREAM *stream,
							  IN_RANGE( 0, 65536 ) const int type,
							  IN_LENGTH_SHORT_Z const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( type >= 0 && type <= 65536 );
	REQUIRES( isShortIntegerRange( length ) );
			  /* May be zero for signalling extensions */

	writeUint16( stream, type );
	return( writeUint16( stream, length ) );
	}

/* Write TLS extensions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeClientExtensions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );
	const TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	EXT_SIZE_INFO extSizeInfo;
	int minVersion, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS );
	REQUIRES( protocolInfo != NULL );

	/* Get the minimum protocol version.  We have to do it at this point 
	   after ensuring that protocolInfo is valid */
	minVersion = ( tlsInfo->minVersion > 0 ) ? \
				 tlsInfo->minVersion : protocolInfo->minVersion;

	/* Determine the overall length of the extension data */
	status = sizeofExtensions( sessionInfoPtr, handshakeInfo, minVersion, 
							   &extSizeInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the list of extensions */
	writeUint16( stream, extSizeInfo.serverNameHdrLen + \
								extSizeInfo.serverNameExtLen + \
						 extSizeInfo.supportedVersionsHdrLen + \
								extSizeInfo.supportedVersionsExtLen + \
						 RENEG_EXT_SIZE +					/* Renegotiation */
						 ( UINT16_SIZE + UINT16_SIZE ) +	/* EncThenMAC */
						 ( UINT16_SIZE + UINT16_SIZE ) +	/* Extended MS */
						 ( UINT16_SIZE + UINT16_SIZE ) +	/* TLS 1.2 LTS */
						 extSizeInfo.sigHashHdrLen + \
								extSizeInfo.sigHashExtLen + \
						 extSizeInfo.supportedGroupsHdrLen + \
								extSizeInfo.supportedGroupsExtLen + \
						 extSizeInfo.pointFormatHdrLen + \
								extSizeInfo.pointFormatExtLen + \
						 extSizeInfo.pskModeHdrLen + \
								extSizeInfo.pskModeExtLen + \
						 extSizeInfo.keyexHdrLen + \
								extSizeInfo.keyexExtLen );
	if( extSizeInfo.serverNameHdrLen > 0 )
		{
		writeExtensionHdr( stream, TLS_EXT_SNI, extSizeInfo.serverNameExtLen );
		status = writeSNI( stream, sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension server name indication (%d), length %d.\n",
					  TLS_EXT_SNI, extSizeInfo.serverNameExtLen ));
		DEBUG_DUMP_STREAM( stream, 
						   stell( stream ) - extSizeInfo.serverNameExtLen, 
						   extSizeInfo.serverNameExtLen );
		DEBUG_PRINT_END();
		}
	if( extSizeInfo.supportedVersionsHdrLen > 0 )
		{
		writeExtensionHdr( stream, TLS_EXT_SUPPORTED_VERSIONS, 
						   extSizeInfo.supportedVersionsExtLen );
		status = writeSupportedVersions( stream, sessionInfoPtr, minVersion );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension supported versions (%d), length %d.\n",
					  TLS_EXT_SUPPORTED_VERSIONS, 
					  extSizeInfo.supportedVersionsExtLen ));
		DEBUG_DUMP_STREAM( stream, 
						   stell( stream ) - extSizeInfo.supportedVersionsExtLen, 
						   extSizeInfo.supportedVersionsExtLen );
		DEBUG_PRINT_END();
		}
	status = swrite( stream, RENEG_EXT_DATA, RENEG_EXT_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT_BEGIN();
	DEBUG_PRINT(( "Wrote extension secure renegotiation (%d), length 1.\n",
				  TLS_EXT_SECURE_RENEG ));
	DEBUG_DUMP_STREAM( stream, stell( stream ) - 1, 1 );
	DEBUG_PRINT_END();
	status = writeExtensionHdr( stream, TLS_EXT_ENCTHENMAC, 0 );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT(( "Wrote extension encrypt-then-MAC (%d), length 0.\n",
				  TLS_EXT_ENCTHENMAC ));
	status = writeExtensionHdr( stream, TLS_EXT_EMS, 0 );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT(( "Wrote extension extended Master Secret (%d), length 0.\n",
				  TLS_EXT_EMS ));
	status = writeExtensionHdr( stream, TLS_EXT_TLS12LTS, 0 );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_PRINT(( "Wrote extension TLS 1.2 LTS (%d), length 0.\n",
				  TLS_EXT_TLS12LTS ));
	if( extSizeInfo.sigHashExtLen > 0 )
		{
		/* Write the signature+hash algorithms extension */
		status = writeExtensionHdr( stream, TLS_EXT_SIGNATURE_ALGORITHMS, 
									extSizeInfo.sigHashExtLen );
		if( cryptStatusOK( status ) )
			status = writeSignatureAlgos( stream );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension signature algorithm (%d), length %d.\n",
					  TLS_EXT_SIGNATURE_ALGORITHMS, 
					  extSizeInfo.sigHashExtLen ));
		DEBUG_DUMP_STREAM( stream, 
						   stell( stream ) - extSizeInfo.sigHashExtLen, 
						   extSizeInfo.sigHashExtLen );
		DEBUG_PRINT_END();
		}
	if( extSizeInfo.supportedGroupsExtLen > 0 )
		{
		/* Write the supported groups extension */
		writeExtensionHdr( stream, TLS_EXT_SUPPORTED_GROUPS, 
						   extSizeInfo.supportedGroupsExtLen );
		status = writeSupportedGroups( stream, sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension supported groups (%d), length %d.\n",
					  TLS_EXT_SUPPORTED_GROUPS, 
					  extSizeInfo.supportedGroupsExtLen ));
		DEBUG_DUMP_STREAM( stream, 
						   stell( stream ) - extSizeInfo.supportedGroupsExtLen, 
						   extSizeInfo.supportedGroupsExtLen );
		DEBUG_PRINT_END();

		/* Write the ECC point format extension */
		writeExtensionHdr( stream, TLS_EXT_EC_POINT_FORMATS, 
						   extSizeInfo.pointFormatExtLen );
		sputc( stream, 1 );						/* Point-format list len.*/
		status = sputc( stream, 0 );			/* Uncompressed points */
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension ECC point format (%d), length %d.\n",
					  TLS_EXT_EC_POINT_FORMATS, 1 + 1 ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - ( 1 + 1 ), 1 + 1 );
		DEBUG_PRINT_END();
		}
#ifdef USE_TLS13
	if( extSizeInfo.pskModeHdrLen > 0 )
		{
		/* Write the TLS 1.3 PSK modes extension.  This extension, 
		   psk_key_exchange_modes, must be sent if the pre_shared_key 
		   extension is sent.  In other words the PSK information is split 
		   across two different extensions for no known reason, with 
		   incredibly complex and awkward rules (RFC 8446 section 
		   4.2.9/4.2.11) for the server having to reconcileg the two after 
		   the client has split them up */
		writeExtensionHdr( stream, TLS_EXT_PSK_KEYEX_MODES, 
						   extSizeInfo.pskModeExtLen );
		sputc( stream, 1 );
		status = sputc( stream, TLS_PSK_STANDARD );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension PSK modes (%d), length %d.\n",
					  TLS_EXT_PSK_KEYEX_MODES, 
					  extSizeInfo.pskModeExtLen ));
		DEBUG_DUMP_STREAM( stream, 
						   stell( stream ) - extSizeInfo.pskModeExtLen, 
						   extSizeInfo.pskModeExtLen );
		DEBUG_PRINT_END();
		}
	if( extSizeInfo.keyexExtLen > 0 )
		{
		/* Write the TLS 1.3 keyex extension */
		writeExtensionHdr( stream, TLS_EXT_KEY_SHARE, 
						   extSizeInfo.keyexExtLen );
		status = writeKeyexTLS13( stream, handshakeInfo, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension keyex (%d), length %d.\n",
					  TLS_EXT_KEY_SHARE, extSizeInfo.keyexExtLen ));
		DEBUG_DUMP_STREAM( stream, 
						   stell( stream ) - extSizeInfo.keyexExtLen, 
						   extSizeInfo.keyexExtLen );
		DEBUG_PRINT_END();
		}
#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int writeServerExtensions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	const BOOLEAN isTLS13 = \
			( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 ) ? \
			TRUE : FALSE;
	int keyexHdrLen = 0, keyexExtLen = 0;
	int extListLen = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS );

	/* Calculate the size of the extensions.  Unlike the client extensions,
	   most of these are just signalling values that acknowledge the 
	   corresponding client extensions or have a single byte of fixed length 
	   so we don't need to explicitly calculate payload lengths.
	   
	   TLS 1.3 doesn't send a lot of the usual extensions, the extension
	   read code manages this by clearing the various needXXX flags, however
	   the SNI response is still sent but in the encrypted extensions rather
	   than the standard extensions so we explicitly check for sending it
	   here */
	if( ( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDSNIRESPONSE ) && \
		!isTLS13 )
		extListLen += UINT16_SIZE + UINT16_SIZE;	/* SNI */
	if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDRENEGRESPONSE )
		extListLen += RENEG_EXT_SIZE;				/* Renegotiation */
	if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDETMRESPONSE )
		extListLen += UINT16_SIZE + UINT16_SIZE;	/* EtM */
	if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDEMSRESPONSE )
		extListLen += UINT16_SIZE + UINT16_SIZE;	/* EMS */
	if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE )
		extListLen += UINT16_SIZE + UINT16_SIZE;	/* LTS */
#ifdef USE_TLS13
	if( isTLS13 )
		{
		extListLen += UINT16_SIZE + UINT16_SIZE + UINT16_SIZE;
		}											/* Supported versions */
#endif /* USE_TLS13 */
	if( isEccAlgo( handshakeInfo->keyexAlgo ) && \
		handshakeInfo->sendECCPointExtn )
		{
		extListLen += UINT16_SIZE + UINT16_SIZE + 1 + 1;
		}											/* Point formats */
#ifdef USE_TLS13
	if( isTLS13 )									/* Keyex */
		{
		/* If this is a Hello Retry Request disguised as a Server Hello,
		   we write the group that we expect the client to use rather than
		   any actual keyex data */
		if( handshakeInfo->flags & HANDSHAKE_FLAG_RETRIEDCLIENTHELLO )
			{
			keyexHdrLen = UINT16_SIZE + UINT16_SIZE;
			keyexExtLen = UINT16_SIZE;
			}
		else
			{
			STREAM nullStream;

			keyexHdrLen = UINT16_SIZE + UINT16_SIZE;
			sMemNullOpen( &nullStream );
			status = writeKeyexTLS13( &nullStream, handshakeInfo, TRUE );
			if( cryptStatusOK( status ) )
				{
				keyexExtLen = stell( &nullStream );
				REQUIRES( isShortIntegerRangeNZ( keyexExtLen ) );
				}
			sMemClose( &nullStream );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
#endif /* USE_TLS13 */
	if( extListLen + keyexHdrLen <= 0 )
		{
		/* No extensions to write, we're done */
		return( CRYPT_OK );
		}

	/* Write the overall extension list length */
	writeUint16( stream, extListLen + keyexHdrLen + keyexExtLen );

	/* If the client sent an SNI extension then we have to acknowledge it
	   with a zero-length SNI extension response.  In most cases, in which
	   the caller hasn't set TLS_PFLAG_SERVER_SNI, this is slightly 
	   dishonest because we haven't passed the SNI data back to the caller,
	   but is typically sent by default by clients and since we're highly 
	   unlikely to be used with multihomed servers but likely to be used in 
	   oddball environments like ones without DNS we just accept any SNI 
	   and allow a connect.  In the case where the caller has set 
	   TLS_PFLAG_SERVER_SNI, we handle the SNI-based server-key switching in 
	   the server code so this response is also appropriate there */
	if( ( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDSNIRESPONSE ) && \
		!isTLS13 )
		{
		status = writeExtensionHdr( stream, TLS_EXT_SNI, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension server name indication (%d), "
					  "length 0.\n", TLS_EXT_SNI, 0 ));
		}

	/* If the client sent a secure-renegotiation indicator we have to send a
	   response even though we don't support renegotiation.  See the comment 
	   by extCheckInfoTbl for why this odd behaviour is necessary */
	if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDRENEGRESPONSE )
		{
		status = swrite( stream, RENEG_EXT_DATA, RENEG_EXT_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension secure renegotiation (%d), length 1.\n",
					  TLS_EXT_SECURE_RENEG ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - 1, 1 );
		DEBUG_PRINT_END();
		}

	/* If the client sent various request indicators, acknowledge them */
	if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDETMRESPONSE )
		{
		status = writeExtensionHdr( stream, TLS_EXT_ENCTHENMAC, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension encrypt-then-MAC (%d), length 0.\n", 
					  TLS_EXT_ENCTHENMAC, 0 ));
		}
	if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDEMSRESPONSE )
		{
		status = writeExtensionHdr( stream, TLS_EXT_EMS, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension extended Master Secret (%d), length 0.\n", 
					  TLS_EXT_EMS, 0 ));
		}
	if( handshakeInfo->flags & HANDSHAKE_FLAG_NEEDTLS12LTSRESPONSE )
		{
		status = writeExtensionHdr( stream, TLS_EXT_TLS12LTS, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension TLS 1.2 LTS (%d), length 0.\n", 
					  TLS_EXT_TLS12LTS ));
		}
#ifdef USE_TLS13
	if( isTLS13 )
		{
		/* Supported versions.  These can only be written if we're talking 
		   TLS 1.3 (RFC 8446 section 4.2.1) */
		writeExtensionHdr( stream, TLS_EXT_SUPPORTED_VERSIONS, UINT16_SIZE );
		status = writeUint16( stream, ( TLS_MAJOR_VERSION << 8 ) | \
										TLS_MINOR_VERSION_TLS13 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension suported versions (%d), length 2.\n", 
					  TLS_MINOR_VERSION_TLS13 ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - UINT16_SIZE, 
						   UINT16_SIZE );
		DEBUG_PRINT_END();
		}
#endif /* USE_TLS13 */

	/* If the client sent ECC extensions and we've negotiated an ECC cipher 
	   suite, send back the appropriate response.  We don't have to send 
	   back the curve ID that we've chosen because this is communicated 
	   explicitly in the server keyex */
	if( isEccAlgo( handshakeInfo->keyexAlgo ) && \
		handshakeInfo->sendECCPointExtn )
		{
		writeExtensionHdr( stream, TLS_EXT_EC_POINT_FORMATS, 1 + 1 );	
										/* Extn. length */
		sputc( stream, 1 );				/* Point-format list len.*/
		status = sputc( stream, 0 );	/* Uncompressed points */
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Wrote extension ECC point format (%d), length 2.\n",
					  TLS_EXT_EC_POINT_FORMATS ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - 1 + 1, 1 + 1 );
		DEBUG_PRINT_END();
		}

	/* If we're using TLS 1.3 then we have to send back a keyex extension 
	   unless this is a Hello Retry Request pretending to be a Server Hello */
#ifdef USE_TLS13
	if( isTLS13 )
		{
		/* If this is a Hello Retry Request disguised as a Server Hello,
		   we write the group that we expect the client to use rather than
		   any actual keyex data */
		if( handshakeInfo->flags & HANDSHAKE_FLAG_RETRIEDCLIENTHELLO )
			{
			writeExtensionHdr( stream, TLS_EXT_KEY_SHARE, UINT16_SIZE );
			status = writeUint16( stream, TLS_GROUP_SECP256R1 );
			if( cryptStatusError( status ) )
				return( status );
			DEBUG_PRINT_BEGIN();
			DEBUG_PRINT(( "Wrote extension pseudo-keyex for Hello Retry "
						  "Request (%d), length %d.\n", TLS_EXT_KEY_SHARE, 
						  UINT16_SIZE ));
			DEBUG_DUMP_STREAM( stream, stell( stream ) - keyexExtLen, 
							   keyexExtLen );
			DEBUG_PRINT_END();
			}
		else
			{
			/* Write the TLS 1.3 keyex extension */
			writeExtensionHdr( stream, TLS_EXT_KEY_SHARE, keyexExtLen );
			status = writeKeyexTLS13( stream, handshakeInfo, TRUE );
			if( cryptStatusError( status ) )
				return( status );
			DEBUG_PRINT_BEGIN();
			DEBUG_PRINT(( "Wrote extension keyex (%d), length %d.\n",
						  TLS_EXT_KEY_SHARE, keyexExtLen ));
			DEBUG_DUMP_STREAM( stream, stell( stream ) - keyexExtLen, 
							   keyexExtLen );
			DEBUG_PRINT_END();
			}
		}
#endif /* USE_TLS13 */

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
