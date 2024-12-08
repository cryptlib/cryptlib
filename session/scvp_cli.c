<<<<<<< HEAD
/****************************************************************************
*																			*
*						 cryptlib SCVP Client Management					*
*						Copyright Peter Gutmann 2009-2021					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "scvp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "session/session.h"
  #include "session/scvp.h"
#endif /* Compiler-specific includes */

#ifdef USE_SCVP

/* SCVP response status messages */

typedef struct {
	const int scvpStatus;			/* SCVP status code */
	const int status;				/* cryptlib error status */
	const char *string;				/* Descriptive error message */
	const int stringLength;
	} FAILURE_INFO;

static const FAILURE_INFO responseStatusInfo[] = {
	{ SCVP_STATUS_OKAY, CRYPT_OK,
	  "Request was fully processed", 27 },
	{ SCVP_STATUS_SKIPUNRECOGNIZEDITEMS, CRYPT_OK,
	  "Request included unrecognized non-critical extensions, but "
	  "processing was able to continue ignoring them", 100 },
	{ SCVP_STATUS_TOOBUSY, CRYPT_ERROR_TIMEOUT,
	  "Too busy, try again later", 25 },
	{ SCVP_STATUS_INVALIDREQUEST, CRYPT_ERROR_INVALID,
	  "Server was able to decode the request but there was some other "
	  "problem with the request", 87 },
	{ SCVP_STATUS_INTERNALERROR, CRYPT_ERROR_FAILED,
	  "An internal server error occurred", 33 },
	{ SCVP_STATUS_BADSTRUCTURE, CRYPT_ERROR_BADDATA,
	  "Structure of the request was wrong", 34 },
	{ SCVP_STATUS_UNSUPPORTEDVERSION, CRYPT_ERROR_NOTAVAIL,
	  "Request version is not supported by this server", 47 },
	{ SCVP_STATUS_ABORTUNRECOGNIZEDITEMS, CRYPT_ERROR_BADDATA,
	  "Request included unrecognized items", 35 },
	{ SCVP_STATUS_UNRECOGNIZEDSIGKEY, CRYPT_ERROR_WRONGKEY,
	  "Server could not validate the key used to protect the request", 61 },
	{ SCVP_STATUS_BADSIGNATUREORMAC, CRYPT_ERROR_SIGNATURE,
	  "Signature or MAC did not match the body of the request", 54 },
	{ SCVP_STATUS_UNABLETODECODE, CRYPT_ERROR_BADDATA,
	  "Encoding was not understood", 27 },
	{ SCVP_STATUS_NOTAUTHORIZED, CRYPT_ERROR_PERMISSION,
	  "Request was not authorized", 26 },
	{ SCVP_STATUS_UNSUPPORTEDCHECKS, CRYPT_ERROR_NOTAVAIL,
	  "Request included unsupported checks items", 41 },
	{ SCVP_STATUS_UNSUPPORTEDWANTBACKS, CRYPT_ERROR_NOTAVAIL,
	  "Request included unsupported wantBack items", 43 },
	{ SCVP_STATUS_UNSUPPORTEDSIGNATUREORMAC, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support the signature or MAC algorithm used by the "
	  "client", 73 },
	{ SCVP_STATUS_INVALIDSIGNATUREORMAC, CRYPT_ERROR_SIGNATURE,
	  "Server could not validate the client's signature or MAC on the "
	  "request", 70 },
	{ SCVP_STATUS_PROTECTEDRESPONSEUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server could not generate a protected response", 46 },
	{ SCVP_STATUS_UNRECOGNIZEDRESPONDERNAME, CRYPT_ERROR_NOTFOUND,
	  "Server does not have a certificate matching the requested responder "
	  "name", 72 },
	{ SCVP_STATUS_RELAYINGLOOP, CRYPT_ERROR_DUPLICATE,
	  "Request was previously relayed by the same server", 50 },
	{ SCVP_STATUS_UNRECOGNIZEDVALPOL, CRYPT_ERROR_NOTAVAIL,
	  "Request contained an unrecognized validation policy reference", 61 },
	{ SCVP_STATUS_UNRECOGNIZEDVALALG, CRYPT_ERROR_NOTAVAIL,
	  "Request contained an unrecognized validation algorithm", 54 },
	{ SCVP_STATUS_FULLREQUESTINRESPONSEUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support returning the full request in the "
	  "response", 66 },
	{ SCVP_STATUS_FULLPOLRESPONSEUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support returning the full validation policy by "
	  "value in the response", 85 },
	{ SCVP_STATUS_INHIBITPOLICYMAPPINGUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support the requested value for inhibit policy "
	  "mapping", 70 },
	{ SCVP_STATUS_REQUIREEXPLICITPOLICYUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support the requested value for require explicit "
	  "policy", 71 },
	{ SCVP_STATUS_INHIBITANYPOLICYUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support the requested value for inhibit anyPolicy", 
	  65 },
	{ SCVP_STATUS_VALIDATIONTIMEUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server only validates requests using current time", 49 },
	{ SCVP_STATUS_UNRECOGNIZEDCRITQUERYEXT, CRYPT_ERROR_INVALID,
	  "Query item in the request contains a critical extension whose OID "
	  "is not recognized", 83 },
	{ SCVP_STATUS_UNRECOGNIZEDCRITREQUESTEXT, CRYPT_ERROR_INVALID,
	  "Request contains a critical request extension whose OID is not "
	  "recognized", 73 },
	{ CRYPT_ERROR, CRYPT_ERROR, "Unknown SCVP response status", 28 }, 
	{ CRYPT_ERROR, CRYPT_ERROR, "Unknown SCVP response status", 28 }
	};

static const FAILURE_INFO replyStatusInfo[] = {
	{ SCVP_REPLYSTATUS_SUCCESS, CRYPT_OK,
	  "All checks performed successfully", 33 },
	{ SCVP_REPLYSTATUS_MALFORMEDPKC, CRYPT_ERROR_BADDATA,
	  "Public key certificate was malformed", 36 },
	{ SCVP_REPLYSTATUS_MALFORMEDAC, CRYPT_ERROR_BADDATA,
	  "Attribute certificate was malformed", 35 },
	{ SCVP_REPLYSTATUS_UNAVAILABLEVALIDATIONTIME, CRYPT_ERROR_NOTAVAIL,
	  "Historical data for requested validation time is not available", 62 },
	{ SCVP_REPLYSTATUS_REFERENCECERTHASHFAIL, CRYPT_ERROR_NOTFOUND,
	  "Server could not locate reference certificate or referenced "
	  "certificate did not match hash value provided", 105 },
	{ SCVP_REPLYSTATUS_CERTPATHCONSTRUCTFAIL, CRYPT_ERROR_NOTFOUND,
	  "No certification path could be constructed", 42 },
	{ SCVP_REPLYSTATUS_CERTPATHNOTVALID, CRYPT_ERROR_INVALID,
	  "Constructed certification path is not valid with respect to the "
	  "validation policy", 81 },
	{ SCVP_REPLYSTATUS_CERTPATHNOTVALIDNOW, CRYPT_ERROR_INVALID,
	  "Constructed certification path is not valid with respect to the "
	  "validation policy, query at later time may be successful", 120 },
	{ SCVP_REPLYSTATUS_WANTBACKUNSATISFIED, CRYPT_ERROR_NOTFOUND,
	  "All checks were performed successfully, however one or wantBacks "
	  "could not be satisfied", 87 },
	{ CRYPT_ERROR, CRYPT_ERROR, "Unknown SCVP reply status", 25 }, 
	{ CRYPT_ERROR, CRYPT_ERROR, "Unknown SCVP reply status", 25 }
	};

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/****************************************************************************
*																			*
*						Request Management Functions						*
*																			*
****************************************************************************/

/* Write an SCVP request:

	CVRequest ::= SEQUENCE {
		query						SEQUENCE {
			queriedCerts			CertReferences,
			checks					SEQUENCE OF OBJECT IDENTIFIER,
			wantBack			[1]	SEQUENCE OF OBJECT IDENTIFIER OPTIONAL, -- Actually mandatory
			validationPolicy		ValidationPolicy
			},
		hashAlgo				[6]	OBJECT IDENTIFIER		-- If not SHA-1
	} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeScvpRequest( INOUT_PTR STREAM *stream,
							 const SESSION_INFO *sessionInfoPtr,
							 const SCVP_PROTOCOL_INFO *protocolInfo )
	{
	int certRefLength, queryLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );
	
	/* Determine the size of the certificate reference */
	status = certRefLength = sizeofCertRefs( sessionInfoPtr->iCertRequest );
	if( cryptStatusError( status ) )
		return( status );
	queryLength = certRefLength + \
				  sizeofObject( sizeofOID( OID_SCVP_DEFAULTCHECKPOLICY ) ) + \
				  sizeofObject( sizeofOID( OID_SCVP_DEFAULTWANTBACK ) ) + \
				  sizeofValidationPolicy();

	/* Write the request data.  We don't write the outer SEQUENCE since this
	   is added by the enveloping process */
	writeSequence( stream, queryLength );
	status = writeCertRefs( stream, sessionInfoPtr->iCertRequest );
	if( cryptStatusOK( status ) )
		{
		writeSequence( stream, sizeofOID( OID_SCVP_DEFAULTCHECKPOLICY ) );
		writeOID( stream, OID_SCVP_DEFAULTCHECKPOLICY );
		writeConstructed( stream, sizeofOID( OID_SCVP_DEFAULTWANTBACK ), 
						  CTAG_QR_WANTBACK );
		writeOID( stream, OID_SCVP_DEFAULTWANTBACK );
		status = writeValidationPolicy( stream );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the requested hash algorithm information if it's not the 
	   default SHA-1 */
	if( protocolInfo->requestHashAlgo != CRYPT_ALGO_SHA1 )
		{
		ALGOID_PARAMS algoIDparams;

		initAlgoIDparamsHash( &algoIDparams, protocolInfo->requestHashAlgo, 
							  protocolInfo->requestHashSize );
		status = writeAlgoIDex( stream, protocolInfo->requestHashAlgo, 
								&algoIDparams, CTAG_RQ_HASHALG );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Send an SCVP request to the server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sendScvpRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	int status, dataLength DUMMY_INIT;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* If we're fuzzing, there's no request to send out */
	FUZZ_SKIP_REMAINDER();

	/* Create the SCVP request */
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 
			  sessionInfoPtr->receiveBufSize );
	status = writeScvpRequest( &stream, sessionInfoPtr, protocolInfo );
	if( cryptStatusOK( status ) )
		dataLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create SCVP request for '%s'",
				  getCertHolderName( sessionInfoPtr->iCertRequest, 
									 certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	DEBUG_DUMP_FILE( "scvp_req0", sessionInfoPtr->receiveBuffer, dataLength );

	/* Wrap the request in a CMS envelope */
	clearErrorInfo( &localErrorInfo );
	status = envelopeWrap( sessionInfoPtr->receiveBuffer, dataLength,
						   sessionInfoPtr->receiveBuffer, 
						   sessionInfoPtr->receiveBufSize, 
						   &sessionInfoPtr->receiveBufEnd, 
						   CRYPT_FORMAT_CMS, CRYPT_CONTENT_SCVPCERTVALREQUEST, 
						   CRYPT_UNUSED, NULL, 0, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't wrap SCVP request data" ) );
		}
	DEBUG_DUMP_FILE( "scvp_req1", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );

	/* Calculate the request hash and send the request to the server */
	status = calculateRequestHash( protocolInfo, 
								   sessionInfoPtr->receiveBuffer, 
								   sessionInfoPtr->receiveBufEnd );
	if( cryptStatusOK( status ) )
		{
		status = writePkiDatagram( sessionInfoPtr, 
								   SCVP_CONTENTTYPE_REQUEST,
								   SCVP_CONTENTTYPE_REQUEST_LEN,
								   MK_ERRTEXT( "Couldnt send SCVP request "
											   "to server" ) );
		}
	return( status );
	}

/****************************************************************************
*																			*
*						Response Management Functions						*
*																			*
****************************************************************************/

/* Read a response time field and make sure that the value is within a
   sensible range */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processMessageTime( INOUT_PTR STREAM *stream, 
							   INOUT_PTR ERROR_INFO *errorInfo )
	{
	const time_t systemTime = getTime( GETTIME_MINUTES );
	time_t messageTime, delta;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the message time */
	status = readGeneralizedTime( stream, &messageTime );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Couldn't read message time" ) );
		}

	/* If we're fuzzing then the message time won't be anywhere near the
	   actual time */
	FUZZ_SKIP_REMAINDER();

	/* Make sure that the message time is within 24 hours of the system 
	   time */
	delta = ( messageTime > systemTime ) ? \
			messageTime - systemTime : systemTime - messageTime;
	if( delta > 86400 )
		{
		/* The difference between the sender and our time is more than 24 
		   hours, treat it as an error */
		delta /= 60 * 60;	/* Difference in hours */
		if( delta >= 24 * 3 )
			{
			/* Three or more days difference, report it in days */
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Peer system time is %d days out from our system "
					  "time, can't proceed with certificate check "
					  "operation", ( int ) ( delta / 24 ) ) );
			}
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Peer system time is %d hours out from our system "
				  "time, can't proceed with certificate check operation", 
				  ( int ) delta ) );
		}

	return( CRYPT_OK );
	}

/* Read the responseStatus/replyStatus fields */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readResponseStatus( INOUT_PTR STREAM *stream, 
							   INOUT_PTR ERROR_INFO *errorInfo )
	{
	const FAILURE_INFO *responseStatusInfoPtr = NULL;
	int value, i, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the response status value.  A value of SCVP_STATUS_OKAY...9 is 
	   an OK status, anything else is an error */
	readSequence( stream, NULL );
	status = readEnumerated( stream, &value );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				   ( status, errorInfo,
					 "Couldn't read response status" ) );
		}
	if( value >= SCVP_STATUS_OKAY && value <= 9 )
		return( CRYPT_OK );

	/* It's an error status, convert it into an error message */
	LOOP_MED( i = 0,
			  i < FAILSAFE_ARRAYSIZE( responseStatusInfo, FAILURE_INFO ) && \
				  responseStatusInfo[ i ].scvpStatus != CRYPT_ERROR,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( responseStatusInfo, \
														 FAILURE_INFO ) - 1 ) );

		if( responseStatusInfo[ i ].scvpStatus == value )
			{
			responseStatusInfoPtr = &responseStatusInfo[ i ];
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( responseStatusInfo, FAILURE_INFO ) );
	if( responseStatusInfoPtr == NULL )
		{
		retExt( CRYPT_ERROR_FAILED,
				( CRYPT_ERROR_FAILED, errorInfo, 
				  "Server returned response status %d: Unknown SCVP "
				  "response status", value ) );
		}

	retExt( responseStatusInfoPtr->status,
			( responseStatusInfoPtr->status, errorInfo, 
			  "Server returned response status %d: %s", value, 
			  responseStatusInfoPtr->string ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readReplyStatus( INOUT_PTR STREAM *stream, 
							INOUT_PTR ERROR_INFO *errorInfo )
	{
	const FAILURE_INFO *replyStatusInfoPtr = NULL;
	int value, i, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the reply status value */
	status = readEnumerated( stream, &value );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				   ( status, errorInfo,
					 "Couldn't read reply status" ) );
		}
	if( value == SCVP_REPLYSTATUS_SUCCESS )
		return( CRYPT_OK );

	/* It's an error status, convert it into an error message */
	LOOP_MED( i = 0,
			  i < FAILSAFE_ARRAYSIZE( replyStatusInfo, FAILURE_INFO ) && \
				  replyStatusInfo[ i ].scvpStatus != CRYPT_ERROR,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( replyStatusInfo, \
														 FAILURE_INFO ) - 1 ) );

		if( replyStatusInfo[ i ].scvpStatus == value )
			{
			replyStatusInfoPtr = &replyStatusInfo[ i ];
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( replyStatusInfo, FAILURE_INFO ) );
	if( replyStatusInfoPtr == NULL )
		{
		retExt( CRYPT_ERROR_FAILED,
				( CRYPT_ERROR_FAILED, errorInfo, 
				  "Server returned reply status %d: Unknown SCVP reply "
				  "status", value ) );
		}

	retExt( replyStatusInfoPtr->status,
			( replyStatusInfoPtr->status, errorInfo, 
			  "Server returned reply status %d: %s", value, 
			  replyStatusInfoPtr->string ) );
	}

/* Read the requestRef field.  This misnamed field contains a hash of the 
   request that we sent as it was received by the server, used to detect
   manipulation of the unauthenticated request data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readRequestRef( INOUT_PTR STREAM *stream, 
						   INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
						   INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_ALGO_TYPE hashAlgo = CRYPT_ALGO_SHA1;
	ALGOID_PARAMS algoIDparams;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	int tag, hashValueSize DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the wrapper, optional request hash specifier, and hash value */
	initAlgoIDparams( &algoIDparams );
	readConstructed( stream, NULL, CTAG_RP_REQUESTREF );
	status = readConstructed( stream, NULL, CTAG_RR_REQUESTHASH );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == BER_SEQUENCE )
		{
		status = readAlgoIDex( stream, &hashAlgo, &algoIDparams,
							   ALGOID_CLASS_HASH );
		}
	if( !cryptStatusError( status ) )
		{
		status = readOctetString( stream, hashValue, &hashValueSize, 
								  16, CRYPT_MAX_HASHSIZE );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read request reference" ) );
		}
	FUZZ_SKIP_REMAINDER();
	if( hashAlgo != protocolInfo->requestHashAlgo )
		{
		retExt( status,
				( status, errorInfo, 
				  "Requested request hash algorithm %d (%s), "
				  "server sent %d (%s)", protocolInfo->requestHashAlgo,
				  getAlgoName( protocolInfo->requestHashAlgo ),
				  hashAlgo, getAlgoName( hashAlgo ) ) );
		}

	/* Make sure that the request hash matches the returned value */
	if( protocolInfo->requestHashSize != algoIDparams.hashParam || \
		protocolInfo->requestHashSize != hashValueSize || \
		memcmp( protocolInfo->requestHash, hashValue, hashValueSize ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Hash value of request doesn't match server's returned "
				  "request reference" ) );
		}

	return( CRYPT_OK );
	}

/* Read the replyObjects field */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readReplyObjects( INOUT_PTR STREAM *stream, 
							 INOUT_PTR ERROR_INFO *errorInfo )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Skip the certReference, which we already know since we've just sent 
	   it in the request */
	status = readUniversal( stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read reply certificate reference" ) );
		}

	/* Read the reply status */
	status = readReplyStatus( stream, errorInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Read another message time with the same check as before */
	status = processMessageTime( stream, errorInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* A lot more stuff follows, at the moment we can't do anything with it 
	   so we skip it */
	status = readUniversal( stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read reply checks" ) );
		}
	status = readUniversal( stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read reply wantbacks" ) );
		}

	return( CRYPT_OK );
	}

/* Read an SCVP response:

	CVResponse ::= SEQUENCE {
		cvResponseVersion			INTEGER,
		serverConfigurationID		INTEGER,
		producedAt					GeneralizedTime,
		responseStatus				SEQUENCE {
			cvStatusCode			ENUMERATED { ... } DEFAULT okay,
			},
		respValidationPolicy	[0]	... OPTIONAL,		-- Ignored
		requestRef				[1]	EXPLICIT [0] SEQUENCE {
			algorithm				AlgorithmIdentifier DEFAULT SHA-1,
			value					OCTET STRING
			} OPTIONAL,
		requestorRef			[2]	... OPTIONAL,		-- Ignored
		requestorName			[3]	... OPTIONAL,		-- Ignored
		replyObjects			[4] SEQUENCE OF SEQUENCE {
			cert					CertReference,		-- NB not CertReferences
			replyStatus				ENUMERATED { ... } DEFAULT success,
			replyValTime			GeneralizedTime,
			replyChecks				SEQUENCE OF SEQUENCE {
				check				OBJECT IDENTIFIER,
				status				INTEGER DEFAULT 0
				},
			replyWantBacks			SEQUENCE OF SEQUENCE {
				wb					OBJECT IDENTIFIER,
				value				OCTET STRING
				},
			validationErrors	[0]	... OPTIONAL,
			nextUpdate			[1]	GeneralizedTime OPTIONAL,
			certReplyExtensions	[2]	Extensions OPTIONAL 
			} OPTIONAL,									-- Mandatory
		respNonce				[5]	... OPTIONAL,	-- Ignored
		serverContextInfo		[6]	... OPTIONAL,	-- Ignored
		cvResponseExtensions	[7]	... OPTIONAL,	-- Ignored
		requestorText			[8]	... OPTIONAL	-- Ignored
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readScvpResponse( INOUT_PTR STREAM *stream,
							 INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	long value;
	int tag, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	/* Skip the wrapper, version, and server configuration ID */
	readSequence( stream, NULL );
	readShortInteger( stream, &value );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		{
		retExt( status,
			   ( status, SESSION_ERRINFO, 
				 "Couldn't read version information" ) );
		}

	/* Read the message time and make sure that it's within range of our 
	   time */
	status = processMessageTime( stream, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the response status, one of two status values returned in the 
	   response.  This one is for the overall response, for example 
	   invalidRequest, rather than for the certificate reply contained in 
	   the response */
	status = readResponseStatus( stream, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* Skip the response validation policy if it's present */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_RP_RESPVALIDATIONPOLICY ) )
		{
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Couldn't read response validation policy" ) );
			}
		}

	/* Check the requestRef if it's present.  This is used to detect 
	   manipulation of the client's request, which goes out 
	   unauthenticated */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_RP_REQUESTREF ) )
		{
		status = readRequestRef( stream, protocolInfo, SESSION_ERRINFO );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Skip further noise if it's present */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_RP_REQUESTORREF ) )
		status = readUniversal( stream );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_RP_REQUESTORNAME ) )
		status = readUniversal( stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't read requestor reference or name" ) );
		}

	/* Read the reply objects, another optional-but-mandatory field */	
	readConstructed( stream, &length, CTAG_RP_REPLYOBJECTS );
	status = readSequence( stream, NULL );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't read reply objects wrapper" ) );
		}
	status = readReplyObjects( stream, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* Even more fields follow, but at the moment there's nothing much that 
	   we can do with them */

	return( CRYPT_OK );
	}

/* Check a SCVP response message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkScvpResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							  INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	ERROR_INFO localErrorInfo;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* Unwrap the response from its CMS envelope */
	DEBUG_DUMP_FILE( "scvp_resp1", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );
	clearErrorInfo( &localErrorInfo );
	status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, 
							 sessionInfoPtr->receiveBufEnd,
							 sessionInfoPtr->receiveBuffer, 
							 sessionInfoPtr->receiveBufSize, &dataLength, 
							 CRYPT_UNUSED, NULL, 0, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		registerCryptoFailure();
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't unwrap CMS enveloped data in SCVP "
					 "response" ) );
		}
	CFI_CHECK_UPDATE( "envelopeUnwrap" );
	DEBUG_DUMP_FILE( "scvp_resp0", sessionInfoPtr->receiveBuffer, 
					 dataLength );

	/* Check the SCVP response */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, dataLength );
	status = readScvpResponse( &stream, sessionInfoPtr, protocolInfo );
	sMemDisconnect( &stream );
	CFI_CHECK_UPDATE( "readScvpResponse" );

	ENSURES( CFI_CHECK_SEQUENCE_2( "envelopeUnwrap", "readScvpResponse" ) );

	return( status );
	}

/****************************************************************************
*																			*
*							SCVP Client Functions							*
*																			*
****************************************************************************/

/* Exchange data with a SCVP server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientTransact( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	SCVP_PROTOCOL_INFO protocolInfo;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* Initialise the client-side protocol state information */
	status = initSCVPprotocolInfo( &protocolInfo, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Request certificate status information from the server */
	status = sendScvpRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "createScvpRequest" );

	/* Read back the response certificate from the server */
	status = readPkiDatagram( sessionInfoPtr, MIN_CRYPT_OBJECTSIZE,
							  MK_ERRTEXT( "Couldnt read SCVP server "
										  "response" ) );
	if( cryptStatusOK( status ) )
		status = checkScvpResponse( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkScvpResponse" );

	ENSURES( CFI_CHECK_SEQUENCE_2( "createScvpRequest", 
								   "checkScvpResponse" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initSCVPclientProcessing( SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	FNPTR_SET( sessionInfoPtr->transactFunction, clientTransact );
	}
#endif /* USE_SCVP */
=======
/****************************************************************************
*																			*
*						 cryptlib SCVP Client Management					*
*						Copyright Peter Gutmann 2009-2021					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "scvp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "session/session.h"
  #include "session/scvp.h"
#endif /* Compiler-specific includes */

#ifdef USE_SCVP

/* SCVP response status messages */

typedef struct {
	const int scvpStatus;			/* SCVP status code */
	const int status;				/* cryptlib error status */
	const char *string;				/* Descriptive error message */
	const int stringLength;
	} FAILURE_INFO;

static const FAILURE_INFO responseStatusInfo[] = {
	{ SCVP_STATUS_OKAY, CRYPT_OK,
	  "Request was fully processed", 27 },
	{ SCVP_STATUS_SKIPUNRECOGNIZEDITEMS, CRYPT_OK,
	  "Request included unrecognized non-critical extensions, but "
	  "processing was able to continue ignoring them", 100 },
	{ SCVP_STATUS_TOOBUSY, CRYPT_ERROR_TIMEOUT,
	  "Too busy, try again later", 25 },
	{ SCVP_STATUS_INVALIDREQUEST, CRYPT_ERROR_INVALID,
	  "Server was able to decode the request but there was some other "
	  "problem with the request", 87 },
	{ SCVP_STATUS_INTERNALERROR, CRYPT_ERROR_FAILED,
	  "An internal server error occurred", 33 },
	{ SCVP_STATUS_BADSTRUCTURE, CRYPT_ERROR_BADDATA,
	  "Structure of the request was wrong", 34 },
	{ SCVP_STATUS_UNSUPPORTEDVERSION, CRYPT_ERROR_NOTAVAIL,
	  "Request version is not supported by this server", 47 },
	{ SCVP_STATUS_ABORTUNRECOGNIZEDITEMS, CRYPT_ERROR_BADDATA,
	  "Request included unrecognized items", 35 },
	{ SCVP_STATUS_UNRECOGNIZEDSIGKEY, CRYPT_ERROR_WRONGKEY,
	  "Server could not validate the key used to protect the request", 61 },
	{ SCVP_STATUS_BADSIGNATUREORMAC, CRYPT_ERROR_SIGNATURE,
	  "Signature or MAC did not match the body of the request", 54 },
	{ SCVP_STATUS_UNABLETODECODE, CRYPT_ERROR_BADDATA,
	  "Encoding was not understood", 27 },
	{ SCVP_STATUS_NOTAUTHORIZED, CRYPT_ERROR_PERMISSION,
	  "Request was not authorized", 26 },
	{ SCVP_STATUS_UNSUPPORTEDCHECKS, CRYPT_ERROR_NOTAVAIL,
	  "Request included unsupported checks items", 41 },
	{ SCVP_STATUS_UNSUPPORTEDWANTBACKS, CRYPT_ERROR_NOTAVAIL,
	  "Request included unsupported wantBack items", 43 },
	{ SCVP_STATUS_UNSUPPORTEDSIGNATUREORMAC, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support the signature or MAC algorithm used by the "
	  "client", 73 },
	{ SCVP_STATUS_INVALIDSIGNATUREORMAC, CRYPT_ERROR_SIGNATURE,
	  "Server could not validate the client's signature or MAC on the "
	  "request", 70 },
	{ SCVP_STATUS_PROTECTEDRESPONSEUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server could not generate a protected response", 46 },
	{ SCVP_STATUS_UNRECOGNIZEDRESPONDERNAME, CRYPT_ERROR_NOTFOUND,
	  "Server does not have a certificate matching the requested responder "
	  "name", 72 },
	{ SCVP_STATUS_RELAYINGLOOP, CRYPT_ERROR_DUPLICATE,
	  "Request was previously relayed by the same server", 50 },
	{ SCVP_STATUS_UNRECOGNIZEDVALPOL, CRYPT_ERROR_NOTAVAIL,
	  "Request contained an unrecognized validation policy reference", 61 },
	{ SCVP_STATUS_UNRECOGNIZEDVALALG, CRYPT_ERROR_NOTAVAIL,
	  "Request contained an unrecognized validation algorithm", 54 },
	{ SCVP_STATUS_FULLREQUESTINRESPONSEUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support returning the full request in the "
	  "response", 66 },
	{ SCVP_STATUS_FULLPOLRESPONSEUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support returning the full validation policy by "
	  "value in the response", 85 },
	{ SCVP_STATUS_INHIBITPOLICYMAPPINGUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support the requested value for inhibit policy "
	  "mapping", 70 },
	{ SCVP_STATUS_REQUIREEXPLICITPOLICYUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support the requested value for require explicit "
	  "policy", 71 },
	{ SCVP_STATUS_INHIBITANYPOLICYUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server does not support the requested value for inhibit anyPolicy", 
	  65 },
	{ SCVP_STATUS_VALIDATIONTIMEUNSUPPORTED, CRYPT_ERROR_NOTAVAIL,
	  "Server only validates requests using current time", 49 },
	{ SCVP_STATUS_UNRECOGNIZEDCRITQUERYEXT, CRYPT_ERROR_INVALID,
	  "Query item in the request contains a critical extension whose OID "
	  "is not recognized", 83 },
	{ SCVP_STATUS_UNRECOGNIZEDCRITREQUESTEXT, CRYPT_ERROR_INVALID,
	  "Request contains a critical request extension whose OID is not "
	  "recognized", 73 },
	{ CRYPT_ERROR, CRYPT_ERROR, "Unknown SCVP response status", 28 }, 
	{ CRYPT_ERROR, CRYPT_ERROR, "Unknown SCVP response status", 28 }
	};

static const FAILURE_INFO replyStatusInfo[] = {
	{ SCVP_REPLYSTATUS_SUCCESS, CRYPT_OK,
	  "All checks performed successfully", 33 },
	{ SCVP_REPLYSTATUS_MALFORMEDPKC, CRYPT_ERROR_BADDATA,
	  "Public key certificate was malformed", 36 },
	{ SCVP_REPLYSTATUS_MALFORMEDAC, CRYPT_ERROR_BADDATA,
	  "Attribute certificate was malformed", 35 },
	{ SCVP_REPLYSTATUS_UNAVAILABLEVALIDATIONTIME, CRYPT_ERROR_NOTAVAIL,
	  "Historical data for requested validation time is not available", 62 },
	{ SCVP_REPLYSTATUS_REFERENCECERTHASHFAIL, CRYPT_ERROR_NOTFOUND,
	  "Server could not locate reference certificate or referenced "
	  "certificate did not match hash value provided", 105 },
	{ SCVP_REPLYSTATUS_CERTPATHCONSTRUCTFAIL, CRYPT_ERROR_NOTFOUND,
	  "No certification path could be constructed", 42 },
	{ SCVP_REPLYSTATUS_CERTPATHNOTVALID, CRYPT_ERROR_INVALID,
	  "Constructed certification path is not valid with respect to the "
	  "validation policy", 81 },
	{ SCVP_REPLYSTATUS_CERTPATHNOTVALIDNOW, CRYPT_ERROR_INVALID,
	  "Constructed certification path is not valid with respect to the "
	  "validation policy, query at later time may be successful", 120 },
	{ SCVP_REPLYSTATUS_WANTBACKUNSATISFIED, CRYPT_ERROR_NOTFOUND,
	  "All checks were performed successfully, however one or wantBacks "
	  "could not be satisfied", 87 },
	{ CRYPT_ERROR, CRYPT_ERROR, "Unknown SCVP reply status", 25 }, 
	{ CRYPT_ERROR, CRYPT_ERROR, "Unknown SCVP reply status", 25 }
	};

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/****************************************************************************
*																			*
*						Request Management Functions						*
*																			*
****************************************************************************/

/* Write an SCVP request:

	CVRequest ::= SEQUENCE {
		query						SEQUENCE {
			queriedCerts			CertReferences,
			checks					SEQUENCE OF OBJECT IDENTIFIER,
			wantBack			[1]	SEQUENCE OF OBJECT IDENTIFIER OPTIONAL, -- Actually mandatory
			validationPolicy		ValidationPolicy
			},
		hashAlgo				[6]	OBJECT IDENTIFIER		-- If not SHA-1
	} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeScvpRequest( INOUT_PTR STREAM *stream,
							 const SESSION_INFO *sessionInfoPtr,
							 const SCVP_PROTOCOL_INFO *protocolInfo )
	{
	int certRefLength, queryLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );
	
	/* Determine the size of the certificate reference */
	status = certRefLength = sizeofCertRefs( sessionInfoPtr->iCertRequest );
	if( cryptStatusError( status ) )
		return( status );
	queryLength = certRefLength + \
				  sizeofObject( sizeofOID( OID_SCVP_DEFAULTCHECKPOLICY ) ) + \
				  sizeofObject( sizeofOID( OID_SCVP_DEFAULTWANTBACK ) ) + \
				  sizeofValidationPolicy();

	/* Write the request data.  We don't write the outer SEQUENCE since this
	   is added by the enveloping process */
	writeSequence( stream, queryLength );
	status = writeCertRefs( stream, sessionInfoPtr->iCertRequest );
	if( cryptStatusOK( status ) )
		{
		writeSequence( stream, sizeofOID( OID_SCVP_DEFAULTCHECKPOLICY ) );
		writeOID( stream, OID_SCVP_DEFAULTCHECKPOLICY );
		writeConstructed( stream, sizeofOID( OID_SCVP_DEFAULTWANTBACK ), 
						  CTAG_QR_WANTBACK );
		writeOID( stream, OID_SCVP_DEFAULTWANTBACK );
		status = writeValidationPolicy( stream );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the requested hash algorithm information if it's not the 
	   default SHA-1 */
	if( protocolInfo->requestHashAlgo != CRYPT_ALGO_SHA1 )
		{
		ALGOID_PARAMS algoIDparams;

		initAlgoIDparamsHash( &algoIDparams, protocolInfo->requestHashAlgo, 
							  protocolInfo->requestHashSize );
		status = writeAlgoIDex( stream, protocolInfo->requestHashAlgo, 
								&algoIDparams, CTAG_RQ_HASHALG );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Send an SCVP request to the server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sendScvpRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	int status, dataLength DUMMY_INIT;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* If we're fuzzing, there's no request to send out */
	FUZZ_SKIP_REMAINDER();

	/* Create the SCVP request */
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 
			  sessionInfoPtr->receiveBufSize );
	status = writeScvpRequest( &stream, sessionInfoPtr, protocolInfo );
	if( cryptStatusOK( status ) )
		dataLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create SCVP request for '%s'",
				  getCertHolderName( sessionInfoPtr->iCertRequest, 
									 certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	DEBUG_DUMP_FILE( "scvp_req0", sessionInfoPtr->receiveBuffer, dataLength );

	/* Wrap the request in a CMS envelope */
	clearErrorInfo( &localErrorInfo );
	status = envelopeWrap( sessionInfoPtr->receiveBuffer, dataLength,
						   sessionInfoPtr->receiveBuffer, 
						   sessionInfoPtr->receiveBufSize, 
						   &sessionInfoPtr->receiveBufEnd, 
						   CRYPT_FORMAT_CMS, CRYPT_CONTENT_SCVPCERTVALREQUEST, 
						   CRYPT_UNUSED, NULL, 0, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't wrap SCVP request data" ) );
		}
	DEBUG_DUMP_FILE( "scvp_req1", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );

	/* Calculate the request hash and send the request to the server */
	status = calculateRequestHash( protocolInfo, 
								   sessionInfoPtr->receiveBuffer, 
								   sessionInfoPtr->receiveBufEnd );
	if( cryptStatusOK( status ) )
		{
		status = writePkiDatagram( sessionInfoPtr, 
								   SCVP_CONTENTTYPE_REQUEST,
								   SCVP_CONTENTTYPE_REQUEST_LEN,
								   MK_ERRTEXT( "Couldnt send SCVP request "
											   "to server" ) );
		}
	return( status );
	}

/****************************************************************************
*																			*
*						Response Management Functions						*
*																			*
****************************************************************************/

/* Read a response time field and make sure that the value is within a
   sensible range */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processMessageTime( INOUT_PTR STREAM *stream, 
							   INOUT_PTR ERROR_INFO *errorInfo )
	{
	const time_t systemTime = getTime( GETTIME_MINUTES );
	time_t messageTime, delta;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the message time */
	status = readGeneralizedTime( stream, &messageTime );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Couldn't read message time" ) );
		}

	/* If we're fuzzing then the message time won't be anywhere near the
	   actual time */
	FUZZ_SKIP_REMAINDER();

	/* Make sure that the message time is within 24 hours of the system 
	   time */
	delta = ( messageTime > systemTime ) ? \
			messageTime - systemTime : systemTime - messageTime;
	if( delta > 86400 )
		{
		/* The difference between the sender and our time is more than 24 
		   hours, treat it as an error */
		delta /= 60 * 60;	/* Difference in hours */
		if( delta >= 24 * 3 )
			{
			/* Three or more days difference, report it in days */
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Peer system time is %d days out from our system "
					  "time, can't proceed with certificate check "
					  "operation", ( int ) ( delta / 24 ) ) );
			}
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Peer system time is %d hours out from our system "
				  "time, can't proceed with certificate check operation", 
				  ( int ) delta ) );
		}

	return( CRYPT_OK );
	}

/* Read the responseStatus/replyStatus fields */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readResponseStatus( INOUT_PTR STREAM *stream, 
							   INOUT_PTR ERROR_INFO *errorInfo )
	{
	const FAILURE_INFO *responseStatusInfoPtr = NULL;
	int value, i, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the response status value.  A value of SCVP_STATUS_OKAY...9 is 
	   an OK status, anything else is an error */
	readSequence( stream, NULL );
	status = readEnumerated( stream, &value );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				   ( status, errorInfo,
					 "Couldn't read response status" ) );
		}
	if( value >= SCVP_STATUS_OKAY && value <= 9 )
		return( CRYPT_OK );

	/* It's an error status, convert it into an error message */
	LOOP_MED( i = 0,
			  i < FAILSAFE_ARRAYSIZE( responseStatusInfo, FAILURE_INFO ) && \
				  responseStatusInfo[ i ].scvpStatus != CRYPT_ERROR,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( responseStatusInfo, \
														 FAILURE_INFO ) - 1 ) );

		if( responseStatusInfo[ i ].scvpStatus == value )
			{
			responseStatusInfoPtr = &responseStatusInfo[ i ];
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( responseStatusInfo, FAILURE_INFO ) );
	if( responseStatusInfoPtr == NULL )
		{
		retExt( CRYPT_ERROR_FAILED,
				( CRYPT_ERROR_FAILED, errorInfo, 
				  "Server returned response status %d: Unknown SCVP "
				  "response status", value ) );
		}

	retExt( responseStatusInfoPtr->status,
			( responseStatusInfoPtr->status, errorInfo, 
			  "Server returned response status %d: %s", value, 
			  responseStatusInfoPtr->string ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readReplyStatus( INOUT_PTR STREAM *stream, 
							INOUT_PTR ERROR_INFO *errorInfo )
	{
	const FAILURE_INFO *replyStatusInfoPtr = NULL;
	int value, i, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the reply status value */
	status = readEnumerated( stream, &value );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				   ( status, errorInfo,
					 "Couldn't read reply status" ) );
		}
	if( value == SCVP_REPLYSTATUS_SUCCESS )
		return( CRYPT_OK );

	/* It's an error status, convert it into an error message */
	LOOP_MED( i = 0,
			  i < FAILSAFE_ARRAYSIZE( replyStatusInfo, FAILURE_INFO ) && \
				  replyStatusInfo[ i ].scvpStatus != CRYPT_ERROR,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( replyStatusInfo, \
														 FAILURE_INFO ) - 1 ) );

		if( replyStatusInfo[ i ].scvpStatus == value )
			{
			replyStatusInfoPtr = &replyStatusInfo[ i ];
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( replyStatusInfo, FAILURE_INFO ) );
	if( replyStatusInfoPtr == NULL )
		{
		retExt( CRYPT_ERROR_FAILED,
				( CRYPT_ERROR_FAILED, errorInfo, 
				  "Server returned reply status %d: Unknown SCVP reply "
				  "status", value ) );
		}

	retExt( replyStatusInfoPtr->status,
			( replyStatusInfoPtr->status, errorInfo, 
			  "Server returned reply status %d: %s", value, 
			  replyStatusInfoPtr->string ) );
	}

/* Read the requestRef field.  This misnamed field contains a hash of the 
   request that we sent as it was received by the server, used to detect
   manipulation of the unauthenticated request data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readRequestRef( INOUT_PTR STREAM *stream, 
						   INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
						   INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_ALGO_TYPE hashAlgo = CRYPT_ALGO_SHA1;
	ALGOID_PARAMS algoIDparams;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	int tag, hashValueSize DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the wrapper, optional request hash specifier, and hash value */
	initAlgoIDparams( &algoIDparams );
	readConstructed( stream, NULL, CTAG_RP_REQUESTREF );
	status = readConstructed( stream, NULL, CTAG_RR_REQUESTHASH );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == BER_SEQUENCE )
		{
		status = readAlgoIDex( stream, &hashAlgo, &algoIDparams,
							   ALGOID_CLASS_HASH );
		}
	if( !cryptStatusError( status ) )
		{
		status = readOctetString( stream, hashValue, &hashValueSize, 
								  16, CRYPT_MAX_HASHSIZE );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read request reference" ) );
		}
	FUZZ_SKIP_REMAINDER();
	if( hashAlgo != protocolInfo->requestHashAlgo )
		{
		retExt( status,
				( status, errorInfo, 
				  "Requested request hash algorithm %d (%s), "
				  "server sent %d (%s)", protocolInfo->requestHashAlgo,
				  getAlgoName( protocolInfo->requestHashAlgo ),
				  hashAlgo, getAlgoName( hashAlgo ) ) );
		}

	/* Make sure that the request hash matches the returned value */
	if( protocolInfo->requestHashSize != algoIDparams.hashParam || \
		protocolInfo->requestHashSize != hashValueSize || \
		memcmp( protocolInfo->requestHash, hashValue, hashValueSize ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Hash value of request doesn't match server's returned "
				  "request reference" ) );
		}

	return( CRYPT_OK );
	}

/* Read the replyObjects field */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readReplyObjects( INOUT_PTR STREAM *stream, 
							 INOUT_PTR ERROR_INFO *errorInfo )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Skip the certReference, which we already know since we've just sent 
	   it in the request */
	status = readUniversal( stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read reply certificate reference" ) );
		}

	/* Read the reply status */
	status = readReplyStatus( stream, errorInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Read another message time with the same check as before */
	status = processMessageTime( stream, errorInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* A lot more stuff follows, at the moment we can't do anything with it 
	   so we skip it */
	status = readUniversal( stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read reply checks" ) );
		}
	status = readUniversal( stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Couldn't read reply wantbacks" ) );
		}

	return( CRYPT_OK );
	}

/* Read an SCVP response:

	CVResponse ::= SEQUENCE {
		cvResponseVersion			INTEGER,
		serverConfigurationID		INTEGER,
		producedAt					GeneralizedTime,
		responseStatus				SEQUENCE {
			cvStatusCode			ENUMERATED { ... } DEFAULT okay,
			},
		respValidationPolicy	[0]	... OPTIONAL,		-- Ignored
		requestRef				[1]	EXPLICIT [0] SEQUENCE {
			algorithm				AlgorithmIdentifier DEFAULT SHA-1,
			value					OCTET STRING
			} OPTIONAL,
		requestorRef			[2]	... OPTIONAL,		-- Ignored
		requestorName			[3]	... OPTIONAL,		-- Ignored
		replyObjects			[4] SEQUENCE OF SEQUENCE {
			cert					CertReference,		-- NB not CertReferences
			replyStatus				ENUMERATED { ... } DEFAULT success,
			replyValTime			GeneralizedTime,
			replyChecks				SEQUENCE OF SEQUENCE {
				check				OBJECT IDENTIFIER,
				status				INTEGER DEFAULT 0
				},
			replyWantBacks			SEQUENCE OF SEQUENCE {
				wb					OBJECT IDENTIFIER,
				value				OCTET STRING
				},
			validationErrors	[0]	... OPTIONAL,
			nextUpdate			[1]	GeneralizedTime OPTIONAL,
			certReplyExtensions	[2]	Extensions OPTIONAL 
			} OPTIONAL,									-- Mandatory
		respNonce				[5]	... OPTIONAL,	-- Ignored
		serverContextInfo		[6]	... OPTIONAL,	-- Ignored
		cvResponseExtensions	[7]	... OPTIONAL,	-- Ignored
		requestorText			[8]	... OPTIONAL	-- Ignored
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readScvpResponse( INOUT_PTR STREAM *stream,
							 INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	long value;
	int tag, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	/* Skip the wrapper, version, and server configuration ID */
	readSequence( stream, NULL );
	readShortInteger( stream, &value );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		{
		retExt( status,
			   ( status, SESSION_ERRINFO, 
				 "Couldn't read version information" ) );
		}

	/* Read the message time and make sure that it's within range of our 
	   time */
	status = processMessageTime( stream, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the response status, one of two status values returned in the 
	   response.  This one is for the overall response, for example 
	   invalidRequest, rather than for the certificate reply contained in 
	   the response */
	status = readResponseStatus( stream, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* Skip the response validation policy if it's present */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_RP_RESPVALIDATIONPOLICY ) )
		{
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Couldn't read response validation policy" ) );
			}
		}

	/* Check the requestRef if it's present.  This is used to detect 
	   manipulation of the client's request, which goes out 
	   unauthenticated */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_RP_REQUESTREF ) )
		{
		status = readRequestRef( stream, protocolInfo, SESSION_ERRINFO );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Skip further noise if it's present */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_RP_REQUESTORREF ) )
		status = readUniversal( stream );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_RP_REQUESTORNAME ) )
		status = readUniversal( stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't read requestor reference or name" ) );
		}

	/* Read the reply objects, another optional-but-mandatory field */	
	readConstructed( stream, &length, CTAG_RP_REPLYOBJECTS );
	status = readSequence( stream, NULL );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't read reply objects wrapper" ) );
		}
	status = readReplyObjects( stream, SESSION_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );

	/* Even more fields follow, but at the moment there's nothing much that 
	   we can do with them */

	return( CRYPT_OK );
	}

/* Check a SCVP response message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkScvpResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							  INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	ERROR_INFO localErrorInfo;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* Unwrap the response from its CMS envelope */
	DEBUG_DUMP_FILE( "scvp_resp1", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );
	clearErrorInfo( &localErrorInfo );
	status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, 
							 sessionInfoPtr->receiveBufEnd,
							 sessionInfoPtr->receiveBuffer, 
							 sessionInfoPtr->receiveBufSize, &dataLength, 
							 CRYPT_UNUSED, NULL, 0, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		registerCryptoFailure();
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't unwrap CMS enveloped data in SCVP "
					 "response" ) );
		}
	CFI_CHECK_UPDATE( "envelopeUnwrap" );
	DEBUG_DUMP_FILE( "scvp_resp0", sessionInfoPtr->receiveBuffer, 
					 dataLength );

	/* Check the SCVP response */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, dataLength );
	status = readScvpResponse( &stream, sessionInfoPtr, protocolInfo );
	sMemDisconnect( &stream );
	CFI_CHECK_UPDATE( "readScvpResponse" );

	ENSURES( CFI_CHECK_SEQUENCE_2( "envelopeUnwrap", "readScvpResponse" ) );

	return( status );
	}

/****************************************************************************
*																			*
*							SCVP Client Functions							*
*																			*
****************************************************************************/

/* Exchange data with a SCVP server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientTransact( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	SCVP_PROTOCOL_INFO protocolInfo;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* Initialise the client-side protocol state information */
	status = initSCVPprotocolInfo( &protocolInfo, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Request certificate status information from the server */
	status = sendScvpRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "createScvpRequest" );

	/* Read back the response certificate from the server */
	status = readPkiDatagram( sessionInfoPtr, MIN_CRYPT_OBJECTSIZE,
							  MK_ERRTEXT( "Couldnt read SCVP server "
										  "response" ) );
	if( cryptStatusOK( status ) )
		status = checkScvpResponse( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkScvpResponse" );

	ENSURES( CFI_CHECK_SEQUENCE_2( "createScvpRequest", 
								   "checkScvpResponse" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initSCVPclientProcessing( SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	FNPTR_SET( sessionInfoPtr->transactFunction, clientTransact );
	}
#endif /* USE_SCVP */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
