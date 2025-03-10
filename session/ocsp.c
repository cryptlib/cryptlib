/****************************************************************************
*																			*
*						 cryptlib OCSP Session Management					*
*						Copyright Peter Gutmann 1999-2019					*
*																			*
****************************************************************************/

#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_OCSP

/* OCSP HTTP content types */

#define OCSP_CONTENT_TYPE_REQ		"application/ocsp-request"
#define OCSP_CONTENT_TYPE_REQ_LEN	24
#define OCSP_CONTENT_TYPE_RESP		"application/ocsp-response"
#define OCSP_CONTENT_TYPE_RESP_LEN	25

/* OCSP query/response types */

typedef enum {
	OCSPRESPONSE_TYPE_NONE,				/* No response type */
	OCSPRESPONSE_TYPE_OCSP,				/* OCSP standard response */
	OCSPRESPONSE_TYPE_LAST				/* Last valid response type */
	} OCSPRESPONSE_TYPE;

/* OCSP response status values */

enum { OCSP_RESP_SUCCESSFUL, OCSP_RESP_MALFORMEDREQUEST,
	   OCSP_RESP_INTERNALERROR, OCSP_RESP_TRYLATER, OCSP_RESP_DUMMY,
	   OCSP_RESP_SIGREQUIRED, OCSP_RESP_UNAUTHORISED };

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Deliver an Einladung betreff Kehrseite to the client.  We don't bother
   checking the return value since there's nothing that we can do in the
   case of an error except close the connection, which we do anyway since
   this is the last message */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void sendErrorResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   IN_BUFFER( responseDataLength ) \
									const void *responseData,
							   IN_LENGTH_SHORT const int responseDataLength )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( responseData, responseDataLength ) );

	REQUIRES_V( isShortIntegerRangeNZ( responseDataLength ) );

	/* Since we're already in an error state there's not much that we can do
	   in terms of alerting the user if a further error occurs when writing 
	   the error response, so we ignore any potential write errors that occur
	   at this point */
	REQUIRES_V( rangeCheck( responseDataLength, 1, 
							sessionInfoPtr->receiveBufSize ) );
	memcpy( sessionInfoPtr->receiveBuffer, responseData,
			responseDataLength );
	sessionInfoPtr->receiveBufEnd = responseDataLength;
	( void ) writePkiDatagram( sessionInfoPtr, OCSP_CONTENT_TYPE_RESP,
							   OCSP_CONTENT_TYPE_RESP_LEN,
							   MK_ERRTEXT( "Couldn't send OCSP error "
										   "response to client" ) );
	}

/* Compare the nonce in a request with the returned nonce in the response */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
static int checkNonce( IN_HANDLE const CRYPT_CERTIFICATE iCertResponse,
					   IN_BUFFER( requestNonceLength ) const void *requestNonce, 
					   IN_LENGTH_SHORT const int requestNonceLength )
	{
	MESSAGE_DATA responseMsgData;
	BYTE responseNonceBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int status;

	assert( isReadPtrDynamic( requestNonce, requestNonceLength ) );

	REQUIRES( isHandleRangeValid( iCertResponse ) );
	REQUIRES( isShortIntegerRangeNZ( requestNonceLength ) );

	/* Make sure that the nonce has a plausible length */
	if( requestNonceLength < 4 || requestNonceLength > CRYPT_MAX_HASHSIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Try and read the nonce from the response */
	setMessageData( &responseMsgData, responseNonceBuffer,
					CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCertResponse, IMESSAGE_GETATTRIBUTE_S,
							  &responseMsgData, CRYPT_CERTINFO_OCSP_NONCE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_NOTFOUND );

	/* Make sure that the two nonces match.  The comparison is in theory 
	   somewhat complex because OCSP never specifies how the nonce is meant 
	   to be encoded so it's possible that some implementations will use 
	   things like TSP's bizarre INTEGER rather than the obvious and logical 
	   OCTET STRING.  In theory this means that we might need to check for 
	   the INTEGER-encoding alternatives that arise due to sign bits, but 
	   this doesn't seem to be required in practice since everyone uses a de 
	   facto encoding of OCTET STRING */
	if( requestNonceLength != responseMsgData.length || \
		memcmp( requestNonce, responseMsgData.data, requestNonceLength ) )
		return( CRYPT_ERROR_SIGNATURE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Client-side Functions							*
*																			*
****************************************************************************/

/* OID information used to read responses */

static const OID_INFO ocspOIDinfo[] = {
	{ OID_OCSP_RESPONSE_OCSP, OCSPRESPONSE_TYPE_OCSP },
	{ NULL, 0 }, { NULL, 0 }
	};

/* Send a request to an OCSP server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sendClientRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* If we're fuzzing, there's no request to send out */
	FUZZ_SKIP_REMAINDER();

	/* Get the encoded request data.  We store this in the session buffer, 
	   which at its minimum size is roughly two orders of magnitude larger 
	   than the request */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_ICERTFORMAT_DATA );
	if( cryptStatusError( status ) )
		{
		retExtObj( status,
				   ( status, SESSION_ERRINFO, sessionInfoPtr->iCertRequest,
					 "Couldn't get OCSP request data from OCSP request "
					 "object" ) );
		}
	sessionInfoPtr->receiveBufEnd = msgData.length;
	DEBUG_DUMP_FILE( "ocsp_req", sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufEnd );

	/* Send the request to the responder */
	return( writePkiDatagram( sessionInfoPtr, OCSP_CONTENT_TYPE_REQ,
							  OCSP_CONTENT_TYPE_REQ_LEN,
							  MK_ERRTEXT( "Couldn't send OCSP request to "
										  "server" ) ) );
	}

/* Read the response from the OCSP server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int readServerResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	CRYPT_CERTIFICATE iCertResponse;
	MESSAGE_DATA msgData;
	STREAM_PEER_TYPE peerSystemType;
	STREAM stream;
	ERROR_INFO localErrorInfo;
	BYTE nonceBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_ERRMSGS
	const char *errorString = NULL;
#endif /* USE_ERRMSGS */
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int errorCode, responseType, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Read the response from the responder.  This may be only a few bytes 
	   in the case of an error response, so we allow a datagram size of 4 
	   bytes and then later explicitly check for a valid length if we get a 
	   non-error response */
	status = readPkiDatagram( sessionInfoPtr, 4,
							  MK_ERRTEXT( "Couldnt read OCSP response from "
										  "server" ) );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_DUMP_FILE( "ocsp_resp", sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufEnd );
	CFI_CHECK_UPDATE( "readPkiDatagram" );

	/* See whether we can determine the remote system type, used to work 
	   around bugs in implementations (and we're specifically talking 
	   Microsoft here, see further down) */
	status = sioctlGet( &sessionInfoPtr->stream, STREAM_IOCTL_GETPEERTYPE, 
						&peerSystemType, sizeof( STREAM_PEER_TYPE ) );
	if( cryptStatusError( status ) )
		peerSystemType = STREAM_PEER_NONE;

	/* Try and extract an OCSP status code from the returned object:

		SEQUENCE {
			respStatus			ENUMERATED,			-- 0 = OK
			respBytes		[0]	EXPLICIT SEQUENCE {	-- If status == OK
								... */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	readSequence( &stream, NULL );
	status = readEnumerated( &stream, &errorCode );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Invalid OCSP response status data" ) );
		}

	/* If it's an error status, try and translate it into something a bit 
	   more meaningful.  Some of the translations are a bit questionable, 
	   but it's better than the generic no va response (which should 
	   actually be "no marcha" in any case) */
	switch( errorCode )
		{
		case OCSP_RESP_SUCCESSFUL:
			status = CRYPT_OK;
			break;

		case OCSP_RESP_TRYLATER:
			status = CRYPT_ERROR_NOTAVAIL;
			break;

		case OCSP_RESP_SIGREQUIRED:
			status = CRYPT_ERROR_SIGNATURE;
			break;

		case OCSP_RESP_UNAUTHORISED:
			status = CRYPT_ERROR_PERMISSION;
			break;

		default:
			status = CRYPT_ERROR_INVALID;
			break;
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
#ifdef USE_ERRMSGS
		switch( errorCode )
			{
			case OCSP_RESP_TRYLATER:
				errorString = "Try again later";
				break;

			case OCSP_RESP_SIGREQUIRED:
				errorString = "Signed OCSP request required";
				break;

			case OCSP_RESP_UNAUTHORISED:
				if( peerSystemType == STREAM_PEER_MICROSOFT || \
					peerSystemType == STREAM_PEER_MICROSOFT_2008 || \
					peerSystemType == STREAM_PEER_MICROSOFT_2012 )
					{
					errorString = "Client isn't authorised to perform query.  "
								  "This is probably due to a Windows Server "
								  "configuration issue, the server "
								  "administrator needs to enable 'Allow "
								  "Nonce requests' for compliance with RFC "
								  "2560";
					}
				else
					errorString = "Client isn't authorised to perform query";
				break;

			default:
				errorString = "Unknown error";
				break;
			}
#endif /* USE_ERRMSGS */
		retExt( status,
				( status, SESSION_ERRINFO, 
				   "OCSP server returned status %d: %s",
				   errorCode, errorString ) );
		}
	CFI_CHECK_UPDATE( "readEnumerated" );

	/* Now that we know we've got an actual OCSP response rather than just a 
	   few bytes of error status, make sure that the data size is valid.  
	   This differs from the length check below in that we're checking the 
	   overall amount of data received, not the value of a length field 
	   inside the data.

	   Note that the following error message is the same as what
	   readPkiDatagram() reports, since we're checking the received message 
	   length and not the OCSP response length */
	if( sessionInfoPtr->receiveBufEnd < MIN_CRYPT_OBJECTSIZE )
		{
		retExt( CRYPT_ERROR_UNDERFLOW,
				( CRYPT_ERROR_UNDERFLOW, SESSION_ERRINFO, 
				  "Invalid PKI message length %d", 
				  sessionInfoPtr->receiveBufEnd ) );
		}

	/* We've got a valid response, read the [0] EXPLICIT SEQUENCE { OID,
	   OCTET STRING { encapsulation and import the response into an OCSP
	   certificate object */
	clearErrorInfo( &localErrorInfo );
	readConstructed( &stream, NULL, 0 );		/* responseBytes */
	readSequence( &stream, NULL );
	readOID( &stream, ocspOIDinfo,				/* responseType */
			 FAILSAFE_ARRAYSIZE( ocspOIDinfo, OID_INFO ), &responseType );
	status = readGenericHole( &stream, &length, 16, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid OCSP response data header" ) );
		}
	if( !isShortIntegerRangeMin( length, MIN_CRYPT_OBJECTSIZE ) )
		{
		sMemDisconnect( &stream );
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid OCSP response size %d, should be %d...%d", 
				  length, MIN_CRYPT_OBJECTSIZE, MAX_INTLENGTH_SHORT ) );
		}
	status = importCertFromStream( &stream, &iCertResponse, 
								   DEFAULTUSER_OBJECT_HANDLE,
								   CRYPT_CERTTYPE_OCSP_RESPONSE, length,
								   KEYMGMT_FLAG_NONE, &localErrorInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
				     "Invalid OCSP response" ) );
		}
	CFI_CHECK_UPDATE( "importCertFromStream" );

	/* If we're fuzzing the input then we're reading static data for which 
	   the nonces won't match so the check that follows will fail, so we 
	   have to exit now */
	FUZZ_EXIT();

	/* If the request went out with a nonce included (which it does by
	   default), make sure that it matches the nonce in the response */
	setMessageData( &msgData, nonceBuffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CERTINFO_OCSP_NONCE );
	if( cryptStatusOK( status ) )
		{
		/* There's a nonce in the request, check that it matches the one in
		   the response */
		status = checkNonce( iCertResponse, msgData.data, msgData.length );
		if( cryptStatusError( status ) )
			{
			/* The response doesn't contain a nonce or it doesn't match what 
			   we sent, we can't trust it.  The best error that we can return 
			   here is a signature error to indicate that the integrity 
			   check failed.
			   
			   Note that a later modification to OCSP, in an attempt to make 
			   it scale, removed the nonce, thus breaking the security of 
			   the protocol against replay attacks.  Since the protocol is 
			   now broken against attack we treat a nonce-less response from 
			   one of these responders as a failure, since it's 
			   indistinguishable from an actual attack */
			krnlSendNotifier( iCertResponse, IMESSAGE_DECREFCOUNT );
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					  ( status == CRYPT_ERROR_NOTFOUND ) ? \
					  "OCSP response doesn't contain a nonce" : \
					  "OCSP response nonce doesn't match the one in the "
					  "request" ) );
			}
		}
	krnlSendNotifier( sessionInfoPtr->iCertRequest, IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCertRequest = CRYPT_ERROR;
	sessionInfoPtr->iCertResponse = iCertResponse;
	CFI_CHECK_UPDATE( "checkNonce" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "readPkiDatagram", "readEnumerated", 
								   "importCertFromStream", "checkNonce" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Server-side Functions							*
*																			*
****************************************************************************/

/* Send an error response back to the client.  Since there are only a small
   number of these, we write back a fixed blob rather than encoding each
   one */

#define RESPONSE_SIZE		5

static const BYTE respBadRequest[] = {
	0x30, 0x03, 0x0A, 0x01, 0x01	/* Rejection, malformed request */
	};
static const BYTE respIntError[] = {
	0x30, 0x03, 0x0A, 0x01, 0x02	/* Rejection, internal error */
	};

/* Read a request from an OCSP client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int readClientRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	CRYPT_CERTIFICATE iOcspRequest;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	ERROR_INFO localErrorInfo;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int tag, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Read the request data from the client.  We don't write an error
	   response at this initial stage to prevent scanning/DOS attacks
	   (vir sapit qui pauca loquitur) */
	status = readPkiDatagram( sessionInfoPtr, MIN_CRYPT_OBJECTSIZE,
							  MK_ERRTEXT( "Couldnt read OCSP request from "
										  "client" ) );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_DUMP_FILE( "ocsp_sreq", sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufEnd );
	CFI_CHECK_UPDATE( "readPkiDatagram" );

	/* Basic lint filter to check for approximately-OK requests before we
	   try creating a certificate object from the data:

		SEQUENCE {
			SEQUENCE {					-- tbsRequest
				version		[0]	...
				reqName		[1]	...
				SEQUENCE {				-- requestList
					SEQUENCE {			-- request
					... */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	readSequence( &stream, NULL );
	status = readSequence( &stream, NULL );
	if( checkStatusPeekTag( &stream, status, tag ) && \
		tag == MAKE_CTAG( 0 ) )
		status = readUniversal( &stream );
	if( checkStatusPeekTag( &stream, status, tag ) && \
		tag == MAKE_CTAG( 1 ) )
		status = readUniversal( &stream );
	if( !cryptStatusError( status ) )
		{
		readSequence( &stream, NULL );
		status = readSequence( &stream, NULL );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, "Invalid OCSP request header" ) );
		}

	/* Import the request as a cryptlib object */
	clearErrorInfo( &localErrorInfo );
	setMessageCreateObjectIndirectInfo( &createInfo,
										sessionInfoPtr->receiveBuffer,
										sessionInfoPtr->receiveBufEnd,
										CRYPT_CERTTYPE_OCSP_REQUEST,
										&localErrorInfo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, respBadRequest, RESPONSE_SIZE );
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
				     "Invalid OCSP request" ) );
		}
	iOcspRequest = createInfo.cryptHandle;
	CFI_CHECK_UPDATE( "IMESSAGE_DEV_CREATEOBJECT_INDIRECT" );

	/* If we're fuzzing the input then we're done */
	FUZZ_EXIT();

	/* Create an OCSP response and add the request information to it */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_OCSP_RESPONSE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iOcspRequest, IMESSAGE_DECREFCOUNT );
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		return( status );
		}
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_SETATTRIBUTE, &iOcspRequest,
							  CRYPT_IATTRIBUTE_OCSPREQUEST );
	krnlSendNotifier( iOcspRequest, IMESSAGE_DECREFCOUNT );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;
		BYTE nonceBuffer[ 8 + 8 ];

		/* Add a nonce as a response attribute.  This is required because 
		   OCSP will sign identical data if two requests are received within
		   one second of each other, leading to an opening for a fault 
		   attack */
		setMessageData( &msgData, nonceBuffer, 8 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( createInfo.cryptHandle, 
									  IMESSAGE_SETATTRIBUTE_S, &msgData, 
									  CRYPT_CERTINFO_CMS_NONCE );
			}
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create OCSP response from request" ) );
		}
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;
	CFI_CHECK_UPDATE( "IMESSAGE_SETATTRIBUTE" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "readPkiDatagram",
								   "IMESSAGE_DEV_CREATEOBJECT_INDIRECT",
								   "IMESSAGE_SETATTRIBUTE" ) );

	return( CRYPT_OK );
	}

/* Return a response to an OCSP client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sendServerResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	int responseLength, responseDataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Check the entries from the request against the certificate store and 
	   sign the resulting status information ("Love, ken").  Note that
	   CRYPT_ERROR_INVALID is a valid return status for the sigcheck call
	   since it indicates that one (or more) of the certificates was 
	   revoked */
	status = krnlSendMessage( sessionInfoPtr->iCertResponse,
							  IMESSAGE_CRT_SIGCHECK, NULL,
							  sessionInfoPtr->cryptKeyset );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_INVALID )
		{
		delayRandom();	/* Dither error timing info */
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		if( cryptArgError( status ) )
			{
			/* There's a problem with one of the parameters, convert the
			   error status to a general invalid-information error */
			status = CRYPT_ERROR_INVALID;
			}
		retExtObj( status,
				   ( status, SESSION_ERRINFO, sessionInfoPtr->iCertResponse,
					 "Couldn't check OCSP request against certificate "
					 "store" ) );
		}
	setMessageData( &msgData, NULL, 0 );	/* To deal with value-uninit err.*/
	status = krnlSendMessage( sessionInfoPtr->iCertResponse,
							  IMESSAGE_CRT_SIGN, NULL,
							  sessionInfoPtr->privateKey );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sessionInfoPtr->iCertResponse,
								  IMESSAGE_CRT_EXPORT, &msgData,
								  CRYPT_CERTFORMAT_CERTIFICATE );
		}
	if( cryptStatusError( status ) )
		{
		delayRandom();	/* Dither error timing info */
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		retExtObj( status,
				   ( status, SESSION_ERRINFO, sessionInfoPtr->iCertResponse,
					 "Couldn't create signed OCSP response" ) );
		}
	responseDataLength = msgData.length;

	/* Write the wrapper for the response */
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer,
			  sessionInfoPtr->receiveBufSize );
	responseLength = sizeofOID( OID_OCSP_RESPONSE_OCSP ) + \
					 sizeofObject( responseDataLength );
	writeSequence( &stream, sizeofEnumerated( 0 ) + \
				   sizeofObject( sizeofObject( responseLength ) ) );
	writeEnumerated( &stream, 0, DEFAULT_TAG );		/* respStatus */
	writeConstructed( &stream, sizeofObject( responseLength ), 0 );
	writeSequence( &stream, responseLength );		/* respBytes */
	writeOID( &stream, OID_OCSP_RESPONSE_OCSP );	/* respType */
	status = writeOctetStringHole( &stream, responseDataLength, 
								   DEFAULT_TAG );	/* response */
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		return( status );
		}

	/* Get the encoded response data */
	status = exportCertToStream( &stream, sessionInfoPtr->iCertResponse,
								 CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		sessionInfoPtr->receiveBufEnd = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		delayRandom();	/* Dither error timing info */
		sendErrorResponse( sessionInfoPtr, respIntError, RESPONSE_SIZE );
		return( status );
		}
	ENSURES( isBufsizeRangeNZ( sessionInfoPtr->receiveBufEnd ) );
	DEBUG_DUMP_FILE( "ocsp_sresp", sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufEnd );

	/* Send the response to the client */
	return( writePkiDatagram( sessionInfoPtr, OCSP_CONTENT_TYPE_RESP,
							  OCSP_CONTENT_TYPE_RESP_LEN,
							  MK_ERRTEXT( "Couldn't send OCSP response to "
										  "client" ) ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Exchange data with an OCSP client/server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientTransact( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
			  /* There's no sanityCheckSessionOCSP() since there's no OCSP-
			     specific data in a session */

	/* Get certificate revocation information from the server */
	status = sendClientRequest( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = readServerResponse( sessionInfoPtr );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int serverTransact( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
			  /* There's no sanityCheckSessionOCSP() since there's no OCSP-
			     specific data in a session */

	/* Send certificate revocation information to the client */
	status = readClientRequest( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = sendServerResponse( sessionInfoPtr );
	return( status );
	}

/****************************************************************************
*																			*
*					Control Information Management Functions				*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int setAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 IN_PTR const void *data,
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	const CRYPT_CERTIFICATE ocspRequest = *( ( CRYPT_CERTIFICATE * ) data );
	MESSAGE_DATA msgData = { NULL, 0 };
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, sizeof( int ) ) );

	REQUIRES( type == CRYPT_SESSINFO_REQUEST );

	/* Make sure that everything is set up ready to go.  Since OCSP requests
	   aren't (usually) signed like normal certificate objects we can't just 
	   check the immutable attribute but have to perform a dummy export for 
	   which the certificate export code will return an error status if 
	   there's a problem with the request.  If not, it pseudo-signs the 
	   request (if it hasn't already done so) and prepares it for use */
	status = krnlSendMessage( ocspRequest, IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_ICERTFORMAT_DATA );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ARGERROR_NUM1,
				( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
				  "OCSP request is incomplete" ) );
		}

	/* If we haven't already got a server name explicitly set, try and get
	   it from the request.  This is an opportunistic action so we ignore 
	   any potential error, the caller can still set the value explicitly */
	if( findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME ) == NULL )
		{
		char buffer[ MAX_URL_SIZE + 8 ];

		setMessageData( &msgData, buffer, MAX_URL_SIZE );
		status = krnlSendMessage( ocspRequest, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_RESPONDERURL );
		if( cryptStatusOK( status ) )
			{
			( void ) krnlSendMessage( sessionInfoPtr->objectHandle,
									  IMESSAGE_SETATTRIBUTE_S, &msgData,
									  CRYPT_SESSINFO_SERVER_NAME );
			}
		}

	/* Add the request and increment its usage count */
	krnlSendNotifier( ocspRequest, IMESSAGE_INCREFCOUNT );
	sessionInfoPtr->iCertRequest = ocspRequest;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodOCSP( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_PROTOCOL_HTTPTRANSPORT, /* Flags */
		80,							/* HTTP port */
		SESSION_NEEDS_REQUEST,		/* Client attributes */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_KEYSET,
		1, 1, 2,					/* Version 1 */
		CRYPT_SUBPROTOCOL_NONE, CRYPT_SUBPROTOCOL_NONE
									/* Allowed sub-protocols */

		/* Protocol-specific information */
		};

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Set the access method pointers */
	DATAPTR_SET( sessionInfoPtr->protocolInfo, ( void * ) &protocolInfo );
	if( isServer( sessionInfoPtr ) )
		{
		FNPTR_SET( sessionInfoPtr->transactFunction, serverTransact );
		}
	else
		{
		FNPTR_SET( sessionInfoPtr->transactFunction, clientTransact );
		}
	FNPTR_SET( sessionInfoPtr->setAttributeFunction, setAttributeFunction );

	return( CRYPT_OK );
	}
#endif /* USE_OCSP */
