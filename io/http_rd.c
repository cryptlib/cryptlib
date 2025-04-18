/****************************************************************************
*																			*
*						  cryptlib HTTP Read Routines						*
*						Copyright Peter Gutmann 1998-2017					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "http.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "io/http.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/* HTTP request line parsing information */

typedef struct {
	BUFFER_FIXED( reqNameLen ) \
	const char *reqName;		/* Request name */
	int reqNameLen;				/* Length of request name */
	STREAM_HTTPREQTYPE_TYPE reqType;	/* Request type */
	int reqTypeFlag;			/* Stream flag for this request type */
	} HTTP_REQUEST_INFO;

static const HTTP_REQUEST_INFO httpReqInfo[] = {
	{ "GET", 3, STREAM_HTTPREQTYPE_GET, STREAM_NHFLAG_GET },
	{ "POST", 4, STREAM_HTTPREQTYPE_POST, STREAM_NHFLAG_POST },
	{ NULL, 0, 0 }, { NULL, 0, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Callback function used by readTextLine() to read characters from a
   stream.  When reading text data over a network we don't know how much
   more data is to come so we have to read a byte at a time looking for an
   EOL.  In addition we can't use the simple optimisation of reading two
   bytes at a time because some servers only send a LF even though the spec
   requires a CRLF.  This is horribly inefficient but is pretty much
   eliminated through the use of opportunistic read-ahead buffering */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int readCharFunction( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr )
	{
	STREAM *stream = streamPtr;
	BYTE ch;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = bufferedTransportRead( stream, &ch, 1, &length,
									TRANSPORT_FLAG_NONE );
	return( cryptStatusError( status ) ? status : ch );
	}

/* Clear the HTTP input stream after a soft error has occurred so that 
   further HTTP transactions can be read */

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int clearInputStream( INOUT_PTR STREAM *stream, 
							 OUT_BUFFER_FIXED( lineBufSize ) char *lineBuffer, 
							 IN_LENGTH_SHORT_MIN( MIN_LINEBUF_SIZE ) \
									const int lineBufSize )
	{
	HTTP_HEADER_INFO headerInfo;
	BOOLEAN isSoftError;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( lineBuffer, lineBufSize ) );

	REQUIRES( isShortIntegerRangeMin( lineBufSize, MIN_LINEBUF_SIZE ) );

	/* Perform a dummy read to clear any remaining HTTP header lines.  Since 
	   we're merely clearing the input stream after a soft error for further
	   reads or to write back an error response, we can ignore a range of
	   non-fatal errors that might occur in the process */
	initHeaderInfo( &headerInfo, 1, 8192, HTTP_FLAG_NOOP );
	status = readHeaderLines( stream, lineBuffer, lineBufSize,
							  &headerInfo, &isSoftError );
	if( status != CRYPT_ERROR_UNDERFLOW && \
		status != CRYPT_ERROR_OVERFLOW && \
		status != CRYPT_ERROR_BADDATA )
		return( status );
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read Request Header							*
*																			*
****************************************************************************/

/* Read an HTTP request header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
static int readRequestHeader( INOUT_PTR STREAM *stream, 
							  OUT_BUFFER_FIXED( lineBufSize ) char *lineBuffer, 
							  IN_LENGTH_SHORT_MIN( MIN_LINEBUF_SIZE ) \
									const int lineBufSize, 
							  INOUT_PTR HTTP_DATA_INFO *httpDataInfo, 
							  OUT_FLAGS_Z( HTTP ) int *flags )
	{
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	HTTP_HEADER_INFO headerInfo;
	HTTP_URI_INFO *uriInfo = httpDataInfo->uriInfo;
	STREAM_HTTPREQTYPE_TYPE reqType = STREAM_HTTPREQTYPE_NONE;
	BOOLEAN isTextDataError, isSoftError;
	char *bufPtr;
	LOOP_INDEX i;
	int length, offset, reqNameLen DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( lineBuffer, lineBufSize ) );
	assert( isWritePtr( httpDataInfo, sizeof( HTTP_DATA_INFO ) ) );
	assert( isWritePtr( flags, sizeof( int ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStream( netStream ) );
	REQUIRES( isShortIntegerRangeMin( lineBufSize, MIN_LINEBUF_SIZE ) );
	REQUIRES( sanityCheckHttpDataInfo( httpDataInfo ) );
	REQUIRES( TEST_FLAG( netStream->nFlags, STREAM_NFLAG_ISSERVER ) );
	REQUIRES( ( ( TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_GET ) || \
				  TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_WS_UPGRADE ) ) && \
				uriInfo != NULL ) || \
			  ( !TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_GET ) && \
				uriInfo == NULL ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( lineBufSize ) ); 
	memset( lineBuffer, 0, min( 16, lineBufSize ) );
	*flags = HTTP_FLAG_NONE;

	/* Read the header and check for "POST/GET x HTTP/1.x".  In theory this
	   could be a bit risky because the original CERN server required an
	   extra (spurious) CRLF after a POST, so that various early clients sent
	   an extra CRLF that isn't included in the Content-Length header and
	   ends up preceding the start of the next load of data.  We don't check
	   for this because it only applies to very old pure-HTTP (rather than
	   HTTP-as-a-transport-layer) clients, which are unlikely to be hitting a
	   PKI responder */
	status = readTextLine( stream, lineBuffer, lineBufSize, &length, 
						   &isTextDataError, readCharFunction, 
						   READTEXT_NONE );
	if( cryptStatusError( status ) )
		{
		/* If it's an HTTP-level error (e.g. line too long), send back an
		   HTTP-level error response */
		if( status != CRYPT_ERROR_COMPLETE )
			{
			sendHTTPError( stream, lineBuffer, lineBufSize,
						   ( status == CRYPT_ERROR_OVERFLOW ) ? \
						   414 : 400 );
			}

		return( retTextLineError( stream, status, isTextDataError, 
								  "Invalid HTTP request header line 1", 
								  0 ) );
		}
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( httpReqInfo, HTTP_REQUEST_INFO ) && \
					httpReqInfo[ i ].reqName != NULL,
			  i++ )
		{
		const HTTP_REQUEST_INFO *reqInfoPtr;

		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( httpReqInfo, \
														 HTTP_REQUEST_INFO ) - 1 ) );

		reqInfoPtr = &httpReqInfo[ i ];
		if( TEST_FLAG( netStream->nhFlags, reqInfoPtr->reqTypeFlag ) && \
			length >= reqInfoPtr->reqNameLen && \
			!strCompare( lineBuffer, reqInfoPtr->reqName, \
						 reqInfoPtr->reqNameLen ) )
			{
			reqType = reqInfoPtr->reqType;
			reqNameLen = reqInfoPtr->reqNameLen;
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( httpReqInfo, HTTP_REQUEST_INFO ) );
	if( reqType == STREAM_HTTPREQTYPE_NONE )
		{
		char reqNameBuffer[ 16 + 8 ];

		/* Return the extended error information */
		if( length <= 0 )
			{
			sendHTTPError( stream, lineBuffer, lineBufSize, 501 );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
					  "Invalid empty HTTP request" ) );
			}
		if( ( offset = strSkipNonWhitespace( lineBuffer, length ) ) > 0 )
			length = offset;
		memcpy( reqNameBuffer, lineBuffer, min( 16, length ) );
		sendHTTPError( stream, lineBuffer, lineBufSize, 501 );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Invalid HTTP request '%s'",
				  sanitiseString( reqNameBuffer, 16, length ) ) );
		}
	bufPtr = lineBuffer + reqNameLen;
	length -= reqNameLen;

	/* Process the ' '* * ' '* and check for the HTTP ID */
	if( length <= 0 || ( offset = strSkipWhitespace( bufPtr, length ) ) <= 0 )
		{
		sendHTTPError( stream, lineBuffer, lineBufSize, 400 );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Missing HTTP request URI" ) );
		}
	bufPtr += offset;
	length -= offset;
	if( reqType == STREAM_HTTPREQTYPE_GET && \
		!TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_WS_UPGRADE ) )
		{
		/* Safety check, make sure that we can handle the HTTP GET */
		REQUIRES( uriInfo != NULL );

		/* If it's an idempotent read then the client is sending a GET 
		   rather than submitting a POST, process the request details.  
		   This performs in-place decoding of (possibly encoded) data, so 
		   it returns two length values, the new length after the in-place
		   decoding has occurred, and the offset of the next character of
		   data as usual */
		status = offset = parseUriInfo( bufPtr, length, &length, uriInfo );
		}
	else
		{
		/* For non-idempotent queries we don't care what the location is
		   since it's not relevant for anything, so we just skip the URI.
		   This also avoids complications with absolute vs. relative URLs,
		   character encoding/escape sequences, and so on */
		status = offset = strSkipNonWhitespace( bufPtr, length );
		}
	if( cryptStatusError( status ) )
		{
		sendHTTPError( stream, lineBuffer, lineBufSize, 400 );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Invalid HTTP GET request URI" ) );
		}
	bufPtr += offset;
	length -= offset;
	if( length <= 0 || ( offset = strSkipWhitespace( bufPtr, length ) ) < 0 )
		{
		sendHTTPError( stream, lineBuffer, lineBufSize, 400 );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Missing HTTP request ID/version" ) );
		}
	bufPtr += offset;
	length -= offset;
	if( length <= 0 || \
		cryptStatusError( checkHTTPID( bufPtr, length, stream ) ) )
		{
		sendHTTPError( stream, lineBuffer, lineBufSize, 505 );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, NETSTREAM_ERRINFO, 
				  "Invalid HTTP request ID/version" ) );
		}

	/* Process the remaining header lines.  ~32 bytes is the minimum-size
	   object that can be returned from any HTTP-based message which is
	   exchanged by cryptlib, this being a TSP request */
	initHeaderInfo( &headerInfo, 32, httpDataInfo->bufSize, *flags );
	if( reqType == STREAM_HTTPREQTYPE_GET )
		{
		/* It's an HTTP GET, make sure that we don't try and read a body */
		SET_FLAG( headerInfo.flags, HTTP_FLAG_GET );
		}
	status = readHeaderLines( stream, lineBuffer, lineBufSize,
							  &headerInfo, &isSoftError );
	if( cryptStatusError( status ) )
		{
		/* If it's a soft error, clear the input stream of any remaining 
		   header lines */
		if( isSoftError )
			{
			int localStatus;

			localStatus = clearInputStream( stream, lineBuffer, 
											lineBufSize );
			if( cryptStatusError( localStatus ) )
				return( localStatus );
			}

		/* We always (try and) send an HTTP error response once we get to
		   this stage since chances are that it'll be a problem with an
		   HTTP header rather than a low-level network read problem */
		sendHTTPError( stream, lineBuffer, lineBufSize,
					   headerInfo.httpStatus );
		return( status );
		}

	/* Copy any status info back to the caller */
	httpDataInfo->reqType = reqType;
	if( reqType != STREAM_HTTPREQTYPE_GET )
		httpDataInfo->bytesAvail = headerInfo.contentLength;
	*flags = GET_FLAGS( headerInfo.flags, HTTP_FLAG_MAX );
	if( TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_WS_UPGRADE ) )
		{
		/* Safety check, STREAM_NHFLAG_WS_UPGRADE implies the earlier 
		   STREAM_NHFLAG_GET */
		REQUIRES( uriInfo != NULL );

		/* Copy the protocol-related information up to the caller */
		if( headerInfo.wsProtocolLen > 0 )
			{
			REQUIRES( rangeCheck( headerInfo.wsProtocolLen, 1, 
								  CRYPT_MAX_TEXTSIZE ) );
			memcpy( uriInfo->protocol, headerInfo.wsProtocol, 
					headerInfo.wsProtocolLen );
			uriInfo->protocolLen = headerInfo.wsProtocolLen;
			}
		REQUIRES( rangeCheck( headerInfo.wsAuthLen, 1, 
							  CRYPT_MAX_TEXTSIZE ) );
		memcpy( uriInfo->auth, headerInfo.wsAuth, 
				headerInfo.wsAuthLen );
		uriInfo->authLen = headerInfo.wsAuthLen;
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read Response Header						*
*																			*
****************************************************************************/

/* Read an HTTP response header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
static int readResponseHeader( INOUT_PTR STREAM *stream, 
							   OUT_BUFFER_FIXED( lineBufSize ) char *lineBuffer, 
							   IN_LENGTH_SHORT_MIN( MIN_LINEBUF_SIZE ) \
									const int lineBufSize, 
							   INOUT_PTR HTTP_DATA_INFO *httpDataInfo, 
							   OUT_FLAGS_Z( HTTP ) int *flags )
	{
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	LOOP_INDEX repeatCount;
	int persistentStatus = CRYPT_OK, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( lineBuffer, lineBufSize ) );
	assert( isWritePtr( httpDataInfo, sizeof( HTTP_DATA_INFO ) ) );
	assert( isWritePtr( flags, sizeof( int ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStream( netStream ) );
	REQUIRES( isShortIntegerRangeMin( lineBufSize, MIN_LINEBUF_SIZE ) );
	REQUIRES( sanityCheckHttpDataInfo( httpDataInfo ) );

	/* Clear return value */
	*flags = HTTP_FLAG_NONE;

	/* Read the returned response header from the server, taking various
	   special-case conditions into account.  In theory we could also handle
	   the 503 "Retry-After" status, but there's no sensible reason why
	   anyone should send us this, and even if they do it'll screw up a lot
	   of the PKI protocols, which have timeliness constraints built in */
	LOOP_SMALL( repeatCount = 0, repeatCount < 5, repeatCount++ )
		{
		HTTP_HEADER_INFO headerInfo;
		BOOLEAN needsSpecialHandling = FALSE;
		BOOLEAN isSoftError, isResponseSoftError;
		int httpStatus;

		ENSURES( LOOP_INVARIANT_SMALL( repeatCount, 0, 4 ) );

		/* Read the response header */
		status = readFirstHeaderLine( stream, lineBuffer, lineBufSize,
									  &httpStatus, &isResponseSoftError );
		if( cryptStatusError( status ) )
			{
			/* Some errors like an HTTP 404 aren't necessarily fatal in the 
			   same way as (say) a CRYPT_ERROR_BADDATA because while the 
			   latter means that the stream has been corrupted and we can't 
			   continue, the former merely means that the requested item 
			   wasn't found but we can still submit further requests */
			if( !isResponseSoftError )
				return( status );

			/* If it's a special-case header (e.g. a 100 Continue) remember 
			   that it needs special handling later, otherwise turn the read 
			   into a no-op read that drains the input to get to the next set 
			   of data */
			persistentStatus = status;
			if( status == OK_SPECIAL )
				{
				needsSpecialHandling = TRUE;
				if( httpStatus == 100 )
					{
					/* 100 Continue is a noise status so we also drain the 
					   input in this case */
					*flags |= HTTP_FLAG_NOOP;
					}
				if( httpStatus == 101 )
					*flags |= HTTP_FLAG_UPGRADE;
				}
			else
				*flags |= HTTP_FLAG_NOOP;
			}

		/* Process the remaining header lines.  5 bytes is the minimum-size
		   object that can be returned from any HTTP-based message which is
		   exchanged by cryptlib, this being an OCSP response containing a
		   single-byte status value, i.e. SEQUENCE { ENUM x }.

		   A soft error at this stage is different from a response soft
		   error (for example one arising from a 403, which is a valid 
		   response but not the one desired) because it's an error in an 
		   HTTP header line, which is an invalid response but not a fatal
		   error.  If we get a soft error at this point we clear the
		   remaining input in order to allow further input to be processed.

		   If the read buffer is dynamically allocated then we allow an
		   effectively arbitrary content length, otherwise it has to fit 
		   into the fixed-size read buffer.  Unfortunately since CRLs can 
		   reach > 100MB in size it's not really possible to provide any 
		   sensible limit on the length for dynamic-buffer reads, however
		   to avoid DoS issues we limit it to 8MB until someone complains 
		   that they can't read the 150MB CRLs that their CA is issuing 
		   (yes, there are CAs that are issuing 150MB CRLs) */
		initHeaderInfo( &headerInfo, 5,
						httpDataInfo->bufferResize ? \
							min( MAX_BUFFER_SIZE, 8388608L ) : \
							httpDataInfo->bufSize,
						*flags );
		status = readHeaderLines( stream, lineBuffer, lineBufSize,
								  &headerInfo, &isSoftError );
		if( cryptStatusError( status ) )
			{
			if( isSoftError )
				{
				int localStatus;

				localStatus = clearInputStream( stream, lineBuffer, 
												lineBufSize );
				if( cryptStatusError( localStatus ) )
					return( localStatus );
				}
			return( status );
			}

		/* Copy any status info back to the caller */
		*flags = GET_FLAGS( headerInfo.flags, 
							HTTP_FLAG_MAX ) & ~HTTP_FLAG_NOOP;
		httpDataInfo->bytesAvail = headerInfo.contentLength;

		/* If it's not something like a redirect that needs special-case
		   handling, we're done */
		if( !needsSpecialHandling )
			{
			/* If this was a soft error due to not finding the requested 
			   item, pass the status on to the caller.  The low-level error 
			   information will still be present from 
			   readFirstHeaderLine() */
			if( isResponseSoftError )
				{
				return( cryptStatusError( persistentStatus ) ? \
						persistentStatus : CRYPT_ERROR_NOTFOUND );
				}

			/* There's no special-case handling required, we're done */
			return( CRYPT_OK );
			}

#ifdef USE_WEBSOCKETS
		REQUIRES( httpStatus == 100 || httpStatus == 101 || \
				  httpStatus == 301 || httpStatus == 302 || \
				  httpStatus == 307 );
#else
		REQUIRES( httpStatus == 100 || httpStatus == 301 || \
				  httpStatus == 302 || httpStatus == 307 );
#endif /* USE_WEBSOCKETS */

		/* If we got a 100 Continue response, try for another header that
		   follows the first one */
		if( httpStatus == 100 )
			continue;

		/* If we got a 101 Switching Protocols response, make sure that this
		   is allowed */
#ifdef USE_WEBSOCKETS
		if( httpStatus == 101 )
			{
			HTTP_URI_INFO *httpUriInfo = httpDataInfo->uriInfo;

			/* If an upgrade response isn't permitted at this point, report
			   the error that readHTTPStatus() in http_parse.c would have
			   returned */
			if( !TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_WS_UPGRADE ) )
				{
				retExt( CRYPT_ERROR_READ,
						( CRYPT_ERROR_READ, NETSTREAM_ERRINFO, 
						  "HTTP response status: Switching Protocols" ) );
				}
			ENSURES( httpUriInfo != NULL );
			
			/* Copy the protocol-related information up to the caller */
			if( headerInfo.wsProtocolLen > 0 )
				{
				REQUIRES( rangeCheck( headerInfo.wsProtocolLen, 1, 
									  CRYPT_MAX_TEXTSIZE ) );
				memcpy( httpUriInfo->protocol, headerInfo.wsProtocol, 
						headerInfo.wsProtocolLen );
				httpUriInfo->protocolLen = headerInfo.wsProtocolLen;
				}
			REQUIRES( rangeCheck( headerInfo.wsAuthLen, 1, 
								  CRYPT_MAX_TEXTSIZE ) );
			memcpy( httpUriInfo->auth, headerInfo.wsAuth, 
					headerInfo.wsAuthLen );
			httpUriInfo->authLen = headerInfo.wsAuthLen;

			return( CRYPT_OK );
			}
#endif /* USE_WEBSOCKETS */

		/* A redirect isn't permitted for anything other than an HTTP GET */
		if( !TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_GET ) )
			{
			retExt( CRYPT_ERROR_READ,
					( CRYPT_ERROR_READ, NETSTREAM_ERRINFO, 
					  "Received invalid HTTP %d redirect during message "
					  "exchange", httpStatus ) );
			}			

		/* If we got a 301, 302, or 307 Redirect then in theory we should
		   proceed roughly as per the code below, however in practice it's
		   not nearly as simple as this, because what we're in effect doing
		   is taking a stream and replacing it with a completely new stream
		   (different host/abs-path/query info, new socket with optional
		   proxy handling, etc etc).  One way to do this would be to read
		   the new location into the current stream buffer and pass it back
		   with a special status telling the stream-level code to create a
		   new stream, clean up the old one, and perform a deep copy of the
		   new stream over to the old one.  We'll leave this for a time when
		   it's really needed.

		   A less problematic variant occurs when the GET redirects to a 
		   different abs-path on the same server, which just requires 
		   resubmitting the GET with a different abs-path.

		   In addition the semantics of the following pseudocode don't quite
		   match those of RFC 2616/7230,1,2,3,4,... because of the HTTP-as-a-
		   substrate use rather than direct use in a browser.  Specifically, 
		   anything other than a GET for a 302 or 307 isn't supposed to 
		   perform an automatic redirect without asking the user, because of 
		   concerns that it'll change the semantics of the request.  However 
		   since we're not an interactive web browser there's no way that we 
		   can ask a user for redirect permission, and in any case since 
		   we're merely using HTTP as a substrate for a cryptographically
		   protected PKI message (and specifically assuming that the HTTP
		   layer is completely insecure), any problems will be caught by the
		   crypto protocol layer */
#if 0
		if( !*location )
			return( CRYPT_ERROR_READ );
		netStream->closeSocketFunction( stream );
		clFree( "readResponseHeader", netStream->host );
		netStream->host = NULL;
		status = parseLocation( stream, location );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_READ );
#endif /* 0 */
		retExt( CRYPT_ERROR_READ,
				( CRYPT_ERROR_READ, NETSTREAM_ERRINFO, 
				  "Unable to process HTTP %d redirect", httpStatus ) );
		}
	ENSURES( LOOP_BOUND_OK );

	/* We used up our maximum number of retries, bail out */
	retExt( CRYPT_ERROR_READ,
			( CRYPT_ERROR_READ, NETSTREAM_ERRINFO, 
			  "Encountered more than %d HTTP retry/redirect requests", 5 ) );
	}

/****************************************************************************
*																			*
*							HTTP Access Functions							*
*																			*
****************************************************************************/

/* Read data from an HTTP stream.  This has a nonstandard interpretation of
   the read buffer in that it's not a direct pointer to the read buffer but
   to an HTTP_DATA_INFO structure that contains additional metadata about 
   the HTTP read.  For this reason it's an INOUT_BUFFER rather than an 
   OUT_BUFFER */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readFunction( INOUT_PTR STREAM *stream, 
						 INOUT_BUFFER( maxLength, *length ) void *buffer, 
						 IN_LENGTH_FIXED( sizeof( HTTP_DATA_INFO ) ) \
							const int maxLength, 
						 OUT_DATALENGTH_Z int *length )
	{
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	HTTP_DATA_INFO *httpDataInfo = ( HTTP_DATA_INFO * ) buffer;
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];
	int flags = HTTP_FLAG_NONE, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( buffer, maxLength ) );
	assert( isWritePtr( length, sizeof( int ) ) );
	assert( httpDataInfo->uriInfo == NULL || \
			isWritePtr( httpDataInfo->uriInfo, sizeof( HTTP_URI_INFO ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStream( netStream ) );
	REQUIRES( maxLength == sizeof( HTTP_DATA_INFO ) );
	REQUIRES( sanityCheckHttpDataInfo( httpDataInfo ) );
	REQUIRES( !TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_WS_UPGRADE ) || \
			  httpDataInfo->uriInfo != NULL );

	/* Clear return value */
	*length = 0;

	/* Check whether the other side has indicated that it closed the 
	   connection after the previous message was read.  This operates at a 
	   different level to the usual stream-level connection management 
	   because the network connection may still be open but any further 
	   attempts to do anything with it will return an error */
	if( TEST_FLAG( netStream->nFlags, STREAM_NFLAG_LASTMSGR ) )
		{
		retExt( CRYPT_ERROR_COMPLETE,
				( CRYPT_ERROR_COMPLETE, NETSTREAM_ERRINFO, 
				  "Peer has closed the connection via HTTP 'Connection: "
				  "close'" ) );
		}

	/* Read the HTTP packet header */
	if( TEST_FLAG( netStream->nFlags, STREAM_NFLAG_ISSERVER ) )
		{
		status = readRequestHeader( stream, headerBuffer, HTTP_LINEBUF_SIZE,
									httpDataInfo, &flags );
		}
	else
		{
		status = readResponseHeader( stream, headerBuffer, HTTP_LINEBUF_SIZE,
									 httpDataInfo, &flags );
		if( cryptStatusOK( status ) && \
			httpDataInfo->bytesAvail > httpDataInfo->bufSize )
			{
			void *newBuffer;

			REQUIRES( isBufsizeRangeMin( httpDataInfo->bytesAvail, \
										 MIN_LINEBUF_SIZE ) );

			/* readResponseHeader() will only allow content larger than the 
			   buffer size if it's marked as a resizeable buffer */
			REQUIRES( httpDataInfo->bufferResize == TRUE );

			/* Adjust the read buffer size to handle the extra data and 
			   record the details of the resized buffer */
			newBuffer = safeBufferAlloc( httpDataInfo->bytesAvail );
			if( newBuffer == NULL )
				return( CRYPT_ERROR_MEMORY );
			REQUIRES( isIntegerRangeNZ( httpDataInfo->bufSize ) ); 
			zeroise( httpDataInfo->buffer, httpDataInfo->bufSize );
			safeBufferFree( httpDataInfo->buffer );
			httpDataInfo->buffer = newBuffer;
			httpDataInfo->bufSize = httpDataInfo->bytesAvail;
			}
		else
			{
			/* We didn't dynically resize the buffer, let the caller know */
			httpDataInfo->bufferResize = FALSE;
			}
		}
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( httpDataInfo->bytesAvail <= httpDataInfo->bufSize );

	REQUIRES( !TEST_FLAG( netStream->nFlags, STREAM_NFLAG_ISSERVER ) || \
			  ( httpDataInfo->reqType != STREAM_HTTPREQTYPE_NONE ) );

	/* If we're the server and the client sends us an HTTP GET, all of the 
	   information was contained in the header and we're done */
	if( TEST_FLAG( netStream->nFlags, STREAM_NFLAG_ISSERVER ) && \
		( httpDataInfo->reqType == STREAM_HTTPREQTYPE_GET ) )
		{
		*length = maxLength;
		return( CRYPT_OK );
		}

	/* If the peer has sent us a protocol upgrade request, all of the 
	   information was contained in the header and we're done */
	if( TEST_FLAG( netStream->nhFlags, STREAM_NHFLAG_WS_UPGRADE ) )
		{
		*length = maxLength;
		return( CRYPT_OK );
		}

	/* Read the payload data from the client/server */
	status = bufferedTransportRead( stream, httpDataInfo->buffer, 
									httpDataInfo->bytesAvail, 
									&httpDataInfo->bytesTransferred, 
									TRANSPORT_FLAG_NONE );
	if( cryptStatusError( status ) )
		return( status );
	if( httpDataInfo->bytesTransferred < httpDataInfo->bytesAvail )
		{
		/* We timed out before reading all of the data.  Usually this will 
		   be reported as a CRYPT_ERROR_TIMEOUT by the lower-level read
		   routines, however due to the multiple layers of I/O layering that 
		   are possible we perform an explicit check here to make sure that 
		   we got everything */
		retExt( CRYPT_ERROR_TIMEOUT,
				( CRYPT_ERROR_TIMEOUT, NETSTREAM_ERRINFO, 
				  "HTTP read timed out before all data could be read, only "
				  "got %d of %d bytes", httpDataInfo->bytesTransferred, 
				  httpDataInfo->bytesAvail ) );
		}

	/* If it's a plain-text error message, return it to the caller */
	if( ( flags & HTTP_FLAG_TEXTMSG ) && !httpDataInfo->responseIsText )
		{
		BYTE *byteBufPtr = httpDataInfo->buffer;

		/* Usually a body returned as plain text is an error message that
		   (for some reason) is sent as content rather than an HTTP error,
		   however in some unusual cases the content will be the requested
		   object marked as plain text.  We try and filter out genuine PKI
		   data erroneously marked as text by requiring that the request is 
		   over a minimum size (most error messages are quite short) and 
		   that the first bytes match what would be seen in a PKI object 
		   such as a cert or CRL */
		if( httpDataInfo->bytesAvail < 256 || ( byteBufPtr[ 0 ] != 0x30 ) || \
			!( byteBufPtr[ 1 ] & 0x80 ) || \
			( isAlpha( byteBufPtr[ 2 ] ) && isAlpha( byteBufPtr[ 3 ] ) && \
			  isAlpha( byteBufPtr[ 4 ] ) ) )
			{
			retExt( CRYPT_ERROR_READ,
					( CRYPT_ERROR_READ, NETSTREAM_ERRINFO, 
					  "HTTP server reported: '%s'",
					  sanitiseString( byteBufPtr, \
									  httpDataInfo->bufSize,
									  min( httpDataInfo->bytesTransferred, \
										   MAX_ERRMSG_SIZE - 32 ) ) ) );
			}
		}

	/* If we're reading chunked data, drain the input by processing the
	   trailer.  The reason why there can be extra header lines at the end
	   of the chunked data is because it's designed to be an indefinite-
	   length streamable format that doesn't require buffering the entire
	   message before emitting it.  Since some header information may not be
	   available until the entire message has been generated, the HTTP 
	   specification makes provisions for adding further header lines as a 
	   trailer.  In theory we should check for the HTTP_FLAG_TRAILER flag 
	   before reading trailer lines rather than just swallowing the last 
	   CRLF, however the "Trailer:" header wasn't added until RFC 2616 (RFC 
	   2068 didn't have it) so we can't rely on its presence.  Normally we 
	   wouldn't have to worry about trailer data, but if it's an HTTP 1.1 
	   persistent connection then we need to clear the way for the next lot 
	   of data */
	if( flags & HTTP_FLAG_CHUNKED )
		{
		status = readTrailerLines( stream, headerBuffer,
								   HTTP_LINEBUF_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	*length = maxLength;
	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerHTTP( INOUT_PTR NET_STREAM_INFO *netStream )
	{
	assert( isWritePtr( netStream, sizeof( NET_STREAM_INFO ) ) );

	/* Set the access method pointers */
	FNPTR_SET( netStream->readFunction, readFunction );
	setStreamLayerHTTPwrite( netStream );

	/* The default HTTP operation type is POST, since in most cases it's 
	   being used as a substrate by a PKI protocol */
	SET_FLAG( netStream->nhFlags, STREAM_NHFLAG_POST );

	/* HTTP provides its own data-size and flow-control indicators so we
	   don't want the higher-level code to try and do this for us */
	SET_FLAG( netStream->nFlags, STREAM_NFLAG_ENCAPS );
	}
#endif /* USE_HTTP */
