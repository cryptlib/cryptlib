/****************************************************************************
*																			*
*						 cryptlib SCEP Client Management					*
*						Copyright Peter Gutmann 1999-2022					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "session.h"
  #include "scep.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "session/session.h"
  #include "session/scep.h"
#endif /* Compiler-specific includes */

#ifdef USE_SCEP

/* Prototypes for functions in pnppki.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int pnpPkiSession( INOUT_PTR SESSION_INFO *sessionInfoPtr );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Import a SCEP CA certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
static int importCACertificate( OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCryptCert,
								IN_BUFFER( certLength ) const void *certificate,
								IN_LENGTH_SHORT const int certLength,
								IN_FLAGS( KEYMGMT ) const int options,
								INOUT_PTR ERROR_INFO *errorInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	BOOLEAN isCertChain = FALSE;
	int tag, status;

	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtrDynamic( certificate, certLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isShortIntegerRangeMin( certLength, 8 ) );
	REQUIRES( options == KEYMGMT_FLAG_USAGE_CRYPT || \
			  options == KEYMGMT_FLAG_USAGE_SIGN );

	/* Clear return value */
	*iCryptCert = CRYPT_ERROR;

	/* Depending on what the server feels like it can return either a single
	   certificate or a complete certificate chain, with the type denoted
	   by the HTTP-transport content type.  Because we have no easy way of
	   getting at this, we sniff the payload data to see what it contains.
	   The two objects begin with:

		Cert:		SEQUENCE { SEQUENCE ...
		Cert.chain:	SEQNEUCE { OID ...

	   so we can use the second tag to determine what we've got.  In theory 
	   we could get the certificate-import code to do this for us, but 
	   that'll import anything, not just a certificate */
	sMemConnect( &stream, certificate, certLength );
	status = readSequence( &stream, NULL );
	if( checkStatusPeekTag( &stream, status, tag ) && \
		tag == BER_OBJECT_IDENTIFIER )
		{
		/* We've been sent a certificate chain, we need to import it as 
		   such */
		isCertChain = TRUE;
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the certificate */
	if( isCertChain )
		{
		setMessageCreateObjectIndirectInfoEx( &createInfo, certificate, 
							certLength, CRYPT_CERTTYPE_CERTCHAIN, options,
							errorInfo );
		}
	else
		{
		setMessageCreateObjectIndirectInfo( &createInfo, certificate, 
							certLength, CRYPT_CERTTYPE_CERTIFICATE, 
							errorInfo );
		}
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	*iCryptCert = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/* Check whether two certificates are identical.  Since these may be present 
   at the end of a certificate chain, we have to jump through extra hoops to
   compare them */

static BOOLEAN isSameCertificate( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert1,
								  IN_HANDLE const CRYPT_CERTIFICATE iCryptCert2 )
	{
	BOOLEAN isSameCert = FALSE;
	int status;

	REQUIRES( isHandleRangeValid( iCryptCert1 ) );
	REQUIRES( isHandleRangeValid( iCryptCert2 ) );

	/* Lock the certificate chains for exclusive use */
	status = krnlSendMessage( iCryptCert1, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iCryptCert2, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		{
		( void ) krnlSendMessage( iCryptCert1, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_FALSE, 
								  CRYPT_IATTRIBUTE_LOCKED );
		return( status );
		}

	/* Select the leaf certificate in both chains */
	status = krnlSendMessage( iCryptCert1, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_CURSORFIRST,
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptCert2, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_CURSORFIRST,
								  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
		}
	if( cryptStatusOK( status ) )
		{
		int compareStatus;

		compareStatus = krnlSendMessage( iCryptCert1, IMESSAGE_COMPARE, 
										 ( MESSAGE_CAST ) &iCryptCert2,
										 MESSAGE_COMPARE_CERTOBJ );
		if( cryptStatusOK( compareStatus ) )
			isSameCert = TRUE;
		}
	( void ) krnlSendMessage( iCryptCert1, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_FALSE, 
							  CRYPT_IATTRIBUTE_LOCKED );
	( void ) krnlSendMessage( iCryptCert2, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_FALSE, 
							  CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		{
		/* It's not clear what we should return in the case of an error 
		   (mostly because it's a shouldn't-occur condition), we have two 
		   valid certificates so we shouldn't abort processing because a
		   compare operation failed.  Because of this we report a non-
		   match, which in most cases will allow things to proceeed as
		   required, and when it is a match it'll be caught later */
		return( FALSE );
		}

	return( isSameCert );
	}

/* Write a PKI datagram, with additional information communicated as part of 
   the HTTP metadata */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writePkiDatagramEx( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							   IN_BUFFER_OPT( contentTypeLen ) \
									const char *contentType, 
							   IN_LENGTH_TEXT_Z const int contentTypeLen )
	{
	HTTP_DATA_INFO httpDataInfo;
	static const HTTP_REQ_INFO httpReqInfo = {
		"operation", 9,
		"PKIOperation", 12, 
		"", 0
		};
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( contentType == NULL || \
			isReadPtrDynamic( contentType, contentTypeLen ) );

	REQUIRES( ( contentType == NULL && contentTypeLen ) || \
			  ( contentType != NULL && \
				contentTypeLen > 0 && contentTypeLen <= CRYPT_MAX_TEXTSIZE ) );
	REQUIRES( isBufsizeRangeMin( sessionInfoPtr->receiveBufEnd, 4 ) );

	/* Write the datagram.  Request/response sessions use a single buffer 
	   for both reads and writes, which is why we're (apparently) writing
	   the contents of the read buffer */
	status = initHttpInfoWriteEx( &httpDataInfo,
				sessionInfoPtr->receiveBuffer, sessionInfoPtr->receiveBufEnd, 
				sessionInfoPtr->receiveBufSize, &httpReqInfo );
	ENSURES( cryptStatusOK( status ) );
	httpDataInfo.contentType = contentType;
	httpDataInfo.contentTypeLen = contentTypeLen;
	status = swrite( &sessionInfoPtr->stream, &httpDataInfo,
					 sizeof( HTTP_DATA_INFO ) );
	if( cryptStatusError( status ) )
		{
		sessionInfoPtr->receiveBufEnd = 0;
		sNetGetErrorInfo( &sessionInfoPtr->stream, SESSION_ERRINFO );
		retExtErr( status,
				   ( status, SESSION_ERRINFO, SESSION_ERRINFO,
				     "Couldn't send SCEP request to server" ) );
		}
	sessionInfoPtr->receiveBufEnd = 0;

	return( CRYPT_OK );
	}

#ifdef USE_BASE64

/* Some broken servers (and we're specifically talking Microsoft's one here) 
   don't handle POST but require the use of a POST disguised as a GET, for 
   which we provide the following variant of writePkiDatagram() that sends
   the POST as an HTTP GET */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writePkiDatagramAsGet( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	HTTP_DATA_INFO httpDataInfo;
	static const HTTP_REQ_INFO httpReqInfo = {
		"operation", 9,
		"PKIOperation", 12, 
		"message=", 8
		};
	const int dataSize = sessionInfoPtr->receiveBufEnd;
	LOOP_INDEX i;
	int fullEncodedLength, encodedLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isBufsizeRangeMin( dataSize, 4 ) );

	/* The way that we do the encoding is to move the raw data up in the 
	   buffer to make room for the encoded form and then encode it into the 
	   freed-up room:

				+---------------+
				v	  Encode	|
		+---------------+---------------+
		| base64'd data	|	Raw data	|
		+---------------+---------------+
		|<-fullEncLen ->|<- dataSize -->|

	   First we have to determine how long the base64-encoded form of the 
	   message will be and make sure that it fits into the buffer */
	status = base64encodeLen( dataSize, &fullEncodedLength, 
							  CRYPT_CERTTYPE_NONE );
	ENSURES( cryptStatusOK( status ) );
	if( fullEncodedLength + dataSize >= sessionInfoPtr->receiveBufSize )
		return( CRYPT_ERROR_OVERFLOW );

	/* Move the message up in the buffer to make room for its encoded form 
	   and encode it */
	REQUIRES( boundsCheck( fullEncodedLength, dataSize, 
						   sessionInfoPtr->receiveBufSize ) );
	memmove( sessionInfoPtr->receiveBuffer + fullEncodedLength,
			 sessionInfoPtr->receiveBuffer, dataSize );
	status = base64encode( sessionInfoPtr->receiveBuffer, fullEncodedLength, 
						   &encodedLength, 
						   sessionInfoPtr->receiveBuffer + fullEncodedLength,
						   dataSize, CRYPT_CERTTYPE_NONE );
	if( cryptStatusError( status ) )
		return( status );

	/* The base64 encoding in the form that we're calling it produces raw 
	   output without the trailing '=' padding bytes so we have to manually
	   insert the required padding based on the calculated vs.actual encoded 
	   length.  This can't overflow because we're simply padding the data 
	   out to the fullEncodedLength size that was calculated earlier */
	if( encodedLength < fullEncodedLength )
		{
		const int delta = fullEncodedLength - encodedLength;

		REQUIRES( delta > 0 && delta < 3 );
		REQUIRES( boundsCheck( encodedLength, delta, 
							   sessionInfoPtr->receiveBufSize ) );
		memcpy( sessionInfoPtr->receiveBuffer + encodedLength,
				"========", delta );
		}

	/* Now that it's base64-encoded it can no longer be sent as is because 
	   some base64 values, specifically '/', '+' and '=', are used for other
	   purposes in URLs.  Because of this we have to make another pass over
	   the data escaping these characters into the '%xx' form */
	LOOP_MAX( i = 0, i < fullEncodedLength, i++ )
		{
		char escapeBuffer[ 8 + 8 ];
		int ch, result;

		ENSURES( LOOP_INVARIANT_MAX( i, 0, fullEncodedLength - 1 ) );

		/* If this isn't a special character, there's nothing to do */
		ch = sessionInfoPtr->receiveBuffer[ i ];
		if( ch != '/' && ch != '+' && ch != '=' )
			continue;

		/* Make room for the escaped form and encode the value */
		if( fullEncodedLength + 2 >= sessionInfoPtr->receiveBufSize )
			return( CRYPT_ERROR_OVERFLOW );
		REQUIRES( boundsCheck( i + 2, fullEncodedLength - i, 
							   sessionInfoPtr->receiveBufSize ) );
		memmove( sessionInfoPtr->receiveBuffer + i + 2, 
				 sessionInfoPtr->receiveBuffer + i, fullEncodedLength - i );
		result = sprintf_s( escapeBuffer, 8, "%%%02X", ch );
		ENSURES( rangeCheck( result, 3, 7 ) );
		REQUIRES( boundsCheck( i, 3, sessionInfoPtr->receiveBufSize ) );
		memcpy( sessionInfoPtr->receiveBuffer + i, escapeBuffer, 3 );
		fullEncodedLength += 2;
		} 
	ENSURES( LOOP_BOUND_OK );

	/* Send the POST as an HTTP GET */
	sioctlSet( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, 
			   STREAM_HTTPREQTYPE_POST_AS_GET );
	status = initHttpInfoWriteEx( &httpDataInfo, 
						sessionInfoPtr->receiveBuffer, fullEncodedLength, 
						sessionInfoPtr->receiveBufSize, &httpReqInfo );
	ENSURES( cryptStatusOK( status ) );
	httpDataInfo.contentType = SCEP_CONTENTTYPE;
	httpDataInfo.contentTypeLen = SCEP_CONTENTTYPE_LEN;
	status = swrite( &sessionInfoPtr->stream, &httpDataInfo,
					 sizeof( HTTP_DATA_INFO ) );
	sioctlSet( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, 
			   STREAM_HTTPREQTYPE_POST );
	if( cryptStatusError( status ) )
		{
		sessionInfoPtr->receiveBufEnd = 0;
		sNetGetErrorInfo( &sessionInfoPtr->stream, SESSION_ERRINFO );
		retExtErr( status,
				   ( status, SESSION_ERRINFO, SESSION_ERRINFO,
				     "Couldn't send SCEP request as HTTP GET to server" ) );
		}
	sessionInfoPtr->receiveBufEnd = 0;

	return( CRYPT_OK );
	}
#endif /* USE_BASE64 */

/****************************************************************************
*																			*
*					Additional Request Management Functions					*
*																			*
****************************************************************************/

/* The responses that we can get from a GetCACaps request, or at least the
   ones that we can do something with */

typedef struct {
	const char *caCap;
	const int caCapSize;
	const int caCapFlag;
	} CACAPS_INFO;

static const CACAPS_INFO caCapsInfo[] = {
	{ "SCEPStandard", 12, SCEP_PFLAG_SCEPSTANDARD },
		{ NULL, 0, SCEP_PFLAG_NONE }, { NULL, 0, SCEP_PFLAG_NONE }
	};

/* Process the various bolted-on additions to the basic SCEP protocol */

#define MAX_GETCACAPS_LINES		32

typedef enum { GETREQUEST_NONE, GETREQUEST_GETCACAPS, GETREQUEST_GETCACERT, 
			   GETREQUEST_LAST } GETREQUEST_TYPE;

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sendGetRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   const GETREQUEST_TYPE requestType )
	{
	HTTP_DATA_INFO httpDataInfo;
#if 0	/* 23/3/18 Older versions of the SCEP draft specified the GetCACaps
				   format as '... "?operation=GetCACaps&message=" CA-IDENT' 
				   but no-one knew what CA-IDENT was meant to be.  According 
				   to the draft it's "a string that represents the 
				   certification authority issuer identifier" but no-one 
				   (including the spec's authors) seem to know what this is 
				   supposed to be.  We used '*' on the basis that it's 
				   better than nothing, but the final RFC fixed it by 
				   specifying the message as '"?operation=GetCACaps"' */
	static const HTTP_REQ_INFO httpReqGetCACaps = {
		"operation", 9,
		"GetCACaps", 9,
		"message=*", 9
		};
	static const HTTP_REQ_INFO httpReqGetCACert = {
		"operation", 9,
		"GetCACert", 9,
		"message=*", 9
		};
#else
	static const HTTP_REQ_INFO httpReqGetCACaps = {
		"operation", 9,
		"GetCACaps", 9,
		};
	static const HTTP_REQ_INFO httpReqGetCACert = {
		"operation", 9,
		"GetCACert", 9,
		};
#endif /* 0 */
	HTTP_REQ_INFO *httpReqInfo = \
		( requestType == GETREQUEST_GETCACAPS ) ? \
		( void * ) &httpReqGetCACaps : ( void * ) &httpReqGetCACert;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	
	REQUIRES( isEnumRange( requestType, GETREQUEST ) );

	/* Perform an HTTP GET with arguments "operation=<command>&message=*" */
	sioctlSet( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, 
			   STREAM_HTTPREQTYPE_GET );
	status = initHttpInfoReqEx( &httpDataInfo, httpReqInfo );
	ENSURES( cryptStatusOK( status ) );
	status = swrite( &sessionInfoPtr->stream, &httpDataInfo,
					 sizeof( HTTP_DATA_INFO ) );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream, SESSION_ERRINFO );
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, SESSION_ERRINFO,
					 "'%s' request write failed", httpReqInfo->value ) );
		}
	status = initHttpInfoRead( &httpDataInfo, sessionInfoPtr->receiveBuffer,
							   sessionInfoPtr->receiveBufSize );
	ENSURES( cryptStatusOK( status ) );
	if( requestType == GETREQUEST_GETCACAPS )
		{
		/* Indicate that a response consisting of a text message, rather 
		   than PKI data, is valid for this operation */
		httpDataInfo.responseIsText = TRUE;
		}
	status = sread( &sessionInfoPtr->stream, &httpDataInfo,
					sizeof( HTTP_DATA_INFO ) );
	sioctlSet( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, 
			   STREAM_HTTPREQTYPE_POST );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream, SESSION_ERRINFO );
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, SESSION_ERRINFO,
					 "'%s' operation failed", httpReqInfo->value ) );
		}
	sessionInfoPtr->receiveBufEnd = httpDataInfo.bytesAvail;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int getCACapabilities( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	LOOP_INDEX lineCount;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Get the CA capabilities */
	status = sendGetRequest( sessionInfoPtr, GETREQUEST_GETCACAPS );
	if( cryptStatusError( status ) )
		{
		/* Microsoft's NDES under Server 2003 and Server 2008 without the
		   KB2483564 hotfix either simply close the connection with no 
		   further output or send back a zero-length response.  If we get 
		   this then we provide a hint about what the problem could be.  
		   
		   This can be a bit problematic because we could also be talking 
		   to something that isn't a SCEP server, which will lead to a 
		   misleading diagnostic, but it should be safe to assume that the 
		   user is intending to talk to a SCEP server and that if we get 
		   this response then it's likely to be Server 2003/pre-hotfix 
		   2008.
		   
		   In any case even with GetCACaps enabled via a hotfix the results
		   are more or less useless, AES isn't listed as a supported
		   algorithm (see also the next comment below) but is supported 
		   anyway, and the response is hardcoded to use single DES (!!!) no 
		   matter what algorithm is used for the request 
		   (see 
		   http://serverfault.com/questions/458643/can-i-configure-wndows-ndes-server-to-use-triple-des-3des-algorithm-for-pkcs7
		   ).
		
		   We still need to support these old versions, probably more or 
		   less indefinitely, because, particularly in the SCADA world they
		   continue to run zombie-like for eternity.  The only reason why
		   we're not still seeing Server 2000 occasionally is because it 
		   didn't do SCEP */
		if( status == CRYPT_ERROR_READ )
			{
			retExt( CRYPT_ERROR_OPEN,
					( CRYPT_ERROR_OPEN, SESSION_ERRINFO, 
					  "Server closed the connection in response to a SCEP "
					  "GetCACaps message, if this is Windows Server 2003 "
					  "or 2008 then you need to upgrade to at least Server "
					  "2008 R2 with the KB2483564 hotfix in order to talk "
					  "to the server" ) );
			}
		return( status );
		}

	/* Read the GetCACaps response lines.  Alongside the close-the-
	   connection bug in older versions of NDES, Microsoft still don't, as 
	   of Server 2022, advertise AES support in their GetCACaps message, 
	   sending only "POSTPKIOperation / Renewal / SHA-512 / SHA-256 / 
	   SHA-1 / DES3" for "Server: Microsoft-IIS/10.0", which covers 2016, 
	   2019, and 2022.
	   
	   In addition the "Renewal" isn't what you think, it's based on text 
	   that changed several times but finally stabilised in the 2009 draft 
	   as "An enrollment request that occurs more than halfway through the 
	   validity period of an existing certificate for the same subject name 
	   and key usage MAY be interpreted as a re-enrollment or renewal 
	   request and be accepted.  A new certificate with new validity dates 
	   can be issued, even though the old one is still valid, if the CA 
	   policy permits".  This text was last seen in the 2011 draft, and has
	   nothing to do with the RenewalReq message type.
	   
	   Since we rely on server fingerprinting (see the check at the start of 
	   clientTransact() below) we know that IIS 10 and newer support AES 
	   even if they don't advertise it, and without the bugs that it brings 
	   in Server 2012, so we don't perform any explicit checks for it here 
	   since it's done via fingerprinting */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, 
				 sessionInfoPtr->receiveBufEnd );
	LOOP_MED( lineCount = 0, 
			  lineCount < MAX_GETCACAPS_LINES && sMemDataLeft( &stream ) > 0, 
			  lineCount++ )
		{
		char buffer[ 512 + 8 ];
		LOOP_INDEX_ALT i;

		ENSURES( LOOP_INVARIANT_MED( lineCount, 0, MAX_GETCACAPS_LINES - 1 ) );

		/* Read the next CA capability */
		status = readTextLine( &stream, buffer, 512, &length, NULL, NULL, 
							   READTEXT_NONE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid GETCACaps response line %d", lineCount ) );
			}
		DEBUG_PRINT(( "GetCACaps: %s.\n", 
					  sanitiseString( buffer, 512, length ) )); 
		if( length < 3 || length > 16 )
			{
			/* It's not within the length range of "AES" ... 
			   "POSTPKIOperation" */
			continue;
			}

		/* Check whether it's something that we care about */
		LOOP_MED_ALT( i = 0, 
					  i < FAILSAFE_ARRAYSIZE( caCapsInfo, CACAPS_INFO ) && \
						  caCapsInfo[ i ].caCap != NULL,
					  i++ )
			{
			ENSURES( LOOP_INVARIANT_MED_ALT( i, 0, 
											 FAILSAFE_ARRAYSIZE( caCapsInfo, 
																 CACAPS_INFO ) - 1 ) );

			if( caCapsInfo[ i ].caCapSize == length && \
				!memcmp( caCapsInfo[ i ].caCap, buffer, length ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  caCapsInfo[ i ].caCapFlag );
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		}
	ENSURES( LOOP_BOUND_OK );
	sMemDisconnect( &stream );
	if( lineCount >= MAX_GETCACAPS_LINES )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Excessive number (more than %d) of GETCACaps response "
				  "lines", MAX_GETCACAPS_LINES ) );
		}

	/* We currently don't do much more with this, what the (effectively) 
	   dummy read does is allow us to fingerprint NDES so that we can work 
	   around its bugs later on */
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getCACertificate( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 INOUT_PTR SCEP_PROTOCOL_INFO *protocolInfo )
	{
	ERROR_INFO localErrorInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	REQUIRES( sessionInfoPtr->iAuthInContext == CRYPT_ERROR );

	/* Get the CA certificate */
	status = sendGetRequest( sessionInfoPtr, GETREQUEST_GETCACERT );
	if( cryptStatusError( status ) )
		return( status );

	/* Since we can't use readPkiDatagram() because of the weird dual-
	   purpose HTTP transport used in SCEP where the main protocol uses
	   POST + read response while the bolted-on portions use various GET
	   variations, we have to duplicate portions of readPkiDatagram() here.  
	   See the readPkiDatagram() function for code comments explaining the 
	   following operations */
	if( !isBufsizeRangeMin( sessionInfoPtr->receiveBufEnd, 4 ) )
		{
		retExt( CRYPT_ERROR_UNDERFLOW,
				( CRYPT_ERROR_UNDERFLOW, SESSION_ERRINFO, 
				  "Invalid SCEP CA certificate size %d", 
				  sessionInfoPtr->receiveBufEnd ) );
		}
	status = checkCertObjectEncodingLength( sessionInfoPtr->receiveBuffer, 
											sessionInfoPtr->receiveBufEnd,
											&sessionInfoPtr->receiveBufEnd );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid SCEP CA certificate encoding" ) );
		}
	DEBUG_DUMP_FILE( "scep_cacrt", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );

	/* Import the CA/RA certificates and save it/them for later use.  There
	   may be distinct signature and encryption certificates stuffed into 
	   the same chain so we first try for a signature certificate */
	clearErrorInfo( &localErrorInfo );
	status = importCACertificate( &sessionInfoPtr->iAuthInContext,
								  sessionInfoPtr->receiveBuffer, 
								  sessionInfoPtr->receiveBufEnd,
								  KEYMGMT_FLAG_USAGE_SIGN,
								  &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Invalid SCEP CA certificate" ) );
		}
	SET_FLAG( sessionInfoPtr->protocolFlags, SCEP_PFLAG_FETCHEDCACERT );

	/* Now that we've got a signing certificate, check whether this single
	   certificate has the unusual additional capabilities that are required
	   for SCEP */
	if( !checkSCEPCACert( sessionInfoPtr->iAuthInContext, 
						  KEYMGMT_FLAG_NONE ) )
		{
		/* It doesn't have the required capabilities, assume that it's a
		   signature-only certificate and try again for an encryption
		   certificate */
		status = importCACertificate( &sessionInfoPtr->iCryptOutContext,
									  sessionInfoPtr->receiveBuffer, 
									  sessionInfoPtr->receiveBufEnd,
									  KEYMGMT_FLAG_USAGE_CRYPT,
									  &localErrorInfo );
		if( cryptStatusError( status ) )
			{
			retExtErr( status, 
					   ( status, SESSION_ERRINFO, &localErrorInfo,
						 "Invalid SCEP CA certificate" ) );
			}
		
		/* Because of the vagaries of dealing with chains containing 
		   multiple certificates, with or without keyUsage extensions, the
		   certificate-import code returns a best-match certificate rather
		   than an absolute-match certificate.  In particular if there's 
		   only one certificate present and it doesn't have the encryption
		   keyUsage that we require, it'll be returned anyway since it's the
		   only certificate that can be returned.  In order to deal with 
		   this we have to check whether the certificates at the end of the
		   two chains are identical */
		if( isSameCertificate( sessionInfoPtr->iAuthInContext,
							   sessionInfoPtr->iCryptOutContext ) )
			{
			/* There's only one certificate and it's signature-only, use the
			   signature-only form of SCEP */
			krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_DECREFCOUNT );
			sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
			protocolInfo->caSignOnlyKey = TRUE;
			}
		}

	/* Process the server's key fingerprint */
	return( processKeyFingerprint( sessionInfoPtr ) );
	}

/* Check that the SCEP CA's certificate can be used for this run of the
   SCEP protocol */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkCACertificate( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR SCEP_PROTOCOL_INFO *protocolInfo )
	{
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
	char altCertName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Make sure that the CA certificate has the unusual additional 
	   capabilities that are required to meet the SCEP protocol 
	   requirements */
	if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
		{
		/* There are distinct encryption and signing certificates (probably
		   from an RA) present, make sure that they meet the necessary
		   requirements */
		if( !checkSCEPCACert( sessionInfoPtr->iAuthInContext, 
							  KEYMGMT_FLAG_USAGE_SIGN ) || \
			!checkSCEPCACert( sessionInfoPtr->iCryptOutContext, 
							  KEYMGMT_FLAG_USAGE_CRYPT ) )
			{
			retExt( CRYPT_ERROR_INVALID, 
					( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
					  "CA/RA certificate usage restrictions for '%s' and "
					  "'%s' prevent them from being used with SCEP",
					  getCertHolderName( sessionInfoPtr->iAuthInContext, 
										 certName, CRYPT_MAX_TEXTSIZE ),
					  getCertHolderName( sessionInfoPtr->iCryptOutContext, 
										 altCertName, 
										 CRYPT_MAX_TEXTSIZE ) ) );
			}

		return( CRYPT_OK );
		}

	/* There's a single multipurpose certificate present, make sure that it 
	   meets all of the requirements for SCEP use */
	if( !checkSCEPCACert( sessionInfoPtr->iAuthInContext, 
						  protocolInfo->caSignOnlyKey ? \
							KEYMGMT_FLAG_USAGE_SIGN : \
							KEYMGMT_FLAG_NONE ) )
		{
		retExt( CRYPT_ERROR_INVALID, 
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "CA certificate usage restrictions for '%s' prevent it "
				  "from being used with SCEP",
				  getCertHolderName( sessionInfoPtr->iAuthInContext, 
									 certName, CRYPT_MAX_TEXTSIZE ) ) );
		}

	/* If the CA has a signature-only key then some additional conditions 
	   need to be met */
	if( protocolInfo->caSignOnlyKey )
		{
		/* Some older SCEP implementations can't handle portions of the full 
		   SCEP standard, if we're going to be using that then make sure the
		   implementation can handle it */
		if( !TEST_FLAG( sessionInfoPtr->protocolFlags, \
						SCEP_PFLAG_SCEPSTANDARD ) )
			{
			retExt( CRYPT_ERROR_INVALID, 
					( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
					  "SCEP CA certificate for '%s' isn't valid for "
					  "encryption and the server can't handle SCEPStandard "
					  "signature-only messages",
					  getCertHolderName( sessionInfoPtr->iAuthInContext, 
										 certName, CRYPT_MAX_TEXTSIZE ) ) );
			}

		/* Since the CA's certificate can't be used to encrypt the 
		   messaging, the user has to have provided an encryption password.
		   This is normally the case since it's required for enrolment but
		   it's optional for certificate renewal */
		if( findSessionInfo( sessionInfoPtr, \
							 CRYPT_SESSINFO_PASSWORD ) == NULL )
			{
			retExt( CRYPT_ERROR_NOTINITED,
					( CRYPT_ERROR_NOTINITED, SESSION_ERRINFO,
					  "CA certificate is signature-only so SCEP requires a "
					  "user password to encrypt messages" ) );
			}
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Request Management Functions						*
*																			*
****************************************************************************/

/* Create a self-signed certificate for signing the request and decrypting
   the response */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createScepCert( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   INOUT_PTR SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iNewCert;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	time_t currentTime = getTime( GETTIME_MINUTES );
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionSCEP( sessionInfoPtr ) );

	/* Create a certificate, add the certificate request and other 
	   information required by SCEP to it, and sign it.  To limit the 
	   exposure from having it floating around out there we give it a 
	   validity of a day, which is somewhat longer than required but may be 
	   necessary to get around time-zone issues in which the CA checks the 
	   expiry time relative to the time zone that it's in rather than GMT 
	   (although given some of the broken certificates used with SCEP it 
	   seems likely that many CAs do little to no checking at all).
	   
	   SCEP formerly required that the certificate serial number matched the 
	   user name/transaction ID, the spec also said that the transaction ID 
	   should be a hash of the public key but since it never specified 
	   exactly what was hashed ("MD5 hash on [sic] public key") so this could 
	   probably be anything.  We used the user name, which was required to 
	   identify the pkiUser entry in the CA certificate store, but since 
	   this requirement has been removed in the final RFC we don't bother 
	   any more.  Since no-one ever checked it anyway even when it was still
	   required, this shouldn't be a problem even when talking to older
	   implementations */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &sessionInfoPtr->iCertRequest,
							  CRYPT_CERTINFO_CERTREQUEST );
	if( cryptStatusOK( status ) )
		{
		/* Set the certificate usage to signing (to sign the request) and
		   encryption (to decrypt the response, if the key is capable of
		   this).  We've already checked that the sign capability was
		   available when the key was added to the session.
		   
		   We delete the attribute before we try and set it in case there 
		   was already one present in the request */
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_DELETEATTRIBUTE, 
						 NULL, CRYPT_CERTINFO_KEYUSAGE );
		if( protocolInfo->clientSignOnlyKey )
			{
			static const int keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE;

			status = krnlSendMessage( createInfo.cryptHandle, 
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &keyUsage, 
									  CRYPT_CERTINFO_KEYUSAGE );
			}
		else
			{
			static const int keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
										CRYPT_KEYUSAGE_KEYENCIPHERMENT;

			status = krnlSendMessage( createInfo.cryptHandle, 
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &keyUsage, 
									  CRYPT_CERTINFO_KEYUSAGE );
			}
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( MESSAGE_CAST ) &currentTime, 
						sizeof( time_t ) );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_VALIDFROM );
		}
	if( cryptStatusOK( status ) )
		{
		currentTime += 86400;	/* 24 hours */
		setMessageData( &msgData, ( MESSAGE_CAST ) &currentTime, 
						sizeof( time_t ) );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE,
								  CRYPT_CERTINFO_SELFSIGNED );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_CRT_SIGN, NULL,
								  sessionInfoPtr->privateKey );
		}
	if( cryptStatusError( status ) )
		{
#ifdef USE_ERRMSGS
		ERROR_INFO localErrorInfo;
#endif /* USE_ERRMSGS */

		status = readErrorInfo( &localErrorInfo, createInfo.cryptHandle );
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptStatusOK( status ) )
			{
			/* We got extended error information on why the create failed,
			   return that alongside the overall message */
			retExtErr( status,
					   ( status, SESSION_ERRINFO, &localErrorInfo,
						 "Couldn't create ephemeral self-signed SCEP "
						 "certificate" ) );
			}
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create ephemeral self-signed SCEP "
				  "certificate" ) );
		}

	/* Now that we have a certificate, temporarily attach it to the private 
	   key in order to allow later decryption of the CA's response.  This is 
	   somewhat ugly since it alters the private key object by constraining 
	   the private-key actions to make them internal-only since it now has a 
	   certificate attached, hopefully the user won't notice this since it 
	   should only be used for the SCEP request.

	   To further complicate things, we can't directly attach the newly-
	   created certificate because it already has a public-key context 
	   attached to it, which would result in two keys being associated with 
	   the single certificate.  To resolve this, we create a copy of the 
	   certificate as a data-only certificate and attach that to the private 
	   key instead of the full certificate+context */
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_GETATTRIBUTE, 
							  &iNewCert, CRYPT_IATTRIBUTE_CERTCOPY_DATAONLY );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sessionInfoPtr->privateKey, 
								  IMESSAGE_SETDEPENDENT, &iNewCert, 
								  SETDEP_OPTION_NOINCREF );
		}
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Complete the user-supplied PKCS #10 request by adding SCEP-internal
   attributes and information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completeScepCertRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD );
	MESSAGE_DATA msgData;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSCEP( sessionInfoPtr ) );

	/* Add the password to the PKCS #10 request as a ChallengePassword
	   attribute.  We always send this in its ASCII string form even if it's 
	   an encoded value because the ChallengePassword attribute has to be a 
	   text string */
	if( attributeListPtr != NULL )
		{
		INJECT_FAULT( CORRUPT_AUTHENTICATOR, 
					  SESSION_CORRUPT_AUTHENTICATOR_SCEP_1 );
		setMessageData( &msgData, attributeListPtr->value,
						attributeListPtr->valueLength );
		status = krnlSendMessage( sessionInfoPtr->iCertRequest, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_CHALLENGEPASSWORD );
		INJECT_FAULT( CORRUPT_AUTHENTICATOR, 
					  SESSION_CORRUPT_AUTHENTICATOR_SCEP_2 );
		if( cryptStatusError( status ) )
			{
			retExtObj( status,
					   ( status, SESSION_ERRINFO, 
					     sessionInfoPtr->iCertRequest,
					     "Couldn't finalise SCEP PKCS #10 certificate "
						 "request for '%s'",
						 getCertHolderName( sessionInfoPtr->iCertRequest, 
											certName, 
											CRYPT_MAX_TEXTSIZE ) ) );
			}
		}

	/* Sign the request */
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_CRT_SIGN, NULL,
							  sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		{
		retExtObj( status,
				   ( status, SESSION_ERRINFO, sessionInfoPtr->iCertRequest,
					 "Couldn't sign SCEP PKCS #10 certificate request "
					 "for '%s'",
					 getCertHolderName( sessionInfoPtr->iCertRequest, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}

	return( CRYPT_OK );
	}

/* Create the request type needed to continue after the server responds with
   an issue-pending response:

	issuerAndSubject ::= SEQUENCE {
		issuer		Name,
		subject		Name
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int createScepPendingRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
									 OUT_LENGTH_SHORT_Z int *dataLength )
	{
	STREAM stream;
	int issuerAndSubjectLen DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	/* Clear return value */
	*dataLength = 0;

	/* Determine the overall length of the issuer and subject DNs */
	sMemNullOpen( &stream );
	status = exportAttributeToStream( &stream, 
									  sessionInfoPtr->iAuthInContext, 
									  CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusOK( status ) )
		{
		status = exportAttributeToStream( &stream, 
										  sessionInfoPtr->iCertRequest, 
										  CRYPT_IATTRIBUTE_SUBJECT );
		}
	if( cryptStatusOK( status ) )
		issuerAndSubjectLen = stell( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( issuerAndSubjectLen ) );

	/* Write the issuerAndSubject to the session buffer */
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 
			  sessionInfoPtr->receiveBufSize );
	writeSequence( &stream, issuerAndSubjectLen );
	status = exportAttributeToStream( &stream, 
									  sessionInfoPtr->iAuthInContext, 
									  CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusOK( status ) )
		{
		status = exportAttributeToStream( &stream, 
										  sessionInfoPtr->iCertRequest, 
										  CRYPT_IATTRIBUTE_SUBJECT );
		}
	if( cryptStatusOK( status ) )
		*dataLength = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

/* Create a SCEP request message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createScepRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR SCEP_PROTOCOL_INFO *protocolInfo )
	{
	const SCEP_INFO *scepInfo = sessionInfoPtr->sessionSCEP;
	const CRYPT_CERTIFICATE iCACryptContext = \
		( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR ) ? \
		sessionInfoPtr->iCryptOutContext : sessionInfoPtr->iAuthInContext;
	CRYPT_CERTIFICATE iCmsAttributes;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	const BOOLEAN isPendingRequest = TEST_FLAG( sessionInfoPtr->protocolFlags, 
												SCEP_PFLAG_PENDING ) ? \
									 TRUE : FALSE;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionSCEP( sessionInfoPtr ) );

	/* If it's a straight issue operation, extract the request data into the 
	   session buffer */
	if( !isPendingRequest )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
						sessionInfoPtr->receiveBufSize );
		status = krnlSendMessage( sessionInfoPtr->iCertRequest,
								  IMESSAGE_CRT_EXPORT, &msgData,
								  CRYPT_CERTFORMAT_CERTIFICATE );
		if( cryptStatusError( status ) )
			{
			retExtObj( status,
					   ( status, SESSION_ERRINFO, 
					     sessionInfoPtr->iCertRequest,
						 "Couldn't get PKCS #10 request data from SCEP "
						 "request object for '%s'",
						 getCertHolderName( sessionInfoPtr->iCertRequest, 
											certName, 
											CRYPT_MAX_TEXTSIZE ) ) );
			}
		dataLength = msgData.length;
		}
	else
		{
		/* It's a continuation of a previous issue operation whose status 
		   the server has reported as pending, encode the special-case form
		   that's required for this operation */
		status = createScepPendingRequest( sessionInfoPtr, &dataLength );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Couldn't create SCEP request needed to continue from "
					  "an issue-pending response" ) );
			}
		}
	DEBUG_DUMP_FILE( isPendingRequest ? "scep_req0pend" : "scep_req0", 
					 sessionInfoPtr->receiveBuffer, dataLength );

	/* Phase 1: Encrypt the data using either the CA's key or the client's
	   password.  If this is a broken Microsoft server it may be necessary
	   to add functionality like:

		static const int algo3DES = CRYPT_ALGO_3DES;	// enum vs.int

		status = krnlSendMessage( iCryptEnvelope, IMESSAGE_SETATTRIBUTE,
								  ( MESSAGE_CAST ) &algo3DES,
								  CRYPT_OPTION_ENCR_ALGO );

	   to envelopeWrap() */
	clearErrorInfo( &localErrorInfo );
	if( protocolInfo->caSignOnlyKey )
		{
		const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD );

		REQUIRES( attributeListPtr != NULL );

		status = envelopeWrap( sessionInfoPtr->receiveBuffer, dataLength,
							   sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufSize, &dataLength, 
							   CRYPT_FORMAT_CMS, CRYPT_CONTENT_NONE, 
							   CRYPT_UNUSED, attributeListPtr->value, 
							   attributeListPtr->valueLength, 
							   &localErrorInfo );
		}
	else
		{
		status = envelopeWrap( sessionInfoPtr->receiveBuffer, dataLength,
							   sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufSize, &dataLength, 
							   CRYPT_FORMAT_CMS, CRYPT_CONTENT_NONE, 
							   iCACryptContext, NULL, 0, &localErrorInfo );
		}
	if( cryptStatusError( status ) )
		{
		if( protocolInfo->caSignOnlyKey )
			{
			retExtErr( status,
					   ( status, SESSION_ERRINFO, &localErrorInfo,
						 "Couldn't encrypt SCEP request data with user "
						 "password" ) );
			}
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't encrypt SCEP request data with CA public "
					 "key for '%s'",
					 getCertHolderName( iCACryptContext, certName, 
										CRYPT_MAX_TEXTSIZE ) ) );
		}
	DEBUG_DUMP_FILE( isPendingRequest ? "scep_req1pend" : "scep_req1", 
					 sessionInfoPtr->receiveBuffer, dataLength );

	/* Create the SCEP signing attributes */
	status = createScepAttributes( sessionInfoPtr, protocolInfo,  
					&iCmsAttributes, isPendingRequest ? \
						MESSAGETYPE_GETCERTINITIAL : \
					( scepInfo->requestType == CRYPT_REQUESTTYPE_INITIALISATION ) ? \
						MESSAGETYPE_PKCSREQ : MESSAGETYPE_RENEWAL, 
					CRYPT_OK );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create SCEP request signing attributes" ) );
		}

	/* Phase 2: Sign the data using the self-signed certificate and SCEP 
	   attributes */
	status = envelopeSign( sessionInfoPtr->receiveBuffer, dataLength,
						   sessionInfoPtr->receiveBuffer, 
						   sessionInfoPtr->receiveBufSize, 
						   &sessionInfoPtr->receiveBufEnd, 
						   CRYPT_CONTENT_NONE, sessionInfoPtr->privateKey, 
						   iCmsAttributes, &localErrorInfo );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't sign request data with ephemeral SCEP "
					 "certificate" ) );
		}
	DEBUG_DUMP_FILE( isPendingRequest ? "scep_req2pend" : "scep_req2", 
					 sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Response Management Functions						*
*																			*
****************************************************************************/

/* Check the status of a SCEP response */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkScepStatus( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							IN_HANDLE const CRYPT_CERTIFICATE iCmsAttributes )
	{
	typedef struct {
		const int failInfoValue;
		const int failStatus;
		const char *failInfoString;
		} FAILINFO_MESSAGE;
	static const FAILINFO_MESSAGE failInfoMsgTbl[] = {
		{ MESSAGEFAILINFO_BADALG_VALUE, CRYPT_ERROR_NOTAVAIL,
		  "Unrecognized or unsupported algorithm identifier" },
		{ MESSAGEFAILINFO_BADMESSAGECHECK_VALUE, CRYPT_ERROR_SIGNATURE,
		  "Integrity check failed" },
		{ MESSAGEFAILINFO_BADREQUEST_VALUE, CRYPT_ERROR_PERMISSION,
		  "Transaction not permitted or supported" },
		{ MESSAGEFAILINFO_BADTIME_VALUE, CRYPT_ERROR_INVALID,
		  "CMS signingTime attribute was not sufficiently close to the "
		  "system time" },
		{ MESSAGEFAILINFO_BADCERTID_VALUE, CRYPT_ERROR_NOTFOUND,
		  "No certificate could be identified matching the provided "
		  "criteria" },
		{ CRYPT_ERROR, CRYPT_ERROR_FAILED, "<Unknown failure reason>" },
			{ CRYPT_ERROR, CRYPT_ERROR_FAILED, "<Unknown failure reason>" }
		};
	LOOP_INDEX i;
	int value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCmsAttributes ) );

	/* Make sure that we've got the correct response type */
	status = getScepStatusValue( iCmsAttributes,
								 CRYPT_CERTINFO_SCEP_MESSAGETYPE, &value );
	if( cryptStatusError( status ) )
		{
		/* Make sure that we fail the following test, this allows us to 
		   report an incorrect value without having to have two separate 
		   error message handlers for this simple case */
		value = MESSAGETYPE_VALUE_NONE;
		}
	if( value != MESSAGETYPE_CERTREP_VALUE )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid SCEP response type %d, expected %d", 
				  value, MESSAGETYPE_CERTREP_VALUE ) );
		}

	/* Check the status of the operation */
	status = getScepStatusValue( iCmsAttributes, 
								 CRYPT_CERTINFO_SCEP_PKISTATUS, &value );
	if( cryptStatusError( status ) )
		value = MESSAGESTATUS_FAILURE_VALUE;
	if( value == MESSAGESTATUS_SUCCESS_VALUE )
		return( CRYPT_OK );

	/* There was a problem with the operation, get more detailed information
	   on what went wrong.  If we get a MESSAGESTATUS_PENDING result then we 
	   can't go any further until the CA makes up its mind about issuing us 
	   a certificate */
	if( value == MESSAGESTATUS_PENDING_VALUE )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, SCEP_PFLAG_PENDING );
		retExt( CRYPT_ENVELOPE_RESOURCE, 
				( CRYPT_ENVELOPE_RESOURCE, SESSION_ERRINFO, 
				  "SCEP server reports that certificate status is "
				  "pending, try again later" ) );
		}

	/* It's some other sort of error, report the details to the user */
	status = getScepStatusValue( iCmsAttributes, 
								 CRYPT_CERTINFO_SCEP_FAILINFO, &value );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_FAILED, 
				( CRYPT_ERROR_FAILED, SESSION_ERRINFO, 
				  "SCEP server reports that certificate issue operation "
				  "failed, no further information available" ) );
		}
	LOOP_SMALL( i = 0,
				i < FAILSAFE_ARRAYSIZE( failInfoMsgTbl, \
										FAILINFO_MESSAGE ) && \
					failInfoMsgTbl[ i ].failInfoValue != value && \
					failInfoMsgTbl[ i ].failInfoValue != CRYPT_ERROR,
				i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
									   FAILSAFE_ARRAYSIZE( failInfoMsgTbl, \
														   FAILINFO_MESSAGE ) - 1 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( failInfoMsgTbl, FAILINFO_MESSAGE ) );
	retExt( failInfoMsgTbl[ i ].failStatus, 
			( failInfoMsgTbl[ i ].failStatus, SESSION_ERRINFO, 
			  "SCEP server reports that certificate issue operation "
			  "failed with error code %d (%s)", value, 
			  failInfoMsgTbl[ i ].failInfoString ) );
	}

/* Check a SCEP response message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkScepResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
							  INOUT_PTR SCEP_PROTOCOL_INFO *protocolInfo )
	{
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME );
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	ERROR_INFO localErrorInfo;
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int dataLength, sigResult, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionSCEP( sessionInfoPtr ) );
	REQUIRES( userNamePtr != NULL );

	/* Reset any issue-pending status that may have been set from a previous
	   operation */
	CLEAR_FLAG( sessionInfoPtr->protocolFlags, SCEP_PFLAG_PENDING );

	/* Phase 1: Sig-check the data using the CA's key.  We allow an empty 
	   message body which may be sent for error responses */
	DEBUG_DUMP_FILE( "scep_resp2", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );
	clearErrorInfo( &localErrorInfo );
	status = envelopeSigCheck( sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufEnd,
							   sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufSize, &dataLength, 
							   sessionInfoPtr->iAuthInContext, 
							   ENVELOPE_OPTION_EMPTYOK, &sigResult,
							   NULL, &iCmsAttributes, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Invalid CMS signed data in SCEP CA response" ) );
		}
	DEBUG_DUMP_FILE_OPT( "scep_resp1", sessionInfoPtr->receiveBuffer, 
						 dataLength );	/* May be zero len.if error status */
	if( cryptStatusError( sigResult ) )
		{
		/* The signed data was valid but the signature on it wasn't, this is
		   a different style of error than the previous one */
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sigResult, 
				( sigResult, SESSION_ERRINFO, 
				  "SCEP CA response data signature check with key '%s' "
				  "failed",
				  getCertHolderName( sessionInfoPtr->iAuthInContext, 
									 certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	CFI_CHECK_UPDATE( "envelopeSigCheck" );

	/* Check that the returned transaction ID matches our transaction ID */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_TRANSACTIONID );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_NOTFOUND,
				( CRYPT_ERROR_NOTFOUND, SESSION_ERRINFO, 
				  "Missing SCEP transaction ID in server response" ) );
		}
	if( msgData.length != userNamePtr->valueLength || \
		memcmp( buffer, userNamePtr->value, userNamePtr->valueLength ) )
		{
#ifdef USE_ERRMSGS
		char userNameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
		char transIDText[ CRYPT_MAX_TEXTSIZE + 8 ];
		int userNameLen;
#endif /* USE_ERRMSGS */

		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
#ifdef USE_ERRMSGS
		userNameLen = min( userNamePtr->valueLength, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( userNameLen, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( userNameBuffer, userNamePtr->value, userNameLen );
		formatHexData( transIDText, CRYPT_MAX_TEXTSIZE, buffer, 
					   msgData.length );
#endif /* USE_ERRMSGS */
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Returned SCEP transaction ID '%s' doesn't match our "
				  "original transaction ID '%s'", transIDText,
				  sanitiseString( userNameBuffer, CRYPT_MAX_TEXTSIZE, 
								  userNamePtr->valueLength ) ) );
		}

	/* Check that the returned nonce matches our initial nonce.  It's now
	   identified as a recipient nonce since it's coming from the 
	   responder.  This is somewhat superfluous given that the transactionID
	   serves the same purpose, but we check it because it's in the spec */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_RECIPIENTNONCE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_NOTFOUND,
				( CRYPT_ERROR_NOTFOUND, SESSION_ERRINFO, 
				  "Missing SCEP nonce in server response" ) );
		}
	if( msgData.length != protocolInfo->nonceSize || \
		memcmp( buffer, protocolInfo->nonce, protocolInfo->nonceSize ) )
		{
#ifdef USE_ERRMSGS
		char clientNonceText[ CRYPT_MAX_TEXTSIZE + 8 ];
		char serverNonceText[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */

		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
#ifdef USE_ERRMSGS
		formatHexData( clientNonceText, CRYPT_MAX_TEXTSIZE, 
					   protocolInfo->nonce, protocolInfo->nonceSize );
		formatHexData( serverNonceText, CRYPT_MAX_TEXTSIZE, 
					   buffer, msgData.length );
#endif /* USE_ERRMSGS */
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Returned SCEP nonce '%s' doesn't match our original "
				  "nonce '%s'", serverNonceText, serverNonceText ) );
		}
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* Check that the operation succeeded */
	status = checkScepStatus( sessionInfoPtr, iCmsAttributes );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkScepStatus" );

	/* Check that there's a message body present.  This is necessary because 
	   an error response can have an empty body so the envelope signature
	   check is done with ENVELOPE_OPTION_EMPTYOK, which means that we could
	   get here with no message body to unwrap, which will be rejected by the
	   sanity check in envelopeUnwrap() */
	if( dataLength < 16 )
		return( CRYPT_ERROR_BADDATA );

	/* Phase 2: Decrypt the data using either our self-signed key or our
	   password */
	if( protocolInfo->clientSignOnlyKey )
		{
		const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD );

		REQUIRES( attributeListPtr != NULL );

		status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, dataLength,
								 sessionInfoPtr->receiveBuffer, 
								 sessionInfoPtr->receiveBufSize, &dataLength, 
								 CRYPT_UNUSED, attributeListPtr->value, 
								 attributeListPtr->valueLength, 
								 &localErrorInfo );
		}
	else
		{
		status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, dataLength,
								 sessionInfoPtr->receiveBuffer, 
								 sessionInfoPtr->receiveBufSize, &dataLength, 
								 sessionInfoPtr->privateKey, NULL, 0, 
								 &localErrorInfo );
		}
	if( cryptStatusError( status ) )
		{
		registerCryptoFailure();
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't decrypt CMS enveloped data in SCEP CA "
					 "response" ) );
		}
	DEBUG_DUMP_FILE( "scep_resp0", sessionInfoPtr->receiveBuffer, 
					 dataLength );
	CFI_CHECK_UPDATE( "envelopeUnwrap" );

	/* Finally, import the returned certificate(s) as a CMS certificate 
	   chain */
	setMessageCreateObjectIndirectInfo( &createInfo,
								sessionInfoPtr->receiveBuffer, dataLength,
								CRYPT_CERTTYPE_CERTCHAIN, &localErrorInfo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Invalid certificate chain in SCEP CA response" ) );
		}
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;
	CFI_CHECK_UPDATE( "IMESSAGE_DEV_CREATEOBJECT_INDIRECT" );

	ENSURES( CFI_CHECK_SEQUENCE_5( "envelopeSigCheck",
								   "IMESSAGE_GETATTRIBUTE_S", "checkScepStatus",
								   "envelopeUnwrap",
								   "IMESSAGE_DEV_CREATEOBJECT_INDIRECT" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							SCEP Client Functions							*
*																			*
****************************************************************************/

/* Exchange data with a SCEP server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientTransact( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	SCEP_PROTOCOL_INFO protocolInfo;
	SCEP_INFO *scepInfo = sessionInfoPtr->sessionSCEP;
	STREAM_PEER_TYPE peerSystemType;
	const BOOLEAN isPendingRequest = TEST_FLAG( sessionInfoPtr->protocolFlags, 
												SCEP_PFLAG_PENDING ) ? \
									 TRUE : FALSE;
	BOOLEAN sendPostAsGet = FALSE, signOnlyKey = FALSE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSCEP( sessionInfoPtr ) );

	/* If the user hasn't explicitly set a request type, default to an 
	   initialisation request */
	if( scepInfo->requestType == CRYPT_REQUESTTYPE_NONE )
		scepInfo->requestType = CRYPT_REQUESTTYPE_INITIALISATION;

	/* Check whether the client's key is signature-only, in which case we 
	   need to have a password present to decrypt the CA's response */
	if( !checkContextCapability( sessionInfoPtr->privateKey, 
								 MESSAGE_CHECK_PKC_DECRYPT ) )
		{
		/* Since the key isn't encryption-capable we need a password to
		   encrypt the messaging */
		if( findSessionInfo( sessionInfoPtr, 
							 CRYPT_SESSINFO_PASSWORD ) == NULL )
			{
			retExt( CRYPT_ERROR_NOTINITED,
					( CRYPT_ERROR_NOTINITED, SESSION_ERRINFO,
					  "Use of a signature-only key requires a user password "
					  "to encrypt messages" ) );
			}

		/* Remember that this is a non-encryption key for when we need to 
		   perform encrypted messaging */
		signOnlyKey = TRUE;
		}

	/* Try and find out which extended SCEP capabilities the CA supports */
	if( !TEST_FLAG( sessionInfoPtr->protocolFlags, SCEP_PFLAG_GOTCACAPS ) )
		{
		/* The returned status from getCACapabilities() isn't currently 
		   used, the only system for which we need it is Microsoft's NDES 
		   and that has a broken implementation of it unless the exact 
		   conditions given in the long comment in getCACapabilities() are 
		   met, a nice catch-22 where we can't identify the broken system 
		   because the mechanism used to identify its brokenness is in turn 
		   broken.
		   
		   We do however use the function side-effects indirectly by using 
		   the HTTP GET that's sent to fingerprint the remote server, which 
		   (usually) allows us to tell whether we're talking to NDES */
		( void ) getCACapabilities( sessionInfoPtr );
		
		/* We've got the CA capabilities, don't try and read them again */
		SET_FLAG( sessionInfoPtr->protocolFlags, SCEP_PFLAG_GOTCACAPS );
		}
	CFI_CHECK_UPDATE( "getCACapabilities" );

	/* See whether we can determine the remote system type, used to work 
	   around bugs in implementations (all of which are currently from
	   Microsoft).  See the comment in getCACapabilities() on why we still
	   need to support apparently-defunct NDES versions */
	status = sioctlGet( &sessionInfoPtr->stream, STREAM_IOCTL_GETPEERTYPE, 
						&peerSystemType, sizeof( STREAM_PEER_TYPE ) );
	if( cryptStatusOK( status ) && peerSystemType != STREAM_PEER_NONE )
		{
		switch( peerSystemType )
			{
			case STREAM_PEER_MICROSOFT:
			case STREAM_PEER_MICROSOFT_2008:
				/* Older versions of NDES/Microsoft don't support HTTP POST, 
				   but then they also don't have a working implementation of 
				   GetCACaps that would indicate that they don't support 
				   HTTP POST either */
				sendPostAsGet = TRUE;
				break;

			case STREAM_PEER_MICROSOFT_2012:
				/* This server version has a different set of bugs, it 
				   now supports GetCACaps but silently switches to OAEP when 
				   AES is used.  If we're not running a custom build with 
				   OAEP enabled then we probably won't be able to continue 
				   later so we provide a warning about this now.
				   
				   In addition it now supports HTTP POST, but returns a
				   zero-length response as an "HTTP/1.1 200 OK"-status 
				   message in response to a POSTed request, so we still need 
				   to rely on HTTP GET to communicate with it */
#ifndef USE_OAEP
				DEBUG_PUTS(( "Peer is Server 2012, if decryption of the "
							 "returned message fails then this is due to "
							 "the server erroneously using OAEP in its "
							 "response" ));
#endif /* USE_OAEP */
				sendPostAsGet = TRUE;
				break;

			case STREAM_PEER_MICROSOFT_2019:
				/* This server now finally supports HTTP POST properly as
				   indicated in the GetCACaps response */
				break;

			default:
				retIntError();
			}
		}

	/* Get the issuing CA certificate via SCEP's bolted-on HTTP GET facility 
	   if necessary and make sure that it's usable for SCEP */
	initSCEPprotocolInfo( &protocolInfo );
	if( sessionInfoPtr->iAuthInContext == CRYPT_ERROR )
		{
		status = getCACertificate( sessionInfoPtr, &protocolInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = checkCACertificate( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );
	protocolInfo.clientSignOnlyKey = signOnlyKey;
	CFI_CHECK_UPDATE( "initSCEPprotocolInfo" );

	/* If this is an initialisation request, if we're not still waiting for 
	   a previous pending issue operation to complete complete the PKCS #10 
	   request by adding the required SCEP attributes and signing it, and 
	   then create the self-signed certificate that we need in order to sign 
	   and decrypt messages.  We create a new certificate each time both 
	   because it's only an ephemeral certificate and gets deleted after being
	   used to sign the request and because, at least in theory, the pending-
	   issue wait could be longer than the lifetime of the ephemeral 
	   certificate */
	if( scepInfo->requestType == CRYPT_REQUESTTYPE_INITIALISATION ) 
		{
		if( !isPendingRequest )
			status = completeScepCertRequest( sessionInfoPtr );
		if( cryptStatusOK( status ) )
			status = createScepCert( sessionInfoPtr, &protocolInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "createScepCert" );

	/* Request a new certificate from the server.  Once we've done that we need
	   to unhook the temporary self-signed certificate from the private key 
	   since the caller won't be expecting this to be there */
	status = createScepRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		{
#ifdef USE_BASE64
		if( sendPostAsGet )
			status = writePkiDatagramAsGet( sessionInfoPtr );
		else
#endif /* USE_BASE64 */
			{
			status = writePkiDatagramEx( sessionInfoPtr, SCEP_CONTENTTYPE,
										 SCEP_CONTENTTYPE_LEN );
			}
		}
	if( cryptStatusError( status ) )
		{
		if( scepInfo->requestType == CRYPT_REQUESTTYPE_INITIALISATION ) 
			{
			/* Clean up the temporary certificate created in 
			   createScepCert() */
			krnlSendNotifier( sessionInfoPtr->privateKey, 
							  IMESSAGE_CLEARDEPENDENT );
			}
		return( status );
		}

	/* Read back the newly-issued certificate from the server */
	status = readPkiDatagram( sessionInfoPtr, MIN_CRYPT_OBJECTSIZE,
							  MK_ERRTEXT( "Couldnt read SCEP server "
										  "response" ) );
	if( cryptStatusOK( status ) )
		status = checkScepResponse( sessionInfoPtr, &protocolInfo );
	if( scepInfo->requestType == CRYPT_REQUESTTYPE_INITIALISATION ) 
		{
		/* Clean up the temporary certificate created in createScepCert() */
		krnlSendNotifier( sessionInfoPtr->privateKey, 
						  IMESSAGE_CLEARDEPENDENT );
		}
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkScepResponse" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "getCACapabilities", "initSCEPprotocolInfo", 
								   "createScepCert", "checkScepResponse" ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientTransactWrapper( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSCEP( sessionInfoPtr ) );

	/* If it's not a plug-and-play PKI session, just pass the call on down
	   to the client transaction function */
	if( !TEST_FLAG( sessionInfoPtr->protocolFlags, SCEP_PFLAG_PNPPKI ) )
		return( clientTransact( sessionInfoPtr ) );

	/* We're doing plug-and-play PKI, point the transaction function at the 
	   client-transact function to execute the PnP steps, then reset it back 
	   to the PnP wrapper after we're done */
	FNPTR_SET( sessionInfoPtr->transactFunction, clientTransact );
	status = pnpPkiSession( sessionInfoPtr );
	FNPTR_SET( sessionInfoPtr->transactFunction, clientTransactWrapper );
	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initSCEPclientProcessing( SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	FNPTR_SET( sessionInfoPtr->transactFunction, clientTransactWrapper );
	}
#endif /* USE_SCEP */
