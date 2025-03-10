/****************************************************************************
*																			*
*						 cryptlib TSP Session Management					*
*						Copyright Peter Gutmann 1999-2011					*
*																			*
****************************************************************************/

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

#ifdef USE_TSP

/* TSP constants */

#define TSP_VERSION					1	/* Version number */
#define MIN_MSGIMPRINT_SIZE			( 2 + 10 + 16 )	/* SEQ + MD5 OID + MD5 hash */
#define MAX_MSGIMPRINT_SIZE			( 32 + CRYPT_MAX_HASHSIZE )

/* TSP HTTP content types */

#define TSP_CONTENT_TYPE_REQ		"application/timestamp-query"
#define TSP_CONTENT_TYPE_REQ_LEN	27
#define TSP_CONTENT_TYPE_RESP		"application/timestamp-reply"
#define TSP_CONTENT_TYPE_RESP_LEN	27

/* TSP protocol state information.  This is passed around the various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	/* TSP protocol control information.  The hashAlgo is usually unset (so 
	   it has a value of CRYPT_ALGO_NONE) but may be set if the client has
	   indicated that they want to use a stronger hash algorithm than the 
	   default one */
	CRYPT_ALGO_TYPE hashAlgo;			/* Optional hash algorithm for TSA resp.*/
	BOOLEAN includeSigCerts;			/* Whether to include signer certificates */

	/* TSP request/response data */
	BUFFER( MAX_MSGIMPRINT_SIZE, msgImprintSize ) \
	BYTE msgImprint[ MAX_MSGIMPRINT_SIZE + 8 ];
	int msgImprintSize;					/* Message imprint */
	BUFFER( CRYPT_MAX_HASHSIZE, nonceSize ) \
	BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];
	int nonceSize;						/* Nonce (if present) */

	} TSP_PROTOCOL_INFO;

/* Prototypes for functions in cmp_rd.c.  This code is shared due to TSP's use
   of random elements cut & pasted from CMP */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
int readPkiStatusInfo( INOUT_PTR STREAM *stream, 
					   IN_BOOL const BOOLEAN isServer,
					   IN_BOOL const BOOLEAN isUnauthenticated,
					   INOUT_PTR ERROR_INFO *errorInfo );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the session state */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheckSessionTSP( IN_PTR \
										const SESSION_INFO *sessionInfoPtr )
	{
	const TSP_INFO *tspInfo = sessionInfoPtr->sessionTSP;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( tspInfo, sizeof( TSP_INFO ) ) );

	/* Check the general envelope state */
	if( !sanityCheckSession( sessionInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionTSP: Session check" ));
		return( FALSE );
		}

	/* Check TSP session parameters */
	if( ( tspInfo->imprintAlgo != CRYPT_ALGO_NONE && \
		  !isHashAlgo( tspInfo->imprintAlgo ) ) || \
		tspInfo->imprintSize < 0 || \
		tspInfo->imprintSize > CRYPT_MAX_HASHSIZE )
		{
		DEBUG_PUTS(( "sanityCheckSessionTSP: Session parameters" ));
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheckTSPProtocolInfo( IN_PTR \
									const TSP_PROTOCOL_INFO *protocolInfo )
	{
	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Read a TSP request:

	TSARequest ::= SEQUENCE {
		version				INTEGER (1),
		msgImprint			MessageDigest,
		policy				OBJECT IDENTIFIER OPTIONAL,
												-- Ignored
		nonce				INTEGER OPTIONAL,	-- Copy to output if present
		includeSigCerts		BOOLEAN DEFAULT FALSE,
												-- Include signer certs if set
		extensions		[0]	Extensions OPTIONAL	-- Ignored, see below
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
static int readTSPRequest( INOUT_PTR STREAM *stream, 
						   INOUT_PTR TSP_PROTOCOL_INFO *protocolInfo,
						   IN_HANDLE const CRYPT_USER iOwnerHandle, 
						   IN_LENGTH const int endPos, 
						   INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_ALGO_TYPE defaultHashAlgo, msgImprintHashAlgo DUMMY_INIT;
	ALGOID_PARAMS algoidParams;
	STREAM msgImprintStream;
	void *dataPtr DUMMY_INIT_PTR;
	long value;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int tag, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( TSP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( iOwnerHandle == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( iOwnerHandle ) );
	REQUIRES( isBufsizeRangeNZ( endPos ) && endPos > stell( stream ) );

	/* Read the request header and make sure everything is in order */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) || value != TSP_VERSION )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid TSP request header" ) );
		}

	/* Read the message imprint.  We don't really care what this is so we
	   just treat it as a blob */
	status = getStreamObjectLength( stream, &length, 16 );
	if( cryptStatusOK( status ) && !isShortIntegerRangeNZ( length ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		status = sMemGetDataBlock( stream, &dataPtr, length );
	if( cryptStatusOK( status ) )
		{
		if( length < MIN_MSGIMPRINT_SIZE || length > MAX_MSGIMPRINT_SIZE || \
			cryptStatusError( sSkip( stream, length, MAX_INTLENGTH_SHORT ) ) )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid TSP message imprint data" ) );
		}
	ANALYSER_HINT( dataPtr != NULL );
	REQUIRES( rangeCheck( length, 1, MAX_MSGIMPRINT_SIZE ) );
	memcpy( protocolInfo->msgImprint, dataPtr, length );
	protocolInfo->msgImprintSize = length;
	CFI_CHECK_UPDATE( "readMessageImprint" );

	/* Pick apart the msgImprint:

		msgImprint			SEQUENCE {
			algorithm		AlgorithmIdentifier,
			hash			OCTET STRING
			}

	   to see whether we can use a stronger hash in our response than the 
	   default SHA-1.  This is done on the basis that if the client sends us
	   a message imprint with a stronger hash then they should be able to
	   process a response with a stronger hash as well */
	sMemConnect( &msgImprintStream, protocolInfo->msgImprint, 
				 protocolInfo->msgImprintSize );
	status = readSequence( &msgImprintStream, NULL );
	if( cryptStatusOK( status ) )
		{
		status = readAlgoIDex( &msgImprintStream, &msgImprintHashAlgo, 
							   &algoidParams, ALGOID_CLASS_HASH );
		}
	if( cryptStatusOK( status ) )
		{
		status = readOctetStringHole( &msgImprintStream, NULL, 16, 
									  DEFAULT_TAG );
		}
	sMemDisconnect( &msgImprintStream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid TSP message imprint content" ) );
		}
	CFI_CHECK_UPDATE( "processMessageImprint" );

	/* Upgrade to a stronger hash if we can.  Note that this check doesn't
	   take into account parameterisation of hash algorithms since there's
	   no effective difference security-wise between (say) SHA-256 and
	   SHA-512, so we can upgrade from SHA-1 to SHA-2 but not from
	   SHA-2-goes-to-ten to SHA-2-goes-to-eleven (or at least we could to
	   make a fashion statement, but not because it makes any difference
	   in security).  If this is required then we could compare 
	   algoIDparams->hashSize to CRYPT_OPTION_ENCR_HASHPARAM */
	status = krnlSendMessage( iOwnerHandle, IMESSAGE_GETATTRIBUTE, 
							  &defaultHashAlgo, CRYPT_OPTION_ENCR_HASH );
	if( cryptStatusOK( status ) && \
		isStrongerHash( msgImprintHashAlgo, defaultHashAlgo ) )
		{
		protocolInfo->hashAlgo = msgImprintHashAlgo;
		}

	/* Check for the presence of the assorted optional fields */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == BER_OBJECT_IDENTIFIER )
		{
		/* This could be anything since it's defined as "by prior agreement"
		   so we ignore it and give them whatever policy we happen to
		   implement, if they don't like it then they're free to ignore it */
		status = readUniversal( stream );
		}
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == BER_INTEGER )
		{
		/* For some unknown reason the nonce is encoded as an INTEGER 
		   instead of an OCTET STRING, so in theory we'd have to jump 
		   through all sorts of hoops to handle it because it's really an 
		   OCTET STRING blob dressed up as an INTEGER.  To avoid this mess,
		   we just read it as a blob and memcpy() it back to the output */
		status = readRawObject( stream, protocolInfo->nonce,
								CRYPT_MAX_HASHSIZE, 
								&protocolInfo->nonceSize, BER_INTEGER );
		}
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == BER_BOOLEAN )
		{
		status = readBoolean( stream, &protocolInfo->includeSigCerts );
		}
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( 0 ) )
		{
		/* The TSP RFC specifies a truly braindamaged interpretation of
		   extension handling, added at the last minute with no debate or
		   discussion.  This says that extensions are handled just like RFC
		   2459 except when they're not.  In particular it requires that you
		   reject all extensions that you don't recognise, even if they
		   don't have the critical bit set (in violation of RFC 2459).
		   Since "recognise" is never defined and the spec doesn't specify
		   any particular extensions that must be handled (via MUST/SHALL/
		   SHOULD), any extension at all is regarded as unrecognised in the
		   context of the RFC.  For example if a request with a
		   subjectAltName is submitted then although the TSA knows perfectly
		   well what a subjectAltName, it has no idea what it's supposed to
		   do with it when it sees it in the request.  Since the semantics of
		   all extensions are unknown (in the context of the RFC), any
		   request with extensions has to be rejected.

		   Along with assorted other confusing and often contradictory terms
		   added in the last-minute rewrite, cryptlib ignores this
		   requirement and instead uses the common-sense interpretation of
		   allowing any extension that the RFC doesn't specifically provide
		   semantics for.  Since it doesn't provide semantics for any
		   extension, we allow anything */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid TSP request additional information fields" ) );
		}
	CFI_CHECK_UPDATE( "processAddiotionalFields" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "readMessageImprint", 
								   "processMessageImprint", 
								   "processAddiotionalFields" ) );

	return( CRYPT_OK );
	}

/* Sign a timestamp token */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int signTSToken( OUT_BUFFER( tsaRespMaxLength, *tsaRespLength ) \
							BYTE *tsaResp, 
						IN_LENGTH_SHORT_MIN( 64 ) \
							const int tsaRespMaxLength, 
						OUT_LENGTH_BOUNDED_Z( tsaRespMaxLength ) \
							int *tsaRespLength,
						IN_ALGO_OPT const CRYPT_ALGO_TYPE tsaRespHashAlgo,
						IN_BUFFER( tstInfoLength ) const BYTE *tstInfo, 
						IN_LENGTH_SHORT const int tstInfoLength,
						IN_HANDLE const CRYPT_CONTEXT privateKey,
						IN_BOOL const BOOLEAN includeCerts )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	DYNBUF essCertDB;
	static const int minBufferSize = MIN_BUFFER_SIZE;
	static const int contentType = CRYPT_CONTENT_TSTINFO;
	int status;

	assert( isWritePtrDynamic( tsaResp, tsaRespMaxLength ) );
	assert( isWritePtr( tsaRespLength, sizeof( int ) ) );
	assert( isReadPtrDynamic( tstInfo, tstInfoLength ) );

	REQUIRES( isShortIntegerRangeMin( tsaRespMaxLength, 64 ) );
	REQUIRES( tsaRespHashAlgo == CRYPT_ALGO_NONE || \
			  ( tsaRespHashAlgo >= CRYPT_ALGO_FIRST_HASH && \
				tsaRespHashAlgo <= CRYPT_ALGO_LAST_HASH ) );
	REQUIRES( isShortIntegerRangeNZ( tstInfoLength ) );
	REQUIRES( isHandleRangeValid( privateKey ) );
	REQUIRES( isBooleanValue( includeCerts ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( tsaRespMaxLength ) ); 
	memset( tsaResp, 0, min( 16, tsaRespMaxLength ) );
	*tsaRespLength = 0;

	/* Create the signing attributes.  We don't have to set the content-type
	   attribute since it'll be set automatically based on the envelope
	   content type */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	iCmsAttributes = createInfo.cryptHandle;
	status = dynCreate( &essCertDB, privateKey, CRYPT_IATTRIBUTE_ESSCERTID );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, dynData( essCertDB ),
						dynLength( essCertDB ) );
		status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
						&msgData, CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID );
		dynDestroy( &essCertDB );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Create a cryptlib envelope to sign the data.  If we're not being
	   asked to include signer certificates we have to explicitly disable 
	   the inclusion of certificates in the signature since S/MIME includes 
	   them by default.  In addition the caller may have asked us to use a
	   non-default hash algorithm, which we specify for the envelope if it's
	   been set.  Unfortunately these special-case operations mean that we 
	   can't use envelopeSign() to process the data, but have to perform the 
	   whole process ourselves */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_CMS );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  ( MESSAGE_CAST ) &minBufferSize,
							  CRYPT_ATTRIBUTE_BUFFERSIZE );
	if( cryptStatusOK( status ) && tsaRespHashAlgo != CRYPT_ALGO_NONE )
		{
		const int value = tsaRespHashAlgo;	/* int vs.enum */

		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &value,
								  CRYPT_OPTION_ENCR_HASH );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &tstInfoLength,
								  CRYPT_ENVINFO_DATASIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &contentType,
								  CRYPT_ENVINFO_CONTENTTYPE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &privateKey,
								  CRYPT_ENVINFO_SIGNATURE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, &iCmsAttributes,
								  CRYPT_ENVINFO_SIGNATURE_EXTRADATA );
		}
	if( cryptStatusOK( status ) && !includeCerts )
		{
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_FALSE,
								  CRYPT_IATTRIBUTE_INCLUDESIGCERT );
		}
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Push in the data and pop the signed result */
	setMessageData( &msgData, ( MESSAGE_CAST ) tstInfo, tstInfoLength );
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, tsaResp, tsaRespMaxLength );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_POPDATA, &msgData, 0 );
		*tsaRespLength = msgData.length;
		}
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/****************************************************************************
*																			*
*							Client-side Functions							*
*																			*
****************************************************************************/

/* Send a request to a TSP server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sendClientRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR TSP_PROTOCOL_INFO *protocolInfo )
	{
	TSP_INFO *tspInfo = sessionInfoPtr->sessionTSP;
	STREAM stream;
	void *msgImprintPtr;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( TSP_PROTOCOL_INFO ) ) );

	/* If we're fuzzing, there's no request to send out */
#ifdef CONFIG_FUZZ
	memset( protocolInfo->msgImprint, '*', 16 );
	protocolInfo->msgImprintSize = 16;
	return( CRYPT_OK );
#endif /* CONFIG_FUZZ */

	/* Create the encoded request:

		TSARequest ::= SEQUENCE {
			version				INTEGER (1),
			msgImprint			MessageDigest,
			includeSigCerts		BOOLEAN TRUE
			}
	
	   We have to ask for the inclusion of signing certificates in the
	   response (by default they're not included) because the caller may not 
	   have the TSA's certificate, or may have an out-of-date version 
	   depending on how frequently the TSA rolls over certificates.  This 
	   tends to bloat up the response somewhat, but it's only way to deal
	   with the certificate issue without requiring lots of manual 
	   certificate-processing from the caller.

	   When we write the message imprint as a hash value we save a copy of
	   the encoded data so that we can check it against the returned
	   timestamp, see the comment in readServerResponse() for details */
	protocolInfo->msgImprintSize = \
							sizeofMessageDigest( tspInfo->imprintAlgo,
												 tspInfo->imprintSize );
	ENSURES( protocolInfo->msgImprintSize > 0 && \
			 protocolInfo->msgImprintSize <= MAX_MSGIMPRINT_SIZE );
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 1024 );
	writeSequence( &stream, sizeofShortInteger( TSP_VERSION ) + \
							protocolInfo->msgImprintSize + \
							sizeofBoolean() );
	writeShortInteger( &stream, TSP_VERSION, DEFAULT_TAG );
	status = sMemGetDataBlock( &stream, &msgImprintPtr, 
							   protocolInfo->msgImprintSize );
	ENSURES( cryptStatusOK( status ) );
	writeMessageDigest( &stream, tspInfo->imprintAlgo, 
						tspInfo->imprint, tspInfo->imprintSize );
	REQUIRES( rangeCheck( protocolInfo->msgImprintSize, 1, 
						  MAX_MSGIMPRINT_SIZE ) );
	memcpy( protocolInfo->msgImprint, msgImprintPtr,
			protocolInfo->msgImprintSize );
	status = writeBoolean( &stream, TRUE, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		sessionInfoPtr->receiveBufEnd = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( sessionInfoPtr->receiveBufEnd ) );
	DEBUG_DUMP_FILE( "tsa_req", sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufEnd );

	/* Send the request to the server */
	return( writePkiDatagram( sessionInfoPtr, TSP_CONTENT_TYPE_REQ,
							  TSP_CONTENT_TYPE_REQ_LEN,
							  MK_ERRTEXT( "Couldnt send TSP request to "
										  "server" ) ) );
	}

/* Read the response from the TSP server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readServerResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR TSP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( TSP_PROTOCOL_INFO ) ) );

	/* Reset the buffer position indicators to clear any old data in the
	   buffer from previous transactions */
	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos = 0;

	/* Read the response data from the server.  TSP error responses can be
	   shorter than the minimum object size so we allow for smaller-than-
	   usual data reads */
	status = readPkiDatagram( sessionInfoPtr, min( 48, MIN_CRYPT_OBJECTSIZE ),
							  MK_ERRTEXT( "Couldnt read TSP response from "
										  "server" ) );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readPkiDatagram" );

	/* Strip off the header and check the PKIStatus wrapper to make sure
	   that everything's OK:

		SEQUENCE {
			status	SEQUENCE {
				status	INTEGER,			-- 0 = OK
						... OPTIONAL
				}
			... */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	readSequence( &stream, NULL );
	status = readPkiStatusInfo( &stream, FALSE, FALSE,
								&sessionInfoPtr->errorInfo );
	if( cryptStatusError( status ) )
		{
		/* readPkiStatusInfo() has already set the extended error 
		   information */
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "readPkiStatusInfo" );

	/* Remember where the encoded timestamp payload starts in the buffer so
	   that we can return it to the caller */
	sessionInfoPtr->receiveBufPos = stell( &stream );
	REQUIRES( isIntegerRangeNZ( sessionInfoPtr->receiveBufPos ) );

	/* Make sure that we got back a timestamp of the value that we sent.  
	   This check means that it works with and without nonces (in theory 
	   someone could repeatedly contersign the same signature rather than 
	   countersigning the last timestamp as they're supposed to, but (a) 
	   that's rather unlikely and (b) cryptlib doesn't support it so they'd 
	   have to make some rather serious changes to the code to do it) */
	readSequence( &stream, NULL );		/* contentInfo */
	readUniversal( &stream );			/* contentType */
	readConstructed( &stream, NULL, 0 );/* content */
	readSequence( &stream, NULL );			/* signedData */
	readShortInteger( &stream, NULL );		/* version */
	readUniversal( &stream );				/* digestAlgos */
	readSequence( &stream, NULL );			/* encapContent */
	readUniversal( &stream );					/* contentType */
	readConstructed( &stream, NULL, 0 );		/* content */
	readOctetStringHole( &stream, NULL, 16, 
						 DEFAULT_TAG );			/* OCTET STRING hole */
	readSequence( &stream, NULL );					/* tstInfo */
	readShortInteger( &stream, NULL );				/* version */
	status = readUniversal( &stream );				/* policy */
	if( cryptStatusError( status ) )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		void *msgImprintPtr;

		status = sMemGetDataBlock( &stream, &msgImprintPtr, 
								   protocolInfo->msgImprintSize );
		if( cryptStatusOK( status ) && \
			memcmp( protocolInfo->msgImprint, msgImprintPtr,
					protocolInfo->msgImprintSize ) )
			status = CRYPT_ERROR_INVALID;
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  ( status == CRYPT_ERROR_BADDATA || \
					status == CRYPT_ERROR_UNDERFLOW ) ? \
					"Invalid timestamp data" : \
					"Returned timestamp message imprint doesn't match "
					"original message imprint" ) );
		}
	CFI_CHECK_UPDATE( "readTimestamp" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "readPkiDatagram", "readPkiStatusInfo", 
								   "readTimestamp" ) );

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

#define respSize( data )	( data[ 1 ] + 2 )

static const BYTE respBadGeneric[] = {
	0x30, 0x05, 
		  0x30, 0x03, 
			    0x02, 0x01, 0x02		/* Rejection, unspecified reason */
	};
static const BYTE respBadData[] = {
	0x30, 0x09, 
		  0x30, 0x07, 
			    0x02, 0x01, 0x02, 
				0x03, 0x02, 0x05, 0x20	/* Rejection, badDataFormat */
	};
static const BYTE respBadExtension[] = {
	0x30, 0x0B, 
		  0x30, 0x09, 
				0x02, 0x01, 0x02, 
				0x03, 0x04, 0x07, 0x00, 0x00, 0x80	/* Rejection, unacceptedExtension */
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sendErrorResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  const BYTE *errorResponse, 
							  IN_ERROR const int status )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( cryptStatusError( status ) );

	/* Since we're already in an error state there's not much that we can do
	   in terms of alerting the user if a further error occurs when writing 
	   the error response, so we ignore any potential write errors that occur
	   at this point */
	REQUIRES( rangeCheck( respSize( errorResponse ), 1, 
						  sessionInfoPtr->receiveBufSize ) );
	memcpy( sessionInfoPtr->receiveBuffer, errorResponse,
			respSize( errorResponse ) );
	sessionInfoPtr->receiveBufEnd = respSize( errorResponse );
	( void ) writePkiDatagram( sessionInfoPtr, TSP_CONTENT_TYPE_RESP,
							   TSP_CONTENT_TYPE_RESP_LEN,
							   MK_ERRTEXT( "Couldnt send error response to "
										   "client" ) );
	return( status );
	}

/* Read a request from a TSP client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readClientRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR TSP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( TSP_PROTOCOL_INFO ) ) );

	/* Read the request data from the client.  This can be quite short, just 
	   an OID and a hash, so we specify a minimum length shorter than
	   MIN_CRYPT_OBJECTSIZE */
	status = readPkiDatagram( sessionInfoPtr, 32,
							  MK_ERRTEXT( "Couldnt read TSP request fron "
										  "client" ) );
	if( cryptStatusError( status ) )
		{
		return( sendErrorResponse( sessionInfoPtr, respBadGeneric, 
								   status ) );
		}
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	status = readTSPRequest( &stream, protocolInfo, 
							 sessionInfoPtr->ownerHandle, 
							 sessionInfoPtr->receiveBufEnd, 
							 SESSION_ERRINFO );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		delayRandom();	/* Dither error timing info */
		return( sendErrorResponse( sessionInfoPtr, \
					( status == CRYPT_ERROR_BADDATA || \
					  status == CRYPT_ERROR_UNDERFLOW ) ? respBadData : \
					( status == CRYPT_ERROR_INVALID ) ? respBadExtension : \
					respBadGeneric, status ) );
		}
	return( CRYPT_OK );
	}

/* Send a response to the TSP client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sendServerResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR TSP_PROTOCOL_INFO *protocolInfo )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE tstBuffer[ 1024 ];
	BYTE serialNo[ 16 + 8 ];
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
	const time_t currentTime = getReliableTime( sessionInfoPtr->privateKey, 
												GETTIME_MINUTES );
	int tstLength DUMMY_INIT, responseLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( TSP_PROTOCOL_INFO ) ) );

	ENSURES( currentTime > MIN_TIME_VALUE );
			 /* Already checked in checkAttributeFunction() */

	/* If we're fuzzing, there's nothing to send */
	FUZZ_SKIP_REMAINDER();

	/* Create a timestamp token */
	setMessageData( &msgData, serialNo, 16 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );
	sMemOpen( &stream, tstBuffer, 1024 );
	writeSequence( &stream, sizeofShortInteger( 1 ) + \
			sizeofOID( OID_TSP_POLICY ) + protocolInfo->msgImprintSize + \
			sizeofInteger( serialNo, 16 ) + sizeofGeneralizedTime() + \
			protocolInfo->nonceSize );
	writeShortInteger( &stream, 1, DEFAULT_TAG );
	writeOID( &stream, OID_TSP_POLICY );
	swrite( &stream, protocolInfo->msgImprint, protocolInfo->msgImprintSize );
	writeInteger( &stream, serialNo, 16, DEFAULT_TAG );
	status = writeGeneralizedTime( &stream, currentTime, DEFAULT_TAG );
	if( protocolInfo->nonceSize > 0 )
		{
		status = swrite( &stream, protocolInfo->nonce,
						 protocolInfo->nonceSize );
		}
	if( cryptStatusOK( status ) )
		tstLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		return( sendErrorResponse( sessionInfoPtr, respBadGeneric, 
								   status ) );
		}
	ENSURES( isShortIntegerRangeNZ( tstLength ) );
	
	/* Sign the token.   The reason for the min() part of the expression is 
	   that signTSToken() gets suspicious of very large buffer sizes, for 
	   example when the user has specified the use of a huge send buffer */
	status = signTSToken( sessionInfoPtr->receiveBuffer + 9,
						  min( sessionInfoPtr->receiveBufSize, \
							   MAX_INTLENGTH_SHORT - 1 ), &responseLength, 
						  protocolInfo->hashAlgo, tstBuffer, tstLength, 
						  sessionInfoPtr->privateKey, 
						  protocolInfo->includeSigCerts );
	if( cryptStatusError( status ) )
		{
		delayRandom();	/* Dither error timing info */
		return( sendErrorResponse( sessionInfoPtr, respBadGeneric, status ) );
		}
	DEBUG_DUMP_FILE( "tsa_token", sessionInfoPtr->receiveBuffer + 9,
					 responseLength );

	/* Add the TSA response wrapper and send it to the client.  This assumes
	   that the TSA response will be >= 256 bytes (for a 4-byte SEQUENCE
	   header encoding), which is always the case since it uses PKCS #7
	   signed data */
	REQUIRES( isShortIntegerRangeMin( responseLength, 256 ) );
	sMemOpen( &stream, bufPtr, 4 + 5 );		/* SEQ + resp.header */
	writeSequence( &stream, 5 + responseLength );
	swrite( &stream, "\x30\x03\x02\x01\x00", 5 );
	sMemDisconnect( &stream );
	sessionInfoPtr->receiveBufEnd = 9 + responseLength;
	DEBUG_DUMP_FILE( "tsa_resp", sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufEnd );
	return( writePkiDatagram( sessionInfoPtr, TSP_CONTENT_TYPE_RESP,
							  TSP_CONTENT_TYPE_RESP_LEN,
							  MK_ERRTEXT( "Couldnt send TSP response to "
										  "client" ) ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Exchange data with a TSP client/server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientTransact( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	TSP_PROTOCOL_INFO protocolInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTSP( sessionInfoPtr ) );

	/* Make sure that we have all of the needed information */
	if( sessionInfoPtr->sessionTSP->imprintSize <= 0 )
		{
		setObjectErrorInfo( sessionInfoPtr, 
							CRYPT_SESSINFO_TSP_MSGIMPRINT,
							CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Get a timestamp from the server */
	memset( &protocolInfo, 0, sizeof( TSP_PROTOCOL_INFO ) );
	status = sendClientRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		status = readServerResponse( sessionInfoPtr, &protocolInfo );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int serverTransact( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	TSP_PROTOCOL_INFO protocolInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTSP( sessionInfoPtr ) );

	/* Send a timestamp to the client */
	memset( &protocolInfo, 0, sizeof( TSP_PROTOCOL_INFO ) );
	status = readClientRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		status = sendServerResponse( sessionInfoPtr, &protocolInfo );
	return( status );
	}

/****************************************************************************
*																			*
*					Control Information Management Functions				*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 INOUT_PTR void *data, 
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_ENVELOPE *cryptEnvelopePtr = ( CRYPT_ENVELOPE * ) data;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int dataSize = sessionInfoPtr->receiveBufEnd - \
						 sessionInfoPtr->receiveBufPos;
	const int bufSize = max( dataSize + 128, MIN_BUFFER_SIZE );
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( data, sizeof( int ) ) );

	REQUIRES( type == CRYPT_SESSINFO_RESPONSE || \
			  type == CRYPT_IATTRIBUTE_ENC_TIMESTAMP );
	REQUIRES( isBufsizeRange( dataSize ) );

	/* Make sure that there's actually a timestamp present (this can happen 
	   if we're using a persistent session and a subsequent transaction
	   fails, resulting in no timestamp being available) */
	if( sessionInfoPtr->receiveBufPos <= 0 )
		return( CRYPT_ERROR_NOTFOUND );

	/* If we're being asked for raw encoded timestamp data, return it
	   directly to the caller */
	if( type == CRYPT_IATTRIBUTE_ENC_TIMESTAMP )
		{
		REQUIRES( boundsCheck( sessionInfoPtr->receiveBufPos, dataSize,
							   sessionInfoPtr->receiveBufEnd ) );
		return( attributeCopy( ( MESSAGE_DATA * ) data,
					sessionInfoPtr->receiveBuffer + sessionInfoPtr->receiveBufPos,
					dataSize ) );
		}

	/* Delete any existing response if necessary */
	if( sessionInfoPtr->iCertResponse != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCertResponse,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCertResponse = CRYPT_ERROR;
		}

	/* We're being asked for interpreted data, create a cryptlib envelope to
	   contain it */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( MESSAGE_CAST ) &bufSize, 
					 CRYPT_ATTRIBUTE_BUFFERSIZE );

	/* Push in the timestamp data */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer + \
							  sessionInfoPtr->receiveBufPos, dataSize );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_ENV_PUSHDATA, &msgData, 0 );
		}
	if( cryptStatusError( status ) )
		return( status );
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;

	/* Return the information to the caller */
	krnlSendNotifier( sessionInfoPtr->iCertResponse, IMESSAGE_INCREFCOUNT );
	*cryptEnvelopePtr = sessionInfoPtr->iCertResponse;
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int setAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 IN_PTR const void *data,
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CONTEXT hashContext = *( ( CRYPT_CONTEXT * ) data );
	TSP_INFO *tspInfo = sessionInfoPtr->sessionTSP;
	int imprintAlgo, status;	/* int vs.enum */

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, sizeof( int ) ) );

	REQUIRES( type == CRYPT_SESSINFO_TSP_MSGIMPRINT );

	if( tspInfo->imprintSize != 0 )
		return( CRYPT_ERROR_INITED );

	/* Get the message imprint from the hash context */
	status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE,
							  &imprintAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;

		tspInfo->imprintAlgo = imprintAlgo;	/* int vs.enum */
		setMessageData( &msgData, tspInfo->imprint, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusOK( status ) )
			tspInfo->imprintSize = msgData.length;
		}

	return( cryptStatusError( status ) ? CRYPT_ARGERROR_NUM1 : CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								   IN_PTR const void *data,
								   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	const CRYPT_CONTEXT cryptContext = *( ( CRYPT_CONTEXT * ) data );
	int value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, sizeof( int ) ) );

	REQUIRES( isEnumRange( type, CRYPT_ATTRIBUTE ) );

	if( type != CRYPT_SESSINFO_PRIVATEKEY )
		return( CRYPT_OK );

	/* Make sure that the key is valid for timestamping */
	if( !checkContextCapability( cryptContext, MESSAGE_CHECK_PKC_SIGN ) )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
							CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE, &value,
							  CRYPT_CERTINFO_EXTKEY_TIMESTAMPING );
	if( cryptStatusError( status ) )
		{
		setObjectErrorInfo( sessionInfoPtr, 
							CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
							CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* Make sure that the time appears correct (if the time is screwed up 
	   then we can't really provide a signed indication of it to clients).  
	   The error information is somewhat misleading, but there's not much 
	   else that we can provide at this point */
	if( getReliableTime( cryptContext, GETTIME_MINUTES ) <= MIN_TIME_VALUE )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_VALIDFROM,
							CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodTSP( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_PROTOCOL_HTTPTRANSPORT, /* Flags */
		80,							/* HTTP port */
		0,							/* Client flags */
		SESSION_NEEDS_PRIVATEKEY |	/* Server flags */
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCERT,
		1, 1, 1,					/* Version 1 */
		CRYPT_SUBPROTOCOL_NONE, CRYPT_SUBPROTOCOL_NONE,
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
	FNPTR_SET( sessionInfoPtr->getAttributeFunction, getAttributeFunction );
	FNPTR_SET( sessionInfoPtr->setAttributeFunction, setAttributeFunction );
	FNPTR_SET( sessionInfoPtr->checkAttributeFunction, checkAttributeFunction );

	return( CRYPT_OK );
	}
#endif /* USE_TSP */
