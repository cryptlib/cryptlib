/****************************************************************************
*																			*
*						 cryptlib SCVP Server Management					*
*						Copyright Peter Gutmann 2009-2021					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "certstore.h"
  #include "scvp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "session/session.h"
  #include "session/certstore.h"
  #include "session/scvp.h"
#endif /* Compiler-specific includes */

#ifdef USE_SCVP

/* Table to map a cryptlib status into an SCVP equivalent.  Some of these 
   are approximations since many SCVP status values can map to a single 
   cryptlib status, in particular CRYPT_ERROR_NOTAVAIL covers a lot of 
   cases */

static const MAP_TABLE statusToSCVPMapTbl[] = {
	{ CRYPT_OK, SCVP_STATUS_OKAY }, 
	{ CRYPT_ERROR_TIMEOUT, SCVP_STATUS_TOOBUSY },
	{ CRYPT_ERROR_NOTAVAIL, SCVP_STATUS_UNSUPPORTEDCHECKS },
	{ CRYPT_ERROR_FAILED, SCVP_STATUS_INTERNALERROR },
	{ CRYPT_ERROR_INVALID, SCVP_STATUS_INVALIDREQUEST },
	{ CRYPT_ERROR_BADDATA, SCVP_STATUS_BADSTRUCTURE },
	{ CRYPT_ERROR_WRONGKEY, SCVP_STATUS_UNRECOGNIZEDSIGKEY },
	{ CRYPT_ERROR_SIGNATURE, SCVP_STATUS_BADSIGNATUREORMAC },
	{ CRYPT_ERROR_PERMISSION, SCVP_STATUS_NOTAUTHORIZED },
	{ CRYPT_ERROR_NOTFOUND, SCVP_STATUS_UNRECOGNIZEDRESPONDERNAME },
	{ CRYPT_ERROR_DUPLICATE, SCVP_STATUS_RELAYINGLOOP },
	{ CRYPT_ERROR, CRYPT_ERROR }, 
		{ CRYPT_ERROR, CRYPT_ERROR }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read the wantBack information:

	wantBack	[1]	SEQUENCE OF OBJECT IDENTIFIER OPTIONAL

   We can be asked for multiple things back so we have to keep reading in a 
   loop until we've got all the items */

#define SCVP_OID_WANTBACK_BESTCERTPATH \
		MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x01" )
#define SCVP_OID_WANTBACK_CERT \
		MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x0A" )

static const OID_INFO wantBackOIDinfo[] = {
	{ SCVP_OID_WANTBACK_BESTCERTPATH, SCVP_WANTBACK_FLAG_BESTCERTPATH, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x02" ), 
	  SCVP_WANTBACK_FLAG_REVOCATIONINFO, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x04" ), 
	  SCVP_WANTBACK_FLAG_PUBLICKEYINFO, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x09" ), 
	  SCVP_WANTBACK_FLAG_RELAYEDRESPONSES, NULL },
	{ SCVP_OID_WANTBACK_CERT, SCVP_WANTBACK_FLAG_CERT, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x0C" ), 
	  SCVP_WANTBACK_FLAG_ALLCERTPATHS, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x0D" ), 
	  SCVP_WANTBACK_FLAG_EEREVOCATIONINFO, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x12\x0E" ), 
	  SCVP_WANTBACK_FLAG_CAREVOCATIONINFO, NULL },
	{ NULL, 0 }, { NULL, 0 }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readWantBacks( INOUT_PTR STREAM *stream,
						  INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	int length, endPos, selectionID, status;
	LOOP_INDEX wantBackCount;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	/* Find out how many entries we need to read */
	status = readConstructed( stream, &length, CTAG_QR_WANTBACK );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );

	/* Read and record each wantBack */
	protocolInfo->wantBacks = SCVP_WANTBACK_FLAG_NONE;
	LOOP_MED( wantBackCount = 0, 
			  wantBackCount < 16 && stell( stream ) < endPos, 
			  wantBackCount++ )
		{
		ENSURES( LOOP_INVARIANT_MED( wantBackCount, 0, 15 ) );

		status = readOID( stream, wantBackOIDinfo, 
						  FAILSAFE_ARRAYSIZE( wantBackOIDinfo, OID_INFO ), 
						  &selectionID );
		if( cryptStatusError( status ) )
			return( status );
		protocolInfo->wantBacks |= selectionID;
		}
	ENSURES( LOOP_BOUND_OK );
	if( wantBackCount >= 16 )
		return( CRYPT_ERROR_OVERFLOW );

	return( CRYPT_OK );
	}

/* Calculate the size of a certificate item */

CHECK_RETVAL_LENGTH_SHORT \
static int sizeofCertItem( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
						   IN_ENUM( CRYPT_CERTFORMAT ) \
								const CRYPT_CERTFORMAT_TYPE formatType )
	{
	MESSAGE_DATA msgData;
	int status;

	REQUIRES( isHandleRangeValid( iCryptCert ) );
	REQUIRES( isEnumRange( formatType, CRYPT_CERTFORMAT ) );

	/* Determine the size of the exported certificate */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData,
							  formatType );
	if( cryptStatusError( status ) )
		return( status );

	return( msgData.length );
	}

/* Write the requestRef.  This misnamed field contains a hash of the 
   request that the client sent as it we received it, used to detect
   manipulation of the unauthenticated request data */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
static int sizeofRequestRef( IN_PTR const SCVP_PROTOCOL_INFO *protocolInfo )
	{
	return( sizeofObject( \
				sizeofAlgoID( protocolInfo->requestHashAlgo ) + \
				sizeofObject( protocolInfo->requestHashSize ) ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRequestRef( INOUT_PTR STREAM *stream,
							IN_PTR const SCVP_PROTOCOL_INFO *protocolInfo )
	{
	ALGOID_PARAMS algoIDparams;
	int dataSize;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	dataSize = sizeofAlgoID( protocolInfo->requestHashAlgo ) + \
			   sizeofObject( protocolInfo->requestHashSize );
	writeConstructed( stream, sizeofObject( dataSize ), CTAG_RP_REQUESTREF );
	writeConstructed( stream, dataSize, CTAG_RR_REQUESTHASH );
	initAlgoIDparamsHash( &algoIDparams, protocolInfo->requestHashAlgo, 
						  protocolInfo->requestHashSize );
	writeAlgoIDex( stream, protocolInfo->requestHashAlgo, &algoIDparams, 
				   DEFAULT_TAG );
	return( writeOctetString( stream, protocolInfo->requestHash, 
							  protocolInfo->requestHashSize, DEFAULT_TAG ) );
	}

/****************************************************************************
*																			*
*						Request Management Functions						*
*																			*
****************************************************************************/

/* Read an SCVP request:

	CVRequest ::= SEQUENCE {
		cvRequestVersion			INTEGER DEFAULT 1, -- May be encoded even if default
		query						SEQUENCE {
			queriedCerts			CertReferences,
			checks					SEQUENCE OF OBJECT IDENTIFIER,
			wantBack			[1]	SEQUENCE OF OBJECT IDENTIFIER OPTIONAL, -- Mandatory
			validationPolicy		SEQUENCE {
				validationPolRef	SEQUENCE {
					valPolId		OBJECT IDENTIFIER scvpDefaultValPolicy,
					valPolParams	ANY DEFINED BY valPolId OPTIONAL
					},
				validationAlg	[0]	... OPTIONAL,		-- Ignored
				userPolicySet	[1]	... OPTIONAL,		-- Ignored
				inhibitPolicyMapping [2] ... OPTIONAL,	-- Ignored
				requireExplicitPolicy [3] ... OPTIONAL,	-- Ignored
				inhibitAnyPolicy [4] ... OPTIONAL,		-- Ignored
				trustAnchors	[5]	... OPTIONAL,		-- Ignored
				keyUsages		[6]	... OPTIONAL,		-- Ignored
				extendedKeyUsages [7] ... OPTIONAL,		-- Ignored
				specifiedKeyUsages [8] ... OPTIONAL,	-- Ignored
				},
			responseFlags			SEQ ... OPTIONAL,	-- Ignored
			serverContextInfo	[2]	... OPTIONAL,		-- Ignored
			validationTime		[3]	... OPTIONAL,		-- Ignored
			intermediateCerts	[4]	... OPTIONAL,		-- Ignored
			revInfos			[5]	... OPTIONAL,		-- Ignored
			producedAt			[6]	... OPTIONAL,		-- Ignored
			queryExtensions		[7]	... OPTIONAL 		-- Ignored
			},
		requestorRef			[0]	... OPTIONAL,		-- Ignored
		requestNonce			[1]	OCTET STRING OPTIONAL,
		requestorName			[2]	... OPTIONAL,		-- Ignored
		responderName			[3]	... OPTIONAL,		-- Ignored
		requestExtensions		[4]	... OPTIONAL,		-- Ignored
		signatureAlg			[5]	... OPTIONAL,		-- Ignored
		hashAlg					[6]	... OPTIONAL,		-- Ignored
		requestorText			[7]	... OPTIONAL 		-- Ignored
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readScvpRequest( INOUT_PTR STREAM *stream,
							INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	ERROR_INFO localErrorInfo;
	int tag, length, endPos DUMMY_INIT, status = CRYPT_OK;
	LOOP_INDEX additionalInfoCount;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	/* Read the wrapper and certificate ID information.  The outer SEQUENCE
	   isn't present because it's been removed by the de-enveloping process */
	clearErrorInfo( &localErrorInfo );
	if( peekTag( stream ) == BER_INTEGER )
		{
		/* There's only one version possible and that's DEFAULT 1 but some
		   implementations still encode the default value so we skip it if
		   present */
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = readSequence( stream, &length );
	if( cryptStatusOK( status ) )
		{
		endPos = stell( stream ) + length;
		ENSURES( isIntegerRangeMin( endPos, length ) );
		status = readCertRefs( stream, &sessionInfoPtr->iCertRequest, 
							   &localErrorInfo );
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't read certificate ID information" ) );
		}

	/* Read the checks that are required.  Another PKIX special, it's
	   specified as a SEQUENCE OF rather than just a single check.  However
	   all of this is rendered moot through a number of factors related to
	   the confused design.  While in theory we could run into problems 
	   because it's never specified whether, if multiple checks are present
	   they should be treated as AND, OR, XOR, or whatever, the fact that each 
	   subsequent check is a superset of the previous one means that if A and
	   B are specified then A is already performed as part of B.

	   A second factor is that all of SCVP is designed around the digital
	   ancestor-worship design of X.509's blacklist-based thinking.  Since
	   we're using whitelists, there's no need to specify which of a dozen 
	   different types of checking is wanted since there's only one check 
	   possible that covers all cases, "is this certificate valid right 
	   now".  Because of this, for checking purposes, we ignore whatever's 
	   been specified here since it doesn't apply to an implementation that 
	   doesn't follow the digital ancestor-worship way of thinking.
	   
	   Unfortunately we can't completely ignore what's here though because 
	   we need to echo the checks back to the client in the response in case
	   it's forgotten what it was that it requested, so we read the OID so 
	   that we can copy it back to the client */
	status = readSequence( stream, &length );
	if( cryptStatusOK( status ) )
		{
		status = readEncodedOID( stream, protocolInfo->checks, MAX_OID_SIZE,
								 &protocolInfo->checksSize, 
								 BER_OBJECT_IDENTIFIER );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status,
				   ( status, SESSION_ERRINFO, 
					 "Couldn't read checks information" ) );
		}

	/* Read the indication of what the client wants back.  This is an 
	   optional field that's actually mandatory.  We use 
	   checkStatusPeekTag() rather than peekTag() because we need to exit if
	   there's an error before calling readValidationPolicy() */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_QR_WANTBACK ) )
		{
		status = readWantBacks( stream, protocolInfo );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					   ( status, SESSION_ERRINFO, 
						 "Couldn't read wantBack information" ) );
			}
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* Read the validation policy information */
	status = readValidationPolicy( stream, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't read validation policy information" ) );
		}

	/* Now we're into the infinite number of optional extras, none of which 
	   are obviously useful for anything (see the comment for 
	   readValidationPolicy() for more on this).  Because we can't do 
	   anything with any of this stuff, we skip it until someone can 
	   identify a use for any of the fields */
	LOOP_MED( additionalInfoCount = 0,
			  additionalInfoCount < 16 && stell( stream ) < endPos,
			  additionalInfoCount++ )
		{
		ENSURES( LOOP_INVARIANT_MED( additionalInfoCount, 0, 15 ) );

		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Couldn't read additional query information" ) );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( additionalInfoCount >= 16 )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Too many additional query information items" ) );
		}

	/* Finally, even more optional extras to extend the optional extras
	   present earlier.  There is one single field in here, the nonce, that
	   actually has an identifiable purpose, so we process this if we see
	   it */
	LOOP_MED( additionalInfoCount = 0,
			  additionalInfoCount < 16 && sMemDataLeft( stream ) > 0,
			  additionalInfoCount++ )
		{
		ENSURES( LOOP_INVARIANT_MED( additionalInfoCount, 0, 15 ) );

		status = tag = peekTag( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( tag == MAKE_CTAG_PRIMITIVE( CTAG_RQ_REQUESTNONCE ) )
			{
			status = readOctetStringTag( stream, protocolInfo->nonce,
										 &protocolInfo->nonceSize,
										 4, CRYPT_MAX_HASHSIZE,
										 CTAG_RQ_REQUESTNONCE );
			}
		else
			status = readUniversal( stream );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Couldn't read additional request information" ) );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( additionalInfoCount >= 16 )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Too many additional request information items" ) );
		}

	return( CRYPT_OK );
	}

/* Check an SCVP request message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int checkScvpRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
							 OUT_ALWAYS BOOLEAN *requestDataAvailable )
	{
	STREAM stream;
	ERROR_INFO localErrorInfo;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( requestDataAvailable, sizeof( BOOLEAN ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* Clear return value */
	*requestDataAvailable = FALSE;

	/* Calculate the request hash */
	status = calculateRequestHash( protocolInfo, 
								   sessionInfoPtr->receiveBuffer, 
								   sessionInfoPtr->receiveBufEnd );
	if( cryptStatusError( status ) )
		return( status );

	/* All that we need for an error response is the request hash, so after
	   this point we've got enough to send an error response if required */
	*requestDataAvailable = TRUE;

	/* Unwrap the request from its CMS envelope */
	clearErrorInfo( &localErrorInfo );
	DEBUG_DUMP_FILE( "scvp_sreq1", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );
	status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, 
							 sessionInfoPtr->receiveBufEnd,
							 sessionInfoPtr->receiveBuffer, 
							 sessionInfoPtr->receiveBufSize, &dataLength, 
							 CRYPT_UNUSED, NULL, 0, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Couldn't unwrap SCVP request data" ) );
		}
	DEBUG_DUMP_FILE( "scvp_sreq0", sessionInfoPtr->receiveBuffer, 
					 dataLength );

	/* Check the SCVP request */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, dataLength );
	status = readScvpRequest( &stream, sessionInfoPtr, protocolInfo );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*						Response Management Functions						*
*																			*
****************************************************************************/

/* Process an SCVP request, filling in the elements that we need in the
   response */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processScvpRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	MESSAGE_KEYMGMT_INFO getkeyInfo DUMMY_INIT_STRUCT;
	MESSAGE_DATA msgData;
	BYTE keyID[ CRYPT_MAX_HASHSIZE + 8 ];
	int getItemFlag = KEYMGMT_FLAG_CHECK_ONLY, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	/* Check the status of the certificate.  If it's a basic status check
	   with no additional wantbacks then we just perform a straight presence
	   check, if there are wantbacks for a certificate path then we combine 
	   the fetch with the status check as a single operation */
	if( protocolInfo->wantBacks & ( SCVP_WANTBACK_FLAG_BESTCERTPATH | \
									SCVP_WANTBACK_FLAG_ALLCERTPATHS ) )
		{
		/* We need to return something other than what the requestor sent 
		   us, perform an actual fetch rather than just a status check */
		getItemFlag = KEYMGMT_FLAG_NONE;
		}
	setMessageData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusOK( status ) )
		{
		setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID, keyID, 
							   KEYID_SIZE, NULL, 0, getItemFlag );
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
								  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
								  KEYMGMT_ITEM_PUBLICKEY );
		}
	if( cryptStatusError( status ) )
		{
#ifdef USE_ERRMSGS
		char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
		char textBuffer[ 64 + CRYPT_MAX_TEXTSIZE + 8 ];
		int textLength;

		/* Not finding a certificate in response to a request isn't a real 
		   error so all we do is return a warning to the caller.  
		   Unfortunately since we're not using retExt() we have to assemble
		   the message string ourselves */
		textLength = sprintf_s( textBuffer, 64 + CRYPT_MAX_TEXTSIZE,
								"Warning: Couldn't find certificate for '%s'", 
								getCertHolderName( sessionInfoPtr->privateKey, 
												   certName, 
												   CRYPT_MAX_TEXTSIZE ) );
		ENSURES( rangeCheck( textLength, 17, 64 + CRYPT_MAX_TEXTSIZE - 1 ) );
		setErrorString( SESSION_ERRINFO, textBuffer, textLength );
#endif /* USE_ERRMSGS */

		/* Turn the cryptlib status into an SCVP reply status */
		protocolInfo->scvpReplyStatus = \
								SCVP_REPLYSTATUS_CERTPATHCONSTRUCTFAIL;

		return( CRYPT_OK );
		}

	if( getItemFlag != KEYMGMT_FLAG_CHECK_ONLY )
		protocolInfo->iWantbackCertPath = getkeyInfo.cryptHandle;
	protocolInfo->scvpReplyStatus = SCVP_REPLYSTATUS_SUCCESS;
	return( CRYPT_OK );
	}

/* Write individual wantBack responses:

	wantBack ::= SEQUENCE {
		type						OBJECT IDENTIFIER,
		value						OCTET STRING
		} */

CHECK_RETVAL_LENGTH_SHORT \
static int sizeofWantbackCert( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	int certSize, status;

	REQUIRES( isHandleRangeValid( iCryptCert ) );

	status = certSize = sizeofCertItem( iCryptCert, 
										CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	return( sizeofOID( SCVP_OID_WANTBACK_CERT ) + \
			sizeofObject( certSize ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeWantbackCert( INOUT_PTR STREAM *stream,
							  const SCVP_PROTOCOL_INFO *protocolInfo,
							  IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	int certSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCert ) );
 
	/* Write the certificate */
	status = certSize = sizeofCertItem( iCryptCert, 
										CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	writeSequence( stream, protocolInfo->wbCertSize );
	writeOID( stream, SCVP_OID_WANTBACK_CERT );
	status = writeOctetStringHole( stream, certSize, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = exportCertToStream( stream, iCryptCert, 
									 CRYPT_CERTFORMAT_CERTIFICATE );
		}

	return( status );
	}

CHECK_RETVAL_LENGTH_SHORT \
static int sizeofWantbackBestCertPath( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	int certBundleSize, status;

	REQUIRES( isHandleRangeValid( iCryptCert ) );

	status = certBundleSize = sizeofCertItem( iCryptCert, 
											  CRYPT_ICERTFORMAT_CERTSEQUENCE );
	if( cryptStatusError( status ) )
		return( status );
	return( sizeofOID( SCVP_OID_WANTBACK_BESTCERTPATH ) + \
			sizeofObject( certBundleSize ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeWantbackBestCertPath( INOUT_PTR STREAM *stream,
									  const SCVP_PROTOCOL_INFO *protocolInfo,
									  IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	int certBundleSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCert ) );

	status = certBundleSize = sizeofCertItem( iCryptCert, 
											  CRYPT_ICERTFORMAT_CERTSEQUENCE );
	if( cryptStatusError( status ) )
		return( status );
	writeSequence( stream, protocolInfo->wbBestCertPathSize );
	writeOID( stream, SCVP_OID_WANTBACK_BESTCERTPATH );
	status = writeOctetStringHole( stream, certBundleSize, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = exportCertToStream( stream, iCryptCert, 
									 CRYPT_ICERTFORMAT_CERTSEQUENCE );
		}

	return( status );
	}

/* Write an error response, which is just the first part of an SCVP 
   response:

	CVResponse ::= SEQUENCE {
		cvResponseVersion			INTEGER = 1,
		serverConfigurationID		INTEGER = 1,
		producedAt					GeneralizedTime,
		responseStatus				SEQUENCE {
			cvStatusCode			ENUMERATED { ... },
			},
		requestRef				[1] EXPLICIT [0] SEQUENCE {
			algorithm				AlgorithmIdentifier DEFAULT SHA-1,
			value					OCTET STRING
			}
		} */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void sendErrorResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
							   IN_ERROR const int errorStatus )
	{
	STREAM stream;
	int scvpStatus, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );
	
	REQUIRES_V( cryptStatusError( errorStatus ) );

	/* Try and map the cryptlib status to an SCVP one.  Since this isn't 
	   always possible we may have to fall back to a generic invalid-request 
	   response */
	status = mapValue( errorStatus, &scvpStatus, statusToSCVPMapTbl, 
					   FAILSAFE_ARRAYSIZE( statusToSCVPMapTbl, MAP_TABLE ) );
	if( cryptStatusError( status ) )
		scvpStatus = SCVP_STATUS_INVALIDREQUEST;

	/* Write the general header information.  We write the status even if it
	   has the default value because writing an empty SEQUENCE to convey the
	   status quacks more like an encoding error than something done 
	   deliberately */
	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 
			  sessionInfoPtr->receiveBufSize );
	writeSequence( &stream, 
				   sizeofShortInteger( 1 ) + sizeofShortInteger( 1 ) + \
				   sizeofGeneralizedTime() + \
				   sizeofObject( sizeofEnumerated( scvpStatus ) ) + \
				   sizeofRequestRef( protocolInfo ) );
	writeShortInteger( &stream, 1, DEFAULT_TAG );
	writeShortInteger( &stream, 1, DEFAULT_TAG );
	writeGeneralizedTime( &stream, getTime( GETTIME_NOFAIL_MINUTES ), 
						  DEFAULT_TAG );
	writeSequence( &stream, sizeofEnumerated( scvpStatus ) );
	writeEnumerated( &stream, scvpStatus, DEFAULT_TAG );
	status = writeRequestRef( &stream, protocolInfo );
	if( cryptStatusOK( status ) )
		sessionInfoPtr->receiveBufEnd = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		ERROR_INFO localErrorInfo;

		/* Since this message is being sent in response to an existing 
		   error, we don't care about the possible error information 
		   returned from the function that sends the error response,
		   so the ERROR_INFO result is ignored */
		clearErrorInfo( &localErrorInfo );
		status = envelopeSign( sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufEnd,
							   sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufSize, 
							   &sessionInfoPtr->receiveBufEnd, 
							   CRYPT_CONTENT_SCVPCERTVALRESPONSE, 
							   sessionInfoPtr->privateKey, CRYPT_UNUSED, 
							   &localErrorInfo );
		}
	if( cryptStatusError( status ) )
		{
		HTTP_DATA_INFO httpDataInfo;

		/* If we encounter an error generating the error response then there 
		   won't be anything available to send.  At this point the best that 
		   we can do is send an error at the HTTP level */
		status = initHttpInfoReq( &httpDataInfo );
		ENSURES_V( cryptStatusOK( status ) );
		httpDataInfo.reqStatus = errorStatus;
		sioctlSet( &sessionInfoPtr->stream, STREAM_IOCTL_LASTMESSAGE, TRUE );
		( void ) swrite( &sessionInfoPtr->stream, &httpDataInfo, 
						 sizeof( HTTP_DATA_INFO ) );
		return;
		}
	DEBUG_DUMP_FILE( "scvp_srespx", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );

	( void ) writePkiDatagram( sessionInfoPtr, SCVP_CONTENTTYPE_RESPONSE, 
							   SCVP_CONTENTTYPE_RESPONSE_LEN,
							   MK_ERRTEXT( "Couldnt send SCVP error response "
										   "to client" ) );
	}

/* Write an SCVP response:

	CVResponse ::= SEQUENCE {
		cvResponseVersion			INTEGER = 1,
		serverConfigurationID		INTEGER = 1,
		producedAt					GeneralizedTime,
		responseStatus				SEQUENCE {
			cvStatusCode			ENUMERATED { ... } DEFAULT okay,
			},
		requestRef				[1] EXPLICIT [0] SEQUENCE {
			algorithm				AlgorithmIdentifier DEFAULT SHA-1,
			value					OCTET STRING
			} OPTIONAL,									-- Mandatory
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
			} OPTIONAL,									-- Mandatory
		respNonce				[5]	OCTET STRING OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeReplyObjects( INOUT_PTR STREAM *stream,
							  INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	/* Write general bookkeeping information.  We write the replyStatus even 
	   if it's the default value because it seems a bit odd to leave out the
	   most important field of the response */
	status = writeCertRef( stream, sessionInfoPtr->iCertRequest );
	if( cryptStatusError( status ) )
		return( status );
	writeEnumerated( stream, protocolInfo->scvpReplyStatus, DEFAULT_TAG );
	writeGeneralizedTime( stream, getTime( GETTIME_NOFAIL_MINUTES ), 
						  DEFAULT_TAG );
	writeSequence( stream, sizeofObject( protocolInfo->checksSize ) );
	writeSequence( stream, protocolInfo->checksSize );
	status = writeRawObject( stream, protocolInfo->checks, 
							 protocolInfo->checksSize );
	if( cryptStatusError( status ) )
		return( status );

	/* If there are no wantbacks, we're done */
	if( !protocolInfo->wantBacks )
		return( CRYPT_OK );

	/* If we're only doing a size check, just fill in the length fields */
	if( sIsNullStream( stream ) )
		{
		protocolInfo->wbTotalSize = 0;
		if( protocolInfo->wantBacks & SCVP_WANTBACK_FLAG_CERT )
			{
			protocolInfo->wbCertSize = \
				sizeofWantbackCert( sessionInfoPtr->iCertRequest );
			protocolInfo->wbTotalSize += \
				sizeofObject( protocolInfo->wbCertSize );
			}
		if( ( protocolInfo->wantBacks & SCVP_WANTBACK_FLAG_BESTCERTPATH ) && \
			protocolInfo->iWantbackCertPath != CRYPT_ERROR )
			{
			protocolInfo->wbBestCertPathSize = \
				sizeofWantbackBestCertPath( protocolInfo->iWantbackCertPath );
			protocolInfo->wbTotalSize += \
				sizeofObject( protocolInfo->wbBestCertPathSize );
			}
		if( protocolInfo->wbTotalSize <= 0 )
			return( CRYPT_OK );

		/* Pseudo-write the wantBack information so that an stell() can 
		   determine the total length */
		writeSequence( stream, protocolInfo->wbTotalSize );
		return( sSkip( stream, protocolInfo->wbTotalSize, SSKIP_MAX ) );
		}

	/* Write the overall wrapper for the wantbacks */
	status = writeSequence( stream, protocolInfo->wbTotalSize );
	if( cryptStatusError( status ) )
		return( status );

	/* If the client wants back a copy of the certificate that it's just 
	   sent us in the request, in case they misplaced their own copy or
	   something and the copy that we've already sent in the CertReference
	   isn't enough, send them back yet another copy of the same thing that 
	   they just sent us */
	if( protocolInfo->wantBacks & SCVP_WANTBACK_FLAG_CERT )
		{
		status = writeWantbackCert( stream, protocolInfo, 
									sessionInfoPtr->iCertRequest );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If the client wants back a full certificate chain for the certificate
	   that it's just sent us, send back the chain.  If this is a query-not-
	   processed response then there could be no certificate chain present 
	   so we only try and send it if the chain was successfully fetched */
	if( ( protocolInfo->wantBacks & SCVP_WANTBACK_FLAG_BESTCERTPATH ) && \
		protocolInfo->iWantbackCertPath != CRYPT_ERROR )
		{
		status = writeWantbackBestCertPath( stream, protocolInfo, 
											protocolInfo->iWantbackCertPath );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createScvpResponse( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	STREAM stream;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	int replyObjSize DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* Determine how big the reply objects will be */
	sMemNullOpen( &stream );
	status = writeReplyObjects( &stream, sessionInfoPtr, protocolInfo );
	if( cryptStatusOK( status ) )
		replyObjSize = stell( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );

	sMemOpen( &stream, sessionInfoPtr->receiveBuffer, 
			  sessionInfoPtr->receiveBufSize );

	/* Write a gap for the outer SEQUENCE wrapper.  This will always be in 
	   the range of 1-2K ... 16K or so, so we know that the length will be 
	   encoded as two bytes.  To fill the space we write a dummy length of 
	   10K which will be overwritten once we know the actual length */
	writeSequence( &stream, 10000 );

	/* Write the general header information.  We write the status even if it
	   has the default value because writing an empty SEQUENCE to convey the
	   status quacks more like an encoding error than something done 
	   deliberately */
	writeShortInteger( &stream, 1, DEFAULT_TAG );
	writeShortInteger( &stream, 1, DEFAULT_TAG );
	writeGeneralizedTime( &stream, getTime( GETTIME_NOFAIL_MINUTES ), 
						  DEFAULT_TAG );
	writeSequence( &stream, sizeofEnumerated( SCVP_STATUS_OKAY ) );
	status = writeEnumerated( &stream, SCVP_STATUS_OKAY, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Write the request reference.  Yet another optional-but-mandatory 
	   field, this is reqired to check that the request, which is sent 
	   unprotected, hasn't been tampered with */
	status = writeRequestRef( &stream, protocolInfo );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Write the reply objects */
	writeConstructed( &stream, sizeofObject( replyObjSize ), 
					  CTAG_RP_REPLYOBJECTS );
	status = writeSequence( &stream, replyObjSize );
	if( cryptStatusOK( status ) )
		status = writeReplyObjects( &stream, sessionInfoPtr, protocolInfo );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Finally, write the nonce if there was one present in the request */
	if( protocolInfo->nonceSize > 0 )
		{
		status = writeOctetString( &stream, protocolInfo->nonce, 
								   protocolInfo->nonceSize, 
								   CTAG_RP_RESPNONCE  );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}

	/* We've written the entire message, determine how long it is so that we 
	   can add the header.  This overwrites the dummy 16-bit length value 
	   that we wrote earlier.  The magic value that's subtracted from the 
	   overall length is the size of the SEQUENCE wrapper, consisting of 
	   tag + length-of-length + 2-byte length */
	sessionInfoPtr->receiveBufEnd = stell( &stream );
	ENSURES( sessionInfoPtr->receiveBufEnd > 256 && \
			 sessionInfoPtr->receiveBufEnd <= 65536 );
	sseek( &stream, 0 );
	status = writeSequence( &stream, 
							sessionInfoPtr->receiveBufEnd - ( 1 + 1 + 2 ) );
	sMemDisconnect( &stream );
	ENSURES( isBufsizeRangeNZ( sessionInfoPtr->receiveBufEnd ) );
	if( cryptStatusError( status ) )
		return( status );
	DEBUG_DUMP_FILE( "scvp_sresp0", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );

	/* Sign the response in preparation for sending it to the client */
	clearErrorInfo( &localErrorInfo );
	status = envelopeSign( sessionInfoPtr->receiveBuffer, 
						   sessionInfoPtr->receiveBufEnd,
						   sessionInfoPtr->receiveBuffer, 
						   sessionInfoPtr->receiveBufSize, 
						   &sessionInfoPtr->receiveBufEnd, 
						   CRYPT_CONTENT_SCVPCERTVALRESPONSE, 
						   sessionInfoPtr->privateKey, CRYPT_UNUSED, 
						   &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo, 
					 "Couldn't sign SCVP response data with CA key for "
					 "'%s'",
					 getCertHolderName( sessionInfoPtr->privateKey, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	DEBUG_DUMP_FILE( "scvp_sresp1", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							SCVP Server Functions							*
*																			*
****************************************************************************/

/* Exchange data with a SCVP client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int serverTransact( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	SCVP_PROTOCOL_INFO protocolInfo;
	STREAM stream;
	BOOLEAN requestDataOK;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionSCVP( sessionInfoPtr ) );

	/* Initialise the server-side protocol state information */
	status = initSCVPprotocolInfo( &protocolInfo, sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the initial message from the client.  We don't write an error
	   response at the initial read stage to prevent scanning/DOS attacks 
	   (vir sapit qui pauca loquitur) */
	status = readPkiDatagram( sessionInfoPtr, MIN_CRYPT_OBJECTSIZE,
							  MK_ERRTEXT( "Couldnt read SCVP request from "
										  "client" ) );
	if( cryptStatusError( status ) )
		{
		destroySCVPprotocolInfo( &protocolInfo );
		return( status );
		}
	CFI_CHECK_UPDATE( "readPkiDatagram" );

	/* Basic lint filter to check for approximately-OK requests before we
	   try applying enveloping operations to the data:

		SEQUENCE {
			OID xxxx			-- contentType = scvpCertValRequest
			[0] {				-- content
				SEQUENCE {
					... 

	   We can't go beyond the first encapsulated SEQUENCE because what 
	   follows is an INTEGER DEFAULT 1 but some implementations don't know 
	   that you're not supposed to encode default values so we could see
	   different things at this point */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	readSequence( &stream, NULL );
	readUniversal( &stream );
	readConstructed( &stream, NULL, 0 );
	status = readSequence( &stream, NULL );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		sendCertErrorResponse( sessionInfoPtr, CRYPT_ERROR_BADDATA );
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid SCVP request header" ) );
		}

	/* Process the initial message from the client */
	status = checkScvpRequest( sessionInfoPtr, &protocolInfo, 
							   &requestDataOK );
	if( cryptStatusError( status ) )
		{
		/* If we're fuzzing the input then we're done, the writes below are 
		   turned into no-ops but the enveloping of the response still 
		   requires a private-key operation so we exit before we get there */
		FUZZ_EXIT();

		/* If we got far enough into the request data to be able to send an 
		   SCVP-level response, send that, otherwise just send an HTTP-level
		   response */
		delayRandom();	/* Dither error timing info */
		if( requestDataOK )
			sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		else
			sendCertErrorResponse( sessionInfoPtr, status );
		destroySCVPprotocolInfo( &protocolInfo );
		return( status );
		}
	CFI_CHECK_UPDATE( "checkScvpRequest" );

	/* If we're fuzzing the input then we're reading static data for which 
	   we can't go beyond this point */
	FUZZ_EXIT();

	/* Return the certificate to the client */
	status = processScvpRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		status = createScvpResponse( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		{
		delayRandom();	/* Dither error timing info */
		sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		destroySCVPprotocolInfo( &protocolInfo );
		return( status );
		}
	status = writePkiDatagram( sessionInfoPtr, SCVP_CONTENTTYPE_RESPONSE, 
							   SCVP_CONTENTTYPE_RESPONSE_LEN,
							   MK_ERRTEXT( "Couldnt send SCVP response to "
										   "client" ) );
	destroySCVPprotocolInfo( &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "createScvpResponse" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "readPkiDatagram", "checkScvpRequest", 
								   "createScvpResponse" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initSCVPserverProcessing( SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	FNPTR_SET( sessionInfoPtr->transactFunction, serverTransact );
	}
#endif /* USE_SCVP */
