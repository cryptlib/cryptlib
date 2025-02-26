/****************************************************************************
*																			*
*							Read CMP Message Types							*
*						Copyright Peter Gutmann 1999-2020					*
*																			*
****************************************************************************/

#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "cmp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "session/session.h"
  #include "session/cmp.h"
#endif /* Compiler-specific includes */

#ifdef USE_CMP

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#if 0	/* 12/6/09 Due to a bug in the buffer-positioning the following code 
				   hasn't actually worked since 3.2.1 in 2005, since this 
				   hasn't caused any complaints we disable it for attack-
				   surface reduction */

/* Read a certificate encrypted with CMP's garbled reinvention of CMS 
   content:

	EncryptedCert ::= SEQUENCE {
		dummy1			[0]	... OPTIONAL,		-- Ignored
		cekAlg			[1]	AlgorithmIdentifier,-- CEK algorithm
		encCEK			[2]	BIT STRING,			-- Encrypted CEK
		dummy2			[3]	... OPTIONAL,		-- Ignored
		dummy3			[4] ... OPTIONAL,		-- Ignored
		encData			BIT STRING				-- Encrypted certificate
		} 

   This muddle is only applied for non-cryptlib sessions, if two cryptlib
   implementations are communicating then the certificate is wrapped using 
   CMS */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 5 ) ) \
static int readEncryptedDataInfo( INOUT_PTR STREAM *stream, 
								  OUT_BUFFER_ALLOC( *encDataLength ) \
										void **encDataPtrPtr, 
								  OUT_LENGTH_BOUNDED_Z( maxLength ) \
										int *encDataLength, 
								  IN_LENGTH_SHORT_MIN( 32 ) const int minLength,
								  IN_LENGTH_SHORT_MIN( 32 ) const int maxLength )
	{
	void *dataPtr;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( encDataPtrPtr, sizeof( void * ) ) );
	assert( isWritePtr( encDataLength, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( minLength, 32 ) && \
			  minLength < maxLength );

	/* Clear return values */
	*encDataPtrPtr = NULL;
	*encDataLength = 0;

	/* Read and remember the encrypted data */
	status = readBitStringHole( stream, &length, minLength, 
								CTAG_EV_ENCCEK );
	if( cryptStatusError( status ) )
		return( status );
	if( length < MIN_PKCSIZE || length > CRYPT_MAX_PKCSIZE )
		return( CRYPT_ERROR_BADDATA );
	status = sMemGetDataBlock( stream, &dataPtr, length );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, length );
	if( cryptStatusError( status ) )
		return( status );
	*encDataPtrPtr = dataPtr;
	*encDataLength = length;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int readEncryptedCert( INOUT_PTR STREAM *stream,
							  IN_HANDLE const CRYPT_CONTEXT iImportContext,
							  OUT_BUFFER( outDataMaxLength, *outDataLength ) \
									void *outData, 
							  IN_DATALENGTH_MIN( 16 ) const int outDataMaxLength,
							  OUT_DATALENGTH_Z int *outDataLength, 
							  INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT iSessionKey;
	MECHANISM_WRAP_INFO mechanismInfo;
	QUERY_INFO queryInfo;
	void *encKeyPtr = DUMMY_INIT_PTR, *encCertPtr;
	int encKeyLength = DUMMY_INIT, encCertLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isHandleRangeValid( iImportContext ) );

	/* Read the CEK algorithm identifier and encrypted CEK.  All of the
	   values are optional although there's no indication of why or what
	   you're supposed to do if they're not present (OTOH for others there's
	   no indication of what you're supposed to do when they're present
	   either) so we treat an absent required value as an error and ignore
	   the others */
	status = readSequence( stream, NULL );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_EV_DUMMY1 ) )	/* Junk */
		status = readUniversal( stream );
	if( !cryptStatusError( status ) )			/* CEK algo */
		{
		status = readContextAlgoID( stream, &iSessionKey, &queryInfo,
									CTAG_EV_CEKALGO );
		}
	if( !cryptStatusError( status ) )			/* Enc.CEK */
		{
		status = readEncryptedDataInfo( stream, &encKeyPtr, &encKeyLength, 
										MIN_PKCSIZE, CRYPT_MAX_PKCSIZE );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo, 
				  "Invalid encrypted certificate CEK information" ) );
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_EV_DUMMY2 ) )
		status = readUniversal( stream );		/* Junk */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_EV_DUMMY3 ) )
		status = readUniversal( stream );		/* Junk */
	if( !cryptStatusError( status ) )
		status = readEncryptedDataInfo( stream, &encCertPtr, &encCertLength,
										128, 8192 );
	if( !cryptStatusError( status ) &&			/* Enc.certificate */
		( queryInfo.cryptMode == CRYPT_MODE_ECB || \
		  queryInfo.cryptMode == CRYPT_MODE_CBC ) )
		{
		int blockSize;

		/* Make sure that the data length is valid.  Checking at this point
		   saves a lot of unnecessary processing and allows us to return a
		   more meaningful error code */
		status = krnlSendMessage( iSessionKey, IMESSAGE_GETATTRIBUTE, 
								  &blockSize, CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) || \
			( queryInfo.size % blockSize ) != 0 )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, errorInfo, 
				  "Invalid encrypted certificate data" ) );
		}

	/* Import the wrapped session key into the session key context */
	setMechanismWrapInfo( &mechanismInfo, encKeyPtr, encKeyLength,
						  NULL, 0, iSessionKey, iImportContext );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT,
							  &mechanismInfo, MECHANISM_ENC_PKCS1 );
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, errorInfo, 
				  "Couldn't decrypt encrypted certificate CEK" ) );
		}

	/* Decrypt the returned certificate and copy the result back to the
	   caller.  We don't worry about padding because the certificate-import
	   code knows when to stop based on the encoded certificate data */
	status = krnlSendMessage( iSessionKey, IMESSAGE_CTX_DECRYPT,
							  encCertPtr, encCertLength );
	krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		registerCryptoFailure();
		retExt( status,
				( status, errorInfo, 
				  "Couldn't decrypt returned encrypted certificate using "
				  "CEK" ) );
		}
	return( attributeCopyParams( outData, outDataMaxLength, outDataLength, 
								 encCertPtr, encCertLength ) );
	}
#endif /* 0 */

/* Process a request that's (supposedly) been authorised by an RA rather 
   than coming directly from a user */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int processRARequest( INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
							 IN_HANDLE const CRYPT_CERTIFICATE iCertRequest,
							 IN_ENUM_OPT( CMP_MESSAGE ) \
								const CMP_MESSAGE_TYPE messageType,
							 INOUT_PTR ERROR_INFO *errorInfo )
	{
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */

	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCertRequest ) );
	REQUIRES( messageType >= CTAG_PB_IR && messageType < CTAG_PB_LAST );
			  /* CTAG_PB_IR == 0 so this is the same as _NONE */

	/* If the user isn't an RA then this can't be an RA-authorised request */
	if( !protocolInfo->userIsRA )
		{
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo, 
				  "Request for '%s' supposedly from an RA didn't come from "
				  "an actual RA user",
				  getCertHolderName( iCertRequest, certName, 
									 CRYPT_MAX_TEXTSIZE ) ) );
		}

	/* An RA-authorised request can only be a CR.  They can't be an IR 
	   because they need to be signed, and they can't be a KUR or RR because 
	   we assume that users will be updating and revoking their own 
	   certificates, it doesn't make much sense to require an RA for this */
	if( messageType != CTAG_PB_CR )
		{
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo, 
				  "Request for '%s' supposedly from an RA is of the wrong "
				  "type %s, should be %s", 
				  getCertHolderName( iCertRequest, certName, 
									 CRYPT_MAX_TEXTSIZE ), 
				  getCMPMessageName( messageType ), 
				  getCMPMessageName( CTAG_PB_CR ) ) );
		}

	/* It's an RA-authorised request, mark the request as such */
	return( krnlSendMessage( iCertRequest, IMESSAGE_SETATTRIBUTE, 
							 MESSAGE_VALUE_TRUE, 
							 CRYPT_IATTRIBUTE_REQFROMRA ) );
	}

/****************************************************************************
*																			*
*								PKI Body Functions							*
*																			*
****************************************************************************/

/* Read request body:

	body			[n]	EXPLICIT SEQUENCE {	-- Processed by caller
						...					-- CRMF request
					} 

   The outer tag and SEQUENCE have already been processed by the caller */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readRequestBody( INOUT_PTR STREAM *stream, 
							INOUT_PTR SESSION_INFO *sessionInfoPtr,
							INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
							IN_ENUM_OPT( CMP_MESSAGE ) \
								const CMP_MESSAGE_TYPE messageType,
							IN_LENGTH_SHORT const int messageLength )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	MESSAGE_DATA msgData;
	ERROR_INFO localErrorInfo;
	BYTE authCertID[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionCMP( sessionInfoPtr ) );
	REQUIRES( sanityCheckCMPProtocolInfo( protocolInfo ) );
	REQUIRES( messageType >= CTAG_PB_IR && messageType < CTAG_PB_LAST );
			  /* CTAG_PB_IR == 0 so this is the same as _NONE */
	REQUIRES( isShortIntegerRangeNZ( messageLength ) );

	/* If we're fuzzing the input then we're reading static data for which 
	   we can't go beyond this point */
	FUZZ_SKIP_REMAINDER();

	/* Import the CRMF request */
	clearErrorInfo( &localErrorInfo );
	status = importCertFromStream( stream,
								   &sessionInfoPtr->iCertRequest,
								   DEFAULTUSER_OBJECT_HANDLE,
								   ( messageType == CTAG_PB_P10CR ) ? \
									CRYPT_CERTTYPE_CERTREQUEST : \
								   ( messageType == CTAG_PB_RR ) ? \
									CRYPT_CERTTYPE_REQUEST_REVOCATION : \
									CRYPT_CERTTYPE_REQUEST_CERT,
								   messageLength, KEYMGMT_FLAG_NONE,
								   &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADCERTTEMPLATE;
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
				     "Invalid CRMF request" ) );
		}

	/* If it's a request type that can be self-signed (revocation requests 
	   are unsigned) and it's from an encryption-only key (that is, a key 
	   that's not capable of signing, indicated by the request not being 
	   self-signed) remember this so that we can peform special-case 
	   processing later on */
	if( messageType != CTAG_PB_RR )
		{
		BOOLEAN_INT selfSigned;

		status = krnlSendMessage( sessionInfoPtr->iCertRequest,
								  IMESSAGE_GETATTRIBUTE, &selfSigned,
								  CRYPT_CERTINFO_SELFSIGNED );
		if( cryptStatusError( status ) )
			return( status );
		if( !selfSigned )
			{
			/* If the request is for a signing key then having an unsigned 
			   request is an error */
			status = krnlSendMessage( sessionInfoPtr->iCertRequest,
									  IMESSAGE_GETATTRIBUTE, &value,
									  CRYPT_CERTINFO_KEYUSAGE );
			if( cryptStatusOK( status ) && \
				( value & ( KEYUSAGE_SIGN | KEYUSAGE_CA ) ) )
				{
				protocolInfo->pkiFailInfo = CMPFAILINFO_BADCERTTEMPLATE;
				retExt( CRYPT_ERROR_INVALID,
						( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
						  "CRMF request for '%s' is for a signing key but "
						  "the request isn't signed",
						  getCertHolderName( sessionInfoPtr->iCertRequest, 
											 certName, 
											 CRYPT_MAX_TEXTSIZE ) ) );
				}
			protocolInfo->cryptOnlyKey = TRUE;
			}
		}

	/* Record the identity of the PKI user (for a MAC'd request) or 
	   certificate (for a signed request) that authorised this request */
	setMessageData( &msgData, authCertID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( protocolInfo->useMACreceive ? \
								cmpInfo->userInfo : \
								sessionInfoPtr->iAuthInContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sessionInfoPtr->iCertRequest,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_AUTHCERTID );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Revocation requests don't contain any information so there's nothing
	   further to check */
	if( messageType == CTAG_PB_RR )
		return( CRYPT_OK );

	/* Check whether this request is one that's been authorised by an RA
	   rather than coming directly from a user */
	status = krnlSendMessage( sessionInfoPtr->iCertRequest, 
							  IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_CERTINFO_KEYFEATURES );
	if( cryptStatusOK( status ) && ( value & KEYFEATURE_FLAG_RAISSUED ) )
		{
		status = processRARequest( protocolInfo, 
								   sessionInfoPtr->iCertRequest, 
								   messageType, SESSION_ERRINFO );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Make sure that the information in the request is consistent with the
	   user information template.  If it's an ir then the subject may not 
	   know their DN or may only know their CN, in which case they'll send 
	   an empty/CN-only subject DN in the hope that we can fill it in for 
	   them.  If it's not an ir then the user information acts as a filter 
	   to ensure that the request doesn't contain values that it shouldn't */
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_SETATTRIBUTE, &cmpInfo->userInfo,
							  CRYPT_IATTRIBUTE_PKIUSERINFO );
	if( cryptStatusError( status ) )
		{
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADCERTTEMPLATE;

		retExtObj( status,
					( status, SESSION_ERRINFO, 
					  sessionInfoPtr->iCertRequest,
					  "Information in certificate request for '%s' can't "
					  "be reconciled with our information for the user",
					  getCertHolderName( sessionInfoPtr->iCertRequest, 
										 certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	return( CRYPT_OK );
	}

/* Read response body:

	body			[n] EXPLICIT SEQUENCE {	-- Processed by caller
		caPubs		[1] EXPLICIT SEQUENCE {...} OPTIONAL,-- Ignored
		response		SEQUENCE {
						SEQUENCE {
			certReqID	INTEGER (0),
			status		PKIStatusInfo,
			certKeyPair	SEQUENCE {			-- If status == 0 or 1
				cert[0]	EXPLICIT Certificate,
or				cmpEncCert					-- For encr-only key
					[1] EXPLICIT CMPEncryptedCert,
or				cmsEncCert					-- For encr-only key
					[2] EXPLICIT EncryptedCert,
						...					-- Ignored
					}
				}
			}
		}

   The outer tag and SEQUENCE have already been processed by the caller */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readResponseBody( INOUT_PTR STREAM *stream, 
							 INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
							 IN_ENUM_OPT( CMP_MESSAGE ) \
								const CMP_MESSAGE_TYPE messageType,
							 STDC_UNUSED IN_LENGTH_SHORT const int messageLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *bodyInfoPtr DUMMY_INIT_PTR;
	int bodyLength, tag, value, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionCMP( sessionInfoPtr ) );
	REQUIRES( sanityCheckCMPProtocolInfo( protocolInfo ) );
	REQUIRES( messageType == CTAG_PB_IP || messageType == CTAG_PB_CP || \
			  messageType == CTAG_PB_KUP || messageType == CTAG_PB_RP );

	/* Skip any noise before the payload if necessary.  The only field that
	   could be present here is caPubs, a field that's never defined in the
	   standard (it literally exists purely as a named field in an ASN.1
	   structure, there's no explanation of what it's for or how it's 
	   supposed to be used) */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_CR_CAPUBS ) )
		{
		int certSize;

		readConstructed( stream, NULL, CTAG_CR_CAPUBS );
		status = readSequence( stream, &certSize );
		if( cryptStatusOK( status ) )
			{
			DEBUG_PRINT(( "%s: Skipping caPubs field in %s length %d.\n", 
						  isServer( sessionInfoPtr ) ? "SVR" : "CLI", 
						  getCMPMessageName( messageType ), certSize ));
			status = sSkip( stream, certSize, SSKIP_MAX );
			}
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Invalid caPubs field in %s",
					  getCMPMessageName( messageType ) ) );
			}
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from checkStatusPeekTag() */

	/* If it's a revocation response then the only returned data is the 
	   status value */
	if( protocolInfo->operation == CTAG_PB_RR )
		{
		status = readSequence( stream, NULL );/* Inner wrapper */
		if( cryptStatusError( status ) )
			return( status );
		return( readPkiStatusInfo( stream, 
								   isServer( sessionInfoPtr ) ? TRUE : FALSE,
								   FALSE, &sessionInfoPtr->errorInfo ) );
		}

	/* It's a certificate response, unwrap the body to find the certificate 
	   payload */
	readSequence( stream, NULL );			/* Inner wrapper */
	readSequence( stream, NULL );
	status = readUniversal( stream );		/* certReqId */
	if( cryptStatusOK( status ) )
		{
		status = readPkiStatusInfo( stream, isServer( sessionInfoPtr ) ? \
											TRUE : FALSE, FALSE, 
									&sessionInfoPtr->errorInfo );
		}
	if( cryptStatusError( status ) )
		return( status );
	readSequence( stream, NULL );			/* certKeyPair wrapper */
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	tag = EXTRACT_CTAG( tag );
	status = readConstructed( stream, &bodyLength, tag );
	if( cryptStatusOK( status ) )
		status = sMemGetDataBlock( stream, &bodyInfoPtr, bodyLength );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( bodyInfoPtr != NULL );

	/* If we're fuzzing the input then we're reading static data for which 
	   we can't go beyond this point */
	FUZZ_SKIP_REMAINDER();

	/* Process the returned certificate as required */
	clearErrorInfo( &localErrorInfo );
	switch( tag )
		{
		case CTAG_CK_CERT:
			/* Plaintext certificate, we're done */
			break;

#if 0	/* 12/6/09 See earlier comment */
		case CTAG_CK_ENCRYPTEDCERT:
			/* Certificate encrypted with CMP's garbled attempt at doing 
			   CMS, try and decrypt it */
			status = readEncryptedCert( stream, sessionInfoPtr->privateKey,
										SESSION_ERRINFO );
			break;
#endif /* 0 */

		case CTAG_CK_NEWENCRYPTEDCERT:
			{
			/* Certificate encrypted with CMS, unwrap it.  Note that this 
			   relies on the fact that cryptlib generates the 
			   subjectKeyIdentifier that's used to identify the decryption 
			   key by hashing the subjectPublicKeyInfo, this is needed 
			   because when the newly-issued certificate is received only 
			   the keyID is available (since the certificate hasn't been 
			   decrypted and read yet) while the returned certificate uses 
			   the sKID to identify the decryption key.  If the keyID and
			   sKID aren't the same then the envelope-unwrapping code will
			   report a CRYPT_ERROR_WRONGKEY */
			status = envelopeUnwrap( bodyInfoPtr, bodyLength,
									 bodyInfoPtr, bodyLength, &bodyLength,
									 sessionInfoPtr->privateKey, NULL, 0,
									 &localErrorInfo );
			if( cryptStatusError( status ) )
				{
				registerCryptoFailure();
				retExtErr( cryptArgError( status ) ? \
						   CRYPT_ERROR_FAILED : status,
						   ( cryptArgError( status ) ? \
							 CRYPT_ERROR_FAILED : status, SESSION_ERRINFO, 
							 &localErrorInfo, 
							 "Couldn't decrypt CMS enveloped certificate "
							 "in %s with key for '%s'",
							 getCMPMessageName( messageType ),
							 getCertHolderName( sessionInfoPtr->privateKey, 
												certName, 
												CRYPT_MAX_TEXTSIZE ) ) );
				}
			break;
			}

		default:
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Unknown returned certificate encapsulation type %d "
					  "in %s", tag, getCMPMessageName( messageType ) ) );
		}
	ENSURES( cryptStatusOK( status ) );
		/* All error paths have already been checked above */

	/* Import the certificate as a cryptlib object */
	setMessageCreateObjectIndirectInfo( &createInfo, bodyInfoPtr, bodyLength,
										CRYPT_CERTTYPE_CERTIFICATE, 
										&localErrorInfo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT, &createInfo,
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Invalid returned certificate in %s",
					 getCMPMessageName( messageType ) ) );
		}
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;

	/* In order to acknowledge receipt of this message we have to return at a
	   later point a hash of the certificate carried in this message created 
	   using the hash algorithm used in the certificate signature.  This 
	   makes the CMP-level transport layer dependant on the certificate 
	   format it's carrying (so the code will break every time a new 
	   certificate hash algorithm or certificate format is added), but 
	   that's what the standard requires */
	status = krnlSendMessage( sessionInfoPtr->iCertResponse,
							  IMESSAGE_GETATTRIBUTE, &value,
							  CRYPT_IATTRIBUTE_CERTHASHALGO );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't extract confirmation hash type from returned "
				  "certificate for '%s'",
				  getCertHolderName( sessionInfoPtr->iCertResponse, 
									 certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	if( ( value != CRYPT_ALGO_SHA1 && value != CRYPT_ALGO_SHA2 && \
		  value != CRYPT_ALGO_SHAng ) || !algoAvailable( value ) )
		{
		/* Certificates can only provide fingerprints using a subset of
		   available hash algorithms */
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "Can't confirm certificate issue for '%s' using %s "
				  "algorithm",
				  getCertHolderName( sessionInfoPtr->iCertResponse, 
									 certName, CRYPT_MAX_TEXTSIZE ),
				  getAlgoName( value ) ) );
		}
	protocolInfo->confHashAlgo = value;

	return( CRYPT_OK );
	}

/* Read conf body:

	body		   [19]	EXPLICIT SEQUENCE {	-- Processed by caller
						SEQUENCE {
		certHash		OCTET STRING
		certReqID		INTEGER (0),
			}
		}

   The outer tag and SEQUENCE have already been processed by the caller */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readConfBody( INOUT_PTR STREAM *stream, 
						 INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						 IN_ENUM_OPT( CMP_MESSAGE ) \
							const CMP_MESSAGE_TYPE messageType,
						 IN_LENGTH_SHORT_Z const int messageLength )
	{
	static const MAP_TABLE hashMapTable[] = {
		/* We're the server so we control the hash algorithm that'll be 
		   used, which means that it'll always be one of the following */
		{ CRYPT_ALGO_SHA1, MESSAGE_COMPARE_FINGERPRINT_SHA1 },
		{ CRYPT_ALGO_SHA2, MESSAGE_COMPARE_FINGERPRINT_SHA2 },
		{ CRYPT_ALGO_SHAng, MESSAGE_COMPARE_FINGERPRINT_SHAng },
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	MESSAGE_DATA msgData;
	BYTE certHash[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	int compareMessageValue, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionCMP( sessionInfoPtr ) );
	REQUIRES( sanityCheckCMPProtocolInfo( protocolInfo ) );
	REQUIRES( messageType == CTAG_PB_CERTCONF );
	REQUIRES( isShortIntegerRange( messageLength ) );

	/* If there's no certStatus then the client has rejected the 
	   certificate.  This isn't an explicit error since it's a valid 
	   protocol outcome so we return an OK status but set the overall 
	   protocol status to a generic error value to indicate that we don't 
	   want to continue normally */
	if( messageLength <= 0 )
		{
		protocolInfo->status = CRYPT_ERROR;
		return( CRYPT_OK );
		}

	/* Read the client's returned confirmation information */
	readSequence( stream, NULL );
	status = readOctetString( stream, certHash, &length,
							  MIN_HASHSIZE, CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid %s message for certificate for '%s'",
				  getCMPMessageName( messageType ),
				  getCertHolderName( sessionInfoPtr->iCertResponse, 
									 certName, CRYPT_MAX_TEXTSIZE ) ) );
		}

	/* Compare the certificate hash to the one sent by the client.  Since 
	   we're the server this is a cryptlib-issued certificate so we know 
	   that it'll always be a supported algorithm */
	status = mapValue( protocolInfo->confHashAlgo, &compareMessageValue,
					   hashMapTable, 
					   FAILSAFE_ARRAYSIZE( hashMapTable, MAP_TABLE ) );
	ENSURES( cryptStatusOK( status ) );
	setMessageData( &msgData, certHash, length );
	status = krnlSendMessage( sessionInfoPtr->iCertResponse, 
							  IMESSAGE_COMPARE, &msgData, 
							  compareMessageValue );
	if( cryptStatusError( status ) )
		{
		/* The user is confirming an unknown certificate, the best that we 
		   can do is return a generic certificate-mismatch error */
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADCERTID;
		retExt( CRYPT_ERROR_NOTFOUND,
				( CRYPT_ERROR_NOTFOUND, SESSION_ERRINFO, 
				  "Returned certificate hash in %s doesn't match issued "
				  "certificate for '%s'",
				  getCMPMessageName( messageType ),
				  getCertHolderName( sessionInfoPtr->iCertResponse, 
									 certName, CRYPT_MAX_TEXTSIZE ) ) );
		}

	return( CRYPT_OK );
	}

/* Read genMsg body:

	body		   [21]	EXPLICIT SEQUENCE OF {	-- Processed by caller
						SEQUENCE {
		infoType		OBJECT IDENTIFIER,
		intoValue		ANY DEFINED BY infoType OPTIONAL
						}
					}

   The outer tag and SEQUENCE have already been processed by the caller.
   The code currently assumes a single entry in the SEQUENCE, in the 
   sense that it doesn't look for anything past the first entry, which is
   all that's needed to process PKIBoot requests */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readGenMsgBody( INOUT_PTR STREAM *stream, 
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   STDC_UNUSED CMP_PROTOCOL_INFO *protocolInfo,
						   IN_ENUM_OPT( CMP_MESSAGE ) \
								const CMP_MESSAGE_TYPE messageType,
						   IN_LENGTH_SHORT const int messageLength )
	{
	static const OID_INFO genMessageOIDinfo[] = {
		{ OID_PKIBOOT, 0 },
		{ WILDCARD_OID, 1 },
		{ NULL, 0 }, { NULL, 0 }
		};
	ERROR_INFO localErrorInfo;
	const BOOLEAN isRequest = ( messageType == CTAG_PB_GENM ) ? TRUE : FALSE;
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionCMP( sessionInfoPtr ) );
	REQUIRES( messageType == CTAG_PB_GENM || messageType == CTAG_PB_GENP );
	REQUIRES( isShortIntegerRangeNZ( messageLength ) );

	/* If it's a request GenMsg, check for a PKIBoot request */
	if( isRequest )
		{
		int length, endPos;

		/* Read the type-and-value information */
		status = readSequence( stream, &length );
		if( cryptStatusError( status ) )
			return( status );
		endPos = stell( stream ) + length;
		REQUIRES( isIntegerRangeMin( endPos, length ) );
		status = readOID( stream, genMessageOIDinfo, 
						  FAILSAFE_ARRAYSIZE( genMessageOIDinfo, OID_INFO ),
						  &value );
		if( cryptStatusOK( status ) && stell( stream ) < endPos )
			{
			/* There's infoValue data attached, skip it */
			status = readUniversal( stream );
			}
		if( cryptStatusError( status ) )
			{
			retExt( status, 
					( status, SESSION_ERRINFO, 
					  "Invalid %s type-and-value pair",
					  getCMPMessageName( messageType ) ) );
			}

		/* If it's something that we don't recognise, skip it */
		if( value != 0 )
			{
			DEBUG_PRINT(( "%s: Skipping unknown %s information "
						  "length %d.\n", 
						  isServer( sessionInfoPtr ) ? "SVR" : "CLI", 
						  getCMPMessageName( messageType ), length ));
			return( CRYPT_OK );
			}

		return( CRYPT_OK );
		}

	/* If we're fuzzing the input then we're reading static data for which 
	   we can't go beyond this point */
	FUZZ_SKIP_REMAINDER();

	/* It's a PKIBoot response with the InfoTypeAndValue handled as CMS
	   content (see the comment for writeGenMsgResponseBody() in 
	   cmp_wrmsg.c, in particular that infoType ::= id-signedData and
	   infoValue ::= [0] EXPLICIT SignedData), import the certificate 
	   trust list.  Since this isn't a true certificate chain and isn't 
	   used as such, we import it as data-only certificates */
	clearErrorInfo( &localErrorInfo );
	status = importCertFromStream( stream, &sessionInfoPtr->iCertResponse,
								   DEFAULTUSER_OBJECT_HANDLE, 
								   CRYPT_CERTTYPE_CERTCHAIN, messageLength,
								   KEYMGMT_FLAG_DATAONLY_CERT,
								   &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, SESSION_ERRINFO, &localErrorInfo,
					 "Invalid %s PKIBoot response",
					 getCMPMessageName( messageType ) ) );
		}
	return( CRYPT_OK );
	}

/* Read error body.  In the typical CMP mishmash this consists of an error 
   message with error details containing as its first element a differently-
   formatted set of error details.  To deal with this mess we stop at the 
   first set of error details that make sense:

	body		   [23]	EXPLICIT SEQUENCE {	-- Processed by caller
		pkiStatusInfo	SEQUENCE {
			status		INTEGER,
			statusString SEQUENCE OF UTF8STRING OPTIONAL,
			failInfo	BIT STRING OPTIONAL	-- PKIFailureInfo
			}
		errorCode		INTEGER OPTIONAL,	-- Implementation-specific
		errorDetails	SEQUENCE OF UTF8String OPTIONAL	
											-- Ignored
		}

   The outer tag and SEQUENCE have already been processed by the caller.
   
   The protocolInfo parameter isn't modified but can't be declared const 
   because the function signature has to match that of the overall read
   functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readErrorBody( INOUT_PTR STREAM *stream, 
						  INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR /* const */ CMP_PROTOCOL_INFO *protocolInfo,
						  IN_ENUM_OPT( CMP_MESSAGE ) \
								const CMP_MESSAGE_TYPE messageType,
						  IN_LENGTH_SHORT const int messageLength )
	{
	ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;
#ifdef USE_ERRMSGS
	const char *peerTypeString = isServer( sessionInfoPtr ) ? \
								 "Client" : "Server";
#endif /* USE_ERRMSGS */
	const int endPos = stell( stream ) + messageLength;
	int tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionCMP( sessionInfoPtr ) );
	REQUIRES( sanityCheckCMPProtocolInfo( protocolInfo ) );
	REQUIRES( messageType == CTAG_PB_ERROR );
	REQUIRES( isShortIntegerRangeNZ( messageLength ) );
	REQUIRES( isIntegerRangeMin( endPos, messageLength ) );

	/* Read the outer wrapper and PKI status information.  In another one of
	   CMP's many wonderful features there are two places to communicate 
	   error information with no clear indication in the spec as to which one
	   is meant to be used.  To deal with this we stop at the first one that
	   contains an error status.
	   
	   First we read the pkiStatusInfo, this usually contains the information
	   that we want.  Since this is an error-return function it usually 
	   returns with an error status set to the cryptlib-mapped form of the
	   pkiStatusInfo, in which case we exit at this point */
	status = readPkiStatusInfo( stream, 
								isServer( sessionInfoPtr ) ? TRUE : FALSE,
								protocolInfo->noIntegrity, errorInfo );
	if( cryptStatusError( status ) )
		{
		/* Return with the error status read by readPkiStatusInfo() */
		return( status );
		}

	/* Getting to here means that we've got an error message with status no-
	   error, warn the user in debug mode */
	DEBUG_PRINT(( "%s returned %s message with error status no-error.\n", 
				  peerTypeString, getCMPMessageName( messageType ) ));
	assert_nofuzz( DEBUG_WARN );
	 
	/* In addition to the PKI status information there can be a second lot
	   of error information which is exactly the same only different, so if 
	   we haven't got anything from the status information we check to see 
	   whether this layer can give us anything */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == BER_INTEGER )
		{
		long value;

		status = readShortInteger( stream, &value );
		if( cryptStatusOK( status ) && !isIntegerRange( value ) )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status ) )
			{
#ifdef USE_ERRMSGS
			const int errorCode = ( int ) value;
#endif /* USE_ERRMSGS */

			retExt( CRYPT_ERROR_FAILED,
					( CRYPT_ERROR_FAILED, errorInfo,
					  protocolInfo->noIntegrity ? \
					  "%s returned non-authenticated %s response: "
						"Nonspecific failure code %d" : \
					  "%s returned %s response with nonspecific failure "
						"code %d",
					  peerTypeString, getCMPMessageName( messageType ), 
					  errorCode ) );
			}
		}
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == BER_SEQUENCE )
		{
		/* Skip the errorDetails, whatever that may be */
		status = readUniversal( stream );
		}
	/* Fall through with error code from the above reads */

	/* We've got all the way through without there being any error 
	   information present, make sure that we always return an error code.  
	   That is, if there's no error in reading the error information then we 
	   still have to return an error because what we've successfully read is 
	   a report of an error */
	retExt( cryptStatusError( status ) ? status : CRYPT_ERROR_FAILED,
			( cryptStatusError( status ) ? status : CRYPT_ERROR_FAILED, 
			  errorInfo, protocolInfo->noIntegrity ? \
			  "%s returned non-authenticated %s error response: No error" : \
			  "%s returned %s error response: No error", 
			  peerTypeString, getCMPMessageName( messageType ) ) );
	}

/****************************************************************************
*																			*
*						Read Function Access Information					*
*																			*
****************************************************************************/

typedef struct {
	const CMP_MESSAGE_TYPE type;
	const READMESSAGE_FUNCTION function;
	} MESSAGEREAD_INFO;
static const MESSAGEREAD_INFO messageReadTable[] = {
	{ CTAG_PB_IR, readRequestBody },
	{ CTAG_PB_CR, readRequestBody },
	{ CTAG_PB_P10CR, readRequestBody },
	{ CTAG_PB_KUR, readRequestBody },
	{ CTAG_PB_RR, readRequestBody },
	{ CTAG_PB_IP, readResponseBody },
	{ CTAG_PB_CP, readResponseBody },
	{ CTAG_PB_KUP, readResponseBody },
	{ CTAG_PB_RP, readResponseBody },
	{ CTAG_PB_CERTCONF, readConfBody },
	{ CTAG_PB_PKICONF, readConfBody },
	{ CTAG_PB_GENM, readGenMsgBody },
	{ CTAG_PB_GENP, readGenMsgBody },
	{ CTAG_PB_ERROR, readErrorBody },
	{ CTAG_PB_LAST, NULL }, { CTAG_PB_LAST, NULL }
	};

CHECK_RETVAL_PTR \
READMESSAGE_FUNCTION getMessageReadFunction( IN_ENUM_OPT( CMP_MESSAGE ) \
									const CMP_MESSAGE_TYPE messageType )
	{
	LOOP_INDEX i;

	REQUIRES_N( messageType >= CTAG_PB_IR && messageType < CTAG_PB_LAST );
				/* CTAG_PB_IR == 0 so this is the same as _NONE */

	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( messageReadTable, \
									  MESSAGEREAD_INFO ) && \
				  messageReadTable[ i ].type != CTAG_PB_LAST,
			  i++ )
		{
		ENSURES_N( LOOP_INVARIANT_MED( i, 0, 
									   FAILSAFE_ARRAYSIZE( messageReadTable, \
														   MESSAGEREAD_INFO ) - 1 ) );

		if( messageReadTable[ i ].type == messageType )
			return( messageReadTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( messageReadTable, MESSAGEREAD_INFO ) );

	return( NULL );
	}
#endif /* USE_CMP */
