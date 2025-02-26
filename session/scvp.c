/****************************************************************************
*																			*
*						 cryptlib SCVP Session Management					*
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

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the session state and protocol information */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionSCVP( IN_PTR const SESSION_INFO *sessionInfoPtr )
	{
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Check the general envelope state */
	if( !sanityCheckSession( sessionInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionSCVP: Session check" ));
		return( FALSE );
		}

	/* Check SCVP session parameters */
	if( !CHECK_FLAGS( sessionInfoPtr->protocolFlags, SCVP_PFLAG_NONE, 
					  SCVP_PFLAG_MAX ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionSCVP: Protocol flags" ));
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSCVPProtocolInfo( IN_PTR \
										const SCVP_PROTOCOL_INFO *protocolInfo )
	{
	/* Check server status information */
	if( !isEnumRangeOpt( protocolInfo->scvpReplyStatus, SCVP_REPLYSTATUS ) || \
		!( protocolInfo->iWantbackCertPath == CRYPT_ERROR || \
		   isHandleRangeValid( protocolInfo->iWantbackCertPath ) ) )
		{
		DEBUG_PUTS(( "sanityCheckSCVPProtocolInfo: Server status information" ));
		return( FALSE );
		}

	/* Check state variables */
	if( protocolInfo->nonceSize < 0 || \
		protocolInfo->nonceSize > CRYPT_MAX_HASHSIZE )
		{
		DEBUG_PUTS(( "sanityCheckSCVPProtocolInfo: State variables" ));
		return( FALSE );
		}

	/* Check checks and wantBack information */
	if( protocolInfo->checksSize < 0 || \
		protocolInfo->checksSize > MAX_OID_SIZE || \
		!( isFlagRangeZ( protocolInfo->wantBacks, SCVP_WANTBACK ) ) )
		{
		DEBUG_PUTS(( "sanityCheckSCVPProtocolInfo: Checks/wantback information" ));
		return( FALSE );
		}

	/* Check wantBack entry sizes */
	if( !isShortIntegerRange( protocolInfo->wbCertSize ) || \
		!isShortIntegerRange( protocolInfo->wbBestCertPathSize ) || \
		!isShortIntegerRange( protocolInfo->wbTotalSize ) )
		{
		DEBUG_PUTS(( "sanityCheckSCVPProtocolInfo: Wantback entry sizes" ));
		return( FALSE );
		}

	/* Check request hash information */
	if( protocolInfo->requestHashSize < 0 || \
		protocolInfo->requestHashSize > CRYPT_MAX_HASHSIZE || \
		!( protocolInfo->requestHashAlgo == CRYPT_ALGO_NONE || \
		   isHashAlgo( protocolInfo->requestHashAlgo ) ) ) 
		{
		DEBUG_PUTS(( "sanityCheckSCVPProtocolInfo: Request hash information" ));
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Initialise and clean up protocol information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initSCVPprotocolInfo( OUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
						  IN_PTR const SESSION_INFO *sessionInfoPtr )
	{
	int value, status;

	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	memset( protocolInfo, 0, sizeof( SCVP_PROTOCOL_INFO ) );
	protocolInfo->iWantbackCertPath = CRYPT_ERROR;

	/* Get any state information that we may need */
	status = krnlSendMessage( sessionInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_OPTION_ENCR_HASH );
	if( cryptStatusError( status ) || \
		!checkAlgoID( value, CRYPT_MODE_NONE ) )
		{
		protocolInfo->requestHashAlgo = CRYPT_ALGO_SHA2;
		protocolInfo->requestHashSize = bitsToBytes( 256 );
		}
	else
		{
		protocolInfo->requestHashAlgo = value;	/* int vs.enum */
		status = krnlSendMessage( sessionInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_OPTION_ENCR_HASHPARAM );
		if( cryptStatusOK( status ) )
			protocolInfo->requestHashSize = value;
		else
			protocolInfo->requestHashSize = bitsToBytes( 256 );
		}

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroySCVPprotocolInfo( INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo )
	{
	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );

	if( protocolInfo->iWantbackCertPath != CRYPT_ERROR )
		{
		krnlSendNotifier( protocolInfo->iWantbackCertPath, 
						  IMESSAGE_DECREFCOUNT );
		}

	zeroise( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) );
	}

/* Calculate the requestorRef, a hash of the request used to detect 
   manipulation */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int calculateRequestHash( INOUT_PTR SCVP_PROTOCOL_INFO *protocolInfo,
						  IN_BUFFER( requestDataLength ) \
								const void *requestData,
						  IN_LENGTH const int requestDataLength )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	STREAM stream;
	void *request DUMMY_INIT_PTR;
	int requestLength, dummy, status;

	assert( isWritePtr( protocolInfo, sizeof( SCVP_PROTOCOL_INFO ) ) );
	assert( isReadPtr( requestData, requestDataLength ) );

	REQUIRES( isIntegerRangeMin( requestDataLength, MIN_CRYPT_OBJECTSIZE ) );

	/* Read past the CMS wrapper to get to the encapsulated content that 
	   needs to be hashed:

		SEQUENCE {
			contentType		OBJECT IDENTIFIER;
			content		[0]	SEQUENCE { ... }
			} */
	sMemConnect( &stream, requestData, requestDataLength );
	readSequence( &stream, NULL );		/* Outer SEQUENCE */
	readUniversal( &stream );			/* OID */
	status = readConstructed( &stream, &requestLength, 0 );
	if( cryptStatusOK( status ) )
		status = sMemGetDataBlock( &stream, &request, requestLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the message contents */
	getHashAtomicParameters( protocolInfo->requestHashAlgo, 
							 protocolInfo->requestHashSize, 
							 &hashFunctionAtomic, &dummy );
	hashFunctionAtomic( protocolInfo->requestHash, CRYPT_MAX_HASHSIZE, 
						request, requestLength );
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Validation Policy Functions							*
*																			*
****************************************************************************/

/* Read a validation policy:

	ValidationPolicy ::= SEQUENCE {
		validationPolRef			SEQUENCE {
			valPolId				OBJECT IDENTIFIER svpDefaultValPolicy,
			valPolParams			ANY DEFINED BY valPolId OPTIONAL
			},
		validationAlg			[0]	... OPTIONAL,	-- Ignored
		userPolicySet			[1]	... OPTIONAL,	-- Ignored
		inhibitPolicyMapping	[2]	... OPTIONAL,	-- Ignored
		requireExplicitPolicy	[3]	... OPTIONAL,	-- Ignored
		inhibitAnyPolicy		[4]	... OPTIONAL,	-- Ignored
		trustAnchors			[5]	... OPTIONAL,	-- Ignored
		keyUsages				[6]	... OPTIONAL,	-- Ignored
		extendedKeyUsages		[7]	... OPTIONAL,	-- Ignored
		specifiedKeyUsages		[8]	... OPTIONAL,	-- Ignored
		} 

   This is yet another place where digital ancestor-worship clashes with 
   practical reality, for a blacklist-based approach it's necessary to 
   perform an incredible silly-walk to try and sort out something that may 
   or may not be valid while for a whitelist-based approach there's only one 
   outcome, "valid" or "not valid".  Because of this the huge mass of policy 
   information is simply a pointless distraction to returning a result that 
   can only be either FALSE or TRUE, so for now we simply skip it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readValidationPolicy( INOUT_PTR STREAM *stream, 
						  INOUT_PTR ERROR_INFO *errorInfo )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	return( readUniversal( stream ) );
	}

/* Write a validation policy:

	ValidationPolicy ::= SEQUENCE {
		validationPolRef			SEQUENCE {
			valPolId				OBJECT IDENTIFIER svpDefaultValPolicy
			}
		} */

CHECK_RETVAL_LENGTH \
int sizeofValidationPolicy( void )
	{
	return( sizeofShortObject( \
				sizeofShortObject( \
					sizeofOID( OID_SCVP_DEFAULTVALPOLICY ) ) ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeValidationPolicy( INOUT_PTR STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	writeSequence( stream, 
				   sizeofShortObject( \
						sizeofOID( OID_SCVP_DEFAULTVALPOLICY ) ) ); 
	writeSequence( stream, sizeofOID( OID_SCVP_DEFAULTVALPOLICY ) ); 
	return( writeOID( stream, OID_SCVP_DEFAULTVALPOLICY ) );
	}

/****************************************************************************
*																			*
*						Certificate Reference Functions						*
*																			*
****************************************************************************/

/* Read a certificate reference:

	CertReferences ::=			[0]	SEQUENCE OF CHOICE {
		cert					[0]	Certificate,
		pkcRef					[1]	SEQUENCE {
			certHash				OCTET STRING,
			issuerSerial			SEQUENCE {
				issuer				SEQUENCE OF GeneralName,	-- Must be cert DN
				serialNumber		INTEGER,
			hashAlgorithm			AlgorithmIdentifier DEFAULT sha-1
			}
		} 

   There are two variants of this, CertReferences which is a [0] SEQUENCE OF 
   PKCReference and CertReference which is a straight PKCReference.  The 
   definition is actually an error-tempting double indirection of:

	CertReference ::= CHOICE {
		pkc							PKCReference,
		ac							ACReference
		}

	PKCReference ::= CHOICE {
		cert					[0]	Certificate,
		pkcRef					[1]	SCVPCertID
		}

	ACReference ::= CHOICE {
		attrCert				[2]	AttributeCertificate,
		acRef					[3]	SCVPCertID
		}

   with no idication as to why there needs to be a distinction since both 
   the certificate itself and the OID identifying what's being done indicate 
   whether it's an attribute certificate or not */

enum { CTAG_CR_PKCREFS };
enum { CTAG_PR_CERT, CTAG_PR_PKCREF };

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readCertRef( INOUT_PTR STREAM *stream, 
				 OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCryptCert,
				 INOUT_PTR ERROR_INFO *errorInfo )
	{
	BYTE *certDataPtr;
	int length, tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Clear return value */
	*iCryptCert = CRYPT_ERROR;

	/* Check the certificate reference type.  For now we only allow a direct 
	   certificate reference since nothing seems to use the garbled pkcRef 
	   option */
	if( peekTag( stream ) != MAKE_CTAG( CTAG_PR_CERT ) )
		return( CRYPT_ERROR_BADDATA );

	/* Find out how big the certificate is */
	status = getStreamObjectLength( stream, &length, MIN_CRYPT_OBJECTSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Importing the certificate is a pain because of the weird nonstandard 
	   tagging used, and we can't rewrite the tag into the correct form 
	   because we're probably dealing with a read-only stream.  Because of
	   this we have to access the stream buffer directly and swap out the
	   tag around the certificate import */
	status = sMemGetDataBlock( stream, ( void ** ) &certDataPtr, 1 );
	if( cryptStatusError( status ) )
		return( status );
	tag = *certDataPtr;
	*certDataPtr = BER_SEQUENCE;
	status = importCertFromStream( stream, iCryptCert, 
								   DEFAULTUSER_OBJECT_HANDLE,
								   CRYPT_CERTTYPE_CERTIFICATE, length, 
								   KEYMGMT_FLAG_NONE, errorInfo );
	*certDataPtr = intToByte( tag );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readCertRefs( INOUT_PTR STREAM *stream, 
				  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCryptCert,
				  INOUT_PTR ERROR_INFO *errorInfo )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Clear return value */
	*iCryptCert = CRYPT_ERROR;

	/* Read the certificate reference wrapper */
	status = readConstructed( stream, NULL, CTAG_CR_PKCREFS );
	if( cryptStatusOK( status ) )
		status = readCertRef( stream, iCryptCert, errorInfo );
	return( status );
	}

/* Write a certificate reference:

	CertReferences ::= [0] SEQUENCE { [0] Certificate } */

CHECK_RETVAL_LENGTH \
int sizeofCertRef( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	MESSAGE_DATA msgData;
	int status;

	REQUIRES( isHandleRangeValid( iCryptCert ) );

	/* Determine the size of the exported certificate */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );

	return( msgData.length );
	}

CHECK_RETVAL_LENGTH \
int sizeofCertRefs( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	int length, status;

	REQUIRES( isHandleRangeValid( iCryptCert ) );

	status = length = sizeofCertRef( iCryptCert );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( length ) );
	
	return( sizeofShortObject( length ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCertRef( INOUT_PTR STREAM *stream,
				  IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	const int certDataOffset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iCryptCert ) );
	REQUIRES( isIntegerRange( certDataOffset ) );
			  /* The start offset can be zero if we're writing to a null 
			     stream for a length check */

	/* Write the certificate and then rewrite the SEQUENCE tag at the 
	   start of the certificate data with the [0] tag for a 'cert' 
	   CHOICE */
	status = exportCertToStream( stream, iCryptCert, 
								 CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		const int streamPos = stell( stream );

		ENSURES( isIntegerRangeMin( streamPos, MIN_CRYPT_OBJECTSIZE ) );
		sseek( stream, certDataOffset );
		writeTag( stream, MAKE_CTAG( CTAG_PR_CERT ) );
		sseek( stream, streamPos );
		}

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCertRefs( INOUT_PTR STREAM *stream,
				   IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( iCryptCert ) );

	/* Determine the size of the exported certificate */
	status = length = sizeofCertRef( iCryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the certificate reference */
	status = writeConstructed( stream, length, CTAG_CR_PKCREFS );
	if( cryptStatusOK( status ) )
		status = writeCertRef( stream, iCryptCert );
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
	CRYPT_CERTIFICATE cryptCert = *( ( CRYPT_CERTIFICATE * ) data );
	BOOLEAN_INT isInited;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, sizeof( int ) ) );

	REQUIRES( type == CRYPT_SESSINFO_REQUEST );

	/* Make sure that there aren't any conflicts with existing attributes */
	if( !checkAttributesConsistent( sessionInfoPtr, type ) )
		return( CRYPT_ERROR_INITED );

	/* Make sure that everything is set up ready to go.  The certificate 
	   object type has already been checked by the kernel */
	status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE, &isInited, 
							  CRYPT_CERTINFO_IMMUTABLE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !isInited )
		{
		retExt( CRYPT_ARGERROR_NUM1,
				( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
				  "Certificate is incomplete" ) );
		}

	/* Add the request and increment its usage count */
	krnlSendNotifier( cryptCert, IMESSAGE_INCREFCOUNT );
	sessionInfoPtr->iCertRequest = cryptCert;

	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodSCVP( INOUT_PTR SESSION_INFO *sessionInfoPtr )
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
		1, 1, 1,					/* Version 1 */
		CRYPT_SUBPROTOCOL_NONE, CRYPT_SUBPROTOCOL_NONE
									/* Allowed sub-protocols */

		/* Protocol-specific information */
		};

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Set the access method pointers */
	DATAPTR_SET( sessionInfoPtr->protocolInfo, ( void * ) &protocolInfo );
	if( isServer( sessionInfoPtr ) )
		initSCVPserverProcessing( sessionInfoPtr );
	else
		initSCVPclientProcessing( sessionInfoPtr );
	FNPTR_SET( sessionInfoPtr->setAttributeFunction, setAttributeFunction );

	return( CRYPT_OK );
	}
#endif /* USE_SCVP */
