/****************************************************************************
*																			*
*							Certificate Write Routines						*
*						Copyright Peter Gutmann 1996-2016					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

/* The X.509 version numbers */

enum { X509VERSION_1, X509VERSION_2, X509VERSION_3 };
enum { X509ACVERSION_1, X509ACVERSION_2 }; 

#ifdef USE_CERTIFICATES

#if defined( __MVS__ )
  /* MVS control section (CSECT) names default to the file name and can't
	 match any symbol name either in the file or in another file or library 
	 (e.g. write.c vs. write()).  Because of this we have to explicitly 
	 name the csect's so that they don't conflict with external symbol
	 names */
  #pragma csect( CODE, "writeC" )
  #pragma csect( STATIC, "writeS" )
  #pragma csect( TEST, "writeT" )
#endif /* __MVS__ */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

#if defined( USE_CERTREV ) || defined( USE_CERTVAL )

/* Set/refresh a nonce in an RTCS/OCSP request (difficile est tenere quae 
   acceperis nisi exerceas) */

static int setNonce( INOUT_PTR DATAPTR_ATTRIBUTE *attributePtr,
					 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE nonceType )
	{
	DATAPTR_ATTRIBUTE attribute;
	MESSAGE_DATA msgData;
	void *noncePtr;
	int nonceLength, status;

	assert( isWritePtr( attributePtr, sizeof( DATAPTR_ATTRIBUTE ) ) );

	REQUIRES( nonceType == CRYPT_CERTINFO_CMS_NONCE || \
			  nonceType == CRYPT_CERTINFO_OCSP_NONCE );

	/* To ensure freshness we always use a new nonce when we write an RTCS 
	   or OCSP request */
	attribute = findAttributeField( *attributePtr, nonceType,
									CRYPT_ATTRIBUTE_NONE );
	if( DATAPTR_ISNULL( attribute ) )
		{
		CRYPT_ATTRIBUTE_TYPE dummy1;
		CRYPT_ERRTYPE_TYPE dummy2;
		ERROR_INFO localErrorInfo;
		BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];

		/* There's no nonce present, add a new one.  Since this is a 
		   low-level operation there isn't any useful additional error 
		   information to return */
		clearErrorInfo( &localErrorInfo );
		setMessageData( &msgData, nonce, 16 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		return( addAttributeFieldString( attributePtr, nonceType, 
										 CRYPT_ATTRIBUTE_NONE, nonce, 16, 
										 ATTR_FLAG_NONE, FALSE, 
										 &localErrorInfo, &dummy1, 
										 &dummy2 ) );
		}

	/* There's an existing nonce present, refresh it */
	status = getAttributeDataPtr( attribute, &noncePtr, &nonceLength );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( nonceLength == 16 );
	setMessageData( &msgData, noncePtr, 16 );
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE ) );
	}
#endif /* USE_CERTREV || USE_CERTVAL */

/****************************************************************************
*																			*
*							Write Certificate Objects						*
*																			*
****************************************************************************/

/* Write certificate information:

	CertificateInfo ::= SEQUENCE {
		version			  [ 0 ]	EXPLICIT INTEGER DEFAULT(0),
		serialNumber			INTEGER,
		signature				AlgorithmIdentifier,
		issuer					Name
		validity				Validity,
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		extensions		  [ 3 ]	Extensions OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeCertInfo( INOUT_PTR STREAM *stream, 
						  INOUT_PTR CERT_INFO *subjectCertInfoPtr,
						  IN_PTR const CERT_INFO *issuerCertInfoPtr,
						  IN_HANDLE const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_CERT_INFO *certCertInfo = subjectCertInfoPtr->cCertCert;
	ALGOID_PARAMS algoIDparams;
	int algoIdInfoSize, length, extensionSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( sanityCheckCert( issuerCertInfoPtr ) );
	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		BOOLEAN_INT isXyzzyCert;
		int dnCheckFlag = PRE_CHECK_DN;

		/* If it's a XYZZY certificate then a complete DN isn't required */
		status = getCertComponent( subjectCertInfoPtr, CRYPT_CERTINFO_XYZZY, 
								   &isXyzzyCert );
		if( cryptStatusOK( status ) && isXyzzyCert == TRUE )
			dnCheckFlag = PRE_CHECK_DN_PARTIAL;

		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   PRE_SET_STANDARDATTR | PRE_SET_ISSUERATTR | \
									   PRE_SET_ISSUERDN | PRE_SET_VALIDITYPERIOD );
		if( cryptStatusError( status ) )
			return( status );
		status = preCheckCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									  PRE_CHECK_SPKI | dnCheckFlag | \
									  PRE_CHECK_ISSUERDN | PRE_CHECK_SERIALNO | \
							( TEST_FLAG( subjectCertInfoPtr->flags, 
										 CERT_FLAG_SELFSIGNED ) ? \
									  0 : PRE_CHECK_NONSELFSIGNED_DN ),
							( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
									  PRE_FLAG_DN_IN_ISSUERCERT : \
									  PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded */
	status = length = ( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
						issuerCertInfoPtr->subjectDNsize : \
						sizeofDN( subjectCertInfoPtr->issuerName );
	if( cryptStatusError( status ) )
		return( status );
	subjectCertInfoPtr->issuerDNsize = length;
	status = length = sizeofDN( subjectCertInfoPtr->subjectName );
	if( cryptStatusError( status ) )
		return( status );
	subjectCertInfoPtr->subjectDNsize = length;

	/* Determine the size of the certificate information */
	initAlgoIDparamsHash( &algoIDparams, certCertInfo->hashAlgo, 
						  certCertInfo->hashParam );
	status = algoIdInfoSize = \
				sizeofContextAlgoIDex( iIssuerCryptContext, 
									   &algoIDparams );
	if( cryptStatusError( status ) )
		return( status );
	status = extensionSize = \
				sizeofAttributes( subjectCertInfoPtr->attributes,
								  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	length = sizeofInteger( certCertInfo->serialNumber,
							certCertInfo->serialNumberLength ) + \
			 algoIdInfoSize + \
			 subjectCertInfoPtr->issuerDNsize + \
			 sizeofObject( sizeofTime( subjectCertInfoPtr->startTime ) + \
						   sizeofTime( subjectCertInfoPtr->endTime ) ) + \
			 subjectCertInfoPtr->subjectDNsize + \
			 subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize > 0 )
		{
		length += sizeofObject( sizeofShortInteger( X509VERSION_3 ) ) + \
				  sizeofObject( sizeofObject( extensionSize ) );
		}

	/* Write the outer SEQUENCE wrapper */
	status = writeSequence( stream, length );
	if( cryptStatusError( status ) )
		return( status );

	/* If there are extensions present, mark this as a v3 certificate */
	if( extensionSize > 0 )
		{
		writeConstructed( stream, sizeofShortInteger( X509VERSION_3 ),
						  CTAG_CE_VERSION );
		status = writeShortInteger( stream, X509VERSION_3, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the serial number and signature algorithm identifier */
	initAlgoIDparamsHash( &algoIDparams, certCertInfo->hashAlgo, 
						  certCertInfo->hashParam );
	writeInteger( stream, certCertInfo->serialNumber,
				  certCertInfo->serialNumberLength, DEFAULT_TAG );
	status = writeContextAlgoIDex( stream, iIssuerCryptContext,
								   &algoIDparams );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the issuer name, validity period, subject name, and public key
	   information */
	if( issuerCertInfoPtr->subjectDNptr != NULL )
		{
		status = swrite( stream, issuerCertInfoPtr->subjectDNptr,
						 issuerCertInfoPtr->subjectDNsize );
		}
	else
		{
		status = writeDN( stream, subjectCertInfoPtr->issuerName, 
						  DEFAULT_TAG );
		}
	if( cryptStatusError( status ) )
		return( status );
	writeSequence( stream, sizeofTime( subjectCertInfoPtr->startTime ) + \
						   sizeofTime( subjectCertInfoPtr->endTime ) );
	writeTime( stream, subjectCertInfoPtr->startTime );
	writeTime( stream, subjectCertInfoPtr->endTime );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = swrite( stream, subjectCertInfoPtr->publicKeyInfo,
						 subjectCertInfoPtr->publicKeyInfoSize );
		}
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CERTIFICATE, extensionSize ) );
	}

#ifdef USE_ATTRCERT

/* Write attribute certificate information.  There are two variants of this, 
   v1 attributes certificates that were pretty much never used (the fact 
   that no-one had bothered to define any attributes to be used with them
   didn't help here) and v2 attribute certificates that are also almost
   never used but are newer, we write v2 certificates.  The original v1
   attribute certificate format was:

	AttributeCertificateInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(0),
		owner			  [ 1 ]	Name,
		issuer					Name,
		signature				AlgorithmIdentifier,
		serialNumber			INTEGER,
		validity				Validity,
		attributes				SEQUENCE OF Attribute,
		extensions				Extensions OPTIONAL
		} 

   In v2 this changed to:

	AttributeCertificateInfo ::= SEQUENCE {
		version					INTEGER (1),
		holder					SEQUENCE {
			entityNames	  [ 1 ]	SEQUENCE OF {
				entityName[ 4 ]	EXPLICIT Name
								},
							}
		issuer			  [ 0 ]	SEQUENCE {
			issuerNames			SEQUENCE OF {
				issuerName[ 4 ]	EXPLICIT Name
								},
							}
		signature				AlgorithmIdentifier,
		serialNumber			INTEGER,
		validity				SEQUENCE {
			notBefore			GeneralizedTime,
			notAfter			GeneralizedTime
								},
		attributes				SEQUENCE OF Attribute,
		extensions				Extensions OPTIONAL
		} 

   In order to write the issuer and owner/holder DN as GeneralName we encode
   it using the DN choice of a GeneralName with explicit tag 4, see the 
   comments on GeneralName encoding in cert/ext_def.c for an explanation of 
   the tagging.
   
   Since there aren't any attributes defined, we write a dummy clearance
   attribute so that there's at least one field present:

	  0  12: SEQUENCE {
	  2   3:   OBJECT IDENTIFIER clearance (2 5 4 55)
	  7   5:   SEQUENCE {
	  9   3:     OBJECT IDENTIFIER '1 2 3 4'
	       :     }
	       :   } */

#define DUMMY_ATTRIBUTE			"\x30\x0C\x06\x03\x55\x04\x37\x30\x05\x06\x03\x2A\x03\x04"
#define DUMMY_ATTRIBUTE_SIZE	14

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeAttributeCertInfo( INOUT_PTR STREAM *stream,
								   INOUT_PTR CERT_INFO *subjectCertInfoPtr,
								   IN_PTR const CERT_INFO *issuerCertInfoPtr,
								   IN_HANDLE const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_CERT_INFO *certCertInfo = subjectCertInfoPtr->cCertCert;
	ALGOID_PARAMS algoIDparams;
	int algoIdInfoSize, length, extensionSize;
	int issuerNameSize, holderNameSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( sanityCheckCert( issuerCertInfoPtr ) );
	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   PRE_SET_ISSUERDN | PRE_SET_ISSUERATTR | \
									   PRE_SET_VALIDITYPERIOD );
		if( cryptStatusError( status ) )
			return( status );
		status = preCheckCertificate( subjectCertInfoPtr, issuerCertInfoPtr, 
									  PRE_CHECK_DN | PRE_CHECK_ISSUERDN | \
									  PRE_CHECK_SERIALNO | \
							( TEST_FLAG( subjectCertInfoPtr->flags, 
										 CERT_FLAG_SELFSIGNED ) ? \
									  0 : PRE_CHECK_NONSELFSIGNED_DN ),
							( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
									  PRE_FLAG_DN_IN_ISSUERCERT : \
									  PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded */
	status = length = ( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
						issuerCertInfoPtr->subjectDNsize : \
						sizeofDN( subjectCertInfoPtr->issuerName );
	if( cryptStatusError( status ) )
		return( status );
 	issuerNameSize = length;
	status = length = sizeofDN( subjectCertInfoPtr->subjectName );
	if( cryptStatusError( status ) )
		return( status );
	holderNameSize = length;

	/* Determine the size of the certificate information */
	initAlgoIDparamsHash( &algoIDparams, certCertInfo->hashAlgo, 
						  certCertInfo->hashParam );
	status = algoIdInfoSize = \
					sizeofContextAlgoIDex( iIssuerCryptContext, 
										   &algoIDparams );
	if( cryptStatusError( status ) )
		return( status );
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_ATTRIBUTE_CERT );
	if( cryptStatusError( status ) )
		return( status );
	length = sizeofShortInteger( X509ACVERSION_2 ) + \
			 sizeofObject( sizeofObject( sizeofObject( holderNameSize ) ) ) + \
			 sizeofObject( sizeofObject( sizeofObject( issuerNameSize ) ) ) + \
			 algoIdInfoSize + \
			 sizeofInteger( certCertInfo->serialNumber,
							certCertInfo->serialNumberLength ) + \
			 sizeofObject( sizeofGeneralizedTime() * 2 ) + \
			 sizeofObject( DUMMY_ATTRIBUTE_SIZE );
	if( extensionSize > 0 )
		length += sizeofShortObject( extensionSize );

	/* Write the outer SEQUENCE wrapper and version */
	writeSequence( stream, length );
	status = writeShortInteger( stream, X509ACVERSION_2, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the owner and issuer name */
	writeSequence( stream, sizeofObject( sizeofObject( holderNameSize ) ) );
	writeConstructed( stream, sizeofObject( holderNameSize ), 
					  CTAG_AC_HOLDER_ENTITYNAME );
	writeConstructed( stream, holderNameSize, 4 );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		writeConstructed( stream, 
						  sizeofObject( sizeofObject( issuerNameSize ) ), 0 );
		writeSequence( stream, sizeofObject( issuerNameSize ) );
		writeConstructed( stream, issuerNameSize, 4 );
		if( issuerCertInfoPtr->subjectDNptr != NULL )
			{
			status = swrite( stream, issuerCertInfoPtr->subjectDNptr,
							 issuerCertInfoPtr->subjectDNsize );
			}
		else
			{
			status = writeDN( stream, subjectCertInfoPtr->issuerName, 
							  DEFAULT_TAG );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the signature algorithm identifier, serial number and validity
	   period */
	initAlgoIDparamsHash( &algoIDparams, certCertInfo->hashAlgo, 
						  certCertInfo->hashParam );
	writeContextAlgoIDex( stream, iIssuerCryptContext, 
						  &algoIDparams );
	writeInteger( stream, certCertInfo->serialNumber,
				  certCertInfo->serialNumberLength, DEFAULT_TAG );
	writeSequence( stream, sizeofGeneralizedTime() * 2 );
	writeGeneralizedTime( stream, subjectCertInfoPtr->startTime, 
						  DEFAULT_TAG );
	status = writeGeneralizedTime( stream, subjectCertInfoPtr->endTime, 
								   DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attributes */
	writeSequence( stream, DUMMY_ATTRIBUTE_SIZE );
	status = swrite( stream, DUMMY_ATTRIBUTE, DUMMY_ATTRIBUTE_SIZE );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_ATTRIBUTE_CERT, extensionSize ) );
	}
#endif /* USE_ATTRCERT */

/****************************************************************************
*																			*
*								Write CRL Objects							*
*																			*
****************************************************************************/

#ifdef USE_CERTREV

/* Write CRL information:

	CRLInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(0),
		signature				AlgorithmIdentifier,
		issuer					Name,
		thisUpdate				UTCTime,
		nextUpdate				UTCTime OPTIONAL,
		revokedCertificates		SEQUENCE OF RevokedCerts,
		extensions		  [ 0 ]	Extensions OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCRLInfo( INOUT_PTR STREAM *stream, 
						 INOUT_PTR CERT_INFO *subjectCertInfoPtr,
						 IN_PTR_OPT const CERT_INFO *issuerCertInfoPtr,
						 IN_HANDLE_OPT \
							const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	const BOOLEAN isCrlEntry = ( issuerCertInfoPtr == NULL ) ? TRUE : FALSE;
	ALGOID_PARAMS algoIDparams;
	BOOLEAN isV2CRL;
	int length, algoIdInfoSize, extensionSize, revocationInfoLength;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( issuerCertInfoPtr == NULL && \
			  iIssuerCryptContext == CRYPT_UNUSED ) || \
			( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) && \
			  isHandleRangeValid( iIssuerCryptContext ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( issuerCertInfoPtr == NULL || \
			  sanityCheckCert( issuerCertInfoPtr ) );
	REQUIRES( ( issuerCertInfoPtr == NULL && \
				iIssuerCryptContext == CRYPT_UNUSED ) || \
			  ( issuerCertInfoPtr != NULL && \
				isHandleRangeValid( iIssuerCryptContext ) ) );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		if( isCrlEntry )
			{
			status = preEncodeCertificate( subjectCertInfoPtr, NULL,
										   PRE_SET_REVINFO );
			}
		else
			{
			status = preEncodeCertificate( subjectCertInfoPtr, 
										   issuerCertInfoPtr,
										   PRE_SET_ISSUERDN | \
										   PRE_SET_ISSUERATTR | \
										   PRE_SET_REVINFO );
			if( cryptStatusError( status ) )
				return( status );
			status = preCheckCertificate( subjectCertInfoPtr, 
										  issuerCertInfoPtr,
										  PRE_CHECK_ISSUERCERTDN | \
										  PRE_CHECK_ISSUERDN,
										  PRE_FLAG_DN_IN_ISSUERCERT );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process CRL entries and version information */
	subjectCertInfoPtr->version = \
				( DATAPTR_ISSET( subjectCertInfoPtr->attributes ) ) ? 2 : 1;
	status = revocationInfoLength = \
				sizeofCRLentries( certRevInfo->revocations, &isV2CRL );
	if( cryptStatusError( status ) )
		return( status );
	if( isV2CRL )
		{
		/* The CRL can be forced to v2 even if it would otherwise by v1 by 
		   the presence of certain information in the CRL entries */
		subjectCertInfoPtr->version = 2;
		}

	/* If we're being asked to write a single CRL entry, we don't try and go
	   any further since the remaining CRL fields (and issuer information) 
	   may not be set up */
	if( isCrlEntry )
		{
		const REVOCATION_INFO *revInfoPtr;

		revInfoPtr = DATAPTR_GET( certRevInfo->currentRevocation );
		ENSURES_B( revInfoPtr != NULL );
		return( writeCRLentry( stream, revInfoPtr ) );
		}

	ENSURES( issuerCertInfoPtr != NULL );

	/* Determine how big the encoded CRL will be */
	initAlgoIDparamsHash( &algoIDparams, certRevInfo->hashAlgo, 
						  certRevInfo->hashParam );
	status = algoIdInfoSize = \
					sizeofContextAlgoIDex( iIssuerCryptContext, 
										   &algoIDparams );
	if( cryptStatusError( status ) )
		return( status );
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_CRL );
	if( cryptStatusError( status ) )
		return( status );
	length = algoIdInfoSize + \
			 issuerCertInfoPtr->subjectDNsize + \
			 sizeofTime( subjectCertInfoPtr->startTime ) + \
			 ( ( subjectCertInfoPtr->endTime > MIN_TIME_VALUE ) ? \
				sizeofTime( subjectCertInfoPtr->endTime ) : 0 ) + \
			 sizeofObject( revocationInfoLength );
	if( extensionSize > 0 )
		{
		length += sizeofShortInteger( X509VERSION_2 ) + \
			 	  sizeofObject( sizeofObject( extensionSize ) );
		}

	/* Write the outer SEQUENCE wrapper */
	status = writeSequence( stream, length );
	if( cryptStatusError( status ) )
		return( status );

	/* If there are extensions present, mark this as a v2 CRL */
	if( extensionSize > 0 )
		{
		status = writeShortInteger( stream, X509VERSION_2, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the signature algorithm identifier, issuer name, and CRL time */
	initAlgoIDparamsHash( &algoIDparams, certRevInfo->hashAlgo, 
						  certRevInfo->hashParam );
	status = writeContextAlgoIDex( stream, iIssuerCryptContext,
								   &algoIDparams );
	if( cryptStatusError( status ) )
		return( status );
	swrite( stream, issuerCertInfoPtr->subjectDNptr,
			issuerCertInfoPtr->subjectDNsize );
	status = writeTime( stream, subjectCertInfoPtr->startTime );
	if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
		{
		status = writeTime( stream, subjectCertInfoPtr->endTime );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the SEQUENCE OF revoked certificates wrapper and the revoked
	   certificate information */
	status = writeSequence( stream, revocationInfoLength );
	if( cryptStatusOK( status ) )
		status = writeCRLentries( stream, certRevInfo->revocations );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CRL, extensionSize ) );
	}
#endif /* USE_CERTREV */

/****************************************************************************
*																			*
*						Write Certificate Request Objects					*
*																			*
****************************************************************************/

#ifdef USE_CERTREQ

/* Write certificate request information:

	CertificationRequestInfo ::= SEQUENCE {
		version					INTEGER (0),
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		attributes		  [ 0 ]	SET OF Attribute
		}

   If extensions are present they are encoded as:

	SEQUENCE {							-- Attribute from X.501
		OBJECT IDENTIFIER {pkcs-9 14},	--   type
		SET OF {						--   values
			SEQUENCE OF {				-- ExtensionReq from CMMF draft
				<X.509v3 extensions>
				}
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCertRequestInfo( INOUT_PTR STREAM *stream,
								 INOUT_PTR CERT_INFO *subjectCertInfoPtr,
								 STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								 IN_HANDLE const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int length, extensionSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preCheckCertificate( subjectCertInfoPtr, NULL, 
									  PRE_CHECK_SPKI | PRE_CHECK_DN_PARTIAL,
									  PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	status = length = sizeofDN( subjectCertInfoPtr->subjectName );
	if( cryptStatusError( status ) )
		return( status );
	subjectCertInfoPtr->subjectDNsize = length;
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		return( status );
	length = sizeofShortInteger( 0 ) + \
			 subjectCertInfoPtr->subjectDNsize + \
			 subjectCertInfoPtr->publicKeyInfoSize;
	length += sizeofShortObject( \
						( extensionSize > 0 ) ? extensionSize : 0 );

	/* Write the header, version number, DN, and public key information */
	writeSequence( stream, length );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = swrite( stream, subjectCertInfoPtr->publicKeyInfo,
						 subjectCertInfoPtr->publicKeyInfoSize );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attributes.  If there are no attributes we still have to 
	   write an (erroneous) zero-length field */
	if( extensionSize <= 0 )
		return( writeConstructed( stream, 0, CTAG_CR_ATTRIBUTES ) );
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CERTREQUEST, extensionSize ) );
	}

/* Write CRMF certificate request information:

	CertReq ::= SEQUENCE {
		certReqID				INTEGER (0),
		certTemplate			SEQUENCE {
			validity	  [ 4 ]	SEQUENCE {
				validFrom [ 0 ]	EXPLICIT GeneralizedTime OPTIONAL,
				validTo	  [ 1 ] EXPLICIT GeneralizedTime OPTIONAL
				} OPTIONAL,
			subject		  [ 5 ]	EXPLICIT Name OPTIONAL,
			publicKey	  [ 6 ]	SubjectPublicKeyInfo,
			extensions	  [ 9 ]	SET OF Attribute OPTIONAL
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCrmfRequestInfo( INOUT_PTR STREAM *stream,
								 INOUT_PTR CERT_INFO *subjectCertInfoPtr,
								 STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								 IN_HANDLE const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int payloadLength, extensionSize, subjectDNsize = 0, timeSize = 0;
	int status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preCheckCertificate( subjectCertInfoPtr, NULL, 
									  PRE_CHECK_SPKI | \
					( ( DATAPTR_ISSET( subjectCertInfoPtr->subjectName ) ) ? \
									  PRE_CHECK_DN_PARTIAL : 0 ),
									  PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	payloadLength = subjectCertInfoPtr->publicKeyInfoSize;
	if( DATAPTR_ISSET( subjectCertInfoPtr->subjectName ) )
		{
		status = subjectDNsize = sizeofDN( subjectCertInfoPtr->subjectName );
		if( cryptStatusError( status ) )
			return( status );
		subjectCertInfoPtr->subjectDNsize = subjectDNsize;
		payloadLength += sizeofObject( subjectDNsize );
		}
	if( subjectCertInfoPtr->startTime > MIN_TIME_VALUE )
		timeSize = sizeofObject( sizeofGeneralizedTime() );
	if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
		timeSize += sizeofObject( sizeofGeneralizedTime() );
	if( timeSize > 0 ) 
		payloadLength += sizeofObject( timeSize );
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_REQUEST_CERT );
	if( cryptStatusError( status ) )
		return( status );
	if( extensionSize > 0 )
		payloadLength += sizeofObject( extensionSize );

	/* Write the header, request ID, inner header, DN, and public key */
	writeSequence( stream, sizeofShortInteger( 0 ) + \
				   sizeofObject( payloadLength ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeSequence( stream, payloadLength );
	if( timeSize > 0 )
		{
		writeConstructed( stream, timeSize, CTAG_CF_VALIDITY );
		if( subjectCertInfoPtr->startTime > MIN_TIME_VALUE )
			{
			writeConstructed( stream, sizeofGeneralizedTime(), 0 );
			writeGeneralizedTime( stream, subjectCertInfoPtr->startTime,
								  DEFAULT_TAG );
			}
		if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
			{
			writeConstructed( stream, sizeofGeneralizedTime(), 1 );
			writeGeneralizedTime( stream, subjectCertInfoPtr->endTime,
								  DEFAULT_TAG );
			}
		}
	if( subjectDNsize > 0 )
		{
		status = writeConstructed( stream, subjectCertInfoPtr->subjectDNsize,
								   CTAG_CF_SUBJECT );
		if( cryptStatusOK( status ) )
			{
			status = writeDN( stream, subjectCertInfoPtr->subjectName,
							  DEFAULT_TAG );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	sputc( stream, MAKE_CTAG( CTAG_CF_PUBLICKEY ) );
		   	/* Convert the SPKI SEQUENCE tag to the CRMF alternative */
	status = swrite( stream, 
					 ( BYTE * ) subjectCertInfoPtr->publicKeyInfo + 1,
					 subjectCertInfoPtr->publicKeyInfoSize - 1 );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	status = writeConstructed( stream, extensionSize, CTAG_CF_EXTENSIONS );
	if( cryptStatusOK( status ) )
		{
		status = writeAttributes( stream, subjectCertInfoPtr->attributes,
								  CRYPT_CERTTYPE_REQUEST_CERT, 
								  extensionSize );
		}
	return( status );
	}

/* Write CRMF revocation request information:

	RevDetails ::= SEQUENCE {
		certTemplate			SEQUENCE {
			serialNumber  [ 1 ]	INTEGER,
			issuer		  [ 3 ]	EXPLICIT Name,
			},
		crlEntryDetails			SET OF Attribute
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRevRequestInfo( INOUT_PTR STREAM *stream, 
								INOUT_PTR CERT_INFO *subjectCertInfoPtr,
								STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								STDC_UNUSED const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int payloadLength, extensionSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preCheckCertificate( subjectCertInfoPtr, NULL, 
									  PRE_CHECK_ISSUERDN | PRE_CHECK_SERIALNO,
									  PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_REQUEST_REVOCATION );
	if( cryptStatusError( status ) )
		return( status );
	payloadLength = sizeofInteger( subjectCertInfoPtr->cCertCert->serialNumber,
								   subjectCertInfoPtr->cCertCert->serialNumberLength ) + \
					sizeofObject( subjectCertInfoPtr->issuerDNsize );
	if( extensionSize > 0 )
		payloadLength += sizeofObject( extensionSize );

	/* Write the header, inner header, serial number and issuer DN */
	writeSequence( stream, sizeofObject( payloadLength ) );
	writeSequence( stream, payloadLength );
	writeInteger( stream, subjectCertInfoPtr->cCertCert->serialNumber,
				  subjectCertInfoPtr->cCertCert->serialNumberLength,
				  CTAG_CF_SERIALNUMBER );
	writeConstructed( stream, subjectCertInfoPtr->issuerDNsize,
					  CTAG_CF_ISSUER );
	status = swrite( stream, subjectCertInfoPtr->issuerDNptr,
					 subjectCertInfoPtr->issuerDNsize );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	status = writeConstructed( stream, extensionSize, CTAG_CF_EXTENSIONS );
	if( cryptStatusOK( status ) )
		{
		status = writeAttributes( stream, subjectCertInfoPtr->attributes,
								  CRYPT_CERTTYPE_REQUEST_REVOCATION, 
								  extensionSize );
		}
	return( status );
	}
#endif /* USE_CERTREQ */

/****************************************************************************
*																			*
*						Write Validity-checking Objects						*
*																			*
****************************************************************************/

#ifdef USE_CERTVAL

/* Write an RTCS request:

	RTCSRequests ::= SEQUENCE {
		SEQUENCE OF SEQUENCE {
			certHash	OCTET STRING SIZE(20)
			},
		attributes		Attributes OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRtcsRequestInfo( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CERT_INFO *subjectCertInfoPtr,
								 STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								 STDC_UNUSED \
									const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_VAL_INFO *certValInfo = subjectCertInfoPtr->cCertVal;
	int length, extensionSize, requestInfoLength;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		/* Generate a fresh nonce for the request */
		status = setNonce( &subjectCertInfoPtr->attributes, 
						   CRYPT_CERTINFO_CMS_NONCE );
		if( cryptStatusError( status ) )
			return( status );

		/* Perform the pre-encoding checks */
		status = preCheckCertificate( subjectCertInfoPtr, NULL, 
									  PRE_CHECK_VALENTRIES, PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded RTCS request will be */
	status = requestInfoLength = \
					sizeofRtcsRequestEntries( certValInfo->validityInfo );
	if( cryptStatusError( status ) )
		return( status );
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_RTCS_REQUEST );
	if( cryptStatusError( status ) )
		return( status );
	length = sizeofObject( requestInfoLength ) + \
			 ( ( extensionSize > 0 ) ? sizeofObject( extensionSize ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* Write the SEQUENCE OF request wrapper and the request information */
	status = writeSequence( stream, requestInfoLength );
	if( cryptStatusOK( status ) )
		{
		status = writeRtcsRequestEntries( stream, 
										  certValInfo->validityInfo );
		}
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_RTCS_REQUEST, extensionSize ) );
	}

/* Write an RTCS response:

	RTCSResponse ::= SEQUENCE OF SEQUENCE {
		certHash	OCTET STRING SIZE(20),
		RESPONSEINFO
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRtcsResponseInfo( INOUT_PTR STREAM *stream,
								  INOUT_PTR CERT_INFO *subjectCertInfoPtr,
								  STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								  STDC_UNUSED \
									const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_VAL_INFO *certValInfo = subjectCertInfoPtr->cCertVal;
	const BOOLEAN isExtendedResponse = \
		( certValInfo->responseType == RTCSRESPONSE_TYPE_EXTENDED ) ? \
		  TRUE : FALSE;
	int extensionSize, validityInfoLength;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );

	/* RTCS can legitimately return an empty response if there's a problem
	   with the responder so we don't require that any responses be present
	   as for CRLs/OCSP */

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
									   PRE_SET_VALINFO );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded RTCS response will be */
	status = validityInfoLength = \
					sizeofRtcsResponseEntries( certValInfo->validityInfo,
											   isExtendedResponse );
	if( cryptStatusError( status ) )
		return( status );
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_RTCS_RESPONSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the SEQUENCE OF status information wrapper and the certificate 
	   status information */
	status = writeSequence( stream, validityInfoLength );
	if( cryptStatusOK( status ) )
		{
		status = writeRtcsResponseEntries( stream, 
										   certValInfo->validityInfo,
										   isExtendedResponse );
		}
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_RTCS_RESPONSE, extensionSize ) );
	}
#endif /* USE_CERTVAL */

/****************************************************************************
*																			*
*						Write Revocation-checking Objects					*
*																			*
****************************************************************************/

#ifdef USE_CERTREV

/* Write an OCSP request:

	OCSPRequest ::= SEQUENCE {				-- Write, v1
		reqName		[1]	EXPLICIT [4] EXPLICIT DirectoryName OPTIONAL,
		reqList			SEQUENCE OF SEQUENCE {
						SEQUENCE {			-- certID
			hashAlgo	AlgorithmIdentifier,
			iNameHash	OCTET STRING,
			iKeyHash	OCTET STRING,
			serialNo	INTEGER
			} }
		}

	OCSPRequest ::= SEQUENCE {				-- Write, v2 (not used)
		version		[0]	EXPLICIT INTEGER (1),
		reqName		[1]	EXPLICIT [4] EXPLICIT DirectoryName OPTIONAL,
		reqList			SEQUENCE OF SEQUENCE {
			certID	[2]	EXPLICIT OCTET STRING	-- Certificate hash
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeOcspRequestInfo( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CERT_INFO *subjectCertInfoPtr,
								 IN_PTR_OPT \
									const CERT_INFO *issuerCertInfoPtr,
								 IN_HANDLE_OPT \
									const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	int length, extensionSize, revocationInfoLength = 0;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( issuerCertInfoPtr == NULL || \
			  sanityCheckCert( issuerCertInfoPtr ) );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED || \
			  isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		/* Generate a fresh nonce for the request */
		status = setNonce( &subjectCertInfoPtr->attributes, 
						   CRYPT_CERTINFO_OCSP_NONCE );
		if( cryptStatusError( status ) )
			return( status );

		/* Perform the pre-encoding checks */
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr, 
									   PRE_SET_REVINFO );
		if( cryptStatusError( status ) )
			return( status );
		if( issuerCertInfoPtr != NULL )
			{
			/* It's a signed request, there has to be an issuer DN present */
			status = preCheckCertificate( subjectCertInfoPtr, 
										  issuerCertInfoPtr, 
										  PRE_CHECK_ISSUERDN | \
										  PRE_CHECK_REVENTRIES,
										  PRE_FLAG_DN_IN_ISSUERCERT );
			}
		else
			{
			status = preCheckCertificate( subjectCertInfoPtr, NULL,
										  PRE_CHECK_REVENTRIES, 
										  PRE_FLAG_NONE );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP request will be */
	status = revocationInfoLength = \
					sizeofOcspRequestEntries( certRevInfo->revocations );
	if( cryptStatusError( status ) )
		return( status );
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_OCSP_REQUEST );
	if( cryptStatusError( status ) )
		return( status );
	length = ( ( subjectCertInfoPtr->version == 2 ) ? \
				 sizeofObject( sizeofShortInteger( CTAG_OR_VERSION ) ) : 0 ) + \
			 ( ( issuerCertInfoPtr != NULL ) ? \
				 sizeofObject( sizeofObject( issuerCertInfoPtr->subjectDNsize ) ) : 0 ) + \
			 sizeofObject( revocationInfoLength );
	if( extensionSize > 0 )
		length += sizeofObject( sizeofObject( extensionSize ) );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If we're using v2 identifiers, mark this as a v2 request */
	if( subjectCertInfoPtr->version == 2 )
		{
		writeConstructed( stream, sizeofShortInteger( 1 ), CTAG_OR_VERSION );
		status = writeShortInteger( stream, 1, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If we're signing the request, write the issuer DN as a GeneralName */
	if( issuerCertInfoPtr != NULL )
		{
		writeConstructed( stream,
						  sizeofObject( issuerCertInfoPtr->subjectDNsize ), 1 );
		writeConstructed( stream, issuerCertInfoPtr->subjectDNsize, 4 );
		status = swrite( stream, issuerCertInfoPtr->subjectDNptr,
						 issuerCertInfoPtr->subjectDNsize );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the SEQUENCE OF revocation information wrapper and the
	   revocation information */
	status = writeSequence( stream, revocationInfoLength );
	if( cryptStatusOK( status ) )
		status = writeOcspRequestEntries( stream, certRevInfo->revocations );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_OCSP_REQUEST, extensionSize ) );
	}

/* Write an OCSP response:

	OCSPResponse ::= SEQUENCE {
		version		[0]	EXPLICIT INTEGER (1),
		respID		[1]	EXPLICIT Name,
		producedAt		GeneralizedTime,
		responses		SEQUENCE OF Response
		exts		[1]	EXPLICIT Extensions OPTIONAL,
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeOcspResponseInfo( INOUT_PTR STREAM *stream,
								  INOUT_PTR CERT_INFO *subjectCertInfoPtr,
								  IN_PTR const CERT_INFO *issuerCertInfoPtr,
								  IN_HANDLE \
									const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	int length, extensionSize, revocationInfoLength = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preCheckCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									  PRE_CHECK_ISSUERDN | \
									  PRE_CHECK_REVENTRIES,
									  PRE_FLAG_DN_IN_ISSUERCERT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP response will be */
	status = revocationInfoLength = \
					sizeofOcspResponseEntries( certRevInfo->revocations );
	if( cryptStatusError( status ) )
		return( status );
	status = extensionSize = \
					sizeofAttributes( subjectCertInfoPtr->attributes,
									  CRYPT_CERTTYPE_OCSP_RESPONSE );
	if( cryptStatusError( status ) )
		return( status );
	length = sizeofObject( sizeofShortInteger( CTAG_OP_VERSION ) ) + \
			 sizeofObject( issuerCertInfoPtr->subjectDNsize ) + \
			 sizeofGeneralizedTime() + \
			 sizeofObject( revocationInfoLength );
	if( extensionSize > 0 )
		length += sizeofObject( sizeofObject( extensionSize ) );

	/* Write the outer SEQUENCE wrapper, version, and issuer DN and 
	   producedAt time */
	writeSequence( stream, length );
	writeConstructed( stream, sizeofShortInteger( 1 ), CTAG_OP_VERSION );
	writeShortInteger( stream, 1, DEFAULT_TAG );
	writeConstructed( stream, issuerCertInfoPtr->subjectDNsize, 1 );
	swrite( stream, issuerCertInfoPtr->subjectDNptr,
			issuerCertInfoPtr->subjectDNsize );
	status = writeGeneralizedTime( stream, subjectCertInfoPtr->startTime,
								   DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the SEQUENCE OF revocation information wrapper and the
	   revocation information */
	status = writeSequence( stream, revocationInfoLength );
	if( cryptStatusOK( status ) )
		{
		status = writeOcspResponseEntries( stream, certRevInfo->revocations,
										   subjectCertInfoPtr->startTime );
		}
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_OCSP_RESPONSE, extensionSize ) );
	}
#endif /* USE_CERTREV */

/****************************************************************************
*																			*
*						Write CMS Attribute Objects							*
*																			*
****************************************************************************/

#ifdef USE_CMSATTR

/* Write CMS attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCmsAttributes( INOUT_PTR STREAM *stream, 
							   INOUT_PTR CERT_INFO *attributeInfoPtr,
							   STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
							   STDC_UNUSED const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int attributeSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( attributeInfoPtr ) );
	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );
	REQUIRES( DATAPTR_ISSET( attributeInfoPtr->attributes ) );

	/* Make sure that there's a hash and content type present */
	if( !checkAttributePresent( attributeInfoPtr->attributes,
								CRYPT_CERTINFO_CMS_MESSAGEDIGEST ) )
		{
		setObjectErrorInfo( attributeInfoPtr, 
							CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
							CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_INVALID );
		}
	if( !checkAttributePresent( attributeInfoPtr->attributes,
								CRYPT_CERTINFO_CMS_CONTENTTYPE ) )
		{
		setObjectErrorInfo( attributeInfoPtr, 
							CRYPT_CERTINFO_CMS_CONTENTTYPE,
							CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Check that the attributes are in order and determine how big the whole
	   mess will be */
	status = checkAttributes( ATTRIBUTE_CMS, attributeInfoPtr->attributes,
							  &attributeInfoPtr->errorLocus,
							  &attributeInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	status = attributeSize = \
					sizeofAttributes( attributeInfoPtr->attributes,
									  CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	if( cryptStatusError( status ) || attributeSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, attributeInfoPtr->attributes,
							 CRYPT_CERTTYPE_CMS_ATTRIBUTES, attributeSize ) );
	}
#endif /* USE_CMSATTR */

/****************************************************************************
*																			*
*							Write PKI User Objects							*
*																			*
****************************************************************************/

#ifdef USE_PKIUSER

/* Write PKI user information:

	userData ::= SEQUENCE {
		name				Name,			-- Name for CMP
		encAlgo				AlgorithmIdentifier,-- Algo to encrypt passwords
		encPW				OCTET STRING,	-- Encrypted passwords
		certAttributes		Attributes		-- Certificate attributes
		userAttributes		SEQUENCE {		-- PKI user attributes
			isRA			BOOLEAN OPTIONAL -- Whether user is an RA
			} OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5, 7 ) ) \
static int createPkiUserInfo( INOUT_PTR CERT_PKIUSER_INFO *certUserInfo,
							  OUT_BUFFER( maxUserInfoSize, *userInfoSize ) \
									BYTE *userInfo, 
							  IN_LENGTH_SHORT_MIN( 64 ) \
									const int maxUserInfoSize, 
							  OUT_LENGTH_BOUNDED_Z( maxUserInfoSize ) \
									int *userInfoSize, 
							  OUT_BUFFER( maxCryptAlgoIDSize, *cryptAlgoIDSize ) \
									BYTE *cryptAlgoID, 
							  IN_LENGTH_SHORT_MIN( 16 ) \
									const int maxCryptAlgoIDSize, 
							  OUT_LENGTH_BOUNDED_Z( maxCryptAlgoIDSize ) \
									int *cryptAlgoIDSize )
	{
	CRYPT_CONTEXT iCryptContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE encryptedDataBuffer[ 16 + 8 ];
	LOOP_INDEX i;
	int userInfoBufPos DUMMY_INIT, status;

	assert( isWritePtr( certUserInfo, sizeof( CERT_PKIUSER_INFO ) ) );
	assert( isWritePtrDynamic( userInfo, maxUserInfoSize ) );
	assert( isWritePtr( userInfoSize, sizeof( int ) ) );
	assert( isWritePtrDynamic( cryptAlgoID, maxCryptAlgoIDSize ) );
	assert( isWritePtr( cryptAlgoIDSize, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( maxUserInfoSize, 64 ) );
	REQUIRES( isShortIntegerRangeMin( maxCryptAlgoIDSize, 16 ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( maxUserInfoSize ) ); 
	memset( userInfo, 0, maxUserInfoSize );
	REQUIRES( isShortIntegerRangeNZ( maxCryptAlgoIDSize ) ); 
	memset( cryptAlgoID, 0, maxCryptAlgoIDSize );
	*userInfoSize = *cryptAlgoIDSize = 0;

	/* Create a stream-cipher encryption context and use it to generate the 
	   user passwords.  These aren't encryption keys but just authenticators 
	   used for MACing so we don't go to the usual extremes to protect 
	   them */
	setMessageCreateObjectInfo( &createInfo, DEFAULT_CRYPT_ALGO );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iCryptContext = createInfo.cryptHandle;
	status = krnlSendNotifier( iCryptContext, IMESSAGE_CTX_GENKEY );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( iCryptContext, IMESSAGE_CTX_GENIV );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Create the PKI user authenticators */
	static_assert( PKIUSER_AUTHENTICATOR_SIZE <= 16, 
				   "pkiUser authenticator size" );
	memset( encryptedDataBuffer, 0, 16 );
	status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
							  encryptedDataBuffer, 16 );
	if( cryptStatusOK( status ) )
		{
		memcpy( certUserInfo->pkiIssuePW, encryptedDataBuffer, 
				PKIUSER_AUTHENTICATOR_SIZE );
		memset( encryptedDataBuffer, 0, 16 );
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
								  encryptedDataBuffer, 16 );
		}
	if( cryptStatusOK( status ) )
		{
		memcpy( certUserInfo->pkiRevPW, encryptedDataBuffer, 
				PKIUSER_AUTHENTICATOR_SIZE );
		}
	krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Encode the user information so that it can be encrypted */
	sMemOpen( &stream, userInfo, maxUserInfoSize );
	writeSequence( &stream, 2 * sizeofObject( PKIUSER_AUTHENTICATOR_SIZE ) );
	writeOctetString( &stream, certUserInfo->pkiIssuePW,
					  PKIUSER_AUTHENTICATOR_SIZE, DEFAULT_TAG );
	status = writeOctetString( &stream, certUserInfo->pkiRevPW,
							   PKIUSER_AUTHENTICATOR_SIZE, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		userInfoBufPos = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Encrypt (or at least mask) the user information.  For forwards 
	   compatibility (and because the format requires the use of some form 
	   of encryption when encoding the data) we encrypt the user data, once 
	   user roles are fully implemented this can use the data storage key 
	   associated with the CA user to perform the encryption instead of a 
	   fixed interop key.  This isn't a security issue because the CA 
	   database is assumed to be secure (or at least the CA is in serious 
	   trouble if its database isn't secured), we encrypt because it's 
	   pretty much free and because it doesn't hurt either way.  Most CA 
	   guidelines merely require that the CA protect its user database via 
	   standard (physical/ACL) security measures so this is no less secure 
	   than what's required by various CA guidelines.

	   When we do this for real we probably need an extra level of 
	   indirection to go from the CA secret to the database decryption key 
	   so that we can change the encryption algorithm and so that we don't 
	   have to directly apply the CA's data storage key to the user 
	   database */
	setMessageCreateObjectInfo( &createInfo, DEFAULT_CRYPT_ALGO );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iCryptContext = createInfo.cryptHandle;
#ifdef DEFAULT_ALGO_AES
	setMessageData( &msgData, "interop interop ", 16 );
#else
	setMessageData( &msgData, "interop interop interop ", 24 );
#endif /* AES vs. 3DES key size */
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Add PKCS #5 padding to the end of the user information and encrypt 
	   it */
	REQUIRES( userInfoBufPos + 2 == PKIUSER_ENCR_AUTHENTICATOR_SIZE );
	LOOP_SMALL( i = 0, i < 2, i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, 1 ) );

		userInfo[ userInfoBufPos++ ] = 2;
		}
	ENSURES( LOOP_BOUND_OK );
	status = krnlSendNotifier( iCryptContext, IMESSAGE_CTX_GENIV );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT, 
								  userInfo, userInfoBufPos );
		}
	if( cryptStatusOK( status ) )
		{
		sMemOpen( &stream, cryptAlgoID, maxCryptAlgoIDSize );
		status = writeCryptContextAlgoID( &stream, iCryptContext );
		if( cryptStatusOK( status ) )
			*cryptAlgoIDSize = stell( &stream );
		sMemDisconnect( &stream );
		}
	krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	*userInfoSize = userInfoBufPos;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePkiUserInfo( INOUT_PTR STREAM *stream, 
							 INOUT_PTR CERT_INFO *userInfoPtr,
							 STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
							 STDC_UNUSED const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_PKIUSER_INFO *certUserInfo = userInfoPtr->cCertUser;
	BYTE userInfo[ 128 + 8 ], cryptAlgoID[ 128 + 8 ];
	int certAttributeSize, userAttributeSize = 0, userInfoSize;
	int cryptAlgoIDSize, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( userInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( userInfoPtr ) );
	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );

	if( sIsNullStream( stream ) )
		{
		CRYPT_ATTRIBUTE_TYPE dummy1;
		CRYPT_ERRTYPE_TYPE dummy2;
		ERROR_INFO localErrorInfo;
		MESSAGE_DATA msgData;
		BYTE keyID[ 16 + 8 ];
		int keyIDlength DUMMY_INIT;

		/* Generate the key identifier.  Once it's in user-encoded form the
		   full identifier can't quite fit so we adjust the size to the
		   maximum amount that we can encode by creating the encoded form 
		   (which trims the input to fit) and then decoding it again.  This 
		   is necessary because it's also used to locate the user information 
		   in a key store, if we used the un-adjusted form for the key ID then 
		   we couldn't locate the stored user information using the adjusted 
		   form */
		clearErrorInfo( &localErrorInfo );
		setMessageData( &msgData, keyID, 16 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusOK( status ) )
			{
			char encodedKeyID[ 32 + 8 ];
			int encKeyIdSize;

			status = encodePKIUserValue( encodedKeyID, 32, &encKeyIdSize,
										 keyID, 16, 3 );
			if( cryptStatusOK( status ) )
				{
				status = decodePKIUserValue( keyID, 16, &keyIDlength,
											 encodedKeyID, encKeyIdSize );
				}
			}
		if( cryptStatusError( status ) )
			return( status );
		status = addAttributeFieldString( &userInfoPtr->attributes,
										  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
										  CRYPT_ATTRIBUTE_NONE, keyID, 
										  keyIDlength, ATTR_FLAG_NONE, FALSE,
										  &localErrorInfo, &dummy1, &dummy2 );
		if( cryptStatusOK( status ) )
			{
			status = checkAttributes( ATTRIBUTE_CERTIFICATE,
									  userInfoPtr->attributes,
									  &userInfoPtr->errorLocus,
									  &userInfoPtr->errorType );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* We can't generate the user information yet since we're doing the 
		   pre-encoding pass and writing to a null stream so we leave it for 
		   the actual encoding pass and only provide a size estimate for 
		   now */
		userInfoSize = PKIUSER_ENCR_AUTHENTICATOR_SIZE;
		memset( userInfo, 0, userInfoSize );

		/* Since we can't use the CA's data storage key yet we set the 
		   algorithm ID size to the size of the information for the fixed 
		   AES or 3DES key */
#ifdef DEFAULT_ALGO_AES
		cryptAlgoIDSize = 31;
#else
		cryptAlgoIDSize = 22;
#endif /* AES vs. 3DES algoID size */
		REQUIRES( rangeCheck( cryptAlgoIDSize, 1, 128 ) );
		memset( cryptAlgoID, 0, cryptAlgoIDSize );
		}
	else
		{
		status = createPkiUserInfo( certUserInfo, userInfo, 128, 
									&userInfoSize, cryptAlgoID, 128, 
									&cryptAlgoIDSize );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine the size of the user information */
	status = length = sizeofDN( userInfoPtr->subjectName );
	if( cryptStatusError( status ) )
		return( status );
	userInfoPtr->subjectDNsize = length;
	status = certAttributeSize = \
					sizeofAttributes( userInfoPtr->attributes,
									  CRYPT_CERTTYPE_PKIUSER );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( isShortIntegerRangeNZ( certAttributeSize ) );
	if( certUserInfo->isRA )
		userAttributeSize += sizeofBoolean();

	/* Write the user DN, encrypted user information, and any supplementary 
	   information */
	status = writeDN( stream, userInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	swrite( stream, cryptAlgoID, cryptAlgoIDSize );
	status = writeOctetString( stream, userInfo, userInfoSize, 
							   DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		status = writeAttributes( stream, userInfoPtr->attributes,
								  CRYPT_CERTTYPE_PKIUSER, 
								  certAttributeSize );
		}
	if( cryptStatusOK( status ) && userAttributeSize > 0 )
		{
		status = writeSequence( stream, userAttributeSize );
		if( certUserInfo->isRA )
			status = writeBoolean( stream, TRUE, DEFAULT_TAG );
		}
	return( status );
	}
#endif /* USE_PKIUSER */

/****************************************************************************
*																			*
*						Write Function Access Information					*
*																			*
****************************************************************************/

typedef struct {
	const CRYPT_CERTTYPE_TYPE type;
	const WRITECERT_FUNCTION function;
	} CERTWRITE_INFO;
static const CERTWRITE_INFO certWriteTable[] = {
	{ CRYPT_CERTTYPE_CERTIFICATE, writeCertInfo },
	{ CRYPT_CERTTYPE_CERTCHAIN, writeCertInfo },
#ifdef USE_ATTRCERT
	{ CRYPT_CERTTYPE_ATTRIBUTE_CERT, writeAttributeCertInfo },
#endif /* USE_ATTRCERT */
#ifdef USE_CERTREV
	{ CRYPT_CERTTYPE_CRL, writeCRLInfo },
#endif /* USE_CERTREV */
#ifdef USE_CERTREQ
	{ CRYPT_CERTTYPE_CERTREQUEST, writeCertRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_CERT, writeCrmfRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_REVOCATION, writeRevRequestInfo },
#endif /* USE_CERTREQ */
#ifdef USE_CERTVAL
	{ CRYPT_CERTTYPE_RTCS_REQUEST, writeRtcsRequestInfo },
	{ CRYPT_CERTTYPE_RTCS_RESPONSE, writeRtcsResponseInfo },
#endif /* USE_CERTVAL */
#ifdef USE_CERTREV
	{ CRYPT_CERTTYPE_OCSP_REQUEST, writeOcspRequestInfo },
	{ CRYPT_CERTTYPE_OCSP_RESPONSE, writeOcspResponseInfo },
#endif /* USE_CERTREV */
#ifdef USE_CMSATTR
	{ CRYPT_CERTTYPE_CMS_ATTRIBUTES, writeCmsAttributes },
#endif /* USE_CMSATTR */
#ifdef USE_PKIUSER
	{ CRYPT_CERTTYPE_PKIUSER, writePkiUserInfo },
#endif /* USE_PKIUSER */
	{ CRYPT_CERTTYPE_NONE, NULL }, { CRYPT_CERTTYPE_NONE, NULL }
	};

CHECK_RETVAL_PTR \
WRITECERT_FUNCTION getCertWriteFunction( IN_ENUM( CRYPT_CERTTYPE ) \
											const CRYPT_CERTTYPE_TYPE certType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( certType, CRYPT_CERTTYPE ) );

	LOOP_MED( i = 0,
			  i < FAILSAFE_ARRAYSIZE( certWriteTable, CERTWRITE_INFO ) && \
					certWriteTable[ i ].type != CRYPT_CERTTYPE_NONE, 
			  i++ )
		{
		ENSURES_N( LOOP_INVARIANT_MED( i, 0, 
									   FAILSAFE_ARRAYSIZE( certWriteTable, \
														   CERTWRITE_INFO ) - 1 ) );

		if( certWriteTable[ i ].type == certType )
			return( certWriteTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( certWriteTable, CERTWRITE_INFO ) );

	return( NULL );
	}
#endif /* USE_CERTIFICATES */
