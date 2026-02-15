/****************************************************************************
*																			*
*						  Certificate Signing Routines						*
*						Copyright Peter Gutmann 1997-2016					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #ifdef USE_STRICT_ECCPARAMS
	#include "asn1_ext.h"
  #endif /* USE_STRICT_ECCPARAMS */
#else
  #include "cert/cert.h"
  #ifdef USE_STRICT_ECCPARAMS
	#include "enc_dec/asn1_ext.h"
  #endif /* USE_STRICT_ECCPARAMS */
#endif /* Compiler-specific includes */

#ifdef USE_CERTIFICATES

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Set the end time for a certificate object.  Because of the Y2038 problem
   we have to be careful about the maximum time value that we allow, if 
   it'll overflow then we clamp it at MAX_TIME_VALUE */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setEndTime( INOUT_PTR CERT_INFO *certInfoPtr,
					   IN_RANGE( 1, 20 * 365 ) const int timeInDays,
					   const time_t currentTime )
	{
	time_t timeInSeconds;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( timeInDays >= 1 && timeInDays <= 20 * 365 );

	/* Check for startTime + endTime overflowing MAX_TIME_VALUE.  The
	   peculiar order of operations below is required to avoid an overflow
	   during the check, it's checking that timeInSeconds fits into the
	   interval between startTime and MAX_TIME */
	timeInSeconds = timeInDays * ( time_t ) 86400UL;
	if( timeInSeconds >= MAX_TIME_VALUE - certInfoPtr->startTime )
		{
		/* The end time would go past MAX_TIME_VALUE, clamp it at 
		   MAX_TIME_VALUE */
		certInfoPtr->endTime = MAX_TIME_VALUE;

		return( CRYPT_OK );
		}

	/* There's a second special-case condition that occurs when the start 
	   time is backdated far enough that startTime + timeInSeconds produces
	   an already-expired or about-to-expire certificate.  To deal with 
	   this we extend the end time so that the certificate is valid for one 
	   day.  The other alternative would be to pull up the start time so 
	   that it's within timeInSeconds range of currentTime, but presumably 
	   if the certificate has been backdated then there's some reason for it 
	   so we modify the end time rather than the start time */
	if( certInfoPtr->startTime < ( currentTime + 120 ) - timeInSeconds )
		{
		/* The certificate, if issued with the given start time and validity
		   period, would either be already expired or would expire within 
		   two minutes of issue, extend the end time so that it's valid for
		   at least one day */
		DEBUG_PRINT(( "Certificate with given start time and %d-day "
					  "validity period would be expired on issue, "
					  "extending validity so that it's valid for one "
					  "day after issue.\n", timeInDays ));
		certInfoPtr->endTime = currentTime + 86400UL;

		return( CRYPT_OK );
		}

	certInfoPtr->endTime = certInfoPtr->startTime + timeInSeconds;
	return( CRYPT_OK );
	}

/* Recover information normally set up on certificate import.  After 
   signing the certificate the data is present without the certificate 
   having been explicitly imported so we have to go back and perform the 
   actions normally performed on import here.  The subject DN and public key 
   data length was recorded when the certificate data was written but the 
   position of the other elements in the certificate can't be determined 
   until the certificate has been signed */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int getObjectDataPtr( INOUT_PTR STREAM *stream,
							 OUT_BUFFER_ALLOC_OPT( *dataLength ) \
									void **dataPtrPtr,
							 OUT_LENGTH_Z int *dataLength )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dataPtrPtr, sizeof( void * ) ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	/* Clear return values */
	*dataPtrPtr = NULL;
	*dataLength = 0;

	/* Get the length of the object */
	status = getStreamObjectLength( stream, &length, MIN_DN_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Get a reference to the object data */
	status = sMemGetDataBlock( stream, dataPtrPtr, length );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = length;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int recoverCertData( INOUT_PTR CERT_INFO *certInfoPtr,
							IN_ENUM( CRYPT_CERTTYPE ) \
								const CRYPT_CERTTYPE_TYPE certType, 
							IN_BUFFER( encodedCertDataLength ) \
								const void *encodedCertData,
							IN_LENGTH_SHORT_MIN( 16 ) \
								const int encodedCertDataLength )
	{
	STREAM stream;
	int tag, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtrDynamic( encodedCertData, encodedCertDataLength ) );

	REQUIRES( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			  certType == CRYPT_CERTTYPE_CERTCHAIN || \
			  certType == CRYPT_CERTTYPE_CERTREQUEST || \
			  certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			  certType == CRYPT_CERTTYPE_REQUEST_REVOCATION || \
			  certType == CRYPT_CERTTYPE_CRL || \
			  certType == CRYPT_CERTTYPE_PKIUSER );
	REQUIRES( isShortIntegerRangeMin( encodedCertDataLength, 16 ) || \
			  ( certType == CRYPT_CERTTYPE_CRL && \
				isIntegerRangeMin( encodedCertDataLength, 16 ) ) );
			  /* CRLs can become quite large */

	/* If there's public-key or DN data stored with the certificate, free it 
	   since we now have a copy as part of the encoded certificate.  Since the 
	   publicKeyInfo/subject/issuerDNptr pointer points at the public-key/DN 
	   data, we clear this as well.
	   
	   Revocation requests present a slight exception to this since they 
	   store a subject DN that's not needed for the request itself but is 
	   required by the CMP protocol that they're used with (see the long 
	   comment in copyCertToRevRequest() in comp_cert.c), so we leave the
	   subject DN alone if there's one present and it's a revocation 
	   request */
	if( certInfoPtr->publicKeyData != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( certInfoPtr->publicKeyInfoSize ) ); 
		zeroise( certInfoPtr->publicKeyData, certInfoPtr->publicKeyInfoSize );
		clFree( "recoverCertData", certInfoPtr->publicKeyData );
		certInfoPtr->publicKeyData = certInfoPtr->publicKeyInfo = NULL;
		}
	if( certInfoPtr->subjectDNdata != NULL && \
		certType != CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		REQUIRES( isShortIntegerRangeNZ( certInfoPtr->subjectDNsize ) ); 
		zeroise( certInfoPtr->subjectDNdata, certInfoPtr->subjectDNsize );
		clFree( "recoverCertData", certInfoPtr->subjectDNdata );
		certInfoPtr->subjectDNdata = certInfoPtr->subjectDNptr = NULL;
		}
	if( certInfoPtr->issuerDNdata != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( certInfoPtr->issuerDNsize ) ); 
		zeroise( certInfoPtr->issuerDNdata, certInfoPtr->issuerDNsize );
		clFree( "recoverCertData", certInfoPtr->issuerDNdata );
		certInfoPtr->issuerDNdata = certInfoPtr->issuerDNptr = NULL;
		}

	/* If it's a PKCS #10 request parse the encoded form to locate the 
	   subject DN and public key */
	if( certType == CRYPT_CERTTYPE_CERTREQUEST )
		{
		sMemConnect( &stream, encodedCertData, encodedCertDataLength );
		readSequence( &stream, NULL );				/* Outer wrapper */
		readSequence( &stream, NULL );				/* Inner wrapper */
		status = readShortInteger( &stream, NULL );	/* Version */
		if( cryptStatusOK( status ) )
			{
			status = getObjectDataPtr( &stream, &certInfoPtr->subjectDNptr, 
									   &certInfoPtr->subjectDNsize );
			}
		if( cryptStatusOK( status ) )
			status = readUniversal( &stream );
		if( cryptStatusOK( status ) )
			{
			status = getObjectDataPtr( &stream, &certInfoPtr->publicKeyInfo, 
									   &certInfoPtr->publicKeyInfoSize );
			}
		sMemDisconnect( &stream );
		ENSURES( cryptStatusOK( status ) );

		return( CRYPT_OK );
		}

	/* If it's a CRMF request, parse the signed form to locate the start of
	   the encoded DN if there is one (the issuer DN is already set up when
	   the issuer certificate is added) and the public key.  The public key 
	   is actually something of a special case in that in the CRMF/CMP 
	   tradition it has a weird nonstandard tag which means that we can't 
	   directly use it elsewhere as a SubjectPublicKeyInfo blob.  In order 
	   to work around this the code that reads SPKIs allows something other
	   than a plain SEQUENCE for the outer wrapper */
	if( certType == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		sMemConnect( &stream, encodedCertData, encodedCertDataLength );
		readSequence( &stream, NULL );			/* Outer wrapper */
		readSequence( &stream, NULL );
		readUniversal( &stream );				/* Request ID */
		status = readSequence( &stream, NULL );	/* Inner wrapper */
		if( checkStatusPeekTag( &stream, status, tag ) && \
			tag == MAKE_CTAG( 4 ) )
			status = readUniversal( &stream );	/* Validity */
		if( checkStatusPeekTag( &stream, status, tag ) && \
			tag == MAKE_CTAG( 5 ) )
			{									/* Subj.name wrapper */
			status = readConstructed( &stream, NULL, 5 );
			if( cryptStatusOK( status ) )
				{
				status = getObjectDataPtr( &stream, &certInfoPtr->subjectDNptr, 
										   &certInfoPtr->subjectDNsize );
				}
			ENSURES( cryptStatusOK( status ) );
			status = readUniversal( &stream );	/* Subject name */
			}
		if( checkStatusPeekTag( &stream, status, tag ) && \
			tag != MAKE_CTAG( 6 ) )
			status = CRYPT_ERROR_BADDATA;		/* Public key */
		if( !cryptStatusError( status ) )
			{
			status = getObjectDataPtr( &stream, &certInfoPtr->publicKeyInfo, 
									   &certInfoPtr->publicKeyInfoSize );
			}
		ENSURES( cryptStatusOK( status ) );
		sMemDisconnect( &stream );

		return( CRYPT_OK );
		}
	if( certType == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		sMemConnect( &stream, encodedCertData, encodedCertDataLength );
		readSequence( &stream, NULL );			/* Outer wrapper */
		status = readSequence( &stream, NULL );
		if( checkStatusPeekTag( &stream, status, tag ) && \
			tag == MAKE_CTAG_PRIMITIVE( 1 ) )
			status = readUniversal( &stream );	/* Serial number */
		if( checkStatusPeekTag( &stream, status, tag ) && \
			tag == MAKE_CTAG( 3 ) )
			{									/* Issuer.name wrapper */
			status = readConstructed( &stream, NULL, 3 );
			if( cryptStatusOK( status ) )
				{
				status = getObjectDataPtr( &stream, &certInfoPtr->issuerDNptr, 
										   &certInfoPtr->issuerDNsize );
				}
			ENSURES( cryptStatusOK( status ) );
			status = readUniversal( &stream );	/* Subject name */
			}
		ENSURES( cryptStatusOK( status ) );
		sMemDisconnect( &stream );

		return( CRYPT_OK );
		}

	/* If it's a CRL, parse the encoded form to locate the start of the 
	   issuer DN.  We have to use the Long variants of the read routines 
	   since CRLs can get quite large */
	if( certType == CRYPT_CERTTYPE_CRL )
		{
		sMemConnect( &stream, encodedCertData, encodedCertDataLength );
		readLongSequence( &stream, NULL );		/* Outer wrapper */
		status = readLongSequence( &stream, NULL );
		if( checkStatusPeekTag( &stream, status, tag ) && \
			tag == BER_INTEGER )
			status = readUniversal( &stream );	/* Version */
		if( !cryptStatusError( status ) )
			status = readUniversal( &stream );	/* AlgorithmID */
		if( cryptStatusOK( status ) )
			{
			status = getObjectDataPtr( &stream, &certInfoPtr->issuerDNptr, 
									   &certInfoPtr->issuerDNsize );
			}
		ENSURES( cryptStatusOK( status ) );
		sMemDisconnect( &stream );

		return( CRYPT_OK );
		}

	/* If it's PKI user data, parse the encoded form to locate the start of 
	   the PKI user DN */
	if( certType == CRYPT_CERTTYPE_PKIUSER )
		{
		sMemConnect( &stream, encodedCertData, encodedCertDataLength );
		status = readSequence( &stream, NULL );		/* Wrapper */
		if( cryptStatusOK( status ) )
			{
			status = getObjectDataPtr( &stream, &certInfoPtr->subjectDNptr, 
									   &certInfoPtr->subjectDNsize );
			}
		sMemDisconnect( &stream );
		ENSURES( cryptStatusOK( status ) );

		return( CRYPT_OK );
		}

	ENSURES( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			 certType == CRYPT_CERTTYPE_CERTCHAIN );

	/* It's a certificate, parse the signed form to locate the start of the
	   encoded issuer and subject DN and public key */
	sMemConnect( &stream, encodedCertData, encodedCertDataLength );
	readSequence( &stream, NULL );			/* Outer wrapper */
	status = readSequence( &stream, NULL );	/* Inner wrapper */
	if( checkStatusPeekTag( &stream, status, tag ) && \
		tag == MAKE_CTAG( 0 ) )
		readUniversal( &stream );			/* Version */
	readUniversal( &stream );				/* Serial number */
	status = readUniversal( &stream );		/* Signature algo */
	if( cryptStatusOK( status ) )
		{
		status = getObjectDataPtr( &stream, &certInfoPtr->issuerDNptr, 
								   &certInfoPtr->issuerDNsize );
		}
	ENSURES( cryptStatusOK( status ) );
	readUniversal( &stream );				/* Issuer DN */
	status = readUniversal( &stream );		/* Validity */
	if( cryptStatusOK( status ) )
		{
#ifdef USE_CERTLEVEL_PKIX_FULL
		const int startPos = stell( &stream );
		int length;

		REQUIRES( isIntegerRangeNZ( startPos ) );

		/* Full PKIX allows zero-length DNs, which can't be extracted using
		   getObjectDataPtr().  To deal with this we have to explicitly read
		   the SEQUENCE that encapsulates the DN and, if it's zero-length,
		   call sMemGetDataBlock() with the size of the zero-length object
		   given explicitly */
		status = readSequenceZ( &stream, &length );
		if( cryptStatusOK( status ) )
			{
			sseek( &stream, startPos );
			if( length > 0 )
				{
				status = getObjectDataPtr( &stream, 
										   &certInfoPtr->subjectDNptr, 
										   &certInfoPtr->subjectDNsize );
				ENSURES( cryptStatusOK( status ) );
				status = readUniversal( &stream );		/* Subject DN */
				}
			else
				{
				certInfoPtr->subjectDNsize = sizeofShortObject( 0 );
				status = sMemGetDataBlock( &stream, 
										   &certInfoPtr->subjectDNptr,
										   certInfoPtr->subjectDNsize );
				ENSURES( cryptStatusOK( status ) );
				status = readSequenceZ( &stream, NULL );
				}										/* Empty DN */
			}
#else
		status = getObjectDataPtr( &stream, &certInfoPtr->subjectDNptr, 
								   &certInfoPtr->subjectDNsize );
		ENSURES( cryptStatusOK( status ) );
		status = readUniversal( &stream );		/* Subject DN */
#endif /* USE_CERTLEVEL_PKIX_FULL */
		}
	if( cryptStatusOK( status ) )
		{
		status = getObjectDataPtr( &stream, &certInfoPtr->publicKeyInfo, 
								   &certInfoPtr->publicKeyInfoSize );
		}
	ENSURES( cryptStatusOK( status ) );
	sMemDisconnect( &stream );

	/* Since the certificate may be used for public-key operations as soon 
	   as it's signed we have to reconstruct the public-key context and 
	   apply to it the constraints that would be applied on import, the 
	   latter being done implicitly via the MESSAGE_SETDEPENDENT mechanism */
	sMemConnect( &stream, certInfoPtr->publicKeyInfo,
				 certInfoPtr->publicKeyInfoSize );
	status = iCryptReadSubjectPublicKey( &stream,
										 &certInfoPtr->iPubkeyContext,
										 CRYPTO_OBJECT_HANDLE, FALSE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( certInfoPtr->objectHandle,
							  IMESSAGE_SETDEPENDENT,
							  &certInfoPtr->iPubkeyContext,
							  SETDEP_OPTION_NOINCREF );
	if( cryptStatusOK( status ) )
		CLEAR_FLAG( certInfoPtr->flags, CERT_FLAG_DATAONLY );
	return( status );
	}

/* Check that the ECC domain parameters used by the CA match the ones used 
   by the subject.  This is used in some signing hierarchies where a 
   particular fashion statement has to be expressed all the way up and down 
   the chain, as opposed to the usual practice of using a stronger long-term 
   CA key to sign a standard EE key */

#ifdef USE_STRICT_ECCPARAMS

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getCurveType( const CERT_INFO *certInfoPtr,
						 OUT_OPT CRYPT_ECCCURVE_TYPE *curveType )
	{
	int value, status;

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( curveType, sizeof( CRYPT_ECCCURVE_TYPE ) ) );

	/* Clear return value */
	*curveType = CRYPT_ECCCURVE_NONE;

	/* Get the ECC parameter information from the certificate.  This is
	   complicated by the fact that it may be a data-only certificate, in 
	   which case we have to parse the subjectPublicKeyInfo to extract the
	   curve type */
	if( TEST_FLAG( certInfoPtr->flags, CERT_FLAG_DATAONLY ) )
		{
		CRYPT_ALGO_TYPE dummyAlgo;
		ALGOID_PARAMS algoIDparams;
		STREAM stream;
		int dummyFieldSize;

		sMemConnect( &stream, certInfoPtr->publicKeyInfo, 
					 certInfoPtr->publicKeyInfoSize );
		status = readGenericHole( &stream, NULL, 4, DEFAULT_TAG );
		if( cryptStatusOK( status ) )
			{
			status = readAlgoIDex( &stream, &dummyAlgo, 
								   &algoIDparams, ALGOID_CLASS_PKC );
			}
		if( cryptStatusOK( status ) )
			status = readECCOID( &stream, curveType, &dummyFieldSize );
		sMemDisconnect( &stream );

		return( status );
		}

	/* It's a certificate with a context attached, get the information 
	   directly from the context */
	status = krnlSendMessage( certInfoPtr->objectHandle, 
							  IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
	if( cryptStatusError( status ) )
		return( status );

	*curveType = value;	/* int vs. enum */
	return( CRYPT_OK );
	}

static int checkEccParams( const CERT_INFO *subjectCertInfoPtr,
						   const CERT_INFO *issuerCertInfoPtr )
	{
	CRYPT_ECCCURVE_TYPE subjectCurveType, issuerCurveType DUMMY_INIT;
	int status;

	assert( isReadPtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isEccAlgo( subjectCertInfoPtr->publicKeyAlgo ) );

	/* If the signing certificate doesn't use ECC, we're done */
	if( !isEccAlgo( issuerCertInfoPtr->publicKeyAlgo ) )
		return( CRYPT_ERROR_INVALID );

	/* Make sure that the subject and issuer use the same set of ECC 
	   parameters */
	status = getCurveType( subjectCertInfoPtr, &subjectCurveType );
	if( cryptStatusOK( status ) )
		status = getCurveType( issuerCertInfoPtr, &issuerCurveType );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_INVALID );

	return( ( subjectCurveType == issuerCurveType ) ? \
			CRYPT_OK : CRYPT_ERROR_INVALID );
	}
#endif /* USE_STRICT_ECCPARAMS */

/* Check the key being used to sign a certificate object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkSigningKey( INOUT_PTR CERT_INFO *certInfoPtr,
							INOUT_PTR CERT_INFO *issuerCertInfoPtr,
							IN_HANDLE const CRYPT_CONTEXT iSignContext,
							IN_BOOL const BOOLEAN isCertificate )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
	MESSAGE_DATA msgData;
	int complianceLevel, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isBooleanValue( isCertificate ) );

	/* Get references to the certificate's error information */
	errorLocus = &certInfoPtr->errorLocus;
	errorType = &certInfoPtr->errorType;

	/* Determine how much checking we need to perform */
	status = krnlSendMessage( certInfoPtr->ownerHandle,
							  IMESSAGE_GETATTRIBUTE, &complianceLevel,
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the signing key is associated with an issuer 
	   certificate rather than some other key-related object like a 
	   certificate request */
	if( issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
		issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN )
		{
		retExt( CRYPT_ARGERROR_VALUE,
				( CRYPT_ARGERROR_VALUE, CERTIFICATE_ERRINFO,
				  "Signing object must be a certificate, not a %s",
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}

	/* Make sure that the signing key is associated with a completed issuer 
	   certificate.  If it's a self-signed certificate then we don't have to 
	   have a completed certificate present because the self-sign operation 
	   hasn't created it yet */
	if( !TEST_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED ) && \
		issuerCertInfoPtr->certificate == NULL )
		{
		retExt( CRYPT_ARGERROR_VALUE,
				( CRYPT_ARGERROR_VALUE, CERTIFICATE_ERRINFO,
				  "Signing certificate is incomplete" ) );
		}

	/* If it's a CRL then the signing certificate has to match the 
	   certificate(s) being revoked.  If it's an empty CRL then the issuer DN
	   isn't set (since no certificates have been added to the CRL, there's 
	   no issuer DN to copy over) so we only check this if there are entries
	   present */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CRL && \
		certInfoPtr->issuerDNptr != NULL )
		{
		REQUIRES( issuerCertInfoPtr->subjectDNptr != NULL );

		if( certInfoPtr->issuerDNsize != issuerCertInfoPtr->subjectDNsize || \
			memcmp( certInfoPtr->issuerDNptr, issuerCertInfoPtr->subjectDNptr,
					certInfoPtr->issuerDNsize ) )
			{
			setObjectErrorInfo( certInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
								CRYPT_ERRTYPE_ATTR_VALUE );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "Signing certificate didn't issue the certificate "
					  "being revoked" ) );
			}
		}

	/* If it's an OCSP request or response then the signing certificate has 
	   to be valid for signing */
	if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
		certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_NONE,
								KEYUSAGE_SIGN, complianceLevel, 
								certInfoPtr );
		if( cryptStatusOK( status ) )
			return( CRYPT_OK );

		/* There's a problem with the issuer certificate, set a general 
		   error status indicating this for the subject certificate */
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		retExt( status,
				( status, CERTIFICATE_ERRINFO,
				  "Issuer certificate isn't valid for signing this %s",
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}

	/* If required, make sure that the ECC domain parameters used by the CA
	   match the ones used by the subject */
#ifdef USE_STRICT_ECCPARAMS
	if( isEccAlgo( certInfoPtr->publicKeyAlgo ) && \
		!TEST_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED ) )
		{
		status = checkEccParams( certInfoPtr, issuerCertInfoPtr );
		if( cryptStatusError( status ) )
			{
			setErrorValues( CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
							CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "Issuer certificate ECC domain parameters don't "
					  "match %s domain parameteres",
					  getCertTypeNameLC( certInfoPtr->type ) ) );
			}
		}
#endif /* USE_STRICT_ECCPARAMS */

	/* If it's a non-self-signed object then it must be signed by a CA 
	   certificate */
	if( !TEST_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED ) )
		{
		status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_CA,
								isCertificate ? CRYPT_KEYUSAGE_KEYCERTSIGN : \
												CRYPT_KEYUSAGE_CRLSIGN,
								complianceLevel, certInfoPtr );
		if( cryptStatusOK( status ) )
			return( CRYPT_OK );

		/* There's a problem with the issuer certificate, set a general 
		   error status indicating this for the subject certificate */
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		retExt( status,
				( status, CERTIFICATE_ERRINFO,
				  "Issuer certificate isn't valid for signing this %s",
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}

	/* It's a self-signed certificate, the signing key must match the key in 
	   the certificate */
	setMessageData( &msgData, certInfoPtr->publicKeyID, KEYID_SIZE );
	status = krnlSendMessage( iSignContext, IMESSAGE_COMPARE, &msgData,
							  MESSAGE_COMPARE_KEYID );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ARGERROR_VALUE,
				( CRYPT_ARGERROR_VALUE, CERTIFICATE_ERRINFO,
				  "Signing key for self-signed %s doesn't match the key in "
				  "the %s", getCertTypeNameLC( certInfoPtr->type ),
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Signing Setup Functions							*
*																			*
****************************************************************************/

/* Copy a signing certificate chain into the certificate being signed */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int copySigningCertChain( INOUT_PTR CERT_INFO *certInfoPtr,
								 IN_HANDLE const CRYPT_CONTEXT iSignContext )
	{
	CERT_CERT_INFO *certInfo = certInfoPtr->cCertCert;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iSignContext ) );

	/* If there's a chain of certificates present (for example from a 
	   previous signing attempt that wasn't completed due to an error), free 
	   them */
	if( certInfo->chainEnd > 0 )
		{
		LOOP_INDEX i;
			
		LOOP_EXT( i = 0, i < certInfo->chainEnd, i++, MAX_CHAINLENGTH )
			{
			ENSURES( LOOP_INVARIANT_EXT( i, 0, certInfo->chainEnd - 1,
										 MAX_CHAINLENGTH ) );
			krnlSendNotifier( certInfo->chain[ i ], IMESSAGE_DECREFCOUNT );
			}
		ENSURES( LOOP_BOUND_OK );
		certInfo->chainEnd = 0;
		}

	/* If it's a self-signed certificate then it must be the only one in the 
	   chain (creating a chain like this doesn't make much sense but we 
	   handle it anyway) */
	if( TEST_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED ) )
		{
		if( certInfo->chainEnd > 0 )
			{
			setObjectErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
								CRYPT_ERRTYPE_ATTR_PRESENT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "Self-signed certificate must be the only one in the "
					  "chain" ) );
			}
		
		return( CRYPT_OK );
		}

	/* Copy the certificate chain into the certificate to be signed */
	return( copyCertChain( certInfoPtr, iSignContext, FALSE ) );
	}

/* Set up any required timestamp data for a certificate object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setCertTimeinfo( INOUT_PTR CERT_INFO *certInfoPtr,
							IN_HANDLE_OPT const CRYPT_CONTEXT iSignContext,
							IN_BOOL const BOOLEAN isCertificate )
	{
	const time_t currentTime = ( iSignContext == CRYPT_UNUSED ) ? \
								 getTime( GETTIME_MINUTES ) : \
								 getReliableTime( iSignContext, 
												  GETTIME_MINUTES );
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( iSignContext == CRYPT_UNUSED || \
			  isHandleRangeValid( iSignContext ) );
	REQUIRES( isBooleanValue( isCertificate ) );

	/* If it's some certificate variant or a CRL/OCSP response and the 
	   various timestamps haven't been set yet, start them at the current 
	   time and give them the default validity period or next update time if 
	   these haven't been set.  The time used is the local time, this is 
	   converted to GMT when we write it to the certificate.  Issues like 
	   validity period nesting and checking for valid time periods are 
	   handled elsewhere */
	if( isCertificate )
		{
		if( certInfoPtr->startTime <= MIN_TIME_VALUE )
			{
			/* If the time is screwed up then we can't continue */
			if( currentTime <= MIN_TIME_VALUE )
				{
				setObjectErrorInfo( certInfoPtr, CRYPT_CERTINFO_VALIDFROM,
									CRYPT_ERRTYPE_ATTR_VALUE );
				retExt( CRYPT_ERROR_NOTINITED,
						( CRYPT_ERROR_NOTINITED, CERTIFICATE_ERRINFO,
						  "System time isn't valid and can't be added to "
						  "the %s", 
						  getCertTypeNameLC( certInfoPtr->type ) ) );
				}
			certInfoPtr->startTime = currentTime;
			}
		if( certInfoPtr->endTime <= MIN_TIME_VALUE )
			{
			int validity;

			ENSURES( certInfoPtr->startTime > MIN_TIME_VALUE && \
					 certInfoPtr->startTime < MAX_TIME_VALUE );

			/* The end time is an offset from the start time, so we don't
			   necessarily need a valid time to set this */
			status = krnlSendMessage( certInfoPtr->ownerHandle, 
									  IMESSAGE_GETATTRIBUTE, &validity, 
									  CRYPT_OPTION_CERT_VALIDITY );
			if( cryptStatusError( status ) )
				return( status );
			status = setEndTime( certInfoPtr, validity, currentTime );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
#ifdef USE_CERTREV
	if( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
		certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		/* If the time is messed up then we can't provide an indication of 
		   the revocation time */
		if( currentTime <= MIN_TIME_VALUE )
			{
			setObjectErrorInfo( certInfoPtr, CRYPT_CERTINFO_VALIDFROM,
								CRYPT_ERRTYPE_ATTR_VALUE );
			retExt( CRYPT_ERROR_NOTINITED,
					( CRYPT_ERROR_NOTINITED, CERTIFICATE_ERRINFO,
					  "System time isn't valid and can't be added to "
					  "the %s", 
					  getCertTypeNameLC( certInfoPtr->type ) ) );
			}

		/* Set the revocation/validity times */
		if( certInfoPtr->startTime <= MIN_TIME_VALUE )
			certInfoPtr->startTime = currentTime;
		if( certInfoPtr->endTime <= MIN_TIME_VALUE )
			{
			if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
				{
				/* OCSP responses come directly from the certificate store 
				   and represent an atomic (and ephemeral) snapshot of the 
				   store state.  Because of this the next-update time occurs 
				   effectively immediately since the next snapshot could 
				   provide a different response */
				certInfoPtr->endTime = currentTime;
				}
			else
				{
				int updateInterval;

				status = krnlSendMessage( certInfoPtr->ownerHandle,
										  IMESSAGE_GETATTRIBUTE, &updateInterval,
										  CRYPT_OPTION_CERT_UPDATEINTERVAL );
				if( cryptStatusError( status ) )
					return( status );
				status = setEndTime( certInfoPtr, updateInterval, currentTime );
				if( cryptStatusError( status ) )
					return( status );
				}
			}
		if( certInfoPtr->cCertRev->revocationTime <= MIN_TIME_VALUE )
			certInfoPtr->cCertRev->revocationTime = currentTime;
		}
#endif /* USE_CERTREV */

	return( CRYPT_OK );
	}

/* Perform any final initialisation of the certificate object before we sign 
   it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5, 6 ) ) \
static int initSignatureInfo( INOUT_PTR CERT_INFO *certInfoPtr, 
							  IN_PTR_OPT const CERT_INFO *issuerCertInfoPtr,
							  IN_HANDLE_OPT const CRYPT_CONTEXT iSignContext,
							  IN_BOOL const BOOLEAN isCertificate,
							  OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo,
							  OUT_LENGTH_HASH_Z int *hashParam,
							  IN_ENUM_OPT( CRYPT_SIGNATURELEVEL ) \
								const CRYPT_SIGNATURELEVEL_TYPE signatureLevel,
							  OUT_OPT_LENGTH_SHORT_Z int *extraDataLength )
	{
	const CRYPT_ALGO_TYPE signingAlgo = ( issuerCertInfoPtr != NULL ) ? \
				issuerCertInfoPtr->publicKeyAlgo : certInfoPtr->publicKeyAlgo;
	int value, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( hashAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( hashParam, sizeof( int ) ) );
	assert( extraDataLength == NULL || \
			isWritePtr( extraDataLength, sizeof( int ) ) );

	REQUIRES( iSignContext == CRYPT_UNUSED || \
			  isHandleRangeValid( iSignContext ) );
	REQUIRES( isBooleanValue( isCertificate ) );
	REQUIRES( ( signatureLevel == CRYPT_SIGNATURELEVEL_NONE && \
				extraDataLength == NULL ) || \
			  ( signatureLevel >= CRYPT_SIGNATURELEVEL_SIGNERCERT && \
				signatureLevel < CRYPT_SIGNATURELEVEL_LAST && \
				extraDataLength != NULL ) );

	/* Clear return values */
	*hashAlgo = CRYPT_ALGO_NONE;
	*hashParam = 0;
	if( extraDataLength != NULL )
		*extraDataLength = 0;

	/* If we need to include extra data in the signature, make sure that 
	   it's available and determine how big it'll be.  If there's no issuer 
	   certificate available and we've been asked for extra signature data 
	   then we fall back to providing just a raw signature rather than 
	   bailing out completely */
	if( extraDataLength != NULL && issuerCertInfoPtr != NULL )
		{
		ENSURES( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT || \
				 certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST );

		if( signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT )
			{
			status = exportCert( NULL, 0, extraDataLength,
								 CRYPT_CERTFORMAT_CERTIFICATE,
								 issuerCertInfoPtr );
			}
		else
			{
			MESSAGE_DATA msgData;

			ENSURES( signatureLevel == CRYPT_SIGNATURELEVEL_ALL );

			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( issuerCertInfoPtr->objectHandle,
									  IMESSAGE_CRT_EXPORT, &msgData,
									  CRYPT_ICERTFORMAT_CERTSEQUENCE );
			if( cryptStatusOK( status ) )
				*extraDataLength = msgData.length;
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's a certificate chain, copy over the signing certificate(s) */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		REQUIRES( isHandleRangeValid( iSignContext ) );

		status = copySigningCertChain( certInfoPtr, iSignContext );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Set up any required timestamps */
	status = setCertTimeinfo( certInfoPtr, iSignContext, isCertificate );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a certificate, set up the certificate serial number */
	if( isCertificate )
		{
		status = setSerialNumber( certInfoPtr, NULL, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine the hash algorithm to use and if it's a certificate or 
	   CRL remember it for when we write the certificate (the value is 
	   embedded in the certificate to prevent an obscure attack on unpadded 
	   RSA signature algorithms or (EC)DSA signatures) */
	status = krnlSendMessage( certInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_OPTION_ENCR_HASH );
	if( cryptStatusOK( status ) )
		{
		*hashAlgo = value;	/* int vs. enum */
		status = krnlSendMessage( certInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, hashParam, 
								  CRYPT_OPTION_ENCR_HASHPARAM );
		}
	if( cryptStatusError( status ) )
		return( status );
#ifdef USE_DSA
	if( signingAlgo == CRYPT_ALGO_DSA )
		{
		/* If we're going to be signing with DSA then things get a bit 
		   complicated, the only OID defined for non-SHA1 DSA is for 256-bit
		   SHA2, and even then in order to use it with a generic 1024-bit 
		   key we have to truncate the hash.  It's not clear how many 
		   implementations can handle this, and if we're using a hash wider
		   than SHA-2/256 or a newer hash like SHAng then we can't encode 
		   the result at all.  To deal with this we restrict the hash used 
		   with DSA to SHA-1 only */
		*hashAlgo = CRYPT_ALGO_SHA1;
		*hashParam = 20;
		}
#endif /* USE_DSA */
#ifdef USE_ED25519
	if( isBernsteinAlgo( signingAlgo ) )
		{
		/* The usual special-snowflake handling, in this case the algorithms
		   implicitly hardcode SHA2-512 */
		*hashAlgo = CRYPT_ALGO_SHA2;
		*hashParam = 64;
		}
#endif /* USE_ED25519 */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
		certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN || \
		certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		certInfoPtr->cCertCert->hashAlgo = *hashAlgo;
		certInfoPtr->cCertCert->hashParam = *hashParam;
		}
#ifdef USE_CERTREV
	else
		{
		if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
			{
			certInfoPtr->cCertRev->hashAlgo = *hashAlgo;
			certInfoPtr->cCertRev->hashParam = *hashParam;
			}
		}
#endif /* USE_CERTREV */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Signing Functions							*
*																			*
****************************************************************************/

#if defined( USE_CERTREQ ) || defined( USE_CERTREV ) || \
	defined( USE_CERTVAL ) || defined( USE_PKIUSER )

/* Pseudo-sign certificate information by writing the outer wrapper around 
   the certificate object data and moving the object into the initialised 
   state */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int pseudoSignCertificate( INOUT_PTR CERT_INFO *certInfoPtr,
								  INOUT_BUFFER_FIXED( signedObjectMaxLength ) \
										void *signedObject,
								  IN_LENGTH_SHORT_MIN( 16 ) \
										const int signedObjectMaxLength,
								  IN_BUFFER( certObjectLength ) \
										const void *certObject,
								  IN_LENGTH_SHORT_MIN( 16 ) \
										const int certObjectLength )
	{
	STREAM stream;
	int signedObjectLength, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtrDynamic( signedObject, signedObjectMaxLength ) );
	assert( isReadPtrDynamic( certObject, certObjectLength ) );

	REQUIRES( isShortIntegerRangeMin( signedObjectMaxLength, 16 ) );
	REQUIRES( isShortIntegerRangeMin( certObjectLength, 16 ) && \
			  certObjectLength <= signedObjectMaxLength );

	switch( certInfoPtr->type )
		{
		case CRYPT_CERTTYPE_OCSP_REQUEST:
		case CRYPT_CERTTYPE_PKIUSER:
			/* It's an unsigned OCSP request or PKI user information, write 
			   the outer wrapper */
			signedObjectLength = sizeofObject( certObjectLength );
			ENSURES( signedObjectLength >= 16 && \
					 signedObjectLength <= signedObjectMaxLength );
			sMemOpen( &stream, signedObject, signedObjectLength );
			writeSequence( &stream, certObjectLength );
			status = swrite( &stream, certObject, certObjectLength );
			sMemDisconnect( &stream );
			ENSURES( cryptStatusOK( status ) );
			if( certInfoPtr->type == CRYPT_CERTTYPE_PKIUSER )
				{
				status = recoverCertData( certInfoPtr, 
										  CRYPT_CERTTYPE_PKIUSER, 
										  signedObject, signedObjectLength );
				if( cryptStatusError( status ) )
					return( status );
				}
			break;

		case CRYPT_CERTTYPE_RTCS_REQUEST:
		case CRYPT_CERTTYPE_RTCS_RESPONSE:
		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			/* It's an RTCS request/response or OCSP response, it's already
			   in the form required */
			signedObjectLength = certObjectLength;
			REQUIRES( rangeCheck( certObjectLength, 16, 
								  signedObjectMaxLength ) );
			memcpy( signedObject, certObject, certObjectLength );
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
			{
			const int dataSize = certObjectLength + \
								 sizeofObject( sizeofShortInteger( 0 ) );

			ENSURES( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT );

			/* It's an encryption-only key, wrap up the certificate data 
			   with an indication that private key POP will be performed via 
			   out-of-band means and remember where the encoded data 
			   starts */
			signedObjectLength = sizeofObject( dataSize );
			ENSURES( signedObjectLength >= 16 && \
					 signedObjectLength <= signedObjectMaxLength );
			sMemOpen( &stream, signedObject, signedObjectLength );
			writeSequence( &stream, dataSize );
			swrite( &stream, certObject, certObjectLength );
			writeConstructed( &stream, sizeofShortInteger( 0 ), 2 );
			status = writeShortInteger( &stream, 0, 1 );
			sMemDisconnect( &stream );
			ENSURES( cryptStatusOK( status ) );
			status = recoverCertData( certInfoPtr, 
									  CRYPT_CERTTYPE_REQUEST_CERT,
									  signedObject, signedObjectLength );
			if( cryptStatusError( status ) )
				return( status );

			/* Indicate that the pseudo-signature has been checked (since we 
			   just created it), this also avoids nasty semantic problems 
			   with not-really-signed CRMF requests containing encryption-
			   only keys */
			SET_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED );
			break;
			}

		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* Revocation requests can't be signed so the (pseudo-)signed
			   data is just the object data */
			signedObjectLength = certObjectLength;
			REQUIRES( rangeCheck( certObjectLength, 16, 
								  signedObjectMaxLength ) );
			memcpy( signedObject, certObject, certObjectLength );
			status = recoverCertData( certInfoPtr, 
									  CRYPT_CERTTYPE_REQUEST_REVOCATION,
									  signedObject, signedObjectLength );
			if( cryptStatusError( status ) )
				return( status );

			/* Since revocation requests can't be signed we mark them as
			   pseudo-signed to avoid any problems that might arise from
			   this */
			SET_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED );
			break;

		default:
			retIntError();
		}
	certInfoPtr->certificate = signedObject;
	certInfoPtr->certificateSize = signedObjectLength;

	/* The object is now (pseudo-)signed and initialised */
	SET_FLAG( certInfoPtr->flags, CERT_FLAG_SIGCHECKED );
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		/* If it's a CRMF request with POP done via out-of-band means we
		   got here via a standard signing action (except that the key was
		   an encryption-only key), don't change the object state since the
		   kernel will do this as the post-signing step */
		return( CRYPT_OK );
		}
	return( krnlSendMessage( certInfoPtr->objectHandle,
							 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED,
							 CRYPT_IATTRIBUTE_INITIALISED ) );
	}
#endif /* USE_CERTREQ || USE_CERTREV || USE_CERTVAL || USE_PKIUSER */

/* Sign the certificate information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 6, 13 ) ) \
static int signCertInfo( OUT_BUFFER( signedObjectMaxLength, \
									 *signedObjectLength ) \
							void *signedObject, 
						 IN_DATALENGTH const int signedObjectMaxLength, 
						 OUT_DATALENGTH_Z int *signedObjectLength,
						 IN_BUFFER( objectLength ) const void *object, 
						 IN_DATALENGTH const int objectLength,
						 INOUT_PTR CERT_INFO *certInfoPtr, 
						 IN_HANDLE const CRYPT_CONTEXT iSignContext,
						 IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						 IN_LENGTH_HASH const int hashParam,
						 IN_ENUM( CRYPT_SIGNATURELEVEL ) \
							const CRYPT_SIGNATURELEVEL_TYPE signatureLevel,
						 IN_LENGTH_SHORT_Z const int extraDataLength,
						 IN_PTR_OPT const CERT_INFO *issuerCertInfoPtr,
						 INOUT_PTR ERROR_INFO *errorInfo )
	{
	STREAM stream;
	const int extraDataType = \
			( signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT ) ? \
			CRYPT_CERTFORMAT_CERTIFICATE : CRYPT_ICERTFORMAT_CERTSEQUENCE;
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtrDynamic( signedObject, signedObjectMaxLength ) );
	assert( isWritePtr( signedObjectLength, sizeof( int ) ) );
	assert( isReadPtrDynamic( object, objectLength ) && \
			cryptStatusOK( checkCertObjectEncoding( object, objectLength ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isBufsizeRangeMin( signedObjectMaxLength, \
								 MIN_CRYPT_OBJECTSIZE ) );
	REQUIRES( isBufsizeRangeMin( objectLength, 16 ) && \
			  objectLength <= signedObjectMaxLength );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashParam >= MIN_HASHSIZE && \
			  hashParam <= CRYPT_MAX_HASHSIZE );
	REQUIRES( isEnumRangeOpt( signatureLevel, CRYPT_SIGNATURELEVEL ) );
	REQUIRES( isShortIntegerRange( extraDataLength ) );
	REQUIRES( extraDataLength <= 0 || issuerCertInfoPtr != NULL );

	/* Sign the certificate information.  CRMF and OCSP use a b0rken
	   signature format (the authors couldn't quite manage a cut & paste of
	   two lines of text) so if it's one of these we have to use nonstandard
	   formatting */
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT || \
		certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST )
		{
		X509SIG_FORMATINFO formatInfo;

		if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
			{
			/* [1] SEQUENCE */
			setX509FormatInfo( &formatInfo, 1, FALSE );
			}
		else
			{
			/* [0] EXPLICIT SEQUENCE */
			setX509FormatInfo( &formatInfo, 0, TRUE );
			}
		if( signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT )
			{
			formatInfo.extraLength = \
							sizeofShortObject( \
								sizeofShortObject( extraDataLength ) );
			}
		else
			{
			if( signatureLevel == CRYPT_SIGNATURELEVEL_ALL )
				{
				formatInfo.extraLength = \
							sizeofShortObject( extraDataLength );
				}
			}
		status = createX509signature( signedObject, signedObjectMaxLength, 
								signedObjectLength, object, objectLength, 
								iSignContext, hashAlgo, hashParam, 
								&formatInfo, errorInfo );
		}
	else
		{
		/* It's a standard signature */
		status = createX509signature( signedObject, signedObjectMaxLength, 
								signedObjectLength, object, objectLength, 
								iSignContext, hashAlgo, hashParam, NULL, 
								errorInfo );
		}
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_VALUE : status );

	/* If there's no extra data to handle then we're done */
	if( extraDataLength <= 0 )
		{
		ENSURES( cryptStatusOK( \
					checkCertObjectEncoding( signedObject, 
											 *signedObjectLength ) ) );
		return( CRYPT_OK );
		}
	
	/* The extra data consists of signing certificates, so we can't continue
	   if there are none provided.  Figuring out how we get to this point is 
	   rather complex, if we have a certificate, a CRL, or an OCSP object 
	   with an associated signing key then we have an issuer cert present 
	   (from signCert()).  If it's an OCSP request then the signature level 
	   is something other than CRYPT_SIGNATURELEVEL_NONE, at which point if 
	   there's an issuer certificate present then extraDataLength != 0 (from 
	   initSignatureInfo()).  After this, signCert() will exit if there's no 
	   signing key present since there's nothing further to do.  This means 
	   that when we get here and extraDataLength != 0 then it means that 
	   there's an issuer certificate present.  The following check ensures 
	   that this is indeed the case */
	ENSURES( issuerCertInfoPtr != NULL );

	/* If we need to include extra data with the signature attach it to the 
	   end of the signature */
	ENSURES( boundsCheck( *signedObjectLength, 
						  signedObjectMaxLength - *signedObjectLength, 
						  signedObjectMaxLength ) );
	sMemOpen( &stream, ( BYTE * ) signedObject + *signedObjectLength,
			  signedObjectMaxLength - *signedObjectLength );
	if( signatureLevel == CRYPT_SIGNATURELEVEL_SIGNERCERT )
		{
		writeConstructed( &stream, sizeofObject( extraDataLength ), 0 );
		status = writeSequence( &stream, extraDataLength );
		}
	else
		{
		ENSURES( signatureLevel == CRYPT_SIGNATURELEVEL_ALL );

		status = writeConstructed( &stream, extraDataLength, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		status = exportCertToStream( &stream, issuerCertInfoPtr->objectHandle,
									 extraDataType );
		}
	if( cryptStatusOK( status ) )
		*signedObjectLength += stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( cryptStatusOK( \
					checkCertObjectEncoding( signedObject, 
											 *signedObjectLength ) ) );

	return( CRYPT_OK );
	}

/* Create the signed certificate object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int createSignedObject( INOUT_PTR CERT_INFO *certInfoPtr, 
							   IN_PTR_OPT const CERT_INFO *issuerCertInfoPtr,
							   IN_HANDLE_OPT const CRYPT_CONTEXT iSignContext,
							   IN_ENUM_OPT( CRYPT_SIGNATURELEVEL ) \
									const CRYPT_SIGNATURELEVEL_TYPE signatureLevel,
							   IN_LENGTH_SHORT_Z const int extraDataLength,
							   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
							   IN_LENGTH_HASH const int hashParam,
							   IN_BOOL const BOOLEAN nonSigningKey )
	{
	WRITECERT_FUNCTION writeCertFunction;
	STREAM stream;
	ERROR_INFO localErrorInfo;
	BYTE certObjectBuffer[ 1024 + 8 ], *certObjectPtr = certObjectBuffer;
	void *signedCertObject;
	int certObjectLength DUMMY_INIT, signedCertObjectLength;
	int signedCertAllocSize, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( iSignContext == CRYPT_UNUSED || \
			  isHandleRangeValid( iSignContext ) );
	REQUIRES( isEnumRangeOpt( signatureLevel, CRYPT_SIGNATURELEVEL ) );
	REQUIRES( isShortIntegerRange( extraDataLength ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( rangeCheck( hashParam, MIN_HASHSIZE, CRYPT_MAX_HASHSIZE ) );
	REQUIRES( isBooleanValue( nonSigningKey ) );

	/* Select the function to use to write the certificate object to be
	   signed */
	writeCertFunction = getCertWriteFunction( certInfoPtr->type );
	ENSURES( writeCertFunction != NULL );

	/* Determine how big the encoded certificate information will be,
	   allocate memory for it and the full signed certificate, and write the
	   encoded certificate information */
	sMemNullOpen( &stream );
	status = writeCertFunction( &stream, certInfoPtr, issuerCertInfoPtr, 
								iSignContext );
	if( cryptStatusOK( status ) )
		certObjectLength = stell( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( isIntegerRangeNZ( certObjectLength ) );
	signedCertAllocSize = certObjectLength + 1024 + extraDataLength;
	if( certObjectLength > 1024 )
		{
		REQUIRES( isIntegerRangeNZ( certObjectLength ) );
		certObjectPtr = clDynAlloc( "signCert", certObjectLength );
		if( certObjectPtr == NULL )
			return( CRYPT_ERROR_MEMORY );
		}
	REQUIRES( rangeCheck( signedCertAllocSize, 1, MAX_BUFFER_SIZE ) );
	signedCertObject = clAlloc( "signCert", signedCertAllocSize );
	if( signedCertObject == NULL )
		{
		if( certObjectPtr != certObjectBuffer )
			clFree( "signCert", certObjectPtr );
		return( CRYPT_ERROR_MEMORY );
		}
	sMemOpen( &stream, certObjectPtr, certObjectLength );
	status = writeCertFunction( &stream, certInfoPtr, issuerCertInfoPtr, 
								iSignContext );
	ENSURES_PTR( cryptStatusError( status ) || \
				 certObjectLength == stell( &stream ), 
				 signedCertObject );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		REQUIRES_PTR( isIntegerRangeNZ( certObjectLength ),
					  signedCertObject ); 
		zeroise( certObjectPtr, certObjectLength );
		if( certObjectPtr != certObjectBuffer )
			clFree( "signCert", certObjectPtr );
		clFree( "signCert", signedCertObject );
		return( status );
		}
	ENSURES_PTR( cryptStatusOK( \
						checkCertObjectEncoding( certObjectPtr, \
												 certObjectLength ) ),
				 signedCertObject );

#if defined( USE_CERTREQ ) || defined( USE_CERTREV ) || \
	defined( USE_CERTVAL ) || defined( USE_PKIUSER )
	/* If there's no signing key present we pseudo-sign the certificate 
	   information by writing the outer wrapper and moving the object into 
	   the initialised state */
	if( nonSigningKey )
		{
		status = pseudoSignCertificate( certInfoPtr, signedCertObject,
										signedCertAllocSize, certObjectPtr, 
										certObjectLength );
		REQUIRES_PTR( isIntegerRangeNZ( certObjectLength ),
					  signedCertObject ); 
		zeroise( certObjectPtr, certObjectLength );
		if( certObjectPtr != certObjectBuffer )
			clFree( "signCert", certObjectPtr );
		if( cryptStatusError( status ) )
			{
			clFree( "signCert", signedCertObject );
			return( status );
			}
		ANALYSER_HINT( certInfoPtr->certificate != NULL );
		ENSURES( cryptStatusOK( \
					checkCertObjectEncoding( certInfoPtr->certificate, 
											 certInfoPtr->certificateSize ) ) );

		return( CRYPT_OK );
		}
#endif /* USE_CERTREQ || USE_CERTREV || USE_CERTVAL || USE_PKIUSER */

	/* Sign the certificate information */
	clearErrorInfo( &localErrorInfo );
	status = signCertInfo( signedCertObject, signedCertAllocSize, 
						   &signedCertObjectLength, certObjectPtr, 
						   certObjectLength, certInfoPtr, iSignContext, 
						   hashAlgo, hashParam, signatureLevel, 
						   extraDataLength, issuerCertInfoPtr, 
						   &localErrorInfo );
	REQUIRES_PTR( isIntegerRangeNZ( certObjectLength ),
				  signedCertObject ); 
	zeroise( certObjectPtr, certObjectLength );
	if( certObjectPtr != certObjectBuffer )
		clFree( "signCert", certObjectPtr );
	if( cryptStatusError( status ) )
		{
		clFree( "signCert", signedCertObject );
		retExtErr( status,
				   ( status, CERTIFICATE_ERRINFO, &localErrorInfo,
					 "Couldn't sign %s data", 
					 getCertTypeNameLC( certInfoPtr->type ) ) );
		}
	certInfoPtr->certificate = signedCertObject;
	certInfoPtr->certificateSize = signedCertObjectLength;

	return( CRYPT_OK );
	}

/* Sign a certificate object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int signCert( INOUT_PTR CERT_INFO *certInfoPtr, 
			  IN_HANDLE_OPT const CRYPT_CONTEXT iSignContext )
	{
	CRYPT_ALGO_TYPE hashAlgo;
	CERT_INFO *issuerCertInfoPtr = NULL;
#ifdef USE_CERTREV
	const CRYPT_SIGNATURELEVEL_TYPE signatureLevel = \
				( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST ) ? \
					certInfoPtr->cCertRev->signatureLevel : \
					CRYPT_SIGNATURELEVEL_NONE;
#else
	const CRYPT_SIGNATURELEVEL_TYPE signatureLevel = CRYPT_SIGNATURELEVEL_NONE;
#endif /* USE_CERTREV */
	const BOOLEAN isCertificate = \
			( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN ) ? TRUE : FALSE;
	BOOLEAN issuerCertAcquired = FALSE, nonSigningKey = FALSE;
	int hashParam, extraDataLength = 0, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );
	REQUIRES( certInfoPtr->certificate == NULL );
	REQUIRES( iSignContext == CRYPT_UNUSED || \
			  isHandleRangeValid( iSignContext ) );

	/* If it's a non-signing key then we have to create a special format of 
	   certificate request that isn't signed but contains an indication that 
	   the private key POP will be performed by out-of-band means.  We also 
	   have to check for the iSignContext being absent to handle OCSP 
	   requests for which the signature is optional so there may be no 
	   signing key present */
	if( iSignContext == CRYPT_UNUSED )
		nonSigningKey = TRUE;
	else
		{
		/* We've got a signing key, make sure that it's signature-capable */
		if( !checkContextCapability( iSignContext, 
									 MESSAGE_CHECK_PKC_SIGN_CA ) && \
			!checkContextCapability( iSignContext, 
									 MESSAGE_CHECK_PKC_SIGN ) )
			nonSigningKey = TRUE;
		}

	/* Obtain the issuer certificate from the private key if necessary 
	   (aliena nobis, nostra plus aliis placent - Publilius Syrus) */
	if( isCertificate || \
		certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
		( ( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE ) && \
		  !nonSigningKey ) )
		{
		REQUIRES( isHandleRangeValid( iSignContext ) );

		/* If it's a self-signed certificate then the issuer is also the 
		   subject */
		if( TEST_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED ) )
			issuerCertInfoPtr = certInfoPtr;
		else
			{
			CRYPT_CERTIFICATE dataOnlyCert;

			/* Get the data-only certificate from the context */
			status = krnlSendMessage( iSignContext, IMESSAGE_GETDEPENDENT,
									  &dataOnlyCert, OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				{
				return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
						CRYPT_ARGERROR_VALUE : status );
				}
			status = krnlAcquireObject( dataOnlyCert, OBJECT_TYPE_CERTIFICATE,
										( MESSAGE_PTR_CAST ) &issuerCertInfoPtr,
										CRYPT_ARGERROR_VALUE );
			if( cryptStatusError( status ) )
				return( status );
			REQUIRES_OBJECT( sanityCheckCert( issuerCertInfoPtr ),
							 issuerCertInfoPtr->objectHandle );
			issuerCertAcquired = TRUE;
			}

		/* Check the signing key */
		status = checkSigningKey( certInfoPtr, issuerCertInfoPtr, 
								  iSignContext, isCertificate );
		if( cryptStatusError( status ) )
			{
			if( issuerCertAcquired == TRUE )
				krnlReleaseObject( issuerCertInfoPtr->objectHandle );
			return( status );
			}
		}

	/* Perform any final initialisation of the certificate object before we 
	   sign it */
	status = initSignatureInfo( certInfoPtr, issuerCertInfoPtr, 
								iSignContext, isCertificate, &hashAlgo,
								&hashParam, signatureLevel,
								( signatureLevel > CRYPT_SIGNATURELEVEL_NONE ) ? \
									&extraDataLength : NULL );
	if( cryptStatusError( status ) )
		{
		if( issuerCertAcquired == TRUE )
			krnlReleaseObject( issuerCertInfoPtr->objectHandle );
		retExt( status,
				( status, CERTIFICATE_ERRINFO,
				  "Couldn't initialise %s signing information",
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}

	/* Create the signed certifcate object */
	status = createSignedObject( certInfoPtr, issuerCertInfoPtr, 
								 iSignContext, signatureLevel, 
								 extraDataLength, hashAlgo, hashParam,
								 nonSigningKey );
	if( issuerCertAcquired == TRUE )
		krnlReleaseObject( issuerCertInfoPtr->objectHandle );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( certInfoPtr->certificate != NULL );

	/* If it's a pseudo-signed certificate object, we're done */
	if( nonSigningKey )
		{
		ENSURES( sanityCheckCert( certInfoPtr ) );

		return( CRYPT_OK );
		}

	/* If it's a certification request it's now self-signed.  In addition 
	   the signature has been checked since we've just created it */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
		certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		SET_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED );
	SET_FLAG( certInfoPtr->flags, CERT_FLAG_SIGCHECKED );

	/* If it's not an object type with special-case post-signing
	   requirements we're done */
	if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
		certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN && \
		certInfoPtr->type != CRYPT_CERTTYPE_CERTREQUEST && \
		certInfoPtr->type != CRYPT_CERTTYPE_REQUEST_CERT && \
		certInfoPtr->type != CRYPT_CERTTYPE_CRL )
		{
		ENSURES( sanityCheckCert( certInfoPtr ) );

		return( CRYPT_OK );
		}

	/* Recover information such as pointers to encoded certificate data */
	status = recoverCertData( certInfoPtr, certInfoPtr->type, 
							  certInfoPtr->certificate, 
							  certInfoPtr->certificateSize );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( sanityCheckCert( certInfoPtr ) );

	return( CRYPT_OK );
	}
#endif /* USE_CERTIFICATES */
