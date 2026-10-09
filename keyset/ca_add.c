/****************************************************************************
*																			*
*					cryptlib DBMS CA Certificate Add Interface				*
*						Copyright Peter Gutmann 1996-2025					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "dbms.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "keyset/dbms.h"
  #include "keyset/keyset.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check that the request that we've been passed is in order */

CHECK_RETVAL_BOOL \
BOOLEAN checkRequest( IN_HANDLE const CRYPT_CERTIFICATE iCertRequest,
					  IN_ENUM_OPT( CRYPT_CERTACTION ) \
						const CRYPT_CERTACTION_TYPE action )
	{
	MESSAGE_DATA msgData;
	BOOLEAN_INT isInited, isSelfSigned;
	int certType, value, status;

	REQUIRES_B( isHandleRangeValid( iCertRequest ) );
	REQUIRES_B( action == CRYPT_CERTACTION_CERT_CREATION || \
				action == CRYPT_CERTACTION_ISSUE_CERT || \
				action == CRYPT_CERTACTION_REVOKE_CERT || \
				action == CRYPT_CERTACTION_ADDREQUEST || \
				action == CRYPT_CERTACTION_NONE );

	/* Make sure that the request type is consistent with the operation
	   being performed */
	status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
							  &certType, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( FALSE );
	switch( action )
		{
		case CRYPT_CERTACTION_CERT_CREATION:
		case CRYPT_CERTACTION_ISSUE_CERT:
			if( certType != CRYPT_CERTTYPE_CERTREQUEST && \
				certType != CRYPT_CERTTYPE_REQUEST_CERT )
				return( FALSE );
			break;

		case CRYPT_CERTACTION_REVOKE_CERT:
			if( certType != CRYPT_CERTTYPE_REQUEST_REVOCATION )
				return( FALSE );
			break;

		case CRYPT_CERTACTION_ADDREQUEST:
		case CRYPT_CERTACTION_NONE:
			/* We're performing a straight add of a request to the store,
			   any request type is permitted */
			break;

		default:
			retIntError_Boolean();
		}

	/* Make sure that the request is completed and valid.  We don't check
	   the signature on revocation requests since they aren't signed, and
	   have to be careful with CRMF requests which can be unsigned for
	   encryption-only keys */
	status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
							  &isInited, CRYPT_CERTINFO_IMMUTABLE );
	if( cryptStatusError( status ) || !isInited )
		return( FALSE );
	switch( certType )
		{
		case CRYPT_CERTTYPE_REQUEST_CERT:
			status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
									  &isSelfSigned, 
									  CRYPT_CERTINFO_SELFSIGNED );
			if( cryptStatusOK( status ) && !isSelfSigned )
				{
				/* It's an unsigned CRMF request, make sure that it really 
				   is an encryption-only key, indicated by having a keyUsage
				   attribute present with no signing usages */
				status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
										  &value, CRYPT_CERTINFO_KEYUSAGE );
				if( cryptStatusError( status ) || \
					( value & ~KEYUSAGE_CRYPT ) )
					return( FALSE );
				break;
				}
			STDC_FALLTHROUGH;

		case CRYPT_CERTTYPE_CERTREQUEST:
			status = krnlSendMessage( iCertRequest, IMESSAGE_CRT_SIGCHECK,
									  NULL, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				return( FALSE );
			break;

		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* Revocation requests are unsigned so we can't perform a 
			   signature check on them */
			break;

		default:
			retIntError_Boolean();
		}

	/* Check that required parameters are present.  This is necessary for
	   CRMF requests where every single parameter is optional, for our use
	   we require that a certificate request contains at least a subject DN 
	   and public key and a revocation request contains at least an issuer 
	   DN and serial number */
	switch( certType )
		{
		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_CERTREQUEST:
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_IATTRIBUTE_SUBJECT );
			if( cryptStatusError( status ) )
				return( FALSE );
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_IATTRIBUTE_SPKI );
			if( cryptStatusError( status ) )
				return( FALSE );
			break;

		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, 
									  CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
			if( cryptStatusError( status ) )
				return( FALSE );
			break;

		default:
			retIntError_Boolean();
		}

	return( TRUE );
	}

/* Check that a revocation request is consistent with information held in the
   certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkRevRequest( INOUT_PTR DBMS_INFO *dbmsInfo,
							IN_HANDLE const CRYPT_CERTIFICATE iCertRequest )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	char certID[ ENCODED_DBXKEYID_SIZE + 8 ];
	char issuerID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int certIDlength, issuerIDlength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	
	REQUIRES( isHandleRangeValid( iCertRequest ) );

	/* Check that the certificate being referred to in the request is 
	   present and active */
	status = getKeyID( issuerID, ENCODED_DBXKEYID_SIZE, &issuerIDlength, 
					   iCertRequest, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) )
		{
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, issuerID, issuerIDlength );
		status = dbmsQuery(
			"SELECT certData FROM certificates WHERE issuerID = ?",
							NULL, 0, NULL, boundDataPtr,
							DBMS_CACHEDQUERY_ISSUERID, DBMS_QUERY_CHECK );
		}
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );

	/* The certificate isn't an active certificate, it's either not present 
	   or not active, return an appropriate error code.  If this request has 
	   been entered into the certificate store log then it's a duplicate 
	   request, otherwise it's a request to revoke a non-present certificate 
	   (either that or something really obscure which is best reported as a 
	   non-present certificate problem) */
	status = getKeyID( certID, ENCODED_DBXKEYID_SIZE, &certIDlength, 
					   iCertRequest, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusOK( status ) )
		{
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, certID, certIDlength );
		status = dbmsQuery(
			"SELECT certData FROM certLog WHERE certID = ?",
							NULL, 0, NULL, boundDataPtr,
							DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CHECK );
		}
	return( cryptStatusOK( status ) ? \
			CRYPT_ERROR_DUPLICATE : CRYPT_ERROR_NOTFOUND );
	}

/****************************************************************************
*																			*
*							Certificate Add Functions						*
*																			*
****************************************************************************/

/* Add a new PKI user to the certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int caAddPKIUser( INOUT_PTR DBMS_INFO *dbmsInfo, 
				  IN_HANDLE const CRYPT_CERTIFICATE iPkiUser,
				  INOUT_PTR ERROR_INFO *errorInfo )
	{
	BYTE certData[ MAX_CERT_SIZE + 8 ];
	char certID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int certDataLength, certIDlength DUMMY_INIT, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	
	REQUIRES( isHandleRangeValid( iPkiUser ) );
	REQUIRES( errorInfo != NULL );

	/* Extract the information that we need from the PKI user object.  In
	   addition to simply obtaining the information for logging purposes we
	   also need to perform this action to tell the certificate management 
	   code to fill in the remainder of the (implicitly-added) user 
	   information  before we start querying fields as we add it to the 
	   certificate store.  Because of this we also need to place the certID 
	   fetch after the object export since it's in an incomplete state 
	   before this point */
	status = extractCertData( iPkiUser, CRYPT_ICERTFORMAT_DATA,
							  certData, MAX_CERT_SIZE, &certDataLength );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( certID, ENCODED_DBXKEYID_SIZE, &certIDlength, 
						   iPkiUser, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't extract PKI user data to add to certificate "
				  "store" ) );
		}

	/* Update the certificate store */
	status = addCert( dbmsInfo, iPkiUser, CRYPT_CERTTYPE_PKIUSER,
					  CERTADD_NORMAL, DBMS_UPDATE_BEGIN, errorInfo );
	if( cryptStatusOK( status ) )
		{
		status = updateCertLogEx( dbmsInfo, CRYPT_CERTACTION_ADDUSER, 
								  certID, certIDlength, NULL, 0, NULL, 0, 
								  certID, certIDlength, certData, 
								  certDataLength, DBMS_UPDATE_COMMIT );
		}
	else
		{
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "PKI user add operation failed" ) );
		}
		
	return( CRYPT_OK );
	}

/* Delete a PKI user from the certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int caDeletePKIUser( INOUT_PTR DBMS_INFO *dbmsInfo, 
					 IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
					 IN_BUFFER( keyIDlength ) const void *keyID, 
					 IN_LENGTH_KEYID const int keyIDlength,
					 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CERTIFICATE iPkiUser;
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	char pkiUserID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int pkiUserIDlength DUMMY_INIT, dummy, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isReadPtrDynamic( keyID, keyIDlength ) );

	REQUIRES( keyIDtype == CRYPT_KEYID_NAME || \
			  keyIDtype == CRYPT_KEYID_URI );
	REQUIRES( keyIDlength >= MIN_NAME_LENGTH && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );
	REQUIRES( errorInfo != NULL );

	/* Get information on the PKI user that we're about to delete */
	status = getItemData( dbmsInfo, &iPkiUser, &dummy, 
						  KEYMGMT_ITEM_PKIUSER, keyIDtype, 
						  keyID, keyIDlength, KEYMGMT_FLAG_NONE, 
						  errorInfo );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( pkiUserID, ENCODED_DBXKEYID_SIZE, 
						   &pkiUserIDlength, iPkiUser, 
						   CRYPT_CERTINFO_FINGERPRINT_SHA1 );
		krnlSendNotifier( iPkiUser, IMESSAGE_DECREFCOUNT );
		iPkiUser = CRYPT_ERROR;
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "Couldn't get information on PKI user to be "
					 "deleted" ) );
		}

	/* Delete the PKI user information and record the deletion */
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, pkiUserID, pkiUserIDlength );
	status = dbmsUpdate( 
			"DELETE FROM pkiUsers WHERE certID = ?", 
						 boundDataPtr, DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		{
		char pkiUserIDmod[ ENCODED_DBXKEYID_SIZE + 8 ];

		/* This pkiUserID is already recorded in the log from when the
		   user was created so we modify it for the delete log entry */
		REQUIRES( pkiUserIDlength == ENCODED_DBXKEYID_SIZE );
		memcpy( pkiUserIDmod, pkiUserID, pkiUserIDlength );
		modifyUniqueID( pkiUserIDmod, pkiUserIDlength, 
						IDMOD_CERTISSUE_COMPLETE );
		status = updateCertLogEx( dbmsInfo, CRYPT_CERTACTION_DELETEUSER, 
								  pkiUserIDmod, pkiUserIDlength, NULL, 0, 
								  NULL, 0, pkiUserID, pkiUserIDlength, 
								  NULL, 0, DBMS_UPDATE_COMMIT );
		}
	else
		{
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "PKI user delete operation failed" ) );
		}
		
	return( CRYPT_OK );
	}

/* Add a certificate issue or revocation request to the certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
int caAddCertRequest( INOUT_PTR DBMS_INFO *dbmsInfo, 
					  IN_HANDLE const CRYPT_CERTIFICATE iCertRequest,
					  IN_HANDLE_OPT const CRYPT_CERTIFICATE iAuthCert,
					  IN_HANDLE_OPT const CRYPT_CERTIFICATE iPkiUser,
					  IN_ENUM_OPT( CERTMGMT_OPTION ) \
						const CERTMGMT_OPTION_TYPE option,
					  INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CERTTYPE_TYPE requestType;
	CERTID_INFO certIDinfo;
	BYTE certData[ MAX_CERT_SIZE + 8 ];
	int certDataLength DUMMY_INIT, value, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	
	REQUIRES( isHandleRangeValid( iCertRequest ) );
	REQUIRES( iAuthCert == CRYPT_UNUSED || isHandleRangeValid( iAuthCert ) );
	REQUIRES( iPkiUser == CRYPT_UNUSED || isHandleRangeValid( iPkiUser ) );
	REQUIRES( isEnumRangeOpt( option, CERTMGMT_OPTION ) );
	REQUIRES( errorInfo != NULL );

	/* Find out what sort of request type we're dealing with.  The type check
	   should have been enforced by the kernel but we make the check explicit
	   here */
	status = krnlSendMessage( iCertRequest, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	requestType = value;	/* int vs. enum */
	if( requestType != CRYPT_CERTTYPE_CERTREQUEST && \
		requestType != CRYPT_CERTTYPE_REQUEST_CERT && \
		requestType != CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, errorInfo, 
					 "Invalid item type for CA certificate store" ) );
		}

	/* Make sure that the request is OK and if it's a revocation request 
	   make sure that it refers to a certificate which is both present in 
	   the store and currently active */
	if( !checkRequest( iCertRequest, CRYPT_CERTACTION_NONE ) )
		{
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, errorInfo, 
					 "Certificate request information "
					 "inconsistent/invalid" ) );
		}
	if( requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		status = checkRevRequest( dbmsInfo, iCertRequest );
		if( cryptStatusError( status ) )
			retExt( status, 
					( status, errorInfo, 
					  "Revocation request doesn't correspond to a currently "
					  "active certificate" ) );
		}

	/* Extract the information that we need from the certificate request */
	status = getCertIDinfo( &certIDinfo, iCertRequest, iAuthCert, iPkiUser );
	if( cryptStatusOK( status ) )
		{
		status = extractCertData( iCertRequest, 
								  ( requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION ) ? \
									CRYPT_ICERTFORMAT_DATA : \
									CRYPT_CERTFORMAT_CERTIFICATE,
								  certData, MAX_CERT_SIZE, &certDataLength );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't extract certificate ID information to add to "
				  "certificate store" ) );
		}

	/* If the request was authorised with a signing certificate, make sure 
	   that it's valid */
	if( iAuthCert != CRYPT_UNUSED )
		{
		CRYPT_CERTIFICATE iAuthPkiUser;

		REQUIRES( isHandleRangeValid( iPkiUser ) );

		/* Check that the PKI user who authorised this certificate issue 
		   still exists.  If the CA has deleted them then all further 
		   requests for certificates fail */
		status = caGetIssuingUser( dbmsInfo, &iAuthPkiUser, 
								   certIDinfo.authCertID, 
								   certIDinfo.authCertIDlength, errorInfo );
		if( cryptStatusError( status ) )
			{
			updateCertErrorLog( dbmsInfo, status,
								"Certificate request submitted for "
								"nonexistent PKI user", 
								certIDinfo.authCertID, 
								certIDinfo.authCertIDlength );
			retExt( CRYPT_ERROR_PERMISSION, 
					( CRYPT_ERROR_PERMISSION, errorInfo, 
					  "Certificate request submitted for nonexistent PKI "
					  "user" ) );
			}

		/* Make sure that the PKI user for the authorising certificate is 
		   the same as the PKI user for the request */
		status = krnlSendMessage( iAuthPkiUser, IMESSAGE_COMPARE, 
								  ( MESSAGE_CAST ) &iPkiUser, 
								  MESSAGE_COMPARE_CERTOBJ );
		krnlSendNotifier( iAuthPkiUser, IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			{
			/* The order of the parameters for the error log is a bit
			   unusual, they don't correspond to the usual log columns
			   because we're not following the { cert, request, authCert, 
			   pkiUser } form but just { A, B }, with the parameters 
			   matching the order of the text in the error message */
			updateCertErrorLogEx( dbmsInfo, CRYPT_ERROR_PERMISSION,
								  "PKI user for authorising certificate "
								  "doesn't match PKI user for certificate "
								  "request", certIDinfo.authCertID, 
								  certIDinfo.authCertIDlength,
								  certIDinfo.pkiUserIDptr, 
								  certIDinfo.pkiUserIDlength );
			retExt( CRYPT_ERROR_PERMISSION, 
					( CRYPT_ERROR_PERMISSION, errorInfo, 
					  "PKI user for authorising certificate doesn't match "
					  "PKI user for certificate request" ) );
			}
		}

	/* If there's a PKI user present make sure that it hasn't already been 
	   used to authorise the issuance of an initial certificate.  This is 
	   potentially vulnerable to the following race condition:

		1: check pkiUserID + initial issue -> none issued yet
		2: check pkiUserID + initial issue -> none issued yet
		1: add
		2: add

	   In theory we could detect this by recording the pkiUserID + initial 
	   issue in a column with a UNIQUE constraint, but this just adds extra
	   kludges for a condition that will most likely never occur.
	   
	   In terms of certificate issuance after the first one, it's not 
	   certain how many further operations a certificate (rather than a PKI 
	   user) can authorise, in theory a single signing certificate can 
	   authorise at least four further operations, these being the update of 
	   itself, the update of an associated encryption certificate, and the 
	   revocation of itself and the encryption certificate.  In addition its 
	   possible that a signing certificate could be used to authorise a 
	   series of short-duration encryption certificates or a variety of 
	   other combinations of operations.

	   Because of these issues only check for the case where a PKI user 
	   authorises an initial certificate issue.  We can't perform a general-
	   purpose check because as soon as a single issue has been authorised 
	   for a user there'll be a request for that user logged so that all 
	   further attempts to submit a request (for example for a renewal, or 
	   an encryption certificate to go with a signing one) will fail.  
	   Because of this we only perform a check on the first attempt to issue 
	   a certificate.  
	   
	   What this means in CMP terms is that the user gets a single MAC 
	   (password) authenticated ir and after that subsequent requests have 
	   to be signed cr/kurs */
	if( option == CERTMGMT_OPTION_INITIAL && iPkiUser != CRYPT_UNUSED )
		{
		BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ];
		BOUND_DATA *boundDataPtr = boundData;

		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, certIDinfo.pkiUserID, 
					  certIDinfo.pkiUserIDlength );
		status = dbmsQuery(
			"SELECT certID FROM certLog WHERE pkiUserID = ? "
			"AND action = " TEXT_CERTACTION_REQUEST_CERT,
							NULL, 0, NULL, boundDataPtr, 
							DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CHECK );
		if( cryptStatusOK( status ) )
			{
			/* This user has already authorised the issue of a certificate, 
			   it can't be used to issue a second certificate */
			updateCertErrorLog( dbmsInfo, CRYPT_ERROR_DUPLICATE,
								"Attempt to request additional certificate "
								"when an initial certificate for this user "
								"has already been issued", 
								certIDinfo.pkiUserID, 
								certIDinfo.pkiUserIDlength );
			retExt( CRYPT_ERROR_DUPLICATE, 
					( CRYPT_ERROR_DUPLICATE, errorInfo, 
					  "Attempt to request additional certificate when an "
					  "initial certificate for this user has already been "
					  "issued" ) );
			}
		}

	/* Update the certificate store.  Since a revocation request generally 
	   won't have any fields of any significance set we have to use a 
	   special cut-down insert statement that doesn't expect to find any 
	   fields except the certificate ID */
	if( requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ];
		BOUND_DATA *boundDataPtr = boundData;
		char encodedCertData[ MAX_ENCODED_CERT_SIZE + 8 ];

		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, certIDinfo.certID, 
					  certIDinfo.certIDlength );
		if( hasBinaryBlobs( dbmsInfo ) )
			{
			setBoundDataBlob( boundDataPtr, 1, certData, certDataLength );
			}
		else
			{
			int encodedCertDataLength;
			
			status = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE, 
								   &encodedCertDataLength, certData, 
								   certDataLength, CRYPT_CERTTYPE_NONE );
			if( cryptStatusError( status ) )
				{
				/* This is a should-never-occur so we don't bother with
				   extended error information */
				DEBUG_DIAG(( "Couldn't base64-encode data" ));
				assert( DEBUG_WARN );
				return( status );
				}
			setBoundData( boundDataPtr, 1, encodedCertData, 
						  encodedCertDataLength );
			}
		status = dbmsUpdate( 
			"INSERT INTO certRequests (type, certID, certData) VALUES ('"
			TEXT_CERTTYPE_REQUEST_REVOCATION "', ?, ?)", 
			boundDataPtr, DBMS_UPDATE_BEGIN );
		}
	else
		{
		status = addCert( dbmsInfo, iCertRequest, CRYPT_CERTTYPE_REQUEST_CERT,
						  CERTADD_NORMAL, DBMS_UPDATE_BEGIN, errorInfo );
		}
	if( cryptStatusOK( status ) )
		{
		status = updateCertLogEx( dbmsInfo,
						( requestType == CRYPT_CERTTYPE_REQUEST_REVOCATION ) ? \
							CRYPT_CERTACTION_REQUEST_REVOCATION : \
						( option == CERTMGMT_OPTION_RENEWAL ) ? \
							CRYPT_CERTACTION_REQUEST_RENEWAL : \
							CRYPT_CERTACTION_REQUEST_CERT,
						certIDinfo.certID, certIDinfo.certIDlength, NULL, 0, 
						certIDinfo.authCertIDptr, certIDinfo.authCertIDlength, 
						certIDinfo.pkiUserIDptr, certIDinfo.pkiUserIDlength, 
						certData, certDataLength, DBMS_UPDATE_COMMIT );
		}
	else
		{
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
		}
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "Certificate request add operation failed" ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
