/****************************************************************************
*																			*
*					cryptlib DBMS CA Certificate Issue Interface			*
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

/* Get the issue type (request vs. renewal) for a particular certificate 
   request or certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int getCertIssueType( INOUT_PTR DBMS_INFO *dbmsInfo,
							 IN_HANDLE const CRYPT_CERTIFICATE iCertificate,
							 OUT_ENUM_OPT( CERTADD ) CERTADD_TYPE *issueType,
							 IN_BOOL const BOOLEAN isCert )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	BYTE certData[ MAX_QUERY_RESULT_SIZE + 8 ];
	char certID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int certIDlength, length, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isWritePtr( issueType, sizeof( CERTADD_TYPE ) ) );
	
	REQUIRES( isHandleRangeValid( iCertificate ) );
	REQUIRES( isBooleanValue( isCert ) );

	/* Clear return value */
	*issueType = CERTADD_NONE;

	/* Get the certID of the request that resulted in the certificate 
	   creation */
	status = getKeyID( certID, ENCODED_DBXKEYID_SIZE, &certIDlength, 
					   iCertificate, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusOK( status ) && isCert )
		{
		/* If it's a certificate then we have to apply an extra level of 
		   indirection to get the request that resulted in its creation */
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, certID, certIDlength );
		status = dbmsQuery(
			"SELECT reqCertID FROM certLog WHERE certID = ?",
							certData, MAX_QUERY_RESULT_SIZE, &length, 
							boundDataPtr, DBMS_CACHEDQUERY_NONE, 
							DBMS_QUERY_NORMAL );
		if( cryptStatusOK( status ) )
			{
			if( length > ENCODED_DBXKEYID_SIZE )
				length = ENCODED_DBXKEYID_SIZE;
			REQUIRES( rangeCheck( length, 1, ENCODED_DBXKEYID_SIZE ) );
			memcpy( certID, certData, length );
			certIDlength = length;
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Find out whether this was a certificate update by checking whether it 
	   was added as a standard or renewal request, then set the update type
	   appropriately.  The comparison for the action type is a bit odd since
	   some back-ends will return the action as text and some as a binary
	   numeric value, rather than relying on the back-end glue code to
	   perform the appropriate conversion we just check for either value
	   type.
	   
	   In addition to performing this basic check in order to figure out how
	   the replacement process should be handled we could in theory also 
	   check that an update really is a pure update with all other portions
	   of the certificate being identical, however there are two problems
	   with this.  The first is that we don't know when we get the request 
	   how much of what's in the final certificate will be added by the CA 
	   (in other words we'd have to check that the request is a proper 
	   subset of the certificate that it's supposedly updating, which isn't 
	   easily feasible).  The second, more important one is that if a client 
	   really wants to change the certificate details then they can just use 
	   a CRYPT_CERTACTION_REQUEST_CERT in place of a 
	   CRYPT_CERTACTION_REQUEST_RENEWAL and change whatever details they 
	   want.  The distinction between the two is really just an artefact of 
	   CMP's messaging, and as usual the CMP spec confuses the issue 
	   completely, with varied discussions of updating a key vs. updating a 
	   certificate vs. obtaining a certificate.  Because of this there 
	   doesn't seem to be anything to be gained by performing whatever it is 
	   that we could be checking for here */
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, certID, certIDlength );
	status = dbmsQuery(
		"SELECT action FROM certLog WHERE certID = ?",
						certData, MAX_QUERY_RESULT_SIZE, &length, 
						boundDataPtr, DBMS_CACHEDQUERY_NONE, 
						DBMS_QUERY_NORMAL );
	if( cryptStatusError( status ) )
		return( status );
	if( length < 1 )
		{
		/* Safety check for should-never-occur situation */
		return( CRYPT_ERROR_BADDATA );
		}
	switch( certData[ 0 ] )
		{
		case CRYPT_CERTACTION_REQUEST_CERT:
		case TEXTCH_CERTACTION_REQUEST_CERT:
			*issueType = CERTADD_PARTIAL;
			return( CRYPT_OK );

		case CRYPT_CERTACTION_REQUEST_RENEWAL:
		case TEXTCH_CERTACTION_REQUEST_RENEWAL:
			*issueType = CERTADD_PARTIAL_RENEWAL;
			return( CRYPT_OK );

		default:
			DEBUG_DIAG(( "Unknown certificate action type %d", 
						 certData[ 0 ] ));
			assert( DEBUG_WARN );
		}

	return( CRYPT_ERROR_NOTFOUND );
	}

/* Sanitise a new certificate of potentially dangerous attributes by 
   creating a template of the disallowed values and setting them as blocked 
   attributes.  For our use we clear all CA and CA-equivalent attributes to 
   prevent users from submitting requests that turn them into CAs */

CHECK_RETVAL \
static int sanitiseCertAttributes( IN_HANDLE const CRYPT_CERTIFICATE iCertificate )
	{
	CRYPT_CERTIFICATE iTemplateCertificate;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	REQUIRES( isHandleRangeValid( iCertificate ) );

	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	iTemplateCertificate = createInfo.cryptHandle;

	/* Add as disallowed values the CA flag and and CA keyUsages, and any 
	   CA-equivalent values, in this case the old Netscape usage flags which 
	   (incredibly) are still used today by some CAs in place of the X.509 
	   keyUsage extension.  We can only do the latter if use of the obsolete 
	   Netscape extensions is enabled, by default these are disabled so they 
	   can still be sneaked in as blob attributes, but only if the user has
	   enabled the (disabled-by-default) 
	   CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES option.
	   
	   The disabling of the CA flag isn't really necessary since the entire
	   basicConstraints extension is disallowed in certificate requests, 
	   we only have it here for belt-and-suspenders security.
	   
	   Note that the blocked-attributes check currently assumes that the 
	   value being checked for non-permitted values is a keyUsage-style 
	   bitflag (since almost no attributes are allowed in certificate
	   requests for security purposes), if any other data types are blocked 
	   then the checking will have to be extended to handle these */
	status = krnlSendMessage( iTemplateCertificate, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_CERTINFO_CA );
#ifdef USE_CERT_OBSOLETE
	if( cryptStatusOK( status ) )
		{
		static const int value = CRYPT_NS_CERTTYPE_SSLCA | \
								 CRYPT_NS_CERTTYPE_SMIMECA | \
								 CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA;

		status = krnlSendMessage( iTemplateCertificate, IMESSAGE_SETATTRIBUTE,
								  ( MESSAGE_CAST ) &value, 
								  CRYPT_CERTINFO_NS_CERTTYPE );
		}
#endif /* USE_CERT_OBSOLETE */
	if( cryptStatusOK( status ) )
		{
		static const int value = KEYUSAGE_CA;

		status = krnlSendMessage( iTemplateCertificate, IMESSAGE_SETATTRIBUTE,
								  ( MESSAGE_CAST ) &value, 
								  CRYPT_CERTINFO_KEYUSAGE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCertificate, IMESSAGE_SETATTRIBUTE,
								  ( MESSAGE_CAST ) &iTemplateCertificate,
								  CRYPT_IATTRIBUTE_BLOCKEDATTRS );
		}
	if( status == CRYPT_ERROR_INVALID )
		{
		/* If the request would have resulted in the creation of an invalid 
		   certificate, report it as an error with the request */
		status = CAMGMT_ARGERROR_REQUEST;
		}
	krnlSendNotifier( iTemplateCertificate, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Make sure that an about-to-be-issued certificate hasn't been added to the 
   certificate store yet.  In theory we wouldn't need to do this since the 
   keyID uniqueness constraint will catch duplicates, however duplicates are 
   allowed for updates and won't automatically be caught for partial adds 
   because the keyID has to be added in a special form to enable the 
   completion of the partial add to work.  What we therefore need to check 
   for is that a partial add (which will add the keyID in special form) 
   won't in the future clash with a keyID in standard form.  The checking 
   for a keyID clash in special form happens automagically through the 
   uniqueness constraint.

   There are two special cases in which the issue can fail during the 
   completion rather than initial add phase, one is during an update (which 
   can't be avoided, since clashes are legal for this and we can't resolve 
   things until the completion phase) and the other is through a race 
   condition caused by the following sequence of updates:

	1: check keyID -> OK
	2: check keyID -> OK
	1: add as ESC1+keyID
	1: issue as keyID
	2: add as ESC1+keyID
	2: issue -> fails

   This condition will be fairly rare.  Note that in neither case are the 
   integrity constraints of the certificate issuing process violated, the 
   only thing that happens is that a failure due to duplicates is detected 
   at a later stage than it normally would be */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkDuplicateAdd( INOUT_PTR DBMS_INFO *dbmsInfo,
							  IN_HANDLE const CRYPT_CERTIFICATE iLocalCertificate, 
							  IN_ENUM( CERTADD ) const CERTADD_TYPE issueType )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	char keyID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int keyIDlength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	
	REQUIRES( isHandleRangeValid( iLocalCertificate ) );
	REQUIRES( isEnumRange( issueType, CERTADD ) );

	/* If it's a normal certificate issue then there's no problem with the
	   potential presence of pseudo-duplicates */
	if( issueType != CERTADD_PARTIAL )
		return( CRYPT_OK );

	/* Check whether a certificate with this keyID is already present in the 
	   store.  Note that this fails open on a (should-never-occur) error, as
	   with other errors of this type it's a coin-toss as to what to do to
	   handle something that should never happen */
	status = getCertKeyID( keyID, ENCODED_DBXKEYID_SIZE, &keyIDlength, 
						   iLocalCertificate );
	if( cryptStatusError( status ) )
		return( status );
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, keyID, keyIDlength );
	status = dbmsQuery( \
				"SELECT certData FROM certificates WHERE keyID = ?",
						NULL, 0, NULL, boundDataPtr, 
						DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CHECK );
	resetErrorInfo( dbmsInfo );
	return( cryptStatusOK( status ) ? CRYPT_ERROR_DUPLICATE : CRYPT_OK );
	}

/* Replace one certificate (usually a partially-issued one) with another 
   (usually its completed form).  The types of operations and their 
   corresponding add-type values are:

	ESC1 -> std		CERTADD_PARTIAL				Completion of partial
	ESC1 -> ESC2	CERTADD_PARTIAL_RENEWAL		First half of renewal
	ESC2 -> std		CERTADD_RENEWAL_COMPLETE	Second half of renewal */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
static int completeCert( INOUT_PTR DBMS_INFO *dbmsInfo,
						 IN_HANDLE const CRYPT_CERTIFICATE iCertificate,
						 IN_HANDLE_OPT const CRYPT_CERTIFICATE iAuthCert,
						 IN_HANDLE_OPT const CRYPT_CERTIFICATE iPkiUser,
						 IN_ENUM( CERTADD ) const CERTADD_TYPE addType,
						 INOUT_PTR ERROR_INFO *errorInfo )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	CERTID_INFO certIDinfo;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	
	REQUIRES( isHandleRangeValid( iCertificate ) );
	REQUIRES( addType == CERTADD_PARTIAL || \
			  addType == CERTADD_PARTIAL_RENEWAL || \
			  addType == CERTADD_RENEWAL_COMPLETE );
	REQUIRES( errorInfo != NULL );

	status = getCertIDinfo( &certIDinfo, iCertificate, iAuthCert, 
							iPkiUser );
	if( cryptStatusError( status ) )
		return( status );
	status = addCert( dbmsInfo, iCertificate, CRYPT_CERTTYPE_CERTIFICATE,
					  ( addType == CERTADD_PARTIAL_RENEWAL ) ? \
						CERTADD_PARTIAL_RENEWAL : CERTADD_NORMAL,
					  DBMS_UPDATE_BEGIN, errorInfo );
	if( cryptStatusOK( status ) )
		{
		char specialCertID[ ENCODED_DBXKEYID_SIZE + 8 ];

		/* Modify the certID to identify an item from part one of a two-part
		   operation */
		REQUIRES( certIDinfo.certIDlength == ENCODED_DBXKEYID_SIZE );
		memcpy( specialCertID, certIDinfo.certID, ENCODED_DBXKEYID_SIZE );
		modifyCertIssueID( specialCertID, ENCODED_DBXKEYID_SIZE,
						   ( addType != CERTADD_RENEWAL_COMPLETE ) ? 
							 IDMOD_CERTISSUE_STD : IDMOD_CERTISSUE_RENEW );
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, specialCertID, 
					  certIDinfo.certIDlength );
		status = dbmsUpdate( 
			"DELETE FROM certificates WHERE certID = ?",
							 boundDataPtr,
							 ( addType == CERTADD_PARTIAL_RENEWAL ) ? \
							 DBMS_UPDATE_COMMIT : DBMS_UPDATE_CONTINUE );
		}
	if( cryptStatusOK( status ) )
		{
		if( addType != CERTADD_PARTIAL_RENEWAL )
			{
			/* This certID is already recorded in the log from the first
			   half of the certificate issue operation so we modify it for 
			   the completion log entry */
			modifyUniqueID( certIDinfo.certID, certIDinfo.certIDlength, 
							IDMOD_CERTISSUE_COMPLETE );
			status = updateCertLogEx( dbmsInfo,
						CRYPT_CERTACTION_CERT_CREATION_COMPLETE,
						certIDinfo.certID, certIDinfo.certIDlength, NULL, 0, 
						certIDinfo.authCertIDptr, certIDinfo.authCertIDlength,
						certIDinfo.pkiUserIDptr, certIDinfo.pkiUserIDlength,
						NULL, 0, DBMS_UPDATE_COMMIT );
			}
		}
	else
		{
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
		}

	/* If the operation failed, record the details.  We've already got a log
	   entry with this ID present so we pass the certID as the reqCertID */
	if( cryptStatusError( status ) )
		{
		updateCertErrorLog( dbmsInfo, status,
							"Certificate creation - completion operation "
							"failed", certIDinfo.certID, 
							certIDinfo.certIDlength );
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "Certificate creation - completion operation "
					 "failed" ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Certificate Issue Functions						*
*																			*
****************************************************************************/

/* Complete a certificate renewal operation by revoking the certificate to 
   be replaced and replacing it with the newly-issued certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int completeCertRenewal( INOUT_PTR DBMS_INFO *dbmsInfo,
						 IN_HANDLE const CRYPT_CERTIFICATE iNewCertificate,
						 IN_HANDLE_OPT const CRYPT_CERTIFICATE iAuthCert,
						 IN_HANDLE_OPT const CRYPT_CERTIFICATE iPkiUser,
						 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CERTIFICATE iOrigCertificate = iAuthCert;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iNewCertificate ) );
	REQUIRES( iAuthCert == CRYPT_UNUSED || isHandleRangeValid( iAuthCert ) );
	REQUIRES( iPkiUser == CRYPT_UNUSED || isHandleRangeValid( iPkiUser ) );
	REQUIRES( errorInfo != NULL );

	/* If we're not being used with a higher-level protocol that provides us 
	   with the authorising certificate, recover it via the certificate 
	   log.  This is a multi-step process, first we have to get the certID
	   of the authorising certificate, then convert it into a binary keyID,
	   and finally call getItemData() on that */
	if( iAuthCert == CRYPT_UNUSED )
		{
		BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ];
		BOUND_DATA *boundDataPtr = boundData;
		BYTE certData[ MAX_QUERY_RESULT_SIZE + 8 ];
		char certID[ ENCODED_DBXKEYID_SIZE + 8 ];
		int certDataLength DUMMY_INIT, certIDlength, dummy;

		status = getKeyID( certID, ENCODED_DBXKEYID_SIZE, &certIDlength, 
						   iNewCertificate, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
		if( cryptStatusOK( status ) )
			{
			initBoundData( boundDataPtr );
			setBoundData( boundDataPtr, 0, certID, certIDlength );
			status = dbmsQuery(
						"SELECT authCertID FROM certLog WHERE certID = ?",
								certData, MAX_QUERY_RESULT_SIZE, 
								&certDataLength, boundDataPtr, 
								DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
			}
		if( cryptStatusOK( status ) )
			{
			if( certDataLength > ENCODED_DBXKEYID_SIZE )
				certDataLength = ENCODED_DBXKEYID_SIZE;
			status = getItemData( dbmsInfo, &iOrigCertificate, &dummy,
								  KEYMGMT_ITEM_PUBLICKEY, CRYPT_IKEYID_CERTID, 
								  certData, certDataLength, 
								  KEYMGMT_FLAG_NONE, errorInfo );
			}
		if( cryptStatusError( status ) )
			{
			/* If the original certificate fetch fails with a notfound error 
			   then this is OK since we may be resuming from a point where 
			   the revocation has already occurred or the certificate may 
			   have already expired or been otherwise replaced, so we just 
			   slide in the new certificate */
			if( status == CRYPT_ERROR_NOTFOUND )
				{
				DEBUG_DIAG(( "Couldn't find original certificate to revoke "
							 "for update request, continuing on the "
							 "assumption that the certificate has been "
							 "otherwise replaced or revoked" ));
				return( completeCert( dbmsInfo, iNewCertificate, CRYPT_UNUSED,
									  iPkiUser, CERTADD_RENEWAL_COMPLETE, 
									  errorInfo ) );
				}
			retExtErr( status, 
					   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
						 "Couldn't get information for the certificate to "
						 "be renewed" ) );
			}
		
		/* We've recovered the authorising certificate, fall through */
		}

	/* Replace the original certificate with the new one */
	status = revokeCertDirect( dbmsInfo, iOrigCertificate, iAuthCert, 
							   iPkiUser, CRYPT_CERTACTION_REVOKE_CERT, 
							   errorInfo );
	if( cryptStatusOK( status ) )
		{
		status = completeCert( dbmsInfo, iNewCertificate, iAuthCert,
							   iPkiUser, CERTADD_RENEWAL_COMPLETE, 
							   errorInfo );
		}
	if( iAuthCert == CRYPT_UNUSED )
		krnlSendNotifier( iOrigCertificate, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Issue a certificate from a certificate request */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 9 ) ) \
int caIssueCert( INOUT_PTR DBMS_INFO *dbmsInfo, 
				 OUT_OPT_HANDLE_OPT CRYPT_CERTIFICATE *iCertificate,
				 IN_HANDLE const CRYPT_CERTIFICATE caKey,
				 IN_HANDLE const CRYPT_CERTIFICATE iCertRequest,
				 IN_HANDLE_OPT const CRYPT_CERTIFICATE iAuthCert,
				 IN_HANDLE_OPT const CRYPT_CERTIFICATE iPkiUser,
				 IN_ENUM( CRYPT_CERTACTION ) \
					const CRYPT_CERTACTION_TYPE action,
				 IN_ENUM_OPT( CERTMGMT_OPTION ) \
					const CERTMGMT_OPTION_TYPE option,
				 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CERTIFICATE iLocalCertificate;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	CERTID_INFO certIDinfo;
	BYTE certData[ MAX_CERT_SIZE + 8 ];
	char issuerID[ ENCODED_DBXKEYID_SIZE + 8 ];
	char reqCertID[ ENCODED_DBXKEYID_SIZE + 8 ];
	CERTADD_TYPE addType = CERTADD_NORMAL, issueType;
	int certDataLength DUMMY_INIT, issuerIDlength;
	int reqCertIDlength DUMMY_INIT, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( ( iCertificate == NULL ) || \
			isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( isHandleRangeValid( caKey ) );
	REQUIRES( isHandleRangeValid( iCertRequest ) );
	REQUIRES( iAuthCert == CRYPT_UNUSED || isHandleRangeValid( iAuthCert ) );
	REQUIRES( iPkiUser == CRYPT_UNUSED || isHandleRangeValid( iPkiUser ) );
	REQUIRES( ( action == CRYPT_CERTACTION_ISSUE_CERT && \
				option == CERTMGMT_OPTION_NONE ) || \
			  action == CRYPT_CERTACTION_CERT_CREATION );
			  /* A one-step certificate issue can't have any partial-issue
			     options associated with it */
	REQUIRES( isEnumRangeOpt( option, CERTMGMT_OPTION ) );
	REQUIRES( errorInfo != NULL );

	/* Clear return value */
	if( iCertificate != NULL )
		*iCertificate = CRYPT_ERROR;

	/* Extract the information that we need from the certificate request and
	   optional authorising certificate */
	status = getCertIssueType( dbmsInfo, iCertRequest, &issueType, FALSE );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( reqCertID, ENCODED_DBXKEYID_SIZE, 
						   &reqCertIDlength, iCertRequest, 
						   CRYPT_CERTINFO_FINGERPRINT_SHA1 );
		}
	if( cryptStatusError( status ) )
		{
		if( cryptArgError( status ) )
			status = CAMGMT_ARGERROR_REQUEST;
		retExtArg( status, 
				   ( status, errorInfo, 
					 "Couldn't extract certificate request information "
					 "needed to issue certificate" ) );
		}
	ENSURES( ( option == CERTMGMT_OPTION_RENEWAL && \
			   issueType == CERTADD_PARTIAL_RENEWAL ) || \
			 ( option != CERTMGMT_OPTION_RENEWAL && \
			   issueType != CERTADD_PARTIAL_RENEWAL ) );

	/* We're ready to perform the certificate issue transaction.  First we 
	   turn the request into a certificate.  Note that when working with PKI
	   protocols like CMP the encoded request data is that of the original
	   request but the actual information held in the request has been 
	   augmented with any required PKI user information via
	   session/cmp_rdmsg.c:readRequestBody().  This means that any further
	   checks that need to be done have to be done on the final certificate
	   which is created from the (pkiUser-augmented) information held in the
	   request, rather than the encoded request data */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	iLocalCertificate = createInfo.cryptHandle;
	status = krnlSendMessage( iLocalCertificate, IMESSAGE_SETATTRIBUTE,
							  ( MESSAGE_CAST ) &iCertRequest,
							  CRYPT_CERTINFO_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't create certificate from certificate request "
				  "data" ) );
		}

	/* Sanitise the new certificate of potentially dangerous attributes */
	status = sanitiseCertAttributes( iLocalCertificate );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		retExtArg( status, 
				   ( status, errorInfo, 
					 "Certificate request contains attributes that would "
					 "result in the creation of a CA rather than a normal "
					 "user certificate" ) );
		}

	/* Finally, sign the certificate */
	status = krnlSendMessage( iLocalCertificate, IMESSAGE_CRT_SIGN, NULL,
							  caKey );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		if( status == CRYPT_ARGERROR_VALUE )
			status = CAMGMT_ARGERROR_CAKEY;
		retExtArg( status, 
				   ( status, errorInfo, 
					 "Couldn't sign certificate created from certificate "
					 "request" ) );
		}

	/* We've now got the unified information in the request (see the comment
	   above) in the certificate, perform any additional checks, in this 
	   case that the subject name in a certificate renewal matches the 
	   subject name in the authorising certificate, which is the one that's 
	   being renewed.  As usual the spec (CMP) is silent on what the 
	   requirements for a renewed certificate are so we have to invent our
	   own, which is that at least the subject name should match from
	   renewing -> renewed certificate.  We could perhaps also check for
	   altName matches and other things, but if the user really wants to
	   change anything they like then they can just submit exactly the same
	   request as a CMP cr rather than a CMP kur and no checks will be 
	   performed (which they could also do to change the subject name), so
	   we just perform the subject name check in order to at least have 
	   something that separates a cr from a kur.
	   
	   This also serves a secondary purpose, by verifying that the iAuthCert 
	   corresponds to the newly-issued certificate, in other words that it's
	   the renewing certificate, then when we do the caIssueCertComplete() 
	   below we can revoke the iAuthCert as the renewing certificate */
	if( option == CERTMGMT_OPTION_RENEWAL )
		{
		MESSAGE_DATA msgData;
		DYNBUF subjectDB;

		REQUIRES( isHandleRangeValid( iAuthCert ) );
		
		/* Get the name in the authorising certificate (the one requesting 
		   the renewal) and make sure that it matches the one in the renewed 
		   certificate */
		status = dynCreate( &subjectDB, iAuthCert, 
							CRYPT_IATTRIBUTE_SUBJECT );
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, dynData( subjectDB ), 
							dynLength( subjectDB ) );
			status = krnlSendMessage( iLocalCertificate, IMESSAGE_COMPARE,
									  &msgData, MESSAGE_COMPARE_SUBJECT );
			dynDestroy( &subjectDB );
			}
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
			retExtArg( CRYPT_ERROR_INVALID, 
					   ( CRYPT_ERROR_INVALID, errorInfo, 
						 "Name in the requested renewed certificate doesn't "
						 "match the name in the certificate requesting "
						 "renewal" ) );
			}
		}

	/* Extract the information that we need from the newly-created 
	   certificate */
	status = getCertIDinfo( &certIDinfo, iLocalCertificate, iAuthCert, 
							iPkiUser );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( issuerID, ENCODED_DBXKEYID_SIZE, &issuerIDlength, 
						   iLocalCertificate,
						   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		}
	if( cryptStatusOK( status ) )
		{
		status = extractCertData( iLocalCertificate, 
								  CRYPT_CERTFORMAT_CERTIFICATE, certData, 
								  MAX_CERT_SIZE, &certDataLength );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't extract new certificate data to add to "
				  "certificate store" ) );
		}

	/* If we're doing a partial certificate creation, handle the 
	   complexities created by things like certificate renewals that create 
	   pseudo-duplicates while the update is taking place */
	if( action == CRYPT_CERTACTION_CERT_CREATION )
		{
		status = checkDuplicateAdd( dbmsInfo, iLocalCertificate, issueType );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
			retExt( status, 
					( status, errorInfo, 
					  "Certificate already exists in certificate store" ) );
			}

		/* This is a partial add, make sure that the certificate is added in 
		   the appropriate manner */
		addType = CERTADD_PARTIAL;
		}

	/* Update the certificate store */
	status = addCert( dbmsInfo, iLocalCertificate, CRYPT_CERTTYPE_CERTIFICATE,
					  addType, DBMS_UPDATE_BEGIN, errorInfo );
	if( cryptStatusOK( status ) )
		{
		status = updateCertLogEx( dbmsInfo, action, certIDinfo.certID, 
						certIDinfo.certIDlength, reqCertID, reqCertIDlength, 
						certIDinfo.authCertIDptr, certIDinfo.authCertIDlength, 
						certIDinfo.pkiUserIDptr, certIDinfo.pkiUserIDlength, 
						certData, certDataLength, DBMS_UPDATE_CONTINUE );
		}
	if( cryptStatusOK( status ) )
		{
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, reqCertID, reqCertIDlength );
		status = dbmsUpdate( 
			"DELETE FROM certRequests WHERE certID = ?",
							 boundDataPtr, DBMS_UPDATE_COMMIT );
		}
	else
		{
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
		}

	/* If the operation failed, record the details */
	if( cryptStatusError( status ) )
		{
		updateCertErrorLog( dbmsInfo, status,
							( action == CRYPT_CERTACTION_ISSUE_CERT ) ? \
								"Certificate issue operation failed" : \
								"Certificate creation operation failed",
							reqCertID, reqCertIDlength );
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 ( action == CRYPT_CERTACTION_ISSUE_CERT ) ? \
						"Certificate issue operation failed" : \
						"Certificate creation operation failed" ) );
		}

	/* The certificate has been successfully issued, return it to the caller 
	   if necessary */
	if( iCertificate != NULL )
		*iCertificate = iLocalCertificate;
	else
		{
		/* The caller isn't interested in the certificate, destroy it */
		krnlSendNotifier( iLocalCertificate, IMESSAGE_DECREFCOUNT );
		}
	return( CRYPT_OK );
	}

/* Complete a previously-started certificate issue.  This is the completion 
   of the process started in caIssueCert(), so we don't need to re-check
   the things that were already checked there, for example the iAuthCert ->
   iCertificate correspondence for a renewal */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
int caIssueCertComplete( INOUT_PTR DBMS_INFO *dbmsInfo, 
						 IN_HANDLE const CRYPT_CERTIFICATE iCertificate,
						 IN_HANDLE_OPT const CRYPT_CERTIFICATE iAuthCert,
						 IN_HANDLE_OPT const CRYPT_CERTIFICATE iPkiUser,
						 IN_ENUM( CRYPT_CERTACTION ) \
							const CRYPT_CERTACTION_TYPE action,
						 INOUT_PTR ERROR_INFO *errorInfo )
	{
	int status;
	
	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCertificate ) );
	REQUIRES( iAuthCert == CRYPT_UNUSED || isHandleRangeValid( iAuthCert ) );
	REQUIRES( iPkiUser == CRYPT_UNUSED || isHandleRangeValid( iPkiUser ) );
	REQUIRES( action == CRYPT_CERTACTION_CERT_CREATION_COMPLETE || \
			  action == CRYPT_CERTACTION_CERT_CREATION_DROP || \
			  action == CRYPT_CERTACTION_CERT_CREATION_REVERSE );
	REQUIRES( errorInfo != NULL );

	/* If we're completing the certificate issue process, replace the
	   incomplete certificate with the completed one and exit */
	if( action == CRYPT_CERTACTION_CERT_CREATION_COMPLETE )
		{
		CERTADD_TYPE issueType;

		status = getCertIssueType( dbmsInfo, iCertificate, &issueType, TRUE );
		if( cryptStatusError( status ) )
			{
			retExt( status, 
					( status, errorInfo, 
					  "Couldn't get original certificate issue type to "
					  "complete certificate issue operation" ) );
			}
		status = completeCert( dbmsInfo, iCertificate, iAuthCert, iPkiUser, 
							   issueType, errorInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* If we're doing a certificate renewal, complete the multi-phase 
		   update required to replace an existing certificate.  We know that
		   the iAuthCert that requested the renewal is the one being 
		   renewed via the check in caIssueCert() above, so this is the one
		   that gets revoked */
		if( issueType == CERTADD_PARTIAL_RENEWAL )
			{
			return( completeCertRenewal( dbmsInfo, iCertificate, iAuthCert, 
										 iPkiUser, errorInfo ) );
			}

		return( CRYPT_OK );
		}

	/* If we're abandoning the certificate issue process, delete the
	   incomplete certificate and exit */
	if( action == CRYPT_CERTACTION_CERT_CREATION_DROP )
		{
		CERTID_INFO certIDinfo;
		BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
		char incompleteCertID[ ENCODED_DBXKEYID_SIZE + 8 ];

		/* Extract the information that we need from the certificates */
		status = getCertIDinfo( &certIDinfo, iCertificate, iAuthCert, 
								iPkiUser );
		if( cryptStatusError( status ) )
			return( status );

		/* Modify the certID to identify an item from part one of a two-part 
		   operation, then delete the object with that ID */
		REQUIRES( certIDinfo.certIDlength == ENCODED_DBXKEYID_SIZE );
		memcpy( incompleteCertID, certIDinfo.certID, ENCODED_DBXKEYID_SIZE );
		modifyCertIssueID( incompleteCertID, ENCODED_DBXKEYID_SIZE, 
						   IDMOD_CERTISSUE_STD );
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, incompleteCertID, 
					  ENCODED_DBXKEYID_SIZE );
		status = dbmsUpdate( 
			"DELETE FROM certificates WHERE certID = ?",
							 boundDataPtr, DBMS_UPDATE_BEGIN );
		if( cryptStatusOK( status ) )
			{
			/* This certID is already recorded in the log from the first
			   half of the certificate issue operation so we modify it for 
			   the drop log entry */
			modifyUniqueID( certIDinfo.certID, certIDinfo.certIDlength, 
							IDMOD_CERTISSUE_COMPLETE );
			status = updateCertLogEx( dbmsInfo, 
						CRYPT_CERTACTION_CERT_CREATION_DROP, 
						certIDinfo.certID, certIDinfo.certIDlength, NULL, 0, 
						certIDinfo.authCertIDptr, certIDinfo.authCertIDlength, 
						certIDinfo.pkiUserIDptr, certIDinfo.pkiUserIDlength, 
						NULL, 0, DBMS_UPDATE_COMMIT );
			}
		else
			{
			/* Something went wrong, abort the transaction */
			dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
			}
		if( cryptStatusOK( status ) )
			return( CRYPT_OK );

		/* The drop operation failed, record the details and fall back to a
		   straight delete.  We've already got a log entry with this ID 
		   present so we pass the certID as the reqCertID */
		updateCertErrorLog( dbmsInfo, status,
							"Certificate creation - drop operation failed, "
							"performing straight delete", 
							certIDinfo.certID, certIDinfo.certIDlength );
		status = dbmsUpdate( 
			"DELETE FROM certificates WHERE certID = ?",
							 boundDataPtr, DBMS_UPDATE_NORMAL );
		if( cryptStatusError( status ) )
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );
			retExtErr( status, 
					   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
						 "Certificate creation - drop operation failed" ) );
			}
		return( CRYPT_OK );
		}

	/* We're reversing a certificate creation as a compensating transaction 
	   for an aborted certificate issue, we need to explicitly revoke the 
	   certificate rather than just deleting it */
	ENSURES( action == CRYPT_CERTACTION_CERT_CREATION_REVERSE );

	return( revokeCertDirect( dbmsInfo, iCertificate, iAuthCert, iPkiUser,
							  CRYPT_CERTACTION_CERT_CREATION_REVERSE, 
							  errorInfo ) );
	}
#endif /* USE_DBMS */
