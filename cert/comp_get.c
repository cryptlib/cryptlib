/****************************************************************************
*																			*
*							Get Certificate Components						*
*						Copyright Peter Gutmann 1997-2016					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_CERTIFICATES

/****************************************************************************
*																			*
*							Get Certificate Information						*
*																			*
****************************************************************************/

/* Find an attribute in an attribute list, either in the overall certificate 
   object attribute list or a per-entry attribute list.  This can also 
   return entries with two special-case properties: 
   
	ATTRIBUTE_PROPERTY_DEFAULTVALUE: The field has a default value and isn't 
		present in the list, but some other field in the same attribute is 
		present.  For example if CRYPT_CERTINFO_ISSUINGDIST_FULLNAME were 
		present in the attribute list than an attempt to read 
		CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL, which is declared 'DEFAULT 
		FALSE', would return an entry with this property.

	ATTRIBUTE_PROPERTY_COMPLETEATTRIBUTE: The field is an identifier for a
		complete attribute, e.g. CRYPT_CERTINFO_AUTHORITYINFOACCESS, for 
		which only the individual CRYPT_CERTINFO_AUTHORITYINFO_xyz fields 
		can be present */

CHECK_RETVAL_DATAPTR STDC_NONNULL_ARG( ( 1 ) ) \
DATAPTR_ATTRIBUTE findAttributeComponent( IN_PTR const CERT_INFO *certInfoPtr,
										  IN_ATTRIBUTE \
											const CRYPT_ATTRIBUTE_TYPE certInfoType )
	{
#ifdef USE_CERTREV
	const CERT_REV_INFO *certRevInfo;
	DATAPTR_ATTRIBUTE attributePtr;
	REVOCATION_INFO *currentRevocation;
#endif /* USE_CERTREV */

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES_D( sanityCheckCert( certInfoPtr ) );
	REQUIRES_D( isEnumRange( certInfoType, CRYPT_ATTRIBUTE ) );

	/* If it's just a general certificate attribute, return it to the 
	   caller */
	if( !isRevocationEntryComponent( certInfoType ) )
		{
		return( findAttributeFieldEx( certInfoPtr->attributes, 
									  certInfoType ) );
		}

	/* It's an attribute that's normally present in a CRL or CRL-equivalent
	   object, however it may also be present in a revocation request for 
	   which attributes work like they do for general certificates */
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		return( findAttributeFieldEx( certInfoPtr->attributes, 
									  certInfoType ) );
		}

#ifdef USE_CERTVAL
	/* It's a per-entry attribute, if it's an RTCS per-entry attribute get 
	   the attribute from the currently selected entry */
	if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
		certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
		{
		CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;
		VALIDITY_INFO *validityInfoPtr;

		validityInfoPtr = DATAPTR_GET( certValInfo->currentValidity );
		if( validityInfoPtr == NULL )
			return( DATAPTR_NULL );
		return( findAttributeFieldEx( validityInfoPtr->attributes, 
									  certInfoType ) );
		}
#endif /* USE_CERTVAL */

#ifdef USE_CERTREV
	ENSURES_D( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
			   certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			   certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE || \
			   certInfoPtr->type == CRYPT_ICERTTYPE_REVINFO );

	/* It's a CRL or OCSP per-entry attribute, get the attribute from the 
	   currently selected entry */
	certRevInfo = certInfoPtr->cCertRev;
	currentRevocation = DATAPTR_GET( certRevInfo->currentRevocation );
	if( currentRevocation == NULL )
		return( DATAPTR_NULL );
	attributePtr = findAttributeFieldEx( currentRevocation->attributes, 
										 certInfoType );
	if( DATAPTR_ISNULL( attributePtr ) && \
		certInfoType == CRYPT_CERTINFO_CRLREASON )
		{
		/* Revocation reason codes are actually a single range of values 
		   spread across two different extensions so if we don't find the 
		   value as a straight cRLReason then we try again for a 
		   cRLExtReason.  If we've been specifically asked for a 
		   cRLExtReason then we don't go the other way because the caller 
		   (presumably) specifically wants the extended reason code */
		attributePtr = findAttributeFieldEx( currentRevocation->attributes,
											 CRYPT_CERTINFO_CRLEXTREASON );
		}

	return( attributePtr );
#else
	return( DATAPTR_NULL );
#endif /* USE_CERTREV */
	}

/* Get a certificate component */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int getCertAttributeComponent( const CERT_INFO *certInfoPtr,
									  IN_ATTRIBUTE \
										const CRYPT_ATTRIBUTE_TYPE certInfoType,
									  OUT_INT_Z int *value )
	{
	DATAPTR_ATTRIBUTE attributePtr;

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( value, sizeof( int ) ) );

	REQUIRES( isEnumRange( certInfoType, CRYPT_ATTRIBUTE ) );

	/* Clear return values */
	*value = 0;

	/* Try and find this attribute in the attribute list */
	attributePtr = findAttributeComponent( certInfoPtr, certInfoType );
	if( DATAPTR_ISNULL( attributePtr ) )
		return( CRYPT_ERROR_NOTFOUND );

	/* If this is a non-present field with a default value in an attribute 
	   for which some other field is present (e.g. if we're trying to read
	   CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY, which is declared
	   DEFAULT FALSE, and CRYPT_CERTINFO_ISSUINGDIST_FULLNAME is present)
	   then we regard any default fields in the same attribute to be
	   (pseudo)-present, so we return the default value */
	if( checkAttributeProperty( attributePtr, 
								ATTRIBUTE_PROPERTY_DEFAULTVALUE ) )
		{
		int defaultValue, status;
		
		status = defaultValue = getDefaultFieldValue( certInfoType );
		if( cryptStatusError( status ) )
			return( status );

		*value = defaultValue;
		return( CRYPT_OK );
		}

	/* If we've been given the ID for a complete attribute (e.g. 
	   CRYPT_CERTINFO_AUTHORITYINFOACCESS, for which only the individual 
	   CRYPT_CERTINFO_AUTHORITYINFO_xyz fields can be present), return a 
	   boolean value indicating that the overall attribute is present */
	if( checkAttributeProperty( attributePtr, 
								ATTRIBUTE_PROPERTY_COMPLETEATRIBUTE ) )
		{
		*value = TRUE;
		return( CRYPT_OK );
		}

	/* Get the attribute component value */
	return( getAttributeDataValue( attributePtr, value ) );
	}

/* Create a copy of a certificate object for external use.  This is used 
   principally to sanitise internal certificate objects, for example if 
   they're attached to a private key or for internal use only.  Since the 
   object can be either a standalone certificate or a complete certificate 
   chain we have to process it somewhat indirectly rather than just 
   instantiating a new certificate from the encoded certificate data.

   It's also used to convert to/from data-only certificates, for example to 
   convert from a stored data-only certificate to a full certificate capable 
   of being used for signature checking, this is easier than trying to 
   retroactively attach a public-key context to a data-only certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getCertCopy( IN_PTR const CERT_INFO *certInfoPtr, 
						OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertCopy,
						IN_BOOL const BOOLEAN isDataOnlyCert )
	{
	const CRYPT_CERTFORMAT_TYPE formatType = \
		( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE ) ? \
		CRYPT_CERTFORMAT_CERTIFICATE : CRYPT_CERTFORMAT_CERTCHAIN;
	ERROR_INFO localErrorInfo;
	DYNBUF certDB;
	int status;

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO  ) ) );
	assert( isWritePtr( iCertCopy, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );
	REQUIRES( isBooleanValue( isDataOnlyCert ) );

	/* Clear return value */
	*iCertCopy = CRYPT_ERROR;

	/* Export and reimport the certificate as a new object.  Since this is 
	   just a straight export-reimport we don't do anything with the error 
	   information since it's both unlikely to occur and unlikely to prove 
	   useful */
	clearErrorInfo( &localErrorInfo );
	status = dynCreateCert( &certDB, certInfoPtr->objectHandle, 
							formatType );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		setMessageCreateObjectIndirectInfoEx( &createInfo, dynData( certDB ), 
							dynLength( certDB ), certInfoPtr->type,
							isDataOnlyCert ? KEYMGMT_FLAG_DATAONLY_CERT : \
											 KEYMGMT_FLAG_NONE,
							&localErrorInfo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT, 
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		dynDestroy( &certDB );
		if( cryptStatusOK( status ) )
			*iCertCopy = createInfo.cryptHandle;
		}

	return( status );
	}

/****************************************************************************
*																			*
*							Get a Certificate Component						*
*																			*
****************************************************************************/

/* Get a certificate component */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int getCertComponent( INOUT_PTR CERT_INFO *certInfoPtr,
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  OUT_INT_Z int *certInfo )
	{
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( certInfo, sizeof( int ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );
	REQUIRES( isAttribute( certInfoType ) || \
			  isInternalAttribute( certInfoType ) );

	/* Clear return value */
	*certInfo = 0;

	/* If it's a GeneralName or DN component, return it.  These are 
	   special-case attribute values so they have to come before the 
	   general attribute-handling code */
	if( isGeneralNameSelectionComponent( certInfoType ) )
		{
		SELECTION_STATE savedState;

		/* Determine whether the given component is present or not.  This
		   has a somewhat odd status return since it returns the found/
		   notfound status in the return code as well as the returned value,
		   which mirrors the behaviour when reading extension-present
		   pseudo-attributes */
		saveSelectionState( savedState, certInfoPtr );
		status = selectGeneralName( certInfoPtr, certInfoType, 
									MAY_BE_ABSENT );
		if( cryptStatusOK( status ) )
			{
			status = selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE, 
										MUST_BE_PRESENT );
			}
		restoreSelectionState( savedState, certInfoPtr );
		*certInfo = cryptStatusOK( status ) ? TRUE : FALSE;

		return( status );
		}
	if( isGeneralNameComponent( certInfoType ) )
		{
		SELECTION_STATE savedState;

		/* Find the requested GeneralName component and return an 
		   indication of its presence to the caller, with the same return-
		   status indication as above.  Since selectGeneralNameComponent() 
		   changes the current selection within the GeneralName, we save the 
		   selection state around the call */
		saveSelectionState( savedState, certInfoPtr );
		status = selectGeneralNameComponent( certInfoPtr, certInfoType );
		restoreSelectionState( savedState, certInfoPtr );
		*certInfo = cryptStatusOK( status ) ? TRUE : FALSE;

		return( status );
		}

	/* If it's standard certificate or CMS attribute, return it */
	if( isValidExtension( certInfoType ) )
		{
		return( getCertAttributeComponent( certInfoPtr, certInfoType,
										   certInfo ) );
		}

	/* If it's anything else, handle it specially */
	switch( certInfoType )
		{
		case CRYPT_CERTINFO_SELFSIGNED:
			*certInfo = TEST_FLAG( certInfoPtr->flags, 
								   CERT_FLAG_SELFSIGNED ) ? TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_IMMUTABLE:
			*certInfo = ( certInfoPtr->certificate != NULL ) ? TRUE: FALSE;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_XYZZY:
			{
			DATAPTR_ATTRIBUTE attributePtr;

			/* Check for the presence of the XYZZY policy OID */
			attributePtr = findAttributeField( certInfoPtr->attributes,
											   CRYPT_CERTINFO_CERTPOLICYID,
											   CRYPT_ATTRIBUTE_NONE );
			if( DATAPTR_ISSET( attributePtr ) )
				{
				void *policyOidPtr;
				int policyOidLength;

				status = getAttributeDataPtr( attributePtr, &policyOidPtr, 
											  &policyOidLength );
				if( cryptStatusOK( status ) && \
					matchOID( policyOidPtr, policyOidLength, 
							  OID_CRYPTLIB_XYZZYCERT ) )
					{
					*certInfo = TRUE;
					return( CRYPT_OK );
					}
				}

			/* It's not a XYZZY certificate */
			*certInfo = FALSE;
			return( CRYPT_OK );
			}

		case CRYPT_CERTINFO_CERTTYPE:
			*certInfo = certInfoPtr->type;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_CURRENT_CERTIFICATE:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_INSTANCE:
			{
			CRYPT_ATTRIBUTE_TYPE infoID;

			/* The subject and issuer DNs are treated as pseudo-attributes 
			   for manipulation purposes, so if these are selected 
			   (indicated by there being no attribute selected since 
			   selecting the pseudo-attribute DNs deselects any actual
			   attributes) we have to provide special-case handling for 
			   them */
			if( DATAPTR_ISNULL( certInfoPtr->attributeCursor ) )
				{
				const SELECTION_INFO *currentSelection = \
							&certInfoPtr->currentSelection;

				switch( certInfoType )
					{
					case CRYPT_CERTINFO_CURRENT_CERTIFICATE:
					case CRYPT_ATTRIBUTE_CURRENT_GROUP:
						/* These selection types don't apply to DNs */
						break;

					case CRYPT_ATTRIBUTE_CURRENT:
						if( isSubjectNameSelected( certInfoPtr) )
							{
							*certInfo = CRYPT_CERTINFO_SUBJECTNAME;
							return( CRYPT_OK );
							}
						if( isIssuerNameSelected( certInfoPtr ) )
							{
							*certInfo = CRYPT_CERTINFO_ISSUERNAME;
							return( CRYPT_OK );
							}
						break;

					case CRYPT_ATTRIBUTE_CURRENT_INSTANCE:
						if( currentSelection->dnComponent != CRYPT_ATTRIBUTE_NONE )
							{
							*certInfo = currentSelection->dnComponent;
							return( CRYPT_OK );
							}
						break;

					default:
						retIntError();
					}
				return( CRYPT_ERROR_NOTINITED );
				}

			/* The current component and field are usually the same thing 
			   since a component is one of a set of entries in a multivalued 
			   field, however in the case of complex subtypes (attribute ->
			   generalName -> generalName field) they can be distinct 
			   values.  To handle this we try for a field ID and if 
			   that's not available return the component ID */
			switch( certInfoType )
				{
				case CRYPT_ATTRIBUTE_CURRENT_GROUP:
					status = getAttributeIdInfo( certInfoPtr->attributeCursor, 
												 &infoID, NULL, NULL );
					break;

				case CRYPT_CERTINFO_CURRENT_CERTIFICATE:
				case CRYPT_ATTRIBUTE_CURRENT:
					status = getAttributeIdInfo( certInfoPtr->attributeCursor, 
												 NULL, &infoID, NULL );
					break;

				case CRYPT_ATTRIBUTE_CURRENT_INSTANCE:
					status = getAttributeIdInfo( certInfoPtr->attributeCursor, 
												 NULL, NULL, &infoID );
					if( cryptStatusError( status ) )
						{
						status = getAttributeIdInfo( certInfoPtr->attributeCursor, 
													 NULL, &infoID, NULL );
						}
					break;

				default:
					retIntError();
				}
			if( cryptStatusOK( status ) )
				*certInfo = infoID;
			return( status );
			}

		case CRYPT_CERTINFO_TRUSTED_USAGE:
			if( certInfoPtr->cCertCert->trustedUsage == CRYPT_ERROR )
				return( CRYPT_ERROR_NOTFOUND );
			*certInfo = certInfoPtr->cCertCert->trustedUsage;
 			return( CRYPT_OK );

		case CRYPT_CERTINFO_TRUSTED_IMPLICIT:
			status = krnlSendMessage( certInfoPtr->ownerHandle,
									  IMESSAGE_USER_TRUSTMGMT,
									  &certInfoPtr->objectHandle,
									  MESSAGE_TRUSTMGMT_CHECK );
			*certInfo = cryptStatusOK( status ) ? TRUE : FALSE;
			return( CRYPT_OK );

#ifdef USE_CERTREV
		case CRYPT_CERTINFO_SIGNATURELEVEL:
			*certInfo = certInfoPtr->cCertRev->signatureLevel;
			return( CRYPT_OK );
#endif /* USE_CERTREV */

		case CRYPT_CERTINFO_VERSION:
			*certInfo = certInfoPtr->version;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_ISSUERNAME:
		case CRYPT_CERTINFO_SUBJECTNAME:
			{
			const DATAPTR_DN dnPtr = \
					( certInfoType == CRYPT_CERTINFO_ISSUERNAME ) ? \
					certInfoPtr->issuerName : certInfoPtr->subjectName;

			if( DATAPTR_ISNULL( dnPtr ) ) 
				{
				*certInfo = FALSE;
				return( CRYPT_ERROR_NOTFOUND );
				}
			*certInfo = TRUE;
			return( CRYPT_OK );
			}

#ifdef USE_CERTREV
		case CRYPT_CERTINFO_REVOCATIONSTATUS:
			{
			const CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
			const REVOCATION_INFO *revInfoPtr;

			revInfoPtr = DATAPTR_GET( certRevInfo->currentRevocation );
			if( revInfoPtr == NULL )
				revInfoPtr = DATAPTR_GET( certRevInfo->revocations );
			if( revInfoPtr == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			*certInfo = revInfoPtr->status;
			return( CRYPT_OK );
			}
#endif /* USE_CERTREV */

#ifdef USE_CERTVAL
		case CRYPT_CERTINFO_CERTSTATUS:
			{
			const CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;
			const VALIDITY_INFO *validityInfoPtr;

			if( DATAPTR_ISSET( certValInfo->currentValidity ) )
				{
				validityInfoPtr = DATAPTR_GET( certValInfo->currentValidity );
				ENSURES( validityInfoPtr != NULL );
				}
			else
				validityInfoPtr = DATAPTR_GET( certValInfo->validityInfo );
			if( validityInfoPtr == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			*certInfo = validityInfoPtr->extStatus;
			return( CRYPT_OK );
			}
#endif /* USE_CERTVAL */

#ifdef USE_PKIUSER
		case CRYPT_CERTINFO_PKIUSER_RA:
			*certInfo = certInfoPtr->cCertUser->isRA;
			return( CRYPT_OK );
#endif /* USE_PKIUSER */

		case CRYPT_IATTRIBUTE_CERTHASHALGO:
			*certInfo = certInfoPtr->cCertCert->hashAlgo;
			return( CRYPT_OK );

#ifdef USE_CERTREQ
		case CRYPT_IATTRIBUTE_REQFROMRA:
			*certInfo = certInfoPtr->cCertReq->requestFromRA;
			return( CRYPT_OK );
#endif /* USE_CERTREQ */

		case CRYPT_IATTRIBUTE_CERTCOPY:
			{
			CRYPT_CERTIFICATE certCopy;

			status = getCertCopy( certInfoPtr, &certCopy, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			*certInfo = certCopy;
			return( CRYPT_OK );
			}
		case CRYPT_IATTRIBUTE_CERTCOPY_DATAONLY:
			{
			CRYPT_CERTIFICATE certCopy;

			status = getCertCopy( certInfoPtr, &certCopy, TRUE );
			if( cryptStatusError( status ) )
				return( status );
			*certInfo = certCopy;
			return( CRYPT_OK );
			}
		}

	retIntError();
	}
#endif /* USE_CERTIFICATES */
