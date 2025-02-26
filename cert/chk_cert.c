/****************************************************************************
*																			*
*						  Certificate Checking Routines						*
*						Copyright Peter Gutmann 1997-2015					*
*																			*
****************************************************************************/

#include <ctype.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_CERTIFICATES

/* Size check for MAX_POLICY_SIZE, which corresponds to MAX_OID_SIZE but
   this isn't visible at the point where MAX_POLICY_SIZE is defined */

#if defined( USE_CERTLEVEL_PKIX_FULL ) && ( MAX_POLICY_SIZE != MAX_OID_SIZE )
  #error MAX_POLICY_SIZE must be the same as MAX_OID_SIZE
#endif /* MAX_POLICY_SIZE != MAX_OID_SIZE */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#ifdef USE_CERTLEVEL_PKIX_PARTIAL

/* Check whether disallowed CA-only attributes are present in a (non-CA) 
   attribute list.  We report the error as a constraint derived from the CA
   flag rather than the attribute itself since it's the absence of the flag 
   that renders the presence of the attribute invalid */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 3, 4 ) ) \
static BOOLEAN invalidAttributesPresent( IN_DATAPTR \
											const DATAPTR_ATTRIBUTE attributePtr,
										 IN_BOOL const BOOLEAN isIssuer,
										 OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
											CRYPT_ATTRIBUTE_TYPE *errorLocus, 
										 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
											CRYPT_ERRTYPE_TYPE *errorType )
	{
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES_B( sanityCheckAttribute( attributePtr ) );
	REQUIRES_B( isBooleanValue( isIssuer ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Check for entire disallowed attributes */
#ifdef USE_CERTLEVEL_PKIX_FULL
	if( checkAttributePresent( attributePtr, \
							   CRYPT_CERTINFO_NAMECONSTRAINTS ) || \
		checkAttributePresent( attributePtr, \
							   CRYPT_CERTINFO_POLICYCONSTRAINTS ) || \
		checkAttributePresent( attributePtr, \
							   CRYPT_CERTINFO_INHIBITANYPOLICY ) || \
		checkAttributePresent( attributePtr, \
							   CRYPT_CERTINFO_POLICYMAPPINGS ) )
		{
		setErrorValues( CRYPT_CERTINFO_CA, isIssuer ? \
						CRYPT_ERRTYPE_ISSUERCONSTRAINT : \
						CRYPT_ERRTYPE_CONSTRAINT );
		return( TRUE );
		}
#endif /* USE_CERTLEVEL_PKIX_FULL */

	/* Check for a particular field of an attribute that's invalid rather 
	   than the entire attribute (the specific exclusion of path-length 
	   constraints in basicConstraints was introduced in RFC 3280) */
	if( checkAttributeFieldPresent( attributePtr, \
									CRYPT_CERTINFO_PATHLENCONSTRAINT ) )
		{
		setErrorValues( CRYPT_CERTINFO_CA, isIssuer ? \
						CRYPT_ERRTYPE_ISSUERCONSTRAINT : \
						CRYPT_ERRTYPE_CONSTRAINT );
		return( TRUE );
		}

	return( FALSE );
	}
#endif /* USE_CERTLEVEL_PKIX_PARTIAL */

#ifdef USE_CERTLEVEL_PKIX_FULL

/* Check whether a certificate is a PKIX path-kludge certificate, which 
   allows extra certificates to be kludged into the path without violating 
   any constraints */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN isPathKludge( IN_PTR const CERT_INFO *certInfoPtr )
	{
	int value, status;

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Perform a quick-reject check for certificates that haven't been 
	   identified by the certificate chain processing code as path-kludge 
	   certificates */
	if( !TEST_FLAG( certInfoPtr->flags, CERT_FLAG_PATHKLUDGE ) )
		return( FALSE );

	/* Only CA path-kludge certificates are exempt from constraint 
	   enforcement.  Non-CA path kludges shouldn't ever occur but who knows 
	   what other weirdness future RFCs will dream up, so we perform an 
	   explicit check here */
	status = getAttributeFieldValue( certInfoPtr->attributes, 
									 CRYPT_CERTINFO_CA, 
									 CRYPT_ATTRIBUTE_NONE, &value );
	return( ( cryptStatusOK( status ) && value ) ? TRUE : FALSE );
	}
#endif /* USE_CERTLEVEL_PKIX_FULL */

/****************************************************************************
*																			*
*								General Checks								*
*																			*
****************************************************************************/

/* Check the certificate version number */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int checkVersion( INOUT_PTR CERT_INFO *certInfoPtr,
						 IN_BOOL const BOOLEAN subjectSelfSigned,
						 OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
							CRYPT_ATTRIBUTE_TYPE *errorLocus,
						 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType )
	{
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Attribute certificates must be v2 */
	if( certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		if( certInfoPtr->version != 2 )
			{
			setErrorValues( CRYPT_CERTINFO_VERSION, 
							CRYPT_ERRTYPE_ATTR_VALUE );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
					  "Attribute certificate version number must be 2" ) );
			}

		return( CRYPT_OK );
		}

	/* If the certificate isn't v3 or above then it's only allowed under 
	   very specific circumstances */
	if( certInfoPtr->version < X509_V3 )
		{
		/* If the certificate isn't self-signed then it has to be version 3 
		   or above.  This is because the only certificates that are still 
		   allowed to be X.509v1 are trusted root certificates, any chain-
		   internal certificate must be X.509v3 or higher.  In addition if 
		   it's less than version 3 then it can't have any extensions.
			   
		   This is another failure situation for which it's difficult to 
		   provide appropriately descriptive error information, however a 
		   certificate like this is so broken that it should never be 
		   encountered, and if it is then a somewhat odd error code is to be 
		   expected */
		if( !subjectSelfSigned || DATAPTR_ISSET( certInfoPtr->attributes ) )
			{
			setErrorValues( CRYPT_CERTINFO_VERSION, 
							CRYPT_ERRTYPE_CONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
					  "An X.509v1 certificates can only be a self-signed "
					  "CA root certificate" ) );
			}
		}

	return( CRYPT_OK );
	}

/* Check that the subject issuer name and issuer subject name chain 
   properly */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int checkNameChaining( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
							  const CERT_INFO *issuerCertInfoPtr,
							  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Check that the subject issuer name and issuer subject name chain.  If 
	   the DNs are present in pre-encoded form we do a binary comparison, 
	   which is faster than calling compareDN() */
	if( subjectCertInfoPtr->certificate != NULL )
		{
		if( subjectCertInfoPtr->issuerDNsize == \
							issuerCertInfoPtr->subjectDNsize && \
			!memcmp( subjectCertInfoPtr->issuerDNptr, 
					 issuerCertInfoPtr->subjectDNptr, 
					 subjectCertInfoPtr->issuerDNsize ) )
			return( CRYPT_OK );
		}
	else
		{
		if( compareDN( subjectCertInfoPtr->issuerName,
					   issuerCertInfoPtr->subjectName, 
					   FALSE, NULL ) )
			return( CRYPT_OK );
		}

	/* The issuer/subject names don't chain */
	setErrorValues( CRYPT_CERTINFO_ISSUERNAME, 
					CRYPT_ERRTYPE_CONSTRAINT );
	retExt( CRYPT_ERROR_INVALID,
			( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO, 
			  "Subject and issuer DNs don't chain" ) );
	}

/* Check all the blob (unrecognised) attributes to see if any are marked 
   critical */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int checkUnrecognisedExtension( INOUT_PTR CERT_INFO *certInfoPtr,
									   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
											CRYPT_ATTRIBUTE_TYPE *errorLocus,
									   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
											CRYPT_ERRTYPE_TYPE *errorType )
	{
	LOOP_INDEX_PTR DATAPTR_ATTRIBUTE attributePtr;
	ATTRIBUTE_ENUM_INFO attrEnumInfo;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	LOOP_LARGE( attributePtr = \
						getFirstAttribute( &attrEnumInfo, 
										   certInfoPtr->attributes, 
										   ATTRIBUTE_ENUM_BLOB ), 
				DATAPTR_ISSET( attributePtr ),
				attributePtr = getNextAttribute( &attrEnumInfo ) )
		{
		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		/* If we've found an unrecognised critical extension, reject the 
		   certificate (PKIX section 4.2).  The one exception to this is if 
		   the attribute was recognised but has been ignored at this 
		   compliance level, in which case it's treated as a blob 
		   attribute */
		if( checkAttributeProperty( attributePtr, \
									ATTRIBUTE_PROPERTY_CRITICAL ) && \
			!checkAttributeProperty( attributePtr, \
									 ATTRIBUTE_PROPERTY_IGNORED ) )
			{
			setErrorValues( CRYPT_ATTRIBUTE_NONE, 
							CRYPT_ERRTYPE_CONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
					  "%s contains unrecognised critical extension",
					  getCertTypeName( certInfoPtr->type ) ) );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}

/* Check for nesting of extKeyUsages.  This checks that subjects don't have 
   any extKeyUsages not present in the issuer.  Since no-one can agree on 
   whether an extKeyUsage in a CA certificate applies to the CA's 
   certificates or the certificates that it issues, this is disabled unless 
   requested for a custom configuration */

#ifdef USE_CUSTOM_CONFIG_1

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkExtKeyUsageNesting( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
									IN_DATAPTR \
										const DATAPTR_ATTRIBUTE issuerAttributes,
									OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
										CRYPT_ATTRIBUTE_TYPE *errorLocus,
									OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
										CRYPT_ERRTYPE_TYPE *errorType )
	{
	DATAPTR_ATTRIBUTE attributePtr;
	LOOP_INDEX attributeID;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Check each extKeyUsage to make sure it's present in the issuer if 
	   present in the subject */
	LOOP_MED( attributeID = CRYPT_CERTINFO_EXTKEYUSAGE, 
			  attributeID <= CRYPT_CERTINFO_EXTKEYUSAGE_LAST, 
			  attributeID++ )
		{
		/* Check whether this extKeyUsage is present in the subject */
		attributePtr = findAttributeField( subjectCertInfoPtr->attributes, 
										   attributeID, 
										   CRYPT_ATTRIBUTE_NONE );
		if( DATAPTR_ISNULL( attributePtr ) )
			continue;

		/* It's present in the subject, make sure that it's also present in
		   the issuer */
		attributePtr = findAttributeField( issuerAttributes, attributeID, 
										   CRYPT_ATTRIBUTE_NONE );
		if( DATAPTR_ISSET( attributePtr ) )
			continue;

		/* The subject contains an extKeyUsage not present in the issuer */
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO, 
				  "Subject %s contains extendedKeyUsage attribute %d not "
				  "present in the issuer", 
				  getCertTypeNameLC( subjectCertInfoPtr->type ), 
				  attributeID ) );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}
#endif /* USE_CUSTOM_CONFIG_1 */

/****************************************************************************
*																			*
*								Check Name Constraints						*
*																			*
****************************************************************************/

#ifdef USE_CERTLEVEL_PKIX_FULL

/* Perform a wildcarded compare of two strings in attributes.  Certificates
   don't use standard ? and * regular-expression wildcards but instead 
   specify the constraint as a form of longest-suffix filter that's applied 
   to the string (with the usual pile of special-case exceptions that apply 
   to any certificate-related rules) so that e.g. www.foo.com would be 
   constrained using foo.com (or more usually .foo.com to avoid erroneous 
   matches for strings like www.barfoo.com) */

typedef enum {
	MATCH_NONE,		/* No special-case matching rules */
	MATCH_EMAIL,	/* Match using email address special-case rules */
	MATCH_URI,		/* Match only DNS name portion of URI */
	MATCH_LAST		/* Last valid match rule type */
	} MATCH_TYPE;

CHECK_RETVAL_BOOL \
static BOOLEAN wildcardMatch( IN_DATAPTR const DATAPTR constrainedAttribute,
							  IN_DATAPTR const DATAPTR constrainingAttribute,
							  IN_ENUM_OPT( MATCH ) \
								const MATCH_TYPE matchType )
	{
	const BYTE *constrainingString, *constrainedString;
	int constrainingStringLength, constrainedStringLength;
	BOOLEAN isWildcardMatch;
	int startPos, status;

	REQUIRES_B( DATAPTR_ISSET( constrainedAttribute ) );
	REQUIRES_B( DATAPTR_ISSET( constrainingAttribute ) );
	REQUIRES_B( isEnumRangeOpt( matchType, MATCH ) );

	status = getAttributeDataPtr( constrainingAttribute, 
								  ( void ** ) &constrainingString, 
								  &constrainingStringLength );
	if( cryptStatusError( status ) )
		return( FALSE );
	status = getAttributeDataPtr( constrainedAttribute, 
								  ( void ** ) &constrainedString, 
								  &constrainedStringLength );
	if( cryptStatusError( status ) )
		return( FALSE );
	isWildcardMatch = ( *constrainingString == '.' ) ? TRUE : FALSE;

	/* Determine the start position of the constraining string within the
	   constrained string: 

		xxxxxyyyyy	- Constrained string
			 yyyyy	- Constraining string
			^
			|
		startPos
	   
	   If the constraining string is longer than the constrained string 
	   (making startPos negative), it can never match */
	startPos = constrainedStringLength - constrainingStringLength;
	if( !isShortIntegerRange( startPos ) )
		return( FALSE );

	/* Handle special-case match requirements (PKIX section 4.2.1.11) */
	switch( matchType )
		{
		case MATCH_EMAIL:
			/* Email addresses have a special-case requirement where the 
			   absence of a wildcard-match indicator (the leading dot)
			   indicates that the mailbox has to be located directly on the 
			   constraining hostname rather than merely within that domain, 
			   i.e. user@foo.bar.com is a valid match for .bar.com but not 
			   for bar.com, which would require user@bar.com to match */
			ENSURES_B( startPos <= constrainedStringLength );
			if( !isWildcardMatch && \
				( startPos < 1 || constrainedString[ startPos - 1 ] != '@' ) )
				return( FALSE );
			break;

		case MATCH_URI:
			{
			URL_INFO urlInfo;

			/* URIs can contain trailing location information that isn't 
			   regarded as part of the URI for matching purposes so before 
			   performing the match we have to parse the URL and only use 
			   the DNS name portion */
			status = sNetParseURL( &urlInfo, constrainedString, 
								   constrainedStringLength, URL_TYPE_NONE );
			if( cryptStatusError( status ) )
				{
				/* Exactly what to do in the case of a URL parse error is a
				   bit complicated.  The standard action is to fail closed, 
				   otherwise anyone who creates a URL that the certificate 
				   software can't parse but that's still accepted by other 
				   apps (who in general will bend over backwards to try and 
				   accept almost any malformed URI, if they didn't do this 
				   then half the Internet would stop working) would be able 
				   to bypass the name constraint.  However this mode of 
				   handling is complicated by the fact that to report a 
				   failure at this point we need to report a match for 
				   excluded subtrees but a non-match for permitted subtrees.  
				   Since it's more likely that we'll encounter a permitted-
				   subtrees whitelist we report the constraint as being not 
				   matched which will reject the certificate for permitted-
				   subtrees (who in their right mind would trust something as 
				   flaky as PKI software to reliably apply an excluded-
				   subtrees blacklist?  Even something as trivial as 
				   "ex%41mple.com", let alone "ex%u0041mple.com", 
				   "ex&#x41;mple.com", or "ex%EF%BC%A1mple.com", is likely 
				   to trivially fool all certificate software in existence, 
				   so permitted-subtrees will never work anyway).  In 
				   addition we throw an exception in debug mode */
				assert( DEBUG_WARN );
				return( FALSE );
				}

			/* Adjust the constrained string information to contain only the 
 			   DNS name portion of the URI */
			constrainedString = urlInfo.host;
			startPos = urlInfo.hostLen - constrainingStringLength;
			if( !isShortIntegerRange( startPos ) )
				return( FALSE );
			ENSURES_B( boundsCheckZ( startPos, constrainingStringLength, \
									 urlInfo.hostLen ) );

			/* URIs have a special-case requirement where the absence of a
			   wildcard-match indicator (the leading dot) indicates that the
			   constraining DNS name is for a standalone host and not a 
			   portion of the constrained string's DNS name.  This means
			   that the DNS-name portion of the URI must be an exact match
			   for the constraining string */
			if( !isWildcardMatch && startPos != 0 )
				return( FALSE );
			}
		}
	ENSURES_B( boundsCheckZ( startPos, constrainingStringLength, \
							 constrainedStringLength ) );

	/* Check whether the constraining string is a suffix of the constrained
	   string.  For DNS name constraints the rule for RFC 3280 became 
	   "adding to the LHS" as for other constraints, in RFC 2459 it was
	   another special case where it had to be a subdomain as if an 
	   implicit "." was present */
	return( !strCompare( constrainedString + startPos, constrainingString, 
						 constrainingStringLength ) ? TRUE : FALSE );
	}

CHECK_RETVAL_BOOL \
static BOOLEAN matchAltnameComponent( IN_DATAPTR \
										const DATAPTR constrainedAttribute,
									  IN_DATAPTR \
										const DATAPTR constrainingAttribute,
									  IN_ATTRIBUTE \
										const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	REQUIRES_B( DATAPTR_ISSET( constrainedAttribute ) );
	REQUIRES_B( DATAPTR_ISSET( constrainingAttribute ) );
	REQUIRES_B( attributeType == CRYPT_CERTINFO_DIRECTORYNAME || \
				attributeType == CRYPT_CERTINFO_RFC822NAME || \
				attributeType == CRYPT_CERTINFO_DNSNAME || \
				attributeType == CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );

	/* If the attribute being matched is a DN, use a DN-specific match */
	if( attributeType == CRYPT_CERTINFO_DIRECTORYNAME )
		{
		DATAPTR constrainedDnPtr, constrainingDnPtr;
		int status;

		status = getAttributeDataDN( constrainedAttribute, 
									 &constrainedDnPtr );
		if( cryptStatusError( status ) )
			return( FALSE );
		status = getAttributeDataDN( constrainingAttribute, &constrainingDnPtr );
		if( cryptStatusError( status ) )
			return( FALSE );
		return( compareDN( constrainingDnPtr, constrainedDnPtr, TRUE, 
						   NULL ) );
		}

	/* It's a string name, use a substring match with attribute type-specific
	   special cases */
	return( wildcardMatch( constrainedAttribute, constrainingAttribute, 
					( attributeType == CRYPT_CERTINFO_RFC822NAME ) ? \
						MATCH_EMAIL : \
					( attributeType == CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER ) ? \
						MATCH_URI : \
						MATCH_NONE ) );
	}

CHECK_RETVAL_BOOL \
static BOOLEAN checkAltnameConstraints( IN_DATAPTR \
											const DATAPTR subjectAttributes,
										IN_DATAPTR \
											const DATAPTR issuerAttributes,
										IN_ATTRIBUTE \
											const CRYPT_ATTRIBUTE_TYPE attributeType,
										IN_BOOL const BOOLEAN isExcluded )
	{
	DATAPTR_ATTRIBUTE attributePtr;
	LOOP_INDEX_PTR DATAPTR_ATTRIBUTE constrainedAttributePtr; 

	REQUIRES_B( DATAPTR_ISVALID( subjectAttributes ) );
	REQUIRES_B( DATAPTR_ISVALID( issuerAttributes ) );
	REQUIRES_B( attributeType == CRYPT_CERTINFO_DIRECTORYNAME || \
				attributeType == CRYPT_CERTINFO_RFC822NAME || \
				attributeType == CRYPT_CERTINFO_DNSNAME || \
				attributeType == CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	REQUIRES_B( isBooleanValue( isExcluded ) );

	/* Check for the presence of constrained or constraining altName 
	   components.  If either are absent, there are no constraints to 
	   apply */
	attributePtr = findAttributeField( issuerAttributes,
									   isExcluded ? \
										CRYPT_CERTINFO_EXCLUDEDSUBTREES : \
										CRYPT_CERTINFO_PERMITTEDSUBTREES,
									   attributeType );
	if( DATAPTR_ISNULL( attributePtr ) )
		return( TRUE );

	LOOP_LARGE( constrainedAttributePtr = \
					findAttributeField( subjectAttributes, \
										CRYPT_CERTINFO_SUBJECTALTNAME, \
										attributeType ), \
				DATAPTR_ISSET( constrainedAttributePtr ),
				constrainedAttributePtr = \
					findNextFieldInstance( constrainedAttributePtr ) )
		{
		LOOP_INDEX_PTR_ALT DATAPTR_ATTRIBUTE attributeCursor;
		BOOLEAN isMatch = FALSE;

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		/* Step through the constraining attributes checking if any match 
		   the constrained attribute.  If it's an excluded subtree then none 
		   can match, if it's a permitted subtree then at least one must 
		   match */
		LOOP_LARGE_ALT( attributeCursor = attributePtr, 
						DATAPTR_ISSET( attributeCursor ) && !isMatch,
						attributeCursor = \
							findNextFieldInstance( attributeCursor ) )
			{
			ENSURES( LOOP_INVARIANT_LARGE_ALT_GENERIC() );

			isMatch = matchAltnameComponent( constrainedAttributePtr,
											 attributeCursor,
											 attributeType );
			}
		ENSURES_B( LOOP_BOUND_OK_ALT );
		if( isExcluded == isMatch )
			return( FALSE );
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( TRUE );
	}

/* Check name constraints placed by an issuer, checked if complianceLevel >=
   CRYPT_COMPLIANCELEVEL_PKIX_FULL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkNameConstraints( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
						  IN_DATAPTR const DATAPTR_ATTRIBUTE issuerAttributes,
						  IN_BOOL const BOOLEAN isExcluded )
	{
	const CRYPT_ATTRIBUTE_TYPE constraintType = isExcluded ? \
		CRYPT_CERTINFO_EXCLUDEDSUBTREES : CRYPT_CERTINFO_PERMITTEDSUBTREES;
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
	DATAPTR_ATTRIBUTE subjectAttributes = subjectCertInfoPtr->attributes;
	DATAPTR_ATTRIBUTE attributePtr;
	BOOLEAN isMatch = FALSE;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( DATAPTR_ISVALID( issuerAttributes ) );

	/* Get references to the certificate's error information */
	errorLocus = &subjectCertInfoPtr->errorLocus;
	errorType = &subjectCertInfoPtr->errorType;

	/* If this is a PKIX path-kludge CA certificate then the name 
	   constraints don't apply to it (PKIX section 4.2.1.11).  This is 
	   required in order to allow extra certificates to be kludged into the 
	   path without violating the constraint.  For example with the chain:

		Issuer	Subject		Constraint
		------	-------		----------
		Root	CA			permitted = "EE"
		CA'		CA'
		CA		EE

	   the kludge certificate CA' must be excluded from name constraint 
	   restrictions in order for the path to be valid.  Obviously this is 
	   only necessary for constraints set by the immediate parent but PKIX 
	   says it's for constraints set by all certificates in the chain (!!), 
	   thus making the pathkludge certificate exempt from any name 
	   constraints and not just the one that would cause problems */
	if( isPathKludge( subjectCertInfoPtr ) )
		return( CRYPT_OK );

	/* Check the subject DN if constraints exist.  If it's an excluded 
	   subtree then none can match, if it's a permitted subtree then at 
	   least one must match.  We also check for the special case of an
	   empty subject DN, which acts as a wildcard that matches/doesn't
	   match permitted/excluded as required */
	REQUIRES( DATAPTR_ISVALID( subjectCertInfoPtr->subjectName ) );
	attributePtr = findAttributeField( issuerAttributes, constraintType, 
									   CRYPT_CERTINFO_DIRECTORYNAME );
	if( DATAPTR_ISSET( attributePtr ) && \
		DATAPTR_ISSET( subjectCertInfoPtr->subjectName ) )
		{
		int LOOP_ITERATOR;

		LOOP_LARGE_CHECKINC( DATAPTR_ISSET( attributePtr ) && !isMatch,
							 attributePtr = findNextFieldInstance( attributePtr ) )
			{
			DATAPTR_DN dnPtr;
			int status;

			ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

			status = getAttributeDataDN( attributePtr, &dnPtr );
			if( cryptStatusOK( status ) )
				{
				/* Check whether the constraining DN is a substring of the 
				   subject DN.  For example if the constraining DN is 
				   C=US/O=Foo/OU=Bar and the subject DN is 
				   C=US/O=Foo/OU=Bar/CN=Baz then compareDN() will return 
				   TRUE to indicate that it's a substring */
				isMatch = compareDN( dnPtr, subjectCertInfoPtr->subjectName, 
									 TRUE, NULL );
				}
			}
		ENSURES( LOOP_BOUND_OK );
		if( isExcluded == isMatch )
			{
			setErrorValues( CRYPT_CERTINFO_SUBJECTNAME, 
							CRYPT_ERRTYPE_CONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
					  "%s subject name is excluded by name constraint",
					  getCertTypeName( subjectCertInfoPtr->type ) ) );
			}
		}

	/* DN constraints apply to both the main subject DN and any other DNs 
	   that may be present as subject altNames, so after we've checked the 
	   main DN we check any altName DNs as well */
	if( !checkAltnameConstraints( subjectAttributes, issuerAttributes,
								  CRYPT_CERTINFO_DIRECTORYNAME, isExcluded ) )
		{
		setErrorValues( CRYPT_CERTINFO_SUBJECTALTNAME, 
						CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
				  "%s alternative name DN is excluded by name constraint",
				  getCertTypeName( subjectCertInfoPtr->type ) ) );
		}

	/* Compare the Internet-related names if constraints exist.  We don't
	   have to check for the special case of an email address in the DN 
	   since the certificate import code transparently maps this to the 
	   appropriate altName component */
	if( !checkAltnameConstraints( subjectAttributes, issuerAttributes,
								  CRYPT_CERTINFO_RFC822NAME, isExcluded ) || \
		!checkAltnameConstraints( subjectAttributes, issuerAttributes,
								  CRYPT_CERTINFO_DNSNAME, isExcluded ) || \
		!checkAltnameConstraints( subjectAttributes, issuerAttributes,
								  CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, 
								  isExcluded ) )
		{
		setErrorValues( CRYPT_CERTINFO_SUBJECTALTNAME, 
						CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
				  "%s alternative email/DNS/URL name is excluded by name "
				  "constraint",
				  getCertTypeName( subjectCertInfoPtr->type ) ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_CERTLEVEL_PKIX_FULL */

/****************************************************************************
*																			*
*							Check Policy Constraints						*
*																			*
****************************************************************************/

#ifdef USE_CERTLEVEL_PKIX_FULL

/* Check whether a policy is the wildcard anyPolicy */

CHECK_RETVAL_BOOL \
BOOLEAN isAnyPolicy( IN_DATAPTR const DATAPTR_ATTRIBUTE attributePtr )
	{
	void *policyOidPtr;
	int policyOidLength, status;

	REQUIRES_B( DATAPTR_ISSET( attributePtr ) );

	status = getAttributeDataPtr( attributePtr, &policyOidPtr, 
								  &policyOidLength );
	if( cryptStatusError( status ) )
		return( FALSE );
	return( matchOID( policyOidPtr, policyOidLength, OID_ANYPOLICY ) ? \
			TRUE : FALSE );
	}

/* Check whether a set of policies contains an instance of the anyPolicy
   wildcard */

CHECK_RETVAL_BOOL \
static BOOLEAN containsAnyPolicy( IN_DATAPTR \
									const DATAPTR_ATTRIBUTE attributePtr,
								  IN_ATTRIBUTE \
									const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	LOOP_INDEX_PTR DATAPTR_ATTRIBUTE attributeCursor;

	REQUIRES_B( DATAPTR_ISVALID( attributePtr ) );
	REQUIRES_B( isValidExtension( attributeType ) );
	
	LOOP_LARGE( attributeCursor = \
					findAttributeField( attributePtr, attributeType, \
										CRYPT_ATTRIBUTE_NONE ), 
				DATAPTR_ISSET( attributeCursor ),
				attributeCursor = findNextFieldInstance( attributeCursor ) )
		{
		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		if( isAnyPolicy( attributeCursor ) )
			return( TRUE );
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( FALSE );
	}

/* Check the type of policy present in a certificate and make sure that it's 
   valid */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 2, 3 ) ) \
static BOOLEAN checkPolicyType( IN_DATAPTR const DATAPTR_ATTRIBUTE attributePtr,
								OUT_BOOL BOOLEAN *hasPolicy, 
								OUT_BOOL BOOLEAN *hasAnyPolicy,
								IN_BOOL const BOOLEAN inhibitAnyPolicy )
	{
	LOOP_INDEX_PTR DATAPTR_ATTRIBUTE attributeCursor = attributePtr;

	assert( isWritePtr( hasPolicy, sizeof( BOOLEAN ) ) );
	assert( isWritePtr( hasAnyPolicy, sizeof( BOOLEAN ) ) );

	REQUIRES( DATAPTR_ISVALID( attributePtr ) );
	REQUIRES_B( isBooleanValue( inhibitAnyPolicy ) );

	/* Clear return values */
	*hasPolicy = *hasAnyPolicy = FALSE;

	/* Make sure that there's a policy present and that it's a specific 
	   policy if an explicit policy is required (the ability to disallow the 
	   wildcard policy via inhibitAnyPolicy was introduced in RFC 3280 along 
	   with the introduction of anyPolicy) */
	if( DATAPTR_ISNULL( attributeCursor ) )
		return( FALSE );
	LOOP_LARGE_CHECKINC( DATAPTR_ISSET( attributeCursor ), 
						 attributeCursor = findNextFieldInstance( attributeCursor ) )
		{
		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		if( isAnyPolicy( attributeCursor ) )
			*hasAnyPolicy = TRUE;
		else
			*hasPolicy = TRUE;
		}
	ENSURES_B( LOOP_BOUND_OK );
	if( inhibitAnyPolicy )
		{
		/* The wildcard anyPolicy isn't valid for the subject, if there's no
		   other policy set then this is an error, otherwise we continue 
		   without the wildcard match allowed */
		if( !*hasPolicy )
			return( FALSE );
		*hasAnyPolicy = FALSE;
		}

	return( TRUE );
	}

/* Check whether a given policy is present in a certificate */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 2 ) ) \
BOOLEAN isPolicyPresent( const DATAPTR_ATTRIBUTE subjectAttributes,
						 IN_BUFFER( issuerPolicyValueLength ) \
								const void *issuerPolicyValue,
						 IN_LENGTH_OID const int issuerPolicyValueLength )
	{
	LOOP_INDEX_PTR DATAPTR_ATTRIBUTE attributeCursor;
	int status;

	assert( isReadPtrDynamic( issuerPolicyValue, issuerPolicyValueLength ) );

	REQUIRES_B( DATAPTR_ISVALID( subjectAttributes ) );
	REQUIRES_B( issuerPolicyValueLength > 0 && \
				issuerPolicyValueLength < MAX_POLICY_SIZE );

	LOOP_LARGE( attributeCursor = subjectAttributes, 
				DATAPTR_ISSET( attributeCursor ),
				attributeCursor = findNextFieldInstance( attributeCursor ) )
		{
		void *subjectPolicyValuePtr;
		int subjectPolicyValueLength;

		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		status = getAttributeDataPtr( attributeCursor, &subjectPolicyValuePtr, 
									  &subjectPolicyValueLength );
		if( cryptStatusError( status ) )
			continue;
		if( issuerPolicyValueLength == subjectPolicyValueLength && \
			!memcmp( issuerPolicyValue, subjectPolicyValuePtr, 
					 issuerPolicyValueLength ) )
			return( TRUE );
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( FALSE );
	}

/* Check policy constraints placed by an issuer, checked if complianceLevel 
   >= CRYPT_COMPLIANCELEVEL_PKIX_FULL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkPolicyConstraints( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
							IN_DATAPTR \
								const DATAPTR_ATTRIBUTE issuerAttributes,
							IN_ENUM_OPT( POLICY ) const POLICY_TYPE policyType,
							IN_PTR_OPT const POLICY_INFO *policyInfo,
							IN_BOOL const BOOLEAN allowMappedPolicies )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
	DATAPTR_ATTRIBUTE constrainingAttributePtr, constrainedAttributePtr;
	BOOLEAN subjectHasPolicy, issuerHasPolicy;
	BOOLEAN subjectHasAnyPolicy, issuerHasAnyPolicy;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( policyInfo == NULL || \
			isReadPtr( policyInfo, sizeof( POLICY_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( DATAPTR_ISSET( issuerAttributes ) );
	REQUIRES( isEnumRangeOpt( policyType, POLICY ) );
	REQUIRES( isBooleanValue( allowMappedPolicies ) );

	/* Get references to the certificate's error information */
	errorLocus = &subjectCertInfoPtr->errorLocus;
	errorType = &subjectCertInfoPtr->errorType;

	/* Get references to the constrained and constraining attributes */
	constrainingAttributePtr = \
					findAttributeField( issuerAttributes, 
										CRYPT_CERTINFO_CERTPOLICYID, 
										CRYPT_ATTRIBUTE_NONE );
	constrainedAttributePtr = \
					findAttributeField( subjectCertInfoPtr->attributes, 
										CRYPT_CERTINFO_CERTPOLICYID, 
										CRYPT_ATTRIBUTE_NONE );

	/* If there's a policy mapping present then neither the issuer nor 
	   subject domain policies can be the wildcard anyPolicy (PKIX section 
	   4.2.1.6) */
	if( containsAnyPolicy( issuerAttributes, 
						   CRYPT_CERTINFO_ISSUERDOMAINPOLICY ) || \
		containsAnyPolicy( issuerAttributes, 
						   CRYPT_CERTINFO_SUBJECTDOMAINPOLICY ) )
		{
		setErrorValues( CRYPT_CERTINFO_POLICYMAPPINGS, 
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
				  "%s issuer contains unmappable anyPolicy attribute",
				  getCertTypeName( subjectCertInfoPtr->type ) ) );
		}

	/* If there's no requirement for a policy and there's none set, we're 
	   done */
	if( policyType == POLICY_NONE && \
		DATAPTR_ISNULL( constrainedAttributePtr ) )
		return( CRYPT_OK );

	/* Check the subject policy */
	if( !checkPolicyType( constrainedAttributePtr, &subjectHasPolicy,
						  &subjectHasAnyPolicy, 
						  ( policyType == POLICY_NONE_SPECIFIC || \
							policyType == POLICY_SUBJECT_SPECIFIC || \
							policyType == POLICY_BOTH_SPECIFIC ) ? \
							TRUE : FALSE ) )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, 
						CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
				  "%s is excluded by a policy constraint",
				  getCertTypeName( subjectCertInfoPtr->type ) ) );
		}

	/* If there's no requirement for an issuer policy and there's none set 
	   by the issuer, we're done */
	if( ( ( policyType == POLICY_SUBJECT ) || \
		  ( policyType == POLICY_SUBJECT_SPECIFIC ) ) && \
		DATAPTR_ISNULL( constrainingAttributePtr ) )
		return( CRYPT_OK );

	/* Check the issuer policy */
	if( !checkPolicyType( constrainingAttributePtr , &issuerHasPolicy,
						  &issuerHasAnyPolicy, 
						  ( policyType == POLICY_BOTH_SPECIFIC ) ? \
							TRUE : FALSE ) )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, 
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
				  "%s is excluded by an issuer policy constraint",
				  getCertTypeName( subjectCertInfoPtr->type ) ) );
		}

	/* Both the issuer and subject have some sort of policy, if either are 
	   anyPolicy wildcards (introduced in RFC 3280 section 4.2.1.5) then 
	   it's considered a match */
	if( subjectHasAnyPolicy || issuerHasAnyPolicy )
		return( CRYPT_OK );

	/* An explicit policy is required, make sure that at least one of the 
	   issuer policies matches at least one of the subject policies.  Note
	   that there's no exception for PKIX path-kludge certificates, this is 
	   an error in the RFC for which the text at this point is unchanged 
	   from RFC 2459.  In fact this contradicts the path-processing 
	   pesudocode but since that in turn contradicts the main text in a 
	   number of places we take the main text as definitive, not the buggy 
	   pseudocode */
	if( policyInfo != NULL )
		{
		const POLICY_DATA *policyData = policyInfo->policies;
		LOOP_INDEX i;

		LOOP_MED( i = 0, i < policyInfo->noPolicies, i++ )
			{
			ENSURES( LOOP_INVARIANT_MED( i, 0, policyInfo->noPolicies - 1 ) );

			if( policyData[ i ].isMapped && !allowMappedPolicies )
				continue;
			if( isPolicyPresent( constrainedAttributePtr, 
								 policyData[ i ].data, 
								 policyData[ i ].length ) )
				return( CRYPT_OK );
			}
		ENSURES( LOOP_BOUND_OK );
		}
	else
		{
		LOOP_INDEX_PTR DATAPTR_ATTRIBUTE constrainingAttributeCursor;

		LOOP_LARGE( constrainingAttributeCursor = constrainingAttributePtr, 
					!DATAPTR_ISNULL( constrainingAttributeCursor ), 
					constrainingAttributeCursor = \
						findNextFieldInstance( constrainingAttributeCursor ) )
			{
			void *constrainingPolicyValuePtr;
			int constrainingPolicyValueLength, status;

			ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

			status = getAttributeDataPtr( constrainingAttributeCursor, 
										  &constrainingPolicyValuePtr, 
										  &constrainingPolicyValueLength );
			if( cryptStatusError( status ) )
				break;
			if( isPolicyPresent( constrainedAttributePtr, 
								 constrainingPolicyValuePtr, 
								 constrainingPolicyValueLength ) )
				return( CRYPT_OK );
			}
		ENSURES( LOOP_BOUND_OK );
		}

	/* We couldn't find a matching policy, report an error */
	setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, CRYPT_ERRTYPE_CONSTRAINT );
	retExt( CRYPT_ERROR_INVALID,
			( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
			  "%s isn't covered by a matching policy",
			  getCertTypeName( subjectCertInfoPtr->type ) ) );
	}
#endif /* USE_CERTLEVEL_PKIX_FULL */

/****************************************************************************
*																			*
*							Check Path Constraints							*
*																			*
****************************************************************************/

#ifdef USE_CERTLEVEL_PKIX_PARTIAL

/* Check path constraints placed by an issuer, checked if complianceLevel 
   >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkPathConstraints( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
						  IN_LENGTH_SHORT_Z const int pathLength )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
	int value, status;

	assert( isReadPtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( isShortIntegerRange( pathLength ) );

	/* Get references to the certificate's error information */
	errorLocus = &subjectCertInfoPtr->errorLocus;
	errorType = &subjectCertInfoPtr->errorType;

#ifdef USE_CERTLEVEL_PKIX_FULL
	/* If this is a PKIX path-kludge certificate then the path length 
	   constraints don't apply to it (PKIX section 4.2.1.10).  This is 
	   required in order to allow extra certificates to be kludged into the 
	   path without violating the name constraint */
	if( isPathKludge( subjectCertInfoPtr ) )
		return( CRYPT_OK );
#endif /* USE_CERTLEVEL_PKIX_FULL */

	/* If the path length constraint hasn't been triggered yet we're OK */
	if( pathLength > 0 )
		return( CRYPT_OK );

	/* If the certificate is self-signed (i.e. the certificate is applying 
	   the constraint to itself) then a path length constraint of zero is 
	   valid.  Checking only the subject certificate information is safe 
	   because the calling code has guaranteed that if the certificate is 
	   self-signed then the issuer attributes are the attributes from the 
	   subject certificate */
	if( TEST_FLAG( subjectCertInfoPtr->flags, CERT_FLAG_SELFSIGNED ) )
		return( CRYPT_OK );

	/* The path length constraint is in effect, the next certificate down 
	   the chain must be an end-entity certificate */
	status = getAttributeFieldValue( subjectCertInfoPtr->attributes, 
									 CRYPT_CERTINFO_CA, 
									 CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusOK( status ) && value > 0 )
		{
		setErrorValues( CRYPT_CERTINFO_PATHLENCONSTRAINT,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
				  "%s is excluded by path length constraint",
				  getCertTypeName( subjectCertInfoPtr->type ) ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_CERTLEVEL_PKIX_PARTIAL */

/****************************************************************************
*																			*
*						Check Miscellaneous Constraints						*
*																			*
****************************************************************************/

/* If there's a clearance attribute present, make sure that the subject only 
   has clearances that are present in the issuer.  Conversely, if the issuer 
   has a clearance attribute then the subject must have one too */

#ifdef USE_CUSTOM_CONFIG_1

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkClearanceConstraints( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
									  IN_DATAPTR \
										const DATAPTR_ATTRIBUTE issuerAttributes,
									  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
										CRYPT_ATTRIBUTE_TYPE *errorLocus,
									  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
										CRYPT_ERRTYPE_TYPE *errorType )
	{
	int value, status;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* If the subject has a clearance attribute, make sure that the issuer 
	   does too and that the subject is a subset of the issuer's ones */
	status = getAttributeFieldValue( subjectCertInfoPtr->attributes, 
							CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST, 
							CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusOK( status ) )
		{
		const int subjectClearance = value;

		status = getAttributeFieldValue( issuerAttributes, 
							CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST, 
							CRYPT_ATTRIBUTE_NONE, &value );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO, 
					  "Subject %s contains Clearance attribute value %X but "
					  "issuer doesn't", 
					  getCertTypeNameLC( subjectCertInfoPtr->type ), 
					  subjectClearance ) );
			}
		if( ( subjectClearance & ~value ) != 0 )
			{
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO, 
					  "Subject %s contains Clearance value %X not present "
					  "in issuer, which only has %X",
					  getCertTypeNameLC( subjectCertInfoPtr->type ), 
					  subjectClearance, value ) );
			}

		return( CRYPT_OK );
		}

	/* The subject doesn't have a clearance attribute so the issuer 
	   shouldn't have one either */
	status = getAttributeFieldValue( subjectCertInfoPtr->attributes, 
							CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST, 
							CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusOK( status ) )
		{
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO, 
				  "Issuer contains Clearance attribute value %X but "
				  "subject %s doesn't", value,
				  getCertTypeNameLC( subjectCertInfoPtr->type ) ) ); 
		}

	return( CRYPT_OK );
	}
#endif /* USE_CUSTOM_CONFIG_1 */

/****************************************************************************
*																			*
*							Check RPKI Attributes							*
*																			*
****************************************************************************/

#ifdef USE_RPKI

/* Check attributes for a resource RPKI (RPKI) certificate.  This is 
   somewhat ugly in that it entails a number of implicit checks rather
   than just applying constraints specified in the certificate itself,
   but then again it's not much different to the range of checks
   hardcoded into checkCert(), the only real difference is that the latter
   is specified for all certificates while these are only for RPKI
   certificates */

CHECK_RETVAL STDC_NONNULL_ARG( ( 4, 5 ) ) \
static int checkRPKIAttributes( IN_DATAPTR const DATAPTR_ATTRIBUTE subjectAttributes,
								IN_BOOL const BOOLEAN isCA,
								IN_BOOL const BOOLEAN isSelfSigned,
								OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
								OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	DATAPTR_ATTRIBUTE attributePtr;
	void *policyOidPtr;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT( "checkRPKIAttributes" );
	int policyOidLength, value, status;

	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE  ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( DATAPTR_ISVALID( subjectAttributes ) );
	REQUIRES( isBooleanValue( isCA ) );
	REQUIRES( isBooleanValue( isSelfSigned ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Check that there's a keyUsage present, and that for CA certificates 
	   it's the CA usages and for EE certificates it's digital signature 
	   (RPKI section 3.9.4) */
	status = getAttributeFieldValue( subjectAttributes,
									 CRYPT_CERTINFO_KEYUSAGE, 
									 CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusError( status ) )
		{
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE, CRYPT_ERRTYPE_ATTR_ABSENT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
				  "RPKI %s doesn't contain a keyUsage attribute",
				  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
		}
	if( isCA )
		{
		if( value != ( CRYPT_KEYUSAGE_KEYCERTSIGN | \
					   CRYPT_KEYUSAGE_CRLSIGN ) )
			status = CRYPT_ERROR_INVALID;
		}
	else
		{
		if( value != CRYPT_KEYUSAGE_DIGITALSIGNATURE )
			status = CRYPT_ERROR_INVALID;
		}
	if( cryptStatusError( status ) )
		{
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE, CRYPT_ERRTYPE_ATTR_VALUE );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
				  "RPKI %s contains an invalid keyUsage",
				  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
		}
	CFI_CHECK_UPDATE( "getAttributeFieldValue" );

	/* If it's a CA, check that there's no extendedKeyUsage (RPKI section 
	   3.9.5) and there's a caRepository SIA (RPKI section 3.9.8) */
	if( isCA )
		{
		if( checkAttributePresent( subjectAttributes, 
								   CRYPT_CERTINFO_EXTKEYUSAGE ) )
			{
			setErrorValues( CRYPT_CERTINFO_EXTKEYUSAGE, 
							CRYPT_ERRTYPE_ATTR_PRESENT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "RPKI CA %s contains extKeyUsage attribute",
					  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
			}
		if( !checkAttributeFieldPresent( subjectAttributes,
								CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY ) )
			{
			setErrorValues( CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY, 
							CRYPT_ERRTYPE_ATTR_ABSENT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "RPKI CA %s doesn't contain caRepository attribute",
					  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "checkAttributePresent" );

	/* If it's not self-signed (i.e. not a root certificate) check that
	   there's a caIssuers AIA (RPKI section 3.9.7) */
	if( !isSelfSigned )
		{
		if( !checkAttributeFieldPresent( subjectAttributes,
								CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS ) )
			{
			setErrorValues( CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS, 
							CRYPT_ERRTYPE_ATTR_ABSENT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "RPKI %s doesn't caIssuers attribute",
					  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "checkAttributeFieldPresent" );

	/* Check that there's an RPKI policy present (RPKI section 3.9.9) */
	attributePtr = findAttributeField( subjectAttributes,
									   CRYPT_CERTINFO_CERTPOLICYID,
									   CRYPT_ATTRIBUTE_NONE );
	if( attributePtr == NULL )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, 
						CRYPT_ERRTYPE_ATTR_ABSENT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
				  "RPKI %s doesn't contains a policy attribute",
				  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
		}
	status = getAttributeDataPtr( attributePtr, &policyOidPtr, 
								  &policyOidLength );
	if( cryptStatusError( status ) || \
		!matchOID( policyOidPtr, policyOidLength, OID_RPKI_POLICY ) )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, 
						CRYPT_ERRTYPE_ATTR_VALUE );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
				  "RPKI %s doesn't contains a policy attribute",
				  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
		}
	CFI_CHECK_UPDATE( "findAttributeField" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "checkRPKIAttributes", 
								   "getAttributeFieldValue", 
								   "checkAttributePresent", 
								   "checkAttributeFieldPresent", 
								   "findAttributeField" ) );


	return( CRYPT_OK );
	}
#endif /* USE_RPKI */

/****************************************************************************
*																			*
*							Check a Certificate	Object						*
*																			*
****************************************************************************/

#ifdef USE_CERTREV

/* Check the consistency of a CRL against its issuing certificate.  Note 
   that this is the reverse of the usual form of checking the certificate 
   against the CRL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkCrlConsistency( INOUT_PTR CERT_INFO *crlInfoPtr,
								IN_PTR_OPT const CERT_INFO *issuerCertInfoPtr,
								IN_RANGE( CRYPT_COMPLIANCELEVEL_OBLIVIOUS, \
										  CRYPT_COMPLIANCELEVEL_LAST - 1 ) \
									const int complianceLevel )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
#ifdef CONFIG_CUSTOM_1
	DATAPTR_ATTRIBUTE attributePtr;
	const void *deltaCRLindicator DUMMY_INIT_PTR;
	int deltaCRLindicatorLen DUMMY_INIT, status = CRYPT_OK;
#else
	int deltaCRLindicator, status;
#endif /* CONFIG_CUSTOM_1 */

	assert( isReadPtr( crlInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( complianceLevel >= CRYPT_COMPLIANCELEVEL_OBLIVIOUS && \
			  complianceLevel < CRYPT_COMPLIANCELEVEL_LAST );

	/* Get references to the certificate's error information */
	errorLocus = &crlInfoPtr->errorLocus;
	errorType = &crlInfoPtr->errorType;

	/* If it's a delta CRL make sure that the CRL numbers make sense, i.e.
	   that the delta CRL was issued after the full CRL */
#ifdef CONFIG_CUSTOM_1
	attributePtr = findAttributeField( crlInfoPtr->attributes,
									   CRYPT_CERTINFO_DELTACRLINDICATOR, 
									   CRYPT_ATTRIBUTE_NONE );
	if( DATAPTR_ISSET( attributePtr ) )
		{
		status = getAttributeDataPtr( attributePtr, 
									  ( void ** ) &deltaCRLindicator, 
									  &deltaCRLindicatorLen );
		}
	else
		status = CRYPT_ERROR;
	if( cryptStatusOK( status ) )
		{
		const void *crlNumber DUMMY_INIT_PTR;
		int crlNumberLen DUMMY_INIT;

		attributePtr = findAttributeField( crlInfoPtr->attributes,
										   CRYPT_CERTINFO_CRLNUMBER, 
										   CRYPT_ATTRIBUTE_NONE );
		if( DATAPTR_ISSET( attributePtr ) )
			{
			status = getAttributeDataPtr( attributePtr, 
										  ( void ** ) &crlNumber, 
										  &crlNumberLen );
			}
		else
			status = CRYPT_ERROR;
		if( cryptStatusOK( status ) && \
			( crlNumberLen > deltaCRLindicatorLen || \
			  memcmp( crlNumber, deltaCRLindicator, crlNumberLen ) >= 0 ) )
			{
			setErrorValues( CRYPT_CERTINFO_DELTACRLINDICATOR,
							CRYPT_ERRTYPE_CONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CRL_ERRINFO,
					  "%s contains an invalid delta CRL indicator",
					  getCertTypeNameLC( crlInfoPtr->type ) ) );
			}
		}
#else
	status = getAttributeFieldValue( crlInfoPtr->attributes,
									 CRYPT_CERTINFO_DELTACRLINDICATOR, 
									 CRYPT_ATTRIBUTE_NONE, 
									 &deltaCRLindicator );
	if( cryptStatusOK( status ) )
		{
		int crlNumber;

		status = getAttributeFieldValue( crlInfoPtr->attributes,
										 CRYPT_CERTINFO_CRLNUMBER, 
										 CRYPT_ATTRIBUTE_NONE, &crlNumber );
		if( cryptStatusOK( status ) && crlNumber >= deltaCRLindicator )
			{
			setErrorValues( CRYPT_CERTINFO_DELTACRLINDICATOR,
							CRYPT_ERRTYPE_CONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CRL_ERRINFO,
					  "%s contains an invalid delta CRL indicator",
					  getCertTypeNameLC( crlInfoPtr->type ) ) );
			}
		}
#endif /* CONFIG_CUSTOM_1 */

	/* If it's a standalone CRL entry used purely as a container for 
	   revocation data don't try and perform any issuer-based checking */
	if( issuerCertInfoPtr == NULL )
		return( CRYPT_OK );

	/* Make sure that the issuer can sign CRLs and that the issuer 
	   certificate in general is in order */
	status = checkKeyUsage( issuerCertInfoPtr, 
							CHECKKEY_FLAG_CA | CHECKKEY_FLAG_GENCHECK, 
							CRYPT_KEYUSAGE_CRLSIGN, complianceLevel,
							crlInfoPtr );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );

	/* There's a problem with the issuer certificate, set a general
	   error status indicating this for the CRL */
	setErrorValues( CRYPT_CERTINFO_KEYUSAGE,
					CRYPT_ERRTYPE_ISSUERCONSTRAINT );
	retExt( status,
			( status, CRL_ERRINFO,
			  "Issuer certificate isn't capable of CRL signing" ) );
	}
#endif /* USE_CERTREV */

/* Perform basic checks on a certificate.  Apart from its use as part of the 
   normal certificate-checking process this is also used to provide a quick
   "is this certificate obviously invalid" check without having to check
   signatures from issuing certificates and other paraphernalia, for example
   when a full certificate check has been performed earlier and all we want
   to do is make sure that the certificate hasn't expired or been declared
   untrusted in the meantime */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCertBasic( INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
	const time_t currentTime = getTime( GETTIME_NONE );
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int complianceLevel, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );
	REQUIRES( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );

	/* Get references to the certificate's error information */
	errorLocus = &certInfoPtr->errorLocus;
	errorType = &certInfoPtr->errorType;

	/* Determine how much checking we need to perform */
	status = krnlSendMessage( certInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

	/* There is one universal case in which a certificate is regarded as 
	   invalid and that's when it's explicitly not trusted */
	if( certInfoPtr->cCertCert->trustedUsage == 0 )
		{
		setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE,
						CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
				  "%s isn't trusted for any usage",
				  getCertTypeName( certInfoPtr->type ) ) );
		}

	/* If we're running in oblivious mode, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_REDUCED )
		{
		ENSURES( CFI_CHECK_SEQUENCE_1( "IMESSAGE_GETATTRIBUTE" ) );

		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CRYPT_COMPLIANCELEVEL_REDUCED" );

	/* Check that the validity period is in order.  If we're checking an 
	   existing certificate then the start time has to be valid, if we're 
	   creating a new certificate then it doesn't have to be valid since the 
	   certificate could be created for use in the future */
	if( currentTime <= MIN_TIME_VALUE )
		{
		/* Time is broken, we can't reliably check for expiry times */
		setErrorValues( CRYPT_CERTINFO_VALIDFROM, CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
				  "System time is broken, can't check %s validity",
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}
	if( certInfoPtr->startTime >= certInfoPtr->endTime || \
		( certInfoPtr->certificate != NULL && \
		  currentTime < certInfoPtr->startTime ) )
		{
		setErrorValues( CRYPT_CERTINFO_VALIDFROM, CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
				  "%s isn't valid yet", 
				  getCertTypeName( certInfoPtr->type ) ) );
		}
	if( currentTime > certInfoPtr->endTime )
		{
		setErrorValues( CRYPT_CERTINFO_VALIDTO, CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
				  "%s has expired", 
				  getCertTypeName( certInfoPtr->type ) ) );
		}
	CFI_CHECK_UPDATE( "timeCheck" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "IMESSAGE_GETATTRIBUTE", 
								   "CRYPT_COMPLIANCELEVEL_REDUCED", 
								   "timeCheck" ) );

	return( CRYPT_OK );
	}

/* Check the validity of a subject certificate based on an issuer 
   certificate with the level of checking performed depending on the 
   complianceLevel setting.  If the shortCircuitCheck flag is set (used for 
   certificate issuer : subject pairs that may already have been checked) 
   we skip the constant-result checks if the combination has already been 
   checked at this compliance level */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCert( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
			   IN_PTR_OPT const CERT_INFO *issuerCertInfoPtr,
			   IN_BOOL const BOOLEAN shortCircuitCheck )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
	DATAPTR_ATTRIBUTE subjectAttributes;
	BOOLEAN subjectSelfSigned;
#ifdef USE_CERTLEVEL_PKIX_PARTIAL
	DATAPTR_ATTRIBUTE issuerAttributes, attributePtr;
	BOOLEAN subjectIsCA = FALSE, issuerIsCA = FALSE;
	int value;
#endif /* USE_CERTLEVEL_PKIX_PARTIAL */
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int complianceLevel, status;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( isBooleanValue( shortCircuitCheck ) );

	/* Get references to the certificate's error information */
	errorLocus = &subjectCertInfoPtr->errorLocus;
	errorType = &subjectCertInfoPtr->errorType;

	/* Get certificate information */
	subjectAttributes = subjectCertInfoPtr->attributes;
	subjectSelfSigned = TEST_FLAG( subjectCertInfoPtr->flags, 
								   CERT_FLAG_SELFSIGNED ) ? TRUE : FALSE;
#ifdef USE_CERTLEVEL_PKIX_PARTIAL
	if( issuerCertInfoPtr != NULL )
		issuerAttributes = issuerCertInfoPtr->attributes;
	else
		DATAPTR_SET( issuerAttributes, NULL );
#endif /* USE_CERTLEVEL_PKIX_PARTIAL */

	/* Determine how much checking we need to perform.  If this is a 
	   currently-under-construction certificate then we use the maximum 
	   compliance level to ensure that cryptlib never produces broken 
	   certificates */
	if( subjectCertInfoPtr->certificate == NULL )
		complianceLevel = CRYPT_COMPLIANCELEVEL_PKIX_FULL;
	else
		{
		status = krnlSendMessage( subjectCertInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
								  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

	/* If it's some form of certificate request or an OCSP object (which 
	   means that it isn't signed by an issuer in the normal sense) then 
	   there's nothing to check (yet) */
	switch( subjectCertInfoPtr->type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
		case CRYPT_CERTTYPE_CERTCHAIN:
			/* It's an issuer-signed object, there must be an issuer 
			   certificate present */
			REQUIRES( issuerCertInfoPtr != NULL );
			if( TEST_FLAG( subjectCertInfoPtr->flags, 
						   CERT_FLAG_CERTCOLLECTION ) )
				{
				/* Certificate collections are pure container objects for 
				   which the base certificate object doesn't correspond to 
				   an actual certificate */
				retIntError();
				}
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* These are merely templates submitted to a CA, there's nothing 
			   to check.  More specifically, the template could contain 
			   constraints that only make sense once the issuer certificate 
			   is incorporated into a chain or a future-dated validity time 
			   or a CA keyUsage for which the CA provides the appropriate 
			   matching basicConstraints value(s) so we can't really perform 
			   much checking here */
			ENSURES( CFI_CHECK_SEQUENCE_1( "IMESSAGE_GETATTRIBUTE" ) );
			return( CRYPT_OK );

#ifdef USE_CERTREV
		case CRYPT_CERTTYPE_CRL:
			/* There must be an issuer certificate present unless we're 
			   checking a standalone CRL entry that acts purely as a 
			   container for revocation data */
			assert( issuerCertInfoPtr == NULL || \
					isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

			/* CRL checking is handled specially */
			status = checkCrlConsistency( subjectCertInfoPtr, 
										  issuerCertInfoPtr, complianceLevel );
			if( cryptStatusError( status ) )
				{
				retExtErr( status,
						   ( status, SUBJECTCERT_ERRINFO, SUBJECTCERT_ERRINFO, 
							 "CRL isn't consistent with the CA certificate "
							 "that issued it" ) );
				}
			CFI_CHECK_UPDATE( "checkCrlConsistency" );

			ENSURES( CFI_CHECK_SEQUENCE_2( "IMESSAGE_GETATTRIBUTE",
										   "checkCrlConsistency" ) );
			return( CRYPT_OK );
#endif /* USE_CERTREV */

		case CRYPT_CERTTYPE_CMS_ATTRIBUTES:
		case CRYPT_CERTTYPE_PKIUSER:
			retIntError();

		case CRYPT_CERTTYPE_RTCS_REQUEST:
		case CRYPT_CERTTYPE_RTCS_RESPONSE:
		case CRYPT_CERTTYPE_OCSP_REQUEST:
		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			/* These aren't normal certificate types, there's nothing to 
			   check - we can't even check the issuer since they're not 
			   normally issued by CAs */
			ENSURES( CFI_CHECK_SEQUENCE_1( "IMESSAGE_GETATTRIBUTE" ) );
			return( CRYPT_OK );

		default:
			retIntError();
		}
	ENSURES( issuerCertInfoPtr != NULL );
	ENSURES( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			 subjectCertInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			 subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );

	/* Perform a basic check for obvious invalidity issues */
	status = checkCertBasic( subjectCertInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkCertBasic" );

	/* There is one universal case in which a certificate is regarded as 
	   invalid and that's when the issuing certificate isn't trusted as an 
	   issuer.  We perform the check in oblivious mode to ensure that only 
	   the basic trusted usage gets checked at this point */
	if( issuerCertInfoPtr->cCertCert->trustedUsage != CRYPT_ERROR )
		{
		status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_CA, 
								CRYPT_KEYUSAGE_KEYCERTSIGN,
								CRYPT_COMPLIANCELEVEL_OBLIVIOUS,
								subjectCertInfoPtr );
		if( cryptStatusOK( status ) )
			return( CRYPT_OK );

		/* There's a problem with the issuer certificate, set a general
		   error status indicating this for the subject certificate */
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		retExt( status,
				( status, SUBJECTCERT_ERRINFO,
				  "Issuer certificate isn't trusted to sign this %s",
				  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
		}
	CFI_CHECK_UPDATE( "checkKeyUsage" );

	/* If we're running in oblivious mode, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_REDUCED )
		{
		ENSURES( CFI_CHECK_SEQUENCE_3( "IMESSAGE_GETATTRIBUTE", 
									   "checkCertBasic", "checkKeyUsage" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CRYPT_COMPLIANCELEVEL_REDUCED" );

	/* If it's a self-signed certificate or if we're doing a short-circuit 
	   check of a certificate in a chain that's already been checked and 
	   we've already checked it at the appropriate level then there's no 
	   need to perform any further checks */
	if( ( subjectSelfSigned || shortCircuitCheck ) && \
		( subjectCertInfoPtr->cCertCert->maxCheckLevel >= complianceLevel ) )
		{
		ENSURES( CFI_CHECK_SEQUENCE_4( "IMESSAGE_GETATTRIBUTE", 
									   "checkCertBasic", "checkKeyUsage",
									   "CRYPT_COMPLIANCELEVEL_REDUCED" ) );
		return( CRYPT_OK );
		}

	/* Perform certificate object-type-specific version checks */
	status = checkVersion( subjectCertInfoPtr, subjectSelfSigned, 
						   errorLocus, errorType );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkVersion" );

	/* If the certificate isn't self-signed, check name chaining */
	if( !subjectSelfSigned )
		{
		status = checkNameChaining( subjectCertInfoPtr, issuerCertInfoPtr,
									errorLocus, errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "checkNameChaining" );

	/* If we're doing a reduced level of checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_STANDARD )
		{
		if( subjectCertInfoPtr->cCertCert->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->cCertCert->maxCheckLevel = complianceLevel;
		ENSURES( CFI_CHECK_SEQUENCE_6( "IMESSAGE_GETATTRIBUTE", 
									   "checkCertBasic", "checkKeyUsage", 
									   "CRYPT_COMPLIANCELEVEL_REDUCED", 
									   "checkVersion", "checkNameChaining" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CRYPT_COMPLIANCELEVEL_STANDARD" );

	/* Check that the certificate usage flags are present and consistent.  
	   The key usage checking level ranges up to 
	   CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL so we re-do the check even if it's 
	   already been done at a lower level */
	if( subjectCertInfoPtr->cCertCert->maxCheckLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL && \
		subjectCertInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		status = checkKeyUsage( subjectCertInfoPtr, CHECKKEY_FLAG_GENCHECK, 
								CRYPT_KEYUSAGE_NONE, complianceLevel, 
								subjectCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
        }
	CFI_CHECK_UPDATE( "checkKeyUsage" );

	/* If the certificate isn't self-signed check that the issuer is a CA */
	if( !subjectSelfSigned )
		{
		status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_CA, 
								CRYPT_KEYUSAGE_KEYCERTSIGN, complianceLevel,
								subjectCertInfoPtr );
		if( cryptStatusError( status ) )
			{
			/* There's a problem with the issuer certificate, set a general
			   error status indicating this for the subject certificate */
			setErrorValues( CRYPT_CERTINFO_KEYUSAGE,
							CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			retExt( status,
					( status, SUBJECTCERT_ERRINFO,
					  "Issuer certificate isn't valid for signing this %s",
					  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "checkKeyUsageIssuer" );

	/* Check all the blob (unrecognised) attributes to see if any are marked 
	   critical.  We only do this if it's an existing certificate that we've
	   imported rather than one that we've just created since applying this 
	   check to the latter would make it impossible to create certificates 
	   with unrecognised critical extensions */
	if( subjectCertInfoPtr->certificate != NULL )
		{
		status = checkUnrecognisedExtension( subjectCertInfoPtr, 
											 errorLocus, errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "checkAttributeProperty" );

#ifdef USE_CERTLEVEL_PKIX_PARTIAL
	/* If we're not doing at least partial PKIX checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		{
		if( subjectCertInfoPtr->cCertCert->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->cCertCert->maxCheckLevel = complianceLevel;
		ENSURES( CFI_CHECK_SEQUENCE_10( "IMESSAGE_GETATTRIBUTE", 
										"checkCertBasic", "checkKeyUsage", 
										"CRYPT_COMPLIANCELEVEL_REDUCED", 
										"checkVersion", "checkNameChaining", 
										"CRYPT_COMPLIANCELEVEL_STANDARD", 
										"checkKeyUsage", "checkKeyUsageIssuer",
										"checkAttributeProperty" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL" );

	/* Determine whether the subject or issuer are CA certificates */
	status = getAttributeFieldValue( subjectAttributes, 
									 CRYPT_CERTINFO_CA, 
									 CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusOK( status ) )
		subjectIsCA = ( value > 0 ) ? TRUE : FALSE;
	status = getAttributeFieldValue( issuerAttributes,
									 CRYPT_CERTINFO_CA, 
									 CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusOK( status ) )
		issuerIsCA = ( value > 0 ) ? TRUE : FALSE;

	/* Constraints can only be present in CA certificates.  The issuer may 
	   not be a proper CA if it's a self-signed end entity certificate or 
	   an X.509v1 CA certificate, which is why we also check for 
	   !issuerIsCA */
	if( DATAPTR_ISSET( subjectAttributes ) )
		{
		BOOLEAN invalidAttributes = FALSE;

		if( !subjectIsCA )
			{ 
			invalidAttributes = \
					invalidAttributesPresent( subjectAttributes, FALSE, 
											  errorLocus, errorType );
			}
		if( !issuerIsCA && !invalidAttributes )
			{
			invalidAttributes = \
					invalidAttributesPresent( subjectAttributes, TRUE, 
											  errorLocus, errorType );
			}
		if( invalidAttributes )
			{
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO, 
					  "%s contains invalid CA-only attributes",
					  getCertTypeName( subjectCertInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "invalidAttributesPresent" );

	/*  From this point onwards if we're doing a short-circuit check of 
	    certificates in a chain, we don't apply constraint checks.  This is 
		because the certificate-chain code has already performed far more 
		complete checks of the various constraints set by all the 
		certificates in the chain rather than just the current certificate 
		issuer : subject pair */

	/* If there's a path length constraint present, apply it */
	status = getAttributeFieldValue( issuerAttributes,
									 CRYPT_CERTINFO_PATHLENCONSTRAINT, 
									 CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusOK( status ) && !shortCircuitCheck )
		{
		status = checkPathConstraints( subjectCertInfoPtr, value );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SUBJECTCERT_ERRINFO, 
					  "%s contains path constraint violation",
					  getCertTypeName( subjectCertInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "checkPathConstraints" );

	/* In order to dig itself out of a hole caused by a circular definition, 
	   RFC 3280 added a new extKeyUsage anyExtendedKeyUsage (rather than the
	   more obvious fix of removing the problematic definition).  
	   Unfortunately this causes more problems than it solves because the exact
	   semantics of this new usage aren't precisely defined.  To fix this 
	   problem we invent some plausible ones ourselves: If the only eKU is 
	   anyKU we treat the overall extKeyUsage as empty, i.e. there are no
	   particular restrictions on usage.  If any other usage is present then 
	   the extension has become self-contradictory so we treat the anyKU as
	   being absent.  See the comment for getExtendedKeyUsageFlags() for how
	   this is handled */
	attributePtr = findAttributeField( subjectAttributes,
									   CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE, 
									   CRYPT_ATTRIBUTE_NONE );
	if( DATAPTR_ISSET( attributePtr ) && \
		checkAttributeProperty( attributePtr, ATTRIBUTE_PROPERTY_CRITICAL ) )
		{
		/* If anyKU is present the extension must be non-critical 
		   (PKIX section 4.2.1.13) */
		setErrorValues( CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE, 
						CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO, 
				  "%s contains critical anyExtendedKeyUsage attribute",
				  getCertTypeName( subjectCertInfoPtr->type ) ) );
		}
	CFI_CHECK_UPDATE( "anyKeyUsage" );

	/* If this is a resource PKI (RPKI) certificate, apply RPKI-specific 
	   checks */
#ifdef USE_RPKI
	if( checkAttributePresent( subjectAttributes, \
							   CRYPT_CERTINFO_IPADDRESSBLOCKS ) || \
		checkAttributePresent( subjectAttributes, \
							   CRYPT_CERTINFO_AUTONOMOUSSYSIDS ) )
		{
		ANALYSER_HINT( subjectAttributes != NULL );

		status = checkRPKIAttributes( subjectAttributes, subjectIsCA,
									  subjectSelfSigned, errorLocus,
									  errorType );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, CERTIFICATE_ERRINFO, 
					  "%s contains invalid RPKI attributes",
					  getCertTypeName( subjectCertInfoPtr->type ) ) );
			}
		}
#endif /* USE_RPKI */
	CFI_CHECK_UPDATE( "rpkiAttributes" );

#ifdef USE_CERTLEVEL_PKIX_FULL
	/* If we're not doing full PKIX checking, we're done.  In addition since 
	   all of the remaining checks are constraint checks we can exit at this
	   point if we're doing a short-circuit check */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_FULL || \
		shortCircuitCheck )
		{
		if( subjectCertInfoPtr->cCertCert->maxCheckLevel < complianceLevel )
			subjectCertInfoPtr->cCertCert->maxCheckLevel = complianceLevel;
		ENSURES( CFI_CHECK_SEQUENCE_15( "IMESSAGE_GETATTRIBUTE", 
										"checkCertBasic", "checkKeyUsage", 
										"CRYPT_COMPLIANCELEVEL_REDUCED", 
										"checkVersion", "checkNameChaining", 
										"CRYPT_COMPLIANCELEVEL_STANDARD", 
										"checkKeyUsage", "checkKeyUsageIssuer",
										"checkAttributeProperty", 
										"CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL",
										"invalidAttributesPresent", 
										"checkPathConstraints", "anyKeyUsage",
										"rpkiAttributes" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CRYPT_COMPLIANCELEVEL_PKIX_FULL" );

	/* If the issuing certificate has name constraints and isn't 
	   self-signed make sure that the subject name and altName fall within 
	   the constrained subtrees.  Since excluded subtrees override permitted 
	   subtrees we check these first */
	if( !subjectSelfSigned )
		{
		attributePtr = findAttributeField( issuerAttributes, 
										   CRYPT_CERTINFO_EXCLUDEDSUBTREES,
										   CRYPT_ATTRIBUTE_NONE );
		if( DATAPTR_ISSET( attributePtr ) )
			{
			status = checkNameConstraints( subjectCertInfoPtr, attributePtr, 
										   TRUE );
			if( cryptStatusError( status ) )
				return( status );
			}
		attributePtr = findAttributeField( issuerAttributes, 
										   CRYPT_CERTINFO_PERMITTEDSUBTREES,
										   CRYPT_ATTRIBUTE_NONE );
		if( DATAPTR_ISSET( attributePtr ) )
			{
			status = checkNameConstraints( subjectCertInfoPtr, attributePtr, 
										   FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	CFI_CHECK_UPDATE( "checkNameConstraints" );

	/* If there's a policy constraint present and the skip count is set to 
	   zero (i.e. the constraint applies to the current certificate) check 
	   the issuer constraints against the subject */
	status = getAttributeFieldValue( issuerAttributes,
									 CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
									 CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusOK( status ) && value <= 0 )
		{
		POLICY_TYPE policyType = POLICY_SUBJECT;

		/* Check whether use of the the wildcard anyPolicy has been 
		   disallowed */
		attributePtr = findAttribute( issuerCertInfoPtr->attributes, 
									  CRYPT_CERTINFO_INHIBITANYPOLICY, 
									  TRUE );
		if( DATAPTR_ISSET( attributePtr ) && \
			cryptStatusOK( getAttributeDataValue( attributePtr, \
												  &value ) ) && \
			value <= 0 )
			policyType = POLICY_SUBJECT_SPECIFIC;

		/* Apply the appropriate policy constraint */
		status = checkPolicyConstraints( subjectCertInfoPtr,
										 issuerAttributes, policyType,
										 NULL, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "checkPolicyConstraints" );

	/* Enforce nesting of extKeyUsages if required.  This checks that 
	   subjects don't have any extKeyUsages not present in the issuer.  
	   Since no-one can agree on whether an extKeyUsage in a CA certificate 
	   applies to the CA's certificates or the certificates that it issues, 
	   this is disabled unless requested for a custom configuration */
#ifdef USE_CUSTOM_CONFIG_1
	status = checkExtKeyUsageNesting( subjectCertInfoPtr, issuerAttributes, 
									  errorLocus, errorType );
	if( cryptStatusError( status ) )
		return( status );
#endif /* USE_CUSTOM_CONFIG_1 */
	CFI_CHECK_UPDATE( "checkExtKeyUsageNesting" );

	/* If there's a clearance attribute present, make sure that the subject
	   only has clearances that are present in the issuer.  Conversely, if 
	   the issuer has a clearance attribute then the subject must have one 
	   too */
#ifdef USE_CUSTOM_CONFIG_1
	status = checkClearanceConstraints( subjectCertInfoPtr, issuerAttributes, 
										errorLocus, errorType );
	if( cryptStatusError( status ) )
		return( status );
#endif /* USE_CUSTOM_CONFIG_1 */
	CFI_CHECK_UPDATE( "checkClearanceConstraints" );
#endif /* USE_CERTLEVEL_PKIX_FULL */
#endif /* USE_CERTLEVEL_PKIX_PARTIAL */

	if( subjectCertInfoPtr->cCertCert->maxCheckLevel < complianceLevel )
		subjectCertInfoPtr->cCertCert->maxCheckLevel = complianceLevel;

#if defined( USE_CERTLEVEL_PKIX_FULL )
	ENSURES( CFI_CHECK_SEQUENCE_20( "IMESSAGE_GETATTRIBUTE", 
									"checkCertBasic", "checkKeyUsage", 
									"CRYPT_COMPLIANCELEVEL_REDUCED", 
									"checkVersion", "checkNameChaining", 
									"CRYPT_COMPLIANCELEVEL_STANDARD", 
									"checkKeyUsage", "checkKeyUsageIssuer",
									"checkAttributeProperty", 
									"CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL",
									"invalidAttributesPresent", 
									"checkPathConstraints", "anyKeyUsage",
									"rpkiAttributes", 
									"CRYPT_COMPLIANCELEVEL_PKIX_FULL", 
									"checkNameConstraints", 
									"checkPolicyConstraints",
									"checkExtKeyUsageNesting",
									"checkClearanceConstraints" ) );
#elif defined( USE_CERTLEVEL_PKIX_PARTIAL )
	ENSURES( CFI_CHECK_SEQUENCE_15( "IMESSAGE_GETATTRIBUTE", 
									"checkCertBasic", "checkKeyUsage", 
									"CRYPT_COMPLIANCELEVEL_REDUCED", 
									"checkVersion", "checkNameChaining", 
									"CRYPT_COMPLIANCELEVEL_STANDARD", 
									"checkKeyUsage", "checkKeyUsageIssuer",
									"checkAttributeProperty", 
									"CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL",
									"invalidAttributesPresent", 
									"checkPathConstraints", "anyKeyUsage",
									"rpkiAttributes" ) );
#else
	ENSURES( CFI_CHECK_SEQUENCE_10( "IMESSAGE_GETATTRIBUTE", 
									"checkCertBasic", "checkKeyUsage", 
									"CRYPT_COMPLIANCELEVEL_REDUCED", 
									"checkVersion", "checkNameChaining", 
									"CRYPT_COMPLIANCELEVEL_STANDARD", 
									"checkKeyUsage", "checkKeyUsageIssuer",
									"checkAttributeProperty" ) );
#endif /* CFI checks based on PKIX compliance levels */

	return( CRYPT_OK );
	}
#endif /* USE_CERTIFICATES */
