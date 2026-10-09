/****************************************************************************
*																			*
*						  Certificate Checking Routines						*
*						Copyright Peter Gutmann 1997-2025					*
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

/* Many of the checks applied here don't work, and in some cases were known
   not to work even as the standard was being written, an example being
   excludedSubtrees.  includedSubtrees are also bypassable with a bit of
   creativity, and the various policy constraints are both so complex and
   have so many booby-traps built into them, for example path-kludge
   certificates in the presence of policy constraints where even the 
   standards authors (PKIX) didn't know about the effect they had until 
   someone from the standard they'd been copied from (X.509) told them about
   it, that there's no way they should be relied on.  Because of this we 
   only enable them at USE_CERTLEVEL_PKIX_FULL in order to say that we're 
   compliant with at least one guess at what's required, and the manual 
   warns against both their use and relying on them and has recommendations
   for what to do to provide effective controls.
   
   For anyone reading this code, if you think the processing is convoluted
   and difficult to follow then try reading the 18-page-long version in the
   RFC, augmented by dozens of pages of additional comments and 
   requirements, many vague or contradictory, scattered throughout the rest
   of the RFC.  This is why the code makes numerous judgement calls to try
   and apply the principle of least surprise and reduce the chances of
   complexity-induced unexpected behaviour.
   
   "Everybody knows you never go full PKIX [...] You went full PKIX, man. 
    Never go full PKIX" - Robert Downey Jr (sort of) */

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
	return( ( cryptStatusOK( status ) && value > 0 ) ? TRUE : FALSE );
	}
#endif /* USE_CERTLEVEL_PKIX_FULL */

/****************************************************************************
*																			*
*								General Checks								*
*																			*
****************************************************************************/

/* Check the certificate version number */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkVersion( INOUT_PTR CERT_INFO *certInfoPtr,
						 IN_BOOL const BOOLEAN subjectSelfSigned )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus = &certInfoPtr->errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType = &certInfoPtr->errorType;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isBooleanValue( subjectSelfSigned ) );

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
					  "An X.509v1 certificate can only be a self-signed CA "
					  "root certificate" ) );
			}
		}

	return( CRYPT_OK );
	}

/* Check that the validity period is in order.  If we're checking an 
   existing certificate then the start time has to be valid, if we're 
   creating a new certificate then it doesn't have to be valid since the 
   certificate could be created for use in the future */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkCertValidityPeriod( INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus = &certInfoPtr->errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType = &certInfoPtr->errorType;
	const time_t currentTime = getTime( GETTIME_NONE );

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* If the time is broken then we can't reliably check for expiry times */
	if( currentTime <= MIN_TIME_VALUE )
		{
		setErrorValues( CRYPT_CERTINFO_VALIDFROM, CRYPT_ERRTYPE_CONSTRAINT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
				  "System time is broken, can't check %s validity",
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}

	/* Check that the object is within its validity period */
	if( certInfoPtr->startTime >= certInfoPtr->endTime || \
		( certInfoPtr->certificate != NULL && \
		  currentTime < certInfoPtr->startTime ) )
		{
		/* We fold the shouldn't-occur time value check into the can-occur
		   not-valid-yet check to save having to add an extra error report
		   for something that should never actually happen */
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
		
	return( CRYPT_OK );
	}

/* Check that the subject issuer name and issuer subject name chain 
   properly */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkNameChaining( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
							  const CERT_INFO *issuerCertInfoPtr )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus = &subjectCertInfoPtr->errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType = &subjectCertInfoPtr->errorType;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

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
			  "%s's issuer name doesn't match the name in the issuing "
			  "certificate", getCertTypeName( subjectCertInfoPtr->type ) ) );
	}

/* Check all the blob (unrecognised) attributes to see if any are marked 
   critical */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkUnrecognisedExtension( INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus = &certInfoPtr->errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType = &certInfoPtr->errorType;
	LOOP_INDEX_PTR DATAPTR_ATTRIBUTE attributePtr;
	ATTRIBUTE_ENUM_INFO attrEnumInfo;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

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
										const DATAPTR_ATTRIBUTE issuerAttributes )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus = &subjectCertInfoPtr->errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType = &subjectCertInfoPtr->errorType;
	DATAPTR_ATTRIBUTE attributePtr;
	LOOP_INDEX attributeID;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( DATAPTR_ISVALID( issuerAttributes ) );

	/* Check each extKeyUsage to make sure it's present in the issuer if 
	   present in the subject */
	LOOP_MED( attributeID = CRYPT_CERTINFO_EXTKEYUSAGE, 
			  attributeID <= CRYPT_CERTINFO_EXTKEYUSAGE_LAST, 
			  attributeID++ )
		{
		ENSURES( LOOP_INVARIANT_MED( attributeID, 
									 CRYPT_CERTINFO_EXTKEYUSAGE, 
									 CRYPT_CERTINFO_EXTKEYUSAGE_LAST ) );
		
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
		setErrorValues( CRYPT_CERTINFO_EXTKEYUSAGE, 
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
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
   matches for strings like www.barfoo.com).
   
   We choose to fail closed for permittedSubtrees (couldn't-resolve becomes
   FALSE, so not permitted) rather than excludedSubtrees, which are almost 
   trivially evaded through various name-form and encoding tricks and so 
   have next to no security relevance anyway */

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
	if( constrainingStringLength < 1 || constrainedStringLength < 1 )
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
	if( constrainingStringLength > constrainedStringLength )
		startPos = UNDERFLOW_MARKER;
	else
		{
		REQUIRES_B( !checkOverflowSub( constrainedStringLength, 
									   constrainingStringLength ) );
		startPos = constrainedStringLength - constrainingStringLength;
		}
	if( !isShortIntegerRange( startPos ) )
		return( FALSE );

	/* Handle special-case match requirements (PKIX section 4.2.1.11) */
	switch( matchType )
		{
		case MATCH_NONE:
			/* A DNS name constraint without a leading wildcard-match 
			   indicator has to match the entire subdomain, to avoid having 
			   "site.com" allow "badsite.com".  We check for this by 
			   verifying that there's a '.' at the start of the match 
			   substring portion of the constrained string */
			if( !isWildcardMatch && startPos > 0 && \
				constrainedString[ startPos - 1 ] != '.' )
				return( FALSE );
			break;
			
		case MATCH_EMAIL:
			/* Email addresses have a special-case requirement where the 
			   absence of a wildcard-match indicator (the leading dot)
			   indicates that the mailbox has to be located directly on the 
			   constraining hostname rather than merely within that domain, 
			   i.e. user@foo.bar.com is a valid match for .bar.com but not 
			   for bar.com, which would require user@bar.com to match */
			if( !isWildcardMatch )
				{
				if( strFindCh( constrainingString, 
							   constrainingStringLength, '@' ) >= 0 )
					{
					/* It's a complete mail address, it has to match the
					   entire constrained string */
					if( startPos != 0 )
						return( FALSE );
					}
				else
					{
					/* It's a bare host name, the mailbox has to be located
					   directly on that host */
					if( startPos < 1 || \
						constrainedString[ startPos - 1 ] != '@' )
						return( FALSE );
					}
				}
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
				   subtrees blocklist?  Even something as trivial as 
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
			if( constrainingStringLength > urlInfo.hostLen )
				startPos = UNDERFLOW_MARKER;
			else
				{
				REQUIRES_B( !checkOverflowSub( urlInfo.hostLen, 
											   constrainingStringLength ) );
	  			startPos = urlInfo.hostLen - constrainingStringLength;
	  			}
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
			
			break;
			}
		
		default:
			retIntError_Boolean();
		}
	ENSURES_B( boundsCheckZ( startPos, constrainingStringLength, \
							 constrainedStringLength ) );
			   /* This check is slightly weaker for the MATCH_URI case since
			      startPos is now relative to urlInfo.hostLen, but it checks
			      the overall condition without making it an over-complex
			      matchType-dependent check */

	/* Check whether the constraining string is a suffix of the constrained
	   string.  For DNS name constraints the rule for RFC 3280 became 
	   "adding to the LHS" as for other constraints, in RFC 2459 it was
	   another special case where it had to be a subdomain as if an 
	   implicit "." was present */
	return( strSame( constrainedString + startPos, constrainingString, 
					 constrainingStringLength ) );
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

		ENSURES_B( LOOP_INVARIANT_LARGE_GENERIC() );

		/* Step through the constraining attributes checking if any match 
		   the constrained attribute.  If it's an excluded subtree then none 
		   can match, if it's a permitted subtree then at least one must 
		   match */
		LOOP_LARGE_ALT( attributeCursor = attributePtr, 
						DATAPTR_ISSET( attributeCursor ) && !isMatch,
						attributeCursor = \
							findNextFieldInstance( attributeCursor ) )
			{
			ENSURES_B( LOOP_INVARIANT_LARGE_ALT_GENERIC() );

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
   CRYPT_COMPLIANCELEVEL_PKIX_FULL.  Note that this only checks for 
   actually-used name forms that we have at least an attempt at rules for, 
   but not the kitchen-sink otherName, registeredID, or ediPartyName, which
   in any case the spec (RFC 5280 section 4.2.1.10) disallows, [CA's] "SHOULD 
   NOT impose name constraints on the x400Address, ediPartyName, or 
   registeredID name forms" (excluding the kitchen-sink otherName, which 
   LAMPS is working on fuxing) while RFC 3280 (section 4.2.1.11) just 
   applied the standard someone-else's-problem, "the syntax and semantics 
   for name constraints for otherName, ediPartyName, and registeredID are 
   not defined by this specification".  RFC 3280 also made X.400 enforcement
   a MUST while RFC 5280 did the exact opposite and made it a SHOULD NOT.
   
   It also, as a design decision, doesn't check for name constraints on IP 
   addresses, which we've never seen used since support for name constraints 
   was first added in cryptlib 3.1.0 in 2003 and which would therefore leave 
   the checks as yet another set of never-exercised code paths alongside most 
   of the other CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL/
   CRYPT_COMPLIANCELEVEL_PKIX_FULL code.
   
   The (non-)handling of IP addresses is compliant with RFC 3280 section 
   4.2.1.11 which never set any requirements for enforcement, but not the 
   changed RFC 5280 section 4.2.1.10 which requires that "if a name 
   constraints extension that is marked as critical imposes constraints on 
   a particular name form, and an instance of that name form appears in the 
   subject field or subjectAltName extension of a subsequent certificate, 
   then the application MUST either process the constraint or reject the 
   certificate"
   
   This means that when the code was originally written based on RFC 2459 
   and RFC 3280, not enforcing the IP address constraints was compliant. 
   After RFC 5280 changed the requirements it was no longer compliant, but
   by that time long real-world experience had led to most of the PKIX 
   folderol being relegated to CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL / 
   CRYPT_COMPLIANCELEVEL_PKIX_FULL for purposes of attack surface reduction
   which means that had it been present it wouldn't have been enabled.  So
   it fell into a crack between "religiously implement (almost) everything 
   no matter how crazy" when it wasn't required, and the current "implement
   only what actually gets used and makes sense in order to keep the attack 
   surface down" when it is */

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
	const char *errorDescription = isExcluded ? "excluded" : "not permitted";
	BOOLEAN isMatch = FALSE;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( subjectCertInfoPtr ) );
	REQUIRES( DATAPTR_ISVALID( issuerAttributes ) );
			  /* This isn't actually the full attribute list but the first 
			     permitted/excluded subtrees attribute in the list, which
			     has been located by the caller when checking whether we
			     need to be called */
	REQUIRES( isBooleanValue( isExcluded ) );

	/* Get references to the certificate's error information */
	errorLocus = &subjectCertInfoPtr->errorLocus;
	errorType = &subjectCertInfoPtr->errorType;

	/* If this is a PKIX path-kludge CA certificate then the name 
	   constraints don't apply to it (RFC 3280 section 4.2.1.11).  This is 
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
	   least one must match.  We don't perform the check in the special 
	   case of an empty subject DN, which acts as a wildcard that 
	   matches/doesn't match permitted/excluded as required (RFC 5280
	   section 4.2.1.10) */
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
					  "%s subject name is %s by name constraint",
					  getCertTypeName( subjectCertInfoPtr->type ),
					  errorDescription ) );
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
				  "%s alternative name DN is %s by name constraint",
				  getCertTypeName( subjectCertInfoPtr->type ),
				  errorDescription ) );
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
				  "%s alternative email/DNS/URL name is %s by name "
				  "constraint",
				  getCertTypeName( subjectCertInfoPtr->type ),
				  errorDescription ) );
		}

	return( CRYPT_OK );
	}

/* Check that the name-matching functions are working as expected */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA 

typedef struct {
	const char *constrainedString;
	const int constrainedStringLength;
	const char *constrainingString;
	const int constrainingStringLength;
	const MATCH_TYPE matchType;
	const int matchResult;
	} MATCH_TEST_INFO;

static const MATCH_TEST_INFO matchTestInfo[] = {
	/* RFC 5280 worked examples (section 4.2.1.10), more in the email 
	   section */
	{ "www.foo.bar.com", 15, "foo.bar.com", 11, MATCH_NONE, TRUE },
	{ "foo1.bar.com", 12, "foo.bar.com", 11, MATCH_NONE, FALSE },

	/* Case-insensitive matching */
	{ "WWW.FOO.COM", 11, ".foo.com", 8, MATCH_NONE, TRUE },

	/* Identity-transformation match */
	{ "foo.com", 7, "foo.com", 7, MATCH_NONE, TRUE },

	/* Leading-dot constraints which match subdomains at any depth but not 
	   the domain itself, e.g. ".xyz.com" allows abc.xyz.com and 
	   abc.def.xyz.com but not xyz.com */
	{ "www.foo.com", 11, ".foo.com", 8, MATCH_NONE, TRUE },
	{ "a.b.foo.com", 11, ".foo.com", 8, MATCH_NONE, TRUE },
	{ "foo.com", 7, ".foo.com", 8, MATCH_NONE, FALSE },

	/* Leading dots prevent a substring false match */
	{ "barfoo.com", 10, ".foo.com", 8, MATCH_NONE, FALSE },
	{ "barfoo.com", 10, "foo.com", 7, MATCH_NONE, FALSE },

	/* URI constraints apply to the host portion of the name */
	{ "http://barfoo.com", 17, "foo.com", 7, MATCH_URI, FALSE },
	{ "http://foo.com/path", 19, "foo.com", 7, MATCH_URI, TRUE },
	{ "http://www.foo.com/xyz", 22, ".foo.com", 8, MATCH_URI, TRUE },	

	/* Complete-email-address match */
	{ "root@example.com", 16, "root@example.com", 16, MATCH_EMAIL, TRUE },
	{ "toor@example.com", 16, "root@example.com", 16, MATCH_EMAIL, FALSE },
	{ "notroot@example.com", 19, "root@example.com", 16, MATCH_EMAIL, FALSE },
	{ "root@example.com", 16, "ROOT@EXAMPLE.COM", 16, MATCH_EMAIL, TRUE },

	/* Email host-name match where the mailbox has to be located directly on 
	   the constraining host */
	{ "root@example.com", 16, "example.com", 11, MATCH_EMAIL, TRUE },
	{ "root@mail.example.com", 21, "example.com", 11, MATCH_EMAIL, FALSE },
	{ "root@badexample.com", 19, "example.com", 11, MATCH_EMAIL, FALSE },
	{ "example.com", 11, "example.com", 11, MATCH_EMAIL, FALSE },

	/* Email domain match which matches subdomains but not the domain 
	   itself */
	{ "root@mail.example.com", 21, ".example.com", 12, MATCH_EMAIL, TRUE },
	{ "root@example.com", 16, ".example.com", 12, MATCH_EMAIL, FALSE },
	{ "root@badexample.com", 19, ".example.com", 12, MATCH_EMAIL, FALSE },

	/* More tests TBD */
	{ "a@b.com", 7, "*@b.com", 7, MATCH_EMAIL, FALSE },
		{ NULL, 0 }, { NULL, 0 }
	};

CHECK_RETVAL_BOOL \
BOOLEAN checkNameMatch( void )
	{
	ERROR_INFO errorInfo;
	CRYPT_ATTRIBUTE_TYPE errorLocus;
	CRYPT_ERRTYPE_TYPE errorType;
	LOOP_INDEX i;
	int status;
	
	/* This code is still under development pending the LAMPS WG's attempt 
	   to resolve the PKIX name-matching mess.  At the moment it just tests
	   basic DNS name handling, which is what approximately 100% of cases 
	   will be, and email, because it's unclear what correct behaviour for 
	   the rest will actually be */
	clearErrorInfo( &errorInfo );
	LOOP_MED( i = 0, i < FAILSAFE_ARRAYSIZE( matchTestInfo, \
											 MATCH_TEST_INFO ) && \
					 matchTestInfo[ i ].constrainedString != NULL, i++ )
		{
		DATAPTR constrainedName, constrainingName;
		BOOLEAN matchResult;
		
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( matchTestInfo, \
														 MATCH_TEST_INFO ) - 1 ) );

		DATAPTR_SET( constrainedName, NULL );
		status = addAttributeFieldString( &constrainedName, 
					CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, CRYPT_ATTRIBUTE_NONE,
					matchTestInfo[ i ].constrainedString, 
					matchTestInfo[ i ].constrainedStringLength, ATTR_FLAG_NONE, 
					FALSE, &errorInfo, &errorLocus, &errorType  );
		ENSURES( cryptStatusOK( status ) );
		DATAPTR_SET( constrainingName, NULL );
		status = addAttributeFieldString( &constrainingName, 
					CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, CRYPT_ATTRIBUTE_NONE,
					matchTestInfo[ i ].constrainingString, 
					matchTestInfo[ i ].constrainingStringLength, ATTR_FLAG_NONE, 
					FALSE, &errorInfo, &errorLocus, &errorType  );
		ENSURES( cryptStatusOK( status ) );
		matchResult = wildcardMatch( constrainedName, constrainingName, 
									 matchTestInfo[ i ].matchType );
		status = deleteAttributeField( &constrainedName, NULL, 
									   constrainedName, NULL );
		ENSURES( cryptStatusOK( status ) );
		status = deleteAttributeField( &constrainingName, NULL, 
									   constrainingName, NULL );
		ENSURES( cryptStatusOK( status ) );
		if( matchResult != matchTestInfo[ i ].matchResult )
			{
			DEBUG_DIAG(( "wildcardMatch() test %d failed", i ));
			return( FALSE );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
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
		ENSURES_B( LOOP_INVARIANT_LARGE_GENERIC() );

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

	REQUIRES_B( DATAPTR_ISVALID( attributePtr ) );
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
		ENSURES_B( LOOP_INVARIANT_LARGE_GENERIC() );

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
static BOOLEAN isPolicyPresent( IN_DATAPTR \
									const DATAPTR_ATTRIBUTE subjectAttributes,
								IN_BUFFER( issuerPolicyValueLength ) \
									const void *issuerPolicyValue,
								IN_LENGTH_OID \
									const int issuerPolicyValueLength )
	{
	LOOP_INDEX_PTR DATAPTR_ATTRIBUTE attributeCursor;
	int status;

	assert( isReadPtrDynamic( issuerPolicyValue, issuerPolicyValueLength ) );

	REQUIRES_B( DATAPTR_ISVALID( subjectAttributes ) );
			  /* This isn't actually the full attribute list but the first 
			     policy attribute in the list, which has been located by the 
			     caller when checking whether we need to be called */
	REQUIRES_B( issuerPolicyValueLength > 0 && \
				issuerPolicyValueLength < MAX_POLICY_SIZE );

	LOOP_LARGE( attributeCursor = subjectAttributes, 
				DATAPTR_ISSET( attributeCursor ),
				attributeCursor = findNextFieldInstance( attributeCursor ) )
		{
		void *subjectPolicyValuePtr;
		int subjectPolicyValueLength;

		ENSURES_B( LOOP_INVARIANT_LARGE_GENERIC() );

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
	if( ( policyType == POLICY_NONE || \
		  policyType == POLICY_NONE_SPECIFIC ) && \
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
					DATAPTR_ISSET( constrainingAttributeCursor ), 
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
						  IN_LENGTH_SHORT_Z const int pathLength,
						  IN_BOOL const BOOLEAN issuerIsSubject )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
	int value, status;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

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

	/* If the path length came from the subject certificate's own attributes,
	   meaning that the certificate is being checked against itself, then a 
	   path length constraint of zero is valid */
	if( issuerIsSubject )
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

/* If there's an RFC 5755 clearance attribute present, make sure that the 
   subject only has clearances that are present in the issuer.  Conversely, 
   if the issuer has a clearance attribute then the subject must have one 
   too */

#ifdef USE_CUSTOM_CONFIG_1

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkClearanceConstraints( INOUT_PTR CERT_INFO *subjectCertInfoPtr,
									  IN_DATAPTR \
										const DATAPTR_ATTRIBUTE issuerAttributes )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus = &subjectCertInfoPtr->errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType = &subjectCertInfoPtr->errorType;
	int value, status;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( DATAPTR_ISVALID( issuerAttributes ) );

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
			setErrorValues( CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST, 
							CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO, 
					  "Subject %s contains Clearance attribute value %X but "
					  "issuer doesn't", 
					  getCertTypeNameLC( subjectCertInfoPtr->type ), 
					  subjectClearance ) );
			}
		if( ( subjectClearance & ~value ) != 0 )
			{
			setErrorValues( CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST, 
							CRYPT_ERRTYPE_ISSUERCONSTRAINT );
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
	status = getAttributeFieldValue( issuerAttributes, 
							CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST, 
							CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusOK( status ) )
		{
		setErrorValues( CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST, 
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
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

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkRPKIAttributes( INOUT_PTR CERT_INFO *certInfoPtr,
								IN_BOOL const BOOLEAN isCA,
								IN_BOOL const BOOLEAN isSelfSigned )

	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus = &certInfoPtr->errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType = &certInfoPtr->errorType;
	DATAPTR_ATTRIBUTE attributePtr;
	void *policyOidPtr;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int policyOidLength, value, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isBooleanValue( isCA ) );
	REQUIRES( isBooleanValue( isSelfSigned ) );

	/* Check that there's a keyUsage present, and that for CA certificates 
	   it's the CA usages and for EE certificates it's digital signature 
	   (RPKI section 3.9.4) */
	status = getAttributeFieldValue( certInfoPtr->attributes,
									 CRYPT_CERTINFO_KEYUSAGE, 
									 CRYPT_ATTRIBUTE_NONE, &value );
	if( cryptStatusError( status ) )
		{
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE, CRYPT_ERRTYPE_ATTR_ABSENT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
				  "RPKI %s doesn't contain a keyUsage attribute",
				  getCertTypeNameLC( certInfoPtr->type ) ) );
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
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}
	CFI_CHECK_UPDATE( "getAttributeFieldValue" );

	/* If it's a CA, check that there's no extendedKeyUsage (RPKI section 
	   3.9.5) and there's a caRepository SIA (RPKI section 3.9.8) */
	if( isCA )
		{
		if( checkAttributePresent( certInfoPtr->attributes, 
								   CRYPT_CERTINFO_EXTKEYUSAGE ) )
			{
			setErrorValues( CRYPT_CERTINFO_EXTKEYUSAGE, 
							CRYPT_ERRTYPE_ATTR_PRESENT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "RPKI CA %s contains extKeyUsage attribute",
					  getCertTypeNameLC( certInfoPtr->type ) ) );
			}
		if( !checkAttributeFieldPresent( certInfoPtr->attributes,
								CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY ) )
			{
			setErrorValues( CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY, 
							CRYPT_ERRTYPE_ATTR_ABSENT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "RPKI CA %s doesn't contain caRepository attribute",
					  getCertTypeNameLC( certInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "checkAttributePresent" );

	/* If it's not self-signed (i.e. not a root certificate) check that
	   there's a caIssuers AIA (RPKI section 3.9.7) */
	if( !isSelfSigned )
		{
		if( !checkAttributeFieldPresent( certInfoPtr->attributes,
								CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS ) )
			{
			setErrorValues( CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS, 
							CRYPT_ERRTYPE_ATTR_ABSENT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
					  "RPKI %s doesn't contain caIssuers attribute",
					  getCertTypeNameLC( certInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "checkAttributeFieldPresent" );

	/* Check that there's an RPKI policy present (RPKI section 3.9.9) */
	attributePtr = findAttributeField( certInfoPtr->attributes,
									   CRYPT_CERTINFO_CERTPOLICYID,
									   CRYPT_ATTRIBUTE_NONE );
	if( DATAPTR_ISNULL( attributePtr ) )
		{
		setErrorValues( CRYPT_CERTINFO_CERTPOLICYID, 
						CRYPT_ERRTYPE_ATTR_ABSENT );
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO,
				  "RPKI %s doesn't contain a policy attribute",
				  getCertTypeNameLC( certInfoPtr->type) ) );
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
				  "RPKI %s's policy attribute isn't for the RPKI policy",
				  getCertTypeNameLC( certInfoPtr->type ) ) );
		}
	CFI_CHECK_UPDATE( "findAttributeField" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "getAttributeFieldValue", 
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
	const void *baseCRLnumber DUMMY_INIT_PTR;
	int baseCRLnumberLen DUMMY_INIT, status = CRYPT_OK;
#else
	int baseCRLnumber, status;
#endif /* CONFIG_CUSTOM_1 */

	assert( isWritePtr( crlInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( complianceLevel >= CRYPT_COMPLIANCELEVEL_OBLIVIOUS && \
			  complianceLevel < CRYPT_COMPLIANCELEVEL_LAST );

	/* Get references to the certificate's error information */
	errorLocus = &crlInfoPtr->errorLocus;
	errorType = &crlInfoPtr->errorType;

	/* If it's a delta CRL make sure that the CRL numbers make sense, i.e.
	   that the base CRL number given in the delta CRL indicator is lower
	   than the (delta CRL's own) CRL number (RFC 3280 section 5.2.4).  So 
	   if the base CRL contains a CRL number b and the delta CRL contains a 
	   CRL number d and delta CRL indicator d_b == b then we must have 
	   d_b < d in the delta CRL.  
	   
	   The spec (RFC 3280 section 5.2.4) states that "If a delta CRL and a 
	   complete CRL that cover the same scope are issued at the same time, 
	   they MUST have the same CRL number and provide the same revocation 
	   information" which would imply that the CRL number and delta CRL 
	   indicator containing the base CRL's CRL number would have the same 
	   value.  This doesn't make any sense so we enforce the d_b < d 
	   requirement.
	   
	   There are also a pile of additional conditions (RFC 3280 section 
	   5.2.4 again) required to combine the base with the delta CRL, but 
	   that's for the caller to check since we only have the delta CRL 
	   available here.
	   
	   All of which are probably moot because delta CRLs, along with large
	   amounts of other PKI folderol, are essentially if not actually 
	   nonexistent */
#ifdef CONFIG_CUSTOM_1
	attributePtr = findAttributeField( crlInfoPtr->attributes,
									   CRYPT_CERTINFO_DELTACRLINDICATOR, 
									   CRYPT_ATTRIBUTE_NONE );
	if( DATAPTR_ISSET( attributePtr ) )
		{
		status = getAttributeDataPtr( attributePtr, 
									  ( void ** ) &baseCRLnumber, 
									  &baseCRLnumberLen );
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
			( crlNumberLen < baseCRLnumberLen || \
			  ( crlNumberLen == baseCRLnumberLen && \
				memcmp( crlNumber, baseCRLnumber, crlNumberLen ) <= 0 ) ) )
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
									 &baseCRLnumber );
	if( cryptStatusOK( status ) )
		{
		int crlNumber;

		status = getAttributeFieldValue( crlInfoPtr->attributes,
										 CRYPT_CERTINFO_CRLNUMBER, 
										 CRYPT_ATTRIBUTE_NONE, &crlNumber );
		if( cryptStatusOK( status ) && crlNumber <= baseCRLnumber )
			{
			setErrorValues( CRYPT_CERTINFO_DELTACRLINDICATOR,
							CRYPT_ERRTYPE_CONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CRL_ERRINFO,
					  "%s base CRL number %d is greater than delta CRL "
					  "number %d", getCertTypeNameLC( crlInfoPtr->type ),
					  baseCRLnumber, crlNumber ) );
			}
		}
#endif /* CONFIG_CUSTOM_1 */

	/* If it's a standalone CRL entry used purely as a container for 
	   revocation data don't try and perform any issuer-based checking */
	if( issuerCertInfoPtr == NULL )
		return( CRYPT_OK );

	/* Check that the validity period is in order */
	status = checkCertValidityPeriod( crlInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the issuer can sign CRLs and that the issuer 
	   certificate in general is in order */
	status = checkKeyUsage( issuerCertInfoPtr, 
							CHECKKEY_FLAG_CA | CHECKKEY_FLAG_GENCHECK, 
							CRYPT_KEYUSAGE_CRLSIGN, complianceLevel,
							crlInfoPtr );
	if( cryptStatusError( status ) )
		{
		/* There's a problem with the issuer certificate, set a general
		   error status indicating this for the CRL */
		setErrorValues( CRYPT_CERTINFO_KEYUSAGE,
						CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		retExtErr( status,
				   ( status, CRL_ERRINFO, CRL_ERRINFO,
					 "Issuer certificate isn't capable of CRL signing" ) );
		}

	/* Make sure that the issuer actually issued this CRL */
	status = checkNameChaining( crlInfoPtr, issuerCertInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
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
int checkCertBasic( INOUT_PTR CERT_INFO *certInfoPtr,
					IN_BOOL const BOOLEAN fullComplianceCheck )
	{
	CRYPT_ATTRIBUTE_TYPE *errorLocus;
	CRYPT_ERRTYPE_TYPE *errorType;
	int complianceLevel, status;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );
	REQUIRES( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CRL );
	REQUIRES( isBooleanValue( fullComplianceCheck ) );

	/* Get references to the certificate's error information */
	errorLocus = &certInfoPtr->errorLocus;
	errorType = &certInfoPtr->errorType;

	/* Determine how much checking we need to perform.  If this is a 
	   currently-under-construction certificate then we use the maximum 
	   compliance level to ensure that cryptlib never produces broken 
	   certificates */
	if( fullComplianceCheck )
		complianceLevel = CRYPT_COMPLIANCELEVEL_PKIX_FULL;
	else
		{
		status = krnlSendMessage( certInfoPtr->ownerHandle, 
								  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
								  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* There is one universal case in which a certificate is regarded as 
	   invalid and that's when it's explicitly not trusted */
	if( certInfoPtr->type != CRYPT_CERTTYPE_CRL )
		{
		const CERT_CERT_INFO *certInfo = DATAPTR_GET_CERT( certInfoPtr );

		REQUIRES( certInfo != NULL );

		if( certInfo->trustedUsage == 0 )
			{
			setErrorValues( CRYPT_CERTINFO_TRUSTED_USAGE,
							CRYPT_ERRTYPE_CONSTRAINT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, CERTIFICATE_ERRINFO, 
					  "%s isn't trusted for any usage",
					  getCertTypeName( certInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "trustedUsage" );

	/* If we're running in oblivious mode, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_REDUCED )
		{
		ENSURES( CFI_CHECK_SEQUENCE_1( "trustedUsage" ) );

		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CRYPT_COMPLIANCELEVEL_REDUCED" );

	/* Check that the validity period is in order */
	status = checkCertValidityPeriod( certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "validityPeriod" );

	ENSURES( CFI_CHECK_SEQUENCE_3( "trustedUsage", 
								   "CRYPT_COMPLIANCELEVEL_REDUCED", 
								   "validityPeriod" ) );

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
	const CERT_CERT_INFO *issuerCertInfo;
	CERT_CERT_INFO *subjectCertInfo;
	DATAPTR_ATTRIBUTE subjectAttributes;
	const BOOLEAN issuerIsSubject = \
			( issuerCertInfoPtr == subjectCertInfoPtr ) ? TRUE : FALSE;
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

	/* Get certificate information.  For the significance of the self-signed
	   flag, see the long comment in cert/read.c:readCertInfo() */
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
			   much checking here as it would reject inconsistent but valid
			   requests.  This means that the actual checking only occurs at
			   the cryptSignCert() stage once the data in the certificate has
			   been reconciled by the CA */
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
			/* These aren't normal certificate types, none of the standard
			   certificate checks apply.  We can't even check the issuer 
			   since they're not normally issued by CAs, however for OCSP
			   responses the one thing that we do need to check is whether
			   they're allowed to sign responses */
			if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
				{
				static const int ekuValue = CRYPT_CERTINFO_EXTKEY_OCSPSIGNING;

				REQUIRES( issuerCertInfoPtr != NULL )

				/* Check whether the certificate is valid for this purpose 
				   using the usual PKIX fail-open checking mechanism */
				status = krnlSendMessage( issuerCertInfoPtr->objectHandle, 
										  IMESSAGE_COMPARE,
										  ( MESSAGE_CAST ) &ekuValue,
										  MESSAGE_COMPARE_EKU );
				if( cryptStatusError( status ) )
					{
					retExt( CRYPT_ERROR_INVALID,
							( CRYPT_ERROR_INVALID, SUBJECTCERT_ERRINFO,
							  "Signing certificate isn't valid for OCSP "
							  "signing" ) );
					}
				}
			ENSURES( CFI_CHECK_SEQUENCE_1( "IMESSAGE_GETATTRIBUTE" ) );
			return( CRYPT_OK );

		default:
			retIntError();
		}
	ENSURES( issuerCertInfoPtr != NULL );
	ENSURES( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			 subjectCertInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			 subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );
	subjectCertInfo = DATAPTR_GET_CERT( subjectCertInfoPtr );
	REQUIRES( subjectCertInfo != NULL );
	issuerCertInfo = DATAPTR_GET_CERT( issuerCertInfoPtr );
	REQUIRES( issuerCertInfo != NULL );

	/* Perform a basic check for obvious invalidity issues */
	status = checkCertBasic( subjectCertInfoPtr, 
				( complianceLevel == CRYPT_COMPLIANCELEVEL_PKIX_FULL ) ? \
				  TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkCertBasic" );

	/* There is one universal case in which a certificate is regarded as 
	   invalid and that's when the issuing certificate isn't trusted as an 
	   issuer.  We perform the check in oblivious mode to ensure that only 
	   the basic trusted usage gets checked at this point */
	if( issuerCertInfo->trustedUsage != CRYPT_ERROR )
		{
		status = checkKeyUsage( issuerCertInfoPtr, CHECKKEY_FLAG_CA, 
								CRYPT_KEYUSAGE_KEYCERTSIGN,
								CRYPT_COMPLIANCELEVEL_OBLIVIOUS,
								subjectCertInfoPtr );
		if( cryptStatusError( status ) )
			{
			/* There's a problem with the issuer certificate, set a 
			   general error status indicating this for the subject 
			   certificate */
			setErrorValues( CRYPT_CERTINFO_KEYUSAGE,
							CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			retExt( status,
					( status, SUBJECTCERT_ERRINFO,
					  "Issuer certificate isn't trusted to sign this %s",
					  getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
			}
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

	/* Check name chaining.  We do this even for self-signed certificates 
	   because a caller could in theory pass us a self-signed subject 
	   certificate as the one to check and something else as the issuer 
	   certificate which leads to an undefined result since it's not clear
	   whether we're being asked to check the subject certificate, which 
	   will be valid since it's self-signed, or the subject certificate in
	   the context of the issuer certificate, which won't be valid.
	   
	   We can't use the other alternative of always requiring that the 
	   issuer certificate is set to CRYPT_UNUSED if the subject is self-
	   signed because cryptlib checks created (self-signed) certificates 
	   by passing them as both the subject and issuer.
	   
	   The chaining check and the issuer-is-CA check that follows it are 
	   placed here because the cached-check-result early-exit below is 
	   associated with the certificate being checked, not the combination 
	   of certificate and issuer, so in theory if a certificate is checked 
	   against issuer1, the check result recorded, and it's then checked 
	   against issuer2 identifying as issuer1, the result would be the 
	   cached result from the issuer1 check rather than a new issuer2 
	   check.
	   
	   It's not clear how these situations could ever arise apart from as a 
	   programming error, but the checks are cheap so we place them here 
	   rather than after the already-checked early exit */
	status = checkNameChaining( subjectCertInfoPtr, issuerCertInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkNameChaining" );

	/* Check that the issuer is a CA if required.  The only exception is for 
	   a self-signed certificate being checked against itself as it's being
	   created, which requires both conditions below to hold.  Testing only
	   issuerIsSubject would also skip the check when the same object is 
	   passed for both but the certificate isn't self-signed, and testing 
	   only subjectSelfSigned would skip it for a self-signed certificate 
	   being checked against a different issuer certificate, which would 
	   allow a non-CA certificate to appear to be an issuer */
	if( !( issuerIsSubject && subjectSelfSigned ) )
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
			retExtErr( status,
					   ( status, SUBJECTCERT_ERRINFO, SUBJECTCERT_ERRINFO,
						 "Issuer certificate isn't valid for signing "
						 "this %s",
						 getCertTypeNameLC( subjectCertInfoPtr->type ) ) );
			}
		}
	CFI_CHECK_UPDATE( "checkKeyUsageIssuer" );

	/* If we're doing a short-circuit check of a certificate in a chain 
	   that's already been checked and we've already checked it at the 
	   appropriate level then there's no need to perform any further checks */
	if( shortCircuitCheck && \
		( subjectCertInfo->maxCheckLevel >= complianceLevel ) )
		{
		ENSURES( CFI_CHECK_SEQUENCE_6( "IMESSAGE_GETATTRIBUTE", 
									   "checkCertBasic", "checkKeyUsage",
									   "CRYPT_COMPLIANCELEVEL_REDUCED",
									   "checkNameChaining", 
									   "checkKeyUsageIssuer" ) );
		return( CRYPT_OK );
		}

	/* Perform certificate object-type-specific version checks */
	status = checkVersion( subjectCertInfoPtr, subjectSelfSigned );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkVersion" );

	/* If we're doing a reduced level of checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_STANDARD )
		{
		if( subjectCertInfo->maxCheckLevel < complianceLevel )
			subjectCertInfo->maxCheckLevel = complianceLevel;
		ENSURES( CFI_CHECK_SEQUENCE_7( "IMESSAGE_GETATTRIBUTE", 
									   "checkCertBasic", "checkKeyUsage", 
									   "CRYPT_COMPLIANCELEVEL_REDUCED", 
									   "checkNameChaining", 
									   "checkKeyUsageIssuer", 
									   "checkVersion" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CRYPT_COMPLIANCELEVEL_STANDARD" );

	/* Check that the certificate usage flags are present and consistent.  
	   The key usage checking level ranges up to 
	   CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL so we re-do the check even if it's 
	   already been done at a lower level */
	if( subjectCertInfo->maxCheckLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL && \
		subjectCertInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		status = checkKeyUsage( subjectCertInfoPtr, CHECKKEY_FLAG_GENCHECK, 
								CRYPT_KEYUSAGE_NONE, complianceLevel, 
								subjectCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "checkKeyUsage" );

	/* Check all the blob (unrecognised) attributes to see if any are marked 
	   critical.  We only do this if it's an existing certificate that we've
	   imported rather than one that we've just created since applying this 
	   check to the latter would make it impossible to create certificates 
	   with unrecognised critical extensions */
	if( subjectCertInfoPtr->certificate != NULL )
		{
		status = checkUnrecognisedExtension( subjectCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}
	CFI_CHECK_UPDATE( "checkAttributeProperty" );

#ifdef USE_CERTLEVEL_PKIX_PARTIAL
	/* If we're not doing at least partial PKIX checking, we're done */
	if( complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		{
		if( subjectCertInfo->maxCheckLevel < complianceLevel )
			subjectCertInfo->maxCheckLevel = complianceLevel;
		ENSURES( CFI_CHECK_SEQUENCE_10( "IMESSAGE_GETATTRIBUTE", 
										"checkCertBasic", "checkKeyUsage", 
										"CRYPT_COMPLIANCELEVEL_REDUCED", 
										"checkNameChaining", 
										"checkKeyUsageIssuer", "checkVersion",
										"CRYPT_COMPLIANCELEVEL_STANDARD", 
										"checkKeyUsage", 
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
			/* A self-signed or X509v1 certificate isn't a CA but is a
			   certificate that's issued itself, so we check for CA 
			   attributes and also report it (via invalidAttributesPresent()
			   as an issuer constraint since the subject is the issuer */
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
		status = checkPathConstraints( subjectCertInfoPtr, value, 
									   issuerIsSubject );
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
		status = checkRPKIAttributes( subjectCertInfoPtr, subjectIsCA,
									  subjectSelfSigned );
		if( cryptStatusError( status ) )
			return( status );
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
		if( subjectCertInfo->maxCheckLevel < complianceLevel )
			subjectCertInfo->maxCheckLevel = complianceLevel;
		ENSURES( CFI_CHECK_SEQUENCE_15( "IMESSAGE_GETATTRIBUTE", 
										"checkCertBasic", "checkKeyUsage", 
										"CRYPT_COMPLIANCELEVEL_REDUCED", 
										"checkNameChaining", 
										"checkKeyUsageIssuer", "checkVersion", 
										"CRYPT_COMPLIANCELEVEL_STANDARD", 
										"checkKeyUsage", 
										"checkAttributeProperty", 
										"CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL",
										"invalidAttributesPresent", 
										"checkPathConstraints", "anyKeyUsage",
										"rpkiAttributes" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CRYPT_COMPLIANCELEVEL_PKIX_FULL" );

	/* If the issuing certificate has name constraints and we're not 
	   checking a certificate against itself, make sure that the subject 
	   name and altName fall within the constrained subtrees.  Since 
	   excluded subtrees override permitted subtrees we check these first.
	   
	   The exception to the checking is for a certificate being checked 
	   against itself, not for self-signed certificates in general.  RFC 
	   5280 (section 6.1.3) skips name constraints for self-signed 
	   certificates only when they aren't the final certificate in the path, 
	   and that part of the rule is handled inside checkNameConstraints() 
	   via the path-kludge check.  The certificate-chain assembly code marks 
	   chain-internal self-signed certificates as path kludges but leaves 
	   the leaf alone.  If we made the check conditional on 
	   CERT_FLAG_SELFSIGNED it wouldn't check a self-signed leaf 
	   certificate */
	if( !issuerIsSubject )
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
		attributePtr = findAttribute( issuerAttributes, 
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
	status = checkExtKeyUsageNesting( subjectCertInfoPtr, issuerAttributes );
	if( cryptStatusError( status ) )
		return( status );
#endif /* USE_CUSTOM_CONFIG_1 */
	CFI_CHECK_UPDATE( "checkExtKeyUsageNesting" );

	/* If there's a clearance attribute present, make sure that the subject
	   only has clearances that are present in the issuer.  Conversely, if 
	   the issuer has a clearance attribute then the subject must have one 
	   too */
#ifdef USE_CUSTOM_CONFIG_1
	status = checkClearanceConstraints( subjectCertInfoPtr, 
										issuerAttributes );
	if( cryptStatusError( status ) )
		return( status );
#endif /* USE_CUSTOM_CONFIG_1 */
	CFI_CHECK_UPDATE( "checkClearanceConstraints" );
#endif /* USE_CERTLEVEL_PKIX_FULL */
#endif /* USE_CERTLEVEL_PKIX_PARTIAL */

	if( subjectCertInfo->maxCheckLevel < complianceLevel )
		subjectCertInfo->maxCheckLevel = complianceLevel;

#if defined( USE_CERTLEVEL_PKIX_FULL )
	ENSURES( CFI_CHECK_SEQUENCE_20( "IMESSAGE_GETATTRIBUTE", 
									"checkCertBasic", "checkKeyUsage", 
									"CRYPT_COMPLIANCELEVEL_REDUCED", 
									"checkNameChaining", 
									"checkKeyUsageIssuer", "checkVersion", 
									"CRYPT_COMPLIANCELEVEL_STANDARD", 
									"checkKeyUsage", 
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
									"checkNameChaining", 
									"checkKeyUsageIssuer", "checkVersion", 
									"CRYPT_COMPLIANCELEVEL_STANDARD", 
									"checkKeyUsage",
									"checkAttributeProperty", 
									"CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL",
									"invalidAttributesPresent", 
									"checkPathConstraints", "anyKeyUsage",
									"rpkiAttributes" ) );
#else
	ENSURES( CFI_CHECK_SEQUENCE_10( "IMESSAGE_GETATTRIBUTE", 
									"checkCertBasic", "checkKeyUsage", 
									"CRYPT_COMPLIANCELEVEL_REDUCED", 
									"checkNameChaining", 
									"checkKeyUsageIssuer", "checkVersion", 
									"CRYPT_COMPLIANCELEVEL_STANDARD", 
									"checkKeyUsage", 
									"checkAttributeProperty" ) );
#endif /* CFI checks based on PKIX compliance levels */

	return( CRYPT_OK );
	}
#endif /* USE_CERTIFICATES */
