/****************************************************************************
*																			*
*						Certificate Attribute Read Routines					*
*						 Copyright Peter Gutmann 1996-2020					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

/* Define the following to print a trace of the certificate fields being 
   parsed, useful for debugging broken certificates */

#if !defined( NDEBUG ) && 0
  #define TRACE_DEBUG( message ) \
		  DEBUG_PRINT( message ); \
		  DEBUG_PUTS(( "" ));
  #define getDescription( attributeInfoPtr ) \
		  ( ( attributeInfoPtr ) != NULL && \
		    ( attributeInfoPtr )->description != NULL ) ? \
			( attributeInfoPtr )->description : "(unknown blob attribute)"
#else
  #define TRACE_DEBUG( message )
#endif /* NDEBUG */

#ifdef USE_CERTIFICATES

/****************************************************************************
*																			*
*								Error Handling								*
*																			*
****************************************************************************/

/* Return from an attribute read after encountering an error, setting the 
   extended error information.  This formats the error message as "Couldn't 
   read attribute $description $errorString" where errorString is a user-
   supplied qualifier for what's being read, e.g. "wrapper", "OID", "data".
   
   In theory we could also report the offset at which the error occurred but
   since we'll frequently arrive here after a read error the stream will be
   in an error state and the stell() will fail */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6 ) ) \
int readAttributeErrorReturn( OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType, 
							  INOUT_PTR ERROR_INFO *errorInfo,
							  IN_PTR_OPT \
								const ATTRIBUTE_INFO *attributeInfoPtr,
							  IN_INT_SHORT_Z const int attributeNo,
							  IN_STRING const char *errorString,
							  IN_ERROR const int status )
	{
	CRYPT_ATTRIBUTE_TYPE fieldID;

	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( attributeInfoPtr == NULL || \
			isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isReadPtr( errorString, 4 ) );

	REQUIRES( isShortIntegerRange( attributeNo ) );
	REQUIRES( cryptStatusError( status ) );

	/* Clear return values */
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* If there's no attribute information available, for example if we ran 
	   into an error reading the OID that identifies an attribute, return an 
	   error message based on the attribute number */
	if( attributeInfoPtr == NULL )
		{
		/* Sometimes we're reading something for which there's not even an 
		   attribute number available, in which case we have to fall back to
		   the most generic error message */
		if( attributeNo <= 0 )
			{
			retExt( status, 
					( status, errorInfo, "Couldn't read attribute %s", 
					  errorString ) );
			}
		retExt( status, 
				( status, errorInfo, "Couldn't read attribute #%d %s", 
				  attributeNo, errorString ) );
		}

	/* For some attributes the field ID is in the following entry so we 
	   skip to this if required */
	if( attributeInfoPtr->fieldID == FIELDID_FOLLOWS )
		{
		attributeInfoPtr++;
		fieldID = attributeInfoPtr->fieldID;

		/* Verified during the startup check */
		ENSURES( fieldID > CRYPT_CERTINFO_FIRST && \
				 fieldID < CRYPT_CERTINFO_LAST );
		}
	else
		{
		/* Since some fields are internal-use only (e.g. meaningless blob 
		   data, version numbers, and other paraphernalia) we only set the 
		   locus if it has a meaningful value */
		fieldID = attributeInfoPtr->fieldID;
		if( fieldID <= CRYPT_CERTINFO_FIRST || \
			fieldID >= CRYPT_CERTINFO_LAST )
			fieldID = CRYPT_ATTRIBUTE_NONE;
		}
	*errorLocus = fieldID;
	*errorType = CRYPT_ERRTYPE_ATTR_VALUE;

	/* If there's a description available, return an error message based on 
	   that */
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	if( attributeInfoPtr->description != NULL ) 
		{
		retExt( status,
				( status, errorInfo, "Couldn't read %s %s", 
				  attributeInfoPtr->description, errorString ) );
		}
#endif /* USE_ERRMSGS || Debug mode */

	/* There's no description available, return a generic error message 
	   based on the field ID.  This may be CRYPT_ATTRIBUTE_NONE, but we're
	   getting into the law of diminishing returns here so it's not worth
	   adding even more special-case handling */
	retExt( status,
			( status, errorInfo, "Couldn't read attribute type %d %s", 
			  fieldID, errorString ) );
	}

/****************************************************************************
*																			*
*						Attribute Wrapper Read Routines						*
*																			*
****************************************************************************/

/* Read the certificate object-specific wrapper for a set of attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readAttributeWrapper( INOUT_PTR STREAM *stream, 
								 OUT_LENGTH_Z int *lengthPtr, 
								 IN_ENUM_OPT( CRYPT_CERTTYPE ) \
									const CRYPT_CERTTYPE_TYPE type,
								 IN_LENGTH_SHORT const int attributeLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( lengthPtr, sizeof( int ) ) );

	REQUIRES( isEnumRangeOpt( type, CRYPT_CERTTYPE ) );
			  /* Single CRL entries have the special-case type 
			     CRYPT_CERTTYPE_NONE */
	REQUIRES( isShortIntegerRange( attributeLength ) );

	/* Clear return value */
	*lengthPtr = 0;

	/* Read the appropriate wrapper for the certificate object type and 
	   determine how far we can read.  CRLs and OCSP requests/responses have 
	   two attribute types that have different tagging, per-entry attributes 
	   and entire-CRL/request attributes.  To differentiate between the two 
	   we read per-entry attributes with a type of CRYPT_CERTTYPE_NONE */
	switch( type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
			readConstructed( stream, NULL, CTAG_CE_EXTENSIONS );
			return( readSequence( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_CRL:
			readConstructed( stream, NULL, CTAG_CL_EXTENSIONS );
			return( readSequence( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
		case CRYPT_CERTTYPE_PKIUSER:
		case CRYPT_CERTTYPE_NONE:
			/* Any outer wrapper for per-entry CRL/OCSP attributes has
			   already been read by the caller so there's only the inner
			   SEQUENCE left to read */
			return( readSequence( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_CMS_ATTRIBUTES:
			return( readConstructed( stream, lengthPtr,
									 CTAG_SI_AUTHENTICATEDATTRIBUTES ) );

		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* CRMF/CMP attributes don't contain any wrapper so there's
			   nothing to read */
			*lengthPtr = attributeLength;
			return( CRYPT_OK );

		case CRYPT_CERTTYPE_RTCS_REQUEST:
			return( readSet( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_RTCS_RESPONSE:
			return( readConstructed( stream, lengthPtr, CTAG_RP_EXTENSIONS ) );

		case CRYPT_CERTTYPE_OCSP_REQUEST:
			readConstructed( stream, NULL, CTAG_OR_EXTENSIONS );
			return( readSequence( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			readConstructed( stream, NULL, CTAG_OP_EXTENSIONS );
			return( readSequence( stream, lengthPtr ) );
		}

	retIntError();
	}

#ifdef USE_CERTREQ 

/* Read a PKCS #10 certificate request wrapper for a set of attributes.  
   This isn't as simple as it should be because there are two approaches to 
   adding attributes to a request, the PKCS #10 approach which puts them all 
   inside a PKCS #9 extensionRequest attribute and the SET approach which 
   lists them all individually (CRMF is a separate case handled by 
   readAttributeWrapper() above).  Complicating this even further is the 
   SCEP approach, which puts attributes intended to be put into the final 
   certificate inside a PKCS #9 extensionRequest but other attributes used 
   for certificate issuance control, for example a challengePassword, 
   individually as SET does.  So the result can be something like:

	[0] SEQUENCE {
		SEQUENCE { challengePassword ... }
		SEQUENCE { extensionRequest 
			SEQUENCE basicConstraints 
			SEQUENCE keyUsage 
			}
		}

   In addition Microsoft invented their own incompatible version of the PKCS 
   #9 extensionRequest which is exactly the same as the PKCS #9 one but with 
   a MS OID, however they also invented other values to add containing God 
   knows what sort of data (long Unicode strings describing the Windows 
   module that created it, as if you'd need that to know where it came from, 
   the scripts from "Gilligan's Island", every "Brady Bunch" episode ever 
   made, dust from under somebody's bed from the 1930s, etc).
   
   Because of these problems, the code does the following:

	- If it's a standalone attribute, it processes it.
	- If it's a PKCS #9 extensionRequest, it reads the wrapper and returns.
	- If it's unknown garbage, it skips it.
   
   This leads to two follow-on issues.  Firstly, since all attributes may be 
   either skipped or processed at this stage we include provisions for 
   bailing out if we exhaust the available attributes.  Secondly, as soon as 
   we encounter a PKCS #9 extensionRequest we exit back to readAttributes() 
   for handling the individual attributes within the extensionRequest.  This 
   means that in order to handle any additional attributes present after the 
   ones encapsulated in the PKCS #9 extensionRequest we have to make a 
   second call to here after the main attribute-processing loop in 
   readAttributes() has finished reading the encapsulated attributes */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3, 5, 6, 7 ) ) \
static int readCertReqWrapper( INOUT_PTR STREAM *stream, 
							   INOUT_PTR DATAPTR_ATTRIBUTE *attributePtrPtr,
							   OUT_DATALENGTH_Z int *lengthPtr, 
							   IN_LENGTH_SHORT const int attributeLength,
							   INOUT_PTR ERROR_INFO *errorInfo,
							   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
							   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	const int endPos = stell( stream ) + attributeLength;
	LOOP_INDEX attributesProcessed;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributePtrPtr, sizeof( DATAPTR_ATTRIBUTE ) ) );
	assert( isWritePtr( lengthPtr, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( isShortIntegerRangeNZ( attributeLength ) );
	REQUIRES( isIntegerRangeMin( endPos, attributeLength ) );

	/* Clear return values */
	*lengthPtr = 0;
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	/* Make sure that the length that we've been given makes sense */
	if( !isShortIntegerRangeMin( attributeLength, MIN_ATTRIBUTE_SIZE ) )
		return( CRYPT_ERROR_BADDATA );

	LOOP_MED( attributesProcessed = 0, attributesProcessed < 16, 
			  attributesProcessed++ )
		{
#if defined( USE_CERT_OBSOLETE ) || defined( USE_SCEP )
		const ATTRIBUTE_INFO *attributeInfoPtr;
#endif /* USE_CERT_OBSOLETE || USE_SCEP */
		BYTE oid[ MAX_OID_SIZE + 8 ];
		int oidLength;

		ENSURES( LOOP_INVARIANT_MED( attributesProcessed, 0, 15 ) );

		/* If we've run out of attributes, exit */
		if( stell( stream ) >= endPos )
			return( OK_SPECIAL );

		/* Read the wrapper SEQUENCE and OID */
		readSequence( stream, NULL );
		status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			{
			return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, NULL, attributesProcessed, 
									"OID", status ) );
			}

#if defined( USE_CERT_OBSOLETE ) || defined( USE_SCEP )
		/* Check for a known attribute, which can happen with SET and SCEP 
		   certificate requests.  If it's a known attribute, process it */
		attributeInfoPtr = oidToAttribute( ATTRIBUTE_CERTIFICATE, 
										   oid, oidLength );
		if( attributeInfoPtr != NULL )
			{
			int length;

			status = readSet( stream, &length );
			if( cryptStatusOK( status ) )
				{
				status = readAttribute( stream, attributePtrPtr,
										attributeInfoPtr, length, FALSE, 
										errorInfo, errorLocus, errorType );
				}
			if( cryptStatusError( status ) )
				return( status );

			continue;
			}
#endif /* USE_CERT_OBSOLETE || USE_SCEP */

		/* It's not a known attribute, check whether it's a CRMF or MS 
		   wrapper attribute */
		if( matchOID( oid, oidLength, OID_PKCS9_EXTREQ ) || \
			matchOID( oid, oidLength, OID_MS_EXTREQ ) )
			{
			/* Skip the wrapper to reveal the encapsulated attributes */
			readSet( stream, NULL );
			return( readSequence( stream, lengthPtr ) );
			}

		/* It's unknown MS garbage, skip it */
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	/* As with the check in readAttribute(), getting to this point could be 
	   either a certificate-parsing error or a CRYPT_ERROR_INTERNAL internal 
	   error.  Since we can't tell without human intervention we treat it as 
	   a certificate error rather than throwing a retIntError() exception.
	   
	   The error message reported here is somewhat unusual, the reason why 
	   it's reported this way is that if after processing 16 attributes we 
	   still haven't encountered a PKCS #9 extensionRequest then there's
	   something wrong with the request attributes */
	DEBUG_DIAG(( "Unknown certificate request extensions encountered" ));
	assert_nofuzz( DEBUG_WARN );
	retExt( CRYPT_ERROR_BADDATA,
			( CRYPT_ERROR_BADDATA, errorInfo, 
			  "Processed more than %d certificate request attributes "
			  "without finding a usable one", 16 ) );
	}
#endif /* USE_CERTREQ */

/****************************************************************************
*																			*
*							Attribute Read Routines							*
*																			*
****************************************************************************/

/* Read a set of attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5, 6, 7 ) ) \
int readAttributes( INOUT_PTR STREAM *stream, 
					INOUT_PTR DATAPTR_ATTRIBUTE *attributePtrPtr,
					IN_ENUM_OPT( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE type, 
					IN_LENGTH_Z const int attributeLength,
					INOUT_PTR ERROR_INFO *errorInfo,
					OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
					OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_TYPE attributeType = ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES || \
										   type == CRYPT_CERTTYPE_RTCS_REQUEST || \
										   type == CRYPT_CERTTYPE_RTCS_RESPONSE ) ? \
										 ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	const BOOLEAN wrapperTagSet = ( attributeType == ATTRIBUTE_CMS ) ? \
								  TRUE : FALSE;
#ifdef USE_CERTREQ 
	const int attributeEndPos = stell( stream ) + attributeLength;
#endif /* USE_CERTREQ */
	int length, endPos, complianceLevel, attributesProcessed;
	int status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributePtrPtr, sizeof( DATAPTR_ATTRIBUTE ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( isEnumRangeOpt( type, CRYPT_CERTTYPE ) );
			  /* Single CRL entries have the special-case type 
			     CRYPT_CERTTYPE_NONE */
	REQUIRES( ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
				attributeLength == 0 ) || \
			  ( type != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
				isIntegerRangeNZ( attributeLength ) ) );
			  /* CMS attributes are pure attribute data with no 
			     encapsulation to indicate the length so the length is 
				 implicitly "everything that's present".
				 See the comment below for why we check for MAX_INTLENGTH
				 rather than MAX_INTLENGTH_SHORT */
#ifdef USE_CERTREQ 
	REQUIRES( ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
				isIntegerRange( attributeEndPos ) ) || \
			  ( type != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
				isIntegerRangeNZ( attributeEndPos ) ) );
	REQUIRES( isIntegerRangeMin( attributeEndPos, attributeLength ) );
#endif /* USE_CERTREQ */

	/* Clear return values */
	DATAPTR_SET_PTR( attributePtrPtr, NULL );
	*errorLocus = CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_NONE;

	status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE, &complianceLevel,
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* If we've been given an excessively long length, don't try and go any 
	   further.  Generally the higher-level code will have enforced this
	   check by way of the length being passed to us being what's left of
	   the data in the certificate object, but if the length has come from
	   a read of any level of wrapper around the attributes then this 
	   implicit enforcement won't have taken place so we perform an explicit 
	   check here.  This means that from now on we can guarantee that the 
	   length is no greater than MAX_INTLENGTH_SHORT rather than the more 
	   generic MAX_INTLENGTH that's checked for in the precondition check
	   above */
	if( ( type != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		  attributeLength < MIN_ATTRIBUTE_SIZE ) || \
		attributeLength >= MAX_INTLENGTH_SHORT )
		return( CRYPT_ERROR_BADDATA );

	/* Read the wrapper for the certificate object's attributes and 
	   determine how far we can read */
#ifdef USE_CERTREQ 
	if( type == CRYPT_CERTTYPE_CERTREQUEST )
		{
		status = readCertReqWrapper( stream, attributePtrPtr, 
									 &length, attributeLength, errorInfo,
									 errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			if( status == OK_SPECIAL )
				{
				/* We processed all of the attributes that were present as 
				   part of the wrapper read (see the explanation in 
				   readCertReqWrapper() for details), we're done */
				return( CRYPT_OK );
				}

			return( status );
			}
		}
	else
#endif /* USE_CERTREQ */
		{
		status = readAttributeWrapper( stream, &length, type, 
									   attributeLength );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo, 
					  "Couldn't read attribute wrapper" ) );
			}
		}
	if( !isShortIntegerRangeMin( length, MIN_ATTRIBUTE_SIZE ) )
		return( CRYPT_ERROR_BADDATA );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length + 1 ) );

	/* Read the collection of attributes */
	TRACE_DEBUG(( "\nReading attributes for certificate object starting at "
				  "offset %d.", stell( stream ) ));
	LOOP_LARGE( attributesProcessed = 0, stell( stream ) < endPos, 
				attributesProcessed++ )
		{
		const ATTRIBUTE_INFO *attributeInfoPtr;
		BYTE oid[ MAX_OID_SIZE + 8 ];
		BOOLEAN criticalFlag = FALSE, ignoreAttribute = FALSE;
		void *attributeDataPtr;
		int tag, oidLength, attributeDataLength;

		ENSURES( LOOP_INVARIANT_LARGE( attributesProcessed, 0, 
									   FAILSAFE_ITERATIONS_LARGE - 1 ) );

		/* Read the outer wrapper and determine the attribute type based on
		   the OID */
		readSequence( stream, NULL );
		status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			{
			TRACE_DEBUG(( "Couldn't read attribute #%d OID, status %s.", 
						  attributesProcessed, getStatusName( status ) ));
			return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, NULL, attributesProcessed, 
									"OID", status ) );
			}
		attributeInfoPtr = oidToAttribute( attributeType, oid, oidLength );
		if( attributeInfoPtr != NULL && \
			complianceLevel < decodeComplianceLevel( attributeInfoPtr->typeInfoFlags ) )
			{
			/* If we're running at a lower compliance level than that
			   required for the attribute, ignore it by treating it as a
			   blob-type attribute */
			TRACE_DEBUG(( "Reading %s (%d) as a blob.", 
						  getDescription( attributeInfoPtr ), 
						  attributeInfoPtr->fieldID ));
			ignoreAttribute = TRUE;
			}

		/* Read the optional critical flag if it's a certificate object.  If 
		   the attribute is marked critical and we don't recognise it then 
		   we don't reject it at this point because that'd make it 
		   impossible to examine the contents of the certificate or display 
		   it to the user.  Instead we reject the certificate when we try 
		   and check it with cryptCheckCert()/checkCertValidity() */
		if( attributeType != ATTRIBUTE_CMS && \
			checkStatusPeekTag( stream, status, tag ) && \
			tag == BER_BOOLEAN )
			{
			status = readBoolean( stream, &criticalFlag );
			if( cryptStatusError( status ) )
				{
				return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 
									attributesProcessed, "critical flag", 
									status ) );
				}
			}
		if( cryptStatusError( status ) )
			return( status );	/* Residual error from peekTag() */

		/* Read the wrapper around the attribute payload.  We allow a length 
		   down to zero since it could be an attribute with all-default 
		   fields */
		if( wrapperTagSet )
			status = readSet( stream, &attributeDataLength );
		else
			{
			status = readOctetStringHole( stream, &attributeDataLength, 2,
										  DEFAULT_TAG );
			}
#ifdef USE_RPKI
		if( cryptStatusOK( status ) && \
			!isShortIntegerRange( attributeDataLength ) )
			status = CRYPT_ERROR_BADDATA;
#else
		if( cryptStatusOK( status ) && \
			( attributeDataLength < 0 || \
			  attributeDataLength >= MAX_ATTRIBUTE_SIZE ) )
			status = CRYPT_ERROR_BADDATA;
#endif /* USE_RPKI */
		if( cryptStatusError( status ) )
			{
			TRACE_DEBUG(( "Couldn't read attribute payload wrapper for %s, "
						  "status %s.", getDescription( attributeInfoPtr ), 
						  getStatusName( status ) ));
			return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 
									attributesProcessed, "payload wrapper", 
									status ) );
			}

		/* If it's a known attribute and we're processing it at this 
		   compliance level, parse the payload */
		if( attributeInfoPtr != NULL && !ignoreAttribute )
			{
			status = readAttribute( stream, attributePtrPtr,
									attributeInfoPtr, attributeDataLength,
									criticalFlag, errorInfo, errorLocus, 
									errorType );
			if( cryptStatusError( status ) )
				{
				TRACE_DEBUG(( "Error %s reading %s attribute.", 
							  getStatusName( status ),
							  getDescription( attributeInfoPtr ) ));
				return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 
									attributesProcessed, "data", status ) );
				}
			continue;
			}

		/* If it's a zero-length unrecognised attribute, don't add anything.
		   A zero length indicates that the attribute contains all default
		   values, however since we don't recognise the attribute we can't
		   fill these in so the attribute is in effect not present */
		if( attributeDataLength <= 0 )
			continue;

		/* It's an unrecognised or ignored attribute type, add the raw data
		   to the list of attributes */
		status = sMemGetDataBlock( stream, &attributeDataPtr, 
								   attributeDataLength );
		if( cryptStatusOK( status ) )
			{
			ANALYSER_HINT( attributeDataPtr != NULL );
			status = addAttribute( attributeType, attributePtrPtr, 
								   oid, oidLength, criticalFlag, 
								   attributeDataPtr, attributeDataLength, 
								   ignoreAttribute ? \
										ATTR_FLAG_BLOB | ATTR_FLAG_IGNORED : \
										ATTR_FLAG_BLOB );
			}
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_ERROR_INITED )
				{
				/* If there's a duplicate attribute present, set error
				   information for it and flag it as a bad data error.  We
				   can't set an error locus since it's an unknown blob */
				*errorLocus = ( attributeInfoPtr != NULL ) ? \
								attributeInfoPtr->fieldType : \
								CRYPT_ATTRIBUTE_NONE;
				*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
				status = CRYPT_ERROR_BADDATA;
				}
			TRACE_DEBUG(( "Error %s adding unrecognised blob attribute data.", 
						  getStatusName( status ) ));
			return( readAttributeErrorReturn( errorLocus, errorType, 
									errorInfo, attributeInfoPtr, 
									attributesProcessed, "blob data", 
									status ) );
			}

		/* Skip the attribute data */
		sSkip( stream, attributeDataLength, MAX_INTLENGTH_SHORT );
		}
	ENSURES( LOOP_BOUND_OK );
	TRACE_DEBUG(( "Finished reading attributes for certificate object ending at "
				  "offset %d.\n", stell( stream ) ));

	/* Certificate requests can contain unencapsulated attributes as well as
	   attributes encapsulated inside PKCS #9 extensionRequests.  
	   readCertReqWrapper() processes any unencapsulated attributes that 
	   precede a PKCS #9 extensionRequest (if present) and the attribute-
	   read loop above reads the encapsulated attributes.  If there are 
	   further unencapsulated attributes present following the PKCS #9 
	   extensionRequest-encapsulated ones then we read them now */
#ifdef USE_CERTREQ 
	if( type == CRYPT_CERTTYPE_CERTREQUEST && \
		stell( stream ) < attributeEndPos )
		{
		status = readCertReqWrapper( stream, attributePtrPtr, &length, 
									 attributeEndPos - stell( stream ), 
									 errorInfo, errorLocus, errorType );
		if( cryptStatusError( status ) && status != OK_SPECIAL )
			{
			/* If all remaining attributes were processed by 
			   readCertReqWrapper() then it returns OK_SPECIAL, this is used 
			   to indicate that there are no PKCS #9 extensionRequest-
			   encapsulated attributes present.  Since this condition is
			   always met at this point because we're calling it after
			   processing encapsulated attributes, we have to filter it
			   out */
			return( status );
			}
		}
#endif /* USE_CERTREQ */

	return( CRYPT_OK );
	}
#endif /* USE_CERTIFICATES */
