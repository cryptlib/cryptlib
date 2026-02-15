/****************************************************************************
*																			*
*							Certificate Read Routines						*
*						Copyright Peter Gutmann 1996-2020					*
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

#if defined( __MVS__ )
  /* MVS control section (CSECT) names default to the file name and can't
	 match any symbol name either in the file or in another file or library 
	 (e.g. write.c vs. write()).  Because of this we have to explicitly 
	 name the csect's so that they don't conflict with external symbol
	 names */
  #pragma csect( CODE, "readC" )
  #pragma csect( STATIC, "readS" )
  #pragma csect( TEST, "readT" )
#endif /* __MVS__ */

/****************************************************************************
*																			*
*							Read Certificate Components						*
*																			*
****************************************************************************/

/* Return from a certificate information read after encountering an error, 
   setting the extended error information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int certErrorReturn( INOUT_PTR CERT_INFO *certInfoPtr,
							IN_STRING const char *errorString,
							IN_ERROR const int status )
	{
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( errorString, 4 ) );

	REQUIRES( cryptStatusError( status ) );

	retExt( status, 
			( status, CERTIFICATE_ERRINFO, 
			  "Invalid %s %s information", 
			  getCertTypeNameLC( certInfoPtr->type ), errorString ) );
	}

/* Read version information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readVersion( INOUT_PTR STREAM *stream, 
						INOUT_PTR CERT_INFO *certInfoPtr,
						IN_TAG const int tag,
						IN_RANGE( 1, 5 ) const int maxVersion )
	{
	long version;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );
	REQUIRES( maxVersion >= 1 && maxVersion <= 5 );

	/* Versions can be represented in one of three ways:

		1. version		  INTEGER
		2. version		  INTEGER DEFAULT (1)
		3. version	[tag] INTEGER DEFAULT (1)

	   To handle this we check for the required tags for versions with 
	   DEFAULT values and exit if they're not found, setting the version to 
	   1 first */
	certInfoPtr->version = X509_V1;
	if( tag != DEFAULT_TAG )
		{
		int peekedTag;

		status = peekedTag = peekTag( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( tag == BER_INTEGER )
			{
			/* INTEGER DEFAULT (1), if we don't find this then we're done */
			if( peekedTag != BER_INTEGER )
				return( CRYPT_OK );
			}
		else
			{
			/* [tag] INTEGER DEFAULT (1), if we don't find this then we're 
			   done */
			if( peekedTag != MAKE_CTAG( tag ) )
				return( CRYPT_OK );
			status = readConstructed( stream, NULL, tag );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* We've definitely got a version number present, process it.  Since the
	   version number is zero-based, we have to adjust the range-check and 
	   value we store by one to compensate for this */
	status = readShortInteger( stream, &version );
	if( cryptStatusError( status ) )
		return( status );
	if( version < 0 || version > maxVersion - 1 )
		return( CRYPT_ERROR_BADDATA );
	ENSURES( isIntegerRangeNZ( version + 1 ) );
	certInfoPtr->version = ( int ) version + 1;

	return( CRYPT_OK );
	}

/* Read a certificate serial number */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readSerialNumber( INOUT_PTR STREAM *stream, 
							 INOUT_PTR CERT_INFO *certInfoPtr,
							 IN_TAG const int tag )
	{
	BYTE integer[ MAX_SERIALNO_SIZE + 8 ];
	int integerLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );

	/* Read the integer component of the serial number */
	status = readIntegerTag( stream, integer, MAX_SERIALNO_SIZE, 
							 &integerLength, tag );
	if( cryptStatusError( status ) )
		return( status );

	/* Some certificates may have a serial number of zero, which is turned 
	   into a zero-length integer by the ASN.1 read code since it truncates 
	   leading zeroes that are added due to ASN.1 encoding requirements.  If 
	   we get a zero-length integer we turn it into a single zero byte */
	if( integerLength <= 0 )
		{
		integer[ 0 ] = 0;
		integerLength = 1;
		}

	/* Copy the data across for the caller */
	return( setSerialNumber( certInfoPtr, integer, integerLength ) );
	}

/* Read DN information and remember the encoded DN data so that we can copy 
   it (complete with any encoding errors) to the issuer DN field of 
   anything that we sign */

#ifdef USE_CERTLEVEL_PKIX_FULL

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readSubjectDN( INOUT_PTR STREAM *stream, 
						  INOUT_PTR CERT_INFO *certInfoPtr )
	{
	const int startPos = stell( stream );
	BOOLEAN isNullDN = FALSE;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isIntegerRangeNZ( startPos ) );

	status = getStreamObjectLength( stream, &length, MIN_DN_SIZE );
	if( cryptStatusError( status ) )
		{
		/* Full PKIX allows null DNs, which would otherwise fail all sorts 
		   of sanity checks.  To identify a null DN we need to retry the
		   read for a zero-length SEQUENCE and if we find that, treat it as
		   a null DN */
		sClearError( stream );
		status = sseek( stream, startPos );
		if( cryptStatusOK( status ) )
			status = readSequenceExt( stream, &length, LENGTH_CHECK_ZERO );
		if( cryptStatusOK( status ) )
			{
			if( length == 0 )
				{
				/* It's an empty sequence, this is a null DN */
				length = sizeofObject( 0 );
				isNullDN = TRUE;
				status = sseek( stream, startPos );
				}
			else
				status = CRYPT_ERROR_BADDATA;
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Get the DN in both encoded and decoded form */
	certInfoPtr->subjectDNsize = length;
	status = sMemGetDataBlock( stream, &certInfoPtr->subjectDNptr, length );
	if( cryptStatusOK( status ) )
		{
		if( isNullDN )
			status = readSequenceZ( stream, NULL );
		else
			status = readDN( stream, &certInfoPtr->subjectName );
		}
	return( status );
	}

#else

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readSubjectDN( INOUT_PTR STREAM *stream, 
						  INOUT_PTR CERT_INFO *certInfoPtr )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Get the DN in both encoded and decoded form */
	status = getStreamObjectLength( stream, &length, MIN_DN_SIZE );
	if( cryptStatusOK( status ) )
		{
		certInfoPtr->subjectDNsize = length;
		status = sMemGetDataBlock( stream, &certInfoPtr->subjectDNptr, 
								   length );
		}
	if( cryptStatusOK( status ) )
		status = readDN( stream, &certInfoPtr->subjectName );
	return( status );
	}
#endif /* USE_CERTLEVEL_PKIX_FULL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readIssuerDN( INOUT_PTR STREAM *stream, 
						 INOUT_PTR CERT_INFO *certInfoPtr )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Get the DN in both encoded and decoded form */
	status = getStreamObjectLength( stream, &length, MIN_DN_SIZE );
	if( cryptStatusOK( status ) )
		{
		certInfoPtr->issuerDNsize = length;
		status = sMemGetDataBlock( stream, &certInfoPtr->issuerDNptr, 
								   length );
		}
	if( cryptStatusOK( status ) )
		status = readDN( stream, &certInfoPtr->issuerName );
	return( status );
	}

/* Read public-key information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPublicKeyInfo( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CERT_INFO *certInfoPtr )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Record a reference to the public-key data */
	status = getStreamObjectLength( stream, &length, 16 );
	if( cryptStatusOK( status ) )
		{
		certInfoPtr->publicKeyInfoSize = length;
		status = sMemGetDataBlock( stream, &certInfoPtr->publicKeyInfo, 
								   length );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Import or read (for a data-only certificate) the public key 
	   information */
	if( TEST_FLAG( certInfoPtr->flags, CERT_FLAG_DATAONLY ) )
		{
		ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;

		/* We're doing deferred handling of the public key, skip it for now.
		   Because of weird tagging in things like CRMF objects we have to
		   read the information as a generic hole rather than a normal
		   SEQUENCE.
		   
		   Unlike a standard read via iCryptReadSubjectPublicKey() this
		   doesn't catch the use of too-short key parameters because we'd
		   have to duplicate most of the code that 
		   iCryptReadSubjectPublicKey() calls in order to read the key
		   components, however data-only certificates are only created for 
		   use in conjunction with encryption contexts so the context create 
		   will catch the use of too-short parameters */
		status = readGenericHole( stream, NULL, 4, DEFAULT_TAG );
		if( cryptStatusOK( status ) )
			{
			status = readAlgoIDex( stream, &certInfoPtr->publicKeyAlgo, 
								   &algoIDparams, ALGOID_CLASS_PKC );
			}
		if( cryptStatusOK( status ) )
			{
			if( algoIDparams.extraLength > 0 )
				{
				sSkip( stream, algoIDparams.extraLength, 
					   MAX_INTLENGTH_SHORT );
				}
			status = readUniversal( stream );
			}
		}
	else
		{
		status = iCryptReadSubjectPublicKey( stream,
										&certInfoPtr->iPubkeyContext, 
										CRYPTO_OBJECT_HANDLE, FALSE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( certInfoPtr->iPubkeyContext,
									  IMESSAGE_GETATTRIBUTE,
									  &certInfoPtr->publicKeyAlgo,
									  CRYPT_CTXINFO_ALGO );
			}
		}

	return( status );
	}

/****************************************************************************
*																			*
*							Read Certificate Objects						*
*																			*
****************************************************************************/

/* Read validity information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readValidity( INOUT_PTR STREAM *stream, 
						 INOUT_PTR CERT_INFO *certInfoPtr )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	status = readSequence( stream, NULL );
	if( cryptStatusOK( status ) )
		status = readTime( stream, &certInfoPtr->startTime );
	if( cryptStatusOK( status ) )
		status = readTime( stream, &certInfoPtr->endTime );
	return( status );
	}

#ifdef USE_CERT_OBSOLETE 

/* Read a uniqueID */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readUniqueID( INOUT_PTR STREAM *stream, 
						 INOUT_PTR CERT_INFO *certInfoPtr,
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( type == CRYPT_CERTINFO_ISSUERUNIQUEID || \
			  type == CRYPT_CERTINFO_SUBJECTUNIQUEID );

	/* Read the length of the unique ID, allocate room for it, and read it
	   into the certificate */
	status = readBitStringHole( stream, &length, 1, 
								( type == CRYPT_CERTINFO_ISSUERUNIQUEID ) ? \
									CTAG_CE_ISSUERUNIQUEID : \
									CTAG_CE_SUBJECTUNIQUEID );
	if( cryptStatusOK( status ) && ( length < 1 || length > 256 ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		{
		void *bufPtr;

		REQUIRES( isShortIntegerRangeNZ( length ) );
		if( ( bufPtr = clDynAlloc( "readUniqueID", length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		if( type == CRYPT_CERTINFO_SUBJECTUNIQUEID )
			{
			certInfoPtr->cCertCert->subjectUniqueID = bufPtr;
			certInfoPtr->cCertCert->subjectUniqueIDlength = length;
			}
		else
			{
			certInfoPtr->cCertCert->issuerUniqueID = bufPtr;
			certInfoPtr->cCertCert->issuerUniqueIDlength = length;
			}
		REQUIRES( rangeCheck( length, 1, 256 ) );
		status = sread( stream, bufPtr, length );
		}
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, type, status ) );

	return( CRYPT_OK );
	}
#else
  #define readUniqueID( stream, certInfoPtr, type )	readUniversal( stream );
#endif /* USE_CERT_OBSOLETE */

/* Read certificate information:

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

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCertInfo( INOUT_PTR STREAM *stream, 
						 INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CRYPT_ALGO_TYPE dummyAlgo;
	ALGOID_PARAMS algoIDparams DUMMY_INIT_STRUCT;
	int length, endPos, tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Read the outer SEQUENCE and version number if it's present */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	status = readVersion( stream, certInfoPtr, CTAG_CE_VERSION, 3 );
	if( cryptStatusError( status ) )
		{
		return( certErrorReturn( certInfoPtr, "version information",
								 status ) );
		}

	/* Read the serial number and signature algorithm information.  The
	   algorithm information was included to avert a somewhat obscure attack
	   where it's possible to substitute the hash algorithm specified for 
	   the signature with a broken one, however this isn't possible because 
	   of the way that the signature data is encoded in PKCS #1 sigs 
	   (although it's still possible for some of the ISO signature types) or 
	   because the (EC)DSA sigs have a different size for each hash 
	   algorithm (SHA-1, SHA-256, SHA-384, SHA-512) so technically there's 
	   no need to record it, however we record it because CMP uses the hash 
	   algorithm in the certificate as an implicit indicator of the hash 
	   algorithm that it uses for CMP messages (!!) and also just because 
	   it's good practice to do so in case some future hash algorithm of
	   the same size as an existing (EC)DSA one but that's breakable turns
	   up */
	status = readSerialNumber( stream, certInfoPtr, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "serial number", status ) );
	status = readAlgoIDex( stream, &dummyAlgo, &algoIDparams,
						   ALGOID_CLASS_PKCSIG );
	if( cryptStatusError( status ) )
		{
		return( certErrorReturn( certInfoPtr, "signature algorithm", 
								 status ) );
		}
	certInfoPtr->cCertCert->hashAlgo = algoIDparams.hashAlgo;
	certInfoPtr->cCertCert->hashParam = algoIDparams.hashParam;

	/* Read the issuer name, validity information, and subject name */
	status = readIssuerDN( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "issuer name", status ) );
	status = readValidity( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "validity", status ) );
	status = readSubjectDN( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "subject name", status ) );

	/* Check to see whether it's a self-signed certificate */
	if( certInfoPtr->issuerDNsize == certInfoPtr->subjectDNsize && \
		!memcmp( certInfoPtr->issuerDNptr, certInfoPtr->subjectDNptr,
				 certInfoPtr->subjectDNsize ) )
		SET_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED );

	/* Read the public key information */
	status = readPublicKeyInfo( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "public key", status ) );

	/* Read the issuer and subject unique IDs if there are any present */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG_PRIMITIVE( CTAG_CE_ISSUERUNIQUEID ) )
		{
		status = readUniqueID( stream, certInfoPtr,
							   CRYPT_CERTINFO_ISSUERUNIQUEID );
		if( cryptStatusError( status ) )
			{
			return( certErrorReturn( certInfoPtr, "issuer unique ID", 
					status ) );
			}
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG_PRIMITIVE( CTAG_CE_SUBJECTUNIQUEID ) )
		{
		status = readUniqueID( stream, certInfoPtr,
							   CRYPT_CERTINFO_SUBJECTUNIQUEID );
		if( cryptStatusError( status ) )
			{
			return( certErrorReturn( certInfoPtr, "subject unique ID", 
					status ) );
			}
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* Read the extensions if there are any present.  In theory we're only 
	   supposed to accept extensions if the certificate is marked as v3
	   (RFC 3280 section 4.1.2.8) however this requirement doesn't serve any 
	   useful function in that while we always mark certificates with 
	   extensions as v3 when we create them, there's no problem introduced
	   by accepting extensions for any certificate version */
	if( stell( stream ) < endPos )
		{
		status = readAttributes( stream, &certInfoPtr->attributes,
								 CRYPT_CERTTYPE_CERTIFICATE, 
								 endPos - stell( stream ), 
								 CERTIFICATE_ERRINFO, 
								 &certInfoPtr->errorLocus, 
								 &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Fix up any problems in attributes */
	return( fixAttributes( certInfoPtr ) );
	}

#ifdef USE_ATTRCERT

/* Read attribute certificate information.  There are two variants of this, 
   v1 attribute certificates that were pretty much never used (the fact 
   that no-one had bothered to define any attributes to be used with them
   didn't help here) and v2 attribute certificates that are also never used 
   but are newer and shinier.  We read v2 certificates.  
   
   The original v1 attribute certificate format was:

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

   In v2 this was bloated up to:

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

   because obviously the failure of attribute certificates in the market was 
   because they weren't complex enough the first time round */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readAttributeCertInfo( INOUT_PTR STREAM *stream, 
								  INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CRYPT_ALGO_TYPE dummyAlgo;
	ALGOID_PARAMS algoIDparams;
	int tag, length, endPos, innerEndPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Read the outer SEQUENCE and version number */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	status = readVersion( stream, certInfoPtr, BER_INTEGER, 2 );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "version", status ) );

	/* Read the owner and issuer names */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	innerEndPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( innerEndPos, length ) );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_AC_HOLDER_BASECERTIFICATEID ) )
		status = readUniversal( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( checkStatusLimitsPeekTag( stream, status, tag, innerEndPos ) && \
		tag == MAKE_CTAG( CTAG_AC_HOLDER_ENTITYNAME ) )
		{
		readConstructed( stream, NULL, CTAG_AC_HOLDER_ENTITYNAME );
		status = readConstructed( stream, NULL, 4 );
		if( cryptStatusOK( status ) )
			status = readSubjectDN( stream, certInfoPtr );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, "holder name", status ) );
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */
	if( checkStatusLimitsPeekTag( stream, status, tag, innerEndPos ) && \
		tag == MAKE_CTAG( CTAG_AC_HOLDER_OBJECTDIGESTINFO ) )
		{
		/* This is a complicated structure that in effect encodes a generic 
		   hole reference to "other", for now we just skip it until we can
		   find an example of something that actually uses it */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = readConstructed( stream, &length, 0 );
	if( cryptStatusError( status ) )
		return( status );
	innerEndPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( innerEndPos, length ) );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == BER_SEQUENCE )
		{
		readSequence( stream, NULL );
		status = readConstructed( stream, NULL, 4 );
		if( cryptStatusOK( status ) )
			status = readIssuerDN( stream, certInfoPtr );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, "issuer name", status ) );
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */
	if( checkStatusLimitsPeekTag( stream, status, tag, innerEndPos ) && \
		tag == MAKE_CTAG( CTAG_AC_ISSUER_BASECERTIFICATEID ) )
		{
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( checkStatusLimitsPeekTag( stream, status, tag, innerEndPos ) && \
		tag == MAKE_CTAG( CTAG_AC_ISSUER_OBJECTDIGESTINFO ) )
		{
		/* See the comment for the owner objectDigectInfo above */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the signature algorithm information and remember the hash
	   algorithm.  See the comment in readCertInfo() for why we do this */
	status = readAlgoIDex( stream, &dummyAlgo, &algoIDparams, 
						   ALGOID_CLASS_PKCSIG );
	if( cryptStatusError( status ) )
		return( status );
	certInfoPtr->cCertCert->hashAlgo = algoIDparams.hashAlgo;
	certInfoPtr->cCertCert->hashParam =  algoIDparams.hashParam;

	/* Read the serial number and validity information */
	status = readSerialNumber( stream, certInfoPtr, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "serial number", status ) );
	status = readValidity( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "validity", status ) );

	/* Skip the attributes for now since these aren't really defined yet */
	status = readUniversal( stream );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "attributes", status ) );

	/* Read the issuer unique ID if there's one present */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == BER_BITSTRING )
		{
		status = readUniqueID( stream, certInfoPtr,
							   CRYPT_CERTINFO_ISSUERUNIQUEID );
		if( cryptStatusError( status ) )
			{
			return( certErrorReturn( certInfoPtr, "issuer unique ID", 
					status ) );
			}
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* If there are no extensions present, we're done */
	if( stell( stream ) >= endPos )
		return( CRYPT_OK );

	/* Read the extensions */
	return( readAttributes( stream, &certInfoPtr->attributes,
							CRYPT_CERTTYPE_ATTRIBUTE_CERT, 
							endPos - stell( stream ), CERTIFICATE_ERRINFO, 
							&certInfoPtr->errorLocus, 
							&certInfoPtr->errorType ) );
	}
#endif /* USE_ATTRCERT */

/****************************************************************************
*																			*
*								Read CRL Objects							*
*																			*
****************************************************************************/

#ifdef USE_CERTREV

/* Read CRL information:

	CRLInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(0),
		signature				AlgorithmIdentifier,
		issuer					Name,
		thisUpdate				UTCTime/GeneralisedTime,
		nextUpdate				UTCTime/GeneralisedTime OPTIONAL,
		revokedCertificates		SEQUENCE OF RevokedCerts,
		extensions		  [ 0 ]	Extensions OPTIONAL
		}

   We read various lengths as long values since CRLs can get quite large */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCRLInfo( INOUT_PTR STREAM *stream, 
						INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CRYPT_ALGO_TYPE dummyAlgo;
	CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
	ALGOID_PARAMS algoIDparams;
	long length, endPos;
	int tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* If it's a standalone CRL entry, read the single entry and return */
	if( TEST_FLAG( certInfoPtr->flags, CERT_FLAG_CRLENTRY ) )
		{
		return( readCRLentry( stream, &certRevInfo->revocations, 1,
							  CERTIFICATE_ERRINFO, &certInfoPtr->errorLocus,
							  &certInfoPtr->errorType ) );
		}

	/* Read the outer SEQUENCE and version number if it's present */
	status = readLongSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length == CRYPT_UNUSED )
		{
		/* If it's an (invalid) indefinite-length encoding 
		   (readLongSequence() also accepts those) then we can't do anything 
		   with it */
		return( CRYPT_ERROR_BADDATA );
		}
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	status = readVersion( stream, certInfoPtr, BER_INTEGER, 2 );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "version", status ) );

	/* Read the signature algorithm information and remember the hash
	   algorithm.  See the comment in readCertInfo() for why we do this */
	status = readAlgoIDex( stream, &dummyAlgo, &algoIDparams,
						   ALGOID_CLASS_PKCSIG );
	if( cryptStatusError( status ) )
		{
		return( certErrorReturn( certInfoPtr, "signature algorithm", 
				status ) );
		}
	certInfoPtr->cCertRev->hashAlgo = algoIDparams.hashAlgo;
	certInfoPtr->cCertRev->hashParam = algoIDparams.hashParam;

	/* Read the issuer name, update time, and optional next update time */
	status = readIssuerDN( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "issuer name", status ) );
	status = readTime( stream, &certInfoPtr->startTime );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "update time", status ) );
	if( checkStatusPeekTag( stream, status, tag ) && \
		( ( tag == BER_TIME_UTC ) || ( tag == BER_TIME_GENERALIZED ) ) )
		{
		status = readTime( stream, &certInfoPtr->endTime );
		if( cryptStatusError( status ) )
			{
			return( certErrorReturn( certInfoPtr, "next update time", 
					status ) );
			}
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* Read the SEQUENCE OF revoked certificates and make the currently 
	   selected one the start of the list.  Since the set of revoked
	   certificates may be empty, we need to check for the presence of the
	   SEQUENCE tag before we try and read it */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == BER_SEQUENCE )
		{
		status = readCRLentries( stream, &certRevInfo->revocations,
								 CERTIFICATE_ERRINFO,
								 &certInfoPtr->errorLocus,
								 &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		certRevInfo->currentRevocation = certRevInfo->revocations;
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* Read the extensions if there are any present.  In theory we're only 
	   supposed to accept extensions if the CRL is marked as v2 (RFC 3280
	   section 5.1.2.7), but see the comment in readCertInfo() for why we
	   read them unconditionally */
	if( stell( stream ) < endPos )
		{
		status = readAttributes( stream, &certInfoPtr->attributes,
								 CRYPT_CERTTYPE_CRL, 
								 endPos - stell( stream ),
								 CERTIFICATE_ERRINFO, 
								 &certInfoPtr->errorLocus, 
								 &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Fix up any problems in attributes */
	return( fixAttributes( certInfoPtr ) );
	}
#endif /* USE_CERTREV */

/****************************************************************************
*																			*
*						Read Certificate Request Objects					*
*																			*
****************************************************************************/

#ifdef USE_CERTREQ

/* Read certificate request information:

	CertificationRequestInfo ::= SEQUENCE {
		version					INTEGER (0),
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		attributes		  [ 0 ]	SET OF Attribute
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCertRequestInfo( INOUT_PTR STREAM *stream, 
								INOUT_PTR CERT_INFO *certInfoPtr )
	{
	long endPos;
	int tag, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Skip the outer SEQUENCE and read the version number */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	status = readVersion( stream, certInfoPtr, DEFAULT_TAG, 1 );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "version", status ) );

	/* Read the subject name and public key information */
	status = readSubjectDN( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "subject name", status ) );
	status = readPublicKeyInfo( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "public key", status ) );

	/* Read the attributes.  Since these can be zero-length due to an error
	   in the ASN.1 which makes them mandatory, we use readConstructedZ() 
	   rather than readConstructed() to allow this */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_CR_ATTRIBUTES ) )
		{
		status = readConstructedZ( stream, &length, CTAG_CR_ATTRIBUTES );
		if( cryptStatusOK( status ) && length > 0 )
			{
			status = readAttributes( stream, &certInfoPtr->attributes,
									 CRYPT_CERTTYPE_CERTREQUEST, length,
									 CERTIFICATE_ERRINFO, 
									 &certInfoPtr->errorLocus, 
									 &certInfoPtr->errorType );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Certification requests are always self-signed */
	SET_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED );

	/* Fix up any problems in attributes */
	return( fixAttributes( certInfoPtr ) );
	}

/* Read validity information.  Despite being a post-Y2K standard, CRMF still
   allows the non-Y2K UTCTime format to be used for dates so we have to 
   accomodate both date types.  In addition both values are optional so we
   only try and read them if we see their tags */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCrmfValidity( INOUT_PTR STREAM *stream, 
							 INOUT_PTR CERT_INFO *certInfoPtr )
	{
	int tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	status = readConstructed( stream, NULL, CTAG_CF_VALIDITY );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 0 ) )
		{
		readConstructed( stream, NULL, 0 );
		status = readTime( stream, &certInfoPtr->startTime );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 1 ) )
		{
		readConstructed( stream, NULL, 1 );
		status = readTime( stream, &certInfoPtr->endTime );
		if( cryptStatusError( status ) )
			return( status );
		}
	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}		/* checkStatusPeekTag() can return tag as status */

/* CRMF requests can include a large amount of unnecessary junk that no-one 
   (including the RFC authors, when asked) can explain and the semantics of 
   which are at best undefined (version) and at worst dangerous 
   (serialNumber).  The best way to deal with them on the off chance that 
   the client has specified them is to skip the unneeded information until 
   we get to something that we can use */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int skipCrmfJunk( INOUT_PTR STREAM *stream,
						 IN_LENGTH_SHORT const int endPos,
						 IN_TAG_ENCODED const int terminatorTag,
						 IN_TAG_ENCODED const int optTerminatorTag1,
						 IN_TAG_ENCODED const int optTerminatorTag2 )
	{
	LOOP_INDEX fieldsProcessed;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isIntegerRangeNZ( endPos ) );
			  /* See the comment below for why we check for MAX_INTLENGTH
				 rather than MAX_INTLENGTH_SHORT */
	REQUIRES( terminatorTag > 0 && terminatorTag <= MAX_TAG );
	REQUIRES( ( optTerminatorTag1 == NO_TAG ) || \
			  ( optTerminatorTag1 > 0 && optTerminatorTag1 <= MAX_TAG ) );
	REQUIRES( ( optTerminatorTag2 == NO_TAG ) || \
			  ( optTerminatorTag2 > 0 && optTerminatorTag2 <= MAX_TAG ) );

	/* If we've been given an end position that doesn't make sense, don't 
	   try and go any further.  This saves having to perform the check in
	   every higher-level function that calls us.  From now on we can 
	   guarantee that the length is no greater than MAX_INTLENGTH_SHORT 
	   rather than the more generic MAX_INTLENGTH that's checked for in the 
	   precondition check above */
	if( !isShortIntegerRangeNZ( endPos ) )
		return( CRYPT_ERROR_BADDATA );

	/* Skip any junk until we get to a field that we're interested in */
	LOOP_SMALL( fieldsProcessed = 0,
				stell( stream ) < endPos - MIN_ATTRIBUTE_SIZE && \
					fieldsProcessed < 8, 
				fieldsProcessed++ )
		{
		int tag, status;

		ENSURES( LOOP_INVARIANT_SMALL( fieldsProcessed, 0, 7 ) );

		/* Check whether we've reached any of the requested terminator 
		   tags */
		status = tag = peekTag( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( tag == terminatorTag )
			break;
		if( optTerminatorTag1 != NO_TAG && tag == optTerminatorTag1 )
			break;
		if( optTerminatorTag2 != NO_TAG && tag == optTerminatorTag2 )
			break;

		/* Skip this item */
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );
	if( fieldsProcessed >= 8 )
		{
		/* We should have hit something useful by this point */
		return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

/* Read CRMF certificate request information:

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
		} 

   We enforce the requirement that the request must contain at least a 
   subject DN and a public key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCrmfRequestInfo( INOUT_PTR STREAM *stream, 
								INOUT_PTR CERT_INFO *certInfoPtr )
	{
	int tag, length, endPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Skip the outer SEQUENCE, request ID, and inner SEQUENCE.  We read the
	   INTEGER request ID using readUniversal() because of the standard PKIX
	   practice of stuffing OCTET STRINGs and other garbage into it */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	readUniversal( stream );
	status = readSequence( stream, NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Skip any junk before the Validity, SubjectName, or
	   SubjectPublicKeyInfo */
	status = skipCrmfJunk( stream, endPos, 
						   MAKE_CTAG( CTAG_CF_VALIDITY ),
						   MAKE_CTAG( CTAG_CF_SUBJECT ), 
						   MAKE_CTAG( CTAG_CF_PUBLICKEY ) );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's validity data present, read it */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_CF_VALIDITY ) )
		{
		status = readCrmfValidity( stream, certInfoPtr );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, "validity", status ) );
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* If there's a subject name present, read it */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_CF_SUBJECT ) )
		{
		status = readConstructed( stream, NULL, CTAG_CF_SUBJECT );
		if( cryptStatusOK( status ) )
			status = readSubjectDN( stream, certInfoPtr );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, "subject name", status ) );
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* Read the public key information.  CRMF uses yet more nonstandard 
	   tagging for the public key, in theory we'd have to read it with the 
	   CTAG_CF_PUBLICKEY tag instead of the default SEQUENCE, however the 
	   public-key-read code reads the SPKI encapsulation as a generic hole 
	   to handle this so there's no need for any special handling */
	status = tag = peekTag( stream );
	if( !cryptStatusError( status ) )
		{
		if( tag != MAKE_CTAG( CTAG_CF_PUBLICKEY ) )
			status = CRYPT_ERROR_BADDATA;
		else
			status = readPublicKeyInfo( stream, certInfoPtr );
		}
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "public key", status ) );

	/* Read the attributes */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_CF_EXTENSIONS ) )
		{
		status = readConstructed( stream, &length, CTAG_CF_EXTENSIONS );
		if( cryptStatusOK( status ) && length > 0 )
			{
			status = readAttributes( stream, &certInfoPtr->attributes,
									 CRYPT_CERTTYPE_REQUEST_CERT, length, 
									 CERTIFICATE_ERRINFO, 
									 &certInfoPtr->errorLocus, 
									 &certInfoPtr->errorType );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Fix up any problems in attributes */
	status = fixAttributes( certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* The request may contain additional data that doesn't apply to the
	   request itself but to the management of the request by CMP (which 
	   means that it should actually be part of the management protocol and 
	   not the request data but CMP muddles things up quite thoroughly, 
	   including encoding CMP protocol data inside fields in the issuer 
	   certificate(!!)).  Because we can't do anything with this 
	   information, we just skip it if it's present */
	if( stell( stream ) < endPos )
		{
		status = readUniversal( stream );	/* Skip request management information */
		if( cryptStatusError( status ) )
			return( status );
		}

	/* CRMF requests are usually self-signed, however if they've been
	   generated with an encryption-only key then the place of the signature
	   is taken by one of a number of magic values which indicate that no
	   signature is present and that something else needs to be done to
	   verify that the sender has the private key */
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	tag = EXTRACT_CTAG( tag );
	if( tag == CTAG_CF_POP_SIGNATURE )
		{
		/* It's a signature, the request is self-signed */
		SET_FLAG( certInfoPtr->flags, CERT_FLAG_SELFSIGNED );
		}
	else
		{
		/* If it's neither a signature nor an indication that private-key 
		   POP will be performed by returning the certificate in encrypted 
		   form then we can't do anything with it */
		if( tag != CTAG_CF_POP_ENCRKEY )
			{
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, CERTIFICATE_ERRINFO, 
					  "Unrecognised CRMF request private-key POP "
					  "mechanism %d", tag ) );
			}
		}
	return( readConstructed( stream, NULL, EXTRACT_CTAG( tag ) ) );
	}

/* Read CRMF revocation request information:

	RevDetails ::= SEQUENCE {
		certTemplate			SEQUENCE {
			serialNumber  [ 1 ]	INTEGER,
			issuer		  [ 3 ]	EXPLICIT Name,
			},
		crlEntryDetails			SET OF Attribute
		}

   We enforce the requirement that the request must contain at least an 
   issuer DN and a serial number */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRevRequestInfo( INOUT_PTR STREAM *stream, 
							   INOUT_PTR CERT_INFO *certInfoPtr )
	{
	int tag, length, endPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Find out how much certificate template information is present */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );

	/* Skip any junk before the serial number and read the serial number */
	status = skipCrmfJunk( stream, endPos, 
						   MAKE_CTAG_PRIMITIVE( CTAG_CF_SERIALNUMBER ), 
						   NO_TAG, NO_TAG );
	if( cryptStatusError( status ) )
		return( status );
	status = readSerialNumber( stream, certInfoPtr,
							   CTAG_CF_SERIALNUMBER );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "serial number", status ) );

	/* Skip any further junk before the issuer name and read the issuer 
	   name.  We don't actually care about the contents of the DN but we 
	   have to decode it anyway in case the caller wants to view it */
	status = skipCrmfJunk( stream, endPos, MAKE_CTAG( CTAG_CF_ISSUER ),
						   NO_TAG, NO_TAG );
	if( cryptStatusOK( status ) )
		status = readConstructed( stream, NULL, CTAG_CF_ISSUER );
	if( cryptStatusError( status ) )
		return( status );
	status = readIssuerDN( stream, certInfoPtr );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "issuer name", status ) );

	/* Skip any additional junk that may be present in the template, 
	   stopping if we get to the request attributes */
	status = skipCrmfJunk( stream, endPos, MAKE_CTAG( CTAG_CF_EXTENSIONS ),
						   NO_TAG, NO_TAG );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the attributes */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_CF_EXTENSIONS ) )
		{
		status = readConstructed( stream, &length, CTAG_CF_EXTENSIONS );
		if( cryptStatusOK( status ) && length > 0 )
			{
			status = readAttributes( stream, &certInfoPtr->attributes,
									 CRYPT_CERTTYPE_REQUEST_REVOCATION,
									 length, CERTIFICATE_ERRINFO,
									 &certInfoPtr->errorLocus,
									 &certInfoPtr->errorType );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Fix up any problems in attributes */
	return( fixAttributes( certInfoPtr ) );
	}
#endif /* USE_CERTREQ */

/****************************************************************************
*																			*
*						Read Validity-checking Objects						*
*																			*
****************************************************************************/

#ifdef USE_CERTVAL

/* Read an RTCS request:

	RTCSRequests ::= SEQUENCE {
		SEQUENCE OF 
			SEQUENCE {
				certHash	OCTET STRING SIZE(20)
				},
		attributes		Attributes OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRtcsRequestInfo( INOUT_PTR STREAM *stream, 
								INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;
	int length, endPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Read the outer wrapper */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );

	/* Read the request information and make the currently selected one the 
	   start of the list */
	status = readRTCSRequestEntries( stream, &certValInfo->validityInfo,
									 CERTIFICATE_ERRINFO );
	if( cryptStatusError( status ) )
		return( status );
	certValInfo->currentValidity = certValInfo->validityInfo;

	/* Read the extensions if there are any present */
	if( stell( stream ) < endPos )
		{
		status = readAttributes( stream, &certInfoPtr->attributes,
								 CRYPT_CERTTYPE_RTCS_REQUEST, 
								 endPos - stell( stream ),
								 CERTIFICATE_ERRINFO, 
								 &certInfoPtr->errorLocus, 
								 &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Fix up any problems in attributes */
	return( fixAttributes( certInfoPtr ) );
	}

/* Read an RTCS response:

	RTCSResponses ::= SEQUENCE OF 
		SEQUENCE {
			certHash	OCTET STRING SIZE(20),
			status		BOOLEAN
			} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRtcsResponseInfo( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Read the SEQUENCE OF validity information and make the currently 
	   selected one the start of the list */
	status = readRTCSResponseEntries( stream, &certValInfo->validityInfo,
									  CERTIFICATE_ERRINFO,
									  &certInfoPtr->errorLocus,
									  &certInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	certValInfo->currentValidity = certValInfo->validityInfo;

	return( CRYPT_OK );
	}
#endif /* USE_CERTVAL */

/****************************************************************************
*																			*
*						Read Revocation-checking Objects					*
*																			*
****************************************************************************/

#ifdef USE_CERTREV

/* Read an OCSP request:

	OCSPRequest ::= SEQUENCE {				-- Write, v1
		version		[0]	EXPLICIT INTEGER DEFAULT(0),
		reqName		[1]	EXPLICIT [4] EXPLICIT DirectoryName OPTIONAL,
		reqList			SEQUENCE OF SEQUENCE {
						SEQUENCE {			-- certID
			hashAlgo	AlgorithmIdentifier,
			iNameHash	OCTET STRING,
			iKeyHash	OCTET STRING,
			serialNo	INTEGER
			} }
		}

	OCSPRequest ::= SEQUENCE {				-- Write, v2
		version		[0]	EXPLICIT INTEGER (1),
		reqName		[1]	EXPLICIT [4] EXPLICIT DirectoryName OPTIONAL,
		reqList			SEQUENCE OF SEQUENCE {
			certID	[2]	EXPLICIT OCTET STRING	-- Certificate hash
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readOcspRequestInfo( INOUT_PTR STREAM *stream, 
								INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
	int tag, length, endPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Read the wrapper and version information */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	status = readVersion( stream, certInfoPtr, CTAG_OR_VERSION, 1 );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "version", status ) );

	/* Skip the optional requestor name */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_OR_DUMMY ) )
		status = readUniversal( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the SEQUENCE OF revocation information and make the currently 
	   selected one the start of the list */
	status = readOcspRequestEntries( stream, &certRevInfo->revocations,
									 CERTIFICATE_ERRINFO,
									 &certInfoPtr->errorLocus, 
									 &certInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	certRevInfo->currentRevocation = certRevInfo->revocations;

	/* Read the extensions if there are any present */
	if( stell( stream ) < endPos )
		{
		status = readAttributes( stream, &certInfoPtr->attributes,
								 CRYPT_CERTTYPE_OCSP_REQUEST, 
								 endPos - stell( stream ), 
								 CERTIFICATE_ERRINFO,
								 &certInfoPtr->errorLocus, 
								 &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Fix up any problems in attributes */
	return( fixAttributes( certInfoPtr ) );
	}

/* Read an OCSP response:

	OCSPResponse ::= SEQUENCE {
		version		[0]	EXPLICIT INTEGER DEFAULT (0),
		respID		[1]	EXPLICIT Name,
		producedAt		GeneralizedTime,
		responses		SEQUENCE OF Response
		exts		[1]	EXPLICIT Extensions OPTIONAL,
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readOcspResponseInfo( INOUT_PTR STREAM *stream, 
								 INOUT_PTR CERT_INFO *certInfoPtr )
	{
	CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
	int tag, length, endPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( certInfoPtr ) );

	/* Read the wrapper and version information */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	status = readVersion( stream, certInfoPtr, CTAG_OP_VERSION, 2 );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "version", status ) );

	/* Read the responder ID and produced-at time value */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 1 ) )
		{
		/* It's a DN, read it as the issuer name in case the caller is
		   interested in it */
		status = readConstructed( stream, NULL, 1 );
		if( cryptStatusOK( status ) )
			status = readIssuerDN( stream, certInfoPtr );
		}
	else
		{
		/* We can't do much with a key hash, in any case all current
		   responders use the issuer DN to identify the responder so
		   this shouldn't be much of a problem */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "responder ID", status ) );
	status = readGeneralizedTime( stream, &certInfoPtr->startTime );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, "produced-at time", status ) );

	/* Read the SEQUENCE OF revocation information and make the currently 
	   selected one the start of the list */
	status = readOcspResponseEntries( stream, &certRevInfo->revocations,
									  CERTIFICATE_ERRINFO,
									  &certInfoPtr->errorLocus, 
									  &certInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	certRevInfo->currentRevocation = certRevInfo->revocations;

	/* Read the extensions if there are any present */
	if( stell( stream ) < endPos )
		{
		status = readAttributes( stream, &certInfoPtr->attributes,
								 CRYPT_CERTTYPE_OCSP_RESPONSE, 
								 endPos - stell( stream ), 
								 CERTIFICATE_ERRINFO,
								 &certInfoPtr->errorLocus, 
								 &certInfoPtr->errorType );
		}

	/* In theory some OCSP responses can be sort of self-signed via attached
	   certificates but there are so many incompatible ways to delegate 
	   trust and signing authority mentioned in the RFC (one for each vendor
	   that contributed and an additional catchall in case any option got 
	   missed) without any indication of which one implementors will follow 
	   that we require the user to supply the signature check certificate 
	   rather than assuming that some particular trust delegation mechanism 
	   will happen to be in place */
/*	certInfoPtr->flags |= CERT_FLAG_SELFSIGNED; */

	return( status );
	}
#endif /* USE_CERTREV */

/****************************************************************************
*																			*
*						Read CMS Attribute Objects							*
*																			*
****************************************************************************/

#ifdef USE_CMSATTR

/* Read CMS attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readCmsAttributes( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CERT_INFO *attributeInfoPtr )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( attributeInfoPtr ) );

	/* CMS attributes are straight attribute objects so we just pass the call
	   through.  In addition since there's no encapsulation we specify a
	   special-case length of 0 to mean "whatever's there" */
	return( readAttributes( stream, &attributeInfoPtr->attributes,
							CRYPT_CERTTYPE_CMS_ATTRIBUTES, 0, CMS_ERRINFO,
							&attributeInfoPtr->errorLocus,
							&attributeInfoPtr->errorType ) );
	}
#endif /* USE_CMSATTR */

/****************************************************************************
*																			*
*							Read PKI User Objects							*
*																			*
****************************************************************************/

#ifdef USE_PKIUSER

/* Read PKI user information:

	userData ::= SEQUENCE {
		name				Name,			-- Name for CMP
		encAlgo				AlgorithmIdentifier,-- Algo to encrypt passwords
		encAuthData			OCTET STRING,	-- Encrypted authenticators
		certAttributes		Attributes		-- Certificate attributes
		userAttributes		SEQUENCE {		-- PKI user attributes
			isRA			BOOLEAN OPTIONAL -- Whether user is an RA
			} OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPkiUserInfo( INOUT_PTR STREAM *stream, 
							INOUT_PTR CERT_INFO *userInfoPtr )
	{
	CRYPT_CONTEXT iCryptContext;
	CERT_PKIUSER_INFO *certUserInfo = userInfoPtr->cCertUser;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	LOOP_INDEX_PTR DATAPTR_ATTRIBUTE attributeCursor;
	MESSAGE_DATA msgData;
	QUERY_INFO queryInfo;
	STREAM userInfoStream;
	ATTRIBUTE_ENUM_INFO attrEnumInfo;
	BYTE userInfo[ 128 + 8 ];
	int userInfoSize DUMMY_INIT, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( userInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( sanityCheckCert( userInfoPtr ) );

	/* Read the user name and encryption algorithm information */
	status = getStreamObjectLength( stream, &length, 16 );
	if( cryptStatusOK( status ) )
		{
		userInfoPtr->subjectDNsize = length;
		status = sMemGetDataBlock( stream, &userInfoPtr->subjectDNptr, 
								   length );
		}
	if( cryptStatusOK( status ) )
		status = readDN( stream, &userInfoPtr->subjectName );
	if( cryptStatusError( status ) )
		return( certErrorReturn( userInfoPtr, "name", status ) );
	status = readContextAlgoID( stream, NULL, &queryInfo, DEFAULT_TAG,
								ALGOID_CLASS_CRYPT );
	if( cryptStatusError( status ) )
		{
		return( certErrorReturn( userInfoPtr, "encryption algorithm", 
								 status ) );
		}

	/* Read the encrypted authentication data */
	status = readOctetString( stream, userInfo, &userInfoSize, 8, 128 );
	if( cryptStatusOK( status ) && \
		userInfoSize != PKIUSER_ENCR_AUTHENTICATOR_SIZE )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		{
		return( certErrorReturn( userInfoPtr, 
								 "encrypted authenticaton data", status ) );
		}

	/* Clone the CA data storage key for our own use, load the IV from the 
	   encryption information, and use the cloned context to decrypt the 
	   user information.  We need to do this to prevent problems if multiple 
	   threads try to simultaneously decrypt with the CA data storage key.  
	   See the comment in write.c for the use of the fixed interop key 
	   rather than actually using a clone of the CA data storage key as the 
	   comment would imply */
	switch( queryInfo.cryptAlgo )
		{
		case CRYPT_ALGO_AES:
			setMessageData( &msgData, "interop interop ", 16 );
			break;

		case CRYPT_ALGO_3DES:
			setMessageData( &msgData, "interop interop interop ", 24 );
			break;

		default:
			retIntError();
		}
	setMessageCreateObjectInfo( &createInfo, queryInfo.cryptAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iCryptContext = createInfo.cryptHandle;
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, queryInfo.iv, queryInfo.ivLength );
		status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_IV );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_DECRYPT,
								  userInfo, userInfoSize );
		}
	krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, PKIUSER_ERRINFO, 
				  "Couldn't decrypt PKI user authentication data" ) );
		}

	/* Read the user information.  If we get a bad data error at this point 
	   we report it as a wrong decryption key rather than bad data since 
	   it's more likely to be the former */
	sMemConnect( &userInfoStream, userInfo, userInfoSize );
	readSequence( &userInfoStream, NULL );
	readOctetString( &userInfoStream, certUserInfo->pkiIssuePW, &length,
					 PKIUSER_AUTHENTICATOR_SIZE, PKIUSER_AUTHENTICATOR_SIZE );
	status = readOctetString( &userInfoStream, certUserInfo->pkiRevPW,
							  &length, PKIUSER_AUTHENTICATOR_SIZE, 
							  PKIUSER_AUTHENTICATOR_SIZE );
	sMemDisconnect( &userInfoStream );
	REQUIRES( rangeCheck( userInfoSize, 1, 128 ) );
	zeroise( userInfo, userInfoSize );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_WRONGKEY, 
				( CRYPT_ERROR_WRONGKEY, PKIUSER_ERRINFO, 
				  "Error reading decrypted PKI user authentication data, "
				  "probably due to incorrect decryption key" ) );
		}

	/* Read any attributes */
	status = readAttributes( stream, &userInfoPtr->attributes,
							 CRYPT_CERTTYPE_PKIUSER, sMemDataLeft( stream ),
							 PKIUSER_ERRINFO, &userInfoPtr->errorLocus,
							 &userInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	if( sMemDataLeft( stream ) > 3 )
		{
		int tag;

		status = readSequence( stream, NULL );
		if( checkStatusPeekTag( stream, status, tag ) && \
			tag == BER_BOOLEAN )
			{
			status = readBoolean( stream, &certUserInfo->isRA );
			}
		if( cryptStatusError( status ) )
			return( certErrorReturn( userInfoPtr, "attributes", status ) );
		}

	/* As used by cryptlib the PKI user information is applied as a template 
	   to certificates to modify their contents before issue.  This is done 
	   by merging the user information with the certificate before it's 
	   issued.  Since there can be overlapping or conflicting attributes in 
	   the two objects, the ones in the PKI user information are marked as 
	   locked to ensure that they override any conflicting attributes that 
	   may be present in the certificate */
	LOOP_MAX( attributeCursor = getFirstAttribute( &attrEnumInfo, 
												   userInfoPtr->attributes,
												   ATTRIBUTE_ENUM_NONBLOB ), 
			  DATAPTR_ISSET( attributeCursor ),
			  attributeCursor = getNextAttribute( &attrEnumInfo ) )
		{
		ENSURES( LOOP_INVARIANT_MAX_GENERIC() );

		setAttributeProperty( attributeCursor, 
							  ATTRIBUTE_PROPERTY_LOCKED, 0 );
		}
	ENSURES( LOOP_BOUND_OK );

	return( CRYPT_OK );
	}
#endif /* USE_PKIUSER */

/****************************************************************************
*																			*
*						Read Function Access Information					*
*																			*
****************************************************************************/

typedef struct {
	const CRYPT_CERTTYPE_TYPE type;
	const READCERT_FUNCTION function;
	} CERTREAD_INFO;
static const CERTREAD_INFO certReadTable[] = {
	{ CRYPT_CERTTYPE_CERTIFICATE, readCertInfo },
#ifdef USE_ATTRCERT
	{ CRYPT_CERTTYPE_ATTRIBUTE_CERT, readAttributeCertInfo },
#endif /* USE_ATTRCERT */
#ifdef USE_CERTREV
	{ CRYPT_CERTTYPE_CRL, readCRLInfo },
#endif /* USE_CERTREV */
#ifdef USE_CERTREQ
	{ CRYPT_CERTTYPE_CERTREQUEST, readCertRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_CERT, readCrmfRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_REVOCATION, readRevRequestInfo },
#endif /* USE_CERTREQ */
#ifdef USE_CERTVAL
	{ CRYPT_CERTTYPE_RTCS_REQUEST, readRtcsRequestInfo },
	{ CRYPT_CERTTYPE_RTCS_RESPONSE, readRtcsResponseInfo },
#endif /* USE_CERTVAL */
#ifdef USE_CERTREV
	{ CRYPT_CERTTYPE_OCSP_REQUEST, readOcspRequestInfo },
	{ CRYPT_CERTTYPE_OCSP_RESPONSE, readOcspResponseInfo },
#endif /* USE_CERTREV */
#ifdef USE_CMSATTR
	{ CRYPT_CERTTYPE_CMS_ATTRIBUTES, readCmsAttributes },
#endif /* USE_CMSATTR */
#ifdef USE_PKIUSER
	{ CRYPT_CERTTYPE_PKIUSER, readPkiUserInfo },
#endif /* USE_PKIUSER */
	{ CRYPT_CERTTYPE_NONE, NULL }, { CRYPT_CERTTYPE_NONE, NULL }
	};

CHECK_RETVAL_PTR \
READCERT_FUNCTION getCertReadFunction( IN_ENUM( CRYPT_CERTTYPE ) \
										const CRYPT_CERTTYPE_TYPE certType )
	{
	LOOP_INDEX i;

	REQUIRES_N( isEnumRange( certType, CRYPT_CERTTYPE ) );

	LOOP_MED( i = 0,
			  i < FAILSAFE_ARRAYSIZE( certReadTable, CERTREAD_INFO ) && \
					certReadTable[ i ].type != CRYPT_CERTTYPE_NONE,
			  i++ )
		{
		ENSURES_N( LOOP_INVARIANT_MED( i, 0, 
									   FAILSAFE_ARRAYSIZE( certReadTable, \
														   CERTREAD_INFO ) - 1 ) );

		if( certReadTable[ i ].type == certType )
			return( certReadTable[ i ].function );
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( certReadTable, CERTREAD_INFO ) );

	return( NULL );
	}
#endif /* USE_CERTIFICATES */
