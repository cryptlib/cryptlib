<<<<<<< HEAD
/****************************************************************************
*																			*
*							Internal Signature Routines						*
*						Copyright Peter Gutmann 1993-2019					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "mech.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "mechs/mech.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Utility Functions								*
*																			*
****************************************************************************/

#ifdef USE_ERRMSGS

/* Get the name of a signature format for use in error messages */

static const char *getSigTypeName( IN_ENUM( SIGNATURE ) \
										const SIGNATURE_TYPE signatureType )
	{
	REQUIRES_EXT( isEnumRange( signatureType, SIGNATURE ), "<Unknown type>" );

	switch( signatureType )
		{
		case SIGNATURE_RAW:
		case SIGNATURE_X509:
			return( "X.509" );

		case SIGNATURE_PGP:
			return( "PGP" );

		case SIGNATURE_SSH:
			return( "SSH" );

		case SIGNATURE_TLS:
		case SIGNATURE_TLS12:
		case SIGNATURE_TLS13:
			return( "TLS" );
		
		default:
			return( "CMS" );
		}

	retIntError_Null();
	}
#endif /* USE_ERRMSGS */

/****************************************************************************
*																			*
*							DLP Signature Handling							*
*																			*
****************************************************************************/

/* Create a DLP signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int createDlpSignature( OUT_BUFFER_OPT( bufSize, *length ) \
									void *buffer,
							   IN_RANGE( 0, CRYPT_MAX_PKCSIZE ) \
									const int bufSize, 
							   OUT_LENGTH_BOUNDED_SHORT_Z( bufSize ) \
									int *length, 
							   IN_HANDLE const CRYPT_CONTEXT iSignContext,
							   IN_HANDLE const CRYPT_CONTEXT iHashContext,
							   IN_ENUM( SIGNATURE ) \
									const SIGNATURE_TYPE signatureType,
							   IN_BOOL const BOOLEAN isECC )
	{
	DLP_PARAMS dlpParams;
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int hashSize, status;

	assert( ( buffer == NULL && bufSize == 0 ) || \
			isWritePtrDynamic( buffer, bufSize ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( ( buffer == NULL && bufSize == 0 ) || \
			  ( buffer != NULL && \
			    bufSize > MIN_CRYPT_OBJECTSIZE && \
				bufSize <= CRYPT_MAX_PKCSIZE ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isEnumRange( signatureType, SIGNATURE ) );
	REQUIRES( isBooleanValue( isECC ) );

	/* Clear return value */
	*length = 0;

	/* Extract the hash value from the context.  If we're doing a length 
	   check then there's no hash value present yet, so we just fill in the 
	   hash length value from the blocksize attribute */
	if( buffer == NULL )
		{
		memset( hash, 0, CRYPT_MAX_HASHSIZE );	/* Keep mem.checkers happy */
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &msgData.length, 
								  CRYPT_CTXINFO_BLOCKSIZE );
		}
	else
		{
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* SSH hardcodes SHA-1 (or at least two fixed-length values of 20 bytes)
	   into its signature format, so we can't create an SSH signature unless
	   we're using a 20-byte hash */
	if( !isECC && signatureType == SIGNATURE_SSH && hashSize != 20 )
		{
		/* The error reporting here is a bit complex, see the comment in 
		   createSignature() for how this works */
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* If we're doing a length check and the signature is being written in 
	   cryptlib format the length is just an estimate since it can change by 
	   several bytes depending on whether the signature values have the high 
	   bit set or not (which requires zero-padding of the ASN.1-encoded 
	   integers) or have the high bytes set to zero(es).  We use a worst-
	   case estimate here and assume that both integers will be of the 
	   maximum size and need padding, which is rather nasty because it means 
	   that we can't tell how large a signature will be without actually 
	   creating it */
	if( buffer == NULL )
		{
		int sigComponentSize = hashSize;

		if( isECC )
			{
			/* For ECC signatures the reduction is done mod n, which is
			   variable-length, but for standard curves is the same as the
			   key size */
			status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE,
									  &sigComponentSize, 
									  CRYPT_CTXINFO_KEYSIZE );
			if( cryptStatusError( status ) )
				return( status );
			}
		switch( signatureType )
			{
#ifdef USE_PGP
			case SIGNATURE_PGP:
				*length = 2 * ( 2 + sigComponentSize );
				break;
#endif /* USE_PGP */

#ifdef USE_SSH
			case SIGNATURE_SSH:
				*length = 2 * sigComponentSize;
				break;
#endif /* USE_SSH */

#ifdef USE_INT_ASN1
			default:
				*length = sizeofObject( \
								( 2 * sizeofObject( \
										sigComponentSize + 1 ) ) );
				break;
#else
			default:
				retIntError();
#endif /* USE_INT_ASN1 */
			}
		CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

		ENSURES( CFI_CHECK_SEQUENCE_2( "IMESSAGE_GETATTRIBUTE_S", 
									   "IMESSAGE_GETATTRIBUTE" ) );

		ENSURES( isShortIntegerRangeNZ( *length ) );

		return( CRYPT_OK );
		}

	/* Sign the data */
	setDLPParams( &dlpParams, hash, hashSize, buffer, bufSize );
	if( signatureType == SIGNATURE_PGP )
		dlpParams.formatType = CRYPT_FORMAT_PGP;
	if( signatureType == SIGNATURE_SSH )
		dlpParams.formatType = CRYPT_IFORMAT_SSH;
	status = krnlSendMessage( iSignContext, IMESSAGE_CTX_SIGN, 
							  &dlpParams, sizeof( DLP_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );
	*length = dlpParams.outLen;
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGN" );

	ENSURES( CFI_CHECK_SEQUENCE_2( "IMESSAGE_GETATTRIBUTE_S", 
								   "IMESSAGE_CTX_SIGN" ) );

	ENSURES( isShortIntegerRangeNZ( *length ) );
	
	return( CRYPT_OK );
	}

/* Check a DLP signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkDlpSignature( IN_BUFFER( signatureDataLength ) \
									const void *signatureData, 
							  IN_LENGTH_SHORT const int signatureDataLength,
							  IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
							  IN_HANDLE const CRYPT_CONTEXT iHashContext,
							  IN_ENUM( SIGNATURE ) \
									const SIGNATURE_TYPE signatureType )
	{
	DLP_PARAMS dlpParams;
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int hashSize, status;

	REQUIRES( ( signatureType == SIGNATURE_SSH && \
				signatureDataLength == 40 ) || \
			  ( isShortIntegerRangeMin( signatureDataLength, 40 ) ) );
	REQUIRES( isHandleRangeValid( iSigCheckContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isEnumRange( signatureType, SIGNATURE ) );

	/* Extract the hash value from the context */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* Check the signature validity using the encoded signature data and 
	   hash */
	setDLPParams( &dlpParams, hash, hashSize, NULL, 0 );
	dlpParams.inParam2 = signatureData;
	dlpParams.inLen2 = signatureDataLength;
	if( signatureType == SIGNATURE_PGP )
		dlpParams.formatType = CRYPT_FORMAT_PGP;
	if( signatureType == SIGNATURE_SSH )
		dlpParams.formatType = CRYPT_IFORMAT_SSH;
	status = krnlSendMessage( iSigCheckContext, IMESSAGE_CTX_SIGCHECK,
							  &dlpParams, sizeof( DLP_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGCHECK" );

	ENSURES( CFI_CHECK_SEQUENCE_2( "IMESSAGE_GETATTRIBUTE_S", 
								   "IMESSAGE_CTX_SIGCHECK" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Create a Signature							*
*																			*
****************************************************************************/

/* Common signature-creation routine, used by other sign_xxx.c modules */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 8 ) ) \
int createSignature( OUT_BUFFER_OPT( sigMaxLength, *signatureLength ) \
						void *signature, 
					 IN_LENGTH_SHORT_Z const int sigMaxLength, 
					 OUT_LENGTH_BOUNDED_SHORT_Z( sigMaxLength ) \
						int *signatureLength, 
					 IN_HANDLE const CRYPT_CONTEXT iSignContext,
					 IN_HANDLE const CRYPT_CONTEXT iHashContext,
					 IN_HANDLE_OPT const CRYPT_CONTEXT iHashContext2,
					 IN_ENUM( SIGNATURE ) \
						const SIGNATURE_TYPE signatureType,
					 INOUT_PTR ERROR_INFO *errorInfo )
	{
	STREAM stream;
	const WRITESIG_FUNCTION writeSigFunction = getWriteSigFunction( signatureType );
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE *bufPtr = ( signature == NULL ) ? NULL : buffer;
	const int bufSize = ( signature == NULL ) ? 0 : CRYPT_MAX_PKCSIZE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int signAlgo, hashAlgo, length DUMMY_INIT, hashParam = 0, status;

	assert( ( signature == NULL && sigMaxLength == 0 ) || \
			isWritePtrDynamic( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( ( signature == NULL && sigMaxLength == 0 ) || \
			  ( signature != NULL && \
			    isShortIntegerRangeMin( sigMaxLength, \
										MIN_CRYPT_OBJECTSIZE ) ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( ( signatureType == SIGNATURE_TLS && \
				isHandleRangeValid( iHashContext2 ) ) || \
			  ( ( signatureType == SIGNATURE_CMS || \
				  signatureType == SIGNATURE_CMS_PSS || \
				  signatureType == SIGNATURE_CRYPTLIB || \
				  signatureType == SIGNATURE_PGP || \
				  signatureType == SIGNATURE_RAW || \
				  signatureType == SIGNATURE_SSH || \
				  signatureType == SIGNATURE_TLS12 || \
				  signatureType == SIGNATURE_TLS13 || \
				  signatureType == SIGNATURE_X509 ) && \
				iHashContext2 == CRYPT_UNUSED ) );

	/* Clear return value */
	if( signature != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( sigMaxLength ) ); 
		memset( signature, 0, min( 16, sigMaxLength ) );
		}
	*signatureLength = 0;

	/* Make sure that the requested signature format is available */
	if( writeSigFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Extract general information */
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE, &signAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM1 : status );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &hashParam, CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM2 : status );
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

	/* DLP and ECDLP signatures are handled somewhat specially */
	INJECT_FAULT( MECH_CORRUPT_HASH, MECH_CORRUPT_HASH_1 );
	if( isDlpAlgo( signAlgo ) || isEccAlgo( signAlgo ) )
		{
		/* In addition to the special-case processing for DLP/ECDLP 
		   signatures, we have to provide even further special handling for 
		   TLS signatures, which normally sign a dual hash of MD5 and SHA-1 
		   but for DLP only sign the second SHA-1 hash */
		status = createDlpSignature( bufPtr, bufSize, &length, iSignContext, 
									 ( signatureType == SIGNATURE_TLS ) ? \
									   iHashContext2 : iHashContext, 
									 signatureType, 
									 isEccAlgo( signAlgo ) ? TRUE : FALSE );
		CFI_CHECK_UPDATE( "IMESSAGE_DEV_SIGN" );
		}
	else
		{
		MECHANISM_SIGN_INFO mechanismInfo;

		/* It's a standard signature, process it as normal */
		setMechanismSignInfo( &mechanismInfo, bufPtr, bufSize, iHashContext, 
							  iHashContext2, iSignContext );
		status = krnlSendMessage( iSignContext, IMESSAGE_DEV_SIGN, &mechanismInfo,
								  ( signatureType == SIGNATURE_TLS ) ? \
									MECHANISM_SIG_TLS : \
								  ( signatureType == SIGNATURE_CMS_PSS || \
									signatureType == SIGNATURE_TLS13 ) ? \
									MECHANISM_SIG_PSS : MECHANISM_SIG_PKCS1 );
		if( cryptStatusOK( status ) )
			length = mechanismInfo.signatureLength;
		clearMechanismInfo( &mechanismInfo );
		CFI_CHECK_UPDATE( "IMESSAGE_DEV_SIGN" );
		}
	if( cryptStatusError( status ) )
		{
		/* The mechanism messages place the acted-on object (in this case the
		   hash context) first while the higher-level functions place the
		   signature context next to the signature data, in other words
		   before the hash context.  Because of this we have to reverse
		   parameter error values when translating from the mechanism to the
		   signature function level */
		if( bufPtr != NULL )
			zeroise( bufPtr, CRYPT_MAX_PKCSIZE );
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ARGERROR_NUM2 : \
				 ( status == CRYPT_ARGERROR_NUM2 ) ? CRYPT_ARGERROR_NUM1 : \
				 status;
		retExt( status,
				( status, errorInfo,
				  "Creation of %s %s signature failed", 
				  getAlgoName( signAlgo ), 
				  getSigTypeName( signatureType ) ) );
		}
	INJECT_FAULT( MECH_CORRUPT_SIG, MECH_CORRUPT_SIG_1 );

	/* If we're perfoming a dummy sign for a length check, set up a dummy 
	   value to write */
	if( signature == NULL )
		{
		REQUIRES( rangeCheck( length, 1, CRYPT_MAX_PKCSIZE ) );
		memset( buffer, 0x01, length );
		}

	/* Write the signature record to the output */
	sMemOpenOpt( &stream, signature, sigMaxLength );
	status = writeSigFunction( &stream, iSignContext, hashAlgo, hashParam, 
							   signAlgo, buffer, length );
	if( cryptStatusOK( status ) )
		*signatureLength = stell( &stream );
	sMemDisconnect( &stream );
	CFI_CHECK_UPDATE( "writeSigFunction" );

	/* Clean up */
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Couldn't write %s %s signature",
				  getAlgoName( signAlgo ), 
				  getSigTypeName( signatureType ) ) );
		}
	ENSURES( isShortIntegerRangeNZ( *signatureLength ) );

	ENSURES( CFI_CHECK_SEQUENCE_3( "IMESSAGE_GETATTRIBUTE", 
								   "IMESSAGE_DEV_SIGN", "writeSigFunction" ) );

	ENSURES( isShortIntegerRangeNZ( *signatureLength ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Check a Signature							*
*																			*
****************************************************************************/

/* Common signature-checking routine, used by other sign_xxx.c modules */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 7 ) ) \
int checkSignature( IN_BUFFER( signatureLength ) const void *signature, 
					IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength,
					IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
					IN_HANDLE const CRYPT_CONTEXT iHashContext,
					IN_HANDLE_OPT const CRYPT_CONTEXT iHashContext2,
					IN_ENUM( SIGNATURE ) \
						const SIGNATURE_TYPE signatureType,
					INOUT_PTR ERROR_INFO *errorInfo )
	{
	MECHANISM_SIGN_INFO mechanismInfo;
	const READSIG_FUNCTION readSigFunction = getReadSigFunction( signatureType );
	QUERY_INFO queryInfo;
	STREAM stream;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *signatureData;
	BOOLEAN isCertificate = FALSE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int signAlgo, hashAlgo, hashParam = 0, sigFormat, value;
	int signatureDataLength, compareType = MESSAGE_COMPARE_NONE, status;

	assert( isReadPtrDynamic( signature, signatureLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	
	REQUIRES( isShortIntegerRangeMin( signatureLength, 40 ) );
	REQUIRES( isHandleRangeValid( iSigCheckContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( ( signatureType == SIGNATURE_TLS && \
				isHandleRangeValid( iHashContext2 ) ) || \
			  ( ( signatureType == SIGNATURE_CMS || \
				  signatureType == SIGNATURE_CMS_PSS || \
				  signatureType == SIGNATURE_CRYPTLIB || \
				  signatureType == SIGNATURE_PGP || \
				  signatureType == SIGNATURE_RAW || \
				  signatureType == SIGNATURE_SSH || \
				  signatureType == SIGNATURE_TLS12 || \
				  signatureType == SIGNATURE_TLS13 || \
				  signatureType == SIGNATURE_X509 ) && \
				iHashContext2 == CRYPT_UNUSED ) );

	/* Make sure that the requested signature format is available */
	if( readSigFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Extract general information */
	sigFormat = ( signatureType == SIGNATURE_TLS ) ? MECHANISM_SIG_TLS : \
				( signatureType == SIGNATURE_CMS_PSS ) ? \
				  MECHANISM_SIG_PSS : MECHANISM_SIG_PKCS1;
	status = krnlSendMessage( iSigCheckContext, IMESSAGE_GETATTRIBUTE,
							  &signAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM1 : status );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && isParameterisedHashAlgo( hashAlgo ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &hashParam, CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM2 : status );
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

	/* Check whether we're dealing with a certificate.  This is used to 
	   allow for more detailed error reporting if something goes wrong */
	status = krnlSendMessage( iSigCheckContext, IMESSAGE_GETATTRIBUTE, 
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) )
		isCertificate = TRUE;

	/* Read and check the signature record */
	sMemConnect( &stream, signature, signatureLength );
	status = readSigFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		retExt( status,
				( status, errorInfo,
				  "Invalid %s signature record", 
				  getSigTypeName( signatureType ) ) );
		}
	CFI_CHECK_UPDATE( "readSigFunction" );

	/* Make sure that we've been given the correct algorithms */
	if( signatureType != SIGNATURE_RAW && signatureType != SIGNATURE_TLS )
		{
		if( signAlgo != queryInfo.cryptAlgo || \
			hashAlgo != queryInfo.hashAlgo )
			status = CRYPT_ERROR_SIGNATURE;
		if( signatureType != SIGNATURE_SSH )
			{
			/* SSH requires complex string-parsing to determine the optional
			   parameters, so the check is done elsewhere */
			if( isParameterisedHashAlgo( hashAlgo ) && \
				hashParam != queryInfo.hashParam )
				status = CRYPT_ERROR_SIGNATURE;
			}
		if( cryptStatusError( status ) )
			{
			zeroise( &queryInfo, sizeof( QUERY_INFO ) );
			retExt( status,
					( status, errorInfo,
					  "%s/%s algorithms in %s signature don't match "
					  "%s/%s algorithms in signature-check/hash objects", 
					  getAlgoName( queryInfo.cryptAlgo ), 
					  getAlgoNameEx( queryInfo.hashAlgo, 
									 queryInfo.hashParam ), 
					  getSigTypeName( signatureType ),
					  getAlgoName( signAlgo ), 
					  getAlgoNameEx( hashAlgo, hashParam ) ) );
			}
		}

	/* Make sure that we've been given the correct key if the signature
	   format supports this type of check */
	switch( signatureType )
		{
		case SIGNATURE_CMS:
			/* This format supports a check with 
			   MESSAGE_COMPARE_ISSUERANDSERIALNUMBER but this has already 
			   been done while procesing the other CMS data before we were 
			   called so we don't need to do it again */
			/* compareType = MESSAGE_COMPARE_ISSUERANDSERIALNUMBER; */
			break;

		case SIGNATURE_CRYPTLIB:
			compareType = MESSAGE_COMPARE_KEYID;
			break;

		case SIGNATURE_PGP:
			compareType = ( queryInfo.version == PGP_VERSION_2 ) ? \
							MESSAGE_COMPARE_KEYID_PGP : \
							MESSAGE_COMPARE_KEYID_OPENPGP;
			break;

		default:
			/* Other format types don't include identification information
			   with the signature */
			break;
		}
	if( compareType != MESSAGE_COMPARE_NONE )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, queryInfo.keyID, queryInfo.keyIDlength );
		status = krnlSendMessage( iSigCheckContext, IMESSAGE_COMPARE,
								  &msgData, compareType );
		if( cryptStatusError( status ) && \
			compareType == MESSAGE_COMPARE_KEYID )
			{
			/* Checking for the keyID gets a bit complicated, in theory it's 
			   the subjectKeyIdentifier from a certificate but in practice 
			   this form is mostly used for certificateless public keys.  
			   Because of this we check for the keyID first and if that 
			   fails fall back to the sKID */
			status = krnlSendMessage( iSigCheckContext, IMESSAGE_COMPARE, 
									  &msgData, 
									  MESSAGE_COMPARE_SUBJECTKEYIDENTIFIER );
			}
		if( cryptStatusError( status ) )
			{
			/* A failed comparison is reported as a generic CRYPT_ERROR,
			   convert it into a wrong-key error */
			zeroise( &queryInfo, sizeof( QUERY_INFO ) );
			if( isCertificate )
				{
				retExt( CRYPT_ERROR_WRONGKEY,
						( CRYPT_ERROR_WRONGKEY, errorInfo,
						  "%s signature-check key for '%s' doesn't match "
						  "key used in %s signature", 
						  getAlgoName( signAlgo ), 
						  getCertHolderName( iSigCheckContext, certName, 
											 CRYPT_MAX_TEXTSIZE ),
						  getSigTypeName( signatureType ) ) );
				}
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, errorInfo,
					  "%s signature-check key doesn't match key used in "
					  "%s signature", getAlgoName( signAlgo ), 
					  getSigTypeName( signatureType ) ) );
			}
		}
	REQUIRES( boundsCheck( queryInfo.dataStart, queryInfo.dataLength,
						   signatureLength ) );
	signatureData = ( BYTE * ) signature + queryInfo.dataStart;
	signatureDataLength = queryInfo.dataLength;
	if( queryInfo.cryptAlgoEncoding != ALGOID_ENCODING_NONE )
		{
		/* The signature type has been modified by something in the encoded 
		   signature data, change the format type to match */
		switch( queryInfo.cryptAlgoEncoding )
			{
			case ALGOID_ENCODING_PSS:
				sigFormat = MECHANISM_SIG_PSS;
				break;

			default:
				retIntError();
			}
		}
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );
	CFI_CHECK_UPDATE( "IMESSAGE_COMPARE" );

	/* DLP and ECDLP signatures are handled somewhat specially */
	if( isDlpAlgo( signAlgo ) || isEccAlgo( signAlgo ) )
		{
		/* In addition to the special-case processing for DLP/ECDLP 
		   signatures, we have to provide even further special handling for 
		   TLS signatures, which normally sign a dual hash of MD5 and SHA-1 
		   but for DLP only sign the second SHA-1 hash */
		status = checkDlpSignature( signatureData, signatureDataLength, 
									iSigCheckContext, 
									( signatureType == SIGNATURE_TLS ) ? \
									  iHashContext2 : iHashContext,
									signatureType );
		if( cryptStatusError( status ) )
			{
			if( isCertificate )
				{
				retExt( status,
						( status, errorInfo,
						  "Signature check of %s %s signature with key for "
						  "'%s' failed", 
						  getAlgoName( signAlgo ), 
						  getSigTypeName( signatureType ),
						  getCertHolderName( iSigCheckContext, certName, 
											 CRYPT_MAX_TEXTSIZE ) ) );
				}
			retExt( status,
					( status, errorInfo,
					  "Signature check of %s %s signature failed", 
					  getAlgoName( signAlgo ), 
					  getSigTypeName( signatureType ) ) );
			}
		CFI_CHECK_UPDATE( "checkDlpSignature" );

		ENSURES( CFI_CHECK_SEQUENCE_4( "IMESSAGE_GETATTRIBUTE", 
									   "readSigFunction", "IMESSAGE_COMPARE", 
									   "checkDlpSignature" ) );
		return( CRYPT_OK );
		}

	/* It's a standard signature, process it as normal */
	setMechanismSignInfo( &mechanismInfo, signatureData, signatureDataLength, 
						  iHashContext, iHashContext2, iSigCheckContext );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_SIGCHECK, 
							  &mechanismInfo, sigFormat );
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		{
		/* The mechanism messages place the acted-on object (in this case the 
		   hash context) first while the higher-level functions place the 
		   signature context next to the signature data, in other words 
		   before the hash context.  Because of this we have to reverse 
		   parameter error values when translating from the mechanism to the 
		   signature function level */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ARGERROR_NUM2 : \
				 ( status == CRYPT_ARGERROR_NUM2 ) ? CRYPT_ARGERROR_NUM1 : \
				 status;
		if( isCertificate )
			{
			retExt( status,
					( status, errorInfo,
					  "Signature check of %s %s signature with key for "
					  "'%s' failed", 
					  getAlgoName( signAlgo ), 
					  getSigTypeName( signatureType ),
					  getCertHolderName( iSigCheckContext, certName, 
										 CRYPT_MAX_TEXTSIZE ) ) );
			}
		retExt( status,
				( status, errorInfo,
				  "Signature check of %s %s signature failed", 
				  getAlgoName( signAlgo ), 
				  getSigTypeName( signatureType ) ) );
		}
	CFI_CHECK_UPDATE( "IMESSAGE_DEV_SIGCHECK" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "IMESSAGE_GETATTRIBUTE", "readSigFunction", 
								   "IMESSAGE_COMPARE", 
								   "IMESSAGE_DEV_SIGCHECK" ) );

	return( CRYPT_OK );
	}
=======
/****************************************************************************
*																			*
*							Internal Signature Routines						*
*						Copyright Peter Gutmann 1993-2019					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "mech.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "mechs/mech.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Utility Functions								*
*																			*
****************************************************************************/

#ifdef USE_ERRMSGS

/* Get the name of a signature format for use in error messages */

static const char *getSigTypeName( IN_ENUM( SIGNATURE ) \
										const SIGNATURE_TYPE signatureType )
	{
	REQUIRES_EXT( isEnumRange( signatureType, SIGNATURE ), "<Unknown type>" );

	switch( signatureType )
		{
		case SIGNATURE_RAW:
		case SIGNATURE_X509:
			return( "X.509" );

		case SIGNATURE_PGP:
			return( "PGP" );

		case SIGNATURE_SSH:
			return( "SSH" );

		case SIGNATURE_TLS:
		case SIGNATURE_TLS12:
		case SIGNATURE_TLS13:
			return( "TLS" );
		
		default:
			return( "CMS" );
		}

	retIntError_Null();
	}
#endif /* USE_ERRMSGS */

/****************************************************************************
*																			*
*							DLP Signature Handling							*
*																			*
****************************************************************************/

/* Create a DLP signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int createDlpSignature( OUT_BUFFER_OPT( bufSize, *length ) \
									void *buffer,
							   IN_RANGE( 0, CRYPT_MAX_PKCSIZE ) \
									const int bufSize, 
							   OUT_LENGTH_BOUNDED_SHORT_Z( bufSize ) \
									int *length, 
							   IN_HANDLE const CRYPT_CONTEXT iSignContext,
							   IN_HANDLE const CRYPT_CONTEXT iHashContext,
							   IN_ENUM( SIGNATURE ) \
									const SIGNATURE_TYPE signatureType,
							   IN_BOOL const BOOLEAN isECC )
	{
	DLP_PARAMS dlpParams;
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int hashSize, status;

	assert( ( buffer == NULL && bufSize == 0 ) || \
			isWritePtrDynamic( buffer, bufSize ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( ( buffer == NULL && bufSize == 0 ) || \
			  ( buffer != NULL && \
			    bufSize > MIN_CRYPT_OBJECTSIZE && \
				bufSize <= CRYPT_MAX_PKCSIZE ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isEnumRange( signatureType, SIGNATURE ) );
	REQUIRES( isBooleanValue( isECC ) );

	/* Clear return value */
	*length = 0;

	/* Extract the hash value from the context.  If we're doing a length 
	   check then there's no hash value present yet, so we just fill in the 
	   hash length value from the blocksize attribute */
	if( buffer == NULL )
		{
		memset( hash, 0, CRYPT_MAX_HASHSIZE );	/* Keep mem.checkers happy */
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &msgData.length, 
								  CRYPT_CTXINFO_BLOCKSIZE );
		}
	else
		{
		setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* SSH hardcodes SHA-1 (or at least two fixed-length values of 20 bytes)
	   into its signature format, so we can't create an SSH signature unless
	   we're using a 20-byte hash */
	if( !isECC && signatureType == SIGNATURE_SSH && hashSize != 20 )
		{
		/* The error reporting here is a bit complex, see the comment in 
		   createSignature() for how this works */
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* If we're doing a length check and the signature is being written in 
	   cryptlib format the length is just an estimate since it can change by 
	   several bytes depending on whether the signature values have the high 
	   bit set or not (which requires zero-padding of the ASN.1-encoded 
	   integers) or have the high bytes set to zero(es).  We use a worst-
	   case estimate here and assume that both integers will be of the 
	   maximum size and need padding, which is rather nasty because it means 
	   that we can't tell how large a signature will be without actually 
	   creating it */
	if( buffer == NULL )
		{
		int sigComponentSize = hashSize;

		if( isECC )
			{
			/* For ECC signatures the reduction is done mod n, which is
			   variable-length, but for standard curves is the same as the
			   key size */
			status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE,
									  &sigComponentSize, 
									  CRYPT_CTXINFO_KEYSIZE );
			if( cryptStatusError( status ) )
				return( status );
			}
		switch( signatureType )
			{
#ifdef USE_PGP
			case SIGNATURE_PGP:
				*length = 2 * ( 2 + sigComponentSize );
				break;
#endif /* USE_PGP */

#ifdef USE_SSH
			case SIGNATURE_SSH:
				*length = 2 * sigComponentSize;
				break;
#endif /* USE_SSH */

#ifdef USE_INT_ASN1
			default:
				*length = sizeofObject( \
								( 2 * sizeofObject( \
										sigComponentSize + 1 ) ) );
				break;
#else
			default:
				retIntError();
#endif /* USE_INT_ASN1 */
			}
		CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

		ENSURES( CFI_CHECK_SEQUENCE_2( "IMESSAGE_GETATTRIBUTE_S", 
									   "IMESSAGE_GETATTRIBUTE" ) );

		ENSURES( isShortIntegerRangeNZ( *length ) );

		return( CRYPT_OK );
		}

	/* Sign the data */
	setDLPParams( &dlpParams, hash, hashSize, buffer, bufSize );
	if( signatureType == SIGNATURE_PGP )
		dlpParams.formatType = CRYPT_FORMAT_PGP;
	if( signatureType == SIGNATURE_SSH )
		dlpParams.formatType = CRYPT_IFORMAT_SSH;
	status = krnlSendMessage( iSignContext, IMESSAGE_CTX_SIGN, 
							  &dlpParams, sizeof( DLP_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );
	*length = dlpParams.outLen;
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGN" );

	ENSURES( CFI_CHECK_SEQUENCE_2( "IMESSAGE_GETATTRIBUTE_S", 
								   "IMESSAGE_CTX_SIGN" ) );

	ENSURES( isShortIntegerRangeNZ( *length ) );
	
	return( CRYPT_OK );
	}

/* Check a DLP signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkDlpSignature( IN_BUFFER( signatureDataLength ) \
									const void *signatureData, 
							  IN_LENGTH_SHORT const int signatureDataLength,
							  IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
							  IN_HANDLE const CRYPT_CONTEXT iHashContext,
							  IN_ENUM( SIGNATURE ) \
									const SIGNATURE_TYPE signatureType )
	{
	DLP_PARAMS dlpParams;
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int hashSize, status;

	REQUIRES( ( signatureType == SIGNATURE_SSH && \
				signatureDataLength == 40 ) || \
			  ( isShortIntegerRangeMin( signatureDataLength, 40 ) ) );
	REQUIRES( isHandleRangeValid( iSigCheckContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isEnumRange( signatureType, SIGNATURE ) );

	/* Extract the hash value from the context */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashSize = msgData.length;
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE_S" );

	/* Check the signature validity using the encoded signature data and 
	   hash */
	setDLPParams( &dlpParams, hash, hashSize, NULL, 0 );
	dlpParams.inParam2 = signatureData;
	dlpParams.inLen2 = signatureDataLength;
	if( signatureType == SIGNATURE_PGP )
		dlpParams.formatType = CRYPT_FORMAT_PGP;
	if( signatureType == SIGNATURE_SSH )
		dlpParams.formatType = CRYPT_IFORMAT_SSH;
	status = krnlSendMessage( iSigCheckContext, IMESSAGE_CTX_SIGCHECK,
							  &dlpParams, sizeof( DLP_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_SIGCHECK" );

	ENSURES( CFI_CHECK_SEQUENCE_2( "IMESSAGE_GETATTRIBUTE_S", 
								   "IMESSAGE_CTX_SIGCHECK" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Create a Signature							*
*																			*
****************************************************************************/

/* Common signature-creation routine, used by other sign_xxx.c modules */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 8 ) ) \
int createSignature( OUT_BUFFER_OPT( sigMaxLength, *signatureLength ) \
						void *signature, 
					 IN_LENGTH_SHORT_Z const int sigMaxLength, 
					 OUT_LENGTH_BOUNDED_SHORT_Z( sigMaxLength ) \
						int *signatureLength, 
					 IN_HANDLE const CRYPT_CONTEXT iSignContext,
					 IN_HANDLE const CRYPT_CONTEXT iHashContext,
					 IN_HANDLE_OPT const CRYPT_CONTEXT iHashContext2,
					 IN_ENUM( SIGNATURE ) \
						const SIGNATURE_TYPE signatureType,
					 INOUT_PTR ERROR_INFO *errorInfo )
	{
	STREAM stream;
	const WRITESIG_FUNCTION writeSigFunction = getWriteSigFunction( signatureType );
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE *bufPtr = ( signature == NULL ) ? NULL : buffer;
	const int bufSize = ( signature == NULL ) ? 0 : CRYPT_MAX_PKCSIZE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int signAlgo, hashAlgo, length DUMMY_INIT, hashParam = 0, status;

	assert( ( signature == NULL && sigMaxLength == 0 ) || \
			isWritePtrDynamic( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( ( signature == NULL && sigMaxLength == 0 ) || \
			  ( signature != NULL && \
			    isShortIntegerRangeMin( sigMaxLength, \
										MIN_CRYPT_OBJECTSIZE ) ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( ( signatureType == SIGNATURE_TLS && \
				isHandleRangeValid( iHashContext2 ) ) || \
			  ( ( signatureType == SIGNATURE_CMS || \
				  signatureType == SIGNATURE_CMS_PSS || \
				  signatureType == SIGNATURE_CRYPTLIB || \
				  signatureType == SIGNATURE_PGP || \
				  signatureType == SIGNATURE_RAW || \
				  signatureType == SIGNATURE_SSH || \
				  signatureType == SIGNATURE_TLS12 || \
				  signatureType == SIGNATURE_TLS13 || \
				  signatureType == SIGNATURE_X509 ) && \
				iHashContext2 == CRYPT_UNUSED ) );

	/* Clear return value */
	if( signature != NULL )
		{
		REQUIRES( isShortIntegerRangeNZ( sigMaxLength ) ); 
		memset( signature, 0, min( 16, sigMaxLength ) );
		}
	*signatureLength = 0;

	/* Make sure that the requested signature format is available */
	if( writeSigFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Extract general information */
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE, &signAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM1 : status );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &hashParam, CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM2 : status );
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

	/* DLP and ECDLP signatures are handled somewhat specially */
	INJECT_FAULT( MECH_CORRUPT_HASH, MECH_CORRUPT_HASH_1 );
	if( isDlpAlgo( signAlgo ) || isEccAlgo( signAlgo ) )
		{
		/* In addition to the special-case processing for DLP/ECDLP 
		   signatures, we have to provide even further special handling for 
		   TLS signatures, which normally sign a dual hash of MD5 and SHA-1 
		   but for DLP only sign the second SHA-1 hash */
		status = createDlpSignature( bufPtr, bufSize, &length, iSignContext, 
									 ( signatureType == SIGNATURE_TLS ) ? \
									   iHashContext2 : iHashContext, 
									 signatureType, 
									 isEccAlgo( signAlgo ) ? TRUE : FALSE );
		CFI_CHECK_UPDATE( "IMESSAGE_DEV_SIGN" );
		}
	else
		{
		MECHANISM_SIGN_INFO mechanismInfo;

		/* It's a standard signature, process it as normal */
		setMechanismSignInfo( &mechanismInfo, bufPtr, bufSize, iHashContext, 
							  iHashContext2, iSignContext );
		status = krnlSendMessage( iSignContext, IMESSAGE_DEV_SIGN, &mechanismInfo,
								  ( signatureType == SIGNATURE_TLS ) ? \
									MECHANISM_SIG_TLS : \
								  ( signatureType == SIGNATURE_CMS_PSS || \
									signatureType == SIGNATURE_TLS13 ) ? \
									MECHANISM_SIG_PSS : MECHANISM_SIG_PKCS1 );
		if( cryptStatusOK( status ) )
			length = mechanismInfo.signatureLength;
		clearMechanismInfo( &mechanismInfo );
		CFI_CHECK_UPDATE( "IMESSAGE_DEV_SIGN" );
		}
	if( cryptStatusError( status ) )
		{
		/* The mechanism messages place the acted-on object (in this case the
		   hash context) first while the higher-level functions place the
		   signature context next to the signature data, in other words
		   before the hash context.  Because of this we have to reverse
		   parameter error values when translating from the mechanism to the
		   signature function level */
		if( bufPtr != NULL )
			zeroise( bufPtr, CRYPT_MAX_PKCSIZE );
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ARGERROR_NUM2 : \
				 ( status == CRYPT_ARGERROR_NUM2 ) ? CRYPT_ARGERROR_NUM1 : \
				 status;
		retExt( status,
				( status, errorInfo,
				  "Creation of %s %s signature failed", 
				  getAlgoName( signAlgo ), 
				  getSigTypeName( signatureType ) ) );
		}
	INJECT_FAULT( MECH_CORRUPT_SIG, MECH_CORRUPT_SIG_1 );

	/* If we're perfoming a dummy sign for a length check, set up a dummy 
	   value to write */
	if( signature == NULL )
		{
		REQUIRES( rangeCheck( length, 1, CRYPT_MAX_PKCSIZE ) );
		memset( buffer, 0x01, length );
		}

	/* Write the signature record to the output */
	sMemOpenOpt( &stream, signature, sigMaxLength );
	status = writeSigFunction( &stream, iSignContext, hashAlgo, hashParam, 
							   signAlgo, buffer, length );
	if( cryptStatusOK( status ) )
		*signatureLength = stell( &stream );
	sMemDisconnect( &stream );
	CFI_CHECK_UPDATE( "writeSigFunction" );

	/* Clean up */
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Couldn't write %s %s signature",
				  getAlgoName( signAlgo ), 
				  getSigTypeName( signatureType ) ) );
		}
	ENSURES( isShortIntegerRangeNZ( *signatureLength ) );

	ENSURES( CFI_CHECK_SEQUENCE_3( "IMESSAGE_GETATTRIBUTE", 
								   "IMESSAGE_DEV_SIGN", "writeSigFunction" ) );

	ENSURES( isShortIntegerRangeNZ( *signatureLength ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Check a Signature							*
*																			*
****************************************************************************/

/* Common signature-checking routine, used by other sign_xxx.c modules */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 7 ) ) \
int checkSignature( IN_BUFFER( signatureLength ) const void *signature, 
					IN_LENGTH_SHORT_MIN( 40 ) const int signatureLength,
					IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
					IN_HANDLE const CRYPT_CONTEXT iHashContext,
					IN_HANDLE_OPT const CRYPT_CONTEXT iHashContext2,
					IN_ENUM( SIGNATURE ) \
						const SIGNATURE_TYPE signatureType,
					INOUT_PTR ERROR_INFO *errorInfo )
	{
	MECHANISM_SIGN_INFO mechanismInfo;
	const READSIG_FUNCTION readSigFunction = getReadSigFunction( signatureType );
	QUERY_INFO queryInfo;
	STREAM stream;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	void *signatureData;
	BOOLEAN isCertificate = FALSE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int signAlgo, hashAlgo, hashParam = 0, sigFormat, value;
	int signatureDataLength, compareType = MESSAGE_COMPARE_NONE, status;

	assert( isReadPtrDynamic( signature, signatureLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	
	REQUIRES( isShortIntegerRangeMin( signatureLength, 40 ) );
	REQUIRES( isHandleRangeValid( iSigCheckContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( ( signatureType == SIGNATURE_TLS && \
				isHandleRangeValid( iHashContext2 ) ) || \
			  ( ( signatureType == SIGNATURE_CMS || \
				  signatureType == SIGNATURE_CMS_PSS || \
				  signatureType == SIGNATURE_CRYPTLIB || \
				  signatureType == SIGNATURE_PGP || \
				  signatureType == SIGNATURE_RAW || \
				  signatureType == SIGNATURE_SSH || \
				  signatureType == SIGNATURE_TLS12 || \
				  signatureType == SIGNATURE_TLS13 || \
				  signatureType == SIGNATURE_X509 ) && \
				iHashContext2 == CRYPT_UNUSED ) );

	/* Make sure that the requested signature format is available */
	if( readSigFunction == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Extract general information */
	sigFormat = ( signatureType == SIGNATURE_TLS ) ? MECHANISM_SIG_TLS : \
				( signatureType == SIGNATURE_CMS_PSS ) ? \
				  MECHANISM_SIG_PSS : MECHANISM_SIG_PKCS1;
	status = krnlSendMessage( iSigCheckContext, IMESSAGE_GETATTRIBUTE,
							  &signAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM1 : status );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && isParameterisedHashAlgo( hashAlgo ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &hashParam, CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_NUM2 : status );
	CFI_CHECK_UPDATE( "IMESSAGE_GETATTRIBUTE" );

	/* Check whether we're dealing with a certificate.  This is used to 
	   allow for more detailed error reporting if something goes wrong */
	status = krnlSendMessage( iSigCheckContext, IMESSAGE_GETATTRIBUTE, 
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) )
		isCertificate = TRUE;

	/* Read and check the signature record */
	sMemConnect( &stream, signature, signatureLength );
	status = readSigFunction( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		retExt( status,
				( status, errorInfo,
				  "Invalid %s signature record", 
				  getSigTypeName( signatureType ) ) );
		}
	CFI_CHECK_UPDATE( "readSigFunction" );

	/* Make sure that we've been given the correct algorithms */
	if( signatureType != SIGNATURE_RAW && signatureType != SIGNATURE_TLS )
		{
		if( signAlgo != queryInfo.cryptAlgo || \
			hashAlgo != queryInfo.hashAlgo )
			status = CRYPT_ERROR_SIGNATURE;
		if( signatureType != SIGNATURE_SSH )
			{
			/* SSH requires complex string-parsing to determine the optional
			   parameters, so the check is done elsewhere */
			if( isParameterisedHashAlgo( hashAlgo ) && \
				hashParam != queryInfo.hashParam )
				status = CRYPT_ERROR_SIGNATURE;
			}
		if( cryptStatusError( status ) )
			{
			zeroise( &queryInfo, sizeof( QUERY_INFO ) );
			retExt( status,
					( status, errorInfo,
					  "%s/%s algorithms in %s signature don't match "
					  "%s/%s algorithms in signature-check/hash objects", 
					  getAlgoName( queryInfo.cryptAlgo ), 
					  getAlgoNameEx( queryInfo.hashAlgo, 
									 queryInfo.hashParam ), 
					  getSigTypeName( signatureType ),
					  getAlgoName( signAlgo ), 
					  getAlgoNameEx( hashAlgo, hashParam ) ) );
			}
		}

	/* Make sure that we've been given the correct key if the signature
	   format supports this type of check */
	switch( signatureType )
		{
		case SIGNATURE_CMS:
			/* This format supports a check with 
			   MESSAGE_COMPARE_ISSUERANDSERIALNUMBER but this has already 
			   been done while procesing the other CMS data before we were 
			   called so we don't need to do it again */
			/* compareType = MESSAGE_COMPARE_ISSUERANDSERIALNUMBER; */
			break;

		case SIGNATURE_CRYPTLIB:
			compareType = MESSAGE_COMPARE_KEYID;
			break;

		case SIGNATURE_PGP:
			compareType = ( queryInfo.version == PGP_VERSION_2 ) ? \
							MESSAGE_COMPARE_KEYID_PGP : \
							MESSAGE_COMPARE_KEYID_OPENPGP;
			break;

		default:
			/* Other format types don't include identification information
			   with the signature */
			break;
		}
	if( compareType != MESSAGE_COMPARE_NONE )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, queryInfo.keyID, queryInfo.keyIDlength );
		status = krnlSendMessage( iSigCheckContext, IMESSAGE_COMPARE,
								  &msgData, compareType );
		if( cryptStatusError( status ) && \
			compareType == MESSAGE_COMPARE_KEYID )
			{
			/* Checking for the keyID gets a bit complicated, in theory it's 
			   the subjectKeyIdentifier from a certificate but in practice 
			   this form is mostly used for certificateless public keys.  
			   Because of this we check for the keyID first and if that 
			   fails fall back to the sKID */
			status = krnlSendMessage( iSigCheckContext, IMESSAGE_COMPARE, 
									  &msgData, 
									  MESSAGE_COMPARE_SUBJECTKEYIDENTIFIER );
			}
		if( cryptStatusError( status ) )
			{
			/* A failed comparison is reported as a generic CRYPT_ERROR,
			   convert it into a wrong-key error */
			zeroise( &queryInfo, sizeof( QUERY_INFO ) );
			if( isCertificate )
				{
				retExt( CRYPT_ERROR_WRONGKEY,
						( CRYPT_ERROR_WRONGKEY, errorInfo,
						  "%s signature-check key for '%s' doesn't match "
						  "key used in %s signature", 
						  getAlgoName( signAlgo ), 
						  getCertHolderName( iSigCheckContext, certName, 
											 CRYPT_MAX_TEXTSIZE ),
						  getSigTypeName( signatureType ) ) );
				}
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, errorInfo,
					  "%s signature-check key doesn't match key used in "
					  "%s signature", getAlgoName( signAlgo ), 
					  getSigTypeName( signatureType ) ) );
			}
		}
	REQUIRES( boundsCheck( queryInfo.dataStart, queryInfo.dataLength,
						   signatureLength ) );
	signatureData = ( BYTE * ) signature + queryInfo.dataStart;
	signatureDataLength = queryInfo.dataLength;
	if( queryInfo.cryptAlgoEncoding != ALGOID_ENCODING_NONE )
		{
		/* The signature type has been modified by something in the encoded 
		   signature data, change the format type to match */
		switch( queryInfo.cryptAlgoEncoding )
			{
			case ALGOID_ENCODING_PSS:
				sigFormat = MECHANISM_SIG_PSS;
				break;

			default:
				retIntError();
			}
		}
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );
	CFI_CHECK_UPDATE( "IMESSAGE_COMPARE" );

	/* DLP and ECDLP signatures are handled somewhat specially */
	if( isDlpAlgo( signAlgo ) || isEccAlgo( signAlgo ) )
		{
		/* In addition to the special-case processing for DLP/ECDLP 
		   signatures, we have to provide even further special handling for 
		   TLS signatures, which normally sign a dual hash of MD5 and SHA-1 
		   but for DLP only sign the second SHA-1 hash */
		status = checkDlpSignature( signatureData, signatureDataLength, 
									iSigCheckContext, 
									( signatureType == SIGNATURE_TLS ) ? \
									  iHashContext2 : iHashContext,
									signatureType );
		if( cryptStatusError( status ) )
			{
			if( isCertificate )
				{
				retExt( status,
						( status, errorInfo,
						  "Signature check of %s %s signature with key for "
						  "'%s' failed", 
						  getAlgoName( signAlgo ), 
						  getSigTypeName( signatureType ),
						  getCertHolderName( iSigCheckContext, certName, 
											 CRYPT_MAX_TEXTSIZE ) ) );
				}
			retExt( status,
					( status, errorInfo,
					  "Signature check of %s %s signature failed", 
					  getAlgoName( signAlgo ), 
					  getSigTypeName( signatureType ) ) );
			}
		CFI_CHECK_UPDATE( "checkDlpSignature" );

		ENSURES( CFI_CHECK_SEQUENCE_4( "IMESSAGE_GETATTRIBUTE", 
									   "readSigFunction", "IMESSAGE_COMPARE", 
									   "checkDlpSignature" ) );
		return( CRYPT_OK );
		}

	/* It's a standard signature, process it as normal */
	setMechanismSignInfo( &mechanismInfo, signatureData, signatureDataLength, 
						  iHashContext, iHashContext2, iSigCheckContext );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_SIGCHECK, 
							  &mechanismInfo, sigFormat );
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		{
		/* The mechanism messages place the acted-on object (in this case the 
		   hash context) first while the higher-level functions place the 
		   signature context next to the signature data, in other words 
		   before the hash context.  Because of this we have to reverse 
		   parameter error values when translating from the mechanism to the 
		   signature function level */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ARGERROR_NUM2 : \
				 ( status == CRYPT_ARGERROR_NUM2 ) ? CRYPT_ARGERROR_NUM1 : \
				 status;
		if( isCertificate )
			{
			retExt( status,
					( status, errorInfo,
					  "Signature check of %s %s signature with key for "
					  "'%s' failed", 
					  getAlgoName( signAlgo ), 
					  getSigTypeName( signatureType ),
					  getCertHolderName( iSigCheckContext, certName, 
										 CRYPT_MAX_TEXTSIZE ) ) );
			}
		retExt( status,
				( status, errorInfo,
				  "Signature check of %s %s signature failed", 
				  getAlgoName( signAlgo ), 
				  getSigTypeName( signatureType ) ) );
		}
	CFI_CHECK_UPDATE( "IMESSAGE_DEV_SIGCHECK" );

	ENSURES( CFI_CHECK_SEQUENCE_4( "IMESSAGE_GETATTRIBUTE", "readSigFunction", 
								   "IMESSAGE_COMPARE", 
								   "IMESSAGE_DEV_SIGCHECK" ) );

	return( CRYPT_OK );
	}
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
