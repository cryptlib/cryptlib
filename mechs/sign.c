/****************************************************************************
*																			*
*								Signature Routines							*
*						Copyright Peter Gutmann 1993-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp_rw.h"
  #include "mech.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/misc_rw.h"
  #include "enc_dec/pgp_rw.h"
  #include "mechs/mech.h"
#endif /* Compiler-specific includes */

#ifdef USE_INT_CMS

/****************************************************************************
*																			*
*							Utility Functions 								*
*																			*
****************************************************************************/

/* Try and determine the format of the signed data */

CHECK_RETVAL_ENUM( CRYPT_FORMAT ) STDC_NONNULL_ARG( ( 1 ) ) \
static CRYPT_FORMAT_TYPE getFormatType( IN_BUFFER( dataLength ) const void *data, 
										IN_DATALENGTH const int dataLength )
	{
	STREAM stream;
	long value;
	int status;

	assert( isReadPtrDynamic( data, dataLength ) );
	
	REQUIRES_EXT( isBufsizeRangeMin( dataLength, MIN_CRYPT_OBJECTSIZE ), \
				  CRYPT_FORMAT_NONE );

	sMemConnect( &stream, data, min( 16, dataLength ) );

	/* Figure out what we've got.  A PKCS #7/CMS/SMIME signature begins:

		cryptlibSignature ::= SEQUENCE {
			version		INTEGER (3),
			keyID [ 0 ]	OCTET STRING

	   while a CMS signature begins:

		cmsSignature ::= SEQUENCE {
			version		INTEGER (1),
			digestAlgo	SET OF {

	   which allows us to determine which type of object we have.  Note that 
	   we use sPeek() rather than peekTag() because we want to continue
	   processing (or at least checking for) PGP data if it's no ASN.1 */
	if( sPeek( &stream ) == BER_SEQUENCE )
		{
		CRYPT_FORMAT_TYPE formatType;

		readSequence( &stream, NULL );
		status = readShortInteger( &stream, &value );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( CRYPT_FORMAT_NONE );
			}
		switch( value )
			{
			case SIGNATURE_VERSION:
				formatType = CRYPT_FORMAT_CMS;
				break;

			case SIGNATURE_EX_VERSION:
				formatType = CRYPT_FORMAT_CRYPTLIB;
				break;

			default:
				formatType = CRYPT_FORMAT_NONE;
			}
		sMemDisconnect( &stream );

		return( formatType );
		}

#ifdef USE_PGP
	/* It's not ASN.1 data, check for PGP data */
	status = pgpReadPacketHeader( &stream, NULL, &value, 30, 8192 );
	if( cryptStatusOK( status ) && value > 30 && value < 8192 )
		{
		sMemDisconnect( &stream );
		return( CRYPT_FORMAT_PGP );
		}
#endif /* USE_PGP */

	sMemDisconnect( &stream );

	return( CRYPT_FORMAT_NONE );
	}

/****************************************************************************
*																			*
*							Create a Signature 								*
*																			*
****************************************************************************/

/* Create an extended signature type */

C_CHECK_RETVAL C_NONNULL_ARG( ( 3 ) ) \
C_RET cryptCreateSignatureEx( C_OUT_OPT void C_PTR signature,
							  C_IN int signatureMaxLength,
							  C_OUT int C_PTR signatureLength,
							  C_IN CRYPT_FORMAT_TYPE formatType,
							  C_IN CRYPT_CONTEXT signContext,
							  C_IN CRYPT_CONTEXT hashContext,
							  C_IN CRYPT_HANDLE extraData )
	{
	SIGPARAMS sigParams;
	ERROR_INFO localErrorInfo;
	BOOLEAN hasSigParams = FALSE;
	int value, status;

	/* Perform basic error checking.  We have to use an internal message to
	   check for signing capability because the DLP algorithms have
	   specialised data-formatting requirements that can't normally be
	   directly accessed via external messages, and even the non-DLP
	   algorithms may be internal-use-only if there's a certificate attached 
	   to the context.  To make sure that the context is OK we first check 
	   its external accessibility by performing a dummy attribute read.  
	   Note that we can't safely use the certificate-type read performed 
	   later on for this check because some error conditions (e.g. "not a 
	   certificate") are valid in this case, but we don't want to have mess 
	   with trying to distinguish OK-in-this-instance vs.not-OK error 
	   conditions */
	if( signature != NULL )
		{
		if( signatureMaxLength < MIN_CRYPT_OBJECTSIZE || \
			signatureMaxLength >= MAX_BUFFER_SIZE )
			return( CRYPT_ERROR_PARAM2 );
		if( !isWritePtrDynamic( signature, signatureMaxLength ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( signature, 0, MIN_CRYPT_OBJECTSIZE );
		}
	else
		{
		if( signatureMaxLength != 0 )
			return( CRYPT_ERROR_PARAM2 );
		}
	if( !isWritePtr( signatureLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*signatureLength = 0;
	if( !isEnumRangeExternal( formatType, CRYPT_FORMAT ) )
		return( CRYPT_ERROR_PARAM4 );
	status = krnlSendMessage( signContext, MESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ERROR_PARAM5 : status );
	status = krnlSendMessage( signContext, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC_SIGN );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ERROR_PARAM5 : status );
	status = krnlSendMessage( hashContext, MESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_HASH );
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ERROR_PARAM6 : status );

	/* Perform any required format-specific checking */
	switch( formatType )
		{
		case CRYPT_FORMAT_AUTO:
		case CRYPT_FORMAT_CRYPTLIB:
			/* If it's a cryptlib-format signature there can't be any extra
			   signing attributes present */
			if( extraData != CRYPT_UNUSED )
				return( CRYPT_ERROR_PARAM7 );
			break;

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			{
			int certType;	/* int vs.enum */

			/* Make sure that the signing context has a certificate attached 
			   to it */
			status = krnlSendMessage( signContext, MESSAGE_GETATTRIBUTE,
									  &certType, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) || \
				( certType != CRYPT_CERTTYPE_CERTIFICATE && \
				  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
				return( CRYPT_ERROR_PARAM5 );

			/* Make sure that the extra data object is in order */
			if( extraData != CRYPT_USE_DEFAULT )
				{
				status = krnlSendMessage( extraData, MESSAGE_GETATTRIBUTE,
										  &certType, CRYPT_CERTINFO_CERTTYPE );
				if( cryptStatusError( status ) || \
					certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
					return( CRYPT_ERROR_PARAM7 );
				}
			break;
			}

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			/* There's nothing specific to check for PGP signatures */
			break;
#endif /* USE_PGP */

		default:
			retIntError();
		}

	/* Set up any optional signing parameters if required */
	if( extraData != CRYPT_UNUSED )
		{
		initSigParams( &sigParams );
		if( extraData == CRYPT_USE_DEFAULT )
			sigParams.useDefaultAuthAttr = TRUE;
		else
			sigParams.iAuthAttr = extraData;
		hasSigParams = TRUE;
		}
	if( formatType == CRYPT_FORMAT_PGP )
		{
		initSigParamsPGP( &sigParams, PGP_SIG_DATA, NULL, 0 );
		hasSigParams = TRUE;
		}

	/* Call the low-level signature create function to create the
	   signature.  Since there's nothing to return the error information 
	   through we don't do anything with it */
	clearErrorInfo( &localErrorInfo );
	status = iCryptCreateSignature( signature, 
					min( signatureMaxLength, MAX_INTLENGTH_SHORT - 1 ),
					signatureLength, formatType, signContext, hashContext, 
					hasSigParams ? &sigParams : NULL, &localErrorInfo );
	if( cryptArgError( status ) )
		{
		/* Remap the error code to refer to the correct parameter */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM5 : CRYPT_ERROR_PARAM6;
		}
	return( status );
	}

C_CHECK_RETVAL C_NONNULL_ARG( ( 3 ) ) \
C_RET cryptCreateSignature( C_OUT_OPT void C_PTR signature,
							C_IN int signatureMaxLength,
							C_OUT int C_PTR signatureLength,
							C_IN CRYPT_CONTEXT signContext,
							C_IN CRYPT_CONTEXT hashContext )
	{
	int status;

	status = cryptCreateSignatureEx( signature, signatureMaxLength,
									 signatureLength, CRYPT_FORMAT_CRYPTLIB,
									 signContext, hashContext,
									 CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		/* Remap parameter errors to the correct position */
		if( status == CRYPT_ERROR_PARAM5 )
			status = CRYPT_ERROR_PARAM4;
		if( status == CRYPT_ERROR_PARAM6 )
			status = CRYPT_ERROR_PARAM5;
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Check a Signature 								*
*																			*
****************************************************************************/

/* Check an extended signature type */

C_CHECK_RETVAL C_NONNULL_ARG( ( 1 ) ) \
C_RET cryptCheckSignatureEx( C_IN void C_PTR signature,
							 C_IN int signatureLength,
							 C_IN CRYPT_HANDLE sigCheckKey,
							 C_IN CRYPT_CONTEXT hashContext,
							 C_OUT_OPT CRYPT_HANDLE C_PTR extraData )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_CERTIFICATE iExtraData DUMMY_INIT;
	CRYPT_CONTEXT sigCheckContext;
	ERROR_INFO localErrorInfo;
	int status;

	/* Perform basic error checking */
	if( !isShortIntegerRangeMin( signatureLength, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_ERROR_PARAM2 );
	if( !isReadPtrDynamic( signature, signatureLength ) )
		return( CRYPT_ERROR_PARAM1 );
	if( ( formatType = getFormatType( signature, \
									  signatureLength ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_ERROR_BADDATA );

	/* Clear return values */
	if( extraData != NULL )
		*extraData = CRYPT_UNUSED;

	/* Perform extended error checking */
	status = krnlSendMessage( sigCheckKey, MESSAGE_GETDEPENDENT,
							  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sigCheckContext, IMESSAGE_CHECK,
								  NULL, MESSAGE_CHECK_PKC_SIGCHECK );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( hashContext, MESSAGE_CHECK, NULL,
								  MESSAGE_CHECK_HASH );
		if( cryptArgError( status ) )
			status = CRYPT_ERROR_PARAM4;
		}
	else
		{
		if( cryptArgError( status ) )
			status = CRYPT_ERROR_PARAM3;
		}
	if( cryptStatusError( status ) )
		return( status );
	if( formatType == CRYPT_FORMAT_CMS || \
		formatType == CRYPT_FORMAT_SMIME )
		{
		int certType;	/* int vs.enum */

		/* Make sure that the sig check key includes a certificate */
		status = krnlSendMessage( sigCheckKey, MESSAGE_GETATTRIBUTE,
								  &certType, CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusError( status ) ||
			( certType != CRYPT_CERTTYPE_CERTIFICATE && \
			  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
			return( CRYPT_ERROR_PARAM3 );
		}

	/* Perform any required format-specific checking */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			/* If it's a cryptlib-format signature there can't be any extra
			   signing attributes present */
			if( extraData != NULL )
				return( CRYPT_ERROR_PARAM5 );
			break;

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			if( extraData != NULL )
				{
				if( !isWritePtr( extraData, sizeof( int ) ) )
					return( CRYPT_ERROR_PARAM6 );
				*extraData = CRYPT_ERROR;
				}
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			/* PGP doesn't have signing attributes */
			if( extraData != NULL )
				return( CRYPT_ERROR_PARAM5 );
			break;
#endif /* USE_PGP */

		default:
			retIntError();
		}

	/* Call the low-level signature create function to check the signature.  
	   Since there's nothing to return the error information through we 
	   don't do anything with it */
	clearErrorInfo( &localErrorInfo );
	status = iCryptCheckSignature( signature, signatureLength, formatType, 
						sigCheckKey, hashContext, CRYPT_UNUSED,
						( extraData != NULL ) ? &iExtraData : NULL,
						&localErrorInfo );
	if( cryptArgError( status ) )
		{
		/* Remap the error code to refer to the correct parameter */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM3 : CRYPT_ERROR_PARAM4;
		}
	if( cryptStatusError( status ) )
		return( status );
	if( extraData == NULL )
		return( CRYPT_OK );
	
	/* The caller has requested to see the the recovered signing attributes, 
	   make them externally visible.  Bailing out if this operation fails 
	   may be a bit excessive in that the signature has already verified so 
	   failing the whole operation just because we can't make auxiliary 
	   attributes visible could be seen as overkill, however since the 
	   caller has indicated an interest in the attributes it can be argued 
	   that an inability to return them is as serious as a general sig.check 
	   failure */
	status = krnlSendMessage( iExtraData, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_FALSE,
							  CRYPT_IATTRIBUTE_INTERNAL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iExtraData, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*extraData = iExtraData;

	return( CRYPT_OK );
	}

C_CHECK_RETVAL C_NONNULL_ARG( ( 1 ) ) \
C_RET cryptCheckSignature( C_IN void C_PTR signature,
						   C_IN int signatureLength,
						   C_IN CRYPT_HANDLE sigCheckKey,
						   C_IN CRYPT_CONTEXT hashContext )
	{
	return( cryptCheckSignatureEx( signature, signatureLength, sigCheckKey,
								   hashContext, NULL ) );
	}
#endif /* USE_INT_CMS */

/****************************************************************************
*																			*
*						Internal Sign/Sig Check Functions					*
*																			*
****************************************************************************/

/* Internal versions of the above.  These skip a lot of the explicit 
   checking done by the external versions (e.g. "Is this value really a 
   handle to a valid PKC context?") since they're only called by cryptlib 
   internal functions rather than being passed untrusted user data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 8 ) ) \
int iCryptCreateSignature( OUT_BUFFER_OPT( signatureMaxLength, *signatureLength ) \
							void *signature, 
						   IN_DATALENGTH_Z const int signatureMaxLength,
						   OUT_DATALENGTH_Z int *signatureLength,
						   IN_ENUM( CRYPT_FORMAT ) \
							const CRYPT_FORMAT_TYPE formatType,
						   IN_HANDLE const CRYPT_CONTEXT iSignContext,
						   IN_HANDLE const CRYPT_CONTEXT iHashContext,
						   IN_PTR_OPT const SIGPARAMS *sigParams,
						   INOUT_PTR ERROR_INFO *errorInfo )
	{
	int certType, status;	/* int vs.enum */

	assert( signature == NULL || \
			isWritePtrDynamic( signature, signatureMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( sigParams == NULL || isReadPtr( sigParams, sizeof( SIGPARAMS ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( ( signature == NULL && signatureMaxLength == 0 ) || \
			  ( signature != NULL && \
				isBufsizeRangeMin( signatureMaxLength, \
								   MIN_CRYPT_OBJECTSIZE ) ) );
	REQUIRES( isEnumRange( formatType, CRYPT_FORMAT ) );
	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( ( ( formatType == CRYPT_FORMAT_CRYPTLIB || \
				  formatType == CRYPT_IFORMAT_SSH || \
				  formatType == CRYPT_IFORMAT_TLS12 || \
				  formatType == CRYPT_IFORMAT_TLS13 ) && \
				sigParams == NULL ) || 
			  ( ( formatType == CRYPT_FORMAT_CMS || \
				  formatType == CRYPT_FORMAT_SMIME || \
				  formatType == CRYPT_FORMAT_PGP || \
				  formatType == CRYPT_IFORMAT_TLS ) && \
				sigParams != NULL ) );
			  /* The sigParams structure is too complex to check fully here
			     so we check it in the switch statement below */

	ANALYSER_HINT( signatureLength != NULL );

	/* Clear return value */
	*signatureLength = 0;

	/* If the signing context has a certificate chain attached then the 
	   currently-selected certificate may not be the leaf certificate.  To 
	   ensure that we use the correct certificate we lock the chain (which 
	   both protects us from having the user select a different certificate 
	   while we're using it and saves the selection state for when we later 
	   unlock it) and explicitly select the leaf certificate.  Certificates 
	   are used for formats other than the obvious CRYPT_FORMAT_CMS/
	   CRYPT_FORMAT_SMIME so we perform this operation unconditionally 
	   rather than only for those two formats */
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE,
							  &certType, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		{
		/* There's no certificate of the required type attached */
		certType = CRYPT_CERTTYPE_NONE;
		}
	else
		{
		/* If it's a certificate chain, lock it and select the leaf 
		   certificate */
		if( certType == CRYPT_CERTTYPE_CERTCHAIN )
			{
			status = krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
									  MESSAGE_VALUE_TRUE,
									  CRYPT_IATTRIBUTE_LOCKED );
			if( cryptStatusError( status ) )
				return( status );
			status = krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
									  MESSAGE_VALUE_CURSORFIRST,
									  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
			if( cryptStatusError( status ) )
				{
				( void ) krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
										  MESSAGE_VALUE_FALSE, 
										  CRYPT_IATTRIBUTE_LOCKED );
				return( status );
				}
			}
		}

	/* Call the low-level signature create function to create the signature */
	switch( formatType )
		{
#ifdef USE_INT_CMS
		case CRYPT_FORMAT_CRYPTLIB:
			status = createSignature( signature, signatureMaxLength, 
									  signatureLength, iSignContext,
									  iHashContext, CRYPT_UNUSED,
									  SIGNATURE_CRYPTLIB, errorInfo );
			break;

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			{
			SIGNATURE_TYPE sigType = SIGNATURE_CMS;
			int sigFormat;

			/* Get the signature format type to use */
			status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
									  IMESSAGE_GETATTRIBUTE, &sigFormat, 
									  CRYPT_OPTION_PKC_FORMAT );
			if( cryptStatusError( status ) )
				return( status );
			if( sigFormat != CRYPT_PKCFORMAT_DEFAULT )
				{
				int algorithm;

				/* We're using a nonstandard signature format, make sure 
				   that it's compatible with the algorithm being used */
				status = krnlSendMessage( iSignContext, MESSAGE_GETATTRIBUTE,
										  &algorithm, CRYPT_CTXINFO_ALGO );
				if( cryptStatusError( status ) )
					return( status );
				if( algorithm == CRYPT_ALGO_RSA && \
					sigFormat == CRYPT_PKCFORMAT_PSS )
					sigType = SIGNATURE_CMS_PSS;
				}

			REQUIRES( ( sigParams->iAuthAttr == CRYPT_ERROR && \
						sigParams->useDefaultAuthAttr == FALSE ) || \
					  ( sigParams->iAuthAttr == CRYPT_ERROR && \
						sigParams->useDefaultAuthAttr == TRUE ) || \
					  ( isHandleRangeValid( sigParams->iAuthAttr ) && \
					    sigParams->useDefaultAuthAttr == FALSE ) );
			REQUIRES( sigParams->iTspSession == CRYPT_ERROR || \
					  isHandleRangeValid( sigParams->iTspSession ) );

			status = createSignatureCMS( signature, signatureMaxLength, 
										 signatureLength, iSignContext,
										 iHashContext, 
										 sigParams->useDefaultAuthAttr, 
										 ( sigParams->iAuthAttr == CRYPT_ERROR ) ? \
											CRYPT_UNUSED : sigParams->iAuthAttr,
										 ( sigParams->iTspSession == CRYPT_ERROR ) ? \
											CRYPT_UNUSED : sigParams->iTspSession, 
										 sigType,
										 ( formatType == CRYPT_FORMAT_SMIME ) ? \
											TRUE : FALSE, errorInfo );
			break;
			}
#endif /* USE_INT_CMS */

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			REQUIRES( sigParams->useDefaultAuthAttr == FALSE && \
					  sigParams->iAuthAttr == CRYPT_ERROR && \
					  sigParams->iTspSession == CRYPT_ERROR && \
					  ( sigParams->sigType >= PGP_SIG_NONE && \
					    sigParams->sigType < PGP_SIG_LAST ) && \
					  sigParams->iSecondHash == CRYPT_ERROR );

			status = createSignaturePGP( signature, signatureMaxLength, 
										 signatureLength, iSignContext,
										 iHashContext, sigParams->sigAttributes,
										 sigParams->sigAttributeSize,
										 sigParams->sigType, errorInfo );
			break;
#endif /* USE_PGP */

#ifdef USE_TLS
		case CRYPT_IFORMAT_TLS:
			REQUIRES( sigParams->useDefaultAuthAttr == FALSE && \
					  sigParams->iAuthAttr == CRYPT_ERROR && \
					  sigParams->iTspSession == CRYPT_ERROR && \
					  sigParams->sigType == PGP_SIG_NONE && \
					  isHandleRangeValid( sigParams->iSecondHash ) );

			status = createSignature( signature, signatureMaxLength, 
									  signatureLength, iSignContext,
									  iHashContext, sigParams->iSecondHash,
									  SIGNATURE_TLS, errorInfo );
			break;

		case CRYPT_IFORMAT_TLS12:
		case CRYPT_IFORMAT_TLS13:
			REQUIRES( sigParams == NULL );

			status = createSignature( signature, signatureMaxLength, 
									  signatureLength, iSignContext,
									  iHashContext, CRYPT_UNUSED,
									  ( formatType == CRYPT_IFORMAT_TLS12 ) ? \
										SIGNATURE_TLS12 : SIGNATURE_TLS13, 
									  errorInfo );
			break;
#endif /* USE_TLS */

#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			status = createSignature( signature, signatureMaxLength, 
									  signatureLength, iSignContext,
									  iHashContext, CRYPT_UNUSED,
									  SIGNATURE_SSH, errorInfo );
			break;
#endif /* USE_SSH */

		default:
			retIntError();
		}
	if( cryptArgError( status ) )
		{
		/* Catch any parameter errors that slip through */
		DEBUG_DIAG(( "Signature creation returned argError status" ));
		assert( DEBUG_WARN );
		status = CRYPT_ERROR_FAILED;
		}
	if( certType == CRYPT_CERTTYPE_CERTCHAIN )
		{
		/* We're signing with a certificate chain, restore its state and 
		   unlock it to allow others access.  If this fails there's not much 
		   that we can do to recover so we don't do anything with the return 
		   value */
		( void ) krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_FALSE, 
								  CRYPT_IATTRIBUTE_LOCKED );
		}

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 8 ) ) \
int iCryptCheckSignature( IN_BUFFER( signatureLength ) const void *signature, 
						  IN_LENGTH_SHORT const int signatureLength,
						  IN_ENUM( CRYPT_FORMAT ) \
							const CRYPT_FORMAT_TYPE formatType,
						  IN_HANDLE const CRYPT_HANDLE iSigCheckKey,
						  IN_HANDLE const CRYPT_CONTEXT iHashContext,
						  IN_HANDLE_OPT const CRYPT_CONTEXT iHash2Context,
						  OUT_OPT_HANDLE_OPT CRYPT_HANDLE *extraData,
						  INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT sigCheckContext;
	int status;

	assert( isReadPtrDynamic( signature, signatureLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isShortIntegerRangeMin( signatureLength, 40 ) );
	REQUIRES( isEnumRange( formatType, CRYPT_FORMAT ) );
	REQUIRES( isHandleRangeValid( iSigCheckKey ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( ( formatType == CRYPT_IFORMAT_TLS && \
				isHandleRangeValid( iHash2Context ) && extraData == NULL ) || \
			  ( ( formatType == CRYPT_FORMAT_CMS || \
				  formatType == CRYPT_FORMAT_SMIME || \
				  formatType == CRYPT_IFORMAT_TLS12 ) && \
				iHash2Context == CRYPT_UNUSED ) || \
			  ( ( formatType == CRYPT_FORMAT_CRYPTLIB || \
				  formatType == CRYPT_FORMAT_PGP || \
				  formatType == CRYPT_IFORMAT_TLS12 || \
				  formatType == CRYPT_IFORMAT_SSH ) && \
				iHash2Context == CRYPT_UNUSED && extraData == NULL ) );

	/* Clear return value */
	if( extraData != NULL )
		*extraData = CRYPT_ERROR;

	/* Perform basic error checking */
	status = krnlSendMessage( iSigCheckKey, IMESSAGE_GETDEPENDENT,
							  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the low-level signature check function to check the signature */
	switch( formatType )
		{
#ifdef USE_INT_CMS
		case CRYPT_FORMAT_CRYPTLIB:
			/* For this call we have to pass in the original handle (which 
			   may be a certificate with an attached public-key context) 
			   rather than the raw context because the signature format uses 
			   the subjectKeyIdentifier to identify the key, and that's only 
			   available via the certificate */
			status = checkSignature( signature, signatureLength,
									 iSigCheckKey, iHashContext,
									 CRYPT_UNUSED, SIGNATURE_CRYPTLIB,
									 errorInfo );
			break;

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			if( extraData != NULL )
				*extraData = CRYPT_ERROR;
			status = checkSignatureCMS( signature, signatureLength, 
										sigCheckContext, iHashContext, 
										extraData, iSigCheckKey,
										errorInfo );
			break;
#endif /* USE_INT_CMS */

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = checkSignaturePGP( signature, signatureLength,
										sigCheckContext, iHashContext,
										errorInfo );
			break;
#endif /* USE_PGP */

#ifdef USE_TLS
		case CRYPT_IFORMAT_TLS:
			status = checkSignature( signature, signatureLength,
									 sigCheckContext, iHashContext,
									 iHash2Context, SIGNATURE_TLS,
									 errorInfo );
			break;

		case CRYPT_IFORMAT_TLS12:
			status = checkSignature( signature, signatureLength,
									 sigCheckContext, iHashContext,
									 CRYPT_UNUSED, SIGNATURE_TLS12,
									 errorInfo );
			break;
#endif /* USE_TLS */

#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			status = checkSignature( signature, signatureLength,
									 sigCheckContext, iHashContext,
									 CRYPT_UNUSED, SIGNATURE_SSH,
									 errorInfo );
			break;
#endif /* USE_SSH */

		default:
			retIntError();
		}
	if( cryptArgError( status ) )
		{
		/* Catch any parameter errors that slip through */
		DEBUG_DIAG(( "Signature creation returned argError status" ));
		assert( DEBUG_WARN );
		status = CRYPT_ERROR_SIGNATURE;
		}
	return( status );
	}

/****************************************************************************
*																			*
*						Stub Functions for non-CMS/PGP Use					*
*																			*
****************************************************************************/

#ifndef USE_INT_CMS 

C_RET cryptCreateSignatureEx( C_OUT_OPT void C_PTR signature,
							  C_IN int signatureMaxLength,
							  C_OUT int C_PTR signatureLength,
							  C_IN CRYPT_FORMAT_TYPE formatType,
							  C_IN CRYPT_CONTEXT signContext,
							  C_IN CRYPT_CONTEXT hashContext,
							  C_IN CRYPT_HANDLE extraData )
	{
	UNUSED_ARG( signature );
	UNUSED_ARG( signatureLength );

	return( CRYPT_ERROR_NOTAVAIL );
	}

C_RET cryptCreateSignature( C_OUT_OPT void C_PTR signature,
							C_IN int signatureMaxLength,
							C_OUT int C_PTR signatureLength,
							C_IN CRYPT_CONTEXT signContext,
							C_IN CRYPT_CONTEXT hashContext )
	{
	UNUSED_ARG( signature );
	UNUSED_ARG( signatureLength );

	return( CRYPT_ERROR_NOTAVAIL );
	}

C_RET cryptCheckSignatureEx( C_IN void C_PTR signature,
							 C_IN int signatureLength,
							 C_IN CRYPT_HANDLE sigCheckKey,
							 C_IN CRYPT_CONTEXT hashContext,
							 C_OUT_OPT CRYPT_HANDLE C_PTR extraData )
	{
	UNUSED_ARG( signature );
	UNUSED_ARG( extraData );

	return( CRYPT_ERROR_NOTAVAIL );
	}

C_RET cryptCheckSignature( C_IN void C_PTR signature,
						   C_IN int signatureLength,
						   C_IN CRYPT_HANDLE sigCheckKey,
						   C_IN CRYPT_CONTEXT hashContext )
	{
	UNUSED_ARG( signature );

	return( CRYPT_ERROR_NOTAVAIL );
	}
#endif /* USE_INT_CMS */
