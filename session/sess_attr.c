/****************************************************************************
*																			*
*						cryptlib Session Attribute Routines					*
*						Copyright Peter Gutmann 1998-2019					*
*																			*
****************************************************************************/

#include <stdio.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "misc_rw.h"				/* For TOTP check */
  #include "session.h"
#else
  #include "enc_dec/misc_rw.h"		/* For TOTP check */
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_SESSIONS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitError( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  IN_ENUM( CRYPT_ERRTYPE ) const CRYPT_ERRTYPE_TYPE errorType, 
					  IN_ERROR const int status )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );
	REQUIRES( isEnumRange( errorType, CRYPT_ERRTYPE ) );
	REQUIRES( cryptStatusError( status ) );

	setObjectErrorInfo( sessionInfoPtr, errorLocus, errorType );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorInited( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT,
					   CRYPT_ERROR_INITED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorNotInited( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTINITED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorNotFound( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Make sure that an attribute that's being added isn't already present */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkAttributePresent( INOUT_PTR SESSION_INFO *sessionInfoPtr,
									  IN_ATTRIBUTE \
						 				const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( attribute ) );

	/* Some attributes are present directly in the session information so we 
	   have to handle them specially */
	if( attribute == CRYPT_SESSINFO_PRIVATEKEY )
		{
		/* If multiple keys for the same server are allowed then adding more
		   than one key isn't an error */
		if( TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_MULTIPLEKEYS ) )
			return( CRYPT_OK );
		return( ( sessionInfoPtr->privateKey != CRYPT_ERROR ) ? \
				TRUE : FALSE );
		}
	if( attribute == CRYPT_SESSINFO_KEYSET )
		{
		return( ( sessionInfoPtr->cryptKeyset != CRYPT_ERROR ) ? \
				TRUE : FALSE );
		}
	if( attribute == CRYPT_SESSINFO_NETWORKSOCKET )
		{
		return( ( sessionInfoPtr->networkSocket != CRYPT_ERROR ) ? \
				TRUE : FALSE );
		}

	return( findSessionInfo( sessionInfoPtr, attribute ) ? TRUE : FALSE );
	}

/* Convert a user authentication token into a TOTP value */

#if defined( USE_TLS ) || defined( USE_SSH )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int checkAuthToken( IN_BUFFER( credentialLength ) const void *credential,
						   IN_LENGTH_TEXT const int credentialLength,
						   IN_BUFFER( authTokenSize ) const void *authToken,
						   IN_LENGTH_SHORT_MIN( 16 ) const int authTokenSize,
						   INOUT_PTR ERROR_INFO *errorInfo )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	STREAM stream;
	BYTE totpBuffer[ 16 + 8 ], totpSeed[ 64 + 8 ], counter[ 8 + 8 ];
	const time_t currentTime = getTime( GETTIME_NONE );
	int totpSeedSize, status;

	assert( isReadPtrDynamic( credential, credentialLength ) );
	assert( isReadPtrDynamic( authToken, authTokenSize ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( credentialLength > 0 && \
			  credentialLength <= CRYPT_MAX_TEXTSIZE );
	REQUIRES( authTokenSize >= 16 && authTokenSize <= CRYPT_MAX_TEXTSIZE );

	/* If the time is screwed up then we can't continue */
	if( currentTime <= MIN_TIME_VALUE )
		return( CRYPT_ERROR_NOTINITED );

	/* Make sure that the TOTP value is of the correct length */
	if( credentialLength != 6 )
		{
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, errorInfo, 
				  "Client TOTP value is %d characters, should be 6 "
				  "characters", credentialLength ) );
		}

	/* Extract the seed value from the Base32-encoded authentication token */
	status = decodeBase32Value( totpSeed, 64, &totpSeedSize, authToken, 
								authTokenSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the current time interval number as a 64-bit value, used as the 
	   HOTP counter.  TOTP doesn't use the absolute time but divides it up
	   into X-second intervals and uses the interval number, with the 
	   default interval duration being 30 seconds.  This conveniently means 
	   that we can use a 32-bit value for the foreseeable future (about a 
	   thousand years), but also menas that we need to use writeUint32() 
	   rather than writeUint32Time() since we're not writing a valid time 
	   value */
	sMemOpen( &stream, counter, 8 );
	swrite( &stream, "\x00\x00\x00\x00", 4 );
	status = writeUint32( &stream, ( int ) ( currentTime / 30 ) );
	sMemDisconnect( &stream );
	REQUIRES( cryptStatusOK( status ) );

	/* Derive the HOTP value from the seed and (time-based) counter, 
	   producing a TOTP value */
	setMechanismDeriveInfo( &mechanismInfo, totpBuffer, 6, 
							totpSeed, totpSeedSize, CRYPT_ALGO_SHA1, 
							counter, 8, 1 );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							  &mechanismInfo, MECHANISM_DERIVE_HOTP );
	zeroise( totpSeed, totpSeedSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the HOTP value matches the value supplied as the 
	   password */
	if( compareDataConstTime( credential, totpBuffer, 6 ) != TRUE )
		{
		BYTE credentialBuffer[ 16 + 8 ];

		memcpy( credentialBuffer, credential, 6 );
		totpBuffer[ 6 ] = '\0';
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, errorInfo, 
				  "Invalid client TOTP value '%s', should have been '%s'", 
				  sanitiseString( credentialBuffer, 16, 6 ),
				  totpBuffer ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_TLS || USE_SSH */

/****************************************************************************
*																			*
*						Add Various Attribute Types							*
*																			*
****************************************************************************/

/* Add the contents of an encoded URL to a session.  This requires parsing
   the individual session attribute components out of the URL and then 
   adding each one in turn */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int addUrl( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				   IN_BUFFER( urlLength ) const void *url,
				   IN_LENGTH_DNS const int urlLength )
	{
	const PROTOCOL_INFO *protocolInfo;
	URL_INFO urlInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( url, urlLength ) );
	
	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
	REQUIRES( urlLength > 0 && urlLength <= MAX_URL_SIZE );

	protocolInfo = DATAPTR_GET( sessionInfoPtr->protocolInfo );
	REQUIRES( protocolInfo != NULL );

	/* If there's already a network socket specified then we can't set a 
	   server name as well */
	if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
		{
		return( exitErrorInited( sessionInfoPtr, 
								 CRYPT_SESSINFO_NETWORKSOCKET ) );
		}

	/* Parse the server name.  The PKI protocols all use HTTP as their 
	   substrate so if it's not SSH or TLS we require HTTP */
	status = sNetParseURL( &urlInfo, url, urlLength,
						   ( sessionInfoPtr->type == CRYPT_SESSION_SSH ) ? \
								URL_TYPE_SSH : \
						   ( sessionInfoPtr->type == CRYPT_SESSION_TLS ) ? \
								URL_TYPE_HTTPS : URL_TYPE_HTTP );
	if( cryptStatusError( status ) )
		{
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );
		}

	/* We can only use autodetection with PKI services */
	if( urlInfo.hostLen == 12 && \
		!strCompare( urlInfo.host, "[Autodetect]", urlInfo.hostLen ) && \
		!protocolInfo->isReqResp )
		{
		retExt( CRYPT_ARGERROR_STR1,
				( CRYPT_ARGERROR_STR1, SESSION_ERRINFO,
				  "Autodetection can only be used with PKI services" ) );
		}

	/* Remember the server name */
	if( urlInfo.hostLen + urlInfo.locationLen >= MAX_URL_SIZE )
		{
		/* This should never happen since the overall URL size has to be 
		   less than MAX_URL_SIZE */
		assert( INTERNAL_ERROR );
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );
		}
	if( ( protocolInfo->flags & SESSION_PROTOCOL_HTTPTRANSPORT ) && \
		urlInfo.locationLen > 0 )
		{
		char urlBuffer[ MAX_URL_SIZE + 8 ];

		/* We only remember the location if the session uses HTTP transport.  
		   This is to deal with situations where the caller specifies a URL
		   like https://www.server.com/index.html for a TLS session, which 
		   should be treated as valid even though it's not really a pure 
		   FQDN */
		REQUIRES( boundsCheck( urlInfo.hostLen, urlInfo.locationLen,
							   MAX_URL_SIZE ) );
		memcpy( urlBuffer, urlInfo.host, urlInfo.hostLen );
		memcpy( urlBuffer + urlInfo.hostLen, urlInfo.location, 
				urlInfo.locationLen );
		status = addSessionInfoS( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								  urlBuffer, 
								  urlInfo.hostLen + urlInfo.locationLen );
		}
	else
		{
		status = addSessionInfoS( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
								  urlInfo.host, urlInfo.hostLen );
		}
	if( cryptStatusError( status ) )
		{
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );
		}

	/* If there's a port or user name specified in the URL, remember them.  
	   We have to add the user name after we add any other attributes 
	   because it's paired with a password, so adding the user name and then 
	   following it with something that isn't a password will cause an error 
	   return */
	if( urlInfo.port > 0 )
		{
		( void ) krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_DELETEATTRIBUTE, NULL,
								  CRYPT_SESSINFO_SERVER_PORT );
		status = krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE, &urlInfo.port,
								  CRYPT_SESSINFO_SERVER_PORT );
		}
	if( cryptStatusOK( status ) && urlInfo.userInfoLen > 0 )
		{
		MESSAGE_DATA userInfoMsgData;

		( void ) krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_DELETEATTRIBUTE, NULL,
								  CRYPT_SESSINFO_USERNAME );
		setMessageData( &userInfoMsgData, ( MESSAGE_CAST ) urlInfo.userInfo, 
						urlInfo.userInfoLen );
		status = krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &userInfoMsgData,
								  CRYPT_SESSINFO_USERNAME );
		}
	if( cryptStatusError( status ) )
		{
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );
		}

	/* Remember the transport type */
	if( protocolInfo->flags & SESSION_PROTOCOL_HTTPTRANSPORT )
		SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISHTTPTRANSPORT );
#if defined( USE_WEBSOCKETS ) 
	if( urlInfo.type == URL_TYPE_WEBSOCKET )
		sessionInfoPtr->subProtocol = CRYPT_SUBPROTOCOL_WEBSOCKETS;
#endif /* USE_WEBSOCKETS */

	return( CRYPT_OK );
	}

/* Add credentials (username/password) to a session */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int addCredential( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  IN_BUFFER( credentialLength ) \
								const void *credential,
						  IN_LENGTH_TEXT const int credentialLength,
						  IN_ATTRIBUTE \
								const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	const PROTOCOL_INFO *protocolInfo = \
					DATAPTR_GET( sessionInfoPtr->protocolInfo );
	const ATTRIBUTE_LIST *attributeListPtr;
	int flags = isServer( sessionInfoPtr ) ? \
				ATTR_FLAG_MULTIVALUED : ATTR_FLAG_NONE;
	int credentialMaxLength = credentialLength;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( credential, credentialLength ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
	REQUIRES( credentialLength > 0 && \
			  credentialLength <= CRYPT_MAX_TEXTSIZE );
	REQUIRES( attribute == CRYPT_SESSINFO_USERNAME || \
			  attribute == CRYPT_SESSINFO_PASSWORD || \
			  attribute == CRYPT_SESSINFO_AUTHTOKEN );
	REQUIRES( protocolInfo != NULL );

	/* If we're using fixed-size credential storage in case the value later 
	   gets replaced, modify the maximum credential size value */
	if( ( protocolInfo->flags & SESSION_PROTOCOL_FIXEDSIZECREDENTIALS ) && \
		( attribute == CRYPT_SESSINFO_USERNAME || \
		  attribute == CRYPT_SESSINFO_PASSWORD ) )
		credentialMaxLength = CRYPT_MAX_TEXTSIZE;

	/* If this is a client session then we can only have a single instance 
	   of this attribute */
	if( !isServer( sessionInfoPtr ) )
		{
		/* Make sure that there's only a single instance present */
		if( findSessionInfo( sessionInfoPtr, attribute ) != NULL )
			return( exitErrorInited( sessionInfoPtr, attribute ) );
		}

	/* Check that what we're adding is consistent with what we've already 
	   got */
	status = setSessionAttributeCursor( sessionInfoPtr,
										CRYPT_ATTRIBUTE_CURRENT_GROUP, 
										CRYPT_CURSOR_LAST );
	switch( attribute )
		{
		case CRYPT_SESSINFO_USERNAME:
			/* If there are no attributes present yet, we're done */
			if( cryptStatusError( status ) )
				break;

			/* We're adding a username, make sure that the last attribute 
			   added wasn't also a username and that what we're addig 
			   doesn't duplicate an existing name */
			attributeListPtr = DATAPTR_GET( sessionInfoPtr->attributeListCurrent );
			REQUIRES( attributeListPtr != NULL );
			if( attributeListPtr->attributeID == CRYPT_SESSINFO_USERNAME )
				{
				return( exitErrorInited( sessionInfoPtr, 
										 CRYPT_SESSINFO_USERNAME ) );
				}
			if( findSessionInfoEx( sessionInfoPtr, 
								   CRYPT_SESSINFO_USERNAME, 
								   credential, credentialLength ) != NULL )
				{
				return( exitError( sessionInfoPtr, 
								   CRYPT_SESSINFO_USERNAME,
								   CRYPT_ERRTYPE_ATTR_PRESENT, 
								   CRYPT_ERROR_DUPLICATE ) );
				}

			break;

		case CRYPT_SESSINFO_PASSWORD:
			/* We're adding a password, make sure that there's an associated 
			   username to go with it.  There are two approaches that we can 
			   take here, the first simply requires that the current cursor 
			   position is a username, implying that the last-added attribute 
			   was a username.  
		   
			   The other is to try and move the cursor to the last username 
			   in the attribute list and check that the next attribute isn't 
			   a password and then add it there, however this is doing a bit 
			   too much behind the user's back, is somewhat difficult to 
			   back out of, and leads to exceptions to exceptions, so we 
			   keep it simple and only allow passwords to be added if 
			   there's an immediately preceding username */
			if( cryptStatusError( status ) )
				{
				return( exitErrorNotInited( sessionInfoPtr, 
											CRYPT_SESSINFO_USERNAME ) );
				}
			attributeListPtr = \
						DATAPTR_GET( sessionInfoPtr->attributeListCurrent );
			REQUIRES( attributeListPtr != NULL );
			if( attributeListPtr->attributeID != CRYPT_SESSINFO_USERNAME )
				{
				return( exitErrorNotInited( sessionInfoPtr, 
											CRYPT_SESSINFO_USERNAME ) );
				}

			break;

		case CRYPT_SESSINFO_AUTHTOKEN:
			/* We're checking an authentication token against a password 
			   value from the client, make sure that there's a password 
			   present */
			if( cryptStatusError( status ) )
				{
				return( exitErrorNotInited( sessionInfoPtr, 
											CRYPT_SESSINFO_PASSWORD ) );
				}
			attributeListPtr = \
						DATAPTR_GET( sessionInfoPtr->attributeListCurrent );
			REQUIRES( attributeListPtr != NULL );
			if( attributeListPtr->attributeID != CRYPT_SESSINFO_PASSWORD )
				{
				retExt( CRYPT_ERROR_NOTINITED,
						( CRYPT_ERROR_NOTINITED, SESSION_ERRINFO,
						  "No client credentials present to check against "
						  "authentication token" ) );
				}

#if defined( USE_TLS ) || defined( USE_SSH )
			/* For now authentication tokens are always Base32-encoded TOTP 
			   seeds */
			if( !isBase32Value( credential, credentialLength ) )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO,
						  "Authentication token isn't valid Base32 data" ) );
				}

			/* An authentication token isn't really added but is used to 
			   verify the value that was communicated as a password, so we 
			   return the result of the verification check without adding 
			   anything */
			return( checkAuthToken( attributeListPtr->value, 
									attributeListPtr->valueLength,
									credential, credentialLength,
									SESSION_ERRINFO ) );
#else
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "TOTP authentication isn't supported for this "
					  "protocol" ) );
#endif /* USE_TLS || USE_SSH */

		default:
			retIntError();
		}

	/* If it could be an encoded PKI value, check its validity */
#ifdef USE_BASE64ID
	if( credentialLength >= 15 && \
		isPKIUserValue( credential, credentialLength ) )
		{
		BYTE decodedValue[ CRYPT_MAX_TEXTSIZE + 8 ];
		int decodedValueLen;

		/* It's an encoded value, make sure that it's in order */
		status = decodePKIUserValue( decodedValue, CRYPT_MAX_TEXTSIZE, 
									 &decodedValueLen, credential, 
									 credentialLength );
		zeroise( decodedValue, CRYPT_MAX_TEXTSIZE );
		if( cryptStatusError( status ) )
			return( status );
		flags = ATTR_FLAG_ENCODEDVALUE;
		}
#endif /* USE_BASE64ID */

	/* Perform any protocol-specific additional checks if necessary */
	if( FNPTR_ISSET( sessionInfoPtr->checkAttributeFunction ) )
		{
		const SES_CHECKATTRIBUTE_FUNCTION checkAttributeFunction = \
					( SES_CHECKATTRIBUTE_FUNCTION ) \
					FNPTR_GET( sessionInfoPtr->checkAttributeFunction );
		MESSAGE_DATA msgData;

		REQUIRES( checkAttributeFunction != NULL );

		setMessageData( &msgData, ( MESSAGE_CAST ) credential, 
						credentialLength );
		status = checkAttributeFunction( sessionInfoPtr, &msgData, 
										 attribute );
		if( status == OK_SPECIAL )
			{
			/* The value was dealt with as a side-effect of the check 
			   function, there's nothing more to do */
			return( CRYPT_OK );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Remember the value */
	return( addSessionInfoEx( sessionInfoPtr, attribute, credential, 
							  credentialLength, credentialMaxLength, 
							  flags ) );
	}

/* Add a private key to a session */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int addPrivateKey( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  IN_HANDLE const CRYPT_CONTEXT privateKey )
	{
	const int requiredAttributeFlags = \
		isServer( sessionInfoPtr ) ? sessionInfoPtr->serverReqAttrFlags : \
									 sessionInfoPtr->clientReqAttrFlags;
#ifndef USE_SHA2_EXT
	int privateKeyAlgo;
#endif /* USE_SHA2_EXT */
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
	REQUIRES( isHandleRangeValid( privateKey ) );

	/* Make sure that it's a private key */
	if( !checkContextCapability( privateKey, 
								 MESSAGE_CHECK_PKC_PRIVATE ) )
		return( CRYPT_ARGERROR_NUM1 );

	/* If we need a private key with certain capabilities, make sure that it 
	   has these capabilities.  This is a more specific check than that 
	   allowed by the kernel ACLs */
	if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYSIGN )
		{
		if( !checkContextCapability( privateKey, 
									 MESSAGE_CHECK_PKC_SIGN ) )
			{
			setObjectErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ARGERROR_NUM1 );
			}
		}
	if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCRYPT )
		{
		if( !checkContextCapability( privateKey, 
									 MESSAGE_CHECK_PKC_DECRYPT ) )
			{
			setObjectErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ARGERROR_NUM1 );
			}
		}

	/* If we need a private key with a certificate, make sure that the 
	   appropriate type of initialised certificate object is present.  This 
	   is a more specific check than that allowed by the kernel ACLs */
	if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCERT )
		{
		BOOLEAN_INT isInited;
		int value;

		status = krnlSendMessage( privateKey, IMESSAGE_GETATTRIBUTE, 
								  &isInited, CRYPT_CERTINFO_IMMUTABLE );
		if( cryptStatusError( status ) || !isInited )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_CERTINFO_CERTIFICATE, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ARGERROR_NUM1 );
			}
		status = krnlSendMessage( privateKey, IMESSAGE_GETATTRIBUTE, 
								  &value, CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusError( status ) || \
			( value != CRYPT_CERTTYPE_CERTIFICATE && \
			  value != CRYPT_CERTTYPE_CERTCHAIN ) )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_CERTINFO_CERTIFICATE, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ARGERROR_NUM1 );
			}
		}
	if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCACERT )
		{
		if( !checkContextCapability( privateKey, 
									 MESSAGE_CHECK_PKC_SIGN_CA ) )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_CERTINFO_CACERTIFICATE, 
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ARGERROR_NUM1 );
			}
		}

	/* If we're using a certificate, make sure that it's currently valid.  
	   This self-check avoids ugly silent failures where everything appears 
	   to work just fine on the server side but the client gets invalid data 
	   back */
	if( requiredAttributeFlags & ( SESSION_NEEDS_PRIVKEYCERT | \
								   SESSION_NEEDS_PRIVKEYCACERT ) )
		{
		status = checkServerCertValid( privateKey, 
									   sessionInfoPtr->ownerHandle, 
									   SESSION_ERRINFO );
		if( cryptStatusError( status ) )
			{
			/* This check sets the extended error information so there's no
			   need to explicitly set anything here */
			return( CRYPT_ARGERROR_NUM1 );
			}
		}

	/* If we're using ECDSA and the 64-bit SHA-2 algorithms aren't available,
	   make sure that the key is P256 and not one that requires a 64-bit hash
	   fashion statement */
#ifndef USE_SHA2_EXT
	status = krnlSendMessage( privateKey, IMESSAGE_GETATTRIBUTE, 
							  &privateKeyAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( privateKeyAlgo == CRYPT_ALGO_ECDSA )
		{
		int privateKeySize;

		status = krnlSendMessage( privateKey, IMESSAGE_GETATTRIBUTE, 
								  &privateKeySize, CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_NUM1 );
		if( privateKeySize > bitsToBytes( 256 ) )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_SESSINFO_PRIVATEKEY, 
								CRYPT_ERRTYPE_ATTR_SIZE );
			return( CRYPT_ARGERROR_NUM1 );
			}
		}
#endif /* !USE_SHA2_EXT */

	/* Perform any protocol-specific additional checks if necessary */
	if( FNPTR_ISSET( sessionInfoPtr->checkAttributeFunction ) )
		{
		const SES_CHECKATTRIBUTE_FUNCTION checkAttributeFunction = \
						( SES_CHECKATTRIBUTE_FUNCTION ) \
						FNPTR_GET( sessionInfoPtr->checkAttributeFunction );

		REQUIRES( checkAttributeFunction != NULL );

		status = checkAttributeFunction( sessionInfoPtr, &privateKey, 
										 CRYPT_SESSINFO_PRIVATEKEY );
		if( status == OK_SPECIAL )
			{
			/* The value was dealt with as a side-effect of the check 
			   function, there's nothing more to do */
			return( CRYPT_OK );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Add the private key and increment its reference count */
	krnlSendNotifier( privateKey, IMESSAGE_INCREFCOUNT );
	sessionInfoPtr->privateKey = privateKey;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get Attributes								*
*																			*
****************************************************************************/

/* Get a numeric/boolean attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getSessionAttribute( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 OUT_INT_Z int *valuePtr, 
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( valuePtr, sizeof( int ) ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Clear return value */
	*valuePtr = 0;

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			{
			CRYPT_ATTRIBUTE_TYPE attributeID;
			int status;

			status = getSessionAttributeCursor( sessionInfoPtr, attribute, 
												&attributeID );
			if( cryptStatusError( status ) )
				{
				return( exitError( sessionInfoPtr, attribute, 
								   CRYPT_ERRTYPE_ATTR_ABSENT, status ) );
				}
			*valuePtr = attributeID;

			return( CRYPT_OK );
			}

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				{
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_OPTION_NET_CONNECTTIMEOUT ) );
				}
			*valuePtr = sessionInfoPtr->connectTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
				{
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_OPTION_NET_READTIMEOUT ) );
				}
			*valuePtr = sessionInfoPtr->readTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
				{
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_OPTION_NET_WRITETIMEOUT ) );
				}
			*valuePtr = sessionInfoPtr->writeTimeout;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = sessionInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = sessionInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			*valuePtr = sessionInfoPtr->receiveBufSize;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			/* Only secure transport sessions can be persistently active,
			   request/response sessions are only active while the 
			   transaction is in progress.  Note that this differs from the
			   connection-active state below, which records the fact that 
			   there's a network-level connection established but not whether
			   there's any messages or a secure session active across it.  
			   See the comment in setSessionAttribute() for more on this */
			*valuePtr = sessionInfoPtr->iCryptInContext != CRYPT_ERROR && \
						TEST_FLAG( sessionInfoPtr->flags, 
								   SESSION_FLAG_ISOPEN ) ? TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_CONNECTIONACTIVE:
			*valuePtr = TEST_FLAG( sessionInfoPtr->flags, 
								   SESSION_FLAG_ISOPEN ) ? TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SERVER_PORT:
		case CRYPT_SESSINFO_CLIENT_PORT:
			{
			const ATTRIBUTE_LIST *attributeListPtr = \
									findSessionInfo( sessionInfoPtr, attribute );
			if( attributeListPtr == NULL )
				return( exitErrorNotInited( sessionInfoPtr, attribute ) );
			*valuePtr = attributeListPtr->intValue;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_VERSION:
			*valuePtr = sessionInfoPtr->version;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_AUTHRESPONSE:
			if( sessionInfoPtr->authResponse == AUTHRESPONSE_NONE )
				{
				return( exitErrorNotFound( sessionInfoPtr, 
										   CRYPT_SESSINFO_AUTHRESPONSE ) );
				}
			*valuePtr = \
				( sessionInfoPtr->authResponse == AUTHRESPONSE_SUCCESS ) ? \
				TRUE : FALSE;
			return( CRYPT_OK );
		}

	retIntError();
	}

/* Get a string attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getSessionAttributeS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR MESSAGE_DATA *msgData, 
						  IN_ATTRIBUTE \
								const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( msgData, sizeof( MESSAGE_DATA ) ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never user */
			return( exitErrorNotFound( sessionInfoPtr, attribute ) );

		case CRYPT_ATTRIBUTE_ERRORMESSAGE:
			{
#ifdef USE_ERRMSGS
			ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;

			if( errorInfo->errorStringLength > 0 )
				{
				return( attributeCopy( msgData, errorInfo->errorString,
									   errorInfo->errorStringLength ) );
				}
#endif /* USE_ERRMSGS */

			/* We don't set extended error information for this atribute 
			   because it's usually read in response to an existing error, 
			   which would overwrite the existing error information */
			return( CRYPT_ERROR_NOTFOUND );
			}

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_AUTHTOKEN:
			/* If the session was resumed from cached information then the
			   username and password won't be present, however we provide a
			   dummy username to indicate what's happening */
			if( TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_CACHEDINFO ) )
				{
				if( attribute == CRYPT_SESSINFO_PASSWORD )
					return( exitErrorNotInited( sessionInfoPtr, attribute ) );
				return( attributeCopy( msgData, 
									   "[Resumed from previous session]", 31 ) );
				}
			STDC_FALLTHROUGH;

		case CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1:
		case CRYPT_SESSINFO_SERVER_NAME:
		case CRYPT_SESSINFO_CLIENT_NAME:
			attributeListPtr = findSessionInfo( sessionInfoPtr, attribute );
			if( attributeListPtr == NULL )
				return( exitErrorNotInited( sessionInfoPtr, attribute ) );
			return( attributeCopy( msgData, attributeListPtr->value,
								   attributeListPtr->valueLength ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Set Attributes								*
*																			*
****************************************************************************/

/* Set a numeric/boolean attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setSessionAttribute( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 const int value, 
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
	REQUIRES( ( attribute == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
				attribute == CRYPT_ATTRIBUTE_CURRENT ) || 
				/* CURRENT = cursor positioning code */
			  ( attribute == CRYPT_SESSINFO_NETWORKSOCKET ) ||
				/* Socket = non-typed value */
			  isIntegerRange( value ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Make sure that the caller isn't trying to set a second copy of a 
	   singleton attribute */
	if( attribute == CRYPT_SESSINFO_PRIVATEKEY || \
		attribute == CRYPT_SESSINFO_KEYSET || \
		attribute == CRYPT_SESSINFO_NETWORKSOCKET )
		{
		if( checkAttributePresent( sessionInfoPtr, attribute ) )
			return( exitErrorInited( sessionInfoPtr, attribute ) );
		}

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			{
			REQUIRES( value >= CRYPT_CURSOR_LAST && \
					  value <= CRYPT_CURSOR_FIRST );	/* Values are -ve */
			status = setSessionAttributeCursor( sessionInfoPtr, attribute, 
												value );
			if( cryptStatusError( status ) )
				{
				return( exitError( sessionInfoPtr, attribute, 
								   CRYPT_ERRTYPE_ATTR_ABSENT, status ) );
				}
			return( CRYPT_OK );
			}

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			sessionInfoPtr->connectTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			sessionInfoPtr->readTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			sessionInfoPtr->writeTimeout = value;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			REQUIRES( !TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISOPEN ) );

			sessionInfoPtr->receiveBufSize = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			{
			CRYPT_ATTRIBUTE_TYPE missingInfo;

			/* Session state and persistent sessions are handled as follows:
			   The CRYPT_SESSINFO_ACTIVE attribute records the active state
			   of the session as a whole, and the CRYPT_SESSINFO_-
			   CONNECTIONACTIVE attribute records the state of the 
			   underlying comms session.  Setting CRYPT_SESSINFO_ACTIVE for 
			   the first time activates the comms session and leaves it 
			   active if the underlying mechanism (e.g. HTTP 1.1 persistent 
			   connections) supports it.  The CRYPT_SESSINFO_ACTIVE 
			   attribute is reset once the transaction completes, and 
			   further transactions can be initiated as long as 
			   CRYPT_SESSINFO_CONNECTIONACTIVE is set:

										Obj.state	_active		_connactive
										---------	-------		-----------
				create						0			0			0
				setattr						0			0			0
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
				setattr						1			0			1
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
					(peer closes conn)		1			0			0
				setattr							CRYPT_ERROR_COMPLETE */
			if( value == FALSE )
				return( CRYPT_OK );	/* No-op */

			/* If the session is in the partially-open state while we wait 
			   for the caller to allow or disallow the session authentication 
			   they have to provide a clear yes or no indication by setting 
			   CRYPT_SESSINFO_AUTHRESPONSE to TRUE or FALSE before they can 
			   try to continue the session activation */
			if( TEST_FLAG( sessionInfoPtr->flags, 
						   SESSION_FLAG_PARTIALOPEN ) && \
				sessionInfoPtr->authResponse == AUTHRESPONSE_NONE )
				{
				return( exitErrorNotInited( sessionInfoPtr,
										    CRYPT_SESSINFO_AUTHRESPONSE ) );
				}

			/* Make sure that all of the information that we need to proceed 
			   is present */
			REQUIRES( DATAPTR_ISVALID( sessionInfoPtr->attributeList ) );
			missingInfo = checkMissingInfo( DATAPTR_GET( sessionInfoPtr->attributeList ),
								isServer( sessionInfoPtr ) ? TRUE : FALSE );
			if( missingInfo != CRYPT_ATTRIBUTE_NONE )
				return( exitErrorNotInited( sessionInfoPtr, missingInfo ) );
			status = activateSession( sessionInfoPtr );
			if( cryptArgError( status ) )
				{
				/* Catch leaked low-level status values.  The session 
				   management code does a large amount of work involving 
				   other cryptlib objects so it's possible that an 
				   unexpected failure at some point will leak through an 
				   inappropriate status value */
				DEBUG_DIAG(( "Session activate returned argError status" ));
				assert( DEBUG_WARN );
				status = CRYPT_ERROR_FAILED;
				}
			return( status );
			}

		case CRYPT_SESSINFO_SERVER_PORT:
			/* If there's already a network socket specified then we can't 
			   set a port as well */
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				{
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );
				}

			return( addSessionInfo( sessionInfoPtr,
									CRYPT_SESSINFO_SERVER_PORT, value ) );

		case CRYPT_SESSINFO_VERSION:
			{
			const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );

			ENSURES( protocolInfo != NULL );

			if( value < protocolInfo->minVersion || \
				value > protocolInfo->maxVersion )
				return( CRYPT_ARGERROR_VALUE );
			sessionInfoPtr->version = value;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_PRIVATEKEY:
			return( addPrivateKey( sessionInfoPtr, value ) );

		case CRYPT_SESSINFO_KEYSET:
			{
			int type;

			/* Make sure that it's either a certificate store (rather than 
			   just a generic keyset) if required, or specifically not a 
			   certificate store if not required.  This is to prevent a 
			   session running with unnecessary privileges, we should only 
			   be using a certificate store if it's actually required.  The 
			   checking is already performed by the kernel but we do it 
			   again here just to be safe */
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, &type, 
									  CRYPT_IATTRIBUTE_SUBTYPE );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( sessionInfoPtr->serverReqAttrFlags & SESSION_NEEDS_CERTSTORE )
				{
				if( type != SUBTYPE_KEYSET_DBMS_STORE )
					return( CRYPT_ARGERROR_NUM1 );
				}
			else
				{
				if( type != SUBTYPE_KEYSET_DBMS )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* Add the keyset and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->cryptKeyset = value;

			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_AUTHRESPONSE:
			{
			const SES_SETATTRIBUTE_FUNCTION setAttributeFunction = \
							( SES_SETATTRIBUTE_FUNCTION ) \
							FNPTR_GET( sessionInfoPtr->setAttributeFunction );
			const PROTOCOL_INFO *protocolInfo = \
							DATAPTR_GET( sessionInfoPtr->protocolInfo );

			REQUIRES( protocolInfo != NULL );

			sessionInfoPtr->authResponse = value ? AUTHRESPONSE_SUCCESS : \
												   AUTHRESPONSE_FAILURE;
			if( !( protocolInfo->flags & SESSION_PROTOCOL_REFLECTAUTHOK ) )
				return( CRYPT_OK );

			/* Besides recording whether it's OK to continue, in some cases 
			   we need to reflect the auth-response action down to session-
			   specific handlers for protocol-specific handling */
			REQUIRES( setAttributeFunction != NULL );
			return( setAttributeFunction( sessionInfoPtr, 
										  &sessionInfoPtr->authResponse,
										  CRYPT_SESSINFO_AUTHRESPONSE ) );
			}

		case CRYPT_SESSINFO_SESSION:
			/* Not used, blocked by the kernel */
			retIntError();

		case CRYPT_SESSINFO_NETWORKSOCKET:
			{
			NET_CONNECT_INFO connectInfo;
			STREAM stream;

			/* If there's already a host specified then we can't set a 
			   network socket as well */
			if( findSessionInfo( sessionInfoPtr,
								 CRYPT_SESSINFO_SERVER_NAME ) != NULL )
				{
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
				}

			/* Create a dummy network stream to make sure that the network 
			   socket is OK */
			initNetConnectInfo( &connectInfo, sessionInfoPtr->ownerHandle, 
								sessionInfoPtr->readTimeout, 
								sessionInfoPtr->connectTimeout,
								NET_OPTION_NETWORKSOCKET_DUMMY );
			connectInfo.networkSocket = value;
			status = sNetConnect( &stream, STREAM_PROTOCOL_TCP, 
								  &connectInfo, &sessionInfoPtr->errorInfo );
			if( cryptStatusError( status ) )
				return( status );
			sNetDisconnect( &stream );

			/* Add the network socket */
			sessionInfoPtr->networkSocket = value;

			return( CRYPT_OK );
			}
		}

	retIntError();
	}

/* Set a string attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setSessionAttributeS( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  IN_BUFFER( dataLength ) const void *data,
						  IN_LENGTH const int dataLength,
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
	REQUIRES( isIntegerRangeNZ( dataLength ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Make sure that the caller isn't trying to set a second copy of a 
	   singleton attribute */
	if( attribute == CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1 || \
		attribute == CRYPT_SESSINFO_SERVER_NAME )
		{
		if( checkAttributePresent( sessionInfoPtr, attribute ) )
			return( exitErrorInited( sessionInfoPtr, attribute ) );
		}

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never used */
			return( CRYPT_ARGERROR_VALUE );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_AUTHTOKEN:
			return( addCredential( sessionInfoPtr, data, dataLength, 
								   attribute ) );

		case CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1:
			/* Remember the value */
			return( addSessionInfoS( sessionInfoPtr, attribute, data, 
									 dataLength ) );

		case CRYPT_SESSINFO_SERVER_NAME:
			return( addUrl( sessionInfoPtr, data, dataLength ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Delete Attributes							*
*																			*
****************************************************************************/

/* Delete an attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deleteSessionAttribute( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							IN_ATTRIBUTE \
								const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSession( sessionInfoPtr ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				{
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_OPTION_NET_CONNECTTIMEOUT ) );
				}
			sessionInfoPtr->connectTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
				{
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_OPTION_NET_READTIMEOUT ) );
				}
			sessionInfoPtr->readTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
				{
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_OPTION_NET_WRITETIMEOUT ) );
				}
			sessionInfoPtr->writeTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_AUTHTOKEN:
		case CRYPT_SESSINFO_SERVER_NAME:
		case CRYPT_SESSINFO_SERVER_PORT:
			/* Make sure that the attribute to delete is actually present */
			attributeListPtr = findSessionInfo( sessionInfoPtr, attribute );
			if( attributeListPtr == NULL )
				return( exitErrorNotFound( sessionInfoPtr, attribute ) );

			/* Delete the attribute.  If we're in the middle of a paired-
			   attribute add then the delete affects the paired attribute.  
			   This can get quite complex because the user could (for 
			   example) add a { username, password } pair, then add a second 
			   username (but not password), and then delete the first 
			   password, leaving an orphaned password followed by an 
			   orphaned username.  There isn't any easy way to fix this 
			   short of forcing some form of group delete of paired 
			   attributes, but this gets too complicated both to implement 
			   and to explain to the user in an error status.  What we do 
			   here is handle the simple case and let the pre-session-
			   activation sanity check catch situations where the user's 
			   gone out of their way to be difficult */
			deleteSessionInfo( sessionInfoPtr,
							   ( ATTRIBUTE_LIST * ) attributeListPtr );
			return( CRYPT_OK );

		case CRYPT_SESSINFO_REQUEST:
			if( sessionInfoPtr->iCertRequest == CRYPT_ERROR )
				{
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_REQUEST ) );
				}
			krnlSendNotifier( sessionInfoPtr->iCertRequest,
							  IMESSAGE_DECREFCOUNT );
			sessionInfoPtr->iCertRequest = CRYPT_ERROR;

			return( CRYPT_OK );

#ifdef USE_TSP
		case CRYPT_SESSINFO_TSP_MSGIMPRINT:
			if( sessionInfoPtr->sessionTSP->imprintAlgo == CRYPT_ALGO_NONE || \
				sessionInfoPtr->sessionTSP->imprintSize <= 0 )
				{
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_TSP_MSGIMPRINT ) );
				}
			sessionInfoPtr->sessionTSP->imprintAlgo = CRYPT_ALGO_NONE;
			sessionInfoPtr->sessionTSP->imprintSize = 0;

			return( CRYPT_OK );
#endif /* USE_TSP */
		}

	retIntError();
	}
#endif /* USE_SESSIONS */
