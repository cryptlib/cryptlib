/****************************************************************************
*																			*
*						 cryptlib CMP Session Management					*
*						Copyright Peter Gutmann 1999-2011					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "session.h"
  #include "cmp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "session/session.h"
  #include "session/cmp.h"
#endif /* Compiler-specific includes */

#ifdef USE_CMP

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Sanity-check the session state and protocol information */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckSessionCMP( IN_PTR const SESSION_INFO *sessionInfoPtr )
	{
	const CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( cmpInfo, sizeof( CMP_INFO ) ) );

	/* Check the general envelope state */
	if( !sanityCheckSession( sessionInfoPtr ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionCMP: Session check" ));
		return( FALSE );
		}

	/* Check CMP session parameters */
	if( !CHECK_FLAGS( sessionInfoPtr->protocolFlags, CMP_PFLAG_NONE, 
					  CMP_PFLAG_MAX ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionCMP: Protocol flags" ));
		return( FALSE );
		}
	if( !isEnumRangeOpt( cmpInfo->requestType, CRYPT_REQUESTTYPE ) || \
		( cmpInfo->userInfo != CRYPT_ERROR && \
		  !isHandleRangeValid( cmpInfo->userInfo ) ) || \
		( cmpInfo->iExtraCerts != CRYPT_ERROR && \
		  !isHandleRangeValid( cmpInfo->iExtraCerts ) ) || \
		( cmpInfo->iSavedMacContext != CRYPT_ERROR && \
		  !isHandleRangeValid( cmpInfo->iSavedMacContext ) ) )
		{
		DEBUG_PUTS(( "sanityCheckSessionCMP: Session parameters" ));
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckCMPProtocolInfo( IN_PTR \
										const CMP_PROTOCOL_INFO *protocolInfo )
	{
	/* Check the session state information */
	if( !isEnumRangeOpt( protocolInfo->operation, CMP_MESSAGE ) || \
		!isBooleanValue( protocolInfo->isCryptlib ) || \
		!isBooleanValue( protocolInfo->isServer ) )
		{
		DEBUG_PUTS(( "sanityCheckCMPProtocolInfo: Session state" ));
		return( FALSE );
		}

	/* Check the identification/state variable information */
	if( protocolInfo->userIDsize < 0 || \
		protocolInfo->userIDsize > CRYPT_MAX_TEXTSIZE || \
		protocolInfo->transIDsize < 0 || \
		protocolInfo->transIDsize > CRYPT_MAX_HASHSIZE || \
		protocolInfo->certIDsize < 0 || \
		protocolInfo->certIDsize > CRYPT_MAX_HASHSIZE || \
		protocolInfo->senderNonceSize < 0 || \
		protocolInfo->senderNonceSize > CRYPT_MAX_HASHSIZE || \
		protocolInfo->recipNonceSize < 0 || \
		protocolInfo->recipNonceSize > CRYPT_MAX_HASHSIZE )
		{
		DEBUG_PUTS(( "sanityCheckCMPProtocolInfo: Identification values" ));
		return( FALSE );
		}
	if( !isBooleanValue( protocolInfo->userIDchanged ) || \
		!isBooleanValue( protocolInfo->certIDchanged ) || \
		!isBooleanValue( protocolInfo->noIntegrity ) || \
		!isBooleanValue( protocolInfo->headerRead ) || \
		!isBooleanValue( protocolInfo->useAltAuthKey ) )
		{
		DEBUG_PUTS(( "sanityCheckCMPProtocolInfo: State variables" ));
		return( FALSE );
		}

	/* Check encryption-only key information */
	if( !isBooleanValue( protocolInfo->cryptOnlyKey ) || \
		( protocolInfo->authContext != CRYPT_ERROR && \
		  !isHandleRangeValid( protocolInfo->authContext ) ) )
		{
		DEBUG_PUTS(( "sanityCheckCMPProtocolInfo: Encryption-only values" ));
		return( FALSE );
		}

	/* Check message integrity values */
	if( !( protocolInfo->hashAlgo == CRYPT_ALGO_NONE || \
		   isHashAlgo( protocolInfo->hashAlgo ) ) || \
		!( protocolInfo->iMacContext == CRYPT_ERROR || \
		   isHandleRangeValid( protocolInfo->iMacContext ) ) || \
		protocolInfo->saltSize < 0 || \
		protocolInfo->saltSize > CRYPT_MAX_HASHSIZE || \
		protocolInfo->altMacKeySize < 0 || \
		protocolInfo->altMacKeySize > CRYPT_MAX_HASHSIZE || \
		!isBooleanValue( protocolInfo->useMACsend ) || \
		!isBooleanValue( protocolInfo->useMACreceive ) )
		{
		DEBUG_PUTS(( "sanityCheckCMPProtocolInfo: Message integrity values" ));
		return( FALSE );
		}

	/* Check CA/RA status */	
	if( !isBooleanValue( protocolInfo->userIsRA ) )
		{
		DEBUG_PUTS(( "sanityCheckCMPProtocolInfo: CA/RA status" ));
		return( FALSE );
		}

	/* Check miscellaneous information */
	if( !( protocolInfo->confHashAlgo == CRYPT_ALGO_NONE || \
		   isHashAlgo( protocolInfo->confHashAlgo ) ) || \
		!isShortIntegerRange( protocolInfo->macInfoPos ) || \
		!( ( protocolInfo->senderDNPtr == NULL && \
			 protocolInfo->senderDNlength == 0 ) || \
		   ( protocolInfo->senderDNPtr != NULL && \
		     isShortIntegerRangeNZ( protocolInfo->senderDNlength ) ) ) )
		{
		DEBUG_PUTS(( "sanityCheckCMPProtocolInfo: Miscellaneous information" ));
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

#ifdef USE_ERRMSGS

/* Get a string description of CMP message types, used for diagnostic error 
   messages */

CHECK_RETVAL_PTR_NONNULL \
const char *getCMPMessageName( IN_BYTE const int messageType )
	{
	static const OBJECT_NAME_INFO packetNameInfo[] = {
		/* { CTAG_PB_IR, "ir" } */	/* See comment below */
		{ CTAG_PB_IP, "ip" },
		{ CTAG_PB_CR, "cr" },
		{ CTAG_PB_CP, "cp" },
		{ CTAG_PB_P10CR, "p10cr" },
		{ CTAG_PB_POPDECC, "popdecc" },
		{ CTAG_PB_POPDECR, "popdecr" },
		{ CTAG_PB_KUR, "kur" },
		{ CTAG_PB_KUP, "kup" },
		{ CTAG_PB_KRR, "krr" },
		{ CTAG_PB_KRP, "krp" },
		{ CTAG_PB_RR, "rr" },
		{ CTAG_PB_RP, "rp" },
		{ CTAG_PB_CCR, "ccr" },
		{ CTAG_PB_CCP, "ccp" },
		{ CTAG_PB_CKUANN, "ckuann" },
		{ CTAG_PB_CANN, "cann" },
		{ CTAG_PB_RANN, "rann" },
		{ CTAG_PB_CRLANN, "crlann" },
		{ CTAG_PB_PKICONF, "pkiconf" },
		{ CTAG_PB_NESTED, "nested" },
		{ CTAG_PB_GENM, "genm" },
		{ CTAG_PB_GENP, "genp" },
		{ CTAG_PB_ERROR, "error" },
		{ CTAG_PB_CERTCONF, "certConf" },
		{ CTAG_PB_POLLREQ, "pollReq" }, 
		{ CTAG_PB_POLLREP, "pollRep" },
		{ CMP_MESSAGE_NONE, "<Unknown type>" },
			{ CMP_MESSAGE_NONE, "<Unknown type>" }
		};

	REQUIRES_EXT( ( messageType >= 0 && messageType <= 0xFF ),
				  "<Internal error>" );

	/* We have to special-case CTAG_PB_IR since the CMP spec decided to
	   assign 0 as a valid message type so it looks like the end-of-list 
	   delimiter */
	if( messageType == CTAG_PB_IR )
		return( "ir" );

	return( getObjectName( packetNameInfo,
						   FAILSAFE_ARRAYSIZE( packetNameInfo, \
											   OBJECT_NAME_INFO ),
						   messageType ) );
	}
#endif /* USE_ERRMSGS */

#if defined( __WIN32__ ) && !defined( NDEBUG )

/* Dump a message to disk for diagnostic purposes.  The CMP messages are
   complex enough that we can't use the normal DEBUG_DUMP() macro but have
   to use a special-purpose wrapper that uses meaningful names for all
   of the files that are created */

STDC_NONNULL_ARG( ( 3 ) ) \
void debugDumpCMP( IN_ENUM( CMP_MESSAGE ) const CMP_MESSAGE_TYPE type, 
				   IN_RANGE( 1, 4 ) const int phase,
				   const SESSION_INFO *sessionInfoPtr )
	{
	static const char *irStrings[] = \
		{ "cmpi1_ir", "cmpi2_ip", "cmpi3_conf", "cmpi4_confack" };
	static const char *crStrings[] = \
		{ "cmpc1_cr", "cmpc2_cp", "cmpc3_conf", "cmpc4_confack" };
	static const char *kurStrings[] = \
		{ "cmpk1_kur", "cmpk2_kup", "cmpk3_conf", "cmpk4_confack" };
	static const char *rrStrings[] = \
		{ "cmpr1_rr", "cmpr2_rp" };
	static const char *gmStrings[] = \
		{ "cmpg1_gr", "cmpg2_gp" };
	static const char *errorStrings[] = \
		{ "cmpe1_error" };
	static const char *unkStrings[] = \
		{ "cmp_unknown1", "cmp_unknown2", "cmp_unknown3", "cmp_unknown4" };
	const char **fnStringPtr = ( type == CTAG_PB_IR ) ? irStrings : \
							   ( type == CTAG_PB_CR ) ? crStrings : \
							   ( type == CTAG_PB_KUR ) ? kurStrings : \
							   ( type == CTAG_PB_RR ) ? rrStrings : \
							   ( type == CTAG_PB_GENM ) ? gmStrings : \
							   ( type == CTAG_PB_ERROR ) ? errorStrings : \
							  unkStrings;
	char fileName[ 1024 + 8 ];

#ifndef DUMP_SERVER_MESSAGES
	/* Server messages have complex names based on the server DN so we only 
	   dump them if explicitly requested */
	if( isServer( sessionInfoPtr ) )
		return;
#else
	if( isServer( sessionInfoPtr ) )
		{
		MESSAGE_DATA msgData;
		const int pathLength = strlen( fileName );
		LOOP_INDEX i;

		setMessageData( &msgData, fileName + pathLength, 1024 - pathLength );
		krnlSendMessage( sessionInfoPtr->privateKey, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_CERTINFO_DN );
		LOOP_LARGE( i = 0, i < msgData.length, i++ )
			{
			int ch;

			ENSURES( LOOP_INVARIANT_LARGE( i, 0, msgData.length - 1 ) );

			ch = byteToInt( fileName[ pathLength + i ] );
			if( ch == ' ' || ch == '\'' || ch == '"' || ch == '?' || \
				ch == '*' || ch == '[' || ch == ']' || ch == '`' || \
				ch == ',' || ch < ' ' || ch > 'z' )
				fileName[ pathLength + i ] = '_';
			}
		ENSURES( LOOP_BOUND_OK );
		strlcat_s( fileName, 1024, "_" );
		strlcat_s( fileName, 1024, fnStringPtr[ phase - 1 ] );
		}
	else
#endif /* DUMP_SERVER_MESSAGES */
	strcpy_s( fileName, 1024, fnStringPtr[ phase - 1 ] );

	DEBUG_DUMP_FILE( fileName, sessionInfoPtr->receiveBuffer,
					 sessionInfoPtr->receiveBufEnd );
	}
#endif /* Windows debug mode only */

/* Map request to response types */

static const MAP_TABLE reqRespMapTbl[] = {
	{ CTAG_PB_IR, CTAG_PB_IP },
	{ CTAG_PB_CR, CTAG_PB_CP },
	{ CTAG_PB_P10CR, CTAG_PB_CP },
	{ CTAG_PB_POPDECC, CTAG_PB_POPDECR },
	{ CTAG_PB_KUR, CTAG_PB_KUP },
	{ CTAG_PB_KRR, CTAG_PB_KRP },
	{ CTAG_PB_RR, CTAG_PB_RP },
	{ CTAG_PB_CCR, CTAG_PB_CCP },
	{ CTAG_PB_GENM, CTAG_PB_GENP },
	{ CRYPT_ERROR, CRYPT_ERROR }, 
		{ CRYPT_ERROR, CRYPT_ERROR }
	};

CHECK_RETVAL_RANGE( CMP_MESSAGE_NONE, CMP_MESSAGE_LAST - 1 ) \
int reqToResp( IN_ENUM_OPT( CMP_MESSAGE ) const CMP_MESSAGE_TYPE reqType )
	{
	int value, status;

	REQUIRES( reqType >= CTAG_PB_IR && reqType < CTAG_PB_LAST );
			  /* CTAG_PB_IR == 0 so this is the same as _NONE */

	status = mapValue( reqType, &value, reqRespMapTbl, 
					   FAILSAFE_ARRAYSIZE( reqRespMapTbl, MAP_TABLE ) );
	return( cryptStatusError( status ) ? status : value );
	}

/* Initialise and destroy the protocol state information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int initCMPprotocolInfo( OUT_PTR CMP_PROTOCOL_INFO *protocolInfo, 
						 IN_PTR const SESSION_INFO *sessionInfoPtr,
						 IN_BOOL const BOOLEAN isServer )
	{
	int value, status;

	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isBooleanValue( isServer ) );

	memset( protocolInfo, 0, sizeof( CMP_PROTOCOL_INFO ) );
	protocolInfo->iMacContext = protocolInfo->authContext = CRYPT_ERROR;
	if( TEST_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISCRYPTLIB ) )
		protocolInfo->isCryptlib = TRUE;
	if( isServer )
		{
		protocolInfo->isServer = TRUE;
		protocolInfo->authContext = sessionInfoPtr->privateKey;
		}

	/* Get any other state information that we may need */
	status = krnlSendMessage( sessionInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_OPTION_ENCR_HASH );
	ENSURES( cryptStatusOK( status ) );
	protocolInfo->hashAlgo = value;	/* int vs.enum */
	status = krnlSendMessage( sessionInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_OPTION_ENCR_HASHPARAM );
	ENSURES( cryptStatusOK( status ) );
	protocolInfo->hashParam = value;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setCMPprotocolInfo( INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo, 
						IN_BUFFER_OPT( userIDlength ) const void *userID, 
						IN_LENGTH_SHORT_Z const int userIDlength, 
						IN_FLAGS_Z( CMP_INIT ) const int flags,
						IN_BOOL const BOOLEAN isCryptlib )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );
	assert( ( userID == NULL && userIDlength == 0 ) || \
			isReadPtrDynamic( userID, userIDlength ) );

	REQUIRES( ( !( flags & CMP_INIT_FLAG_USERID ) && userID == NULL && \
				userIDlength == 0 ) || \
			  ( ( flags & CMP_INIT_FLAG_USERID ) && userID != NULL && \
				isShortIntegerRangeNZ( userIDlength ) ) );
	REQUIRES( isFlagRangeZ( flags, CMP_INIT ) );
	REQUIRES( isBooleanValue( isCryptlib ) );

	/* Initalise the protocol state information.  The sender nonce is 
	   refreshed on each message read (i.e. at each round of the protocol),
	   but its initial value has to be set here at startup */
	setMessageData( &msgData, protocolInfo->senderNonce, CMP_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );
	protocolInfo->senderNonceSize = CMP_NONCE_SIZE;

	/* Set fixed identification information */
	if( flags & CMP_INIT_FLAG_USERID )
		{
		REQUIRES( rangeCheck( userIDlength, 0, CRYPT_MAX_TEXTSIZE ) );
		memcpy( protocolInfo->userID, userID, userIDlength );
		protocolInfo->userIDsize = userIDlength;
		DEBUG_PRINT(( "%s: Set userID.\n",
					  protocolInfo->isServer ? "SVR" : "CLI" ));
		DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
						protocolInfo->userID, protocolInfo->userIDsize );
		}
	if( flags & CMP_INIT_FLAG_TRANSID )
		{
		setMessageData( &msgData, protocolInfo->transID, CMP_NONCE_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		protocolInfo->transIDsize = CMP_NONCE_SIZE;
		DEBUG_PRINT(( "%s: Set new transID.\n",
					  protocolInfo->isServer ? "SVR" : "CLI" ));
		DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
						protocolInfo->transID, protocolInfo->transIDsize );
		}

	/* Set the MAC information and context.  cryptlib uses strong passwords 
	   (or at least MAC keys) so if we're using a cryptlib-generated key we
	   apply a smaller number of iterations than what'd be needed for an 
	   unknown-strength password/MAC key */
	if( flags & CMP_INIT_FLAG_MACINFO )
		{
		setMessageData( &msgData, protocolInfo->salt, CMP_NONCE_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		protocolInfo->saltSize = CMP_NONCE_SIZE;
		protocolInfo->iterations = isCryptlib ? CMP_PW_ITERATIONS_CLIB : \
												CMP_PW_ITERATIONS_OTHER;
		}
	if( flags & CMP_INIT_FLAG_MACCTX )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		REQUIRES( protocolInfo->iMacContext == CRYPT_ERROR );
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_HMAC_SHA1 );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		protocolInfo->iMacContext = createInfo.cryptHandle;
		protocolInfo->useMACsend = protocolInfo->useMACreceive = TRUE;
		}

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroyCMPprotocolInfo( INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Destroy any active MAC contexts.  The authContext is just a reference 
	   to the appropriate context in the session information so we don't 
	   destroy it here.  The reason why we keep a reference to the 
	   authentication context is because it could be one of several 
	   different objects associated with the session information, if the
	   client private key that's being certified is a signing key then the
	   authentication context is the private key itself, if the private key 
	   is an encryption-only key then the authentication context is a 
	   separate signing key that was certified earlier.  Maintaining a
	   reference in the protocol information avoids having to decide on the 
	   fly which one to use */
	if( protocolInfo->iMacContext != CRYPT_ERROR )
		krnlSendNotifier( protocolInfo->iMacContext, IMESSAGE_DECREFCOUNT );

	zeroise( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Shut down a CMP session */

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES_V( sanityCheckSession( sessionInfoPtr ) );

	/* Clean up CMP-specific objects */
	if( cmpInfo->userInfo != CRYPT_ERROR )
		krnlSendNotifier( cmpInfo->userInfo, IMESSAGE_DECREFCOUNT );
	if( cmpInfo->iExtraCerts != CRYPT_ERROR )
		krnlSendNotifier( cmpInfo->iExtraCerts, IMESSAGE_DECREFCOUNT );
	if( cmpInfo->iSavedMacContext != CRYPT_ERROR )
		krnlSendNotifier( cmpInfo->iSavedMacContext, IMESSAGE_DECREFCOUNT );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 INOUT_PTR void *data, 
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	CRYPT_CERTIFICATE *cmpResponsePtr = ( CRYPT_CERTIFICATE * ) data;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( data, sizeof( int ) ) );
	
	REQUIRES( type == CRYPT_SESSINFO_RESPONSE || \
			  type == CRYPT_SESSINFO_CMP_REQUESTTYPE || \
			  type == CRYPT_SESSINFO_CMP_OPTIONS );

	/* If it's a general protocol-specific attribute read, return the
	   information and exit */
	if( type == CRYPT_SESSINFO_CMP_REQUESTTYPE )
		{
		if( cmpInfo->requestType == CRYPT_REQUESTTYPE_NONE )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_SESSINFO_CMP_REQUESTTYPE,
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		*( ( int * ) data ) = cmpInfo->requestType;
		return( CRYPT_OK );
		}
	if( type == CRYPT_SESSINFO_CMP_OPTIONS )
		{
		int cmpOption = 0;

		if( TEST_FLAG( sessionInfoPtr->protocolFlags, CMP_PFLAG_3GPP ) )
			cmpOption |= CRYPT_CMPOPTION_3GPP;
		*( ( int * ) data ) = cmpOption;
		return( CRYPT_OK );
		}
	if( type == -1 )
		{
		if( cmpInfo->iExtraCerts == CRYPT_ERROR )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								-1,
								CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTFOUND );
			}
		krnlSendNotifier( cmpInfo->iExtraCerts, IMESSAGE_INCREFCOUNT );
		*cmpResponsePtr = cmpInfo->iExtraCerts;
		return( CRYPT_OK );
		}

	/* If we didn't get a response there's nothing to return */
	if( sessionInfoPtr->iCertResponse == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the information to the caller */
	krnlSendNotifier( sessionInfoPtr->iCertResponse, IMESSAGE_INCREFCOUNT );
	*cmpResponsePtr = sessionInfoPtr->iCertResponse;
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int setAttributeFunction( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 IN_PTR const void *data,
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	CRYPT_CERTIFICATE cryptCert = *( ( CRYPT_CERTIFICATE * ) data );
	int certReqType, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, sizeof( int ) ) );

	REQUIRES( type == CRYPT_SESSINFO_REQUEST || \
			  type == CRYPT_SESSINFO_CACERTIFICATE || \
			  type == CRYPT_SESSINFO_CMP_REQUESTTYPE || \
			  type == CRYPT_SESSINFO_CMP_PRIVKEYSET || \
			  type == CRYPT_SESSINFO_CMP_OPTIONS );

	/* Standard CMP (with user-supplied request information) can't be 
	   combined with plug-and-play CMP (with automatically-generated request 
	   information) */
	if( ( type == CRYPT_SESSINFO_CMP_REQUESTTYPE || \
		  type == CRYPT_SESSINFO_REQUEST ) && \
		sessionInfoPtr->privKeyset != CRYPT_ERROR )
		{
		setObjectErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_CMP_PRIVKEYSET,
							CRYPT_ERRTYPE_ATTR_PRESENT );
		retExt( CRYPT_ERROR_INITED,
				( CRYPT_ERROR_INITED, SESSION_ERRINFO,
				  "Standard CMP can't be combined with plug-and-play "
				  "CMP" ) );
		}
	if( type == CRYPT_SESSINFO_CMP_PRIVKEYSET && \
		( cmpInfo->requestType != CRYPT_REQUESTTYPE_NONE || \
		  sessionInfoPtr->iCertRequest != CRYPT_ERROR ) )
		{
		setObjectErrorInfo( sessionInfoPtr, 
					( sessionInfoPtr->iCertRequest != CRYPT_ERROR ) ? \
					  CRYPT_SESSINFO_REQUEST : \
					  CRYPT_SESSINFO_CMP_REQUESTTYPE,
					CRYPT_ERRTYPE_ATTR_PRESENT );
		retExt( CRYPT_ERROR_INITED,
				( CRYPT_ERROR_INITED, SESSION_ERRINFO,
				  "Standard CMP can't be combined with plug-and-play "
				  "CMP" ) );
		}

	/* If it's general protocol-specific information other than a request or 
	   certificate, set it */
	if( type == CRYPT_SESSINFO_CMP_REQUESTTYPE )
		{
		const int cmpReqType = *( ( int * ) data );

		/* Make sure that the value hasn't been set yet */
		if( cmpInfo->requestType != CRYPT_REQUESTTYPE_NONE )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_SESSINFO_CMP_REQUESTTYPE,
								CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* If the request object is already present, make sure that it 
		   matches the request type.  We can't do this check unconditionally 
		   because the request type may be set before the request object is 
		   set */
		if( sessionInfoPtr->iCertRequest != CRYPT_ERROR )
			{
			status = krnlSendMessage( sessionInfoPtr->iCertRequest,
									  IMESSAGE_GETATTRIBUTE, &certReqType, 
									  CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) )
				return( status );
			if( certReqType == CRYPT_CERTTYPE_REQUEST_CERT )
				{
				if( cmpReqType != CRYPT_REQUESTTYPE_INITIALISATION && \
					cmpReqType != CRYPT_REQUESTTYPE_CERTIFICATE && \
					cmpReqType != CRYPT_REQUESTTYPE_KEYUPDATE )
					status = CRYPT_ERROR_INVALID;
				}
			else
				{
				if( cmpReqType != CRYPT_REQUESTTYPE_REVOCATION )
					status = CRYPT_ERROR_INVALID;
				}
			if( cryptStatusError( status ) )
				{
				setObjectErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_REQUEST,
									CRYPT_ERRTYPE_CONSTRAINT );
				retExt( status,
						( status, SESSION_ERRINFO,
						  "Certificate request object type %d doesn't match "
						  "request type %d", certReqType, cmpReqType ) );
				}
			}

		/* Set the CMP request type and tell the higher-level code that 
		   further information needs to be provided before we can activate 
		   the session */
		cmpInfo->requestType = cmpReqType;
		if( cmpReqType == CRYPT_REQUESTTYPE_INITIALISATION || \
			cmpReqType == CRYPT_REQUESTTYPE_PKIBOOT )
			{
			sessionInfoPtr->clientReqAttrFlags = \
									SESSION_NEEDS_USERID | \
									SESSION_NEEDS_PASSWORD;
			}
		else
			{
			if( cmpReqType == CRYPT_REQUESTTYPE_REVOCATION )
				{
				sessionInfoPtr->clientReqAttrFlags = \
									SESSION_NEEDS_PRIVATEKEY | \
									SESSION_NEEDS_PRIVKEYSIGN | \
									SESSION_NEEDS_PRIVKEYCERT | \
									SESSION_NEEDS_KEYORPASSWORD;
				}
			else
				{
				sessionInfoPtr->clientReqAttrFlags = \
									SESSION_NEEDS_PRIVATEKEY | \
									SESSION_NEEDS_PRIVKEYSIGN | \
									SESSION_NEEDS_PRIVKEYCERT;
				}
			}
		return( CRYPT_OK );
		}
	if( type == CRYPT_SESSINFO_CMP_PRIVKEYSET )
		{
		CRYPT_KEYSET privKeyset = *( ( CRYPT_KEYSET * ) data );

		/* Make sure that the value hasn't been set yet */
		if( sessionInfoPtr->privKeyset != CRYPT_ERROR )
			{
			setObjectErrorInfo( sessionInfoPtr, 
								CRYPT_SESSINFO_CMP_PRIVKEYSET,
								CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* Remember that we're using plug-and-play PKI functionality */
		SET_FLAG( sessionInfoPtr->protocolFlags, CMP_PFLAG_PNPPKI );

		krnlSendNotifier( privKeyset, IMESSAGE_INCREFCOUNT );
		sessionInfoPtr->privKeyset = privKeyset;
		return( CRYPT_OK );
		}
	if( type == CRYPT_SESSINFO_CMP_OPTIONS )
		{
		const int cmpOption = *( ( int * ) data );

		/* Set protocol-specific flags based on the options the user has 
		   provided */
		if( cmpOption & CRYPT_CMPOPTION_3GPP )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, CMP_PFLAG_3GPP );
			}
		return( CRYPT_OK );
		}

	/* Make sure that the request/certificate type is consistent with the 
	   operation being performed.  The requirements for this are somewhat 
	   more complex than the basic ACL-based check can manage, so we handle 
	   it here with custom code */
	status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE, &certReqType, 
							  CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	switch( type )
		{
		case CRYPT_SESSINFO_REQUEST:
			{
			const CRYPT_REQUESTTYPE_TYPE cmpReqType = cmpInfo->requestType;

			if( certReqType != CRYPT_CERTTYPE_REQUEST_CERT && \
				certReqType != CRYPT_CERTTYPE_REQUEST_REVOCATION )
				{
				retExt( CRYPT_ARGERROR_NUM1,
						( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
						  "Certificate request object type %d doesn't match "
						  "request type %d", certReqType, cmpReqType ) );
				}

			/* If there's no CMP request type already set, we're done.  We 
			   can't otherwise perform the checks that follow because the 
			   request object may be set before the request type is set */
			if( cmpReqType == CRYPT_REQUESTTYPE_NONE )
				break;

			/* The request type is already present, make sure that it 
			   matches the request object */
			if( certReqType == CRYPT_CERTTYPE_REQUEST_CERT )
				{
				if( cmpReqType != CRYPT_REQUESTTYPE_INITIALISATION && \
					cmpReqType != CRYPT_REQUESTTYPE_CERTIFICATE && \
					cmpReqType != CRYPT_REQUESTTYPE_KEYUPDATE )
					status = CRYPT_ERROR_INVALID;
				}
			else
				{
				if( cmpReqType != CRYPT_REQUESTTYPE_REVOCATION )
					status = CRYPT_ERROR_INVALID;
				}
			if( cryptStatusError( status ) )
				{
				setObjectErrorInfo( sessionInfoPtr, 
									CRYPT_SESSINFO_CMP_REQUESTTYPE,
									CRYPT_ERRTYPE_CONSTRAINT );
				retExt( status,
						( status, SESSION_ERRINFO,
						  "Certificate request object type %d doesn't match "
						  "request type %d", certReqType, cmpReqType ) );
				}

			/* If it's a non-ir certificate request, make sure that there's 
			   a subject DN present.  We perform this check because subject 
			   DNs are optional for irs but may be required for some CMP
			   servers for other request types and we want to catch this 
			   before we get into the CMP exchange itself */
			if( cmpReqType == CRYPT_REQUESTTYPE_CERTIFICATE || \
				cmpReqType == CRYPT_REQUESTTYPE_KEYUPDATE )
				{
				MESSAGE_DATA msgData = { NULL, 0 };

				status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE_S, 
										  &msgData, CRYPT_IATTRIBUTE_SUBJECT );
				if( cryptStatusError( status ) )
					{
					setObjectErrorInfo( sessionInfoPtr, 
										CRYPT_CERTINFO_SUBJECTNAME,
										CRYPT_ERRTYPE_ATTR_ABSENT );
					retExt( CRYPT_ARGERROR_NUM1,
							( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
							  "Certificate request doesn't contain a DN" ) );
					}
				}
			break;
			}

		case CRYPT_SESSINFO_CACERTIFICATE:
			if( certReqType != CRYPT_CERTTYPE_CERTIFICATE )
				{
				retExt( CRYPT_ARGERROR_NUM1,
						( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
						  "Certificate object type %d isn't a certificate", 
						  certReqType ) );
				}
			break;

		default:
			retIntError();
		}
	if( certReqType == CRYPT_CERTTYPE_CERTIFICATE || \
		certReqType == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		BOOLEAN_INT isImmutable;

		/* Make sure that everything is set up ready to go.  We don't check 
		   for the object being a CA certificate when certReqType == 
		   CRYPT_CERTTYPE_CERTIFICATE because we could be dealing with an 
		   RA, which isn't necessarily a CA */
		status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE, 
								  &isImmutable, CRYPT_CERTINFO_IMMUTABLE );
		if( cryptStatusError( status ) || !isImmutable )
			{
			retExt( CRYPT_ARGERROR_NUM1,
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
					  "Certificate%s is incomplete", 
					  ( certReqType == CRYPT_CERTTYPE_REQUEST_CERT ) ? \
						" request" : "" ) );
			}
		}
	else
		{
		MESSAGE_DATA msgData = { NULL, 0 };

		/* Make sure that everything is set up ready to go.  Since 
		   revocation requests aren't signed like normal certificate objects 
		   we can't just check the immutable attribute but have to perform a 
		   dummy export for which the certificate export code will return an 
		   error status if there's a problem with the request */
		status = krnlSendMessage( cryptCert, IMESSAGE_CRT_EXPORT, &msgData, 
								  CRYPT_ICERTFORMAT_DATA );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ARGERROR_NUM1,
					( CRYPT_ARGERROR_NUM1, SESSION_ERRINFO,
					  "Revocation request is incomplete" ) );
			}
		}

	/* Add the request and increment its usage count */
	krnlSendNotifier( cryptCert, IMESSAGE_INCREFCOUNT );
	if( type == CRYPT_SESSINFO_CACERTIFICATE )
		sessionInfoPtr->iAuthInContext = cryptCert;
	else
		sessionInfoPtr->iCertRequest = cryptCert;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodCMP( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_PROTOCOL_HTTPTRANSPORT | /* Flags */
			SESSION_PROTOCOL_FIXEDSIZECREDENTIALS,
		80,							/* HTTP port */
		0,							/* Client attributes */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_PRIVKEYCACERT | \
			SESSION_NEEDS_KEYSET | \
			SESSION_NEEDS_CERTSTORE,
		2, 2, 2,					/* Version 2 */
		CRYPT_SUBPROTOCOL_NONE, CRYPT_SUBPROTOCOL_NONE,
									/* Allowed sub-protocols */
	
		/* Protocol-specific information */
		};

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Set the access method pointers */
	DATAPTR_SET( sessionInfoPtr->protocolInfo, ( void * ) &protocolInfo );
	if( isServer( sessionInfoPtr ) )
		initCMPserverProcessing( sessionInfoPtr );
	else
		initCMPclientProcessing( sessionInfoPtr );
	FNPTR_SET( sessionInfoPtr->shutdownFunction, shutdownFunction );
	FNPTR_SET( sessionInfoPtr->getAttributeFunction, getAttributeFunction );
	FNPTR_SET( sessionInfoPtr->setAttributeFunction, setAttributeFunction );

	/* Initialise CMP-specific objects */
	sessionInfoPtr->sessionCMP->userInfo = CRYPT_ERROR;
	sessionInfoPtr->sessionCMP->iExtraCerts = \
		sessionInfoPtr->sessionCMP->iSavedMacContext = CRYPT_ERROR;

	return( CRYPT_OK );
	}
#endif /* USE_CMP */
