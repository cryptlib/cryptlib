<<<<<<< HEAD
/****************************************************************************
*																			*
*								Read CMP Messages							*
*						Copyright Peter Gutmann 1999-2021					*
*																			*
****************************************************************************/

#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "cmp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "session/session.h"
  #include "session/cmp.h"
#endif /* Compiler-specific includes */

#ifdef USE_CMP

/* Additional details about the message type being read: Initial message 
   from the client, initial message from the server */

typedef enum {
	CMP_MSGINFO_NONE,				/* No additional details */
	CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER, /* First message from client */
	CMP_MSGINFO_FIRSTMESSAGE_TO_CLIENT, /* First mesage from server */
	CMP_MSGINFO_LAST				/* Last possible additional details */
	} CMP_MSGINFO_TYPE;

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Update the session's user ID and certificate ID information from the 
   newly-read protocol information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int updateUserID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						 IN_ENUM( CMP_MSGINFO ) \
							const CMP_MSGINFO_TYPE cmpMsgInfo,
						 IN_BOOL const BOOLEAN useMAC )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isEnumRangeOpt( cmpMsgInfo, CMP_MSGINFO ) );
	REQUIRES( isBooleanValue( useMAC ) );

	/* We've got a new PKI user ID, if it looks like a cryptlib encoded ID 
	   save it in encoded form, otherwise save it as is.  Again, CMP's
	   totally ambiguous protocol fields complicate things for us because 
	   although in theory we could reject any message containing a 
	   non-cryptlib user ID on the basis that it couldn't have been assigned 
	   to the user by a cryptlib server, the fact that an arbitrary client 
	   could be sending us who knows what sort of data in the user ID field, 
	   expecting the key to be identified through other means, means that we 
	   can't perform this simple check.  We can at least reject a 
	   non-cryptlib ID for the ir, which must be MAC'd */
	if( isServer( sessionInfoPtr ) && protocolInfo->userIDsize == 9 )
		{
		char encodedUserID[ CRYPT_MAX_TEXTSIZE + 8 ];
		int encodedUserIDLength;

		status = encodePKIUserValue( encodedUserID, CRYPT_MAX_TEXTSIZE,
									 &encodedUserIDLength, 
									 protocolInfo->userID, 
									 protocolInfo->userIDsize, 3 );
		if( cryptStatusError( status ) )
			return( status );
		status = updateSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
									encodedUserID, encodedUserIDLength, 
									CRYPT_MAX_TEXTSIZE, ATTR_FLAG_ENCODEDVALUE );
		}
	else
		{
		/* If we're processing an ir then that at least must have a valid 
		   cryptlib user ID */
		if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER && useMAC )
			{
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO,
					  "User ID provided by client isn't a cryptlib user "
					  "ID" ) );
			}

		/* It's not a valid cryptlib PKI user ID, save it anyway since
		   it'll be used for diagnostic/error-reporting purposes */
		status = updateSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME,
									protocolInfo->userID,
									protocolInfo->userIDsize,
									CRYPT_MAX_TEXTSIZE, ATTR_FLAG_NONE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If this is the first message to the server and we're using MAC-based
	   authentication, set up the server's MAC context based on the 
	   information supplied by the client */
#ifndef CONFIG_FUZZ
	if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER && useMAC )
		return( initServerAuthentMAC( sessionInfoPtr, protocolInfo ) );
#endif /* CONFIG_FUZZ */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int updateCertID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						 IN_ENUM( CMP_MSGINFO ) \
							const CMP_MSGINFO_TYPE cmpMsgInfo )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isEnumRangeOpt( cmpMsgInfo, CMP_MSGINFO ) );

	status = addSessionInfoS( sessionInfoPtr,
							  CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
							  protocolInfo->certID,
							  protocolInfo->certIDsize );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is the first message to the server, set up the server's 
	   public-key context for the client's key based on the information
	   supplied by the client */
	if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER )
		return( initServerAuthentSign( sessionInfoPtr, protocolInfo ) );

	return( CRYPT_OK );
	}

/* In another piece of brilliant design, CMP provides the information 
   required to set up MAC processing in reverse order, so we don't know what 
   to do with any MAC information that may be present in the header until 
   we've read the start of the message body.  To handle this we have to 
   record the position of the MAC information in the header and then go back 
   and process it once we've read the necessary additional data from the 
   message body, which is handled by the following function.
   
   The MAC information in this case is the homebrew Entrust MAC, not 
   anything normal */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int updateMacInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						  INOUT_PTR STREAM *stream,
						  IN_BOOL const BOOLEAN isRevocation )
	{
	const ATTRIBUTE_LIST *passwordPtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD );
	BYTE macKey[ 64 + 8 ];
	BOOLEAN decodedMacKey = FALSE;
	const void *macKeyPtr;
	const int streamPos = stell( stream );
	int macKeyLength, status;

	REQUIRES( isBooleanValue( isRevocation ) );
	REQUIRES( passwordPtr != NULL );
	REQUIRES( isIntegerRangeNZ( streamPos ) );

	sseek( stream, protocolInfo->macInfoPos );
	if( isRevocation && protocolInfo->altMacKeySize > 0 )
		{
		/* If it's a revocation and we're using a distinct revocation
		   password (which we've already decoded into a MAC key), use
		   that */
		macKeyPtr = protocolInfo->altMacKey;
		macKeyLength = protocolInfo->altMacKeySize;
		}
	else
		{
		/* It's a standard issue (or we're using the same password/key
		   for the issue and revocation), use that */
		if( TEST_FLAG( passwordPtr->flags, ATTR_FLAG_ENCODEDVALUE ) )
			{
			/* It's an encoded value, get the decoded form */
			macKeyPtr = macKey;
			status = decodePKIUserValue( macKey, 64, &macKeyLength, 
										 passwordPtr->value, 
										 passwordPtr->valueLength );
			ENSURES( cryptStatusOK( status ) );
			decodedMacKey = TRUE;
			}
		else
			{
			macKeyPtr = passwordPtr->value;
			macKeyLength = passwordPtr->valueLength;
			}
		}
	status = readMacInfo( stream, protocolInfo, macKeyPtr,
						  macKeyLength, SESSION_ERRINFO );
	if( decodedMacKey )
		zeroise( macKey, 64 );
	if( cryptStatusError( status ) )
		return( status );
	sseek( stream, streamPos );

	return( CRYPT_OK );
	}

/* Read and process the unauthenticated extraCerts attached to a message:

	extraCerts	[1]	EXPLICIT SEQUENCE SIZE (1..MAX) OF Certificate 

   This is required by ETSI 33.310 to kludge around various shortcomings in
   CMP, see the inline comments for details */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processExtraCerts( INOUT_PTR STREAM *stream,
							  INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
							  IN_ENUM( CMP_MESSAGE ) \
									const CMP_MESSAGE_TYPE messageType )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
	char newCertName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	int length, trustValue, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isEnumRange( messageType, CMP_MESSAGE ) );

	/* Some servers erroneously send extraCerts in messages like pkiConf
	   even though it's explicitly prohibited in 33.310 section 9.5.4.5, so 
	   we make sure that we've got an ip/cp/kup before continuing */
	if( !isServer( sessionInfoPtr ) && \
		messageType != CTAG_PB_IP && messageType != CTAG_PB_CP && \
		messageType != CTAG_PB_KUP )
		{
		DEBUG_PRINT(( "CLI: Server sent spurious extraCerts in %s message, "
					  "this may result in signature checks failing due to "
					  "the use of incorrect certificates.\n",
					  getCMPMessageName( messageType ) ) );

		/* In theory this is an error but in the interests of 
		   interoperability we just skip the extraCerts and try and 
		   continue.  Depending on what the server was trying to do we'll
		   either continue as normal or the next signature check will fail
		   due to incorrect certificates being used */
		return( CRYPT_OK );
		}

	/* Read the extraCerts wrapper */
	status = readConstructed( stream, &length, CTAG_PM_EXTRACERTS );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the certificate sequence */
	clearErrorInfo( &localErrorInfo );
	status = importCertFromStream( stream, &cmpInfo->iExtraCerts, 
								   DEFAULTUSER_OBJECT_HANDLE,
								   CRYPT_ICERTTYPE_CMP_CERTSEQUENCE, length, 
								   KEYMGMT_FLAG_NONE, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo, 
					 "Couldn't read extra certificates for %s message", 
					 getCMPMessageName( messageType ) ) );
		}

	/* Since this field is unauthenticated, we have to verify the chain that 
	   we've just read using the signature-check certificate.  If we're not 
	   using signatures for authentication (meaning we don't have a 
	   certificate present to check the chain that we've just read) we can't 
	   do anything with the extraCerts since there's no way to verify 
	   whether they're legitimate or not.  
	   
	   As an alternative to failing the exchange we could quietly delete 
	   them and continue, but it's probably better to make problems explicit 
	   rather than silently skipping them */
	if( protocolInfo->useMACreceive )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Couldn't verify unauthenticated extraCerts certificate "
				  "chain for '%s' from %s", 
				  getCertHolderName( cmpInfo->iExtraCerts, 
									 newCertName, CRYPT_MAX_TEXTSIZE ),
				  getCMPMessageName( messageType ) ) );
		}
	
	/* Now we have to figure out what we're going to do with these things.  
	   If we're the server then there's no obvious use for the certificates
	   so we just ignore them */
	if( isServer( sessionInfoPtr ) )
		return( CRYPT_OK );

	/* We're the client, at the moment the only real use seems to be when 
	   the client has been configured with nothing but a CA root certificate 
	   and the server is being run from an intermediate CA and we're not 
	   using an encrypt-only key, in which case we can't verify the 
	   signature on the returned response.  To deal with this, 33.310 
	   requires that the CA include any additional needed certificates in 
	   the response, which we try and process now.

	   Since we're performing certificate verification, we have to mark the 
	   verifying certificate as trusted if it's not already set as such 
	   otherwise the verification will fail due to an untrusted-issuer 
	   error */
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_GETATTRIBUTE, &trustValue, 
							  CRYPT_CERTINFO_TRUSTED_IMPLICIT );
	if( cryptStatusOK( status ) && trustValue == FALSE )
		{
		status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE, 
								  CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cmpInfo->iExtraCerts,
								  IMESSAGE_CRT_SIGCHECK, NULL,
								  sessionInfoPtr->iAuthInContext );
		krnlSendMessage( sessionInfoPtr->iAuthInContext, 
						 IMESSAGE_SETATTRIBUTE, &trustValue, 
						 CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		}
	if( cryptStatusError( status ) )
		{
		if( cryptArgError( status ) )
			{
			/* There's a problem with one of the parameters, convert the 
			   error status to a general invalid-information error */
			status = CRYPT_ERROR_INVALID;
			}			
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo, 
					 "Couldn't verify extraCerts certificate chain '%s' "
					 "from %s using signature check key '%s'",
					 getCertHolderName( cmpInfo->iExtraCerts, 
										newCertName, CRYPT_MAX_TEXTSIZE ),
					 getCMPMessageName( messageType ),
					 getCertHolderName( sessionInfoPtr->iAuthInContext, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	DEBUG_PRINT(( "%s: Verified extraCerts certificate chain '%s' "
				  "from %s using configured CA key '%s'.\n", 
				  isServer( sessionInfoPtr ) ? "SVR" : "CLI",
				  getCertHolderName( cmpInfo->iExtraCerts, 
									 newCertName, CRYPT_MAX_TEXTSIZE ),
				  getCMPMessageName( messageType ),
				  getCertHolderName( sessionInfoPtr->iAuthInContext, 
									 certName, CRYPT_MAX_TEXTSIZE ) ));

	/* The certificate chain in the extraCerts field has been verified, use 
	   this to process the CMP message instead of the certificate that we've 
	   been configured with */
	DEBUG_PRINT(( "%s: Switching to extraCerts certificate chain '%s' "
				  "to verify message signatures.\n", 
				  isServer( sessionInfoPtr ) ? "SVR" : "CLI",
				  getCertHolderName( cmpInfo->iExtraCerts, 
									 newCertName, CRYPT_MAX_TEXTSIZE ) ));
	protocolInfo->useAltAuthKey = TRUE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read PKIHeader Fields							*
*																			*
****************************************************************************/

/* Read the kitchen-sink field in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readGeneralInfoAttribute( INOUT_PTR STREAM *stream, 
									 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	BYTE oid[ MAX_OID_SIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Read the attribute.  Since there are only two attribute types that we 
	   use, we hardcode the read in here rather than performing a general-
	   purpose attribute read */
	readSequence( stream, NULL );
	status = readEncodedOID( stream, oid, MAX_OID_SIZE, &length, 
							 BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the cryptlib presence-check value */
	if( matchOID( oid, length, OID_CRYPTLIB_PRESENCECHECK ) )
		{
		/* The other side is running cryptlib, we can make some common-sense 
		   assumptions about its behaviour */
		protocolInfo->isCryptlib = TRUE;
		return( readSetZ( stream, NULL ) );			/* Attribute */
		}

	/* Check for the ESSCertID, which fixes CMP's broken certificate 
	   identification mechanism */
	if( matchOID( oid, length, OID_ESS_CERTID ) )
		{
		BYTE certID[ CRYPT_MAX_HASHSIZE + 8 ];
		int certIDsize, endPos;

		/* Extract the certificate hash from the ESSCertID */
		readSet( stream, NULL );					/* Attribute */
		readSequence( stream, NULL );				/* SigningCerts */
		readSequence( stream, NULL );				/* Certs */
		status = readSequence( stream, &length );	/* ESSCertID */
		if( cryptStatusError( status ) )
			return( status );
		endPos = stell( stream ) + length;
		ENSURES( isIntegerRangeMin( endPos, length ) );
		status = readOctetString( stream, certID, &certIDsize, 
								  KEYID_SIZE, KEYID_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		if( protocolInfo->certIDsize != KEYID_SIZE || \
			memcmp( certID, protocolInfo->certID, KEYID_SIZE ) )
			{
			/* The certificate used for authentication purposes has changed,
			   remember the new certID */
			memcpy( protocolInfo->certID, certID, KEYID_SIZE );
			protocolInfo->certIDsize = KEYID_SIZE;
			protocolInfo->certIDchanged = TRUE;
			}
		if( stell( stream ) < endPos )
			{
			/* Skip the issuerSerial if there's one present.  We can't 
			   really do much with it in this form without rewriting it into 
			   the standard issuerAndSerialNumber, but in any case we don't 
			   need it because we've already got the certificate ID */
			status = readUniversal( stream );
			}
		return( status );
		}

	/* It's something that we don't recognise, skip it */
	return( readUniversal( stream ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readGeneralInfo( INOUT_PTR STREAM *stream, 
							INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	int length, endPos, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Go through the various attributes looking for anything that we can
	   use */
	readConstructed( stream, NULL, CTAG_PH_GENERALINFO );
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	LOOP_MED_WHILE( stell( stream ) < endPos )
		{
		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		status = readGeneralInfoAttribute( stream, protocolInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	return( status );
	}

/* Read the user ID in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readUserID( INOUT_PTR STREAM *stream, 
					   INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	BYTE userID[ CRYPT_MAX_HASHSIZE + 8 ];
	int userIDsize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Read the PKI user ID that we'll need to handle the integrity 
	   protection on the message */
	readConstructed( stream, NULL, CTAG_PH_SENDERKID );
	status = readOctetString( stream, userID, &userIDsize, 8, 
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( userIDsize >= 8 && userIDsize <= CRYPT_MAX_HASHSIZE );

	/* If there's already been a previous transaction (which means that we 
	   have PKI user information present) and the current transaction 
	   matches what was used in the previous one, we don't have to update 
	   the user information */
	if( protocolInfo->userIDsize == userIDsize && \
		!memcmp( protocolInfo->userID, userID, userIDsize ) )
		{
		DEBUG_PRINT(( "%s: Skipped repeated userID.\n",
					  protocolInfo->isServer ? "SVR" : "CLI" ));
		DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
						protocolInfo->userID, protocolInfo->userIDsize );
		return( CRYPT_OK );
		}

	/* Record the new or changed PKI user information.  At this point we 
	   fall into another one of the many traps set by CMP: If the user ID 
	   has changed there's no obvious way to deal with this.  If we're using a 
	   MAC then presumably a different MAC key is in use but we have no idea 
	   what it is, if we're using a signature then we also have no idea what 
	   signature key the new ID correspond to.  The best that we can do is 
	   to keep going with whatever's at hand in the hope that the new user 
	   ID refers to the existing key (EJBCA at least uses the sKID of the 
	   signing certificate as the user ID, so if we send a request with a 
	   user name as the user ID we get back a response with the CA's sKID as 
	   the user ID, which means that ignoring the changed user ID works fine 
	   because the CA key is used to sign the response) */
	static_assert( CRYPT_MAX_HASHSIZE <= CRYPT_MAX_TEXTSIZE,
				   "MAX_HASHSIZE > MAX_TEXTSIZE" );
	REQUIRES( rangeCheck( userIDsize, 1, CRYPT_MAX_TEXTSIZE ) );
	memcpy( protocolInfo->userID, userID, userIDsize );
	protocolInfo->userIDsize = userIDsize;
	protocolInfo->userIDchanged = TRUE;
#if 0
	/* Delete the MAC context associated with the previous user if necessary.  
	   See the note above, this won't work because we've now deleted the MAC
	   context that we need to authenticate further outgoing messages */
	if( protocolInfo->iMacContext != CRYPT_ERROR )
		{
		krnlSendNotifier( protocolInfo->iMacContext,
						  IMESSAGE_DECREFCOUNT );
		protocolInfo->iMacContext = CRYPT_ERROR;
		protocolInfo->useMACsend = protocolInfo->useMACreceive = FALSE;
		}
#endif /* 0 */
	DEBUG_PRINT(( "%s: Read new userID.\n",
				  protocolInfo->isServer ? "SVR" : "CLI" ));
	DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
					protocolInfo->userID, protocolInfo->userIDsize );

	return( CRYPT_OK );
	}

/* Read the messageTime field in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readMessageTime( INOUT_PTR STREAM *stream, 
							INOUT_PTR ERROR_INFO *errorInfo )
	{
	const time_t systemTime = getTime( GETTIME_MINUTES );
	time_t messageTime, delta;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the message time and make sure that it's within 24 hours of the 
	   system time */
	readConstructed( stream, NULL, CTAG_PH_MESSAGETIME );
	status = readGeneralizedTime( stream, &messageTime );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid message time in PKI header" ) );
		}
	delta = ( messageTime > systemTime ) ? \
			messageTime - systemTime : systemTime - messageTime;
	if( delta > 86400 )
		{
		/* The difference between the sender and our time is more than 24 
		   hours, treat it as an error.  At this point we don't know the
		   message type yet so we can't report any information about the
		   message type in the error text */
		delta /= 60 * 60;	/* Difference in hours */
		if( delta > 24 * 3 )
			{
			/* More than three days difference, report it in days */
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Peer system time is %d days out from our system "
					  "time, can't proceed with certification operation", 
					  ( int ) ( delta / 24 ) ) );
			}
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Peer system time is %d hours out from our system "
				  "time, can't proceed with certification operation", 
				  ( int ) delta ) );
		}

	return( CRYPT_OK );
	}

/* Read the transaction ID (effectively the nonce) in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readTransactionID( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
							  IN_ENUM( CMP_MSGINFO ) \
								const CMP_MSGINFO_TYPE cmpMsgInfo )
	{
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isEnumRangeOpt( cmpMsgInfo, CMP_MSGINFO ) );

	/* If this is the first message and we're the server, record the 
	   transaction ID for later */
	if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER )
		{
		status = readOctetString( stream, protocolInfo->transID,
								  &protocolInfo->transIDsize,
								  4, CRYPT_MAX_HASHSIZE );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "%s: Read initial transID.\n",
					  protocolInfo->isServer ? "SVR" : "CLI" ));
		DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
						protocolInfo->transID, protocolInfo->transIDsize );
		return( CRYPT_OK );
		}

	/* Make sure that the transaction ID for this message matches the 
	   recorded value (the bad signature error code is the best that we can 
	   provide here) */
	status = readOctetString( stream, buffer, &length, 4, 
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );
	FUZZ_SKIP_REMAINDER();
	ANALYSER_HINT( length >= 4 && length <= CRYPT_MAX_HASHSIZE );
	DEBUG_PRINT(( "%s: Read transID.\n",
				  protocolInfo->isServer ? "SVR" : "CLI" ));
	DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
					protocolInfo->transID, protocolInfo->transIDsize );
	if( protocolInfo->transIDsize != length || \
		memcmp( protocolInfo->transID, buffer, length ) )
		return( CRYPT_ERROR_SIGNATURE );

	return( CRYPT_OK );
	}

/* Read the integrity protection algorithm information, either for a MAC or
   signature, in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readProtectionAlgo( INOUT_PTR STREAM *stream, 
							   INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	ALGOID_PARAMS algoIDparams;
	int streamPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Read the wrapper.  If there's a problem we don't exit immediately 
	   since an error status from the readAlgoIDex() that follows is 
	   interpreted to indicate the presence of the weird Entrust MAC rather 
	   than a real error */
	status = readConstructed( stream, NULL, CTAG_PH_PROTECTIONALGO );
	if( cryptStatusError( status ) )
		return( status );
	streamPos = stell( stream );
	REQUIRES( isIntegerRangeNZ( streamPos ) );
	status = readAlgoIDex( stream, &cryptAlgo, &algoIDparams,
						   ALGOID_CLASS_PKCSIG );
	if( cryptStatusOK( status ) )
		{
		/* Make sure that it's a recognised signature algorithm to avoid
		   false positives if the other side sends some bizarre algorithm 
		   ID */
		if( !isSigAlgo( cryptAlgo ) )
			return( CRYPT_ERROR_NOTAVAIL );

		/* It's a recognised signature algorithm, use the CA certificate to 
		   verify it rather than the MAC */
		protocolInfo->useMACreceive = FALSE;
		protocolInfo->hashAlgo = algoIDparams.hashAlgo;
		protocolInfo->hashParam = algoIDparams.hashParam;

		return( CRYPT_OK );
		}
	ENSURES( cryptStatusError( status ) );

	/* If we get an error other than one due to an unknown OID, exit */
	if( status != CRYPT_ERROR_NOTAVAIL )
		return( status );

	/* It's nothing normal, it must be the Entrust MAC algorithm 
	   information, make sure that we at least find the OID for this and
	   remember where the information starts so that we can process it 
	   later */
	sClearError( stream );
	sseek( stream, streamPos );
	protocolInfo->useMACreceive = TRUE;
	protocolInfo->macInfoPos = streamPos;
	readSequence( stream, NULL );
	status = readFixedOID( stream, OID_ENTRUST_MAC,
						   sizeofOID( OID_ENTRUST_MAC ) );
	if( cryptStatusError( status ) )
		{
		/* It's not the Entrust algorithm either, we don't know what to do
		   with it */
		return( CRYPT_ERROR_BADDATA );
		}

	/* Skip the AlgorithmID parameters.  We use the Opt form of 
	   readUniversal() since the parameters are redundant for anything but
	   the first message so are usually sent as a zero-length object*/
	return( readUniversalOpt( stream ) );
	}

/****************************************************************************
*																			*
*								Read a PKI Header							*
*																			*
****************************************************************************/

/* Read a PKI header and make sure that it matches the header that we sent
   (for EE or non-initial CA/RA messages) or set up the EE information in
   response to an initial message (for an initial CA/RA message).  We ignore
   all of the redundant fields in the header that don't directly affect the
   protocol, based on the results of CMP interop testing this appears to be
   standard practice among implementers.  This also helps get around 
   problems with implementations that get the fields wrong, since most of 
   the fields aren't useful it doesn't affect the processing while making 
   the code more tolerant of implementation errors:

	header				SEQUENCE {
		version			INTEGER (2),
		senderDN	[4]	EXPLICIT DirectoryName,		-- Copied if non-clib
		dummy		[4]	EXPLICIT DirectoryName,		-- Ignored
		messageTime	[0] EXPLICIT GeneralisedTime OPT,-- Checked against local clock
		protAlgo	[1]	EXPLICIT AlgorithmIdentifier,
		protKeyID	[2] EXPLICIT OCTET STRING,		-- Copied if changed
		dummy		[3] EXPLICIT OCTET STRING OPT,	-- Ignored
		transID		[4] EXPLICIT OCTET STRING,
		nonce		[5] EXPLICIT OCTET STRING OPT,	-- Copied if non-clib
		dummy		[6] EXPLICIT OCTET STRING OPT,	-- Ignored
		dummy		[7] EXPLICIT SEQUENCE OF UTF8String OPT,-- Ignored
		generalInfo	[8] EXPLICIT SEQUENCE OF Info OPT -- cryptlib-specific info
		} 

   Note the massive quantity of random tags sprayed all over the place, the 
   correct tagging should be: 

	header				SEQUENCE {
		version			INTEGER (2),
		senderDN		DirectoryName,				-- Copied if non-clib
		dummy			DirectoryName,				-- Ignored
		messageTime		GeneralisedTime OPTIONAL,	-- Checked against local clock
		protAlgo		AlgorithmIdentifier,
		protKeyID		OCTET STRING,				-- Copied if changed
		dummy		[0] OCTET STRING OPTIONAL,		-- Ignored
		transID			OCTET STRING,
		nonce		[1] OCTET STRING OPTIONAL,		-- Copied if non-clib
		dummy		[2] OCTET STRING OPTIONAL,		-- Ignored
		dummy			SEQUENCE OF UTF8String OPTIONAL,-- Ignored
		generalInfo	[3] SEQUENCE OF Info OPTIONAL	-- cryptlib-specific info
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readPkiHeader( INOUT_PTR STREAM *stream, 
						  INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						  INOUT_PTR ERROR_INFO *errorInfo,
						  IN_ENUM_OPT( CMP_MSGINFO ) \
								const CMP_MSGINFO_TYPE cmpMsgInfo )
	{
	int tag = CRYPT_ERROR, length, endPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isEnumRangeOpt( cmpMsgInfo, CMP_MSGINFO ) );

	/* Clear per-message state information */
	protocolInfo->userIDchanged = protocolInfo->certIDchanged = \
		protocolInfo->useMACreceive = FALSE;
	protocolInfo->macInfoPos = 0;
	protocolInfo->senderDNPtr = NULL;
	protocolInfo->senderDNlength = 0;
	protocolInfo->headerRead = protocolInfo->noIntegrity = FALSE;

	/* Read the wrapper and skip the static information, which matches what 
	   we sent and is protected by the MAC so there's little point in 
	   looking at it */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	readShortInteger( stream, NULL );		/* Version */
	if( !protocolInfo->isCryptlib )
		{
		/* The ID of the key used for integrity protection (or in general
		   the identity of the sender) can be specified either as the sender
		   DN or the senderKID or both, or in some cases even indirectly via
		   the transaction ID.  With no real guidance as to which one to 
		   use, implementors are using any of these options to identify the 
		   key.  Since we need to check that the integrity-protection key 
		   that we're using is correct so that we can report a more 
		   appropriate error than bad signature or bad data, we need to 
		   remember the sender DN for later in case this is the only form of 
		   key identification provided.  Unfortunately since the sender DN 
		   can't uniquely identify a certificate, if this is the only 
		   identifier that we're given then the caller can still get a bad 
		   signature error, yet another one of CMPs many wonderful features.
		   
		   Note the use of readUniversalOpt() rather than readUniversal()
		   since the recipient DN typically serves no purpose and so the 
		   client will send a zero-length value */
		status = readConstructed( stream, &protocolInfo->senderDNlength, 4 );
		if( cryptStatusOK( status ) && protocolInfo->senderDNlength > 0 )
			{
			status = sMemGetDataBlock( stream, &protocolInfo->senderDNPtr, 
									   protocolInfo->senderDNlength );
			if( cryptStatusOK( status ) )
				status = readUniversalOpt( stream );
			}
		}
	else
		{
		/* cryptlib includes a proper certID so the whole signer
		   identification mess is avoided and we can ignore the sender DN.
		   Note the use of readUniversalOpt() rather than readUniversal()
		   since the sender typically doesn't know their DN and will send
		   a zero-length value */
		status = readUniversalOpt( stream );	/* Sender DN */
		}
	if( cryptStatusOK( status ) )
		status = readUniversalOpt( stream );	/* Recipient DN */
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid DN information in PKI header" ) );
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_PH_MESSAGETIME ) )
		{
		/* Read the message time and make sure that it's within range of our 
		   time */
		status = readMessageTime( stream, errorInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( !checkStatusPeekTag( stream, status, tag ) || \
		tag != MAKE_CTAG( CTAG_PH_PROTECTIONALGO ) )
		{
		/* The message was sent without integrity protection, report it as
		   a signature error rather than the generic bad data error that
		   we'd get from the following read unless this is the first message
		   from the server, in which case it could be an unprotected error
		   response to our mesage where the server can't figure out how to 
		   sign the response */
		if( cmpMsgInfo != CMP_MSGINFO_FIRSTMESSAGE_TO_CLIENT )
			{
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, errorInfo, 
					  "Message was sent without integrity protection" ) );
			}
		protocolInfo->noIntegrity = TRUE;
		}
	if( !protocolInfo->noIntegrity )
		{
		status = readProtectionAlgo( stream, protocolInfo );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo, 
					  "Invalid integrity protection information in PKI "
					  "header" ) );
			}
		if( checkStatusPeekTag( stream, status, tag ) && \
			tag == MAKE_CTAG( CTAG_PH_SENDERKID ) )
			{							/* Sender protection keyID */
			status = readUserID( stream, protocolInfo );
			if( cryptStatusError( status ) )
				{
				retExt( status,
						( status, errorInfo, 
						  "Invalid PKI user ID in PKI header" ) );
				}
			}
		else
			{
			/* If we're the server, the client must provide a PKI user ID in the
			   first message unless we got one in an earlier transaction */
			if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER && \
				protocolInfo->userIDsize <= 0 )
				{
				retExt( CRYPT_ERROR_BADDATA, 
						( CRYPT_ERROR_BADDATA, errorInfo, 
						  "Missing PKI user ID in PKI header" ) );
				}
			}
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_PH_RECIPKID ) )
		{
		/* Recipient protection keyID */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Record the transaction ID (which is effectively the nonce) or make 
	   sure that it matches the one that we sent.  There's no real need to 
	   do an explicit duplicate check since a replay attempt will be 
	   rejected as a duplicate by the certificate store and the locking 
	   performed at that level makes it a much better place to catch 
	   duplicates, but we do it anyway because it doesn't cost anything and
	   we can catch at least some problems a bit earlier */
	status = readConstructed( stream, NULL, CTAG_PH_TRANSACTIONID );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Missing transaction ID in PKI header" ) );
		}
	status = readTransactionID( stream, protocolInfo, cmpMsgInfo );
	if( cryptStatusError( status ) )
		{
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADRECIPIENTNONCE;
		retExt( status, 
				( status, errorInfo, 
				  ( status == CRYPT_ERROR_SIGNATURE ) ? \
				  "Returned message transaction ID doesn't match our "
						"transaction ID" : \
				  "Invalid transaction ID in PKI header" ) );
		}

	/* Read the sender nonce, which becomes the new recipient nonce, and skip
	   the recipient nonce if there's one present.  These values may be
	   absent, either because the other side doesn't implement them or
	   because they're not available, for example because it's sending a
	   response to an error that occurred before it could read the nonce from
	   a request.  In any case we don't bother checking the nonce values
	   since the transaction ID serves the same purpose */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_PH_SENDERNONCE ) )
		{
		readConstructed( stream, NULL, CTAG_PH_SENDERNONCE );
		status = readOctetString( stream, protocolInfo->recipNonce,
								  &protocolInfo->recipNonceSize,
								  4, CRYPT_MAX_HASHSIZE );
		if( cryptStatusError( status ) )
			{
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADSENDERNONCE;
			retExt( status,
					( status, errorInfo, 
					  "Invalid sender nonce in PKI header" ) );
			}
		}
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_PH_RECIPNONCE ) )
		{
		readConstructed( stream, NULL, CTAG_PH_RECIPNONCE );
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			{
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADRECIPIENTNONCE;
			retExt( status,
					( status, errorInfo, 
					  "Invalid recipient nonce in PKI header" ) );
			}
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* Remember that we've successfully read enough of the header 
	   information to generate a response */
	protocolInfo->headerRead = TRUE;

	/* Skip any further junk and process the general information if there is 
	   any */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_PH_FREETEXT ) )
		{
		/* Skip junk */
		status = readUniversal( stream );
		}
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_PH_GENERALINFO ) )
		{
		status = readGeneralInfo( stream, protocolInfo );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo, 
					  "Invalid generalInfo information in PKI header" ) );
			}
		}

	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}		/* checkStatusLimitsPeekTag() can return tag as status */

/****************************************************************************
*																			*
*							Read a PKI Message								*
*																			*
****************************************************************************/

/* Read a PKI message:

	PkiMessage ::= SEQUENCE {
		header			PKIHeader,
		body			CHOICE { [0]... [24]... },
		protection	[0]	EXPLICIT BIT STRING,
		extraCerts	[1] EXPLICIT SEQUENCE OF Certificate OPTIONAL
		}

   Note that readPkiDatagram() has already performed an initial valid-ASN.1 
   check before we get here.
   
   The extraCerts field is described in the spec as a dumping-ground for any 
   certs that the CA may wish to include there, since there's no indicator 
   of what these could be or what we should do with them, and even more 
   importantly the field is unauthenticated so we can't trust any of these 
   extra certs, we ignore it unless we've been explicitly told to process it 
   as per the 3GPP profile of CMP */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readPkiMessage( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
					IN_ENUM_OPT( CMP_MESSAGE ) CMP_MESSAGE_TYPE messageType )
	{
#ifdef USE_ERRMSGS
	ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;
#endif /* USE_ERRMSGS */
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	READMESSAGE_FUNCTION readMessageFunction;
	STREAM stream;
	const CMP_MSGINFO_TYPE cmpMsgInfo = \
					( messageType == CTAG_PB_READ_ANY ) ? \
					  CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER : 
					( messageType == CTAG_PB_IP || \
					  messageType == CTAG_PB_CP || \
					  messageType == CTAG_PB_KUP ) ? \
					  CMP_MSGINFO_FIRSTMESSAGE_TO_CLIENT : CMP_MSGINFO_NONE;
	void *integrityInfoPtr DUMMY_INIT_PTR;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int protPartStart DUMMY_INIT, protPartSize, bodyStart DUMMY_INIT;
	int length, endPos DUMMY_INIT, integrityInfoLength DUMMY_INIT, tag;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionCMP( sessionInfoPtr ) );
	REQUIRES( sanityCheckCMPProtocolInfo( protocolInfo ) );
	REQUIRES( ( messageType >= CTAG_PB_IR && \
				messageType < CTAG_PB_LAST ) || \
			  ( messageType == CTAG_PB_READ_ANY ) );
			  /* CTAG_PB_IR == 0 so this is the same as _NONE */

	DEBUG_PRINT(( "%s: Reading message type %d.\n",
				  isServer( sessionInfoPtr ) ? "SVR" : "CLI", 
				  messageType ));
				  /* We can't use getCMPMessageName() at this point since
				     we haven't read the message tag yet and messageType is
					 usually a generic code indicating one of a range of
					 messages */

	/* Strip off the header and PKIStatus wrapper */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	status = readSequence( &stream, &length );		/* Outer wrapper */
	if( cryptStatusOK( status ) )
		{
		protPartStart = stell( &stream );
		REQUIRES( isIntegerRangeNZ( protPartStart ) );
		endPos = protPartStart + length;
		REQUIRES( isIntegerRangeMin( endPos, length ) );
		status = readPkiHeader( &stream, protocolInfo, SESSION_ERRINFO,
								cmpMsgInfo );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	ENSURES( protocolInfo->transIDsize > 0 && \
			 protocolInfo->transIDsize <= CRYPT_MAX_HASHSIZE );
	CFI_CHECK_UPDATE( "readPkiHeader" );

	/* Set up session state information based on the header that we've just 
	   read */
	if( protocolInfo->isCryptlib )
		SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISCRYPTLIB );

	/* In order to fix CMP's inability to properly identify keys via 
	   certificates, we use the certID field in the generalInfo.  If there's
	   no PKI user ID present but no certID either then we can't identify 
	   the key that's needed in order to continue.  This also retroactively 
	   invalidates the headerRead flag, since we don't know which key to use
	   to authenticate our response.

	   In theory we shouldn't ever get into this state because we require 
	   a PKI user ID for the client's initial message and the server will
	   always send a certID for its signing certificate, but due to the
	   confusing combination of values that can affect the protocol state
	   (see the start of writePkiHeader() in cmp_wr.c for an example) we
	   do the following as a safety check to catch potential problems 
	   early.
	   
	   This also leads to a special-case exception, if we're the client then
	   the server may identify its signing key purely through the 
	   dysfunctional sender DN mechanism (see the comment in 
	   readPkiHeader()) so we allow this option as well.  The DN can't 
	   actually tell us whether it's the correct key or not (see the
	   comment in checkMessageSignature()) but there's not much else that
	   we can do */
	if( protocolInfo->useMACreceive )
		{
		/* There is one special-case situation in which we can have no user 
		   ID present and that's when we're doing a PnP PKI transaction with 
		   an initial PKIBoot that creates the required MAC context followed 
		   by an ir that doesn't need to send any ID information since it's 
		   reusing the MAC context that was created by the PKIBoot */
		if( protocolInfo->userIDsize <= 0 && \
			!( protocolInfo->isCryptlib && \
			   protocolInfo->iMacContext != CRYPT_ERROR ) )
			{
			sMemDisconnect( &stream );
			protocolInfo->headerRead = FALSE;
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Missing PKI user ID for MAC authentication of PKI "
					  "messages" ) );
			}
		}
	else
		{
		/* As with the case for MAC contexts, there's a special-case 
		   situation in which there's no certID present and that's during a 
		   PnP PKI transaction preceded by a PKIBoot that communicates the 
		   CA's certificate, where the PKIBoot creates the required 
		   sig-check context as part of the initialisation process.  In
		   addition we have to allow for DN-only identification from 
		   servers, see the comment above for details */
		if( protocolInfo->certIDsize <= 0 && \
			( !isServer( sessionInfoPtr ) && 
			  protocolInfo->senderDNlength <= 0 ) && \
			!( protocolInfo->isCryptlib && \
			   sessionInfoPtr->iAuthInContext != CRYPT_ERROR ) )
			{
			sMemDisconnect( &stream );
			protocolInfo->headerRead = FALSE;
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Missing certificate ID for signature authentication "
					  "of PKI messages" ) );
			}
		}

	/* If this is the first message from the client and we've been sent a 
	   new user ID or certificate ID (via the ESSCertID in the header's
	   kitchen-sink field, used to identify the signing certificate when
	   signature-based authentication is used), process the user/
	   authentication information */
	if( protocolInfo->userIDchanged )
		{
		status = updateUserID( sessionInfoPtr, protocolInfo, cmpMsgInfo, 
							   protocolInfo->useMACreceive );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	if( protocolInfo->certIDchanged )
		{
		status = updateCertID( sessionInfoPtr, protocolInfo, cmpMsgInfo );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "updateUserID" );

	/* Determine the message body type.  An error response can occur at any
	   point in an exchange so we process this immediately.  We don't do an
	   integrity verification for this one since it's not certain what we
	   should report if the check fails (what if the error response is to
	   report that no key is available to authenticate the user, for 
	   example?), and an unauthenticated error message is better than an 
	   authenticated paketewhainau */
	status = tag = peekTag( &stream );
	if( cryptStatusError( status ) )
		return( status );
	tag = EXTRACT_CTAG( tag );
	if( tag == CTAG_PB_ERROR )
		{
		readMessageFunction = getMessageReadFunction( CTAG_PB_ERROR );
		ENSURES( readMessageFunction != NULL );
		readConstructed( &stream, NULL, CTAG_PB_ERROR );
		status = readSequence( &stream, &length );
		if( cryptStatusOK( status ) )
			{
			status = readMessageFunction( &stream, sessionInfoPtr, 
										  protocolInfo, CTAG_PB_ERROR, 
										  length );
			}
		sMemDisconnect( &stream );

		/* Reading an error response always returns an error status since 
		   what we're reading is a report of an error, so we perform the CFI
		   check even in the presence of an error status */
		ENSURES( cryptStatusError( status ) );

		ENSURES( CFI_CHECK_SEQUENCE_2( "readPkiHeader", "updateUserID" ) );

		return( status );
		}
	if( protocolInfo->noIntegrity )
		{
		/* We may have received a response without integrity protection 
		   which can occur in some cases for error responses, see the 
		   comment in readPkiHeader() for details, however since what we've 
		   got if we reach this point isn't an error response we can't 
		   continue */
		sMemDisconnect( &stream );
		if( tag >= CMP_MESSAGE_NONE && tag <= CMP_MESSAGE_LAST_STANDARD )
			{
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, errorInfo, 
					  "%s message was sent without integrity protection",
					  getCMPMessageName( tag ) ) );
			}
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, errorInfo, 
				  "Message type %d was sent without integrity protection",
				  tag ) );
		}
	CFI_CHECK_UPDATE( "readError" );

	/* If this is an initial message to the server then we don't know what 
	   to expect yet so we set the type to whatever we find, as long as it's 
	   a valid message to send to a CA */
	if( messageType == CTAG_PB_READ_ANY )
		{
		if( tag == CTAG_PB_IR || tag == CTAG_PB_CR || \
			tag == CTAG_PB_P10CR || tag == CTAG_PB_KUR || \
			tag == CTAG_PB_RR || tag == CTAG_PB_GENM )
			{
			protocolInfo->operation = messageType = tag;
			}
		else
			{
			sMemDisconnect( &stream );
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADREQUEST;
			if( tag >= CMP_MESSAGE_NONE && \
				tag <= CMP_MESSAGE_LAST_STANDARD )
				{
				/* It's a known message type, report its name as well as its 
				   tag */
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Client sent %s message as initial message", 
						  getCMPMessageName( tag ) ) );
				}
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Client sent message type %d as initial message", 
					  tag ) );
			}
		}
	else
		{
		/* Make sure that this is what we're after */
		if( tag != messageType )
			{
			sMemDisconnect( &stream );
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADREQUEST;
			if( tag >= CMP_MESSAGE_NONE && \
				tag <= CMP_MESSAGE_LAST_STANDARD )
				{
				/* It's a known message type, report its name as well as its 
				   tag */
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid message type %s, expected %s", 
						  getCMPMessageName( tag ),
						  getCMPMessageName( messageType ) ) );
				}
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid message type %d, expected %s (%d)", tag,
					  getCMPMessageName( messageType ), messageType ) );
			}
		}
	DEBUG_PRINT(( "%s: Message is %s.\n",
				  isServer( sessionInfoPtr ) ? "SVR" : "CLI", 
				  getCMPMessageName( messageType ) ));

	/* If we're using a MAC for authentication, we can finally set up the
	   MAC information using the appropriate password.  We couldn't do this 
	   when we read the header because the order of the information used to 
	   set this up is backwards, so we have to go back and re-process it 
	   now */
#ifndef CONFIG_FUZZ
	if( protocolInfo->useMACreceive )
		{
		status = updateMacInfo( sessionInfoPtr, protocolInfo, &stream,
								( messageType == CTAG_PB_RR ) ? TRUE : FALSE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
#endif /* CONFIG_FUZZ */
	CFI_CHECK_UPDATE( "updateMacInfo" );

	/* Remember where the message body starts and skip it (it'll be 
	   processed after we verify its integrity) */
	status = readConstructed( &stream, &length, messageType );
	if( cryptStatusOK( status ) && !isIntegerRangeNZ( length ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK ( status ) )
		{
		bodyStart = stell( &stream );
		REQUIRES( isIntegerRangeNZ( bodyStart ) );
		status = sSkip( &stream, length, SSKIP_MAX );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADDATAFORMAT;
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid message body start for %s message",
				  getCMPMessageName( tag ) ) );
		}

	/* Read the start of the message integrity information */
	status = calculateStreamObjectLength( &stream, protPartStart,
										  &protPartSize );
	if( cryptStatusOK( status ) )
		{
		status = readConstructed( &stream, &integrityInfoLength,
								  CTAG_PM_PROTECTION );
		}
	if( cryptStatusOK( status ) && protocolInfo->useMACreceive )
		{
		/* If it's a MAC then we want the raw MAC value without any 
		   surrounding encapsulation */
		status = readBitStringHole( &stream, &integrityInfoLength, 
									MIN_HASHSIZE, DEFAULT_TAG );
		if( cryptStatusOK( status ) && \
			( integrityInfoLength < MIN_HASHSIZE || \
			  integrityInfoLength > CRYPT_MAX_HASHSIZE ) )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusOK( status ) )
		{
		status = sMemGetDataBlock( &stream, &integrityInfoPtr, 
								   integrityInfoLength );
		}
	if( cryptStatusOK( status ) )
		{
		status = sSkip( &stream, integrityInfoLength, MAX_INTLENGTH_SHORT );
		}
	if( cryptStatusError( status ) )
		{
		/* If the integrity protection is missing report it as a wrong-
		   integrity-information problem, the closest that we can get to the 
		   real error */
		sMemDisconnect( &stream );
		protocolInfo->pkiFailInfo = CMPFAILINFO_WRONGINTEGRITY;
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, errorInfo, 
				  "%s data for %s message is missing or truncated", 
				  protocolInfo->useMACreceive ? "MAC" : "Signature",
				  getCMPMessageName( tag ) ) );
		}
	if( tag == CTAG_PB_IR && !protocolInfo->useMACreceive )
		{
		/* An ir has to be MAC'd, in theory this doesn't really matter but
		   the spec requires that we only allow a MAC.  If it's not MAC'd it
		   has to be a cr, which is exactly the same only different */
		sMemDisconnect( &stream );
		protocolInfo->pkiFailInfo = CMPFAILINFO_WRONGINTEGRITY;
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, errorInfo, 
				  "Received signed ir message, should be MAC'd" ) );
		}
	ANALYSER_HINT( integrityInfoPtr != NULL );
	CFI_CHECK_UPDATE( "readIntegrityInfo" );

	/* There may be an (unauthenticated) extraCerts field present after the 
	   main message, try and process it as required */ 
	if( stell( &stream ) < endPos )
		{
		/* If we're running in compliance with ETSI 33.310, process the
		   extra certificates */
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, CMP_PFLAG_3GPP ) )
			{
			status = processExtraCerts( &stream, sessionInfoPtr, 
										protocolInfo, tag );
			if( cryptStatusError( status ) )
				{
				protocolInfo->pkiFailInfo = \
						( status == CRYPT_ERROR_SIGNATURE || \
						  status == CRYPT_ERROR_INVALID ) ? \
						  CMPFAILINFO_BADMESSAGECHECK : \
						  CMPFAILINFO_BADDATAFORMAT;
				}
			}
		else
			{
			int certSize;

			/* We have no idea what to do with these things and in any case
			   they're unauthenticated, skip them */
			readConstructed( &stream, NULL, CTAG_PM_EXTRACERTS );
			status = readSequence( &stream, &certSize );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( &stream );
				protocolInfo->pkiFailInfo = CMPFAILINFO_BADDATAFORMAT;
				retExt( status,
						( status, SESSION_ERRINFO, 
						   "Invalid extraCerts field for %s",
						   getCMPMessageName( tag ) ) );
				}
			DEBUG_PRINT(( "%s: Skipping unauthenticated extraCerts field "
						  "length %d for %s.\n", getCMPMessageName( tag ), 
						  isServer( sessionInfoPtr ) ? "SVR" : "CLI", 
						  certSize, getCMPMessageName( tag ) ));
			status = sSkip( &stream, certSize, MAX_INTLENGTH_SHORT );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADDATAFORMAT;
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "extraCerts" );

	/* Verify the message integrity.  We convert any error that we encounter 
	   during this check to a CRYPT_ERROR_SIGNATURE, this is somewhat 
	   overreaching since it could have been something like a formatting 
	   error but overall the problem is in the signature-check so we make 
	   this explicit rather than returning a somewhat vague underflow/
	   overflow/bad-data/whatever */
#ifndef CONFIG_FUZZ
	if( protocolInfo->useMACreceive )
		{
		status = checkMessageMAC( protocolInfo, 
						sessionInfoPtr->receiveBuffer + protPartStart,
						protPartSize, integrityInfoPtr, integrityInfoLength );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADMESSAGECHECK;
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					  "Bad message MAC for %s",
					  getCMPMessageName( tag ) ) );
			}
		}
	else
		{
		status = checkMessageSignature( protocolInfo,
						sessionInfoPtr->receiveBuffer + protPartStart,
						protPartSize, integrityInfoPtr, integrityInfoLength, 
						protocolInfo->useAltAuthKey ? \
							cmpInfo->iExtraCerts : \
							sessionInfoPtr->iAuthInContext );
		if( cryptStatusError( status ) )
			{
#ifdef USE_ERRMSGS
			char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */

			sMemDisconnect( &stream );
			if( status == CRYPT_ERROR_WRONGKEY )
				{
				/* Provide a more specific error message for the wrong-key 
				   error.  CMPFAILINFO_BADCERTID, "no certificate could be 
				   found matching the provided criteria", is the least 
				   inappropriate failure code */
				protocolInfo->pkiFailInfo = CMPFAILINFO_BADCERTID;
				retExt( CRYPT_ERROR_WRONGKEY,
						( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						  "Message signature key for %s doesn't match "
						  "certificate key from '%s', signature can't be "
						  "checked", getCMPMessageName( tag ), 
						  getCertHolderName( protocolInfo->useAltAuthKey ? \
												cmpInfo->iExtraCerts : \
												sessionInfoPtr->iAuthInContext,
											 certName, 
											 CRYPT_MAX_TEXTSIZE ) ) );
				}
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADMESSAGECHECK;
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					   "Couldn't verify message signature for %s message "
					   "using certificate from '%s'",
					   getCMPMessageName( tag ), 
					   getCertHolderName( protocolInfo->useAltAuthKey ? \
											cmpInfo->iExtraCerts : \
											sessionInfoPtr->iAuthInContext,
										  certName, CRYPT_MAX_TEXTSIZE ) ) );
			}
		}
#endif /* CONFIG_FUZZ */
	CFI_CHECK_UPDATE( "checkIntegrityInfo" );

	/* We've performed the integrity check, go back to the message body so 
	   that we can process it */
	sseek( &stream, bodyStart );

	/* In the usual CMP tradition there's a nonstandard way used to encode
	   one of the message types, which we have to handle specially here */
	if( messageType == CTAG_PB_PKICONF )
		{
		status = readNull( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		ENSURES( CFI_CHECK_SEQUENCE_7( "readPkiHeader", "updateUserID", 
									   "readError", "updateMacInfo", 
									   "readIntegrityInfo", "extraCerts",
									   "checkIntegrityInfo" ) );

		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "pkiConf" );

	/* Read the message body wrapper */
	status = readSequence( &stream, &length );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Process the message body */
	readMessageFunction = getMessageReadFunction( messageType );
	if( readMessageFunction == NULL )
		{
		DEBUG_DIAG(( "No message-read function available for %s message", 
					 getCMPMessageName( tag ) ));
		assert( DEBUG_WARN );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Unexpected %s message can't be processed", 
				  getCMPMessageName( tag ) ) );
		}
	status = readMessageFunction( &stream, sessionInfoPtr, protocolInfo,
								  messageType, length );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readMessageFunction" );

	ENSURES( CFI_CHECK_SEQUENCE_9( "readPkiHeader", "updateUserID", 
								   "readError", "updateMacInfo", 
								   "readIntegrityInfo", "extraCerts",
								   "checkIntegrityInfo", "pkiConf", 
								   "readMessageFunction" ) );

	return( CRYPT_OK );
	}
#endif /* USE_CMP */
=======
/****************************************************************************
*																			*
*								Read CMP Messages							*
*						Copyright Peter Gutmann 1999-2021					*
*																			*
****************************************************************************/

#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "cmp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "session/session.h"
  #include "session/cmp.h"
#endif /* Compiler-specific includes */

#ifdef USE_CMP

/* Additional details about the message type being read: Initial message 
   from the client, initial message from the server */

typedef enum {
	CMP_MSGINFO_NONE,				/* No additional details */
	CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER, /* First message from client */
	CMP_MSGINFO_FIRSTMESSAGE_TO_CLIENT, /* First mesage from server */
	CMP_MSGINFO_LAST				/* Last possible additional details */
	} CMP_MSGINFO_TYPE;

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Update the session's user ID and certificate ID information from the 
   newly-read protocol information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int updateUserID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						 IN_ENUM( CMP_MSGINFO ) \
							const CMP_MSGINFO_TYPE cmpMsgInfo,
						 IN_BOOL const BOOLEAN useMAC )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isEnumRangeOpt( cmpMsgInfo, CMP_MSGINFO ) );
	REQUIRES( isBooleanValue( useMAC ) );

	/* We've got a new PKI user ID, if it looks like a cryptlib encoded ID 
	   save it in encoded form, otherwise save it as is.  Again, CMP's
	   totally ambiguous protocol fields complicate things for us because 
	   although in theory we could reject any message containing a 
	   non-cryptlib user ID on the basis that it couldn't have been assigned 
	   to the user by a cryptlib server, the fact that an arbitrary client 
	   could be sending us who knows what sort of data in the user ID field, 
	   expecting the key to be identified through other means, means that we 
	   can't perform this simple check.  We can at least reject a 
	   non-cryptlib ID for the ir, which must be MAC'd */
	if( isServer( sessionInfoPtr ) && protocolInfo->userIDsize == 9 )
		{
		char encodedUserID[ CRYPT_MAX_TEXTSIZE + 8 ];
		int encodedUserIDLength;

		status = encodePKIUserValue( encodedUserID, CRYPT_MAX_TEXTSIZE,
									 &encodedUserIDLength, 
									 protocolInfo->userID, 
									 protocolInfo->userIDsize, 3 );
		if( cryptStatusError( status ) )
			return( status );
		status = updateSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
									encodedUserID, encodedUserIDLength, 
									CRYPT_MAX_TEXTSIZE, ATTR_FLAG_ENCODEDVALUE );
		}
	else
		{
		/* If we're processing an ir then that at least must have a valid 
		   cryptlib user ID */
		if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER && useMAC )
			{
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO,
					  "User ID provided by client isn't a cryptlib user "
					  "ID" ) );
			}

		/* It's not a valid cryptlib PKI user ID, save it anyway since
		   it'll be used for diagnostic/error-reporting purposes */
		status = updateSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME,
									protocolInfo->userID,
									protocolInfo->userIDsize,
									CRYPT_MAX_TEXTSIZE, ATTR_FLAG_NONE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If this is the first message to the server and we're using MAC-based
	   authentication, set up the server's MAC context based on the 
	   information supplied by the client */
#ifndef CONFIG_FUZZ
	if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER && useMAC )
		return( initServerAuthentMAC( sessionInfoPtr, protocolInfo ) );
#endif /* CONFIG_FUZZ */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int updateCertID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						 IN_ENUM( CMP_MSGINFO ) \
							const CMP_MSGINFO_TYPE cmpMsgInfo )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isEnumRangeOpt( cmpMsgInfo, CMP_MSGINFO ) );

	status = addSessionInfoS( sessionInfoPtr,
							  CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
							  protocolInfo->certID,
							  protocolInfo->certIDsize );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is the first message to the server, set up the server's 
	   public-key context for the client's key based on the information
	   supplied by the client */
	if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER )
		return( initServerAuthentSign( sessionInfoPtr, protocolInfo ) );

	return( CRYPT_OK );
	}

/* In another piece of brilliant design, CMP provides the information 
   required to set up MAC processing in reverse order, so we don't know what 
   to do with any MAC information that may be present in the header until 
   we've read the start of the message body.  To handle this we have to 
   record the position of the MAC information in the header and then go back 
   and process it once we've read the necessary additional data from the 
   message body, which is handled by the following function.
   
   The MAC information in this case is the homebrew Entrust MAC, not 
   anything normal */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int updateMacInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						  INOUT_PTR STREAM *stream,
						  IN_BOOL const BOOLEAN isRevocation )
	{
	const ATTRIBUTE_LIST *passwordPtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD );
	BYTE macKey[ 64 + 8 ];
	BOOLEAN decodedMacKey = FALSE;
	const void *macKeyPtr;
	const int streamPos = stell( stream );
	int macKeyLength, status;

	REQUIRES( isBooleanValue( isRevocation ) );
	REQUIRES( passwordPtr != NULL );
	REQUIRES( isIntegerRangeNZ( streamPos ) );

	sseek( stream, protocolInfo->macInfoPos );
	if( isRevocation && protocolInfo->altMacKeySize > 0 )
		{
		/* If it's a revocation and we're using a distinct revocation
		   password (which we've already decoded into a MAC key), use
		   that */
		macKeyPtr = protocolInfo->altMacKey;
		macKeyLength = protocolInfo->altMacKeySize;
		}
	else
		{
		/* It's a standard issue (or we're using the same password/key
		   for the issue and revocation), use that */
		if( TEST_FLAG( passwordPtr->flags, ATTR_FLAG_ENCODEDVALUE ) )
			{
			/* It's an encoded value, get the decoded form */
			macKeyPtr = macKey;
			status = decodePKIUserValue( macKey, 64, &macKeyLength, 
										 passwordPtr->value, 
										 passwordPtr->valueLength );
			ENSURES( cryptStatusOK( status ) );
			decodedMacKey = TRUE;
			}
		else
			{
			macKeyPtr = passwordPtr->value;
			macKeyLength = passwordPtr->valueLength;
			}
		}
	status = readMacInfo( stream, protocolInfo, macKeyPtr,
						  macKeyLength, SESSION_ERRINFO );
	if( decodedMacKey )
		zeroise( macKey, 64 );
	if( cryptStatusError( status ) )
		return( status );
	sseek( stream, streamPos );

	return( CRYPT_OK );
	}

/* Read and process the unauthenticated extraCerts attached to a message:

	extraCerts	[1]	EXPLICIT SEQUENCE SIZE (1..MAX) OF Certificate 

   This is required by ETSI 33.310 to kludge around various shortcomings in
   CMP, see the inline comments for details */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processExtraCerts( INOUT_PTR STREAM *stream,
							  INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
							  IN_ENUM( CMP_MESSAGE ) \
									const CMP_MESSAGE_TYPE messageType )
	{
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	ERROR_INFO localErrorInfo;
#ifdef USE_ERRMSGS
	char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
	char newCertName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	int length, trustValue, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isEnumRange( messageType, CMP_MESSAGE ) );

	/* Some servers erroneously send extraCerts in messages like pkiConf
	   even though it's explicitly prohibited in 33.310 section 9.5.4.5, so 
	   we make sure that we've got an ip/cp/kup before continuing */
	if( !isServer( sessionInfoPtr ) && \
		messageType != CTAG_PB_IP && messageType != CTAG_PB_CP && \
		messageType != CTAG_PB_KUP )
		{
		DEBUG_PRINT(( "CLI: Server sent spurious extraCerts in %s message, "
					  "this may result in signature checks failing due to "
					  "the use of incorrect certificates.\n",
					  getCMPMessageName( messageType ) ) );

		/* In theory this is an error but in the interests of 
		   interoperability we just skip the extraCerts and try and 
		   continue.  Depending on what the server was trying to do we'll
		   either continue as normal or the next signature check will fail
		   due to incorrect certificates being used */
		return( CRYPT_OK );
		}

	/* Read the extraCerts wrapper */
	status = readConstructed( stream, &length, CTAG_PM_EXTRACERTS );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the certificate sequence */
	clearErrorInfo( &localErrorInfo );
	status = importCertFromStream( stream, &cmpInfo->iExtraCerts, 
								   DEFAULTUSER_OBJECT_HANDLE,
								   CRYPT_ICERTTYPE_CMP_CERTSEQUENCE, length, 
								   KEYMGMT_FLAG_NONE, &localErrorInfo );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo, 
					 "Couldn't read extra certificates for %s message", 
					 getCMPMessageName( messageType ) ) );
		}

	/* Since this field is unauthenticated, we have to verify the chain that 
	   we've just read using the signature-check certificate.  If we're not 
	   using signatures for authentication (meaning we don't have a 
	   certificate present to check the chain that we've just read) we can't 
	   do anything with the extraCerts since there's no way to verify 
	   whether they're legitimate or not.  
	   
	   As an alternative to failing the exchange we could quietly delete 
	   them and continue, but it's probably better to make problems explicit 
	   rather than silently skipping them */
	if( protocolInfo->useMACreceive )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Couldn't verify unauthenticated extraCerts certificate "
				  "chain for '%s' from %s", 
				  getCertHolderName( cmpInfo->iExtraCerts, 
									 newCertName, CRYPT_MAX_TEXTSIZE ),
				  getCMPMessageName( messageType ) ) );
		}
	
	/* Now we have to figure out what we're going to do with these things.  
	   If we're the server then there's no obvious use for the certificates
	   so we just ignore them */
	if( isServer( sessionInfoPtr ) )
		return( CRYPT_OK );

	/* We're the client, at the moment the only real use seems to be when 
	   the client has been configured with nothing but a CA root certificate 
	   and the server is being run from an intermediate CA and we're not 
	   using an encrypt-only key, in which case we can't verify the 
	   signature on the returned response.  To deal with this, 33.310 
	   requires that the CA include any additional needed certificates in 
	   the response, which we try and process now.

	   Since we're performing certificate verification, we have to mark the 
	   verifying certificate as trusted if it's not already set as such 
	   otherwise the verification will fail due to an untrusted-issuer 
	   error */
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_GETATTRIBUTE, &trustValue, 
							  CRYPT_CERTINFO_TRUSTED_IMPLICIT );
	if( cryptStatusOK( status ) && trustValue == FALSE )
		{
		status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE, 
								  CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cmpInfo->iExtraCerts,
								  IMESSAGE_CRT_SIGCHECK, NULL,
								  sessionInfoPtr->iAuthInContext );
		krnlSendMessage( sessionInfoPtr->iAuthInContext, 
						 IMESSAGE_SETATTRIBUTE, &trustValue, 
						 CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		}
	if( cryptStatusError( status ) )
		{
		if( cryptArgError( status ) )
			{
			/* There's a problem with one of the parameters, convert the 
			   error status to a general invalid-information error */
			status = CRYPT_ERROR_INVALID;
			}			
		retExtErr( status,
				   ( status, SESSION_ERRINFO, &localErrorInfo, 
					 "Couldn't verify extraCerts certificate chain '%s' "
					 "from %s using signature check key '%s'",
					 getCertHolderName( cmpInfo->iExtraCerts, 
										newCertName, CRYPT_MAX_TEXTSIZE ),
					 getCMPMessageName( messageType ),
					 getCertHolderName( sessionInfoPtr->iAuthInContext, 
										certName, CRYPT_MAX_TEXTSIZE ) ) );
		}
	DEBUG_PRINT(( "%s: Verified extraCerts certificate chain '%s' "
				  "from %s using configured CA key '%s'.\n", 
				  isServer( sessionInfoPtr ) ? "SVR" : "CLI",
				  getCertHolderName( cmpInfo->iExtraCerts, 
									 newCertName, CRYPT_MAX_TEXTSIZE ),
				  getCMPMessageName( messageType ),
				  getCertHolderName( sessionInfoPtr->iAuthInContext, 
									 certName, CRYPT_MAX_TEXTSIZE ) ));

	/* The certificate chain in the extraCerts field has been verified, use 
	   this to process the CMP message instead of the certificate that we've 
	   been configured with */
	DEBUG_PRINT(( "%s: Switching to extraCerts certificate chain '%s' "
				  "to verify message signatures.\n", 
				  isServer( sessionInfoPtr ) ? "SVR" : "CLI",
				  getCertHolderName( cmpInfo->iExtraCerts, 
									 newCertName, CRYPT_MAX_TEXTSIZE ) ));
	protocolInfo->useAltAuthKey = TRUE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read PKIHeader Fields							*
*																			*
****************************************************************************/

/* Read the kitchen-sink field in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readGeneralInfoAttribute( INOUT_PTR STREAM *stream, 
									 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	BYTE oid[ MAX_OID_SIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Read the attribute.  Since there are only two attribute types that we 
	   use, we hardcode the read in here rather than performing a general-
	   purpose attribute read */
	readSequence( stream, NULL );
	status = readEncodedOID( stream, oid, MAX_OID_SIZE, &length, 
							 BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the cryptlib presence-check value */
	if( matchOID( oid, length, OID_CRYPTLIB_PRESENCECHECK ) )
		{
		/* The other side is running cryptlib, we can make some common-sense 
		   assumptions about its behaviour */
		protocolInfo->isCryptlib = TRUE;
		return( readSetZ( stream, NULL ) );			/* Attribute */
		}

	/* Check for the ESSCertID, which fixes CMP's broken certificate 
	   identification mechanism */
	if( matchOID( oid, length, OID_ESS_CERTID ) )
		{
		BYTE certID[ CRYPT_MAX_HASHSIZE + 8 ];
		int certIDsize, endPos;

		/* Extract the certificate hash from the ESSCertID */
		readSet( stream, NULL );					/* Attribute */
		readSequence( stream, NULL );				/* SigningCerts */
		readSequence( stream, NULL );				/* Certs */
		status = readSequence( stream, &length );	/* ESSCertID */
		if( cryptStatusError( status ) )
			return( status );
		endPos = stell( stream ) + length;
		ENSURES( isIntegerRangeMin( endPos, length ) );
		status = readOctetString( stream, certID, &certIDsize, 
								  KEYID_SIZE, KEYID_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		if( protocolInfo->certIDsize != KEYID_SIZE || \
			memcmp( certID, protocolInfo->certID, KEYID_SIZE ) )
			{
			/* The certificate used for authentication purposes has changed,
			   remember the new certID */
			memcpy( protocolInfo->certID, certID, KEYID_SIZE );
			protocolInfo->certIDsize = KEYID_SIZE;
			protocolInfo->certIDchanged = TRUE;
			}
		if( stell( stream ) < endPos )
			{
			/* Skip the issuerSerial if there's one present.  We can't 
			   really do much with it in this form without rewriting it into 
			   the standard issuerAndSerialNumber, but in any case we don't 
			   need it because we've already got the certificate ID */
			status = readUniversal( stream );
			}
		return( status );
		}

	/* It's something that we don't recognise, skip it */
	return( readUniversal( stream ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readGeneralInfo( INOUT_PTR STREAM *stream, 
							INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	int length, endPos, status, LOOP_ITERATOR;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Go through the various attributes looking for anything that we can
	   use */
	readConstructed( stream, NULL, CTAG_PH_GENERALINFO );
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	LOOP_MED_WHILE( stell( stream ) < endPos )
		{
		ENSURES( LOOP_INVARIANT_MED_GENERIC() );

		status = readGeneralInfoAttribute( stream, protocolInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( LOOP_BOUND_OK );

	return( status );
	}

/* Read the user ID in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readUserID( INOUT_PTR STREAM *stream, 
					   INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	BYTE userID[ CRYPT_MAX_HASHSIZE + 8 ];
	int userIDsize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Read the PKI user ID that we'll need to handle the integrity 
	   protection on the message */
	readConstructed( stream, NULL, CTAG_PH_SENDERKID );
	status = readOctetString( stream, userID, &userIDsize, 8, 
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( userIDsize >= 8 && userIDsize <= CRYPT_MAX_HASHSIZE );

	/* If there's already been a previous transaction (which means that we 
	   have PKI user information present) and the current transaction 
	   matches what was used in the previous one, we don't have to update 
	   the user information */
	if( protocolInfo->userIDsize == userIDsize && \
		!memcmp( protocolInfo->userID, userID, userIDsize ) )
		{
		DEBUG_PRINT(( "%s: Skipped repeated userID.\n",
					  protocolInfo->isServer ? "SVR" : "CLI" ));
		DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
						protocolInfo->userID, protocolInfo->userIDsize );
		return( CRYPT_OK );
		}

	/* Record the new or changed PKI user information.  At this point we 
	   fall into another one of the many traps set by CMP: If the user ID 
	   has changed there's no obvious way to deal with this.  If we're using a 
	   MAC then presumably a different MAC key is in use but we have no idea 
	   what it is, if we're using a signature then we also have no idea what 
	   signature key the new ID correspond to.  The best that we can do is 
	   to keep going with whatever's at hand in the hope that the new user 
	   ID refers to the existing key (EJBCA at least uses the sKID of the 
	   signing certificate as the user ID, so if we send a request with a 
	   user name as the user ID we get back a response with the CA's sKID as 
	   the user ID, which means that ignoring the changed user ID works fine 
	   because the CA key is used to sign the response) */
	static_assert( CRYPT_MAX_HASHSIZE <= CRYPT_MAX_TEXTSIZE,
				   "MAX_HASHSIZE > MAX_TEXTSIZE" );
	REQUIRES( rangeCheck( userIDsize, 1, CRYPT_MAX_TEXTSIZE ) );
	memcpy( protocolInfo->userID, userID, userIDsize );
	protocolInfo->userIDsize = userIDsize;
	protocolInfo->userIDchanged = TRUE;
#if 0
	/* Delete the MAC context associated with the previous user if necessary.  
	   See the note above, this won't work because we've now deleted the MAC
	   context that we need to authenticate further outgoing messages */
	if( protocolInfo->iMacContext != CRYPT_ERROR )
		{
		krnlSendNotifier( protocolInfo->iMacContext,
						  IMESSAGE_DECREFCOUNT );
		protocolInfo->iMacContext = CRYPT_ERROR;
		protocolInfo->useMACsend = protocolInfo->useMACreceive = FALSE;
		}
#endif /* 0 */
	DEBUG_PRINT(( "%s: Read new userID.\n",
				  protocolInfo->isServer ? "SVR" : "CLI" ));
	DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
					protocolInfo->userID, protocolInfo->userIDsize );

	return( CRYPT_OK );
	}

/* Read the messageTime field in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readMessageTime( INOUT_PTR STREAM *stream, 
							INOUT_PTR ERROR_INFO *errorInfo )
	{
	const time_t systemTime = getTime( GETTIME_MINUTES );
	time_t messageTime, delta;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Read the message time and make sure that it's within 24 hours of the 
	   system time */
	readConstructed( stream, NULL, CTAG_PH_MESSAGETIME );
	status = readGeneralizedTime( stream, &messageTime );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid message time in PKI header" ) );
		}
	delta = ( messageTime > systemTime ) ? \
			messageTime - systemTime : systemTime - messageTime;
	if( delta > 86400 )
		{
		/* The difference between the sender and our time is more than 24 
		   hours, treat it as an error.  At this point we don't know the
		   message type yet so we can't report any information about the
		   message type in the error text */
		delta /= 60 * 60;	/* Difference in hours */
		if( delta > 24 * 3 )
			{
			/* More than three days difference, report it in days */
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Peer system time is %d days out from our system "
					  "time, can't proceed with certification operation", 
					  ( int ) ( delta / 24 ) ) );
			}
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Peer system time is %d hours out from our system "
				  "time, can't proceed with certification operation", 
				  ( int ) delta ) );
		}

	return( CRYPT_OK );
	}

/* Read the transaction ID (effectively the nonce) in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readTransactionID( INOUT_PTR STREAM *stream, 
							  INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
							  IN_ENUM( CMP_MSGINFO ) \
								const CMP_MSGINFO_TYPE cmpMsgInfo )
	{
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isEnumRangeOpt( cmpMsgInfo, CMP_MSGINFO ) );

	/* If this is the first message and we're the server, record the 
	   transaction ID for later */
	if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER )
		{
		status = readOctetString( stream, protocolInfo->transID,
								  &protocolInfo->transIDsize,
								  4, CRYPT_MAX_HASHSIZE );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "%s: Read initial transID.\n",
					  protocolInfo->isServer ? "SVR" : "CLI" ));
		DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
						protocolInfo->transID, protocolInfo->transIDsize );
		return( CRYPT_OK );
		}

	/* Make sure that the transaction ID for this message matches the 
	   recorded value (the bad signature error code is the best that we can 
	   provide here) */
	status = readOctetString( stream, buffer, &length, 4, 
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );
	FUZZ_SKIP_REMAINDER();
	ANALYSER_HINT( length >= 4 && length <= CRYPT_MAX_HASHSIZE );
	DEBUG_PRINT(( "%s: Read transID.\n",
				  protocolInfo->isServer ? "SVR" : "CLI" ));
	DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
					protocolInfo->transID, protocolInfo->transIDsize );
	if( protocolInfo->transIDsize != length || \
		memcmp( protocolInfo->transID, buffer, length ) )
		return( CRYPT_ERROR_SIGNATURE );

	return( CRYPT_OK );
	}

/* Read the integrity protection algorithm information, either for a MAC or
   signature, in the PKI header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readProtectionAlgo( INOUT_PTR STREAM *stream, 
							   INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	ALGOID_PARAMS algoIDparams;
	int streamPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	/* Read the wrapper.  If there's a problem we don't exit immediately 
	   since an error status from the readAlgoIDex() that follows is 
	   interpreted to indicate the presence of the weird Entrust MAC rather 
	   than a real error */
	status = readConstructed( stream, NULL, CTAG_PH_PROTECTIONALGO );
	if( cryptStatusError( status ) )
		return( status );
	streamPos = stell( stream );
	REQUIRES( isIntegerRangeNZ( streamPos ) );
	status = readAlgoIDex( stream, &cryptAlgo, &algoIDparams,
						   ALGOID_CLASS_PKCSIG );
	if( cryptStatusOK( status ) )
		{
		/* Make sure that it's a recognised signature algorithm to avoid
		   false positives if the other side sends some bizarre algorithm 
		   ID */
		if( !isSigAlgo( cryptAlgo ) )
			return( CRYPT_ERROR_NOTAVAIL );

		/* It's a recognised signature algorithm, use the CA certificate to 
		   verify it rather than the MAC */
		protocolInfo->useMACreceive = FALSE;
		protocolInfo->hashAlgo = algoIDparams.hashAlgo;
		protocolInfo->hashParam = algoIDparams.hashParam;

		return( CRYPT_OK );
		}
	ENSURES( cryptStatusError( status ) );

	/* If we get an error other than one due to an unknown OID, exit */
	if( status != CRYPT_ERROR_NOTAVAIL )
		return( status );

	/* It's nothing normal, it must be the Entrust MAC algorithm 
	   information, make sure that we at least find the OID for this and
	   remember where the information starts so that we can process it 
	   later */
	sClearError( stream );
	sseek( stream, streamPos );
	protocolInfo->useMACreceive = TRUE;
	protocolInfo->macInfoPos = streamPos;
	readSequence( stream, NULL );
	status = readFixedOID( stream, OID_ENTRUST_MAC,
						   sizeofOID( OID_ENTRUST_MAC ) );
	if( cryptStatusError( status ) )
		{
		/* It's not the Entrust algorithm either, we don't know what to do
		   with it */
		return( CRYPT_ERROR_BADDATA );
		}

	/* Skip the AlgorithmID parameters.  We use the Opt form of 
	   readUniversal() since the parameters are redundant for anything but
	   the first message so are usually sent as a zero-length object*/
	return( readUniversalOpt( stream ) );
	}

/****************************************************************************
*																			*
*								Read a PKI Header							*
*																			*
****************************************************************************/

/* Read a PKI header and make sure that it matches the header that we sent
   (for EE or non-initial CA/RA messages) or set up the EE information in
   response to an initial message (for an initial CA/RA message).  We ignore
   all of the redundant fields in the header that don't directly affect the
   protocol, based on the results of CMP interop testing this appears to be
   standard practice among implementers.  This also helps get around 
   problems with implementations that get the fields wrong, since most of 
   the fields aren't useful it doesn't affect the processing while making 
   the code more tolerant of implementation errors:

	header				SEQUENCE {
		version			INTEGER (2),
		senderDN	[4]	EXPLICIT DirectoryName,		-- Copied if non-clib
		dummy		[4]	EXPLICIT DirectoryName,		-- Ignored
		messageTime	[0] EXPLICIT GeneralisedTime OPT,-- Checked against local clock
		protAlgo	[1]	EXPLICIT AlgorithmIdentifier,
		protKeyID	[2] EXPLICIT OCTET STRING,		-- Copied if changed
		dummy		[3] EXPLICIT OCTET STRING OPT,	-- Ignored
		transID		[4] EXPLICIT OCTET STRING,
		nonce		[5] EXPLICIT OCTET STRING OPT,	-- Copied if non-clib
		dummy		[6] EXPLICIT OCTET STRING OPT,	-- Ignored
		dummy		[7] EXPLICIT SEQUENCE OF UTF8String OPT,-- Ignored
		generalInfo	[8] EXPLICIT SEQUENCE OF Info OPT -- cryptlib-specific info
		} 

   Note the massive quantity of random tags sprayed all over the place, the 
   correct tagging should be: 

	header				SEQUENCE {
		version			INTEGER (2),
		senderDN		DirectoryName,				-- Copied if non-clib
		dummy			DirectoryName,				-- Ignored
		messageTime		GeneralisedTime OPTIONAL,	-- Checked against local clock
		protAlgo		AlgorithmIdentifier,
		protKeyID		OCTET STRING,				-- Copied if changed
		dummy		[0] OCTET STRING OPTIONAL,		-- Ignored
		transID			OCTET STRING,
		nonce		[1] OCTET STRING OPTIONAL,		-- Copied if non-clib
		dummy		[2] OCTET STRING OPTIONAL,		-- Ignored
		dummy			SEQUENCE OF UTF8String OPTIONAL,-- Ignored
		generalInfo	[3] SEQUENCE OF Info OPTIONAL	-- cryptlib-specific info
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readPkiHeader( INOUT_PTR STREAM *stream, 
						  INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						  INOUT_PTR ERROR_INFO *errorInfo,
						  IN_ENUM_OPT( CMP_MSGINFO ) \
								const CMP_MSGINFO_TYPE cmpMsgInfo )
	{
	int tag = CRYPT_ERROR, length, endPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isEnumRangeOpt( cmpMsgInfo, CMP_MSGINFO ) );

	/* Clear per-message state information */
	protocolInfo->userIDchanged = protocolInfo->certIDchanged = \
		protocolInfo->useMACreceive = FALSE;
	protocolInfo->macInfoPos = 0;
	protocolInfo->senderDNPtr = NULL;
	protocolInfo->senderDNlength = 0;
	protocolInfo->headerRead = protocolInfo->noIntegrity = FALSE;

	/* Read the wrapper and skip the static information, which matches what 
	   we sent and is protected by the MAC so there's little point in 
	   looking at it */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	ENSURES( isIntegerRangeMin( endPos, length ) );
	readShortInteger( stream, NULL );		/* Version */
	if( !protocolInfo->isCryptlib )
		{
		/* The ID of the key used for integrity protection (or in general
		   the identity of the sender) can be specified either as the sender
		   DN or the senderKID or both, or in some cases even indirectly via
		   the transaction ID.  With no real guidance as to which one to 
		   use, implementors are using any of these options to identify the 
		   key.  Since we need to check that the integrity-protection key 
		   that we're using is correct so that we can report a more 
		   appropriate error than bad signature or bad data, we need to 
		   remember the sender DN for later in case this is the only form of 
		   key identification provided.  Unfortunately since the sender DN 
		   can't uniquely identify a certificate, if this is the only 
		   identifier that we're given then the caller can still get a bad 
		   signature error, yet another one of CMPs many wonderful features.
		   
		   Note the use of readUniversalOpt() rather than readUniversal()
		   since the recipient DN typically serves no purpose and so the 
		   client will send a zero-length value */
		status = readConstructed( stream, &protocolInfo->senderDNlength, 4 );
		if( cryptStatusOK( status ) && protocolInfo->senderDNlength > 0 )
			{
			status = sMemGetDataBlock( stream, &protocolInfo->senderDNPtr, 
									   protocolInfo->senderDNlength );
			if( cryptStatusOK( status ) )
				status = readUniversalOpt( stream );
			}
		}
	else
		{
		/* cryptlib includes a proper certID so the whole signer
		   identification mess is avoided and we can ignore the sender DN.
		   Note the use of readUniversalOpt() rather than readUniversal()
		   since the sender typically doesn't know their DN and will send
		   a zero-length value */
		status = readUniversalOpt( stream );	/* Sender DN */
		}
	if( cryptStatusOK( status ) )
		status = readUniversalOpt( stream );	/* Recipient DN */
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid DN information in PKI header" ) );
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_PH_MESSAGETIME ) )
		{
		/* Read the message time and make sure that it's within range of our 
		   time */
		status = readMessageTime( stream, errorInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( !checkStatusPeekTag( stream, status, tag ) || \
		tag != MAKE_CTAG( CTAG_PH_PROTECTIONALGO ) )
		{
		/* The message was sent without integrity protection, report it as
		   a signature error rather than the generic bad data error that
		   we'd get from the following read unless this is the first message
		   from the server, in which case it could be an unprotected error
		   response to our mesage where the server can't figure out how to 
		   sign the response */
		if( cmpMsgInfo != CMP_MSGINFO_FIRSTMESSAGE_TO_CLIENT )
			{
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, errorInfo, 
					  "Message was sent without integrity protection" ) );
			}
		protocolInfo->noIntegrity = TRUE;
		}
	if( !protocolInfo->noIntegrity )
		{
		status = readProtectionAlgo( stream, protocolInfo );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo, 
					  "Invalid integrity protection information in PKI "
					  "header" ) );
			}
		if( checkStatusPeekTag( stream, status, tag ) && \
			tag == MAKE_CTAG( CTAG_PH_SENDERKID ) )
			{							/* Sender protection keyID */
			status = readUserID( stream, protocolInfo );
			if( cryptStatusError( status ) )
				{
				retExt( status,
						( status, errorInfo, 
						  "Invalid PKI user ID in PKI header" ) );
				}
			}
		else
			{
			/* If we're the server, the client must provide a PKI user ID in the
			   first message unless we got one in an earlier transaction */
			if( cmpMsgInfo == CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER && \
				protocolInfo->userIDsize <= 0 )
				{
				retExt( CRYPT_ERROR_BADDATA, 
						( CRYPT_ERROR_BADDATA, errorInfo, 
						  "Missing PKI user ID in PKI header" ) );
				}
			}
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( CTAG_PH_RECIPKID ) )
		{
		/* Recipient protection keyID */
		status = readUniversal( stream );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Record the transaction ID (which is effectively the nonce) or make 
	   sure that it matches the one that we sent.  There's no real need to 
	   do an explicit duplicate check since a replay attempt will be 
	   rejected as a duplicate by the certificate store and the locking 
	   performed at that level makes it a much better place to catch 
	   duplicates, but we do it anyway because it doesn't cost anything and
	   we can catch at least some problems a bit earlier */
	status = readConstructed( stream, NULL, CTAG_PH_TRANSACTIONID );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Missing transaction ID in PKI header" ) );
		}
	status = readTransactionID( stream, protocolInfo, cmpMsgInfo );
	if( cryptStatusError( status ) )
		{
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADRECIPIENTNONCE;
		retExt( status, 
				( status, errorInfo, 
				  ( status == CRYPT_ERROR_SIGNATURE ) ? \
				  "Returned message transaction ID doesn't match our "
						"transaction ID" : \
				  "Invalid transaction ID in PKI header" ) );
		}

	/* Read the sender nonce, which becomes the new recipient nonce, and skip
	   the recipient nonce if there's one present.  These values may be
	   absent, either because the other side doesn't implement them or
	   because they're not available, for example because it's sending a
	   response to an error that occurred before it could read the nonce from
	   a request.  In any case we don't bother checking the nonce values
	   since the transaction ID serves the same purpose */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_PH_SENDERNONCE ) )
		{
		readConstructed( stream, NULL, CTAG_PH_SENDERNONCE );
		status = readOctetString( stream, protocolInfo->recipNonce,
								  &protocolInfo->recipNonceSize,
								  4, CRYPT_MAX_HASHSIZE );
		if( cryptStatusError( status ) )
			{
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADSENDERNONCE;
			retExt( status,
					( status, errorInfo, 
					  "Invalid sender nonce in PKI header" ) );
			}
		}
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_PH_RECIPNONCE ) )
		{
		readConstructed( stream, NULL, CTAG_PH_RECIPNONCE );
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			{
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADRECIPIENTNONCE;
			retExt( status,
					( status, errorInfo, 
					  "Invalid recipient nonce in PKI header" ) );
			}
		}
	if( cryptStatusError( status ) )
		return( status );	/* Residual error from peekTag() */

	/* Remember that we've successfully read enough of the header 
	   information to generate a response */
	protocolInfo->headerRead = TRUE;

	/* Skip any further junk and process the general information if there is 
	   any */
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_PH_FREETEXT ) )
		{
		/* Skip junk */
		status = readUniversal( stream );
		}
	if( checkStatusLimitsPeekTag( stream, status, tag, endPos ) && \
		tag == MAKE_CTAG( CTAG_PH_GENERALINFO ) )
		{
		status = readGeneralInfo( stream, protocolInfo );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo, 
					  "Invalid generalInfo information in PKI header" ) );
			}
		}

	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}		/* checkStatusLimitsPeekTag() can return tag as status */

/****************************************************************************
*																			*
*							Read a PKI Message								*
*																			*
****************************************************************************/

/* Read a PKI message:

	PkiMessage ::= SEQUENCE {
		header			PKIHeader,
		body			CHOICE { [0]... [24]... },
		protection	[0]	EXPLICIT BIT STRING,
		extraCerts	[1] EXPLICIT SEQUENCE OF Certificate OPTIONAL
		}

   Note that readPkiDatagram() has already performed an initial valid-ASN.1 
   check before we get here.
   
   The extraCerts field is described in the spec as a dumping-ground for any 
   certs that the CA may wish to include there, since there's no indicator 
   of what these could be or what we should do with them, and even more 
   importantly the field is unauthenticated so we can't trust any of these 
   extra certs, we ignore it unless we've been explicitly told to process it 
   as per the 3GPP profile of CMP */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readPkiMessage( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
					IN_ENUM_OPT( CMP_MESSAGE ) CMP_MESSAGE_TYPE messageType )
	{
#ifdef USE_ERRMSGS
	ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;
#endif /* USE_ERRMSGS */
	CMP_INFO *cmpInfo = sessionInfoPtr->sessionCMP;
	READMESSAGE_FUNCTION readMessageFunction;
	STREAM stream;
	const CMP_MSGINFO_TYPE cmpMsgInfo = \
					( messageType == CTAG_PB_READ_ANY ) ? \
					  CMP_MSGINFO_FIRSTMESSAGE_TO_SERVER : 
					( messageType == CTAG_PB_IP || \
					  messageType == CTAG_PB_CP || \
					  messageType == CTAG_PB_KUP ) ? \
					  CMP_MSGINFO_FIRSTMESSAGE_TO_CLIENT : CMP_MSGINFO_NONE;
	void *integrityInfoPtr DUMMY_INIT_PTR;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int protPartStart DUMMY_INIT, protPartSize, bodyStart DUMMY_INIT;
	int length, endPos DUMMY_INIT, integrityInfoLength DUMMY_INIT, tag;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( sanityCheckSessionCMP( sessionInfoPtr ) );
	REQUIRES( sanityCheckCMPProtocolInfo( protocolInfo ) );
	REQUIRES( ( messageType >= CTAG_PB_IR && \
				messageType < CTAG_PB_LAST ) || \
			  ( messageType == CTAG_PB_READ_ANY ) );
			  /* CTAG_PB_IR == 0 so this is the same as _NONE */

	DEBUG_PRINT(( "%s: Reading message type %d.\n",
				  isServer( sessionInfoPtr ) ? "SVR" : "CLI", 
				  messageType ));
				  /* We can't use getCMPMessageName() at this point since
				     we haven't read the message tag yet and messageType is
					 usually a generic code indicating one of a range of
					 messages */

	/* Strip off the header and PKIStatus wrapper */
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer,
				 sessionInfoPtr->receiveBufEnd );
	status = readSequence( &stream, &length );		/* Outer wrapper */
	if( cryptStatusOK( status ) )
		{
		protPartStart = stell( &stream );
		REQUIRES( isIntegerRangeNZ( protPartStart ) );
		endPos = protPartStart + length;
		REQUIRES( isIntegerRangeMin( endPos, length ) );
		status = readPkiHeader( &stream, protocolInfo, SESSION_ERRINFO,
								cmpMsgInfo );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	ENSURES( protocolInfo->transIDsize > 0 && \
			 protocolInfo->transIDsize <= CRYPT_MAX_HASHSIZE );
	CFI_CHECK_UPDATE( "readPkiHeader" );

	/* Set up session state information based on the header that we've just 
	   read */
	if( protocolInfo->isCryptlib )
		SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISCRYPTLIB );

	/* In order to fix CMP's inability to properly identify keys via 
	   certificates, we use the certID field in the generalInfo.  If there's
	   no PKI user ID present but no certID either then we can't identify 
	   the key that's needed in order to continue.  This also retroactively 
	   invalidates the headerRead flag, since we don't know which key to use
	   to authenticate our response.

	   In theory we shouldn't ever get into this state because we require 
	   a PKI user ID for the client's initial message and the server will
	   always send a certID for its signing certificate, but due to the
	   confusing combination of values that can affect the protocol state
	   (see the start of writePkiHeader() in cmp_wr.c for an example) we
	   do the following as a safety check to catch potential problems 
	   early.
	   
	   This also leads to a special-case exception, if we're the client then
	   the server may identify its signing key purely through the 
	   dysfunctional sender DN mechanism (see the comment in 
	   readPkiHeader()) so we allow this option as well.  The DN can't 
	   actually tell us whether it's the correct key or not (see the
	   comment in checkMessageSignature()) but there's not much else that
	   we can do */
	if( protocolInfo->useMACreceive )
		{
		/* There is one special-case situation in which we can have no user 
		   ID present and that's when we're doing a PnP PKI transaction with 
		   an initial PKIBoot that creates the required MAC context followed 
		   by an ir that doesn't need to send any ID information since it's 
		   reusing the MAC context that was created by the PKIBoot */
		if( protocolInfo->userIDsize <= 0 && \
			!( protocolInfo->isCryptlib && \
			   protocolInfo->iMacContext != CRYPT_ERROR ) )
			{
			sMemDisconnect( &stream );
			protocolInfo->headerRead = FALSE;
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Missing PKI user ID for MAC authentication of PKI "
					  "messages" ) );
			}
		}
	else
		{
		/* As with the case for MAC contexts, there's a special-case 
		   situation in which there's no certID present and that's during a 
		   PnP PKI transaction preceded by a PKIBoot that communicates the 
		   CA's certificate, where the PKIBoot creates the required 
		   sig-check context as part of the initialisation process.  In
		   addition we have to allow for DN-only identification from 
		   servers, see the comment above for details */
		if( protocolInfo->certIDsize <= 0 && \
			( !isServer( sessionInfoPtr ) && 
			  protocolInfo->senderDNlength <= 0 ) && \
			!( protocolInfo->isCryptlib && \
			   sessionInfoPtr->iAuthInContext != CRYPT_ERROR ) )
			{
			sMemDisconnect( &stream );
			protocolInfo->headerRead = FALSE;
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Missing certificate ID for signature authentication "
					  "of PKI messages" ) );
			}
		}

	/* If this is the first message from the client and we've been sent a 
	   new user ID or certificate ID (via the ESSCertID in the header's
	   kitchen-sink field, used to identify the signing certificate when
	   signature-based authentication is used), process the user/
	   authentication information */
	if( protocolInfo->userIDchanged )
		{
		status = updateUserID( sessionInfoPtr, protocolInfo, cmpMsgInfo, 
							   protocolInfo->useMACreceive );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	if( protocolInfo->certIDchanged )
		{
		status = updateCertID( sessionInfoPtr, protocolInfo, cmpMsgInfo );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "updateUserID" );

	/* Determine the message body type.  An error response can occur at any
	   point in an exchange so we process this immediately.  We don't do an
	   integrity verification for this one since it's not certain what we
	   should report if the check fails (what if the error response is to
	   report that no key is available to authenticate the user, for 
	   example?), and an unauthenticated error message is better than an 
	   authenticated paketewhainau */
	status = tag = peekTag( &stream );
	if( cryptStatusError( status ) )
		return( status );
	tag = EXTRACT_CTAG( tag );
	if( tag == CTAG_PB_ERROR )
		{
		readMessageFunction = getMessageReadFunction( CTAG_PB_ERROR );
		ENSURES( readMessageFunction != NULL );
		readConstructed( &stream, NULL, CTAG_PB_ERROR );
		status = readSequence( &stream, &length );
		if( cryptStatusOK( status ) )
			{
			status = readMessageFunction( &stream, sessionInfoPtr, 
										  protocolInfo, CTAG_PB_ERROR, 
										  length );
			}
		sMemDisconnect( &stream );

		/* Reading an error response always returns an error status since 
		   what we're reading is a report of an error, so we perform the CFI
		   check even in the presence of an error status */
		ENSURES( cryptStatusError( status ) );

		ENSURES( CFI_CHECK_SEQUENCE_2( "readPkiHeader", "updateUserID" ) );

		return( status );
		}
	if( protocolInfo->noIntegrity )
		{
		/* We may have received a response without integrity protection 
		   which can occur in some cases for error responses, see the 
		   comment in readPkiHeader() for details, however since what we've 
		   got if we reach this point isn't an error response we can't 
		   continue */
		sMemDisconnect( &stream );
		if( tag >= CMP_MESSAGE_NONE && tag <= CMP_MESSAGE_LAST_STANDARD )
			{
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, errorInfo, 
					  "%s message was sent without integrity protection",
					  getCMPMessageName( tag ) ) );
			}
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, errorInfo, 
				  "Message type %d was sent without integrity protection",
				  tag ) );
		}
	CFI_CHECK_UPDATE( "readError" );

	/* If this is an initial message to the server then we don't know what 
	   to expect yet so we set the type to whatever we find, as long as it's 
	   a valid message to send to a CA */
	if( messageType == CTAG_PB_READ_ANY )
		{
		if( tag == CTAG_PB_IR || tag == CTAG_PB_CR || \
			tag == CTAG_PB_P10CR || tag == CTAG_PB_KUR || \
			tag == CTAG_PB_RR || tag == CTAG_PB_GENM )
			{
			protocolInfo->operation = messageType = tag;
			}
		else
			{
			sMemDisconnect( &stream );
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADREQUEST;
			if( tag >= CMP_MESSAGE_NONE && \
				tag <= CMP_MESSAGE_LAST_STANDARD )
				{
				/* It's a known message type, report its name as well as its 
				   tag */
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Client sent %s message as initial message", 
						  getCMPMessageName( tag ) ) );
				}
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Client sent message type %d as initial message", 
					  tag ) );
			}
		}
	else
		{
		/* Make sure that this is what we're after */
		if( tag != messageType )
			{
			sMemDisconnect( &stream );
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADREQUEST;
			if( tag >= CMP_MESSAGE_NONE && \
				tag <= CMP_MESSAGE_LAST_STANDARD )
				{
				/* It's a known message type, report its name as well as its 
				   tag */
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid message type %s, expected %s", 
						  getCMPMessageName( tag ),
						  getCMPMessageName( messageType ) ) );
				}
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid message type %d, expected %s (%d)", tag,
					  getCMPMessageName( messageType ), messageType ) );
			}
		}
	DEBUG_PRINT(( "%s: Message is %s.\n",
				  isServer( sessionInfoPtr ) ? "SVR" : "CLI", 
				  getCMPMessageName( messageType ) ));

	/* If we're using a MAC for authentication, we can finally set up the
	   MAC information using the appropriate password.  We couldn't do this 
	   when we read the header because the order of the information used to 
	   set this up is backwards, so we have to go back and re-process it 
	   now */
#ifndef CONFIG_FUZZ
	if( protocolInfo->useMACreceive )
		{
		status = updateMacInfo( sessionInfoPtr, protocolInfo, &stream,
								( messageType == CTAG_PB_RR ) ? TRUE : FALSE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
#endif /* CONFIG_FUZZ */
	CFI_CHECK_UPDATE( "updateMacInfo" );

	/* Remember where the message body starts and skip it (it'll be 
	   processed after we verify its integrity) */
	status = readConstructed( &stream, &length, messageType );
	if( cryptStatusOK( status ) && !isIntegerRangeNZ( length ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK ( status ) )
		{
		bodyStart = stell( &stream );
		REQUIRES( isIntegerRangeNZ( bodyStart ) );
		status = sSkip( &stream, length, SSKIP_MAX );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADDATAFORMAT;
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid message body start for %s message",
				  getCMPMessageName( tag ) ) );
		}

	/* Read the start of the message integrity information */
	status = calculateStreamObjectLength( &stream, protPartStart,
										  &protPartSize );
	if( cryptStatusOK( status ) )
		{
		status = readConstructed( &stream, &integrityInfoLength,
								  CTAG_PM_PROTECTION );
		}
	if( cryptStatusOK( status ) && protocolInfo->useMACreceive )
		{
		/* If it's a MAC then we want the raw MAC value without any 
		   surrounding encapsulation */
		status = readBitStringHole( &stream, &integrityInfoLength, 
									MIN_HASHSIZE, DEFAULT_TAG );
		if( cryptStatusOK( status ) && \
			( integrityInfoLength < MIN_HASHSIZE || \
			  integrityInfoLength > CRYPT_MAX_HASHSIZE ) )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusOK( status ) )
		{
		status = sMemGetDataBlock( &stream, &integrityInfoPtr, 
								   integrityInfoLength );
		}
	if( cryptStatusOK( status ) )
		{
		status = sSkip( &stream, integrityInfoLength, MAX_INTLENGTH_SHORT );
		}
	if( cryptStatusError( status ) )
		{
		/* If the integrity protection is missing report it as a wrong-
		   integrity-information problem, the closest that we can get to the 
		   real error */
		sMemDisconnect( &stream );
		protocolInfo->pkiFailInfo = CMPFAILINFO_WRONGINTEGRITY;
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, errorInfo, 
				  "%s data for %s message is missing or truncated", 
				  protocolInfo->useMACreceive ? "MAC" : "Signature",
				  getCMPMessageName( tag ) ) );
		}
	if( tag == CTAG_PB_IR && !protocolInfo->useMACreceive )
		{
		/* An ir has to be MAC'd, in theory this doesn't really matter but
		   the spec requires that we only allow a MAC.  If it's not MAC'd it
		   has to be a cr, which is exactly the same only different */
		sMemDisconnect( &stream );
		protocolInfo->pkiFailInfo = CMPFAILINFO_WRONGINTEGRITY;
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, errorInfo, 
				  "Received signed ir message, should be MAC'd" ) );
		}
	ANALYSER_HINT( integrityInfoPtr != NULL );
	CFI_CHECK_UPDATE( "readIntegrityInfo" );

	/* There may be an (unauthenticated) extraCerts field present after the 
	   main message, try and process it as required */ 
	if( stell( &stream ) < endPos )
		{
		/* If we're running in compliance with ETSI 33.310, process the
		   extra certificates */
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, CMP_PFLAG_3GPP ) )
			{
			status = processExtraCerts( &stream, sessionInfoPtr, 
										protocolInfo, tag );
			if( cryptStatusError( status ) )
				{
				protocolInfo->pkiFailInfo = \
						( status == CRYPT_ERROR_SIGNATURE || \
						  status == CRYPT_ERROR_INVALID ) ? \
						  CMPFAILINFO_BADMESSAGECHECK : \
						  CMPFAILINFO_BADDATAFORMAT;
				}
			}
		else
			{
			int certSize;

			/* We have no idea what to do with these things and in any case
			   they're unauthenticated, skip them */
			readConstructed( &stream, NULL, CTAG_PM_EXTRACERTS );
			status = readSequence( &stream, &certSize );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( &stream );
				protocolInfo->pkiFailInfo = CMPFAILINFO_BADDATAFORMAT;
				retExt( status,
						( status, SESSION_ERRINFO, 
						   "Invalid extraCerts field for %s",
						   getCMPMessageName( tag ) ) );
				}
			DEBUG_PRINT(( "%s: Skipping unauthenticated extraCerts field "
						  "length %d for %s.\n", getCMPMessageName( tag ), 
						  isServer( sessionInfoPtr ) ? "SVR" : "CLI", 
						  certSize, getCMPMessageName( tag ) ));
			status = sSkip( &stream, certSize, MAX_INTLENGTH_SHORT );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADDATAFORMAT;
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "extraCerts" );

	/* Verify the message integrity.  We convert any error that we encounter 
	   during this check to a CRYPT_ERROR_SIGNATURE, this is somewhat 
	   overreaching since it could have been something like a formatting 
	   error but overall the problem is in the signature-check so we make 
	   this explicit rather than returning a somewhat vague underflow/
	   overflow/bad-data/whatever */
#ifndef CONFIG_FUZZ
	if( protocolInfo->useMACreceive )
		{
		status = checkMessageMAC( protocolInfo, 
						sessionInfoPtr->receiveBuffer + protPartStart,
						protPartSize, integrityInfoPtr, integrityInfoLength );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADMESSAGECHECK;
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					  "Bad message MAC for %s",
					  getCMPMessageName( tag ) ) );
			}
		}
	else
		{
		status = checkMessageSignature( protocolInfo,
						sessionInfoPtr->receiveBuffer + protPartStart,
						protPartSize, integrityInfoPtr, integrityInfoLength, 
						protocolInfo->useAltAuthKey ? \
							cmpInfo->iExtraCerts : \
							sessionInfoPtr->iAuthInContext );
		if( cryptStatusError( status ) )
			{
#ifdef USE_ERRMSGS
			char certName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */

			sMemDisconnect( &stream );
			if( status == CRYPT_ERROR_WRONGKEY )
				{
				/* Provide a more specific error message for the wrong-key 
				   error.  CMPFAILINFO_BADCERTID, "no certificate could be 
				   found matching the provided criteria", is the least 
				   inappropriate failure code */
				protocolInfo->pkiFailInfo = CMPFAILINFO_BADCERTID;
				retExt( CRYPT_ERROR_WRONGKEY,
						( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						  "Message signature key for %s doesn't match "
						  "certificate key from '%s', signature can't be "
						  "checked", getCMPMessageName( tag ), 
						  getCertHolderName( protocolInfo->useAltAuthKey ? \
												cmpInfo->iExtraCerts : \
												sessionInfoPtr->iAuthInContext,
											 certName, 
											 CRYPT_MAX_TEXTSIZE ) ) );
				}
			protocolInfo->pkiFailInfo = CMPFAILINFO_BADMESSAGECHECK;
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					   "Couldn't verify message signature for %s message "
					   "using certificate from '%s'",
					   getCMPMessageName( tag ), 
					   getCertHolderName( protocolInfo->useAltAuthKey ? \
											cmpInfo->iExtraCerts : \
											sessionInfoPtr->iAuthInContext,
										  certName, CRYPT_MAX_TEXTSIZE ) ) );
			}
		}
#endif /* CONFIG_FUZZ */
	CFI_CHECK_UPDATE( "checkIntegrityInfo" );

	/* We've performed the integrity check, go back to the message body so 
	   that we can process it */
	sseek( &stream, bodyStart );

	/* In the usual CMP tradition there's a nonstandard way used to encode
	   one of the message types, which we have to handle specially here */
	if( messageType == CTAG_PB_PKICONF )
		{
		status = readNull( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		ENSURES( CFI_CHECK_SEQUENCE_7( "readPkiHeader", "updateUserID", 
									   "readError", "updateMacInfo", 
									   "readIntegrityInfo", "extraCerts",
									   "checkIntegrityInfo" ) );

		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "pkiConf" );

	/* Read the message body wrapper */
	status = readSequence( &stream, &length );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Process the message body */
	readMessageFunction = getMessageReadFunction( messageType );
	if( readMessageFunction == NULL )
		{
		DEBUG_DIAG(( "No message-read function available for %s message", 
					 getCMPMessageName( tag ) ));
		assert( DEBUG_WARN );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Unexpected %s message can't be processed", 
				  getCMPMessageName( tag ) ) );
		}
	status = readMessageFunction( &stream, sessionInfoPtr, protocolInfo,
								  messageType, length );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "readMessageFunction" );

	ENSURES( CFI_CHECK_SEQUENCE_9( "readPkiHeader", "updateUserID", 
								   "readError", "updateMacInfo", 
								   "readIntegrityInfo", "extraCerts",
								   "checkIntegrityInfo", "pkiConf", 
								   "readMessageFunction" ) );

	return( CRYPT_OK );
	}
#endif /* USE_CMP */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
