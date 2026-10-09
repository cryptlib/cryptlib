/****************************************************************************
*																			*
*					cryptlib DBMS CA Certificate Misc Interface				*
*						Copyright Peter Gutmann 1996-2025					*
*																			*
****************************************************************************/

#include <stdio.h>		/* For snprintf() */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "dbms.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "keyset/dbms.h"
  #include "keyset/keyset.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Generate a nonce certID value, used for log entries where the main certID
   is already present in an earlier record */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateNonceID( OUT_BUFFER_FIXED( ENCODED_DBXKEYID_SIZE ) \
								char *certID, 
							IN_LENGTH_FIXED( ENCODED_DBXKEYID_SIZE ) \
								const int certIdLength )
	{
	MESSAGE_DATA msgData;
	BYTE nonce[ DBXKEYID_SIZE + 8 ];
	int length DUMMY_INIT, status;

	assert( isWritePtrDynamic( certID, certIdLength ) );
	
	REQUIRES( certIdLength == ENCODED_DBXKEYID_SIZE );

	setMessageData( &msgData, nonce, DBXKEYID_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusOK( status ) )
		{
		status = base64encode( certID, certIdLength, &length, nonce, 
							   DBXKEYID_SIZE, CRYPT_CERTTYPE_NONE );
		}
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( length == ENCODED_DBXKEYID_SIZE );
	memset( certID, '-', 4 );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Logging Functions							*
*																			*
****************************************************************************/

/* Add an entry to the CA log.  What's logged is:

	action				certID	reqCertID	authCertID	pkiUserID
	------				------	---------	----------	---------
	ADDUSER	(5)			pkiUser							pkiUser
	DELETEUSER (6)		pkiUser							pkiUser
	REQUEST_XXX	(7-9)	request				authCert	pkiUser	-- cert, renew, rev
	ISSUE_CERT (17)		cert	request		authCert	pkiUser
	CERT_CREATION_xxx:
	  CREATION (10)		cert	request		authCert	pkiUser
	  COMPLETE(11)		cert--
	  DROP (12)			cert--
	  REVERSE (13)		cert--
	REVOKE_CERT	(19)	cert&&
	ISSUE_CRL (18)
	EXPIRE_CERT (20)	nonce	cert
	CLEANUP	(21)		nonce	cert (one entry per certificate)
	CREATE (1)			(dummy)
	CONNECT (2)
	DISCONNECT (3)
	ERROR (4)			ERR-nonce cert

   The authCertID is only present for signed requests, for example SCEP and 
   CMP renewals.  The logged certIDs are modified as required via 
   modifyUnique/CertIssueID() to avoid collisions for multi-step operations, 
   e.g. _CREATION vs. _COMPLETE.  The cleanup action records the cleaned-up 
   item as the reqCertID rather than the certID because an entry for the 
   certID already exists from when the item was added */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int updateCertLogEx( INOUT_PTR DBMS_INFO *dbmsInfo, 
					 IN_ENUM( CRYPT_CERTACTION ) const CRYPT_CERTACTION_TYPE action, 
					 IN_BUFFER_OPT( certIDlength ) const char *certID, 
					 IN_LENGTH_SHORT_Z const int certIDlength,
					 IN_BUFFER_OPT( reqCertIDlength ) const char *reqCertID, 
					 IN_LENGTH_SHORT_Z const int reqCertIDlength,
					 IN_BUFFER_OPT( authCertIDlength ) const char *authCertID, 
					 IN_LENGTH_SHORT_Z const int authCertIDlength,
					 IN_BUFFER_OPT( pkiUserIDlength ) const char *pkiUserID, 
					 IN_LENGTH_SHORT_Z const int pkiUserIDlength,
					 IN_BUFFER_OPT( dataLength ) const void *data, 
					 IN_LENGTH_SHORT_Z const int dataLength, 
					 IN_ENUM( DBMS_UPDATE ) const DBMS_UPDATE_TYPE updateType )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE + 8 ];
	char certIDbuffer[ ENCODED_DBXKEYID_SIZE + 8 ];
	char encodedCertData[ MAX_ENCODED_CERT_SIZE + 8 ];
	const time_t boundDate = getTime( GETTIME_NOFAIL );
	int localCertIDlength = certIDlength, sqlOffset, sqlLength;
	int boundDataIndex, result, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( ( certID == NULL && certIDlength == 0 ) || \
			isReadPtrDynamic( certID, certIDlength ) );
	assert( ( reqCertID == NULL && reqCertIDlength == 0 ) || \
			isReadPtrDynamic( reqCertID, reqCertIDlength ) );
	assert( ( authCertID == NULL && authCertIDlength == 0 ) || \
			isReadPtrDynamic( authCertID, authCertIDlength ) );
	assert( ( pkiUserID == NULL && pkiUserIDlength == 0 ) || \
			isReadPtrDynamic( pkiUserID, pkiUserIDlength ) );
	assert( ( data == NULL && dataLength == 0 ) || \
			isReadPtrDynamic( data, dataLength ) );
	
	REQUIRES( isEnumRange( action, CRYPT_CERTACTION ) );
	REQUIRES( ( certID == NULL && certIDlength == 0 ) || \
			  ( certID != NULL && \
				isShortIntegerRangeNZ( certIDlength ) ) );
	REQUIRES( ( reqCertID == NULL && reqCertIDlength == 0 ) || \
			  ( reqCertID != NULL && \
				isShortIntegerRangeNZ( reqCertIDlength ) ) );
	REQUIRES( ( authCertID == NULL && authCertIDlength == 0 ) || \
			  ( authCertID != NULL && \
				isShortIntegerRangeNZ( authCertIDlength ) ) );
	REQUIRES( ( pkiUserID == NULL && pkiUserIDlength == 0 ) || \
			  ( pkiUserID != NULL && \
				isShortIntegerRangeNZ( pkiUserIDlength ) ) );
	REQUIRES( ( data == NULL && dataLength == 0 ) || \
			  ( data != NULL && \
				isShortIntegerRangeNZ( dataLength ) ) );
	REQUIRES( isEnumRange( updateType, DBMS_UPDATE ) );

	/* Build up the necessary SQL format string required to insert the log
	   entry.  This is complicated somewhat by the fact that some of the
	   values may be NULL so we have to insert them by naming the columns
	   (some databases allow the use of the DEFAULT keyword but this isn't
	   standardised enough to be safe) */
	status = strlcpy_s( sqlBuffer, MAX_SQL_QUERY_SIZE,
						"INSERT INTO certLog (action, actionTime, certID" );
	ENSURES( cryptStatusOK( status ) );
	if( reqCertID != NULL )
		{
		status = strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, ", reqCertID" );
		ENSURES( cryptStatusOK( status ) );
		}
	if( authCertID != NULL )
		{
		status = strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, ", authCertID" );
		ENSURES( cryptStatusOK( status ) );
		}
	if( pkiUserID != NULL )
		{
		status = strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, ", pkiUserID" );
		ENSURES( cryptStatusOK( status ) );
		}
	if( data != NULL )
		{
		status = strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, ", certData" );
		ENSURES( cryptStatusOK( status ) );
		}
	status = strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, ") VALUES (" );
	ENSURES( cryptStatusOK( status ) );
	sqlOffset = strnlen_s( sqlBuffer, MAX_SQL_QUERY_SIZE );
	REQUIRES( !checkOverflowSub( MAX_SQL_QUERY_SIZE, sqlOffset ) );
	sqlLength = MAX_SQL_QUERY_SIZE - sqlOffset;
	ENSURES( isShortIntegerRangeMin( sqlLength, 16 ) );
	result = sprintf_s( sqlBuffer + sqlOffset, sqlLength, "%d, ?, ?", 
						action );
	ENSURES( rangeCheck( result, 7, sqlLength - 1 ) );
	if( reqCertID != NULL )
		{
		status = strlcat_s( sqlBuffer + sqlOffset, sqlLength, ", ?" );
		ENSURES( cryptStatusOK( status ) );
		}
	if( authCertID != NULL )
		{
		status = strlcat_s( sqlBuffer + sqlOffset, sqlLength, ", ?" );
		ENSURES( cryptStatusOK( status ) );
		}
	if( pkiUserID != NULL )
		{
		status = strlcat_s( sqlBuffer + sqlOffset, sqlLength, ", ?" );
		ENSURES( cryptStatusOK( status ) );
		}
	if( data != NULL )
		{
		status = strlcat_s( sqlBuffer + sqlOffset, sqlLength, ", ?" );
		ENSURES( cryptStatusOK( status ) );
		}
	status = strlcat_s( sqlBuffer + sqlOffset, sqlLength, ")" );
	ENSURES( cryptStatusOK( status ) );

	/* If we're not worried about the certID we just insert a nonce value
	   which is used to meet the constraints for a unique entry.  In order
	   to ensure that it doesn't clash with a real certID we set the first
	   four characters to an out-of-band value */
	if( certID == NULL )
		{
		status = generateNonceID( certIDbuffer, ENCODED_DBXKEYID_SIZE );
		if( cryptStatusError( status ) )
			{
			/* Normally this is a should-never-occur error, however if
			   cryptlib has been shut down from another thread the kernel
			   will fail all non shutdown-related calls with a permission
			   error.  To avoid false alarms, we mask out failures due to
			   permission errors */
			assert( ( status == CRYPT_ERROR_PERMISSION ) || DEBUG_WARN );
			if( updateType == DBMS_UPDATE_COMMIT )
				{
				/* We're exiting without concluding the update, roll back the
				   transaction */
				dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
				}
			return( status );
			}
		certID = certIDbuffer;
		localCertIDlength = ENCODED_DBXKEYID_SIZE;
		}

	/* Set up the parameter information and update the certificate store 
	   log */
	initBoundData( boundDataPtr );
	setBoundDataDate( boundDataPtr, 0, &boundDate );
	setBoundData( boundDataPtr, 1, certID, localCertIDlength );
	boundDataIndex = 2;
	if( reqCertID != NULL )
		{
		setBoundData( boundDataPtr, boundDataIndex++, reqCertID, 
					  reqCertIDlength );
		}
	if( authCertID != NULL )
		{
		setBoundData( boundDataPtr, boundDataIndex++, authCertID, 
					  authCertIDlength );
		}
	if( pkiUserID != NULL )
		{
		setBoundData( boundDataPtr, boundDataIndex++, pkiUserID, 
					  pkiUserIDlength );
		}
	if( data != NULL )
		{
		if( hasBinaryBlobs( dbmsInfo ) )
			{
			setBoundDataBlob( boundDataPtr, boundDataIndex, 
							  data, dataLength );
			}
		else
			{
			int encodedDataLength;

			status = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE,
								   &encodedDataLength, data, dataLength, 
								   CRYPT_CERTTYPE_NONE );
			if( cryptStatusError( status ) )
				{
				DEBUG_DIAG(( "Couldn't base64-encode data" ));
				assert( DEBUG_WARN );
				if( updateType == DBMS_UPDATE_COMMIT )
					{
					/* We're exiting without concluding the update, roll 
					   back the transaction */
					dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
					}
				return( status );
				}
			setBoundData( boundDataPtr, boundDataIndex, 
						  encodedCertData, encodedDataLength );
			}
		}
	status = dbmsUpdate( sqlBuffer, boundDataPtr, updateType );
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "updateCertLog() returned status %d", status ));
		assert( DEBUG_WARN );
		}
	return( status );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int updateCertLog( INOUT_PTR DBMS_INFO *dbmsInfo, 
				   IN_ENUM( CRYPT_CERTACTION ) const CRYPT_CERTACTION_TYPE action, 
				   IN_BUFFER_OPT( certIDlength ) const char *certID, 
				   IN_LENGTH_SHORT_Z const int certIDlength,
				   IN_BUFFER_OPT( reqCertIDlength ) const char *reqCertID, 
				   IN_LENGTH_SHORT_Z const int reqCertIDlength,
				   IN_BUFFER_OPT( dataLength ) const void *data, 
				   IN_LENGTH_SHORT_Z const int dataLength, 
				   IN_ENUM( DBMS_UPDATE ) const DBMS_UPDATE_TYPE updateType )
	{
	return( updateCertLogEx( dbmsInfo, action, certID, certIDlength, 
							 reqCertID, reqCertIDlength, NULL, 0, NULL, 0,
							 data, dataLength, updateType ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int updateCertErrorLogEx( INOUT_PTR DBMS_INFO *dbmsInfo, 
						  IN_ERROR const int errorStatus,
						  IN_STRING const char *errorString, 
						  IN_BUFFER_OPT( certIDlength ) const char *certID, 
						  IN_LENGTH_SHORT_Z const int certIDlength,
						  IN_BUFFER_OPT( reqCertIDlength ) const char *reqCertID, 
						  IN_LENGTH_SHORT_Z const int reqCertIDlength )
	{
	STREAM stream;
	BYTE errorData[ 64 + MAX_CERT_SIZE + 8 ];
	char nonceIDbuffer[ ENCODED_DBXKEYID_SIZE + 8 ];
	const char *nonceIDptr = nonceIDbuffer;
	const int errorStringLength = strnlen_s( errorString, MAX_ERRMSG_SIZE );
	int errorDataLength DUMMY_INIT, nonceIdLength = ENCODED_DBXKEYID_SIZE;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( ( certID == NULL && certIDlength == 0 ) || \
			isReadPtrDynamic( certID, certIDlength ) );
	assert( ( reqCertID == NULL && reqCertIDlength == 0 ) || \
			isReadPtrDynamic( reqCertID, reqCertIDlength ) );

	ANALYSER_HINT_STRING( errorString );

	REQUIRES( cryptStatusError( errorStatus ) );
	REQUIRES( errorString != NULL && \
			  rangeCheck( errorStringLength, 1, MAX_ERRMSG_SIZE ) );
	REQUIRES( ( certID == NULL && certIDlength == 0 ) || \
			  ( certID != NULL && certIDlength == ENCODED_DBXKEYID_SIZE ) );
	REQUIRES( ( reqCertID == NULL && reqCertIDlength == 0 ) || \
			  ( reqCertID != NULL && reqCertIDlength == ENCODED_DBXKEYID_SIZE ) );

	/* Encode the error information:

		SEQUENCE {
			errorStatus	INTEGER,
			errorString	UTF8String,
			certData	ANY OPTIONAL
			} 

	   Note that the buffer we use is slightly larger than MAX_CERT_SIZE in 
	   order to accommodate the error status information alongside the 
	   largest possible certificate, in theory this means that if the database
	   back-end doesn't support binary blobs there won't be enough room in
	   the logging code to text-encode this worst-case scenario, but the use
	   of non-binary-blob capable database should be fairly rare so it's 
	   easier to just rely on the logging code to catch this unlikely 
	   scenario than to try and special-case around it */
	sMemOpen( &stream, errorData, 64 + MAX_CERT_SIZE );
	writeSequence( &stream, sizeofShortInteger( -errorStatus ) + \
							sizeofShortObject( errorStringLength ) );
	writeShortInteger( &stream, -errorStatus, DEFAULT_TAG );
	status = writeCharacterString( &stream, errorString, errorStringLength,
								   BER_STRING_UTF8 );
	if( cryptStatusOK( status ) )
		status = errorDataLength = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		sMemOpen( &stream, errorData, 64 + MAX_CERT_SIZE );
		writeSequence( &stream, sizeofObject( 1 ) + sizeofObject( 31 ) );
		writeShortInteger( &stream, -( CRYPT_ERROR_FAILED ), DEFAULT_TAG );
		status = writeCharacterString( &stream, 
									   "Error writing error information", 31,
									   BER_STRING_UTF8 );
		if( cryptStatusOK( status ) )
			status = errorDataLength = stell( &stream );
		sMemDisconnect( &stream );
		}
	ENSURES( !cryptStatusError( status ) );
	ENSURES( isShortIntegerRangeNZ( errorDataLength ) );

	/* Since the certID that we're recording will almost certainly already 
	   be present from an existing transaction, we replace it with a nonce
	   value that (probabilistically) won't collide with an existing ID */
	status = generateNonceID( nonceIDbuffer, ENCODED_DBXKEYID_SIZE );
	if( cryptStatusOK( status ) )
		memcpy( nonceIDbuffer, "ERR", 3 );
	else
		{
		/* Fall back to having updateCertLogEx() generate the nonce ID for 
		   us.  Since our call to generateNonceID() has failed the one there
		   will probably fail as well, but it'll go through the database
		   transaction cleanup path in that case */
		nonceIDptr = NULL;
		nonceIdLength = 0;
		}

	/* Update the certificate store log with the error information as the 
	   data value */
	return( updateCertLogEx( dbmsInfo, CRYPT_CERTACTION_ERROR, 
							 nonceIDptr, nonceIdLength, 
							 certID, certIDlength, 
							 reqCertID, reqCertIDlength, NULL, 0,
							 errorData, errorDataLength, 
							 DBMS_UPDATE_NORMAL ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int updateCertErrorLog( INOUT_PTR DBMS_INFO *dbmsInfo, 
						IN_ERROR const int errorStatus,
						IN_STRING const char *errorString, 
						IN_BUFFER_OPT( certIDlength ) const char *certID, 
						IN_LENGTH_SHORT_Z const int certIDlength )
	{
	return( updateCertErrorLogEx( dbmsInfo, errorStatus, errorString,
								  certID, certIDlength, NULL, 0 ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int updateCertErrorLogMsg( INOUT_PTR DBMS_INFO *dbmsInfo, 
						   IN_ERROR const int errorStatus,
						   IN_STRING const char *errorString )
	{
	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	return( updateCertErrorLogEx( dbmsInfo, errorStatus, errorString,
								  NULL, 0, NULL, 0 ) );
	}

/****************************************************************************
*																			*
*							Miscellaneous CA Functions						*
*																			*
****************************************************************************/

/* Get the PKI user that originally authorised the issuance of a certificate.  
   This can involve chaining back through multiple generations of 
   certificates, for example to check authorisation on a revocation request 
   we might have to go through:

	rev_req:	get reqCertID = update_req
	update_req:	get reqCertID = cert_req
	cert_req:	get reqCertID = init_req
	init_req:	get reqCertID = pki_user */

#if 0	/* 8/9/26 No longer necessary as of 3.4.9.6 with the pkiUser stored 
				  alongside the certID, also no longer works with the change
				  in log structure, the first fetch goes from certificate ->
				  request, the second from request -> requestor but this is 
				  now stored as the pkiUserID, not the reqCertID */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int caGetIssuingUser( INOUT_PTR DBMS_INFO *dbmsInfo, 
					  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iPkiUser,
					  IN_BUFFER( initialCertIDlength ) const char *initialCertID, 
					  IN_LENGTH_FIXED( ENCODED_DBXKEYID_SIZE ) \
							const int initialCertIDlength, 
					  INOUT_PTR ERROR_INFO *errorInfo )
	{
	char certID[ ENCODED_DBXKEYID_SIZE + 8 ];
	LOOP_INDEX chainingLevel;
	int certIDlength, dummy, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isWritePtr( iPkiUser, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtr( initialCertID, ENCODED_DBXKEYID_SIZE ) );

	REQUIRES( initialCertIDlength == ENCODED_DBXKEYID_SIZE );
	REQUIRES( errorInfo != NULL );

	/* Clear return value */
	*iPkiUser = CRYPT_ERROR;

	/* Walk through the chain of updates in the certificate store log until 
	   we find the PKI user that authorised the first certificate issue */
	REQUIRES( rangeCheck( initialCertIDlength, 1, ENCODED_DBXKEYID_SIZE ) );
	memcpy( certID, initialCertID, initialCertIDlength );
	certIDlength = initialCertIDlength;
	LOOP_MED( chainingLevel = 0, chainingLevel < 32, chainingLevel++ )
		{
		BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ];
		BOUND_DATA *boundDataPtr = boundData;
		BYTE certData[ MAX_QUERY_RESULT_SIZE + 8 ];
		int certDataLength;

		ENSURES( LOOP_INVARIANT_MED( chainingLevel, 0, 31 ) );

		/* Find out whether this is a PKI user.  The comparison for the
		   action type is a bit odd since some back-ends will return the
		   action as text and some as a binary numeric value.  Rather than
		   relying on the back-end glue code to perform the appropriate
		   conversion we just check for either value type */
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, certID, certIDlength );
		status = dbmsQuery(
			"SELECT action FROM certLog WHERE certID = ?",
							certData, MAX_QUERY_RESULT_SIZE, &certDataLength, 
							boundDataPtr, DBMS_CACHEDQUERY_NONE, 
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		if( certData[ 0 ] == CRYPT_CERTACTION_ADDUSER || \
			certData[ 0 ] == TEXTCH_CERTACTION_ADDUSER )
			{
			/* We've found the PKI user, we're done */
			break;
			}

		/* Find the certificate that was issued, recorded either as a
		   CERTACTION_CERT_CREATION for a multi-phase CMP-based certificate
		   creation or a CERTACTION_ISSUE_CERT for a one-step creation */
		status = dbmsQuery(
			"SELECT reqCertID FROM certLog WHERE certID = ?",
							certData, MAX_QUERY_RESULT_SIZE, &certDataLength, 
							boundDataPtr, DBMS_CACHEDQUERY_NONE, 
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		certIDlength = min( certDataLength, ENCODED_DBXKEYID_SIZE );
		REQUIRES( rangeCheck( certIDlength, 1, ENCODED_DBXKEYID_SIZE ) );
		memcpy( certID, certData, certIDlength );

		/* Find the request to issue this certificate.  For a CMP-based issue
		   this will have an authorising object (found in the next iteration
		   through the loop), for a one-step issue it won't */
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, certID, certIDlength );
		status = dbmsQuery(
			"SELECT reqCertID FROM certLog WHERE certID = ?",
							certData, MAX_QUERY_RESULT_SIZE, &certDataLength, 
							boundDataPtr, DBMS_CACHEDQUERY_NONE, 
							DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		certIDlength = min( certDataLength, ENCODED_DBXKEYID_SIZE );
		REQUIRES( rangeCheck( certIDlength, 1, ENCODED_DBXKEYID_SIZE ) );
		memcpy( certID, certData, certIDlength );
		}
	ENSURES( LOOP_BOUND_OK );
	if( chainingLevel >= 32 )
		{
		/* We've chained through too many entries, bail out */
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* We've found the original PKI user, get the user information */
	return( getItemData( dbmsInfo, iPkiUser, &dummy, KEYMGMT_ITEM_PKIUSER,
						 CRYPT_IKEYID_CERTID, certID, certIDlength, 
						 KEYMGMT_FLAG_NONE, errorInfo ) );
	}
#else

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int caGetIssuingUser( INOUT_PTR DBMS_INFO *dbmsInfo, 
					  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iPkiUser,
					  IN_BUFFER( certIDlength ) const char *certID, 
					  IN_LENGTH_FIXED( ENCODED_DBXKEYID_SIZE ) \
							const int certIDlength, 
					  INOUT_PTR ERROR_INFO *errorInfo )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ];
	BOUND_DATA *boundDataPtr = boundData;
	char pkiUserID[ MAX_QUERY_RESULT_SIZE + 8 ];
	int pkiUserIDlength, dummy, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isWritePtr( iPkiUser, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtr( certID, ENCODED_DBXKEYID_SIZE ) );

	REQUIRES( certIDlength == ENCODED_DBXKEYID_SIZE );
	REQUIRES( errorInfo != NULL );

	/* Clear return value */
	*iPkiUser = CRYPT_ERROR;

	/* Get the PKI user that originally authorised the issuance of a 
	   certificate */
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, certID, certIDlength );
	status = dbmsQuery( "SELECT pkiUserID FROM certLog WHERE certID = ?",
						pkiUserID, MAX_QUERY_RESULT_SIZE, &pkiUserIDlength, 
						boundDataPtr, DBMS_CACHEDQUERY_NONE, 
						DBMS_QUERY_NORMAL );
	if( cryptStatusError( status ) )
		return( status );
	if( pkiUserIDlength > ENCODED_DBXKEYID_SIZE )
		pkiUserIDlength = ENCODED_DBXKEYID_SIZE;

	/* Get the PKI user for the given certificate */
	return( getItemData( dbmsInfo, iPkiUser, &dummy, KEYMGMT_ITEM_PKIUSER,
						 CRYPT_IKEYID_CERTID, pkiUserID, pkiUserIDlength, 
						 KEYMGMT_FLAG_NONE, errorInfo ) );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*						CA Certificate Management Interface					*
*																			*
****************************************************************************/

/* Perform a certificate management operation */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int certMgmtFunction( INOUT_PTR KEYSET_INFO *keysetInfoPtr,
							 OUT_OPT_HANDLE_OPT \
								CRYPT_CERTIFICATE *iCertificate,
							 IN_HANDLE_OPT const CRYPT_CERTIFICATE caKey,
							 IN_HANDLE_OPT const CRYPT_CERTIFICATE request,
							 IN_HANDLE_OPT \
								const CRYPT_CERTIFICATE iAuthCert,
							 IN_HANDLE_OPT \
								const CRYPT_CERTIFICATE iPkiUser,
							 IN_ENUM( CRYPT_CERTACTION ) \
								const CRYPT_CERTACTION_TYPE action,
							 IN_ENUM_OPT( CERTMGMT_OPTION ) \
								const CERTMGMT_OPTION_TYPE option )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	DBMS_INFO *dbmsInfo = DATAPTR_GET( keysetInfoPtr->keysetInfo );
	char reqCertID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int reqCertIDlength, status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );
	assert( ( iCertificate == NULL ) || \
			isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( sanityCheckKeyset( keysetInfoPtr ) );
	REQUIRES( keysetInfoPtr->type == KEYSET_DBMS );
	REQUIRES( ( action != CRYPT_CERTACTION_ISSUE_CRL && 
				action != CRYPT_CERTACTION_CERT_CREATION ) || \
			  ( ( action == CRYPT_CERTACTION_ISSUE_CRL || \
				  action == CRYPT_CERTACTION_CERT_CREATION ) && \
				iCertificate != NULL ) );
			  /* An ISSUE_CERT can have iCertificate == NULL, which leaves
			     the issued certificate in the store without returning it
				 to the caller */
	REQUIRES( caKey == CRYPT_UNUSED || isHandleRangeValid( caKey ) );
	REQUIRES( request == CRYPT_UNUSED || isHandleRangeValid( request ) );
	REQUIRES( iAuthCert == CRYPT_UNUSED || isHandleRangeValid( iAuthCert ) );
	REQUIRES( iPkiUser == CRYPT_UNUSED || isHandleRangeValid( iPkiUser ) );
	REQUIRES( isEnumRange( action, CRYPT_CERTACTION ) );
	REQUIRES( isEnumRangeOpt( option, CERTMGMT_OPTION ) );
	REQUIRES( dbmsInfo != NULL );

	/* In order for various SQL query strings to use the correct values the
	   type values have to match their text equivalents defined at the start
	   of this file.  Since we can't check this at compile time we have to
	   do it here via an assertion */
	static_assert_opt( TEXT_CERTTYPE_REQUEST_CERT[ 0 ] - '0' == \
							CRYPT_CERTTYPE_REQUEST_CERT, \
					   "SQL data type" );
	static_assert_opt( TEXT_CERTTYPE_REQUEST_REVOCATION[ 0 ] - '0' == \
							CRYPT_CERTTYPE_REQUEST_REVOCATION, \
					   "SQL data type" );
	static_assert_opt( TEXT_CERTACTION_CREATE[ 0 ] - '0' == \
							CRYPT_CERTACTION_CREATE, \
					   "SQL data type" );
	static_assert( TEXTCH_CERTACTION_ADDUSER - '0' == \
						CRYPT_CERTACTION_ADDUSER, \
				   "SQL data type" );
	static_assert_opt( TEXT_CERTACTION_REQUEST_CERT[ 0 ] - '0' == \
							CRYPT_CERTACTION_REQUEST_CERT, \
					   "SQL data type" );
	static_assert( TEXTCH_CERTACTION_REQUEST_CERT - '0' == \
						CRYPT_CERTACTION_REQUEST_CERT, \
				   "SQL data type" );
	static_assert_opt( TEXT_CERTACTION_REQUEST_RENEWAL[ 0 ] - '0' == \
							CRYPT_CERTACTION_REQUEST_RENEWAL, \
					   "SQL data type" );
	static_assert( TEXTCH_CERTACTION_REQUEST_RENEWAL - '0' == \
						CRYPT_CERTACTION_REQUEST_RENEWAL, \
				   "SQL data type" );
	static_assert_opt( TEXT_CERTACTION_CERT_CREATION[ 0 ] - '0' == \
							CRYPT_CERTACTION_CERT_CREATION / 10, \
					   "SQL data type" );
	static_assert_opt( TEXT_CERTACTION_CERT_CREATION[ 1 ] - '0' == \
							CRYPT_CERTACTION_CERT_CREATION % 10, \
					   "SQL data type" );

	/* Clear return value */
	if( iCertificate != NULL )
		*iCertificate = CRYPT_ERROR;

	/* If it's a simple certificate expire or cleanup, there are no 
	   parameters to check so we can perform the action immediately */
	if( action == CRYPT_CERTACTION_EXPIRE_CERT || \
		action == CRYPT_CERTACTION_CLEANUP )
		{
		REQUIRES( caKey == CRYPT_UNUSED );
		REQUIRES( request == CRYPT_UNUSED );
		REQUIRES( iAuthCert == CRYPT_UNUSED );
		REQUIRES( iPkiUser == CRYPT_UNUSED );

		return( caCleanup( dbmsInfo, action, KEYSET_ERRINFO ) );
		}

	/* If it's the completion of a certificate creation, process it */
	if( action == CRYPT_CERTACTION_CERT_CREATION_COMPLETE || \
		action == CRYPT_CERTACTION_CERT_CREATION_DROP || \
		action == CRYPT_CERTACTION_CERT_CREATION_REVERSE )
		{
		REQUIRES( caKey == CRYPT_UNUSED );
		REQUIRES( isHandleRangeValid( request ) );
		REQUIRES( iAuthCert == CRYPT_UNUSED || isHandleRangeValid( iAuthCert ) );
		REQUIRES( isHandleRangeValid( iPkiUser ) );

		return( caIssueCertComplete( dbmsInfo, request, iAuthCert, iPkiUser, 
									 action, KEYSET_ERRINFO ) );
		}

	/* If it's a CRL issue it's a read-only operation on the CRL store for 
	   which we only need the CA certificate (there's no request involved) */
	if( action == CRYPT_CERTACTION_ISSUE_CRL )
		{
		int value;

		REQUIRES( isHandleRangeValid( caKey ) );
		REQUIRES( request == CRYPT_UNUSED );
		REQUIRES( iAuthCert == CRYPT_UNUSED );
		REQUIRES( iPkiUser == CRYPT_UNUSED );

		/* If we're issuing a CRL, the key must be capable of CRL signing */
		status = krnlSendMessage( caKey, IMESSAGE_GETATTRIBUTE, &value,
								  CRYPT_CERTINFO_KEYUSAGE );
		if( cryptStatusError( status ) || \
			!( value & CRYPT_KEYUSAGE_CRLSIGN ) )
			{
			retExtArg( CAMGMT_ARGERROR_CAKEY, 
					   ( CAMGMT_ARGERROR_CAKEY, KEYSET_ERRINFO, 
						 "CA certificate isn't valid for CRL signing" ) );
			}

		return( caIssueCRL( dbmsInfo, iCertificate, caKey, KEYSET_ERRINFO ) );
		}

	/* For anything other than a revocation action (which just updates the 
	   certificate store without doing anything else) or an add-user action 
	   the key must be a CA key.  These checks are performed automatically 
	   during the issue process by the kernel when we try and convert the 
	   request into a certificate, however we perform them explicitly here 
	   so that we can return a more meaningful error message to the caller */
	if( action != CRYPT_CERTACTION_REVOKE_CERT && \
		action != CRYPT_CERTACTION_ADDREQUEST )
		{
		REQUIRES( isHandleRangeValid( caKey ) );

		if( !checkContextCapability( caKey, MESSAGE_CHECK_PKC_SIGN_CA ) )
			{
			retExtArg( CAMGMT_ARGERROR_CAKEY, 
					   ( CAMGMT_ARGERROR_CAKEY, KEYSET_ERRINFO, 
						 "CA certificate isn't valid for certificate "
						 "signing" ) );
			}
		}

	/* Beyond this point we need to be working with a valid request */
	REQUIRES( isHandleRangeValid( request ) );

	/* We're processing an action that requires an explicit certificate 
	   request, perform further checks on the request */
	if( !checkRequest( request, action ) )
		{
		retExtArg( CAMGMT_ARGERROR_REQUEST, 
				   ( CAMGMT_ARGERROR_REQUEST, KEYSET_ERRINFO, 
					 "Certificate request information "
					 "inconsistent/invalid" ) );
		}

	/* If we're just adding a request, add it and exit */
	if( action == CRYPT_CERTACTION_ADDREQUEST )
		{
		return( caAddCertRequest( dbmsInfo, request, iAuthCert, iPkiUser, 
								  option, KEYSET_ERRINFO ) );
		}

	/* Make sure that the request is present in the request table in order 
	   to issue a certificate for it.  Again, this will be checked later but 
	   we can return a more meaningful error here */
	status = getKeyID( reqCertID, ENCODED_DBXKEYID_SIZE, &reqCertIDlength, 
					   request, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusError( status ) )
		return( CAMGMT_ARGERROR_REQUEST );
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, reqCertID, reqCertIDlength );
	status = dbmsQuery(
		"SELECT certData FROM certRequests WHERE certID = ?",
						NULL, 0, NULL, boundDataPtr, 
						DBMS_CACHEDQUERY_NONE, DBMS_QUERY_CHECK );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_NOTFOUND, 
				( CRYPT_ERROR_NOTFOUND, KEYSET_ERRINFO, 
				  "Certificate request doesn't correspond to any existing "
				  "request in the certificate store" ) );
		}

	/* If it's a revocation request, process it */
	if( action == CRYPT_CERTACTION_REVOKE_CERT )
		{
		REQUIRES( caKey == CRYPT_UNUSED );
		REQUIRES( iAuthCert == CRYPT_UNUSED || isHandleRangeValid( iAuthCert ) );
		REQUIRES( isHandleRangeValid( iPkiUser ) );

		return( caRevokeCert( dbmsInfo, request, CRYPT_UNUSED, iAuthCert,
							  iPkiUser, CRYPT_CERTACTION_REVOKE_CERT, 
							  KEYSET_ERRINFO ) );
		}

	/* It's a certificate issue request, issue the certificate */
	REQUIRES( action == CRYPT_CERTACTION_ISSUE_CERT || \
			  action == CRYPT_CERTACTION_CERT_CREATION );
	REQUIRES( isHandleRangeValid( caKey ) );
	REQUIRES( iAuthCert == CRYPT_UNUSED || isHandleRangeValid( iAuthCert ) );
	REQUIRES( iPkiUser == CRYPT_UNUSED || isHandleRangeValid( iPkiUser ) );

	return( caIssueCert( dbmsInfo, iCertificate, caKey, request, 
						 iAuthCert, iPkiUser, action, option, 
						 KEYSET_ERRINFO ) );
	}

/* Set up the function pointers to the keyset methods */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initDBMSCA( INOUT_PTR KEYSET_INFO *keysetInfoPtr )
	{
	DBMS_INFO *dbmsInfo = DATAPTR_GET( keysetInfoPtr->keysetInfo );

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_DBMS );
	REQUIRES( sanityCheckKeyset( keysetInfoPtr ) );
	REQUIRES( dbmsInfo != NULL );

	dbmsInfo->certMgmtFunction = certMgmtFunction;

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
