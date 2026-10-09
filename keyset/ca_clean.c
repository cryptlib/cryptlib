/****************************************************************************
*																			*
*					  cryptlib DBMS CA Cleanup Interface					*
*						Copyright Peter Gutmann 1996-2025					*
*																			*
****************************************************************************/

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

/* When we iterate through the entries in the certificate store we have to 
   protect ourselves against repeatedly fetching the same value over and 
   over again if there's a problem with the certificate store, which we do 
   by remembering data from the previous certificate that we fetched.  The 
   following value defines the amount of certificate data that we record */

#define MAX_PREVCERT_DATA	128

#ifdef USE_DBMS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Delete a certificate request or partially-issued certificated if a 
   cleanup operation for it failed, recording the failure details in the 
   log */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
static int deleteIncompleteRequest( INOUT_PTR DBMS_INFO *dbmsInfo,
									IN_BUFFER( reqCertIDlength ) \
										const char *reqCertID, 
									IN_LENGTH_SHORT_Z const int reqCertIDlength, 
									IN_ERROR const int errorStatus,
									IN_STRING const char *reasonMessage )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isReadPtrDynamic( reqCertID, reqCertIDlength ) );

	ANALYSER_HINT_STRING( reasonMessage );

	REQUIRES( isShortIntegerRangeNZ( reqCertIDlength ) );
	REQUIRES( cryptStatusError( errorStatus ) );

	/* Delete the request and record the cause */
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, reqCertID, reqCertIDlength );
	status = dbmsUpdate( 
				"DELETE FROM certRequests WHERE certID = ?",
						 boundDataPtr, DBMS_UPDATE_NORMAL );
	updateCertErrorLog( dbmsInfo, errorStatus, reasonMessage, 
						reqCertID, reqCertIDlength );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int deleteIncompleteCert( INOUT_PTR DBMS_INFO *dbmsInfo,
								 IN_BUFFER( incompleteCertIDlength ) \
									const char *incompleteCertID, 
								 IN_LENGTH_SHORT_Z \
									const int incompleteCertIDlength, 
								 IN_BOOL const BOOLEAN isRenewal,
								 IN_ERROR const int errorStatus,
								 IN_STRING const char *reasonMessage )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	BYTE certID[ MAX_QUERY_RESULT_SIZE + 8 ];
	const BYTE *certIDptr = incompleteCertID;
	int certIDlength = incompleteCertIDlength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( incompleteCertIDlength == 0 || \
			isReadPtrDynamic( incompleteCertID, incompleteCertIDlength ) );

	ANALYSER_HINT_STRING( reasonMessage );

	REQUIRES( isBooleanValue( isRenewal ) );
	REQUIRES( cryptStatusError( errorStatus ) );

	/* We should have got the certID from the initial getNextPartialCert() 
	   fetch that starts the attempted operation whose failure we're trying 
	   to recover from, but if not we have to fall back to the same general 
	   SELECT that that function used.  This isn't 100% safe since in theory 
	   the second SELECT here won't return rows in the same order as the 
	   first one, but every tested backend does and we're also now into the 
	   same should-never-occur territory (if the getNextPartialCert() SELECT
	   failed then the following one should fail too) that makes it 
	   difficult to pick a good option */
	if( incompleteCertIDlength == 0 )
		{
		status = dbmsQuery( isRenewal ? \
				"SELECT certID FROM certificates WHERE keyID LIKE " CERTID_LIKE_CERTISSUE_RENEW : \
				"SELECT certID FROM certificates WHERE keyID LIKE " CERTID_LIKE_CERTISSUE_STD,
						certID, MAX_QUERY_RESULT_SIZE, &certIDlength, NULL, 
						DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
		if( cryptStatusError( status ) )
			return( status );
		if( certIDlength > ENCODED_DBXKEYID_SIZE )
			certIDlength = ENCODED_DBXKEYID_SIZE;
		certIDptr = certID;
		}

	/* Delete the request and record the cause */
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, certIDptr, certIDlength );
	status = dbmsUpdate( 
				"DELETE FROM certificates WHERE certID = ?",
						 boundDataPtr, DBMS_UPDATE_NORMAL );
	updateCertErrorLog( dbmsInfo, errorStatus, reasonMessage, 
						certIDptr, certIDlength );
	return( status );
	}

/* Get a partially-issued certificate.  We have to perform the import
   ourselves since it's marked as an incompletely-issued certificate and so 
   is invisible to accesses performed via the standard certificate fetch 
   routines */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5, 6, 9 ) ) \
static int getNextPartialCert( INOUT_PTR DBMS_INFO *dbmsInfo,
							   OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertificate,
							   OUT_BUFFER( certIdMaxLen, *certIdLength ) \
									char *certID, 
							   IN_LENGTH_SHORT_MIN( ENCODED_DBXKEYID_SIZE ) \
									const int certIdMaxLen,
							   OUT_LENGTH_BOUNDED_Z( certIdMaxLen ) \
									int *certIdLength,
							   INOUT_BUFFER_FIXED( prevCertDataMaxLen ) \
									BYTE *prevCertData, 
							   IN_LENGTH_FIXED( MAX_PREVCERT_DATA ) \
									const int prevCertDataMaxLen, 
							   IN_BOOL const BOOLEAN isRenewal,
							   INOUT_PTR ERROR_INFO *errorInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE certData[ MAX_QUERY_RESULT_SIZE + 8 ];
	char encodedCertData[ MAX_QUERY_RESULT_SIZE + 8 ];
	void *certPtr = hasBinaryBlobs( dbmsInfo ) ? \
					( void * ) certData : encodedCertData;
	int certDataLength, status;		/* Cast needed for gcc */

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isWritePtrDynamic( certID, certIdMaxLen ) );
	assert( isWritePtr( certIdLength, sizeof( int ) ) );
	assert( isWritePtrDynamic( prevCertData, prevCertDataMaxLen ) );

	REQUIRES( isShortIntegerRangeMin( certIdMaxLen, 
									  ENCODED_DBXKEYID_SIZE ) );
	REQUIRES( prevCertDataMaxLen == MAX_PREVCERT_DATA );
	REQUIRES( isBooleanValue( isRenewal ) );

	/* Clear return values */
	*iCertificate = CRYPT_ERROR;
	REQUIRES( isShortIntegerRangeNZ( certIdMaxLen ) ); 
	memset( certID, 0, min( 16, certIdMaxLen ) );
	*certIdLength = 0;

	/* Find the next certificate and import it.  Although this would appear 
	   to be fetching the same certificate over and over again, the caller 
	   will be deleting the currently-fetched certificate after we return it 
	   to them so in practice it fetches a new certificate each time.  To
	   ensure that this is the case we also perform a duplicate check on the 
	   prevCertData once we've fetched the next certificate so we'll detect 
	   any looping */
	status = dbmsQuery( isRenewal ? \
				"SELECT certID FROM certificates WHERE keyID LIKE " CERTID_LIKE_CERTISSUE_RENEW : \
				"SELECT certID FROM certificates WHERE keyID LIKE " CERTID_LIKE_CERTISSUE_STD,
						certData, MAX_QUERY_RESULT_SIZE, &certDataLength, 
						NULL, DBMS_CACHEDQUERY_NONE, DBMS_QUERY_NORMAL );
	if( cryptStatusOK( status ) )
		{
		BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ];
		BOUND_DATA *boundDataPtr = boundData;

		/* Remember the certID for the caller */
		if( certDataLength > ENCODED_DBXKEYID_SIZE )
			certDataLength = ENCODED_DBXKEYID_SIZE;
		ENSURES( rangeCheck( certDataLength, 1, certIdMaxLen ) );
		memcpy( certID, certData, certDataLength );
		*certIdLength = certDataLength;

		/* Fetch the certificate data */
		initBoundData( boundDataPtr );
		setBoundData( boundDataPtr, 0, certID, *certIdLength );
		status = dbmsQuery( 
				"SELECT certData FROM certificates WHERE certID = ?",
							certPtr, 
							hasBinaryBlobs( dbmsInfo ) ? \
								MAX_CERT_SIZE : MAX_QUERY_RESULT_SIZE,
							&certDataLength, boundDataPtr, 
							DBMS_CACHEDQUERY_CERTID, DBMS_QUERY_NORMAL );
		}
	if( cryptStatusError( status ) )
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );

		/* We've processed all of the entries, this isn't an error */
		resetErrorInfo( dbmsInfo );
		return( OK_SPECIAL );
		}
	if( !hasBinaryBlobs( dbmsInfo ) )
		{
		status = base64decode( certData, MAX_CERT_SIZE, &certDataLength,
							   encodedCertData, certDataLength, 
							   CRYPT_CERTFORMAT_NONE );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "Couldn't base64-decode data" ));
			assert( DEBUG_WARN );
			return( status );
			}
		}

	/* If we're stuck in a loop fetching the same value over and over, make
	   an emergency exit */
	if( !memcmp( prevCertData, certData, \
				 min( certDataLength, prevCertDataMaxLen ) ) )
		{
		DEBUG_DIAG(( "Certificate-fetch loop detected" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_DUPLICATE );
		}
	memcpy( prevCertData, certData, 
			min( certDataLength, prevCertDataMaxLen ) );

	/* Reset the first byte of the certificate data from the not-present 
	   magic value to allow it to be imported and create a certificate from 
	   it */
	certData[ 0 ] = BER_SEQUENCE;
	setMessageCreateObjectIndirectInfo( &createInfo, certData, 
										certDataLength, 
										CRYPT_CERTTYPE_CERTIFICATE, 
										errorInfo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCertificate = createInfo.cryptHandle;
	return( status );
	}

/****************************************************************************
*																			*
*								CA Cleanup Functions						*
*																			*
****************************************************************************/

/* Perform a cleanup operation on the certificate store, removing 
   incomplete, expired, and otherwise leftover certificates.  Since we're 
   cleaning up the certificate store we try and continue even if an error 
   occurs, at least up to a limit.
   
   All of the cleanup loops here except for revocation requests for which 
   see the comments inline rely on a SELECT to find the next item to 
   process, if there's an error processing the item we fall back to a 
   straight delete in order to allow the loop to continue, i.e. to have
   the SELECT move on to fetching the next item to process */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int caCleanup( INOUT_PTR DBMS_INFO *dbmsInfo, 
			   IN_ENUM( CRYPT_CERTACTION ) const CRYPT_CERTACTION_TYPE action,
			   INOUT_PTR ERROR_INFO *errorInfo )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	BYTE certID[ MAX_QUERY_RESULT_SIZE + 8 ];
	BYTE prevCertID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BYTE prevCertData[ MAX_PREVCERT_DATA + 8 ];
	const time_t currentTime = getTime( GETTIME_NONE );
	LOOP_INDEX noEntriesProcessed, errorCount;
	int certIDlength, prevCertIDlength;
	int persistentErrorStatus = CRYPT_OK, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( action == CRYPT_CERTACTION_EXPIRE_CERT || \
			  action == CRYPT_CERTACTION_CLEANUP );
	REQUIRES( errorInfo != NULL );

	/* If the time is screwed up then we can't perform time-based cleanup
	   actions.  In theory this will prevent any cleanup from taking place 
	   if there's no system clock available but anything that can run an
	   RDBMS should also have a system clock */
	if( action == CRYPT_CERTACTION_EXPIRE_CERT && \
		currentTime <= MIN_TIME_VALUE )
		{
		assert( DEBUG_WARN );
		retExt( CRYPT_ERROR_FAILED,
				( CRYPT_ERROR_FAILED, errorInfo, 
				  "System time is broken, can't perform time-based "
				  "cleanup" ) );
		}

	/* Rumble through the certificate store either deleting leftover 
	   requests or expiring every certificate which is no longer current */
	memset( prevCertID, 0, ENCODED_DBXKEYID_SIZE );
	prevCertIDlength = 0;
	LOOP_LARGE( ( status = CRYPT_OK, errorCount = 0, noEntriesProcessed = 0 ),
				status != CRYPT_ERROR_NOTFOUND && errorCount < 5 && \
					noEntriesProcessed < 500,
				noEntriesProcessed++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( noEntriesProcessed, 0, 499 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( errorCount, 0, 4 ) );

		/* Find the certificate ID of the next expired certificate or next 
		   certificate request (revocation requests are handled later by 
		   completing the revocation).  Note that the select requires that 
		   the database glue code be capable of returning a single result 
		   and then finishing the query, in theory for some backends there 
		   may be a need to explicitly cancel the query after the first 
		   result is returned if the database returns an entire result set 
		   but so far no tested backend has required this */
		if( action == CRYPT_CERTACTION_EXPIRE_CERT )
			{
			initBoundData( boundDataPtr );
			setBoundDataDate( boundDataPtr, 0, &currentTime );
			status = dbmsQuery(
						"SELECT certID FROM certificates WHERE validTo < ?",
								certID, MAX_QUERY_RESULT_SIZE, &certIDlength, 
								boundDataPtr, DBMS_CACHEDQUERY_NONE, 
								DBMS_QUERY_NORMAL );
			}
		else
			{
			status = dbmsQuery(
						"SELECT certID FROM certRequests WHERE type = "
							TEXT_CERTTYPE_REQUEST_CERT,
								certID, MAX_QUERY_RESULT_SIZE, &certIDlength, 
								NULL, DBMS_CACHEDQUERY_NONE, 
								DBMS_QUERY_NORMAL );
			}
		if( cryptStatusError( status ) )
			{
			/* If we've processed all of the entries this isn't an error */
			if( status == CRYPT_ERROR_NOTFOUND )
				resetErrorInfo( dbmsInfo );
			else
				{
				REQUIRES( !checkOverflowInc( errorCount ) );
				errorCount++;
				}
			continue;
			}
		if( certIDlength > ENCODED_DBXKEYID_SIZE )
			certIDlength = ENCODED_DBXKEYID_SIZE;
		if( prevCertIDlength == certIDlength && \
			!memcmp( prevCertID, certID, certIDlength ) )
			{
			/* We're stuck in a loop fetching the same value over and over,
			   make an emergency exit */
			DEBUG_DIAG(( "Certificate-fetch loop detected" ));
			assert( DEBUG_WARN );
			break;
			}
		REQUIRES( rangeCheck( certIDlength, 1, ENCODED_DBXKEYID_SIZE ) );
		memcpy( prevCertID, certID, certIDlength );
		prevCertIDlength = certIDlength;

		/* Clean up/expire the certificate.  Since CRYPT_CERTACTION_CLEANUP 
		   is a composite action that encompasses a whole series of 
		   operations we replace it with a more specific action code.  In
		   addition we can't log the certID as such because an existing 
		   entry with that ID already exists when the item was added, so we
		   log it as the reqCertID instead */
		status = updateCertLog( dbmsInfo,
								( action == CRYPT_CERTACTION_CLEANUP ) ? \
								  CRYPT_CERTACTION_RESTART_CLEANUP : action,
								NULL, 0, certID, certIDlength, NULL, 0, 
								DBMS_UPDATE_BEGIN );
		if( cryptStatusOK( status ) )
			{
			initBoundData( boundDataPtr );
			setBoundData( boundDataPtr, 0, certID, certIDlength );
			status = dbmsUpdate( ( action == CRYPT_CERTACTION_EXPIRE_CERT ) ? \
				"DELETE FROM certificates WHERE certID = ?" : \
				"DELETE FROM certRequests WHERE certID = ?",
								 boundDataPtr, DBMS_UPDATE_COMMIT );
			}
		else
			{
			/* Something went wrong, abort the transaction */
			dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
			REQUIRES( !checkOverflowInc( errorCount ) );
			errorCount++;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	if( errorCount >= 5 || noEntriesProcessed >= 500 )
		{
		/* It's hard to tell what type of error an iterationCount-exceeded
		   situation really is, in theory it's a software error (either in
		   cryptlib's fetch logic or in the dabatase) but because we could be
		   cleaning up a large number of entries, for example if it's 
		   cleaning up the result of an app going into an endless loop and
		   requesting a large number of certificates, it's entirely possible 
		   that this is isn't an abnormal situation. Because of this we 
		   don't flag it as an internal error but simply warn in the debug 
		   build, although we do bail out after a fixed limit */
		DEBUG_DIAG(( "Certificate-fetch loop detected" ));
		assert( DEBUG_WARN );
		}

	/* If we ran into a problem, perform a fallback general delete of
	   entries that caused the problem */
	if( status != CRYPT_ERROR_NOTFOUND )
		{
		if( action == CRYPT_CERTACTION_EXPIRE_CERT )
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Expire operation "
								   "failed, performing fallback straight "
								   "delete" );
			initBoundData( boundDataPtr );
			setBoundDataDate( boundDataPtr, 0, &currentTime );
			status = dbmsUpdate(
						"DELETE FROM certificates WHERE validTo < ?",
								 boundDataPtr, DBMS_UPDATE_NORMAL );
			}
		else
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Certificate request "
								   "cleanup operation failed, performing "
								   "fallback straight delete" );
			status = dbmsStaticUpdate(
						"DELETE FROM certRequests WHERE type = "
							TEXT_CERTTYPE_REQUEST_CERT );
			}
		if( cryptStatusError( status ) )
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );

			/* The overall cleanup failed, let the caller know */
			persistentErrorStatus = status;
			}
		}

	/* If it's an expiry action we've done the expired certificates, now 
	   remove any stale CRL entries and exit.  If there are no CRL entries 
	   in the expiry period this isn't an error, so we remap the error code 
	   if necessary */
	if( action == CRYPT_CERTACTION_EXPIRE_CERT )
		{
		initBoundData( boundDataPtr );
		setBoundDataDate( boundDataPtr, 0, &currentTime );
		status = dbmsUpdate(
					"DELETE FROM CRLs WHERE expiryDate < ?",
							 boundDataPtr, DBMS_UPDATE_NORMAL );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			resetErrorInfo( dbmsInfo );
			return( CRYPT_OK );
			}
		if( cryptStatusError( status ) )
			{
			retExtErr( status, 
					   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
						 "Couldn't delete stale CRL entries from "
						 "certificate store" ) );
			}
		return( CRYPT_OK );
		}

	/* It's a restart, process any incompletely-issued certificates in the
	   same manner as the expiry/cleanup is handled.  Since we don't know at
	   what stage the issue process was interrupted we have to make a worst-
	   case assumption and do a full reversal as a compensating transaction
	   for an aborted certificate issue */
	memset( prevCertData, 0, MAX_PREVCERT_DATA );
	LOOP_LARGE( ( status = CRYPT_OK, errorCount = 0, noEntriesProcessed = 0 ),
				status != CRYPT_ERROR_NOTFOUND && errorCount < 5 && \
					noEntriesProcessed < 500,
				noEntriesProcessed++ )
		{
		CRYPT_CERTIFICATE iCertificate;

		ENSURES( LOOP_INVARIANT_LARGE( noEntriesProcessed, 0, 499 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( errorCount, 0, 4 ) );

		/* Get the next partially-issued certificate */
		status = getNextPartialCert( dbmsInfo, &iCertificate, certID, 
									 ENCODED_DBXKEYID_SIZE, &certIDlength, 
									 prevCertData, MAX_PREVCERT_DATA, FALSE,
									 errorInfo );
		if( cryptStatusError( status ) )
			{
			/* If we've processed all of the entries, convert the signalling 
			   OK_SPECIAL status to a more meaningful value and exit */
			if( status == OK_SPECIAL )
				{
				status = CRYPT_ERROR_NOTFOUND;
				break;
				}

			/* If we're stuck in a loop fetching the same value over and 
			   over, make an emergency exit */
			if( status == CRYPT_ERROR_DUPLICATE )
				{
				DEBUG_DIAG(( "Partial-certificate-fetch loop detected" ));
				assert( DEBUG_WARN );
				break;
				}

			/* It's some other type of problem, clear it and continue */
			status = deleteIncompleteCert( dbmsInfo, certID, certIDlength, 
										   FALSE, status, 
										   "Couldn't get partially-issued "
										   "certificate to complete issue, "
										   "deleting and continuing" );
			REQUIRES( !checkOverflowInc( errorCount ) );
			errorCount++;
			continue;
			}

		/* We found a certificate to revoke, complete the revocation */
		status = revokeCertDirect( dbmsInfo, iCertificate, CRYPT_UNUSED, 
								   CRYPT_UNUSED, 
								   CRYPT_CERTACTION_CERT_CREATION_REVERSE,
								   errorInfo );
		krnlSendNotifier( iCertificate, IMESSAGE_DECREFCOUNT );
		iCertificate = CRYPT_ERROR;
		}
	ENSURES( LOOP_BOUND_OK );
	if( errorCount >= 5 || noEntriesProcessed >= 500 )
		{
		/* See note with earlier code */
		DEBUG_DIAG(( "Partial-certificate-fetch loop detected or excessive "
					 "error count" ));
		assert( DEBUG_WARN );
		}

	/* If we ran into a problem, perform a fallback general delete of
	   entries that caused the problem */
	if( status != CRYPT_ERROR_NOTFOUND )
		{
		updateCertErrorLogMsg( dbmsInfo, status, "Partially-issued "
							   "certificate cleanup operation failed, "
							   "performing fallback straight delete" );
		status = dbmsStaticUpdate(
			"DELETE FROM certificates WHERE keyID LIKE " 
			CERTID_LIKE_CERTISSUE_STD );
		if( cryptStatusError( status ) )
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );

			/* The overall cleanup failed, let the caller know */
			if( cryptStatusOK( persistentErrorStatus ) )
				persistentErrorStatus = status;
			}
		}

	/* Now process any partially-completed renewals */
	memset( prevCertData, 0, MAX_PREVCERT_DATA );
	LOOP_LARGE( ( status = CRYPT_OK, errorCount = 0, noEntriesProcessed = 0 ),
				status != CRYPT_ERROR_NOTFOUND && errorCount < 5 && \
					noEntriesProcessed < 500,
				noEntriesProcessed++ )
		{
		CRYPT_CERTIFICATE iCertificate;

		ENSURES( LOOP_INVARIANT_LARGE( noEntriesProcessed, 0, 499 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( errorCount, 0, 4 ) );

		/* Get the next partially-completed certificate */
		status = getNextPartialCert( dbmsInfo, &iCertificate, certID, 
									 ENCODED_DBXKEYID_SIZE, &certIDlength, 
									 prevCertData, MAX_PREVCERT_DATA, TRUE,
									 errorInfo );
		if( cryptStatusError( status ) )
			{
			/* If we've processed all of the entries, convert the signalling 
			   OK_SPECIAL status to a more meaningful value and exit */
			if( status == OK_SPECIAL )
				{
				status = CRYPT_ERROR_NOTFOUND;
				break;
				}

			/* If we're stuck in a loop fetching the same value over and 
			   over, make an emergency exit */
			if( status == CRYPT_ERROR_DUPLICATE )
				{
				DEBUG_DIAG(( "Partial-renewal-fetch loop detected" ));
				assert( DEBUG_WARN );
				break;
				}

			/* It's some other type of problem, clear it and continue */
			status = deleteIncompleteCert( dbmsInfo, certID, certIDlength, 
										   TRUE, status, 
										   "Couldn't get partially-renewed "
										   "certificate to complete renewal, "
										   "deleting and continuing" );
			REQUIRES( !checkOverflowInc( errorCount ) );
			errorCount++;
			continue;
			}

		/* We found a partially-completed certificate, complete the renewal */
		status = completeCertRenewal( dbmsInfo, iCertificate, CRYPT_UNUSED, 
									  CRYPT_UNUSED, errorInfo );
		krnlSendNotifier( iCertificate, IMESSAGE_DECREFCOUNT );
		iCertificate = CRYPT_ERROR;
		}
	ENSURES( LOOP_BOUND_OK );
	if( errorCount >= 5 || noEntriesProcessed >= 500 )
		{
		/* See note with earlier code */
		DEBUG_DIAG(( "Partial-renewal-fetch loop detected or excessive "
					 "error count" ));
		assert( DEBUG_WARN );
		}

	/* If we ran into a problem, perform a fallback general delete of
	   entries that caused the problem */
	if( status != CRYPT_ERROR_NOTFOUND )
		{
		updateCertErrorLogMsg( dbmsInfo, status, "Partially-renewed "
							   "certificate cleanup operation failed, "
							   "performing fallback straight delete" );
		status = dbmsStaticUpdate(
			"DELETE FROM certificates WHERE keyID LIKE " 
			CERTID_LIKE_CERTISSUE_RENEW );
		if( cryptStatusError( status ) )
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );

			/* The overall cleanup failed, let the caller know */
			if( cryptStatusOK( persistentErrorStatus ) )
				persistentErrorStatus = status;
			}
		}

	/* Finally, process any pending revocations.  These require a different
	   strategy than certificate issuance because those can be easily backed 
	   out simply by deleting the request or partial certificate, while with
	   revocations we have to try and process them if at all possible */
	memset( prevCertID, 0, ENCODED_DBXKEYID_SIZE );
	prevCertIDlength = 0;
	LOOP_LARGE( ( errorCount = 0, noEntriesProcessed = 0 ),
				errorCount < 5 && noEntriesProcessed < 500,
				noEntriesProcessed++ )
		{
		CRYPT_CERTIFICATE iCertRequest;
		int dummy;

		ENSURES( LOOP_INVARIANT_LARGE( noEntriesProcessed, 0, 499 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( errorCount, 0, 4 ) );

		/* Find the next revocation request.  We use a slightly different 
		   strategy to ensure forward progress, moving through the certIDs 
		   by value so that if there's a problem processing one then we move 
		   on to the next one at the next iteration.
		   
		   This leads to a secondary problem in that it can potentially lead
		   to a buildup of un-processable entries over time, but again we're 
		   into should-never-occur territory so it's not clear what the best
		   option, for example the commented-out bulk delete after the loop
		   exits, would be.  What the current strategy does do is allow 
		   retries in the case of transient errors, with the entry still 
		   being present the next time caCleanup() is run */
		if( prevCertIDlength <= 0 )
			{
			status = dbmsQuery(
				"SELECT certID FROM certRequests WHERE type = "
				TEXT_CERTTYPE_REQUEST_REVOCATION " ORDER BY certID",
								certID, MAX_QUERY_RESULT_SIZE, 
								&certIDlength, NULL, DBMS_CACHEDQUERY_NONE, 
								DBMS_QUERY_NORMAL );
			}
		else
			{
			/* Get the next entry in the sequence.  Compares for '>' by
			   database backends may or may not be case-insensitive (for
			   example MySQL and SQL Server are case-insensitive, 
			   PostgreSQL, SQLite and Oracle aren't) and the base64 IDs use 
			   both cases, but all that matters is consistency within the 
			   backend itself.
			   
			   There's also the theoretical issue of two randomly-generated 
			   IDs differing only by a single bit that flips the case, but 
			   the chances of that are negligible */
			initBoundData( boundDataPtr );
			setBoundData( boundDataPtr, 0, prevCertID, prevCertIDlength );
			status = dbmsQuery(
				"SELECT certID FROM certRequests WHERE type = "
				TEXT_CERTTYPE_REQUEST_REVOCATION " AND certID > ? "
				"ORDER BY certID",
								certID, MAX_QUERY_RESULT_SIZE, 
								&certIDlength, boundDataPtr, 
								DBMS_CACHEDQUERY_NONE, 
								DBMS_QUERY_NORMAL );
			}
		if( cryptStatusError( status ) )
			{
			/* If we've processed all of the entries this isn't an error */
			if( status == CRYPT_ERROR_NOTFOUND )
				{
				resetErrorInfo( dbmsInfo );
				break;
				}

			/* We've hit an error with the query.  In theory we could try
			   and increment the prevCertID in some way to move the 
			   'certID > x' qualifier past the problem entry, but to do that 
			   we'd need to know which certID is causing the problem.  Not 
			   incrementing will just retry the same query in the hope that 
			   it was a transient issue, and in any case we're again in
			   should-never-occur territory so predicting what could occur, 
			   let alone testing a response to it, isn't really possible */
			REQUIRES( !checkOverflowInc( errorCount ) );
			errorCount++;
			continue;
			}
		if( certIDlength > ENCODED_DBXKEYID_SIZE )
			certIDlength = ENCODED_DBXKEYID_SIZE;
		if(	prevCertIDlength == certIDlength && \
			!memcmp( prevCertID, certID, certIDlength ) )
			{
			/* We're stuck in a loop fetching the same value over and over,
			   make an emergency exit */
			DEBUG_DIAG(( "Certificate-fetch loop detected" ));
			assert( DEBUG_WARN );
			break;
			}
			
		/* Remember the current certID */
		REQUIRES( rangeCheck( certIDlength, 1, ENCODED_DBXKEYID_SIZE ) );
		memcpy( prevCertID, certID, certIDlength );
		prevCertIDlength = certIDlength;

		/* Import the revocation request */
		status = getItemData( dbmsInfo, &iCertRequest, &dummy, 
							  KEYMGMT_ITEM_REVREQUEST, 
							  CRYPT_IKEYID_CERTID, certID, certIDlength, 
							  KEYMGMT_FLAG_NONE, errorInfo );
		if( cryptStatusError( status ) )
			{
			/* This is another should-not-occur condition, the two most 
			   likely causes are some transient database error and a problem
			   importing the request, for example due to data corruption.
			   If it's likely a data-corruption error then we fall back to a 
			   straight delete because a later retry will fail the same way, 
			   otherwise we leave it in place for another try at the next 
			   cleanup.  Another error possibility is CRYPT_ERROR_NOTAVAIL 
			   for an algorithm that's not (or no longer) supported, but for
			   that we wouldn't be able to import the request to add it to 
			   the certificate store in the first place */
			if( status == CRYPT_ERROR_OVERFLOW || \
				status == CRYPT_ERROR_UNDERFLOW || \
				status == CRYPT_ERROR_BADDATA || \
				status == CRYPT_ERROR_INVALID )
				{
				status = \
					deleteIncompleteRequest( dbmsInfo, certID, certIDlength, 
											 status, "Couldn't instantiate "
											 "revocation request from stored "
											 "data, deleting request and "
											 "continuing" );
				}
			REQUIRES( !checkOverflowInc( errorCount ) );
			errorCount++;
			continue;
			}

		/* Complete the revocation */
		status = caRevokeCert( dbmsInfo, iCertRequest, CRYPT_UNUSED,
							   CRYPT_UNUSED, CRYPT_UNUSED,	
							   CRYPT_CERTACTION_RESTART_REVOKE_CERT,
							   errorInfo );
		if( cryptStatusError( status ) )
			{
			/* If we get a not-found error then this is an allowable 
			   condition since the certificate may have expired or been 
			   otherwise removed after the revocation request was received, 
			   so we just delete the entry.
			   
			   For any other type of error it's unclear what to do, if it's
			   a transient database error probably leaving it in place for a 
			   future cleanup is the correct action but as with other 
			   should-not-occur errors it's difficult to plan for actual
			   cases that should never occur in the first place */
			if( status == CRYPT_ERROR_NOTFOUND )
				{
				status = \
					deleteIncompleteRequest( dbmsInfo, certID, certIDlength, 
											 status, "Deleted revocation "
											 "request for non-present "
											 "certificate" );
				}
			else
				{
				/* Leave the request in place for a retry on the next 
				   cleanup */
				updateCertErrorLog( dbmsInfo, status, "Couldn't revoke "
									"certificate from revocation request, "
									"will retry on next cleanup", certID, 
									certIDlength );
				REQUIRES( !checkOverflowInc( errorCount ) );
				errorCount++;

				/* The overall cleanup failed, let the caller know */
				if( cryptStatusOK( persistentErrorStatus ) )
					persistentErrorStatus = status;
				}
			}
		krnlSendNotifier( iCertRequest, IMESSAGE_DECREFCOUNT );
		iCertRequest = CRYPT_ERROR;
		}
	ENSURES( LOOP_BOUND_OK );
	if( errorCount >= 5 || noEntriesProcessed >= 500 )
		{
		/* See note with earlier code */
		DEBUG_DIAG(( "Revocation-fetch loop detected or excessive error "
					 "count" ));
		assert( DEBUG_WARN );
		}

	/* If we ran into a problem, perform a fallback general delete of
	   entries that caused the problem */
#if 0	/* 22/9/26 No longer necessary with the change to handle certIDs
				   by value */
	if( status != CRYPT_ERROR_NOTFOUND )
		{
		updateCertErrorLogMsg( dbmsInfo, status, "Revocation request "
							   "cleanup operation failed, performing "
							   "fallback straight delete" );
		status = dbmsStaticUpdate(
					"DELETE FROM certRequests WHERE type = "
						TEXT_CERTTYPE_REQUEST_REVOCATION );
		if( cryptStatusError( status ) )
			{
			updateCertErrorLogMsg( dbmsInfo, status, "Fallback straight "
								   "delete failed" );
			retExtErr( status, 
					   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
						 "Revocation request cleanup operation failed" ) );
			}
		}
#endif /* 0 */

	/* We always return CRYPT_OK for a cleanup call except for overall 
	   errors because we're reporting the result of the overall cleanup 
	   operation, not whether some low-level internal part of it failed */
	if( cryptStatusError( persistentErrorStatus ) )
		return( persistentErrorStatus );
	return( resetErrorInfo( dbmsInfo ) );
	}
#endif /* USE_DBMS */
