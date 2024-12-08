<<<<<<< HEAD
/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-2020					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "dbms.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "keyset/dbms.h"
  #include "keyset/keyset.h"
#endif /* Compiler-specific includes */

/* A structure to store ID information extracted from a certificate before 
   it's added to the certificate store */

typedef struct {
	/* User identification data */
	BUFFER( CRYPT_MAX_TEXTSIZE, Clength ) \
	char C[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, SPlength ) \
	char SP[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, Llength ) \
	char L[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, Olength ) \
	char O[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, OUlength ) \
	char OU[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, CNlength ) \
	char CN[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, uriLength ) \
	char uri[ CRYPT_MAX_TEXTSIZE + 8 ];
	int Clength, SPlength, Llength, Olength, OUlength, CNlength, uriLength;

	/* Certificate identification data */
	BUFFER( ENCODED_DBXKEYID_SIZE, certIDlength ) \
	char certID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BUFFER( ENCODED_DBXKEYID_SIZE, nameIDlength ) \
	char nameID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BUFFER( ENCODED_DBXKEYID_SIZE, issuerIDlength ) \
	char issuerID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BUFFER( ENCODED_DBXKEYID_SIZE, keyIDlength ) \
	char keyID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int certIDlength, nameIDlength, issuerIDlength, keyIDlength;
	} CERT_ID_DATA;

#ifdef USE_DBMS

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the SQL string to delete data from a given table */

CHECK_RETVAL_PTR \
static char *getDeleteString( IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType )
	{
	REQUIRES_N( itemType == KEYMGMT_ITEM_PKIUSER || \
				itemType == KEYMGMT_ITEM_PUBLICKEY );

	switch( itemType )
		{
		case KEYMGMT_ITEM_PKIUSER:
			return( "DELETE FROM pkiUsers WHERE " );

		case KEYMGMT_ITEM_PUBLICKEY:
			return( "DELETE FROM certificates WHERE " );
		}

	retIntError_Null();
	}

/* Check whether a duplicate certificate that we're trying to add is a newer
   version of an existing certificate.  The replacement policy is:

		Contents		Certificate dates
		DN		key		same		newer
		--		---		----		-----
	A	same	same	duplicate	replace
	B	diff	same	error		error
	C	same	diff		See below
   
   In text form:

	* If a certificate with the same DN and key as an existing certificate 
	  (case A) is added and the one being added is newer than the existing 
	  certificate, the existing certificate will be replaced with the new 
	  one.

	* If a certificate with a different DN but the same key as an existing
	  certificate (case B) is added, this is an error since it means that 
	  the same private key is being shared across multiple certificates.

	* If a certificate with the same DN but a different key as an existing
	  certificate (case C) is added then this is a standard certificate add.  
	  This is required in order to deal with things like distinct signing 
	  and encryption certificates for the same entity, which results in a 
	  duplicate name but different keys.

   The above is enforced by the database, for which the keyID has uniqueness 
   constraints (see keyset/dbx_misc.c), so that A and B will result in a 
   duplicate certificate notification.  

   If there's an error in this function while trying to determine whether 
   the certificate is a duplicate or not it returns CRYPT_ERROR_DUPLICATE 
   since the caller isn't expecting to get something like a 
   CRYPT_ERROR_READ in response to a write attempt */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkReplacementCert( INOUT_PTR DBMS_INFO *dbmsInfo,
								 IN_HANDLE const CRYPT_HANDLE iNewCert )
	{
	CRYPT_CERTIFICATE iExistingCert DUMMY_INIT;
	MESSAGE_DATA msgData;
	BYTE certID[ CRYPT_MAX_HASHSIZE + 8 ]; 
	BYTE keyID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BYTE newCertNameID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BYTE existingCertNameID[ ENCODED_DBXKEYID_SIZE + 8 ];
	time_t existingCertValidTo, newCertValidFrom DUMMY_INIT;
	time_t newCertValidTo DUMMY_INIT;
	int keyIDlength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iNewCert ) );

	/* In the most common case the certificate will already be present in 
	   the keyset and there's nothing further to do, so we perform a
	   quick-reject check for an exact duplicate */
	setMessageData( &msgData, certID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iNewCert, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_DUPLICATE );
	status = presenceCheck( dbmsInfo, KEYMGMT_ITEM_PUBLICKEY, 
							CRYPT_IKEYID_CERTID, certID, KEYID_SIZE );
	if( cryptStatusOK( status ) )
		{
		/* This exact certificate is already present, we can't add it again */
		return( CRYPT_ERROR_DUPLICATE );
		}

	/* This exact certificate isn't already present but we got a duplicate
	   error when adding it, this must be because the key in the certificate
	   is already present (see the table uniqueness constraints in 
	   keyset/dbx_misc.c).  To find out whether we can replace it we need to 
	   fetch it and check whether the certificate to be added is newer than 
	   the existing one.  Since this is just a presence-check operation we 
	   don't do anything with the error information */
	status = getCertKeyID( keyID, ENCODED_DBXKEYID_SIZE, &keyIDlength, 
						   iNewCert );
	if( cryptStatusOK( status ) )
		{
		ERROR_INFO localErrorInfo;
		int dummy;

		clearErrorInfo( &localErrorInfo );
		status = getItemData( dbmsInfo, &iExistingCert, &dummy, 
							  KEYMGMT_ITEM_PUBLICKEY, CRYPT_IKEYID_KEYID, 
							  keyID, keyIDlength, KEYMGMT_FLAG_NONE, 
							  &localErrorInfo );
		}
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_DUPLICATE );

	/* There is one special case where we can't replace the certificate and
	   that's if the same key is present in a different certificate, in other
	   words the DNs for the existing and new certificate differ but the key
	   is the same.  This is case B above */
	status = getKeyID( newCertNameID, ENCODED_DBXKEYID_SIZE, &keyIDlength, 
					   iNewCert, CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( existingCertNameID, ENCODED_DBXKEYID_SIZE, 
						   &keyIDlength, iExistingCert, 
						   CRYPT_IATTRIBUTE_SUBJECT );
		}
	if( cryptStatusError( status ) || \
		memcmp( newCertNameID, existingCertNameID, keyIDlength ) )
		{
		/* We're trying to add a certificate with the same key but a 
		   different DN, this shouldn't happen */
		DEBUG_DIAG(( "Attempt to add certificate with the same key as an "
					 "existing certificate" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_DUPLICATE );
		}

	/* We've got what's presumably an older copy of the certificate being 
	   added, get the validity information for the two and check which is
	   the more recent.  This is case A above.  See the long comment in 
	   keyset/pkcs15_set.c:checkAddInfo() for a discussion on the 
	   implications of replacing certificates */
	setMessageData( &msgData, &existingCertValidTo, sizeof( time_t ) );
	status = krnlSendMessage( iExistingCert , IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_VALIDTO );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, &newCertValidFrom, sizeof( time_t ) );
		status = krnlSendMessage( iNewCert, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDFROM );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, &newCertValidTo, sizeof( time_t ) );
		status = krnlSendMessage( iNewCert, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
		}
	krnlSendNotifier( iExistingCert, IMESSAGE_DESTROY );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_DUPLICATE );
	if( existingCertValidTo >= newCertValidTo )
		{
		/* The existing certificate is newer than the one being added, don't 
		   try and add it */
		return( CRYPT_ERROR_DUPLICATE );
		}
	if( newCertValidFrom > getTime( GETTIME_NOFAIL ) + 86400L )
		{
		/* The new certificate is future-dated, again see the discussion in
		   keyset/pkcs15_set.c:checkAddInfo() for more on this */
		DEBUG_DIAG(( "Attempt to replace certificate with future-dated "
					 "certificate" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_DUPLICATE );
		}

	/* The existing certificate is an older copy of the current certificate,
	   indicate that it's OK to replace it */
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Extract ID Information							*
*																			*
****************************************************************************/

/* Extract user identification data from a certificate.  This can potentially
   run into problems with rare certificates that have over-long DN 
   components, to deal with this we read them into a buffer of size
   CRYPT_MAX_TEXTSIZE * 2 and then copy across the first CRYPT_MAX_TEXTSIZE 
   characters.  This isn't a problem because certificates with such invalid-
   length name components are almost nonexistent, and even when they do 
   occur are only used for lookup rather than display so it won't matter if 
   some characters at the end are truncated */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int extractCertNameData( IN_HANDLE const CRYPT_CERTIFICATE iCryptHandle,
								IN_ENUM( CRYPT_CERTTYPE ) \
									const CRYPT_CERTTYPE_TYPE certType,
								OUT_PTR CERT_ID_DATA *certIdData )
	{
	static const int nameValue = CRYPT_CERTINFO_SUBJECTNAME;
	static const int altNameValue = CRYPT_CERTINFO_SUBJECTALTNAME;
	MESSAGE_DATA msgData;
	BYTE buffer[ ( CRYPT_MAX_TEXTSIZE * 2 ) + 8 ];
	LOOP_INDEX i;
	int status;

	assert( isWritePtr( certIdData, sizeof( CERT_ID_DATA ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			  certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			  certType == CRYPT_CERTTYPE_PKIUSER );

	/* Clear return value */
	memset( certIdData, 0, sizeof( CERT_ID_DATA ) );

	/* Extract the DN and altName (URI) components.  This changes the 
	   currently selected DN components but this is OK because the caller has 
	   the certificate locked and the prior state will be restored when they
	   unlock it */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  ( MESSAGE_CAST ) &nameValue, 
							  CRYPT_ATTRIBUTE_CURRENT );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_COUNTRYNAME );
	if( cryptStatusOK( status ) )
		{
		/* Although the country code is supposed to be ISO 3166, 
		   certificates can turn up with all kinds of random garbage in the
		   country code field including values that aren't two-letter codes, 
		   so we truncate the field if required in order to fit it into the
		   underlying database column */
		certIdData->Clength = min( msgData.length, 2 );
		REQUIRES( rangeCheck( certIdData->Clength, 1, 2 ) );
		memcpy( certIdData->C, buffer, certIdData->Clength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_STATEORPROVINCENAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->SPlength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->SPlength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->SP, buffer, certIdData->SPlength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_LOCALITYNAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->Llength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->Llength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->L, buffer, certIdData->Llength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_ORGANIZATIONNAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->Olength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->Olength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->O, buffer, certIdData->Olength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->OUlength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->OUlength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->OU, buffer, certIdData->OUlength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}

	/* The CommonName component is the generic "name" associated with the 
	   certificate, to make sure that there's always at least something 
	   useful present to identify it we fetch the certificate holder name 
	   rather than the specific common name */
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_HOLDERNAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->CNlength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->CNlength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->CN, buffer, certIdData->CNlength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}

	/* PKI user objects don't have URI information so if we're processing 
	   one of these we're done */
	if( certType == CRYPT_CERTTYPE_PKIUSER )
		return( CRYPT_OK );

	/* Get the URI for this certificate, in order of likelihood of 
	   occurrence */
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( MESSAGE_CAST ) &altNameValue, 
					 CRYPT_ATTRIBUTE_CURRENT );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_RFC822NAME );
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, 
								  CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
		}
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_DNSNAME );
		}
	if( cryptStatusError( status ) )
		{
		/* If there's no URI present, we're done */
		if( status == CRYPT_ERROR_NOTFOUND )
			return( CRYPT_OK );

		return( status );
		}
	certIdData->uriLength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
	REQUIRES( rangeCheck( certIdData->uriLength, 1, CRYPT_MAX_TEXTSIZE ) );
	memcpy( certIdData->uri, buffer, certIdData->uriLength );

	/* Force the URI (as stored) to lowercase to make case-insensitive 
	   matching easier.  In most cases we could ask the back-end to do this 
	   but this complicates indexing and there's no reason why we can't do 
	   it here */
	LOOP_LARGE( i = 0, i < certIdData->uriLength, i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, certIdData->uriLength - 1 ) );

		certIdData->uri[ i ] = \
					intToByte( toLower( certIdData->uri[ i ] ) );
		}
	ENSURES( LOOP_BOUND_OK );
	
	return( CRYPT_OK );
	}

/* Extract certificate identification data from a certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int extractCertIdData( IN_HANDLE const CRYPT_CERTIFICATE iCryptHandle,
							  IN_ENUM( CRYPT_CERTTYPE ) \
								const CRYPT_CERTTYPE_TYPE certType,
							  INOUT_PTR CERT_ID_DATA *certIdData )
	{
	int status;

	assert( isWritePtr( certIdData, sizeof( CERT_ID_DATA ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			  certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			  certType == CRYPT_CERTTYPE_PKIUSER );

	/* Get general ID information */
	status = getKeyID( certIdData->certID, ENCODED_DBXKEYID_SIZE, 
					   &certIdData->certIDlength, iCryptHandle,
					   CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusError( status ) )
		return( status );

	/* Get object-specific ID information */
	if( certType == CRYPT_CERTTYPE_CERTIFICATE )
		{
		status = getKeyID( certIdData->nameID, ENCODED_DBXKEYID_SIZE, 
						   &certIdData->nameIDlength, iCryptHandle, 
						   CRYPT_IATTRIBUTE_SUBJECT );
		if( cryptStatusOK( status ) )
			{
			status = getKeyID( certIdData->issuerID, ENCODED_DBXKEYID_SIZE, 
							   &certIdData->issuerIDlength, iCryptHandle, 
							   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
			}
		if( cryptStatusOK( status ) )
			{
			status = getCertKeyID( certIdData->keyID, ENCODED_DBXKEYID_SIZE, 
								   &certIdData->keyIDlength, iCryptHandle );
			}
		return( status );
		}
#ifdef USE_PKIUSER
	if( certType == CRYPT_CERTTYPE_PKIUSER )
		{
		status = getPkiUserKeyID( certIdData->keyID, ENCODED_DBXKEYID_SIZE, 
								  &certIdData->keyIDlength, iCryptHandle );
		if( cryptStatusOK( status ) )
			{
			status = getKeyID( certIdData->nameID, ENCODED_DBXKEYID_SIZE, 
							   &certIdData->nameIDlength, iCryptHandle, 
							   CRYPT_IATTRIBUTE_SUBJECT );
			}
		return( status );
		}
#endif /* USE_PKIUSER */

	return( CRYPT_OK );
	}

/* Extract certificate identification data from a CRL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int extractCrlIdData( IN_HANDLE const CRYPT_CERTIFICATE iCryptCRL,
							 IN_HANDLE_OPT \
								const CRYPT_CERTIFICATE iCryptRevokeCert,
							 OUT_PTR CERT_ID_DATA *crlIdData )
	{
	int status;

	assert( isWritePtr( crlIdData, sizeof( CERT_ID_DATA ) ) );

	REQUIRES( isHandleRangeValid( iCryptCRL ) );
	REQUIRES( iCryptRevokeCert == CRYPT_UNUSED || \
			  isHandleRangeValid( iCryptRevokeCert ) );

	/* Clear return value */
	memset( crlIdData, 0, sizeof( CERT_ID_DATA ) );

	/* Get general ID information */
	status = getKeyID( crlIdData->issuerID, ENCODED_DBXKEYID_SIZE, 
					   &crlIdData->issuerIDlength, iCryptCRL, 
					   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's no certificate being revoked present (i.e. we're just 
	   adding a set of CRL entries), we're done */
	if( iCryptRevokeCert == CRYPT_UNUSED )
		return( CRYPT_OK );

	/* Get the certificate ID and the name ID of the issuer from the 
	   certificate being revoked */
	status = getKeyID( crlIdData->certID, ENCODED_DBXKEYID_SIZE, 
					   &crlIdData->certIDlength, iCryptRevokeCert,
					   CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( crlIdData->nameID, ENCODED_DBXKEYID_SIZE, 
						   &crlIdData->nameIDlength, iCryptRevokeCert,
						   CRYPT_IATTRIBUTE_ISSUER );
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Database Add Routines							*
*																			*
****************************************************************************/

/* Add a certificate object (certificate, certificate request, PKI user) to 
   a certificate store.  Normally existing rows would be overwritten if we 
   added duplicate entries but the UNIQUE constraint on the indices will 
   catch this */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
int addCert( INOUT_PTR DBMS_INFO *dbmsInfo, 
			 IN_HANDLE const CRYPT_HANDLE iCryptHandle,
			 IN_ENUM( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE certType, 
			 IN_ENUM( CERTADD ) const CERTADD_TYPE addType,
			 IN_ENUM( DBMS_UPDATE ) const DBMS_UPDATE_TYPE updateType, 
			 INOUT_PTR ERROR_INFO *errorInfo )
	{
	MESSAGE_DATA msgData;
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	CERT_ID_DATA certIdData;
	BYTE certData[ MAX_CERT_SIZE + 8 ];
	char encodedCertData[ MAX_ENCODED_CERT_SIZE + 8 ];
	const char *sqlString;
	time_t boundDate;
	int certDataLength DUMMY_INIT, boundDataIndex, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			  certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			  certType == CRYPT_CERTTYPE_PKIUSER );
	REQUIRES( isEnumRange( addType, CERTADD ) );
	REQUIRES( isEnumRange( updateType, DBMS_UPDATE ) );
	REQUIRES( errorInfo != NULL );

	/* Extract name-related information from the certificate */
	status = extractCertNameData( iCryptHandle, certType, &certIdData );
	if( cryptStatusOK( status ) && certType == CRYPT_CERTTYPE_CERTIFICATE )
		{
		setMessageData( &msgData, &boundDate, sizeof( time_t ) );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusError( status ) )
		{
		/* Convert any low-level certificate-specific error into something 
		   generic that makes a bit more sense to the caller */
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, errorInfo, 
					 "Couldn't extract user identification information "
					 "from certificate" ) );
		}

	/* Get the ID information and certificate data from the certificate */
	status = extractCertIdData( iCryptHandle, certType, &certIdData );
	if( cryptStatusOK( status ) )
		{
		status = extractCertData( iCryptHandle, 
								  ( certType == CRYPT_CERTTYPE_PKIUSER ) ? \
									CRYPT_ICERTFORMAT_DATA : \
									CRYPT_CERTFORMAT_CERTIFICATE,
								  certData, MAX_CERT_SIZE, &certDataLength );
		}
	if( cryptStatusError( status ) )
		{
		/* Convert any low-level certificate-specific error into something 
		   generic that makes a bit more sense to the caller */
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, errorInfo, 
					 "Couldn't extract certificate data from "
					 "certificate" ) );
		}

	/* If this is a partial add in which we add a certificate item which is 
	   in the initial stages of the creation process so that although the 
	   item may be physically present in the store it can't be accessed 
	   directly, we set the first byte to 0xFF to indicate this.  In 
	   addition we set the first two bytes of the IDs that have uniqueness 
	   constraints to an out-of-band value to prevent a clash with the 
	   finished entry when we complete the issue process and replace the 
	   partial version with the full version */
	if( addType == CERTADD_PARTIAL || addType == CERTADD_PARTIAL_RENEWAL )
		{
		const char *escapeStr = ( addType == CERTADD_PARTIAL ) ? \
								KEYID_ESC1 : KEYID_ESC2;

		certData[ 0 ] = 0xFF;
		memcpy( certIdData.issuerID, escapeStr, KEYID_ESC_SIZE );
		memcpy( certIdData.keyID, escapeStr, KEYID_ESC_SIZE );
		memcpy( certIdData.certID, escapeStr, KEYID_ESC_SIZE );
		}

	/* Set up the certificate object data to be written and send it to the
	   database */
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, certIdData.C, certIdData.Clength );
	setBoundData( boundDataPtr, 1, certIdData.SP, certIdData.SPlength );
	setBoundData( boundDataPtr, 2, certIdData.L, certIdData.Llength );
	setBoundData( boundDataPtr, 3, certIdData.O, certIdData.Olength );
	setBoundData( boundDataPtr, 4, certIdData.OU, certIdData.OUlength );
	setBoundData( boundDataPtr, 5, certIdData.CN, certIdData.CNlength );
	switch( certType )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
			setBoundData( boundDataPtr, 6, certIdData.uri, 
						  certIdData.uriLength );
			setBoundDataDate( boundDataPtr, 7, &boundDate );
			setBoundData( boundDataPtr, 8, certIdData.nameID, 
						  certIdData.nameIDlength );
			setBoundData( boundDataPtr, 9, certIdData.issuerID, 
						  certIdData.issuerIDlength );
			setBoundData( boundDataPtr, 10, certIdData.keyID, 
						  certIdData.keyIDlength );
			boundDataIndex = 11;
			sqlString = \
			"INSERT INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?,"
											 "?, ?, ?, ?, ?, ?)";
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
			setBoundData( boundDataPtr, 6, certIdData.uri, 
						  certIdData.uriLength );
			boundDataIndex = 7;
			sqlString = \
			"INSERT INTO certRequests VALUES ('" TEXT_CERTTYPE_REQUEST_CERT "', "
											 "?, ?, ?, ?, ?, ?, ?, ?, ?)";
			break;

		case CRYPT_CERTTYPE_PKIUSER:
			setBoundData( boundDataPtr, 6, certIdData.nameID, 
						  certIdData.nameIDlength );
			setBoundData( boundDataPtr, 7, certIdData.keyID, 
						  certIdData.keyIDlength );
			boundDataIndex = 8;
			sqlString = \
			"INSERT INTO pkiUsers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
			break;

		default:
			retIntError();
		}
	setBoundData( boundDataPtr, boundDataIndex++, certIdData.certID, 
				  certIdData.certIDlength );
	if( hasBinaryBlobs( dbmsInfo ) )
		{
		setBoundDataBlob( boundDataPtr, boundDataIndex, 
						  certData, certDataLength );
		}
	else
		{
		int encodedCertDataLength;

		status = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE, 
							   &encodedCertDataLength, certData, 
							   certDataLength, CRYPT_CERTTYPE_NONE );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "Couldn't base64-encode data" ));
			assert( DEBUG_WARN );
			retIntError();
			}
		setBoundData( boundDataPtr, boundDataIndex, encodedCertData, 
					  encodedCertDataLength );
		}
	status = dbmsUpdate( sqlString, boundDataPtr, updateType );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "Certificate database add operation failed" ) );
		}
	return( CRYPT_OK );
	}

/* Add a CRL to a certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int addCRL( INOUT_PTR DBMS_INFO *dbmsInfo, 
			IN_HANDLE const CRYPT_CERTIFICATE iCryptCRL,
			IN_HANDLE_OPT const CRYPT_CERTIFICATE iCryptRevokeCert,
			IN_ENUM( DBMS_UPDATE ) const DBMS_UPDATE_TYPE updateType, 
			INOUT_PTR ERROR_INFO *errorInfo )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	CERT_ID_DATA crlIdData;
	BYTE certData[ MAX_CERT_SIZE + 8 ];
	char encodedCertData[ MAX_ENCODED_CERT_SIZE + 8 ];
	const char *sqlString;
	time_t expiryDate = 0;
	int certDataLength DUMMY_INIT, boundDataIndex, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCRL ) );
	REQUIRES( ( isCertStore( dbmsInfo ) && \
				isHandleRangeValid( iCryptRevokeCert ) ) || \
			  ( !isCertStore( dbmsInfo ) && \
				iCryptRevokeCert == CRYPT_UNUSED ) );
	REQUIRES( isEnumRange( updateType, DBMS_UPDATE ) );
	REQUIRES( errorInfo != NULL );

	/* Get the ID information for the current CRL entry */
	status = extractCrlIdData( iCryptCRL, iCryptRevokeCert, &crlIdData );
	if( cryptStatusOK( status ) )
		{
		status = extractCertData( iCryptCRL, CRYPT_IATTRIBUTE_CRLENTRY,
								  certData, MAX_CERT_SIZE, &certDataLength );
		}
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, &expiryDate, sizeof( time_t ) );
		status = krnlSendMessage( iCryptRevokeCert, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusError( status ) )
		{
		/* Convert any low-level certificate-specific error into something 
		   generic that makes a bit more sense to the caller */
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, errorInfo, 
					 "Couldn't extract CRL data from CRL" ) );
		}

	/* Set up the certificate object data to be written and send it to the 
	   database.  Certificate stores contain extra inforomation that's 
	   needed to build a CRL so we have to vary the SQL string depending on 
	   the keyset type */
	initBoundData( boundDataPtr );
	if( isCertStore( dbmsInfo ) )
		{
		setBoundDataDate( boundDataPtr, 0, &expiryDate );
		setBoundData( boundDataPtr, 1, crlIdData.nameID, 
					  crlIdData.nameIDlength );
		setBoundData( boundDataPtr, 2, crlIdData.issuerID, 
					  crlIdData.issuerIDlength );
		setBoundData( boundDataPtr, 3, crlIdData.certID, 
					  crlIdData.certIDlength );
		boundDataIndex = 4;
		sqlString = "INSERT INTO CRLs VALUES (?, ?, ?, ?, ?)";

		}
	else
		{
		setBoundData( boundDataPtr, 0, crlIdData.issuerID, 
					  crlIdData.issuerIDlength );
		boundDataIndex = 1;
		sqlString = "INSERT INTO CRLs VALUES (?, ?)";
		}
	if( hasBinaryBlobs( dbmsInfo ) )
		{
		setBoundDataBlob( boundDataPtr, boundDataIndex, certData, 
						  certDataLength );
		}
	else
		{
		int encodedCertDataLength;
		
		status = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE,
							   &encodedCertDataLength, certData, 
							   certDataLength, CRYPT_CERTTYPE_NONE );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "Couldn't base64-encode data" ));
			assert( DEBUG_WARN );
			retIntError();
			}
		setBoundData( boundDataPtr, boundDataIndex, encodedCertData, 
					  encodedCertDataLength );
		}
	status = dbmsUpdate( sqlString, boundDataPtr, updateType );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "CRL database add operation failed" ) );
		}

	return( CRYPT_OK );
	}

/* Replace an existing certificate with a newer one */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int replaceCert( INOUT_PTR DBMS_INFO *dbmsInfo, 
						IN_HANDLE const CRYPT_HANDLE iCryptCert,
						INOUT_PTR ERROR_INFO *errorInfo )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	BYTE encodedKeyID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int encodedKeyIDlength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCert ) );
	REQUIRES( errorInfo != NULL );

	/* Delete the existing certificate and replace it with the new one */
	status = getCertKeyID( encodedKeyID, ENCODED_DBXKEYID_SIZE, 
						   &encodedKeyIDlength, iCryptCert );
	if( cryptStatusError( status ) )
		return( status );
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, encodedKeyID, encodedKeyIDlength );
	status = dbmsUpdate( "DELETE FROM certificates WHERE keyID = ?", 
						 boundDataPtr, DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		{
		status = addCert( dbmsInfo, iCryptCert, CRYPT_CERTTYPE_CERTIFICATE,
						  CERTADD_NORMAL, DBMS_UPDATE_COMMIT, errorInfo );
		}
	else
		{
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
		}

	return( status );
	}

/* Add an item to the certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setItemFunction( INOUT_PTR KEYSET_INFO *keysetInfoPtr,
							IN_HANDLE const CRYPT_HANDLE iCryptHandle,
							IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType,
							STDC_UNUSED const char *password, 
							STDC_UNUSED const int passwordLength,
							IN_FLAGS( KEYMGMT ) const int flags )
	{
	DBMS_INFO *dbmsInfo = keysetInfoPtr->keysetDBMS;
	BOOLEAN itemAdded = FALSE;
	int type, status, loopStatus, LOOP_ITERATOR;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( sanityCheckKeyset( keysetInfoPtr ) );
	REQUIRES( keysetInfoPtr->type == KEYSET_DBMS );
	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_REVOCATIONINFO || \
			  itemType == KEYMGMT_ITEM_REQUEST || \
			  itemType == KEYMGMT_ITEM_REVREQUEST || \
			  itemType == KEYMGMT_ITEM_PKIUSER );
	REQUIRES( password == NULL && passwordLength == 0 );
	REQUIRES( isFlagRangeZ( flags, KEYMGMT ) );

	/* Make sure that we've been given a certificate, certificate chain, or 
	   CRL (or a PKI user if it's a CA certificate store).  We can't do any 
	   more specific checking against the itemType because if it's coming 
	   from outside cryptlib it'll just be passed in as a generic 
	   certificate object with no distinction between object subtypes */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE,
							  &type, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( isCertStore( dbmsInfo ) )
		{
		/* The only item that can be inserted directly into a CA certificate
		   store is a CA request or PKI user information */
		if( type != CRYPT_CERTTYPE_CERTREQUEST && \
			type != CRYPT_CERTTYPE_REQUEST_CERT && \
			type != CRYPT_CERTTYPE_REQUEST_REVOCATION && \
			type != CRYPT_CERTTYPE_PKIUSER )
			{
			retExtArg( CRYPT_ARGERROR_NUM1, 
					   ( CRYPT_ARGERROR_NUM1, KEYSET_ERRINFO, 
						 "Invalid item type for CA certificate store" ) );
			}

		if( itemType == KEYMGMT_ITEM_PKIUSER )
			{
			REQUIRES( type == CRYPT_CERTTYPE_PKIUSER );
			return( caAddPKIUser( dbmsInfo, iCryptHandle, KEYSET_ERRINFO ) );
			}

		/* It's a certificate request being added to a CA certificate 
		   store */
		REQUIRES( ( itemType == KEYMGMT_ITEM_REQUEST && \
					( type == CRYPT_CERTTYPE_CERTREQUEST || \
					  type == CRYPT_CERTTYPE_REQUEST_CERT ) ) || \
				  ( itemType == KEYMGMT_ITEM_REVREQUEST && \
				    type == CRYPT_CERTTYPE_REQUEST_REVOCATION ) );
		return( caAddCertRequest( dbmsInfo, iCryptHandle, type,
								  ( flags & KEYMGMT_FLAG_UPDATE ) ? \
									TRUE : FALSE, 
								  ( flags & KEYMGMT_FLAG_INITIALOP ) ? \
									TRUE : FALSE, KEYSET_ERRINFO ) );
		}
	if( type != CRYPT_CERTTYPE_CERTIFICATE && \
		type != CRYPT_CERTTYPE_CERTCHAIN && \
		type != CRYPT_CERTTYPE_CRL )
		{
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, KEYSET_ERRINFO, 
					 "Item being added must be a CRL or certificate" ) );
		}

	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_REVOCATIONINFO );

	/* Lock the certificate or CRL for our exclusive use and select the 
	   first sub-item (certificate in a certificate chain, entry in a CRL), 
	   update the keyset with the certificate(s)/CRL entries, and unlock it 
	   to allow others access.

	   An item being added may already be present but we can't fail 
	   immediately because what's being added may be a chain containing 
	   further certificates or a CRL containing further entries so we keep 
	   track of whether we've successfully added at least one item and clear 
	   data duplicate errors */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_CURSORFIRST,
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		( void ) krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_FALSE, 
								  CRYPT_IATTRIBUTE_LOCKED );

		/* CRLs can be empty in which case not finding any entries in them 
		   isn't an error - being asked to add nothing always succeeds 
		   ("Bring on the empty CRLs" - Michael Curtiz) */
		if( type == CRYPT_CERTTYPE_CRL && status == CRYPT_ERROR_NOTFOUND )
			return( CRYPT_OK );

		return( status );
		}
	if( type == CRYPT_CERTTYPE_CRL )
		{
		LOOP_LARGE( loopStatus = CRYPT_OK, cryptStatusOK( loopStatus ),
					loopStatus = krnlSendMessage( iCryptHandle, 
									IMESSAGE_SETATTRIBUTE,
									MESSAGE_VALUE_CURSORNEXT,
									CRYPT_CERTINFO_CURRENT_CERTIFICATE ) )
			{
			ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

			/* Add the next entry in the CRL */
			status = addCRL( dbmsInfo, iCryptHandle, CRYPT_UNUSED,
							 DBMS_UPDATE_NORMAL, KEYSET_ERRINFO );
			if( cryptStatusError( status ) )
				{
				if( status != CRYPT_ERROR_DUPLICATE )
					break;
				status = CRYPT_OK;
				}
			else
				itemAdded = TRUE;
			}
		}
	else
		{
		LOOP_MED( loopStatus = CRYPT_OK, cryptStatusOK( loopStatus ),
				  loopStatus = krnlSendMessage( iCryptHandle, 
									IMESSAGE_SETATTRIBUTE,
									MESSAGE_VALUE_CURSORNEXT,
									CRYPT_CERTINFO_CURRENT_CERTIFICATE ) )
			{
			ENSURES( LOOP_INVARIANT_MED_GENERIC() );

			/* Add the next certificate in the chain */
			status = addCert( dbmsInfo, iCryptHandle,
							  CRYPT_CERTTYPE_CERTIFICATE, CERTADD_NORMAL,
							  DBMS_UPDATE_NORMAL, KEYSET_ERRINFO );
			if( cryptStatusError( status ) )
				{
				if( status != CRYPT_ERROR_DUPLICATE )
					break;

				/* When a certificate is re-issued with everything identical 
				   except for the expiry date, which unfortunately is far
				   more common than it should be through a combination of 
				   forced expiry at 12 months for CA billing purposes and 
				   magical thinking around the significance of a key once
				   generated, we can't add the new certificate since it's an
				   exact duplicate of an existing one except for the 
				   validity period.  To deal with this we check for the 
				   newer-certificate situation and try and replace the 
				   existing copy with the newer one */
				status = checkReplacementCert( dbmsInfo, iCryptHandle );
				if( cryptStatusError( status ) )
					{
					/* It's a duplicate, continue with the next 
					   certificate in the chain */
					status = CRYPT_OK;
					continue;
					}

				/* It's a newer version of an existing certificate, replace
				   the current one with the newer one */
				status = replaceCert( dbmsInfo, iCryptHandle, 
									  KEYSET_ERRINFO );
				if( cryptStatusError( status ) )
					break;
				}

			/* Remember that we added at least one item */
			itemAdded = TRUE;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	( void ) krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	if( !itemAdded )
		{
		/* We reached the end of the certificate chain/CRL without finding 
		   anything that we could add, return a data duplicate error */
		retExt( CRYPT_ERROR_DUPLICATE, 
				( CRYPT_ERROR_DUPLICATE, KEYSET_ERRINFO, 
				  "No new %s were found to add to the certificate store",
				  ( type == CRYPT_CERTTYPE_CRL ) ? \
					"CRL entries" : "certificates" ) );
		}

	return( CRYPT_OK );
	}

/* Delete an item from the certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int deleteItemFunction( INOUT_PTR KEYSET_INFO *keysetInfoPtr,
							   IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType,
							   IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
							   IN_BUFFER( keyIDlength ) const void *keyID, 
							   IN_LENGTH_KEYID const int keyIDlength )
	{
	DBMS_INFO *dbmsInfo = keysetInfoPtr->keysetDBMS;
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE + 8 ];
	char encodedKeyID[ ( CRYPT_MAX_TEXTSIZE * 2 ) + 8 ];
	const char *keyName = getKeyName( keyIDtype );
	const char *deleteString = getDeleteString( itemType );
	int encodedKeyIDlength, status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );
	assert( isReadPtrDynamic( keyID, keyIDlength ) );

	REQUIRES( sanityCheckKeyset( keysetInfoPtr ) );
	REQUIRES( keysetInfoPtr->type == KEYSET_DBMS );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_PKIUSER );
	REQUIRES( ( !isCertStore( dbmsInfo ) && \
				itemType == KEYMGMT_ITEM_PUBLICKEY ) || \
			  ( isCertStore( dbmsInfo ) && \
				itemType == KEYMGMT_ITEM_PKIUSER ) );
	REQUIRES( isEnumRange( keyIDtype, CRYPT_KEYID ) );
	REQUIRES( keyIDlength >= MIN_NAME_LENGTH && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );

	/* Delete the item from the certificate store */
	status = makeKeyID( encodedKeyID, CRYPT_MAX_TEXTSIZE * 2, 
						&encodedKeyIDlength, keyIDtype, keyID, keyIDlength );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_STR1 );
	if( isCertStore( dbmsInfo ) )
		{
		/* The only item that can be deleted from a CA certificate store is 
		   PKI user information */
		if( itemType != KEYMGMT_ITEM_PKIUSER )
			{
			retExtArg( CRYPT_ARGERROR_NUM1, 
					   ( CRYPT_ARGERROR_NUM1, KEYSET_ERRINFO, 
						 "Invalid operation for CA certificate store" ) );
			}

		return( caDeletePKIUser( dbmsInfo, keyIDtype, keyID, keyIDlength, 
								 KEYSET_ERRINFO ) );
		}
	ENSURES( keyName != NULL && deleteString != NULL );
	strlcpy_s( sqlBuffer, MAX_SQL_QUERY_SIZE, deleteString );
	strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, keyName );
	strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, " = ?" );
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, encodedKeyID, encodedKeyIDlength );
	status = dbmsUpdate( sqlBuffer, boundDataPtr, DBMS_UPDATE_NORMAL );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, KEYSET_ERRINFO, getDbmsErrorInfo( dbmsInfo ),
					 "Certificate database delete operation failed" ) );
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Database Access Routines						*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initDBMSwrite( INOUT_PTR KEYSET_INFO *keysetInfoPtr )
	{
	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_DBMS );

	FNPTR_SET( keysetInfoPtr->setItemFunction, setItemFunction );
	FNPTR_SET( keysetInfoPtr->deleteItemFunction, deleteItemFunction );

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
=======
/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-2020					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "dbms.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "keyset/dbms.h"
  #include "keyset/keyset.h"
#endif /* Compiler-specific includes */

/* A structure to store ID information extracted from a certificate before 
   it's added to the certificate store */

typedef struct {
	/* User identification data */
	BUFFER( CRYPT_MAX_TEXTSIZE, Clength ) \
	char C[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, SPlength ) \
	char SP[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, Llength ) \
	char L[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, Olength ) \
	char O[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, OUlength ) \
	char OU[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, CNlength ) \
	char CN[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, uriLength ) \
	char uri[ CRYPT_MAX_TEXTSIZE + 8 ];
	int Clength, SPlength, Llength, Olength, OUlength, CNlength, uriLength;

	/* Certificate identification data */
	BUFFER( ENCODED_DBXKEYID_SIZE, certIDlength ) \
	char certID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BUFFER( ENCODED_DBXKEYID_SIZE, nameIDlength ) \
	char nameID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BUFFER( ENCODED_DBXKEYID_SIZE, issuerIDlength ) \
	char issuerID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BUFFER( ENCODED_DBXKEYID_SIZE, keyIDlength ) \
	char keyID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int certIDlength, nameIDlength, issuerIDlength, keyIDlength;
	} CERT_ID_DATA;

#ifdef USE_DBMS

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the SQL string to delete data from a given table */

CHECK_RETVAL_PTR \
static char *getDeleteString( IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType )
	{
	REQUIRES_N( itemType == KEYMGMT_ITEM_PKIUSER || \
				itemType == KEYMGMT_ITEM_PUBLICKEY );

	switch( itemType )
		{
		case KEYMGMT_ITEM_PKIUSER:
			return( "DELETE FROM pkiUsers WHERE " );

		case KEYMGMT_ITEM_PUBLICKEY:
			return( "DELETE FROM certificates WHERE " );
		}

	retIntError_Null();
	}

/* Check whether a duplicate certificate that we're trying to add is a newer
   version of an existing certificate.  The replacement policy is:

		Contents		Certificate dates
		DN		key		same		newer
		--		---		----		-----
	A	same	same	duplicate	replace
	B	diff	same	error		error
	C	same	diff		See below
   
   In text form:

	* If a certificate with the same DN and key as an existing certificate 
	  (case A) is added and the one being added is newer than the existing 
	  certificate, the existing certificate will be replaced with the new 
	  one.

	* If a certificate with a different DN but the same key as an existing
	  certificate (case B) is added, this is an error since it means that 
	  the same private key is being shared across multiple certificates.

	* If a certificate with the same DN but a different key as an existing
	  certificate (case C) is added then this is a standard certificate add.  
	  This is required in order to deal with things like distinct signing 
	  and encryption certificates for the same entity, which results in a 
	  duplicate name but different keys.

   The above is enforced by the database, for which the keyID has uniqueness 
   constraints (see keyset/dbx_misc.c), so that A and B will result in a 
   duplicate certificate notification.  

   If there's an error in this function while trying to determine whether 
   the certificate is a duplicate or not it returns CRYPT_ERROR_DUPLICATE 
   since the caller isn't expecting to get something like a 
   CRYPT_ERROR_READ in response to a write attempt */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkReplacementCert( INOUT_PTR DBMS_INFO *dbmsInfo,
								 IN_HANDLE const CRYPT_HANDLE iNewCert )
	{
	CRYPT_CERTIFICATE iExistingCert DUMMY_INIT;
	MESSAGE_DATA msgData;
	BYTE certID[ CRYPT_MAX_HASHSIZE + 8 ]; 
	BYTE keyID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BYTE newCertNameID[ ENCODED_DBXKEYID_SIZE + 8 ];
	BYTE existingCertNameID[ ENCODED_DBXKEYID_SIZE + 8 ];
	time_t existingCertValidTo, newCertValidFrom DUMMY_INIT;
	time_t newCertValidTo DUMMY_INIT;
	int keyIDlength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iNewCert ) );

	/* In the most common case the certificate will already be present in 
	   the keyset and there's nothing further to do, so we perform a
	   quick-reject check for an exact duplicate */
	setMessageData( &msgData, certID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iNewCert, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_DUPLICATE );
	status = presenceCheck( dbmsInfo, KEYMGMT_ITEM_PUBLICKEY, 
							CRYPT_IKEYID_CERTID, certID, KEYID_SIZE );
	if( cryptStatusOK( status ) )
		{
		/* This exact certificate is already present, we can't add it again */
		return( CRYPT_ERROR_DUPLICATE );
		}

	/* This exact certificate isn't already present but we got a duplicate
	   error when adding it, this must be because the key in the certificate
	   is already present (see the table uniqueness constraints in 
	   keyset/dbx_misc.c).  To find out whether we can replace it we need to 
	   fetch it and check whether the certificate to be added is newer than 
	   the existing one.  Since this is just a presence-check operation we 
	   don't do anything with the error information */
	status = getCertKeyID( keyID, ENCODED_DBXKEYID_SIZE, &keyIDlength, 
						   iNewCert );
	if( cryptStatusOK( status ) )
		{
		ERROR_INFO localErrorInfo;
		int dummy;

		clearErrorInfo( &localErrorInfo );
		status = getItemData( dbmsInfo, &iExistingCert, &dummy, 
							  KEYMGMT_ITEM_PUBLICKEY, CRYPT_IKEYID_KEYID, 
							  keyID, keyIDlength, KEYMGMT_FLAG_NONE, 
							  &localErrorInfo );
		}
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_DUPLICATE );

	/* There is one special case where we can't replace the certificate and
	   that's if the same key is present in a different certificate, in other
	   words the DNs for the existing and new certificate differ but the key
	   is the same.  This is case B above */
	status = getKeyID( newCertNameID, ENCODED_DBXKEYID_SIZE, &keyIDlength, 
					   iNewCert, CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( existingCertNameID, ENCODED_DBXKEYID_SIZE, 
						   &keyIDlength, iExistingCert, 
						   CRYPT_IATTRIBUTE_SUBJECT );
		}
	if( cryptStatusError( status ) || \
		memcmp( newCertNameID, existingCertNameID, keyIDlength ) )
		{
		/* We're trying to add a certificate with the same key but a 
		   different DN, this shouldn't happen */
		DEBUG_DIAG(( "Attempt to add certificate with the same key as an "
					 "existing certificate" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_DUPLICATE );
		}

	/* We've got what's presumably an older copy of the certificate being 
	   added, get the validity information for the two and check which is
	   the more recent.  This is case A above.  See the long comment in 
	   keyset/pkcs15_set.c:checkAddInfo() for a discussion on the 
	   implications of replacing certificates */
	setMessageData( &msgData, &existingCertValidTo, sizeof( time_t ) );
	status = krnlSendMessage( iExistingCert , IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_VALIDTO );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, &newCertValidFrom, sizeof( time_t ) );
		status = krnlSendMessage( iNewCert, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDFROM );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, &newCertValidTo, sizeof( time_t ) );
		status = krnlSendMessage( iNewCert, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
		}
	krnlSendNotifier( iExistingCert, IMESSAGE_DESTROY );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_DUPLICATE );
	if( existingCertValidTo >= newCertValidTo )
		{
		/* The existing certificate is newer than the one being added, don't 
		   try and add it */
		return( CRYPT_ERROR_DUPLICATE );
		}
	if( newCertValidFrom > getTime( GETTIME_NOFAIL ) + 86400L )
		{
		/* The new certificate is future-dated, again see the discussion in
		   keyset/pkcs15_set.c:checkAddInfo() for more on this */
		DEBUG_DIAG(( "Attempt to replace certificate with future-dated "
					 "certificate" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_DUPLICATE );
		}

	/* The existing certificate is an older copy of the current certificate,
	   indicate that it's OK to replace it */
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Extract ID Information							*
*																			*
****************************************************************************/

/* Extract user identification data from a certificate.  This can potentially
   run into problems with rare certificates that have over-long DN 
   components, to deal with this we read them into a buffer of size
   CRYPT_MAX_TEXTSIZE * 2 and then copy across the first CRYPT_MAX_TEXTSIZE 
   characters.  This isn't a problem because certificates with such invalid-
   length name components are almost nonexistent, and even when they do 
   occur are only used for lookup rather than display so it won't matter if 
   some characters at the end are truncated */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int extractCertNameData( IN_HANDLE const CRYPT_CERTIFICATE iCryptHandle,
								IN_ENUM( CRYPT_CERTTYPE ) \
									const CRYPT_CERTTYPE_TYPE certType,
								OUT_PTR CERT_ID_DATA *certIdData )
	{
	static const int nameValue = CRYPT_CERTINFO_SUBJECTNAME;
	static const int altNameValue = CRYPT_CERTINFO_SUBJECTALTNAME;
	MESSAGE_DATA msgData;
	BYTE buffer[ ( CRYPT_MAX_TEXTSIZE * 2 ) + 8 ];
	LOOP_INDEX i;
	int status;

	assert( isWritePtr( certIdData, sizeof( CERT_ID_DATA ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			  certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			  certType == CRYPT_CERTTYPE_PKIUSER );

	/* Clear return value */
	memset( certIdData, 0, sizeof( CERT_ID_DATA ) );

	/* Extract the DN and altName (URI) components.  This changes the 
	   currently selected DN components but this is OK because the caller has 
	   the certificate locked and the prior state will be restored when they
	   unlock it */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  ( MESSAGE_CAST ) &nameValue, 
							  CRYPT_ATTRIBUTE_CURRENT );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_COUNTRYNAME );
	if( cryptStatusOK( status ) )
		{
		/* Although the country code is supposed to be ISO 3166, 
		   certificates can turn up with all kinds of random garbage in the
		   country code field including values that aren't two-letter codes, 
		   so we truncate the field if required in order to fit it into the
		   underlying database column */
		certIdData->Clength = min( msgData.length, 2 );
		REQUIRES( rangeCheck( certIdData->Clength, 1, 2 ) );
		memcpy( certIdData->C, buffer, certIdData->Clength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_STATEORPROVINCENAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->SPlength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->SPlength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->SP, buffer, certIdData->SPlength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_LOCALITYNAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->Llength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->Llength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->L, buffer, certIdData->Llength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_ORGANIZATIONNAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->Olength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->Olength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->O, buffer, certIdData->Olength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->OUlength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->OUlength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->OU, buffer, certIdData->OUlength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}

	/* The CommonName component is the generic "name" associated with the 
	   certificate, to make sure that there's always at least something 
	   useful present to identify it we fetch the certificate holder name 
	   rather than the specific common name */
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_HOLDERNAME );
	if( cryptStatusOK( status ) )
		{
		certIdData->CNlength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
		REQUIRES( rangeCheck( certIdData->CNlength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( certIdData->CN, buffer, certIdData->CNlength );
		}
	else
		{
		if( status != CRYPT_ERROR_NOTFOUND )
			return( status );
		}

	/* PKI user objects don't have URI information so if we're processing 
	   one of these we're done */
	if( certType == CRYPT_CERTTYPE_PKIUSER )
		return( CRYPT_OK );

	/* Get the URI for this certificate, in order of likelihood of 
	   occurrence */
	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( MESSAGE_CAST ) &altNameValue, 
					 CRYPT_ATTRIBUTE_CURRENT );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_RFC822NAME );
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, 
								  CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
		}
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE * 2 );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_DNSNAME );
		}
	if( cryptStatusError( status ) )
		{
		/* If there's no URI present, we're done */
		if( status == CRYPT_ERROR_NOTFOUND )
			return( CRYPT_OK );

		return( status );
		}
	certIdData->uriLength = min( msgData.length, CRYPT_MAX_TEXTSIZE );
	REQUIRES( rangeCheck( certIdData->uriLength, 1, CRYPT_MAX_TEXTSIZE ) );
	memcpy( certIdData->uri, buffer, certIdData->uriLength );

	/* Force the URI (as stored) to lowercase to make case-insensitive 
	   matching easier.  In most cases we could ask the back-end to do this 
	   but this complicates indexing and there's no reason why we can't do 
	   it here */
	LOOP_LARGE( i = 0, i < certIdData->uriLength, i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, certIdData->uriLength - 1 ) );

		certIdData->uri[ i ] = \
					intToByte( toLower( certIdData->uri[ i ] ) );
		}
	ENSURES( LOOP_BOUND_OK );
	
	return( CRYPT_OK );
	}

/* Extract certificate identification data from a certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int extractCertIdData( IN_HANDLE const CRYPT_CERTIFICATE iCryptHandle,
							  IN_ENUM( CRYPT_CERTTYPE ) \
								const CRYPT_CERTTYPE_TYPE certType,
							  INOUT_PTR CERT_ID_DATA *certIdData )
	{
	int status;

	assert( isWritePtr( certIdData, sizeof( CERT_ID_DATA ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			  certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			  certType == CRYPT_CERTTYPE_PKIUSER );

	/* Get general ID information */
	status = getKeyID( certIdData->certID, ENCODED_DBXKEYID_SIZE, 
					   &certIdData->certIDlength, iCryptHandle,
					   CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusError( status ) )
		return( status );

	/* Get object-specific ID information */
	if( certType == CRYPT_CERTTYPE_CERTIFICATE )
		{
		status = getKeyID( certIdData->nameID, ENCODED_DBXKEYID_SIZE, 
						   &certIdData->nameIDlength, iCryptHandle, 
						   CRYPT_IATTRIBUTE_SUBJECT );
		if( cryptStatusOK( status ) )
			{
			status = getKeyID( certIdData->issuerID, ENCODED_DBXKEYID_SIZE, 
							   &certIdData->issuerIDlength, iCryptHandle, 
							   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
			}
		if( cryptStatusOK( status ) )
			{
			status = getCertKeyID( certIdData->keyID, ENCODED_DBXKEYID_SIZE, 
								   &certIdData->keyIDlength, iCryptHandle );
			}
		return( status );
		}
#ifdef USE_PKIUSER
	if( certType == CRYPT_CERTTYPE_PKIUSER )
		{
		status = getPkiUserKeyID( certIdData->keyID, ENCODED_DBXKEYID_SIZE, 
								  &certIdData->keyIDlength, iCryptHandle );
		if( cryptStatusOK( status ) )
			{
			status = getKeyID( certIdData->nameID, ENCODED_DBXKEYID_SIZE, 
							   &certIdData->nameIDlength, iCryptHandle, 
							   CRYPT_IATTRIBUTE_SUBJECT );
			}
		return( status );
		}
#endif /* USE_PKIUSER */

	return( CRYPT_OK );
	}

/* Extract certificate identification data from a CRL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int extractCrlIdData( IN_HANDLE const CRYPT_CERTIFICATE iCryptCRL,
							 IN_HANDLE_OPT \
								const CRYPT_CERTIFICATE iCryptRevokeCert,
							 OUT_PTR CERT_ID_DATA *crlIdData )
	{
	int status;

	assert( isWritePtr( crlIdData, sizeof( CERT_ID_DATA ) ) );

	REQUIRES( isHandleRangeValid( iCryptCRL ) );
	REQUIRES( iCryptRevokeCert == CRYPT_UNUSED || \
			  isHandleRangeValid( iCryptRevokeCert ) );

	/* Clear return value */
	memset( crlIdData, 0, sizeof( CERT_ID_DATA ) );

	/* Get general ID information */
	status = getKeyID( crlIdData->issuerID, ENCODED_DBXKEYID_SIZE, 
					   &crlIdData->issuerIDlength, iCryptCRL, 
					   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's no certificate being revoked present (i.e. we're just 
	   adding a set of CRL entries), we're done */
	if( iCryptRevokeCert == CRYPT_UNUSED )
		return( CRYPT_OK );

	/* Get the certificate ID and the name ID of the issuer from the 
	   certificate being revoked */
	status = getKeyID( crlIdData->certID, ENCODED_DBXKEYID_SIZE, 
					   &crlIdData->certIDlength, iCryptRevokeCert,
					   CRYPT_CERTINFO_FINGERPRINT_SHA1 );
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( crlIdData->nameID, ENCODED_DBXKEYID_SIZE, 
						   &crlIdData->nameIDlength, iCryptRevokeCert,
						   CRYPT_IATTRIBUTE_ISSUER );
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Database Add Routines							*
*																			*
****************************************************************************/

/* Add a certificate object (certificate, certificate request, PKI user) to 
   a certificate store.  Normally existing rows would be overwritten if we 
   added duplicate entries but the UNIQUE constraint on the indices will 
   catch this */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 6 ) ) \
int addCert( INOUT_PTR DBMS_INFO *dbmsInfo, 
			 IN_HANDLE const CRYPT_HANDLE iCryptHandle,
			 IN_ENUM( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE certType, 
			 IN_ENUM( CERTADD ) const CERTADD_TYPE addType,
			 IN_ENUM( DBMS_UPDATE ) const DBMS_UPDATE_TYPE updateType, 
			 INOUT_PTR ERROR_INFO *errorInfo )
	{
	MESSAGE_DATA msgData;
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	CERT_ID_DATA certIdData;
	BYTE certData[ MAX_CERT_SIZE + 8 ];
	char encodedCertData[ MAX_ENCODED_CERT_SIZE + 8 ];
	const char *sqlString;
	time_t boundDate;
	int certDataLength DUMMY_INIT, boundDataIndex, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			  certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			  certType == CRYPT_CERTTYPE_PKIUSER );
	REQUIRES( isEnumRange( addType, CERTADD ) );
	REQUIRES( isEnumRange( updateType, DBMS_UPDATE ) );
	REQUIRES( errorInfo != NULL );

	/* Extract name-related information from the certificate */
	status = extractCertNameData( iCryptHandle, certType, &certIdData );
	if( cryptStatusOK( status ) && certType == CRYPT_CERTTYPE_CERTIFICATE )
		{
		setMessageData( &msgData, &boundDate, sizeof( time_t ) );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusError( status ) )
		{
		/* Convert any low-level certificate-specific error into something 
		   generic that makes a bit more sense to the caller */
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, errorInfo, 
					 "Couldn't extract user identification information "
					 "from certificate" ) );
		}

	/* Get the ID information and certificate data from the certificate */
	status = extractCertIdData( iCryptHandle, certType, &certIdData );
	if( cryptStatusOK( status ) )
		{
		status = extractCertData( iCryptHandle, 
								  ( certType == CRYPT_CERTTYPE_PKIUSER ) ? \
									CRYPT_ICERTFORMAT_DATA : \
									CRYPT_CERTFORMAT_CERTIFICATE,
								  certData, MAX_CERT_SIZE, &certDataLength );
		}
	if( cryptStatusError( status ) )
		{
		/* Convert any low-level certificate-specific error into something 
		   generic that makes a bit more sense to the caller */
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, errorInfo, 
					 "Couldn't extract certificate data from "
					 "certificate" ) );
		}

	/* If this is a partial add in which we add a certificate item which is 
	   in the initial stages of the creation process so that although the 
	   item may be physically present in the store it can't be accessed 
	   directly, we set the first byte to 0xFF to indicate this.  In 
	   addition we set the first two bytes of the IDs that have uniqueness 
	   constraints to an out-of-band value to prevent a clash with the 
	   finished entry when we complete the issue process and replace the 
	   partial version with the full version */
	if( addType == CERTADD_PARTIAL || addType == CERTADD_PARTIAL_RENEWAL )
		{
		const char *escapeStr = ( addType == CERTADD_PARTIAL ) ? \
								KEYID_ESC1 : KEYID_ESC2;

		certData[ 0 ] = 0xFF;
		memcpy( certIdData.issuerID, escapeStr, KEYID_ESC_SIZE );
		memcpy( certIdData.keyID, escapeStr, KEYID_ESC_SIZE );
		memcpy( certIdData.certID, escapeStr, KEYID_ESC_SIZE );
		}

	/* Set up the certificate object data to be written and send it to the
	   database */
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, certIdData.C, certIdData.Clength );
	setBoundData( boundDataPtr, 1, certIdData.SP, certIdData.SPlength );
	setBoundData( boundDataPtr, 2, certIdData.L, certIdData.Llength );
	setBoundData( boundDataPtr, 3, certIdData.O, certIdData.Olength );
	setBoundData( boundDataPtr, 4, certIdData.OU, certIdData.OUlength );
	setBoundData( boundDataPtr, 5, certIdData.CN, certIdData.CNlength );
	switch( certType )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
			setBoundData( boundDataPtr, 6, certIdData.uri, 
						  certIdData.uriLength );
			setBoundDataDate( boundDataPtr, 7, &boundDate );
			setBoundData( boundDataPtr, 8, certIdData.nameID, 
						  certIdData.nameIDlength );
			setBoundData( boundDataPtr, 9, certIdData.issuerID, 
						  certIdData.issuerIDlength );
			setBoundData( boundDataPtr, 10, certIdData.keyID, 
						  certIdData.keyIDlength );
			boundDataIndex = 11;
			sqlString = \
			"INSERT INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?,"
											 "?, ?, ?, ?, ?, ?)";
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
			setBoundData( boundDataPtr, 6, certIdData.uri, 
						  certIdData.uriLength );
			boundDataIndex = 7;
			sqlString = \
			"INSERT INTO certRequests VALUES ('" TEXT_CERTTYPE_REQUEST_CERT "', "
											 "?, ?, ?, ?, ?, ?, ?, ?, ?)";
			break;

		case CRYPT_CERTTYPE_PKIUSER:
			setBoundData( boundDataPtr, 6, certIdData.nameID, 
						  certIdData.nameIDlength );
			setBoundData( boundDataPtr, 7, certIdData.keyID, 
						  certIdData.keyIDlength );
			boundDataIndex = 8;
			sqlString = \
			"INSERT INTO pkiUsers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
			break;

		default:
			retIntError();
		}
	setBoundData( boundDataPtr, boundDataIndex++, certIdData.certID, 
				  certIdData.certIDlength );
	if( hasBinaryBlobs( dbmsInfo ) )
		{
		setBoundDataBlob( boundDataPtr, boundDataIndex, 
						  certData, certDataLength );
		}
	else
		{
		int encodedCertDataLength;

		status = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE, 
							   &encodedCertDataLength, certData, 
							   certDataLength, CRYPT_CERTTYPE_NONE );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "Couldn't base64-encode data" ));
			assert( DEBUG_WARN );
			retIntError();
			}
		setBoundData( boundDataPtr, boundDataIndex, encodedCertData, 
					  encodedCertDataLength );
		}
	status = dbmsUpdate( sqlString, boundDataPtr, updateType );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "Certificate database add operation failed" ) );
		}
	return( CRYPT_OK );
	}

/* Add a CRL to a certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int addCRL( INOUT_PTR DBMS_INFO *dbmsInfo, 
			IN_HANDLE const CRYPT_CERTIFICATE iCryptCRL,
			IN_HANDLE_OPT const CRYPT_CERTIFICATE iCryptRevokeCert,
			IN_ENUM( DBMS_UPDATE ) const DBMS_UPDATE_TYPE updateType, 
			INOUT_PTR ERROR_INFO *errorInfo )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	CERT_ID_DATA crlIdData;
	BYTE certData[ MAX_CERT_SIZE + 8 ];
	char encodedCertData[ MAX_ENCODED_CERT_SIZE + 8 ];
	const char *sqlString;
	time_t expiryDate = 0;
	int certDataLength DUMMY_INIT, boundDataIndex, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCRL ) );
	REQUIRES( ( isCertStore( dbmsInfo ) && \
				isHandleRangeValid( iCryptRevokeCert ) ) || \
			  ( !isCertStore( dbmsInfo ) && \
				iCryptRevokeCert == CRYPT_UNUSED ) );
	REQUIRES( isEnumRange( updateType, DBMS_UPDATE ) );
	REQUIRES( errorInfo != NULL );

	/* Get the ID information for the current CRL entry */
	status = extractCrlIdData( iCryptCRL, iCryptRevokeCert, &crlIdData );
	if( cryptStatusOK( status ) )
		{
		status = extractCertData( iCryptCRL, CRYPT_IATTRIBUTE_CRLENTRY,
								  certData, MAX_CERT_SIZE, &certDataLength );
		}
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, &expiryDate, sizeof( time_t ) );
		status = krnlSendMessage( iCryptRevokeCert, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusError( status ) )
		{
		/* Convert any low-level certificate-specific error into something 
		   generic that makes a bit more sense to the caller */
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, errorInfo, 
					 "Couldn't extract CRL data from CRL" ) );
		}

	/* Set up the certificate object data to be written and send it to the 
	   database.  Certificate stores contain extra inforomation that's 
	   needed to build a CRL so we have to vary the SQL string depending on 
	   the keyset type */
	initBoundData( boundDataPtr );
	if( isCertStore( dbmsInfo ) )
		{
		setBoundDataDate( boundDataPtr, 0, &expiryDate );
		setBoundData( boundDataPtr, 1, crlIdData.nameID, 
					  crlIdData.nameIDlength );
		setBoundData( boundDataPtr, 2, crlIdData.issuerID, 
					  crlIdData.issuerIDlength );
		setBoundData( boundDataPtr, 3, crlIdData.certID, 
					  crlIdData.certIDlength );
		boundDataIndex = 4;
		sqlString = "INSERT INTO CRLs VALUES (?, ?, ?, ?, ?)";

		}
	else
		{
		setBoundData( boundDataPtr, 0, crlIdData.issuerID, 
					  crlIdData.issuerIDlength );
		boundDataIndex = 1;
		sqlString = "INSERT INTO CRLs VALUES (?, ?)";
		}
	if( hasBinaryBlobs( dbmsInfo ) )
		{
		setBoundDataBlob( boundDataPtr, boundDataIndex, certData, 
						  certDataLength );
		}
	else
		{
		int encodedCertDataLength;
		
		status = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE,
							   &encodedCertDataLength, certData, 
							   certDataLength, CRYPT_CERTTYPE_NONE );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "Couldn't base64-encode data" ));
			assert( DEBUG_WARN );
			retIntError();
			}
		setBoundData( boundDataPtr, boundDataIndex, encodedCertData, 
					  encodedCertDataLength );
		}
	status = dbmsUpdate( sqlString, boundDataPtr, updateType );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, errorInfo, getDbmsErrorInfo( dbmsInfo ),
					 "CRL database add operation failed" ) );
		}

	return( CRYPT_OK );
	}

/* Replace an existing certificate with a newer one */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int replaceCert( INOUT_PTR DBMS_INFO *dbmsInfo, 
						IN_HANDLE const CRYPT_HANDLE iCryptCert,
						INOUT_PTR ERROR_INFO *errorInfo )
	{
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	BYTE encodedKeyID[ ENCODED_DBXKEYID_SIZE + 8 ];
	int encodedKeyIDlength, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCert ) );
	REQUIRES( errorInfo != NULL );

	/* Delete the existing certificate and replace it with the new one */
	status = getCertKeyID( encodedKeyID, ENCODED_DBXKEYID_SIZE, 
						   &encodedKeyIDlength, iCryptCert );
	if( cryptStatusError( status ) )
		return( status );
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, encodedKeyID, encodedKeyIDlength );
	status = dbmsUpdate( "DELETE FROM certificates WHERE keyID = ?", 
						 boundDataPtr, DBMS_UPDATE_BEGIN );
	if( cryptStatusOK( status ) )
		{
		status = addCert( dbmsInfo, iCryptCert, CRYPT_CERTTYPE_CERTIFICATE,
						  CERTADD_NORMAL, DBMS_UPDATE_COMMIT, errorInfo );
		}
	else
		{
		/* Something went wrong, abort the transaction */
		dbmsUpdate( NULL, NULL, DBMS_UPDATE_ABORT );
		}

	return( status );
	}

/* Add an item to the certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setItemFunction( INOUT_PTR KEYSET_INFO *keysetInfoPtr,
							IN_HANDLE const CRYPT_HANDLE iCryptHandle,
							IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType,
							STDC_UNUSED const char *password, 
							STDC_UNUSED const int passwordLength,
							IN_FLAGS( KEYMGMT ) const int flags )
	{
	DBMS_INFO *dbmsInfo = keysetInfoPtr->keysetDBMS;
	BOOLEAN itemAdded = FALSE;
	int type, status, loopStatus, LOOP_ITERATOR;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( sanityCheckKeyset( keysetInfoPtr ) );
	REQUIRES( keysetInfoPtr->type == KEYSET_DBMS );
	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_REVOCATIONINFO || \
			  itemType == KEYMGMT_ITEM_REQUEST || \
			  itemType == KEYMGMT_ITEM_REVREQUEST || \
			  itemType == KEYMGMT_ITEM_PKIUSER );
	REQUIRES( password == NULL && passwordLength == 0 );
	REQUIRES( isFlagRangeZ( flags, KEYMGMT ) );

	/* Make sure that we've been given a certificate, certificate chain, or 
	   CRL (or a PKI user if it's a CA certificate store).  We can't do any 
	   more specific checking against the itemType because if it's coming 
	   from outside cryptlib it'll just be passed in as a generic 
	   certificate object with no distinction between object subtypes */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE,
							  &type, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( isCertStore( dbmsInfo ) )
		{
		/* The only item that can be inserted directly into a CA certificate
		   store is a CA request or PKI user information */
		if( type != CRYPT_CERTTYPE_CERTREQUEST && \
			type != CRYPT_CERTTYPE_REQUEST_CERT && \
			type != CRYPT_CERTTYPE_REQUEST_REVOCATION && \
			type != CRYPT_CERTTYPE_PKIUSER )
			{
			retExtArg( CRYPT_ARGERROR_NUM1, 
					   ( CRYPT_ARGERROR_NUM1, KEYSET_ERRINFO, 
						 "Invalid item type for CA certificate store" ) );
			}

		if( itemType == KEYMGMT_ITEM_PKIUSER )
			{
			REQUIRES( type == CRYPT_CERTTYPE_PKIUSER );
			return( caAddPKIUser( dbmsInfo, iCryptHandle, KEYSET_ERRINFO ) );
			}

		/* It's a certificate request being added to a CA certificate 
		   store */
		REQUIRES( ( itemType == KEYMGMT_ITEM_REQUEST && \
					( type == CRYPT_CERTTYPE_CERTREQUEST || \
					  type == CRYPT_CERTTYPE_REQUEST_CERT ) ) || \
				  ( itemType == KEYMGMT_ITEM_REVREQUEST && \
				    type == CRYPT_CERTTYPE_REQUEST_REVOCATION ) );
		return( caAddCertRequest( dbmsInfo, iCryptHandle, type,
								  ( flags & KEYMGMT_FLAG_UPDATE ) ? \
									TRUE : FALSE, 
								  ( flags & KEYMGMT_FLAG_INITIALOP ) ? \
									TRUE : FALSE, KEYSET_ERRINFO ) );
		}
	if( type != CRYPT_CERTTYPE_CERTIFICATE && \
		type != CRYPT_CERTTYPE_CERTCHAIN && \
		type != CRYPT_CERTTYPE_CRL )
		{
		retExtArg( CRYPT_ARGERROR_NUM1, 
				   ( CRYPT_ARGERROR_NUM1, KEYSET_ERRINFO, 
					 "Item being added must be a CRL or certificate" ) );
		}

	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_REVOCATIONINFO );

	/* Lock the certificate or CRL for our exclusive use and select the 
	   first sub-item (certificate in a certificate chain, entry in a CRL), 
	   update the keyset with the certificate(s)/CRL entries, and unlock it 
	   to allow others access.

	   An item being added may already be present but we can't fail 
	   immediately because what's being added may be a chain containing 
	   further certificates or a CRL containing further entries so we keep 
	   track of whether we've successfully added at least one item and clear 
	   data duplicate errors */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_CURSORFIRST,
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		( void ) krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_FALSE, 
								  CRYPT_IATTRIBUTE_LOCKED );

		/* CRLs can be empty in which case not finding any entries in them 
		   isn't an error - being asked to add nothing always succeeds 
		   ("Bring on the empty CRLs" - Michael Curtiz) */
		if( type == CRYPT_CERTTYPE_CRL && status == CRYPT_ERROR_NOTFOUND )
			return( CRYPT_OK );

		return( status );
		}
	if( type == CRYPT_CERTTYPE_CRL )
		{
		LOOP_LARGE( loopStatus = CRYPT_OK, cryptStatusOK( loopStatus ),
					loopStatus = krnlSendMessage( iCryptHandle, 
									IMESSAGE_SETATTRIBUTE,
									MESSAGE_VALUE_CURSORNEXT,
									CRYPT_CERTINFO_CURRENT_CERTIFICATE ) )
			{
			ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

			/* Add the next entry in the CRL */
			status = addCRL( dbmsInfo, iCryptHandle, CRYPT_UNUSED,
							 DBMS_UPDATE_NORMAL, KEYSET_ERRINFO );
			if( cryptStatusError( status ) )
				{
				if( status != CRYPT_ERROR_DUPLICATE )
					break;
				status = CRYPT_OK;
				}
			else
				itemAdded = TRUE;
			}
		}
	else
		{
		LOOP_MED( loopStatus = CRYPT_OK, cryptStatusOK( loopStatus ),
				  loopStatus = krnlSendMessage( iCryptHandle, 
									IMESSAGE_SETATTRIBUTE,
									MESSAGE_VALUE_CURSORNEXT,
									CRYPT_CERTINFO_CURRENT_CERTIFICATE ) )
			{
			ENSURES( LOOP_INVARIANT_MED_GENERIC() );

			/* Add the next certificate in the chain */
			status = addCert( dbmsInfo, iCryptHandle,
							  CRYPT_CERTTYPE_CERTIFICATE, CERTADD_NORMAL,
							  DBMS_UPDATE_NORMAL, KEYSET_ERRINFO );
			if( cryptStatusError( status ) )
				{
				if( status != CRYPT_ERROR_DUPLICATE )
					break;

				/* When a certificate is re-issued with everything identical 
				   except for the expiry date, which unfortunately is far
				   more common than it should be through a combination of 
				   forced expiry at 12 months for CA billing purposes and 
				   magical thinking around the significance of a key once
				   generated, we can't add the new certificate since it's an
				   exact duplicate of an existing one except for the 
				   validity period.  To deal with this we check for the 
				   newer-certificate situation and try and replace the 
				   existing copy with the newer one */
				status = checkReplacementCert( dbmsInfo, iCryptHandle );
				if( cryptStatusError( status ) )
					{
					/* It's a duplicate, continue with the next 
					   certificate in the chain */
					status = CRYPT_OK;
					continue;
					}

				/* It's a newer version of an existing certificate, replace
				   the current one with the newer one */
				status = replaceCert( dbmsInfo, iCryptHandle, 
									  KEYSET_ERRINFO );
				if( cryptStatusError( status ) )
					break;
				}

			/* Remember that we added at least one item */
			itemAdded = TRUE;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	( void ) krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	if( !itemAdded )
		{
		/* We reached the end of the certificate chain/CRL without finding 
		   anything that we could add, return a data duplicate error */
		retExt( CRYPT_ERROR_DUPLICATE, 
				( CRYPT_ERROR_DUPLICATE, KEYSET_ERRINFO, 
				  "No new %s were found to add to the certificate store",
				  ( type == CRYPT_CERTTYPE_CRL ) ? \
					"CRL entries" : "certificates" ) );
		}

	return( CRYPT_OK );
	}

/* Delete an item from the certificate store */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int deleteItemFunction( INOUT_PTR KEYSET_INFO *keysetInfoPtr,
							   IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType,
							   IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
							   IN_BUFFER( keyIDlength ) const void *keyID, 
							   IN_LENGTH_KEYID const int keyIDlength )
	{
	DBMS_INFO *dbmsInfo = keysetInfoPtr->keysetDBMS;
	BOUND_DATA boundData[ BOUND_DATA_MAXITEMS ], *boundDataPtr = boundData;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE + 8 ];
	char encodedKeyID[ ( CRYPT_MAX_TEXTSIZE * 2 ) + 8 ];
	const char *keyName = getKeyName( keyIDtype );
	const char *deleteString = getDeleteString( itemType );
	int encodedKeyIDlength, status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );
	assert( isReadPtrDynamic( keyID, keyIDlength ) );

	REQUIRES( sanityCheckKeyset( keysetInfoPtr ) );
	REQUIRES( keysetInfoPtr->type == KEYSET_DBMS );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_PKIUSER );
	REQUIRES( ( !isCertStore( dbmsInfo ) && \
				itemType == KEYMGMT_ITEM_PUBLICKEY ) || \
			  ( isCertStore( dbmsInfo ) && \
				itemType == KEYMGMT_ITEM_PKIUSER ) );
	REQUIRES( isEnumRange( keyIDtype, CRYPT_KEYID ) );
	REQUIRES( keyIDlength >= MIN_NAME_LENGTH && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );

	/* Delete the item from the certificate store */
	status = makeKeyID( encodedKeyID, CRYPT_MAX_TEXTSIZE * 2, 
						&encodedKeyIDlength, keyIDtype, keyID, keyIDlength );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_STR1 );
	if( isCertStore( dbmsInfo ) )
		{
		/* The only item that can be deleted from a CA certificate store is 
		   PKI user information */
		if( itemType != KEYMGMT_ITEM_PKIUSER )
			{
			retExtArg( CRYPT_ARGERROR_NUM1, 
					   ( CRYPT_ARGERROR_NUM1, KEYSET_ERRINFO, 
						 "Invalid operation for CA certificate store" ) );
			}

		return( caDeletePKIUser( dbmsInfo, keyIDtype, keyID, keyIDlength, 
								 KEYSET_ERRINFO ) );
		}
	ENSURES( keyName != NULL && deleteString != NULL );
	strlcpy_s( sqlBuffer, MAX_SQL_QUERY_SIZE, deleteString );
	strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, keyName );
	strlcat_s( sqlBuffer, MAX_SQL_QUERY_SIZE, " = ?" );
	initBoundData( boundDataPtr );
	setBoundData( boundDataPtr, 0, encodedKeyID, encodedKeyIDlength );
	status = dbmsUpdate( sqlBuffer, boundDataPtr, DBMS_UPDATE_NORMAL );
	if( cryptStatusError( status ) )
		{
		retExtErr( status, 
				   ( status, KEYSET_ERRINFO, getDbmsErrorInfo( dbmsInfo ),
					 "Certificate database delete operation failed" ) );
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Database Access Routines						*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initDBMSwrite( INOUT_PTR KEYSET_INFO *keysetInfoPtr )
	{
	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_DBMS );

	FNPTR_SET( keysetInfoPtr->setItemFunction, setItemFunction );
	FNPTR_SET( keysetInfoPtr->deleteItemFunction, deleteItemFunction );

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
