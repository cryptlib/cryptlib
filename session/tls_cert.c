<<<<<<< HEAD
/****************************************************************************
*																			*
*					  cryptlib TLS Certificate Handling						*
*					   Copyright Peter Gutmann 1998-2022					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "tls.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Matching names in certificates can get quite tricky due to the usual 
   erratic nature of what gets put in them.  Firstly, supposed FQDNs can be 
   unqualified names and/or can be present as full URLs rather than just 
   domain names, so we use sNetParseURL() on them before doing anything else 
   with them.  Secondly, PKIX tries to pretend that wildcard certificates 
   don't exist, and so there are no official guidelines for how they should 
   be laid out.  To minimise the potential for mischief we only allow a
   wildcard at the start of the domain, and don't allow wildcards for the 
   first- or second-level names.
   
   Since this code is going to result in server names (and therefore 
   connections) being rejected, it's unusually loquacious about the reasons 
   for the rejection */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 6 ) ) \
static int matchName( INOUT_BUFFER_FIXED( serverNameLength ) \
						BYTE *serverName,
					  IN_LENGTH_DNS const int serverNameLength,
					  INOUT_BUFFER_FIXED( originalCertNameLength ) \
						BYTE *certName,
					  IN_LENGTH_DNS const int originalCertNameLength,
					  const CRYPT_CERTIFICATE iCryptCert,
					  OUT_PTR ERROR_INFO *errorInfo )
	{
	URL_INFO urlInfo;
	BOOLEAN hasWildcard = FALSE;
#ifdef USE_ERRMSGS
	char serverCertName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	LOOP_INDEX i;
	int certNameLength, dotCount = 0, status;

	assert( isWritePtrDynamic( serverName, serverNameLength ) );
	assert( isWritePtrDynamic( certName, originalCertNameLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( serverNameLength > 0 && serverNameLength <= MAX_DNS_SIZE );
	REQUIRES( originalCertNameLength > 0 && \
			  originalCertNameLength <= MAX_DNS_SIZE );
	REQUIRES( isHandleRangeValid( iCryptCert ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	/* Extract the FQDN portion from the certificate name */
	status = sNetParseURL( &urlInfo, certName, originalCertNameLength, 
						   URL_TYPE_NONE );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo,
				  "Invalid host name '%s' in server's certificate for '%s'",
				  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
								  originalCertNameLength ),
				  getCertHolderName( iCryptCert, serverCertName, 
									 CRYPT_MAX_TEXTSIZE ) ) );
		}
	certName = ( BYTE * ) urlInfo.host;
	certNameLength = urlInfo.hostLen;
	ENSURES( certNameLength > 0 && certNameLength <= MAX_URL_SIZE ); 

	/* If the name in the certificate is too short or longer than the server 
	   name then it can't be a match */
	if( certNameLength < MIN_DNS_SIZE || \
		certNameLength > serverNameLength )
		{
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo,
				  "Server name '%s' doesn't match host name '%s' in "
				  "server's certificate for '%s'", 
				  sanitiseString( serverName, CRYPT_MAX_TEXTSIZE,
								  serverNameLength ),
				  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
								  certNameLength ),
				  getCertHolderName( iCryptCert, serverCertName, 
									 CRYPT_MAX_TEXTSIZE ) ) );
		}

	/* Make sure that, if it's a wildcarded name, it follows the pattern 
	   "'*' ... '.' ... '.' ..." */
	LOOP_EXT( i = 0, i < certNameLength, i++, MAX_URL_SIZE + 1 )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_EXT( i, 0, certNameLength - 1,
									 MAX_URL_SIZE + 1 ) );

		ch = byteToInt( certName[ i ] );
		if( ch == '*' )
			{
			if( i != 0 )
				{
				/* The wildcard character isn't the first one in the name, 
				   it's invalid */
				retExt( CRYPT_ERROR_INVALID,
						( CRYPT_ERROR_INVALID, errorInfo,
						  "Host name '%s' in server's certificate for '%s' "
						  "contains wildcard at invalid location",
						  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
										  certNameLength ),
						  getCertHolderName( iCryptCert, serverCertName, 
											 CRYPT_MAX_TEXTSIZE ) ) );
				}
			hasWildcard = TRUE;
			}
		if( ch == '.' )
			dotCount++;
		}
	ENSURES( LOOP_BOUND_OK );
	if( hasWildcard && dotCount < 2 )
		{
		/* The wildcard applies to the first- or second-level domain, it's 
		   invalid */
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo,
				  "Host name '%s' in server's certificate for '%s' "
				  "contains wildcard at invalid domain level",
				  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
								  certNameLength ),
				  getCertHolderName( iCryptCert, serverCertName, 
									 CRYPT_MAX_TEXTSIZE ) ) );
		}

	/* Match the certificate name and the server name, taking into account
	   wildcarding:
					   +------+ certNameLength
					   |	  |
		certName	  *.abc.com		certName+1 = .abc.com
		serverName	foo.abc.com		serverName+delta = .abc.com
					|		  |
					+---------+ serverNameLength
					|--| delta */
	if( hasWildcard )
		{
		const int delta = serverNameLength - ( certNameLength - 1 );

		ENSURES_B( delta > 0 && delta < serverNameLength );

		/* Match the suffix past the wildcard */
		if( !memcmp( certName + 1, serverName + delta, 
					 certNameLength - 1 ) )
			return( CRYPT_OK );
		}
	else
		{
		/* It's a straight match */
		if( certNameLength == serverNameLength && \
			!memcmp( certName, serverName, certNameLength ) )
			return( CRYPT_OK );
		}

	/* The name doesn't match */
	retExt( CRYPT_ERROR_INVALID,
			( CRYPT_ERROR_INVALID, errorInfo,
			  "Server name '%s' doesn't match host name '%s' in server's " 
			  "certificate for '%s'", 
			  sanitiseString( serverName, CRYPT_MAX_TEXTSIZE,
							  serverNameLength ),
			  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
							  certNameLength ),
			  getCertHolderName( iCryptCert, serverCertName, 
								 CRYPT_MAX_TEXTSIZE ) ) );
	}

/****************************************************************************
*																			*
*					Server Certificate Checking Functions					*
*																			*
****************************************************************************/

/* Check a host name against one or more server names in the certificate.
   This is used by both the client to verify the server's certificate and
   the server to switch certificates based on an SNI */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int checkHostNameTLS( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
					  INOUT_BUFFER_FIXED( serverNameLength ) void *serverName,
					  IN_LENGTH_DNS const int serverNameLength,
					  OUT_PTR ERROR_INFO *errorInfo )
	{
	MESSAGE_DATA msgData;
	static const int nameValue = CRYPT_CERTINFO_SUBJECTNAME;
	static const int altNameValue = CRYPT_CERTINFO_SUBJECTALTNAME;
	static const int dnsNameValue = CRYPT_CERTINFO_DNSNAME;
	char certName[ MAX_DNS_SIZE + 8 ];
#ifdef USE_ERRMSGS
	char serverCertName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	BOOLEAN multipleNamesPresent = FALSE;
	int certNameLength = CRYPT_ERROR, status, LOOP_ITERATOR;

	assert( isWritePtrDynamic( serverName, serverNameLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCert ) );
	REQUIRES( serverNameLength > 0 && serverNameLength <= MAX_DNS_SIZE );
	REQUIRES( isBooleanValue( multipleNamesPresent ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	/* The server name is traditionally given as the certificate's CN, 
	   however it may also be present as an altName.  First we check whether 
	   there's an altName present, this is used to control error handling 
	   since if there isn't one present we stop after a failed CN check and 
	   if there is one present we continue on to the altName(s) */
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
							  ( MESSAGE_CAST ) &altNameValue, 
							  CRYPT_ATTRIBUTE_CURRENT );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CERTINFO_DNSNAME );
		if( cryptStatusOK( status ) )
			multipleNamesPresent = TRUE;
		}
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 ( MESSAGE_CAST ) &nameValue, CRYPT_ATTRIBUTE_CURRENT );
					 /* Re-select the subject DN */

	/* Get the CN and check it against the host name */
	setMessageData( &msgData, certName, MAX_DNS_SIZE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CERTINFO_COMMONNAME );
	if( cryptStatusOK( status ) )
		{
		certNameLength = msgData.length;
		status = matchName( serverName, serverNameLength, certName,
							certNameLength, iCryptCert, errorInfo );
		if( cryptStatusOK( status ) )
			return( status );

		/* If this was the only name that's present then we can't go any 
		   further (the extended error information will have been provided 
		   by matchName()) */
		if( !multipleNamesPresent )
			return( CRYPT_ERROR_INVALID );
		}

	/* The CN didn't match, check the altName */
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
							  ( MESSAGE_CAST ) &altNameValue, 
							  CRYPT_ATTRIBUTE_CURRENT );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &dnsNameValue, 
								  CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
		}
	if( cryptStatusError( status ) )
		{
		/* We couldn't find a DNS name in the altName, which means that the 
		   server name doesn't match the name (from the previously-used CN) 
		   in the certificate.
		   
		   If there's no CN present then there's no certificate host name to 
		   use in the error message and we have to construct our own one, 
		   otherwise it'll have been provided by the previous call to 
		   matchName() */
		krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
						 ( MESSAGE_CAST ) &nameValue, 
						 CRYPT_ATTRIBUTE_CURRENT );	/* Re-select subject DN */
		if( certNameLength == CRYPT_ERROR )
			{
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, errorInfo,
					  "Server name '%s' doesn't match host name in "
					  "server's certificate for '%s'",
					  sanitiseString( serverName, CRYPT_MAX_TEXTSIZE,
									  serverNameLength ),
					  getCertHolderName( iCryptCert, serverCertName, 
										 CRYPT_MAX_TEXTSIZE ) ) );
			}
		return( CRYPT_ERROR_INVALID );	/* See comment above */
		}
	LOOP_LARGE_CHECKINC( cryptStatusOK( status ), 
						 status = krnlSendMessage( iCryptCert, 
											IMESSAGE_SETATTRIBUTE, 
											MESSAGE_VALUE_CURSORNEXT,
											CRYPT_ATTRIBUTE_CURRENT_INSTANCE ) )
		{
		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		setMessageData( &msgData, certName, MAX_DNS_SIZE );
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CERTINFO_DNSNAME );
		if( cryptStatusOK( status ) )
			{
			status = matchName( serverName, serverNameLength, certName,
								msgData.length, iCryptCert, errorInfo );
			if( cryptStatusOK( status ) )
				return( status );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 ( MESSAGE_CAST ) &nameValue, CRYPT_ATTRIBUTE_CURRENT );
					 /* Re-select subject DN */

	/* We couldn't find any name that matches the server name */
	retExt( CRYPT_ERROR_INVALID,
			( CRYPT_ERROR_INVALID, errorInfo,
			  "Server name '%s' doesn't match any of the host names in "
			  "server's certificate for '%s'",
			  sanitiseString( serverName, CRYPT_MAX_TEXTSIZE,
							  serverNameLength ),
			  getCertHolderName( iCryptCert, serverCertName, 
								 CRYPT_MAX_TEXTSIZE ) ) );
	}

/* Check that the certificate presented by the server is in order.  This 
   involves checking that the name of the host that we've connected to
   matches one of the names in the certificate, and that the certificate 
   itself is in order */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkTLSCertificateInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	const CRYPT_CERTIFICATE iCryptCert = sessionInfoPtr->iKeyexAuthContext;
	const ATTRIBUTE_LIST *serverNamePtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME );
	const int verifyFlags = \
				GET_FLAGS( sessionInfoPtr->protocolFlags,
						   TLS_PFLAG_DISABLE_NAMEVERIFY | \
						   TLS_PFLAG_DISABLE_CERTVERIFY );
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* There is one check that overrides all others and that's when an 
	   explicit permitted-certificates whitelist has been provided */
	status = checkCertWhitelist( sessionInfoPtr, iCryptCert, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* If all verification has been disabled then there's nothing to do */
	if( verifyFlags == ( TLS_PFLAG_DISABLE_NAMEVERIFY | \
						 TLS_PFLAG_DISABLE_CERTVERIFY ) )
		return( CRYPT_OK );

	/* If there's a server name present and name checking hasn't been 
	   disabled, make sure that it matches one of the names in the 
	   certificate */
	if( serverNamePtr != NULL && \
		!( verifyFlags & TLS_PFLAG_DISABLE_NAMEVERIFY ) )
		{
		status = checkHostNameTLS( iCryptCert, serverNamePtr->value, 
								   serverNamePtr->valueLength, 
								   SESSION_ERRINFO );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If certificate verification hasn't been disabled, make sure that the 
	   server's certificate verifies */
	if( !( verifyFlags & TLS_PFLAG_DISABLE_CERTVERIFY ) )
		{
		/* This is something that can't be easily enabled by default since 
		   cryptlib isn't a web browser and therefore won't follow the 
		   "trust anything from a commercial CA" model.  In particular 
		   cryptlib users tend to fall into two classes, commercial/
		   government users, often in high-security environments, who run 
		   their own PKIs and definitely won't want anything from a 
		   commercial CA to be accepted, and noncommercial users who won't 
		   be buying certificates from a commercial CA.  In neither of these 
		   cases is trusting certs from a commercial CA useful, in the 
		   former case it leads to a serious security breach (as some US 
		   government agencies have discovered), in the latter case it leads 
		   to all certificates being rejected since they weren't bought from 
		   a commercial CA.  The recommended solutions to this problem are 
		   covered in the cryptlib manual.
		   
		   Another lesser problem that this deals with s that it defeats 
		   root store fingerprinting.  To do this, you MITM the target and 
		   use a self-signed root certificate that matches an existing 
		   (probable) CA in the root store, except that the key will be 
		   different.  If the target responds with a signature failure then 
		   the real CA certificate is present in the root store, and we can
		   buy a cert from them that will be trusted by the target */
		}

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
=======
/****************************************************************************
*																			*
*					  cryptlib TLS Certificate Handling						*
*					   Copyright Peter Gutmann 1998-2022					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "tls.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Matching names in certificates can get quite tricky due to the usual 
   erratic nature of what gets put in them.  Firstly, supposed FQDNs can be 
   unqualified names and/or can be present as full URLs rather than just 
   domain names, so we use sNetParseURL() on them before doing anything else 
   with them.  Secondly, PKIX tries to pretend that wildcard certificates 
   don't exist, and so there are no official guidelines for how they should 
   be laid out.  To minimise the potential for mischief we only allow a
   wildcard at the start of the domain, and don't allow wildcards for the 
   first- or second-level names.
   
   Since this code is going to result in server names (and therefore 
   connections) being rejected, it's unusually loquacious about the reasons 
   for the rejection */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 6 ) ) \
static int matchName( INOUT_BUFFER_FIXED( serverNameLength ) \
						BYTE *serverName,
					  IN_LENGTH_DNS const int serverNameLength,
					  INOUT_BUFFER_FIXED( originalCertNameLength ) \
						BYTE *certName,
					  IN_LENGTH_DNS const int originalCertNameLength,
					  const CRYPT_CERTIFICATE iCryptCert,
					  OUT_PTR ERROR_INFO *errorInfo )
	{
	URL_INFO urlInfo;
	BOOLEAN hasWildcard = FALSE;
#ifdef USE_ERRMSGS
	char serverCertName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	LOOP_INDEX i;
	int certNameLength, dotCount = 0, status;

	assert( isWritePtrDynamic( serverName, serverNameLength ) );
	assert( isWritePtrDynamic( certName, originalCertNameLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( serverNameLength > 0 && serverNameLength <= MAX_DNS_SIZE );
	REQUIRES( originalCertNameLength > 0 && \
			  originalCertNameLength <= MAX_DNS_SIZE );
	REQUIRES( isHandleRangeValid( iCryptCert ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	/* Extract the FQDN portion from the certificate name */
	status = sNetParseURL( &urlInfo, certName, originalCertNameLength, 
						   URL_TYPE_NONE );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo,
				  "Invalid host name '%s' in server's certificate for '%s'",
				  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
								  originalCertNameLength ),
				  getCertHolderName( iCryptCert, serverCertName, 
									 CRYPT_MAX_TEXTSIZE ) ) );
		}
	certName = ( BYTE * ) urlInfo.host;
	certNameLength = urlInfo.hostLen;
	ENSURES( certNameLength > 0 && certNameLength <= MAX_URL_SIZE ); 

	/* If the name in the certificate is too short or longer than the server 
	   name then it can't be a match */
	if( certNameLength < MIN_DNS_SIZE || \
		certNameLength > serverNameLength )
		{
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo,
				  "Server name '%s' doesn't match host name '%s' in "
				  "server's certificate for '%s'", 
				  sanitiseString( serverName, CRYPT_MAX_TEXTSIZE,
								  serverNameLength ),
				  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
								  certNameLength ),
				  getCertHolderName( iCryptCert, serverCertName, 
									 CRYPT_MAX_TEXTSIZE ) ) );
		}

	/* Make sure that, if it's a wildcarded name, it follows the pattern 
	   "'*' ... '.' ... '.' ..." */
	LOOP_EXT( i = 0, i < certNameLength, i++, MAX_URL_SIZE + 1 )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_EXT( i, 0, certNameLength - 1,
									 MAX_URL_SIZE + 1 ) );

		ch = byteToInt( certName[ i ] );
		if( ch == '*' )
			{
			if( i != 0 )
				{
				/* The wildcard character isn't the first one in the name, 
				   it's invalid */
				retExt( CRYPT_ERROR_INVALID,
						( CRYPT_ERROR_INVALID, errorInfo,
						  "Host name '%s' in server's certificate for '%s' "
						  "contains wildcard at invalid location",
						  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
										  certNameLength ),
						  getCertHolderName( iCryptCert, serverCertName, 
											 CRYPT_MAX_TEXTSIZE ) ) );
				}
			hasWildcard = TRUE;
			}
		if( ch == '.' )
			dotCount++;
		}
	ENSURES( LOOP_BOUND_OK );
	if( hasWildcard && dotCount < 2 )
		{
		/* The wildcard applies to the first- or second-level domain, it's 
		   invalid */
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, errorInfo,
				  "Host name '%s' in server's certificate for '%s' "
				  "contains wildcard at invalid domain level",
				  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
								  certNameLength ),
				  getCertHolderName( iCryptCert, serverCertName, 
									 CRYPT_MAX_TEXTSIZE ) ) );
		}

	/* Match the certificate name and the server name, taking into account
	   wildcarding:
					   +------+ certNameLength
					   |	  |
		certName	  *.abc.com		certName+1 = .abc.com
		serverName	foo.abc.com		serverName+delta = .abc.com
					|		  |
					+---------+ serverNameLength
					|--| delta */
	if( hasWildcard )
		{
		const int delta = serverNameLength - ( certNameLength - 1 );

		ENSURES_B( delta > 0 && delta < serverNameLength );

		/* Match the suffix past the wildcard */
		if( !memcmp( certName + 1, serverName + delta, 
					 certNameLength - 1 ) )
			return( CRYPT_OK );
		}
	else
		{
		/* It's a straight match */
		if( certNameLength == serverNameLength && \
			!memcmp( certName, serverName, certNameLength ) )
			return( CRYPT_OK );
		}

	/* The name doesn't match */
	retExt( CRYPT_ERROR_INVALID,
			( CRYPT_ERROR_INVALID, errorInfo,
			  "Server name '%s' doesn't match host name '%s' in server's " 
			  "certificate for '%s'", 
			  sanitiseString( serverName, CRYPT_MAX_TEXTSIZE,
							  serverNameLength ),
			  sanitiseString( certName, CRYPT_MAX_TEXTSIZE,
							  certNameLength ),
			  getCertHolderName( iCryptCert, serverCertName, 
								 CRYPT_MAX_TEXTSIZE ) ) );
	}

/****************************************************************************
*																			*
*					Server Certificate Checking Functions					*
*																			*
****************************************************************************/

/* Check a host name against one or more server names in the certificate.
   This is used by both the client to verify the server's certificate and
   the server to switch certificates based on an SNI */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int checkHostNameTLS( IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
					  INOUT_BUFFER_FIXED( serverNameLength ) void *serverName,
					  IN_LENGTH_DNS const int serverNameLength,
					  OUT_PTR ERROR_INFO *errorInfo )
	{
	MESSAGE_DATA msgData;
	static const int nameValue = CRYPT_CERTINFO_SUBJECTNAME;
	static const int altNameValue = CRYPT_CERTINFO_SUBJECTALTNAME;
	static const int dnsNameValue = CRYPT_CERTINFO_DNSNAME;
	char certName[ MAX_DNS_SIZE + 8 ];
#ifdef USE_ERRMSGS
	char serverCertName[ CRYPT_MAX_TEXTSIZE + 8 ];
#endif /* USE_ERRMSGS */
	BOOLEAN multipleNamesPresent = FALSE;
	int certNameLength = CRYPT_ERROR, status, LOOP_ITERATOR;

	assert( isWritePtrDynamic( serverName, serverNameLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCert ) );
	REQUIRES( serverNameLength > 0 && serverNameLength <= MAX_DNS_SIZE );
	REQUIRES( isBooleanValue( multipleNamesPresent ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	/* The server name is traditionally given as the certificate's CN, 
	   however it may also be present as an altName.  First we check whether 
	   there's an altName present, this is used to control error handling 
	   since if there isn't one present we stop after a failed CN check and 
	   if there is one present we continue on to the altName(s) */
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
							  ( MESSAGE_CAST ) &altNameValue, 
							  CRYPT_ATTRIBUTE_CURRENT );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CERTINFO_DNSNAME );
		if( cryptStatusOK( status ) )
			multipleNamesPresent = TRUE;
		}
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 ( MESSAGE_CAST ) &nameValue, CRYPT_ATTRIBUTE_CURRENT );
					 /* Re-select the subject DN */

	/* Get the CN and check it against the host name */
	setMessageData( &msgData, certName, MAX_DNS_SIZE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CERTINFO_COMMONNAME );
	if( cryptStatusOK( status ) )
		{
		certNameLength = msgData.length;
		status = matchName( serverName, serverNameLength, certName,
							certNameLength, iCryptCert, errorInfo );
		if( cryptStatusOK( status ) )
			return( status );

		/* If this was the only name that's present then we can't go any 
		   further (the extended error information will have been provided 
		   by matchName()) */
		if( !multipleNamesPresent )
			return( CRYPT_ERROR_INVALID );
		}

	/* The CN didn't match, check the altName */
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
							  ( MESSAGE_CAST ) &altNameValue, 
							  CRYPT_ATTRIBUTE_CURRENT );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &dnsNameValue, 
								  CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
		}
	if( cryptStatusError( status ) )
		{
		/* We couldn't find a DNS name in the altName, which means that the 
		   server name doesn't match the name (from the previously-used CN) 
		   in the certificate.
		   
		   If there's no CN present then there's no certificate host name to 
		   use in the error message and we have to construct our own one, 
		   otherwise it'll have been provided by the previous call to 
		   matchName() */
		krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
						 ( MESSAGE_CAST ) &nameValue, 
						 CRYPT_ATTRIBUTE_CURRENT );	/* Re-select subject DN */
		if( certNameLength == CRYPT_ERROR )
			{
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, errorInfo,
					  "Server name '%s' doesn't match host name in "
					  "server's certificate for '%s'",
					  sanitiseString( serverName, CRYPT_MAX_TEXTSIZE,
									  serverNameLength ),
					  getCertHolderName( iCryptCert, serverCertName, 
										 CRYPT_MAX_TEXTSIZE ) ) );
			}
		return( CRYPT_ERROR_INVALID );	/* See comment above */
		}
	LOOP_LARGE_CHECKINC( cryptStatusOK( status ), 
						 status = krnlSendMessage( iCryptCert, 
											IMESSAGE_SETATTRIBUTE, 
											MESSAGE_VALUE_CURSORNEXT,
											CRYPT_ATTRIBUTE_CURRENT_INSTANCE ) )
		{
		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		setMessageData( &msgData, certName, MAX_DNS_SIZE );
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CERTINFO_DNSNAME );
		if( cryptStatusOK( status ) )
			{
			status = matchName( serverName, serverNameLength, certName,
								msgData.length, iCryptCert, errorInfo );
			if( cryptStatusOK( status ) )
				return( status );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 ( MESSAGE_CAST ) &nameValue, CRYPT_ATTRIBUTE_CURRENT );
					 /* Re-select subject DN */

	/* We couldn't find any name that matches the server name */
	retExt( CRYPT_ERROR_INVALID,
			( CRYPT_ERROR_INVALID, errorInfo,
			  "Server name '%s' doesn't match any of the host names in "
			  "server's certificate for '%s'",
			  sanitiseString( serverName, CRYPT_MAX_TEXTSIZE,
							  serverNameLength ),
			  getCertHolderName( iCryptCert, serverCertName, 
								 CRYPT_MAX_TEXTSIZE ) ) );
	}

/* Check that the certificate presented by the server is in order.  This 
   involves checking that the name of the host that we've connected to
   matches one of the names in the certificate, and that the certificate 
   itself is in order */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkTLSCertificateInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	const CRYPT_CERTIFICATE iCryptCert = sessionInfoPtr->iKeyexAuthContext;
	const ATTRIBUTE_LIST *serverNamePtr = \
				findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME );
	const int verifyFlags = \
				GET_FLAGS( sessionInfoPtr->protocolFlags,
						   TLS_PFLAG_DISABLE_NAMEVERIFY | \
						   TLS_PFLAG_DISABLE_CERTVERIFY );
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );

	/* There is one check that overrides all others and that's when an 
	   explicit permitted-certificates whitelist has been provided */
	status = checkCertWhitelist( sessionInfoPtr, iCryptCert, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* If all verification has been disabled then there's nothing to do */
	if( verifyFlags == ( TLS_PFLAG_DISABLE_NAMEVERIFY | \
						 TLS_PFLAG_DISABLE_CERTVERIFY ) )
		return( CRYPT_OK );

	/* If there's a server name present and name checking hasn't been 
	   disabled, make sure that it matches one of the names in the 
	   certificate */
	if( serverNamePtr != NULL && \
		!( verifyFlags & TLS_PFLAG_DISABLE_NAMEVERIFY ) )
		{
		status = checkHostNameTLS( iCryptCert, serverNamePtr->value, 
								   serverNamePtr->valueLength, 
								   SESSION_ERRINFO );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If certificate verification hasn't been disabled, make sure that the 
	   server's certificate verifies */
	if( !( verifyFlags & TLS_PFLAG_DISABLE_CERTVERIFY ) )
		{
		/* This is something that can't be easily enabled by default since 
		   cryptlib isn't a web browser and therefore won't follow the 
		   "trust anything from a commercial CA" model.  In particular 
		   cryptlib users tend to fall into two classes, commercial/
		   government users, often in high-security environments, who run 
		   their own PKIs and definitely won't want anything from a 
		   commercial CA to be accepted, and noncommercial users who won't 
		   be buying certificates from a commercial CA.  In neither of these 
		   cases is trusting certs from a commercial CA useful, in the 
		   former case it leads to a serious security breach (as some US 
		   government agencies have discovered), in the latter case it leads 
		   to all certificates being rejected since they weren't bought from 
		   a commercial CA.  The recommended solutions to this problem are 
		   covered in the cryptlib manual.
		   
		   Another lesser problem that this deals with s that it defeats 
		   root store fingerprinting.  To do this, you MITM the target and 
		   use a self-signed root certificate that matches an existing 
		   (probable) CA in the root store, except that the key will be 
		   different.  If the target responds with a signature failure then 
		   the real CA certificate is present in the root store, and we can
		   buy a cert from them that will be trusted by the target */
		}

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
