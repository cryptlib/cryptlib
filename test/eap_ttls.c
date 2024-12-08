<<<<<<< HEAD
/****************************************************************************
*																			*
*							cryptlib EAP-TTLS Code							*
*						Copyright Peter Gutmann 2016-2023					*
*																			*
****************************************************************************/

/* Under Windows debug mode everything is enabled by default when building 
   cryptlib, so we also enable the required options here.  Under Unix it'll
   need to be enabled manually by adding '-DUSE_EAP -DUSE_DES' to the build 
   command.  Note that this needs to be done via the build process even if
   it's already defined in config.h since that only applies to cryptlib, not
   to this module */

#if defined( _MSC_VER ) && !defined( NDEBUG )
  #define USE_EAP
#endif /* Windows debug build */

#include <stdlib.h>
#include <string.h>
#if !( defined( _WIN32 ) || defined( _WIN64 ) )
  #include <locale.h>
#endif /* !Windows */
#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/* RADIUS attribute types and flags used with DIAMETER as used with 
   EAP-TTLS */

#define RADIUS_SUBTYPE_USERNAME			1
#define RADIUS_SUBTYPE_PASSWORD			2
#define RADIUS_SUBTYPE_CHAP				3
#define RADIUS_SUBTYPE_CHAPCHALLENGE	60

#define FLAG_MANDATORY					0x40
#define FLAG_VENDORIDPRESENT			0x80

/* Vendor-specific types used with DIAMETER as used with EAP-TTLS.  This 
   changes the interpretation of the type field above to use a vendor-
   specific namespace rather than the RADIUS namespace */

#define VENDOR_ID_MICROSOFT				311

#define VENDOR_MSCHAP_CHALLENGE			11
#define VENDOR_MSCHAP2_RESPONSE			25

/* The maximum size of the buffer to hold the authentication data sent over
   the EAP-TTLS tunnel */

#define EAPTTLS_BUFFER_SIZE				256

/* Additional debugging suppport when we're built in debug mode */

#ifdef NDEBUG
  #define DEBUG_PUTS( x )
  #define DEBUG_PRINT( x )
  #define DEBUG_DUMPHEX( x, xLen )
  #define DEBUG_DUMPHEX_ALL( x, xLen )
#else
  #define DEBUG_PUTS( x )			printf( "%s\n", x )
  #define DEBUG_PRINT( x )			printf x
  #define DEBUG_DUMPHEX				dumpHexDataPart
  #define DEBUG_DUMPHEX_ALL			dumpHexData
#endif /* NDEBUG */

typedef enum { AUTH_PAP, AUTH_CHAP, AUTH_MSCHAPV2, AUTH_LAST } AUTH_TYPE;

#ifdef USE_EAP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/****************************************************************************
*																			*
*							Encode EAP-TTLS Message							*
*																			*
****************************************************************************/

/* Encode an attribute in TTLS AVP format, RFC 5281:

	0..3:	uint32	type
	4:		byte	flags
	5..7:	uint24	length		// Including header size
  [	8..11:	uint32	vendorID ]

   The TTLS AVP format, although it's built on RADIUS values, uses the 
   DIAMETER encoding which requires that all TLVs be zero-padded to 4-byte 
   alignment for no known reason.  The following function adds the necessary 
   zero padding alongside performing the TLV encoding.  encode(Vendor)AVP() 
   assumes that get(Vendor)AVPsize() has been called previously in order to 
   verify available space */

#define getPadSize( length )	( ( 4 - ( ( length ) % 4 ) ) % 4 )
#define getHeaderLen( vendorID ) \
								( 8 + ( ( vendorID > 0 ) ? 4 : 0 ) )

static int getVendorAVPsize( const int vendorID, const int valueLen )
	{
	const int length = getHeaderLen( vendorID ) + valueLen;

	return( length + getPadSize( length ) );
	}

#define getAVPsize( valueLen ) \
		getVendorAVPsize( CRYPT_UNUSED, valueLen )

static int encodeVendorAVP( BYTE *dataPtr, const int type, 
							const int vendorID, const BYTE *value, 
							const int valueLen )
	{
	const int headerLen = getHeaderLen( vendorID );
	const int totalLen = headerLen + valueLen;
	const int padSize = getPadSize( totalLen );

	/* Encode the header */
	memset( dataPtr, 0, 16 );
	dataPtr[ 2 ] = ( type >> 8 ) & 0xFF;
	dataPtr[ 3 ] = type & 0xFF;
	dataPtr[ 4 ] = FLAG_MANDATORY;
	dataPtr[ 6 ] = ( totalLen >> 8 ) & 0xFF;
	dataPtr[ 7 ] = totalLen & 0xFF;
	if( vendorID > 0 )
		{
		dataPtr[ 4 ] |= FLAG_VENDORIDPRESENT;
		dataPtr[ 10 ] = ( vendorID >> 8 ) & 0xFF;
		dataPtr[ 11 ] = vendorID & 0xFF;
		}

	/* Encode the payload and padding */
	memcpy( dataPtr + headerLen, value, valueLen );
	if( padSize > 0 )
		memset( dataPtr + totalLen, 0, padSize );

	return( totalLen + padSize );
	}

#define encodeAVP( dataPtr, type, value, valueLen ) \
		encodeVendorAVP( dataPtr, type, CRYPT_UNUSED, value, valueLen )

/* Create a TTLS AVP encoding of the PAP data:

	{ User-Name, byte[] data },
	{ Password, byte[] data } */

static int createTTLSAVPPAP( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
							 int *ttlsAVPlength,
							 const void *userName, const int userNameLength,
							 const void *password, const int passwordLength )
	{
	int ttlsAVPlen;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( getAVPsize( userNameLength ) + \
		getAVPsize( passwordLength ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Set up the RADIUS User-Name and Password attributes */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_PASSWORD, 
							 password, passwordLength );
	*ttlsAVPlength = ttlsAVPlen;

	return( CRYPT_OK );
	}

/* Create a TTLS AVP encoding of the CHAP data:

	{ User-Name, byte[] data },
	{ CHAP-Challenge, byte[16] data },
	{ CHAP-Password, byte ident || 
					 byte[16] data } */

static int createTTLSAVPCHAP( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
							  int *ttlsAVPlength,
							  const void *userName, const int userNameLength,
							  const void *password, const int passwordLength,
							  const void *chapChallenge )
	{
	CRYPT_CONTEXT cryptContext;
	const BYTE identifier = ( ( BYTE * ) chapChallenge )[ 16 ];
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ], chapResponse[ CRYPT_MAX_HASHSIZE ];
	int hashValueLength, ttlsAVPlen, status;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( getAVPsize( userNameLength ) + getAVPsize( 16 ) + \
		getAVPsize( 1 + 16 ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Create the CHAP response: MD5( identifier || password || challenge ) */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_MD5 );
	if( cryptStatusError( status ) )
		return( status );
	cryptEncrypt( cryptContext, ( void * ) &identifier, 1 );
	cryptEncrypt( cryptContext, ( void * ) password, passwordLength );
	cryptEncrypt( cryptContext, ( void * ) chapChallenge, 16 );
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE, 
										  hashValue, &hashValueLength );
		}
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Encode the CHAP response: identifier || hashValue */
	chapResponse[ 0 ] = identifier;
	memcpy( chapResponse + 1, hashValue, 16 );

	/* Set up the RADIUS User-Name attribute */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );

	/* Set up the RADIUS CHAP-Challenge and CHAP-Password attributes */
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_CHAPCHALLENGE, 
							 chapChallenge, 16 );
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_CHAP, 
							 chapResponse, 17 );
	*ttlsAVPlength = ttlsAVPlen;

	/* Clean up */
	memset( hashValue, 0, CRYPT_MAX_HASHSIZE );
	memset( chapResponse, 0, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Create a TTLS AVP encoding of the MSCHAPv2 data:

	{ User-Name, byte[] data },
	{ MS-CHAP-Challenge, byte[16] chapChallenge },
	{ MS-CHAP2-Response, byte vendorIdent || 
						 byte vendorFlags = 0 || 
						 byte[16] vendorPeerChallenge	// MS-CHAP challenge data
						 byte[8] vendorReserved = { 0 } ||
						 byte[24] vendorResponse }		// MS-CHAP response data 
	*/

static int createTTLSAVPMSCHAPv2( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
								  int *ttlsAVPlength,
								  const void *userName, const int userNameLength,
								  const void *password, const int passwordLength,
								  const void *chapChallenge )
	{
	const BYTE *chapChallengePtr = chapChallenge;
	const BYTE identifier = ( ( BYTE * ) chapChallenge )[ 16 ];
	BYTE chapResponse[ 128 ];
	int ttlsAVPlen, status;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( getAVPsize( userNameLength ) + \
		getVendorAVPsize( VENDOR_ID_MICROSOFT, 16 ) + \
		getVendorAVPsize( VENDOR_ID_MICROSOFT, 50 ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Generate the MSCHAPv2 challenge response */
	memset( chapResponse, 0, 128 );
	chapResponse[ 0 ] = identifier;							/* MS-CHAP ident */
	memcpy( chapResponse + 2, chapChallengePtr + 16, 16 );	/* MS-CHAP challenge */
#if 1	////////////////////////////////////////////////////////////////
	status = eapCreateMSCHAPv2Response( userName, userNameLength, password, 
										passwordLength, 
										chapChallengePtr, chapChallengePtr + 16, 
										chapResponse + 26 );
#else
	status = GenerateNTResponse( chapChallengePtr, chapChallengePtr + 16,
								 userName, userNameLength,
								 unicodePassword, unicodePasswordLength, 
								 chapResponse + 26 );		/* MS-CHAP response */
#endif	////////////////////////////////////////////////////////////////
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the RADIUS User-Name attribute */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );

	/* Set up the vendor-specific MS-CHAP-Challenge and MS-CHAP2-Response 
	   attributes */
	ttlsAVPlen += encodeVendorAVP( ttlsAVP + ttlsAVPlen, 
								   VENDOR_MSCHAP_CHALLENGE, 
								   VENDOR_ID_MICROSOFT, chapChallengePtr, 16 );
	ttlsAVPlen += encodeVendorAVP( ttlsAVP + ttlsAVPlen, 
								   VENDOR_MSCHAP2_RESPONSE, 
								   VENDOR_ID_MICROSOFT, chapResponse, 50 );
	*ttlsAVPlength = ttlsAVPlen;

	/* Clean up */
	memset( chapResponse, 0, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							EAP-TTLS Client Routines						*
*																			*
****************************************************************************/

/* Complete an EAP-TTLS handshake */

int completeEAPTTLShandshake( const CRYPT_SESSION cryptSession,
							  const char *user, 
							  const char *password,
							  const AUTH_TYPE authType )
	{
	BYTE payload[ EAPTTLS_BUFFER_SIZE ], eapChallenge[ 256 ];
	int payloadLength, bytesCopied, eapChallengeLength, status;

	/* Get the EAP challenge value from the session */
	status = cryptGetAttributeString( cryptSession, 
									  CRYPT_SESSINFO_TLS_EAPCHALLENGE, 
									  eapChallenge, &eapChallengeLength );
	if( cryptStatusError( status ) )
		return( status );

	switch( authType )
		{
		case AUTH_PAP:
 			status = createTTLSAVPPAP( payload, EAPTTLS_BUFFER_SIZE, 
									   &payloadLength, 
									   user, strlen( user ),
									   password, strlen( password ) );
			break;

		case AUTH_CHAP:
			status = createTTLSAVPCHAP( payload, EAPTTLS_BUFFER_SIZE, 
										&payloadLength, 
										user, strlen( user ),
										password, strlen( password ), 
										eapChallenge );
			break;

		case AUTH_MSCHAPV2:
			status = createTTLSAVPMSCHAPv2( payload, EAPTTLS_BUFFER_SIZE, 
											&payloadLength,
											user, strlen( user ),
											password, strlen( password ), 
											eapChallenge );
			break;

		default:
			return( CRYPT_ERROR_PARAM3 );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Send the authentication information to the server */
	status = cryptPushData( cryptSession, payload, payloadLength, 
							&bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's response.  For PAP and CHAP, FreeRADIUS returns a 
	   zero-byte payload with the response being in the unprotected 
	   RADIUS/EAP wrapper around the EAP-TTLS data (!!).  For MSCHAPv2 we
	   get the Success/Failure message back in TTLS-AVP format */
	status = cryptPopData( cryptSession, payload, EAPTTLS_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( authType == AUTH_MSCHAPV2 )
		{
		/* Read the server's MSCHAPv2 Sucess or Failure Request (in TTLS-AVP 
		   format, i.e. in DIAMETER format):

			uint32	type = 26 / 0x1A	// MSCHAPv2
			byte	flags = FLAG_MANDATORY | FLAG_VENDORIDPRESENT
			uint24	length				// Including header
			uint32	vendorID = 311 / 0x137	// Microsoft
				byte	chapID
				byte[]	authResponse	// "S=<auth_string> M=<message>"
										// "E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=vvvvvvvvvv M=<msg>" */
		if( bytesCopied < 12 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( memcmp( payload, "\x00\x00\x00\x1A\xC0", 5 ) || \
			memcmp( payload + 8, "\x00\x00\x01\x37", 4 ) )
			{
			/* We were expecting an MSCHAPv2 response but got something 
			   else */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, 12 );
			DEBUG_PRINT(( ",\n  length 12, expected MSCHAPv2 Response "
						  "message 00 00 00 1A C0 00 nn nn 00 00 01 37.\n" ));
			return( CRYPT_ERROR_BADDATA );
			}
		payload[ bytesCopied ] = '\0';
		DEBUG_PRINT(( "Server responded with MSCHAPv2 message '%s'.\n", 
					  payload + 13 ));
		}
	else
		{
		/* Just in case the server has returned something other than a zero-
		   length respose, we display it for the caller */
		if( bytesCopied > 0 )
			{
			DEBUG_PRINT(( "Server sent %d bytes unexpected data:\n  ", 
						  bytesCopied ));
			DEBUG_DUMPHEX_ALL( payload, bytesCopied );
			DEBUG_PRINT(( ".\n" ));
			}
		}

	/* Acknowledge the server's response if required */
	if( authType == AUTH_MSCHAPV2 )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_AUTHRESPONSE, 
									TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}
#endif /* USE_EAP */
=======
/****************************************************************************
*																			*
*							cryptlib EAP-TTLS Code							*
*						Copyright Peter Gutmann 2016-2023					*
*																			*
****************************************************************************/

/* Under Windows debug mode everything is enabled by default when building 
   cryptlib, so we also enable the required options here.  Under Unix it'll
   need to be enabled manually by adding '-DUSE_EAP -DUSE_DES' to the build 
   command.  Note that this needs to be done via the build process even if
   it's already defined in config.h since that only applies to cryptlib, not
   to this module */

#if defined( _MSC_VER ) && !defined( NDEBUG )
  #define USE_EAP
#endif /* Windows debug build */

#include <stdlib.h>
#include <string.h>
#if !( defined( _WIN32 ) || defined( _WIN64 ) )
  #include <locale.h>
#endif /* !Windows */
#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/* RADIUS attribute types and flags used with DIAMETER as used with 
   EAP-TTLS */

#define RADIUS_SUBTYPE_USERNAME			1
#define RADIUS_SUBTYPE_PASSWORD			2
#define RADIUS_SUBTYPE_CHAP				3
#define RADIUS_SUBTYPE_CHAPCHALLENGE	60

#define FLAG_MANDATORY					0x40
#define FLAG_VENDORIDPRESENT			0x80

/* Vendor-specific types used with DIAMETER as used with EAP-TTLS.  This 
   changes the interpretation of the type field above to use a vendor-
   specific namespace rather than the RADIUS namespace */

#define VENDOR_ID_MICROSOFT				311

#define VENDOR_MSCHAP_CHALLENGE			11
#define VENDOR_MSCHAP2_RESPONSE			25

/* The maximum size of the buffer to hold the authentication data sent over
   the EAP-TTLS tunnel */

#define EAPTTLS_BUFFER_SIZE				256

/* Additional debugging suppport when we're built in debug mode */

#ifdef NDEBUG
  #define DEBUG_PUTS( x )
  #define DEBUG_PRINT( x )
  #define DEBUG_DUMPHEX( x, xLen )
  #define DEBUG_DUMPHEX_ALL( x, xLen )
#else
  #define DEBUG_PUTS( x )			printf( "%s\n", x )
  #define DEBUG_PRINT( x )			printf x
  #define DEBUG_DUMPHEX				dumpHexDataPart
  #define DEBUG_DUMPHEX_ALL			dumpHexData
#endif /* NDEBUG */

typedef enum { AUTH_PAP, AUTH_CHAP, AUTH_MSCHAPV2, AUTH_LAST } AUTH_TYPE;

#ifdef USE_EAP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/****************************************************************************
*																			*
*							Encode EAP-TTLS Message							*
*																			*
****************************************************************************/

/* Encode an attribute in TTLS AVP format, RFC 5281:

	0..3:	uint32	type
	4:		byte	flags
	5..7:	uint24	length		// Including header size
  [	8..11:	uint32	vendorID ]

   The TTLS AVP format, although it's built on RADIUS values, uses the 
   DIAMETER encoding which requires that all TLVs be zero-padded to 4-byte 
   alignment for no known reason.  The following function adds the necessary 
   zero padding alongside performing the TLV encoding.  encode(Vendor)AVP() 
   assumes that get(Vendor)AVPsize() has been called previously in order to 
   verify available space */

#define getPadSize( length )	( ( 4 - ( ( length ) % 4 ) ) % 4 )
#define getHeaderLen( vendorID ) \
								( 8 + ( ( vendorID > 0 ) ? 4 : 0 ) )

static int getVendorAVPsize( const int vendorID, const int valueLen )
	{
	const int length = getHeaderLen( vendorID ) + valueLen;

	return( length + getPadSize( length ) );
	}

#define getAVPsize( valueLen ) \
		getVendorAVPsize( CRYPT_UNUSED, valueLen )

static int encodeVendorAVP( BYTE *dataPtr, const int type, 
							const int vendorID, const BYTE *value, 
							const int valueLen )
	{
	const int headerLen = getHeaderLen( vendorID );
	const int totalLen = headerLen + valueLen;
	const int padSize = getPadSize( totalLen );

	/* Encode the header */
	memset( dataPtr, 0, 16 );
	dataPtr[ 2 ] = ( type >> 8 ) & 0xFF;
	dataPtr[ 3 ] = type & 0xFF;
	dataPtr[ 4 ] = FLAG_MANDATORY;
	dataPtr[ 6 ] = ( totalLen >> 8 ) & 0xFF;
	dataPtr[ 7 ] = totalLen & 0xFF;
	if( vendorID > 0 )
		{
		dataPtr[ 4 ] |= FLAG_VENDORIDPRESENT;
		dataPtr[ 10 ] = ( vendorID >> 8 ) & 0xFF;
		dataPtr[ 11 ] = vendorID & 0xFF;
		}

	/* Encode the payload and padding */
	memcpy( dataPtr + headerLen, value, valueLen );
	if( padSize > 0 )
		memset( dataPtr + totalLen, 0, padSize );

	return( totalLen + padSize );
	}

#define encodeAVP( dataPtr, type, value, valueLen ) \
		encodeVendorAVP( dataPtr, type, CRYPT_UNUSED, value, valueLen )

/* Create a TTLS AVP encoding of the PAP data:

	{ User-Name, byte[] data },
	{ Password, byte[] data } */

static int createTTLSAVPPAP( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
							 int *ttlsAVPlength,
							 const void *userName, const int userNameLength,
							 const void *password, const int passwordLength )
	{
	int ttlsAVPlen;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( getAVPsize( userNameLength ) + \
		getAVPsize( passwordLength ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Set up the RADIUS User-Name and Password attributes */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_PASSWORD, 
							 password, passwordLength );
	*ttlsAVPlength = ttlsAVPlen;

	return( CRYPT_OK );
	}

/* Create a TTLS AVP encoding of the CHAP data:

	{ User-Name, byte[] data },
	{ CHAP-Challenge, byte[16] data },
	{ CHAP-Password, byte ident || 
					 byte[16] data } */

static int createTTLSAVPCHAP( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
							  int *ttlsAVPlength,
							  const void *userName, const int userNameLength,
							  const void *password, const int passwordLength,
							  const void *chapChallenge )
	{
	CRYPT_CONTEXT cryptContext;
	const BYTE identifier = ( ( BYTE * ) chapChallenge )[ 16 ];
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ], chapResponse[ CRYPT_MAX_HASHSIZE ];
	int hashValueLength, ttlsAVPlen, status;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( getAVPsize( userNameLength ) + getAVPsize( 16 ) + \
		getAVPsize( 1 + 16 ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Create the CHAP response: MD5( identifier || password || challenge ) */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_MD5 );
	if( cryptStatusError( status ) )
		return( status );
	cryptEncrypt( cryptContext, ( void * ) &identifier, 1 );
	cryptEncrypt( cryptContext, ( void * ) password, passwordLength );
	cryptEncrypt( cryptContext, ( void * ) chapChallenge, 16 );
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE, 
										  hashValue, &hashValueLength );
		}
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Encode the CHAP response: identifier || hashValue */
	chapResponse[ 0 ] = identifier;
	memcpy( chapResponse + 1, hashValue, 16 );

	/* Set up the RADIUS User-Name attribute */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );

	/* Set up the RADIUS CHAP-Challenge and CHAP-Password attributes */
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_CHAPCHALLENGE, 
							 chapChallenge, 16 );
	ttlsAVPlen += encodeAVP( ttlsAVP + ttlsAVPlen, RADIUS_SUBTYPE_CHAP, 
							 chapResponse, 17 );
	*ttlsAVPlength = ttlsAVPlen;

	/* Clean up */
	memset( hashValue, 0, CRYPT_MAX_HASHSIZE );
	memset( chapResponse, 0, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Create a TTLS AVP encoding of the MSCHAPv2 data:

	{ User-Name, byte[] data },
	{ MS-CHAP-Challenge, byte[16] chapChallenge },
	{ MS-CHAP2-Response, byte vendorIdent || 
						 byte vendorFlags = 0 || 
						 byte[16] vendorPeerChallenge	// MS-CHAP challenge data
						 byte[8] vendorReserved = { 0 } ||
						 byte[24] vendorResponse }		// MS-CHAP response data 
	*/

static int createTTLSAVPMSCHAPv2( BYTE *ttlsAVP, const int ttlsAVPmaxLength, 
								  int *ttlsAVPlength,
								  const void *userName, const int userNameLength,
								  const void *password, const int passwordLength,
								  const void *chapChallenge )
	{
	const BYTE *chapChallengePtr = chapChallenge;
	const BYTE identifier = ( ( BYTE * ) chapChallenge )[ 16 ];
	BYTE chapResponse[ 128 ];
	int ttlsAVPlen, status;

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( getAVPsize( userNameLength ) + \
		getVendorAVPsize( VENDOR_ID_MICROSOFT, 16 ) + \
		getVendorAVPsize( VENDOR_ID_MICROSOFT, 50 ) > ttlsAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Generate the MSCHAPv2 challenge response */
	memset( chapResponse, 0, 128 );
	chapResponse[ 0 ] = identifier;							/* MS-CHAP ident */
	memcpy( chapResponse + 2, chapChallengePtr + 16, 16 );	/* MS-CHAP challenge */
#if 1	////////////////////////////////////////////////////////////////
	status = eapCreateMSCHAPv2Response( userName, userNameLength, password, 
										passwordLength, 
										chapChallengePtr, chapChallengePtr + 16, 
										chapResponse + 26 );
#else
	status = GenerateNTResponse( chapChallengePtr, chapChallengePtr + 16,
								 userName, userNameLength,
								 unicodePassword, unicodePasswordLength, 
								 chapResponse + 26 );		/* MS-CHAP response */
#endif	////////////////////////////////////////////////////////////////
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the RADIUS User-Name attribute */
	ttlsAVPlen = encodeAVP( ttlsAVP, RADIUS_SUBTYPE_USERNAME, 
							userName, userNameLength );

	/* Set up the vendor-specific MS-CHAP-Challenge and MS-CHAP2-Response 
	   attributes */
	ttlsAVPlen += encodeVendorAVP( ttlsAVP + ttlsAVPlen, 
								   VENDOR_MSCHAP_CHALLENGE, 
								   VENDOR_ID_MICROSOFT, chapChallengePtr, 16 );
	ttlsAVPlen += encodeVendorAVP( ttlsAVP + ttlsAVPlen, 
								   VENDOR_MSCHAP2_RESPONSE, 
								   VENDOR_ID_MICROSOFT, chapResponse, 50 );
	*ttlsAVPlength = ttlsAVPlen;

	/* Clean up */
	memset( chapResponse, 0, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							EAP-TTLS Client Routines						*
*																			*
****************************************************************************/

/* Complete an EAP-TTLS handshake */

int completeEAPTTLShandshake( const CRYPT_SESSION cryptSession,
							  const char *user, 
							  const char *password,
							  const AUTH_TYPE authType )
	{
	BYTE payload[ EAPTTLS_BUFFER_SIZE ], eapChallenge[ 256 ];
	int payloadLength, bytesCopied, eapChallengeLength, status;

	/* Get the EAP challenge value from the session */
	status = cryptGetAttributeString( cryptSession, 
									  CRYPT_SESSINFO_TLS_EAPCHALLENGE, 
									  eapChallenge, &eapChallengeLength );
	if( cryptStatusError( status ) )
		return( status );

	switch( authType )
		{
		case AUTH_PAP:
 			status = createTTLSAVPPAP( payload, EAPTTLS_BUFFER_SIZE, 
									   &payloadLength, 
									   user, strlen( user ),
									   password, strlen( password ) );
			break;

		case AUTH_CHAP:
			status = createTTLSAVPCHAP( payload, EAPTTLS_BUFFER_SIZE, 
										&payloadLength, 
										user, strlen( user ),
										password, strlen( password ), 
										eapChallenge );
			break;

		case AUTH_MSCHAPV2:
			status = createTTLSAVPMSCHAPv2( payload, EAPTTLS_BUFFER_SIZE, 
											&payloadLength,
											user, strlen( user ),
											password, strlen( password ), 
											eapChallenge );
			break;

		default:
			return( CRYPT_ERROR_PARAM3 );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Send the authentication information to the server */
	status = cryptPushData( cryptSession, payload, payloadLength, 
							&bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's response.  For PAP and CHAP, FreeRADIUS returns a 
	   zero-byte payload with the response being in the unprotected 
	   RADIUS/EAP wrapper around the EAP-TTLS data (!!).  For MSCHAPv2 we
	   get the Success/Failure message back in TTLS-AVP format */
	status = cryptPopData( cryptSession, payload, EAPTTLS_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( authType == AUTH_MSCHAPV2 )
		{
		/* Read the server's MSCHAPv2 Sucess or Failure Request (in TTLS-AVP 
		   format, i.e. in DIAMETER format):

			uint32	type = 26 / 0x1A	// MSCHAPv2
			byte	flags = FLAG_MANDATORY | FLAG_VENDORIDPRESENT
			uint24	length				// Including header
			uint32	vendorID = 311 / 0x137	// Microsoft
				byte	chapID
				byte[]	authResponse	// "S=<auth_string> M=<message>"
										// "E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=vvvvvvvvvv M=<msg>" */
		if( bytesCopied < 12 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( memcmp( payload, "\x00\x00\x00\x1A\xC0", 5 ) || \
			memcmp( payload + 8, "\x00\x00\x01\x37", 4 ) )
			{
			/* We were expecting an MSCHAPv2 response but got something 
			   else */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, 12 );
			DEBUG_PRINT(( ",\n  length 12, expected MSCHAPv2 Response "
						  "message 00 00 00 1A C0 00 nn nn 00 00 01 37.\n" ));
			return( CRYPT_ERROR_BADDATA );
			}
		payload[ bytesCopied ] = '\0';
		DEBUG_PRINT(( "Server responded with MSCHAPv2 message '%s'.\n", 
					  payload + 13 ));
		}
	else
		{
		/* Just in case the server has returned something other than a zero-
		   length respose, we display it for the caller */
		if( bytesCopied > 0 )
			{
			DEBUG_PRINT(( "Server sent %d bytes unexpected data:\n  ", 
						  bytesCopied ));
			DEBUG_DUMPHEX_ALL( payload, bytesCopied );
			DEBUG_PRINT(( ".\n" ));
			}
		}

	/* Acknowledge the server's response if required */
	if( authType == AUTH_MSCHAPV2 )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_AUTHRESPONSE, 
									TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}
#endif /* USE_EAP */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
