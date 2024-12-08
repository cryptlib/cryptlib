<<<<<<< HEAD
/****************************************************************************
*																			*
*							cryptlib EAP-PEAP Code							*
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

/* The maximum size of the buffer to hold the authentication data sent over
   the EAP subprotocol tunnel */

#define EAP_PEAP_BUFFER_SIZE		256

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

/* Define the following to NAK a CryptoBinding request rather than trying
   to run the CryptoBinding exchange */

/* #define USE_CRYPTOBINDING_NAK */

#ifdef USE_EAP

/* The challenge value that we use for MSCHAPv2.  This is tunnelled inside 
   TLS and is only used as a complex way of communicating password-based 
   auth data so we make it a fixed value */

static BYTE MSCHAPV2_CHALLENGE_VALUE[ 16 ] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Create a PEAP AVP encoding of the MSCHAPv2 data:

  [ EAP type, ID, and length fields omitted, because Microsoft ]
	byte	type = 26 / 0x1A		// MS-CHAP2-Response = EAP subtype field
	byte	opcode = 2				// Response = PEAP message
	byte	MSCHAPv2ID				// Copied from request
	uint16	length = 54+n / 0x36+n	// 6 + payload + username length, see note
	byte	value-size = 49 / 0x31	// Fixed at 49 bytes
		byte[16] challenge			// Our challenge to server
		byte[8]	reserved = { 0 }
		byte[24] response			// NT-Response
		byte	flags = 0
	byte[n]	name					// Remaining bytes = User name 

   Since we only need to do MSCHAPv2 (in fact it's pretty much the only 
   thing defined for PEAP) we hardcode in the message fields as a fixed data 
   block and copy the ephemeral fields into the appropriate locations.

   Note that the length field buried inside the packet at offset 4 has a 
   value of 54+n rather than the expected 55+n that the packet is long, this
   is because the packet is preceded by an EAP header that isn't there and
   the first byte is counted as being part of the nonexistent EAP header
   rather than the packet itself, so the length field records a value one 
   byte shorter than the actual length.

   Although the user name field at the end is optional, in practice it must 
   be sent or FreeRADIUS will fail the authentication */

static int createPEAPAVPMSCHAPv2( BYTE *peapAVP, const int peapAVPmaxLength, 
								  int *peapAVPlength,const void *userName, 
								  const void *password, 
								  const void *clientChallenge, 
								  const void *serverChallenge, 
								  const int chapID )
	{
	static const BYTE peapMSCHAPResponse[] = \
				"\x1A\x02\xFF\x00\x36\x31"
		/*  6 */	"################"						/* Challenge placeholder */
		/* 22 */	"\x00\x00\x00\x00\x00\x00\x00\x00"		/* Reserved */
		/* 30 */	"************************"				/* Response placeholder */
		/* 54 */	"\x00";									/* Flags */
		/* 55 */											/* Username */
	const int peapMSCHAPResponseLength = sizeof( peapMSCHAPResponse ) - 1;
	const int userNameLength = strlen( userName );
	const int passwordLength = strlen( password );

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( peapMSCHAPResponseLength + userNameLength > peapAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	*peapAVPlength = peapMSCHAPResponseLength;

	/* Set up the PEAP MS-CHAP-Response, including the mandatory optional
	   user name */
	memcpy( peapAVP, peapMSCHAPResponse, peapMSCHAPResponseLength );
	peapAVP[ 2 ] = chapID;						/* MS-CHAP ident */
	memcpy( peapAVP + 6, clientChallenge, 16 );
#if 0		/* Optionally make the challenge non-fixed */
	{
	const BYTE *challengePtr = serverChallenge;
	int i;

	/* Turn our fixed challenge into a random-ish looking one in case the 
	   other side checks for static values */
	for( i = 0; i < 16; i++ )
		peapAVP[ 6 + i ] = challengePtr[ i ] ^ ( 0x55 - i );
	}
#endif /* 0 */
#if 1		/* See comment above */
	memcpy( peapAVP + 55, userName, userNameLength );
	peapAVP[ 4 ] += userNameLength;
	*peapAVPlength += userNameLength;
#endif /* 0 */

///////////////////////////////////////////////////////////////////////////
//DEBUG_PRINT(( "Client, server challenge.\n" ));
//DEBUG_DUMPHEX( clientChallenge, 16 );
//DEBUG_PRINT(( "\n" ));
//DEBUG_DUMPHEX( serverChallenge, 16 );
//DEBUG_PRINT(( "\n" ));
///////////////////////////////////////////////////////////////////////////

	/* Generate the MSCHAPv2 response */
#if 1	///////////////////////////////////////////////////////
	return( eapCreateMSCHAPv2Response( userName, userNameLength, password, 
									   passwordLength, serverChallenge,  
									   clientChallenge, peapAVP + 30 ) );
#else
	return( GenerateNTResponse( serverChallenge, clientChallenge,
								userName, userNameLength,
								unicodePassword, unicodePasswordLength, 
								peapAVP + 30 ) );
#endif	///////////////////////////////////////////////////////
	}

/* Create the "S=xxxx" authenticator response needed later in the 
   PEAP/MSCHAPv2 negotiation process */

static int createPEAPMSCHAPv2Authenticator( BYTE *authenticator, 
											const int authenticatorMaxLength, 
											int *authenticatorLength,
											const void *userName, 
											const void *password, 
											const void *ntResponse, 
											const void *clientChallenge, 
											const void *serverChallenge )
	{
	const int userNameLength = strlen( userName );
	const int passwordLength = strlen( password );

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( authenticatorMaxLength < 42 || authenticatorMaxLength > 255 )
		return( CRYPT_ERROR_PARAM3 );

	/* Generate the Authenticator Response */
	*authenticatorLength = 42;
#if 1	//////////////////////////////////////////////////////////////
	return( eapCreateAuthenticatorResponse( userName, userNameLength,
											password, passwordLength,
											serverChallenge, clientChallenge,
											ntResponse, authenticator ) );
#else
	return( GenerateAuthenticatorResponse( unicodePassword, 
										   unicodePasswordLength, ntResponse,
										   serverChallenge, clientChallenge,
										   userName, authenticator ) );
#endif	//////////////////////////////////////////////////////////////
	}

/****************************************************************************
*																			*
*								PEAP Client Routines						*
*																			*
****************************************************************************/

/* Microsoft servers can send one or more Extension Requests, in EAP rather 
   than PEAP format, using Microsoft-proprietary attributes and contents.  
   The most common one that's sent is Capabilities Negotiation Method, 
   documented in "[MS-PEAP]: Protected Extensible Authentication Protocol 
   (PEAP)", section 2.2.8.3:

	byte	code = 1				// Request
	byte	packet ID
	uint16	length = 16				// Including header
	byte	type = 254				// Expanded Types
	uint24	vendorID = 311			// Microsodt
	uint32	vendorType = 34			// Capabilities Negotiation Method
	byte[]	vendorData = 00 00 00 01
									// 32-bit flag, bit 31 = supports PEAP 
									// phase 2 fragmentation

   No idea what you're supposed to do with this if you're a non-Microsoft 
   product, but in most cases wpa_supplicant just sends another copy of the 
   Identity Response which produces the desired effect (but see also further
   down on wpa_supplicant's handling of vendorType = 33 requests).  
   
   Another option, suggested in the often-wrong "[MS-PEAP] Protected 
   Extensible Authentication Protocol (PEAP)", section 4.2.1, is to send a
   NAK response, but it's unclear whether this is a standard EAP NAK or
   Microsoft's bizarro NAK-as-an-EAP-extension-TLV NAK, but probably the
   latter since it's a response to an expanded type.

   However since we know what it is we can send it back, but with the 
   fragmentation flag cleared since it's unclear what we need to do to 
   handle this.  According to the above doc if a packet is larger than 
   MaxSendPacketSize then it's fragmented but there's no indication what 
   MaxSendPacketSize is apart from that it's obtained via another Microsoft-
   proprietary EAP message, nor is there any indication of what "PEAP 
   fragmentation" is beyond the already-present UDP, RADIUS, and EAP 
   fragmentation (the "phase 2" refers to the traffic inside the TLS tunnel 
   so it may be some sort of additional fragmentation at the PEAP level to 
   go with the other three?).
   
   Another possible message is SoH EAP Extensions Method, documented in 
   "[MS-PEAP]: Protected Extensible Authentication Protocol (PEAP)", section 
   2.2.8.2:

	byte	code = 1				// Request
	byte	packet ID
	uint16	length					// Including header
	byte	type = 254				// Expanded Types
	uint24	vendorID = 311			// Microsodt
	uint32	vendorType = 33			// Capabilities Negotiation Method
	byte[]	vendorData = 00 02 00 00
									// Magic value for SoH Request

   We're supposed to respond to this with an SoH TLV, whose payload is
   defined in the TCG's "TNC IF-TNCCS: Protocol Bindings for SoH" section
   3.5, "Statement of Health (SoH) Message", which contains a section
   3.5.1.3 System SoH (SSoH), but this is a composite field containing huge
   masses of information, way too complex to fill in, so we just resend the
   Identity Response as for an otherwise unknown EAP Extension.
   
   wpa_supplicant handles this slightly differently, if EAP_TNC is defined
   (and it seems to be enabled by default in builds included in standard 
   distros) then in /src/eap_peer/eap_peap.c:640 it calls 
   /src/eap_peer/tncc.c:tncc_process_soh_request() which just calls
   tncc_build_soh() to populate a dummy SoH packet with partially-guessed
   values rather than just dropping through to the default unrecognised-
   packet handling */

static int processExtensionRequest( const CRYPT_SESSION cryptSession, 
									const char *user, const int userLength,
									BYTE *payload, int *bytesCopied )
	{
	int status;

#if 0	/* Display some info on the packets and send a fake response */
	if( !memcmp( payload + 5, "\x00\x01\x37\x00\x00\x00\x22", 7 ) )
		{
		DEBUG_PRINT(( "Server sent Microsoft-proprietary Capabilities "
					  "Negotiation Method Request\n  EAP message " ));
		DEBUG_DUMPHEX( payload, *bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, sending Capabilities Negotiation "
					  "Method Response.\n", *bytesCopied ));
		payload[ 0 ] = 0x02;		/* Convert Request to Response */
		payload[ 15 ] = 0x00;		/* No fragmentation */
		}
	else
		{
		if( !memcmp( payload + 5, "\x00\x01\x37\x00\x00\x00\x21", 7 ) )
			{
			DEBUG_PRINT(( "Server sent Microsoft-proprietary SoH EAP "
						  "Extensions Method Request\n  EAP message " ));
			DEBUG_DUMPHEX( payload, *bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, resending Identity Response.\n",
						  *bytesCopied ));
			
			/* At this point we could in theory send a fake tncc_build_soh()-
			   style response, but for now we just retry the request */
			}
		else
			{
			DEBUG_PRINT(( "Server sent unknown proprietary EAP message\n" ));
			DEBUG_DUMPHEX_ALL( payload, *bytesCopied );
			DEBUG_PRINT(( ",\n  , length %d, resending Identity Response.\n",
						  *bytesCopied ));
			}
		payload[ 0 ] = 0x01;	/* Resend identity request */
		memcpy( payload + 1, user, userLength );
		*bytesCopied = 1 + userLength;
		}
#elif 0	/* Some sort of NAK as per the Microsoft PEAP doc, section 4.2.1 */
	/* Send an expanded NAK, RFC 3748 section 5.3.2:

		byte	code = 2				// Response
		byte	packet ID
		uint16	length = 12				// Including header
		byte	type = 254				// Expanded Types
		uint24	vendorID = 311			// Microsoft
		uint32	vendorType = 3			// NAK 
		byte	vendorData = {
			byte	type = 254
			uint24	vendorID = 0
			uint32	vendorType = 0 
			}							// No alternative 

	   However it would take quite a bit of trial-and-error to determine 
	   what it was that NPS expected, and given the near-useless level of
	   error reporting and the fact that resending the identity request 
	   (below) works we go with that instead */
#else	/* Just ignore it and repeat our request.  See the long comment in
		   completePEAPhandshake() for why we send a PEAP rather than full 
		   EAP response */
	payload[ 0 ] = 0x01;	/* Resend identity request */
	memcpy( payload + 1, user, userLength );
	*bytesCopied = 1 + userLength;
#endif /* 0 */
	status = cryptPushData( cryptSession, payload, *bytesCopied, 
							bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( *bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );

	return( CRYPT_OK );
	}

/* Complete a PEAP handshake */

int completePEAPhandshake( const CRYPT_SESSION cryptSession,
						   const char *user, const char *password )
	{ 
	BYTE payload[ EAP_PEAP_BUFFER_SIZE ];
	BYTE chapChallenge[ 256 ], ntResponse[ 24 ];
	BYTE tk[ 128 ], isk[ 32 ];	/* Tunnel Key, Inner Session Key */
	char authenticator[ CRYPT_MAX_TEXTSIZE ];
	BOOLEAN hasCryptobinding = FALSE;
	const int userLength = strlen( user );
	int payloadLength, bytesCopied, chapID, tlsOptions, length, status;
	int authenticatorLength;

	/* At this point PEAP requires an EAP ACK to be sent in order to 
	   trigger further responses from FreeRADIUS.  If this isn't sent then 
	   the server indicates "eap_peap: PEAP state ?", if it is sent then it 
	   indicates "eap_peap: PEAP state TUNNEL ESTABLISHED" and continues
	   the session.  This is required because PEAP omits the EAP type, ID,
	   and length fields so there's no way for the client to communicate 
	   what it's doing to the server, the only way to continue the protocol
	   is for the server to request things and the client to respond, and to
	   do that it needs to be triggered in some way.

	   This may be an artefact of the FreeRADIUS implementation, since PEAP 
	   can't communicate EAP packets in any normal manner exactly what 
	   happens is very implementation-dependent.  Some diagrams of the PEAP
	   message flow omit this step entirely, some label it "EAP Response",
	   some "EAP Response (PEAP)", and some try and provide an explanation 
	   like "EAP Response Identity to TLS tunnel opened".  All four of these 
	   are different things.
	   
	   The deciding factor seems to be Appendix A of 
	   draft-kamath-pppext-peapv0-00 which has an 
	   "EAP-Response/EAP-Type=PEAP ->" sent after the TLS handshake has 
	   completed, this being the ACK.
	   
	   However there is an exception to this when a TLS session is resumed.
	   In the non-resumed case the flow is:

		Client Hello	-------->
						<--------	Server Hello / Certificate / Done
		Client Keyex
		CCS / Finished	-------->
						<--------	CCS / Finished
		EAP ACK			-------->

	   In the resumed case the flow is:

		Client Hello	-------->
						<--------	Server Hello / CCS / Finished
		CCS / Finished	-------->

	   In this case the manufactured EAP ACK isn't necessary because the 
	   server will respond to the client message that ends the session
	   resumption */
	status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_TLS_OPTIONS,
								&tlsOptions );
	if( cryptStatusError( status ) )
		return( status );
	if( !( tlsOptions & CRYPT_TLSOPTION_RESUMED ) )
		{
		DEBUG_PRINT(( "Sending dummy EAP ACK to trigger server "
					  "response.\n" ));
		status = cryptSetAttribute( cryptSession, 
									CRYPT_SESSINFO_AUTHRESPONSE, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		DEBUG_PRINT(( "Session is resumed, skipping dummy EAP ACK.\n" ));
		}

	/* Read the server's Identity Request.  This should be in PEAP format as
	   per "Microsoft's PEAP version 0 (Implementation in Windows XP SP1)",
	   section 1.1, "for EAP Types other than 33, the Code, Identifier, and 
	   Length fields are not sent, but rather EAP packets sent within the 
	   PEAP tunnel begin with the Type field":

		byte	type = 1			// Identity 
	   
	   This is also specified in "[MS-PEAP]: Protected Extensible 
	   Authentication Protocol (PEAP)" section 3.1.5.6 which states that
	   PEAP "compression", stripping the EAP code, packet ID, and length
	   field and leaving only the type and payload, is mandatory for 
	   everything except the Microsoft-specific EAP TLV Extension, 
	   Capabilities Negotiation, and SoH EAP Extensions packets.

	   However FreeRADIUS incorrectly sends the full EAP packet (in EAP 
	   format, code = Request, type = Identity):

		byte	code = 1			// Request
		byte	packet ID			// From the EAP layer below the TLS 
									// tunnel, packet ID there is 5
		uint16	length = 5			// Including header
		byte	type = 1			// Identity
	   
	   See the comment in /src/eap_peer/eap_peap.c:791, "At least FreeRADIUS 
	   seems to send full EAP header with EAP Request Identity", so we need 
	   to be able to deal with either form */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied == 1 )
		{
		/* PEAP identity request */
		if( payload[ 0 ] != 0x01 )
			{
			/* We were expecting a PEAP Identity Request but got something 
			   else */
			DEBUG_PRINT(( "Server sent %02X, expected PEAP Identity Request "
						  "message 01.\n", payload[ 0 ] ));
			return( CRYPT_ERROR_BADDATA );
			}
		}
	else
		{
		/* FreeRADIUS incorrect EAP identity request */
		if( bytesCopied < 5 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( payload[ 0 ] != 0x01 || payload[ 4 ] != 0x01 )
			{
			/* We were expecting an EAP Identity Request but got something 
			   else */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, expected EAP Identity Request "
						  "message 01 nn 00 05 01.\n", bytesCopied ));
			return( CRYPT_ERROR_BADDATA );
			}
		}

	/* Respond with our Identity (in PEAP format):

		byte	type = 1			// Identity
		byte[]	identity */
#if 0
	/* wpa_supplicant claims that it sends an EAP (rather than PEAP) 
	   response at this point and the eapol_test output also prints a full
	   EAP response: 

		02 xx 00 09 01 'test'

	   but sending that to FreeRADIUS produces:

		eap_peap: Received unexpected EAP-Response, rejecting the session.
		eap_peap: ERROR: Tunneled data is invalid 
	
	   with an Access-Reject sent back to the client.  The error log comes 
	   from FreeRADIUS 3.2.x 
	   src/modules/rlm_eap/types/rlm_eap_peap:eappeap_process() which
	   calls eapmessage_verify() and, for a PW_EAP_RESPONSE packet requires 
	   that it's a PW_EAP_TLV, in other words an extension request 
	   containing some sort of status response to the server.  So 
	   wpa_supplicant can't possibly be sending the message that it claims 
	   it's sending */
	payload[ 0 ] = 0x02;			/* Request -> Response */
	if( bytesCopied <= 1 )
		{
		BYTE eapID;
		int eapIDlength;

		/* We got a PEAP packet, manufacture an EAP packet from the
		   data sent at the outer EAP level */
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_TLS_EAPDATA, 
										  NULL, &eapIDlength );
		if( cryptStatusOK( status ) && eapIDlength != 1 )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status )  )
			{
			status = cryptGetAttributeString( cryptSession, 
											  CRYPT_SESSINFO_TLS_EAPDATA, 
											  &eapID, &eapIDlength );
			}
		if( cryptStatusError( status ) )
			return( status );
		payload[ 1 ] = eapID;
		payload[ 2 ] = 0x00;
		payload[ 3 ] = 5 + userLength;
		payload[ 4 ] = 0x01;
		}
	else
		{
		/* We got an EAP packet, update the header */
		payload[ 3 ] = 5 + userLength;
		}
	memcpy( payload + 5, user, userLength );
	status = cryptPushData( cryptSession, payload, 5 + userLength, 
							&bytesCopied );
#else
	payload[ 0 ] = 0x01;
	memcpy( payload + 1, user, userLength );
	status = cryptPushData( cryptSession, payload, 1 + userLength, 
							&bytesCopied );
#endif
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's MSCHAPv2 Challenge (in PEAP format):

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 1			// Challenge 
		byte	chapID				// Copy to response
		uint16	length == 22 + nLen	// Including header
		byte	value-size = 16 / 0x10	// Fixed at 16 bytes
			byte[16]	chapChallenge// Challenge 
		byte[]	name				// Remaining bytes = server name */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );
	while( bytesCopied >= 12 && \
		   payload[ 0 ] == 0x01 && payload[ 4 ] == 0xFE )
		{
		/* At this point Microsoft servers may send back one or more 
		   extension requests, this time in EAP rather than PEAP format, 
		   with the 12-byte EAP extension header followed by the payload:

			byte	code = 1		// Request
			byte	packet ID
			uint16	length			// Including header
			byte	type = 254		// Expanded Types
			uint24	vendorID		
			uint32	vendorType
			...

		   using Microsoft-proprietary attributes and contents.  In order to 
		   continue we have to work our way past these, so we keep reading
		   extension requests until we get to something else */
		status = processExtensionRequest( cryptSession, user, userLength, 
										  payload, &bytesCopied );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( bytesCopied < 22 || \
		payload[ 0 ] != 0x1A || payload[ 1 ] != 0x01 || payload[ 5 ] != 0x10 )
		{
		/* We were expecting an MSCHAPv2 Challenge but got something else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected MSCHAPv2 Challenge message "
					  "1A 01 nn 00 nn 10...\n", bytesCopied ));
		return( CRYPT_ERROR_BADDATA );
		}
	memcpy( chapChallenge, payload + 6, 16 );
	chapID = payload[ 2 ] & 0xFF;

	/* Respond with our MSCHAPv2 Response (in PEAP format) */
	status = createPEAPAVPMSCHAPv2( payload, EAP_PEAP_BUFFER_SIZE, 
									&payloadLength, user, password, 
									MSCHAPV2_CHALLENGE_VALUE, 
									chapChallenge, chapID );
	if( cryptStatusOK( status ) )
		{
		status = cryptPushData( cryptSession, payload, payloadLength, 
								&bytesCopied );
		}
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the NT-Response value is at payload + 30 and take a 
	   copy */
	assert( !memcmp( payload + 22, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) );
	assert( payload[ 54 ] == 0x00 );
	memcpy( ntResponse, payload + 30, 24 );

	/* Create the MSCHAPv2 Authenticator value sent in the MSCHAPv2 
	   Success */
	status = createPEAPMSCHAPv2Authenticator( authenticator, CRYPT_MAX_TEXTSIZE,
											  &authenticatorLength, user, 
											  password, ntResponse, 
											  MSCHAPV2_CHALLENGE_VALUE,
											  chapChallenge );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the TK and calculate the ISK value from the user password and 
	   NT-Response value */
	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPKEY,
									  tk, &length );
	if( cryptStatusError( status ) )
		return( status );
	assert( length >= 40 );		/* Make sure we have at least 40 bytes of TK */
	status = eapCreateISK( isk, password, strlen( password ), ntResponse );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's MSCHAPv2 Success or Failure Request (in PEAP format):

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 3			// Success Request
		byte	chapID
		uint16	length
		byte[]	authResponse		// "S=<auth_string>"

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 4			// Failure Request
		byte	chapID
		uint16	length
		byte[]	authResponse		// "E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=vvvvvvvvvv M=<msg>" 

	   The opcodes for these packets are actually 3 = Success and 4 = Failure, 
	   however when sent from the server they're Success/Failure Request and 
	   when sent back from the client they're Success/Failure Response.
	   
	   For the errors, E is a typically 3-digit error code, R is 1 if 
	   request retries are allowed, C is a new 16-digit challenge for the
	   retried request, and V is the MSCHAP version supported on the server.
	   With true Microsoft logic, for MSCHAPv2 the version value is 3 (RFC 
	   2759 section 6).

	   The documented error codes, from RFC 2759, are:

		646 ERROR_RESTRICTED_LOGON_HOURS
		647 ERROR_ACCT_DISABLED
		648 ERROR_PASSWD_EXPIRED
		649 ERROR_NO_DIALIN_PERMISSION
		691 ERROR_AUTHENTICATION_FAILURE
		709 ERROR_CHANGING_PASSWORD

	   In the case of "E=691 R=1" this technically means "The remote 
	   connection was denied because the user name and password combination 
	   you provided is not recognized, or the selected authentication 
	   protocol is not permitted on the remote access server" however in 
	   practice it's a more generic "Something went wrong".  In particular 
	   MSCHAPv2 uses NTLMv1 when used in Windows RAS services, but this
	   is usually disabled on DCs with only NTLMv2 being enabled.  The fix
	   is to enable NTLMv2 for MSCHAPv2 as per
	   https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/rras-vpn-connections-fail-ms-chapv2-authentication

	   This may also be affected by the LmCompatibilityLevel setting on
	   the DC, see
	   https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960646(v=technet.10)
	   */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );
	if( payload[ 0 ] != 0x1A || \
		( payload[ 1 ] != 0x03 && payload[ 1 ] != 0x04 ) )
		{
		/* We were expecting an MSCHAPv2 Success Request but got something 
		   else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected MSCHAPv2 Success/Failure "
					  "Request message 1A 03 nn 00 nn... or 1A 04 nn 00 "
					  "nn...\n", bytesCopied ));

		/* In the case of an invalid user name we get back an EAP Extension 
		   Request (in EAP format):

			byte	type = 1		// Identity Request
			byte	packet ID		// From the EAP layer below the TLS 
									// tunnel, packet ID there is 7 so this
									// will be 8
			uint16	length = 11 / 0x0B	// Including header
			byte	type = 33 / 0x21	// EAP Extensions / PW_EAP_TLV
				byte	ext.flags = 0x80// TLV flags, mandatory AVP
				byte	ext.type = 3	// TLV type, Result = 3 / EAP_TLV_ACK_RESULT
				uint16	ext.length = 2	// TLV length
				uint16	status = 2		// TLV data, Failure = 2 / EAP_TLV_FAILURE

		   This differs from EAP-TTLS where a message with an unknown 
		   Identity is rejected at the RADIUS/EAP level because in PEAP the 
		   real identity is conveyed over the PEAP tunnel, with the one 
		   given at the RADIUS/EAP level typically being something like 
		   "anonymous".

		   In the case of FreeRADIUS the implementation is in 
		   /src/modules/rlm_eap/types/rlm_eap_peap/peap.c function 
		   eappeap_failure(), but other servers like Microsoft's NPS do the 
		   same thing */
		if( bytesCopied >= 11 && \
			payload[ 0 ] == 0x01 && payload[ 4 ] == 0x21 && \
			payload[ 6 ] == 0x03 && payload[ 10 ] == 0x02 )
			{
			/* There isn't really an appropriate error code for incorrect-
			   username so the best that we can report is a 
			   CRYPT_ERROR_WRONGKEY, in the sense of "wrong credentials" */
			DEBUG_PUTS(( "Server sent Identity Request - EAP Extension - "
						 "Failure, indicating an incorrect user name." ));
			return( CRYPT_ERROR_WRONGKEY );
			}

		return( CRYPT_ERROR_BADDATA );
		}
	payload[ bytesCopied ] = '\0';
	if( payload[ 1 ] == 0x03 )
		{
		DEBUG_PRINT(( "Server responded with Success packet, message "
					  "'%s'.\n", payload + 5 ));
		if( memcmp( payload + 5, authenticator, authenticatorLength ) )
			{
			payload[ 5 + authenticatorLength ] = '\0';
			DEBUG_PRINT(( "Server's Authenticator value '%s' doesn't "
						  "match\n  our calculated Authenticator '%s'.\n",
						  payload + 5, authenticator ));
			return( CRYPT_ERROR_SIGNATURE );
			}
		}
	else
		{
		DEBUG_PRINT(( "Server responded with Failure packet, message "
					  "'%s'.\n", payload + 5 ));
		}

	/* Send our MSCHAPv2 Success/Failure Response (in PEAP format):

		byte	type = 26 / 0x1A		// MSCHAPv2
		byte	opcode = 3				// Success Response

		byte	type = 26 / 0x1A		// MSCHAPv2
		byte	opcode = 4				// Failure Response 

	   In essence this just consists of echoing the first two bytes of the 
	   received packet back to the server */
	status = cryptPushData( cryptSession, payload, 2, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* At this point the negotiation should be complete, however FreeRADIUS
	   continues with EAP (not PEAP) messages, which we need to deal with in
	   order to get RADIUS attributes back.  This is based on the 
	   "Microsoft's PEAP version 0 Implementation in Windows XP SP1" draft
	   (draft-kamath-pppext-peapv0-00.txt), section 1.3 which specifies it 
	   as required for Windows XP SP1 compatibility, and see also the note 
	   earlier on why the EAP format is used.  
	   
	   Microsoft documents it differently in "[MS-CHAP]: Extensible 
	   Authentication Protocol Method for Microsoft Challenge Handshake 
	   Authentication Protocol (CHAP)", stating that what's sent back is an
	   EAP Success packet, however what it calls "EAP Success" is actually 
	   an Extension Request containing a Success status.
	   
	   Cisco also apparently sends extensions at this point, specifically an
	   ACK Result which we just echo back with the first byte changed to 02,
	   Response */

	/* Read the server's Extension Request (in EAP format, code = Request, 
	   type = Extension, type names from FreeRADIUS).  The following is from 
	   draft-kamath-pppext-peapv0-00.txt mentioned above, section 2, which 
	   defines Extension Request/Response packets, type = 33, for which the 
	   only valid TLV type is 3, "Acknowledged Result" (PEAPv2 just calls 
	   this "Result", draft-josefsson-pppext-eap-tls-eap-10.txt section 4.2).  
	   So essentially the entire packet is fixed boilerplate except for the 
	   last byte, which is either "1 - Success", or "2 - Failure".

		byte	code = 1			// Request / PW_EAP_REQUEST
		byte	packet ID			// From the EAP layer below the TLS 
									// tunnel, packet ID there is 7 so this 
									// will be 8
		uint16	length = 11 / 0x0B	// Including header
		byte	type = 33 / 0x21	// EAP Extensions, from PEAP RFC / PW_EAP_TLV
			byte	ext.flags = 0x80// TLV flags, mandatory AVP
			byte	ext.type = 3	// TLV type, Result = 3 / EAP_TLV_ACK_RESULT
			uint16	ext.length = 2	// TLV length, payload only
			uint16	status = 1		// TLV data, Success = 1 / EAP_TLV_SUCCESS,
									//			 Failure = 2 / EAP_TLV_FAILURE
	   or, for Windows NPS:

		byte	code = 1			// Request / PW_EAP_REQUEST
		byte	packet ID			// From the EAP layer below the TLS 
									// tunnel, packet ID there is 7 so this 
									// will be 8
		uint16	length = 71 / 0x47	// Including header
		byte	type = 33 / 0x21	// EAP Extensions, from PEAP RFC / PW_EAP_TLV
			byte	ext.flags = 0x80// TLV flags, mandatory AVP
			byte	ext.type = 3	// TLV type, Result = 3 / EAP_TLV_ACK_RESULT
			uint16	ext.length = 2	// TLV length, payload only
			uint16	status = 1		// TLV data, Success = 1 / EAP_TLV_SUCCESS,
									//			 Failure = 2 / EAP_TLV_FAILURE
			byte	ext.flags = 0x00// TLV flags, mandatory according to the spec
									// but NPS sets it to optional
			byte	ext.type = 12 / 0x0C// TLV type, Crypto-Binding
			uint16	ext.length = 56 / 0x38// TLV length, payload only
			byte[3]	versions		// Version info, 0x00 0x00 0x00
			byte	subtype			// Binding Request = 0
			byte[32] nonce			// Nonce for PRF
			byte[20] MAC			// HMAC-SHA1 MAC

	   The AVP format is actually a single-bit flag for mandatory/optional,
	   a zero bit, and then 14 bits of type, but only the value 3 is 
	   defined for the type (see above) so we treat it as two bytes, one with 
	   flags and one with the type */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 11 )
		return( CRYPT_ERROR_UNDERFLOW );
	if( payload[ 0 ] != 0x01 || payload[ 4 ] != 0x21 || \
		payload[ 6 ] != 0x03 )
		{
		/* We were expecting another Identity Request but got something 
		   else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected EAP Identity Request - "
					  "Acknowledged Result - Success message 01 nn 00 11 "
					  "21 80 03 00 02 00 01.\n", bytesCopied ));
		return( CRYPT_ERROR_BADDATA );
		}
	if( payload[ 10 ] == 0x01 )
		{
		DEBUG_PRINT(( "Server responded with Acknowledged Result - Success "
					  "packet.\n" ));
		}
	else
		{
		DEBUG_PRINT(( "Server responded with Acknowledged Result - Failure "
					  "packet.\n" ));

		/* This isn't a CRYPT_ERROR_WRONGKEY because the authentication has
		   already succeeded, the only reason why we'd get a failure 
		   response at this point is because of a server error where it 
		   can't continue for some reason */
		return( CRYPT_ERROR_BADDATA );
		}

	/* There may be further TLVs following the first one, typically a 
	   Cryptobinding request from NPS 
	   (draft-josefsson-pppext-eap-tls-eap-10.txt section 4.5).  This 
	   doesn't exist for PEAPv0 but was added in PEAPv2 so technically
	   shouldn't be sent, however it's kludged into what's actually a PEAPv0
	   exchange by setting the version fields to an invalid 0x00 0x00 0x00 
	   rather than the required PEAPv2 version values:

		byte	ext.flags = 0x00	// TLV flags, mandatory according to the 
									// spec but NPS sets it to optional
		byte	ext.type = 12 / 0x0C// TLV type, Crypto-Binding
		uint16	ext.length = 56 / 0x38// TLV length
			byte[3]	versions		// Version info, 0x00 0x00 0x00
			byte	subtype			// Binding Request = 0
			byte[32] nonce			// Nonce used when creating Cryptobinding
			byte[20] MAC			// HMAC-SHA1 MAC

	   So if there's more data present, indicated by an overall length 
	   greater than the length of the basic Acknowledged Result plus the 
	   header of another TLV following it then we display information on 
	   the additional TLV.  The second TLV starts at offset 11 */
	if( payload[ 3 ] > 11 + 4 )
		{
		DEBUG_PRINT(( "Server Acknowledged Result contains additional "
					  "TLV " ));
		if( payload[ 12 ] == 0x0C )
			{
			/* There's a Crypto-Binding request from NPS present that we 
			   have to deal with.  Sending just an Extension Response as we 
			   do for FreeRADIUS results in a "Received Crypto-Binding TLV 
			   is invalid" error, this is caused by having the "Disconnect 
			   Clients Without Cryptobinding" option set on the server so 
			   that it expects a Crypto-Binding but doesn't see one.  To fix
			   this the documentation states that the setting "Disconnect 
			   Clients Without Cryptobinding" needs to be unset and we need 
			   to NAK the Cryptobinding request which is done further down,
			   however this also doesn't work, see the comment for the NAK
			   code */
			DEBUG_PRINT(( "Crypto-Binding - Request.\n" ));
			hasCryptobinding = TRUE;
			}
		else
			{
			DEBUG_PRINT(( "of unknown type %d (%X).\n", 
						  payload[ 12 ], payload[ 12 ] ));
			}
		}

	/* Convert the previous Extension Request into an Extension Response (in 
	   EAP format, code = Response, type names from FreeRADIUS):

		byte	code = 2			// Response / PW_EAP_RESPONSE
		[ Rest as above ] 

	   This is as per the PEAP-kludges RFC mentioned above 
	   (draft-kamath-pppext-peapv0-00.txt), section 3.2, which says that for 
	   use with Windows support for the Result AVP is required, with the 
	   only allowed message being EAP Request, type = Extensions, status = 
	   Success answered by EAP Response, type = Extensions, status = 
	   Success.  Anything else should be treated as a failure.  FreeRADIUS 
	   implements this by only checking that the code is PW_EAP_RESPONSE, 
	   the type is PW_EAP_TLV, and the status is EAP_TLV_SUCCESS */
	payload[ 0 ] = 0x02;
	if( hasCryptobinding )
		{
#ifdef USE_CRYPTOBINDING_NAK
		/* If we got a Cryptobinding request 
		   (draft-josefsson-pppext-eap-tls-eap-10.txt section 4.3) then we
		   need to NAK it in order to continue.  No-one seems to know what 
		   to do with the vendorID field, we send 0x137 which is Microsoft 
		   since it's their mess, but wpa_supplicant 
		   eap_peap.c:eap_tlv_build_nak() sets this field to 0, not 0x137:

			byte	ext.flags = 0x80	// TLV flags, mandatory AVP
			byte	ext.type = 4		// TLV type, NAK / EAP_TLV_NAK_TLV
			uint16	ext.length = 6		// TLV length
				uint32	vendorID = 0x137// Vendor ID = Microsoft
				uint16	type = 0x0C		// Type = Crypto-Binding

		   This code is disabled because it results in NPS ending the 
		   negotiation at this point, despite what the Windows docs say it
		   seems to be necessary to perform the Cryptobinding silly-walk in
		   order to continue */
		static const BYTE cryptobindingNAK[] = {
			0x80, 0x04, 0x00, 0x06, 0x00, 0x00, 0x01, 0x37, 0x00, 0x0C
			};

		memcpy( payload + 11, cryptobindingNAK, 10 );
		payload[ 3 ] = 11 + 10;

		/* Since we're sending back a NAK as the second TLV rather than the
		   Cryptobinding response we have to truncate the reply at the end 
		   of the NAK */
		bytesCopied = 11 + 10;
#else
		BYTE ipmk[ 40 ], cmk[ 20 ], cmac[ 20 ];
		BYTE message[ 60 ];
		BYTE *cryptoBinding = payload + 11;

		/* Make sure that the Crypto-Binding message is at payload + 11 */
		assert( !memcmp( cryptoBinding, "\x00\x0C\x00\x38\x00\x00\x00\x00", 8 ) );

		/* Copy the Crypto-Binding message with the last the last 20 bytes 
		   containing the MAC value zeroed out */
		memset( message, 0, 60 );
		memcpy( message, cryptoBinding, 60 - 20 );

		/* Create the Intermediate PEAP MAC Key and Compound MAC Key and use
		   the latter to MAC the Crypto-Binding message */
		status = eapCreateCMK( ipmk, cmk, tk, isk );
		if( cryptStatusOK( status ) )
			status = eapCreateCMAC( cmac, cmk, message, 60 );
		if( cryptStatusError( status ) )
			return( status );
		if( memcmp( cmac, cryptoBinding + 40, 20 ) )
			{
			DEBUG_PRINT(( "Received Crypto-Binding CMAC value " ));
			DEBUG_DUMPHEX( cryptoBinding + 40, 20 );
			DEBUG_PRINT(( "\n     didn't match calculated value " ));
			DEBUG_DUMPHEX( cmac, 20 );
			DEBUG_PRINT(( ".\n" ));
			return( CRYPT_ERROR_SIGNATURE );
			}

		/* Create the Crypto-Binding response */
		assert( cryptoBinding[ 7 ] == 0x00 );
		cryptoBinding[ 7 ] = 0x01;	/* Request -> Response */ 
		memset( message, 0, 60 );
		memcpy( message, cryptoBinding, 60 - 20 );
		status = eapCreateCMAC( cmac, cmk, message, 60 );
		if( cryptStatusError( status ) )
			return( status );
		memcpy( cryptoBinding + 40, cmac, 20 );
//////////////////////////////////////////////////////////////////////
//DEBUG_PRINT(( "Crypto-Binding response:\n" ));
//DEBUG_DUMPHEX_ALL( payload, bytesCopied );
//DEBUG_PRINT(( "\n" ));
//////////////////////////////////////////////////////////////////////
#endif /* USE_CRYPTOBINDING_NAK */
		}
	status = cryptPushData( cryptSession, payload, bytesCopied, 
							&bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the final response from the server.  This is used to communicate 
	   the RADIUS attributes outside the tunnel (because why send them in the
	   secure tunnel when you can include them unsecured outside it?), so 
	   the PEAP payload is just a no-op unless it's NPS' garbled response to
	   our Cryptobinding NAK */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
#ifdef USE_CRYPTOBINDING_NAK
	if( hasCryptobinding )
		{
		/* Since we've sent a NAK for the Cryptobinding we're going to get 
		   back an ACK of the NAK, or at least NPS' broken interpretation of
		   an ACK, encoded as a Response rather than a Request and with the 
		   length and status (data) fields missing, because Microsoft.  So
		   what's returned is 02 09 00 07 21 80 03 instead of what the spec
		   says (draft-josefsson-pppext-eap-tls-eap-06.txt section 4.5):

			byte	code = 2		// Response / PW_EAP_RESPONSE
			byte	packet ID		// From the EAP layer below the TLS 
									// tunnel, packet ID there is 8 so this 
									// will be 9
			uint16	length = 7		// Including header
			byte	type = 33 / 0x21// EAP Extensions, from PEAP RFC / PW_EAP_TLV
				byte	ext.flags = 0x80// TLV flags, mandatory AVP
				byte	ext.type = 3// TLV type, Result = 3 / EAP_TLV_ACK_RESULT 
			  [	uint16	ext.len		// Missing TLV length 
			    uint16	sttaus		// Missing TLV data ] */
		if( bytesCopied < 7 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( ( payload[ 0 ] != 0x01 && payload[ 0 ] != 0x02 ) || \
			payload[ 4 ] != 0x21 || payload[ 6 ] != 0x03 )
			{
			/* We were expecting an ACK but got something else */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, expected EAP Identity Request - "
						  "Acknowledged Result - Success message 01 nn 00 11 "
						  "21 80 03 00 02 00 01.\n", bytesCopied ));
			return( CRYPT_ERROR_BADDATA );
			}
		DEBUG_PRINT(( "Server responded with Microsoft garbled Acknowledged "
					  "Result packet.\n" ));
		}
	else
#endif /* USE_CRYPTOBINDING_NAK */
		{
		if( bytesCopied != 0 )
			{
			/* This should be a zero-length EAP message */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, should have been zero-length "
						  "message.\n", bytesCopied ));
			return( CRYPT_ERROR_BADDATA );
			}
		DEBUG_PRINT(( "Server responded with zero-length packet used to convey "
					  "RADIUS attributes.\n" ));
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								PEAP Server Routines						*
*																			*
****************************************************************************/

/* The various messages we have to send to the client to allow things to
   progress */

static const BYTE mschapv2Challenge[] = {
	0x1A,				/* Type = MSCHAPv2 */
	0x01,				/* Subtype = Challenge */
	0x02,				/* ChapID */
	0x00, 0x16 - 1,		/* Not-really length = 21 (see comment below) */
	0x10,				/* Challenge length = 16 */
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
	};					/* Different from MSCHAPV2_CHALLENGE_VALUE */

static const BYTE mschapv2Success[] = {
	0x1A,				/* Type = MSCHAPv2 */
	0x03,				/* Subtype = Success Request */
	0x02,				/* ChapID */
	0x00, 0x2F - 1,		/* Not-really length = 46 (as above) */
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23		/* Placeholder for Authenticator value,
						   "S=0123456789ABCDEFFEDCBA9876543210" */
	};

static const BYTE eapExtensionRequest[] = {
	0x01,				/* Type = Request / PW_EAP_REQUEST */
	0x08,				/* packetID	from the EAP layer below the TLS tunnel, 
						   packet ID there is 7 so this will be 8 */
	0x00, 0x47,			/* Length including header = 71 */
	0x21,				/* EAP Extensions = 33, from PEAP RFC / PW_EAP_TLV */
		0x80,			/* TLV flags, mandatory AVP */
		0x03,			/* TLV type, Result = 3 / EAP_TLV_ACK_RESULT */
		0x00, 0x02,		/* TLV length, payload only */
		0x00, 0x01,		/* TLV data, Success = 1 / EAP_TLV_SUCCESS */
		0x00,			/* TLV flags, mandatory according to the spec but 
						   NPS sets it to optional */
		0x0C,			/* TLV type, Crypto-Binding = 12 */
		0x00, 0x38,		/* TLV length, payload only */
		0x00, 0x00, 0x00, /* Version info, 0x00 0x00 0x00 */
		0x00,			/* Subtype = Binding Request = 0 */
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 
		0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x79, 0x77, 
		0x79, 0x7A, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
						/* 32-byte nonce for PRF,
						   "abcdefghijklmnopqrstuvywyz123456" */
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23, 0x23, 0x23
						/* Placeholder for HMAC-SHA1 MAC,
						   "####################" */
	};

/* Complete the server-side PEAP handshake.  See the comments in 
   completePEAPhandshake() for explanations of what's going on here */

int completePEAPhandshakeServer( const CRYPT_SESSION cryptSession,
								 const char *user, 
								 const char *password )
	{
	BYTE payload[ EAP_PEAP_BUFFER_SIZE ], chapChallenge[ 256 ];
	BYTE mschapv2Response[ 256 ], ntResponse[ 24 ];
	BYTE tk[ 128 ], isk[ 32 ];	/* Tunnel Key, Inner Session Key */
	BYTE ipmk[ 40 ], cmk[ 20 ];	/* Intermediate PEAP MAC Key,Compound MAC 
								   Key */
	BYTE cmacMessage[ 60 ], cmac[ 20 ], *cryptoBinding;
	char authenticator[ CRYPT_MAX_TEXTSIZE ];
	int bytesCopied, chapID, mschapv2Length, authenticatorLength, length;
	int status;

	/* Read the dummy EAP ACK that the client needs to send to continue the
	   negotiations */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the server's Identity Request (in PEAP format):

		byte	type = 1			// Identity */
	status = cryptPushData( cryptSession, "\x01", 1, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the client's Identity (in PEAP format):

		byte	type = 1			// Identity
		byte[]	identity */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 2 )
		return( CRYPT_ERROR_BADDATA );
	if( payload[ 0 ] != 0x01 )
		{
		/* We were expecting a PEAP Identity but got something else */
		DEBUG_PRINT(( "Client sent %02X, expected PEAP Identity "
					  "message 01.\n", payload[ 0 ] ));
		return( CRYPT_ERROR_BADDATA );
		}

	/* Send our MSCHAPv2 Challenge (in PEAP format):

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 1			// Challenge 
		byte	chapID				// Copied to response
		uint16	length == 21		// Including header
		byte	value-size = 16 / 0x10	// Fixed at 16 bytes
			byte[16]	chapChallenge// Challenge 

	   See the long comment for createPEAPAVPMSCHAPv2() for why the
	   length field is 21 instead of the expected 22 */
	status = cryptPushData( cryptSession, mschapv2Challenge, 22, 
							&bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );
	chapID = mschapv2Challenge[ 2 ] & 0xFF;

	/* Read the client's response and create our MSCHAPv2 Response (in PEAP 
	   format) to compare to what the client sent us */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusOK( status ) )
		{
		memcpy( chapChallenge, payload + 6, 16 );
		status = createPEAPAVPMSCHAPv2( mschapv2Response, 256, &mschapv2Length,
										user, password, chapChallenge, 
										mschapv2Challenge + 6, chapID );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied != mschapv2Length || \
		memcmp( payload, mschapv2Response, mschapv2Length ) )
		{
		DEBUG_PRINT(( "Client's MSCHAPv2 Response doesn't match calculated "
					  "MSCHAPv2 Response.\n  Client Response:\n" ));
		DEBUG_DUMPHEX_ALL( payload, bytesCopied );
		DEBUG_PRINT(( "\n  Our Response:\n" ));
		DEBUG_DUMPHEX_ALL( mschapv2Response, mschapv2Length );
		DEBUG_PRINT(( "\n" ));
		return( CRYPT_ERROR_SIGNATURE );
		}

	/* Make sure that the NT-Response value is at payload + 30 and take a 
	   copy */
	assert( !memcmp( payload + 22, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) );
	assert( payload[ 54 ] == 0x00 );	
	memcpy( ntResponse, payload + 30, 24 );

	/* Create the MSCHAPv2 Authenticator value sent in the MSCHAPv2 
	   Success */
	status = createPEAPMSCHAPv2Authenticator( authenticator, CRYPT_MAX_TEXTSIZE,
											  &authenticatorLength, user, 
											  password, ntResponse, 
											  chapChallenge,
											  mschapv2Challenge + 6 );
	if( cryptStatusError( status ) )
		return( status );

	/* Send our MSCHAPv2 Success Request (in PEAP format) */
	memcpy( payload, mschapv2Success, 47 );
	memcpy( payload + 5, authenticator, 42 );
	status = cryptPushData( cryptSession, payload, 47, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the client/s MSCHAPv2 Success Response (in PEAP format) */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusOK( status ) && \
		( payload[ 0 ] != 0x1A || payload[ 1 ] != 0x03 ) )
		{
		DEBUG_PRINT(( "Client didn't respond with MSCHAPv2 Success "
					  "Response.\n" ));
		status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Get the TK and calculate the ISK value from the user password and 
	   NT-Response value */
	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPKEY,
									  tk, &length );
	if( cryptStatusError( status ) )
		return( status );
	assert( length >= 40 );		/* Make sure we have at least 40 bytes of TK */
	status = eapCreateISK( isk, password, strlen( password ), ntResponse );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the Crypto-Binding message is at payload + 11 */
	memcpy( payload, eapExtensionRequest, 71 ); 
	cryptoBinding = payload + 11;
	assert( !memcmp( cryptoBinding, "\x00\x0C\x00\x38\x00\x00\x00\x00", 8 ) );

	/* Copy the Crypto-Binding message with the last the last 20 bytes 
	   containing the MAC value zeroed out */
	memset( cmacMessage, 0, 60 );
	memcpy( cmacMessage, cryptoBinding, 60 - 20 );

	/* Create the Intermediate PEAP MAC Key and Compound MAC Key and use the 
	   latter to MAC the Crypto-Binding message */
	status = eapCreateCMK( ipmk, cmk, tk, isk );
	if( cryptStatusOK( status ) )
		status = eapCreateCMAC( cmac, cmk, cmacMessage, 60 );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( cryptoBinding + 40, cmac, 20 );

	/* Send our Extension Request and Cryptobinding Request (in EAP 
	   format) */
	status = cryptPushData( cryptSession, payload, 71, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the client's Extension Response (in EAP format */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusOK( status ) && \
		( payload[ 0 ] != 0x2 || payload[ 4 ] != 0x21 || 
		  payload[ 6 ] != 0x03 ) )
		{
		DEBUG_PRINT(( "Client didn't respond with Extension Response.\n" ));
		status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Verify the client's Crypto-Binding response */
	if( cryptoBinding[ 1 ] != 0x0C || cryptoBinding[ 3 ] != 0x38 || \
		cryptoBinding[ 7 ] != 0x01 )
		{
		DEBUG_PRINT(( "Client didn't respond with Cryptobinding Response.\n" ));
		return( CRYPT_ERROR_BADDATA );
		}
	memset( cmacMessage, 0, 60 );
	memcpy( cmacMessage, cryptoBinding, 60 - 20 );
	status = eapCreateCMAC( cmac, cmk, cmacMessage, 60 );
	if( cryptStatusError( status ) )
		return( status );
	if( memcmp( cryptoBinding + 40, cmac, 20 ) )
		{
		DEBUG_PRINT(( "Received client Crypto-Binding CMAC value " ));
		DEBUG_DUMPHEX( cryptoBinding + 40, 20 );
		DEBUG_PRINT(( "\n     didn't match calculated value " ));
		DEBUG_DUMPHEX( cmac, 20 );
		DEBUG_PRINT(( ".\n" ));
		}

	/* We're finally through all the crypto, we're done, tell the client 
	   they can come in.

	   Windows NPS sends a bunch of additional attributes at this point 
	   which clients like eapol_test complain about the absence of if all
	   of the Microsoft-specific calisthenics above have been followed,
	   these are (descriptions from RFC 2548):

		00000137	// Vendor-ID = MS
		0E			// Vendor-Type = 14 = MS-Link-Utilization-Threshold
		06			// Vendor-Length = 6
		00000032

		00000137	// Vendor-ID = MS
		0F			// Vendor-Type = 15 = MS-Link-Drop-Time-Limit
		06			// Vendor-Length = 6
		00000078

		00000137	// Vendor-ID = MS
		0A			// Vendor-Type = 10 = MS-CHAP-Domain
		09			// Vendor-Length = 9
		01			// Ident
		524144535256// "RADSRV"

		00000137	// Vendor-ID = MS
		1A			// Vendor-Type = 26 = MS-CHAP2-Success
		2D			// Vendor-Length = 45
		01			// Ident
		533D37313038353845304433463135424637313636423945323032414532343744333844413242343032
					// "S=710858E0D3F15BF7166B9E202AE247D38DA2B402"

		00000137	// Vendor-ID = MS
		10			// Vendor-Type = 16 = MS-MPPE-Send-Key
		34			// Vendor-Length = 52
		801f		// Salt
		3492A5E95CAE75D3167137550766898A3E77BBFF15C46FB5FFFAF758A335CA8E935763ED82CD9441CB0CEA01C01160F0

		00000137	// Vendor-ID = MS
		11			// Vendor-Type = 17 = MS-MPPE-Recv-Key
		34			// Vendor-Length = 52
		8020		// Salt
		C3116680D15E4EFA7D46559AEA387424662C67674A876735BC7CA80A349BE35006F8125157B112C8EACC6015FD0F5D71
	   
	   As with several other security-critical operations, these are all 
	   sent in an unprotected RADIUS message */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_AUTHRESPONSE, 
								TRUE );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}
#endif /* USE_EAP */
=======
/****************************************************************************
*																			*
*							cryptlib EAP-PEAP Code							*
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

/* The maximum size of the buffer to hold the authentication data sent over
   the EAP subprotocol tunnel */

#define EAP_PEAP_BUFFER_SIZE		256

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

/* Define the following to NAK a CryptoBinding request rather than trying
   to run the CryptoBinding exchange */

/* #define USE_CRYPTOBINDING_NAK */

#ifdef USE_EAP

/* The challenge value that we use for MSCHAPv2.  This is tunnelled inside 
   TLS and is only used as a complex way of communicating password-based 
   auth data so we make it a fixed value */

static BYTE MSCHAPV2_CHALLENGE_VALUE[ 16 ] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Create a PEAP AVP encoding of the MSCHAPv2 data:

  [ EAP type, ID, and length fields omitted, because Microsoft ]
	byte	type = 26 / 0x1A		// MS-CHAP2-Response = EAP subtype field
	byte	opcode = 2				// Response = PEAP message
	byte	MSCHAPv2ID				// Copied from request
	uint16	length = 54+n / 0x36+n	// 6 + payload + username length, see note
	byte	value-size = 49 / 0x31	// Fixed at 49 bytes
		byte[16] challenge			// Our challenge to server
		byte[8]	reserved = { 0 }
		byte[24] response			// NT-Response
		byte	flags = 0
	byte[n]	name					// Remaining bytes = User name 

   Since we only need to do MSCHAPv2 (in fact it's pretty much the only 
   thing defined for PEAP) we hardcode in the message fields as a fixed data 
   block and copy the ephemeral fields into the appropriate locations.

   Note that the length field buried inside the packet at offset 4 has a 
   value of 54+n rather than the expected 55+n that the packet is long, this
   is because the packet is preceded by an EAP header that isn't there and
   the first byte is counted as being part of the nonexistent EAP header
   rather than the packet itself, so the length field records a value one 
   byte shorter than the actual length.

   Although the user name field at the end is optional, in practice it must 
   be sent or FreeRADIUS will fail the authentication */

static int createPEAPAVPMSCHAPv2( BYTE *peapAVP, const int peapAVPmaxLength, 
								  int *peapAVPlength,const void *userName, 
								  const void *password, 
								  const void *clientChallenge, 
								  const void *serverChallenge, 
								  const int chapID )
	{
	static const BYTE peapMSCHAPResponse[] = \
				"\x1A\x02\xFF\x00\x36\x31"
		/*  6 */	"################"						/* Challenge placeholder */
		/* 22 */	"\x00\x00\x00\x00\x00\x00\x00\x00"		/* Reserved */
		/* 30 */	"************************"				/* Response placeholder */
		/* 54 */	"\x00";									/* Flags */
		/* 55 */											/* Username */
	const int peapMSCHAPResponseLength = sizeof( peapMSCHAPResponse ) - 1;
	const int userNameLength = strlen( userName );
	const int passwordLength = strlen( password );

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( peapMSCHAPResponseLength + userNameLength > peapAVPmaxLength )
		return( CRYPT_ERROR_OVERFLOW );

	*peapAVPlength = peapMSCHAPResponseLength;

	/* Set up the PEAP MS-CHAP-Response, including the mandatory optional
	   user name */
	memcpy( peapAVP, peapMSCHAPResponse, peapMSCHAPResponseLength );
	peapAVP[ 2 ] = chapID;						/* MS-CHAP ident */
	memcpy( peapAVP + 6, clientChallenge, 16 );
#if 0		/* Optionally make the challenge non-fixed */
	{
	const BYTE *challengePtr = serverChallenge;
	int i;

	/* Turn our fixed challenge into a random-ish looking one in case the 
	   other side checks for static values */
	for( i = 0; i < 16; i++ )
		peapAVP[ 6 + i ] = challengePtr[ i ] ^ ( 0x55 - i );
	}
#endif /* 0 */
#if 1		/* See comment above */
	memcpy( peapAVP + 55, userName, userNameLength );
	peapAVP[ 4 ] += userNameLength;
	*peapAVPlength += userNameLength;
#endif /* 0 */

///////////////////////////////////////////////////////////////////////////
//DEBUG_PRINT(( "Client, server challenge.\n" ));
//DEBUG_DUMPHEX( clientChallenge, 16 );
//DEBUG_PRINT(( "\n" ));
//DEBUG_DUMPHEX( serverChallenge, 16 );
//DEBUG_PRINT(( "\n" ));
///////////////////////////////////////////////////////////////////////////

	/* Generate the MSCHAPv2 response */
#if 1	///////////////////////////////////////////////////////
	return( eapCreateMSCHAPv2Response( userName, userNameLength, password, 
									   passwordLength, serverChallenge,  
									   clientChallenge, peapAVP + 30 ) );
#else
	return( GenerateNTResponse( serverChallenge, clientChallenge,
								userName, userNameLength,
								unicodePassword, unicodePasswordLength, 
								peapAVP + 30 ) );
#endif	///////////////////////////////////////////////////////
	}

/* Create the "S=xxxx" authenticator response needed later in the 
   PEAP/MSCHAPv2 negotiation process */

static int createPEAPMSCHAPv2Authenticator( BYTE *authenticator, 
											const int authenticatorMaxLength, 
											int *authenticatorLength,
											const void *userName, 
											const void *password, 
											const void *ntResponse, 
											const void *clientChallenge, 
											const void *serverChallenge )
	{
	const int userNameLength = strlen( userName );
	const int passwordLength = strlen( password );

	/* Check input parameters */
	if( userNameLength <= 0 || userNameLength > 255 )
		return( CRYPT_ERROR_PARAM1 );
	if( passwordLength <= 0 || passwordLength > 255 )
		return( CRYPT_ERROR_PARAM2 );
	if( authenticatorMaxLength < 42 || authenticatorMaxLength > 255 )
		return( CRYPT_ERROR_PARAM3 );

	/* Generate the Authenticator Response */
	*authenticatorLength = 42;
#if 1	//////////////////////////////////////////////////////////////
	return( eapCreateAuthenticatorResponse( userName, userNameLength,
											password, passwordLength,
											serverChallenge, clientChallenge,
											ntResponse, authenticator ) );
#else
	return( GenerateAuthenticatorResponse( unicodePassword, 
										   unicodePasswordLength, ntResponse,
										   serverChallenge, clientChallenge,
										   userName, authenticator ) );
#endif	//////////////////////////////////////////////////////////////
	}

/****************************************************************************
*																			*
*								PEAP Client Routines						*
*																			*
****************************************************************************/

/* Microsoft servers can send one or more Extension Requests, in EAP rather 
   than PEAP format, using Microsoft-proprietary attributes and contents.  
   The most common one that's sent is Capabilities Negotiation Method, 
   documented in "[MS-PEAP]: Protected Extensible Authentication Protocol 
   (PEAP)", section 2.2.8.3:

	byte	code = 1				// Request
	byte	packet ID
	uint16	length = 16				// Including header
	byte	type = 254				// Expanded Types
	uint24	vendorID = 311			// Microsodt
	uint32	vendorType = 34			// Capabilities Negotiation Method
	byte[]	vendorData = 00 00 00 01
									// 32-bit flag, bit 31 = supports PEAP 
									// phase 2 fragmentation

   No idea what you're supposed to do with this if you're a non-Microsoft 
   product, but in most cases wpa_supplicant just sends another copy of the 
   Identity Response which produces the desired effect (but see also further
   down on wpa_supplicant's handling of vendorType = 33 requests).  
   
   Another option, suggested in the often-wrong "[MS-PEAP] Protected 
   Extensible Authentication Protocol (PEAP)", section 4.2.1, is to send a
   NAK response, but it's unclear whether this is a standard EAP NAK or
   Microsoft's bizarro NAK-as-an-EAP-extension-TLV NAK, but probably the
   latter since it's a response to an expanded type.

   However since we know what it is we can send it back, but with the 
   fragmentation flag cleared since it's unclear what we need to do to 
   handle this.  According to the above doc if a packet is larger than 
   MaxSendPacketSize then it's fragmented but there's no indication what 
   MaxSendPacketSize is apart from that it's obtained via another Microsoft-
   proprietary EAP message, nor is there any indication of what "PEAP 
   fragmentation" is beyond the already-present UDP, RADIUS, and EAP 
   fragmentation (the "phase 2" refers to the traffic inside the TLS tunnel 
   so it may be some sort of additional fragmentation at the PEAP level to 
   go with the other three?).
   
   Another possible message is SoH EAP Extensions Method, documented in 
   "[MS-PEAP]: Protected Extensible Authentication Protocol (PEAP)", section 
   2.2.8.2:

	byte	code = 1				// Request
	byte	packet ID
	uint16	length					// Including header
	byte	type = 254				// Expanded Types
	uint24	vendorID = 311			// Microsodt
	uint32	vendorType = 33			// Capabilities Negotiation Method
	byte[]	vendorData = 00 02 00 00
									// Magic value for SoH Request

   We're supposed to respond to this with an SoH TLV, whose payload is
   defined in the TCG's "TNC IF-TNCCS: Protocol Bindings for SoH" section
   3.5, "Statement of Health (SoH) Message", which contains a section
   3.5.1.3 System SoH (SSoH), but this is a composite field containing huge
   masses of information, way too complex to fill in, so we just resend the
   Identity Response as for an otherwise unknown EAP Extension.
   
   wpa_supplicant handles this slightly differently, if EAP_TNC is defined
   (and it seems to be enabled by default in builds included in standard 
   distros) then in /src/eap_peer/eap_peap.c:640 it calls 
   /src/eap_peer/tncc.c:tncc_process_soh_request() which just calls
   tncc_build_soh() to populate a dummy SoH packet with partially-guessed
   values rather than just dropping through to the default unrecognised-
   packet handling */

static int processExtensionRequest( const CRYPT_SESSION cryptSession, 
									const char *user, const int userLength,
									BYTE *payload, int *bytesCopied )
	{
	int status;

#if 0	/* Display some info on the packets and send a fake response */
	if( !memcmp( payload + 5, "\x00\x01\x37\x00\x00\x00\x22", 7 ) )
		{
		DEBUG_PRINT(( "Server sent Microsoft-proprietary Capabilities "
					  "Negotiation Method Request\n  EAP message " ));
		DEBUG_DUMPHEX( payload, *bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, sending Capabilities Negotiation "
					  "Method Response.\n", *bytesCopied ));
		payload[ 0 ] = 0x02;		/* Convert Request to Response */
		payload[ 15 ] = 0x00;		/* No fragmentation */
		}
	else
		{
		if( !memcmp( payload + 5, "\x00\x01\x37\x00\x00\x00\x21", 7 ) )
			{
			DEBUG_PRINT(( "Server sent Microsoft-proprietary SoH EAP "
						  "Extensions Method Request\n  EAP message " ));
			DEBUG_DUMPHEX( payload, *bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, resending Identity Response.\n",
						  *bytesCopied ));
			
			/* At this point we could in theory send a fake tncc_build_soh()-
			   style response, but for now we just retry the request */
			}
		else
			{
			DEBUG_PRINT(( "Server sent unknown proprietary EAP message\n" ));
			DEBUG_DUMPHEX_ALL( payload, *bytesCopied );
			DEBUG_PRINT(( ",\n  , length %d, resending Identity Response.\n",
						  *bytesCopied ));
			}
		payload[ 0 ] = 0x01;	/* Resend identity request */
		memcpy( payload + 1, user, userLength );
		*bytesCopied = 1 + userLength;
		}
#elif 0	/* Some sort of NAK as per the Microsoft PEAP doc, section 4.2.1 */
	/* Send an expanded NAK, RFC 3748 section 5.3.2:

		byte	code = 2				// Response
		byte	packet ID
		uint16	length = 12				// Including header
		byte	type = 254				// Expanded Types
		uint24	vendorID = 311			// Microsoft
		uint32	vendorType = 3			// NAK 
		byte	vendorData = {
			byte	type = 254
			uint24	vendorID = 0
			uint32	vendorType = 0 
			}							// No alternative 

	   However it would take quite a bit of trial-and-error to determine 
	   what it was that NPS expected, and given the near-useless level of
	   error reporting and the fact that resending the identity request 
	   (below) works we go with that instead */
#else	/* Just ignore it and repeat our request.  See the long comment in
		   completePEAPhandshake() for why we send a PEAP rather than full 
		   EAP response */
	payload[ 0 ] = 0x01;	/* Resend identity request */
	memcpy( payload + 1, user, userLength );
	*bytesCopied = 1 + userLength;
#endif /* 0 */
	status = cryptPushData( cryptSession, payload, *bytesCopied, 
							bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( *bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );

	return( CRYPT_OK );
	}

/* Complete a PEAP handshake */

int completePEAPhandshake( const CRYPT_SESSION cryptSession,
						   const char *user, const char *password )
	{ 
	BYTE payload[ EAP_PEAP_BUFFER_SIZE ];
	BYTE chapChallenge[ 256 ], ntResponse[ 24 ];
	BYTE tk[ 128 ], isk[ 32 ];	/* Tunnel Key, Inner Session Key */
	char authenticator[ CRYPT_MAX_TEXTSIZE ];
	BOOLEAN hasCryptobinding = FALSE;
	const int userLength = strlen( user );
	int payloadLength, bytesCopied, chapID, tlsOptions, length, status;
	int authenticatorLength;

	/* At this point PEAP requires an EAP ACK to be sent in order to 
	   trigger further responses from FreeRADIUS.  If this isn't sent then 
	   the server indicates "eap_peap: PEAP state ?", if it is sent then it 
	   indicates "eap_peap: PEAP state TUNNEL ESTABLISHED" and continues
	   the session.  This is required because PEAP omits the EAP type, ID,
	   and length fields so there's no way for the client to communicate 
	   what it's doing to the server, the only way to continue the protocol
	   is for the server to request things and the client to respond, and to
	   do that it needs to be triggered in some way.

	   This may be an artefact of the FreeRADIUS implementation, since PEAP 
	   can't communicate EAP packets in any normal manner exactly what 
	   happens is very implementation-dependent.  Some diagrams of the PEAP
	   message flow omit this step entirely, some label it "EAP Response",
	   some "EAP Response (PEAP)", and some try and provide an explanation 
	   like "EAP Response Identity to TLS tunnel opened".  All four of these 
	   are different things.
	   
	   The deciding factor seems to be Appendix A of 
	   draft-kamath-pppext-peapv0-00 which has an 
	   "EAP-Response/EAP-Type=PEAP ->" sent after the TLS handshake has 
	   completed, this being the ACK.
	   
	   However there is an exception to this when a TLS session is resumed.
	   In the non-resumed case the flow is:

		Client Hello	-------->
						<--------	Server Hello / Certificate / Done
		Client Keyex
		CCS / Finished	-------->
						<--------	CCS / Finished
		EAP ACK			-------->

	   In the resumed case the flow is:

		Client Hello	-------->
						<--------	Server Hello / CCS / Finished
		CCS / Finished	-------->

	   In this case the manufactured EAP ACK isn't necessary because the 
	   server will respond to the client message that ends the session
	   resumption */
	status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_TLS_OPTIONS,
								&tlsOptions );
	if( cryptStatusError( status ) )
		return( status );
	if( !( tlsOptions & CRYPT_TLSOPTION_RESUMED ) )
		{
		DEBUG_PRINT(( "Sending dummy EAP ACK to trigger server "
					  "response.\n" ));
		status = cryptSetAttribute( cryptSession, 
									CRYPT_SESSINFO_AUTHRESPONSE, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		DEBUG_PRINT(( "Session is resumed, skipping dummy EAP ACK.\n" ));
		}

	/* Read the server's Identity Request.  This should be in PEAP format as
	   per "Microsoft's PEAP version 0 (Implementation in Windows XP SP1)",
	   section 1.1, "for EAP Types other than 33, the Code, Identifier, and 
	   Length fields are not sent, but rather EAP packets sent within the 
	   PEAP tunnel begin with the Type field":

		byte	type = 1			// Identity 
	   
	   This is also specified in "[MS-PEAP]: Protected Extensible 
	   Authentication Protocol (PEAP)" section 3.1.5.6 which states that
	   PEAP "compression", stripping the EAP code, packet ID, and length
	   field and leaving only the type and payload, is mandatory for 
	   everything except the Microsoft-specific EAP TLV Extension, 
	   Capabilities Negotiation, and SoH EAP Extensions packets.

	   However FreeRADIUS incorrectly sends the full EAP packet (in EAP 
	   format, code = Request, type = Identity):

		byte	code = 1			// Request
		byte	packet ID			// From the EAP layer below the TLS 
									// tunnel, packet ID there is 5
		uint16	length = 5			// Including header
		byte	type = 1			// Identity
	   
	   See the comment in /src/eap_peer/eap_peap.c:791, "At least FreeRADIUS 
	   seems to send full EAP header with EAP Request Identity", so we need 
	   to be able to deal with either form */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied == 1 )
		{
		/* PEAP identity request */
		if( payload[ 0 ] != 0x01 )
			{
			/* We were expecting a PEAP Identity Request but got something 
			   else */
			DEBUG_PRINT(( "Server sent %02X, expected PEAP Identity Request "
						  "message 01.\n", payload[ 0 ] ));
			return( CRYPT_ERROR_BADDATA );
			}
		}
	else
		{
		/* FreeRADIUS incorrect EAP identity request */
		if( bytesCopied < 5 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( payload[ 0 ] != 0x01 || payload[ 4 ] != 0x01 )
			{
			/* We were expecting an EAP Identity Request but got something 
			   else */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, expected EAP Identity Request "
						  "message 01 nn 00 05 01.\n", bytesCopied ));
			return( CRYPT_ERROR_BADDATA );
			}
		}

	/* Respond with our Identity (in PEAP format):

		byte	type = 1			// Identity
		byte[]	identity */
#if 0
	/* wpa_supplicant claims that it sends an EAP (rather than PEAP) 
	   response at this point and the eapol_test output also prints a full
	   EAP response: 

		02 xx 00 09 01 'test'

	   but sending that to FreeRADIUS produces:

		eap_peap: Received unexpected EAP-Response, rejecting the session.
		eap_peap: ERROR: Tunneled data is invalid 
	
	   with an Access-Reject sent back to the client.  The error log comes 
	   from FreeRADIUS 3.2.x 
	   src/modules/rlm_eap/types/rlm_eap_peap:eappeap_process() which
	   calls eapmessage_verify() and, for a PW_EAP_RESPONSE packet requires 
	   that it's a PW_EAP_TLV, in other words an extension request 
	   containing some sort of status response to the server.  So 
	   wpa_supplicant can't possibly be sending the message that it claims 
	   it's sending */
	payload[ 0 ] = 0x02;			/* Request -> Response */
	if( bytesCopied <= 1 )
		{
		BYTE eapID;
		int eapIDlength;

		/* We got a PEAP packet, manufacture an EAP packet from the
		   data sent at the outer EAP level */
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_TLS_EAPDATA, 
										  NULL, &eapIDlength );
		if( cryptStatusOK( status ) && eapIDlength != 1 )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusOK( status )  )
			{
			status = cryptGetAttributeString( cryptSession, 
											  CRYPT_SESSINFO_TLS_EAPDATA, 
											  &eapID, &eapIDlength );
			}
		if( cryptStatusError( status ) )
			return( status );
		payload[ 1 ] = eapID;
		payload[ 2 ] = 0x00;
		payload[ 3 ] = 5 + userLength;
		payload[ 4 ] = 0x01;
		}
	else
		{
		/* We got an EAP packet, update the header */
		payload[ 3 ] = 5 + userLength;
		}
	memcpy( payload + 5, user, userLength );
	status = cryptPushData( cryptSession, payload, 5 + userLength, 
							&bytesCopied );
#else
	payload[ 0 ] = 0x01;
	memcpy( payload + 1, user, userLength );
	status = cryptPushData( cryptSession, payload, 1 + userLength, 
							&bytesCopied );
#endif
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's MSCHAPv2 Challenge (in PEAP format):

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 1			// Challenge 
		byte	chapID				// Copy to response
		uint16	length == 22 + nLen	// Including header
		byte	value-size = 16 / 0x10	// Fixed at 16 bytes
			byte[16]	chapChallenge// Challenge 
		byte[]	name				// Remaining bytes = server name */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );
	while( bytesCopied >= 12 && \
		   payload[ 0 ] == 0x01 && payload[ 4 ] == 0xFE )
		{
		/* At this point Microsoft servers may send back one or more 
		   extension requests, this time in EAP rather than PEAP format, 
		   with the 12-byte EAP extension header followed by the payload:

			byte	code = 1		// Request
			byte	packet ID
			uint16	length			// Including header
			byte	type = 254		// Expanded Types
			uint24	vendorID		
			uint32	vendorType
			...

		   using Microsoft-proprietary attributes and contents.  In order to 
		   continue we have to work our way past these, so we keep reading
		   extension requests until we get to something else */
		status = processExtensionRequest( cryptSession, user, userLength, 
										  payload, &bytesCopied );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( bytesCopied < 22 || \
		payload[ 0 ] != 0x1A || payload[ 1 ] != 0x01 || payload[ 5 ] != 0x10 )
		{
		/* We were expecting an MSCHAPv2 Challenge but got something else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected MSCHAPv2 Challenge message "
					  "1A 01 nn 00 nn 10...\n", bytesCopied ));
		return( CRYPT_ERROR_BADDATA );
		}
	memcpy( chapChallenge, payload + 6, 16 );
	chapID = payload[ 2 ] & 0xFF;

	/* Respond with our MSCHAPv2 Response (in PEAP format) */
	status = createPEAPAVPMSCHAPv2( payload, EAP_PEAP_BUFFER_SIZE, 
									&payloadLength, user, password, 
									MSCHAPV2_CHALLENGE_VALUE, 
									chapChallenge, chapID );
	if( cryptStatusOK( status ) )
		{
		status = cryptPushData( cryptSession, payload, payloadLength, 
								&bytesCopied );
		}
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the NT-Response value is at payload + 30 and take a 
	   copy */
	assert( !memcmp( payload + 22, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) );
	assert( payload[ 54 ] == 0x00 );
	memcpy( ntResponse, payload + 30, 24 );

	/* Create the MSCHAPv2 Authenticator value sent in the MSCHAPv2 
	   Success */
	status = createPEAPMSCHAPv2Authenticator( authenticator, CRYPT_MAX_TEXTSIZE,
											  &authenticatorLength, user, 
											  password, ntResponse, 
											  MSCHAPV2_CHALLENGE_VALUE,
											  chapChallenge );
	if( cryptStatusError( status ) )
		return( status );

	/* Get the TK and calculate the ISK value from the user password and 
	   NT-Response value */
	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPKEY,
									  tk, &length );
	if( cryptStatusError( status ) )
		return( status );
	assert( length >= 40 );		/* Make sure we have at least 40 bytes of TK */
	status = eapCreateISK( isk, password, strlen( password ), ntResponse );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's MSCHAPv2 Success or Failure Request (in PEAP format):

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 3			// Success Request
		byte	chapID
		uint16	length
		byte[]	authResponse		// "S=<auth_string>"

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 4			// Failure Request
		byte	chapID
		uint16	length
		byte[]	authResponse		// "E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=vvvvvvvvvv M=<msg>" 

	   The opcodes for these packets are actually 3 = Success and 4 = Failure, 
	   however when sent from the server they're Success/Failure Request and 
	   when sent back from the client they're Success/Failure Response.
	   
	   For the errors, E is a typically 3-digit error code, R is 1 if 
	   request retries are allowed, C is a new 16-digit challenge for the
	   retried request, and V is the MSCHAP version supported on the server.
	   With true Microsoft logic, for MSCHAPv2 the version value is 3 (RFC 
	   2759 section 6).

	   The documented error codes, from RFC 2759, are:

		646 ERROR_RESTRICTED_LOGON_HOURS
		647 ERROR_ACCT_DISABLED
		648 ERROR_PASSWD_EXPIRED
		649 ERROR_NO_DIALIN_PERMISSION
		691 ERROR_AUTHENTICATION_FAILURE
		709 ERROR_CHANGING_PASSWORD

	   In the case of "E=691 R=1" this technically means "The remote 
	   connection was denied because the user name and password combination 
	   you provided is not recognized, or the selected authentication 
	   protocol is not permitted on the remote access server" however in 
	   practice it's a more generic "Something went wrong".  In particular 
	   MSCHAPv2 uses NTLMv1 when used in Windows RAS services, but this
	   is usually disabled on DCs with only NTLMv2 being enabled.  The fix
	   is to enable NTLMv2 for MSCHAPv2 as per
	   https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/rras-vpn-connections-fail-ms-chapv2-authentication

	   This may also be affected by the LmCompatibilityLevel setting on
	   the DC, see
	   https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960646(v=technet.10)
	   */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 5 )
		return( CRYPT_ERROR_UNDERFLOW );
	if( payload[ 0 ] != 0x1A || \
		( payload[ 1 ] != 0x03 && payload[ 1 ] != 0x04 ) )
		{
		/* We were expecting an MSCHAPv2 Success Request but got something 
		   else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected MSCHAPv2 Success/Failure "
					  "Request message 1A 03 nn 00 nn... or 1A 04 nn 00 "
					  "nn...\n", bytesCopied ));

		/* In the case of an invalid user name we get back an EAP Extension 
		   Request (in EAP format):

			byte	type = 1		// Identity Request
			byte	packet ID		// From the EAP layer below the TLS 
									// tunnel, packet ID there is 7 so this
									// will be 8
			uint16	length = 11 / 0x0B	// Including header
			byte	type = 33 / 0x21	// EAP Extensions / PW_EAP_TLV
				byte	ext.flags = 0x80// TLV flags, mandatory AVP
				byte	ext.type = 3	// TLV type, Result = 3 / EAP_TLV_ACK_RESULT
				uint16	ext.length = 2	// TLV length
				uint16	status = 2		// TLV data, Failure = 2 / EAP_TLV_FAILURE

		   This differs from EAP-TTLS where a message with an unknown 
		   Identity is rejected at the RADIUS/EAP level because in PEAP the 
		   real identity is conveyed over the PEAP tunnel, with the one 
		   given at the RADIUS/EAP level typically being something like 
		   "anonymous".

		   In the case of FreeRADIUS the implementation is in 
		   /src/modules/rlm_eap/types/rlm_eap_peap/peap.c function 
		   eappeap_failure(), but other servers like Microsoft's NPS do the 
		   same thing */
		if( bytesCopied >= 11 && \
			payload[ 0 ] == 0x01 && payload[ 4 ] == 0x21 && \
			payload[ 6 ] == 0x03 && payload[ 10 ] == 0x02 )
			{
			/* There isn't really an appropriate error code for incorrect-
			   username so the best that we can report is a 
			   CRYPT_ERROR_WRONGKEY, in the sense of "wrong credentials" */
			DEBUG_PUTS(( "Server sent Identity Request - EAP Extension - "
						 "Failure, indicating an incorrect user name." ));
			return( CRYPT_ERROR_WRONGKEY );
			}

		return( CRYPT_ERROR_BADDATA );
		}
	payload[ bytesCopied ] = '\0';
	if( payload[ 1 ] == 0x03 )
		{
		DEBUG_PRINT(( "Server responded with Success packet, message "
					  "'%s'.\n", payload + 5 ));
		if( memcmp( payload + 5, authenticator, authenticatorLength ) )
			{
			payload[ 5 + authenticatorLength ] = '\0';
			DEBUG_PRINT(( "Server's Authenticator value '%s' doesn't "
						  "match\n  our calculated Authenticator '%s'.\n",
						  payload + 5, authenticator ));
			return( CRYPT_ERROR_SIGNATURE );
			}
		}
	else
		{
		DEBUG_PRINT(( "Server responded with Failure packet, message "
					  "'%s'.\n", payload + 5 ));
		}

	/* Send our MSCHAPv2 Success/Failure Response (in PEAP format):

		byte	type = 26 / 0x1A		// MSCHAPv2
		byte	opcode = 3				// Success Response

		byte	type = 26 / 0x1A		// MSCHAPv2
		byte	opcode = 4				// Failure Response 

	   In essence this just consists of echoing the first two bytes of the 
	   received packet back to the server */
	status = cryptPushData( cryptSession, payload, 2, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* At this point the negotiation should be complete, however FreeRADIUS
	   continues with EAP (not PEAP) messages, which we need to deal with in
	   order to get RADIUS attributes back.  This is based on the 
	   "Microsoft's PEAP version 0 Implementation in Windows XP SP1" draft
	   (draft-kamath-pppext-peapv0-00.txt), section 1.3 which specifies it 
	   as required for Windows XP SP1 compatibility, and see also the note 
	   earlier on why the EAP format is used.  
	   
	   Microsoft documents it differently in "[MS-CHAP]: Extensible 
	   Authentication Protocol Method for Microsoft Challenge Handshake 
	   Authentication Protocol (CHAP)", stating that what's sent back is an
	   EAP Success packet, however what it calls "EAP Success" is actually 
	   an Extension Request containing a Success status.
	   
	   Cisco also apparently sends extensions at this point, specifically an
	   ACK Result which we just echo back with the first byte changed to 02,
	   Response */

	/* Read the server's Extension Request (in EAP format, code = Request, 
	   type = Extension, type names from FreeRADIUS).  The following is from 
	   draft-kamath-pppext-peapv0-00.txt mentioned above, section 2, which 
	   defines Extension Request/Response packets, type = 33, for which the 
	   only valid TLV type is 3, "Acknowledged Result" (PEAPv2 just calls 
	   this "Result", draft-josefsson-pppext-eap-tls-eap-10.txt section 4.2).  
	   So essentially the entire packet is fixed boilerplate except for the 
	   last byte, which is either "1 - Success", or "2 - Failure".

		byte	code = 1			// Request / PW_EAP_REQUEST
		byte	packet ID			// From the EAP layer below the TLS 
									// tunnel, packet ID there is 7 so this 
									// will be 8
		uint16	length = 11 / 0x0B	// Including header
		byte	type = 33 / 0x21	// EAP Extensions, from PEAP RFC / PW_EAP_TLV
			byte	ext.flags = 0x80// TLV flags, mandatory AVP
			byte	ext.type = 3	// TLV type, Result = 3 / EAP_TLV_ACK_RESULT
			uint16	ext.length = 2	// TLV length, payload only
			uint16	status = 1		// TLV data, Success = 1 / EAP_TLV_SUCCESS,
									//			 Failure = 2 / EAP_TLV_FAILURE
	   or, for Windows NPS:

		byte	code = 1			// Request / PW_EAP_REQUEST
		byte	packet ID			// From the EAP layer below the TLS 
									// tunnel, packet ID there is 7 so this 
									// will be 8
		uint16	length = 71 / 0x47	// Including header
		byte	type = 33 / 0x21	// EAP Extensions, from PEAP RFC / PW_EAP_TLV
			byte	ext.flags = 0x80// TLV flags, mandatory AVP
			byte	ext.type = 3	// TLV type, Result = 3 / EAP_TLV_ACK_RESULT
			uint16	ext.length = 2	// TLV length, payload only
			uint16	status = 1		// TLV data, Success = 1 / EAP_TLV_SUCCESS,
									//			 Failure = 2 / EAP_TLV_FAILURE
			byte	ext.flags = 0x00// TLV flags, mandatory according to the spec
									// but NPS sets it to optional
			byte	ext.type = 12 / 0x0C// TLV type, Crypto-Binding
			uint16	ext.length = 56 / 0x38// TLV length, payload only
			byte[3]	versions		// Version info, 0x00 0x00 0x00
			byte	subtype			// Binding Request = 0
			byte[32] nonce			// Nonce for PRF
			byte[20] MAC			// HMAC-SHA1 MAC

	   The AVP format is actually a single-bit flag for mandatory/optional,
	   a zero bit, and then 14 bits of type, but only the value 3 is 
	   defined for the type (see above) so we treat it as two bytes, one with 
	   flags and one with the type */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 11 )
		return( CRYPT_ERROR_UNDERFLOW );
	if( payload[ 0 ] != 0x01 || payload[ 4 ] != 0x21 || \
		payload[ 6 ] != 0x03 )
		{
		/* We were expecting another Identity Request but got something 
		   else */
		DEBUG_PRINT(( "Server sent " ));
		DEBUG_DUMPHEX( payload, bytesCopied );
		DEBUG_PRINT(( ",\n  length %d, expected EAP Identity Request - "
					  "Acknowledged Result - Success message 01 nn 00 11 "
					  "21 80 03 00 02 00 01.\n", bytesCopied ));
		return( CRYPT_ERROR_BADDATA );
		}
	if( payload[ 10 ] == 0x01 )
		{
		DEBUG_PRINT(( "Server responded with Acknowledged Result - Success "
					  "packet.\n" ));
		}
	else
		{
		DEBUG_PRINT(( "Server responded with Acknowledged Result - Failure "
					  "packet.\n" ));

		/* This isn't a CRYPT_ERROR_WRONGKEY because the authentication has
		   already succeeded, the only reason why we'd get a failure 
		   response at this point is because of a server error where it 
		   can't continue for some reason */
		return( CRYPT_ERROR_BADDATA );
		}

	/* There may be further TLVs following the first one, typically a 
	   Cryptobinding request from NPS 
	   (draft-josefsson-pppext-eap-tls-eap-10.txt section 4.5).  This 
	   doesn't exist for PEAPv0 but was added in PEAPv2 so technically
	   shouldn't be sent, however it's kludged into what's actually a PEAPv0
	   exchange by setting the version fields to an invalid 0x00 0x00 0x00 
	   rather than the required PEAPv2 version values:

		byte	ext.flags = 0x00	// TLV flags, mandatory according to the 
									// spec but NPS sets it to optional
		byte	ext.type = 12 / 0x0C// TLV type, Crypto-Binding
		uint16	ext.length = 56 / 0x38// TLV length
			byte[3]	versions		// Version info, 0x00 0x00 0x00
			byte	subtype			// Binding Request = 0
			byte[32] nonce			// Nonce used when creating Cryptobinding
			byte[20] MAC			// HMAC-SHA1 MAC

	   So if there's more data present, indicated by an overall length 
	   greater than the length of the basic Acknowledged Result plus the 
	   header of another TLV following it then we display information on 
	   the additional TLV.  The second TLV starts at offset 11 */
	if( payload[ 3 ] > 11 + 4 )
		{
		DEBUG_PRINT(( "Server Acknowledged Result contains additional "
					  "TLV " ));
		if( payload[ 12 ] == 0x0C )
			{
			/* There's a Crypto-Binding request from NPS present that we 
			   have to deal with.  Sending just an Extension Response as we 
			   do for FreeRADIUS results in a "Received Crypto-Binding TLV 
			   is invalid" error, this is caused by having the "Disconnect 
			   Clients Without Cryptobinding" option set on the server so 
			   that it expects a Crypto-Binding but doesn't see one.  To fix
			   this the documentation states that the setting "Disconnect 
			   Clients Without Cryptobinding" needs to be unset and we need 
			   to NAK the Cryptobinding request which is done further down,
			   however this also doesn't work, see the comment for the NAK
			   code */
			DEBUG_PRINT(( "Crypto-Binding - Request.\n" ));
			hasCryptobinding = TRUE;
			}
		else
			{
			DEBUG_PRINT(( "of unknown type %d (%X).\n", 
						  payload[ 12 ], payload[ 12 ] ));
			}
		}

	/* Convert the previous Extension Request into an Extension Response (in 
	   EAP format, code = Response, type names from FreeRADIUS):

		byte	code = 2			// Response / PW_EAP_RESPONSE
		[ Rest as above ] 

	   This is as per the PEAP-kludges RFC mentioned above 
	   (draft-kamath-pppext-peapv0-00.txt), section 3.2, which says that for 
	   use with Windows support for the Result AVP is required, with the 
	   only allowed message being EAP Request, type = Extensions, status = 
	   Success answered by EAP Response, type = Extensions, status = 
	   Success.  Anything else should be treated as a failure.  FreeRADIUS 
	   implements this by only checking that the code is PW_EAP_RESPONSE, 
	   the type is PW_EAP_TLV, and the status is EAP_TLV_SUCCESS */
	payload[ 0 ] = 0x02;
	if( hasCryptobinding )
		{
#ifdef USE_CRYPTOBINDING_NAK
		/* If we got a Cryptobinding request 
		   (draft-josefsson-pppext-eap-tls-eap-10.txt section 4.3) then we
		   need to NAK it in order to continue.  No-one seems to know what 
		   to do with the vendorID field, we send 0x137 which is Microsoft 
		   since it's their mess, but wpa_supplicant 
		   eap_peap.c:eap_tlv_build_nak() sets this field to 0, not 0x137:

			byte	ext.flags = 0x80	// TLV flags, mandatory AVP
			byte	ext.type = 4		// TLV type, NAK / EAP_TLV_NAK_TLV
			uint16	ext.length = 6		// TLV length
				uint32	vendorID = 0x137// Vendor ID = Microsoft
				uint16	type = 0x0C		// Type = Crypto-Binding

		   This code is disabled because it results in NPS ending the 
		   negotiation at this point, despite what the Windows docs say it
		   seems to be necessary to perform the Cryptobinding silly-walk in
		   order to continue */
		static const BYTE cryptobindingNAK[] = {
			0x80, 0x04, 0x00, 0x06, 0x00, 0x00, 0x01, 0x37, 0x00, 0x0C
			};

		memcpy( payload + 11, cryptobindingNAK, 10 );
		payload[ 3 ] = 11 + 10;

		/* Since we're sending back a NAK as the second TLV rather than the
		   Cryptobinding response we have to truncate the reply at the end 
		   of the NAK */
		bytesCopied = 11 + 10;
#else
		BYTE ipmk[ 40 ], cmk[ 20 ], cmac[ 20 ];
		BYTE message[ 60 ];
		BYTE *cryptoBinding = payload + 11;

		/* Make sure that the Crypto-Binding message is at payload + 11 */
		assert( !memcmp( cryptoBinding, "\x00\x0C\x00\x38\x00\x00\x00\x00", 8 ) );

		/* Copy the Crypto-Binding message with the last the last 20 bytes 
		   containing the MAC value zeroed out */
		memset( message, 0, 60 );
		memcpy( message, cryptoBinding, 60 - 20 );

		/* Create the Intermediate PEAP MAC Key and Compound MAC Key and use
		   the latter to MAC the Crypto-Binding message */
		status = eapCreateCMK( ipmk, cmk, tk, isk );
		if( cryptStatusOK( status ) )
			status = eapCreateCMAC( cmac, cmk, message, 60 );
		if( cryptStatusError( status ) )
			return( status );
		if( memcmp( cmac, cryptoBinding + 40, 20 ) )
			{
			DEBUG_PRINT(( "Received Crypto-Binding CMAC value " ));
			DEBUG_DUMPHEX( cryptoBinding + 40, 20 );
			DEBUG_PRINT(( "\n     didn't match calculated value " ));
			DEBUG_DUMPHEX( cmac, 20 );
			DEBUG_PRINT(( ".\n" ));
			return( CRYPT_ERROR_SIGNATURE );
			}

		/* Create the Crypto-Binding response */
		assert( cryptoBinding[ 7 ] == 0x00 );
		cryptoBinding[ 7 ] = 0x01;	/* Request -> Response */ 
		memset( message, 0, 60 );
		memcpy( message, cryptoBinding, 60 - 20 );
		status = eapCreateCMAC( cmac, cmk, message, 60 );
		if( cryptStatusError( status ) )
			return( status );
		memcpy( cryptoBinding + 40, cmac, 20 );
//////////////////////////////////////////////////////////////////////
//DEBUG_PRINT(( "Crypto-Binding response:\n" ));
//DEBUG_DUMPHEX_ALL( payload, bytesCopied );
//DEBUG_PRINT(( "\n" ));
//////////////////////////////////////////////////////////////////////
#endif /* USE_CRYPTOBINDING_NAK */
		}
	status = cryptPushData( cryptSession, payload, bytesCopied, 
							&bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the final response from the server.  This is used to communicate 
	   the RADIUS attributes outside the tunnel (because why send them in the
	   secure tunnel when you can include them unsecured outside it?), so 
	   the PEAP payload is just a no-op unless it's NPS' garbled response to
	   our Cryptobinding NAK */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
#ifdef USE_CRYPTOBINDING_NAK
	if( hasCryptobinding )
		{
		/* Since we've sent a NAK for the Cryptobinding we're going to get 
		   back an ACK of the NAK, or at least NPS' broken interpretation of
		   an ACK, encoded as a Response rather than a Request and with the 
		   length and status (data) fields missing, because Microsoft.  So
		   what's returned is 02 09 00 07 21 80 03 instead of what the spec
		   says (draft-josefsson-pppext-eap-tls-eap-06.txt section 4.5):

			byte	code = 2		// Response / PW_EAP_RESPONSE
			byte	packet ID		// From the EAP layer below the TLS 
									// tunnel, packet ID there is 8 so this 
									// will be 9
			uint16	length = 7		// Including header
			byte	type = 33 / 0x21// EAP Extensions, from PEAP RFC / PW_EAP_TLV
				byte	ext.flags = 0x80// TLV flags, mandatory AVP
				byte	ext.type = 3// TLV type, Result = 3 / EAP_TLV_ACK_RESULT 
			  [	uint16	ext.len		// Missing TLV length 
			    uint16	sttaus		// Missing TLV data ] */
		if( bytesCopied < 7 )
			return( CRYPT_ERROR_UNDERFLOW );
		if( ( payload[ 0 ] != 0x01 && payload[ 0 ] != 0x02 ) || \
			payload[ 4 ] != 0x21 || payload[ 6 ] != 0x03 )
			{
			/* We were expecting an ACK but got something else */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, expected EAP Identity Request - "
						  "Acknowledged Result - Success message 01 nn 00 11 "
						  "21 80 03 00 02 00 01.\n", bytesCopied ));
			return( CRYPT_ERROR_BADDATA );
			}
		DEBUG_PRINT(( "Server responded with Microsoft garbled Acknowledged "
					  "Result packet.\n" ));
		}
	else
#endif /* USE_CRYPTOBINDING_NAK */
		{
		if( bytesCopied != 0 )
			{
			/* This should be a zero-length EAP message */
			DEBUG_PRINT(( "Server sent " ));
			DEBUG_DUMPHEX( payload, bytesCopied );
			DEBUG_PRINT(( ",\n  length %d, should have been zero-length "
						  "message.\n", bytesCopied ));
			return( CRYPT_ERROR_BADDATA );
			}
		DEBUG_PRINT(( "Server responded with zero-length packet used to convey "
					  "RADIUS attributes.\n" ));
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								PEAP Server Routines						*
*																			*
****************************************************************************/

/* The various messages we have to send to the client to allow things to
   progress */

static const BYTE mschapv2Challenge[] = {
	0x1A,				/* Type = MSCHAPv2 */
	0x01,				/* Subtype = Challenge */
	0x02,				/* ChapID */
	0x00, 0x16 - 1,		/* Not-really length = 21 (see comment below) */
	0x10,				/* Challenge length = 16 */
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
	};					/* Different from MSCHAPV2_CHALLENGE_VALUE */

static const BYTE mschapv2Success[] = {
	0x1A,				/* Type = MSCHAPv2 */
	0x03,				/* Subtype = Success Request */
	0x02,				/* ChapID */
	0x00, 0x2F - 1,		/* Not-really length = 46 (as above) */
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23		/* Placeholder for Authenticator value,
						   "S=0123456789ABCDEFFEDCBA9876543210" */
	};

static const BYTE eapExtensionRequest[] = {
	0x01,				/* Type = Request / PW_EAP_REQUEST */
	0x08,				/* packetID	from the EAP layer below the TLS tunnel, 
						   packet ID there is 7 so this will be 8 */
	0x00, 0x47,			/* Length including header = 71 */
	0x21,				/* EAP Extensions = 33, from PEAP RFC / PW_EAP_TLV */
		0x80,			/* TLV flags, mandatory AVP */
		0x03,			/* TLV type, Result = 3 / EAP_TLV_ACK_RESULT */
		0x00, 0x02,		/* TLV length, payload only */
		0x00, 0x01,		/* TLV data, Success = 1 / EAP_TLV_SUCCESS */
		0x00,			/* TLV flags, mandatory according to the spec but 
						   NPS sets it to optional */
		0x0C,			/* TLV type, Crypto-Binding = 12 */
		0x00, 0x38,		/* TLV length, payload only */
		0x00, 0x00, 0x00, /* Version info, 0x00 0x00 0x00 */
		0x00,			/* Subtype = Binding Request = 0 */
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 
		0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x79, 0x77, 
		0x79, 0x7A, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
						/* 32-byte nonce for PRF,
						   "abcdefghijklmnopqrstuvywyz123456" */
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
		0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
		0x23, 0x23, 0x23, 0x23
						/* Placeholder for HMAC-SHA1 MAC,
						   "####################" */
	};

/* Complete the server-side PEAP handshake.  See the comments in 
   completePEAPhandshake() for explanations of what's going on here */

int completePEAPhandshakeServer( const CRYPT_SESSION cryptSession,
								 const char *user, 
								 const char *password )
	{
	BYTE payload[ EAP_PEAP_BUFFER_SIZE ], chapChallenge[ 256 ];
	BYTE mschapv2Response[ 256 ], ntResponse[ 24 ];
	BYTE tk[ 128 ], isk[ 32 ];	/* Tunnel Key, Inner Session Key */
	BYTE ipmk[ 40 ], cmk[ 20 ];	/* Intermediate PEAP MAC Key,Compound MAC 
								   Key */
	BYTE cmacMessage[ 60 ], cmac[ 20 ], *cryptoBinding;
	char authenticator[ CRYPT_MAX_TEXTSIZE ];
	int bytesCopied, chapID, mschapv2Length, authenticatorLength, length;
	int status;

	/* Read the dummy EAP ACK that the client needs to send to continue the
	   negotiations */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the server's Identity Request (in PEAP format):

		byte	type = 1			// Identity */
	status = cryptPushData( cryptSession, "\x01", 1, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the client's Identity (in PEAP format):

		byte	type = 1			// Identity
		byte[]	identity */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied < 2 )
		return( CRYPT_ERROR_BADDATA );
	if( payload[ 0 ] != 0x01 )
		{
		/* We were expecting a PEAP Identity but got something else */
		DEBUG_PRINT(( "Client sent %02X, expected PEAP Identity "
					  "message 01.\n", payload[ 0 ] ));
		return( CRYPT_ERROR_BADDATA );
		}

	/* Send our MSCHAPv2 Challenge (in PEAP format):

		byte	type = 26 / 0x1A	// MSCHAPv2
		byte	opcode = 1			// Challenge 
		byte	chapID				// Copied to response
		uint16	length == 21		// Including header
		byte	value-size = 16 / 0x10	// Fixed at 16 bytes
			byte[16]	chapChallenge// Challenge 

	   See the long comment for createPEAPAVPMSCHAPv2() for why the
	   length field is 21 instead of the expected 22 */
	status = cryptPushData( cryptSession, mschapv2Challenge, 22, 
							&bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );
	chapID = mschapv2Challenge[ 2 ] & 0xFF;

	/* Read the client's response and create our MSCHAPv2 Response (in PEAP 
	   format) to compare to what the client sent us */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusOK( status ) )
		{
		memcpy( chapChallenge, payload + 6, 16 );
		status = createPEAPAVPMSCHAPv2( mschapv2Response, 256, &mschapv2Length,
										user, password, chapChallenge, 
										mschapv2Challenge + 6, chapID );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( bytesCopied != mschapv2Length || \
		memcmp( payload, mschapv2Response, mschapv2Length ) )
		{
		DEBUG_PRINT(( "Client's MSCHAPv2 Response doesn't match calculated "
					  "MSCHAPv2 Response.\n  Client Response:\n" ));
		DEBUG_DUMPHEX_ALL( payload, bytesCopied );
		DEBUG_PRINT(( "\n  Our Response:\n" ));
		DEBUG_DUMPHEX_ALL( mschapv2Response, mschapv2Length );
		DEBUG_PRINT(( "\n" ));
		return( CRYPT_ERROR_SIGNATURE );
		}

	/* Make sure that the NT-Response value is at payload + 30 and take a 
	   copy */
	assert( !memcmp( payload + 22, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) );
	assert( payload[ 54 ] == 0x00 );	
	memcpy( ntResponse, payload + 30, 24 );

	/* Create the MSCHAPv2 Authenticator value sent in the MSCHAPv2 
	   Success */
	status = createPEAPMSCHAPv2Authenticator( authenticator, CRYPT_MAX_TEXTSIZE,
											  &authenticatorLength, user, 
											  password, ntResponse, 
											  chapChallenge,
											  mschapv2Challenge + 6 );
	if( cryptStatusError( status ) )
		return( status );

	/* Send our MSCHAPv2 Success Request (in PEAP format) */
	memcpy( payload, mschapv2Success, 47 );
	memcpy( payload + 5, authenticator, 42 );
	status = cryptPushData( cryptSession, payload, 47, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the client/s MSCHAPv2 Success Response (in PEAP format) */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusOK( status ) && \
		( payload[ 0 ] != 0x1A || payload[ 1 ] != 0x03 ) )
		{
		DEBUG_PRINT(( "Client didn't respond with MSCHAPv2 Success "
					  "Response.\n" ));
		status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Get the TK and calculate the ISK value from the user password and 
	   NT-Response value */
	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_TLS_EAPKEY,
									  tk, &length );
	if( cryptStatusError( status ) )
		return( status );
	assert( length >= 40 );		/* Make sure we have at least 40 bytes of TK */
	status = eapCreateISK( isk, password, strlen( password ), ntResponse );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the Crypto-Binding message is at payload + 11 */
	memcpy( payload, eapExtensionRequest, 71 ); 
	cryptoBinding = payload + 11;
	assert( !memcmp( cryptoBinding, "\x00\x0C\x00\x38\x00\x00\x00\x00", 8 ) );

	/* Copy the Crypto-Binding message with the last the last 20 bytes 
	   containing the MAC value zeroed out */
	memset( cmacMessage, 0, 60 );
	memcpy( cmacMessage, cryptoBinding, 60 - 20 );

	/* Create the Intermediate PEAP MAC Key and Compound MAC Key and use the 
	   latter to MAC the Crypto-Binding message */
	status = eapCreateCMK( ipmk, cmk, tk, isk );
	if( cryptStatusOK( status ) )
		status = eapCreateCMAC( cmac, cmk, cmacMessage, 60 );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( cryptoBinding + 40, cmac, 20 );

	/* Send our Extension Request and Cryptobinding Request (in EAP 
	   format) */
	status = cryptPushData( cryptSession, payload, 71, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the client's Extension Response (in EAP format */
	status = cryptPopData( cryptSession, payload, EAP_PEAP_BUFFER_SIZE, 
						   &bytesCopied );
	if( cryptStatusOK( status ) && \
		( payload[ 0 ] != 0x2 || payload[ 4 ] != 0x21 || 
		  payload[ 6 ] != 0x03 ) )
		{
		DEBUG_PRINT(( "Client didn't respond with Extension Response.\n" ));
		status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Verify the client's Crypto-Binding response */
	if( cryptoBinding[ 1 ] != 0x0C || cryptoBinding[ 3 ] != 0x38 || \
		cryptoBinding[ 7 ] != 0x01 )
		{
		DEBUG_PRINT(( "Client didn't respond with Cryptobinding Response.\n" ));
		return( CRYPT_ERROR_BADDATA );
		}
	memset( cmacMessage, 0, 60 );
	memcpy( cmacMessage, cryptoBinding, 60 - 20 );
	status = eapCreateCMAC( cmac, cmk, cmacMessage, 60 );
	if( cryptStatusError( status ) )
		return( status );
	if( memcmp( cryptoBinding + 40, cmac, 20 ) )
		{
		DEBUG_PRINT(( "Received client Crypto-Binding CMAC value " ));
		DEBUG_DUMPHEX( cryptoBinding + 40, 20 );
		DEBUG_PRINT(( "\n     didn't match calculated value " ));
		DEBUG_DUMPHEX( cmac, 20 );
		DEBUG_PRINT(( ".\n" ));
		}

	/* We're finally through all the crypto, we're done, tell the client 
	   they can come in.

	   Windows NPS sends a bunch of additional attributes at this point 
	   which clients like eapol_test complain about the absence of if all
	   of the Microsoft-specific calisthenics above have been followed,
	   these are (descriptions from RFC 2548):

		00000137	// Vendor-ID = MS
		0E			// Vendor-Type = 14 = MS-Link-Utilization-Threshold
		06			// Vendor-Length = 6
		00000032

		00000137	// Vendor-ID = MS
		0F			// Vendor-Type = 15 = MS-Link-Drop-Time-Limit
		06			// Vendor-Length = 6
		00000078

		00000137	// Vendor-ID = MS
		0A			// Vendor-Type = 10 = MS-CHAP-Domain
		09			// Vendor-Length = 9
		01			// Ident
		524144535256// "RADSRV"

		00000137	// Vendor-ID = MS
		1A			// Vendor-Type = 26 = MS-CHAP2-Success
		2D			// Vendor-Length = 45
		01			// Ident
		533D37313038353845304433463135424637313636423945323032414532343744333844413242343032
					// "S=710858E0D3F15BF7166B9E202AE247D38DA2B402"

		00000137	// Vendor-ID = MS
		10			// Vendor-Type = 16 = MS-MPPE-Send-Key
		34			// Vendor-Length = 52
		801f		// Salt
		3492A5E95CAE75D3167137550766898A3E77BBFF15C46FB5FFFAF758A335CA8E935763ED82CD9441CB0CEA01C01160F0

		00000137	// Vendor-ID = MS
		11			// Vendor-Type = 17 = MS-MPPE-Recv-Key
		34			// Vendor-Length = 52
		8020		// Salt
		C3116680D15E4EFA7D46559AEA387424662C67674A876735BC7CA80A349BE35006F8125157B112C8EACC6015FD0F5D71
	   
	   As with several other security-critical operations, these are all 
	   sent in an unprotected RADIUS message */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_AUTHRESPONSE, 
								TRUE );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}
#endif /* USE_EAP */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
