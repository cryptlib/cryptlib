/****************************************************************************
*																			*
*					cryptlib Session EAP-TLS/TTLS/PEAP Routines				*
*						Copyright Peter Gutmann 2016-2021					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "eap.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "io/eap.h"
#endif /* Compiler-specific includes */

#ifdef USE_EAP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the EAP state */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckNetStreamEAP( IN_PTR const NET_STREAM_INFO *netStream )
	{
	const EAP_INFO *eapInfo = ( EAP_INFO * ) netStream->subTypeInfo;

	assert( isReadPtr( netStream, sizeof( NET_STREAM_INFO ) ) );

	/* Check the network stream state */
	if( !sanityCheckNetStream( netStream ) )
		{
		DEBUG_PUTS(( "sanityCheckNetstreamEAP: netStream" ));
		return( FALSE );
		}

	/* Check RADIUS state information */
	if( eapInfo == NULL )
		{
		DEBUG_PUTS(( "sanityCheckNetstreamEAP: EAP info" ));
		return( FALSE );
		}
	if( !isEnumRangeOpt( eapInfo->radiusType, RADIUS_TYPE ) || \
		eapInfo->radiusLength < 0 || \
		eapInfo->radiusLength > RADIUS_MAX_PACKET_SIZE || \
		eapInfo->radiusCtr < 0 || eapInfo->radiusCtr > 0xFF || \
		eapInfo->radiusStateNonceSize < 0 || \
		eapInfo->radiusStateNonceSize > CRYPT_MAX_HASHSIZE )
		{
		DEBUG_PUTS(( "sanityCheckNetstreamEAP: RADIUS state" ));
		return( FALSE );
		}

	/* Check EAP state information */
	if( !isEnumRangeOpt( eapInfo->eapState, EAP_STATE ) || \
		!isEnumRangeOpt( eapInfo->eapType, EAP_TYPE ) || \
		!isEnumRangeOpt( eapInfo->eapSubtypeRead, EAP_SUBTYPE ) || \
		!isEnumRangeOpt( eapInfo->eapSubtypeWrite, EAP_SUBTYPE ) || \
		!isShortIntegerRange( eapInfo->eapLength ) || \
		!isShortIntegerRange( eapInfo->eapRemainderLength ) || \
		!isFlagRangeZ( eapInfo->eapFlags, EAP ) || \
		eapInfo->eapCtr < 0 || eapInfo->eapCtr > 0xFF )
		{
		DEBUG_PUTS(( "sanityCheckNetstreamEAP: EAP state" ));
		return( FALSE );
		}

	/* Check RADIUS authentication information */
	if( eapInfo->userNameLength < 0 || \
		eapInfo->userNameLength > CRYPT_MAX_TEXTSIZE || \
		eapInfo->passwordLength < 0 || \
		eapInfo->passwordLength > CRYPT_MAX_TEXTSIZE )
		{
		DEBUG_PUTS(( "sanityCheckNetstreamEAP: RADIUS auth info" ));
		return( FALSE );
		}

	/* Check RADIUS metadata information */
	if( eapInfo->extraDataLength < 0 || \
		eapInfo->extraDataLength > MAX_EXTRADATA_SIZE )
		{
		DEBUG_PUTS(( "sanityCheckNetstreamEAP: RADIUS metadata info" ));
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Generate the HMAC-MD5 (!!) hash that's used to "protect" EAP-over-RADIUS 
   messages.  Since HMAC-MD5 isn't used any more and even bare MD5 only 
   exists for its use in TLS 1.0-1.1 we have to synthesise it from raw 
   MD5 */

#define HMAC_BLOCK_SIZE		64
#define HMAC_IPAD			0x36
#define HMAC_OPAD			0x5C

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int radiusMD5MacBuffer( OUT_BUFFER_FIXED( 16 ) BYTE *macValue,
						IN_LENGTH_FIXED( 16 ) const int macLength,
						IN_BUFFER( dataLength ) const void *data,
						IN_LENGTH_SHORT const int dataLength,
						IN_BUFFER( keyDataLength ) const void *keyData, 
						IN_LENGTH_SHORT const int keyDataLength )
	{
	HASH_FUNCTION hashFunction;
	HASHINFO hashInfo;
	BYTE hmacBlockBuffer[ HMAC_BLOCK_SIZE + 8 ];
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	LOOP_INDEX i;
	int hashSize;

	assert( isWritePtrDynamic( macValue, macLength ) );
	assert( isReadPtrDynamic( data, dataLength ) );
	assert( isReadPtrDynamic( keyData, keyDataLength ) );

	REQUIRES( macLength == 16 );
	REQUIRES( isShortIntegerRangeNZ( dataLength ) );
	REQUIRES( isShortIntegerRangeNZ( keyDataLength ) );

	getHashParameters( CRYPT_ALGO_MD5, 0, &hashFunction, &hashSize );

	/* Perform the inner hash */
	memset( hmacBlockBuffer, 0, HMAC_BLOCK_SIZE );
	REQUIRES( rangeCheck( keyDataLength, 1, HMAC_BLOCK_SIZE ) );
	memcpy( hmacBlockBuffer, keyData, keyDataLength );
	LOOP_EXT( i = 0, i < HMAC_BLOCK_SIZE, i++, HMAC_BLOCK_SIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, HMAC_BLOCK_SIZE - 1,
									 HMAC_BLOCK_SIZE + 1 ) );

		hmacBlockBuffer[ i ] ^= HMAC_IPAD;
		}
	ENSURES( LOOP_BOUND_OK );
	hashFunction( hashInfo, NULL, 0, hmacBlockBuffer, HMAC_BLOCK_SIZE, 
				  HASH_STATE_START );
	hashFunction( hashInfo, hashBuffer, hashSize, data, dataLength, 
				  HASH_STATE_END );

	/* Perform the outer hash */
	memset( hmacBlockBuffer, 0, HMAC_BLOCK_SIZE );
	REQUIRES( rangeCheck( keyDataLength, 1, HMAC_BLOCK_SIZE ) );
	memcpy( hmacBlockBuffer, keyData, keyDataLength );
	LOOP_EXT( i = 0, i < HMAC_BLOCK_SIZE, i++, HMAC_BLOCK_SIZE + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, HMAC_BLOCK_SIZE - 1,
									 HMAC_BLOCK_SIZE + 1 ) );

		hmacBlockBuffer[ i ] ^= HMAC_OPAD;
		}
	ENSURES( LOOP_BOUND_OK );
	hashFunction( hashInfo, NULL, 0, hmacBlockBuffer, HMAC_BLOCK_SIZE, 
				  HASH_STATE_START );
	hashFunction( hashInfo, macValue, macLength, hashBuffer, hashSize,
				  HASH_STATE_END );

	zeroise( hmacBlockBuffer, HMAC_BLOCK_SIZE );

	return( CRYPT_OK );
	}

/* As above but not a proper MAC but just a totally insecure hash with the 
   password hashed in at the end */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int radiusMD5HashBuffer( OUT_BUFFER_FIXED( 16 ) BYTE *hashValue,
						 IN_LENGTH_FIXED( 16 ) const int hashLength,
						 IN_BUFFER( dataLength ) const void *data,
						 IN_LENGTH_SHORT const int dataLength,
						 IN_BUFFER( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT const int keyDataLength )
	{
	HASH_FUNCTION hashFunction;
	HASHINFO hashInfo;
	int hashSize;

	assert( isWritePtrDynamic( hashValue, hashLength ) );
	assert( isReadPtrDynamic( data, dataLength ) );
	assert( isReadPtrDynamic( keyData, keyDataLength ) );

	REQUIRES( hashLength == 16 );
	REQUIRES( isShortIntegerRangeNZ( dataLength ) );
	REQUIRES( isShortIntegerRangeNZ( keyDataLength ) );

	getHashParameters( CRYPT_ALGO_MD5, 0, &hashFunction, &hashSize );

	/* Hash the packet data followed by the password.  Note that the hash 
	   value is written back into the data block so we can't clear it like 
	   we'd normally do */
	hashFunction( hashInfo, NULL, 0, data, dataLength, HASH_STATE_START );
	hashFunction( hashInfo, hashValue, hashSize, keyData, keyDataLength, 
				  HASH_STATE_END );

	return( CRYPT_OK );
	}

/* Initialise the RADIUS state info */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initEAPInfo( OUT_PTR EAP_INFO *eapInfo,
						IN_PTR const NET_CONNECT_INFO *connectInfo )
	{
	assert( isWritePtr( eapInfo, sizeof( EAP_INFO ) ) );
	assert( isReadPtr( connectInfo, sizeof( NET_CONNECT_INFO ) ) );

	memset( eapInfo, 0, sizeof( EAP_INFO ) );

	/* Set the RADIUS counter to its maximum value so that it'll roll over 
	   to zero on the first message.  On the EAP side the first message sent
	   is a response (a bizarre side-effect of the fact that RADIUS is a
	   three-party protocol even if it's used as a straight client/server
	   auth mechanism) so it stays at zero */
	eapInfo->radiusCtr = 0xFF;
	eapInfo->eapCtr = 0;

	/* Copy across the RADIUS authentication inforation */
	REQUIRES( rangeCheck( connectInfo->authNameLength, 1, 
						  CRYPT_MAX_TEXTSIZE ) );
	memcpy( eapInfo->userName, connectInfo->authName, 
			connectInfo->authNameLength );
	eapInfo->userNameLength = connectInfo->authNameLength;
	REQUIRES( rangeCheck( connectInfo->authKeyLength, 1, 
						  CRYPT_MAX_TEXTSIZE ) );
	memcpy( eapInfo->password, connectInfo->authKey, 
			connectInfo->authKeyLength );
	eapInfo->passwordLength = connectInfo->authKeyLength;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Display EAP Packet Info							*
*																			*
****************************************************************************/

#ifdef USE_ERRMSGS

/* Get string descriptions of EAP and RADIUS packet types, used for 
   diagnostic error messages */

CHECK_RETVAL_PTR_NONNULL \
const char *getEAPPacketName( IN_BYTE const int packetType )
	{
	static const OBJECT_NAME_INFO packetNameInfo[] = {
		{ EAP_TYPE_REQUEST, "Request" },
		{ EAP_TYPE_RESPONSE, "Response" },
		{ EAP_TYPE_SUCCESS, "Success" },
		{ EAP_TYPE_FAILURE, "Failure" },
		{ EAP_TYPE_INITIATE, "Initiate" },
		{ EAP_TYPE_FINISH, "Finish" },
		{ EAP_TYPE_NONE, "<Unknown type>" },
			{ EAP_TYPE_NONE, "<Unknown type>" }
		};

	REQUIRES_EXT( ( packetType >= 0 && packetType <= 0xFF ),
				  "<Internal error>" );

	return( getObjectName( packetNameInfo,
						   FAILSAFE_ARRAYSIZE( packetNameInfo, \
											   OBJECT_NAME_INFO ),
						   packetType ) );
	}

CHECK_RETVAL_PTR_NONNULL \
const char *getEAPSubtypeName( IN_BYTE const int packetType )
	{
	static const OBJECT_NAME_INFO packetNameInfo[] = {
		{ EAP_SUBTYPE_IDENTITY, "Identity" },
		{ EAP_SUBTYPE_NOTIFICATION, "Notification" },
		{ EAP_SUBTYPE_NAK, "Legacy Nak" },
		{ EAP_SUBTYPE_MD5_CHALLENGE, "MD5-Challenge" },
		{ EAP_SUBTYPE_OTP, "One-Time Password (OTP)" },
		{ EAP_SUBTYPE_GTC, "Generic Token Card (GTC)" },
		{ EAP_SUBTYPE_RSA, "RSA Public Key Authentication" },
		{ EAP_SUBTYPE_DSS, "DSS Unilateral" },
		{ EAP_SUBTYPE_KEA, "KEA" },
		{ EAP_SUBTYPE_KEA_VALIDATE, "KEA-VALIDATE" },
		{ EAP_SUBTYPE_EAP_TLS, "EAP-TLS" },
		{ EAP_SUBTYPE_AXENT, "Defender Token (AXENT)" },
		{ EAP_SUBTYPE_SECURID, "RSA Security SecurID" },
		{ EAP_SUBTYPE_ARCOT, "Arcot Systems" },
		{ EAP_SUBTYPE_CISCO, "Cisco Wireless" },
		{ EAP_SUBTYPE_EAP_SIM, "GSM SIM (EAP-SIM)" },
		{ EAP_SUBTYPE_SRP_SHA1, "SRP-SHA1" },
		{ EAP_SUBTYPE_EAP_TTLS, "EAP-TTLS" },
		{ EAP_SUBTYPE_REMOTEACCESS, "Remote Access Service" },
		{ EAP_SUBTYPE_EAP_AKA, "EAP-AKA Authentication" },
		{ EAP_SUBTYPE_3COM, "EAP-3Com Wireless" },
		{ EAP_SUBTYPE_PEAP, "PEAP" },
		{ EAP_SUBTYPE_MS_EAP, "MS-EAP-Authentication" },
		{ EAP_SUBTYPE_MAKE, "Mutual Authentication w/Key Exchange (MAKE)" },
		{ EAP_SUBTYPE_CRYPTOCARD, "CRYPTOCard" },
		{ EAP_SUBTYPE_EAP_MSCHAPV2, "EAP-MSCHAP-V2" },
		{ EAP_SUBTYPE_DYNAMID, "DynamID" },
		{ EAP_SUBTYPE_ROBEAP, "Rob EAP" },
		{ EAP_SUBTYPE_POTP, "Protected One-Time Password" },
		{ EAP_SUBTYPE_MS_TLV, "MS-Authentication-TLV" },
		{ EAP_SUBTYPE_SENTRINET, "SentriNET" },
		{ EAP_SUBTYPE_ACTIONTEC, "EAP-Actiontec Wireless" },
		{ EAP_SUBTYPE_COGENT, "Cogent Systems Biometrics Authentication" },
		{ EAP_SUBTYPE_AIRFORTRESS, "AirFortress EAP" },
		{ EAP_SUBTYPE_HTTPDIGEST, "EAP-HTTP Digest" },
		{ EAP_SUBTYPE_SECURESUITE, "SecureSuite" },
		{ EAP_SUBTYPE_DEVICECONNECT, "DeviceConnect" },
		{ EAP_SUBTYPE_SPEKE, "EAP-SPEKE" },
		{ EAP_SUBTYPE_MOBAC, "EAP-MOBAC" },
		{ EAP_SUBTYPE_EAP_FAST, "EAP-FAST" },
		{ EAP_SUBTYPE_EAP_ZONELABS, "ZoneLabs EAP (ZLXEAP)" },
		{ EAP_SUBTYPE_EAP_LINK, "EAP-Link" },
		{ EAP_SUBTYPE_EAP_PAX, "EAP-PAX" },
		{ EAP_SUBTYPE_EAP_PSK, "EAP-PSK" },
		{ EAP_SUBTYPE_EAP_SAKE, "EAP-SAKE" },
		{ EAP_SUBTYPE_EAP_IKEV2, "EAP-IKEv2" },
		{ EAP_SUBTYPE_EAP_AKAPLUS, "EAP-AKA'" },
		{ EAP_SUBTYPE_EAP_GPSK, "EAP-GPSK" },
		{ EAP_SUBTYPE_EAP_PWD, "EAP-pwd" },
		{ EAP_SUBTYPE_EAP_EKE, "EAP-EKE " },
		{ EAP_SUBTYPE_PT_EAP, "PT-EAP" },
		{ EAP_SUBTYPE_TEAP, "TEAP" },
		{ EAP_SUBTYPE_NONE, "<Unknown type>" },
			{ EAP_SUBTYPE_NONE, "<Unknown type>" }
		};

	REQUIRES_EXT( ( packetType >= 0 && packetType <= 0xFF ),
				  "<Internal error>" );

	return( getObjectName( packetNameInfo,
						   FAILSAFE_ARRAYSIZE( packetNameInfo, \
											   OBJECT_NAME_INFO ),
						   packetType ) );
	}

CHECK_RETVAL_PTR_NONNULL \
const char *getRADIUSPacketName( IN_BYTE const int packetType )
	{
	static const OBJECT_NAME_INFO packetNameInfo[] = {
		{ RADIUS_TYPE_REQUEST, "Access-Request" },
		{ RADIUS_TYPE_ACCEPT, "Access-Accept" },
		{ RADIUS_TYPE_REJECT, "Access-Reject" },
		{ RADIUS_TYPE_ACC_REQ, "Accounting-Request" },
		{ RADIUS_TYPE_ACC_RESP, "Accounting-Response" },
		{ RADIUS_TYPE_ACC_STATUS, "Accounting-Status" },
		{ RADIUS_TYPE_PW_REQ, "Password-Request" },
		{ RADIUS_TYPE_PW_ACK, "Password-Ack" },
		{ RADIUS_TYPE_PW_REJ, "Password-Reject" },
		{ RADIUS_TYPE_ACC_MSG, "Accounting-Message" },
		{ RADIUS_TYPE_CHALLENGE, "Access-Challenge" },
		{ RADIUS_TYPE_STATUSSVR, "Status-Server" },
		{ RADIUS_TYPE_STATUSCLI, "Status-Client" },
		{ RADIUS_TYPE_FREE_REQ, "Resource-Free-Request" },
		{ RADIUS_TYPE_FREE_RESP, "Resource-Free-Response" },
		{ RADIUS_TYPE_QRY_REQ, "Resource-Query-Request" },
		{ RADIUS_TYPE_QRY_RESP, "Resource-Query-Response" },
		{ RADIUS_TYPE_RECLAIM, "Alternate-Resource-Reclaim-Request" },
		{ RADIUS_TYPE_REBOOT_REQ, "NAS-Reboot-Request" },
		{ RADIUS_TYPE_REBOOT_RESP, "NAS-Reboot-Response" },
		{ RADIUS_TYPE_NEXTPASS, "Next-Passcode" },
		{ RADIUS_TYPE_NEWPIN, "New-Pin" },
		{ RADIUS_TYPE_TERMINATE, "Terminate-Session" },
		{ RADIUS_TYPE_EXPIRED, "Password-Expired" },
		{ RADIUS_TYPE_EVT_REQ, "Event-Request" },
		{ RADIUS_TYPE_EVT_RESP, "Event-Response" },
		{ RADIUS_TYPE_DISCONN_REQ, "Disconnect-Request" },
		{ RADIUS_TYPE_DISCONN_ACK, "Disconnect-ACK" },
		{ RADIUS_TYPE_DISCONN_NAK, "Disconnect-NAK" },
		{ RADIUS_TYPE_COA_REQ, "CoA-Request" },
		{ RADIUS_TYPE_COA_ACK, "CoA-ACK" },
		{ RADIUS_TYPE_COA_NAK, "CoA-NAK" },
		{ RADIUS_TYPE_ADDR_ALLOC, "IP-Address-Allocate" },
		{ RADIUS_TYPE_ADD_RELEASE, "IP-Address-Release" },
		{ RADIUS_TYPE_ERROR, "Protocol-Error" },
		{ RADIUS_TYPE_NONE, "<Unknown type>" },
			{ RADIUS_TYPE_NONE, "<Unknown type>" }
		};

	REQUIRES_EXT( ( packetType >= 0 && packetType <= 0xFF ),
				  "<Internal error>" );

	return( getObjectName( packetNameInfo,
						   FAILSAFE_ARRAYSIZE( packetNameInfo, \
											   OBJECT_NAME_INFO ),
						   packetType ) );
	}

CHECK_RETVAL_PTR_NONNULL \
const char *getRADIUSSubtypeName( IN_BYTE const int packetType )
	{
	static const OBJECT_NAME_INFO packetNameInfo[] = {
		{ RADIUS_SUBTYPE_USERNAME, "User-Name" },
		{ RADIUS_SUBTYPE_PASSWORD, "User-Password" },
		{ RADIUS_SUBTYPE_CHAP, "CHAP-Password" },
		{ RADIUS_SUBTYPE_IPADDRESS, "NAS-IP-Address" },
		{ RADIUS_SUBTYPE_PORT, "NAS-Port" },
		{ RADIUS_SUBTYPE_SERVICETYPE, "Service-Type" },
		{ RADIUS_SUBTYPE_FRAMED_PROTOCOL, "Framed-Protocol" },
		{ RADIUS_SUBTYPE_FRAMED_IPADDRESS, "Framed-IP-Address" },
		{ RADIUS_SUBTYPE_FRAMED_NETMASK, "Framed-IP-Netmask" },
		{ RADIUS_SUBTYPE_FRAMED_ROUTING, "Framed-Routing" },
		{ RADIUS_SUBTYPE_FILTERID, "Filter-Id" },
		{ RADIUS_SUBTYPE_FRAMED_MTU, "Framed-MTU" },
		{ RADIUS_SUBTYPE_FRAMED_COMPRESSION, "Framed-Compression" },
		{ RADIUS_SUBTYPE_LOGIN_IPADDRESS, "Login-IP-Host" },
		{ RADIUS_SUBTYPE_LOGIN_SERVICE, "Login-Service" },
		{ RADIUS_SUBTYPE_LOGIN_PORT, "Login-TCP-Port" },
		{ RADIUS_SUBTYPE_REPLYMESSAGE, "Reply-Message" },
		{ RADIUS_SUBTYPE_CALLBACK_NUMBER, "Callback-Number" },
		{ RADIUS_SUBTYPE_CALLBACK_ID, "Callback-Id" },
		{ RADIUS_SUBTYPE_FRAMED_ROUTE, "Framed-Route" },
		{ RADIUS_SUBTYPE_FRAMED_IPX, "Framed-IPX-Network" },
		{ RADIUS_SUBTYPE_STATE, "State" },
		{ RADIUS_SUBTYPE_CLASS, "Class" },
		{ RADIUS_SUBTYPE_VENDORSPECIFIC, "Vendor-Specific" },
		{ RADIUS_SUBTYPE_SESSIONTIMEOUT, "Session-Timeout" },
		{ RADIUS_SUBTYPE_IDLETIMEOUT, "Idle-Timeout" },
		{ RADIUS_SUBTYPE_TERMINATION, "Termination-Action" },
		{ RADIUS_SUBTYPE_CALLED_STATIONID, "Called-Station-Id" },
		{ RADIUS_SUBTYPE_CALLING_STATIONID, "Calling-Station-Id" },
		{ RADIUS_SUBTYPE_NAS_IDENTIFIER, "NAS-Identifier" },
		{ RADIUS_SUBTYPE_PROXYSTATE, "Proxy-State" },
		{ RADIUS_SUBTYPE_LOGIN_LATSERVICE, "Login-LAT-Service" },
		{ RADIUS_SUBTYPE_LOGIN_LATNODE, "Login-LAT-Node" },
		{ RADIUS_SUBTYPE_LOGIN_LATGROUP, "Login-LAT-Group" },
		{ RADIUS_SUBTYPE_FRAMED_APPLETALKLINK, "Framed-AppleTalk-Link" },
		{ RADIUS_SUBTYPE_FRAMED_APPLETALKNETWORK, "Framed-AppleTalk-Network" },
		{ RADIUS_SUBTYPE_FRAMED_APPLETALK_ZONE, "Framed-AppleTalk-Zone" },
		{ RADIUS_SUBTYPE_ACCT_STATUS, "Acct-Status-Type" },
		{ RADIUS_SUBTYPE_ACCT_DELAYTIME, "Acct-Delay-Time" },
		{ RADIUS_SUBTYPE_ACCT_INPUT, "Acct-Input-Octets" },
		{ RADIUS_SUBTYPE_ACCT_OUTPUT, "Acct-Output-Octets" },
		{ RADIUS_SUBTYPE_ACCT_ID, "Acct-Session-Id" },
		{ RADIUS_SUBTYPE_ACCT_AUTHENTIC, "Acct-Authentic" },
		{ RADIUS_SUBTYPE_ACCT_TIME, "Acct-Session-Time" },
		{ RADIUS_SUBTYPE_ACCT_INPUTPACKETS, "Acct-Input-Packets" },
		{ RADIUS_SUBTYPE_ACCT_OUTPUTPACKETS, "Acct-Output-Packets" },
		{ RADIUS_SUBTYPE_ACCT_CAUSE, "Acct-Terminate-Cause" },
		{ RADIUS_SUBTYPE_ACCT_MULTISESSIONID, "Acct-Multi-Session-Id" },
		{ RADIUS_SUBTYPE_ACCT_LINKCOUNT, "Acct-Link-Count" },
		{ RADIUS_SUBTYPE_ACCT_INPUTGIGAWORDS, "Acct-Input-Gigawords" },
		{ RADIUS_SUBTYPE_ACCT_OUTPUTGIGAWORDS, "Acct-Output-Gigawords" },
		{ RADIUS_SUBTYPE_ACCT_EVENTTIME, "Event-Timestamp" },
		{ RADIUS_SUBTYPE_EGRESSVLANID, "Egress-VLANID" },
		{ RADIUS_SUBTYPE_INGRESSFILTERS, "Ingress-Filters" },
		{ RADIUS_SUBTYPE_EGRESSVLANNAME, "Egress-VLAN-Name" },
		{ RADIUS_SUBTYPE_USERPRIORITY, "User-Priority-Table" },
		{ RADIUS_SUBTYPE_CHAPCHALLENGE, "CHAP-Challenge" },
		{ RADIUS_SUBTYPE_PORTTYPE, "NAS-Port-Type" },
		{ RADIUS_SUBTYPE_PORTLIMIT, "Port-Limit" },
		{ RADIUS_SUBTYPE_LOGINPORT, "Login-LAT-Port" },
		{ RADIUS_SUBTYPE_TUNNEL_TYPE, "Tunnel-Type" },
		{ RADIUS_SUBTYPE_TUNNEL_MEDIUMTYPE, "Tunnel-Medium-Type" },
		{ RADIUS_SUBTYPE_TUNNEL_CLIENTENDPOINT, "Tunnel-Client-Endpoint" },
		{ RADIUS_SUBTYPE_TUNNEL_SERVERENDPOINT, "Tunnel-Server-Endpoint" },
		{ RADIUS_SUBTYPE_ACCT_TUNNEL_CONNECTION, "Acct-Tunnel-Connection" },
		{ RADIUS_SUBTYPE_TUNNEL_PASSWORD, "Tunnel-Password" },
		{ RADIUS_SUBTYPE_ARAP_PASSWORD, "ARAP-Password" },
		{ RADIUS_SUBTYPE_ARAP_FEATURES, "ARAP-Features" },
		{ RADIUS_SUBTYPE_ARAP_ZONE, "ARAP-Zone-Access" },
		{ RADIUS_SUBTYPE_ARAP_SECURITY, "ARAP-Security" },
		{ RADIUS_SUBTYPE_ARAP_SECURITYDATA, "ARAP-Security-Data" },
		{ RADIUS_SUBTYPE_PASSWORDRETRY, "Password-Retry" },
		{ RADIUS_SUBTYPE_PROMPT, "Prompt" },
		{ RADIUS_SUBTYPE_CONNECTINFO, "Connect-Info" },
		{ RADIUS_SUBTYPE_CONFIGTOKEN, "Configuration-Token" },
		{ RADIUS_SUBTYPE_EAPMESSAGE, "EAP-Message" },
		{ RADIUS_SUBTYPE_MESSAGEAUTH, "Message-Authenticator" },
		{ RADIUS_SUBTYPE_TUNNEL_GROUPID, "Tunnel-Private-Group-ID" },
		{ RADIUS_SUBTYPE_TUNNEL_ASSIGNMENT, "Tunnel-Assignment-ID" },
		{ RADIUS_SUBTYPE_TUNNEL_PREFERENCE, "Tunnel-Preference" },
		{ RADIUS_SUBTYPE_ARAP_CHALLRESP, "ARAP-Challenge-Response" },
		{ RADIUS_SUBTYPE_ACCT_INTERVAL, "Acct-Interim-Interval" },
		{ RADIUS_SUBTYPE_ACCT_PACKETSLOST, "Acct-Tunnel-Packets-Lost" },
		{ RADIUS_SUBTYPE_PORTID, "NAS-Port-Id" },
		{ RADIUS_SUBTYPE_FRAMED_POOL, "Framed-Pool" },
		{ RADIUS_SUBTYPE_CUI, "CUI" },
		{ RADIUS_SUBTYPE_TUNNEL_CLIENTAUTH, "Tunnel-Client-Auth-ID" },
		{ RADIUS_SUBTYPE_TUNNEL_SERVERAUTH, "Tunnel-Server-Auth-ID" },
		{ RADIUS_SUBTYPE_NAS_FILTER_RULE, "NAS-Filter-Rule" },
		{ RADIUS_SUBTYPE_ORIG_LINE_INFO, "Originating-Line-Info" },
		{ RADIUS_SUBTYPE_NAS_IPV6_ADDR, "NAS-IPv6-Address" },
		{ RADIUS_SUBTYPE_FRAMED_INTERFACE, "Framed-Interface-Id" },
		{ RADIUS_SUBTYPE_FRAMED_IPV6_PREFIX, "Framed-IPv6-Prefix" },
		{ RADIUS_SUBTYPE_LOGIN_IPV6_HOST, "Login-IPv6-Host" },
		{ RADIUS_SUBTYPE_FRAMED_IPV6_ROUTE, "Framed-IPv6-Route" },
		{ RADIUS_SUBTYPE_FRAMED_IPV6_POOL, "Framed-IPv6-Pool" },
		{ RADIUS_SUBTYPE_ERROR_CAUSE, "Error-Cause Attribute" },
		{ RADIUS_SUBTYPE_EAP_KEYNAME, "EAP-Key-Name" },
		{ RADIUS_SUBTYPE_DIGEST_RESPONSE, "Digest-Response" },
		{ RADIUS_SUBTYPE_DIGEST_REALM, "Digest-Realm" },
		{ RADIUS_SUBTYPE_DIGEST_NONE, "Digest-Nonce" },
		{ RADIUS_SUBTYPE_DIGEST_RESPONSE_AUTH, "Digest-Response-Auth" },
		{ RADIUS_SUBTYPE_DIGEST_NEXTNONE, "Digest-Nextnonce" },
		{ RADIUS_SUBTYPE_DIGEST_METHOD, "Digest-Method" },
		{ RADIUS_SUBTYPE_DIGEST_URI, "Digest-URI" },
		{ RADIUS_SUBTYPE_DIGEST_QOP, "Digest-Qop" },
		{ RADIUS_SUBTYPE_DIGEST_ALGO, "Digest-Algorithm" },
		{ RADIUS_SUBTYPE_DIGEST_BODYHASH, "Digest-Entity-Body-Hash" },
		{ RADIUS_SUBTYPE_DIGEST_CNONCE, "Digest-CNonce" },
		{ RADIUS_SUBTYPE_DIGEST_NONCECT, "Digest-Nonce-Count" },
		{ RADIUS_SUBTYPE_DIGEST_USERNAME, "Digest-Username" },
		{ RADIUS_SUBTYPE_DIGEST_OPAQUE, "Digest-Opaque" },
		{ RADIUS_SUBTYPE_DIGEST_AUTHPARAM, "Digest-Auth-Param" },
		{ RADIUS_SUBTYPE_DIGEST_AKAAUTS, "Digest-AKA-Auts" },
		{ RADIUS_SUBTYPE_DIGEST_DOMAIN, "Digest-Domain" },
		{ RADIUS_SUBTYPE_DIGEST_STALE, "Digest-Stale" },
		{ RADIUS_SUBTYPE_DIGEST_HA1, "Digest-HA1" },
		{ RADIUS_SUBTYPE_DIGEST_SIPAOR, "SIP-AOR" },
		/* Another hundred-odd types, not listed here */
		{ RADIUS_SUBTYPE_NONE, "<Unknown type>" },
			{ RADIUS_SUBTYPE_NONE, "<Unknown type>" }
		};

	REQUIRES_EXT( ( packetType >= 0 && packetType <= 0xFF ),
				  "<Internal error>" );

	return( getObjectName( packetNameInfo,
						   FAILSAFE_ARRAYSIZE( packetNameInfo, \
											   OBJECT_NAME_INFO ),
						   packetType ) );
	}
#endif /* USE_ERRMSGS */

/****************************************************************************
*																			*
*								EAP Handshake Functions						*
*																			*
****************************************************************************/

/* The size of the buffer used to process the initial RADIUS ping */

#define RADIUS_BUFFER_SIZE			256

/* Activate an EAP client session */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int activateEAPClient( INOUT_PTR STREAM *stream,
							  IN_PTR const NET_CONNECT_INFO *connectInfo )
	{
	static const MAP_TABLE subProtocolMapTable[] = {
		{ CRYPT_SUBPROTOCOL_EAPTTLS, EAP_SUBTYPE_EAP_TTLS },
		{ CRYPT_SUBPROTOCOL_PEAP, EAP_SUBTYPE_PEAP },
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	EAP_INFO *eapInfo;
	EAP_PARAMS eapParams;
	STREAM radiusStream;
	BYTE buffer[ RADIUS_BUFFER_SIZE + 8 ];
	int bytesCopied, eapSubType, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( connectInfo, sizeof( NET_CONNECT_INFO ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStreamEAP( netStream ) );

	/* Initialise the EAP state information */
	eapInfo = ( EAP_INFO * ) netStream->subTypeInfo;
	status = initEAPInfo( eapInfo, connectInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Send the RADIUS packet containing the request to trigger the 
	   EAP-TLS/TTLS/PEAP response, an EAP_SUBTYPE_IDENTITY packet containing 
	   the user name as payload.  Because only the server is allowed to
	   send requests, our request is encoded as a response to an imaginary
	   request from the server */
	DEBUG_PRINT(( "Connecting to RADIUS server with username = '%s', "
				  "password = '%s'\n", eapInfo->userName, 
				  eapInfo->password ));
	setEAPParams( &eapParams, EAP_TYPE_RESPONSE, EAP_SUBTYPE_IDENTITY );
#ifdef USE_ANONYMOUS_ID
	if( netStream->subProtocol == CRYPT_SUBPROTOCOL_PEAP )
		{
		/* PEAP sends the identity inside the TLS tunnel, so we give our
		   identity at the RADIUS level as "anonymous".  How the server
		   generates a Message-Authenticator without any identity to bind it
		   to is a mystery, but RFC 2865 suggests that "The source IP 
		   address of the Access-Request packet MUST be used to select the 
		   shared secret", so presumably that's recorded somewhere as it
		   passes through RADIUS proxies and tunnels and whatnot */
		status = writeRADIUSMessage( stream, eapInfo, &eapParams,
									 "anonymous", 9 );
		}
	else
#endif /* USE_ANONYMOUS_ID */
		{
		status = writeRADIUSMessage( stream, eapInfo, &eapParams,
									 eapInfo->userName, 
									 eapInfo->userNameLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the server's EAP-TLS/TTLS/PEAP authentication response.  As per
	   the previous comment, the server sends requests, not responses, so 
	   what we're reading is encoded as a request even though it's a 
	   response */
	status = readRADIUSMessage( stream, eapInfo, FALSE );
	if( cryptStatusError( status ) )
		return( status );
	if( eapInfo->radiusLength <= 0 )
		{
		/* The server sent back an empty response that we can't do anything 
		   with.  This will typically be an Access-Reject in response to a
		   malformed message, in other words a generic error response, so we
		   report it as an Access-Reject */
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, NETSTREAM_ERRINFO, 
				  "Server responded with a generic error response in the "
				  "form of a RADIUS Access-Reject message" ) );
		}
	sMemConnect( &radiusStream, stream->buffer, eapInfo->radiusLength );
	status = processRADIUSTLVs( &radiusStream, eapInfo, buffer, RADIUS_BUFFER_SIZE, 
								&bytesCopied, NETSTREAM_ERRINFO );
	sMemDisconnect( &radiusStream );
	if( cryptStatusError( status ) )
		return( status );

	/* If the server responded with the protocol that we're expecting, we're
	   done */
	status = mapValue( netStream->subProtocol, &eapSubType, 
					   subProtocolMapTable,
					   FAILSAFE_ARRAYSIZE( subProtocolMapTable, \
										   MAP_TABLE ) );
	if( cryptStatusOK( status ) && eapSubType == eapInfo->eapSubtypeRead )
		{
		eapInfo->eapSubtypeWrite = eapInfo->eapSubtypeRead;
		return( CRYPT_OK );
		}
	DEBUG_PRINT(( "Server offered %s (%d) when we wanted %s (%d), retrying "
				  "with explicit request for %s.\n", 
				  getEAPSubtypeName( eapInfo->eapSubtypeRead ), 
					eapInfo->eapSubtypeRead,
				  getEAPSubtypeName( eapSubType ), eapSubType,
					getEAPSubtypeName( eapSubType ) ));

	/* The server responded with something other than what we're expecting, 
	   send an EAP NAK requesting the protocol that we want and retry the 
	   read of the resonse */
	setEAPParamsExt( &eapParams, EAP_TYPE_RESPONSE, EAP_SUBTYPE_NAK, 
					 eapSubType );
	status = writeRADIUSMessage( stream, eapInfo, &eapParams,
								 eapInfo->userName, eapInfo->userNameLength );
	if( cryptStatusError( status ) )
		return( status );
	status = readRADIUSMessage( stream, eapInfo, FALSE );
	if( cryptStatusError( status ) )
		return( status );
	if( eapInfo->radiusLength <= 0 )
		{
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, NETSTREAM_ERRINFO, 
				  "Server responded with a generic error response in the "
				  "form of a RADIUS Access-Reject message" ) );
		}
	sMemConnect( &radiusStream, stream->buffer, eapInfo->radiusLength );
	status = processRADIUSTLVs( &radiusStream, eapInfo, buffer, RADIUS_BUFFER_SIZE, 
								&bytesCopied, NETSTREAM_ERRINFO );
	sMemDisconnect( &radiusStream );
	if( cryptStatusError( status ) )
		return( status );

	/* See if we got what we're after */
	if( eapSubType != eapInfo->eapSubtypeRead )
		{
		if( eapInfo->eapSubtypeRead == 0 )
			{
			/* Windows NPS can send subtype 0 at the EAP level when there's 
			   a problem at the RADIUS level so we have to use a special-
			   case error message in this case */
			retExt( CRYPT_ERROR_NOTAVAIL,
					( CRYPT_ERROR_NOTAVAIL, NETSTREAM_ERRINFO, 
					  "Server reported an empty EAP subtype, this may be "
					  "because of a problem at the RADIUS level" ) );
			}
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, NETSTREAM_ERRINFO, 
				  "Requested EAP subtype %s (%d) but server only allows "
				  "subtype %s (%d)", 
				  getEAPSubtypeName( eapSubType ), eapSubType,
				  getEAPSubtypeName( eapInfo->eapSubtypeRead ), 
					eapInfo->eapSubtypeRead ) );
		}
	eapInfo->eapSubtypeWrite = eapInfo->eapSubtypeRead;
	DEBUG_PRINT(( "Successfully negotiated %s (%d) with server.\n", 
				  getEAPSubtypeName( eapSubType ), eapSubType ));

	return( status );
	}

/* Activate an EAP server  session */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int activateEAPServer( INOUT_PTR STREAM *stream,
							  IN_PTR const NET_CONNECT_INFO *connectInfo )
	{
	static const MAP_TABLE subProtocolMapTable[] = {
		{ CRYPT_SUBPROTOCOL_EAPTTLS, EAP_SUBTYPE_EAP_TTLS },
		{ CRYPT_SUBPROTOCOL_PEAP, EAP_SUBTYPE_PEAP },
		{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
		};
	NET_STREAM_INFO *netStream = DATAPTR_GET( stream->netStream );
	EAP_INFO *eapInfo;
	EAP_PARAMS eapParams;
	STREAM radiusStream;
	BYTE buffer[ RADIUS_BUFFER_SIZE + 8 ];
	int bytesCopied, eapSubType, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( connectInfo, sizeof( NET_CONNECT_INFO ) ) );

	REQUIRES( netStream != NULL && sanityCheckNetStreamEAP( netStream ) );

	/* Map the cryptlib-level subprotocol value to an EAP-level one */
	status = mapValue( netStream->subProtocol, &eapSubType, 
					   subProtocolMapTable,
					   FAILSAFE_ARRAYSIZE( subProtocolMapTable, \
										   MAP_TABLE ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Initialise the EAP state information.  The first message from the 
	   client is a dummy wakeup packet so we remember to treat it
	   specially */
	eapInfo = ( EAP_INFO * ) netStream->subTypeInfo;
	status = initEAPInfo( eapInfo, connectInfo );
	if( cryptStatusError( status ) )
		return( status );
	eapInfo->eapSubtypeRead = eapInfo->eapSubtypeWrite = eapSubType;
	eapInfo->eapFlags |= EAP_FLAG_CLIENTWAKEUP;

	/* Read the client's EAP-TLS/TTLS/PEAP wakeup packet, an Identity 
	   Response to a request that we never sent */
	status = readRADIUSMessage( stream, eapInfo, TRUE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &radiusStream, stream->buffer, eapInfo->radiusLength );
	status = processRADIUSTLVs( &radiusStream, eapInfo, buffer, 
								RADIUS_BUFFER_SIZE, &bytesCopied, 
								NETSTREAM_ERRINFO );
	sMemDisconnect( &radiusStream );
	if( cryptStatusError( status ) )
		return( status );
	eapInfo->eapFlags &= ~EAP_FLAG_CLIENTWAKEUP;

	/* Respond with our Access Challenge, which starts the TLS setup */
	setEAPParams( &eapParams, EAP_TYPE_REQUEST, eapSubType );
	eapParams.paramOpt = EAPTLS_FLAG_START;
	return( writeRADIUSMessage( stream, eapInfo, &eapParams,
								RADIUS_DATA_CHALLENGE, 
								RADIUS_DATA_CHALLENGE_LEN ) );
	}

/****************************************************************************
*																			*
*							EAP Access Functions							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerEAP( INOUT_PTR NET_STREAM_INFO *netStream )
	{
	assert( isWritePtr( netStream, sizeof( NET_STREAM_INFO ) ) );

	/* Set the access method pointers */
	if( TEST_FLAG( netStream->nFlags, STREAM_NFLAG_ISSERVER ) )
		{
		FNPTR_SET( netStream->connectFunctionOpt, activateEAPServer );
		}
	else
		{
		FNPTR_SET( netStream->connectFunctionOpt, activateEAPClient );
		}
	setStreamLayerEAPread( netStream );
	setStreamLayerEAPwrite( netStream );

	/* EAP provides its own data-size and flow-control indicators so we
	   don't want the higher-level code to try and do this for us */
	SET_FLAG( netStream->nFlags, STREAM_NFLAG_ENCAPS );
	}
#endif /* USE_EAP */
