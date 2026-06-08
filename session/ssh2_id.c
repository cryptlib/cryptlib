/****************************************************************************
*																			*
*						cryptlib SSHv2 SSH ID Management					*
*						Copyright Peter Gutmann 1998-2026					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH

/* Although SSH ID strings are defined in RFC 4253 section 4.2 "Protocol 
   Version Exchange" as "SSH-protoversion-softwareversion SP comments CR LF"
   with protoversion being "2.0", in practice it's a complete free-for-all
   with anything being possible.  For example the RFC says:

	If the 'comments' string is included, a 'space' character (denoted above 
	as SP, ASCII 32) MUST separate the 'softwareversion' and 'comments' 
	strings. 

   (only a dash is valid as a delimiter) but in practice a space is more 
   likely to be part of the softwareversion than an indicator of a comment 
   to follow.  Having said that the RFC then contradicts itself with:
   
	Both the 'protoversion' and 'softwareversion' strings MUST consist of
	printable US-ASCII characters, with the exception of whitespace
	characters and the minus sign (-)

   making it impossible to tell what's a comment and what isn't.

   In general though there are three formats:
   
	The original ssh.com interpretation "SSH-2.0-x.y vendorname", for
	example "SSH-2.0-3.0.0 SSH Secure Shell".
	
	Most other implementations that include versions, 
	"SSH-2.0-vendorname_version", for example "SSH-2.0-OpenSSH_3.0"
	(a few have a space instead of an underscore, e.g. Mocana).
	
	A free-form text string, including complete gibberish like "SSH-2.0--"
	and "SSH-2.0-X", but more typically either a vendor name with no version
	number or some user-selected string that should be in a banner, for 
	example "SSH-2.0-You are connected Nissan Cleo [...]".

   We handle all three, except for the extremely broken ones in the third
   class like "SSH-2.0--".
	
   The vendors that we recognise are as follows, these aren't necessarily 
   ones that need special handling but just some of the ones that we've 
   encountered in the past that we ID here in case it's needed in the 
   future */

typedef enum {
	SSH_VENDOR_NONE,					/* No vendor type */
	SSH_VENDOR_ALLEGRO,					/* Allegro */
	SSH_VENDOR_AZURESSH,				/* AzureSSH */
	SSH_VENDOR_BITVISE,					/* BitVise */
	SSH_VENDOR_CERBERUS,				/* Cerberus */
	SSH_VENDOR_CHILKAT,					/* Chilkat */
	SSH_VENDOR_CISCO,					/* Cisco */
	SSH_VENDOR_CRUSHFTP,				/* CrushFTP */
	SSH_VENDOR_CRYPTLIB,				/* cryptlib */
	SSH_VENDOR_CUTEFTP,					/* CuteFTP */
	SSH_VENDOR_DROPBEAR,				/* Dropbear */
	SSH_VENDOR_JSCAPE,					/* JSCAPE */
	SSH_VENDOR_LIBSSH,					/* libssh */
	SSH_VENDOR_MOBAXTERM,				/* MobaXTerm */
	SSH_VENDOR_MOCANA,					/* Mocana */
	SSH_VENDOR_NETAPP,					/* NetApp */
	SSH_VENDOR_OPENSSH,					/* OpenSSH */
	SSH_VENDOR_PROFTPD,					/* ProFTPD */
	SSH_VENDOR_PUTTY,					/* Putty */
	SSH_VENDOR_REBEX,					/* Rebex */
	SSH_VENDOR_RSSBUS,					/* RSSBus */
	SSH_VENDOR_SSHCOM,					/* ssh.com */
	SSH_VENDOR_SOLARWINDS,				/* SolarWinds */
	SSH_VENDOR_SYSAX,					/* Sysax */
	SSH_VENDOR_TECTIA,					/* Tectia */
	SSH_VENDOR_TELDAT,					/* Teldat */
	SSH_VENDOR_VANDYKE,					/* Van Dyke */
	SSH_VENDOR_VXWORKS,					/* VxWorks */
	SSH_VENDOR_WEONLYDO,				/* WeOnlyDo */
	SSH_VENDOR_WSFTP,					/* WS_FTP */
	SSH_VENDOR_LAST						/* Last possible vendor type */
	} SSH_VENDOR_TYPE;

/* Flags that control parsing of the SSH ID string:

	VENDORFLAG_NO_VERSION: No version number in the ID string, don't try to
		parse out a version number */

#define SSH_VENDORFLAG_NONE		0x00	/* No parsing-control flag */
#define SSH_VENDORFLAG_NO_VERSION 0x01	/* No version number */
#define SSH_VENDORFLAG_LAST		0x01	/* Maximum possible flag value */

/* A structure to hold the information on each vendor.  The debugText field 
  isn't used in error messages but is enabled if their use is defined 
  because of the way the DESCRIPTION() macro that sets it works  */

typedef struct {
	BUFFER_FIXED( vendorNameLen ) \
	const char *vendorName;				/* Vendor name string */
	const int vendorNameLen;
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	const char *debugText;
#endif /* USE_ERRMSGS || !NDEBUG */
	const SSH_VENDOR_TYPE vendorType;	/* Vendor type value */
	const int flags;					/* Parsing-control flags */
	} VENDOR_INFO;

/* The parsed information for a vendor that we recognise.  We need to do the
   stepping for implementations like the ssh.com one which were at 2.x for
   more than a decade, so the version 2.minor.stepping is actually 
   [x].major.minor */

typedef struct {
	SSH_VENDOR_TYPE vendorType;			/* Vendor ID and version info */
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	const char *vendorName;
#endif /* USE_ERRMSGS || !NDEBUG */
	int majorVersion, minorVersion, stepping;
	int vendorInfoEnd;					/* End of vendor info in string */
	} VERSION_INFO;

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check for and process a pre-authentication value attached to the SSH 
   version string.  The processing is as follows:

	Server sent		Got back	Action
	-----------		--------	------
		-				-		Skip				(A)
		-				R		Skip				(B)
		C				-		Error				(C)
		C				R		Require R = valid	(D)
		
	Client received
	---------------
		-						Skip				(E)
		C, invalid				Non-fatal CRYPT_ERROR_BADDATA (F)
		C, valid				Respond with R		(G) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkPreAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo,
						 IN_BUFFER( versionStringLength ) \
							const char *versionString, 
						 IN_LENGTH_SHORT_Z const int versionStringLength )
	{
	const char *preAuthValue;
#ifdef USE_ERRMSGS
	const char *peerType = isServer( sessionInfoPtr ) ? "Client" : "Server";
#endif /* USE_ERRMSGS */
	int preAuthPosition DUMMY_INIT, preAuthLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( versionStringLength == 0 || \
			isReadPtr( versionString, versionStringLength ) );

	REQUIRES( isShortIntegerRange( versionStringLength ) );
			  /* May be zero if no further data present beyond the vendor ID */

	/* If we're the server and didn't send a pre-authentication challenge
	   to the client then there's nothing to do (A, B) */
	if( isServer( sessionInfoPtr ) && handshakeInfo->challengeLength <= 0 )
		return( CRYPT_OK );

	/* Check for a pre-authentication challenge or response */
	if( versionStringLength < 3 + SSH_PREAUTH_NONCE_ENCODEDSIZE )
		status = CRYPT_ERROR_NOTFOUND;
	else
		{
		status = preAuthPosition = \
				strFindStr( versionString, versionStringLength, 
							isServer( sessionInfoPtr ) ? " R=" : " C=", 3 );
		}
	if( cryptStatusError( status ) )
		{
		/* If we're the client then the server didn't send us a pre-
		   authentication challenge, there's nothing to do (E) */
		if( !isServer( sessionInfoPtr ) )
			return( CRYPT_OK );

		/* We're the server, the client should have sent a response to our
		   challenge (C) */
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Client didn't respond to our pre-authentication "
				  "challenge" ) );
		}

	/* Make sure that the pre-authentication value looks valid.  We don't do 
	   anything with the decoded value since we work with the encoded form, 
	   it's just used as a check for valid data:

							 preAuthValue
	   versionString   preAuthPos |		remValue
			|				|	  | 		|
			+---------------+---------------+-----------+
			|				|" X="			|",Y="		|
			+---------------+---------------+-----------+
								  |<------------------->| preAuthLen
								  |<------->|<--------->|
								  preAuthLen'	remLen 
								  
	    The preAuthLen is initially the remaining string data starting from
	    the preAuthValue and is then trimmed to just the preAuth data 
	    itself */
	REQUIRES( !checkOverflowAdd( preAuthPosition, 3 ) );
	REQUIRES( !checkOverflowSub( versionStringLength, 
								 preAuthPosition + 3 ) );
	preAuthValue = versionString + preAuthPosition + 3;
	preAuthLength = versionStringLength - ( preAuthPosition + 3 );
	if( !isShortIntegerRangeMin( preAuthLength, 
								 SSH_PREAUTH_NONCE_ENCODEDSIZE ) )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		BYTE buffer[ SSH_PREAUTH_MAX_SIZE + 8 ];
		int length;

		status = base64decode( buffer, SSH_PREAUTH_MAX_SIZE, &length, 
							   preAuthValue, SSH_PREAUTH_NONCE_ENCODEDSIZE, 
							   CRYPT_CERTFORMAT_NONE );
		}
	if( cryptStatusOK( status ) && \
		preAuthLength > SSH_PREAUTH_NONCE_ENCODEDSIZE )
		{
		const int remainderLength = \
						preAuthLength - SSH_PREAUTH_NONCE_ENCODEDSIZE;
		const char *remainderValue = \
						preAuthValue + SSH_PREAUTH_NONCE_ENCODEDSIZE;

		REQUIRES( !checkOverflowSub( preAuthLength, 
									 SSH_PREAUTH_NONCE_ENCODEDSIZE ) );

		/* There's more data following the pre-authentication value, check 
		   that it follows the form ',X=...' to match the general pattern
		   'C=abcdefg,X=....,Y=.....' */
		if( !isShortIntegerRangeMin( remainderLength, 4 ) || \
			remainderValue[ 0 ] != ',' || !isAlpha( remainderValue[ 1 ] ) || \
			remainderValue[ 2 ] != '=' )
			status = CRYPT_ERROR_BADDATA;
		else
			{
			/* The extra data that follows the pre-authentication value 
			   looks OK, what's present before it must be the fixed-length 
			   preAuth data */
			preAuthLength = SSH_PREAUTH_NONCE_ENCODEDSIZE;
			}
		}
	if( cryptStatusError( status ) )
		{
		/* If we're the client and the server sent us an invalid-looking 
		   challenge then, because of the free-for-all in SSH version
		   strings, we can't automatically hard-fail because it could be 
		   some random thing a vendor has stuffed in there.  Because of this
		   we skip the challenge, the server won't let us continue if it
		   was a legitimate but malformed challenge (F) */
		if( !isServer( sessionInfoPtr ) )
			{
			DEBUG_PRINT(( "Server sent invalid preauth string '%s'.\n",
						  versionString ));
			return( CRYPT_OK );
			}
			
		if( preAuthLength <= 0 )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "%s sent empty pre-authentication value", 
					  peerType ) );
			}
		retExtSan( CRYPT_ERROR_BADDATA,
				   ( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					 "%s sent invalid pre-authentication value '%s'", 
					 peerType, 0, preAuthValue, preAuthLength, NULL, 0 ) );
		}

	/* Remember the challenge or response.  The server records the value as
	   receivedResponse for later comparison with the locally computed
	   response value.
	   
	   The following precondition is part-tautology but is present to 
	   document the requirements for the memory move (D, G) */
	REQUIRES( preAuthLength == SSH_PREAUTH_NONCE_ENCODEDSIZE && \
			  SSH_PREAUTH_NONCE_ENCODEDSIZE <= SSH_PREAUTH_MAX_SIZE );
	if( isServer( sessionInfoPtr ) )
		{
		memcpy( handshakeInfo->receivedResponse, preAuthValue, 
				SSH_PREAUTH_NONCE_ENCODEDSIZE );
		handshakeInfo->receivedResponseLength = SSH_PREAUTH_NONCE_ENCODEDSIZE;
		}
	else
		{
		memcpy( handshakeInfo->challenge, preAuthValue, 
				SSH_PREAUTH_NONCE_ENCODEDSIZE );
		handshakeInfo->challengeLength = SSH_PREAUTH_NONCE_ENCODEDSIZE;
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read an SSH ID								*
*																			*
****************************************************************************/

/* Read an SSH ID string with optional pre-authentication value.  This 
   identifies implementations that require special-case bug workarounds.  To 
   find out what a server is running:

	nmap -sV -p 22 <server_address>

   The versions that we check for are:

	AzureSSH: Sends SSH_MSG_EXT_INFO messages containing zero extensions, 
		and quite probably has numerous other bugs since it's an SSH that 
		Microsoft created themselves.

	BitVise WinSSHD:
		This one is hard to identify because it's built on top of their SSH 
		library and keeps changing names:
		
		WinSSHD version		ID string
		---------------		---------
			 3, 4			"sshlib: WinSSHD 3/4.yy"
				5			"FlowSsh: WinSSHD 5.xx"
			 6, 7			"FlowSsh: Bitvise SSH Server (WinSSHD) 6/7.xx"

		In theory we could handle this by skipping the library name and 
		looking further inside the string for the "WinSSHD" identifier, but 
		then there's another version that uses "SrSshServer" instead of 
		"WinSSHD", and there's also a "GlobalScape" ID used by CuteFTP 
		(which means that CuteFTP might have finally fixed their buggy 
		implementation of SSH by using someone else's).  As a result we can 
		see any of "sshlib: <vendor>" or "FlowSsh: <vendor>", which we use 
		as the identifier.
			
		Sends mismatched compression algorithm IDs, no compression client -> 
		server, zlib server -> client, but works fine if no compression is 
		selected, for versions 4.x and up.

		Doesn't support any MTI encryption algorithms in the default config 
		for versions 5.35 and up (!!).

	Cerberus FTP:
		Another difficult-to-ID one, this is an FTP server with SFTP 
		capabilities that identifies itself using the near-anonymous ID 
		"SshServer", alongside the actually-useful "CerberusFTPServer".

	Chilkat sFTP:
		Yet another difficult-to-ID one, this time it's "FTP Server ready".
		Instantly fails the handshake if it sees SSH_MSG_KEY_DH_GEX_REQUEST
		rather than SSH_MSG_KEX_DH_GEX_REQUEST_OLD from 20-odd years ago 
		(and it also does blowfish, 3des, rsa1024-sha1, hmac-ripemd160, and 
		a bunch of others).

	CrushFTP:
		Java-based FTP server using J2SSH-Maverick from Jadaptive, a fork of 
		the abandoned J2SSH, identified as either "CrushFTPSSHD" or 
		"J2SSH_Maverick", but also "Maverick_SSHD" in newer versions.
			
		Advertises support for SSH_MSG_EXT_INFO but drops the connection 
		when it gets an actual SSH_MSG_EXT_INFO from the client.

	cryptlib:
		Nothing because we are by definition perfect.

	CuteFTP:
		Drops the connection after seeing the server hello with no (usable) 
		error indication.  This implementation is somewhat tricky to detect 
		since it identifies itself using the dubious vendor ID string "1.0" 
		(see the ssh.com note below), this problem still hasn't been fixed 
		several years after the vendor was notified of it, indicating that 
		it's unlikely to ever be fixed.  This runs into problems with other 
		implementations like BitVise WinSSHD 5.x, which has an ID string 
		beginning with "1.0" (see the comment for WinSSHD above) so when 
		trying to identify CuteFTP we check for an exact match for "1.0" as 
		the ID string.
			
		CuteFTP also uses the SSHv1 backwards-compatible version string 
		"1.99" even though it can't actually do SSHv1, which means that 
		it'll fail if it ever tries to connect to an SSHv1 peer.
		
	dropbear:
		Randomly sends its version as either 20xx.yy ("dropbear_2016.74", 
		"dropbear_2022.83") or 0.xx ("dropbear_0.46", "dropbear_0.52"), to 
		deal with this we match the "20xx" portion first and report the "xx"
		as the major version, otherwise we match the numeric portion.  There
		aren't any bug workarounds required at the moment so this isn't a
		problem for now. 
		
	MobaXTerm:
		Placeholder, ID "MoTTY_Release".  Based on the PuTTY code so will
		presumably have the same issues if any are discovered in newer
		versions.

	OpenSSH:
		Omits hashing the exchange hash length when creating the hash to be 
		signed for client auth for version 2.0 (all subversions).

		Generates an invalid keyex signature if sent an 
		SSH_MSG_KEX_DH_GEX_REQUEST rather than an 
		SSH_MSG_KEX_DH_GEX_REQUEST_OLD, presumably due to hashing the wrong 
		packet format, for versions around the 3.x mark.

		Requires RSA signatures to be padded out with zeroes to the RSA 
		modulus size for all versions from 2.5 to 3.2.

		Can't handle "password" as a PAM sub-method (meaning an
		authentication method hint), it responds with an authentication-
		failed response as soon as we send the PAM authentication request, 
		for versions 3.8 onwards.  This doesn't look like it'll get fixed 
		any time soon so we enable it for all newer versions up until 10.x
		in the hope that it'll at least have been fixed by then.

		Requires and actually checks SSH_MSG_USERAUTH_PK_OK, unlike all other 
		known implementations.

		Doesn't support MTI encryption algorithms as of 7.4 or 7.6 (the 
		release notes are vague on when they were removed from client vs. 
		server, in some cases it's been seen as early as 7.1).

	ProFTPD mod_sftp:
		Requires the old-style GEX and drops the connection if it gets the 
		standard one.  This is complicated by the fact that it provides a 
		configuration setting 'ServerIdent off' that disables sending the 
		version number, so it's unclear which versions this applies to but 
		it seems to be pretty persistent across versions since even ones 
		recent enough to send RFC 8308 extensions and RFC 8332 RSA-SHA2 
		algorithms (both added in 1.3.7rc3, mid-2020) still have the bug.

	Putty:
		Sends zero-length SSH_MSG_IGNORE messages for version 0.59.

	RSSBus:
		Placeholder, ID "IP*Works!".

	ssh.com:
		This implementation puts the version number first so if we find
		something without a vendor name at the start we treat it as an 
		ssh.com version.  However, Van Dyke's SSH server VShell also uses 
		the ssh.com-style identification (fronti nulla fides) so when we 
		check for the ssh.com implementation we habe to make sure that it 
		isn't really VShell.  In addition CuteFTP advertises its 
		implementation as "1.0" (without any vendor name), which is going 
		to cause problems in the future when they move to 2.x.

		Omits the DH-derived shared secret when hashing the keying material 
		for versions identified as "2.0.0" (all sub-versions) and "2.0.10".

		Uses an SSH2_FIXED_KEY_SIZE-sized key for HMAC instead of the de 
		facto 160 bits for versions identified as "2.0.", "2.1 ", "2.1.", 
		and "2.2." (i.e. all sub-versions of 2.0, 2.1, and 2.2), and
		specifically version "2.3.0".  This was fixed in 2.3.1, however 
		"2.0" servers still running in 2020(!!) can't be connected to if
		this workaround is enabled so we only enable it for 2.1 - 2.3.0.

		Omits the signature algorithm name for versions identified as "2.0" 
		and "2.1" (all sub-versions), requiring a complex rewrite of the 
		signature data in order to process it.

		Mishandles large window sizes in a variety of ways.  Typically for 
		any size over about 8M the server gets slower and slower, eventually 
		more or less grinding to halt at about 64MB (presumably some O(n^2) 
		algorithm, although how you manage to do this for a window-size 
		notification is a mystery).  Some versions also reportedly require a 
		window adjust for every 32K or so sent no matter what the actual 
		window size is, which seems to occur for versions identified as 
		"2.0" and "2.1" (all sub-versions).  This may be just a variant of 
		the general mis-handling of large window sizes so we treat it as the 
		same thing and advertise a smaller-than-optimal window which, as a 
		side-effect, results in a constant flow of window adjusts.

		Omits hashing the exchange hash length when creating the hash to be 
		signed for client auth for versions 2.1 and 2.2 (all subversions).

		Sends an empty SSH_SERVICE_ACCEPT response for version 2.0 (all
		subversions).

		Sends an empty userauth-failure response if no authentication is
		required instead of allowing the auth, for uncertain versions 
		probably in the 2.x range.

		Dumps text diagnostics (that is, raw text strings rather than SSH 
		error packets) onto the connection if something unexpected occurs, 
		for uncertain versions probably in the 2.x range.

	Van Dyke:
		Omits hashing the exchange hash length when creating the hash to be 
		signed for client auth for version 3.0 (SecureCRT = SSH) and 1.7 
		(SecureFX = SFTP).

	VxWorks:
		VxWorks did their own implementation of SSH with the version 
		apparently tracking the VxWorks version rather than the SSH 
		implementation version, and even then only being an approximation, 
		for example 6.8.3 from 2015 is reported as 6.8.0 from 2010-11.  
		This is quite problematic because the VxWorks SSH implementation has 
		a range of bugs but there's no way to fingerprint which ones are 
		present due to a combination of incorrect version reporting and the 
		fact that different VxWorks lines advance at their own rate, so that 
		for example 6.8.3 is newer than 6.9.3, see for example 
		https://www.cisa.gov/uscert/ics/advisories/ICSA-15-169-01.

		In particular 5.x would be from the 1990s and predate SSHv2, 6.x is 
		from the 2000s and early 2010s, and 7.x is from around 2015, but a 
		claimed SSH version of 6.8.0 (VxWorks 6.8 from 2010-11) has SSH 
		features like hmac-sha2-256 (RFC 6668, 2012), 
		rsa-sha2-256 (RFC 8332, 2018) and hmac-sha2-256-etm@openssh.com 
		(OpenSSH, 2012) that didn't exist in 2010.  This may be explained by 
		https://www.isssource.com/wind-river-ge-update-6-year-old-holes/, 
		where vendors replaced the buggy 6.5-6.9 versions with a supposed 
		2019 version but still kept the old version number (another source 
		claims the 6.8.x replacement was 6.8.3 which dates from 2015, but 
		that still predates rsa-sha2-256 and in any case identifies itself 
		as 6.8.0).  7 is an even bigger mess because they're all called 7 
		and then there's just an SR designator to indicate which variant 
		you've got.

		Some claimed later versions of 6.x require the old-style GEX and 
		drop the connection if they get the standard one, hopefully 7.x will 
		handle the new-format GEX from the by then decade-old RFC 4419.  
		Given that all versions from 6.5 to 6.9 share the same CVEs, see 
		e.g. the version range for
		https://www.cvedetails.com/cve/CVE-2013-0712/, it's likely that this 
		is a similar code base so we enable it for all 6.x versions.

		Claimed versions of 6.x and possibly also 7.x that support the -sha2 
		variants encode the server public key incorrectly, using 
		"rsa-sha2-256" instead of "ssh-rsa" if a -sha2 cipher suite is 
		selected by the client.  This issue is often masked through 
		widespread use of very old clients that don't know about -sha2 and 
		so don't request any of the -sha2 cipher suites.

	WeOnlyDo:
		Has the same mismatched compression algorithm ID bug as BitVise 
		WinSSHD (see comment above) for unknown versions above about 2.x.

   Further quirks and peculiarities abound, some are handled automatically by 
   workarounds in the code and for the rest they're fortunately rare enough 
   (mostly for long-obsolete SSHv1 versions) that we don't have to go out of 
   our way to handle them.
	   
   A more comprehensive list of SSH server IDs is at
   https://github.com/rapid7/recog/blob/main/xml/ssh_banners.xml and
   https://github.com/0x4D31/hassh-utils/blob/master/hasshdb, with a list of
   (some of) the bugs in implementations at
   https://tartarus.org/~simon/putty-snapshots/htmldoc/Chapter4.html#config-ssh-bugs */

static const VENDOR_INFO vendorInfoTbl[] = {
	{ "RomSShell_", 10, DESCRIPTION( "Allegro" )
	  SSH_VENDOR_ALLEGRO },
	{ "AzureSSH_", 9, DESCRIPTION( "Azure SSH" )
	  SSH_VENDOR_AZURESSH },
	{ "sshlib", 6, DESCRIPTION( "Bitvise" )
	  SSH_VENDOR_BITVISE },			/* Version precedes string */
	{ "FlowSsh", 7, DESCRIPTION( "Bitvise" )
	  SSH_VENDOR_BITVISE },			/* Version precedes string */
	{ "SshServer", 9, DESCRIPTION( "Cerberus" )
	  SSH_VENDOR_CERBERUS, SSH_VENDORFLAG_NO_VERSION },
	{ "CerberusFTPServer_", 18, DESCRIPTION( "Cerberus" )
	  SSH_VENDOR_CERBERUS },
	{ "FTP Server ready", 16, DESCRIPTION( "Chilkat" )
	  SSH_VENDOR_CHILKAT, SSH_VENDORFLAG_NO_VERSION },
	{ "Cisco-", 6, DESCRIPTION( "Cisco" )
	  SSH_VENDOR_CISCO },
	{ "CISCO_WLC", 9, DESCRIPTION( "Cisco" )
	  SSH_VENDOR_CISCO },
	{ "CrushFTPSSHD", 12, DESCRIPTION( "CrushFTP" )
	  SSH_VENDOR_CRUSHFTP, SSH_VENDORFLAG_NO_VERSION },
	{ "J2SSH_Maverick", 14, DESCRIPTION( "CrushFTP" )
	  SSH_VENDOR_CRUSHFTP, SSH_VENDORFLAG_NO_VERSION },
	{ "Maverick_SSHD", 13, DESCRIPTION( "CrushFTP" )
	  SSH_VENDOR_CRUSHFTP, SSH_VENDORFLAG_NO_VERSION },
	{ "cryptlib", 8, DESCRIPTION( "cryptlib" )
	  SSH_VENDOR_CRYPTLIB, SSH_VENDORFLAG_NO_VERSION },
	{ "dropbear_20", 11, DESCRIPTION( "Dropbear" )
	  SSH_VENDOR_DROPBEAR },		/* Version as 20xx year */
	{ "dropbear_", 9, DESCRIPTION( "Dropbear" )
	  SSH_VENDOR_DROPBEAR },		/* Version as number */
	{ "JSCAPE", 6, DESCRIPTION( "JSCAPE" )
	  SSH_VENDOR_JSCAPE, SSH_VENDORFLAG_NO_VERSION },
	{ "libssh-", 7, DESCRIPTION( "libssh" )
	  SSH_VENDOR_LIBSSH },
	{ "MoTTY_Release_", 14, DESCRIPTION( "MobaXterm" )
	  SSH_VENDOR_MOBAXTERM },
	{ "Mocana SSH ", 11, DESCRIPTION( "Mocana" )
	  SSH_VENDOR_MOCANA },
	{ "Data ONTAP SSH ", 15, DESCRIPTION( "NetApp" )
	  SSH_VENDOR_NETAPP },
	{ "OpenSSH_", 8, DESCRIPTION( "OpenSSH" )
	  SSH_VENDOR_OPENSSH },
	{ "mod_sftp", 8, DESCRIPTION( "mod_sftp" )
	  SSH_VENDOR_PROFTPD, SSH_VENDORFLAG_NO_VERSION },
	{ "PuTTY_Release_", 14, DESCRIPTION( "PuTTY" )
	  SSH_VENDOR_PUTTY },
	{ "RebexSSH_", 9, DESCRIPTION( "Rebex" )
	  SSH_VENDOR_REBEX },
	{ "IP*Works!", 9, DESCRIPTION( "RSSBus" )
	  SSH_VENDOR_RSSBUS },
	{ "SSH Secure Shell", 16, DESCRIPTION( "ssh.com" )
	  SSH_VENDOR_SSHCOM },			/* Version precedes string */
	{ "Serv-U_", 7, DESCRIPTION( "SolarWinds" )
	  SSH_VENDOR_SOLARWINDS },
	{ "SysaxSSH_", 9, DESCRIPTION( "Sysax" )
	  SSH_VENDOR_SYSAX }, 
	{ "SSH Tectia", 10, DESCRIPTION( "Tectia" )
	  SSH_VENDOR_TECTIA },			/* Version precedes string */
	{ "TeldatSSH_", 10, DESCRIPTION( "Teldat" )
	  SSH_VENDOR_TELDAT },
	{ "VShell_", 7, DESCRIPTION( "Van Dyke" )
	  SSH_VENDOR_VANDYKE },
	{ "SecureCRT", 9, DESCRIPTION( "Van Dyke" )
	  SSH_VENDOR_VANDYKE },			/* Version precedes string */
	{ "SecureFX", 8, DESCRIPTION( "Van Dyke" )
	  SSH_VENDOR_VANDYKE },			/* Version precedes string */
	{ "IPSSH-", 6, DESCRIPTION( "VxWorks" )
	  SSH_VENDOR_VXWORKS },
	{ "WeOnlyDo-wodFTPD ", 17, DESCRIPTION( "WeOnlyDo" )
	  SSH_VENDOR_WEONLYDO },
	{ "WeOnlyDo ", 9, DESCRIPTION( "WeOnlyDo" )
	  SSH_VENDOR_WEONLYDO },
	{ "WS_FTP-SSH_", 11, DESCRIPTION( "WS_FTP" )
	  SSH_VENDOR_WSFTP },
		{ NULL, 0 }, { NULL, 0 }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int parseIdString( OUT_PTR VERSION_INFO *versionInfo,
						  IN_BUFFER( stringLength ) const BYTE *string,
						  IN_LENGTH_SHORT_MIN( 6 ) const int stringLength )
	{
	const VENDOR_INFO *matchedVendorInfo = NULL;
	const BYTE *vendorIDptr = string, *versionStringPtr DUMMY_INIT_PTR;
	BOOLEAN versionFirst = FALSE;
	int vendorIDlen = stringLength, versionStringLength DUMMY_INIT;
	int length, value;
	LOOP_INDEX i;
	
	assert( isWritePtr( versionInfo, sizeof( VERSION_INFO ) ) );
	assert( isReadPtr( string, stringLength ) );

	REQUIRES( isShortIntegerRangeMin( stringLength, 6 ) );

	/* Clear return value */
	memset( versionInfo, 0, sizeof( VERSION_INFO ) );

	/* The ssh.com-style version string has the version number first, then 
	   the vendor name, in the format "x.y vendorname", so we have to skip
	   the version string to get to the vendor name.  However if the peer
	   sends us garbage like github's 7-hex-digit strings then we don't want 
	   to misinterpret that as a version string and report a parsing error.  
	   To filter out these sorts of things we check for the presence of the
	   '.' and ' ' delimiters towards the start of the string and don't try
	   and process it if we can't find them */
	if( isDigit( string[ 0 ] ) && \
		strFindCh( string, min( 10, stringLength ), '.' ) > 0 && \
		strFindCh( string, min( 10, stringLength ), ' ' ) > 0 )
		{
		/* Get the version substring.  We need at least "x.y" (plus the 
		   implicit space delimiter) before the vendor name */
		versionStringPtr = string;
		versionStringLength = strFindCh( string, stringLength, ' ' );
		if( versionStringLength < 3 )
			return( CRYPT_ERROR_BADDATA );
		
		/* We need at least "xx" for the vendor name.  The +1 is for the 
		   space delimiter */
		REQUIRES( !checkOverflowAdd( versionStringLength, 1 ) );
		vendorIDptr = string + versionStringLength + 1;
		REQUIRES( !checkOverflowSub( stringLength, \
									 versionStringLength + 1 ) );
		vendorIDlen = stringLength - ( versionStringLength + 1 );
		if( vendorIDlen < 2 )
			return( CRYPT_ERROR_BADDATA );

		/* Remember that we've already got the version information */
		versionFirst = TRUE;
		}
	
	/* Determine the vendor of the peer's SSH implementation */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( vendorInfoTbl, VENDOR_INFO ) && \
					vendorInfoTbl[ i ].vendorName != NULL,
			  i++ )
		{
		const VENDOR_INFO *vendorInfoPtr;

		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( vendorInfoTbl, 
														 VENDOR_INFO ) - 1 ) );

		vendorInfoPtr = &vendorInfoTbl[ i ];
		if( vendorInfoPtr->vendorNameLen <= vendorIDlen && \
			!memcmp( vendorIDptr, vendorInfoPtr->vendorName, 
					 vendorInfoPtr->vendorNameLen ) )
			{
			matchedVendorInfo = vendorInfoPtr;
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( vendorInfoTbl, VENDOR_INFO ) );
	if( matchedVendorInfo == NULL )
		{
		/* Nothing on record for this vendor */
		return( OK_SPECIAL );
		}
	versionInfo->vendorType = matchedVendorInfo->vendorType;
#if defined( USE_ERRMSGS ) || !defined( NDEBUG )
	versionInfo->vendorName = matchedVendorInfo->debugText;
#endif /* USE_ERRMSGS || !NDEBUG */

	/* Set the end, as far as we know it at the moment, of the vendor info 
	   part of the string.  If the version is first then this is the actual
	   end, if it's second then it's the start of the version information.
	   This is only an approximation, allowing us to skip parts of the 
	   string when looking for preauth information */
	versionInfo->vendorInfoEnd = matchedVendorInfo->vendorNameLen;
	if( versionFirst )
		{   
		REQUIRES( !checkOverflowAdd( versionInfo->vendorInfoEnd,
									 versionStringLength + 1 ) );
		versionInfo->vendorInfoEnd += versionStringLength + 1;
		}
	ENSURES( rangeCheck( versionInfo->vendorInfoEnd, 1, stringLength ) );
	
	/* If there's no version number present then we're done */
	if( matchedVendorInfo->flags & SSH_VENDORFLAG_NO_VERSION )
		return( CRYPT_OK );

	/* If the version follows the vendor name, remember the version string 
	   information.  As before, we need at least "x.y" */
	if( !versionFirst )
		{
		versionStringPtr = string + matchedVendorInfo->vendorNameLen;
		REQUIRES( !checkOverflowSub( stringLength, \
									 matchedVendorInfo->vendorNameLen ) );
		versionStringLength = stringLength - matchedVendorInfo->vendorNameLen;
		if( versionStringLength < 3 )
			return( CRYPT_ERROR_BADDATA );
		}
	ENSURES( versionStringLength >= 3 );

	/* Parse out the major and minor version numbers.  We have to allow for 
	   a minimum version of 0 to handle Putty's eternal 0.x versions.  The
	   checks for a length of 2 at each stage are to accommodate a ".x"
	   string */
	length = strParseNumeric( versionStringPtr, versionStringLength, 
							  &value, 0, 99 );
	if( length <= 0 )
		return( CRYPT_ERROR_BADDATA );
	versionInfo->majorVersion = value;
	versionStringPtr += length;
	REQUIRES( !checkOverflowSub( versionStringLength, length ) );
	versionStringLength -= length;
	if( versionStringLength < 2 )
		return( CRYPT_OK );
	ENSURES( versionStringLength >= 2 );
	if( versionStringPtr[ 0 ] == '.' )
		{
		versionStringPtr++; versionStringLength--;	/* Skip '.' */
		length = strParseNumeric( versionStringPtr, versionStringLength, 
								  &value, 0, 99 );
		if( length <= 0 )
			return( CRYPT_ERROR_BADDATA );
		versionInfo->minorVersion = value;
		versionStringPtr += length;
		REQUIRES( !checkOverflowSub( versionStringLength, length ) );
		versionStringLength -= length;
		} 
	if( versionStringLength < 2 )
		return( CRYPT_OK );
	ENSURES( versionStringLength >= 2 );
	if( versionInfo->vendorType == SSH_VENDOR_SSHCOM && \
		versionStringPtr[ 0 ] == '.' )
		{
		/* ssh.com used a major version of 2 for many years so the actual
		   version is the minor version and stepping */
		versionStringPtr++; versionStringLength--;	/* Skip '.' */
		length = strParseNumeric( versionStringPtr, versionStringLength, 
								  &value, 0, 99 );
		if( length <= 0 )
			return( CRYPT_ERROR_BADDATA );
		versionInfo->stepping = value;
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processIDinfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  const VERSION_INFO *versionInfo )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( versionInfo, sizeof( VERSION_INFO ) ) );

	switch( versionInfo->vendorType )
		{
		case SSH_VENDOR_ALLEGRO:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );
		
		case SSH_VENDOR_AZURESSH:
			DEBUG_PUTS(( "Peer is buggy AzureSSH implementation." ));

			return( CRYPT_OK );

		case SSH_VENDOR_BITVISE:
			if( versionInfo->majorVersion == 1 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_ASYMMCOPR );
				DEBUG_PUTS(( "Enabling workaround for FlowSSH compression "
							 "algorithm bug." ));
				}
			if( versionInfo->majorVersion >= 6 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_NOMTI );
				DEBUG_PUTS(( "Enabling workaround for FlowSSH no-MTI "
							 "cipher bug." ));
				}
			return( CRYPT_OK );
		
		case SSH_VENDOR_CERBERUS:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );

		case SSH_VENDOR_CHILKAT:
			SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_OLDGEX );
			DEBUG_PUTS(( "Enabling workaround for Chilkat old-GEX bug." ));
			return( CRYPT_OK );

		case SSH_VENDOR_CISCO:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );
		
		case SSH_VENDOR_CRUSHFTP:
			SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_NOEXTINFO );
			DEBUG_PUTS(( "Enabling workaround for CrushFTP/Maverick "
						 "SSH_MSG_EXT_INFO bug." ));
			return( CRYPT_OK );

		case SSH_VENDOR_CRYPTLIB:
			SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISCRYPTLIB );
			return( CRYPT_OK );

		case SSH_VENDOR_CUTEFTP:
			if( versionInfo->majorVersion == 1 && \
				versionInfo->minorVersion == 0 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_CUTEFTP );
				DEBUG_PUTS(( "Enabling workaround for CuteFTP connection-"
							 "drop bug." ));
				}
			return( CRYPT_OK );

		case SSH_VENDOR_DROPBEAR:
			/* Nothing yet, this is present only as a placeholder,
			   full string is either "dropbear_20yy.xx", yy = year, 
			   xx = version or "dropbear_x.y" */
			return( CRYPT_OK );

		case SSH_VENDOR_JSCAPE:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );

		case SSH_VENDOR_LIBSSH:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );
		
		case SSH_VENDOR_MOBAXTERM:
			/* Nothing yet, this is present only as a placeholder, full 
			   string is "MoTTY_Release_x.xx" where x.xx tracks the PuTTY 
			   version number that it's based on */
			return( CRYPT_OK );

		case SSH_VENDOR_MOCANA:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );

		case SSH_VENDOR_NETAPP:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );

		case SSH_VENDOR_OPENSSH:
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  SSH_PFLAG_CHECKSPKOK );
			DEBUG_PUTS(( "Enabling workaround for OpenSSH "
						 "SSH_MSG_USERAUTH_PK_OK bug." ));
			if( versionInfo->majorVersion == 2 && \
				versionInfo->minorVersion == 0 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHLENGTH );
				DEBUG_PUTS(( "Enabling workaround for OpenSSH length-hash "
							 "bug." ));
				}
			if( ( versionInfo->majorVersion == 3 && \
				  versionInfo->minorVersion >= 8 ) ||
				( versionInfo->majorVersion >= 4 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_PAMPW );
				DEBUG_PUTS(( "Enabling workaround for OpenSSH PAM "
							 "password-auth bug." ));
				}
			if( ( versionInfo->majorVersion == 2 && \
				  versionInfo->minorVersion >= 2 ) || \
				( versionInfo->majorVersion == 3 && \
				  versionInfo->minorVersion <= 2 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_OLDGEX );
				DEBUG_PUTS(( "Enabling workaround for OpenSSH old-GEX "
							 "bug." ));
				}
			if( ( versionInfo->majorVersion == 2 && \
				  versionInfo->minorVersion >= 5 ) || \
				( versionInfo->majorVersion == 3 && \
				  versionInfo->minorVersion <= 2 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_RSASIGPAD );
				DEBUG_PUTS(( "Enabling workaround for OpenSSH RSA "
							 "signature padding bug." ));
				}
			if( ( versionInfo->majorVersion == 7 && \
				  versionInfo->minorVersion >= 1 ) || \
				( versionInfo->majorVersion >= 8 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOMTI );
				DEBUG_PUTS(( "Enabling workaround for OpenSSH no-MTI "
							 "cipher bug." ));
				}
			return( CRYPT_OK );

		case SSH_VENDOR_PROFTPD:
			/* ProFTPD mod_sftp, this has the added complication that it's 
			   possible to disable the version information via a server 
			   configuration setting so it's not possible to reliably 
			   detect which version we need to enable bug-workarounds for, 
			   which is why we don't try and perform any type of version 
			   check */
			SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_OLDGEX );
			DEBUG_PUTS(( "Enabling workaround for ProFTPD mod_sftp "
						 "old-GEX bug." ));

			return( CRYPT_OK );

		case SSH_VENDOR_PUTTY:
			if( versionInfo->majorVersion == 0 && \
				versionInfo->minorVersion == 59 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_ZEROLENIGNORE );
				DEBUG_PUTS(( "Enabling workaround for Putty SSH_MSG_IGNORE "
							 "bug." ));
				}
			return( CRYPT_OK );

		case SSH_VENDOR_REBEX:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );

		case SSH_VENDOR_RSSBUS:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );

		case SSH_VENDOR_SSHCOM:
			/* ssh.com was at version 2.x for quite a long time, these 
			   versions have a lot of bugs.  The current (2025) version is 
			   4.x */
			if( versionInfo->majorVersion != 2 )
				return( CRYPT_OK );
			/* All checks beyond this point are for a major version of 2 */
			if( ( versionInfo->minorVersion == 0 && \
				  versionInfo->stepping == 0 ) || \
				( versionInfo->minorVersion == 0 && \
				  versionInfo->stepping == 10 ) ) 
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHSECRET );
				DEBUG_PUTS(( "Enabling workaround for ssh.com secret-hash "
							 "bug." ));
				}
			if( versionInfo->minorVersion == 0 || \
				versionInfo->minorVersion == 1 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_SIGFORMAT );
				DEBUG_PUTS(( "Enabling workaround for ssh.com "
							 "signature-format bug." ));
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_WINDOWSIZE );
				DEBUG_PUTS(( "Enabling workaround for ssh.com window-size "
							 "bug." ));
				}
			if( versionInfo->minorVersion == 1 || \
				versionInfo->minorVersion == 2 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHLENGTH );
				DEBUG_PUTS(( "Enabling workaround for ssh.com length-hash "
							 "bug." ));
				}
			if( versionInfo->minorVersion == 1 || \
				versionInfo->minorVersion == 2 || \
				( versionInfo->minorVersion == 3 && \
				  versionInfo->stepping == 0 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_HMACKEYSIZE );
				DEBUG_PUTS(( "Enabling workaround for ssh.com HMAC keysize "
							 "bug." ));
				}
			if( versionInfo->minorVersion == 0 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_EMPTYSVCACCEPT );
				DEBUG_PUTS(( "Enabling workaround for ssh.com "
							 "SSH_SERVICE_ACCEPT bug." ));
				}
			if( versionInfo->minorVersion >= 0 && \
				versionInfo->minorVersion <= 5 ) 
				{
				/* Not sure of the exact versions where this occurs */
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_EMPTYUSERAUTH | SSH_PFLAG_TEXTDIAGS );
				DEBUG_PUTS(( "Enabling workaround for ssh.com "
							 "SSH_MSG_USERAUTH bug." ));
				DEBUG_PUTS(( "Enabling workaround for ssh.com text "
							 "diagnostics bug." ));
				}
			return( CRYPT_OK );

		case SSH_VENDOR_SOLARWINDS:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );
		
		case SSH_VENDOR_SYSAX:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );
		
		case SSH_VENDOR_TECTIA:
			if( versionInfo->majorVersion == 5 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_DUMMYUSERAUTH );
				DEBUG_PUTS(( "Enabling workaround for SSH Tectia "
							 "length-hash bug." ));
				}
			return( CRYPT_OK );

		case SSH_VENDOR_TELDAT:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );
		
		case SSH_VENDOR_VANDYKE:
			if( versionInfo->majorVersion == 1 && \
				versionInfo->minorVersion == 7 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHLENGTH );
				DEBUG_PUTS(( "Enabling workaround for Van Dyke length-hash "
							 "bug." ));
				}
			if( versionInfo->majorVersion == 3 && \
				versionInfo->minorVersion == 0 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHLENGTH );
				DEBUG_PUTS(( "Enabling workaround for Van Dyke length-hash "
							 "bug." ));
				}
			return( CRYPT_OK );

		case SSH_VENDOR_VXWORKS:
			SET_FLAG( sessionInfoPtr->protocolFlags, SSH_PFLAG_OLDGEX );
			DEBUG_PUTS(( "The peer identifies itself with a version string "
						 "that corresponds to multiple incompatible "
						 "versions,\n  some of which have serious bugs.  "
						 "This session may not work properly." ));
			DEBUG_PUTS(( "Enabling workaround for possible VxWorks old-GEX "
						 "bug." ));
			DEBUG_PUTS(( "Enabling workaround for possible VxWorks host key "
						 "format bug." ));
			return( CRYPT_OK );

		case SSH_VENDOR_WEONLYDO:
			if( versionInfo->majorVersion >= 2 )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_ASYMMCOPR );
				DEBUG_PUTS(( "Enabling workaround for WeOnlyDo compression "
							 "algorithm bug." ));
				}
			return( CRYPT_OK );

		case SSH_VENDOR_WSFTP:
			/* Nothing yet, this is present only as a placeholder */
			return( CRYPT_OK );
		
		default:
			retIntError();
		}

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readSSHID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
			   INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	VERSION_INFO versionInfo;
	const BYTE *versionStringPtr DUMMY_INIT_PTR;
#ifdef USE_ERRMSGS
	const char *peerType = isServer( sessionInfoPtr ) ? "Client" : "Server";
#endif /* USE_ERRMSGS */
	LOOP_INDEX linesRead;
	int versionStringLength DUMMY_INIT, position, length DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );

	/* Read the peer's version information.  The handling is rather ugly 
	   since it's a variable-length string terminated with a newline so we 
	   have to use readTextLine() as if we were talking HTTP.  However since 
	   this canonicalises the text and some implementations send garbled/
	   invalid IDs we have to use the READTEXT_RAW option to ensure that we 
	   get the same invalid data that the server sent.

	   Unfortunately the SSH RFC then further complicates this by allowing 
	   implementations to send non-version-related text lines before the
	   version line.  The theory is that this will allow applications like
	   TCP wrappers to display a (human-readable) error message before
	   disconnecting, however some installations use it to display general
	   banners before the ID string (as opposed to implementations that put
	   the banner in the ID string, see the comment at the start of this 
	   module).
	   
	   Since the RFC doesn't provide any means of distinguishing this banner 
	   information from arbitrary data we can't quickly reject attempts to 
	   connect to something that isn't an SSH server.  In other words we 
	   have to sit here waiting for further data in the hope that eventually 
	   an SSH ID turns up, until such time as the connect timeout expires.
	   
	   See the commented-out code in writeSSHID() below for what you can do
	   with this capability */
	LOOP_MED( linesRead = 0, linesRead < 20, linesRead++ )
		{
		BOOLEAN isTextDataError;

		ENSURES( LOOP_INVARIANT_MED( linesRead, 0, 19 ) );

		/* Get a line of input, which sanitises the data read into non-
		   control ASCII text.  Since this is the first communication that
		   we have with the remote system we're a bit more loquacious about
		   diagnostics in the event of an error */
		status = readTextLine( &sessionInfoPtr->stream, 
							   sessionInfoPtr->receiveBuffer, 
							   SSH_ID_MAX_SIZE, &length, &isTextDataError, 
							   NULL, READTEXT_RAW );
		if( cryptStatusError( status ) )
			{
#ifdef USE_ERRMSGS
			const char *lowercasePeerType = isServer( sessionInfoPtr ) ? \
											"client" : "server";
#endif /* USE_ERRMSGS */
			ERROR_INFO localErrorInfo;

			sNetGetErrorInfo( &sessionInfoPtr->stream, &localErrorInfo );
			retExtErr( status, 
					   ( status, SESSION_ERRINFO, &localErrorInfo, 
					     "Error reading %s's SSH identifier string", 
						 lowercasePeerType ) );
			}

		/* If it's the SSH ID/version string then we're done */
		if( length >= SSH_ID_SIZE && \
			!memcmp( sessionInfoPtr->receiveBuffer, SSH_ID, SSH_ID_SIZE ) )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	DEBUG_DUMP_SSH( sessionInfoPtr->receiveBuffer, 
					( length < 1 ) ? 1 : length, TRUE );
					/* Dummy length value if empty line sent */

	/* The peer shouldn't be throwing infinite amounts of junk at us, if we 
	   don't get an SSH ID after reading 20 lines of input then there's a 
	   problem */
	if( linesRead >= 20 )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "%s sent excessive amounts of text without sending an "
				  "SSH identifier string", peerType ) );
		}

	/* Insertion point to test processing of SSH ID strings */
#if 0
	{
//	const char *testString = "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2"; length = 39;
//	const char *testString = "SSH-2.0-OpenSSH_10.0"; length = 20;
//	const char *testString = "SSH-2.0-3.0.0 SSH Secure Shell"; length = 30;
//	const char *testString = "SSH-2.0-a59182e"; length = 15;	/* github */
	const char *testString = "SSH-2.0-00779af"; length = 15;	/* github */
//	const char *testString = "SSH-2.0-You are connected Nissan Cleo Non-PROD Environment via SSHFTP connection."; length = 81;
//	const char *testString = "SSH-2.0-GitLab-SSHD"; length = 19;
//	const char *testString = "SSH-2.0-Maverick_SSHD"; length = 21;
//	const char *testString = "SSH-2.0-cryptlib C=123456789-A"; length = 30;
//	const char *testString = "SSH-2.0-cryptlib C=1234567890A"; length = 30;
//	const char *testString = "SSH-2.0-cryptlib C=1234567890A,X-"; length = 33;
//	const char *testString = "SSH-2.0-cryptlib C=1234567890A,X=A"; length = 34;
	memcpy( sessionInfoPtr->receiveBuffer, testString, length );
	}
#endif /* 0 */

	/* Make sure that we got enough data to work with.  We need at least 
	   "SSH-" (ID, size SSH_ID_SIZE) + "x.y-" (SSH protocol version, size 4) + 
	   "xx" (software version/ID, of which the shortest-known is "Go", used 
	   by "a fork of go's ssh lib", followed by the next-shortest "ConfD", 
	   size 2) */
	if( length < SSH_ID_SIZE + 4 + 2 || length > SSH_ID_MAX_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "%s sent invalid-length identifier string '%s', total "
				  "length %d", peerType,
				  sanitiseString( sessionInfoPtr->receiveBuffer, 
								  CRYPT_MAX_TEXTSIZE, length ),
				  length ) );
		}
	DEBUG_DUMP_DATA_LABEL( "Read SSH ID string:",
						   sessionInfoPtr->receiveBuffer, length );

	/* Remember how much we've got and set a block of memory following the 
	   string to zeroes in case of any slight range errors in the free-
	   format text-string checks that are required to identify bugs in SSH 
	   implementations */
	REQUIRES( rangeCheck( length, SSH_ID_SIZE + 4 + 2, 
						  sessionInfoPtr->receiveBufSize - 16 ) );
	memset( sessionInfoPtr->receiveBuffer + length, 0, 16 );
	sessionInfoPtr->receiveBufEnd = length;

	/* Check the version and remember where the rest of the information 
	   starts */
	switch( sessionInfoPtr->receiveBuffer[ SSH_ID_SIZE ] )
		{
		case '1':
			if( !memcmp( sessionInfoPtr->receiveBuffer + SSH_ID_SIZE, 
						 "1.99-", 5 ) )
				{
				/* SSHv2 server in backwards-compatibility mode */
				sessionInfoPtr->version = 2;
				position = SSH_ID_SIZE + 5;
				break;
				}
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
					  "%s can only do SSHv1", peerType ) );

		case '2':
			if( !memcmp( sessionInfoPtr->receiveBuffer + SSH_ID_SIZE, 
						 "2.0-", 4 ) )
				{
				sessionInfoPtr->version = 2;
				position = SSH_ID_SIZE + 4;
				break;
				}
			STDC_FALLTHROUGH;

		default:
			retExtSan( CRYPT_ERROR_BADDATA,
					   ( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						 "Invalid SSH version '%s'",
						 sessionInfoPtr->receiveBuffer + SSH_ID_SIZE, 
						 length - SSH_ID_SIZE, NULL, 0, NULL, 0 ) );
						 /* Subtract checked earlier */
		}
	versionStringPtr = sessionInfoPtr->receiveBuffer + position;
	REQUIRES( !checkOverflowSub( length, position ) );
	versionStringLength = length - position;
	
	/* Perform a second more specific check that we've got enough data to 
	   continue.  We need at least "x.y xx" or "xx-x.y" after the initial 
	   ID string, there used to be a version of CuteFTP that identified 
	   itself using the string "1.0" and nothing else, which is also a 
	   prefix of other vendors' ID strings, but this version should be 
	   extinct by now after Globalscape, the vendor, switched to using 
	   Bitvise sshlib.
		   
	   There also exist some very broken implementations that send the
	   garbage values described in the third class in the comment at the 
	   start of this module which get rejected by this check, for obvious 
	   reasons there's no way to identify or fingerprint what these are */
	if( !isShortIntegerRangeMin( versionStringLength, 4 + 2 ) )
		{
		retExtSan( CRYPT_ERROR_BADDATA,
				   ( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					 "%s sent malformed identifier string '%s'", 
					 peerType, 0, sessionInfoPtr->receiveBuffer, length,
					 NULL, 0 ) );
		}
	ENSURES( versionStringLength >= 4 + 2 && \
			 versionStringLength < SSH_ID_MAX_SIZE );	/* From earlier checks */
	status = parseIdString( &versionInfo, versionStringPtr, 
							versionStringLength );
	if( cryptStatusOK( status ) )
		{
		DEBUG_PRINT(( "Detected SSH vendor %d (%s), version %d.%d.\n",
					  versionInfo.vendorType, versionInfo.vendorName,
					  versionInfo.majorVersion,
					  versionInfo.minorVersion ));
		status = processIDinfo( sessionInfoPtr, &versionInfo );
		}
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		{							  /* OK_SPECIAL = unknown vendor */
		retExtSan( status,
				   ( status, SESSION_ERRINFO, 
					 "%s sent malformed identifier string '%s'", 
					 peerType, 0, sessionInfoPtr->receiveBuffer, length,
					 NULL, 0 ) );
		}

	/* Finally, check whether there's a pre-authentication challenge or 
	   response present */
	if( status != OK_SPECIAL && versionInfo.vendorInfoEnd > 0 )
		{
		/* It's a recognised vendor, we can skip the vendor ID string */
		ENSURES( rangeCheck( versionInfo.vendorInfoEnd, 1, versionStringLength ) );
		return( checkPreAuth( sessionInfoPtr, handshakeInfo, 
							  versionStringPtr + versionInfo.vendorInfoEnd, 
							  versionStringLength - versionInfo.vendorInfoEnd ) );
		}
	return( checkPreAuth( sessionInfoPtr, handshakeInfo, 
						  versionStringPtr, versionStringLength ) );
	}

/****************************************************************************
*																			*
*								Write an SSH ID								*
*																			*
****************************************************************************/

/* Send an SSH ID string with optional pre-authentication value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeSSHID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
				INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	const ATTRIBUTE_LIST *attributeListPtr;
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );

	sMemOpen( &stream, sessionInfoPtr->sendBuffer, CRYPT_MAX_TEXTSIZE );

	/* Check whether we're using pre-authentication */
	attributeListPtr = findSessionInfo( sessionInfoPtr, 
										CRYPT_SESSINFO_SSH_PREAUTH );
	if( isServer( sessionInfoPtr ) && attributeListPtr != NULL )
		{
		/* We're the server and a pre-authentication value is present, 
		   create the pre-authentication challenge for the client and 
		   precompute the expected response */
		status = createPreauthChallengeResponse( handshakeInfo, 
												 attributeListPtr );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}

		/* Encode the client challenge as part of the SSH ID string */
		swrite( &stream, SSH_ID_STRING " C=", SSH_ID_STRING_SIZE + 3 );
		swrite( &stream, handshakeInfo->challenge, 
				handshakeInfo->challengeLength );
		status = swrite( &stream, "\r\n", 2 );
		}
	else
		{
		/* We're the client and have received a challenge, create the 
		   response for the server */
		if( !isServer( sessionInfoPtr ) && attributeListPtr != NULL && \
			handshakeInfo->challengeLength > 0 )
			{
			status = createPreauthResponse( handshakeInfo, attributeListPtr );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( &stream );
				return( status );
				}

			/* Encode the server response as part of the SSH ID string */
			swrite( &stream, SSH_ID_STRING " R=", SSH_ID_STRING_SIZE + 3 );
			swrite( &stream, handshakeInfo->response, 
					handshakeInfo->responseLength );
			status = swrite( &stream, "\r\n", 2 );
			}
		else
			{
			/* The following is technically legal (RFC 4253 section 4.2 
			   "Protocol Version Exchange") but pretty wrong, however 
			   correctly-written clients will still accept it because only 
			   the last line, the standard server ID, is hashed into the key 
			   exchange.  That doesn't make it right though... */
#if 0
			const char *idString = \
				"220 server.com ESMTP Chuckmail bent over and ready\r\n"
				"+OK POP3 server ready <abcd@server.com>\r\n"
				"OK IMAP/POP3 ready server.com\r\n"
				"220 FTP Server server.com ready\r\n"
				SSH_ID_STRING "\r\n";
			swrite( &stream, idString, 
					strnlen_s( idString, MAX_ATTRIBUTE_SIZE ) );
#endif /* 0 */
			/* We're just using standard SSH ID strings */
			status = swrite( &stream, SSH_ID_STRING "\r\n", 
							 SSH_ID_STRING_SIZE + 2 );
			}
		}
	if( cryptStatusOK( status ) )
		sessionInfoPtr->sendBufPos = stell( &stream );
	sMemDisconnect( &stream );
	ENSURES( cryptStatusOK( status ) );

	/* Send the ID string to the client before we continue with the
	   handshake.  While the ID string that's sent has a CRLF at the end,
	   this isn't hashed so we adjust the buffer size after sending to 
	   exclude the CRLF */
	status = swrite( &sessionInfoPtr->stream, sessionInfoPtr->sendBuffer, 
					 sessionInfoPtr->sendBufPos );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	REQUIRES( !checkOverflowSub( sessionInfoPtr->sendBufPos, 2 ) );
	sessionInfoPtr->sendBufPos -= 2;
	DEBUG_DUMP_DATA_LABEL( "Wrote SSH ID string:\n",
						   sessionInfoPtr->sendBuffer, 
						   sessionInfoPtr->sendBufPos );

	return( CRYPT_OK );
	}
#endif /* USE_SSH */
