/****************************************************************************
*																			*
*						cryptlib SSHv2 SSH ID Management					*
*						Copyright Peter Gutmann 1998-2021					*
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

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check for and process a pre-authentication value attached to the SSH 
   version string */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkPreAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						 INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo,
						 IN_BUFFER( versionStringLength ) \
							const char *versionString, 
						 IN_LENGTH_SHORT_MIN( 2 + SSH_PREAUTH_NONCE_ENCODEDSIZE ) \
							const int versionStringLength )
	{
#ifdef USE_ERRMSGS
	const char *peerType = isServer( sessionInfoPtr ) ? "Client" : "Server";
#endif /* USE_ERRMSGS */
	int preAuthPosition, preAuthLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( versionString, versionStringLength ) );

	REQUIRES( isShortIntegerRangeMin( versionStringLength, 
									  2 + SSH_PREAUTH_NONCE_ENCODEDSIZE ) );

	/* If we're the server and didn't send a pre-authentication challenge
	   to the client then there's nothing to do */
	if( isServer( sessionInfoPtr ) && handshakeInfo->challengeLength <= 0 )
		return( CRYPT_OK );

	/* Check for a pre-authentication challenge or response.  This should
	   be the first value in the string but the check we perform here is a
	   bit more general since it's a recent change to SSH and we don't know
	   how some implementations will handle it */
	status = preAuthPosition = \
		strFindStr( versionString, versionStringLength, 
					isServer( sessionInfoPtr ) ? "R=" : "C=", 2 );
	if( cryptStatusError( status ) )
		{
		/* If we're the client then the server didn't send us a pre-
		   authentication challenge, there's nothing to do */
		if( !isServer( sessionInfoPtr ) )
			return( CRYPT_OK );

		/* We're the server, the client should have sent a response to our
		   challenge */
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Client didn't respond to our pre-authentication "
				  "challenge" ) );
		}

	/* Make sure that the pre-authentication value looks valid.  We don't do 
	   anything with the decoded value since we work with the encoded form, 
	   it's just used as a check for valid data */
	preAuthLength = versionStringLength - ( preAuthPosition + 2 );
	if( !isShortIntegerRangeMin( preAuthLength, 
								 SSH_PREAUTH_NONCE_ENCODEDSIZE ) )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		BYTE buffer[ SSH_PREAUTH_MAX_SIZE + 8 ];
		int length;

		status = base64decode( buffer, SSH_PREAUTH_MAX_SIZE, &length, 
							   versionString + preAuthPosition + 2,
							   SSH_PREAUTH_NONCE_ENCODEDSIZE, 
							   CRYPT_CERTFORMAT_NONE );
		}
	if( cryptStatusOK( status ) && \
		preAuthLength != SSH_PREAUTH_NONCE_ENCODEDSIZE )
		{
		const int remainderLength = \
						preAuthLength - SSH_PREAUTH_NONCE_ENCODEDSIZE;
		const int remainderPos = \
						preAuthPosition + 2 + SSH_PREAUTH_NONCE_ENCODEDSIZE;

		/* There's more data following the pre-authentication value, check 
		   that it follows the form ',X=...' to match the general pattern
		   'C=abcdefg,X=....,Y=.....' */
		if( !isShortIntegerRangeMin( remainderLength, 4 ) || \
			versionString[ remainderPos ] != ',' || \
			!isAlpha( versionString[ remainderPos + 1 ] ) || \
			versionString[ remainderPos + 2 ] != '=' )
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
		const int preAuthDataLen = min( preAuthLength, CRYPT_MAX_TEXTSIZE );
#ifdef USE_ERRMSGS
		char preAuthBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];

#endif /* USE_ERRMSGS */
		if( preAuthDataLen <= 0 )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "%s sent empty pre-authentication value", 
					  peerType ) );
			}
#ifdef USE_ERRMSGS
		REQUIRES( rangeCheck( preAuthDataLen, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( preAuthBuffer, versionString + preAuthPosition, 
				preAuthDataLen );
#endif /* USE_ERRMSGS */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "%s sent invalid pre-authentication value '%s'", 
				  peerType,
				  sanitiseString( preAuthBuffer, CRYPT_MAX_TEXTSIZE, 
								  preAuthLength ) ) );
		}

	/* Remember the challenge or response.  The server records the value as
	   receivedResponse for later comparison with the locally computed
	   response value */
	REQUIRES( preAuthLength == SSH_PREAUTH_NONCE_ENCODEDSIZE && \
			  SSH_PREAUTH_NONCE_ENCODEDSIZE <= SSH_PREAUTH_MAX_SIZE );
	if( isServer( sessionInfoPtr ) )
		{
		memcpy( handshakeInfo->receivedResponse, 
				versionString + preAuthPosition + 2, 
				SSH_PREAUTH_NONCE_ENCODEDSIZE );
		handshakeInfo->receivedResponseLength = SSH_PREAUTH_NONCE_ENCODEDSIZE;
		}
	else
		{
		memcpy( handshakeInfo->challenge, 
				versionString + preAuthPosition + 2, 
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
		"SshServer".

	Chilkat sFTP:
		Yet another difficult-to-ID one, this time it's "FTP Server ready".
		Instantly fails the handshake if it sees SSH_MSG_KEY_DH_GEX_REQUEST
		rather than SSH_MSG_KEX_DH_GEX_REQUEST_OLD from 20-odd years ago 
		(and it also does blowfish, 3des, rsa1024-sha1, hmac-ripemd160, and 
		a bunch of others).

	CrushFTP:
		Java-based FTP server using J2SSH-Maverick from Jadaptive, a fork of 
		the abandoned J2SSH, identified as either "CrushFTPSSHD" or 
		"J2SSH_Maverick".
			
		Advertises support for SSH_MSG_EXT_INFO but drops the connection 
		when it gets an actual SSH_MSG_EXT_INFO from the client.

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
		for versions 3.8 onwards (this doesn't look like it'll get fixed any 
		time soon so we enable it for all newer versions until further 
		notice).

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
   https://github.com/rapid7/recog/blob/main/xml/ssh_banners.xml */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processStringID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							IN_BUFFER( versionStringLength ) \
								const char *versionString,
							IN_LENGTH_SHORT_MIN( 3 ) \
								const int versionStringLength )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( versionString, sizeof( versionStringLength ) ) );

	REQUIRES( isShortIntegerRangeMin( versionStringLength, 3 ) );

	if( ( versionStringLength >= 8 && \
		  !memcmp( versionString, "AzureSSH", 8 ) ) )
		{
		DEBUG_PUTS(( "Peer is buggy AzureSSH implementation." ));

		return( CRYPT_OK );
		}
	if( ( versionStringLength >= 12 && \
		  !memcmp( versionString, "CrushFTPSSHD", 12 ) ) || \
		( versionStringLength >= 14 && \
		  !memcmp( versionString, "J2SSH_Maverick", 14 ) ) )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, 
				  SSH_PFLAG_NOEXTINFO );
		DEBUG_PUTS(( "Enabling workaround for CrushFTP/Maverick "
					 "SSH_MSG_EXT_INFO bug." ));

		return( CRYPT_OK );
		}
	if( versionStringLength >= 11 && \
		!memcmp( versionString, "dropbear_20", 11 ) )
		{
		/* Dropbear: Nothing yet, this is present only as a placeholder,
		   full string is "dropbear_20yy.xx", yy = year, xx = version */
		return( CRYPT_OK );
		}
	if( versionStringLength >= 16 && \
		!memcmp( versionString, "FTP Server ready", 16 ) )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, 
				  SSH_PFLAG_OLDGEX );
		DEBUG_PUTS(( "Enabling workaround for Chilkat old-GEX bug." ));

		return( CRYPT_OK );
		}
	if( versionStringLength >= 9 && \
		!memcmp( versionString, "IP*Works!", 9 ) )
		{
		/* RSSBus: Nothing yet, this is present only as a placeholder */
		return( CRYPT_OK );
		}
	if( versionStringLength >= 7 && \
		!memcmp( versionString, "IPSSH-6", 7 ) )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, 
				  SSH_PFLAG_OLDGEX );
		DEBUG_PUTS(( "The peer identifies itself with a version string "
					 "that corresponds to multiple incompatible versions,\n"
					 "  some of which have serious bugs.  This session may "
					 "not work properly." ));
		DEBUG_PUTS(( "Enabling workaround for possible VxWorks old-GEX "
					 "bug." ));
		DEBUG_PUTS(( "Enabling workaround for possible VxWorks host key "
					 "format bug." ));

		return( CRYPT_OK );
		}
	if( versionStringLength >= 6 && \
		!memcmp( versionString, "JSCAPE", 6 ) )
		{
		/* JScape: Nothing yet, this is present only as a placeholder */
		return( CRYPT_OK );
		}
	if( versionStringLength >= 8 && \
		!memcmp( versionString, "mod_sftp", 8 ) )
		{
		/* ProFTPD mod_sftp, this has the added complication that it's 
		   possible to disable the version information via a server 
		   configuration setting so it's not possible to reliably detect 
		   which version we need to enable bug-workarounds for, which is
		   why we don't try and perform any type of version check */
		SET_FLAG( sessionInfoPtr->protocolFlags, 
				  SSH_PFLAG_OLDGEX );
		DEBUG_PUTS(( "Enabling workaround for ProFTPD mod_sftp old-GEX "
					 "bug." ));

		return( CRYPT_OK );
		}
	if( versionStringLength >= 8 + 3 && \
		!memcmp( versionString, "OpenSSH_", 8 ) )
		{
		const BYTE *subVersionStringPtr = versionString + 8;

		SET_FLAG( sessionInfoPtr->protocolFlags, 
				  SSH_PFLAG_CHECKSPKOK );
		DEBUG_PUTS(( "Enabling workaround for OpenSSH "
					 "SSH_MSG_USERAUTH_PK_OK bug." ));
		if( !memcmp( subVersionStringPtr, "2.0", 3 ) )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  SSH_PFLAG_NOHASHLENGTH );
			DEBUG_PUTS(( "Enabling workaround for OpenSSH length-hash "
						 "bug." ));
			}
		if( !memcmp( subVersionStringPtr, "3.8", 3 ) || \
			!memcmp( subVersionStringPtr, "3.9", 3 ) || \
			( versionStringLength >= 8 + 4 && \
			  !memcmp( subVersionStringPtr, "3.10", 4 ) ) || \
			*subVersionStringPtr >= '4' )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  SSH_PFLAG_PAMPW );
			DEBUG_PUTS(( "Enabling workaround for OpenSSH PAM password-auth "
						 "bug." ));
			}
		if( !memcmp( subVersionStringPtr, "3.", 2 ) )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  SSH_PFLAG_OLDGEX );
			DEBUG_PUTS(( "Enabling workaround for OpenSSH old-GEX "
						 "bug." ));
			}
		if( ( !memcmp( subVersionStringPtr, "2.", 2 ) && \
			  subVersionStringPtr[ 2 ] >= '5' ) || \
			( !memcmp( subVersionStringPtr, "3.", 2 ) && \
			  subVersionStringPtr[ 2 ] <= '2' ) )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  SSH_PFLAG_RSASIGPAD );
			DEBUG_PUTS(( "Enabling workaround for OpenSSH RSA signature "
						 "paddin gbug." ));
			}
		if( ( !memcmp( subVersionStringPtr, "7.", 2 ) && \
			  subVersionStringPtr[ 2 ] >= '1' ) || \
			( subVersionStringPtr[ 0 ] >= '8' ) )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  SSH_PFLAG_NOMTI );
			DEBUG_PUTS(( "Enabling workaround for OpenSSH no-MTI cipher "
						 "bug." ));
			}

		return( CRYPT_OK );
		}
	if( versionStringLength >= 14 + 4 && \
		!memcmp( versionString, "PuTTY_Release_", 14 ) )
		{
		const BYTE *subVersionStringPtr = versionString + 14;

		if( !memcmp( subVersionStringPtr, "0.59", 4 ) )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  SSH_PFLAG_ZEROLENIGNORE );
			DEBUG_PUTS(( "Enabling workaround for Putty SSH_MSG_IGNORE "
						 "bug." ));
			}

		return( CRYPT_OK );
		}
	if( versionStringLength >= 9 && \
		!memcmp( versionString, "SshServer", 9 ) )
		{
		/* Cerberus FTP: Nothing yet, this is present only as a 
		   placeholder */
		return( CRYPT_OK );
		}
	if( versionStringLength >= 9 && \
		!memcmp( versionString, "WeOnlyDo ", 9 ) )
		{
		const BYTE *subVersionStringPtr = versionString + 9;

		if( subVersionStringPtr[ 0 ] >= '2' )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  SSH_PFLAG_ASYMMCOPR );
			DEBUG_PUTS(( "Enabling workaround for WeOnlyDo compression "
						 "algorithm bug." ));
			}

		return( CRYPT_OK );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processVersionID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 IN_BUFFER( versionStringLength ) \
								const char *versionString,
							 IN_LENGTH_SHORT_MIN( 3 ) \
								const int versionStringLength )
	{
	const BYTE *vendorIDString;
	const int versionDigit = byteToInt( *versionString );
	LOOP_INDEX vendorIDStringLength;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( versionString, sizeof( versionStringLength ) ) );

	REQUIRES( isShortIntegerRangeMin( versionStringLength, 3 ) );

	/* Look for a vendor ID after the version information.  This breaks down 
	   the string "[SSH-x.y-]x.yy vendor-text" to 'versionString = "x.yy"' 
	   and 'vendorIDString = "vendor-text"' */
	LOOP_LARGE_REV( ( vendorIDStringLength = versionStringLength, \
					  vendorIDString = versionString ),
					vendorIDStringLength > 0 && *vendorIDString != ' ',
					( vendorIDStringLength--, vendorIDString++ ) )
		{
		ENSURES( LOOP_INVARIANT_REV( vendorIDStringLength, 1, 
									 versionStringLength ) );
		}
	ENSURES( LOOP_BOUND_LARGE_REV_OK );
	if( vendorIDStringLength > 1 )
		{
		/* There's a vendor ID present, skip the ' ' separator */
		vendorIDString++;
		vendorIDStringLength--;
		}
	ENSURES( vendorIDStringLength >= 0 && \
			 vendorIDStringLength < SSH_ID_MAX_SIZE );
	switch( versionDigit )
		{
		case '1':
			if( versionStringLength >= 12 && \
				!memcmp( versionString, "1.7 SecureFX", 12 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHLENGTH );
				DEBUG_PUTS(( "Enabling workaround for Van Dyke length-hash "
							 "bug." ));
				}
			if( versionStringLength == 3 && \
				!memcmp( versionString, "1.0", 3 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_CUTEFTP );
				DEBUG_PUTS(( "Enabling workaround for CuteFTP "
							 "connection-drop bug." ));
				}
			if( ( vendorIDStringLength > 8 && \
				!memcmp( vendorIDString, "sshlib: ", 8 ) ) || \
				( vendorIDStringLength > 9 && \
				!memcmp( vendorIDString, "FlowSsh: ", 9 ) ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_ASYMMCOPR );
				DEBUG_PUTS(( "Enabling workaround for FlowSSH compression "
							 "algorithm bug." ));
				}
			break;

		case '2':
			if( vendorIDStringLength >= 6 && \
				!memcmp( vendorIDString, "VShell", 6 ) )
				break;	/* Make sure that it isn't VShell */

			/* ssh.com 2.x versions have quite a number of bugs so we check 
			   for them as a group */
			if( ( versionStringLength >= 5 && \
				  !memcmp( versionString, "2.0.0", 5 ) ) || \
				( versionStringLength >= 6 && \
				  !memcmp( versionString, "2.0.10", 6 ) ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHSECRET );
				DEBUG_PUTS(( "Enabling workaround for ssh.com secret-hash "
							 "bug." ));
				}
			if( !memcmp( versionString, "2.0", 3 ) || \
				!memcmp( versionString, "2.1", 3 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_SIGFORMAT );
				DEBUG_PUTS(( "Enabling workaround for ssh.com "
							 "signature-format bug." ));
				}
			if( !memcmp( versionString, "2.0", 3 ) || \
				!memcmp( versionString, "2.1", 3 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_WINDOWSIZE );
				DEBUG_PUTS(( "Enabling workaround for ssh.com window-size "
							 "bug." ));
				}
			if( !memcmp( versionString, "2.1", 3 ) || \
				!memcmp( versionString, "2.2", 3 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHLENGTH );
				DEBUG_PUTS(( "Enabling workaround for ssh.com length-hash "
							 "bug." ));
				}
			if( !memcmp( versionString, "2.1", 3 ) || \
				!memcmp( versionString, "2.2", 3 ) || \
				( versionStringLength >= 5 && \
				  !memcmp( versionString, "2.3.0", 5 ) ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_HMACKEYSIZE );
				DEBUG_PUTS(( "Enabling workaround for ssh.com HMAC keysize "
							 "bug." ));
				}
			if( !memcmp( versionString, "2.0", 3 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_EMPTYSVCACCEPT );
				DEBUG_PUTS(( "Enabling workaround for ssh.com "
							 "SSH_SERVICE_ACCEPT bug." ));
				}
			if( !memcmp( versionString, "2.", 2 ) )
				{
				/* Not sure of the exact versions where this occurs */
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_EMPTYUSERAUTH | SSH_PFLAG_TEXTDIAGS );
				DEBUG_PUTS(( "Enabling workaround for ssh.com "
							 "SSH_MSG_USERAUTH bug." ));
				DEBUG_PUTS(( "Enabling workaround for ssh.com text "
							 "diagnostics bug." ));
				}
			break;

		case '3':
			if( versionStringLength >= 13 && \
				!memcmp( versionString, "3.0 SecureCRT", 13 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOHASHLENGTH );
				DEBUG_PUTS(( "Enabling workaround for Van Dyke length-hash "
							 "bug." ));
				}
			break;

		case '5':
			if( versionStringLength >= 10 && \
				!memcmp( vendorIDString, "SSH Tectia", 10 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_DUMMYUSERAUTH );
				DEBUG_PUTS(( "Enabling workaround for SSH Tectia "
							 "length-hash bug." ));
				}
			break;

		case '6':
		case '7':
		case '8':
		case '9':
			if( vendorIDStringLength > 9 && \
				!memcmp( vendorIDString, "FlowSsh: ", 9 ) )
				{
				SET_FLAG( sessionInfoPtr->protocolFlags, 
						  SSH_PFLAG_NOMTI );
				DEBUG_PUTS(( "Enabling workaround for FlowSSH no-MTI cipher "
							 "bug." ));
				}
			break;
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readSSHID( INOUT_PTR SESSION_INFO *sessionInfoPtr,
			   INOUT_PTR SSH_HANDSHAKE_INFO *handshakeInfo )
	{
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

	/* Read the server version information, with the format for the ID 
	   string being "SSH-protocolversion-softwareversion comments", which 
	   (in the original ssh.com interpretation) was "SSH-x.y-x.y vendorname" 
	   (e.g. "SSH-2.0-3.0.0 SSH Secure Shell") but for almost everyone else 
	   is "SSH-x.y-vendorname*version" (e.g "SSH-2.0-OpenSSH_3.0").

	   This version information handling is rather ugly since it's a 
	   variable-length string terminated with a newline, so we have to use
	   readTextLine() as if we were talking HTTP.  However since this 
	   canonicalises the text and some implementations send garbled/invalid 
	   IDs we have to use the READTEXT_RAW option to ensure that we get the 
	   same invalid data that the server sent.

	   Unfortunately the SSH RFC then further complicates this by allowing 
	   implementations to send non-version-related text lines before the
	   version line.  The theory is that this will allow applications like
	   TCP wrappers to display a (human-readable) error message before
	   disconnecting, however some installations use it to display general
	   banners before the ID string.  Since the RFC doesn't provide any 
	   means of distinguishing this banner information from arbitrary data 
	   we can't quickly reject attempts to connect to something that isn't 
	   an SSH server.  In other words we have to sit here waiting for 
	   further data in the hope that eventually an SSH ID turns up, until 
	   such time as the connect timeout expires.
	   
	   See the commented-out code in serverStartup() for what you can do
	   with this capability */
	LOOP_MED( linesRead = 0, linesRead < 20, linesRead++ )
		{
		BOOLEAN isTextDataError;

		ENSURES( LOOP_INVARIANT_MED( linesRead, 0, 19 ) );

		/* Get a line of input.  Since this is the first communication that
		   we have with the remote system we're a bit more loquacious about
		   diagnostics in the event of an error */
		status = readTextLine( &sessionInfoPtr->stream, 
							   sessionInfoPtr->receiveBuffer, 
							   SSH_ID_MAX_SIZE, &length, &isTextDataError, 
							   NULL, READTEXT_RAW );
		if( cryptStatusError( status ) )
			{
#ifdef USE_ERRMSGS
			const char *lcPeerType = isServer( sessionInfoPtr ) ? \
									 "client" : "server";
#endif /* USE_ERRMSGS */
			ERROR_INFO localErrorInfo;	/* Lowercase version of peerType */

			sNetGetErrorInfo( &sessionInfoPtr->stream, &localErrorInfo );
			retExtErr( status, 
					   ( status, SESSION_ERRINFO, &localErrorInfo, 
					     "Error reading %s's SSH identifier string", 
						 lcPeerType ) );
			}

		/* If it's the SSH ID/version string, we're done */
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

	/* Make sure that we got enough data to work with.  We need at least 
	   "SSH-" (ID, size SSH_ID_SIZE) + "x.y-" (protocol version) + "xx" 
	   (software version/ID, of which the shortest-known is "Go", used by
	   "a fork of go's ssh lib", followed by "ConfD") */
	if( length < SSH_ID_SIZE + 6 || length > SSH_ID_MAX_SIZE )
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
	   format text-string checks that are required further on to identify 
	   bugs in SSH implementations */
	REQUIRES( rangeCheck( length, SSH_ID_SIZE + 6, 
						  sessionInfoPtr->receiveBufSize - 16 ) );
	memset( sessionInfoPtr->receiveBuffer + length, 0, 16 );
	sessionInfoPtr->receiveBufEnd = length;

	/* Determine which version we're talking to */
	switch( sessionInfoPtr->receiveBuffer[ SSH_ID_SIZE ] )
		{
		case '1':
			if( !memcmp( sessionInfoPtr->receiveBuffer + SSH_ID_SIZE, 
						 "1.99", 4 ) )
				{
				/* SSHv2 server in backwards-compatibility mode */
				sessionInfoPtr->version = 2;
				break;
				}
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
					  "%s can only do SSHv1", peerType ) );

		case '2':
			sessionInfoPtr->version = 2;
			break;

		default:
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid SSH version '%s'",
					  sanitiseString( &sessionInfoPtr->receiveBuffer[ SSH_ID_SIZE ],
									  CRYPT_MAX_TEXTSIZE, 1 ) ) );
		}

	/* Find the end of the protocol version substring, i.e. locate whatever 
	   follows the "SSH-x.y" portion of the ID string by searching for the
	   second '-' delimiter in the string, which is the first one after the
	   "SSH-x.y" */
	status = \
		position = strFindCh( sessionInfoPtr->receiveBuffer + SSH_ID_SIZE, 
							  length - SSH_ID_SIZE, '-' );
	if( !cryptStatusError( status ) )
		{
		const int startOffset = SSH_ID_SIZE + position + 1;	/* Skip '-' */

		versionStringPtr = sessionInfoPtr->receiveBuffer + startOffset;
		versionStringLength = length - startOffset;
		}
	if( cryptStatusError( status ) || \
		!isShortIntegerRangeMin( versionStringLength, 3 ) )
		{
		/* We need at least "-x.y" after the initial ID string, we can't 
		   require any more than this because of CuteFTP (see note below).
		   
		   There exists a very broken implementation that sends 'SSH-2.0-""'
		   as its ID which gets rejected by this check, for obvious reasons 
		   there's no way to identify or fingerprint this one */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "%s sent malformed identifier string '%s'", peerType,
				  sanitiseString( sessionInfoPtr->receiveBuffer, 
								  CRYPT_MAX_TEXTSIZE, length ) ) );
		}
	ENSURES( versionStringLength >= 3 && \
			 versionStringLength < SSH_ID_MAX_SIZE );	/* From earlier checks */

	/* Check whether the peer is using cryptlib */
	if( versionStringLength >= 8 && \
		!memcmp( versionStringPtr, "cryptlib", 8 ) )
		{
		SET_FLAG( sessionInfoPtr->flags, SESSION_FLAG_ISCRYPTLIB );
		}

	/* Check for implementations that require special workrounds */
	if( isDigit( *versionStringPtr ) )
		{
		status = processVersionID( sessionInfoPtr, versionStringPtr,
								   versionStringLength );
		}
	else
		{
		status = processStringID( sessionInfoPtr, versionStringPtr,
								  versionStringLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, check whether there's a pre-authentication challenge or 
	   response present.  We look for the space delimiter that denotes the
	   (possible) presence of the pre-authentication value and try and 
	   process it if there's room for an 'x=yyyyyyyyyyyy' */
	status = \
		position = strFindCh( versionStringPtr, versionStringLength, ' ' );
	if( !cryptStatusError( status ) && position > 0 )
		{
		versionStringPtr += position + 1;	/* Skip ' ' */
		versionStringLength -= position + 1;
		if( isShortIntegerRangeMin( versionStringLength, 
									2 + SSH_PREAUTH_NONCE_ENCODEDSIZE ) )
			{
			/* There's a pre-authentication value present, process it */
			return( checkPreAuth( sessionInfoPtr, handshakeInfo, 
								  versionStringPtr, versionStringLength ) );
			}
		}

	/* If we're the server and we sent a challenge to the client then the 
	   client should have sent a response */
	if( isServer( sessionInfoPtr ) && handshakeInfo->challengeLength > 0 )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Client didn't respond to our pre-authentication "
				  "challenge" ) );
		}

	return( CRYPT_OK );
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
		/* We're the client and and have received a challenge, create the 
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

			/* Encode the server respnse as part of the SSH ID string */
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
			swrite( &stream, idString, strlen( idString ) );
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
		}
	sessionInfoPtr->sendBufPos -= 2;
	DEBUG_DUMP_DATA_LABEL( "Wrote SSH ID string:\n",
						   sessionInfoPtr->sendBuffer, 
						   sessionInfoPtr->sendBufPos );

	return( status );
	}
#endif /* USE_SSH */
