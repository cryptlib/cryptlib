/****************************************************************************
*																			*
*			cryptlib SSHv2 Server-side Authentication Management			*
*						Copyright Peter Gutmann 1998-2024					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH

/* SSH user authentication gets quite complicated because of the way that 
   the multi-pass dog's-breakfast process defined in the spec affects our 
   handling of user name and password information.  The SSH spec allows the 
   client to perform authentication in bits and pieces and change the 
   details of what it sends at each step and use authentication methods 
   that it specifically knows the server can't handle and all manner of 
   other craziness, see the SimpleSSH draft for a long discussion of these 
   problems.  
   
   This is particularly nasty because of the large amount of leeway that it 
   provides for malicious clients to subvert the authentication process, for 
   example the client can supply a privileged user name the first time 
   around and then authenticate the second time round as an unprivileged 
   user.  If the calling application just checks the first user name that it 
   finds then it'll then treat the client as being an authenticated 
   privileged user which indeed some server applications have done in the 
   past.
   
   To defend against this we record the user name and any other state-based
   information the first time that they're provided and from then on require 
   that the client supply the same information on subsequent authentication 
   attempts.  This is the standard client behaviour anyway, if the user 
   name + password are rejected then the assumption is that the password is 
   wrong and the user gets to retry the password.  We don't allow retry on
   public-key authentication because the signature isn't going to change on
   subsequent attempts.
   
   In order to accommodate public-key authentication we also verify that the 
   authentication method remains constant over successive iterations, i.e. 
   that the client doesn't try part of an authentication with a public key 
   and then another part with a password.  Finally, we enforce a state 
   machine that only allows messages in a certain sequence.

   Handling the state machine required to process all of this gets rather
   complicated, the protocol flow that we enforce is:

	Step 0 (optional):

		Client sends SSH_MSG_USERAUTH_REQUEST with method "none" to query 
		available authentication method types.

		Server responds with SSH_MSG_USERAUTH_FAILURE listing available 
		methods.

	Step 0a (optional):

		Client sends SSH_MSG_USERAUTH_REQUEST with only a public key, no
		signature.

		Server responds with SSH_MSG_USERAUTH_PK_OK.  We always respond with 
		PK_OK in order to prevent account enumeration.

	Step 1:

		Client sends SSH_MSG_USERAUTH_REQUEST with method "password" or 
		"publickey" and password data or a digital signature as appropriate.

	Step 2, one of:

		a. Server responds with SSH_MSG_USERAUTH_SUCCESS and the 
		authentication exchange terminates.

		b. Server responds to method "password" with 
		SSH_MSG_USERAUTH_FAILURE, the client may retry step 1 if permitted 
		by the server as described in the SSH specification.

		c. Server responds to method "publickey" with 
		SSH_MSG_USERAUTH_FAILURE and the authentication exchange terminates.

   This is a simplified form of what's given in the SSH spec, which allows
   almost any jumble of messages including ones that don't make any sense 
   (again, see the SimpleSSH draft for more details - if any aspiring 
   academic is looking for an easy-win publication, try attacking this 
   dog's-breakfast exchange process).  
   
   The credential-type matching that we perform in processUserAuth() is 
   indicated by the caller supplying one of the following values:

	NONE_PRESENT: No existing user name or password to match against, store 
		the client's user name and password for the caller to check.

	USERNAME_PRESENT: Existing user name present from a previous iteration 
		of authentication, match the client's user name to the existing one 
		and store the client's password for the caller to check.

	USERNAME_PASSWORD_PRESENT: Caller-supplied credentials present, match 
		the client's credentials against them.

	USERNAME_PUBKEY_PRESENT: Partial public-key authentication started in 
		the previous round, complete the public-key authentication */

typedef enum {
	CREDENTIAL_NONE,		/* No credential information type */
	CREDENTIAL_NONE_PRESENT,/* No credentials present */
	CREDENTIAL_USERNAME_PRESENT,
							/* User name is present and must match */
	CREDENTIAL_USERNAME_PASSWORD_PRESENT,
							/* User/password present and must match */
	CREDENTIAL_USERNAME_PUBKEY_PRESENT,
							/* User/public key present and must match */
	CREDENTIAL_LAST			/* Last possible credential information type */
	} CREDENTIAL_TYPE;

/* The processUserAuth() function has multiple possible return values, 
   broken down into CRYPT_OK for a password match, OK_SPECIAL for something 
   that the caller has to handle, and the standard error status, with 
   subvalues given in the userAuthInfo variable.  The different types and
   subtypes are:

	CRYPT_OK + uAInfo = USERAUTH_SUCCESS: User credentials present and 
		matched. Note that the caller has to check both of these values, one 
		a return status and the other a by-reference parameter, to avoid a 
		single point of failure for the authentication.

	OK_SPECIAL + uAInfo = USERAUTH_CALLERCHECK: User credentials not 
		present, added to the session attributes for the caller to check.

	OK_SPECIAL + uAInfo = USERAUTH_NOOP: No-op read for a client query of 
		available authentication methods via the pseudo-method "none".

	OK_SPECIAL + uAInfo = USERAUTH_NOOP_2: Additional no-op read for a 
		client partial public-key authentication without a signature, 
		requiring another round of messages to get a public-key 
		authentication with a signature.

	Error + uAInfo = USERAUTH_ERROR: Standard error status, which includes 
		non-matched credentials */

typedef enum {
	USERAUTH_NONE,			/* No authentication type */
	USERAUTH_SUCCESS,		/* User authenticated successfully */
	USERAUTH_CALLERCHECK,	/* Caller must check whether auth.was successful */
	USERAUTH_NOOP,			/* No-op read */
	USERAUTH_NOOP_2,		/* Public-key authentication no-op */
	USERAUTH_ERROR,			/* User failed authentication */
	USERAUTH_ERROR_RETRY,	/* Failed authentication, password retry allowed */
	USERAUTH_LAST			/* Last possible authentication type */
	} USERAUTH_TYPE;

/* The state of progress through the authentication process, used to 
   indicate special handling for the first message from the client and the
   need for a fatal authentication failure rather than a retry request for
   the last authentication attempt that we allow.  There's also a special
   password-only progress state to indicate that retries are allowed but
   only for passwords */

typedef enum {
	AUTHSTATE_NONE,			/* No authentication state */
	AUTHSTATE_FIRST_MESSAGE,/* First message from client */
	AUTHSTATE_IN_PROGRESS,	/* Authentication in progress */
	AUTHSTATE_IN_PROGRESS_PWONLY,/* In progress but only passwords */
	AUTHSTATE_FINAL_MESSAGE,/* Final message allowed from client */
	AUTHSTATE_LAST			/* Last possible authentication state */
	} AUTHSTATE_TYPE;

/* The client sends the following as the first part of each message, 
   representing a query, password authentication, or public-key 
   authentication:

	byte	type = SSH_MSG_USERAUTH_REQUEST
	string	user_name
	string	service_name = "ssh-connection"
	string	method_name = "none" | "password" | "publickey"
	[...]

   Handling of the case where two different user names are supplied in 
   different messages gets a bit tricky because if both names are present in 
   the list of set-by-the-caller credentials then we'll get a successful 
   match both times even though a different user name was used.  To detect 
   this we record the initial user name in the SSH session information and 
   check it against subsequently supplied values.  We do the same for the 
   keyID for public-key authentication.
   
   In this case the "Store" for the username/keyID in the tables below means 
   that it's recorded for future rounds of authentication to allow for 
   consistency checks denoted by "Check", but not added to the session 
   attributes, while "Add" means that it's added to the session attributes 
   and matched with "Match".  

   If an error status is returned then any value other than 
   CRYPT_ERROR_WRONGKEY for passwords is treated as a fatal error.  
   CRYPT_ERROR_WRONGKEY for a password is nonfatal as determined by the 
   caller, for example until some predefined retry count has been exceeded.

   These are the match options with a caller-supplied list of userame+
   password credentials to match against, the letter and number corresponds
   to locations in the code where that condition is enforced:

	Client sends | Credentials	| Action					| Result
				 | present		|							|
	-------------+--------------+---------------------------+--------------
	Name, "pass" | _USERNAME_PW	| Store name				|			 A1
				 |				| Match name, password		| SUCCESS/ERROR
	-------------+--------------+---------------------------+--------------
	Name, "none" | _USERNAME_PW	| Store name				| NOOP		 A2
	Name, "none" | _USERNAME_PW	| Error						| ERROR (fatal)
	-------------+--------------+---------------------------+--------------
	Name, "none" | _USERNAME_PW	| Store name				| NOOP		 A3
	Name, "pass" | _USERNAME_PW	| Check/match name, password| SUCCESS/ERROR
	-------------+--------------+---------------------------+--------------
	Name, "none" | _USERNAME_PW	| Store name				| NOOP		 A4
	Name2, "pass"| _USERNAME_PW	| Check name2 -> Fail		| ERROR (fatal)
	-------------+--------------+---------------------------+--------------
	Name, "pass" | _USERNAME_PW	| Store/match name, wrong	|			 A5
		  (wrong}|				|	password -> Fail		| ERROR
	Name, "pass" | _USERNAME_PW	| Check/match name, password| SUCCESS/ERROR
	-------------+--------------+---------------------------+--------------
	Name, "pass" | _USERNAME_PW	| Store/match name, wrong	|			 A6
		  (wrong}|				|	password -> Fail		| ERROR
	Name,"pubkey"| _USERNAME_PW	| Error						| ERROR (fatal)

   The match options with no caller-supplied list of credentials to match 
   against are:

	Client sends | Credentials	| Action					| Result
				 | present		|							|
	-------------+--------------+---------------------------+--------------
	Name, "pass" | _NONE		| Store/add name, password	| CALLERCHECK B1
	-------------+--------------+---------------------------+--------------
	Name, "none" | _NONE		| Store/add name			| NOOP		 B2
	Name, "none" | _USERNAME	| Error						| ERROR (fatal)
	-------------+--------------+---------------------------+--------------
	Name, "none" | _NONE		| Store/add name			| NOOP		 B3
	Name, "pass" | _USERNAME	| Check/match name,			|
				 |				|	add password			| CALLERCHECK
	-------------+--------------+---------------------------+--------------
	Name, "none" | _NONE		| Store/add name			| NOOP		 B4
	Name2, "pass"| _USERNAME	| Check name2 -> Fail		| ERROR (fatal)
	-------------+--------------+---------------------------+--------------
	Name, "pass" | _NONE		| Store/add name, password	| CALLERCHECK
		  (wrong)|				|							|			 B5
	Name, "pass" | _USERNAME	| Check/match name,			|
				 |				|	update password			| CALLERCHECK
	-------------+--------------+---------------------------+--------------
	Name, "pass" | _NONE		| Store/add name, password	| CALLERCHECK
		  (wrong)|				|							|			 B6
	Name,"pubkey"| _USERNAME	| Error						| ERROR (fatal)

   Finally the match options for public-key authentication, these are 
   dependent on the presence of a public-key database rather than a list of 
   credentials (or lack thereof).  We don't list things like the Name/Name2
   sequence because they're already handled as part of the password 
   processing above and it would make the table rather large with all of the
   extra states.

	Client sends | Credentials	| Action					| Result
				 | present		|							|
	-------------+--------------+---------------------------+--------------
	Name,"pubkey"| _NONE		| Store/add name, keyID		| SUCCESS/ERROR
		  (+sig) |				| Check pkauth				|			 C1
	-------------+--------------+---------------------------+--------------
	Name, "none" | _NONE		| Store/add name			| NOOP		 C2
	Name, "none" | _USERNAME	| Error						| ERROR (fatal)
	-------------+--------------+---------------------------+--------------
	Name,"pubkey"| _NONE		| Store/add name, keyID		| NOOP_2	 C3
	Name,"pubkey"| _USERNAME_PK	| Check/match name, keyID	|
		  (+sig) |				|	Verify pkauth			| SUCCESS/ERROR
	-------------+--------------+---------------------------+--------------
	Name, "none" | _NONE		| Store/add name			| NOOP		 C4
	Name,"pubkey"| _USERNAME_PK	| Check/match name,			|
				 |				|	add keyID				| NOOP_2
	Name,"pubkey"| _USERNAME_PK	| Check/match name, keyID	|
		  (+sig) |				|	Verify pkauth			| SUCCESS/ERROR
	-------------+--------------+---------------------------+--------------
	Name,"pubkey"| _NONE		| Store/add name, keyID		| NOOP_2	 C5
	Name,"pubkey"| _USERNAME_PK	| Error						| ERROR (fatal)
	-------------+--------------+---------------------------+--------------
	Name,"pubkey"| _NONE		| Store/add name, keyID		| NOOP_2	 C6
	Name,"pubk2" | _USERNAME_PK	| Check/match name, keyID	|
		 (+sig)	 |				|	-> Fail					| ERROR (fatal)
	-------------+--------------+---------------------------+--------------
	Name,"pubkey"| _NONE		| Store/add name, keyID		| NOOP_2	 C7
	Name,"pass"	 | _USERNAME_PK	| Error						| ERROR (fatal) */

/* A lookup table for the authentication methods submitted by the client.  

   Some servers also do "keyboard-interactive" (misnamed PAM) which extends
   the dog's-breakfast to throw in breakfast for all of its puppies as well, 
   this can among other things be used as an alternative for password 
   authentication but we don't support it because we already do passwords
   and it just makes the authentication mess even bigger and harder to 
   handle safely.
   
   There's also a "hostbased" authentication type which is just public-key
   authentication without allowing all of the Lucy-and-Charlie-Brown steps
   but also adding the remote host name and user name on that host.  The 
   idea is that there's a single key used for the remote host and that 
   vouches for all users on it, a bit like rhosts.  Since most of our usage
   is for machine-to-machine comms we could in theory add this because
   there's only ever one host and one (pseudo-)user on it so it just becomes
   a differently-labelled public-key authentication, but so far everyone's
   just used actual public-key authentication in this role */

typedef struct {
	BUFFER_FIXED( nameLength ) \
	const char *name;			/* Authtype name */
	const int nameLength;
	const SSH_AUTHTYPE_TYPE type;	/* Authentication type */
	} AUTHTYPE_INFO;

static const AUTHTYPE_INFO authTypeInfoPasswordTbl[] = {
	{ "none", 4, SSH_AUTHTYPE_QUERY },
	{ "password", 8, SSH_AUTHTYPE_PASSWORD },
	{ NULL, 0, SSH_AUTHTYPE_NONE }, { NULL, 0, SSH_AUTHTYPE_NONE }
	};
static const AUTHTYPE_INFO authTypeInfoTbl[] = {
	{ "none", 4, SSH_AUTHTYPE_QUERY },
	{ "password", 8, SSH_AUTHTYPE_PASSWORD },
	{ "publickey", 9, SSH_AUTHTYPE_PUBKEY },
	{ NULL, 0, SSH_AUTHTYPE_NONE }, { NULL, 0, SSH_AUTHTYPE_NONE }
	};

/* Storage for the information in the userAuth packet header */

typedef struct AI {
	/* Method and user names and optional password for password 
	   authentication */
	BUFFER( CRYPT_MAX_TEXTSIZE, methodNameLength ) \
	BYTE methodName[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, userNameLength ) \
	BYTE userName[ CRYPT_MAX_TEXTSIZE + 8 ];
	BUFFER( CRYPT_MAX_TEXTSIZE, passwordLength ) \
	BYTE password[ CRYPT_MAX_TEXTSIZE + 8 ];
	int methodNameLength, userNameLength, passwordLength;

	/* Kludge flag used to indicate that the payload portion of a method-
	   specific packet needs special-case handling */
	BOOLEAN kludgeFlag;
	} AUTH_INFO;

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Send a succeeded/failed-authentication response to the client:

	byte	type = SSH_MSG_USERAUTH_SUCCESS

   or

	byte	type = SSH_MSG_USERAUTH_FAILURE
	string	allowed_authent = empty
	boolean	partial_success = FALSE 

   or

	byte	type = SSH_MSG_USERAUTH_FAILURE
	string	allowed_authent = "publickey" / "password"
	boolean	partial_success = FALSE

   The latter two variants are necessary because the failure response is
   overloaded to perform two functions, firstly to indicate that the 
   authentication failed and secondly to provide a list of methods that can
   be used to authenticate (see the comment at the start of this module for
   the calisthentics that are required to support this).
   
   The partial_success flag is used when multiple rounds of authentication
   are required to tell the caller to keep going with more authentication,
   since this is a pure pass/fail response we always set it to FALSE */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sendResponseSuccess( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	
	status = openPacketStreamSSH( &stream, sessionInfoPtr, 
								  SSH_MSG_USERAUTH_SUCCESS );
	if( cryptStatusError( status ) )
		return( status );
	status = wrapSendPacketSSH2( sessionInfoPtr, &stream );
	sMemDisconnect( &stream );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sendResponseFailure( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Straight failure response */
	status = openPacketStreamSSH( &stream, sessionInfoPtr, 
								  SSH_MSG_USERAUTH_FAILURE );
	if( cryptStatusError( status ) )
		return( status );
	writeUint32( &stream, 0 );
	status = sputc( &stream, 0 );
	if( cryptStatusOK( status ) )
		status = wrapSendPacketSSH2( sessionInfoPtr, &stream );
	sMemDisconnect( &stream );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sendResponseFailureInfo( INOUT_PTR SESSION_INFO *sessionInfoPtr,
									IN_BOOL const BOOLEAN allowPubkeyAuth )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isBooleanValue( allowPubkeyAuth ) );

	/* Failure response but really a means of telling the client how they 
	   can authenticate.  What to send as the allowed method is a bit 
	   tricky, if the caller tells us that publickey authentication is 
	   allowed then we can always send that, but it's not clear whether we 
	   can say that password authentication is OK or not.  In theory we 
	   could check whether a password is present in the attribute list, but 
	   the caller could be performing on-demand checking without explicitly 
	   setting a password attribute so there's no way to tell whether 
	   passwords should be allowed or not.  Because of this we always 
	   advertise password authentication as being available */
	status = openPacketStreamSSH( &stream, sessionInfoPtr, 
								  SSH_MSG_USERAUTH_FAILURE );
	if( cryptStatusError( status ) )
		return( status );
	if( allowPubkeyAuth )
		writeString32( &stream, "publickey,password", 18 );
	else
		writeString32( &stream, "password", 8 );
	status = sputc( &stream, 0 );
	if( cryptStatusOK( status ) )
		status = wrapSendPacketSSH2( sessionInfoPtr, &stream );
	sMemDisconnect( &stream );

	return( status );
	}

/* Check that the query form and credentials submitted by the client are 
   consistent with any information submitted during earlier rounds of 
   authentication */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int storeQueryParams( INOUT_PTR SSH_INFO *sshInfo,
							 IN_BUFFER( userNameLength ) const void *userName,
							 IN_LENGTH_TEXT const int userNameLength,
							 IN_ENUM( SSH_AUTHTYPE ) \
									const SSH_AUTHTYPE_TYPE initialAuthType )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	BYTE userNameHash[ KEYID_SIZE + 8 ];

	assert( isWritePtr( sshInfo, sizeof( SSH_INFO ) ) );
	assert( isReadPtrDynamic( userName, userNameLength ) );

	REQUIRES( userNameLength >= 1 && userNameLength <= CRYPT_MAX_TEXTSIZE );
	REQUIRES( isEnumRange( initialAuthType, SSH_AUTHTYPE ) );

	/* Hash the user name so that we only need to store the fixed-length 
	   hash rather than the variable-length user name */
	getHashAtomicParameters( CRYPT_ALGO_SHA1, 0, &hashFunctionAtomic, NULL );
	hashFunctionAtomic( userNameHash, KEYID_SIZE, userName, userNameLength );

	/* Remember the user name and authentication method so that we can check 
	   them on subsequent rounds of authentication */
	memcpy( sshInfo->prevAuthUserNameHash, userNameHash, KEYID_SIZE );
	sshInfo->prevAuthType = initialAuthType;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkQueryValidity( INOUT_PTR SSH_INFO *sshInfo,
							   IN_BUFFER( userNameLength ) const void *userName,
							   IN_LENGTH_TEXT const int userNameLength,
							   IN_ENUM( SSH_AUTHTYPE ) \
									const SSH_AUTHTYPE_TYPE currentAuthType )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	BYTE userNameHash[ KEYID_SIZE + 8 ];

	assert( isWritePtr( sshInfo, sizeof( SSH_INFO ) ) );
	assert( isReadPtrDynamic( userName, userNameLength ) );

	REQUIRES( userNameLength >= 1 && userNameLength <= CRYPT_MAX_TEXTSIZE );
	REQUIRES( isEnumRange( currentAuthType, SSH_AUTHTYPE ) );

	/* Hash the user name so that we can compare it to the stored hash 
	   value */
	getHashAtomicParameters( CRYPT_ALGO_SHA1, 0, &hashFunctionAtomic, NULL );
	hashFunctionAtomic( userNameHash, KEYID_SIZE, userName, userNameLength );

	/* If the client is switching credentials across authentication messages 
	   then there's something fishy going on (A4, B4) */
	if( compareDataConstTime( sshInfo->prevAuthUserNameHash, userNameHash, 
							  KEYID_SIZE ) != TRUE )
		return( CRYPT_ERROR_INVALID );

	/* Make sure that the authentication messages follow the state 
	   transitions:

		<empty> -> query -> auth_method
		<empty> ----------> auth_method

	   There are two error cases that can occur here, either the client 
	   sends multiple authentication requests with the pseudo-method "none"
	   (SSH's way of performing a method query) or they send a request with
	   a different method than a previous one, for example "password" in the
	   initial request and then "publickey" in a following one */
	if( sshInfo->prevAuthType == SSH_AUTHTYPE_QUERY )
		{
		/* If we've already processed a query message then any subsequent 
		   message has to be an actual authentication message (A2, B2, C2) */
		if( currentAuthType == SSH_AUTHTYPE_QUERY )
			return( CRYPT_ERROR_DUPLICATE );

		/* A query must be followed by a standard authentication method.  
		   This also catches the previous case but we special-case it to 
		   provide a more appropriate error message */
		if( currentAuthType != SSH_AUTHTYPE_PASSWORD && \
			currentAuthType != SSH_AUTHTYPE_PUBKEY )
			return( CRYPT_ERROR_INVALID );

		/* We've had a query followed by a standard authentication method, 
		   remember the authentication method for later */
		sshInfo->prevAuthType = currentAuthType;
		return( CRYPT_OK );
		}

	/* If we've already seen a standard authentication method then the new 
	   method must be the same (A6, B6, C7) */
	if( sshInfo->prevAuthType != currentAuthType )
		return( CRYPT_ERROR_INVALID );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Password Authentication Functions					*
*																			*
****************************************************************************/

/* Process password authentication */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processPasswordAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							    IN_PTR const AUTH_INFO *authInfo,
								IN_PTR const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( authInfo, sizeof( AUTH_INFO ) ) );
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* Beyond normal password authentication the client can also set the 
	   kludgeFlag to indicate that it wants to change the password.  The RFC
	   never says what you're supposed to do in response to this if you're
	   not expecting it (it's normally explicitly requested by having the
	   server send a SSH_MSG_USERAUTH_PASSWD_CHANGEREQ): "The client MAY 
	   also send this message instead of the normal password authentication 
	   request without the server asking for it".  However later text only
	   allows us to respond with SSH_MSG_USERAUTH_FAILURE if we don't change
	   the password, so we reject any messages that have the kludgeFlag set */
	if( authInfo->kludgeFlag )
		{
#ifdef USE_ERRMSGS
		BYTE userNameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];

		REQUIRES( rangeCheck( authInfo->userNameLength, \
							  1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( userNameBuffer, authInfo->userName, 
				authInfo->userNameLength );
#endif /* USE_ERRMSGS */
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, SESSION_ERRINFO, 
				  "User '%s' sent unauthorised password-change request", 
				  sanitiseString( userNameBuffer, CRYPT_MAX_TEXTSIZE,
								  authInfo->userNameLength ) ) );
		}

	/* Move on to the password associated with the user name */
	REQUIRES( DATAPTR_ISVALID( attributeListPtr->next ) );
	attributeListPtr = DATAPTR_GET( attributeListPtr->next );
	ENSURES( attributeListPtr != NULL && \
			 attributeListPtr->attributeID == CRYPT_SESSINFO_PASSWORD );
			 /* Ensured by checkMissingInfo() in sess_iattr.c */

	/* Make sure that the password matches.  Note that in the case of an 
	   error we don't report the incorrect password that was entered since 
	   we don't want it appearing in logfiles (A1, A3, A5) */
	if( authInfo->passwordLength != attributeListPtr->valueLength || \
		compareDataConstTime( authInfo->password, attributeListPtr->value, 
							  authInfo->passwordLength ) != TRUE )
		{
#ifdef USE_ERRMSGS
		BYTE userNameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];

		REQUIRES( rangeCheck( authInfo->userNameLength, \
							  1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( userNameBuffer, authInfo->userName, 
				authInfo->userNameLength );
#endif /* USE_ERRMSGS */
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "Invalid password for user '%s'", 
				  sanitiseString( userNameBuffer, CRYPT_MAX_TEXTSIZE,
								  authInfo->userNameLength ) ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Public-key Authentication Functions					*
*																			*
****************************************************************************/

/* Read the public key value that'll be used for public-key authentication:

	[...]
	string		"ssh-rsa"	"ssh-dss"	"ecdsa-sha2-*"
	string		[ client key/certificate ]
		string	"ssh-rsa"	"ssh-dss"	"ecdsa-sha2-*"
		mpint	e			p			Q
		mpint	n			q
		mpint				g
		mpint				y
	[...] */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPublicKey( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR STREAM *stream,
						  const BOOLEAN isInitialAuth )
	{
	CRYPT_ALGO_TYPE pubkeyAlgo;
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	BYTE keyID[ KEYID_SIZE + 8 ];
	void *keyPtr DUMMY_INIT_PTR;
	int keyLength, dummy, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isBooleanValue( isInitialAuth ) );

	/* Skip the first of the three copies of the algorithm name (see the 
	   comment in ssh2_cli.c for more on this).  We don't do anything with 
	   it because we're about to get two more copies of the same thing, and 
	   the key and signature information take precedence over anything that 
	   we find here */
	status = readUniversal32( stream );
	if( cryptStatusError( status ) )
		return( status );
	
	/* Read the client's public key */	
	streamBookmarkSet( stream, keyLength );
	status = checkReadPublicKey( stream, &pubkeyAlgo, &dummy, 
								 SESSION_ERRINFO );
	if( cryptStatusOK( status ) )
		{
		status = streamBookmarkComplete( stream, &keyPtr, &keyLength, 
										 keyLength );
		}
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid client public-key data" ) );
		}

	/* Import the public-key data into a context */
	setMessageCreateObjectInfo( &createInfo, pubkeyAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, keyPtr, keyLength );
	status = krnlSendMessage( createInfo.cryptHandle, 
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_KEY_SSH );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( cryptArgError( status ) ? \
				CRYPT_ERROR_BADDATA : status,
				( cryptArgError( status ) ? \
				  CRYPT_ERROR_BADDATA : status, SESSION_ERRINFO, 
				  "Invalid client public-key value" ) );
		}

	/* Yet another location where it's possible for an attacker to perform a
	   Lucy-and-Charlie-Brown rugpull, this time by swapping out keys during
	   the multiple rounds of authentication.  Since we always respond to a 
	   public-key authentication request with PK_OK (see the comment in 
	   processPubkeyAuth()), effectively ignoring the initial copy of the 
	   public-key that's sent, we're not affected by this, but we make the 
	   check explicit here in case a future code change alters this */
	setMessageData( &msgData, keyID, KEYID_SIZE );
	status = krnlSendMessage( createInfo.cryptHandle, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	if( isInitialAuth )
		{
		/* This is the first authentication-exchange message, remember 
		   the key that was presented */
		memcpy( sshInfo->prevAuthKeyID, keyID, KEYID_SIZE );
		}
	else
		{
		/* It's a subsequent message, make sure that the key remains the 
		   same.  We use the same error message that checkQueryValidity() 
		   produces since this check is a logical extension of the one
		   performed there (C6) */
		if( compareDataConstTime( sshInfo->prevAuthKeyID, keyID, 
								  KEYID_SIZE ) != TRUE )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
					  "Client supplied different credentials than the ones "
					  "supplied during a previous authentication attempt" ) );
			}
		}
	sessionInfoPtr->iKeyexAuthContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/* Read and verify the public-key authentication signature:

	[...]
	string		[ client signature ]
		string	"ssh-rsa"	"ssh-dss"	"ecdsa-sha2-*"
		string	signature
	[...] */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int checkPublicKeySig( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  const SSH_HANDSHAKE_INFO *handshakeInfo, 
							  INOUT_PTR STREAM *stream,
							  IN_BUFFER( userNameLength ) const void *userName, 
							  IN_LENGTH_TEXT const int userNameLength )
	{
	MESSAGE_KEYMGMT_INFO getkeyInfo DUMMY_INIT_STRUCT;
	MESSAGE_DATA msgData;
	BYTE keyID[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE holderName[ CRYPT_MAX_TEXTSIZE + 8 ];
	void *packetDataPtr DUMMY_INIT_PTR;
	int pkcAlgo;		/* enum vs. int */
	int packetDataLength, holderNameLen, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( userName, userNameLength ) );

	REQUIRES( userNameLength > 0 && userNameLength <= CRYPT_MAX_TEXTSIZE );

	/* Find out which algorithm we're dealing with, which affects how the
	   signature check is done */
	status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
							  IMESSAGE_GETATTRIBUTE, &pkcAlgo, 
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		{
		/* This is a can't-occur error condition so we convert it into 
		   something more meaningful in this context */
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Make sure that this key is valid for authentication purposes, in 
	   other words that it's present in the authentication keyset.
	   
	   Note that this uses a not-entirely-reliable means of identifying the
	   key in the database in that CRYPT_IKEYID_KEYID is the 
	   subjectKeyIdentifier of the certificate if this is present, otherwise
	   a hash of the subjectPublicKey.  If the sKID is in a cryptlib-created 
	   certificate then the two are the same thing, but a certificate coming
	   from an external CA may contain arbitrary data for the sKID.  
	   However, since it's unlikely that someone is performing SSH client 
	   authentication using a certificate from a commercial CA, it seems 
	   safe to assume that any certificate present will be a cryptlib-
	   generated one used as a bit-bagging mechanism to get the key into a 
	   database, and therefore that sKID == hash( subjectPublicKey ) (C1a, 
	   C3a, C4a) */
	setMessageData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusError( status ) )
		{
		/* This is a can't-occur error condition since there's always a keyID
		   present, we just need to handle it specially since anything beyond
		   this point uses the keyID in the error message */
		return( CRYPT_ERROR_PERMISSION );
		}
	if( !isHandleRangeValid( sessionInfoPtr->cryptKeyset ) )
		{
		/* If there's no keyset present to check against, report the key as
		   not-present.  This is already checked for in processUserAuth()
		   which disallows "publickey" as an authentication type if there's 
		   no public-key keyset present, this is just a redundant check and 
		   is turned into a general key-not-trusted error below so we really 
		   just need to set any sort of error status */
		status = CRYPT_ERROR_NOTFOUND;
		}
	else
		{
		setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID, 
							   msgData.data, msgData.length, NULL, 0, 
							   KEYMGMT_FLAG_NONE );
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset, 
								  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
								  KEYMGMT_ITEM_PUBLICKEY );
		}
	if( cryptStatusError( status ) )
		{
#ifdef USE_ERRMSGS
		char keyIDText[ CRYPT_MAX_TEXTSIZE + 8 ];

		formatHexData( keyIDText, CRYPT_MAX_TEXTSIZE, keyID, 
					   msgData.length );
#endif /* USE_ERRMSGS */
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, SESSION_ERRINFO, 
				  "Client public key with ID '%s' is not trusted for "
				  "authentication purposes", keyIDText ) );
		}

	/* Check that the name in the certificate matches the supplied user 
	   name (C1b, C3b, C4b) */
	setMessageData( &msgData, holderName, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( getkeyInfo.cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_HOLDERNAME );
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DESTROY );
	if( cryptStatusOK( status ) )
		{
		holderNameLen = msgData.length;
		if( userNameLength != holderNameLen || \
			compareDataConstTime( userName, holderName, 
								  userNameLength ) != TRUE )
			status = CRYPT_ERROR_INVALID;
		}
	else
		{
		memcpy( holderName, "<Unknown>", 9 );
		holderNameLen = 9;
		}
	if( cryptStatusError( status ) )
		{
#ifdef USE_ERRMSGS
		BYTE userNameBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];

		REQUIRES( rangeCheck( userNameLength, 1, CRYPT_MAX_TEXTSIZE ) );
		memcpy( userNameBuffer, userName, userNameLength );
#endif /* USE_ERRMSGS */
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Client public key name '%s' doesn't match supplied user "
				  "name '%s'", 
				  sanitiseString( holderName, CRYPT_MAX_TEXTSIZE, 
								  holderNameLen ),
				  sanitiseString( userNameBuffer, CRYPT_MAX_TEXTSIZE, 
								  userNameLength ) ) );
		}

	/* Get a pointer to the portion of the packet that gets signed */
	status = packetDataLength = stell( stream );
	if( !cryptStatusError( status ) )
		{
		status = sMemGetDataBlockAbs( stream, 0, &packetDataPtr, 
									  packetDataLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Process the signature on the authentication data, with the usual 
	   special-snowflake handling for the Bernstein algorithms (C1c, C3c, 
	   C4c) */
#ifdef USE_ED25519
	if( isBernsteinAlgo( pkcAlgo ) )
		{
		return( processAuthDataSigBernstein( sessionInfoPtr, handshakeInfo, 
											 stream, packetDataPtr, 
											 packetDataLength, pkcAlgo, 
											 FALSE ) );
		}
#endif /* USE_ED25519 */
	return( processAuthDataSig( sessionInfoPtr, handshakeInfo, stream,
								packetDataPtr,packetDataLength, pkcAlgo, 
								FALSE ) );
	}

/* Process public-key authentication */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int processPubkeyAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  IN_PTR const SSH_HANDSHAKE_INFO *handshakeInfo, 
							  IN_PTR const AUTH_INFO *authInfo,
							  INOUT_PTR STREAM *stream,
							  IN_ENUM( CREDENTIAL ) \
									const CREDENTIAL_TYPE credentialType )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( authInfo, sizeof( AUTH_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isEnumRange( credentialType, CREDENTIAL ) );

	/* In yet another variant of SSH's Lucy-and-Charlie-Brown authentication 
	   process, for public-key authentication the client can supply a public 
	   key but omit the signature, in which case the server has to go through 
	   yet another round of messages exchanged in the hope of eventually 
	   getting the actual authentication data */
	if( !authInfo->kludgeFlag )
		{
		STREAM responseStream;
		int pkcAlgo;

		/* Repeated partial public-key authentication messages are a sign that 
		   something is wrong (C5) */
		if( credentialType == CREDENTIAL_USERNAME_PUBKEY_PRESENT )
			{
			( void ) sendResponseFailure( sessionInfoPtr );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Client sent duplicate partial public-key "
					  "authentication request" ) );
			}

		/* If we're given a public-key authentication message with the 
		   signature missing then we have to send back a copy of the public 
		   key algorithm name and data, presumably to confirm that the three 
		   copies the client sent us arrived in good order.  We always send 
		   this response in order to avoid account enumeration attacks since 
		   the client is going to follow it up with their public-key 
		   authentication anyway:
			   
			byte	type = SSH_MSG_USERAUTH_PK_OK
			string	pubkey_algorithm_from_request
			string	pubkey_data_from_request
		
		   There's no obvious reason for this process, and no implementation 
		   that bothers with this additional unnecessary step appears to 
		   check the returned data except for OpenSSH, and even that only 
		   checks it as an implementation artefact.  
			   
		   What OpenSSH does is throw every key it has available at the 
		   server until it finds one that sticks, however it doesn't 
		   remember which key was sent in which request but relies on the 
		   server's response to tell it which one it was.  It's likely that 
		   this message only exists as an OpenSSH quirk that got written 
		   into the spec, and as implemented in OpenSSH it allows a server 
		   to request authentication from a key other than the one the 
		   client thinks it's using by sending back an ACK for key B when 
		   the client has proposed key A.
		   
		   This allows makes it very easy to fingerprint users, and there's
		   even a demo SSH server that does this, 
		   https://github.com/FiloSottile/whoami.filippo.io, greeting you by 
		   name when you connect via SSH (no user interaction required) and 
		   have your name on Github.
			   
		   There was an attempt to fix the OpenSSH problem in 2021 by 
		   forcing the issue with a CVE, see
		   https://github.com/openssh/openssh-portable/pull/270#issuecomment-920577097,
		   but the OpenSSH maintainers rejected the patch, so it looks like 
		   it'll be with us in perpetuity.

		   Because only OpenSSH appears to bother checking this message, we 
		   send back an easter egg for any other implementation to catch 
		   anything that we're not currently aware of that does actually 
		   check what's coming back.  In the years since this code was 
		   written no-one has ever reported a problem */
		status = openPacketStreamSSH( &responseStream, sessionInfoPtr, 
									  SSH_MSG_USERAUTH_PK_OK );
		if( cryptStatusError( status ) )
			return( status );
		if( TEST_FLAG( sessionInfoPtr->protocolFlags, 
					   SSH_PFLAG_CHECKSPKOK ) )
			{
			status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
									  IMESSAGE_GETATTRIBUTE, &pkcAlgo, 
									  CRYPT_CTXINFO_ALGO );
			if( cryptStatusOK( status ) )
				{
				status = writeAlgoStringEx( &responseStream, pkcAlgo, 
											handshakeInfo->hashAlgo, 
											CRYPT_UNUSED,
											SSH_ALGOSTRINGINFO_NONE );
				}
			if( cryptStatusOK( status ) )
				{
				status = exportAttributeToStream( &responseStream, 
										sessionInfoPtr->iKeyexAuthContext,
										CRYPT_IATTRIBUTE_KEY_SSH );
				}
			}
		else
			{
			writeString32( &responseStream, 
						   "Surprise! Does anything check this?", 35 );
			status = writeString32( &responseStream, "Blah, blah, blah, "
									"stolen plans, blah, blah, blah, "
									"missing scientist, blah, blah, blah, "
									"atom bomb, blah, blah, blah", 114 );
			}						/* Vote for Nosh! */
		if( cryptStatusOK( status ) )
			status = wrapSendPacketSSH2( sessionInfoPtr, &responseStream );
		sMemDisconnect( &responseStream );
		if( cryptStatusError( status ) )
			return( status );

		/* Since the client is going to send us yet another copy of the key 
		   in the next iteration, we destroy the one that we've just read so 
		   that we can re-read it again in a second.  We don't cache the key
		   because we need to actually read the new copy when it arrives to
		   check that it's the same as the one that we've just seen */
		krnlSendNotifier( sessionInfoPtr->iKeyexAuthContext, 
						  IMESSAGE_DESTROY );
		sessionInfoPtr->iKeyexAuthContext = CRYPT_ERROR;

		return( OK_SPECIAL );
		}

	/* Check the signature on the authentication data */
	return( checkPublicKeySig( sessionInfoPtr, handshakeInfo, stream,
							   authInfo->userName, 
							   authInfo->userNameLength ) );
	}

/****************************************************************************
*																			*
*						Verify the Client's Authentication					*
*																			*
****************************************************************************/

/* Read the common data at the start of the userAuth packet:

	byte	type = SSH_MSG_USERAUTH_REQUEST
	string	user_name
	string	service_name = "ssh-connection"
	string	method_name = "none" | "password" | "publickey"
  [	boolean	FALSE/TRUE								-- For password, public-key ]
	[...] */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int readAuthPacketHeader( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 OUT_PTR AUTH_INFO *authInfo,
								 INOUT_PTR STREAM *stream,
								 OUT_ENUM( SSH_AUTHTYPE ) \
									SSH_AUTHTYPE_TYPE *authType )
	{
	const BOOLEAN allowPubkeyAuth = \
			( sessionInfoPtr->cryptKeyset != CRYPT_ERROR ) ? TRUE : FALSE;
	const AUTHTYPE_INFO *authTypeInfoTblPtr = allowPubkeyAuth ? \
			authTypeInfoTbl : authTypeInfoPasswordTbl;
	const int authTypeInfoTblSize = allowPubkeyAuth ? \
			FAILSAFE_ARRAYSIZE( authTypeInfoTbl, AUTHTYPE_INFO ) : \
			FAILSAFE_ARRAYSIZE( authTypeInfoPasswordTbl, AUTHTYPE_INFO );
	const AUTHTYPE_INFO *authTypeInfoPtr = NULL;
	BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	LOOP_INDEX i;
	int stringLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( authInfo, sizeof( AUTH_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( authType, sizeof( SSH_AUTHTYPE_TYPE ) ) );

	/* Clear return value */
	memset( authInfo, 0, sizeof( AUTH_INFO ) );
	*authType = SSH_AUTHTYPE_NONE;

	/* Read the user name, service name, and authentication method type */
	status = readString32( stream, authInfo->userName, CRYPT_MAX_TEXTSIZE, 
						   &authInfo->userNameLength );
	if( cryptStatusError( status ) || \
		authInfo->userNameLength <= 0 || \
		authInfo->userNameLength > CRYPT_MAX_TEXTSIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid user-authentication user name" ) );
		}
	status = readString32( stream, stringBuffer, CRYPT_MAX_TEXTSIZE, 
						   &stringLength );
	if( cryptStatusOK( status ) )
		{
		if( stringLength != 14 || \
			memcmp( stringBuffer, "ssh-connection", 14 ) )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusOK( status ) )
		{
		status = readString32( stream, authInfo->methodName, 
							   CRYPT_MAX_TEXTSIZE, 
							   &authInfo->methodNameLength );
		}
	if( cryptStatusOK( status ) )
		{
		if( authInfo->methodNameLength <= 0 || \
			authInfo->methodNameLength > CRYPT_MAX_TEXTSIZE )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid user-authentication service or method name" ) );
		}
	INJECT_FAULT( CORRUPT_ID, SESSION_CORRUPT_ID_SSH_1 );

	/* Check which authentication method the client has requested */
	LOOP_SMALL( i = 0, 
				i < authTypeInfoTblSize && \
					authTypeInfoTblPtr[ i ].type != SSH_AUTHTYPE_NONE,
				i++ )
		{
		const AUTHTYPE_INFO *authTypeInfo;

		ENSURES( LOOP_INVARIANT_SMALL( i, 0, authTypeInfoTblSize - 1 ) );

		authTypeInfo = &authTypeInfoTblPtr[ i ];
		if( authTypeInfo->nameLength == authInfo->methodNameLength && \
			!memcmp( authTypeInfo->name, authInfo->methodName, 
					 authInfo->methodNameLength ) )
			{
			authTypeInfoPtr = authTypeInfo;
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < authTypeInfoTblSize );
	if( authTypeInfoPtr == NULL )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Unknown user-authentication method '%s'",
				  sanitiseString( authInfo->methodName, CRYPT_MAX_TEXTSIZE,
								  authInfo->methodNameLength ) ) );
		}
	*authType = authTypeInfoPtr->type;

	/* Read the kludge flag used to denote all sorts of additional 
	   functionality kludged onto the basic message.  In some cases the
	   kludgeFlag is set to TRUE (the password-authentication message is 
	   actually a change-password message), in others it's set to FALSE (the 
	   public-key authentication message doesn't contain any public-key 
	   authentication) */
	if( authTypeInfoPtr->type != SSH_AUTHTYPE_QUERY )
		{
		int value;

		status = value = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		authInfo->kludgeFlag = value ? TRUE : FALSE;
		}

	return( CRYPT_OK );
	}

/* Read the body of the userAuth packet:

	[...]
	"none":
		<empty>
	"password":
		string	password
	"publickey":
		string		"ssh-rsa"	"ssh-dss"	"ecdsa-sha2-*"	"ed25519"
		string		[ client key/certificate ]
			string	"ssh-rsa"	"ssh-dss"	"ecdsa-sha2-*"	"ed25519"
			mpint	e			p			Q				string	pubKey
			mpint	n			q
			mpint				g
			mpint				y
		[...] */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readAuthPacketBody( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR AUTH_INFO *authInfo,
							   INOUT_PTR STREAM *stream,
							   IN_ENUM( SSH_AUTHTYPE ) \
									SSH_AUTHTYPE_TYPE authType,
							   const BOOLEAN isInitialAuth )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( authInfo, sizeof( AUTH_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( isEnumRange( authType, SSH_AUTHTYPE ) );
	REQUIRES( isBooleanValue( isInitialAuth ) );

	/* Read the authentication information */
	switch( authType )
		{
		case SSH_AUTHTYPE_QUERY:
			/* No payload */
			break;

		case SSH_AUTHTYPE_PASSWORD:
			/* Read the password and check that it's approximately valid */
			status = readString32( stream, authInfo->password, 
								   CRYPT_MAX_TEXTSIZE, 
								   &authInfo->passwordLength );
			if( cryptStatusOK( status ) )
				{
				if( authInfo->passwordLength <= 0 || \
					authInfo->passwordLength > CRYPT_MAX_TEXTSIZE )
					status = CRYPT_ERROR_BADDATA;
				}
			if( cryptStatusError( status ) )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid password data" ) );
				}
			INJECT_FAULT( CORRUPT_AUTHENTICATOR, 
						  SESSION_CORRUPT_AUTHENTICATOR_SSH_1 );
			break;

		case SSH_AUTHTYPE_PUBKEY:
			/* Read the public key */
			status = readPublicKey( sessionInfoPtr, stream, isInitialAuth );
			if( cryptStatusError( status ) )
				return( status );
			break;

		default:
			retIntError();
		}

	return( CRYPT_OK );
	}

/* Handle client authentication */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processUserAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							IN_PTR const SSH_HANDSHAKE_INFO *handshakeInfo, 
							OUT_ENUM( USERAUTH ) USERAUTH_TYPE *userAuthInfo,
							IN_ENUM( CREDENTIAL ) \
								const CREDENTIAL_TYPE credentialType,
							IN_ENUM( AUTHSTATE ) \
								const AUTHSTATE_TYPE authState )
	{
	STREAM stream;
	const BOOLEAN allowPubkeyAuth = \
			isHandleRangeValid( sessionInfoPtr->cryptKeyset ) ? TRUE : FALSE;
	const ATTRIBUTE_LIST *attributeListPtr DUMMY_INIT_PTR;
	AUTH_INFO authInfo;
	SSH_AUTHTYPE_TYPE authType;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( userAuthInfo, sizeof( USERAUTH_TYPE ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( isEnumRange( credentialType, CREDENTIAL ) );
	REQUIRES( isEnumRange( authState, AUTHSTATE ) );

	/* Clear the return value, or at least set it to the default failed-
	   authentication state */
	*userAuthInfo = USERAUTH_ERROR;

	/* Get the userAuth packet from the client:

		byte	type = SSH_MSG_USERAUTH_REQUEST
		string	user_name
		string	service_name = "ssh-connection"
		string	method_name = "none" | "password" | "publickey"
	  "none":
		<empty>
	  "password":
		boolean	FALSE/TRUE
		string	password
	  "publickey":
		boolean	FALSE/TRUE
		string		"ssh-rsa"	"ssh-dss"	"ecdsa-sha2-*"
		string		[ client key/certificate ]
			string	"ssh-rsa"	"ssh-dss"	"ecdsa-sha2-*"
			mpint	e			p			Q
			mpint	n			q
			mpint				g
			mpint				y
	  [	string		[ client signature ]			-- If boolean == TRUE
			string	"ssh-rsa"	"ssh-dss"	"ecdsa-sha2-*"
			string	signature ]

	    The client can optionally send a method-type of "none" as its first
		message to indicate that it'd like the server to return a list of 
		allowed authentication types, if we get a packet of this kind and 
		we're in AUTHSTATE_FIRST_MESSAGE then we return our allowed types 
		list */
	status = length = \
		readAuthPacketSSH2( sessionInfoPtr, SSH_MSG_USERAUTH_REQUEST,
							ID_SIZE + sizeofString32( 1 ) + \
								sizeofString32( 8 ) + sizeofString32( 4 ) );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	CFI_CHECK_UPDATE( "readAuthPacketSSH2" );
	status = readAuthPacketHeader( sessionInfoPtr, &authInfo, &stream, 
								   &authType );
	if( cryptStatusError( status ) )
		{
		/* We don't perform a sendResponseFailure[Info]() at this point
		   because we haven't even started the authentication so an error
		   isn't really an authentication failure.  In theory if the client
		   sends an unknown method_name then we could send back failure info
		   with permitted method names but if they've chosen to use something
		   nonstandard then they should be performing a query first rather 
		   than just blindly trying it */
		sMemDisconnect( &stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "readAuthPacketHeader" );

	/* Either store the initial query parameters for later consistency 
	   checking or check that the query submitted by the client is valid, 
	   meaning that it doesn't appear to be an attempt to subvert the 
	   authentication process in some way, e.g. by changing data during 
	   subsequent rounds of the authentication negotiation.  
	   
	   We perform this and the following checks of the authentication packet 
	   body before any checking of the user name to make it harder for an 
	   attacker to perform account enumeration (but see also the comment 
	   about this issue further on where the user-name check is performed) */
	if( authState == AUTHSTATE_FIRST_MESSAGE )
		{
		/* Remember the query parameters for later */
		status = storeQueryParams( sessionInfoPtr->sessionSSH, 
								   authInfo.userName, 
								   authInfo.userNameLength, authType );
		}
	else
		{
		/* Make sure that the new parameters are consistent with the 
		   previously-seen ones */
		status = checkQueryValidity( sessionInfoPtr->sessionSSH, 
									 authInfo.userName, 
									 authInfo.userNameLength, authType );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		( void ) sendResponseFailure( sessionInfoPtr );

		/* There are two slightly different error conditions that we can 
		   encounter here, we provide distinct error messages to give the
		   caller more information on what went wrong */
		if( status == CRYPT_ERROR_DUPLICATE )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Client sent duplicate authentication requests with "
					  "method 'none'" ) );
			}
		retExt( CRYPT_ERROR_INVALID,
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Client supplied different credentials than the ones "
				  "supplied during a previous authentication attempt" ) );
		}
	CFI_CHECK_UPDATE( "checkQueryValidity" );

	/* Read the rest of the authentication packet.  In the case of public-key 
	   authentication this performs further checking of the kind done in
	   checkQueryValidity(), since we did't yet have the public key data
	   available for checking at that point */
	status = readAuthPacketBody( sessionInfoPtr, &authInfo, &stream, 
								 authType, 
								 ( authState == AUTHSTATE_FIRST_MESSAGE ) ? \
								   TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		if( authType == SSH_AUTHTYPE_PUBKEY )
			{
			/* The additional checks performed during the public-key read 
			   failed, this is an authentication failure as for the
			   checkQueryValidity() check */
			( void ) sendResponseFailure( sessionInfoPtr );
			}
		return( status );
		}
	CFI_CHECK_UPDATE( "readAuthPacketBody" );

	/* If the user credentials are pre-set make sure that the newly-
	   submitted user name matches an existing one.  We've left this check 
	   as late as possible so that it's right next to the password check to 
	   avoid timing attacks that might help an attacker guess a valid user 
	   name.  On the other hand given the typical pattern of SSH password-
	   guessing attacks which just run through a fixed set of user names 
	   this probably isn't worth the trouble since it'll have little to no 
	   effect on attackers, so what it's avoiding is purely a 
	   certificational weakness.

	   There's also a slight anomaly in error reporting here, if the client
	   is performing a dummy read and there are pre-set user credentials
	   present then instead of the expected list of available authentication
	   methods they'll get an error response.  This is consistent with the
	   specification (which is ambiguous on the topic), it says that the 
	   server must return a failure response and may also include a list of 
	   allowed methods, but it may not be what the client is expecting.  
	   This problem occurs because of the overloading of the authentication
	   mechanism as a method-query mechanism, it's not clear whether the
	   query response or the username-check response is supposed to take
	   precedence */
	if( credentialType == CREDENTIAL_NONE_PRESENT )
		{
		/* It's a new user name, add it after making sure that there isn't
		   already one from a previous exchange present.  This can't 
		   actually happen due to the state machine excluding duplicate 
		   adds, but we check for it anyway in case a future code change to
		   handle some special corner case in the dogs-breakfast 
		   authentication process allows it */
		if( findSessionInfo( sessionInfoPtr, \
							 CRYPT_SESSINFO_USERNAME ) != NULL )
			{
			sMemDisconnect( &stream );
			( void ) sendResponseFailure( sessionInfoPtr );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
					  "Client supplied different credentials than the ones "
					  "supplied during a previous authentication attempt" ) );
			}
		status = addSessionInfoS( sessionInfoPtr,
								  CRYPT_SESSINFO_USERNAME,
								  authInfo.userName, 
								  authInfo.userNameLength );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Error recording user name '%s'", 
					  sanitiseString( authInfo.userName, CRYPT_MAX_TEXTSIZE,
									  authInfo.userNameLength ) ) );
			}
		}
	else
		{
		attributeListPtr = \
					findSessionInfoEx( sessionInfoPtr, 
									   CRYPT_SESSINFO_USERNAME,
									   authInfo.userName, 
									   authInfo.userNameLength );
		if( attributeListPtr == NULL )
			{
			sMemDisconnect( &stream );
			( void ) sendResponseFailure( sessionInfoPtr );
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "Unknown/invalid user name '%s'", 
					  sanitiseString( authInfo.userName, CRYPT_MAX_TEXTSIZE, 
									  authInfo.userNameLength ) ) );
			}

		/* We've matched an existing user name, select the attribute that
		   contains it */
		DATAPTR_SET( sessionInfoPtr->attributeListCurrent,
					 ( ATTRIBUTE_LIST * ) attributeListPtr );
		}
	CFI_CHECK_UPDATE( "findSessionInfoEx" );

	/* If the client just wants a list of supported authentication 
	   mechanisms tell them what we allow (handled by sending a failed-
	   authentication response, which contains a list of mechanisms that can 
	   be used to continue) and await further input */
	if( authType == SSH_AUTHTYPE_QUERY )
		{
		sMemDisconnect( &stream );

		/* Tell the client which authentication methods can continue */
		status = sendResponseFailureInfo( sessionInfoPtr, allowPubkeyAuth );
		if( cryptStatusError( status ) )
			return( status );
		CFI_CHECK_UPDATE( "sendResponseFailureInfo" );

		/* Inform the caller that this was a no-op pass and the client can 
		   try again */
		*userAuthInfo = USERAUTH_NOOP;

		ENSURES( CFI_CHECK_SEQUENCE_6( "readAuthPacketSSH2", 
									   "readAuthPacketHeader", 
									   "checkQueryValidity", 
									   "readAuthPacketBody", 
									   "findSessionInfoEx",
									   "sendResponseFailureInfo" ) );
		return( OK_SPECIAL );
		}
	CFI_CHECK_UPDATE( "SSH_AUTHTYPE_QUERY" );

	/* If it's public-key authentication, try and verify the signature */
	if( authType == SSH_AUTHTYPE_PUBKEY )
		{
		/* If only password retries are allowed at this point then we can't
		   continue (C5) */
		if( authState == AUTHSTATE_IN_PROGRESS_PWONLY )
			{
			( void ) sendResponseFailure( sessionInfoPtr );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Client sent duplicate public-key authentication"
					  "request" ) );
			}

		status = processPubkeyAuth( sessionInfoPtr, handshakeInfo, 
									&authInfo, &stream, credentialType );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			{
			/* If we got back a status of OK_SPECIAL then it means that this 
			   was yet another no-op pass and the client can try again.  This
			   isn't a standard sendResponseFailureInfo() response so it's
			   already been handled specially by processPubkeyAuth() */
			if( status == OK_SPECIAL )
				*userAuthInfo = USERAUTH_NOOP_2;
			else
				( void ) sendResponseFailure( sessionInfoPtr );
			return( status );
			}
		( void ) sendResponseSuccess( sessionInfoPtr );
		CFI_CHECK_UPDATE( "processPubkeyAuth" );

		/* Indicate that the user has successfully authenticated through a 
		   failsafe two-value return status (see the comment for 
		   processFixedAuth()/processServerAuth() for details) */
	   	*userAuthInfo = USERAUTH_SUCCESS;

		ENSURES( CFI_CHECK_SEQUENCE_7( "readAuthPacketSSH2", 
									   "readAuthPacketHeader", 
									   "checkQueryValidity", 
									   "readAuthPacketBody", 
									   "findSessionInfoEx", 
									   "SSH_AUTHTYPE_QUERY",
									   "processPubkeyAuth" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "SSH_AUTHTYPE_PUBKEY" );

	/* At this point we're processing password authentication which means 
	   that there's nothing further to read */
	ENSURES( authType == SSH_AUTHTYPE_PASSWORD );
	sMemDisconnect( &stream );

	/* If the client started with partial public-key authentication then 
	   they can't continue with password authentication */
	if( credentialType == CREDENTIAL_USERNAME_PUBKEY_PRESENT )
		{
		( void ) sendResponseFailure( sessionInfoPtr );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Client started public-key authentication but tried to "
				  "complete with password authentication" ) );
		}

	/* If full user credentials are present then the user name has been 
	   matched to a caller-supplied list of allowed { user name, password } 
	   pairs and we move on to the corresponding password and verify it */
	if( credentialType == CREDENTIAL_USERNAME_PASSWORD_PRESENT )
		{
		status = processPasswordAuth( sessionInfoPtr, &authInfo, 
									  attributeListPtr );
		if( cryptStatusError( status ) )
			{
			/* If this is the last attempt allowed then the failure is 
			   fatal, otherwise tell the client to try again */
			if( authState == AUTHSTATE_FINAL_MESSAGE )
				( void ) sendResponseFailure( sessionInfoPtr );
			else
				{
				( void ) sendResponseFailureInfo( sessionInfoPtr, FALSE );
				*userAuthInfo = USERAUTH_ERROR_RETRY;
				}
			return( status );
			}
		( void ) sendResponseSuccess( sessionInfoPtr );
		CFI_CHECK_UPDATE( "processPasswordAuth" );

		/* Indicate that the user has successfully authenticated through a 
		   failsafe two-value return status (see the comment for 
		   processFixedAuth()/processServerAuth() for details) */
	   	*userAuthInfo = USERAUTH_SUCCESS;

		ENSURES( CFI_CHECK_SEQUENCE_8( "readAuthPacketSSH2", 
									   "readAuthPacketHeader", 
									   "checkQueryValidity", 
									   "readAuthPacketBody", 
									   "findSessionInfoEx", 
									   "SSH_AUTHTYPE_QUERY",
									   "SSH_AUTHTYPE_PUBKEY",
									   "processPasswordAuth" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "CREDENTIAL_USERNAME_PASSWORD_PRESENT" );

	ENSURES( credentialType == CREDENTIAL_NONE_PRESENT || \
			 credentialType == CREDENTIAL_USERNAME_PRESENT );

	/* There are no pre-set credentials present to match against, record the 
	   password for the caller to check, making it an ephemeral attribute 
	   since the client could try and re-enter it on a subsequent iteration 
	   if we tell them that it's incorrect.  This adds the password after 
	   the first user name that it finds but since there's only one user
	   name present, namely the one that was recorded or matched earlier, 
	   there's no problems with potentially ambiguous password entries in
	   the attribute list (B1, B3, B5) */
	status = updateSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD,
								authInfo.password, authInfo.passwordLength,
								CRYPT_MAX_TEXTSIZE, ATTR_FLAG_EPHEMERAL );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Error recording password for user '%s'",
				  sanitiseString( authInfo.userName, CRYPT_MAX_TEXTSIZE,
								  authInfo.userNameLength ) ) );
		}
	CFI_CHECK_UPDATE( "updateSessionInfo" );

	*userAuthInfo = USERAUTH_CALLERCHECK;

	ENSURES( CFI_CHECK_SEQUENCE_9( "readAuthPacketSSH2", 
								   "readAuthPacketHeader", "checkQueryValidity", 
								   "readAuthPacketBody", "findSessionInfoEx", 
								   "SSH_AUTHTYPE_QUERY", "SSH_AUTHTYPE_PUBKEY", 
								   "CREDENTIAL_USERNAME_PASSWORD_PRESENT", 
								   "updateSessionInfo" ) );
	return( OK_SPECIAL );
	}

/****************************************************************************
*																			*
*						Perform Server-side Authentication					*
*																			*
****************************************************************************/

/* Server-side authentication is a critical authorisation step so we don't 
   want to make it vulnerable to a simple boolean control-variable overwrite
   that an attacker can use to bypass the authentication check.  To do this
   we require confirmation both via the function return status and the by-
   reference value, we require the two values to be different (one a zero 
   value, the other a small nonzero integer value), and we store them 
   separated by a canary that's also checked when the status values are
   checked.  In theory it's still possible to overwrite this if an exact
   pattern of 96 bits (on a 32-bit system) can be placed in memory, but this
   is now vastly harder than simply entering an over-long user name or 
   password that converts an access-granted boolean-flag zero value to a 
   nonzero value.
   
   If we ever add a CRYPT_SESSINFO_SSH_OPTIONS then we could additionally 
   strengthen the process by allowing the user to set the number of password 
   retries, since we're almost always used for machine authentication there
   shouldn't be a need for three password tries in most cases */

typedef struct {
	USERAUTH_TYPE userAuthInfo;
	int canary;
	int status;
	} FAILSAFE_AUTH_INFO;

static const FAILSAFE_AUTH_INFO failsafeAuthSuccessTemplate = \
	{ USERAUTH_SUCCESS, OK_SPECIAL, CRYPT_OK };

#define initFailsafeAuthInfo( authInfo ) \
	{ \
	memset( ( authInfo ), 0, sizeof( FAILSAFE_AUTH_INFO ) ); \
	( authInfo )->userAuthInfo = USERAUTH_ERROR; \
	( authInfo )->canary = OK_SPECIAL; \
	( authInfo )->status = CRYPT_ERROR_FAILED; \
	}

#define NO_FIXEDAUTH_RETRIES		3

/* Process the client's authentication */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int processFixedAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							 const SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	FAILSAFE_AUTH_INFO authInfo DUMMY_INIT_STRUCT;
	LOOP_INDEX authAttempts;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );

	/* The caller has specified user credentials to match against so we can
	   perform a basic pass/fail check against the client-supplied 
	   information.  Since this is an all-or-nothing process at the end of 
	   which the client is either authenticated or not authenticated we 
	   allow the traditional three retries (or until the first fatal error) 
	   to get it right */
	LOOP_SMALL( authAttempts = 0, authAttempts < NO_FIXEDAUTH_RETRIES, \
				authAttempts++ )
		{
		/* Set the allowed authentication type for this attempt.  On the 
		   first attempt the full dog's-breakfast is allowed, on subsequent
		   attempts only password retries are allowed */
		const AUTHSTATE_TYPE authState = \
				( !sshInfo->authRead && authAttempts <= 0 ) ? \
				  AUTHSTATE_FIRST_MESSAGE : \
				( authAttempts >= NO_FIXEDAUTH_RETRIES - 1 ) ? \
				  AUTHSTATE_FINAL_MESSAGE : AUTHSTATE_IN_PROGRESS_PWONLY;

		ENSURES( LOOP_INVARIANT_SMALL( authAttempts, 0, 2 ) );

		/* Process the user authentication and, if it's a dummy read, try a 
		   second time.  This can only happen on the first read, after this 
		   checkQueryValidity() disallows it  */
		initFailsafeAuthInfo( &authInfo );
		authInfo.status = processUserAuth( sessionInfoPtr, handshakeInfo,
									&authInfo.userAuthInfo, 
									CREDENTIAL_USERNAME_PASSWORD_PRESENT, 
									authState );
		if( authInfo.status == OK_SPECIAL && \
			authInfo.userAuthInfo == USERAUTH_NOOP )
			{
			/* We can only get a retry on the first read */
			ENSURES( authState == AUTHSTATE_FIRST_MESSAGE );

			/* It was an initial dummy read, try again */
			authInfo.status = processUserAuth( sessionInfoPtr, handshakeInfo,
									&authInfo.userAuthInfo, 
									CREDENTIAL_USERNAME_PASSWORD_PRESENT, 
									AUTHSTATE_IN_PROGRESS );
			}
		if( authInfo.status == OK_SPECIAL && \
			authInfo.userAuthInfo == USERAUTH_NOOP_2 )
			{
			/* It was yet another a dummy read, try again.  At this point 
			   it's public-key authentication so we mark it as the final 
			   allowed attempt */
			authInfo.status = processUserAuth( sessionInfoPtr, handshakeInfo,
									&authInfo.userAuthInfo, 
									CREDENTIAL_USERNAME_PUBKEY_PRESENT, 
									AUTHSTATE_FINAL_MESSAGE );
			}
		if( !memcmp( &authInfo, &failsafeAuthSuccessTemplate, \
					 sizeof( FAILSAFE_AUTH_INFO ) ) )
			{
			/* The user has authenticated successfully and this fact has 
			   been verified in a (reasonably) failsafe manner, we're 
			   done */
			return( CRYPT_OK );
			}
		ENSURES( cryptStatusError( authInfo.status ) );
		sshInfo->authRead = TRUE;

		/* If the authentication processing returned anything other than a 
		   password retry indicator then the error is fatal and we can't 
		   continue */
		if( authInfo.userAuthInfo != USERAUTH_ERROR_RETRY )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( cryptStatusError( authInfo.status ) && \
			 authInfo.status != OK_SPECIAL );

	/* The user still hasn't successfully authenticated after multiple 
	   attempts, we're done */
	return( authInfo.status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processServerAuth( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					   IN_PTR const SSH_HANDSHAKE_INFO *handshakeInfo, 
					   IN_BOOL const BOOLEAN userInfoPresent )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	FAILSAFE_AUTH_INFO authInfo DUMMY_INIT_STRUCT;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionSSH( sessionInfoPtr ) );
	REQUIRES( sanityCheckSSHHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBooleanValue( userInfoPresent ) );

	/* If the caller has specified user credentials to match against then 
	   we perform a basic pass/fail check against the client-supplied 
	   information */
	if( userInfoPresent )
		return( processFixedAuth( sessionInfoPtr, handshakeInfo ) );

	/* The caller hasn't supplied any user credentials to match against,
	   indicating that they're going to perform an on-demand match */
	initFailsafeAuthInfo( &authInfo );
	if( !sshInfo->authRead )
		{
		/* This is the first time that the client has tried to authenticate,
		   allow them to go through the full authentication dance.  On 
		   subsequent attempts with sshInfo->authRead == TRUE the only thing
		   they're allowed to do is retry password authentication with the
		   previously-supplied user name */
		authInfo.status = processUserAuth( sessionInfoPtr, handshakeInfo, 
									&authInfo.userAuthInfo, 
									CREDENTIAL_NONE_PRESENT, 
									AUTHSTATE_FIRST_MESSAGE );
		if( authInfo.status == OK_SPECIAL && \
			authInfo.userAuthInfo == USERAUTH_NOOP )
			{
			/* It was a dummy read, try again */
			authInfo.status = processUserAuth( sessionInfoPtr, handshakeInfo,
									&authInfo.userAuthInfo, 
									CREDENTIAL_USERNAME_PRESENT, 
									AUTHSTATE_IN_PROGRESS );
			}
		if( authInfo.status == OK_SPECIAL && \
			authInfo.userAuthInfo == USERAUTH_NOOP_2 )
			{
			/* It was yet another a dummy read, try again.  At this point 
			   it's public-key authentication so we mark it as the final 
			   allowed attempt */
			authInfo.status = processUserAuth( sessionInfoPtr, handshakeInfo,
									&authInfo.userAuthInfo, 
									CREDENTIAL_USERNAME_PUBKEY_PRESENT, 
									AUTHSTATE_FINAL_MESSAGE );
			}
		sshInfo->authRead = TRUE;
		}
	else
		{
		/* If the caller accepted the authentication then we're done */
		if( sessionInfoPtr->authResponse == AUTHRESPONSE_SUCCESS )
			return( sendResponseSuccess( sessionInfoPtr ) );

		/* The caller denied the authentication, inform the client and let
		   them have another go at authenticating.  We set allowPubkeyAuth 
		   to FALSE and authState to AUTHSTATE_IN_PROGRESS_PWONLY because 
		   the only retry-able method at this point is password 
		   authentication, so we can assume CREDENTIAL_USERNAME_PRESENT
		   rather than having to figure out which part of the Lucy-and-
		   Charlie-Brown process we're in.
		   
		   The signalling here is a bit awkward because for whatever the 
		   caller decides is the final failed authentication attempt the 
		   client doesn't get a failureInfo message but has the connection 
		   closed on them since there's no way to tell in advance when the 
		   caller will decide to end the negotiation */
		status = sendResponseFailureInfo( sessionInfoPtr, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		sessionInfoPtr->authResponse = AUTHRESPONSE_NONE;
		authInfo.status = processUserAuth( sessionInfoPtr, handshakeInfo, 
									&authInfo.userAuthInfo, 
									CREDENTIAL_USERNAME_PRESENT, 
									AUTHSTATE_IN_PROGRESS_PWONLY );
		ENSURES( !( authInfo.status == OK_SPECIAL && \
					( authInfo.userAuthInfo == USERAUTH_NOOP || \
					  authInfo.userAuthInfo == USERAUTH_NOOP_2 ) ) );
		}
	ENSURES( ( cryptStatusOK( authInfo.status ) && \
			   authInfo.userAuthInfo == USERAUTH_SUCCESS ) || \
			 ( ( cryptStatusError( authInfo.status ) || \
				 authInfo.status == OK_SPECIAL ) && \
			   authInfo.userAuthInfo != USERAUTH_SUCCESS ) );
	if( !memcmp( &authInfo, &failsafeAuthSuccessTemplate, \
		sizeof( FAILSAFE_AUTH_INFO ) ) )
		{
		/* The user has authenticated successfully and this fact has been 
		   verified in a (reasonably) failsafe manner, we're done */
		return( CRYPT_OK );
		}
	ENSURES( cryptStatusError( authInfo.status ) );
	return( ( authInfo.status == OK_SPECIAL ) ? CRYPT_ENVELOPE_RESOURCE : \
												authInfo.status );
	}
#endif /* USE_SSH */
