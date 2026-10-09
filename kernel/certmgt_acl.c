/****************************************************************************
*																			*
*							Cert Management ACLs							*
*						Copyright Peter Gutmann 1997-2025					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

/* Macro to access the secondary parameter ACL information for a given
   parameter in a list of parameter ACLs */

#define secParamInfo( parentACL, paramNo )	( parentACL )->secParamACL[ paramNo ]

#if defined( USE_CERTIFICATES ) && defined( USE_KEYSETS )

/****************************************************************************
*																			*
*								Cert Management ACLs						*
*																			*
****************************************************************************/

/* The ACL tables for each cert management action */

static const CERTMGMT_ACL certMgmtACLTbl[] = {
	/* Create certificate store */
	{ CRYPT_CERTACTION_CREATE,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Connect to certificate store */
	{ CRYPT_CERTACTION_CONNECT,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Disconnect from certificate store */
	{ CRYPT_CERTACTION_DISCONNECT,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Error information */
	{ CRYPT_CERTACTION_ERROR,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Add PKI user */
	{ CRYPT_CERTACTION_ADDUSER,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Certificate request */
	{ CRYPT_CERTACTION_REQUEST_CERT,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Certificate renewal request */
	{ CRYPT_CERTACTION_REQUEST_RENEWAL,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Certificate revocation request */
	{ CRYPT_CERTACTION_REQUEST_REVOCATION,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Certificate creation begin */
	{ CRYPT_CERTACTION_CERT_CREATION,
	  ACTION_PERM_NONE_EXTERNAL,		/* Cert mgmt.use */
	  { MKACP_O( ST_CTX_PKC,			/* CA key w/cert (see below) */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_CERTREQ | ST_CERT_REQ_CERT,/* Cert request */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O_OPT( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* Authorising cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_PKIUSER,		/* PKI user */
				 ACL_FLAG_HIGH_STATE ) },
	  { MKACP_O( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* CA cert */
				 ACL_FLAG_HIGH_STATE ) } },

	/* Completion of certificate creation */
	{ CRYPT_CERTACTION_CERT_CREATION_COMPLETE,
	  ACTION_PERM_NONE_EXTERNAL,		/* Cert mgmt.use */
	  { MKACP_O_NONE(),
		MKACP_O( ST_CERT_CERT,			/* Completed cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O_OPT( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* Authorising cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_PKIUSER,		/* PKI user */
				 ACL_FLAG_HIGH_STATE ) } },

	/* Cancellation of certificate creation */
	{ CRYPT_CERTACTION_CERT_CREATION_DROP,
	  ACTION_PERM_NONE_EXTERNAL,		/* Cert mgmt.use */
	  { MKACP_O_NONE(),
		MKACP_O( ST_CERT_CERT,			/* Completed cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O_OPT( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* Authorising cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_PKIUSER,		/* PKI user */
				 ACL_FLAG_HIGH_STATE ) } },

	/* Cancellation of creation with revocation of already-issued 
	   certificate */
	{ CRYPT_CERTACTION_CERT_CREATION_REVERSE,
	  ACTION_PERM_NONE_EXTERNAL,		/* Cert mgmt.use */
	  { MKACP_O_NONE(),
		MKACP_O( ST_CERT_CERT,			/* Completed cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O_OPT( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* Authorising cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_PKIUSER,		/* PKI user */
				 ACL_FLAG_HIGH_STATE ) } },

	/* Delete requests after restart */
	{ CRYPT_CERTACTION_RESTART_CLEANUP,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Complete revocation after restart */
	{ CRYPT_CERTACTION_RESTART_REVOKE_CERT,
	  ACTION_PERM_NONE,					/* Cert dbx.internal use only */
	  { MKACP_END() } },

	/* Add certificate request */
	{ CRYPT_CERTACTION_ADDREQUEST,
	  ACTION_PERM_NONE_EXTERNAL,		/* Cert mgmt.use */
	  { MKACP_O( ST_CERT_CERTREQ | ST_CERT_REQ_CERT | \
				 ST_CERT_REQ_REV,		/* Cert request */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_CERTREQ | ST_CERT_REQ_CERT| \
				 ST_CERT_REQ_REV,		/* Cert request */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O_OPT( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* Authorising cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_PKIUSER,		/* PKI user */
				 ACL_FLAG_HIGH_STATE ) } },

	/* Certificate issue */
	{ CRYPT_CERTACTION_ISSUE_CERT,
	  ACTION_PERM_ALL,					/* Any access */
	  { MKACP_O( ST_CTX_PKC,			/* CA key w/cert (see below) */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_CERTREQ | ST_CERT_REQ_CERT,/* Cert request */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O_OPT( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* Authorising cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O_OPT( ST_CERT_PKIUSER,	/* PKI user */
				 ACL_FLAG_HIGH_STATE ) },
	  { MKACP_O( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* CA cert */
				 ACL_FLAG_HIGH_STATE ) } },

	/* CRL issue */
	{ CRYPT_CERTACTION_ISSUE_CRL,
	  ACTION_PERM_ALL,					/* Any access */
	  { MKACP_O( ST_CTX_PKC,			/* CA key w/cert (see below) */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O_NONE(),
		MKACP_O_NONE(),
		MKACP_O_NONE() },
	  { MKACP_O( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* CA cert */
				 ACL_FLAG_HIGH_STATE ) } },

	/* Certificate revocation */
	{ CRYPT_CERTACTION_REVOKE_CERT,
	  ACTION_PERM_NONE_EXTERNAL,		/* Cert mgmt.use */
	  { MKACP_O_NONE(),
		MKACP_O( ST_CERT_REQ_REV,		/* Rev.request.  Rev.reqs are usually */
				 ACL_FLAG_ANY_STATE ),	/* unsigned, but may be in the high */
										/* state if imported from an external */
										/* source */
		MKACP_O_OPT( ST_CERT_CERT | ST_CERT_CERTCHAIN,	/* Authorising cert */
				 ACL_FLAG_HIGH_STATE ),
		MKACP_O( ST_CERT_PKIUSER,		/* PKI user */
				 ACL_FLAG_HIGH_STATE ) } },

	/* Certificate expiry */
	{ CRYPT_CERTACTION_EXPIRE_CERT,
	  ACTION_PERM_ALL,					/* Any access */
	  { MKACP_O_NONE(),
		MKACP_O_NONE(),
		MKACP_O_NONE(),
		MKACP_O_NONE() } },

	/* Clean up on restart */
	{ CRYPT_CERTACTION_CLEANUP,
	  ACTION_PERM_ALL,					/* Any access */
	  { MKACP_O_NONE(),
		MKACP_O_NONE(),
		MKACP_O_NONE(),
		MKACP_O_NONE() } },

	/* End-of-ACL marker */
	{ CRYPT_CERTACTION_NONE,
	  ACTION_PERM_NONE,
	  { MKACP_END() } },
	{ CRYPT_CERTACTION_NONE,
	  ACTION_PERM_NONE,
	  { MKACP_END() } }
	};

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

CHECK_RETVAL \
int initCertMgmtACL( void )
	{
	LOOP_INDEX i;

	/* Perform a consistency check on the cert management ACLs */
	LOOP_LARGE( i = 0, 
				i < FAILSAFE_ARRAYSIZE( certMgmtACLTbl, CERTMGMT_ACL ) && \
					certMgmtACLTbl[ i ].action != CRYPT_CERTACTION_NONE, 
				i++ )
		{
		const CERTMGMT_ACL *certMgmtACL;

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( certMgmtACLTbl, \
														   CERTMGMT_ACL ) - 1 ) );

		/* Actions and permissions are consistent */
		certMgmtACL = &certMgmtACLTbl[ i ];
		ENSURES( isEnumRange( certMgmtACL->action, CRYPT_CERTACTION ) );
		ENSURES( certMgmtACL->access == ACTION_PERM_NONE || \
				 certMgmtACL->access == ACTION_PERM_NONE_EXTERNAL || \
				 certMgmtACL->access == ACTION_PERM_ALL );

		/* If it's a no-access ACL, all mechanisms should be blocked */
		if( certMgmtACL->access == ACTION_PERM_NONE )
			{
			ENSURES( paramInfo( certMgmtACL, 0 ).valueType == PARAM_VALUE_NONE );
			continue;
			}

		/* If it's an internal-only ACL, it always needs a request
		   parameter */
		if( certMgmtACL->access == ACTION_PERM_NONE_EXTERNAL )
			{
			if( paramInfo( certMgmtACL, 1 ).valueType != PARAM_VALUE_OBJECT || \
				( paramInfo( certMgmtACL, 1 ).subTypeA & \
					~( ST_CERT_CERTREQ | ST_CERT_REQ_CERT | \
					   ST_CERT_REQ_REV | ST_CERT_CERT ) ) || \
				paramInfo( certMgmtACL, 1 ).subTypeB != ST_NONE || \
				paramInfo( certMgmtACL, 1 ).subTypeC != ST_NONE )
				{
				DEBUG_DIAG(( "Certificate management ACLs inconsistent" ));
				retIntError();
				}
			}

		/* If it's a straight add then there's no CA key involved */
		if( certMgmtACL->action == CRYPT_CERTACTION_ADDREQUEST )
			{
			if( paramInfo( certMgmtACL, 0 ).valueType != PARAM_VALUE_OBJECT || \
				( paramInfo( certMgmtACL, 0 ).subTypeA & \
					~( ST_CERT_CERTREQ | ST_CERT_REQ_CERT | ST_CERT_REQ_REV ) ) || \
				paramInfo( certMgmtACL, 1 ).subTypeB != ST_NONE || \
				paramInfo( certMgmtACL, 1 ).subTypeC != ST_NONE )
				{
				DEBUG_DIAG(( "Certificate management ACLs inconsistent" ));
				retIntError();
				}
			continue;
			}

		/* If it requires a CA key parameter, it must be a private-key
		   context with the key loaded and an attached CA certificate */
		if( paramInfo( certMgmtACL, 0 ).valueType == PARAM_VALUE_OBJECT )
			{
			ENSURES( paramInfo( certMgmtACL, 0 ).subTypeA == ST_CTX_PKC && \
					 paramInfo( certMgmtACL, 0 ).subTypeB == ST_NONE && \
					 paramInfo( certMgmtACL, 0 ).subTypeC == ST_NONE && \
					 paramInfo( certMgmtACL, 0 ).flags == ACL_FLAG_HIGH_STATE );
			if( ( secParamInfo( certMgmtACL, 0 ).subTypeA & \
					~( ST_CERT_CERT | ST_CERT_CERTCHAIN ) ) || \
				secParamInfo( certMgmtACL, 0 ).subTypeB != ST_NONE || \
				secParamInfo( certMgmtACL, 0 ).subTypeC != ST_NONE || \
				secParamInfo( certMgmtACL, 0 ).flags != ACL_FLAG_HIGH_STATE )
				{
				DEBUG_DIAG(( "Certificate management ACLs inconsistent" ));
				retIntError();
				}
			continue;
			}
		ENSURES( paramInfo( certMgmtACL, 0 ).valueType == PARAM_VALUE_NUMERIC && \
				 paramInfo( certMgmtACL, 0 ).lowRange == CRYPT_UNUSED );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( certMgmtACLTbl, CERTMGMT_ACL ) );

	return( CRYPT_OK );
	}
#else

CHECK_RETVAL \
int initCertMgmtACL( void )
	{
	return( CRYPT_OK );
	}
#endif /* CONFIG_NO_SELFTEST */

void endCertMgmtACL( void )
	{
	}

/****************************************************************************
*																			*
*						Cert Management ACL Check Functions					*
*																			*
****************************************************************************/

/* Functions to implement the checks in the cert management ACL tables */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckCertMgmtAccess( IN_HANDLE const int objectHandle,
									IN_MESSAGE const MESSAGE_TYPE message,
									IN_BUFFER_C( sizeof( MESSAGE_CERTMGMT_INFO ) ) \
										const void *messageDataPtr,
									IN_ENUM( CRYPT_CERTACTION ) \
										const int messageValue,
									STDC_UNUSED const void *dummy )
	{
	const MESSAGE_CERTMGMT_INFO *mechanismInfo = \
		  ( MESSAGE_CERTMGMT_INFO * ) messageDataPtr;
	const CERTMGMT_ACL *certMgmtACL = certMgmtACLTbl;
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	LOOP_INDEX i;

	assert( isReadPtr( messageDataPtr, sizeof( MESSAGE_CERTMGMT_INFO ) ) );

	/* Precondition */
	REQUIRES( checkBuiltinStorage( SYSTEM_STORAGE_OBJECT_TABLE ) );
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( message == MESSAGE_KEY_CERTMGMT || message == IMESSAGE_KEY_CERTMGMT );
	REQUIRES( isEnumRange( messageValue, CRYPT_CERTACTION ) );

	/* Find the appropriate ACL for this mechanism */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( certMgmtACLTbl, CERTMGMT_ACL ) && \
					certMgmtACL[ i ].action != messageValue && \
					certMgmtACL[ i ].action != CRYPT_CERTACTION_NONE, 
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( certMgmtACLTbl, \
														 CERTMGMT_ACL ) - 1 ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( certMgmtACLTbl, CERTMGMT_ACL ) );
	ENSURES( certMgmtACL[ i ].action != CRYPT_CERTACTION_NONE );
	certMgmtACL = &certMgmtACL[ i ];

	/* Make sure that the access is valid.  Most cert management actions can
	   never be initiated explicitly (they're only used internally by the
	   cert management code), a few can be initiated explicitly but only
	   internally by some cert management protocols, and an even smaller
	   number can be initiated externally */
	switch( certMgmtACL->access )
		{
		case ACTION_PERM_ALL:
			/* Any access is valid */
			break;

		case ACTION_PERM_NONE_EXTERNAL:
			/* Only internal access (e.g. from a cert management protocol)
			   is permitted */
			if( !isInternalMessage( message ) )
				return( CRYPT_ARGERROR_VALUE );
			break;

		case ACTION_PERM_NONE:
			/* No access is permitted, it's a value used only by the cert
			   management code */
			return( CRYPT_ARGERROR_VALUE );

		default:
			retIntError();
		}

	/* Check the mechanism parameters */
	if( paramInfo( certMgmtACL, 0 ).valueType == PARAM_VALUE_OBJECT )
		{
		if( !fullObjectCheck( mechanismInfo->caKey, message ) || \
			!isSameOwningObject( objectHandle, mechanismInfo->caKey ) )
			return( CRYPT_ARGERROR_NUM1 );
		if( !checkParamObject( paramInfo( certMgmtACL, 0 ), \
							   mechanismInfo->caKey ) )
			return( CRYPT_ARGERROR_NUM1 );

		/* If there's a secondary parameter present, check it against the
		   dependent object.  We perform a basic isValidObject() check
		   rather than a fullObjectCheck() since the dependent object is
		   usually internal, and this would fail with an external message */
		if( secParamInfo( certMgmtACL, 0 ).valueType == PARAM_VALUE_OBJECT )
			{
			const int dependentObject = \
						objectTable[ mechanismInfo->caKey ].dependentObject;

			if( !isValidObject( dependentObject ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( !checkParamObject( secParamInfo( certMgmtACL, 0 ), \
								   dependentObject ) )
				return( CRYPT_ARGERROR_NUM1 );
			}
		}
	else
		{
		REQUIRES( paramInfo( certMgmtACL, 0 ).valueType == PARAM_VALUE_NUMERIC && \
				  paramInfo( certMgmtACL, 0 ).lowRange == CRYPT_UNUSED );

		if( mechanismInfo->caKey != CRYPT_UNUSED )
			return( CRYPT_ARGERROR_NUM1 );
		}
	if( paramInfo( certMgmtACL, 1 ).valueType == PARAM_VALUE_OBJECT )
		{
		if( !fullObjectCheck( mechanismInfo->request, message ) || \
			!isSameOwningObject( objectHandle, mechanismInfo->request ) )
			return( CRYPT_ARGERROR_NUM2 );
		if( !checkParamObject( paramInfo( certMgmtACL, 1 ), \
							   mechanismInfo->request ) )
			return( CRYPT_ARGERROR_NUM2 );
		}
	else
		{
		REQUIRES( paramInfo( certMgmtACL, 1 ).valueType == PARAM_VALUE_NUMERIC && \
				  paramInfo( certMgmtACL, 1 ).lowRange == CRYPT_UNUSED );

		if( mechanismInfo->request != CRYPT_UNUSED )
			return( CRYPT_ARGERROR_NUM2 );
		}
	if( paramInfo( certMgmtACL, 2 ).valueType == PARAM_VALUE_OBJECT_OPT )
		{
		if( mechanismInfo->authCert != CRYPT_UNUSED )
			{
			if( !fullObjectCheck( mechanismInfo->authCert, message ) || \
				!isSameOwningObject( objectHandle, mechanismInfo->authCert ) )
				return( CRYPT_ARGERROR_NUM2 );
			}
		}
	else
		{
		REQUIRES( paramInfo( certMgmtACL, 2 ).valueType == PARAM_VALUE_NUMERIC && \
				  paramInfo( certMgmtACL, 2 ).lowRange == CRYPT_UNUSED );

		if( mechanismInfo->authCert != CRYPT_UNUSED )
			return( CRYPT_ARGERROR_NUM2 );
		}
	switch( paramInfo( certMgmtACL, 3 ).valueType )
		{
		case PARAM_VALUE_OBJECT:
			if( !fullObjectCheck( mechanismInfo->pkiUser, message ) || \
				!isSameOwningObject( objectHandle, mechanismInfo->pkiUser ) )
				return( CRYPT_ARGERROR_NUM2 );
			break;

		case PARAM_VALUE_OBJECT_OPT:
			if( mechanismInfo->pkiUser != CRYPT_UNUSED )
				{
				if( !fullObjectCheck( mechanismInfo->pkiUser, message ) || \
					!isSameOwningObject( objectHandle, mechanismInfo->pkiUser ) )
					return( CRYPT_ARGERROR_NUM2 );
				}
			break;
			
		case PARAM_VALUE_NUMERIC:
			REQUIRES( paramInfo( certMgmtACL, 3 ).lowRange == CRYPT_UNUSED );

			if( mechanismInfo->pkiUser != CRYPT_UNUSED )
				return( CRYPT_ARGERROR_NUM2 );
			break;
			
		default:
			retIntError();
		}

	return( CRYPT_OK );
	}
#else

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckCertMgmtAccess( IN_HANDLE const int objectHandle,
									IN_MESSAGE const MESSAGE_TYPE message,
									IN_BUFFER_C( sizeof( MESSAGE_CERTMGMT_INFO ) ) \
										const void *messageDataPtr,
									IN_ENUM( CRYPT_CERTACTION ) \
										const int messageValue,
									STDC_UNUSED const void *dummy )
	{
	UNUSED_ARG( messageDataPtr );

	return( CRYPT_ERROR_PERMISSION );
	}
#endif /* USE_CERTIFICATES && USE_KEYSETS */
