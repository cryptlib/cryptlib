/****************************************************************************
*																			*
*							Object Attribute ACLs							*
*						Copyright Peter Gutmann 1997-2019					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"		/* For MAX_PATH_LENGTH */
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "io/stream.h"	/* For MAX_PATH_LENGTH */
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */
#ifndef MAX_PATH_LENGTH
  /* This is used for PKCS #11 driver locations, devices without filesystems 
	 won't support PKCS #11 so we define a dummy value to populate the ACL */
  #ifdef USE_PKCS11
	#error Cant have USE_PKCS11 in a device without a filesystem
  #endif /* USE_PKCS11 */
  #define MAX_PATH_LENGTH	2
#endif /* MAX_PATH_LENGTH */

/* Common object ACLs for various object types */

static const OBJECT_ACL objectCtxConv = {
		ST_CTX_CONV, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL objectCtxPKC = {
		ST_CTX_PKC, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX };
static const OBJECT_ACL objectCtxHash = {
		ST_CTX_HASH, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };

static const OBJECT_ACL objectCertificate = {
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CERT };
static const OBJECT_ACL objectCertificateTemplate = {
		ST_CERT_CERT, ST_NONE, ST_NONE, ACL_FLAG_ANY_STATE };		/* Template for cert.attrs */
static const OBJECT_ACL objectCertRequest = {
		ST_CERT_CERTREQ | ST_CERT_REQ_CERT, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL objectCertRevRequest = {
		ST_CERT_REQ_REV, ST_NONE, ST_NONE, ACL_FLAG_ANY_STATE };	/* Unsigned obj.*/
static const OBJECT_ACL objectCertSessionRTCSRequest = {
		ST_CERT_RTCS_REQ, ST_NONE, ST_NONE, ACL_FLAG_ANY_STATE };	/* Unsigned obj.*/
static const OBJECT_ACL objectCertSessionSCVPRequest = {
		ST_CERT_CERT, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL objectCertSessionOCSPRequest = {
		ST_CERT_OCSP_REQ, ST_NONE, ST_NONE, ACL_FLAG_ANY_STATE };	/* Unsigned obj.*/
static const OBJECT_ACL objectCertSessionCMPRequest = {
		ST_CERT_CERTREQ | ST_CERT_REQ_CERT | ST_CERT_REQ_REV, ST_NONE, ST_NONE, ACL_FLAG_ANY_STATE };
static const OBJECT_ACL objectCertSessionPKCS10Request = {
		ST_CERT_CERTREQ, ST_NONE, ST_NONE, ACL_FLAG_ANY_STATE };
static const OBJECT_ACL objectCertRTCSRequest = {
		ST_CERT_RTCS_REQ, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL objectCertRTCSResponse = {
		ST_CERT_RTCS_RESP, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL objectCertOCSPRequest = {
		ST_CERT_OCSP_REQ, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL objectCertOCSPResponse = {
		ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL objectCertPKIUser = {
		ST_CERT_PKIUSER, ST_NONE, ST_NONE, ACL_FLAG_HIGH_STATE };

static const OBJECT_ACL objectCMSAttr = {
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, ACL_FLAG_ANY_STATE };

static const OBJECT_ACL objectKeyset = {
		ST_NONE, ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_NONE, ACL_FLAG_NONE };
static const OBJECT_ACL objectKeysetCerts = {
		ST_NONE, ST_KEYSET_DBMS | SUBTYPE_KEYSET_DBMS_STORE, ST_NONE, ACL_FLAG_NONE };
static const OBJECT_ACL objectKeysetCertstore = {
		ST_NONE, SUBTYPE_KEYSET_DBMS_STORE, ST_NONE, ACL_FLAG_NONE };
static const OBJECT_ACL objectKeysetPrivate = {
		ST_NONE, ST_KEYSET_FILE | ST_DEV_P11, ST_NONE, ACL_FLAG_NONE };
static const OBJECT_ACL objectKeysetConfigdata = {
		ST_NONE, SUBTYPE_KEYSET_FILE, ST_NONE, ACL_FLAG_NONE };

static const OBJECT_ACL objectDeenvelope = {
		ST_NONE, ST_ENV_DEENV, ST_NONE, ACL_FLAG_HIGH_STATE };

static const OBJECT_ACL objectHardwareDevice = {
		ST_NONE, ST_DEV_HW | ST_DEV_TPM, ST_NONE, ACL_FLAG_NONE };

static const OBJECT_ACL objectSessionDataClient = {
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_TLS, ACL_FLAG_NONE };
static const OBJECT_ACL objectSessionTSP = {
		ST_NONE, ST_NONE, ST_SESS_TSP, ACL_FLAG_LOW_STATE };

/****************************************************************************
*																			*
*								Object/Property ACLs						*
*																			*
****************************************************************************/

static const RANGE_SUBRANGE_TYPE allowedCertCursorSubranges[] = {
	/* Alongside the standard attributes and cursor movement codes we also
	   allow the selection of the subject and issuer DN pseudo-attributes, 
	   which is required when we've implicitly moved to another DN by 
	   selecting a GeneralName */
	{ CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST },
	{ CRYPT_CERTINFO_FIRST_EXTENSION, CRYPT_CERTINFO_LAST_EXTENSION },
	{ CRYPT_CERTINFO_ISSUERNAME, CRYPT_CERTINFO_ISSUERNAME },
	{ CRYPT_CERTINFO_SUBJECTNAME, CRYPT_CERTINFO_SUBJECTNAME },
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};
static const RANGE_SUBRANGE_TYPE allowedCertCursorSubrangesEx[] = {
	/* This one is a bit more complex than the other object types, since 
	   certificates are so complex it's possible to enumerate items at what 
	   would normally be the attribute-instance level once components of 
	   GeneralNames are taken into account, so we also allow GeneralName 
	   entries as complete attributes rather than an instance of an 
	   attribute.
	   
	   There's a second special case in which DN entries can be 
	   multivalued, and depending on whether the DN is a primary DN in the
	   certificate (subject or issuer name) this could be either a non-
	   attribute type (since primary DNs aren't attributes) or something
	   below even the attribute-instance level.  To handle this we allow
	   enumeration of multivalued entries in DNs as pseudo-attribute
	   instances, and don't allow enumeration of multivalued DNs as 
	   subclasses of GeneralNames, since the only likely reason for anyone 
	   doing that is to engage in shenanigans with name checking in
	   implementations, and even the standards groups have no real idea of
	   what to do with these things */
	{ CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST },
	{ CRYPT_CERTINFO_FIRST_EXTENSION, CRYPT_CERTINFO_LAST_EXTENSION },
	{ CRYPT_CERTINFO_FIRST_GENERALNAME, CRYPT_CERTINFO_LAST_GENERALNAME },
	{ CRYPT_CERTINFO_FIRST_DN, CRYPT_CERTINFO_LAST_DN },
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};
static const RANGE_SUBRANGE_TYPE allowedEnvCursorSubranges[] = {
	{ CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST },
	{ CRYPT_ENVINFO_FIRST, CRYPT_ENVINFO_LAST },
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};
static const RANGE_SUBRANGE_TYPE allowedSessionCursorSubranges[] = {
	{ CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST },
	{ CRYPT_SESSINFO_FIRST, CRYPT_SESSINFO_LAST },
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};

static const ATTRIBUTE_ACL subACL_AttributeCurrentGroup[] = {
	MKACL_SS(	/* Certs */
		CRYPT_ATTRIBUTE_CURRENT_GROUP, 
		ST_CERT_ANY, ST_NONE, ST_NONE, 
		MKPERM( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		allowedCertCursorSubranges 
		),
	MKACL_SS(	/* Envelopes */
		CRYPT_ATTRIBUTE_CURRENT_GROUP, 
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		allowedEnvCursorSubranges ),
	MKACL_SS(	/* Sessions */
		CRYPT_ATTRIBUTE_CURRENT_GROUP, 
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_SESSION ),
		allowedSessionCursorSubranges ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_AttributeCurrent[] = {
	MKACL_SS(	/* Certs */
		CRYPT_ATTRIBUTE_CURRENT, 
		ST_CERT_ANY, ST_NONE, ST_NONE, 
		MKPERM( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		allowedCertCursorSubranges ),
	MKACL_SS(	/* Envelopes */
		CRYPT_ATTRIBUTE_CURRENT, 
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		allowedEnvCursorSubranges ),
	MKACL_SS(	/* Sessions */
		CRYPT_ATTRIBUTE_CURRENT, 
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_SESSION ),
		allowedSessionCursorSubranges ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_AttributeCurrentInstance[] = {
	/* Only certificates are complex enough to have instances of fields,
	   the progression being certificate-extension -> GeneralName ->
	   GeneralName-field */
	MKACL_SS(	/* Certs */
		CRYPT_ATTRIBUTE_CURRENT_INSTANCE, 
		ST_CERT_ANY, ST_NONE, ST_NONE, 
		MKPERM( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		allowedCertCursorSubrangesEx ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};

/* Object properties */

static const ATTRIBUTE_ACL propertyACL[] = {
	MKACL(		/* Owned+non-forwardable+locked */
		CRYPT_PROPERTY_HIGHSECURITY, ATTRIBUTE_VALUE_BOOLEAN,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM( xWx_xWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) ),
	MKACL_SA_EX(/* Object owner */
		CRYPT_PROPERTY_OWNER,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM( RWx_RWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE ),
	MKACL_N_EX(	/* No.of times object can be forwarded */
		CRYPT_PROPERTY_FORWARDCOUNT,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM( RWx_RWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( 1, 1000 ) ),
	MKACL(		/* Whether properties can be chged/read */
		CRYPT_PROPERTY_LOCKED, ATTRIBUTE_VALUE_BOOLEAN,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM( RWx_RWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) ),
	MKACL_N_EX(	/* Usage count before object expires */
		CRYPT_PROPERTY_USAGECOUNT,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM( RWx_RWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( 1, 1000 ) ),
	MKACL(		/* Whether key is nonexp.from context */
		CRYPT_PROPERTY_NONEXPORTABLE, ATTRIBUTE_VALUE_BOOLEAN,
		ST_CTX_ANY, ST_NONE, ST_NONE, 
		MKPERM( xxx_xxx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( TRUE, TRUE ) ),
	MKACL_END(), MKACL_END()
	};

/* Generic attributes */

static const ATTRIBUTE_ACL genericACL[] = {
	MKACL_N(	/* Type of last error */
		CRYPT_ATTRIBUTE_ERRORTYPE,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM( Rxx_Rxx ),
		ROUTE_NONE, RANGE( CRYPT_ERRTYPE_NONE, CRYPT_ERRTYPE_LAST - 1 ) ),
	MKACL_N(	/* Locus of last error */
		CRYPT_ATTRIBUTE_ERRORLOCUS,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM( Rxx_Rxx ),
		ROUTE_NONE, RANGE( CRYPT_ATTRIBUTE_NONE, CRYPT_ATTRIBUTE_LAST ) ),
	MKACL_S(	/* Detailed error description */
		CRYPT_ATTRIBUTE_ERRORMESSAGE,
		ST_CERT_ANY, ST_ENV_ANY | ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_SESS_ANY, 
		MKPERM( Rxx_Rxx ),
		ROUTE_NONE, RANGE( 0, 512 ) ),
	MKACL_ST(	/* Cursor mgt: Group in attribute list */
/* In = cursor components, out = component type */
		CRYPT_ATTRIBUTE_CURRENT_GROUP,
		ST_CERT_ANY, ST_ENV_DEENV, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM( RWx_RWx ),
		ROUTE_ALT2( OBJECT_TYPE_CERTIFICATE, OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ),
		subACL_AttributeCurrentGroup ),
	MKACL_ST(	/* Cursor mgt: Entry in attribute list */
/* In = cursor components, out = component type */
		CRYPT_ATTRIBUTE_CURRENT,
		ST_CERT_ANY, ST_ENV_DEENV, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM( RWx_RWx ),
		ROUTE_ALT2( OBJECT_TYPE_CERTIFICATE, OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ),
		subACL_AttributeCurrent ),
	MKACL_ST(	/* Cursor mgt: Instance in attribute list */
/* In = cursor components, out = component type */
		CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
		ST_CERT_ANY, ST_NONE, ST_NONE, 
		MKPERM( RWx_RWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		subACL_AttributeCurrentInstance ),
	MKACL_N(	/* Internal data buffer size */
		CRYPT_ATTRIBUTE_BUFFERSIZE,
		ST_NONE, ST_ENV_ANY, ST_SESS_ANY, 
		MKPERM( Rxx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ), RANGE( MIN_BUFFER_SIZE, MAX_BUFFER_SIZE ) ),
	MKACL_END(), MKACL_END()
	};

/****************************************************************************
*																			*
*								Config Option ACLs							*
*																			*
****************************************************************************/

static const RANGE_SUBRANGE_TYPE allowedEncrAlgoSubranges[] = {
#ifdef USE_3DES
	{ CRYPT_ALGO_3DES, CRYPT_ALGO_3DES },		/* No DES */
#endif /* USE_3DES */
	{ CRYPT_ALGO_AES, CRYPT_ALGO_AES },			/* No IDEA, CAST, RC2, RC4, RC5, Blowfish */
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};
static const RANGE_SUBRANGE_TYPE allowedHashParamSubranges[] = {
	{ bitsToBytes( 256 ), bitsToBytes( 256 ) },
#ifdef USE_SHA2_EXT
	{ bitsToBytes( 384 ), bitsToBytes( 384 ) },
	{ bitsToBytes( 512 ), bitsToBytes( 512 ) },
#endif /* USE_SHA2_EXT */
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};
static const int allowedLDAPObjectTypes[] = {
	CRYPT_CERTTYPE_NONE, CRYPT_CERTTYPE_CERTIFICATE, CRYPT_CERTTYPE_CRL,
	CRYPT_ERROR, CRYPT_ERROR
	};

/* Config attributes */

static const ATTRIBUTE_ACL optionACL[] = {
	MKACL_S(	/* Text description */
		CRYPT_OPTION_INFO_DESCRIPTION,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 16, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Copyright notice */
		CRYPT_OPTION_INFO_COPYRIGHT,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 16, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_N(	/* Major release version */
		CRYPT_OPTION_INFO_MAJORVERSION,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 3, 3 ) ),
	MKACL_N(	/* Minor release version */
		CRYPT_OPTION_INFO_MINORVERSION,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 0, 5 ) ),
	MKACL_N(	/* Stepping version */
		CRYPT_OPTION_INFO_STEPPING,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 1, 50 ) ),

	MKACL_SS(	/* Encryption algorithm */
		/* We restrict the subrange to disallow the selection of the
		   insecure or deprecated DES, RC2, RC4, and Skipjack algorithms
		   as the default encryption algorithms */
		CRYPT_OPTION_ENCR_ALGO, 
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_USER_ANY, 
		MKPERM( RWx_RWx ), 
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_USER ),
		allowedEncrAlgoSubranges ),
	MKACL_N(	/* Hash algorithm */
		/* We restrict the subrange to disallow the selection of the
		   insecure or deprecated MD2, MD4, and MD5 algorithms as the
		   default hash algorithm */
		CRYPT_OPTION_ENCR_HASH,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_SHA1, CRYPT_ALGO_LAST_HASH ) ),
	MKACL_N(	/* MAC algorithm */
		CRYPT_OPTION_ENCR_MAC,
		ST_NONE, ST_ENV_ENV, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_FIRST_MAC, CRYPT_ALGO_LAST_MAC ) ),
	MKACL_N(	/* PKC algorithm */
		CRYPT_OPTION_PKC_ALGO,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_FIRST_PKC, CRYPT_ALGO_LAST_PKC ) ),
	MKACL_N(	/* PKC key size */
		CRYPT_OPTION_PKC_KEYSIZE,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( bitsToBytes( 512 ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* PKC format */
		CRYPT_OPTION_PKC_FORMAT,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( CRYPT_PKCFORMAT_NONE + 1, CRYPT_PKCFORMAT_LAST - 1 ) ),
	MKACL_SS(	/* Hash/MAC parameter */
		CRYPT_OPTION_ENCR_HASHPARAM,
		ST_NONE, ST_ENV_ENV, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_USER ),
		allowedHashParamSubranges ),
	MKACL_N(	/* Key processing algorithm */
		/* Note that this is non-orthongonal to CRYPT_CTXINFO_KEYING_ALGO,
		   for the configuration option we're specifying a setting for
		   PBKDF2, for CRYPT_CTXINFO_KEYING_ALGO it's usually PBKDF2 but may
		   also be PGP-style key derivation which uses the hash directly, 
		   and can also use MD5 if it's enabled */
		CRYPT_OPTION_KEYING_ALGO,
		ST_CTX_CONV, ST_NONE, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_CONTEXT, OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_HMAC_SHA1, CRYPT_ALGO_HMAC_SHAng ) ),
	MKACL_N(	/* Key processing iterations */
		CRYPT_OPTION_KEYING_ITERATIONS,
		ST_CTX_CONV, ST_NONE, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_CONTEXT, OBJECT_TYPE_USER ),
		RANGE( 1, MAX_KEYSETUP_ITERATIONS ) ),

	MKACL_B(	/* Whether to sign unrecog.attrs */
		CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_CERTIFICATES( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ) ),
	MKACL_N(	/* Certificate validity period */
		CRYPT_OPTION_CERT_VALIDITY,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_CERTIFICATES( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 1, 20 * 365 ) ),
	MKACL_N(	/* CRL update interval */
		CRYPT_OPTION_CERT_UPDATEINTERVAL,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_CERTREV( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 1, 365 ) ),
	MKACL_N(	/* PKIX compliance level for cert chks.*/
		CRYPT_OPTION_CERT_COMPLIANCELEVEL,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_ALT_CERTIFICATES( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( CRYPT_COMPLIANCELEVEL_OBLIVIOUS, \
			   MAX_COMPLIANCE_LEVEL ) ),
	MKACL_B(	/* Whether explicit policy req'd for certs */
		CRYPT_OPTION_CERT_REQUIREPOLICY,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_CERTIFICATES( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ) ),

	MKACL_B(	/* Add default CMS attributes */
		CRYPT_OPTION_CMS_DEFAULTATTRIBUTES,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ) ),

	MKACL_S(	/* Object class */
		CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS,
		ST_NONE, ST_KEYSET_LDAP, ST_USER_ANY, 
		MKPERM_LDAP( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_SL(	/* Object type to fetch */
		CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, 
		ST_NONE, ST_KEYSET_LDAP, ST_USER_ANY, 
		MKPERM_LDAP( RWx_RWx ), 
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		allowedLDAPObjectTypes ),
	MKACL_S(	/* Query filter */
		CRYPT_OPTION_KEYS_LDAP_FILTER,
		ST_NONE, ST_KEYSET_LDAP, ST_USER_ANY, 
		MKPERM_LDAP( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CA certificate attribute name */
		CRYPT_OPTION_KEYS_LDAP_CACERTNAME,
		ST_NONE, ST_KEYSET_LDAP, ST_USER_ANY, 
		MKPERM_LDAP( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Certificate attribute name */
		CRYPT_OPTION_KEYS_LDAP_CERTNAME,
		ST_NONE, ST_KEYSET_LDAP, ST_USER_ANY, 
		MKPERM_LDAP( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CRL attribute name */
		CRYPT_OPTION_KEYS_LDAP_CRLNAME,
		ST_NONE, ST_KEYSET_LDAP, ST_USER_ANY, 
		MKPERM_LDAP( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Email attribute name */
		CRYPT_OPTION_KEYS_LDAP_EMAILNAME,
		ST_NONE, ST_KEYSET_LDAP, ST_USER_ANY, 
		MKPERM_LDAP( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_S(	/* Name of first PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR01,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_PKCS11( RWD_RWD ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of second PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR02,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_PKCS11( RWD_RWD ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of third PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR03,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_PKCS11( RWD_RWD ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of fourth PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR04,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_PKCS11( RWD_RWD ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of fifth PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR05,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_PKCS11( RWD_RWD ),
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_B(	/* Use only hardware mechanisms */
		CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_PKCS11( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ) ),

	MKACL_S(	/* Socks server name */
		CRYPT_OPTION_NET_SOCKS_SERVER,
		ST_NONE, ST_NONE, ST_SESS_ANY | ST_USER_ANY, 
		MKPERM_TCP( RWD_RWD ),
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( MIN_DNS_SIZE, MAX_DNS_SIZE ) ),
	MKACL_S(	/* Socks user name */
		CRYPT_OPTION_NET_SOCKS_USERNAME,
		ST_NONE, ST_NONE, ST_SESS_ANY | ST_USER_ANY, 
		MKPERM_TCP( RWD_RWD ),
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Web proxy server */
		CRYPT_OPTION_NET_HTTP_PROXY,
		ST_NONE, ST_NONE, ST_SESS_ANY | ST_USER_ANY, 
		MKPERM_HTTP( RWD_RWD ),
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( MIN_DNS_SIZE, MAX_DNS_SIZE ) ),
	MKACL_N(	/* Timeout for network connection setup */
		CRYPT_OPTION_NET_CONNECTTIMEOUT,
		ST_NONE, ST_NONE, ST_SESS_ANY | ST_USER_ANY, 
		MKPERM_TCP( Rxx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( 5, MAX_NETWORK_TIMEOUT ) ),
	MKACL_N(	/* Timeout for network reads */
		CRYPT_OPTION_NET_READTIMEOUT,
		ST_NONE, ST_NONE, ST_SESS_ANY | ST_USER_ANY, 
		MKPERM_TCP( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( 0, MAX_NETWORK_TIMEOUT ) ),
	MKACL_N(	/* Timeout for network writes */
		CRYPT_OPTION_NET_WRITETIMEOUT,
		ST_NONE, ST_NONE, ST_SESS_ANY | ST_USER_ANY, 
		MKPERM_TCP( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( 0, MAX_NETWORK_TIMEOUT ) ),

	MKACL_B(	/* Whether to init cryptlib async'ly */
		CRYPT_OPTION_MISC_ASYNCINIT,
		ST_NONE, ST_NONE, ST_USER_SO, 
		MKPERM( RWx_RWx ),
		ROUTE( OBJECT_TYPE_USER ) ),
	MKACL_N(	/* Protect against side-channel attacks */
		CRYPT_OPTION_MISC_SIDECHANNELPROTECTION,
		ST_CTX_PKC, ST_NONE, ST_USER_SO, 
		MKPERM( RWx_RWx ),
		ROUTE_ALT( OBJECT_TYPE_CONTEXT, OBJECT_TYPE_USER ),
		RANGE( 0, 2 ) ),

	MKACL(		/* Whether in-mem.opts match on-disk ones */
		/* This is a special-case boolean attribute value that can only be
		   set to FALSE to indicate that the config options should be
		   flushed to disk */
		CRYPT_OPTION_CONFIGCHANGED, ATTRIBUTE_VALUE_BOOLEAN,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_PKCS15( RWx_RWx ), 0,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( FALSE, FALSE ) ),

	MKACL_B(	/* Algorithm self-test status */
		CRYPT_OPTION_SELFTESTOK, 
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_USER ) ),
	MKACL_END(), MKACL_END()
	};

/****************************************************************************
*																			*
*									Context ACLs							*
*																			*
****************************************************************************/

static const int allowedPKCKeysizes[] = {
	sizeof( CRYPT_PKCINFO_DLP ), sizeof( CRYPT_PKCINFO_RSA ), 
	sizeof( CRYPT_PKCINFO_ECC ), CRYPT_ERROR, CRYPT_ERROR 
	};
static const int allowedKeyingAlgos[] = {
	/* Hash algos used for PGP */
#ifdef USE_PGP
  #ifdef USE_MD5
	CRYPT_ALGO_MD5,
  #endif /* USE_MD5 */
	CRYPT_ALGO_SHA1, 
	CRYPT_ALGO_SHA2,
#endif /* USE_PGP */
	/* MAC algos used for everything else */
	CRYPT_ALGO_HMAC_SHA1, CRYPT_ALGO_HMAC_SHA2, CRYPT_ALGO_HMAC_SHAng, 
	CRYPT_ERROR, CRYPT_ERROR
	};

static const ATTRIBUTE_ACL subACL_CtxinfoBlocksize[] = {
	MKACL_N(	/* Encr. and PKC is determined implicitly algorithm type */
		CRYPT_CTXINFO_BLOCKSIZE,
		ST_CTX_CONV | ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, CRYPT_MAX_HASHSIZE ) ),
	MKACL_N(	/* Some hash/MAC algos have variable-length outputs */
		/* Hash contexts are a special case because they're moved into the
		   high state as soon as they're created because there's no further
		   initialisation to be done.  This means that the output size can
		   be changed even when they're (effectively) in the high state, 
		   although the actual meaning of this state is somewhat different
		   than for other context types */
		CRYPT_CTXINFO_BLOCKSIZE,
		ST_CTX_HASH, ST_NONE, ST_NONE, 
		MKPERM( RWx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( MIN_HASHSIZE, CRYPT_MAX_HASHSIZE ) ),
	MKACL_N(	/* Some hash/MAC algos have variable-length outputs */
		CRYPT_CTXINFO_BLOCKSIZE,
		ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( MIN_HASHSIZE, CRYPT_MAX_HASHSIZE ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};

static const ATTRIBUTE_ACL subACL_CtxinfoPersistent[] = {
	MKACL_B(	/* PKC is determined implicitly by storage type */
		CRYPT_CTXINFO_PERSISTENT,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ) ),
	MKACL_B(	/* Conv./MAC can be set on create to create persistent object */
		CRYPT_CTXINFO_PERSISTENT,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CONTEXT ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};

/* Context attributes */

static const ATTRIBUTE_ACL contextACL[] = {
	MKACL_N(	/* Algorithm */
		CRYPT_CTXINFO_ALGO,
		ST_CTX_ANY, ST_NONE, ST_NONE, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( CRYPT_ALGO_NONE + 1, CRYPT_ALGO_LAST - 1 ) ),
	MKACL_N(	/* Mode */
		CRYPT_CTXINFO_MODE,
		ST_CTX_CONV, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( CRYPT_MODE_NONE + 1, CRYPT_MODE_LAST - 1 ) ),
	MKACL_S(	/* Algorithm name */
		CRYPT_CTXINFO_NAME_ALGO,
		ST_CTX_ANY, ST_NONE, ST_NONE, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 3, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Mode name */
		CRYPT_CTXINFO_NAME_MODE,
		ST_CTX_CONV, ST_NONE, ST_NONE, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 3, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_N(	/* Key size in bytes */
		CRYPT_CTXINFO_KEYSIZE,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC | ST_CTX_GENERIC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( MIN_KEYSIZE, CRYPT_MAX_PKCSIZE ) ),
	MKACL_ST(	/* Block size in bytes */
		CRYPT_CTXINFO_BLOCKSIZE,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_HASH | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( RWx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		subACL_CtxinfoBlocksize ),
	MKACL_N(	/* IV size in bytes */
		CRYPT_CTXINFO_IVSIZE,
		ST_CTX_CONV, ST_NONE, ST_NONE, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( MIN_IVSIZE, CRYPT_MAX_IVSIZE ) ),
	MKACL_SL(	/* Key processing algorithm */
		/* The allowed algorithm range is a bit peculiar, usually we only
		   allow HMAC-SHA1 for normal key derivation, however PGP uses
		   plain hash algorithms for the derivation and although these
		   are never applied they are stored in the context when PGP keys
		   are loaded */
		CRYPT_CTXINFO_KEYING_ALGO, 
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWD ), 
		ROUTE( OBJECT_TYPE_CONTEXT ),
		allowedKeyingAlgos ),
	MKACL_N(	/* Key processing iterations */
		CRYPT_CTXINFO_KEYING_ITERATIONS,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, MAX_KEYSETUP_ITERATIONS ) ),
	MKACL_S(	/* Key processing salt */
		CRYPT_CTXINFO_KEYING_SALT,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S_EX(	/* Value used to derive key */
		CRYPT_CTXINFO_KEYING_VALUE,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),
#ifdef USE_FIPS140
	MKACL_S_EX(	/* Key */
		CRYPT_CTXINFO_KEY,
		ST_CTX_CONV | ST_CTX_MAC | ST_CTX_GENERIC, ST_NONE, ST_NONE, 
		MKPERM_INT( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( MIN_KEYSIZE, CRYPT_MAX_KEYSIZE ) ),
	MKACL_SLS_EX(/* Public-key components */
		CRYPT_CTXINFO_KEY_COMPONENTS, 
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		allowedPKCKeysizes ),
#else
	MKACL_S_EX(	/* Key */
		CRYPT_CTXINFO_KEY,
		ST_CTX_CONV | ST_CTX_MAC | ST_CTX_GENERIC, ST_NONE, ST_NONE, 
		MKPERM( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( MIN_KEYSIZE, CRYPT_MAX_KEYSIZE ) ),
	MKACL_SLS_EX(/* Public-key components */
		CRYPT_CTXINFO_KEY_COMPONENTS, 
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		allowedPKCKeysizes ),
#endif /* FIPS 140 keying rules */
	MKACL_S(	/* IV */
		CRYPT_CTXINFO_IV,
		ST_CTX_CONV, ST_NONE, ST_NONE, 
		MKPERM( RWx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( MIN_IVSIZE, CRYPT_MAX_IVSIZE ) ),
	MKACL_S(	/* Hash value */
		CRYPT_CTXINFO_HASHVALUE,
		ST_CTX_HASH | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( RxD_RxD ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( MIN_HASHSIZE, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* Label for private/secret key */
		CRYPT_CTXINFO_LABEL,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_ST(	/* Object is backed by a device or keyset */
		CRYPT_CTXINFO_PERSISTENT,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		subACL_CtxinfoPersistent ),
	MKACL_END(), MKACL_END()
	};

/****************************************************************************
*																			*
*								Certificate ACLs							*
*																			*
****************************************************************************/

#if defined( USE_CERTIFICATES ) || defined( USE_ENVELOPES )

static const RANGE_SUBRANGE_TYPE allowedContentTypeSubranges[] = {
	{ CRYPT_CONTENT_DATA, CRYPT_CONTENT_ENVELOPEDDATA },
#ifdef USE_CMSATTR_OBSCURE
	{ CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA, CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA },
#endif /* USE_CMSATTR_OBSCURE */
	{ CRYPT_CONTENT_DIGESTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA },
#ifdef USE_COMPRESSION
	{ CRYPT_CONTENT_COMPRESSEDDATA, CRYPT_CONTENT_COMPRESSEDDATA },
#endif /* USE_COMPRESSION */
#ifdef USE_TSP
	{ CRYPT_CONTENT_TSTINFO, CRYPT_CONTENT_TSTINFO },
#endif /* USE_TSP */
#ifdef USE_CMSATTR_OBSCURE
	{ CRYPT_CONTENT_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT },
#endif /* USE_CMSATTR_OBSCURE */
#ifdef USE_CERTVAL
	{ CRYPT_CONTENT_RTCSREQUEST, CRYPT_CONTENT_RTCSRESPONSE_EXT },
#endif /* USE_CERTVAL */
#ifdef USE_SCVP
	{ CRYPT_CONTENT_SCVPCERTVALREQUEST, CRYPT_CONTENT_SCVPVALPOLRESPONSE },
#endif /* USE_SCVP */
	{ CRYPT_CONTENT_MRTD, CRYPT_CONTENT_MRTD },
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR } 
	};
#endif /* USE_CERTIFICATES || USE_ENVELOPES */

#ifdef USE_CERTIFICATES

static const int allowedIPAddressSizes[] = \
	{ 4, 16, CRYPT_ERROR, CRYPT_ERROR };

static const ATTRIBUTE_ACL subACL_CertinfoFingerprintSHA[] = {
	MKACL_S(	/* Certs: General access */
		CRYPT_CERTINFO_FINGERPRINT_SHA1,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 20, 20 ) ),
	MKACL_S(	/* Selected other objs (requests, PKI users): Int.access only */
		CRYPT_CERTINFO_FINGERPRINT_SHA1,
		ST_CERT_ANY_CERT | ST_CERT_REQ_REV | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 20, 20 ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};

static const ATTRIBUTE_ACL subACL_CRLReason[] = {
	MKACL_N(	/* CRLs, Rev.requests: General access */
		/* We allow a range up to the last extended reason because the cert-
		   handling code transparently maps one to the other to provide the
		   illusion of a unified crlReason attribute */
		CRYPT_CERTINFO_CRLREASON,
		ST_CERT_CRL | ST_CERT_REQ_REV, ST_NONE, ST_NONE, 
		MKPERM_CERTREQ_REV( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASON_UNSPECIFIED, CRYPT_CRLEXTREASON_LAST - 1 ) ),
	MKACL_N(	/* OCSP responses: Read-only */
		/* These are contained in responses returned from an OCSP server so
		   are read-only in the high state */
		CRYPT_CERTINFO_CRLREASON,
		ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTREQ_REV( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASON_UNSPECIFIED, CRYPT_CRLREASON_LAST - 1 ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};

/* Certificate: General info */

static const ATTRIBUTE_ACL certificateACL[] = {
	MKACL_B(	/* Cert is self-signed */
		CRYPT_CERTINFO_SELFSIGNED,
		ST_CERT_ANY_CERT, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* Cert is signed and immutable */
		CRYPT_CERTINFO_IMMUTABLE,
		ST_CERT_ANY, ST_NONE, ST_NONE, 
		MKPERM_ALT_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* Cert is a magic just-works cert */
		CRYPT_CERTINFO_XYZZY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Certificate object type */
		CRYPT_CERTINFO_CERTTYPE,
		ST_CERT_ANY, ST_NONE, ST_NONE, 
		MKPERM_ALT_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CERTTYPE_NONE + 1, CRYPT_CERTTYPE_LAST - 1 ) ),
	MKACL_ST(	/* Certificate fingerprint: SHA-1 */
		CRYPT_CERTINFO_FINGERPRINT_SHA1,
		ST_CERT_ANY_CERT | ST_CERT_REQ_REV | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		subACL_CertinfoFingerprintSHA ),
	MKACL_S(	/* Certificate fingerprint: SHA-2 */
		CRYPT_CERTINFO_FINGERPRINT_SHA2,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 32, 32 ) ),
	MKACL_S(	/* Certificate fingerprint: SHAng */
		CRYPT_CERTINFO_FINGERPRINT_SHAng,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 32, 32 ) ),
	MKACL_N(	/* Cursor mgt: Rel.pos in chain/CRL/OCSP */
		/* The subtype flag is somewhat unusual since it includes as an
		   allowed subtype a cert, which doesn't have further cert components.
		   The reason for this is that when the chain is created it's just a
		   collection of certs, it isn't until all of them are available that
		   one can be marked the leaf cert and its type changed to cert chain.
		   Since an object's subtype can't be changed after it's created, we
		   have to allow cursor movement commands to certs in case one of
		   them is really the leaf in a cert chain - it's because of the way
		   the leaf can act as both a cert and a cert chain.  A pure cert
		   looks just like a one-cert chain, so there's no harm in sending a
		   movement command to a cert that isn't a chain leaf */
		CRYPT_CERTINFO_CURRENT_CERTIFICATE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL | ST_CERT_RTCS_REQ | \
					   ST_CERT_RTCS_RESP | ST_CERT_OCSP_REQ | \
					   ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( xWx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST ) ),
	MKACL_N(	/* Usage that cert is trusted for */
		CRYPT_CERTINFO_TRUSTED_USAGE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( RWD_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_KEYUSAGE_NONE, CRYPT_KEYUSAGE_LAST - 1 ) ),
	MKACL_B(	/* Whether cert is implicitly trusted */
		CRYPT_CERTINFO_TRUSTED_IMPLICIT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( RWD_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Amount of detail to include in sigs.*/
		CRYPT_CERTINFO_SIGNATURELEVEL,
		ST_CERT_OCSP_REQ, ST_NONE, ST_NONE, 
		MKPERM_CERTREV( RWx_RWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_SIGNATURELEVEL_NONE, CRYPT_SIGNATURELEVEL_ALL ) ),

	MKACL_N(	/* Certificate format version */
		CRYPT_CERTINFO_VERSION,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL | \
					   ST_CERT_RTCS_REQ | ST_CERT_RTCS_RESP | \
					   ST_CERT_OCSP_REQ | ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 3 ) ),
	MKACL_S(	/* Serial number */
		CRYPT_CERTINFO_SERIALNUMBER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL | \
					   ST_CERT_REQ_REV, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 32 ) ),
	MKACL_O(	/* Public key */
		CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
		ST_CERT_ANY_CERT, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCtxPKC ),
	MKACL_O(	/* User certificate */
		CRYPT_CERTINFO_CERTIFICATE,
		ST_CERT_CERTCHAIN | ST_CERT_CRL | ST_CERT_REQ_CERT | ST_CERT_REQ_REV | \
							ST_CERT_RTCS_REQ | ST_CERT_OCSP_REQ, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificate ),
	MKACL_O(	/* CA certificate */
		CRYPT_CERTINFO_CACERTIFICATE,
		ST_CERT_OCSP_REQ, ST_NONE, ST_NONE, 
		MKPERM_CERTREV( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificate ),
	MKACL_B(	/* Issuer DN */
		CRYPT_CERTINFO_ISSUERNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
					   ST_CERT_CRL | ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* Cert valid-from time */
		CRYPT_CERTINFO_VALIDFROM,
		ST_CERT_CERT | ST_CERT_REQ_CERT | ST_CERT_CERTCHAIN | \
					   ST_CERT_ATTRCERT, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* Cert valid-to time */
		CRYPT_CERTINFO_VALIDTO,
		ST_CERT_CERT | ST_CERT_REQ_CERT | ST_CERT_CERTCHAIN | \
					   ST_CERT_ATTRCERT, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* Subject DN */
		CRYPT_CERTINFO_SUBJECTNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* Issuer unique ID */
		CRYPT_CERTINFO_ISSUERUNIQUEID,
		ST_CERT_CERT, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Subject unique ID */
		CRYPT_CERTINFO_SUBJECTUNIQUEID,
		ST_CERT_CERT, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Cert.request (DN + public key) */
		CRYPT_CERTINFO_CERTREQUEST,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertRequest ),
	MKACL_T(	/* CRL/OCSP current-update time */
		CRYPT_CERTINFO_THISUPDATE,
		ST_CERT_CRL | ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTREV( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* CRL/OCSP next-update time */
		CRYPT_CERTINFO_NEXTUPDATE,
		ST_CERT_CRL | ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTREV( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* CRL/RTCS/OCSP cert-revocation time */
		CRYPT_CERTINFO_REVOCATIONDATE,
		ST_CERT_CRL | ST_CERT_RTCS_RESP | ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_VAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* OCSP revocation status */
		CRYPT_CERTINFO_REVOCATIONSTATUS,
		ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTREV( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_OCSPSTATUS_NOTREVOKED, CRYPT_OCSPSTATUS_UNKNOWN ) ),
	MKACL_N(	/* RTCS certificate status */
		CRYPT_CERTINFO_CERTSTATUS,
		ST_CERT_RTCS_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTVAL( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CERTSTATUS_VALID, CRYPT_CERTSTATUS_UNKNOWN ) ),
	MKACL_S(	/* Currently selected DN in string form */
		CRYPT_CERTINFO_DN,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_DNSTRING( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* PKI user ID */
		CRYPT_CERTINFO_PKIUSER_ID,
		ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_PKIUSER( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 17, 17 ) ),
	MKACL_S(	/* PKI user issue password */
		CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
		ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_PKIUSER( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 23, 23 ) ),
	MKACL_S(	/* PKI user revocation password */
		CRYPT_CERTINFO_PKIUSER_REVPASSWORD,
		ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_PKIUSER( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 23, 23 ) ),
	MKACL_B(	/* PKI user is an RA */
		CRYPT_CERTINFO_PKIUSER_RA,
		ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_END(), MKACL_END()
	};

/* Certificate: Name components */

static const ATTRIBUTE_ACL certNameACL[] = {
	MKACL_S(	/* countryName */
		CRYPT_CERTINFO_COUNTRYNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 2 ) ),
	MKACL_WCS(	/* stateOrProvinceName */
		CRYPT_CERTINFO_STATEORPROVINCENAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_WCS(	/* localityName */
		CRYPT_CERTINFO_LOCALITYNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_WCS(	/* organizationName */
		CRYPT_CERTINFO_ORGANIZATIONNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_WCS(	/* organizationalUnitName */
		CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_WCS(	/* commonName */
		CRYPT_CERTINFO_COMMONNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_S(	/* otherName.typeID */
		CRYPT_CERTINFO_OTHERNAME_TYPEID,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* otherName.value */
		CRYPT_CERTINFO_OTHERNAME_VALUE,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* rfc822Name */
		CRYPT_CERTINFO_RFC822NAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_RFC822_SIZE, MAX_RFC822_SIZE ) ),
	MKACL_S(	/* dNSName */
		CRYPT_CERTINFO_DNSNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_DNS_SIZE, MAX_DNS_SIZE ) ),
	MKACL_N(	/* directoryName */
		CRYPT_CERTINFO_DIRECTORYNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_S(	/* ediPartyName.nameAssigner */
		CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* ediPartyName.partyName */
		CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* uniformResourceIdentifier */
		CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_SLS(/* iPAddress */
		CRYPT_CERTINFO_IPADDRESS, 
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ), 
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		allowedIPAddressSizes ),
	MKACL_S(	/* registeredID */
		CRYPT_CERTINFO_REGISTEREDID,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END(), MKACL_END()
	};

/* Certificate: Extensions */

static const ATTRIBUTE_ACL certExtensionACL[] = {
	/* 1 2 840 113549 1 9 7 challengePassword.  This is here even though it's
	   a CMS attribute because SCEP stuffs it into PKCS #10 requests */
	MKACL_S(	/* challengePassword for PKCS #10 */
		CRYPT_CERTINFO_CHALLENGEPASSWORD,
		ST_CERT_CERTREQ, ST_NONE, ST_NONE, 
		MKPERM_CERTREQ( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	/* 1 3 6 1 4 1 3029 3 1 4 cRLExtReason */
	MKACL_N(	/* cRLExtReason */
		CRYPT_CERTINFO_CRLEXTREASON,
		ST_CERT_CRL | ST_CERT_REQ_REV, ST_NONE, ST_NONE, 
		MKPERM_CERTREQ_REV( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASON_UNSPECIFIED, CRYPT_CRLEXTREASON_LAST - 1 ) ),

	/* 1 3 6 1 4 1 3029 3 1 5 keyFeatures */
	MKACL_N(	/* keyFeatures */
		CRYPT_CERTINFO_KEYFEATURES,
		ST_CERT_ANY_CERT, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 7 ) ),

	/* 1 3 6 1 5 5 7 1 1 authorityInfoAccess.  The values are GeneralName
	   selectors so the ACL doesn't allow writes, since they can only be
	   used to select the GeneralName that's written to */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_AUTHORITYINFOACCESS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_RTCS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_OCSP,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_CERTSTORE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_CRLS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 3 6 1 5 5 7 1 2 biometricInfo */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_BIOMETRICINFO,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* biometricData.typeOfData */
		CRYPT_CERTINFO_BIOMETRICINFO_TYPE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 1 ) ),
	MKACL_S(	/* biometricData.hashAlgorithm */
		CRYPT_CERTINFO_BIOMETRICINFO_HASHALGO,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* biometricData.dataHash */
		CRYPT_CERTINFO_BIOMETRICINFO_HASH,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_HASHSIZE, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* biometricData.sourceDataUri */
		CRYPT_CERTINFO_BIOMETRICINFO_URL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),

	/* 1 3 6 1 5 5 7 1 3 qcStatements */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_QCSTATEMENT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* qcStatement.statementInfo.semanticsIdentifier */
		CRYPT_CERTINFO_QCSTATEMENT_SEMANTICS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_N(	/* qcStatement.statementInfo.nameRegistrationAuthorities */
		/* This is a GeneralName selector so it can't be written to directly */
		CRYPT_CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 3 6 1 5 5 7 1 7 ipAddrBlocks */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_IPADDRESSBLOCKS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* addressFamily */
		CRYPT_CERTINFO_IPADDRESSBLOCKS_ADDRESSFAMILY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 2 ) ),
	MKACL_S(	/* ipAddress.addressPrefix */
		/* See the comment in ext_def.c for the length range */
		CRYPT_CERTINFO_IPADDRESSBLOCKS_PREFIX,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 19 ) ),
	MKACL_S(	/* ipAddress.addressRangeMin */
		CRYPT_CERTINFO_IPADDRESSBLOCKS_MIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 19 ) ),
	MKACL_S(	/* ipAddress.addressRangeMax */
		CRYPT_CERTINFO_IPADDRESSBLOCKS_MAX,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 19 ) ),

	/* 1 3 6 1 5 5 7 1 8 autonomousSysIds */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_AUTONOMOUSSYSIDS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* asNum.id */
		/* See the comment in ext_def.c for the AS range */
		CRYPT_CERTINFO_AUTONOMOUSSYSIDS_ASNUM_ID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 500000 ) ),
	MKACL_N(	/* asNum.min */
		CRYPT_CERTINFO_AUTONOMOUSSYSIDS_ASNUM_MIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 500000 ) ),
	MKACL_N(	/* asNum.max */
		CRYPT_CERTINFO_AUTONOMOUSSYSIDS_ASNUM_MAX,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 500000 ) ),

	/* 1 3 6 1 5 5 7 48 1 2 ocspNonce */
	MKACL_S(	/* nonce */
		CRYPT_CERTINFO_OCSP_NONCE,
		ST_CERT_OCSP_REQ | ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTREV( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 1 3 6 1 5 5 7 48 1 4 ocspAcceptableResponses */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_OCSP_RESPONSE,
		ST_CERT_OCSP_REQ, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* OCSP standard response */
		CRYPT_CERTINFO_OCSP_RESPONSE_OCSP,
		ST_CERT_OCSP_REQ, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 3 6 1 5 5 7 48 1 5 ocspNoCheck */
	MKACL_N(	/* noCheck */
		CRYPT_CERTINFO_OCSP_NOCHECK,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 1 3 6 1 5 5 7 48 1 6 ocspArchiveCutoff */
	MKACL_T(	/* archiveCutoff */
		CRYPT_CERTINFO_OCSP_ARCHIVECUTOFF,
		ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 3 6 1 5 5 7 48 1 11 subjectInfoAccess.  The values are GeneralName
	   selectors so the ACL doesn't allow writes, since they can only be
	   used to select the GeneralName that's written to */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SUBJECTINFOACCESS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_SUBJECTINFO_SIGNEDOBJECTREPOSITORY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_SUBJECTINFO_RPKIMANIFEST,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_SUBJECTINFO_SIGNEDOBJECT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 3 36 8 3 1 dateOfCertGen */
	MKACL_T(	/* dateOfCertGen */
		CRYPT_CERTINFO_SIGG_DATEOFCERTGEN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 3 36 8 3 2 procuration */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SIGG_PROCURATION,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* country */
		CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 2 ) ),
	MKACL_S(	/* typeOfSubstitution */
		CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_N(	/* signingFor.thirdPerson */
		CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 3 36 8 3 3 siggAdmissions */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SIGG_ADMISSIONS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* authority */
		CRYPT_CERTINFO_SIGG_ADMISSIONS_AUTHORITY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_S(	/* namingAuth.iD */
		CRYPT_CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* namingAuth.uRL */
		CRYPT_CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_S(	/* namingAuth.text */
		CRYPT_CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHTEXT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_S(	/* professionItem */
		CRYPT_CERTINFO_SIGG_ADMISSIONS_PROFESSIONITEM,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_S(	/* professionOID */
		CRYPT_CERTINFO_SIGG_ADMISSIONS_PROFESSIONOID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* registrationNumber */
		CRYPT_CERTINFO_SIGG_ADMISSIONS_REGISTRATIONNUMBER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),

	/* 1 3 36 8 3 4 monetaryLimit */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SIGG_MONETARYLIMIT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* currency */
		CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 3 ) ),
	MKACL_N(	/* amount */
		CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 255 ) ),
	MKACL_N(	/* exponent */
		CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 255 ) ),

	/* 1 3 36 8 3 5 declarationOfMajority */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SIGG_DECLARATIONOFMAJORITY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* fullAgeAtCountry */
		CRYPT_CERTINFO_SIGG_DECLARATIONOFMAJORITY_COUNTRY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 2 ) ),

	/* 1 3 36 8 3 8 restriction */
	MKACL_S(	/* restriction */
		CRYPT_CERTINFO_SIGG_RESTRICTION,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),

	/* 1 3 36 8 3 13 siggCertHash */
	MKACL_S(	/* certHash */
		CRYPT_CERTINFO_SIGG_CERTHASH,
		ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 32, MAX_ATTRIBUTE_SIZE ) ),

	/* 1 3 36 8 3 15 additionalInformation */
	MKACL_S(	/* additionalInformation */
		CRYPT_CERTINFO_SIGG_ADDITIONALINFORMATION,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_PKIX_PARTIAL_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),

	/* 1 3 101 1 4 1 strongExtranet */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_STRONGEXTRANET,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* sxNetIDList.sxNetID.zone */
		CRYPT_CERTINFO_STRONGEXTRANET_ZONE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, RANGE_MAX ) ),
	MKACL_S(	/* sxNetIDList.sxNetID.id */
		CRYPT_CERTINFO_STRONGEXTRANET_ID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 2 5 29 9 subjectDirectoryAttributes */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
  #ifdef USE_CUSTOM_CONFIG_1
	MKACL_S(	/* Object class */
		CRYPT_CERTINFO_SUBJECTDIR_OBJECTCLASS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* Clearance policy */
		CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_POLICY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_N(	/* Clearance level */
		CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CLASSLIST,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 31 ) ),
	MKACL_S(	/* Clearance category policy 1 */
		CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CATEGORY_POLICY1,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Clearance category policy 1 */
		CRYPT_CERTINFO_SUBJECTDIR_CLEARANCE_CATEGORY_POLICY2,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 16, 16 ) ),
  #else
	MKACL_S(	/* attribute.type */
		CRYPT_CERTINFO_SUBJECTDIR_TYPE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* attribute.values */
		CRYPT_CERTINFO_SUBJECTDIR_VALUES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),
  #endif /* USE_CUSTOM_CONFIG_1 */

	/* 2 5 29 14 subjectKeyIdentifier */
	MKACL_S(	/* subjectKeyIdentifier */
		CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 2 5 29 15 keyUsage */
	MKACL_N(	/* keyUsage */
		CRYPT_CERTINFO_KEYUSAGE,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_KEYUSAGE_NONE + 1, CRYPT_KEYUSAGE_LAST - 1 ) ),

	/* 2 5 29 16 privateKeyUsagePeriod */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* notBefore */
		CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* notBefore */
		CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 17 subjectAltName */
	MKACL_N(	/* subjectAltName */
		CRYPT_CERTINFO_SUBJECTALTNAME,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 18 issuerAltName */
	MKACL_N(	/* issuerAltName */
		CRYPT_CERTINFO_ISSUERALTNAME,
		ST_CERT_ANY_CERT, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 19 basicConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_BASICCONSTRAINTS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* cA */
		CRYPT_CERTINFO_CA,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* pathLenConstraint */
		CRYPT_CERTINFO_PATHLENCONSTRAINT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),

	/* 2 5 29 20 cRLNumber */
#ifdef CONFIG_CUSTOM_1
	MKACL_S(	/* cRLNumber */
		CRYPT_CERTINFO_CRLNUMBER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 20 ) ),
#else
	MKACL_N(	/* cRLNumber */
		CRYPT_CERTINFO_CRLNUMBER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, RANGE_MAX ) ),
#endif /* CONFIG_CUSTOM_1 */

	/* 2 5 29 21 cRLReason */
	MKACL_ST(	/* cRLReason */
		CRYPT_CERTINFO_CRLREASON,
		ST_CERT_CRL | ST_CERT_REQ_REV | ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_CERTREQ_REV( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		subACL_CRLReason ),

	/* 2 5 29 23 holdInstructionCode */
	MKACL_N(	/* holdInstructionCode */
		CRYPT_CERTINFO_HOLDINSTRUCTIONCODE,
		ST_CERT_CRL | ST_CERT_REQ_REV, ST_NONE, ST_NONE, 
		MKPERM_CERTREQ_REV_PKIX_FULL( Rxx_RWD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_HOLDINSTRUCTION_NONE + 1, CRYPT_HOLDINSTRUCTION_LAST - 1 ) ),

	/* 2 5 29 24 invalidityDate */
	MKACL_T(	/* invalidityDate */
		CRYPT_CERTINFO_INVALIDITYDATE,
		ST_CERT_CRL | ST_CERT_REQ_REV, ST_NONE, ST_NONE, 
		MKPERM_CERTREQ_REV( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 27 deltaCRLIndicator */
#ifdef CONFIG_CUSTOM_1
	MKACL_S(	/* deltaCRLIndicator */
		CRYPT_CERTINFO_DELTACRLINDICATOR,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 20 ) ),
#else
	MKACL_N(	/* deltaCRLIndicator */
		CRYPT_CERTINFO_DELTACRLINDICATOR,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, RANGE_MAX ) ),
#endif /* CONFIG_CUSTOM_1 */

	/* 2 5 29 28 issuingDistributionPoint */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RxD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_ISSUINGDIST_FULLNAME,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RxD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_B(	/* onlyContainsUserCerts */
		CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* onlyContainsCACerts */
		CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* onlySomeReasons */
		CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASONFLAG_UNUSED, CRYPT_CRLREASONFLAG_LAST - 1 ) ),
	MKACL_B(	/* indirectCRL */
		CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 29 certificateIssuer */
	MKACL_N(	/* certificateIssuer */
		CRYPT_CERTINFO_CERTIFICATEISSUER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_PARTIAL( Rxx_RxD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 30 nameConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_NAMECONSTRAINTS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* permittedSubtrees */
		CRYPT_CERTINFO_PERMITTEDSUBTREES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* excludedSubtrees */
		CRYPT_CERTINFO_EXCLUDEDSUBTREES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 31 cRLDistributionPoint */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_CRLDIST_FULLNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* reasons */
		CRYPT_CERTINFO_CRLDIST_REASONS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASONFLAG_UNUSED, CRYPT_CRLREASONFLAG_LAST - 1 ) ),
	MKACL_N(	/* cRLIssuer */
		CRYPT_CERTINFO_CRLDIST_CRLISSUER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 32 certificatePolicies */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CERTIFICATEPOLICIES,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* policyInformation.policyIdentifier */
		CRYPT_CERTINFO_CERTPOLICYID,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.cPSuri */
		CRYPT_CERTINFO_CERTPOLICY_CPSURI,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization */
		CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 200 ) ),
	MKACL_N(	/* policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers */
		CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1024 ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.userNotice.explicitText */
		CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 200 ) ),

	/* 2 5 29 33 policyMappings */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_POLICYMAPPINGS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* policyMappings.issuerDomainPolicy */
		CRYPT_CERTINFO_ISSUERDOMAINPOLICY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* policyMappings.subjectDomainPolicy */
		CRYPT_CERTINFO_SUBJECTDOMAINPOLICY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),

	/* 2 5 29 35 authorityKeyIdentifier */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* keyIdentifier */
		CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_N(	/* authorityCertIssuer */
		CRYPT_CERTINFO_AUTHORITY_CERTISSUER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_S(	/* authorityCertSerialNumber */
		CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_PARTIAL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 2 5 29 36 policyConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_POLICYCONSTRAINTS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* policyConstraints.requireExplicitPolicy */
		CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),
	MKACL_N(	/* policyConstraints.inhibitPolicyMapping */
		CRYPT_CERTINFO_INHIBITPOLICYMAPPING,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),

	/* 2 5 29 37 extKeyUsage */
	MKACL_N(	/* Extension present flag */
		CRYPT_CERTINFO_EXTKEYUSAGE,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* individualCodeSigning */
		CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* commercialCodeSigning */
		CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* certTrustListSigning */
		CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* timeStampSigning */
		CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* serverGatedCrypto */
		CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* encrypedFileSystem */
		CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* serverAuth */
		CRYPT_CERTINFO_EXTKEY_SERVERAUTH,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* clientAuth */
		CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* codeSigning */
		CRYPT_CERTINFO_EXTKEY_CODESIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* emailProtection */
		CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* ipsecEndSystem */
		CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* ipsecTunnel */
		CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* ipsecUser */
		CRYPT_CERTINFO_EXTKEY_IPSECUSER,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* timeStamping */
		CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* ocspSigning */
		CRYPT_CERTINFO_EXTKEY_OCSPSIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* directoryService */
		CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* anyExtendedKeyUsage */
		/* This extension exists solely as a bugfix for a circular
		   definition in the PKIX RFC and introduces a number of further
		   problems, to avoid falling into this rathole we don't allow
		   the creation of certs with this usage type */
		CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* serverGatedCrypto */
		CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* serverGatedCrypto CA */
		CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERTIFICATES( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 2 5 29 40 crlStreamIdentifier */
	MKACL_N(	/* crlStreamIdentifier */
		CRYPT_CERTINFO_CRLSTREAMIDENTIFIER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),

	/* 2 5 29 46 freshestCRL */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_FRESHESTCRL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_FRESHESTCRL_FULLNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* reasons */
		CRYPT_CERTINFO_FRESHESTCRL_REASONS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASONFLAG_UNUSED, CRYPT_CRLREASONFLAG_LAST - 1 ) ),
	MKACL_N(	/* cRLIssuer */
		CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 47 orderedList */
	MKACL_N(	/* orderedList */
		CRYPT_CERTINFO_ORDEREDLIST,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 1 ) ),

	/* 2 5 29 51 baseUpdateTime */
	MKACL_T(	/* baseUpdateTime */
		CRYPT_CERTINFO_BASEUPDATETIME,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 53 deltaInfo */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_DELTAINFO,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* deltaLocation */
		CRYPT_CERTINFO_DELTAINFO_LOCATION,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_T(	/* nextDelta */
		CRYPT_CERTINFO_DELTAINFO_NEXTDELTA,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 54 inhibitAnyPolicy */
	MKACL_N(	/* inhibitAnyPolicy */
		CRYPT_CERTINFO_INHIBITANYPOLICY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_CERT_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),

	/* 2 5 29 58 toBeRevoked */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_TOBEREVOKED,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* certificateIssuer */
		CRYPT_CERTINFO_TOBEREVOKED_CERTISSUER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* reasonCode */
		CRYPT_CERTINFO_TOBEREVOKED_REASONCODE,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASON_UNSPECIFIED, CRYPT_CRLEXTREASON_LAST - 1 ) ),
	MKACL_T(	/* revocationTime */
		CRYPT_CERTINFO_TOBEREVOKED_REVOCATIONTIME,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* certSerialNumber */
		CRYPT_CERTINFO_TOBEREVOKED_CERTSERIALNUMBER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 2 5 29 59 revokedGroups */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_REVOKEDGROUPS,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* certificateIssuer */
		CRYPT_CERTINFO_REVOKEDGROUPS_CERTISSUER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* reasonCode */
		CRYPT_CERTINFO_REVOKEDGROUPS_REASONCODE,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASON_UNSPECIFIED, CRYPT_CRLEXTREASON_LAST - 1 ) ),
	MKACL_T(	/* revocationTime */
		CRYPT_CERTINFO_REVOKEDGROUPS_INVALIDITYDATE,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* startingNumber */
		CRYPT_CERTINFO_REVOKEDGROUPS_STARTINGNUMBER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_S(	/* endingNumber */
		CRYPT_CERTINFO_REVOKEDGROUPS_ENDINGNUMBER,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 2 5 29 60 expiredCertsOnCRL */
	MKACL_T(	/* expiredCertsOnCRL */
		CRYPT_CERTINFO_EXPIREDCERTSONCRL,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 63 aaIssuingDistributionPoint */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_AAISSUINGDISTRIBUTIONPOINT,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RxD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_AAISSUINGDIST_FULLNAME,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RxD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* onlySomeReasons */
		CRYPT_CERTINFO_AAISSUINGDIST_SOMEREASONSONLY,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASONFLAG_UNUSED, CRYPT_CRLREASONFLAG_LAST - 1 ) ),
	MKACL_B(	/* indirectCRL */
		CRYPT_CERTINFO_AAISSUINGDIST_INDIRECTCRL,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* containsUserAttributeCerts */
		CRYPT_CERTINFO_AAISSUINGDIST_USERATTRCERTS,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),	
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* containsAACerts */
		CRYPT_CERTINFO_AAISSUINGDIST_AACERTS,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* containsSOAPublicKeyCerts */
		CRYPT_CERTINFO_AAISSUINGDIST_SOACERTS,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_CERTREV_PKIX_FULL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 16 840 1 113730 1 x Netscape extensions (obsolete) */
	MKACL_N(	/* netscape-cert-type */
		/* This attribute can't normally be set, however when creating a
		   template of disallowed attributes to apply to an about-to-be-
		   issued cert we need to be able to set it to mask out any
		   attributes of this type that may have come in via a cert
		   request */
		CRYPT_CERTINFO_NS_CERTTYPE,
		ST_CERT_ANY_CERT, ST_NONE, ST_NONE, 
		MKPERM_SPECIAL_CERTIFICATES( Rxx_RWx_Rxx_Rxx ),		/* OBSOLETE */
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_NS_CERTTYPE_SSLCLIENT, CRYPT_NS_CERTTYPE_LAST - 1 ) ),
	MKACL_S(	/* netscape-base-url */
		CRYPT_CERTINFO_NS_BASEURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-revocation-url */
		CRYPT_CERTINFO_NS_REVOCATIONURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ca-revocation-url */
		CRYPT_CERTINFO_NS_CAREVOCATIONURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-cert-renewal-url */
		CRYPT_CERTINFO_NS_CERTRENEWALURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ca-policy-url */
		CRYPT_CERTINFO_NS_CAPOLICYURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ssl-server-name */
		CRYPT_CERTINFO_NS_SSLSERVERNAME,
		ST_CERT_ANY_CERT, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-comment */
		CRYPT_CERTINFO_NS_COMMENT,
		ST_CERT_ANY_CERT, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),

	/* 2 23 42 7 0 SET hashedRootKey */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_HASHEDROOTKEY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* rootKeyThumbPrint */
		CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 20, 20 ) ),

	/* 2 23 42 7 1 SET certificateType */
	MKACL_N(	/* certificateType */
		CRYPT_CERTINFO_SET_CERTIFICATETYPE,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_SET_CERTTYPE_CARD, CRYPT_SET_CERTTYPE_LAST - 1 ) ),

	/* 2 23 42 7 2 SET merchantData */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_MERCHANTDATA,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* merID */
		CRYPT_CERTINFO_SET_MERID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 30 ) ),
	MKACL_S(	/* merAcquirerBIN */
		CRYPT_CERTINFO_SET_MERACQUIRERBIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 6, 6 ) ),
	MKACL_S(	/* merNames.language */
		CRYPT_CERTINFO_SET_MERCHANTLANGUAGE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 35 ) ),
	MKACL_S(	/* merNames.name */
		CRYPT_CERTINFO_SET_MERCHANTNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.city */
		CRYPT_CERTINFO_SET_MERCHANTCITY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.stateProvince */
		CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.postalCode */
		CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.countryName */
		CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_N(	/* merCountry */
		CRYPT_CERTINFO_SET_MERCOUNTRY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 999 ) ),
	MKACL_B(	/* merAuthFlag */
		CRYPT_CERTINFO_SET_MERAUTHFLAG,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 23 42 7 3 SET certCardRequired */
	MKACL_B(	/* certCardRequired */
		CRYPT_CERTINFO_SET_CERTCARDREQUIRED,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 23 42 7 4 SET tunneling */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_TUNNELING,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* tunneling */
		CRYPT_CERTINFO_SET_TUNNELINGFLAG,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* tunnelingAlgID */
		CRYPT_CERTINFO_SET_TUNNELINGALGID,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_CERT_OBSOLETE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_END(), MKACL_END()
	};

/* Certificate: S/MIME attributes */

static const ATTRIBUTE_ACL certSmimeACL[] = {
	/* 1 2 840 113549 1 9 3 contentType */
	MKACL_SS(	/* contentType */
		CRYPT_CERTINFO_CMS_CONTENTTYPE, 
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ), 
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		allowedContentTypeSubranges ),

	/* 1 2 840 113549 1 9 4 messageDigest */
	MKACL_S(	/* messageDigest */
		CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_HASHSIZE, CRYPT_MAX_HASHSIZE ) ),

	/* 1 2 840 113549 1 9 5 signingTime */
	MKACL_T(	/* signingTime */
		CRYPT_CERTINFO_CMS_SIGNINGTIME,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_SPECIAL_CMSATTR( Rxx_RWD_Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 2 840 113549 1 9 6 counterSignature */
	MKACL_S(	/* counterSignature */
		CRYPT_CERTINFO_CMS_COUNTERSIGNATURE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 64, MAX_ATTRIBUTE_SIZE ) ),

	/* 1 2 840 113549 1 9 13 signingDescription */
	MKACL_S(	/* counterSignature */
		CRYPT_CERTINFO_CMS_SIGNINGDESCRIPTION,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),

	/* 1 2 840 113549 1 9 15 sMIMECapabilities */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SMIMECAPABILITIES,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* 3DES encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_3DES,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* AES encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_AES,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* CAST-128 encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_CAST128,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* SHA2-ng hash */
		CRYPT_CERTINFO_CMS_SMIMECAP_SHAng,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* SHA2-256 hash */
		CRYPT_CERTINFO_CMS_SMIMECAP_SHA2,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* SHA1 hash */
		CRYPT_CERTINFO_CMS_SMIMECAP_SHA1,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* HMAC-SHA2-ng MAC */
		CRYPT_CERTINFO_CMS_SMIMECAP_HMAC_SHAng,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* HMAC-SHA2-256 MAC */
		CRYPT_CERTINFO_CMS_SMIMECAP_HMAC_SHA2,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* HMAC-SHA1 MAC */
		CRYPT_CERTINFO_CMS_SMIMECAP_HMAC_SHA1,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* AuthEnc w.256-bit key */
		CRYPT_CERTINFO_CMS_SMIMECAP_AUTHENC256,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* AuthEnc w.128-bit key */
		CRYPT_CERTINFO_CMS_SMIMECAP_AUTHENC128,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* RSA with SHA-ng signing */
		CRYPT_CERTINFO_CMS_SMIMECAP_RSA_SHAng,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* RSA with SHA2-256 signing */
		CRYPT_CERTINFO_CMS_SMIMECAP_RSA_SHA2,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* RSA with SHA1 signing */
		CRYPT_CERTINFO_CMS_SMIMECAP_RSA_SHA1,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* DSA with SHA-1 signing */
		CRYPT_CERTINFO_CMS_SMIMECAP_DSA_SHA1,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* ECDSA with SHA-ng signing */
		CRYPT_CERTINFO_CMS_SMIMECAP_ECDSA_SHAng,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* ECDSA with SHA2-256 signing */
		CRYPT_CERTINFO_CMS_SMIMECAP_ECDSA_SHA2,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* ECDSA with SHA-1 signing */
		CRYPT_CERTINFO_CMS_SMIMECAP_ECDSA_SHA1,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* preferSignedData */
		CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* canNotDecryptAny */
		CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* preferBinaryInside */
		CRYPT_CERTINFO_CMS_SMIMECAP_PREFERBINARYINSIDE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE,
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 1 2 840 113549 1 9 16 2 1 receiptRequest */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_RECEIPTREQUEST,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* contentIdentifier */
		CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 16, 64 ) ),
	MKACL_N(	/* receiptsFrom */
		CRYPT_CERTINFO_CMS_RECEIPT_FROM,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 1 ) ),
	MKACL_N(	/* receiptsTo */
		CRYPT_CERTINFO_CMS_RECEIPT_TO,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 2 840 113549 1 9 16 2 2 essSecurityLabel */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SECURITYLABEL,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* securityPolicyIdentifier */
		CRYPT_CERTINFO_CMS_SECLABEL_POLICY,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_N(	/* securityClassification */
		CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST ) ),
	MKACL_S(	/* privacyMark */
		CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_S(	/* securityCategories.securityCategory.type */
		CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* securityCategories.securityCategory.value */
		CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),

	/* 1 2 840 113549 1 9 16 2 3 mlExpansionHistory */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* mlData.mailListIdentifier.issuerAndSerialNumber */
		CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),
	MKACL_T(	/* mlData.expansionTime */
		CRYPT_CERTINFO_CMS_MLEXP_TIME,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* mlData.mlReceiptPolicy.none */
		CRYPT_CERTINFO_CMS_MLEXP_NONE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* mlData.mlReceiptPolicy.insteadOf.generalNames.generalName */
		CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName */
		CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 2 840 113549 1 9 16 2 4 contentHints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_CONTENTHINTS,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* contentDescription */
		CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_N(	/* contentType */
		CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST - 1 ) ),

	/* 1 2 840 113549 1 9 16 2 9 equivalentLabels */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_EQUIVALENTLABEL,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* securityPolicyIdentifier */
		CRYPT_CERTINFO_CMS_EQVLABEL_POLICY,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_N(	/* securityClassification */
		CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST ) ),
	MKACL_S(	/* privacyMark */
		CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_S(	/* securityCategories.securityCategory.type */
		CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* securityCategories.securityCategory.value */
		CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),

	/* 1 2 840 113549 1 9 16 2 12 signingCertificate */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE_TSP( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* certs.essCertID */
		CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE_TSP( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 32, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* policies.policyInformation.policyIdentifier */
		CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE_TSP( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),

	/* 1 2 840 113549 1 9 16 2 47 signingCertificateV2 */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATEV2,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* certs.essCertID */
		CRYPT_CERTINFO_CMS_SIGNINGCERTV2_ESSCERTIDV2,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 32, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* policies.policyInformation.policyIdentifier */
		CRYPT_CERTINFO_CMS_SIGNINGCERTV2_POLICIES,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),

	/* 1 2 840 113549 1 9 16 2 15 signaturePolicyID */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SIGNATUREPOLICYID,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyID */
		CRYPT_CERTINFO_CMS_SIGPOLICYID,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_ASCII_OIDSIZE, 32 ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyHash */
		CRYPT_CERTINFO_CMS_SIGPOLICYHASH,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 32, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.cPSuri */
		CRYPT_CERTINFO_CMS_SIGPOLICY_CPSURI,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization */
		CRYPT_CERTINFO_CMS_SIGPOLICY_ORGANIZATION,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 200 ) ),
	MKACL_N(	/* signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers */
		CRYPT_CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1024 ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText */
		CRYPT_CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 200 ) ),

	/* 1 2 840 113549 1 9 16 9 signatureTypeIdentifier */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SIGTYPEIDENTIFIER,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* originatorSig */
		CRYPT_CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* domainSig */
		CRYPT_CERTINFO_CMS_SIGTYPEID_DOMAINSIG,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* additionalAttributesSig */
		CRYPT_CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* reviewSig */
		CRYPT_CERTINFO_CMS_SIGTYPEID_REVIEWSIG,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 1 2 840 113549 1 9 25 3 randomNonce */
	MKACL_S(	/* randomNonce */
		/* This is valid in RTCS requests, which are occasionally
		   communicated using a CMS content-type that can't provide
		   attributes so they need to be bundled with the request instead,
		   and is also used in OCSP responses to avoid signing identical
		   data leaving an opening for a fault attack */
		CRYPT_CERTINFO_CMS_NONCE,
		ST_CERT_CMSATTR | ST_CERT_OCSP_RESP | ST_CERT_RTCS_REQ, ST_NONE, ST_NONE, 
		MKPERM_CERTVAL( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 4, CRYPT_MAX_HASHSIZE ) ),

	/* 1 2 840 113549 1 9 52 cmsAlgorithmProtection */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_ALGORITHMPROTECTION,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Signer hash algorithm */
		CRYPT_CERTINFO_CMS_ALGORITHMPROTECTION_HASH,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( CRYPT_ALGO_FIRST_HASH, CRYPT_ALGO_LAST_HASH ) ),
	MKACL_N(	/* Signer sig.algorithm */
		CRYPT_CERTINFO_CMS_ALGORITHMPROTECTION_SIG,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( CRYPT_ALGO_FIRST_PKC, CRYPT_ALGO_LAST_PKC ) ),
	MKACL_N(	/* Signer MAC algorithm */
		CRYPT_CERTINFO_CMS_ALGORITHMPROTECTION_MAC,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( CRYPT_ALGO_FIRST_MAC, CRYPT_ALGO_LAST_MAC ) ),

	/* SCEP attributes:
	   2 16 840 1 113733 1 9 2 messageType
	   2 16 840 1 113733 1 9 3 pkiStatus
	   2 16 840 1 113733 1 9 4 failInfo
	   2 16 840 1 113733 1 9 5 senderNonce
	   2 16 840 1 113733 1 9 6 recipientNonce
	   2 16 840 1 113733 1 9 7 transID */
	MKACL_S(	/* messageType */
		CRYPT_CERTINFO_SCEP_MESSAGETYPE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_SCEP( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 2 ) ),
	MKACL_S(	/* pkiStatus */
		CRYPT_CERTINFO_SCEP_PKISTATUS,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_SCEP( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1 ) ),
	MKACL_S(	/* failInfo */
		CRYPT_CERTINFO_SCEP_FAILINFO,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_SCEP( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1 ) ),
	MKACL_S(	/* senderNonce */
		CRYPT_CERTINFO_SCEP_SENDERNONCE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_SCEP( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* recipientNonce */
		CRYPT_CERTINFO_SCEP_RECIPIENTNONCE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_SCEP( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* transID */
		CRYPT_CERTINFO_SCEP_TRANSACTIONID,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_SCEP( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),

	/* 1 3 6 1 4 1 311 2 1 10 spcAgencyInfo */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SPCAGENCYINFO,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* spcAgencyInfo.url */
		CRYPT_CERTINFO_CMS_SPCAGENCYURL,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),

	/* 1 3 6 1 4 1 311 2 1 11 spcStatementType */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* individualCodeSigning */
		CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* commercialCodeSigning */
		CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 1 3 6 1 4 1 311 2 1 12 spcOpusInfo */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SPCOPUSINFO,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RxD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* spcOpusInfo.name */
		CRYPT_CERTINFO_CMS_SPCOPUSINFO_NAME,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 128 ) ),
	MKACL_S(	/* spcOpusInfo.url */
		CRYPT_CERTINFO_CMS_SPCOPUSINFO_URL,
		ST_CERT_CMSATTR, ST_NONE, ST_NONE, 
		MKPERM_CMSATTR_OBSCURE( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_END(), MKACL_END()
	};
#endif /* USE_CERTIFICATES */

/****************************************************************************
*																			*
*									Keyset ACLs								*
*																			*
****************************************************************************/

#ifdef USE_KEYSETS

/* Keyset attributes */

static const ATTRIBUTE_ACL keysetACL[] = {
	MKACL_S(	/* Keyset query */
		CRYPT_KEYINFO_QUERY,
		ST_NONE, ST_KEYSET_DBMS | ST_KEYSET_DBMS_STORE, ST_NONE, 
		MKPERM_DBMS( xWx_xWx ),
		ROUTE( OBJECT_TYPE_KEYSET ),
		RANGE( 6, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Query of requests in cert store */
		CRYPT_KEYINFO_QUERY_REQUESTS,
		ST_NONE, ST_KEYSET_DBMS_STORE, ST_NONE, 
		MKPERM_DBMS( xWx_xWx ),
		ROUTE( OBJECT_TYPE_KEYSET ),
		RANGE( 6, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END(), MKACL_END()
	};
#endif /* USE_KEYSETS */

/****************************************************************************
*																			*
*									Device ACLs								*
*																			*
****************************************************************************/

/* Device attributes */

static const ATTRIBUTE_ACL deviceACL[] = {
	MKACL_S_EX(	/* Initialise device for use */
		CRYPT_DEVINFO_INITIALISE,
		ST_NONE, ST_DEV_P11 | ST_DEV_TPM | ST_DEV_HW, ST_NONE, 
		MKPERM( xWx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S_EX(	/* Authenticate user to device */
		/* This is allowed in both the low and high states since the device
		   may be in the SSO initialised state and all we're doing is
		   switching it to the user initialised state */
		CRYPT_DEVINFO_AUTHENT_USER,
		ST_NONE, ST_DEV_P11 | ST_DEV_HW, ST_NONE, 
		MKPERM( xWx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S_EX(	/* Authenticate supervisor to dev.*/
		CRYPT_DEVINFO_AUTHENT_SUPERVISOR,
		ST_NONE, ST_DEV_P11 | ST_DEV_HW, ST_NONE, 
		MKPERM( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Set user authent.value */
		CRYPT_DEVINFO_SET_AUTHENT_USER,
		ST_NONE, ST_DEV_P11 | ST_DEV_TPM | ST_DEV_HW, ST_NONE, 
		MKPERM( xWx_xxx ),
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Set supervisor auth.val.*/
		CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR,
		ST_NONE, ST_DEV_P11 | ST_DEV_TPM | ST_DEV_HW, ST_NONE, 
		MKPERM( xWx_xxx ),
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Zeroise device */
		CRYPT_DEVINFO_ZEROISE,
		ST_NONE, ST_DEV_P11 | ST_DEV_TPM | ST_DEV_HW, ST_NONE, 
		MKPERM( xWx_xWx ),
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_B(	/* Whether user is logged in */
		CRYPT_DEVINFO_LOGGEDIN,
		ST_NONE, ST_DEV_ANY_STD, ST_NONE, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_DEVICE ) ),
	MKACL_S(	/* Device/token label */
		CRYPT_DEVINFO_LABEL,
		ST_NONE, ST_DEV_ANY_STD, ST_NONE, 
		MKPERM( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END(), MKACL_END()
	};

/****************************************************************************
*																			*
*									Envelope ACLs							*
*																			*
****************************************************************************/

#ifdef USE_ENVELOPES

static const RANGE_SUBRANGE_TYPE allowedSigResultSubranges[] = {
	/* We make the error subrange start at CRYPT_ERROR_MEMORY rather than
	   the generic CRYPT_ERROR_PARAM1, which is the same as CRYPT_ERROR,
	   the end-of-range marker */
	{ CRYPT_OK, CRYPT_OK },
	{ CRYPT_ERROR_MEMORY, CRYPT_ENVELOPE_RESOURCE },
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};

static const ATTRIBUTE_ACL subACL_EnvinfoContentType[] = {
	MKACL_SS(	/* Envelope: Read/write */
		CRYPT_ENVINFO_CONTENTTYPE, 
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		allowedContentTypeSubranges ),
	MKACL_SS(	/* Deenvelope: Read-only */
		CRYPT_ENVINFO_CONTENTTYPE, 
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_xxx ), 
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		allowedContentTypeSubranges ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_EnvinfoIntegrity[] = {
	MKACL_N(	/* Envelope: Write-only */
		CRYPT_ENVINFO_INTEGRITY,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE( CRYPT_INTEGRITY_NONE, CRYPT_INTEGRITY_FULL ) ),
	MKACL_N(	/* De-envelope: Read-only */
		CRYPT_ENVINFO_INTEGRITY,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE( CRYPT_INTEGRITY_NONE, CRYPT_INTEGRITY_FULL ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_EnvinfoSignature[] = {
	MKACL_O(	/* Envelope: Write-only */
		CRYPT_ENVINFO_SIGNATURE,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxPKC ),
	MKACL_O(	/* De-envelope: Read/write */
		/* This is readable and writeable since it can be used to add a sig-
		   check key to an envelope that doesn't include certs */
		CRYPT_ENVINFO_SIGNATURE,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( RWx_xxx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxPKC ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_EnvinfoSignatureExtraData[] = {
	MKACL_O(	/* Envelope: Write-only */
		CRYPT_ENVINFO_SIGNATURE_EXTRADATA,
		ST_NONE, ST_ENV_ENV, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCMSAttr ),
	MKACL_O(	/* De-envelope: Read-only */
		CRYPT_ENVINFO_SIGNATURE_EXTRADATA,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCMSAttr ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_EnvinfoTimestamp[] = {
	MKACL_O(	/* Envelope: Write-only TSP session */
		CRYPT_ENVINFO_TIMESTAMP,
		ST_NONE, ST_ENV_ENV, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectSessionTSP ),
	MKACL_O(	/* De-envelope: Read-only sub-envelope */
		CRYPT_ENVINFO_TIMESTAMP,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectDeenvelope ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};

/* Envelope attributes */

static const ATTRIBUTE_ACL envelopeACL[] = {
	MKACL_N(	/* Data size information */
		/* The maximum length is adjusted by MAX_INTLENGTH_DELTA bytes
		   because what this attribute specifies is only the payload size
		   and not the overall message size, which could be up to
		   MAX_INTLENGTH_DELTA bytes larger */
		CRYPT_ENVINFO_DATASIZE,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 0, MAX_INTLENGTH - MAX_INTLENGTH_DELTA ) ),
	MKACL_N(	/* Compression information */
		CRYPT_ENVINFO_COMPRESSION,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_ST(	/* Inner CMS content type */
		CRYPT_ENVINFO_CONTENTTYPE,
		ST_NONE, ST_ENV_ANY, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoContentType ),
	MKACL_B(	/* Detached signature */
		CRYPT_ENVINFO_DETACHEDSIGNATURE,
		ST_NONE, ST_ENV_ANY, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_SS(	/* Signature check result */
		/* This is a special case because an OK status is positive but an
		   error status is negative, which spans two range types.  To handle
		   this we treat it as two distinct subranges, the positive CRYPT_OK
		   and the negative error values */
		CRYPT_ENVINFO_SIGNATURE_RESULT, 
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_xxx ), 
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		allowedSigResultSubranges ),
	MKACL_ST(	/* Integrity-protection level */
		CRYPT_ENVINFO_INTEGRITY,
		ST_NONE, ST_ENV_ANY, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoIntegrity ),
	MKACL_S(	/* User password */
		CRYPT_ENVINFO_PASSWORD,
		ST_NONE, ST_ENV_ANY, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Conventional encryption key */
		CRYPT_ENVINFO_KEY,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxConv ),
	MKACL_ST(	/* Signature/signature check key */
		CRYPT_ENVINFO_SIGNATURE,
		ST_NONE, ST_ENV_ANY, ST_NONE, 
		MKPERM_ENVELOPE( RWx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoSignature ),
	MKACL_ST(	/* Extra information added to CMS sigs */
		CRYPT_ENVINFO_SIGNATURE_EXTRADATA,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoSignatureExtraData ),
	MKACL_S(	/* Recipient email address */
		CRYPT_ENVINFO_RECIPIENT,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* PKC encryption key */
		CRYPT_ENVINFO_PUBLICKEY,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxPKC ),
	MKACL_O(	/* PKC decryption key */
		CRYPT_ENVINFO_PRIVATEKEY,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),  &objectCtxPKC ),
	MKACL_S(	/* Label of PKC decryption key */
		CRYPT_ENVINFO_PRIVATEKEY_LABEL,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( xxx_Rxx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Originator info/key */
		/* 18/7/16 Historic value only needed for Fortezza, permissions
				   formerly 'MKPERM_ENVELOPE( xxx_xWx )' */
		CRYPT_ENVINFO_ORIGINATOR,
		ST_NONE, ST_ENV_ENV, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xxx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxPKC ),
	MKACL_O(	/* Session key */
		CRYPT_ENVINFO_SESSIONKEY,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxConv ),
	MKACL_O(	/* Hash value */
		CRYPT_ENVINFO_HASH,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP | ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( xxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxHash ),
	MKACL_ST(	/* Timestamp */
		CRYPT_ENVINFO_TIMESTAMP,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( Rxx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoTimestamp ),
	MKACL_O(	/* Signature check keyset */
		CRYPT_ENVINFO_KEYSET_SIGCHECK,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( xWx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectKeyset ),
	MKACL_O(	/* PKC encryption keyset */
		CRYPT_ENVINFO_KEYSET_ENCRYPT,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ST_NONE, 
		MKPERM_ENVELOPE( xWx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectKeyset ),
	MKACL_O(	/* PKC decryption keyset */
		CRYPT_ENVINFO_KEYSET_DECRYPT,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_ENVELOPE( xWx_xWx ),
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectKeyset ),
	MKACL_END(), MKACL_END()
	};
#endif /* USE_ENVELOPES */

/****************************************************************************
*																			*
*									Session ACLs							*
*																			*
****************************************************************************/

#ifdef USE_SESSIONS

static const RANGE_SUBRANGE_TYPE allowedSubprotocolSubranges[] = {
#if defined( USE_WEBSOCKETS )
  #ifdef USE_EAP
	/* Both WebSockets and EAP */
	{ CRYPT_SUBPROTOCOL_WEBSOCKETS, CRYPT_SUBPROTOCOL_PEAP },
  #else
	/* WebSockets only */
	{ CRYPT_SUBPROTOCOL_WEBSOCKETS, CRYPT_SUBPROTOCOL_WEBSOCKETS },
  #endif /* USE_EAP */
#elif defined( USE_EAP )
	/* EAP only */
	{ CRYPT_SUBPROTOCOL_EAPTTLS, CRYPT_SUBPROTOCOL_PEAP },
#endif /* USE_WEBSOCKETS */
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};
static const RANGE_SUBRANGE_TYPE allowedSSHChannelSubranges[] = {
	{ CRYPT_UNUSED, CRYPT_UNUSED },
	{ 1, RANGE_MAX },
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};
static const int allowedAuthResponses[] = \
	{ CRYPT_UNUSED, FALSE, TRUE, TRUE_ALT, CRYPT_ERROR, CRYPT_ERROR };

static const ATTRIBUTE_ACL subACL_SessinfoActive[] = {
	MKACL_B_EX(	/* SSH/TLS: Can only be activated once */
		CRYPT_SESSINFO_ACTIVE,
		ST_NONE, ST_NONE, ST_SESS_ANY_DATA, 
		MKPERM_SESSIONS( Rxx_RWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_B_EX(	/* Ongoing protocol: Persistent connections */
		CRYPT_SESSINFO_ACTIVE,
		ST_NONE, ST_NONE, ST_SESS_ANY_REQRESP, 
		MKPERM_SESSIONS( RWx_RWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoUsername[] = {
	MKACL_S(	/* SSH/TLS/SCEP client: RWD for client auth */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_TLS | ST_SESS_SCEP, 
		MKPERM_SESSIONS( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSH server: Read-only for client auth */
		/* We can read this attribute in the low state because we might be
		   going back to the caller for confirmation before we transition
		   into the high state */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_NONE, ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CMP server: Read-only for client auth */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_NONE, ST_SESS_CMP_SVR, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* TLS server: RW for client auth */
		/* For TLS the username doesn't work like a standard user name but
		   instead acts as a magic value to identify a shared secret in the
		   session cache which is used to peform an TLS resume when the
		   client connects.  Multiple username/password combinations can be
		   added, what's read back is either the last one added if the
		   session hasn't been activated, or the one that was used to provide
		   the encryption keys for the currently-active session */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_NONE, ST_SESS_TLS_SVR, 
		MKPERM_SESSIONS( RWx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CMP client: RWD in both states for persistent conns */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_NONE, ST_SESS_CMP, 
		MKPERM_SESSIONS( RWD_RWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoPassword[] = {
	MKACL_S(	/* SSH/TLS/SCEP client: Write-only for client auth */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_TLS | ST_SESS_SCEP, 
		MKPERM_SESSIONS( xxx_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSH server: Read-only from client auth */
		/* We can read this attribute in the low state because we might be
		   going back to the caller for confirmation before we transition
		   into the high state */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_NONE, ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* TLS server: Write-only in both states for client auth */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_NONE, ST_SESS_TLS_SVR, 
		MKPERM_SESSIONS( xWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CMP client: Write-only in both states for persistent conns */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_NONE, ST_SESS_CMP, 
		MKPERM_SESSIONS( xWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoPrivatekey[] = {
	MKACL_O(	/* Server or SSH/TLS/SCEP client: Write-only */
		CRYPT_SESSINFO_PRIVATEKEY,
		ST_NONE, ST_NONE, MK_ST_EXCEPTION( ST_SESS_ANY_SVR, ST_SESS_CERT_SVR ) | \
						  ST_SESS_SSH | ST_SESS_TLS | ST_SESS_SCEP, 
		MKPERM_SESSIONS( xxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCtxPKC ),
	MKACL_O(	/* CMP client: Write-only in both states for persistent conns */
		CRYPT_SESSINFO_PRIVATEKEY,
		ST_NONE, ST_NONE, ST_SESS_CMP, 
		MKPERM_SESSIONS( xWx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCtxPKC ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoKeyset[] = {
	MKACL_O(	/* SSH/TLS and cert status/access protocols: Certificate/pubkey auth.source */
		CRYPT_SESSINFO_KEYSET,
		ST_NONE, ST_NONE, ST_SESS_SSH_SVR | ST_SESS_TLS_SVR | \
						  ST_SESS_RTCS_SVR | ST_SESS_SCVP_SVR | \
						  ST_SESS_OCSP_SVR | ST_SESS_CERT_SVR | \
						  ST_SESS_TLS, 
		MKPERM_SESSIONS( xxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectKeysetCerts ),
	MKACL_O(	/* Cert management protocols: Certificate store */
		CRYPT_SESSINFO_KEYSET,
		ST_NONE, ST_NONE, ST_SESS_CMP_SVR | ST_SESS_SCEP_SVR, 
		MKPERM_SESSIONS( xxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectKeysetCertstore ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoFingerprint[] = {
	MKACL_S(	/* Client: Read/write low, read-only high */
		/* The reason why we allow read in low mode although technically it 
		   should only be available in high mode is because it allows the
		   client to perform a dummy connect to check the server's key
		   fingerprint.  This is usually done by popping up a dialog asking
		   the user to click OK to continue (see "Do Users Verify SSH Keys?",
		   ;login, August 2011), however since we're a library we can't
		   display UI so performing an initial dummy connect is the best way
		   to check the fingerprint */
		CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_SSH | ST_SESS_SCEP, 
		MKPERM_SESSIONS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 20, 20 ) ),
	MKACL_S(	/* Server: Read-only */
		CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
		ST_NONE, ST_NONE, ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 20, 20 ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoVersion[] = {
	MKACL_N(	/* SSH: 2 */
		CRYPT_SESSINFO_VERSION,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 2, 2 ) ),
	MKACL_N(	/* 1 (TLS 1.0), 2 (TLS 1.1), 3 (TLS 1.2), or 4 (TLS 1.3) */
		CRYPT_SESSINFO_VERSION,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_TLS_SVR, 
		MKPERM_SESSIONS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, 4 ) ),
	MKACL_N(	/* OCSP: 1 or 2 */
		CRYPT_SESSINFO_VERSION,
		ST_NONE, ST_NONE, ST_SESS_OCSP | ST_SESS_OCSP_SVR, 
		MKPERM_SESSIONS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, 2 ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoSubprotocol[] = {
	MKACL_SS(	/* TLS client: WebSockets, EAP-TTLS, PEAP */
		CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
		ST_NONE, ST_NONE, ST_SESS_TLS, 
		MKPERM_SESSIONS( Rxx_RWx ), 
		ROUTE( OBJECT_TYPE_SESSION ),
		allowedSubprotocolSubranges ),
	MKACL_SS(	/* TLS server: WebSockets */
		CRYPT_SESSINFO_TLS_SUBPROTOCOL, 
		ST_NONE, ST_NONE, ST_SESS_TLS_SVR, 
		MKPERM_SESSIONS( Rxx_RWx ), 
		ROUTE( OBJECT_TYPE_SESSION ),
		allowedSubprotocolSubranges ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoRequest[] = {
	MKACL_O(	/* TLS session: SNI-selected server certificate */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_NONE, ST_SESS_TLS_SVR, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertificate ),
	MKACL_O(	/* RTCS session: RTCS request */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_NONE, ST_SESS_RTCS, 
		MKPERM_SESSIONS( xWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionRTCSRequest ),
	MKACL_O(	/* SCVP session: Certificate */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_NONE, ST_SESS_SCVP, 
		MKPERM_SESSIONS( xWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionSCVPRequest ),
	MKACL_O(	/* OCSP session: OCSP request */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_NONE, ST_SESS_OCSP, 
		MKPERM_SESSIONS( xWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionOCSPRequest ),
	MKACL_O(	/* CMP session: Cert/rev.request */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_NONE, ST_SESS_CMP, 
		MKPERM_SESSIONS( xWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionCMPRequest ),
	MKACL_O(	/* SCEP session: Signed or unsigned PKCS #10 request */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_NONE, ST_SESS_SCEP, 
		MKPERM_SESSIONS( xWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionPKCS10Request ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoResponse[] = {
	MKACL_O(	/* RTCS session: RTCS response */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_NONE, ST_SESS_RTCS, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertRTCSResponse ),
	MKACL_O(	/* OCSP session: OCSP response */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_NONE, ST_SESS_OCSP, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertOCSPResponse ),
	MKACL_O(	/* TLS server: Client cert during handshake */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_NONE, ST_SESS_TLS_SVR, 
		MKPERM_SESSIONS( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertificate ),
	MKACL_O(	/* TLS, PKI mgt.session: Cert, cert.response */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_CMP | ST_SESS_CMP_SVR | \
						  ST_SESS_SCEP | ST_SESS_SCEP_SVR, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertificate ),
	MKACL_O(	/* TSP session: CMS enveloped timestamp */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_NONE, ST_SESS_TSP, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectDeenvelope ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoCACertificate[] = {
	MKACL_O(	/* SCEP: Read/write */
		/* This is write-only in the low state if supplied by the user, but 
		   read-only in the high state if fetched by cryptlib as part of the 
		   SCEP handshake */
		CRYPT_SESSINFO_CACERTIFICATE,
		ST_NONE, ST_NONE, ST_SESS_SCEP, 
		MKPERM_SESSIONS( Rxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertificate ),
	MKACL_O(	/* CMP: Write-only */
		CRYPT_SESSINFO_CACERTIFICATE,
		ST_NONE, ST_NONE, ST_SESS_CMP, 
		MKPERM_SESSIONS( xxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertificate ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoRequesttype[] = {
	MKACL_N(	/* CMP/SCEP client: Read/write */
		CRYPT_SESSINFO_CMP_REQUESTTYPE,
		ST_NONE, ST_NONE, ST_SESS_CMP | ST_SESS_SCEP, 
		MKPERM_SESSIONS( RWx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( CRYPT_REQUESTTYPE_NONE + 1, CRYPT_REQUESTTYPE_LAST - 1 ) ),
	MKACL_N(	/* CMP/SCEP server: Read-only info from client */
		CRYPT_SESSINFO_CMP_REQUESTTYPE,
		ST_NONE, ST_NONE, ST_SESS_CMP_SVR | ST_SESS_SCEP_SVR, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( CRYPT_REQUESTTYPE_NONE + 1, CRYPT_REQUESTTYPE_LAST - 1 ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoSSHChannel[] = {
	MKACL_SS(	/* SSH client: Read/write */
		/* Write = CRYPT_UNUSED to create channel, read = channel number */
		CRYPT_SESSINFO_SSH_CHANNEL, 
		ST_NONE, ST_NONE, ST_SESS_SSH, 
		MKPERM_SSH_EXT( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_SESSION ),
		allowedSSHChannelSubranges ),
	MKACL_SS(	/* SSH server: Read-only info from client */
		/* Write = CRYPT_UNUSED to create channel, read = channel number */
		CRYPT_SESSINFO_SSH_CHANNEL, 
		ST_NONE, ST_NONE, ST_SESS_SSH_SVR, 
		MKPERM_SSH_EXT( RWx_xxx ), 
		ROUTE( OBJECT_TYPE_SESSION ),
		allowedSSHChannelSubranges ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoSSHChannelType[] = {
	MKACL_S(	/* SSH client: Read/write */
		/* Shortest valid name = "exec" */
		CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
		ST_NONE, ST_NONE, ST_SESS_SSH, 
		MKPERM_SSH_EXT( RWx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 4, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSH server: Read-only info from client */
		CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
		ST_NONE, ST_NONE, ST_SESS_SSH_SVR, 
		MKPERM_SSH_EXT( RWx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 7, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL subACL_SessinfoSSHChannelArg1[] = {
	MKACL_S(	/* SSH client: Read/write */
		/* Shortest valid name = "sftp" */
		CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
		ST_NONE, ST_NONE, ST_SESS_SSH, 
		MKPERM_SSH_EXT( RWx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 4, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSH server: Read-only info from client */
		CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
		ST_NONE, ST_NONE, ST_SESS_SSH_SVR, 
		MKPERM_SSH_EXT( RWx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 4, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};

/* Session attributes */

static const ATTRIBUTE_ACL sessionACL[] = {
	MKACL_ST_EX(/* Whether session is active */
		CRYPT_SESSINFO_ACTIVE,
		ST_NONE, ST_NONE, ST_SESS_ANY, 
		MKPERM_SESSIONS( RWx_RWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoActive ),
	MKACL_B(	/* Whether network connection is active */
		CRYPT_SESSINFO_CONNECTIONACTIVE,
		ST_NONE, ST_NONE, ST_SESS_ANY, 
		MKPERM_SESSIONS( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_ST(	/* User name */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_NONE, ST_SESS_ANY_DATA | ST_SESS_CMP | ST_SESS_CMP_SVR | \
						  ST_SESS_SCEP, 
		MKPERM_SESSIONS( RWD_RWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoUsername ),
	MKACL_ST(	/* Password */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_NONE, ST_SESS_ANY_DATA | ST_SESS_CMP | ST_SESS_SCEP, 
		MKPERM_SESSIONS( RWD_RWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoPassword ),
	MKACL_S(	/* Authentication token, e.g. TOTP */
		/* Write-only for SSH servers, this is the HOTP seed value used to 
		   check the OTP from the client after they connect */
		CRYPT_SESSINFO_AUTHTOKEN,
		ST_NONE, ST_NONE, ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( xxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 16, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_ST(	/* Server/client private key */
		CRYPT_SESSINFO_PRIVATEKEY,
		ST_NONE, ST_NONE, MK_ST_EXCEPTION( ST_SESS_ANY_SVR, ST_SESS_CERT_SVR ) | \
						  ST_SESS_SSH | ST_SESS_TLS | ST_SESS_CMP | \
						  ST_SESS_SCEP, 
		MKPERM_SESSIONS( xWx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoPrivatekey ),
	MKACL_ST(	/* Certificate store/auth.keyset */
		CRYPT_SESSINFO_KEYSET,
		ST_NONE, ST_NONE, MK_ST_EXCEPTION( ST_SESS_ANY_SVR, ST_SESS_TSP_SVR ) | \
						  ST_SESS_TLS, 
		MKPERM_SESSIONS( xxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoKeyset ),
	MKACL_SL(	/* Session authorisation OK */
		CRYPT_SESSINFO_AUTHRESPONSE, 
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_TLS_SVR | ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( RWx_RWx ), 
		ROUTE( OBJECT_TYPE_SESSION ),
		allowedAuthResponses ),
	MKACL_S(	/* Server name */
		CRYPT_SESSINFO_SERVER_NAME,
		ST_NONE, ST_NONE, ST_SESS_ANY, 
		MKPERM_SESSIONS( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 2, MAX_URL_SIZE ) ),
	MKACL_N(	/* Server port number */
		CRYPT_SESSINFO_SERVER_PORT,
		ST_NONE, ST_NONE, ST_SESS_ANY, 
		MKPERM_SESSIONS( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( MIN_PORT_NUMBER, MAX_DEST_PORT_NUMBER ) ),
	MKACL_ST(	/* Server key fingerprint */
		CRYPT_SESSINFO_SERVER_FINGERPRINT_SHA1,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_SSH | ST_SESS_SCEP | \
						  ST_SESS_SSH_SVR, 
		MKPERM_SESSIONS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoFingerprint ),
	MKACL_S(	/* Client name */
		CRYPT_SESSINFO_CLIENT_NAME,
		ST_NONE, ST_NONE, ST_SESS_ANY_SVR, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 2, MAX_URL_SIZE ) ),
	MKACL_N(	/* Client port number */
		CRYPT_SESSINFO_CLIENT_PORT,
		ST_NONE, ST_NONE, ST_SESS_ANY_SVR, 
		MKPERM_SESSIONS( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( MIN_PORT_NUMBER, MAX_SRC_PORT_NUMBER ) ),
	MKACL_O(	/* Transport mechanism - Disabled */
		CRYPT_SESSINFO_SESSION,
		ST_NONE, ST_NONE, ST_SESS_RTCS | ST_SESS_RTCS_SVR | \
						  ST_SESS_SCVP | ST_SESS_SCVP_SVR | \
						  ST_SESS_OCSP | ST_SESS_OCSP_SVR | \
						  ST_SESS_TSP | ST_SESS_TSP_SVR | \
						  ST_SESS_CMP | ST_SESS_CMP_SVR | \
						  ST_SESS_SCEP | ST_SESS_SCEP_SVR, 
		MKPERM_SESSIONS( xxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectSessionDataClient ),
	MKACL_SA(	/* User-supplied network socket */
		CRYPT_SESSINFO_NETWORKSOCKET,
		ST_NONE, ST_NONE, ST_SESS_ANY, 
		MKPERM_SESSIONS( xxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ) ),

	MKACL_ST(	/* Session protocol version */
		CRYPT_SESSINFO_VERSION,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR | ST_SESS_TLS | \
						  ST_SESS_TLS_SVR | ST_SESS_OCSP | ST_SESS_OCSP_SVR, 
		MKPERM_SESSIONS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoVersion ),
	MKACL_ST(	/* Cert.request object */
		/* The object can be updated in both states for persistent
		   connections */
		CRYPT_SESSINFO_REQUEST,	
		ST_NONE, ST_NONE, ST_SESS_TLS_SVR | ST_SESS_RTCS | ST_SESS_SCVP | \
						  ST_SESS_OCSP | ST_SESS_CMP | ST_SESS_SCEP, 
		MKPERM_SESSIONS( RWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoRequest ),
	MKACL_ST(	/* Cert.response object */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_TLS_SVR | ST_SESS_RTCS | \
						  ST_SESS_OCSP | ST_SESS_TSP | ST_SESS_CMP | \
						  ST_SESS_CMP_SVR | ST_SESS_SCEP | ST_SESS_SCEP_SVR, 
		MKPERM_SESSIONS( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoResponse ),
	MKACL_ST(	/* Issuing CA certificate */
		CRYPT_SESSINFO_CACERTIFICATE,
		ST_NONE, ST_NONE, ST_SESS_CMP | ST_SESS_SCEP, 
		MKPERM_SESSIONS( Rxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoCACertificate ),

	MKACL_ST(	/* CMP/SCEP request type */
		CRYPT_SESSINFO_CMP_REQUESTTYPE,
		ST_NONE, ST_NONE, ST_SESS_CMP | ST_SESS_CMP_SVR | \
						  ST_SESS_SCEP | ST_SESS_SCEP_SVR, 
		MKPERM_CMP( RWx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoRequesttype ),
	MKACL_O(	/* Private-key keyset */
		CRYPT_SESSINFO_CMP_PRIVKEYSET,
		ST_NONE, ST_NONE, ST_SESS_CMP, 
		MKPERM_CMP( xxx_xWx ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectKeysetPrivate ),
	MKACL_N(	/* CMP protocol options */
		CRYPT_SESSINFO_CMP_OPTIONS,
		ST_NONE, ST_NONE, ST_SESS_CMP | ST_SESS_CMP_SVR, 
		MKPERM_TLS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( CRYPT_CMPOPTION_NONE, CRYPT_CMPOPTION_MAX ) ),

	MKACL_ST(	/* SSH current channel */
		/* Write = CRYPT_UNUSED to create channel, read = channel number */
		CRYPT_SESSINFO_SSH_CHANNEL,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SSH_EXT( RWx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoSSHChannel ),
	MKACL_ST(	/* SSH channel type */
		CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SSH_EXT( RWx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoSSHChannelType ),
	MKACL_ST(	/* SSH channel argument 1 */
		CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SSH_EXT( RWx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoSSHChannelArg1 ),
	MKACL_S(	/* SSH channel argument 2 */
		CRYPT_SESSINFO_SSH_CHANNEL_ARG2,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SSH_EXT( RWx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 5, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_B(	/* SSH channel active */
		CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SSH_EXT( RWx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_S(	/* SSH pre-authentication value */
		CRYPT_SESSINFO_SSH_PREAUTH,
		ST_NONE, ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, 
		MKPERM_SSH( Rxx_RWD ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_N(	/* TLS protocol options */
		CRYPT_SESSINFO_TLS_OPTIONS,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_TLS_SVR, 
		MKPERM_TLS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( CRYPT_TLSOPTION_NONE, CRYPT_TLSOPTION_MAX ) ),
	MKACL_ST(	/* TLS additional sub-protocol */
		CRYPT_SESSINFO_TLS_SUBPROTOCOL,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_TLS_SVR, 
		MKPERM_TLS_EAPWS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoSubprotocol ),
	MKACL_S(	/* TLS WebSockets sub-protocol */
		CRYPT_SESSINFO_TLS_WSPROTOCOL,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_TLS_SVR, 
		MKPERM_TLS_WS( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 3, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* TLS EAP challenge */
		CRYPT_SESSINFO_TLS_EAPCHALLENGE,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_TLS_SVR, 
		MKPERM_TLS_EAP( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* TLS EAP key */
		CRYPT_SESSINFO_TLS_EAPKEY,
		ST_NONE, ST_NONE, ST_SESS_TLS | ST_SESS_TLS_SVR, 
		MKPERM_TLS_EAP( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* TLS EAP additional data */
		CRYPT_SESSINFO_TLS_EAPDATA,
		ST_NONE, ST_NONE, ST_SESS_TLS, 
		MKPERM_TLS_EAP( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 1, MAX_ATTRIBUTE_SIZE / 2 ) ),

	MKACL_O(	/* TSP message imprint */
		/* The object can be updated in both states for persistent
		   connections */
		CRYPT_SESSINFO_TSP_MSGIMPRINT,
		ST_NONE, ST_NONE, ST_SESS_TSP, 
		MKPERM_TSP( xWD_xWD ),
		ROUTE( OBJECT_TYPE_SESSION ), &objectCtxHash ),

	MKACL_END(), MKACL_END()
	};
#endif /* USE_SESSIONS */

/****************************************************************************
*																			*
*									User ACLs								*
*																			*
****************************************************************************/

/* User attributes */

static const ATTRIBUTE_ACL userACL[] = {
	MKACL_S_EX(	/* Password */
		CRYPT_USERINFO_PASSWORD,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_PKCS15( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_O(	/* CA cert signing key */
		CRYPT_USERINFO_CAKEY_CERTSIGN,
		ST_NONE, ST_NONE, ST_USER_CA, 
		MKPERM_PKCS15( xxx_xWx ),
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* CA CRL signing key */
		CRYPT_USERINFO_CAKEY_CRLSIGN,
		ST_NONE, ST_NONE, ST_USER_CA, 
		MKPERM_PKCS15( xxx_xWx ),
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* CA RTCS signing key */
		CRYPT_USERINFO_CAKEY_RTCSSIGN,
		ST_NONE, ST_NONE, ST_USER_CA, 
		MKPERM_PKCS15( xxx_xWx ),
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* CA OCSP signing key */
		CRYPT_USERINFO_CAKEY_OCSPSIGN,
		ST_NONE, ST_NONE, ST_USER_CA, 
		MKPERM_PKCS15( xxx_xWx ),
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_END(), MKACL_END()
	};

/****************************************************************************
*																			*
*									Internal ACLs							*
*																			*
****************************************************************************/

static const int allowedObjectStatusValues[] = {
	CRYPT_OK, CRYPT_ERROR_TIMEOUT, CRYPT_ERROR, CRYPT_ERROR };

static const RANGE_SUBRANGE_TYPE allowedCommitNotifySubranges[] = {
	{ MIN_CRYPT_OBJECTSIZE, MAX_INTLENGTH },	/* Data size */
	{ 0, 0 },									/* Empty data */
	{ CRYPT_UNUSED, CRYPT_UNUSED },				/* Invalid data */
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};

static const ATTRIBUTE_ACL subACL_IAttributeSubject[] = {
	MKACL_S(	/* CRMF objects: Readable in any state (unsigned in CMP msgs) */
		CRYPT_IATTRIBUTE_SUBJECT,
		ST_CERT_REQ_CERT | ST_CERT_REQ_REV, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Other objects: Object must be in high state */
		CRYPT_IATTRIBUTE_SUBJECT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CERTREQ | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_END_SUBACL(), MKACL_END_SUBACL()
	};

/* Internal attributes */

static const ATTRIBUTE_ACL internalACL[] = {
	MKACL_N_EX(	/* Object type */
		CRYPT_IATTRIBUTE_TYPE,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM_INT( Rxx_Rxx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( OBJECT_TYPE_NONE + 1, OBJECT_TYPE_LAST - 1 ) ),
	MKACL_N_EX(	/* Object subtype */
		CRYPT_IATTRIBUTE_SUBTYPE,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM_INT( Rxx_Rxx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( OBJECT_TYPE_NONE + 1, OBJECT_TYPE_LAST - 1 ) ),
	MKACL_SL_EX(/* Object status */
		/* Write = status value, read = OBJECT_FLAG_xxx (since an object may
		   be, for example, busy and signalled at the same time) */
		CRYPT_IATTRIBUTE_STATUS, 
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM_INT( RWx_RWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, allowedObjectStatusValues ),
	MKACL(		/* Object internal flag */
		CRYPT_IATTRIBUTE_INTERNAL, ATTRIBUTE_VALUE_BOOLEAN,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM_INT( RWx_RWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( FALSE, FALSE )  ),
	MKACL_N_EX(	/* Object action permissions */
		CRYPT_IATTRIBUTE_ACTIONPERMS,
		ST_CTX_ANY, ST_NONE, ST_NONE, 
		MKPERM_INT( RWx_RWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( ACTION_PERM_NOTAVAIL, ACTION_PERM_LAST ) ),
	MKACL_B_EX(	/* Object locked for exclusive use */
		CRYPT_IATTRIBUTE_LOCKED,
		ST_CTX_PKC | ST_CTX_CONV | ST_CERT_ANY_CERT | ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_INT( xWx_xWx ), ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE ),
	MKACL_N_EX(	/* Object inited (e.g. key loaded, cert signed) */
		CRYPT_IATTRIBUTE_INITIALISED,
		ST_ANY_A, ST_ANY_B, ST_ANY_C, 
		MKPERM_INT( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE_NONE, RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_B_EX(	/* Complete init of system objects */
		CRYPT_IATTRIBUTE_COMPLETEINIT,
		ST_NONE, ST_DEV_HW, ST_USER_SO, 
		MKPERM_INT( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE_NONE ),

	/* Context internal attributes */
	MKACL_N(	/* Ctx: Key size (for non-native ctxts) */
		CRYPT_IATTRIBUTE_KEYSIZE,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC | ST_CTX_GENERIC, ST_NONE, ST_NONE, 
		MKPERM_INT( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( MIN_KEYSIZE, CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Ctx: Key feature info */
		CRYPT_IATTRIBUTE_KEYFEATURES,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 0, 16 ) ),
	MKACL_S(	/* Ctx: Key ID */
		CRYPT_IATTRIBUTE_KEYID,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 20, 20 ) ),
	MKACL_S(	/* Ctx: PGP 2 key ID */
		CRYPT_IATTRIBUTE_KEYID_PGP2,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8, 8 ) ),
	MKACL_S(	/* Ctx: OpenPGP key ID */
		/* This attribute is writeable in the high state since it may be
		   retroactively set for objects for which the value couldn't be
		   calculated at object instantiation time, for example a
		   certificate that has the OpenPGP information stored alongside
		   it */
		CRYPT_IATTRIBUTE_KEYID_OPENPGP,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( RWx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8, 8 ) ),
#if !( defined( USE_ECDSA ) || defined( USE_ECDH ) || \
	   defined( USE_EDDSA ) || defined( USE_25519 ) )
	MKACL_S_EX(	/* Ctx: SubjectPublicKeyInfo */
		/* The attribute length values are only approximate because there's
		   wrapper data involved, and (for the maximum length) several of
		   the DLP PKC values are only a fraction of CRYPT_MAX_PKCSIZE, the
		   rest of the space requirement being allocated to the wrapper */
		CRYPT_IATTRIBUTE_KEY_SPKI,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8 + MIN_PKCSIZE, CRYPT_MAX_PKCSIZE * 4 ) ),
	MKACL_S_EX(	/* Ctx: PGP-format public key */
		CRYPT_IATTRIBUTE_KEY_PGP,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_PGP( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 10 + MIN_PKCSIZE, CRYPT_MAX_PKCSIZE * 4 ) ),
	MKACL_S_EX(	/* Ctx: SSH-format public key */
		CRYPT_IATTRIBUTE_KEY_SSH,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_SSH( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 16 + MIN_PKCSIZE, ( CRYPT_MAX_PKCSIZE * 4 ) + 20 ) ),
	MKACL_S_EX(	/* Ctx: TLS-format public key */
		CRYPT_IATTRIBUTE_KEY_TLS,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_TLS( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 4 + MIN_PKCSIZE, ( CRYPT_MAX_PKCSIZE * 4 ) + 20 ) ),
	MKACL_S_EX(	/* Ctx: TLS-extended-format public key */
		CRYPT_IATTRIBUTE_KEY_TLS_EXT,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_TLS( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 4 + MIN_PKCSIZE, ( CRYPT_MAX_PKCSIZE * 4 ) + 20 ) ),
	MKACL_S(	/* Ctx: SubjectPublicKeyInfo w/o trigger */
		/* We allow a read as well as write to handle dummy contexts tied to 
		   hardware that are used as placeholders for crypto hardware 
		   functionality, these aren't necessarily in the high state as
		   required by CRYPT_IATTRIBUTE_KEY_SPKI when they're accessed 
		   because the hardware may not be ready yet, but we can still
		   fetch the stored public-key data from them */
		CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8 + MIN_PKCSIZE, CRYPT_MAX_PKCSIZE * 4 ) ),
#else
	MKACL_S_EX(	/* Ctx: SubjectPublicKeyInfo */
		/* ECC keys are somewhat different, the lower bound is much smaller 
		   but the key data consists of a point on a curve so it's calcuated
		   as twice the minimum key size */
		CRYPT_IATTRIBUTE_KEY_SPKI,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8 + MIN_PKCSIZE_ECCPOINT_THRESHOLD, CRYPT_MAX_PKCSIZE * 4 ) ),
	MKACL_S_EX(	/* Ctx: PGP-format public key */
		CRYPT_IATTRIBUTE_KEY_PGP,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_PGP( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 10 + MIN_PKCSIZE_ECCPOINT_THRESHOLD, CRYPT_MAX_PKCSIZE * 4 ) ),
	MKACL_S_EX(	/* Ctx: SSH-format public key */
		CRYPT_IATTRIBUTE_KEY_SSH,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_SSH( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 16 + MIN_PKCSIZE_ECC, ( CRYPT_MAX_PKCSIZE * 4 ) + 20 ) ),
	MKACL_S_EX(	/* Ctx: TLS-format public key */
		CRYPT_IATTRIBUTE_KEY_TLS,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_TLS( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 1 + 2, ( CRYPT_MAX_PKCSIZE * 4 ) + 20 ) ),
	MKACL_S_EX(	/* Ctx: TLS-extended-format public key */
		CRYPT_IATTRIBUTE_KEY_TLS_EXT,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_TLS( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 4 + MIN_PKCSIZE, ( CRYPT_MAX_PKCSIZE * 4 ) + 20 ) ),
	MKACL_S(	/* Ctx: SubjectPublicKeyInfo w/o trigger */
		CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8 + MIN_PKCSIZE_ECCPOINT_THRESHOLD, CRYPT_MAX_PKCSIZE * 4 ) ),
#endif /* !( USE_ECDSA || USE_ECDH || USE_EDDSA || USE_25519 ) */
	MKACL_S(	/* Ctx: PGP public key w/o trigger */
		CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT_PGP( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 10 + MIN_PKCSIZE, CRYPT_MAX_PKCSIZE * 3 ) ),
#if !defined( USE_DH )
	MKACL_N_EX(	/* DLP domain parameters */
		CRYPT_IATTRIBUTE_KEY_DLPPARAM,
		ST_CTX_PKC, ST_NONE, ST_NONE,
		MKPERM_INT( xxx_xxx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( MIN_PKCSIZE, CRYPT_MAX_PKCSIZE ) ),
#else
	MKACL_N_EX(	/* DLP domain parameters */
		CRYPT_IATTRIBUTE_KEY_DLPPARAM,
		ST_CTX_PKC, ST_NONE, ST_NONE,
		MKPERM_INT( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( MIN_PKCSIZE, CRYPT_MAX_PKCSIZE ) ),
#endif /* !USE_DH */
#if !( defined( USE_ECDH ) || defined( USE_ECDSA ) )
	MKACL_N_EX(	/* ECC domain parameters */
		CRYPT_IATTRIBUTE_KEY_ECCPARAM,
		ST_CTX_PKC, ST_NONE, ST_NONE,
		MKPERM_INT( xxx_xxx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( CRYPT_ECCCURVE_NONE + 1, CRYPT_ECCCURVE_LAST - 1 ) ),
#else
	MKACL_N_EX(	/* ECC domain parameters */
		CRYPT_IATTRIBUTE_KEY_ECCPARAM,
		ST_CTX_PKC, ST_NONE, ST_NONE,
		MKPERM_INT( Rxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( CRYPT_ECCCURVE_NONE + 1, CRYPT_ECCCURVE_LAST - 1 ) ),
#endif /* !( USE_ECDH || USE_ECDSA ) */
	MKACL_T(	/* Ctx: PGP key validity */
		/* This attribute is writeable in the high state since it may be
		   retroactively set for objects for which the value couldn't be
		   calculated at object instantiation time, for example a
		   certificate that has the OpenPGP information stored alongside
		   it */
		CRYPT_IATTRIBUTE_PGPVALIDITY,
		ST_CTX_PKC, ST_NONE, ST_NONE, 
		MKPERM_INT( RWx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ) ),
	MKACL_SA(	/* Ctx: Handle for object in device */
		CRYPT_IATTRIBUTE_DEVICEOBJECT,
		ST_CTX_ANY, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ) ),
	MKACL_S(	/* Ctx: Storage ID for data in device */
		CRYPT_IATTRIBUTE_DEVICESTORAGEID,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC | ST_CTX_GENERIC, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_RWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 1, KEYID_SIZE ) ),
	MKACL_S(	/* Ctx: Existing label for object in device */
		/* This is like CRYPT_CTXINFO_LABEL except that what we're setting 
		   is the label for an existing persistent object in a device, so
		   the context code doesn't reject it if it finds a match for this
		   label in the device */
		CRYPT_IATTRIBUTE_EXISTINGLABEL,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM_INT( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_N(	/* Ctx: Optional params for CRYPT_CTXINFO_KEYING_ALGO */
		CRYPT_IATTRIBUTE_KEYING_ALGO_PARAM,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM_INT( xxx_xWx ), 
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 20, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* Ctx: Opt.KDF params for generic-secret */
		CRYPT_IATTRIBUTE_KDFPARAMS,
		ST_CTX_GENERIC, ST_NONE, ST_NONE, 
		MKPERM_INT( RWx_xWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Ctx: Encryption params for generic-secret */
		CRYPT_IATTRIBUTE_ENCPARAMS,
		ST_CTX_GENERIC, ST_NONE, ST_NONE, 
		MKPERM_INT( RWx_xWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Ctx: MAC params for generic-secret */
		CRYPT_IATTRIBUTE_MACPARAMS,
		ST_CTX_GENERIC, ST_NONE, ST_NONE, 
		MKPERM_INT( RWx_xWx ),
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* AAD for AEAD modes */
		CRYPT_IATTRIBUTE_AAD,
		ST_CTX_CONV, ST_NONE, ST_NONE, 
		MKPERM_INT( xWx_xxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* ICV for AEAD modes */
		CRYPT_IATTRIBUTE_ICV,
		ST_CTX_CONV, ST_NONE, ST_NONE, 
		MKPERM_INT( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 12, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* Rekey for AEAD modes */
		CRYPT_IATTRIBUTE_REKEY,
		ST_CTX_MAC, ST_NONE, ST_NONE, 
		MKPERM_INT( xWx_xxx ),
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 16, CRYPT_MAX_KEYSIZE ) ),

	/* Certificate internal attributes */
	MKACL_ST(	/* Cert: SubjectName */
		/* Although in theory this attribute should only be present for
		   signed cert objects, it also exists in CRMF objects that are
		   being used as CMP revocation requests and that aren't signed and
		   are therefore never in the high state.  Because of this we have to
		   allow reads in the low state for this one object type */
		CRYPT_IATTRIBUTE_SUBJECT,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_REQ_CERT | ST_CERT_REQ_REV | \
					   ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), subACL_IAttributeSubject ),
	MKACL_S(	/* Cert: IssuerName */
		CRYPT_IATTRIBUTE_ISSUER,
		ST_CERT_CERT | ST_CERT_REQ_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Cert: IssuerAndSerial */
		CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_REQ_REV | ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Cert: Best approximation to cert.owner name */
		CRYPT_IATTRIBUTE_HOLDERNAME,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_REQ_CERT | ST_CERT_REQ_REV | \
					   ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Cert: Best approximation to cert.owner URI */
		CRYPT_IATTRIBUTE_HOLDERURI,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_REQ_CERT | ST_CERT_REQ_REV | \
					   ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* Cert: Encoded SubjectPublicKeyInfo */
		/* Although we never need to extract the SPKI from a CRMF request, we
		   have to be able to read it so we can do a presence check since we
		   can't issue a cert without having a public key present (although
		   this would be detcted later on, it allows us to report the error
		   at an earlier stage by explicitly checking).  Since the same
		   checks are also applied to PKCS #10 cert requests, we also have to
		   make it readable for those */
		CRYPT_IATTRIBUTE_SPKI,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CERTREQ | ST_CERT_REQ_CERT, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, CRYPT_MAX_PKCSIZE * 3 ) ),
	MKACL_N(	/* Cert: Certificate hash algorithm */
		/* Although this attribute is technically valid for most certificate 
		   types, it's only used with standard certificates, where it's used 
		   as an implicit indicator of the preferred hash algorithm to use 
		   when signing data */
		CRYPT_IATTRIBUTE_CERTHASHALGO,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( CRYPT_ALGO_FIRST_HASH, CRYPT_ALGO_LAST_HASH ) ),
	MKACL_O_EX(	/* Cert: Certs added to cert chain */
		/* This attribute is marked as a trigger attribute since the cert
		   chain object it affects doesn't contain a true chain of certs but
		   only a collection of non-duplicate certs that are never
		   explicitly signed.  To allow it to function as a normal cert
		   chain, we move it into the high state as soon as at least on cert
		   is added.  In addition, this is a retriggerable attribute in that
		   further data can be added after the initial trigger action */
		CRYPT_IATTRIBUTE_CERTCOLLECTION,
		ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( xWx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificate ),
	MKACL_S(	/* Cert: Individual entry from CRL */
		CRYPT_IATTRIBUTE_CRLENTRY,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTREV( Rxx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 8, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* Cert: RTCS/OCSP responder name */
		CRYPT_IATTRIBUTE_RESPONDERURL,
		ST_CERT_RTCS_REQ | ST_CERT_OCSP_REQ, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTREV_VAL( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_O(	/* Cert: RTCS req.info added to RTCS resp.*/
		CRYPT_IATTRIBUTE_RTCSREQUEST,
		ST_CERT_RTCS_RESP, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTVAL( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertRTCSRequest ),
	MKACL_O(	/* Cert: OCSP req.info added to OCSP resp.*/
		CRYPT_IATTRIBUTE_OCSPREQUEST,
		ST_CERT_OCSP_RESP, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTREV( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertOCSPRequest ),
	MKACL_O_EX(	/* Cert: CRMF rev.request added to CRL */
		/* This is marked as a trigger attribute since it's used to create a
		   CRL template from a CRMF request (i.e. to turn a CRMF revocation
		   request into something that the rest of cryptlib can work with),
		   so adding it has to create a pseudosigned CRL from which we can
		   read things like the encoded CRL entry and the
		   issuerAndSerialNumber */
		CRYPT_IATTRIBUTE_REVREQUEST,
		ST_CERT_CRL, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTREV( xxx_xWx ), ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertRevRequest ),
	MKACL_O(	/* Cert: Additional user info added to cert.request */
		CRYPT_IATTRIBUTE_PKIUSERINFO,
		ST_CERT_CERTREQ | ST_CERT_REQ_CERT, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTREQ( xWx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertPKIUser ),
	MKACL_O(	/* Cert: Template of disallowed attrs.in cert */
		CRYPT_IATTRIBUTE_BLOCKEDATTRS,
		ST_CERT_CERT, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( xxx_xWx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificateTemplate ),
	MKACL_B(	/* Cert request came from RA */
		CRYPT_IATTRIBUTE_REQFROMRA,
		ST_CERT_REQ_CERT, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTREQ( RWx_xxx ), 
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* Cert: Authorising cert ID for a cert/rev.request */
		CRYPT_IATTRIBUTE_AUTHCERTID,
		ST_CERT_REQ_CERT | ST_CERT_REQ_REV, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTREQ( RWx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 20, 20 ) ),
	MKACL_S(	/* Cert: ESSCertID */
		CRYPT_IATTRIBUTE_ESSCERTID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_Rxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 32, 8192 ) ),
	MKACL_O(	/* Cert: Copy of cert object */
		/* This is used to create a sanitised copy of a (possibly-internal)
		   cert.for external use */
		CRYPT_IATTRIBUTE_CERTCOPY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificate ),
	MKACL_O(	/* Cert: Copy of cert object as data-only cert */
		CRYPT_IATTRIBUTE_CERTCOPY_DATAONLY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ST_NONE, 
		MKPERM_INT_CERTIFICATES( Rxx_xxx ),
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificate ),

	/* Device internal attributes */
	MKACL_S(	/* Dev: Polled entropy data */
		CRYPT_IATTRIBUTE_ENTROPY,
		ST_NONE, ST_DEV_SYSTEM, ST_NONE, 
		MKPERM_INT( xWx_xWx ), 
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 1, MAX_BUFFER_SIZE - 1 ) ),
	MKACL_N(	/* Dev: Quality of entropy */
		CRYPT_IATTRIBUTE_ENTROPY_QUALITY,
		ST_NONE, ST_DEV_SYSTEM, ST_NONE, 
		MKPERM_INT( xWx_xWx ), 
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 1, 100 ) ),
	MKACL_B(	/* Slow/fast entropy poll */
		CRYPT_IATTRIBUTE_RANDOM_POLL,
		ST_NONE, ST_DEV_SYSTEM, ST_NONE, 
		MKPERM_INT( xWx_xWx ), 
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ) ),
	MKACL_N(	/* Dev: Low picket for random data attrs.*/
		/* This and the high picket are used to protect the critical
		   randomness attributes from accidental access due to fencepost
		   errors or similar problems. They're marked as non-accessible numeric
		   attributes (randomness is a string attribute) to ensure they'll both
		   be trapped as an error in the debug kernel and rejected in normal
		   use */
		CRYPT_IATTRIBUTE_RANDOM_LOPICKET,
		ST_NONE, ST_DEV_ANY, ST_NONE, 
		MKPERM_INT( xxx_xxx ),
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 0, 0 ) ),
	MKACL_S(	/* Dev: Random data */
		CRYPT_IATTRIBUTE_RANDOM,
		ST_NONE, ST_DEV_ANY, ST_NONE, 
		MKPERM_INT( Rxx_Rxx ),  
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( MIN_KEYSIZE, CRYPT_MAX_PKCSIZE ) ),
	MKACL_S(	/* Dev: Nonzero random data */
		CRYPT_IATTRIBUTE_RANDOM_NZ,
		ST_NONE, ST_DEV_ANY, ST_NONE, 
		MKPERM_INT( Rxx_Rxx ),
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( MIN_KEYSIZE, CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Dev: High picket for random data attrs.*/
		CRYPT_IATTRIBUTE_RANDOM_HIPICKET,
		ST_NONE, ST_DEV_ANY, ST_NONE, 
		MKPERM_INT( xxx_xxx ),
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 0, 0 ) ),
	MKACL_S(	/* Dev: Basic nonce */
		CRYPT_IATTRIBUTE_RANDOM_NONCE,
		ST_NONE, ST_DEV_SYSTEM, ST_NONE, 
		MKPERM_INT( Rxx_Rxx ),
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 1, MAX_INTLENGTH_SHORT ) ),
	MKACL_T(	/* Dev: Reliable (hardware-based) time value */
		CRYPT_IATTRIBUTE_TIME,
		ST_NONE, ST_DEV_ANY, ST_NONE, 
		MKPERM_INT( Rxx_xxx ),
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ) ),
	MKACL_O(	/* Dev: Associated keyset for priv.key data */
		/* We use the config-data keyset type since this is used to provide 
		   backing storage for a hardware device so the requirements are
		   more specific than just generic private-key storage */
		CRYPT_IATTRIBUTE_HWSTORAGE,
		ST_NONE, ST_DEV_HW, ST_NONE, 
		MKPERM_INT_HARDWARE( Rxx_xxx ),
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), &objectKeysetConfigdata ),
	MKACL_SS(	/* Dev: Commit notification for device data */
		CRYPT_IATTRIBUTE_COMMITNOTIFY,
		ST_NONE, ST_DEV_HW | ST_DEV_TPM, ST_NONE, 
		MKPERM_INT_HARDWARE( xWx_xWx ),
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), 
		allowedCommitNotifySubranges ),
	MKACL_B(	/* Dev: Reset notification for device data */
		CRYPT_IATTRIBUTE_RESETNOTIFY,
		ST_NONE, ST_DEV_HW, ST_NONE, 
		MKPERM_INT_HARDWARE( xWx_xWx ),
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ) ),

	/* Envelope internal attributes */
	MKACL_B(	/* Env: Whether to include signing cert(s) */
		CRYPT_IATTRIBUTE_INCLUDESIGCERT,
		ST_NONE, ST_ENV_ENV, ST_NONE, 
		MKPERM_INT_ENVELOPE( xxx_xWx ),
		ROUTE_FIXED( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_B(	/* Env: Signed data contains only CMS attrs.*/
		CRYPT_IATTRIBUTE_ATTRONLY,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ST_NONE, 
		MKPERM_INT_ENVELOPE( xWx_xWx ),
		ROUTE_FIXED( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_N(	/* Env: Envelope format type */
		CRYPT_IATTRIBUTE_ENVFORMAT,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_INT_ENVELOPE( Rxx_Rxx ),
		ROUTE_FIXED( OBJECT_TYPE_ENVELOPE ), RANGE( CRYPT_FORMAT_NONE, CRYPT_FORMAT_LAST_EXTERNAL ) ),
	MKACL_N(	/* Env: Envelope usage as content-type */
		CRYPT_IATTRIBUTE_ENVUSAGE,
		ST_NONE, ST_ENV_DEENV, ST_NONE, 
		MKPERM_INT_ENVELOPE( Rxx_Rxx ),
		ROUTE_FIXED( OBJECT_TYPE_ENVELOPE ), RANGE( CRYPT_CONTENT_NONE, CRYPT_CONTENT_LAST ) ),

	/* Keyset internal attributes */
	MKACL_S(	/* Keyset: Config information */
		CRYPT_IATTRIBUTE_CONFIGDATA,
		ST_NONE, ST_KEYSET_FILE, ST_NONE, 
		MKPERM_INT( RWx_RWx ),
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 8, 16384 ) ),
	MKACL_S(	/* Keyset: Index of users */
		CRYPT_IATTRIBUTE_USERINDEX,
		ST_NONE, ST_KEYSET_FILE, ST_NONE, 
		MKPERM_INT( RWx_RWx ),
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 16, 16384 ) ),
	MKACL_S(	/* Keyset: User ID */
		CRYPT_IATTRIBUTE_USERID,
		ST_NONE, ST_KEYSET_FILE, ST_NONE, 
		MKPERM_INT( RWx_RWx ),
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( KEYID_SIZE, KEYID_SIZE ) ),
	MKACL_S(	/* Keyset: User information */
		CRYPT_IATTRIBUTE_USERINFO,
		ST_NONE, ST_KEYSET_FILE, ST_NONE, 
		MKPERM_INT( RWx_RWx ),
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 64, 16384 ) ),
	MKACL_S(	/* Keyset: First trusted cert */
		CRYPT_IATTRIBUTE_TRUSTEDCERT,
		ST_NONE, ST_KEYSET_FILE, ST_NONE, 
		MKPERM_INT( Rxx_Rxx ),
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 64, 2048 ) ),
	MKACL_S(	/* Keyset: Successive trusted certs */
		CRYPT_IATTRIBUTE_TRUSTEDCERT_NEXT,
		ST_NONE, ST_KEYSET_FILE, ST_NONE, 
		MKPERM_INT( Rxx_Rxx ),
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 64, 2048 ) ),
	MKACL_O(	/* Keyset: Associated device for private key data */
		CRYPT_IATTRIBUTE_HWDEVICE,
		ST_NONE, ST_KEYSET_FILE, ST_NONE, 
		MKPERM_INT_HARDWARE( xWx_xWx ),
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), &objectHardwareDevice ),

	/* Session internal attributes */
	MKACL_S(	/* Session: Encoded TSA timestamp */
		CRYPT_IATTRIBUTE_ENC_TIMESTAMP,
		ST_NONE, ST_NONE, ST_SESS_TSP, 
		MKPERM_INT_TSP( Rxx_xxx ),
		ROUTE_FIXED( OBJECT_TYPE_SESSION ), RANGE( 128, 8192 ) ),

	/* User internal attributes */
	MKACL_O(	/* User: Keyset to send trusted certs to */
		CRYPT_IATTRUBUTE_CERTKEYSET,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_INT( xWx_xxx ),
		ROUTE( OBJECT_TYPE_USER ), &objectKeysetConfigdata ),
	MKACL_O(	/* User: Cert.trust list */
		CRYPT_IATTRIBUTE_CTL,
		ST_NONE, ST_NONE, ST_USER_ANY, 
		MKPERM_INT_CERTIFICATES( RWx_xxx ),
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_END(), MKACL_END()
	};

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

/* Check that a special range entry is consistent */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN specialRangeConsistent( const ATTRIBUTE_ACL *attributeACL )
	{
	const void *rangeVal = getSpecialRangeInfo( attributeACL );
	const int rangeValSize = getSpecialRangeInfoSize( attributeACL );

	assert( isReadPtr( attributeACL, sizeof( ATTRIBUTE_ACL ) ) );

	switch( getSpecialRangeType( attributeACL ) )
		{
		case RANGEVAL_ANY:
			if( rangeVal != NULL || rangeValSize != 0 )
				return( FALSE );
			break;

		case RANGEVAL_ALLOWEDVALUES:
			{
			const int *rangeValInt = rangeVal;
			LOOP_INDEX i;

			if( rangeValInt == NULL )
				return( FALSE );
			if( rangeValSize < 1 || rangeValSize > 10 )
				return( FALSE );
			LOOP_SMALL( i = 0, i < rangeValSize, i++ )
				{
				ENSURES_B( LOOP_INVARIANT_SMALL( i, 0, rangeValSize - 1 ) );

				if( *rangeValInt++ == CRYPT_ERROR )
					break;
				}
			ENSURES_B( LOOP_BOUND_OK );
			if( i >= rangeValSize )
				return( FALSE );
			break;
			}

		case RANGEVAL_SUBRANGES:
			{
			const RANGE_SUBRANGE_TYPE *rangeValSubrange = rangeVal;
			LOOP_INDEX i;

			if( rangeValSubrange == NULL )
				return( FALSE );
			if( rangeValSize < 1 || rangeValSize > 10 )
				return( FALSE );
			LOOP_SMALL( i = 0, i < rangeValSize, i++ )
				{
				ENSURES_B( LOOP_INVARIANT_SMALL( i, 0, rangeValSize - 1 ) );

				if( rangeValSubrange->highRange == CRYPT_ERROR )
					break;
				if( rangeValSubrange->lowRange < 0 )
					{
					if( !( rangeValSubrange->lowRange < 0 && \
						   rangeValSubrange->highRange < 0 ) || \
						rangeValSubrange->lowRange < rangeValSubrange->highRange )
						{
						return( FALSE );
						}
					}
				else
					{
					if( !( rangeValSubrange->lowRange >= 0 && \
						   rangeValSubrange->highRange >= 0 ) || \
						rangeValSubrange->lowRange > rangeValSubrange->highRange )
						{
						return( FALSE );
						}
					}
				rangeValSubrange++;
				}
			ENSURES_B( LOOP_BOUND_OK );
			if( i >= rangeValSize )
				return( FALSE );
			break;
			}

		default:
			return( FALSE );
		}

	return( TRUE );
	}

/* Check that an ACL is consistent */

#define ACCESS_RWx_xxx		0x6060	/* Special-case used for consistency check */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN aclConsistent( const ATTRIBUTE_ACL *attributeACL,
							  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
							  const OBJECT_SUBTYPE subTypeA, 
							  const OBJECT_SUBTYPE subTypeB,
							  const OBJECT_SUBTYPE subTypeC )
	{
	assert( isReadPtr( attributeACL, sizeof( ATTRIBUTE_ACL ) ) );
	
#ifndef NDEBUG
	REQUIRES_B( attribute > CRYPT_ATTRIBUTE_NONE && \
				attribute < CRYPT_IATTRIBUTE_LAST );
#endif /* !NDEBUG */
	REQUIRES_B( !( subTypeA & ( SUBTYPE_CLASS_B | SUBTYPE_CLASS_C ) ) );
	REQUIRES_B( !( subTypeB & ( SUBTYPE_CLASS_A | SUBTYPE_CLASS_C ) ) );
	REQUIRES_B( !( subTypeC & ( SUBTYPE_CLASS_A | SUBTYPE_CLASS_B ) ) );

	/* General consistency checks.  We can only check the attribute type in
	   the debug build because it's not present in the release to save
	   space */
#ifndef NDEBUG
	if( attributeACL->attribute != attribute )
		{
		DEBUG_DIAG(( "Inconsistent attribute value" ));
		return( FALSE );
		}
#endif /* !NDEBUG */
	if( attributeACL->flags >= ATTRIBUTE_FLAG_LAST )
		{
		DEBUG_DIAG(( "Inconsistent attribute flags" ));
		return( FALSE );
		}
	if( ( attributeACL->subTypeA & ( SUBTYPE_CLASS_B | SUBTYPE_CLASS_C ) ) || \
		( attributeACL->subTypeB & ( SUBTYPE_CLASS_A | SUBTYPE_CLASS_C ) ) || \
		( attributeACL->subTypeC & ( SUBTYPE_CLASS_A | SUBTYPE_CLASS_B ) ) )
		{
		DEBUG_DIAG(( "Inconsistent attribute subtype" ));
		return( FALSE );
		}
	if( ( attributeACL->subTypeA & ~( SUBTYPE_CLASS_A | subTypeA ) ) != 0 || \
		( attributeACL->subTypeB & ~( SUBTYPE_CLASS_B | subTypeB ) ) != 0 || \
		( attributeACL->subTypeC & ~( SUBTYPE_CLASS_C | subTypeC ) ) != 0 )
		{
		DEBUG_DIAG(( "Inconsistent attribute subtype" ));
		return( FALSE );
		}

	/* ACL-specific checks */
	switch( attributeACL->valueType )
		{
		case ATTRIBUTE_VALUE_BOOLEAN:
			/* Some boolean values can only be set to TRUE or FALSE, so it's
			   possible to have a range of { FALSE, FALSE } or
			   { TRUE, TRUE } */
			if( ( attributeACL->lowRange != FALSE && \
				  attributeACL->lowRange != TRUE ) || \
				( attributeACL->highRange != FALSE && \
				  attributeACL->highRange != TRUE ) || \
				attributeACL->extendedInfo != NULL )
				{
				DEBUG_DIAG(( "Inconsistent boolean attribute range" ));
				return( FALSE );
				}
			break;

		case ATTRIBUTE_VALUE_NUMERIC:
			if( isSpecialRange( attributeACL ) )
				{
				if( !specialRangeConsistent( attributeACL ) )
					{
					DEBUG_DIAG(( "Inconsistent numeric attribute range" ));
					return( FALSE );
					}
				}
			else
				{
				if( attributeACL->lowRange < 0 )
					{
					/* Negative ranges, e.g. -10 ... -1 */
					if( !( attributeACL->lowRange < 0 && \
						   attributeACL->highRange < 0 ) || \
						attributeACL->lowRange < attributeACL->highRange )
						{
						DEBUG_DIAG(( "Inconsistent numeric attribute range" ));
						return( FALSE );
						}
					}
				else
					{
					/* Positive ranges */
					if( !( attributeACL->lowRange >= 0 && \
						   attributeACL->highRange >= 0 ) || \
						attributeACL->lowRange > attributeACL->highRange )
						{
						DEBUG_DIAG(( "Inconsistent numeric attribute range" ));
						return( FALSE );
						}
					}
				if( attributeACL->extendedInfo != NULL )
					{
					DEBUG_DIAG(( "Inconsistent numeric attribute extended info" ));
					return( FALSE );
					}
				}
			break;

		case ATTRIBUTE_VALUE_STRING:
			if( isSpecialRange( attributeACL ) )
				{
				if( getSpecialRangeType( attributeACL ) != RANGEVAL_ALLOWEDVALUES || \
					getSpecialRangeInfo( attributeACL ) == NULL )
					{
					DEBUG_DIAG(( "Inconsistent special string attribute range" ));
					return( FALSE );
					}
				if( !specialRangeConsistent( attributeACL ) )
					{
					DEBUG_DIAG(( "Inconsistent special string attribute range" ));
					return( FALSE );
					}
				}
			else
				{
				/* The special-case check for MAX_BUFFER_SIZE is needed for
				   polled entropy data, which can be of arbitrary length */
				if( attributeACL->extendedInfo != NULL )
					{
					DEBUG_DIAG(( "Inconsistent string attribute range" ));
					return( FALSE );
					}
				if( attributeACL->lowRange < 0 || \
					( attributeACL->highRange > 16384 && \
					  attributeACL->highRange != MAX_BUFFER_SIZE - 1 ) || \
					attributeACL->lowRange > attributeACL->highRange )
					{
					DEBUG_DIAG(( "Inconsistent string attribute range" ));
					return( FALSE );
					}
				}
			break;

		case ATTRIBUTE_VALUE_WCSTRING:
			/* These are text strings and so can never be zero-length.  In 
			   theory they can't be length 1 either, but the WCS-ness is
			   optional so they could also be single-byte character 
			   strings */
			if( attributeACL->extendedInfo != NULL )
				{
				DEBUG_DIAG(( "Inconsistent widechar string attribute range" ));
				return( FALSE );
				}
			if( attributeACL->lowRange <= 0 || \
				attributeACL->highRange > 16384 || \
				attributeACL->lowRange > attributeACL->highRange )
				{
				DEBUG_DIAG(( "Inconsistent widechar string attribute range" ));
				return( FALSE );
				}
			break;

		case ATTRIBUTE_VALUE_OBJECT:
			if( attributeACL->lowRange != 0 || \
				attributeACL->highRange != 0 || \
				attributeACL->extendedInfo == NULL )
				{
				DEBUG_DIAG(( "Inconsistent object attribute range" ));
				return( FALSE );
				}
			break;

		case ATTRIBUTE_VALUE_TIME:
			if( attributeACL->lowRange != 0 || \
				attributeACL->highRange != 0 || \
				attributeACL->extendedInfo != NULL )
				{
				DEBUG_DIAG(( "Inconsistent time attribute range" ));
				return( FALSE );
				}
			break;

		case ATTRIBUTE_VALUE_SPECIAL:
			{
			LOOP_INDEX_PTR const ATTRIBUTE_ACL *attributeACLPtr;
			int access = attributeACL->access;
			int subTypes = attributeACL->subTypeA | \
						   attributeACL->subTypeB | \
						   attributeACL->subTypeC;

			if( !isSpecialRange( attributeACL ) || \
				getSpecialRangeType( attributeACL ) != RANGEVAL_SUBTYPED || \
				getSpecialRangeInfo( attributeACL ) == NULL )
				{
				DEBUG_DIAG(( "Inconsistent special attribute information" ));
				return( FALSE );
				}

			/* Recursively check the sub-ACLs */
			LOOP_MED( attributeACLPtr = getSpecialRangeInfo( attributeACL ), 
					  attributeACLPtr->valueType != ATTRIBUTE_VALUE_NONE,
					  attributeACLPtr++ )
				{
				ENSURES( LOOP_INVARIANT_MED_GENERIC() );

				if( !aclConsistent( attributeACLPtr, 
#ifndef NDEBUG
									attributeACL->attribute,
#else
									CRYPT_ATTRIBUTE_NONE,
#endif /* !NDEBUG */
									attributeACL->subTypeA,
									attributeACL->subTypeB,
									attributeACL->subTypeC ) )
					{
					DEBUG_DIAG(( "Inconsistent sub-attribute information" ));
					return( FALSE );
					}
				}
			ENSURES_B( LOOP_BOUND_OK );

			/* Make sure that all subtypes and acess settings in the main
			   attribute are handled in the sub-attributes */
			LOOP_MED( attributeACLPtr = getSpecialRangeInfo( attributeACL ), 
					  attributeACLPtr->valueType != ATTRIBUTE_VALUE_NONE,
					  attributeACLPtr++ )
				{
				ENSURES( LOOP_INVARIANT_MED_GENERIC() );

				subTypes &= ~( attributeACLPtr->subTypeA | \
							   attributeACLPtr->subTypeB | \
							   attributeACLPtr->subTypeC );
				access &= ~attributeACLPtr->access;
				}
			ENSURES_B( LOOP_BOUND_OK );
			if( subTypes != 0 || access != 0 )
				{
				DEBUG_DIAG(( "Inconsistent special attribute permissions" ));
				return( FALSE );
				}
			break;
			}

		default:
			DEBUG_DIAG(( "Unknown attribute type %d", 
						 attributeACL->valueType ));
			return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL \
int initAttributeACL( void )
	{
	LOOP_INDEX i;

	/* Perform a consistency check on values used to handle ACL subranges.
	   These are somewhat tricky to check automatically since they represent
	   variable start and end ranges, we hardcode in absolute values to
	   ensure that adding new attributes in the header file will trigger an
	   exception here to provide a reminder to change the range-end
	   definitions as well */
	static_assert( CRYPT_CERTINFO_FIRST_CERTINFO == 2001, "Attribute value" );
	static_assert( CRYPT_CERTINFO_LAST_CERTINFO == 2033, "Attribute value" );
	static_assert( CRYPT_CERTINFO_FIRST_PSEUDOINFO == 2001, "Attribute value" );
	static_assert( CRYPT_CERTINFO_LAST_PSEUDOINFO == 2011, "Attribute value" );
	static_assert( CRYPT_CERTINFO_FIRST_NAME == 2100, "Attribute value" );
	static_assert( CRYPT_CERTINFO_LAST_NAME == 2115, "Attribute value" );
	static_assert( CRYPT_CERTINFO_FIRST_DN == 2100, "Attribute value" );
	static_assert( CRYPT_CERTINFO_LAST_DN == 2105, "Attribute value" );
	static_assert( CRYPT_CERTINFO_FIRST_GENERALNAME == 2106, "Attribute value" );
	static_assert( CRYPT_CERTINFO_LAST_GENERALNAME == 2115, "Attribute value" );
	static_assert( CRYPT_CERTINFO_FIRST_EXTENSION == 2200, "Attribute value" );
	static_assert( CRYPT_CERTINFO_FIRST_CMS == 2500, "Attribute value" );
	static_assert( CRYPT_SESSINFO_FIRST_SPECIFIC == 6017, "Attribute value" );
	static_assert( CRYPT_SESSINFO_LAST_SPECIFIC == 6035, "Attribute value" );
	static_assert( CRYPT_CERTFORMAT_LAST == 13, "Attribute value" );

	/* Perform a consistency check on the attribute ACLs.  The ACLs are
	   complex enough that we assert on each one to quickly catch problems
	   when one is changed.  First we check the universal property, generic,
	   and option ACLs */
	LOOP_LARGE( i = 0, i < CRYPT_PROPERTY_LAST - CRYPT_PROPERTY_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( propertyACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( propertyACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &propertyACL[ i ], i + CRYPT_PROPERTY_FIRST + 1,
							ST_ANY_A, ST_ANY_B, ST_ANY_C ) )
			{
			DEBUG_DIAG(( "Property ACL #%d inconsistent", i ));
			retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( propertyACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( propertyACL[ CRYPT_PROPERTY_LAST - \
						  CRYPT_PROPERTY_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
	LOOP_LARGE( i = 0, i < CRYPT_GENERIC_LAST - CRYPT_GENERIC_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( genericACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( genericACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &genericACL[ i ], i + CRYPT_GENERIC_FIRST + 1,
							ST_ANY_A, ST_ANY_B, ST_ANY_C ) )
			{
			DEBUG_DIAG(( "Generic ACL #%d inconsistent", i ));
			retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( genericACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( genericACL[ CRYPT_GENERIC_LAST - \
						 CRYPT_GENERIC_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
	LOOP_LARGE( i = 0, i < CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( optionACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( optionACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &optionACL[ i ], i + CRYPT_OPTION_FIRST + 1,
							ST_CTX_CONV | ST_CTX_PKC,
							ST_ENV_ENV | ST_ENV_ENV_PGP | ST_KEYSET_LDAP,
							ST_SESS_ANY | ST_USER_ANY ) )
			{
			DEBUG_DIAG(( "Option ACL #%d inconsistent", i ));
			retIntError();
			}
#ifndef NDEBUG
		if( optionACL[ i ].attribute >= CRYPT_OPTION_KEYING_ALGO && \
			optionACL[ i ].attribute <= CRYPT_OPTION_KEYING_ITERATIONS )
			{
			if( optionACL[ i ].subTypeA != ST_CTX_CONV || \
				optionACL[ i ].subTypeB != ST_NONE || \
				( optionACL[ i ].subTypeC & ~( SUBTYPE_CLASS_C | \
											   ST_USER_ANY ) ) != 0 )
				{
				DEBUG_DIAG(( "Keying property ACL #%d inconsistent", i ));
				retIntError();
				}
			}
		else
		if( optionACL[ i ].attribute >= CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS && \
			optionACL[ i ].attribute <= CRYPT_OPTION_KEYS_LDAP_EMAILNAME )
			{
			if( optionACL[ i ].subTypeA != ST_NONE || \
				optionACL[ i ].subTypeB != ST_KEYSET_LDAP || \
				( optionACL[ i ].subTypeC & ~( SUBTYPE_CLASS_C | \
											   ST_USER_ANY ) ) != 0 )
				{
				DEBUG_DIAG(( "LDAP property ACL #%d inconsistent", i ));
				retIntError();
				}
			}
		else
		if( optionACL[ i ].attribute == CRYPT_OPTION_MISC_SIDECHANNELPROTECTION )
			{
			if( optionACL[ i ].subTypeA != ST_CTX_PKC || \
				optionACL[ i ].subTypeB != ST_NONE || \
				optionACL[ i ].subTypeC != ST_USER_SO )
				{
				DEBUG_DIAG(( "Sidechannel property ACL #%d inconsistent", i ));
				retIntError();
				}
			}
		else
		if( ( optionACL[ i ].attribute >= CRYPT_OPTION_ENCR_ALGO && \
			  optionACL[ i ].attribute <= CRYPT_OPTION_ENCR_MAC ) || \
			( optionACL[ i ].attribute == CRYPT_OPTION_ENCR_HASHPARAM ) )
			{
			if( optionACL[ i ].subTypeA != ST_NONE || \
				optionACL[ i ].subTypeB & ~( SUBTYPE_CLASS_B | ST_ENV_ENV | \
											 ST_ENV_ENV_PGP ) || 
				optionACL[ i ].subTypeC & ~( SUBTYPE_CLASS_C | ST_USER_ANY ) )
				{
				DEBUG_DIAG(( "Encryption property ACL #%d inconsistent", i ));
				retIntError();
				}
			}
		else
		if( optionACL[ i ].attribute >= CRYPT_OPTION_NET_SOCKS_SERVER && \
			optionACL[ i ].attribute <= CRYPT_OPTION_NET_WRITETIMEOUT )
			{
			if( optionACL[ i ].subTypeA != ST_NONE || \
				optionACL[ i ].subTypeB != ST_NONE || \
				optionACL[ i ].subTypeC != ( ST_SESS_ANY | ST_USER_ANY ) )
				{
				DEBUG_DIAG(( "Networking property ACL #%d inconsistent", i ));
				retIntError();
				}
			}
		else
		if( optionACL[ i ].subTypeA != ST_NONE || \
			optionACL[ i ].subTypeB != ST_NONE || \
			optionACL[ i ].subTypeC & ~( SUBTYPE_CLASS_C | ST_USER_ANY ) )
			{
			DEBUG_DIAG(( "Networking property ACL #%d inconsistent", i ));
			retIntError();
			}
#endif /* !NDEBUG */
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( optionACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( optionACL[ CRYPT_OPTION_LAST - \
						CRYPT_OPTION_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */

	/* Check the context ACLs */
	LOOP_LARGE( i = 0, i < CRYPT_CTXINFO_LAST - CRYPT_CTXINFO_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( contextACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( contextACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &contextACL[ i ], i + CRYPT_CTXINFO_FIRST + 1,
							ST_CTX_ANY, ST_NONE, ST_NONE ) )
			{
			DEBUG_DIAG(( "Context ACL #%d inconsistent", i ));
			retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( contextACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( contextACL[ CRYPT_CTXINFO_LAST - \
						 CRYPT_CTXINFO_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */

	/* Check the certificate ACLs */
#ifdef USE_CERTIFICATES
	LOOP_LARGE( i = 0, i < CRYPT_CERTINFO_LAST_CERTINFO - CRYPT_CERTINFO_FIRST_CERTINFO && \
					   i < FAILSAFE_ARRAYSIZE( certificateACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( certificateACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &certificateACL[ i ],
							i + CRYPT_CERTINFO_FIRST_CERTINFO,
							ST_CERT_ANY, ST_NONE, ST_NONE ) )
			{
			DEBUG_DIAG(( "Certificate ACL #%d inconsistent", i ));
			retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( certificateACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( certificateACL[ CRYPT_CERTINFO_LAST_CERTINFO - \
							 CRYPT_CERTINFO_FIRST_CERTINFO + 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
	LOOP_LARGE( i = 0, i < CRYPT_CERTINFO_LAST_NAME - CRYPT_CERTINFO_FIRST_NAME && \
					   i < FAILSAFE_ARRAYSIZE( certNameACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( certNameACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &certNameACL[ i ], i + CRYPT_CERTINFO_FIRST_NAME,
							ST_CERT_ANY, ST_NONE, ST_NONE ) )
			{
			DEBUG_DIAG(( "Certificate name ACL #%d inconsistent", i ));
			retIntError();
			}
#ifdef USE_CERTIFICATES
  #ifndef NDEBUG
		ENSURES( certNameACL[ i ].attribute == CRYPT_CERTINFO_DIRECTORYNAME || \
				 certNameACL[ i ].access == ACCESS_Rxx_RWD );
  #endif /* !NDEBUG */
#else
		ENSURES( certNameACL[ i ].access == ACCESS_xxx_xxx );
#endif /* USE_CERTIFICATES */
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( certNameACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( certNameACL[ CRYPT_CERTINFO_LAST_NAME - \
						  CRYPT_CERTINFO_FIRST_NAME + 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
	LOOP_LARGE( i = 0, i < CRYPT_CERTINFO_LAST_EXTENSION - CRYPT_CERTINFO_FIRST_EXTENSION && \
					   i < FAILSAFE_ARRAYSIZE( certExtensionACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( certExtensionACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &certExtensionACL[ i ],
							i + CRYPT_CERTINFO_FIRST_EXTENSION,
							ST_CERT_ANY, ST_NONE, ST_NONE ) )
			{
			DEBUG_DIAG(( "Certificate extension ACL #%d inconsistent", i ));
			retIntError();
			}
#ifndef USE_CERTIFICATES
		ENSURES( certExtensionACL[ i ].access == ACCESS_xxx_xxx );
#endif /* !USE_CERTIFICATES */
		if( certExtensionACL[ i ].access == ACCESS_xxx_xxx )
			continue;	/* Disabled attribute */
		if( ( certExtensionACL[ i ].access & ACCESS_RWD_xxx ) != ACCESS_Rxx_xxx )
			{
			DEBUG_DIAG(( "Certificate extension ACL #%d inconsistent", i ));
			retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( certExtensionACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( certExtensionACL[ CRYPT_CERTINFO_LAST_EXTENSION - \
							   CRYPT_CERTINFO_FIRST_EXTENSION + 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
	LOOP_LARGE( i = 0, i < CRYPT_CERTINFO_LAST_CMS - CRYPT_CERTINFO_FIRST_CMS && \
					   i < FAILSAFE_ARRAYSIZE( certSmimeACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( certSmimeACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &certSmimeACL[ i ], i + CRYPT_CERTINFO_FIRST_CMS,
							ST_CERT_CMSATTR | ST_CERT_OCSP_RESP | ST_CERT_RTCS_REQ, \
							ST_NONE, ST_NONE ) )
			{
			DEBUG_DIAG(( "CMS attribute ACL #%d inconsistent", i ));
			retIntError();
			}
#ifndef NDEBUG
		if( certSmimeACL[ i ].attribute == CRYPT_CERTINFO_CMS_NONCE )
			{
			/* Nonces are also used in OCSP and RTCS, see the comment the 
			   ACL for this attribute for details */
			if( certSmimeACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_CMSATTR | \
												ST_CERT_OCSP_RESP | ST_CERT_RTCS_REQ ) )
				{
				DEBUG_DIAG(( "CMS attribute ACL #%d inconsistent", i ));
				retIntError();
				}
			}
		else
			{
			if( certSmimeACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_CMSATTR ) )
				{
				DEBUG_DIAG(( "CMS attribute ACL #%d inconsistent", i ));
				retIntError();
				}
			}
#endif /* !NDEBUG */
#ifndef USE_CERTIFICATES
		ENSURES( certSmimeACL[ i ].access == ACCESS_xxx_xxx );
#endif /* !USE_CERTIFICATES */
		if( certSmimeACL[ i ].access == ACCESS_xxx_xxx )
			continue;	/* Disabled attribute */
		if( ( certSmimeACL[ i ].access & ACCESS_RWD_xxx ) != ACCESS_Rxx_xxx )
			{
			DEBUG_DIAG(( "CMS attribute ACL #%d inconsistent", i ));
			retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( certSmimeACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( certSmimeACL[ CRYPT_CERTINFO_LAST_CMS - \
						   CRYPT_CERTINFO_FIRST_CMS + 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
#endif /* USE_CERTIFICATES */

	/* Check the keyset ACLs */
#ifdef USE_KEYSETS
	LOOP_LARGE( i = 0, i < CRYPT_KEYINFO_LAST - CRYPT_KEYINFO_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( keysetACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( keysetACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &keysetACL[ i ], i + CRYPT_KEYINFO_FIRST + 1,
							ST_NONE, ST_KEYSET_ANY, ST_NONE ) )
			{
			DEBUG_DIAG(( "Keyset ACL #%d inconsistent", i ));
			retIntError();
			}
#ifndef USE_KEYSETS
		ENSURES( keysetACL[ i ].access == ACCESS_xxx_xxx );
#endif /* !USE_KEYSETS */
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( keysetACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( keysetACL[ CRYPT_KEYINFO_LAST - \
						CRYPT_KEYINFO_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
#endif /* USE_KEYSETS */

	/* Check the device ACLs.  We don't perform a USE_DEVICES check to 
	   parallel the checks done for other object classes because the 
	   system device is always enabled */
	LOOP_LARGE( i = 0, i < CRYPT_DEVINFO_LAST - CRYPT_DEVINFO_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( deviceACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( deviceACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &deviceACL[ i ], i + CRYPT_DEVINFO_FIRST + 1,
							ST_NONE, ST_DEV_ANY_STD, ST_NONE ) )
			{
			DEBUG_DIAG(( "Device ACL #%d inconsistent", i ));
			retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( deviceACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( deviceACL[ CRYPT_DEVINFO_LAST - \
						CRYPT_DEVINFO_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */

	/* Check the envelope ACLs */
#ifdef USE_ENVELOPES
	LOOP_LARGE( i = 0, i < CRYPT_ENVINFO_LAST - CRYPT_ENVINFO_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( envelopeACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( envelopeACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &envelopeACL[ i ], i + CRYPT_ENVINFO_FIRST + 1,
							ST_NONE, ST_ENV_ANY, ST_NONE ) )
			{
			DEBUG_DIAG(( "Envelope ACL #%d inconsistent", i ));
			retIntError();
			}
#ifndef USE_ENVELOPES
		ENSURES( envelopeACL[ i ].access == ACCESS_xxx_xxx );
#endif /* !USE_ENVELOPES */
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( envelopeACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( envelopeACL[ CRYPT_ENVINFO_LAST - \
						  CRYPT_ENVINFO_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
#endif /* USE_ENVELOPES */

	/* Check the session ACLs */
#ifdef USE_SESSIONS
	LOOP_LARGE( i = 0, i < CRYPT_SESSINFO_LAST - CRYPT_SESSINFO_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( sessionACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( sessionACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &sessionACL[ i ], i + CRYPT_SESSINFO_FIRST + 1,
							ST_NONE, ST_NONE, ST_SESS_ANY ) )
			{
			DEBUG_DIAG(( "Session ACL #%d inconsistent", i ));
			retIntError();
			}
#ifndef USE_SESSIONS
		ENSURES( sessionACL[ i ].access == ACCESS_xxx_xxx );
#endif /* !USE_SESSIONS */
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( sessionACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( sessionACL[ CRYPT_SESSINFO_LAST - \
						 CRYPT_SESSINFO_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */
#endif /* USE_SESSIONS */

	/* Check the user ACLs */
	LOOP_LARGE( i = 0, i < CRYPT_USERINFO_LAST - CRYPT_USERINFO_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( userACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( userACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &userACL[ i ], i + CRYPT_USERINFO_FIRST + 1,
							ST_NONE, ST_NONE, ST_USER_ANY ) )
			{
			DEBUG_DIAG(( "User ACL #%d inconsistent", i ));
			retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( userACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( userACL[ CRYPT_USERINFO_LAST - \
					  CRYPT_USERINFO_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */

	/* Check the internal ACLs */
	LOOP_LARGE( i = 0, i < CRYPT_IATTRIBUTE_LAST - CRYPT_IATTRIBUTE_FIRST - 1 && \
					   i < FAILSAFE_ARRAYSIZE( internalACL, ATTRIBUTE_ACL ), i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( internalACL, \
														   ATTRIBUTE_ACL ) - 1 ) );

		if( !aclConsistent( &internalACL[ i ],
							i + CRYPT_IATTRIBUTE_FIRST + 1,
							ST_ANY_A, ST_ANY_B, ST_ANY_C ) )
			{
			DEBUG_DIAG(( "Internal ACL #%d inconsistent", i ));
			retIntError();
			}
		ENSURES( ( internalACL[ i ].access & ACCESS_MASK_EXTERNAL ) == 0 );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( internalACL, ATTRIBUTE_ACL ) );
#ifndef NDEBUG
	ENSURES( internalACL[ CRYPT_IATTRIBUTE_LAST - \
						  CRYPT_IATTRIBUTE_FIRST - 1 ].attribute == \
									( CRYPT_ATTRIBUTE_TYPE ) CRYPT_ERROR );
#endif /* !NDEBUG */

	return( CRYPT_OK );
	}
#else

CHECK_RETVAL \
int initAttributeACL( void )
	{
	return( CRYPT_OK );
	}
#endif /* CONFIG_NO_SELFTEST */

void endAttributeACL( void )
	{
	}

/****************************************************************************
*																			*
*								ACL Lookup Functions						*
*																			*
****************************************************************************/

/* Find the ACL for an object attribute */

CHECK_RETVAL_PTR \
const void *findAttributeACL( IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
							  IN_BOOL const BOOLEAN isInternalMessage )
	{
	/* Precondition: If it's an internal message (i.e. not raw data from the
	   user) then the attribute is valid */
	REQUIRES_N( !isInternalMessage || \
				isAttribute( attribute ) || isInternalAttribute( attribute ) );
	REQUIRES_N( isBooleanValue( isInternalMessage ) );

	/* Perform a hardcoded binary search for the attribute ACL, this minimises
	   the number of comparisons necessary to find a match.
	   
	   All of the checks here are specified as debug-only assertions rather 
	   than REQUIRES() preconditions since the attribute values that are 
	   being checked are only present in the debug build to save space.  
	   This isn't a major issue since it just catches cases where the static 
	   list of attributes has expanded but the equally static ACL table 
	   hasn't, which will be caught by the first run of the self-test */
	if( attribute < CRYPT_CTXINFO_LAST )
		{
		if( attribute < CRYPT_GENERIC_LAST )
			{
			if( attribute > CRYPT_PROPERTY_FIRST && \
				attribute < CRYPT_PROPERTY_LAST )
				{
				assert( propertyACL[ attribute - CRYPT_PROPERTY_FIRST - 1 ].attribute == attribute );
				return( &propertyACL[ attribute - CRYPT_PROPERTY_FIRST - 1 ] );
				}
			if( attribute > CRYPT_GENERIC_FIRST && \
				attribute < CRYPT_GENERIC_LAST )
				{
				assert( genericACL[ attribute - CRYPT_GENERIC_FIRST - 1 ].attribute == attribute );
				return( &genericACL[ attribute - CRYPT_GENERIC_FIRST - 1 ] );
				}
			}
		else
			{
			if( attribute > CRYPT_OPTION_FIRST && \
				attribute < CRYPT_OPTION_LAST )
				{
				assert( optionACL[ attribute - CRYPT_OPTION_FIRST - 1 ].attribute == attribute );
				return( &optionACL[ attribute - CRYPT_OPTION_FIRST - 1 ] );
				}
			if( attribute > CRYPT_CTXINFO_FIRST && \
				attribute < CRYPT_CTXINFO_LAST )
				{
				assert( contextACL[ attribute - CRYPT_CTXINFO_FIRST - 1 ].attribute == attribute );
				return( &contextACL[ attribute - CRYPT_CTXINFO_FIRST - 1 ] );
				}
			}
		
		return( NULL );
		}
	if( attribute < CRYPT_KEYINFO_LAST )
		{
#ifdef USE_CERTIFICATES
		if( attribute > CRYPT_CERTINFO_FIRST && \
			attribute < CRYPT_CERTINFO_LAST )
			{
			/* Certificate attributes are split into subranges so we have to 
			   adjust the offsets to get the right ACL.  The subrange 
			   specifiers are inclusive ranges rather than bounding values, 
			   so we use >= rather than > comparisons */
			if( attribute < CRYPT_CERTINFO_FIRST_EXTENSION )
				{
				if( attribute >= CRYPT_CERTINFO_FIRST_CERTINFO && \
					attribute <= CRYPT_CERTINFO_LAST_CERTINFO )
					{
					assert( certificateACL[ attribute - CRYPT_CERTINFO_FIRST_CERTINFO ].attribute == attribute );
					return( &certificateACL[ attribute - CRYPT_CERTINFO_FIRST_CERTINFO ] );
					}
				if( attribute >= CRYPT_CERTINFO_FIRST_NAME && \
					attribute <= CRYPT_CERTINFO_LAST_NAME )
					{
					assert( certNameACL[ attribute - CRYPT_CERTINFO_FIRST_NAME ].attribute == attribute );
					return( &certNameACL[ attribute - CRYPT_CERTINFO_FIRST_NAME ] );
					}
				}
			else
				{
				if( attribute >= CRYPT_CERTINFO_FIRST_EXTENSION && \
					attribute <= CRYPT_CERTINFO_LAST_EXTENSION )
					{
					assert( certExtensionACL[ attribute - CRYPT_CERTINFO_FIRST_EXTENSION ].attribute == attribute );
					return( &certExtensionACL[ attribute - CRYPT_CERTINFO_FIRST_EXTENSION ] );
					}
				if( attribute >= CRYPT_CERTINFO_FIRST_CMS && \
					attribute <= CRYPT_CERTINFO_LAST_CMS )
					{
					assert( certSmimeACL[ attribute - CRYPT_CERTINFO_FIRST_CMS ].attribute == attribute );
					return( &certSmimeACL[ attribute - CRYPT_CERTINFO_FIRST_CMS ] );
					}
				}
			}
#endif /* USE_CERTIFICATES */
#ifdef USE_KEYSETS
		if( attribute > CRYPT_KEYINFO_FIRST && \
			attribute < CRYPT_KEYINFO_LAST )
			{
			assert( keysetACL[ attribute - CRYPT_KEYINFO_FIRST - 1 ].attribute == attribute );
			return( &keysetACL[ attribute - CRYPT_KEYINFO_FIRST - 1 ] );
			}
#endif /* USE_KEYSETS */

		return( NULL );
		}
	if( attribute < CRYPT_USERINFO_LAST )
		{
		if( attribute > CRYPT_DEVINFO_FIRST && \
			attribute < CRYPT_DEVINFO_LAST )
			{
			assert( deviceACL[ attribute - CRYPT_DEVINFO_FIRST - 1 ].attribute == attribute );
			return( &deviceACL[ attribute - CRYPT_DEVINFO_FIRST - 1 ] );
			}
#ifdef USE_ENVELOPES
		if( attribute > CRYPT_ENVINFO_FIRST && \
			attribute < CRYPT_ENVINFO_LAST )
			{
			assert( envelopeACL[ attribute - CRYPT_ENVINFO_FIRST - 1 ].attribute == attribute );
			return( &envelopeACL[ attribute - CRYPT_ENVINFO_FIRST - 1 ] );
			}
#endif /* USE_ENVELOPES */
#ifdef USE_SESSIONS
		if( attribute > CRYPT_SESSINFO_FIRST && \
			attribute < CRYPT_SESSINFO_LAST )
			{
			assert( sessionACL[ attribute - CRYPT_SESSINFO_FIRST - 1 ].attribute == attribute );
			return( &sessionACL[ attribute - CRYPT_SESSINFO_FIRST - 1 ] );
			}
#endif /* USE_SESSIONS */
		if( attribute > CRYPT_USERINFO_FIRST && \
			attribute < CRYPT_USERINFO_LAST )
			{
			assert( userACL[ attribute - CRYPT_USERINFO_FIRST - 1 ].attribute == attribute );
			return( &userACL[ attribute - CRYPT_USERINFO_FIRST - 1 ] );
			}

		return( NULL );
		}

	/* If it's an external message then the internal attributes don't 
	   exist */
	if( !isInternalMessage )
		return( NULL );
	if( attribute > CRYPT_IATTRIBUTE_FIRST && \
		attribute < CRYPT_IATTRIBUTE_LAST )
		{
		assert( internalACL[ attribute - CRYPT_IATTRIBUTE_FIRST - 1 ].attribute == attribute );
		return( &internalACL[ attribute - CRYPT_IATTRIBUTE_FIRST - 1 ] );
		}

	retIntError_Null();
	}
