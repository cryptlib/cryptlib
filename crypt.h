<<<<<<< HEAD
/****************************************************************************
*																			*
*					  cryptlib Internal General Header File 				*
*						Copyright Peter Gutmann 1992-2021					*
*																			*
****************************************************************************/

#ifndef _CRYPT_DEFINED

#define _CRYPT_DEFINED

/* The overall cryptlib header file, which pulls in all other universally-
   used header files.  The include order is:

	os_detect.h		// Detect system configuration
	config.h		// Overall cryptlib configuration settings
	consts.h		// Constants
	analyse.h		// Code analysis definitions, needs consts.h
	os_spec.h		// OS- and compiler-specific definitions, needs analyse.h
	cryptlib.h		// cryptlib external API header
	cryptkrn.h		// Kernel API
	safety.h		// Code/memory safety definitions, needs os_spec.h
	int_api.h		// General internal API
	list.h			// List handling header
	debug.h			// Debugging header
	fault.h			// Debugging (fault-injection) header */

/* Global headers used in almost every module.  Before includng these, we 
   have to set a few defines to enable normally-disabled functionality */

#ifndef __STDC_WANT_LIB_EXT1__
  /* Set the magic define that enables safe(r) C library functions, which for
	 some unfathomable reason are disabled by default, like disabling the
	 seatbelts in a car */
  #define __STDC_WANT_LIB_EXT1__	1
#endif /* __STDC_WANT_LIB_EXT1__ */
#if !defined( NDEBUG) && ( defined( __MVS__ ) || defined( __VMCMS__ ) )
  /* IBM mainframe debug builds need extra functions for diagnostics 
	 support */
  #define _OPEN_SYS_ITOA_EXT
#endif /* IBM big iron debug build */
#if defined( __APPLE__ ) 
  /* Apple headers rely on a pile of BSD-isms that don't get defined unless 
     _DARWIN_C_SOURCE is defined */
  #define _DARWIN_C_SOURCE
#endif /* Apple */

#include <stdlib.h>
#include <string.h>

/****************************************************************************
*																			*
*						System- and Compiler-Specific Defines				*
*																			*
****************************************************************************/

/* Pull in the system and compiler-specific defines and values.  This 
   detects the system config and is used by config.h */

#if defined( INC_ALL )
  #include "os_detect.h"
#else
  #include "misc/os_detect.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Config Options								*
*																			*
****************************************************************************/

/* Pull in the cryptlib initialisation options file, which contains the
   various USE_xxx defines that enable different cryptlib features */

#if defined( INC_ALL )
  #include "config.h"
#else
  #include "misc/config.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Data Size and Crypto-related Constants				*
*																			*
****************************************************************************/

/* Pull in the data-size and crypt-related constants */

#if defined( INC_ALL )
  #include "consts.h"
#else
  #include "misc/consts.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						System- and Compiler-Specific Interface				*
*																			*
****************************************************************************/

/* Pull in the source code analysis header.  This is needed before we pull
   in os_spec.h since this uses defines in analyse.h */

#if defined( INC_ALL )
  #include "analyse.h"
#else
  #include "misc/analyse.h"
#endif /* Compiler-specific includes */

/* Pull in the system and compiler-specific interface definitions.  This 
   uses the output from config.h to enable/disable system-specific 
   interfaces and options */

#if defined( INC_ALL )
  #include "os_spec.h"
#else
  #include "misc/os_spec.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Global Cryptlib Header						*
*																			*
****************************************************************************/

/* Pull in the global cryptlib header */

#include "cryptlib.h"

/* Since some of the _LAST types are used in the code, we have to undefine
   them again if they've been used in the enum-fix kludge */

#ifdef NEED_ENUMFIX
  #undef CRYPT_ALGO_LAST
  #undef CRYPT_MODE_LAST
  #undef CRYPT_KEYSET_LAST
  #undef CRYPT_DEVICE_LAST
  #undef CRYPT_CERTTYPE_LAST
  #undef CRYPT_FORMAT_LAST
  #undef CRYPT_SESSION_LAST
  #undef CRYPT_USER_LAST
  #undef CRYPT_IATTRIBUTE_LAST
  #undef CRYPT_CRLEXTREASON_LAST
  #undef CRYPT_CONTENT_LAST
  #undef CRYPT_SIGNATURELEVEL_LAST
  #undef CRYPT_CERTFORMAT_LAST
  #undef CRYPT_REQUESTTYPE_LAST
  #undef CRYPT_KEYID_LAST
  #undef CRYPT_OBJECT_LAST
  #undef CRYPT_ERRTYPE_LAST
  #undef CRYPT_CERTACTION_LAST
  #undef CRYPT_KEYOPT_LAST
#endif /* NEED_ENUMFIX */

/****************************************************************************
*																			*
*								Kernel Interface							*
*																			*
****************************************************************************/

/* Pull in the cryptlib kernel interface defines */

#include "cryptkrn.h"

/****************************************************************************
*																			*
*								Portability Defines							*
*																			*
****************************************************************************/

/* Read/write values as 32-bit big-endian data in cases where we're not 
   dealing with a stream.  Used to sample data from the crypto RNG to detect 
   stuck-at faults and in the debug version of clAlloc() */

#define mgetLong( memPtr ) \
		( ( ( unsigned long ) ( memPtr )[ 0 ] << 24 ) | \
		  ( ( unsigned long ) ( memPtr )[ 1 ] << 16 ) | \
		  ( ( unsigned long ) ( memPtr )[ 2 ] << 8 ) | \
		    ( unsigned long ) ( memPtr )[ 3 ] ); \
		memPtr += 4

#define mputLong( memPtr, data ) \
		( memPtr )[ 0 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		( memPtr )[ 1 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		( memPtr )[ 2 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		( memPtr )[ 3 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 4

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* Information on exported key/signature data.  This is an extended version
   of the data returned by the externally-visible cryptQueryObject() routine */

#define AUTHENCPARAM_MAX_SIZE	128

typedef struct {
	/* Object format and status information.  If we get an object type 
	   that's valid but that we can't process, for example because it's a
	   newer version or format than we can deal with, we report it as a 
	   CRYPT_OBJECT_NONE but set the optType to what it should be if we
	   could handle it */
	CRYPT_FORMAT_TYPE formatType;	/* Object format type */
	CRYPT_OBJECT_TYPE type, optType;/* Object type */
	long size;						/* Object size */
	VALUE( 0, 10 ) \
	int version;					/* Object format version */

	/* The encryption algorithm and mode */
	CRYPT_ALGO_TYPE cryptAlgo;		/* The encryption algorithm */
	CRYPT_MODE_TYPE cryptMode;		/* The encryption mode */
	int cryptParam;					/* Optional algorithm parameter */
	int cryptAlgoEncoding;			/* Optional encoding ALGOID_ENCODING_xxx */

	/* The key ID for public key objects */
	BUFFER( CRYPT_MAX_HASHSIZE, keyIDlength ) \
	BYTE keyID[ CRYPT_MAX_HASHSIZE + 8 ];/* PKC key ID */
	VALUE( 0, CRYPT_MAX_HASHSIZE ) \
	int keyIDlength;

	/* The IV for conventionally encrypted data */
	BUFFER( CRYPT_MAX_IVSIZE, ivLength ) \
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];/* IV */
	VALUE( 0, CRYPT_MAX_IVSIZE ) \
	int ivLength;

	/* The key derivation algorithm and iteration count for conventionally
	   encrypted keys */
	CRYPT_ALGO_TYPE keySetupAlgo;	/* Key setup algorithm */
	int keySetupParam;				/* Optional parameter for key setup algo */
	int keySetupIterations;			/* Key setup iteration count */
	int keySize;					/* Key size (if not implicit) */
	BUFFER( CRYPT_MAX_HASHSIZE, saltLength ) \
	BYTE salt[ CRYPT_MAX_HASHSIZE + 8 ];/* Key setup salt */
	VALUE( 0, CRYPT_MAX_HASHSIZE ) \
	int saltLength;

	/* The hash algorithm for signatures */
	CRYPT_ALGO_TYPE hashAlgo;		/* Hash algorithm */
	int hashParam;					/* Optional algorithm parameter */

	/* The encoded parameter data for authenticated encryption, and the
	   optional KDF and encryption and MAC algorithm parameter data within 
	   that */
	BUFFER( AUTHENCPARAM_MAX_SIZE, authEncParamLength ) \
	BYTE authEncParamData[ AUTHENCPARAM_MAX_SIZE + 8 ];
	VALUE( 0, AUTHENCPARAM_MAX_SIZE ) \
	int authEncParamLength;			/* AuthEnc parameter data */
	int kdfParamStart, kdfParamLength;	/* Position of opt.KDF params */
	int encParamStart, encParamLength;	/* Position of enc.parameters */
	int macParamStart, macParamLength;	/* Position of MAC parameters */

	/* The start and length of the payload data, either the encrypted key or
	   the signature data */
	int dataStart, dataLength;

	/* The start and length of the issuerAndSerialNumber, authenticated 
	   attributes, and unauthenticated attributes for CMS objects */
	int iAndSStart, iAndSLength;
	int attributeStart, attributeLength;
	int unauthAttributeStart, unauthAttributeLength;
	} QUERY_INFO;

/* DLP algorithms require composite parameters when en/decrypting and
   signing/sig checking, so we can't just pass in a single buffer full of
   data as we can with RSA.  In addition the data length changes, for
   example for a DSA sig we pass in a 20-byte hash and get back a ~50-byte
   sig, for sig.checking we pass in a 20-byte hash and ~50-byte sig and get
   back nothing.  Because of this we have to use the following structure to
   pass data to the DLP-based PKCs */

typedef struct {
	BUFFER_FIXED( inLen1 ) \
	const BYTE *inParam1;
	BUFFER_OPT_FIXED( inLen2 ) \
	const BYTE *inParam2;				/* Input parameters */
	BUFFER_FIXED( outLen ) \
	BYTE *outParam;						/* Output parameter */
	int inLen1, inLen2, outLen;			/* Parameter lengths */
	CRYPT_FORMAT_TYPE formatType;		/* Paramter format type */
	} DLP_PARAMS;

#define setDLPParams( dlpDataPtr, dataIn, dataInLen, dataOut, dataOutLen ) \
	{ \
	memset( ( dlpDataPtr ), 0, sizeof( DLP_PARAMS ) ); \
	( dlpDataPtr )->formatType = CRYPT_FORMAT_CRYPTLIB; \
	( dlpDataPtr )->inParam1 = ( dataIn ); \
	( dlpDataPtr )->inLen1 = ( dataInLen ); \
	( dlpDataPtr )->outParam = ( dataOut ); \
	( dlpDataPtr )->outLen = ( dataOutLen ); \
	}

/* When calling key agreement functions we have to pass a mass of cruft
   around instead of the usual flat data (even more than the generic DLP
   parameter information) for which we use the following structure.  The
   public value is the public key value used for the agreement process,
   typically y = g^x mod p for DH-like mechanisms.  The ukm is the user
   keying material, typically something which is mixed into the DH process
   to make the new key unique.  The wrapped key is the output (originator)/
   input(recipient) to the keyagreement process.  The session key context
   contains a context into which the derived key is loaded.  Typical
   examples of use are:

	PKCS #3: publicValue = y
	S/MIME: publicValue = y, ukm = 512-bit nonce, wrappedKey = g^x mod p
	SSH, SSL: publicValue = y, wrappedKey = x */

typedef struct {
	BUFFER( CRYPT_MAX_PKCSIZE, publicValueLen ) \
	BYTE publicValue[ CRYPT_MAX_PKCSIZE + 8 ];
	VALUE( 0, CRYPT_MAX_PKCSIZE ) \
	int publicValueLen;				/* Public key value */
	BUFFER( CRYPT_MAX_PKCSIZE, wrappedKeyLen ) \
	BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];
	VALUE( 0, CRYPT_MAX_PKCSIZE ) \
	int wrappedKeyLen;				/* Wrapped key */
	} KEYAGREE_PARAMS;

/****************************************************************************
*																			*
*								Useful General Macros						*
*																			*
****************************************************************************/

/* Reasonably reliable way to get rid of unused argument warnings in a
   compiler-independant manner.  There are two forms of this, a standard one
   and an _OPT form in cases where the compiler recognises STDC_UNUSED and
   knows the arg. is actually unused, for which applying UNUSED_ARG() would 
   lead to a warning about an unused arg. being used */

#define UNUSED_ARG( arg )		( ( arg ) = ( arg ) )
#ifdef HAS_STDC_UNUSED
  #define UNUSED_ARG_OPT( arg )
#else
  #define UNUSED_ARG_OPT( arg )	( ( arg ) = ( arg ) )
#endif /* HAS_STDC_UNUSED */

/* Although min() and max() aren't in the ANSI standard, most compilers have
   them in one form or another, but just enough don't that we need to define 
   them ourselves in some cases */

#if !defined( min )
  #ifdef MIN
	#define min			MIN
	#define max			MAX
  #else
	#define min( a, b )	( ( ( a ) < ( b ) ) ? ( a ) : ( b ) )
	#define max( a, b )	( ( ( a ) > ( b ) ) ? ( a ) : ( b ) )
  #endif /* Various min/max macros */
#endif /* !min/max */

/* Macros to convert to and from the bit counts used for some encryption
   parameters */

#define bitsToBytes( bits )			( ( ( bits ) + 7 ) >> 3 )
#define bytesToBits( bytes )		( ( bytes ) << 3 )

/* When initialising a static block of bytes, it's useful to be able to 
   specify it as a character string, however this runs into problems with
   the fact that the default char type is signed.  To get around this the
   following macro declares a byte string as a set of unsigned bytes */

#define MKDATA( x )					( ( BYTE * ) ( x ) )

/* Macro to round a value up to the nearest multiple of a second value,
   with the second value being a power of 2 */

#define roundUp( size, roundSize ) \
	( ( ( size ) + ( ( roundSize ) - 1 ) ) & ~( ( roundSize ) - 1 ) )

/* A macro to clear sensitive data from memory.  This is somewhat easier to
   use than calling memset with the second parameter set to 0 all the time,
   and makes it obvious where sensitive data is being erased.  In addition
   some systems, recognising the problem of compilers removing what they see
   as dead stores, have distinct memory zeroisation support, so if available 
   we use that */

#if defined( _MSC_VER ) && VC_GE_2005( _MSC_VER )
  /* This is just a mapping to RtlSecureZeroMemory() (via WinBase.h) which 
     is implemented as inline code implementing a loop on a pointer declared 
	 volatile, but unlike the corresponding RtlZeroMemory() there's a 
	 contract that this will always zeroise memory even in the face of 
	 compiler changes that would otherwise optimise away the access */
  #define zeroise( memory, size )	SecureZeroMemory( memory, size )
#elif defined( __STDC_LIB_EXT1__ )
  /* C11 defines a function memset_s() that guarantees that it won't be
	 optimised away, although this is quite well obfuscated in the spec,
	 "the memory indicated by [the memset parameters] may be accessible in 
	 the future and therefore must contain the values indicated by [the
	 value to set]", hopefully the implementers will know that this equates
	 to "the memset_s() call can't be optimised away" */
  #define zeroise( memory, size )	memset_s( memory, size, 0, size )
#elif defined( __OpenBSD__ )
  /* The OpenBSD folks defined their own won't-be-optimised-away bzero()
	 function */
  #define zeroise( memory, size )	explicit_bzero( memory, size )
#else
  #define zeroise( memory, size )	memset( memory, 0, size )
#endif /* Systems with distinct zeroise functions */

/* A macro to check that a value is a possibly valid handle.  This doesn't
   check that the handle refers to a valid object, merely that the value is
   in the range for valid handles.  The full function isValidHandle() used
   in the kernel does check that the handle refers to a valid object, being
   more than just a range check */

#define isHandleRangeValid( handle ) \
		( ( handle ) > NO_SYSTEM_OBJECTS - 1 && ( handle ) < MAX_NO_OBJECTS )

/* A macro to check whether an encryption mode needs an IV or not */

#define needsIV( mode ) \
		( ( mode ) == CRYPT_MODE_CBC || ( mode ) == CRYPT_MODE_CFB || \
		  ( mode ) == CRYPT_MODE_GCM )

/* A macro to check whether an algorithm is a pure stream cipher (that is,
   a real stream cipher rather than just a block cipher run in a stream
   mode) */

#define isStreamCipher( algorithm ) \
		( ( algorithm ) == CRYPT_ALGO_RC4 )

/* Some stream ciphers are actually block ciphers pretending to be stream
   ciphers, which means that although they can produce byte-oriented 
   output they still need an IV.  The following macro checks for these
   special snowflakes */

#define isSpecialStreamCipher( algorithm ) \
		( ( algorithm ) == CRYPT_ALGO_CHACHA20 )

/* A macro to check whether an algorithm is regarded as being (relatively)
   insecure or not.  This is used by some of the higher-level internal
   routines that normally use the default algorithm set in the configuration
   database if nothing else is explicitly specified, but that specifically
   check for the weaker algorithms and use something stronger instead if a
   weak algorithm is specified.  This is done both for luser-proofing and to
   avoid possible problems from a trojan patching the configuration
   database */

#define isWeakCryptAlgo( algorithm )	( ( algorithm ) == CRYPT_ALGO_DES || \
										  ( algorithm ) == CRYPT_ALGO_RC2 || \
										  ( algorithm ) == CRYPT_ALGO_RC4 )
#define isWeakHashAlgo( algorithm )		( ( algorithm ) == CRYPT_ALGO_MD5 )
#define isWeakMacAlgo( algorithm )		( 0 )
										/* None left with HMAC-MD5 deprecated */

/* Macros to check for membership in overall algorithm classes */

#define isConvAlgo( algorithm ) \
		( ( algorithm ) >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		  ( algorithm ) <= CRYPT_ALGO_LAST_CONVENTIONAL )
#define isPkcAlgo( algorithm ) \
		( ( algorithm ) >= CRYPT_ALGO_FIRST_PKC && \
		  ( algorithm ) <= CRYPT_ALGO_LAST_PKC )
#define isHashAlgo( algorithm ) \
		( ( algorithm ) >= CRYPT_ALGO_FIRST_HASH && \
		  ( algorithm ) <= CRYPT_ALGO_LAST_HASH )
#define isMacAlgo( algorithm ) \
		( ( algorithm ) >= CRYPT_ALGO_FIRST_MAC && \
		  ( algorithm ) <= CRYPT_ALGO_LAST_MAC )
#define isSpecialAlgo( algorithm ) \
		( ( algorithm ) == CRYPT_IALGO_GENERIC_SECRET )

/* Macros to check whether a PKC algorithm is useful for a certain purpose 
   or requires special-case handling.  Note that isDlpAlgo() doesn't include 
   the ECC algorithms, which are also based on the DLP (although in this 
   case the ECDLP and not the standard DLP).  This is a bit ugly but it's 
   used in various places to distinguish DLP-based PKCs from non-DLP-based
   PKCs, while ECDLP-based-PKCs are in a separate class.  This means that
   when checking for the extended class { DLP | ECDLP } it's necessary to
   explicitly include isEccAlgo() alongside isDlpAlgo() */

#define isSigAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_DSA || \
	  ( algorithm ) == CRYPT_ALGO_ECDSA || ( algorithm ) == CRYPT_ALGO_EDDSA )
#define isCryptAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_ELGAMAL )
#define isKeyexAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_DH || ( algorithm ) == CRYPT_ALGO_ECDH || \
	  ( algorithm ) == CRYPT_ALGO_25519 )
#define isDlpAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_DSA || ( algorithm ) == CRYPT_ALGO_ELGAMAL || \
	  ( algorithm ) == CRYPT_ALGO_DH )
#define isEccAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_ECDSA || ( algorithm ) == CRYPT_ALGO_ECDH || \
	  ( algorithm ) == CRYPT_ALGO_EDDSA || ( algorithm ) == CRYPT_ALGO_25519 )

/* Macros to check whether an algorithm has additional parameters that need 
   to be handled explicitly */

#define isParameterisedConvAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_AES )
#define isParameterisedHashAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_SHA2 || ( algorithm ) == CRYPT_ALGO_SHAng )
#define isParameterisedMacAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_HMAC_SHA2 || \
	  ( algorithm ) == CRYPT_ALGO_HMAC_SHAng )

/* A macro to check whether an error status is related to a data-formatting
   problem or some other problem.  This is used to provide extended string-
   format error information, if it's a data error then the message being
   processed was (probably) invalid, if it's not a data error then it may be
   due to an invalid decryption key being used or something similar that's
   unrelated to the message itself.
   
   The exact definition of what constitutes a "data error" is a bit vague 
   but since it's only used to control what additional error information is
   returned a certain level of fuzziness is permitted */

#define isDataError( status ) \
		( ( status ) == CRYPT_ERROR_OVERFLOW || \
		  ( status ) == CRYPT_ERROR_UNDERFLOW || \
		  ( status ) == CRYPT_ERROR_BADDATA || \
		  ( status ) == CRYPT_ERROR_SIGNATURE || \
		  ( status ) == CRYPT_ERROR_NOTAVAIL || \
		  ( status ) == CRYPT_ERROR_INCOMPLETE || \
		  ( status ) == CRYPT_ERROR_COMPLETE || \
		  ( status ) == CRYPT_ERROR_INVALID )

/* A macro to check whether a public key is too short to be secure.  This
   is a bit more complex than just a range check because any length below 
   about 512 bits is probably a bad data error, while lengths from about
   512 bits to MIN_PKCSIZE (for standard PKCs) or 120 bits to 
   MIN_PKCSIZE_ECC are too-short key errors */

#define isShortPKCKey( keySize ) \
		( ( keySize ) >= MIN_PKCSIZE_THRESHOLD && \
		  ( keySize ) < MIN_PKCSIZE )
#define isShortECCKey( keySize ) \
		( ( keySize ) >= MIN_PKCSIZE_ECC_THRESHOLD && \
		  ( keySize ) < MIN_PKCSIZE_ECC )

/* To avoid problems with signs, for example due to (signed) characters
   being potentially converted to large signed integer values we perform a
   safe conversion by going via an intermediate unsigned value, which in
   the case of char -> int results in 0xFF turning into 0x000000FF rather
   than 0xFFFFFFFF.
   
   For Visual Studio we explicitly mask some values to avoid runtime traps 
   in debug builds */

#define byteToInt( x )				( ( int ) ( ( unsigned char ) ( x ) ) )
#define intToLong( x )				( ( unsigned int ) ( x ) )

#define sizeToInt( x )				( ( unsigned int ) ( x ) )
#if defined( _MSC_VER ) && VC_GE_2010( _MSC_VER )
  #define intToByte( x )			( ( unsigned char ) ( ( x ) & 0xFF ) )
#else
  #define intToByte( x )			( ( unsigned char ) ( x ) )
#endif /* VS 2010 or newer */

/* Clear/set object error information */

#define clearObjectErrorInfo( objectInfoPtr ) \
	{ \
	( objectInfoPtr )->errorLocus = CRYPT_ATTRIBUTE_NONE; \
	( objectInfoPtr )->errorType = CRYPT_OK; \
	}

#define setObjectErrorInfo( objectInfoPtr, locus, type ) \
	{ \
	( objectInfoPtr )->errorLocus = locus; \
	( objectInfoPtr )->errorType = type; \
	}

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Pull in the internal API function definitions and prototypes */

#if defined( INC_ALL )
  #include "safety.h"		/* Must be before int_api.h for safe pointers */
  #include "int_api.h"
  #include "list.h"
#else
  #include "misc/safety.h"	/* Must be before int_api.h for safe pointers */
  #include "misc/int_api.h"
  #include "misc/list.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Debugging Functions							*
*																			*
****************************************************************************/

/* Pull in the debugging function definitions and prototypes */

#if defined( INC_ALL )
  #include "debug.h"
  #include "fault.h"
#else
  #include "misc/debug.h"
  #include "misc/fault.h"
#endif /* Compiler-specific includes */

#endif /* _CRYPT_DEFINED */
=======
/****************************************************************************
*																			*
*					  cryptlib Internal General Header File 				*
*						Copyright Peter Gutmann 1992-2021					*
*																			*
****************************************************************************/

#ifndef _CRYPT_DEFINED

#define _CRYPT_DEFINED

/* The overall cryptlib header file, which pulls in all other universally-
   used header files.  The include order is:

	os_detect.h		// Detect system configuration
	config.h		// Overall cryptlib configuration settings
	consts.h		// Constants
	analyse.h		// Code analysis definitions, needs consts.h
	os_spec.h		// OS- and compiler-specific definitions, needs analyse.h
	cryptlib.h		// cryptlib external API header
	cryptkrn.h		// Kernel API
	safety.h		// Code/memory safety definitions, needs os_spec.h
	int_api.h		// General internal API
	list.h			// List handling header
	debug.h			// Debugging header
	fault.h			// Debugging (fault-injection) header */

/* Global headers used in almost every module.  Before includng these, we 
   have to set a few defines to enable normally-disabled functionality */

#ifndef __STDC_WANT_LIB_EXT1__
  /* Set the magic define that enables safe(r) C library functions, which for
	 some unfathomable reason are disabled by default, like disabling the
	 seatbelts in a car */
  #define __STDC_WANT_LIB_EXT1__	1
#endif /* __STDC_WANT_LIB_EXT1__ */
#if !defined( NDEBUG) && ( defined( __MVS__ ) || defined( __VMCMS__ ) )
  /* IBM mainframe debug builds need extra functions for diagnostics 
	 support */
  #define _OPEN_SYS_ITOA_EXT
#endif /* IBM big iron debug build */
#if defined( __APPLE__ ) 
  /* Apple headers rely on a pile of BSD-isms that don't get defined unless 
     _DARWIN_C_SOURCE is defined */
  #define _DARWIN_C_SOURCE
#endif /* Apple */

#include <stdlib.h>
#include <string.h>

/****************************************************************************
*																			*
*						System- and Compiler-Specific Defines				*
*																			*
****************************************************************************/

/* Pull in the system and compiler-specific defines and values.  This 
   detects the system config and is used by config.h */

#if defined( INC_ALL )
  #include "os_detect.h"
#else
  #include "misc/os_detect.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Config Options								*
*																			*
****************************************************************************/

/* Pull in the cryptlib initialisation options file, which contains the
   various USE_xxx defines that enable different cryptlib features */

#if defined( INC_ALL )
  #include "config.h"
#else
  #include "misc/config.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Data Size and Crypto-related Constants				*
*																			*
****************************************************************************/

/* Pull in the data-size and crypt-related constants */

#if defined( INC_ALL )
  #include "consts.h"
#else
  #include "misc/consts.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						System- and Compiler-Specific Interface				*
*																			*
****************************************************************************/

/* Pull in the source code analysis header.  This is needed before we pull
   in os_spec.h since this uses defines in analyse.h */

#if defined( INC_ALL )
  #include "analyse.h"
#else
  #include "misc/analyse.h"
#endif /* Compiler-specific includes */

/* Pull in the system and compiler-specific interface definitions.  This 
   uses the output from config.h to enable/disable system-specific 
   interfaces and options */

#if defined( INC_ALL )
  #include "os_spec.h"
#else
  #include "misc/os_spec.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Global Cryptlib Header						*
*																			*
****************************************************************************/

/* Pull in the global cryptlib header */

#include "cryptlib.h"

/* Since some of the _LAST types are used in the code, we have to undefine
   them again if they've been used in the enum-fix kludge */

#ifdef NEED_ENUMFIX
  #undef CRYPT_ALGO_LAST
  #undef CRYPT_MODE_LAST
  #undef CRYPT_KEYSET_LAST
  #undef CRYPT_DEVICE_LAST
  #undef CRYPT_CERTTYPE_LAST
  #undef CRYPT_FORMAT_LAST
  #undef CRYPT_SESSION_LAST
  #undef CRYPT_USER_LAST
  #undef CRYPT_IATTRIBUTE_LAST
  #undef CRYPT_CRLEXTREASON_LAST
  #undef CRYPT_CONTENT_LAST
  #undef CRYPT_SIGNATURELEVEL_LAST
  #undef CRYPT_CERTFORMAT_LAST
  #undef CRYPT_REQUESTTYPE_LAST
  #undef CRYPT_KEYID_LAST
  #undef CRYPT_OBJECT_LAST
  #undef CRYPT_ERRTYPE_LAST
  #undef CRYPT_CERTACTION_LAST
  #undef CRYPT_KEYOPT_LAST
#endif /* NEED_ENUMFIX */

/****************************************************************************
*																			*
*								Kernel Interface							*
*																			*
****************************************************************************/

/* Pull in the cryptlib kernel interface defines */

#include "cryptkrn.h"

/****************************************************************************
*																			*
*								Portability Defines							*
*																			*
****************************************************************************/

/* Read/write values as 32-bit big-endian data in cases where we're not 
   dealing with a stream.  Used to sample data from the crypto RNG to detect 
   stuck-at faults and in the debug version of clAlloc() */

#define mgetLong( memPtr ) \
		( ( ( unsigned long ) ( memPtr )[ 0 ] << 24 ) | \
		  ( ( unsigned long ) ( memPtr )[ 1 ] << 16 ) | \
		  ( ( unsigned long ) ( memPtr )[ 2 ] << 8 ) | \
		    ( unsigned long ) ( memPtr )[ 3 ] ); \
		memPtr += 4

#define mputLong( memPtr, data ) \
		( memPtr )[ 0 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		( memPtr )[ 1 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		( memPtr )[ 2 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		( memPtr )[ 3 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 4

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* Information on exported key/signature data.  This is an extended version
   of the data returned by the externally-visible cryptQueryObject() routine */

#define AUTHENCPARAM_MAX_SIZE	128

typedef struct {
	/* Object format and status information.  If we get an object type 
	   that's valid but that we can't process, for example because it's a
	   newer version or format than we can deal with, we report it as a 
	   CRYPT_OBJECT_NONE but set the optType to what it should be if we
	   could handle it */
	CRYPT_FORMAT_TYPE formatType;	/* Object format type */
	CRYPT_OBJECT_TYPE type, optType;/* Object type */
	long size;						/* Object size */
	VALUE( 0, 10 ) \
	int version;					/* Object format version */

	/* The encryption algorithm and mode */
	CRYPT_ALGO_TYPE cryptAlgo;		/* The encryption algorithm */
	CRYPT_MODE_TYPE cryptMode;		/* The encryption mode */
	int cryptParam;					/* Optional algorithm parameter */
	int cryptAlgoEncoding;			/* Optional encoding ALGOID_ENCODING_xxx */

	/* The key ID for public key objects */
	BUFFER( CRYPT_MAX_HASHSIZE, keyIDlength ) \
	BYTE keyID[ CRYPT_MAX_HASHSIZE + 8 ];/* PKC key ID */
	VALUE( 0, CRYPT_MAX_HASHSIZE ) \
	int keyIDlength;

	/* The IV for conventionally encrypted data */
	BUFFER( CRYPT_MAX_IVSIZE, ivLength ) \
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];/* IV */
	VALUE( 0, CRYPT_MAX_IVSIZE ) \
	int ivLength;

	/* The key derivation algorithm and iteration count for conventionally
	   encrypted keys */
	CRYPT_ALGO_TYPE keySetupAlgo;	/* Key setup algorithm */
	int keySetupParam;				/* Optional parameter for key setup algo */
	int keySetupIterations;			/* Key setup iteration count */
	int keySize;					/* Key size (if not implicit) */
	BUFFER( CRYPT_MAX_HASHSIZE, saltLength ) \
	BYTE salt[ CRYPT_MAX_HASHSIZE + 8 ];/* Key setup salt */
	VALUE( 0, CRYPT_MAX_HASHSIZE ) \
	int saltLength;

	/* The hash algorithm for signatures */
	CRYPT_ALGO_TYPE hashAlgo;		/* Hash algorithm */
	int hashParam;					/* Optional algorithm parameter */

	/* The encoded parameter data for authenticated encryption, and the
	   optional KDF and encryption and MAC algorithm parameter data within 
	   that */
	BUFFER( AUTHENCPARAM_MAX_SIZE, authEncParamLength ) \
	BYTE authEncParamData[ AUTHENCPARAM_MAX_SIZE + 8 ];
	VALUE( 0, AUTHENCPARAM_MAX_SIZE ) \
	int authEncParamLength;			/* AuthEnc parameter data */
	int kdfParamStart, kdfParamLength;	/* Position of opt.KDF params */
	int encParamStart, encParamLength;	/* Position of enc.parameters */
	int macParamStart, macParamLength;	/* Position of MAC parameters */

	/* The start and length of the payload data, either the encrypted key or
	   the signature data */
	int dataStart, dataLength;

	/* The start and length of the issuerAndSerialNumber, authenticated 
	   attributes, and unauthenticated attributes for CMS objects */
	int iAndSStart, iAndSLength;
	int attributeStart, attributeLength;
	int unauthAttributeStart, unauthAttributeLength;
	} QUERY_INFO;

/* DLP algorithms require composite parameters when en/decrypting and
   signing/sig checking, so we can't just pass in a single buffer full of
   data as we can with RSA.  In addition the data length changes, for
   example for a DSA sig we pass in a 20-byte hash and get back a ~50-byte
   sig, for sig.checking we pass in a 20-byte hash and ~50-byte sig and get
   back nothing.  Because of this we have to use the following structure to
   pass data to the DLP-based PKCs */

typedef struct {
	BUFFER_FIXED( inLen1 ) \
	const BYTE *inParam1;
	BUFFER_OPT_FIXED( inLen2 ) \
	const BYTE *inParam2;				/* Input parameters */
	BUFFER_FIXED( outLen ) \
	BYTE *outParam;						/* Output parameter */
	int inLen1, inLen2, outLen;			/* Parameter lengths */
	CRYPT_FORMAT_TYPE formatType;		/* Paramter format type */
	} DLP_PARAMS;

#define setDLPParams( dlpDataPtr, dataIn, dataInLen, dataOut, dataOutLen ) \
	{ \
	memset( ( dlpDataPtr ), 0, sizeof( DLP_PARAMS ) ); \
	( dlpDataPtr )->formatType = CRYPT_FORMAT_CRYPTLIB; \
	( dlpDataPtr )->inParam1 = ( dataIn ); \
	( dlpDataPtr )->inLen1 = ( dataInLen ); \
	( dlpDataPtr )->outParam = ( dataOut ); \
	( dlpDataPtr )->outLen = ( dataOutLen ); \
	}

/* When calling key agreement functions we have to pass a mass of cruft
   around instead of the usual flat data (even more than the generic DLP
   parameter information) for which we use the following structure.  The
   public value is the public key value used for the agreement process,
   typically y = g^x mod p for DH-like mechanisms.  The ukm is the user
   keying material, typically something which is mixed into the DH process
   to make the new key unique.  The wrapped key is the output (originator)/
   input(recipient) to the keyagreement process.  The session key context
   contains a context into which the derived key is loaded.  Typical
   examples of use are:

	PKCS #3: publicValue = y
	S/MIME: publicValue = y, ukm = 512-bit nonce, wrappedKey = g^x mod p
	SSH, SSL: publicValue = y, wrappedKey = x */

typedef struct {
	BUFFER( CRYPT_MAX_PKCSIZE, publicValueLen ) \
	BYTE publicValue[ CRYPT_MAX_PKCSIZE + 8 ];
	VALUE( 0, CRYPT_MAX_PKCSIZE ) \
	int publicValueLen;				/* Public key value */
	BUFFER( CRYPT_MAX_PKCSIZE, wrappedKeyLen ) \
	BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];
	VALUE( 0, CRYPT_MAX_PKCSIZE ) \
	int wrappedKeyLen;				/* Wrapped key */
	} KEYAGREE_PARAMS;

/****************************************************************************
*																			*
*								Useful General Macros						*
*																			*
****************************************************************************/

/* Reasonably reliable way to get rid of unused argument warnings in a
   compiler-independant manner.  There are two forms of this, a standard one
   and an _OPT form in cases where the compiler recognises STDC_UNUSED and
   knows the arg. is actually unused, for which applying UNUSED_ARG() would 
   lead to a warning about an unused arg. being used */

#define UNUSED_ARG( arg )		( ( arg ) = ( arg ) )
#ifdef HAS_STDC_UNUSED
  #define UNUSED_ARG_OPT( arg )
#else
  #define UNUSED_ARG_OPT( arg )	( ( arg ) = ( arg ) )
#endif /* HAS_STDC_UNUSED */

/* Although min() and max() aren't in the ANSI standard, most compilers have
   them in one form or another, but just enough don't that we need to define 
   them ourselves in some cases */

#if !defined( min )
  #ifdef MIN
	#define min			MIN
	#define max			MAX
  #else
	#define min( a, b )	( ( ( a ) < ( b ) ) ? ( a ) : ( b ) )
	#define max( a, b )	( ( ( a ) > ( b ) ) ? ( a ) : ( b ) )
  #endif /* Various min/max macros */
#endif /* !min/max */

/* Macros to convert to and from the bit counts used for some encryption
   parameters */

#define bitsToBytes( bits )			( ( ( bits ) + 7 ) >> 3 )
#define bytesToBits( bytes )		( ( bytes ) << 3 )

/* When initialising a static block of bytes, it's useful to be able to 
   specify it as a character string, however this runs into problems with
   the fact that the default char type is signed.  To get around this the
   following macro declares a byte string as a set of unsigned bytes */

#define MKDATA( x )					( ( BYTE * ) ( x ) )

/* Macro to round a value up to the nearest multiple of a second value,
   with the second value being a power of 2 */

#define roundUp( size, roundSize ) \
	( ( ( size ) + ( ( roundSize ) - 1 ) ) & ~( ( roundSize ) - 1 ) )

/* A macro to clear sensitive data from memory.  This is somewhat easier to
   use than calling memset with the second parameter set to 0 all the time,
   and makes it obvious where sensitive data is being erased.  In addition
   some systems, recognising the problem of compilers removing what they see
   as dead stores, have distinct memory zeroisation support, so if available 
   we use that */

#if defined( _MSC_VER ) && VC_GE_2005( _MSC_VER )
  /* This is just a mapping to RtlSecureZeroMemory() (via WinBase.h) which 
     is implemented as inline code implementing a loop on a pointer declared 
	 volatile, but unlike the corresponding RtlZeroMemory() there's a 
	 contract that this will always zeroise memory even in the face of 
	 compiler changes that would otherwise optimise away the access */
  #define zeroise( memory, size )	SecureZeroMemory( memory, size )
#elif defined( __STDC_LIB_EXT1__ )
  /* C11 defines a function memset_s() that guarantees that it won't be
	 optimised away, although this is quite well obfuscated in the spec,
	 "the memory indicated by [the memset parameters] may be accessible in 
	 the future and therefore must contain the values indicated by [the
	 value to set]", hopefully the implementers will know that this equates
	 to "the memset_s() call can't be optimised away" */
  #define zeroise( memory, size )	memset_s( memory, size, 0, size )
#elif defined( __OpenBSD__ )
  /* The OpenBSD folks defined their own won't-be-optimised-away bzero()
	 function */
  #define zeroise( memory, size )	explicit_bzero( memory, size )
#else
  #define zeroise( memory, size )	memset( memory, 0, size )
#endif /* Systems with distinct zeroise functions */

/* A macro to check that a value is a possibly valid handle.  This doesn't
   check that the handle refers to a valid object, merely that the value is
   in the range for valid handles.  The full function isValidHandle() used
   in the kernel does check that the handle refers to a valid object, being
   more than just a range check */

#define isHandleRangeValid( handle ) \
		( ( handle ) > NO_SYSTEM_OBJECTS - 1 && ( handle ) < MAX_NO_OBJECTS )

/* A macro to check whether an encryption mode needs an IV or not */

#define needsIV( mode ) \
		( ( mode ) == CRYPT_MODE_CBC || ( mode ) == CRYPT_MODE_CFB || \
		  ( mode ) == CRYPT_MODE_GCM )

/* A macro to check whether an algorithm is a pure stream cipher (that is,
   a real stream cipher rather than just a block cipher run in a stream
   mode) */

#define isStreamCipher( algorithm ) \
		( ( algorithm ) == CRYPT_ALGO_RC4 )

/* Some stream ciphers are actually block ciphers pretending to be stream
   ciphers, which means that although they can produce byte-oriented 
   output they still need an IV.  The following macro checks for these
   special snowflakes */

#define isSpecialStreamCipher( algorithm ) \
		( ( algorithm ) == CRYPT_ALGO_CHACHA20 )

/* A macro to check whether an algorithm is regarded as being (relatively)
   insecure or not.  This is used by some of the higher-level internal
   routines that normally use the default algorithm set in the configuration
   database if nothing else is explicitly specified, but that specifically
   check for the weaker algorithms and use something stronger instead if a
   weak algorithm is specified.  This is done both for luser-proofing and to
   avoid possible problems from a trojan patching the configuration
   database */

#define isWeakCryptAlgo( algorithm )	( ( algorithm ) == CRYPT_ALGO_DES || \
										  ( algorithm ) == CRYPT_ALGO_RC2 || \
										  ( algorithm ) == CRYPT_ALGO_RC4 )
#define isWeakHashAlgo( algorithm )		( ( algorithm ) == CRYPT_ALGO_MD5 )
#define isWeakMacAlgo( algorithm )		( 0 )
										/* None left with HMAC-MD5 deprecated */

/* Macros to check for membership in overall algorithm classes */

#define isConvAlgo( algorithm ) \
		( ( algorithm ) >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		  ( algorithm ) <= CRYPT_ALGO_LAST_CONVENTIONAL )
#define isPkcAlgo( algorithm ) \
		( ( algorithm ) >= CRYPT_ALGO_FIRST_PKC && \
		  ( algorithm ) <= CRYPT_ALGO_LAST_PKC )
#define isHashAlgo( algorithm ) \
		( ( algorithm ) >= CRYPT_ALGO_FIRST_HASH && \
		  ( algorithm ) <= CRYPT_ALGO_LAST_HASH )
#define isMacAlgo( algorithm ) \
		( ( algorithm ) >= CRYPT_ALGO_FIRST_MAC && \
		  ( algorithm ) <= CRYPT_ALGO_LAST_MAC )
#define isSpecialAlgo( algorithm ) \
		( ( algorithm ) == CRYPT_IALGO_GENERIC_SECRET )

/* Macros to check whether a PKC algorithm is useful for a certain purpose 
   or requires special-case handling.  Note that isDlpAlgo() doesn't include 
   the ECC algorithms, which are also based on the DLP (although in this 
   case the ECDLP and not the standard DLP).  This is a bit ugly but it's 
   used in various places to distinguish DLP-based PKCs from non-DLP-based
   PKCs, while ECDLP-based-PKCs are in a separate class.  This means that
   when checking for the extended class { DLP | ECDLP } it's necessary to
   explicitly include isEccAlgo() alongside isDlpAlgo() */

#define isSigAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_DSA || \
	  ( algorithm ) == CRYPT_ALGO_ECDSA || ( algorithm ) == CRYPT_ALGO_EDDSA )
#define isCryptAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_ELGAMAL )
#define isKeyexAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_DH || ( algorithm ) == CRYPT_ALGO_ECDH || \
	  ( algorithm ) == CRYPT_ALGO_25519 )
#define isDlpAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_DSA || ( algorithm ) == CRYPT_ALGO_ELGAMAL || \
	  ( algorithm ) == CRYPT_ALGO_DH )
#define isEccAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_ECDSA || ( algorithm ) == CRYPT_ALGO_ECDH || \
	  ( algorithm ) == CRYPT_ALGO_EDDSA || ( algorithm ) == CRYPT_ALGO_25519 )

/* Macros to check whether an algorithm has additional parameters that need 
   to be handled explicitly */

#define isParameterisedConvAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_AES )
#define isParameterisedHashAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_SHA2 || ( algorithm ) == CRYPT_ALGO_SHAng )
#define isParameterisedMacAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_HMAC_SHA2 || \
	  ( algorithm ) == CRYPT_ALGO_HMAC_SHAng )

/* A macro to check whether an error status is related to a data-formatting
   problem or some other problem.  This is used to provide extended string-
   format error information, if it's a data error then the message being
   processed was (probably) invalid, if it's not a data error then it may be
   due to an invalid decryption key being used or something similar that's
   unrelated to the message itself.
   
   The exact definition of what constitutes a "data error" is a bit vague 
   but since it's only used to control what additional error information is
   returned a certain level of fuzziness is permitted */

#define isDataError( status ) \
		( ( status ) == CRYPT_ERROR_OVERFLOW || \
		  ( status ) == CRYPT_ERROR_UNDERFLOW || \
		  ( status ) == CRYPT_ERROR_BADDATA || \
		  ( status ) == CRYPT_ERROR_SIGNATURE || \
		  ( status ) == CRYPT_ERROR_NOTAVAIL || \
		  ( status ) == CRYPT_ERROR_INCOMPLETE || \
		  ( status ) == CRYPT_ERROR_COMPLETE || \
		  ( status ) == CRYPT_ERROR_INVALID )

/* A macro to check whether a public key is too short to be secure.  This
   is a bit more complex than just a range check because any length below 
   about 512 bits is probably a bad data error, while lengths from about
   512 bits to MIN_PKCSIZE (for standard PKCs) or 120 bits to 
   MIN_PKCSIZE_ECC are too-short key errors */

#define isShortPKCKey( keySize ) \
		( ( keySize ) >= MIN_PKCSIZE_THRESHOLD && \
		  ( keySize ) < MIN_PKCSIZE )
#define isShortECCKey( keySize ) \
		( ( keySize ) >= MIN_PKCSIZE_ECC_THRESHOLD && \
		  ( keySize ) < MIN_PKCSIZE_ECC )

/* To avoid problems with signs, for example due to (signed) characters
   being potentially converted to large signed integer values we perform a
   safe conversion by going via an intermediate unsigned value, which in
   the case of char -> int results in 0xFF turning into 0x000000FF rather
   than 0xFFFFFFFF.
   
   For Visual Studio we explicitly mask some values to avoid runtime traps 
   in debug builds */

#define byteToInt( x )				( ( int ) ( ( unsigned char ) ( x ) ) )
#define intToLong( x )				( ( unsigned int ) ( x ) )

#define sizeToInt( x )				( ( unsigned int ) ( x ) )
#if defined( _MSC_VER ) && VC_GE_2010( _MSC_VER )
  #define intToByte( x )			( ( unsigned char ) ( ( x ) & 0xFF ) )
#else
  #define intToByte( x )			( ( unsigned char ) ( x ) )
#endif /* VS 2010 or newer */

/* Clear/set object error information */

#define clearObjectErrorInfo( objectInfoPtr ) \
	{ \
	( objectInfoPtr )->errorLocus = CRYPT_ATTRIBUTE_NONE; \
	( objectInfoPtr )->errorType = CRYPT_OK; \
	}

#define setObjectErrorInfo( objectInfoPtr, locus, type ) \
	{ \
	( objectInfoPtr )->errorLocus = locus; \
	( objectInfoPtr )->errorType = type; \
	}

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Pull in the internal API function definitions and prototypes */

#if defined( INC_ALL )
  #include "safety.h"		/* Must be before int_api.h for safe pointers */
  #include "int_api.h"
  #include "list.h"
#else
  #include "misc/safety.h"	/* Must be before int_api.h for safe pointers */
  #include "misc/int_api.h"
  #include "misc/list.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Debugging Functions							*
*																			*
****************************************************************************/

/* Pull in the debugging function definitions and prototypes */

#if defined( INC_ALL )
  #include "debug.h"
  #include "fault.h"
#else
  #include "misc/debug.h"
  #include "misc/fault.h"
#endif /* Compiler-specific includes */

#endif /* _CRYPT_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
