/****************************************************************************
*																			*
*				cryptlib Data Size and Crypto-related Constants 			*
*						Copyright Peter Gutmann 1992-2021					*
*																			*
****************************************************************************/

#ifndef _CONSTS_DEFINED

#define _CONSTS_DEFINED

/****************************************************************************
*																			*
*								Crypto Constants							*
*																			*
****************************************************************************/

/* The size of a cryptlib key ID, a SHA-1 hash of the SubjectPublicKeyInfo,
   and the PGP key ID */

#define KEYID_SIZE				20
#define	PGP_KEYID_SIZE			8

/* The minimum and maximum private key data size.  This is used when
   buffering the encrypted private key from a keyset during decryption and
   is equal to the overall size of the total number of possible PKC
   parameters in an encryption context, plus a little extra for encoding and
   encryption */

#define MIN_PRIVATE_KEYSIZE		18	/* For DLP keys */
#define MAX_PRIVATE_KEYSIZE		( ( CRYPT_MAX_PKCSIZE * 8 ) + 256 )

/* The minimum and maximum working conventional key size.  In order to avoid
   problems with space inside PKC-encrypted blocks when MIN_PKCSIZE is less
   than 1024 bits, we limit the total keysize to 256 bits, which is adequate
   for all purposes - the limiting factor is AES-256 */

#ifdef USE_DES
  #define MIN_KEYSIZE			bitsToBytes( 64 )
#else
  #define MIN_KEYSIZE			bitsToBytes( 80 )
#endif /* USE_DES */
#define MAX_WORKING_KEYSIZE		bitsToBytes( 256 )

/* The minimum IV size */

#define MIN_IVSIZE				bitsToBytes( 64 )

/* The minimum public key size (c.f. CRYPT_MAX_PKCSIZE).  This is a bit less
   than the actual size because keygen specifics can lead to keys that are
   slightly shorter than the nominal size, and signatures and wrapped keys
   can also be shorter (1/256 will be one byte shorter, 1/64K will be two
   bytes shorter, and so on).  In addition we have to have a special value
   for ECC keys, for which key sizes work differently that conventional
   PKCs */

#define MIN_PKCSIZE				( bitsToBytes( 1024 ) - 2 )
#define MIN_PKCSIZE_ECC			( bitsToBytes( 256 ) - 2 )

/* When we read a public key, a value that's too short to be even vaguely
   sensible is reported as CRYPT_ERROR_BADDATA, but if it's at least
   vaguely sensible but too short to be secure it's reported as
   CRYPT_ERROR_NOSECURE.  The following value defines the cutoff point
   between "obviously invalid" and "theoretically valid but not secure",
   so that 0...MIN_PKCSIZE_THRESHOLD - 1 is rejected with
   CRYPT_ERROR_BADDATA, MIN_PKCSIZE_THRESHOLD... MIN_PKCSIZE - 1 is rejected
   with CRYPT_ERROR_NOSECURE, and MIN_PKCSIZE...CRYPT_MAX_PKCSIZE is
   accepted */

#define MIN_PKCSIZE_THRESHOLD	( bitsToBytes( 504 ) )
#define MIN_PKCSIZE_ECC_THRESHOLD ( bitsToBytes( 120 ) )

/* ECC points present special problems of their own since they're encoded
   by stuffing them into byte strings with a type indicator at the start
   which leads to a length that bears no relation to the actual key size */

#define MIN_PKCSIZE_ECCPOINT	( 1 + ( MIN_PKCSIZE_ECC * 2 ) )
#define MIN_PKCSIZE_ECCPOINT_THRESHOLD \
								( 1 + ( MIN_PKCSIZE_ECC_THRESHOLD * 2 ) )
#define MAX_PKCSIZE_ECCPOINT	( 1 + ( CRYPT_MAX_PKCSIZE_ECC * 2 ) )

/* The Bernstein ECCs are yet another special case since they only use the 
   X coordinate (via point compression), for which the smallest curve is
   25519 with 32 bytes */

#define MIN_PKCSIZE_BERNSTEIN	32
#define MAX_PKCSIZE_BERNSTEIN	32

/* The minimum hash/MAC size */

#define MIN_HASHSIZE			16

/* The size of the largest public-key wrapped value, corresponding to an
   ASN.1-encoded Elgamal-encrypted key.  If we're not using Elgamal it's
   the same as CRYPT_MAX_PKCSIZE */

#ifdef USE_ELGAMAL
  #define MAX_PKCENCRYPTED_SIZE	( 16 + ( CRYPT_MAX_PKCSIZE * 2 ) )
#else
  #define MAX_PKCENCRYPTED_SIZE	CRYPT_MAX_PKCSIZE
#endif /* USE_ELGAMAL */

/* The maximum public-key object size.  This is used to allocate temporary
   buffers when working with signatures and PKC-encrypted keys.  The size
   estimate is somewhat crude and involves a fair safety margin, it usually
   contains a single PKC object (signature or encrypted key) along with
   algorithm and key ID information */

#define MAX_PKC_OBJECTSIZE		( CRYPT_MAX_PKCSIZE * 2 )

/* The minimum size of an encoded signature or exported key object.  This is
   used by the pointer-check macros (for the OSes that support this) to
   check that the pointers to objects that are passed to functions point to
   the minimal amount of valid memory required for an object, and also to
   zero the buffer for the object to ensure that the caller gets invalid
   data if the function fails.  Objects must be >= MIN_CRYPT_OBJECTSIZE */

#define MIN_CRYPT_OBJECTSIZE	64

/* The maximum number of iterations that we allow for an iterated key setup
   such as a hashed password.  This is used to prevent DoS attacks from data
   containing excessive iteration counts.

   The best value to use here is difficult to determine, see the comment
   below about PGP S2K issues, and in particular we don't want to have
   older/less capable systems grind to a halt processing excessive iteration
   counts while it doesn't really matter so much for newer ones.  Taking
   newer = 64-bit, we specify a much more generous upper bound for 64-bit
   systems.  The somewhat odd bound of 55000L if PKCS #12 is enabled is to
   deal with OpenSSL-created PKCS #12 files which default to 51200
   iterations */

#if defined( SYSTEM_64BIT )
  #define MAX_KEYSETUP_ITERATIONS	min( INT_MAX - 256, 100000L )
#elif defined( USE_PKCS12 )
  #define MAX_KEYSETUP_ITERATIONS	min( INT_MAX - 256, 55000L )
#else
  #define MAX_KEYSETUP_ITERATIONS	min( INT_MAX - 256, 50000L )
#endif /* SYSTEM_64BIT */

/* PGP's S2K uses a bizarre processing-complexity specifier that specifies,
   in a very roundabout manner, the number of bytes hashed rather than the
   iteration count.  In addition a number of PGP implementations specify
   ridiculous levels of hashing that make them more akin to a DoS attack
   than any legitimate security measure.  In theory we could recalculate the
   above define for an assumption of an 8-byte hash salt and and 8-byte
   password to get a value of ( ( MAX_KEYSETUP_ITERATIONS * 16 ) / 64 ),
   with the '/ 64' term being present because what's specified is the value
   without an additional * 64 multiplier that's added by the S2K mechanism
   code, so we divide by 64 to account for this later scaling.

   However in 2011 GPG raised its default hash specifier count from the
   GPG 1.x standard of 64K to over 2M (while still defaulting to the 15-
   year-old CAST5 for its block cipher, so it may use an obsolete 64-bit
   crypto algorithm but at least it iterates the password hashing enough to
   perform a DoS on anyone with an older machine) and some configurations go
   even further and set it at 3,407,872.  Then at some point in 2017 the
   Kleopatra GPG front-end raised the stakes even further with a value of
   3,932,160, and then some time early in 2018 to 6,815,744 (all of these
   values appear to be arbitrary, with or without the * 64 multiplier they
   have no obvious significance).

   In addition to GPG's constantly-changing behaviour, PGP Desktop 9
   (apparently) in its default config uses values up to 4M, and there's a
   mutant GPG build used with loop-AES that uses 8M setup iterations for PGP
   private keys.  Why this is used and why it writes PGP keys with this
   setting is uncertain.

   The more extreme GPG iteration-count settings seem to be OS-specific
   fashion statements, Centos 8.4 has 39,845,888, Fedora has 58,720,256,
   and Ubuntu goes all the way to 65,011,712, corresponding to a coded count
   of 0xFF, the highest that it's possible to set (see below).

   Unfortunately with these ludicrous-speed iteration counts there's no way
   to ensure any protection against DoS attacks due to such ridiculously
   high iteration counts.  What eventually saves us is that it's physically
   impossible to encode more than 65M iterations, since the encoding is
   poked into a single byte, defined as:

	count = (16 + (c & 15)) << ((c >> 4) + EXPBIAS);

   where c is an 8-bit value and EXPBIAS is 6.  This then evaluates to:

	= (16 + (0x0F)) << ((0xF0 >> 4) + EXPBIAS);
	= 31 << (15 + EXPBIAS);
	= 31 << 21
	= 65,011,712

   which means that we can see counts close to 2^26, working out to
   1,015,808 with the / 64 factor taken into account */

#define MAX_KEYSETUP_HASHSPECIFIER	min( INT_MAX - 256, ( 65011712L / 64 ) )

/* The HMAC input and output padding values.  These are defined here rather
   than in context.h because they're needed by some PRF mechanisms that
   synthesise HMAC operations from low-level hash operations */

#define HMAC_IPAD				0x36
#define HMAC_OPAD				0x5C

/* The default encryption, hash, and MAC algorithms, representing an
   always-available algorithm type

   Alongside the algorithm type define, we also need to define symbolic
   values that indicate which option is in use, since the preprocessor
   can't evaluate the enums used to identify the algorithm type */

#if defined( USE_AES )
  #define DEFAULT_CRYPT_ALGO	CRYPT_ALGO_AES
  #define DEFAULT_ALGO_AES
#elif defined( USE_3DES )
  #define DEFAULT_CRYPT_ALGO	CRYPT_ALGO_3DES
  #define DEFAULT_ALGO_3DES
#else
  #error Either 3DES or AES must be enabled as the default encryption algorithm
#endif /* Default encryption algorithm */
#define DEFAULT_HASH_ALGO		CRYPT_ALGO_SHA2
#define DEFAULT_HASH_PARAM		32
#define DEFAULT_MAC_ALGO		CRYPT_ALGO_HMAC_SHA2
#define DEFAULT_MAC_PARAM		32
#define DEFAULT_ALGO_SHA2

/****************************************************************************
*																			*
*								Data Size Constants							*
*																			*
****************************************************************************/

/* The maximum length that can be safely handled using an integer.  We don't
   quite allow the maximum possible length since most data/message formats
   impose some extra overhead themselves, this means that we can, for 
   example, do something like sizeofObject() + small extra data values
   without risk of overflowing the calculation.

   In addition to the maximum-possible length we also define a shorter
   length defined as a generally sensible upper bound for values that
   shouldn't require arbitrary-length data quantities */

#ifdef SYSTEM_16BIT
  #define MAX_INTLENGTH_DELTA	8192
#else
  #define MAX_INTLENGTH_DELTA	1048576
#endif /* 16- vs. 32/64-bit systems */
#define MAX_INTLENGTH			( INT_MAX - MAX_INTLENGTH_DELTA )
#define MAX_INTLENGTH_SHORT		16384

/* The minimum size of a certificate.  The Bernstein algorithms combined with
   PKCS #10 certificate requests can result in unusually small objects so we
   allow shorter-than-normal sizes if they're being used */

#if defined( USE_25519 ) || defined( USE_ED25519 )
  #define MIN_CERTSIZE			200
#else
  #define MIN_CERTSIZE			256
#endif /* USE_25519 || USE_ED25519 */

/* The maximum size of an object attribute.  In theory this can be any size,
   but in practice we limit it to the following maximum to stop people
   creating things like certs containing MPEGs of themselves playing with
   their cat */

#define MAX_ATTRIBUTE_SIZE		1024

/* Some objects contain internal buffers used to process data whose size can
   be specified by the user, the following is the minimum and maximum size
   allowed for these buffers.  We don't use MAX_INTLENGTH for this both
   because it's a peculiarly high value (using all addressable memory as a
   buffer is a bit odd) and because using a fraction of the full INT_MAX
   range makes it safe to perform range-based comparisons, 'value1 +
   value2 < value3', without the risk of integer overflow */

#define MIN_BUFFER_SIZE			8192
#define MAX_BUFFER_SIZE			( INT_MAX / 8 )

/* The minimum allowed length for (typically human-readable) object names
   (keysets, devices, users, etc).  In theory this could be a single
   character, but by default we make it 2 chars to make things more
   resistant to off-by-one errors in lengths, particularly since it applies
   to external objects outside cryptlib's control.  Alongside this we also
   define a minimum length for generic binary IDs */

#ifdef UNICODE_CHARS
  #define MIN_NAME_LENGTH		( 2 * sizeof( wchar_t ) )
#else
  #define MIN_NAME_LENGTH		2
#endif /* Unicode vs. ASCII environments */
#define MIN_ID_LENGTH			2

/* The minimum and maximum size of various Internet-related values, used for
   range checking.  Note that there's one exception to MIN_DNS_SIZE which is
   "::1", however there are only two places where we can encounter this, in 
   IPv6 loopback tests when reading the TLS SNI in 
   session/tls_ext.c:readSNI() and when parsing URLs in 
   io/net_url.c:parseURL() and the accompanying sanity-check function, which 
   special-case the length value there */

#define MIN_DNS_SIZE			5			/* x.com */
#define MAX_DNS_SIZE			255			/* Max hostname size */
#define MIN_RFC822_SIZE			7			/* x@yy.zz */
#define MAX_RFC822_SIZE			255
#define MIN_URL_SIZE			12			/* http://x.com */
#define MAX_URL_SIZE			MAX_DNS_SIZE

/* The minimum and maximum size of various ASN.1-related values */

#define MIN_ASCII_OIDSIZE		7

/* Some object types interact with exteral services that can return detailed
   error messages when problems occur, the following is the maximum length
   error string that we store.  Anything beyond this size is truncated */

#define MAX_ERRMSG_SIZE			512

/****************************************************************************
*																			*
*							Miscellaneous Constants							*
*																			*
****************************************************************************/

/* Various time values:

	MIN_TIME_VALUE: The minimum time value that's regarded as being a valid
		time.  We have to allow dates slightly before the current time
		because of things like backdated certificate revocations, as a rule
		of thumb we allow a date up to two years in the past.

	MIN_STORED_TIME_VALUE: A somewhat more relaxed minimum time value used
		when reading stored data like private keys, which can contain
		associated certificates that have been hanging around for years.

	MAX_TIME_VALUE: The maximum time value that we can safely use while
		avoiding the Y2038 problem.  This issue only affects systens with
		a 32-bit time_t so we only clip the time value on those systems.

	CURRENT_TIME_VALUE: An approximation of the current time with the
		constraint that it's not after the current date.  Unfortunately we
		can't use any preprocessor macros for this since __DATE__ and
		__TIME__ are text strings rather than timestamps so we have to
		build it the hard way from the __DATE__ value, which ANSI defines as
		"Mmm dd yyyy" with a space inserted if dd is less than 10.  The year
		is relatively straightforward, the month is more complicated.  We
		perform a match on the third letter of the month name, which has the
		least collisions, and then disambiguate between Jan/Jun and Mar/Apr
		to select the month days from a cumulative count of 31, 28, 31, 30,
		31, 30, 31, 31, 30, 31, 30, 31, which is 0, 31, 59, 90, 120, 151,
		181, 212, 243, 273, 304, 334, (365).  We ignore leap years since
		it's only a single day and all we need is an approximate date, and
		we backdate the calculated date by one month to deal with leap-year
		rounding errors.

		Note that some compilers aren't tough enough to evaluate this at
		compile time so we whitelist the compilers that can handle it and
		for all others use an approximation.  In particular no version of
		VC++ up to 2019 can handle it and different versions of gcc seem to
		handle or not handle it at random for version 6 and above.

		Also the calculation is typically done by the compiler rather than
		the preprocessor so using it in the code works but using it in a
		preprocessor expression, "#if CURRENT_TIME_VALUE < xxx", doesn't */

#define DATE_YEAR \
		( ( __DATE__[ 7 ] == '?' ? ( 2020 - 1970 ) : \
			( ( ( __DATE__[  7 ] - '0' ) * 1000 ) + \
			  ( ( __DATE__[  8 ] - '0' ) * 100 ) + \
			  ( ( __DATE__[  9 ] - '0' ) * 10 ) + \
				( __DATE__[ 10 ] - '0' ) ) - 1970 ) * 365 )

#define DATE_MONTH \
		( __DATE__[ 2 ] == "Jan"[ 2 ] ? \
		  	( __DATE__[ 1 ] == "Jan"[ 1 ] ? 0 : 151 ) : \
		  __DATE__[ 2 ] == "Feb"[ 2 ] ? 31 : \
		  __DATE__[ 2 ] == "Mar"[ 2 ] ? \
		  	( __DATE__[ 1 ] == "Mar"[ 1 ] ? 59 : 90 ) : \
		  __DATE__[ 2 ] == "May"[ 2 ] ? 120 : \
		  __DATE__[ 2 ] == "Jul"[ 2 ] ? 181 : \
		  __DATE__[ 2 ] == "Aug"[ 2 ] ? 212 : \
		  __DATE__[ 2 ] == "Sep"[ 2 ] ? 243 : \
		  __DATE__[ 2 ] == "Oct"[ 2 ] ? 273 : \
		  __DATE__[ 2 ] == "Nov"[ 2 ] ? 304 : \
		  __DATE__[ 2 ] == "Dec"[ 2 ] ? 334 : 0 )

#define DATE_DAY \
		( __DATE__[ 4 ] == '?' ? 0 : \
		  ( ( __DATE__[ 4 ] == ' ' ) ? \
		  	( __DATE__[ 5 ] - '0' ) : \
		  	( ( ( __DATE__[ 4 ] - '0' ) * 10 ) + __DATE__[ 5 ] - '0' ) ) )

#ifdef SYSTEM_64BIT
  #define YEARS_TO_SECONDS( years ) ( ( years ) * 365 * 86400LL )
#else
  #define YEARS_TO_SECONDS( years ) ( ( years ) * 365 * 86400UL )
#endif /* 64- vs. 32-bit systems */
#define MIN_TIME_VALUE			( CURRENT_TIME_VALUE - YEARS_TO_SECONDS( 2 ) )
#define MIN_STORED_TIME_VALUE	( YEARS_TO_SECONDS( 1995 - 1970 ) )
#define MAX_TIME_VALUE_Y2038	( YEARS_TO_SECONDS( 2036 - 1970 ) )
#ifdef SYSTEM_64BIT
  #define MAX_TIME_VALUE		( YEARS_TO_SECONDS( 2100 - 1970 ) )
#else
  #define MAX_TIME_VALUE		MAX_TIME_VALUE_Y2038
#endif /* 64- vs. 32-bit systems */

#if defined( __clang__ ) && ( __clang_major__ > 5 ) && \
	( !defined( __apple_build_version__ ) || \
	  ( __apple_build_version__ >= 8000000 ) )
  /* Apple's mutant clang fork reports the Xcode version as the clang
	 version, thus inflating the apparent version number, so we have to add
	 an explicit check for this and base use on an approximate mapping from
	 Xcode to clang releases */
  #define CURRENT_TIME_VALUE	( ( DATE_YEAR + DATE_MONTH - 30 ) * 86400UL )
#elif defined( __GNUC__ ) && ( __GNUC__ > 7 )
  #define CURRENT_TIME_VALUE	( ( DATE_YEAR + DATE_MONTH - 30 ) * 86400UL )
#else
  #define CURRENT_TIME_VALUE	( YEARS_TO_SECONDS( 2021 - 1970 ) )
  #define CHECK_CURRENT_TIME
#endif /* Compilers that aren't tough enough for the above */

/* Check that there are no (obvious) under- or overflows in the time
   constant calculations.  We explicitly check for the value going negative
   alongside the general range check just to make it obvious.  The two
   constants are a value less then MAX_TIME_VALUE_Y2038 for the
   MAX_TIME_VALUE check and 1/1/2020 for the CURRENT_TIME_VALUE check.

   Since the CURRENT_TIME_VALUE when calcuated via __DATE__ requires the
   compiler rather than the preprocessor, we only perform the check if
   we're using the preprocessor-safe derivation of CURRENT_TIME_VALUE.
   This is OK because the place where overflow is likely to occur is with
   MAX_TIME_VALUE, not CURRENT_TIME_VALUE, it's merely a belt-and-
   suspenders check */

#if ( MAX_TIME_VALUE < 0 ) || ( MAX_TIME_VALUE < 0x7C000000 )
  #error Overflow/underflow in MAX_TIME_VALUE calculation
#endif /* Range check for MAX_TIME_VALUE calculation */
#ifdef CHECK_CURRENT_TIME
  #undef CHECK_CURRENT_TIME
  #if ( CURRENT_TIME_VALUE < 0 ) || ( CURRENT_TIME_VALUE < 0x5DFC0F00L )
	#error Overflow/underflow in CURRENT_TIME_VALUE calculation
  #endif /* Range check for CURRENT_TIME_VALUE calculation */
#endif /* CHECK_CURRENT_TIME */

/* The minimum and maximum network port numbers.  Note that we allow ports
   down to 21 (= FTP) rather than the more obvious 22 (= SSH) provided by
   cryptlib sessions because the URL-handling code is also used for general-
   purpose URI parsing for which the lowest-numbered one that we'd normally
   run into is FTP.  For desitnation ports we set the upper bound at the end
   of the non-ephemeral port range, 49152-65535 is for ephemeral source
   ports that are only valid for the duration of a TCP session */

#define MIN_PORT_NUMBER			21
#define MAX_DEST_PORT_NUMBER	49151L
#define MAX_SRC_PORT_NUMBER		65534L

/* The maximum certificate compliance level */

#if defined( USE_CERTLEVEL_PKIX_FULL )
  #define MAX_COMPLIANCE_LEVEL	CRYPT_COMPLIANCELEVEL_PKIX_FULL
#elif defined( USE_CERTLEVEL_PKIX_PARTIAL )
  #define MAX_COMPLIANCE_LEVEL	CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL
#else
  #define MAX_COMPLIANCE_LEVEL	CRYPT_COMPLIANCELEVEL_STANDARD
#endif /* Maximum compliance level */

/* The maximum network read/write timeout, in seconds */

#define MAX_NETWORK_TIMEOUT		300

/* Generic error return code/invalid value code */

#define CRYPT_ERROR				-1

/* Sometimes compilers get confused about whether a variable has been
   initialised or not and report a used-before-initialised error when there
   isn't one.  This happens most frequently when the variable is initialised
   as part of a conditional expression where the developer knows the control
   flow will result in an initialisation but the compiler doesn't.  To get
   around this we perform a dummy initialisation of the variable with a
   symbolic value to get rid of the false positive */

#define DUMMY_INIT				= 0
#define DUMMY_INIT_PTR			= NULL
#define DUMMY_INIT_STRUCT		= { 0 }

/* A special return code to indicate that everything went OK but there's
   some special action to perform.  This is generally used when a lower-level
   routine wants to return a CRYPT_OK with some condition attached, typically
   that the calling routine not update state information since it's already
   been done by the returning routine or because the returning routine has
   more work to do on a later call.  The parentheses are to catch potential
   erroneous use in an expression */

#define OK_SPECIAL				( -123 )

/* When parameters get passed in messages, their mapping to parameters passed
   to the calling function gets lost.  The following error codes are used to
   denote errors in message parameters that are mapped to function parameter
   error codes by the caller.  For a message call:

	krnlSendMessage( object, {args}, MESSAGE_TYPE, value );

   we have the following possible error codes.  The parentheses are to catch
   potential erroneous use in an expression */

#define CRYPT_ARGERROR_OBJECT	( -100 )	/* Error in object being sent msg.*/
#define CRYPT_ARGERROR_VALUE	( -101 )	/* Error in message value */
#define CRYPT_ARGERROR_STR1		( -102 )	/* Error in first string arg */
#define CRYPT_ARGERROR_STR2		( -103 )	/* Error in second string arg */
#define CRYPT_ARGERROR_NUM1		( -104 )	/* Error in first numeric arg */
#define CRYPT_ARGERROR_NUM2		( -105 )	/* Error in second numeric arg */

#define cryptArgError( status )	\
		( ( status ) >= CRYPT_ARGERROR_NUM2 && ( status ) <= CRYPT_ARGERROR_OBJECT )
#define cryptStandardError( status ) \
		( ( status ) >= CRYPT_ENVELOPE_RESOURCE && ( status ) <= CRYPT_OK )
#define cryptParamError( status ) \
		( ( status ) >= CRYPT_ERROR_PARAM7 && ( status ) <= CRYPT_ERROR_PARAM1 )

/* Network I/O is government by all sorts of timeouts.  The following are
   the default timeout values used for network I/O, unless overridden by the
   user */

#define	NET_TIMEOUT_CONNECT		30
#define NET_TIMEOUT_READ		15
#define NET_TIMEOUT_WRITE		5

/* The data formats for reading/writing public keys */

typedef enum {
	KEYFORMAT_NONE,		/* No key format */
	KEYFORMAT_CERT,		/* X.509 SubjectPublicKeyInfo */
	KEYFORMAT_SSH,		/* SSHv2 public key */
	KEYFORMAT_TLS,		/* TLS public key */
	KEYFORMAT_TLS_EXT,	/* TLS extended public key */
	KEYFORMAT_PGP,		/* PGP public key */
	KEYFORMAT_PRIVATE,	/* Private key */
	KEYFORMAT_PRIVATE_EXT,	/* Private key with pubkey crypto binding */
	KEYFORMAT_PRIVATE_OLD,	/* Older format for backwards-compatibility */
	KEYFORMAT_LAST		/* Last possible key format type */
	} KEYFORMAT_TYPE;

/* The different types of actions that can be signalled to the management
   function for each object class.  This instructs the management function
   to initialise or shut down any object-class-specific information that it
   may maintain.

   Init actions are split into two classes, standard and deferred.  This
   distinction is necessary because some initialisation actions such as
   driver binding may be performed asychronously, so we need to distinguish
   between init actions that need to be performed sychronously and ones that
   can be performed asynchronously */

typedef enum {
	MANAGEMENT_ACTION_NONE,				/* No management action */
	MANAGEMENT_ACTION_PRE_INIT,			/* Pre-initialisation */
	MANAGEMENT_ACTION_INIT,				/* Initialisation */
	MANAGEMENT_ACTION_INIT_DEFERRED,	/* Initialisation, possibly asynchronous */
	MANAGEMENT_ACTION_PRE_SHUTDOWN,		/* Pre-shutdown */
	MANAGEMENT_ACTION_SHUTDOWN,			/* Shutdown */
	MANAGEMENT_ACTION_LAST				/* Last possible management action */
	} MANAGEMENT_ACTION_TYPE;

/* Certificate key usage types.  SIGN is for data signing and CA is for
   certificate signing.  we don't include CRYPT_KEYUSAGE_DATAENCIPHERMENT in
   KEYUSAGE_CRYPT since this is more or less never what's actually meant */

#define KEYUSAGE_SIGN			( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
								  CRYPT_KEYUSAGE_NONREPUDIATION )
#define KEYUSAGE_CA				( CRYPT_KEYUSAGE_KEYCERTSIGN | \
								  CRYPT_KEYUSAGE_CRLSIGN )
#define KEYUSAGE_CRYPT			( CRYPT_KEYUSAGE_KEYENCIPHERMENT )
#define KEYUSAGE_KEYAGREEMENT	( CRYPT_KEYUSAGE_KEYAGREEMENT | \
								  CRYPT_KEYUSAGE_ENCIPHERONLY | \
								  CRYPT_KEYUSAGE_DECIPHERONLY )

#endif /* _CONSTS_DEFINED */
