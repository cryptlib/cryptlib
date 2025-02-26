/****************************************************************************
*																			*
*						cryptlib Microsoft Crypto Code						*
*						Copyright Peter Gutmann 2016-2023					*
*																			*
****************************************************************************/

/* This module implements the garbled muddle of crypto and hashing that
   Microsoft invented for use with EAP authentication.  The low-level
   reference code is wrapped in higher-level cryptlib-like wrappers 
   beginning with 'eap' to try to make the whole mess more comprehensible */

/* Under Windows debug mode everything is enabled by default when building 
   cryptlib, so we also enable the required options here.  Under Unix it'll
   need to be enabled manually by adding '-DUSE_EAP -DUSE_DES' to the build 
   command.  Note that this needs to be done via the build process even if
   it's already defined in config.h since that only applies to cryptlib, not
   to this module */

#if defined( _MSC_VER ) && !defined( NDEBUG )
  #define USE_EAP
  #define USE_DES
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

/* Check that EAP and any required ancilliary capabilities are enabled in 
   the build */

#if defined( USE_EAP ) && !defined( USE_DES )
  #error USE_EAP requires USE_DES for MSCHAPv2
#endif /* !USE_EAP */

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

#ifdef USE_EAP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Convert a password to Windows-format Unicode.  Note that this conversion 
   may run into i18n problems if mapping from the source system's local 
   format to Windows-format Unicode isn't possible.  For this reason use of 
   non-basic-ASCII+latin1 characters is discouraged unless you're sure that 
   the local system, conversion process, and remote system all agree on what 
   translates to what */

static int convertToUnicode( BYTE *unicodePassword, 
							 const int unicodePasswordMaxLength,
							 const BYTE *password, const int passwordLength )
	{
	wchar_t wcsBuffer[ 256 + 1 ];
#if defined( _WIN32 ) || defined( _WIN64 )
	const int unicodePasswordLength = \
				MultiByteToWideChar( CP_UTF8, 0, password, passwordLength,
									 NULL, 0 );
#else
	const int unicodePasswordLength = ( int ) \
				mbstowcs( NULL, password, passwordLength );
#endif /* Windows vs. Unix */
	int i, status;

	/* Make sure that the converted result will fit */
	if( unicodePasswordLength <= 0 )
		return( CRYPT_ERROR_BADDATA );
	if( unicodePasswordLength * 2 > unicodePasswordMaxLength || \
		unicodePasswordLength * 2 > 256 )
		return( CRYPT_ERROR_OVERFLOW );

	/* Convert the input string into 16-bit little-endian Windows-style
	   Unicode.  We have to be careful here because wchar_t can be 16 or 32 
	   bits and of either endianness while Windows Unicode is 16-bit little-
	   endian.  In addition the Windows mbstowcs() can't do UTF-8 so we 
	   have to use MultiByteToWideChar() instead, however since we're 
	   hardcoding in UTF-8 to be compatible with the Unix usage it also
	   won't convert from a standard Windows locale which will never be
	   UTF-8 */
	memset( unicodePassword, 0, unicodePasswordMaxLength );
#if defined( _WIN32 ) || defined( _WIN64 )
	status = MultiByteToWideChar( CP_UTF8, 0, password, passwordLength,
								  wcsBuffer, 256 );
#else
	status = mbstowcs( wcsBuffer, password, passwordLength );
#endif /* Windows vs. Unix */
	if( status <= 0 )
		return( CRYPT_ERROR_BADDATA );
	for( i = 0; i < unicodePasswordLength; i++ )
		{
		const wchar_t wCh = wcsBuffer[ i ];

		/* The string is now in the local system's wchar_t form, convert 
		   it to Windows Unicode form */
		if( wCh > 0x7FFF )
			return( CRYPT_ERROR_BADDATA );
		unicodePassword[ i * 2 ] = wCh & 0xFF;
		unicodePassword[ ( i * 2 ) + 1 ] = ( wCh >> 8 ) & 0xFF;
		}

	return( unicodePasswordLength * 2 );
	}

/****************************************************************************
*																			*
*					Obsolete Crypto Algorithms for MS-CHAP					*
*																			*
****************************************************************************/

/* Public-domain MD4 implementation, see comment below */

#define MD4_BLOCK_LENGTH			64
#define MD4_DIGEST_LENGTH			16

typedef struct {
	unsigned long state[ 4 ];		/* State */
	long count;						/* Number of bits */
	BYTE buffer[ MD4_BLOCK_LENGTH ];/* input buffer */
	} MD4_CTX;

/* ===== start - public domain MD4 implementation ===== */
/*      $OpenBSD: md4.c,v 1.7 2005/08/08 08:05:35 espie Exp $   */

/*
 * This code implements the MD4 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 * Todd C. Miller modified the MD5 code to do MD4 based on RFC 1186.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD4Context structure, pass it to MD4Init, call MD4Update as
 * needed on buffers full of bytes, and then call MD4Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#define MD4_DIGEST_STRING_LENGTH        (MD4_DIGEST_LENGTH * 2 + 1)

static void
MD4Transform(unsigned long state[4], const BYTE block[MD4_BLOCK_LENGTH]);

#define PUT_64BIT_LE(cp, value) do {                \
        (cp)[7] = 0;                                \
        (cp)[6] = 0;                                \
        (cp)[5] = 0;                                \
        (cp)[4] = 0;                                \
        (cp)[3] = (BYTE)((value) >> 24);            \
        (cp)[2] = (BYTE)((value) >> 16);            \
        (cp)[1] = (BYTE)((value) >> 8);             \
        (cp)[0] = (BYTE)(value); } while (0)

#define PUT_32BIT_LE(cp, value) do {                \
        (cp)[3] = (BYTE)((value) >> 24);            \
        (cp)[2] = (BYTE)((value) >> 16);            \
        (cp)[1] = (BYTE)((value) >> 8);             \
        (cp)[0] = (BYTE)(value); } while (0)

static BYTE PADDING[MD4_BLOCK_LENGTH] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Start MD4 accumulation.
 * Set bit count to 0 and buffer to mysterious initialization constants.
 */
static void MD4Init(MD4_CTX *ctx)
{
        ctx->count = 0;
        ctx->state[0] = 0x67452301;
        ctx->state[1] = 0xefcdab89;
        ctx->state[2] = 0x98badcfe;
        ctx->state[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void MD4Update(MD4_CTX *ctx, const unsigned char *input, size_t len)
{
        size_t have, need;

        /* Check how many bytes we already have and how many more we need. */
        have = (size_t)((ctx->count >> 3) & (MD4_BLOCK_LENGTH - 1));
        need = MD4_BLOCK_LENGTH - have;

        /* Update bitcount */
        ctx->count += (unsigned long)len << 3;

        if (len >= need) {
                if (have != 0) {
                        memcpy(ctx->buffer + have, input, need);
                        MD4Transform(ctx->state, ctx->buffer);
                        input += need;
                        len -= need;
                        have = 0;
                }

                /* Process data in MD4_BLOCK_LENGTH-byte chunks. */
                while (len >= MD4_BLOCK_LENGTH) {
                        MD4Transform(ctx->state, input);
                        input += MD4_BLOCK_LENGTH;
                        len -= MD4_BLOCK_LENGTH;
                }
        }

        /* Handle any remaining bytes of data. */
        if (len != 0)
                memcpy(ctx->buffer + have, input, len);
}

/*
 * Pad pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void MD4Pad(MD4_CTX *ctx)
{
        BYTE count[8];
        size_t padlen;

        /* Convert count to 8 bytes in little endian order. */
        PUT_64BIT_LE(count, ctx->count);

        /* Pad out to 56 mod 64. */
        padlen = MD4_BLOCK_LENGTH -
            ((ctx->count >> 3) & (MD4_BLOCK_LENGTH - 1));
        if (padlen < 1 + 8)
                padlen += MD4_BLOCK_LENGTH;
        MD4Update(ctx, PADDING, padlen - 8);            /* padlen - 8 <= 64 */
        MD4Update(ctx, count, 8);
}

/*
 * Final wrapup--call MD4Pad, fill in digest and zero out ctx.
 */
static void MD4Final(unsigned char digest[MD4_DIGEST_LENGTH], MD4_CTX *ctx)
{
        int i;

        MD4Pad(ctx);
        if (digest != NULL) {
                for (i = 0; i < 4; i++)
                        PUT_32BIT_LE(digest + i * 4, ctx->state[i]);
                memset(ctx, 0, sizeof(*ctx));
        }
}

/* The three core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) ((x & y) | (x & z) | (y & z))
#define F3(x, y, z) (x ^ y ^ z)

/* This is the central step in the MD4 algorithm. */
#define MD4STEP(f, w, x, y, z, data, s) \
        ( w += f(x, y, z) + data,  w = ((w<<s)&0xFFFFFFFF) | (w&0xFFFFFFFF)>>(32-s) )
		/* Added 32-bit masking to avoid having to use system-specific 
		   fixed-size 32-bit data types - pcg */

/*
 * The core of the MD4 algorithm, this alters an existing MD4 hash to
 * reflect the addition of 16 longwords of new data.  MD4Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void
MD4Transform(unsigned long state[4], const BYTE block[MD4_BLOCK_LENGTH])
{
        unsigned long a, b, c, d, in[MD4_BLOCK_LENGTH / 4];

        for (a = 0; a < MD4_BLOCK_LENGTH / 4; a++) {
                in[a] = (unsigned long)(
                    (unsigned long)(block[a * 4 + 0]) |
                    (unsigned long)(block[a * 4 + 1]) <<  8 |
                    (unsigned long)(block[a * 4 + 2]) << 16 |
                    (unsigned long)(block[a * 4 + 3]) << 24);
        }

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];

        MD4STEP(F1, a, b, c, d, in[ 0],  3);
        MD4STEP(F1, d, a, b, c, in[ 1],  7);
        MD4STEP(F1, c, d, a, b, in[ 2], 11);
        MD4STEP(F1, b, c, d, a, in[ 3], 19);
        MD4STEP(F1, a, b, c, d, in[ 4],  3);
        MD4STEP(F1, d, a, b, c, in[ 5],  7);
        MD4STEP(F1, c, d, a, b, in[ 6], 11);
        MD4STEP(F1, b, c, d, a, in[ 7], 19);
        MD4STEP(F1, a, b, c, d, in[ 8],  3);
        MD4STEP(F1, d, a, b, c, in[ 9],  7);
        MD4STEP(F1, c, d, a, b, in[10], 11);
        MD4STEP(F1, b, c, d, a, in[11], 19);
        MD4STEP(F1, a, b, c, d, in[12],  3);
        MD4STEP(F1, d, a, b, c, in[13],  7);
        MD4STEP(F1, c, d, a, b, in[14], 11);
        MD4STEP(F1, b, c, d, a, in[15], 19);

        MD4STEP(F2, a, b, c, d, in[ 0] + 0x5a827999,  3);
        MD4STEP(F2, d, a, b, c, in[ 4] + 0x5a827999,  5);
        MD4STEP(F2, c, d, a, b, in[ 8] + 0x5a827999,  9);
        MD4STEP(F2, b, c, d, a, in[12] + 0x5a827999, 13);
        MD4STEP(F2, a, b, c, d, in[ 1] + 0x5a827999,  3);
        MD4STEP(F2, d, a, b, c, in[ 5] + 0x5a827999,  5);
        MD4STEP(F2, c, d, a, b, in[ 9] + 0x5a827999,  9);
        MD4STEP(F2, b, c, d, a, in[13] + 0x5a827999, 13);
        MD4STEP(F2, a, b, c, d, in[ 2] + 0x5a827999,  3);
        MD4STEP(F2, d, a, b, c, in[ 6] + 0x5a827999,  5);
        MD4STEP(F2, c, d, a, b, in[10] + 0x5a827999,  9);
        MD4STEP(F2, b, c, d, a, in[14] + 0x5a827999, 13);
        MD4STEP(F2, a, b, c, d, in[ 3] + 0x5a827999,  3);
        MD4STEP(F2, d, a, b, c, in[ 7] + 0x5a827999,  5);
        MD4STEP(F2, c, d, a, b, in[11] + 0x5a827999,  9);
        MD4STEP(F2, b, c, d, a, in[15] + 0x5a827999, 13);

        MD4STEP(F3, a, b, c, d, in[ 0] + 0x6ed9eba1,  3);
        MD4STEP(F3, d, a, b, c, in[ 8] + 0x6ed9eba1,  9);
        MD4STEP(F3, c, d, a, b, in[ 4] + 0x6ed9eba1, 11);
        MD4STEP(F3, b, c, d, a, in[12] + 0x6ed9eba1, 15);
        MD4STEP(F3, a, b, c, d, in[ 2] + 0x6ed9eba1,  3);
        MD4STEP(F3, d, a, b, c, in[10] + 0x6ed9eba1,  9);
        MD4STEP(F3, c, d, a, b, in[ 6] + 0x6ed9eba1, 11);
        MD4STEP(F3, b, c, d, a, in[14] + 0x6ed9eba1, 15);
        MD4STEP(F3, a, b, c, d, in[ 1] + 0x6ed9eba1,  3);
        MD4STEP(F3, d, a, b, c, in[ 9] + 0x6ed9eba1,  9);
        MD4STEP(F3, c, d, a, b, in[ 5] + 0x6ed9eba1, 11);
        MD4STEP(F3, b, c, d, a, in[13] + 0x6ed9eba1, 15);
        MD4STEP(F3, a, b, c, d, in[ 3] + 0x6ed9eba1,  3);
        MD4STEP(F3, d, a, b, c, in[11] + 0x6ed9eba1,  9);
        MD4STEP(F3, c, d, a, b, in[ 7] + 0x6ed9eba1, 11);
        MD4STEP(F3, b, c, d, a, in[15] + 0x6ed9eba1, 15);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
}
/* ===== end - public domain MD4 implementation ===== */

static void md4Hash( const void *data, const int dataLength, BYTE *hashValue )
	{
	MD4_CTX md4CTX;

	MD4Init( &md4CTX );
	MD4Update( &md4CTX, data, dataLength );
	MD4Final( hashValue, &md4CTX );
	}

/****************************************************************************
*																			*
*									MS-CHAPv2								*
*																			*
****************************************************************************/

/* MSCHAPv2 functionality as specified in RFC 2759.  This is a great
   teaching example of every mistake you can make in challenge-response 
   authentication, it gets pretty much everything wrong from start to 
   finish, but we have to implement it because so much stuff uses it.
   
   Later parts are also a great example of what happens when you give a hash 
   function to an eight-year-old to play with */

/* ChallengeHash(), RFC 2759 page 8 */

static int ChallengeHash( const BYTE PeerChallenge[ 16 ], 
						  const BYTE AuthenticatorChallenge[ 16 ],
						  const BYTE *UserName, const int UserNameLength,
						  BYTE Challenge[ 8 ] )
	{
	CRYPT_CONTEXT hashContext;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
	int hashSize, status;

	status = cryptCreateContext( &hashContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_SHA1 );
	if( cryptStatusError( status ) )
		return( status );
	cryptEncrypt( hashContext, ( void * ) PeerChallenge, 16 );
	cryptEncrypt( hashContext, ( void * ) AuthenticatorChallenge, 16 );
	cryptEncrypt( hashContext, ( void * ) UserName, UserNameLength );
	status = cryptEncrypt( hashContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( hashContext, 
										  CRYPT_CTXINFO_HASHVALUE,
										  hashValue, &hashSize );
		}
	cryptDestroyContext( hashContext );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( Challenge, hashValue, 8 );

	/* Clean up */	
	memset( hashValue, 0, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* NtPasswordHash(), RFC 2759 page 9 */

static int NtPasswordHash( const BYTE *Password, const int PasswordLength,
						   BYTE PasswordHash[ 16 ] )
	{
	md4Hash( Password, PasswordLength, PasswordHash );

	return( CRYPT_OK );
	}

/* HashNtPasswordHash(), RFC 2759 page 8 */

static int HashNtPasswordHash( const BYTE *PasswordHash,
							   BYTE PasswordHashHash[ 16 ] )
	{
	md4Hash( PasswordHash, 16, PasswordHashHash );

	return( CRYPT_OK );
	}

/* ChallengeResponse(), RFC 2759 page 9.
   DesEncrypt(), RFC 2759 page 10 */

static int DesEncrypt( const BYTE Clear[ 8 ], 
					   const BYTE Key[ 7 ], 
					   BYTE Cypher[ 8 ] )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE desKey[ 8 ];
	int i, status;

	/* Convert the 56-bit Key value into the eight 7-bit key data bytes 
	   required by DES.  This involves first expanding the 56 input bits
	   into 64 7-bit bytes and then shifting each byte up by one since the
	   parity bits are in the LSB, not the MSB */
	desKey[ 0 ] = Key[ 0 ] >> 0x01;
	desKey[ 1 ] = ( ( Key[ 0 ] & 0x01 ) << 6 ) | ( Key[ 1 ] >> 2 );
	desKey[ 2 ] = ( ( Key[ 1 ] & 0x03 ) << 5 ) | ( Key[ 2 ] >> 3 );
 	desKey[ 3 ] = ( ( Key[ 2 ] & 0x07 ) << 4 ) | ( Key[ 3 ] >> 4 );
	desKey[ 4 ] = ( ( Key[ 3 ] & 0x0F ) << 3 ) | ( Key[ 4 ] >> 5 );
	desKey[ 5 ] = ( ( Key[ 4 ] & 0x1F ) << 2 ) | ( Key[ 5 ] >> 6 );
	desKey[ 6 ] = ( ( Key[ 5 ] & 0x3F ) << 1 ) | ( Key[ 6 ] >> 7 );
	desKey[ 7 ] = Key[ 6 ] & 0x7F;
	for( i = 0; i < 8; i++ )
		desKey[ i ] = ( desKey[ i ] << 1 ) & 0xFE;

	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_DES );
	if( cryptStatusError( status ) )
		return( status );
	cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE, CRYPT_MODE_ECB );
	status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY, 
									  desKey, 8 );
	if( cryptStatusOK( status ) )
		{
		memcpy( Cypher, Clear, 8 );
		status = cryptEncrypt( cryptContext, Cypher, 8 );
		}
	cryptDestroyContext( cryptContext );
	memset( desKey, 0, 8 );

	return( status );
	}

static int ChallengeResponse( const BYTE Challenge[ 8 ], 
							  const BYTE PasswordHash[ 16 ],
							  BYTE Response[ 24 ] )
	{
	BYTE ZPasswordHash[ 21 ];
	int status;

	memset( ZPasswordHash, 0, 21 );
	memcpy( ZPasswordHash, PasswordHash, 16 );

	status = DesEncrypt( Challenge, ZPasswordHash, Response );
	if( cryptStatusOK( status ) )
		status = DesEncrypt( Challenge, ZPasswordHash + 7, Response + 8 );
	if( cryptStatusOK( status ) )
		status = DesEncrypt( Challenge, ZPasswordHash + 14, Response + 16 );
	memset( ZPasswordHash, 0, 21 );

	return( status );
	}

/* GenerateNTResponse, RFC 2759 p.7 */

static int GenerateNTResponse( const BYTE AuthenticatorChallenge[ 16 ],
							   const BYTE PeerChallenge[ 16 ],
							   const BYTE *UserName, const int UserNameLength,
							   const BYTE *Password, const int PasswordLength,
							   BYTE Response[ 24 ] )
	{
	BYTE Challenge[ 8 ], PasswordHash[ 16 ];
	int status;

	status = ChallengeHash( PeerChallenge, AuthenticatorChallenge,
							UserName, UserNameLength, Challenge );
	if( cryptStatusOK( status ) )
		status = NtPasswordHash( Password, PasswordLength, PasswordHash );
	if( cryptStatusOK( status ) )
		status = ChallengeResponse( Challenge, PasswordHash, Response );

	/* Clean up */	
	memset( Challenge, 0, 8 );
	memset( PasswordHash, 0, 16 );

	return( status );
	}

/* GenerateAuthenticatorResponse, RFC 2759 p.9 */

static int GenerateAuthenticatorResponse( const BYTE *UnicodePassword, 
										  const int UnicodePasswordLength,
										  const BYTE NTResponse[ 24 ],
										  const BYTE PeerChallenge[ 16 ],
										  const BYTE AuthenticatorChallenge[ 16 ],
										  const char *UserName,
										  BYTE AuthenticatorResponse[ 42 ] )
	{
	const BYTE Magic1[ 39 ] = {
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 
		0x72, 0x76, 0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 
		0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x73, 
		0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x63, 
		0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74
		};
	const BYTE Magic2[ 41 ] = {
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 
		0x61, 0x6B, 0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 
		0x6F, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x20, 0x74, 
		0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E, 0x65, 0x20, 
		0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E
		};
	CRYPT_CONTEXT hashContext;
	BYTE PasswordHash[ 16 ], PasswordHashHash[ 16 ], Challenge[ 8 ];
	BYTE Digest[ CRYPT_MAX_HASHSIZE ];
	const int UserNameLength = strlen( UserName );
	int hashSize, i, status;

	/* Hash the password with MD4 */
	NtPasswordHash( UnicodePassword, UnicodePasswordLength, PasswordHash );

	/* Now hash the hash */
	HashNtPasswordHash( PasswordHash, PasswordHashHash );

	/* Create the first hash */
	status = cryptCreateContext( &hashContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_SHA1 );
	if( cryptStatusError( status ) )
		return( status );
	cryptEncrypt( hashContext, PasswordHashHash, 16 );
	cryptEncrypt( hashContext, ( void * ) NTResponse, 24 );
	cryptEncrypt( hashContext, ( void * ) Magic1, 39 );
	status = cryptEncrypt( hashContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( hashContext, 
										  CRYPT_CTXINFO_HASHVALUE,
										  Digest, &hashSize );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Create the Challenge hash */
	status = ChallengeHash( PeerChallenge, AuthenticatorChallenge, UserName, 
							UserNameLength, Challenge );
	if( cryptStatusError( status ) )
		{
		memset( PasswordHash, 0, 16 );
		memset( PasswordHashHash, 0, 16 );
		memset( Digest, 0, 20 );
		return( status );
		}

	/* Create the second hash */
	cryptDeleteAttribute( hashContext, CRYPT_CTXINFO_HASHVALUE );
	cryptEncrypt( hashContext, Digest, 20 );
	cryptEncrypt( hashContext, Challenge, 8 );
	cryptEncrypt( hashContext, ( void * ) Magic2, 41 );
	status = cryptEncrypt( hashContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( hashContext, 
										  CRYPT_CTXINFO_HASHVALUE,
										  Digest, &hashSize );
		}
	cryptDestroyContext( hashContext );
	if( cryptStatusError( status ) )
		{
		memset( PasswordHash, 0, 16 );
		memset( PasswordHashHash, 0, 16 );
		memset( Challenge, 0, 8 );
		memset( Digest, 0, 20 );
		return( status );
		}

	/* Format the output as "S=xxxxxx" */
	memcpy( AuthenticatorResponse, "S=", 2 );
	for( i = 0; i < 20; i++ )
		sprintf( AuthenticatorResponse + 2 + ( i * 2 ), "%02X", Digest[ i ] );

	/* Clean up */	
	memset( PasswordHash, 0, 16 );
	memset( PasswordHashHash, 0, 16 );
	memset( Challenge, 0, 8 );
	memset( Digest, 0, 20 );

	return( status );
	}

/* Wrappers for the above to make them more cryptlib-like.  The 
   AuthenticatorChallenge is the value sent by the server in its MSCHAPv2
   Challenge Packet, so the server challenge, and the PeerChallenge is the
   value sent by the client in its MSCHAPv2 Response Packet, so the client
   challenge.  
   
   Note that the original functions reverse the order of the challenges 
   across the functions, so GenerateNTResponse() uses 
   ( AuthenticatorChallenge, PeerChallenge ) = ( serverChallenge, 
   clientChallenge ) while GenerateAuthenticatorResponse() uses 
   ( PeerChallenge, AuthenticatorChallenge ) = ( clientChallenge, 
   serverChallenge ) */

int eapCreateMSCHAPv2Response( const void *userName, 
							   const int userNameLength,
							   const void *password, 
							   const int passwordLength,
							   const void *serverChallenge,
							   const void *clientChallenge, void *response )
	{
	BYTE unicodePassword[ 256 ];
	int unicodePasswordLength, status;

	/* Convert the password to Windows-format Unicode */
	status = unicodePasswordLength = \
					convertToUnicode( unicodePassword, 256, 
									  password, passwordLength );
	if( cryptStatusError( status ) )
		return( status );

	return( GenerateNTResponse( serverChallenge, clientChallenge, 
								userName, userNameLength, unicodePassword, 
								unicodePasswordLength, response ) );
	}

int eapCreateAuthenticatorResponse( const void *userName, 
									const int userNameLength,
									const void *password, 
									const int passwordLength,
									const void *serverChallenge,
									const void *clientChallenge,
									const void *ntResponse, 
									void *authenticator )
	{
	BYTE unicodePassword[ 256 ];
	int unicodePasswordLength, status;

	/* Convert the password to Windows-format Unicode */
	status = unicodePasswordLength = \
					convertToUnicode( unicodePassword, 256, 
									  password, passwordLength );
	if( cryptStatusError( status ) )
		return( status );

	return( GenerateAuthenticatorResponse( unicodePassword, 
										   unicodePasswordLength, ntResponse,
										   clientChallenge, serverChallenge,  
										   userName, authenticator ) );
	}

/****************************************************************************
*																			*
*								MPPE Key Derivation							*
*																			*
****************************************************************************/

/* MPPE, specifically from MSCHAP, key derivation as specified in RFC 3079 */

/* GetMasterKey, RFC 3079 page 11 */

static int GetMasterKey( const BYTE *PasswordHashHash,
						 const BYTE *NTResponse,
						 BYTE MasterKey[ 16 ] )
	{
	static const BYTE Magic1[ 27 ] = {
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x4D, 0x50, 0x50, 0x45, 0x20, 0x4D,
		0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4B, 0x65, 0x79
		};
	CRYPT_CONTEXT cryptContext;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
	int length, status;

	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_SHA1 );
	if( cryptStatusError( status ) )
		return( status );
	cryptEncrypt( cryptContext, ( void * ) PasswordHashHash, 16 );
	cryptEncrypt( cryptContext, ( void * ) NTResponse, 24 );
	cryptEncrypt( cryptContext, ( void * ) Magic1, 27 );
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE,
										  hashValue, &length );
		}
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( MasterKey, hashValue, 16 );
	
	return( CRYPT_OK );
	}

/* GetAsymetricStartKey, RFC 3079 page 11 */

static int GetAsymetricStartKey( const BYTE *MasterKey,
								 BYTE SessionKey[ 16 ],
								 const int SessionKeyLength,
								 const BOOLEAN IsSend,
								 const BOOLEAN IsServer )
	{
	static const BYTE Magic2[ 84 ] = {
		0x4F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6C, 0x69,
		0x65, 0x6E, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2C, 0x20,
		0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x73, 0x65, 0x6E, 0x64, 0x20, 0x6B, 0x65, 0x79,
		0x3B, 0x20, 0x6F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
		0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
		0x2C, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
		0x6B, 0x65, 0x79, 0x2E
		};
	static const BYTE Magic3[ 84 ] = {
		0x4F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6C, 0x69,
		0x65, 0x6E, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2C, 0x20,
		0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
		0x6B, 0x65, 0x79, 0x3B, 0x20, 0x6F, 0x6E, 0x20, 0x74, 0x68,
		0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
		0x69, 0x64, 0x65, 0x2C, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
		0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6E, 0x64, 0x20,
		0x6B, 0x65, 0x79, 0x2E
		};
	static const BYTE SHSpad1[ 40 ] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
	static const BYTE SHSpad2[ 40 ] = {
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
		0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2
		};
	CRYPT_CONTEXT cryptContext;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
	const BYTE *s;
	int length, status;

	if( IsSend )
		{
		if( IsServer ) 
			s = Magic3;
		else 
			s = Magic2;
		} 
	else 
		{
		if( IsServer ) 
			s = Magic2;
		else 
			s = Magic3;
		}

	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_SHA1 );
	if( cryptStatusError( status ) )
		return( status );
	cryptEncrypt( cryptContext, ( void * ) MasterKey, 16 );
	cryptEncrypt( cryptContext, ( void * ) SHSpad1, 40 );
	cryptEncrypt( cryptContext, ( void * ) s, 84 );
	cryptEncrypt( cryptContext, ( void * ) SHSpad2, 40 );
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE,
										  hashValue, &length );
		}
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( SessionKey, hashValue, SessionKeyLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Cryptobinding Routines						*
*																			*
****************************************************************************/

/* The Microsoft-invented Crypto-Binding mechanism is what happens when you
   give an eight-year-old a hash function to play with and then get the 
   eight-year-old's friends to document it based on Chinese whispers.  It's 
   difficult to document because it's such a dog's breakfast, but the flow
   is approximately:

	// TK: RFC 5126 section 2.3.
	TK = TLS-PRF( TLS-master-secret, "client EAP encryption" || \
									 client_random || server_random );

	// NTResponse: RFC 2759 section 8.1.
	NTResponse = DES/MD4 mix of challenge, unicode_pw;

	// ISK: RFC 3079 section 3.3.
	ISK' = SHA1( MD4( MD4( unicode_pw ) ) || NTResponse || magicString1 );
	ISK = SHA1( ISK' || padString1 || magicString2 || padString2 ) || \	
		  SHA1( ISK' || padString1 || magicString3 || padString2 );

	// CMK: Not PEAPv2
	T1 = HMAC-SHA1( CMK, "Inner Methods Compound Keys" || ISK || \
						 0x01 0x00 0x00 );
	T2 = HMAC-SHA1( CMK, T1 || "Inner Methods Compound Keys" || ISK || \
						 0x02 0x00 0x00 );
	CMK = HMAC-SHA1( CMK, T2 || "Inner Methods Compound Keys" || ISK || \
						  0x03 0x00 0x00 ); */

/* Create the ISK from the user password and NT-Response value.  The correct
   way to call GetAsymetricStartKey() to get the key we want is never 
   explained in RFC 3079 (or anywhere else for that matter) but 
   /src/eap_peer/eap_mschapv2:eap_mschapv2_getKey() uses:

	get_asymetric_start_key(data->master_key, key, MSCHAPV2_KEY_LEN, 1, 0);
	get_asymetric_start_key(data->master_key, key + MSCHAPV2_KEY_LEN, 
							MSCHAPV2_KEY_LEN, 0, 0); 

   This is one interpretation of the confusing explanation at
   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-peap/0de54161-0bd3-424a-9b1a-854b4040a6df
   which says:

	Peer ISK = InnerMPPESendKey | InnerMPPERecvKey
	Server ISK = InnerMPPERecvKey | InnerMPPESendKey

   Since we're the client the ISK is both a Peer ISK and a Server ISK, which
   makes the calls:

	GetAsymetricStartKey( IsSend = TRUE, IsServer = FALSE );
	GetAsymetricStartKey( IsSend = FALSE, IsServer = FALSE );

   creating a Peer ISK */

int eapCreateISK( BYTE *isk, const void *password, const int passwordLength, 
				  const BYTE NTResponse[ 24 ] )
	{
	BYTE unicodePassword[ 256 ], PasswordHash[ 16 ], PasswordHashHash[ 16 ];
	BYTE MasterKey[ 16 ];
	int unicodePasswordLength, status;

	/* Convert the password to Windows-format Unicode */
	unicodePasswordLength = convertToUnicode( unicodePassword, 256, 
											  password, passwordLength );
	if( unicodePasswordLength < 0 )
		return( unicodePasswordLength );

	/* Double-hash the converted password and use it with the NT-Response to
	   generate the Master Key */
	status = NtPasswordHash( unicodePassword, unicodePasswordLength, 
							 PasswordHash );
	if( cryptStatusOK( status ) )
		status = HashNtPasswordHash( PasswordHash, PasswordHashHash );
	if( cryptStatusOK( status ) )
		status = GetMasterKey( PasswordHashHash, NTResponse, MasterKey );
	if( cryptStatusError( status ) )
		return( status );

	/* Convert the Master Key into the ISK */
	status = GetAsymetricStartKey( MasterKey, isk, 16, TRUE, FALSE );
	if( cryptStatusOK( status ) )
		status = GetAsymetricStartKey( MasterKey, isk + 16, 16, FALSE, FALSE );
///////////////////////////////////////////////////////////////////////////
//	DEBUG_PUTS( "ISK:" );
//	DEBUG_DUMPHEX_ALL( isk, 32 );
//	DEBUG_PUTS( "" );
///////////////////////////////////////////////////////////////////////////

	/* Clean up */
	memset( unicodePassword, 0, 256 );
	memset( PasswordHash, 0, 16 );
	memset( PasswordHashHash, 0, 16 );
	memset( MasterKey, 0, 16 );

	return( status );
	}

/* Create the Intermediate PEAP MAC Key IPMK and Compound MAC Key CMK from 
   the TK and ISK.  This is incorrectly documented in 
   draft-josefsson-pppext-eap-tls-eap-10.txt as being the PRF from IKEv2 in 
   RFC 4306:

	prf+ (K,S) = T1 | T2 | T3 | T4 | ...

	where:
	T1 = prf (K, S | 0x01)
	T2 = prf (K, T1 | S | 0x02)
	T3 = prf (K, T2 | S | 0x03)
	T4 = prf (K, T3 | S | 0x04)

   The PEAPv2 draft above however documents it as:

	PRF (K,S,LEN) = T1 | T2 | T3 | T4 | ... where:

	T1 = HMAC-SHA1(K, S | LEN | 0x01)
	T2 = HMAC-SHA1 (K, T1 | S | LEN | 0x02)
	T3 = HMAC-SHA1 (K, T2 | S | LEN | 0x03)
	T4 = HMAC-SHA1 (K, T3 | S | LEN | 0x04)

   and "LEN = output length, represented as binary in a single octet", given
   as 60 bytes or 0x3C in the draft.

   However what's actually used is documented in 
   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-peap/0de54161-0bd3-424a-9b1a-854b4040a6df
   as (K = TK, S = IPMK Seed):

	IPMK Seed = "Inner Methods Compound Keys" | ISK

	PRF+(K, S, LEN) = T1 | T2 | ... |Tn
	Where:
	T1 = HMAC-SHA1 (K, S | 0x01 | 0x00 | 0x00)
	T2 = HMAC-SHA1 (K, T1 | S | 0x02 | 0x00 | 0x00)
	...
	Tn = HMAC-SHA1 (K, Tn-1 | S | n | 0x00 | 0x00)

   By trial and error against NPS the one that works is the latter, 
   presumably a Microsoft implementation bug, not the actual PRF as
   documented in the spec.  src/eap_common/eap_peap_common.c:peap_prfplus()
   uses the three-byte version for PEAPv0 (for which this mechanism isn't
   even defined since it's a PEAPv2 one) and the one-byte version for PEAPv2 
   making it even more likely that it's a Microsoft bug.
   
   The output is generated as (also from the above web page):

	TempKey = First 40 octets of TK
	IPMK = First 40 octets of PRF+ (TempKey, IPMK Seed, 60);
	CMK = Last 20 octets of PRF+ (TempKey, IPMK Seed, 60);

   where the IPMK Seed is "Inner Methods Compound Keys" | ISK.
   
   The IPMK is used when multiple EAP methods are applied, being fed forward
   to the PRF for the next method, but we're only using one method so only 
   the CMK at the end is needed */

int eapCreateCMK( BYTE *ipmk, BYTE *cmk, const BYTE *tk, const BYTE *isk )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE ipmkSeed[ 64 ];
	int length, status;

	/* Create the IPMK seed S = "Inner Methods Compound Keys" || ISK */
	memcpy( ipmkSeed, "Inner Methods Compound Keys", 27 );
	memcpy( ipmkSeed + 27, isk, 32 );

	/* Create the HMAC-SHA1 context and set the key, the first 40 bytes of 
	   TK */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_HMAC_SHA1 );
	if( cryptStatusError( status ) )
		{
		memset( ipmkSeed, 0, 64 );
		return( status );
		}
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY, tk, 40 );

	/* Generate T1, the first half of the IPMK:

		T1 = HMAC-SHA1( K, S | 0x01 | 0x00 | 0x00 ) */
	memcpy( ipmkSeed + 27 + 32, "\x01\x00\x00", 3 );
	cryptEncrypt( cryptContext, ipmkSeed, 27 + 32 + 3 );
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE, 
										  ipmk, &length );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		memset( ipmkSeed, 0, 64 );
		return( status );
		}
	cryptDeleteAttribute( cryptContext, CRYPT_CTXINFO_HASHVALUE );

	/* Generate T2, the second half of the IPMK:

		T2 = HMAC-SHA1( K, T1 | S | 0x02 | 0x00 | 0x00 ) */
	cryptEncrypt( cryptContext, ipmk, 20 );
	memcpy( ipmkSeed + 27 + 32, "\x02\x00\x00", 3 );
	cryptEncrypt( cryptContext, ipmkSeed, 27 + 32 + 3 );
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE, 
										  ipmk + 20, &length );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		memset( ipmkSeed, 0, 64 );
		return( status );
		}
	cryptDeleteAttribute( cryptContext, CRYPT_CTXINFO_HASHVALUE );

	/* Generate T3, the CMK:

		T3 = HMAC-SHA1( K, T2 | S | 0x03 | 0x00 | 0x00 ) */
	cryptEncrypt( cryptContext, ipmk + 20, 20 );
	memcpy( ipmkSeed + 27 + 32, "\x03\x00\x00", 3 );
	cryptEncrypt( cryptContext, ipmkSeed, 27 + 32 + 3 );
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE, 
										  cmk, &length );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		memset( ipmkSeed, 0, 64 );
		return( status );
		}
///////////////////////////////////////////////////////////////////////////
//	DEBUG_PRINT(( "CMK:\n" ));
//	DEBUG_DUMPHEX( cmk, 20 );
//	DEBUG_PUTS( "" );
///////////////////////////////////////////////////////////////////////////

	/* Clean up */
	cryptDestroyContext( cryptContext );
	memset( ipmkSeed, 0, 64 );

	return( CRYPT_OK );
	}

/* Create the Compound MAC of the Crypto-Binding packet.  As with the IPMK
   derivation the documentation for this is wrong, but differently wrong
   everywhere it's documented.  draft-josefsson-pppext-eap-tls-eap-10 says:

	The MAC is computed over the buffer created after concatenating these 
	fields in the following order:

	[a]  The entire Crypto-Binding TLV attribute with the MAC field zeroed
	     out.

	[b]  The EAP Type sent by the other party in the first PEAP message.

	[c]  All the Outer-TLVs from the first PEAP message sent by EAP-server
	     to peer.  If a single PEAP message is fragmented into multiple PEAP
	     packets; then the Outer-TLVs in all the fragments of that message
	     MUST be included.

	[d]  All the Outer-TLVs from the first PEAP message sent by the peer to
	     the EAP server.  If a single PEAP message is fragmented into
	     multiple PEAP packets, then the Outer-TLVs in all the fragments of
	     that message MUST be included.

   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-peap/a0919a6f-0fa2-4fb3-abc8-7735f2586af3
   says:

	The data used as the input to the HMAC-SHA1-160 operation used in the 
	creation of the Compound MAC MUST be constructed, through concatenation, 
	as follows:

	60 bytes containing the cryptobinding TLV with the Compound_MAC field 
	zeroed out.

	1 byte containing the EAP type sent by the peer in the first processed 
	PEAP message. For PEAP, the value MUST be the IANA-assigned EAP type 
	code (25) for PEAP (see [IANA-EAP]).

	The Outer_TLV_Data field of a PEAP start packet (as specified in section 
	2.2.6.2) when the HMAC-SHA1-160 operation is performed on a Peer, or the 
	Outer_TLV_Data field of a Client Hello Packet (as specified in section 
	2.2.6.1) when the HMAC-SHA1-160 operation is performed on a Server.

   What's actually MACd is:

	60 bytes containing the cryptobinding TLV with the Compound_MAC field 
	zeroed out.

	1 byte containing the EAP type = PEAP (25) 

   This is from /src/eap_peer/eap_peap.c:eap_tlv_validate_cryptobinding() */

int eapCreateCMAC( BYTE *cmac, const BYTE *cmk, const BYTE *data, 
				   const int dataLen )
	{
	CRYPT_CONTEXT cryptContext;
	int length, status;

	/* Create the HMAC-SHA1 context and set the key */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_HMAC_SHA1 );
	if( cryptStatusError( status ) )
		return( status );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY, cmk, 20 );
///////////////////////////////////////////////////////////////////////////
//	DEBUG_PRINT(( "CMAC key: " ));
//	DEBUG_DUMPHEX( cmk, 20 );
//	DEBUG_PUTS( "" );
///////////////////////////////////////////////////////////////////////////

	/* Create the compound MAC value */
	cryptEncrypt( cryptContext, ( void * ) data, dataLen );
///////////////////////////////////////////////////////////////////////////
//	DEBUG_PRINT(( "CMAC data:\n" ));
//	DEBUG_DUMPHEX_ALL( data, dataLen );
//	DEBUG_PUTS( "" );
///////////////////////////////////////////////////////////////////////////
	cryptEncrypt( cryptContext, "\x19", 1 );	/* EAP type = PEAP (25) */
	status = cryptEncrypt( cryptContext, "", 0 );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptContext, 
										  CRYPT_CTXINFO_HASHVALUE, 
										  cmac, &length );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		return( status );
		}
///////////////////////////////////////////////////////////////////////////
//	DEBUG_PRINT(( "CMAC: " ));
//	DEBUG_DUMPHEX( cmac, length );
//	DEBUG_PUTS( "" );
///////////////////////////////////////////////////////////////////////////

	cryptDestroyContext( cryptContext );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Self-Test Routines							*
*																			*
****************************************************************************/

/* Test the MSCHAPv2 implementation using the test vectors from RFC 2759:

	0-to-256-char UserName:
	55 73 65 72													// "User"

	0-to-256-unicode-char Password:
	63 00 6C 00 69 00 65 00 6E 00 74 00 50 00 61 00 73 00 73 00	// "clientPass"

	16-octet AuthenticatorChallenge:
	5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28

	16-octet PeerChallenge:
	21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E

	8-octet Challenge:
	D0 2E 43 86 BC E9 12 26

	16-octet PasswordHash:
	44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE

	24 octet NT-Response:
	82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF

	16-octet PasswordHashHash:
	41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F

	42-octet AuthenticatorResponse:
	"S=407A5589115FD0D6209F510FE9C04566932CDA56" */

static int testMSCHAPv2( void )
	{
	CRYPT_CONTEXT cryptContext;
	const BYTE UserName[] = "\x55\x73\x65\x72";	/* "User" */
	const BYTE Password[] = "\x63\x6C\x69\x65\x6E\x74\x50\x61\x73\x73";
							/* "clientPass" */	
	const BYTE UnicodePassword[] = "\x63\x00\x6C\x00\x69\x00\x65\x00" \
								   "\x6E\x00\x74\x00\x50\x00\x61\x00" \
								   "\x73\x00\x73\x00";
	const BYTE AuthenticatorChallenge[] = \
							"\x5B\x5D\x7C\x7D\x7B\x3F\x2F\x3E" \
							"\x3C\x2C\x60\x21\x32\x26\x26\x28";
	const BYTE PeerChallenge[] = \
							"\x21\x40\x23\x24\x25\x5E\x26\x2A" \
							"\x28\x29\x5F\x2B\x3A\x33\x7C\x7E";
	const BYTE *utf8String = "\x52\xC3\xA9\x73\x75\x6D\xC3\xA9";	/* "Résumé" */
	const BYTE *unicodeString = "\x52\x00\xE9\x00\x73\x00\x75\x00" \
								"\x6D\x00\xE9\x00";
	BYTE unicodePassword[ 256 ], Challenge[ 8 ], PasswordHash[ 16 ];
	BYTE PasswordHashHash[ 16 ], NTResponse[ 24 ];
	BYTE AuthenticatorResponse[ 50 ];
	int unicodePasswordLength, status;
#if !( defined( _WIN32 ) || defined( _WIN64 ) )
	const char *locale = setlocale( LC_ALL, NULL );

	/* Try and set UTF-8 for the convertToUnicode() self-test.  There's no 
	   portable way to do this since locales are defined in whatever way the 
	   system feels like, but one of the following should give us UTF-8 */
	if( !setlocale( LC_ALL, "en_US.UTF-8" ) && \
		!setlocale( LC_ALL, "en_US.utf8" ) && \
		!setlocale( LC_ALL, "C.UTF-8" ) )
		{
		DEBUG_PUTS(( "Couldn't set locale to UTF-8 for self-test." ));
		return( CRYPT_ERROR_FAILED );
		}
#endif /* !Windows */

	/* Test that the antique crypto that we need for MSCHAPv2 is enabled */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_DES );
	if( cryptStatusError( status ) )
		{
		DEBUG_PUTS(( "Single DES isn't enabled in cryptlib, MSCHAPv2 can't "
					 "be used." ));
		return( CRYPT_ERROR_FAILED );
		}
	cryptDestroyContext( cryptContext );

	/* General test that Unicode conversion is working */
	unicodePasswordLength = convertToUnicode( unicodePassword, 256, 
											  utf8String, 8 );
	if( unicodePasswordLength != 12 || \
		memcmp( unicodePassword, unicodeString, 12 ) )
		{
		DEBUG_PUTS(( "UTF-8 to Windows Unicode conversion via mbstowcs() "
					 "failed." ));
		return( CRYPT_ERROR_FAILED );
		}

#if !( defined( _WIN32 ) || defined( _WIN64 ) )
	setlocale( LC_ALL, locale );
#endif /* !Windows */

	/* Run through each step in GenerateNTResponse() verifying that the 
	   intermediate results are correct */
	unicodePasswordLength = convertToUnicode( unicodePassword, 256, 
											  Password, 10 );
	if( unicodePasswordLength != 20 || \
		memcmp( unicodePassword, UnicodePassword, unicodePasswordLength ) )
		{
		DEBUG_PUTS(( "convertToUnicode() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = ChallengeHash( PeerChallenge, AuthenticatorChallenge,
							UserName, 4, Challenge );
	if( cryptStatusError( status ) || \
		memcmp( Challenge, "\xD0\x2E\x43\x86\xBC\xE9\x12\x26", 8 ) )
		{
		DEBUG_PUTS(( "ChallengeHash() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = NtPasswordHash( UnicodePassword, unicodePasswordLength, 
							 PasswordHash );
	if( cryptStatusError( status ) || \
		memcmp( PasswordHash, "\x44\xEB\xBA\x8D\x53\x12\xB8\xD6" \
							  "\x11\x47\x44\x11\xF5\x69\x89\xAE", 16 ) )
		{
		DEBUG_PUTS(( "NtPasswordHash() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = HashNtPasswordHash( PasswordHash, PasswordHashHash );
	if( cryptStatusError( status ) || \
		memcmp( PasswordHashHash, "\x41\xC0\x0C\x58\x4B\xD2\xD9\x1C"
								  "\x40\x17\xA2\xA1\x2F\xA5\x9F\x3F", 16 ) )
		{
		DEBUG_PUTS(( "HashNtPasswordHash() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = ChallengeResponse( Challenge, PasswordHash, NTResponse );
	if( cryptStatusError( status ) || \
		memcmp( NTResponse, "\x82\x30\x9E\xCD\x8D\x70\x8B\x5E" \
							"\xA0\x8F\xAA\x39\x81\xCD\x83\x54" \
							"\x42\x33\x11\x4A\x3D\x85\xD6\xDF", 24 ) )
		{
		DEBUG_PUTS(( "ChallengeResponse() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}

	/* Now verify that the overall function and its cryptlib wrapper are 
	   correct */
	status = GenerateNTResponse( AuthenticatorChallenge, PeerChallenge, 
								 UserName, 4, UnicodePassword, 20, 
								 NTResponse );
	if( cryptStatusError( status ) || \
		memcmp( NTResponse, "\x82\x30\x9E\xCD\x8D\x70\x8B\x5E" \
							"\xA0\x8F\xAA\x39\x81\xCD\x83\x54" \
							"\x42\x33\x11\x4A\x3D\x85\xD6\xDF", 24 ) )
		{
		DEBUG_PUTS(( "GenerateNTResponse() test failed.\n" ));
		return( CRYPT_ERROR_FAILED  );
		}
	status = eapCreateMSCHAPv2Response( UserName, 4, Password, 10,
										AuthenticatorChallenge, 
										PeerChallenge, NTResponse );
	if( cryptStatusError( status ) || \
		memcmp( NTResponse, "\x82\x30\x9E\xCD\x8D\x70\x8B\x5E" \
							"\xA0\x8F\xAA\x39\x81\xCD\x83\x54" \
							"\x42\x33\x11\x4A\x3D\x85\xD6\xDF", 24 ) )
		{
		DEBUG_PUTS(( "eapCreateMSCHAPv2Response() test failed.\n" ));
		return( CRYPT_ERROR_FAILED  );
		}

	/* Verify that we can generate the correct AuthenticatorResponse */
	status = GenerateAuthenticatorResponse( UnicodePassword, 
											unicodePasswordLength, NTResponse, 
											PeerChallenge,
											AuthenticatorChallenge, UserName,
											AuthenticatorResponse );
	if( cryptStatusError( status ) || \
		memcmp( AuthenticatorResponse,
				"S=407A5589115FD0D6209F510FE9C04566932CDA56", 42 ) )
		{
		DEBUG_PUTS(( "GenerateAuthenticatorResponse() test failed.\n" ));
		return( CRYPT_ERROR_FAILED  );
		}
	status = eapCreateAuthenticatorResponse( UserName, 4, Password, 10,
											 AuthenticatorChallenge, 
											 PeerChallenge,
											 NTResponse, 
											 AuthenticatorResponse );
	if( cryptStatusError( status ) || \
		memcmp( AuthenticatorResponse,
				"S=407A5589115FD0D6209F510FE9C04566932CDA56", 42 ) )
		{
		DEBUG_PUTS(( "eapCreateAuthenticatorResponse() test failed.\n" ));
		return( CRYPT_ERROR_FAILED  );
		}

	return( CRYPT_OK );
	}

/* Test the MPPE key derivation implementation using the test vectors from 
   RFC 3079:

	UserName = "User"
    55 73 65 72

	Password = "clientPass"
	63 00 6C 00 69 00 65 00 6E 00 74 00 50 00 61 00 73 00 73 00

	AuthenticatorChallenge
	5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28

	PeerChallenge
	21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E

	NT-Response:
	82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF

	PasswordHash:
	44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE

	PasswordHashHash
	41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F

	MasterKey
	FD EC E3 71 7A 8C 83 8C B3 88 E5 27 AE 3C DD 31
	
	SendStartKey128
	8B 7C DC 14 9B 99 3A 1B A1 18 CB 15 3F 56 DC CB */

static int testMPPE( void )
	{
	static const char *Password = "clientPass";
	static const char *UserName = "User";
	static const BYTE AuthenticatorChallenge[ 16 ] = {
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28
		};
	static const BYTE PeerChallenge[ 16 ] = {
		0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
		0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E
		};
	static const BYTE eapolPassword[] = {
		0x70, 0x61, 0x73, 0x73				/* "pass" */
		};
	static const BYTE eapolNTResponse[ 24 ] = {
		0xA6, 0xBA, 0xEB, 0xE7, 0x88, 0xE5, 0xC0, 0xCD,
		0x70, 0x5F, 0xB3, 0xFD, 0x3E, 0x81, 0x2A, 0x2F,
		0xF6, 0x99, 0xA3, 0x44, 0x93, 0xFB, 0x51, 0x26
		};
	static const BYTE eapolISK[ 32 ] = {
		0x47, 0x24, 0x09, 0x4C, 0xEC, 0xAA, 0x4F, 0x8A, 
		0xBD, 0x5B, 0x00, 0xC9, 0x4E, 0x28, 0xAB, 0xC2, 
		0x7F, 0x70, 0x2B, 0x80, 0x09, 0x95, 0x3A, 0x71, 
		0x1A, 0x63, 0x0D, 0xF9, 0x39, 0x19, 0x36, 0xAE
		};
	BYTE unicodePassword[ 256 ], PasswordHash[ 16 ], NTResponse[ 24 ];
	BYTE PasswordHashHash[ 16 ], MasterKey[ 16 ], SessionKey[ 16 ], ISK[ 32 ];
	BYTE eapolUnicodePassword[ 16 ], eapolPasswordHash[ 16 ];
	int unicodePasswordLength, eapolUnicodePasswordLength, status;

	/* Generate the NTResponse from the Password and Challenge as a self-
	   check that the input to the RFC 3079 computations are correct */
	unicodePasswordLength = convertToUnicode( unicodePassword, 256, 
											  Password, strlen( Password ) );
	status = GenerateNTResponse( AuthenticatorChallenge, PeerChallenge, 
								 UserName, strlen( UserName ), 
								 unicodePassword, unicodePasswordLength, 
								 NTResponse );
	if( cryptStatusError( status ) || \
		memcmp( NTResponse, "\x82\x30\x9E\xCD\x8D\x70\x8B\x5E"
							"\xA0\x8F\xAA\x39\x81\xCD\x83\x54"
							"\x42\x33\x11\x4A\x3D\x85\xD6\xDF", 24 ) )
		{
		DEBUG_PUTS(( "GenerateNTResponse() sanity check for RFC 3079 test "
					 "failed." ));
		return( CRYPT_ERROR_FAILED );
		}

	/* Run through the tests using the values from RFC 3079 */
	status = NtPasswordHash( unicodePassword, unicodePasswordLength, 
							 PasswordHash );
	if( cryptStatusError( status ) || \
		memcmp( PasswordHash, "\x44\xEB\xBA\x8D\x53\x12\xB8\xD6", 8 ) )
		{
		DEBUG_PUTS(( "NtPasswordHash() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = HashNtPasswordHash( PasswordHash, PasswordHashHash );
	if( cryptStatusError( status ) || \
		memcmp( PasswordHashHash, "\x41\xC0\x0C\x58\x4B\xD2\xD9\x1C", 8 ) )
		{
		DEBUG_PUTS(( "HashNtPasswordHash() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = GetMasterKey( PasswordHashHash, NTResponse, MasterKey );
	if( cryptStatusError( status ) || \
		memcmp( MasterKey, "\xFD\xEC\xE3\x71\x7A\x8C\x83\x8C", 8 ) )
		{
		DEBUG_PUTS(( "GetMasterKey() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = GetAsymetricStartKey( MasterKey, SessionKey, 16, TRUE, TRUE );
	if( cryptStatusError( status ) || \
		memcmp( SessionKey, "\x8B\x7C\xDC\x14\x9B\x99\x3A\x1B", 8 ) )
		{
		DEBUG_PUTS(( "GetAsymetricStartKey() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}

	/* Now run the tests again using test data from eapol_test */
	eapolUnicodePasswordLength = \
		convertToUnicode( eapolUnicodePassword, 16, eapolPassword, 4 );
	NtPasswordHash( eapolUnicodePassword, eapolUnicodePasswordLength, 
					eapolPasswordHash );
	HashNtPasswordHash( eapolPasswordHash, PasswordHashHash );
	status = GetMasterKey( PasswordHashHash, eapolNTResponse, MasterKey );
	if( cryptStatusError( status ) || \
		memcmp( MasterKey, "\xCF\x53\x2C\x21\xFC\xD0\x48\x7F", 8 ) )
		{
		DEBUG_PUTS(( "GetMasterKey() (eapol_test) test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	status = GetAsymetricStartKey( MasterKey, ISK, 16, TRUE, FALSE );
	if( cryptStatusOK( status ) )
		status = GetAsymetricStartKey( MasterKey, ISK + 16, 16, FALSE, FALSE );
	if( cryptStatusError( status ) || \
		memcmp( ISK, eapolISK, 32 ) )
		{
		DEBUG_PUTS(( "GetAsymetricStartKey() (eapol_test) test failed." ));
		return( CRYPT_ERROR_FAILED );
		}

	/* Finally, make sure that the single-step function produces the same 
	   result */
	status = eapCreateISK( ISK, eapolPassword, 4, eapolNTResponse );
	if( cryptStatusError( status ) || \
		memcmp( ISK, eapolISK, 32 ) )
		{
		DEBUG_PUTS(( "eapCreateISK() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}

	return( CRYPT_OK );
	}

/* Test the Crypto-Binding implementation using test data from eapol_test */

static int testCryptoBindings( void )
	{
	static const BYTE eapolTK[] = {		/* EAP handshake secret, 60 bytes */
		0x24, 0xF3, 0xC4, 0xCF, 0xF9, 0x19, 0x21, 0x49,
		0xD9, 0x60, 0xE8, 0x0B, 0x87, 0xF4, 0x60, 0xBA,
		0x0C, 0x70, 0xD7, 0xA3, 0xF1, 0xE4, 0xCF, 0x79,
		0x37, 0xE2, 0xB0, 0x99, 0xA4, 0xF1, 0xC7, 0x3F,
		0x39, 0xA2, 0xB1, 0x7B, 0x28, 0xBB, 0x06, 0x5B,
		0xEF, 0xA1, 0x3F, 0x6C, 0x54, 0x05, 0x0C, 0x3C,
		0xA6, 0x96, 0x9D, 0xBC, 0xB1, 0xEE, 0xBC, 0xED,
		0x3D, 0x21, 0xC1, 0xF8
		};
	static const BYTE eapolISK[] = {	/* From testMPPE() above, 32 bytes */
		0x47, 0x24, 0x09, 0x4C, 0xEC, 0xAA, 0x4F, 0x8A,
		0xBD, 0x5B, 0x00, 0xC9, 0x4E, 0x28, 0xAB, 0xC2,
		0x7F, 0x70, 0x2B, 0x80, 0x09, 0x95, 0x3A, 0x71,
		0x1A, 0x63, 0x0D, 0xF9, 0x39, 0x19, 0x36, 0xAE
		};
	static const BYTE eapolIPMK[] = {	/* IPMK from TK and ISK, 40 bytes */
		0x2A, 0x9D, 0x7D, 0xD0, 0x3F, 0x7F, 0xB4, 0x95,
		0x03, 0x56, 0xCA, 0x2A, 0xF5, 0x3A, 0x69, 0xAF,
		0xD2, 0x05, 0xEA, 0xE3, 0x67, 0x32, 0xCF, 0xE5,
		0xFD, 0xEB, 0x1A, 0x84, 0x64, 0x4E, 0xE4, 0xFD,
		0x0B, 0xBC, 0x82, 0x6E, 0x06, 0x04, 0x0F, 0xBF
		};
	static const BYTE eapolCMK[] = {	/* CMK from TK and ISK, 20 bytes */
		0x71, 0x86, 0xE1, 0x36, 0xE1, 0x1C, 0x77, 0x78,
		0x27, 0x02, 0x9A, 0x7F, 0xF6, 0x3B, 0x32, 0xD2,
		0xD0, 0x8A, 0x30, 0xCB
		};
	static const BYTE eapolMacDataRx[] = {
		0x00, 0x0C,					/* Type = 12 = Crypto-Binding */
		0x00, 0x38,					/* Length = 56 */
		0x00, 0x00, 0x00,			/* Reserved, SendVersion, RecvVersion */
		0x00,						/* 00 = Request, 01 = Response */ 
		/* 32-byte nonce */
		0xF0, 0x17, 0xA9, 0xB5, 0x90, 0x9F, 0xC8, 0xFC, 
		0x26, 0x1D, 0x7A, 0x53, 0x0E, 0x45, 0x6B, 0xC4, 
		0xFB, 0xA2, 0x2F, 0x6C, 0x60, 0x29, 0x0E, 0x58, 
		0x56, 0xF5, 0x32, 0x91, 0x6D, 0x25, 0xE3, 0x91, 
		/* 20-byte HMAC value zeroed out */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00
		};
	static const BYTE eapolCMACRx[] = {	/* CMAC of above, 20 bytes */
		0x13, 0xE7, 0x8A, 0x8A, 0x70, 0x6B, 0xEE, 0x8D,
		0x46, 0xA5, 0x31, 0x6C, 0x9D, 0xF3, 0x4A, 0x86,
		0x6E, 0x93, 0x7A, 0x9B
		};
	static const BYTE eapolMacDataTx[] = {
		0x00, 0x0C,					/* Type = 12 = Crypto-Binding */
		0x00, 0x38,					/* Length = 56 */
		0x00, 0x00, 0x00,			/* Reserved, SendVersion, RecvVersion */
		0x01,						/* 00 = Request, 01 = Response */ 
		/* 32-byte nonce */
		0xF0, 0x17, 0xA9, 0xB5, 0x90, 0x9F, 0xC8, 0xFC, 
		0x26, 0x1D, 0x7A, 0x53, 0x0E, 0x45, 0x6B, 0xC4, 
		0xFB, 0xA2, 0x2F, 0x6C, 0x60, 0x29, 0x0E, 0x58, 
		0x56, 0xF5, 0x32, 0x91, 0x6D, 0x25, 0xE3, 0x91, 
		/* 20-byte HMAC value zeroed out */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00
		};
	static const BYTE eapolCMACTx[] = {	/* CMAC of above, 20 bytes */
		0x54, 0x4E, 0xF7, 0x77, 0x78, 0xC6, 0x36, 0x0A, 
		0x5E, 0xB2, 0x1A, 0xAC, 0xE2, 0x76, 0xE0, 0xA5, 
		0x4B, 0x97, 0x86, 0x44
		};
	BYTE ipmk[ 40 ], cmk[ 20 ], cmac[ 20 ];
	int status;

	/* Turn the TK and ISK into the CMK */
	status = eapCreateCMK( ipmk, cmk, eapolTK, eapolISK );
	if( cryptStatusError( status ) )
		{
		DEBUG_PUTS(( "eapCreateCMK() test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	if( memcmp( ipmk, eapolIPMK, 40 ) || \
		memcmp( cmk, eapolCMK, 20 ) )
		{
		DEBUG_PUTS(( "IPMK/CMK test failed.\n" ));
		return( CRYPT_ERROR_FAILED  );
		}

	/* Check the CMAC on the received message */
	status = eapCreateCMAC( cmac, cmk, eapolMacDataRx, 60 );
	if( cryptStatusError( status ) )
		{
		DEBUG_PUTS(( "eapCreateCMAC() request test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	if( memcmp( cmac, eapolCMACRx, 20 ) )
		{
		DEBUG_PUTS(( "Compouned MAC Rx test failed.\n" ));
		return( CRYPT_ERROR_FAILED  );
		}

	/* Create the CMAC on the sent message */
	status = eapCreateCMAC( cmac, cmk, eapolMacDataTx, 60 );
	if( cryptStatusError( status ) )
		{
		DEBUG_PUTS(( "eapCreateCMAC() respponse test failed." ));
		return( CRYPT_ERROR_FAILED );
		}
	if( memcmp( cmac, eapolCMACTx, 20 ) )
		{
		DEBUG_PUTS(( "Compouned MAC Tx test failed.\n" ));
		return( CRYPT_ERROR_FAILED  );
		}

	return( CRYPT_OK );
	}

/* Run a self-test of the MSCHAPv2, MPPE, and Crypto-Binding code to verify 
   that we're getting the correct values */

int testEAPCrypto( void )
	{
	int status;

	status = testMSCHAPv2();
	if( cryptStatusError( status ) )
		{
		printf( "MSCHAPv2 self-test failed, status = %d.\n", status );
		return( FALSE );
		}
	status = testMPPE();
	if( cryptStatusError( status ) )
		{
		printf( "MPPE self-test failed, status = %d.\n", status );
		return( FALSE );
		}
	status = testCryptoBindings();
	if( cryptStatusError( status ) )
		{
		printf( "Crypto-Binding self-test failed, status = %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* USE_EAP */
