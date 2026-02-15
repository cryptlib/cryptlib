/****************************************************************************
*																			*
*				cryptlib RSA Key Generation/Checking Routines				*
*						Copyright Peter Gutmann 1997-2024					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#include "crypt.h"
#if defined( INC_ALL )
  #include "context.h"
  #include "keygen.h"
#else
  #include "context/context.h"
  #include "context/keygen.h"
#endif /* Compiler-specific includes */

/* We use F4 as the default public exponent e unless the user chooses to
   override this with some other value:

	Fn = 2^(2^n) + 1, n = 0...4.

	F0 = 3, F1 = 5, F2 = 17, F3 = 257, F4 = 65537.
   
   The older (X.509v1) recommended value of 3 is insecure for general use 
   and even if used very carefully at risk due to the likes of Coppersmith's
   and Bleichenbacher's low-exponent attacks, and more recent work indicates 
   that values like 17 (used by PGP) are also insecure against the Hastad 
   attack.  We could work around this by using 41 or 257 as the exponent, 
   however current best practice favours F4 unless you're doing banking 
   standards, in which case you set e=2 (EMV) and use raw, unpadded RSA 
   (HBCI) to make it easier for students to break your banking security as a 
   homework exercise */

#ifndef RSA_PUBLIC_EXPONENT
  #define RSA_PUBLIC_EXPONENT		65537L
#endif /* RSA_PUBLIC_EXPONENT */

/* The minimum allowed public exponent.  In theory this could go as low as 3
   (and in fact a GoDaddy root cert for "Go Daddy Class 2 Certification 
   Authority" from 2004 still uses this value and won't expire until 2034), 
   however there are all manner of obscure corner cases that have to be 
   checked if this exponent is used and in general the necessary checking 
   presents a more or less intractable problem.  
   
   To avoid this minefield we require a minimum exponent of at 17, the next 
   generally-used value above 3.  However even this is only used by PGP 2.x, 
   the next minimum is 33 (a weird value used by OpenSSH until mid-2010, see 
   the comment further down), 41 (another weird value used by GPG until 
   mid-2006), and then 257 or (in practice) F4 / 65537 by everything else */

#if defined( USE_PGP ) || defined( USE_PGPKEYS )
  #define MIN_PUBLIC_EXPONENT		17
#elif defined( USE_SSH )
  #define MIN_PUBLIC_EXPONENT		33
#else
  #define MIN_PUBLIC_EXPONENT		257
#endif /* Smallest exponents used by various crypto protocols */
#if ( MIN_PUBLIC_EXPONENT <= 0xFF && RSAPARAM_MIN_E > 1 ) || \
	( MIN_PUBLIC_EXPONENT <= 0xFFFF && RSAPARAM_MIN_E > 2 )
  #error RSAPARAM_MIN_E is too large for MIN_PUBLIC_EXPONENT
#endif /* MIN_PUBLIC_EXPONENT size > RSAPARAM_MIN_E value */

/****************************************************************************
*																			*
*							Utility Functions								*
*																			*
****************************************************************************/

/* Enable various side-channel protection mechanisms */

#if defined( __WINCE__ ) && defined( ARMV4 ) && defined( NDEBUG )
  #pragma optimize( "g", off )
#endif /* eVC++ 4.0 ARMv4 optimiser bug */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int enableSidechannelProtection( INOUT_PTR PKC_INFO *pkcInfo, 
										IN_BOOL const BOOLEAN isPrivateKey )
	{
	const BIGNUM *n = &pkcInfo->rsaParam_n, *e = &pkcInfo->rsaParam_e;
	BIGNUM *k = &pkcInfo->rsaParam_blind_k;
	BIGNUM *kInv = &pkcInfo->rsaParam_blind_kInv;
	MESSAGE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
	int noBytes = bitsToBytes( pkcInfo->keySizeBits );
	int bnStatus = BN_STATUS, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( isBooleanValue( isPrivateKey ) );

	/* Generate a random bignum for blinding.  Since this merely has to be 
	   unpredictable to an outsider but not cryptographically strong, and to 
	   avoid having more crypto RNG output than necessary sitting around in 
	   memory, we get it from the nonce PRNG rather than the crypto one.  In
	   addition we don't have to perform a range check on import to see if 
	   it's larger than 'n' since we're about to reduce it mod n in the next 
	   step, and doing so would give false positives */
	setMessageData( &msgData, buffer, noBytes );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusOK( status ) )
		{
		buffer[ 0 ] &= 0xFF >> ( -pkcInfo->keySizeBits & 7 );
		status = importBignum( k, buffer, noBytes, MIN_PKCSIZE - 8, 
							   CRYPT_MAX_PKCSIZE, NULL, 
							   BIGNUM_CHECK_VALUE );
		}
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the blinding and unblinding values */
	CK( BN_mod( k, k, n, &pkcInfo->bnCTX ) );	/* k = rand() mod n */
	CKPTR( BN_mod_inverse( kInv, k, n, &pkcInfo->bnCTX ) );
												/* kInv = k^-1 mod n */
	CK( BN_mod_exp_mont( k, k, e, n, &pkcInfo->bnCTX,
						 &pkcInfo->rsaParam_mont_n ) );
												/* k = k^e mod n */
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Use constant-time modexp() to protect the private key from timing 
	   channels if required */
	if( isPrivateKey )
		{
		BN_set_flags( &pkcInfo->rsaParam_exponent1, BN_FLG_CONSTTIME );
		BN_set_flags( &pkcInfo->rsaParam_exponent2, BN_FLG_CONSTTIME );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

#if defined( __WINCE__ ) && defined( ARMV4 ) && defined( NDEBUG )
  #pragma optimize( "g", on )
#endif /* eVC++ 4.0 ARMv4 optimiser bug */

/* Adjust p and q if necessary to ensure that the CRT decrypt works.  We 
   could in theory do this for our own keys by setting the top bits of p to 
   111 and q to 110 in generatePrimeRSA(), but this still requires the use
   of fixCRTvalues() for keys from elsewhere, and it's better to have a 
   single code path for all keys */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int fixCRTvalues( INOUT_PTR PKC_INFO *pkcInfo, 
						 IN_BOOL const BOOLEAN fixPKCSvalues )
	{
	BIGNUM *p = &pkcInfo->rsaParam_p, *q = &pkcInfo->rsaParam_q;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( isBooleanValue( fixPKCSvalues ) );

	/* Make sure that p > q, which is required for the CRT decrypt */
	if( BN_cmp( p, q ) > 0 )
		return( CRYPT_OK );

	/* Swap the values p and q and, if necessary, the PKCS parameters e1
	   and e2 that depend on them (e1 = d mod (p - 1) and
	   e2 = d mod (q - 1)), and recompute u = qInv mod p */
	BN_swap( p, q );
	if( fixPKCSvalues )
		{
		BN_swap( &pkcInfo->rsaParam_exponent1, 
				 &pkcInfo->rsaParam_exponent2 );
		CKPTR( BN_mod_inverse( &pkcInfo->rsaParam_u, q, p,
							   &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		}
	ENSURES( BN_cmp( p, q ) > 0 );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Evaluate the Montgomery forms for public and private components */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int getRSAMontgomery( INOUT_PTR PKC_INFO *pkcInfo, 
							 IN_BOOL const BOOLEAN isPrivateKey )
	{
	int bnStatus = BN_STATUS;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( isBooleanValue( isPrivateKey ) );

	/* Evaluate the public value */
	CK( BN_MONT_CTX_set( &pkcInfo->rsaParam_mont_n, &pkcInfo->rsaParam_n,
						 &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( !isPrivateKey )
		return( CRYPT_OK );

	/* Evaluate the private values */
	CK( BN_MONT_CTX_set( &pkcInfo->rsaParam_mont_p, &pkcInfo->rsaParam_p,
						 &pkcInfo->bnCTX ) );
	CK( BN_MONT_CTX_set( &pkcInfo->rsaParam_mont_q, &pkcInfo->rsaParam_q,
						 &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Check whether a public key has too-close prime factors using Fermat's 
   factorisation method.  This should never happen, but apparently did for
   keys from some printer manufacturers:

	a = ceil( sqrt( n ) );
	b2 = a^2 - n;
	repeat until b2 is a square:
		a = a + 1;
		b2 = a^2 - n;
   
   We can quickly weed out most candidates for squares by checking whether 
   the input is a quadratic residue mod 256, and theoretically take it even 
   further by testing mod small primes, but the initial test weeds out most 
   candidates already.
   
   Table generated with:

	BYTE table[ 32 ];
	int i;
	
	memset( table, 0, 64 );
	for( i = 0; i < 0x100; i++ )
		{
		int value, index, bit;
		
		value = ( i * i ) % 0x100;
		index = value / 8;
		bit = 1 << ( value % 8 );
		table[ index ] |= bit;
		}
	for( i = 0; i < 32; i++ )
		{
		if( i > 0 && ( i % 8 ) == 0 )
			printf( "\n" );
		printf( "0x%02X, ", table[ i ] );
		} 

   This has 44 entries so we weed out 82% of values with this check */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkPrimeFactors( INOUT_PTR PKC_INFO *pkcInfo )
	{
	static const BYTE residueTable[ 32 ] = {
		0x13, 0x02, 0x03, 0x02, 0x12, 0x02, 0x02, 0x02,
		0x13, 0x02, 0x02, 0x02, 0x12, 0x02, 0x02, 0x02,
		0x12, 0x02, 0x03, 0x02, 0x12, 0x02, 0x02, 0x02,
		0x12, 0x02, 0x02, 0x02, 0x12, 0x02, 0x02, 0x02
		};
	const BIGNUM *n = &pkcInfo->rsaParam_n;
	BIGNUM *a, *b2, *tmp; 
	BN_CTX *bnCTX = &pkcInfo->bnCTX;
	BN_ULONG lsWord;
	int bnStatus = BN_STATUS;
	LOOP_INDEX i;

	assert( isReadPtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	BN_CTX_start( bnCTX );
	a = BN_CTX_get( bnCTX );
	b2 = BN_CTX_get( bnCTX );
	tmp = BN_CTX_get( bnCTX );
	if( a == NULL || b2 == NULL || tmp == NULL )
		{
		BN_CTX_end( bnCTX );
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* a = ceil( sqrt( n ) );
		 = sqrt( n ) + 1;
	   b2 = a^2 - n */
	CK( BN_isqrt( a, n, bnCTX ) );
	CK( BN_add_word( a, 1 ) );
	CK( BN_sqr( b2, a, bnCTX ) );
	CK( BN_sub( b2, b2, n ) );
	if( bnStatusError( bnStatus ) )
		{
		BN_CTX_end( bnCTX );
		return( bnStatus );
		}

	/* Perform n iterations of the Fermat factorisation:

		repeat until b2 is a square:
			a = a + 1;
			b2 = a^2 - n;

	   Note that we can merge this with the initialisation step above 
	   because of the way ceil( n ) is calculated, but we keep it distinct 
	   in order to follow the pseudocode */
	LOOP_MED( i = 0, i < 20, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 20 - 1 ) );

		/* Check whether it's a perfect square by performing an initial 
		   quadratic residue test via the residue table bitmap before going 
		   on to the full test */
		lsWord = b2->d[ 0 ] % 0x100;
		if( residueTable[ lsWord / 8 ] & ( 1 << ( lsWord % 8 ) ) )
			{
			CK( BN_isqrt( tmp, b2, bnCTX ) );
			CK( BN_sqr( tmp, tmp, bnCTX ) );
			if( !BN_cmp( b2, tmp ) )
				{
				/* It's a square, the factors are sqrt( b2 ) + a, 
				   sqrt( b2 ) - a */
				DEBUG_DIAG(( "Prime factors for public key found" ));
				return( CRYPT_ERROR_NOSECURE );
				}
			}

		CK( BN_add_word( a, 1 ) );
		CK( BN_sqr( b2, a, bnCTX ) );
		CK( BN_sub( b2, b2, n ) );
		if( bnStatusError( bnStatus ) )
			{
			BN_CTX_end( bnCTX );
			return( bnStatus );
			}
		}
	ENSURES( LOOP_BOUND_OK );
		
	return( CRYPT_OK );
	}

#ifdef CHECK_PRIMETEST

int rsaTestFactors( INOUT_PTR PKC_INFO *pkcInfo )
	{
	static const BYTE testValue1[ 4 ] = {
		/* Small values that can be verified by hand.  The reason why some
		   of the values take a large number of rounds is because Fermat's 
		   method works best if the two factors share half their leading 
		   bits, in other words that the gap between them is less than 
		   isqrt( n ) */
		/* 101 * 59 = 5959 = 0x1747, 3 rounds */
		/* 0x00, 0x00, 0x17, 0x47 */
		/* 10501 * 14753 = 154921253 = 0x93BE925, 180 rounds */
		/* 0x09, 0x3B, 0xE9, 0x25 */
		/* 12263 * 17137 = 210151031 = 0xC86A677, 203 rounds */
		/* 0x0C, 0x86, 0xA6, 0x77 */
		/* 54323 * 57641 = 3131232043 = 0xBAA2CF2B, 24 rounds */
		0xBA, 0xA2, 0xCF, 0x2B
		};
	static const BYTE testValue2[ 128 ] = {
		/* Test value from 
		   https://wiremask.eu/articles/fermats-prime-numbers-factorization,
		   7422236843002619998657542152935407597465626963556444983366482781089760760914403641211700959458736191688739694068306773186013683526913015038631710959988771
		   = 8DB72351E42D5E717ED7C317D06C4B3A6166CB1AAD0B1407C472E6DC8B34 F9488BF0A0CB68FD652D93E54E882A4FB1ECA7CAF8CD9B014D4F4FAE1FC4EE51F023
		   7422236843002619998657542152935407597465626963556444983366482781089760759017266051147512413638949173306397011800331344424158682304439958652982994939276427
		   = 8DB72351E42D5E717ED7C317D06C4B3A6166CB1AAD0B1407C472E6DC8B34 B9488BF0A0CB68FD652D93E54E882A4FB1ECA7CAF8CD9B014D4F4FAE1FC4EE51EC8B
		   found in ?? steps */
		0x4E, 0x73, 0x3F, 0xEB, 0xB9, 0x4D, 0xB1, 0x7C,
		0xA3, 0xE6, 0xAA, 0x26, 0xEC, 0x33, 0xB4, 0x96,
		0x0C, 0x15, 0x0C, 0x52, 0x30, 0x0E, 0x06, 0xC6,
		0x0B, 0x33, 0x18, 0xF0, 0x74, 0x4F, 0xEF, 0x2D,
		0x68, 0x7A, 0x8F, 0x5B, 0xF5, 0x98, 0x89, 0x4A,
		0x22, 0xEE, 0xC4, 0xAB, 0xDA, 0xE0, 0x1B, 0x19,
		0x7E, 0x4C, 0xC5, 0x60, 0x3D, 0xE6, 0x7E, 0xB6,
		0x70, 0xE2, 0x61, 0xEB, 0x4E, 0x4C, 0xC5, 0xE2,
		0x62, 0x41, 0xED, 0xCD, 0xE4, 0x94, 0xCC, 0xE4,
		0x15, 0xBB, 0xC5, 0xA4, 0x10, 0xAB, 0xCE, 0xFD,
		0xFF, 0x61, 0x99, 0xBB, 0xCD, 0xF6, 0x2E, 0x9D,
		0x43, 0x4F, 0xAA, 0x88, 0xA1, 0xD1, 0x60, 0x12,
		0x52, 0x0F, 0x80, 0xD1, 0x26, 0x20, 0x82, 0x06,
		0xFF, 0x80, 0x19, 0x1E, 0x20, 0xED, 0x74, 0x23,
		0xCD, 0xCE, 0x5B, 0x8A, 0x55, 0x5B, 0x41, 0x61,
		0x53, 0x4E, 0x78, 0x9A, 0x74, 0xF0, 0xA7, 0x01
		};
	static const BYTE testValue3[ 128 ] = {
		/* Test value from 
		   https://github.com/letsencrypt/boulder/blob/main/goodkey/good_key_test.go,
		   two very close factors, 
		   12451309173743450529024753538187635497858772172998414407116324997634262083672423797183640278969532658774374576700091736519352600717664126766443002156788367
		   = EDBCBB418B43DC58EB31BA2BC8276AA99062E432BCC1A9E84845DC3EAB23BE9489892EBFBF547E11D3B6310E94F482977986EF750BFA2B1CA3074EA9035BAA 8F
		   12451309173743450529024753538187635497858772172998414407116324997634262083672423797183640278969532658774374576700091736519352600717664126766443002156788337
		   = EDBCBB418B43DC58EB31BA2BC8276AA99062E432BCC1A9E84845DC3EAB23BE9489892EBFBF547E11D3B6310E94F482977986EF750BFA2B1CA3074EA9035BAA 71
		   found in 1 step */
		0xDC, 0xC6, 0xFD, 0xDA, 0xED, 0x19, 0x03, 0xE5, 
		0x6E, 0x36, 0x13, 0xC6, 0x39, 0xBF, 0x85, 0x5A,
		0xD8, 0xC0, 0x34, 0xD9, 0x67, 0x36, 0x32, 0x20, 
		0x78, 0x03, 0x01, 0x73, 0x6B, 0xE6, 0x40, 0xDA,
		0x25, 0x8E, 0xAE, 0x2C, 0x29, 0x81, 0x7A, 0x77, 
		0xD8, 0x22, 0x16, 0x9C, 0xA0, 0x8C, 0x47, 0xE9,
		0x67, 0x45, 0x5C, 0x95, 0x42, 0xD1, 0x8C, 0x1C, 
		0xCC, 0x87, 0x31, 0x7C, 0x43, 0x09, 0x75, 0xF8,
		0x9E, 0x96, 0xDC, 0xE7, 0x5E, 0x44, 0x29, 0x4C, 
		0x6D, 0x28, 0x5C, 0x96, 0x75, 0xAA, 0xB0, 0x98,
		0x07, 0xA9, 0x53, 0x9F, 0xDD, 0xD1, 0xA4, 0x68, 
		0xAF, 0xBA, 0x08, 0xA2, 0x23, 0xF1, 0x0D, 0xC5,
		0x1F, 0xC0, 0x09, 0x62, 0x5A, 0x9B, 0xC6, 0xEF, 
		0x43, 0xB0, 0x65, 0x6F, 0x8C, 0x2A, 0x75, 0xE6,
		0x66, 0x61, 0x93, 0x2A, 0x29, 0x04, 0xA3, 0xC3, 
		0x9D, 0xF8, 0x63, 0xD1, 0xA8, 0x8E, 0x3F, 0x1F
		};
	static const BYTE testValue4[ 128 ] = {
		/* Test value from 
		   https://github.com/letsencrypt/boulder/blob/main/goodkey/good_key_test.go,
		   two very factors that differ by around 2^256, 
		   11779932606551869095289494662458707049283241949932278009554252037480401854504909149712949171865707598142483830639739537075502512627849249573564209082969463
		   = E0EB1C756F901043799F4B219BDB9C8424758C142D0A9CD0C44E2C60DC73CB 72A0742E1BAF3B79573824F18A760E929D3C41B833A6859A37CFF088B9EE28AD77
		   11779932606551869095289494662458707049283241949932278009554252037480401854503793357623711855670284027157475142731886267090836872063809791989556295953329083
		   = E0EB1C756F901043799F4B219BDB9C8424758C142D0A9CD0C44E2C60DC73CB 68FD983CD8CF6EFEA054CE5E63AE8A5F2A924CE5E3484B5A37CFF088B9EE28ABBB
		   found in 14 steps */
		0xC5, 0x9C, 0x49, 0xBA, 0xC6, 0x00, 0xD5, 0x3A,
		0x9E, 0x93, 0xED, 0x63, 0x94, 0xE7, 0xF5, 0x41,
		0x92, 0xE7, 0xE5, 0xB7, 0x69, 0xE1, 0x08, 0x23,
		0x2B, 0x71, 0xCA, 0xDC, 0x68, 0xFD, 0xE5, 0xFF,
		0xE2, 0x8F, 0x68, 0x9B, 0x43, 0x57, 0xF6, 0xBD,
		0x6E, 0xA9, 0xA8, 0x64, 0xE6, 0x4B, 0x85, 0x92,
		0x3A, 0xD4, 0x78, 0x3B, 0xF9, 0x71, 0x15, 0xB7,
		0x70, 0x14, 0x69, 0x63, 0x44, 0x66, 0xC4, 0x2D,
		0xCC, 0x0D, 0x89, 0xFC, 0x9A, 0xA7, 0x17, 0x88,
		0xF1, 0x1A, 0xA3, 0xE0, 0xEB, 0x7A, 0xC9, 0xD0,
		0xBE, 0xB0, 0xB0, 0x93, 0x45, 0x89, 0xAB, 0xAE,
		0x9D, 0xBF, 0x5C, 0xEF, 0x6F, 0x66, 0x34, 0x34,
		0x44, 0xF0, 0x69, 0xEF, 0x19, 0xDC, 0xE2, 0x3A,
		0x40, 0x2D, 0xF3, 0x8C, 0x55, 0x26, 0xBD, 0xD2,
		0x41, 0xA3, 0x08, 0xF7, 0x32, 0x92, 0xE5, 0x36,
		0x58, 0x9B, 0xAC, 0x84, 0xE0, 0x2D, 0x32, 0xED
		};
	int status;

	BN_clear( &pkcInfo->rsaParam_n );
	status = importBignum( &pkcInfo->rsaParam_n, testValue1, 4, 
						   1, CRYPT_MAX_PKCSIZE, NULL, BIGNUM_CHECK_NONE );
	ENSURES( cryptStatusOK( status ) );
	checkPrimeFactors( pkcInfo );		/* 24 rounds */

	BN_clear( &pkcInfo->rsaParam_n );
	status = importBignum( &pkcInfo->rsaParam_n, testValue2, 128, 
						   3, CRYPT_MAX_PKCSIZE, NULL, BIGNUM_CHECK_NONE );
	ENSURES( cryptStatusOK( status ) );
	checkPrimeFactors( pkcInfo );		/* ?? rounds */

	BN_clear( &pkcInfo->rsaParam_n );
	status = importBignum( &pkcInfo->rsaParam_n, testValue3, 128, 
						   3, CRYPT_MAX_PKCSIZE, NULL, BIGNUM_CHECK_NONE );
	ENSURES( cryptStatusOK( status ) );
	checkPrimeFactors( pkcInfo );		/* 1 round */

	BN_clear( &pkcInfo->rsaParam_n );
	status = importBignum( &pkcInfo->rsaParam_n, testValue4, 128, 
						   3, CRYPT_MAX_PKCSIZE, NULL, BIGNUM_CHECK_NONE );
	ENSURES( cryptStatusOK( status ) );
	checkPrimeFactors( pkcInfo );		/* 14 rounds */

	return( CRYPT_OK );
	}
#endif /* CHECK_PRIMETEST */

/****************************************************************************
*																			*
*							Check an RSA Key								*
*																			*
****************************************************************************/

/* Perform validity checks on the public key.  We have to make the PKC_INFO
   data non-const because the bignum code wants to modify some of the values
   as it's working with them */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkRSAPublicKeyComponents( INOUT_PTR PKC_INFO *pkcInfo,
										IN_BOOL const BOOLEAN isPrivateKey )
	{
	BIGNUM *n = &pkcInfo->rsaParam_n, *e = &pkcInfo->rsaParam_e;
	const BN_ULONG eWord = BN_get_word( e );
	const int eLen = BN_num_bits( e );
	int length;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( isBooleanValue( isPrivateKey ) );
	REQUIRES( eLen > 0 && eLen <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Verify that nLen >= RSAPARAM_MIN_N (= MIN_PKCSIZE), 
	   nLen <= RSAPARAM_MAX_N (= CRYPT_MAX_PKCSIZE) */
	length = BN_num_bytes( n );
	if( isShortPKCKey( length ) )
		{
		/* Special-case handling for insecure-sized public keys */
		return( CRYPT_ERROR_NOSECURE );
		}
	if( length < RSAPARAM_MIN_N || length > RSAPARAM_MAX_N )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that n is not (obviously) composite */
	if( !primeCheckQuick( n ) )
		{
		DEBUG_DIAG(( "RSA n value is not prime" ));
		return( CRYPT_ARGERROR_STR1 );
		}

	/* Another test that we could apply here is to check whether n is the 
	   product of two identical primes, i.e. a square.  To do this we'd use 
	   a probabalistic test involving computing the Legendre symbol with a 
	   series of small primes p, i.e. checking whether n^((p-1)/2) = 1 (mod 
	   p).  If n is a perfect square then n mod p will be a quadratic 
	   residue, if not then the probability of it being a quadratic residue 
	   is around 0.5, so we have to repeat the test a number of times.  What 
	   we're actually checking for is a quadratic nonresidue (thus the 
	   Legendre) which allows us an early-out.  However this is an awful lot 
	   of work to perform for every public key we encounter:

		for( i = 0; i < NO_TESTS; i++ )
			{
			p = small prime;
			BN_copy( temp, p );
			BN_sub_word( temp, 1 );
			BN_rshift1( temp, temp );
			BN_mod_exp( result, n, temp, p, bnCtx );
			if( BN_cmp( result, 0 ) < 1 )
				// Quadratic nonresidue, exit
			}

	   and it's not clear what we'd be gaining by checking for this one 
	   particular case when there's a million other ways generate broken 
	   keys that aren't detectable.  
	   
	   A better option is to apply Fermat's factorisation algorithm to look 
	   for values around the square root, which finds too-close factors and
	   not just perfect squares.  Since this is a somewhat expensive op
	   we don't perform it if we have the private key present, for which we 
	   can just do a comparison */
	if( isPrivateKey )
		{
		int status;
		
		status = checkPrimeFactors( pkcInfo );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "RSA public key has dangerously close prime "
						 "factors" ));
			assert_nofuzz( DEBUG_WARN );	/* Warn in debug build */
			return( CRYPT_ARGERROR_STR1 );
			}
		}
 
	/* Verify that e >= MIN_PUBLIC_EXPONENT, eLen <= RSAPARAM_MAX_E 
	   (= 32 bits).  The latter check is to preclude DoS attacks due to 
	   ridiculously large e values.  BN_get_word() works even on 16-bit 
	   systems because it returns BN_MASK2 (== UINT_MAX) if the value 
	   can't be represented in a machine word */
	if( eWord < MIN_PUBLIC_EXPONENT || bitsToBytes( eLen ) > RSAPARAM_MAX_E )
		{
		DEBUG_DIAG(( "RSA e value %ld is invalid/insecure, should be "
					 "%d...%ld", eWord, MIN_PUBLIC_EXPONENT, 
					 ( RSAPARAM_MAX_E == 1 ) ? 0x0FFL : \
					 ( RSAPARAM_MAX_E == 2 ) ? 0x0FFFFL : \
					 ( RSAPARAM_MAX_E == 3 ) ? 0x0FFFFFFL : INT_MAX - 1 ));
		assert_nofuzz( DEBUG_WARN );	/* Warn in debug build */
		return( CRYPT_ARGERROR_STR1 );
		}

	/* Perform a second check to make sure that e will fit into a signed 
	   integer.  This isn't strictly required since a BN_ULONG is unsigned 
	   but it's unlikely that anyone would consciously use a full 32-bit e
	   value (well, except for the German RegTP, who do all sorts of other
	   bizarre things as well) so we weed out any attempts to use one here */
	if( eLen >= bytesToBits( sizeof( int ) ) )
		{
		DEBUG_DIAG(( "RSA e value size %d bits can't be expressed as an int", 
					 eLen ));
		return( CRYPT_ARGERROR_STR1 );
		}

	/* Verify that e is a small prime.  The easiest way to do this would be
	   to compare it to a set of standard values but there'll always be some
	   wierdo implementation that uses a nonstandard value and that would
	   therefore fail the test so we perform a quick check that just tries
	   dividing by all primes below 1000.  In addition since in almost all
	   cases e will be one of a standard set of values we don't bother with 
	   the trial division unless it's an unusual value.  This test isn't
	   perfect but it'll catch obvious non-primes */
	if( eWord != 17 && eWord != 257 && eWord != 65537L && \
		!primeCheckQuick( e ) )
		{
		/* OpenSSH versions up to 5.4 (released in 2010) hardcoded e = 35, 
		   which is both a suboptimal exponent (it's less efficient that a 
		   safer value like 257 or F4) and non-prime.  The reason for this 
		   was that the original SSH used an e relatively prime to 
		   (p-1)(q-1), choosing odd (in both senses of the word) 
		   numbers > 31.  33 or 35 probably ended up being chosen frequently 
		   so it was hardcoded into OpenSSH for cargo-cult reasons, finally 
		   being fixed after more than a decade to use F4.  In order to use 
		   pre-5.4 OpenSSH keys that use this odd value we make a special-
		   case exception for SSH use */
#ifdef USE_SSH
		if( eWord == 33 || eWord == 35 )
			return( CRYPT_OK );
#endif /* USE_SSH */

		DEBUG_DIAG(( "RSA e value %d is suspicious/invalid", eWord ));
		assert_nofuzz( DEBUG_WARN );	/* Warn in debug build */
		return( CRYPT_ARGERROR_STR1 );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );
	
	return( CRYPT_OK );
	}

/* Perform validity checks on the private key.  We have to make the PKC_INFO
   data non-const because the bignum code wants to modify some of the values
   as it's working with them */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkRSAPrivateKeyComponents( INOUT_PTR PKC_INFO *pkcInfo )
	{
	const BIGNUM *n = &pkcInfo->rsaParam_n, *e = &pkcInfo->rsaParam_e;
	const BIGNUM *d = &pkcInfo->rsaParam_d, *p = &pkcInfo->rsaParam_p;
	const BIGNUM *q = &pkcInfo->rsaParam_q;
	BIGNUM *p1 = &pkcInfo->tmp1, *q1 = &pkcInfo->tmp2, *tmp = &pkcInfo->tmp3;
	const BN_ULONG eWord = BN_get_word( e );
	BN_ULONG word DUMMY_INIT;
	BOOLEAN isPrime;
	int threshold, bnStatus = BN_STATUS, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( eWord > 0 && eWord < INT_MAX );
			  /* Already checked in checkRSAPublicKeyComponents() */

	/* Verify that p, q aren't (obviously) composite.  Note that we can't 
	   use primeProbable() because this updates the Montgomery CTX data, 
	   it's OK to use it early in the keygen process before everything is 
	   set up but not after the pkcInfo is fully initialised so we use
	   primeProbableFermat() instead */
	if( !primeCheckQuick( p ) || !primeCheckQuick( q ) )
		return( CRYPT_ARGERROR_STR1 );
	status = primeProbableFermat( pkcInfo, p, &pkcInfo->rsaParam_mont_p, 
								  &isPrime );
	if( cryptStatusError( status ) )
		return( status );
	if( !isPrime )
		return( CRYPT_ARGERROR_STR1 );
	status = primeProbableFermat( pkcInfo, q, &pkcInfo->rsaParam_mont_q,
								  &isPrime );
	if( cryptStatusError( status ) )
		return( status );
	if( !isPrime )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that |p-q| > (nBits/2 - 100) bits.  We know that p >= q 
	   because this is a precondition for the CRT decrypt to work.  FIPS 
	   186-3 sets this somewhat arbitrary value which is merely meant to 
	   delimit "not too close", for example the shortest possible key, with 
	   1024 bits, would require 612 bits difference, well out of reach of 
	   Fermat's factorisation method.
	   
	   There's a second more obscure check that we could in theory perform 
	   to make sure that p and q don't have the least significant nLen / 4 
	   bits the same (which would still be caught by the previous check), 
	   this would make the Boneh/Durfee attack marginally less improbable 
	   (result by Zhao and Qi).  Since the chance of them having 256 LSB 
	   bits the same is vanishingly small and the Boneh/Dufree attack 
	   requires special properties for d (see the comment in 
	   generateRSAkey()) we don't bother with this check */
	threshold = ( BN_num_bits( n ) / 2 ) - 100;
	ENSURES( threshold >= ( MIN_PKCSIZE / 2 ) - 100 && \
			 threshold <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	ENSURES( BN_cmp( p, q ) >= 0 );
	CKPTR( BN_copy( tmp, p ) );
	CK( BN_sub( tmp, tmp, q ) );
	if( bnStatusError( bnStatus ) || \
		BN_num_bits( tmp ) <= threshold )
		return( CRYPT_ARGERROR_STR1 );

	/* Calculate p - 1, q - 1 */
	CKPTR( BN_copy( p1, p ) );
	CK( BN_sub_word( p1, 1 ) );
	CKPTR( BN_copy( q1, q ) );
	CK( BN_sub_word( q1, 1 ) );
	if( bnStatusError( bnStatus ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that n = p * q */
	CK( BN_mul( tmp, p, q, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) || BN_cmp( n, tmp ) != 0 )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that:

		p, q < d
		( d * e ) mod p-1 == 1 
		( d * e ) mod q-1 == 1
	
	   Some implementations don't store d since it's not needed when the CRT
	   shortcut is used so we can only perform this check if d is present */
	if( !BN_is_zero( d ) )
		{
		if( BN_cmp( p, d ) >= 0 || BN_cmp( q, d ) >= 0 )
			return( CRYPT_ARGERROR_STR1 );
		CK( BN_mod_mul( tmp, d, e, p1, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) || !BN_is_one( tmp ) )
			return( CRYPT_ARGERROR_STR1 );
		CK( BN_mod_mul( tmp, d, e, q1, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) || !BN_is_one( tmp ) )
			return( CRYPT_ARGERROR_STR1 );
		}

#ifdef USE_FIPS140
	/* Verify that sizeof( d ) > sizeof( p ) / 2, a weird requirement set by 
	   FIPS 186-3.  This is one of those things where the probability of the
	   check going wrong in some way outweighs the probability of the 
	   situation actually occurring by about two dozen orders of magnitude 
	   so we only do this when we have to.  The fact that this parameter is
	   never even used makes the check even less meaningful.
	   
	   (This check possibly has something to do with defending against 
	   Wiener's continued-fraction attack, which requires d < n^(1/4) in
	   order to succeed, later extended into the range d < n^(0.29) by
	   Boneh and Durfee/Bloemer and May and d < 1/2 n^(1/2) by Maitra and 
	   Sarkar) */
	if( !BN_is_zero( d ) && BN_num_bits( d ) <= pkcInfo->keySizeBits )
		return( CRYPT_ARGERROR_STR1 );
#endif /* USE_FIPS140 */

	/* Verify that ( q * u ) mod p == 1 */
	CK( BN_mod_mul( tmp, q, &pkcInfo->rsaParam_u, p, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) || !BN_is_one( tmp ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that e1 < p, e2 < q */
	if( BN_cmp( &pkcInfo->rsaParam_exponent1, p ) >= 0 || \
		BN_cmp( &pkcInfo->rsaParam_exponent2, q ) >= 0 )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that u < p, where u was calculated as q^-1 mod p */
	if( BN_cmp( &pkcInfo->rsaParam_u, p ) >= 0 )
		return( CRYPT_ARGERROR_STR1 );

	/* A very small number of systems/compilers can't handle 32 * 32 -> 64
	   ops which means that we have to use 16-bit bignum components.  For 
	   the common case where e = F4 the value won't fit into a 16-bit bignum
	   component so we have to use the full BN_mod() form of the checks that 
	   are carried out further on */
#ifdef SIXTEEN_BIT
	CK( BN_mod( tmp, p1, e, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) || BN_is_zero( tmp ) )
		return( CRYPT_ARGERROR_STR1 );
	CK( BN_mod( tmp, q1, e, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) || BN_is_zero( tmp ) )
		return( CRYPT_ARGERROR_STR1 );
	return( CRYPT_OK );
#endif /* Systems without 32 * 32 -> 64 ops */

	/* Verify that gcd( ( p - 1 )( q - 1), e ) == 1
	
	   Since e is a small prime we can do this much more efficiently by 
	   checking that:

		( p - 1 ) mod e != 0
		( q - 1 ) mod e != 0 */
	CK( BN_mod_word( &word, p1, eWord ) );
	if( bnStatusError( bnStatus ) || word == 0 )
		return( CRYPT_ARGERROR_STR1 );
	CK( BN_mod_word( &word, q1, eWord ) );
	if( bnStatusError( bnStatus ) || word == 0 )
		return( CRYPT_ARGERROR_STR1 );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Initialise/Check an RSA Key						*
*																			*
****************************************************************************/

/* Generate an RSA key pair into an encryption context.  For FIPS 140 
   purposes the keygen method used here complies with FIPS 186-3 Appendix 
   B.3, "IFC Key Pair Generation", specifically method B.3.3, "Generation of 
   Random Primes that are Probably Prime".  Note that FIPS 186-3 provides a
   range of key-generation methods and allows implementations to select one
   that's appropriate, this implementation provides the one in B.3.3, with
   the exception that it allows keys in the range MIN_PKC_SIZE ... 
   CRYPT_MAX_PKCSIZE to be generated.  FIPS 186-3 is rather confusing in
   that it discusses conditions and requirements for generating pairs from
   512 ... 3072 bits and then gives different lengths and restrictions on
   lengths depending on which portion of text you consult.  Because of this
   confusion, and the fact that telling users that they can't generate the
   key that they want because of some obscure document that they've never
   even heard of will cause friction, we leave it as a policy decision to
   define the appropriate key size to use */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int generateRSAkey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_LENGTH_SHORT_MIN( MIN_PKCSIZE * 8 ) const int keyBits )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	const CAPABILITY_INFO *capabilityInfoPtr = \
								DATAPTR_GET( contextInfoPtr->capabilityInfo );
	BIGNUM *d = &pkcInfo->rsaParam_d, *p = &pkcInfo->rsaParam_p;
	BIGNUM *q = &pkcInfo->rsaParam_q;
	BIGNUM *tmp = &pkcInfo->tmp1;
	int pBits, qBits, bnStatus, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	
	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( keyBits >= bytesToBits( MIN_PKCSIZE ) && \
			  keyBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );
	REQUIRES( capabilityInfoPtr != NULL );

	/* Determine how many bits to give to each of p and q */
	pBits = ( keyBits + 1 ) / 2;
	qBits = keyBits - pBits;
	pkcInfo->keySizeBits = pBits + qBits;

	/* Generate the primes p and q and set them up so that the CRT decrypt
	   will work.  FIPS 186-3 requires that they be in the range 
	   sqr(2) * 2^(keyBits-1) ... 2^keyBits (so that pq will be exactly 
	   keyBits long), but this is guaranteed by the way that generatePrime()
	   selects its prime values so we don't have to check explicitly for it
	   here */
	bnStatus = BN_set_word( &pkcInfo->rsaParam_e, RSA_PUBLIC_EXPONENT );
	ENSURES( bnStatusOK( bnStatus ) );
	status = generatePrimeRSA( pkcInfo, p, pBits, RSA_PUBLIC_EXPONENT );
	if( cryptStatusOK( status ) )
		status = generatePrimeRSA( pkcInfo, q, qBits, RSA_PUBLIC_EXPONENT );
	if( cryptStatusOK( status ) )
		status = fixCRTvalues( pkcInfo, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Compute d = eInv mod (p - 1)(q - 1) */
	CK( BN_sub_word( p, 1 ) );
	CK( BN_sub_word( q, 1 ) );
	CK( BN_mul( tmp, p, q, &pkcInfo->bnCTX ) );
	CKPTR( BN_mod_inverse( d, &pkcInfo->rsaParam_e, tmp, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

#ifdef USE_FIPS140
	/* Check that sizeof( d ) > sizeof( p ) / 2, a weird requirement set by 
	   FIPS 186-3.  This is one of those things where the probability of the
	   check going wrong in some way outweighs the probability of the 
	   situation actually occurring by about two dozen orders of magnitude 
	   so we only do this when we have to.  The fact that this parameter is
	   never even used makes the check even less meaningful.
	   
	   (This check possibly has something to do with defending against 
	   Wiener's continued-fraction attack, which requires d < n^(1/4) in
	   order to succeed, later extended into the range d < n^(0.29) by
	   Boneh and Durfee/Bloemer and May and d < 1/2 n^(1/2) by Maitra and 
	   Sarkar) */
	if( BN_num_bits( d ) <= pkcInfo->keySizeBits / 2 )
		return( CRYPT_ERROR_FAILED );
#endif /* USE_FIPS140 */

	/* Compute e1 = d mod (p - 1), e2 = d mod (q - 1) */
	CK( BN_mod( &pkcInfo->rsaParam_exponent1, d,
				p, &pkcInfo->bnCTX ) );
	CK( BN_mod( &pkcInfo->rsaParam_exponent2, d, q, &pkcInfo->bnCTX ) );
	CK( BN_add_word( p, 1 ) );
	CK( BN_add_word( q, 1 ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Compute n = pq, u = qInv mod p */
	CK( BN_mul( &pkcInfo->rsaParam_n, p, q, &pkcInfo->bnCTX ) );
	CKPTR( BN_mod_inverse( &pkcInfo->rsaParam_u, q, p, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* Since the keygen is randomised it may occur that the final size of 
	   the public value that determines its nominal size is slightly smaller 
	   than the requested nominal size.  To handle this we recalculate the 
	   effective key size after we've finished generating the public value
	   that determines its nominal size */
	pkcInfo->keySizeBits = BN_num_bits( &pkcInfo->rsaParam_n );
	ENSURES( pkcInfo->keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			 pkcInfo->keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Evaluate the Montgomery forms */
	status = getRSAMontgomery( pkcInfo, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Enable side-channel protection if required */
	if( TEST_FLAG( contextInfoPtr->flags, 
				   CONTEXT_FLAG_SIDECHANNELPROTECTION ) )
		{
		status = enableSidechannelProtection( pkcInfo, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Checksum the bignums to try and detect fault attacks.  Since we're
	   setting the checksum at this point there's no need to check the 
	   return value */
	( void ) checksumContextData( pkcInfo, capabilityInfoPtr->cryptAlgo, 
								  TRUE );

	/* Make sure that the generated values are valid */
	status = checkRSAPublicKeyComponents( pkcInfo, TRUE );
	if( cryptStatusOK( status ) )
		status = checkRSAPrivateKeyComponents( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that what we generated is still valid */
	if( cryptStatusError( \
			checksumContextData( pkcInfo, capabilityInfoPtr->cryptAlgo, 
								 TRUE ) ) )
		{
		DEBUG_DIAG(( "Generated RSA key memory corruption detected" ));
		return( CRYPT_ERROR_FAILED );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Initialise and check an RSA key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initCheckRSAkey( INOUT_PTR CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	const BIGNUM *n = &pkcInfo->rsaParam_n, *e = &pkcInfo->rsaParam_e;
	const BIGNUM *d = &pkcInfo->rsaParam_d, *p = &pkcInfo->rsaParam_p;
	const BIGNUM *q = &pkcInfo->rsaParam_q;
	const BOOLEAN isPrivateKey = TEST_FLAG( contextInfoPtr->flags,
											CONTEXT_FLAG_ISPUBLICKEY ) ? \
								 FALSE : TRUE;
	int bnStatus = BN_STATUS, status = CRYPT_OK;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );

	/* Make sure that the necessary key parameters have been initialised */
	if( BN_is_zero( n ) || BN_is_zero( e ) )
		return( CRYPT_ARGERROR_STR1 );
	if( isPrivateKey )
		{
		if( BN_is_zero( p ) || BN_is_zero( q ) )
			return( CRYPT_ARGERROR_STR1 );
		if( BN_is_zero( d ) && \
			( BN_is_zero( &pkcInfo->rsaParam_exponent1 ) || \
			  BN_is_zero( &pkcInfo->rsaParam_exponent2 ) ) )
			{
			/* Either d or e1+e2 must be present, d isn't needed if we have 
			   e1+e2 and e1+e2 can be reconstructed from d */
			return( CRYPT_ARGERROR_STR1 );
			}
		}

	/* Make sure that the public key parameters are valid */
	status = checkRSAPublicKeyComponents( pkcInfo, isPrivateKey );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a public key, we're done */
	if( !isPrivateKey )
		{
		/* Precompute the Montgomery forms of required values */
		status = getRSAMontgomery( pkcInfo, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		pkcInfo->keySizeBits = BN_num_bits( &pkcInfo->rsaParam_n );
		ENSURES( pkcInfo->keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
				 pkcInfo->keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

		/* Enable side-channel protection if required */
		if( TEST_FLAG( contextInfoPtr->flags, 
					   CONTEXT_FLAG_SIDECHANNELPROTECTION ) )
			{
			status = enableSidechannelProtection( pkcInfo, TRUE );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Checksum the bignums to try and detect fault attacks.  Since 
		   we're setting the checksum at this point there's no need to check 
		   the return value.  Note that this isn't the TOCTOU issue that it 
		   appears to be because the bignum values are read by the calling 
		   code from their stored form a second time and compared to the 
		   values that we're checksumming here */
		( void ) checksumContextData( pkcInfo, CRYPT_ALGO_RSA, FALSE );

		ENSURES( sanityCheckPKCInfo( pkcInfo ) );

		return( CRYPT_OK );
		}

	/* If we're not using PKCS keys that have exponent1 = d mod ( p - 1 )
	   and exponent2 = d mod ( q - 1 ) precalculated, evaluate them now
	   (this only ever occurs for PGP keys).  If there's no u precalculated, 
	   evaluate it now (this should never occur with any normal source of
	   keys) */
	if( BN_is_zero( &pkcInfo->rsaParam_exponent1 ) )
		{
		BIGNUM *exponent1 = &pkcInfo->rsaParam_exponent1;
		BIGNUM *exponent2 = &pkcInfo->rsaParam_exponent2;

		REQUIRES( !BN_is_zero( d ) );

		/* exponent1 = d mod ( p - 1 ) ) */
		CKPTR( BN_copy( exponent1, p ) );
		CK( BN_sub_word( exponent1, 1 ) );
		CK( BN_mod( exponent1, d, exponent1, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );

		/* exponent2 = d mod ( q - 1 ) ) */
		CKPTR( BN_copy( exponent2, q ) );
		CK( BN_sub_word( exponent2, 1 ) );
		CK( BN_mod( exponent2, d, exponent2, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		}
	if( BN_is_zero( &pkcInfo->rsaParam_u ) )
		{
		CKPTR( BN_mod_inverse( &pkcInfo->rsaParam_u, q, p,
							   &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		}

	/* Make sure that p and q are set up correctly for the CRT decryption */
	status = fixCRTvalues( pkcInfo, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Precompute the Montgomery forms of required values */
	status = getRSAMontgomery( pkcInfo, TRUE );
	if( cryptStatusError( status ) )
		return( status );
	pkcInfo->keySizeBits = BN_num_bits( &pkcInfo->rsaParam_n );
	ENSURES( pkcInfo->keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			 pkcInfo->keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* We've got the remaining components set up, perform further validity 
	   checks on the private key */
	status = checkRSAPrivateKeyComponents( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Enable side-channel protection if required */
	if( TEST_FLAG( contextInfoPtr->flags, 
				   CONTEXT_FLAG_SIDECHANNELPROTECTION ) )
		{
		status = enableSidechannelProtection( pkcInfo, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Checksum the bignums to try and detect fault attacks.  Since we're
	   setting the checksum at this point there's no need to check the 
	   return value.  Note that this isn't the TOCTOU issue that it appears 
	   to be because the bignum values are read by the calling code from 
	   their stored form a second time and compared to the values that we're 
	   checksumming here */
	( void ) checksumContextData( pkcInfo, CRYPT_ALGO_RSA, TRUE );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}
