/****************************************************************************
*																			*
*				cryptlib ECC Key Generation/Checking Routines				*
*					Copyright Peter Gutmann 2006-2025						*
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

#if defined( USE_ECDH ) || defined( USE_ECDSA )

/****************************************************************************
*																			*
*							Utility Functions								*
*																			*
****************************************************************************/

/* Enable various side-channel protection mechanisms */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int enableSidechannelProtection( INOUT_PTR PKC_INFO *pkcInfo )
	{
	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	/* Use constant-time modexp() to protect the private key from timing 
	   channels.

	   (There really isn't much around in the way of side-channel protection 
	   for the ECC computations, for every operation we use a new random 
	   secret value as the point multiplier so there doesn't seem to be much 
	   scope for timing attacks.  In the absence of anything better to do, 
	   we set the constant-time modexp() flag just for warm fuzzies) */
	BN_set_flags( &pkcInfo->eccParam_d, BN_FLG_CONSTTIME );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						ECC Information Access Functions					*
*																			*
****************************************************************************/

/* Get the nominal size of an ECC field based on an CRYPT_ECCCURVE_TYPE.  See
   the comment for getECCFieldID() for the handling of the special-snowflake
   curves */

static const MAP_TABLE fieldSizeMapTbl[] = {
	{ CRYPT_ECCCURVE_P256, 256 },
	{ CRYPT_ECCCURVE_BRAINPOOL_P256, 256 },
	{ CRYPT_ECCCURVE_P384, 384 },
	{ CRYPT_ECCCURVE_BRAINPOOL_P384, 384 },
	{ CRYPT_ECCCURVE_P521, 521 },
	{ CRYPT_ECCCURVE_BRAINPOOL_P512, 512 },
	{ CRYPT_ECCCURVE_25519, 255 },
	{ CRYPT_ECCCURVE_448, 448 },
	{ CRYPT_ERROR, CRYPT_ERROR }, { CRYPT_ERROR, CRYPT_ERROR }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int getECCFieldSize( IN_ENUM( CRYPT_ECCCURVE ) \
						const CRYPT_ECCCURVE_TYPE fieldID,
					 OUT_INT_Z int *fieldSize,
					 IN_BOOL const BOOLEAN isBits )
	{
	int value, status;

	assert( isWritePtr( fieldSize, sizeof( int ) ) );

	REQUIRES( isEnumRange( fieldID, CRYPT_ECCCURVE ) );
	REQUIRES( isBooleanValue( isBits ) );

	/* Clear return value */
	*fieldSize = 0;

	/* Find the nominal field size for the given fieldID */
	status = mapValue( fieldID, &value, fieldSizeMapTbl, 
					   FAILSAFE_ARRAYSIZE( fieldSizeMapTbl, MAP_TABLE ) );
	ENSURES( cryptStatusOK( status ) );
	*fieldSize = isBits ? value : bitsToBytes( value );
	
	return( CRYPT_OK );
	}

/* Get a CRYPT_ECCCURVE_TYPE based on a nominal ECC field size.  Since this
   is a one-to-many mapping, so for example a field size of 256 bits maps to
   both CRYPT_ECCCURVE_P256 and CRYPT_ECCCURVE_BRAINPOOL_P256, we always
   return the standard curve rather than the Brainpool alternative, which is
   what's required for any ECC-using protocol like TLS and SSH.  In addition 
   the special-snowflake curves like 25519 are handled through their own code
   paths so while they're present here for completeness they're never 
   accessed through these functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int getECCFieldID( IN_LENGTH_SHORT_MIN( MIN_PKCSIZE_ECC ) \
						const int fieldSize,
				   OUT_ENUM_OPT( CRYPT_ECCCURVE ) 
						CRYPT_ECCCURVE_TYPE *fieldID )
	{
	LOOP_INDEX i;

	assert( isWritePtr( fieldID, sizeof( CRYPT_ECCCURVE_TYPE ) ) );

	REQUIRES( fieldSize >= MIN_PKCSIZE_ECC && \
			  fieldSize <= CRYPT_MAX_PKCSIZE_ECC );

	/* Clear return value */
	*fieldID = CRYPT_ECCCURVE_NONE;

	/* Find the fieldID for the given nominal field size.  We use a map 
	   table because it's convenient but we can't use mapValue() because
	   we need a >= comparison rather then == */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( fieldSizeMapTbl, MAP_TABLE ) && \
					fieldSizeMapTbl[ i ].source != CRYPT_ERROR,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( fieldSizeMapTbl, \
														 MAP_TABLE ) - 1 ) );

		if( bitsToBytes( fieldSizeMapTbl[ i ].destination ) >= fieldSize )
			{
			*fieldID = fieldSizeMapTbl[ i ].source;
			return( CRYPT_OK );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( fieldSizeMapTbl, MAP_TABLE ) );

	/* Because of rounding issues in parameter bounds checking, combined 
	   with the odd-length sizes chosen for some of the standard curves,
	   we can end up with a situation where the requested curve size is a 
	   few bits over even the largest field size.  If we run into this 
	   situation then we use the largest field size */
	if( fieldSize >= bitsToBytes( 521 ) )
		{
		*fieldID = CRYPT_ECCCURVE_P521;
		return( CRYPT_OK );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Generate an ECC Key							*
*																			*
****************************************************************************/

/* Generate the ECC private value d and public value Q */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateECCPrivateValue( INOUT_PTR PKC_INFO *pkcInfo,
									IN_BOOL \
										const BOOLEAN sideChannelProtection )
	{
	const ECC_DOMAINPARAMS *domainParams = pkcInfo->domainParams;
	const BIGNUM *n = &domainParams->n;
	BIGNUM *d = &pkcInfo->eccParam_d, *n_1 = &pkcInfo->tmp1;
	int nBits, dLen, bnStatus = BN_STATUS, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( isBooleanValue( sideChannelProtection ) );

	/* Generate the ECC private value d s.t. 1 <= d <= n-1.  Because the mod 
	   n-1 is expensive we do a quick check to make sure that it's really 
	   necessary before calling it.  In practice for the NIST curves for 
	   which n begins with a minimum of 32 1-bits, even more for P-384 and
	   P-521, this essentially never happens, it's only for the Brainpool 
	   curves that we end up taking the mod path.  
	   
	   The Brainpool curves begin with { A9, 8C, AA } so in theory we could
	   make the high-byte mask conditional on the MSB of n but this is
	   now hardcoding in low-level internal details of the curve parameters
	   (0xC0 is the universal high-byte mask used for all keygen, it just
	   happens to fit the NIST parameters) and the Brainpool curves are
	   essentially never used so we just let them fall through the additional
	   operations below */
	nBits = BN_num_bits( n );
	REQUIRES( bitsToBytes( nBits ) >= MIN_PKCSIZE_ECC && \
			  bitsToBytes( nBits ) <= CRYPT_MAX_PKCSIZE_ECC );
	status = generateBignum( d, nBits, 0xC0, 0 );
	if( cryptStatusError( status ) )
		return( status );
	CKPTR( BN_copy( n_1, n ) );
	CK( BN_sub_word( n_1, 1 ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( BN_cmp( d, n_1 ) <= 0 )
		{
		/* We've got d within range, we're done */
		if( sideChannelProtection )
			{
			status = enableSidechannelProtection( pkcInfo );
			if( cryptStatusError( status ) )
				return( status );
			}

		ENSURES( sanityCheckPKCInfo( pkcInfo ) );

		return( CRYPT_OK );
		}

	/* Trim d down to size.  To get the range 1 <= d <= n-1 we have to mod
	   n-1 and add 1 */
	CK( BN_mod( d, d, n_1, &pkcInfo->bnCTX ) );
	CK( BN_add_word( d, 1 ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	/* If the value that we ended up with is too small, just generate a new 
	   value one bit shorter, which guarantees that it'll fit the criteria 
	   (the target is a suitably large random value, not the closest 
	   possible fit within the range).  In the case of the Brainpool curves
	   this means a small percentage go through the re-generation path,
	   which means they cover a slightly smaller range than 1 ... n-1, but
	   this is of no consequence */
	dLen = BN_num_bits( d );
	REQUIRES( dLen > 0 && dLen <= bytesToBits( CRYPT_MAX_PKCSIZE_ECC ) );
	if( dLen < nBits - 5 )	/* Range checked above */
		{
		status = generateBignum( d, nBits - 1, 0xC0, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( sideChannelProtection )
		{
		status = enableSidechannelProtection( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateECCPublicValue( INOUT_PTR PKC_INFO *pkcInfo )
	{
	const BIGNUM *d = &pkcInfo->eccParam_d;
	BIGNUM *qx = &pkcInfo->eccParam_qx, *qy = &pkcInfo->eccParam_qy;
	const EC_GROUP *ecCTX = &pkcInfo->ecCTX;
	EC_POINT *q = &pkcInfo->tmpPoint;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Calculate the public-key value Q = d * G */
	CK( EC_POINT_mul( ecCTX, q, d, NULL, NULL, &pkcInfo->bnCTX ) );
	CK( EC_POINT_get_affine_coordinates_GFp( ecCTX, q, qx, qy,
											 &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Check an ECC Key							*
*																			*
****************************************************************************/

/* Perform validity checks on the public key.  In the tradition of these
   documents, FIPS 186 and the X9.62 standard that it's derived from 
   occasionally use different names for the parameters, the following 
   mapping can be used to go from one to the other:

	FIPS 186	X9.62/SECG		Description
	--------	----------		-----------
		p			p			Finite field Fp
	  a, b		  a, b			Elliptic curve y^2 == x^3 + ax + b
	 xg, yg		 xg, yg			Base point G on the curve
		n			n			Prime n of order G
		h			h			Cofactor
	--------	---------		-----------
	 wx, wy		 xq, yq			Public key Q
		d			d			Private key

   We have to make the PKC_INFO data non-const because the bignum code wants 
   to modify some of the values as it's working with them */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static BOOLEAN checkComponentLength( IN_PTR const BIGNUM *component,
									 IN_PTR const BIGNUM *maxRange,
									 IN_BOOL const BOOLEAN lowerBoundZero )
	{
	int length;

	assert( isReadPtr( component, sizeof( BIGNUM ) ) );
	assert( isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES_B( isBooleanValue( lowerBoundZero ) );

	/* Make sure that the component is in the range 0...maxRange - 1 
	   (optionally MIN_PKCSIZE_ECC if lowerBoundZero is false) */
	length = BN_num_bytes( component );
	if( length < ( lowerBoundZero ? 0 : MIN_PKCSIZE_ECC ) || \
		length > CRYPT_MAX_PKCSIZE_ECC )
		return( FALSE );
	if( BN_cmp( component, maxRange ) >= 0 )
		return( FALSE );

	return( TRUE );
	}

/* Check that y^2 = x^3 + a*x + b is in the field GF(p) */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 5 ) ) \
static BOOLEAN isPointOnCurve( const BIGNUM *x, const BIGNUM *y, 
							   const BIGNUM *a, const BIGNUM *b, 
							   INOUT_PTR PKC_INFO *pkcInfo )
	{
	const ECC_DOMAINPARAMS *domainParams = pkcInfo->domainParams;
	const BIGNUM *p = &domainParams->p;
	BIGNUM *tmp1 = &pkcInfo->tmp1, *tmp2 = &pkcInfo->tmp2;
	BN_CTX *ctx = &pkcInfo->bnCTX;
	int bnStatus = BN_STATUS;

	assert( isReadPtr( x, sizeof( BIGNUM ) ) );
	assert( isReadPtr( y, sizeof( BIGNUM ) ) );
	assert( isReadPtr( a, sizeof( BIGNUM ) ) );
	assert( isReadPtr( b, sizeof( BIGNUM ) ) );
	assert( isReadPtr( p, sizeof( BIGNUM ) ) );
	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES_B( sanityCheckBignum( x ) );
	REQUIRES_B( sanityCheckBignum( y ) );
	REQUIRES_B( sanityCheckBignum( a ) );
	REQUIRES_B( sanityCheckBignum( b ) );
	REQUIRES_B( sanityCheckPKCInfo( pkcInfo ) );

	CK( BN_mod_mul( tmp1, y, y, p, ctx ) );
	CK( BN_mod_mul( tmp2, x, x, p, ctx ) );
	CK( BN_mod_add( tmp2, tmp2, a, p, ctx ) );
	CK( BN_mod_mul( tmp2, tmp2, x, p, ctx ) );
	CK( BN_mod_add( tmp2, tmp2, b, p, ctx ) );
	if( bnStatusError( bnStatus ) )
		return( FALSE );
	if( BN_cmp( tmp1, tmp2 ) != 0 )
		return( FALSE );
	
	return( TRUE );
	}

/* Check the ECC domain parameters.  X9.62 specifies curves in the field 
   GF(q) of size q, where q is either a prime integer or equal to 2^m (with 
   m prime).  The following checks only handle curves where q is a prime 
   integer (the de facto universal standard), referred to as 'p' in the 
   following code */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkECCDomainParameters( INOUT_PTR PKC_INFO *pkcInfo,
									 IN_BOOL const BOOLEAN isFullyInitialised )
	{
	const ECC_DOMAINPARAMS *domainParams = pkcInfo->domainParams;
	const BIGNUM *p = &domainParams->p;
	const BIGNUM *a = &domainParams->a, *b = &domainParams->b;
	const BIGNUM *n = &domainParams->n, *h = &domainParams->h;
	const BIGNUM *gx = &domainParams->gx, *gy = &domainParams->gy;
	BIGNUM *tmp1 = &pkcInfo->tmp1, *tmp2 = &pkcInfo->tmp2;
	BIGNUM *tmp3_h = &pkcInfo->tmp3;
	const EC_GROUP *ecCTX = &pkcInfo->ecCTX;
	EC_POINT *vp = &pkcInfo->tmpPoint;
	const BOOLEAN isStandardCurve = \
			( pkcInfo->curveType != CRYPT_ECCCURVE_NONE ) ? TRUE : FALSE;
	BOOLEAN isPrime;
	LOOP_INDEX i;
	int length, pLen, tmp3hBits, nBits, bnStatus = BN_STATUS, status;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );
	REQUIRES( isBooleanValue( isFullyInitialised ) );

	/* Verify that the domain parameter sizes are valid:

		pLen >= MIN_PKCSIZE_ECC, pLen <= CRYPT_MAX_PKCSIZE_ECC
		a, b >= 0, a, b <= p - 1
		gx, gy >= 0, gx, gy <= p - 1
		nLen >= MIN_PKCSIZE_ECC, nLen <= CRYPT_MAX_PKCSIZE_ECC
		hLen >= 1, hLen <= CRYPT_MAX_PKCSIZE_ECC (if present).  These are
		cheap checks so we perform them even for the hardcoded and checksum-
		protected NIST and Brainpool parameter sets */
	length = BN_num_bytes( p );
	if( length < MIN_PKCSIZE_ECC || length > CRYPT_MAX_PKCSIZE_ECC )
		return( CRYPT_ARGERROR_STR1 );
	if( !checkComponentLength( a, p, TRUE ) || \
		!checkComponentLength( b, p, TRUE ) )
		return( CRYPT_ARGERROR_STR1 );
	if( !checkComponentLength( gx, p, TRUE ) || \
		!checkComponentLength( gy, p, TRUE ) )
		return( CRYPT_ARGERROR_STR1 );
	length = BN_num_bytes( n );
	if( length < MIN_PKCSIZE_ECC || length > CRYPT_MAX_PKCSIZE_ECC )
		return( CRYPT_ARGERROR_STR1 );
	if( !BN_is_zero( h ) )
		{
		length = BN_num_bytes( h );
		if( length < 1 || length > CRYPT_MAX_PKCSIZE_ECC )
			return( CRYPT_ARGERROR_STR1 );
		}

	/* Whether the domain parameters need to be validated each time that 
	   they're loaded is left unclear in the specifications.  In fact 
	   whether they, or the public key data, needs to be validated at all, 
	   is left unspecified.  FIPS 186-3 is entirely silent on the matter and 
	   X9.62 defers to an annex that contains two whole sentences that 
	   merely say that it's someone else's problem.  In the absence of any 
	   guidance we only validate domain parameters if they're supplied 
	   externally.  Since the hardcoded internal values are checksummed,
	   there's not much need to perform additional validation on them.
	   
	   To activate domain validation on known curves, comment out the check
	   below.  Note that the code beyond this point is never actually used
	   since we always used standard curves and don't allow custom ones */
	if( isStandardCurve )
		return( CRYPT_OK );

	/* Verify that p is not (obviously) composite.  ECC doesn't use 
	   Montgomery forms at this level so we have to set the necessary 
	   context up explicitly just for the primality check */
	if( !primeCheckQuick( p ) )
		return( CRYPT_ARGERROR_STR1 );
	CK( BN_MONT_CTX_set( &pkcInfo->montCTX1, p, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	status = primeProbableFermat( pkcInfo, p, &pkcInfo->montCTX1, &isPrime );
	if( cryptStatusError( status ) )
		return( status );
	if( !isPrime )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that a, b and gx, gy are integers in the range 0...p - 1.  
	   This has already been done in the range checks performed earlier */

	/* Verify that (4a^3 + 27b^2) is not congruent to zero (mod p).  Note
	   that the intermediates aren't computed mod p so can get quite large,
	   they'll always fit into a CRYPT_MAX_PKCSIZE bignum but if this code
	   is ever enabled it'd probably be better the perform the reduction
	   on intermediate values */
	CK( BN_sqr( tmp1, a, &pkcInfo->bnCTX ) );
	CK( BN_mul( tmp1, tmp1, a, &pkcInfo->bnCTX ) );
	CK( BN_mul_word( tmp1, 4 ) );
	CK( BN_sqr( tmp2, b, &pkcInfo->bnCTX ) );
	CK( BN_mul_word( tmp2, 27 ) );
	CK( BN_add( tmp1, tmp1, tmp2 ) );
	CK( BN_mod( tmp1, tmp1, p, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( BN_is_zero( tmp1 ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that gy^2 is congruent to gx^3 + a*gx + b (mod p) */
	if( !isPointOnCurve( gx, gy, a, b, pkcInfo ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that:

		n is not (obviously) composite.

		n > 2^160 and n > 2^( 2s-1 ), where s is the "security level"

		The second test is about ensuring that the subgroup order is large 
		enough to make the ECDLP infeasible.  X9.62 measures infeasibility 
		by the security level, and the test on 2^160 means that X9.62 
		considers that there is no worthwhile security below level 80.5.  
		The security level has already been implicitly checked via the 
		MIN_PKCSIZE_ECC constant, and n has already been tested above */
	if( !primeCheckQuick( n ) )
		return( CRYPT_ARGERROR_STR1 );
	CK( BN_MONT_CTX_set( &pkcInfo->montCTX1, n, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	status = primeProbableFermat( pkcInfo, n, &pkcInfo->montCTX1, &isPrime );
	if( cryptStatusError( status ) )
		return( status );
	if( !isPrime )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that n * G is the point at infinity.  This runs into a nasty 
	   catch-22 where we have to initialise at least some of the ECC 
	   parameter information in order to perform the check, but we can't 
	   (safely) use the parameters before we've checked them.  To get around
	   this, if the values haven't been fully set up yet then we perform the 
	   check inline in the initCheckECCKey() code */
	if( isFullyInitialised )
		{
		CK( EC_POINT_mul( ecCTX, vp, n, NULL, NULL, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		if( !EC_POINT_is_at_infinity( ecCTX, vp ) )
			return( CRYPT_ARGERROR_STR1 );
		}

	/* Compute the cofactor h.  The domain parameters may include h, but we 
	   still want to compute it and check that we get the same value.  The 
	   cofactor will be needed for verification of the "anomalous condition".

	   The curve size is #E = q + 1 - t, where t is the trace of Frobenius.  
	   Hasse's theorem guarantees that |t| <= 2*sqrt( q ).  Since we work 
	   over a subgroup of size n, we know that n divides #E.  The cofactor h 
	   is the integer such that #E = n * h.

	   In the X9.62 world, h is much smaller than n.  It follows that h can 
	   be recomputed accurately from q and n, since there's only one integer 
	   value for h that puts t in the proper range.  The formula given in 
	   X9.62 is:

			h = floor( ( sqrt( q ) + 1 )^2 / n )

	   which expands to:

			h = floor( ( q + 1 + 2*sqrt( q ) ) / n )

	   which can be seen to map to the proper cofactor.  To check this we 
	   compute a value which is one more than the maximum possible curve 
	   order and divide by n.  If we then verify that h is small enough 
	   (which is a requirement of X9.62) then we know that we've found the 
	   proper cofactor.

	   The X9.62 formula is cumbersome because it requires a square root, 
	   and we have to keep track of fractional bits as well.  The expanded 
	   formula requires less fractional bits, but it still needs a square 
	   root.  To avoid having to deal with this we can take advantage of the 
	   fact that the conditions on the "security level" (n >= 2^160, 
	   n >= 2^( 2s - 1 ) and h <= 2^( s / 8 ) for an integer s) imply that 
	   n >= h^15.  A consequence of this is that n*h <= n^( 1 + 1/15 ).  
	   n * h is the curve order, which is close to q and lower than 2 * q.

	   Now, let qlen = log2( q ) (the size of q in bits, so that 
	   2^( qlen-1 ) <= q < 2^qlen).  We then compute:

	      z = q + 2^( floor( qlen / 2 ) + 3 )

	   which is easily obtained by shifting one bit and performing an 
	   addition.  It's then easily seen that z > #E.  Since we work in a 
	   field of sufficiently large size (according to X9.62, qlen >= 160, 
	   but we may accept slightly smaller values of q, but no less than 
	   qlen = 128), we can show that n is much larger than
	   2^( floor( qlen / 2 ) + 4 ) (the size of n is at least 15/16ths of 
	   that of q).  This implies that z - n is much smaller than the minimal 
	   possible size of E.

	   We conclude that h = floor( z / n ), which is then the formula that 
	   we apply.  We also check that h is no larger than 1/14th of n (using 
	   14 instead of 15 avoids rounding issues since the size in bits of h 
	   is not exactly equal to log2( h ), but it's still good enough for the 
	   analysis above).

	   For the standard named curves in GF( p ) (the P-* NIST curves), h = 1
	   and is implicitly present */
	pLen = BN_num_bits( p );
	REQUIRES( bitsToBytes( pLen ) >= MIN_PKCSIZE_ECC && \
			  bitsToBytes( pLen ) <= CRYPT_MAX_PKCSIZE_ECC );
	CK( BN_one( tmp1 ) );
	CK( BN_lshift( tmp1, tmp1, ( pLen >> 1 ) + 3 ) );
	CK( BN_add( tmp1, tmp1, p ) );
	CK( BN_div( tmp3_h, NULL, tmp1, n, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( BN_is_zero( tmp3_h ) )
		return( CRYPT_ARGERROR_STR1 );
	tmp3hBits = BN_num_bits( tmp3_h );
	REQUIRES( tmp3hBits > 0 && \
			  tmp3hBits <= bytesToBits( CRYPT_MAX_PKCSIZE_ECC ) );
	nBits = BN_num_bits( n );
	REQUIRES( nBits > 0 && \
			  nBits <= bytesToBits( CRYPT_MAX_PKCSIZE_ECC ) );
	if( tmp3hBits * 14 > nBits )
		return( CRYPT_ARGERROR_STR1 );
	if( isStandardCurve )
		{
		/* This code is executed only if the early exit for known curves 
		   above has been deactivated */
		if ( !BN_is_one( tmp3_h ) )
			return( CRYPT_ARGERROR_STR1 );
		}
	else
		{
		if( !BN_is_zero( h ) && BN_cmp( h, tmp3_h ) != 0 )
			return( CRYPT_ARGERROR_STR1 );
		}
	h = tmp3_h;

	/* Verify that the MOV condition holds.  We use a MOV threshold B = 100
	   as per X9.62:2005 ('98 used B = 20).
	   
	   Mathematically, we want to make sure that the embedding degree of the 
	   curve (for the subgroup that we're interested in) is greater than 100.  
	   The embedding degree is the lowest integer k such that r divides q^k-1 
	   (using the X9.62 notations where q is the field size, here held in 
	   the local variable p, while r is the subgroup order size, which the 
	   code below calls n).  The embedding degree always exists, except if 
	   the curve is anomalous, i.e. the size of the curve is equal to the 
	   field size.  Anomalous curves are a bad thing to have, so they're
	   checked for later on.

	   The Weil and Tate pairings allow the conversion of the ECDLP problem
	   into the "plain" DLP problem in GF( q^k ), the field extension of 
	   GF( q ) of degree k, for which subexponential algorithms are known.  
	   For example if a curve is defined over a field GF(q) such that the 
	   size of q is 256 bits and n also has a size close to 256 bits then we 
	   expect the ECDLP to have a cost of about O( 2^128 ), i.e. it's very 
	   much infeasible.  However if that curve happens to have an extension 
	   degree k = 2 then a Weil or Tate pairing transforms the ECLDP into 
	   the DLP in GF( q^2 ), a field of size 512 bits, for which the DLP is 
	   technologically feasible.

	   For a random curve, k should be a large integer of the same size as 
	   n, thus making q^k astronomically high.  For our purposes we want to 
	   make sure that k isn't very small.  X9.62 checks that k > 100, which 
	   is good enough, since if if k = 101 then the 256-bit ECDLP is 
	   transformed into the 25856-bit DLP, which is awfully big and totally 
	   infeasible as far as we know.

	   Computing the value of k is feasible if you can factor r - 1, but 
	   this is expensive.  The X9.62 test computes q, q^2, q^3... q^100 
	   modulo n and checks that none of these equal one */
	CK( BN_one( tmp1 ) );
	CK( BN_mod( tmp2, p, n, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	LOOP_LARGE( i = 0, i < 100, i++ )
		{
		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 99 ) );

		CK( BN_mod_mul( tmp1, tmp1, tmp2, n, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		if( BN_is_one( tmp1 ) )
			return( CRYPT_ARGERROR_STR1 );
		}
	ENSURES( LOOP_BOUND_OK );

	/* Verify that the anomalous condition holds.  An "anomalous curve" is a 
	   curve E defined over a field of size q such that #E = q, i.e. the 
	   curve size is equal to the field size.  ECDLP on an anomalous curve 
	   can be computed very efficiently, hence we want to avoid anomalous 
	   curves.

	   The curve order is r * h, where h is the cofactor, which we computed 
	   (and checked) above */
	CK( BN_mul( tmp1, n, h, &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( BN_cmp( tmp1, p ) == 0 )
		return( CRYPT_ARGERROR_STR1 );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Check an ECC public value, typically the public key Q but more generally
   any public value such as the input to the ECDH computation */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkECCPublicValue( INOUT_PTR PKC_INFO *pkcInfo, 
						 IN_PTR const BIGNUM *qx, 
						 IN_PTR const BIGNUM *qy )
	{
	const ECC_DOMAINPARAMS *domainParams = pkcInfo->domainParams;
	const BIGNUM *p = &domainParams->p, *n = &domainParams->n;
	const EC_GROUP *ecCTX = &pkcInfo->ecCTX;
	EC_POINT *q = &pkcInfo->tmpPoint;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );
	assert( isReadPtr( qx, sizeof( BIGNUM ) ) );
	assert( isReadPtr( qy, sizeof( BIGNUM ) ) );

	REQUIRES( sanityCheckBignum( qx ) );
	REQUIRES( sanityCheckBignum( qy ) );
	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Verify that the public key parameter sizes are valid:

		qx, qy >= MIN_PKCSIZE_ECC, qx, qy <= p - 1 */
	if( !checkComponentLength( qx, p, FALSE ) || \
		!checkComponentLength( qy, p, FALSE ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that Q is not the point at infinity */
	CK( EC_POINT_set_affine_coordinates_GFp( ecCTX, q, qx, qy,
											 &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( EC_POINT_is_at_infinity( ecCTX, q ) )
		{
		DEBUG_DIAG(( "ECC Q is the point at infinity" ));
		return( CRYPT_ARGERROR_STR1 );
		}

	/* Verify that qx, qy are elements in the field Fq, i.e. in the range
	   0...p - 1.  This has already been done in the range checks performed
	   earlier */

	/* Verify that Q is a point on the curve */
	if( !isPointOnCurve( qx, qy, &domainParams->a, &domainParams->b, 
						 pkcInfo ) )
		{
		DEBUG_DIAG(( "ECC Q is not on the curve" ));
		return( CRYPT_ARGERROR_STR1 );
		}

	/* Verify that n * Q is the point at infinity, i.e. that Q is in a 
	   subgroup of order n, if we're using custom domain parameters.  For 
	   the NIST and Brainpool curves this isn't needed since the cofactor 
	   h = 1 and the group has prime order n, so n * Q = point at infinity
	   because Q is a non-identity point on the curve, so a small-subgroup 
	   attack isn't feasible */
	if( pkcInfo->curveType == CRYPT_ECCCURVE_NONE )
		{
		CK( EC_POINT_mul( ecCTX, q, NULL, q, n, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		if( !EC_POINT_is_at_infinity( ecCTX, q ) )
			{
			DEBUG_DIAG(( "ECC n * Q is not the point at infinity" ));
			return( CRYPT_ARGERROR_STR1 );
			}
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Perform validity checks on the private key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkECCPrivateKey( INOUT_PTR PKC_INFO *pkcInfo )
	{
	const ECC_DOMAINPARAMS *domainParams = pkcInfo->domainParams;
	const BIGNUM *n = &domainParams->n;
	const BIGNUM *d = &pkcInfo->eccParam_d;
	BIGNUM *tmp1 = &pkcInfo->tmp1, *tmp2 = &pkcInfo->tmp2;
	const EC_GROUP *ecCTX = &pkcInfo->ecCTX;
	EC_POINT *q = &pkcInfo->tmpPoint;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	/* Verify that the private key parameter sizes are valid:

		d >= MIN_PKCSIZE_ECC, d <= n - 1 */
	if( !checkComponentLength( d, n, FALSE ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Verify that Q = d * G */
	CK( EC_POINT_mul( ecCTX, q, d, NULL, NULL, &pkcInfo->bnCTX ) );
	CK( EC_POINT_get_affine_coordinates_GFp( ecCTX, q, tmp1, tmp2,
											 &pkcInfo->bnCTX ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );
	if( BN_cmp( tmp1, &pkcInfo->eccParam_qx ) != 0 || \
		BN_cmp( tmp2, &pkcInfo->eccParam_qy ) != 0 )
		return( CRYPT_ARGERROR_STR1 );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Generate/Initialise an ECC Key					*
*																			*
****************************************************************************/

/* Initialise the mass of variables required by the ECC operations */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initECCVariables( INOUT_PTR PKC_INFO *pkcInfo )
	{
	const ECC_DOMAINPARAMS *domainParams = pkcInfo->domainParams;
	EC_GROUP *ecCTX = &pkcInfo->ecCTX;
	EC_POINT *ecPoint = &pkcInfo->ecPoint;
	int bnStatus = BN_STATUS;

	assert( isWritePtr( pkcInfo, sizeof( PKC_INFO ) ) );

	REQUIRES( sanityCheckPKCInfo( pkcInfo ) );

	CK( EC_GROUP_set_curve_GFp( ecCTX, &domainParams->p, &domainParams->a, 
								&domainParams->b, &pkcInfo->bnCTX ) );
	CK( EC_POINT_set_affine_coordinates_GFp( ecCTX, ecPoint, 
								&domainParams->gx, &domainParams->gy, 
								&pkcInfo->bnCTX ) );
	CK( EC_GROUP_set_generator( ecCTX, ecPoint, &domainParams->n, 
								&domainParams->h ) );
	if( bnStatusError( bnStatus ) )
		return( getBnStatus( bnStatus ) );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Generate and check a generic ECC key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int generateECCkey( INOUT_PTR CONTEXT_INFO *contextInfoPtr, 
					IN_LENGTH_SHORT_MIN( bytesToBits( MIN_PKCSIZE_ECC ) ) \
						const int keyBits )
	{
	CRYPT_ECCCURVE_TYPE fieldID;
	PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const BOOLEAN sideChannelProtection = \
			TEST_FLAG( contextInfoPtr->flags, \
					   CONTEXT_FLAG_SIDECHANNELPROTECTION ) ? TRUE : FALSE;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( pkcInfo->cryptAlgo == CRYPT_ALGO_ECDH || \
			  pkcInfo->cryptAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( keyBits >= bytesToBits( MIN_PKCSIZE_ECC ) && \
			  keyBits <= bytesToBits( CRYPT_MAX_PKCSIZE_ECC ) );

	/* Find the fieldID matching the requested key size.  This gets a bit
	   complicated because with fixed-parameter curves the key size is taken 
	   to indicate the closest matching curve size (if we didn't do this and
	   required that the caller specify exact sizes to match the predefined
	   curves then they'd end up having to play guessing games to match
	   byte-valued key sizes to oddball curve sizes like P521).  To handle
	   this we map the key size to the matching curve and then load the
	   parameters from that */
	status = getECCFieldID( bitsToBytes( keyBits ), &fieldID );
	if( cryptStatusError( status ) )
		return( status );
	status = loadECCparams( contextInfoPtr, fieldID );
	if( cryptStatusError( status ) )
		return( status );

	/* Initialise the mass of variables required by the ECC operations */
	status = initECCVariables( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the private key */
	status = generateECCPrivateValue( pkcInfo, sideChannelProtection );
	if( cryptStatusError( status ) )
		return( status );

	/* We've now got a private key present, enable side-channel protection 
	   if required.  This has already been done as a side-effect of 
	   generateECCPrivateValue() but we make it explicit here */
	if( sideChannelProtection )
		{
		status = enableSidechannelProtection( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Calculate the public-key value Q = d * G */
	status = generateECCPublicValue( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Checksum the bignums to try and detect fault attacks.  Since we're
	   setting the checksum at this point there's no need to check the 
	   return value */
	( void ) checksumContextData( pkcInfo, TRUE );

	/* Make sure that the generated values are valid */
	status = checkECCDomainParameters( pkcInfo, TRUE );
	if( cryptStatusOK( status ) )
		{
		status = checkECCPublicValue( pkcInfo, &pkcInfo->eccParam_qx, 
									  &pkcInfo->eccParam_qy );
		}
	if( cryptStatusOK( status ) )
		status = checkECCPrivateKey( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that what we generated is still valid */
	if( cryptStatusError( \
			checksumContextData( pkcInfo, TRUE ) ) )
		{
		DEBUG_DIAG(( "Generated ECC key memory corruption detected" ));
		return( CRYPT_ERROR_FAILED );
		}

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}

/* Initialise and check an ECC key.  If the isECDH flag is set then it's an 
   ECDH key and we generate the d value (and by extension the Q value) if 
   it's not present */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initCheckECCkey( INOUT_PTR CONTEXT_INFO *contextInfoPtr,
					 IN_BOOL const BOOLEAN isECDH )
	{
	PKC_INFO *pkcInfo = DATAPTR_GET_PKC( contextInfoPtr );
	const ECC_DOMAINPARAMS *domainParams;
	const EC_GROUP *ecCTX;
	const BIGNUM *p;
	const BOOLEAN isPrivateKey = TEST_FLAG( contextInfoPtr->flags,
											CONTEXT_FLAG_ISPUBLICKEY ) ? \
								 FALSE : TRUE;
	const BOOLEAN sideChannelProtection = \
			TEST_FLAG( contextInfoPtr->flags, \
					   CONTEXT_FLAG_SIDECHANNELPROTECTION ) ? TRUE : FALSE;
	BOOLEAN generatedD = FALSE;
	int bnStatus = BN_STATUS, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( sanityCheckContext( contextInfoPtr ) );
	REQUIRES( isBooleanValue( isECDH ) );
	REQUIRES( pkcInfo != NULL );
	REQUIRES( pkcInfo->cryptAlgo == CRYPT_ALGO_ECDH || \
			  pkcInfo->cryptAlgo == CRYPT_ALGO_ECDSA );

	/* Now that we've checked everything, set up the various values that
	   we'll need */
	ecCTX = &pkcInfo->ecCTX;

	/* If we're loading a named curve then the public-key parameters may not 
	   have been set yet, in which case we have to set them before we can
	   continue */
	if( pkcInfo->domainParams == NULL )
		{
		status = loadECCparams( contextInfoPtr, pkcInfo->curveType );
		if( cryptStatusError( status ) )
			return( status );
		}
	domainParams = pkcInfo->domainParams;
	ENSURES( domainParams != NULL );
	p = &domainParams->p;

	/* Make sure that the necessary key parameters have been initialised */
	if( !isECDH )
		{
		/* For private keys we can have Q unavailable (see the comment 
		   further down about PKCS #11) so we only require that we have d,
		   and later on some other components, present.  However since
		   Q comes in two parts we have to make sure that the two halves 
		   match, either both absent (we generate them) or both present 
		   (we leave them as is) */
		if( isPrivateKey )
			{
			const BOOLEAN hasQX = BN_is_zero( &pkcInfo->eccParam_qx ) ? \
								  TRUE : FALSE;
			const BOOLEAN hasQY = BN_is_zero( &pkcInfo->eccParam_qy ) ? \
								  TRUE : FALSE;
			
			if( BN_is_zero( &pkcInfo->eccParam_d ) )
				return( CRYPT_ARGERROR_STR1 );
			if( hasQX != hasQY )
				return( CRYPT_ARGERROR_STR1 );
			}
		else
			{
			if( BN_is_zero( &pkcInfo->eccParam_qx ) || \
				BN_is_zero( &pkcInfo->eccParam_qy ) )
				return( CRYPT_ARGERROR_STR1 );
			}
		}

	/* Make sure that the domain parameters are valid */
	status = checkECCDomainParameters( pkcInfo, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* ECCs are somewhat weird in that the nominal key size is defined by
	   executive fiat based on the curve type.  For named curves this is 
	   fairly simple but for curves loaded as raw parameters we have to
	   recover the nominal value from the ECC p parameter */
	if( pkcInfo->keySizeBits <= 0 )
		{
		pkcInfo->keySizeBits = BN_num_bits( p );
		ENSURES( bitsToBytes( pkcInfo->keySizeBits ) >= MIN_PKCSIZE_ECC && \
				 bitsToBytes( pkcInfo->keySizeBits ) <= CRYPT_MAX_PKCSIZE_ECC );
		}

	/* Initialise the mass of variables required by the ECC operations */
	status = initECCVariables( pkcInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Additional verification for custom ECC domain parameters, verify that 
	   n * G is the point at infinity.  We have to do this at this point 
	   rather than in checkECCDomainParameters() because it requires 
	   initialisation of values that haven't been set up yet when 
	   checkECCDomainParameters() is called */
	if( pkcInfo->curveType == CRYPT_ECCCURVE_NONE )
		{
		CK( EC_POINT_mul( ecCTX, &pkcInfo->tmpPoint, &domainParams->n, 
						  NULL, NULL, &pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		if( !EC_POINT_is_at_infinity( ecCTX, &pkcInfo->tmpPoint ) )
			return( CRYPT_ARGERROR_STR1 );
		}

	/* If it's an ECDH key and there's no d value present, generate one 
	   now.  This is needed because all ECDH keys are effectively private 
	   keys.  We also update the context flags to reflect this change in 
	   status */
	if( isECDH && BN_is_zero( &pkcInfo->eccParam_d ) )
		{
		status = generateECCPrivateValue( pkcInfo, sideChannelProtection );
		if( cryptStatusError( status ) )
			return( status );
		CLEAR_FLAG( contextInfoPtr->flags, CONTEXT_FLAG_ISPUBLICKEY );
		generatedD = TRUE;
		}

	/* Enable side-channel protection if required */
	if( sideChannelProtection )
		{
		status = enableSidechannelProtection( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Some sources (specifically PKCS #11) don't make Q available for
	   private keys so if the caller is trying to load a private key with a
	   zero Q value we calculate it for them.  First, we check to make sure
	   that we have d available to calculate Q.  This is actually always the
	   case from the combination of conditions and checks above, but we make
	   it explicit here */
	if( BN_is_zero( &pkcInfo->eccParam_qx ) && \
		BN_is_zero( &pkcInfo->eccParam_d ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Calculate Q if required.  This is a bit odd because if we've 
	   generated a new d value it'll cause any existing Q value to be 
	   overwritten by a new one based on the newly-generated Q value.  This 
	   means that if we load an ECDH key from a certificate containing an 
	   existing Q value then this process will overwrite the value with a 
	   new one, so that the context associated with the certificate will 
	   contain a Q value that differs from the one in the certificate.  This 
	   is unfortunate, but again because of the ECDH key duality we need to 
	   have both a d and a Q value present otherwise the key is useless and 
	   in order to get a d value we have to recreate the Q value */
	if( BN_is_zero( &pkcInfo->eccParam_qx ) || generatedD )
		{
		/* At this point we're in a bit of a catch-22, to generate the ECC
		   public value we need to work with d but we can't check d until
		   we've got the ECC public value.  To deal with this we apply the
		   initial check in checkECCPrivateKey() to d, i.e. checking that 
		   d >= MIN_PKCSIZE_ECC, d <= n - 1 */
		if( !checkComponentLength( &pkcInfo->eccParam_d, &domainParams->n, 
								   FALSE ) )
			return( CRYPT_ARGERROR_STR1 );

		status = generateECCPublicValue( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Make sure that the public key is valid */
	status = checkECCPublicValue( pkcInfo, &pkcInfo->eccParam_qx, 
								  &pkcInfo->eccParam_qy );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the private key is valid */
	if( isPrivateKey || generatedD )
		{
		status = checkECCPrivateKey( pkcInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Checksum the bignums to try and detect fault attacks.  Since we're 
	   setting the checksum at this point there's no need to check the 
	   return value.  Note that this isn't the TOCTOU issue that it appears 
	   to be because the bignum values are read by the calling code from 
	   their stored form a second time and compared to the values that we're 
	   checksumming here */
	( void ) checksumContextData( pkcInfo, 
								  ( isPrivateKey || generatedD ) ? \
								    TRUE : FALSE );

	ENSURES( sanityCheckPKCInfo( pkcInfo ) );

	return( CRYPT_OK );
	}
#endif /* USE_ECDH || USE_ECDSA */
