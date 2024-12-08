<<<<<<< HEAD
/****************************************************************************
*																			*
*						cryptlib PKC Keygen Header File 					*
*					  Copyright Peter Gutmann 1997-2015						*
*																			*
****************************************************************************/

#ifndef _KEYGEN_DEFINED

#define _KEYGEN_DEFINED

/* The number of iterations of Miller-Rabin for an error probbility of
   (1/2)^80, from HAC */

#define getNoPrimeChecks( noBits ) \
	( ( ( noBits ) < 150 ) ? 18 : ( ( noBits ) < 200 ) ? 15 : \
	  ( ( noBits ) < 250 ) ? 12 : ( ( noBits ) < 300 ) ? 9 : \
	  ( ( noBits ) < 350 ) ? 8 : ( ( noBits ) < 400 ) ? 7 : \
	  ( ( noBits ) < 500 ) ? 6 : ( ( noBits ) < 600 ) ? 5 : \
	  ( ( noBits ) < 800 ) ? 4 : ( ( noBits ) < 1250 ) ? 3 : 2 )

#define MAX_NO_PRIME_CHECKS		50

/* The size of the prime sieve array, 1 memory page (on most CPUs) = 4K 
   candidate values.  When changing this value the LFSR parameters need to 
   be adjusted to match */

#define SIEVE_SIZE				4096

/* The size of the predefined prime table array */

#ifdef CONFIG_CONSERVE_MEMORY
  #define PRIME_TABLE_SIZE		100
#else
  #define PRIME_TABLE_SIZE		2000
#endif /* CONFIG_CONSERVE_MEMORY */

/* Random-data access function, used to allow deterministic prime generation 
   when generating DLP parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
typedef int ( *GETRANDOMDATA_FUNCTION )( INOUT_PTR_OPT void *randomState,
										 OUT_BUFFER_FIXED( noBytes ) void *buffer, 
										 IN_LENGTH_PKC const int noBytes  );
typedef struct { 
	FNPTR getRandomFunction;
	void *getRandomState;
	} GET_RANDOM_INFO;

/* Prototypes for functions in ctx_bsieve.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int initSieve( IN_ARRAY( sieveSize ) BOOLEAN *sieveArray, 
			   IN_LENGTH_FIXED( SIEVE_SIZE ) const int sieveSize,
			   const BIGNUM *candidate );
CHECK_RETVAL_RANGE( 0, SIEVE_SIZE ) \
int nextSievePosition( IN_INT_SHORT int value );
CHECK_RETVAL_RANGE( 0, PRIME_TABLE_SIZE ) \
int getSieveEntry( IN_RANGE( 0, PRIME_TABLE_SIZE - 1 ) int position );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN primeCheckQuick( const BIGNUM *candidate );

/* Prototypes for functions in kg_prime.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int primeProbable( INOUT_PTR PKC_INFO *pkcInfo, 
				   INOUT_PTR BIGNUM *n, 
				   IN_RANGE( 1, MAX_NO_PRIME_CHECKS ) const int noChecks,
				   OUT_PTR BOOLEAN *isPrime );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int primeProbableFermat( INOUT_PTR PKC_INFO *pkcInfo, 
						 const BIGNUM *n,
						 INOUT_PTR BN_MONT_CTX *montCTX_n,
						 OUT_PTR BOOLEAN *isPrime );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int generatePrime( INOUT_PTR PKC_INFO *pkcInfo, 
				   INOUT_PTR BIGNUM *candidate, 
				   IN_LENGTH_SHORT_MIN( 120 ) const int noBits, 
				   IN_PTR_OPT const GET_RANDOM_INFO *getRandomInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int generatePrimeRSA( INOUT_PTR PKC_INFO *pkcInfo, 
					  INOUT_PTR BIGNUM *candidate, 
					  IN_LENGTH_SHORT_MIN( bytesToBits( MIN_PKCSIZE ) / 2 ) \
							const int noBits, 
					  IN_INT const long exponent );

#endif /* _KEYGEN_DEFINED */

=======
/****************************************************************************
*																			*
*						cryptlib PKC Keygen Header File 					*
*					  Copyright Peter Gutmann 1997-2015						*
*																			*
****************************************************************************/

#ifndef _KEYGEN_DEFINED

#define _KEYGEN_DEFINED

/* The number of iterations of Miller-Rabin for an error probbility of
   (1/2)^80, from HAC */

#define getNoPrimeChecks( noBits ) \
	( ( ( noBits ) < 150 ) ? 18 : ( ( noBits ) < 200 ) ? 15 : \
	  ( ( noBits ) < 250 ) ? 12 : ( ( noBits ) < 300 ) ? 9 : \
	  ( ( noBits ) < 350 ) ? 8 : ( ( noBits ) < 400 ) ? 7 : \
	  ( ( noBits ) < 500 ) ? 6 : ( ( noBits ) < 600 ) ? 5 : \
	  ( ( noBits ) < 800 ) ? 4 : ( ( noBits ) < 1250 ) ? 3 : 2 )

#define MAX_NO_PRIME_CHECKS		50

/* The size of the prime sieve array, 1 memory page (on most CPUs) = 4K 
   candidate values.  When changing this value the LFSR parameters need to 
   be adjusted to match */

#define SIEVE_SIZE				4096

/* The size of the predefined prime table array */

#ifdef CONFIG_CONSERVE_MEMORY
  #define PRIME_TABLE_SIZE		100
#else
  #define PRIME_TABLE_SIZE		2000
#endif /* CONFIG_CONSERVE_MEMORY */

/* Random-data access function, used to allow deterministic prime generation 
   when generating DLP parameters */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
typedef int ( *GETRANDOMDATA_FUNCTION )( INOUT_PTR_OPT void *randomState,
										 OUT_BUFFER_FIXED( noBytes ) void *buffer, 
										 IN_LENGTH_PKC const int noBytes  );
typedef struct { 
	FNPTR getRandomFunction;
	void *getRandomState;
	} GET_RANDOM_INFO;

/* Prototypes for functions in ctx_bsieve.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int initSieve( IN_ARRAY( sieveSize ) BOOLEAN *sieveArray, 
			   IN_LENGTH_FIXED( SIEVE_SIZE ) const int sieveSize,
			   const BIGNUM *candidate );
CHECK_RETVAL_RANGE( 0, SIEVE_SIZE ) \
int nextSievePosition( IN_INT_SHORT int value );
CHECK_RETVAL_RANGE( 0, PRIME_TABLE_SIZE ) \
int getSieveEntry( IN_RANGE( 0, PRIME_TABLE_SIZE - 1 ) int position );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN primeCheckQuick( const BIGNUM *candidate );

/* Prototypes for functions in kg_prime.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int primeProbable( INOUT_PTR PKC_INFO *pkcInfo, 
				   INOUT_PTR BIGNUM *n, 
				   IN_RANGE( 1, MAX_NO_PRIME_CHECKS ) const int noChecks,
				   OUT_PTR BOOLEAN *isPrime );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int primeProbableFermat( INOUT_PTR PKC_INFO *pkcInfo, 
						 const BIGNUM *n,
						 INOUT_PTR BN_MONT_CTX *montCTX_n,
						 OUT_PTR BOOLEAN *isPrime );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int generatePrime( INOUT_PTR PKC_INFO *pkcInfo, 
				   INOUT_PTR BIGNUM *candidate, 
				   IN_LENGTH_SHORT_MIN( 120 ) const int noBits, 
				   IN_PTR_OPT const GET_RANDOM_INFO *getRandomInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int generatePrimeRSA( INOUT_PTR PKC_INFO *pkcInfo, 
					  INOUT_PTR BIGNUM *candidate, 
					  IN_LENGTH_SHORT_MIN( bytesToBits( MIN_PKCSIZE ) / 2 ) \
							const int noBits, 
					  IN_INT const long exponent );

#endif /* _KEYGEN_DEFINED */

>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
