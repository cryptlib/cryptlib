/* Header file to interface to the DJB algorithm suite */

#ifdef DJB_INTERNAL

/* NaCl glue functionality for djb-internal code */

#define sodium_memzero		zeroise
#define COMPILER_ASSERT		assert
#ifdef _MSC_VER	
  #define LONGLONG_TYPE		__int64
#else
  #define LONGLONG_TYPE		long long
#endif /* Compiler-specific 64-bit type */
#define ROTL32( value, bits ) \
		( ( ( value ) << ( bits ) ) | ( ( value ) >> ( 32 - ( bits ) ) ) )
#define LOAD32_LE( memPtr ) \
		(	( uint32_t ) ( memPtr )[ 0 ] | \
		  ( ( uint32_t ) ( memPtr )[ 1 ] << 8 ) | \
		  ( ( uint32_t ) ( memPtr )[ 2 ] << 16 ) | \
		  ( ( uint32_t ) ( memPtr )[ 3 ] << 24 ) )
#define STORE32_LE( memPtr, data ) \
		( memPtr )[ 0 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		( memPtr )[ 1 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		( memPtr )[ 2 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		( memPtr )[ 3 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF )

#endif /* DJB_INTERNAL */

#define poly1305_block_size	16

typedef struct poly1305_state_internal_t {
    unsigned long      r[5];
    unsigned long      h[5];
    unsigned long      pad[4];
    unsigned long	   leftover;
    unsigned char      buffer[poly1305_block_size];
    unsigned char      final;
} poly1305_state_internal_t;

#define POLY1305_STATE_SIZE	\
		( ( 15 * sizeof( unsigned long ) ) + poly1305_block_size + 1 )

void poly1305_init(poly1305_state_internal_t *st, const unsigned char key[32]);
void poly1305_update(poly1305_state_internal_t *st, const unsigned char *m, 
						unsigned long bytes);
void poly1305_finish(poly1305_state_internal_t *st, unsigned char mac[16]);

typedef struct chacha_ctx {
    uint32_t input[16];
} chacha_ctx;

void chacha_keysetup(chacha_ctx *ctx, const uint8_t *k);
void chacha_ietf_ivsetup(chacha_ctx *ctx, const uint8_t *iv, const uint8_t *counter);
void chacha20_encrypt_bytes(chacha_ctx *ctx, const uint8_t *m, uint8_t *c,
                       unsigned long bytes);	/* m = plaintext message, c = ciphertext */
