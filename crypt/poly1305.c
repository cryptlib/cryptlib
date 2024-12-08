<<<<<<< HEAD
/* /libsodium-stable/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c

   Changes for cryptlib.  In addition, replace all 'long long' in function 
   parameters with 'long'	- pcg */

#define DJB_INTERNAL

#include "crypt.h"
#include "crypt/djb.h"

/* End changes for cryptlib - pcg */
=======
/* /libsodium-stable/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c

   Changes for cryptlib.  In addition, replace all 'long long' in function 
   parameters with 'long'	- pcg */

#define DJB_INTERNAL

#include "crypt.h"
#include "crypt/djb.h"

/* End changes for cryptlib - pcg */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae

#ifdef HAVE_TI_MODE
#include "poly1305_64.h"
#else
#include "poly1305_32.h"
#endif

void	/* pcg */
poly1305_update(poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long bytes)
{
    unsigned long i;

    /* handle leftover */
    if (st->leftover) {
        unsigned long want = (poly1305_block_size - st->leftover);

        if (want > bytes) {
            want = bytes;
        }
        for (i = 0; i < want; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_block_size) {
            return;
        }
        poly1305_blocks(st, st->buffer, poly1305_block_size);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_block_size) {
        unsigned long want = (bytes & ~(poly1305_block_size - 1));

        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        st->leftover += bytes;
    }
}

int	/* pcg */
crypto_onetimeauth_poly1305_donna(unsigned char *out, const unsigned char *m,
                                  unsigned long   inlen,
                                  const unsigned char *key)
<<<<<<< HEAD
{
#if 0	/* pcg */
    CRYPTO_ALIGN(64) poly1305_state_internal_t state;
#else
	ALIGN_DATA( hashState, sizeof( poly1305_state_internal_t ), 16 );
	poly1305_state_internal_t *state = ALIGN_GET_PTR( hashState, 16 );
#endif /* 0 */
=======
{
#if 0	/* pcg */
    CRYPTO_ALIGN(64) poly1305_state_internal_t state;
#else
	ALIGN_DATA( hashState, sizeof( poly1305_state_internal_t ), 16 );
	poly1305_state_internal_t *state = ALIGN_GET_PTR( hashState, 16 );
#endif /* 0 */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae

    poly1305_init(state, key);
    poly1305_update(state, m, inlen);
    poly1305_finish(state, out);

    return 0;
}
<<<<<<< HEAD

#if 0	/* pcg - temp */
=======

#if 0	/* pcg - temp */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae

static int
crypto_onetimeauth_poly1305_donna_init(crypto_onetimeauth_poly1305_state *state,
                                       const unsigned char *key)
{
    COMPILER_ASSERT(sizeof(crypto_onetimeauth_poly1305_state) >=
        sizeof(poly1305_state_internal_t));
    poly1305_init((poly1305_state_internal_t *) (void *) state, key);

    return 0;
}

static int
crypto_onetimeauth_poly1305_donna_update(
    crypto_onetimeauth_poly1305_state *state, const unsigned char *in,
    unsigned long inlen)
{
    poly1305_update((poly1305_state_internal_t *) (void *) state, in, inlen);

    return 0;
}

static int
crypto_onetimeauth_poly1305_donna_final(
    crypto_onetimeauth_poly1305_state *state, unsigned char *out)
{
    poly1305_finish((poly1305_state_internal_t *) (void *) state, out);

    return 0;
}

static int
crypto_onetimeauth_poly1305_donna_verify(const unsigned char *h,
                                         const unsigned char *in,
                                         unsigned long   inlen,
                                         const unsigned char *k)
{
    unsigned char correct[16];

    crypto_onetimeauth_poly1305_donna(correct, in, inlen, k);

    return crypto_verify_16(h, correct);
<<<<<<< HEAD
}
#endif

#if 0	/* pcg */
=======
}
#endif

#if 0	/* pcg */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae

struct crypto_onetimeauth_poly1305_implementation
    crypto_onetimeauth_poly1305_donna_implementation = {
        SODIUM_C99(.onetimeauth =) crypto_onetimeauth_poly1305_donna,
        SODIUM_C99(.onetimeauth_verify =)
            crypto_onetimeauth_poly1305_donna_verify,
        SODIUM_C99(.onetimeauth_init =) crypto_onetimeauth_poly1305_donna_init,
        SODIUM_C99(.onetimeauth_update =)
            crypto_onetimeauth_poly1305_donna_update,
        SODIUM_C99(.onetimeauth_final =) crypto_onetimeauth_poly1305_donna_final
    };
<<<<<<< HEAD
#endif /* pcg */
=======
#endif /* pcg */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
