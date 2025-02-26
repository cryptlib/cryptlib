/* This file is a combination of bn_isqrt.c and bn_bspw.c from:

   https://github.com/libressl-portable/openbsd/blob/master/src/lib/libcrypto/bn/bn_bpsw.c
   https://github.com/libressl-portable/openbsd/blob/master/src/lib/libcrypto/bn/bn_isqrt.c

   These are under a BSD-style license, not the usual OpenSSL license.
   
   This code isn't used because it relies on the ability to perform 
   operations on negative numbers which aren't supported by cryptlib's BN
   routines, so it will compile and link but will reject the values used */

/* Changes for cryptlib - pcg */

#if defined( INC_ALL )
  #include "bn_lcl.h"
#else
  #include "bn/bn_lcl.h"
#endif /* Compiler-specific includes */

#define BNerror( x )
#define CTASSERT( x )
#define NUMPRIMES			PRIME_TABLE_SIZE
#define primes				primeTbl
#define BN_div_ct			BN_div
#define BN_mod_ct			BN_mod
#define BN_mod_exp_ct		BN_mod_exp
#define BN_lsw( n )			( ( ( n )->top <= 0 ) ? 0 : ( n )->d[ 0 ] )

/* End changes for cryptlib - pcg */

/*	$OpenBSD: bn_isqrt.c,v 1.2 2022/07/13 11:20:00 tb Exp $ */
/*
 * Copyright (c) 2022 Theo Buehler <tb@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Calculate integer square root of |n| using a variant of Newton's method.
 *
 * Returns the integer square root of |n| in the caller-provided |out_sqrt|;
 * |*out_perfect| is set to 1 if and only if |n| is a perfect square.
 * One of |out_sqrt| and |out_perfect| can be NULL; |in_ctx| can be NULL.
 *
 * Returns 0 on error, 1 on success.
 *
 * Adapted from pure Python describing cpython's math.isqrt(), without bothering
 * with any of the optimizations in the C code. A correctness proof is here:
 * https://github.com/mdickinson/snippets/blob/master/proofs/isqrt/src/isqrt.lean
 * The comments in the Python code also give a rather detailed proof.
 */

int
bn_isqrt(BIGNUM *out_sqrt, int *out_perfect, const BIGNUM *n, BN_CTX *in_ctx)
{
	BN_CTX *ctx = NULL;
	BIGNUM *a, *b;
	int c, d, e, s;
	int cmp, perfect;
	int ret = 0;

	if (out_perfect == NULL && out_sqrt == NULL) {
		BNerror(ERR_R_PASSED_NULL_PARAMETER);
		goto err;
	}

	if (BN_is_negative(n)) {
		BNerror(BN_R_INVALID_RANGE);
		goto err;
	}

	if ((ctx = in_ctx) == NULL)
		ctx = BN_CTX_new();
	if (ctx == NULL)
		goto err;

	BN_CTX_start(ctx);

	if ((a = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((b = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (BN_is_zero(n)) {
		perfect = 1;
		if (!BN_zero(a))
			goto err;
		goto done;
	}

	if (!BN_one(a))
		goto err;

	c = (BN_num_bits(n) - 1) / 2;
	d = 0;

	/* Calculate s = floor(log(c)). */
	if (!BN_set_word(b, c))
		goto err;
	s = BN_num_bits(b) - 1;

	/*
	 * By definition, the loop below is run <= floor(log(log(n))) times.
	 * Comments in the cpython code establish the loop invariant that
	 *
	 *	(a - 1)^2 < n / 4^(c - d) < (a + 1)^2
	 *
	 * holds true in every iteration. Once this is proved via induction,
	 * correctness of the algorithm is easy.
	 *
	 * Roughly speaking, A = (a << (d - e)) is used for one Newton step
	 * "a = (A >> 1) + (m >> 1) / A" approximating m = (n >> 2 * (c - d)).
	 */

	for (; s >= 0; s--) {
		e = d;
		d = c >> s;

		if (!BN_rshift(b, n, 2 * c - d - e + 1))
			goto err;

		if (!BN_div_ct(b, NULL, b, a, ctx))
			goto err;

		if (!BN_lshift(a, a, d - e - 1))
			goto err;

		if (!BN_add(a, a, b))
			goto err;
	}

	/*
	 * The loop invariant implies that either a or a - 1 is isqrt(n).
	 * Figure out which one it is. The invariant also implies that for
	 * a perfect square n, a must be the square root.
	 */

	if (!BN_sqr(b, a, ctx))
		goto err;

	/* If a^2 > n, we must have isqrt(n) == a - 1. */
	if ((cmp = BN_cmp(b, n)) > 0) {
		if (!BN_sub_word(a, 1))
			goto err;
	}

	perfect = cmp == 0;

 done:
	if (out_perfect != NULL)
		*out_perfect = perfect;

	if (out_sqrt != NULL) {
		if (!BN_copy(out_sqrt, a))
			goto err;
	}

	ret = 1;

 err:
	BN_CTX_end(ctx);

	if (ctx != in_ctx)
		BN_CTX_free(ctx);

	return ret;
}

/*
 * is_square_mod_N[r % N] indicates whether r % N has a square root modulo N.
 * The tables are generated in regress/lib/libcrypto/bn/bn_isqrt.c.
 */

const uint8_t is_square_mod_11[] = {
	1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0,
};
CTASSERT(sizeof(is_square_mod_11) == 11);

const uint8_t is_square_mod_63[] = {
	1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
	1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
	0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
};
CTASSERT(sizeof(is_square_mod_63) == 63);

const uint8_t is_square_mod_64[] = {
	1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
};
CTASSERT(sizeof(is_square_mod_64) == 64);

const uint8_t is_square_mod_65[] = {
	1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0,
	1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0,
	0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0,
	1,
};
CTASSERT(sizeof(is_square_mod_65) == 65);

/*
 * Determine whether n is a perfect square or not.
 *
 * Returns 1 on success and 0 on error. In case of success, |*out_perfect| is
 * set to 1 if and only if |n| is a perfect square.
 */

int
bn_is_perfect_square(int *out_perfect, const BIGNUM *n, BN_CTX *ctx)
{
	BN_ULONG r;

	*out_perfect = 0;

	if (BN_is_negative(n))
		return 1;

	/*
	 * Before performing an expensive bn_isqrt() operation, weed out many
	 * obvious non-squares. See H. Cohen, "A course in computational
	 * algebraic number theory", Algorithm 1.7.3.
	 *
	 * The idea is that a square remains a square when reduced modulo any
	 * number. The moduli are chosen in such a way that a non-square has
	 * probability < 1% of passing the four table lookups.
	 */

	/* n % 64 */
	r = BN_lsw(n) & 0x3f;

	if (!is_square_mod_64[r % 64])
		return 1;

	if( !BN_mod_word( &r, n, 11 * 63 * 65 ) )	/* pcg */
		return 0;

	if (!is_square_mod_63[r % 63] ||
	    !is_square_mod_65[r % 65] ||
	    !is_square_mod_11[r % 11])
		return 1;

	return bn_isqrt(NULL, out_perfect, n, ctx);
}

/* $OpenBSD: bn_kron.c,v 1.10 2022/07/12 16:08:19 tb Exp $ */
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "bn_lcl.h"

/*
 * Kronecker symbol, implemented according to Henri Cohen, "A Course in
 * Computational Algebraic Number Theory", Algorithm 1.4.10.
 *
 * Returns -1, 0, or 1 on success and -2 on error.
 */

int
BN_kronecker(const BIGNUM *A, const BIGNUM *B, BN_CTX *ctx)
{
	/* tab[BN_lsw(n) & 7] = (-1)^((n^2 - 1)) / 8) for odd values of n. */
	static const int tab[8] = {0, 1, 0, -1, 0, -1, 0, 1};
	BIGNUM *a, *b, *tmp;
	int k, v;
	int ret = -2;

	bn_check_top(A);
	bn_check_top(B);

	BN_CTX_start(ctx);

	if ((a = BN_CTX_get(ctx)) == NULL)
		goto end;
	if ((b = BN_CTX_get(ctx)) == NULL)
		goto end;

	if (BN_copy(a, A) == NULL)
		goto end;
	if (BN_copy(b, B) == NULL)
		goto end;

	/*
	 * Cohen's step 1:
	 */

	/* If b is zero, output 1 if |a| is 1, otherwise output 0. */
	if (BN_is_zero(b)) {
#if 0	/* pcg */
		ret = BN_abs_is_word(a, 1);
#else
		assert( !BN_is_negative( a ) );
		ret = BN_is_one( a );
#endif
		goto end;
	}

	/*
	 * Cohen's step 2:
	 */

	/* If both are even, they have a factor in common, so output 0. */
	if (!BN_is_odd(a) && !BN_is_odd(b)) {
		ret = 0;
		goto end;
	}

	/* Factorize b = 2^v * u with odd u and replace b with u. */
	v = 0;
	while (!BN_is_bit_set(b, v))
		v++;
	if (v > 0 && !BN_rshift(b, b, v))	/* pcg */
		goto end;

	/* If v is even set k = 1, otherwise set it to (-1)^((a^2 - 1) / 8). */
	k = 1;
	if (v % 2 != 0)
		k = tab[BN_lsw(a) & 7];

	/*
	 * If b is negative, replace it with -b and if a is also negative
	 * replace k with -k.
	 */
	if (BN_is_negative(b)) {
		BN_set_negative(b, 0);

		if (BN_is_negative(a))
			k = -k;
	}

	/*
	 * Now b is positive and odd, so compute the Jacobi symbol (a/b)
	 * and multiply it by k.
	 */

	while (1) {
		/*
		 * Cohen's step 3:
		 */

		/* b is positive and odd. */

		/* If a is zero output k if b is one, otherwise output 0. */
		if (BN_is_zero(a)) {
			ret = BN_is_one(b) ? k : 0;
			goto end;
		}

		/* Factorize a = 2^v * u with odd u and replace a with u. */
		v = 0;
		while (!BN_is_bit_set(a, v))
			v++;
		if (v > 0 && !BN_rshift(a, a, v))	/* pcg */
			goto end;

		/* If v is odd, multiply k with (-1)^((b^2 - 1) / 8). */
		if (v % 2 != 0)
			k *= tab[BN_lsw(b) & 7];

		/*
		 * Cohen's step 4:
		 */

		/*
		 * Apply the reciprocity law: multiply k by (-1)^((a-1)(b-1)/4).
		 *
		 * This expression is -1 if and only if a and b are 3 (mod 4).
		 * In turn, this is the case if and only if their two's
		 * complement representations have the second bit set.
		 * a could be negative in the first iteration, b is positive.
		 */
		if ((BN_is_negative(a) ? ~BN_lsw(a) : BN_lsw(a)) & BN_lsw(b) & 2)
			k = -k;

		/*
		 * (a, b) := (b mod |a|, |a|)
		 *
		 * Once this is done, we know that 0 < a < b at the start of the
		 * loop. Since b is strictly decreasing, the loop terminates.
		 */

		if (!BN_nnmod(b, b, a, ctx))
			goto end;

		tmp = a;
		a = b;
		b = tmp;

		BN_set_negative(b, 0);
	}

 end:
	BN_CTX_end(ctx);

	return ret;
}

/*	$OpenBSD: bn_bpsw.c,v 1.5 2022/07/29 08:37:33 tb Exp $ */
/*
 * Copyright (c) 2022 Martin Grenouilloux <martin.grenouilloux@lse.epita.fr>
 * Copyright (c) 2022 Theo Buehler <tb@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * For an odd n compute a / 2 (mod n). If a is even, we can do a plain
 * division, otherwise calculate (a + n) / 2. Then reduce (mod n).
 */

static int
bn_div_by_two_mod_odd_n(BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
	if (!BN_is_odd(n))
		return 0;

	if (BN_is_odd(a)) {
		if (!BN_add(a, a, n))
			return 0;
	}
	if (!BN_rshift1(a, a))
		return 0;
	if (!BN_mod_ct(a, a, n, ctx))
		return 0;

	return 1;
}

/*
 * Given the next binary digit of k and the current Lucas terms U and V, this
 * helper computes the next terms in the Lucas sequence defined as follows:
 *
 *   U' = U * V                  (mod n)
 *   V' = (V^2 + D * U^2) / 2    (mod n)
 *
 * If digit == 0, bn_lucas_step() returns U' and V'. If digit == 1, it returns
 *
 *   U'' = (U' + V') / 2         (mod n)
 *   V'' = (V' + D * U') / 2     (mod n)
 *
 * Compare with FIPS 186-4, Appendix C.3.3, step 6.
 */

static int
bn_lucas_step(BIGNUM *U, BIGNUM *V, int digit, const BIGNUM *D,
    const BIGNUM *n, BN_CTX *ctx)
{
	BIGNUM *tmp;
	int ret = 0;

	BN_CTX_start(ctx);

	if ((tmp = BN_CTX_get(ctx)) == NULL)
		goto err;

	/* Calculate D * U^2 before computing U'. */
	if (!BN_sqr(tmp, U, ctx))
		goto err;
	if (!BN_mul(tmp, D, tmp, ctx))
		goto err;

	/* U' = U * V (mod n). */
	if (!BN_mod_mul(U, U, V, n, ctx))
		goto err;

	/* V' = (V^2 + D * U^2) / 2 (mod n). */
	if (!BN_sqr(V, V, ctx))
		goto err;
	if (!BN_add(V, V, tmp))
		goto err;
	if (!bn_div_by_two_mod_odd_n(V, n, ctx))
		goto err;

	if (digit == 1) {
		/* Calculate D * U' before computing U''. */
		if (!BN_mul(tmp, D, U, ctx))
			goto err;

		/* U'' = (U' + V') / 2 (mod n). */
		if (!BN_add(U, U, V))
			goto err;
		if (!bn_div_by_two_mod_odd_n(U, n, ctx))
			goto err;

		/* V'' = (V' + D * U') / 2 (mod n). */
		if (!BN_add(V, V, tmp))
			goto err;
		if (!bn_div_by_two_mod_odd_n(V, n, ctx))
			goto err;
	}

	ret = 1;

 err:
	BN_CTX_end(ctx);

	return ret;
}

/*
 * Compute the Lucas terms U_k, V_k, see FIPS 186-4, Appendix C.3.3, steps 4-6.
 */

static int
bn_lucas(BIGNUM *U, BIGNUM *V, const BIGNUM *k, const BIGNUM *D,
    const BIGNUM *n, BN_CTX *ctx)
{
	int digit, i;
	int ret = 0;

	if (!BN_one(U))
		goto err;
	if (!BN_one(V))
		goto err;

	/*
	 * Iterate over the digits of k from MSB to LSB. Start at digit 2
	 * since the first digit is dealt with by setting U = 1 and V = 1.
	 */

	for (i = BN_num_bits(k) - 2; i >= 0; i--) {
		digit = BN_is_bit_set(k, i);

		if (!bn_lucas_step(U, V, digit, D, n, ctx))
			goto err;
	}

	ret = 1;

 err:
	return ret;
}

/*
 * This is a stronger variant of the Lucas test in FIPS 186-4, Appendix C.3.3.
 * Every strong Lucas pseudoprime n is also a Lucas pseudoprime since
 * U_{n+1} == 0 follows from U_k == 0 or V_{k * 2^r} == 0 for 0 <= r < s.
 */

static int
bn_strong_lucas_test(int *is_prime, const BIGNUM *n, const BIGNUM *D,
    BN_CTX *ctx)
{
	BIGNUM *k, *U, *V;
	int r, s;
	int ret = 0;

	BN_CTX_start(ctx);

	if ((k = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((U = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((V = BN_CTX_get(ctx)) == NULL)
		goto err;

	/*
	 * Factorize n + 1 = k * 2^s with odd k: shift away the s trailing ones
	 * of n and set the lowest bit of the resulting number k.
	 */

	s = 0;
	while (BN_is_bit_set(n, s))
		s++;
	if (s > 0 && !BN_rshift(k, n, s))	/* pcg */
		goto err;
	if (!BN_set_bit(k, 0))
		goto err;

	/*
	 * Calculate the Lucas terms U_k and V_k. If either of them is zero,
	 * then n is a strong Lucas pseudoprime.
	 */

	if (!bn_lucas(U, V, k, D, n, ctx))
		goto err;

	if (BN_is_zero(U) || BN_is_zero(V)) {
		*is_prime = 1;
		goto done;
	}

	/*
	 * Calculate the Lucas terms U_{k * 2^r}, V_{k * 2^r} for 1 <= r < s.
	 * If any V_{k * 2^r} is zero then n is a strong Lucas pseudoprime.
	 */

	for (r = 1; r < s; r++) {
		if (!bn_lucas_step(U, V, 0, D, n, ctx))
			goto err;

		if (BN_is_zero(V)) {
			*is_prime = 1;
			goto done;
		}
	}

	/*
	 * If we got here, n is definitely composite.
	 */

	*is_prime = 0;

 done:
	ret = 1;

 err:
	BN_CTX_end(ctx);

	return ret;
}

/*
 * Test n for primality using the strong Lucas test with Selfridge's Method A.
 * Returns 1 if n is prime or a strong Lucas-Selfridge pseudoprime.
 * If it returns 0 then n is definitely composite.
 */

int bn_strong_lucas_selfridge(int *is_prime, const BIGNUM *n, BN_CTX *ctx)	/* pcg */
{
	BIGNUM *D, *two;
	int is_perfect_square, jacobi_symbol, sign;
	int ret = 0;

	BN_CTX_start(ctx);

	/* If n is a perfect square, it is composite. */
	if (!bn_is_perfect_square(&is_perfect_square, n, ctx))
		goto err;
	if (is_perfect_square) {
		*is_prime = 0;
		goto done;
	}

	/*
	 * Find the first D in the Selfridge sequence 5, -7, 9, -11, 13, ...
	 * such that the Jacobi symbol (D/n) is -1.
	 */

	if ((D = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((two = BN_CTX_get(ctx)) == NULL)
		goto err;

	sign = 1;
	if (!BN_set_word(D, 5))
		goto err;
	if (!BN_set_word(two, 2))
		goto err;

	while (1) {
		/* For odd n the Kronecker symbol computes the Jacobi symbol. */
		if ((jacobi_symbol = BN_kronecker(D, n, ctx)) == -2)
			goto err;

		/* We found the value for D. */
		if (jacobi_symbol == -1)
			break;

		/* n and D have prime factors in common. */
		if (jacobi_symbol == 0) {
			*is_prime = 0;
			goto done;
		}

		sign = -sign;
		if (!BN_uadd(D, D, two))
			goto err;
		BN_set_negative(D, sign == -1);
	}

	if (!bn_strong_lucas_test(is_prime, n, D, ctx))
		goto err;

 done:
	ret = 1;

 err:
	BN_CTX_end(ctx);

	return ret;
}
