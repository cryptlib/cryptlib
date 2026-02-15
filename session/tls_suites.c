/****************************************************************************
*																			*
*						cryptlib TLS Cipher Suites							*
*					Copyright Peter Gutmann 1998-2020						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "tls.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/****************************************************************************
*																			*
*							Cipher Suite Definitions						*
*																			*
****************************************************************************/

/* The monster list of cryptlib's TLS cipher suites (the full list is much, 
   much longer than this).  There are a pile of DH cipher suites, in 
   practice only DHE is used, DH requires the use of X9.42 DH certificates 
   (there aren't any) and DH_anon uses unauthenticated DH which implementers 
   seem to have an objection to even though it's not much different in 
   effect from the way RSA cipher suites are used in practice.

   To keep things simple for the caller we only allow RSA auth for DH key
   agreement and not DSA, since the former also automatically works for the
   far more common RSA key exchange that's usually used for key setup.
   In theory we should only allow ECDSA for ECDH, however due to the 
   practical nonexistence of ECDSA certificates except from boutique CAs for
   many years everyone who did ECDH used it with RSA certificates, so we 
   have to support the rather odd combination of ECDH for keyex but RSA for 
   authentication.

   We prefer AES-128 to AES-256 since -256 has a weaker key schedule than
   -128, so if anyone's going to attack it they'll go for the key schedule
   rather than the (mostly irrelevant) -128 vs. -256.

   We allow 3DES suites if the algorithm is enabled because it's difficult 
   to take the SWEET32 "vulnerability", which requires that an attacker 
   use adaptive chosen plaintext injected via a JS man-in-the-browser 
   attack and then record 785 GB of traffic encrypted with the same key to 
   recover an HTTP cookie, seriously.

   In some piece of SuiteB bizarritude a number of suites that have a
   xxx_WITH_AES_128_xxx_SHA256 only have a xxx_WITH_AES_256_xxx_SHA384
   equivalent but no xxx_WITH_AES_256_xxx_SHA256, which is why there are a
   number of suites with apparently-mismatched AES-128 only options.

   The number of suites and different configuration options are sufficiently
   complex that we can't use a fixed table for them but have to dynamically
   build them up at runtime from the following sub-tables */

static const CIPHERSUITE_INFO cipherSuiteDH[] = {
	/* AES with DH */
	{ TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	  DESCRIPTION( "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, SHA2MAC_SIZE, 
	  CIPHERSUITE_FLAG_TLS12 },
	{ TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	  DESCRIPTION( "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 32, SHA2MAC_SIZE, 
	  CIPHERSUITE_FLAG_TLS12 },
	{ TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	  DESCRIPTION( "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 16, SHA1MAC_SIZE },
	{ TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	  DESCRIPTION( "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 32, SHA1MAC_SIZE },

	/* 3DES with DH */
#ifdef USE_3DES
	{ TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	  DESCRIPTION( "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 24, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_TRIGGER },
#endif /* USE_3DES */

	/* End-of-list marker */
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE },
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE }
	};

#ifdef USE_ECDH

static const CIPHERSUITE_INFO cipherSuiteECC[] = {
  #ifdef USE_ECDSA
	/* ECDH with ECDSA */
	{ TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 
	  DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, SHA2MAC_SIZE, CIPHERSUITE_FLAG_TLS12 },
  #ifdef CONFIG_SUITEB
	{ TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA384, 
	  DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA384" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 48, 16, 48, CIPHERSUITE_FLAG_TLS12 }, 
  #endif /* CONFIG_SUITEB */
	{ TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 
	  DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },
	{ TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 
	  DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },
	#ifdef USE_3DES
	{ TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, 
	  DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_TRIGGER },
	#endif /* USE_3DES */
  #endif /* USE_ECDSA */

	/* ECDH with RSA, see the comment at the start for why this is used */
	{ TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 
	  DESCRIPTION( "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, SHA2MAC_SIZE, CIPHERSUITE_FLAG_TLS12 },
  #ifdef CONFIG_SUITEB
	{ TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 
	  DESCRIPTION( "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 48, 32, 48, CIPHERSUITE_FLAG_TLS12 }, 
  #endif /* CONFIG_SUITEB */
	{ TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 
	  DESCRIPTION( "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE }, 
	{ TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 
	  DESCRIPTION( "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },

	/* End-of-list marker */
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE },
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE }
	};
#endif /* USE_ECDH */

#ifdef USE_GCM

static const CIPHERSUITE_INFO cipherSuiteGCM[] = {
	/* ECDH with ECDSA and AES-GCM */
	{ TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 
	  DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 },
  #ifdef CONFIG_SUITEB
	{ TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA384, 
	  DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA384" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 48, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 }, 
  #endif /* CONFIG_SUITEB */

	/* ECDH with RSA and AES-GCM, see the comment at the start for why this 
	   is used */
	{ TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 
	  DESCRIPTION( "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 },
  #ifdef CONFIG_SUITEB
	{ TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 
	  DESCRIPTION( "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 48, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 }, 
  #endif /* CONFIG_SUITEB */

	/* AES-GCM with DH */
	{ TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	  DESCRIPTION( "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 },
  #ifdef CONFIG_SUITEB
	{ TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	  DESCRIPTION( "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 }, 
  #endif /* CONFIG_SUITEB */

	/* AES-GCM with RSA */
	{ TLS_RSA_WITH_AES_128_GCM_SHA256,
	  DESCRIPTION( "TLS_RSA_WITH_AES_128_GCM_SHA256" )
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 },
  #ifdef CONFIG_SUITEB
	{ TLS_RSA_WITH_AES_256_GCM_SHA384,
	  DESCRIPTION( "TLS_RSA_WITH_AES_256_GCM_SHA384" )
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 48, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 }, 
  #endif /* CONFIG_SUITEB */

	/* AES-GCM symmetric-only suites for TLS 1.3 */
#ifdef USE_TLS13
	{ TLS_AES_128_GCM_SHA256, 
	  DESCRIPTION( "TLS_AES_128_GCM_SHA256" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 32, 16, GCMICV_SIZE, 
	  CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS13 },
#endif /* USE_TLS13 */

	/* End-of-list marker */
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE },
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE }
	};
#endif /* USE_GCM */

static const CIPHERSUITE_INFO cipherSuitePSK[] = {
	/* PSK with PFS */
	{ TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
	  DESCRIPTION( "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, SHA2MAC_SIZE, 
	  CIPHERSUITE_FLAG_PSK | CIPHERSUITE_FLAG_TLS12 },
	{ TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
	  DESCRIPTION( "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 16, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_PSK },
	{ TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
	  DESCRIPTION( "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 32, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_PSK },
#ifdef USE_3DES
	{ TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
	  DESCRIPTION( "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_NONE, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 24, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_PSK | CIPHERSUITE_FLAG_TRIGGER },
#endif /* USE_3DES */

	/* PSK without PFS */
	{ TLS_PSK_WITH_AES_128_CBC_SHA256,
	  DESCRIPTION( "TLS_PSK_WITH_AES_128_CBC_SHA256" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, SHA2MAC_SIZE, 
	  CIPHERSUITE_FLAG_PSK | CIPHERSUITE_FLAG_TLS12 },
	{ TLS_PSK_WITH_AES_128_CBC_SHA,
	  DESCRIPTION( "TLS_PSK_WITH_AES_128_CBC_SHA" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 16, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_PSK },
	{ TLS_PSK_WITH_AES_256_CBC_SHA,
	  DESCRIPTION( "TLS_PSK_WITH_AES_256_CBC_SHA" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 32, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_PSK },
#ifdef USE_3DES
	{ TLS_PSK_WITH_3DES_EDE_CBC_SHA,
	  DESCRIPTION( "TLS_PSK_WITH_3DES_EDE_CBC_SHA" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 24, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_PSK | CIPHERSUITE_FLAG_TRIGGER },
#endif /* USE_3DES */

	/* End-of-list marker */
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE },
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE }
	};

#ifdef USE_CHACHA20

static const CIPHERSUITE_INFO cipherSuiteBernstein[] = {
	{ TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 
	  DESCRIPTION( "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_CHACHA20,
	  CRYPT_ALGO_POLY1305, 0, 32, 16, 
	  CIPHERSUITE_FLAG_BERNSTEIN | CIPHERSUITE_FLAG_TLS12 },
	
	{ TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
	  DESCRIPTION( "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" )
	  CRYPT_ALGO_DH, CRYPT_ALGO_NONE, CRYPT_ALGO_CHACHA20,
	  CRYPT_ALGO_POLY1305, 0, 32, 16, 
	  CIPHERSUITE_FLAG_PSK | CIPHERSUITE_FLAG_BERNSTEIN | \
							 CIPHERSUITE_FLAG_TLS12 },

	{ TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	  DESCRIPTION( "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_CHACHA20,
	  CRYPT_ALGO_POLY1305, 0, 32, 16, 
	  CIPHERSUITE_FLAG_PSK | CIPHERSUITE_FLAG_BERNSTEIN | \
							 CIPHERSUITE_FLAG_TLS12 },

  #ifdef USE_ECDH
	{ TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	  DESCRIPTION( "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_CHACHA20,
	  CRYPT_ALGO_POLY1305, 0, 32, 16, 
	  CIPHERSUITE_FLAG_BERNSTEIN | CIPHERSUITE_FLAG_TLS12 },

	{ TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 
	  DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" )
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_CHACHA20,
	  CRYPT_ALGO_POLY1305, 0, 32, 16, 
	  CIPHERSUITE_FLAG_BERNSTEIN | CIPHERSUITE_FLAG_TLS12 },
  #endif /* USE_ECDH */

	/* Symmetric-only suites for TLS 1.3 */
#ifdef USE_TLS13
	{ TLS_CHACHA20_POLY1305_SHA256,
	  DESCRIPTION( "TLS_CHACHA20_POLY1305_SHA256" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_CHACHA20,
	  CRYPT_ALGO_POLY1305, 32, 32, 16, 
	  CIPHERSUITE_FLAG_BERNSTEIN | CIPHERSUITE_FLAG_TLS13 },
#endif /* USE_TLS13 */

	/* End-of-list marker */
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE },
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE }
	};
#endif /* USE_CHACHA20 */

#ifdef USE_RSA_SUITES

static const CIPHERSUITE_INFO cipherSuiteRSA[] = {
	/* AES with RSA */
	{ TLS_RSA_WITH_AES_128_CBC_SHA256,
	  DESCRIPTION( "TLS_RSA_WITH_AES_128_CBC_SHA256" )
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 16, SHA2MAC_SIZE, 
	  CIPHERSUITE_FLAG_TLS12 | CIPHERSUITE_FLAG_TRIGGER },
	{ TLS_RSA_WITH_AES_256_CBC_SHA256,
	  DESCRIPTION( "TLS_RSA_WITH_AES_256_CBC_SHA256" )
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA2, 0, 32, SHA2MAC_SIZE, 
	  CIPHERSUITE_FLAG_TLS12 | CIPHERSUITE_FLAG_TRIGGER },
	{ TLS_RSA_WITH_AES_128_CBC_SHA,
	  DESCRIPTION( "TLS_RSA_WITH_AES_128_CBC_SHA" )
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 16, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_TRIGGER },
	{ TLS_RSA_WITH_AES_256_CBC_SHA,
	  DESCRIPTION( "TLS_RSA_WITH_AES_256_CBC_SHA" )
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 32, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_TRIGGER },

	/* 3DES with RSA */
#ifdef USE_3DES
	{ SSL_RSA_WITH_3DES_EDE_CBC_SHA,
	  DESCRIPTION( "SSL_RSA_WITH_3DES_EDE_CBC_SHA" )
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA1, 0, 24, SHA1MAC_SIZE, 
	  CIPHERSUITE_FLAG_TRIGGER },
#endif /* USE_3DES */

	/* End-of-list marker */
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE },
	{ SSL_NULL_WITH_NULL,
	  DESCRIPTION( "End-of-list marker" )
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE }
	};
#endif /* USE_RSA_SUITES */

/* Tables defining the arrangement of the above sets of suites into a 
   single monster list */

typedef struct {
	const CIPHERSUITE_INFO *cipherSuites;
	const int cipherSuiteCount;
	} CIPHERSUITES_LIST;

static const CIPHERSUITES_LIST cipherSuitesList[] = {
	/* PSK suites first, since these provide proper mutual authentication */
	{ cipherSuitePSK, FAILSAFE_ARRAYSIZE( cipherSuitePSK, CIPHERSUITE_INFO ) },

	/* ECC suites if these are preferred */
#ifdef PREFER_ECC
  #ifdef USE_GCM
	{ cipherSuiteGCM, FAILSAFE_ARRAYSIZE( cipherSuiteGCM, CIPHERSUITE_INFO ) },
  #endif /* USE_GCM */
  #if defined( USE_ECDH )
	{ cipherSuiteECC, FAILSAFE_ARRAYSIZE( cipherSuiteECC, CIPHERSUITE_INFO ) },
  #endif /* USE_ECDH */
  #ifdef USE_CHACHA20
	{ cipherSuiteBernstein, FAILSAFE_ARRAYSIZE( cipherSuiteBernstein, CIPHERSUITE_INFO ) },
  #endif /* USE_CHACH20 */
#endif /* PREFER_ECC */

	/* DH suites */
	{ cipherSuiteDH, FAILSAFE_ARRAYSIZE( cipherSuiteDH, CIPHERSUITE_INFO ) },

	/* ECC suites if they're not preferred */
#ifndef PREFER_ECC
  #ifdef USE_GCM
	{ cipherSuiteGCM, FAILSAFE_ARRAYSIZE( cipherSuiteGCM, CIPHERSUITE_INFO ) },
  #endif /* USE_GCM */
  #if defined( USE_ECDH )
	{ cipherSuiteECC, FAILSAFE_ARRAYSIZE( cipherSuiteECC, CIPHERSUITE_INFO ) },
  #endif /* USE_ECDH */
  #ifdef USE_CHACHA20
	{ cipherSuiteBernstein, FAILSAFE_ARRAYSIZE( cipherSuiteBernstein, CIPHERSUITE_INFO ) },
  #endif /* USE_CHACH20 */
#endif /* !PREFER_ECC */

#ifdef USE_RSA_SUITES 
	/* Non-PFS RSA suites, the last resort */
	{ cipherSuiteRSA, FAILSAFE_ARRAYSIZE( cipherSuiteRSA, CIPHERSUITE_INFO ) },
#endif /* USE_RSA_SUITES */
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*						Cipher Suite Definitions for Suite B				*
*																			*
****************************************************************************/

/* If we're running in a Suite B configuration then we don't bother with any
   of the standard cipher suites but only provide Suite B suites */

#if defined( CONFIG_SUITEB )

#if defined( _MSC_VER ) || defined( __GNUC__ ) || defined( __clang__ )
  #pragma message( "  Building with custom suite: Suite B" )
  #if defined( CONFIG_SUITEB_TESTS )
	#pragma message( "  Building with custom suite: Suite B test suites" )
  #endif /* Suite B special test suites */
#endif /* Notify Suite B use */

/* 256-bit Suite B suites */

static const CIPHERSUITE_INFO suiteBP384GCM = { 
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 
	DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" )
	CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	CRYPT_ALGO_HMAC_SHA2, bitsToBytes( 384 ), 32, GCMICV_SIZE, 
	CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 
	};

/* 128-bit Suite B suites */

static const CIPHERSUITE_INFO suiteBP256GCM = { 
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 
	DESCRIPTION( "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" )
	CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	CRYPT_ALGO_HMAC_SHA2, 0, 16, GCMICV_SIZE, 
	CIPHERSUITE_FLAG_GCM | CIPHERSUITE_FLAG_TLS12 
	};

/* End-of-list marker */

static const CIPHERSUITE_INFO suiteBEOL = { 
	SSL_NULL_WITH_NULL,
	DESCRIPTION( "End-of-list marker" )
	CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	CRYPT_ALGO_NONE, 0, 0, 0, CIPHERSUITE_FLAG_NONE 
	};

/* Since the only suites that we're enabling are the Suite B ones, we 
   override the default getCipherSuiteInfo() with our own one */

CHECK_RETVAL \
int getSuiteBCipherSuiteInfo( OUT_PTR \
								const CIPHERSUITE_INFO ***cipherSuiteInfoPtrPtrPtr,
							  OUT_INT_Z int *noSuiteEntries,
							  IN_BOOL const BOOLEAN isServer,
							  IN_FLAGS_Z( TLS ) const int suiteBinfo )
	{
	static const CIPHERSUITE_INFO *cipherSuite192InfoTbl[] = \
		{ &suiteBP384GCM, &suiteBEOL, &suiteBEOL };
	static const CIPHERSUITE_INFO *cipherSuite128InfoTbl[] = \
		{ &suiteBP256GCM, &suiteBP384GCM, &suiteBEOL, &suiteBEOL };
	BOOLEAN is128bitLevel = ( ( suiteBinfo & TLS_PFLAG_SUITEB ) == \
									TLS_PFLAG_SUITEB_128 ) ? TRUE : FALSE;

	assert( isReadPtr( cipherSuiteInfoPtrPtrPtr, \
					   sizeof( CIPHERSUITE_INFO ** ) ) );
	assert( isWritePtr( noSuiteEntries, sizeof( int ) ) );

	REQUIRES( isBooleanValue( isServer ) );
	REQUIRES( suiteBinfo >= TLS_PFLAG_NONE && suiteBinfo < TLS_PFLAG_MAX );

	/* Depending on the security level that we're configured for we either 
	   prefer the 128-bit suites or the 192-bit suites */
	if( is128bitLevel )
		{
		*cipherSuiteInfoPtrPtrPtr = ( const CIPHERSUITE_INFO ** ) \
									cipherSuite128InfoTbl;	/* For gcc */
		*noSuiteEntries = FAILSAFE_ARRAYSIZE( cipherSuite128InfoTbl, \
											  CIPHERSUITE_INFO * );
		}
	else
		{
		*cipherSuiteInfoPtrPtrPtr = ( const CIPHERSUITE_INFO ** ) \
									cipherSuite192InfoTbl;	/* For gcc */
		*noSuiteEntries = FAILSAFE_ARRAYSIZE( cipherSuite192InfoTbl, \
											  CIPHERSUITE_INFO * );
		}
	return( CRYPT_OK );
	}

/* Remap the usual getCipherSuiteInfo() into an alternative name that
   doesn't clash with the Suite B replacement */

#undef getCipherSuiteInfo
#define	getCipherSuiteInfo	getCipherSuiteInfoOriginal

#endif /* CONFIG_SUITEB */

/****************************************************************************
*																			*
*							Cipher Suite Functions							*
*																			*
****************************************************************************/

/* Build the single unified list of ciphers suites in preferred-algorithm
   order */

CHECK_RETVAL \
static int addCipherSuiteInfo( INOUT_PTR CIPHERSUITE_INFO **cipherSuiteTbl, 
							   IN_RANGE( 0, MAX_NO_SUITES ) \
									const int cipherSuiteTblCount,
							   OUT_RANGE( 0, MAX_NO_SUITES ) \
									int *newCipherSuiteTblCount, 
							   const CIPHERSUITE_INFO *cipherSuites,
							   IN_RANGE( 0, MAX_NO_SUITES / 2 ) \
									const int cipherSuitesCount )
	{
	LOOP_INDEX srcIndex, destIndex;

	assert( isReadPtr( cipherSuiteTbl, \
					   sizeof( CIPHERSUITE_INFO * ) * MAX_NO_SUITES ) );
	assert( isWritePtr( newCipherSuiteTblCount, sizeof( int ) ) );
	assert( isReadPtr( cipherSuites,
					   sizeof( CIPHERSUITE_INFO * ) * 2 ) );

	REQUIRES( cipherSuiteTblCount >= 0 && \
			  cipherSuiteTblCount < MAX_NO_SUITES );
	REQUIRES( cipherSuitesCount >= 0 && \
			  cipherSuitesCount < MAX_NO_SUITES && \
			  cipherSuiteTblCount + \
					cipherSuitesCount < MAX_NO_SUITES );

	/* Clear return value.  Unlike standard practice this doesn't set it to
	   zero but to the existing count, making the call a no-op */
	*newCipherSuiteTblCount = cipherSuiteTblCount;

	/* Add any new suites to the existing table */
	LOOP_LARGE( ( srcIndex = 0, destIndex = cipherSuiteTblCount ), 
				srcIndex < cipherSuitesCount && \
					cipherSuites[ srcIndex ].cipherSuite != SSL_NULL_WITH_NULL && \
					destIndex < MAX_NO_SUITES,
				( srcIndex++, destIndex++ ) )
		{
		ENSURES( LOOP_INVARIANT_LARGE( srcIndex, 0, cipherSuitesCount - 1 ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( destIndex, cipherSuiteTblCount, 
										   MAX_NO_SUITES - 1 ) );

		cipherSuiteTbl[ destIndex ] = \
				( CIPHERSUITE_INFO * ) &cipherSuites[ srcIndex ];
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( srcIndex < cipherSuitesCount );
	ENSURES( destIndex < MAX_NO_SUITES );

	*newCipherSuiteTblCount = destIndex;

	return( CRYPT_OK );
	}

CHECK_RETVAL \
int getCipherSuiteInfo( OUT_PTR_PTR \
							const CIPHERSUITE_INFO ***cipherSuiteInfoPtrPtrPtr,
						OUT_INT_Z int *noSuiteEntries )
	{
	static CIPHERSUITE_INFO *cipherSuiteInfoTbl[ MAX_NO_SUITES + 8 ];
	static BOOLEAN cipherSuitInfoInited = FALSE;
	static int cipherSuiteCount = 0;
	int status;

	assert( isReadPtr( cipherSuiteInfoPtrPtrPtr, \
					   sizeof( CIPHERSUITE_INFO ** ) ) );
	assert( isWritePtr( noSuiteEntries, sizeof( int ) ) );

	/* Dynamically set up the monster table of cipher suites.  Note that 
	   this isn't thread-safe, but since it performs the setup in a
	   completely deterministic manner it doesn't matter if the extremely
	   unlikely situation of two threads initialising the array at the same
	   time occurs, since they're initialising it identically */
	if( !cipherSuitInfoInited )
		{
		static const CIPHERSUITE_INFO endOfList = {
			SSL_NULL_WITH_NULL,
			DESCRIPTION( "End-of-list marker" )
			CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
			CRYPT_ALGO_NONE, 0, 0, CIPHERSUITE_FLAG_NONE };
		LOOP_INDEX i;

		/* Build the unified list of cipher suites */
		LOOP_LARGE( i = 0, 
					i < FAILSAFE_ARRAYSIZE( cipherSuitesList, \
											CIPHERSUITES_LIST ) && \
						cipherSuitesList[ i ].cipherSuites != NULL,
					i++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
										   FAILSAFE_ARRAYSIZE( cipherSuitesList, \
															   CIPHERSUITES_LIST ) - 1 ) );

			status = addCipherSuiteInfo( cipherSuiteInfoTbl, cipherSuiteCount,
						&cipherSuiteCount, cipherSuitesList[ i ].cipherSuites,
						cipherSuitesList[ i ].cipherSuiteCount );
			if( cryptStatusError( status ) )
				return( status );
			}
		ENSURES( LOOP_BOUND_OK );
		ENSURES( i < FAILSAFE_ARRAYSIZE( cipherSuitesList, CIPHERSUITES_LIST ) );

		/* Add the end-of-list marker suites.  Note that we don't increment 
		   the suite count when the second one is added to match the 
		   behaviour of FAILSAFE_ARRAYSIZE() */
		REQUIRES( cipherSuiteCount + 2 < MAX_NO_SUITES );
		cipherSuiteInfoTbl[ cipherSuiteCount++ ] = \
								( CIPHERSUITE_INFO * ) &endOfList;
		cipherSuiteInfoTbl[ cipherSuiteCount ] = \
								( CIPHERSUITE_INFO * ) &endOfList;

		cipherSuitInfoInited = TRUE;
		}

	*cipherSuiteInfoPtrPtrPtr = ( const CIPHERSUITE_INFO ** ) \
								cipherSuiteInfoTbl;	/* For gcc */
	*noSuiteEntries = cipherSuiteCount;

	return( CRYPT_OK );
	}
#endif /* USE_TLS */
