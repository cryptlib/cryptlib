/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#if defined( INC_ALL )
  #include "crypt.h"
  #include "osconfig.h"
  #include "common.h"
  #include "verify.h"
#else
  #include "crypt.h"
  #include "crypt/osconfig.h"
  #include "crypt/common.h"
  #include "crypt/verify.h"
#endif /* Compiler-specific includes */

#ifdef USE_MLKEM

#if !defined(MLK_USE_ASM_VALUE_BARRIER) && \
    !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
/*
 * Masking value used in constant-time functions from
 * verify.h to block the compiler's range analysis and
 * thereby reduce the risk of compiler-introduced branches.
 */
volatile uint64_t mlk_ct_opt_blocker_u64 = 0;

#else /* !MLK_USE_ASM_VALUE_BARRIER && !MLK_CONFIG_MULTILEVEL_NO_SHARED */

MLK_EMPTY_CU(verify)

#endif /* !(!MLK_USE_ASM_VALUE_BARRIER && !MLK_CONFIG_MULTILEVEL_NO_SHARED) */

#endif /* USE_MLKEM */
