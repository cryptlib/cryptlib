/*
---------------------------------------------------------------------------
Copyright (c) 1998-2013, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007

 This file contains the compilation options for AES (Rijndael) and code
 that is common across encryption, key scheduling and table generation.

 OPERATION

 These source code files implement the AES algorithm Rijndael designed by
 Joan Daemen and Vincent Rijmen. This version is designed for the standard
 block size of 16 bytes and for key sizes of 128, 192 and 256 bits (16, 24
 and 32 bytes).

 This version is designed for flexibility and speed using operations on
 32-bit words rather than operations on bytes.  It can be compiled with
 either big or little endian internal byte order but is faster when the
 native byte order for the processor is used.

 THE CIPHER INTERFACE

 The cipher interface is implemented as an array of bytes in which lower
 AES bit sequence indexes map to higher numeric significance within bytes.

  uint8_t                 (an unsigned  8-bit type)
  uint32_t                (an unsigned 32-bit type)
  struct aes_encrypt_ctx  (structure for the cipher encryption context)
  struct aes_decrypt_ctx  (structure for the cipher decryption context)
  AES_RETURN                the function return type

  C subroutine calls:

  AES_RETURN aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1]);
  AES_RETURN aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1]);
  AES_RETURN aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1]);
  AES_RETURN aes_encrypt(const unsigned char *in, unsigned char *out,
                                                  const aes_encrypt_ctx cx[1]);

  AES_RETURN aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1]);
  AES_RETURN aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1]);
  AES_RETURN aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1]);
  AES_RETURN aes_decrypt(const unsigned char *in, unsigned char *out,
                                                  const aes_decrypt_ctx cx[1]);

 IMPORTANT NOTE: If you are using this C interface with dynamic tables make sure that
 you call aes_init() before AES is used so that the tables are initialised.

 C++ aes class subroutines:

     Class AESencrypt  for encryption

      Construtors:
          AESencrypt(void)
          AESencrypt(const unsigned char *key) - 128 bit key
      Members:
          AES_RETURN key128(const unsigned char *key)
          AES_RETURN key192(const unsigned char *key)
          AES_RETURN key256(const unsigned char *key)
          AES_RETURN encrypt(const unsigned char *in, unsigned char *out) const

      Class AESdecrypt  for encryption
      Construtors:
          AESdecrypt(void)
          AESdecrypt(const unsigned char *key) - 128 bit key
      Members:
          AES_RETURN key128(const unsigned char *key)
          AES_RETURN key192(const unsigned char *key)
          AES_RETURN key256(const unsigned char *key)
          AES_RETURN decrypt(const unsigned char *in, unsigned char *out) const
*/

#if !defined( _AESOPT_H )
#define _AESOPT_H

#include <stddef.h>

#include "crypt.h"

/* Cryptlib options: Enable use of asm encryption with C key schedule (the
   fastest combination) and use Intel NI and VIA ACE if possible, but for
   VIA ACE not under WinCE, both because it's possible that we could be 
   running on an oddball embedded x86 that doesn't understand the necessary 
   opcodes, and because eVC++ doesn't understand some of the extensions 
   used in the ACE-support code - pcg */

#if defined( _MSC_VER ) && ( _MSC_VER > 1500 ) && \
	defined( _M_X64 )
  #define USE_INTEL_AES_IF_PRESENT
#endif /* VC++ on x64 under Win64 - pcg */
#if defined( _MSC_VER ) && ( _MSC_VER > 800 ) && \
	defined( _M_IX86 ) && \
	!( defined( _WIN32_WCE ) || defined( NO_ASM ) )
  #ifndef USE_VIA_ACE_IF_PRESENT
	#define USE_VIA_ACE_IF_PRESENT
  #endif
#endif /* VC++ on x86 under Win32 - pcg */

#if defined( _MSC_VER ) && ( _MSC_VER > 800 ) && \
	!( defined( _WIN32_WCE ) || defined( NO_ASM ) )
  /* The apparently redundant guards are necessary in case users manually
     define the values to enable various asm options */
  #if defined( _M_X64 )
	#ifndef ASM_AMD64_C
	  #define ASM_AMD64_C
	#endif /* ASM_AMD64_C */
  #elif defined( _M_IX86 )
	#ifndef ASM_X86_V2C
	  #define ASM_X86_V2C
	#endif /* ASM_X86_V2C */
  #else
	#define NO_ASM
  #endif /* Different x86 architectures */
#endif /* VC++ on x86 under Win32 - pcg */

#if defined( INC_ALL )
  #include "aes.h"
#else
  #include "crypt/aes.h"
#endif /* Compiler-specific includes - pcg */

/*  PLATFORM SPECIFIC INCLUDES */

#if defined( INC_ALL )
  #include "brg_endian.h"
#else
  #include "crypt/brg_endian.h"
#endif /* Compiler-specific includes - pcg */

#ifdef __VxWorks__
  /* vxWorksCommon.h defines NONE ("for times when NULL won't do") so we 
	 undefine it so that the AES code can define it below */
  #undef NONE
#endif /* __VxWorks__ - pcg */

/*  CONFIGURATION - THE USE OF DEFINES

    Later in this section there are a number of defines that control the
    operation of the code.  In each section, the purpose of each define is
    explained so that the relevant form can be included or excluded by
    setting either 1's or 0's respectively on the branches of the related
    #if clauses.  The following local defines should not be changed.
*/

#define ENCRYPTION_IN_C     1
#define DECRYPTION_IN_C     2
#define ENC_KEYING_IN_C     4
#define DEC_KEYING_IN_C     8

#define NO_TABLES           0
#define ONE_TABLE           1
#define FOUR_TABLES         4
#define NONE                0
#define PARTIAL             1
#define FULL                2

/*  --- START OF USER CONFIGURED OPTIONS --- */

/*  1. BYTE ORDER WITHIN 32 BIT WORDS

    The fundamental data processing units in Rijndael are 8-bit bytes. The
    input, output and key input are all enumerated arrays of bytes in which
    bytes are numbered starting at zero and increasing to one less than the
    number of bytes in the array in question. This enumeration is only used
    for naming bytes and does not imply any adjacency or order relationship
    from one byte to another. When these inputs and outputs are considered
    as bit sequences, bits 8*n to 8*n+7 of the bit sequence are mapped to
    byte[n] with bit 8n+i in the sequence mapped to bit 7-i within the byte.
    In this implementation bits are numbered from 0 to 7 starting at the
    numerically least significant end of each byte (bit n represents 2^n).

    However, Rijndael can be implemented more efficiently using 32-bit
    words by packing bytes into words so that bytes 4*n to 4*n+3 are placed
    into word[n]. While in principle these bytes can be assembled into words
    in any positions, this implementation only supports the two formats in
    which bytes in adjacent positions within words also have adjacent byte
    numbers. This order is called big-endian if the lowest numbered bytes
    in words have the highest numeric significance and little-endian if the
    opposite applies.

    This code can work in either order irrespective of the order used by the
    machine on which it runs. Normally the internal byte order will be set
    to the order of the processor on which the code is to be run but this
    define can be used to reverse this in special situations

    WARNING: Assembler code versions rely on PLATFORM_BYTE_ORDER being set.
    This define will hence be redefined later (in section 4) if necessary
*/

#if 1
#  define ALGORITHM_BYTE_ORDER PLATFORM_BYTE_ORDER
#elif 0
#  define ALGORITHM_BYTE_ORDER IS_LITTLE_ENDIAN
#elif 0
#  define ALGORITHM_BYTE_ORDER IS_BIG_ENDIAN
#else
#  error The algorithm byte order is not defined
#endif

/*  2. Intel AES AND VIA ACE SUPPORT */

#if defined( __GNUC__ ) && defined( __i386__ ) \
 || defined( _WIN32 ) && defined( _M_IX86 ) && !(defined( _WIN64 ) \
 || defined( _WIN32_WCE ) || defined( _MSC_VER ) && ( _MSC_VER <= 800 ))
#  define VIA_ACE_POSSIBLE
#endif

/* AES is supported out of the box by Windows x64 compilers, but by gcc only 
   if the stars are right, we have to feature-test for SSE 2, SSE 3, and AES 
   to enable it (we don't actually explicitly test for SSE2 since SSE3 
   implies SSE2).  However neither gcc nor clang define the expected __AES__
   no matter what x86-64 architecture level we select:

	gcc -march=x86-64-v3 -dM -E -x c /dev/null | grep -i aes
	gcc -march=x86-64-v4 -dM -E -x c /dev/null | grep -i aes
	clang -march=x86-64-v3 -dM -E -x c /dev/null | grep -i aes
	clang -march=x86-64-v4 -dM -E -x c /dev/null | grep -i aes

   unless we use the risky -march=native (see the long comment in ccopts.sh
   about why this is unsafe to use):

	gcc -march=native -dM -E -x c /dev/null | grep -i aes
	clang -march=native -dM -E -x c /dev/null | grep -i aes

   so we use __SSE4_2__ as a proxy since that (Nehalem, Nov.2008) came out 
   at approximately the same time as the AES instructions (Westmere, 
   Jan.2010, the Nehalem die shrink) - pcg */

#ifndef INTEL_AES_POSSIBLE
  #if defined( _WIN64 ) && defined( _MSC_VER ) 
	#define INTEL_AES_POSSIBLE
  #elif ( ( defined( __GNUC__ ) && ( __GNUC__ >= 7 ) ) || \
		  ( defined( __clang__ ) ) ) && \
		defined( __x86_64__ ) && defined( __SSE3__ ) && \
		defined( __SSE4_2__ ) 
	#define INTEL_AES_POSSIBLE
  #endif /* Compiler-specific AES instruction support */
#endif /* INTEL_AES_POSSIBLE */

/*  Define this option if support for the Intel AESNI is required
    If USE_INTEL_AES_IF_PRESENT is defined then AESNI will be used
    if it is detected (both present and enabled).

	AESNI uses a decryption key schedule with the first decryption
	round key at the high end of the key scedule with the following
	round keys at lower positions in memory.  So AES_REV_DKS must NOT
	be defined when AESNI will be used.  ALthough it is unlikely that
	assembler code will be used with an AESNI build, if it is then
	AES_REV_DKS must NOT be defined when the assembler files are
	built
*/

#if 1 && defined( INTEL_AES_POSSIBLE ) && !defined( USE_INTEL_AES_IF_PRESENT )
#  define USE_INTEL_AES_IF_PRESENT
#endif

/*  Define this option if support for the VIA ACE is required. This uses
    inline assembler instructions and is only implemented for the Microsoft,
    Intel and GCC compilers.  If VIA ACE is known to be present, then defining
    ASSUME_VIA_ACE_PRESENT will remove the ordinary encryption/decryption
    code.  If USE_VIA_ACE_IF_PRESENT is defined then VIA ACE will be used if
    it is detected (both present and enabled) but the normal AES code will
    also be present.

    When VIA ACE is to be used, all AES encryption contexts MUST be 16 byte
    aligned; other input/output buffers do not need to be 16 byte aligned
    but there are very large performance gains if this can be arranged.
    VIA ACE also requires the decryption key schedule to be in reverse
    order (which later checks below ensure).

	AES_REV_DKS must be set for assembler code used with a VIA ACE build
*/

#if 1 && defined( VIA_ACE_POSSIBLE ) && !defined( USE_VIA_ACE_IF_PRESENT )
#  define USE_VIA_ACE_IF_PRESENT
#endif

#if 0 && defined( VIA_ACE_POSSIBLE ) && !defined( ASSUME_VIA_ACE_PRESENT )
#  define ASSUME_VIA_ACE_PRESENT
#  endif

/*  3. ASSEMBLER SUPPORT

    This define (which can be on the command line) enables the use of the
    assembler code routines for encryption, decryption and key scheduling
    as follows:

    ASM_X86_V1C uses the assembler (aes_x86_v1.asm) with large tables for
                encryption and decryption and but with key scheduling in C
    ASM_X86_V2  uses assembler (aes_x86_v2.asm) with compressed tables for
                encryption, decryption and key scheduling
    ASM_X86_V2C uses assembler (aes_x86_v2.asm) with compressed tables for
                encryption and decryption and but with key scheduling in C
    ASM_AMD64_C uses assembler (aes_amd64.asm) with compressed tables for
                encryption and decryption and but with key scheduling in C

    Change one 'if 0' below to 'if 1' to select the version or define
    as a compilation option.
*/

#if 0 && !defined( ASM_X86_V1C )
#  define ASM_X86_V1C
#elif 0 && !defined( ASM_X86_V2  )
#  define ASM_X86_V2
#elif 0 && !defined( ASM_X86_V2C )
#  define ASM_X86_V2C
#elif 0 && !defined( ASM_AMD64_C )
#  define ASM_AMD64_C
#endif

#if defined( __i386 ) || defined( _M_IX86 )
#  define A32_
#elif defined( __x86_64__ ) || defined( _M_X64 )
#  define A64_
#endif

#if (defined ( ASM_X86_V1C ) || defined( ASM_X86_V2 ) || defined( ASM_X86_V2C )) \
       && !defined( A32_ )  || defined( ASM_AMD64_C ) && !defined( A64_ )
#  error Assembler code is only available for x86 and AMD64 systems
#endif

/*  4. FAST INPUT/OUTPUT OPERATIONS.

    On some machines it is possible to improve speed by transferring the
    bytes in the input and output arrays to and from the internal 32-bit
    variables by addressing these arrays as if they are arrays of 32-bit
    words.  On some machines this will always be possible but there may
    be a large performance penalty if the byte arrays are not aligned on
    the normal word boundaries. On other machines this technique will
    lead to memory access errors when such 32-bit word accesses are not
    properly aligned. The option SAFE_IO avoids such problems but will
    often be slower on those machines that support misaligned access
    (especially so if care is taken to align the input  and output byte
    arrays on 32-bit word boundaries). If SAFE_IO is not defined it is
    assumed that access to byte arrays as if they are arrays of 32-bit
    words will not cause problems when such accesses are misaligned.
*/
#if 1 && !defined( _MSC_VER )
#  define SAFE_IO
#endif

/*  5. LOOP UNROLLING

    The code for encryption and decrytpion cycles through a number of rounds
    that can be implemented either in a loop or by expanding the code into a
    long sequence of instructions, the latter producing a larger program but
    one that will often be much faster. The latter is called loop unrolling.
    There are also potential speed advantages in expanding two iterations in
    a loop with half the number of iterations, which is called partial loop
    unrolling.  The following options allow partial or full loop unrolling
    to be set independently for encryption and decryption
*/
#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define ENC_UNROLL  FULL
#elif defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define ENC_UNROLL  PARTIAL
#else
#  define ENC_UNROLL  NONE
#endif

#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define DEC_UNROLL  FULL
#elif defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define DEC_UNROLL  PARTIAL
#else
#  define DEC_UNROLL  NONE
#endif

#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define ENC_KS_UNROLL
#endif

#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define DEC_KS_UNROLL
#endif

/*  6. FAST FINITE FIELD OPERATIONS

    If this section is included, tables are used to provide faster finite
    field arithmetic (this has no effect if STATIC_TABLES is defined).
*/
#if 1
#  define FF_TABLES
#endif

/*  7. INTERNAL STATE VARIABLE FORMAT

    The internal state of Rijndael is stored in a number of local 32-bit
    word varaibles which can be defined either as an array or as individual
    names variables. Include this section if you want to store these local
    varaibles in arrays. Otherwise individual local variables will be used.
*/
#if 1
#  define ARRAYS
#endif

/*  8. FIXED OR DYNAMIC TABLES

    When this section is included the tables used by the code are compiled
    statically into the binary file.  Otherwise the subroutine aes_init()
    must be called to compute them before the code is first used.
*/
#if 1 && !(defined( _MSC_VER ) && ( _MSC_VER <= 800 ))
#  define STATIC_TABLES
#endif

/*  9. MASKING OR CASTING FROM LONGER VALUES TO BYTES

    In some systems it is better to mask longer values to extract bytes
    rather than using a cast. This option allows this choice.
*/
#if 0
#  define to_byte(x)  ((uint8_t)(x))
#else
#  define to_byte(x)  ((x) & 0xff)
#endif

/*  10. TABLE ALIGNMENT

    On some sytsems speed will be improved by aligning the AES large lookup
    tables on particular boundaries. This define should be set to a power of
    two giving the desired alignment. It can be left undefined if alignment
    is not needed.  This option is specific to the Microsft VC++ compiler -
    it seems to sometimes cause trouble for the VC++ version 6 compiler.
*/

#if 1 && defined( _MSC_VER ) && ( _MSC_VER >= 1300 )
#  define TABLE_ALIGN 32
#endif

/*  11.  REDUCE CODE AND TABLE SIZE

    This replaces some expanded macros with function calls if AES_ASM_V2 or
    AES_ASM_V2C are defined
*/

#if 1 && (defined( ASM_X86_V2 ) || defined( ASM_X86_V2C ))
#  define REDUCE_CODE_SIZE
#endif

/*  12. TABLE OPTIONS

    This cipher proceeds by repeating in a number of cycles known as 'rounds'
    which are implemented by a round function which can optionally be speeded
    up using tables.  The basic tables are each 256 32-bit words, with either
    one or four tables being required for each round function depending on
    how much speed is required. The encryption and decryption round functions
    are different and the last encryption and decrytpion round functions are
    different again making four different round functions in all.

    This means that:
      1. Normal encryption and decryption rounds can each use either 0, 1
         or 4 tables and table spaces of 0, 1024 or 4096 bytes each.
      2. The last encryption and decryption rounds can also use either 0, 1
         or 4 tables and table spaces of 0, 1024 or 4096 bytes each.

    Include or exclude the appropriate definitions below to set the number
    of tables used by this implementation.
*/

#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define ENC_ROUND   FOUR_TABLES
#elif defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define ENC_ROUND   ONE_TABLE
#else
#  define ENC_ROUND   NO_TABLES
#endif

#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define LAST_ENC_ROUND  FOUR_TABLES
#elif defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define LAST_ENC_ROUND  ONE_TABLE
#else
#  define LAST_ENC_ROUND  NO_TABLES
#endif

#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define DEC_ROUND   FOUR_TABLES
#elif defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define DEC_ROUND   ONE_TABLE
#else
#  define DEC_ROUND   NO_TABLES
#endif

#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define LAST_DEC_ROUND  FOUR_TABLES
#elif defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define LAST_DEC_ROUND  ONE_TABLE
#else
#  define LAST_DEC_ROUND  NO_TABLES
#endif

/*  The decryption key schedule can be speeded up with tables in the same
    way that the round functions can.  Include or exclude the following
    defines to set this requirement.
*/
#if !defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define KEY_SCHED   FOUR_TABLES
#elif defined( CONFIG_CONSERVE_MEMORY )		/* pcg */
#  define KEY_SCHED   ONE_TABLE
#else
#  define KEY_SCHED   NO_TABLES
#endif

/*  ---- END OF USER CONFIGURED OPTIONS ---- */

/* VIA ACE support is only available for VC++ and GCC */

#if !defined( _MSC_VER ) && !defined( __GNUC__ )
#  if defined( ASSUME_VIA_ACE_PRESENT )
#    undef ASSUME_VIA_ACE_PRESENT
#  endif
#  if defined( USE_VIA_ACE_IF_PRESENT )
#    undef USE_VIA_ACE_IF_PRESENT
#  endif
#endif

#if defined( ASSUME_VIA_ACE_PRESENT ) && !defined( USE_VIA_ACE_IF_PRESENT )
#  define USE_VIA_ACE_IF_PRESENT
#endif

#if defined( __APPLE__ ) && TARGET_OS_SIMULATOR
  /* The iPhone simmulator, even though it's simulating an ARM platform, 
     actually builds x86 (ARMv7) or x86 (ARM64) binaries.  In addition the
	 simulator isn't very complete, and crashes with an EXC_BAD_ACCESS when 
	 we do the CPUID check for the Via ACE, so we disable it */
  #undef ASSUME_VIA_ACE_PRESENT
  #undef USE_VIA_ACE_IF_PRESENT
#endif /* iPhone simulator - pcg */

#if defined(__BEOS__)
  /* The BeOS compiler (and ancient version of gcc) cannot generate code 
     that reliably determines if a VIA CPU is available */
  #undef USE_VIA_ACE_IF_PRESENT
#endif /* BeOS gcc - pcg */

/* define to reverse decryption key schedule    */
#if 1 || defined( USE_VIA_ACE_IF_PRESENT ) && !defined ( AES_REV_DKS )
#  define AES_REV_DKS
#endif

/* Intel AESNI uses a decryption key schedule in the encryption order */
#if defined( USE_INTEL_AES_IF_PRESENT ) && defined ( AES_REV_DKS )
#  undef AES_REV_DKS
#endif

/* Assembler support requires the use of platform byte order */

#if ( defined( ASM_X86_V1C ) || defined( ASM_X86_V2C ) || defined( ASM_AMD64_C ) ) \
    && (ALGORITHM_BYTE_ORDER != PLATFORM_BYTE_ORDER)
#  undef  ALGORITHM_BYTE_ORDER
#  define ALGORITHM_BYTE_ORDER PLATFORM_BYTE_ORDER
#endif

/* In this implementation the columns of the state array are each held in
   32-bit words. The state array can be held in various ways: in an array
   of words, in a number of individual word variables or in a number of
   processor registers. The following define maps a variable name x and
   a column number c to the way the state array variable is to be held.
   The first define below maps the state into an array x[c] whereas the
   second form maps the state into a number of individual variables x0,
   x1, etc.  Another form could map individual state colums to machine
   register names.
*/

#if defined( ARRAYS )
#  define s(x,c) x[c]
#else
#  define s(x,c) x##c
#endif

/*  This implementation provides subroutines for encryption, decryption
    and for setting the three key lengths (separately) for encryption
    and decryption. Since not all functions are needed, masks are set
    up here to determine which will be implemented in C
*/

#if !defined( AES_ENCRYPT )
#  define EFUNCS_IN_C   0
#elif defined( ASSUME_VIA_ACE_PRESENT ) || defined( ASM_X86_V1C ) \
    || defined( ASM_X86_V2C ) || defined( ASM_AMD64_C )
#  define EFUNCS_IN_C   ENC_KEYING_IN_C
#elif !defined( ASM_X86_V2 )
#  define EFUNCS_IN_C   ( ENCRYPTION_IN_C | ENC_KEYING_IN_C )
#else
#  define EFUNCS_IN_C   0
#endif

#if !defined( AES_DECRYPT )
#  define DFUNCS_IN_C   0
#elif defined( ASSUME_VIA_ACE_PRESENT ) || defined( ASM_X86_V1C ) \
    || defined( ASM_X86_V2C ) || defined( ASM_AMD64_C )
#  define DFUNCS_IN_C   DEC_KEYING_IN_C
#elif !defined( ASM_X86_V2 )
#  define DFUNCS_IN_C   ( DECRYPTION_IN_C | DEC_KEYING_IN_C )
#else
#  define DFUNCS_IN_C   0
#endif

#define FUNCS_IN_C  ( EFUNCS_IN_C | DFUNCS_IN_C )

/* END OF CONFIGURATION OPTIONS */

#define RC_LENGTH   (5 * (AES_BLOCK_SIZE / 4 - 2))

/* Disable or report errors on some combinations of options */

#if ENC_ROUND == NO_TABLES && LAST_ENC_ROUND != NO_TABLES
#  undef  LAST_ENC_ROUND
#  define LAST_ENC_ROUND  NO_TABLES
#elif ENC_ROUND == ONE_TABLE && LAST_ENC_ROUND == FOUR_TABLES
#  undef  LAST_ENC_ROUND
#  define LAST_ENC_ROUND  ONE_TABLE
#endif

#if ENC_ROUND == NO_TABLES && ENC_UNROLL != NONE
#  undef  ENC_UNROLL
#  define ENC_UNROLL  NONE
#endif

#if DEC_ROUND == NO_TABLES && LAST_DEC_ROUND != NO_TABLES
#  undef  LAST_DEC_ROUND
#  define LAST_DEC_ROUND  NO_TABLES
#elif DEC_ROUND == ONE_TABLE && LAST_DEC_ROUND == FOUR_TABLES
#  undef  LAST_DEC_ROUND
#  define LAST_DEC_ROUND  ONE_TABLE
#endif

#if DEC_ROUND == NO_TABLES && DEC_UNROLL != NONE
#  undef  DEC_UNROLL
#  define DEC_UNROLL  NONE
#endif

#if defined( bswap32 )
#  define aes_sw32    bswap32
#elif defined( bswap_32 )
#  define aes_sw32    bswap_32
#else
#  define brot(x,n)   (((uint32_t)(x) <<  (n)) | ((uint32_t)(x) >> (32 - (n))))
#  define aes_sw32(x) ((brot((x),8) & 0x00ff00ff) | (brot((x),24) & 0xff00ff00))
#endif

/*  upr(x,n):  rotates bytes within words by n positions, moving bytes to
               higher index positions with wrap around into low positions
    ups(x,n):  moves bytes by n positions to higher index positions in
               words but without wrap around
    bval(x,n): extracts a byte from a word

    WARNING:   The definitions given here are intended only for use with
               unsigned variables and with shift counts that are compile
               time constants
*/

#if ( ALGORITHM_BYTE_ORDER == IS_LITTLE_ENDIAN )
#  define upr(x,n)      (((uint32_t)(x) << (8 * (n))) | ((uint32_t)(x) >> (32 - 8 * (n))))
#  define ups(x,n)      ((uint32_t) (x) << (8 * (n)))
#  define bval(x,n)     to_byte((x) >> (8 * (n)))
#  define bytes2word(b0, b1, b2, b3)  \
        (((uint32_t)(b3) << 24) | ((uint32_t)(b2) << 16) | ((uint32_t)(b1) << 8) | (b0))
#endif

#if ( ALGORITHM_BYTE_ORDER == IS_BIG_ENDIAN )
#  define upr(x,n)      (((uint32_t)(x) >> (8 * (n))) | ((uint32_t)(x) << (32 - 8 * (n))))
#  define ups(x,n)      ((uint32_t) (x) >> (8 * (n)))
#  define bval(x,n)     to_byte((x) >> (24 - 8 * (n)))
#  define bytes2word(b0, b1, b2, b3)  \
        (((uint32_t)(b0) << 24) | ((uint32_t)(b1) << 16) | ((uint32_t)(b2) << 8) | (b3))
#endif

#if defined( SAFE_IO )
#  define word_in(x,c)    bytes2word(((const uint8_t*)(x)+4*(c))[0], ((const uint8_t*)(x)+4*(c))[1], \
                                   ((const uint8_t*)(x)+4*(c))[2], ((const uint8_t*)(x)+4*(c))[3])
#  define word_out(x,c,v) { ((uint8_t*)(x)+4*c)[0] = bval(v,0); ((uint8_t*)(x)+4*c)[1] = bval(v,1); \
                          ((uint8_t*)(x)+4*c)[2] = bval(v,2); ((uint8_t*)(x)+4*c)[3] = bval(v,3); }
#elif ( ALGORITHM_BYTE_ORDER == PLATFORM_BYTE_ORDER )
#  define word_in(x,c)    (*((uint32_t*)(x)+(c)))
#  define word_out(x,c,v) (*((uint32_t*)(x)+(c)) = (v))
#else
#  define word_in(x,c)    aes_sw32(*((uint32_t*)(x)+(c)))
#  define word_out(x,c,v) (*((uint32_t*)(x)+(c)) = aes_sw32(v))
#endif

/* the finite field modular polynomial and elements */

#define WPOLY   0x011b
#define BPOLY     0x1b

/* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

#define gf_c1  0x80808080
#define gf_c2  0x7f7f7f7f
#define gf_mulx(x)  ((((x) & gf_c2) << 1) ^ ((((x) & gf_c1) >> 7) * BPOLY))

/* The following defines provide alternative definitions of gf_mulx that might
   give improved performance if a fast 32-bit multiply is not available. Note
   that a temporary variable u needs to be defined where gf_mulx is used.

#define gf_mulx(x) (u = (x) & gf_c1, u |= (u >> 1), ((x) & gf_c2) << 1) ^ ((u >> 3) | (u >> 6))
#define gf_c4  (0x01010101 * BPOLY)
#define gf_mulx(x) (u = (x) & gf_c1, ((x) & gf_c2) << 1) ^ ((u - (u >> 7)) & gf_c4)
*/

/* Work out which tables are needed for the different options   */

#if defined( ASM_X86_V1C )
#  if defined( ENC_ROUND )
#    undef  ENC_ROUND
#  endif
#  define ENC_ROUND   FOUR_TABLES
#  if defined( LAST_ENC_ROUND )
#    undef  LAST_ENC_ROUND
#  endif
#  define LAST_ENC_ROUND  FOUR_TABLES
#  if defined( DEC_ROUND )
#    undef  DEC_ROUND
#  endif
#  define DEC_ROUND   FOUR_TABLES
#  if defined( LAST_DEC_ROUND )
#    undef  LAST_DEC_ROUND
#  endif
#  define LAST_DEC_ROUND  FOUR_TABLES
#  if defined( KEY_SCHED )
#    undef  KEY_SCHED
#    define KEY_SCHED   FOUR_TABLES
#  endif
#endif

#if ( FUNCS_IN_C & ENCRYPTION_IN_C ) || defined( ASM_X86_V1C )
#  if ENC_ROUND == ONE_TABLE
#    define FT1_SET
#  elif ENC_ROUND == FOUR_TABLES
#    define FT4_SET
#  else
#    define SBX_SET
#  endif
#  if LAST_ENC_ROUND == ONE_TABLE
#    define FL1_SET
#  elif LAST_ENC_ROUND == FOUR_TABLES
#    define FL4_SET
#  elif !defined( SBX_SET )
#    define SBX_SET
#  endif
#endif

#if ( FUNCS_IN_C & DECRYPTION_IN_C ) || defined( ASM_X86_V1C )
#  if DEC_ROUND == ONE_TABLE
#    define IT1_SET
#  elif DEC_ROUND == FOUR_TABLES
#    define IT4_SET
#  else
#    define ISB_SET
#  endif
#  if LAST_DEC_ROUND == ONE_TABLE
#    define IL1_SET
#  elif LAST_DEC_ROUND == FOUR_TABLES
#    define IL4_SET
#  elif !defined(ISB_SET)
#    define ISB_SET
#  endif
#endif

#if !(defined( REDUCE_CODE_SIZE ) && (defined( ASM_X86_V2 ) || defined( ASM_X86_V2C )))
#  if ((FUNCS_IN_C & ENC_KEYING_IN_C) || (FUNCS_IN_C & DEC_KEYING_IN_C))
#    if KEY_SCHED == ONE_TABLE
#      if !defined( FL1_SET )  && !defined( FL4_SET )
#        define LS1_SET
#      endif
#    elif KEY_SCHED == FOUR_TABLES
#      if !defined( FL4_SET )
#        define LS4_SET
#      endif
#    elif !defined( SBX_SET )
#      define SBX_SET
#    endif
#  endif
#  if (FUNCS_IN_C & DEC_KEYING_IN_C)
#    if KEY_SCHED == ONE_TABLE
#      define IM1_SET
#    elif KEY_SCHED == FOUR_TABLES
#      define IM4_SET
#    elif !defined( SBX_SET )
#      define SBX_SET
#    endif
#  endif
#endif

/* generic definitions of Rijndael macros that use tables    */

#define no_table(x,box,vf,rf,c) bytes2word( \
    box[bval(vf(x,0,c),rf(0,c))], \
    box[bval(vf(x,1,c),rf(1,c))], \
    box[bval(vf(x,2,c),rf(2,c))], \
    box[bval(vf(x,3,c),rf(3,c))])

#define one_table(x,op,tab,vf,rf,c) \
 (     tab[bval(vf(x,0,c),rf(0,c))] \
  ^ op(tab[bval(vf(x,1,c),rf(1,c))],1) \
  ^ op(tab[bval(vf(x,2,c),rf(2,c))],2) \
  ^ op(tab[bval(vf(x,3,c),rf(3,c))],3))

#define four_tables(x,tab,vf,rf,c) \
 (  tab[0][bval(vf(x,0,c),rf(0,c))] \
  ^ tab[1][bval(vf(x,1,c),rf(1,c))] \
  ^ tab[2][bval(vf(x,2,c),rf(2,c))] \
  ^ tab[3][bval(vf(x,3,c),rf(3,c))])

#define vf1(x,r,c)  (x)
#define rf1(r,c)    (r)
#define rf2(r,c)    ((8+(r)-(c))&3)

/* perform forward and inverse column mix operation on four bytes in long word x in */
/* parallel. NOTE: x must be a simple variable, NOT an expression in these macros.  */

#if !(defined( REDUCE_CODE_SIZE ) && (defined( ASM_X86_V2 ) || defined( ASM_X86_V2C )))

#if defined( FM4_SET )      /* not currently used */
#  define fwd_mcol(x)       four_tables(x,t_use(f,m),vf1,rf1,0)
#elif defined( FM1_SET )    /* not currently used */
#  define fwd_mcol(x)       one_table(x,upr,t_use(f,m),vf1,rf1,0)
#else
#  define dec_fmvars        uint32_t g2
#  define fwd_mcol(x)       (g2 = gf_mulx(x), g2 ^ upr((x) ^ g2, 3) ^ upr((x), 2) ^ upr((x), 1))
#endif

#if defined( IM4_SET )
#  define inv_mcol(x)       four_tables(x,t_use(i,m),vf1,rf1,0)
#elif defined( IM1_SET )
#  define inv_mcol(x)       one_table(x,upr,t_use(i,m),vf1,rf1,0)
#else
#  define dec_imvars        uint32_t g2, g4, g9
#  define inv_mcol(x)       (g2 = gf_mulx(x), g4 = gf_mulx(g2), g9 = (x) ^ gf_mulx(g4), g4 ^= g9, \
                            (x) ^ g2 ^ g4 ^ upr(g2 ^ g9, 3) ^ upr(g4, 2) ^ upr(g9, 1))
#endif

#if defined( FL4_SET )
#  define ls_box(x,c)       four_tables(x,t_use(f,l),vf1,rf2,c)
#elif defined( LS4_SET )
#  define ls_box(x,c)       four_tables(x,t_use(l,s),vf1,rf2,c)
#elif defined( FL1_SET )
#  define ls_box(x,c)       one_table(x,upr,t_use(f,l),vf1,rf2,c)
#elif defined( LS1_SET )
#  define ls_box(x,c)       one_table(x,upr,t_use(l,s),vf1,rf2,c)
#else
#  define ls_box(x,c)       no_table(x,t_use(s,box),vf1,rf2,c)
#endif

#endif

#if defined( ASM_X86_V1C ) && defined( AES_DECRYPT ) && !defined( ISB_SET )
#  define ISB_SET
#endif

#endif
