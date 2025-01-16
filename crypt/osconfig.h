#ifndef _OSCONFIG_DEFINED
#define _OSCONFIG_DEFINED

/* Pull in cryptlib-wide configuration options */

#include "crypt.h"

/* OpenSSL-specific defines */

#define OPENSSL_EXTERN	extern
#define OPENSSL_GLOBAL
#if defined( _WINDOWS ) && !defined( WINDOWS )	/* Windows */
  #define WINDOWS				/* Old format */
  #define OPENSSL_SYS_WINDOWS	/* New fomat */
#endif /* OpenSSL Windows not defined */
#if defined( _WIN32 )			/* Win32 and WinCE */
  #ifndef WIN32
	#define WIN32				/* Old format OpenSSL Win32 identifier */
  #endif /* WIN32 */
  #define OPENSSL_SYS_WIN32		/* New format OpenSSL Win32 identifier */
  /* Note that the following asm defines are duplicated in misc/os_spec.h, 
	 because the OpenSSL headers are non-orthogonal to the cryptlib ones. 
	 Any changes made here need to be reflected in os_spec.h */
  #if !( defined( _WIN32_WCE ) || defined( _M_X64 ) || \
		 defined( __BORLANDC__ ) || defined( NO_ASM ) )
	//#define USE_ASM				/* Always enabled for x86 Win32 */
  #endif /* WinCE || x86-64 || Borland compilers */
#endif /* OpenSSL Win32 not defined */
#include <stdlib.h>			/* For malloc() */
#include <string.h>			/* For memset() */
#if defined( USE_ASM ) && defined( __WATCOMC__ )
  #define ASM_EXPORT	__cdecl
#else
  #define ASM_EXPORT
#endif /* System-specific interface to ASM files */

/* General defines.  An older generic config from the original OpenSSL 
   version can be found at 
   http://lists.alioth.debian.org/pipermail/pkg-openssl-changes/2005-October/000012.html 
   (which is just the OpenSSL Configure file, posted to the web), the 
   current one is at 
   https://github.com/openssl/openssl/blob/master/Configurations/10-main.conf.

   Alongside all of the portability defines we also define a string 
   SYSTEM_NAME that's used for debugging purposes */

#include <limits.h>
#if ULONG_MAX > 0xFFFFFFFFUL
  #define SIXTY_FOUR_BIT
#else
  #define THIRTY_TWO_BIT
#endif /* Machine word size */

/* Cross-compiles of embedded OSes override any native compiles.  We first 
   try for OS-specific options, then we try for the most obvious generic 
   options like the GNU toolchain, and finally if we can't find anything we 
   bail out with an error message.
   
   Since we're cross-compiling we also undefine anything that may have been
   set earlier in a host-specific manner */

#if defined( USE_EMBEDDED_OS )

  /* VS test build, this comes before all the others because it's used as a 
     quick test for buildability before switching to the embedded target and 
	 so overrides any other options */
  #if defined( _MSC_VER )

	/* VS 64-bit */
	#if defined( _M_X64 )
	  /* Win64's ULONG_MAX (via limits.h) is 32 bits so the system isn't
	     detected as a 64-bit one, to fix this we manually override the
	     detected machine word size here */
	  #undef SYSTEM_NAME
	  #define SYSTEM_NAME	"Embedded Win64 emulated cross-compile"
	  #define L_ENDIAN
	  #undef THIRTY_TWO_BIT
	  #define SIXTY_FOUR_BIT 
	  #define DES_INT 

	/* VC++ 32-bit */
	#elif ( _MSC_VER >= 1000 )
	  #undef SYSTEM_NAME
	  #define SYSTEM_NAME	"Embedded Win32 emulated cross-compile"
	  #define L_ENDIAN
	  #define BN_LLONG
	  #define RC4_INDEX

	#endif /* VC++ 64 vs 32-bit */

  /* Xilinx XMK */
  #elif defined ( _XMK ) || defined( __XMK__ )
	#if defined( __mb__ )
	  #define SYSTEM_NAME		"XMK MicroBlaze"
	  #define B_ENDIAN
	  /* Not sure what other options the MicroBlaze build should enable... */
	#elif defined( __ppc__ ) || defined( __powerpc ) || defined( __powerpc__ )
	  #define SYSTEM_NAME	"XMK PowerPC"
	  #ifdef DATA_LITTLEENDIAN
		#define L_ENDIAN
	  #else
		#define B_ENDIAN
	  #endif	/* Usually big-endian but may be little-endian */
	  #define BN_LLONG
	  #define DES_RISC1
	  #define DES_UNROLL
	  #define RC4_CHAR
	#else
	  #error Need to define CPU type for non-MicroBlaze/non-PPC XMK.
	#endif /* XMK target variants */

  /* IAR and TI ARM compilers */
  #elif defined( __IAR_SYSTEMS_ICC__ ) || defined( __TI_ARM__ )
	#define SYSTEM_NAME			"IAR/TI Arm"
	#ifdef DATA_LITTLEENDIAN
	  #define L_ENDIAN
	#else
	  #define B_ENDIAN
	#endif
	#define BN_LLONG
	#define DES_RISC1

  /* Generic 68K */
  #elif defined( __m68k__  )
	/* This one is CISC-y enough that any of the (mostly) RISC-specific
	   optimisations won't have much effect, so the generic code is as good
	   as any */
	#define SYSTEM_NAME			"Embedded 68K"
	#define B_ENDIAN

  /* Renesas V850 */
  #elif defined( __RENESAS__ )
	#define SYSTEM_NAME			"Renesas V850"
	#ifdef __LIT
	  #define L_ENDIAN
	#else
	  #define B_ENDIAN
	#endif
	#define BN_LLONG
	#define DES_RISC1

  /* VxWorks */
  #elif defined( __VxWorks__ )
	#if defined( __ppc__ ) || defined( __powerpc ) || defined( __powerpc__ )
	  #if defined( __clang__ ) 
		#define SYSTEM_NAME		"VxWorks PowerPC clang"
	  #else
		#define SYSTEM_NAME		"VxWorks PowerPC gcc"
	  #endif /* __clang__ */
	  #ifdef DATA_LITTLEENDIAN
		#define L_ENDIAN
	  #else
		#define B_ENDIAN
	  #endif	/* Usually big-endian but may be little-endian */
	  #define BN_LLONG
	  #define DES_RISC1
	  #define DES_UNROLL
	  #define RC4_CHAR
	#elif defined( __aarch64__ ) || defined( __arm64 )
	  /* We check for Arm64 before generic Arm for the same reasons as
		 x64 vs. x86 */
	  #if defined( __clang__ ) 
		#define SYSTEM_NAME		"VxWorks Arm64 clang"
	  #else
		#define SYSTEM_NAME		"VxWorks Arm64 gcc"
	  #endif /* __clang__ */
	  #ifdef DATA_BIGENDIAN
		#define B_ENDIAN
	  #else
		#define L_ENDIAN
	  #endif	/* Usually little-endian but may be big-endian */
	  #undef THIRTY_TWO_BIT
	  #undef SIXTY_FOUR_BIT
	  #define SIXTY_FOUR_BIT_LONG
	  #define RC4_CHAR
	#elif defined( __arm ) || defined( __arm__ )
	  #if defined( __clang__ ) 
		#define SYSTEM_NAME		"VxWorks Arm clang"
	  #else
		#define SYSTEM_NAME		"VxWorks Arm gcc"
	  #endif /* __clang__ */
	  #ifdef DATA_BIGENDIAN
		#define B_ENDIAN
	  #else
		#define L_ENDIAN
	  #endif	/* Usually little-endian but may be big-endian */
	  #define BN_LLONG
	  #define DES_RISC1
	#else
	  #error Need to define CPU type for non-ARM/non-PPC VxWorks.
	#endif /* XMK target variants */

  /* Generic clang or gcc, placed below all the others so that system-
     specific options are used first */
  #elif defined( __clang__ ) || defined( __GNUC__ )
	#if defined( __i386__ )
	  #if defined( __clang__ ) 
		#define SYSTEM_NAME		"Embedded x86 clang"
	  #else
		#define SYSTEM_NAME		"Embedded x86 gcc"
	  #endif /* __clang__ */
	  #define L_ENDIAN
	  #define BN_LLONG
	  #define DES_PTR
	  #define DES_RISC1
	  #define DES_UNROLL
	  #define RC4_INDEX
	#elif defined( __ppc__ ) || defined( __powerpc ) || defined( __powerpc__ )
	  #if defined( __clang__ ) 
		#define SYSTEM_NAME		"Embedded PowerPC clang"
	  #else
		#define SYSTEM_NAME		"Embedded PowerPC gcc"
	  #endif /* __clang__ */
	  #ifdef DATA_LITTLEENDIAN
		#define L_ENDIAN
	  #else
		#define B_ENDIAN
	  #endif	/* Usually big-endian but may be little-endian */
	  #define BN_LLONG
	  #define DES_RISC1
	  #define DES_UNROLL
	  #define RC4_CHAR
	#elif defined( __aarch64__ ) || defined( __arm64 )
	  /* We check for Arm64 before generic Arm for the same reasons as
		 x64 vs. x86 */
	  #if defined( __clang__ ) 
		#define SYSTEM_NAME		"Embedded Arm64 clang"
	  #else
		#define SYSTEM_NAME		"Embedded Arm64 gcc"
	  #endif /* __clang__ */
	  #ifdef DATA_BIGENDIAN
		#define B_ENDIAN
	  #else
		#define L_ENDIAN
	  #endif	/* Usually little-endian but may be big-endian */
	  #undef THIRTY_TWO_BIT
	  #undef SIXTY_FOUR_BIT
	  #define SIXTY_FOUR_BIT_LONG
	  #define RC4_CHAR
	#elif defined( __arm ) || defined( __arm__ )
	  #if defined( __clang__ ) 
		#define SYSTEM_NAME		"Embedded Arm clang"
	  #else
		#define SYSTEM_NAME		"Embedded Arm gcc"
	  #endif /* __clang__ */
	  #ifdef DATA_BIGENDIAN
		#define B_ENDIAN
	  #else
		#define L_ENDIAN
	  #endif	/* Usually little-endian but may be big-endian */
	  #define BN_LLONG
	  #define DES_RISC1
	#elif defined( __xtensa__ )
	  #if defined( __clang__ ) 
		#define SYSTEM_NAME		"Embedded Xtensa clang"
	  #else
		#define SYSTEM_NAME		"Embedded Xtensa gcc"
	  #endif /* __clang__ */
	  #define L_ENDIAN
	  #define BN_LLONG
	  #define DES_RISC1
	#else
	  #error Need to define CPU type for non-x86/non-PPC/non-ARM/non-Xtensa generic embedded.
	#endif /* XMK target variants */

  /* We need the developer's help to sort it out */
  #else
	#error Need to configure the crypto build options for your toolchain.
  #endif /* Embedded OS variants */

/* Aches */
#elif defined( _AIX )
  #define SYSTEM_NAME		"AIX on PowerPC"
  #define B_ENDIAN
  #define BN_LLONG
  #define RC4_CHAR

/* Alpha */
#elif defined( __osf__ ) || defined( __alpha__ )
  #define SYSTEM_NAME	"DEC Alpha"
  #define L_ENDIAN
  #undef SIXTY_FOUR_BIT
  #define SIXTY_FOUR_BIT_LONG
  #define DES_INT
  #define DES_UNROLL
  #define DES_RISC1

/* BeOS */
#elif defined( __BEOS__ )
  #if defined( __i386__ )
	#define SYSTEM_NAME		"BeOS x86"
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #elif defined( __ppc__ )
	#define SYSTEM_NAME		"BeOS PowerPC"
	#define B_ENDIAN
	#define BN_LLONG
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_CHAR
  #else
	#error Need to define CPU type for non-x86/non-PPC BeOS
  #endif /* BeoS variants */

/* The BSDs and Linux.  For low-level code-generation purposes these are 
   identical, even if they differ at a higher level */
#elif defined( __FreeBSD__ ) || defined( __bsdi__ ) || \
	  defined( __OpenBSD__ ) || defined( __NetBSD__ ) || \
	  defined( __linux__ )
  #if defined( __x86_64__ ) || defined( __amd64__ )
	/* 64-bit x86 has both 'long' and 'long long' as 64 bits.  In addition
	   we use DES_INT since int's are 64-bit.  We have to check for the
	   64-bit x86 variants before the generic ones because they're a
	   variation on the generics (e.g. AMD64 defines both __athlon__ and
	   __x86_64__, so if we checked for __athlon__ first we'd identify it
	   as a generic rather than 64-bit build) */
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux x64"
	#else
	  #define SYSTEM_NAME	"BSD x64"
	#endif /* BSD vs. Linux */
	#define L_ENDIAN
	#undef SIXTY_FOUR_BIT
	#define SIXTY_FOUR_BIT_LONG
	#define DES_INT
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #elif defined( __i386__ )
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux x86"
	#else
	  #define SYSTEM_NAME	"BSD x86"
	#endif /* BSD vs. Linux */
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #elif defined( __aarch64__ ) || defined( __arm64 )
	/* We check for Arm64 before generic Arm for the same reasons as
	   x64 vs. x86 */
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux Arm64"
	#else
	  #define SYSTEM_NAME	"BSD Arm64"
	#endif /* BSD vs. Linux */
	#ifdef DATA_BIGENDIAN
	  #define B_ENDIAN
	#else
	  #define L_ENDIAN
	#endif	/* Usually little-endian but may be big-endian */
	#undef SIXTY_FOUR_BIT
	#define SIXTY_FOUR_BIT_LONG
	#define RC4_CHAR
  #elif defined( __arm ) || defined( __arm__ )
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux Arm"
	#else
	  #define SYSTEM_NAME	"BSD Arm"
	#endif /* BSD vs. Linux */
	#ifdef DATA_BIGENDIAN
	  #define B_ENDIAN
	#else
	  #define L_ENDIAN
	#endif	/* Usually little-endian but may be big-endian */
	#define BN_LLONG
	#define DES_RISC1
  #elif defined( __mips__ )
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux MIPS"
	#else
	  #define SYSTEM_NAME	"BSD MIPS"
	#endif /* BSD vs. Linux */
	#ifdef DATA_BIGENDIAN
	  #define B_ENDIAN
	#else
	  #define L_ENDIAN
	#endif	/* Usually little-endian but may be big-endian */
	#ifndef SIXTY_FOUR_BIT	/* No built-in define for 64 bit */
	  #define BN_LLONG
	#endif /* SIXTY_FOUR_BIT */
	#define DES_RISC2
	#ifndef __clang__
	  /* Causes a segfault in des_encrypt2() with OpenBSD clang but not
		 Linux gcc */
	  #define DES_PTR
	#endif /* __clang__ */
	#define DES_UNROLL
	#define RC4_INDEX
	#define RC4_CHAR
  #elif defined( _ARCH_PPC ) || defined( _ARCH_PPC64 ) || \
		defined( __ppc ) || defined( __ppc__ ) || \
		defined( __powerpc ) || defined( __powerpc__ ) || \
		defined( __powerpc64__ )
	#ifdef DATA_LITTLEENDIAN
	  #define L_ENDIAN
	#else
	  #define B_ENDIAN
	#endif	/* Usually big-endian but may be little-endian */
	#if defined( _ARCH_PPC64 ) || defined( __powerpc64__ )
	  /* int = 32 bits, long/long long = 64 bits */
	  #ifdef __linux__
		#define SYSTEM_NAME	"Linux PowerPC 64"
	  #else
		#define SYSTEM_NAME	"BSD PowerPC 64"
	  #endif /* BSD vs. Linux */
	  #undef SIXTY_FOUR_BIT
	  #define SIXTY_FOUR_BIT_LONG
	#else
	  #ifdef __linux__
		#define SYSTEM_NAME	"Linux PowerPC"
	  #else
		#define SYSTEM_NAME	"BSD PowerPC"
	  #endif /* BSD vs. Linux */
	  #define BN_LLONG
	#endif /* PPC 64-bit */
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_CHAR
  #elif defined( __hppa__ )
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux HPPA"
	#else
	  #define SYSTEM_NAME	"BSD HPPA"
	#endif /* BSD vs. Linux */
	#define B_ENDIAN
	#ifndef SIXTY_FOUR_BIT	/* No built-in define for 64 bit */
	  #define BN_LLONG
	#endif /* SIXTY_FOUR_BIT */
	#define BN_DIV2W
	#define DES_PTR
	#define DES_UNROLL
	#define DES_RISC1
	#define MD32_XARRAY
  #elif defined( __sparc__ )
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux Sparc"
	#else
	  #define SYSTEM_NAME	"BSD Sparc"
	#endif /* BSD vs. Linux */
	#define B_ENDIAN
	#ifdef SIXTY_FOUR_BIT
	  /* Sparc64 is a bit of a pain, the best multiply op is 32 x 32 -> 64,
		 and there's no 64-bit add with carry/subtract with borrow, so we're
		 better off using 32-bit ops even on a 64-bit architecture */
	  #undef SIXTY_FOUR_BIT	
	  #define THIRTY_TWO_BIT
	#endif /* SIXTY_FOUR_BIT */
	#define BN_LLONG
	#define BN_DIV2W
	#define DES_UNROLL
	#define RC4_CHAR
  #elif defined( __riscv )
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux RISC-V"
	#else
	  #define SYSTEM_NAME	"BSD RISC-V"
	#endif /* BSD vs. Linux */
	#define L_ENDIAN
	#undef SIXTY_FOUR_BIT
	#define SIXTY_FOUR_BIT_LONG 
	#define RC4_CHAR
  #elif defined( __loongarch__ ) || defined( __loongarch64 )
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux Loongson"
	#else
	  #define SYSTEM_NAME	"BSD Loongson"
	#endif /* BSD vs. Linux */
	#define L_ENDIAN
	#undef SIXTY_FOUR_BIT
	#define SIXTY_FOUR_BIT_LONG 
	#define RC4_CHAR
  #elif defined( __sh__ )
	/* Super-H has defines for subtypes, __sh1__ to __sh3__ and then 
	   __SH3__ to __SH5__, but we treat them all as the same general 
	   architecture.
	   
	   There isn't any official config for Super-H (specifically SH4), the 
	   following is the config for MIPS which seems to work OK (the only
	   one that really matters is BN_LLONG which is generic for any 32-bit
	   CPU, Blowfish and RC4 are disabled by default and 3DES isn't used
	   much any more) */
	#ifdef __linux__
	  #define SYSTEM_NAME	"Linux SuperH"
	#else
	  #define SYSTEM_NAME	"BSD SuperH"
	#endif /* BSD vs. Linux */
	#ifdef DATA_BIGENDIAN
	  #define B_ENDIAN
	#else
	  #define L_ENDIAN
	#endif	/* Usually little-endian but may be big-endian */
	#define BN_LLONG
	#define DES_RISC2
	#define DES_PTR
	#define DES_UNROLL
	#define RC4_INDEX
	#define RC4_CHAR
  #else
	#error Need to define CPU type for non-x86/Arm/MIPS/PA-Risc/PPC/Sparc Linux
  #endif /* *BSD/Linux variants */
#elif defined( __LINUX__ ) && defined( __WATCOMC__ )
  #define SYSTEM_NAME		"Linux x86 Watcom C"
  #define L_ENDIAN
  #define BN_LLONG
  #define RC4_INDEX

/* Cray Unicos */
#elif defined( _CRAY )
  /* Crays are big-endian, but if B_ENDIAN is defined the code implicitly
     assumes 32-bit ints whereas Crays have 64-bit ints and longs.  However,
     the non-B/L_ENDIAN code happens to work, so we don't define either */
  #define SYSTEM_NAME		"Cray"
  #undef SIXTY_FOUR_BIT
  #define SIXTY_FOUR_BIT_LONG
  #define DES_INT

/* DGUX */
#elif defined( __dgux )
  #define SYSTEM_NAME		"DGUX"
  #define L_ENDIAN
  #define RC4_INDEX
  #define DES_UNROLL

/* DOS */
#elif defined( MSDOS ) || defined( __MSDOS__ )
  #if defined(__WATCOMC__)
	/* 32-bit DOS */
	#define SYSTEM_NAME		"32-bit DOS"
	#define L_ENDIAN
	#define BN_LLONG
	#define RC4_INDEX
  #else
	/* 16-bit DOS */
	#define SYSTEM_NAME		"16-bit DOS"
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_UNROLL
	#define DES_PTR
	#define RC4_INDEX
	#undef THIRTY_TWO_BIT
	#define SIXTEEN_BIT
  #endif /* 16- vs.32-bit DOS */

/* Emscripten */
#elif defined( __EMSCRIPTEN__ )
  #define SYSTEM_NAME		"Emscripten"
  #define L_ENDIAN
  #define BN_LLONG

/* Irix */
#elif defined( __sgi )
  #define SYSTEM_NAME		"IRIX MIPS"

  /* Irix 5.x and lower */
  #if ( OSVERSION <= 5 )
	#define B_ENDIAN
	#define BN_LLONG
	#define DES_RISC2
	#define DES_PTR
	#define DES_UNROLL
	#define RC4_INDEX
	#define RC4_CHAR

  /* Irix 6.x and higher */
  #else
	#define B_ENDIAN
	#define RC4_INDEX
	#define RC4_CHAR
	#define DES_UNROLL
	#define DES_RISC2
	#define DES_PTR
	/* Pure 64-bit should also define SIXTY_FOUR_BIT_LONG */
  #endif /* Irix versions */

/* Mac */
#elif defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __MRC__ )
  #define SYSTEM_NAME		"Macintosh"
  #define B_ENDIAN
  #define BN_LLONG
  #define DES_UNROLL
  #define RC4_CHAR

/* Mac OS X / iOS */
#elif defined( __APPLE__ ) && !defined( __MAC__ )
  #include <TargetConditionals.h>
  #if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR || TARGET_OS_WATCH
	#define L_ENDIAN
	#if defined( __aarch64__ ) || defined( __arm64 )
	  #define SYSTEM_NAME	"iOS Arm64"
	  #define L_ENDIAN
	  #undef SIXTY_FOUR_BIT
	  #define SIXTY_FOUR_BIT_LONG
	  #define RC4_CHAR
	#elif defined( __x86_64__ )
	  #define SYSTEM_NAME	"iOS x64"
	  #define L_ENDIAN
	  #undef SIXTY_FOUR_BIT
	  #define SIXTY_FOUR_BIT_LONG	
	  #define DES_INT
	  #define DES_RISC1
	  #define DES_UNROLL
	#else
	  #define SYSTEM_NAME	"iOS Arm"
	  #define BN_LLONG
	  #define DES_RISC1
	#endif /* 64- vs. 32-bit ARM */
  #elif defined( __aarch64__ ) || defined( __arm64 )
	#define SYSTEM_NAME		"OS X Arm64"
	#define L_ENDIAN
	#undef SIXTY_FOUR_BIT
	#define SIXTY_FOUR_BIT_LONG
	#define RC4_CHAR
  #elif defined( __x86_64__ )
	/* See the comment for the BSDs and Linux above */
	#define SYSTEM_NAME		"OS X x64"
	#define L_ENDIAN
	#undef SIXTY_FOUR_BIT
	#define SIXTY_FOUR_BIT_LONG
	#define DES_INT
	#define DES_RISC1
	#define DES_UNROLL
  #elif defined( __ppc__ )
	#define SYSTEM_NAME		"OS X PowerPC"
	#define B_ENDIAN
	#define BN_LLONG
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_CHAR
  #else
	#define SYSTEM_NAME		"OS X x86"
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #endif /* Mac OS variants */

/* MSDOS */
#elif defined( __MSDOS__ )
  #define SYSTEM_NAME		"DOS 16-bit"
  #define L_ENDIAN
  #define BN_LLONG
  #define DES_UNROLL
  #define DES_PTR
  #define RC4_INDEX
  #undef THIRTY_TWO_BIT
  #define SIXTEEN_BIT

/* MVS */
#elif defined( __MVS__ )
  #define SYSTEM_NAME		"MVS"
  #define B_ENDIAN
  #define BN_LLONG

/* NCR MP-RAS */
#elif defined( __UNIX_SV__ )
  #define SYSTEM_NAME		"NCR MP-RAS"
  #define L_ENDIAN
  #define BN_LLONG
  #define DES_PTR
  #define DES_RISC1
  #define DES_UNROLL
  #define RC4_INDEX

/* Nucleus */
#elif defined( __Nucleus__ )
  #define SYSTEM_NAME		"Nucleus"
  #ifdef DATA_BIGENDIAN
	#define B_ENDIAN
  #else
	#define L_ENDIAN
  #endif /* Big vs.little-endian */
  #define BN_LLONG
  #define DES_RISC1

/* Palm OS: ARM */
#elif defined( __PALMSOURCE__ )
  #if defined( __arm ) || defined( __arm__ )
	#define SYSTEM_NAME		"PalmOS Arm"
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_RISC1
  #else
	#error Need to define architecture-specific values for crypto code
  #endif /* Palm OS variants */

/* PHUX */
#elif defined( __hpux )
  #define SYSTEM_NAME		"HPUX HPPA"

  /* PHUX 9.x (some versions report it as 09 so we also check for 0) */
  #if ( OSVERSION == 0 || OSVERSION == 9 )
	#define B_ENDIAN
	#define BN_DIV2W
	#define BN_LLONG
	#define DES_PTR
	#define DES_UNROLL
	#define DES_RISC1
	#define MD32_XARRAY

  /* PHUX 10.x, 11.x */
  #else
	#define B_ENDIAN
	#ifndef SIXTY_FOUR_BIT	/* No built-in define for 64 bit */
	  #define BN_LLONG
	#endif /* SIXTY_FOUR_BIT */
	#define BN_DIV2W
	#define DES_PTR
	#define DES_UNROLL
	#define DES_RISC1
	#define MD32_XARRAY
	/* Pure 64-bit should also define SIXTY_FOUR_BIT_LONG RC4_INDEX
	   RC4_CHAR DES_INT */
  #endif /* PHUX versions */

/* QNX */
#elif defined( __QNX__ )
  #define SYSTEM_NAME		"QNX x86"
  #define L_ENDIAN
  #define BN_LLONG
  #define DES_PTR
  #define DES_RISC1
  #define DES_UNROLL
  #define RC4_INDEX
  #if OSVERSION <= 4
	/* The Watcom compiler can't handle 64-bit ints even though the hardware
	   can, so we have to build it as 16-bit code with 16x16 -> 32 multiplies
	   rather than 32x32 -> 64 */
	#undef THIRTY_TWO_BIT
	#define SIXTEEN_BIT
  #endif /* QNX 4.x */

/* SCO/UnixWare */
#elif defined( __SCO_VERSION__ )
  #define SYSTEM_NAME		"SCO x86"

  /* SCO gcc */
  #if defined( __GNUC__ )
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX

  /* SCO cc */
  #else
    #define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #endif /* SCO	gcc/cc */

/* Solaris */
#elif defined( sun ) || defined( __sun )

  /* Solaris Sparc */
  #if defined( sparc ) || defined( __sparc )
	#define B_ENDIAN

	/* Solaris Sparc gcc */
	#if defined( __GNUC__ )
	  #if defined( __sparc64 ) || defined( __arch64__ )
		#define SYSTEM_NAME	"Solaris Sparc64 gcc"
		#ifdef SIXTY_FOUR_BIT
		  /* Sparc64 is a bit of a pain, the best multiply op is 
		     32 x 32 -> 64, and there's no 64-bit add with carry/subtract 
			 with borrow, so we're better off using 32-bit ops even on a 
			 64-bit architecture */
		  #undef SIXTY_FOUR_BIT	
		  #define THIRTY_TWO_BIT
		#endif /* SIXTY_FOUR_BIT */
		#define BN_LLONG
		#define DES_INT 
		#define DES_PTR 
		#define DES_RISC1 
		#define DES_UNROLL 
		#define RC4_CHAR
	  #else
	    /* No obvious test for 32-bit Sparc */
		#define SYSTEM_NAME	"Solaris Sparc gcc"
		#define BN_DIV2W
		#define BN_LLONG
		#define DES_UNROLL
		#define RC4_CHAR
	  #endif /* 64- vs 32-bit */

	/* Solaris Sparc Sun C */
	#elif defined( __SUNPRO_C )
	  #if defined( __sparc64 ) || defined( __arch64__ )
		#define SYSTEM_NAME	"Solaris Sparc64 SunPro"
		#ifdef SIXTY_FOUR_BIT
		  /* Sparc64 is a bit of a pain, the best multiply op is 
		     32 x 32 -> 64, and there's no 64-bit add with carry/subtract 
			 with borrow, so we're better off using 32-bit ops even on a 
			 64-bit architecture */
		  #undef SIXTY_FOUR_BIT	
		  #define THIRTY_TWO_BIT
		#endif /* SIXTY_FOUR_BIT */
		#define BN_LLONG
		#define DES_INT 
		#define DES_PTR 
		#define DES_RISC1
		#define DES_UNROLL 
		#define RC4_CHAR 
	  #else
	    /* No obvious test for 32-bit Sparc */
		#define SYSTEM_NAME	"Solaris Sparc SunPro"
		#define BN_DIV2W
		#define BN_LLONG
		#define DES_PTR
		#define DES_RISC1
		#define DES_UNROLL
		#define RC4_CHAR
	  #endif /* 64- vs 32-bit */

	#else
	  #error Unknown Sun architecture (neither x86/x64 nor Sparc) encountered
	#endif /* Solaris Sparc */

  /* Solaris x86 */
  #else
	#define L_ENDIAN

	/* Solaris x86 gcc */
	#if defined( __GNUC__ )
	  #if defined( __x86_64__ )
		#define SYSTEM_NAME	"Solaris x64 gcc"
		#undef SIXTY_FOUR_BIT
		#define SIXTY_FOUR_BIT_LONG 
		#define DES_INT 
		#define DES_UNROLL
	  #elif defined( __i386__ )
		#define SYSTEM_NAME	"Solaris x86 gcc"
		#define BN_LLONG
		#define DES_PTR
		#define DES_RISC1
		#define DES_UNROLL
		#define RC4_INDEX
	  #else
		#error Unknown Sun x86 architecture (neither 32- nor 64-bit) encountered
	  #endif /* 32- vs 64-bit */

	/* Solaris x86 Sun C */
	#elif defined( __SUNPRO_C )
	  #if defined( __x86_64__ ) || defined( __x86_64 )
		#define SYSTEM_NAME	"Solaris x64 SunPro"
		#undef SIXTY_FOUR_BIT
		#define SIXTY_FOUR_BIT_LONG 
		#define DES_INT
		#define DES_UNROLL
	  #elif defined( __i386__ ) || defined( __i386 ) 
		#define SYSTEM_NAME	"Solaris x86 SunPro"
		#define BN_LLONG
		#define DES_PTR
		#define DES_UNROLL
		#define RC4_CHAR
	  #else
		#error Unknown Sun x86 architecture (neither 32- nor 64-bit) encountered
	  #endif /* 32- vs 64-bit */

	#else
	  #error Unknown Sun architecture (neither x86/x64 nor Sparc) encountered
	#endif /* Solaris x86 */
  #endif /* Solaris Sparc vs x86 */

/* Symbian OS: Usually ARM, but we may be running under the x86 emulator */
#elif defined( __SYMBIAN32__ )
  #if defined( __MARM__ )
	#define SYSTEM_NAME		"Symbian Arm"
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_RISC1
  #elif defined( __EMU_SYMBIAN_OS__ )
	#define SYSTEM_NAME		"Symbian Arm emulator"
	#define L_ENDIAN
	#define BN_LLONG
	#define DES_PTR
	#define DES_UNROLL
	#define RC4_INDEX
  #else
	#error Need to define architecture-specific values for crypto code
  #endif /* Symbian OS variants */

/* Tandem NSK/OSS */
#elif defined( __TANDEM )
  #if defined( _GUARDIAN_HOST ) || defined( _GUARDIAN_TARGET )
	#define SYSTEM_NAME		"Tandem NSK"
  #elif defined( _OSS_HOST ) || defined( _OSS_TARGET )
	#define SYSTEM_NAME		"Tandem OSS"
  #else
	#define SYSTEM_NAME		"Tandem (unknown configuration)"
  #endif /* System variants */
  #ifndef _TANDEM_ARCH_
	#error Cant determine Tandem architecture type to target
  #endif /* !_TANDEM_ARCH_ */
  #if ( _TANDEM_ARCH_ == 1 )
	/* TNS/R = 32-bit MIPS */
	#define B_ENDIAN
	#define DES_RISC2
	#define DES_PTR
	#define DES_UNROLL
	#define RC4_INDEX
	#define RC4_CHAR
  #elif ( _TANDEM_ARCH_ == 2 )
	/* TNS/E = Itanium */
	#define L_ENDIAN
	#undef SIXTY_FOUR_BIT
	#define SIXTY_FOUR_BIT_LONG
	#define DES_INT
	#define DES_UNROLL
	#define DES_RISC1
  #elif ( _TANDEM_ARCH_ == 3 )
	/* TNS/X = x86.  This is weird because it should be little-endian but 
	   Tandem have managed to make it seem big-endian (for compatibility 
	   with all of their previous hardware) by having their compiler
	   generate byte-swap instructions as data is moved to and from
	   memory.  No idea how this works in the presence of explicit
	   endian-aware data reads and writes but somehow it does */ 
	#if defined( __ILP32 )
	  #define B_ENDIAN
	  #define BN_LLONG
	  #define DES_PTR
	  #define DES_RISC1
	  #define DES_UNROLL
	  #define RC4_INDEX
	#elif defined( __LP64 )
	  #define B_ENDIAN
	  #undef SIXTY_FOUR_BIT
	  #define SIXTY_FOUR_BIT_LONG
	  #define DES_INT
	  #define DES_RISC1
	  #define DES_UNROLL
	#else
	  #error Unknown Tandem x86 architecture encountered
    #endif /* Tandem x86 architecture-specific options */
  #else
	#error Unknown Tandem architecture (neither TNS/R, TNS/E, or TNS/X) encountered
  #endif /* Tandem architecture-specific options */

/* Ultrix */
#elif defined( __ultrix__ )
  #define SYSTEM_NAME		"Ultrix"
  #define L_ENDIAN
  #define DES_PTR
  #define DES_RISC2
  #define DES_UNROLL

/* VM/CMS */
#elif defined( __VMCMS__ )
  #define SYSTEM_NAME		"VM/CMS"
  #define B_ENDIAN

/* Windows */
#elif defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 )
  #define L_ENDIAN

  /* VC++ */
  #if defined( _MSC_VER )

	/* VS 64-bit */
	#if defined( _M_X64 )
	  /* Win64's ULONG_MAX (via limits.h) is 32 bits so the system isn't
	     detected as a 64-bit one, to fix this we manually override the
	     detected machine word size here */
	  #define SYSTEM_NAME	"Win64 Visual Studio"
	  #undef THIRTY_TWO_BIT
	  #define SIXTY_FOUR_BIT 
	  #define DES_INT 

	/* VC++ 32-bit */
	#elif ( _MSC_VER >= 1000 )
	  #define SYSTEM_NAME	"Win32 Visual Studio"
	  #define BN_LLONG
	  #define RC4_INDEX

	/* VC++ 16-bit */
	#else
	  #define SYSTEM_NAME	"Win16 Visual Studio"
	  #define BN_LLONG
	  #define DES_UNROLL
	  #define DES_PTR
	  #define RC4_INDEX
	  #undef THIRTY_TWO_BIT
	  #define SIXTEEN_BIT
	#endif /* VC++ 32 vs 16-bit */

  /* BC++ */
  #elif defined( __BORLANDC__ )
	#define SYSTEM_NAME		"Win32 Borland C"
	#define BN_LLONG
	#define DES_PTR
	#define RC4_INDEX

  /* gcc */
  #else
	#define SYSTEM_NAME		"Win32 gcc"
	#define BN_LLONG
	#define DES_PTR
	#define DES_RISC1
	#define DES_UNROLL
	#define RC4_INDEX
  #endif /* Assorted Windows compilers */

#elif defined( __CYGWIN__ )
  #define SYSTEM_NAME		"cygwin x86"
  #define L_ENDIAN
  #define BN_LLONG
  #define DES_PTR
  #define DES_RISC1
  #define DES_UNROLL
  #define RC4_INDEX

#endif /* Platform-specific defines */

/* Make sure that we weren't missed out.  See the comment in the Cray 
   section for the exception for Crays */

#if !defined( _CRAY ) && !defined( L_ENDIAN ) && !defined( B_ENDIAN )
  #error You need to add system-specific configuration settings to osconfig.h.
#endif /* Endianness not defined */
#if defined( L_ENDIAN ) && defined( B_ENDIAN )
  #error Incorrect endianness detection in osconfig.h, both L_ENDIAN and B_ENDIAN are defined.
#endif /* Endianness defined erratically */
#if defined( CHECK_ENDIANNESS ) && !defined( OSX_UNIVERSAL_BINARY )
  /* One-off check in des_enc.c, however for OS X universal (fat) binaries
	 we're effectively cross-compiling for multiple targets so we don't
	 perform the check, which would yield false positives */
  #if defined( DATA_LITTLEENDIAN ) && defined( DATA_BIGENDIAN )
	#error Incorrect endianness detection in crypt.h, 
	#error both DATA_LITTLEENDIAN and DATA_BIGENDIAN are defined.
  #endif /* Global endianness defined erratically */
  #if ( defined( L_ENDIAN ) && !defined( DATA_LITTLEENDIAN ) )
	#error You need to synchronise the endianness configuration settings 
	#error in osconfig.h and crypt.h.  The cryptlib config is set to 
	#error DATA_BIGENDIAN but osconfig.h has detected L_ENDIAN.
  #endif /* L_ENDIAN && !DATA_LITTLEENDIAN */
  #if ( defined( B_ENDIAN ) && !defined( DATA_BIGENDIAN ) )
	#error You need to synchronise the endianness configuration settings 
	#error in osconfig.h and crypt.h.  The cryptlib config is set to 
	#error DATA_LITTLEENDIAN but osconfig.h has detected B_ENDIAN.
  #endif /* B_ENDIAN && !DATA_BIGENDIAN */
#endif /* One-off check */

#endif /* _OSCONFIG_DEFINED */
