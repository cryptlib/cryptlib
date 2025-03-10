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

 The unsigned integer types defined here are of the form uint_<nn>t where
 <nn> is the length of the type; for example, the unsigned 32-bit type is
 'uint32_t'.  These are NOT the same as the 'C99 integer types' that are
 defined in the inttypes.h and stdint.h headers since attempts to use these
 types have shown that support for them is still highly variable.  However,
 since the latter are of the form uint<nn>_t, a regular expression search
 and replace (in VC++ search on 'uint_{:z}t' and replace with 'uint\1_t')
 can be used to convert the types used here to the C99 standard types.
*/

#ifndef _BRG_TYPES_H
#define _BRG_TYPES_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <limits.h>

/* Include portions of crypt.h.  This is necessary because the maze of 
   headers and infinitely-nested macros in the AES code get confused by
   something in crypt.h that's proven impossible to track through said
   maze - pcg */
#if 1
  #include "crypt.h"
#else
  #include "misc/os_detect.h"
  #include "misc/config.h"
  #include "misc/os_spec.h"
#endif /* 0 */

#define ptrint_t	intptr_t

#ifndef BRG_UI32
#  define BRG_UI32
#  if UINT_MAX == 4294967295u
#    define li_32(h) 0x##h##u
#  elif ULONG_MAX == 4294967295u
#    define li_32(h) 0x##h##ul
#  elif defined( _CRAY )
  /* USE_AES is undefined on Crays, however we define a dummy data type
     to get the code to compile - pcg */
/*#error Crays don't support 32-bit data types, this code won't compile on a Cray*/
	typedef   unsigned int     uint32_t;
#  else
#    error Please define uint32_t as a 32-bit unsigned integer type in brg_types.h
#  endif
#endif

#ifndef BRG_UI64
#  if defined( __BORLANDC__ ) && !defined( __MSDOS__ )
#    define BRG_UI64
#    define li_64(h) 0x##h##ui64
#  elif defined( _MSC_VER ) && ( _MSC_VER < 1300 )    /* 1300 == VC++ 7.0 */
#    define BRG_UI64
#    define li_64(h) 0x##h##ui64
#  elif defined( __sun ) && defined( ULONG_MAX ) && ULONG_MAX == 0xfffffffful
#    define BRG_UI64
#    define li_64(h) 0x##h##ull
#  elif defined( __MVS__ )
#    define BRG_UI64
#    define li_64(h) 0x##h##ull
#  elif defined( UINT_MAX ) && UINT_MAX > 4294967295u
#    if UINT_MAX == 18446744073709551615u
#      define BRG_UI64
#      define li_64(h) 0x##h##u
#    endif
#  elif defined( ULONG_MAX ) && ULONG_MAX > 4294967295u
#    if ULONG_MAX == 18446744073709551615ul
#      define BRG_UI64
#      define li_64(h) 0x##h##ul
	#if !( defined( _UINT64_T ) || defined( _UINT64_T_DEFINED_ ) )
		/* Apple and OpenBSD define their own version - pcg */
		typedef unsigned long uint64_t;		/* AES-GCM - pcg */
	#endif /* !( _UINT64_T || _UINT64_T_DEFINED_ ) */
#    endif
#  elif defined( ULLONG_MAX ) && ULLONG_MAX > 4294967295u
#    if ULLONG_MAX == 18446744073709551615ull
#      define BRG_UI64
#      define li_64(h) 0x##h##ull
#    endif
#  elif defined( ULONG_LONG_MAX ) && ULONG_LONG_MAX > 4294967295u
#    if ULONG_LONG_MAX == 18446744073709551615ull
#      define BRG_UI64
#      define li_64(h) 0x##h##ull
#    endif
   #elif defined( __clang__ ) || defined( __GNUC__ )
		/* clang and gcc support 64-bit ints no matter what limits.h 
		   says - pcg */
		#define BRG_UI64
		#define li_64(h)	0x##h##ul
   #endif /* __clang__ || __GNUC__ */
#endif

#if !defined( BRG_UI64 )
#  if defined( NEED_UINT_64T )
#    error Please define uint64_t as an unsigned 64 bit type in brg_types.h
#  endif
#endif

#ifndef RETURN_VALUES
#  define RETURN_VALUES
#  if defined( DLL_EXPORT )
#    if defined( _MSC_VER ) || defined ( __INTEL_COMPILER )
#      define VOID_RETURN    __declspec( dllexport ) void __stdcall
#      define INT_RETURN     __declspec( dllexport ) int  __stdcall
#    elif defined( __GNUC__ )
#      define VOID_RETURN    __declspec( __dllexport__ ) void
#      define INT_RETURN     __declspec( __dllexport__ ) int
#    else
#      error Use of the DLL is only available on the Microsoft, Intel and GCC compilers
#    endif
#  elif defined( DLL_IMPORT )
#    if defined( _MSC_VER ) || defined ( __INTEL_COMPILER )
#      define VOID_RETURN    __declspec( dllimport ) void __stdcall
#      define INT_RETURN     __declspec( dllimport ) int  __stdcall
#    elif defined( __GNUC__ )
#      define VOID_RETURN    __declspec( __dllimport__ ) void
#      define INT_RETURN     __declspec( __dllimport__ ) int
#    else
#      error Use of the DLL is only available on the Microsoft, Intel and GCC compilers
#    endif
#  elif defined( __WATCOMC__ )
#    define VOID_RETURN  void __cdecl
#    define INT_RETURN   int  __cdecl
#  else
#    define VOID_RETURN  void
#    define INT_RETURN   int
#  endif
#endif

/*	These defines are used to detect and set the memory alignment of pointers.
    Note that offsets are in bytes.

    ALIGN_OFFSET(x,n)			return the positive or zero offset of 
                                the memory addressed by the pointer 'x' 
                                from an address that is aligned on an 
                                'n' byte boundary ('n' is a power of 2)

    ALIGN_FLOOR(x,n)			return a pointer that points to memory
                                that is aligned on an 'n' byte boundary 
                                and is not higher than the memory address
                                pointed to by 'x' ('n' is a power of 2)

    ALIGN_CEIL(x,n)				return a pointer that points to memory
                                that is aligned on an 'n' byte boundary 
                                and is not lower than the memory address
                                pointed to by 'x' ('n' is a power of 2)
*/

#define ALIGN_OFFSET(x,n)	(((ptrint_t)(x)) & ((n) - 1))
#define ALIGN_FLOOR(x,n)	((uint8_t*)(x) - ( ((ptrint_t)(x)) & ((n) - 1)))
#define ALIGN_CEIL(x,n)		((uint8_t*)(x) + (-((ptrint_t)(x)) & ((n) - 1)))

/*  These defines are used to declare buffers in a way that allows
    faster operations on longer variables to be used.  In all these
    defines 'size' must be a power of 2 and >= 8. NOTE that the 
    buffer size is in bytes but the type length is in bits

    UNIT_TYPEDEF(x,size)        declares a variable 'x' of length 
                                'size' bits

    BUFR_TYPEDEF(x,size,bsize)  declares a buffer 'x' of length 'bsize' 
                                bytes defined as an array of variables
                                each of 'size' bits (bsize must be a 
                                multiple of size / 8)

    UNIT_CAST(x,size)           casts a variable to a type of 
                                length 'size' bits

    UPTR_CAST(x,size)           casts a pointer to a pointer to a 
                                varaiable of length 'size' bits
*/

#define UI_TYPE(size)               uint##size##_t
#define UNIT_TYPEDEF(x,size)        typedef UI_TYPE(size) x
#define BUFR_TYPEDEF(x,size,bsize)  typedef UI_TYPE(size) x[bsize / (size >> 3)]
#define UNIT_CAST(x,size)           ((UI_TYPE(size) )(x))  
#define UPTR_CAST(x,size)           ((UI_TYPE(size)*)(x))

#if defined(__cplusplus)
}
#endif

#endif
