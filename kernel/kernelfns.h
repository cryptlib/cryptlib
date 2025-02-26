/****************************************************************************
*																			*
*					Kernel-specific Function Header File					*
*					  Copyright Peter Gutmann 1992-2019						*
*																			*
****************************************************************************/

#ifndef _KERNELFNS_DEFINED

#define _KERNELFNS_DEFINED

/* This file defines kernel-specific functions that are called directly from 
   init code.  These represent the external access point for functionality 
   like init, self-test, and shutdown */

/* Prototypes for kernel functions in init.c that need to be called from the 
   cryptlib init/shutdown code.  These should actually be annotated with 
   CHECK_RETVAL_ACQUIRELOCK( MUTEX_LOCKNAME( initialisation ) and
   RELEASELOCK( MUTEX_LOCKNAME( initialisation ) ) but the mutex locking
   types aren't visible outside the kernel and in any case the annotation is
   only required where the functions are defined, so we just annotate them
   normally here */

void preInit( void );
void postShutdown( void );
CHECK_RETVAL \
int krnlBeginInit( void );
void krnlCompleteInit( void );
CHECK_RETVAL \
int krnlBeginShutdown( void );
RETVAL \
int krnlCompleteShutdown( void );

/* Kernel-internal functions that need to be called from the cryptlib init/
   shutdown code */

CHECK_RETVAL \
int destroyObjects( void );
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL \
int testFunctionality( void );
CHECK_RETVAL \
int testKernel( void );
#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#endif /* _KERNELFNS_DEFINED */
