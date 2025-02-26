/****************************************************************************
*																			*
*							Secure Memory Management						*
*						Copyright Peter Gutmann 1995-2019					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

/* The minimum and maximum amount of secure memory that we can ever 
   allocate.  A more normal upper bound is 1K, however the TLS session cache 
   constitutes a single large chunk of secure memory that goes way over this 
   limit */

#define MIN_ALLOC_SIZE			8
#define MAX_ALLOC_SIZE			8192

/* Memory block flags.  These are:

	FLAG_LOCKED: The memory block has been page-locked to prevent it from 
			being swapped to disk and will need to be unlocked when it's 
			freed.

	FLAG_PROTECTED: The memory is read-only, enforced by running a checksum
			over it that's stored at the end of the user-visible block */

#define MEM_FLAG_NONE			0x00	/* No memory flag */
#define MEM_FLAG_LOCKED			0x01	/* Memory block is page-locked */
#define MEM_FLAG_PROTECTED		0x02	/* Memory block can't be changed */
#define MEM_FLAG_MAX			0x03	/* Maximum possible flag value */

/* To support page locking and other administration tasks we need to store 
   some additional information with the memory block.  We do this by 
   reserving an extra memory block at the start of the allocated block and 
   saving the information there.

   The information stored in the extra block is flags that control the use
   of the memory block, the size of the block, and pointers to the next and 
   previous pointers in the list of allocated blocks (this is used by the 
   thread that walks the block list touching each one).  We also insert a 
   canary at the start and end of each allocated memory block to detect 
   memory overwrites and modification, which is just a checksum of the memory
   header that doubles as a canary (which also makes it somewhat 
   unpredictable).

   The resulting memory block looks as follows:

			External mem.ptr
					|						Canary
					v						  v
		+-------+---+-----------------------+---+
		| Hdr	|###| Memory				|###|
		+-------+---+-----------------------+---+
		^									^	|
		|<----------- memHdrPtr->size --------->|
		|									|
	memPtr (BYTE *)							|
	memHdrPtr (MEM_INFO_HDR *)		memTrlPtr (MEM_INFO_TRL *) */

typedef struct {
	SAFE_FLAGS flags;		/* Flags for this memory block.  The memory 
							   header is checksummed so we don't strictly
							   have to use safe flags, but we do it anyway
							   for appearances' sake */
	int size;				/* Size of the block, including the size
							   of the MEM_INFO_HEADER header and 
							   MEM_INFO_TRAILER trailer */
	DATAPTR prev, next;		/* Next, previous memory block */
	int checksum;			/* Header checksum+canary for spotting overwrites */
	} MEM_INFO_HEADER;

typedef struct {
	int checksum;			/* Memory block checksum or canary (= header chks) */
	} MEM_INFO_TRAILER;

#if INT_MAX <= 32767
  #define MEM_ROUNDSIZE		4
#elif INT_MAX <= 0xFFFFFFFFUL
  #define MEM_ROUNDSIZE		8
#else
  #define MEM_ROUNDSIZE		16
#endif /* 16/32/64-bit systems */
#define MEM_INFO_HEADERSIZE	roundUp( sizeof( MEM_INFO_HEADER ), MEM_ROUNDSIZE )
#define MEM_INFO_TRAILERSIZE sizeof( MEM_INFO_TRAILER )

/****************************************************************************
*																			*
*						OS-Specific Nonpageable Allocators					*
*																			*
****************************************************************************/

/* Some OSes handle page-locking by explicitly locking an already-allocated
   address range, others require the use of a special allocate-nonpageable-
   memory function.  For the latter class we redefine the standard 
   clAlloc()/clFree() macros to use the appropriate OS-specific allocators */

#if defined( __BEOS__xxx )	/* See comment below */

/* BeOS' create_area(), like most of the low-level memory access functions 
   provided by different OSes, functions at the page level so we round the 
   size up to the page size.  We can mitigate the granularity somewhat by 
   specifying lazy locking, which means that the page isn't locked until it's 
   committed.

   In pre-open-source BeOS, areas were bit of a security tradeoff because 
   they were globally visible(!!!) through the use of find_area(), so that 
   any other process in the system could find them.  An attacker could 
   always find the app's malloc() arena anyway because of this, but putting 
   data directly into areas made the attacker's task somewhat easier.  Open-
   source BeOS fixed this, mostly because it would have taken extra work to 
   make areas explicitly globally visible and no-one could see a reason for 
   this, so it's somewhat safer there.

   However, the implementation of create_area() in the open-source BeOS 
   seems to be rather flaky (simply creating an area and then immediately 
   destroying it again causes a segmentation violation) so it may be 
   necessary to turn it off for some BeOS releases.
   
   In more recent open-source BeOS releases create_area() simply maps to
   mmap(), and that uses a function convert_area_protection_flags() to
   convert the BeOS to Posix flags which simply discards everything but
   AREA_READ, AREA_WRITE, and AREA_EXEC, so it appears that create_area()
   can no longer allocate non-pageable memory.  If the original behaviour is 
   ever restored then the code will need to be amended to add the following
   member to MEM_INFO_HEADER:

	area_id areaID;				// Needed for page locking under BeOS

   and save the areaID after the create_area() call:

	memHdrPtr->areaID = areaID; */

#define clAlloc( string, size )		beosAlloc( size )
#define clFree( string, memblock )	beosFree( memblock )

static void *beosAlloc( const int size )
	{ 
	void *memPtr = NULL; 
	area_id areaID; 

	areaID = create_area( "memory_block", &memPtr, B_ANY_ADDRESS,
						  roundUp( size + MEM_INFO_HEADERSIZE, B_PAGE_SIZE ),
						  B_LAZY_LOCK, B_READ_AREA | B_WRITE_AREA );
	if( areaID < B_NO_ERROR )
		return( NULL );

	return( memPtr );
	}

static void beosFree( void *memPtr )
	{
	MEM_INFO_HEADER *memHdrPtr = memPtr;
	area_id areaID; 

	areaID = memHdrPtr->areaID;
	REQUIRES( isIntegerRangeNZ( memHdrPtr->size ) ); 
	zeroise( memPtr, memHdrPtr->size );
	delete_area( areaID );
	}

#elif defined( __CHORUS__ )

/* ChorusOS is one of the very few embedded OSes with paging capabilities,
   fortunately there's a way to allocate nonpageable memory if paging is
   enabled */

#include <mem/chMem.h>

#define clAlloc( string, size )		chorusAlloc( size )
#define clFree( string, memblock )	chorusFree( memblock )

static void *chorusAlloc( const int size )
	{ 
	KnRgnDesc rgnDesc = { K_ANYWHERE, size + MEM_INFO_HEADERSIZE, \
						  K_WRITEABLE | K_NODEMAND };

	if( rgnAllocate( K_MYACTOR, &rgnDesc ) != K_OK )
		return( NULL );

	return( rgnDesc.startAddr );
	}

static void chorusFree( void *memPtr )
	{
	MEM_INFO_HEADER *memHdrPtr = memPtr;
	KnRgnDesc rgnDesc = { K_ANYWHERE, 0, 0 };

	rgnDesc.size = memHdrPtr->size;
	rgnDesc.startAddr = memPtr;
	REQUIRES( isIntegerRangeNZ( memHdrPtr->size ) ); 
	zeroise( memPtr, memHdrPtr->size );
	rgnFree( K_MYACTOR, &rgnDesc );
	}
#endif /* OS-specific nonpageable allocation handling */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Calculate the checksum for a memory header block */

STDC_NONNULL_ARG( ( 1 ) ) \
static int checksumMemHdr( INOUT_PTR MEM_INFO_HEADER *memHdrPtr )
	{
	const int memHdrChecksum = memHdrPtr->checksum;
	int checksum;

	memHdrPtr->checksum = 0;
	checksum = checksumData( memHdrPtr, MEM_INFO_HEADERSIZE );
	memHdrPtr->checksum = memHdrChecksum;

	return( checksum );
	}

/* Set the checksum for a block of memory */

STDC_NONNULL_ARG( ( 1 ) ) \
static void setMemChecksum( INOUT_PTR MEM_INFO_HEADER *memHdrPtr )
	{
	MEM_INFO_TRAILER *memTrlPtr;

	assert( isWritePtr( memHdrPtr, sizeof( MEM_INFO_HEADER * ) ) );

	memHdrPtr->checksum = 0;	/* Set mutable members to zero */
	memHdrPtr->checksum = checksumData( memHdrPtr, MEM_INFO_HEADERSIZE );
	memTrlPtr = ( MEM_INFO_TRAILER * ) \
				( ( BYTE * ) memHdrPtr + memHdrPtr->size - MEM_INFO_TRAILERSIZE );
	memTrlPtr->checksum = memHdrPtr->checksum;
	}

/* Check that a memory block is in order */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkMemBlockHdr( INOUT_PTR MEM_INFO_HEADER *memHdrPtr )
	{
	const MEM_INFO_TRAILER *memTrlPtr;
	int checksum;

	assert( isWritePtr( memHdrPtr, sizeof( MEM_INFO_HEADER * ) ) );

	/* Make sure that the general header information is valid.  This is a 
	   quick check for obviously-invalid blocks, as well as ensuring that a 
	   corrupted size member doesn't result in us reading off into the 
	   weeds */
	if( memHdrPtr->size < MEM_INFO_HEADERSIZE + MIN_ALLOC_SIZE + \
						  MEM_INFO_TRAILERSIZE || \
		memHdrPtr->size > MEM_INFO_HEADERSIZE + MAX_ALLOC_SIZE + \
						  MEM_INFO_TRAILERSIZE )
		return( FALSE );
	if( !CHECK_FLAGS( memHdrPtr->flags, MEM_FLAG_NONE, 
					  MEM_FLAG_MAX ) )
		return( FALSE );

	/* Everything seems kosher so far, check that the header hasn't been 
	   altered */
	checksum = checksumMemHdr( memHdrPtr );
	if( checksum != memHdrPtr->checksum )
		return( FALSE );

	/* Check that the trailer hasn't been altered */
	memTrlPtr = ( MEM_INFO_TRAILER * ) \
				( ( BYTE * ) memHdrPtr + memHdrPtr->size - MEM_INFO_TRAILERSIZE );
	if( memHdrPtr->checksum != memTrlPtr->checksum )
		return( FALSE );
	
	return( TRUE );
	}

/* Insert and unlink a memory block from a list of memory blocks, with 
   appropriate updates of memory checksums and other information.  Because
   of this additional processing we can't use the standard 
   insertSingleListElement()/deleteSingleListElement() operations but have
   to do things explicitly.
   
   We keep the code for this in distinct functions to make sure that an 
   exception-condition doesn't force an exit without the memory mutex 
   unlocked */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int insertMemBlock( INOUT_PTR MEM_INFO_HEADER **allocatedListHeadPtr, 
						   INOUT_PTR MEM_INFO_HEADER **allocatedListTailPtr, 
						   INOUT_PTR MEM_INFO_HEADER *memHdrPtr )
	{
	MEM_INFO_HEADER *allocatedListHead = *allocatedListHeadPtr;
	MEM_INFO_HEADER *allocatedListTail = *allocatedListTailPtr;

	assert( isWritePtr( allocatedListHeadPtr, sizeof( MEM_INFO_HEADER * ) ) );
	assert( allocatedListHead == NULL || \
			isWritePtr( allocatedListHead, sizeof( MEM_INFO_HEADER ) ) );
	assert( isWritePtr( allocatedListTailPtr, sizeof( MEM_INFO_HEADER * ) ) );
	assert( allocatedListTail == NULL || \
			isWritePtr( allocatedListTail, sizeof( MEM_INFO_HEADER ) ) );
	assert( isWritePtr( memHdrPtr, sizeof( MEM_INFO_HEADER * ) ) );

	/* Precondition: The memory block list is empty, or there's at least a 
	   one-entry list present */
	REQUIRES( ( allocatedListHead == NULL && allocatedListTail == NULL ) || \
			  ( allocatedListHead != NULL && allocatedListTail != NULL ) );

	/* If it's a new list, set up the head and tail pointers and return */
	if( allocatedListHead == NULL )
		{
		/* In yet another of gcc's endless supply of compiler bugs, if the
		   following two lines of code are combined into a single line then
		   the write to the first value, *allocatedListHeadPtr, ends up 
		   going to some arbitrary memory location and only the second
		   write goes to the correct location (completely different code is
		   generated for the two writes)  This leaves 
		   krnlData->allocatedListHead as a NULL pointer, leading to an
		   exception being triggered the next time that it's accessed */
#if defined( __GNUC__ ) && ( __GNUC__ == 4 )
		*allocatedListHeadPtr = memHdrPtr;
		*allocatedListTailPtr = memHdrPtr;
#else
		*allocatedListHeadPtr = *allocatedListTailPtr = memHdrPtr;
#endif /* gcc 4.x compiler bug */

		return( CRYPT_OK );
		}
	ENSURES( allocatedListHead != NULL && allocatedListTail != NULL );

	/* It's an existing list, add the new element to the end */
	REQUIRES( checkMemBlockHdr( allocatedListTail ) );
	DATAPTR_SET( allocatedListTail->next, memHdrPtr );
	setMemChecksum( allocatedListTail );
	DATAPTR_SET( memHdrPtr->prev, allocatedListTail );
	*allocatedListTailPtr = memHdrPtr;

	/* Postcondition: The new block has been linked into the end of the 
	   list */
	ENSURES( DATAPTR_GET( allocatedListTail->next ) == memHdrPtr && \
			 DATAPTR_GET( memHdrPtr->prev ) == allocatedListTail && \
			 DATAPTR_ISNULL( memHdrPtr->next ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int unlinkMemBlock( INOUT_PTR MEM_INFO_HEADER **allocatedListHeadPtr, 
						   INOUT_PTR MEM_INFO_HEADER **allocatedListTailPtr, 
						   INOUT_PTR MEM_INFO_HEADER *memHdrPtr )
	{
	MEM_INFO_HEADER *allocatedListHead = *allocatedListHeadPtr;
	MEM_INFO_HEADER *allocatedListTail = *allocatedListTailPtr;
	MEM_INFO_HEADER *nextBlockPtr = DATAPTR_GET( memHdrPtr->next );
	MEM_INFO_HEADER *prevBlockPtr = DATAPTR_GET( memHdrPtr->prev );

	assert( isWritePtr( allocatedListHeadPtr, sizeof( MEM_INFO_HEADER * ) ) );
	assert( allocatedListHead == NULL || \
			isWritePtr( allocatedListHead, sizeof( MEM_INFO_HEADER ) ) );
	assert( isWritePtr( allocatedListTailPtr, sizeof( MEM_INFO_HEADER * ) ) );
	assert( allocatedListTail == NULL || \
			isWritePtr( allocatedListTail, sizeof( MEM_INFO_HEADER ) ) );
	assert( isWritePtr( memHdrPtr, sizeof( MEM_INFO_HEADER * ) ) );

	REQUIRES( DATAPTR_ISVALID( memHdrPtr->next ) );
	REQUIRES( DATAPTR_ISVALID( memHdrPtr->prev ) );

	/* If we're removing the block from the start of the list, make the
	   start the next block */
	if( memHdrPtr == allocatedListHead )
		{
		REQUIRES( prevBlockPtr == NULL );

		*allocatedListHeadPtr = nextBlockPtr;
		}
	else
		{
		REQUIRES( prevBlockPtr != NULL && \
				  DATAPTR_GET( prevBlockPtr->next ) == memHdrPtr );

		/* Delete from the middle or end of the list */
		REQUIRES( checkMemBlockHdr( prevBlockPtr ) );
		DATAPTR_SET( prevBlockPtr->next, nextBlockPtr );
		setMemChecksum( prevBlockPtr );
		}
	if( nextBlockPtr != NULL )
		{
		REQUIRES( DATAPTR_GET( nextBlockPtr->prev ) == memHdrPtr );

		REQUIRES( checkMemBlockHdr( nextBlockPtr ) );
		DATAPTR_SET( nextBlockPtr->prev, prevBlockPtr );
		setMemChecksum( nextBlockPtr );
		}

	/* If we've removed the last element, update the end pointer */
	if( memHdrPtr == allocatedListTail )
		{
		REQUIRES( nextBlockPtr == NULL );

		*allocatedListTailPtr = prevBlockPtr;
		}

	/* Clear the current block's pointers, just to be clean */
	DATAPTR_SET( memHdrPtr->next, NULL );
	DATAPTR_SET( memHdrPtr->prev, NULL );

	return( CRYPT_OK );
	}

/* Some OSes handle memory locking on a per-page basis, which means that we
   can't unlock a block of memory without knowing that it doesn't share a
   page with another block of locked memory which would also be unlocked.
   The following helper function retrieves the size and address of each
   allocated block of memory to allow its presence in an about-to-be-unlocked
   page to be checked */

#if defined( __WIN32__ )

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int getBlockListInfo( IN_PTR_OPT const void *currentBlockPtr, 
					  OUT_PTR_PTR_COND const void **address, 
					  OUT_LENGTH_Z int *size )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	const MEM_INFO_HEADER *currentBlock = currentBlockPtr;

	assert( ( currentBlockPtr == NULL ) || \
			isReadPtr( currentBlockPtr, sizeof( MEM_INFO_HEADER ) ) );
	assert( isReadPtr( address, sizeof( void * ) ) );
	assert( isWritePtr( size, sizeof( int ) ) );

	/* Clear return values */
	*address = NULL;
	*size = 0;

	/* Get the first or next block in the list */
	if( currentBlock == NULL )
		currentBlock = DATAPTR_GET( krnlData->allocatedListHead );
	else
		currentBlock = DATAPTR_GET( currentBlock->next );
	if( currentBlock == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	*address = currentBlock;
	*size = currentBlock->size;

	return( CRYPT_OK );
	}
#endif /* Windows */

#if 0	/* Currently unused, in practice would be called from a worker thread
		   that periodically touches all secure-data pages */

/* Walk the allocated block list touching each page.  In most cases we don't
   need to explicitly touch the page since the allocated blocks are almost
   always smaller than the MMU's page size and simply walking the list
   touches them, but in some rare cases we need to explicitly touch each
   page */

static void touchAllocatedPages( void )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	LOOP_INDEX_PTR MEM_INFO_HEADER *memHdrPtr;
	const int pageSize = getSysVar( SYSVAR_PAGESIZE );

	/* Lock the allocation object to ensure that other threads don't try to
	   access them */
	MUTEX_LOCK( allocation );

	/* Walk down the list (which implicitly touches each page).  If the
	   allocated region is larger than the page size, explicitly touch each 
	   additional page */
	LOOP_LARGE( memHdrPtr = krnlData->allocatedListHead, memHdrPtr != NULL,
				memHdrPtr = memHdrPtr->next )
		{
		ENSURES( LOOP_INVARIANT_LARGE_GENERIC() );

		/* If the allocated region has pages beyond the first one (which 
		   we've already touched by accessing the header), explicitly
		   touch those pages as well */
		if( memHdrPtr->size > pageSize )
			{
			BYTE *memPtr = ( BYTE * ) memHdrPtr + pageSize;
			int memSize = memHdrPtr->size;

			/* Touch each page.  The rather convoluted expression in the loop
			   body is to try and stop it from being optimised away - it 
			   always evaluates to true since we only get here if 
			   allocatedListHead != NULL, but hopefully the compiler won't 
			   be able to figure that out */
			LOOP_LARGE_ALT( memSize = memHdrPtr->size, memSize > pageSize, 
						memSize -= pageSize )
				{
				ENSURES( LOOP_INVARIANT_LARGE_ALT_GENERIC() );

				if( *memPtr || krnlData->allocatedListHead != NULL )
					memPtr += pageSize;
				}
			ENSURES( LOOP_BOUND_ALT_OK );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	/* Unlock the allocation object to allow access by other threads */
	MUTEX_UNLOCK( allocation );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* Create and destroy the secure allocation information */

CHECK_RETVAL \
int initAllocation( void )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	int status;

	assert( isWritePtr( krnlData, sizeof( KERNEL_DATA ) ) );

	/* Clear the allocated block list head and tail pointers */
	DATAPTR_SET( krnlData->allocatedListHead, NULL );
	DATAPTR_SET( krnlData->allocatedListTail, NULL );

	/* Initialize any data structures required to make the allocation thread-
	   safe */
	MUTEX_CREATE( allocation, status );
	ENSURES( cryptStatusOK( status ) );

	return( CRYPT_OK );
	}

void endAllocation( void )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );

	/* Destroy any data structures required to make the allocation thread-
	   safe */
	MUTEX_DESTROY( allocation );
	}

/****************************************************************************
*																			*
*						Secure Memory Allocation Functions					*
*																			*
****************************************************************************/

/* A safe malloc function that performs page locking if possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemalloc( OUT_BUFFER_ALLOC_OPT( size ) void **pointer, 
				  IN_LENGTH int size )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	MEM_INFO_HEADER *allocatedListHeadPtr, *allocatedListTailPtr; 
	MEM_INFO_HEADER *memHdrPtr;
	BYTE *memPtr;
	const int alignedSize = roundUp( size, MEM_ROUNDSIZE );
	const int memSize = MEM_INFO_HEADERSIZE + alignedSize + \
						MEM_INFO_TRAILERSIZE;
	int status;

	static_assert( MEM_INFO_HEADERSIZE >= sizeof( MEM_INFO_HEADER ), \
				   "Memlock header size" );

	/* Make sure that the parameters are in order */
	if( !isWritePtr( pointer, sizeof( void * ) ) )
		retIntError();
	
	REQUIRES( size >= MIN_ALLOC_SIZE && size <= MAX_ALLOC_SIZE );

	/* Clear return values */
	*pointer = NULL;

	/* Allocate and clear the memory */
	REQUIRES( isIntegerRangeNZ( memSize ) );
	if( ( memPtr = clAlloc( "krnlMemAlloc", memSize ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( memPtr, 0, memSize );

	/* Set up the memory block header and trailer */
	memHdrPtr = ( MEM_INFO_HEADER * ) memPtr;
	INIT_FLAGS( memHdrPtr->flags, MEM_FLAG_NONE );
	memHdrPtr->size = memSize;
	DATAPTR_SET( memHdrPtr->next, NULL );
	DATAPTR_SET( memHdrPtr->prev, NULL );

	/* Try to lock the pages in memory */
	if( lockMemory( memHdrPtr, memHdrPtr->size ) )
		SET_FLAG( memHdrPtr->flags, MEM_FLAG_LOCKED );

	/* Lock the memory list */
	MUTEX_LOCK( allocation );

	/* Check safe pointers */
	if( !DATAPTR_ISVALID( krnlData->allocatedListHead ) || \
		!DATAPTR_ISVALID( krnlData->allocatedListTail ) )
		{
		MUTEX_UNLOCK( allocation );
		clFree( "krnlMemAlloc", memPtr );
		DEBUG_DIAG(( "Kernel memory data corrupted" ));
		retIntError();
		}

	/* Insert the new block into the list */
	allocatedListHeadPtr = DATAPTR_GET( krnlData->allocatedListHead );
	allocatedListTailPtr = DATAPTR_GET( krnlData->allocatedListTail );
	status = insertMemBlock( &allocatedListHeadPtr, &allocatedListTailPtr, 
							 memHdrPtr );
	if( cryptStatusError( status ) )
		{
		MUTEX_UNLOCK( allocation );
		clFree( "krnlMemAlloc", memPtr );
		retIntError();
		}
	DATAPTR_SET( krnlData->allocatedListHead, allocatedListHeadPtr );
	DATAPTR_SET( krnlData->allocatedListTail, allocatedListTailPtr );

	/* Calculate the checksums for the memory block */
	setMemChecksum( memHdrPtr );

	/* Perform heap sanity-checking if the functionality is available */
#ifdef USE_HEAP_CHECKING
	/* Sanity check to detect memory chain corruption */
	assert( _CrtIsValidHeapPointer( memHdrPtr ) );
	assert( DATAPTR_ISNULL( memHdrPtr->next ) );
	assert( DATAPTR_GET( krnlData->allocatedListHead ) == \
				DATAPTR_GET( krnlData->allocatedListTail ) || \
			_CrtIsValidHeapPointer( DATAPTR_GET( memHdrPtr->prev ) ) );
#endif /* USE_HEAP_CHECKING */

	MUTEX_UNLOCK( allocation );

	*pointer = memPtr + MEM_INFO_HEADERSIZE;

	return( CRYPT_OK );
	}

/* A safe free function that scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlMemfree( INOUT_PTR_PTR void **pointer )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	MEM_INFO_HEADER *allocatedListHeadPtr, *allocatedListTailPtr; 
	MEM_INFO_HEADER *memHdrPtr;
	BYTE *memPtr;
	int status;

	assert( isReadPtr( pointer, sizeof( void * ) ) );

	/* Make sure that the parameters are in order */
	if( !isReadPtr( pointer, sizeof( void * ) ) || \
		!isReadPtr( *pointer, MIN_ALLOC_SIZE ) )
		retIntError();

	/* Recover the actual allocated memory block data from the pointer */
	memPtr = ( ( BYTE * ) *pointer ) - MEM_INFO_HEADERSIZE;
	if( !isReadPtr( memPtr, MEM_INFO_HEADERSIZE ) )
		retIntError();
	memHdrPtr = ( MEM_INFO_HEADER * ) memPtr;

	/* Lock the memory list */
	MUTEX_LOCK( allocation );

	/* Check safe pointers */
	if( !DATAPTR_ISVALID( krnlData->allocatedListHead ) || \
		!DATAPTR_ISVALID( krnlData->allocatedListTail ) )
		{
		MUTEX_UNLOCK( allocation );
		DEBUG_DIAG(( "Kernel memory data corrupted" ));
		retIntError();
		}

	/* Make sure that the memory header information and canaries are 
	   valid */
	if( !checkMemBlockHdr( memHdrPtr ) )
		{
		MUTEX_UNLOCK( allocation );

		/* The memory block doesn't look right, don't try and go any 
		   further */
		DEBUG_DIAG(( "Attempt to free invalid memory segment at %lX inside "
					 "memory block at %lX", *pointer, memHdrPtr ));
		retIntError();
		}

	/* Perform heap sanity-checking if the functionality is available */
#ifdef USE_HEAP_CHECKING
	/* Sanity check to detect memory chain corruption */
	assert( _CrtIsValidHeapPointer( memHdrPtr ) );
	assert( DATAPTR_ISNULL( memHdrPtr->next ) || \
			_CrtIsValidHeapPointer( DATAPTR_GET( memHdrPtr->next ) ) );
	assert( DATAPTR_ISNULL( memHdrPtr->prev ) || \
			_CrtIsValidHeapPointer( DATAPTR_GET( memHdrPtr->prev ) ) );
#endif /* USE_HEAP_CHECKING */

	/* Unlink the memory block from the list */
	allocatedListHeadPtr = DATAPTR_GET( krnlData->allocatedListHead );
	allocatedListTailPtr = DATAPTR_GET( krnlData->allocatedListTail );
	status = unlinkMemBlock( &allocatedListHeadPtr, &allocatedListTailPtr, 
							 memHdrPtr );
	if( cryptStatusOK( status ) )
		{
		DATAPTR_SET( krnlData->allocatedListHead, allocatedListHeadPtr );
		DATAPTR_SET( krnlData->allocatedListTail, allocatedListTailPtr );
		}

	MUTEX_UNLOCK( allocation );

	/* Zeroise the memory (including the memlock info), free it, and zero
	   the pointer */
	REQUIRES( isIntegerRangeNZ( memHdrPtr->size ) ); 
	zeroise( memPtr, memHdrPtr->size );
	if( TEST_FLAG( memHdrPtr->flags, MEM_FLAG_LOCKED ) )
		unlockMemory( memHdrPtr, memHdrPtr->size, TRUE );
	clFree( "krnlMemFree", memPtr );
	*pointer = NULL;

	return( status );
	}
