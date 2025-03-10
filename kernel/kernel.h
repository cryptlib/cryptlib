/****************************************************************************
*																			*
*							cryptlib Kernel Header File						*
*						Copyright Peter Gutmann 1992-2020					*
*																			*
****************************************************************************/

#ifndef _KERNEL_DEFINED

#define _KERNEL_DEFINED

#if defined( INC_ALL )
  #include "thread.h"
#else
  #include "kernel/thread.h"
#endif /* Compiler-specific includes */

/* RAY and EGON look over code.

   EGON: The structure of this kernel is exactly like the kind of telemetry
         tracker that NASA uses to secure dead pulsars in deep space.

   RAY: All message dispatch mechanisms and callback functions.

   PETER (to other jailbirds): Everyone getting this so far?  So what?  I
         guess they just don't make them like they used to.

   RAY: No!  Nobody ever made them like this!  The architect was either a
        certified genius or an authentic wacko! */

/* "There is a fine line between genius and insanity.
    I have erased this line" - Oscar Levant
	(or "Nullum magnum ingenium sine mixtura dementiae" if you want it in
	the usual style) */

/****************************************************************************
*																			*
*							Parameter Checking Macros						*
*																			*
****************************************************************************/

/* Macros to perform validity checks on objects and handles.  These checks
   are:

	isValidHandle(): Whether a handle is a valid index into the object table.
	isValidObject(): Whether a handle refers to an object in the table.
	isFreeObject(): Whether a handle refers to an empty entry in the table.
	isInternalObject(): Whether an object is an internal object.
	isInvalidObjectState(): Whether an object is in an invalid (error) state.
	isInUse(): Whether an object is currently in use (processing a message).
	isObjectOwner(): If inUse == TRUE, whether this thread is the one using
					 the object.
	isInHighState(): Whether an object is in the 'high' security state.
	isSameOwningObject(): Whether two objects have the same owner.  We also
						  have to handle the situation where the first object
						  is a user object, in which case it has to be the
						  owner of the second object.
	isObjectAccessValid(): Internal/external object access check.
	isValidMessage(): Whether a message type is valid.
	isInternalMessage(): Whether a message is an internal message.
	isValidType(): Whether an object type is valid
	isValidSubtype(): Whether an object subtype is allowed based on access
					  bitflags */

#define isValidHandle( handle ) \
		( ( handle ) >= 0 && ( handle ) < MAX_NO_OBJECTS )
#define isValidObject( handle ) \
		( isValidHandle( handle ) && \
		  DATAPTR_GET( objectTable[ ( handle ) ].objectPtr ) != NULL )
#define isFreeObject( handle ) \
		( isValidHandle( handle ) && \
		  DATAPTR_GET( objectTable[ ( handle ) ].objectPtr ) == NULL )
#define isInternalObject( handle ) \
		( TEST_FLAG( objectTable[ handle ].flags, OBJECT_FLAG_INTERNAL ) )
#define isObjectAccessValid( objectHandle, message ) \
		!( isInternalObject( objectHandle ) && \
		   !( ( message ) & MESSAGE_FLAG_INTERNAL ) )
#define isInvalidObjectState( handle ) \
		( TEST_FLAG( objectTable[ ( handle ) ].flags, OBJECT_FLAGMASK_STATUS ) )
#define isInUse( handle ) \
		( objectTable[ ( handle ) ].lockCount > 0 )
#define isObjectOwner( handle ) \
		THREAD_IS_CURRENT( objectTable[ ( handle ) ].lockOwner )
#define isInHighState( handle ) \
		( TEST_FLAG( objectTable[ ( handle ) ].flags, OBJECT_FLAG_HIGH ) )
#define isSameOwningObject( handle1, handle2 ) \
		( objectTable[ ( handle1 ) ].owner == CRYPT_UNUSED || \
		  objectTable[ ( handle2 ) ].owner == CRYPT_UNUSED || \
		  ( objectTable[ ( handle1 ) ].owner == objectTable[ ( handle2 ) ].owner ) || \
		  ( ( handle1 ) == objectTable[ ( handle2 ) ].owner ) )
#define isValidMessage( message ) \
		( ( message ) > MESSAGE_NONE && ( message ) < MESSAGE_LAST )
#define isInternalMessage( message ) \
		( ( message ) & MESSAGE_FLAG_INTERNAL )
#define isValidType( type ) \
		( ( type ) > OBJECT_TYPE_NONE && ( type ) < OBJECT_TYPE_LAST )
#define isValidSubtype( subtypeMask, subtype ) \
		( ( ( subtypeMask ) & ( subtype ) ) == ( subtype ) )

/* The set of object checks is used frequently enough that we combine them
   into a composite check that performs all of the checks in one place */

#define fullObjectCheck( objectHandle, message ) \
		( isValidObject( objectHandle ) && \
		  isObjectAccessValid( objectHandle, message ) && \
		  checkObjectOwnership( objectTable[ objectHandle ] ) )

/* Macros to test whether a message falls into a certain class.  These tests
   are:

	isParamMessage(): Whether a message contains an object as a parameter */

#define isParamMessage( message ) \
		( ( message ) == MESSAGE_CRT_SIGN || \
		  ( message ) == MESSAGE_CRT_SIGCHECK )

/* Macros to manage object ownership, if the OS supports it */

#define checkObjectOwnership( objectPtr ) \
		( !TEST_FLAG( ( objectPtr ).flags, OBJECT_FLAG_OWNED ) || \
		  THREAD_IS_CURRENT( ( objectPtr ).objectOwner ) )

/* A macro to turn an abnormal status indicated in an object's flags into a
   status code.  The values are prioritised so that notinited > signalled >
   busy */

#define getObjectStatusValue( flags ) \
		( TEST_FLAG( flags, OBJECT_FLAG_NOTINITED ) ? CRYPT_ERROR_NOTINITED : \
		  TEST_FLAG( flags, OBJECT_FLAG_SIGNALLED ) ? CRYPT_ERROR_SIGNALLED : \
		  CRYPT_OK )

/****************************************************************************
*																			*
*						Object Definitions and Information					*
*																			*
****************************************************************************/

/* The information maintained by the kernel for each object */

typedef struct {
	/* Object type and value */
	OBJECT_TYPE type;			/* Object type */
	OBJECT_SUBTYPE subType;		/* Object subtype */
	DATAPTR objectPtr;			/* Object data */
	int objectSize;				/* Object data size */

	/* Object properties */
	SAFE_FLAGS flags;			/* Internal-only, locked, etc */
	int actionFlags;			/* Permitted actions */
	int intRefCount, extRefCount;/* Number of int/ext refs.to this object */
	int lockCount;				/* Message-processing lock recursion count */
#ifdef USE_THREADS
	THREAD_HANDLE lockOwner;	/* Lock owner if lockCount > 0 */
#endif /* USE_THREADS */
	int uniqueID;				/* Unique ID for this object */
/*	time_t lastAccess;			// Last access time */

	/* Object security properties */
	int forwardCount;			/* Number of times ownership can be transferred */
	int usageCount;				/* Number of times obj.can be used */
#ifdef USE_THREADS
	THREAD_HANDLE objectOwner;	/* The object's owner */
#endif /* USE_THREADS */

	/* Object methods */
	FNPTR messageFunction;		/* The object's message handler */

	/* Owning and dependent objects */
	CRYPT_USER owner;			/* Owner object handle */
	CRYPT_HANDLE dependentObject;	/* Dependent object (context or cert) */
	CRYPT_HANDLE dependentDevice;	/* Dependent crypto device */
	} OBJECT_INFO;

/* The flags that apply to each object in the table:

	FLAG_ATTRLOCKED: The security properties, for example the owner or usage 
		count, of the object are locked and can no longer be modified.

	FLAG_HIGH: The object is in the 'high' security state, limiting what
		can be done with it.

	FLAG_INTERNAL: Object is internal-use only, i.e. can't be accessed from
		public API calls.

	FLAG_NOTINITED: Object is in the process of being initialised and can't 
		be used yet.

	FLAG_OWNED: Object is bound to a thread.

	FLAG_SECUREMALLOC: Object data storage was allocated using 
		krnlMemAlloc() rather than the standard malloc().

	FLAG_SIGNALLED: Object is in the signalled state and can't be used any 
		more except to be destroyed.

	FLAG_STATICALLOC: Object uses statically allocated storage from the 
		kernel memory block */

#define OBJECT_FLAG_NONE		0x0000	/* Non-flag */
#define OBJECT_FLAG_INTERNAL	0x0001	/* Internal-use only */
#define OBJECT_FLAG_NOTINITED	0x0002	/* Still being initialised */
#define OBJECT_FLAG_HIGH		0x0004	/* In 'high' security state */
#define OBJECT_FLAG_SIGNALLED	0x0008	/* In signalled state */
#define OBJECT_FLAG_STATICALLOC	0x0010	/* Statically allocated object */
#define OBJECT_FLAG_SECUREMALLOC 0x0020	/* Uses secure memory */
#define OBJECT_FLAG_OWNED		0x0040	/* Object is bound to a thread */
#define OBJECT_FLAG_ATTRLOCKED	0x0080	/* Security properties can't be modified */
#define OBJECT_FLAG_MAX			0x00FF	/* Last possible flag type */

/* The flags that convey information about an object's status */

#define OBJECT_FLAGMASK_STATUS \
		( OBJECT_FLAG_NOTINITED | OBJECT_FLAG_SIGNALLED )

/****************************************************************************
*																			*
*							Kernel Data Structures							*
*																			*
****************************************************************************/

/* The object allocation state data.  This controls the allocation of
   handles to newly-created objects.  The first NO_SYSTEM_OBJECTS handles
   are system objects that exist with fixed handles, the remainder are
   allocated pseudorandomly under the control of an LFSR */

typedef struct {
	int objectHandle;			/* Current object handle */
	} OBJECT_STATE_INFO;

/* A structure to store the details of a message sent to an object, and the
   size of the message queue.  This defines the maximum nesting depth of
   messages sent by an object.  Because of the way krnlSendMessage() handles
   message processing, it's extremely difficult to ever have more than two
   or three messages in the queue unless an object starts recursively
   sending itself messages */

typedef struct {
	int objectHandle;			/* Handle to send message to */
	DATAPTR handlingInfoPtr;	/* Message handling info */
	MESSAGE_TYPE message;
	DATAPTR messageDataPtr;
	int messageValue;			/* Message parameters */
	} MESSAGE_QUEUE_DATA;

#define MESSAGE_QUEUE_SIZE	16

/* Semaphores are one-shots, so that once set and cleared they can't be
   reset.  This is handled by enforcing the following state transitions:

	Uninited -> Set | Clear
	Set -> Set | Clear
	Clear -> Clear

   The handling is complicated somewhat by the fact that on some systems the
   semaphore has to be explicitly deleted, but only the last thread to use
   it can safely delete it.  In order to handle this, we reference-count the
   semaphore and let the last thread out delete it.  In order to do this we
   introduce an additional state, preClear, which indicates that while the
   semaphore object is still present, the last thread out should delete it,
   bringing it to the true clear state */

typedef enum {
	SEMAPHORE_STATE_UNINITED,
	SEMAPHORE_STATE_CLEAR,
	SEMAPHORE_STATE_PRECLEAR,
	SEMAPHORE_STATE_SET,
	SEMAPHORE_STATE_LAST
	} SEMAPHORE_STATE;

typedef struct {
	SEMAPHORE_STATE state;		/* Semaphore state */
	MUTEX_HANDLE semaphoreObject; /* Handle to synchronisation object, */
	THREAD_HANDLE threadObject;	/* either semaphore or thread handle */
	int refCount;				/* Reference count for handle */
	} SEMAPHORE_INFO;

/* A structure to store the details of a thread */

typedef struct {
	FNPTR threadFunction;			/* Function to call from thread */
	THREAD_PARAMS threadParams;		/* Thread function parameter struct */
	SEMAPHORE_TYPE semaphore;		/* Optional semaphore to set */
	THREAD_HANDLE threadHandle;		/* Handle for the thread */
	MUTEX_HANDLE syncHandle;		/* Handle for thread synchronisation */
	} THREAD_INFO;

/* When the kernel starts up and closes down it does so in a multi-stage 
   process that's equivalent to Unix runlevels.  For the startup at the
   first level the kernel data block and all kernel-level primitive
   objects like mutexes have been initialised.
   
   For the shutdown, at the first level all internal worker threads/tasks 
   must exist.  At the next level all messages to objects except destroy 
   messages fail.  At the final level all kernel-managed primitives such as 
   mutexes and semaphores are no longer available */

typedef enum {
	INIT_LEVEL_NONE,			/* Uninitialised */
	INIT_LEVEL_KRNLDATA,		/* Kernel data block initialised */
	INIT_LEVEL_FULL,			/* Full initialisation */
	INIT_LEVEL_LAST				/* Last possible init level */
	} INIT_LEVEL;

typedef enum {
	SHUTDOWN_LEVEL_NONE,		/* Normal operation */
	SHUTDOWN_LEVEL_THREADS,		/* Internal threads must exit */
	SHUTDOWN_LEVEL_MESSAGES,	/* Only destroy messages are valid */
	SHUTDOWN_LEVEL_MUTEXES,		/* Kernel objects become invalid */
	SHUTDOWN_LEVEL_ALL,			/* Complete shutdown */
	SHUTDOWN_LEVEL_LAST			/* Last possible shutdown level */
	} SHUTDOWN_LEVEL;

/* The kernel data block, containing all variables used by the kernel.  With
   the exception of the special-case values at the start, all values in this
   block should be set to use zero/NULL as their ground state (for example a
   boolean variable should have a ground state of FALSE (zero) rather than
   TRUE (nonzero)).

   If the objectTable giant lock (or more strictly speaking monolithic lock, 
   since the kernel's message-handling is designed to be straight-line code 
   and so never blocks for any amount of time like the Linux giant lock can) 
   ever proves to be a problem then the solution would be to use lock 
   striping, dividing the load of the object table across NO_TABLE_LOCKS 
   locks.  This gets a bit tricky because the object table is dynamically
   resizeable, a basic mod_NO_TABLE_LOCKS strategy where every n-th entry 
   uses the same lock works but then we'd still need a giant lock to check 
   whether the table is being resized.  To avoid this we can use a lock-free 
   implementation that operates by acquiring each lock (to make sure we have 
   complete control of the table), checking whether another thread beat us to 
   it, and if not resizing the table.  The pseudocode for this is as 
   follows:

	// Remember the original table size
	const int oldSize = krnlData->objectTableSize;

	// Acquire each lock
	for( i = 0; i < NO_LOCKS; i++ )
		THREAD_LOCK( krnlData->locks[ i ] );

	// Check whether another thread beat us to the resize while we were 
	// acquiring locks
	if( krnlData->objectTableSize != oldSize )
		{
		// Unlock all the locks
		// ... //
		return;
		}

	// We hold all the locks and therefore have exclusive control of the 
	// table, resize it
	// ... //

	// Release each lock again //
	for( i = 0; i < NO_LOCKS; i++ )
		THREAD_UNLOCK( krnlData->locks[ i ] );

   This is a conventional lock-free implementation of such an algorithm but 
   is conceptually ugly in that it accesses protected data outside the lock, 
   which will cause concurrency-checking tools to complain.  Until the fast-
   path through the kernel actually becomes a real bottleneck it's probably 
   best to leave well enough alone */

typedef struct {
	/* The kernel initialisation state and a lock to protect it.  The
	   lock and shutdown level value are handled externally and aren't
	   cleared when the kernel data block as a whole is cleared.  Note
	   that the shutdown level has to be before the lock so that we can
	   statically initialise the data with '{ 0 }', which won't work if
	   the lock data is non-scalar */
	SHUTDOWN_LEVEL shutdownLevel;		/* Kernel shutdown level */
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( initialisation );
#endif /* USE_THREADS */
	/* Everything from this point on is cleared at init and shutdown */
	int initLevel;						/* Kernel initialisation level */

	/* The kernel object table management info */
	int objectUniqueID;					/* Unique ID for next object */
	OBJECT_STATE_INFO objectStateInfo;	/* Object allocation state */
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( objectTable );
#endif /* USE_THREADS */

	/* The kernel message dispatcher queue */
	BUFFER( MESSAGE_QUEUE_SIZE, queueEnd ) \
	MESSAGE_QUEUE_DATA messageQueue[ MESSAGE_QUEUE_SIZE + 8 ];
	int queueEnd;						/* Points past last queue element */

	/* The kernel semaphores */
	BUFFER_FIXED( SEMAPHORE_LAST ) \
	SEMAPHORE_INFO semaphoreInfo[ SEMAPHORE_LAST + 8 ];
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( semaphore );
#endif /* USE_THREADS */

	/* The kernel mutexes.  Since mutexes usually aren't scalar values and
	   are declared and accessed via macros that manipulate various fields,
	   we have to declare a pile of them individually rather than using an
	   array of mutexes */
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( mutex1 );
	MUTEX_DECLARE_STORAGE( mutex2 );
  #ifdef USE_SESSIONS
	MUTEX_DECLARE_STORAGE( mutex3 );
	MUTEX_DECLARE_STORAGE( mutex4 );
	MUTEX_DECLARE_STORAGE( mutex5 );
	MUTEX_DECLARE_STORAGE( mutex6 );
  #endif /* USE_SESSIONS */
#endif /* USE_THREADS */

	/* The kernel thread data */
#ifdef USE_THREADS
	THREAD_INFO threadInfo;
#endif /* USE_THREADS */

	/* The kernel secure memory list and a lock to protect access to both it 
	   and the kernel static object storage */
	DATAPTR allocatedListHead, allocatedListTail;
#ifdef USE_THREADS
	MUTEX_DECLARE_STORAGE( allocation );
#endif /* USE_THREADS */

	/* A marker for the end of the kernel data, used during init/shutdown */
	int endMarker;
	} KERNEL_DATA;

/****************************************************************************
*																			*
*								ACL Functions								*
*																			*
****************************************************************************/

/* Prototypes for functions in certm_acl.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckCertMgmtAccess( IN_HANDLE const int objectHandle,
									IN_MESSAGE const MESSAGE_TYPE message,
									IN_BUFFER_C( sizeof( MESSAGE_CERTMGMT_INFO ) ) \
										const void *messageDataPtr,
									IN_ENUM( CRYPT_CERTACTION ) \
										const int messageValue,
									STDC_UNUSED const void *dummy );

/* Prototypes for functions in key_acl.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckKeysetAccess( IN_HANDLE const int objectHandle,
								  IN_MESSAGE const MESSAGE_TYPE message,
								  IN_BUFFER_C( sizeof( MESSAGE_KEYMGMT_INFO ) ) \
										const void *messageDataPtr,
								  IN_ENUM( KEYMGMT_ITEM ) const int messageValue,
								  STDC_UNUSED const void *dummy );

/* Prototypes for functions in mech_acl.c.  These all have to have the same
   signature so while we can TYPECAST() the mechanism information argument 
   at the analyzer level we have to keep it as a generic 'void *' at the 
   compiler level */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckMechanismWrapAccess( IN_HANDLE const int objectHandle,
										 IN_MESSAGE const MESSAGE_TYPE message,
										 IN_BUFFER_C( sizeof( MECHANISM_WRAP_INFO ) ) \
											TYPECAST( MECHANISM_WRAP_INFO * ) \
											const void *messageDataPtr,
										 IN_ENUM( MECHANISM ) const int messageValue,
										 STDC_UNUSED const void *dummy );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckMechanismSignAccess( IN_HANDLE const int objectHandle,
										 IN_MESSAGE const MESSAGE_TYPE message,
										 IN_BUFFER_C( sizeof( MECHANISM_SIGN_INFO ) ) \
											TYPECAST( MECHANISM_SIGN_INFO * ) \
											const void *messageDataPtr,
										 IN_ENUM( MECHANISM ) const int messageValue,
										 STDC_UNUSED const void *dummy );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckMechanismDeriveAccess( IN_HANDLE const int objectHandle,
										   IN_MESSAGE const MESSAGE_TYPE message,
										   IN_BUFFER_C( sizeof( MECHANISM_DERIVE_INFO ) ) \
												TYPECAST( MECHANISM_DERIVE_INFO * ) \
												const void *messageDataPtr,
										   IN_ENUM( MECHANISM ) const int messageValue,
										   STDC_UNUSED const void *dummy );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckMechanismKDFAccess( IN_HANDLE const int objectHandle,
										IN_MESSAGE const MESSAGE_TYPE message,
										IN_BUFFER_C( sizeof( MECHANISM_KDF_INFO ) ) \
											TYPECAST( MECHANISM_KDF_INFO * ) \
											const void *messageDataPtr,
										IN_ENUM( MECHANISM ) const int messageValue,
										STDC_UNUSED const void *dummy );

/* Prototypes for functions in msg_acl.c.  These all have to have the same
   signature so while we can TYPECAST() the ACL argument at the analyzer 
   level we have to keep it as a generic 'void *' at the compiler level */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN paramAclConsistent( const PARAM_ACL *paramACL );
CHECK_RETVAL \
int preDispatchSignalDependentObjects( IN_HANDLE const int objectHandle,
									   STDC_UNUSED const MESSAGE_TYPE dummy1,
									   STDC_UNUSED const void *dummy2,
									   STDC_UNUSED const int dummy3,
									   STDC_UNUSED const void *dummy4 );
CHECK_RETVAL STDC_NONNULL_ARG( ( 5 ) ) \
int preDispatchCheckAttributeAccess( IN_HANDLE const int objectHandle,
									 IN_MESSAGE const MESSAGE_TYPE message,
									 IN_PTR_OPT const void *messageDataPtr,
									 IN_ATTRIBUTE const int messageValue,
									 IN_PTR TYPECAST( ATTRIBUTE_ACL * ) \
										const void *auxInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 5 ) ) \
int preDispatchCheckCompareParam( IN_HANDLE const int objectHandle,
								  IN_MESSAGE const MESSAGE_TYPE message,
								  IN_PTR const void *messageDataPtr,
								  IN_ENUM( MESSAGE_COMPARE ) const int messageValue,
								  STDC_UNUSED const void *dummy2 );
CHECK_RETVAL \
int preDispatchCheckCheckParam( IN_HANDLE const int objectHandle,
								IN_MESSAGE const MESSAGE_TYPE message,
								STDC_UNUSED const void *dummy1,
								IN_ENUM( MESSAGE_CHECK ) const int messageValue,
								STDC_UNUSED const void *dummy2 );
CHECK_RETVAL \
int preDispatchCheckActionAccess( IN_HANDLE const int objectHandle,
								  IN_MESSAGE const MESSAGE_TYPE message,
								  STDC_UNUSED const void *dummy1,
								  STDC_UNUSED const int dummy2,
								  STDC_UNUSED const void *dummy3 );
CHECK_RETVAL \
int preDispatchCheckState( IN_HANDLE const int objectHandle,
						   IN_MESSAGE const MESSAGE_TYPE message,
						   STDC_UNUSED const void *dummy1,
						   STDC_UNUSED const int dummy2, 
						   STDC_UNUSED const void *dummy3 );
CHECK_RETVAL \
int preDispatchCheckParamHandleOpt( IN_HANDLE const int objectHandle,
									IN_MESSAGE const MESSAGE_TYPE message,
									STDC_UNUSED const void *dummy1,
									const int messageValue,
									IN_PTR TYPECAST( MESSAGE_ACL * ) \
										const void *auxInfo );
CHECK_RETVAL \
int preDispatchCheckStateParamHandle( IN_HANDLE const int objectHandle,
									  IN_MESSAGE const MESSAGE_TYPE message,
									  STDC_UNUSED const void *dummy1,
									  const int messageValue,
									  IN_PTR TYPECAST( MESSAGE_ACL * ) \
											const void *auxInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckExportAccess( IN_HANDLE const int objectHandle,
								  IN_MESSAGE const MESSAGE_TYPE message,
								  IN_PTR const void *messageDataPtr,
								  IN_ENUM( CRYPT_CERTFORMAT ) const int messageValue,
								  STDC_UNUSED const void *dummy2 );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckData( IN_HANDLE const int objectHandle,
						  IN_MESSAGE const MESSAGE_TYPE message,
						  IN_BUFFER_C( sizeof( MESSAGE_DATA ) ) \
								const void *messageDataPtr,
						  STDC_UNUSED const int dummy1,
						  STDC_UNUSED const void *dummy2 );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckCreate( IN_HANDLE const int objectHandle,
							IN_MESSAGE const MESSAGE_TYPE message,
							IN_BUFFER_C( sizeof( MESSAGE_CREATEOBJECT_INFO ) ) \
								const void *messageDataPtr,
							IN_ENUM( OBJECT_TYPE ) const int messageValue,
							STDC_UNUSED const void *dummy );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckUserMgmtAccess( IN_HANDLE const int objectHandle, 
									IN_MESSAGE const MESSAGE_TYPE message,
									STDC_UNUSED const void *dummy1,
									IN_ENUM( MESSAGE_USERMGMT ) const int messageValue, 
									STDC_UNUSED const void *dummy2 );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int preDispatchCheckTrustMgmtAccess( IN_HANDLE const int objectHandle, 
									 IN_MESSAGE const MESSAGE_TYPE message,
									 IN_PTR const void *messageDataPtr,
									 STDC_UNUSED const int messageValue, 
									 STDC_UNUSED const void *dummy );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int postDispatchSignalDependentDevices( IN_HANDLE const int objectHandle,
										STDC_UNUSED const MESSAGE_TYPE dummy1,
										STDC_UNUSED const void *dummy2,
										STDC_UNUSED const int dummy3,
										STDC_UNUSED const void *dummy4 );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int postDispatchMakeObjectExternal( STDC_UNUSED const int dummy,
									IN_MESSAGE const MESSAGE_TYPE message,
									IN_PTR const void *messageDataPtr,
									const int messageValue,
									IN_PTR_OPT const void *auxInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int postDispatchForwardToDependentObject( IN_HANDLE const int objectHandle,
										  IN_MESSAGE const MESSAGE_TYPE message,
										  STDC_UNUSED const void *dummy1,
										  IN_ENUM( MESSAGE_CHECK ) const int messageValue,
										  STDC_UNUSED const void *dummy2 );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int postDispatchUpdateUsageCount( IN_HANDLE const int objectHandle,
								  STDC_UNUSED const MESSAGE_TYPE dummy1,
								  STDC_UNUSED const void *dummy2,
								  STDC_UNUSED const int dummy3,
								  STDC_UNUSED const void *dummy4 );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int postDispatchChangeState( IN_HANDLE const int objectHandle,
							 STDC_UNUSED const MESSAGE_TYPE dummy1,
							 STDC_UNUSED const void *dummy2,
							 STDC_UNUSED const int dummy3,
							 STDC_UNUSED const void *dummy4 );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int postDispatchChangeStateOpt( IN_HANDLE const int objectHandle,
								STDC_UNUSED const MESSAGE_TYPE dummy1,
								STDC_UNUSED const void *dummy2,
								const int messageValue,
								IN_PTR TYPECAST( ATTRIBUTE_ACL * ) \
									const void *auxInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int postDispatchHandleZeroise( IN_HANDLE const int objectHandle, 
							   IN_MESSAGE const MESSAGE_TYPE message,
							   STDC_UNUSED const void *dummy2,
							   IN_ENUM( MESSAGE_USERMGMT ) const int messageValue,
							   STDC_UNUSED const void *dummy3 );

/****************************************************************************
*																			*
*								Kernel Functions							*
*																			*
****************************************************************************/

/* Sanity-check object data */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckObject( const OBJECT_INFO *objectInfoPtr );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Prototypes for functions in attr_acl.c */

CHECK_RETVAL_PTR \
const void *findAttributeACL( IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
							  IN_BOOL const BOOLEAN isInternalMessage );

/* Prototypes for functions in int_msg.c */

CHECK_RETVAL \
int convertIntToExtRef( IN_HANDLE const int objectHandle );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int getPropertyAttribute( IN_HANDLE const int objectHandle,
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						  OUT_BUFFER_FIXED_C( sizeof( int ) ) void *messageDataPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int setPropertyAttribute( IN_HANDLE const int objectHandle,
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						  IN_BUFFER_C( sizeof( int ) ) void *messageDataPtr );
CHECK_RETVAL \
int incRefCount( IN_HANDLE const int objectHandle, 
				 STDC_UNUSED const int dummy1,
				 STDC_UNUSED const void *dummy2, 
				 IN_BOOL const BOOLEAN isInternal );
CHECK_RETVAL \
int decRefCount( IN_HANDLE const int objectHandle, 
				 STDC_UNUSED const int dummy1,
				 STDC_UNUSED const void *dummy2, 
				 IN_BOOL const BOOLEAN isInternal );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int getDependentObject( IN_HANDLE const int objectHandle, 
						const int targetType,
						IN_BUFFER_C( sizeof( int ) ) \
								const void *messageDataPtr,
							/* This is a bit of a lie since we actually 
							   return the dependent object through this 
							   pointer, however making it non-const means 
							   that we'd have to also un-const every other 
							   use of this parameter in all other functions 
							   accessed via this function pointer */
						STDC_UNUSED const BOOLEAN dummy );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int setDependentObject( IN_HANDLE const int objectHandle, 
						IN_ENUM( SETDEP_OPTION ) const int option,
						IN_BUFFER_C( sizeof( int ) ) \
								const void *messageDataPtr,
						STDC_UNUSED const BOOLEAN dummy );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int clearDependentObject( IN_HANDLE const int objectHandle, 
						  STDC_UNUSED const int messageValue,
						  STDC_UNUSED const void *messageDataPtr,
						  STDC_UNUSED const BOOLEAN dummy );
CHECK_RETVAL \
int cloneObject( IN_HANDLE const int objectHandle, 
				 IN_HANDLE const int clonedObject,
				 STDC_UNUSED const void *dummy1, 
				 STDC_UNUSED const BOOLEAN dummy2 );

/* Prototypes for functions in sendmsg.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int checkTargetType( IN_HANDLE const CRYPT_HANDLE originalObjectHandle, 
					 OUT_HANDLE_OPT CRYPT_HANDLE *targetObjectHandle,
					 const long targets );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int findTargetType( IN_HANDLE const CRYPT_HANDLE originalObjectHandle, 
					OUT_HANDLE_OPT CRYPT_HANDLE *targetObjectHandle,
					const long targets );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int waitForObject( IN_HANDLE const int objectHandle, 
				   OUT_PTR_PTR_COND OBJECT_INFO **objectInfoPtrPtr );
#ifndef NDEBUG
CHECK_RETVAL_PTR_NONNULL \
const char *getObjectTypeDescriptionNT( IN_ENUM( OBJECT_TYPE ) \
											const OBJECT_TYPE type, 
										IN_ENUM( SUBTYPE ) \
											const OBJECT_SUBTYPE subType );
CHECK_RETVAL_PTR_NONNULL \
const char *getObjectDescriptionNT( IN_HANDLE const int objectHandle );
#endif /* NDEBUG */

/* Prototypes for functions in objects.c */

CHECK_RETVAL \
int destroyObjectData( IN_HANDLE const int objectHandle );

/* Prototypes for functions in semaphore.c.  Depending on the OS type the 
   synchronisation object can be a semaphore or thread so we have to pass in 
   both when we initialise the semaphore */

#ifdef USE_THREAD_FUNCTIONS
void setSemaphore( IN_ENUM( SEMAPHORE ) const SEMAPHORE_TYPE semaphore,
				   const MUTEX_HANDLE semaphoreObject,
				   const THREAD_HANDLE threadObject );
void clearSemaphore( IN_ENUM( SEMAPHORE ) const SEMAPHORE_TYPE semaphore );
#endif /* USE_THREAD_FUNCTIONS */

/* Prototypes for functions in storage.c.  These are kernel-internal access
   functions, non-kernel storage is allocated via the functions defined in 
   int_api.h */

typedef enum {
	SYSTEM_STORAGE_NONE,
	SYSTEM_STORAGE_KRNLDATA,
	SYSTEM_STORAGE_OBJECT_TABLE,
	SYSTEM_STORAGE_LAST
	} SYSTEM_STORAGE_TYPE;

void initBuiltinStorage( void );
void destroyBuiltinStorage( void );
void clearKernelData( void );
void *getSystemStorage( IN_ENUM( SYSTEM_STORAGE ) \
							const SYSTEM_STORAGE_TYPE storageType );
#ifndef NDEBUG
int getSystemStorageSize( IN_ENUM( SYSTEM_STORAGE ) \
							const SYSTEM_STORAGE_TYPE storageType );
#endif /* !NDEBUG */
CHECK_RETVAL_PTR \
void *getBuiltinObjectStorage( IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE type,
							   IN_ENUM( SUBTYPE ) const OBJECT_SUBTYPE subType,
							   IN_LENGTH_MIN( 32 ) const int size );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int releaseBuiltinObjectStorage( IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE type,
								 IN_ENUM( SUBTYPE ) const OBJECT_SUBTYPE subType,
								 const void *address );
#ifndef NDEBUG
int getBuiltinObjectStorageSize( IN_ENUM( OBJECT_TYPE ) \
									const OBJECT_TYPE type,
								 IN_ENUM( SUBTYPE ) \
									const OBJECT_SUBTYPE subType,
								 IN_LENGTH_MIN( 32 ) const int size );
#endif /* !NDEBUG */

/* Init/shutdown functions for each kernel module */

CHECK_RETVAL \
int initAllocation( void );
void endAllocation( void );
CHECK_RETVAL \
int initAttributeACL( void );
void endAttributeACL( void );
#if defined( USE_CERTIFICATES ) && defined( USE_KEYSETS )
CHECK_RETVAL \
int initCertMgmtACL( void );
void endCertMgmtACL( void );
#else
  #define initCertMgmtACL()		CRYPT_OK
  #define endCertMgmtACL()
#endif /* USE_CERTIFICATES && USE_KEYSETS */
CHECK_RETVAL \
int initInternalMsgs( void );
void endInternalMsgs( void );
#ifdef USE_KEYSETS
CHECK_RETVAL \
int initKeymgmtACL( void );
void endKeymgmtACL( void );
#else
  #define initKeymgmtACL()		CRYPT_OK
  #define endKeymgmtACL()
#endif /* USE_KEYSETS */
CHECK_RETVAL \
int initMechanismACL( void );
void endMechanismACL( void );
CHECK_RETVAL \
int initMessageACL( void );
void endMessageACL( void );
CHECK_RETVAL \
int initObjects( void );
void endObjects( void );
CHECK_RETVAL \
int initObjectAltAccess( void );
void endObjectAltAccess( void );
CHECK_RETVAL \
int initSemaphores( void );
void endSemaphores( void );
CHECK_RETVAL \
int initSendMessage( void );
void endSendMessage( void );

#endif /* _KERNEL_DEFINED */
