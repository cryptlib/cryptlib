<<<<<<< HEAD
/****************************************************************************
*																			*
*							Kernel Object Management						*
*						Copyright Peter Gutmann 1997-2019					*
*																			*
****************************************************************************/

#include "crypt.h"
#if defined( INC_ALL )
  #include "acl.h"
  #include "kernel.h"
  #include "kernelfns.h"
#else
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
  #include "kernel/kernelfns.h"
#endif /* Compiler-specific includes */

/* Define the following to use fixed (deterministic) object handles.  This
   orders object handles sequentially, making it easier to pin down 
   approximately where/when a leftover objects was created, as well as
   ensuring that handles have consistent values across runs */

/* #define USE_FIXED_OBJECTHANDLES */

/* A template used to initialise object table entries.  Some of the entries
   are either object handles that have to be set to CRYPT_ERROR or values
   for which 0 is significant (so they're set to CRYPT_UNUSED), because of
   this we can't just memset the entry to all zeroes */

static const OBJECT_INFO OBJECT_INFO_TEMPLATE = {
	OBJECT_TYPE_NONE, SUBTYPE_NONE,	/* Type, subtype */
	DATAPTR_INIT, 0,			/* Object data and size */
	SAFE_FLAGS_INIT( OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED ),	
								/* Flags */
	0,							/* Action flags */
	1, 0, 0,					/* Int.and ext. ref.counts, lock count */
#ifdef USE_THREADS
	THREAD_INITIALISER,			/* Lock owner */
#endif /* USE_THREADS */
	0,							/* Unique ID */
	CRYPT_UNUSED, CRYPT_UNUSED,	/* Forward count, usage count */
#ifdef USE_THREADS
	THREAD_INITIALISER,			/* Owner */
#endif /* USE_THREADS */
	FNPTR_INIT,					/* Message function */
	CRYPT_ERROR,				/* Owner */
	CRYPT_ERROR, CRYPT_ERROR	/* Dependent object/device */
	};

/* When we use the template to clear an object table entry we can't directly
   assign the template to the position that we want to clear because there
   may be padding bytes appended to the struct for alignment purposes.  What
   this means is that saying:

	objectTable[ index ] = OBJECT_INFO_TEMPLATE;

   will leave the padding bytes at the end of the struct untouched.  
   Technically this isn't really an issue because the bytes are effectively
   invisible, but it's somewhat ugly so we define a macro to carry out the
   assignment which uses a memcpy() of the sizeof struct, which includes the
   padding bytes */

#define CLEAR_TABLE_ENTRY( entry ) \
		memcpy( ( entry ), &OBJECT_INFO_TEMPLATE, sizeof( OBJECT_INFO ) )

/* LFSR parameters for selcting the next object handle */

#define LFSR_MASK				MAX_NO_OBJECTS
#if MAX_NO_OBJECTS == 16
  #define LFSRPOLY				0x13
#elif MAX_NO_OBJECTS == 32
  #define LFSRPOLY				0x25
#elif MAX_NO_OBJECTS == 64
  #define LFSRPOLY				0x43
#elif MAX_NO_OBJECTS == 128
  #define LFSRPOLY				0x83
#elif MAX_NO_OBJECTS == 256
  #define LFSRPOLY				0x11D
#elif MAX_NO_OBJECTS == 512
  #define LFSRPOLY				0x211
#elif MAX_NO_OBJECTS == 1024
  #define LFSRPOLY				0x409
#elif MAX_NO_OBJECTS == 2048
  #define LFSRPOLY				0x805
#elif MAX_NO_OBJECTS == 4096
  #define LFSRPOLY				0x1053
#elif MAX_NO_OBJECTS == 8192
  #define LFSRPOLY				0x201B
#elif MAX_NO_OBJECTS == 16384
  #define LFSRPOLY				0x402B
#elif MAX_NO_OBJECTS == 32768
  #define LFSRPOLY				0x8003L
#elif MAX_NO_OBJECTS == 65536
  #define LFSRPOLY				0x1002DL
  /* Further LFSR polynomials are 0x20009L, 0x40027L, 0x80027L, 0x100009L, 
     0x200005L, 0x400003L, ... */
#endif /* LFSR polynomial for object table size */

/* A template used to initialise the object allocation state data */

static const OBJECT_STATE_INFO OBJECT_STATE_INFO_TEMPLATE = {
	-1							/* Initial-1'th object handle */
	};

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* Create and destroy the object table.  The destroy process is handled in
   two stages, the first of which is called fairly early in the shutdown
   process to destroy any remaining objects, and the second which is called
   at the end of the shutdown when the kernel data is being deleted.  This
   is because some of the objects are tied to things like external devices,
   and deleting them at the end when everything else has been shut down
   isn't possible */

CHECK_RETVAL \
int initObjects( void )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	LOOP_INDEX i;
	int status;

	/* Perform a consistency check on various things that need to be set
	   up in a certain way for things to work properly */
	static_assert( MAX_NO_OBJECTS >= 16, "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.type == OBJECT_TYPE_NONE, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.subType == 0, \
					   "Object table param" );
	static_assert_opt( DATAPTR_GET( OBJECT_INFO_TEMPLATE.objectPtr ) == NULL, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.objectSize == 0, \
					   "Object table param" );
	static_assert_opt( CHECK_FLAGS( OBJECT_INFO_TEMPLATE.flags, \
									OBJECT_FLAG_NONE, OBJECT_FLAG_MAX ), \
					   "Object table param" );
	static_assert_opt( GET_FLAGS( OBJECT_INFO_TEMPLATE.flags, OBJECT_FLAG_MAX ) == \
							( OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED ), \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.actionFlags == 0, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.forwardCount == CRYPT_UNUSED, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.usageCount == CRYPT_UNUSED, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.owner == CRYPT_ERROR, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.dependentDevice == CRYPT_ERROR, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.dependentObject == CRYPT_ERROR, \
					   "Object table param" );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	static_assert( SYSTEM_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 3, \
				   "Object table param" );
	static_assert( DEFAULTUSER_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 2, \
				   "Object table param" );
	static_assert( CRYPTO_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 1, \
				   "Object table param" );
#else
	static_assert( SYSTEM_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 2, \
				   "Object table param" );
	static_assert( DEFAULTUSER_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 1, \
				   "Object table param" );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	/* Allocate and initialise the object table */
	LOOP_EXT( i = 0, i < MAX_NO_OBJECTS, i++, MAX_NO_OBJECTS + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, MAX_NO_OBJECTS - 1,
									 MAX_NO_OBJECTS + 1 ) );

		CLEAR_TABLE_ENTRY( &objectTable[ i ] );
		}
	ENSURES( LOOP_BOUND_OK );
	krnlData->objectStateInfo = OBJECT_STATE_INFO_TEMPLATE;

	/* Initialise object-related information.  This isn't strictly part of
	   the object table but is used to assign unique ID values to objects
	   within the table, since table entries (object handles) may be reused
	   as objects are destroyed and new ones created in their place */
	krnlData->objectUniqueID = 0;

	/* Initialize any data structures required to make the object table
	   thread-safe */
	MUTEX_CREATE( objectTable, status );
	if( cryptStatusError( status ) )
		retIntError();

	/* Postconditions */
	FORALL( i, 0, MAX_NO_OBJECTS, \
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );
	ENSURES( krnlData->objectStateInfo.objectHandle == SYSTEM_OBJECT_HANDLE - 1 );
	ENSURES( krnlData->objectUniqueID == 0 );

	return( CRYPT_OK );
	}

void endObjects( void )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );

	/* Hinc igitur effuge */
	MUTEX_LOCK( objectTable );
	zeroise( objectTable, sizeof( OBJECT_INFO ) * MAX_NO_OBJECTS );
	krnlData->objectUniqueID = 0;
	MUTEX_UNLOCK( objectTable );
	MUTEX_DESTROY( objectTable );
	krnlData = NULL;
	}

/****************************************************************************
*																			*
*							Object Table Management							*
*																			*
****************************************************************************/

/* Destroy an object's instance data and object table entry */

CHECK_RETVAL \
int destroyObjectData( IN_HANDLE const int objectHandle )
	{
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	OBJECT_INFO *objectInfoPtr;
	void *objectPtr;
	int status;

	/* Precondition: It's a valid object */
	REQUIRES( isValidObject( objectHandle ) );

	objectInfoPtr = &objectTable[ objectHandle ];
	REQUIRES( sanityCheckObject( objectInfoPtr ) );
	objectPtr = DATAPTR_GET( objectInfoPtr->objectPtr );

	/* Inner precondition: There's valid object data present */
	REQUIRES( objectPtr != NULL );
	REQUIRES( isBufsizeRangeNZ( objectInfoPtr->objectSize ) );

	/* Destroy the object's data and clear the object table entry */
	if( TEST_FLAG( objectInfoPtr->flags, OBJECT_FLAG_SECUREMALLOC ) )
		{
		status = krnlMemfree( &objectPtr );
		ENSURES( cryptStatusOK( status ) );
		}
	else
		{
		/* Mors ultima linea rerum est */
		REQUIRES( isIntegerRangeNZ( objectInfoPtr->objectSize ) ); 
		zeroise( objectPtr, objectInfoPtr->objectSize );
		if( TEST_FLAG( objectInfoPtr->flags, OBJECT_FLAG_STATICALLOC ) )
			{
			status = releaseBuiltinObjectStorage( objectInfoPtr->type,
												  objectInfoPtr->subType,
												  objectPtr );
			ENSURES( cryptStatusOK( status ) );
			}
		else
			clFree( "destroyObjectData", objectPtr );
		}
	CLEAR_TABLE_ENTRY( &objectTable[ objectHandle ] );

	return( CRYPT_OK );
	}

/* Destroy an object.  This is only called when cryptlib is shutting down,
   normally objects are destroyed directly in response to messages */

CHECK_RETVAL \
static int destroyObject( IN_HANDLE const int objectHandle )
	{
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	const OBJECT_INFO *objectInfoPtr;
	MESSAGE_FUNCTION messageFunction;

	/* Precondition: It's a valid object */
	REQUIRES( isValidObject( objectHandle ) );

	/* Get the object info and message function.  We don't throw an 
	   exception if there's a problem with recovering the message function
	   (although we do assert in debug mode) because there's not much that 
	   we can do for error recovery at this point, we just skip the object-
	   specific cleanup and go straight to the object cleanup */
	objectInfoPtr = &objectTable[ objectHandle ];
	REQUIRES( sanityCheckObject( objectInfoPtr ) );
	messageFunction = ( MESSAGE_FUNCTION ) \
					  FNPTR_GET( objectInfoPtr->messageFunction );

	/* If there's no object present at this position, just clear the entry 
	   (it should be cleared anyway) */
	if( objectInfoPtr->type == OBJECT_TYPE_NONE )
		{
		CLEAR_TABLE_ENTRY( &objectTable[ objectHandle ] );
		return( CRYPT_OK );
		}
	assert( messageFunction != NULL );

	/* Destroy the object and its object table entry */
	if( messageFunction != NULL )
		{
		void *objectPtr = DATAPTR_GET( objectInfoPtr->objectPtr );

		ENSURES( objectPtr != NULL );

		if( objectInfoPtr->type == OBJECT_TYPE_DEVICE )
			{
			MESSAGE_FUNCTION_EXTINFO messageExtInfo;

			/* Device objects are unlockable so we have to pass in extended 
			   information to handle this */
			initMessageExtInfo( &messageExtInfo, objectPtr );
			messageFunction( &messageExtInfo, MESSAGE_DESTROY, NULL, 0 );
			}
		else
			{
			messageFunction( objectPtr, MESSAGE_DESTROY, NULL, 0 );
			}
		}
	return( destroyObjectData( objectHandle ) );
	}

/* Destroy all objects at a given nesting level */

CHECK_RETVAL \
static int destroySelectedObjects( IN_RANGE( 1, 3 ) const int currentDepth )
	{
	const OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	LOOP_INDEX objectHandle;
	int status = CRYPT_OK;

	/* Enter with the object table mutex held */

	/* Preconditions: We're destroying objects at a fixed depth */
	REQUIRES( currentDepth >= 1 && currentDepth <= 3 );

	LOOP_EXT( objectHandle = NO_SYSTEM_OBJECTS,
			  objectHandle < MAX_NO_OBJECTS,
			  objectHandle++, MAX_NO_OBJECTS + 1 )
		{
		int dependentObject, depth = 1;

		ENSURES( LOOP_INVARIANT_EXT( objectHandle, NO_SYSTEM_OBJECTS, \
									 MAX_NO_OBJECTS - 1,
									 MAX_NO_OBJECTS + 1 ) );

		/* If there's nothing there, continue.  In this case we don't 
		   perform a REQUIRES( DATAPTR_VALID() ) because we don't want a 
		   single corrupted pointer to prevent the cleanup of the entire 
		   object table */
		if( !DATAPTR_ISSET( objectTable[ objectHandle ].objectPtr ) )
			continue;

		/* There's an object still present, determine its nesting depth.
		   Dependent devices are terminal so we only follow the path down for
		   dependent objects */
		dependentObject = objectTable[ objectHandle ].dependentObject;
		if( isValidObject( dependentObject ) )
			{
			if( isValidObject( objectTable[ dependentObject ].dependentObject ) )
				depth = 3;
			else
				{
				if( isValidObject( objectTable[ dependentObject ].dependentDevice ) )
					depth = 2;
				}
			}
		else
			{
			if( isValidObject( objectTable[ objectHandle ].dependentDevice ) )
				depth = 2;
			}

		/* If the nesting level of the object matches the current level,
		   destroy it.  We unlock the object table around the access to
		   prevent remaining active objects from blocking the shutdown (the
		   activation of krnlIsExiting() takes care of any other messages 
		   that may arrive during this process).

		   "For death is come up into our windows, and it is entered into
		    our palaces, to cut off the children from the without"
			-- Jeremiah 9:21 */
		if( depth >= currentDepth )
			{
			KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );

			DEBUG_DIAG(( "Destroying leftover %s, ID = %d", 
						 getObjectDescriptionNT( objectHandle ),
						 objectTable[ objectHandle ].uniqueID ));
			objectTable = NULL;
			MUTEX_UNLOCK( objectTable );
			krnlSendNotifier( objectHandle, IMESSAGE_DESTROY );
			status = CRYPT_ERROR_INCOMPLETE;
			MUTEX_LOCK( objectTable );
			objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( objectHandle <= MAX_NO_OBJECTS );

	/* Exit with the object table mutex held */
	return( status );
	}

/* Destroy all objects (homini necesse est mori) */

CHECK_RETVAL \
int destroyObjects( void )
	{
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	LOOP_INDEX objectHandle;
	int depth, localStatus, status DUMMY_INIT;

	/* Preconditions: We either didn't complete the initialisation and are 
	   shutting down during a krnlBeginInit(), or we've completed 
	   initialisation and are shutting down after a krnlBeginShutdown() */
	REQUIRES( ( krnlData->initLevel == INIT_LEVEL_KRNLDATA && \
				krnlData->shutdownLevel == SHUTDOWN_LEVEL_NONE ) || \
			  ( krnlData->initLevel == INIT_LEVEL_KRNLDATA && \
				krnlData->shutdownLevel == SHUTDOWN_LEVEL_THREADS ) );

	/* Indicate that we're shutting down the object handling.  From now on
	   all messages other than object-destruction ones will be rejected by
	   the kernel.  This is needed in order to have any remaining active
	   objects exit quickly, since we don't want them to block the shutdown.
	   Note that we do this before we lock the object table to encourage
	   anything that might have the table locked to exit quickly once we try
	   and lock the table */
	krnlData->shutdownLevel = SHUTDOWN_LEVEL_MESSAGES;

	/* Lock the object table to ensure that other threads don't try to
	   access it */
	MUTEX_LOCK( objectTable );

	/* Destroy all system objects except the root system object ("The death
	   of God left the angels in a strange position" - Donald Barthelme, "On
	   Angels").  We have to do this before we destroy any unclaimed
	   leftover objects because some of them may depend on system objects,
	   if the system objects aren't destroyed they'll be erroneously flagged
	   as leftover objects.  The destruction is done explicitly by invoking
	   the object's message function directly because the message dispatcher
	   checks to make sure that they're never destroyed through a standard
	   message, which would indicate a programming error */
	LOOP_SMALL( objectHandle = SYSTEM_OBJECT_HANDLE + 1,
				objectHandle < NO_SYSTEM_OBJECTS, objectHandle++ )
		{
		ENSURES_MUTEX( LOOP_INVARIANT_SMALL( objectHandle, \
											 SYSTEM_OBJECT_HANDLE + 1, \
											 NO_SYSTEM_OBJECTS - 1 ),
					   objectTable );

		/* In the extremely unlikely event that we encounter an error during 
		   the creation of the system object, no other objects will have been 
		   created, so before we try and destroy an object we make sure that 
		   it's actually been created */
		if( !isValidObject( objectHandle ) )
			continue;

		status = destroyObject( objectHandle );
		ENSURES_MUTEX( cryptStatusOK( status ), objectTable );
		}
	ENSURES_MUTEX( LOOP_BOUND_OK, objectTable );

	/* Postcondition: All system objects except the root system object have
	   been destroyed */
	FORALL( i, SYSTEM_OBJECT_HANDLE + 1, NO_SYSTEM_OBJECTS,
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );

	/* Delete any unclaimed leftover objects.  This is rather more complex
	   than just rumbling through deleting each object we find since some
	   objects have dependent objects underneath them, and deleting the
	   lower-level object causes problems when we later delete their parents
	   (the code handles it cleanly, but we get a kernel trap warning us that
	   we're trying to delete a non-present object).  Because of this we have
	   to delete the objects in order of depth, first all three-level objects
	   (e.g. cert -> context -> device), then all two-level objects, and
	   finally all one-level objects.  This means that we can never delete
	   another object out from under a dependent object */
	LOOP_SMALL_REV( depth = 3, depth > 0, depth-- )
		{
		ENSURES_MUTEX( LOOP_INVARIANT_REV( depth, 1, 3 ), objectTable );

		localStatus = destroySelectedObjects( depth );
		if( cryptStatusError( localStatus ) )
			status = localStatus;
		}
	ENSURES_MUTEX( LOOP_BOUND_SMALL_REV_OK, objectTable );

	/* Postcondition: All objects except the root system object have been
	   destroyed */
	FORALL( i, SYSTEM_OBJECT_HANDLE + 1, MAX_NO_OBJECTS, \
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );

	/* Finally, destroy the system root object.  We need to preserve the 
	   possible error status from cleaning up any leftover objects so we use 
	   a local status value to get the destroy-object results */
	localStatus = destroyObject( SYSTEM_OBJECT_HANDLE );
	ENSURES_MUTEX( cryptStatusOK( localStatus ), objectTable );

	/* Unlock the object table to allow access by other threads */
	MUTEX_UNLOCK( objectTable );

	return( status );
	}

/****************************************************************************
*																			*
*							Object Creation/Destruction						*
*																			*
****************************************************************************/

/* Create a new object.  This function has to be very careful about locking
   to ensure that another thread can't manipulate the newly-created object
   while it's in an indeterminate state.  To accomplish this it locks the
   object table and tries to create the new object.  If this succeeds it sets
   the OBJECT_FLAG_NOTINITED flag pending completion of the object's
   initialisation by the caller, unlocks the object table, and returns
   control to the caller.  While the object is in this state, the kernel
   will allow it to process only two message types, either a notification
   from the caller that the init stage is complete (which sets the object's
   state to OK), or a destroy object message, which sets the
   OBJECT_FLAG_SIGNALLED flag pending arrival of the init complete
   notification, whereupon the object is immediately destroyed.  The state
   diagram for this is:
									 State
						  Notinited			Signalled
			--------+-------------------+-----------------
			-> OK	| state -> OK,		| Msg -> Destroy
					| ret( OK )			|
	Msg.	Destroy	| state -> Sig'd,	| state -> Sig'd,
					| ret( OK )			| ret( OK )
			CtrlMsg	| process as usual	| process as usual
			NonCtrl	| ret( Notinited )	| ret( Sig'd )

   The initialisation process for an object is therefore:

	status = krnlCreateObject( ... );
	if( cryptStatusError( status ) )
		return( status );

	// Complete object-specific initialisation
	initStatus = ...;

	status = krnlSendMessage( ..., state -> CRYPT_OK );
	return( ( cryptStatusError( initStatus ) ? initStatus : status );

   If the object is destroyed during the object-specific initialisation
   (either by the init code when an error is encountered or due to an
   external signal), the destroy is deferred until the change state message
   at the end occurs.  If a destroy is pending, the change state is converted
   to a destroy and the newly-created object is destroyed.

   This mechanism ensures that the object table is only locked for a very
   short time (typically for only a few lines of executed code in the create
   object function) so that slow initialisation (for example of keyset
   objects associated with network links) can't block other objects.

   In addition to the locking, we need to be careful with how we create new
   objects because if we just allocate handles sequentially and reuse handles
   as soon as possible, an existing object could be signalled and a new one
   created in its place without the caller or owning object realizing that
   they're now working with a different object (although the kernel can tell
   them apart because it maintains an internal unique ID for each object).
   Unix systems handle this by always incrementing pids and assuming that
   there won't be any problems when they wrap, we do the same thing but in
   addition allocate handles in a non-sequential manner using an LFSR to
   step through the object table.  There's no strong reason for this apart
   from helping disabuse users of the notion that any cryptlib objects have
   stdin/stdout-style fixed handles, but it only costs a few extra clocks so
   we may as well do it.
   
   There is one case in which we can still get handle reuse and that's then 
   the object table is heavily loaded but not quite enough to trigger a 
   resize.  For example with a table of size 1024 if the caller creates 1023
   objects and then repeatedly creates and destroys a final object it'll 
   always be reassigned the same handle if no other objects are destroyed in
   the meantime.  This is rather unlikely unless the caller is using 
   individual low-level objects (all of the high-level objects create 
   object-table churn through their dependent objects) so it's not worth
   adding special-case handling for it */

CHECK_RETVAL_RANGE( NO_SYSTEM_OBJECTS, MAX_NO_OBJECTS ) \
static int findFreeObjectEntry( int value )
	{
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	BOOLEAN freeEntryAvailable = FALSE;
	LOOP_INDEX iterations;
	int oldValue = value;

	/* Preconditions: We're starting with a valid object handle, and it's not
	   a system object */
	REQUIRES( isValidHandle( value ) && value >= NO_SYSTEM_OBJECTS );

	/* Step through the entire table looking for a free entry */
	LOOP_EXT( iterations = 0, 
			  isValidHandle( value ) && iterations < MAX_NO_OBJECTS, 
			  iterations++, MAX_NO_OBJECTS + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( iterations, 0, MAX_NO_OBJECTS - 1,
									 MAX_NO_OBJECTS + 1 ) );

		/* Get the next value: Multiply by x and reduce by the polynomial */
#ifdef USE_FIXED_OBJECTHANDLES
		value++;
#else
		value <<= 1;
		if( value & LFSR_MASK )
			value ^= LFSRPOLY;
#endif /* USE_FIXED_OBJECTHANDLES */

		/* Invariant: We're still within the object table */
		ENSURES( isValidHandle( value ) );

		/* If we've found a free object or we've covered the entire table,
		   exit.  We do this check after we update the value rather than as
		   part of the loop test to ensure that we always progress to a new
		   object handle whenever we call this function.  If we did the
		   check as part of the loop test then deleting and creating an
		   object would result in the handle of the deleted object being
		   re-assigned to the new object */
		if( isFreeObject( value ) )
			{
			/* We've found a free entry, we're done */
			freeEntryAvailable = TRUE;
			break;
			}
		if( value == oldValue )
			{
			/* We've covered the entire object table, there's no room for
			   further objects */
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( iterations < MAX_NO_OBJECTS )

	/* Postcondition: We're still within the object table */
	ENSURES( isValidHandle( value ) );

	/* If we didn't find a free entry, tell the caller that the tank is 
	   full */
	if( !freeEntryAvailable )
		{
		/* Postcondition: We tried all locations and there are no free slots
		   available (or, vastly less likely, an internal error has
		   occurred) */
		ENSURES( iterations == MAX_NO_OBJECTS - 2 );
		FORALL( i, 0, MAX_NO_OBJECTS, \
				!isFreeObject( i ) );

		return( CRYPT_ERROR_OVERFLOW );
		}

	/* Postconditions: We found a handle to a free slot */
	REQUIRES( isValidHandle( value ) && value >= NO_SYSTEM_OBJECTS );
	ENSURES( isFreeObject( value ) );

	return( value );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 9 ) ) \
int krnlCreateObject( OUT_HANDLE_OPT int *objectHandle,
					  OUT_BUFFER_ALLOC_OPT( objectDataSize ) void **objectDataPtr, 
					  IN_LENGTH_SHORT const int objectDataSize,
					  IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE type, 
					  IN_ENUM( SUBTYPE ) const OBJECT_SUBTYPE subType,
					  IN_FLAGS_Z( CREATEOBJECT ) const int createObjectFlags, 
					  IN_HANDLE_OPT const CRYPT_USER owner,
					  IN_FLAGS_Z( ACTION_PERM ) const int actionFlags,
					  IN_PTR MESSAGE_FUNCTION messageFunction )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	OBJECT_INFO objectInfo;
	OBJECT_STATE_INFO *objectStateInfo = &krnlData->objectStateInfo;
	OBJECT_SUBTYPE bitCount;
	BOOLEAN isStaticAlloc = FALSE;
	int localObjectHandle, status = CRYPT_OK;

	assert( isWritePtr( krnlData, sizeof( KERNEL_DATA ) ) );
	assert( isWritePtr( objectDataPtr, sizeof( void * ) ) );

	/* Preconditions (the subType check is just the standard hakmem bitcount
	   which ensures that we don't try and create multi-typed objects, the
	   sole exception to this rule is the default user object, which acts as
	   both a user and an SO object) */
	REQUIRES( objectDataSize > 16 && \
			  ( ( !( type == OBJECT_TYPE_CONTEXT && subType == SUBTYPE_CTX_PKC ) && \
				objectDataSize < MAX_INTLENGTH_SHORT ) || \
			  ( type == OBJECT_TYPE_CONTEXT && subType == SUBTYPE_CTX_PKC && \
				objectDataSize < MAX_INTLENGTH ) ) );
	REQUIRES( isValidType( type ) );
	REQUIRES( subType > SUBTYPE_NONE && subType <= SUBTYPE_LAST );
	REQUIRES( \
		( bitCount = ( subType & ~SUBTYPE_CLASS_MASK ) - \
					 ( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 1 ) & 033333333333L ) - \
					 ( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 2 ) & 011111111111L ) ) != 0 );
	REQUIRES( ( ( bitCount + ( bitCount >> 3 ) ) & 030707070707L ) % 63 == 1 );
	REQUIRES( createObjectFlags == CREATEOBJECT_FLAG_NONE || \
			  createObjectFlags == CREATEOBJECT_FLAG_SECUREMALLOC );
	REQUIRES( owner == CRYPT_UNUSED || isValidHandle( owner ) );
	REQUIRES( isFlagRangeZ( actionFlags, ACTION_PERM ) );
	REQUIRES( messageFunction != NULL );

	/* Clear return values */
	*objectHandle = CRYPT_ERROR;
	*objectDataPtr = NULL;

	/* If we haven't been initialised yet or we're in the middle of a
	   shutdown, we can't create any new objects */
	if( !isWritePtr( krnlData, sizeof( KERNEL_DATA ) ) || \
		krnlData->initLevel <= INIT_LEVEL_NONE )
		return( CRYPT_ERROR_NOTINITED );
	if( krnlData->shutdownLevel >= SHUTDOWN_LEVEL_MESSAGES )
		{
		DEBUG_DIAG(( "Can't create new objects during a shutdown" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Allocate memory for the object and set up as much as we can of the 
	   object table entry (the remainder has to be set up inside the object-
	   table lock).  The object is always created as an internal object, 
	   it's up to the caller to make it externally visible.
	   
	   The apparently redundant clearning of objectInfo before overwriting
	   it with the object-info template is due to yet another gcc bug, in
	   this case in the x64 debug (-o0) build, for which it doesn't memcpy()
	   the template across but sets each field individually, leaving 
	   whatever padding bytes were present beforehand set to random values */
	if( objectStateInfo->objectHandle < NO_SYSTEM_OBJECTS - 1 )
		{
		/* This is either the system object or the default user object or, 
		   if a distinct crypto hardware device is being used, the crypto
		   hardware object.
		   
		   The reason for checking for one less than the value is that it's
		   incremented on assignement, so at this point it's one less than 
		   the final value */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		REQUIRES( ( type == OBJECT_TYPE_DEVICE && \
					subType == SUBTYPE_DEV_SYSTEM && \
					owner == CRYPT_UNUSED && \
					objectStateInfo->objectHandle == SYSTEM_OBJECT_HANDLE - 1 ) || \
				  ( type == OBJECT_TYPE_USER && \
				    subType == SUBTYPE_USER_SO && \
					owner == SYSTEM_OBJECT_HANDLE && \
					objectStateInfo->objectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 ) || \
				  ( type == OBJECT_TYPE_DEVICE && \
					subType == SUBTYPE_DEV_HARDWARE && \
					owner == DEFAULTUSER_OBJECT_HANDLE && \
					objectStateInfo->objectHandle != SYSTEM_OBJECT_HANDLE - 1 && \
					objectStateInfo->objectHandle != DEFAULTUSER_OBJECT_HANDLE - 1 ) );
#else
		REQUIRES( ( type == OBJECT_TYPE_DEVICE && \
					subType == SUBTYPE_DEV_SYSTEM && \
					owner == CRYPT_UNUSED && \
					objectStateInfo->objectHandle == SYSTEM_OBJECT_HANDLE - 1 ) || \
				  ( type == OBJECT_TYPE_USER && \
				    subType == SUBTYPE_USER_SO && \
					owner == SYSTEM_OBJECT_HANDLE && \
					objectStateInfo->objectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

		MUTEX_LOCK( allocation );
		*objectDataPtr = getBuiltinObjectStorage( type, subType, 
												  objectDataSize );
		MUTEX_UNLOCK( allocation );
		ENSURES( *objectDataPtr != NULL );
		isStaticAlloc = TRUE;
		}
	else
		{
		/* Nothing should be creating system objects at this point */
		REQUIRES( subType != SUBTYPE_DEV_SYSTEM && \
				  subType != SUBTYPE_USER_SO );

		/* If it's a keyset or context then we may be able to use a built-in 
		   storage block for it */
		if( type == OBJECT_TYPE_KEYSET || type == OBJECT_TYPE_CONTEXT )
			{
			void *storagePtr;
			
			MUTEX_LOCK( allocation );
			storagePtr = getBuiltinObjectStorage( type, subType,
												  objectDataSize );
			MUTEX_UNLOCK( allocation );
			if( storagePtr != NULL )
				{
				*objectDataPtr = storagePtr;
				isStaticAlloc = TRUE;
				}
			}
		}
	if( !isStaticAlloc )
		{
		/* The object isn't using built-in storage, allocate it dynamically
		   as required */
		if( createObjectFlags & CREATEOBJECT_FLAG_SECUREMALLOC )
			{
			status = krnlMemalloc( objectDataPtr, objectDataSize );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			{
			REQUIRES( isIntegerRangeNZ( objectDataSize ) );
			if( ( *objectDataPtr = clAlloc( "krnlCreateObject", \
											objectDataSize ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			}
		}
	assert( isWritePtrDynamic( *objectDataPtr, objectDataSize ) );
	memset( &objectInfo, 0, sizeof( OBJECT_INFO ) ); /* See comment above */
	objectInfo = OBJECT_INFO_TEMPLATE;
	REQUIRES( isIntegerRangeNZ( objectDataSize ) ); 
	memset( *objectDataPtr, 0, objectDataSize );
	DATAPTR_SET( objectInfo.objectPtr, *objectDataPtr );
	objectInfo.objectSize = objectDataSize;
	if( isStaticAlloc )
		SET_FLAG( objectInfo.flags, OBJECT_FLAG_STATICALLOC );
	else
		{
		if( createObjectFlags & CREATEOBJECT_FLAG_SECUREMALLOC )
			SET_FLAG( objectInfo.flags, OBJECT_FLAG_SECUREMALLOC );
		}
	objectInfo.owner = owner;
	objectInfo.type = type;
	objectInfo.subType = subType;
	objectInfo.actionFlags = actionFlags;
	FNPTR_SET( objectInfo.messageFunction, messageFunction );
	ENSURES( sanityCheckObject( &objectInfo ) );

	/* Make sure that the kernel has been initialised and lock the object
	   table for exclusive access */
	MUTEX_LOCK( initialisation );
	MUTEX_LOCK( objectTable );
	MUTEX_UNLOCK( initialisation );

	/* Finish setting up the object table entry with any remaining data */
	objectInfo.uniqueID = krnlData->objectUniqueID;

	/* The first objects created are internal objects with predefined
	   handles (spes lucis aeternae).  As we create these objects we ratchet
	   up through the fixed handles until we reach the last fixed object,
	   whereupon we allocate handles normally */
	localObjectHandle = objectStateInfo->objectHandle;
	if( localObjectHandle < NO_SYSTEM_OBJECTS - 1 )
		{
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		REQUIRES_MUTEX( ( type == OBJECT_TYPE_DEVICE && \
						  subType == SUBTYPE_DEV_SYSTEM && \
						  owner == CRYPT_UNUSED && \
						  localObjectHandle == SYSTEM_OBJECT_HANDLE - 1 ) || \
						( type == OBJECT_TYPE_USER && \
						  subType == SUBTYPE_USER_SO && \
						  owner == SYSTEM_OBJECT_HANDLE && \
						  localObjectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 ) || \
						( type == OBJECT_TYPE_DEVICE && \
						  subType == SUBTYPE_DEV_HARDWARE && \
						  owner == DEFAULTUSER_OBJECT_HANDLE && \
						  localObjectHandle == CRYPTO_OBJECT_HANDLE - 1 ),
						objectTable );
#else
		REQUIRES_MUTEX( ( type == OBJECT_TYPE_DEVICE && \
						  subType == SUBTYPE_DEV_SYSTEM && \
						  owner == CRYPT_UNUSED && \
						  localObjectHandle == SYSTEM_OBJECT_HANDLE - 1 ) || \
						( type == OBJECT_TYPE_USER && \
						  subType == SUBTYPE_USER_SO && \
						  owner == SYSTEM_OBJECT_HANDLE && \
						  localObjectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 ), 
						objectTable );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
		localObjectHandle++;
		ENSURES_MUTEX( isValidHandle( localObjectHandle ) && \
					   localObjectHandle < NO_SYSTEM_OBJECTS && \
					   localObjectHandle == objectStateInfo->objectHandle + 1, \
					   objectTable );
		}
	else
		{
		REQUIRES_MUTEX( isValidHandle( owner ), objectTable );

		/* Search the table for a free entry */
		status = localObjectHandle = findFreeObjectEntry( localObjectHandle );
		}


	/* If there's a problem with allocating a handle then it either means 
	   that we've run out of entries in the object table or there's a more 
	   general error */
	if( cryptStatusError( status ) )
		{
		void *objectPtr = DATAPTR_GET( objectInfo.objectPtr );

		MUTEX_UNLOCK( objectTable );

		ENSURES( objectPtr != NULL );

		/* Warn about the problem */
		DEBUG_DIAG_ERRMSG(( "Error %s allocating new handle for %s object", 
							getStatusName( status ), 
							getObjectTypeDescriptionNT( type, subType ) ));
		assert( DEBUG_WARN );

		/* Free the object instance data storage that we allocated earlier 
		   and return the error status */
		if( TEST_FLAG( objectInfo.flags, OBJECT_FLAG_SECUREMALLOC ) )
			{
			int localStatus = krnlMemfree( &objectPtr );
			ENSURES( cryptStatusOK( localStatus ) );
			}
		else
			{
			REQUIRES( isIntegerRangeNZ( objectInfo.objectSize ) ); 
			zeroise( objectPtr, objectInfo.objectSize );
			if( !TEST_FLAG( objectInfo.flags, OBJECT_FLAG_STATICALLOC ) ) 
				clFree( "destroyObjectData", objectPtr );
			}
		zeroise( &objectInfo, sizeof( OBJECT_INFO ) );

		return( status );
		}

	/* Inner precondition: This object table slot is free */
	REQUIRES_MUTEX( isFreeObject( localObjectHandle ), objectTable );

	/* Set up the new object entry in the table and update the object table
	   state */
	objectTable[ localObjectHandle ] = objectInfo;
	if( localObjectHandle == NO_SYSTEM_OBJECTS - 1 )
		{
		time_t theTime;

		/* We've set up all of the objects that have fixed handles, from now 
		   on we're using dynamically assigned handled.  To start this 
		   process we get a non-constant seed to use for the initial object 
		   handle.  See the comment in findFreeObjectEntry() for why this is 
		   done, and why it only uses a relatively weak seed.  
		   
		   Since we may be running on an embedded system with no reliable 
		   time source available we use GETTIME_NOFAIL rather than 
		   GETTIME_NONE, the check for correct functioning of the time 
		   source on non-embedded systems has already been done in the init 
		   code */
		theTime = getTime( GETTIME_NOFAIL );

		/* From now on we start allocating handles starting from a 
		   randomised location in the table */
#ifndef USE_FIXED_OBJECTHANDLES
		objectStateInfo->objectHandle = \
				( int ) theTime & ( LFSR_MASK - 1 );
#endif /* USE_FIXED_OBJECTHANDLES */
		if( objectStateInfo->objectHandle < NO_SYSTEM_OBJECTS )
			{
			/* Can occur with probability
			   NO_SYSTEM_OBJECTS / MAX_NO_OBJECTS */
			objectStateInfo->objectHandle = NO_SYSTEM_OBJECTS + 42;
			}
		}
	else
		objectStateInfo->objectHandle = localObjectHandle;

	/* Update the object unique ID value */
	if( krnlData->objectUniqueID < 0 || \
		krnlData->objectUniqueID >= INT_MAX - 1 )
		krnlData->objectUniqueID = NO_SYSTEM_OBJECTS;
	else
		krnlData->objectUniqueID++;
	ENSURES_MUTEX( krnlData->objectUniqueID > 0 && \
				   krnlData->objectUniqueID < INT_MAX, objectTable );

	/* Postconditions: It's a valid object that's been set up as required */
	ENSURES_MUTEX( isValidObject( localObjectHandle ), objectTable );
	ENSURES_MUTEX( DATAPTR_GET( objectInfo.objectPtr ) == *objectDataPtr, objectTable );
	ENSURES_MUTEX( objectInfo.owner == owner, objectTable );
	ENSURES_MUTEX( objectInfo.type == type, objectTable );
	ENSURES_MUTEX( objectInfo.subType == subType, objectTable );
	ENSURES_MUTEX( objectInfo.actionFlags == actionFlags, objectTable );
	ENSURES_MUTEX( FNPTR_ISSET( objectInfo.messageFunction ), 
				   objectTable );

	/* Report what's just been created, useful for determining where 
	   leftover objects are coming from.  We only enable this when tracking 
	   down leaks since it otherwise creates a huge amount of noise */
#if 0
	DEBUG_DIAG(( "Created %s, ID = %d", 
				 getObjectDescriptionNT( localObjectHandle ),
				 objectInfo.uniqueID ));
#endif /* 0 */

	MUTEX_UNLOCK( objectTable );

	*objectHandle = localObjectHandle;

	return( CRYPT_OK );
	}
=======
/****************************************************************************
*																			*
*							Kernel Object Management						*
*						Copyright Peter Gutmann 1997-2019					*
*																			*
****************************************************************************/

#include "crypt.h"
#if defined( INC_ALL )
  #include "acl.h"
  #include "kernel.h"
  #include "kernelfns.h"
#else
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
  #include "kernel/kernelfns.h"
#endif /* Compiler-specific includes */

/* Define the following to use fixed (deterministic) object handles.  This
   orders object handles sequentially, making it easier to pin down 
   approximately where/when a leftover objects was created, as well as
   ensuring that handles have consistent values across runs */

/* #define USE_FIXED_OBJECTHANDLES */

/* A template used to initialise object table entries.  Some of the entries
   are either object handles that have to be set to CRYPT_ERROR or values
   for which 0 is significant (so they're set to CRYPT_UNUSED), because of
   this we can't just memset the entry to all zeroes */

static const OBJECT_INFO OBJECT_INFO_TEMPLATE = {
	OBJECT_TYPE_NONE, SUBTYPE_NONE,	/* Type, subtype */
	DATAPTR_INIT, 0,			/* Object data and size */
	SAFE_FLAGS_INIT( OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED ),	
								/* Flags */
	0,							/* Action flags */
	1, 0, 0,					/* Int.and ext. ref.counts, lock count */
#ifdef USE_THREADS
	THREAD_INITIALISER,			/* Lock owner */
#endif /* USE_THREADS */
	0,							/* Unique ID */
	CRYPT_UNUSED, CRYPT_UNUSED,	/* Forward count, usage count */
#ifdef USE_THREADS
	THREAD_INITIALISER,			/* Owner */
#endif /* USE_THREADS */
	FNPTR_INIT,					/* Message function */
	CRYPT_ERROR,				/* Owner */
	CRYPT_ERROR, CRYPT_ERROR	/* Dependent object/device */
	};

/* When we use the template to clear an object table entry we can't directly
   assign the template to the position that we want to clear because there
   may be padding bytes appended to the struct for alignment purposes.  What
   this means is that saying:

	objectTable[ index ] = OBJECT_INFO_TEMPLATE;

   will leave the padding bytes at the end of the struct untouched.  
   Technically this isn't really an issue because the bytes are effectively
   invisible, but it's somewhat ugly so we define a macro to carry out the
   assignment which uses a memcpy() of the sizeof struct, which includes the
   padding bytes */

#define CLEAR_TABLE_ENTRY( entry ) \
		memcpy( ( entry ), &OBJECT_INFO_TEMPLATE, sizeof( OBJECT_INFO ) )

/* LFSR parameters for selcting the next object handle */

#define LFSR_MASK				MAX_NO_OBJECTS
#if MAX_NO_OBJECTS == 16
  #define LFSRPOLY				0x13
#elif MAX_NO_OBJECTS == 32
  #define LFSRPOLY				0x25
#elif MAX_NO_OBJECTS == 64
  #define LFSRPOLY				0x43
#elif MAX_NO_OBJECTS == 128
  #define LFSRPOLY				0x83
#elif MAX_NO_OBJECTS == 256
  #define LFSRPOLY				0x11D
#elif MAX_NO_OBJECTS == 512
  #define LFSRPOLY				0x211
#elif MAX_NO_OBJECTS == 1024
  #define LFSRPOLY				0x409
#elif MAX_NO_OBJECTS == 2048
  #define LFSRPOLY				0x805
#elif MAX_NO_OBJECTS == 4096
  #define LFSRPOLY				0x1053
#elif MAX_NO_OBJECTS == 8192
  #define LFSRPOLY				0x201B
#elif MAX_NO_OBJECTS == 16384
  #define LFSRPOLY				0x402B
#elif MAX_NO_OBJECTS == 32768
  #define LFSRPOLY				0x8003L
#elif MAX_NO_OBJECTS == 65536
  #define LFSRPOLY				0x1002DL
  /* Further LFSR polynomials are 0x20009L, 0x40027L, 0x80027L, 0x100009L, 
     0x200005L, 0x400003L, ... */
#endif /* LFSR polynomial for object table size */

/* A template used to initialise the object allocation state data */

static const OBJECT_STATE_INFO OBJECT_STATE_INFO_TEMPLATE = {
	-1							/* Initial-1'th object handle */
	};

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* Create and destroy the object table.  The destroy process is handled in
   two stages, the first of which is called fairly early in the shutdown
   process to destroy any remaining objects, and the second which is called
   at the end of the shutdown when the kernel data is being deleted.  This
   is because some of the objects are tied to things like external devices,
   and deleting them at the end when everything else has been shut down
   isn't possible */

CHECK_RETVAL \
int initObjects( void )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	LOOP_INDEX i;
	int status;

	/* Perform a consistency check on various things that need to be set
	   up in a certain way for things to work properly */
	static_assert( MAX_NO_OBJECTS >= 16, "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.type == OBJECT_TYPE_NONE, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.subType == 0, \
					   "Object table param" );
	static_assert_opt( DATAPTR_GET( OBJECT_INFO_TEMPLATE.objectPtr ) == NULL, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.objectSize == 0, \
					   "Object table param" );
	static_assert_opt( CHECK_FLAGS( OBJECT_INFO_TEMPLATE.flags, \
									OBJECT_FLAG_NONE, OBJECT_FLAG_MAX ), \
					   "Object table param" );
	static_assert_opt( GET_FLAGS( OBJECT_INFO_TEMPLATE.flags, OBJECT_FLAG_MAX ) == \
							( OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED ), \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.actionFlags == 0, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.forwardCount == CRYPT_UNUSED, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.usageCount == CRYPT_UNUSED, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.owner == CRYPT_ERROR, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.dependentDevice == CRYPT_ERROR, \
					   "Object table param" );
	static_assert_opt( OBJECT_INFO_TEMPLATE.dependentObject == CRYPT_ERROR, \
					   "Object table param" );
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	static_assert( SYSTEM_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 3, \
				   "Object table param" );
	static_assert( DEFAULTUSER_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 2, \
				   "Object table param" );
	static_assert( CRYPTO_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 1, \
				   "Object table param" );
#else
	static_assert( SYSTEM_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 2, \
				   "Object table param" );
	static_assert( DEFAULTUSER_OBJECT_HANDLE == NO_SYSTEM_OBJECTS - 1, \
				   "Object table param" );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

	/* Allocate and initialise the object table */
	LOOP_EXT( i = 0, i < MAX_NO_OBJECTS, i++, MAX_NO_OBJECTS + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, MAX_NO_OBJECTS - 1,
									 MAX_NO_OBJECTS + 1 ) );

		CLEAR_TABLE_ENTRY( &objectTable[ i ] );
		}
	ENSURES( LOOP_BOUND_OK );
	krnlData->objectStateInfo = OBJECT_STATE_INFO_TEMPLATE;

	/* Initialise object-related information.  This isn't strictly part of
	   the object table but is used to assign unique ID values to objects
	   within the table, since table entries (object handles) may be reused
	   as objects are destroyed and new ones created in their place */
	krnlData->objectUniqueID = 0;

	/* Initialize any data structures required to make the object table
	   thread-safe */
	MUTEX_CREATE( objectTable, status );
	if( cryptStatusError( status ) )
		retIntError();

	/* Postconditions */
	FORALL( i, 0, MAX_NO_OBJECTS, \
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );
	ENSURES( krnlData->objectStateInfo.objectHandle == SYSTEM_OBJECT_HANDLE - 1 );
	ENSURES( krnlData->objectUniqueID == 0 );

	return( CRYPT_OK );
	}

void endObjects( void )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );

	/* Hinc igitur effuge */
	MUTEX_LOCK( objectTable );
	zeroise( objectTable, sizeof( OBJECT_INFO ) * MAX_NO_OBJECTS );
	krnlData->objectUniqueID = 0;
	MUTEX_UNLOCK( objectTable );
	MUTEX_DESTROY( objectTable );
	krnlData = NULL;
	}

/****************************************************************************
*																			*
*							Object Table Management							*
*																			*
****************************************************************************/

/* Destroy an object's instance data and object table entry */

CHECK_RETVAL \
int destroyObjectData( IN_HANDLE const int objectHandle )
	{
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	OBJECT_INFO *objectInfoPtr;
	void *objectPtr;
	int status;

	/* Precondition: It's a valid object */
	REQUIRES( isValidObject( objectHandle ) );

	objectInfoPtr = &objectTable[ objectHandle ];
	REQUIRES( sanityCheckObject( objectInfoPtr ) );
	objectPtr = DATAPTR_GET( objectInfoPtr->objectPtr );

	/* Inner precondition: There's valid object data present */
	REQUIRES( objectPtr != NULL );
	REQUIRES( isBufsizeRangeNZ( objectInfoPtr->objectSize ) );

	/* Destroy the object's data and clear the object table entry */
	if( TEST_FLAG( objectInfoPtr->flags, OBJECT_FLAG_SECUREMALLOC ) )
		{
		status = krnlMemfree( &objectPtr );
		ENSURES( cryptStatusOK( status ) );
		}
	else
		{
		/* Mors ultima linea rerum est */
		REQUIRES( isIntegerRangeNZ( objectInfoPtr->objectSize ) ); 
		zeroise( objectPtr, objectInfoPtr->objectSize );
		if( TEST_FLAG( objectInfoPtr->flags, OBJECT_FLAG_STATICALLOC ) )
			{
			status = releaseBuiltinObjectStorage( objectInfoPtr->type,
												  objectInfoPtr->subType,
												  objectPtr );
			ENSURES( cryptStatusOK( status ) );
			}
		else
			clFree( "destroyObjectData", objectPtr );
		}
	CLEAR_TABLE_ENTRY( &objectTable[ objectHandle ] );

	return( CRYPT_OK );
	}

/* Destroy an object.  This is only called when cryptlib is shutting down,
   normally objects are destroyed directly in response to messages */

CHECK_RETVAL \
static int destroyObject( IN_HANDLE const int objectHandle )
	{
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	const OBJECT_INFO *objectInfoPtr;
	MESSAGE_FUNCTION messageFunction;

	/* Precondition: It's a valid object */
	REQUIRES( isValidObject( objectHandle ) );

	/* Get the object info and message function.  We don't throw an 
	   exception if there's a problem with recovering the message function
	   (although we do assert in debug mode) because there's not much that 
	   we can do for error recovery at this point, we just skip the object-
	   specific cleanup and go straight to the object cleanup */
	objectInfoPtr = &objectTable[ objectHandle ];
	REQUIRES( sanityCheckObject( objectInfoPtr ) );
	messageFunction = ( MESSAGE_FUNCTION ) \
					  FNPTR_GET( objectInfoPtr->messageFunction );

	/* If there's no object present at this position, just clear the entry 
	   (it should be cleared anyway) */
	if( objectInfoPtr->type == OBJECT_TYPE_NONE )
		{
		CLEAR_TABLE_ENTRY( &objectTable[ objectHandle ] );
		return( CRYPT_OK );
		}
	assert( messageFunction != NULL );

	/* Destroy the object and its object table entry */
	if( messageFunction != NULL )
		{
		void *objectPtr = DATAPTR_GET( objectInfoPtr->objectPtr );

		ENSURES( objectPtr != NULL );

		if( objectInfoPtr->type == OBJECT_TYPE_DEVICE )
			{
			MESSAGE_FUNCTION_EXTINFO messageExtInfo;

			/* Device objects are unlockable so we have to pass in extended 
			   information to handle this */
			initMessageExtInfo( &messageExtInfo, objectPtr );
			messageFunction( &messageExtInfo, MESSAGE_DESTROY, NULL, 0 );
			}
		else
			{
			messageFunction( objectPtr, MESSAGE_DESTROY, NULL, 0 );
			}
		}
	return( destroyObjectData( objectHandle ) );
	}

/* Destroy all objects at a given nesting level */

CHECK_RETVAL \
static int destroySelectedObjects( IN_RANGE( 1, 3 ) const int currentDepth )
	{
	const OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	LOOP_INDEX objectHandle;
	int status = CRYPT_OK;

	/* Enter with the object table mutex held */

	/* Preconditions: We're destroying objects at a fixed depth */
	REQUIRES( currentDepth >= 1 && currentDepth <= 3 );

	LOOP_EXT( objectHandle = NO_SYSTEM_OBJECTS,
			  objectHandle < MAX_NO_OBJECTS,
			  objectHandle++, MAX_NO_OBJECTS + 1 )
		{
		int dependentObject, depth = 1;

		ENSURES( LOOP_INVARIANT_EXT( objectHandle, NO_SYSTEM_OBJECTS, \
									 MAX_NO_OBJECTS - 1,
									 MAX_NO_OBJECTS + 1 ) );

		/* If there's nothing there, continue.  In this case we don't 
		   perform a REQUIRES( DATAPTR_VALID() ) because we don't want a 
		   single corrupted pointer to prevent the cleanup of the entire 
		   object table */
		if( !DATAPTR_ISSET( objectTable[ objectHandle ].objectPtr ) )
			continue;

		/* There's an object still present, determine its nesting depth.
		   Dependent devices are terminal so we only follow the path down for
		   dependent objects */
		dependentObject = objectTable[ objectHandle ].dependentObject;
		if( isValidObject( dependentObject ) )
			{
			if( isValidObject( objectTable[ dependentObject ].dependentObject ) )
				depth = 3;
			else
				{
				if( isValidObject( objectTable[ dependentObject ].dependentDevice ) )
					depth = 2;
				}
			}
		else
			{
			if( isValidObject( objectTable[ objectHandle ].dependentDevice ) )
				depth = 2;
			}

		/* If the nesting level of the object matches the current level,
		   destroy it.  We unlock the object table around the access to
		   prevent remaining active objects from blocking the shutdown (the
		   activation of krnlIsExiting() takes care of any other messages 
		   that may arrive during this process).

		   "For death is come up into our windows, and it is entered into
		    our palaces, to cut off the children from the without"
			-- Jeremiah 9:21 */
		if( depth >= currentDepth )
			{
			KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );

			DEBUG_DIAG(( "Destroying leftover %s, ID = %d", 
						 getObjectDescriptionNT( objectHandle ),
						 objectTable[ objectHandle ].uniqueID ));
			objectTable = NULL;
			MUTEX_UNLOCK( objectTable );
			krnlSendNotifier( objectHandle, IMESSAGE_DESTROY );
			status = CRYPT_ERROR_INCOMPLETE;
			MUTEX_LOCK( objectTable );
			objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( objectHandle <= MAX_NO_OBJECTS );

	/* Exit with the object table mutex held */
	return( status );
	}

/* Destroy all objects (homini necesse est mori) */

CHECK_RETVAL \
int destroyObjects( void )
	{
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	LOOP_INDEX objectHandle;
	int depth, localStatus, status DUMMY_INIT;

	/* Preconditions: We either didn't complete the initialisation and are 
	   shutting down during a krnlBeginInit(), or we've completed 
	   initialisation and are shutting down after a krnlBeginShutdown() */
	REQUIRES( ( krnlData->initLevel == INIT_LEVEL_KRNLDATA && \
				krnlData->shutdownLevel == SHUTDOWN_LEVEL_NONE ) || \
			  ( krnlData->initLevel == INIT_LEVEL_KRNLDATA && \
				krnlData->shutdownLevel == SHUTDOWN_LEVEL_THREADS ) );

	/* Indicate that we're shutting down the object handling.  From now on
	   all messages other than object-destruction ones will be rejected by
	   the kernel.  This is needed in order to have any remaining active
	   objects exit quickly, since we don't want them to block the shutdown.
	   Note that we do this before we lock the object table to encourage
	   anything that might have the table locked to exit quickly once we try
	   and lock the table */
	krnlData->shutdownLevel = SHUTDOWN_LEVEL_MESSAGES;

	/* Lock the object table to ensure that other threads don't try to
	   access it */
	MUTEX_LOCK( objectTable );

	/* Destroy all system objects except the root system object ("The death
	   of God left the angels in a strange position" - Donald Barthelme, "On
	   Angels").  We have to do this before we destroy any unclaimed
	   leftover objects because some of them may depend on system objects,
	   if the system objects aren't destroyed they'll be erroneously flagged
	   as leftover objects.  The destruction is done explicitly by invoking
	   the object's message function directly because the message dispatcher
	   checks to make sure that they're never destroyed through a standard
	   message, which would indicate a programming error */
	LOOP_SMALL( objectHandle = SYSTEM_OBJECT_HANDLE + 1,
				objectHandle < NO_SYSTEM_OBJECTS, objectHandle++ )
		{
		ENSURES_MUTEX( LOOP_INVARIANT_SMALL( objectHandle, \
											 SYSTEM_OBJECT_HANDLE + 1, \
											 NO_SYSTEM_OBJECTS - 1 ),
					   objectTable );

		/* In the extremely unlikely event that we encounter an error during 
		   the creation of the system object, no other objects will have been 
		   created, so before we try and destroy an object we make sure that 
		   it's actually been created */
		if( !isValidObject( objectHandle ) )
			continue;

		status = destroyObject( objectHandle );
		ENSURES_MUTEX( cryptStatusOK( status ), objectTable );
		}
	ENSURES_MUTEX( LOOP_BOUND_OK, objectTable );

	/* Postcondition: All system objects except the root system object have
	   been destroyed */
	FORALL( i, SYSTEM_OBJECT_HANDLE + 1, NO_SYSTEM_OBJECTS,
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );

	/* Delete any unclaimed leftover objects.  This is rather more complex
	   than just rumbling through deleting each object we find since some
	   objects have dependent objects underneath them, and deleting the
	   lower-level object causes problems when we later delete their parents
	   (the code handles it cleanly, but we get a kernel trap warning us that
	   we're trying to delete a non-present object).  Because of this we have
	   to delete the objects in order of depth, first all three-level objects
	   (e.g. cert -> context -> device), then all two-level objects, and
	   finally all one-level objects.  This means that we can never delete
	   another object out from under a dependent object */
	LOOP_SMALL_REV( depth = 3, depth > 0, depth-- )
		{
		ENSURES_MUTEX( LOOP_INVARIANT_REV( depth, 1, 3 ), objectTable );

		localStatus = destroySelectedObjects( depth );
		if( cryptStatusError( localStatus ) )
			status = localStatus;
		}
	ENSURES_MUTEX( LOOP_BOUND_SMALL_REV_OK, objectTable );

	/* Postcondition: All objects except the root system object have been
	   destroyed */
	FORALL( i, SYSTEM_OBJECT_HANDLE + 1, MAX_NO_OBJECTS, \
			!memcmp( &objectTable[ i ], &OBJECT_INFO_TEMPLATE, \
					 sizeof( OBJECT_INFO ) ) );

	/* Finally, destroy the system root object.  We need to preserve the 
	   possible error status from cleaning up any leftover objects so we use 
	   a local status value to get the destroy-object results */
	localStatus = destroyObject( SYSTEM_OBJECT_HANDLE );
	ENSURES_MUTEX( cryptStatusOK( localStatus ), objectTable );

	/* Unlock the object table to allow access by other threads */
	MUTEX_UNLOCK( objectTable );

	return( status );
	}

/****************************************************************************
*																			*
*							Object Creation/Destruction						*
*																			*
****************************************************************************/

/* Create a new object.  This function has to be very careful about locking
   to ensure that another thread can't manipulate the newly-created object
   while it's in an indeterminate state.  To accomplish this it locks the
   object table and tries to create the new object.  If this succeeds it sets
   the OBJECT_FLAG_NOTINITED flag pending completion of the object's
   initialisation by the caller, unlocks the object table, and returns
   control to the caller.  While the object is in this state, the kernel
   will allow it to process only two message types, either a notification
   from the caller that the init stage is complete (which sets the object's
   state to OK), or a destroy object message, which sets the
   OBJECT_FLAG_SIGNALLED flag pending arrival of the init complete
   notification, whereupon the object is immediately destroyed.  The state
   diagram for this is:
									 State
						  Notinited			Signalled
			--------+-------------------+-----------------
			-> OK	| state -> OK,		| Msg -> Destroy
					| ret( OK )			|
	Msg.	Destroy	| state -> Sig'd,	| state -> Sig'd,
					| ret( OK )			| ret( OK )
			CtrlMsg	| process as usual	| process as usual
			NonCtrl	| ret( Notinited )	| ret( Sig'd )

   The initialisation process for an object is therefore:

	status = krnlCreateObject( ... );
	if( cryptStatusError( status ) )
		return( status );

	// Complete object-specific initialisation
	initStatus = ...;

	status = krnlSendMessage( ..., state -> CRYPT_OK );
	return( ( cryptStatusError( initStatus ) ? initStatus : status );

   If the object is destroyed during the object-specific initialisation
   (either by the init code when an error is encountered or due to an
   external signal), the destroy is deferred until the change state message
   at the end occurs.  If a destroy is pending, the change state is converted
   to a destroy and the newly-created object is destroyed.

   This mechanism ensures that the object table is only locked for a very
   short time (typically for only a few lines of executed code in the create
   object function) so that slow initialisation (for example of keyset
   objects associated with network links) can't block other objects.

   In addition to the locking, we need to be careful with how we create new
   objects because if we just allocate handles sequentially and reuse handles
   as soon as possible, an existing object could be signalled and a new one
   created in its place without the caller or owning object realizing that
   they're now working with a different object (although the kernel can tell
   them apart because it maintains an internal unique ID for each object).
   Unix systems handle this by always incrementing pids and assuming that
   there won't be any problems when they wrap, we do the same thing but in
   addition allocate handles in a non-sequential manner using an LFSR to
   step through the object table.  There's no strong reason for this apart
   from helping disabuse users of the notion that any cryptlib objects have
   stdin/stdout-style fixed handles, but it only costs a few extra clocks so
   we may as well do it.
   
   There is one case in which we can still get handle reuse and that's then 
   the object table is heavily loaded but not quite enough to trigger a 
   resize.  For example with a table of size 1024 if the caller creates 1023
   objects and then repeatedly creates and destroys a final object it'll 
   always be reassigned the same handle if no other objects are destroyed in
   the meantime.  This is rather unlikely unless the caller is using 
   individual low-level objects (all of the high-level objects create 
   object-table churn through their dependent objects) so it's not worth
   adding special-case handling for it */

CHECK_RETVAL_RANGE( NO_SYSTEM_OBJECTS, MAX_NO_OBJECTS ) \
static int findFreeObjectEntry( int value )
	{
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	BOOLEAN freeEntryAvailable = FALSE;
	LOOP_INDEX iterations;
	int oldValue = value;

	/* Preconditions: We're starting with a valid object handle, and it's not
	   a system object */
	REQUIRES( isValidHandle( value ) && value >= NO_SYSTEM_OBJECTS );

	/* Step through the entire table looking for a free entry */
	LOOP_EXT( iterations = 0, 
			  isValidHandle( value ) && iterations < MAX_NO_OBJECTS, 
			  iterations++, MAX_NO_OBJECTS + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( iterations, 0, MAX_NO_OBJECTS - 1,
									 MAX_NO_OBJECTS + 1 ) );

		/* Get the next value: Multiply by x and reduce by the polynomial */
#ifdef USE_FIXED_OBJECTHANDLES
		value++;
#else
		value <<= 1;
		if( value & LFSR_MASK )
			value ^= LFSRPOLY;
#endif /* USE_FIXED_OBJECTHANDLES */

		/* Invariant: We're still within the object table */
		ENSURES( isValidHandle( value ) );

		/* If we've found a free object or we've covered the entire table,
		   exit.  We do this check after we update the value rather than as
		   part of the loop test to ensure that we always progress to a new
		   object handle whenever we call this function.  If we did the
		   check as part of the loop test then deleting and creating an
		   object would result in the handle of the deleted object being
		   re-assigned to the new object */
		if( isFreeObject( value ) )
			{
			/* We've found a free entry, we're done */
			freeEntryAvailable = TRUE;
			break;
			}
		if( value == oldValue )
			{
			/* We've covered the entire object table, there's no room for
			   further objects */
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( iterations < MAX_NO_OBJECTS )

	/* Postcondition: We're still within the object table */
	ENSURES( isValidHandle( value ) );

	/* If we didn't find a free entry, tell the caller that the tank is 
	   full */
	if( !freeEntryAvailable )
		{
		/* Postcondition: We tried all locations and there are no free slots
		   available (or, vastly less likely, an internal error has
		   occurred) */
		ENSURES( iterations == MAX_NO_OBJECTS - 2 );
		FORALL( i, 0, MAX_NO_OBJECTS, \
				!isFreeObject( i ) );

		return( CRYPT_ERROR_OVERFLOW );
		}

	/* Postconditions: We found a handle to a free slot */
	REQUIRES( isValidHandle( value ) && value >= NO_SYSTEM_OBJECTS );
	ENSURES( isFreeObject( value ) );

	return( value );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 9 ) ) \
int krnlCreateObject( OUT_HANDLE_OPT int *objectHandle,
					  OUT_BUFFER_ALLOC_OPT( objectDataSize ) void **objectDataPtr, 
					  IN_LENGTH_SHORT const int objectDataSize,
					  IN_ENUM( OBJECT_TYPE ) const OBJECT_TYPE type, 
					  IN_ENUM( SUBTYPE ) const OBJECT_SUBTYPE subType,
					  IN_FLAGS_Z( CREATEOBJECT ) const int createObjectFlags, 
					  IN_HANDLE_OPT const CRYPT_USER owner,
					  IN_FLAGS_Z( ACTION_PERM ) const int actionFlags,
					  IN_PTR MESSAGE_FUNCTION messageFunction )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	OBJECT_INFO objectInfo;
	OBJECT_STATE_INFO *objectStateInfo = &krnlData->objectStateInfo;
	OBJECT_SUBTYPE bitCount;
	BOOLEAN isStaticAlloc = FALSE;
	int localObjectHandle, status = CRYPT_OK;

	assert( isWritePtr( krnlData, sizeof( KERNEL_DATA ) ) );
	assert( isWritePtr( objectDataPtr, sizeof( void * ) ) );

	/* Preconditions (the subType check is just the standard hakmem bitcount
	   which ensures that we don't try and create multi-typed objects, the
	   sole exception to this rule is the default user object, which acts as
	   both a user and an SO object) */
	REQUIRES( objectDataSize > 16 && \
			  ( ( !( type == OBJECT_TYPE_CONTEXT && subType == SUBTYPE_CTX_PKC ) && \
				objectDataSize < MAX_INTLENGTH_SHORT ) || \
			  ( type == OBJECT_TYPE_CONTEXT && subType == SUBTYPE_CTX_PKC && \
				objectDataSize < MAX_INTLENGTH ) ) );
	REQUIRES( isValidType( type ) );
	REQUIRES( subType > SUBTYPE_NONE && subType <= SUBTYPE_LAST );
	REQUIRES( \
		( bitCount = ( subType & ~SUBTYPE_CLASS_MASK ) - \
					 ( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 1 ) & 033333333333L ) - \
					 ( ( ( subType & ~SUBTYPE_CLASS_MASK ) >> 2 ) & 011111111111L ) ) != 0 );
	REQUIRES( ( ( bitCount + ( bitCount >> 3 ) ) & 030707070707L ) % 63 == 1 );
	REQUIRES( createObjectFlags == CREATEOBJECT_FLAG_NONE || \
			  createObjectFlags == CREATEOBJECT_FLAG_SECUREMALLOC );
	REQUIRES( owner == CRYPT_UNUSED || isValidHandle( owner ) );
	REQUIRES( isFlagRangeZ( actionFlags, ACTION_PERM ) );
	REQUIRES( messageFunction != NULL );

	/* Clear return values */
	*objectHandle = CRYPT_ERROR;
	*objectDataPtr = NULL;

	/* If we haven't been initialised yet or we're in the middle of a
	   shutdown, we can't create any new objects */
	if( !isWritePtr( krnlData, sizeof( KERNEL_DATA ) ) || \
		krnlData->initLevel <= INIT_LEVEL_NONE )
		return( CRYPT_ERROR_NOTINITED );
	if( krnlData->shutdownLevel >= SHUTDOWN_LEVEL_MESSAGES )
		{
		DEBUG_DIAG(( "Can't create new objects during a shutdown" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Allocate memory for the object and set up as much as we can of the 
	   object table entry (the remainder has to be set up inside the object-
	   table lock).  The object is always created as an internal object, 
	   it's up to the caller to make it externally visible.
	   
	   The apparently redundant clearning of objectInfo before overwriting
	   it with the object-info template is due to yet another gcc bug, in
	   this case in the x64 debug (-o0) build, for which it doesn't memcpy()
	   the template across but sets each field individually, leaving 
	   whatever padding bytes were present beforehand set to random values */
	if( objectStateInfo->objectHandle < NO_SYSTEM_OBJECTS - 1 )
		{
		/* This is either the system object or the default user object or, 
		   if a distinct crypto hardware device is being used, the crypto
		   hardware object.
		   
		   The reason for checking for one less than the value is that it's
		   incremented on assignement, so at this point it's one less than 
		   the final value */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		REQUIRES( ( type == OBJECT_TYPE_DEVICE && \
					subType == SUBTYPE_DEV_SYSTEM && \
					owner == CRYPT_UNUSED && \
					objectStateInfo->objectHandle == SYSTEM_OBJECT_HANDLE - 1 ) || \
				  ( type == OBJECT_TYPE_USER && \
				    subType == SUBTYPE_USER_SO && \
					owner == SYSTEM_OBJECT_HANDLE && \
					objectStateInfo->objectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 ) || \
				  ( type == OBJECT_TYPE_DEVICE && \
					subType == SUBTYPE_DEV_HARDWARE && \
					owner == DEFAULTUSER_OBJECT_HANDLE && \
					objectStateInfo->objectHandle != SYSTEM_OBJECT_HANDLE - 1 && \
					objectStateInfo->objectHandle != DEFAULTUSER_OBJECT_HANDLE - 1 ) );
#else
		REQUIRES( ( type == OBJECT_TYPE_DEVICE && \
					subType == SUBTYPE_DEV_SYSTEM && \
					owner == CRYPT_UNUSED && \
					objectStateInfo->objectHandle == SYSTEM_OBJECT_HANDLE - 1 ) || \
				  ( type == OBJECT_TYPE_USER && \
				    subType == SUBTYPE_USER_SO && \
					owner == SYSTEM_OBJECT_HANDLE && \
					objectStateInfo->objectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 ) );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */

		MUTEX_LOCK( allocation );
		*objectDataPtr = getBuiltinObjectStorage( type, subType, 
												  objectDataSize );
		MUTEX_UNLOCK( allocation );
		ENSURES( *objectDataPtr != NULL );
		isStaticAlloc = TRUE;
		}
	else
		{
		/* Nothing should be creating system objects at this point */
		REQUIRES( subType != SUBTYPE_DEV_SYSTEM && \
				  subType != SUBTYPE_USER_SO );

		/* If it's a keyset or context then we may be able to use a built-in 
		   storage block for it */
		if( type == OBJECT_TYPE_KEYSET || type == OBJECT_TYPE_CONTEXT )
			{
			void *storagePtr;
			
			MUTEX_LOCK( allocation );
			storagePtr = getBuiltinObjectStorage( type, subType,
												  objectDataSize );
			MUTEX_UNLOCK( allocation );
			if( storagePtr != NULL )
				{
				*objectDataPtr = storagePtr;
				isStaticAlloc = TRUE;
				}
			}
		}
	if( !isStaticAlloc )
		{
		/* The object isn't using built-in storage, allocate it dynamically
		   as required */
		if( createObjectFlags & CREATEOBJECT_FLAG_SECUREMALLOC )
			{
			status = krnlMemalloc( objectDataPtr, objectDataSize );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			{
			REQUIRES( isIntegerRangeNZ( objectDataSize ) );
			if( ( *objectDataPtr = clAlloc( "krnlCreateObject", \
											objectDataSize ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			}
		}
	assert( isWritePtrDynamic( *objectDataPtr, objectDataSize ) );
	memset( &objectInfo, 0, sizeof( OBJECT_INFO ) ); /* See comment above */
	objectInfo = OBJECT_INFO_TEMPLATE;
	REQUIRES( isIntegerRangeNZ( objectDataSize ) ); 
	memset( *objectDataPtr, 0, objectDataSize );
	DATAPTR_SET( objectInfo.objectPtr, *objectDataPtr );
	objectInfo.objectSize = objectDataSize;
	if( isStaticAlloc )
		SET_FLAG( objectInfo.flags, OBJECT_FLAG_STATICALLOC );
	else
		{
		if( createObjectFlags & CREATEOBJECT_FLAG_SECUREMALLOC )
			SET_FLAG( objectInfo.flags, OBJECT_FLAG_SECUREMALLOC );
		}
	objectInfo.owner = owner;
	objectInfo.type = type;
	objectInfo.subType = subType;
	objectInfo.actionFlags = actionFlags;
	FNPTR_SET( objectInfo.messageFunction, messageFunction );
	ENSURES( sanityCheckObject( &objectInfo ) );

	/* Make sure that the kernel has been initialised and lock the object
	   table for exclusive access */
	MUTEX_LOCK( initialisation );
	MUTEX_LOCK( objectTable );
	MUTEX_UNLOCK( initialisation );

	/* Finish setting up the object table entry with any remaining data */
	objectInfo.uniqueID = krnlData->objectUniqueID;

	/* The first objects created are internal objects with predefined
	   handles (spes lucis aeternae).  As we create these objects we ratchet
	   up through the fixed handles until we reach the last fixed object,
	   whereupon we allocate handles normally */
	localObjectHandle = objectStateInfo->objectHandle;
	if( localObjectHandle < NO_SYSTEM_OBJECTS - 1 )
		{
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
		REQUIRES_MUTEX( ( type == OBJECT_TYPE_DEVICE && \
						  subType == SUBTYPE_DEV_SYSTEM && \
						  owner == CRYPT_UNUSED && \
						  localObjectHandle == SYSTEM_OBJECT_HANDLE - 1 ) || \
						( type == OBJECT_TYPE_USER && \
						  subType == SUBTYPE_USER_SO && \
						  owner == SYSTEM_OBJECT_HANDLE && \
						  localObjectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 ) || \
						( type == OBJECT_TYPE_DEVICE && \
						  subType == SUBTYPE_DEV_HARDWARE && \
						  owner == DEFAULTUSER_OBJECT_HANDLE && \
						  localObjectHandle == CRYPTO_OBJECT_HANDLE - 1 ),
						objectTable );
#else
		REQUIRES_MUTEX( ( type == OBJECT_TYPE_DEVICE && \
						  subType == SUBTYPE_DEV_SYSTEM && \
						  owner == CRYPT_UNUSED && \
						  localObjectHandle == SYSTEM_OBJECT_HANDLE - 1 ) || \
						( type == OBJECT_TYPE_USER && \
						  subType == SUBTYPE_USER_SO && \
						  owner == SYSTEM_OBJECT_HANDLE && \
						  localObjectHandle == DEFAULTUSER_OBJECT_HANDLE - 1 ), 
						objectTable );
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
		localObjectHandle++;
		ENSURES_MUTEX( isValidHandle( localObjectHandle ) && \
					   localObjectHandle < NO_SYSTEM_OBJECTS && \
					   localObjectHandle == objectStateInfo->objectHandle + 1, \
					   objectTable );
		}
	else
		{
		REQUIRES_MUTEX( isValidHandle( owner ), objectTable );

		/* Search the table for a free entry */
		status = localObjectHandle = findFreeObjectEntry( localObjectHandle );
		}


	/* If there's a problem with allocating a handle then it either means 
	   that we've run out of entries in the object table or there's a more 
	   general error */
	if( cryptStatusError( status ) )
		{
		void *objectPtr = DATAPTR_GET( objectInfo.objectPtr );

		MUTEX_UNLOCK( objectTable );

		ENSURES( objectPtr != NULL );

		/* Warn about the problem */
		DEBUG_DIAG_ERRMSG(( "Error %s allocating new handle for %s object", 
							getStatusName( status ), 
							getObjectTypeDescriptionNT( type, subType ) ));
		assert( DEBUG_WARN );

		/* Free the object instance data storage that we allocated earlier 
		   and return the error status */
		if( TEST_FLAG( objectInfo.flags, OBJECT_FLAG_SECUREMALLOC ) )
			{
			int localStatus = krnlMemfree( &objectPtr );
			ENSURES( cryptStatusOK( localStatus ) );
			}
		else
			{
			REQUIRES( isIntegerRangeNZ( objectInfo.objectSize ) ); 
			zeroise( objectPtr, objectInfo.objectSize );
			if( !TEST_FLAG( objectInfo.flags, OBJECT_FLAG_STATICALLOC ) ) 
				clFree( "destroyObjectData", objectPtr );
			}
		zeroise( &objectInfo, sizeof( OBJECT_INFO ) );

		return( status );
		}

	/* Inner precondition: This object table slot is free */
	REQUIRES_MUTEX( isFreeObject( localObjectHandle ), objectTable );

	/* Set up the new object entry in the table and update the object table
	   state */
	objectTable[ localObjectHandle ] = objectInfo;
	if( localObjectHandle == NO_SYSTEM_OBJECTS - 1 )
		{
		time_t theTime;

		/* We've set up all of the objects that have fixed handles, from now 
		   on we're using dynamically assigned handled.  To start this 
		   process we get a non-constant seed to use for the initial object 
		   handle.  See the comment in findFreeObjectEntry() for why this is 
		   done, and why it only uses a relatively weak seed.  
		   
		   Since we may be running on an embedded system with no reliable 
		   time source available we use GETTIME_NOFAIL rather than 
		   GETTIME_NONE, the check for correct functioning of the time 
		   source on non-embedded systems has already been done in the init 
		   code */
		theTime = getTime( GETTIME_NOFAIL );

		/* From now on we start allocating handles starting from a 
		   randomised location in the table */
#ifndef USE_FIXED_OBJECTHANDLES
		objectStateInfo->objectHandle = \
				( int ) theTime & ( LFSR_MASK - 1 );
#endif /* USE_FIXED_OBJECTHANDLES */
		if( objectStateInfo->objectHandle < NO_SYSTEM_OBJECTS )
			{
			/* Can occur with probability
			   NO_SYSTEM_OBJECTS / MAX_NO_OBJECTS */
			objectStateInfo->objectHandle = NO_SYSTEM_OBJECTS + 42;
			}
		}
	else
		objectStateInfo->objectHandle = localObjectHandle;

	/* Update the object unique ID value */
	if( krnlData->objectUniqueID < 0 || \
		krnlData->objectUniqueID >= INT_MAX - 1 )
		krnlData->objectUniqueID = NO_SYSTEM_OBJECTS;
	else
		krnlData->objectUniqueID++;
	ENSURES_MUTEX( krnlData->objectUniqueID > 0 && \
				   krnlData->objectUniqueID < INT_MAX, objectTable );

	/* Postconditions: It's a valid object that's been set up as required */
	ENSURES_MUTEX( isValidObject( localObjectHandle ), objectTable );
	ENSURES_MUTEX( DATAPTR_GET( objectInfo.objectPtr ) == *objectDataPtr, objectTable );
	ENSURES_MUTEX( objectInfo.owner == owner, objectTable );
	ENSURES_MUTEX( objectInfo.type == type, objectTable );
	ENSURES_MUTEX( objectInfo.subType == subType, objectTable );
	ENSURES_MUTEX( objectInfo.actionFlags == actionFlags, objectTable );
	ENSURES_MUTEX( FNPTR_ISSET( objectInfo.messageFunction ), 
				   objectTable );

	/* Report what's just been created, useful for determining where 
	   leftover objects are coming from.  We only enable this when tracking 
	   down leaks since it otherwise creates a huge amount of noise */
#if 0
	DEBUG_DIAG(( "Created %s, ID = %d", 
				 getObjectDescriptionNT( localObjectHandle ),
				 objectInfo.uniqueID ));
#endif /* 0 */

	MUTEX_UNLOCK( objectTable );

	*objectHandle = localObjectHandle;

	return( CRYPT_OK );
	}
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
