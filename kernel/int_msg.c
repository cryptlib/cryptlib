/****************************************************************************
*																			*
*							Internal Message Handlers						*
*						Copyright Peter Gutmann 1997-2018					*
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

/****************************************************************************
*																			*
*								Dependency ACLs								*
*																			*
****************************************************************************/

/* The ACL tables for each object dependency type */

static const DEPENDENCY_ACL dependencyACLTbl[] = {
	/* Envelopes and sessions can have conventional encryption and MAC
	   contexts attached */
	MK_DEPACL( OBJECT_TYPE_ENVELOPE, ST_NONE, ST_ENV_ANY, ST_NONE, \
			   OBJECT_TYPE_CONTEXT, ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ST_NONE ),
	MK_DEPACL( OBJECT_TYPE_SESSION, ST_NONE, ST_NONE, ST_SESS_ANY, \
			   OBJECT_TYPE_CONTEXT, ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ST_NONE ),

	/* PKC contexts can have certs attached and vice versa.  Since the
	   certificate can change the permissions on the context, we set the
	   DEP_FLAG_UPDATEDEP flag to ensure that the cert permissions get
	   reflected onto the context */
	MK_DEPACL_EX( OBJECT_TYPE_CONTEXT, ST_CTX_PKC, ST_NONE, ST_NONE, \
				  OBJECT_TYPE_CERTIFICATE, ST_CERT_ANY, ST_NONE, ST_NONE, 
				  DEP_FLAG_UPDATEDEP ),
	MK_DEPACL_EX( OBJECT_TYPE_CERTIFICATE, ST_CERT_ANY, ST_NONE, ST_NONE, \
				  OBJECT_TYPE_CONTEXT, ST_CTX_PKC, ST_NONE, ST_NONE, 
				  DEP_FLAG_UPDATEDEP ),

	/* Contexts can have crypto devices attached */
	MK_DEPACL( OBJECT_TYPE_CONTEXT, ST_CTX_ANY, ST_NONE, ST_NONE, \
			   OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_ANY_STD, ST_NONE ),

	/* Hardware crypto devices can have PKCS #15 storage objects attached */
	MK_DEPACL( OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_HW, ST_NONE, \
			   OBJECT_TYPE_KEYSET, ST_NONE, ST_KEYSET_FILE, ST_NONE ),

	/* Anything can have the system device attached, since all objects not
	   created via crypto devices are created via the system device */
	MK_DEPACL( OBJECT_TYPE_CONTEXT, ST_CTX_ANY, ST_NONE, ST_NONE, \
			   OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_SYSTEM, ST_NONE ),
	MK_DEPACL( OBJECT_TYPE_CERTIFICATE, ST_CERT_ANY, ST_NONE, ST_NONE, \
			   OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_SYSTEM, ST_NONE ),
	MK_DEPACL( OBJECT_TYPE_KEYSET, ST_NONE, ST_KEYSET_ANY, ST_NONE, \
			   OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_SYSTEM, ST_NONE ),
	MK_DEPACL( OBJECT_TYPE_ENVELOPE, ST_NONE, ST_ENV_ANY, ST_NONE, \
			   OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_SYSTEM, ST_NONE ),
	MK_DEPACL( OBJECT_TYPE_SESSION, ST_NONE, ST_NONE, ST_SESS_ANY, \
			   OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_SYSTEM, ST_NONE ),
	MK_DEPACL( OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_ANY_STD, ST_NONE, \
			   OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_SYSTEM, ST_NONE ),
	MK_DEPACL( OBJECT_TYPE_USER, ST_NONE, ST_NONE, ST_USER_ANY, \
			   OBJECT_TYPE_DEVICE, ST_NONE, ST_DEV_SYSTEM, ST_NONE ),

	/* End-of-ACL marker */
	MK_DEPACL_END(), MK_DEPACL_END()
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Update an action permission.  This implements a ratchet that only allows
   permissions to be made more restrictive after they've initially been set,
   so that once a permission is set to a given level it can't be set back to
   a less restrictive one (i.e. it's a write-up policy) */

CHECK_RETVAL \
static int updateActionPerms( IN_FLAGS( ACTION_PERM ) int currentPerm, 
							  IN_FLAGS( ACTION_PERM ) const int newPerm )
	{
	LOOP_INDEX i;
	int permMask = ACTION_PERM_MASK;

	/* Preconditions: The permissions are valid */
	REQUIRES( currentPerm > 0 && currentPerm <= ACTION_PERM_ALL_MAX );
	REQUIRES( newPerm > 0 && newPerm <= ACTION_PERM_ALL_MAX );

	/* For each permission, update its value if the new setting is more
	   restrictive than the current one.  Since smaller values are more
	   restrictive, we can do a simple range comparison and replace the
	   existing value if it's larger than the new one */
	LOOP_SMALL( i = 0, i < ACTION_PERM_COUNT, i++ )
		{
		ENSURES( LOOP_INVARIANT_SMALL( i, 0, ACTION_PERM_COUNT - 1 ) );

		if( ( newPerm & permMask ) < ( currentPerm & permMask ) )
			currentPerm = ( currentPerm & ~permMask ) | ( newPerm & permMask );
		permMask <<= ACTION_PERM_BITS;
		}
	ENSURES( LOOP_BOUND_OK );

	/* Postcondition: The new permission is at least as restrictive (or more
	   so) than the old one */
	FORALL( i, 0, ACTION_PERM_COUNT,
			( currentPerm & ( ACTION_PERM_MASK << ( i * ACTION_PERM_BITS ) ) ) <= \
				( newPerm & ( ACTION_PERM_MASK << ( i * ACTION_PERM_BITS ) ) ) );

	return( currentPerm );
	}

/* Update the action permissions for an object based on the composite
   permissions for it and a dependent object.  This is a special-case
   function because it has to operate with the object table unlocked.  This
   is necessary because the dependent object may be owned by another thread,
   and if we were to leave the object table locked the two would deadlock if
   we were sending the object a message while owning the object table at the
   same time that the other thread was sending a message while owning the
   object.

   There is one (rather unlikely) potential race condition possible here in
   which the object is destroyed and replaced by a new one while the object
   table is unlocked, so we end up updating the action permissions for a
   different object.  To protect against this, we check the unique ID after
   we re-lock the object table to make sure that it's the same object */

CHECK_RETVAL \
static int updateDependentObjectPerms( IN_HANDLE const CRYPT_HANDLE objectHandle,
									   IN_HANDLE const CRYPT_HANDLE dependentObject )
	{
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	const OBJECT_TYPE objectType = objectTable[ objectHandle ].type;
	const CRYPT_CONTEXT contextHandle = \
		( objectType == OBJECT_TYPE_CONTEXT ) ? objectHandle : dependentObject;
	const CRYPT_CERTIFICATE certHandle = \
		( objectType == OBJECT_TYPE_CERTIFICATE ) ? objectHandle : dependentObject;
	const int uniqueID = objectTable[ objectHandle ].uniqueID;
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	int actionFlags = 0, status;
	ORIGINAL_INT_VAR( oldPerm, objectTable[ contextHandle ].actionFlags );
		/* Note that the above macro gives initialised-but-not-referenced 
		   warnings in release builds */
	
	/* Preconditions: Objects are valid, one is a cert and the other a
	   context, and they aren't dependent on each other (which would create
	   a dependency update loop).  Note that these checks aren't performed
	   at runtime since they've already been performed by the calling
	   function, all we're doing here is establishing preconditions rather
	   than performing actual parameter checking */
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( isValidHandle( dependentObject ) );
	REQUIRES( ( objectTable[ objectHandle ].type == OBJECT_TYPE_CONTEXT && \
				objectTable[ dependentObject ].type == OBJECT_TYPE_CERTIFICATE ) || \
			  ( objectTable[ objectHandle ].type == OBJECT_TYPE_CERTIFICATE && \
				objectTable[ dependentObject ].type == OBJECT_TYPE_CONTEXT ) );
	REQUIRES( objectTable[ objectHandle ].dependentObject != dependentObject || \
			  objectTable[ dependentObject ].dependentObject != objectHandle );

	/* Since we're about to send messages to the dependent object, we have to
	   unlock the object table.  Since we're about to hand off control to
	   other threads, we clear any object-table references since we can't 
	   rely on them to be consistent when we re-lock the table */
	objectTable = NULL;
	MUTEX_UNLOCK( objectTable );

	/* Make sure that we're not making a private key dependent on a cert,
	   which is a public-key object.  We check this here rather than having
	   the caller check it because it requires having the object table
	   unlocked */
	if( objectType == OBJECT_TYPE_CERTIFICATE && \
		checkContextCapability( dependentObject, 
								MESSAGE_CHECK_PKC_PRIVATE ) )
		{
		MUTEX_LOCK( objectTable );
		retIntError();
		}

	/* For each action type, enable its continued use only if the cert
	   allows it.  Because the certificate may not have been fully
	   initialised yet (for example if we're attaching a context to a
	   cert that's in the process of being created), we have to perform
	   a passive-container action-available check that also works on a
	   low-state object rather than a standard active-object check.  
	   
	   In addition since the introduction of certificates now requires that
	   we distinguish between "sign any kind of data except data that's a
	   certificate" and "sign data that's a certificate", we have to check
	   for MESSAGE_CHECK_PKC_SIGN_SPECIAL_AVAIL alongside the standard
	   MESSAGE_CHECK_PKC_SIGN_AVAIL.

	   Because a key with a certificate attached indicates that it's
	   (probably) being used for some function that involves interaction
	   with a relying party (i.e. that it probably has more value than a raw
	   key with no strings attached), we set the action permission to
	   ACTION_PERM_NONE_EXTERNAL rather than allowing ACTION_PERM_ALL.  This
	   both ensures that it's only used in a safe manner via the cryptlib
	   internal mechanisms, and makes sure that it's not possible to utilize
	   the signature/encryption duality of some algorithms to create a
	   signature where it's been disallowed */
	if( checkContextCapability( certHandle, MESSAGE_CHECK_PKC_SIGN_AVAIL ) || \
		checkContextCapability( certHandle, MESSAGE_CHECK_PKC_SIGN_CA_AVAIL ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_NONE_EXTERNAL );
	if( checkContextCapability( certHandle, MESSAGE_CHECK_PKC_SIGCHECK_AVAIL ) || \
		checkContextCapability( certHandle, MESSAGE_CHECK_PKC_SIGCHECK_CA_AVAIL ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_NONE_EXTERNAL );
	if( checkContextCapability( certHandle, MESSAGE_CHECK_PKC_ENCRYPT_AVAIL ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL );
	if( checkContextCapability( certHandle, MESSAGE_CHECK_PKC_DECRYPT_AVAIL ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );
	if( checkContextCapability( certHandle, MESSAGE_CHECK_PKC_KA_EXPORT_AVAIL ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL );
	if( checkContextCapability( certHandle, MESSAGE_CHECK_PKC_KA_IMPORT_AVAIL ) )
		actionFlags |= \
			MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );

	/* Inner precondition: The usage shouldn't be all-zero.  Technically it
	   can be since there are bound to be certs out there broken enough to do
	   this, and certainly under the stricter compliance levels this *will*
	   happen, so we make it a warning that's only produced in debug mode */
	if( actionFlags == 0 )
		{
		DEBUG_DIAG(( "Action %s is constrained by its associated",
					 getObjectDescriptionNT( contextHandle ) ));
		DEBUG_DIAG(( "certificate %s to not allow any actions", 
					 getObjectDescriptionNT( certHandle ) ));
		assert_nofuzz( DEBUG_WARN );
		}

	/* We're done querying the dependent object, re-lock the object table, 
	   reinitialise any references to it, and make sure that the original 
	   object hasn't been touched */
	MUTEX_LOCK( objectTable );
	objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	if( objectTable[ objectHandle ].uniqueID != uniqueID )
		return( CRYPT_ERROR_SIGNALLED );
	if( actionFlags == 0 )
		{
		/* See the comment above, we can't continue at this point because we 
		   can't set the action permissions attribute to nothing */
		return( CRYPT_ERROR_NOTAVAIL );
		}
	status = setPropertyAttribute( contextHandle, CRYPT_IATTRIBUTE_ACTIONPERMS,
								   &actionFlags );

	/* Postcondition: The new permission is at least as restrictive (or more
	   so) than the old one */
	FORALL( i, 0, ACTION_PERM_COUNT,
			( objectTable[ contextHandle ].actionFlags & ( ACTION_PERM_MASK << ( i * 2 ) ) ) <= \
			( ORIGINAL_VALUE( oldPerm ) & ( ACTION_PERM_MASK << ( i * 2 ) ) ) );

	return( status );
	}

/* Convert an internal object reference to an external one */

CHECK_RETVAL \
int convertIntToExtRef( IN_HANDLE const int objectHandle )
	{
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	int status;

	/* Preconditions */
	REQUIRES( isValidObject( objectHandle ) );

	/* Convert at least one internal reference to the object to an external 
	   one */
	status = incRefCount( objectHandle, 0, NULL, FALSE );
	if( cryptStatusOK( status ) )
		status = decRefCount( objectHandle, 0, NULL, TRUE );
	if( cryptStatusOK( status ) )
		return( status );

	/* Recovering from an error at this point is tricky, it's a shouldn't-
	   occur condition in any case but if it does occur then the fact that 
	   the object reference is in an unclear state means we can't do a 
	   straight decRef().  The safest option seems to be to explicitly 
	   destroy it, which usually produces the correct result but in the case 
	   of something like fetching a certificate from a session or envelope 
	   will lead to the session/envelope's reference being destroyed as 
	   well */
	( void ) krnlSendNotifier( objectHandle, IMESSAGE_DESTROY );

	return( status );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

#ifndef CONFIG_NO_SELFTEST

CHECK_RETVAL \
int initInternalMsgs( void )
	{
	LOOP_INDEX i;

	/* Perform a consistency check on the object dependency ACL */
	LOOP_LARGE( i = 0, 
				i < FAILSAFE_ARRAYSIZE( dependencyACLTbl, DEPENDENCY_ACL ) && \
					dependencyACLTbl[ i ].type != OBJECT_TYPE_NONE, 
				i++ )
		{
		const DEPENDENCY_ACL *dependencyACL;

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, 
									   FAILSAFE_ARRAYSIZE( dependencyACLTbl, \
														   DEPENDENCY_ACL ) - 1 ) );

		dependencyACL = &dependencyACLTbl[ i ];
		ENSURES( isEnumRange( dependencyACL->type, OBJECT_TYPE ) && \
				 isEnumRange( dependencyACL->dType, OBJECT_TYPE ) );
		ENSURES( !( dependencyACL->subTypeA & ( SUBTYPE_CLASS_B | \
												SUBTYPE_CLASS_C ) ) && \
				 !( dependencyACL->subTypeB & ( SUBTYPE_CLASS_A | \
												SUBTYPE_CLASS_C ) ) && \
				 !( dependencyACL->subTypeC & ( SUBTYPE_CLASS_A | \
												SUBTYPE_CLASS_B ) ) );
		ENSURES( !( dependencyACL->dSubTypeA & ( SUBTYPE_CLASS_B | \
												 SUBTYPE_CLASS_C ) ) && \
				 !( dependencyACL->dSubTypeB & ( SUBTYPE_CLASS_A | \
												 SUBTYPE_CLASS_C ) ) && \
				 !( dependencyACL->dSubTypeC & ( SUBTYPE_CLASS_A | \
												 SUBTYPE_CLASS_B ) ) );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( dependencyACLTbl, DEPENDENCY_ACL ) );

	return( CRYPT_OK );
	}
#else

CHECK_RETVAL \
int initInternalMsgs( void )
	{
	return( CRYPT_OK );
	}
#endif /* CONFIG_NO_SELFTEST */

void endInternalMsgs( void )
	{
	}

/****************************************************************************
*																			*
*							Get/Set Property Attributes						*
*																			*
****************************************************************************/

/* Get/set object property attributes.  We differentiate between a small
   number of user-accessible properties such as the object's owner, and
   properties that are only accessible by cryptlib.  The user-accessible
   properties can be locked, which makes them immutable (at least to being
   explicitly set, they can still be implicitly altered, for example setting
   a new object owner decrements the forwardcount value) and also unreadable
   by the user */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int getPropertyAttribute( IN_HANDLE const int objectHandle,
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						  OUT_BUFFER_FIXED_C( sizeof( int ) ) void *messageDataPtr )
	{
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	int *valuePtr = ( int * ) messageDataPtr;

	assert( isWritePtr( messageDataPtr, sizeof( int ) ) );

	/* Preconditions */
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( attribute == CRYPT_PROPERTY_OWNER || \
			  attribute == CRYPT_PROPERTY_FORWARDCOUNT || \
			  attribute == CRYPT_PROPERTY_LOCKED || \
			  attribute == CRYPT_PROPERTY_USAGECOUNT || \
			  attribute == CRYPT_IATTRIBUTE_TYPE || \
			  attribute == CRYPT_IATTRIBUTE_SUBTYPE || \
			  attribute == CRYPT_IATTRIBUTE_STATUS || \
			  attribute == CRYPT_IATTRIBUTE_INTERNAL || \
			  attribute == CRYPT_IATTRIBUTE_ACTIONPERMS );
	REQUIRES( sanityCheckObject( objectInfoPtr ) );

	switch( attribute )
		{
		/* User-accessible properties */
		case CRYPT_PROPERTY_OWNER:
			/* We allow this to be read since its value can be determined
			   anyway with a trial access */
			if( !TEST_FLAG( objectInfoPtr->flags, OBJECT_FLAG_OWNED ) )
				return( CRYPT_ERROR_NOTINITED );
#ifdef USE_THREADS
			/* A small number of implementations use non-scalar thread IDs, 
			   which we can't easily handle when all that we have is an 
			   integer handle.  However, the need to bind threads to objects 
			   only exists because of Win32 security holes arising from the 
			   ability to perform thread injection, so this isn't a big 
			   issue */
  #ifdef NONSCALAR_HANDLES
			if( sizeof( objectInfoPtr->objectOwner ) > sizeof( int ) )
				return( CRYPT_ERROR_NOTAVAIL );
  #endif /* NONSCALAR_HANDLES */
			*valuePtr = ( int ) objectInfoPtr->objectOwner;
#else
			*valuePtr = 0;
#endif /* USE_THREADS */
			break;

		case CRYPT_PROPERTY_FORWARDCOUNT:
			if( TEST_FLAG( objectInfoPtr->flags, OBJECT_FLAG_ATTRLOCKED ) )
				return( CRYPT_ERROR_PERMISSION );
			*valuePtr = objectInfoPtr->forwardCount;
			break;

		case CRYPT_PROPERTY_LOCKED:
			/* We allow this to be read since its value can be determined
			   anyway with a trial write */
			*( ( BOOLEAN * ) messageDataPtr ) = \
						TEST_FLAG( objectInfoPtr->flags, 
								   OBJECT_FLAG_ATTRLOCKED ) ? TRUE : FALSE;
			break;

		case CRYPT_PROPERTY_USAGECOUNT:
			*valuePtr = objectInfoPtr->usageCount;
			break;

		/* Internal properties */
		case CRYPT_IATTRIBUTE_TYPE:
			*valuePtr = objectInfoPtr->type;
			break;

		case CRYPT_IATTRIBUTE_SUBTYPE:
			*valuePtr = objectInfoPtr->subType;
			break;

		case CRYPT_IATTRIBUTE_STATUS:
			*valuePtr = GET_FLAGS( objectInfoPtr->flags, 
								   OBJECT_FLAGMASK_STATUS );
			break;

		case CRYPT_IATTRIBUTE_INTERNAL:
			*( ( BOOLEAN * ) messageDataPtr ) = \
					TEST_FLAG( objectInfoPtr->flags, 
							   OBJECT_FLAG_INTERNAL ) ? TRUE : FALSE;
			break;

		case CRYPT_IATTRIBUTE_ACTIONPERMS:
			*valuePtr = objectInfoPtr->actionFlags;
			break;

		default:
			retIntError();
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int setPropertyAttribute( IN_HANDLE const int objectHandle,
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
						  IN_BUFFER_C( sizeof( int ) ) void *messageDataPtr )
	{
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const int value = *( ( int * ) messageDataPtr );

	assert( isReadPtr( messageDataPtr, sizeof( int ) ) );

	/* Preconditions */
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( attribute == CRYPT_PROPERTY_HIGHSECURITY || \
			  attribute == CRYPT_PROPERTY_OWNER || \
			  attribute == CRYPT_PROPERTY_FORWARDCOUNT || \
			  attribute == CRYPT_PROPERTY_LOCKED || \
			  attribute == CRYPT_PROPERTY_USAGECOUNT || \
			  attribute == CRYPT_IATTRIBUTE_STATUS || \
			  attribute == CRYPT_IATTRIBUTE_INTERNAL || \
			  attribute == CRYPT_IATTRIBUTE_ACTIONPERMS || \
			  attribute == CRYPT_IATTRIBUTE_LOCKED );
	REQUIRES( objectHandle >= NO_SYSTEM_OBJECTS || \
			  attribute == CRYPT_IATTRIBUTE_STATUS );
	REQUIRES( sanityCheckObject( objectInfoPtr ) );

	switch( attribute )
		{
		/* User-accessible properties */
		case CRYPT_PROPERTY_HIGHSECURITY:
			/* This is a combination property that makes an object owned,
			   non-forwardable, and locked */
			if( TEST_FLAG( objectInfoPtr->flags, OBJECT_FLAG_ATTRLOCKED ) )
				return( CRYPT_ERROR_PERMISSION );
#ifdef USE_THREADS
			objectInfoPtr->objectOwner = THREAD_SELF();
#endif /* USE_THREADS */
			objectInfoPtr->forwardCount = 0;
			SET_FLAGS( objectInfoPtr->flags, 
					   OBJECT_FLAG_ATTRLOCKED | OBJECT_FLAG_OWNED );
			break;

		case CRYPT_PROPERTY_OWNER:
			/* This property can still be changed (even if the object is
			   locked) until the forwarding count drops to zero, otherwise
			   locking the object would prevent any forwarding */
			if( objectInfoPtr->forwardCount != CRYPT_UNUSED )
				{
				if( objectInfoPtr->forwardCount <= 0 )
					return( CRYPT_ERROR_PERMISSION );
				objectInfoPtr->forwardCount--;
				}
			if( value == CRYPT_UNUSED )
				CLEAR_FLAG( objectInfoPtr->flags, OBJECT_FLAG_OWNED );
			else
				{
#if defined( USE_THREADS ) 
				/* See the comment in getPropertyAttribute() about the use 
				   of scalar vs. non-scalar thread types */
  #ifdef NONSCALAR_HANDLES
				if( sizeof( objectInfoPtr->objectOwner ) <= sizeof( int ) )
  #endif /* NONSCALAR_HANDLES */
					{
					objectInfoPtr->objectOwner = ( THREAD_HANDLE ) value;
					SET_FLAG( objectInfoPtr->flags, OBJECT_FLAG_OWNED );
					}
#endif /* USE_THREADS */
				}
			break;

		case CRYPT_PROPERTY_FORWARDCOUNT:
			if( TEST_FLAG( objectInfoPtr->flags, OBJECT_FLAG_ATTRLOCKED ) )
				return( CRYPT_ERROR_PERMISSION );
			if( objectInfoPtr->forwardCount != CRYPT_UNUSED && \
				objectInfoPtr->forwardCount < value )
				{
				/* Once set the forward count can only be decreased, never
				   increased */
				return( CRYPT_ERROR_PERMISSION );
				}
			objectInfoPtr->forwardCount = value;
			break;

		case CRYPT_PROPERTY_LOCKED:
			/* Precondition: This property can only be set to true */
			REQUIRES( value != FALSE );

			SET_FLAG( objectInfoPtr->flags, OBJECT_FLAG_ATTRLOCKED );
			break;

		case CRYPT_PROPERTY_USAGECOUNT:
			if( TEST_FLAG( objectInfoPtr->flags, 
						   OBJECT_FLAG_ATTRLOCKED ) || \
				( objectInfoPtr->usageCount != CRYPT_UNUSED && \
				  objectInfoPtr->usageCount < value ) )
				{
				/* Once set the usage count can only be decreased, never
				   increased */
				return( CRYPT_ERROR_PERMISSION );
				}
			objectInfoPtr->usageCount = value;
			break;

		/* Internal properties */
		case CRYPT_IATTRIBUTE_STATUS:
			/* We're clearing an error/abnormal state */
			REQUIRES( value == CRYPT_OK );

			if( isInvalidObjectState( objectHandle ) )
				{
				/* If the object is in an abnormal state, we can only (try to)
				   return it back to the normal state after the problem is
				   resolved */
				REQUIRES( value == CRYPT_OK );

				/* If we're processing a notification from the caller that
				   the object init is complete and the object was destroyed
				   while it was being created (which sets its state to
				   CRYPT_ERROR_SIGNALLED), tell the caller to convert the
				   message to a destroy object message unless it's a system
				   object, which can't be explicitly destroyed.  In this case
				   we just return an error so the cryptlib init fails */
				if( TEST_FLAG( objectInfoPtr->flags, 
							   OBJECT_FLAG_SIGNALLED ) )
					{
					return( ( objectHandle < NO_SYSTEM_OBJECTS ) ?
							CRYPT_ERROR_SIGNALLED : OK_SPECIAL );
					}

				/* We're transitioning the object to the initialised state */
				REQUIRES( TEST_FLAG( objectInfoPtr->flags, 
									 OBJECT_FLAG_NOTINITED ) );
				CLEAR_FLAG( objectInfoPtr->flags, OBJECT_FLAG_NOTINITED );
				ENSURES( !TEST_FLAG( objectInfoPtr->flags, 
									 OBJECT_FLAG_NOTINITED ) );
				break;
				}

			/* Postcondition: The object is in a valid state */
			ENSURES( !isInvalidObjectState( objectHandle ) );

			break;

		case CRYPT_IATTRIBUTE_INTERNAL:
			{
			int status;

			/* Internal objects can be made external after creation or fetch 
			   from another object like a keyset, but not the other way 
			   round */
			REQUIRES( value == FALSE );

			/* Make the object externally accessible */
			REQUIRES( isInternalObject( objectHandle ) );
			CLEAR_FLAG( objectInfoPtr->flags, OBJECT_FLAG_INTERNAL );

			/* Now that the object is external we need to convert at least 
			   one internal reference to it to an external one */
			status = convertIntToExtRef( objectHandle );
			if( cryptStatusError( status ) )
				return( status );

			break;
			}

		case CRYPT_IATTRIBUTE_ACTIONPERMS:
			{
			const int newPerm = \
					updateActionPerms( objectInfoPtr->actionFlags, value );

			if( cryptStatusError( newPerm ) )
				return( newPerm );
			objectInfoPtr->actionFlags = newPerm;
			break;
			}

		case CRYPT_IATTRIBUTE_LOCKED:
			/* Incremement or decrement the object's lock count depending on
			   whether we're locking or unlocking it */
			if( value )
				{
				/* Precondition: The lock count is positive or zero */
				REQUIRES( objectInfoPtr->lockCount >= 0 );

				objectInfoPtr->lockCount++;

				ENSURES( objectInfoPtr->lockCount < MAX_INTLENGTH );
#ifdef USE_THREADS
				objectInfoPtr->lockOwner = THREAD_SELF();
#endif /* USE_THREADS */
				}
			else
				{
				/* Precondition: The lock count is positive */
				REQUIRES( objectInfoPtr->lockCount > 0 );

				objectInfoPtr->lockCount--;

				ENSURES( objectInfoPtr->lockCount >= 0 );
				}

			/* If it's a certificate, notify it that it should save/restore
			   its internal state */
			if( objectInfoPtr->type == OBJECT_TYPE_CERTIFICATE )
				{
				const MESSAGE_FUNCTION messageFunction = \
								( MESSAGE_FUNCTION ) \
								FNPTR_GET( objectInfoPtr->messageFunction );
				void *objectPtr = DATAPTR_GET( objectInfoPtr->objectPtr );

				ENSURES( messageFunction != NULL );
				ENSURES( objectPtr != NULL );
				( void ) messageFunction( objectPtr, MESSAGE_CHANGENOTIFY, 
										  messageDataPtr, 
										  MESSAGE_CHANGENOTIFY_STATE );
				}
			break;

		default:
			retIntError();
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Update Internal Properties						*
*																			*
****************************************************************************/

/* Increment/decrement the reference counts for an object.  Since references 
   can be either internal or external, we have to handle the two separately.  
   If the last external reference is removed then the object becomes 
   internal-only, if all references are removed then the object is 
   destroyed.
   
   There's an additional reference-count manipulation facility in the 
   attribute-handling mechanism for CRYPT_IATTRIBUTE_INTERNAL, which 
   transfers a reference from internal to external when making an object 
   external */

CHECK_RETVAL \
int incRefCount( IN_HANDLE const int objectHandle, 
				 STDC_UNUSED const int dummy1,
				 STDC_UNUSED const void *dummy2, 
				 IN_BOOL const BOOLEAN isInternal )
	{
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	int *referenceCountPtr = isInternal ? \
							 &objectTable[ objectHandle ].intRefCount : \
							 &objectTable[ objectHandle ].extRefCount;
	ORIGINAL_INT_VAR( oldRefCount, *referenceCountPtr );

	/* Preconditions.  Since there are two reference counts, the one that 
	   we're updating can be zero if the other one is nonzero */
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( isBooleanValue( isInternal ) );
	REQUIRES( isShortIntegerRange( *referenceCountPtr ) );

	/* Make sure that we don't try and increment a reference count a 
	   suspicious number of times */
	if( *referenceCountPtr >= MAX_INTLENGTH_SHORT - 1 )
		return( CRYPT_ARGERROR_OBJECT );

	/* Increment the object's reference count */
	( *referenceCountPtr )++;

	/* Postcondition: We incremented the reference count and it's now greater
	   than zero (the ground state) */
	ENSURES( isShortIntegerRangeNZ( *referenceCountPtr ) );
	ENSURES( *referenceCountPtr == ORIGINAL_VALUE( oldRefCount ) + 1 );

	return( CRYPT_OK );
	}

CHECK_RETVAL \
int decRefCount( IN_HANDLE const int objectHandle, 
				 STDC_UNUSED const int dummy1,
				 STDC_UNUSED const void *dummy2, 
				 IN_BOOL const BOOLEAN isInternal )
	{
	KERNEL_DATA *krnlData = getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	int *referenceCountPtr = isInternal ? \
							 &objectTable[ objectHandle ].intRefCount : \
							 &objectTable[ objectHandle ].extRefCount;
	int status;
	ORIGINAL_INT_VAR( oldRefCount, *referenceCountPtr );

	/* Preconditions */
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( isBooleanValue( isInternal ) );
	REQUIRES( isShortIntegerRangeNZ( *referenceCountPtr ) );

	/* If the last external reference is about to be destroyed, make the 
	   object internal.  This marks it as invalid for any external access, 
	   so that to the caller it looks like it's been destroyed even if its 
	   internal reference count keeps it active */
	if( !isInternal && !isInternalObject( objectHandle ) && \
		*referenceCountPtr <= 1 )
		{
		SET_FLAG( objectTable[ objectHandle ].flags, OBJECT_FLAG_INTERNAL );
		ENSURES( isInternalObject( objectHandle ) );
		}

	/* Decrement the object's reference count */
	( *referenceCountPtr )--;

	/* Postconditions: We decremented the reference count and it's greater 
	   than or equal to zero (the ground state) */
	ENSURES( *referenceCountPtr >= 0 && \
			 *referenceCountPtr < MAX_INTLENGTH_SHORT - 1 );
	ENSURES( *referenceCountPtr == ORIGINAL_VALUE( oldRefCount ) - 1 );

	/* If there are still references to the object present, there's nothing
	   further to do */
	if( objectTable[ objectHandle ].intRefCount > 0 || \
		objectTable[ objectHandle ].extRefCount > 0 )
		return( CRYPT_OK );

	/* We're about to destroy the object, all references to it have been 
	   removed */
	ENSURES( objectTable[ objectHandle ].extRefCount == 0 && \
			 objectTable[ objectHandle ].intRefCount == 0 );

	/* Destroy the object.  Since this can entail arbitrary amounts of 
	   processing during the object shutdown phase, we have to unlock the 
	   object table around the call */
	MUTEX_UNLOCK( objectTable );
	status = krnlSendNotifier( objectHandle, IMESSAGE_DESTROY );
	MUTEX_LOCK( objectTable );

	return( status );
	}

/* Get/set/clear dependent objects for an object */

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
						STDC_UNUSED const BOOLEAN dummy )
	{
	const OBJECT_INFO *objectTable = \
							getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	int *valuePtr = ( int * ) messageDataPtr, status;

	assert( isReadPtr( messageDataPtr, sizeof( int ) ) );

	/* Preconditions */
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( isValidType( targetType ) );

	/* Clear return value */
	*valuePtr = CRYPT_ERROR;

	status = findTargetType( objectHandle, valuePtr, targetType );
	if( cryptStatusError( status ) )
		{
		/* Postconditions: No dependent object found */
		ENSURES( *valuePtr == CRYPT_ERROR );

		return( CRYPT_ARGERROR_OBJECT );
		}

	/* Postconditions: We found a dependent object */
	ENSURES( isValidObject( *valuePtr ) && \
			 isSameOwningObject( *valuePtr, objectHandle ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int setDependentObject( IN_HANDLE const int objectHandle, 
						IN_ENUM( SETDEP_OPTION ) const int option,
						IN_BUFFER_C( sizeof( int ) ) \
								const void *messageDataPtr,
						STDC_UNUSED const BOOLEAN dummy )
	{
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const OBJECT_INFO *dependentObjectInfoPtr;
	const int dependentObject = *( ( int * ) messageDataPtr );
	const DEPENDENCY_ACL *dependencyACL = NULL;
	LOOP_INDEX i;
	int *objectHandlePtr, status;

	assert( isReadPtr( messageDataPtr, sizeof( int ) ) );

	/* Preconditions: Parameters are valid */
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( option == SETDEP_OPTION_NOINCREF || \
			  option == SETDEP_OPTION_INCREF );
	REQUIRES( isValidHandle( dependentObject ) );
	REQUIRES( sanityCheckObject( objectInfoPtr ) );

	/* Make sure that the object is valid, it may have been signalled after
	   the message was sent */
	if( !isValidObject( dependentObject ) )
		return( CRYPT_ERROR_SIGNALLED );
	dependentObjectInfoPtr = &objectTable[ dependentObject ];
	REQUIRES( sanityCheckObject( dependentObjectInfoPtr ) );
	if( dependentObjectInfoPtr->type == OBJECT_TYPE_DEVICE )
		objectHandlePtr = &objectInfoPtr->dependentDevice;
	else
		objectHandlePtr = &objectInfoPtr->dependentObject;

	/* Basic validity checks: There can't already be a dependent object set */
	if( *objectHandlePtr != CRYPT_ERROR )
		{
		/* There's already a dependent object present and we're trying to
		   overwrite it with a new one, something is seriously wrong */
		retIntError();
		}

	/* More complex validity checks to ensure that the object table is
	   consistent: The object isn't already dependent on the dependent object
	   (making the dependent object then dependent on the object would
	   create a loop), and the object won't be dependent on its own object
	   type unless it's a device dependent on the system device */
	if( ( ( ( objectInfoPtr->type == OBJECT_TYPE_DEVICE ) ? \
			  dependentObjectInfoPtr->dependentDevice : \
			  dependentObjectInfoPtr->dependentObject ) == objectHandle ) || \
		( objectInfoPtr->type == dependentObjectInfoPtr->type && \
		  dependentObject != SYSTEM_OBJECT_HANDLE ) )
		retIntError();

	/* Find the dependency ACL entry for this object/dependent object
	   combination.  Since there can be more than one dependent object
	   type for an object, we check subtypes as well */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( dependencyACLTbl, DEPENDENCY_ACL ) && \
					dependencyACLTbl[ i ].type != OBJECT_TYPE_NONE,
			  i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, 
									 FAILSAFE_ARRAYSIZE( dependencyACLTbl, \
														 DEPENDENCY_ACL ) - 1 ) );

		if( dependencyACLTbl[ i ].type == objectInfoPtr->type && \
			dependencyACLTbl[ i ].dType == dependentObjectInfoPtr->type && \
			( isValidSubtype( dependencyACLTbl[ i ].dSubTypeA, \
							  dependentObjectInfoPtr->subType ) || \
			  isValidSubtype( dependencyACLTbl[ i ].dSubTypeB, \
							  dependentObjectInfoPtr->subType ) || \
			  isValidSubtype( dependencyACLTbl[ i ].dSubTypeC, \
							  dependentObjectInfoPtr->subType ) ) )
			{
			dependencyACL = &dependencyACLTbl[ i ];
			break;
			}
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( i < FAILSAFE_ARRAYSIZE( dependencyACLTbl, DEPENDENCY_ACL ) );
	ENSURES( dependencyACL != NULL );

	/* Inner precondition: We have the appropriate ACL for this combination
	   of object and dependent object */
	REQUIRES( dependencyACL->type == objectInfoPtr->type && \
			  dependencyACL->dType == dependentObjectInfoPtr->type && \
			  ( isValidSubtype( dependencyACL->dSubTypeA, \
								dependentObjectInfoPtr->subType ) || \
				isValidSubtype( dependencyACL->dSubTypeB, \
								dependentObjectInfoPtr->subType ) || \
				isValidSubtype( dependencyACL->dSubTypeC, \
								dependentObjectInfoPtr->subType ) ) );

	/* Type-specific checks.  For PKC context -> cert and cert -> PKC context
	   attaches we should also check that the primary PKC object is a
	   private-key object and the dependent PKC object is a public-key object
	   to catch things like a private key depending on a (public-key) cert,
	   however this requires unlocking the object table in order to send the
	   context a check message.  Since this requires additional precautions,
	   we leave it for updateDependentObjectPerms(), which has to unlock the
	   table for its own update operations */
	ENSURES( isValidSubtype( dependencyACL->subTypeA, \
							 objectInfoPtr->subType ) || \
			 isValidSubtype( dependencyACL->subTypeB, \
							 objectInfoPtr->subType ) || \
			 isValidSubtype( dependencyACL->subTypeC, \
							 objectInfoPtr->subType ) );
	ENSURES( isValidSubtype( dependencyACL->dSubTypeA, \
							 dependentObjectInfoPtr->subType ) || \
			 isValidSubtype( dependencyACL->dSubTypeB, \
							 dependentObjectInfoPtr->subType ) || \
			 isValidSubtype( dependencyACL->dSubTypeC, \
							 dependentObjectInfoPtr->subType ) );

	/* Inner precondition */
	REQUIRES( *objectHandlePtr == CRYPT_ERROR );
	REQUIRES( isSameOwningObject( objectHandle, dependentObject ) );

	/* Certs and contexts have special relationships in that the cert can
	   constrain the use of the context beyond its normal level.  If we're
	   performing this type of object attachment, we have to adjust one
	   object's behaviour based on the permissions of the other one.  We do
	   this before we increment the reference count because the latter can
	   never fail so we don't have to worry about undoing the update */
	if( dependencyACL->flags & DEP_FLAG_UPDATEDEP )
		{
		status = updateDependentObjectPerms( objectHandle, dependentObject );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Update the dependent object's reference count if required and record
	   the new status in the object table.  Dependent objects can be
	   established in one of two ways, by taking an existing object and
	   attaching it to another object (which increments its reference count,
	   since it's now being referred to by the original owner and by the
	   object it's  attached to), or by creating a new object and attaching
	   it to another object (which doesn't increment the reference count
	   since it's only referred to by the controlling object).  An example of
	   the former operation is adding a context from a cert request to a cert
	   (the cert request is referenced by both the caller and the cert), an
	   example of the latter operation is attaching a data-only cert to a
	   context (the cert is only referenced by the context) */
	if( option == SETDEP_OPTION_INCREF )
		{
		status = incRefCount( dependentObject, 0, NULL, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}
	*objectHandlePtr = dependentObject;

	/* Postconditions */
	ENSURES( isValidObject( *objectHandlePtr ) && \
			 isSameOwningObject( objectHandle, *objectHandlePtr ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int clearDependentObject( IN_HANDLE const int objectHandle, 
						  STDC_UNUSED const int messageValue,
						  STDC_UNUSED const void *messageDataPtr,
						  STDC_UNUSED const BOOLEAN dummy )
	{
	OBJECT_INFO *objectTable = \
					getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	int status;

	/* Preconditions */
	REQUIRES( isValidObject( objectHandle ) );
	REQUIRES( messageValue == 0 && messageDataPtr == NULL );
	REQUIRES( isValidObject( objectInfoPtr->dependentObject ) );

	/* We're about to remove the object reference, decrement its reference 
	   count */
	status = decRefCount( objectInfoPtr->dependentObject, 0, NULL, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Clear the object reference */
	objectInfoPtr->dependentObject = CRYPT_ERROR;

	/* Postconditions: We've cleared the dependent object */
	ENSURES( objectInfoPtr->dependentObject == CRYPT_ERROR );

	return( CRYPT_OK );
	}

/* Clone an object.  The older copy-on-write implementation didn't actually
   do anything at this point except check that the access was valid and set
   the aliased and cloned flags to indicate that the object needed to be
   handled specially if a write access was made to it, but with the kernel
   tracking instance data we can do a copy immediately to create two
   distinct objects */

CHECK_RETVAL \
int cloneObject( IN_HANDLE const int objectHandle, 
				 IN_HANDLE const int clonedObject,
				 STDC_UNUSED const void *dummy1, 
				 STDC_UNUSED const BOOLEAN dummy2 )
	{
	OBJECT_INFO *objectTable = getSystemStorage( SYSTEM_STORAGE_OBJECT_TABLE );
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	OBJECT_INFO *clonedObjectInfoPtr = &objectTable[ clonedObject ];
	const MESSAGE_FUNCTION messageFunction = ( MESSAGE_FUNCTION ) \
							FNPTR_GET( objectInfoPtr->messageFunction );
	void *objectPtr = DATAPTR_GET( objectInfoPtr->objectPtr );
	void *clonedObjectPtr = DATAPTR_GET( clonedObjectInfoPtr->objectPtr );
	int actionFlags, status;

	/* Preconditions */
	REQUIRES( isValidObject( objectHandle ) && \
			  objectHandle >= NO_SYSTEM_OBJECTS );
	REQUIRES( sanityCheckObject( objectInfoPtr ) );
	REQUIRES( objectInfoPtr->type == OBJECT_TYPE_CONTEXT );
	REQUIRES( isValidObject( clonedObject ) && \
			  clonedObject >= NO_SYSTEM_OBJECTS );
	REQUIRES( sanityCheckObject( clonedObjectInfoPtr ) );
	REQUIRES( clonedObjectInfoPtr->type == OBJECT_TYPE_CONTEXT );
	REQUIRES( objectHandle != clonedObject );
	REQUIRES( messageFunction != NULL );
	REQUIRES( objectPtr != NULL );
	REQUIRES( clonedObjectPtr != NULL );

	/* Make sure that the original object is in the high state.  This will
	   have been checked by the caller anyway, but we check again here to
	   make sure */
	if( !isInHighState( objectHandle ) )
		return( CRYPT_ERROR_NOTINITED );

	/* Cloning of non-native contexts is somewhat complex because we usually
	   can't clone a device object, so we have to detect requests to clone
	   these objects and increment their reference count instead.  This
	   isn't a major problem because cryptlib always creates native contexts
	   for clonable algorithms, if the user explicitly overrides this by
	   using their own device-specific context then the usage will usually
	   be create, add to envelope, destroy, so there's no need to clone the
	   context anyway.  The only that time there's a potential problem is if
	   they override the use of native contexts by adding device contexts to
	   multiple envelopes, but in that case it's assumed that they'll be
	   aware of potential problems with this approach */
#if defined( CONFIG_CRYPTO_HW1 ) || defined( CONFIG_CRYPTO_HW2 )
	if( objectInfoPtr->dependentDevice != SYSTEM_OBJECT_HANDLE && \
		objectInfoPtr->dependentDevice != CRYPTO_OBJECT_HANDLE )
#else
	if( objectInfoPtr->dependentDevice != SYSTEM_OBJECT_HANDLE )
#endif /* CONFIG_CRYPTO_HW1 || CONFIG_CRYPTO_HW2 */
		{
		/* This doesn't actually work since it just leaves the clone in an
		   uninitialised state, however no code triggers this for the reason
		   given above */
		DEBUG_PUTS(( "Attempt to clone non-cloneable object" ));
		assert( DEBUG_WARN );
		return( incRefCount( objectHandle, 0, NULL, TRUE ) );
		}

	/* Since this is an internal-use-only object, lock down the action
	   permissions so that only encryption and hash actions from internal
	   sources are allowed (assuming they were allowed to begin with).
	   Keygen is disabled entirely (there should already be a key loaded),
	   and signing isn't possible with a non-PKC object anyway.  This takes
	   advantage of the ratchet enforced for the action permissions, which
	   can only make them more restrictive than the existing permissions, to
	   avoid having to read and modify each permission individually */
	actionFlags = \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_NONE_EXTERNAL );
	status = setPropertyAttribute( clonedObject, CRYPT_IATTRIBUTE_ACTIONPERMS,
								   &actionFlags );
	if( cryptStatusError( status ) )
		return( status );

	/* Postcondition: The cloned object can only be used internally */
	ENSURES( ( clonedObjectInfoPtr->actionFlags & \
								~ACTION_PERM_NONE_EXTERNAL_ALL ) == 0 );

	/* Inner precondition: The instance data is valid and ready to be
	   copied */
	assert( isWritePtrDynamic( objectPtr, objectInfoPtr->objectSize ) );
	assert( isWritePtrDynamic( clonedObjectPtr, \
							   clonedObjectInfoPtr->objectSize ) );
	REQUIRES( objectInfoPtr->objectSize == clonedObjectInfoPtr->objectSize );

	/* Copy across the object contents and reset any instance-specific
	   information.  We only update the owning object if required, in
	   almost all cases this will be the system device so there's no need
	   to perform the update */
	memcpy( clonedObjectPtr, objectPtr, objectInfoPtr->objectSize );
	status = messageFunction( clonedObjectPtr, MESSAGE_CHANGENOTIFY,
							  ( MESSAGE_CAST ) &clonedObject, 
							  MESSAGE_CHANGENOTIFY_OBJHANDLE );
	if( cryptStatusOK( status ) && \
		objectInfoPtr->owner != clonedObjectInfoPtr->owner )
		{
		status = messageFunction( clonedObjectPtr, MESSAGE_CHANGENOTIFY,
								  &clonedObjectInfoPtr->owner,
								  MESSAGE_CHANGENOTIFY_OWNERHANDLE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We've copied across the object's state, the cloned object is now
	   initialised ready for use */
	SET_FLAG( clonedObjectInfoPtr->flags, OBJECT_FLAG_HIGH );

	return( CRYPT_OK );
	}
