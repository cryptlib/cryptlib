<<<<<<< HEAD
/****************************************************************************
*																			*
*					  cryptlib Correctness/Safety Header File 				*
*						Copyright Peter Gutmann 1994-2020					*
*																			*
****************************************************************************/

#ifndef _SAFETY_DEFINED

#define _SAFETY_DEFINED

/****************************************************************************
*																			*
*							Design-by-Contract Predicates					*
*																			*
****************************************************************************/

/* Symbolic defines to handle design-by-contract predicates.  If we're 
   really short of code space, we can save a little extra by turning the 
   predicates into no-ops */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES( x )		if( !( x ) ) retIntError()
#define REQUIRES_N( x )		if( !( x ) ) retIntError_Null()
#define REQUIRES_B( x )		if( !( x ) ) retIntError_Boolean()
#define REQUIRES_V( x )		if( !( x ) ) retIntError_Void()
#define REQUIRES_EXT( x, y )	if( !( x ) ) retIntError_Ext( y )
#define REQUIRES_D( x )		if( !( x ) ) retIntError_Dataptr()
#define REQUIRES_S( x )		if( !( x ) ) retIntError_Stream( stream )

#else

#define REQUIRES( x )
#define REQUIRES_N( x )
#define REQUIRES_B( x )
#define REQUIRES_V( x )
#define REQUIRES_EXT( x, y )
#define REQUIRES_D( x )
#define REQUIRES_S( x )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#define ENSURES				REQUIRES
#define ENSURES_N			REQUIRES_N
#define ENSURES_B			REQUIRES_B
#define ENSURES_V			REQUIRES_V
#define ENSURES_EXT			REQUIRES_EXT
#define ENSURES_D			REQUIRES_D
#define ENSURES_S			REQUIRES_S

/* A special-case form of the REQUIRES() predicate that's used in functions 
   that acquire a mutex.  There are two versions of this, one for cryptlib
   kernel mutexes, denoted by KRNLMUTEX, and one for native mutexes that are
   only visible inside the kernel, denoted by MUTEX */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES_KRNLMUTEX( x, mutex ) \
		if( !( x ) ) \
			{ \
			krnlExitMutex( mutex ); \
			retIntError(); \
			}
#define REQUIRES_KRNLMUTEX_V( x, mutex ) \
		if( !( x ) ) \
			{ \
			krnlExitMutex( mutex ); \
			retIntError_Void(); \
			}

#define REQUIRES_MUTEX( x, mutex ) \
		if( !( x ) ) \
			{ \
			MUTEX_UNLOCK( mutex ); \
			retIntError(); \
			}
#else

#define REQUIRES_KRNLMUTEX( x, mutex )
#define REQUIRES_KRNLMUTEX_V( x, mutex )
#define REQUIRES_MUTEX( x, mutex )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#define ENSURES_KRNLMUTEX	REQUIRES_KRNLMUTEX
#define ENSURES_KRNLMUTEX_V	REQUIRES_KRNLMUTEX_V

#define ENSURES_MUTEX		REQUIRES_MUTEX

/* Another variant of REQUIRES() that releases an object on exit */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES_OBJECT( x, object ) \
		if( !( x ) ) \
			{ \
			krnlReleaseObject( object ); \
			retIntError(); \
			}
#else

#define REQUIRES_OBJECT( x, object )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#define ENSURES_OBJECT		REQUIRES_OBJECT

/* Special-case forms of REQUIRES/ENSURES() for functions that free an 
   object, or allocate and populate the fields in an object, which free the 
   object before exiting */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES_PTR( x, ptr ) \
		if( !( x ) ) \
			retIntError_Ptr( ptr )
#define REQUIRES_V_PTR( x, ptr ) \
		if( !( x ) ) \
			{ \
			clFree( "Internal error", ptr ); \
			retIntError_Void(); \
			}
#define ENSURES_PTR		REQUIRES_PTR
#define ENSURES_N_PTR( x, ptr ) \
		if( !( x ) ) \
			{ \
			clFree( "Internal error", ptr ); \
			retIntError_Null(); \
			}
#else

#define REQUIRES_PTR( x, ptr )
#define REQUIRES_V_PTR( x, ptr )
#define ENSURES_PTR		REQUIRES_PTR
#define ENSURES_N_PTR( x, ptr )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*								Range/Bounds Checks							*
*																			*
****************************************************************************/

/* Check whether an integer value is within range */

#define isIntegerRange( value )	\
		( ( value ) >= 0 && ( value ) < MAX_INTLENGTH )
#define isIntegerRangeNZ( value ) \
		( ( value ) >= 1 && ( value ) < MAX_INTLENGTH )
#define isIntegerRangeMin( value, minLength ) \
		( ( value ) >= ( minLength ) && ( value ) < MAX_INTLENGTH )
#define isShortIntegerRange( value ) \
		( ( value ) >= 0 && ( value ) < MAX_INTLENGTH_SHORT )
#define isShortIntegerRangeNZ( value ) \
		( ( value ) >= 1 && ( value ) < MAX_INTLENGTH_SHORT )
#define isShortIntegerRangeMin( value, minLength ) \
		( ( value ) >= ( minLength ) && ( value ) < MAX_INTLENGTH_SHORT )

/* Buffers are special cases of integer ranges where the maximum size is 
   capped at well below the standard integer range, see the comment in
   misc/const.h for more on this */

#define isBufsizeRange( value )	\
		( ( value ) >= 0 && ( value ) < MAX_BUFFER_SIZE )
#define isBufsizeRangeNZ( value )	\
		( ( value ) > 0 && ( value ) < MAX_BUFFER_SIZE )
#define isBufsizeRangeMin( value, minLength )	\
		( ( value ) >= ( minLength ) && ( value ) < MAX_BUFFER_SIZE )

/* Alongside the integer range check macros we also define one for enum 
   and flag range checks */

#define isEnumRange( value, name ) \
		( ( value ) > name##_NONE && ( value ) < name##_LAST )
#define isEnumRangeOpt( value, name ) \
		( ( value ) >= name##_NONE && ( value ) < name##_LAST )
#define isEnumRangeExternal( value, name ) \
		( ( value ) > name##_NONE && ( value ) < name##_LAST_EXTERNAL )
#define isEnumRangeExternalOpt( value, name ) \
		( ( value ) >= name##_NONE && ( value ) < name##_LAST_EXTERNAL )
#define isFlagRange( value, name ) \
		( ( value ) > name##_FLAG_NONE && ( value ) <= name##_FLAG_MAX )
#define isFlagRangeZ( value, name ) \
		( ( value ) >= name##_FLAG_NONE && ( value ) <= name##_FLAG_MAX )

/* We also define checks for booleans, which have only two permissible
   values */

#define isBooleanValue( value ) \
		( ( value ) == TRUE || ( value ) == FALSE )

/* Perform a range check, verifying that { value } falls within 
   { start, end } */

#define rangeCheck( value, start, end ) \
		( ( ( value ) < ( start ) || ( value ) > ( end ) ) ? FALSE : TRUE )

/* Perform a bounds check on indexes into a block of memory, verifying that 
   { start, length } falls within { 0, totalLength }.  There are two 
   versions of this, the default which requires a nonzero start offset and 
   the special-case variant which also allows a zero start offset.  The
   latter is used for situations like optionally MIME-wrapped data which 
   have a nonzero offset if there's a MIME header to be skipped but a zero 
   offset if it's unencapsulated data */

#define boundsCheck( start, length, totalLength ) \
		( ( ( start ) <= 0 || ( length ) < 1 || \
			( start ) + ( length ) > ( totalLength ) ) ? FALSE : TRUE )
#define boundsCheckZ( start, length, totalLength ) \
		( ( ( start ) < 0 || ( length ) < 1 || \
			( start ) + ( length ) > ( totalLength ) ) ? FALSE : TRUE )

/* Perform a bounds check on pointers to blocks of memory, verifying that an
   inner block of memory is contained entirely within an outer block of 
   memory:

			innerPtr
				v ----- innerLength ---->
		+-------+-----------------------+-------+
		|		|						|		|
		+-------+-----------------------+-------+
		^ ------------- dataLength ------------->
	dataPtr

   This is used for pointers to specific objects within a large encoded data
   block.  Since it's a fairly complex set of checks, it's implemented as a
   function in int_api.c */

CHECK_RETVAL_BOOL \
BOOLEAN pointerBoundsCheck( IN_PTR_OPT const void *data,
							IN_LENGTH_Z const int dataLength,
							IN_PTR_OPT const void *innerData,
							IN_LENGTH_SHORT_Z const int innerDataLength );

/****************************************************************************
*																			*
*							Pointer Validity Checks							*
*																			*
****************************************************************************/

/* Check the validity of a pointer passed to a cryptlib function.  Usually
   the best that we can do is check that it's not NULL, but some OSes allow
   for better checking than this, for example that it points to a block of
   readable or writeable memory.  Under Windows IsBadReadPtr() will always
   succeed if the size is 0, so we have to add a separate check to make sure
   that it's non-NULL.

   For any OS, we check not just for the specific value NULL but for anything
   that appears to be pointing into an unlikely memory range.  This is used
   to catch invalid pointers to elements inside structures, for example:

	struct foo_struct *fooPtr; 
	
	function( &fooPtr->element ); 
	
   where fooPtr is NULL, which will pass in a small integer value as the 
   pointer.  While it won't catch most invalid pointers, it's at least a bit 
   more useful than just checking for NULL.

   There are additional caveats with the use of the Windows memory-checking
   functions.  In theory these would be implemented via VirtualQuery(),
   however this is quite slow, requiring a kernel transition and poking
   around with the page protection mechanisms.  Instead, they try and read
   or write the memory with an exception handler wrapped around the access.
   If the exception is thrown, they fail.  The problem with this way of
   doing things is that if the memory address is a stack guard page used to
   grow the stack (when the system-level exception handler sees an access to
   the bottom-of-stack guard page, it knows that it has to grow the stack)
   *and* the guard page is owned by another thread, IsBadXxxPtr() will catch 
   the exception and the system will never see it, so it can't grow the 
   stack past the current limit (note that this only occurs if the guard 
   page that we hit is owned by a different thread; if we own in then the
   kernel will catch the STATUS_GUARD_PAGE_VIOLATION exception and grow the
   stack as required).  In addition if it's the last guard page then instead 
   of getting an "out of stack" exception, it's turned into a no-op.  The 
   second time the last guard page is hit, the application is terminated by 
   the system, since it's passed its first-chance exception.

   A variation of this is that the calling app could be deliberately passing
   a pointer to a guard page and catching the guard page exception in order
   to dynamically generate the data that would fill the page (this can 
   happen for example when simulating a large address space with pointer 
   swizzling), but this is a pretty weird programming technique that's 
   unlikely to be used with a crypto library.

   A lesser problem is that there's a race condition in the checking in 
   which the memory can be unmapped between the IsBadXxxPtr() check and the 
   actual access, but you'd pretty much have to be trying to actively 
   subvert the checks to do something like this.

   For these reasons we use these functions mostly for debugging, wrapping
   them up in assert()s in most cases where they're used.  Under Windows 
   Vista and newer they've actually been turned into no-ops because of the 
   above problems, although it's probable that they'll be replaced by code 
   to check for NULL pointers, since some of Microsoft's docs indicate that 
   this much checking will still be done.  In addition the type of checking 
   seems to be a function of the Visual C++ libraries used rather than the 
   OS, since VC++ 6 applications still perform the full readability check 
   even under Windows 7 and 8.
   
   If necessary we could also replace the no-op'd out versions with the 
   equivalent code:

	inline BOOL IsBadReadPtr( const VOID *lp, UINT_PTR ucb )
		{
		__try { memcmp( p, p, cb ); }
		__except( EXCEPTION_EXECUTE_HANDLER ) { return( FALSE ); }
		return( TRUE );
		}

	inline BOOL IsBadWritePtr( LPVOID lp, UINT_PTR ucb )
		{
		__try { memset( p, 0, cb ); }
		__except( EXCEPTION_EXECUTE_HANDLER ) { return( FALSE ); }
		return( TRUE );
		} 

   In a number of cases the code is called as 
   isXXXPtr( ptr, sizeof( ptrObject ) ), which causes warnings about 
   constant expressions, to avoid this we define a separate version 
   isXXXPtrConst() that avoids the size check.
   
   Under Unix we could in theory check against _etext but this is too 
   unreliable to use, with shared libraries the single shared image can be 
   mapped pretty much anywhere into the process' address space and there can 
   be multiple _etext's present, one per shared library, it fails with 
   SELinux (which is something you'd expect to see used in combination with 
   code that's been carefully written to do things like perform pointer 
   checking), and who knows what it'll do in combination with different 
   approaches to ASLR.  Because of its high level of nonportability (even on 
   the same system it can break depending on whether something like SELinux 
   is enabled or not) it's too dangerous to enable its use */

#define isValidPointer( ptr )	( ( uintptr_t ) ( ptr ) > 0x0FFFF )

#if defined( __WIN32__ ) || defined( __WINCE__ )
  /* The use of code analysis complicates the pointer-checking macros
	 because they read memory that's uninitialised at that point.  This is
	 fine because we're only checking for readability/writeability, but the
	 analyser doesn't know this and flags it as an error.  To avoid this,
	 we remove the read/write calls when running the analyser */
  #ifdef _PREFAST_
	#define isReadPtr( ptr, size )	( isValidPointer( ptr ) )
	#define isWritePtr( ptr, size )	( isValidPointer( ptr ) )
	#define isReadPtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
	#define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
  #else
	#define isReadPtr( ptr, size )	( isValidPointer( ptr ) && \
									  !IsBadReadPtr( ( ptr ), ( size ) ) )
	#define isWritePtr( ptr, size )	( isValidPointer( ptr ) && \
									  !IsBadWritePtr( ( ptr ), ( size ) ) )
	#define isReadPtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 && \
									  !IsBadReadPtr( ( ptr ), ( size ) ) )
	#define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 && \
									  !IsBadWritePtr( ( ptr ), ( size ) ) )
  #endif /* _PREFAST_ */
#elif defined( __UNIX__ ) && 0		/* See comment above */
  extern int _etext;

  #define isReadPtr( ptr, size )	( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext )
  #define isWritePtr( ptr, size )	( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext )
  #define isReadPtrDynamic( ptr, size )	\
									( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext && \
									  ( size ) > 0 )
  #define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext && \
									  ( size ) > 0 )
#else
  #define isReadPtr( ptr, type )	( isValidPointer( ptr ) )
  #define isWritePtr( ptr, type )	( isValidPointer( ptr ) )
  #define isReadPtrDynamic( ptr, size )	\
									( isValidPointer( ptr ) && ( size ) > 0 )
  #define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
#endif /* Pointer check macros */

/****************************************************************************
*																			*
*						Safe Buffer Management Functions					*
*																			*
****************************************************************************/

/* The size of the canary inserted into a buffer, and a macros to work with
   overall buffer sizes.  SAFEBUFFER_SIZE() takes the data size and 
   calculates the overall buffer size, SAFEBUFFER_DATASIZE() takes the 
   overall buffer size and calculates the data size.  These macros assumes 
   that the size parameter will never even get close to a value where 
   overflow is an issue, which is always the case since we only use it with 
   buffers under MAX_BUFSIZE */

#define SAFEBUFFER_COOKIE_SIZE	( sizeof( uintptr_t ) )

#define SAFEBUFFER_SIZE( size )	( SAFEBUFFER_COOKIE_SIZE + ( size ) + \
								  SAFEBUFFER_COOKIE_SIZE )
#define SAFEBUFFER_DATASIZE( bufSize ) \
								( ( bufSize ) - ( SAFEBUFFER_COOKIE_SIZE + \
												  SAFEBUFFER_COOKIE_SIZE ) )
#define SAFEBUFFER_PTR( bufPtr ) \
								( ( ( BYTE * ) bufPtr ) + SAFEBUFFER_COOKIE_SIZE )

/* Manage canaried buffers that check for writes outside the bounds of the
   buffer.  For a statically allocated buffer this is used as:
   
	BYTE buffer[ SAFEBUFFER_SIZE( 1024 ) ]; 
	
	safeBufferInit( SAFEBUFFER_PTR( buffer ), 1024 );
	sread( stream, SAFEBUFFER_PTR( buffer ), 1024 ); 
	
   For a dynamically allocated buffer this is used as:

	BYTE bufPtr = malloc( SAFEBUFFER_SIZE( 1024 ) );

	struct->buffer = SAFEBUFFER_PTR( bufPtr );
	struct->bufSize = 1024;
	safeBufferInit( struct->buffer, struct->bufSize ); 

   A combined allocate + init function is:

	buffer = safeBufferAlloc( 1024 ); */

STDC_NONNULL_ARG( ( 1 ) ) \
void safeBufferInit( INOUT_BUFFER_FIXED( bufSize ) void *buffer, 
					 IN_DATALENGTH const int bufSize );
CHECK_RETVAL_PTR \
void *safeBufferAlloc( IN_DATALENGTH const int size );
void safeBufferFree( const void *buffer );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN safeBufferCheck( IN_BUFFER( bufSize ) const void *buffer, 
						 IN_DATALENGTH const int bufSize );

/****************************************************************************
*																			*
*						Control Flow Integrity Checks						*
*																			*
****************************************************************************/

/* Turn a string into an access token, used to maintain control-flow 
   integrity (CFI), implemented as the macro MK_TOKEN().  In it's simplest 
   form it's used as an acess token for a function call to ensure that the 
   function really was called as intended:

	functionName( MK_TOKEN( "functionName", 12 ), ..... );

	int functionName( const ACCESS_TOKEN accessToken, ... )
		{
		REQUIRES( CHECK_TOKEN( "functionName", 12 ) );

		...
		}

    To work with access tokens we need a means of converting a string into 
	an integer value, which we do by hashing it using the preprocessor (on
	compilers with any level of optimisation, so essentially anything where
	-O0 isn't specified).  The hash function is the standard djb hash, 
	'hash = hash * 33 + c' where the initial seed is 5381, with the property 
	that it's good on ASCII strings, which is what we're using it for.  In
	particular it'll hash 6-character lowercase strings into 32 bits with no
	collisions, this isn't something we specifically need since we just need 
	a fairly low probability of collision, but it's a specific property of
	the function that's worth pointing out.  Source of the magic values: 
	Something djb thought up */

#define DJB_SEED				5381
#define DJB_HASH( hash, ch )	( ( ( unsigned int ) ( hash ) * 33 ) + ( BYTE ) ch )

#define DJB_LEN( str )			( sizeof( str ) - 1 )
#define DJB_HASH_1( str )		DJB_HASH( DJB_SEED, str[ 0 ] )
#define DJB_HASH_2( str )		DJB_HASH( DJB_HASH_1( str ), str[ 1 ] )
#define DJB_HASH_3( str )		DJB_HASH( DJB_HASH_2( str ), str[ 2 ] )
#define DJB_HASH_4( str )		DJB_HASH( DJB_HASH_3( str ), str[ 3 ] )
#define DJB_HASH_025( str )		DJB_HASH( DJB_HASH_4( str ), str[ DJB_LEN( str ) / 4 ] )
#define DJB_HASH_050( str )		DJB_HASH( DJB_HASH_025( str ), str[ DJB_LEN( str ) / 2 ] )
#define DJB_HASH_075( str )		DJB_HASH( DJB_HASH_050( str ), str[ ( DJB_LEN( str ) * 3 ) / 4 ] )
#define DJB_HASH_100( str )		DJB_HASH( DJB_HASH_075( str ), str[ DJB_LEN( str ) - 1 ] )

#define MK_TOKEN( key )			DJB_HASH_100( key ) 
#define CHECK_TOKEN( key )		( DJB_HASH_100( key ) == ( accessToken ) )

typedef unsigned int ACCESS_TOKEN;

/* Access tokens are also used to enforce CFI within functions.  The way 
   this works is that an ongoing record of sequence points visited is kept 
   by an accumulator, and at the end of the function the accumulator value 
   is compared to the expected value.  This means that there are two 
   expressions of the control flow, one implicitly coded into the function 
   and a second explicitly stated at the end of the function.  If the final 
   values don't match then there's a problem with the control flow.  
   
   The initial accumulator value used in the CFI protection is derived from 
   the function name:

	accumulator = MK_TOKEN( $function_name );

   with subsequent updates being the hash of the sequence point name:

	updateAccumulator( accumulator, MK_TOKEN( $sequence_point_name ) );

   Finally, the check that all sequence points have been passed in the 
   correct order is performed as:

	check( accumulator,
		   updateAccumulator( MK_TOKEN( $sequence_point_name ),
		   					  MK_TOKEN( $function_name ) ) );

   with the updateAccumulator() calls nested as required by the number of
   sequence points being checked for.

   CFI checking is then performed as follows, via macros that hide the low-
   level details:

	int function( ... )
		{
		CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	
		code;
		CFI_CHECK_UPDATE( sequencePoint1Name ); 
		code;
		CFI_CHECK_UPDATE( sequencePoint2Name ); 
		code;
		CFI_CHECK_UPDATE( sequencePoint3Name ); 

		REQUIRES( CFI_CHECK_SEQUENCE_3( sequencePoint1Name, 
				  						sequencePoint2Name, 
										sequencePoint3Name ) );
		}

   For example consider the following function from the TLS client code:

	int processServerKeyex( ... )
		{
		CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;

		checkHandshakePacketHeader( ... );
		CFI_CHECK_UPDATE( "checkHSPacketHeader" );

		readServerKeyexDH( ... );
		CFI_CHECK_UPDATE( "readServerKeyex" );

		checkKeyexSignature( ... );
		CFI_CHECK_UPDATE( "checkKeyexSignature" );

		krnlSendMessage( ..., IMESSAGE_CTX_ENCRYPT, ... );
		CFI_CHECK_UPDATE( "IMESSAGE_CTX_ENCRYPT" );

		krnlSendMessage( ..., IMESSAGE_CTX_DECRYPT, ... );
		CFI_CHECK_UPDATE( "IMESSAGE_CTX_DECRYPT" );

		REQUIRES( CFI_CHECK_SEQUENCE_5( "checkHSPacketHeader", "readServerKeyex",
										"checkKeyexSignature", "IMESSAGE_CTX_ENCRYPT",
										"IMESSAGE_CTX_DECRYPT" ) );
		return( CRYPT_OK );
		}

   This verifies that the function was entered correctly (rather than a 
   random jump into the middle of the code) and that all of the sequence 
   points were passed before exiting.

   Although this looks rather ugly, most of the work is being done by the 
   preprocessor and not in generated code.  Hopefully no compiler will be 
   smart enough to optimise everything before the CFI_CHECK_SEQUENCE() into 
   a single fixed integer value.
   
   Without reliable access to variadic macros, we have to hardcode the 
   number of arguments into the macro name.  In order to avoid passing large
   numbers of dummy parameters as padding when not all parameters are used,
   we use a helper function cfiCheckSequence() and nest calls to it where
   more parameters need to be handled.  Another reason for using this helper
   function is that it prevents excessively clever compilers from optimising
   away the entire sequence of calculations and the resulting compare of two
   fixed values (in theory a compiler that inlines cfiCheckSequence() could
   still do this, but curently no compiler seems to be able to do this) */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

typedef unsigned int CFI_CHECK_TYPE;
#define CFI_CHECK_VALUE				cfiCheckValue
#ifdef __SUNPRO_C
  /* SunPro C can't do sizeof( __func__ ) (or __FUNCTION__, as an 
	 alternative), a bug that's been present for at least a decade so is 
	 unlikely to ever get fixed.  The best that we can do is substitute
	 __FILE__, which isn't as granular but close enough in most cases
	 since CFI is only used for critical functions */
  #define CFI_FUNCTION_NAME			MK_TOKEN( __FILE__ )
#else
  #define CFI_FUNCTION_NAME			MK_TOKEN( __func__ )
#endif /* Sun braindamage */
#define CFI_CHECK_INIT				CFI_FUNCTION_NAME
#define CFI_CHECK_UPDATE( label ) \
		cfiCheckValue = ( cfiCheckValue << 5 ) + MK_TOKEN( label )
#define CFI_CHECK_SEQUENCE_1( label1 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_2( label1, label2 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							MK_TOKEN( label2 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_3( label1, label2, label3 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							MK_TOKEN( label2 ), MK_TOKEN( label3 ) ) )
#define CFI_CHECK_SEQUENCE_4( label1, label2, label3, label4 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							MK_TOKEN( label4 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_5( label1, label2, label3, label4, label5 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_6( label1, label2, label3, label4, label5, \
							  label6 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							MK_TOKEN( label6 ) ) )
#define CFI_CHECK_SEQUENCE_7( label1, label2, label3, label4, label5, \
							  label6, label7 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
								  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							  MK_TOKEN( label6 ) ), \
							MK_TOKEN( label7 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_8( label1, label2, label3, label4, label5, \
							  label6, label7, label8 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
								  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							  MK_TOKEN( label6 ) ), \
							MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
							( CFI_CHECK_TYPE ) -1 ) )
/* The following are only required for certificate-related functions, which
   have high levels of complexity */
#define CFI_CHECK_SEQUENCE_9( label1, label2, label3, label4, label5, \
							  label6, label7, label8, label9 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
								  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							  MK_TOKEN( label6 ) ), \
							MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
							MK_TOKEN( label9 ) ) )
#define CFI_CHECK_SEQUENCE_10( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
									  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
								  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
								  MK_TOKEN( label6 ) ), \
								MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
								MK_TOKEN( label9 ) ), \
							MK_TOKEN( label10 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_11( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
									  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
								  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
								  MK_TOKEN( label6 ) ), \
								MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
								MK_TOKEN( label9 ) ), \
							MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_12( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
									  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
								  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
								  MK_TOKEN( label6 ) ), \
								MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
								MK_TOKEN( label9 ) ), \
							MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
							MK_TOKEN( label12 ) ) )
#define CFI_CHECK_SEQUENCE_13( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
										  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
									  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
									  MK_TOKEN( label6 ) ), \
									MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
									MK_TOKEN( label9 ) ), \
								MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
								MK_TOKEN( label12 ) ), \
							MK_TOKEN( label13 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_14( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
										  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
									  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
									  MK_TOKEN( label6 ) ), \
									MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
									MK_TOKEN( label9 ) ), \
								MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
								MK_TOKEN( label12 ) ), \
							MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_15( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, label15 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
										  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
									  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
									  MK_TOKEN( label6 ) ), \
									MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
									MK_TOKEN( label9 ) ), \
								MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
								MK_TOKEN( label12 ) ), \
							MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
							MK_TOKEN( label15 ) ) )
#define CFI_CHECK_SEQUENCE_17( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, label15, \
							   label16, label17 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				  cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( \
							cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
											  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
										  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
										  MK_TOKEN( label6 ) ), \
										MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
										MK_TOKEN( label9 ) ), \
									MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
									MK_TOKEN( label12 ) ), \
								MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
								MK_TOKEN( label15 ) ), \
							MK_TOKEN( label16 ), MK_TOKEN( label17 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_18( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, label15, \
							   label16, label17, label18 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				  cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( \
							cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
											  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
										  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
										  MK_TOKEN( label6 ) ), \
										MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
										MK_TOKEN( label9 ) ), \
									MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
									MK_TOKEN( label12 ) ), \
								MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
								MK_TOKEN( label15 ) ), \
							MK_TOKEN( label16 ), MK_TOKEN( label17 ), \
							MK_TOKEN( label18 ) ) )
#define CFI_CHECK_SEQUENCE_20( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, label15, \
							   label16, label17, label18, label19, label20 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				  cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( \
							cfiCheckSequence( \
								cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
												  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
											  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
											  MK_TOKEN( label6 ) ), \
											MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
											MK_TOKEN( label9 ) ), \
										MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
										MK_TOKEN( label12 ) ), \
									MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
									MK_TOKEN( label15 ) ), \
								MK_TOKEN( label16 ), MK_TOKEN( label17 ), \
								MK_TOKEN( label18 ) ), \
							MK_TOKEN( label19 ), MK_TOKEN( label20 ), \
							( CFI_CHECK_TYPE ) -1 ) )

CFI_CHECK_TYPE cfiCheckSequence( const CFI_CHECK_TYPE initValue, 
								 const CFI_CHECK_TYPE label1Value,
								 const CFI_CHECK_TYPE label2Value, 
								 const CFI_CHECK_TYPE label3Value );

#else

typedef unsigned int CFI_CHECK_TYPE;
#define CFI_CHECK_VALUE											cfiCheckValue
#define CFI_CHECK_INIT											0
#define CFI_CHECK_UPDATE( label )
#define CFI_CHECK_SEQUENCE_1( label1 )							0
#define CFI_CHECK_SEQUENCE_2( label1, label2 )					0
#define CFI_CHECK_SEQUENCE_3( label1, label2, label3 )			0
#define CFI_CHECK_SEQUENCE_4( label1, label2, label3, label4 )	0
#define CFI_CHECK_SEQUENCE_5( label1, label2, label3, label4, \
							  label5 )							0
#define CFI_CHECK_SEQUENCE_6( label1, label2, label3, label4, label5, \
							  label6 )							0
#define CFI_CHECK_SEQUENCE_7( label1, label2, label3, label4, label5, \
							  label6, label7 )					0
#define CFI_CHECK_SEQUENCE_8( label1, label2, label3, label4, label5, \
							  label6, label7, label8 )			0
#define CFI_CHECK_SEQUENCE_9( label1, label2, label3, label4, label5, \
							  label6, label7, label8, label9 )	0
#define CFI_CHECK_SEQUENCE_10( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, \
							   label10 )						0
#define CFI_CHECK_SEQUENCE_11( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11 )						0
#define CFI_CHECK_SEQUENCE_12( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12 )				0
#define CFI_CHECK_SEQUENCE_13( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13 )		0
#define CFI_CHECK_SEQUENCE_14( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, \
							   label14 )						0
#define CFI_CHECK_SEQUENCE_15( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, \
							   label14, label15 )				0
#define CFI_CHECK_SEQUENCE_17( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, \
							   label15, label16, label17 )		0
#define CFI_CHECK_SEQUENCE_18( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, \
							   label15, label16, label17, label18 ) \
																0
#define CFI_CHECK_SEQUENCE_20( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, \
							   label15, label16, label17, label18, \
							   label19, label20 )				0

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*								Loop Bounds Checks							*
*																			*
****************************************************************************/

/* Loop bounds used when a more specific constant upper bound isn't 
   available.  The following bounds on loop iterations apply:

	FAILSAFE_SMALL: Expect 1 but can have a few more.
	FAILSAFE_MED: Expect 10-20 but can have a few more.
	FAILSAFE_LARGE: Expect many, but not too many.

  In addition to these values there's a special value 
  FAILSAFE_ITERATIONS_MAX which is equivalent to the ASN.1 (1...MAX) 
  construct in setting an upper bound on loop iterations without necessarily 
  setting any specific limit:

	FAILSAFE_MAX: A value that's unlikely to be reached during normal 
				  operation, but that also won't result in an excessive 
				  stall if it's exceeded */

#define FAILSAFE_ITERATIONS_SMALL	10
#define FAILSAFE_ITERATIONS_MED		50
#define FAILSAFE_ITERATIONS_LARGE	1000
#define FAILSAFE_ITERATIONS_MAX		min( 100000L, INT_MAX )

/* Pseudo-constants used for array bounds-checking.  These provide a more
   precise limit than the FAILSAFE_ITERATIONS_xxx values above.  We subtract
   one from the total count because static arrays are always overallocated 
   with two extra dummy elements at the end */

#define FAILSAFE_ARRAYSIZE( array, elementType ) \
		( ( sizeof( array ) / sizeof( elementType ) ) - 1 )

/* In order to provide its availability guarantees, all loops in cryptlib 
   are statically bounded and double-indexed in case of a fault in the
   primary loop index.  In addition the loops are indexed in opposite
   directions to prevent compilers from combining the two loop index 
   variables into one.  So instead of:

	for( i = 0; i < max; i++ )

   the loop construct used is:

	for( i = 0,		_iterationCount = FAILSAFE_ITERATIONS_XXX;
		 i < max && _iterationCount > 0;
		 i++,		_iterationCount-- )

   (in practice the static bounds check is performed before the dynamic one).

   In order to hide the resulting complexity and to ensure a consistent
   implementation, the overall construct is mangled through macros so that
   the above becomes:

	LOOP_INDEX i;

	LOOP_MED( i = 0, i < max, i++ )
		{
		<loop body>;
		}
	ENSURES( LOOP_BOUND_OK );

	LOOP_INDEX_PTR THING_TYPE *thingPtr;

	LOOP_MED( thingPtr = getFirstThing(), thingPtr != NULL, \
			  thingPtr = getNextThing( thingPtr ) )
		{
		<loop body>;
		}
	ENSURES( LOOP_BOUND_OK );

   First we define the loop variables and conditions that we need.  Since we
   can have nested loops, we also define alternative values for a total of 
   up to three levels of nesting */

#define LOOP_ITERATOR				_iterationCount
#define LOOP_ITERATOR_ALT			_innerIterationCount
#define LOOP_ITERATOR_ALT2			_innerInnerIterationCount

#define LOOP_INDEX					int _iterationCount; int
#define LOOP_INDEX_PTR				int _iterationCount; 
#define LOOP_BOUND_INIT( value )	_iterationCount = ( value )
#define LOOP_BOUND_CHECK			( _iterationCount > 0 )
#define LOOP_BOUND_INC				_iterationCount--
#define LOOP_BOUND_OK				LOOP_BOUND_CHECK

#define LOOP_INDEX_ALT				int _innerIterationCount; int
#define LOOP_INDEX_PTR_ALT			int _innerIterationCount; 
#define LOOP_BOUND_INIT_ALT( value ) _innerIterationCount = ( value )
#define LOOP_BOUND_CHECK_ALT		( _innerIterationCount > 0 )
#define LOOP_BOUND_INC_ALT			_innerIterationCount--
#define LOOP_BOUND_OK_ALT			LOOP_BOUND_CHECK_ALT

#define LOOP_INDEX_ALT2				int _innerInnerIterationCount; int
#define LOOP_INDEX_PTR_ALT2			int _innerInnerIterationCount; 
#define LOOP_BOUND_INIT_ALT2( value ) _innerInnerIterationCount = ( value )
#define LOOP_BOUND_CHECK_ALT2		( _innerInnerIterationCount > 0 )
#define LOOP_BOUND_INC_ALT2			_innerInnerIterationCount--
#define LOOP_BOUND_OK_ALT2			LOOP_BOUND_CHECK_ALT2

/* Sometimes there are two loops in the same function that use different 
   index values, for which we still want to indicate that both are loop
   indices.  We can't use LOOP_INDEX twice, so instead we declare any 
   further loop indices as LOOP_INDEX_XXX */

#define LOOP_INDEX_XXX				int

/* Very occasionally the loop index counts down rather than up:

	LOOP_INDEX i;

	LOOP_MED_REV( i = max, i > 0, i-- )
		{
		<loop body>;
		}
	ENSURES( LOOP_BOUND_MED_REV_OK );

   In this situation the second index needs to count up rather than down, and
   the loop bound check needs to be given the maximum count that the loop
   shouldn't exceed:
   
	for( i = max,	_iterationCount = 0;
		 i >= 0 &&	_iterationCount < FAILSAFE_ITERATIONS_XXX;
		 i--,		_iterationCount++ ) */

#define LOOP_BOUND_REV_INIT			_iterationCount = 0
#define LOOP_BOUND_REV_CHECK( value ) ( _iterationCount < ( value ) )
#define LOOP_BOUND_REV_INC			_iterationCount++

#define LOOP_BOUND_REV_INIT_ALT		_innerIterationCount = 0
#define LOOP_BOUND_REV_CHECK_ALT( value ) ( _innerIterationCount < ( value ) )
#define LOOP_BOUND_REV_INC_ALT		_innerIterationCount++

#define LOOP_BOUND_REV_INIT_ALT2	_innerInnerIterationCount = 0
#define LOOP_BOUND_REV_CHECK_ALT2( value ) ( _innerInnerIterationCount < ( value ) )
#define LOOP_BOUND_REV_INC_ALT2		_innerInnerIterationCount++

#define LOOP_BOUND_EXT_REV_OK( value )	LOOP_BOUND_REV_CHECK( value )
#define LOOP_BOUND_EXT_REV_OK_ALT( value )	LOOP_BOUND_REV_CHECK_ALT( value )
#define LOOP_BOUND_EXT_REV_OK_ALT2( value )	LOOP_BOUND_REV_CHECK_ALT2( value )

#define LOOP_BOUND_SMALL_REV_OK		LOOP_BOUND_EXT_REV_OK( FAILSAFE_ITERATIONS_SMALL )
#define LOOP_BOUND_MED_REV_OK		LOOP_BOUND_EXT_REV_OK( FAILSAFE_ITERATIONS_MED )
#define LOOP_BOUND_LARGE_REV_OK		LOOP_BOUND_EXT_REV_OK( FAILSAFE_ITERATIONS_LARGE )
#define LOOP_BOUND_MAX_REV_OK		LOOP_BOUND_EXT_REV_OK( FAILSAFE_ITERATIONS_MAX )

#define LOOP_BOUND_MED_REV_OK_ALT	LOOP_BOUND_EXT_REV_OK_ALT( FAILSAFE_ITERATIONS_MED )
#define LOOP_BOUND_LARGE_REV_OK_ALT	LOOP_BOUND_EXT_REV_OK_ALT( FAILSAFE_ITERATIONS_LARGE )
#define LOOP_BOUND_MAX_REV_OK_ALT	LOOP_BOUND_EXT_REV_OK_ALT( FAILSAFE_ITERATIONS_MAX )

#define LOOP_BOUND_LARGE_REV_OK_ALT2 LOOP_BOUND_EXT_REV_OK_ALT2( FAILSAFE_ITERATIONS_LARGE )

/* With the above we can now create the building blocks for the loops, the
   basic universal form and then more specific forms built on top of that.
   
   Note that when building loops with custom bounds by directly using the 
   _EXT() form with a specific bound rather than wrappers like LOOP_MED(), 
   it's necessary to specify the bound + 1 since the LOOP_BOUND_OK check
   verifies that the hard bound is > 0, not >= 0.  In other words if
   expecting up to XXX_MAX iterations then the bound should be given as
   XXX_MAX + 1.
   
   In addition when using an ENSURES() at the end of the loop then for a 
   bounded array the check is 'index < FAILSAFE_ARRAYSIZE()' since the end-
   of-array marker should be hit before the hard bound is encountered, while 
   for other loop bounds the check is 'index <= bound' since the index will 
   go one past the loop check value */

#define LOOP_EXT( a, b, c, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC, ( c ) )
#define LOOP_EXT_ALT( a, b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT, ( c ) )
#define LOOP_EXT_ALT2( a, b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT2( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT2 && ( b ); \
			 LOOP_BOUND_INC_ALT2, ( c ) )

#define LOOP_EXT_REV( a, b, c, bound ) \
		for( LOOP_BOUND_REV_INIT, ( a ); \
			 LOOP_BOUND_REV_CHECK( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC, ( c ) )
#define LOOP_EXT_REV_ALT( a, b, c, bound ) \
		for( LOOP_BOUND_REV_INIT_ALT, ( a ); \
			 LOOP_BOUND_REV_CHECK_ALT( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC_ALT, ( c ) )
#define LOOP_EXT_REV_ALT2( a, b, c, bound ) \
		for( LOOP_BOUND_REV_INIT_ALT2, ( a ); \
			 LOOP_BOUND_REV_CHECK_ALT2( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC_ALT2, ( c ) )

#define LOOP_SMALL( a, b, c )	LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED( a, b, c )		LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE( a, b, c )	LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX( a, b, c )		LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_SMALL_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_LARGE_ALT2( a, b, c ) \
								LOOP_EXT_ALT2( a, b, c, FAILSAFE_ITERATIONS_LARGE )

#define LOOP_SMALL_REV( a, b, c ) \
								LOOP_EXT_REV( a, b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_REV( a, b, c ) \
								LOOP_EXT_REV( a, b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_REV( a, b, c ) \
								LOOP_EXT_REV( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_REV( a, b, c ) \
								LOOP_EXT_REV( a, b, c, FAILSAFE_ITERATIONS_MAX )
#define LOOP_LARGE_REV_ALT( a, b, c ) \
								LOOP_EXT_REV_ALT( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_LARGE_REV_ALT2( a, b, c ) \
								LOOP_EXT_REV_ALT2( a, b, c, FAILSAFE_ITERATIONS_LARGE )

/* Finally, we need a few specialised subtypes to handle constructs like:

	for( ; i < max ; i++ )

   or even:

	for( ; i < max ; )

   which is really a while() loop */

#define LOOP_EXT_INITCHECK( a, b, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC )
#define LOOP_EXT_INITINC( a, c, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK; \
			 LOOP_BOUND_INC, ( c ) )
#define LOOP_EXT_WHILE( b, bound ) \
		for( LOOP_BOUND_INIT( bound ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC )
#define LOOP_EXT_CHECKINC( b, c, bound ) \
		for( LOOP_BOUND_INIT( bound ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC, ( c ) )

#define LOOP_EXT_REV_INITCHECK( a, b, bound ) \
		for( LOOP_BOUND_REV_INIT, ( a ); \
			 LOOP_BOUND_REV_CHECK( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC )
#define LOOP_EXT_REV_CHECKINC( b, c, bound ) \
		for( LOOP_BOUND_REV_INIT; \
			 LOOP_BOUND_REV_CHECK( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC, ( c ) )

#define LOOP_EXT_INITCHECK_ALT( a, b, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT )
#define LOOP_EXT_WHILE_ALT( b, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT )
#define LOOP_EXT_CHECKINC_ALT( b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT, ( c ) )

#define LOOP_EXT_REV_CHECKINC_ALT( b, c, bound ) \
		for( LOOP_BOUND_REV_INIT_ALT; \
			 LOOP_BOUND_REV_CHECK_ALT( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC_ALT, ( c ) )

#define LOOP_SMALL_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_SMALL ) 
#define LOOP_MED_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_MED ) 
#define LOOP_LARGE_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_LARGE ) 
#define LOOP_MAX_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_MAX ) 

#define LOOP_MED_INITINC( a, c ) \
								LOOP_EXT_INITINC( a, c, FAILSAFE_ITERATIONS_MED )

#define LOOP_SMALL_WHILE( b )	LOOP_EXT_WHILE( b, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_WHILE( b )		LOOP_EXT_WHILE( b, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_WHILE( b )	LOOP_EXT_WHILE( b, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_WHILE( b )		LOOP_EXT_WHILE( b, FAILSAFE_ITERATIONS_MAX )

#define LOOP_SMALL_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_MED_WHILE_ALT( b ) \
								LOOP_EXT_WHILE_ALT( b, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_WHILE_ALT( b ) \
								LOOP_EXT_WHILE_ALT( b, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_WHILE_ALT( b )	LOOP_EXT_WHILE_ALT( b, FAILSAFE_ITERATIONS_MAX )

#define LOOP_MED_INITCHECK_ALT( a, b ) \
								LOOP_EXT_INITCHECK_ALT( a, b, FAILSAFE_ITERATIONS_MED ) 
#define LOOP_MAX_INITCHECK_ALT( a, b ) \
								LOOP_EXT_INITCHECK_ALT( a, b, FAILSAFE_ITERATIONS_LARGE ) 

#define LOOP_MED_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_MED_REV_INITCHECK( a, b ) \
								LOOP_EXT_REV_INITCHECK( a, b, FAILSAFE_ITERATIONS_MED ) 
#define LOOP_LARGE_REV_INITCHECK( a, b ) \
								LOOP_EXT_REV_INITCHECK( a, b, FAILSAFE_ITERATIONS_LARGE ) 
#define LOOP_MAX_REV_INITCHECK( a, b ) \
								LOOP_EXT_REV_INITCHECK( a, b, FAILSAFE_ITERATIONS_MAX ) 
#define LOOP_SMALL_REV_CHECKINC( b, c ) \
								LOOP_EXT_REV_CHECKINC( b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_REV_CHECKINC( b, c ) \
								LOOP_EXT_REV_CHECKINC( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_REV_CHECKINC( b, c ) \
								LOOP_EXT_REV_CHECKINC( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_REV_CHECKINC( b, c ) \
								LOOP_EXT_REV_CHECKINC( b, c, FAILSAFE_ITERATIONS_MAX )
#define LOOP_MED_REV_CHECKINC_ALT( b, c ) \
								LOOP_EXT_REV_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_REV_CHECKINC_ALT( b, c ) \
								LOOP_EXT_REV_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_REV_CHECKINC_ALT( b, c ) \
								LOOP_EXT_REV_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MAX )

/* The double-indexed loop allows us to apply loop invariants.  Alongside 
   checking that the index remains within bounds, we can also verify that 
   the sum of the primary and secondary index variables match the loop 
   bound */

#define LOOP_INVARIANT_EXT( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) - ( lowerBound ) + _iterationCount == ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) - ( lowerBound ) + _innerIterationCount == ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_ALT2( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) - ( lowerBound ) + _innerInnerIterationCount == ( loopBound ) ) )

#define LOOP_INVARIANT_SMALL( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_SMALL_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_LARGE_ALT2( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT2( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )

/* Loops where the index variable counts downwards are slightly different 
   since the secondary index starts from zero rather than the loop bound, so 
   there's only one way of expressing the invariant */ 

#define LOOP_INVARIANT_REV( index, lowerBound, upperBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) + _iterationCount == ( upperBound ) ) )
#define LOOP_INVARIANT_REV_ALT( index, lowerBound, upperBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) + _innerIterationCount == ( upperBound ) ) )
#define LOOP_INVARIANT_REV_ALT2( index, lowerBound, upperBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) + _innerInnerIterationCount == ( upperBound ) ) )

/* Some loops have no fixed relationship between the primary and secondary 
   index variables.  For example the following loops have this property:

	i = ...;
	...;
	for( ; i < 5; i++ )
		{ }

	for( i = 0; i < 10; i +=2 )
		{ }

  In this case we can't perform a check for a fixed relationship between the
  primary and secondary index variables but can only check that the primary
  is within the given bounds and the secondary is within the loop bounds.
  
  We need two forms of the check, one for standard loops for which the 
  secondary counts down from MAX...1, the other for reverse loops for which
  the secondary counts up from 0...MAX-1 */

#define LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _iterationCount > 0 && _iterationCount <= ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_XXX_ALT( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _innerIterationCount > 0 && _innerIterationCount <= ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_XXX_ALT2( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _innerInnerIterationCount > 0 && _innerInnerIterationCount <= ( loopBound ) ) )

#define LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _iterationCount >= 0 && _iterationCount < ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_REV_XXX_ALT( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _innerIterationCount >= 0 && _innerIterationCount < ( loopBound ) ) )

#define LOOP_INVARIANT_SMALL_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )
#define LOOP_INVARIANT_MED_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_SMALL_REV_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED_REV_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_REV_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_REV_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_MED_REV_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_REV_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_REV_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

/* Sometimes there's no loop index variable, for example when we're walking 
   down a linked list.  In this case only the hidden second iterator is 
   present and checked */

#define LOOP_INVARIANT_EXT_GENERIC( loopBound ) \
		( _iterationCount > 0 && _iterationCount <= ( loopBound ) )
#define LOOP_INVARIANT_EXT_ALT_GENERIC( loopBound ) \
		( _innerIterationCount > 0 && _innerIterationCount <= ( loopBound ) )

#define LOOP_INVARIANT_SMALL_GENERIC() \
		LOOP_INVARIANT_EXT_GENERIC( FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED_GENERIC() \
		LOOP_INVARIANT_EXT_GENERIC( FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_GENERIC() \
		LOOP_INVARIANT_EXT_GENERIC( FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_GENERIC() \
		LOOP_INVARIANT_EXT_GENERIC( FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_MED_ALT_GENERIC() \
		LOOP_INVARIANT_EXT_ALT_GENERIC( FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_ALT_GENERIC() \
		LOOP_INVARIANT_EXT_ALT_GENERIC( FAILSAFE_ITERATIONS_LARGE )

/* Sometimes there are two loop variables, with the second being used as a
   secondary index rather than the main loop variable.  In this case all
   that we can do is verify that it remains within bounds */

#define LOOP_INVARIANT_SECONDARY( index, lowerBound, upperBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) )

/* These constructs however now run into conflict with both compilers in 
   general and various optimisers in particular.  Consider the following 
   block of test code:

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i;
		unsigned int j;

		for( i = 0; i < 512; i++ )
			array[ i ] = 5;
		doStuff( array );

		for( j = 0; j < 512; j++ )
			array[ j ] = 3;
		doStuff( array );

		return( 0 );
		}

   When compiled with gcc this produces:

	gcc -O1/O2 -S temp.c		// -O3 is similar but vectorised

	x86:

	.L2:	movl $5, (%rax)		# store $5 to address
			addq $4, %rax		# increment address pointer
			cmpq %rbp, %rax		# compare to bound
			jne .L2				# loop if not equal

	.L3:	movl $3, (%rbx)		# store $3 to address
			addq $4, %rbx		# increment address pointer
			cmpq %rbp, %rbx		# compare to bound
			jne .L3				# loop if not equal

	Arm64:

			mov w1, 5
	.L3:	str w1, [x0],4		# store word from W1 to address X0, add 4
			cmp x0, x19			# compare to limit in X19
			bne .L3				# loop if not equal

			mov w1, 3
	.L5:	str w1, [x0],4		# store word from W1 to address X0, add 4
			cmp x0, x19			# compare to limit in X19
			bne .L5				# loop if not equal

	MIPS64:

			li $3,5
	$L2:	sw $3,0($2)			# store data
			addiu $2,$2,4		# increment address pointer
			bne $2,$17,$L2		# loop if not equal

			li $2,3
	$L3:	sw $2,0($16)		# store data
			addiu $16,$16,4		# increment address pointer
			bne $16,$17,$L3		# loop if not equal

	PPC64:

			li 8,512
			mtctr 8				# move 512 to CTR register via GPR 8
			li 10,5
	.L3:	stwu 10,4(9)		# store word with update from GPR 10
			bdnz .L3			# decrement count, branch if nonzero

			li 8,512
			mtctr 8				# move 512 to CTR register via GPR 8
			li 10,3
	.L5:	stwu 10,4(9)		# store word with update from GPR 10
			bdnz .L5			# decrement count, branch if nonzero

	RISC-V:

			li a4,5
	.L2:	sw a4,0(a5)			# store word in A4 in address
			addi a5,a5,4		# increment address pointer
			bne a5,s1,.L2		# branch if address less than bound

			li a5,3
	.L3:	sw a5,0(s0)			# store word in A4 in address
			addi s0,s0,4		# increment address pointer
			bne s0,s1,.L3		# branch if address less than bound

	Sparc64:

			mov 5, %g2
			st %g2, [%g1]
	.L7:	add %g1, 4, %g1		# add 4
			cmp %g1, %i4		# compare to bound
			bne %xcc, .L7		# loop if not equal
			st %g2, [%g1]		# store data in delay slot

			mov 3, %g1
			st %g1, [%i5]
	.L8:	add %i5, 4, %i5		# add 4
			cmp %i5, %i4		# compare to bound
			bne %xcc, .L8		# loop if not equal
			st %g1, [%i5]		# store data in delay slot

   In every case gcc converts the index < bound comparison into an 
   index != bound comparison.  clang is no better:

	clang -O2 -S temp.c

	.LBB0_1:movaps %xmm0, (%rsp,%rax,4)
			...
			movaps %xmm0, 240(%rsp,%rax,4)	# store data via XMMs
			addq $64, %rax		# increment address pointer
			cmpq $512, %rax		# compare to bound
			jne .LBB0_1			# branch if not equal

	.LBB0_3:movaps %xmm0, (%rsp,%rax,4)
			...
			movaps %xmm0, 240(%rsp,%rax,4)	# store data via XMMs
			addq $64, %rax		# increment address pointer
			cmpq $512, %rax		# compare to bound
			jne .LBB0_3			# branch if not equal

			movi v0.4s, #5		# vector load data
	.LBB0_1:add x10, x9, x8
			add x8, x8, #32		# increment address pointer
			cmp x8, #2048		# compare to bound
			stp q0, q0, [x10]	# store quadword register pair
			b.ne .LBB0_1		# branch if not equal

			movi v0.4s, #3		# vector load data
	.LBB0_3:add x9, x19, x8
			add x8, x8, #32		# increment address pointer
			cmp x8, #2048		# compare to bound
			stp q0, q0, [x9]	# store quadword register pair
			b.ne .LBB0_3		# branch if not equal

   System-specific compilers are occasionally better, specifically icc and 
   the Sun compiler, but others are the same as gcc/clang:

	icc -O2 -S temp.c

	..B1.2:	movdqu XMMWORD PTR [rsp+rax*4], xmm0
			...
			movdqu XMMWORD PTR [48+rsp+rax*4], xmm0
			add rax, 16 		# increment address pointer
			cmp rax, 512		# compare to bound
			jb ..B1.2			# branch if below	-- Unsigned compare/branch

	..B1.5:	lea edx, DWORD PTR [4+rax]
			movdqu XMMWORD PTR [rsp+rdx*4], xmm0
			...
			lea esi, DWORD PTR [12+rax]
			movdqu XMMWORD PTR [rsp+rax*4], xmm0
			add eax, 16			# increment address pointer
			cmp eax, 512		# compare to bound
			jb ..B1.5			# branch if below	-- Unsigned compare/branch

	MSVC:

			mov ecx, 32
			mov rdx, 0000000500000005H
	$LL18@main:
			mov QWORD PTR [rax], rdx
			...
			mov QWORD PTR [rax+16], rdx
			lea rax, QWORD PTR [rax+64]
			mov QWORD PTR [rax-40], rdx
			...
			mov QWORD PTR [rax-8], rdx	# store data
			sub rcx, 1			# decrement count
			jne SHORT $LL18@main	# branch if not equal

			mov rcx, 0000000300000003H
	$LL17@main:
			mov QWORD PTR [rax], rcx
			...
			mov QWORD PTR [rax+16], rcx
			lea rax, QWORD PTR [rax+64]
			mov QWORD PTR [rax-40], rcx
			...
			mov QWORD PTR [rax-8], rcx	# store data
			sub rbx, 1			# decrement count
			jne SHORT $LL17@main	# branch if not equal

	xlc -O2 -S temp.c

			cal r4,64(r0)
			mtspr CTR,r4		# move 64 to CTR register via GPR 4
	__L30:	st r0,4(r3)
			...
			st r0,32(r3)		# store data, unrolled
			cal r3,32(r3)		# add 32 to address
			bc BO_dCTR_NZERO,CR0_LT,__L30	# branch if counter nonzero

			cal r4,64(r0)
			mtspr CTR,r4		# move 64 to CTR register via GPR 4
	__L80:	st r0,4(r31)
			...
			st r0,32(r31)		# store data, unrolled
			cal r31,32(r31)		# add 32 to address
			bc BO_dCTR_NZERO,CR0_LT,__L80	# branch if counter nonzero

	cc -O2 -S temp.c	(Solaris)

			or %g0,5,%i5
			st %i5,[%i1]
			or %g0,0,%i0		# zero counter
	.L900000109:
			add %i0,1,%i0		# increment counter
			add %i1,4,%i1		# increment address
			cmp %i0,511			# compare to bound
			ble %icc,.L900000109	# branch if less or equal
			st %i5,[%i1]		# store data in delay slot

			or %g0,3,%i4
			sll %i2,2,%i5
	.L900000108:
			add %i2,1,%i2		# increment counter
			st %i4,[%i5+%i3]	# store data
			cmp %i2,511			# compare to bound
			bleu %icc,.L900000108	# branch if less or equal, unsigned
			sll %i2,2,%i5		# address = counter * 4 in delay slot

   Only when compiled with -O0 does gcc produce the correct code, but it's 
   pretty bad:

			jmp .L2
	.L3:	movl -4(%rbp), %eax	# load address
			cltq				# convert long to quadword
			movl $5, -2064(%rbp,%rax,4) # store data
			addl $1, -4(%rbp)	# increment address
	.L2:	cmpl $511, -4(%rbp)	# compare to bound
			jle .L3				# branch if less or equal

			jmp .L4
	.L5:	movl -8(%rbp), %eax	# load address
			movl $3, -2064(%rbp,%rax,4) # store data
			addl $1, -8(%rbp)	# increment address
	.L4:	cmpl $511, -8(%rbp)	# compare to bound
			jbe .L5				# branch if below or equal

   CompCert, the compiler with a "mathematical proof that the generated 
   executable code behaves exactly as prescribed by the semantics of the 
   source program", actually gets it right:

	ccomp -O2 -S temp.c

	.L100:	leaq 8(%rsp), %rcx
			movslq %r9d, %r10
			movl $5, %r8d
			movl %r8d, 0(%rcx,%r10,4) # store data
			leal 1(%r9d), %r9d
			cmpl $512, %r9d		# compare to bound
			jl .L100			# branch if less than

	.L101:	leaq 8(%rsp), %rax
			movl %edx, %edi
			movl $3, %esi
			movl %esi, 0(%rax,%rdi,4) # store data
			leal 1(%edx), %edx
			cmpl $512, %edx		# compare to bound
			jb .L101			# branch if less than, unsigned

   The downside is that the code is quite inefficient, containing many 
   unnecessary memory accesses and register transfers, and it's not clear
   whether this is a side-effect of semantics-preserving transformations or 
   just poor code generation (the output has remained the same from 3.6
   through 3.11).

   The damage on double-indexed loops is even worse:

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i, __i;

		for( __i = 1000, i = 0; __i > 0 && i < 512; __i--, i++ )
			array[ i ] = 5;
	option1:
		if( __i <= 0 )
			return -1;
		doStuff( array );
	option2:
		if( __i > 0 )
			doStuff( array );

		return( 0 );
		}

	gcc -O2 -S temp.c

	.L2:	movl $5, (%rax)		# store $5 to address
			addq $4, %rax		# increment address pointer
			cmpq %rdx, %rax		# compare to bound
			jne .L2				# loop if not equal
			call doStuff		# unconditional call

   making it identical to the single-indexed loop since the second index has
   been removed entirely, and specifically identical to the unsafe single-
   indexed loop.

   The brute-force solution of making the second index volatile works, but 
   has the expected effect on efficiency:

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i;
		volatile int __i;

		for( __i = 1000, i = 0; __i > 0 && i < 512; __i--, i++ )
			array[ i ] = 5;
		if( __i > 0 )
			doStuff( array );

		return( 0 );
		}

			movl $1000, 2048(%rsp)	# __i = 1000
			xorl %eax, %eax			# i = 0
			movl 2048(%rsp), %edx
			testl %edx, %edx		# check __i > 0
			jle ..B1.6
	..B1.3:	movl $5, (%rsp,%rax,4)	# store data
			incq %rax				# i++
			decl 2048(%rsp)			# __i--
			movl 2048(%rsp), %edx
			testl %edx, %edx		# check __i > 0
			jle ..B1.6
			cmpq $512, %rax			# check i < 512
			jl ..B1.3
	..B1.6:	movl 2048(%rsp), %eax
			testl %eax, %eax		# check __i > 0
			jle ..B1.8

   Trying to make only parts of the access volatile makes things even worse:

	#define FORCE_PRESENCE( var )	( ( volatile int ) ( var ) )
	#define FORCE_PRESENCE( var )	( *( volatile int * ) &( var ) )
									// Both forms produce the same result

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i;
		volatile int __i;

		for( __i = 1000, i = 0; FORCE_PRESENCE( __i ) > 0 && i < 512; __i--, i++ )
			array[ i ] = 5;
		if( __i > 0 )
			doStuff( array );

		return( 0 );
		}

			movl $1000, 12(%rsp)	# __i = 1000
			movl 12(%rsp), %eax		# reload __i from memory
			testl %eax, %eax		# check __i > 0
			jle .L7
			xorl %edx, %edx			# i = 0
			jmp .L5
	.L15:	testl %eax, %eax		# check __i > 0
			jle .L7
	.L5:	movl 12(%rsp), %eax
			addl $1, %edx			# i++
			movl $5, (%rcx)			# store data
			addq $4, %rcx
			subl $1, %eax			# __i--
			cmpl $512, %edx			# i != 512
			movl %eax, 12(%rsp)
			movl 12(%rsp), %eax		# waste some cycles (??)
			jne .L15				# branch from i != 512
	.L7:	movl 12(%rsp), %eax		# reload __i
			testl %eax, %eax		# if __i > 0

   Adding the loop invariant:

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i, __i;

		for( __i = 1000, i = 0; __i > 0 && i < 512; __i--, i++ )
			{
			if( i < 0 || i > 511 || i + __i != 1000 )
				return -1;
			array[ i ] = 5;
			}
		if( __i <= 0 )
			return -1;
		doStuff( array );

		return( 0 );
		}

	gcc -O2 -S temp.c

        movl    $1, %eax
        movq    %rsp, %rdi
.L2:	movl    $5, (%rdi,%rax,4)
        addq    $1, %rax
        cmpq    $512, %rax
        jne     .L2
        call    doStuff@PLT

*/

/****************************************************************************
*																			*
*								Safe Pointers								*
*																			*
****************************************************************************/

/* Error-detecting function and data pointers.  We store two copies of the 
   pointer, the value itself and its bitwise inverse.  If on retrieving them 
   their XOR isn't all-ones then one of the values has been corrupted and 
   the pointer isn't safe to dereference.  

   A linked list of items using safe pointers looks as follows:

	DATAPTR --> listItem {
					...
					DATAPTR --> listItem {
					...				...
					}				DATAPTR --> listItem {
									}				...
													DATAPTR --> NULL
													}

   Walking down a list of safe pointers works as follows:

	LOOP_LARGE( listPtr = DATAPTR_GET( listHead ),
				listPtr != NULL,
				listPtr = DATAPTR_GET( listPtr->next ) )

   When traversing a list (meaning walking from one link to the next looking
   for a particular entry), the access pattern is as above.  When processing
   entries (meaning working with the elements of listPtr), the pattern 
   becomes:

	LOOP_LARGE( listPtr = DATAPTR_GET( listHead ),
				listPtr != NULL,
				listPtr = DATAPTR_GET( listPtr->next ) )
		{
		REQUIRES( sanityCheckListEntry( listPtr ) );

		body;
		}

   Sometimes we need to have both a LIST_ITEM and the DATAPTR that refers 
   to it available.  This occurs when we're working with a mixture of 
   internal-access (LIST_ITEM) and external-access (DATAPTR) functions.  
   The following loop structure allows for this dual access:

	LOOP_LARGE( ( listCursor = listHead,
				  listPtr = DATAPTR_GET( listHead ) ),
				listPtr != NULL,
				( listCursor = listPtr->next,
				  listPtr = DATAPTR_GET( listPtr->next ) ) )

   Dealing with some types of loops is now especially difficult because a 
   pointer can become NULL even after it's been checked for being non-NULL.  
   To see how this can happen, consider a loop to find the end of a linked 
   list:

	LOOP( listPtr = DATAPTR_GET( list ),
		  DATAPTR_ISSET( listPtr->next ),
		  listPtr = DATAPTR_GET( listPtr->next ) )

   Since DATAPTR_GET() can return NULL on a fault, the DATAPTR_ISSET() check
   works as a loop condition check but doesn't guarantee that listPtr is 
   non-NULL in the loop body.  To see how this happens, consider the C loop 
   structure:

	for( init; check; increment )
		body

   This is evaluated as:

	init;
	while( check )
		{
		body;
	continue_label:
		increment;
		}

  So the above loop will be evaluated as:

	listPtr = DATAPTR_GET( list ),
	while( DATAPTR_ISSET( listPtr->next ) )
		{
		body;
		listPtr = DATAPTR_GET( listPtr->next );
		}

   If the DATAPTR_GET() in the increment returns NULL then the check
   DATAPTR_ISSET() will dereference a NULL pointer.

   The workaround for this is to rewrite the loop as:

	LOOP( listPtr = DATAPTR_GET( list ),
		  listPtr != NULL && DATAPTR_ISSET( listPtr->next ),
		  listPtr = DATAPTR_GET( listPtr->next ) )
		{
		body;
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( listPtr != NULL && DATAPTR_ISNULL( listPtr->next ) );

   An alternative workaround, using a temporary variable, is:

	LOOP( ( prevElementPtr = NULL, listPtr = DATAPTR_GET( list ) ), 
		  listPtr != NULL,
		  ( prevElementPtr = listPtr,
			listPtr = DATAPTR_GET( listPtr->next ) ) )
		{
		body;
		}
	ENSURES( LOOP_BOUND_OK );

   The pattern for fetching an attribute from a function that returns a 
   pointer to the attribute is:

	attributeListPtr = findAttribute( attributeListHead, attributeType );
	ENSURES( attributeListPtr != NULL );
	REQUIRES( sanityCheckAttribute( attributeListPtr ) ); */

/* First we need to define the safe pointer type, a primary copy consisting 
   of a pointer and the alternative copy as an equivalent-sized integer.  We 
   could alternately store two copies of the same value but that wouldn't 
   detect identical corruption on both values.  We could also mask the value 
   with a secret seed generated at runtime, but that's more useful for 
   preventing pointer-overwriting attacks than detecting corruption, and 
   it's not clear whether that's a real threat.  Finally, we could actually 
   store a triple modular-redundant copy, but if we're trying to deal with 
   that level of corruption then there are likely to be all sorts of other 
   problems as well that we'd need to handle.
   
   Function pointers get a bit more difficult because there's no equivalent 
   to the 'void *' universal data pointer.  The ostensible reason for this
   is that function and data pointers may not be of the same size, an example
   being IA64, which as part of its "totally idiotic calling conventions"
   (Linus) turns pointers into handles.  Since sizeof( data_ptr ) may not be
   the same as sizeof( fn_ptr ), it follows logically (if you're a compiler
   author, who run on their own very special type of logic) that we can't 
   have a 'void *' equivalent for function pointers.  Because of this, we 
   have to declare a generic void-ish function, typedef'd as 
   FNPTR_FUNCTION_TYPE, and then cast every assignment to/from it to avoid 
   compiler warnings.
   
   An additional complication with function pointers is that for the 
   aforementioned idiotic implementations there's no equivalent to a 
   uintptr_t.  However, this doesn't really affect us because we're not 
   storing a function pointer in a uintptr_t, just using it as a check
   value.  In this case the worst that can happen is that a few bits of a
   not-quite-a-pointer implementation of a function pointer don't get
   checked, but on any sane architecture we'll be OK */

#define FNPTR_TYPE				uintptr_t
#define DATAPTR_TYPE			uintptr_t

typedef void ( *FNPTR_FUNCTION_TYPE )( void );

typedef struct { 
	void *dataPtr; 
	uintptr_t dataCheck; 
	} DATAPTR;
typedef struct { 
	FNPTR_FUNCTION_TYPE fnPtr;
	uintptr_t fnCheck; 
	} FNPTR;

/* Initialisers for the safe pointer data.  This is now a scalar so we need 
   both a means of setting it to NULL and a NULL-equivalent value that we
   can use in places where we'd normally use the constant NULL */

#define FNPTR_INIT				{ NULL, ( FNPTR_TYPE ) ~0 }
#define DATAPTR_INIT			{ NULL, ( DATAPTR_TYPE ) ~0 }

extern const DATAPTR DATAPTR_NULL;
extern const FNPTR FNPTR_NULL;

/* Check safe pointers.  There are now three checks that can be performed 
   rather than the usual two NULL/non-NULL ones, since there's a third 
   possibility, "not valid".  The latter is required because pointers are 
   now tri-state, valid and non-NULL, valid and NULL, and invalid, which is 
   reported as NULL by FN/DATAPTR_GET() and so would be indistinguishable 
   from valid and NULL */

#define FNPTR_ISVALID( name ) \
		( ( ( ( FNPTR_TYPE ) ( name.fnPtr ) ) ^ ( name.fnCheck ) ) == ~0 )
#define DATAPTR_ISVALID( name ) \
		( ( ( ( DATAPTR_TYPE ) ( name.dataPtr ) ) ^ ( name.dataCheck ) ) == ~0 )
#define DATAPTR_ISVALID_PTR( name ) \
		( ( ( ( DATAPTR_TYPE ) ( name->dataPtr ) ) ^ ( name->dataCheck ) ) == ~0 )

#define FNPTR_ISSET( name ) \
		( FNPTR_ISVALID( name ) && ( name.fnPtr ) != NULL )
#define DATAPTR_ISSET( name ) \
		( DATAPTR_ISVALID( name ) && ( name.dataPtr ) != NULL )
#define DATAPTR_ISSET_PTR( name ) \
		( DATAPTR_ISVALID_PTR( name ) && ( name->dataPtr ) != NULL )

#define FNPTR_ISNULL( name ) \
		( FNPTR_ISVALID( name ) && ( name.fnPtr ) == NULL )
#define DATAPTR_ISNULL( name ) \
		( DATAPTR_ISVALID( name ) && ( name.dataPtr ) == NULL )
#define DATAPTR_ISNULL_PTR( name ) \
		( DATAPTR_ISVALID_PTR( name ) && ( name->dataPtr ) == NULL )

/* Set and get safe pointers.  The macros are used as:

	DATAPTR ptrStorage;

	FNPTR_SET( ptrStorage, functionAddress );
	DATAPTR_SET( ptrStorage, dataAddress );

	const PTR_TYPE functionPtr = FNPTR_GET( ptrStorage );
	REQUIRES( functionPtr != NULL );
	PTR_TYPE dataPtr = DATAPTR_GET( ptrStorage );
	REQUIRES( dataPtr != NULL ); */

#define FNPTR_GET( name ) \
		( FNPTR_ISVALID( name ) ? ( name.fnPtr ) : NULL )
#define DATAPTR_GET( name ) \
		( DATAPTR_ISVALID( name ) ? ( name.dataPtr ) : NULL )
#define DATAPTR_GET_PTR( name ) \
		( DATAPTR_ISVALID_PTR( name ) ? ( name->dataPtr ) : NULL )

#define FNPTR_SET( name, value ) \
			{ \
			name.fnPtr = ( FNPTR_FUNCTION_TYPE ) value; \
			name.fnCheck = ( ( FNPTR_TYPE ) ( value ) ) ^ ~0; \
			}
#define DATAPTR_SET( name, value ) \
			{ \
			name.dataPtr = value; \
			name.dataCheck = ( ( DATAPTR_TYPE ) ( value ) ) ^ ~0; \
			}
#define DATAPTR_SET_PTR( namePtr, value ) \
			{ \
			namePtr->dataPtr = value; \
			namePtr->dataCheck = ( ( DATAPTR_TYPE ) ( value ) ) ^ ~0; \
			}

/* Finally, since DATAPTRs are now scalar values rather than pointers, we 
   have to replace some operations that work on pointers with macros that
   deal with the use of scalars */

#define DATAPTR_SAME( name1, name2 ) \
		( ( ( name1 ).dataPtr ) == ( ( name2 ).dataPtr ) )

/****************************************************************************
*																			*
*								Safe Bitflags								*
*																			*
****************************************************************************/

/* Safe bitflags.  These are particularly critical because some of them have
   a considerable influence over how objects are used, for example 
   CONTEXT_FLAG_DUMMY (software vs. external hardware context), 
   DEVICE_FLAG_ACTIVE (device has been unlocked via PIN/password and is 
   ready for use), ENVELOPE_FLAG_ISDEENVELOPE (whether the envelope is used 
   for enveloping or de-enveloping) and so on.  In addition since the flags
   are all packed into a single integer value, corruption of that value will
   upset a large range of flags.

   Because of this critical nature we protect flags by making them safe
   objects, in the same way that pointers are protected.  The macros are used 
   as:

	SAFE_FLAGS flags;
	
	INIT_FLAGS( flags, XXX_FLAG_NONE );
	CHECK_FLAGS( flags, XXX_FLAG_NONE, XXX_FLAG_MAX );
	
	SET_FLAG( flags, XXX_FLAG_YYY );
	if( TEST_FLAG( flags, XXX_FLAG_YYY )
		do_something;
	CLEAR_FLAG( flags, XXX_FLAG_YYY ); */

typedef struct {
	int flagValue, flagCheckValue;
	} SAFE_FLAGS;

/* Initialisers for the safe flags.  We need both static and dynamic 
   initialision mechanisms */

#define SAFE_FLAGS_INIT( value )		{ ( value ), ~( value ) }
#define INIT_FLAGS( flags, value ) \
		( flags ).flagValue = ( value ), ( flags ).flagCheckValue = ~( value )

/* Check safe flags.  The check doubles as a sanity-check, so it both 
   verifies that the flags are valid in the sense of not having been 
   corrupted and that they've been set to an allowed value */

#define CHECK_FLAGS( flags, minRange, maxRange ) \
		( ( ( flags ).flagValue ^ ( flags ).flagCheckValue ) == ~0 && \
		  ( ( flags ).flagValue >= ( minRange ) && \
			( flags ).flagValue <= ( maxRange ) ) )

/* Get, set, and clear flags.  The XXX_FLAG() and XXX_FLAGS() operations do 
   the same thing, so one is aliased to the other */

#define GET_FLAG( flags, value ) \
		( ( flags ).flagValue & ( value ) )
#define SET_FLAG( flags, value ) \
		( flags ).flagValue |= ( value ), ( flags ).flagCheckValue &= ~( value )
#define CLEAR_FLAG( flags, value ) \
		( flags ).flagValue &= ~( value ), ( flags ).flagCheckValue |= ( value )
#define GET_FLAGS		GET_FLAG
#define SET_FLAGS		SET_FLAG
#define CLEAR_FLAGS		CLEAR_FLAG

/* Test a flag.  Unlike the other macros there are two distinct versions of 
   this, TEST_FLAG() checks that a single flag value (or one of a set of 
   values) is set, TEST_FLAGS() checks that all specified flags are set */

#define TEST_FLAG		GET_FLAG
#define TEST_FLAGS( flags, mask, reqFlags ) \
		( GET_FLAG( flags, mask ) == ( reqFlags ) )

/****************************************************************************
*																			*
*								Safe Booleans								*
*																			*
****************************************************************************/

/* Boolean constants.  Since the traditional TRUE = 1, FALSE = 0 only has a 
   single-bit difference between the two and it's going to be used to decide
   things like "access authorised" or "cryptographic verification succeeded",
   we define our own value for TRUE that minimises the chances of a simple
   fault converting one value to another.  In addition we explicitly check
   for equality to TRUE rather than just "is non-zero".

   Contrast this with things like the NXP LPC devices, which use four magic
   values, 0x12345678, 0x87654321, 0x43218765, and 0x4E697370 ('Nisp'), to
   indicate that security is in effect, and the other 4 billion values to
   indicate that no security is in effect (see "Breaking Code Read 
   Protection on the NXP LPC-family Microcontrollers" from RECON BRX 2017),
   or STM's barely-better STM32 16-bit { 0xAA, 0x55 } = no security, 
   { 0xCC, 0x33 } = high security, and the remaining 64K-2 values = medium/
   low security ("Shedding too much Light on a Microcontroller’s Firmware 
   Protection" from WOOT 2017) (the values differ between the F0 and F1, F0
   has 0xAA 0x55, F1 has 0xA5, 0x5A ("On the Security of Drop-in Replacement
   and Counterfeit Microcontrollers", WOOT 2020).

   The bit pattern in the TRUE value is chosen to minimise the chances of an
   SEU or similar fault flipping the value into something else that looks 
   valid.  The bit pattern is:

	0000 0000 1111 1111 0011 0011 1100 1100 || \
	  0	   0	F	 F	  3	   3	C	 C

	0000 1111 0011 1100 0101 0110 1001 1111
	  0	   F	3	 C	  5	   6	9	 F

   with the more important patterns at the LSB end, so we use the best
   subset of patterns no matter what the word size is.
   
   For historic purposes we could also use the sample pattern that's given
   in the Sandia UQS design document "The Unique Signal Concept for 
   Detonation Safety in Nuclear Weapons", further analysed in "Mathematical 
   Aspects of Unique Signal Assessment", with a 24-bit example given on p.19
   of the Sandia doc:
   
	ABAAAABAABAABBBBABBBBAAB
	101111011011000010000110

   or 0xBDB086 but, while cute, this doesn't really give us something that's
   targeted against SEUs or similar, which is what we're principally 
   concerned with */

#ifdef TRUE
  /* If the TRUE value has been redefined externally, remember this so that 
     we can warn about it elsewhere.  We can't #pragma message() here 
	 because it would produce an annoying warning for every single file */ 
  #if TRUE == 1 
	#define TRUE_REDEFINED	1
  #endif /* TRUE == 1 */
  #undef TRUE
#endif /* TRUE */
#if INT_MAX > 0xFFFFFFFFL
  #define TRUE			0x00FF33CC0F3C569F
#elif INT_MAX > 0xFFFF
  #define TRUE			0x0F3C569F
#else
  #define TRUE			0x569F
#endif /* System-specific word size */
#if defined( _MSC_VER ) && VC_GE_2010( _MSC_VER )
  /* VC warns about #if FALSE vs. #ifdef FALSE, since FALSE == 0 */
  #pragma warning( push )
  #pragma warning( disable : 4574 )
#endif /* VS 2010 and above */
#ifdef FALSE
  #if FALSE != 0
	#error Value of FALSE is nonzero, this isnt a boolean FALSE value.
  #endif /* FALSE sanity check */
#else
  #define FALSE			0
#endif /* FALSE */
#if defined( _MSC_VER ) && VC_GE_2010( _MSC_VER )
  #pragma warning( pop )
#endif /* VS 2010 and above */

/* To avoid a circular dependency, misc/analyse.h defines its own versions
   of TRUE and FALSE.  The follwing check ensures that they're consistent
   with what we define here */

#if ( TRUE != ANALYSIS_TRUE ) || ( FALSE != ANALYSIS_FALSE )
  #error TRUE/FALSE is defined differentl to ANALYSIS_TRUE/ANALYSIS_FALSE
#endif /* TRUE != ANALYSIS_TRUE || FALSE != ANALYSIS_FALSE */

/* The fault-detecting value of TRUE is OK for internal use, but for 
   external use we still have to use TRUE = 1, for which we define an
   alternative constant to make it explicit that this is the external-
   use TRUE */

#define TRUE_ALT		1

/* Error-detecting boolean variables, used for critical values where we 
   don't want to risk a single bit-flip converting a value from one to the
   other.  In this case we also define SAFE_BOOL_FALSE to an SEU-immune data 
   value rather than allowing it to be all zeroes.
   
   We also mix in an additional value, currently just set to the constant
   SAFE_BOOL_CONST, to deal with data-injection attacks in which an attacker 
   tries to set a boolean flag to a particular value.   In practice this 
   should be some unpredictable value set at runtime, but for now it's just 
   a no-op placeholder.
   
   The usage is:

	SAFE_BOOLEAN safeBool;

	BOOL_SET( &safeBool );
	BOOL_ISVALID( &safeBool );

	if( BOOL_ISSET( &safeBool ) )
		do_something();
	BOOL_CLEAR( &safeBool ); */

#define SAFE_BOOL_TRUE		TRUE
#if INT_MAX > 0xFFFFFFFFL
  #define SAFE_BOOL_FALSE	0x3300CCFF0FC3F596
#elif INT_MAX > 0xFFFF
  #define SAFE_BOOL_FALSE	0x0FC3F596
#else
  #define SAFE_BOOL_FALSE	0xF596
#endif /* System-specific word size */
#define SAFE_BOOL_CONST		0

typedef struct {
		int value1, value2;
		} SAFE_BOOLEAN;

#define BOOL_SET( name ) \
		{ \
		( name )->value1 = SAFE_BOOL_TRUE; \
		( name )->value2 = SAFE_BOOL_TRUE ^ SAFE_BOOL_CONST; \
		}
#define BOOL_CLEAR( name ) \
		{ \
		( name )->value1 = SAFE_BOOL_FALSE; \
		( name )->value2 = ~SAFE_BOOL_FALSE ^ SAFE_BOOL_CONST; \
		}

#define BOOL_ISSET( name )		( ( ( name )->value1 ^ \
									( name )->value2 ^ SAFE_BOOL_CONST ) == 0 )
#define BOOL_ISCLEAR( name )	( ( ( name )->value1 ^ \
									( name )->value2 ^ SAFE_BOOL_CONST ) == ~0 )
#define BOOL_ISVALID( name )	( BOOL_ISSET( name ) || BOOL_ISCLEAR( name ) )

/****************************************************************************
*																			*
*								Safe Integers								*
*																			*
****************************************************************************/

/* Check for overflow on various arithmetic operations.  In theory we could
   also use compiler-specific intrinsics (see the comment further down) but 
   according to "Understanding Integer Overflow in C/C++" by Dietz, Li, 
   Regehr and Adve, 2012, LLVM at least can aggressively optimise the 
   precondition tests below while the intrinsics aren't optimised much, 
   leading to little gain from using intrinsics.

   By default we check for overflow of MAX_INTLENGTH, which is the safe
   upper bound allowed by cryptlib, if we want to check for standard int
   or long overflow we have to make it explicit.  Note that we check for
   <= / >= since the range checks all enforced a range < MAX, not <= MAX.
   This also means that we couldn't use the compiler intrinsics even if
   they were better-performing than they actually are since they check for
   over at INT_MAX, not MAX_INTLENGTH.

   Strictly speaking the check for b < 0 isn't necessary, we just have to
   change the check type for b if a < 0, but neither a nor b should ever be
   negative so it's a general-purpose check.  This also makes the subtract-
   overflow check a bit of a no-op since we can only overflow if either
   a - (-b) = -ve or (-a) - b = +ve, so just checking for either side being
   negative is enough.  It also simplifies the division check, which would
   normally be b == 0 || a == INT_MIN && b == -1 */

#define checkOverflowAdd( a, b )		( ( a ) < 0 || ( b ) < 0 || \
										  ( a ) >= MAX_INTLENGTH - ( b ) )
#define checkOverflowSub( a, b )		( ( a ) < 0 || ( b ) < 0 || \
										  ( a ) <= -MAX_INTLENGTH + ( b ) )
#define checkOverflowMul( a, b )		( ( a ) < 0 || ( b ) <= 0 || \
										  ( a ) >= MAX_INTLENGTH / ( b ) )
#define checkOverflowDiv( a, b )		( ( a ) < 0 || ( b ) <= 0 )

#define checkOverflowAddInt( a, b )		( ( a ) > INT_MAX - ( b ) )
#define checkOverflowSubInt( a, b )		( ( a ) < INT_MIN + ( b ) )
#define checkOverflowMulInt( a, b )		( ( a ) > INT_MAX / ( b ) )
#define checkOverflowDivInt( a, b )		( ( a ) < 0 || ( b ) <= 0 )
#define checkOverflowAddLong( a, b )	( ( a ) > LONG_MAX - ( b ) )
#define checkOverflowSubLong( a, b )	( ( a ) < LONG_MAX + ( b ) )
#define checkOverflowMulLong( a, b )	( ( a ) > LONG_MAX / ( b ) )
#define checkOverflowDivLong( a, b )	( ( a ) < 0 || ( b ) <= 0 )

/* As an alternative to the above we could also define safe-maths functions 
   that check for overflow, but support is pretty hit and miss, for gcc and 
   clang there's the intrinsics:

	bool __builtin_sadd_overflow( int x, int y, int *sum );
	bool __builtin_smul_overflow( int x, int y, int *prod );

   which compile to two instructions, the arithmetic op and a setcc for 
   the bool, however Windows has:
   
	#define ENABLE_INTSAFE_SIGNED_FUNCTIONS
	#include <intsafe.h>

	HRESULT IntAdd( INT iAugend, INT iAddend, INT *piResult );
	HRESULT IntMult( INT iMultiplicand, INT iMultiplier, INT *piResult );

   which aren't implemented as intrinsics but as "portable" code, producing
   a dozen or more instructions per arithmetic operation and possibly
   function calls depending on what the compiler feels like.  For this 
   reason we don't define these until they're more widely supported as
   intrinsics */

/****************************************************************************
*																			*
*								TMR Data Protection							*
*																			*
****************************************************************************/

/* Perform a bitwise majority decode of a data item, i.e. a bit is 1 if the 
   majority of inputs are 1, otherwise 0.  The standard form for this is:

	#define MAJ( a, b, c )		( a & b ) | ( a & c ) | ( b & c ) )
   
   however the form used below requires one less operation */

#define MAJ( a, b, c )				( ( ( a ) & ( ( b ) | ( c ) ) ) | ( ( b ) & ( c ) ) )
#define SCRUB( a, b, c )			a = b = c = MAJ( a, b, c )

#define TMR_DECLARE( type, value )	type value##A, value##B, value##C
#define TMR_DECLARE_STATIC( type, value ) \
									static type value##A = 0, value##B = 0, value##C = 0
#define TMR_GET( value )			MAJ( value##A, value##B, value##C )
#define TMR_SET( value, data )		value##A = value##B = value##C = ( data )
#define TMR_VALID( value )			( ( value##A == value##B ) && ( value##A == value##C ) )
#define TMR_SCRUB( value )			SCRUB( value##A, value##B, value##C )

/* For the sensitive data that we want to have TMR, what's being protected 
   is a block of memory, not a single value, so we use TMR memory functions
   rather than single-value operations.  The operation involved is:

	status = checksumContextData( ... );
	if( cryptStatusError( status ) )
		status = tmrRecoverData( ... );
	if( cryptStatusError( status ) )
		return( status );

   And occasionally:

	status = tmrSrubData( ... ); */

CHECK_RETVAL \
int tmrRecoverData( INOUT_BUFFER_FIXED( size) void *a, 
					INOUT_BUFFER_FIXED( size) void *b, 
					INOUT_BUFFER_FIXED( size) void *c, 
					IN_LENGTH const int size );
CHECK_RETVAL \
int tmrScrubData( INOUT_BUFFER_FIXED( size) void *a, 
				  INOUT_BUFFER_FIXED( size) void *b, 
				  INOUT_BUFFER_FIXED( size) void *c, 
				  IN_LENGTH const int size );

#endif /* _SAFETY_DEFINED */
=======
/****************************************************************************
*																			*
*					  cryptlib Correctness/Safety Header File 				*
*						Copyright Peter Gutmann 1994-2020					*
*																			*
****************************************************************************/

#ifndef _SAFETY_DEFINED

#define _SAFETY_DEFINED

/****************************************************************************
*																			*
*							Design-by-Contract Predicates					*
*																			*
****************************************************************************/

/* Symbolic defines to handle design-by-contract predicates.  If we're 
   really short of code space, we can save a little extra by turning the 
   predicates into no-ops */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES( x )		if( !( x ) ) retIntError()
#define REQUIRES_N( x )		if( !( x ) ) retIntError_Null()
#define REQUIRES_B( x )		if( !( x ) ) retIntError_Boolean()
#define REQUIRES_V( x )		if( !( x ) ) retIntError_Void()
#define REQUIRES_EXT( x, y )	if( !( x ) ) retIntError_Ext( y )
#define REQUIRES_D( x )		if( !( x ) ) retIntError_Dataptr()
#define REQUIRES_S( x )		if( !( x ) ) retIntError_Stream( stream )

#else

#define REQUIRES( x )
#define REQUIRES_N( x )
#define REQUIRES_B( x )
#define REQUIRES_V( x )
#define REQUIRES_EXT( x, y )
#define REQUIRES_D( x )
#define REQUIRES_S( x )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#define ENSURES				REQUIRES
#define ENSURES_N			REQUIRES_N
#define ENSURES_B			REQUIRES_B
#define ENSURES_V			REQUIRES_V
#define ENSURES_EXT			REQUIRES_EXT
#define ENSURES_D			REQUIRES_D
#define ENSURES_S			REQUIRES_S

/* A special-case form of the REQUIRES() predicate that's used in functions 
   that acquire a mutex.  There are two versions of this, one for cryptlib
   kernel mutexes, denoted by KRNLMUTEX, and one for native mutexes that are
   only visible inside the kernel, denoted by MUTEX */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES_KRNLMUTEX( x, mutex ) \
		if( !( x ) ) \
			{ \
			krnlExitMutex( mutex ); \
			retIntError(); \
			}
#define REQUIRES_KRNLMUTEX_V( x, mutex ) \
		if( !( x ) ) \
			{ \
			krnlExitMutex( mutex ); \
			retIntError_Void(); \
			}

#define REQUIRES_MUTEX( x, mutex ) \
		if( !( x ) ) \
			{ \
			MUTEX_UNLOCK( mutex ); \
			retIntError(); \
			}
#else

#define REQUIRES_KRNLMUTEX( x, mutex )
#define REQUIRES_KRNLMUTEX_V( x, mutex )
#define REQUIRES_MUTEX( x, mutex )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#define ENSURES_KRNLMUTEX	REQUIRES_KRNLMUTEX
#define ENSURES_KRNLMUTEX_V	REQUIRES_KRNLMUTEX_V

#define ENSURES_MUTEX		REQUIRES_MUTEX

/* Another variant of REQUIRES() that releases an object on exit */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES_OBJECT( x, object ) \
		if( !( x ) ) \
			{ \
			krnlReleaseObject( object ); \
			retIntError(); \
			}
#else

#define REQUIRES_OBJECT( x, object )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#define ENSURES_OBJECT		REQUIRES_OBJECT

/* Special-case forms of REQUIRES/ENSURES() for functions that free an 
   object, or allocate and populate the fields in an object, which free the 
   object before exiting */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES_PTR( x, ptr ) \
		if( !( x ) ) \
			retIntError_Ptr( ptr )
#define REQUIRES_V_PTR( x, ptr ) \
		if( !( x ) ) \
			{ \
			clFree( "Internal error", ptr ); \
			retIntError_Void(); \
			}
#define ENSURES_PTR		REQUIRES_PTR
#define ENSURES_N_PTR( x, ptr ) \
		if( !( x ) ) \
			{ \
			clFree( "Internal error", ptr ); \
			retIntError_Null(); \
			}
#else

#define REQUIRES_PTR( x, ptr )
#define REQUIRES_V_PTR( x, ptr )
#define ENSURES_PTR		REQUIRES_PTR
#define ENSURES_N_PTR( x, ptr )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*								Range/Bounds Checks							*
*																			*
****************************************************************************/

/* Check whether an integer value is within range */

#define isIntegerRange( value )	\
		( ( value ) >= 0 && ( value ) < MAX_INTLENGTH )
#define isIntegerRangeNZ( value ) \
		( ( value ) >= 1 && ( value ) < MAX_INTLENGTH )
#define isIntegerRangeMin( value, minLength ) \
		( ( value ) >= ( minLength ) && ( value ) < MAX_INTLENGTH )
#define isShortIntegerRange( value ) \
		( ( value ) >= 0 && ( value ) < MAX_INTLENGTH_SHORT )
#define isShortIntegerRangeNZ( value ) \
		( ( value ) >= 1 && ( value ) < MAX_INTLENGTH_SHORT )
#define isShortIntegerRangeMin( value, minLength ) \
		( ( value ) >= ( minLength ) && ( value ) < MAX_INTLENGTH_SHORT )

/* Buffers are special cases of integer ranges where the maximum size is 
   capped at well below the standard integer range, see the comment in
   misc/const.h for more on this */

#define isBufsizeRange( value )	\
		( ( value ) >= 0 && ( value ) < MAX_BUFFER_SIZE )
#define isBufsizeRangeNZ( value )	\
		( ( value ) > 0 && ( value ) < MAX_BUFFER_SIZE )
#define isBufsizeRangeMin( value, minLength )	\
		( ( value ) >= ( minLength ) && ( value ) < MAX_BUFFER_SIZE )

/* Alongside the integer range check macros we also define one for enum 
   and flag range checks */

#define isEnumRange( value, name ) \
		( ( value ) > name##_NONE && ( value ) < name##_LAST )
#define isEnumRangeOpt( value, name ) \
		( ( value ) >= name##_NONE && ( value ) < name##_LAST )
#define isEnumRangeExternal( value, name ) \
		( ( value ) > name##_NONE && ( value ) < name##_LAST_EXTERNAL )
#define isEnumRangeExternalOpt( value, name ) \
		( ( value ) >= name##_NONE && ( value ) < name##_LAST_EXTERNAL )
#define isFlagRange( value, name ) \
		( ( value ) > name##_FLAG_NONE && ( value ) <= name##_FLAG_MAX )
#define isFlagRangeZ( value, name ) \
		( ( value ) >= name##_FLAG_NONE && ( value ) <= name##_FLAG_MAX )

/* We also define checks for booleans, which have only two permissible
   values */

#define isBooleanValue( value ) \
		( ( value ) == TRUE || ( value ) == FALSE )

/* Perform a range check, verifying that { value } falls within 
   { start, end } */

#define rangeCheck( value, start, end ) \
		( ( ( value ) < ( start ) || ( value ) > ( end ) ) ? FALSE : TRUE )

/* Perform a bounds check on indexes into a block of memory, verifying that 
   { start, length } falls within { 0, totalLength }.  There are two 
   versions of this, the default which requires a nonzero start offset and 
   the special-case variant which also allows a zero start offset.  The
   latter is used for situations like optionally MIME-wrapped data which 
   have a nonzero offset if there's a MIME header to be skipped but a zero 
   offset if it's unencapsulated data */

#define boundsCheck( start, length, totalLength ) \
		( ( ( start ) <= 0 || ( length ) < 1 || \
			( start ) + ( length ) > ( totalLength ) ) ? FALSE : TRUE )
#define boundsCheckZ( start, length, totalLength ) \
		( ( ( start ) < 0 || ( length ) < 1 || \
			( start ) + ( length ) > ( totalLength ) ) ? FALSE : TRUE )

/* Perform a bounds check on pointers to blocks of memory, verifying that an
   inner block of memory is contained entirely within an outer block of 
   memory:

			innerPtr
				v ----- innerLength ---->
		+-------+-----------------------+-------+
		|		|						|		|
		+-------+-----------------------+-------+
		^ ------------- dataLength ------------->
	dataPtr

   This is used for pointers to specific objects within a large encoded data
   block.  Since it's a fairly complex set of checks, it's implemented as a
   function in int_api.c */

CHECK_RETVAL_BOOL \
BOOLEAN pointerBoundsCheck( IN_PTR_OPT const void *data,
							IN_LENGTH_Z const int dataLength,
							IN_PTR_OPT const void *innerData,
							IN_LENGTH_SHORT_Z const int innerDataLength );

/****************************************************************************
*																			*
*							Pointer Validity Checks							*
*																			*
****************************************************************************/

/* Check the validity of a pointer passed to a cryptlib function.  Usually
   the best that we can do is check that it's not NULL, but some OSes allow
   for better checking than this, for example that it points to a block of
   readable or writeable memory.  Under Windows IsBadReadPtr() will always
   succeed if the size is 0, so we have to add a separate check to make sure
   that it's non-NULL.

   For any OS, we check not just for the specific value NULL but for anything
   that appears to be pointing into an unlikely memory range.  This is used
   to catch invalid pointers to elements inside structures, for example:

	struct foo_struct *fooPtr; 
	
	function( &fooPtr->element ); 
	
   where fooPtr is NULL, which will pass in a small integer value as the 
   pointer.  While it won't catch most invalid pointers, it's at least a bit 
   more useful than just checking for NULL.

   There are additional caveats with the use of the Windows memory-checking
   functions.  In theory these would be implemented via VirtualQuery(),
   however this is quite slow, requiring a kernel transition and poking
   around with the page protection mechanisms.  Instead, they try and read
   or write the memory with an exception handler wrapped around the access.
   If the exception is thrown, they fail.  The problem with this way of
   doing things is that if the memory address is a stack guard page used to
   grow the stack (when the system-level exception handler sees an access to
   the bottom-of-stack guard page, it knows that it has to grow the stack)
   *and* the guard page is owned by another thread, IsBadXxxPtr() will catch 
   the exception and the system will never see it, so it can't grow the 
   stack past the current limit (note that this only occurs if the guard 
   page that we hit is owned by a different thread; if we own in then the
   kernel will catch the STATUS_GUARD_PAGE_VIOLATION exception and grow the
   stack as required).  In addition if it's the last guard page then instead 
   of getting an "out of stack" exception, it's turned into a no-op.  The 
   second time the last guard page is hit, the application is terminated by 
   the system, since it's passed its first-chance exception.

   A variation of this is that the calling app could be deliberately passing
   a pointer to a guard page and catching the guard page exception in order
   to dynamically generate the data that would fill the page (this can 
   happen for example when simulating a large address space with pointer 
   swizzling), but this is a pretty weird programming technique that's 
   unlikely to be used with a crypto library.

   A lesser problem is that there's a race condition in the checking in 
   which the memory can be unmapped between the IsBadXxxPtr() check and the 
   actual access, but you'd pretty much have to be trying to actively 
   subvert the checks to do something like this.

   For these reasons we use these functions mostly for debugging, wrapping
   them up in assert()s in most cases where they're used.  Under Windows 
   Vista and newer they've actually been turned into no-ops because of the 
   above problems, although it's probable that they'll be replaced by code 
   to check for NULL pointers, since some of Microsoft's docs indicate that 
   this much checking will still be done.  In addition the type of checking 
   seems to be a function of the Visual C++ libraries used rather than the 
   OS, since VC++ 6 applications still perform the full readability check 
   even under Windows 7 and 8.
   
   If necessary we could also replace the no-op'd out versions with the 
   equivalent code:

	inline BOOL IsBadReadPtr( const VOID *lp, UINT_PTR ucb )
		{
		__try { memcmp( p, p, cb ); }
		__except( EXCEPTION_EXECUTE_HANDLER ) { return( FALSE ); }
		return( TRUE );
		}

	inline BOOL IsBadWritePtr( LPVOID lp, UINT_PTR ucb )
		{
		__try { memset( p, 0, cb ); }
		__except( EXCEPTION_EXECUTE_HANDLER ) { return( FALSE ); }
		return( TRUE );
		} 

   In a number of cases the code is called as 
   isXXXPtr( ptr, sizeof( ptrObject ) ), which causes warnings about 
   constant expressions, to avoid this we define a separate version 
   isXXXPtrConst() that avoids the size check.
   
   Under Unix we could in theory check against _etext but this is too 
   unreliable to use, with shared libraries the single shared image can be 
   mapped pretty much anywhere into the process' address space and there can 
   be multiple _etext's present, one per shared library, it fails with 
   SELinux (which is something you'd expect to see used in combination with 
   code that's been carefully written to do things like perform pointer 
   checking), and who knows what it'll do in combination with different 
   approaches to ASLR.  Because of its high level of nonportability (even on 
   the same system it can break depending on whether something like SELinux 
   is enabled or not) it's too dangerous to enable its use */

#define isValidPointer( ptr )	( ( uintptr_t ) ( ptr ) > 0x0FFFF )

#if defined( __WIN32__ ) || defined( __WINCE__ )
  /* The use of code analysis complicates the pointer-checking macros
	 because they read memory that's uninitialised at that point.  This is
	 fine because we're only checking for readability/writeability, but the
	 analyser doesn't know this and flags it as an error.  To avoid this,
	 we remove the read/write calls when running the analyser */
  #ifdef _PREFAST_
	#define isReadPtr( ptr, size )	( isValidPointer( ptr ) )
	#define isWritePtr( ptr, size )	( isValidPointer( ptr ) )
	#define isReadPtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
	#define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
  #else
	#define isReadPtr( ptr, size )	( isValidPointer( ptr ) && \
									  !IsBadReadPtr( ( ptr ), ( size ) ) )
	#define isWritePtr( ptr, size )	( isValidPointer( ptr ) && \
									  !IsBadWritePtr( ( ptr ), ( size ) ) )
	#define isReadPtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 && \
									  !IsBadReadPtr( ( ptr ), ( size ) ) )
	#define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 && \
									  !IsBadWritePtr( ( ptr ), ( size ) ) )
  #endif /* _PREFAST_ */
#elif defined( __UNIX__ ) && 0		/* See comment above */
  extern int _etext;

  #define isReadPtr( ptr, size )	( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext )
  #define isWritePtr( ptr, size )	( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext )
  #define isReadPtrDynamic( ptr, size )	\
									( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext && \
									  ( size ) > 0 )
  #define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext && \
									  ( size ) > 0 )
#else
  #define isReadPtr( ptr, type )	( isValidPointer( ptr ) )
  #define isWritePtr( ptr, type )	( isValidPointer( ptr ) )
  #define isReadPtrDynamic( ptr, size )	\
									( isValidPointer( ptr ) && ( size ) > 0 )
  #define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
#endif /* Pointer check macros */

/****************************************************************************
*																			*
*						Safe Buffer Management Functions					*
*																			*
****************************************************************************/

/* The size of the canary inserted into a buffer, and a macros to work with
   overall buffer sizes.  SAFEBUFFER_SIZE() takes the data size and 
   calculates the overall buffer size, SAFEBUFFER_DATASIZE() takes the 
   overall buffer size and calculates the data size.  These macros assumes 
   that the size parameter will never even get close to a value where 
   overflow is an issue, which is always the case since we only use it with 
   buffers under MAX_BUFSIZE */

#define SAFEBUFFER_COOKIE_SIZE	( sizeof( uintptr_t ) )

#define SAFEBUFFER_SIZE( size )	( SAFEBUFFER_COOKIE_SIZE + ( size ) + \
								  SAFEBUFFER_COOKIE_SIZE )
#define SAFEBUFFER_DATASIZE( bufSize ) \
								( ( bufSize ) - ( SAFEBUFFER_COOKIE_SIZE + \
												  SAFEBUFFER_COOKIE_SIZE ) )
#define SAFEBUFFER_PTR( bufPtr ) \
								( ( ( BYTE * ) bufPtr ) + SAFEBUFFER_COOKIE_SIZE )

/* Manage canaried buffers that check for writes outside the bounds of the
   buffer.  For a statically allocated buffer this is used as:
   
	BYTE buffer[ SAFEBUFFER_SIZE( 1024 ) ]; 
	
	safeBufferInit( SAFEBUFFER_PTR( buffer ), 1024 );
	sread( stream, SAFEBUFFER_PTR( buffer ), 1024 ); 
	
   For a dynamically allocated buffer this is used as:

	BYTE bufPtr = malloc( SAFEBUFFER_SIZE( 1024 ) );

	struct->buffer = SAFEBUFFER_PTR( bufPtr );
	struct->bufSize = 1024;
	safeBufferInit( struct->buffer, struct->bufSize ); 

   A combined allocate + init function is:

	buffer = safeBufferAlloc( 1024 ); */

STDC_NONNULL_ARG( ( 1 ) ) \
void safeBufferInit( INOUT_BUFFER_FIXED( bufSize ) void *buffer, 
					 IN_DATALENGTH const int bufSize );
CHECK_RETVAL_PTR \
void *safeBufferAlloc( IN_DATALENGTH const int size );
void safeBufferFree( const void *buffer );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN safeBufferCheck( IN_BUFFER( bufSize ) const void *buffer, 
						 IN_DATALENGTH const int bufSize );

/****************************************************************************
*																			*
*						Control Flow Integrity Checks						*
*																			*
****************************************************************************/

/* Turn a string into an access token, used to maintain control-flow 
   integrity (CFI), implemented as the macro MK_TOKEN().  In it's simplest 
   form it's used as an acess token for a function call to ensure that the 
   function really was called as intended:

	functionName( MK_TOKEN( "functionName", 12 ), ..... );

	int functionName( const ACCESS_TOKEN accessToken, ... )
		{
		REQUIRES( CHECK_TOKEN( "functionName", 12 ) );

		...
		}

    To work with access tokens we need a means of converting a string into 
	an integer value, which we do by hashing it using the preprocessor (on
	compilers with any level of optimisation, so essentially anything where
	-O0 isn't specified).  The hash function is the standard djb hash, 
	'hash = hash * 33 + c' where the initial seed is 5381, with the property 
	that it's good on ASCII strings, which is what we're using it for.  In
	particular it'll hash 6-character lowercase strings into 32 bits with no
	collisions, this isn't something we specifically need since we just need 
	a fairly low probability of collision, but it's a specific property of
	the function that's worth pointing out.  Source of the magic values: 
	Something djb thought up */

#define DJB_SEED				5381
#define DJB_HASH( hash, ch )	( ( ( unsigned int ) ( hash ) * 33 ) + ( BYTE ) ch )

#define DJB_LEN( str )			( sizeof( str ) - 1 )
#define DJB_HASH_1( str )		DJB_HASH( DJB_SEED, str[ 0 ] )
#define DJB_HASH_2( str )		DJB_HASH( DJB_HASH_1( str ), str[ 1 ] )
#define DJB_HASH_3( str )		DJB_HASH( DJB_HASH_2( str ), str[ 2 ] )
#define DJB_HASH_4( str )		DJB_HASH( DJB_HASH_3( str ), str[ 3 ] )
#define DJB_HASH_025( str )		DJB_HASH( DJB_HASH_4( str ), str[ DJB_LEN( str ) / 4 ] )
#define DJB_HASH_050( str )		DJB_HASH( DJB_HASH_025( str ), str[ DJB_LEN( str ) / 2 ] )
#define DJB_HASH_075( str )		DJB_HASH( DJB_HASH_050( str ), str[ ( DJB_LEN( str ) * 3 ) / 4 ] )
#define DJB_HASH_100( str )		DJB_HASH( DJB_HASH_075( str ), str[ DJB_LEN( str ) - 1 ] )

#define MK_TOKEN( key )			DJB_HASH_100( key ) 
#define CHECK_TOKEN( key )		( DJB_HASH_100( key ) == ( accessToken ) )

typedef unsigned int ACCESS_TOKEN;

/* Access tokens are also used to enforce CFI within functions.  The way 
   this works is that an ongoing record of sequence points visited is kept 
   by an accumulator, and at the end of the function the accumulator value 
   is compared to the expected value.  This means that there are two 
   expressions of the control flow, one implicitly coded into the function 
   and a second explicitly stated at the end of the function.  If the final 
   values don't match then there's a problem with the control flow.  
   
   The initial accumulator value used in the CFI protection is derived from 
   the function name:

	accumulator = MK_TOKEN( $function_name );

   with subsequent updates being the hash of the sequence point name:

	updateAccumulator( accumulator, MK_TOKEN( $sequence_point_name ) );

   Finally, the check that all sequence points have been passed in the 
   correct order is performed as:

	check( accumulator,
		   updateAccumulator( MK_TOKEN( $sequence_point_name ),
		   					  MK_TOKEN( $function_name ) ) );

   with the updateAccumulator() calls nested as required by the number of
   sequence points being checked for.

   CFI checking is then performed as follows, via macros that hide the low-
   level details:

	int function( ... )
		{
		CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	
		code;
		CFI_CHECK_UPDATE( sequencePoint1Name ); 
		code;
		CFI_CHECK_UPDATE( sequencePoint2Name ); 
		code;
		CFI_CHECK_UPDATE( sequencePoint3Name ); 

		REQUIRES( CFI_CHECK_SEQUENCE_3( sequencePoint1Name, 
				  						sequencePoint2Name, 
										sequencePoint3Name ) );
		}

   For example consider the following function from the TLS client code:

	int processServerKeyex( ... )
		{
		CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;

		checkHandshakePacketHeader( ... );
		CFI_CHECK_UPDATE( "checkHSPacketHeader" );

		readServerKeyexDH( ... );
		CFI_CHECK_UPDATE( "readServerKeyex" );

		checkKeyexSignature( ... );
		CFI_CHECK_UPDATE( "checkKeyexSignature" );

		krnlSendMessage( ..., IMESSAGE_CTX_ENCRYPT, ... );
		CFI_CHECK_UPDATE( "IMESSAGE_CTX_ENCRYPT" );

		krnlSendMessage( ..., IMESSAGE_CTX_DECRYPT, ... );
		CFI_CHECK_UPDATE( "IMESSAGE_CTX_DECRYPT" );

		REQUIRES( CFI_CHECK_SEQUENCE_5( "checkHSPacketHeader", "readServerKeyex",
										"checkKeyexSignature", "IMESSAGE_CTX_ENCRYPT",
										"IMESSAGE_CTX_DECRYPT" ) );
		return( CRYPT_OK );
		}

   This verifies that the function was entered correctly (rather than a 
   random jump into the middle of the code) and that all of the sequence 
   points were passed before exiting.

   Although this looks rather ugly, most of the work is being done by the 
   preprocessor and not in generated code.  Hopefully no compiler will be 
   smart enough to optimise everything before the CFI_CHECK_SEQUENCE() into 
   a single fixed integer value.
   
   Without reliable access to variadic macros, we have to hardcode the 
   number of arguments into the macro name.  In order to avoid passing large
   numbers of dummy parameters as padding when not all parameters are used,
   we use a helper function cfiCheckSequence() and nest calls to it where
   more parameters need to be handled.  Another reason for using this helper
   function is that it prevents excessively clever compilers from optimising
   away the entire sequence of calculations and the resulting compare of two
   fixed values (in theory a compiler that inlines cfiCheckSequence() could
   still do this, but curently no compiler seems to be able to do this) */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

typedef unsigned int CFI_CHECK_TYPE;
#define CFI_CHECK_VALUE				cfiCheckValue
#ifdef __SUNPRO_C
  /* SunPro C can't do sizeof( __func__ ) (or __FUNCTION__, as an 
	 alternative), a bug that's been present for at least a decade so is 
	 unlikely to ever get fixed.  The best that we can do is substitute
	 __FILE__, which isn't as granular but close enough in most cases
	 since CFI is only used for critical functions */
  #define CFI_FUNCTION_NAME			MK_TOKEN( __FILE__ )
#else
  #define CFI_FUNCTION_NAME			MK_TOKEN( __func__ )
#endif /* Sun braindamage */
#define CFI_CHECK_INIT				CFI_FUNCTION_NAME
#define CFI_CHECK_UPDATE( label ) \
		cfiCheckValue = ( cfiCheckValue << 5 ) + MK_TOKEN( label )
#define CFI_CHECK_SEQUENCE_1( label1 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_2( label1, label2 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							MK_TOKEN( label2 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_3( label1, label2, label3 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							MK_TOKEN( label2 ), MK_TOKEN( label3 ) ) )
#define CFI_CHECK_SEQUENCE_4( label1, label2, label3, label4 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							MK_TOKEN( label4 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_5( label1, label2, label3, label4, label5 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_6( label1, label2, label3, label4, label5, \
							  label6 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
							  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							MK_TOKEN( label6 ) ) )
#define CFI_CHECK_SEQUENCE_7( label1, label2, label3, label4, label5, \
							  label6, label7 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
								  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							  MK_TOKEN( label6 ) ), \
							MK_TOKEN( label7 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_8( label1, label2, label3, label4, label5, \
							  label6, label7, label8 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
								  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							  MK_TOKEN( label6 ) ), \
							MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
							( CFI_CHECK_TYPE ) -1 ) )
/* The following are only required for certificate-related functions, which
   have high levels of complexity */
#define CFI_CHECK_SEQUENCE_9( label1, label2, label3, label4, label5, \
							  label6, label7, label8, label9 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
								  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
							  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
							  MK_TOKEN( label6 ) ), \
							MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
							MK_TOKEN( label9 ) ) )
#define CFI_CHECK_SEQUENCE_10( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
									  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
								  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
								  MK_TOKEN( label6 ) ), \
								MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
								MK_TOKEN( label9 ) ), \
							MK_TOKEN( label10 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_11( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
									  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
								  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
								  MK_TOKEN( label6 ) ), \
								MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
								MK_TOKEN( label9 ) ), \
							MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_12( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
									  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
								  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
								  MK_TOKEN( label6 ) ), \
								MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
								MK_TOKEN( label9 ) ), \
							MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
							MK_TOKEN( label12 ) ) )
#define CFI_CHECK_SEQUENCE_13( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
										  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
									  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
									  MK_TOKEN( label6 ) ), \
									MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
									MK_TOKEN( label9 ) ), \
								MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
								MK_TOKEN( label12 ) ), \
							MK_TOKEN( label13 ), \
							( CFI_CHECK_TYPE ) -1, ( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_14( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
										  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
									  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
									  MK_TOKEN( label6 ) ), \
									MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
									MK_TOKEN( label9 ) ), \
								MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
								MK_TOKEN( label12 ) ), \
							MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_15( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, label15 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
										  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
									  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
									  MK_TOKEN( label6 ) ), \
									MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
									MK_TOKEN( label9 ) ), \
								MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
								MK_TOKEN( label12 ) ), \
							MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
							MK_TOKEN( label15 ) ) )
#define CFI_CHECK_SEQUENCE_17( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, label15, \
							   label16, label17 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				  cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( \
							cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
											  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
										  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
										  MK_TOKEN( label6 ) ), \
										MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
										MK_TOKEN( label9 ) ), \
									MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
									MK_TOKEN( label12 ) ), \
								MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
								MK_TOKEN( label15 ) ), \
							MK_TOKEN( label16 ), MK_TOKEN( label17 ), \
							( CFI_CHECK_TYPE ) -1 ) )
#define CFI_CHECK_SEQUENCE_18( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, label15, \
							   label16, label17, label18 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				  cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( \
							cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
											  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
										  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
										  MK_TOKEN( label6 ) ), \
										MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
										MK_TOKEN( label9 ) ), \
									MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
									MK_TOKEN( label12 ) ), \
								MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
								MK_TOKEN( label15 ) ), \
							MK_TOKEN( label16 ), MK_TOKEN( label17 ), \
							MK_TOKEN( label18 ) ) )
#define CFI_CHECK_SEQUENCE_20( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, label15, \
							   label16, label17, label18, label19, label20 ) \
		( cfiCheckValue == \
		  cfiCheckSequence( \
			  cfiCheckSequence( \
				  cfiCheckSequence( \
					cfiCheckSequence( \
						cfiCheckSequence( \
							cfiCheckSequence( \
								cfiCheckSequence( CFI_FUNCTION_NAME, MK_TOKEN( label1 ), \
												  MK_TOKEN( label2 ), MK_TOKEN( label3 ) ), \
											  MK_TOKEN( label4 ), MK_TOKEN( label5 ), \
											  MK_TOKEN( label6 ) ), \
											MK_TOKEN( label7 ), MK_TOKEN( label8 ), \
											MK_TOKEN( label9 ) ), \
										MK_TOKEN( label10 ), MK_TOKEN( label11 ), \
										MK_TOKEN( label12 ) ), \
									MK_TOKEN( label13 ), MK_TOKEN( label14 ), \
									MK_TOKEN( label15 ) ), \
								MK_TOKEN( label16 ), MK_TOKEN( label17 ), \
								MK_TOKEN( label18 ) ), \
							MK_TOKEN( label19 ), MK_TOKEN( label20 ), \
							( CFI_CHECK_TYPE ) -1 ) )

CFI_CHECK_TYPE cfiCheckSequence( const CFI_CHECK_TYPE initValue, 
								 const CFI_CHECK_TYPE label1Value,
								 const CFI_CHECK_TYPE label2Value, 
								 const CFI_CHECK_TYPE label3Value );

#else

typedef unsigned int CFI_CHECK_TYPE;
#define CFI_CHECK_VALUE											cfiCheckValue
#define CFI_CHECK_INIT											0
#define CFI_CHECK_UPDATE( label )
#define CFI_CHECK_SEQUENCE_1( label1 )							0
#define CFI_CHECK_SEQUENCE_2( label1, label2 )					0
#define CFI_CHECK_SEQUENCE_3( label1, label2, label3 )			0
#define CFI_CHECK_SEQUENCE_4( label1, label2, label3, label4 )	0
#define CFI_CHECK_SEQUENCE_5( label1, label2, label3, label4, \
							  label5 )							0
#define CFI_CHECK_SEQUENCE_6( label1, label2, label3, label4, label5, \
							  label6 )							0
#define CFI_CHECK_SEQUENCE_7( label1, label2, label3, label4, label5, \
							  label6, label7 )					0
#define CFI_CHECK_SEQUENCE_8( label1, label2, label3, label4, label5, \
							  label6, label7, label8 )			0
#define CFI_CHECK_SEQUENCE_9( label1, label2, label3, label4, label5, \
							  label6, label7, label8, label9 )	0
#define CFI_CHECK_SEQUENCE_10( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, \
							   label10 )						0
#define CFI_CHECK_SEQUENCE_11( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11 )						0
#define CFI_CHECK_SEQUENCE_12( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12 )				0
#define CFI_CHECK_SEQUENCE_13( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13 )		0
#define CFI_CHECK_SEQUENCE_14( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, \
							   label14 )						0
#define CFI_CHECK_SEQUENCE_15( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, \
							   label14, label15 )				0
#define CFI_CHECK_SEQUENCE_17( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, \
							   label15, label16, label17 )		0
#define CFI_CHECK_SEQUENCE_18( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, \
							   label15, label16, label17, label18 ) \
																0
#define CFI_CHECK_SEQUENCE_20( label1, label2, label3, label4, label5, \
							   label6, label7, label8, label9, label10, \
							   label11, label12, label13, label14, \
							   label15, label16, label17, label18, \
							   label19, label20 )				0

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*								Loop Bounds Checks							*
*																			*
****************************************************************************/

/* Loop bounds used when a more specific constant upper bound isn't 
   available.  The following bounds on loop iterations apply:

	FAILSAFE_SMALL: Expect 1 but can have a few more.
	FAILSAFE_MED: Expect 10-20 but can have a few more.
	FAILSAFE_LARGE: Expect many, but not too many.

  In addition to these values there's a special value 
  FAILSAFE_ITERATIONS_MAX which is equivalent to the ASN.1 (1...MAX) 
  construct in setting an upper bound on loop iterations without necessarily 
  setting any specific limit:

	FAILSAFE_MAX: A value that's unlikely to be reached during normal 
				  operation, but that also won't result in an excessive 
				  stall if it's exceeded */

#define FAILSAFE_ITERATIONS_SMALL	10
#define FAILSAFE_ITERATIONS_MED		50
#define FAILSAFE_ITERATIONS_LARGE	1000
#define FAILSAFE_ITERATIONS_MAX		min( 100000L, INT_MAX )

/* Pseudo-constants used for array bounds-checking.  These provide a more
   precise limit than the FAILSAFE_ITERATIONS_xxx values above.  We subtract
   one from the total count because static arrays are always overallocated 
   with two extra dummy elements at the end */

#define FAILSAFE_ARRAYSIZE( array, elementType ) \
		( ( sizeof( array ) / sizeof( elementType ) ) - 1 )

/* In order to provide its availability guarantees, all loops in cryptlib 
   are statically bounded and double-indexed in case of a fault in the
   primary loop index.  In addition the loops are indexed in opposite
   directions to prevent compilers from combining the two loop index 
   variables into one.  So instead of:

	for( i = 0; i < max; i++ )

   the loop construct used is:

	for( i = 0,		_iterationCount = FAILSAFE_ITERATIONS_XXX;
		 i < max && _iterationCount > 0;
		 i++,		_iterationCount-- )

   (in practice the static bounds check is performed before the dynamic one).

   In order to hide the resulting complexity and to ensure a consistent
   implementation, the overall construct is mangled through macros so that
   the above becomes:

	LOOP_INDEX i;

	LOOP_MED( i = 0, i < max, i++ )
		{
		<loop body>;
		}
	ENSURES( LOOP_BOUND_OK );

	LOOP_INDEX_PTR THING_TYPE *thingPtr;

	LOOP_MED( thingPtr = getFirstThing(), thingPtr != NULL, \
			  thingPtr = getNextThing( thingPtr ) )
		{
		<loop body>;
		}
	ENSURES( LOOP_BOUND_OK );

   First we define the loop variables and conditions that we need.  Since we
   can have nested loops, we also define alternative values for a total of 
   up to three levels of nesting */

#define LOOP_ITERATOR				_iterationCount
#define LOOP_ITERATOR_ALT			_innerIterationCount
#define LOOP_ITERATOR_ALT2			_innerInnerIterationCount

#define LOOP_INDEX					int _iterationCount; int
#define LOOP_INDEX_PTR				int _iterationCount; 
#define LOOP_BOUND_INIT( value )	_iterationCount = ( value )
#define LOOP_BOUND_CHECK			( _iterationCount > 0 )
#define LOOP_BOUND_INC				_iterationCount--
#define LOOP_BOUND_OK				LOOP_BOUND_CHECK

#define LOOP_INDEX_ALT				int _innerIterationCount; int
#define LOOP_INDEX_PTR_ALT			int _innerIterationCount; 
#define LOOP_BOUND_INIT_ALT( value ) _innerIterationCount = ( value )
#define LOOP_BOUND_CHECK_ALT		( _innerIterationCount > 0 )
#define LOOP_BOUND_INC_ALT			_innerIterationCount--
#define LOOP_BOUND_OK_ALT			LOOP_BOUND_CHECK_ALT

#define LOOP_INDEX_ALT2				int _innerInnerIterationCount; int
#define LOOP_INDEX_PTR_ALT2			int _innerInnerIterationCount; 
#define LOOP_BOUND_INIT_ALT2( value ) _innerInnerIterationCount = ( value )
#define LOOP_BOUND_CHECK_ALT2		( _innerInnerIterationCount > 0 )
#define LOOP_BOUND_INC_ALT2			_innerInnerIterationCount--
#define LOOP_BOUND_OK_ALT2			LOOP_BOUND_CHECK_ALT2

/* Sometimes there are two loops in the same function that use different 
   index values, for which we still want to indicate that both are loop
   indices.  We can't use LOOP_INDEX twice, so instead we declare any 
   further loop indices as LOOP_INDEX_XXX */

#define LOOP_INDEX_XXX				int

/* Very occasionally the loop index counts down rather than up:

	LOOP_INDEX i;

	LOOP_MED_REV( i = max, i > 0, i-- )
		{
		<loop body>;
		}
	ENSURES( LOOP_BOUND_MED_REV_OK );

   In this situation the second index needs to count up rather than down, and
   the loop bound check needs to be given the maximum count that the loop
   shouldn't exceed:
   
	for( i = max,	_iterationCount = 0;
		 i >= 0 &&	_iterationCount < FAILSAFE_ITERATIONS_XXX;
		 i--,		_iterationCount++ ) */

#define LOOP_BOUND_REV_INIT			_iterationCount = 0
#define LOOP_BOUND_REV_CHECK( value ) ( _iterationCount < ( value ) )
#define LOOP_BOUND_REV_INC			_iterationCount++

#define LOOP_BOUND_REV_INIT_ALT		_innerIterationCount = 0
#define LOOP_BOUND_REV_CHECK_ALT( value ) ( _innerIterationCount < ( value ) )
#define LOOP_BOUND_REV_INC_ALT		_innerIterationCount++

#define LOOP_BOUND_REV_INIT_ALT2	_innerInnerIterationCount = 0
#define LOOP_BOUND_REV_CHECK_ALT2( value ) ( _innerInnerIterationCount < ( value ) )
#define LOOP_BOUND_REV_INC_ALT2		_innerInnerIterationCount++

#define LOOP_BOUND_EXT_REV_OK( value )	LOOP_BOUND_REV_CHECK( value )
#define LOOP_BOUND_EXT_REV_OK_ALT( value )	LOOP_BOUND_REV_CHECK_ALT( value )
#define LOOP_BOUND_EXT_REV_OK_ALT2( value )	LOOP_BOUND_REV_CHECK_ALT2( value )

#define LOOP_BOUND_SMALL_REV_OK		LOOP_BOUND_EXT_REV_OK( FAILSAFE_ITERATIONS_SMALL )
#define LOOP_BOUND_MED_REV_OK		LOOP_BOUND_EXT_REV_OK( FAILSAFE_ITERATIONS_MED )
#define LOOP_BOUND_LARGE_REV_OK		LOOP_BOUND_EXT_REV_OK( FAILSAFE_ITERATIONS_LARGE )
#define LOOP_BOUND_MAX_REV_OK		LOOP_BOUND_EXT_REV_OK( FAILSAFE_ITERATIONS_MAX )

#define LOOP_BOUND_MED_REV_OK_ALT	LOOP_BOUND_EXT_REV_OK_ALT( FAILSAFE_ITERATIONS_MED )
#define LOOP_BOUND_LARGE_REV_OK_ALT	LOOP_BOUND_EXT_REV_OK_ALT( FAILSAFE_ITERATIONS_LARGE )
#define LOOP_BOUND_MAX_REV_OK_ALT	LOOP_BOUND_EXT_REV_OK_ALT( FAILSAFE_ITERATIONS_MAX )

#define LOOP_BOUND_LARGE_REV_OK_ALT2 LOOP_BOUND_EXT_REV_OK_ALT2( FAILSAFE_ITERATIONS_LARGE )

/* With the above we can now create the building blocks for the loops, the
   basic universal form and then more specific forms built on top of that.
   
   Note that when building loops with custom bounds by directly using the 
   _EXT() form with a specific bound rather than wrappers like LOOP_MED(), 
   it's necessary to specify the bound + 1 since the LOOP_BOUND_OK check
   verifies that the hard bound is > 0, not >= 0.  In other words if
   expecting up to XXX_MAX iterations then the bound should be given as
   XXX_MAX + 1.
   
   In addition when using an ENSURES() at the end of the loop then for a 
   bounded array the check is 'index < FAILSAFE_ARRAYSIZE()' since the end-
   of-array marker should be hit before the hard bound is encountered, while 
   for other loop bounds the check is 'index <= bound' since the index will 
   go one past the loop check value */

#define LOOP_EXT( a, b, c, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC, ( c ) )
#define LOOP_EXT_ALT( a, b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT, ( c ) )
#define LOOP_EXT_ALT2( a, b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT2( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT2 && ( b ); \
			 LOOP_BOUND_INC_ALT2, ( c ) )

#define LOOP_EXT_REV( a, b, c, bound ) \
		for( LOOP_BOUND_REV_INIT, ( a ); \
			 LOOP_BOUND_REV_CHECK( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC, ( c ) )
#define LOOP_EXT_REV_ALT( a, b, c, bound ) \
		for( LOOP_BOUND_REV_INIT_ALT, ( a ); \
			 LOOP_BOUND_REV_CHECK_ALT( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC_ALT, ( c ) )
#define LOOP_EXT_REV_ALT2( a, b, c, bound ) \
		for( LOOP_BOUND_REV_INIT_ALT2, ( a ); \
			 LOOP_BOUND_REV_CHECK_ALT2( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC_ALT2, ( c ) )

#define LOOP_SMALL( a, b, c )	LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED( a, b, c )		LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE( a, b, c )	LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX( a, b, c )		LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_SMALL_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_LARGE_ALT2( a, b, c ) \
								LOOP_EXT_ALT2( a, b, c, FAILSAFE_ITERATIONS_LARGE )

#define LOOP_SMALL_REV( a, b, c ) \
								LOOP_EXT_REV( a, b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_REV( a, b, c ) \
								LOOP_EXT_REV( a, b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_REV( a, b, c ) \
								LOOP_EXT_REV( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_REV( a, b, c ) \
								LOOP_EXT_REV( a, b, c, FAILSAFE_ITERATIONS_MAX )
#define LOOP_LARGE_REV_ALT( a, b, c ) \
								LOOP_EXT_REV_ALT( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_LARGE_REV_ALT2( a, b, c ) \
								LOOP_EXT_REV_ALT2( a, b, c, FAILSAFE_ITERATIONS_LARGE )

/* Finally, we need a few specialised subtypes to handle constructs like:

	for( ; i < max ; i++ )

   or even:

	for( ; i < max ; )

   which is really a while() loop */

#define LOOP_EXT_INITCHECK( a, b, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC )
#define LOOP_EXT_INITINC( a, c, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK; \
			 LOOP_BOUND_INC, ( c ) )
#define LOOP_EXT_WHILE( b, bound ) \
		for( LOOP_BOUND_INIT( bound ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC )
#define LOOP_EXT_CHECKINC( b, c, bound ) \
		for( LOOP_BOUND_INIT( bound ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC, ( c ) )

#define LOOP_EXT_REV_INITCHECK( a, b, bound ) \
		for( LOOP_BOUND_REV_INIT, ( a ); \
			 LOOP_BOUND_REV_CHECK( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC )
#define LOOP_EXT_REV_CHECKINC( b, c, bound ) \
		for( LOOP_BOUND_REV_INIT; \
			 LOOP_BOUND_REV_CHECK( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC, ( c ) )

#define LOOP_EXT_INITCHECK_ALT( a, b, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT )
#define LOOP_EXT_WHILE_ALT( b, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT )
#define LOOP_EXT_CHECKINC_ALT( b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT, ( c ) )

#define LOOP_EXT_REV_CHECKINC_ALT( b, c, bound ) \
		for( LOOP_BOUND_REV_INIT_ALT; \
			 LOOP_BOUND_REV_CHECK_ALT( bound ) && ( b ); \
			 LOOP_BOUND_REV_INC_ALT, ( c ) )

#define LOOP_SMALL_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_SMALL ) 
#define LOOP_MED_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_MED ) 
#define LOOP_LARGE_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_LARGE ) 
#define LOOP_MAX_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_MAX ) 

#define LOOP_MED_INITINC( a, c ) \
								LOOP_EXT_INITINC( a, c, FAILSAFE_ITERATIONS_MED )

#define LOOP_SMALL_WHILE( b )	LOOP_EXT_WHILE( b, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_WHILE( b )		LOOP_EXT_WHILE( b, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_WHILE( b )	LOOP_EXT_WHILE( b, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_WHILE( b )		LOOP_EXT_WHILE( b, FAILSAFE_ITERATIONS_MAX )

#define LOOP_SMALL_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_MED_WHILE_ALT( b ) \
								LOOP_EXT_WHILE_ALT( b, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_WHILE_ALT( b ) \
								LOOP_EXT_WHILE_ALT( b, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_WHILE_ALT( b )	LOOP_EXT_WHILE_ALT( b, FAILSAFE_ITERATIONS_MAX )

#define LOOP_MED_INITCHECK_ALT( a, b ) \
								LOOP_EXT_INITCHECK_ALT( a, b, FAILSAFE_ITERATIONS_MED ) 
#define LOOP_MAX_INITCHECK_ALT( a, b ) \
								LOOP_EXT_INITCHECK_ALT( a, b, FAILSAFE_ITERATIONS_LARGE ) 

#define LOOP_MED_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_MED_REV_INITCHECK( a, b ) \
								LOOP_EXT_REV_INITCHECK( a, b, FAILSAFE_ITERATIONS_MED ) 
#define LOOP_LARGE_REV_INITCHECK( a, b ) \
								LOOP_EXT_REV_INITCHECK( a, b, FAILSAFE_ITERATIONS_LARGE ) 
#define LOOP_MAX_REV_INITCHECK( a, b ) \
								LOOP_EXT_REV_INITCHECK( a, b, FAILSAFE_ITERATIONS_MAX ) 
#define LOOP_SMALL_REV_CHECKINC( b, c ) \
								LOOP_EXT_REV_CHECKINC( b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_REV_CHECKINC( b, c ) \
								LOOP_EXT_REV_CHECKINC( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_REV_CHECKINC( b, c ) \
								LOOP_EXT_REV_CHECKINC( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_REV_CHECKINC( b, c ) \
								LOOP_EXT_REV_CHECKINC( b, c, FAILSAFE_ITERATIONS_MAX )
#define LOOP_MED_REV_CHECKINC_ALT( b, c ) \
								LOOP_EXT_REV_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_REV_CHECKINC_ALT( b, c ) \
								LOOP_EXT_REV_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_REV_CHECKINC_ALT( b, c ) \
								LOOP_EXT_REV_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MAX )

/* The double-indexed loop allows us to apply loop invariants.  Alongside 
   checking that the index remains within bounds, we can also verify that 
   the sum of the primary and secondary index variables match the loop 
   bound */

#define LOOP_INVARIANT_EXT( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) - ( lowerBound ) + _iterationCount == ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) - ( lowerBound ) + _innerIterationCount == ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_ALT2( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) - ( lowerBound ) + _innerInnerIterationCount == ( loopBound ) ) )

#define LOOP_INVARIANT_SMALL( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_SMALL_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_LARGE_ALT2( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_ALT2( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )

/* Loops where the index variable counts downwards are slightly different 
   since the secondary index starts from zero rather than the loop bound, so 
   there's only one way of expressing the invariant */ 

#define LOOP_INVARIANT_REV( index, lowerBound, upperBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) + _iterationCount == ( upperBound ) ) )
#define LOOP_INVARIANT_REV_ALT( index, lowerBound, upperBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) + _innerIterationCount == ( upperBound ) ) )
#define LOOP_INVARIANT_REV_ALT2( index, lowerBound, upperBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( ( index ) + _innerInnerIterationCount == ( upperBound ) ) )

/* Some loops have no fixed relationship between the primary and secondary 
   index variables.  For example the following loops have this property:

	i = ...;
	...;
	for( ; i < 5; i++ )
		{ }

	for( i = 0; i < 10; i +=2 )
		{ }

  In this case we can't perform a check for a fixed relationship between the
  primary and secondary index variables but can only check that the primary
  is within the given bounds and the secondary is within the loop bounds.
  
  We need two forms of the check, one for standard loops for which the 
  secondary counts down from MAX...1, the other for reverse loops for which
  the secondary counts up from 0...MAX-1 */

#define LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _iterationCount > 0 && _iterationCount <= ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_XXX_ALT( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _innerIterationCount > 0 && _innerIterationCount <= ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_XXX_ALT2( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _innerInnerIterationCount > 0 && _innerInnerIterationCount <= ( loopBound ) ) )

#define LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _iterationCount >= 0 && _iterationCount < ( loopBound ) ) )
#define LOOP_INVARIANT_EXT_REV_XXX_ALT( index, lowerBound, upperBound, loopBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) && \
		  ( _innerIterationCount >= 0 && _innerIterationCount < ( loopBound ) ) )

#define LOOP_INVARIANT_SMALL_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )
#define LOOP_INVARIANT_MED_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_SMALL_REV_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED_REV_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_REV_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_REV_XXX( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_MED_REV_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_REV_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_REV_XXX_ALT( index, lowerBound, upperBound ) \
		LOOP_INVARIANT_EXT_REV_XXX_ALT( index, lowerBound, upperBound, FAILSAFE_ITERATIONS_MAX )

/* Sometimes there's no loop index variable, for example when we're walking 
   down a linked list.  In this case only the hidden second iterator is 
   present and checked */

#define LOOP_INVARIANT_EXT_GENERIC( loopBound ) \
		( _iterationCount > 0 && _iterationCount <= ( loopBound ) )
#define LOOP_INVARIANT_EXT_ALT_GENERIC( loopBound ) \
		( _innerIterationCount > 0 && _innerIterationCount <= ( loopBound ) )

#define LOOP_INVARIANT_SMALL_GENERIC() \
		LOOP_INVARIANT_EXT_GENERIC( FAILSAFE_ITERATIONS_SMALL )
#define LOOP_INVARIANT_MED_GENERIC() \
		LOOP_INVARIANT_EXT_GENERIC( FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_GENERIC() \
		LOOP_INVARIANT_EXT_GENERIC( FAILSAFE_ITERATIONS_LARGE )
#define LOOP_INVARIANT_MAX_GENERIC() \
		LOOP_INVARIANT_EXT_GENERIC( FAILSAFE_ITERATIONS_MAX )

#define LOOP_INVARIANT_MED_ALT_GENERIC() \
		LOOP_INVARIANT_EXT_ALT_GENERIC( FAILSAFE_ITERATIONS_MED )
#define LOOP_INVARIANT_LARGE_ALT_GENERIC() \
		LOOP_INVARIANT_EXT_ALT_GENERIC( FAILSAFE_ITERATIONS_LARGE )

/* Sometimes there are two loop variables, with the second being used as a
   secondary index rather than the main loop variable.  In this case all
   that we can do is verify that it remains within bounds */

#define LOOP_INVARIANT_SECONDARY( index, lowerBound, upperBound ) \
		( ( index ) >= ( lowerBound ) && ( index ) <= ( upperBound ) )

/* These constructs however now run into conflict with both compilers in 
   general and various optimisers in particular.  Consider the following 
   block of test code:

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i;
		unsigned int j;

		for( i = 0; i < 512; i++ )
			array[ i ] = 5;
		doStuff( array );

		for( j = 0; j < 512; j++ )
			array[ j ] = 3;
		doStuff( array );

		return( 0 );
		}

   When compiled with gcc this produces:

	gcc -O1/O2 -S temp.c		// -O3 is similar but vectorised

	x86:

	.L2:	movl $5, (%rax)		# store $5 to address
			addq $4, %rax		# increment address pointer
			cmpq %rbp, %rax		# compare to bound
			jne .L2				# loop if not equal

	.L3:	movl $3, (%rbx)		# store $3 to address
			addq $4, %rbx		# increment address pointer
			cmpq %rbp, %rbx		# compare to bound
			jne .L3				# loop if not equal

	Arm64:

			mov w1, 5
	.L3:	str w1, [x0],4		# store word from W1 to address X0, add 4
			cmp x0, x19			# compare to limit in X19
			bne .L3				# loop if not equal

			mov w1, 3
	.L5:	str w1, [x0],4		# store word from W1 to address X0, add 4
			cmp x0, x19			# compare to limit in X19
			bne .L5				# loop if not equal

	MIPS64:

			li $3,5
	$L2:	sw $3,0($2)			# store data
			addiu $2,$2,4		# increment address pointer
			bne $2,$17,$L2		# loop if not equal

			li $2,3
	$L3:	sw $2,0($16)		# store data
			addiu $16,$16,4		# increment address pointer
			bne $16,$17,$L3		# loop if not equal

	PPC64:

			li 8,512
			mtctr 8				# move 512 to CTR register via GPR 8
			li 10,5
	.L3:	stwu 10,4(9)		# store word with update from GPR 10
			bdnz .L3			# decrement count, branch if nonzero

			li 8,512
			mtctr 8				# move 512 to CTR register via GPR 8
			li 10,3
	.L5:	stwu 10,4(9)		# store word with update from GPR 10
			bdnz .L5			# decrement count, branch if nonzero

	RISC-V:

			li a4,5
	.L2:	sw a4,0(a5)			# store word in A4 in address
			addi a5,a5,4		# increment address pointer
			bne a5,s1,.L2		# branch if address less than bound

			li a5,3
	.L3:	sw a5,0(s0)			# store word in A4 in address
			addi s0,s0,4		# increment address pointer
			bne s0,s1,.L3		# branch if address less than bound

	Sparc64:

			mov 5, %g2
			st %g2, [%g1]
	.L7:	add %g1, 4, %g1		# add 4
			cmp %g1, %i4		# compare to bound
			bne %xcc, .L7		# loop if not equal
			st %g2, [%g1]		# store data in delay slot

			mov 3, %g1
			st %g1, [%i5]
	.L8:	add %i5, 4, %i5		# add 4
			cmp %i5, %i4		# compare to bound
			bne %xcc, .L8		# loop if not equal
			st %g1, [%i5]		# store data in delay slot

   In every case gcc converts the index < bound comparison into an 
   index != bound comparison.  clang is no better:

	clang -O2 -S temp.c

	.LBB0_1:movaps %xmm0, (%rsp,%rax,4)
			...
			movaps %xmm0, 240(%rsp,%rax,4)	# store data via XMMs
			addq $64, %rax		# increment address pointer
			cmpq $512, %rax		# compare to bound
			jne .LBB0_1			# branch if not equal

	.LBB0_3:movaps %xmm0, (%rsp,%rax,4)
			...
			movaps %xmm0, 240(%rsp,%rax,4)	# store data via XMMs
			addq $64, %rax		# increment address pointer
			cmpq $512, %rax		# compare to bound
			jne .LBB0_3			# branch if not equal

			movi v0.4s, #5		# vector load data
	.LBB0_1:add x10, x9, x8
			add x8, x8, #32		# increment address pointer
			cmp x8, #2048		# compare to bound
			stp q0, q0, [x10]	# store quadword register pair
			b.ne .LBB0_1		# branch if not equal

			movi v0.4s, #3		# vector load data
	.LBB0_3:add x9, x19, x8
			add x8, x8, #32		# increment address pointer
			cmp x8, #2048		# compare to bound
			stp q0, q0, [x9]	# store quadword register pair
			b.ne .LBB0_3		# branch if not equal

   System-specific compilers are occasionally better, specifically icc and 
   the Sun compiler, but others are the same as gcc/clang:

	icc -O2 -S temp.c

	..B1.2:	movdqu XMMWORD PTR [rsp+rax*4], xmm0
			...
			movdqu XMMWORD PTR [48+rsp+rax*4], xmm0
			add rax, 16 		# increment address pointer
			cmp rax, 512		# compare to bound
			jb ..B1.2			# branch if below	-- Unsigned compare/branch

	..B1.5:	lea edx, DWORD PTR [4+rax]
			movdqu XMMWORD PTR [rsp+rdx*4], xmm0
			...
			lea esi, DWORD PTR [12+rax]
			movdqu XMMWORD PTR [rsp+rax*4], xmm0
			add eax, 16			# increment address pointer
			cmp eax, 512		# compare to bound
			jb ..B1.5			# branch if below	-- Unsigned compare/branch

	MSVC:

			mov ecx, 32
			mov rdx, 0000000500000005H
	$LL18@main:
			mov QWORD PTR [rax], rdx
			...
			mov QWORD PTR [rax+16], rdx
			lea rax, QWORD PTR [rax+64]
			mov QWORD PTR [rax-40], rdx
			...
			mov QWORD PTR [rax-8], rdx	# store data
			sub rcx, 1			# decrement count
			jne SHORT $LL18@main	# branch if not equal

			mov rcx, 0000000300000003H
	$LL17@main:
			mov QWORD PTR [rax], rcx
			...
			mov QWORD PTR [rax+16], rcx
			lea rax, QWORD PTR [rax+64]
			mov QWORD PTR [rax-40], rcx
			...
			mov QWORD PTR [rax-8], rcx	# store data
			sub rbx, 1			# decrement count
			jne SHORT $LL17@main	# branch if not equal

	xlc -O2 -S temp.c

			cal r4,64(r0)
			mtspr CTR,r4		# move 64 to CTR register via GPR 4
	__L30:	st r0,4(r3)
			...
			st r0,32(r3)		# store data, unrolled
			cal r3,32(r3)		# add 32 to address
			bc BO_dCTR_NZERO,CR0_LT,__L30	# branch if counter nonzero

			cal r4,64(r0)
			mtspr CTR,r4		# move 64 to CTR register via GPR 4
	__L80:	st r0,4(r31)
			...
			st r0,32(r31)		# store data, unrolled
			cal r31,32(r31)		# add 32 to address
			bc BO_dCTR_NZERO,CR0_LT,__L80	# branch if counter nonzero

	cc -O2 -S temp.c	(Solaris)

			or %g0,5,%i5
			st %i5,[%i1]
			or %g0,0,%i0		# zero counter
	.L900000109:
			add %i0,1,%i0		# increment counter
			add %i1,4,%i1		# increment address
			cmp %i0,511			# compare to bound
			ble %icc,.L900000109	# branch if less or equal
			st %i5,[%i1]		# store data in delay slot

			or %g0,3,%i4
			sll %i2,2,%i5
	.L900000108:
			add %i2,1,%i2		# increment counter
			st %i4,[%i5+%i3]	# store data
			cmp %i2,511			# compare to bound
			bleu %icc,.L900000108	# branch if less or equal, unsigned
			sll %i2,2,%i5		# address = counter * 4 in delay slot

   Only when compiled with -O0 does gcc produce the correct code, but it's 
   pretty bad:

			jmp .L2
	.L3:	movl -4(%rbp), %eax	# load address
			cltq				# convert long to quadword
			movl $5, -2064(%rbp,%rax,4) # store data
			addl $1, -4(%rbp)	# increment address
	.L2:	cmpl $511, -4(%rbp)	# compare to bound
			jle .L3				# branch if less or equal

			jmp .L4
	.L5:	movl -8(%rbp), %eax	# load address
			movl $3, -2064(%rbp,%rax,4) # store data
			addl $1, -8(%rbp)	# increment address
	.L4:	cmpl $511, -8(%rbp)	# compare to bound
			jbe .L5				# branch if below or equal

   CompCert, the compiler with a "mathematical proof that the generated 
   executable code behaves exactly as prescribed by the semantics of the 
   source program", actually gets it right:

	ccomp -O2 -S temp.c

	.L100:	leaq 8(%rsp), %rcx
			movslq %r9d, %r10
			movl $5, %r8d
			movl %r8d, 0(%rcx,%r10,4) # store data
			leal 1(%r9d), %r9d
			cmpl $512, %r9d		# compare to bound
			jl .L100			# branch if less than

	.L101:	leaq 8(%rsp), %rax
			movl %edx, %edi
			movl $3, %esi
			movl %esi, 0(%rax,%rdi,4) # store data
			leal 1(%edx), %edx
			cmpl $512, %edx		# compare to bound
			jb .L101			# branch if less than, unsigned

   The downside is that the code is quite inefficient, containing many 
   unnecessary memory accesses and register transfers, and it's not clear
   whether this is a side-effect of semantics-preserving transformations or 
   just poor code generation (the output has remained the same from 3.6
   through 3.11).

   The damage on double-indexed loops is even worse:

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i, __i;

		for( __i = 1000, i = 0; __i > 0 && i < 512; __i--, i++ )
			array[ i ] = 5;
	option1:
		if( __i <= 0 )
			return -1;
		doStuff( array );
	option2:
		if( __i > 0 )
			doStuff( array );

		return( 0 );
		}

	gcc -O2 -S temp.c

	.L2:	movl $5, (%rax)		# store $5 to address
			addq $4, %rax		# increment address pointer
			cmpq %rdx, %rax		# compare to bound
			jne .L2				# loop if not equal
			call doStuff		# unconditional call

   making it identical to the single-indexed loop since the second index has
   been removed entirely, and specifically identical to the unsafe single-
   indexed loop.

   The brute-force solution of making the second index volatile works, but 
   has the expected effect on efficiency:

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i;
		volatile int __i;

		for( __i = 1000, i = 0; __i > 0 && i < 512; __i--, i++ )
			array[ i ] = 5;
		if( __i > 0 )
			doStuff( array );

		return( 0 );
		}

			movl $1000, 2048(%rsp)	# __i = 1000
			xorl %eax, %eax			# i = 0
			movl 2048(%rsp), %edx
			testl %edx, %edx		# check __i > 0
			jle ..B1.6
	..B1.3:	movl $5, (%rsp,%rax,4)	# store data
			incq %rax				# i++
			decl 2048(%rsp)			# __i--
			movl 2048(%rsp), %edx
			testl %edx, %edx		# check __i > 0
			jle ..B1.6
			cmpq $512, %rax			# check i < 512
			jl ..B1.3
	..B1.6:	movl 2048(%rsp), %eax
			testl %eax, %eax		# check __i > 0
			jle ..B1.8

   Trying to make only parts of the access volatile makes things even worse:

	#define FORCE_PRESENCE( var )	( ( volatile int ) ( var ) )
	#define FORCE_PRESENCE( var )	( *( volatile int * ) &( var ) )
									// Both forms produce the same result

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i;
		volatile int __i;

		for( __i = 1000, i = 0; FORCE_PRESENCE( __i ) > 0 && i < 512; __i--, i++ )
			array[ i ] = 5;
		if( __i > 0 )
			doStuff( array );

		return( 0 );
		}

			movl $1000, 12(%rsp)	# __i = 1000
			movl 12(%rsp), %eax		# reload __i from memory
			testl %eax, %eax		# check __i > 0
			jle .L7
			xorl %edx, %edx			# i = 0
			jmp .L5
	.L15:	testl %eax, %eax		# check __i > 0
			jle .L7
	.L5:	movl 12(%rsp), %eax
			addl $1, %edx			# i++
			movl $5, (%rcx)			# store data
			addq $4, %rcx
			subl $1, %eax			# __i--
			cmpl $512, %edx			# i != 512
			movl %eax, 12(%rsp)
			movl 12(%rsp), %eax		# waste some cycles (??)
			jne .L15				# branch from i != 512
	.L7:	movl 12(%rsp), %eax		# reload __i
			testl %eax, %eax		# if __i > 0

   Adding the loop invariant:

	void doStuff( const int *array );

	int main( void )
		{
		int array[ 512 ];
		int i, __i;

		for( __i = 1000, i = 0; __i > 0 && i < 512; __i--, i++ )
			{
			if( i < 0 || i > 511 || i + __i != 1000 )
				return -1;
			array[ i ] = 5;
			}
		if( __i <= 0 )
			return -1;
		doStuff( array );

		return( 0 );
		}

	gcc -O2 -S temp.c

        movl    $1, %eax
        movq    %rsp, %rdi
.L2:	movl    $5, (%rdi,%rax,4)
        addq    $1, %rax
        cmpq    $512, %rax
        jne     .L2
        call    doStuff@PLT

*/

/****************************************************************************
*																			*
*								Safe Pointers								*
*																			*
****************************************************************************/

/* Error-detecting function and data pointers.  We store two copies of the 
   pointer, the value itself and its bitwise inverse.  If on retrieving them 
   their XOR isn't all-ones then one of the values has been corrupted and 
   the pointer isn't safe to dereference.  

   A linked list of items using safe pointers looks as follows:

	DATAPTR --> listItem {
					...
					DATAPTR --> listItem {
					...				...
					}				DATAPTR --> listItem {
									}				...
													DATAPTR --> NULL
													}

   Walking down a list of safe pointers works as follows:

	LOOP_LARGE( listPtr = DATAPTR_GET( listHead ),
				listPtr != NULL,
				listPtr = DATAPTR_GET( listPtr->next ) )

   When traversing a list (meaning walking from one link to the next looking
   for a particular entry), the access pattern is as above.  When processing
   entries (meaning working with the elements of listPtr), the pattern 
   becomes:

	LOOP_LARGE( listPtr = DATAPTR_GET( listHead ),
				listPtr != NULL,
				listPtr = DATAPTR_GET( listPtr->next ) )
		{
		REQUIRES( sanityCheckListEntry( listPtr ) );

		body;
		}

   Sometimes we need to have both a LIST_ITEM and the DATAPTR that refers 
   to it available.  This occurs when we're working with a mixture of 
   internal-access (LIST_ITEM) and external-access (DATAPTR) functions.  
   The following loop structure allows for this dual access:

	LOOP_LARGE( ( listCursor = listHead,
				  listPtr = DATAPTR_GET( listHead ) ),
				listPtr != NULL,
				( listCursor = listPtr->next,
				  listPtr = DATAPTR_GET( listPtr->next ) ) )

   Dealing with some types of loops is now especially difficult because a 
   pointer can become NULL even after it's been checked for being non-NULL.  
   To see how this can happen, consider a loop to find the end of a linked 
   list:

	LOOP( listPtr = DATAPTR_GET( list ),
		  DATAPTR_ISSET( listPtr->next ),
		  listPtr = DATAPTR_GET( listPtr->next ) )

   Since DATAPTR_GET() can return NULL on a fault, the DATAPTR_ISSET() check
   works as a loop condition check but doesn't guarantee that listPtr is 
   non-NULL in the loop body.  To see how this happens, consider the C loop 
   structure:

	for( init; check; increment )
		body

   This is evaluated as:

	init;
	while( check )
		{
		body;
	continue_label:
		increment;
		}

  So the above loop will be evaluated as:

	listPtr = DATAPTR_GET( list ),
	while( DATAPTR_ISSET( listPtr->next ) )
		{
		body;
		listPtr = DATAPTR_GET( listPtr->next );
		}

   If the DATAPTR_GET() in the increment returns NULL then the check
   DATAPTR_ISSET() will dereference a NULL pointer.

   The workaround for this is to rewrite the loop as:

	LOOP( listPtr = DATAPTR_GET( list ),
		  listPtr != NULL && DATAPTR_ISSET( listPtr->next ),
		  listPtr = DATAPTR_GET( listPtr->next ) )
		{
		body;
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( listPtr != NULL && DATAPTR_ISNULL( listPtr->next ) );

   An alternative workaround, using a temporary variable, is:

	LOOP( ( prevElementPtr = NULL, listPtr = DATAPTR_GET( list ) ), 
		  listPtr != NULL,
		  ( prevElementPtr = listPtr,
			listPtr = DATAPTR_GET( listPtr->next ) ) )
		{
		body;
		}
	ENSURES( LOOP_BOUND_OK );

   The pattern for fetching an attribute from a function that returns a 
   pointer to the attribute is:

	attributeListPtr = findAttribute( attributeListHead, attributeType );
	ENSURES( attributeListPtr != NULL );
	REQUIRES( sanityCheckAttribute( attributeListPtr ) ); */

/* First we need to define the safe pointer type, a primary copy consisting 
   of a pointer and the alternative copy as an equivalent-sized integer.  We 
   could alternately store two copies of the same value but that wouldn't 
   detect identical corruption on both values.  We could also mask the value 
   with a secret seed generated at runtime, but that's more useful for 
   preventing pointer-overwriting attacks than detecting corruption, and 
   it's not clear whether that's a real threat.  Finally, we could actually 
   store a triple modular-redundant copy, but if we're trying to deal with 
   that level of corruption then there are likely to be all sorts of other 
   problems as well that we'd need to handle.
   
   Function pointers get a bit more difficult because there's no equivalent 
   to the 'void *' universal data pointer.  The ostensible reason for this
   is that function and data pointers may not be of the same size, an example
   being IA64, which as part of its "totally idiotic calling conventions"
   (Linus) turns pointers into handles.  Since sizeof( data_ptr ) may not be
   the same as sizeof( fn_ptr ), it follows logically (if you're a compiler
   author, who run on their own very special type of logic) that we can't 
   have a 'void *' equivalent for function pointers.  Because of this, we 
   have to declare a generic void-ish function, typedef'd as 
   FNPTR_FUNCTION_TYPE, and then cast every assignment to/from it to avoid 
   compiler warnings.
   
   An additional complication with function pointers is that for the 
   aforementioned idiotic implementations there's no equivalent to a 
   uintptr_t.  However, this doesn't really affect us because we're not 
   storing a function pointer in a uintptr_t, just using it as a check
   value.  In this case the worst that can happen is that a few bits of a
   not-quite-a-pointer implementation of a function pointer don't get
   checked, but on any sane architecture we'll be OK */

#define FNPTR_TYPE				uintptr_t
#define DATAPTR_TYPE			uintptr_t

typedef void ( *FNPTR_FUNCTION_TYPE )( void );

typedef struct { 
	void *dataPtr; 
	uintptr_t dataCheck; 
	} DATAPTR;
typedef struct { 
	FNPTR_FUNCTION_TYPE fnPtr;
	uintptr_t fnCheck; 
	} FNPTR;

/* Initialisers for the safe pointer data.  This is now a scalar so we need 
   both a means of setting it to NULL and a NULL-equivalent value that we
   can use in places where we'd normally use the constant NULL */

#define FNPTR_INIT				{ NULL, ( FNPTR_TYPE ) ~0 }
#define DATAPTR_INIT			{ NULL, ( DATAPTR_TYPE ) ~0 }

extern const DATAPTR DATAPTR_NULL;
extern const FNPTR FNPTR_NULL;

/* Check safe pointers.  There are now three checks that can be performed 
   rather than the usual two NULL/non-NULL ones, since there's a third 
   possibility, "not valid".  The latter is required because pointers are 
   now tri-state, valid and non-NULL, valid and NULL, and invalid, which is 
   reported as NULL by FN/DATAPTR_GET() and so would be indistinguishable 
   from valid and NULL */

#define FNPTR_ISVALID( name ) \
		( ( ( ( FNPTR_TYPE ) ( name.fnPtr ) ) ^ ( name.fnCheck ) ) == ~0 )
#define DATAPTR_ISVALID( name ) \
		( ( ( ( DATAPTR_TYPE ) ( name.dataPtr ) ) ^ ( name.dataCheck ) ) == ~0 )
#define DATAPTR_ISVALID_PTR( name ) \
		( ( ( ( DATAPTR_TYPE ) ( name->dataPtr ) ) ^ ( name->dataCheck ) ) == ~0 )

#define FNPTR_ISSET( name ) \
		( FNPTR_ISVALID( name ) && ( name.fnPtr ) != NULL )
#define DATAPTR_ISSET( name ) \
		( DATAPTR_ISVALID( name ) && ( name.dataPtr ) != NULL )
#define DATAPTR_ISSET_PTR( name ) \
		( DATAPTR_ISVALID_PTR( name ) && ( name->dataPtr ) != NULL )

#define FNPTR_ISNULL( name ) \
		( FNPTR_ISVALID( name ) && ( name.fnPtr ) == NULL )
#define DATAPTR_ISNULL( name ) \
		( DATAPTR_ISVALID( name ) && ( name.dataPtr ) == NULL )
#define DATAPTR_ISNULL_PTR( name ) \
		( DATAPTR_ISVALID_PTR( name ) && ( name->dataPtr ) == NULL )

/* Set and get safe pointers.  The macros are used as:

	DATAPTR ptrStorage;

	FNPTR_SET( ptrStorage, functionAddress );
	DATAPTR_SET( ptrStorage, dataAddress );

	const PTR_TYPE functionPtr = FNPTR_GET( ptrStorage );
	REQUIRES( functionPtr != NULL );
	PTR_TYPE dataPtr = DATAPTR_GET( ptrStorage );
	REQUIRES( dataPtr != NULL ); */

#define FNPTR_GET( name ) \
		( FNPTR_ISVALID( name ) ? ( name.fnPtr ) : NULL )
#define DATAPTR_GET( name ) \
		( DATAPTR_ISVALID( name ) ? ( name.dataPtr ) : NULL )
#define DATAPTR_GET_PTR( name ) \
		( DATAPTR_ISVALID_PTR( name ) ? ( name->dataPtr ) : NULL )

#define FNPTR_SET( name, value ) \
			{ \
			name.fnPtr = ( FNPTR_FUNCTION_TYPE ) value; \
			name.fnCheck = ( ( FNPTR_TYPE ) ( value ) ) ^ ~0; \
			}
#define DATAPTR_SET( name, value ) \
			{ \
			name.dataPtr = value; \
			name.dataCheck = ( ( DATAPTR_TYPE ) ( value ) ) ^ ~0; \
			}
#define DATAPTR_SET_PTR( namePtr, value ) \
			{ \
			namePtr->dataPtr = value; \
			namePtr->dataCheck = ( ( DATAPTR_TYPE ) ( value ) ) ^ ~0; \
			}

/* Finally, since DATAPTRs are now scalar values rather than pointers, we 
   have to replace some operations that work on pointers with macros that
   deal with the use of scalars */

#define DATAPTR_SAME( name1, name2 ) \
		( ( ( name1 ).dataPtr ) == ( ( name2 ).dataPtr ) )

/****************************************************************************
*																			*
*								Safe Bitflags								*
*																			*
****************************************************************************/

/* Safe bitflags.  These are particularly critical because some of them have
   a considerable influence over how objects are used, for example 
   CONTEXT_FLAG_DUMMY (software vs. external hardware context), 
   DEVICE_FLAG_ACTIVE (device has been unlocked via PIN/password and is 
   ready for use), ENVELOPE_FLAG_ISDEENVELOPE (whether the envelope is used 
   for enveloping or de-enveloping) and so on.  In addition since the flags
   are all packed into a single integer value, corruption of that value will
   upset a large range of flags.

   Because of this critical nature we protect flags by making them safe
   objects, in the same way that pointers are protected.  The macros are used 
   as:

	SAFE_FLAGS flags;
	
	INIT_FLAGS( flags, XXX_FLAG_NONE );
	CHECK_FLAGS( flags, XXX_FLAG_NONE, XXX_FLAG_MAX );
	
	SET_FLAG( flags, XXX_FLAG_YYY );
	if( TEST_FLAG( flags, XXX_FLAG_YYY )
		do_something;
	CLEAR_FLAG( flags, XXX_FLAG_YYY ); */

typedef struct {
	int flagValue, flagCheckValue;
	} SAFE_FLAGS;

/* Initialisers for the safe flags.  We need both static and dynamic 
   initialision mechanisms */

#define SAFE_FLAGS_INIT( value )		{ ( value ), ~( value ) }
#define INIT_FLAGS( flags, value ) \
		( flags ).flagValue = ( value ), ( flags ).flagCheckValue = ~( value )

/* Check safe flags.  The check doubles as a sanity-check, so it both 
   verifies that the flags are valid in the sense of not having been 
   corrupted and that they've been set to an allowed value */

#define CHECK_FLAGS( flags, minRange, maxRange ) \
		( ( ( flags ).flagValue ^ ( flags ).flagCheckValue ) == ~0 && \
		  ( ( flags ).flagValue >= ( minRange ) && \
			( flags ).flagValue <= ( maxRange ) ) )

/* Get, set, and clear flags.  The XXX_FLAG() and XXX_FLAGS() operations do 
   the same thing, so one is aliased to the other */

#define GET_FLAG( flags, value ) \
		( ( flags ).flagValue & ( value ) )
#define SET_FLAG( flags, value ) \
		( flags ).flagValue |= ( value ), ( flags ).flagCheckValue &= ~( value )
#define CLEAR_FLAG( flags, value ) \
		( flags ).flagValue &= ~( value ), ( flags ).flagCheckValue |= ( value )
#define GET_FLAGS		GET_FLAG
#define SET_FLAGS		SET_FLAG
#define CLEAR_FLAGS		CLEAR_FLAG

/* Test a flag.  Unlike the other macros there are two distinct versions of 
   this, TEST_FLAG() checks that a single flag value (or one of a set of 
   values) is set, TEST_FLAGS() checks that all specified flags are set */

#define TEST_FLAG		GET_FLAG
#define TEST_FLAGS( flags, mask, reqFlags ) \
		( GET_FLAG( flags, mask ) == ( reqFlags ) )

/****************************************************************************
*																			*
*								Safe Booleans								*
*																			*
****************************************************************************/

/* Boolean constants.  Since the traditional TRUE = 1, FALSE = 0 only has a 
   single-bit difference between the two and it's going to be used to decide
   things like "access authorised" or "cryptographic verification succeeded",
   we define our own value for TRUE that minimises the chances of a simple
   fault converting one value to another.  In addition we explicitly check
   for equality to TRUE rather than just "is non-zero".

   Contrast this with things like the NXP LPC devices, which use four magic
   values, 0x12345678, 0x87654321, 0x43218765, and 0x4E697370 ('Nisp'), to
   indicate that security is in effect, and the other 4 billion values to
   indicate that no security is in effect (see "Breaking Code Read 
   Protection on the NXP LPC-family Microcontrollers" from RECON BRX 2017),
   or STM's barely-better STM32 16-bit { 0xAA, 0x55 } = no security, 
   { 0xCC, 0x33 } = high security, and the remaining 64K-2 values = medium/
   low security ("Shedding too much Light on a Microcontroller’s Firmware 
   Protection" from WOOT 2017) (the values differ between the F0 and F1, F0
   has 0xAA 0x55, F1 has 0xA5, 0x5A ("On the Security of Drop-in Replacement
   and Counterfeit Microcontrollers", WOOT 2020).

   The bit pattern in the TRUE value is chosen to minimise the chances of an
   SEU or similar fault flipping the value into something else that looks 
   valid.  The bit pattern is:

	0000 0000 1111 1111 0011 0011 1100 1100 || \
	  0	   0	F	 F	  3	   3	C	 C

	0000 1111 0011 1100 0101 0110 1001 1111
	  0	   F	3	 C	  5	   6	9	 F

   with the more important patterns at the LSB end, so we use the best
   subset of patterns no matter what the word size is.
   
   For historic purposes we could also use the sample pattern that's given
   in the Sandia UQS design document "The Unique Signal Concept for 
   Detonation Safety in Nuclear Weapons", further analysed in "Mathematical 
   Aspects of Unique Signal Assessment", with a 24-bit example given on p.19
   of the Sandia doc:
   
	ABAAAABAABAABBBBABBBBAAB
	101111011011000010000110

   or 0xBDB086 but, while cute, this doesn't really give us something that's
   targeted against SEUs or similar, which is what we're principally 
   concerned with */

#ifdef TRUE
  /* If the TRUE value has been redefined externally, remember this so that 
     we can warn about it elsewhere.  We can't #pragma message() here 
	 because it would produce an annoying warning for every single file */ 
  #if TRUE == 1 
	#define TRUE_REDEFINED	1
  #endif /* TRUE == 1 */
  #undef TRUE
#endif /* TRUE */
#if INT_MAX > 0xFFFFFFFFL
  #define TRUE			0x00FF33CC0F3C569F
#elif INT_MAX > 0xFFFF
  #define TRUE			0x0F3C569F
#else
  #define TRUE			0x569F
#endif /* System-specific word size */
#if defined( _MSC_VER ) && VC_GE_2010( _MSC_VER )
  /* VC warns about #if FALSE vs. #ifdef FALSE, since FALSE == 0 */
  #pragma warning( push )
  #pragma warning( disable : 4574 )
#endif /* VS 2010 and above */
#ifdef FALSE
  #if FALSE != 0
	#error Value of FALSE is nonzero, this isnt a boolean FALSE value.
  #endif /* FALSE sanity check */
#else
  #define FALSE			0
#endif /* FALSE */
#if defined( _MSC_VER ) && VC_GE_2010( _MSC_VER )
  #pragma warning( pop )
#endif /* VS 2010 and above */

/* To avoid a circular dependency, misc/analyse.h defines its own versions
   of TRUE and FALSE.  The follwing check ensures that they're consistent
   with what we define here */

#if ( TRUE != ANALYSIS_TRUE ) || ( FALSE != ANALYSIS_FALSE )
  #error TRUE/FALSE is defined differentl to ANALYSIS_TRUE/ANALYSIS_FALSE
#endif /* TRUE != ANALYSIS_TRUE || FALSE != ANALYSIS_FALSE */

/* The fault-detecting value of TRUE is OK for internal use, but for 
   external use we still have to use TRUE = 1, for which we define an
   alternative constant to make it explicit that this is the external-
   use TRUE */

#define TRUE_ALT		1

/* Error-detecting boolean variables, used for critical values where we 
   don't want to risk a single bit-flip converting a value from one to the
   other.  In this case we also define SAFE_BOOL_FALSE to an SEU-immune data 
   value rather than allowing it to be all zeroes.
   
   We also mix in an additional value, currently just set to the constant
   SAFE_BOOL_CONST, to deal with data-injection attacks in which an attacker 
   tries to set a boolean flag to a particular value.   In practice this 
   should be some unpredictable value set at runtime, but for now it's just 
   a no-op placeholder.
   
   The usage is:

	SAFE_BOOLEAN safeBool;

	BOOL_SET( &safeBool );
	BOOL_ISVALID( &safeBool );

	if( BOOL_ISSET( &safeBool ) )
		do_something();
	BOOL_CLEAR( &safeBool ); */

#define SAFE_BOOL_TRUE		TRUE
#if INT_MAX > 0xFFFFFFFFL
  #define SAFE_BOOL_FALSE	0x3300CCFF0FC3F596
#elif INT_MAX > 0xFFFF
  #define SAFE_BOOL_FALSE	0x0FC3F596
#else
  #define SAFE_BOOL_FALSE	0xF596
#endif /* System-specific word size */
#define SAFE_BOOL_CONST		0

typedef struct {
		int value1, value2;
		} SAFE_BOOLEAN;

#define BOOL_SET( name ) \
		{ \
		( name )->value1 = SAFE_BOOL_TRUE; \
		( name )->value2 = SAFE_BOOL_TRUE ^ SAFE_BOOL_CONST; \
		}
#define BOOL_CLEAR( name ) \
		{ \
		( name )->value1 = SAFE_BOOL_FALSE; \
		( name )->value2 = ~SAFE_BOOL_FALSE ^ SAFE_BOOL_CONST; \
		}

#define BOOL_ISSET( name )		( ( ( name )->value1 ^ \
									( name )->value2 ^ SAFE_BOOL_CONST ) == 0 )
#define BOOL_ISCLEAR( name )	( ( ( name )->value1 ^ \
									( name )->value2 ^ SAFE_BOOL_CONST ) == ~0 )
#define BOOL_ISVALID( name )	( BOOL_ISSET( name ) || BOOL_ISCLEAR( name ) )

/****************************************************************************
*																			*
*								Safe Integers								*
*																			*
****************************************************************************/

/* Check for overflow on various arithmetic operations.  In theory we could
   also use compiler-specific intrinsics (see the comment further down) but 
   according to "Understanding Integer Overflow in C/C++" by Dietz, Li, 
   Regehr and Adve, 2012, LLVM at least can aggressively optimise the 
   precondition tests below while the intrinsics aren't optimised much, 
   leading to little gain from using intrinsics.

   By default we check for overflow of MAX_INTLENGTH, which is the safe
   upper bound allowed by cryptlib, if we want to check for standard int
   or long overflow we have to make it explicit.  Note that we check for
   <= / >= since the range checks all enforced a range < MAX, not <= MAX.
   This also means that we couldn't use the compiler intrinsics even if
   they were better-performing than they actually are since they check for
   over at INT_MAX, not MAX_INTLENGTH.

   Strictly speaking the check for b < 0 isn't necessary, we just have to
   change the check type for b if a < 0, but neither a nor b should ever be
   negative so it's a general-purpose check.  This also makes the subtract-
   overflow check a bit of a no-op since we can only overflow if either
   a - (-b) = -ve or (-a) - b = +ve, so just checking for either side being
   negative is enough.  It also simplifies the division check, which would
   normally be b == 0 || a == INT_MIN && b == -1 */

#define checkOverflowAdd( a, b )		( ( a ) < 0 || ( b ) < 0 || \
										  ( a ) >= MAX_INTLENGTH - ( b ) )
#define checkOverflowSub( a, b )		( ( a ) < 0 || ( b ) < 0 || \
										  ( a ) <= -MAX_INTLENGTH + ( b ) )
#define checkOverflowMul( a, b )		( ( a ) < 0 || ( b ) <= 0 || \
										  ( a ) >= MAX_INTLENGTH / ( b ) )
#define checkOverflowDiv( a, b )		( ( a ) < 0 || ( b ) <= 0 )

#define checkOverflowAddInt( a, b )		( ( a ) > INT_MAX - ( b ) )
#define checkOverflowSubInt( a, b )		( ( a ) < INT_MIN + ( b ) )
#define checkOverflowMulInt( a, b )		( ( a ) > INT_MAX / ( b ) )
#define checkOverflowDivInt( a, b )		( ( a ) < 0 || ( b ) <= 0 )
#define checkOverflowAddLong( a, b )	( ( a ) > LONG_MAX - ( b ) )
#define checkOverflowSubLong( a, b )	( ( a ) < LONG_MAX + ( b ) )
#define checkOverflowMulLong( a, b )	( ( a ) > LONG_MAX / ( b ) )
#define checkOverflowDivLong( a, b )	( ( a ) < 0 || ( b ) <= 0 )

/* As an alternative to the above we could also define safe-maths functions 
   that check for overflow, but support is pretty hit and miss, for gcc and 
   clang there's the intrinsics:

	bool __builtin_sadd_overflow( int x, int y, int *sum );
	bool __builtin_smul_overflow( int x, int y, int *prod );

   which compile to two instructions, the arithmetic op and a setcc for 
   the bool, however Windows has:
   
	#define ENABLE_INTSAFE_SIGNED_FUNCTIONS
	#include <intsafe.h>

	HRESULT IntAdd( INT iAugend, INT iAddend, INT *piResult );
	HRESULT IntMult( INT iMultiplicand, INT iMultiplier, INT *piResult );

   which aren't implemented as intrinsics but as "portable" code, producing
   a dozen or more instructions per arithmetic operation and possibly
   function calls depending on what the compiler feels like.  For this 
   reason we don't define these until they're more widely supported as
   intrinsics */

/****************************************************************************
*																			*
*								TMR Data Protection							*
*																			*
****************************************************************************/

/* Perform a bitwise majority decode of a data item, i.e. a bit is 1 if the 
   majority of inputs are 1, otherwise 0.  The standard form for this is:

	#define MAJ( a, b, c )		( a & b ) | ( a & c ) | ( b & c ) )
   
   however the form used below requires one less operation */

#define MAJ( a, b, c )				( ( ( a ) & ( ( b ) | ( c ) ) ) | ( ( b ) & ( c ) ) )
#define SCRUB( a, b, c )			a = b = c = MAJ( a, b, c )

#define TMR_DECLARE( type, value )	type value##A, value##B, value##C
#define TMR_DECLARE_STATIC( type, value ) \
									static type value##A = 0, value##B = 0, value##C = 0
#define TMR_GET( value )			MAJ( value##A, value##B, value##C )
#define TMR_SET( value, data )		value##A = value##B = value##C = ( data )
#define TMR_VALID( value )			( ( value##A == value##B ) && ( value##A == value##C ) )
#define TMR_SCRUB( value )			SCRUB( value##A, value##B, value##C )

/* For the sensitive data that we want to have TMR, what's being protected 
   is a block of memory, not a single value, so we use TMR memory functions
   rather than single-value operations.  The operation involved is:

	status = checksumContextData( ... );
	if( cryptStatusError( status ) )
		status = tmrRecoverData( ... );
	if( cryptStatusError( status ) )
		return( status );

   And occasionally:

	status = tmrSrubData( ... ); */

CHECK_RETVAL \
int tmrRecoverData( INOUT_BUFFER_FIXED( size) void *a, 
					INOUT_BUFFER_FIXED( size) void *b, 
					INOUT_BUFFER_FIXED( size) void *c, 
					IN_LENGTH const int size );
CHECK_RETVAL \
int tmrScrubData( INOUT_BUFFER_FIXED( size) void *a, 
				  INOUT_BUFFER_FIXED( size) void *b, 
				  INOUT_BUFFER_FIXED( size) void *c, 
				  IN_LENGTH const int size );

#endif /* _SAFETY_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
