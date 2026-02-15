/****************************************************************************
*																			*
*		Certificate Attribute SET/SET OF/SEQUENCE/SEQUENCE OF Routines		*
*						 Copyright Peter Gutmann 1996-2020					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_CERTIFICATES

/* When we're processing SETs/SEQUENCEs (generically referred to as a SET
   OF in labels) we need to maintain a stack of state information to handle 
   a nested SET OF/SEQUENCE OF.  The following code implements the state 
   stack, with the zero-th entry being a dummy entry and the first user-set 
   entry being at position 1.

   SET OF stack flags.  These are:

	ISEMPTY: Set when a stack entry is created, cleared once at least one 
		entry has been processed.

	SUBTYPED: We're processing a subtype and need to return to the parent 
		type once the current SET/SEQUENCE ends.

	RESTARTPOINT: This entry is a restart point when processing a 
		SET OF/SEQUENCE OF rather than a straight SET/SEQUENCE */

#define SETOF_FLAG_NONE			0x00	/* No flag value */
#define SETOF_FLAG_SUBTYPED		0x01	/* SET ends on a subtyped value */
#define SETOF_FLAG_RESTARTPOINT	0x02	/* SET OF rather than SET */
#define SETOF_FLAG_ISEMPTY		0x04	/* Cleared if SET OF contains at least one entry */
#define SETOF_FLAG_MAX			0x07	/* Maximum possible flag value */

/* The zero-th (dummy) entry on the stack, and an empty-stack entry used to
   initialise a stack position */

static const SETOF_STATE_INFO stackPos0Data = {
	NULL, 0, MAX_INTLENGTH_SHORT, SETOF_FLAG_NONE, 
	CRYPT_ATTRIBUTE_NONE, SETOF_FLAG_NONE
	};

static const SETOF_STATE_INFO stackPosEmptyData = {
	NULL, 0, 0, SETOF_FLAG_NONE, 
	CRYPT_ATTRIBUTE_NONE, SETOF_FLAG_NONE
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the overall stack state and an individual stack entry */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheckSetofStack( IN_PTR const SETOF_STACK *setofStack )
	{
	const SETOF_STATE_INFO *setofInfoPtr;

	assert( isReadPtr( setofStack, sizeof( SETOF_STACK ) ) );

	/* Check general stack information */
	if( setofStack->stackPos < 0 || \
		setofStack->stackPos >= SETOF_STATE_STACKSIZE )
		{
		DEBUG_PUTS(( "sanityCheckSetofStack: Stack position" ));
		return( FALSE );
		}

	/* Check the special-case zero'th stack position */
	setofInfoPtr = &setofStack->stateInfo[ 0 ];
	if( memcmp( setofInfoPtr, &stackPos0Data, sizeof( SETOF_STATE_INFO ) ) )
		{
		DEBUG_PUTS(( "sanityCheckSetofStack: First stack entry" ));
		return( FALSE );
		}

	return( TRUE ); 
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheckSetofStateInfo( IN_PTR \
											const SETOF_STATE_INFO *setofInfoPtr )
	{
	assert( isReadPtr( setofInfoPtr, sizeof( SETOF_STATE_INFO ) ) );

	/* Check for the zero'th entry, which has special properties */
	if( setofInfoPtr->startPos == stackPos0Data.startPos && \
		setofInfoPtr->endPos == stackPos0Data.endPos )
		{
		if( memcmp( setofInfoPtr, &stackPos0Data, 
					sizeof( SETOF_STATE_INFO ) ) )
			{
			DEBUG_PUTS(( "sanityCheckSetofStateInfo: First stack entry" ));
			return( FALSE );
			}

		return( TRUE );
		}

	/* Check for an empty stack entry, which we can encounter when we've 
	   just pushed an item onto the stack and are setting up the next 
	   entry */
	if( setofInfoPtr->startPos == stackPosEmptyData.startPos && \
		setofInfoPtr->endPos == stackPosEmptyData.endPos  )
		{
		if( memcmp( setofInfoPtr, &stackPosEmptyData, 
					sizeof( SETOF_STATE_INFO ) ) )
			{
			DEBUG_PUTS(( "sanityCheckSetofStateInfo: Empty stack entry" ));
			return( FALSE );
			}

		return( TRUE );
		}

	/* Check general state information */
	if( !isShortIntegerRangeNZ( setofInfoPtr->startPos ) || \
		!isShortIntegerRangeNZ( setofInfoPtr->endPos ) || \
		setofInfoPtr->startPos >= setofInfoPtr->endPos || \
		!isFlagRangeZ( setofInfoPtr->flags, SETOF ) )
		{
		DEBUG_PUTS(( "sanityCheckSetofStateInfo: State information" ));
		return( FALSE );
		}

	/* Check subtyping information */
	if( setofInfoPtr->subtypeParent == CRYPT_ATTRIBUTE_NONE )
		{
		if( setofInfoPtr->inheritedAttrFlags != ATTR_FLAG_NONE )
			{
			DEBUG_PUTS(( "sanityCheckSetofStateInfo: Spurious subtype information" ));
			return( FALSE );
			}
		}
	else
		{
		if( !isAttribute( setofInfoPtr->subtypeParent ) || \
			!isFlagRangeZ( setofInfoPtr->inheritedAttrFlags, ATTR ) )
			{
			DEBUG_PUTS(( "sanityCheckSetofStateInfo: Subtype information" ));
			return( FALSE );
			}
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/****************************************************************************
*																			*
*						SET/SEQUENCE Management Routines					*
*																			*
****************************************************************************/

/* Initialise a SET/SEQUENCE stack */

STDC_NONNULL_ARG( ( 1 ) ) \
void setofStackInit( OUT_PTR SETOF_STACK *setofStack )
	{
	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );

	memset( setofStack, 0, sizeof( SETOF_STACK ) );

	/* Set up the dummy entry at position zero.  This has an (effectively) 
	   infinite length to ensure that the encapsulation check for subsequent 
	   entries always succeeds */
	memcpy( &setofStack->stateInfo[ 0 ], &stackPos0Data, 
			sizeof( SETOF_STATE_INFO ) ); 

	ENSURES_V( sanityCheckSetofStack( setofStack ) );
	}

/* Push and pop items to/from a SET/SEQUENCE stack, and peek at the top-of-
   stack entry */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN setofStackPush( INOUT_PTR SETOF_STACK *setofStack )
	{
	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );

	REQUIRES_B( sanityCheckSetofStack( setofStack ) );

	/* Make sure that there's space left on the stack.  The < 0 check has 
	   already been performed by the sanity check, but we add it to the 
	   comparison here to make it explicit */
	if( setofStack->stackPos < 0 || \
		setofStack->stackPos >= SETOF_STATE_STACKSIZE - 1 )
		return( FALSE );

	/* Increment the stack pointer */
	setofStack->stackPos++;
	ENSURES_B( setofStack->stackPos >= 1 && \
			   setofStack->stackPos < SETOF_STATE_STACKSIZE );

	/* Initialise the new entry */
	memset( &setofStack->stateInfo[ setofStack->stackPos ], 0, 
			sizeof( SETOF_STATE_INFO ) );

	ENSURES_B( sanityCheckSetofStack( setofStack ) );

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN setofStackPop( INOUT_PTR SETOF_STACK *setofStack )
	{
	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );

	REQUIRES_B( sanityCheckSetofStack( setofStack ) );

	/* Decrement the stack pointer.  Note that the precondition is explicitly
	   checked for since it can occur normally as a result of a corrupted
	   certificate while the postcondition can only occur as an internal 
	   error */
	if( setofStack->stackPos <= 0 || \
		setofStack->stackPos >= SETOF_STATE_STACKSIZE )
		return( FALSE );
	setofStack->stackPos--;
	ENSURES_B( setofStack->stackPos >= 0 && \
			   setofStack->stackPos < SETOF_STATE_STACKSIZE - 1 );

	ENSURES_B( sanityCheckSetofStack( setofStack ) );

	return( TRUE );
	}

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
SETOF_STATE_INFO *setofTOS( IN_PTR const SETOF_STACK *setofStack )
	{
	const SETOF_STATE_INFO *setofInfoPtr;

	assert( isReadPtr( setofStack, sizeof( SETOF_STACK ) ) );

	REQUIRES_N( sanityCheckSetofStack( setofStack ) );

	setofInfoPtr = &setofStack->stateInfo[ setofStack->stackPos ];
	ENSURES_N( sanityCheckSetofStateInfo( setofInfoPtr ) );

	return( ( SETOF_STATE_INFO * ) setofInfoPtr );
	}

/* Set/check conditions on an overall SET/SEQUENCE OF stack */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN setofStackIsEmpty( IN_PTR const SETOF_STACK *setofStack )
	{
	assert( isReadPtr( setofStack, sizeof( SETOF_STACK ) ) );

	REQUIRES_B( sanityCheckSetofStack( setofStack ) );

	return( ( setofStack->stackPos <= 0 ) ? TRUE : FALSE );
	}

/* Set/check conditions on an individual SET/SEQUENCE OF stack entry.  These 
   have the Opt designator since the current setofInfoPtr may be pointing to 
   a dummy top-of-stack entry, this avoids having to preface every call with
   a check for the stack being empty */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void setofSetNonemptyOpt( INOUT_PTR SETOF_STATE_INFO *setofInfoPtr,
						  const IN_PTR SETOF_STACK *setofStack )
	{
	assert( isWritePtr( setofInfoPtr, sizeof( SETOF_STATE_INFO ) ) );

	REQUIRES_V( sanityCheckSetofStateInfo( setofInfoPtr ) );

	if( !setofStackIsEmpty( setofStack ) )
		setofInfoPtr->flags &= ~SETOF_FLAG_ISEMPTY;
	}

/* Get the attribute information for the start of a SET/SEQUENCE.  This is
   used when processing a SET OF/SEQUENCE OF to restart the decoding */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
const ATTRIBUTE_INFO *setofGetAttributeInfo( IN_PTR \
												const SETOF_STATE_INFO *setofInfoPtr )
	{
	assert( isReadPtr( setofInfoPtr, sizeof( SETOF_STATE_INFO ) ) );

	REQUIRES_N( sanityCheckSetofStateInfo( setofInfoPtr ) );

	return( setofInfoPtr->infoStart );
	}

/* Push the current attribute information prior to switching to processing
   a subtype */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void setofPushSubtyped( INOUT_PTR SETOF_STATE_INFO *setofInfoPtr,
						IN_PTR const ATTRIBUTE_INFO *attributeInfoPtr )
	{
	assert( isWritePtr( setofInfoPtr, sizeof( SETOF_STATE_INFO ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES_V( sanityCheckSetofStateInfo( setofInfoPtr ) );

	/* Record the subtype parent information */
	setofInfoPtr->subtypeParent = attributeInfoPtr->fieldID;
	setofInfoPtr->inheritedAttrFlags = \
					( attributeInfoPtr->encodingFlags & FL_MULTIVALUED ) ? \
					  ATTR_FLAG_MULTIVALUED : ATTR_FLAG_NONE;

	/* If the subtype is being used to process a list of { ... OPTIONAL, 
	   ... OPTIONAL } of which at least one entry must be present, remember 
	   that we haven't seen any entries yet */
	if( !( attributeInfoPtr->encodingFlags & FL_EMPTYOK ) )
		setofInfoPtr->flags |= SETOF_FLAG_ISEMPTY;

	/* If the subtype ends once the current SET/SEQUENCE ends, remember this 
	   so that we return to the main type when appropriate */
	if( ( attributeInfoPtr->encodingFlags & FL_SEQEND_MASK ) || \
		( attributeInfoPtr->typeInfoFlags & FL_ATTR_ATTREND ) )
		setofInfoPtr->flags |= SETOF_FLAG_SUBTYPED;
	}

/****************************************************************************
*																			*
*						Read a SET/SET OF/SEQUENCE/SEQUENCE OF				*
*																			*
****************************************************************************/

/* Process the start of a SET/SET OF/SEQUENCE/SEQUENCE OF */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int setofBegin( INOUT_PTR SETOF_STACK *setofStack,
				OUT_PTR_PTR SETOF_STATE_INFO **setofInfoPtrPtr,
				INOUT_PTR STREAM *stream, 
				IN_PTR const ATTRIBUTE_INFO *attributeInfoPtr,
				IN_LENGTH const int dataEndPos )
	{
	const SETOF_STATE_INFO *parentSetofInfoPtr;
	SETOF_STATE_INFO *setofInfoPtr;
	int setofLength, status;

	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );
	assert( isWritePtr( setofInfoPtrPtr, sizeof( SETOF_STATE_INFO * ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( sanityCheckSetofStack( setofStack ) );
	REQUIRES( isIntegerRangeNZ( dataEndPos ) );

	/* Clear return value */
	*setofInfoPtrPtr = NULL;

	/* Determine the length and start position of the SET OF items.  If the
	   tag is an explicit tag then we don't have to process it since it's
	   already been handled by the caller */
	if( attributeInfoPtr->fieldEncodedType >= 0 && \
		!( attributeInfoPtr->encodingFlags & FL_EXPLICIT ) )
		{
		status = readConstructed( stream, &setofLength,
								  attributeInfoPtr->fieldEncodedType );
		}
	else
		{
		if( attributeInfoPtr->fieldType == BER_SET )
			status = readSet( stream, &setofLength );
		else
			status = readSequenceZ( stream, &setofLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Sanity-check the wrapper length information to make sure that it 
	   makes sense */
	if( !isShortIntegerRange( setofLength ) || \
		stell( stream ) + setofLength > dataEndPos )
		return( CRYPT_ERROR_BADDATA );

	/* When processing a SEQUENCE with default values for the elements the 
	   result may be a zero-length object, in which case we don't take any 
	   action.  Other too-short objects are an error */
	if( setofLength <= 2 )
		{
		if( setofLength == 0 && \
			( attributeInfoPtr->encodingFlags & FL_EMPTYOK ) )
			{
			/* The SET/SEQUENCE is empty, go back to where we were 
			   previously */
			*setofInfoPtrPtr = setofTOS( setofStack );
			ENSURES( *setofInfoPtrPtr != NULL );
			return( CRYPT_OK );
			}

		return( CRYPT_ERROR_BADDATA );
		}

	/* Remember assorted information such as where the SET/SEQUENCE ends.  
	   In addition if this is a SET OF/SEQUENCE OF, remember this as a 
	   restart point for when we're parsing the next item in the 
	   SET OF/SEQUENCE OF */
	parentSetofInfoPtr = setofTOS( setofStack );
	ENSURES( parentSetofInfoPtr != NULL );
	if( !setofStackPush( setofStack ) )
		{
		/* Stack overflow, there's a problem with the certificate */
		return( CRYPT_ERROR_BADDATA );
		}
	setofInfoPtr = setofTOS( setofStack );	/* New stack entry is empty */
	ENSURES( setofInfoPtr != NULL );
	setofInfoPtr->infoStart = attributeInfoPtr;
	if( attributeInfoPtr->encodingFlags & FL_SETOF )
		setofInfoPtr->flags |= SETOF_FLAG_RESTARTPOINT;
	if( !( attributeInfoPtr->encodingFlags & FL_EMPTYOK ) )
		setofInfoPtr->flags |= SETOF_FLAG_ISEMPTY;
	setofInfoPtr->subtypeParent = parentSetofInfoPtr->subtypeParent;
	setofInfoPtr->inheritedAttrFlags = parentSetofInfoPtr->inheritedAttrFlags;
	setofInfoPtr->startPos = stell( stream );
	setofInfoPtr->endPos = setofInfoPtr->startPos + setofLength;
	ENSURES( sanityCheckSetofStateInfo( setofInfoPtr ) );

	/* Check that the current SET OF is contained within its parent */
	if( setofInfoPtr->startPos < parentSetofInfoPtr->startPos || \
		setofInfoPtr->endPos > parentSetofInfoPtr->endPos )
		return( CRYPT_ERROR_BADDATA );

	*setofInfoPtrPtr = setofInfoPtr;

	return( CRYPT_OK );
	}

/* Check whether we're inside a SET OF/SEQUENCE OF and, if we are, restart 
   the processing at the start point.  Returns OK_SPECIAL if the end of the
   SET OF/SEQUENCE OF has been reached */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int setofCheckRestart( IN_PTR const STREAM *stream, 
					   INOUT_PTR SETOF_STATE_INFO *setofInfoPtr,
					   OUT_PTR_PTR \
							const ATTRIBUTE_INFO **attributeInfoPtrPtr )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( setofInfoPtr, sizeof( SETOF_STATE_INFO ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( sanityCheckSetofStateInfo( setofInfoPtr ) );

	/* If we've passed the end of the SET OF/SEQUENCE OF, let the caller 
	   know that we're done */
	if( stell( stream ) >= setofInfoPtr->endPos )
		return( OK_SPECIAL );

	/* We require at least one entry in a nonempty SET OF/SEQUENCE OF (which
	   is checked for above), if we haven't found one by this point then 
	   this is an error */
	if( setofInfoPtr->flags & SETOF_FLAG_ISEMPTY )
		return( CRYPT_ERROR_BADDATA );
	attributeInfoPtr = setofInfoPtr->infoStart;
	ENSURES( attributeInfoPtr != NULL );

	/* If this isn't a SET OF/SEQUENCE OF, we've run into an error */
	if( !( attributeInfoPtr->encodingFlags & FL_SETOF ) )
		return( CRYPT_ERROR_BADDATA );

	/* If we haven't made any progress in processing the SET OF/SEQUENCE OF,
	   in other words if we're still at the starting position, then further 
	   iterations through the loop won't make any difference, there's a bug 
	   in the decoder */
	ENSURES( stell( stream ) > setofInfoPtr->startPos );

	/* Retry from the restart point */
	attributeInfoPtr = attributeInfoPtr + 1;
	ENSURES( ( setofInfoPtr->flags & SETOF_FLAG_RESTARTPOINT ) || \
			 attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER );

	*attributeInfoPtrPtr = attributeInfoPtr;
	return( CRYPT_OK );
	}

/* Check whether we've reached the end of a SET/SET OF/SEQUENCE/SEQUENCE OF.  
   Returns OK_SPECIAL if the end has been reached */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int setofCheckEnd( IN_PTR const STREAM *stream, 
				   INOUT_PTR SETOF_STACK *setofStack,
				   INOUT_PTR const ATTRIBUTE_INFO **attributeInfoPtrPtr )
	{
	const ATTRIBUTE_INFO *oldAttributeInfoPtr = *attributeInfoPtrPtr;
	const ATTRIBUTE_INFO *attributeInfoPtr = *attributeInfoPtrPtr;
	const SETOF_STATE_INFO *setofInfoPtr;
	const int currentPos = stell( stream );
	int LOOP_ITERATOR;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( sanityCheckSetofStack( setofStack ) );
	REQUIRES( isShortIntegerRangeNZ( currentPos ) );
	
	setofInfoPtr = setofTOS( setofStack );
	ENSURES( setofInfoPtr != NULL );

	/* If we're still within the SET/SEQUENCE, we're done */
	if( currentPos < setofInfoPtr->endPos )
		return( CRYPT_OK );

	/* If we've read past the end of the SET/SEQUENCE then there's a problem
	   with the data.  Usually this will be caught by the encoding-validity
	   check, but if it's been disabled due to an oblivious-mode read then
	   we can end up catching the problem here */
	if( currentPos > setofInfoPtr->endPos )
		return( CRYPT_ERROR_BADDATA );

	/* We've reached the end of one or more layers of SET/SEQUENCE, keep 
	   popping SET/SEQUENCE state information until we can continue.   Note
	   that we check currentPos with '>=' rather than the more obvious '='
	   so that we can catch encoding errors and/or memory faults */
	LOOP_EXT_WHILE( !setofStackIsEmpty( setofStack ) && \
					currentPos >= setofInfoPtr->endPos, 
					SETOF_STATE_STACKSIZE )
		{
		const int flags = setofInfoPtr->flags;

		ENSURES( LOOP_INVARIANT_EXT_GENERIC( SETOF_STATE_STACKSIZE ) );

		/* Pop one level of parse state.  Alongside the standard stack-
		   underflow check we also check whether the stack is empty after 
		   the pop.  This condition should never occur because for any
		   (non-primitive) attribute data inside the { OID, OCTET STRING }
		   wrapper the encapsulation will always be a SEQUENCE (or perhaps 
		   SET):

			OID attributeType,
			OCTET STRING encapsulates {
				SEQUENCE {
					... ,
					... ,
					...
					}
				}

		   which means that it can never be popped until the end of the 
		   attribute is reached.  Since we exit before this, emptying the
		   stack indicates that there's spurious data at the end of the
		   attribute */
		if( !setofStackPop( setofStack ) )
			return( CRYPT_ERROR_BADDATA );
		if( setofStackIsEmpty( setofStack ) )
			return( CRYPT_ERROR_BADDATA );
		setofInfoPtr = setofTOS( setofStack );
		ENSURES( setofInfoPtr != NULL );
		attributeInfoPtr = setofInfoPtr->infoStart;

		/* If it's a pure SET/SEQUENCE rather than a SET OF/SEQUENCE OF and 
		   there are no more elements present, go to the end of the 
		   SET/SEQUENCE information in the decoding table */
		if( !( flags & SETOF_FLAG_RESTARTPOINT ) && \
			currentPos >= setofInfoPtr->endPos )
			{
			int status;

			status = findItemEnd( &attributeInfoPtr, 0 );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	ENSURES( LOOP_BOUND_OK );

	*attributeInfoPtrPtr = attributeInfoPtr;
	return( ( attributeInfoPtr != oldAttributeInfoPtr ) ? \
			OK_SPECIAL : CRYPT_OK );
	}
#endif /* USE_CERTIFICATES */
