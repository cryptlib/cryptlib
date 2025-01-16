/****************************************************************************
*																			*
*					cryptlib Internal Error Reporting API					*
*						Copyright Peter Gutmann 1992-2019					*
*																			*
****************************************************************************/

#include <stdarg.h>
#include <stdio.h>	/* Needed on some systems for macro-mapped *printf()'s */
#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

#ifdef USE_ERRMSGS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Format a printf-style error string.  The ERROR_INFO is annotated as
   OUT_ALWAYS because it's initalised unconditionally, the return status 
   exists only to signal to the caller that, in the case where further 
   information is added to the error information, that it's OK to add this
   further information.

   In the following we can't make the third arg a NONNULL_ARG because in the 
   Arm ABI it's a scalar value */

RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static BOOLEAN formatErrorString( OUT_ALWAYS ERROR_INFO *errorInfo, 
								  IN_STRING const char *format, 
								  IN_PTR va_list argPtr )
	{
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( format, 4 ) );

	ANALYSER_HINT_STRING( format );
	ANALYSER_HINT_FORMAT_STRING( format );

	//REQUIRES_B( verifyVAList( argPtr ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	/* This function is a bit tricky to deal with because of the 
	   braindamaged behaviour of some of the underlying functions that it 
	   may be mapped to.  Specifically, (v)snprintf() returns the number of 
	   bytes it *could* have written had it felt like it rather than how 
	   many it actually wrote on non-Windows systems and an error indicator 
	   with no guarantee of null-termination on Windows systems.  The latter 
	   isn't a problem because we both catch the error and don't require 
	   null termination, the former is more problematic because it can lead 
	   to a length indication that's larger than the actual buffer.  To 
	   handle this we explicitly check for an overflow as well as an 
	   error/underflow */
	errorInfo->errorStringLength = \
				vsprintf_s( errorInfo->errorString, MAX_ERRMSG_SIZE, 
							format, argPtr ); 
	if( errorInfo->errorStringLength <= 0 || \
		errorInfo->errorStringLength > MAX_ERRMSG_SIZE )
		{
		DEBUG_DIAG(( "Invalid error string data" ));
		assert( DEBUG_WARN );
		setErrorString( errorInfo, 
						"(Couldn't record error information)", 35 );

		return( FALSE );
		}

	return( TRUE );
	}

/* Append a second error string containing further explanatory information 
   to an existing one.  There's no failure/success return value for this 
   function since there's not much that we can do in the case of a failure, 
   we rely on the existing primary error string to convey as much 
   information as possible */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void appendErrorString( INOUT_PTR ERROR_INFO *errorInfo, 
							   IN_BUFFER( extErrorStringLength ) \
									const char *extErrorString, 
							   IN_LENGTH_ERRORMESSAGE \
									const int extErrorStringLength )
	{
	BOOLEAN appendDots = FALSE;
	int secondStringLength = extErrorStringLength;

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtrDynamic( extErrorString, extErrorStringLength ) );

	REQUIRES_V( errorInfo->errorStringLength > 0 && \
				errorInfo->errorStringLength <= MAX_ERRMSG_SIZE );
	REQUIRES_V( extErrorStringLength > 0 && \
				extErrorStringLength <= MAX_ERRMSG_SIZE );

	/* If there's no room to store the full strings, truncate the second one,
	   which is secondary and therefore less important than the first one */
	if( errorInfo->errorStringLength + \
							secondStringLength >= MAX_ERRMSG_SIZE - 8 )
		{
		/* If there's nothing much to be added by appending the second 
		   string then don't do anything */
		if( secondStringLength < 8 )
			return;

		/* Append a truncated form of the second string to the first one */
		secondStringLength = MAX_ERRMSG_SIZE - \
								( errorInfo->errorStringLength + 8 );
		ENSURES_V( rangeCheck( secondStringLength, 1, 
						MAX_ERRMSG_SIZE - errorInfo->errorStringLength ) );
		appendDots = TRUE;
		}

	/* Append the second string to the first, with dots to indicate 
	   truncation if necessary */
	REQUIRES_V( boundsCheck( errorInfo->errorStringLength,
							 secondStringLength, MAX_ERRMSG_SIZE ) );
	memcpy( errorInfo->errorString + errorInfo->errorStringLength,
			extErrorString, secondStringLength );
	errorInfo->errorStringLength += secondStringLength;
	if( appendDots )
		{
		memcpy( errorInfo->errorString + errorInfo->errorStringLength,
				"...", 3 );
		errorInfo->errorStringLength += 3;
		}
#ifndef NDEBUG
	/* Null-terminate the string for use with DEBUG_DIAG() and similar */
	errorInfo->errorString[ errorInfo->errorStringLength ] = '\0';
#endif /* NDEBUG */
	}

/****************************************************************************
*																			*
*							Clear/Set/Copy Error Strings					*
*																			*
****************************************************************************/

/* Set a fixed string as the error message.  This is used to set a 
   predefined error string from something like a table of error messages */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void setErrorString( OUT_PTR ERROR_INFO *errorInfo, 
					 IN_BUFFER( stringLength ) const char *string, 
					 IN_LENGTH_ERRORMESSAGE const int stringLength )
	{
	int length = stringLength;

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtrDynamic( string, stringLength ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	/* Since we're already in an error-handling function we don't use the 
	   REQUIRES() predicate (which would result in an infinite page fault)
	   but make the sanity-checking of parameters explicit */
	if( stringLength <= 0 || stringLength > MAX_ERRMSG_SIZE )
		{
		DEBUG_DIAG(( "Invalid error string data" ));
		assert( DEBUG_WARN );
		string = "(Couldn't record error information)";
		length = 35;
		}
	
	REQUIRES_V( rangeCheck( length, 1, MAX_ERRMSG_SIZE ) );
	memcpy( errorInfo->errorString, string, length );
	errorInfo->errorStringLength = length;
	}

/* Copy error information from a low-level state structure (for example a 
   stream) to a high-level one (for example a session or envelope) */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void copyErrorInfo( OUT_PTR ERROR_INFO *destErrorInfo, 
					IN_PTR const ERROR_INFO *srcErrorInfo )
	{
	assert( isWritePtr( destErrorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( srcErrorInfo, sizeof( ERROR_INFO ) ) );

	memset( destErrorInfo, 0, sizeof( ERROR_INFO ) );
	if( srcErrorInfo->errorStringLength > 0 )
		{
		setErrorString( destErrorInfo, srcErrorInfo->errorString, 
						srcErrorInfo->errorStringLength );
		}
	}

/* Read error information from an object into an error-info structure */

STDC_NONNULL_ARG( ( 1 ) ) \
int readErrorInfo( OUT_PTR ERROR_INFO *errorInfo, 
				   IN_HANDLE const CRYPT_HANDLE objectHandle )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( objectHandle == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( objectHandle ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	/* Read any additional error information that may be available */
	setMessageData( &msgData, errorInfo->errorString, MAX_ERRMSG_SIZE );
	status = krnlSendMessage( objectHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_ATTRIBUTE_ERRORMESSAGE );
	if( cryptStatusError( status ) )
		return( status );
	errorInfo->errorStringLength = msgData.length;
	ENSURES( errorInfo->errorStringLength > 0 && \
			 errorInfo->errorStringLength < MAX_ERRMSG_SIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Return Extended Error Information					*
*																			*
****************************************************************************/

/* Exit after recording a detailed error message.  This is used by lower-
   level code to provide more information to the caller than a basic error 
   code.  Felix qui potuit rerum cognoscere causas.

   Since we're already in an error-handling function when we call these 
   functions we don't use the REQUIRES() predicate (which would result in an 
   infinite page fault) but make the sanity-checking of parameters 
   explicit */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) STDC_PRINTF_FN( 3, 4 ) \
int retExtFn( IN_ERROR const int status, 
			  OUT_PTR ERROR_INFO *errorInfo, 
			  FORMAT_STRING const char *format, ... )
	{
	va_list argPtr;

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( format, 4 ) );

	REQUIRES( cryptStatusError( status ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	va_start( argPtr, format );
	formatErrorString( errorInfo, format, argPtr );
	va_end( argPtr );

	DEBUG_PRINT_COND( memcmp( errorInfo->errorString, "Key in ", 7 ),
					  ( "%s\n", errorInfo->errorString ) );
					  /* The key usage message is a warning so we don't 
					     print this as it occurs for many certifiate usage 
						 checks */

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) STDC_PRINTF_FN( 3, 4 ) \
int retExtArgFn( IN_ERROR const int status, 
				 OUT_PTR ERROR_INFO *errorInfo, 
				 FORMAT_STRING const char *format, ... )
	{
	va_list argPtr;

	/* This function is identical to retExtFn() except that it doesn't trap
	   CRYPT_ARGERROR_xxx values, since they're valid return values in some
	   cases */

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( format, 4 ) );

	REQUIRES( cryptStatusError( status ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	va_start( argPtr, format );
	formatErrorString( errorInfo, format, argPtr );
	va_end( argPtr );

	DEBUG_PUTS( errorInfo->errorString );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) STDC_PRINTF_FN( 4, 5 ) \
int retExtObjFn( IN_ERROR const int status, 
				 OUT_PTR ERROR_INFO *errorInfo, 
				 IN_HANDLE const CRYPT_HANDLE extErrorObject, 
				 FORMAT_STRING const char *format, ... )
	{
	ERROR_INFO extErrorInfo;
	va_list argPtr;
	BOOLEAN errorStringOK;
	int errorStringLength, extErrorStatus;

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( format, 4 ) );

	REQUIRES( cryptStatusError( status ) );
	REQUIRES( extErrorObject == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( extErrorObject ) );

	/* Clear return value */
	clearErrorInfo( errorInfo );

	/* If we're being used as a direct pass-through, for example when a 
	   device acts as a keyset, then we just copy the error string up from
	   the lower-level object and exit  */
	if( strlen( format ) == 4 && !memcmp( format, "NULL", 4 ) )
		{
		extErrorStatus = readErrorInfo( &extErrorInfo, extErrorObject );
		if( cryptStatusOK( extErrorStatus ) )
			{
			copyErrorInfo( errorInfo, &extErrorInfo );

			DEBUG_PUTS( errorInfo->errorString );
			}

		return( status );
		}

	/* Format the basic error string */
	va_start( argPtr, format );
	errorStringOK = formatErrorString( errorInfo, format, argPtr );
	va_end( argPtr );
	if( !errorStringOK )
		{
		/* If we couldn't format the basic error string then there's no 
		   point in continuing.  formatErrorString() throws a debug 
		   exception if there's a problem so there's no need to throw one 
		   here */
		return( status );
		}
	errorStringLength = errorInfo->errorStringLength;
	ENSURES( errorStringLength > 0 && errorStringLength < MAX_ERRMSG_SIZE );

	/* Check whether there's any additional error information available */
	extErrorStatus = readErrorInfo( &extErrorInfo, extErrorObject );
	if( cryptStatusError( extErrorStatus ) )
		{
		/* Nothing further to report, exit */
		return( status );
		}

	/* There's additional information present via the additional object, 
	   fetch it and append it to the higher-level error message */
	appendErrorString( errorInfo, ": ", 2 );
	appendErrorString( errorInfo, extErrorInfo.errorString, 
					   extErrorInfo.errorStringLength );

	DEBUG_PUTS( errorInfo->errorString );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) STDC_PRINTF_FN( 4, 5 ) \
int retExtErrFn( IN_ERROR const int status, 
				 OUT_PTR ERROR_INFO *errorInfo, 
				 IN_PTR const ERROR_INFO *existingErrorInfo, 
				 FORMAT_STRING const char *format, ... )
	{
	va_list argPtr;
	char extErrorString[ MAX_ERRMSG_SIZE + 8 ];
	int extErrorStringLength = 0;
	BOOLEAN errorStringOK;

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( existingErrorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( format, 4 ) );

	/* We can't clear the return value at this point because errorInfo
	   could be the same as existingErrorInfo */

	/* This function is used when the caller wants to add a possible
	   existing lower-level error string to the current error string.  If
	   there's no lower-level error information present, this function acts
	   like retExt(), "Error string".  If there is lower-level error
	   information present it appends it to the current error string, 
	   "Error string: Lower-level error string".  
	   
	   Since the lower-level error string may already be held in the 
	   errorInfo buffer where the current error string needs to go, we copy 
	   the string into a temporary buffer from where it can be appended back 
	   onto the string in the errorInfo buffer */
	if( existingErrorInfo->errorStringLength > 0 && \
		existingErrorInfo->errorStringLength <= MAX_ERRMSG_SIZE )
		{
		REQUIRES( rangeCheck( existingErrorInfo->errorStringLength, 1, 
							  MAX_ERRMSG_SIZE ) );
		memcpy( extErrorString, existingErrorInfo->errorString,
				existingErrorInfo->errorStringLength );
		extErrorStringLength = existingErrorInfo->errorStringLength;
		}
	ENSURES( extErrorStringLength >= 0 && \
			 extErrorStringLength <= MAX_ERRMSG_SIZE );

	/* Format the basic error string */
	clearErrorInfo( errorInfo );
	va_start( argPtr, format );
	errorStringOK = formatErrorString( errorInfo, format, argPtr );
	va_end( argPtr );
	if( extErrorStringLength <= 0 )
		{
		/* If there's no lower-level error information present then we just
		   act like the standard retExt() */
		return( status );
		}
	if( !errorStringOK )
		{
		/* If we couldn't format the basic error string then there's no 
		   point in continuing.  formatErrorString() throws a debug 
		   exception if there's a problem so there's no need to throw one 
		   here */
		return( status );
		}

	/* Append the additional status string */
	appendErrorString( errorInfo, ": ", 2 );
	appendErrorString( errorInfo, extErrorString, extErrorStringLength );

	DEBUG_PUTS( errorInfo->errorString );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) STDC_PRINTF_FN( 3, 4 ) \
int retExtAdditionalFn( IN_ERROR const int status, 
						INOUT_PTR ERROR_INFO *errorInfo, 
						FORMAT_STRING const char *format, ... )
	{
	va_list argPtr;
	char extErrorString[ MAX_ERRMSG_SIZE + 8 ];
	int extErrorStringLength;

	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( format, 4 ) );

	/* This function is typically used when the caller wants to convert 
	   something like "Low-level error string" into "Low-level error string,
	   additional comments".  
	   
	   First we need to check that there's actually a base error string 
	   present.  This situation can occur when a low-level function returns 
	   a cryptlib-level error status without getting/setting any extended 
	   error information, which then percolates up to a point where it's 
	   returned via a retExt(). 
	   
	   We have to be careful how we present this information because the
	   additional-information string that we're about to append could appear 
	   to be part of any indication that there's no error information 
	   present.  The additional information will be in the form:

		$MAIN, because ...
		$MAIN, this could be because ...
		$MAIN, however other data suggests ...

	   There isn't any obvious string we can use here that doesn't have the
	   potential to read in a confusing manner when the additional 
	   information is appended, "(Primary error information missing)" seems
	   to be the best bet.  In any case it's mitigated by the fact that this
	   situation should never really occur */
	if( errorInfo->errorStringLength <= 0 || \
		errorInfo->errorStringLength > MAX_ERRMSG_SIZE )
		{
		DEBUG_DIAG(( "Invalid error string data" ));
		assert_nofuzz( DEBUG_WARN );
		setErrorString( errorInfo, 
						"(Primary error information missing)", 35 );
		}

	/* Format the additional-comments string prior to appending it to the 
	   base error string */
	va_start( argPtr, format );
	extErrorStringLength = vsprintf_s( extErrorString, MAX_ERRMSG_SIZE, 
									   format, argPtr ); 
	va_end( argPtr );
	if( extErrorStringLength <= 0 || extErrorStringLength > MAX_ERRMSG_SIZE )
		{
		DEBUG_DIAG(( "Invalid error string data" ));
		assert( DEBUG_WARN );
		setErrorString( errorInfo, 
						"(Couldn't record error information)", 35 );
		return( status );
		}

	/* Append the additional status string */
	appendErrorString( errorInfo, extErrorString, extErrorStringLength );

	DEBUG_PUTS( errorInfo->errorString );

	return( status );
	}

/****************************************************************************
*																			*
*								Helper Functions							*
*																			*
****************************************************************************/

/* Additional helper functions used to provide extended information for
   error messages.  The first set of functions provides names for error
   status values, algorithms, and key IDs */

CHECK_RETVAL_PTR_NONNULL \
const char *getStatusName( IN_STATUS const int errorStatus )
	{
	static const OBJECT_NAME_INFO objectNameInfo[] = {
		{ CRYPT_ERROR_PARAM1, "CRYPT_ERROR_PARAM1" },
		{ CRYPT_ERROR_PARAM2, "CRYPT_ERROR_PARAM2" },
		{ CRYPT_ERROR_PARAM3, "CRYPT_ERROR_PARAM3" },
		{ CRYPT_ERROR_PARAM4, "CRYPT_ERROR_PARAM4" },
		{ CRYPT_ERROR_PARAM5, "CRYPT_ERROR_PARAM5" },
		{ CRYPT_ERROR_PARAM6, "CRYPT_ERROR_PARAM6" },
		{ CRYPT_ERROR_PARAM7, "CRYPT_ERROR_PARAM7" },
		{ CRYPT_ERROR_MEMORY, "CRYPT_ERROR_MEMORY" },
		{ CRYPT_ERROR_NOTINITED, "CRYPT_ERROR_NOTINITED" },
		{ CRYPT_ERROR_INITED, "CRYPT_ERROR_INITED" },
		{ CRYPT_ERROR_NOSECURE, "CRYPT_ERROR_NOSECURE" },
		{ CRYPT_ERROR_RANDOM, "CRYPT_ERROR_RANDOM" },
		{ CRYPT_ERROR_FAILED, "CRYPT_ERROR_FAILED" },
		{ CRYPT_ERROR_INTERNAL, "CRYPT_ERROR_INTERNAL" },
		{ CRYPT_ERROR_NOTAVAIL, "CRYPT_ERROR_NOTAVAIL" },
		{ CRYPT_ERROR_PERMISSION, "CRYPT_ERROR_PERMISSION" },
		{ CRYPT_ERROR_WRONGKEY, "CRYPT_ERROR_WRONGKEY" },
		{ CRYPT_ERROR_INCOMPLETE, "CRYPT_ERROR_INCOMPLETE" },
		{ CRYPT_ERROR_COMPLETE, "CRYPT_ERROR_COMPLETE" },
		{ CRYPT_ERROR_TIMEOUT, "CRYPT_ERROR_TIMEOUT" },
		{ CRYPT_ERROR_INVALID, "CRYPT_ERROR_INVALID" },
		{ CRYPT_ERROR_SIGNALLED, "CRYPT_ERROR_SIGNALLED" },
		{ CRYPT_ERROR_OVERFLOW, "CRYPT_ERROR_OVERFLOW" },
		{ CRYPT_ERROR_UNDERFLOW, "CRYPT_ERROR_UNDERFLOW" },
		{ CRYPT_ERROR_BADDATA, "CRYPT_ERROR_BADDATA" },
		{ CRYPT_ERROR_SIGNATURE, "CRYPT_ERROR_SIGNATURE" },
		{ CRYPT_ERROR_OPEN, "CRYPT_ERROR_OPEN" },
		{ CRYPT_ERROR_READ, "CRYPT_ERROR_READ" },
		{ CRYPT_ERROR_WRITE, "CRYPT_ERROR_WRITE" },
		{ CRYPT_ERROR_NOTFOUND, "CRYPT_ERROR_NOTFOUND" },
		{ CRYPT_ERROR_DUPLICATE, "CRYPT_ERROR_DUPLICATE" },
		{ CRYPT_ENVELOPE_RESOURCE, "CRYPT_ENVELOPE_RESOURCE" },
		{ CRYPT_OK, "<Unknown>" }, { CRYPT_OK, "<Unknown>" },
		};

	REQUIRES_EXT( cryptStatusError( errorStatus ), "<Unknown>" );

	return( getObjectName( objectNameInfo,
						   FAILSAFE_ARRAYSIZE( objectNameInfo, \
											   OBJECT_NAME_INFO ),
						   errorStatus ) ); 
	}

CHECK_RETVAL_PTR_NONNULL \
const char *getAlgoName( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	static const OBJECT_NAME_INFO objectNameInfo[] = {
		/* Conventional algorithms */
		{ CRYPT_ALGO_DES, "DES" },
		{ CRYPT_ALGO_3DES, "3DES" },
		{ CRYPT_ALGO_IDEA, "IDEA" },
		{ CRYPT_ALGO_CAST, "CAST-128" },
		{ CRYPT_ALGO_RC2, "RC2" },
		{ CRYPT_ALGO_RC4, "RC4" },
		{ CRYPT_ALGO_AES, "AES" },
		/* PKC algorithms */
		{ CRYPT_ALGO_DH, "DH" },
		{ CRYPT_ALGO_RSA, "RSA" },
		{ CRYPT_ALGO_DSA, "DSA" },
		{ CRYPT_ALGO_ELGAMAL, "ElGamal" },
		{ CRYPT_ALGO_ECDSA,	"ECDSA" },
		{ CRYPT_ALGO_ECDH, "ECDH" },
		{ CRYPT_ALGO_EDDSA,	"EDDSA" },
		{ CRYPT_ALGO_25519,	"Curve25519" },
		/* Hash algorithms */
		{ CRYPT_ALGO_MD5, "MD5" },
		{ CRYPT_ALGO_SHA1, "SHA1" },
		{ CRYPT_ALGO_SHA2, "SHA2" },
		{ CRYPT_ALGO_SHAng,	"SHAng" },
		/* Generic secret algorithm.  This is a bit of an odd one because 
		   it's only visible internally, but we need to have some 
		   description available for it in case an attempt to create a 
		   context with it fails */
		{ CRYPT_IALGO_GENERIC_SECRET, "Generic Secret" },
		{ CRYPT_ALGO_NONE, "<Unknown>" }, { CRYPT_ALGO_NONE, "<Unknown>" },
		};

	REQUIRES_EXT( isConvAlgo( cryptAlgo ) || isPkcAlgo( cryptAlgo ) || \
				  isHashAlgo( cryptAlgo ) || isSpecialAlgo( cryptAlgo ), 
				  "<Unknown>" );

	return( getObjectName( objectNameInfo,
						   FAILSAFE_ARRAYSIZE( objectNameInfo, \
											   OBJECT_NAME_INFO ),
						   cryptAlgo ) ); 
	}

CHECK_RETVAL_PTR_NONNULL \
const char *getAlgoNameEx( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
						   IN_RANGE( 0, 100 ) const int cryptParam )
	{
	REQUIRES_EXT( isHashAlgo( cryptAlgo ), "<Unknown>" );
	REQUIRES_EXT( cryptParam >= 0 && cryptParam <= 100, "<Unknown>" );

	/* If it's not a parameterised algorithm or there's no parameter 
	   present, just return the base algorithm */
	if( !( isParameterisedHashAlgo( cryptAlgo ) || \
		   isParameterisedMacAlgo( cryptAlgo ) ) || cryptParam <= 0 )
		return( getAlgoName( cryptAlgo ) );

	/* The set of parameterised hash algorithms is small enough that we can 
	   just hardcode in the selection for now */
	return( ( cryptParam == 32 ) ? "SHA2-256" : \
			( cryptParam == 48 ) ? "SHA2-384" : \
			( cryptParam == 64 ) ? "SHA2-512" : "SHA2" );
	}

CHECK_RETVAL_PTR_NONNULL \
const char *getModeName( IN_MODE const CRYPT_MODE_TYPE cryptMode )
	{
	static const OBJECT_NAME_INFO objectNameInfo[] = {
		{ CRYPT_MODE_ECB, "ECB" },
		{ CRYPT_MODE_CBC, "CBC" },
		{ CRYPT_MODE_CFB, "CFB" },
		{ CRYPT_MODE_GCM, "GCM" },
		{ CRYPT_ALGO_NONE, "<Unknown>" }, { CRYPT_ALGO_NONE, "<Unknown>" },
		};

	REQUIRES_EXT( cryptMode > CRYPT_MODE_NONE && \
				  cryptMode < CRYPT_MODE_LAST, "<Unknown>" );

	return( getObjectName( objectNameInfo,
						   FAILSAFE_ARRAYSIZE( objectNameInfo, \
											   OBJECT_NAME_INFO ),
						   cryptMode ) ); 
	}

CHECK_RETVAL_PTR_NONNULL \
const char *getKeyIDName( IN_KEYID const CRYPT_KEYID_TYPE keyIDtype )
	{
	static const OBJECT_NAME_INFO objectNameInfo[] = {
		{ CRYPT_KEYID_NAME, "name" },
		{ CRYPT_KEYID_URI, "email/URI" },
		{ CRYPT_IKEYID_KEYID, "keyID" },
		{ CRYPT_IKEYID_PGPKEYID, "PGP keyID" },
		{ CRYPT_IKEYID_CERTID, "certificate ID" },
		{ CRYPT_IKEYID_SUBJECTID, "subject DN ID" },
		{ CRYPT_IKEYID_ISSUERID, "issuerAndSerialNumber ID" },
		{ CRYPT_IKEYID_ISSUERANDSERIALNUMBER, "issuerAndSerialNumber" },
		{ CRYPT_KEYID_NONE, "<Unknown>" }, { CRYPT_KEYID_NONE, "<Unknown>" },
		};

	REQUIRES_EXT( isEnumRange( keyIDtype, CRYPT_KEYID ), "<Unknown>" );

	/* Return a description of the key ID.  These are meant to be used in 
	   strings of the form "$operation for given %s failed", so "key read "
	   "for given email/URI failed" */
	return( getObjectName( objectNameInfo,
						   FAILSAFE_ARRAYSIZE( objectNameInfo, \
											   OBJECT_NAME_INFO ),
						   keyIDtype ) ); 
	}

/* Get the holder name of a certificate, used to display information on 
   which certificate was used for a failed crypto operation like a signature 
   check.  The function returns a pointer to the passed-in buffer so that it
   can be used directly in print statements */

CHECK_RETVAL_PTR_NONNULL STDC_NONNULL_ARG( ( 2 ) ) \
const char *getCertHolderName( const CRYPT_CERTIFICATE iCryptCert,
							   OUT_BUFFER_FIXED( bufSize ) char *buffer,
							   IN_LENGTH_SHORT_MIN( 16 ) const int bufSize )
	{
	MESSAGE_DATA msgData;
	int value, status;

	REQUIRES_EXT( isHandleRangeValid( iCryptCert ), "<Unknown>" );
	REQUIRES_EXT( isShortIntegerRangeMin( bufSize, 16 ), "<Unknown>" );

	assert( isWritePtr( buffer, bufSize ) );

	/* Clear return value */
	memset( buffer, 0, min( bufSize, 16 ) );

	/* Read the holder name from the certificate and return it to the caller 
	   ready for use in a print statement */
	setMessageData( &msgData, buffer, bufSize );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE, 
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_HOLDERNAME );
		}
	else
		{
		/* We may have been passed a raw public-key context, in which case 
		   we try and return the label if it has one */
		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_LABEL );
		}
	if( cryptStatusOK( status ) )
		sanitiseString( buffer, bufSize, msgData.length );
	else
		memcpy( buffer, "<Unknown>", 10 );	/* String + '\0' */

	return( buffer );
	}

/* Format hex data, typically a fingerprint (hash value) for display in an 
   error message */

STDC_NONNULL_ARG( ( 1, 3 ) ) \
void formatHexData( OUT_BUFFER_FIXED( hexTextMaxLen ) char *hexText, 
					IN_LENGTH_SHORT_MIN( 48 ) const int hexTextMaxLen,
					IN_BUFFER( hexDataLen ) const BYTE *hexData,
					IN_LENGTH_SHORT_MIN( 4 ) const int hexDataLen )
	{
	assert( isWritePtr( hexText, hexTextMaxLen ) );
	assert( isReadPtr( hexData, hexDataLen ) );

	REQUIRES_V( isShortIntegerRangeMin( hexTextMaxLen, 48 ) );
	REQUIRES_V( isShortIntegerRangeMin( hexDataLen, 4 ) );

	/* Clear return value */
	REQUIRES_V( isShortIntegerRangeMin( hexTextMaxLen, 48 ) ); 
	memset( hexText, 0, min( 16, hexTextMaxLen ) );

	/* Format the hex data as ASCII hex.  If it's 10 bytes or less then we 
	   output the entire quantity */
	if( hexDataLen <= 10 )
		{
		int offset = 0;
		LOOP_INDEX i;

		LOOP_SMALL( i = 0, i < hexDataLen - 1, i++ )
			{
			ENSURES_V( LOOP_INVARIANT_SMALL( i, 0, hexDataLen - 2 ) );

			REQUIRES_V( isShortIntegerRangeNZ( hexTextMaxLen - offset ) );
			offset += sprintf_s( hexText + offset, hexTextMaxLen - offset, 
								 "%02X ", byteToInt( hexData[ i ] ) );
			}
		ENSURES_V( LOOP_BOUND_OK );
		REQUIRES_V( isShortIntegerRangeNZ( hexTextMaxLen - offset ) );
		sprintf_s( hexText + offset, hexTextMaxLen - offset, "%02X", 
				   byteToInt( hexData[ i ] ) );
		
		return;
		}

	/* It's more than 10 bytes, only output the first 6 and last 4 bytes.  
	   The potential expansion factor is ( hexDataLen * 3 ) + 1 (+3 for the 
	   ellipses, but -2 for the absent spaces at the start and end of the 
	   string).  Since we currently limit the input to 10 bytes we never 
	   output more than 31 characters of text which is well under the 
	   48-byte minimum buffer size */
	sprintf_s( hexText, hexTextMaxLen, 
			   "%02X %02X %02X %02X %02X %02X ... %02X %02X %02X %02X",
			   hexData[ 0 ], hexData[ 1 ], hexData[ 2 ], hexData[ 3 ],
			   hexData[ 4 ], hexData[ 5 ],
			   hexData[ hexDataLen - 4 ], hexData[ hexDataLen - 3 ],
			   hexData[ hexDataLen - 2 ], hexData[ hexDataLen - 1 ] );
	}
#else

/****************************************************************************
*																			*
*						Minimal Error Reporting Functions					*
*																			*
****************************************************************************/

/* Even if we're not using extended error reporting there is one minimal 
   facility that we still need to support, which is the copying of an integer 
   error code from source to destination */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void copyErrorInfo( OUT_PTR ERROR_INFO *destErrorInfo, 
					IN_PTR const ERROR_INFO *srcErrorInfo )
	{
	assert( isWritePtr( destErrorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( srcErrorInfo, sizeof( ERROR_INFO ) ) );

	memset( destErrorInfo, 0, sizeof( ERROR_INFO ) );
	destErrorInfo->errorCode = srcErrorInfo->errorCode;
	}
#endif /* USE_ERRMSGS */
