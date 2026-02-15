/****************************************************************************
*																			*
*						cryptlib Internal Debugging API						*
*						Copyright Peter Gutmann 1992-2019					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
#else
  #include "crypt.h"
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* The following functions are intended purely for diagnostic purposes 
   during development.  They perform minimal checking (for example using 
   assertions rather than returning error codes, since the calling code 
   can't hardwire in tests for their return status), and should only
   be used with a debugger */

/****************************************************************************
*																			*
*							Diagnostic-dump Functions						*
*																			*
****************************************************************************/

#if !defined( NDEBUG ) || defined( DEBUG_DIAGNOSTIC_ENABLE ) 

/* Older versions of the WinCE runtime don't provide complete stdio
   support so we have to emulate it using wrappers for native 
   functions */

#if defined( __WINCE__ ) && _WIN32_WCE < 500

int remove( const char *pathname )
	{
	wchar_t wcBuffer[ _MAX_PATH + 1 ];

	mbstowcs( wcBuffer, pathname, 
			  strnlen_s( pathname, MAX_PATH_LENGTH ) + 1 );
	DeleteFile( wcBuffer );

	return( 0 );
	}
#endif /* WinCE < 5.x doesn't have remove() */

/* Output text to the debug console or whatever the OS'es nearest equivalent
   is.  If possible this is normally done via a macro in a debug.h that 
   remaps the debug-output macros to the appropriate function but Windows 
   only provides a puts()-equivalent and not a printf()-equivalent and under 
   Unix we need to send the output to stderr which can't easily be done in a 
   macro */
   
#if defined( __WIN32__ ) || defined( __WINCE__ )

/* OutputDebugString() under Windows isn't very reliable, it's implemented 
   using a 4kB chunk of shared memory DBWIN_BUFFER controlled by a mutex 
   DBWinMutex and two events DBWIN_BUFFER_READY and DBWIN_DATA_READY.  
   OutputDebugString() waits for exclusive access to DBWinMutex, maps in 
   DBWIN_BUFFER, waits for DBWIN_BUFFER_READY to be signalled, copies in up 
   to 4K of data, fires DBWIN_DATA_READY, and releases the mutex.  If any of 
   these operations fail, the call to OutputDebugString() is treated as a 
   no-op and we never see the output.  On the receiving side the debugger 
   performs the obvious actions to receive the data.  
   
   Beyond this Rube-Goldberg message-passing mechanism there are also 
   problems with permissions on the mutex and the way the DACL for it has 
   been tweaked in almost every OS release.  The end result of this is that 
   data sent to OutputDebugString() may be randomly lost if other threads 
   are also sending data to it (e.g. Visual Studio as part of its normal 
   chattiness about modules and threads being loaded/started/unloaded/
   stopped/etc).  
   
   The only way to avoid this is to step through the code that uses
   OutputDebugString() so that enough delay is inserted to allow other 
   callers and the code being debugged to get out of each others' hair */

int debugPrintf( IN_STRING const char *format, ... )
	{
	va_list argPtr;
	char buffer[ 1024 + 8 ];
	int length;

	assert( isReadPtr( format, 2 ) );

	va_start( argPtr, format );
#if VC_GE_2005( _MSC_VER )
	length = vsnprintf_s( buffer, 1024, _TRUNCATE, format, argPtr );
#else
	length = vsprintf( buffer, format, argPtr );
#endif /* VC++ 2005 or newer */
	va_end( argPtr );
#if defined( __WIN32__ ) 
	OutputDebugString( buffer );
#else
	NKDbgPrintfW( L"%s", buffer )
#endif /* __WIN32__ */

	return( length );
	}

/* debugPrintf() is used as a building block to create more complex
   diagnostic functions via macro wrappers, however since this often results 
   in multiple calls to the function it can produce mangled output in the 
   presence of multiple threads.  The following function takes the multiple 
   calls macros like DEBUG_DIAG() macro and turns them into a single call to 
   OutputDebugString() */

int debugPrintfAtomic( IN_STRING const char *file, 
					   IN_STRING const char *function, 
					   const int line, 
					   IN_STRING const char *format, ... )
	{
	va_list argPtr;
	char buffer[ 1536 + 8 ];
	int length, totalLength;

	assert( isReadPtr( file, 4 ) );
	assert( isReadPtr( function, 4 ) );
	assert( isReadPtr( function, 2 ) );

	va_start( argPtr, format );
#if VC_GE_2005( _MSC_VER )
	length = sprintf_s( buffer, 1536, "%s:%s:%d: ", file, function, line ); 
	ENSURES( rangeCheck( length, 8, 1536 - 1 ) );
	totalLength = length;
	length = vsnprintf_s( buffer + length, 1536 - length, _TRUNCATE, 
						  format, argPtr );
	ENSURES( rangeCheck( length, 8, 1536 - 1 ) );
	totalLength += length;
	length = sprintf_s( buffer + totalLength, 1536 - totalLength, ".\n" );
	ENSURES( rangeCheck( length, 2, 1536 - 1 ) );
	totalLength += length;
#else
	length = sprintf( buffer, "%s:%s:%d: ", file, function, line ); 
	ENSURES( rangeCheck( length, 8, 1536 - 1 ) );
	totalLength = length;
	length = vsprintf( buffer + length, format, argPtr );
	ENSURES( rangeCheck( length, 8, 1536 - 1 ) );
	totalLength += length;
	length = sprintf( buffer + totalLength, ".\n" );
	ENSURES( rangeCheck( length, 2, 1536 - 1 ) );
	totalLength += length;
#endif /* VC++ 2005 or newer */
	va_end( argPtr );
#if defined( __WIN32__ ) 
	OutputDebugString( buffer );
#else
	NKDbgPrintfW( L"%s", buffer )
#endif /* __WIN32__ */

	return( totalLength );
	}

#elif defined( __UNIX__ )

#include <stdarg.h>			/* Needed for va_list */

int debugPrintf( const char *format, ... )
	{
	va_list argPtr;
	int length;

	assert( isReadPtr( format, 2 ) );

	va_start( argPtr, format );
	length = vfprintf( stderr, format, argPtr );
	va_end( argPtr );
	fflush( stderr );	/* Just in case it gets stuck in a buffer */

	return( length );
	}

#elif defined( __MVS__ ) || defined( __VMCMS__ ) || defined( __ILEC400__ )

/* Implementing debugPrintf() on EBCDIC systems is problematic because all
   internal strings are ASCII, so that both the format specifiers and any
   string arguments that they're being used with won't work with functions
   that expect EBCDIC strings.  To get around this we use the internal 
   vsPrintf_s() that handles all of the format types that cryptlib uses, 
   and then convert the result to EBCDIC */

int debugPrintf( const char *format, ... )
	{
	va_list argPtr;
	char buffer[ 1024 + 8 ];
	int length;

	assert( isReadPtr( format, 2 ) );

	/* Format the arguments as an ASCII string */
	va_start( argPtr, format );
	length = vsPrintf_s( buffer, 1024, format, argPtr );
	va_end( argPtr );

	/* Convert it to EBCDIC and display it */
	bufferToEbcdic( buffer, buffer );
#pragma convlit( suspend )
	printf( "%s", buffer );
#pragma convlit( resume )
	fflush( stdout );	/* Just in case it gets stuck in a buffer */

	return( length );
	}
#else

#include <stdarg.h>			/* Needed for va_list */

int debugPrintf( const char *format, ... )
	{
	va_list argPtr;
	int length;

	assert( isReadPtr( format, 2 ) );

	va_start( argPtr, format );
	length = vprintf( format, argPtr );
	va_end( argPtr );

	return( length );
	}
#endif /* OS-specific debug output functions */

/* When debugging a multithreaded application the output from different
   threads can interfere with each other, so we provide a locking
   mechanism around a series of output operations to keep things clear */

#ifdef __WIN32__
  static CRITICAL_SECTION printMutex;
  static int printMutexInited = FALSE;
#endif /* __WIN32__ */

void debugPrintBegin( void )
	{
#ifdef __WIN32__
	if( !printMutexInited )
		{
		InitializeCriticalSection( &printMutex );
		printMutexInited = TRUE;
		}
	EnterCriticalSection( &printMutex );
#endif /* __WIN32__ */
	}

void debugPrintEnd( void )
	{
#ifdef __WIN32__
	LeaveCriticalSection( &printMutex );
#endif /* __WIN32__ */
	}

/* The __FILE__ value contains the full path, which is a lot of unnecessary
   noise when displaying the source file that we're in.  To deal with this
   we walk down the path and return the last two components, which works for
   most files except for ones in the root directory */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
const char *debugGetBasePath( IN_STRING const char *fileName )
	{
	const int fileNameLen = strnlen_s( fileName, MAX_PATH_LENGTH );
	int index, slashCount = 0;
	LOOP_INDEX i;

	assert( isReadPtr( fileName, 4 ) );

	/* Search for typical substrings in the path that denote the parent 
	   directory */
	index = strFindStr( fileName, fileNameLen, "cryptlib/", 9 );
	if( index < 0 )
		index = strFindStr( fileName, fileNameLen, "cryptlib\\", 9 );
	if( index >= 0 )
		return( fileName + index + 9 );
	index = strFindStr( fileName, fileNameLen, "CLIB/", 5 );
	if( index >= 0 )
		return( fileName + index + 5 );

	/* Walk down the path to the second slash */
	LOOP_MAX_REV( i = fileNameLen - 1, i > 0, i-- )
		{
		ENSURES_EXT( LOOP_INVARIANT_REV( i, 0, fileNameLen - 1 ), fileName );

		if( ( fileName[ i ] == '/' ) || ( fileName[ i ] == '\\' ) )
			{
			slashCount++;
			if( slashCount >= 2 )
				{
				i++;	/* Skip the slash that we're currently pointing at */
				break;
				}
			}
		}
	ENSURES_EXT( LOOP_BOUND_OK, fileName );

	return( fileName + i );
	}

/* Filenames for dumping data to are often derived from packet names.  In 
   the case of unknown types they'll be reported as "<Unknown type>" which 
   is fine for error messages but not so good for filenames.  To deal with 
   this we strip out these characters from the name */

STDC_NONNULL_ARG( ( 1 ) ) \
void debugSanitiseFilename( INOUT_STRING char *fileName )
	{
	int length = strnlen_s( fileName, MAX_PATH_LENGTH );
	LOOP_INDEX i;

	assert( isReadPtr( fileName, 4 ) );

	LOOP_MAX( i = 0, i < length, i++ )
		{
		/* We can't have a loop invariant at this point because the 
		   memmove() at the end of the loop changes the loop index */

		if( fileName[ i ] == ' ' )
			{
			/* Replace spaces by underscores */
			fileName[ i ] = '_';
			continue;
			}
		if( fileName[ i ] != '<' && fileName[ i ] != '>' )
			continue;

		/* Strip out the non-filename character.  Note that the length - i
		   expression includes the trailing null */
		memmove( fileName + i, fileName + i + 1, length - i );
		length--;
		i--;
		}
	ENSURES_V( LOOP_BOUND_OK );
	}

/* Dump a PDU to disk */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void buildFilePath( IN_STRING const char *fileName,
						   OUT_BUFFER_FIXED_C( 1024 ) char *filenameBuffer )
	{
	LOOP_INDEX i;

	assert( isReadPtr( fileName, 4 ) );
	assert( isWritePtr( filenameBuffer, 1024 ) );

	ANALYSER_HINT_STRING( fileName );

	/* Check whether the filename appears to be an absolute path */
	LOOP_MAX( i = 0, fileName[ i ] != '\0', i++ )
		{
		ENSURES_V( LOOP_INVARIANT_MAX( i, 0, FAILSAFE_ITERATIONS_MAX ) );

		if( fileName[ i ] == ':' || fileName[ i ] == '/' )
			break;
		}
	ENSURES_V( LOOP_BOUND_OK );
	if( fileName[ i ] == '\0' )
		{
		/* It's a relative path, put the file in the temp directory */
#if defined( __WIN32__ ) && defined( _MSC_VER ) && VC_GE_2019( _MSC_VER ) && 0
		/* Under either VS 2019 or Windows 10 the temp directory is placed 
		   on the C: drive rather than the currently active drive so we have 
		   to explicitly hardcode in a drive letter */
		strlcpy_s( filenameBuffer, 1024, "d:/tmp/" );
#else
		strlcpy_s( filenameBuffer, 1024, "/tmp/" );
#endif /* Windows 10 */
		strlcat_s( filenameBuffer, 1024, fileName );
		}
	else
		strlcpy_s( filenameBuffer, 1024, fileName );

	/* If it hasn't already got a suffix, append ".der" to the filename */
	if( filenameBuffer[ strnlen_s( filenameBuffer, 
								   MAX_PATH_LENGTH ) - 4 ] != '.' )
		strlcat_s( filenameBuffer, 1024, ".der" );
	}

#if defined( __WINDOWS__ )

/* Check whether the location to dump PDUs for debugging exists.  If it 
   doesn't, the caller can exit silently rather than complaining.  This is 
   used to handle people running debug builds on systems not set up in the 
   appropriate configuration who don't want to get error messages about it 
   popping up */

#ifndef INVALID_FILE_ATTRIBUTES
  #define INVALID_FILE_ATTRIBUTES		( ( DWORD ) -1L )
#endif /* Old SDK versions don't define this */

CHECK_RETVAL_BOOL \
static BOOLEAN checkDebugFilePath( void )
	{
	char filenameBuffer[ 128 + 8 ];
	DWORD attributes;

	/* See the comment in buildFilePath() for the hardcoding of the drive 
	   letter under Windows */
#if defined( _MSC_VER ) && VC_GE_2019( _MSC_VER ) && 0
	strlcpy_s( filenameBuffer, 128, "d:/tmp/" );
#else
	strlcpy_s( filenameBuffer, 128, "/tmp/" );
#endif /* Windows 10 */
	attributes = GetFileAttributes( filenameBuffer );
	return( ( attributes != INVALID_FILE_ATTRIBUTES ) && \
			( attributes & FILE_ATTRIBUTE_DIRECTORY ) ? \
			TRUE : FALSE );
	}

#elif defined( __UNIX__ )

CHECK_RETVAL \
static BOOLEAN checkDebugFilePath( void )
	{
	char filenameBuffer[ 128 + 8 ];

	strlcpy_s( filenameBuffer, 128, "/tmp/" );
	return( access( filenameBuffer, F_OK ) == 0 ? \
			TRUE : FALSE );
	}

#else
  #define checkDebugFilePath()			TRUE
#endif /* OS-specific accessibility checks */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
static FILE *openFile( IN_STRING const char *fileName,
					   OUT_PTR char *filenameBuffer )
	{
	FILE *filePtr;

	assert( isReadPtr( fileName, 4 ) );
	assert( isWritePtr( filenameBuffer, 1024 ) );

	ANALYSER_HINT_STRING( fileName );

	buildFilePath( fileName, filenameBuffer );
#if defined( EBCDIC_CHARS )
	bufferToEbcdic( filenameBuffer, filenameBuffer );
  #pragma convlit( suspend )	
	filePtr = fopen( filenameBuffer, "wb" );
  #pragma convlit( resume )	
#elif defined( __STDC_LIB_EXT1__ )
	if( fopen_s( &filePtr, filenameBuffer, "wb" ) != 0 )
		filePtr = NULL;
#else
	filePtr = fopen( filenameBuffer, "wb" );
#endif /* __STDC_LIB_EXT1__ */

	return( filePtr );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpFile2( IN_STRING const char *fileName, 
					 IN_BUFFER( dataLength1 ) const void *data1, 
					 IN_LENGTH const int dataLength1,
					 IN_BUFFER( dataLength2 ) const void *data2, 
					 IN_LENGTH_Z const int dataLength2 )
	{
	FILE *filePtr;
	char filenameBuffer[ 1024 + 8 ];
	int count1 = 0, count2 = 0;

	assert( isReadPtr( fileName, 4 ) );
	assert( isReadPtrDynamic( data1, dataLength1 ) );
	assert( ( data2 == NULL && dataLength2 == 0 ) || \
			isReadPtrDynamic( data2, dataLength2 ) );

	REQUIRES_V( isIntegerRangeNZ( dataLength1 ) );
	REQUIRES_V( isIntegerRange( dataLength2 ) );

	ANALYSER_HINT_STRING( fileName );

	/* If we're fuzzing, don't write anything to storage */
#ifdef CONFIG_FUZZ
	return;
#endif /* CONFIG_FUZZ */

	/* Make sure that we don't exit with an assertion in debug mode if 
	   there's no debug file location present */
	if( !checkDebugFilePath() )
		return;

	filePtr = openFile( fileName, filenameBuffer );
	assert( filePtr != NULL );
	if( filePtr == NULL )
		return;
	if( dataLength1 > 0 )
		{
#ifdef __MQXRTOS__
		/* MQX gets fwrite() args wrong */
		count1 = fwrite( ( void * ) data1, 1, dataLength1, filePtr );
#else
		count1 = fwrite( data1, 1, dataLength1, filePtr );
#endif /* __MQXRTOS__ */
		assert( count1 == dataLength1 );
		}
	if( dataLength2 > 0 )
		{
#ifdef __MQXRTOS__
		/* MQX gets fwrite() args wrong */
		count2 = fwrite( ( void * ) data2, 1, dataLength2, filePtr );
#else
		count2 = fwrite( data2, 1, dataLength2, filePtr );
#endif /* __MQXRTOS__ */
		assert( count2 == dataLength2 );
		}
	fclose( filePtr );
	if( dataLength1 > 0 && count1 + count2 < dataLength1 + dataLength2 )
		( void ) remove( filenameBuffer );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpFile( IN_STRING const char *fileName, 
					IN_BUFFER( dataLength ) const void *data, 
					IN_LENGTH const int dataLength )
	{
	debugDumpFile2( fileName, data, dataLength, NULL, 0 );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void debugDumpFileCert( IN_STRING const char *fileName, 
						IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	MESSAGE_DATA msgData DUMMY_INIT_STRUCT;
	FILE *filePtr;
	BYTE certData[ 2048 + 8 ];
	char filenameBuffer[ 1024 + 8 ];
	int certType, count DUMMY_INIT, status;

	assert( isReadPtr( fileName, 4 ) );
	assert( isHandleRangeValid( iCryptCert ) );

	ANALYSER_HINT_STRING( fileName );

	/* If we're fuzzing, don't write anything to storage */
#ifdef CONFIG_FUZZ
	return;
#endif /* CONFIG_FUZZ */

	/* Make sure that we don't exit with an assertion in debug mode if 
	   there's no debug file location present */
	if( !checkDebugFilePath() )
		return;

	filePtr = openFile( fileName, filenameBuffer );
	assert( filePtr != NULL );
	if( filePtr == NULL )
		return;
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE, &certType,
							  CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, certData, 2048 );
		status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData, 
								  ( certType == CRYPT_CERTTYPE_PKIUSER ) ? \
									CRYPT_ICERTFORMAT_DATA : \
									CRYPT_CERTFORMAT_CERTIFICATE );
		}
	if( cryptStatusOK( status ) )
		{
		count = fwrite( certData, 1, msgData.length, filePtr );
		assert( count == msgData.length );
		}
	fclose( filePtr );
	if( cryptStatusError( status ) || count < msgData.length )
		( void ) remove( filenameBuffer );
	}

/* Create a hex dump of the first n bytes of a buffer along with the length 
   and a checksum of the entire buffer, used to output a block of hex data 
   along with checksums for debugging things like client/server sessions 
   where it can be used to detect data corruption.  The use of a memory 
   buffer is to allow the hex dump to be performed from multiple threads 
   without them fighting over stdout */

#ifdef __WIN32__
  static CRITICAL_SECTION dumpHexMutex;
  static int dumpHexMutexInited = FALSE;
#endif /* __WIN32__ */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpHex( IN_STRING const char *prefixString, 
				   IN_BUFFER( dataLength ) const void *data, 
				   IN_LENGTH const int dataLength )
	{
	char dumpBuffer[ 128 + 1 + 8 ];
	LOOP_INDEX i;
	int offset;

	assert( isReadPtr( prefixString, 3 ) );
	assert( isReadPtr( data, dataLength ) );
	assert( isIntegerRange( dataLength ) );

	ANALYSER_HINT_STRING( prefixString );

	/* Since dumping a block of memory can take awhile, other threads can 
	   interfere with it, so we wrap it in a mutex */
#ifdef __WIN32__
	if( !dumpHexMutexInited )
		{
		InitializeCriticalSection( &dumpHexMutex );
		dumpHexMutexInited = TRUE;
		}
	EnterCriticalSection( &dumpHexMutex );
#endif /* __WIN32__ */

	offset = sprintf_s( dumpBuffer, 128, "%3s %4d %04X ", 
						prefixString, dataLength, 
						checksumData( data, dataLength ) & 0xFFFF );
	ENSURES_V( rangeCheck( offset, 12, 128 - 1 ) );
	LOOP_MAX( i = 0, i < dataLength, i += 16 )
		{
		const int innerLen = min( dataLength - i, 16 );
		int length;
		LOOP_INDEX_ALT j;

		ENSURES_V( LOOP_INVARIANT_MAX_XXX( i, 0, dataLength - 1 ) );
				   /* i is incremented by 16 */

		if( i > 0 )
			{
			offset = sprintf_s( dumpBuffer, 128, "%3s           ",
								prefixString );
			ENSURES_V( rangeCheck( offset, 12, 128 - 1 ) );
			}
		for( j = 0; j < innerLen; j++ )
			{
			length = sprintf_s( dumpBuffer + offset, 128 - offset, "%02X ",
								byteToInt( ( ( BYTE * ) data )[ i + j ] ) );
			ENSURES_V( rangeCheck( length, 2, 128 - 1 ) );
			offset += length;
			}
		LOOP_MAX_CHECKINC_ALT( j < 16, j++ )
			{
			length = sprintf_s( dumpBuffer + offset, 128 - offset, "   " );
			ENSURES_V( rangeCheck( length, 2, 128 - 1 ) );
			offset += length;
			}
		ENSURES_V( LOOP_BOUND_OK_ALT );
		LOOP_MAX_ALT( j = 0, j < innerLen, j++ )
			{
			int ch;

			ENSURES_V( LOOP_INVARIANT_MAX_ALT( j, 0, innerLen - 1 ) );

			ch = byteToInt( ( ( BYTE * ) data )[ i + j ] );
			length = sprintf_s( dumpBuffer + offset, 128 - offset, "%c",
								isPrint( ch ) ? ch : '.' );
			ENSURES_V( rangeCheck( length, 1, 128 - 1 ) );
			offset += length;
			}
		ENSURES_V( LOOP_BOUND_OK_ALT );
		DEBUG_PUTS(( dumpBuffer ));
		}
	ENSURES_V( LOOP_BOUND_OK );

#if !( defined( __WIN32__ ) || defined( __WINCE__ ) || defined( __ECOS__ ) || \
	   ( defined( __MQXRTOS__ ) && defined( MQX_SUPPRESS_STDIO_MACROS ) ) )
	fflush( stdout );
#endif /* Systems where output doesn't to go stdout */

#ifdef __WIN32__
	LeaveCriticalSection( &dumpHexMutex );
#endif /* __WIN32__ */
	}

/* Variants of debugDumpHex() that only output the raw hex data, for use in
   conjunction with DEBUG_PRINT() to output other information about the 
   data */

STDC_NONNULL_ARG( ( 2 ) ) \
static void dumpData( IN_STRING_OPT const char *label,
					  IN_BUFFER( dataLength ) const void *data, 
					  IN_LENGTH const int dataLength )
	{
	char dumpBuffer[ 128 + 1 + 8 ];
	LOOP_INDEX i;
	int offset, length;

	assert( label == NULL || isReadPtr( label, sizeof( 4 ) ) );
	assert( isReadPtr( data, dataLength ) );
	assert( isIntegerRange( dataLength ) );

	/* Since dumping a block of memory can take awhile, other threads can 
	   interfere with it, so we wrap it in a mutex */
#ifdef __WIN32__
	if( !dumpHexMutexInited )
		{
		InitializeCriticalSection( &dumpHexMutex );
		dumpHexMutexInited = TRUE;
		}
	EnterCriticalSection( &dumpHexMutex );
#endif /* __WIN32__ */

	/* If there's a label present, print it on a separate line */
	if( label != NULL )
		DEBUG_PUTS(( label ));

	LOOP_MAX( i = 0, i < dataLength, i += 16 )
		{
		const int innerLen = min( dataLength - i, 16 );
		LOOP_INDEX_ALT j;

		ENSURES_V( LOOP_INVARIANT_MAX_XXX( i, 0, dataLength - 1 ) );
				   /* i is incremented by 16 */

		offset = sprintf_s( dumpBuffer, 128, "%04d: ", i );
		ENSURES_V( rangeCheck( offset, 6, 128 - 1 ) );
		LOOP_MAX_ALT( j = 0, j < innerLen, j++ )
			{
			length = sprintf_s( dumpBuffer + offset, 128 - offset, "%02X ",
								byteToInt( ( ( BYTE * ) data )[ i + j ] ) );
			ENSURES_V( rangeCheck( length, 2, 128 - 1 ) );
			offset += length;
			}
		ENSURES_V( LOOP_BOUND_OK_ALT );
		LOOP_MAX_CHECKINC_ALT( j < 16, j++ )
			{
			length = sprintf_s( dumpBuffer + offset, 128 - offset, "   " );
			ENSURES_V( rangeCheck( length, 2, 128 - 1 ) );
			offset += length;
			}
		ENSURES_V( LOOP_BOUND_OK_ALT );
		LOOP_MAX_ALT( j = 0, j < innerLen, j++ )
			{
			int ch;

			ENSURES_V( LOOP_INVARIANT_MAX_ALT( j, 0, innerLen - 1 ) );

			ch = byteToInt( ( ( BYTE * ) data )[ i + j ] );
			length = sprintf_s( dumpBuffer + offset, 128 - offset, "%c",
								isPrint( ch ) ? ch : '.' );
			ENSURES_V( rangeCheck( length, 1, 128 - 1 ) );
			offset += length;
			}
		ENSURES_V( LOOP_BOUND_OK_ALT );
		DEBUG_PUTS(( dumpBuffer ));
		}
	ENSURES_V( LOOP_BOUND_OK );

#if !( defined( __WIN32__ ) || defined( __WINCE__ ) || defined( __ECOS__ ) || \
	   ( defined( __MQXRTOS__ ) && defined( MQX_SUPPRESS_STDIO_MACROS ) ) )
	fflush( stdout );
#endif /* Systems where output doesn't to go stdout */

#ifdef __WIN32__
	LeaveCriticalSection( &dumpHexMutex );
#endif /* __WIN32__ */
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpDataLabel( IN_STRING const char *label,
						 IN_BUFFER( dataLength ) const void *data, 
						 IN_LENGTH const int dataLength )
	{
	assert( isReadPtr( label, sizeof( 4 ) ) );

	DEBUG_PRINT_BEGIN();
	dumpData( label, data, dataLength );
	DEBUG_PRINT_END();
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void debugDumpData( IN_BUFFER( dataLength ) const void *data, 
					IN_LENGTH const int dataLength )
	{
	DEBUG_PRINT_BEGIN();
	dumpData( NULL, data, dataLength );
	DEBUG_PRINT_END();
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void debugDumpStream( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr, 
					  IN_LENGTH const int position,
					  IN_LENGTH const int length )
	{
	STREAM *stream = streamPtr;
	BYTE *dataPtr; 
	int status; 

	assert( isReadPtr( streamPtr, sizeof( STREAM ) ) );

	/* In some cases we may be asked to dump zero-length packets, since 
	   we're being called unconditionally (the caller can't put conditional
	   code into a debug macro) we just turn the call into a no-op */
	if( length <= 0 )
		return;

	/* Make sure that we don't put the stream into an invalid state by
	   trying to dump more data than is present */
	if( length > sMemDataLeft( stream ) )
		{
		DEBUG_PRINT(( "Error: Attempt to dump %d bytes but only %d bytes "
					  "available.\n", length, sMemDataLeft( stream ) ));
		return;
		}

	status = sMemGetDataBlockAbs( stream, position, ( void ** ) &dataPtr, 
								  length );
	if( cryptStatusError( status ) )
		return;
	ANALYSER_HINT_V( dataPtr != NULL );
	debugDumpData( dataPtr, length );
	}

/* Dump a stack trace.  Note that under Unix this may require linking with 
   -rdynamic (to force the addition of all symbols, not just public ones, so 
   for example ones for static functions) in order for backtrace_symbols() 
   to be able to display all symbols */

#if defined( __WIN32__ )

#if VC_GE_2005( _MSC_VER )

#pragma warning( push )				/* More errors in Windows headers */
#pragma warning( disable: 4255 )	/* No function prototype given */
#include <dbghelp.h>
#pragma warning( pop )
#pragma comment( lib, "dbghelp.lib" )

#ifdef _WIN64 
  #define BINARIES_PATH	"debug64_vs;binaries64_vs" 
#else
  #define BINARIES_PATH	"debug32_vs;binaries32_vs"
#endif /* Win32 vs. Win64 */

void displayBacktrace( void )
	{
	HANDLE process;
	SYMBOL_INFO *symbolInfo;
	IMAGEHLP_LINE lineInfo;
	ALIGN_STACK_DATA BYTE buffer[ sizeof( SYMBOL_INFO ) + \
								  ( MAX_SYM_NAME * sizeof( TCHAR ) ) ];
	void *stack[ 64 ];
	const int framesToSkip = IsDebuggerPresent() ? 6 : 4;
	int noFrames;
	LOOP_INDEX i;

	/* Load debugging symbols for the current process */
	DEBUG_PUTS(( "Stack trace:" ));
	process = GetCurrentProcess();
	SymSetOptions( SYMOPT_LOAD_LINES );
	if( !SymInitialize( process, BINARIES_PATH, TRUE ) )
		{
		const DWORD error = GetLastError();
		
		DEBUG_PRINT(( "Couldn't load symbols, error = %d.\n", error ));
		return;		
		}

	/* Get the stack backtrace.  Frame 0 is the current function so we start at
	   1, and we don't display the last few frames since they're system 
	   functions.  Usually it's four frames but if we're running inside some 
	   version of the VS debugger this can be more than four frames, up to 
	   six or seven) */
	noFrames = CaptureStackBackTrace( 1, 64, stack, NULL );
	if( noFrames < framesToSkip )
		{
		const DWORD error = GetLastError();
		
		DEBUG_PRINT(( "Couldn't capture stack backtrace, error = %d.\n", error ));
		return;		
		}

	/* Set up the SYMBOL_INFO and LINE_INFO structures */
	symbolInfo = ( SYMBOL_INFO * ) buffer;
	memset( symbolInfo, 0, sizeof( SYMBOL_INFO ) );
	symbolInfo->MaxNameLen = MAX_SYM_NAME;
	symbolInfo->SizeOfStruct = sizeof( SYMBOL_INFO );
	memset( &lineInfo, 0, sizeof( IMAGEHLP_LINE ) );
	lineInfo.SizeOfStruct = sizeof( IMAGEHLP_LINE );

	/* Walk the stack printing addresses and symbols if we can get them */
	LOOP_LARGE( i = 0, i < noFrames - framesToSkip, i++ ) 
		{
		DWORD_PTR address;
		DWORD dwDisplacement;

		ENSURES_V( LOOP_INVARIANT_LARGE( i, 0, 
										 noFrames - ( framesToSkip + 1 ) ) );

		address = ( DWORD_PTR ) stack[ i ];
		if( !SymFromAddr( process, address, 0, symbolInfo ) )
			{
			const DWORD error = GetLastError();
			DEBUG_PRINT(( "<Unknown - %d> - 0x%I64x\n", error, address ));
			continue;
			}
		if( SymGetLineFromAddr( process, address, &dwDisplacement, 
								&lineInfo ) )
			{
			DEBUG_PRINT(( "%s:%d - 0x%I64x\n", symbolInfo->Name, 
						  lineInfo.LineNumber, symbolInfo->Address ));
			}
		else
			{
			DEBUG_PRINT(( "%s - 0x%I64x\n", symbolInfo->Name, 
						  symbolInfo->Address ));
			}
		}
	ENSURES_V( LOOP_BOUND_OK );
	}
#else

/* Older versions of VC++ don't have dbghelp.h/dbghelp.lib which contains 
   CaptureStackBackTrace() so we'd either need to dynamically load it or 
   just use alternate code that walks the stack manually from the current 
   EBP */

#include <ImageHlp.h>
#pragma comment( lib, "imagehlp.lib" )

#define BINARIES_PATH	"debug32_vc6;binaries32_vc6"

void displayBacktrace( void )
	{
	HANDLE process;
	IMAGEHLP_SYMBOL *symbolInfo;
	IMAGEHLP_LINE lineInfo;
	BYTE buffer[ sizeof( IMAGEHLP_SYMBOL ) + 1024 ];
	unsigned long prevAddress, address = 1;
	LOOP_INDEX i;

	/* Horribly nonportable way of walking the stack due to lack of access
	   to CaptureStackBackTrace() */
	__asm { mov prevAddress, ebp };

	/* Load debugging symbols for the current process */
	DEBUG_PUTS(( "Stack trace:" ));
	process = GetCurrentProcess();
	SymSetOptions( SYMOPT_LOAD_LINES );
	if( !SymInitialize( process, BINARIES_PATH, TRUE ) )
		{
		DEBUG_OP( const DWORD error = GetLastError() );
		
		DEBUG_PRINT(( "Couldn't load symbols, error = %d.\n", error ));
		return;		
		}

	/* Set up the SYMBOL_INFO and LINE_INFO structures */
	symbolInfo = ( IMAGEHLP_SYMBOL * ) buffer;
	memset( symbolInfo, 0, sizeof( IMAGEHLP_SYMBOL ) );
	symbolInfo->SizeOfStruct = sizeof( IMAGEHLP_SYMBOL );
	symbolInfo->MaxNameLength = 512;
	memset( &lineInfo, 0, sizeof( IMAGEHLP_LINE ) );
	lineInfo.SizeOfStruct = sizeof( IMAGEHLP_LINE );

	/* Walk the stack printing addresses and symbols if we can get them */
	LOOP_LARGE( i = 0, i < 50, i++ ) 
		{ 
		DWORD dwDisplacement;

		ENSURES_V( LOOP_INVARIANT_LARGE( i, 0, 49 ) );

		address = ( ( unsigned long * ) prevAddress )[ 1 ]; 
		prevAddress = ( ( unsigned long * ) prevAddress )[ 0 ]; 
		if( address == 0 )
			break;
		if( !SymGetSymFromAddr( process, address, 0, symbolInfo ) )
			{
			DEBUG_OP( const DWORD error = GetLastError() );

			DEBUG_PRINT(( "<Unknown - %d> - 0x%0lX\n", error, address ));
			continue;
			}
		if( SymGetLineFromAddr( process, address, &dwDisplacement, 
								&lineInfo ) )
			{
			DEBUG_PRINT(( "%s:%d - 0x%lX\n", symbolInfo->Name, 
						  lineInfo.LineNumber, symbolInfo->Address ));
			}
		else
			{
			DEBUG_PRINT(( "%s - 0x%0X\n", symbolInfo->Name, 
						  symbolInfo->Address ));
			}
		}
	ENSURES_V( LOOP_BOUND_OK );

	SymCleanup( process );
	}
#endif /* Win32 vs. Win64 */

#elif defined( __UNIX__ ) && defined( __GLIBC__ ) && \
	  ( defined( __APPLE__ ) || defined( __linux__ ) || defined( __sun ) )

/* execinfo.h is a glibc thing which isn't included in some Linux distros 
   like Alpine so we have to make it conditional on glibc being available as
   well as just being Linux */

#include <execinfo.h>

#ifdef __GNUC__
  /* Needed with -finstrument */
  void __cyg_profile_func_enter( void *func, void *caller ) \
	   __attribute__(( no_instrument_function ));
  void __cyg_profile_func_enter( void *func, void *caller ) { }	
  void __cyg_profile_func_exit( void *func, void *caller ) \
	   __attribute__(( no_instrument_function ));
  void __cyg_profile_func_exit( void *func, void *caller ) { }
#endif /* __GNUC__ */

void displayBacktrace( void )
	{
	void *stackInfo[ 100 + 8 ];
	char **stackInfoStrings;
	LOOP_INDEX i;
	int stackInfoSize;
 
	DEBUG_PUTS(( "Stack trace:" ));
	stackInfoSize = backtrace( stackInfo, 100 );
	if( stackInfoSize <= 2 )
		{
		/* See also the comment about -rdynamic at the start of this code 
		   section */
		DEBUG_PUTS(( "Only one level of backtrace available, if this is an "
					 "architecture without\nframe pointers like ARM or MIPS "
					 "then you need to rebuild with\n-finstrument-functions "
					 "and/or -fexceptions" ));
		}
	stackInfoStrings = backtrace_symbols( stackInfo, stackInfoSize );
 
	/* We start at position 1, since the 0-th entry is the current function,
	   i.e. displayBacktrace().  We also stop one before the last entry, 
	   which is typically main() or something similar */
	LOOP_LARGE( i = 1, i < stackInfoSize - 1, i++ ) 
		{
		ENSURES_V( LOOP_INVARIANT_LARGE( i, 1, stackInfoSize - 2 ) );

		DEBUG_PRINT(( "%p : %s\n", stackInfo[ i ], stackInfoStrings[ i ] ));
		}
 	ENSURES_V( LOOP_BOUND_OK );

	free( stackInfoStrings );
	}
#endif /* OS-specific backtrace printing */

/* Support function used to access the text string data from an ERROR_INFO
   structure.  Note that this function isn't thread-safe, but that should be
   OK since it's only used for debugging */

#if !defined( NDEBUG ) && defined( USE_ERRMSGS )

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
const char *getErrorInfoString( const ERROR_INFO *errorInfo )
	{
	static char errorInfoString[ MAX_ERRMSG_SIZE + 8 ];
	const int errorStringLength = \
				min( errorInfo->errorStringLength, MAX_ERRMSG_SIZE - 1 );

	assert( isReadPtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* If there's no extended error information available, return an 
	   indicator of this */
	if( errorStringLength <= 0 )
		return( "<<<No further information available>>>" );

	memcpy( errorInfoString, errorInfo->errorString, errorStringLength );
	errorInfoString[ errorStringLength ] = '\0';

	return( errorInfoString );
	}
#endif /* !NDEBUG && USE_ERRMSGS */

/* Support function used with streams to pull data bytes out of the stream,
   allowing type and content data to be dumped with DEBUG_PRINT() */

RETVAL_RANGE_NOERROR( 0, 0xFF ) STDC_NONNULL_ARG( ( 1 ) ) \
int debugGetStreamByte( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr, 
						IN_LENGTH const int position )
	{
	STREAM *stream = streamPtr;
	BYTE *dataPtr; 
	int status; 

	assert( isReadPtr( streamPtr, sizeof( STREAM ) ) );

	status = sMemGetDataBlockAbs( stream, position, ( void ** ) &dataPtr, 1 );
	if( cryptStatusError( status ) )
		return( 0 );
	return( byteToInt( *dataPtr ) );
	}
#endif /* Debug || DEBUG_DIAGNOSTIC_ENABLE */

/****************************************************************************
*																			*
*						Fault-injection Support Functions					*
*																			*
****************************************************************************/

#if defined( CONFIG_FAULTS ) && !defined( NDEBUG )

#define PARAM_ACL	int		/* Fake out unneeded types */
#include "kernel/kernel.h"

/* Variables used for fault-injection tests */

FAULT_TYPE faultType;
int faultParam1;

/* Get a substitute key to replace the actual one, used to check for 
   detection of use of the wrong key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int getSubstituteKey( OUT_HANDLE_OPT CRYPT_CONTEXT *iPrivateKey )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int status;

	assert( isWritePtr( iPrivateKey, sizeof( CRYPT_CONTEXT ) ) );

	/* Clear return value */
	*iPrivateKey = CRYPT_ERROR;

	/* Try and read the certificate chain from the keyset */
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.arg2 = CRYPT_KEYOPT_READONLY;
	createInfo.strArg1 = "test/keys/server2.p15";
	createInfo.strArgLen1 = strnlen_s( createInfo.strArg1, MAX_PATH_LENGTH );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_KEYSET );
	if( cryptStatusError( status ) )
		return( status );
	setMessageKeymgmtInfo( &getkeyInfo, CRYPT_KEYID_NAME, "Test user key", 13,
						   NULL, 0, KEYMGMT_FLAG_USAGE_SIGN );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_KEY_GETKEY, 
							  &getkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DESTROY );
	if( cryptStatusOK( status ) )
		*iPrivateKey = getkeyInfo.cryptHandle;

	return( status );
	}

/* Corrupt a random bit in a block of memory */

CHECK_RETVAL \
static int getDeterministicRandomInt( void )
	{
	HASH_FUNCTION_ATOMIC hashFunction;
	static BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ] = { 0 };
	BYTE *hashBufPtr = hashBuffer;
	int hashSize, retVal;

	/* Step the RNG and extract an integer's-worth of data from it.  We go
	   via the intermediate value retVal because mgetLong() is a macro that
	   doesn't work as part of a return statement */
	getHashAtomicParameters( CRYPT_ALGO_SHA1, 0, &hashFunction, &hashSize );
	hashFunction( hashBuffer, hashSize, hashBuffer, hashSize );
	retVal = mgetLong( hashBufPtr );

	return( retVal );
	}

void injectMemoryFault( void )
	{
	const int value = getDeterministicRandomInt();
	const BYTE bitMask = intToByte( 1 << ( value & 3 ) );
	const int bytePos = value >> 3;
	BYTE *dataPtr = ( BYTE * ) getSystemStorage( SYSTEM_STORAGE_KRNLDATA );
	const int dataSize = getSystemStorageSize( SYSTEM_STORAGE_KRNLDATA );

	dataPtr[ bytePos % dataSize ] ^= bitMask;
	}
#endif /* CONFIG_FAULTS && Debug */

/****************************************************************************
*																			*
*								Timing Functions							*
*																			*
****************************************************************************/

#if !defined( NDEBUG ) && ( defined( __WINDOWS__ ) || defined( __UNIX__ ) )

#ifdef __UNIX__ 
  #include <sys/time.h>		/* For gettimeofday() */
#endif /* __UNIX__  */

/* Get/update high-resolution timer value */

HIRES_TIME debugTimeDiff( HIRES_TIME startTime )
	{
	HIRES_TIME timeValue;
#ifdef __WINDOWS__
	LARGE_INTEGER performanceCount;

	/* Sensitive to context switches */
	QueryPerformanceCounter( &performanceCount );
	timeValue = performanceCount.QuadPart;
#else
	struct timeval tv;

	/* Only accurate to about 1us */
	gettimeofday( &tv, NULL );
  #ifdef HIRES_TIME_64BIT
	timeValue = ( ( ( HIRES_TIME ) tv.tv_sec ) << 32 ) | tv.tv_usec;
  #else
	timeValue = tv.tv_usec;
  #endif /* HIRES_TIME_64BIT */
#endif /* Windows vs.Unix high-res timing */

	if( !startTime )
		return( timeValue );
	return( timeValue - startTime );
	}

/* Display high-resulution time value */

int debugTimeDisplay( HIRES_TIME timeValue )
	{
	HIRES_TIME timeMS, ticksPerSec;

	/* Try and get the clock frequency */
#ifdef __WINDOWS__
	LARGE_INTEGER performanceCount;

	QueryPerformanceFrequency( &performanceCount );
	ticksPerSec = performanceCount.QuadPart;
#else
	ticksPerSec = 1000000L;
#endif /* __WINDOWS__ */	

	timeMS = ( timeValue * 1000 ) / ticksPerSec;
	assert( timeMS < INT_MAX );
	if( timeMS <= 0 )
		printf( "< 1" );
	else
		printf( HIRES_FORMAT_SPECIFIER, timeMS );

	return( ( timeMS <= 0 ) ? 1 : ( int ) timeMS );
	}
#endif /* Debug && ( __WINDOWS__ || __UNIX__ ) */
