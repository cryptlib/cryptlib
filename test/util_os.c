/****************************************************************************
*																			*
*					  cryptlib Self-test Utility Routines					*
*						Copyright Peter Gutmann 1997-2019					*
*																			*
****************************************************************************/

#include <ctype.h>
#include "cryptlib.h"
#include "test/test.h"

/* Various features can be disabled by configuration options, in order to 
   handle this we need to include the cryptlib config file so that we can 
   selectively disable some tests.
   
   Note that this checking isn't perfect, if cryptlib is built in release
   mode but we include misc/config.h here in debug mode then the defines 
   won't match up because the use of debug mode enables extra options that 
   won't be enabled in the release-mode cryptlib.  The checkLibraryIsDebug()
   function can be used to detect this debug/release mismatch and warn about
   self-test failures if one is found */
#include "misc/config.h"	/* For algorithm usage */
#include "misc/consts.h"	/* For DEFAULT_CRYPT_ALGO */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */
#ifdef HAS_WIDECHAR
  #include <wchar.h>
#endif /* HAS_WIDECHAR */
#ifndef NDEBUG
  #include "misc/config.h"
#endif /* NDEBUG */

/****************************************************************************
*																			*
*							OS Helper Functions								*
*																			*
****************************************************************************/

#if defined( __BORLANDC__ ) && ( __BORLANDC__ <= 0x310 )

/* BC++ 3.x doesn't have mbstowcs() in the default library, and also defines
   wchar_t as char (!!) so we fake it here */

size_t mbstowcs( char *pwcs, const char *s, size_t n )
	{
	memcpy( pwcs, s, n );
	return( n );
	}
#endif /* BC++ 3.1 or lower */

/* Helper functions to make tracking down errors on systems with no console
   a bit less painful.  These just use the debug console as stdout */

#ifdef _WIN32_WCE

void wcPrintf( const char *format, ... )
	{
	wchar_t wcBuffer[ 1024 ];
	char buffer[ 1024 ];
	va_list argPtr;

	va_start( argPtr, format );
	vsprintf( buffer, format, argPtr );
	va_end( argPtr );
	mbstowcs( wcBuffer, buffer, strlen( buffer ) + 1 );
	NKDbgPrintfW( wcBuffer );
	}

void wcPuts( const char *string )
	{
	wcPrintf( "%s\n", string );
	}
#endif /* Console-less environments */

/* Conversion functions used to get Unicode input into generic ASCII
   output */

#ifdef UNICODE_STRINGS

/* Get a filename in an appropriate format for the C runtime library */

const char *convertFileName( const C_STR fileName )
	{
	static char fileNameBuffer[ FILENAME_BUFFER_SIZE ];

	wcstombs( fileNameBuffer, fileName, wcslen( fileName ) + 1 );
	return( fileNameBuffer );
	}

/* Map a filename template to an actual filename, input in Unicode, output in
   ASCII */

void filenameFromTemplate( char *buffer, const wchar_t *fileTemplate,
						   const int count )
	{
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
	int length;

	length = _snwprintf( wcBuffer, FILENAME_BUFFER_SIZE, fileTemplate,
						 count );
	wcstombs( buffer, wcBuffer, length + 1 );
	}

void filenameParamFromTemplate( wchar_t *buffer,
								const wchar_t *fileTemplate,
								const int count )
	{
	_snwprintf( buffer, FILENAME_BUFFER_SIZE, fileTemplate, count );
	}
#endif /* UNICODE_STRINGS */

/****************************************************************************
*																			*
*							Thread Support Functions						*
*																			*
****************************************************************************/

#if defined( WINDOWS_THREADS )

static HANDLE hMutex;

void createMutex( void )
	{
	hMutex = CreateMutex( NULL, FALSE, NULL );
	}
void acquireMutex( void )
	{
	if( WaitForSingleObject( hMutex, 30000 ) == WAIT_TIMEOUT )
		{
		fputs( "Warning: Couldn't acquire mutex after 30s wait.  Press a "
			   "key to continue.\n", outputStream );
		getchar();
		}
	}
int waitMutex( void )
	{
	if( WaitForSingleObject( hMutex, 30000 ) == WAIT_TIMEOUT )
		return( CRYPT_ERROR_TIMEOUT );
	
	/* Since this is merely a synchronisation operation in which a later 
	   thread waits to catch up to an earlier one, we release the mutex again
	   so other threads can get in */
	releaseMutex();
	return( CRYPT_OK );
	}
void releaseMutex( void )
	{
	if( !ReleaseMutex( hMutex ) )
		{
		fputs( "Warning: Couldn't release mutex.  Press a key to continue.\n", 
			   outputStream );
		getchar();
		}
	}
void destroyMutex( void )
	{
	CloseHandle( hMutex );
	}

void waitForThread( const HANDLE hThread )
	{
	if( WaitForSingleObject( hThread, 15000 ) == WAIT_TIMEOUT )
		{
		fputs( "Warning: Server thread is still active due to session "
			   "negotiation failure,\n         this will cause an error "
			   "condition when cryptEnd() is called due\n         to "
			   "resources remaining allocated, specifically because the "
			   "client\n          thread will call cryptEnd() while the "
			   "server thread is still\n         active, resulting in the "
			   "server thread object cleanup failing\n         because "
			   "they've already been cleaned up in cryptEnd().  Press a "
			   "key\n         to continue.\n", outputStream );
		getchar();
		}
	CloseHandle( hThread );
	}
#elif defined( UNIX_THREADS )

static pthread_mutex_t mutex;

void createMutex( void )
	{
	pthread_mutex_init( &mutex, NULL );
	}
void acquireMutex( void )
	{
	pthread_mutex_lock( &mutex );
	}
int waitMutex( void )
	{
	/* We should be using a timed wait here but that's not really possible 
	   with pthreads.  Some implementations have a totally stupid function 
	   pthread_mutex_timedlock() which, despite its name and appearance, 
	   doesn't implement a timeout but waits until an absolute time in the 
	   future before timing out (several pthreads tutorials get this wrong
	   and show sample code that treats it as a relative timeout).  So you 
	   can't say "wait 15s, then time out" but have to use:

		struct timespec timeout;

		clock_gettime( CLOCK_REALTIME, &timeout );
		timeoutTime.tv_sec += 15;
		pthread_mutex_timedlock( &mutex, &timeout );

	   to maximise the amount of nonstandard stuff the OS and libraries have
	   to have available before it can be used (e.g. OS X doesn't have either
	   clock_gettime() or pthread_mutex_timedlock(), others don't have 
	   pthread_mutex_timedlock()).
	   
	   There's not even any easy way to test whether this stuff is present, 
	   glibc has ( _POSIX_C_SOURCE >= 199309L ) for clock_gettime() but 
	   there's nothing for pthread_mutex_timedlock() which is in the 
	   pthreads library, so we don't try and use it */
	pthread_mutex_lock( &mutex );
	
	/* Since this is merely a synchronisation operation in which a later 
	   thread waits to catch up to an earlier one, we release the mutex again
	   so other threads can get in */
	releaseMutex();
	return( CRYPT_OK );
	}
void releaseMutex( void )
	{
	pthread_mutex_unlock( &mutex );
	}
void destroyMutex( void )
	{
	pthread_mutex_destroy( &mutex );
	}

void waitForThread( const pthread_t hThread )
	{
	if( pthread_join( hThread, NULL ) < 0 )
		{
		fputs( "Warning: Server thread is still active due to session "
			   "negotiation failure,\n         this will cause an error "
			   "condition when cryptEnd() is called due\n         to "
			   "resources remaining allocated, specifically because the "
			   "client\n          thread will call cryptEnd() while the "
			   "server thread is still\n         active, resulting in the "
			   "server thread object cleanup failing\n         because "
			   "they've already been cleaned up in cryptEnd().  Press a "
			   "key\n         to continue.\n", outputStream );
		getchar();
		}
	}

#else

void createMutex( void )
	{
	}
void acquireMutex( void )
	{
	}
void releaseMutex( void )
	{
	}
int waitMutex( void )
	{
	return( CRYPT_OK );
	}
void destroyMutex( void )
	{
	}
#endif /* WINDOWS_THREADS */

#if defined( WINDOWS_THREADS ) || defined( UNIX_THREADS )

/* When using multiple threads we need to delay one thread for a small
   amount of time, unfortunately there's no easy way to do this with pthreads
   so we have to provide the following wrapper function that makes an
   (implementation-specific) attempt at it */

#if defined( UNIX_THREADS )
  /* This include must be outside the function to avoid weird compiler errors
	 on some systems */
  #include <sys/time.h>
#endif /* UNIX_THREADS */

void delayThread( const int seconds )
	{
#if defined( UNIX_THREADS )
	struct timeval tv = { 0 };

	/* The following should put a thread to sleep for a second on most
	   systems since the select() should be a thread-safe one in the
	   presence of pthreads */
	tv.tv_sec = seconds;
	select( 1, NULL, NULL, NULL, &tv );
#elif defined( WINDOWS_THREADS )
	Sleep( seconds * 1000 );
#endif /* Threading system-specific delay functions */
	}

/* Dispatch multiple client and server threads and wait for them to exit */

int multiThreadDispatch( THREAD_FUNC clientFunction,
						 THREAD_FUNC serverFunction, const int noThreads )
	{
	THREAD_HANDLE hClientThreads[ MAX_NO_THREADS ];
	THREAD_HANDLE hServerThreads[ MAX_NO_THREADS ];
	int sessionID[ MAX_NO_THREADS ];
	int i;

	assert( noThreads <= MAX_NO_THREADS );

	/* Set up the session ID values */	
	for( i = 0; i < MAX_NO_THREADS; i++ )
		sessionID[ i ] = i;

	/* Start the sessions and wait for them to initialise.  We have to wait 
	   for some time since the multiple private key reads can take awhile */
	for( i = 0; i < noThreads; i++ )
		{
#ifdef WINDOWS_THREADS
		unsigned int threadID;

		hServerThreads[ i ] = ( HANDLE ) \
						_beginthreadex( NULL, 0, serverFunction,
										&sessionID[ i ], 0, &threadID );
#else
		pthread_t threadHandle;

		hServerThreads[ i ] = 0;
		if( pthread_create( &threadHandle, NULL, serverFunction,
							&sessionID[ i ] ) == 0 )
			hServerThreads[ i ] = threadHandle;
#endif /* Windows vs. pthreads */
		}
	delayThread( 3 );

	/* Connect to the local server */
	for( i = 0; i < noThreads; i++ )
		{
#ifdef WINDOWS_THREADS
		unsigned int threadID;

		hClientThreads[ i ] = ( HANDLE ) \
						_beginthreadex( NULL, 0, clientFunction,
										&sessionID[ i ], 0, &threadID );
#else
		pthread_t threadHandle;

		hClientThreads[ i ] = 0;
		if( pthread_create( &threadHandle, NULL, clientFunction,
							&sessionID[ i ] ) == 0 )
			hClientThreads[ i ] = threadHandle;
#endif /* Windows vs. pthreads */
		}
#ifdef WINDOWS_THREADS
	if( WaitForMultipleObjects( noThreads, hServerThreads, TRUE,
								60000 ) == WAIT_TIMEOUT || \
		WaitForMultipleObjects( noThreads, hClientThreads, TRUE,
								60000 ) == WAIT_TIMEOUT )
#else
	/* Posix doesn't have an ability to wait for multiple threads for mostly
	   religious reasons ("That's not how we do things around here") so we
	   just wait for two token threads */
	pthread_join( hServerThreads[ 0 ], NULL );
	pthread_join( hClientThreads[ 0 ], NULL );
#endif /* Windows vs. pthreads */
		{
		fputs( "Warning: Server threads are still active due to session "
			   "negotiation failure,\n         this will cause an error "
			   "condition when cryptEnd() is called due\n         to "
			   "resources remaining allocated.  Press a key to continue.\n", 
			   outputStream );
		getchar();
		}
#ifdef WINDOWS_THREADS
	for( i = 0; i < noThreads; i++ )
		{
		if( hServerThreads[ i ] != 0 )
			CloseHandle( hServerThreads[ i ] );
		}
	for( i = 0; i < noThreads; i++ )
		{
		if( hClientThreads[ i ] != 0 )
			CloseHandle( hClientThreads[ i ] );
		}
#endif /* Windows vs. pthreads */

	return( TRUE );
	}
#endif /* Windows/Unix threads */

/****************************************************************************
*																			*
*							Timing Support Functions						*
*																			*
****************************************************************************/

/* Get high-resolution timing info */

#ifdef USE_TIMING

#ifdef __WINDOWS__ 
  /* This needs an explicit -lm on Unix systems so we only enable it for 
     Windows */
  #define USE_SD
  #include <math.h>
#else
  #include <sys/time.h>
#endif /* __WINDOWS__ */

#ifdef USE_32BIT_TIME

HIRES_TIME timeDiff( HIRES_TIME startTime )
	{
	HIRES_TIME timeLSB, timeDifference;

#ifdef __WINDOWS__
  #if defined( _MSC_VER ) && defined( _M_X64 )
	const unsigned __int64 value = __rdtsc();
	timeLSB = ( HIRES_TIME ) value;
  #else
	LARGE_INTEGER performanceCount;

	/* Sensitive to context switches */
	QueryPerformanceCounter( &performanceCount );
	timeLSB = performanceCount.LowPart;
  #endif /* __WIN64__ */
#else
  #if 0	/* Requires linking with librt, not always present */
	struct timespec ts;

	clock_gettime( CLOCK_PROCESS_CPUTIME_ID, &ts );
	timeLSB = ts.tv_nsec;
  #else
	struct timeval tv;

	/* Only accurate to about 1us */
	gettimeofday( &tv, NULL );
	timeLSB = tv.tv_usec;
  #endif /* 0 */
#endif /* Windows vs.Unix high-res timing */

	/* If we're getting an initial time, return an absolute value */
	if( !startTime )
		return( timeLSB );

	/* We're getting a time difference */
	if( startTime < timeLSB )
		timeDifference = timeLSB - startTime;
	else
		{
#ifdef __WINDOWS__
		/* Windows rolls over at INT_MAX */
		timeDifference = ( 0xFFFFFFFFUL - startTime ) + 1 + timeLSB;
#else
		/* gettimeofday() rolls over at 1M us */
		timeDifference = ( 1000000L - startTime ) + timeLSB;
#endif /* __WINDOWS__ */
		}
	if( timeDifference <= 0 )
		{
		fprintf( outputStream, "Error: Time difference = " 
				 HIRES_FORMAT_SPECIFIER ", startTime = " 
				 HIRES_FORMAT_SPECIFIER ", endTime = " 
				 HIRES_FORMAT_SPECIFIER ".\n",
				 timeDifference, startTime, timeLSB );
		return( 1 );
		}

	return( timeDifference );
	}
#else

HIRES_TIME timeDiff( HIRES_TIME startTime )
	{
	HIRES_TIME timeValue;

#ifdef __WINDOWS__
	LARGE_INTEGER performanceCount;

	/* Sensitive to context switches */
	QueryPerformanceCounter( &performanceCount );
	timeValue = performanceCount.QuadPart;
#else
  #if 1
	timespec ts;

	clock_gettime( CLOCK_PROCESS_CPUTIME_ID, &ts );
	timeValue = ( ( ( HIRES_TIME ) ts.tv_sec ) * 1000000000 ) | tv.tv_nsec;
  #else
	struct timeval tv;

	/* Only accurate to about 1us */
	gettimeofday( &tv, NULL );
	timeValue = ( ( ( HIRES_TIME ) tv.tv_sec ) * 1000000 ) | tv.tv_usec;
  #endif /* 0 */
#endif /* Windows vs.Unix high-res timing */

	if( !startTime )
		return( timeValue );
	return( timeValue - startTime );
	}
#endif /* USE_32BIT_TIME */

/* Print timing info.  This gets a bit hairy because we're actually counting 
   low-level timer ticks rather than abstract thread times which means that 
   we'll be affected by things like context switches.  There are two 
   approaches to this:

	1. Take the fastest time, which will be the time least affected by 
	   system overhead.

	2. Apply standard statistical techniques to weed out anomalies.  Since 
	   this is just for testing purposes all we do is discard any results 
	   out by more than 10%, which is crude but reasonably effective.  A 
	   more rigorous approach is to discards results more than n standard 
	   deviations out, but this gets screwed up by the fact that a single 
	   context switch of 20K ticks can throw out results from an execution 
	   time of only 50 ticks.  In any case (modulo context switches) the 
	   fastest, 10%-out, and 2 SD out times are all within about 1% of each 
	   other so all methods are roughly equally accurate */

static int timeDisplayMean( const HIRES_TIME *times, const int noTimes )
	{
	HIRES_TIME timeSum = 0, timeAvg, timeDelta;
	HIRES_TIME timeMin = 1000000L;
	HIRES_TIME timeCorrSum10 = 0;
	HIRES_TIME avgTime;
#ifdef __WINDOWS__
	LARGE_INTEGER performanceCount;
#endif /* __WINDOWS__ */
#ifdef USE_SD
	HIRES_TIME timeCorrSumSD = 0;
	double stdDev;
	int timesCountSD = 0;
#endif /* USE_SD */
	long timeMS, ticksPerSec;
	const int startIndex = ( noTimes == 1 ) ? 0 : 1;
		/* If we're using a multitude of readings we discard the first one,
		   which is always unusually high due to startup overhead */
	int i, timesCount10 = 0;

	/* Try and get the clock frequency */
#ifdef __WINDOWS__
	QueryPerformanceFrequency( &performanceCount );
	ticksPerSec = performanceCount.LowPart;
#else
	ticksPerSec = 1000000;
#endif /* __WINDOWS__ */
	if( noTimes > 1 )
		{
		fprintf( outputStream, "Times given in clock ticks of frequency " );
#ifdef __WINDOWS__
		fprintf( outputStream, "%ld", ticksPerSec );
#else
		fprintf( outputStream, "~1M" );
#endif /* __WINDOWS__ */
		fprintf( outputStream, " ticks per second.\n\n" );
		}

	/* Find the mean execution time */
	for( i = startIndex; i < noTimes; i++ )
		timeSum += times[ i ];
	timeAvg = timeSum / noTimes;
	timeDelta = timeAvg / 10;	/* 10% variation */

	/* Find the fastest overall time */
	for( i = startIndex; i < noTimes; i++ )
		{
		if( times[ i ] < timeMin )
			timeMin = times[ i ];
		}

	/* Find the mean time, discarding anomalous results more than 10% out.  
	   We cast the values to longs in order to (portably) print them, if we 
	   want to print the full 64-bit values we have to use nonstandard 
	   extensions like "%I64d" (for Win32) */
	for( i = startIndex; i < noTimes; i++ )
		{
		if( times[ i ] > timeAvg - timeDelta && \
			times[ i ] < timeAvg + timeDelta )
			{
			timeCorrSum10 += times[ i ];
			timesCount10++;
			}
		}
	if( timesCount10 <= 0 )
		{
		fprintf( outputStream, "Error: No times within +/-%ld of %ld.\n",
				( long ) timeDelta, ( long ) timeAvg );
		return( -1 );
		}
	avgTime = timeCorrSum10 / timesCount10;
	if( noTimes > 1 )
		{
		fprintf( outputStream, "Time: min.= %ld, avg.= %ld ", 
				 ( long ) timeMin, ( long ) avgTime );
		}
	timeMS = ( avgTime * 1000 ) / ticksPerSec;
#if 0	/* Print difference to fastest time, usually only around 1% */
	fprintf( outputStream, "(%4d)", 
			 ( timeCorrSum10 / timesCount10 ) - timeMin );
#endif /* 0 */

#ifdef USE_SD
	/* Find the standard deviation */
	for( i = startIndex; i < noTimes; i++ )
		{
		const HIRES_TIME timeDev = times[ i ] - timeAvg;

		timeCorrSumSD += ( timeDev * timeDev );
		}
	stdDev = timeCorrSumSD / noTimes;
	stdDev = sqrt( stdDev );
	fprintf( outputStream, ", SD = %ld", ( long ) stdDev );

	/* Find the mean time, discarding anomalous results more than two 
	   standard deviations out */
	timeCorrSumSD = 0;
	timeDelta = ( HIRES_TIME ) stdDev * 2;
	for( i = startIndex; i < noTimes; i++ )
		{
		if( times[ i ] > timeAvg - timeDelta && \
			times[ i ] < timeAvg + timeDelta )
			{
			timeCorrSumSD += times[ i ];
			timesCountSD++;
			}
		}
	if( timesCountSD == 0 )
		timesCountSD++;	/* Context switch, fudge it */
	fprintf( outputStream, ", corr.mean = %ld", 
			 ( long ) ( timeCorrSumSD / timesCountSD ) );

#if 0	/* Print difference to fastest and mean times, usually only around
		   1% */
	fprintf( outputStream, " (dF = %4d, dM = %4d)\n",
			 ( timeCorrSumSD / timesCountSD ) - timeMin,
			 abs( ( timeCorrSumSD / timesCountSD ) - \
				  ( timeCorrSum10 / timesCount10 ) ) );
#endif /* 0 */
#endif /* USE_SD */

	/* Print the times in ms */
	if( noTimes > 1 )
		fprintf( outputStream, "\n  Per-op time = " );
	if( timeMS <= 0 )
		fprintf( outputStream, "< 1" );
	else
		fprintf( outputStream, "%ld", timeMS );
	fprintf( outputStream, " ms.\n" );

	return( ( timeMS <= 0 ) ? 1 : timeMS );
	}

int timeDisplay( HIRES_TIME timeValue )
	{
	return( timeDisplayMean( &timeValue, 1 ) );
	}

/* Timing-attack evaluation code.  This requires the following support 
   function in cryptapi.c

C_RET cryptDelayRandom( C_IN CRYPT_CONTEXT signContext,
						C_IN CRYPT_CONTEXT hashContext )
	{
	if( signContext != CRYPT_UNUSED )
		{
		MECHANISM_SIGN_INFO mechanismInfo;
		BYTE buffer[ CRYPT_MAX_PKCSIZE + 8 ];
		int status;

		setMechanismSignInfo( &mechanismInfo, buffer, CRYPT_MAX_PKCSIZE, 
							  hashContext, CRYPT_UNUSED, signContext );
		status = krnlSendMessage( signContext, IMESSAGE_DEV_SIGN, 
								  &mechanismInfo, MECHANISM_SIG_PKCS1 );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( insertCryptoDelay() );
	} */

int testTimingAttackConv( void )
	{
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT sessionKeyContext;
	HIRES_TIME times[ 1000 ];
	BYTE encryptedKeyBlob[ 1024 ];
	int length, i, status;

	/* Create the contexts needed for the decryption timing checks */
	status = cryptCreateContext( &sessionKeyContext, CRYPT_UNUSED,
								 DEFAULT_CRYPT_ALGO );
	if( cryptStatusError( status ) )
		return( FALSE );
	status = cryptGenerateKey( sessionKeyContext );
	if( cryptStatusError( status ) )
		return( FALSE );
	status = loadRSAContexts( CRYPT_UNUSED, &cryptContext, &decryptContext );
	if( !status )
		return( FALSE );

	/* Create the encrypted key blob */
	status = cryptExportKey( encryptedKeyBlob, 1024, &length, cryptContext, 
							 sessionKeyContext );
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "cryptExportKeyEx() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( length != 174 )
		{
		fprintf( outputStream, "Encrypted key should be %d bytes, was %d, "
				 "line %d.\n", 174, length, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( sessionKeyContext );

	/* Determine the time for the unmodified decrypt */
#if 0
	for( i = 0; i < 200; i++ )
		{
		HIRES_TIME timeVal;

		cryptCreateContext( &sessionKeyContext, CRYPT_UNUSED, 
							DEFAULT_CRYPT_ALGO );
		timeVal = timeDiff( 0 );
		status = cryptImportKey( encryptedKeyBlob, length, decryptContext, 
								 sessionKeyContext );
		timeVal = timeDiff( timeVal ); 
		cryptDestroyContext( sessionKeyContext );
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptImportKey() failed with status %s, "
					 "line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		times[ i ] = timeVal;
		}
#if 0
	fprintf( outputStream, "Time for unmodified decrypt:\n" );
	for( i = 0; i < 200; i++ )
		{
		fprintf( outputStream, "%5d ", times[ i ] );
		if( ( ( i + 1 ) % 10 ) == 0 )
			fprintf( outputStream, "\n" );
		}
#endif /* 0 */
	timeDisplayMean( times, 200 );
#endif /* 0 */

	/* Manipulate the encrypted blob and see what timing effect it has */
	for( i = 0; i < 1000; i++ )
		{
		BYTE buffer[ 1024 ], *encryptedKeyPtr;
		HIRES_TIME timeVal;

		/* For the 1024-bit key the encrypted value in the blob ranges from
		   n + 46 to n + 173 (128 bytes, zero-based) */
		encryptedKeyPtr = buffer + 173;
		memcpy( buffer, encryptedKeyBlob, length );
		*encryptedKeyPtr ^= 0x01;
		status = cryptCreateContext( &sessionKeyContext, CRYPT_UNUSED, 
									 DEFAULT_CRYPT_ALGO );
		if( cryptStatusError( status ) )
			return( FALSE );
		timeVal = timeDiff( 0 );
		status = cryptImportKey( buffer, length, decryptContext, 
								 sessionKeyContext );
		timeVal = timeDiff( timeVal ); 
		cryptDestroyContext( sessionKeyContext );
		if( !cryptStatusError( status ) )
			{
			fprintf( outputStream, "Corrupted import wasn't detected, "
					 "line %d.\n", __LINE__ );
			return( FALSE );
			}
		times[ i ] = timeVal;
		}
#if 0
	fprintf( outputStream, "Time for modified decrypt:\n" );
	for( i = 0; i < 1000; i++ )
		{
		fprintf( outputStream, "%5d ", times[ i ] );
		if( ( ( i + 1 ) % 10 ) == 0 )
			fprintf( outputStream, "\n" );
		}
#endif
	timeDisplayMean( times, 1000 );

	return( TRUE );
	}

#define NO_SAMPLES		100

int insertCryptoDelay( void );

int testTimingAttackPKC( void )
	{
	CRYPT_CONTEXT cryptContext, hashContext;
	HIRES_TIME times[ 1000 ];
#ifdef __WINDOWS__
	LARGE_INTEGER performanceCount;
#endif /* __WINDOWS__ */
	BYTE signature[ 1024 ];
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int length, i, status;

#ifdef __WINDOWS__
	QueryPerformanceFrequency( &performanceCount ); 
	printf( "Counter frequency = %ld.\n", performanceCount.LowPart );
#endif /* __WINDOWS__ */

	/* Create the hash to be signed */
	status = cryptCreateContext( &hashContext, CRYPT_UNUSED,
								 CRYPT_ALGO_SHA2 );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptEncrypt( hashContext, "12345678", 8 );
	cryptEncrypt( hashContext, "", 0 );

	/* Get the private key needed for signing */
	filenameFromTemplate( filenameBuffer, USER_PRIVKEY_FILE_TEMPLATE, 1 );
	status = getPrivateKey( &cryptContext, filenameBuffer,
							USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Determine the time for the non-dithered sign */
	for( i = 0; i < NO_SAMPLES; i++ )
		{
		HIRES_TIME timeVal;

		timeVal = timeDiff( 0 );
#if 1
		status = cryptCreateSignature( signature, 1024, &length, 
									   cryptContext, hashContext );
  #if 0
		cryptDelayRandom( CRYPT_UNUSED, CRYPT_UNUSED );
  #endif /* 0 */
#else
		/* Raw RSA signature */
		cryptDelayRandom( cryptContext, hashContext );
#endif /* 0 */
		timeVal = timeDiff( timeVal ); 
		if( cryptStatusError( status ) )
			{
			fprintf( outputStream, "cryptCreateSignature() failed with "
					 "status %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		times[ i ] = timeVal;
		}

	/* Print the results, which can be graphed in CSV-delimited form at
	   https://www.socscistatistics.com/descriptive/histograms or in CRLF-
	   delimited form at https://www.wessa.net/rwasp_histogram.wasp */
	for( i = 0; i < NO_SAMPLES; i++ )
		{
		/* 32/64-bit QPC: All = times[ i ].
		   64-bit rdtsc: All = times[ i ] / 50, delay = times[ i ] / 2 */
		printf( "%d, ", times[ i ] );
		}
	putchar( '\n' );
	timeDisplayMean( times, NO_SAMPLES );

	return( TRUE );
	}
#endif /* USE_TIMING */

