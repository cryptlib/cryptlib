<<<<<<< HEAD
/****************************************************************************
*																			*
*						cryptlib Internal Time/Timer API					*
*						Copyright Peter Gutmann 1992-2020					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/* Expressions involving time_t and integer constant values get a bit hairy 
   if time_t is 64-bit but the integer constant is treated as 32-bit, 
   leading to warnings from some compilers.  To deal with this we cast the
   integer constant value to a time_t */

#define MAX_INTLENGTH_TIME	( ( time_t ) MAX_INTLENGTH )

/****************************************************************************
*																			*
*								Time Functions 								*
*																			*
****************************************************************************/

/* Get the system time safely.  The first function gets the system time, the
   second is used for operations such as signing certs and timestamping and 
   tries to get the time from a hardware-device time source if one is 
   available.
   
   Because of the implementation-dependent behaviour of the time_t type we 
   perform an explicit check against '( time_t ) -1' as well as a general 
   range check to avoid being caught by conversion problems if time_t is a 
   type too far removed from int.
   
   We allow the time to be overridden by a user-set value for testing 
   purposes, since a single bit-flip can now potentially upset all time-
   based calculations we store it in TMR form */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
TMR_DECLARE_STATIC( time_t, testTimeValue );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

static time_t returnTime( const time_t theTime,
						  IN_ENUM_OPT( GETTIME ) \
								const GETTIME_TYPE getTimeType )
	{
	REQUIRES_EXT( isEnumRangeOpt( getTimeType, GETTIME ), 0 );

	/* If no useful time is available, return either an error value or an 
	   approximation of the time */
	if( ( theTime == ( time_t ) -1 ) || \
		( theTime <= MIN_TIME_VALUE ) || \
		( theTime >= MAX_TIME_VALUE ) )
		{
		DEBUG_DIAG(( "No time source available" ));
		assert( DEBUG_WARN );
		if( getTimeType == GETTIME_NOFAIL || \
			getTimeType == GETTIME_NOFAIL_MINUTES )
			{
			/* It's a non-critical time value, return an approximation */
			return( CURRENT_TIME_VALUE );
			}

		return( 0 );
		}

	/* If we're returning time rounded to the nearest minute to mitigate 
	   timing attacks, remove (truncate) the seconds value.  The reasoning 
	   behind this gets a bit complicated because if we round down then 
	   we'll produce backdated times while if we round up we'll produce 
	   future-dated times.  The scenarios where we're called with 
	   GETTIME_MINUTES are the following, first the situations where 
	   rounding doesn't matter:

		certrev.c:prepareRevocationEntries() - Revocation time.
		scep_cli.c:createScepCert() - Creation of self-signed SCEP 
			certificate to sign the client request.

	   Then situations where it's probably better to round down than up:

		sign_cms.c:addSigningTime() - CMS signing time.
		tsp.c:sendServerResponse() - TSA timestamp.

	   Finally ones where it's necessary to round down to ensure that the 
	   item is valid at the time that it's signed:

		certsign.c:setCertTimeinfo() - Certificate validFrom time.

	   As a result we truncate seconds (round down) rather than rounding to 
	   the closest minute, which means that we'll never return a future 
	   time */
	if( getTimeType == GETTIME_MINUTES || \
		getTimeType == GETTIME_NOFAIL_MINUTES )
		{
		return( theTime - ( theTime % 60 ) );
		}

	return( theTime );
	}

time_t getTime( IN_ENUM_OPT( GETTIME ) const GETTIME_TYPE getTimeType )
	{
	const time_t theTime = time( NULL );
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
	time_t testTime;
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

	REQUIRES_EXT( isEnumRangeOpt( getTimeType, GETTIME ), 0 );

	/* If we're running a self-test with externally-controlled time, return
	   the pre-set time value */
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
	testTime = TMR_GET( testTimeValue );
	if( testTime != 0 )
		return( testTime );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

	return( returnTime( theTime, getTimeType ) );
	}

time_t getReliableTime( IN_HANDLE const CRYPT_HANDLE cryptHandle,
						IN_ENUM_OPT( GETTIME ) const GETTIME_TYPE getTimeType )
	{
	CRYPT_DEVICE cryptDevice;
	MESSAGE_DATA msgData;
	time_t theTime;
	int status;

	REQUIRES_EXT( ( cryptHandle == SYSTEM_OBJECT_HANDLE || \
					isHandleRangeValid( cryptHandle ) ), 0 );
	REQUIRES_EXT( getTimeType == GETTIME_MINUTES, 0 );
				  /* This function is only ever used for generating 
					 timestamps so it's always called with GETTIME_MINUTES */

	/* Get the dependent device for the object that needs the time.  This
	   is typically a private key being used for signing something that 
	   needs a timestamp, so what we're doing here is finding a time source
	   associated with that key, for example the HSM that the key is stored
	   in */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETDEPENDENT,
							  &cryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		cryptDevice = SYSTEM_OBJECT_HANDLE;

	/* Try and get the time from the device */
	setMessageData( &msgData, &theTime, sizeof( time_t ) );
	status = krnlSendMessage( cryptDevice, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_TIME );
	if( cryptStatusError( status ) && cryptDevice != SYSTEM_OBJECT_HANDLE )
		{
		/* We couldn't get the time from a crypto token, fall back to the
		   system device */
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_TIME );
		}
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "Error: No time source available" ));
		assert( DEBUG_WARN );
		return( 0 );
		}

	return( returnTime( theTime, getTimeType ) );
	}

/****************************************************************************
*																			*
*								Timer Functions 							*
*																			*
****************************************************************************/

/* Monotonic timer interface that protects against the system clock being 
   changed during a timed operation like network I/O, so we have to abstract 
   the standard time API into a monotonic time API.  Since these functions 
   are purely peripheral to other operations (for example handling timeouts 
   for network I/O) they never fail but simply return good-enough results if 
   there's a problem (although they assert in debug mode).  This is because 
   we don't want to abort a network session just because we've detected some 
   trivial clock irregularity.

   The way this works is that we record the following information for each
   timing interval:

			(endTime - \
				timeRemaining)			 endTime
	................+-----------------------+...............
		^			|						|		^
	currentTime		|<--- timeRemaining --->|	currentTime'
		  ....<------- origTimeout -------->|

   When currentTime falls outside the timeRemaining interval we know that a 
   clock change has occurred and can try and correct it.  Moving forwards
   by an unexpected amount is a bit more tricky than moving back because 
   it's hard to define "unexpected", so we use an estimation method that 
   detects the typical reasons for a clock leap (an attempt to handle a DST 
   adjust by changing the clock) without yielding false positives */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkMonotimer( const MONOTIMER_INFO *timerInfo )
	{
	assert( isReadPtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	/* Make sure that the basic timer values are within bounds.  We can't
	   check endTime for a maximum range value since it's a time_t */
	if( !isIntegerRange( timerInfo->origTimeout ) || \
		!isIntegerRange( timerInfo->timeRemaining ) || \
		timerInfo->endTime < 0 )
		{
		DEBUG_PUTS(( "sanityCheckMonotimer: General info" ));
		return( FALSE );
		}

	/* Make sure that time ranges are withing bounds.  This can generally 
	   only happen when a time_t over/underflow has occurred */
	if( timerInfo->endTime < timerInfo->timeRemaining || \
		timerInfo->origTimeout < timerInfo->timeRemaining )
		{
		DEBUG_PUTS(( "sanityCheckMonotimer: Time range" ));
		return( FALSE );
		}

	return( TRUE );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
static void handleTimeOutOfBounds( INOUT_PTR MONOTIMER_INFO *timerInfo )
	{
	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	DEBUG_DIAG(( "time_t underflow/overflow has occurred" ));
	assert( DEBUG_WARN );

	/* We've run into an overflow condition in the calculations that we've
	   performed on a time_t, this is a bit tricky to handle because we 
	   can't just give up on (say) performing network I/O just because we 
	   can't reliably set a timeout.  The best that we can do is warn in 
	   debug mode and set a zero timeout so that at least one lot of I/O 
	   will still take place */
	timerInfo->origTimeout = timerInfo->timeRemaining = 0;
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN correctMonoTimer( INOUT_PTR MONOTIMER_INFO *timerInfo,
								 const time_t currentTime )
	{
	BOOLEAN needsCorrection = FALSE;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	/* If a time_t over/underflow has occurred, make a best-effort attempt 
	   to recover */
	if( !checkMonotimer( timerInfo ) )
		{
		handleTimeOutOfBounds( timerInfo );
		return( FALSE );
		}

	/* If the clock has been rolled back to before the start time, we need 
	   to correct this.  The range check for endTime vs. timeRemaining has
	   already been done as part of the sanity check */
	if( currentTime < timerInfo->endTime - timerInfo->timeRemaining )
		needsCorrection = TRUE;
	else
		{
		/* If we're past the timer end time, check to see whether it's 
		   jumped by a suspicious amount.  If we're more than 30 minutes 
		   past the timeout (which will catch things like attempted DST 
		   corrections) and the initial timeout was less than the change (to 
		   avoid a false positive if we've been waiting > 30 minutes for a 
		   legitimate timeout), we need to correct this.  This can still 
		   fail if (for example) we have a relatively short timeout and 
		   we're being run in a VM that gets suspended for more than 30 
		   minutes and then restarted, but by then any peer communicating 
		   with us should have long since given up waiting for a response 
		   and timed out the connection.  In any case someone fiddling with 
		   suspending processes in this manner, which will cause problems 
		   for anything doing network I/O, should be prepared to handle any 
		   problems that arise, for example by ensuring that current network 
		   I/O has completed before suspending the process */
		if( currentTime > timerInfo->endTime )
			{
			const time_t delta = currentTime - timerInfo->endTime;

			if( ( delta < 0 || delta > ( 30 * 60 ) ) && \
				timerInfo->origTimeout < delta )
				needsCorrection = TRUE;
			}
		}
	if( !needsCorrection )
		return( TRUE );

	/* The time information has been changed, correct the recorded time 
	   information for the new time.
	   
	   The checking for overflow in time_t is impossible to perform when the
	   compiler uses gcc's braindamaged interpretation of the C standard.
	   A compiler like MSVC knows that a time_t is an int or long and 
	   produces the expected code from the following, a compiler like gcc 
	   also knows that a time_t is an int or a long but assumes that it 
	   could also be a GUID or a variant record or anonymous union or packed 
	   bitfield and therefore removes the checks in the code, because trying 
	   to perform the check on a time_t is undefined behaviour (UB).  There 
	   is no way to work around this issue apart from switching to a less 
	   braindamaged compiler, so we leave the code there for sane compilers
	   under the acknowledgement that there's no way to address this with 
	   gcc */
	if( currentTime >= ( MAX_INTLENGTH_TIME - timerInfo->timeRemaining ) )
		{
		DEBUG_DIAG(( "Invalid monoTimer time correction period" ));
		assert( DEBUG_WARN );
		handleTimeOutOfBounds( timerInfo );
		return( FALSE );
		}
	timerInfo->endTime = currentTime + timerInfo->timeRemaining;
	if( timerInfo->endTime < currentTime || \
		timerInfo->endTime < currentTime + max( timerInfo->timeRemaining,
												timerInfo->origTimeout ) )
		{
		/* There's a problem with the time calculations, handle the overflow
		   condition and tell the caller not to try anything further */
		handleTimeOutOfBounds( timerInfo );
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setMonoTimer( OUT_PTR MONOTIMER_INFO *timerInfo, 
				  IN_INT_Z const int duration )
	{
	const time_t currentTime = getTime( GETTIME_NOFAIL );
	BOOLEAN initOK;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );
	
	REQUIRES( isIntegerRange( duration ) );

	memset( timerInfo, 0, sizeof( MONOTIMER_INFO ) );
	if( currentTime >= ( MAX_INTLENGTH_TIME - duration ) )
		{
		DEBUG_DIAG(( "Invalid monoTimer time period" ));
		assert( DEBUG_WARN );
		handleTimeOutOfBounds( timerInfo );
		return( CRYPT_OK );
		}
	timerInfo->endTime = currentTime + duration;
	timerInfo->timeRemaining = timerInfo->origTimeout = duration;
	if( getTime( GETTIME_NONE ) <= MIN_TIME_VALUE )
		{
		/* There's no usable system time available, just run for 1000
		   iterations.  This isn't a major problem since timers are only
		   used to break out of loops that have other exit conditions,
		   so either one of those will be triggered forcing a loop exit
		   or the loop will iterate for quite some time but eventually
		   terminate anyway.
		   
		   There's an even more obscure condition under which we could run 
		   into problems and that's the case of a frozen clock that keeps 
		   returning the same valid but never-changing time.   This is 
		   obscure enough that we just rely on the other loop-termination
		   conditions for an exit */
		assert( DEBUG_WARN );
		timerInfo->badTimeCount = 1000;
		}
	else
		{
		/* Set the bad-system-time count variable to an invalid value to 
		   make sure that it's not used */
		timerInfo->badTimeCount = -1234;
		}
	initOK = correctMonoTimer( timerInfo, currentTime );
	ENSURES( initOK );

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void extendMonoTimer( INOUT_PTR MONOTIMER_INFO *timerInfo, 
					  IN_INT const int duration )
	{
	const time_t currentTime = getTime( GETTIME_NOFAIL );

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );
	
	REQUIRES_V( isIntegerRange( duration ) );

	/* Correct the timer for clock skew if required */
	if( !correctMonoTimer( timerInfo, currentTime ) )
		return;

	/* Extend the monotonic timer's timeout interval to allow for further
	   data to be processed */
	if( timerInfo->origTimeout >= ( MAX_INTLENGTH_TIME - duration ) || \
		timerInfo->endTime >= ( MAX_INTLENGTH_TIME - duration ) || \
		timerInfo->endTime < currentTime )
		{
		DEBUG_DIAG(( "Invalid monoTimer time period extension" ));
		assert( DEBUG_WARN );
		handleTimeOutOfBounds( timerInfo );
		return;
		}
	timerInfo->origTimeout += duration;
	timerInfo->endTime += duration;
	timerInfo->timeRemaining = timerInfo->endTime - currentTime;

	/* Re-correct the timer in case overflow occurred */
	( void ) correctMonoTimer( timerInfo, currentTime );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkMonoTimerExpiryImminent( INOUT_PTR MONOTIMER_INFO *timerInfo,
									  IN_INT_Z const int timeLeft )
	{
	const time_t currentTime = getTime( GETTIME_NOFAIL );
	time_t timeRemaining;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	REQUIRES_B( isIntegerRange( timeLeft ) );

	/* If the timeout has expired, don't try doing anything else */
	if( timerInfo->timeRemaining <= 0 )
		return( TRUE );

	/* Correct the monotonic timer for clock skew if required */
	if( !correctMonoTimer( timerInfo, currentTime ) )
		return( TRUE );

	/* If there's no reliable time available so that we've fallen back to
	   a simple counter, decrement that and exit */
	if( timerInfo->badTimeCount >= 0 )
		{
		if( timerInfo->badTimeCount <= 0 )
			return( TRUE );
		timerInfo->badTimeCount--;
		return( FALSE );
		}

	/* Check whether the time will expire within timeLeft seconds */
	if( timerInfo->endTime < currentTime )
		{
		DEBUG_DIAG(( "Invalid monoTimer expiry time period" ));
		assert( DEBUG_WARN );
		handleTimeOutOfBounds( timerInfo );
		return( TRUE );
		}
	timeRemaining = timerInfo->endTime - currentTime;
	if( timeRemaining > timerInfo->timeRemaining )
		{
		handleTimeOutOfBounds( timerInfo );
		timeRemaining = 0;
		}
	timerInfo->timeRemaining = timeRemaining;
	return( ( timerInfo->timeRemaining <= timeLeft ) ? TRUE : FALSE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkMonoTimerExpired( INOUT_PTR MONOTIMER_INFO *timerInfo )
	{
	return( checkMonoTimerExpiryImminent( timerInfo, 0 ) );
	}

/****************************************************************************
*																			*
*							Time Dithering Functions						*
*																			*
****************************************************************************/

/* Delay by small random amounts, used to both dither the results of online-
   visible crypto operations to make timing attacks harder and for failed 
   crypto operations to stall probing attacks alongside the dithering by 
   adding much longer delays.  In effect this creates the inverse of fuzzy 
   time/fuzzy I/O from Wei-Ming Hu's "Reducing Timing Channels with Fuzzy 
   Time", Journal of Computer Security, 1992, more usually implemented as 
   spread-spectrum clocking to deal with EMI, by keeping the clock constant 
   but fuzzing the execution time of what's being measured.

   We use this instead of trying to achieve perfect constant-time execution 
   in the code (although we try for that as well as much as possible) 
   because the combination of the wide range of architectures with different
   timing characteristics that cryptlib has to run across, combined with the
   neverending battle against compiler modification of the generated code
   (see the long comment about this in misc/safety.h), and the fact that 
   cryptlib can run with any number of different back-ends of which many 
   don't implement much in the way of timing countermeasures means that 
   there's no guarantee that any low-level approach will remain constant-
   time on a different architecture and/or across different compiler 
   versions and optimisation levels, or even exist at all (e.g. many PKCS 
   #11 devices).
   
   As with anything involving randomness, there's been a lot of smoke and 
   not much light generated over the use of random delays to address timing 
   attacks.  The generic answer is that it doesn't help so there's no point 
   in doing it and everyone should just write constant-time code, another 
   prime example of le mieux est l'ennemi du bien.

   If the arguments ever get beyond abstract theory (theoretical constant-
   time code is better than theoretical random delays), the argument given 
   is usually that we're measuring timing differences in us or ns while the 
   delay functions are typically in ms.  Another argument is that all an 
   attacker has to do is repeat the measurements in order to filter out the 
   delays.

   To give a concrete example, a sleep function with a ms granularity being 
   used with a 2GHz CPU means that there are 2M clock cycles between each 
   timer tick.  The sleep function doesn't guarantee to return after exactly 
   x ms but after at least x ms have elapsed which helps a bit, but we still 
   need a finer-grained delay, which insertCryptoDelay() further down 
   provides.

   A counterargument for the high-precision measurement claim is that if 
   you've got an attacker sitting on your local LAN segment making ns-scale 
   timing measurements on your crypto then you've got bigger things to worry 
   about than side-channel attacks (over more distant connections, you can 
   at best get tens to hundreds of us using thousands of measurements, see 
   e.g. "Opportunities and Limits of Remote Timing Attacks" by Crosby, Reid, 
   and Wallach, which also required multiple days of data-gathering 
   beforehand to characterise the network).  
   
   In addition in cryptlib's case since all operations go via the kernel, 
   you don't have direct (timing) access to the low-level crypto ops but 
   only get strongly dithered results at that level.  This actually makes 
   the effectiveness of the dithering countermeasures somewhat difficult to
   evaluate since the kernel already provides a good measure of dithering.

   As a result, while you can still use repeated measurements to eventually
   filter out the dithering, it's now made the attacker's job much, much 
   harder.  Since the failure-related dithering is essentially free (it's 
   only invoked if an operation fails), it makes sense to add the delay.  
   In addition, on top of the sleep delay, we add the fine-grained delay 
   mentioned earlier to dither exact timings.
   
   Another issue is how long to make the delay.  Obviously the longer the 
   better since it slows down attacks, however if we make it too long then 
   it can end up looking like a different problem, e.g. a networking issue 
   rather than a crypto defence, which will be a pain to diagnose for 
   users.  3s seems to be a good tradeoff between dithering operations and 
   slowing down an attacker while not adding an excessive delay that looks 
   like it's caused by something else.
   
   A final consideration is whether we should also add delays before 
   critical operations in order to make glitch attacks more difficult.  This 
   is more something that belongs in the boot firmware of embedded devices 
   likely to be subject to such attacks since, as a crypto library, we'll be 
   used long after the fixed-timing boot process is complete, making glitch 
   attacks difficult.  In addition the work involved in creating the random 
   delay will be quite visible in side-channel traces, pointing an attacker 
   at where the interesting stuff is going on */

/* Implement an extremely slow busy-wait loop via the world's worst hash
   function.  We use the slowest and most unpredictable data-manipulation
   instructions available, combined with endless data dependencies and 
   pipeline stalls.  Multiplies, while they often have a single-cycle 
   throughput, typically have a multiple-cycle latency, which we enforce 
   with data dependencies.  The magic instruction for poor performance 
   though is the divide, which is typically microcoded and with a huge, 
   data-dependent, latency */

#ifdef SYSTEM_64BIT
  #define CONST1	0x6A09E667BB67AE85	/* SHA2, h0 || h1 */
  #define CONST2	0x3C6EF372A54FF53A	/* SHA2, h2 || h3 */
  #define CONST3	0x510E527F9B05688C	/* SHA2, h4 || h5 */
  #define CONST4	0x1F83D9AB5BE0CD19	/* SHA2, h6 || h7 */
#else
  #define CONST1	0xCA62C1D6			/* SHA1, sqrt10 */
  #define CONST2	0x8F1BBCDC			/* SHA1, sqrt5 */
  #define CONST3	0x6ED9EBA1			/* SHA1, sqrt3 */
  #define CONST4	0x5A827999			/* SHA1, sqrt2 */
#endif /* 32- vs. 64-bit systems */

#if defined( __WIN64__ )
  typedef DWORD64			MACHINE_WORD;
#elif defined( __WIN32__ )
  typedef DWORD				MACHINE_WORD;
#else
  typedef unsigned long		MACHINE_WORD;
#endif /* System-specific machine word data types */

#ifdef _MSC_VER
  #ifdef SYSTEM_64BIT
	#define ROTL( x, r )	_rotl64( x, r )
  #else
	#define ROTL( x, r )	_rotl( x, r )
  #endif /* 32- vs. 64-bit systems */
#else
  /* Most compilers have rotate-recognisers, this is the form that will 
     produce a native rotate instruction */
  #define WORD_SIZE			( sizeof( MACHINE_WORD ) * 8 )
  #define ROTL( x, r )		( ( ( x ) << ( r ) ) | ( ( x ) >> ( WORD_SIZE - ( r ) ) ) )
#endif /* _MSC_VER */

static int merdeMerdeHash( const int value1, const int value2 )
	{
	MACHINE_WORD l = value1, r = value2;
	int fineDelay, i;

	/* Create the initial coarse-grained delay via the world's worst hash 
	   function, full of data dependencies and pipeline stalls */
	for( i = 0; i < value1; i++ )
		{
		/* Fill up both l and r with bits */
		l *= r + CONST1;
		r *= l + CONST2;

		/* Since we're about to divide by r, make sure that it's not zero, 
		   as well as adding a number of unpredictable branches to the code 
		   flow */
		while( !( r & 0x800 ) )
			r += CONST3;

		/* Perform a slow divide.  We actually apply it as a mod operation 
		   (still done via a divide instruction, only the remainder is 
		   what's preserved) since a divide would reduce l to a small 
		   integer value, and zero with 50% probability.  However we also 
		   have to be careful with the mod operation for the same reason as 
		   the problem with divides, at least half the time it'll be a 
		   no-op, so we shift it four bits to increase the chances of it 
		   doing something.  Finally, once we've done the divide, we refill 
		   l since the mod by a smaller amount has decreased its magnitude */
		l %= r >> 4;
		l += ROTL( r, 13 );

		/* As before, this time with r and l */
		while( !( l & 0x800 ) )
			l += CONST4;
		r %= l >> 4;
		r += ROTL( l, 13 );
		}

	/* Finish off with a fine-grained delay */
	fineDelay = ( int ) ( l & 0x7FFF );
	for( i = 0; i < fineDelay; i++ )
		{
		l += ROTL( r, 23 );
		r += ROTL( l, 23 );
		}

	return( ( r + l ) & 0x7FFF );
	}

/* Insert a small random delay to make timing attacks on crypto operations
   harder.  This is a bit of a pain because the delays follow crypto 
   operations that have been tuned to be as fast and efficient as possible,
   while what we're doing here is slowing them down again, however fast
   crypto typically won't get noticed while side-channel vulnerable crypto
   will.
   
   An alternative to trying to make the crypto constant-time is to bracket 
   the operation with clock ticks, so we wait for a clock tick to start the
   operation and wait for another clock tick to finish it.  This is 
   typically even worse than inserting a random delay because it inserts two 
   largeish delays instead, even if it's done via a sleep call rather than a 
   busy-wait
   
   Another option, getting increasingly esoteric, would be possible on a 
   very busy server by batching crypto operations, so that n crypto 
   operations are run back-to-back and the result only returned when the 
   final one has completed, however this again leads to long delays as well
   as being horribly complex to implement */

int insertCryptoDelay( void )
	{
	static int seed = 1;

	/* Insert a short delay.  Since getRandomInteger() returns a short-
	   integer value (which we make explicit here, although the operation
	   is redundant), we have to call the hash function twice to get a long 
	   enough delay.

	   The delay is chosen so that it adds about 1% to the execution time of
	   a 2Kbit private-key op.  This is actually 1/5 of the SD of the 
	   private-key op time, so there's plenty of dithering there anyway...

	   The first value is the iteration count, the second is a a seed value
	   that's fed back to the input to ensure that a compiler can't inline/
	   optimise away the expression if it detects that the result isn't 
	   being used */ 
	seed = merdeMerdeHash( getRandomInteger() % 32768, seed );
	return( merdeMerdeHash( getRandomInteger() % 32768, seed ) );
	}

/* Delay by a large amount by suspending the current thread for a preset 
   time.  The external form delayRandom() is called in response to generic
   failures in secure sessions rather than crypto failures.  Crypto failures 
   are handled via registerCryptoFailure() */

static void randomDelay( IN_RANGE( 0, 10 ) const int baseDelaySeconds, 
						 IN_RANGE( 100, 5000 ) const int maxDelayMS )
	{
	int delayTime = getRandomInteger();

	REQUIRES_V( baseDelaySeconds >= 0 && baseDelaySeconds <= 10 );
	ENSURES_V( maxDelayMS >= 100 && maxDelayMS <= 5000 );

	/* Use a delay from 0.01s to maxDelayMS.  getRandomInteger() can return 
	   zero for a shouldn't-occur error condition, this is converted into a 
	   small nonzero wait alongside an actual zero value */
	delayTime %= ( maxDelayMS + 1 );
	if( delayTime < 5 )
		delayTime = 5;
	ENSURES_V( delayTime >= 5 && delayTime <= 5000 );

	/* Add the base delay amount */
	delayTime += baseDelaySeconds * 1000;

	/* Wait for the given number of milliseconds */
	( void ) krnlWait( delayTime );
	}

int delayRandom( void )
	{
	/* When fuzzing, make sure that we don't insert delays once we bail out 
	   at the end of the fuzzed data */
	FUZZ_EXIT();

	randomDelay( 0, 3000 );
	return( insertCryptoDelay() );
	}

/* Respond to repeated crypto failures, an indication that someone is trying 
   to use us as an oracle.  This tracks how many failures have occurred 
   recently and inserts a delay proportional to the number of failures, 
   acting as a rate-limiting mechanism for attacker queries.  We keep a 
   single count across all crypto failure types to avoid allowing an 
   attacker to bypass the rate-limiting by spreading their queries across
   multiple mechanisms and protocols */ 

#ifdef USE_SESSIONS

int registerCryptoFailure( void )
	{
	static time_t intervalStartTime = CURRENT_TIME_VALUE;
	static int failures = 0;
	const time_t currentTime = getTime( GETTIME_NONE );
	int status;

	/* When fuzzing, make sure that we don't insert delays once we bail out 
	   at the end of the fuzzed data */
	FUZZ_EXIT();

	/* If there's no reliable time source available then there's not much 
	   that we can do apart from inserting a tradeoff delay that's long 
	   enough to slow down attacks but not long enough to DoS ourselves */
	if( currentTime <= MIN_TIME_VALUE )
		{
		randomDelay( 0, 500 );
		insertCryptoDelay();
		return( 0 );
		}

	/* Since the crypto failure state can be accessed by multiple threads, 
	   we need to wrap the accesses in a mutex */
	status = krnlEnterMutex( MUTEX_CRYPTODELAY );
	if( cryptStatusError( status ) )
		{
		/* As before, and exit with mutex not held */
		randomDelay( 0, 500 );
		insertCryptoDelay();
		return( 0 );
		}

	/* If there hasn't been a crypto failure within the last five minutes,
	   decay the failure count and reset the interval start time */
	if( currentTime >= intervalStartTime + ( 5 * 60 ) )
		{
		const int intervals = ( int ) \
						( ( currentTime - intervalStartTime ) / ( 5 * 60 ) );

		if( intervals < 20 )
			failures >>= intervals;
		else
			failures = 0;
		intervalStartTime = currentTime;
		}
	else
		{
		/* There have been multiple failures within a short time period, if
		   the current one is very recent reset the time window */
		if( currentTime <= intervalStartTime + ( 2 * 60 ) )
			intervalStartTime = currentTime;
		}

	/* Increment the failure count, capping the total at a reasonable 
	   value */ 
	if( failures < 50000 )
		failures++;

	krnlExitMutex( MUTEX_CRYPTODELAY );

	/* Insert a delay proportionate to the number of recent crypto failures.  
	   The threshold for the various delays is rather imprecise, we don't 
	   want to respond disproportionately to a small number of legitimate 
	   failures but do want to do so for an actual attack.  On the other 
	   hand the process is somewhat self-limiting in that once a response is
	   triggered the attack rate will be severely throttled unless the code 
	   is being run with a large number of threads, each of which can be 
	   parked in randomDelay() while the next thread is attacked */
	if( failures < 10 )
		randomDelay( 0, 500 );		/* 0..0.5s */
	else
	if( failures < 50 )
		randomDelay( 0, 1000 );		/* 0..1s */
	else
	if( failures < 100 )
		randomDelay( 1, 2000 );		/* 1..3s */
	else
	if( failures < 500 )
		randomDelay( 3, 2000 );		/* 3..5s */
	else
		randomDelay( 5, 5000 );		/* 5...10s */
	
	return( insertCryptoDelay() );
	}
#endif /* USE_SESSIONS */

/****************************************************************************
*																			*
*								Self-test Functions							*
*																			*
****************************************************************************/

/* Test code for the above functions */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

static void setTestTime( const time_t value )
	{
	TMR_SET( testTimeValue, MIN_TIME_VALUE + value );
	}

static void clearTestTime( void )
	{
	TMR_SET( testTimeValue, 0 );
	}

CHECK_RETVAL_BOOL \
BOOLEAN testIntTime( void )
	{
	MONOTIMER_INFO timerInfo;
	int status;

	/* Test basic timer functions */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 0 );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( !checkMonoTimerExpiryImminent( &timerInfo, 1 ) )
		return( FALSE );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		checkMonoTimerExpiryImminent( &timerInfo, 9 ) )
		return( FALSE );
	if( !checkMonoTimerExpiryImminent( &timerInfo, 10 ) )
		return( FALSE );

	/* Check timer period extension functionality */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 0 );
	if( cryptStatusError( status ) )
		return( FALSE );
	extendMonoTimer( &timerInfo, 10 );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		checkMonoTimerExpiryImminent( &timerInfo, 9 ) || \
		!checkMonoTimerExpiryImminent( &timerInfo, 10 ) )
		return( FALSE );

	/* Check clock going forwards normally */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	setTestTime( 1009 );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		!checkMonoTimerExpiryImminent( &timerInfo, 1 ) )
		return( FALSE );

	/* Check clock going backwards.  This recovers by correcting to allow 
	   the original timeout */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	setTestTime( 999 );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		checkMonoTimerExpiryImminent( &timerInfo, 9 ) || \
		!checkMonoTimerExpiryImminent( &timerInfo, 10 ) )
		return( FALSE );

	/* Check clock going forwards too far.  This recovers from a time jump 
	   of > 30 minutes by correcting to allow the original timeout period on 
	   the assumption that the problem is with the time source rather than 
	   that we've waited for over half an hour for a network packet to 
	   arrive */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	setTestTime( 1000 + ( 45 * 60 ) );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		checkMonoTimerExpiryImminent( &timerInfo, 9 ) || \
		!checkMonoTimerExpiryImminent( &timerInfo, 10 ) )
		return( FALSE );

	/* Check fallback operation if the system time is broken */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	timerInfo.badTimeCount = 5;	/* Force fallback operation */
	if( checkMonoTimerExpired( &timerInfo ) || \
		checkMonoTimerExpired( &timerInfo ) || \
		checkMonoTimerExpired( &timerInfo ) || \
		checkMonoTimerExpired( &timerInfo ) || \
		checkMonoTimerExpired( &timerInfo ) || \
		!checkMonoTimerExpired( &timerInfo ) )
		return( FALSE );

	clearTestTime();
	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
=======
/****************************************************************************
*																			*
*						cryptlib Internal Time/Timer API					*
*						Copyright Peter Gutmann 1992-2020					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/* Expressions involving time_t and integer constant values get a bit hairy 
   if time_t is 64-bit but the integer constant is treated as 32-bit, 
   leading to warnings from some compilers.  To deal with this we cast the
   integer constant value to a time_t */

#define MAX_INTLENGTH_TIME	( ( time_t ) MAX_INTLENGTH )

/****************************************************************************
*																			*
*								Time Functions 								*
*																			*
****************************************************************************/

/* Get the system time safely.  The first function gets the system time, the
   second is used for operations such as signing certs and timestamping and 
   tries to get the time from a hardware-device time source if one is 
   available.
   
   Because of the implementation-dependent behaviour of the time_t type we 
   perform an explicit check against '( time_t ) -1' as well as a general 
   range check to avoid being caught by conversion problems if time_t is a 
   type too far removed from int.
   
   We allow the time to be overridden by a user-set value for testing 
   purposes, since a single bit-flip can now potentially upset all time-
   based calculations we store it in TMR form */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
TMR_DECLARE_STATIC( time_t, testTimeValue );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

static time_t returnTime( const time_t theTime,
						  IN_ENUM_OPT( GETTIME ) \
								const GETTIME_TYPE getTimeType )
	{
	REQUIRES_EXT( isEnumRangeOpt( getTimeType, GETTIME ), 0 );

	/* If no useful time is available, return either an error value or an 
	   approximation of the time */
	if( ( theTime == ( time_t ) -1 ) || \
		( theTime <= MIN_TIME_VALUE ) || \
		( theTime >= MAX_TIME_VALUE ) )
		{
		DEBUG_DIAG(( "No time source available" ));
		assert( DEBUG_WARN );
		if( getTimeType == GETTIME_NOFAIL || \
			getTimeType == GETTIME_NOFAIL_MINUTES )
			{
			/* It's a non-critical time value, return an approximation */
			return( CURRENT_TIME_VALUE );
			}

		return( 0 );
		}

	/* If we're returning time rounded to the nearest minute to mitigate 
	   timing attacks, remove (truncate) the seconds value.  The reasoning 
	   behind this gets a bit complicated because if we round down then 
	   we'll produce backdated times while if we round up we'll produce 
	   future-dated times.  The scenarios where we're called with 
	   GETTIME_MINUTES are the following, first the situations where 
	   rounding doesn't matter:

		certrev.c:prepareRevocationEntries() - Revocation time.
		scep_cli.c:createScepCert() - Creation of self-signed SCEP 
			certificate to sign the client request.

	   Then situations where it's probably better to round down than up:

		sign_cms.c:addSigningTime() - CMS signing time.
		tsp.c:sendServerResponse() - TSA timestamp.

	   Finally ones where it's necessary to round down to ensure that the 
	   item is valid at the time that it's signed:

		certsign.c:setCertTimeinfo() - Certificate validFrom time.

	   As a result we truncate seconds (round down) rather than rounding to 
	   the closest minute, which means that we'll never return a future 
	   time */
	if( getTimeType == GETTIME_MINUTES || \
		getTimeType == GETTIME_NOFAIL_MINUTES )
		{
		return( theTime - ( theTime % 60 ) );
		}

	return( theTime );
	}

time_t getTime( IN_ENUM_OPT( GETTIME ) const GETTIME_TYPE getTimeType )
	{
	const time_t theTime = time( NULL );
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
	time_t testTime;
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

	REQUIRES_EXT( isEnumRangeOpt( getTimeType, GETTIME ), 0 );

	/* If we're running a self-test with externally-controlled time, return
	   the pre-set time value */
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
	testTime = TMR_GET( testTimeValue );
	if( testTime != 0 )
		return( testTime );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

	return( returnTime( theTime, getTimeType ) );
	}

time_t getReliableTime( IN_HANDLE const CRYPT_HANDLE cryptHandle,
						IN_ENUM_OPT( GETTIME ) const GETTIME_TYPE getTimeType )
	{
	CRYPT_DEVICE cryptDevice;
	MESSAGE_DATA msgData;
	time_t theTime;
	int status;

	REQUIRES_EXT( ( cryptHandle == SYSTEM_OBJECT_HANDLE || \
					isHandleRangeValid( cryptHandle ) ), 0 );
	REQUIRES_EXT( getTimeType == GETTIME_MINUTES, 0 );
				  /* This function is only ever used for generating 
					 timestamps so it's always called with GETTIME_MINUTES */

	/* Get the dependent device for the object that needs the time.  This
	   is typically a private key being used for signing something that 
	   needs a timestamp, so what we're doing here is finding a time source
	   associated with that key, for example the HSM that the key is stored
	   in */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETDEPENDENT,
							  &cryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		cryptDevice = SYSTEM_OBJECT_HANDLE;

	/* Try and get the time from the device */
	setMessageData( &msgData, &theTime, sizeof( time_t ) );
	status = krnlSendMessage( cryptDevice, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_TIME );
	if( cryptStatusError( status ) && cryptDevice != SYSTEM_OBJECT_HANDLE )
		{
		/* We couldn't get the time from a crypto token, fall back to the
		   system device */
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_TIME );
		}
	if( cryptStatusError( status ) )
		{
		DEBUG_DIAG(( "Error: No time source available" ));
		assert( DEBUG_WARN );
		return( 0 );
		}

	return( returnTime( theTime, getTimeType ) );
	}

/****************************************************************************
*																			*
*								Timer Functions 							*
*																			*
****************************************************************************/

/* Monotonic timer interface that protects against the system clock being 
   changed during a timed operation like network I/O, so we have to abstract 
   the standard time API into a monotonic time API.  Since these functions 
   are purely peripheral to other operations (for example handling timeouts 
   for network I/O) they never fail but simply return good-enough results if 
   there's a problem (although they assert in debug mode).  This is because 
   we don't want to abort a network session just because we've detected some 
   trivial clock irregularity.

   The way this works is that we record the following information for each
   timing interval:

			(endTime - \
				timeRemaining)			 endTime
	................+-----------------------+...............
		^			|						|		^
	currentTime		|<--- timeRemaining --->|	currentTime'
		  ....<------- origTimeout -------->|

   When currentTime falls outside the timeRemaining interval we know that a 
   clock change has occurred and can try and correct it.  Moving forwards
   by an unexpected amount is a bit more tricky than moving back because 
   it's hard to define "unexpected", so we use an estimation method that 
   detects the typical reasons for a clock leap (an attempt to handle a DST 
   adjust by changing the clock) without yielding false positives */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkMonotimer( const MONOTIMER_INFO *timerInfo )
	{
	assert( isReadPtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	/* Make sure that the basic timer values are within bounds.  We can't
	   check endTime for a maximum range value since it's a time_t */
	if( !isIntegerRange( timerInfo->origTimeout ) || \
		!isIntegerRange( timerInfo->timeRemaining ) || \
		timerInfo->endTime < 0 )
		{
		DEBUG_PUTS(( "sanityCheckMonotimer: General info" ));
		return( FALSE );
		}

	/* Make sure that time ranges are withing bounds.  This can generally 
	   only happen when a time_t over/underflow has occurred */
	if( timerInfo->endTime < timerInfo->timeRemaining || \
		timerInfo->origTimeout < timerInfo->timeRemaining )
		{
		DEBUG_PUTS(( "sanityCheckMonotimer: Time range" ));
		return( FALSE );
		}

	return( TRUE );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
static void handleTimeOutOfBounds( INOUT_PTR MONOTIMER_INFO *timerInfo )
	{
	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	DEBUG_DIAG(( "time_t underflow/overflow has occurred" ));
	assert( DEBUG_WARN );

	/* We've run into an overflow condition in the calculations that we've
	   performed on a time_t, this is a bit tricky to handle because we 
	   can't just give up on (say) performing network I/O just because we 
	   can't reliably set a timeout.  The best that we can do is warn in 
	   debug mode and set a zero timeout so that at least one lot of I/O 
	   will still take place */
	timerInfo->origTimeout = timerInfo->timeRemaining = 0;
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN correctMonoTimer( INOUT_PTR MONOTIMER_INFO *timerInfo,
								 const time_t currentTime )
	{
	BOOLEAN needsCorrection = FALSE;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	/* If a time_t over/underflow has occurred, make a best-effort attempt 
	   to recover */
	if( !checkMonotimer( timerInfo ) )
		{
		handleTimeOutOfBounds( timerInfo );
		return( FALSE );
		}

	/* If the clock has been rolled back to before the start time, we need 
	   to correct this.  The range check for endTime vs. timeRemaining has
	   already been done as part of the sanity check */
	if( currentTime < timerInfo->endTime - timerInfo->timeRemaining )
		needsCorrection = TRUE;
	else
		{
		/* If we're past the timer end time, check to see whether it's 
		   jumped by a suspicious amount.  If we're more than 30 minutes 
		   past the timeout (which will catch things like attempted DST 
		   corrections) and the initial timeout was less than the change (to 
		   avoid a false positive if we've been waiting > 30 minutes for a 
		   legitimate timeout), we need to correct this.  This can still 
		   fail if (for example) we have a relatively short timeout and 
		   we're being run in a VM that gets suspended for more than 30 
		   minutes and then restarted, but by then any peer communicating 
		   with us should have long since given up waiting for a response 
		   and timed out the connection.  In any case someone fiddling with 
		   suspending processes in this manner, which will cause problems 
		   for anything doing network I/O, should be prepared to handle any 
		   problems that arise, for example by ensuring that current network 
		   I/O has completed before suspending the process */
		if( currentTime > timerInfo->endTime )
			{
			const time_t delta = currentTime - timerInfo->endTime;

			if( ( delta < 0 || delta > ( 30 * 60 ) ) && \
				timerInfo->origTimeout < delta )
				needsCorrection = TRUE;
			}
		}
	if( !needsCorrection )
		return( TRUE );

	/* The time information has been changed, correct the recorded time 
	   information for the new time.
	   
	   The checking for overflow in time_t is impossible to perform when the
	   compiler uses gcc's braindamaged interpretation of the C standard.
	   A compiler like MSVC knows that a time_t is an int or long and 
	   produces the expected code from the following, a compiler like gcc 
	   also knows that a time_t is an int or a long but assumes that it 
	   could also be a GUID or a variant record or anonymous union or packed 
	   bitfield and therefore removes the checks in the code, because trying 
	   to perform the check on a time_t is undefined behaviour (UB).  There 
	   is no way to work around this issue apart from switching to a less 
	   braindamaged compiler, so we leave the code there for sane compilers
	   under the acknowledgement that there's no way to address this with 
	   gcc */
	if( currentTime >= ( MAX_INTLENGTH_TIME - timerInfo->timeRemaining ) )
		{
		DEBUG_DIAG(( "Invalid monoTimer time correction period" ));
		assert( DEBUG_WARN );
		handleTimeOutOfBounds( timerInfo );
		return( FALSE );
		}
	timerInfo->endTime = currentTime + timerInfo->timeRemaining;
	if( timerInfo->endTime < currentTime || \
		timerInfo->endTime < currentTime + max( timerInfo->timeRemaining,
												timerInfo->origTimeout ) )
		{
		/* There's a problem with the time calculations, handle the overflow
		   condition and tell the caller not to try anything further */
		handleTimeOutOfBounds( timerInfo );
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setMonoTimer( OUT_PTR MONOTIMER_INFO *timerInfo, 
				  IN_INT_Z const int duration )
	{
	const time_t currentTime = getTime( GETTIME_NOFAIL );
	BOOLEAN initOK;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );
	
	REQUIRES( isIntegerRange( duration ) );

	memset( timerInfo, 0, sizeof( MONOTIMER_INFO ) );
	if( currentTime >= ( MAX_INTLENGTH_TIME - duration ) )
		{
		DEBUG_DIAG(( "Invalid monoTimer time period" ));
		assert( DEBUG_WARN );
		handleTimeOutOfBounds( timerInfo );
		return( CRYPT_OK );
		}
	timerInfo->endTime = currentTime + duration;
	timerInfo->timeRemaining = timerInfo->origTimeout = duration;
	if( getTime( GETTIME_NONE ) <= MIN_TIME_VALUE )
		{
		/* There's no usable system time available, just run for 1000
		   iterations.  This isn't a major problem since timers are only
		   used to break out of loops that have other exit conditions,
		   so either one of those will be triggered forcing a loop exit
		   or the loop will iterate for quite some time but eventually
		   terminate anyway.
		   
		   There's an even more obscure condition under which we could run 
		   into problems and that's the case of a frozen clock that keeps 
		   returning the same valid but never-changing time.   This is 
		   obscure enough that we just rely on the other loop-termination
		   conditions for an exit */
		assert( DEBUG_WARN );
		timerInfo->badTimeCount = 1000;
		}
	else
		{
		/* Set the bad-system-time count variable to an invalid value to 
		   make sure that it's not used */
		timerInfo->badTimeCount = -1234;
		}
	initOK = correctMonoTimer( timerInfo, currentTime );
	ENSURES( initOK );

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void extendMonoTimer( INOUT_PTR MONOTIMER_INFO *timerInfo, 
					  IN_INT const int duration )
	{
	const time_t currentTime = getTime( GETTIME_NOFAIL );

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );
	
	REQUIRES_V( isIntegerRange( duration ) );

	/* Correct the timer for clock skew if required */
	if( !correctMonoTimer( timerInfo, currentTime ) )
		return;

	/* Extend the monotonic timer's timeout interval to allow for further
	   data to be processed */
	if( timerInfo->origTimeout >= ( MAX_INTLENGTH_TIME - duration ) || \
		timerInfo->endTime >= ( MAX_INTLENGTH_TIME - duration ) || \
		timerInfo->endTime < currentTime )
		{
		DEBUG_DIAG(( "Invalid monoTimer time period extension" ));
		assert( DEBUG_WARN );
		handleTimeOutOfBounds( timerInfo );
		return;
		}
	timerInfo->origTimeout += duration;
	timerInfo->endTime += duration;
	timerInfo->timeRemaining = timerInfo->endTime - currentTime;

	/* Re-correct the timer in case overflow occurred */
	( void ) correctMonoTimer( timerInfo, currentTime );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkMonoTimerExpiryImminent( INOUT_PTR MONOTIMER_INFO *timerInfo,
									  IN_INT_Z const int timeLeft )
	{
	const time_t currentTime = getTime( GETTIME_NOFAIL );
	time_t timeRemaining;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	REQUIRES_B( isIntegerRange( timeLeft ) );

	/* If the timeout has expired, don't try doing anything else */
	if( timerInfo->timeRemaining <= 0 )
		return( TRUE );

	/* Correct the monotonic timer for clock skew if required */
	if( !correctMonoTimer( timerInfo, currentTime ) )
		return( TRUE );

	/* If there's no reliable time available so that we've fallen back to
	   a simple counter, decrement that and exit */
	if( timerInfo->badTimeCount >= 0 )
		{
		if( timerInfo->badTimeCount <= 0 )
			return( TRUE );
		timerInfo->badTimeCount--;
		return( FALSE );
		}

	/* Check whether the time will expire within timeLeft seconds */
	if( timerInfo->endTime < currentTime )
		{
		DEBUG_DIAG(( "Invalid monoTimer expiry time period" ));
		assert( DEBUG_WARN );
		handleTimeOutOfBounds( timerInfo );
		return( TRUE );
		}
	timeRemaining = timerInfo->endTime - currentTime;
	if( timeRemaining > timerInfo->timeRemaining )
		{
		handleTimeOutOfBounds( timerInfo );
		timeRemaining = 0;
		}
	timerInfo->timeRemaining = timeRemaining;
	return( ( timerInfo->timeRemaining <= timeLeft ) ? TRUE : FALSE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkMonoTimerExpired( INOUT_PTR MONOTIMER_INFO *timerInfo )
	{
	return( checkMonoTimerExpiryImminent( timerInfo, 0 ) );
	}

/****************************************************************************
*																			*
*							Time Dithering Functions						*
*																			*
****************************************************************************/

/* Delay by small random amounts, used to both dither the results of online-
   visible crypto operations to make timing attacks harder and for failed 
   crypto operations to stall probing attacks alongside the dithering by 
   adding much longer delays.  In effect this creates the inverse of fuzzy 
   time/fuzzy I/O from Wei-Ming Hu's "Reducing Timing Channels with Fuzzy 
   Time", Journal of Computer Security, 1992, more usually implemented as 
   spread-spectrum clocking to deal with EMI, by keeping the clock constant 
   but fuzzing the execution time of what's being measured.

   We use this instead of trying to achieve perfect constant-time execution 
   in the code (although we try for that as well as much as possible) 
   because the combination of the wide range of architectures with different
   timing characteristics that cryptlib has to run across, combined with the
   neverending battle against compiler modification of the generated code
   (see the long comment about this in misc/safety.h), and the fact that 
   cryptlib can run with any number of different back-ends of which many 
   don't implement much in the way of timing countermeasures means that 
   there's no guarantee that any low-level approach will remain constant-
   time on a different architecture and/or across different compiler 
   versions and optimisation levels, or even exist at all (e.g. many PKCS 
   #11 devices).
   
   As with anything involving randomness, there's been a lot of smoke and 
   not much light generated over the use of random delays to address timing 
   attacks.  The generic answer is that it doesn't help so there's no point 
   in doing it and everyone should just write constant-time code, another 
   prime example of le mieux est l'ennemi du bien.

   If the arguments ever get beyond abstract theory (theoretical constant-
   time code is better than theoretical random delays), the argument given 
   is usually that we're measuring timing differences in us or ns while the 
   delay functions are typically in ms.  Another argument is that all an 
   attacker has to do is repeat the measurements in order to filter out the 
   delays.

   To give a concrete example, a sleep function with a ms granularity being 
   used with a 2GHz CPU means that there are 2M clock cycles between each 
   timer tick.  The sleep function doesn't guarantee to return after exactly 
   x ms but after at least x ms have elapsed which helps a bit, but we still 
   need a finer-grained delay, which insertCryptoDelay() further down 
   provides.

   A counterargument for the high-precision measurement claim is that if 
   you've got an attacker sitting on your local LAN segment making ns-scale 
   timing measurements on your crypto then you've got bigger things to worry 
   about than side-channel attacks (over more distant connections, you can 
   at best get tens to hundreds of us using thousands of measurements, see 
   e.g. "Opportunities and Limits of Remote Timing Attacks" by Crosby, Reid, 
   and Wallach, which also required multiple days of data-gathering 
   beforehand to characterise the network).  
   
   In addition in cryptlib's case since all operations go via the kernel, 
   you don't have direct (timing) access to the low-level crypto ops but 
   only get strongly dithered results at that level.  This actually makes 
   the effectiveness of the dithering countermeasures somewhat difficult to
   evaluate since the kernel already provides a good measure of dithering.

   As a result, while you can still use repeated measurements to eventually
   filter out the dithering, it's now made the attacker's job much, much 
   harder.  Since the failure-related dithering is essentially free (it's 
   only invoked if an operation fails), it makes sense to add the delay.  
   In addition, on top of the sleep delay, we add the fine-grained delay 
   mentioned earlier to dither exact timings.
   
   Another issue is how long to make the delay.  Obviously the longer the 
   better since it slows down attacks, however if we make it too long then 
   it can end up looking like a different problem, e.g. a networking issue 
   rather than a crypto defence, which will be a pain to diagnose for 
   users.  3s seems to be a good tradeoff between dithering operations and 
   slowing down an attacker while not adding an excessive delay that looks 
   like it's caused by something else.
   
   A final consideration is whether we should also add delays before 
   critical operations in order to make glitch attacks more difficult.  This 
   is more something that belongs in the boot firmware of embedded devices 
   likely to be subject to such attacks since, as a crypto library, we'll be 
   used long after the fixed-timing boot process is complete, making glitch 
   attacks difficult.  In addition the work involved in creating the random 
   delay will be quite visible in side-channel traces, pointing an attacker 
   at where the interesting stuff is going on */

/* Implement an extremely slow busy-wait loop via the world's worst hash
   function.  We use the slowest and most unpredictable data-manipulation
   instructions available, combined with endless data dependencies and 
   pipeline stalls.  Multiplies, while they often have a single-cycle 
   throughput, typically have a multiple-cycle latency, which we enforce 
   with data dependencies.  The magic instruction for poor performance 
   though is the divide, which is typically microcoded and with a huge, 
   data-dependent, latency */

#ifdef SYSTEM_64BIT
  #define CONST1	0x6A09E667BB67AE85	/* SHA2, h0 || h1 */
  #define CONST2	0x3C6EF372A54FF53A	/* SHA2, h2 || h3 */
  #define CONST3	0x510E527F9B05688C	/* SHA2, h4 || h5 */
  #define CONST4	0x1F83D9AB5BE0CD19	/* SHA2, h6 || h7 */
#else
  #define CONST1	0xCA62C1D6			/* SHA1, sqrt10 */
  #define CONST2	0x8F1BBCDC			/* SHA1, sqrt5 */
  #define CONST3	0x6ED9EBA1			/* SHA1, sqrt3 */
  #define CONST4	0x5A827999			/* SHA1, sqrt2 */
#endif /* 32- vs. 64-bit systems */

#if defined( __WIN64__ )
  typedef DWORD64			MACHINE_WORD;
#elif defined( __WIN32__ )
  typedef DWORD				MACHINE_WORD;
#else
  typedef unsigned long		MACHINE_WORD;
#endif /* System-specific machine word data types */

#ifdef _MSC_VER
  #ifdef SYSTEM_64BIT
	#define ROTL( x, r )	_rotl64( x, r )
  #else
	#define ROTL( x, r )	_rotl( x, r )
  #endif /* 32- vs. 64-bit systems */
#else
  /* Most compilers have rotate-recognisers, this is the form that will 
     produce a native rotate instruction */
  #define WORD_SIZE			( sizeof( MACHINE_WORD ) * 8 )
  #define ROTL( x, r )		( ( ( x ) << ( r ) ) | ( ( x ) >> ( WORD_SIZE - ( r ) ) ) )
#endif /* _MSC_VER */

static int merdeMerdeHash( const int value1, const int value2 )
	{
	MACHINE_WORD l = value1, r = value2;
	int fineDelay, i;

	/* Create the initial coarse-grained delay via the world's worst hash 
	   function, full of data dependencies and pipeline stalls */
	for( i = 0; i < value1; i++ )
		{
		/* Fill up both l and r with bits */
		l *= r + CONST1;
		r *= l + CONST2;

		/* Since we're about to divide by r, make sure that it's not zero, 
		   as well as adding a number of unpredictable branches to the code 
		   flow */
		while( !( r & 0x800 ) )
			r += CONST3;

		/* Perform a slow divide.  We actually apply it as a mod operation 
		   (still done via a divide instruction, only the remainder is 
		   what's preserved) since a divide would reduce l to a small 
		   integer value, and zero with 50% probability.  However we also 
		   have to be careful with the mod operation for the same reason as 
		   the problem with divides, at least half the time it'll be a 
		   no-op, so we shift it four bits to increase the chances of it 
		   doing something.  Finally, once we've done the divide, we refill 
		   l since the mod by a smaller amount has decreased its magnitude */
		l %= r >> 4;
		l += ROTL( r, 13 );

		/* As before, this time with r and l */
		while( !( l & 0x800 ) )
			l += CONST4;
		r %= l >> 4;
		r += ROTL( l, 13 );
		}

	/* Finish off with a fine-grained delay */
	fineDelay = ( int ) ( l & 0x7FFF );
	for( i = 0; i < fineDelay; i++ )
		{
		l += ROTL( r, 23 );
		r += ROTL( l, 23 );
		}

	return( ( r + l ) & 0x7FFF );
	}

/* Insert a small random delay to make timing attacks on crypto operations
   harder.  This is a bit of a pain because the delays follow crypto 
   operations that have been tuned to be as fast and efficient as possible,
   while what we're doing here is slowing them down again, however fast
   crypto typically won't get noticed while side-channel vulnerable crypto
   will.
   
   An alternative to trying to make the crypto constant-time is to bracket 
   the operation with clock ticks, so we wait for a clock tick to start the
   operation and wait for another clock tick to finish it.  This is 
   typically even worse than inserting a random delay because it inserts two 
   largeish delays instead, even if it's done via a sleep call rather than a 
   busy-wait
   
   Another option, getting increasingly esoteric, would be possible on a 
   very busy server by batching crypto operations, so that n crypto 
   operations are run back-to-back and the result only returned when the 
   final one has completed, however this again leads to long delays as well
   as being horribly complex to implement */

int insertCryptoDelay( void )
	{
	static int seed = 1;

	/* Insert a short delay.  Since getRandomInteger() returns a short-
	   integer value (which we make explicit here, although the operation
	   is redundant), we have to call the hash function twice to get a long 
	   enough delay.

	   The delay is chosen so that it adds about 1% to the execution time of
	   a 2Kbit private-key op.  This is actually 1/5 of the SD of the 
	   private-key op time, so there's plenty of dithering there anyway...

	   The first value is the iteration count, the second is a a seed value
	   that's fed back to the input to ensure that a compiler can't inline/
	   optimise away the expression if it detects that the result isn't 
	   being used */ 
	seed = merdeMerdeHash( getRandomInteger() % 32768, seed );
	return( merdeMerdeHash( getRandomInteger() % 32768, seed ) );
	}

/* Delay by a large amount by suspending the current thread for a preset 
   time.  The external form delayRandom() is called in response to generic
   failures in secure sessions rather than crypto failures.  Crypto failures 
   are handled via registerCryptoFailure() */

static void randomDelay( IN_RANGE( 0, 10 ) const int baseDelaySeconds, 
						 IN_RANGE( 100, 5000 ) const int maxDelayMS )
	{
	int delayTime = getRandomInteger();

	REQUIRES_V( baseDelaySeconds >= 0 && baseDelaySeconds <= 10 );
	ENSURES_V( maxDelayMS >= 100 && maxDelayMS <= 5000 );

	/* Use a delay from 0.01s to maxDelayMS.  getRandomInteger() can return 
	   zero for a shouldn't-occur error condition, this is converted into a 
	   small nonzero wait alongside an actual zero value */
	delayTime %= ( maxDelayMS + 1 );
	if( delayTime < 5 )
		delayTime = 5;
	ENSURES_V( delayTime >= 5 && delayTime <= 5000 );

	/* Add the base delay amount */
	delayTime += baseDelaySeconds * 1000;

	/* Wait for the given number of milliseconds */
	( void ) krnlWait( delayTime );
	}

int delayRandom( void )
	{
	/* When fuzzing, make sure that we don't insert delays once we bail out 
	   at the end of the fuzzed data */
	FUZZ_EXIT();

	randomDelay( 0, 3000 );
	return( insertCryptoDelay() );
	}

/* Respond to repeated crypto failures, an indication that someone is trying 
   to use us as an oracle.  This tracks how many failures have occurred 
   recently and inserts a delay proportional to the number of failures, 
   acting as a rate-limiting mechanism for attacker queries.  We keep a 
   single count across all crypto failure types to avoid allowing an 
   attacker to bypass the rate-limiting by spreading their queries across
   multiple mechanisms and protocols */ 

#ifdef USE_SESSIONS

int registerCryptoFailure( void )
	{
	static time_t intervalStartTime = CURRENT_TIME_VALUE;
	static int failures = 0;
	const time_t currentTime = getTime( GETTIME_NONE );
	int status;

	/* When fuzzing, make sure that we don't insert delays once we bail out 
	   at the end of the fuzzed data */
	FUZZ_EXIT();

	/* If there's no reliable time source available then there's not much 
	   that we can do apart from inserting a tradeoff delay that's long 
	   enough to slow down attacks but not long enough to DoS ourselves */
	if( currentTime <= MIN_TIME_VALUE )
		{
		randomDelay( 0, 500 );
		insertCryptoDelay();
		return( 0 );
		}

	/* Since the crypto failure state can be accessed by multiple threads, 
	   we need to wrap the accesses in a mutex */
	status = krnlEnterMutex( MUTEX_CRYPTODELAY );
	if( cryptStatusError( status ) )
		{
		/* As before, and exit with mutex not held */
		randomDelay( 0, 500 );
		insertCryptoDelay();
		return( 0 );
		}

	/* If there hasn't been a crypto failure within the last five minutes,
	   decay the failure count and reset the interval start time */
	if( currentTime >= intervalStartTime + ( 5 * 60 ) )
		{
		const int intervals = ( int ) \
						( ( currentTime - intervalStartTime ) / ( 5 * 60 ) );

		if( intervals < 20 )
			failures >>= intervals;
		else
			failures = 0;
		intervalStartTime = currentTime;
		}
	else
		{
		/* There have been multiple failures within a short time period, if
		   the current one is very recent reset the time window */
		if( currentTime <= intervalStartTime + ( 2 * 60 ) )
			intervalStartTime = currentTime;
		}

	/* Increment the failure count, capping the total at a reasonable 
	   value */ 
	if( failures < 50000 )
		failures++;

	krnlExitMutex( MUTEX_CRYPTODELAY );

	/* Insert a delay proportionate to the number of recent crypto failures.  
	   The threshold for the various delays is rather imprecise, we don't 
	   want to respond disproportionately to a small number of legitimate 
	   failures but do want to do so for an actual attack.  On the other 
	   hand the process is somewhat self-limiting in that once a response is
	   triggered the attack rate will be severely throttled unless the code 
	   is being run with a large number of threads, each of which can be 
	   parked in randomDelay() while the next thread is attacked */
	if( failures < 10 )
		randomDelay( 0, 500 );		/* 0..0.5s */
	else
	if( failures < 50 )
		randomDelay( 0, 1000 );		/* 0..1s */
	else
	if( failures < 100 )
		randomDelay( 1, 2000 );		/* 1..3s */
	else
	if( failures < 500 )
		randomDelay( 3, 2000 );		/* 3..5s */
	else
		randomDelay( 5, 5000 );		/* 5...10s */
	
	return( insertCryptoDelay() );
	}
#endif /* USE_SESSIONS */

/****************************************************************************
*																			*
*								Self-test Functions							*
*																			*
****************************************************************************/

/* Test code for the above functions */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

static void setTestTime( const time_t value )
	{
	TMR_SET( testTimeValue, MIN_TIME_VALUE + value );
	}

static void clearTestTime( void )
	{
	TMR_SET( testTimeValue, 0 );
	}

CHECK_RETVAL_BOOL \
BOOLEAN testIntTime( void )
	{
	MONOTIMER_INFO timerInfo;
	int status;

	/* Test basic timer functions */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 0 );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( !checkMonoTimerExpiryImminent( &timerInfo, 1 ) )
		return( FALSE );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		checkMonoTimerExpiryImminent( &timerInfo, 9 ) )
		return( FALSE );
	if( !checkMonoTimerExpiryImminent( &timerInfo, 10 ) )
		return( FALSE );

	/* Check timer period extension functionality */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 0 );
	if( cryptStatusError( status ) )
		return( FALSE );
	extendMonoTimer( &timerInfo, 10 );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		checkMonoTimerExpiryImminent( &timerInfo, 9 ) || \
		!checkMonoTimerExpiryImminent( &timerInfo, 10 ) )
		return( FALSE );

	/* Check clock going forwards normally */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	setTestTime( 1009 );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		!checkMonoTimerExpiryImminent( &timerInfo, 1 ) )
		return( FALSE );

	/* Check clock going backwards.  This recovers by correcting to allow 
	   the original timeout */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	setTestTime( 999 );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		checkMonoTimerExpiryImminent( &timerInfo, 9 ) || \
		!checkMonoTimerExpiryImminent( &timerInfo, 10 ) )
		return( FALSE );

	/* Check clock going forwards too far.  This recovers from a time jump 
	   of > 30 minutes by correcting to allow the original timeout period on 
	   the assumption that the problem is with the time source rather than 
	   that we've waited for over half an hour for a network packet to 
	   arrive */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	setTestTime( 1000 + ( 45 * 60 ) );
	if( checkMonoTimerExpiryImminent( &timerInfo, 0 ) || \
		checkMonoTimerExpiryImminent( &timerInfo, 9 ) || \
		!checkMonoTimerExpiryImminent( &timerInfo, 10 ) )
		return( FALSE );

	/* Check fallback operation if the system time is broken */
	setTestTime( 1000 );
	status = setMonoTimer( &timerInfo, 10 );
	if( cryptStatusError( status ) )
		return( FALSE );
	timerInfo.badTimeCount = 5;	/* Force fallback operation */
	if( checkMonoTimerExpired( &timerInfo ) || \
		checkMonoTimerExpired( &timerInfo ) || \
		checkMonoTimerExpired( &timerInfo ) || \
		checkMonoTimerExpired( &timerInfo ) || \
		checkMonoTimerExpired( &timerInfo ) || \
		!checkMonoTimerExpired( &timerInfo ) )
		return( FALSE );

	clearTestTime();
	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
