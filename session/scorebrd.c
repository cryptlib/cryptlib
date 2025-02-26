/****************************************************************************
*																			*
*							cryptlib Session Scoreboard						*
*						Copyright Peter Gutmann 1998-2016					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "scorebrd.h"
  #include "scorebrd_int.h"
#else
  #include "crypt.h"
  #include "session/scorebrd.h"
  #include "session/scorebrd_int.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

/* Sanity-check the scoreboard state */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheckScoreboard( const SCOREBOARD_INFO *scoreboardInfo )
	{
	assert( isReadPtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );

	/* Make sure that the general state is in order */
	if( scoreboardInfo->lastEntry < 0 || \
		scoreboardInfo->lastEntry > SCOREBOARD_ENTRIES )
		{
		DEBUG_PUTS(( "sanityCheckScoreboard: Scoreboard last entry" ));
		return( FALSE );
		}
	if( scoreboardInfo->uniqueID < 0 )
		{
		DEBUG_PUTS(( "sanityCheckScoreboard: Scoreboard unique ID" ));
		return( FALSE );
		}

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheckScoreboardEntry( const SCOREBOARD_ENTRY *scoreboardEntry )
	{
	assert( isReadPtr( scoreboardEntry, sizeof( SCOREBOARD_ENTRY ) ) );

	/* Check lookup information */
	if( scoreboardEntry->sessionIDlength <= 0 || \
		scoreboardEntry->sessionIDlength > SCOREBOARD_KEY_SIZE )
		{
		DEBUG_PUTS(( "sanityCheckScoreboardEntry: Lookup information" ));
		return( FALSE );
		}

	/* Check scoreboard data */
	if( scoreboardEntry->dataLength < 1 || \
		scoreboardEntry->dataLength > SCOREBOARD_DATA_SIZE )
		{
		DEBUG_PUTS(( "sanityCheckScoreboardEntry: Data size" ));
		return( FALSE );
		}
	if( checksumData( scoreboardEntry->data, 
					  scoreboardEntry->dataLength ) != \
										scoreboardEntry->dataChecksum )
		{
		DEBUG_PUTS(( "sanityCheckScoreboardEntry: Data" ));
		return( FALSE );
		}

	/* Check miscellaneous information */
	if( ( scoreboardEntry->isServerData != TRUE && \
		  scoreboardEntry->isServerData != FALSE ) || \
		scoreboardEntry->uniqueID < 0 || \
		scoreboardEntry->uniqueID > INT_MAX - 10 )
		{
		DEBUG_PUTS(( "sanityCheckScoreboardEntry: Miscellaneous information" ));
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Check whether a scoreboard entry is empty.  This checks a number of 
   values in order to deal with false positives caused by corruption of a
   single value, if this check declares the value non-empty then it has to
   pass a sanityCheckScoreboardEntry() check immediately afterwards */

static BOOLEAN isEmptyEntry( const SCOREBOARD_ENTRY *scoreboardEntryPtr )
	{
	assert( isReadPtr( scoreboardEntryPtr, sizeof( SCOREBOARD_ENTRY ) ) );
	
	if( scoreboardEntryPtr->sessionCheckValue == 0 && \
		scoreboardEntryPtr->fqdnCheckValue == 0 && \
		scoreboardEntryPtr->sessionIDlength == 0 && \
		scoreboardEntryPtr->dataLength == 0 && \
		scoreboardEntryPtr->timeStamp <= MIN_TIME_VALUE )
		return( TRUE );
	
	return( FALSE );
	}

/* Add a scoreboard entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 8 ) ) \
static int addEntryData( INOUT_PTR SCOREBOARD_ENTRY *scoreboardEntryPtr, 
						 IN_INT_Z const int keyCheckValue,
						 IN_BUFFER( keyLength ) const void *key, 
						 IN_LENGTH_SHORT_MIN( SCOREBOARD_KEY_MIN ) \
							const int keyLength, 
						 IN_INT_Z const int altKeyCheckValue,
						 IN_BUFFER_OPT( altKeyLength ) const void *altKey, 
						 IN_LENGTH_SHORT_Z const int altKeyLength, 
						 const SCOREBOARD_ENTRY_INFO *scoreboardEntryInfo,
						 const time_t currentTime )
	{
	int status;

	assert( isWritePtr( scoreboardEntryPtr, sizeof( SCOREBOARD_ENTRY ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );
	assert( ( altKey == NULL && altKeyLength == 0 ) || \
			isReadPtrDynamic( altKey, altKeyLength ) );
	assert( isReadPtr( scoreboardEntryInfo, sizeof( SCOREBOARD_ENTRY_INFO ) ) );

	REQUIRES( keyCheckValue >= 0 );
	REQUIRES( isShortIntegerRangeMin( keyLength, SCOREBOARD_KEY_MIN ) );
	REQUIRES( ( altKey == NULL && altKeyLength == 0 && \
				altKeyCheckValue == 0 ) || \
			  ( altKey != NULL && \
				isShortIntegerRangeMin( altKeyLength, \
										SCOREBOARD_KEY_MIN ) && \
				altKeyCheckValue >= 0 ) );
	REQUIRES( currentTime > MIN_TIME_VALUE );

	/* Clear the existing data in the entry */
	zeroise( scoreboardEntryPtr, sizeof( SCOREBOARD_ENTRY ) );

	/* Copy across the key and value (Amicitiae nostrae memoriam spero 
	   sempiternam fore - Cicero) */
	scoreboardEntryPtr->sessionCheckValue = keyCheckValue;
	hashData( scoreboardEntryPtr->sessionHash, HASH_DATA_SIZE, 
			  key, keyLength );
	if( altKey != NULL )
		{
		scoreboardEntryPtr->fqdnCheckValue = altKeyCheckValue;
		hashData( scoreboardEntryPtr->fqdnHash, HASH_DATA_SIZE, 
				  altKey, altKeyLength );
		}
	status = attributeCopyParams( scoreboardEntryPtr->sessionID, 
								  SCOREBOARD_KEY_SIZE, 
								  &scoreboardEntryPtr->sessionIDlength,
								  key, keyLength );
	ENSURES( cryptStatusOK( status ) );
	status = attributeCopyParams( scoreboardEntryPtr->data, 
								  SCOREBOARD_DATA_SIZE, 
								  &scoreboardEntryPtr->dataLength,
								  scoreboardEntryInfo->data, 
								  scoreboardEntryInfo->dataSize );
	ENSURES( cryptStatusOK( status ) );
	scoreboardEntryPtr->dataChecksum = \
				checksumData( scoreboardEntryPtr->data, 
							  scoreboardEntryPtr->dataLength );
	scoreboardEntryPtr->metaData = scoreboardEntryInfo->metaData;
	scoreboardEntryPtr->isServerData = ( altKey == NULL ) ? TRUE : FALSE;
	scoreboardEntryPtr->timeStamp = currentTime;

	ENSURES( sanityCheckScoreboardEntry( scoreboardEntryPtr ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Scoreboard Management Functions						*
*																			*
****************************************************************************/

/* Find an entry, returning its position in the scoreboard.  This function 
   currently uses a straightforward linear search with entries clustered 
   towards the start of the scoreboard.  Although this may seem somewhat 
   suboptimal, since cryptlib isn't running as a high-performance web server 
   the scoreboard will rarely contain more than a handful of entries (if 
   any).  In any case a quick scan through a small number of integers is 
   probably still faster than the complex in-memory database lookup schemes 
   used by many servers, and is also required to handle things like 
   scoreboard LRU management */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 6 ) ) \
static int findEntry( INOUT_PTR SCOREBOARD_INFO *scoreboardInfo,
					  IN_ENUM( SCOREBOARD_KEY ) \
							const SCOREBOARD_KEY_TYPE keyType,
					  IN_BUFFER( keyLength ) const void *key, 
					  IN_LENGTH_SHORT_MIN( 2 ) const int keyLength, 
					  const time_t currentTime, 
					  OUT_INT_SHORT_Z int *position )
	{
	BYTE hashValue[ HASH_DATA_SIZE + 8 ];
	const BOOLEAN keyIsSessionID = \
		( keyType == SCOREBOARD_KEY_SESSIONID_CLI || \
		  keyType == SCOREBOARD_KEY_SESSIONID_SVR ) ? TRUE : FALSE;
	const BOOLEAN isServerMatch = \
		( keyType == SCOREBOARD_KEY_SESSIONID_SVR ) ? TRUE : FALSE;
	BOOLEAN dataHashed = FALSE;
	time_t oldestTime = currentTime;
	const int checkValue = checksumData( key, keyLength );
	int nextFreeEntry = CRYPT_ERROR, lastUsedEntry = 0, oldestEntry = 0;
	LOOP_INDEX i;
	int matchPosition = CRYPT_ERROR;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );
	assert( isWritePtr( position, sizeof( int ) ) );

	REQUIRES( isEnumRange( keyType, SCOREBOARD_KEY ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, SCOREBOARD_KEY_MIN ) );
	REQUIRES( currentTime > MIN_TIME_VALUE );

	/* Clear return value */
	*position = CRYPT_ERROR;

	/* Scan the scoreboard expiring old entries, looking for a match 
	   (indicated by matchPosition), and keeping a record of the oldest 
	   entry (recorded by oldestEntry) in case we need to expire an entry to
	   make room for a new one */
	LOOP_EXT( i = 0, i < scoreboardInfo->lastEntry, i++, 
			  SCOREBOARD_ENTRIES + 1 )
		{
		SCOREBOARD_ENTRY *scoreboardEntryPtr;

		ENSURES( LOOP_INVARIANT_EXT( i, 0, 
									 scoreboardInfo->lastEntry - 1,
									 SCOREBOARD_ENTRIES + 1 ) );

		/* If this entry has expired, delete it */
		scoreboardEntryPtr = &scoreboardInfo->index[ i ];
		if( scoreboardEntryPtr->timeStamp + SCOREBOARD_TIMEOUT < currentTime )
			zeroise( scoreboardEntryPtr, sizeof( SCOREBOARD_ENTRY ) );

		/* Check for a free entry and the oldest non-free entry.  We could
		   perform an early-out once we find a free entry but this would
		   prevent any following expired entries from being deleted */
		if( isEmptyEntry( scoreboardEntryPtr ) )
			{
			/* We've found a free entry, remember it for future use if
			   required and continue */
			if( nextFreeEntry == CRYPT_ERROR )
				nextFreeEntry = i;
			continue;
			}
		REQUIRES( sanityCheckScoreboardEntry( scoreboardEntryPtr ) );
		lastUsedEntry = i;
		if( scoreboardEntryPtr->timeStamp < oldestTime )
			{
			/* We've found an older entry than the current oldest entry,
			   remember it */
			oldestTime = scoreboardEntryPtr->timeStamp;
			oldestEntry = i;
			}

		/* If we've already found a match then we're just scanning for LRU
		   purposes and we don't need to go any further */
		if( matchPosition != CRYPT_ERROR )
			continue;

		/* Make sure that this entry is appropriate for the match type that
		   we're performing */
		if( scoreboardEntryPtr->isServerData != isServerMatch )
			continue;

		/* Perform a quick check using a checksum of the name to weed out
		   most entries */
		if( ( keyIsSessionID && \
			  scoreboardEntryPtr->sessionCheckValue == checkValue ) || \
			( !keyIsSessionID && \
			  scoreboardEntryPtr->fqdnCheckValue == checkValue ) )
			{
			void *hashPtr = keyIsSessionID ? \
								scoreboardEntryPtr->sessionHash : \
								scoreboardEntryPtr->fqdnHash;

			if( !dataHashed )
				{
				hashData( hashValue, HASH_DATA_SIZE, key, keyLength );
				dataHashed = TRUE;
				}
			if( !memcmp( hashPtr, hashValue, HASH_DATA_SIZE ) )
				{
				/* Remember the match position.  We can't immediately exit 
				   at this point because we still need to look for the last 
				   used entry and potentually shrink the scoreboard-used 
				   size */
				matchPosition = i;
				}
			}
		}
	ENSURES( i < FAILSAFE_ITERATIONS_MAX );

	/* If the total number of entries has shrunk due to old entries expiring,
	   reduce the overall scoreboard-used size */
	if( lastUsedEntry + 1 < scoreboardInfo->lastEntry )
		scoreboardInfo->lastEntry = lastUsedEntry + 1;

	/* If we've found a match, we're done */
	if( matchPosition >= 0 )
		{
		*position = matchPosition;
		return( CRYPT_OK );
		}

	/* The entry wasn't found, return the location where we can add a new 
	   entry */
	if( nextFreeEntry >= 0 )
		{
		/* We've found a freed-up existing position (which will be before 
		   any remaining free entries), add the new entry there */
		*position = nextFreeEntry;
		}
	else
		{
		/* If there are still free positions in the scoreboard, use the next
		   available one */
		if( scoreboardInfo->lastEntry < SCOREBOARD_ENTRIES )
			*position = scoreboardInfo->lastEntry;
		else
			{
			/* There are no free positions, overwrite the oldest entry */
			*position = oldestEntry;
			}
		}
	ENSURES( *position >= 0 && *position < SCOREBOARD_ENTRIES );

	/* Let the caller know that this is an indication of a free position 
	   rather than a match */
	return( OK_SPECIAL );
	}

/* Add an entry to the scoreboard.  The strategy for updating entries can 
   get quite complicated.  In the following the server-side cases are 
   denoted with -S and the client-side cases with -C:

	  Case	|	key		|	altKey	|	Action
			| (sessID)	|  (FQDN)	|
	--------+-----------+-----------+---------------------------------------
	  1-S	|  no match	|	absent	| Add entry
	--------+-----------+-----------+---------------------------------------
	  2-S	|	match	|	absent	| Add-special (see below)
	--------+-----------+-----------+---------------------------------------
	  3-C	|  no match	|  no match	| Add entry
	--------+-----------+-----------+---------------------------------------
	  4-C	|  no match	|	match	| Replace existing match.  This situation
			|			|			| has presumably occurred because we've
			|			|			| re-connected to a server with a full
			|			|			| handshake and were allocated a new 
			|			|			| session ID.
	--------+-----------+-----------+---------------------------------------
	  5-C	|	match	|  no match	| Clear entry.  This situation shouldn't
			|			|			| occur, it means that we've somehow 
			|			|			| acquired a session ID with a different
			|			|			| server.
	--------+-----------+-----------+---------------------------------------
	  6-C	|	match	|	match	| Add-special (see below)
	--------+-----------+-----------+---------------------------------------
	  7-C	|  match-1	|  match-2	| Match, but at different locations, 
			|			|			| clear both entries (variant of case
			|			|			| 5-C).

   Add-special is a conditional add, if the data value that we're trying to 
   add corresponds to the existing one (and the search keys matched as well)
   then it's an update of an existing entry and we update its timestamp.  If
   the data value doesn't match (but the search keys did) then something 
   funny is going on and we clear the existing entry.  If we simply ignore 
   the add attempt then it'll appear to the caller that we've added the new 
   value when in fact we've retained the existing one.  If on the other hand 
   we overwrite the old value with the new one then it'll allow an attacker 
   to replace existing scoreboard contents with attacker-controlled ones.

   In theory not every case listed above can occur because information is 
   only added for new (non-resumed) sessions, so for example case 2-S 
   wouldn't occur because if there's already a match for the session ID then 
   it'd result in a resumed session and so the information wouldn't be added 
   a second time.  However there are situations in which these oddball cases 
   can occur, in general not for servers (even with two threads racing each 
   other for scoreboard access) because it'd require that the cryptlib 
   server allocate the same session ID twice, but it can occur for clients 
   if (case 5-C) two servers allocate us the same session ID or (case 4-C) 
   two threads simultaneously connect to the same server, with FQDNs the 
   same but session IDs different */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 6, 7 ) ) \
static int addEntry( INOUT_PTR SCOREBOARD_INFO *scoreboardInfo, 
					 IN_BUFFER( keyLength ) const void *key, 
					 IN_LENGTH_SHORT_MIN( SCOREBOARD_KEY_MIN ) \
						const int keyLength, 
					 IN_BUFFER_OPT( altKeyLength ) const void *altKey, 
					 IN_LENGTH_SHORT_Z const int altKeyLength, 
					 const SCOREBOARD_ENTRY_INFO *scoreboardEntryInfo,
					 OUT_INT_Z int *uniqueID )
	{
	SCOREBOARD_ENTRY *scoreboardIndex, *scoreboardEntryPtr = NULL;
	const time_t currentTime = getTime( GETTIME_NONE );
	const BOOLEAN isClient = ( altKey != NULL ) ? TRUE : FALSE;
	int checkValue, altCheckValue = 0, altPosition DUMMY_INIT;
	int position, altStatus = CRYPT_ERROR, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );
	assert( ( altKey == NULL && altKeyLength == 0 ) || \
			isReadPtrDynamic( altKey, altKeyLength ) );
	assert( isReadPtr( scoreboardEntryInfo, 
					   sizeof( SCOREBOARD_ENTRY_INFO ) ) );
	assert( isWritePtr( uniqueID, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( keyLength, SCOREBOARD_KEY_MIN ) );
	REQUIRES( ( altKey == NULL && altKeyLength == 0 ) || \
			  ( altKey != NULL && \
				isShortIntegerRangeMin( altKeyLength, \
										SCOREBOARD_KEY_MIN ) ) );

	/* Clear return value */
	*uniqueID = CRYPT_ERROR;

	/* If there's something wrong with the time then we can't perform (time-
	   based) scoreboard management */
	if( currentTime <= MIN_TIME_VALUE )
		return( CRYPT_ERROR_NOTFOUND );

	status = checkValue = checksumData( key, keyLength );
	if( cryptStatusError( status ) )
		return( status );
	
	/* Try and find this entry in the scoreboard */
	status = findEntry( scoreboardInfo, isClient ? \
							SCOREBOARD_KEY_SESSIONID_CLI : \
							SCOREBOARD_KEY_SESSIONID_SVR, 
						key, keyLength, currentTime, &position );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );
	ENSURES( position >= 0 && position < SCOREBOARD_ENTRIES );
	if( altKey != NULL )
		{
		altCheckValue = checksumData( altKey, altKeyLength );
		if( cryptStatusError( altCheckValue ) )
			return( altCheckValue );
		altStatus = findEntry( scoreboardInfo, SCOREBOARD_KEY_FQDN, 
							   altKey, altKeyLength, currentTime, 
							   &altPosition );
		if( cryptStatusError( altStatus ) && altStatus != OK_SPECIAL )
			return( altStatus );
		ENSURES( altPosition >= 0 && \
				 altPosition < SCOREBOARD_ENTRIES );
		}
	ENSURES( cryptStatusOK( status ) || status == OK_SPECIAL );
	ENSURES( altKey == NULL || \
			 cryptStatusOK( altStatus ) || altStatus == OK_SPECIAL );
	scoreboardIndex = scoreboardInfo->index;

	/* We've done the match-checking, now we have to act on the results.  
	   The different result-value settings and corresponding actions are:

		  Case	|		sessID		|		FQDN		| Action
		--------+-------------------+-------------------+-----------------
			1	|  s = MT, pos = x	|		!altK		| Add at x
		--------+-------------------+-------------------+-----------------
			2	|  s = OK, pos = x	|		!altK		| Add-special at x
		--------+-------------------+-------------------+-----------------
			3	|  s = MT, pos = x	| aS = MT, aPos = x	| Add at x
		--------+-------------------+-------------------+-----------------
			4	|  s = MT, pos = x	| aS = OK, aPos = y	| Replace at y
		--------+-------------------+-------------------+-----------------
			5	|  s = OK, pos = x	| aS = MT, aPos = y	| Clear at x
		--------+-------------------+-------------------+-----------------
			6	|  s = OK, pos = x	| aS = OK, aPos = x	| Add-special at x
		--------+-------------------+-------------------+-----------------
			7	|  s = OK, pos = x	| aS = OK, aPos = y	| Clear at x and y */
	if( cryptStatusOK( status ) )
		{
		/* We matched on the main key (session ID), handle cases 2-S, 5-C, 
		   6-C and 7-C */
		if( altKey != NULL && position != altPosition )
			{
			/* Cases 5-C + 7-C, clear */
			zeroise( &scoreboardIndex[ position ], 
					 sizeof( SCOREBOARD_ENTRY ) );
			return( CRYPT_ERROR_NOTFOUND );
			}

		/* Cases 2-S + 6-C, add-special */
		ENSURES( altKey == NULL || ( cryptStatusOK( altStatus ) && \
									 position == altPosition ) );
		scoreboardEntryPtr = &scoreboardIndex[ position ];
		REQUIRES( sanityCheckScoreboardEntry( scoreboardEntryPtr ) );
		if( scoreboardEntryPtr->dataLength != scoreboardEntryInfo->dataSize || \
			memcmp( scoreboardEntryPtr->data, scoreboardEntryInfo->data, 
					scoreboardEntryInfo->dataSize ) )
			{
			/* The search keys match but the data doesn't, something funny 
			   is going on */
			zeroise( &scoreboardIndex[ position ], 
					 sizeof( SCOREBOARD_ENTRY ) );
			assert( DEBUG_WARN );
			return( CRYPT_ERROR_NOTFOUND );
			}
		scoreboardEntryPtr->timeStamp = currentTime;

		return( CRYPT_OK );
		}
	ENSURES( status == OK_SPECIAL );

	/* We didn't match on the main key (session ID), check for a match on 
	   the alt.key (FQDN) */
	if( cryptStatusOK( altStatus ) )
		{
		/* Case 4-C, add at location 'altPosition' */
		ENSURES( position != altPosition );
		scoreboardEntryPtr = &scoreboardIndex[ altPosition ];
		}
	else
		{
		/* Cases 1-S + 3-C, add at location 'position' */
		ENSURES( altKey == NULL || \
				 ( altStatus == OK_SPECIAL && position == altPosition ) )
		scoreboardEntryPtr = &scoreboardIndex[ position ];
		}

	/* It's either an empty entry being added or an existing entry being 
	   updated */
	REQUIRES( isEmptyEntry( scoreboardEntryPtr ) || \
			  sanityCheckScoreboardEntry( scoreboardEntryPtr ) );

	/* Add the data to the new scoreboard entry position */
	status = addEntryData( scoreboardEntryPtr, checkValue, key, keyLength, 
						   altCheckValue, altKey, altKeyLength, 
						   scoreboardEntryInfo, currentTime );
	if( cryptStatusError( status ) )
		{
		zeroise( scoreboardEntryPtr, sizeof( SCOREBOARD_ENTRY ) );
		return( status );
		}
	if( scoreboardInfo->uniqueID >= MAX_INTLENGTH - 100 )
		{
		/* If we're about to wrap, reset the uniqueID value to the initial 
		   value.  This can happen on 16-bit systems */
		scoreboardInfo->uniqueID = 0;
		}
	*uniqueID = scoreboardEntryPtr->uniqueID = \
				scoreboardInfo->uniqueID++;

	/* If we've used a new entry, update the position-used index */
	if( position >= scoreboardInfo->lastEntry )
		scoreboardInfo->lastEntry = position + 1;

	return( CRYPT_OK );
	}

/* Look up data in the scoreboard */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5, 6 ) ) \
static int lookupScoreboard( INOUT_PTR SCOREBOARD_INFO *scoreboardInfo,
							 IN_ENUM( SCOREBOARD_KEY ) \
								const SCOREBOARD_KEY_TYPE keyType,
							 IN_BUFFER( keyLength ) const void *key, 
							 IN_LENGTH_SHORT_MIN( 8 ) const int keyLength, 
						     OUT_PTR SCOREBOARD_ENTRY_INFO *scoreboardEntryInfo,
							 OUT_INT_Z int *uniqueID )
	{
	SCOREBOARD_ENTRY *scoreboardEntryPtr;
	const time_t currentTime = getTime( GETTIME_NONE );
	int position, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );
	assert( isWritePtr( scoreboardEntryInfo, 
						sizeof( SCOREBOARD_ENTRY_INFO ) ) );
	assert( isWritePtr( uniqueID, sizeof( int ) ) );

	REQUIRES( isEnumRange( keyType, SCOREBOARD_KEY ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, SCOREBOARD_KEY_MIN ) );
	REQUIRES( sanityCheckScoreboard( scoreboardInfo ) );

	/* Clear return values */
	memset( scoreboardEntryInfo, 0, sizeof( SCOREBOARD_ENTRY_INFO ) );
	*uniqueID = CRYPT_ERROR;

	/* If there's something wrong with the time then we can't perform (time-
	   based) scoreboard management */
	if( currentTime <= MIN_TIME_VALUE )
		return( CRYPT_ERROR_NOTFOUND );

	/* Try and find this entry in the scoreboard */
	status = findEntry( scoreboardInfo, keyType, key, keyLength, 
						currentTime, &position );
	if( cryptStatusError( status ) )
		{
		/* An OK_SPECIAL status means that the search found an unused entry 
		   position but not a matching entry (this is used by addEntry()), 
		   anything else is an error */
		return( ( status == OK_SPECIAL ) ? CRYPT_ERROR_NOTFOUND : status );
		}
	ENSURES( position >= 0 && position < SCOREBOARD_ENTRIES );
	scoreboardEntryPtr = &scoreboardInfo->index[ position ];
	REQUIRES( sanityCheckScoreboardEntry( scoreboardEntryPtr ) );

	/* We've found a match, return a pointer to the data (which avoids 
	   copying it out of secure memory) and the unique ID for it */
	scoreboardEntryInfo->key = scoreboardEntryPtr->sessionID;
	scoreboardEntryInfo->keySize = scoreboardEntryPtr->sessionIDlength;
	scoreboardEntryInfo->data = scoreboardEntryPtr->data;
	scoreboardEntryInfo->dataSize = scoreboardEntryPtr->dataLength;
	scoreboardEntryInfo->metaData = scoreboardEntryPtr->metaData;
	*uniqueID = scoreboardEntryPtr->uniqueID;

	/* Update the entry's last-access date */
	scoreboardEntryPtr->timeStamp = currentTime;

	ENSURES( sanityCheckScoreboard( scoreboardInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Scoreboard Access Functions						*
*																			*
****************************************************************************/

/* Add and delete entries to/from the scoreboard.  These are just wrappers
   for the local scoreboard-access function, for use by external code */

CHECK_RETVAL_RANGE( 0, MAX_INTLENGTH ) STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int lookupScoreboardEntry( INOUT_PTR TYPECAST( SCOREBOARD_INFO * ) \
								struct SC *scoreboardInfoPtr,
						   IN_ENUM( SCOREBOARD_KEY ) \
								const SCOREBOARD_KEY_TYPE keyType,
						   IN_BUFFER( keyLength ) const void *key, 
						   IN_LENGTH_SHORT_MIN( 2 ) const int keyLength, 
						   OUT_PTR \
								SCOREBOARD_ENTRY_INFO *scoreboardEntryInfo )
	{
	SCOREBOARD_INFO *scoreboardInfo = scoreboardInfoPtr;
	int uniqueID, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );
	assert( isWritePtr( scoreboardEntryInfo, 
						sizeof( SCOREBOARD_ENTRY_INFO ) ) );

	REQUIRES( sanityCheckScoreboard( scoreboardInfo ) );
	REQUIRES( isEnumRange( keyType, SCOREBOARD_KEY ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, SCOREBOARD_KEY_MIN ) );

	/* Clear return values */
	memset( scoreboardEntryInfo, 0, sizeof( SCOREBOARD_ENTRY_INFO ) );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );
	status = lookupScoreboard( scoreboardInfo, keyType, key, keyLength, 
							   scoreboardEntryInfo, &uniqueID );
	krnlExitMutex( MUTEX_SCOREBOARD );
	return( cryptStatusError( status ) ? status : uniqueID );
	}

CHECK_RETVAL_RANGE( 0, MAX_INTLENGTH - 1 ) STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int addScoreboardEntry( INOUT_PTR struct SC *scoreboardInfoPtr,
						IN_BUFFER( keyLength ) const void *key, 
						IN_LENGTH_SHORT_MIN( SCOREBOARD_KEY_MIN ) \
							const int keyLength, 
						const SCOREBOARD_ENTRY_INFO *scoreboardEntryInfo )
	{
	SCOREBOARD_INFO *scoreboardInfo = scoreboardInfoPtr;
	int uniqueID, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );
	assert( isReadPtr( scoreboardEntryInfo, sizeof( SCOREBOARD_ENTRY_INFO ) ) );

	REQUIRES( sanityCheckScoreboard( scoreboardInfo ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, SCOREBOARD_KEY_MIN ) );

	/* Add the entry to the scoreboard */
	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );
	status = addEntry( scoreboardInfo, key, keyLength, NULL, 0,
					   scoreboardEntryInfo, &uniqueID );
	krnlExitMutex( MUTEX_SCOREBOARD );

	ENSURES( sanityCheckScoreboard( scoreboardInfo ) );

	return( cryptStatusError( status ) ? status : uniqueID );
	}

CHECK_RETVAL_RANGE( 0, MAX_INTLENGTH - 1 ) STDC_NONNULL_ARG( ( 1, 2, 4, 6 ) ) \
int addScoreboardEntryEx( INOUT_PTR struct SC *scoreboardInfoPtr,
						  IN_BUFFER( keyLength ) const void *key, 
						  IN_LENGTH_SHORT_MIN( SCOREBOARD_KEY_MIN ) \
								const int keyLength, 
						  IN_BUFFER( keyLength ) const void *altKey, 
						  IN_LENGTH_SHORT_MIN( 2 ) const int altKeyLength, 
						  const SCOREBOARD_ENTRY_INFO *scoreboardEntryInfo )
	{
	SCOREBOARD_INFO *scoreboardInfo = scoreboardInfoPtr;
	int uniqueID, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtrDynamic( key, keyLength ) );
	assert( isReadPtrDynamic( altKey, altKeyLength ) );
	assert( isReadPtr( scoreboardEntryInfo, sizeof( SCOREBOARD_ENTRY_INFO ) ) );

	REQUIRES( sanityCheckScoreboard( scoreboardInfo ) );
	REQUIRES( isShortIntegerRangeMin( keyLength, SCOREBOARD_KEY_MIN ) );
	REQUIRES( isShortIntegerRangeMin( altKeyLength, SCOREBOARD_KEY_MIN ) );

	/* Add the entry to the scoreboard */
	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );
	status = addEntry( scoreboardInfo, key, keyLength, altKey, 
					   altKeyLength, scoreboardEntryInfo, &uniqueID );
	krnlExitMutex( MUTEX_SCOREBOARD );

	ENSURES( sanityCheckScoreboard( scoreboardInfo ) );

	return( cryptStatusError( status ) ? status : uniqueID );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void deleteScoreboardEntry( INOUT_PTR TYPECAST( SCOREBOARD_INFO * ) \
								struct SC *scoreboardInfoPtr, 
							IN_INT_Z const int uniqueID )
	{
	SCOREBOARD_INFO *scoreboardInfo = scoreboardInfoPtr;
	LOOP_INDEX i;
	int lastUsedEntry = -1, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	
	REQUIRES_V( sanityCheckScoreboard( scoreboardInfo ) );
	REQUIRES_V( isIntegerRange( uniqueID ) );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return;

	/* Search the scoreboard for the entry with the given ID */
	LOOP_EXT( i = 0, i < scoreboardInfo->lastEntry, i++, 
			  SCOREBOARD_ENTRIES )
		{
		SCOREBOARD_ENTRY *scoreboardEntryPtr;

		ENSURES_V( LOOP_INVARIANT_EXT( i, 0, 
									   scoreboardInfo->lastEntry - 1,
									   SCOREBOARD_ENTRIES ) );

		/* If it's an empty entry (due to it having expired or being 
		   deleted), skip it and continue */
		scoreboardEntryPtr = &scoreboardInfo->index[ i ];
		if( isEmptyEntry( scoreboardEntryPtr ) )
			continue;

		REQUIRES_V( sanityCheckScoreboardEntry( scoreboardEntryPtr ) );

		/* If we've found the entry that we're after, clear it and exit */
		if( scoreboardEntryPtr->uniqueID == uniqueID )
			{
			zeroise( scoreboardEntryPtr, sizeof( SCOREBOARD_ENTRY ) );
			continue;
			}

		/* Remember how far we got */
		lastUsedEntry = i;
		}
	ENSURES_KRNLMUTEX_V( LOOP_BOUND_OK, MUTEX_SCOREBOARD );

	/* Since we may have deleted entries at the end of the scoreboard, we 
	   can reduce the lastEntry value to the highest remaining entry */
	scoreboardInfo->lastEntry = lastUsedEntry + 1;

	krnlExitMutex( MUTEX_SCOREBOARD );
	}

/****************************************************************************
*																			*
*							Scoreboard Init/Shutdown						*
*																			*
****************************************************************************/

/* Perform a self-test of the scoreboard functions */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN selfTest( INOUT_PTR SCOREBOARD_INFO *scoreboardInfo )
	{
	SCOREBOARD_ENTRY_INFO scoreboardEntryInfo;
	int uniqueID1, uniqueID2, foundUniqueID, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );

	/* Add two entries to the scoreboard */
	memset( &scoreboardEntryInfo, 0, sizeof( SCOREBOARD_ENTRY_INFO ) );
	scoreboardEntryInfo.data = "test value 1";
	scoreboardEntryInfo.dataSize = 12;
	status = uniqueID1 = \
		addScoreboardEntry( scoreboardInfo, "test key 1", 10,
							&scoreboardEntryInfo );
	if( cryptStatusError( status ) )
		return( FALSE );
	scoreboardEntryInfo.data = "test value 2";
	scoreboardEntryInfo.dataSize = 12;
	status = uniqueID2 = \
		addScoreboardEntry( scoreboardInfo, "test key 2", 10,
							&scoreboardEntryInfo );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Read them back and delete them */
	status = foundUniqueID = \
		lookupScoreboardEntry( scoreboardInfo, SCOREBOARD_KEY_SESSIONID_SVR, 
							   "test key 1", 10, &scoreboardEntryInfo );
	if( cryptStatusError( status ) )
		return( FALSE );
	if( foundUniqueID != uniqueID1 || \
		scoreboardEntryInfo.keySize != 10 || \
		memcmp( scoreboardEntryInfo.key, "test key 1", 10 ) || \
		scoreboardEntryInfo.dataSize != 12 || \
		memcmp( scoreboardEntryInfo.data, "test value 1", 12 ) )
		{
		return( FALSE );
		}
	deleteScoreboardEntry( scoreboardInfo, uniqueID1 );
	foundUniqueID = lookupScoreboardEntry( scoreboardInfo, 
							SCOREBOARD_KEY_SESSIONID_SVR, "test key 1", 10,
							&scoreboardEntryInfo );
	if( foundUniqueID != CRYPT_ERROR_NOTFOUND )
		return( FALSE );
	deleteScoreboardEntry( scoreboardInfo, uniqueID2 );
	if( scoreboardInfo->lastEntry != 0 || \
		scoreboardInfo->uniqueID != 2 )
		return( FALSE );

#ifndef NDEBUG
	{
	char dataString[ /*SCOREBOARD_KEY_MIN*/ 8 + 8 ];
	LOOP_INDEX i;

	/* SCOREBOARD_KEY_MIN is currently 32 bits / 4 bytes, but we need more than
	   4 bytes to store the hex-string unique key we're using for testing */
	static_assert( SCOREBOARD_KEY_MIN < 8, 
				   "SCOREBOARD_KEY_MIN size" ); 

	/* Verify that filling the scoreboard is handled correctly */
	memset( &scoreboardEntryInfo, 0, sizeof( SCOREBOARD_ENTRY_INFO ) );
	scoreboardEntryInfo.data = dataString;
	scoreboardEntryInfo.dataSize = 4;
	LOOP_LARGE( i = 0, i < SCOREBOARD_ENTRIES + 10, i++ )
		{
		memset( dataString, 0, /*SCOREBOARD_KEY_MIN*/ 8 );
		sprintf_s( dataString, /*SCOREBOARD_KEY_MIN*/ 8, "%04X", i );

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, SCOREBOARD_ENTRIES + 9 ) );

		status = \
			addScoreboardEntry( scoreboardInfo, dataString, 
								/*SCOREBOARD_KEY_MIN*/ 8, 
								&scoreboardEntryInfo );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	ENSURES( LOOP_BOUND_OK );
	if( scoreboardInfo->lastEntry != SCOREBOARD_ENTRIES || \
		scoreboardInfo->uniqueID != 2 + SCOREBOARD_ENTRIES + 10 )
		return( FALSE );
	}
#endif /* NDEBUG */

	return( TRUE );
	}

/* Initialise and shut down the scoreboard */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initScoreboard( INOUT_PTR TYPECAST( SCOREBOARD_INFO * ) \
						struct SC *scoreboardInfoPtr )
	{
	SCOREBOARD_INFO *scoreboardInfo = scoreboardInfoPtr;
	int status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	
	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );

	/* Initialise the scoreboard */
	memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );

	/* Make sure that everything's working as intended */
#ifndef CONFIG_FUZZ
	if( !selfTest( scoreboardInfo ) )
		{
		zeroise( scoreboardInfo, sizeof( SCOREBOARD_INFO ) );
		DEBUG_DIAG(( "Couldn't initialise scoreboard" ));

		krnlExitMutex( MUTEX_SCOREBOARD );
		retIntError();
		}
#endif /* !CONFIG_FUZZ */

	krnlExitMutex( MUTEX_SCOREBOARD );

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void endScoreboard( INOUT_PTR TYPECAST( SCOREBOARD_INFO * ) \
						struct SC *scoreboardInfoPtr )
	{
	SCOREBOARD_INFO *scoreboardInfo = scoreboardInfoPtr;
	int status;

	/* Shut down the scoreboard.  We acquire the mutex while we're doing 
	   this to ensure that any threads still using it have exited before we 
	   destroy it.  Exactly what to do if we can't acquire the mutex is a 
	   bit complicated because failing to acquire the mutex is a special-
	   case exception condition so it's not even possible to plan for this 
	   since it's uncertain under which conditions (if ever) it would 
	   occur.  For now we play it by the book and don't do anything if we 
	   can't acquire the mutex, which is at least consistent */
	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	ENSURES_V( cryptStatusOK( status ) );	/* See comment above */

	/* Clear the scoreboard */
	zeroise( scoreboardInfo, sizeof( SCOREBOARD_INFO ) );

	krnlExitMutex( MUTEX_SCOREBOARD );
	}
#endif /* USE_TLS */
