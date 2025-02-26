/****************************************************************************
*																			*
*					cryptlib Session Scoreboard Header File					*
*						Copyright Peter Gutmann 1998-2014					*
*																			*
****************************************************************************/

#ifndef _SCOREBRD_DEFINED

#define _SCOREBRD_DEFINED

#ifdef USE_TLS

/****************************************************************************
*																			*
*						Scoreboard Types and Structures						*
*																			*
****************************************************************************/

/* The search key to use for a scoreboard lookup.  We distinguish between
   client and server sessionIDs in order to provide a logically distinct 
   namespace for client and server sessions */

typedef enum {
	SCOREBOARD_KEY_NONE,
	SCOREBOARD_KEY_SESSIONID_CLI,	/* Lookup by client session ID */
	SCOREBOARD_KEY_SESSIONID_SVR,	/* Lookup by server session ID */
	SCOREBOARD_KEY_FQDN,			/* Lookup by server FQDN */
	SCOREBOARD_KEY_LAST
	} SCOREBOARD_KEY_TYPE;

/* Information added to/read from an entry in the scoreboard */

typedef struct {
	/* Scoreboard search key information */
	BUFFER_OPT_FIXED( keySize ) \
	const void *key;
	int keySize;

	/* The data stored with the scoreboard entry */
	BUFFER_OPT_FIXED( dataSize ) \
	const void *data;
	int dataSize;
	int metaData;
	} SCOREBOARD_ENTRY_INFO;

/* Storage for the scoreboard state.  When passed to scoreboard functions
   it's declared as a void * because to the caller it's an opaque memory 
   block while to the scoreboard routines it's structured storage */

typedef BYTE SCOREBOARD_STATE[ 64 ];

/****************************************************************************
*																			*
*							Scoreboard Functions							*
*																			*
****************************************************************************/

/* Session scoreboard management functions.  Since the SCOREBOARD_INFO 
   struct isn't visible at this point, we have to use a forward declaration 
   for it */

struct SC;

CHECK_RETVAL_RANGE( 0, MAX_INTLENGTH ) STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int lookupScoreboardEntry( INOUT_PTR struct SC *scoreboardIndexInfoPtr,
						   IN_ENUM( SCOREBOARD_KEY ) \
								const SCOREBOARD_KEY_TYPE keyType,
						   IN_BUFFER( keyLength ) const void *key, 
						   IN_LENGTH_SHORT_MIN( 2 ) const int keyLength, 
						   OUT_PTR SCOREBOARD_ENTRY_INFO *scoreboardInfo );
#if defined( SCOREBOARD_KEY_MIN ) && ( SCOREBOARD_KEY_MIN != 4 )
  /* This is only visible inside session/scorebrd.c so we have to hardcode
     the value for external use */
  #error SCOREBOARD_KEY_MIN value is wrong in prototype
#endif /* SCOREBOARD_KEY_MIN && SCOREBOARD_KEY_MIN == 4 */
CHECK_RETVAL_RANGE( 0, MAX_INTLENGTH - 1 ) STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int addScoreboardEntry( INOUT_PTR struct SC *scoreboardIndexInfoPtr,
						IN_BUFFER( keyLength ) const void *key, 
						IN_LENGTH_SHORT_MIN( 4 ) const int keyLength, 
						/* 4 = SCOREBOARD_KEY_MIN = MIN_SESSIONID_SIZE */
						const SCOREBOARD_ENTRY_INFO *scoreboardInfo );
CHECK_RETVAL_RANGE( 0, MAX_INTLENGTH - 1 ) STDC_NONNULL_ARG( ( 1, 2, 4, 6 ) ) \
int addScoreboardEntryEx( INOUT_PTR struct SC *scoreboardIndexInfoPtr,
						  IN_BUFFER( keyLength ) const void *key, 
						  IN_LENGTH_SHORT_MIN( 4 ) const int keyLength, 
						  /* 4 = SCOREBOARD_KEY_MIN = MIN_SESSIONID_SIZE */
						  IN_BUFFER( keyLength ) const void *altKey, 
						  IN_LENGTH_SHORT_MIN( 2 ) const int altKeyLength, 
						  const SCOREBOARD_ENTRY_INFO *scoreboardInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void deleteScoreboardEntry( INOUT_PTR struct SC *scoreboardIndexInfoPtr, 
							IN_INT_Z const int uniqueID );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initScoreboard( INOUT_PTR struct SC *scoreboardIndexInfoPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void endScoreboard( INOUT_PTR struct SC *scoreboardIndexInfoPtr );

#else

#define getScoreboardInfoStorage()			NULL
#define initScoreboard( scoreboardInfo )	CRYPT_OK
#define endScoreboard( scoreboardInfo )

#endif /* USE_TLS */

#endif /* _SCOREBRD_DEFINED */
