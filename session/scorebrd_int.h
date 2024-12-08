<<<<<<< HEAD
/****************************************************************************
*																			*
*						 Internal Scoreboard Header File					*
*						Copyright Peter Gutmann 1998-2019					*
*																			*
****************************************************************************/

#ifndef _SCOREBRD_INT_DEFINED

#define _SCOREBRD_INT_DEFINED

#if defined( INC_ALL )
  #include "session.h"
  #include "tls.h"
#else
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/****************************************************************************
*																			*
*								Constants									*
*																			*
****************************************************************************/

/* The number of entries in the TLS session cache, the one specific instance
   of the scoreboard that's used at the moment */

#if defined( CONFIG_CONSERVE_MEMORY )
  #define SCOREBOARD_ENTRIES		8
#else
  #define SCOREBOARD_ENTRIES		64
#endif /* CONFIG_CONSERVE_MEMORY */

/* The minimum and maximum sizes of any identifiers and data values to be 
   stored in the scoreboard.  Since the scoreboard is currently only used 
   for TLS session resumption, these are MIN_SESSIONID_SIZE = 4 bytes, 
   MAX_SESSIONID_SIZE = 32 bytes, and TLS_SECRET_SIZE = 48 bytes */

#define SCOREBOARD_KEY_MIN			MIN_SESSIONID_SIZE
#define SCOREBOARD_KEY_SIZE			MAX_SESSIONID_SIZE
#define SCOREBOARD_DATA_SIZE		TLS_SECRET_SIZE

/* The maximum amount of time that an entry is retained in the scoreboard,
   one hour */

#define SCOREBOARD_TIMEOUT			3600

/****************************************************************************
*																			*
*							Data Types and Structures						*
*																			*
****************************************************************************/

/* An individual scoreboard entry containing index information and its 
   corresponding data, SCOREBOARD_DATA */

typedef BYTE SCOREBOARD_DATA[ SCOREBOARD_DATA_SIZE ];

typedef struct {
	/* Identification information: The checksum and hash of the session ID 
	   (to locate an entry based on the sessionID sent by the client) and 
	   checksum and hash of the FQDN (to locate an entry based on the server
	   FQDN) */
	int sessionCheckValue;
	BUFFER_FIXED( HASH_DATA_SIZE ) \
	BYTE sessionHash[ HASH_DATA_SIZE + 4 ];
	int fqdnCheckValue;
	BUFFER_FIXED( HASH_DATA_SIZE ) \
	BYTE fqdnHash[ HASH_DATA_SIZE + 4 ];

	/* Since a lookup may have to return a session ID value if we're going
	   from an FQDN to a session ID, we have to store the full session ID 
	   value alongside its checksum and hash */
	BUFFER( SCOREBOARD_KEY_SIZE, sessionIDlength ) \
	BYTE sessionID[ SCOREBOARD_KEY_SIZE + 4 ];
	int sessionIDlength;

	/* The scoreboard data, along with a word of metadata that can be used 
	   to convey additional information about it, and a checksum for the 
	   SCOREBOARD_DATA.  The dataLength variable records how much data is 
	   actually present out of the SCOREBOARD_DATA_SIZE bytes that are 
	   available for use */
	SCOREBOARD_DATA data;
	int dataLength, dataChecksum;
	int metaData;

	/* Miscellaneous information.  We record whether an entry corresponds to
	   server or client data in order to provide logically separate 
	   namespaces for client and server */
	time_t timeStamp;		/* Time entry was added to the scoreboard */
	BOOLEAN isServerData;	/* Whether this is client or server value */
	int uniqueID;			/* Unique ID for this entry */
	} SCOREBOARD_ENTRY;

/* Overall scoreboard information.  Note that the SCOREBOARD_STATE size 
   define in scorebrd.h will need to be updated if this structure is 
   changed */

typedef struct SC {
	/* The last used entry in the scoreboard, and a unique ID for each 
	   scoreboard entry.  This is incremented for each index entry added,
	   so that even if an entry is deleted and then another one with the 
	   same index value added, the uniqueID for the two will be different */
	int lastEntry;				/* Last used entry in scoreboard */
	int uniqueID;				/* Unique ID for scoreboard entry */

	/* Scoreboard index and data storage */
	SCOREBOARD_ENTRY index[ SCOREBOARD_ENTRIES ];
	} SCOREBOARD_INFO;

#endif /* USE_TLS */

#endif /* _SCOREBRD_INT_DEFINED */
=======
/****************************************************************************
*																			*
*						 Internal Scoreboard Header File					*
*						Copyright Peter Gutmann 1998-2019					*
*																			*
****************************************************************************/

#ifndef _SCOREBRD_INT_DEFINED

#define _SCOREBRD_INT_DEFINED

#if defined( INC_ALL )
  #include "session.h"
  #include "tls.h"
#else
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

#ifdef USE_TLS

/****************************************************************************
*																			*
*								Constants									*
*																			*
****************************************************************************/

/* The number of entries in the TLS session cache, the one specific instance
   of the scoreboard that's used at the moment */

#if defined( CONFIG_CONSERVE_MEMORY )
  #define SCOREBOARD_ENTRIES		8
#else
  #define SCOREBOARD_ENTRIES		64
#endif /* CONFIG_CONSERVE_MEMORY */

/* The minimum and maximum sizes of any identifiers and data values to be 
   stored in the scoreboard.  Since the scoreboard is currently only used 
   for TLS session resumption, these are MIN_SESSIONID_SIZE = 4 bytes, 
   MAX_SESSIONID_SIZE = 32 bytes, and TLS_SECRET_SIZE = 48 bytes */

#define SCOREBOARD_KEY_MIN			MIN_SESSIONID_SIZE
#define SCOREBOARD_KEY_SIZE			MAX_SESSIONID_SIZE
#define SCOREBOARD_DATA_SIZE		TLS_SECRET_SIZE

/* The maximum amount of time that an entry is retained in the scoreboard,
   one hour */

#define SCOREBOARD_TIMEOUT			3600

/****************************************************************************
*																			*
*							Data Types and Structures						*
*																			*
****************************************************************************/

/* An individual scoreboard entry containing index information and its 
   corresponding data, SCOREBOARD_DATA */

typedef BYTE SCOREBOARD_DATA[ SCOREBOARD_DATA_SIZE ];

typedef struct {
	/* Identification information: The checksum and hash of the session ID 
	   (to locate an entry based on the sessionID sent by the client) and 
	   checksum and hash of the FQDN (to locate an entry based on the server
	   FQDN) */
	int sessionCheckValue;
	BUFFER_FIXED( HASH_DATA_SIZE ) \
	BYTE sessionHash[ HASH_DATA_SIZE + 4 ];
	int fqdnCheckValue;
	BUFFER_FIXED( HASH_DATA_SIZE ) \
	BYTE fqdnHash[ HASH_DATA_SIZE + 4 ];

	/* Since a lookup may have to return a session ID value if we're going
	   from an FQDN to a session ID, we have to store the full session ID 
	   value alongside its checksum and hash */
	BUFFER( SCOREBOARD_KEY_SIZE, sessionIDlength ) \
	BYTE sessionID[ SCOREBOARD_KEY_SIZE + 4 ];
	int sessionIDlength;

	/* The scoreboard data, along with a word of metadata that can be used 
	   to convey additional information about it, and a checksum for the 
	   SCOREBOARD_DATA.  The dataLength variable records how much data is 
	   actually present out of the SCOREBOARD_DATA_SIZE bytes that are 
	   available for use */
	SCOREBOARD_DATA data;
	int dataLength, dataChecksum;
	int metaData;

	/* Miscellaneous information.  We record whether an entry corresponds to
	   server or client data in order to provide logically separate 
	   namespaces for client and server */
	time_t timeStamp;		/* Time entry was added to the scoreboard */
	BOOLEAN isServerData;	/* Whether this is client or server value */
	int uniqueID;			/* Unique ID for this entry */
	} SCOREBOARD_ENTRY;

/* Overall scoreboard information.  Note that the SCOREBOARD_STATE size 
   define in scorebrd.h will need to be updated if this structure is 
   changed */

typedef struct SC {
	/* The last used entry in the scoreboard, and a unique ID for each 
	   scoreboard entry.  This is incremented for each index entry added,
	   so that even if an entry is deleted and then another one with the 
	   same index value added, the uniqueID for the two will be different */
	int lastEntry;				/* Last used entry in scoreboard */
	int uniqueID;				/* Unique ID for scoreboard entry */

	/* Scoreboard index and data storage */
	SCOREBOARD_ENTRY index[ SCOREBOARD_ENTRIES ];
	} SCOREBOARD_INFO;

#endif /* USE_TLS */

#endif /* _SCOREBRD_INT_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
