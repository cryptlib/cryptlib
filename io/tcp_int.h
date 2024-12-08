<<<<<<< HEAD
/****************************************************************************
*																			*
*						Internal TCP/IP Header File							*
*					  Copyright Peter Gutmann 1998-2016						*
*																			*
****************************************************************************/

#ifdef USE_TCP

/****************************************************************************
*																			*
*						 	Defines and Constants 							*
*																			*
****************************************************************************/

/* Wait codes for the ioWait() function */

typedef enum { 
	IOWAIT_NONE,			/* No I/O wait type */
	IOWAIT_READ,			/* Wait for read availability */
	IOWAIT_WRITE,			/* Wait for write availability */
	IOWAIT_CONNECT,			/* Wait for connect to complete */
	IOWAIT_ACCEPT,			/* Wait for accept to complete */
	IOWAIT_LAST				/* Last possible wait type */
	} IOWAIT_TYPE;

/****************************************************************************
*																			*
*						 		Data Structures 							*
*																			*
****************************************************************************/

/* The network socket pool, used to deal with the Unix socket programming
   model which assumes that a single process will listen on a server socket
   and fork off children as required to deal with connect attempts.  See
   the disucssion in io/tcp.c for more on how this works.
   
   Note that although this data structure is only used in io/tcp_conn.c,
   we have to declare it here since it's allocated in the static data set
   at compile time */

#ifdef CONFIG_CONSERVE_MEMORY
  #define SOCKETPOOL_SIZE		8
#else
  #define SOCKETPOOL_SIZE		128
#endif /* CONFIG_CONSERVE_MEMORY */

#define ADDRHASH_SIZE			8

typedef struct {
#if defined( __FreeRTOS__ ) && defined( USE_FREERTOS_SOCKETS )
	void *netSocket;		/* Socket handle, actually a Socket_t */
#elif defined( __WINDOWS__ )
	UINT_PTR netSocket;		/* Socket handle */
#else
	int netSocket;			/* Socket handle */
#endif /* System-specific socket data types */
	int refCount;			/* Reference count for the socket */
	int addrChecksum;		/* Checksum and hash of family, interface, and */
	BYTE addrHash[ ADDRHASH_SIZE + 8 ];	/*	port info for server socket */
	} SOCKET_INFO;

/****************************************************************************
*																			*
*						 		Support Functions 							*
*																			*
****************************************************************************/

#ifdef _STREAM_INT_DEFINED

/* Socket pool access function */

CHECK_RETVAL \
int initSocketPool( void );

/* Prototypes for functions in tcp.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int ioWait( INOUT_PTR NET_STREAM_INFO *netStream, 
			IN_INT_Z const int timeout,
			IN_BOOL const BOOLEAN previousDataRead, 
			IN_ENUM( IOWAIT ) const IOWAIT_TYPE type );

/* Prototypes for functions in tcp_conn.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void setAccessMethodTCPConnect( INOUT_PTR NET_STREAM_INFO *netStream );

/* Prototypes for functions in tcp_rw.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void setAccessMethodTCPReadWrite( INOUT_PTR NET_STREAM_INFO *netStream );

/* Prototypes for functions in tcp_err.c */

#ifdef USE_ERRMSGS

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int mapNetworkError( NET_STREAM_INFO *netStream, 
					 const int netStreamErrorCode,
					 IN_BOOL const BOOLEAN useHostErrorInfo, 
					 IN_ERROR int status );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int getSocketError( NET_STREAM_INFO *netStream, 
					IN_ERROR const int status,
					OUT_INT_Z int *socketErrorCode );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int getHostError( NET_STREAM_INFO *netStream, IN_ERROR const int status );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setSocketError( INOUT_PTR NET_STREAM_INFO *netStream, 
					IN_BUFFER( errorMessageLength ) const char *errorMessage, 
					IN_LENGTH_ERRORMESSAGE const int errorMessageLength,
					IN_ERROR const int status, 
					IN_BOOL const BOOLEAN isFatal );
#else
#define mapNetworkError( netStream, netStreamErrorCode, useHostErrorInfo, status ) \
		status
#define getSocketError( netStream, status, socketErrorCode ) \
		*socketErrorCode = getErrorCode( netStream->netSocket ), status
#define getHostError( netStream, status )	status
#define setSocketError( netStream, errorMessage, errorMessageLength, status, isFatal ) \
		netStream->persistentStatus = ( isFatal ) ? status : CRYPT_OK, status
#endif /* USE_ERRMSGS */
#ifdef USE_RAW_SOCKETS
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int diagnoseConnectionProblem( INOUT_PTR NET_STREAM_INFO *netStream, 
							   IN_BUFFER( hostNameLen ) const char *host, 
							   IN_LENGTH_DNS const int hostNameLen,
							   IN_ERROR const int originalStatus );
#else
#define diagnoseConnectionProblem( netStream, hostName, hostNameLen, status ) \
								   status
#endif /* USE_RAW_SOCKETS */
#ifdef __WIN32__
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkFirewallError( INOUT_PTR NET_STREAM_INFO *netStream );
#else
  #define checkFirewallError( netStream )	CRYPT_ERROR_TIMEOUT
#endif /* Windows */
#endif /* _STREAM_INT_DEFINED */

#endif /* USE_TCP */
=======
/****************************************************************************
*																			*
*						Internal TCP/IP Header File							*
*					  Copyright Peter Gutmann 1998-2016						*
*																			*
****************************************************************************/

#ifdef USE_TCP

/****************************************************************************
*																			*
*						 	Defines and Constants 							*
*																			*
****************************************************************************/

/* Wait codes for the ioWait() function */

typedef enum { 
	IOWAIT_NONE,			/* No I/O wait type */
	IOWAIT_READ,			/* Wait for read availability */
	IOWAIT_WRITE,			/* Wait for write availability */
	IOWAIT_CONNECT,			/* Wait for connect to complete */
	IOWAIT_ACCEPT,			/* Wait for accept to complete */
	IOWAIT_LAST				/* Last possible wait type */
	} IOWAIT_TYPE;

/****************************************************************************
*																			*
*						 		Data Structures 							*
*																			*
****************************************************************************/

/* The network socket pool, used to deal with the Unix socket programming
   model which assumes that a single process will listen on a server socket
   and fork off children as required to deal with connect attempts.  See
   the disucssion in io/tcp.c for more on how this works.
   
   Note that although this data structure is only used in io/tcp_conn.c,
   we have to declare it here since it's allocated in the static data set
   at compile time */

#ifdef CONFIG_CONSERVE_MEMORY
  #define SOCKETPOOL_SIZE		8
#else
  #define SOCKETPOOL_SIZE		128
#endif /* CONFIG_CONSERVE_MEMORY */

#define ADDRHASH_SIZE			8

typedef struct {
#if defined( __FreeRTOS__ ) && defined( USE_FREERTOS_SOCKETS )
	void *netSocket;		/* Socket handle, actually a Socket_t */
#elif defined( __WINDOWS__ )
	UINT_PTR netSocket;		/* Socket handle */
#else
	int netSocket;			/* Socket handle */
#endif /* System-specific socket data types */
	int refCount;			/* Reference count for the socket */
	int addrChecksum;		/* Checksum and hash of family, interface, and */
	BYTE addrHash[ ADDRHASH_SIZE + 8 ];	/*	port info for server socket */
	} SOCKET_INFO;

/****************************************************************************
*																			*
*						 		Support Functions 							*
*																			*
****************************************************************************/

#ifdef _STREAM_INT_DEFINED

/* Socket pool access function */

CHECK_RETVAL \
int initSocketPool( void );

/* Prototypes for functions in tcp.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int ioWait( INOUT_PTR NET_STREAM_INFO *netStream, 
			IN_INT_Z const int timeout,
			IN_BOOL const BOOLEAN previousDataRead, 
			IN_ENUM( IOWAIT ) const IOWAIT_TYPE type );

/* Prototypes for functions in tcp_conn.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void setAccessMethodTCPConnect( INOUT_PTR NET_STREAM_INFO *netStream );

/* Prototypes for functions in tcp_rw.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void setAccessMethodTCPReadWrite( INOUT_PTR NET_STREAM_INFO *netStream );

/* Prototypes for functions in tcp_err.c */

#ifdef USE_ERRMSGS

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int mapNetworkError( NET_STREAM_INFO *netStream, 
					 const int netStreamErrorCode,
					 IN_BOOL const BOOLEAN useHostErrorInfo, 
					 IN_ERROR int status );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int getSocketError( NET_STREAM_INFO *netStream, 
					IN_ERROR const int status,
					OUT_INT_Z int *socketErrorCode );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int getHostError( NET_STREAM_INFO *netStream, IN_ERROR const int status );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setSocketError( INOUT_PTR NET_STREAM_INFO *netStream, 
					IN_BUFFER( errorMessageLength ) const char *errorMessage, 
					IN_LENGTH_ERRORMESSAGE const int errorMessageLength,
					IN_ERROR const int status, 
					IN_BOOL const BOOLEAN isFatal );
#else
#define mapNetworkError( netStream, netStreamErrorCode, useHostErrorInfo, status ) \
		status
#define getSocketError( netStream, status, socketErrorCode ) \
		*socketErrorCode = getErrorCode( netStream->netSocket ), status
#define getHostError( netStream, status )	status
#define setSocketError( netStream, errorMessage, errorMessageLength, status, isFatal ) \
		netStream->persistentStatus = ( isFatal ) ? status : CRYPT_OK, status
#endif /* USE_ERRMSGS */
#ifdef USE_RAW_SOCKETS
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int diagnoseConnectionProblem( INOUT_PTR NET_STREAM_INFO *netStream, 
							   IN_BUFFER( hostNameLen ) const char *host, 
							   IN_LENGTH_DNS const int hostNameLen,
							   IN_ERROR const int originalStatus );
#else
#define diagnoseConnectionProblem( netStream, hostName, hostNameLen, status ) \
								   status
#endif /* USE_RAW_SOCKETS */
#ifdef __WIN32__
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkFirewallError( INOUT_PTR NET_STREAM_INFO *netStream );
#else
  #define checkFirewallError( netStream )	CRYPT_ERROR_TIMEOUT
#endif /* Windows */
#endif /* _STREAM_INT_DEFINED */

#endif /* USE_TCP */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
