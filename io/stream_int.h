<<<<<<< HEAD
/****************************************************************************
*																			*
*						Internal STREAM Header File							*
*					  Copyright Peter Gutmann 1993-2022						*
*																			*
****************************************************************************/

#ifndef _STREAM_INT_DEFINED

#define _STREAM_INT_DEFINED

#if defined( INC_ALL )
  #include "stream.h"
#else
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Stream Constants							*
*																			*
****************************************************************************/

/* General-purpose stream flags.  These are:

	FLAG_DIRTY: Stream buffer contains data that needs to be committed to
		backing store.

	FLAG_FATALERROR: The stream status condition in stream->status is non-
		recoverable.  This is kept distinct from the status setting itself
		which may be just an underflow or similar and can be reset with
		sClearError(), the fatal flag is queryable via sioctlGet() to 
		indicate that no further operations like sending SSH/TLS shutdown
		notifications should be attempted on the stream.

	FLAG_PARTIALREAD: Used for network reads to handle timeouts and for file 
		streams when we don't know the full extent of a file stream.  When 
		this is set and we ask for a read of n bytes and there isn't 
		sufficient data present in the file to satisfy the request the 
		stream code returns 0...n bytes rather than an underflow error.

	FLAG_PARTIALWRITE: Used for network streams when performing bulk data 
		transfers, in this case the write may time out and can be restarted
		later rather than returning a timeout error.

	FLAG_READONLY: Stream is read-only */

#define STREAM_FLAG_NONE		0x0000	/* No stream flag */
#define STREAM_FLAG_READONLY	0x0001	/* Read-only stream */
#define STREAM_FLAG_PARTIALREAD 0x0002	/* Allow read of less than req.amount */
#define STREAM_FLAG_PARTIALWRITE 0x0004	/* Allow write of less than req.amount */
#define STREAM_FLAG_DIRTY		0x0008	/* Stream contains un-committed data */
#define STREAM_FLAG_FATALERROR	0x0010	/* Stream error condition is fatal */
#define STREAM_FLAG_MASK		0x001F	/* Mask for general-purpose flags */

/* Memory stream flags.  These are:

	MFLAG_PSEUDO/PSEUDO_HTTP/PSEUDO_RAW: Used for memory streams 
		emulating some other stream type, writes are discarded and reads 
		come from the stream buffer.  Standard pseudo-streams are used in
		the self-test to test various read functions, then in addition to
		the basic type for fuzzing purposes the HTTP flag is a modifier to 
		the standard pseudo-stream indicating that it's an HTTP-style read 
		and the RAW flag is an indicator that the HTTP stream should read 
		the normally out-of-band header (i.e. the HTTP wrapper for an 
		encapsulated data type) as well as the actual data.  
C
	MFLAG_VFILE: The underlying OS doesn't support conventional file I/O (it
		may only support, for example, access to fixed blocks of flash 
		memory) so this is a memory stream emulating a file stream */

#define STREAM_MFLAG_VFILE		0x0020	/* File stream emulated via mem.stream */
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
  #define STREAM_MFLAG_PSEUDO	0x0040	/* Stream is pseudo-stream */
  #ifdef CONFIG_FUZZ
	#define STREAM_MFLAG_PSEUDO_HTTP 0x0080	/* Stream is HTTP pseudo-stream */
	#define STREAM_MFLAG_PSEUDO_RAW 0x0100	/* Stream reads raw data */
  #endif /* CONFIG_FUZZ */
#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */
#if defined( CONFIG_CONSERVE_MEMORY_EXTRA )
  #define STREAM_MFLAG_MASK		( 0x0020 | STREAM_FLAG_MASK )	
										/* Mask for memory-only flags */
#elif defined( CONFIG_FUZZ )
  #define STREAM_MFLAG_MASK		( 0x01E0 | STREAM_FLAG_MASK )	
										/* Mask for memory-only flags */
#else
  #define STREAM_MFLAG_MASK		( 0x0060 | STREAM_FLAG_MASK )	
										/* Mask for memory-only flags */
#endif /* Valid stream flags */

/* File stream flags.  These are:

	FFLAG_BUFFERSET: Used to indicate that the stream has an I/O buffer 
		associated with it.  A stream can be opened without a buffer, but to
		read/write data it needs to have a buffer associated with it.  Since
		this can be of variable size and sometimes isn't required at all, 
		it's created on-demand rather than always being present, and its 
		presence is indicated by this flag.
	
	FFLAG_EOF: The underlying file has reached EOF, no further data can be 
		read once the current buffer is emptied.
	
	FFLAG_MMAPPED: This is a memory-mapped file stream, used in conjunction
		with MFLAG_VFILE virtual file streams.

	FFLAG_POSCHANGED: The position in the underlying file has changed, 
		requiring the file buffer to be refilled from the new position 
		before data can be read from it */

#define STREAM_FFLAG_BUFFERSET	0x0080	/* Stream has associated buffer */
#define STREAM_FFLAG_EOF		0x0100	/* EOF reached on stream */
#define STREAM_FFLAG_POSCHANGED	0x0200	/* File stream position has changed */
#define STREAM_FFLAG_POSCHANGED_NOSKIP 0x0400	/* New stream pos.is in following block */
#define STREAM_FFLAG_MMAPPED	0x0800	/* File stream is memory-mapped */
#define STREAM_FFLAG_MASK		( 0x0F80 | STREAM_FLAG_MASK )	
										/* Mask for file-only flags */

/* The maximum possible stream flag value */

#define STREAM_FLAG_MAX			0x0FFF	/* Maximum possible flag value */

/* Network stream flags.  Since there are quite a number of these and they're
   only required for the network-specific stream functionality, we give them
   their own flags variable in the netStream structure instead of using the 
   overall stream flags.  In addition we break them up into general network
   stream flags and HTTP-specific flags, which form a sizeable family of their
   own.  The network flags are:

	NFLAG_DGRAM: The stream is run over UDP rather than the default TCP.

	NFLAG_ENCAPS: The protocol is running over a lower encapsulation layer 
		that provides additional packet control information, typically 
		packet size and flow control information.  HTTP and UDP transport
		both provide this type of service, HTTP explicitly and UDP 
		implicitly via its datagram service.  If this flag is set then the 
		lower-level read code overrides some error handling that normally 
		takes place at a higher level.  For example if a read of n bytes is 
		requested and the encapsulation layer reports that only m bytes, 
		m < n is present, this isn't treated as a read/timeout error.

	NFLAG_FIRSTREADOK: The first data read from the stream succeeded.  This
		is used to detect problems due to buggy firewall software, see the
		comments in io/tcp.c for details.

	NFLAG_ISSERVER: The stream is a server stream (default is client).

	NFLAG_LASTMSGR/NFLAG_LASTMSGR: This is the last message in the exchange.
		For a last-message read it means that the other side has indicated
		(for example through an HTTP "Connection: close") that this is the 
		case.  For a last-message write it means that we should indicate to
		the other side (for example through an HTTP "Connection: close") 
		that this is the case.

	NFLAG_USERSOCKET: The network socket was supplied by the user rather 
		than being created by cryptlib, so some actions such as socket
		shutdown should be skipped.

   The HTTP network flags are:

	NHFLAG_HTTP10: This is an HTTP 1.0 (rather than 1.1) HTTP stream.

	NHFLAG_HTTPPROXY/NFLAG_HTTPTUNNEL: HTTP proxy control flags.  When the 
		proxy flag is set, HTTP requests are sent as 
		"GET http://destination-url/location" (sent to the proxy) rather 
		than "GET location" (sent directly to the target host).  When the 
		tunnel flag is set, the initial network connection-establishment 
		request is sent as an explicit proxy command "CONNECT fqdn:port", 
		after which normal PDUs for the protocol being tunneled are sent.

		Note that the HTTP tunnel flag is currently never set by anything
		due to the removal of the SESSION_USEHTTPTUNNEL flag at a higher
		level, which was only ever set implicitly by being set in the TLS 
		altProtocolInfo, which in turn was never selected outside a 
		USE_CMP_TRANSPORT block.  The location at which it would be selected 
		(except for the presence of a USE_CMP_TRANSPORT ifdef) is at line 
		195 of session/sess_attr.c in versions up to 3.4.1.

	NHFLAG_HTTPGET/NFLAG_HTTPPOST: HTTP allowed-actions flags.

	NHFLAG_HTTPPOST_AS_GET: Modify the POST to encode it as a GET (ugh), for 
		b0rken servers that don't do POST */

#define STREAM_NFLAG_NONE		0x0000	/* No network flag */
#define STREAM_NFLAG_ISSERVER	0x0001	/* Stream is server rather than client */
#define STREAM_NFLAG_USERSOCKET	0x0002	/* Network socket was supplied by user */
#define STREAM_NFLAG_DGRAM		0x0004	/* Stream is UDP rather than TCP */
#define STREAM_NFLAG_LASTMSGR	0x0008	/* Last message in read exchange */
#define STREAM_NFLAG_LASTMSGW	0x0010	/* Last message in write exchange */
#define STREAM_NFLAG_ENCAPS		0x0020	/* Network transport is encapsulated */
#define STREAM_NFLAG_FIRSTREADOK 0x0040	/* First data read succeeded */
#define STREAM_NFLAG_MAX		0x007F	/* Maximum possible flag value */

#define STREAM_NHFLAG_NONE		0x0000	/* No network HTTP flag */
#define STREAM_NHFLAG_HTTP10	0x0001	/* HTTP 1.0 stream */
#define STREAM_NHFLAG_PROXY		0x0002	/* Use HTTP proxy format for requests */
#define STREAM_NHFLAG_TUNNEL	0x0004	/* Use HTTP proxy tunnel for connect */
#define STREAM_NHFLAG_GET		0x0008	/* Allow HTTP GET */
#define STREAM_NHFLAG_POST		0x0010	/* Allow HTTP POST */
#define STREAM_NHFLAG_POST_AS_GET 0x0020 /* Implement POST as GET */
#define STREAM_NHFLAG_WS_UPGRADE 0x0040	/* WebSockets Upgrade */
#define STREAM_NHFLAG_MAX		0x007F	/* Maximum possible flag value */

#define STREAM_NHFLAG_REQMASK \
		( STREAM_NHFLAG_GET | STREAM_NHFLAG_POST | \
		  STREAM_NHFLAG_POST_AS_GET )	/* Mask for permitted HTTP req.types */

/* Network transport-specific flags.  These are:

	FLAG_FLUSH: Used in writes to buffered streams to force a flush of data in 
		the stream buffers.
	
	FLAG_BLOCKING/FLAG_NONBLOCKING: Used to override the stream default 
		behaviour on reads and writes and force blocking/nonblocking I/O */

#define TRANSPORT_FLAG_NONE		0x00	/* No transport flag */
#define TRANSPORT_FLAG_FLUSH	0x01	/* Flush data on write */
#define TRANSPORT_FLAG_NONBLOCKING 0x02	/* Explicitly perform nonblocking read */
#define TRANSPORT_FLAG_BLOCKING	0x04	/* Explicitly perform blocking read */
#define TRANSPORT_FLAG_MAX		0x07	/* Maximum possible flag value */

/* URL component size limits, used when parsing a URL.  MAX_LOCATION_SIZE is
   set to a value larger than the canonical CRYPT_MAX_TEXTSIZE to deal with
   some SCEP URLs, which in the pathological case for EJBCA are 71 
   characters, 
   "/ejbca/publicweb/apply/scep/pkiclient.exe?operation=GetCACert&message=*",
   with an option to be even longer by ineserting an alias component between 
   the "scep" and the "pkiclient.exe" */

#define MIN_SCHEMA_SIZE			3
#define MAX_SCHEMA_SIZE			8
#define MIN_LOCATION_SIZE		3
#define MAX_LOCATION_SIZE		128
#define MIN_HOST_SIZE			MIN_DNS_SIZE
#define MAX_HOST_SIZE			MAX_DNS_SIZE

/* The size of the memory buffer used for virtual file streams, which are 
   used in CONFIG_NO_STDIO environments to store data before it's committed
   to backing storage */

#if defined( __MVS__ ) || defined( __VMCMS__ ) || \
	defined( __IBM4758__ ) || defined( __TESTIO__ )
  #define VIRTUAL_FILE_STREAM
#endif /* Nonstandard I/O environments */

#define STREAM_VFILE_BUFSIZE	16384

/****************************************************************************
*																			*
*								Stream Structures							*
*																			*
****************************************************************************/

#ifdef USE_TCP

/* The network-stream specific information stored as part of the STREAM
   data type.  Network streams can work on two levels.  At the lowest 
   level we have the raw network I/O layer, handled by calling 
   setAccessMethodXXX(), which hooks up the transport-level I/O functions.  
   If there's a requirement to replace the built-in network I/O it can be 
   done by replacing the functionality at this level.

   Layered on top of the transport-level I/O via setStreamLayerXXX() is an 
   optional higher layer protocol such as HTTP which is added by calling 
   the appropriate function to layer the higher-level protocol over the 
   transport-level I/O.  This goes via an intermediate buffering layer that
   deals with avoiding making repeated calls to the transport-level I/O 
   function, which is a particular problem for HTTP which has to take input 
   a character at a time.  The buffering layer reads ahead as far as it can 
   and then feeds the buffered result back to the caller as required.  We 
   also use write buffering to avoid potential problems with interactions 
   with some transport layers, details are given in the comment for the 
   buffered write function in net_trans.c.

   Alternatively, we can use setStreamLayerDirect() to just pass the call 
   straight down to the transport layer.

   The layering looks as follows:

	--- httpRead --- bufferedRead ---+--- tcpRead
									 |
	---------------------------------+

	--- httpWrite --- bufferedWrite --+---- tcpWrite
									  |
	----------------------------------+ */

struct NS;

typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *STM_CONNECT_FUNCTION_OPT )( INOUT_PTR struct ST *stream,
										   IN_PTR \
											const NET_CONNECT_INFO *connectInfo );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
		int ( *STM_DISCONNECT_FUNCTION_OPT )( INOUT_PTR struct ST *stream );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
		int ( *STM_GETMETADATA_FUNCTION_OPT )( INOUT_PTR struct ST *stream,
											   OUT_BUFFER_OPT( maxLength, *length ) \
													void *buffer,
											   IN_LENGTH_SHORT_Z const int maxLength, 
											   OUT_LENGTH_BOUNDED_SHORT_Z( maxLength ) \
													int *length );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
		int ( *STM_READ_FUNCTION )( INOUT_PTR struct ST *stream, 
									OUT_BUFFER( maxLength, *length ) \
										void *buffer, 
									IN_DATALENGTH const int maxLength, 
									OUT_DATALENGTH_Z int *length );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
		int ( *STM_WRITE_FUNCTION )( INOUT_PTR struct ST *stream, 
									 IN_BUFFER_OPT( maxLength ) \
										const void *buffer, 
									 IN_DATALENGTH_Z const int maxLength,
									 OUT_DATALENGTH_Z int *length );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *STM_TRANSPORTCONNECT_FUNCTION )( INOUT_PTR struct NS *netStream, 
												IN_BUFFER_OPT( hostNameLen ) \
													const char *hostName,
												IN_LENGTH_DNS_Z \
													const int hostNameLen, 
												IN_PORT const int port );
typedef STDC_NONNULL_ARG( ( 1 ) ) \
		void ( *STM_TRANSPORTDISCONNECT_FUNCTION )( INOUT_PTR struct NS *netStream, 
													IN_BOOL const BOOLEAN fullDisconnect );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
		int ( *STM_TRANSPORTREAD_FUNCTION )( INOUT_PTR struct NS *netStream, 
											 OUT_BUFFER( maxLength, *length ) \
												BYTE *buffer, 
											 IN_DATALENGTH const int maxLength, 
											 OUT_DATALENGTH_Z int *length, 
											 IN_FLAGS_Z( TRANSPORT ) \
												const int flags );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
		int ( *STM_TRANSPORTWRITE_FUNCTION )( INOUT_PTR struct NS *netStream, 
											  IN_BUFFER( maxLength ) \
												const BYTE *buffer,
											  IN_DATALENGTH const int maxLength, 
											  OUT_DATALENGTH_Z int *length, 
											  IN_FLAGS_Z( TRANSPORT ) \
												const int flags );
typedef CHECK_RETVAL_BOOL \
		BOOLEAN ( *STM_TRANSPORTOK_FUNCTION )( void );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
		int ( *STM_TRANSPORTCHECK_FUNCTION )( INOUT_PTR struct NS *netStream );
typedef STDC_NONNULL_ARG( ( 1, 2 ) ) \
		void ( *STM_VIRTUALGETERRORINFO_FUNCTION )( const void *virtualStateInfo,
													INOUT_PTR ERROR_INFO *errorInfo );

typedef struct NS {
	/* General information for the network stream.  For a server the
	   listenSocket is the (possibly shared) common socket that the server 
	   is listening on, the netSocket is the ephemeral socket used for
	   communications */
	STREAM_PROTOCOL_TYPE protocol;/* Network protocol type */
	CRYPT_SUBPROTOCOL_TYPE subProtocol;	/* Optional sub-protocol */
	SAFE_FLAGS nFlags;			/* Network-specific flags */
	SAFE_FLAGS nhFlags;			/* HTTP-specific flags */
#if defined( __FreeRTOS__ ) && defined( USE_FREERTOS_SOCKETS )
	void *netSocket, *listenSocket;/* Network socket, actually a Socket_t */
#elif defined( __WINDOWS__ )
	UINT_PTR netSocket, listenSocket;/* Network socket */
#else
	int netSocket, listenSocket;/* Network socket */
#endif /* System-specific socket data types */

	/* Network timeout information.  The timeout value depends on whether 
	   the stream is in the connect/handshake phase or the data transfer 
	   phase.  The handshake phase is logically treated as part of the 
	   connect phase even though from the stream point of view it's part of 
	   the data transfer phase.  Initially the stream timeout is set to the 
	   connect timeout and the saved timeout is set to the data transfer 
	   timeout.  Once the connect/handshake has completed, the stream 
	   timeout is set to the saved data transfer timeout and the saved 
	   timeout is cleared */
	int timeout, savedTimeout;	/* Network comms timeout */

	/* Network streams require separate read/write buffers for packet
	   assembly/disassembly so we provide a write buffer alongside the 
	   generic stream read buffer */
	BUFFER( writeBufSize, writeBufEnd ) \
	BYTE *writeBuffer;			/* Write buffer */
	int writeBufSize;			/* Total size of buffer */
	int writeBufEnd;			/* Last buffer position with valid data */

	/* Stream subtype-specific information required for some network stream
	   types */
#ifdef USE_EAP
	void *subTypeInfo;			/* Stream subtype-specific information */
	void *transportInfo;		/* UDP transport-specific information */
	int transportInfoPayloadSize;/* Size of payload for above */
#endif /* USE_EAP */

	/* General network-related information.  The server FQDN is held in 
	   dynamically-allocated storage, the optional path for HTTP is a pointer 
	   into the host string at the appropriate location */
	BUFFER_OPT_FIXED( hostLen ) \
	char *host;
	int hostLen;
	BUFFER_OPT_FIXED( pathLen ) \
	char *path;
	int pathLen;
	int port;					/* Host name, path on host, and port */
	BUFFER( CRYPT_MAX_TEXTSIZE / 2, clientAddressLen ) \
	char clientAddress[ ( CRYPT_MAX_TEXTSIZE / 2 ) + 4 ];
	int clientAddressLen;		/* Client IP address (dotted-decimal) */
	int clientPort;				/* Client port */
	BYTE clientAddressBinary[ 16 + 4 ];
	int clientAddressBinaryLen;	/* Client IP address (network byte order) */

	/* Sometimes we can fingerprint the application running on the peer 
	   system, which is useful for working around buggy implementations.  
	   The following value stores the peer application type, if known */
	STREAM_PEER_TYPE systemType;

	/* If a network error condition is fatal we set the persistentStatus 
	   value.  This is checked by the higher-level stream code and copied 
	   to to stream persistent status if required */
	int persistentStatus;

	/* Last-error information returned from lower-level code */
	ERROR_INFO errorInfo;

	/* Network stream read/write functions.  These general-purpose functions 
	   are for the higher-level entry points, they either call straight down 
	   to the transport-layer functions or allow the interposition of 
	   additional layers like HTTP.  For example for an HTTP network read 
	   (http_rd/wr.c) the path would be:

		readFunction -> bufferedTransportReadFunction -> 
										transportReadFunction
		
		http_rd.c:readFunction() -> bufferedTransportReadFunction -> 
										tcp_rw.c:readSocketFunction

	   For an HTTP over TLS read (net_trans.c) the path would be:
		
		http_rd.c:readFunction() -> bufferedTransportReadFunction -> 
										net_trans.c:transportVirtualReadFn 
										
	   For a direct network read the path would be:

		readFunction 

		tcp_rw.c:readSocketFunction.

	   In addition to the read/write functions there also exist optional
	   connect and disconnect functions and get metadata functions (eap.c) 
	   for when the protocol (e.g. TLS) is wrapped in a lower-level protocol 
	   (e.g. EAP) that requires an explicit negotiation as part of the 
	   connect/disconnect process */
	FNPTR connectFunctionOpt, disconnectFunctionOpt, getMetadataFunctionOpt;
	FNPTR readFunction, writeFunction;

	/* Transport-layer network functions.  These can be replaced with user-
	   defined transport mechanisms if required.  Curently they are set in
	   tcp.c for TCP transport, net_trans.c for virtual transport, and, as
	   an oddity, in tcp_err.c for ICMP probes for failed connections */
	FNPTR transportConnectFunction, transportDisconnectFunction;
	FNPTR transportReadFunction, transportWriteFunction;
	FNPTR transportOKFunction, transportCheckFunction;

	/* Virtual stream get/put/get-error-info and state pointers */
	FNPTR virtualGetDataFunction, virtualPutDataFunction;
	FNPTR virtualGetErrorInfoFunction;
	DATAPTR virtualStateInfo;	/* State info for virtual stream */

	/* Variable-length storage for the stream buffers */
	DECLARE_VARSTRUCT_VARS;
	} NET_STREAM_INFO;

/* The size of the network transport stream readahead/write buffers.  We try 
   and make them an optimal size to minimise unnecessary copying and not 
   negatively affect network I/O.  If we make them too big then we'll have 
   to move too much data around when we partially empty them, if we make 
   them too small then the buffering effect is suboptimal.  Since what we're 
   buffering is typically PKI traffic (and rarely UDP packets for UDP 
   transport), a 4K buffer should get most messages in one go.  This also 
   matches many network stacks that use 4K I/O buffers, the BSD default */

#define NETSTREAM_BUFFER_SIZE		4096
#if NETSTREAM_BUFFER_SIZE > MAX_INTLENGTH_SHORT
  #error NETSTREAM_BUFFER_SIZE exceeds buffered I/O length check size
#endif /* NETSTREAM_BUFFER_SIZE > MAX_INTLENGTH_SHORT */

/* Sanity-check a network stream */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckNetStream( const NET_STREAM_INFO *netStream );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

#else

typedef void *NET_STREAM_INFO;	/* Dummy for function prototypes */

#endif /* USE_TCP */

/****************************************************************************
*																			*
*							Stream Function Prototypes						*
*																			*
****************************************************************************/

/* Stream query functions to determine whether a stream is a memory-mapped 
   file stream, a virtual file stream, or a pseudo-stream.  The memory-
   mapped stream check is used when we can eliminate extra buffer allocation 
   if all data is available in memory.  The virtual file stream check is 
   used where the low-level access routines have converted a file on a 
   CONFIG_NO_STDIO system to a memory stream that acts like a file stream.
   The pseudo-stream is used for testing purposes to emulate a standard
   stream like a network stream */

#define sIsMemMappedStream( stream ) \
		( ( ( stream )->type == STREAM_TYPE_FILE ) && \
		  TEST_FLAG( ( stream )->flags, STREAM_FFLAG_MMAPPED ) )
#ifdef VIRTUAL_FILE_STREAM 
  #define sIsVirtualFileStream( stream ) \
		  ( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			TEST_FLAG( ( stream )->flags, STREAM_MFLAG_VFILE ) )
#else
  #define sIsVirtualFileStream( stream )	FALSE
#endif /* VIRTUAL_FILE_STREAM */
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
  #define sIsPseudoStream( stream ) \
		  ( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			TEST_FLAG( ( stream )->flags, STREAM_MFLAG_PSEUDO ) )
  #ifdef CONFIG_FUZZ
	#define sIsPseudoHTTPStream( stream ) \
			( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			  TEST_FLAGS( ( stream )->flags, \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_HTTP ), \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_HTTP ) ) )
	#define sIsPseudoHTTPRawStream( stream ) \
			( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			  TEST_FLAGS( ( stream )->flags, \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_HTTP | \
							STREAM_MFLAG_PSEUDO_RAW ), \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_HTTP | \
							STREAM_MFLAG_PSEUDO_RAW ) ) )
	#define sIsPseudoEAPStream( stream ) \
			( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			  TEST_FLAGS( ( stream )->flags, \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_RAW ), \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_RAW ) ) )
  #endif /* CONFIG_FUZZ */
#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

/* Prototypes for functions in file.c */

#ifdef USE_FILES
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int fileRead( INOUT_PTR STREAM *stream, 
			  OUT_BUFFER( length, *bytesRead ) void *buffer, 
			  IN_DATALENGTH const int length, 
			  OUT_DATALENGTH_Z int *bytesRead );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int fileWrite( INOUT_PTR STREAM *stream, 
			   IN_BUFFER( length ) const void *buffer, 
			   IN_DATALENGTH const int length );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int fileFlush( INOUT_PTR STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int fileSeek( INOUT_PTR STREAM *stream,
			  IN_DATALENGTH_Z const long position );
#endif /* USE_FILES */

#ifdef USE_TCP

/* Network URL processing functions in net_url.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int parseURL( OUT_PTR URL_INFO *urlInfo, 
			  IN_BUFFER( urlLen ) const BYTE *url, 
			  IN_LENGTH_SHORT const int urlLen,
			  IN_PORT_OPT const int defaultPort, 
			  IN_ENUM_OPT( URL_TYPE ) const URL_TYPE urlTypeHint,
			  IN_BOOL const BOOLEAN preParseOnly );

/* Network proxy functions in net_proxy.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int connectViaSocksProxy( INOUT_PTR STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int connectViaHttpProxy( INOUT_PTR STREAM *stream, 
						 INOUT_PTR ERROR_INFO *errorInfo );
#if defined( __WIN32__ )
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int findProxyUrl( OUT_BUFFER( proxyMaxLen, *proxyLen ) char *proxy, 
				  IN_LENGTH_DNS const int proxyMaxLen, 
				  OUT_LENGTH_BOUNDED_Z( proxyMaxLen ) int *proxyLen,
				  IN_BUFFER( urlLen ) const char *url, 
				  IN_LENGTH_DNS const int urlLen );
#else
  #define findProxyUrl( proxy, proxyMaxLen, proxyLen, url, urlLen )	CRYPT_ERROR_NOTFOUND
#endif /* Win32 */

/* Prototypes for functions in net_trans.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int bufferedTransportRead( INOUT_PTR STREAM *stream, 
						   OUT_BUFFER( maxLength, *length ) BYTE *buffer, 
						   IN_DATALENGTH const int maxLength, 
						   OUT_DATALENGTH_Z int *length, 
						   IN_FLAGS_Z( TRANSPORT ) const int flags );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int bufferedTransportWrite( INOUT_PTR STREAM *stream, 
							IN_BUFFER( maxLength ) const BYTE *buffer, 
							IN_DATALENGTH const int maxLength, 
							OUT_DATALENGTH_Z int *length, 
							IN_FLAGS_Z( TRANSPORT ) const int flags );

/* Network access mapping functions */

STDC_NONNULL_ARG( ( 1 ) ) \
void setAccessMethodTCP( INOUT_PTR NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerHTTP( INOUT_PTR NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerEAP( INOUT_PTR NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerDirect( INOUT_PTR NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setAccessMethodTransportVirtual( INOUT_PTR NET_STREAM_INFO *netStream );

#endif /* USE_TCP */

#endif /* _STREAM_INT_DEFINED */
=======
/****************************************************************************
*																			*
*						Internal STREAM Header File							*
*					  Copyright Peter Gutmann 1993-2022						*
*																			*
****************************************************************************/

#ifndef _STREAM_INT_DEFINED

#define _STREAM_INT_DEFINED

#if defined( INC_ALL )
  #include "stream.h"
#else
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Stream Constants							*
*																			*
****************************************************************************/

/* General-purpose stream flags.  These are:

	FLAG_DIRTY: Stream buffer contains data that needs to be committed to
		backing store.

	FLAG_FATALERROR: The stream status condition in stream->status is non-
		recoverable.  This is kept distinct from the status setting itself
		which may be just an underflow or similar and can be reset with
		sClearError(), the fatal flag is queryable via sioctlGet() to 
		indicate that no further operations like sending SSH/TLS shutdown
		notifications should be attempted on the stream.

	FLAG_PARTIALREAD: Used for network reads to handle timeouts and for file 
		streams when we don't know the full extent of a file stream.  When 
		this is set and we ask for a read of n bytes and there isn't 
		sufficient data present in the file to satisfy the request the 
		stream code returns 0...n bytes rather than an underflow error.

	FLAG_PARTIALWRITE: Used for network streams when performing bulk data 
		transfers, in this case the write may time out and can be restarted
		later rather than returning a timeout error.

	FLAG_READONLY: Stream is read-only */

#define STREAM_FLAG_NONE		0x0000	/* No stream flag */
#define STREAM_FLAG_READONLY	0x0001	/* Read-only stream */
#define STREAM_FLAG_PARTIALREAD 0x0002	/* Allow read of less than req.amount */
#define STREAM_FLAG_PARTIALWRITE 0x0004	/* Allow write of less than req.amount */
#define STREAM_FLAG_DIRTY		0x0008	/* Stream contains un-committed data */
#define STREAM_FLAG_FATALERROR	0x0010	/* Stream error condition is fatal */
#define STREAM_FLAG_MASK		0x001F	/* Mask for general-purpose flags */

/* Memory stream flags.  These are:

	MFLAG_PSEUDO/PSEUDO_HTTP/PSEUDO_RAW: Used for memory streams 
		emulating some other stream type, writes are discarded and reads 
		come from the stream buffer.  Standard pseudo-streams are used in
		the self-test to test various read functions, then in addition to
		the basic type for fuzzing purposes the HTTP flag is a modifier to 
		the standard pseudo-stream indicating that it's an HTTP-style read 
		and the RAW flag is an indicator that the HTTP stream should read 
		the normally out-of-band header (i.e. the HTTP wrapper for an 
		encapsulated data type) as well as the actual data.  
C
	MFLAG_VFILE: The underlying OS doesn't support conventional file I/O (it
		may only support, for example, access to fixed blocks of flash 
		memory) so this is a memory stream emulating a file stream */

#define STREAM_MFLAG_VFILE		0x0020	/* File stream emulated via mem.stream */
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
  #define STREAM_MFLAG_PSEUDO	0x0040	/* Stream is pseudo-stream */
  #ifdef CONFIG_FUZZ
	#define STREAM_MFLAG_PSEUDO_HTTP 0x0080	/* Stream is HTTP pseudo-stream */
	#define STREAM_MFLAG_PSEUDO_RAW 0x0100	/* Stream reads raw data */
  #endif /* CONFIG_FUZZ */
#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */
#if defined( CONFIG_CONSERVE_MEMORY_EXTRA )
  #define STREAM_MFLAG_MASK		( 0x0020 | STREAM_FLAG_MASK )	
										/* Mask for memory-only flags */
#elif defined( CONFIG_FUZZ )
  #define STREAM_MFLAG_MASK		( 0x01E0 | STREAM_FLAG_MASK )	
										/* Mask for memory-only flags */
#else
  #define STREAM_MFLAG_MASK		( 0x0060 | STREAM_FLAG_MASK )	
										/* Mask for memory-only flags */
#endif /* Valid stream flags */

/* File stream flags.  These are:

	FFLAG_BUFFERSET: Used to indicate that the stream has an I/O buffer 
		associated with it.  A stream can be opened without a buffer, but to
		read/write data it needs to have a buffer associated with it.  Since
		this can be of variable size and sometimes isn't required at all, 
		it's created on-demand rather than always being present, and its 
		presence is indicated by this flag.
	
	FFLAG_EOF: The underlying file has reached EOF, no further data can be 
		read once the current buffer is emptied.
	
	FFLAG_MMAPPED: This is a memory-mapped file stream, used in conjunction
		with MFLAG_VFILE virtual file streams.

	FFLAG_POSCHANGED: The position in the underlying file has changed, 
		requiring the file buffer to be refilled from the new position 
		before data can be read from it */

#define STREAM_FFLAG_BUFFERSET	0x0080	/* Stream has associated buffer */
#define STREAM_FFLAG_EOF		0x0100	/* EOF reached on stream */
#define STREAM_FFLAG_POSCHANGED	0x0200	/* File stream position has changed */
#define STREAM_FFLAG_POSCHANGED_NOSKIP 0x0400	/* New stream pos.is in following block */
#define STREAM_FFLAG_MMAPPED	0x0800	/* File stream is memory-mapped */
#define STREAM_FFLAG_MASK		( 0x0F80 | STREAM_FLAG_MASK )	
										/* Mask for file-only flags */

/* The maximum possible stream flag value */

#define STREAM_FLAG_MAX			0x0FFF	/* Maximum possible flag value */

/* Network stream flags.  Since there are quite a number of these and they're
   only required for the network-specific stream functionality, we give them
   their own flags variable in the netStream structure instead of using the 
   overall stream flags.  In addition we break them up into general network
   stream flags and HTTP-specific flags, which form a sizeable family of their
   own.  The network flags are:

	NFLAG_DGRAM: The stream is run over UDP rather than the default TCP.

	NFLAG_ENCAPS: The protocol is running over a lower encapsulation layer 
		that provides additional packet control information, typically 
		packet size and flow control information.  HTTP and UDP transport
		both provide this type of service, HTTP explicitly and UDP 
		implicitly via its datagram service.  If this flag is set then the 
		lower-level read code overrides some error handling that normally 
		takes place at a higher level.  For example if a read of n bytes is 
		requested and the encapsulation layer reports that only m bytes, 
		m < n is present, this isn't treated as a read/timeout error.

	NFLAG_FIRSTREADOK: The first data read from the stream succeeded.  This
		is used to detect problems due to buggy firewall software, see the
		comments in io/tcp.c for details.

	NFLAG_ISSERVER: The stream is a server stream (default is client).

	NFLAG_LASTMSGR/NFLAG_LASTMSGR: This is the last message in the exchange.
		For a last-message read it means that the other side has indicated
		(for example through an HTTP "Connection: close") that this is the 
		case.  For a last-message write it means that we should indicate to
		the other side (for example through an HTTP "Connection: close") 
		that this is the case.

	NFLAG_USERSOCKET: The network socket was supplied by the user rather 
		than being created by cryptlib, so some actions such as socket
		shutdown should be skipped.

   The HTTP network flags are:

	NHFLAG_HTTP10: This is an HTTP 1.0 (rather than 1.1) HTTP stream.

	NHFLAG_HTTPPROXY/NFLAG_HTTPTUNNEL: HTTP proxy control flags.  When the 
		proxy flag is set, HTTP requests are sent as 
		"GET http://destination-url/location" (sent to the proxy) rather 
		than "GET location" (sent directly to the target host).  When the 
		tunnel flag is set, the initial network connection-establishment 
		request is sent as an explicit proxy command "CONNECT fqdn:port", 
		after which normal PDUs for the protocol being tunneled are sent.

		Note that the HTTP tunnel flag is currently never set by anything
		due to the removal of the SESSION_USEHTTPTUNNEL flag at a higher
		level, which was only ever set implicitly by being set in the TLS 
		altProtocolInfo, which in turn was never selected outside a 
		USE_CMP_TRANSPORT block.  The location at which it would be selected 
		(except for the presence of a USE_CMP_TRANSPORT ifdef) is at line 
		195 of session/sess_attr.c in versions up to 3.4.1.

	NHFLAG_HTTPGET/NFLAG_HTTPPOST: HTTP allowed-actions flags.

	NHFLAG_HTTPPOST_AS_GET: Modify the POST to encode it as a GET (ugh), for 
		b0rken servers that don't do POST */

#define STREAM_NFLAG_NONE		0x0000	/* No network flag */
#define STREAM_NFLAG_ISSERVER	0x0001	/* Stream is server rather than client */
#define STREAM_NFLAG_USERSOCKET	0x0002	/* Network socket was supplied by user */
#define STREAM_NFLAG_DGRAM		0x0004	/* Stream is UDP rather than TCP */
#define STREAM_NFLAG_LASTMSGR	0x0008	/* Last message in read exchange */
#define STREAM_NFLAG_LASTMSGW	0x0010	/* Last message in write exchange */
#define STREAM_NFLAG_ENCAPS		0x0020	/* Network transport is encapsulated */
#define STREAM_NFLAG_FIRSTREADOK 0x0040	/* First data read succeeded */
#define STREAM_NFLAG_MAX		0x007F	/* Maximum possible flag value */

#define STREAM_NHFLAG_NONE		0x0000	/* No network HTTP flag */
#define STREAM_NHFLAG_HTTP10	0x0001	/* HTTP 1.0 stream */
#define STREAM_NHFLAG_PROXY		0x0002	/* Use HTTP proxy format for requests */
#define STREAM_NHFLAG_TUNNEL	0x0004	/* Use HTTP proxy tunnel for connect */
#define STREAM_NHFLAG_GET		0x0008	/* Allow HTTP GET */
#define STREAM_NHFLAG_POST		0x0010	/* Allow HTTP POST */
#define STREAM_NHFLAG_POST_AS_GET 0x0020 /* Implement POST as GET */
#define STREAM_NHFLAG_WS_UPGRADE 0x0040	/* WebSockets Upgrade */
#define STREAM_NHFLAG_MAX		0x007F	/* Maximum possible flag value */

#define STREAM_NHFLAG_REQMASK \
		( STREAM_NHFLAG_GET | STREAM_NHFLAG_POST | \
		  STREAM_NHFLAG_POST_AS_GET )	/* Mask for permitted HTTP req.types */

/* Network transport-specific flags.  These are:

	FLAG_FLUSH: Used in writes to buffered streams to force a flush of data in 
		the stream buffers.
	
	FLAG_BLOCKING/FLAG_NONBLOCKING: Used to override the stream default 
		behaviour on reads and writes and force blocking/nonblocking I/O */

#define TRANSPORT_FLAG_NONE		0x00	/* No transport flag */
#define TRANSPORT_FLAG_FLUSH	0x01	/* Flush data on write */
#define TRANSPORT_FLAG_NONBLOCKING 0x02	/* Explicitly perform nonblocking read */
#define TRANSPORT_FLAG_BLOCKING	0x04	/* Explicitly perform blocking read */
#define TRANSPORT_FLAG_MAX		0x07	/* Maximum possible flag value */

/* URL component size limits, used when parsing a URL.  MAX_LOCATION_SIZE is
   set to a value larger than the canonical CRYPT_MAX_TEXTSIZE to deal with
   some SCEP URLs, which in the pathological case for EJBCA are 71 
   characters, 
   "/ejbca/publicweb/apply/scep/pkiclient.exe?operation=GetCACert&message=*",
   with an option to be even longer by ineserting an alias component between 
   the "scep" and the "pkiclient.exe" */

#define MIN_SCHEMA_SIZE			3
#define MAX_SCHEMA_SIZE			8
#define MIN_LOCATION_SIZE		3
#define MAX_LOCATION_SIZE		128
#define MIN_HOST_SIZE			MIN_DNS_SIZE
#define MAX_HOST_SIZE			MAX_DNS_SIZE

/* The size of the memory buffer used for virtual file streams, which are 
   used in CONFIG_NO_STDIO environments to store data before it's committed
   to backing storage */

#if defined( __MVS__ ) || defined( __VMCMS__ ) || \
	defined( __IBM4758__ ) || defined( __TESTIO__ )
  #define VIRTUAL_FILE_STREAM
#endif /* Nonstandard I/O environments */

#define STREAM_VFILE_BUFSIZE	16384

/****************************************************************************
*																			*
*								Stream Structures							*
*																			*
****************************************************************************/

#ifdef USE_TCP

/* The network-stream specific information stored as part of the STREAM
   data type.  Network streams can work on two levels.  At the lowest 
   level we have the raw network I/O layer, handled by calling 
   setAccessMethodXXX(), which hooks up the transport-level I/O functions.  
   If there's a requirement to replace the built-in network I/O it can be 
   done by replacing the functionality at this level.

   Layered on top of the transport-level I/O via setStreamLayerXXX() is an 
   optional higher layer protocol such as HTTP which is added by calling 
   the appropriate function to layer the higher-level protocol over the 
   transport-level I/O.  This goes via an intermediate buffering layer that
   deals with avoiding making repeated calls to the transport-level I/O 
   function, which is a particular problem for HTTP which has to take input 
   a character at a time.  The buffering layer reads ahead as far as it can 
   and then feeds the buffered result back to the caller as required.  We 
   also use write buffering to avoid potential problems with interactions 
   with some transport layers, details are given in the comment for the 
   buffered write function in net_trans.c.

   Alternatively, we can use setStreamLayerDirect() to just pass the call 
   straight down to the transport layer.

   The layering looks as follows:

	--- httpRead --- bufferedRead ---+--- tcpRead
									 |
	---------------------------------+

	--- httpWrite --- bufferedWrite --+---- tcpWrite
									  |
	----------------------------------+ */

struct NS;

typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *STM_CONNECT_FUNCTION_OPT )( INOUT_PTR struct ST *stream,
										   IN_PTR \
											const NET_CONNECT_INFO *connectInfo );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
		int ( *STM_DISCONNECT_FUNCTION_OPT )( INOUT_PTR struct ST *stream );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
		int ( *STM_GETMETADATA_FUNCTION_OPT )( INOUT_PTR struct ST *stream,
											   OUT_BUFFER_OPT( maxLength, *length ) \
													void *buffer,
											   IN_LENGTH_SHORT_Z const int maxLength, 
											   OUT_LENGTH_BOUNDED_SHORT_Z( maxLength ) \
													int *length );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
		int ( *STM_READ_FUNCTION )( INOUT_PTR struct ST *stream, 
									OUT_BUFFER( maxLength, *length ) \
										void *buffer, 
									IN_DATALENGTH const int maxLength, 
									OUT_DATALENGTH_Z int *length );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
		int ( *STM_WRITE_FUNCTION )( INOUT_PTR struct ST *stream, 
									 IN_BUFFER_OPT( maxLength ) \
										const void *buffer, 
									 IN_DATALENGTH_Z const int maxLength,
									 OUT_DATALENGTH_Z int *length );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *STM_TRANSPORTCONNECT_FUNCTION )( INOUT_PTR struct NS *netStream, 
												IN_BUFFER_OPT( hostNameLen ) \
													const char *hostName,
												IN_LENGTH_DNS_Z \
													const int hostNameLen, 
												IN_PORT const int port );
typedef STDC_NONNULL_ARG( ( 1 ) ) \
		void ( *STM_TRANSPORTDISCONNECT_FUNCTION )( INOUT_PTR struct NS *netStream, 
													IN_BOOL const BOOLEAN fullDisconnect );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
		int ( *STM_TRANSPORTREAD_FUNCTION )( INOUT_PTR struct NS *netStream, 
											 OUT_BUFFER( maxLength, *length ) \
												BYTE *buffer, 
											 IN_DATALENGTH const int maxLength, 
											 OUT_DATALENGTH_Z int *length, 
											 IN_FLAGS_Z( TRANSPORT ) \
												const int flags );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
		int ( *STM_TRANSPORTWRITE_FUNCTION )( INOUT_PTR struct NS *netStream, 
											  IN_BUFFER( maxLength ) \
												const BYTE *buffer,
											  IN_DATALENGTH const int maxLength, 
											  OUT_DATALENGTH_Z int *length, 
											  IN_FLAGS_Z( TRANSPORT ) \
												const int flags );
typedef CHECK_RETVAL_BOOL \
		BOOLEAN ( *STM_TRANSPORTOK_FUNCTION )( void );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
		int ( *STM_TRANSPORTCHECK_FUNCTION )( INOUT_PTR struct NS *netStream );
typedef STDC_NONNULL_ARG( ( 1, 2 ) ) \
		void ( *STM_VIRTUALGETERRORINFO_FUNCTION )( const void *virtualStateInfo,
													INOUT_PTR ERROR_INFO *errorInfo );

typedef struct NS {
	/* General information for the network stream.  For a server the
	   listenSocket is the (possibly shared) common socket that the server 
	   is listening on, the netSocket is the ephemeral socket used for
	   communications */
	STREAM_PROTOCOL_TYPE protocol;/* Network protocol type */
	CRYPT_SUBPROTOCOL_TYPE subProtocol;	/* Optional sub-protocol */
	SAFE_FLAGS nFlags;			/* Network-specific flags */
	SAFE_FLAGS nhFlags;			/* HTTP-specific flags */
#if defined( __FreeRTOS__ ) && defined( USE_FREERTOS_SOCKETS )
	void *netSocket, *listenSocket;/* Network socket, actually a Socket_t */
#elif defined( __WINDOWS__ )
	UINT_PTR netSocket, listenSocket;/* Network socket */
#else
	int netSocket, listenSocket;/* Network socket */
#endif /* System-specific socket data types */

	/* Network timeout information.  The timeout value depends on whether 
	   the stream is in the connect/handshake phase or the data transfer 
	   phase.  The handshake phase is logically treated as part of the 
	   connect phase even though from the stream point of view it's part of 
	   the data transfer phase.  Initially the stream timeout is set to the 
	   connect timeout and the saved timeout is set to the data transfer 
	   timeout.  Once the connect/handshake has completed, the stream 
	   timeout is set to the saved data transfer timeout and the saved 
	   timeout is cleared */
	int timeout, savedTimeout;	/* Network comms timeout */

	/* Network streams require separate read/write buffers for packet
	   assembly/disassembly so we provide a write buffer alongside the 
	   generic stream read buffer */
	BUFFER( writeBufSize, writeBufEnd ) \
	BYTE *writeBuffer;			/* Write buffer */
	int writeBufSize;			/* Total size of buffer */
	int writeBufEnd;			/* Last buffer position with valid data */

	/* Stream subtype-specific information required for some network stream
	   types */
#ifdef USE_EAP
	void *subTypeInfo;			/* Stream subtype-specific information */
	void *transportInfo;		/* UDP transport-specific information */
	int transportInfoPayloadSize;/* Size of payload for above */
#endif /* USE_EAP */

	/* General network-related information.  The server FQDN is held in 
	   dynamically-allocated storage, the optional path for HTTP is a pointer 
	   into the host string at the appropriate location */
	BUFFER_OPT_FIXED( hostLen ) \
	char *host;
	int hostLen;
	BUFFER_OPT_FIXED( pathLen ) \
	char *path;
	int pathLen;
	int port;					/* Host name, path on host, and port */
	BUFFER( CRYPT_MAX_TEXTSIZE / 2, clientAddressLen ) \
	char clientAddress[ ( CRYPT_MAX_TEXTSIZE / 2 ) + 4 ];
	int clientAddressLen;		/* Client IP address (dotted-decimal) */
	int clientPort;				/* Client port */
	BYTE clientAddressBinary[ 16 + 4 ];
	int clientAddressBinaryLen;	/* Client IP address (network byte order) */

	/* Sometimes we can fingerprint the application running on the peer 
	   system, which is useful for working around buggy implementations.  
	   The following value stores the peer application type, if known */
	STREAM_PEER_TYPE systemType;

	/* If a network error condition is fatal we set the persistentStatus 
	   value.  This is checked by the higher-level stream code and copied 
	   to to stream persistent status if required */
	int persistentStatus;

	/* Last-error information returned from lower-level code */
	ERROR_INFO errorInfo;

	/* Network stream read/write functions.  These general-purpose functions 
	   are for the higher-level entry points, they either call straight down 
	   to the transport-layer functions or allow the interposition of 
	   additional layers like HTTP.  For example for an HTTP network read 
	   (http_rd/wr.c) the path would be:

		readFunction -> bufferedTransportReadFunction -> 
										transportReadFunction
		
		http_rd.c:readFunction() -> bufferedTransportReadFunction -> 
										tcp_rw.c:readSocketFunction

	   For an HTTP over TLS read (net_trans.c) the path would be:
		
		http_rd.c:readFunction() -> bufferedTransportReadFunction -> 
										net_trans.c:transportVirtualReadFn 
										
	   For a direct network read the path would be:

		readFunction 

		tcp_rw.c:readSocketFunction.

	   In addition to the read/write functions there also exist optional
	   connect and disconnect functions and get metadata functions (eap.c) 
	   for when the protocol (e.g. TLS) is wrapped in a lower-level protocol 
	   (e.g. EAP) that requires an explicit negotiation as part of the 
	   connect/disconnect process */
	FNPTR connectFunctionOpt, disconnectFunctionOpt, getMetadataFunctionOpt;
	FNPTR readFunction, writeFunction;

	/* Transport-layer network functions.  These can be replaced with user-
	   defined transport mechanisms if required.  Curently they are set in
	   tcp.c for TCP transport, net_trans.c for virtual transport, and, as
	   an oddity, in tcp_err.c for ICMP probes for failed connections */
	FNPTR transportConnectFunction, transportDisconnectFunction;
	FNPTR transportReadFunction, transportWriteFunction;
	FNPTR transportOKFunction, transportCheckFunction;

	/* Virtual stream get/put/get-error-info and state pointers */
	FNPTR virtualGetDataFunction, virtualPutDataFunction;
	FNPTR virtualGetErrorInfoFunction;
	DATAPTR virtualStateInfo;	/* State info for virtual stream */

	/* Variable-length storage for the stream buffers */
	DECLARE_VARSTRUCT_VARS;
	} NET_STREAM_INFO;

/* The size of the network transport stream readahead/write buffers.  We try 
   and make them an optimal size to minimise unnecessary copying and not 
   negatively affect network I/O.  If we make them too big then we'll have 
   to move too much data around when we partially empty them, if we make 
   them too small then the buffering effect is suboptimal.  Since what we're 
   buffering is typically PKI traffic (and rarely UDP packets for UDP 
   transport), a 4K buffer should get most messages in one go.  This also 
   matches many network stacks that use 4K I/O buffers, the BSD default */

#define NETSTREAM_BUFFER_SIZE		4096
#if NETSTREAM_BUFFER_SIZE > MAX_INTLENGTH_SHORT
  #error NETSTREAM_BUFFER_SIZE exceeds buffered I/O length check size
#endif /* NETSTREAM_BUFFER_SIZE > MAX_INTLENGTH_SHORT */

/* Sanity-check a network stream */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN sanityCheckNetStream( const NET_STREAM_INFO *netStream );
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

#else

typedef void *NET_STREAM_INFO;	/* Dummy for function prototypes */

#endif /* USE_TCP */

/****************************************************************************
*																			*
*							Stream Function Prototypes						*
*																			*
****************************************************************************/

/* Stream query functions to determine whether a stream is a memory-mapped 
   file stream, a virtual file stream, or a pseudo-stream.  The memory-
   mapped stream check is used when we can eliminate extra buffer allocation 
   if all data is available in memory.  The virtual file stream check is 
   used where the low-level access routines have converted a file on a 
   CONFIG_NO_STDIO system to a memory stream that acts like a file stream.
   The pseudo-stream is used for testing purposes to emulate a standard
   stream like a network stream */

#define sIsMemMappedStream( stream ) \
		( ( ( stream )->type == STREAM_TYPE_FILE ) && \
		  TEST_FLAG( ( stream )->flags, STREAM_FFLAG_MMAPPED ) )
#ifdef VIRTUAL_FILE_STREAM 
  #define sIsVirtualFileStream( stream ) \
		  ( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			TEST_FLAG( ( stream )->flags, STREAM_MFLAG_VFILE ) )
#else
  #define sIsVirtualFileStream( stream )	FALSE
#endif /* VIRTUAL_FILE_STREAM */
#ifndef CONFIG_CONSERVE_MEMORY_EXTRA
  #define sIsPseudoStream( stream ) \
		  ( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			TEST_FLAG( ( stream )->flags, STREAM_MFLAG_PSEUDO ) )
  #ifdef CONFIG_FUZZ
	#define sIsPseudoHTTPStream( stream ) \
			( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			  TEST_FLAGS( ( stream )->flags, \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_HTTP ), \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_HTTP ) ) )
	#define sIsPseudoHTTPRawStream( stream ) \
			( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			  TEST_FLAGS( ( stream )->flags, \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_HTTP | \
							STREAM_MFLAG_PSEUDO_RAW ), \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_HTTP | \
							STREAM_MFLAG_PSEUDO_RAW ) ) )
	#define sIsPseudoEAPStream( stream ) \
			( ( ( stream )->type == STREAM_TYPE_MEMORY ) && \
			  TEST_FLAGS( ( stream )->flags, \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_RAW ), \
						  ( STREAM_MFLAG_PSEUDO | STREAM_MFLAG_PSEUDO_RAW ) ) )
  #endif /* CONFIG_FUZZ */
#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

/* Prototypes for functions in file.c */

#ifdef USE_FILES
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int fileRead( INOUT_PTR STREAM *stream, 
			  OUT_BUFFER( length, *bytesRead ) void *buffer, 
			  IN_DATALENGTH const int length, 
			  OUT_DATALENGTH_Z int *bytesRead );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int fileWrite( INOUT_PTR STREAM *stream, 
			   IN_BUFFER( length ) const void *buffer, 
			   IN_DATALENGTH const int length );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int fileFlush( INOUT_PTR STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int fileSeek( INOUT_PTR STREAM *stream,
			  IN_DATALENGTH_Z const long position );
#endif /* USE_FILES */

#ifdef USE_TCP

/* Network URL processing functions in net_url.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int parseURL( OUT_PTR URL_INFO *urlInfo, 
			  IN_BUFFER( urlLen ) const BYTE *url, 
			  IN_LENGTH_SHORT const int urlLen,
			  IN_PORT_OPT const int defaultPort, 
			  IN_ENUM_OPT( URL_TYPE ) const URL_TYPE urlTypeHint,
			  IN_BOOL const BOOLEAN preParseOnly );

/* Network proxy functions in net_proxy.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int connectViaSocksProxy( INOUT_PTR STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int connectViaHttpProxy( INOUT_PTR STREAM *stream, 
						 INOUT_PTR ERROR_INFO *errorInfo );
#if defined( __WIN32__ )
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int findProxyUrl( OUT_BUFFER( proxyMaxLen, *proxyLen ) char *proxy, 
				  IN_LENGTH_DNS const int proxyMaxLen, 
				  OUT_LENGTH_BOUNDED_Z( proxyMaxLen ) int *proxyLen,
				  IN_BUFFER( urlLen ) const char *url, 
				  IN_LENGTH_DNS const int urlLen );
#else
  #define findProxyUrl( proxy, proxyMaxLen, proxyLen, url, urlLen )	CRYPT_ERROR_NOTFOUND
#endif /* Win32 */

/* Prototypes for functions in net_trans.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int bufferedTransportRead( INOUT_PTR STREAM *stream, 
						   OUT_BUFFER( maxLength, *length ) BYTE *buffer, 
						   IN_DATALENGTH const int maxLength, 
						   OUT_DATALENGTH_Z int *length, 
						   IN_FLAGS_Z( TRANSPORT ) const int flags );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int bufferedTransportWrite( INOUT_PTR STREAM *stream, 
							IN_BUFFER( maxLength ) const BYTE *buffer, 
							IN_DATALENGTH const int maxLength, 
							OUT_DATALENGTH_Z int *length, 
							IN_FLAGS_Z( TRANSPORT ) const int flags );

/* Network access mapping functions */

STDC_NONNULL_ARG( ( 1 ) ) \
void setAccessMethodTCP( INOUT_PTR NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerHTTP( INOUT_PTR NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerEAP( INOUT_PTR NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerDirect( INOUT_PTR NET_STREAM_INFO *netStream );
STDC_NONNULL_ARG( ( 1 ) ) \
void setAccessMethodTransportVirtual( INOUT_PTR NET_STREAM_INFO *netStream );

#endif /* USE_TCP */

#endif /* _STREAM_INT_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
