/****************************************************************************
*																			*
*					  cryptlib TLS 1.3 Crypto Routines						*
*					 Copyright Peter Gutmann 2019-2024						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "tls.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
  #include "session/session.h"
  #include "session/tls.h"
#endif /* Compiler-specific includes */

/* TLS 1.3 has an insanely complex key derivation process that, like a 
   Feistel cipher where the designer just kept adding more rounds until it 
   got too hard to analyse, keeps running HKDF over everything in sight 
   until it cries Uncle.  For a full diagram of what's going on see Figure
   2 and Table 2 of "A Cryptographic Analysis of the TLS 1.3 Handshake 
   Protocol" by Dowling, Fischlin, Gunther and Stebila.
   
   There are two primitives used, HKDF-Extract( Key, Data ) from RFC 5869 
   which is just HMAC( Data, Key ) (yes, the data is the key and the key is 
   the data), and Derive-Secret( Key, Label, Messages ), which has a complex 
   derivation:

	Derive-Secret( Key, Label, Messages ) ->
		HKDF-Expand-Label( Key, Label, Hash( Messages ), Hashlength ) ->
			HKDF-Expand( Key, HkdfLabel, Hashlength )

   where HkdfLabel is the Label and Hash( Messages ) and some other stuff 
   in a single structure:

	uint16	length = Hashlength
	byte	labelLength
	byte[]		label = "tls13 " + Label
	byte	dataLength = Hashlength
	byte[]		data = Hash( Messages )
	byte	HKDF -> HMAC suffix = 0x01, see below

   The KDF process begins with Key = Data = zero bytes of length Hashlength, 
   assuming SHA-256 we'll use 32 in this example, and the key for step n+1 
   being the output of step n:

	HKDF-Extract( 0[32], 0[32] )						// HKDF #1

	HKDF-Expand-Label( HKDF #1, "derived",				// HKDF #2
					   Hash(""), 32 )

	HKDF-Extract( HKDF #2, (EC)DHE Value )				// HKDF #3

		HKDF-Extract( HKDF #3, "c hs traffic",			// HKDF #3a
					  Hash( ClientHello || ServerHello, 32 )
		HKDF-Extract( HKDF #3, "s hs traffic",			// HKDF #3b
					  Hash( ClientHello || ServerHello, 32 )

	HKDF-Expand-Label( HKDF #3, "derived",				// HKDF #4
					   Hash(""), 32 )

	HKDF-Extract( HKDF #4, 0[32] )						// HKDF #5

		HKDF-Extract( HKDF #5, "c ap traffic",			// HKDF #5a
					  Hash( ClientHello || ... || ServerFinished, 32 )
		HKDF-Extract( HKDF #5, "s ap traffic",			// HKDF #5b
					  Hash( ClientHello || ... || ServerFinished, 32 )
	  [	HKDF-Extract( HKDF #5, "exp master",			// HKDF #5c
					  Hash( ClientHello || ... || ServerFinished, 32 ) ]
	  [	HKDF-Extract( HKDF #5, "res master",			// HKDF #5c
					  Hash( ClientHello || ... || ClientFinished, 32 ) ]

   The encryption keys are generated from the output of HKDF #3a/b and 
   HKDF #5a/b:

	HKDF-Expand-Label( HKDF #Xa, "key", {}, 32 )		// Client write key
	HKDF-Expand-Label( HKDF #Xa, "iv", {}, 32 )			// Client write IV
	HKDF-Expand-Label( HKDF #Xb, "key", {}, 32 )		// Server write key
	HKDF-Expand-Label( HKDF #Xb, "iv", {}, 32 )			// Server write IV

   What all of this requires is a new HMAC key each time, which would make 
   for a phenomenal burn of encryption contexts.  To deal with this we use 
   direct HMAC access and take advantage of the fact that we never output 
   more than Hashlength bytes to turn the HKDF() call into an HMAC() call, 
   where the first HKDF round is defined as:

	T(0) = empty string (zero length)
	T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)

   In other words it's HMAC( Key, Data || 0x01 ) which the HkdfLabel-
   creation process does for us by appending 0x01 to the HkdfLabel */

#ifdef USE_TLS13

/* Make sure that the necessary crypto prerequisites for TLS 1.3 are met */

#if !defined( USE_ECDH ) || !defined( USE_ECDSA ) || \
	!defined( USE_GCM ) || !defined( USE_PSS )
  #error TLS 1.3 needs ECDH, ECDSA, AES-GCM, and RSA-PSS enabled.
#endif /* !( USE_ECDH && USE_ECDSA && USE_GCM && USE_PSS ) */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Create the HkdfLabel structure that's HMACed to produce PRF output:

	uint16	hkdfOutputLength
	byte	labelLength
	byte[]		label = "tls13 " + Label
	byte	dataLength = Hashlength
	byte[]		data = Hash( Messages )
	byte	HKDF -> HMAC suffix = 0x01
	
   This currently assumes the use of SHA-2, the only hash algorithm defined 
   for TLS 1.3.
   
   The ( hash, hashLength ) parameter is a bit complicated, it can either be
   a hash of the handshake messages so far, or ( NULL, hashLength ) to 
   indicate that a hash of an empty message has to be used, because reasons,
   or ( NULL, 0 ) to indicate that no hash at all is used */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
static int createHkdfLabel( OUT_BUFFER( dataMaxLength, *dataLength ) \
								void *data,
							IN_LENGTH_SHORT_MIN( 32 ) \
								const int dataMaxLength,
							OUT_LENGTH_BOUNDED_Z( dataMaxLength ) \
								int *dataLength,
							IN_LENGTH_SHORT_MIN( 8 ) const int hkdfOutputLength,
							IN_BUFFER( labelLength ) const void *label,
							IN_LENGTH_SHORT_MIN( 2 ) const int labelLength,
							IN_BUFFER_OPT( hashLength ) const void *hash,
							IN_LENGTH_SHORT_Z const int hashLength )
	{
	STREAM stream;
	int status;

	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( ( hash == NULL ) || \
			isReadPtrDynamic( hash, hashLength ) );

	REQUIRES( isShortIntegerRangeMin( hkdfOutputLength, 8 ) );
	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 32 ) );
	REQUIRES( isShortIntegerRangeMin( labelLength, 2 ) );
	REQUIRES( ( hash == NULL && hashLength == 0 ) || \
			  ( hashLength == bitsToBytes( 256 ) || \
				hashLength == bitsToBytes( 384 ) || \
				hashLength == bitsToBytes( 512 ) ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) );
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* If we haven't been passed any data to hash then we slot in a hash of 
	   the empty string */
	if( hash == NULL && hashLength != 0 )
		{
		typedef struct {
			BUFFER_FIXED( hashParam ) const BYTE *hash;
			const int hashParam;
			} FIXED_HASH_INFO;
		static const FIXED_HASH_INFO fixedHashInfo[] = {
			{ ( const BYTE * )		/* For pedantic compilers */
			  "\xE3\xB0\xC4\x42\x98\xFC\x1C\x14"
			  "\x9A\xFB\xF4\xC8\x99\x6F\xB9\x24"
			  "\x27\xAE\x41\xE4\x64\x9B\x93\x4C"
			  "\xA4\x95\x99\x1B\x78\x52\xB8\x55", 32 },
#ifdef USE_SHA2_EXT
			/* SHA2-384 and SHA2-512 are only available on systems with 64-bit data 
			   type support */
			{ ( const BYTE * )		/* For pedantic compilers */
			  "\x38\xB0\x60\xA7\x51\xAC\x96\x38"
			  "\x4C\xD9\x32\x7E\xB1\xB1\xE3\x6A"
			  "\x21\xFD\xB7\x11\x14\xBE\x07\x43"
			  "\x4C\x0C\xC7\xBF\x63\xF6\xE1\xDA"
			  "\x27\x4E\xDE\xBF\xE7\x6F\x65\xFB"
			  "\xD5\x1A\xD2\xF1\x48\x98\xB9\x5B", 48 },
			{ ( const BYTE * )		/* For pedantic compilers */
			  "\xCF\x83\xE1\x35\x7E\xEF\xB8\xBD"
			  "\xF1\x54\x28\x50\xD6\x6D\x80\x07"
			  "\xD6\x20\xE4\x05\x0B\x57\x15\xDC"
			  "\x83\xF4\xA9\x21\xD3\x6C\xE9\xCE"
			  "\x47\xD0\xD1\x3C\x5D\x85\xF2\xB0"
			  "\xFF\x83\x18\xD2\x87\x7E\xEC\x2F"
			  "\x63\xB9\x31\xBD\x47\x41\x7A\x81"
			  "\xA5\x38\x32\x7A\xF9\x27\xDA\x3E", 64 },
#endif /* USE_SHA2_EXT */
				{ NULL, 0 }, { NULL, 0 }
			};
		LOOP_INDEX i;

		/* Find the matching hash data for this algorithm and hash size */
		LOOP_SMALL( i = 0, 
					i < FAILSAFE_ARRAYSIZE( fixedHashInfo, FIXED_HASH_INFO ) && \
						fixedHashInfo[ i ].hashParam != 0,
					i++ )
			{
			ENSURES( LOOP_INVARIANT_SMALL( i, 0, 
										   FAILSAFE_ARRAYSIZE( fixedHashInfo, \
															   FIXED_HASH_INFO ) - 1 ) );

			if( fixedHashInfo[ i ].hashParam == hashLength )
				{
				hash = fixedHashInfo[ i ].hash;
				break;
				}
			}
		ENSURES( LOOP_BOUND_OK );
		ENSURES( i < FAILSAFE_ARRAYSIZE( fixedHashInfo, FIXED_HASH_INFO ) );
		}

	sMemOpen( &stream, data, dataMaxLength );

	/* Write the HKDF Label structure */
	writeUint16( &stream, hkdfOutputLength );
	sputc( &stream, 6 + labelLength );
	swrite( &stream, "tls13 ", 6 );
	swrite( &stream, label, labelLength );
	sputc( &stream, hashLength );
	if( hash != NULL )
		swrite( &stream, hash, hashLength );

	/* Write the suffix byte needed to convert the straight HMAC call into 
	   a single call to HKDF */
	status = sputc( &stream, 0x01 );
	if( cryptStatusOK( status ) )
		*dataLength = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*								Crypto Functions							*
*																			*
****************************************************************************/

/* For TLS 1.3 GCM the IV processing was changed from the TLS classic 
   implicit+explicit IV to a form that matches what's done in the Bernstein 
   suite:

	|<--------------- 12 bytes ---------------->|
	+---------------+---------------------------+
	| 32-bit zeroes	|	64-bit sequence no.		|
	+---------------+---------------------------+
						XOR
	+-------------------------------------------+
	|				TLS read/write IV			|
	+-------------------------------------------+
						 |
						 v
	+-------------------------------------------+
	|				96-bit IV					|
	+-------------------------------------------+

   so we have to use a custom function to set up the value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initCryptGCMTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					   IN_BOOL const BOOLEAN isRead )
	{
	CRYPT_CONTEXT iCryptContext;
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	STREAM stream;
	MESSAGE_DATA msgData;
	BYTE ivBuffer[ CRYPT_MAX_IVSIZE + 8 ];
	const BYTE *ivPtr;
	long seqNo;
	LOOP_INDEX i;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBooleanValue( isRead ) );						 

	/* Set up the appropriate values depending on whether it's a read or a 
	   write */
	if( isRead )
		{
		seqNo = tlsInfo->readSeqNo;
		ivPtr = tlsInfo->aeadReadSalt;
		iCryptContext = sessionInfoPtr->iCryptInContext;
		}
	else
		{
		seqNo = tlsInfo->writeSeqNo;
		ivPtr = tlsInfo->aeadWriteSalt;
		iCryptContext = sessionInfoPtr->iCryptOutContext;
		}

	/* Assemble the TLS 1.3 GCM IV */
	sMemOpen( &stream, ivBuffer, CRYPT_MAX_IVSIZE );
	writeUint32( &stream, 0 );				/* 32 bits of zeroes */
	status = writeUint64( &stream, seqNo );
	sMemDisconnect( &stream );
	ENSURES( cryptStatusOK( status ) );
	LOOP_MED( i = 0, i < GCM_IV_SIZE, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, GCM_IV_SIZE - 1 ) );

		ivBuffer[ i ] ^= ivPtr[ i ];
		}
	ENSURES( LOOP_BOUND_OK );

	/* Load the IV */
	setMessageData( &msgData, ivBuffer, GCM_IV_SIZE );
	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							 &msgData, CRYPT_CTXINFO_IV ) );
	}

/****************************************************************************
*																			*
*								Signature Functions							*
*																			*
****************************************************************************/

/* Create the TLS 1.3 session hash, which is a hash of a prefix string 
   followed by the transcript hash */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createSessionHashTLS13( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						    IN_HANDLE const CRYPT_CONTEXT iHashContext,
							const BOOLEAN isServerVerify )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const char *prefixString;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	int hashValueLength, prefixStringLength, status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isBooleanValue( isServerVerify ) );

	/* Set up the appropriate hash prefix strings */
	if( isServerVerify )
		{
		prefixString = \
			"                                                                "
			"TLS 1.3, server CertificateVerify\x00";
			/* 64 spaces + context string + nul */
		prefixStringLength = 64 + 33 + 1;
		}
	else
		{
		prefixString = \
			"                                                                "
			"TLS 1.3, client CertificateVerify\x00";
			/* 64 spaces + context string + nul */
		prefixStringLength = 64 + 33 + 1;
		}

	/* Get the transcript hash value */
	setMessageData( &msgData, hashValue, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashValueLength = msgData.length;
	DEBUG_DUMP_DATA_LABEL( isServerVerify ? \
								"Transcript hash (server cert_verify):" : \
								"Transcript hash (client cert_verify):" ,
						   hashValue, hashValueLength );

	/* If it's a special-snowflake algorithm that wants to see the entire 
	   message being signed then we need to record details of the message
	   rather than just its hash */
#ifdef USE_ED25519
	if( isBernsteinAlgo( handshakeInfo->authAlgo ) )
		{
		handshakeInfo->transcriptPrefixString = prefixString;
		handshakeInfo->transcriptPrefixStringLength = prefixStringLength;
		REQUIRES( rangeCheck( hashValueLength, 1, CRYPT_MAX_HASHSIZE ) );
		memcpy( handshakeInfo->transcriptHash, hashValue, hashValueLength );
		handshakeInfo->transcriptHashLength = hashValueLength;
		
		return( CRYPT_OK );
		}
#endif /* USE_ED25519 */

	/* Hash the prefix string and the transcript hash to get the hash value
	   that's actually signed/verified */
	setMessageCreateObjectInfo( &createInfo, 
								handshakeInfo->keyexSigHashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	handshakeInfo->sessionHashContext = createInfo.cryptHandle;
	if( handshakeInfo->keyexSigHashAlgoParam > 0 )
		{
		status = krnlSendMessage( handshakeInfo->sessionHashContext, 
						IMESSAGE_SETATTRIBUTE,
						( MESSAGE_CAST ) &handshakeInfo->keyexSigHashAlgoParam, 
						CRYPT_CTXINFO_BLOCKSIZE );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( handshakeInfo->sessionHashContext, 
								  IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) prefixString, 
								  prefixStringLength );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( handshakeInfo->sessionHashContext, 
								  IMESSAGE_CTX_HASH, hashValue, 
								  hashValueLength );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( handshakeInfo->sessionHashContext, 
								  IMESSAGE_CTX_HASH, "", 0 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( handshakeInfo->sessionHashContext, 
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->sessionHashContext = CRYPT_ERROR;
		return( status );
		}

	return( CRYPT_OK );
	}

/* Create the TLS 1.3 Finished message:

	HMAC-Key = HKDF-Expand-Label( Write-Secret, "finished", {}, 32 )

	Finished = HMAC( HMAC-Key, Transcript-Hash ) 
	
	Transcript-Hash-Server = hash( ClientHello || ... || CertificateRequest )
	Transcript-Hash-Client = hash( ClientHello || ... || ServerFinished ) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int createFinishedTLS13( OUT_BUFFER( finishedValueMaxLen, \
									 *finishedValueLen ) \
							void *finishedValue,
						 IN_LENGTH_SHORT_MIN( 20 ) \
							const int finishedValueMaxLen,
						 OUT_LENGTH_BOUNDED_SHORT_Z( finishedValueMaxLen ) \
							 int *finishedValueLen,
						 IN_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						 IN_HANDLE const CRYPT_CONTEXT iHashContext,
						 IN_BOOL const BOOLEAN isServerFinished )
	{
	MAC_FUNCTION_ATOMIC macFunctionAtomic;
	MESSAGE_DATA msgData;
	BYTE hkdfLabel[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	BYTE hkdfValue[ CRYPT_MAX_HASHSIZE + 8 ];
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	const int hashParam = handshakeInfo->integrityAlgoParam;
	int hkdfLabelLength, hashValueLength, status;

	assert( isWritePtrDynamic( finishedValue, finishedValueMaxLen ) );
	assert( isWritePtr( finishedValueLen, sizeof( int ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( isShortIntegerRangeMin( finishedValueMaxLen, 20 ) );
	REQUIRES( finishedValueMaxLen >= hashParam );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isBooleanValue( isServerFinished ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( finishedValueMaxLen ) ); 
	memset( finishedValue, 0, min( 16, finishedValueMaxLen ) );
	*finishedValueLen = 0;

	getMacAtomicFunction( CRYPT_ALGO_HMAC_SHA2, &macFunctionAtomic );

	/* Get the transcript hash value */
	setMessageData( &msgData, hashValue, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	hashValueLength = msgData.length;
	DEBUG_DUMP_DATA_LABEL( isServerFinished ? \
								"Transcript hash (server finished):" : \
								"Transcript hash (client finished):", 
						   hashValue, hashValueLength );

	/* Compute the HMAC key */
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, hashParam, "finished", 8, 
							  NULL, 0 );
	if( cryptStatusError( status ) )
		return( status );
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam,
					   isServerFinished ? \
							handshakeInfo->tls13ServerSecret : \
							handshakeInfo->tls13ClientSecret, hashParam, 
					   hkdfLabel, hkdfLabelLength );

	/* MAC the transcript hash */
	macFunctionAtomic( finishedValue, finishedValueMaxLen, hashParam,
					   hkdfValue, hashParam, hashValue, hashValueLength );
	*finishedValueLen = hashParam;
	zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );
	DEBUG_DUMP_DATA_LABEL( isServerFinished ? \
								"Server finished value:" : \
								"Client finished value:", 
						   finishedValue, hashParam );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								KDF Functions								*
*																			*
****************************************************************************/

/* Perform the first five sets of HKDF hashing to create the handshake
   secrets:

	HKDF-Extract( 0[32], 0[32] )						// HKDF #1

	HKDF-Expand-Label( HKDF #1, "derived",				// HKDF #2
					   Hash(""), 32 )

	HKDF-Extract( HKDF #2, (EC)DHE Value  )				// HKDF #3

		HKDF-Extract( HKDF #3, "c hs traffic",			// HKDF #3a
					  Hash( ClientHello || ServerHello, 32 )
		HKDF-Extract( HKDF #3, "s hs traffic",			// HKDF #3b
					  Hash( ClientHello || ServerHello, 32 ) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int createHandshakeSecret( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	MAC_FUNCTION_ATOMIC macFunctionAtomic;
	static const BYTE zeroBytes[ CRYPT_MAX_HASHSIZE ] = { 0 };
	BYTE hkdfLabel[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	BYTE hkdfValue[ CRYPT_MAX_HASHSIZE + 8 ];
	const int hashParam = handshakeInfo->integrityAlgoParam;
	int hkdfLabelLength, status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	getMacAtomicFunction( CRYPT_ALGO_HMAC_SHA2, &macFunctionAtomic );

	/* Compute HKDF #1 */
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam,
					   zeroBytes, hashParam, zeroBytes, hashParam );

	/* Compute HKDF #2 */
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, hashParam, "derived", 7, 
							  NULL, hashParam );
	if( cryptStatusError( status ) )
		return( status );
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam,
					   hkdfValue, hashParam, hkdfLabel, hkdfLabelLength );

	/* Compute HKDF #3 */
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam, 
					   hkdfValue, hashParam,
					   handshakeInfo->tls13KeyexValue,
					   handshakeInfo->tls13KeyexValueLen );
	
	/* Compute HKDF #3a */
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, hashParam, 
							  "c hs traffic", 12, 
							  handshakeInfo->helloHash, 
							  handshakeInfo->helloHashSize );
	if( cryptStatusError( status ) )
		{
		zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	macFunctionAtomic( handshakeInfo->tls13ClientSecret, CRYPT_MAX_HASHSIZE, 
					   hashParam, hkdfValue, hashParam, 
					   hkdfLabel, hkdfLabelLength );

	/* Compute HKDF #3b */
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, hashParam, 
							  "s hs traffic", 12, 
							  handshakeInfo->helloHash, 
							  handshakeInfo->helloHashSize );
	if( cryptStatusError( status ) )
		{
		zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	macFunctionAtomic( handshakeInfo->tls13ServerSecret, CRYPT_MAX_HASHSIZE, 
					   hashParam, hkdfValue, hashParam, 
					   hkdfLabel, hkdfLabelLength );

	/* Save a copy of the HKDF state for later HKDF'ing */
	REQUIRES( rangeCheck( hashParam, 1, CRYPT_MAX_HASHSIZE ) );
	memcpy( handshakeInfo->tls13MasterSecret, hkdfValue, hashParam );
	zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );

	DEBUG_DUMP_DATA_LABEL( ( handshakeInfo->tls13SuiteInfoPtr != NULL ) ? \
								"Handshake secret (server):" : \
								"Handshake secret (client):",
						   handshakeInfo->tls13MasterSecret, hashParam );
	DEBUG_DUMP_DATA_LABEL( ( handshakeInfo->tls13SuiteInfoPtr != NULL ) ? \
								"Client HS write secret (server):" : \
								"Client HS write secret (client):",
						   handshakeInfo->tls13ClientSecret, hashParam );
	DEBUG_DUMP_DATA_LABEL( ( handshakeInfo->tls13SuiteInfoPtr != NULL ) ? \
								"Server HS write secret (server):" : \
								"Server HS write secret (client):",
						   handshakeInfo->tls13ServerSecret, hashParam );

	return( CRYPT_OK );
	}

/* Perform the final five sets of HKDF hashing to create the application data
   secrets:

	HKDF-Expand-Label( HKDF #3, "derived",				// HKDF #4
					   Hash(""), 32 )

	HKDF-Extract( HKDF #4, 0[32] )						// HKDF #5

		HKDF-Extract( HKDF #5, "c ap traffic",			// HKDF #5a
					  Hash( ClientHello || ... || ServerFinished, 32 )
		HKDF-Extract( HKDF #5, "s ap traffic",			// HKDF #5b
					  Hash( ClientHello || ... || ServerFinished, 32 )
	  [	HKDF-Extract( HKDF #5, "exp master",			// HKDF #5c
					  Hash( ClientHello || ... || ServerFinished, 32 ) ]
	  [	HKDF-Extract( HKDF #5, "res master",			// HKDF #5c
					  Hash( ClientHello || ... || ServerFinished, 32 ) ] */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int createAppdataSecret( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	MAC_FUNCTION_ATOMIC macFunctionAtomic;
	static const BYTE zeroBytes[ CRYPT_MAX_HASHSIZE ] = { 0 };
	BYTE hkdfLabel[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	BYTE hkdfValue[ CRYPT_MAX_HASHSIZE + 8 ];
	const int hashParam = handshakeInfo->integrityAlgoParam;
	int hkdfLabelLength, status;

	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	getMacAtomicFunction( CRYPT_ALGO_HMAC_SHA2, &macFunctionAtomic );

	/* Restore the HKDF state from earlier HKDF'ing */
	REQUIRES( rangeCheck( hashParam, 1, CRYPT_MAX_HASHSIZE ) );
	memcpy( hkdfValue, handshakeInfo->tls13MasterSecret, hashParam );

	/* Compute HKDF #4 */
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, hashParam, "derived", 7, 
							  NULL, hashParam );
	if( cryptStatusError( status ) )
		return( status );
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam,
					   hkdfValue, hashParam, hkdfLabel, hkdfLabelLength );

	/* Compute HKDF #5 */
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam, 
					   hkdfValue, hashParam, zeroBytes, hashParam );
	
	/* Compute HKDF #5a */
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, hashParam, 
							  "c ap traffic", 12, 
							  handshakeInfo->sessionHash, 
							  handshakeInfo->sessionHashSize );
	if( cryptStatusError( status ) )
		{
		zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	macFunctionAtomic( handshakeInfo->tls13ClientSecret, CRYPT_MAX_HASHSIZE, 
					   hashParam, hkdfValue, hashParam, 
					   hkdfLabel, hkdfLabelLength );

	/* Compute HKDF #5b */
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, hashParam, 
							  "s ap traffic", 12, 
							  handshakeInfo->sessionHash, 
							  handshakeInfo->sessionHashSize );
	if( cryptStatusError( status ) )
		{
		zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	macFunctionAtomic( handshakeInfo->tls13ServerSecret, CRYPT_MAX_HASHSIZE, 
					   hashParam, hkdfValue, hashParam, 
					   hkdfLabel, hkdfLabelLength );

	/* Save a copy of the HKDF state for later HKDF'ing */
	REQUIRES( rangeCheck( hashParam, 1, CRYPT_MAX_HASHSIZE ) );
	memcpy( handshakeInfo->tls13MasterSecret, hkdfValue, hashParam );
	zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );

	DEBUG_DUMP_DATA_LABEL( ( handshakeInfo->tls13SuiteInfoPtr != NULL ) ? \
								"Master secret (server):" : \
								"Master secret (client):",
						   handshakeInfo->tls13MasterSecret, hashParam );
	DEBUG_DUMP_DATA_LABEL( ( handshakeInfo->tls13SuiteInfoPtr != NULL ) ? \
								"Client Appdata write secret (server):" : \
								"Client Appdata write secret (client):",
						   handshakeInfo->tls13ClientSecret, hashParam );
	DEBUG_DUMP_DATA_LABEL( ( handshakeInfo->tls13SuiteInfoPtr != NULL ) ? \
								"Server Appdata write secret (server):" : \
								"Server Appdata write secret (client):",
						   handshakeInfo->tls13ServerSecret, hashParam );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Key-load Functions							*
*																			*
****************************************************************************/

/* Recreate the encryption contexts, which is necessary for TLS 1.3 because
   it changes encryption mid-stream.  In theory we could also update the 
   code to allow a CRYPT_IATTRIBUTE_REKEY for the symmetric cipher as we 
   already do for Poly1305 which needs a rekey on each block, however it's
   not clear whether this won't cause problems with some hardware 
   implementations which don't allow a new key to be reloaded without
   reinitialising the (hardware) context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int recreateSecurityContexts( INOUT_PTR SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
#if defined( USE_POLY1305 )
	const BOOLEAN isBernsteinSuite = \
				( TEST_FLAG( sessionInfoPtr->protocolFlags, \
							 TLS_PFLAG_BERNSTEIN ) ) ? TRUE : FALSE;
#endif /* USE_POLY1305 */
	int status;

	/* Destroy the existing encryption and optional MAC contexts */
	krnlSendNotifier( sessionInfoPtr->iCryptInContext,
					  IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCryptInContext = CRYPT_ERROR;
	krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
					  IMESSAGE_DECREFCOUNT );
	sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
#if defined( USE_POLY1305 )
	if( isBernsteinSuite )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthInContext = CRYPT_ERROR;
		krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
		}
#endif /* USE_POLY1305 */

	/* Create the replacement contexts */
	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;
#if defined( USE_POLY1305 )
	if( cryptStatusOK( status ) && isBernsteinSuite )
		{
		setMessageCreateObjectInfo( &createInfo, 
									sessionInfoPtr->integrityAlgo );
		status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			{
			sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;
			setMessageCreateObjectInfo( &createInfo, 
										sessionInfoPtr->integrityAlgo );
			status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
									  OBJECT_TYPE_CONTEXT );
			}
		if( cryptStatusOK( status ) )
			sessionInfoPtr->iAuthOutContext = createInfo.cryptHandle;
		}
#endif /* USE_POLY1305 */
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using GCM then we also need to change the encryption mode 
	   from the default CBC */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) ) 
		{
		static const int mode = CRYPT_MODE_GCM;	/* int vs.enum */

		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &mode,
								  CRYPT_CTXINFO_MODE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &mode,
									  CRYPT_CTXINFO_MODE );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Load encryption keys and IVs from the HKDF output:

	HKDF-Expand-Label( HKDF #Xa, "key", {}, 32 )		// Client write key
	HKDF-Expand-Label( HKDF #Xa, "iv", {}, 32 )			// Client write IV
	HKDF-Expand-Label( HKDF #Xb, "key", {}, 32 )		// Server write key
	HKDF-Expand-Label( HKDF #Xb, "iv", {}, 32 )			// Server write IV */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int loadKeys( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MAC_FUNCTION_ATOMIC macFunctionAtomic;
	MESSAGE_DATA msgData;
	BYTE hkdfLabel[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	BYTE hkdfValue[ CRYPT_MAX_HASHSIZE + 8 ];
	const BOOLEAN isClient = isServer( sessionInfoPtr ) ? FALSE : TRUE;
	const int hashParam = handshakeInfo->integrityAlgoParam;
	int hkdfLabelLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	getMacAtomicFunction( CRYPT_ALGO_HMAC_SHA2, &macFunctionAtomic );

	/* If we're using a special-snowflake MAC then we have to load a dummy 
	   key since it needs a rekey on each packet, and to do that there needs 
	   to be an initial key loaded */
#if defined( USE_POLY1305 )
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_BERNSTEIN ) )
		{
		static const BYTE dummyKey[ 32 ] = { 0 };

		setMessageData( &msgData, ( MESSAGE_CAST ) dummyKey, 32 );
		status = krnlSendMessage( sessionInfoPtr->iAuthInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( sessionInfoPtr->iAuthOutContext,
									  IMESSAGE_SETATTRIBUTE_S, &msgData,
									  CRYPT_CTXINFO_KEY );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_POLY1305 */

	/* Compute HKDF #Xa and load the encryption keys */
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, handshakeInfo->cryptKeysize,
							  "key", 3, NULL, 0 );
	if( cryptStatusError( status ) )
		return( status );
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam,
					   handshakeInfo->tls13ClientSecret, hashParam, 
					   hkdfLabel, hkdfLabelLength );
	setMessageData( &msgData, hkdfValue, handshakeInfo->cryptKeysize );
	status = krnlSendMessage( isClient ? \
									sessionInfoPtr->iCryptOutContext : \
									sessionInfoPtr->iCryptInContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	if( cryptStatusError( status ) )
		{
		zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	DEBUG_DUMP_DATA_LABEL( isServer( sessionInfoPtr ) ? \
								"Client write key (server):" : \
								"Client write key (client):", 
						   hkdfValue, handshakeInfo->cryptKeysize );
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam,
					   handshakeInfo->tls13ServerSecret, hashParam, 
					   hkdfLabel, hkdfLabelLength );
	setMessageData( &msgData, hkdfValue, handshakeInfo->cryptKeysize );
	status = krnlSendMessage( isClient ? \
									sessionInfoPtr->iCryptInContext : \
									sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	if( cryptStatusError( status ) )
		{
		zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	DEBUG_DUMP_DATA_LABEL( isServer( sessionInfoPtr ) ? \
								"Server write key (server):" : \
								"Server write key (client):",
						   hkdfValue, handshakeInfo->cryptKeysize );

	/* Compute HKDF #Xb and load the IVs.  For GCM in TLS 1.2 there was an
	   explicit and implicit portion of the IV but for TLS 1.3 it's been
	   changed to use the same mechanism as the Bernstein protcol suite, a 
	   96-bit value that's XOR'd with the sequence number */
	static_assert( BERNSTEIN_IV_SIZE == GCM_IV_SIZE,
				   "GCM vs. Bernstein IV size" );
	status = createHkdfLabel( hkdfLabel, CRYPT_MAX_HASHSIZE * 2, 
							  &hkdfLabelLength, GCM_IV_SIZE,
							  "iv", 2, NULL, 0 );
	if( cryptStatusError( status ) )
		{
		zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );
		return( status );
		}
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam,
					   handshakeInfo->tls13ClientSecret, hashParam, 
					   hkdfLabel, hkdfLabelLength );
	memcpy( isClient ? tlsInfo->aeadWriteSalt : tlsInfo->aeadReadSalt, 
			hkdfValue, GCM_IV_SIZE );
	macFunctionAtomic( hkdfValue, CRYPT_MAX_HASHSIZE, hashParam,
					   handshakeInfo->tls13ServerSecret, hashParam, 
					   hkdfLabel, hkdfLabelLength );
	memcpy( isClient ? tlsInfo->aeadReadSalt : tlsInfo->aeadWriteSalt, 
			hkdfValue, GCM_IV_SIZE );
	tlsInfo->aeadSaltSize = GCM_IV_SIZE;
	DEBUG_DUMP_DATA_LABEL( isServer( sessionInfoPtr ) ? \
								"Client write IV (server):" : \
								"Client write IV (client):", 
						   tlsInfo->aeadWriteSalt, GCM_IV_SIZE );
	DEBUG_DUMP_DATA_LABEL( isServer( sessionInfoPtr ) ? \
								"Server write IV (server):" : \
								"Server write IV (client):", 
						   tlsInfo->aeadReadSalt, GCM_IV_SIZE );

	zeroise( hkdfValue, CRYPT_MAX_HASHSIZE );

	/* When the cryptovariables change we also need to reset the sequence 
	   numbers, which start again from zero */
	tlsInfo->readSeqNo = tlsInfo->writeSeqNo = 0;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int loadHSKeysTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
					 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Complete the keyex */
	sMemConnect( &stream, handshakeInfo->tls13KeyexValue, 
				 handshakeInfo->tls13KeyexValueLen );
	status = completeTLSKeyex( handshakeInfo, &stream, FALSE, TRUE,
							   SESSION_ERRINFO );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the handshake secret */
	status = createHandshakeSecret( handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the keys and IVs */
	return( loadKeys( sessionInfoPtr, handshakeInfo ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int loadAppdataKeysTLS13( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Create the application data secret */
	status = createAppdataSecret( handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the keys and IVs */
	status = recreateSecurityContexts( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = loadKeys( sessionInfoPtr, handshakeInfo );
	return( status );
	}

/* Test the whole TLS 1.3 HKDF zoo, test vectors from RFC 8448 */

#ifndef NDEBUG

void testTLS13Zoo( void )
	{
	CRYPT_CONTEXT iHashContext;
	SESSION_INFO sessionInfo;
	TLS_INFO tlsInfoStorage, *tlsInfo = &tlsInfoStorage;
	TLS_HANDSHAKE_INFO handshakeInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE finished[ CRYPT_MAX_HASHSIZE + 8 ];
	int finishedLen, status;

	memset( &sessionInfo, 0, sizeof( SESSION_INFO ) );
	sessionInfo.sessionTLS = tlsInfo;
	SET_FLAG( ( &sessionInfo )->flags, SESSION_FLAG_ISSERVER );
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_AES );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	REQUIRES_V( cryptStatusOK( status ) );
	sessionInfo.iCryptInContext = createInfo.cryptHandle;
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_AES );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	REQUIRES_V( cryptStatusOK( status ) );
	sessionInfo.iCryptOutContext = createInfo.cryptHandle;

	memset( &handshakeInfo, 0, sizeof( TLS_HANDSHAKE_INFO ) );
	memcpy( handshakeInfo.tls13KeyexValue,
			"\x8b\xd4\x05\x4f\xb5\x5b\x9d\x63\xfd\xfb\xac\xf9\xf0\x4b\x9f\x0d"
			"\x35\xe6\xd6\x3f\x53\x75\x63\xef\xd4\x62\x72\x90\x0f\x89\x49\x2d", 32 );
	handshakeInfo.tls13KeyexValueLen = 32;	/* SHA-256 */
	memcpy( handshakeInfo.helloHash, 
			"\x86\x0c\x06\xed\xc0\x78\x58\xee\x8e\x78\xf0\xe7\x42\x8c\x58\xed"
			"\xd6\xb4\x3f\x2c\xa3\xe6\xe9\x5f\x02\xed\x06\x3c\xf0\xe1\xca\xd8", 
			32 );
	handshakeInfo.helloHashSize = 32;		/* SHA-256 */
	handshakeInfo.cryptKeysize = 16;		/* AES */
	handshakeInfo.integrityAlgoParam = 32;	/* SHA-256 */
	handshakeInfo.md5context = handshakeInfo.sha1context = \
		handshakeInfo.sha2context = handshakeInfo.keyexContext = \
		handshakeInfo.keyexEcdhContext = CRYPT_ERROR;
  #ifdef USE_25519
	handshakeInfo.keyex25519Context = CRYPT_ERROR;
  #endif /* USE_25519 */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA2 );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	REQUIRES_V( cryptStatusOK( status ) );
	iHashContext = createInfo.cryptHandle;
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "dummy", 5 );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );

	/* Handshake secret, HKDF #1, 2, 3 */
	status = createHandshakeSecret( &handshakeInfo );
	if( cryptStatusError( status ) || \
		memcmp( handshakeInfo.tls13ClientSecret, 
				"\xb3\xed\xdb\x12\x6e\x06\x7f\x35", 8 ) )
		puts( "Bang." );
	if( memcmp( handshakeInfo.tls13ServerSecret,
				"\xb6\x7b\x7d\x69\x0c\xc1\x6c\x4e", 8 ) )
		puts( "Bang." );

	/* Handshake keys, HKDF #3x */
	status = loadKeys( &sessionInfo, &handshakeInfo );
	if( cryptStatusError( status ) || \
		memcmp( tlsInfo->aeadWriteSalt, 
				"\x5d\x31\x3e\xb2\x67\x12\x76\xee", 8 ) )
		puts( "Bang." );
	if( memcmp( tlsInfo->aeadReadSalt, 
				"\x5b\xd3\xc7\x1b\x83\x6e\x0b\x76", 8 ) )
		puts( "Bang." );

	/* Server finished */
	status = createFinishedTLS13( finished, CRYPT_MAX_HASHSIZE, &finishedLen,
								  &handshakeInfo, iHashContext, TRUE );
#if 0	/* Won't match since the transcript hash will differ and
		   the RFC doesn't provide this value */
	if( cryptStatusError( status ) || \
		memcmp( finished, 
				"\x9b\x9b\x14\x1d\x90\x63\x37\xfb", 8 ) )
		puts( "Bang." );
#else
	if( cryptStatusError( status ) )
		puts( "Bang." );
#endif /* 0 */

	/* Application secret, HKDF #4, 5 */
	memcpy( handshakeInfo.sessionHash, 
			"\x96\x08\x10\x2a\x0f\x1c\xcc\x6d\xb6\x25\x0b\x7b\x7e\x41\x7b\x1a"
			"\x00\x0e\xaa\xda\x3d\xaa\xe4\x77\x7a\x76\x86\xc9\xff\x83\xdf\x13",
			32 );
	handshakeInfo.sessionHashSize = 32;		/* SHA-256 */
	status = createAppdataSecret( &handshakeInfo );
	if( cryptStatusError( status ) || \
		memcmp( handshakeInfo.tls13ClientSecret, 
				"\x9e\x40\x64\x6c\xe7\x9a\x7f\x9d", 8 ) )
		puts( "Bang." );
	if( memcmp( handshakeInfo.tls13ServerSecret,
				"\xa1\x1a\xf9\xf0\x55\x31\xf8\x56", 8 ) )
		puts( "Bang." );

	krnlSendNotifier( sessionInfo.iCryptInContext, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( sessionInfo.iCryptOutContext, IMESSAGE_DECREFCOUNT );
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_AES );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	REQUIRES_V( cryptStatusOK( status ) );
	sessionInfo.iCryptInContext = createInfo.cryptHandle;
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_AES );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	REQUIRES_V( cryptStatusOK( status ) );
	sessionInfo.iCryptOutContext = createInfo.cryptHandle;

	/* Application keys, HKDF #5x */
	status = loadKeys( &sessionInfo, &handshakeInfo );
	if( cryptStatusError( status ) || \
		memcmp( tlsInfo->aeadWriteSalt, 
				"\xcf\x78\x2b\x88\xdd\x83\x54\x9a", 8 ) )
		puts( "Bang." );
	if( memcmp( tlsInfo->aeadReadSalt, 
				"\x5b\x78\x92\x3d\xee\x08\x57\x90", 8 ) )
		puts( "Bang." );

	krnlSendNotifier( sessionInfo.iCryptInContext, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( sessionInfo.iCryptOutContext, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	}
#endif /* !NDEBUG */
#endif /* USE_TLS13 */
