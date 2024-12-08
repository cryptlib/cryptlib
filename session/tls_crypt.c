<<<<<<< HEAD
/****************************************************************************
*																			*
*						cryptlib TLS Crypto Routines						*
*					 Copyright Peter Gutmann 1998-2022						*
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

#ifdef USE_TLS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Write packet metadata for input to the MAC/ICV authentication process.
   For TLS classic this is:

	seq_num || type || version || length 

   For the TLS 1.3 UI refresh this was changed to:

	type = 23 || version = ( 0x03, 0x03 } || length + ICV-length */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writePacketMetadata( OUT_BUFFER( dataMaxLength, *dataLength ) \
									void *data,
								IN_LENGTH_SHORT_MIN( 16 ) \
									const int dataMaxLength,
								OUT_LENGTH_BOUNDED_Z( dataMaxLength ) \
									int *dataLength,
								IN_BYTE const int type,
								IN_INT_Z const long seqNo, 
								IN_RANGE( TLS_MINOR_VERSION_TLS, \
										  TLS_MINOR_VERSION_TLS13 ) \
									const int version,
								IN_LENGTH_Z const int payloadLength )
	{
	STREAM stream;
	int status;

	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 16 ) );
	REQUIRES( type >= 0 && type <= 255 );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= TLS_MINOR_VERSION_TLS && \
			  version <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE + 512 );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* Write the sequence number, packet type, version, and length 
	  information to the output buffer */
	sMemOpen( &stream, data, dataMaxLength );
	writeUint64( &stream, seqNo );
	sputc( &stream, type );
	sputc( &stream, TLS_MAJOR_VERSION );
	sputc( &stream, version );
	status = writeUint16( &stream, payloadLength );
	if( cryptStatusOK( status ) )
		*dataLength = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

#ifdef USE_TLS13

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writePacketMetadataTLS13( OUT_BUFFER( dataMaxLength, *dataLength ) \
										void *data,
									 IN_LENGTH_SHORT_MIN( 16 ) \
										const int dataMaxLength,
									 OUT_LENGTH_BOUNDED_Z( dataMaxLength ) \
										int *dataLength,
									 IN_LENGTH_Z const int payloadLength )
	{
	STREAM stream;
	int status;

	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 16 ) );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE + 512 );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* Write the fixed packet type and TLS 1.2 version, and length 
	   information to the output buffer */
	sMemOpen( &stream, data, dataMaxLength );
	sputc( &stream, TLS_MSG_APPLICATION_DATA );
	sputc( &stream, TLS_MAJOR_VERSION );
	sputc( &stream, TLS_MINOR_VERSION_TLS12 );
	status = writeUint16( &stream, payloadLength + GCMICV_SIZE );
	if( cryptStatusOK( status ) )
		*dataLength = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}
#endif /* USE_TLS13 */

/****************************************************************************
*																			*
*							Encrypt/Decrypt Functions						*
*																			*
****************************************************************************/

/* Encrypt/decrypt a data block (in mose cases this also includes the MAC, 
   which has been added to the data by the caller).  The handling of length 
   arguments for these is a bit tricky, for encryption the input is { data, 
   payloadLength } which is padded (if necessary) and the padded length 
   returned in '*dataLength', for decryption the entire data block will be 
   processed but only 'processedDataLength' bytes of result are valid 
   output */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int encryptData( const SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER( dataMaxLength, *dataLength ) \
					BYTE *data, 
				 IN_DATALENGTH const int dataMaxLength,
				 OUT_DATALENGTH_Z int *dataLength,
				 IN_DATALENGTH const int payloadLength )
	{
	int length = payloadLength, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( payloadLength > 0 && \
			  payloadLength <= MAX_PACKET_SIZE + CRYPT_MAX_HASHSIZE && \
			  payloadLength <= sessionInfoPtr->sendBufSize && \
			  payloadLength <= dataMaxLength );

	/* Clear return value */
	*dataLength = 0;

	/* If it's a block cipher then we add end-of-block and message padding.  
	   We can't pad GCM because the spec doesn't allow it.
	   
	   Note that the padding size can range from 0 to 255 bytes, with zero
	   bytes of padding being non-PKCS #5 conformant.  This is possible
	   because the padding doesn't also encode the length as it does in 
	   PKCS #5, the padding length is an extra byte that's always present 
	   but is also treated as the last byte of the padding.  To deal with 
	   this special case we round up the payload size to ensure that 
	   there's always at least one byte of padding present */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		const int paddedSize = getPaddedSize( payloadLength + 1 );
		const int padSize = paddedSize - payloadLength;
		LOOP_INDEX i;

		ENSURES( isBufsizeRangeMin( paddedSize, 16 ) ); 
		ENSURES( padSize > 0 && padSize <= 255 && \
				 length + padSize <= dataMaxLength );

		/* Add the PKCS #5-style padding (PKCS #5 uses n, TLS uses n-1) */
		LOOP_EXT( i = 0, i < padSize, i++, 257 )
			{
			ENSURES( LOOP_INVARIANT_EXT( i, 0, padSize - 1, 257 ) );

			data[ length++ ] = intToByte( padSize - 1 );
			}
		ENSURES( LOOP_BOUND_OK );
		}
	ENSURES( isBufsizeRangeNZ( length ) );

	/* Encrypt the data and optional padding */
	status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_CTX_ENCRYPT, data, length );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = length;

	/* If we're using GCM then we have to append the ICV to the data */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		MESSAGE_DATA msgData;

		REQUIRES( boundsCheck( length, sessionInfoPtr->authBlocksize, 
							   dataMaxLength ) );

		setMessageData( &msgData, data + length, 
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_ICV );
		if( cryptStatusError( status ) )
			return( status );
		*dataLength += sessionInfoPtr->authBlocksize;
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int decryptData( SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER_FIXED( dataLength ) \
					BYTE *data, 
				 IN_DATALENGTH const int dataLength, 
				 OUT_DATALENGTH_Z int *processedDataLength )
	{
	int length = dataLength, padSize, padValue = 0, status;
	LOOP_INDEX i;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtrDynamic( data, dataLength ) );
	assert( isWritePtr( processedDataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) && \
			  dataLength <= sessionInfoPtr->receiveBufEnd );

	/* Clear return value */
	*processedDataLength = 0;

	/* Decrypt the data */
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_CTX_DECRYPT, data, length );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Packet decryption failed" ) );
		}

	/* If we're using GCM then we have to check the ICV that follows the 
	   data */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, data + length, 
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext, 
								  IMESSAGE_COMPARE, &msgData, 
								  MESSAGE_COMPARE_ICV );
		if( cryptStatusError( status ) )
			{
			/* A bad ICV means that the packet data has been corrupted, 
			   which means that we can't report the packet type in the
			   error message since it could be random garbage */
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					  "Bad message ICV for length %d packet", length ) );
			}
		}

	/* If it's a stream cipher then there's no padding present */
	if( sessionInfoPtr->cryptBlocksize <= 1 )
		{
		*processedDataLength = length;

		return( CRYPT_OK );
		}

	/* If it's a block cipher then we need to remove end-of-block padding.  
	   Up until TLS 1.1 the spec was silent about any requirement to check 
	   the padding, and for SSLv3 it didn't specify the padding format at 
	   all apart from specifying that it had to be  less than the cipher 
	   block size so it wasn't really safe to reject a TLS message if we 
	   didn't find the correct padding because many TLS implementations 
	   didn't process the padded data space in any way, leaving it 
	   containing whatever was there before (which can include old plaintext 
	   (!!)).  
	   
	   Almost all TLS implementations get it right (even though in TLS 1.0 
	   there was only a requirement to generate, but not to check, the PKCS 
	   #5-style padding, so we always check the padding bytes if we're 
	   talking TLS.

	   First we make sure that the padding information looks OK.  TLS allows 
	   up to 256 bytes of padding (only GnuTLS actually seems to use this 
	   capability though) so we can't check for a sensible (small) padding 
	   length.

	   There's no easy way to perform these checks in a timing-independent
	   manner because we're using them to reject completely malformed
	   packets (out-of-bounds array references), but hopefully the few 
	   cycles difference won't be measurable in the overall scheme of 
	   things */
	padSize = byteToInt( data[ dataLength - 1 ] );
	length -= padSize + 1;
	if( !isBufsizeRange( length ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Encryption padding adjustment value %d is greater "
				  "than packet length %d", padSize, dataLength ) );
		}

	/* Check for PKCS #5-type padding (PKCS #5 uses n, TLS uses n-1) in a 
	   timing-independent manner */
	LOOP_EXT( i = 0, i < padSize, i++, 257 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, padSize - 1, 257 ) );

		padValue |= data[ length + i ] ^ padSize;
		}
	ENSURES( LOOP_BOUND_OK );
	if( padValue != 0 )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid encryption padding byte value, expected 0x%02X",
				  padSize ) );
		}
	*processedDataLength = length;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								TLS MAC Functions							*
*																			*
****************************************************************************/

/* Perform a TLS MAC of a data block.  We have to provide special-case 
   handling of zero-length blocks since some versions of OpenSSL send these 
   as a kludge in TLS 1.0 to work around chosen-IV attacks.

   In the following functions we don't check the return value of every 
   single component MAC operation since it would lead to endless sequences
   of 'status = x; if( cSOK( x ) ) ...' chains, on the remote chance that
   there's some transient failure in a single component operation it'll be
   picked up at the end anyway when the overall MAC check fails */

CHECK_RETVAL \
static int macDataTLS( IN_HANDLE const CRYPT_CONTEXT iHashContext, 
					   IN_INT_Z const long seqNo, 
					   IN_RANGE( TLS_MINOR_VERSION_TLS, \
								 TLS_MINOR_VERSION_TLS13 ) const int version,
					   IN_BUFFER_OPT( ivLength ) const void *iv, 
					   IN_LENGTH_IV_Z const int ivLength, 
					   IN_BUFFER_OPT( dataLength ) const void *data, 
					   IN_DATALENGTH_Z const int dataLength, 
					   IN_BYTE const int type )
	{
	BYTE metadataBuffer[ 64 + CRYPT_MAX_IVSIZE + 8 ];
	int metadataLength, status;

	assert( ( iv == NULL && ivLength == 0 ) || \
			isReadPtrDynamic( iv, ivLength ) );
	assert( ( data == NULL && dataLength == 0 ) || \
			isReadPtrDynamic( data, dataLength ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= TLS_MINOR_VERSION_TLS && \
			  version <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( ( iv == NULL && ivLength == 0 ) || \
			  ( iv != NULL && \
				ivLength > 0 && ivLength <= CRYPT_MAX_IVSIZE ) );
	REQUIRES( ( data == NULL && dataLength == 0 ) || \
			  ( data != NULL && \
				dataLength > 0 && dataLength <= MAX_PACKET_SIZE + 512 ) );
	REQUIRES( type >= 0 && type <= 255 );

	/* Set up the packet metadata to be MACed */
	status = writePacketMetadata( metadataBuffer, 64, &metadataLength, type, 
								  seqNo, version, dataLength + ivLength );
	if( cryptStatusError( status ) )
		return( status );
	if( ivLength > 0 )
		{
		/* If we're using an explicit IV, append it to the metadata for
		   MAC'ing */
		REQUIRES( boundsCheck( metadataLength, ivLength, 
							   64 + CRYPT_MAX_IVSIZE ) );
		memcpy( metadataBuffer + metadataLength, iv, ivLength );
		metadataLength += ivLength;
		}

	/* Reset the hash context and generate the MAC:

		HMAC( metadata || (IV) || data ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, metadataBuffer, 
					 metadataLength );
	if( dataLength > 0 )
		{
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) data, dataLength );
		}
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				  INOUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				  IN_DATALENGTH const int dataMaxLength, 
				  OUT_DATALENGTH_Z int *dataLength,
				  IN_DATALENGTH const int payloadLength, 
				  IN_BYTE const int type )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( payloadLength > 0 && payloadLength <= MAX_PACKET_SIZE + 512 && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataMaxLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* Clear return values */
	*dataLength = 0;

	/* MAC the payload.  When wrapping a packet the IV is treated as part of
	   the payload so it's always passed in as { NULL, 0 }, it's only when
	   unwrapping that it's stripped before the payload data is copied into
	   the session buffer and so needs to be passed in explicitly */
	status = macDataTLS( sessionInfoPtr->iAuthOutContext, tlsInfo->writeSeqNo,
						 sessionInfoPtr->version, NULL, 0, data, 
						 payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->writeSeqNo++;

	/* Append the MAC value to the end of the packet */
	ENSURES( boundsCheck( payloadLength, sessionInfoPtr->authBlocksize,
						  dataMaxLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthOutContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = payloadLength + sessionInfoPtr->authBlocksize;
	INJECT_FAULT( SESSION_CORRUPT_MAC, SESSION_CORRUPT_MAC_TLS_1 );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) const void *data, 
				 IN_DATALENGTH const int dataLength, 
				 IN_DATALENGTH_Z const int payloadLength, 
				 IN_BYTE const int type, 
				 IN_BOOL const BOOLEAN noReportError )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	const void *ivPtr = NULL;
	int ivLength = 0, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE + 512 && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataLength );
	REQUIRES( type >= 0 && type <= 255 );
	REQUIRES( isBooleanValue( noReportError ) );

	/* MAC the payload.  If the payload length is zero then there's no data 
	   payload, this can happen with some versions of OpenSSL that send 
	   zero-length blocks as a kludge to work around pre-TLS 1.1 chosen-IV
	   attacks */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_ENCTHENMAC ) && \
		tlsInfo->ivSize > 0 )
		{
		/* When using encrypt-then-MAC and TLS 1.1+ explicit IVs, the IV is
		   authenticated alongside the encrypted payload data */
		ivPtr = tlsInfo->iv;
		ivLength = tlsInfo->ivSize;
		}
	if( payloadLength <= 0 )
		{
		status = macDataTLS( sessionInfoPtr->iAuthInContext, 
							 tlsInfo->readSeqNo, sessionInfoPtr->version, 
							 ivPtr, ivLength, NULL, 0, type );
		}
	else
		{
		status = macDataTLS( sessionInfoPtr->iAuthInContext, 
							 tlsInfo->readSeqNo, sessionInfoPtr->version, 
							 ivPtr, ivLength, data, payloadLength, type );
		}
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->readSeqNo++;

	/* Compare the calculated MAC to the MAC present at the end of the 
	   data */
	ENSURES( boundsCheckZ( payloadLength, sessionInfoPtr->authBlocksize,
						   dataLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		/* If the error message has already been set at a higher level, 
		   don't update the error information */
		if( noReportError )
			return( CRYPT_ERROR_SIGNATURE );

		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad message MAC for packet type %d, length %d",
				  type, dataLength ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								TLS GCM Functions							*
*																			*
****************************************************************************/

#ifdef USE_GCM

/* Perform a TLS GCM integrity check of a data block.  This differs somewhat
   from the more conventional MACing routines because GCM combines the ICV
   generation with encryption, so all that we're actually doing is 
   generating the initial stage of the ICV over the packet metadata handled
   as GCM AAD */

CHECK_RETVAL \
int macDataTLSGCM( IN_HANDLE const CRYPT_CONTEXT iCryptContext, 
				   IN_INT_Z const long seqNo, 
				   IN_RANGE( TLS_MINOR_VERSION_TLS, \
							 TLS_MINOR_VERSION_TLS13 ) const int version,
				   IN_LENGTH_Z const int payloadLength, 
				   IN_BYTE const int type )
	{
	MESSAGE_DATA msgData;
	BYTE metadataBuffer[ 64 + 8 ];
	int metadataLength, status;

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= TLS_MINOR_VERSION_TLS && \
			  version <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( payloadLength >= 0 && \
			  payloadLength <= MAX_PACKET_SIZE + \
						( version >= TLS_MINOR_VERSION_TLS13 ? 1 : 0 ) );
	REQUIRES( type >= 0 && type <= 255 );

	/* Set up the packet metadata to be MACed */
#ifdef USE_TLS13
	if( version <= TLS_MINOR_VERSION_TLS12 )
		{
		status = writePacketMetadata( metadataBuffer, 64, &metadataLength, 
									  type, seqNo, version, payloadLength );
		}
	else
		{
		status = writePacketMetadataTLS13( metadataBuffer, 64, 
										   &metadataLength, payloadLength );
		}
#else
	status = writePacketMetadata( metadataBuffer, 64, &metadataLength, 
								  type, seqNo, version, payloadLength );
#endif /* USE_TLS13 */
	if( cryptStatusError( status ) )
		return( status );

	/* Send the AAD to the GCM context for inclusion in the ICV 
	   calculation */
	setMessageData( &msgData, metadataBuffer, metadataLength );
	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
							 &msgData, CRYPT_IATTRIBUTE_AAD ) );
	}
#endif /* USE_GCM */

/****************************************************************************
*																			*
*							TLS Bernstein Functions							*
*																			*
****************************************************************************/

#ifdef USE_POLY1305

/* Because both Chacha20 and Poly1305 fail catastrophically on a repeated 
   IV, TLS goes through considerable calisthenics to try and prevent this
   from happening, with each IV being built up from successive layers of 
   counters and similar values, compensating for the fragility of the modes
   used by throwing in a kitchen sink of changing values.  Each IV is built
   up as follows:

				+---------------+---------------------------+
				| 32-bit zeroes	|	64-bit sequence no.		|
				+---------------+---------------------------+
									XOR
				+-------------------------------------------+
				|				TLS read/write IV			|
				+-------------------------------------------+
									 |
									 v
	+-----------+-------------------------------------------+
	| 32-bit ctr|				96-bit IV					|
	+-----------+-------------------------------------------+

   with the 32-bit counter being encoded backwards (little-endian format) for
   Bernstein cargo-cult purposes.
   
   This IV, with the counter set to zero, is used to generate the Poly1305 
   key.  The counter is then set to one and used to encrypt/decrypt the 
   data */

CHECK_RETVAL \
int initCryptBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_BOOL const BOOLEAN isRead )
	{
	CRYPT_CONTEXT iMacContext, iCryptContext;
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	STREAM stream;
	MESSAGE_DATA msgData;
	BYTE poly1305key[ CRYPT_MAX_KEYSIZE + 8 ];
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
		iMacContext = sessionInfoPtr->iAuthInContext;
		iCryptContext = sessionInfoPtr->iCryptInContext;
		}
	else
		{
		seqNo = tlsInfo->writeSeqNo;
		ivPtr = tlsInfo->aeadWriteSalt;
		iMacContext = sessionInfoPtr->iAuthOutContext;
		iCryptContext = sessionInfoPtr->iCryptOutContext;
		}

	/* Assemble the Chacha20 IV */
	sMemOpen( &stream, ivBuffer, CRYPT_MAX_IVSIZE );
	writeUint32( &stream, 0 );				/* Counter */
	writeUint32( &stream, 0 );				/* 32 bits zeroes */
	status = writeUint64( &stream, seqNo );
	sMemDisconnect( &stream );
	ENSURES( cryptStatusOK( status ) );
	LOOP_MED( i = 0, i < BERNSTEIN_IV_SIZE, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, BERNSTEIN_IV_SIZE - 1 ) );

		ivBuffer[ bitsToBytes( 32 ) + i ] ^= ivPtr[ i ];
		}
	ENSURES( LOOP_BOUND_OK );

	/* Generate the Poly1305 key from the initial IV using Chacha20.  Since 
	   this is only used for one message and then discarded, and in any case
	   is just Chacha20 keystream output whose continuation we're about to 
	   send over the Internet, we don't take any special precautions to keep 
	   it in secure memory */
	setMessageData( &msgData, ivBuffer, 16 );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_IV );
	if( cryptStatusOK( status ) )
		{
		memset( poly1305key, 0, CRYPT_MAX_KEYSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT, 
								  poly1305key, 32 );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( poly1305key, 32 );
		return( status );
		}

	/* Rekey Poly1305, update the counter part of the IV, and reload the 
	   Chacha20 context from it */
	setMessageData( &msgData, poly1305key, 32 );
	status = krnlSendMessage( iMacContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_REKEY );
	if( cryptStatusOK( status ) )
		{
		ivBuffer[ 0 ] = 1;		/* 00 00 00 01 in little-endian format */
		setMessageData( &msgData, ivBuffer, 16 );
		status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_IV );
		}
	zeroise( poly1305key, 32 );

	return( status );
	}

/* Perform an integrity check of a data block using the Bernstein protocol 
   suite.  This is an AEAD exactly like GCM, but the IETF managed to make it 
   incompatible with the standard AEAD use so it needs custom handling.

   Specifically, instead of simply using the MAC as a MAC, the IETF came up 
   with a weirdo construct with no purpose whatsoever (Procter's "A Security 
   Analysis of the Composition of ChaCha20 and Poly1305" mentions it in 
   passing, but it plays no role in anything) but that makes calculating the 
   MAC value unnecessarily awkward and complex.

   Instead of MAC'ing the AAD and data as is, it has to be zero-padded to 
   the nearest 16-byte boundary, and the padded data MAC'd.  However, 
   because this has added needless zero bytes to the data, additional length 
   values that specify the size of the original unpadded data have to be 
   added to the end and MAC'd as well:

	"Once again, the Wellington Police have come up with a perfect solution 
	 to the problem / That's right - by removing the solution we had to 
	 another problem / The fact that if we hadn't put that sign up in the 
	 first place none of this would've happened is irrelevant.  What matters 
	 is that we've identified the problem / That we caused / Job well done / 
	 Good result" 
		- "Wellington Paranormal".

   As the icing on the cake, for Bernstein cargo-cult purposes the lengths 
   are encoded backwards, as little-endian integers rather than the standard 
   big-endian form used in all other IETF security protocols, so we can't 
   use writeUint64() but have to hand-assemble the values ourselves.

   So what finally ends up being MAC'd in place of the obvious "aad || data" 
   is:

	byte[]	aad
	byte[]	aadPadding = { 0 }		// Pad to multiple of 16 bytes
	byte[]	data
	byte[]	dataPadding = { 0 }		// Pad to multiple of 16 bytes
	buint64	aadLength				// Backwards uint64
	buint64	dataLength				// Backwards uint64 */

CHECK_RETVAL \
static int macDataTLSBernstein( IN_HANDLE const CRYPT_CONTEXT iHashContext, 
								IN_INT_Z const long seqNo, 
								IN_RANGE( TLS_MINOR_VERSION_TLS, \
										  TLS_MINOR_VERSION_TLS13 ) \
									const int version,
								IN_BUFFER( payloadLength ) \
									const void *payload, 
								IN_LENGTH_Z const int payloadLength, 
								IN_BYTE const int type )
	{
	static const BYTE zeroes[ 16 ] = { 0 };
	BYTE aadBuffer[ 64 + 8 ], lengthBuffer[ 16 + 8 ];
	int aadLength, aadPadLength, payloadPadLength, status;

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= TLS_MINOR_VERSION_TLS && \
			  version <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( payloadLength >= 0 && \
			  payloadLength <= MAX_PACKET_SIZE + \
						( version >= TLS_MINOR_VERSION_TLS13 ? 1 : 0 ) );
	REQUIRES( type >= 0 && type <= 255 );

	/* Set up the packet metadata to be MACed */
#ifdef USE_TLS13
	if( version <= TLS_MINOR_VERSION_TLS12 )
		{
		status = writePacketMetadata( aadBuffer, 64, &aadLength, type, 
									  seqNo, version, payloadLength );
		}
	else
		{
		status = writePacketMetadataTLS13( aadBuffer, 64, &aadLength, 
										   payloadLength );
		}
#else
	status = writePacketMetadata( aadBuffer, 64, &aadLength, type, 
								  seqNo, version, payloadLength );
#endif /* USE_TLS13 */
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the assorted unnecessary additional values that need to be 
	   MAC'd */
	aadPadLength = ( 16 - ( aadLength % 16 ) ) % 16;
	payloadPadLength = ( 16 - ( payloadLength % 16 ) ) % 16;
	memset( lengthBuffer, 0, 16 );
	lengthBuffer[ 0 ] = intToByte( aadLength );
	lengthBuffer[ 8 ] = intToByte( payloadLength );
	lengthBuffer[ 9 ] = intToByte( payloadLength >> 8 );

	/* MAC all of the little bits and pieces required to generate the AEAD 
	   MAC value */
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, aadBuffer, 
					 aadLength );
	if( aadPadLength > 0 )
		{
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) zeroes, aadPadLength );
		}
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) payload, payloadLength );
	if( payloadPadLength > 0 )
		{
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) zeroes, payloadPadLength );
		}
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, lengthBuffer, 16 );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLSBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_BUFFER( dataMaxLength, *dataLength ) \
								void *data, 
						   IN_DATALENGTH const int dataMaxLength, 
						   OUT_DATALENGTH_Z int *dataLength,
						   IN_DATALENGTH const int payloadLength, 
						   IN_BYTE const int type )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( payloadLength > 0 && payloadLength <= MAX_PACKET_SIZE + 512 && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataMaxLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* Clear return values */
	*dataLength = 0;

	/* MAC the payload and metadata */
	status = macDataTLSBernstein( sessionInfoPtr->iAuthOutContext, 
								  tlsInfo->writeSeqNo, 
								  sessionInfoPtr->version, data, 
								  payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->writeSeqNo++;

	/* Append the MAC value to the end of the packet */
	ENSURES( boundsCheck( payloadLength, sessionInfoPtr->authBlocksize,
						  dataMaxLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthOutContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = payloadLength + sessionInfoPtr->authBlocksize;
	INJECT_FAULT( SESSION_CORRUPT_MAC, SESSION_CORRUPT_MAC_TLS_1 );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLSBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  IN_BUFFER( dataLength ) const void *data, 
						  IN_DATALENGTH const int dataLength, 
						  IN_DATALENGTH_Z const int payloadLength, 
						  IN_BYTE const int type )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE + 512 && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* MAC the payload and metadata */
	status = macDataTLSBernstein( sessionInfoPtr->iAuthInContext, 
								  tlsInfo->readSeqNo, 
								  sessionInfoPtr->version, data, 
								  payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->readSeqNo++;

	/* Compare the calculated MAC to the MAC present at the end of the 
	   data */
	ENSURES( boundsCheckZ( payloadLength, sessionInfoPtr->authBlocksize,
						   dataLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad message MAC for packet type %d, length %d",
				  type, dataLength ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_POLY1305 */

/****************************************************************************
*																			*
*					Handshake Message Hash/MAC Functions					*
*																			*
****************************************************************************/

/* Perform assorted hashing of a data block, a dual dual MD5+SHA-1 hash for 
   TLS 1.0 - 1.1 or a straight SHA-2 hash for TLS 1.2+.  Since this is part 
   of an ongoing message exchange (in other words a failure potentially 
   won't be detected for some time) we check each return value.  This 
   processing was originally done using a dual MD5+SHA-1 hash, however 
   TLS 1.2+ switched to using a single SHA-2 hash, because of this we have 
   to explicitly check which hashing option we're using (in some cases it 
   might be both since we have to speculatively hash initial messages until 
   we've agreed on a version) and only use that hash.
   
   In addition to the overall hashing we may also be running a separate hash 
   of the messages that stops before the other hashing does if certificate-
   based client authentication is being used.  This would add even more 
   overhead to the whole process, however since it's only used with TLS 1.2+
   and in that case is restricted to using SHA-2 via hashing preferences
   sent in the hello messages, we can obtain the necessary hash value by
   cloning the SHA-2 context at the point where we have to generate or 
   verify the client signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int hashHSData( const TLS_HANDSHAKE_INFO *handshakeInfo,
					   IN_BUFFER( dataLength ) const void *data, 
					   IN_DATALENGTH const int dataLength )
	{
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( isBufsizeRangeNZ( dataLength ) );

	if( handshakeInfo->md5context != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->md5context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( handshakeInfo->sha1context,
									  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
									  dataLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	if( handshakeInfo->sha2context != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->sha2context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
		if( cryptStatusError( status ) )
			return( status );
		}
#ifdef CONFIG_SUITEB
	if( handshakeInfo->sha384context != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->sha384context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* CONFIG_SUITEB */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int hashHSPacketRead( IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT_PTR STREAM *stream )
	{
	const int dataLength = sMemDataLeft( stream );
	void *data;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) );

	/* On a read we've just processed the packet header and everything 
	   that's left in the stream is the data to be MACd.  Note that we can't 
	   use sMemGetDataBlockRemaining() for this because that returns the
	   entire available buffer, not just the amount of data in the buffer */
	status = sMemGetDataBlock( stream, &data, dataLength );
	if( cryptStatusOK( status ) )
		{
		ANALYSER_HINT( data != NULL );
		status = hashHSData( handshakeInfo, data, dataLength );
		}
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int hashHSPacketWrite( IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo, 
					   INOUT_PTR STREAM *stream,
					   IN_DATALENGTH_Z const int offset )
	{
	const int dataStart = offset + TLS_HEADER_SIZE;
	void *data DUMMY_INIT;
	int dataLength, status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBufsizeRange( offset ) );

	/* On a write we've just finished writing the packet and everything but
	   the header needs to be MACd */
	status = calculateStreamObjectLength( stream, dataStart, &dataLength );
	if( cryptStatusOK( status ) )
		{
		status = sMemGetDataBlockAbs( stream, dataStart, &data, 
									  dataLength );
		}
	if( cryptStatusOK( status ) )
		{
		ANALYSER_HINT( data != NULL );
		status = hashHSData( handshakeInfo, data, dataLength );
		}
	return( status );
	}

/* Complete the hash/MAC or SHA2 MAC that's used in the finished message.  
   There are no less than three variations of this, one for SSL's dual MAC
   (which is no longer used), one for TLS 1.0 - 1.1's IPsec cargo cult 
   96-bit PRF'd dual MAC, and one for TLS 1.2's similarly cargo-cult 96-bit 
   PRF'd single MAC (unless we're using TLS 1.2 LTS).
   
   We don't check the return value of every single component MAC operation 
   since it would lead to endless sequences of 'status = x; 
   if( cSOK( x ) ) ...' chains, on the remote chance that there's some 
   transient failure in a single component operation it'll be picked up at 
   the end anyway when the overall MAC check fails */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) ) \
int completeTLSHashedMAC( IN_HANDLE const CRYPT_CONTEXT md5context,
						  IN_HANDLE const CRYPT_CONTEXT sha1context, 
						  OUT_BUFFER( hashValuesMaxLen, *hashValuesLen )
								BYTE *hashValues, 
						  IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
						  OUT_LENGTH_BOUNDED_Z( hashValuesMaxLen ) \
								int *hashValuesLen,
						  IN_BUFFER( labelLength ) const char *label, 
						  IN_RANGE( 1, 64 ) const int labelLength, 
						  IN_BUFFER( masterSecretLen ) \
								const BYTE *masterSecret, 
						  IN_LENGTH_SHORT const int masterSecretLen )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	BYTE hashBuffer[ 64 + ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	int status;

	assert( isWritePtrDynamic( hashValues, hashValuesMaxLen ) );
	assert( isWritePtr( hashValuesLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( label, labelLength ) );
	assert( isReadPtrDynamic( masterSecret, masterSecretLen ) );

	REQUIRES( isHandleRangeValid( md5context ) );
	REQUIRES( isHandleRangeValid( sha1context ) );
	REQUIRES( isShortIntegerRangeMin( hashValuesMaxLen, \
									  TLS_HASHEDMAC_SIZE ) );
	REQUIRES( labelLength > 0 && labelLength <= 64 && \
			  labelLength + MD5MAC_SIZE + SHA1MAC_SIZE <= \
						64 + ( CRYPT_MAX_HASHSIZE * 2 ) );

	/* Clear return value */
	*hashValuesLen = 0;

	REQUIRES( rangeCheck( labelLength, 1, 
			  64 + ( CRYPT_MAX_HASHSIZE * 2 ) ) );
	memcpy( hashBuffer, label, labelLength );

	/* Complete the hashing and get the MD5 and SHA-1 hashes */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashBuffer + labelLength, MD5MAC_SIZE );
	status = krnlSendMessage( md5context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hashBuffer + labelLength + MD5MAC_SIZE,
						SHA1MAC_SIZE );
		status = krnlSendMessage( sha1context, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the TLS check value.  This isn't really a hash or a MAC but
	   is generated by feeding the MD5 and SHA1 hashes of the handshake 
	   messages into the TLS key derivation (PRF) function and truncating 
	   the result to 12 bytes (96 bits) for IPsec cargo cult protocol design
	   purposes:

		TLS_PRF( label || MD5_hash || SHA1_hash ) */
	setMechanismDeriveInfo( &mechanismInfo, hashValues, 
							TLS_HASHEDMAC_SIZE, ( MESSAGE_CAST ) masterSecret, 
							masterSecretLen, 
							CRYPT_ALGO_NONE,	/* Implicit SHA1+MD5 */ 
							hashBuffer, 
							labelLength + MD5MAC_SIZE + SHA1MAC_SIZE, 1 );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							  &mechanismInfo, MECHANISM_DERIVE_TLS );
	if( cryptStatusOK( status ) )
		*hashValuesLen = TLS_HASHEDMAC_SIZE;
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4, 5, 7 ) ) \
int completeTLS12HashedMAC( IN_HANDLE const CRYPT_CONTEXT sha2context,
							OUT_BUFFER( hashValuesMaxLen, *hashValuesLen ) \
								BYTE *hashValues, 
							IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
							OUT_LENGTH_BOUNDED_Z( hashValuesMaxLen ) \
								int *hashValuesLen,
							IN_BUFFER( labelLength ) const char *label, 
							IN_RANGE( 1, 64 ) const int labelLength, 
							IN_BUFFER( masterSecretLen ) \
								const BYTE *masterSecret, 
							IN_LENGTH_SHORT const int masterSecretLen,
							IN_BOOL const BOOLEAN fullSizeMAC )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	BYTE hashBuffer[ 64 + ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	const int hashedMacSize = ( fullSizeMAC ) ? 32 : TLS_HASHEDMAC_SIZE;
	int macSize, status;

	assert( isWritePtrDynamic( hashValues, hashValuesMaxLen ) );
	assert( isWritePtr( hashValuesLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( label, labelLength ) );
	assert( isReadPtrDynamic( masterSecret, masterSecretLen ) );

	REQUIRES( isHandleRangeValid( sha2context ) );
	REQUIRES( isShortIntegerRangeMin( hashValuesMaxLen, 32 ) );
	REQUIRES( labelLength > 0 && labelLength <= 64 && \
			  labelLength + CRYPT_MAX_HASHSIZE <= 64 + ( CRYPT_MAX_HASHSIZE ) );
	REQUIRES( isBooleanValue( fullSizeMAC ) );

	/* Clear return value */
	*hashValuesLen = 0;

	REQUIRES( rangeCheck( labelLength, 1, 
			  64 + ( CRYPT_MAX_HASHSIZE * 2 ) ) );
	memcpy( hashBuffer, label, labelLength );

	/* Get the MAC size */
	status = krnlSendMessage( sha2context, IMESSAGE_GETATTRIBUTE, &macSize,
							  CRYPT_CTXINFO_BLOCKSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Complete the hashing and get the SHA-2 hash */
	krnlSendMessage( sha2context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashBuffer + labelLength, macSize );
	status = krnlSendMessage( sha2context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the TLS check value.  This isn't really a hash or a MAC but
	   is generated by feeding the SHA-2 hash of the handshake messages into 
	   the TLS key derivation (PRF) function and truncating the result to 12 
	   bytes (96 bits) for IPsec cargo cult protocol design purposes, unless
	   we're using TLS-LTS in which case we use the full-size result:

		TLS_PRF( label || SHA2_hash ) */
	setMechanismDeriveInfo( &mechanismInfo, hashValues, hashedMacSize, 
							( MESSAGE_CAST ) masterSecret, masterSecretLen, 
							CRYPT_ALGO_SHA2, hashBuffer, 
							labelLength + macSize, 1 );
	if( macSize != bitsToBytes( 256 ) )
		mechanismInfo.hashParam = macSize;
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							  &mechanismInfo, MECHANISM_DERIVE_TLS12 );
	if( cryptStatusOK( status ) )
		*hashValuesLen = hashedMacSize;
	return( status );
	}
#endif /* USE_TLS */
=======
/****************************************************************************
*																			*
*						cryptlib TLS Crypto Routines						*
*					 Copyright Peter Gutmann 1998-2022						*
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

#ifdef USE_TLS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Write packet metadata for input to the MAC/ICV authentication process.
   For TLS classic this is:

	seq_num || type || version || length 

   For the TLS 1.3 UI refresh this was changed to:

	type = 23 || version = ( 0x03, 0x03 } || length + ICV-length */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writePacketMetadata( OUT_BUFFER( dataMaxLength, *dataLength ) \
									void *data,
								IN_LENGTH_SHORT_MIN( 16 ) \
									const int dataMaxLength,
								OUT_LENGTH_BOUNDED_Z( dataMaxLength ) \
									int *dataLength,
								IN_BYTE const int type,
								IN_INT_Z const long seqNo, 
								IN_RANGE( TLS_MINOR_VERSION_TLS, \
										  TLS_MINOR_VERSION_TLS13 ) \
									const int version,
								IN_LENGTH_Z const int payloadLength )
	{
	STREAM stream;
	int status;

	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 16 ) );
	REQUIRES( type >= 0 && type <= 255 );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= TLS_MINOR_VERSION_TLS && \
			  version <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE + 512 );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* Write the sequence number, packet type, version, and length 
	  information to the output buffer */
	sMemOpen( &stream, data, dataMaxLength );
	writeUint64( &stream, seqNo );
	sputc( &stream, type );
	sputc( &stream, TLS_MAJOR_VERSION );
	sputc( &stream, version );
	status = writeUint16( &stream, payloadLength );
	if( cryptStatusOK( status ) )
		*dataLength = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

#ifdef USE_TLS13

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writePacketMetadataTLS13( OUT_BUFFER( dataMaxLength, *dataLength ) \
										void *data,
									 IN_LENGTH_SHORT_MIN( 16 ) \
										const int dataMaxLength,
									 OUT_LENGTH_BOUNDED_Z( dataMaxLength ) \
										int *dataLength,
									 IN_LENGTH_Z const int payloadLength )
	{
	STREAM stream;
	int status;

	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeMin( dataMaxLength, 16 ) );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE + 512 );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( dataMaxLength ) ); 
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* Write the fixed packet type and TLS 1.2 version, and length 
	   information to the output buffer */
	sMemOpen( &stream, data, dataMaxLength );
	sputc( &stream, TLS_MSG_APPLICATION_DATA );
	sputc( &stream, TLS_MAJOR_VERSION );
	sputc( &stream, TLS_MINOR_VERSION_TLS12 );
	status = writeUint16( &stream, payloadLength + GCMICV_SIZE );
	if( cryptStatusOK( status ) )
		*dataLength = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}
#endif /* USE_TLS13 */

/****************************************************************************
*																			*
*							Encrypt/Decrypt Functions						*
*																			*
****************************************************************************/

/* Encrypt/decrypt a data block (in mose cases this also includes the MAC, 
   which has been added to the data by the caller).  The handling of length 
   arguments for these is a bit tricky, for encryption the input is { data, 
   payloadLength } which is padded (if necessary) and the padded length 
   returned in '*dataLength', for decryption the entire data block will be 
   processed but only 'processedDataLength' bytes of result are valid 
   output */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int encryptData( const SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER( dataMaxLength, *dataLength ) \
					BYTE *data, 
				 IN_DATALENGTH const int dataMaxLength,
				 OUT_DATALENGTH_Z int *dataLength,
				 IN_DATALENGTH const int payloadLength )
	{
	int length = payloadLength, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( payloadLength > 0 && \
			  payloadLength <= MAX_PACKET_SIZE + CRYPT_MAX_HASHSIZE && \
			  payloadLength <= sessionInfoPtr->sendBufSize && \
			  payloadLength <= dataMaxLength );

	/* Clear return value */
	*dataLength = 0;

	/* If it's a block cipher then we add end-of-block and message padding.  
	   We can't pad GCM because the spec doesn't allow it.
	   
	   Note that the padding size can range from 0 to 255 bytes, with zero
	   bytes of padding being non-PKCS #5 conformant.  This is possible
	   because the padding doesn't also encode the length as it does in 
	   PKCS #5, the padding length is an extra byte that's always present 
	   but is also treated as the last byte of the padding.  To deal with 
	   this special case we round up the payload size to ensure that 
	   there's always at least one byte of padding present */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		const int paddedSize = getPaddedSize( payloadLength + 1 );
		const int padSize = paddedSize - payloadLength;
		LOOP_INDEX i;

		ENSURES( isBufsizeRangeMin( paddedSize, 16 ) ); 
		ENSURES( padSize > 0 && padSize <= 255 && \
				 length + padSize <= dataMaxLength );

		/* Add the PKCS #5-style padding (PKCS #5 uses n, TLS uses n-1) */
		LOOP_EXT( i = 0, i < padSize, i++, 257 )
			{
			ENSURES( LOOP_INVARIANT_EXT( i, 0, padSize - 1, 257 ) );

			data[ length++ ] = intToByte( padSize - 1 );
			}
		ENSURES( LOOP_BOUND_OK );
		}
	ENSURES( isBufsizeRangeNZ( length ) );

	/* Encrypt the data and optional padding */
	status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_CTX_ENCRYPT, data, length );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = length;

	/* If we're using GCM then we have to append the ICV to the data */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		MESSAGE_DATA msgData;

		REQUIRES( boundsCheck( length, sessionInfoPtr->authBlocksize, 
							   dataMaxLength ) );

		setMessageData( &msgData, data + length, 
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_ICV );
		if( cryptStatusError( status ) )
			return( status );
		*dataLength += sessionInfoPtr->authBlocksize;
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int decryptData( SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER_FIXED( dataLength ) \
					BYTE *data, 
				 IN_DATALENGTH const int dataLength, 
				 OUT_DATALENGTH_Z int *processedDataLength )
	{
	int length = dataLength, padSize, padValue = 0, status;
	LOOP_INDEX i;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtrDynamic( data, dataLength ) );
	assert( isWritePtr( processedDataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) && \
			  dataLength <= sessionInfoPtr->receiveBufEnd );

	/* Clear return value */
	*processedDataLength = 0;

	/* Decrypt the data */
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_CTX_DECRYPT, data, length );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Packet decryption failed" ) );
		}

	/* If we're using GCM then we have to check the ICV that follows the 
	   data */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, data + length, 
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext, 
								  IMESSAGE_COMPARE, &msgData, 
								  MESSAGE_COMPARE_ICV );
		if( cryptStatusError( status ) )
			{
			/* A bad ICV means that the packet data has been corrupted, 
			   which means that we can't report the packet type in the
			   error message since it could be random garbage */
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
					  "Bad message ICV for length %d packet", length ) );
			}
		}

	/* If it's a stream cipher then there's no padding present */
	if( sessionInfoPtr->cryptBlocksize <= 1 )
		{
		*processedDataLength = length;

		return( CRYPT_OK );
		}

	/* If it's a block cipher then we need to remove end-of-block padding.  
	   Up until TLS 1.1 the spec was silent about any requirement to check 
	   the padding, and for SSLv3 it didn't specify the padding format at 
	   all apart from specifying that it had to be  less than the cipher 
	   block size so it wasn't really safe to reject a TLS message if we 
	   didn't find the correct padding because many TLS implementations 
	   didn't process the padded data space in any way, leaving it 
	   containing whatever was there before (which can include old plaintext 
	   (!!)).  
	   
	   Almost all TLS implementations get it right (even though in TLS 1.0 
	   there was only a requirement to generate, but not to check, the PKCS 
	   #5-style padding, so we always check the padding bytes if we're 
	   talking TLS.

	   First we make sure that the padding information looks OK.  TLS allows 
	   up to 256 bytes of padding (only GnuTLS actually seems to use this 
	   capability though) so we can't check for a sensible (small) padding 
	   length.

	   There's no easy way to perform these checks in a timing-independent
	   manner because we're using them to reject completely malformed
	   packets (out-of-bounds array references), but hopefully the few 
	   cycles difference won't be measurable in the overall scheme of 
	   things */
	padSize = byteToInt( data[ dataLength - 1 ] );
	length -= padSize + 1;
	if( !isBufsizeRange( length ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Encryption padding adjustment value %d is greater "
				  "than packet length %d", padSize, dataLength ) );
		}

	/* Check for PKCS #5-type padding (PKCS #5 uses n, TLS uses n-1) in a 
	   timing-independent manner */
	LOOP_EXT( i = 0, i < padSize, i++, 257 )
		{
		ENSURES( LOOP_INVARIANT_EXT( i, 0, padSize - 1, 257 ) );

		padValue |= data[ length + i ] ^ padSize;
		}
	ENSURES( LOOP_BOUND_OK );
	if( padValue != 0 )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid encryption padding byte value, expected 0x%02X",
				  padSize ) );
		}
	*processedDataLength = length;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								TLS MAC Functions							*
*																			*
****************************************************************************/

/* Perform a TLS MAC of a data block.  We have to provide special-case 
   handling of zero-length blocks since some versions of OpenSSL send these 
   as a kludge in TLS 1.0 to work around chosen-IV attacks.

   In the following functions we don't check the return value of every 
   single component MAC operation since it would lead to endless sequences
   of 'status = x; if( cSOK( x ) ) ...' chains, on the remote chance that
   there's some transient failure in a single component operation it'll be
   picked up at the end anyway when the overall MAC check fails */

CHECK_RETVAL \
static int macDataTLS( IN_HANDLE const CRYPT_CONTEXT iHashContext, 
					   IN_INT_Z const long seqNo, 
					   IN_RANGE( TLS_MINOR_VERSION_TLS, \
								 TLS_MINOR_VERSION_TLS13 ) const int version,
					   IN_BUFFER_OPT( ivLength ) const void *iv, 
					   IN_LENGTH_IV_Z const int ivLength, 
					   IN_BUFFER_OPT( dataLength ) const void *data, 
					   IN_DATALENGTH_Z const int dataLength, 
					   IN_BYTE const int type )
	{
	BYTE metadataBuffer[ 64 + CRYPT_MAX_IVSIZE + 8 ];
	int metadataLength, status;

	assert( ( iv == NULL && ivLength == 0 ) || \
			isReadPtrDynamic( iv, ivLength ) );
	assert( ( data == NULL && dataLength == 0 ) || \
			isReadPtrDynamic( data, dataLength ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= TLS_MINOR_VERSION_TLS && \
			  version <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( ( iv == NULL && ivLength == 0 ) || \
			  ( iv != NULL && \
				ivLength > 0 && ivLength <= CRYPT_MAX_IVSIZE ) );
	REQUIRES( ( data == NULL && dataLength == 0 ) || \
			  ( data != NULL && \
				dataLength > 0 && dataLength <= MAX_PACKET_SIZE + 512 ) );
	REQUIRES( type >= 0 && type <= 255 );

	/* Set up the packet metadata to be MACed */
	status = writePacketMetadata( metadataBuffer, 64, &metadataLength, type, 
								  seqNo, version, dataLength + ivLength );
	if( cryptStatusError( status ) )
		return( status );
	if( ivLength > 0 )
		{
		/* If we're using an explicit IV, append it to the metadata for
		   MAC'ing */
		REQUIRES( boundsCheck( metadataLength, ivLength, 
							   64 + CRYPT_MAX_IVSIZE ) );
		memcpy( metadataBuffer + metadataLength, iv, ivLength );
		metadataLength += ivLength;
		}

	/* Reset the hash context and generate the MAC:

		HMAC( metadata || (IV) || data ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, metadataBuffer, 
					 metadataLength );
	if( dataLength > 0 )
		{
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) data, dataLength );
		}
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				  INOUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				  IN_DATALENGTH const int dataMaxLength, 
				  OUT_DATALENGTH_Z int *dataLength,
				  IN_DATALENGTH const int payloadLength, 
				  IN_BYTE const int type )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( payloadLength > 0 && payloadLength <= MAX_PACKET_SIZE + 512 && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataMaxLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* Clear return values */
	*dataLength = 0;

	/* MAC the payload.  When wrapping a packet the IV is treated as part of
	   the payload so it's always passed in as { NULL, 0 }, it's only when
	   unwrapping that it's stripped before the payload data is copied into
	   the session buffer and so needs to be passed in explicitly */
	status = macDataTLS( sessionInfoPtr->iAuthOutContext, tlsInfo->writeSeqNo,
						 sessionInfoPtr->version, NULL, 0, data, 
						 payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->writeSeqNo++;

	/* Append the MAC value to the end of the packet */
	ENSURES( boundsCheck( payloadLength, sessionInfoPtr->authBlocksize,
						  dataMaxLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthOutContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = payloadLength + sessionInfoPtr->authBlocksize;
	INJECT_FAULT( SESSION_CORRUPT_MAC, SESSION_CORRUPT_MAC_TLS_1 );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLS( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) const void *data, 
				 IN_DATALENGTH const int dataLength, 
				 IN_DATALENGTH_Z const int payloadLength, 
				 IN_BYTE const int type, 
				 IN_BOOL const BOOLEAN noReportError )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	const void *ivPtr = NULL;
	int ivLength = 0, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE + 512 && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataLength );
	REQUIRES( type >= 0 && type <= 255 );
	REQUIRES( isBooleanValue( noReportError ) );

	/* MAC the payload.  If the payload length is zero then there's no data 
	   payload, this can happen with some versions of OpenSSL that send 
	   zero-length blocks as a kludge to work around pre-TLS 1.1 chosen-IV
	   attacks */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_ENCTHENMAC ) && \
		tlsInfo->ivSize > 0 )
		{
		/* When using encrypt-then-MAC and TLS 1.1+ explicit IVs, the IV is
		   authenticated alongside the encrypted payload data */
		ivPtr = tlsInfo->iv;
		ivLength = tlsInfo->ivSize;
		}
	if( payloadLength <= 0 )
		{
		status = macDataTLS( sessionInfoPtr->iAuthInContext, 
							 tlsInfo->readSeqNo, sessionInfoPtr->version, 
							 ivPtr, ivLength, NULL, 0, type );
		}
	else
		{
		status = macDataTLS( sessionInfoPtr->iAuthInContext, 
							 tlsInfo->readSeqNo, sessionInfoPtr->version, 
							 ivPtr, ivLength, data, payloadLength, type );
		}
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->readSeqNo++;

	/* Compare the calculated MAC to the MAC present at the end of the 
	   data */
	ENSURES( boundsCheckZ( payloadLength, sessionInfoPtr->authBlocksize,
						   dataLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		/* If the error message has already been set at a higher level, 
		   don't update the error information */
		if( noReportError )
			return( CRYPT_ERROR_SIGNATURE );

		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad message MAC for packet type %d, length %d",
				  type, dataLength ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								TLS GCM Functions							*
*																			*
****************************************************************************/

#ifdef USE_GCM

/* Perform a TLS GCM integrity check of a data block.  This differs somewhat
   from the more conventional MACing routines because GCM combines the ICV
   generation with encryption, so all that we're actually doing is 
   generating the initial stage of the ICV over the packet metadata handled
   as GCM AAD */

CHECK_RETVAL \
int macDataTLSGCM( IN_HANDLE const CRYPT_CONTEXT iCryptContext, 
				   IN_INT_Z const long seqNo, 
				   IN_RANGE( TLS_MINOR_VERSION_TLS, \
							 TLS_MINOR_VERSION_TLS13 ) const int version,
				   IN_LENGTH_Z const int payloadLength, 
				   IN_BYTE const int type )
	{
	MESSAGE_DATA msgData;
	BYTE metadataBuffer[ 64 + 8 ];
	int metadataLength, status;

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= TLS_MINOR_VERSION_TLS && \
			  version <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( payloadLength >= 0 && \
			  payloadLength <= MAX_PACKET_SIZE + \
						( version >= TLS_MINOR_VERSION_TLS13 ? 1 : 0 ) );
	REQUIRES( type >= 0 && type <= 255 );

	/* Set up the packet metadata to be MACed */
#ifdef USE_TLS13
	if( version <= TLS_MINOR_VERSION_TLS12 )
		{
		status = writePacketMetadata( metadataBuffer, 64, &metadataLength, 
									  type, seqNo, version, payloadLength );
		}
	else
		{
		status = writePacketMetadataTLS13( metadataBuffer, 64, 
										   &metadataLength, payloadLength );
		}
#else
	status = writePacketMetadata( metadataBuffer, 64, &metadataLength, 
								  type, seqNo, version, payloadLength );
#endif /* USE_TLS13 */
	if( cryptStatusError( status ) )
		return( status );

	/* Send the AAD to the GCM context for inclusion in the ICV 
	   calculation */
	setMessageData( &msgData, metadataBuffer, metadataLength );
	return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
							 &msgData, CRYPT_IATTRIBUTE_AAD ) );
	}
#endif /* USE_GCM */

/****************************************************************************
*																			*
*							TLS Bernstein Functions							*
*																			*
****************************************************************************/

#ifdef USE_POLY1305

/* Because both Chacha20 and Poly1305 fail catastrophically on a repeated 
   IV, TLS goes through considerable calisthenics to try and prevent this
   from happening, with each IV being built up from successive layers of 
   counters and similar values, compensating for the fragility of the modes
   used by throwing in a kitchen sink of changing values.  Each IV is built
   up as follows:

				+---------------+---------------------------+
				| 32-bit zeroes	|	64-bit sequence no.		|
				+---------------+---------------------------+
									XOR
				+-------------------------------------------+
				|				TLS read/write IV			|
				+-------------------------------------------+
									 |
									 v
	+-----------+-------------------------------------------+
	| 32-bit ctr|				96-bit IV					|
	+-----------+-------------------------------------------+

   with the 32-bit counter being encoded backwards (little-endian format) for
   Bernstein cargo-cult purposes.
   
   This IV, with the counter set to zero, is used to generate the Poly1305 
   key.  The counter is then set to one and used to encrypt/decrypt the 
   data */

CHECK_RETVAL \
int initCryptBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr,
						IN_BOOL const BOOLEAN isRead )
	{
	CRYPT_CONTEXT iMacContext, iCryptContext;
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	STREAM stream;
	MESSAGE_DATA msgData;
	BYTE poly1305key[ CRYPT_MAX_KEYSIZE + 8 ];
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
		iMacContext = sessionInfoPtr->iAuthInContext;
		iCryptContext = sessionInfoPtr->iCryptInContext;
		}
	else
		{
		seqNo = tlsInfo->writeSeqNo;
		ivPtr = tlsInfo->aeadWriteSalt;
		iMacContext = sessionInfoPtr->iAuthOutContext;
		iCryptContext = sessionInfoPtr->iCryptOutContext;
		}

	/* Assemble the Chacha20 IV */
	sMemOpen( &stream, ivBuffer, CRYPT_MAX_IVSIZE );
	writeUint32( &stream, 0 );				/* Counter */
	writeUint32( &stream, 0 );				/* 32 bits zeroes */
	status = writeUint64( &stream, seqNo );
	sMemDisconnect( &stream );
	ENSURES( cryptStatusOK( status ) );
	LOOP_MED( i = 0, i < BERNSTEIN_IV_SIZE, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, BERNSTEIN_IV_SIZE - 1 ) );

		ivBuffer[ bitsToBytes( 32 ) + i ] ^= ivPtr[ i ];
		}
	ENSURES( LOOP_BOUND_OK );

	/* Generate the Poly1305 key from the initial IV using Chacha20.  Since 
	   this is only used for one message and then discarded, and in any case
	   is just Chacha20 keystream output whose continuation we're about to 
	   send over the Internet, we don't take any special precautions to keep 
	   it in secure memory */
	setMessageData( &msgData, ivBuffer, 16 );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_IV );
	if( cryptStatusOK( status ) )
		{
		memset( poly1305key, 0, CRYPT_MAX_KEYSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT, 
								  poly1305key, 32 );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( poly1305key, 32 );
		return( status );
		}

	/* Rekey Poly1305, update the counter part of the IV, and reload the 
	   Chacha20 context from it */
	setMessageData( &msgData, poly1305key, 32 );
	status = krnlSendMessage( iMacContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_REKEY );
	if( cryptStatusOK( status ) )
		{
		ivBuffer[ 0 ] = 1;		/* 00 00 00 01 in little-endian format */
		setMessageData( &msgData, ivBuffer, 16 );
		status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_IV );
		}
	zeroise( poly1305key, 32 );

	return( status );
	}

/* Perform an integrity check of a data block using the Bernstein protocol 
   suite.  This is an AEAD exactly like GCM, but the IETF managed to make it 
   incompatible with the standard AEAD use so it needs custom handling.

   Specifically, instead of simply using the MAC as a MAC, the IETF came up 
   with a weirdo construct with no purpose whatsoever (Procter's "A Security 
   Analysis of the Composition of ChaCha20 and Poly1305" mentions it in 
   passing, but it plays no role in anything) but that makes calculating the 
   MAC value unnecessarily awkward and complex.

   Instead of MAC'ing the AAD and data as is, it has to be zero-padded to 
   the nearest 16-byte boundary, and the padded data MAC'd.  However, 
   because this has added needless zero bytes to the data, additional length 
   values that specify the size of the original unpadded data have to be 
   added to the end and MAC'd as well:

	"Once again, the Wellington Police have come up with a perfect solution 
	 to the problem / That's right - by removing the solution we had to 
	 another problem / The fact that if we hadn't put that sign up in the 
	 first place none of this would've happened is irrelevant.  What matters 
	 is that we've identified the problem / That we caused / Job well done / 
	 Good result" 
		- "Wellington Paranormal".

   As the icing on the cake, for Bernstein cargo-cult purposes the lengths 
   are encoded backwards, as little-endian integers rather than the standard 
   big-endian form used in all other IETF security protocols, so we can't 
   use writeUint64() but have to hand-assemble the values ourselves.

   So what finally ends up being MAC'd in place of the obvious "aad || data" 
   is:

	byte[]	aad
	byte[]	aadPadding = { 0 }		// Pad to multiple of 16 bytes
	byte[]	data
	byte[]	dataPadding = { 0 }		// Pad to multiple of 16 bytes
	buint64	aadLength				// Backwards uint64
	buint64	dataLength				// Backwards uint64 */

CHECK_RETVAL \
static int macDataTLSBernstein( IN_HANDLE const CRYPT_CONTEXT iHashContext, 
								IN_INT_Z const long seqNo, 
								IN_RANGE( TLS_MINOR_VERSION_TLS, \
										  TLS_MINOR_VERSION_TLS13 ) \
									const int version,
								IN_BUFFER( payloadLength ) \
									const void *payload, 
								IN_LENGTH_Z const int payloadLength, 
								IN_BYTE const int type )
	{
	static const BYTE zeroes[ 16 ] = { 0 };
	BYTE aadBuffer[ 64 + 8 ], lengthBuffer[ 16 + 8 ];
	int aadLength, aadPadLength, payloadPadLength, status;

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= TLS_MINOR_VERSION_TLS && \
			  version <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( payloadLength >= 0 && \
			  payloadLength <= MAX_PACKET_SIZE + \
						( version >= TLS_MINOR_VERSION_TLS13 ? 1 : 0 ) );
	REQUIRES( type >= 0 && type <= 255 );

	/* Set up the packet metadata to be MACed */
#ifdef USE_TLS13
	if( version <= TLS_MINOR_VERSION_TLS12 )
		{
		status = writePacketMetadata( aadBuffer, 64, &aadLength, type, 
									  seqNo, version, payloadLength );
		}
	else
		{
		status = writePacketMetadataTLS13( aadBuffer, 64, &aadLength, 
										   payloadLength );
		}
#else
	status = writePacketMetadata( aadBuffer, 64, &aadLength, type, 
								  seqNo, version, payloadLength );
#endif /* USE_TLS13 */
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the assorted unnecessary additional values that need to be 
	   MAC'd */
	aadPadLength = ( 16 - ( aadLength % 16 ) ) % 16;
	payloadPadLength = ( 16 - ( payloadLength % 16 ) ) % 16;
	memset( lengthBuffer, 0, 16 );
	lengthBuffer[ 0 ] = intToByte( aadLength );
	lengthBuffer[ 8 ] = intToByte( payloadLength );
	lengthBuffer[ 9 ] = intToByte( payloadLength >> 8 );

	/* MAC all of the little bits and pieces required to generate the AEAD 
	   MAC value */
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, aadBuffer, 
					 aadLength );
	if( aadPadLength > 0 )
		{
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) zeroes, aadPadLength );
		}
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) payload, payloadLength );
	if( payloadPadLength > 0 )
		{
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) zeroes, payloadPadLength );
		}
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, lengthBuffer, 16 );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLSBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						   INOUT_BUFFER( dataMaxLength, *dataLength ) \
								void *data, 
						   IN_DATALENGTH const int dataMaxLength, 
						   OUT_DATALENGTH_Z int *dataLength,
						   IN_DATALENGTH const int payloadLength, 
						   IN_BYTE const int type )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtrDynamic( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataMaxLength ) );
	REQUIRES( payloadLength > 0 && payloadLength <= MAX_PACKET_SIZE + 512 && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataMaxLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* Clear return values */
	*dataLength = 0;

	/* MAC the payload and metadata */
	status = macDataTLSBernstein( sessionInfoPtr->iAuthOutContext, 
								  tlsInfo->writeSeqNo, 
								  sessionInfoPtr->version, data, 
								  payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->writeSeqNo++;

	/* Append the MAC value to the end of the packet */
	ENSURES( boundsCheck( payloadLength, sessionInfoPtr->authBlocksize,
						  dataMaxLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthOutContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = payloadLength + sessionInfoPtr->authBlocksize;
	INJECT_FAULT( SESSION_CORRUPT_MAC, SESSION_CORRUPT_MAC_TLS_1 );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLSBernstein( INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						  IN_BUFFER( dataLength ) const void *data, 
						  IN_DATALENGTH const int dataLength, 
						  IN_DATALENGTH_Z const int payloadLength, 
						  IN_BYTE const int type )
	{
	TLS_INFO *tlsInfo = sessionInfoPtr->sessionTLS;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE + 512 && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* MAC the payload and metadata */
	status = macDataTLSBernstein( sessionInfoPtr->iAuthInContext, 
								  tlsInfo->readSeqNo, 
								  sessionInfoPtr->version, data, 
								  payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	tlsInfo->readSeqNo++;

	/* Compare the calculated MAC to the MAC present at the end of the 
	   data */
	ENSURES( boundsCheckZ( payloadLength, sessionInfoPtr->authBlocksize,
						   dataLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad message MAC for packet type %d, length %d",
				  type, dataLength ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_POLY1305 */

/****************************************************************************
*																			*
*					Handshake Message Hash/MAC Functions					*
*																			*
****************************************************************************/

/* Perform assorted hashing of a data block, a dual dual MD5+SHA-1 hash for 
   TLS 1.0 - 1.1 or a straight SHA-2 hash for TLS 1.2+.  Since this is part 
   of an ongoing message exchange (in other words a failure potentially 
   won't be detected for some time) we check each return value.  This 
   processing was originally done using a dual MD5+SHA-1 hash, however 
   TLS 1.2+ switched to using a single SHA-2 hash, because of this we have 
   to explicitly check which hashing option we're using (in some cases it 
   might be both since we have to speculatively hash initial messages until 
   we've agreed on a version) and only use that hash.
   
   In addition to the overall hashing we may also be running a separate hash 
   of the messages that stops before the other hashing does if certificate-
   based client authentication is being used.  This would add even more 
   overhead to the whole process, however since it's only used with TLS 1.2+
   and in that case is restricted to using SHA-2 via hashing preferences
   sent in the hello messages, we can obtain the necessary hash value by
   cloning the SHA-2 context at the point where we have to generate or 
   verify the client signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int hashHSData( const TLS_HANDSHAKE_INFO *handshakeInfo,
					   IN_BUFFER( dataLength ) const void *data, 
					   IN_DATALENGTH const int dataLength )
	{
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isReadPtrDynamic( data, dataLength ) );

	REQUIRES( isBufsizeRangeNZ( dataLength ) );

	if( handshakeInfo->md5context != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->md5context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( handshakeInfo->sha1context,
									  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
									  dataLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	if( handshakeInfo->sha2context != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->sha2context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
		if( cryptStatusError( status ) )
			return( status );
		}
#ifdef CONFIG_SUITEB
	if( handshakeInfo->sha384context != CRYPT_ERROR )
		{
		status = krnlSendMessage( handshakeInfo->sha384context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* CONFIG_SUITEB */

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int hashHSPacketRead( IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT_PTR STREAM *stream )
	{
	const int dataLength = sMemDataLeft( stream );
	void *data;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBufsizeRangeNZ( dataLength ) );

	/* On a read we've just processed the packet header and everything 
	   that's left in the stream is the data to be MACd.  Note that we can't 
	   use sMemGetDataBlockRemaining() for this because that returns the
	   entire available buffer, not just the amount of data in the buffer */
	status = sMemGetDataBlock( stream, &data, dataLength );
	if( cryptStatusOK( status ) )
		{
		ANALYSER_HINT( data != NULL );
		status = hashHSData( handshakeInfo, data, dataLength );
		}
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int hashHSPacketWrite( IN_PTR const TLS_HANDSHAKE_INFO *handshakeInfo, 
					   INOUT_PTR STREAM *stream,
					   IN_DATALENGTH_Z const int offset )
	{
	const int dataStart = offset + TLS_HEADER_SIZE;
	void *data DUMMY_INIT;
	int dataLength, status;

	assert( isReadPtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );
	REQUIRES( isBufsizeRange( offset ) );

	/* On a write we've just finished writing the packet and everything but
	   the header needs to be MACd */
	status = calculateStreamObjectLength( stream, dataStart, &dataLength );
	if( cryptStatusOK( status ) )
		{
		status = sMemGetDataBlockAbs( stream, dataStart, &data, 
									  dataLength );
		}
	if( cryptStatusOK( status ) )
		{
		ANALYSER_HINT( data != NULL );
		status = hashHSData( handshakeInfo, data, dataLength );
		}
	return( status );
	}

/* Complete the hash/MAC or SHA2 MAC that's used in the finished message.  
   There are no less than three variations of this, one for SSL's dual MAC
   (which is no longer used), one for TLS 1.0 - 1.1's IPsec cargo cult 
   96-bit PRF'd dual MAC, and one for TLS 1.2's similarly cargo-cult 96-bit 
   PRF'd single MAC (unless we're using TLS 1.2 LTS).
   
   We don't check the return value of every single component MAC operation 
   since it would lead to endless sequences of 'status = x; 
   if( cSOK( x ) ) ...' chains, on the remote chance that there's some 
   transient failure in a single component operation it'll be picked up at 
   the end anyway when the overall MAC check fails */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) ) \
int completeTLSHashedMAC( IN_HANDLE const CRYPT_CONTEXT md5context,
						  IN_HANDLE const CRYPT_CONTEXT sha1context, 
						  OUT_BUFFER( hashValuesMaxLen, *hashValuesLen )
								BYTE *hashValues, 
						  IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
						  OUT_LENGTH_BOUNDED_Z( hashValuesMaxLen ) \
								int *hashValuesLen,
						  IN_BUFFER( labelLength ) const char *label, 
						  IN_RANGE( 1, 64 ) const int labelLength, 
						  IN_BUFFER( masterSecretLen ) \
								const BYTE *masterSecret, 
						  IN_LENGTH_SHORT const int masterSecretLen )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	BYTE hashBuffer[ 64 + ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	int status;

	assert( isWritePtrDynamic( hashValues, hashValuesMaxLen ) );
	assert( isWritePtr( hashValuesLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( label, labelLength ) );
	assert( isReadPtrDynamic( masterSecret, masterSecretLen ) );

	REQUIRES( isHandleRangeValid( md5context ) );
	REQUIRES( isHandleRangeValid( sha1context ) );
	REQUIRES( isShortIntegerRangeMin( hashValuesMaxLen, \
									  TLS_HASHEDMAC_SIZE ) );
	REQUIRES( labelLength > 0 && labelLength <= 64 && \
			  labelLength + MD5MAC_SIZE + SHA1MAC_SIZE <= \
						64 + ( CRYPT_MAX_HASHSIZE * 2 ) );

	/* Clear return value */
	*hashValuesLen = 0;

	REQUIRES( rangeCheck( labelLength, 1, 
			  64 + ( CRYPT_MAX_HASHSIZE * 2 ) ) );
	memcpy( hashBuffer, label, labelLength );

	/* Complete the hashing and get the MD5 and SHA-1 hashes */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashBuffer + labelLength, MD5MAC_SIZE );
	status = krnlSendMessage( md5context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hashBuffer + labelLength + MD5MAC_SIZE,
						SHA1MAC_SIZE );
		status = krnlSendMessage( sha1context, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the TLS check value.  This isn't really a hash or a MAC but
	   is generated by feeding the MD5 and SHA1 hashes of the handshake 
	   messages into the TLS key derivation (PRF) function and truncating 
	   the result to 12 bytes (96 bits) for IPsec cargo cult protocol design
	   purposes:

		TLS_PRF( label || MD5_hash || SHA1_hash ) */
	setMechanismDeriveInfo( &mechanismInfo, hashValues, 
							TLS_HASHEDMAC_SIZE, ( MESSAGE_CAST ) masterSecret, 
							masterSecretLen, 
							CRYPT_ALGO_NONE,	/* Implicit SHA1+MD5 */ 
							hashBuffer, 
							labelLength + MD5MAC_SIZE + SHA1MAC_SIZE, 1 );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							  &mechanismInfo, MECHANISM_DERIVE_TLS );
	if( cryptStatusOK( status ) )
		*hashValuesLen = TLS_HASHEDMAC_SIZE;
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4, 5, 7 ) ) \
int completeTLS12HashedMAC( IN_HANDLE const CRYPT_CONTEXT sha2context,
							OUT_BUFFER( hashValuesMaxLen, *hashValuesLen ) \
								BYTE *hashValues, 
							IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
							OUT_LENGTH_BOUNDED_Z( hashValuesMaxLen ) \
								int *hashValuesLen,
							IN_BUFFER( labelLength ) const char *label, 
							IN_RANGE( 1, 64 ) const int labelLength, 
							IN_BUFFER( masterSecretLen ) \
								const BYTE *masterSecret, 
							IN_LENGTH_SHORT const int masterSecretLen,
							IN_BOOL const BOOLEAN fullSizeMAC )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	BYTE hashBuffer[ 64 + ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	const int hashedMacSize = ( fullSizeMAC ) ? 32 : TLS_HASHEDMAC_SIZE;
	int macSize, status;

	assert( isWritePtrDynamic( hashValues, hashValuesMaxLen ) );
	assert( isWritePtr( hashValuesLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( label, labelLength ) );
	assert( isReadPtrDynamic( masterSecret, masterSecretLen ) );

	REQUIRES( isHandleRangeValid( sha2context ) );
	REQUIRES( isShortIntegerRangeMin( hashValuesMaxLen, 32 ) );
	REQUIRES( labelLength > 0 && labelLength <= 64 && \
			  labelLength + CRYPT_MAX_HASHSIZE <= 64 + ( CRYPT_MAX_HASHSIZE ) );
	REQUIRES( isBooleanValue( fullSizeMAC ) );

	/* Clear return value */
	*hashValuesLen = 0;

	REQUIRES( rangeCheck( labelLength, 1, 
			  64 + ( CRYPT_MAX_HASHSIZE * 2 ) ) );
	memcpy( hashBuffer, label, labelLength );

	/* Get the MAC size */
	status = krnlSendMessage( sha2context, IMESSAGE_GETATTRIBUTE, &macSize,
							  CRYPT_CTXINFO_BLOCKSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Complete the hashing and get the SHA-2 hash */
	krnlSendMessage( sha2context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashBuffer + labelLength, macSize );
	status = krnlSendMessage( sha2context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the TLS check value.  This isn't really a hash or a MAC but
	   is generated by feeding the SHA-2 hash of the handshake messages into 
	   the TLS key derivation (PRF) function and truncating the result to 12 
	   bytes (96 bits) for IPsec cargo cult protocol design purposes, unless
	   we're using TLS-LTS in which case we use the full-size result:

		TLS_PRF( label || SHA2_hash ) */
	setMechanismDeriveInfo( &mechanismInfo, hashValues, hashedMacSize, 
							( MESSAGE_CAST ) masterSecret, masterSecretLen, 
							CRYPT_ALGO_SHA2, hashBuffer, 
							labelLength + macSize, 1 );
	if( macSize != bitsToBytes( 256 ) )
		mechanismInfo.hashParam = macSize;
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							  &mechanismInfo, MECHANISM_DERIVE_TLS12 );
	if( cryptStatusOK( status ) )
		*hashValuesLen = hashedMacSize;
	return( status );
	}
#endif /* USE_TLS */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
