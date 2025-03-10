/****************************************************************************
*																			*
*						 cryptlib CMP Crypto Routines						*
*						Copyright Peter Gutmann 1999-2009					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "cmp.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "session/session.h"
  #include "session/cmp.h"
#endif /* Compiler-specific includes */

#ifdef USE_CMP

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Hash/MAC the message header and body */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int hashMessageContents( IN_HANDLE const CRYPT_CONTEXT iHashContext,
						 IN_BUFFER( length ) const void *data, 
						 IN_LENGTH_SHORT const int length )
	{
	STREAM stream;
	BYTE buffer[ 8 + 8 ];
	int status;

	assert( isReadPtrDynamic( data, length ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isShortIntegerRangeNZ( length ) );

	/* Delete the hash/MAC value, which resets the context */
	status = krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the pseudoheader used for hashing/MACing the message and
	   hash/MAC it */
	sMemOpen( &stream, buffer, 8 );
	status = writeSequence( &stream, length );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, 
								  stell( &stream ) );
		}
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Hash/MAC the message itself */
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
							  ( MESSAGE_CAST ) data, length );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, 0 );
	return( status );
	}

/****************************************************************************
*																			*
*								MAC Routines								*
*																			*
****************************************************************************/

/* Initialise the MAC information used to protect the messages */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) \
int initMacInfo( IN_HANDLE const CRYPT_CONTEXT iMacContext, 
				 IN_BUFFER( passwordLength ) const void *password, 
				 IN_LENGTH_SHORT const int passwordLength, 
				 IN_BUFFER( saltLength ) const void *salt, 
				 IN_LENGTH_SHORT const int saltLength, 
				 IN_RANGE( 1, CMP_MAX_PW_ITERATIONS ) const int iterations )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	BYTE macKey[ CRYPT_MAX_HASHSIZE + 8 ];
	int status;

	assert( isReadPtrDynamic( password, passwordLength ) );
	assert( isReadPtrDynamic( salt, saltLength ) );

	REQUIRES( isHandleRangeValid( iMacContext ) );
	REQUIRES( isShortIntegerRangeNZ( passwordLength ) );
	REQUIRES( isShortIntegerRangeNZ( saltLength ) );
	REQUIRES( iterations >= 1 && iterations <= CMP_MAX_PW_ITERATIONS );

	/* Turn the password into an HMAC key using the CMP/Entrust password 
	   derivation mechanism */
	setMechanismDeriveInfo( &mechanismInfo, macKey, CMP_HMAC_KEYSIZE,
							password, passwordLength, CRYPT_ALGO_SHA1,
							( MESSAGE_CAST ) salt, saltLength, iterations );
	status = krnlSendMessage( MECHANISM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE, 
							  &mechanismInfo, MECHANISM_DERIVE_CMP );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the key into the MAC context */
	setMessageData( &msgData, macKey, CMP_HMAC_KEYSIZE );
	status = krnlSendMessage( iMacContext, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_KEY );
	zeroise( macKey, CRYPT_MAX_HASHSIZE );
	return( status );
	}

/* Read/write the CMP/Entrust MAC information:

	macInfo ::= SEQUENCE {
		algoID			OBJECT IDENTIFIER (entrustMAC),
		algoParams		SEQUENCE {
			salt		OCTET STRING,
			pwHashAlgo	AlgorithmIdentifier (SHA-1)
			iterations	INTEGER,
			macAlgo		AlgorithmIdentifier (HMAC-SHA1)
			} OPTIONAL
		} 

   The standard only specifies the use of SHA1/HMAC-SHA1 (alongside the 
   usual confused text about what should actually be used, including 
   mention of options like single-DES MAC), so we only allow these 
   algorithms.  Since only we're using it as PRF rather than a hash 
   function, it doesn't require strong security properties */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readMacInfo( INOUT_PTR STREAM *stream, 
				 INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
				 IN_BUFFER( passwordLength ) const void *password, 
				 IN_LENGTH_SHORT const int passwordLength,
				 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_ALGO_TYPE algorithm DUMMY_INIT;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE salt[ CRYPT_MAX_HASHSIZE + 8 ];
	long value DUMMY_INIT;
	int saltLength, tag, iterations, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );
	assert( isReadPtrDynamic( password, passwordLength ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isShortIntegerRangeNZ( passwordLength ) );

	/* Read the various parameter fields */
	readSequence( stream, NULL );
	status = readFixedOID( stream, OID_ENTRUST_MAC,
						   sizeofOID( OID_ENTRUST_MAC ) );
	if( cryptStatusError( status ) )
		{
		/* If we don't find the Entrust MAC OID we specifically report it 
		   as an unknown algorithm problem rather than a generic bad data 
		   error */
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADALG;
		retExt( status, 
				( status, errorInfo, 
				  "Unrecognised password-based MAC mechanism" ) );
		}
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == BER_NULL )
		{
		/* No parameters, use the same values as for the previous
		   transaction */
		return( CRYPT_OK );
		}
	readSequence( stream, NULL );
	status = readOctetString( stream, salt, &saltLength, 4, 
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusOK( status ) )
		status = readAlgoID( stream, &algorithm, ALGOID_CLASS_HASH );
	if( cryptStatusOK( status ) && algorithm != CRYPT_ALGO_SHA1 )
		status = CRYPT_ERROR_NOTAVAIL;
	if( cryptStatusOK( status ) )
		{
		status = readShortInteger( stream, &value );
		if( cryptStatusOK( status ) )
			status = readAlgoID( stream, &algorithm, ALGOID_CLASS_HASH );
		if( cryptStatusOK( status ) && algorithm != CRYPT_ALGO_HMAC_SHA1 )
			status = CRYPT_ERROR_NOTAVAIL;
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid passwod-based MAC algorithm information" ) );
		}
	if( value < 1 || value > CMP_MAX_PW_ITERATIONS )
		{
		/* Prevent DoS attacks due to excessive iteration counts (bad
		   algorithm is about the most appropriate error that we can return 
		   here).  The spec never defines any appropriate limits for this 
		   value, which leads to interesting effects when submitting a 
		   request for bignum iterations to some implementations */
		protocolInfo->pkiFailInfo = CMPFAILINFO_BADALG;
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid passwod-based MAC iteration count %ld", 
				  value ) );
		}
	ENSURES( isIntegerRange( value ) );
	iterations = ( int ) value;

	/* If the MAC parameters aren't set yet (meaing that we're the server), 
	   set them based on the client's values */
	if( protocolInfo->saltSize <= 0 )
		{
		status = initMacInfo( protocolInfo->iMacContext, password,
							  passwordLength, salt, saltLength, iterations );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, errorInfo, 
					  "Couldn't initialise passwod-based MAC "
					  "information" ) );
			}
		REQUIRES( rangeCheck( saltLength, 0, CRYPT_MAX_HASHSIZE ) );
		memcpy( protocolInfo->salt, salt, saltLength );
		protocolInfo->saltSize = saltLength;
		protocolInfo->iterations = iterations;
		DEBUG_PRINT(( "%s: Read initial MAC params with salt, %d iterations.\n",
					  protocolInfo->isServer ? "SVR" : "CLI", 
					  protocolInfo->iterations ));
		DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
						protocolInfo->salt, protocolInfo->saltSize );
		return( CRYPT_OK );
		}

	/* If the new parameters match our original MAC parameters, reuse the 
	   existing MAC context.  As usual the spec is ambiguous over the use of 
	   the MAC information, leaving it possible for implementations to re-
	   key the MAC on a per-message basis.  We try and cache MAC information 
	   as much as possible to reduce the performance hit from re-keying for 
	   each message */
	if( protocolInfo->iterations && \
		saltLength == protocolInfo->saltSize && \
		!memcmp( salt, protocolInfo->salt, saltLength ) && \
		iterations == protocolInfo->iterations )
		{
		DEBUG_PRINT(( "%s: Skipped repeated MAC params with salt, "
					  "%d iterations.\n",
					  protocolInfo->isServer ? "SVR" : "CLI", 
					  protocolInfo->iterations ));
		DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
						protocolInfo->salt, protocolInfo->saltSize );
		return( CRYPT_OK );
		}

	/* This is a new set of parameters, recreate the MAC context with them */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_HMAC_SHA1 );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	status = initMacInfo( createInfo.cryptHandle, password, passwordLength,
						  salt, saltLength, iterations );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, errorInfo, 
				  "Couldn't initialise password-based MAC information" ) );
		}
	if( protocolInfo->iMacContext != CRYPT_ERROR )
		{
		krnlSendNotifier( protocolInfo->iMacContext,
						  IMESSAGE_DECREFCOUNT );
		}
	protocolInfo->iMacContext = createInfo.cryptHandle;

	/* Remember the parameters that were used to set up the MAC context */
	REQUIRES( rangeCheck( saltLength, 0, CRYPT_MAX_HASHSIZE ) );
	memcpy( protocolInfo->salt, salt, saltLength );
	protocolInfo->saltSize = saltLength;
	protocolInfo->iterations = iterations;
	DEBUG_PRINT(( "%s: Read new MAC params with salt, %d iterations.\n",
				  protocolInfo->isServer ? "SVR" : "CLI", 
				  protocolInfo->iterations ));
	DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
					protocolInfo->salt, protocolInfo->saltSize );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeMacInfo( INOUT_PTR STREAM *stream,
				  IN_PTR const CMP_PROTOCOL_INFO *protocolInfo,
				  IN_BOOL const BOOLEAN sendFullInfo )
	{
	int paramSize;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );

	REQUIRES( isBooleanValue( sendFullInfo ) );

	/* If we've already sent the MAC parameters in an earlier transaction,
	   just send an indication that we're using MAC protection */
	if( !sendFullInfo )
		{
		writeSequence( stream, sizeofOID( OID_ENTRUST_MAC ) + sizeofNull() );
		writeOID( stream, OID_ENTRUST_MAC );
		return( writeNull( stream, DEFAULT_TAG ) );
		}

	/* Determine how big the payload will be */
	paramSize = sizeofShortObject( protocolInfo->saltSize ) + \
				sizeofAlgoID( CRYPT_ALGO_SHA1 ) + \
				sizeofShortInteger( protocolInfo->iterations ) + \
				sizeofAlgoID( CRYPT_ALGO_HMAC_SHA1 );

	/* Write the wrapper */
	writeSequence( stream, sizeofOID( OID_ENTRUST_MAC ) + \
						   sizeofShortObject( paramSize ) );
	writeOID( stream, OID_ENTRUST_MAC );

	/* Write the payload */
	DEBUG_PRINT(( "%s: Writing MAC params with salt, %d iterations.\n",
				  protocolInfo->isServer ? "SVR" : "CLI", 
				  protocolInfo->iterations ));
	DEBUG_DUMP_HEX( protocolInfo->isServer ? "SVR" : "CLI", 
					protocolInfo->salt, protocolInfo->saltSize );
	writeSequence( stream, paramSize );
	writeOctetString( stream, protocolInfo->salt, protocolInfo->saltSize,
					  DEFAULT_TAG );
	writeAlgoID( stream, CRYPT_ALGO_SHA1, DEFAULT_TAG );
	writeShortInteger( stream, protocolInfo->iterations, DEFAULT_TAG );
	return( writeAlgoID( stream, CRYPT_ALGO_HMAC_SHA1, DEFAULT_TAG ) );
	}

/****************************************************************************
*																			*
*					Verify Integrity-Protection Information					*
*																			*
****************************************************************************/

/* Check integrity protection on a message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int checkMessageMAC( INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
					 IN_BUFFER( messageLength ) const void *message,
					 IN_DATALENGTH const int messageLength,
					 IN_BUFFER( macLength ) const void *mac,
					 IN_LENGTH_SHORT const int macLength )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );
	assert( isReadPtrDynamic( message, messageLength ) );
	assert( isReadPtrDynamic( mac, macLength ) );

	REQUIRES( isBufsizeRangeNZ( messageLength ) );
	REQUIRES( macLength >= MIN_HASHSIZE && macLength <= CRYPT_MAX_HASHSIZE );

	/* MAC the data and make sure that it matches the value attached to the 
	   message */
	status = hashMessageContents( protocolInfo->iMacContext, message,
								  messageLength );
	if( cryptStatusOK( status ) )
		return( status );
	setMessageData( &msgData, ( MESSAGE_CAST ) mac, macLength );
	status = krnlSendMessage( protocolInfo->iMacContext, IMESSAGE_COMPARE, 
							  &msgData, MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_SIGNATURE );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int checkMessageSignature( INOUT_PTR CMP_PROTOCOL_INFO *protocolInfo,
						   IN_BUFFER( messageLength ) const void *message,
						   IN_DATALENGTH const int messageLength,
						   IN_BUFFER( signatureLength ) const void *signature,
						   IN_LENGTH_SHORT const int signatureLength,
						   IN_HANDLE const CRYPT_HANDLE iAuthContext )
	{
	CRYPT_CONTEXT iHashContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	ERROR_INFO localErrorInfo;
	int status;

	assert( isWritePtr( protocolInfo, sizeof( CMP_PROTOCOL_INFO ) ) );
	assert( isReadPtrDynamic( message, messageLength ) );
	assert( isReadPtrDynamic( signature, signatureLength ) );

	REQUIRES( isBufsizeRangeNZ( messageLength ) );
	REQUIRES( isShortIntegerRangeNZ( signatureLength ) );
	REQUIRES( isHandleRangeValid( iAuthContext ) );

	/* If it's a non-cryptlib message (in other words one where the 
	   certificate/signing key isn't unambiguously identified via a certID),
	   make sure that the sig-check key that we'll be using is the correct 
	   one.  Because of CMP's use of a raw signature format we have to do 
	   this manually rather than relying on the sig-check code to do it for 
	   us, and because of the braindamaged way of identifying integrity-
	   protection keys for non-cryptlib messages even this isn't enough to 
	   definitely tell us that we're using the right key, in which case 
	   we'll get a bad data or bad signature response from the sig-check 
	   code */
	if( !protocolInfo->isCryptlib )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, protocolInfo->senderDNPtr,
						protocolInfo->senderDNlength );
		status = krnlSendMessage( iAuthContext, IMESSAGE_COMPARE, &msgData,
								  MESSAGE_COMPARE_SUBJECT );
		if( cryptStatusError( status ) )
			{
			/* A failed comparison is reported as a generic CRYPT_ERROR, 
			   convert it into a wrong-key error if necessary */
			return( ( status == CRYPT_ERROR ) ? \
					CRYPT_ERROR_WRONGKEY : status );
			}
		}

	/* Hash the data and verify the signature.  Since this is a low-level 
	   operation, and the raw signature doesn't contain any metadata to 
	   provide additional information, there isn't any useful additional 
	   error information to return */
	clearErrorInfo( &localErrorInfo );
	setMessageCreateObjectInfo( &createInfo, protocolInfo->hashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iHashContext = createInfo.cryptHandle;
	if( protocolInfo->hashParam != 0 )
		{
		/* Some hash algorithms have variable output size, in which case 
		   we need to explicitly tell the context which one we're working 
		   with */
		status = krnlSendMessage( iHashContext, IMESSAGE_SETATTRIBUTE,
								  &protocolInfo->hashParam, 
								  CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = hashMessageContents( iHashContext, message, messageLength );
	if( cryptStatusOK( status ) )
		{
		status = checkRawSignature( signature, signatureLength, 
									iAuthContext, iHashContext,
									&localErrorInfo );
		}
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/****************************************************************************
*																			*
*					Create Integrity-Protection Information					*
*																			*
****************************************************************************/

/* Write MACd/signed message protection information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4, 6, 7 ) ) \
int writeMacProtinfo( IN_HANDLE const CRYPT_CONTEXT iMacContext,
					  IN_BUFFER( messageLength ) const void *message, 
					  IN_LENGTH_SHORT const int messageLength,
					  OUT_BUFFER( protInfoMaxLength, *protInfoLength ) \
							void *protInfo, 
					  IN_LENGTH_SHORT_MIN( 16 ) const int protInfoMaxLength,
					  OUT_LENGTH_BOUNDED_Z( protInfoMaxLength ) \
							int *protInfoLength,
					  INOUT_PTR ERROR_INFO *errorInfo )
	{
	STREAM macStream;
	MESSAGE_DATA msgData;
	BYTE macValue[ CRYPT_MAX_HASHSIZE + 8 ];
	int macLength, status;

	assert( isReadPtrDynamic( message, messageLength ) );
	assert( isWritePtrDynamic( protInfo, protInfoMaxLength ) );
	assert( isWritePtr( protInfoLength, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isHandleRangeValid( iMacContext ) );
	REQUIRES( isShortIntegerRangeNZ( messageLength ) );
	REQUIRES( isShortIntegerRangeMin( protInfoMaxLength, 16 ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( protInfoMaxLength ) ); 
	memset( protInfo, 0, min( 16, protInfoMaxLength ) );
	*protInfoLength = 0;

	/* MAC the message and get the MAC value */
	status = hashMessageContents( iMacContext, message, messageLength );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, macValue, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iMacContext, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Couldn't hash message contents" ) );
		}
	macLength = msgData.length;

	/* Write the MAC value with BIT STRING encapsulation */
	sMemOpen( &macStream, protInfo, protInfoMaxLength );
	writeBitStringHole( &macStream, macLength, DEFAULT_TAG );
	status = swrite( &macStream, macValue, macLength );
	if( cryptStatusOK( status ) )
		*protInfoLength = stell( &macStream );
	sMemDisconnect( &macStream );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 4, 6, 8, 9 ) ) \
int writeSignedProtinfo( IN_HANDLE const CRYPT_CONTEXT iSignContext,
						 IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						 IN_LENGTH_HASH_Z const int hashParam,
						 IN_BUFFER( messageLength ) const void *message, 
						 IN_LENGTH_SHORT const int messageLength,
						 OUT_BUFFER( protInfoMaxLength, *protInfoLength ) \
								void *protInfo, 
						 IN_LENGTH_SHORT_MIN( 32 ) \
								const int protInfoMaxLength,
						 OUT_LENGTH_BOUNDED_Z( protInfoMaxLength ) \
								int *protInfoLength,
						 INOUT_PTR ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT iHashContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	ERROR_INFO localErrorInfo;
	int status;

	assert( isReadPtrDynamic( message, messageLength ) );
	assert( isWritePtrDynamic( protInfo, protInfoMaxLength ) );
	assert( isWritePtr( protInfoLength, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( isHandleRangeValid( iSignContext ) );
	REQUIRES( isHashAlgo( hashAlgo ) );
	REQUIRES( hashParam == 0 || \
			  ( hashParam >= MIN_HASHSIZE && \
				hashParam <= CRYPT_MAX_HASHSIZE ) );
	REQUIRES( isShortIntegerRangeNZ( messageLength ) );
	REQUIRES( isShortIntegerRangeMin( protInfoMaxLength, 32 ) );

	/* Hash the data */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iHashContext = createInfo.cryptHandle;
	if( hashParam != 0 )
		{
		/* Some hash algorithms have variable output size, in which case
		   we need to explicitly tell the context which one we're working
		   with */
		status = krnlSendMessage( iHashContext, IMESSAGE_SETATTRIBUTE,
								  ( MESSAGE_CAST ) &hashParam, 
								  CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = hashMessageContents( iHashContext, message, messageLength );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, errorInfo,
				  "Couldn't hash message contents" ) );
		}

	/* Create the signature */
	clearErrorInfo( &localErrorInfo );
	status = createRawSignature( protInfo, protInfoMaxLength, 
								 protInfoLength, iSignContext, 
								 iHashContext, &localErrorInfo );
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		retExtErr( status,
				   ( status, errorInfo, &localErrorInfo,
					 "Couldn't sign message contents" ) );
		}

	return( CRYPT_OK );
	}
#endif /* USE_CMP */
