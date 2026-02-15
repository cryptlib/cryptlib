/****************************************************************************
*																			*
*							cryptlib TPM Emulation							*
*						Copyright Peter Gutmann 2020-2022					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "device.h"
  #include "tpm.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "device/device.h"
  #include "device/tpm.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_TPM

/* TPM emulation layer that emulates the FAPI calls without requiring the
   enormously complex and awkward TPM drivers and configuration to be 
   present */

#ifdef USE_TPM_EMULATION 

/* The size of the RSA test keys that we're generating.  This should match 
   the value in devices/tpm_pkc.c:capabilities[] but for testing purposes we 
   use the smallest key size we can get away with to make keygen faster */

#define TEST_KEYSIZE_BITS		1024

/* The path to store data nominally held in the TPM via FAPI_SetAppData()/
   FAPI_GetAppData() */

#define OBJECT_PATH_PREFIX		"/tmp/tpm_"
#define OBJECT_PATH_PREFIX_LEN	9
#define APPDATA_PATH			OBJECT_PATH_PREFIX "appdata.dat"

/* The buffer used to hold TPM data in memory.  This has to be static 
   because we never dynamically allocate any objects so Fapi_Free() is just 
   a no-op.  
   
   The size should match TPM_BUFFER_SIZE defined in device/tpm.c */

static BYTE appDataBuffer[ 8192 ];

/****************************************************************************
*																			*
*						 		Utility Functions							*
*																			*
****************************************************************************/

/* Find the ID portion of a FAPI path */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
static const char *getFapiPathID( IN_STRING const char *tpmPath )
	{
	int localPathPos;

	localPathPos = strFindStr( tpmPath, 
							   strnlen_s( tpmPath, CRYPT_MAX_TEXTSIZE ),
							   "cryptlib-", 9 );
	ENSURES_N( !cryptStatusError( localPathPos ) );
	
	return( tpmPath + localPathPos + 9 );
	}

/* Convert a FAPI object path into one that we can use locally */

STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static void getLocalFilePath( OUT_BUFFER( maxPathLength, *pathLength ) \
								char *localFilePath,
							  IN_LENGTH_SHORT_MIN( 32 ) \
								const int maxPathLength, 
							  OUT_LENGTH_SHORT_Z int *pathLength,
							  IN_STRING const char *tpmPath )
	{
	const char *pathID = getFapiPathID( tpmPath );

	assert( isWritePtr( localFilePath, maxPathLength ) );
	assert( isWritePtr( pathLength, sizeof( int ) ) );
	assert( isReadPtr( tpmPath, 16 ) );

	REQUIRES_V( isShortIntegerRangeMin( maxPathLength, 32 ) );
	REQUIRES_V( pathID != NULL );

	/* Extract the final part of the TPM path and convert it to a local path
	   in /tmp */
	memcpy( localFilePath, OBJECT_PATH_PREFIX, OBJECT_PATH_PREFIX_LEN );
	memcpy( localFilePath + OBJECT_PATH_PREFIX_LEN, pathID, 
			TPM_STORAGEID_STRING_LENGTH + 1 );
	*pathLength = OBJECT_PATH_PREFIX_LEN + TPM_STORAGEID_STRING_LENGTH + 1;
	}

/****************************************************************************
*																			*
*					FAPI Path to Cryptlib Object Functions					*
*																			*
****************************************************************************/

/* FAPI identifies everything through fixed paths which we have to map to 
   more normal handles via an index that takes the unique string at the end
   of the TPM path and maps it to a cryptlib context */

#ifdef USE_TPM_EXT

#define NO_FAPI_OBJECTS		16

typedef struct {
	char fapiID[ TPM_STORAGEID_STRING_LENGTH + 8 ];
	CRYPT_CONTEXT cryptContext;
	} FAPI_CONTEXT_INDEX;

static FAPI_CONTEXT_INDEX fapiContextIndex[ NO_FAPI_OBJECTS ];

static void initFapiContexts( void )
	{
	LOOP_INDEX i;

	memset( fapiContextIndex, 0, 
			sizeof( FAPI_CONTEXT_INDEX ) * NO_FAPI_OBJECTS );
	LOOP_MED( i = 0, i < NO_FAPI_OBJECTS, i++ )
		{
		ENSURES_V( LOOP_INVARIANT_MED( i, 0, NO_FAPI_OBJECTS - 1 ) );
		
		fapiContextIndex[ i ].cryptContext = CRYPT_ERROR;
		}
	ENSURES_V( LOOP_BOUND_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
static int addFapiContext( IN_HANDLE CRYPT_CONTEXT cryptContext,
						   IN_STRING const char *tpmPath )
	{
	const char *pathID = getFapiPathID( tpmPath );
	LOOP_INDEX i;

	assert( isReadPtr( tpmPath, 16 ) );

	REQUIRES( isHandleRangeValid( cryptContext ) );
	REQUIRES( pathID != NULL );

	/* Find a free slots in the context index and add the context to it */
	LOOP_MED( i = 0, i < NO_FAPI_OBJECTS, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, NO_FAPI_OBJECTS - 1 ) );

		if( fapiContextIndex[ i ].cryptContext == CRYPT_ERROR )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	if( i >= NO_FAPI_OBJECTS )
		return( CRYPT_ERROR_OVERFLOW );

	/* Remmeber the path ID and its associated context */
	memcpy( fapiContextIndex[ i ].fapiID, pathID, 
			TPM_STORAGEID_STRING_LENGTH );
	fapiContextIndex[ i ].cryptContext = cryptContext;

	return( CRYPT_OK );
	}

CHECK_RETVAL_RANGE( 0, NO_FAPI_OBJECTS - 1 ) STDC_NONNULL_ARG( ( 1 ) ) \
static int findFapiContextIndex( IN_STRING const char *tpmPath )
	{
	const char *pathID = getFapiPathID( tpmPath );
	LOOP_INDEX i;

	REQUIRES( pathID != NULL );

	LOOP_MED( i = 0, i < NO_FAPI_OBJECTS, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, NO_FAPI_OBJECTS - 1 ) );

		if( fapiContextIndex[ i ].cryptContext != CRYPT_ERROR && \
			!memcmp( fapiContextIndex[ i ].fapiID, pathID, 
					 TPM_STORAGEID_STRING_LENGTH ) )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	if( i >= NO_FAPI_OBJECTS )
		return( CRYPT_ERROR_NOTFOUND );

	return( i );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int findFapiContext( IN_STRING const char *tpmPath,
							OUT_HANDLE_OPT CRYPT_CONTEXT *cryptContext )
	{
	int fapiIndexPos, status;

	assert( isReadPtr( tpmPath, 16 ) );
	assert( isWritePtr( cryptContext, sizeof( CRYPT_CONTEXT ) ) );

	/* Clear return value */
	*cryptContext = CRYPT_ERROR;

	status = fapiIndexPos = findFapiContextIndex( tpmPath );
	if( cryptStatusError( status ) )
		return( status );
	*cryptContext = fapiContextIndex[ fapiIndexPos ].cryptContext;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int deleteFapiContext( IN_STRING const char *tpmPath )
	{
	int fapiIndexPos, status;

	assert( isReadPtr( tpmPath, 16 ) );

	status = fapiIndexPos = findFapiContextIndex( tpmPath );
	if( cryptStatusError( status ) )
		return( status );
	memset( fapiContextIndex[ fapiIndexPos ].fapiID, 0, 
			TPM_STORAGEID_STRING_LENGTH );
	fapiContextIndex[ fapiIndexPos ].cryptContext = CRYPT_ERROR;

	return( CRYPT_OK );
	}
#endif /* USE_TPM_EXT */

/****************************************************************************
*																			*
*						 		TPM Emulation Layer							*
*																			*
****************************************************************************/

/* Emulation of standard FAPI functions */

static BYTE sealKey[ 16 ];
static BOOLEAN sealKeyInited = FALSE;

TSS2_RC Fapi_CreateSeal( FAPI_CONTEXT *context, char const *path, 
						 char const *type, size_t size,
						 char const *policyPath, 
						 char const *authValue, uint8_t const *data )
	{
	memcpy( sealKey, data, 16 );
	sealKeyInited = TRUE;

	return( TSS2_RC_SUCCESS );
	}

void Fapi_Finalize( FAPI_CONTEXT **context )
	{
	/* Dummy function not needed in emulation */
	}

void Fapi_Free( void *ptr )
	{
	/* Emulated data structures are statically allocated so there's nothing 
	   to free */
	}

TSS2_RC Fapi_GetInfo( FAPI_CONTEXT *context, char **info )
	{
#if 1	/* The start of the giant 50-100kB blob of JSON that one FAPI driver 
		   returns for this call */
	*info = "{\r\n  \"version\":\"tpm2-tss 4.0.1-15-g56d90309\",\r\n  "
			"\"fapi_config\":{\r\n    \"profile_dir\":\"/home/ubuntu/"
			"workspace/tpm2-tss/test/data/fapi/\",\r\n    \"user_dir\""
			":\"/tmp/fapi_tmpdir.99ju7I/user/dir\",\r\n    \"system_dir"
			"\":\"/tmp/fapi_tmpdir.99ju7I/system_dir\",\r\n    \"log_dir"
			"\":\"/tmp/fapi_tmpdir.99ju7I\",\r\n    \"profile_name\":"
			"\"P_ECC\",\r\n    \"tcti\":\"swtpm\",\r\n    \"system_pcrs"
			"\":[\r\n    ],\r\n    \"ek_cert_file\":\"\",\r\n    "
			"\"ek_cert_less\":\"YES\",\r\n    \"intel_cert_service\":"
			"\"\"\r\n  },\r\n";
#else
	*info = "Fake TPM driver";
#endif /* 0 */
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_GetRandom( FAPI_CONTEXT *context, size_t numBytes, 
						uint8_t **data )
	{
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_Initialize( FAPI_CONTEXT **context, char const *uri )
	{
#ifdef USE_TPM_EXT
	initFapiContexts();
#endif /* USE_TPM_EXT */
	*context = ( FAPI_CONTEXT * ) "FAPI context memory";
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_Provision( FAPI_CONTEXT *context, const char *authValueEh,
						const char *authValueSh, 
						const char *authValueLockout )
	{
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_Unseal( FAPI_CONTEXT *context, char const *path, 
					 uint8_t **data, size_t *size )
	{
	/* If we haven't been provisioned yet we can't unseal */
	if( !sealKeyInited )
		return( TSS2_FAPI_RC_BAD_PATH );

	/* We've been provisioned, return the seal key */
	*data = sealKey;
	*size = 16;

	return( TSS2_RC_SUCCESS );
	}

/****************************************************************************
*																			*
*						 	TPM Extended Emulation Layer					*
*																			*
****************************************************************************/

/* Emulation of extended FAPI functions */

#ifdef USE_TPM_EXT

TSS2_RC Fapi_CreateKey( FAPI_CONTEXT *context, char const *path, 
						char const *type, 
						char const *policyPath, 
						char const *authValue )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	FILE *filePtr;
	char filePath[ CRYPT_MAX_TEXTSIZE + 8 ];
#if defined( _MSC_VER ) && VC_GE_2008( _MSC_VER )
	errno_t result;
#endif /* TR 24731 I/O functions */
	const int keySize = bitsToBytes( TEST_KEYSIZE_BITS );
	int filePathLength, status;

	/* Write a dummy entry for the key corresponding to the TPM object.  This
	   merely serves as a placeholder so that Fapi_Delete() works properly */
	getLocalFilePath( filePath, CRYPT_MAX_TEXTSIZE, &filePathLength, path );
#if defined( _MSC_VER ) && VC_GE_2008( _MSC_VER )

	result = fopen_s( &filePtr, filePath, "wb" );
	if( result != 0 )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
	ANALYSER_HINT( filePtr != NULL );
#else
	filePtr = fopen( filePath, "wb" );
	if( filePtr == NULL )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
#endif /* TR 24731 I/O functions */
	fwrite( path, strnlen_s( path, 512 ), 1, filePtr );
	fclose( filePtr );

	/* Create an RSA context to use to emulate the required RSA operations */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RSA );
	status = krnlSendMessage( CRYPTO_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( TSS2_FAPI_RC_NO_DECRYPT_PARAM );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
					 ( MESSAGE_CAST ) &keySize, CRYPT_CTXINFO_KEYSIZE );
	setMessageData( &msgData, "TMP Key", 7 );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S, 
					 &msgData, CRYPT_CTXINFO_LABEL );
	status = krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_CTX_GENKEY );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		remove( filePath );
		return( TSS2_RC_SUCCESS + 1 );
		}

	/* Add the context to the emulated FAPI storage */
	status = addFapiContext( createInfo.cryptHandle, path );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		remove( filePath );
		return( TSS2_RC_SUCCESS + 1 );
		}

	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_CreateNv( FAPI_CONTEXT *context, char const *path, 
					   char const *type, size_t size, 
					   char const *policyPath, char const *authValue )
	{
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_Decrypt( FAPI_CONTEXT *context, char const *keyPath, 
					  uint8_t const *cipherText, size_t cipherTextSize, 
					  uint8_t **plainText, size_t *plainTextSize )
	{
	CRYPT_CONTEXT cryptContext;
	static BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	LOOP_INDEX index;
	int payloadStartPos, status;

	/* Look up the context based on the TPM path and perform the private-key 
	   operation on the data */
	status = findFapiContext( keyPath, &cryptContext );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );
	memcpy( buffer, cipherText, cipherTextSize );
	status = krnlSendMessage( cryptContext, IMESSAGE_CTX_DECRYPT, buffer,
							  cipherTextSize );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );

	/* Undo the PKCS #1 padding to recover the key.  We can't use a 
	   LOOP_INVARIANT() or ENSURES() here because we'd need to return a
	   TSS2_RC with it which is nothing normal */
	if( buffer[ 0 ] != 0x00 || buffer[ 1 ] != 0x02 )
		return( TSS2_RC_SUCCESS + 1 );
	LOOP_LARGE( index = 1, index < cipherTextSize, index++ )
		{
		if( buffer[ index ] == 0 )
			break;
		}
	payloadStartPos = index + 1;	/* Skip final 0x00 */
	if( payloadStartPos < cipherTextSize - CRYPT_MAX_KEYSIZE || \
		payloadStartPos > cipherTextSize - MIN_KEYSIZE )
		return( TSS2_RC_SUCCESS + 1 );

	*plainText = buffer + payloadStartPos;
	*plainTextSize = cipherTextSize - payloadStartPos;

	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_Delete( FAPI_CONTEXT *context, char const *path )
	{
	CRYPT_CONTEXT cryptContext;
	int status;

	/* Look up and delete the context based on the TPM path */
	status = findFapiContext( path, &cryptContext );
	if( cryptStatusError( status ) )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
	krnlSendNotifier( cryptContext, IMESSAGE_DECREFCOUNT );
	( void ) deleteFapiContext( path );

	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_GetAppData( FAPI_CONTEXT *context, char const *path,
						 uint8_t **appData, size_t *appDataSize )
	{
	FILE *filePtr;
	long dataSize;
	int count;

#if defined( _MSC_VER ) && VC_GE_2008( _MSC_VER )
	errno_t result;

	result = fopen_s( &filePtr, APPDATA_PATH, "rb" );
	if( result != 0 )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
	ANALYSER_HINT( filePtr != NULL );
#else
	filePtr = fopen( APPDATA_PATH, "rb" );
	if( filePtr == NULL )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
#endif /* TR 24731 I/O functions */
	fseek( filePtr, 0, SEEK_END );
	dataSize = ftell( filePtr );
	if( dataSize >= 8192 )
		{
		fclose( filePtr );
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
		}
	fseek( filePtr, 0, SEEK_SET );
	count = fread( appDataBuffer, dataSize, 1, filePtr );
	fclose( filePtr );
	*appData = appDataBuffer;
	*appDataSize = ( size_t ) dataSize;
	return( TSS2_RC_SUCCESS );
	}

static CRYPT_CONTEXT tpmPublicBlobStorage;

TSS2_RC Fapi_GetTpmBlobs( FAPI_CONTEXT *context, char const *path, 
						  uint8_t **tpm2bPublic, size_t *tpm2bPublicSize, 
						  uint8_t **tpm2bPrivate, size_t *tpm2bPrivateSize, 
						  char **policy )
	{
	CRYPT_CONTEXT cryptContext;
	int status;

	/* This function doesn't actually return anything useful, see the long
	   comment in tpm_pkc.c, so what we have to do is use the returned data
	   field to encode the context containing the data that we want, with 
	   the useful information in it being extracted via 
	   Tss2_MU_TPM2B_PUBLIC_Unmarshal().  This is a somewhat unfortunate use
	   of static data for the context, but since the two calls are one right
	   after the other and it's only test code there shouldn't be a problem */
	status = findFapiContext( path, &cryptContext );
	if( cryptStatusError( status ) )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
	
	tpmPublicBlobStorage = cryptContext;
	*tpm2bPublic = ( uint8_t * ) &tpmPublicBlobStorage;
	*tpm2bPublicSize = sizeof( CRYPT_CONTEXT );

	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_SetAppData( FAPI_CONTEXT *context, char const *path,
						 uint8_t const *appData, size_t appDataSize )
	{
	FILE *filePtr;

#if defined( _MSC_VER ) && VC_GE_2008( _MSC_VER )
	errno_t result;

	result = fopen_s( &filePtr, APPDATA_PATH, "wb" );
	if( result != 0 )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
	ANALYSER_HINT( filePtr != NULL );
#else
	filePtr = fopen( APPDATA_PATH, "wb" );
	if( filePtr == NULL )
		return( TSS2_BASE_RC_PATH_NOT_FOUND );
#endif /* TR 24731 I/O functions */
	fwrite( appData, appDataSize, 1, filePtr );
	fclose( filePtr );
	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Fapi_Sign( FAPI_CONTEXT *context, char const *keyPath, 
				   char const *padding, uint8_t const *digest, 
				   size_t digestSize, uint8_t **signature, 
				   size_t *signatureSize, char **publicKey, 
				   char **certificate )
	{
	CRYPT_CONTEXT cryptContext;
	STREAM stream;
	static BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	LOOP_INDEX i;
	int payloadSize, status;

	/* Add the PKCS #1 needed for the signature.  We can't use a 
	   LOOP_INVARIANT() or ENSURES() here because we'd need to return a
	   TSS2_RC which is nothing normal */
	sMemOpen( &stream, buffer, CRYPT_MAX_PKCSIZE );
	payloadSize = sizeofMessageDigest( CRYPT_ALGO_SHA2, digestSize );
	sputc( &stream, 0 );
	sputc( &stream, 1 );
	LOOP_LARGE( i = 0,
				i < bitsToBytes( TEST_KEYSIZE_BITS ) - ( payloadSize + 3 ),
				i++ )
		{
		sputc( &stream, 0xFF );
		}
	sputc( &stream, 0 );
	status = writeMessageDigest( &stream, CRYPT_ALGO_SHA2, digest, 
								 digestSize );
	assert( cryptStatusOK( status ) );
	payloadSize = stell( &stream );
	sMemDisconnect( &stream );

	/* Look up the context based on the TPM path and perform the private-key 
	   operation on the data */
	status = findFapiContext( keyPath, &cryptContext );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );
	status = krnlSendMessage( cryptContext, IMESSAGE_CTX_DECRYPT, buffer,
							  payloadSize );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );
	*signature = buffer;
	*signatureSize = payloadSize;

	return( TSS2_RC_SUCCESS );
	}

TSS2_RC Tss2_MU_TPM2B_PUBLIC_Unmarshal( uint8_t const buffer[],
										size_t buffer_size, size_t *offset,
										TPM2B_PUBLIC *dest )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_CONTEXT cryptContext;
	static TPM2B_PUBLIC tpm2BPubkey;
	TPMT_PUBLIC *tpmtPubkey;
	TPMS_RSA_PARMS *rsaParams;
	TPM2B_PUBLIC_KEY_RSA *rsaPubKey;
	STREAM stream;
	MESSAGE_DATA msgData;
	BYTE integerValue[ CRYPT_MAX_PKCSIZE ];
	BYTE spkiBuffer[ 128 + CRYPT_MAX_PKCSIZE ];
	int integerLength DUMMY_INIT, status;

	/* Retrieve the context from the data we've been passed */
	if( buffer_size != sizeof( CRYPT_CONTEXT ) )
		return( TSS2_RC_SUCCESS + 1 );
	cryptContext = *( ( CRYPT_CONTEXT * ) buffer );

	/* Get the RSA n value from the SPKI */
	setMessageData( &msgData, spkiBuffer, 128 + CRYPT_MAX_PKCSIZE );
	status = krnlSendMessage( cryptContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );
	sMemConnect( &stream, spkiBuffer, msgData.length );
	readSequence( &stream, NULL );
	status = readAlgoID( &stream, &cryptAlgo, ALGOID_CLASS_PKC );
	if( cryptStatusOK( status ) )
		{
		readBitStringHole( &stream, NULL, 128, DEFAULT_TAG );
		readSequence( &stream, NULL );
		status = readInteger( &stream, integerValue, CRYPT_MAX_PKCSIZE, 
							  &integerLength );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( TSS2_RC_SUCCESS + 1 );

	/* Set up the incredibly convoluted structure needed for the TPM API.  
	   The format of the RSA n value is never documented anywhere but 
	   Botan's BigInt() says that it takes a big-endian encoding and some 
	   Botan sample code passes the contents of raw rsaPubKey->buffer to it 
	   so we assume that it's big-endian.  Additional evidence in support of
	   the big-endian form is some sample RSA keys grabbed via 
	   Fapi_GetTpmBlobs(), of which one was C2 CB AA C6 38 D3 70 85 [...]
	   67 2D 4D 99 90 DE 6B 35, so the form is definitely big-endian */
	memset( &tpm2BPubkey, 0, sizeof( TPM2B_PUBLIC ) );
	tpm2BPubkey.size = sizeof( TPM2B_PUBLIC );
	tpmtPubkey = &tpm2BPubkey.publicArea;
	tpmtPubkey->type = TPM2_ALG_RSA;
	rsaParams = &tpmtPubkey->parameters.rsaDetail;
	rsaParams->scheme.scheme = TPM2_ALG_NULL;
	rsaParams->keyBits = TEST_KEYSIZE_BITS;
	rsaParams->exponent = 65537L;
	rsaPubKey = &tpmtPubkey->unique.rsa;
	memcpy( rsaPubKey->buffer, integerValue, integerLength );
	rsaPubKey->size = ( UINT16 ) integerLength;

	*dest = tpm2BPubkey;

	return( TSS2_RC_SUCCESS );
	}
#endif /* USE_TPM_EXT */

#endif /* USE_TPM_EMULATION */
#endif /* USE_TPM */
