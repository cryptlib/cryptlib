/****************************************************************************
*																			*
*							cryptlib TLS Client								*
*					   Copyright Peter Gutmann 1998-2021					*
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

/* TLS gets a bit complicated because in the presence of the session cache 
   every session after the first one will be a resumed session.  To deal 
   with this, the VC++ debug builds disable the client-side session cache 
   while every other version just ends up going through a series of session 
   resumes.

   Note that changing the follow requires an equivalent change in 
   test/ssl.c */

#if defined( _MSC_VER ) && \
	( ( _MSC_VER == 1200 ) || \
	  ( _MSC_VER == VS_LATEST_VERSION && defined( CRYPTLIB_BUILD ) ) ) && \
	!defined( NDEBUG ) && 1
  #define NO_SESSION_CACHE
#endif /* VC++ debug build */

#ifdef USE_TLS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

#ifdef CONFIG_SUITEB

/* For Suite B the first suite must be ECDHE/AES128-GCM/SHA256 or 
   ECDHE/AES256-GCM/SHA384 depending on the security level and the second 
   suite, at the 128-bit security level, must be ECDHE/AES256-GCM/SHA384 */

CHECK_RETVAL_BOOL \
static int checkSuiteBSelection( IN_RANGE( TLS_FIRST_VALID_SUITE, \
										   TLS_LAST_SUITE - 1 ) \
									const int cipherSuite,
								 IN_FLAGS( TLS_PFLAG ) const int flags,
								 IN_BOOL const BOOLEAN isFirstSuite )
	{
	REQUIRES( cipherSuite >= TLS_FIRST_VALID_SUITE && \
			  cipherSuite < TLS_LAST_SUITE );
	REQUIRES( ( flags & ~( TLS_PFLAG_SUITEB ) ) == 0 );
	REQUIRES( isBooleanValue( isFirstSuite ) );

	if( isFirstSuite )
		{
		switch( flags )
			{
			case TLS_PFLAG_SUITEB_128:
				if( cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 )
					return( TRUE );
				break;

			case TLS_PFLAG_SUITEB_256:
				if( cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 )
					return( TRUE );
				break;

			default:
				retIntError();
			}
		}
	else
		{
		switch( flags )
			{
			case TLS_PFLAG_SUITEB_128:
				if( cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 )
					return( TRUE );
				break;

			case TLS_PFLAG_SUITEB_256:
				/* For the 256-bit level there are no further requirements */
				return( TRUE );

			default:
				retIntError();
			}
		}

	return( FALSE );
	}
#endif /* CONFIG_SUITEB */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeCipherSuiteList( INOUT_PTR STREAM *stream, 
								 IN_RANGE( TLS_MINOR_VERSION_TLS, \
										   TLS_MINOR_VERSION_TLS13 ) \
									const int tlsVersion,
								 IN_RANGE( TLS_MINOR_VERSION_TLS, \
										   TLS_MINOR_VERSION_TLS13 ) \
									const int tlsMinVersion,
								 IN_BOOL const BOOLEAN usePSK, 
#ifndef CONFIG_SUITEB
								 STDC_UNUSED
#endif /* !CONFIG_SUITEB */
								 IN_FLAGS_Z( TLS ) const int suiteBinfo )
	{
	const CIPHERSUITE_INFO **cipherSuiteInfo;
	int availableSuites[ MAX_NO_SUITES + 8 ];
	int cipherSuiteInfoSize, status;
	LOOP_INDEX suiteIndex, cipherSuiteCount = 0;
#ifdef CONFIG_SUITEB
	int suiteNo = 0;
#endif /* CONFIG_SUITEB */

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( tlsVersion >= TLS_MINOR_VERSION_TLS && \
			  tlsVersion <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( tlsMinVersion >= TLS_MINOR_VERSION_TLS && \
			  tlsMinVersion <= TLS_MINOR_VERSION_TLS13 );
	REQUIRES( isBooleanValue( usePSK ) );
#ifdef CONFIG_SUITEB
	REQUIRES( suiteBinfo >= TLS_PFLAG_NONE && suiteBinfo < TLS_PFLAG_MAX );
#endif /* CONFIG_SUITEB */

	/* Get the information for the supported cipher suites */
	status = getCipherSuiteInfo( &cipherSuiteInfo, &cipherSuiteInfoSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Walk down the list of algorithms (and the corresponding cipher
	   suites) remembering each one that's available for use */
	LOOP_EXT_INITCHECK( suiteIndex = 0,
						suiteIndex < cipherSuiteInfoSize && \
							cipherSuiteInfo[ suiteIndex ]->cipherSuite != SSL_NULL_WITH_NULL,
						MAX_NO_SUITES + 1 )
		{
		const CIPHERSUITE_INFO *cipherSuiteInfoPtr = cipherSuiteInfo[ suiteIndex ];
		const CRYPT_ALGO_TYPE keyexAlgo = cipherSuiteInfoPtr->keyexAlgo;
		const CRYPT_ALGO_TYPE cryptAlgo = cipherSuiteInfoPtr->cryptAlgo;
		const CRYPT_ALGO_TYPE authAlgo = cipherSuiteInfoPtr->authAlgo;
		const CRYPT_ALGO_TYPE macAlgo = cipherSuiteInfoPtr->macAlgo;
		const int suiteFlags = cipherSuiteInfoPtr->flags;
		int LOOP_ITERATOR_ALT;

		ENSURES( LOOP_INVARIANT_EXT_XXX( suiteIndex, 0, cipherSuiteInfoSize - 1,
										 MAX_NO_SUITES + 1 ) );
				 /* suiteIndex is incremented multiple times below */

		/* Make sure that the cipher suite is appropriate for SuiteB use if 
		   necessary */
#ifdef CONFIG_SUITEB
		if( suiteNo == 0 || suiteNo == 1 )
			{
			if( !checkSuiteBSelection( cipherSuiteInfoPtr->cipherSuite,
									   ( suiteBinfo == 0 ) ? \
											TLS_PFLAG_SUITEB_128 : suiteBinfo, 
									   ( suiteNo == 0 ) ? TRUE : FALSE ) )
				{
				suiteIndex++;
				continue;
				}
			suiteNo++;
			}
#endif /* CONFIG_SUITEB */

		/* Make sure that the suite is appropriate for the TLS version that 
		   we're using */
#ifdef USE_TLS13
		if( tlsMinVersion >= TLS_MINOR_VERSION_TLS13 && \
			!( suiteFlags & CIPHERSUITE_FLAG_TLS13 ) )
			{
			/* TLS 1.3 cipher suites aren't proper TLS suites but more like 
			   submenu selectors for a vast range of crypto options conveyed 
			   via extensions, so if we only allow TLS 1.3 then we can't 
			   provide any standard TLS suites */
			suiteIndex++;
			continue;
			}
		if( ( suiteFlags & CIPHERSUITE_FLAG_TLS13 ) && \
			tlsVersion <= TLS_MINOR_VERSION_TLS12 )
			{
			suiteIndex++;
			continue;
			}
#endif /* USE_TLS13 */
		if( tlsMinVersion >= TLS_MINOR_VERSION_TLS12 && \
			!( suiteFlags & ( CIPHERSUITE_FLAG_TLS12 | \
							  CIPHERSUITE_FLAG_TLS13 ) ) )
			{
			/* If the minimum version is set to TLS 1.2 then we disallowe 
			   suites from older TLS versions, which in practice means all
			   of the SHA-1 suites, with TLS 1.2 and above using only SHA-2 */
			suiteIndex++;
			continue;
			}
		if( ( suiteFlags & CIPHERSUITE_FLAG_TLS12 ) && \
			tlsVersion <= TLS_MINOR_VERSION_TLS11 )
			{
			suiteIndex++;
			continue;
			}

		/* If it's a PSK suite but we're not using PSK, skip it */
		if( ( suiteFlags & CIPHERSUITE_FLAG_PSK ) && !usePSK )
			{
			suiteIndex++;
			continue;
			}

		/* If the keyex algorithm for this suite isn't enabled for this 
		   build of cryptlib, skip all suites that use it.  We have to 
		   explicitly exclude the special case where there's no keyex 
		   algorithm in order to accomodate the bare TLS-PSK suites (used 
		   without DH/ECDH or RSA), whose keyex mechanism is pure PSK */
		if( keyexAlgo != CRYPT_ALGO_NONE && !algoAvailable( keyexAlgo ) )
			{
			LOOP_EXT_CHECKINC_ALT( \
					suiteIndex < cipherSuiteInfoSize && \
						cipherSuiteInfo[ suiteIndex ]->keyexAlgo == keyexAlgo,
					suiteIndex++, MAX_NO_SUITES + 1 )
				{
				ENSURES( LOOP_INVARIANT_EXT_XXX_ALT( suiteIndex, 0, 
													 cipherSuiteInfoSize - 1,
													 MAX_NO_SUITES + 1 ) );
				}
			ENSURES( LOOP_BOUND_OK_ALT );
			ENSURES( suiteIndex < cipherSuiteInfoSize );
			continue;
			}

		/* If the bulk encryption algorithm or MAC algorithm for this suite 
		   isn't enabled for this build of cryptlib, skip all suites that 
		   use it */
		if( !algoAvailable( cryptAlgo ) )
			{
			LOOP_EXT_CHECKINC_ALT( \
					suiteIndex < cipherSuiteInfoSize && \
						cipherSuiteInfo[ suiteIndex ]->cryptAlgo == cryptAlgo,
					suiteIndex++, MAX_NO_SUITES + 1 )
				{
				ENSURES( LOOP_INVARIANT_EXT_XXX_ALT( suiteIndex, 0, 
													 cipherSuiteInfoSize - 1,
													 MAX_NO_SUITES + 1 ) );
				}
			ENSURES( LOOP_BOUND_OK_ALT );
			ENSURES( suiteIndex < cipherSuiteInfoSize );
			continue;
			}
		if( !algoAvailable( macAlgo ) )
			{
			LOOP_EXT_CHECKINC_ALT( \
					suiteIndex < cipherSuiteInfoSize && \
						cipherSuiteInfo[ suiteIndex ]->macAlgo == macAlgo,
					suiteIndex++, MAX_NO_SUITES + 1 )
				{
				ENSURES( LOOP_INVARIANT_EXT_XXX_ALT( suiteIndex, 0, 
													 cipherSuiteInfoSize - 1,
													 MAX_NO_SUITES + 1 ) );
				}
			ENSURES( LOOP_BOUND_OK_ALT );
			ENSURES( suiteIndex < cipherSuiteInfoSize );
			continue;
			}

		/* The suite is supported, remember it.  In theory there's only a
		   single combination of the various algorithms present, but these 
		   can be subsetted into different key sizes (because they're there, 
		   that's why) so we have to iterate the recording of available 
		   suites instead of just assigning a single value on match */
		LOOP_EXT_WHILE_ALT( \
				suiteIndex < cipherSuiteInfoSize && \
				cipherSuiteInfo[ suiteIndex ]->keyexAlgo == keyexAlgo && \
				cipherSuiteInfo[ suiteIndex ]->authAlgo == authAlgo && \
				cipherSuiteInfo[ suiteIndex ]->cryptAlgo == cryptAlgo && \
				cipherSuiteInfo[ suiteIndex ]->macAlgo == macAlgo && \
				cipherSuiteCount < MAX_NO_SUITES, MAX_NO_SUITES + 1 )
			{
			ENSURES( LOOP_INVARIANT_EXT_XXX_ALT( suiteIndex, 0, 
												 cipherSuiteInfoSize - 1,
												 MAX_NO_SUITES + 1 ) );
			ENSURES( LOOP_INVARIANT_SECONDARY( cipherSuiteCount, 0, 
											   MAX_NO_SUITES - 1 ) );

			DEBUG_PRINT(( "Added cipher suite %s.\n", 
						  cipherSuiteInfo[ suiteIndex ]->debugText ));
			availableSuites[ cipherSuiteCount++ ] = \
						cipherSuiteInfo[ suiteIndex++ ]->cipherSuite;
#ifdef CONFIG_SUITEB
			if( suiteNo == 0 || suiteNo == 1 )
				break;	/* Suite B has special requirements for initial suites */
#endif /* CONFIG_SUITEB */
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		ENSURES( suiteIndex < cipherSuiteInfoSize );
		ENSURES( cipherSuiteCount < MAX_NO_SUITES );
		}
	ENSURES( LOOP_BOUND_OK );
	ENSURES( suiteIndex < cipherSuiteInfoSize );
	ENSURES( cipherSuiteCount > 0 && cipherSuiteCount < MAX_NO_SUITES );

	/* Encode the list of available cipher suites */
	status = writeUint16( stream, cipherSuiteCount * UINT16_SIZE );
	LOOP_EXT( suiteIndex = 0, 
			  suiteIndex < cipherSuiteCount && cryptStatusOK( status ), 
			  suiteIndex++, MAX_NO_SUITES + 1 )
		{
		ENSURES( LOOP_INVARIANT_EXT( suiteIndex, 0, cipherSuiteCount - 1,
									 MAX_NO_SUITES + 1 ) );

		status = writeUint16( stream, availableSuites[ suiteIndex ] );
		}
	ENSURES( LOOP_BOUND_OK );

	return( status );
	}

/* Process the server's certificate request:

		byte	ID = TLS_HAND_SERVER_CERTREQUEST
		uint24	len
		byte	certTypeLen
		byte[]	certType
	  [	uint16	sigHashListLen		-- TLS 1.2 ]
	  [		byte	hashAlgoID		-- TLS 1.2 ]
	  [		byte	sigAlgoID		-- TLS 1.2 ]
		uint16	caNameListLen
			uint16	caNameLen
			byte[]	caName

   We don't really care what's in the certificate request packet since the 
   contents are irrelevant, in a number of cases servers have been known to 
   send out superfluous certificate requests without the admins even knowing 
   that they're doing it, in other cases servers send out requests for every 
   CA that they know of.  This can produce certificate requests containing 
   hundreds of CAs, either because they've carefully catalogued every CA 
   they've ever heard of or because the software enumerates every CA in the 
   local system's trust list, leading in extreme cases to certificate request 
   messages that overflow the maximum TLS message size in order to convey the
   enormous CA lists.  This is pretty much meaningless since they can't 
   possibly trust all of those CAs to authorise access to their site.  In 
   addition virtually all clients just have a single certificate, so if 
   there's one available we try with the one certificate we've got rather 
   than failing the handshake because the server sent out the wrong CA name.

   Because of this, all that we do here is perform a basic sanity check and 
   remember that we may need to submit a certificate later on if we've got 
   one, with special-case handling for certificate requests fragmented 
   across multiple TLS packets because the server wants to list every CA in 
   the known universe.

   See the long comment in the cert-request handling code in tls_svr.c 
   for the handling of the sigHashList */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processFragmentedRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
									 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
									 INOUT_PTR STREAM *stream,
									 IN_RANGE( 1, MAX_PACKET_SIZE + \
												  ( MAX_PACKET_SIZE / 2 ) ) \
											const int totalLength )
	{
	const int dataLeft = sMemDataLeft( stream );
#if 1
	const int remainder = totalLength - dataLeft;
#else	/* See comment below about future extra-oversize data handling */
	LOOP_INDEX remainder = totalLength - dataLeft;
#endif /* 0 */
	int status = CRYPT_OK;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( totalLength >= 1 && totalLength <= MAX_PACKET_SIZE * 2 );
	REQUIRES( isShortIntegerRange( dataLeft ) );
	REQUIRES( isShortIntegerRangeNZ( remainder ) );

	/* Skip the remaining data in the packet if there is any */
	if( dataLeft > 0 )
		{
		status = sSkip( stream, sMemDataLeft( stream ), MAX_INTLENGTH_SHORT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the next packet.  This assumes that there are at most two 
	   fragments, this has been checked by the caller.  
	   
	   If servers that send even larger certificate requests ever turn up 
	   to test against we can use a read loop that just reads and skips 
	   further fragments as per the code below.  This currently isn't used
	   for lack of anything to test against */
#if 1
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
#else	/* Future extra-oversize data handling */
	LOOP_SMALL_WHILE( remainder > 0 )
		{
		int length;

		ENSURES( LOOP_INVARIANT_SMALL_XXX( remainder, 1, 
										   totalLength - dataLeft ) );

		sMemDisconnect( stream );
		status = readHSPacketTLS( sessionInfoPtr, handshakeInfo, &length,
								  TLS_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			break;
		sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
		status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
		if( cryptStatusError( status ) )
			break;
		remainder -= length;
		}
	ENSURES( LOOP_BOUND_OK );
#endif /* 0 */
	if( cryptStatusError( status ) )
		{
		/* Returning at this point is problematic because refreshHSStream()
		   has disconnected the memory stream while reading in new data for
		   it, so that when the caller tries to disconnect the stream in
		   response to getting an error status it'll trigger a sanity-check
		   exception.  This isn't normally a problem because the top-level
		   code exits without trying to disconnect the stream in response to
		   an error from refreshHSStream(), but in this case it's being 
		   called from inside a low-level function to deal with a fragmented
		   packet rather than at the top level.  To deal with this we 
		   temporarily connect the stream to the receive buffer in order for
		   the caller to have something to disconnect */
		sMemConnect( stream, sessionInfoPtr->receiveBuffer, 1 );

		return( status );
		}
	return( sSkip( stream, remainder, MAX_INTLENGTH_SHORT ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processCertRequest( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							   INOUT_PTR STREAM *stream )
	{
	int packetLength, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Although the spec says that at least one CA name entry must be 
	   present, some implementations send a zero-length list so we allow 
	   this as well.  The spec was changed in late TLS 1.1 drafts to reflect 
	   this practice.
	   
	   This packet may be longer than the encapsulating TLS packet, 
	   checkHSPacketHeader() has code to special-case this and allow an
	   over-sized packetLength value */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &packetLength,
								  TLS_HAND_SERVER_CERTREQUEST,
								  1 + 1 + ( ( sessionInfoPtr->version >= \
											  TLS_MINOR_VERSION_TLS12 ) ? \
										  ( UINT16_SIZE + 1 + 1 ) : 0 ) + \
								  UINT16_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	status = length = sgetc( stream );
	if( !cryptStatusError( status ) )
		{
		if( length < 1 || length > 64 )
			status = CRYPT_ERROR_BADDATA;
		}
	if( !cryptStatusError( status ) )
		status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate request certificate-type "
				  "information" ) );
		}

	/* If it's TLS 1.2, skip the assorted additional algorithm 
	   information */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		status = length = readUint16( stream );
		if( !cryptStatusError( status ) )
			{
			if( length < UINT16_SIZE || length > 64 || \
				( length % UINT16_SIZE ) != 0 )
				status = CRYPT_ERROR_BADDATA;
			}
		if( !cryptStatusError( status ) )
			status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid certificate request signature/hash "
					  "algorithm information" ) );
			}
		}

	/* Finally, skip the CA name list.  Since the packet could be an over-
	   length and therefore fragmented packet we can't use readUniversal16() 
	   but have to apply custom proccessing that deals with over-long 
	   packets */
	status = length = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length <= 0 )
		{
		/* Zero-length CA name list */
		return( CRYPT_OK );
		}
	if( length < ( UINT16_SIZE + 16 ) || \
		length > sMemDataLeft( stream ) + ( MAX_PACKET_SIZE - 512 ) )
		{
		/* We limit the over-sized length to the amount of data left in the 
		   current packet, typically a few kB under MAX_PACKET_SIZE, and 
		   almost another MAX_PACKET_SIZE packet, so roughly 
		   MAX_PACKET_SIZE * 2.  We don't allow a second full MAX_PACKET_SIZE
		   packet because that would mean there's a third and possibly 
		   fourth fragment present which we can't currently process */
		status = CRYPT_ERROR_BADDATA;
		}
	else
		{
		/* If the server sent an insanely long certificate request packet
		   that's fragmented across multiple TLS packets, process the
		   fragments */
		if( length > sMemDataLeft( stream ) )
			{
			status = processFragmentedRequest( sessionInfoPtr, handshakeInfo, 
											   stream, length );
			}
		else
			status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
		}
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate request CA name list" ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Handle Client/Server Keyex						*
*																			*
****************************************************************************/

/* Process the identity hint sent with the server keyex.  It's uncertain 
   what we're supposed to do with this so we just skip it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int readIdentityHint( INOUT_PTR STREAM *stream )
	{
	int length, status;

	status = length = readUint16( stream );
	if( !cryptStatusError( status ) && !isShortIntegerRange( length ) )
		status = CRYPT_ERROR_BADDATA;
	if( !cryptStatusError( status ) && length > 0 )
		status = sSkip( stream, length, MAX_INTLENGTH_SHORT );
	return( status );
	}

/* Read a server's DH/ECDH key agreement data:

	   DH:
		uint16		dh_pLen
		byte[]		dh_p
	  [ uint16		dh_qLen
	    byte[]		dp_q			-- For TLS-LTS ]
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
	   ECDH:
		byte		curveType
		uint16		namedCurve
		uint8		ecPointLen		-- NB uint8 not uint16
		byte[]		ecPoint */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int readServerKeyexDH( INOUT_PTR STREAM *stream, 
							  OUT_PTR KEYAGREE_PARAMS *keyAgreeParams,
							  OUT_HANDLE_OPT CRYPT_CONTEXT *dhContextPtr,
							  OUT_LENGTH_SHORT_Z int *publicValueStart,
							  IN_BOOL const BOOLEAN isTLSLTS )
	{
	void *keyData;
	const int keyDataOffset = stell( stream );
	int keyDataLength, dummy, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( keyAgreeParams, sizeof( KEYAGREE_PARAMS ) ) );
	assert( isWritePtr( dhContextPtr, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( publicValueStart, sizeof( int ) ) );

	REQUIRES( isBooleanValue( isTLSLTS ) );
	REQUIRES( isIntegerRangeNZ( keyDataOffset ) );

	/* Clear return values */
	memset( keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	*dhContextPtr = CRYPT_ERROR;
	*publicValueStart = CRYPT_ERROR;

	/* Read the server DH public key data */
	status = readInteger16U( stream, NULL, &dummy, MIN_PKCSIZE_THRESHOLD, 
							 CRYPT_MAX_PKCSIZE, BIGNUM_CHECK_VALUE_PKC );
	if( cryptStatusOK( status ) && isTLSLTS )
		{
		/* Read the optional q value present in TLS-LTS */
		status = readInteger16U( stream, NULL, &dummy, MIN_PKCSIZE_THRESHOLD, 
								 CRYPT_MAX_PKCSIZE, BIGNUM_CHECK_VALUE_PKC );
		}
	if( cryptStatusOK( status ) )
		{
		status = readInteger16U( stream, NULL, &dummy, 1, 
								 CRYPT_MAX_PKCSIZE, BIGNUM_CHECK_VALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Create a DH context from the public key data */
	status = calculateStreamObjectLength( stream, keyDataOffset,
										  &keyDataLength );
	if( cryptStatusError( status ) )
		return( status );
	status = sMemGetDataBlockAbs( stream, keyDataOffset, &keyData, 
								  keyDataLength );
	if( cryptStatusOK( status ) )
		{
		status = initDHcontextTLS( dhContextPtr, keyData, keyDataLength, 
								   CRYPT_UNUSED, CRYPT_ECCCURVE_NONE, 
								   isTLSLTS );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Remember the position of and skip the DH public value, which will be 
	   processed by the caller */
	*publicValueStart = stell( stream );
	ENSURES( isShortIntegerRangeNZ( *publicValueStart ) ); 
	return( readUniversal16( stream ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int readServerKeyexECDH( INOUT_PTR STREAM *stream, 
								OUT_PTR KEYAGREE_PARAMS *keyAgreeParams,
								OUT_HANDLE_OPT CRYPT_CONTEXT *dhContextPtr,
								OUT_LENGTH_SHORT_Z int *publicValueStart )
	{
	void *keyData;
	const int keyDataOffset = stell( stream );
	int keyDataLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( keyAgreeParams, sizeof( KEYAGREE_PARAMS ) ) );
	assert( isWritePtr( dhContextPtr, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( publicValueStart, sizeof( int ) ) );

	REQUIRES( isIntegerRangeNZ( keyDataOffset ) );

	/* Clear return values */
	memset( keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	*dhContextPtr = CRYPT_ERROR;
	*publicValueStart = CRYPT_ERROR;

	/* Read the server ECDH public key data */
	( void ) sgetc( stream );
	status = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Create an ECDH context from the public key data.  We set a dummy 
	   curve type, the actual value is determined by the parameters sent 
	   by the server */
	status = calculateStreamObjectLength( stream, keyDataOffset,
										  &keyDataLength );
	if( cryptStatusError( status ) )
		return( status );
	status = sMemGetDataBlockAbs( stream, keyDataOffset, &keyData, 
								  keyDataLength );
	if( cryptStatusOK( status ) )
		{
		status = initDHcontextTLS( dhContextPtr, keyData, keyDataLength, 
								   CRYPT_UNUSED, CRYPT_ECCCURVE_P256, 
								   FALSE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Remember the position of and skip the ECDH public value, which will 
	   be processed by the caller */
	*publicValueStart = stell( stream );
	ENSURES( isShortIntegerRangeNZ( *publicValueStart ) ); 
	return( readUniversal8( stream ) );
	}

/* Process the optional server keyex:

		byte		ID = TLS_HAND_SERVER_KEYEXCHANGE
		uint24		len
	   DH:
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
	 [	byte		hashAlgoID		-- TLS 1.2 ]
	 [	byte		sigAlgoID		-- TLS 1.2 ]
		uint16		signatureLen
		byte[]		signature 
	   DH-PSK:
		uint16		pskIdentityHintLen
		byte		pskIdentityHint
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
	   ECDH:
		byte		curveType
		uint16		namedCurve
		uint8		ecPointLen		-- NB uint8 not uint16
		byte[]		ecPoint
	 [	byte		hashAlgoID		-- TLS 1.2 ]
	 [	byte		sigAlgoID		-- TLS 1.2 ]
		uint16		signatureLen
		byte[]		signature */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 6 ) ) \
static int processServerKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							   INOUT_PTR STREAM *stream,
							   OUT_BUFFER( keyexPublicValueMaxLen, \
										   *keyexPublicValueLen ) \
									void *keyexPublicValue,
							   IN_LENGTH_SHORT_MIN( 16 ) \
									const int keyexPublicValueMaxLen,
							   OUT_LENGTH_BOUNDED_SHORT_Z( keyexPublicValueMaxLen ) \
									int *keyexPublicValueLen )

	{
	KEYAGREE_PARAMS keyAgreeParams, tempKeyAgreeParams;
	void *keyData DUMMY_INIT_PTR;
	const BOOLEAN isECC = isEccAlgo( handshakeInfo->keyexAlgo ) ? \
						  TRUE : FALSE;
	const BOOLEAN isPSK = ( handshakeInfo->authAlgo == CRYPT_ALGO_NONE ) ? \
						  TRUE : FALSE;
	const BOOLEAN isTLSLTS = TEST_FLAG( sessionInfoPtr->protocolFlags, 
										TLS_PFLAG_TLS12LTS ) ? \
							 TRUE : FALSE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int keyDataOffset, keyDataLength DUMMY_INIT, publicValueOffset;
	int length, offset, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtrDynamic( keyexPublicValue, keyexPublicValueMaxLen ) );
	assert( isWritePtr( keyexPublicValueLen, sizeof( int ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( isShortIntegerRangeMin( keyexPublicValueMaxLen, 16 ) );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( keyexPublicValueMaxLen ) ); 
	memset( keyexPublicValue, 0, min( 16, keyexPublicValueMaxLen ) );
	*keyexPublicValueLen = 0;

	/* Make sure that we've got an appropriate server keyex packet.  We set 
	   the minimum key size to MIN_PKCSIZE_THRESHOLD/MIN_PKCSIZE_ECC_THRESHOLD 
	   instead of MIN_PKCSIZE/MIN_PKCSIZE_ECC in order to provide better 
	   diagnostics if the server is using weak keys since otherwise the data 
	   will be rejected in the packet read long before we get to the keysize 
	   check */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
					TLS_HAND_SERVER_KEYEXCHANGE, 
					isECC ? \
						( 1 + UINT16_SIZE + \
						  1 + MIN_PKCSIZE_ECCPOINT_THRESHOLD + \
						  UINT16_SIZE + MIN_PKCSIZE_ECCPOINT_THRESHOLD ) : \
						( UINT16_SIZE + MIN_PKCSIZE_THRESHOLD + \
						  UINT16_SIZE + 1 + \
						  UINT16_SIZE + MIN_PKCSIZE_THRESHOLD + \
						  UINT16_SIZE + MIN_PKCSIZE_THRESHOLD ) );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "checkHSPacketHeader" );

	/* If we're using a PSK suite then the keyex information is preceded by 
	   a PSK identity hint */
	if( isPSK )
		{
		status = readIdentityHint( stream );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid PSK identity hint" ) );
			}
		}

	/* Read the server's keyex information and convert it into a DH/ECDH 
	   context */
	keyDataOffset = stell( stream );
	ENSURES( isIntegerRangeNZ( keyDataOffset ) );
	if( isECC )
		{
		status = readServerKeyexECDH( stream, &keyAgreeParams, 
									  &handshakeInfo->dhContext,
									  &publicValueOffset );
		}
	else
		{
		status = readServerKeyexDH( stream, &keyAgreeParams,
									&handshakeInfo->dhContext, 
									&publicValueOffset, isTLSLTS );
		}
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, keyDataOffset,
											  &keyDataLength );
		}
	if( cryptStatusOK( status ) )
		{
		status = sMemGetDataBlockAbs( stream, keyDataOffset, &keyData, 
									  keyDataLength );
		}
	if( cryptStatusError( status ) )
		{
		retExt( cryptArgError( status ) ? \
				CRYPT_ERROR_BADDATA : status,
				( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status,
				  SESSION_ERRINFO, 
				  "Invalid server key agreement parameters" ) );
		}
	ANALYSER_HINT( keyData != NULL );
	CFI_CHECK_UPDATE( "readServerKeyex" );

#ifdef CONFIG_FUZZ
	/* Skip the server's signature, set up a dummy premaster secret, and 
	   exit */
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS12 )
		{
		/* Skip algorithm IDs */
		sgetc( stream );
		sgetc( stream );
		}
	status = readUniversal16( stream );
	if( cryptStatusError( status ) )
		return( status );
	memset( handshakeInfo->premasterSecret, '*', TLS_SECRET_SIZE );
	handshakeInfo->premasterSecretSize = TLS_SECRET_SIZE;
	FUZZ_SKIP_REMAINDER();
#endif /* CONFIG_FUZZ */

	/* Check the server's signature on the DH/ECDH parameters, unless it's a 
	   PSK suite in which case the exchange is authenticated via the PSK */
	if( !isPSK )
		{
		ERROR_INFO localErrorInfo;

		clearErrorInfo( &localErrorInfo );
		status = checkKeyexSignature( sessionInfoPtr, handshakeInfo, stream, 
									  keyData, keyDataLength, isECC,
									  &localErrorInfo );
		if( cryptStatusError( status ) )
			{
			retExtErr( status,
					   ( status, SESSION_ERRINFO, &localErrorInfo,
						 "Invalid server key agreement parameter "
						 "signature" ) );
			}
		}
	CFI_CHECK_UPDATE( "checkKeyexSignature" );

	/* Perform phase 1 of the DH/ECDH key agreement process and save the 
	   result so that we can send it to the server later on.  The order of 
	   the TLS messages is a bit unfortunate since we get the one for phase 
	   2 before we need the phase 1 value, so we have to cache the phase 1 
	   result for when we need it later on */
	memset( &tempKeyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	status = krnlSendMessage( handshakeInfo->dhContext,
							  IMESSAGE_CTX_ENCRYPT, &tempKeyAgreeParams,
							  sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) )
		return( status );
	REQUIRES( rangeCheck( tempKeyAgreeParams.publicValueLen, 1,
						  keyexPublicValueMaxLen ) );
	memcpy( keyexPublicValue, tempKeyAgreeParams.publicValue,
			tempKeyAgreeParams.publicValueLen );
	*keyexPublicValueLen = tempKeyAgreeParams.publicValueLen;
	zeroise( &tempKeyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
	CFI_CHECK_UPDATE( "IMESSAGE_CTX_ENCRYPT" );

	/* Move back to the keyex value and complete the keyex */
	status = offset = stell( stream );
	ENSURES( !cryptStatusError( status ) );
	status = sseek( stream, publicValueOffset );
	ENSURES( cryptStatusOK( status ) );
	status = completeTLSKeyex( handshakeInfo, stream, isECC, isTLSLTS, 
							   SESSION_ERRINFO );
	if( cryptStatusOK( status ) )
		status = sseek( stream, offset );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "completeTLSKeyex" );

	ENSURES( CFI_CHECK_SEQUENCE_5( "checkHSPacketHeader", "readServerKeyex", 
								   "checkKeyexSignature", "IMESSAGE_CTX_ENCRYPT", 
								   "completeTLSKeyex" ) );
	return( CRYPT_OK );
	}

/* Build the client key exchange packet:

	  [	byte		ID = TLS_HAND_CLIENT_KEYEXCHANGE ]
	  [	uint24		len				-- Written by caller ]
	   DH:
		uint16		yLen
		byte[]		y
	   DH-PSK:
		uint16		userIDLen
		byte[]		userID
		uint16		yLen
		byte[]		y
	   ECDH:
		uint8		ecPointLen		-- NB uint8 not uint16
		byte[]		ecPoint
	   PSK:
		uint16		userIDLen
		byte[]		userID
	   RSA:
	  [ uint16		encKeyLen		-- TLS only ]
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x0n } || byte[46] random ) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int createClientKeyex( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							  INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
							  INOUT_PTR STREAM *stream,
							  IN_BUFFER_OPT( keyexPublicValueLen ) \
								const BYTE *keyexPublicValue,
							  IN_LENGTH_PKC_Z const int keyexPublicValueLen,
							  IN_BOOL const BOOLEAN isPSK )
	{
	const ATTRIBUTE_LIST *userNamePtr DUMMY_INIT_PTR;
	const ATTRIBUTE_LIST *passwordPtr DUMMY_INIT_PTR;
#ifdef USE_RSA_SUITES
	BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];
	int wrappedKeyLength;
#endif /* USE_RSA_SUITES */
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( keyexPublicValue == NULL && keyexPublicValueLen == 0 ) || \
			isReadPtrDynamic( keyexPublicValue, keyexPublicValueLen ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( ( keyexPublicValue == NULL && keyexPublicValueLen == 0 ) || \
			  ( keyexPublicValueLen > 0 && \
				keyexPublicValueLen <= CRYPT_MAX_PKCSIZE ) );
	REQUIRES( isBooleanValue( isPSK ) );

	/* If we're using a PSK mechanism, get the user name and password/PSK */
	if( isPSK )
		{
		userNamePtr = findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME );
		passwordPtr = findSessionInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD );

		REQUIRES( passwordPtr != NULL );
		REQUIRES( userNamePtr != NULL );
		}

	/* If we're using DH/ECDH (with optional PSK additions), write the 
	   necessary information */
	if( keyexPublicValue != NULL )
		{
		/* If it's a PSK algorithm, convert the DH/ECDH premaster secret to
		   a DH/ECDH + PSK premaster secret and write the client identity 
		   that's required by PSK */
		if( isPSK )
			{
			BYTE premasterTempBuffer[ CRYPT_MAX_PKCSIZE + 8 ];
			const int premasterTempSize = handshakeInfo->premasterSecretSize;

			/* Since this operation rewrites the premaster secret, we have to
			   save the original contents into a temporary buffer first */
			REQUIRES( rangeCheck( handshakeInfo->premasterSecretSize, 1,
								  CRYPT_MAX_PKCSIZE ) );
			memcpy( premasterTempBuffer, handshakeInfo->premasterSecret,
					handshakeInfo->premasterSecretSize );
			status = createSharedPremasterSecret( \
							handshakeInfo->premasterSecret,
							CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE,
							&handshakeInfo->premasterSecretSize,
							passwordPtr->value, 
							passwordPtr->valueLength, 
							premasterTempBuffer, premasterTempSize,
							TEST_FLAG( passwordPtr->flags, 
									   ATTR_FLAG_ENCODEDVALUE ) ? \
								TRUE : FALSE );
			zeroise( premasterTempBuffer, CRYPT_MAX_PKCSIZE );
			if( cryptStatusError( status ) )
				{
				retExt( status,
						( status, SESSION_ERRINFO, 
						  "Couldn't create master secret from shared "
						  "secret/password value" ) );
				}

			/* Write the PSK client identity */
			writeUint16( stream, userNamePtr->valueLength );
			status = swrite( stream, userNamePtr->value,
							 userNamePtr->valueLength );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Write the DH/ECDH public value that we saved earlier when we
		   performed phase 1 of the key agreement process */
		if( isEccAlgo( handshakeInfo->keyexAlgo ) )
			{
			sputc( stream, keyexPublicValueLen );
			status = swrite( stream, keyexPublicValue,
							 keyexPublicValueLen );
			}
		else
			{
			status = writeInteger16U( stream, keyexPublicValue,
									  keyexPublicValueLen );
			}
		
		return( status );
		}

	/* To get to this point, we can't have been using DH/ECDH */
	REQUIRES( keyexPublicValue == NULL && keyexPublicValueLen == 0 );

	/* If we're using straight PSK, write the client identity */
	if( isPSK )
		{
		/* Create the shared premaster secret from the user password */
		status = createSharedPremasterSecret( \
							handshakeInfo->premasterSecret,
							CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE,
							&handshakeInfo->premasterSecretSize,
							passwordPtr->value, 
							passwordPtr->valueLength, NULL, 0,
							TEST_FLAG( passwordPtr->flags, 
									   ATTR_FLAG_ENCODEDVALUE ) ? \
								TRUE : FALSE );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Couldn't create master secret from shared "
					  "secret/password value" ) );
			}

		/* Write the PSK client identity */
		writeUint16( stream, userNamePtr->valueLength );
		return( swrite( stream, userNamePtr->value,
						userNamePtr->valueLength ) );
		}

#ifdef USE_RSA_SUITES
	/* It's an RSA keyex, write the RSA-wrapped premaster secret */
	status = wrapPremasterSecret( sessionInfoPtr, handshakeInfo, wrappedKey, 
								  CRYPT_MAX_PKCSIZE, &wrappedKeyLength );
	if( cryptStatusError( status ) )
		return( status );

	return( writeInteger16U( stream, wrappedKey, wrappedKeyLength ) );
#else
	retIntError();
#endif /* USE_RSA_SUITES */
	}

/****************************************************************************
*																			*
*							Client-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int beginClientHandshake( INOUT_PTR SESSION_INFO *sessionInfoPtr,
								 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
#ifndef NO_SESSION_CACHE
	const ATTRIBUTE_LIST *attributeListPtr;
#endif /* NO_SESSION_CACHE */
	STREAM *stream = &handshakeInfo->stream;
	SCOREBOARD_ENTRY_INFO scoreboardEntryInfo = { 0 };
	MESSAGE_DATA msgData;
	BYTE sentSessionID[ MAX_SESSIONID_SIZE + 8 ];
	TLSHELLO_ACTION_TYPE actionType;
	BOOLEAN sessionIDsent = FALSE, resumeSession = FALSE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int packetOffset, clientHelloLength DUMMY_INIT, serverHelloLength;
	int sentSessionIDlength DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Check whether we have (potentially) cached data available for the
	   server.  If we've had the connection to the remote system provided
	   by the user (for example as an already-connected socket) then there
	   won't be any server name information present, so we can only
	   perform a session resume if we've established the connection
	   ourselves */
#ifndef NO_SESSION_CACHE
	attributeListPtr = findSessionInfo( sessionInfoPtr, 
										CRYPT_SESSINFO_SERVER_NAME );
	if( attributeListPtr != NULL )
		{
		void *scoreboardInfoPtr = \
				DATAPTR_GET( sessionInfoPtr->sessionTLS->scoreboardInfoPtr );
		int resumedSessionID;

		REQUIRES( scoreboardInfoPtr != NULL );

		resumedSessionID = \
			lookupScoreboardEntry( scoreboardInfoPtr, SCOREBOARD_KEY_FQDN, 
								   attributeListPtr->value,
								   attributeListPtr->valueLength, 
								   &scoreboardEntryInfo );
		if( !cryptStatusError( resumedSessionID ) )
			{
			/* We've got cached data for the server available, remember the 
			   session ID so that we can send it to the server */
			status = attributeCopyParams( handshakeInfo->sessionID, 
										  MAX_SESSIONID_SIZE, 
										  &handshakeInfo->sessionIDlength,
										  scoreboardEntryInfo.key, 
										  scoreboardEntryInfo.keySize );
			ENSURES( cryptStatusOK( status ) );

			/* Make a copy of the session ID that we're sending so that we 
			   can check it against what the server sends back to us later.  
			   This is required for when the server can't resume the session
			   and sends us a fresh session ID */
			REQUIRES( rangeCheck( handshakeInfo->sessionIDlength, 1, 
								  MAX_SESSIONID_SIZE ) );
			memcpy( sentSessionID, handshakeInfo->sessionID, 
					handshakeInfo->sessionIDlength );
			sentSessionIDlength = handshakeInfo->sessionIDlength;
			}
		}
#endif /* NO_SESSION_CACHE */
	CFI_CHECK_UPDATE( "lookupScoreboardEntry" );

	/* Get the nonce that's used to randomise all crypto ops */
	setMessageData( &msgData, handshakeInfo->clientNonce, TLS_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using TLS 1.3 with its guessed keyex, create the (EC)DH 
	   contexts that we'll need in order to populate the client hello */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		status = createDHcontextTLS( &handshakeInfo->dhContext, 
									 CRYPT_ALGO_DH );
		if( cryptStatusOK( status ) )
			{
			/* Indicate that we're using the nonstandard DH keys required
			   by TLS 1.3 */
			static const int dhKeySize = bitsToBytes( 2048 ) | 1;

			status = krnlSendMessage( handshakeInfo->dhContext, 
									  IMESSAGE_SETATTRIBUTE, 
									  ( MESSAGE_CAST ) &dhKeySize, 
									  CRYPT_IATTRIBUTE_KEY_DLPPARAM );
			}
		if( cryptStatusError( status ) )
			return( status );
		if( algoAvailable( CRYPT_ALGO_ECDH ) )
			{
			status = createDHcontextTLS( &handshakeInfo->dhContextAlt, 
										 CRYPT_ALGO_ECDH );
			if( cryptStatusOK( status ) )
				{
				static const int ecdhKeyType = CRYPT_ECCCURVE_P256;

				status = krnlSendMessage( handshakeInfo->dhContextAlt, 
										  IMESSAGE_SETATTRIBUTE, 
										  ( MESSAGE_CAST ) &ecdhKeyType, 
										  CRYPT_IATTRIBUTE_KEY_ECCPARAM );
				}
			if( cryptStatusError( status ) )
				return( status );
			}
		}
#endif /* USE_TLS13 */

	/* Build the client hello packet:

		byte		ID = TLS_HAND_CLIENT_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		byte[32]	nonce
		byte		sessIDlen
		byte[]		sessID
		uint16		suiteLen
		uint16[]	suite
		byte		coprLen = 1
		byte[]		copr = { 0x00 }
	  [	uint16	extListLen			-- RFC 3546/RFC 4366/RFC 6066
			byte	extType
			uint16	extLen
			byte[]	extData ] 

	   Extensions used to present a bit of an interoperability problem on 
	   the client side because we had to add them to the client hello before 
	   we knew whether the server can handle them, but pretty much any
	   server should be able to deal with these by now.  To deal with any
	   possible holdbacks we only disable sending them if TLS 1.0 is 
	   explicitly selected, unless if ECC suites are being used in which case
	   we have to write them because they're required for ECC use */
	status = openPacketStreamTLS( stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
								  TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	status = continueHSPacketStream( stream, TLS_HAND_CLIENT_HELLO, 
									 &packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	sputc( stream, TLS_MAJOR_VERSION );
	sputc( stream, min( sessionInfoPtr->version, 
						TLS_MINOR_VERSION_TLS12 ) );
	handshakeInfo->clientOfferedVersion = sessionInfoPtr->version;
	swrite( stream, handshakeInfo->clientNonce, TLS_NONCE_SIZE );
	sputc( stream, handshakeInfo->sessionIDlength );
	if( handshakeInfo->sessionIDlength > 0 )
		{
		swrite( stream, handshakeInfo->sessionID, 
				handshakeInfo->sessionIDlength );
		sessionIDsent = TRUE;
		}
	status = writeCipherSuiteList( stream, sessionInfoPtr->version,
								   sessionInfoPtr->sessionTLS->minVersion,
						findSessionInfo( sessionInfoPtr,
										 CRYPT_SESSINFO_USERNAME ) != NULL ? \
							TRUE : FALSE,
							TEST_FLAG( sessionInfoPtr->protocolFlags, 
									   TLS_PFLAG_SUITEB ) ? TRUE : FALSE );
	if( cryptStatusOK( status ) )
		{
		sputc( stream, 1 );		/* No compression */
		status = sputc( stream, 0 );
		}
	if( cryptStatusOK( status ) && \
		( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS11 || \
		  algoAvailable( CRYPT_ALGO_ECDH ) ) )
		{
		/* Extensions are only written when newer versions of TLS are 
		   enabled, unless they're required for ECC use, see the comment 
		   at the start of this code block for details */
		status = writeClientExtensions( stream, sessionInfoPtr, 
										handshakeInfo );
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusOK( status ) )
		status = sendPacketTLS( sessionInfoPtr, stream, FALSE );
	if( cryptStatusOK( status ) )
		{
		status = calculateStreamObjectLength( stream, TLS_HEADER_SIZE,
											  &clientHelloLength );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "sendPacketTLS" );

	/* Perform the assorted hashing of the client hello in between the 
	   network ops where it's effectively free */
	status = hashHSPacketWrite( handshakeInfo, stream, 0 );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		return( status );
	CFI_CHECK_UPDATE( "hashHSPacketWrite" );

	/* Process the server hello.  The server will usually send us a session 
	   ID to indicate a resumable session (if we've sent one in our 
	   request).  This indicated by a return status of OK_SPECIAL, if this 
	   is present then we try and resume the session.

	   Note that this processing leads to a slight inefficiency in hashing 
	   when multiple hash algorithms need to be accommodated (as they do
	   when TLS 1.2+ is enabled) because readHSPacketTLS() hashes the 
	   incoming packet data as it arrives, and if all possible server 
	   handshake packets are combined into a single TLS message packet then 
	   they'll arrive, and need to be hashed, before the server hello is
	   processed and we can selectively disable the hash algorithms that
	   won't be needed.  Fixing this would require adding special-case
	   processing to readHSPacketTLS() to detect the use of 
	   TLS_MSG_FIRST_HANDSHAKE for the client and skip the hashing, relying
	   on the calling code to then pick out the portions that need to be
	   hashed.  This probably isn't worth the effort required, since it adds
	   a lot of code complexity and custom processing just to save a small
	   amount of hashing on the client, which will generally be the less
	   resource-constrained of the two parties */
	status = readHSPacketTLS( sessionInfoPtr, handshakeInfo, 
							  &serverHelloLength, TLS_MSG_FIRST_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, serverHelloLength );
	status = processHelloTLS( sessionInfoPtr, handshakeInfo, stream, 
							  &actionType, FALSE );
	if( status == OK_SPECIAL )
		{
		ENSURES( actionType == TLSHELLO_ACTION_RESUMEDSESSION );

		/* The server has provided a session ID, if we sent one in our 
		   request and it matches what the server returned then this is a 
		   resumed session */
		if( sessionIDsent && \
			handshakeInfo->sessionIDlength == sentSessionIDlength && \
			!memcmp( handshakeInfo->sessionID, sentSessionID,
					 sentSessionIDlength ) )
			{
			DEBUG_PUTS(( "Server negotiated session resumption" ));
			resumeSession = TRUE;
			}
		status = CRYPT_OK;
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	serverHelloLength = stell( stream );	/* May be followed by other packets */
	REQUIRES( isIntegerRangeNZ( serverHelloLength ) );
	CFI_CHECK_UPDATE( "processHelloTLS" );

	/* TLS 1.2 LTS and TLS 1.3 hash the client and server hello and verify 
	   them before the overall handshake hash is completed so we hash them
	   now */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS ) || \
		sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		HASH_FUNCTION hashFunction;
		HASHINFO hashInfo;
		int hashSize;

		/* Hash the client and server hello messages.  We can only be using 
		   SHA2-256 at this point due to the LTS/TLS 1.3 cipher suite 
		   negotiation so we hardcode that into the hashing */
		getHashParameters( CRYPT_ALGO_SHA2, bitsToBytes( 256 ), &hashFunction, 
						   &hashSize );
		hashFunction( hashInfo, NULL, 0, 
					  sessionInfoPtr->sendBuffer + TLS_HEADER_SIZE, 
					  clientHelloLength, HASH_STATE_START );
		hashFunction( hashInfo, handshakeInfo->helloHash, CRYPT_MAX_HASHSIZE, 
					  sessionInfoPtr->receiveBuffer, serverHelloLength, 
					  HASH_STATE_END );
		handshakeInfo->helloHashSize = hashSize;
		DEBUG_DUMP_DATA_LABEL( "Client/Server hello hash (client):",
							   handshakeInfo->helloHash, 
							   handshakeInfo->helloHashSize );
		}

	/* If we're talking TLS 1.3, which is an entirely different protocol to
	   standard TLS, we can't continue with this code line */
#ifdef USE_TLS13
	if( sessionInfoPtr->version >= TLS_MINOR_VERSION_TLS13 )
		{
		ENSURES( CFI_CHECK_SEQUENCE_4( "lookupScoreboardEntry", "sendPacketTLS", 
									   "hashHSPacketWrite", "processHelloTLS" ) );

		return( CRYPT_OK );
		}
#endif /* USE_TLS13 */

	/* The server has acknowledged our attempt to resume a session, handle 
	   the session resumption */
	if( resumeSession )
		{
		sMemDisconnect( stream );

		/* We're resuming a previous session, if extended TLS facilities 
		   were in use then make sure that the resumed session uses the same 
		   facilities */
		if( !TEST_FLAGS( sessionInfoPtr->protocolFlags, 
						 TLS_RESUMEDSESSION_FLAGS, 
						 scoreboardEntryInfo.metaData ) )
			{
			DEBUG_PRINT(( "Server negotiated resumption of session with "
						  "options %x using options %x.\n", 
						  scoreboardEntryInfo.metaData,
						  GET_FLAGS( sessionInfoPtr->protocolFlags,
									 TLS_RESUMEDSESSION_FLAGS ) ));
			return( CRYPT_ERROR_INVALID );
			}

		/* Remember the premaster secret for the resumed session */
		status = attributeCopyParams( handshakeInfo->premasterSecret, 
									  TLS_SECRET_SIZE,
									  &handshakeInfo->premasterSecretSize,
									  scoreboardEntryInfo.data, 
									  scoreboardEntryInfo.dataSize );
		ENSURES( cryptStatusOK( status ) );

		/* Tell the caller that it's a resumed session */
		DEBUG_PRINT_BEGIN();
		DEBUG_PRINT(( "Resuming session with server based on "
					  "sessionID = \n" ));
		DEBUG_DUMP_DATA( handshakeInfo->sessionID, 
						 handshakeInfo->sessionIDlength );
		DEBUG_PRINT_END();
		status = OK_SPECIAL;
		}
	CFI_CHECK_UPDATE( "resumeSession" );

	/* TLS 1.2 LTS implicitly enables various other crypto options, now that
	   we've got past the initial negotiations, enable those too */
	if( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_TLS12LTS ) )
		{
		SET_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_EMS );
		if( !TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_GCM ) )
			{
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  TLS_PFLAG_ENCTHENMAC );
			}
		}
	CFI_CHECK_UPDATE( "TLS12LTS" );

	/* Return CRYPT_OK for a standard session, OK_SPECIAL for a resumed 
	   one */
	ENSURES( CFI_CHECK_SEQUENCE_6( "lookupScoreboardEntry", "sendPacketTLS", 
								   "hashHSPacketWrite", "processHelloTLS",
								   "resumeSession", "TLS12LTS" ) );
	return( status );
	}

/* Exchange keys with the server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int exchangeClientKeys( INOUT_PTR SESSION_INFO *sessionInfoPtr,
							   INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	BYTE keyexPublicValue[ CRYPT_MAX_PKCSIZE + 8 ];
	BOOLEAN needClientCert = FALSE;
	CFI_CHECK_TYPE CFI_CHECK_VALUE = CFI_CHECK_INIT;
	int packetOffset, length, keyexPublicValueLen = 0, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	REQUIRES( sanityCheckSessionTLS( sessionInfoPtr ) );
	REQUIRES( sanityCheckTLSHandshakeInfo( handshakeInfo ) );

	/* Process the optional server supplemental data:

		byte		ID = TLS_HAND_SUPPLEMENTAL_DATA
		uint24		len
		uint16		type
		uint16		len
		byte[]		value

	   This is a kitchen-sink mechanism for exchanging arbitrary further 
	   data during the TLS handshake (see RFC 4680).  The presence of the
	   supplemental data has to be negotiated using TLS extensions, however
	   the nature of this negotiation is unspecified so we can't just
	   reject an unexpected supplemental data message as required by the RFC 
	   because it may have been quite legitimately negotiated by a TLS
	   extension that we don't know about.  Because of this we perform
	   basic validity checks on any supplemental data messages that arrive
	   but otherwise ignore them */
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( sPeek( stream ) == TLS_HAND_SUPPLEMENTAL_DATA )
		{
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  TLS_HAND_SUPPLEMENTAL_DATA, 
									  UINT16_SIZE + UINT16_SIZE + 1 );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		readUint16( stream );				/* Type */
		status = readUniversal16( stream );	/* Value */
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid supplemental data" ) );
			}
		DEBUG_PRINT(( "Server sent %d bytes TLS supplemental data.\n",
					  length ));
		assert_nofuzz( DEBUG_WARN );
		}
	CFI_CHECK_UPDATE( "checkHSPacketHeader" );

#ifndef CONFIG_FUZZ
	/* Process the theoretically-optional but always-present server 
	   certificate chain:

		byte		ID = TLS_HAND_CERTIFICATE
		uint24		len
		uint24		certLen			-- 1...n certificates ordered
		byte[]		certificate		-- leaf -> root 

	   This could be imported into either the iKeyexCryptContext or the
	   iKeyexAuthContext but since it's always used to authenticate a
	   (EC)DH key exchange (unless the obsolete RSA keyex has been enabled)
	   we read it into the iKeyexAuthContext */
	if( handshakeInfo->authAlgo != CRYPT_ALGO_NONE )
		{
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		status = readTLSCertChain( sessionInfoPtr, handshakeInfo,
							stream, &sessionInfoPtr->iKeyexAuthContext,
							FALSE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}

		/* Check the details in the certificate chain */
		status = checkTLSCertificateInfo( sessionInfoPtr );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}
#endif /* CONFIG_FUZZ */
	CFI_CHECK_UPDATE( "readTLSCertChain" );

	/* Process the optional server keyex */
	if( isKeyexAlgo( handshakeInfo->keyexAlgo ) )
		{
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );

		status = processServerKeyex( sessionInfoPtr, handshakeInfo, 
									 stream, keyexPublicValue, 
									 CRYPT_MAX_PKCSIZE, 
									 &keyexPublicValueLen );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}
	else
		{
		/* If it's a pure PSK mechanism then there may be a pointless server 
		   keyex containing an identity hint whose purpose is never 
		   explained (more specifically the RFC makes it a SHOULD NOT, and
		   clients MUST ignore it), in which case we have to process the 
		   packet to get rid of the identity hint */
		if( handshakeInfo->authAlgo == CRYPT_ALGO_NONE )
			{
			status = refreshHSStream( sessionInfoPtr, handshakeInfo );
			if( cryptStatusError( status ) )
				return( status );
			if( sPeek( stream ) == TLS_HAND_SUPPLEMENTAL_DATA )
				{
				status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
											  TLS_HAND_SERVER_KEYEXCHANGE, 
											  ( UINT16_SIZE + 1 ) );
				if( cryptStatusError( status ) )
					return( status );
				status = readIdentityHint( stream );
				if( cryptStatusError( status ) )
					{
					retExt( CRYPT_ERROR_BADDATA,
							( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
							  "Invalid PSK identity hint" ) );
					}
				}
			}

#ifdef CONFIG_FUZZ
		/* Set up a dummy premaster secret */
		memset( handshakeInfo->premasterSecret, '*', TLS_SECRET_SIZE );
		handshakeInfo->premasterSecretSize = TLS_SECRET_SIZE;
#endif /* CONFIG_FUZZ */
		
		/* Keep static analysers happy */
		memset( keyexPublicValue, 0, CRYPT_MAX_PKCSIZE );
		}
	CFI_CHECK_UPDATE( "processServerKeyex" );

	/* Process the optional server certificate request.  Since we're about 
	   to peek ahead into the stream to see if we need to process a server 
	   certificate request, we have to refresh the stream at this point in 
	   case the certificate request wasn't bundled with the preceding 
	   packets */
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( sPeek( stream ) == TLS_HAND_SERVER_CERTREQUEST )
		{
		status = processCertRequest( sessionInfoPtr, handshakeInfo, 
									 stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		needClientCert = TRUE;
		}
	CFI_CHECK_UPDATE( "processCertRequest" );

	/* Process the server hello done:

		byte		ID = TLS_HAND_SERVER_HELLODONE
		uint24		len = 0 */
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  TLS_HAND_SERVER_HELLODONE, 0 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* If we're fuzzing the input then we don't need to go through any of 
	   the following crypto calisthenics */
	FUZZ_SKIP_REMAINDER();

	/* If we need a client certificate, build the client certificate packet */
	status = openPacketStreamTLS( stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
								  TLS_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	if( needClientCert )
		{
		/* If we haven't got a certificate available, tell the server.  SSL 
		   and TLS differ here, SSL sends a no-certificate alert while TLS 
		   sends an empty client certificate packet, which is handled 
		   further on */
		if( sessionInfoPtr->privateKey == CRYPT_ERROR )
			{
			setObjectErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PRIVATEKEY,
								CRYPT_ERRTYPE_ATTR_ABSENT );

			/* The reaction to the lack of a certificate is up to the server 
			   (some just request one anyway even though they can't do 
			   anything with it) so from here on we just continue as if 
			   nothing had happened */
			SET_FLAG( sessionInfoPtr->protocolFlags, 
					  TLS_PFLAG_CLIAUTHSKIPPED );
			needClientCert = FALSE;
			}

		/* Send our client cert (chain).  If no private key is available this 
		   will send a zero-length chain as required by TLS  */
		status = writeTLSCertChain( sessionInfoPtr, handshakeInfo, stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}
	CFI_CHECK_UPDATE( "writeTLSCertChain" );

	/* Build the client key exchange packet */
	status = continueHSPacketStream( stream, TLS_HAND_CLIENT_KEYEXCHANGE,
									 &packetOffset );
	if( cryptStatusOK( status ) )
		{
		status = createClientKeyex( sessionInfoPtr, handshakeInfo, stream,
									isKeyexAlgo( handshakeInfo->keyexAlgo ) ? \
										keyexPublicValue : NULL, 
									keyexPublicValueLen,
									( handshakeInfo->authAlgo == CRYPT_ALGO_NONE ) ? \
										TRUE : FALSE );
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "createClientKeyex" );

	/* Wrap up the packet and create the session hash if required */
	status = completePacketStreamTLS( stream, 0 );
	if( cryptStatusOK( status ) )
		status = hashHSPacketWrite( handshakeInfo, stream, 0 );
	if( cryptStatusOK( status ) && \
		( TEST_FLAG( sessionInfoPtr->protocolFlags, TLS_PFLAG_EMS ) || \
		  needClientCert ) )
		{
		status = createSessionHash( sessionInfoPtr, handshakeInfo );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	CFI_CHECK_UPDATE( "createSessionHash" );

	/* If we need to supply a client certificate, send the signature 
	   generated with the certificate to prove possession of the private 
	   key */
	if( needClientCert )
		{
		int packetStreamOffset;

		/* Write the packet header and drop in the signature data.  Since 
		   we've interrupted the packet stream to perform the hashing we 
		   have to restart it at this point */
		status = continuePacketStreamTLS( stream, sessionInfoPtr, 
										  TLS_MSG_HANDSHAKE, 
										  &packetStreamOffset );
		if( cryptStatusError( status ) )
			return( status );
		status = continueHSPacketStream( stream, TLS_HAND_CERTVERIFY,
										 &packetOffset );
		if( cryptStatusOK( status ) )
			{
			status = createCertVerify( sessionInfoPtr, handshakeInfo, 
									   stream );
			}
		if( cryptStatusOK( status ) )
			status = completeHSPacketStream( stream, packetOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}

		/* Wrap the packet and perform the assorted hashing for it */
		status = completePacketStreamTLS( stream, packetStreamOffset );
		if( cryptStatusOK( status ) )
			{
			status = hashHSPacketWrite( handshakeInfo, stream, 
										packetStreamOffset );
			}
		if( cryptStatusError( status ) )
			return( status );
		CFI_CHECK_UPDATE( "createCertVerify" );

		ENSURES( CFI_CHECK_SEQUENCE_8( "checkHSPacketHeader", "readTLSCertChain", 
									   "processServerKeyex", 
									   "processCertRequest", "writeTLSCertChain",
									   "createClientKeyex", "createSessionHash", 
									   "createCertVerify" ) );
		return( CRYPT_OK );
		}
	CFI_CHECK_UPDATE( "needClientCert" );

	ENSURES( CFI_CHECK_SEQUENCE_8( "checkHSPacketHeader", "readTLSCertChain", 
								   "processServerKeyex", "processCertRequest", 
								   "writeTLSCertChain", "createClientKeyex", 
								   "createSessionHash", "needClientCert" ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initTLSclientProcessing( INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( TLS_HANDSHAKE_INFO ) ) );

	FNPTR_SET( handshakeInfo->beginHandshake, beginClientHandshake );
	FNPTR_SET( handshakeInfo->exchangeKeys, exchangeClientKeys );
	}
#endif /* USE_TLS */
