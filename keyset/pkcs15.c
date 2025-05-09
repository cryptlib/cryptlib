/****************************************************************************
*																			*
*						  cryptlib PKCS #15 Routines						*
*						Copyright Peter Gutmann 1996-2019					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "keyset.h"
  #include "pkcs15.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs15.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS15

/* OID information used to read the header of a PKCS #15 keyset.  Since the 
   PKCS #15 content can be further wrapped in CMS AuthData we have to check
   for both types of content.  If we find AuthData we retry the read, this
   time allowing only PKCS #15 content.  In addition since this is inner
   content in an EncapsulatedContentInfo structure we don't specify any
   version information because the additional OCTET STRING encapsulation 
   used with EncapsulatedContentInfo means that we need to dig down further 
   before we can find this field */

static const CMS_CONTENT_INFO oidInfoPkcs15Data = { 0, 0 };

static const OID_INFO keyFileOIDinfo[] = {
	{ OID_PKCS15_CONTENTTYPE, TRUE, &oidInfoPkcs15Data },
	{ OID_CMS_AUTHDATA, FALSE, &oidInfoPkcs15Data },
	{ NULL, 0 }, { NULL, 0 }
	};
static const OID_INFO keyFilePKCS15OIDinfo[] = {
	{ OID_PKCS15_CONTENTTYPE, CRYPT_OK, NULL },
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the PKCS #15 information state */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheckPKCS15( const PKCS15_INFO *pkcs15infoPtr )
	{
	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );

	/* Check that the basic fields are in order.  The label field can be 
	   empty for standalone certificates or public keys, which don't 
	   usually have a label associated with the key */
	if( !isEnumRange( pkcs15infoPtr->type, PKCS15_SUBTYPE ) || \
		!isIntegerRange( pkcs15infoPtr->index ) )
		{
		DEBUG_PUTS(( "sanityCheckPKCS15: General info" ));
		return( FALSE );
		}
	if( !rangeCheck( pkcs15infoPtr->labelLength, 0, CRYPT_MAX_TEXTSIZE ) )
		{
		DEBUG_PUTS(( "sanityCheckPKCS15: Label" ));
		return( FALSE );
		}
	if( pkcs15infoPtr->type == PKCS15_SUBTYPE_SECRETKEY || \
		pkcs15infoPtr->type == PKCS15_SUBTYPE_DATA )
		{
		if( pkcs15infoPtr->iDlength != 0 || \
			pkcs15infoPtr->keyIDlength != 0 )
			{
			DEBUG_PUTS(( "sanityCheckPKCS15: Spurious ID" ));
			return( FALSE );
			}
		}
	else
		{
		if( !rangeCheck( pkcs15infoPtr->iDlength, 
						 1, CRYPT_MAX_HASHSIZE ) || \
			!rangeCheck( pkcs15infoPtr->keyIDlength, 
						 1, CRYPT_MAX_HASHSIZE ) )
			{
			DEBUG_PUTS(( "sanityCheckPKCS15: IDs" ));
			return( FALSE );
			}
		}

	/* Check that the ID fields have reasonable values.  This is a general 
	   check for reasonable values that's more targeted at catching 
	   inadvertent memory corruption than a strict sanity check */
	if( !rangeCheck( pkcs15infoPtr->iAndSIDlength, 0, KEYID_SIZE ) || \
		!rangeCheck( pkcs15infoPtr->subjectNameIDlength, 0, KEYID_SIZE ) || \
		!rangeCheck( pkcs15infoPtr->issuerNameIDlength, 0, KEYID_SIZE ) )
		{
		DEBUG_PUTS(( "sanityCheckPKCS15: Subject/issuer ID" ));
		return( FALSE );
		}
	if( !rangeCheck( pkcs15infoPtr->pgp2KeyIDlength, 0, PGP_KEYID_SIZE ) || \
		!rangeCheck( pkcs15infoPtr->openPGPKeyIDlength, 0, PGP_KEYID_SIZE ) )
		{
		DEBUG_PUTS(( "sanityCheckPKCS15: PGP ID" ));
		return( FALSE );
		}

	/* Check that the key/certificate data fields have reasonable values.  
	   This is a general check for reasonable values that's more targeted 
	   at catching inadvertent memory corruption than a strict sanity 
	   check */
	if( pkcs15infoPtr->pubKeyData != NULL )
		{
		if( !isShortIntegerRangeNZ( pkcs15infoPtr->pubKeyDataSize ) || \
			pkcs15infoPtr->pubKeyOffset <= 0 || \
			pkcs15infoPtr->pubKeyOffset >= pkcs15infoPtr->pubKeyDataSize )
			{
			DEBUG_PUTS(( "sanityCheckPKCS15: Public key data" ));
			return( FALSE );
			}
		}
	else
		{
		if( pkcs15infoPtr->pubKeyDataSize != 0 || \
			pkcs15infoPtr->pubKeyOffset != 0 )
			{
			DEBUG_PUTS(( "sanityCheckPKCS15: Spurious public key data" ));
			return( FALSE );
			}
		}
	if( pkcs15infoPtr->privKeyData != NULL )
		{
		if( !isShortIntegerRangeNZ( pkcs15infoPtr->privKeyDataSize ) || \
			pkcs15infoPtr->privKeyOffset <= 0 || \
			pkcs15infoPtr->privKeyOffset >= pkcs15infoPtr->privKeyDataSize )
			{
			DEBUG_PUTS(( "sanityCheckPKCS15: Private key data" ));
			return( FALSE );
			}
		}
	else
		{
		if( pkcs15infoPtr->privKeyDataSize != 0 || \
			pkcs15infoPtr->privKeyOffset != 0 )
			{
			DEBUG_PUTS(( "sanityCheckPKCS15: Spurious private key data" ));
			return( FALSE );
			}
		}
	if( pkcs15infoPtr->certData != NULL )
		{
		if( !isShortIntegerRangeNZ( pkcs15infoPtr->certDataSize ) || \
			pkcs15infoPtr->certOffset <= 0 || \
			pkcs15infoPtr->certOffset >= pkcs15infoPtr->certDataSize )
			{
			DEBUG_PUTS(( "sanityCheckPKCS15: Certificate data" ));
			return( FALSE );
			}
		}
	else
		{
		if( pkcs15infoPtr->certDataSize != 0 || \
			pkcs15infoPtr->certOffset != 0 )
			{
			DEBUG_PUTS(( "sanityCheckPKCS15: Spurious certificate data" ));
			return( FALSE );
			}
		}

	return( TRUE );
	}
#endif /* !CONFIG_CONSERVE_MEMORY_EXTRA */

/* Get the hash of various certificate name fields */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5 ) ) \
int getCertID( IN_HANDLE const CRYPT_HANDLE iCryptHandle, 
			   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE nameType, 
			   OUT_BUFFER( nameIdMaxLen, *nameIdLen ) BYTE *nameID, 
			   IN_LENGTH_SHORT_MIN( KEYID_SIZE ) const int nameIdMaxLen,
			   OUT_LENGTH_BOUNDED_Z( nameIdMaxLen ) int *nameIdLen )
	{
	HASH_FUNCTION_ATOMIC hashFunctionAtomic;
	DYNBUF idDB;
	int status;

	assert( isWritePtrDynamic( nameID, nameIdMaxLen ) );
	assert( isWritePtr( nameIdLen, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( nameType == CRYPT_IATTRIBUTE_SPKI || \
			  nameType == CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER || \
			  nameType == CRYPT_IATTRIBUTE_SUBJECT || \
			  nameType == CRYPT_IATTRIBUTE_ISSUER );
	REQUIRES( isShortIntegerRangeMin( nameIdMaxLen, KEYID_SIZE ) );

	/* Clear return value */
	*nameIdLen = 0;

	/* Get the attribute data and hash algorithm information and hash the 
	   attribute to get the ID */
	status = dynCreate( &idDB, iCryptHandle, nameType );
	if( cryptStatusError( status ) )
		return( status );
	getHashAtomicParameters( CRYPT_ALGO_SHA1, 0, &hashFunctionAtomic, NULL );
	hashFunctionAtomic( nameID, nameIdMaxLen, dynData( idDB ), 
						dynLength( idDB ) );
	dynDestroy( &idDB );
	*nameIdLen = nameIdMaxLen;

	return( CRYPT_OK );
	}

/* Locate a PKCS #15 object based on an ID */

#define matchID( src, srcLen, dest, destLen ) \
		( ( srcLen ) > 0 && ( srcLen ) == ( destLen ) && \
		  !memcmp( ( src ), ( dest ), ( destLen ) ) )

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
PKCS15_INFO *findEntry( IN_ARRAY( noPkcs15objects ) const PKCS15_INFO *pkcs15info,
						IN_LENGTH_SHORT const int noPkcs15objects,
						IN_KEYID_OPT const CRYPT_KEYID_TYPE keyIDtype,
							/* CRYPT_KEYIDEX_ID maps to CRYPT_KEYID_NONE */
						IN_BUFFER_OPT( keyIDlength ) const void *keyID, 
						IN_LENGTH_KEYID_Z const int keyIDlength,
						IN_FLAGS_Z( KEYMGMT ) const int requestedUsage,
						IN_BOOL const BOOLEAN isWildcardMatch )
	{
	const PKCS15_INFO *pkcs15infoWildcardMatch = NULL;
	LOOP_INDEX i;

	assert( isReadPtrDynamic( pkcs15info, \
							  sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( ( keyID == NULL && keyIDlength == 0 ) || \
			isReadPtrDynamic( keyID, keyIDlength ) );

	REQUIRES_N( isShortIntegerRangeNZ( noPkcs15objects ) );
	REQUIRES_N( keyIDtype == CRYPT_KEYID_NAME || \
				keyIDtype == CRYPT_KEYID_URI || \
				keyIDtype == CRYPT_IKEYID_KEYID || \
				keyIDtype == CRYPT_IKEYID_PGPKEYID || \
				keyIDtype == CRYPT_IKEYID_SUBJECTID || \
				keyIDtype == CRYPT_IKEYID_ISSUERID || \
				keyIDtype == CRYPT_KEYIDEX_ID );
	REQUIRES_N( ( keyID == NULL && keyIDlength == 0 ) || \
				( keyID != NULL && \
				  keyIDlength >= MIN_NAME_LENGTH && \
				  keyIDlength < MAX_ATTRIBUTE_SIZE ) );
	REQUIRES_N( isFlagRangeZ( requestedUsage, KEYMGMT ) );
	REQUIRES_N( ( requestedUsage & KEYMGMT_MASK_USAGEOPTIONS ) != \
				KEYMGMT_MASK_USAGEOPTIONS );
	REQUIRES_N( isBooleanValue( isWildcardMatch ) );
	REQUIRES_N( !isWildcardMatch || keyID == NULL );

	/* If there's no ID to search on and we're not performing a wildcard 
	   match, don't try and do anything.  This can occur when we're trying 
	   to build a chain and the necessary chaining data like an issuerID 
	   isn't present in the keyset */
	if( ( keyID == NULL || keyIDlength <= 0 ) && !isWildcardMatch )
		return( NULL );

	/* Try and locate the appropriate object in the PKCS #15 collection */
	LOOP_MED( i = 0, i < noPkcs15objects, i++ )
		{
		const PKCS15_INFO *pkcs15infoPtr;
		int compositeUsage;

		ENSURES_N( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

		/* If there's no entry at this position, continue */
		pkcs15infoPtr = &pkcs15info[ i ];
		if( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE )
			continue;

		ENSURES_N( sanityCheckPKCS15( pkcs15infoPtr ) );

		/* If we've already got a wildcard match and we've found a second
		   potential match, there's an ambiguity over what we should be 
		   returning */
		if( pkcs15infoWildcardMatch != NULL )
			return( NULL );

		/* If there's an explicit usage requested, make sure that the key 
		   usage matches this.  This can get slightly complex because the 
		   advertised usage isn't necessarily the same as the usage 
		   permitted by the associated certificate (PKCS #11 apps are 
		   particularly good at setting bogus usage types) and the overall 
		   result can be further influenced by trusted usage settings, so 
		   all that we check for here is an indicated usage for the key 
		   matching the requested usage */
		compositeUsage = pkcs15infoPtr->pubKeyUsage | \
						 pkcs15infoPtr->privKeyUsage;
		if( ( requestedUsage & KEYMGMT_FLAG_USAGE_CRYPT ) && \
			!( compositeUsage & ENCR_USAGE_MASK ) )
			continue;
		if( ( requestedUsage & KEYMGMT_FLAG_USAGE_SIGN ) && \
			!( compositeUsage & SIGN_USAGE_MASK ) )
			continue;

		/* If we're performing a wildcard match, return the first private-key 
		   entry.  In theory this shouldn't be necessary since cryptlib-
		   generated keysets must have valid labels, but keysets from other 
		   implementations may not have them, or may have machine-generated
		   labels that don't work well for human use, so we allow a wildcard
		   match as a generic "get me whatever you can" */
		if( isWildcardMatch )
			{
			if( pkcs15infoPtr->privKeyData == NULL )
				continue;	/* No private-key data present, continue */

			/* We've found a potential wildcard match, remember it and 
			   continue */
			pkcs15infoWildcardMatch = pkcs15infoPtr;
			continue;
			}
		ENSURES_N( keyID != NULL );

		/* Check for a match based on the ID type */
		switch( keyIDtype )
			{
			case CRYPT_KEYID_NAME:
				if( matchID( pkcs15infoPtr->label, pkcs15infoPtr->labelLength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_KEYID_URI:
				if( matchID( pkcs15infoPtr->uri, pkcs15infoPtr->uriLength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_KEYID:
				if( matchID( pkcs15infoPtr->keyID, pkcs15infoPtr->keyIDlength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_PGPKEYID:
				/* For the PGP keyID we compare both IDs for the reasons 
				   given in the PGP keyset read code */
				if( matchID( pkcs15infoPtr->pgp2KeyID,
							 pkcs15infoPtr->pgp2KeyIDlength, keyID,
							 keyIDlength ) || \
					matchID( pkcs15infoPtr->openPGPKeyID,
							 pkcs15infoPtr->openPGPKeyIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_SUBJECTID:
				if( matchID( pkcs15infoPtr->subjectNameID,
							 pkcs15infoPtr->subjectNameIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_ISSUERID:
				if( matchID( pkcs15infoPtr->iAndSID,
							 pkcs15infoPtr->iAndSIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_KEYIDEX_ID:
				if( matchID( pkcs15infoPtr->iD, pkcs15infoPtr->iDlength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			default:
				retIntError_Null();
			}
		}
	ENSURES_N( LOOP_BOUND_OK );

	/* If we're looking for a wildcard match, return that */
	if( pkcs15infoWildcardMatch != NULL )
		return( ( PKCS15_INFO * ) pkcs15infoWildcardMatch );

	/* If we're trying to match on the PGP key ID and didn't find anything,
	   retry it using the first PGP_KEYID_SIZE bytes of the object ID.  This
	   is necessary because calculation of the OpenPGP ID requires the
	   presence of data that may not be present in non-PGP keys so we can't
	   calculate a real OpenPGP ID but have to use the next-best thing 
	   (sol lucet omnibus) */
	if( keyIDtype == CRYPT_IKEYID_PGPKEYID )
		{
		LOOP_MED( i = 0, i < noPkcs15objects, i++ )
			{
			const PKCS15_INFO *pkcs15infoPtr;

			ENSURES_N( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

			pkcs15infoPtr = &pkcs15info[ i ];
			if( pkcs15infoPtr->type != PKCS15_SUBTYPE_NONE && \
				pkcs15infoPtr->iDlength >= PGP_KEYID_SIZE && \
				!memcmp( keyID, pkcs15infoPtr->iD, PGP_KEYID_SIZE ) )
				{
				return( ( PKCS15_INFO * ) pkcs15infoPtr );
				}
			}
		ENSURES_N( LOOP_BOUND_OK );
		}

	return( NULL );
	}

/* Find a free PKCS #15 entry */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
PKCS15_INFO *findFreeEntry( IN_ARRAY( noPkcs15objects ) \
								const PKCS15_INFO *pkcs15info,
							IN_LENGTH_SHORT const int noPkcs15objects, 
							OUT_OPT_INDEX( noPkcs15objects ) int *index )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( pkcs15info, \
							  sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( ( index == NULL ) || isWritePtr( index, sizeof( int ) ) );

	REQUIRES_N( isShortIntegerRangeNZ( noPkcs15objects ) );

	/* Clear return value */
	if( index != NULL )
		*index = CRYPT_ERROR;

	LOOP_MED( i = 0, i < noPkcs15objects, i++ )
		{
		ENSURES_N( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

		if( pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
			break;
		}
	ENSURES_N( LOOP_BOUND_OK );
	if( i >= noPkcs15objects )
		return( NULL );

	/* Remember the index value (used for enumerating PKCS #15 entries) for 
	   this entry if required */
	if( index != NULL )
		*index = i;

	return( ( PKCS15_INFO * ) &pkcs15info[ i ] );
	}

/* Free object entries */

STDC_NONNULL_ARG( ( 1 ) ) \
void pkcs15freeEntry( INOUT_PTR PKCS15_INFO *pkcs15info )
	{
	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );

	if( pkcs15info->pubKeyData != NULL )
		{
		REQUIRES_V( isShortIntegerRangeNZ( pkcs15info->pubKeyDataSize ) ); 
		zeroise( pkcs15info->pubKeyData, pkcs15info->pubKeyDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->pubKeyData );
		}
	if( pkcs15info->privKeyData != NULL )
		{
		REQUIRES_V( isShortIntegerRangeNZ( pkcs15info->privKeyDataSize ) ); 
		zeroise( pkcs15info->privKeyData, pkcs15info->privKeyDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->privKeyData );
		}
	if( pkcs15info->certData != NULL )
		{
		REQUIRES_V( isShortIntegerRangeNZ( pkcs15info->certDataSize ) ); 
		zeroise( pkcs15info->certData, pkcs15info->certDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->certData );
		}
	if( pkcs15info->dataData != NULL )
		{
		REQUIRES_V( isShortIntegerRangeNZ( pkcs15info->dataDataSize ) ); 
		zeroise( pkcs15info->dataData, pkcs15info->dataDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->dataData );
		}
	zeroise( pkcs15info, sizeof( PKCS15_INFO ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void pkcs15Free( INOUT_ARRAY( noPkcs15objects ) PKCS15_INFO *pkcs15info, 
				 IN_RANGE( 1, MAX_PKCS15_OBJECTS ) const int noPkcs15objects )
	{
	LOOP_INDEX i;

	assert( isWritePtrDynamic( pkcs15info, \
							   sizeof( PKCS15_INFO ) * noPkcs15objects ) );

	REQUIRES_V( noPkcs15objects >= 1 && \
				noPkcs15objects <= MAX_PKCS15_OBJECTS );

	LOOP_MED( i = 0, i < noPkcs15objects, i++ )
		{
		ENSURES_V( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

		pkcs15freeEntry( &pkcs15info[ i ] );
		}
	ENSURES_V( LOOP_BOUND_OK );
	zeroise( pkcs15info, sizeof( PKCS15_INFO ) * noPkcs15objects );
	}

/* Get the PKCS #15 validity information from a certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int getValidityInfo( INOUT_PTR PKCS15_INFO *pkcs15info,
					 IN_HANDLE const CRYPT_HANDLE cryptHandle )
	{
	MESSAGE_DATA msgData;
	time_t validFrom, validTo;
	int status;

	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );

	REQUIRES( isHandleRangeValid( cryptHandle ) );

	/* Remember the validity information for later.  We always update the 
	   validity (even if it's already set) since we may be replacing an 
	   older certificate with a newer one */
	setMessageData( &msgData, &validFrom, sizeof( time_t ) );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_VALIDFROM );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, &validTo, sizeof( time_t ) );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_VALIDTO );
	if( cryptStatusError( status ) )
		return( status );
	if( pkcs15info->validTo > validTo )
		{
		/* There's an existing, newer certificate already present, make sure 
		   that we don't try and add the new one */
		return( CRYPT_ERROR_DUPLICATE );
		}
	pkcs15info->validFrom = validFrom;
	pkcs15info->validTo = validTo;

	return( CRYPT_OK );
	}

/* Read the header of a PKCS #15 keyset */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPkcs15EncapsHeader( INOUT_PTR STREAM *stream,
								   OUT_PTR long *endPosPtr )
	{
	long length;
	int tag, innerLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( endPosPtr, sizeof( long ) ) );

	/* Clear return value */
	*endPosPtr = 0;

	/* The outer header was a CMS AuthData wrapper, try again for an inner 
	   PKCS #15 header.  First we skip the AuthData SET OF RECIPIENTINFO, 
	   macAlgorithm AlgorithmIdentifier, and optional digestAlgorithm 
	   AlgorithmIdentifier */
	readUniversal( stream );
	status = readUniversal( stream );
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 1 ) )
		status = readUniversal( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* We've made our way past the AuthData information, try again for
	   encapsulated PKCS #15 content */
	status = readCMSheader( stream, keyFilePKCS15OIDinfo, 
							FAILSAFE_ARRAYSIZE( keyFilePKCS15OIDinfo, OID_INFO ), 
							NULL, &length, READCMS_FLAG_INNERHEADER );
	if( cryptStatusError( status ) )
		return( status );

	/* Since this is EncapsulatedContentInfo the version information doesn't 
	   immediately follow the header but is encapsulated inside an OCTET 
	   STRING, so we have to skip an additional layer of wrapping and 
	   manually read the version information.  In addition the OCTET STRING
	   could be indefinite-length, in which case it acts as a constructed 
	   value containing an inner OCTET STRING, so we have to skip the inner
	   OCTET STRING before we get to the actual content */
	if( length == CRYPT_UNUSED )
		{
		/* It's an indefinite-length OCTET STRING, skip the inner OCTET 
		   STRING wrapper */
		readOctetStringHole( stream, NULL, 16, DEFAULT_TAG );
		}
	status = readSequence( stream, &innerLength );
	if( cryptStatusOK( status ) )
		{
		long value;

		*endPosPtr = innerLength;
		status = readShortInteger( stream, &value );
		if( cryptStatusOK( status ) && value != 0 )
			status = CRYPT_ERROR_BADDATA;
		}

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readPkcs15header( INOUT_PTR STREAM *stream, 
							 OUT_INT_Z long *endPosPtr,
							 INOUT_PTR ERROR_INFO *errorInfo )
	{
	long endPos;
	int value, currentPos, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( endPosPtr, sizeof( long ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	/* Clear return value */
	*endPosPtr = 0;

	/* Read the outer header and make sure that the length information is 
	   valid */
	status = readCMSheader( stream, keyFileOIDinfo, 
							FAILSAFE_ARRAYSIZE( keyFileOIDinfo, OID_INFO ), 
							&value, &endPos, 
							READCMS_FLAG_DEFINITELENGTH_OPT );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid PKCS #15 keyset header" ) );
		}
	if( value == FALSE )
		{
		/* The outer header was a CMS AuthData wrapper, try again for an 
		   inner PKCS #15 header */
		status = readPkcs15EncapsHeader( stream, &endPos );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Invalid PKCS #15 content wrapped in AuthData" ) );
			}
		}

	/* If it's indefinite-length data, don't try and go any further (the 
	   general length check below will also catch this, but we make the 
	   check explicit here) */
	if( endPos == CRYPT_UNUSED )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Can't process indefinite-length PKCS #15 content" ) );
		}

	/* Make sure that the length information is sensible.  readCMSheader() 
	   reads the version number field at the start of the content so we have 
	   to adjust the stream position for this when we calculate the data end 
	   position */
	status = calculateStreamObjectLength( stream, sizeofShortInteger( 0 ), 
										  &currentPos );
	if( cryptStatusError( status ) || currentPos < MIN_OBJECT_SIZE || \
		endPos < 16 + MIN_OBJECT_SIZE || \
		checkOverflowAdd( currentPos, endPos ) || \
		currentPos + endPos >= MAX_BUFFER_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, errorInfo, 
				  "Invalid PKCS #15 keyset length information" ) );
		}
	*endPosPtr = currentPos + endPos;

	/* Skip the key management information if there is any and read the 
	   inner wrapper */
	if( checkStatusPeekTag( stream, status, value ) && \
		value == MAKE_CTAG( 0 ) )
		{
		status = readUniversal( stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = readLongSequence( stream, NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that, after skipping the key management data, there's still 
	   some payload left */
	if( stell( stream ) >= endPos - MIN_OBJECT_SIZE )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* A PKCS #15 keyset can contain multiple keys and whatnot, so when we open
   it we parse the contents into memory for later use */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initFunction( INOUT_PTR KEYSET_INFO *keysetInfoPtr, 
						 STDC_UNUSED const char *name,
						 STDC_UNUSED const int nameLength,
						 IN_ENUM( CRYPT_KEYOPT ) const CRYPT_KEYOPT_TYPE options )
	{
	PKCS15_INFO *pkcs15info;
	STREAM *stream = &keysetInfoPtr->keysetFile->stream;
	long endPos DUMMY_INIT;
	int status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( sanityCheckKeyset( keysetInfoPtr ) );
	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );
	REQUIRES( name == NULL && nameLength == 0 );
	REQUIRES( options == CRYPT_KEYOPT_NONE || \
			  options == CRYPT_KEYOPT_CREATE );

	/* If we're opening an existing keyset skip the outer header, optional
	   keyManagementInfo, and inner header.  We do this before we perform any
	   setup operations to weed out potential problem keysets */
	if( options != CRYPT_KEYOPT_CREATE )
		{
		status = readPkcs15header( stream, &endPos, KEYSET_ERRINFO );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Allocate the PKCS #15 object information */
	REQUIRES( isShortIntegerRangeNZ( sizeof( PKCS15_INFO ) * \
									 MAX_PKCS15_OBJECTS ) );
	if( ( pkcs15info = clAlloc( "initFunction", \
								sizeof( PKCS15_INFO ) * \
								MAX_PKCS15_OBJECTS ) ) == NULL )
		{
		if( options != CRYPT_KEYOPT_CREATE )
			{
			/* Reset the stream position to account for the header 
			   information that we've already read */
			sseek( stream, 0 ) ;
			}
		return( CRYPT_ERROR_MEMORY );
		}
	memset( pkcs15info, 0, sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS );
	DATAPTR_SET( keysetInfoPtr->keyData, pkcs15info );
	keysetInfoPtr->keyDataSize = sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS;
	keysetInfoPtr->keyDataNoObjects = MAX_PKCS15_OBJECTS;

	/* If this is a newly-created keyset, there's nothing left to do */
	if( options == CRYPT_KEYOPT_CREATE )
		{
		ENSURES( sanityCheckKeyset( keysetInfoPtr ) );

		return( CRYPT_OK );
		}

	/* Read all of the keys in the keyset */
	status = readPkcs15Keyset( &keysetInfoPtr->keysetFile->stream, 
							   pkcs15info, MAX_PKCS15_OBJECTS, endPos, 
							   KEYSET_ERRINFO );
	if( cryptStatusError( status ) )
		{
		clFree( "initFunction", pkcs15info );
		DATAPTR_SET( keysetInfoPtr->keyData, NULL );
		keysetInfoPtr->keyDataSize = 0;
		if( options != CRYPT_KEYOPT_CREATE )
			{
			/* Reset the stream position to account for the header 
			   information that we've already read */
			sseek( stream, 0 ) ;
			}
		return( status );
		}

	ENSURES( sanityCheckKeyset( keysetInfoPtr ) );

	return( CRYPT_OK );
	}

/* Shut down the PKCS #15 state, flushing information to disk if necessary */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int shutdownFunction( INOUT_PTR KEYSET_INFO *keysetInfoPtr )
	{
	PKCS15_INFO *pkcs15info = DATAPTR_GET( keysetInfoPtr->keyData );
	int status = CRYPT_OK;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );
	assert( pkcs15info == NULL || \
			isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );

	REQUIRES( sanityCheckKeyset( keysetInfoPtr ) );
	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );
	REQUIRES( DATAPTR_ISVALID( keysetInfoPtr->keyData ) );

	/* If the contents have been changed, allocate a working I/O buffer for 
	   the duration of the flush and commit the changes to disk */
	if( TEST_FLAG( keysetInfoPtr->flags, KEYSET_FLAG_DIRTY ) )
		{
		STREAM *stream = &keysetInfoPtr->keysetFile->stream;

		REQUIRES( pkcs15info != NULL );

#if defined( USE_HARDWARE ) || defined( USE_TPM )
		if( TEST_FLAG( keysetInfoPtr->flags, KEYSET_FLAG_MEMMAPPED ) )
			{
			FILE_INFO *fileInfo = keysetInfoPtr->keysetFile;

			sMemOpen( stream, fileInfo->storage, 
					  fileInfo->storageTotalSize );
			status = pkcs15Flush( stream, pkcs15info, 
								  keysetInfoPtr->keyDataNoObjects, FALSE );
			if( cryptStatusOK( status ) )
				fileInfo->storageUsedSize = stell( stream );
			sMemDisconnect( stream );
			}
		else
#endif /* USE_HARDWARE || USE_TPM  */
			{
			BYTE ALIGN_STACK_DATA buffer[ SAFEBUFFER_SIZE( STREAM_BUFSIZE ) + 8 ];

			sseek( stream, 0 );
			memset( buffer, 0, SAFEBUFFER_SIZE( STREAM_BUFSIZE ) );
					/* Keep static analysers happy */
			safeBufferInit( SAFEBUFFER_PTR( buffer ), STREAM_BUFSIZE );
			sioctlSetString( stream, STREAM_IOCTL_IOBUFFER, 
							 SAFEBUFFER_PTR( buffer ), STREAM_BUFSIZE );
			status = pkcs15Flush( stream, pkcs15info, 
								  keysetInfoPtr->keyDataNoObjects, TRUE );
			sioctlSet( stream, STREAM_IOCTL_IOBUFFER, 0 );
			}
		if( status == OK_SPECIAL )
			{
			SET_FLAG( keysetInfoPtr->flags, KEYSET_FLAG_EMPTY );
			status = CRYPT_OK;
			}
		}

	/* Free the PKCS #15 object information */
	if( pkcs15info != NULL )
		{
		pkcs15Free( pkcs15info, keysetInfoPtr->keyDataNoObjects );
		REQUIRES( isIntegerRangeNZ( keysetInfoPtr->keyDataSize ) ); 
		zeroise( pkcs15info, keysetInfoPtr->keyDataSize );
		clFree( "shutdownFunction", pkcs15info );
		DATAPTR_SET( keysetInfoPtr->keyData, NULL );
		keysetInfoPtr->keyDataSize = 0;
		}

	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, KEYSET_ERRINFO, 
				  "Couldn't send PKCS #15 data to persistent storage" ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodPKCS15( INOUT_PTR KEYSET_INFO *keysetInfoPtr )
	{
	int status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );

	/* Set the access method pointers */
	FNPTR_SET( keysetInfoPtr->initFunction, initFunction );
	FNPTR_SET( keysetInfoPtr->shutdownFunction, shutdownFunction );
	status = initPKCS15get( keysetInfoPtr );
	if( cryptStatusOK( status ) )
		status = initPKCS15set( keysetInfoPtr );
	return( status );
	}
#endif /* USE_PKCS15 */
