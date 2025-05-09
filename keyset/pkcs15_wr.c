/****************************************************************************
*																			*
*						cryptlib PKCS #15 Write Routines					*
*						Copyright Peter Gutmann 1996-2007					*
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

/****************************************************************************
*																			*
*							Write PKCS #15 Objects							*
*																			*
****************************************************************************/

/* Write the wrapping needed for individual objects */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeObjectWrapper( INOUT_PTR STREAM *stream, 
							   IN_LENGTH_SHORT const int length,
							   IN_TAG const int tag )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( tag >= 0 && tag < MAX_TAG_VALUE );
	REQUIRES( isShortIntegerRangeNZ( length ) );

	writeConstructed( stream, sizeofObject( length ), tag );
	return( writeConstructed( stream, length, CTAG_OV_DIRECT ) );
	}

/* Write a data item */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sizeofDataItem( const PKCS15_INFO *pkcs15infoPtr, 
						   OUT_LENGTH_SHORT_Z int *length )
	{
	const int dataSize = \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO ) ? \
				pkcs15infoPtr->dataDataSize : \
				sizeofShortObject( pkcs15infoPtr->dataDataSize );
	const int labelSize = \
			( pkcs15infoPtr->labelLength > 0 ) ? \
				sizeofShortObject( pkcs15infoPtr->labelLength ) : 0;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	REQUIRES( isShortIntegerRange( labelSize ) );
	REQUIRES( isShortIntegerRangeNZ( dataSize ) );

	*length = sizeofShortObject( \
					sizeofShortObject( labelSize ) + \
					sizeofShortObject( sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) ) + \
					sizeofShortObject( \
						sizeofShortObject( \
							sizeofOID( OID_CRYPTLIB_CONFIGDATA ) + dataSize ) ) );
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeDataItem( INOUT_PTR STREAM *stream, 
						  const PKCS15_INFO *pkcs15infoPtr )
	{
	const BYTE *oid = \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_CONFIGDATA ) ? \
				OID_CRYPTLIB_CONFIGDATA : \
			( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINDEX ) ? \
				OID_CRYPTLIB_USERINDEX : OID_CRYPTLIB_USERINFO;
	const int labelSize = \
			( pkcs15infoPtr->labelLength > 0 ) ? \
				sizeofShortObject( pkcs15infoPtr->labelLength ) : 0;
	const int contentSize = sizeofOID( oid ) + \
			( ( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO ) ? \
				pkcs15infoPtr->dataDataSize : \
				sizeofShortObject( pkcs15infoPtr->dataDataSize ) );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );

	REQUIRES( pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_CONFIGDATA || \
			  pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINDEX || \
			  pkcs15infoPtr->dataType == CRYPT_IATTRIBUTE_USERINFO );
	REQUIRES( isShortIntegerRange( labelSize ) );
	REQUIRES( isShortIntegerRangeNZ( contentSize ) );

	writeConstructed( stream, 
					  sizeofShortObject( labelSize ) + \
					  sizeofShortObject( \
							sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) ) + \
					  sizeofShortObject( \
							sizeofObject( contentSize ) ),
					  CTAG_DO_OIDDO );
	writeSequence( stream, labelSize );
	if( labelSize > 0 )
		{
		writeCharacterString( stream, ( BYTE * ) pkcs15infoPtr->label,
							  pkcs15infoPtr->labelLength, BER_STRING_UTF8 );
		}
	writeSequence( stream, sizeofOID( OID_CRYPTLIB_CONTENTTYPE ) );
	writeOID( stream, OID_CRYPTLIB_CONTENTTYPE );
	writeConstructed( stream, sizeofShortObject( contentSize ),
					  CTAG_OB_TYPEATTR );
	writeSequence( stream, contentSize );
	writeOID( stream, oid );
	if( pkcs15infoPtr->dataType != CRYPT_IATTRIBUTE_USERINFO )
		{
		/* UserInfo is a straight object, the others are SEQUENCEs of
		   objects */
		writeSequence( stream, pkcs15infoPtr->dataDataSize );
		}
	return( swrite( stream, pkcs15infoPtr->dataData, \
					pkcs15infoPtr->dataDataSize ) );
	}

/* Flush a PKCS #15 collection to a stream */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int pkcs15Flush( INOUT_PTR STREAM *stream, 
				 IN_ARRAY( noPkcs15objects ) const PKCS15_INFO *pkcs15info, 
				 IN_LENGTH_SHORT const int noPkcs15objects,
				 IN_BOOL const BOOLEAN commitData )
	{
	int pubKeySize = 0, privKeySize = 0, certSize = 0, dataSize = 0;
	LOOP_INDEX i;
	int objectsSize = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( pkcs15info, \
							  sizeof( PKCS15_INFO ) * noPkcs15objects ) );

	REQUIRES( isShortIntegerRangeNZ( noPkcs15objects ) );
#if defined( USE_HARDWARE ) || defined( USE_TPM )
	REQUIRES( isBooleanValue( commitData ) );
#else
	REQUIRES( commitData == TRUE );
#endif /* USE_HARDWARE || USE_TPM */

	/* Determine the overall size of the objects */
	LOOP_MED( i = 0, i < noPkcs15objects, i++ )
		{
		ENSURES( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

		switch( pkcs15info[ i ].type )
			{
			case PKCS15_SUBTYPE_NONE:
				break;

			case PKCS15_SUBTYPE_NORMAL:
				pubKeySize += pkcs15info[ i ].pubKeyDataSize;
				privKeySize += pkcs15info[ i ].privKeyDataSize;
				STDC_FALLTHROUGH;

			case PKCS15_SUBTYPE_CERT:
				certSize += pkcs15info[ i ].certDataSize;
				break;

			case PKCS15_SUBTYPE_SECRETKEY:
				retIntError();

			case PKCS15_SUBTYPE_DATA:
				{
				int length;

				status = sizeofDataItem( &pkcs15info[ i ], &length );
				if( cryptStatusError( status ) )
					return( status );
				dataSize += length;
				break;
				}

			default:
				retIntError();
			}
		}
	ENSURES( LOOP_BOUND_OK );

	/* Determine how much data there is to write.  If there's no data
	   present, let the caller know that the keyset is empty */
	if( pubKeySize > 0 )
		objectsSize += sizeofObject( sizeofObject( pubKeySize ) );
	if( privKeySize > 0 )
		objectsSize += sizeofObject( sizeofObject( privKeySize ) );
	if( certSize > 0 )
		objectsSize += sizeofObject( sizeofObject( certSize ) );
	if( dataSize > 0 )
		objectsSize += sizeofObject( sizeofObject( dataSize ) );
	if( objectsSize <= 0 )
		return( OK_SPECIAL );	/* Keyset is empty */

	/* Write the header information and each public key, private key, and
	   certificate */
	status = writeCMSheader( stream, OID_PKCS15_CONTENTTYPE, 
							 sizeofOID( OID_PKCS15_CONTENTTYPE ),
							 sizeofShortInteger( 0 ) + \
								sizeofObject( objectsSize ), FALSE );
	if( cryptStatusError( status ) )
		return( status );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	status = writeSequence( stream, objectsSize );
	if( cryptStatusOK( status ) && privKeySize > 0 )
		{
		status = writeObjectWrapper( stream, privKeySize, CTAG_PO_PRIVKEY );
		LOOP_MED( i = 0, cryptStatusOK( status ) && i < noPkcs15objects, i++ )
			{
			ENSURES( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

			if( pkcs15info[ i ].privKeyDataSize > 0 )
				{
				status = swrite( stream, pkcs15info[ i ].privKeyData,
								 pkcs15info[ i ].privKeyDataSize );
				}
			}
		ENSURES( LOOP_BOUND_OK );
		}
	if( cryptStatusOK( status ) && pubKeySize > 0 )
		{
		status = writeObjectWrapper( stream, pubKeySize, CTAG_PO_PUBKEY );
		LOOP_MED( i = 0, cryptStatusOK( status ) && i < noPkcs15objects, i++ )
			{
			ENSURES( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

			if( pkcs15info[ i ].pubKeyDataSize > 0 )
				{
				status = swrite( stream, pkcs15info[ i ].pubKeyData,
								 pkcs15info[ i ].pubKeyDataSize );
				}
			}
		ENSURES( LOOP_BOUND_OK );
		}
	if( cryptStatusOK( status ) && certSize > 0 )
		{
		status = writeObjectWrapper( stream, certSize, CTAG_PO_CERT );
		LOOP_MED( i = 0, cryptStatusOK( status ) && i < noPkcs15objects, i++ )
			{
			ENSURES( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

			if( ( pkcs15info[ i ].type == PKCS15_SUBTYPE_NORMAL && \
				  pkcs15info[ i ].certDataSize > 0 ) || \
				( pkcs15info[ i ].type == PKCS15_SUBTYPE_CERT ) )
				{
				status = swrite( stream, pkcs15info[ i ].certData,
								 pkcs15info[ i ].certDataSize );
				}
			}
		ENSURES( LOOP_BOUND_OK );
		}
	if( cryptStatusOK( status ) && dataSize > 0 )
		{
		status = writeObjectWrapper( stream, dataSize, CTAG_PO_DATA );
		LOOP_MED( i = 0, cryptStatusOK( status ) && i < noPkcs15objects, i++ )
			{
			ENSURES( LOOP_INVARIANT_MED( i, 0, noPkcs15objects - 1 ) );

			if( pkcs15info[ i ].dataDataSize > 0 )
				status = writeDataItem( stream, &pkcs15info[ i ] );
			}
		ENSURES( LOOP_BOUND_OK );
		}
	ENSURES( cryptStatusOK( status ) );

	/* If this is an in-memory keyset, we're done */
#if defined( USE_HARDWARE ) || defined( USE_TPM )
	if( !commitData )
		return( CRYPT_OK );
#endif /* USE_HARDWARE || USE_TPM */

	return( sflush( stream ) );
	}
#endif /* USE_PKCS15 */
