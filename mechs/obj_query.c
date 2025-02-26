/****************************************************************************
*																			*
*						Encoded Object Query Routines						*
*					  Copyright Peter Gutmann 1992-2020						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp_rw.h"
  #include "mech.h"
#else
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "enc_dec/misc_rw.h"
  #include "enc_dec/pgp_rw.h"
  #include "mechs/mech.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#ifdef USE_INT_CMS

/* Get information on an ASN.1 object.  This can be one of the following:

	RecipientInfo ::= CHOICE {
		keyTransRI		SEQUENCE { version = 0 || 2, ... },
		keyAgreeRI	[1]	SEQUENCE { version = 3, ... },
		kekRI		[2]	SEQUENCE { version = 4, ... },
		passwordRI	[3]	SEQUENCE { version = 0, ... },
		otherRI		[4]	SEQUENCE { OID, data },
		rfuRI		[5..9] ...
		}

	SignerInfo ::= SEQUENCE {
		version = 1 || 3

   If we've been given a type hint we make sure that it's one of the 
   expected types, if not we use the tag and version number to distinguish
   between RecipientInfo and SignerInfo.  Note the illogical versioning, 
   this was done because it was thought useful to distinguish the record
   types until PWRI came along at which point it was reset to a sensible
   versioning process, however what this means is that it's unclear whether
   something like a new kekRI version should be 0 (since there's only been a 
   4 previously) or 5, and whether a new keyTransRI should continue from 3
   or fill the gap at 1.  For now we assume that the versioning will 
   continue at the current highest-assigned value for each type and no-op
   out objects with the next two version values rather than rejecting them
   as invalid data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getObjectInfo( INOUT_PTR STREAM *stream, 
						  OUT_PTR QUERY_INFO *queryInfo,
						  const QUERYOBJECT_TYPE objectTypeHint )
	{
	const long startPos = stell( stream );
	long version;
	int tag, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isIntegerRange( startPos ) );
	REQUIRES( isEnumRange( objectTypeHint, QUERYOBJECT ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* We always need at least MIN_CRYPT_OBJECTSIZE more bytes to do
	   anything */
	if( sMemDataLeft( stream ) < MIN_CRYPT_OBJECTSIZE )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Get the object's length and make sure that its encoding is valid, 
	   which also checks that all of the object's data is present */
	status = getStreamObjectLength( stream, &length, 16 );
	if( cryptStatusOK( status ) )
		{
		void *objectPtr;
	
		status = sMemGetDataBlockAbs( stream, startPos, &objectPtr, length );
#ifndef CONFIG_FUZZ
		if( cryptStatusOK( status ) )
			status = checkObjectEncoding( objectPtr, length );
#endif /* CONFIG_FUZZ */
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Get the type and version information */
	queryInfo->type = CRYPT_OBJECT_NONE;
	queryInfo->size = length;
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	ANALYSER_HINT( isValidTag( tag ) );	/* Guaranteed by peekTag() */
	readGenericHole( stream, NULL, 16, tag );
	status = readShortInteger( stream, &version );
	if( cryptStatusError( status ) )
		return( status );
	if( !isIntegerRange( version ) )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->version = ( int ) version;

	/* If the caller has specified that a particular type of object is 
	   expected, make sure that it's the right type */
	if( objectTypeHint == QUERYOBJECT_KEYEX )
		{
		/* If it's a RecipientInfo then the tag must be a SEQUENCE or a 
		   context-specific tag */
		switch( tag )
			{
			case BER_SEQUENCE:
				if( version == KEYTRANS_VERSION )
					{
					queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
					queryInfo->formatType = CRYPT_FORMAT_CMS;
					break;
					}
				if( version == KEYTRANS_EX_VERSION )
					{
					queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
					queryInfo->formatType = CRYPT_FORMAT_CRYPTLIB;
					break;
					}
				if( version == KEYTRANS_EX_VERSION + 1 || \
					version == KEYTRANS_EX_VERSION + 2 )
					{
					/* Assume that it's a new type of keyTransRI and no-op 
					   out the read */
					queryInfo->optType = CRYPT_OBJECT_PKCENCRYPTED_KEY;
					break;
					}
				return( CRYPT_ERROR_BADDATA );

			case MAKE_CTAG( CTAG_RI_PASSWORD ):
				if( version == PWRI_VERSION )
					{
					queryInfo->type = CRYPT_OBJECT_ENCRYPTED_KEY;
					queryInfo->formatType = CRYPT_FORMAT_CRYPTLIB;
					break;
					}
				if( version == PWRI_VERSION + 1 || \
					version == PWRI_VERSION + 2 )
					{
					/* Assume that it's a new type of passwordRI and no-op 
					   out the read */
					queryInfo->optType = CRYPT_OBJECT_ENCRYPTED_KEY;
					break;
					}
				return( CRYPT_ERROR_BADDATA );

			case MAKE_CTAG( CTAG_RI_KEYAGREE ):
			case MAKE_CTAG( CTAG_RI_KEK ):
			case MAKE_CTAG( CTAG_RI_OTHER ):
				/* It's a known RecipientInfo type that we can't do anything 
				   with, leave it as a no-op */
				DEBUG_DIAG(( "Found un-processable RecipientInfo type %d", 
							 EXTRACT_CTAG( tag ) ));
				queryInfo->optType = CRYPT_OBJECT_PKCENCRYPTED_KEY;
				break;
			
			case MAKE_CTAG( CTAG_RI_OTHER + 1 ):
			case MAKE_CTAG( CTAG_RI_OTHER + 2 ):
			case MAKE_CTAG( CTAG_RI_OTHER + 3 ):
				/* It's an unknown RecipientInfo type, leave it as a no-op */
				DEBUG_DIAG(( "Found unknown RecipientInfo type %d", 
							 EXTRACT_CTAG( tag ) ));
				queryInfo->optType = CRYPT_OBJECT_PKCENCRYPTED_KEY;
				break;

			default:
				return( CRYPT_ERROR_BADDATA );
			}

		/* Reset the stream for the caller before we exit */
		sseek( stream, startPos );
		return( CRYPT_OK );
		}
	if( objectTypeHint == QUERYOBJECT_SIGNATURE )
		{
		/* If it's a SignerInfo then the tag must be a SEQUENCE */
		if( tag != BER_SEQUENCE )
			return( CRYPT_ERROR_BADDATA );
		switch( version )
			{
			case SIGNATURE_VERSION:
				queryInfo->type = CRYPT_OBJECT_SIGNATURE;
				queryInfo->formatType = CRYPT_FORMAT_CMS;
				break;

			case SIGNATURE_EX_VERSION:
				queryInfo->type = CRYPT_OBJECT_SIGNATURE;
				queryInfo->formatType = CRYPT_FORMAT_CRYPTLIB;
				break;
				
			case SIGNATURE_EX_VERSION + 1:
			case SIGNATURE_EX_VERSION + 2:
				{
				/* Assume that it's a new type of SignerInfo and no-op out 
				   the read */
				queryInfo->optType = CRYPT_OBJECT_SIGNATURE;
				break;
				}

			default:
				return( CRYPT_ERROR_BADDATA );
			}

		/* Reset the stream for the caller before we exit */
		sseek( stream, startPos );
		return( CRYPT_OK );
		}

	/* We don't know what we're supposed to be seeing, dig into the content 
	   to try and find out.  Unlike the object types with hints where we 
	   convert unknown types to no-ops to allow processing to continue since 
	   it'll be coming from data in an envelope with more objects present, 
	   we reject anything that we can't process since it'll be a standalone 
	   object passed in by the user */
	if( tag != BER_SEQUENCE && tag != MAKE_CTAG( CTAG_RI_PASSWORD ) )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->formatType = CRYPT_FORMAT_CRYPTLIB;
	if( tag == BER_SEQUENCE )
		{
		/* This could be a SignedInfo or a KeyTransRecipientInfo, see what 
		   follows */
		switch( version )
			{
			case KEYTRANS_VERSION:
				queryInfo->formatType = CRYPT_FORMAT_CMS;
				STDC_FALLTHROUGH;
			case KEYTRANS_EX_VERSION:
				queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
				break;

			case SIGNATURE_VERSION:
				queryInfo->formatType = CRYPT_FORMAT_CMS;
				STDC_FALLTHROUGH;
			case SIGNATURE_EX_VERSION:
				queryInfo->type = CRYPT_OBJECT_SIGNATURE;
				break;

			default:
				return( CRYPT_ERROR_BADDATA );
			}
		}
	else
		{
		/* It's PasswordRecipientInfo */
		if( version != PWRI_VERSION )
			return( CRYPT_ERROR_BADDATA );
		queryInfo->type = CRYPT_OBJECT_ENCRYPTED_KEY;
		}

	/* Reset the stream for the caller before we exit */
	sseek( stream, startPos );
	return( CRYPT_OK );
	}
#endif /* USE_INT_CMS */

#ifdef USE_PGP

/* Get information on a PGP data object.  This doesn't reset the stream like
   the ASN.1 equivalent because the PGP header is complex enough that it
   can't be read inline like the ASN.1 header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getPgpPacketInfo( INOUT_PTR STREAM *stream, 
					  OUT_PTR QUERY_INFO *queryInfo,
					  const QUERYOBJECT_TYPE objectTypeHint )
	{
	const long startPos = stell( stream );
	long length;
	int ctb, version, offset, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isIntegerRange( startPos ) );
	REQUIRES( isEnumRange( objectTypeHint, QUERYOBJECT ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the packet header and extract information from the CTB.  There 
	   are two places to stash version numbers, the PGP 2.x vs. OpenPGP flag 
	   in the CTB and then the actual packet version which may be different 
	   from the CTB version, for example some OpenPGP implementations use 
	   PGP 2.x CTBs to contain OpenPGP packets.  To deal with this we 
	   initially set the version based on the CTB but then override it if 
	   the packet version indicates an OpenPGP packet */
	status = pgpReadPacketHeader( stream, &ctb, &length, 8, 
								  MAX_INTLENGTH - 1 );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->type = CRYPT_OBJECT_NONE;
	queryInfo->formatType = CRYPT_FORMAT_PGP;
	queryInfo->version = pgpGetPacketVersion( ctb );
	status = calculateStreamObjectLength( stream, startPos, &offset );
	if( cryptStatusError( status ) )
		return( status );
	if( checkOverflowAdd( offset, length ) )
		return( CRYPT_ERROR_OVERFLOW );
	queryInfo->size = offset + length;
	status = version = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	length--;		/* We've skipped the version number */

	/* If the caller has specified that a particular type of object is 
	   expected, make sure that it's the right type */
	if( objectTypeHint == QUERYOBJECT_KEYEX )
		{
		switch( pgpGetPacketType( ctb ) )
			{
			case PGP_PACKET_SKE:
				if( version == PGP_VERSION_OPENPGP )
					{
					queryInfo->type = CRYPT_OBJECT_ENCRYPTED_KEY;
					queryInfo->version = PGP_VERSION_OPENPGP;
					break;
					}
				if( version == PGP_VERSION_OPENPGP + 1 || \
					version == PGP_VERSION_OPENPGP + 2 )
					{
					/* Assume that it's a new type of SKE packet and no-op 
					   out the read */
					queryInfo->optType = CRYPT_OBJECT_ENCRYPTED_KEY;
					break;
					}
				return( CRYPT_ERROR_BADDATA );

			case PGP_PACKET_PKE:
				/* In this case the OpenPGP version is version 3, not the 
				   expected VERSION_OPENPGP */
				if( version == PGP_VERSION_2 )
					{
					queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
					break;
					}
				if( version == PGP_VERSION_3 )
					{
					queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
					queryInfo->version = PGP_VERSION_OPENPGP;
					break;
					}
				if( version == PGP_VERSION_3 + 1 || \
					version == PGP_VERSION_3 + 2 )
					{
					/* Assume that it's a new type of PKE packet and no-op 
					   out the read */
					queryInfo->optType = CRYPT_OBJECT_PKCENCRYPTED_KEY;
					break;
					}
				return( CRYPT_ERROR_BADDATA );

			default:
				return( CRYPT_ERROR_BADDATA );
			}

		/* Make sure that all of the data is present without resetting the 
		   stream */
		return( ( sMemDataLeft( stream ) < length ) ? \
				CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
		}
	if( objectTypeHint == QUERYOBJECT_SIGNATURE )
		{
		switch( pgpGetPacketType( ctb ) )
			{
			case PGP_PACKET_SIGNATURE:
				if( version == PGP_VERSION_3 )
					{
					queryInfo->type = CRYPT_OBJECT_SIGNATURE;
					break;
					}
				if( version == PGP_VERSION_OPENPGP )
					{
					queryInfo->type = CRYPT_OBJECT_SIGNATURE;
					queryInfo->version = PGP_VERSION_OPENPGP;
					break;
					}
				if( version == PGP_VERSION_OPENPGP + 1 || \
					version == PGP_VERSION_OPENPGP + 2 )
					{
					/* Assume that it's a new type of signature packet and 
					   no-op out the read */
					queryInfo->optType = CRYPT_OBJECT_SIGNATURE;
					break;
					}
				return( CRYPT_ERROR_BADDATA );

			case PGP_PACKET_SIGNATURE_ONEPASS:
				/* First half of a one-pass signature, this is given a 
				   special type since it's not a normal packet.  In this 
				   case the OpenPGP version is version 3, not the expected 
				   VERSION_OPENPGP.
			   
				   Unlike the PKE, SKE, and signature packets we fail if we 
				   find an unrecognised version since this isn't something 
				   that we can skip */
				if( version == PGP_VERSION_3 )
					{
					queryInfo->type = CRYPT_OBJECT_LAST;
					queryInfo->version = PGP_VERSION_OPENPGP;
					break;
					}
				return( CRYPT_ERROR_BADDATA );

			default:
				return( CRYPT_ERROR_BADDATA );
			}

		/* Make sure that all of the data is present without resetting the 
		   stream */
		return( ( sMemDataLeft( stream ) < length ) ? \
				CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
		}

	/* We don't know what we're supposed to be seeing, dig into the content 
	   to try and find out.  Unlike the object types with hints where we 
	   convert unknown types to no-ops to allow processing to continue since 
	   it'll be coming from data in an envelope with more objects present, 
	   we reject anything that we can't process since it'll be a standalone 
	   object passed in by the user */
	switch( pgpGetPacketType( ctb ) )
		{
		case PGP_PACKET_SKE:
			if( version == PGP_VERSION_OPENPGP )
				{
				queryInfo->type = CRYPT_OBJECT_ENCRYPTED_KEY;
				queryInfo->version = PGP_VERSION_OPENPGP;
				break;
				}
			return( CRYPT_ERROR_BADDATA );

		case PGP_PACKET_PKE:
			/* In this case the OpenPGP version is version 3, not the 
			   expected VERSION_OPENPGP */
			if( version == PGP_VERSION_2 )
				{
				queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
				break;
				}
			if( version == PGP_VERSION_3 )
				{
				queryInfo->type = CRYPT_OBJECT_PKCENCRYPTED_KEY;
				queryInfo->version = PGP_VERSION_OPENPGP;
				break;
				}
			return( CRYPT_ERROR_BADDATA );

		case PGP_PACKET_SIGNATURE:
			if( version == PGP_VERSION_3 )
				{
				queryInfo->type = CRYPT_OBJECT_SIGNATURE;
				break;
				}
			if( version == PGP_VERSION_OPENPGP )
				{
				queryInfo->type = CRYPT_OBJECT_SIGNATURE;
				queryInfo->version = PGP_VERSION_OPENPGP;
				break;
				}
			return( CRYPT_ERROR_BADDATA );

		default:
			DEBUG_DIAG(( "Found unrecognised ctb %X", ctb ));
			assert( DEBUG_WARN );
			return( CRYPT_ERROR_BADDATA );
		}

	/* Make sure that all of the data is present without resetting the 
	   stream */
	return( ( sMemDataLeft( stream ) < length ) ? \
			CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*								Object Query Routines						*
*																			*
****************************************************************************/

#ifdef USE_INT_CMS

/* Low-level object query functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int queryAsn1Object( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr, 
					 OUT_PTR QUERY_INFO *queryInfo,
					 const QUERYOBJECT_TYPE objectTypeHint )
	{
	QUERY_INFO basicQueryInfo;
	STREAM *stream = streamPtr;
	const long startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isIntegerRange( startPos ) );
	REQUIRES( isEnumRange( objectTypeHint, QUERYOBJECT ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Determine basic object information.  This also verifies that all of 
	   the object data is present in the stream, and, if an objectTypeHint
	   is given, that we've been fed the correct type of object  */
	status = getObjectInfo( stream, &basicQueryInfo, objectTypeHint );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( basicQueryInfo.type != CRYPT_OBJECT_NONE || \
			 basicQueryInfo.optType != CRYPT_OBJECT_NONE );

	/* Call the appropriate routine to find out more about the object */
	switch( basicQueryInfo.type )
		{
		case CRYPT_OBJECT_ENCRYPTED_KEY:
			{
			const READKEK_FUNCTION readKekFunction = \
									getReadKekFunction( KEYEX_CMS );

			if( readKekFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readKekFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_PKCENCRYPTED_KEY:
			{
			const READKEYTRANS_FUNCTION readKeytransFunction = \
				getReadKeytransFunction( ( basicQueryInfo.formatType == CRYPT_FORMAT_CMS ) ? \
										 KEYEX_CMS : KEYEX_CRYPTLIB );

			if( readKeytransFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readKeytransFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_SIGNATURE:
			{
			const READSIG_FUNCTION readSigFunction = \
				getReadSigFunction( ( basicQueryInfo.formatType == CRYPT_FORMAT_CMS ) ? \
									SIGNATURE_CMS : SIGNATURE_CRYPTLIB );

			if( readSigFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readSigFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_NONE:
			/* New, unrecognised object type */
			status = readUniversal( stream );
			break;

		default:
			retIntError();
		}
	if( cryptStatusOK( status ) && \
		startPos + basicQueryInfo.size != stell( stream ) )
		{
		/* Make sure that the given size of the object matches what we've 
		   actually processed */
		status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		{
		zeroise( queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}
	sseek( stream, startPos );

	/* Augment the per-object query information with the basic query 
	   information that we got earlier */
	queryInfo->formatType = basicQueryInfo.formatType;
	queryInfo->type = basicQueryInfo.type;
	queryInfo->optType = basicQueryInfo.optType;
	queryInfo->size = basicQueryInfo.size;
	queryInfo->version = basicQueryInfo.version;

	return( CRYPT_OK );
	}
#endif /* USE_INT_CMS */

#ifdef USE_PGP

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int queryPgpObject( INOUT_PTR TYPECAST( STREAM * ) struct ST *streamPtr, 
					OUT_PTR QUERY_INFO *queryInfo,
					const QUERYOBJECT_TYPE objectTypeHint )
	{
	QUERY_INFO basicQueryInfo;
	STREAM *stream = streamPtr;
	const long startPos = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES( isIntegerRange( startPos ) );
	REQUIRES( isEnumRange( objectTypeHint, QUERYOBJECT ) );

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Determine basic object information.  This also verifies that all of 
	   the object data is present in the stream and, if an objectTypeHint
	   is given, that we've been fed the correct type of object */
	status = getPgpPacketInfo( stream, &basicQueryInfo, objectTypeHint );
	sseek( stream, startPos );
	if( cryptStatusError( status ) )
		return( status );
	ENSURES( basicQueryInfo.type != CRYPT_OBJECT_NONE || \
			 basicQueryInfo.optType != CRYPT_OBJECT_NONE );

	/* Call the appropriate routine to find out more about the object */
	switch( basicQueryInfo.type )
		{
		case CRYPT_OBJECT_ENCRYPTED_KEY:
			{
			const READKEK_FUNCTION readKekFunction = \
									getReadKekFunction( KEYEX_PGP );

			if( readKekFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readKekFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_PKCENCRYPTED_KEY:
			{
			const READKEYTRANS_FUNCTION readKeytransFunction = \
									getReadKeytransFunction( KEYEX_PGP );

			if( readKeytransFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readKeytransFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_SIGNATURE:
			{
			const READSIG_FUNCTION readSigFunction = \
									getReadSigFunction( SIGNATURE_PGP );

			if( readSigFunction == NULL )
				return( CRYPT_ERROR_NOTAVAIL );
			status = readSigFunction( stream, queryInfo );
			break;
			}

		case CRYPT_OBJECT_LAST:
			/* First half of a one-pass signature */
			status = readPgpOnepassSigPacket( stream, queryInfo );
			break;

		case CRYPT_OBJECT_NONE:
			/* New, unrecognised object type */
			status = sSkip( stream, ( int ) basicQueryInfo.size, 
							MAX_INTLENGTH_SHORT );
			break;

		default:
			retIntError();
		}
	if( cryptStatusOK( status ) && \
		startPos + basicQueryInfo.size != stell( stream ) )
		{
		/* Make sure that the given size of the object matches what we've 
		   actually processed */
		status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		{
		zeroise( queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}
	sseek( stream, startPos );

	/* Augment the per-object query information with the basic query 
	   information that we got earlier */
	queryInfo->formatType = basicQueryInfo.formatType;
	if( queryInfo->type == CRYPT_OBJECT_LAST )
		{
		/* The non-type CRYPT_OBJECT_LAST denotes the first half of a one-
		   pass signature packet, in which case the actual type is given in
		   the packet data */
		queryInfo->type = basicQueryInfo.type;
		}
	queryInfo->optType = basicQueryInfo.optType;
	queryInfo->size = basicQueryInfo.size;
	if( queryInfo->version == 0 )
		{
		/* PGP has multiple packet version numbers sprayed all over the
		   place, and just because an outer version is X doesn't mean that
		   a subsequent inner version can't be Y.  The information is really
		   only used to control the formatting of what gets read, so we
		   just report the first version that we encounter */
		queryInfo->version = basicQueryInfo.version;
		}

	return( CRYPT_OK );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*						External Object Query Interface						*
*																			*
****************************************************************************/

#if defined( USE_INT_CMS ) || defined( USE_PGP )

/* Query an object.  This is just a wrapper that provides an external
   interface for the lower-level object-query routines */

C_CHECK_RETVAL C_NONNULL_ARG( ( 1, 3 ) ) \
C_RET cryptQueryObject( C_IN void C_PTR objectData,
						C_IN int objectDataLength,
						C_OUT CRYPT_OBJECT_INFO C_PTR cryptObjectInfo )
	{
	QUERY_INFO queryInfo DUMMY_INIT_STRUCT;	/* If USE_PGP undef'd */
	STREAM stream;
	int value, length = objectDataLength, status;

	/* Perform basic error checking and clear the return value */
	if( objectDataLength < MIN_CRYPT_OBJECTSIZE || \
		objectDataLength >= MAX_BUFFER_SIZE )
		return( CRYPT_ERROR_PARAM2 );
	if( !isReadPtrDynamic( objectData, objectDataLength ) )
		return( CRYPT_ERROR_PARAM1 );
	if( !isWritePtr( cryptObjectInfo, sizeof( CRYPT_OBJECT_INFO ) ) )
		return( CRYPT_ERROR_PARAM3 );
	memset( cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Query the object.  This is just a wrapper for the lower-level object-
	   query functions.  Note that we use sPeek() rather than peekTag() 
	   because we want to continue processing (or at least checking for) PGP 
	   data if it's no ASN.1 */
	sMemConnect( &stream, ( void * ) objectData, length );
	status = value = sPeek( &stream );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( value == BER_SEQUENCE || value == MAKE_CTAG( CTAG_RI_PASSWORD ) )
		{
		status = queryAsn1Object( &stream, &queryInfo, 
								  QUERYOBJECT_UNKNOWN );
		}
	else
		{
#ifdef USE_PGP
		status = queryPgpObject( &stream, &queryInfo, 
								 QUERYOBJECT_UNKNOWN );
#else
		status = CRYPT_ERROR_BADDATA;
#endif /* USE_PGP */
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Copy the externally-visible fields across */
	cryptObjectInfo->objectType = queryInfo.type;
	cryptObjectInfo->cryptAlgo = queryInfo.cryptAlgo;
	cryptObjectInfo->cryptMode = queryInfo.cryptMode;
	if( queryInfo.type == CRYPT_OBJECT_SIGNATURE )
		cryptObjectInfo->hashAlgo = queryInfo.hashAlgo;
	if( queryInfo.type == CRYPT_OBJECT_ENCRYPTED_KEY && \
		queryInfo.saltLength > 0 )
		{
		REQUIRES( rangeCheck( queryInfo.saltLength, 1, 
							  CRYPT_MAX_HASHSIZE ) );
		memcpy( cryptObjectInfo->salt, queryInfo.salt, 
				queryInfo.saltLength );
		cryptObjectInfo->saltSize = queryInfo.saltLength;
		cryptObjectInfo->iterations = queryInfo.keySetupIterations;
		if( queryInfo.keySetupAlgo != CRYPT_ALGO_NONE )
			cryptObjectInfo->hashAlgo = queryInfo.keySetupAlgo;
		}

	return( CRYPT_OK );
	}

#else

/****************************************************************************
*																			*
*						Stub Functions for non-CMS/PGP Use					*
*																			*
****************************************************************************/

C_RET cryptQueryObject( C_IN void C_PTR objectData,
						C_IN int objectDataLength,
						C_OUT CRYPT_OBJECT_INFO C_PTR cryptObjectInfo )
	{
	UNUSED_ARG( objectData );
	UNUSED_ARG( cryptObjectInfo );

	return( CRYPT_ERROR_NOTAVAIL );
	}
#endif /* USE_INT_CMS || USE_PGP */
