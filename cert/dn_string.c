/****************************************************************************
*																			*
*							Certificate String Routines						*
*						Copyright Peter Gutmann 1996-2020					*
*																			*
****************************************************************************/

#include <ctype.h>
#if defined( INC_ALL )
  #include "cert.h"
  #include "dn.h"
  #include "misc_rw.h"
#else
  #include "cert/cert.h"
  #include "cert/dn.h"
  #include "enc_dec/misc_rw.h"
#endif /* Compiler-specific includes */

/* The character set (or at least ASN.1 string type) for a string.  Although 
   IA5String and VisibleString/ISO646String are technically different the 
   only real difference is that IA5String allows the full range of control 
   characters, which isn't notably useful.  For this reason we treat both as 
   ISO646String.
   
   Occasionally we can be fed Unicode strings that are just bloated versions 
   of another string type, something that Windows likes doing.  We account 
   for these by converting them to the underlying non-Unicode string type.

   UTF-8 strings are a pain because they're only intermittently supported as 
   a native format outside of Unix systems, and in particular incredibly
   difficult to work with under Windows despite being nominally supported.  
   Although the use of UTF-8 was required after the cutover date of December 
   2003, by unspoken unanimous consensus of implementers everywhere 
   implementations stuck with the existing DN encoding to avoid breaking 
   things for at least another fifteen years after that.  However as of 2020
   it seems safe to assume that for exotic character types UTF-8 is more 
   likely to be supported than Unicode so on non-Windows systems we convert
   DN strings to UTF-8 if required while on Windows systems we convert them 
   to a local character set (ASCII, 8859-1, or Unicode as appropriate) when 
   we read them to make them usable.
   
   In terms of writing strings, on non-UTF-8 systems we write as ASCII, 
   8859-1, or Unicode as required.  On UTF-8 systems we write as ASCII or 
   UTF-8 as required */

typedef enum {
	ASN1_STRING_NONE,					/* No string type */

	/* 8-bit string types */
	ASN1_STRING_PRINTABLE,				/* PrintableString */
	ASN1_STRING_IA5,					/* IA5String */
	ASN1_STRING_T61,					/* T61 (8859-1) string */

	/* 8-bit types masquerading as Unicode */
	ASN1_STRING_UNICODE_PRINTABLE,		/* PrintableString as Unicode */
	ASN1_STRING_UNICODE_IA5,			/* IA5String as Unicode */
	ASN1_STRING_UNICODE_T61,			/* 8859-1 as Unicode */

	/* 8-bit native character string (e.g. eastern European latin-2 or 
	   Windows CP 1251) that needs to be converted to UTF-8 / Unicode.  
	   These options are valid for strings originating from the local 
	   system */
#ifdef USE_UTF8
	ASN1_STRING_TO_UTF8,				/* 8-bit string needing conversion */
#else
	ASN1_STRING_TO_UNICODE,				/* 8-bit string needing conversion */
#endif /* USE_UTF8 */

	/* Unicode/UTF-8 */
	ASN1_STRING_UNICODE,				/* Unicode string */
	ASN1_STRING_UTF8,					/* UTF-8 string */

	/* Special-case error string types.  ASN1_STRING_ERROR_TRY_UTF8 / 
	   ASN1_STRING_ERROR_TRY_UNICODE tells the caller to try converting from 
	   a system-native 8-bit character set type to UTF-8 / Unicode before 
	   reporting an error in case this is some oddball 8-bit character set 
	   that the local system understands but that isn't equivalent to any 
	   ASN.1 string type.  If the string type can be converted to UTF-8 / 
	   Unicode it's then reported as ASN1_STRING_TO_UTF8 / 
	   ASN1_STRING_TO_UNICODE */
	ASN1_STRING_ERROR,					/* Error occurred during processing */
#ifdef USE_UTF8
	ASN1_STRING_ERROR_TRY_UTF8,			/* Try converting to UTF-8 */
#else
	ASN1_STRING_ERROR_TRY_UNICODE,		/* Try converting to Unicode */
#endif /* USE_UTF8 */

	ASN1_STRING_LAST					/* Last possible string type */
	} ASN1_STRING_TYPE;

#ifdef USE_UTF8
  #define isErrorStringType( stringType ) \
		  ( ( stringType ) == ASN1_STRING_ERROR_TRY_UTF8 || \
			( stringType ) == ASN1_STRING_ERROR )
#else
  #define isErrorStringType( stringType ) \
		  ( ( stringType ) == ASN1_STRING_ERROR_TRY_UNICODE || \
			( stringType ) == ASN1_STRING_ERROR )
#endif /* USE_UTF8 */

/* The native character set type when we're converting to UTF-8 */

typedef enum {
	NATIVE_CHAR_NONE,					/* No native character set type */
	NATIVE_CHAR_8BIT,					/* 7/8-bit string */
	NATIVE_CHAR_MBS,					/* Multibyte string */
	NATIVE_CHAR_WIDECHAR,				/* Widechar string */
	NATIVE_CHAR_LAST					/* Last possible character set type */
	} NATIVE_CHAR_TYPE;

/* The size of a BMPString character, which we need to convert to/from a 
   widechar or UTF-8 */

#define BMPCHAR_SIZE	2

#ifdef USE_CERTIFICATES

/****************************************************************************
*																			*
*						Character Set Management Functions					*
*																			*
****************************************************************************/

/* Because of the bizarre (and mostly useless) collection of ASN.1 character
   types we need to be very careful about what we allow in a string.  The
   following table is used to determine whether a character is valid within 
   a given string type.

   Although IA5String and VisibleString/ISO646String are technically
   different the only real difference is that IA5String allows the full 
   range of control characters, which isn't notably useful.  For this reason 
   we treat both as ISO646String */

#define P	1						/* PrintableString */
#define I	2						/* IA5String/VisibleString/ISO646String */
#define PI	( P | I )				/* PrintableString and IA5String */

static const int asn1CharFlags[] = {
	/* 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F */
		0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	/* 10  11  12  13  14  15  16  17  18  19  1A  1B  1C  1D  1E  1F */
		0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	/*		!	"	#	$	%	&	'	(	)	*	+	,	-	.	/ */
	   PI,	I,	I,	I,	I,	I,	I, PI, PI, PI,	I, PI, PI, PI, PI, PI,
	/*	0	1	2	3	4	5	6	7	8	9	:	;	<	=	>	? */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I, PI,	I, PI,
	/*	@	A	B	C	D	E	F	G	H	I	J	K	L	M	N	O */
		I, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,
	/*	P	Q	R	S	T	U	V	W	X	Y	Z	[	\	]	^	_ */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I,	I,	I,	I,
	/*	`	a	b	c	d	e	f	g	h	i	j	k	l	m	n	o */
		I, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,
	/*	p	q	r	s	t	u	v	w	x	y	z	{	|	}	~  DL */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I,	I,	I,	0,
		0, 0	/* Catch overflows */
	};

#define nativeCharFlags	asn1CharFlags

/* Check that a text string contains valid characters for its string type.
   This is used in non-DN strings where only a very restrictive subset of 
   string types are allowed */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN isValidASN1TextString( IN_BUFFER( stringLen ) const char *string, 
							   IN_LENGTH_SHORT const int stringLen,
							   IN_BOOL const BOOLEAN isPrintableString )
	{
	const int charTypeMask = isPrintableString ? P : I;
	LOOP_INDEX i;

	assert( isReadPtrDynamic( string, stringLen ) );

	REQUIRES_B( isShortIntegerRangeNZ( stringLen ) );
	REQUIRES_B( isBooleanValue( isPrintableString ) );

	LOOP_LARGE( i = 0, i < stringLen, i++ )
		{
		int ch;

		ENSURES_B( LOOP_INVARIANT_LARGE( i, 0, stringLen - 1 ) );

		ch = byteToInt( string[ i ] );
		if( !isValidTextChar( ch ) )
			return( FALSE );
		if( !( nativeCharFlags[ ch ] & charTypeMask ) )
			return( FALSE );
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( TRUE );
	}

/* Extract a widechar from a string.  Note that if WCHAR_SIZE/
   sizeof( wchar_t ) is larger than 16 bits and we're fed a non-Unicode 
   string or malformed data then the return value can become larger than 
   what's indicated in the CHECK_RETVAL_RANGE() statement, but the calling 
   code checks for this so it's mostly a slightly misleading static-analysis 
   annotation */

#ifdef USE_WIDECHARS

CHECK_RETVAL_RANGE_NOERROR( 0, 0xFFFFL ) STDC_NONNULL_ARG( ( 1 ) ) \
static wchar_t getWidechar( IN_BUFFER_C( WCHAR_SIZE ) const BYTE *string )
	{
	wchar_t ch = 0;
#ifdef DATA_LITTLEENDIAN
	int shiftAmt = 0;
#endif /* DATA_LITTLEENDIAN */
	LOOP_INDEX i;

	assert( isReadPtr( string, WCHAR_SIZE ) );
	
	/* Since we're reading wchar_t-sized values from a char-aligned source, 
	   we have to assemble the data a byte at a time to handle systems where 
	   non-char values can only be accessed on word-aligned boundaries */
	LOOP_SMALL( i = 0, i < WCHAR_SIZE, i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_SMALL( i, 0, WCHAR_SIZE - 1 ), 0 );

#ifdef DATA_LITTLEENDIAN
		ch |= string[ i ] << shiftAmt;
		shiftAmt += 8;
#else
		ch = ( ch << 8 ) | string[ i ];
#endif /* DATA_LITTLEENDIAN */
		}
	ENSURES_EXT( LOOP_BOUND_OK, 0 );

	/* There's a special complication if wchar_t is a signed type, in which 
	   case it can end up negative if the first byte of the string has its 
	   high bit set.  To deal with this we need to trim the return value 
	   down to size.  This takes advantage of the fact that WCHAR_MAX is 
	   always given as a bit mask, e.g. 0x7FFFFFFF for a 32-bit wchar_t */
	if( ch < 0 )
		ch &= WCHAR_MAX;

	return( ch );
	}
#endif /* USE_WIDECHARS */

/****************************************************************************
*																			*
*					String-type Identification Functions					*
*																			*
****************************************************************************/

/* Forward declaration for UTF-8 function */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int checkUtf8String( IN_BUFFER( stringLen ) const void *string, 
							IN_LENGTH_SHORT const int stringLen,
							OUT_LENGTH_Z int *noChars,
							OUT_ENUM_OPT( ASN1_STRING ) \
									ASN1_STRING_TYPE *asn1StringType );

/* Try and guess whether a native string is a widechar string */

#ifdef USE_WIDECHARS

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN isNativeWidecharString( IN_BUFFER( stringLen ) const BYTE *string, 
									   IN_LENGTH_SHORT_MIN( 2 ) const int stringLen )
	{
	wchar_t wCh;
#if WCHAR_MAX <= 0xFFFFL
	LOOP_INDEX i;
	int hiByte = 0;
#endif /* 16-bit wchar_t */

	assert( isReadPtrDynamic( string, stringLen ) );

	REQUIRES_B( isShortIntegerRangeMin( stringLen, WCHAR_SIZE ) );
	REQUIRES_B( !( stringLen % WCHAR_SIZE ) );

	/* Look at the first character in the string */
	wCh = getWidechar( string );

	/* If wchar_t is > 16 bits and the bits above 16 are set or all zero,
	   it's either definitely not Unicode or Unicode, c.f. "abcd" = 
	   { 0x61, 0x62, 0x63, 0x64 } vs. L"a" = { 0x00, 0x00, 0x00, 0x61 }.  

	   Note that some compilers will complain of unreachable code here, 
	   unfortunately we can't easily fix this since WCHAR_SIZE is usually an 
	   expression involving sizeof() which can't be handled via the 
	   preprocessor so we have to guard it with a preprocessor check */
#if WCHAR_MAX > 0xFFFFL
	return( ( wCh > 0xFFFFL ) ? FALSE : TRUE );
#else
	/* wchar_t is 16 bits, make sure that we don't get false positives with 
	   short strings.  Two-character strings are more likely to be ASCII 
	   than a single widechar, and repeated alternate characters (e.g. 
	   "tanaka") in an ASCII string appear to be widechars for the general-
	   purpose check below so we check for these in strings of 2-3 wide 
	   characters before we perform the general-purpose check */
	if( stringLen <= ( WCHAR_SIZE * 3 ) && wCh > 0xFF )
		{
		if( stringLen == WCHAR_SIZE )	/* WCHAR_SIZE == 2 */
			{
			const int ch1 = string[ 0 ];
			const int ch2 = string[ 1 ];

			/* Check for a two-character ASCII string, usually a country 
			   name */
			if( isValidTextChar( ch1 ) && isValidTextChar( ch2 ) )
				return( FALSE );
			}
		else
			{
			int hi1, hi2, hi3;

			ENSURES_B( stringLen == ( WCHAR_SIZE * 2 ) || \
					   stringLen == ( WCHAR_SIZE * 3 ) );

			/* Check for alternate characters being ASCII.  This detects 
			   strings like the "tanaka" example given above, which on a
			   Windows system, pretty much the only one with 16-bit
			   widechars, would be read as 'at', 'an', 'ak'.

			   Note that the shift and use of byteToInt() are valid here 
			   because getWidechar() can only return a value in the range 
			   ( 0...0xFFFF ) because WCHAR_SIZE == 2.  It can't, for 
			   example, return a negative status value */
			hi1 = hi3 = byteToInt( wCh >> 8 );
			hi2 = byteToInt( getWidechar( string + WCHAR_SIZE ) >> 8 );
			if( stringLen > WCHAR_SIZE * 2 )
				{
				hi3 = byteToInt( \
						getWidechar( string + ( WCHAR_SIZE * 2 ) ) >> 8 );
				}
			if( isAlnum( hi1 ) && isAlnum( hi2 ) && isAlnum( hi3 ) && \
				hi1 == hi2 && hi2 == hi3 )
				return( FALSE );
			}
		}

	/* Check whether the string is in the form { 00 xx }* or{ AA|00 xx }*, 
	   either ASCII-as-Unicode or Unicode.  The code used below is safe 
	   because to get to this point the string has to be some multiple of 2 
	   bytes long.  Note that if someone passes in a 1-byte string and 
	   mistakenly includes the terminator in the length then it'll be 
	   identified as a 16-bit widechar string but this doesn't really matter 
	   since it'll get "converted" into a non-widechar string later */
	LOOP_LARGE( i = 0, i < stringLen, i += WCHAR_SIZE )
		{
		ENSURES_B( LOOP_INVARIANT_LARGE_XXX( i, 0, stringLen - WCHAR_SIZE ) );

		wCh = getWidechar( &string[ i ] );
		if( wCh > 0xFF )
			{
			const int wChHi = byteToInt( wCh >> 8 );

			ENSURES_B( wChHi );

			/* If we haven't already seen a high byte, remember it */
			if( hiByte == 0 )
				hiByte = wChHi;
			else
				{
				/* If the current high byte doesn't match the previous one,
				   it's probably 8-bit characters */
				if( wChHi != hiByte )
					return( FALSE );
				}
			}
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( TRUE );				/* Probably 16-bit characters */
#endif /* 32- vs 16-bit wchar_t */ 
	}
#endif /* USE_WIDECHARS */

/* Try and figure out the true string type for an ASN.1 or native string.  
   This detects (or at least tries to detect) not only the basic string type 
   but also basic string types encoded as widechar strings and widechar 
   strings encoded as basic string types.

   All of these functions work by checking for the most restrictive ASN.1
   string subset that'll still contain the string, progressively widening
   from PrintableString -> IA5String -> T61(8859-1)String -> UTF-8 /
   BMP(Unicode)String, reporting an error if even a UTF-8 / Unicode string 
   can't contain the value.  It's up to the caller to decide whether they 
   want to encode e.g. a T61String as such or re-encode it as UTF-8.

   We continue processing the string even when we've reached the least-
   constraining value (UTF-8 / Unicode) because we still need to check 
   whether all of the characters in the string are actually valid before we 
   exit */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int get8bitStringType( IN_BUFFER( stringLen ) const BYTE *string,
							  IN_LENGTH_SHORT const int stringLen,
							  IN_TAG_ENCODED const int stringTag,
							  OUT_ENUM_OPT( ASN1_STRING ) \
										ASN1_STRING_TYPE *asn1StringType )
	{
	BOOLEAN isIA5 = FALSE, isT61 = FALSE;
	LOOP_INDEX i;
	int status;

	assert( isReadPtrDynamic( string, stringLen ) );
	assert( isWritePtr( asn1StringType, sizeof( ASN1_STRING_TYPE ) ) );

	REQUIRES( isShortIntegerRangeNZ( stringLen ) );
	REQUIRES( stringTag >= BER_STRING_UTF8 && stringTag < BER_STRING_BMP );

	/* Clear return value */
	*asn1StringType = ASN1_STRING_NONE;

	/* Walk down the string checking each character */
	LOOP_LARGE( i = 0, i < stringLen, i++ )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_LARGE( i, 0, stringLen - 1 ) );

		/* If the high bit is set then it's not an ASCII subset */
		ch = byteToInt( string[ i ] );
		if( ch >= 128 )
			{
			isT61 = TRUE;
			if( asn1CharFlags[ ch & 0x7F ] )
				continue;
			}
		else
			{
			/* Check whether it's a PrintableString */
			if( !( asn1CharFlags[ ch ] & P ) )
				isIA5 = TRUE;

			/* Check whether it's something peculiar */
			if( asn1CharFlags[ ch ] )
				continue;
			}

		/* It's not 8859-1 either, check whether it's UTF-8.  We can safely 
		   do an early-out in this case because checkUtf8String() checks the 
		   entire string */
		if( stringTag == BER_STRING_UTF8 )
			{
			ASN1_STRING_TYPE dummy1;
			int dummy2;

			status = checkUtf8String( string, stringLen, &dummy2, &dummy1 );
			if( cryptStatusOK( status ) )
				{
				*asn1StringType = ASN1_STRING_UTF8;
				return( CRYPT_OK );
				}
			}

		/* This may be some native 8-bit string type that can be converted 
		   to UTF-8 / Unicode, tell the caller to try this before reporting 
		   an error */
		return( OK_SPECIAL );
		}
	ENSURES( LOOP_BOUND_OK );

	*asn1StringType = isT61 ? ASN1_STRING_T61 : \
					  isIA5 ? ASN1_STRING_IA5 : \
							  ASN1_STRING_PRINTABLE;
	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int getAsn1StringType( IN_BUFFER( stringLen ) const BYTE *string, 
							  IN_LENGTH_SHORT const int stringLen, 
							  IN_TAG_ENCODED const int stringTag,
							  OUT_ENUM_OPT( ASN1_STRING ) \
										ASN1_STRING_TYPE *asn1StringType )
	{
	STREAM stream;
	BOOLEAN isIA5 = FALSE, isT61 = FALSE, isUnicode = FALSE;
	LOOP_INDEX length;
	int status = CRYPT_OK;

	assert( isReadPtrDynamic( string, stringLen ) );
	assert( isWritePtr( asn1StringType, sizeof( ASN1_STRING_TYPE ) ) );

	REQUIRES( isShortIntegerRangeNZ( stringLen ) );
	REQUIRES( stringTag >= BER_STRING_UTF8 && \
			  stringTag <= BER_STRING_BMP );

	/* Clear return value */
	*asn1StringType = ASN1_STRING_NONE;

	/* If it's not a Unicode string, determine the 8-bit string type */
	if( stringTag != BER_STRING_BMP )
		{
		/* get8bitStringType() may return OK_SPECIAL to indicate that this
		   appears to be some oddball native 8-bit string type that might
		   be usable via mbstowcs() or similar, however in this case it's 
		   coming from an ASN.1 string and so should be in a recognised
		   format, so we convert OK_SPECIAL to CRYPT_ERROR_BADDATA */
		status = get8bitStringType( string, stringLen, stringTag, 
									asn1StringType );
		return( ( status == OK_SPECIAL ) ? CRYPT_ERROR_BADDATA : status );
		}

	/* If it's not a multiple of BMPCHAR_SIZE in size then it can't really 
	   be Unicode either */
	if( stringLen % BMPCHAR_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* If the first character isn't a null then it's definitely a Unicode
	   string.  These strings are always big-endian, even coming from 
	   Microsoft software, so we don't have to check for a null as the 
	   second character */
	if( string[ 0 ] != '\0' )
		{
		*asn1StringType = ASN1_STRING_UNICODE;
		return( CRYPT_OK );
		}

	/* Check whether it's an 8-bit string encoded as a BMPString */
	sMemConnect( &stream, string, stringLen );
	LOOP_LARGE( length = 0, length < stringLen, length += BMPCHAR_SIZE )
		{
		int ch;

		ENSURES( LOOP_INVARIANT_LARGE_XXX( length, 0, \
										   stringLen - BMPCHAR_SIZE ) );
		
		status = ch = readUint16( &stream );
		if( cryptStatusError( status ) )
			break;

		/* If it's not an 8-bit value then it's a pure Unicode string */
		if( ch > 0xFF )
			{
			isUnicode = TRUE;
			continue;
			}

		/* If the high bit is set then it's not an ASCII subset */
		if( ch >= 0x80 )
			{
			isT61 = TRUE;
			continue;
			}

		/* Check whether it's a PrintableString */
		if( !( asn1CharFlags[ ch ] & P ) )
			isIA5 = TRUE;
		}
	ENSURES( LOOP_BOUND_OK );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	*asn1StringType = isUnicode ? ASN1_STRING_UNICODE : \
					  isT61 ? ASN1_STRING_UNICODE_T61 : \
					  isIA5 ? ASN1_STRING_UNICODE_IA5 : \
							  ASN1_STRING_UNICODE_PRINTABLE;
	return( CRYPT_OK );
	}

#ifdef USE_WIDECHARS

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int getNativeStringType( IN_BUFFER( stringLen ) const BYTE *string, 
								IN_LENGTH_SHORT const int stringLen,
								OUT_ENUM_OPT( ASN1_STRING ) \
										ASN1_STRING_TYPE *asn1StringType )
	{
	BOOLEAN isIA5 = FALSE, isT61 = FALSE, isUnicode = FALSE;
	LOOP_INDEX i;

	assert( isReadPtrDynamic( string, stringLen ) );
	assert( isWritePtr( asn1StringType, sizeof( ASN1_STRING_TYPE ) ) );

	REQUIRES( isShortIntegerRangeNZ( stringLen ) );

	/* Clear return value */
	*asn1StringType = ASN1_STRING_NONE;

	/* If it's not a widechar string, handle it as a basic 8-bit string 
	   type */
	if( stringLen < WCHAR_SIZE || ( stringLen % WCHAR_SIZE ) != 0 || \
		!isNativeWidecharString( string, stringLen ) )
		{
#ifdef USE_UTF8
		return( get8bitStringType( string, stringLen, BER_STRING_UTF8, 
								   asn1StringType ) );
#else
		return( get8bitStringType( string, stringLen, BER_STRING_T61, 
								   asn1StringType ) );
#endif /* USE_UTF8 */
		}

	/* It's a widechar string, although it may actually be something else 
	   that's been bloated out into widechars so we check for this as well */
	LOOP_LARGE( i = 0, i < stringLen, i += WCHAR_SIZE )
		{
		wchar_t wCh;

		ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, stringLen - WCHAR_SIZE ) );

		/* Make sure that we've got a character from a Unicode (BMP) string.  
		   This check can be triggered if WCHAR_SIZE > 2 and the caller 
		   feeds us a binary garbage string so that the resulting decoded 
		   widechar value is larger than 16 bits */
		wCh = getWidechar( &string[ i ] );
		if( wCh < 0 || ( wCh & 0xFFFF0000L ) )
			return( CRYPT_ERROR_BADDATA );

		/* If the high bit is set then it's not an ASCII subset */
		if( wCh >= 0x80 )
			{
			/* If it's larger than 8 bits then it's definitely Unicode */
			if( wCh >= 0xFF )
				{
				isUnicode = TRUE;
				continue;
				}

			/* Check which (if any) 8-bit type it could be */
			isT61 = TRUE;
			if( nativeCharFlags[ wCh & 0x7F ] )
				continue;

			/* It's not 8859-1 either, or more specifically it's something 
			   that ends up looking like a control character.  What to do at 
			   this point is a bit uncertain but making it a generic Unicode 
			   string which'll be handled via somewhat more robust 
			   mechanisms than something presumed to be ASCII or close to it 
			   is probably safer than storing it as a what's probably a 
			   control character */
			isUnicode = TRUE;

			continue;
			}

		/* Check whether it's a PrintableString */
		if( !( nativeCharFlags[ wCh ] & P ) )
			isIA5 = TRUE;
		}
	ENSURES_EXT( LOOP_BOUND_OK, ASN1_STRING_ERROR );

	*asn1StringType = isUnicode ? ASN1_STRING_UNICODE : \
					  isT61 ? ASN1_STRING_UNICODE_T61 : \
					  isIA5 ? ASN1_STRING_UNICODE_IA5 : \
							  ASN1_STRING_UNICODE_PRINTABLE;
	return( CRYPT_OK );
	}
#else

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int getNativeStringType( IN_BUFFER( stringLen ) const BYTE *string, 
								IN_LENGTH_SHORT const int stringLen,
								OUT_ENUM_OPT( ASN1_STRING ) \
										ASN1_STRING_TYPE *asn1StringType )
	{
	assert( isReadPtrDynamic( string, stringLen ) );
	assert( isWritePtr( asn1StringType, sizeof( ASN1_STRING_TYPE ) ) );

	REQUIRES( isShortIntegerRangeNZ( stringLen ) );

	return( get8bitStringType( string, stringLen, BER_STRING_UTF8, 
							   asn1StringType ) );
	}
#endif /* USE_WIDECHARS */

/****************************************************************************
*																			*
*								UTF-8 Functions								*
*																			*
****************************************************************************/

/* Parse one UTF-8 encoded character from a string, enforcing the UTF-8 
   canonical-encoding rules:

	  00 -  7F = 0xxxxxxx, mask = 0x80
	 80 -  7FF = 110xxxxx 10xxxxxx, mask = 0xE0
	800 - FFFF = 1110xxxx 10xxxxxx 10xxxxxx, mask = 0xF0

   The awkward encoding is a modification of the original FSS-UTF 
   (filesystem-safe UTF) which used the same variable-bit prefix but a one-
   bit header on each subsequent bytes, still redundant but less so than the
   final UTF-8, which added even more redundancy to make it self-
   synchronising since it's possible to detect byte sequence boundaries 
   starting from any arbitrary byte.  Whether anything actually cares about
   this is another matter.

   Note that some of the checks and masking applied below are redundant 
   and/or tautological but due to the powerful nature of UTF-8 string 
   formatting attacks we apply them anyway to make the different checking 
   actions explicit and to reduce the chances of a coding error that allows 
   something dangerous to slip through.  This also complies with the UTF-8
   standard's requirement to "treat ill-formed code unit sequences as an 
   error condition and shall not interpret such sequences as characters"
   (Unicode standard, section 3.2, clause C10) */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getUTF8Char( INOUT_PTR STREAM *stream, 
						long *utf8char )
	{
	long largeCh;
	int firstChar, secondChar, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( utf8char, sizeof( long ) ) );

	/* Clear return value */
	*utf8char = 0;

	/* Process the first character */
	status = firstChar = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( !( firstChar & 0x80 ) )
		{
		/* 1-byte character, straight ASCII */
		*utf8char = firstChar & 0x7F;
		return( 1 );	/* Single-byte char */
		}
	if( ( firstChar & 0xC0 ) == 0x80 )		/* 11xxxxxx -> 10xxxxxx */
		return( CRYPT_ERROR_BADDATA );

	/* Process the second character */
	status = secondChar = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( ( firstChar & 0xE0 ) == 0xC0 )		/* 111xxxxx -> 110xxxxx */
		{
		/* 2-byte character in the range 0x80...0x7FF */
		if( ( secondChar & 0xC0 ) != 0x80 )
			return( CRYPT_ERROR_BADDATA );
		largeCh = ( ( firstChar & 0x1F ) << 6 ) | \
					( secondChar & 0x3F );
		if( largeCh < 0x80 || largeCh > 0x7FF )
			return( CRYPT_ERROR_BADDATA );
		*utf8char = largeCh & 0x7FF;
		return( 2 );	/* Two-byte char */
		}

	/* Process any further characters */
	if( ( firstChar & 0xF0 ) == 0xE0 )		/* 1111xxxx -> 1110xxxx */
		{
		int thirdChar;
		
		status = thirdChar = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );

		/* 3-byte character in the range 0x800...0xFFFF */
		if( ( secondChar & 0xC0 ) != 0x80 || \
			( thirdChar & 0xC0 ) != 0x80 )
			return( CRYPT_ERROR_BADDATA );
		largeCh = ( ( firstChar & 0x1F ) << 12 ) | \
				  ( ( secondChar & 0x3F ) << 6 ) | \
					( thirdChar & 0x3F );
		if( largeCh < 0x800 || largeCh > 0xFFFFL )
			return( CRYPT_ERROR_BADDATA );
		*utf8char = largeCh & 0xFFFFL;
		return( 3 );	/* Three-byte char */
		}

	/* In theory we can also get 4- and 5-byte encodings but this is far 
	   more likely to be invalid data than a genuine attempt to represent 
	   something in Tsolyani or Reformed Styrian */
	return( CRYPT_ERROR_BADDATA );
	}

#ifdef USE_UTF8

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int putUTF8Char( INOUT_PTR STREAM *stream, 
						IN_RANGE( 0, 0xFFFFL ) const long largeCh )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( largeCh >= 0 && largeCh <= 0xFFFFL );

	if( largeCh < 0x80 )
		return( sputc( stream, ( BYTE ) largeCh ) );
	if( largeCh < 0x0800 )
		{
		sputc( stream, ( BYTE )( 0xC0 | ( ( largeCh >> 6 ) & 0x1F ) ) );
		return( sputc( stream, ( BYTE )( 0x80 | ( largeCh & 0x3F ) ) ) );
		}
	sputc( stream, ( BYTE )( 0xE0 | ( ( largeCh >> 12 ) & 0x0F ) ) );
	sputc( stream, ( BYTE )( 0x80 | ( ( largeCh >> 6 ) & 0x3F ) ) );
	return( sputc( stream, ( BYTE )( 0x80 | ( largeCh & 0x3F ) ) ) );
	}

/* Write a string as UTF-8 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeUTF8String( INOUT_PTR STREAM *stream,
							IN_BUFFER( sourceLen ) const void *source, 
							IN_LENGTH_SHORT const int sourceLen,
							IN_ENUM( NATIVE_CHAR ) \
								const NATIVE_CHAR_TYPE nativeCharType )
	{
	mbstate_t mbState;
	const BYTE *srcPtr = source;
	LOOP_INDEX i;
	int status = CRYPT_OK;

	assert( isWritePtrDynamic( stream, sizeof( STREAM ) ) );
	assert( isReadPtrDynamic( source, sourceLen ) );

	REQUIRES( isShortIntegerRangeNZ( sourceLen ) );
	REQUIRES( isEnumRange( nativeCharType, NATIVE_CHAR ) );

	memset( &mbState, 0, sizeof( mbstate_t ) );
  
	/* Copy the characters across, converting to UTF-8 as we go.  In 
	   commemoration of classic non-thread-safe functions like strtok(), the 
	   C99 standards committee also made the standard mbtowc() non-thread-
	   safe by allowing it to be called with a null second argument to 
	   initialise the internal shift state for state-dependent encodings, we 
	   use mbrtowc() to deal with this */
	LOOP_LARGE_INITCHECK( i = 0, i < sourceLen )
		{
		wchar_t wCh;
		int count;

		ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, sourceLen - 1 ) );

		switch( nativeCharType )
			{
			case NATIVE_CHAR_8BIT:
				/* 7/8-bit string */
				wCh = srcPtr[ i++ ];
				break;

			case NATIVE_CHAR_MBS:
				/* Multibyte string */
				count = mbrtowc( &wCh, srcPtr + i, sourceLen - i, 
								 &mbState );
				if( count <= 0 )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				i += count;
				break;

			case NATIVE_CHAR_WIDECHAR:
				/* Widechar string */
				wCh = getWidechar( &srcPtr[ i ] );
				i += WCHAR_SIZE;
				break;

			default:
				retIntError();
			}
		if( cryptStatusOK( status ) )
			status = putUTF8Char( stream, wCh );
		if( cryptStatusError( status ) )
			break;
		}
	ENSURES( LOOP_BOUND_OK );

	return( status );
	}

/* Determine the length of a string once it's encoded as UTF-8 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int utf8TargetStringLen( IN_BUFFER( stringLen ) const BYTE *string, 
								IN_LENGTH_SHORT const int stringLen,
								OUT_LENGTH_SHORT_Z int *targetStringLength,
								IN_ENUM( NATIVE_CHAR ) \
									const NATIVE_CHAR_TYPE nativeCharType )
	{
	STREAM stream;
	int status;

	assert( isReadPtrDynamic( string, stringLen ) );
	assert( isWritePtr( targetStringLength, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeNZ( stringLen ) );
	REQUIRES( isEnumRange( nativeCharType, NATIVE_CHAR ) );

	/* Clear return value */
	*targetStringLength = 0;

	sMemNullOpen( &stream );
	status = writeUTF8String( &stream, string, stringLen, nativeCharType );
	if( cryptStatusOK( status ) )
		*targetStringLength = stell( &stream );
	sMemClose( &stream );

	return( status );
	}
#endif /* USE_UTF8 */

/* Check that a UTF-8 string has a valid encoding and determine what it can 
   be converted to, meaning the widest character type in it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int checkUtf8String( IN_BUFFER( stringLen ) const void *string, 
							IN_LENGTH_SHORT const int stringLen,
							OUT_LENGTH_Z int *noChars,
							OUT_ENUM_OPT( ASN1_STRING ) \
									ASN1_STRING_TYPE *asn1StringType )
	{
	STREAM stream;
	ASN1_STRING_TYPE stringType = ASN1_STRING_PRINTABLE;
	int charCount = 0, i, status DUMMY_INIT, LOOP_ITERATOR;

	assert( isReadPtrDynamic( string, stringLen ) );
	assert( isWritePtr( noChars, sizeof( int ) ) );
	assert( isWritePtr( asn1StringType, sizeof( ASN1_STRING_TYPE ) ) );

	REQUIRES( isShortIntegerRangeNZ( stringLen ) );

	/* Clear return values */
	*noChars = 0;
	*asn1StringType = ASN1_STRING_NONE;

	/* Scan the string making sure that there are no malformed characters */
	sMemConnect( &stream, string, stringLen );
	LOOP_LARGE_INITCHECK( i = 0, i < stringLen )
		{
		long largeCh;
		int charLen;

		ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, stringLen - 1 ) );

		/* Get the next character from it's possibly multibyte UTF-8 
		   encoding */
		status = charLen = getUTF8Char( &stream, &largeCh );
		if( cryptStatusError( status ) )
			break;
		i += charLen;
		charCount++;

		/* If it's not a 7-bit value and if the system can handle UTF-8, 
		   it's UTF-8 */
#ifdef USE_UTF8
		if( largeCh >= 128 )
			stringType = ASN1_STRING_UTF8;
#else
		/* If we've already identified the widest character type then 
		   there's nothing more to do */
		if( stringType == ASN1_STRING_UNICODE )
			continue;

		/* If it's not an 8-bit value then it can only be Unicode */
		if( largeCh > 0xFF )
			{
			stringType = ASN1_STRING_UNICODE;
			continue;
			}

		/* If it's not a PrintableString character mark it as T61 if it's 
		   within range, otherwise it's Unicode */
		if( largeCh >= 128 )
			{
			stringType = ( asn1CharFlags[ largeCh & 0x7F ] & P ) ? \
						 ASN1_STRING_T61 : ASN1_STRING_UNICODE;
			}
#endif /* USE_UTF8 */
		}
	ENSURES( LOOP_BOUND_OK );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	*noChars = charCount;
	*asn1StringType = stringType;
	return( CRYPT_OK );
	}

/* Convert to and from UTF-8 strings.  On UTF-8 systems we convert native or 
   ASN.1 strings to UTF-8, on non-UTF-8 systems we convert ASN.1 UTF-8 
   strings to the native format */

#ifdef USE_UTF8

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int copyNativeToUTF8String( OUT_BUFFER( destMaxLen, *destLen ) \
										void *dest, 
								   IN_LENGTH_SHORT const int destMaxLen, 
								   OUT_LENGTH_BOUNDED_Z( destMaxLen ) \
										int *destLen, 
								   IN_BUFFER( sourceLen ) const void *source, 
								   IN_LENGTH_SHORT const int sourceLen,
								   IN_ENUM( NATIVE_CHAR ) \
										const NATIVE_CHAR_TYPE nativeCharType )
	{
	STREAM stream;
	int status;

	assert( isWritePtrDynamic( dest, destMaxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( source, sourceLen ) );

	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) );
	REQUIRES( isShortIntegerRangeNZ( sourceLen ) );
	REQUIRES( isEnumRange( nativeCharType, NATIVE_CHAR ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) ); 
	memset( dest, 0, min( 16, destMaxLen ) );
	*destLen = 0;

	/* Copy the characters across, converting to UTF-8 as we go */
	sMemOpen( &stream, dest, destMaxLen );
	status = writeUTF8String( &stream, source, sourceLen, nativeCharType );
	if( cryptStatusOK( status ) )
		*destLen = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int copyASN1ToUTF8String( OUT_BUFFER( destMaxLen, *destLen ) \
									void *dest, 
								 IN_LENGTH_SHORT const int destMaxLen, 
								 OUT_LENGTH_BOUNDED_Z( destMaxLen ) \
									int *destLen,
								 IN_BUFFER( sourceLen ) const void *source, 
								 IN_LENGTH_SHORT const int sourceLen,
								 IN_BOOL const BOOLEAN isBMPChar )
	{
	STREAM stream;
	LOOP_INDEX i;
	int status DUMMY_INIT;

	assert( isWritePtrDynamic( dest, destMaxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( source, sourceLen ) );

	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) );
	REQUIRES( isShortIntegerRangeNZ( sourceLen ) );
	REQUIRES( isBooleanValue( isBMPChar ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) ); 
	memset( dest, 0, min( 16, destMaxLen ) );
	*destLen = 0;

	/* Copy an 8-bit or Unicode string to a UTF-8 string.  We don't need to
	   perform any special-case handling for different source string types 
	   because putUTF8Char() takes care of everything for us */
	sMemOpen( &stream, dest, destMaxLen );
	if( isBMPChar )
		{
		STREAM srcStream;

		sMemConnect( &srcStream, source, sourceLen );
		LOOP_LARGE( i = 0, i < sourceLen, i += BMPCHAR_SIZE )
			{
			int wCh;

			ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, \
											   sourceLen - BMPCHAR_SIZE ) );
			
			status = wCh = readUint16( &srcStream );
			if( !cryptStatusError( status ) )
				status = putUTF8Char( &stream, wCh );
			if( cryptStatusError( status ) )
				break;
			}
		ENSURES( LOOP_BOUND_OK );
		sMemDisconnect( &srcStream );
		}
	else
		{
		status = writeUTF8String( &stream, source, sourceLen, 
								  NATIVE_CHAR_8BIT );
		}
	if( cryptStatusOK( status ) )
		*destLen = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}
#else

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
static int copyUTF8ToNativeString( OUT_BUFFER( destMaxLen, *destLen ) \
										void *dest, 
								   IN_LENGTH_SHORT const int destMaxLen, 
								   OUT_LENGTH_BOUNDED_Z( destMaxLen ) \
										int *destLen, 
								   OUT_RANGE( 0, 20 ) int *destStringType,
								   IN_BUFFER( sourceLen ) const void *source, 
								   IN_LENGTH_SHORT const int sourceLen )
	{
	STREAM stream;
	ASN1_STRING_TYPE stringType;
	wchar_t *wcDestPtr = dest;
	BYTE *destPtr = dest;
	LOOP_INDEX i;
	int noChars, status;

	assert( isWritePtrDynamic( dest, destMaxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isWritePtr( destStringType, sizeof( int ) ) );
	assert( isReadPtrDynamic( source, sourceLen ) );

	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) );
	REQUIRES( isShortIntegerRangeNZ( sourceLen ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) ); 
	memset( dest, 0, min( 16, destMaxLen ) );
	*destLen = 0;
	*destStringType = ASN1_STRING_NONE;

	/* Scan the string and determine what native type it can be converted 
	   to */
	status = checkUtf8String( source, sourceLen, &noChars, &stringType );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the translated string will fit into the destination 
	   buffer */
	*destLen = noChars * ( ( stringType == ASN1_STRING_UNICODE ) ? \
						   WCHAR_SIZE : 1 );
	if( *destLen < 0 || *destLen > destMaxLen )
		return( CRYPT_ERROR_OVERFLOW );
	*destStringType = stringType;

	/* Copy the UTF-8 string across, converting the characters as 
	   required */
	sMemConnect( &stream, source, sourceLen );
	LOOP_LARGE_INITCHECK( i = 0, i < sourceLen )
		{
		long largeCh;
		int charLen;

		ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, sourceLen - 1 ) );

		/* Get the next string character.  We shouldn't get an error at this
		   point since we've already run over it to get type information */
		status = charLen = getUTF8Char( &stream, &largeCh );
		ENSURES( !cryptStatusError( status ) );
		i += charLen;

		/* Copy the result as a Unicode or ASCII/8859-1 character.  We know 
		   that largeCh will fit in a wchar_t because it's been checked by
		   getUTF8Char() */
		if( stringType == ASN1_STRING_UNICODE )
			*wcDestPtr++ = ( wchar_t ) largeCh;
		else
			*destPtr++ = ( BYTE ) largeCh;
		}
	ENSURES( LOOP_BOUND_OK );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}
#endif /* USE_UTF8 */

/****************************************************************************
*																			*
*						ASN.1 String Conversion Functions					*
*																			*
****************************************************************************/

/* Determine type information for a string when it's encoded for use with 
   ASN.1.  The 'stringType' value doesn't have any meaning outside this 
   module, it's merely used as a cookie to pass back to other functions 
   here, for which it's an ASN1_STRING_TYPE */

#ifdef USE_UTF8

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
int getAsn1StringInfo( IN_BUFFER( stringLen ) const void *string, 
					   IN_LENGTH_SHORT const int stringLen,
					   OUT_RANGE( 0, 20 ) int *stringType, 
					   OUT_TAG_ENCODED_Z int *asn1StringType,
					   OUT_LENGTH_SHORT_Z int *asn1StringLen,
					   IN_BOOL const BOOLEAN isNativeString )
	{
	ASN1_STRING_TYPE localStringType;
	int status;

	assert( isReadPtrDynamic( string, stringLen ) );
	assert( isWritePtr( stringType, sizeof( int ) ) );
	assert( isWritePtr( asn1StringType, sizeof( int ) ) );
	assert( isWritePtr( asn1StringLen, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeNZ( stringLen ) );
	REQUIRES( isBooleanValue( isNativeString ) );

	/* Clear return values */
	*stringType = ASN1_STRING_NONE;
	*asn1StringType = BER_NULL;
	*asn1StringLen = 0;

	/* Get the native string type as an ASN.1-equivalent string type */
	status = getNativeStringType( string, stringLen, &localStringType );
	if( cryptStatusError( status ) )
		{
		size_t mbStringLen;
		int result;

		/* If it's not a native string or we're not being told to try re-
		   encoding as UTF-8, report an error */
		if( !isNativeString || status != OK_SPECIAL )
			return( CRYPT_ERROR_BADDATA );
		
		/* It's some oddball 8-bit local character type that's not 8859-1 or
		   UTF-8 but that might be convertible into UTF-8, check whether 
		   this is the case */
		result = mbstowcs_s( &mbStringLen, NULL, 0, string, stringLen );
		if( result != 0 || mbStringLen <= 0 || mbStringLen > stringLen )
			return( CRYPT_ERROR_BADDATA );

		/* It's a valid native 8-bit character string, report it as 
		   something that needs to be converted to UTF-8.  It's not clear 
		   that any string would ever reach this point since on systems that 
		   use UTF-8 it'd be in UTF-8 anyway, for now we warn in debug 
		   mode */
		assert( DEBUG_WARN );
		*stringType = ASN1_STRING_TO_UTF8;
		status = utf8TargetStringLen( string, stringLen, asn1StringLen, 
									  NATIVE_CHAR_MBS );
		if( cryptStatusError( status ) )
			return( status );
		*asn1StringType = BER_STRING_UTF8;

		return( CRYPT_OK );
		}

	/* Remember the string type */
	*stringType = localStringType;

	/* Handle Unicode strings, either actual Unicode or an 8-bit string 
	   masquerading as Unicode */
	switch( localStringType )
		{
		case ASN1_STRING_UNICODE:
		case ASN1_STRING_UNICODE_T61:
			/* It's a native widechar string, the output is UTF-8 */
			status = utf8TargetStringLen( string, stringLen, asn1StringLen, 
										  NATIVE_CHAR_WIDECHAR );
			if( cryptStatusError( status ) )
				return( status );
			*asn1StringType = BER_STRING_UTF8;
			return( CRYPT_OK );

		case ASN1_STRING_UNICODE_PRINTABLE:
		case ASN1_STRING_UNICODE_IA5:
			/* It's an ASCII string masquerading as a native widechar 
			   string, output is an 8-bit string type */
			*asn1StringType = \
					( localStringType == ASN1_STRING_UNICODE_PRINTABLE ) ? \
						BER_STRING_PRINTABLE : BER_STRING_IA5;
			*asn1StringLen = stringLen / WCHAR_SIZE;
			return( CRYPT_OK );

		case ASN1_STRING_UTF8:
			/* It's a UTF-8 string (getNativeStringType() has already 
			   checked its validity) */
			*asn1StringType = BER_STRING_UTF8;
			*asn1StringLen = stringLen;
			return( CRYPT_OK );
		}

	/* It's an ASCII or T61/latin1 string */
	ENSURES( ( localStringType == ASN1_STRING_PRINTABLE ) || \
			 ( localStringType == ASN1_STRING_IA5 ) || \
			 ( localStringType == ASN1_STRING_T61 ) );
	if( localStringType == ASN1_STRING_T61 )
		{
		status = utf8TargetStringLen( string, stringLen, asn1StringLen, 
									  NATIVE_CHAR_8BIT );
		if( cryptStatusError( status ) )
			return( status );
		*asn1StringType = BER_STRING_UTF8;
		}
	else
		{
		*asn1StringType = ( localStringType == ASN1_STRING_PRINTABLE ) ? \
							BER_STRING_PRINTABLE : BER_STRING_IA5;
		*asn1StringLen = stringLen;
		}

	return( CRYPT_OK );
	}
#else

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
int getAsn1StringInfo( IN_BUFFER( stringLen ) const void *string, 
					   IN_LENGTH_SHORT const int stringLen,
					   OUT_RANGE( 0, 20 ) int *stringType, 
					   OUT_TAG_ENCODED_Z int *asn1StringType,
					   OUT_LENGTH_SHORT_Z int *asn1StringLen,
					   IN_BOOL const BOOLEAN isNativeString )
	{
	ASN1_STRING_TYPE localStringType;
	int status;

	assert( isReadPtrDynamic( string, stringLen ) );
	assert( isWritePtr( stringType, sizeof( int ) ) );
	assert( isWritePtr( asn1StringType, sizeof( int ) ) );
	assert( isWritePtr( asn1StringLen, sizeof( int ) ) );

	REQUIRES( isShortIntegerRangeNZ( stringLen ) );
	REQUIRES( isBooleanValue( isNativeString ) );

	/* Clear return values */
	*stringType = ASN1_STRING_NONE;
	*asn1StringType = BER_NULL;
	*asn1StringLen = 0;

	/* Get the native string type as an ASN.1-equivalent string type */
	status = getNativeStringType( string, stringLen, &localStringType );
	if( cryptStatusError( status ) )
		{
		size_t mbStringLen;
		int result;

		/* If it's not a native string or we're not being told to try re-
		   encoding as Unicode, report an error */
		if( !isNativeString || status != OK_SPECIAL )
			return( CRYPT_ERROR_BADDATA );
		
		/* It's some oddball 8-bit local character type that's not 8859-1 or
		   Unicode but that might be convertible into Unicode, check whether 
		   this is the case */
		result = mbstowcs_s( &mbStringLen, NULL, 0, string, stringLen );
		if( result != 0 || mbStringLen <= 0 || mbStringLen > stringLen )
			return( CRYPT_ERROR_BADDATA );

		/* It's a valid native 8-bit character string, report it as 
		   something that needs to be converted to UTF-8 / Unicode */
		*stringType = ASN1_STRING_TO_UNICODE;
		*asn1StringType = BER_STRING_BMP;
		*asn1StringLen = mbStringLen * BMPCHAR_SIZE;

		return( CRYPT_OK );
		}

	/* Remember the string type */
	*stringType = localStringType;

	/* Handle Unicode strings, either actual Unicode or an 8-bit string 
	   masquerading as Unicode */
	switch( localStringType )
		{
		case ASN1_STRING_UNICODE:
			/* It's a native widechar string, the output is Unicode 
			   (BMPString) */
			*asn1StringType = BER_STRING_BMP;
			*asn1StringLen = ( stringLen / WCHAR_SIZE ) * BMPCHAR_SIZE;
			return( CRYPT_OK );

		case ASN1_STRING_UNICODE_PRINTABLE:
		case ASN1_STRING_UNICODE_IA5:
		case ASN1_STRING_UNICODE_T61:
			/* It's an ASCII string masquerading as a native widechar 
			   string, output is an 8-bit string type */
			*asn1StringType = \
					( localStringType == ASN1_STRING_UNICODE_PRINTABLE ) ? \
						BER_STRING_PRINTABLE : \
					( localStringType == ASN1_STRING_UNICODE_IA5 ) ? \
						BER_STRING_IA5 : BER_STRING_T61;
			*asn1StringLen = stringLen / WCHAR_SIZE;
			return( CRYPT_OK );

		case ASN1_STRING_UTF8:
			/* It's an already-encoded UTF-8 string (getNativeStringType() 
			   has already checked its validity) */
			*asn1StringType = BER_STRING_UTF8;
			*asn1StringLen = stringLen;
			return( CRYPT_OK );
		}

	/* It's an ASCII or T61/latin1 string */
	ENSURES( ( localStringType == ASN1_STRING_PRINTABLE ) || \
			 ( localStringType == ASN1_STRING_IA5 ) || \
			 ( localStringType == ASN1_STRING_T61 ) );
	*asn1StringType = ( localStringType == ASN1_STRING_PRINTABLE ) ? \
						BER_STRING_PRINTABLE : \
					  ( localStringType == ASN1_STRING_IA5 ) ? \
						BER_STRING_IA5 : BER_STRING_T61;
	*asn1StringLen = stringLen;

	return( CRYPT_OK );
	}
#endif /* USE_UTF8 */

/* Convert a character string from the ASN.1 format into the native format */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
int copyFromAsn1String( OUT_BUFFER( destMaxLen, *destLen ) void *dest, 
						IN_LENGTH_SHORT const int destMaxLen, 
						OUT_LENGTH_BOUNDED_Z( destMaxLen ) int *destLen, 
						OUT_RANGE( 0, 20 ) int *destStringType,
						IN_BUFFER( sourceLen ) const void *source, 
						IN_LENGTH_SHORT const int sourceLen,
						IN_TAG_ENCODED const int stringTag )
	{
	ASN1_STRING_TYPE stringType;
	int status;

	assert( isWritePtrDynamic( dest, destMaxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isWritePtr( destStringType, sizeof( int ) ) );
	assert( isReadPtrDynamic( source, sourceLen ) );

	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) );
	REQUIRES( isShortIntegerRangeNZ( sourceLen ) );
	REQUIRES( stringTag >= BER_STRING_UTF8 && stringTag <= BER_STRING_BMP );

	/* Clear return values */
	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) ); 
	memset( dest, 0, min( 16, destMaxLen ) );
	*destLen = 0;
	*destStringType = ASN1_STRING_NONE;

	/* Get the equivalent ASN.1 string type */
	status = getAsn1StringType( source, sourceLen, stringTag, &stringType );
	if( cryptStatusError( status ) )
		return( status );

	/* If the system supports UTF-8 then the conversion process is 
	   relatively simple, if it's non-7-bit and not already in UTF-8 form 
	   then write it as a UTF-8 string, otherwise copy it directly across */
#ifdef USE_UTF8
	if( stringType == ASN1_STRING_UNICODE || \
		stringType == ASN1_STRING_UNICODE_PRINTABLE || \
		stringType == ASN1_STRING_UNICODE_IA5 || \
		stringType == ASN1_STRING_UNICODE_T61 || \
		stringType == ASN1_STRING_T61 )
		{
		status = copyASN1ToUTF8String( dest, destMaxLen, destLen, source, 
									   sourceLen, 
									   ( stringType != ASN1_STRING_T61 ) ? \
										 TRUE : FALSE );
		if( cryptStatusError( status ) )
			return( status );
		*destStringType = ( stringType == ASN1_STRING_UNICODE_PRINTABLE ) ? \
							ASN1_STRING_PRINTABLE : \
						  ( stringType == ASN1_STRING_UNICODE_IA5 ) ? \
							ASN1_STRING_IA5 : ASN1_STRING_UTF8;

		return( CRYPT_OK );
		}

	/* What's left are 8-bit string types.  We can copy a UTF-8 string 
	   across as is since it's already been checked by getAsn1StringType() */
	ENSURES( stringType == ASN1_STRING_PRINTABLE || \
			 stringType == ASN1_STRING_IA5 || \
			 stringType == ASN1_STRING_UTF8 );
#else
	/* The system doesn't support UTF-8, convert to widechars, 8859-1, or
	   7-bit text as required.

	   If it's a BMPString, convert it to the native format */
	if( stringType == ASN1_STRING_UNICODE )
		{
		STREAM stream;
		wchar_t *wcDestPtr = ( wchar_t * ) dest;
		const int newLen = ( sourceLen / BMPCHAR_SIZE ) * WCHAR_SIZE;
		LOOP_INDEX i;

		if( newLen <= 0 || newLen > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		
		sMemConnect( &stream, source, sourceLen );
		LOOP_LARGE( i = 0, i < sourceLen, i += BMPCHAR_SIZE )
			{
			int wCh;

			ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, \
											   sourceLen - BMPCHAR_SIZE ) );
			
			status = wCh = readUint16( &stream );
			if( cryptStatusError( status ) )
				break;
			*wcDestPtr++ = ( wchar_t ) wCh;
			}
		ENSURES( LOOP_BOUND_OK );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		*destLen = newLen;
		*destStringType = ASN1_STRING_UNICODE;
		return( CRYPT_OK );
		}
	if( stringType == ASN1_STRING_UNICODE_PRINTABLE || \
		stringType == ASN1_STRING_UNICODE_IA5 || \
		stringType == ASN1_STRING_UNICODE_T61 )
		{
		STREAM stream;
		BYTE *destPtr = dest;
		const int newLen = sourceLen / BMPCHAR_SIZE;
		LOOP_INDEX i;

		if( newLen <= 0 || newLen > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );

		/* It's something masquerading as Unicode, convert it to the 
		   narrower format.  We can safely truncate to an 8-bit value 
		   because getAsn1StringType() has checked this for us */
		sMemConnect( &stream, source, sourceLen );
		LOOP_LARGE( i = 0, i < sourceLen, i += BMPCHAR_SIZE )
			{
			int wCh;

			ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, \
											   sourceLen - BMPCHAR_SIZE ) );
			
			status = wCh = readUint16( &stream );
			if( !cryptStatusError( status ) && ( wCh > 0xFF ) )
				{
				/* Should never happen because of the pre-scan that we've 
				   done earlier */
				status = CRYPT_ERROR_BADDATA;
				}
			if( cryptStatusError( status ) )
				break;
			*destPtr++ = intToByte( wCh );
			}
		ENSURES( LOOP_BOUND_OK );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		*destLen = newLen;
		*destStringType = \
					( stringType == ASN1_STRING_UNICODE_PRINTABLE ) ? \
					  ASN1_STRING_PRINTABLE : \
					( stringType == ASN1_STRING_UNICODE_IA5 ) ? \
					  ASN1_STRING_IA5 : ASN1_STRING_T61;
		return( CRYPT_OK );
		}

	/* If it's a UTF-8 string, copy it to the native format */
	if( stringTag == BER_STRING_UTF8 )
		{
		return( copyUTF8ToNativeString( dest, destMaxLen, destLen, 
										destStringType, source, 
										sourceLen ) );
		}

	/* What's left are 8-bit string types */
	ENSURES( stringType == ASN1_STRING_PRINTABLE || \
			 stringType == ASN1_STRING_IA5 || \
			 stringType == ASN1_STRING_T61 );
#endif /* USE_UTF8 */

	/* It's an 8-bit character set, just copy it across */
	if( sourceLen <= 0 || sourceLen > destMaxLen )
		return( CRYPT_ERROR_OVERFLOW );
	REQUIRES( rangeCheck( sourceLen, 1, destMaxLen ) );
	memcpy( dest, source, sourceLen );
	*destLen = sourceLen;
	*destStringType = stringType;

	return( CRYPT_OK );
	}

/* Convert a character string from the native format to the ASN.1 format */

#ifdef USE_UTF8

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int copyToAsn1String( OUT_BUFFER( destMaxLen, *destLen ) void *dest, 
					  IN_LENGTH_SHORT const int destMaxLen, 
					  OUT_LENGTH_BOUNDED_Z( destMaxLen ) int *destLen, 
					  IN_BUFFER( sourceLen ) const void *source, 
					  IN_LENGTH_SHORT const int sourceLen,
					  IN_RANGE( 1, 20 ) const int stringType )
	{
	assert( isWritePtrDynamic( dest, destMaxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( source, sourceLen ) );

	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) );
	REQUIRES( isShortIntegerRangeNZ( sourceLen ) );
	REQUIRES( isEnumRange( stringType, ASN1_STRING ) && \
			  !isErrorStringType( stringType ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) ); 
	memset( dest, 0, min( 16, destMaxLen ) );
	*destLen = 0;

	/* If it's a non-widechar string then we can just copy it across 
	   directly */
	if( stringType == ASN1_STRING_PRINTABLE || \
		stringType == ASN1_STRING_IA5 ||
		stringType == ASN1_STRING_UTF8 )
		{
		if( sourceLen > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		REQUIRES( rangeCheck( sourceLen, 1, destMaxLen ) );
		memcpy( dest, source, sourceLen );
		*destLen = sourceLen;

		return( CRYPT_OK );
		}

	/* If it's a native 8-bit, multibyte (other than UTF-8), or widechar 
	   string type, convert it to UTF-8.  See the comment in 
	   getAsn1StringInfo() for why we're unlikely to ever get 
	   ASN1_STRING_TO_UTF8 */
	return( copyNativeToUTF8String( dest, destMaxLen, destLen, 
									source, sourceLen,
									( stringType == ASN1_STRING_T61 ) ? \
										NATIVE_CHAR_8BIT : \
									( stringType == ASN1_STRING_TO_UTF8 ) ? 
										NATIVE_CHAR_MBS : \
										NATIVE_CHAR_WIDECHAR ) );
	}
#elif defined( USE_WIDECHARS )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int copyToAsn1String( OUT_BUFFER( destMaxLen, *destLen ) void *dest, 
					  IN_LENGTH_SHORT const int destMaxLen, 
					  OUT_LENGTH_BOUNDED_Z( destMaxLen ) int *destLen, 
					  IN_BUFFER( sourceLen ) const void *source, 
					  IN_LENGTH_SHORT const int sourceLen,
					  IN_RANGE( 1, 20 ) const int stringType )
	{
	STREAM stream;
	const BYTE *srcPtr = source;
	const BOOLEAN unicodeTarget = ( stringType == ASN1_STRING_UNICODE ) ? \
								  TRUE : FALSE;
	LOOP_INDEX i;
	int status = CRYPT_OK;

	assert( isWritePtrDynamic( dest, destMaxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( source, sourceLen ) );

	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) );
	REQUIRES( isShortIntegerRangeNZ( sourceLen ) );
	REQUIRES( isEnumRange( stringType, ASN1_STRING ) && \
			  !isErrorStringType( stringType ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) ); 
	memset( dest, 0, min( 16, destMaxLen ) );
	*destLen = 0;

	/* If it's a non-widechar string then we can just copy it across 
	   directly */
	if( stringType == ASN1_STRING_PRINTABLE || \
		stringType == ASN1_STRING_IA5 ||
		stringType == ASN1_STRING_T61 )
		{
		if( sourceLen > destMaxLen )
			return( CRYPT_ERROR_OVERFLOW );
		REQUIRES( rangeCheck( sourceLen, 1, destMaxLen ) );
		memcpy( dest, source, sourceLen );
		*destLen = sourceLen;

		return( CRYPT_OK );
		}

	/* If it's a native 8-bit string type, convert it to Unicode */
	if( stringType == ASN1_STRING_TO_UNICODE )
		{
		mbstate_t mbState;
		int count;

		memset( &mbState, 0, sizeof( mbstate_t ) );
  
		/* Copy the characters across, converting to BMPChars as we go.  In
		   commemoration of classic non-thread-safe functions like strtok(), 
		   the C99 standards committee also made the standard mbtowc() non-
		   thread-safe by allowing it to be called with a null second 
		   argument to initialise the internal shift state for state-
		   dependent encodings, we use mbrtowc() to deal with this */
		sMemOpen( &stream, dest, destMaxLen );
		LOOP_LARGE_INITCHECK( i = 0, i < sourceLen )
			{
			wchar_t wCh;

			ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, sourceLen - 1 ) );

			count = mbrtowc( &wCh, srcPtr + i, sourceLen - i, &mbState );
			if( count <= 0 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			i += count;
			status = writeUint16( &stream, wCh );
			if( cryptStatusError( status ) )
				break;
			}
		ENSURES( LOOP_BOUND_OK );
		if( cryptStatusOK( status ) )
			*destLen = stell( &stream );
		sMemDisconnect( &stream );

		return( status );
		}

	/* We're on a system that doesn't support UTF-8, we shouldn't be 
	   seeing UTF-8 strings */
	ENSURES( stringType != ASN1_STRING_UTF8 );

	/* It's a native widechar string, copy it across converting from wchar_t 
	   to char / Unicode as required */
	sMemOpen( &stream, dest, destMaxLen );
	LOOP_LARGE( i = 0, i < sourceLen, i += WCHAR_SIZE )
		{
		wchar_t wCh;

		ENSURES( LOOP_INVARIANT_LARGE_XXX( i, 0, sourceLen - WCHAR_SIZE ) );

		wCh = getWidechar( &srcPtr[ i ] );
		if( unicodeTarget )
			status = writeUint16( &stream, wCh );
		else
			status = sputc( &stream, intToByte( wCh ) );
		if( cryptStatusError( status ) )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	if( cryptStatusOK( status ) )
		*destLen = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

#else

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int copyToAsn1String( OUT_BUFFER( destMaxLen, *destLen ) void *dest, 
					  IN_LENGTH_SHORT const int destMaxLen, 
					  OUT_LENGTH_BOUNDED_Z( destMaxLen ) int *destLen, 
					  IN_BUFFER( sourceLen ) const void *source, 
					  IN_LENGTH_SHORT const int sourceLen,
					  IN_RANGE( 1, 20 ) const int stringType )
	{
	assert( isWritePtrDynamic( dest, destMaxLen ) );
	assert( isWritePtr( destLen, sizeof( int ) ) );
	assert( isReadPtrDynamic( source, sourceLen ) );

	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) );
	REQUIRES( isShortIntegerRangeNZ( sourceLen ) );
	REQUIRES( isEnumRange( stringType, ASN1_STRING ) && \
			  !isErrorStringType( stringType ) );

	/* Clear return value */
	REQUIRES( isShortIntegerRangeNZ( destMaxLen ) ); 
	memset( dest, 0, min( 16, destMaxLen ) );
	*destLen = 0;

	/* We don't have any widechar or UTF-8 support, the best that we can do 
	   is copy it across as is and hope the caller can do something with it */
	if( sourceLen > destMaxLen )
		return( CRYPT_ERROR_OVERFLOW );
	REQUIRES( rangeCheck( sourceLen, 1, destMaxLen ) );
	memcpy( dest, source, sourceLen );
	*destLen = sourceLen;

	return( CRYPT_OK );
	}
#endif /* USE_UTF8 / USE_WIDECHARS / None of the above */
#endif /* USE_CERTIFICATES */
