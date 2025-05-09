/****************************************************************************
*																			*
*					cryptlib OS-specific Support Routines					*
*					  Copyright Peter Gutmann 1992-2020						*
*																			*
****************************************************************************/

/* IBM mainframe builds need extra functions for EBCDIC printf() */
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #define _OPEN_SYS_ITOA_EXT
#endif /* IBM big iron debug build */

#include <ctype.h>
#include <stddef.h>					/* For ptrdiff_t */
#include <stdio.h>
#include <time.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "kernelfns.h"			/* For preInit()/postShutdown() */
#else
  #include "crypt.h"
  #include "kernel/objectfns.h"		/* For preInit()/postShutdown() */
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*									AMX										*
*																			*
****************************************************************************/

#if defined( __AMX__ )

#include <cjzzz.h>

/* The AMX task-priority function returns the priority via a reference
   parameter.  Because of this we have to provide a wrapper that returns
   it as a return value */

int threadPriority( void )
	{
	int priority = 0;

	cjtkpradjust( cjtkid(), &priority );
	return( priority );
	}

/****************************************************************************
*																			*
*									ARINC 653								*
*																			*
****************************************************************************/

#elif defined( __ARINC653__ )

#include <apex.h>

/* The ARINC 653 API returns status codes as a by-reference parameter, in 
   cases where we don't care about the return status we need to provide a
   dummy value to take this */

RETURN_CODE_TYPE dummyRetCode;

/* The ARINC 653 thread-self function returns the thread ID via a reference 
   parameter, because of this we have to provide a wrapper that returns it 
   as a return value */

PROCESS_ID_TYPE threadSelf( void )
	{
	PROCESS_ID_TYPE processID;
	RETURN_CODE_TYPE retCode; 

	GET_MY_ID( &processID, &retCode );
	return( processID );
	}

/****************************************************************************
*																			*
*									FreeRTOS								*
*																			*
****************************************************************************/

#elif defined( __FreeRTOS__ )

#include <FreeRTOS.h>

/* Check that various FreeRTOS parameters are in order.  This should be done
   by the preprocessor but FreeRTOS includes gratuitous type-casts 
   everywhere which can't be evaluated at preprocessing time so we have to 
   do it via this dummy function and static asserts.  What we're actually 
   trying to do here is:

	#if ( configTOTAL_HEAP_SIZE < 32768L )
	  #pragma message "Warning: configTOTAL_HEAP_SIZE is set to less than 32K, this will cause problems with object creation."
	#elif ( configTOTAL_HEAP_SIZE < 131072L )
	  #pragma message "Warning: configTOTAL_HEAP_SIZE is set to less than 128K, this may cause problems with object creation."
	#endif // configTOTAL_HEAP_SIZE check */

static void freeRTOSCheck( void )
	{
	static_assert( pdTRUE == pdPASS );
	static_assert( configTOTAL_HEAP_SIZE >= 32768L );
	}

/****************************************************************************
*																			*
*									uC/OS-II								*
*																			*
****************************************************************************/

#elif defined( __UCOS__ )

#undef BOOLEAN					/* See comment in kernel/thread.h */
#include <ucos_ii.h>
#define BOOLEAN			int

/* uC/OS-II doesn't have a thread-self function, but allows general task
   info to be queried.  Because of this we provide a wrapper that returns
   the task ID as its return value */

INT8U threadSelf( void )
	{
	OS_TCB osTCB;

	OSTaskQuery( OS_PRIO_SELF, &osTCB );
	return( osTCB.OSTCBPrio );
	}

/****************************************************************************
*																			*
*									uITRON									*
*																			*
****************************************************************************/

#elif defined( __ITRON__ )

#include <itron.h>

/* The uITRON thread-self function returns the thread ID via a reference
   parameter since uITRON IDs can be negative and there'd be no way to
   differentiate a thread ID from an error code.  Because of this we have
   to provide a wrapper that returns it as a return value */

ID threadSelf( void )
	{
	ID tskid;

	get_tid( &tskid );
	return( tskid );
	}

/****************************************************************************
*																			*
*								IBM Mainframe								*
*																			*
****************************************************************************/

/* VM/CMS, MVS, and AS/400 systems need to convert characters from ASCII <->
   EBCDIC before/after they're read/written to external formats, the
   following functions perform the necessary conversion using the latin-1
   code tables for systems that don't have etoa/atoe */

#elif defined( EBCDIC_CHARS )

#ifndef USE_ETOA

/* ISO 8859-1 to IBM Latin-1 Code Page 01047 (EBCDIC) */

static const BYTE asciiToEbcdicTbl[] = {
	0x00, 0x01, 0x02, 0x03, 0x37, 0x2D, 0x2E, 0x2F,	/* 00 - 07 */
	0x16, 0x05, 0x15, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	/* 08 - 0F */
	0x10, 0x11, 0x12, 0x13, 0x3C, 0x3D, 0x32, 0x26,	/* 10 - 17 */
	0x18, 0x19, 0x3F, 0x27, 0x1C, 0x1D, 0x1E, 0x1F,	/* 18 - 1F */
	0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D,	/* 20 - 27 */
	0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,	/* 28 - 2F */
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,	/* 30 - 37 */
	0xF8, 0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,	/* 38 - 3F */
	0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,	/* 40 - 47 */
	0xC8, 0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,	/* 48 - 4F */
	0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,	/* 50 - 57 */
	0xE7, 0xE8, 0xE9, 0xAD, 0xE0, 0xBD, 0x5F, 0x6D,	/* 58 - 5F */
	0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,	/* 60 - 67 */
	0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,	/* 68 - 6F */
	0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,	/* 70 - 77 */
	0xA7, 0xA8, 0xA9, 0xC0, 0x4F, 0xD0, 0xA1, 0x07,	/* 78 - 7F */
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x06, 0x17,	/* 80 - 87 */
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x09, 0x0A, 0x1B,	/* 88 - 8F */
	0x30, 0x31, 0x1A, 0x33, 0x34, 0x35, 0x36, 0x08,	/* 90 - 97 */
	0x38, 0x39, 0x3A, 0x3B, 0x04, 0x14, 0x3E, 0xFF,	/* 98 - 9F */
	0x41, 0xAA, 0x4A, 0xB1, 0x9F, 0xB2, 0x6A, 0xB5,	/* A0 - A7 */
	0xBB, 0xB4, 0x9A, 0x8A, 0xB0, 0xCA, 0xAF, 0xBC,	/* A8 - AF */
	0x90, 0x8F, 0xEA, 0xFA, 0xBE, 0xA0, 0xB6, 0xB3,	/* B0 - B7 */
	0x9D, 0xDA, 0x9B, 0x8B, 0xB7, 0xB8, 0xB9, 0xAB,	/* B8 - BF */
	0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9E, 0x68,	/* C0 - C7 */
	0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77,	/* C8 - CF */
	0xAC, 0x69, 0xED, 0xEE, 0xEB, 0xEF, 0xEC, 0xBF,	/* D0 - D7 */
	0x80, 0xFD, 0xFE, 0xFB, 0xFC, 0xBA, 0xAE, 0x59,	/* D8 - DF */
	0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9C, 0x48,	/* E0 - E7 */
	0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,	/* E8 - EF */
	0x8C, 0x49, 0xCD, 0xCE, 0xCB, 0xCF, 0xCC, 0xE1,	/* F0 - F7 */
	0x70, 0xDD, 0xDE, 0xDB, 0xDC, 0x8D, 0x8E, 0xDF	/* F8 - FF */
	};

/* IBM Latin-1 Code Page 01047 (EBCDIC) to ISO 8859-1 */

static const BYTE ebcdicToAsciiTbl[] = {
	0x00, 0x01, 0x02, 0x03, 0x9C, 0x09, 0x86, 0x7F,	/* 00 - 07 */
	0x97, 0x8D, 0x8E, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,	/* 08 - 0F */
	0x10, 0x11, 0x12, 0x13, 0x9D, 0x0A, 0x08, 0x87,	/* 10 - 17 */
	0x18, 0x19, 0x92, 0x8F, 0x1C, 0x1D, 0x1E, 0x1F,	/* 18 - 1F */
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x17, 0x1B,	/* 20 - 27 */
	0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x05, 0x06, 0x07,	/* 28 - 2F */
	0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04,	/* 30 - 37 */
	0x98, 0x99, 0x9A, 0x9B, 0x14, 0x15, 0x9E, 0x1A,	/* 38 - 3F */
	0x20, 0xA0, 0xE2, 0xE4, 0xE0, 0xE1, 0xE3, 0xE5,	/* 40 - 47 */
	0xE7, 0xF1, 0xA2, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,	/* 48 - 4F */
	0x26, 0xE9, 0xEA, 0xEB, 0xE8, 0xED, 0xEE, 0xEF,	/* 50 - 57 */
	0xEC, 0xDF, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5E,	/* 58 - 5F */
	0x2D, 0x2F, 0xC2, 0xC4, 0xC0, 0xC1, 0xC3, 0xC5,	/* 60 - 67 */
	0xC7, 0xD1, 0xA6, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,	/* 68 - 6F */
	0xF8, 0xC9, 0xCA, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF,	/* 70 - 77 */
	0xCC, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,	/* 78 - 7F */
	0xD8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,	/* 80 - 87 */
	0x68, 0x69, 0xAB, 0xBB, 0xF0, 0xFD, 0xFE, 0xB1,	/* 88 - 8F */
	0xB0, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,	/* 90 - 97 */
	0x71, 0x72, 0xAA, 0xBA, 0xE6, 0xB8, 0xC6, 0xA4,	/* 98 - 9F */
	0xB5, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,	/* A0 - A7 */
	0x79, 0x7A, 0xA1, 0xBF, 0xD0, 0x5B, 0xDE, 0xAE,	/* A8 - AF */
	0xAC, 0xA3, 0xA5, 0xB7, 0xA9, 0xA7, 0xB6, 0xBC,	/* B0 - B7 */
	0xBD, 0xBE, 0xDD, 0xA8, 0xAF, 0x5D, 0xB4, 0xD7,	/* B8 - BF */
	0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,	/* C0 - C7 */
	0x48, 0x49, 0xAD, 0xF4, 0xF6, 0xF2, 0xF3, 0xF5,	/* C8 - CF */
	0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,	/* D0 - D7 */
	0x51, 0x52, 0xB9, 0xFB, 0xFC, 0xF9, 0xFA, 0xFF,	/* D8 - DF */
	0x5C, 0xF7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,	/* E0 - E7 */
	0x59, 0x5A, 0xB2, 0xD4, 0xD6, 0xD2, 0xD3, 0xD5,	/* E8 - EF */
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,	/* F0 - F7 */
	0x38, 0x39, 0xB3, 0xDB, 0xDC, 0xD9, 0xDA, 0x9F	/* F8 - FF */
	};

/* Convert a string to/from EBCDIC */

int asciiToEbcdic( char *dest, const char *src, const int length )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( src, length ) );
	assert( isWritePtrDynamic( dest, length ) );

	LOOP_MAX( i = 0, i < length, i++ )
		{
		ENSURES( LOOP_INVARIANT_MAX( i, 0, length - 1 ) );

		dest[ i ] = asciiToEbcdicTbl[ ( unsigned int ) src[ i ] ];
		}
	ENSURES( LOOP_BOUND_OK );
	return( CRYPT_OK );
	}

int ebcdicToAscii( char *dest, const char *src, const int length )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( src, length ) );
	assert( isWritePtrDynamic( dest, length ) );

	LOOP_MAX( i = 0, i < length, i++ )
		{
		ENSURES( LOOP_INVARIANT_MAX( i, 0, length - 1 ) );

		dest[ i ] = ebcdicToAsciiTbl[ ( unsigned int ) src[ i ] ];
		}
	ENSURES( LOOP_BOUND_OK );
	return( CRYPT_OK );
	}
#else

int asciiToEbcdic( char *dest, const char *src, const int length )
	{
	assert( isReadPtrDynamic( src, length ) );
	assert( isWritePtrDynamic( dest, length ) );

	if( dest != src )
		memcpy( dest, src, length );
	return( __atoe_l( dest, length ) < 0 ? \
			CRYPT_ERROR_BADDATA : CRYPT_OK );
	}

int ebcdicToAscii( char *dest, const char *src, const int length )
	{
	assert( isReadPtrDynamic( src, length ) );
	assert( isWritePtrDynamic( dest, length ) );

	if( dest != src )
		memcpy( dest, src, length );
	return( __etoa_l( dest, length ) < 0 ? \
			CRYPT_ERROR_BADDATA : CRYPT_OK );
	}
#endif /* USE_ETOA */

/* Convert a string to/from EBCDIC via a temporary buffer, used when passing 
   an ASCII string to a system function that requires EBCDIC and vice versa */

char *bufferToEbcdic( char *buffer, const char *string )
	{
	strcpy( buffer, string );
	asciiToEbcdic( buffer, buffer, strlen( string ) );
	return( buffer );
	}

char *bufferToAscii( char *buffer, const char *string )
	{
	strcpy( buffer, string );
	ebcdicToAscii( buffer, buffer, strlen( string ) );
	return( buffer );
	}

/* Table for ctype functions that explicitly use the ASCII character set */

#define A	ASCII_ALPHA
#define L	ASCII_LOWER
#define N	ASCII_NUMERIC
#define S	ASCII_SPACE
#define U	ASCII_UPPER
#define X	ASCII_HEX
#define AL	( A | L )
#define AU	( A | U )
#define ANX	( A | N | X )
#define ALX	( A | L | X )
#define AUX	( A | U | X )

const BYTE asciiCtypeTbl[ 256 ] = {
	/* 00	   01	   02	   03	   04	   05	   06	   07  */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 08	   09	   0A	   0B	   0C	   0D	   0E	   0F */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 10	   11	   12	   13	   14	   15	   16	   17 */
		0,		0,		0,		0,		0,		0,		0,		0,
	/* 18	   19	   1A	   1B	   1C	   1D	   1E	   1F */
		0,		0,		0,		0,		0,		0,		0,		0,
	/*			!		"		#		$		%		&		' */
		A,		A,		A,		A,		A,		A,		A,		A,
	/* 	(		)		*		+		,		-		.		/ */
		A,		A,		A,		A,		A,		A,		A,		A,
	/*	0		1		2		3		4		5		6		7 */
	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,	   ANX,
	/*	8		9		:		;		<		=		>		? */
	   ANX,	   ANX,		A,		A,		A,		A,		A,		A,
	/*	@		A		B		C		D		E		F		G */
		A,	   AUX,	   AUX,	   AUX,	   AUX,	   AUX,	   AUX,	   AU,
	/*	H		I		J		K		L		M		N		O */
	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,
	/*	P		Q		R		S		T		U		V		W */
	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,	   AU,
	/*	X		Y		Z		[		\		]		^		_ */
	   AU,	   AU,	   AU,		A,		A,		A,		A,		A,
	/*	`		a		b		c		d		e		f		g */
		A,	   ALX,	   ALX,	   ALX,	   ALX,	   ALX,	   ALX,	   AL,
	/*	h		i		j		k		l		m		n		o */
	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,
	/*	p		q		r		s		t		u		v		w */
	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,	   AL,
	/*	x		y		z		{		|		}		~	   DL */
	   AL,	   AL,	   AL,		A,		A,		A,		A,		A,
	/* High-bit-set characters */
	0
	};

/* stricmp()/strnicmp() versions that explicitly use the ASCII character
   set.  In order for collation to be handled properly, we have to convert
   to EBCDIC and use the local stricmp()/strnicmp() */

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1, 2 ) ) \
int strCompare( IN_STRING const char *src, IN_STRING const char *dest, 
				IN_LENGTH_SHORT const int length )
	{
	BYTE buffer1[ MAX_ATTRIBUTE_SIZE + 8 ];
	BYTE buffer2[ MAX_ATTRIBUTE_SIZE + 8 ];

	assert( isReadPtrDynamic( src, length ) );
	assert( isReadPtrDynamic( dest, 1 ) );

	if( length <= 0 || length > MAX_ATTRIBUTE_SIZE )
		return( 1 );	/* Invalid length */

	/* Virtually all strings are 7-bit ASCII, the following optimisation
	   speeds up checking, particularly in cases where we're walking down a
	   list of keywords looking for a match */
	if( *src < 0x80 && *dest < 0x80 && \
		toLower( *src ) != toLower( *dest ) )
		return( 1 );	/* Not equal */

	/* Convert the strings to EBCDIC and use a native compare */
	src = bufferToEbcdic( buffer1, src );
	dest = bufferToEbcdic( buffer2, dest );
	return( strncasecmp( src, dest, length ) );
	}

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1, 2 ) ) \
int strCompareZ( IN_STRING const char *src, IN_STRING const char *dest )
	{
	const int length = strlen( src );

	assert( isReadPtrDynamic( src, length ) );
	assert( isReadPtrDynamic( dest, 1 ) );

	if( length != strlen( dest ) )
		return( 1 );	/* Lengths differ */
	return( strCompare( src, dest, length ) );
	}

/* sprintf_s() and vsprintf_s() that take ASCII format strings.  In addition 
   to the standard format specifiers, we also allow the nonstandard '%e' to 
   format an EBCDIC string.  This assumes that the format string is well-
   formed, which it should be since the source is a cryptlib-internal fixed
   string */

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1, 3 ) ) \
int vsPrintf_s( INOUT_BUFFER_FIXED( bufSize ) char *buffer, 
				IN_LENGTH_SHORT const int bufSize, 
				IN_STRING const char *format, 
				va_list argPtr )
	{
	BYTE ch;
	LOOP_INDEX index, bufPos;

	assert( isWritePtrDynamic( buffer, bufSize ) );
	assert( isReadPtrDynamic( format, 2 ) );

	REQUIRES( isShortIntegerRangeNZ( bufSize ) );

	LOOP_LARGE( ( bufPos = 0, index = 0 ), \
				bufPos < bufSize && ( ch = format[ index ] ) && ( ch != 0 ), 
				index++ )
		{
		BYTE formatBuffer[ MAX_ATTRIBUTE_SIZE + 1 + 8 ];
		BOOLEAN needsConversion = FALSE, needsUppercase = FALSE;
		BOOLEAN zeroPad = FALSE;
		int formatBufPos, padCount = 0, count, i;

		ENSURES( LOOP_INVARIANT_LARGE( index, 0, MAX_INTLENGTH_SHORT ) );
		ENSURES( LOOP_INVARIANT_SECONDARY( bufPos, 0, bufSize - 1 ) );

		/* If it's not a formatting character, output it as is */
		if( ch != '%' )
			{
			buffer[ bufPos++ ] = ch;
			continue;
			}

		/* Process a format specifier */
		ch = format[ ++index ];
		if( ch == '0' )
			{
			zeroPad = TRUE;
			ch = format[ ++index ];
			}
		if( ch >= '1' && ch <= '9' )
			{
			/* Process padding requirements */
			padCount = ch - '0';
			ch = format[ ++index ];
			}
		switch( ch )
			{
			case 0:
				break;

			case 'c' :
				formatBuffer[ 0 ] = ( char )( va_arg( argPtr, char ) );
				formatBuffer[ 1 ] = '\0';
				break;

			case 'd':
				itoa( va_arg( argPtr, int ), formatBuffer, 10 );
				needsConversion = TRUE;
				break;
	
			case 'l':
				ch = format[ ++index ];
				if( ch == 0 )
					break;
				ltoa( va_arg( argPtr, long ), formatBuffer, ( ch == 'X' ) ? 16 : 10 );
				if( ch == 'X' )
					needsUppercase = TRUE;
				needsConversion = TRUE;
				break;

			case 's':
			case 'e':	/* For EBCDIC strings */ 
				{
				const char *bufPtr = va_arg( argPtr, char * );
				const int bufStrLen = strlen( bufPtr );

				REQUIRES( isShortIntegerRange( bufStrLen ) );

				/* If we've been given an empty string, which can happen 
				   when using the function as puts( "" ) -> printf( "%s\n" )
				   to print a CRLF, there's nothing more to do */
				if( bufStrLen <= 0 )
					continue;

				/* Copy the string into a local buffer and convert it from 
				   EBCDIC if necessary */
				if( bufStrLen > MAX_ATTRIBUTE_SIZE )
					strcpy( formatBuffer, "<<<String too long>>>" );
				else
					{
					strcpy( formatBuffer, bufPtr );
					if( ch == 'e' )
						needsConversion = TRUE;
					}
				break;
				}

#if 0		/* Not currently used */
			case 'u':
				utoa( va_arg( argPtr, unsigned int ), formatBuffer, 10 );
				needsConversion = TRUE;
				break;
#endif /* 0 */

			case 'x':
			case 'X':
				utoa( va_arg( argPtr, unsigned int ), formatBuffer, 16 );
				if( ch == 'X' )
					needsUppercase = TRUE;
				needsConversion = TRUE;
				break;

			default:
				formatBuffer[ 0 ] = ch;
				formatBuffer[ 1 ] = '\0';
				break;
			}
		if( ch == 0 )
			break;
		if( needsConversion )
			bufferToAscii( formatBuffer, formatBuffer );
		formatBufPos = strlen( formatBuffer );
		if( needsUppercase )
			{
			LOOP_LARGE( i = 0, i < formatBufPos, i++ )
				{
				ENSURES( LOOP_INVARIANT_LARGE( i, 0, formatBufPos - 1 ) );

				formatBuffer[ i ] = toUpper( formatBuffer[ i ] );
				}
			ENSURES( LOOP_BOUND_OK );
			}
		if( padCount > formatBufPos )
			{
			LOOP_SMALL_REV( count = padCount - formatBufPos, 
							count > 0 && bufPos < bufSize, 
							count-- )
				{
				ENSURES( LOOP_INVARIANT_REV( count, 1, 
											 padCount - formatBufPos ) );
				ENSURES( LOOP_INVARIANT_SECONDARY( bufPos, 0, bufSize - 1 ) );

				buffer[ bufPos++ ] = zeroPad ? '0' : ' ';
				}
			ENSURES( LOOP_BOUND_SMALL_REV_OK );
			if( bufPos >= bufSize )
				break;
			}
		LOOP_LARGE( i = 0, i < formatBufPos && bufPos < bufSize, i++ )
			{
			ENSURES( LOOP_INVARIANT_LARGE( i, 0, formatBufPos - 1 ) );
			ENSURES( LOOP_INVARIANT_SECONDARY( bufPos, 0, bufSize - 1 ) );

			buffer[ bufPos++ ] = formatBuffer[ i ];
			}
		ENSURES( LOOP_BOUND_OK );
		if( bufPos >= bufSize )
			break;
		}
	ENSURES( LOOP_BOUND_OK );
	buffer[ bufPos ] = '\0';

	return( bufPos );
	}

CHECK_RETVAL_LENGTH_SHORT STDC_NONNULL_ARG( ( 1, 3 ) ) \
int sPrintf_s( char *buffer, const int bufSize, const char *format, ... )
	{
	va_list argPtr;
	int length;

	va_start( argPtr, format );
	length = vsPrintf_s( buffer, bufSize, format, argPtr );
	va_end( argPtr );

	return( length );
	}

/****************************************************************************
*																			*
*									MQX										*
*																			*
****************************************************************************/

/* In line with its mania for redefining standard C types in broken ways,
   MQX redefines struct tm in a broken manner, giving its tm_mday a range
   of 0...30 instead of the C standard 1...31, see 
   https://community.nxp.com/thread/437013.  What's more, the MQX docs
   indicate that the function doesn't do much, if any, range checking ("If 
   you violate the ranges, undefined behavior results") so it'll probably 
   produce garbage results rather than rejecting a value that it considers 
   invalid.

   To deal with this we define our own mktime() and gmtime_r() (there's no
   gmtime(), only a gmtime_r()) that change the struct tm fields to get them 
   into the incorrect range that MQX uses */

#elif defined( __MQXRTOS__ )

#undef mktime	
#undef gmtime_r		/* Restore the standard mktime() and gmtime_r() */

#ifdef __IAR_SYSTEMS_ICC__
  /* The IAR libraries don't provide any time functions, and since 
     gmtime_r() is a non-ANSI function there's no prototype for it in the
	 IAR headers, although it is in the MQX headers but the IAR comiler can't
	 seem to see it.  Because of this we have to provide it ourselves, 
	 matching the MQX prototype */
  struct tm *gmtime_r( const time_t *timep, struct tm *result );
#endif /* IAR compiler */

time_t mqx_mktime( struct tm *timeptr )
	{
	struct tm mqxTime;

	mqxTime = *timeptr;
	if( mqxTime.tm_mday > 0 )
		mqxTime.tm_mday--;		/* 1...31 -> 0...30 */
	return( mktime( &mqxTime ) );
	}

struct tm *mqx_gmtime_r( const time_t *timep, struct tm *result )
	{
	struct tm *resultPtr;

	resultPtr = gmtime_r( timep, result );
	if( resultPtr == NULL )
		return( NULL );
	if( result->tm_mday < 31 )
		result->tm_mday++;	/* 0...30 -> 1...31 */
	return( result );
	}

/****************************************************************************
*																			*
*									OSEK/VDX								*
*																			*
****************************************************************************/

#elif defined( __OSEK__ )

#include <os.h>

/* The OSEK thread-self function returns the thread ID via a reference 
   parameter, because of this we have to provide a wrapper that returns it 
   as a return value */

TaskType threadSelf( void )
	{
	TaskType taskID;

	GetTaskID( &taskID );
	return( taskID );
	}

/****************************************************************************
*																			*
*									PalmOS									*
*																			*
****************************************************************************/

#elif defined( __Nucleus__ )

#include <nucleus.h>

/* Wrappers for the Nucleus OS-level memory allocation functions */

extern NU_MEMORY_POOL Application_Memory;

void *clAllocFn( size_t size )
	{
	STATUS Rc;
	void *ptr;

	Rc = NU_Allocate_Memory( &Application_Memory, &ptr, size, 
							 NU_NO_SUSPEND );
	if( Rc != NU_SUCCESS || ptr == NULL )
		return( NULL );
	return( ptr );
	}

void clFreeFn( void *memblock )
	{
	NU_Deallocate_Memory( memblock );
	}

/****************************************************************************
*																			*
*									PalmOS									*
*																			*
****************************************************************************/

#elif defined( __PALMOS__ )

#include <CmnErrors.h>
#include <CmnLaunchCodes.h>

/* The cryptlib entry point, defined in cryptlib.sld */

uint32_t cryptlibMain( uint16_t cmd, void *cmdPBP, uint16_t launchFlags )
	{
	UNUSED_ARG( cmdPBP );
	UNUSED_ARG( launchFlags );

	switch( cmd )
		{
		case sysLaunchCmdInitialize:
			/* Set up the initialisation lock in the kernel */
			preInit();
			break;

		case sysLaunchCmdFinalize:
			/* Delete the initialisation lock in the kernel */
			postShutdown();
			break;
		}

	return( errNone );
	}

/****************************************************************************
*																			*
*									RTEMS									*
*																			*
****************************************************************************/

#elif defined( __RTEMS__ )

/* The RTEMS thread-self function returns the task ID via a reference
   parameter, because of this we have to provide a wrapper that returns it
   as a return value.  We use RTEMS_SEARCH_ALL_NODES because there isn't
   any other way to specify the local node, this option always searches the
   local node first so it has the desired effect */

#include <rtems.h>

rtems_id threadSelf( void )
	{
	rtems_id taskID;

	rtems_task_ident( RTEMS_SELF, RTEMS_SEARCH_ALL_NODES, &taskID );
	return( taskID );
	}

/****************************************************************************
*																			*
*									Tandem									*
*																			*
****************************************************************************/

/* The Tandem mktime() is broken and can't convert dates beyond 2023, if
   mktime() fails and the year is between then and the epoch try again with
   a time that it can convert */

#elif defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )

#undef mktime	/* Restore the standard mktime() */

time_t my_mktime( struct tm *timeptr )
	{
	time_t theTime;

	theTime = mktime( timeptr );
	if( theTime < 0 && timeptr->tm_year > 122 && timeptr->tm_year <= 138 )
		{
		timeptr->tm_year = 122;	/* Try again with a safe year of 2022 */
		theTime = mktime( timeptr );
		}
	return( theTime );
	}

/****************************************************************************
*																			*
*									Unix									*
*																			*
****************************************************************************/

#elif defined( __UNIX__ ) && \
	  !( defined( __MVS__ ) || defined( __TANDEM_NSK__ ) || \
		 defined( __TANDEM_OSS__ ) )

#include <sys/time.h>

/* For performance evaluation purposes we provide the following function,
   which returns ticks of the 1us timer */

long getTickCount( long startTime )
	{
	struct timeval tv;
	long timeLSB, timeDifference;

	/* Only accurate to about 1us */
	gettimeofday( &tv, NULL );
	timeLSB = tv.tv_usec;

	/* If we're getting an initial time, return an absolute value */
	if( startTime <= 0 )
		return( timeLSB );

	/* We're getting a time difference */
	if( startTime < timeLSB )
		timeDifference = timeLSB - startTime;
	else
		{
		/* gettimeofday() rolls over at 1M us */
		timeDifference = ( 1000000L - startTime ) + timeLSB;
		}
	if( timeDifference <= 0 )
		{
		printf( "Error: Time difference = %lX, startTime = %lX, "
				"endTime = %lX.\n", timeDifference, startTime, timeLSB );
		return( 1 );
		}
	return( timeDifference );
	}

/* SunOS and older Slowaris have broken sprintf() handling.  In SunOS 4.x
   this was documented as returning a pointer to the output data as per the
   Berkeley original.  Under Slowaris the manpage was changed so that it
   looks like any other sprintf(), but it still returns the pointer to the
   output buffer in some versions so we use a wrapper that checks at
   runtime to see what we've got and adjusts its behaviour accordingly.  In
   fact it's much easier to fix than that, since we have to use vsprintf()
   anyway and this doesn't have the sprintf() problem, this fixes itself
   simply from the use of the wrapper (unfortunately we can't use 
   vsnprintf() because these older OS versions don't include it yet) */

#if defined( sun ) && ( OSVERSION <= 5 )

#include <stdarg.h>

int fixedSprintf( char *buffer, const int bufSize, const char *format, ... )
	{
	va_list argPtr;
	int length;

	va_start( argPtr, format );
	length = vsprintf( buffer, format, argPtr );
	va_end( argPtr );

	return( length );
	}
#endif /* Old SunOS */

/****************************************************************************
*																			*
*									Windows									*
*																			*
****************************************************************************/

#elif defined( __WIN32__ )

/* Needed for various debug-related functions */

int WINAPI MessageBoxA( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption,
						UINT uType );

/* Yielding a thread on an SMP or HT system is a tricky process,
   particularly on an HT system.  On an HT CPU the OS (or at least apps
   running under the OS) think that there are two independent CPUs present,
   but it's really just one CPU with partitioning of pipeline slots.  So
   when one thread yields, the only effect is that all of its pipeline slots
   get marked as available.  Since the other thread can't utilise those
   slots, the first thread immediately reclaims them and continues to run.
   In addition thread scheduling varies across OS versions, the WinXP
   scheduler was changed to preferentially schedule threads on idle physical
   processors rather than an idle logical processor on a physical processor
   whose other logical processor is (potentially) busy.

   There isn't really any easy way to fix this since it'd require a sleep 
   that works across all CPUs, however one solution is to make the thread 
   sleep for a nonzero time limit iff it's running on a multi-CPU system.  
   There's a second problem though, which relates to thread priorities.  If 
   we're at a higher priority than the other thread then we can call 
   Sleep( 0 ) as much as we like, but the scheduler will never allow the 
   other thread to run since we're a higher-priority runnable thread.  As a 
   result, as soon as we release our timeslice the scheduler will restart us 
   again (the Windows scheduler implements a starvation-prevention mechanism 
   via the balance set manager, but this varies across scheduler versions 
   and isn't something that we want to rely on).  In theory we could do:

		x = GetThreadPriority( GetCurrentThread() );
		SetThreadPriority( GetCurrentThread(), x - 5 );
		Sleep( 0 );		// Needed to effect priority change
		<wait loop>
		SetThreadPriority( GetCurrentThread(), x );
		Sleep( 0 );

   however this is somewhat problematic if the caller is also messing with 
   priorities at the same time.  In fact it can get downright nasty because 
   the balance set manager will, if a thread has been starved for ~3-4 
   seconds, give it its own priority boost to priority 15 (time-critical) to 
   ensure that it'll be scheduled, with the priority slowly decaying back to 
   the normal level each time that it's scheduled.  In addition it'll have 
   its scheduling quantum boosted to 2x the normal duration for a client OS 
   or 4x the normal duration for a server OS.

   To solve this, we always force our thread to go to sleep (to allow a 
   potentially lower-priority thread to leap in and get some work done) even 
   on a single-processor system, but use a slightly longer wait on an 
   HT/multi-processor system.

   (Actually this simplified view isn't quite accurate since on a HT system 
   the scheduler executes the top *two* threads on the two logical 
   processors and on a dual-CPU system they're executed on a physical 
   processor.  In addition on a HT system a lower-priority thread on one 
   logical processor can compete with a higher-priority thread on the other
   logical processor since the hardware isn't aware of thread priorities) */

void threadYield( void )
	{
	static int sleepTime = -1;

	/* If the sleep time hasn't been determined yet, get it now */
	if( sleepTime < 0 )
		{
		SYSTEM_INFO systemInfo;

		GetSystemInfo( &systemInfo );
		sleepTime = ( systemInfo.dwNumberOfProcessors > 1 ) ? 10 : 1;
		}

	/* Yield the CPU for this thread */
	Sleep( sleepTime );
	}

#ifndef NDEBUG

/* For performance evaluation purposes we provide the following function,
   which returns ticks of the 3.579545 MHz hardware timer (see the long
   comment in rndwin32.c for more details on Win32 timing issues) */

CHECK_RETVAL_RANGE( 0, INT_MAX ) \
long getTickCount( long startTime )
	{
	long timeLSB, timeDifference;

#ifndef __BORLANDC__
	LARGE_INTEGER performanceCount;

	/* Sensitive to context switches */
	QueryPerformanceCounter( &performanceCount );
	timeLSB = performanceCount.LowPart;
#else
	FILETIME dummyTime, kernelTime, userTime;

	/* Only accurate to 10ms, returns constant values in VC++ debugger */
	GetThreadTimes( GetCurrentThread(), &dummyTime, &dummyTime,
					&kernelTime, &userTime );
	timeLSB = userTime.dwLowDateTime;
#endif /* BC++ vs. everything else */

	/* If we're getting an initial time, return an absolute value */
	if( startTime <= 0 )
		return( timeLSB );

	/* We're getting a time difference */
	if( startTime < timeLSB )
		timeDifference = timeLSB - startTime;
	else
		{
		/* Windows rolls over at INT_MAX */
		timeDifference = ( 0xFFFFFFFFUL - startTime ) + 1 + timeLSB;
		}
	if( timeDifference <= 0 )
		{
		printf( "Error: Time difference = %lX, startTime = %lX, "
				"endTime = %lX.\n", timeDifference, startTime, timeLSB );
		return( 1 );
		}
	return( timeDifference );
	}
#endif /* Debug version */

/* Borland C++ before 5.50 doesn't have snprintf() so we fake it using
   sprintf().  Unfortunately these are all va_args functions so we can't 
   just map them using macros but have to provide an explicit wrapper to get 
   rid of the size argument */

#if defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x0550 )

int bcSnprintf( char *buffer, const int bufSize, const char *format, ... )
	{
	va_list argPtr;
	int length;

	va_start( argPtr, format );
	length = vsprintf( buffer, format, argPtr );
	va_end( argPtr );

	return( length );
	}

int bcVsnprintf( char *buffer, const int bufSize, const char *format, va_list argPtr )
	{
	return( vsprintf( buffer, format, argPtr ) );
	}
#endif /* BC++ before 5.50 */

/* Safely load a DLL.  This gets quite complicated because different 
   versions of Windows have changed how they search for DLLs to load, and 
   the behaviour of a specific version of Windows can be changed based on
   registry keys and SetDllDirectory().  Traditionally Windows searched
   the app directory, the current directory, the system directory, the
   Windows directory, and the directories in $PATH.  Windows XP SP2 added
   the SafeDllSearchMode registry key, which changes the search order so
   the current directory is searched towards the end rather than towards
   the start, however it's (apparently) only set on new installs, on a
   pre-SP2 install that's been upgraded it's not set.  Windows Vista and
   newer enabled this safe behaviour by default, but even there 
   SetDefaultDllDirectories() can be used to explicitly re-enable unsafe
   behaviour, and AddDllDirectory() can be used to add a path to the set of 
   DLL search paths and SetDllDirectory() can be used to add a new directory 
   to the start of the search order.

   None of these options are terribly useful if we want a DLL to either
   be loaded from the system directory or not at all.  To handle this we
   build an absolute load path and prepend it to the name of the DLL
   being loaded */

#if 0	/* Older code using SHGetFolderPath() */

/* The documented behaviour for the handling of the system directory under 
   Win64 seems to be more or less random:

	http://msdn.microsoft.com/en-us/library/bb762584%28VS.85%29.aspx: 
		CSIDL_SYSTEM = %windir%/System32, CSIDL_SYSTEMX86 = %windir%/System32.
	http://social.technet.microsoft.com/Forums/en/appvgeneralsequencing/thread/c58f7d64-6a23-46f0-998f-0a964c1eff2a:
		CSIDL_SYSTEM = %windir%/Syswow64.
	http://msdn.microsoft.com/en-us/library/windows/desktop/ms538044%28v=vs.85%29.aspx:
		CSIDL_SYSTEM = %windir%/System32, CSIDL_SYSTEMX86 = %windir%/Syswow64.
	http://social.msdn.microsoft.com/Forums/en-US/vcgeneral/thread/f9a54564-1006-42f9-b4d1-b225f370c60c:
		GetSystemDirectory() = %windir%/Syswow64.
	http://msdn.microsoft.com/en-us/library/windows/desktop/dd378457%28v=vs.85%29.aspx:
		CSIDL_SYSTEM = %windir%/System32, 
		CSIDL_SYSTEMX86 = %windir%/System32 for Win32, %windir%/Syswow64 for Win64.

   The current use of CSIDL_SYSTEM to get whatever-the-system-directory-is-
   meant-to-be seems to work, so we'll leave it as is */

#ifndef CSIDL_SYSTEM
  #define CSIDL_SYSTEM		0x25	/* 'Windows/System32' */
#endif /* !CSIDL_SYSTEM */
#ifndef SHGFP_TYPE_CURRENT
  #define SHGFP_TYPE_CURRENT	0
#endif /* !SHGFP_TYPE_CURRENT */

static HMODULE WINAPI loadExistingLibrary( IN_STRING LPCTSTR lpFileName )
	{
	HANDLE hFile;

	assert( isReadPtr( lpFileName, 2 ) );

	ANALYSER_HINT_STRING( lpFileName );

	/* Determine whether the DLL is present and accessible */
	hFile = CreateFile( lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, NULL );
	if( hFile == INVALID_HANDLE_VALUE )
		return( NULL );
	CloseHandle( hFile );

	return( LoadLibrary( lpFileName ) );
	}

static HMODULE WINAPI loadFromSystemDirectory( IN_BUFFER( fileNameLength ) \
													const char *fileName,
											   IN_LENGTH_SHORT_MIN( 1 ) \
													const int fileNameLength )
	{
	char path[ MAX_PATH + 8 ];
	int pathLength;

	ENSURES_N( fileNameLength >= 1 && fileNameLength + 8 < MAX_PATH );

	assert( isReadPtrDynamic( fileName, fileNameLength ) );

	/* Get the path to a DLL in the system directory */
	pathLength = \
		GetSystemDirectory( path, MAX_PATH - ( fileNameLength + 8 ) );
	if( pathLength < 3 || pathLength + fileNameLength > MAX_PATH - 8 )
		return( NULL );
	path[ pathLength++ ] = '\\';
	REQUIRES_N( boundsCheck( pathLength, fileNameLength, MAX_PATH ) );
	memcpy( path + pathLength, fileName, fileNameLength );
	path[ pathLength + fileNameLength ] = '\0';

	return( loadExistingLibrary( path ) );
	}

HMODULE WINAPI SafeLoadLibrary( IN_STRING LPCTSTR lpFileName )
	{
	typedef HRESULT ( WINAPI *SHGETFOLDERPATH )( HWND hwndOwner,
										int nFolder, HANDLE hToken,
										DWORD dwFlags, LPTSTR lpszPath );
	typedef struct {
		const char *dllName; const int dllNameLen; 
		} DLL_NAME_INFO;
	static const DLL_NAME_INFO dllNameInfoTbl[] = {
		{ "Crypt32.dll", 11 }, { "ComCtl32.dll", 12 },
		{ "dnsapi.dll", 10 }, { "Mpr.dll", 7 },
		{ "NetAPI32.dll", 12 }, { "ODBC32.dll", 10 },
		{ "SetupAPI.dll", 12 }, { "SHFolder.dll", 12 },
		{ "Shell32.dll", 11 }, { "WinHTTP.dll", 11 },
		{ "wldap32.dll", 11 }, { "ws2_32.dll", 10 },
		{ "wsock32.dll", 11 }, 
		{ NULL, 0 }, { NULL, 0 }
		};
	SHGETFOLDERPATH pSHGetFolderPath;
	HINSTANCE hShell32;
	char path[ MAX_PATH + 8 ];
	const int fileNameLength = strlen( lpFileName );
	BOOLEAN gotPath = FALSE;
	LOOP_INDEX i;
	int pathLength;

	ANALYSER_HINT_STRING( lpFileName );

	REQUIRES_N( fileNameLength >= 1 && fileNameLength < MAX_PATH );

	assert( isReadPtr( lpFileName, 2 ) );

	/* If it's Win98 or NT4, just call LoadLibrary directly.  In theory
	   we could try a few further workarounds (see io/file.c) but in 
	   practice bending over backwards to fix search path issues under
	   Win98, which doesn't have ACLs to protect the files in the system
	   directory anyway, isn't going to achieve much, and in any case both
	   of these OSes should be long dead by now */
	if( getSysVar( SYSVAR_OSMAJOR ) <= 4 )
		return( LoadLibrary( lpFileName ) );

	/* If it's already an absolute path, don't try and override it */
	if( lpFileName[ 0 ] == '/' || \
		( fileNameLength >= 3 && isAlpha( lpFileName[ 0 ] ) && \
		  lpFileName[ 1 ] == ':' && lpFileName[ 2 ] == '/' ) )
		{
		return( loadExistingLibrary( lpFileName ) );
		}

	/* If it's a well-known DLL, load it from the system directory */
	LOOP_MED( i = 0, 
			  i < FAILSAFE_ARRAYSIZE( dllNameInfoTbl, DLL_NAME_INFO ) && \
					dllNameInfoTbl[ i ].dllName != NULL,
			  i++ )
		{
		ENSURES_N( LOOP_INVARIANT_MED( i, 0, 
									   FAILSAFE_ARRAYSIZE( dllNameInfoTbl, \
														   DLL_NAME_INFO ) - 1 ) );

		if( dllNameInfoTbl[ i ].dllNameLen == fileNameLength && \
			!strCompare( dllNameInfoTbl[ i ].dllName, lpFileName, 
						 fileNameLength ) )
			{
			/* It's a standard system DLL, load it from the system 
			   directory */
			return( loadFromSystemDirectory( lpFileName, fileNameLength ) );
			}
		}
	ENSURES_N( LOOP_BOUND_OK );
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( dllNameInfoTbl, DLL_NAME_INFO ) );

	/* It's a system new enough to support SHGetFolderPath(), get the path
	   to the system directory.  Unfortunately at this point we're in a 
	   catch-22, in order to resolve SHGetFolderPath() we need to call
	   Shell32.dll and if an attacker uses that as the injection point then
	   they can give us a SHGetFolderPath() that'll do whatever they want.  
	   There's no real way to fix this because we have to load Shell32 at
	   some point, either explicitly here or on program load, and since we
	   can't control the load path at either point we can't control what's
	   actually being loaded.  In addition DLLs typically recursively load
	   more DLLs so even if we can control the path of the DLL that we load 
	   directly we can't influence the paths over which further DLLs get 
	   loaded.  So unfortunately the best that we can do is make the 
	   attacker work a little harder rather than providing a full fix */
	hShell32 = loadFromSystemDirectory( "Shell32.dll", 11 );
	if( hShell32 != NULL )
		{
		pSHGetFolderPath = ( SHGETFOLDERPATH ) \
						   GetProcAddress( hShell32, "SHGetFolderPathA" );
		if( pSHGetFolderPath != NULL && \
			pSHGetFolderPath( NULL, CSIDL_SYSTEM, NULL, SHGFP_TYPE_CURRENT, 
							  path ) == S_OK )
			gotPath = TRUE;
		FreeLibrary( hShell32 );
		}
	if( !gotPath )
		{
		/* If for some reason we couldn't get the path to the Windows system
		   directory this means that there's something drastically wrong,
		   don't try and go any further */
		return( NULL );
		}
	pathLength = strlen( path );
	if( pathLength < 3 || pathLength + fileNameLength > MAX_PATH - 8 )
		{
		/* Under WinNT and Win2K the LocalSystem account doesn't have its 
		   own profile so SHGetFolderPath() will report success but return a 
		   zero-length path if we're running as a service.  To detect this 
		   we have to check for a valid-looking path as well as performing a 
		   general check on the return status.
		   
		   In effect prepending a zero-length path to the DLL name just 
		   turns the call into a standard LoadLibrary() call, but we make 
		   the action explicit here.  Unfortunately this reintroduces the
		   security hole that we were trying to fix, and what's worse it's
		   for the LocalSystem account (sigh). */
		return( LoadLibrary( lpFileName ) );
		}
	path[ pathLength++ ] = '\\';
	REQUIRES_N( boundsCheck( pathLength, fileNameLength, MAX_PATH ) );
	memcpy( path + pathLength, lpFileName, fileNameLength );
	path[ pathLength + fileNameLength ] = '\0';

	return( loadExistingLibrary( path ) );
	}
#else	/* Newer code that does the same thing */

#if VC_GE_2005( _MSC_VER )
  #pragma warning( push )
  #pragma warning( disable : 4255 )	/* Errors in VersionHelpers.h */
  #include <VersionHelpers.h>
  #pragma warning( pop )
#endif /* VC++ >= 2005 */

HMODULE WINAPI SafeLoadLibrary( IN_STRING LPCTSTR lpFileName )
	{
	char path[ MAX_PATH + 8 ];
	const int fileNameLength = strlen( lpFileName );
	int pathLength;

	REQUIRES_EXT( fileNameLength >= 1 && fileNameLength < MAX_PATH, \
				  NULL );

	assert( isReadPtr( lpFileName, 2 ) );

	ANALYSER_HINT_STRING( lpFileName );

	/* If it's Win98 or NT4, just call LoadLibrary directly.  In theory
	   we could try a few further workarounds (see io/file.c) but in 
	   practice bending over backwards to fix search path issues under
	   Win98, which doesn't have ACLs to protect the files in the system
	   directory anyway, isn't going to achieve much, and in any case both
	   of these OSes should be long dead by now */
#if VC_LT_2010( _MSC_VER )
	if( getSysVar( SYSVAR_OSMAJOR ) <= 4 )
		return( LoadLibrary( lpFileName ) );
#else
	if( !IsWindowsXPOrGreater() )
		return( LoadLibrary( lpFileName ) );
#endif /* VC++ < 2010 */

	/* If it's already an absolute path, don't try and override it */
	if( lpFileName[ 0 ] == '/' || \
		lpFileName[ 0 ] == '\\' || \
		( fileNameLength >= 3 && isAlpha( lpFileName[ 0 ] ) && \
		  lpFileName[ 1 ] == ':' && \
		  ( lpFileName[ 2 ] == '/' || lpFileName[ 2 ] == '\\' ) ) )
		{
		return( LoadLibrary( lpFileName ) );
		}

	/* Load the DLL from the system directory */
	pathLength = \
		GetSystemDirectory( path, MAX_PATH - ( fileNameLength + 8 ) );
	if( pathLength < 3 || pathLength + fileNameLength > MAX_PATH - 8 )
		return( NULL );
	path[ pathLength++ ] = '\\';
	REQUIRES_N( boundsCheck( pathLength, fileNameLength, MAX_PATH ) );
	memcpy( path + pathLength, lpFileName, fileNameLength );
	path[ pathLength + fileNameLength ] = '\0';

	return( LoadLibrary( path ) );
	}
#endif /* Old/New SafeLoadLibrary() */

/* Windows NT-derived systems support ACL-based access control mechanisms 
   for system objects so when we create objects such as files and threads 
   we give them an ACL that allows only the creator access.  The following 
   functions return the security info needed when creating objects.  The 
   interface for this has changed in every major OS release, although it 
   never got any better, just differently ugly.  The following code uses the 
   original NT 3.1 interface, which works for all OS versions */

/* The size of the buffer for ACLs and the user token */

#define ACL_BUFFER_SIZE		1024
#define TOKEN_BUFFER_SIZE	256

/* A composite structure to contain the various ACL structures.  This is
   required because ACL handling is a complex, multistage operation that
   requires first creating an ACL and security descriptor to contain it,
   adding an access control entry (ACE) to the ACL, adding the ACL as the
   DACL of the security descriptor, and finally, wrapping the security
   descriptor up in a security attributes structure that can be passed to
   an object-creation function.

   The handling of the TOKEN_INFO is extraordinarily ugly because although
   the TOKEN_USER struct as defined is only 8 bytes long, Windoze allocates
   an extra 24 bytes after the end of the struct into which it stuffs data
   that the SID pointer in the TOKEN_USER struct points to.  This means that
   we can't statically allocate memory of the size of the TOKEN_USER struct
   but have to make it a pointer into a larger buffer that can contain the
   additional invisible data tacked onto the end */

typedef struct SECI {
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR pSecurityDescriptor;
	PACL pAcl;
	PTOKEN_USER pTokenUser;
	BYTE aclBuffer[ ACL_BUFFER_SIZE + 8 ];
	BYTE tokenBuffer[ TOKEN_BUFFER_SIZE + 8 ];
	} SECURITY_INFO;

/* Initialise an ACL allowing only the creator access and return it to the
   caller as an opaque value */

CHECK_RETVAL_PTR \
void *initACLInfo( const int access )
	{
	SECURITY_INFO *securityInfo;
	HANDLE hToken = INVALID_HANDLE_VALUE;	/* See comment below */
	BOOLEAN tokenOK = FALSE;

	REQUIRES_N( access > 0 );

	/* Allocate and initialise the composite security info structure */
	REQUIRES_N( isShortIntegerRangeNZ( sizeof( SECURITY_INFO ) ) );
	if( ( securityInfo = \
				clAlloc( "initACLInfo", sizeof( SECURITY_INFO ) ) ) == NULL )
		return( NULL );
	memset( securityInfo, 0, sizeof( SECURITY_INFO ) );
	securityInfo->pAcl = ( PACL ) securityInfo->aclBuffer;
	securityInfo->pTokenUser = ( PTOKEN_USER ) securityInfo->tokenBuffer;

	/* Get the security token for this thread.  First we try for the thread
	   token (which it typically only has when impersonating), if we don't
	   get that we use the token associated with the process.  We also
	   initialise the hToken (above) even though it shouldn't be necessary
	   because Windows tries to read its contents, which indicates there
	   might be problems if it happens to start out with the wrong value */
	if( OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken ) || \
		OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
		{
		DWORD cbTokenUser;

		tokenOK = GetTokenInformation( hToken, TokenUser,
									   securityInfo->pTokenUser,
									   TOKEN_BUFFER_SIZE, &cbTokenUser );
		CloseHandle( hToken );
		}
	if( !tokenOK )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Set a security descriptor owned by the current user */
	if( !InitializeSecurityDescriptor( &securityInfo->pSecurityDescriptor,
									   SECURITY_DESCRIPTOR_REVISION ) || \
		!SetSecurityDescriptorOwner( &securityInfo->pSecurityDescriptor,
									 securityInfo->pTokenUser->User.Sid,
									 FALSE ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Set up the discretionary access control list (DACL) with one access
	   control entry (ACE) for the current user */
	if( !InitializeAcl( securityInfo->pAcl, ACL_BUFFER_SIZE,
						ACL_REVISION ) || \
		!AddAccessAllowedAce( securityInfo->pAcl, ACL_REVISION, access,
							  securityInfo->pTokenUser->User.Sid ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	/* Bind the DACL to the security descriptor */
	if( !SetSecurityDescriptorDacl( &securityInfo->pSecurityDescriptor, TRUE,
									securityInfo->pAcl, FALSE ) )
		{
		clFree( "initACLInfo", securityInfo );
		return( NULL );
		}

	assert( IsValidSecurityDescriptor( &securityInfo->pSecurityDescriptor ) );

	/* Finally, set up the security attributes structure */
	securityInfo->sa.nLength = sizeof( SECURITY_ATTRIBUTES );
	securityInfo->sa.bInheritHandle = FALSE;
	securityInfo->sa.lpSecurityDescriptor = &securityInfo->pSecurityDescriptor;

	return( securityInfo );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void freeACLInfo( IN_PTR TYPECAST( SECURITY_INFO * ) \
					struct SECI *securityInfoPtr )
	{
	SECURITY_INFO *securityInfo = ( SECURITY_INFO * ) securityInfoPtr;

	assert( securityInfoPtr == NULL || \
			isWritePtr( securityInfoPtr, sizeof( SECURITY_INFO ) ) );

	if( securityInfo == NULL )
		return;
	clFree( "freeACLInfo", securityInfo );
	}

/* Extract the security info needed in Win32 API calls from the collection of
   security data that we set up earlier */

void *getACLInfo( INOUT_PTR_OPT TYPECAST( SECURITY_INFO * ) \
						struct SECI *securityInfoPtr )
	{
	SECURITY_INFO *securityInfo = ( SECURITY_INFO * ) securityInfoPtr;

	assert( securityInfo == NULL || \
			isWritePtr( securityInfo, sizeof( SECURITY_INFO ) ) );

	return( ( securityInfo == NULL ) ? NULL : &securityInfo->sa );
	}

/* The DLL entry point */

#if !( defined( NT_DRIVER ) || defined( STATIC_LIB ) )

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
	{
	UNUSED_ARG( hinstDLL );
	UNUSED_ARG( lpvReserved );

	/* Enable heap terminate-on-corruption.  In theory this could cause 
	   problems when cryptlib is linked with buggy applications that rely on 
	   the resilience of the heap manager in order to function since running 
	   the app with cryptlib will cause it to crash through no fault of 
	   cryptlib's, however this setting is enabled by default for all 64-bit
	   processes and all 32-bit processes that set the subsystem major version
	   to 6 or higher in the image header, so chances are it'll be enabled 
	   anyway */
#if VC_GE_2005( _MSC_VER )
	( void ) HeapSetInformation( NULL, HeapEnableTerminationOnCorruption,
								 NULL, 0 );
#endif /* VS 2005 and newer */

	switch( fdwReason )
		{
		case DLL_PROCESS_ATTACH:
			/* Disable thread-attach notifications, which we don't do
			   anything with and therefore don't need */
			DisableThreadLibraryCalls( hinstDLL );

			/* Set up the initialisation lock in the kernel */
			preInit();
			break;

		case DLL_PROCESS_DETACH:
			/* Delete the initialisation lock in the kernel */
			postShutdown();
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
		}

	return( TRUE );
	}

/* Idiot-proofing.  Yes, there really are people who'll try and register a
   straight DLL */

#ifndef MB_OK
  #define MB_OK					0x00000000L
  #define MB_ICONQUESTION		0x00000020L
  #define MB_ICONEXCLAMATION	0x00000030L
#endif /* MB_OK */

#ifndef _WIN64
  #pragma comment( linker, "/export:DllRegisterServer=_DllRegisterServer@0,PRIVATE" )
#endif /* Win64 */
#if defined( __MINGW32__ ) && !defined( STDAPI )
  #define STDAPI	HRESULT __stdcall
#endif /* MinGW without STDAPI defined */

STDAPI DllRegisterServer( void )
	{
	MessageBoxA( NULL, "Why are you trying to register the cryptlib DLL?\n"
				 "It's just a standard Windows DLL, there's nothing\nto be "
				 "registered.", "ESO Error",
				 MB_ICONQUESTION | MB_OK );
	return( E_NOINTERFACE );
	}
#endif /* !( NT_DRIVER || STATIC_LIB ) */

#if VC_LE_VC6( _MSC_VER ) || VC_GE_2019( _MSC_VER )

/* Under VC++ 6 assert() can randomly stop working so that only the abort() 
   portion still functions, making it impossible to find out what went wrong.
   Under VS 2019, assert() still functions but reports the location where the
   assert was triggered as some random location somewhere in cryptlib, 
   requiring tedious stepping through each line of code to find out where 
   the actuall assertion occurred.

   To deal with this, misc/debug.h redefines the assert() macro to call the 
   following function, which emulates what a correctly-functioning assert()
   would do */

#ifndef MB_OKCANCEL
  #define MB_OKCANCEL			0x00000001L
#endif /* MB_OKCANCEL */
#ifndef MB_YESNOCANCEL
  #define MB_YESNOCANCEL		0x00000003L
#endif /* MB_YESNOCANCEL */
#ifndef MB_ICONEXCLAMATION
  #define MB_ICONEXCLAMATION	0x00000030L
#endif /* MB_ICONEXCLAMATION */

void vsAssert( const char *exprString, const char *fileName, 
			   const int lineNo )
	{
	char string[ 1024 ], title[ 1024 ];
	int result;

	/* Log the output to the debug console */
	DEBUG_PRINT(( "Assertion failed in %s:%d, '%s'.\n", fileName, lineNo, exprString ));

	/* Emulate the standard assert() functionality.  Note that the spurious 
	   spaces in the last line of the message are to ensure that the title
	   text doesn't get truncated, since the message box width is determined 
	   by the text in the dialog rather than the title length */
	sprintf_s( string, 1024, "File %s, line %d:\n\n  '%s'.\n\n"
			   "Yes to debug, no to continue, cancel to exit.                  ", 
			   fileName, lineNo, exprString );
	sprintf_s( title, 1024, "Assertion failed, file %s, line %d", 
			   fileName, lineNo );
	result = MessageBoxA( NULL, string, title, 
						  MB_ICONEXCLAMATION | MB_YESNOCANCEL );
	if( result == IDCANCEL )
		{
		/* If the user wants to exit without further debugging, exit 
		   immediately.  We don't call the more usual abort() because that
		   throws up another dialog asking more or less the same thing as 
		   our assert() dialog just did */
		exit( EXIT_FAILURE );
		}
	if( result == IDYES )
		DebugBreak();
	}
#endif /* VC++ 6.0 || VS 2019 */

/* Borland's archaic compilers don't recognise DllMain() but still use the
   OS/2-era DllEntryPoint(), so we have to alias it to DllMain() in order
   for things to be initialised properly */

#if defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x550 )

BOOL WINAPI DllEntryPoint( HINSTANCE hinstDLL, DWORD fdwReason, 
						   LPVOID lpvReserved )
	{
	return( DllMain( hinstDLL, fdwReason, lpvReserved ) );
	}
#endif /* BC++ */

#elif defined( __WIN16__ )

/* WinMain() and WEP() under Win16 are intended for DLL initialisation,
   however it isn't possible to reliably do anything terribly useful in these
   routines.  The reason for this is that the WinMain/WEP functions are
   called by the windows module loader, which has a very limited workspace
   and can cause peculiar behaviour for some functions (allocating/freeing
   memory and loading other modules from these routines is unreliable), the
   order in which WinMain() and WEP() will be called for a set of DLL's is
   unpredictable (sometimes WEP doesn't seem to be called at all), and they
   can't be tracked by a standard debugger.  This is why MS have
   xxxRegisterxxx() and xxxUnregisterxxx() functions in their DLL's.

   Under Win16 on a Win32 system this isn't a problem because the module
   loader has been rewritten to work properly, but it isn't possible to get
   reliable performance under pure Win16, so the DLL entry/exit routines here
   do almost nothing, with the real work being done in cryptInit()/
   cryptEnd() */

HWND hInst;

int CALLBACK LibMain( HINSTANCE hInstance, WORD wDataSeg, WORD wHeapSize, 
					  LPSTR lpszCmdLine )
	{
	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

int CALLBACK WEP( int nSystemExit )
	{
	switch( nSystemExit )
		{
		case WEP_SYSTEM_EXIT:
			/* System is shutting down */
			break;

		case WEP_FREE_DLL:
			/* DLL reference count = 0, DLL-only shutdown */
			break;
		}

	return( TRUE );
	}

/* Check whether we're running inside a VM, which is a potential risk for
   cryptovariables.  It gets quite tricky to detect the various VMs so for
   now the only one that we detect is the most widespread one, VMware */

#if defined( __WIN32__ ) && !defined( NO_ASM )

BOOLEAN isRunningInVM( void )
	{
	unsigned int magicValue, version;

	__try {
	__asm {
		push eax
		push ebx
		push ecx
		push edx

		/* Check for VMware via the VMware guest-to-host communications 
		   channel */
		mov eax, 'VMXh'		/* VMware magic value 0x564D5868 */
		xor ebx, ebx		/* Clear parameters register */
		mov ecx, 0Ah		/* Get-version command */
		mov dx, 'VX'		/* VMware I/O port 0x5658 */
		in eax, dx			/* Perform VMware call */
		mov magicValue, ebx	/* VMware magic value */
		mov version, ecx	/* VMware version */

		pop edx
		pop ecx
		pop ebx
		pop eax
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {}

	return( magicValue == 'VMXh' ) ? TRUE : FALSE );
	}
#else

BOOLEAN isRunningInVM( void )
	{
	return( FALSE );
	}
#endif /* __WIN32__ && !NO_ASM */

/****************************************************************************
*																			*
*									Windows CE								*
*																			*
****************************************************************************/

#elif defined( __WINCE__ )

/* Windows CE doesn't provide ANSI standard time functions (although it'd be
   relatively easy to do so, and they are in fact provided in MFC), so we
   have to provide our own */

CHECK_RETVAL \
static LARGE_INTEGER *getTimeOffset( void )
	{
	static LARGE_INTEGER timeOffset = { 0 };

	/* Get the difference between the ANSI/ISO C time epoch and the Windows
	   time epoch if we haven't already done so (we could also hardcode this
	   in as 116444736000000000LL) */
	if( timeOffset.QuadPart == 0 )
		{
		SYSTEMTIME ofsSystemTime;
		FILETIME ofsFileTime;

		memset( &ofsSystemTime, 0, sizeof( SYSTEMTIME ) );
		ofsSystemTime.wYear = 1970;
		ofsSystemTime.wMonth = 1;
		ofsSystemTime.wDay = 1;
		SystemTimeToFileTime( &ofsSystemTime, &ofsFileTime );
		timeOffset.HighPart = ofsFileTime.dwHighDateTime;
		timeOffset.LowPart = ofsFileTime.dwLowDateTime;
		}

	return( &timeOffset );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static time_t fileTimeToTimeT( const FILETIME *fileTime )
	{
	const LARGE_INTEGER *timeOffset = getTimeOffset();
	LARGE_INTEGER largeInteger;

	/* Convert a Windows FILETIME to a time_t by dividing by
	   10,000,000 (to go from 100ns ticks to 1s ticks) */
	largeInteger.HighPart = fileTime->dwHighDateTime;
	largeInteger.LowPart = fileTime->dwLowDateTime;
	largeInteger.QuadPart = ( largeInteger.QuadPart - \
							  timeOffset->QuadPart ) / 10000000L;
	if( sizeof( time_t ) == 4 && \
		largeInteger.QuadPart > 0x80000000UL )
		{
		/* time_t is 32 bits but the converted time is larger than a 32-bit
		   signed value, indicate that we couldn't convert it.  In theory
		   we could check for largeInteger.HighPart == 0 and perform a
		   second check to see if time_t is unsigned, but it's unlikely that
		   this change would be made to the VC++ runtime time_t since it'd
		   break too many existing apps */
		return( -1 );
		}
	return( ( time_t ) largeInteger.QuadPart );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static void timeTToFileTime( FILETIME *fileTime, const time_t timeT )
	{
	const LARGE_INTEGER *timeOffset = getTimeOffset();
	LARGE_INTEGER largeInteger = { timeT };

	/* Convert a time_t to a Windows FILETIME by multiplying by
	   10,000,000 (to go from 1s ticks to 100ns ticks) */
	largeInteger.QuadPart = ( largeInteger.QuadPart * 10000000L ) + \
							timeOffset->QuadPart;
	fileTime->dwHighDateTime = largeInteger.HighPart;
	fileTime->dwLowDateTime = largeInteger.LowPart;
	}

time_t time( time_t *timePtr )
	{
	FILETIME fileTime;
#ifdef __WINCE__
	SYSTEMTIME systemTime;
#endif /* __WINCE__ */

	assert( timePtr == NULL );

	/* Get the time via GetSystemTimeAsFileTime().  Windows CE doesn't have
	   the unified call so we have to assemble it from discrete calls */
#ifdef __WINCE__
	GetSystemTime( &systemTime );
	SystemTimeToFileTime( &systemTime, &fileTime );
#else
	GetSystemTimeAsFileTime( &fileTime );
#endif /* Win32 vs. WinCE */

	return( fileTimeToTimeT( &fileTime ) );
	}

time_t mktime( struct tm *tmStruct )
	{
	SYSTEMTIME systemTime;
	FILETIME fileTime;

	assert( isWritePtr( tmStruct, sizeof( struct tm ) ) );

	/* Use SystemTimeToFileTime() as a mktime() substitute.  The input time
	   seems to be treated as local time, so we have to convert it to GMT
	   before we return it */
	memset( &systemTime, 0, sizeof( SYSTEMTIME ) );
	systemTime.wYear = tmStruct->tm_year + 1900;
	systemTime.wMonth = tmStruct->tm_mon + 1;
	systemTime.wDay = tmStruct->tm_mday;
	systemTime.wHour = tmStruct->tm_hour;
	systemTime.wMinute = tmStruct->tm_min;
	systemTime.wSecond = tmStruct->tm_sec;
	SystemTimeToFileTime( &systemTime, &fileTime );
	LocalFileTimeToFileTime( &fileTime, &fileTime );

	return( fileTimeToTimeT( &fileTime ) );
	}

struct tm *gmtime( const time_t *timePtr )
	{
	static struct tm tmStruct;
	SYSTEMTIME systemTime;
	FILETIME fileTime;

	assert( isReadPtr( timePtr, sizeof( time_t ) ) );

	/* Use FileTimeToSystemTime() as a gmtime() substitute.  Note that this
	   function, like its original ANSI/ISO C counterpart, is not thread-
	   safe */
	timeTToFileTime( &fileTime, *timePtr );
	FileTimeToSystemTime( &fileTime, &systemTime );
	memset( &tmStruct, 0, sizeof( struct tm ) );
	tmStruct.tm_year = systemTime.wYear - 1900;
	tmStruct.tm_mon = systemTime.wMonth - 1;
	tmStruct.tm_mday = systemTime.wDay;
	tmStruct.tm_hour = systemTime.wHour;
	tmStruct.tm_min = systemTime.wMinute;
	tmStruct.tm_sec = systemTime.wSecond;

	return( &tmStruct );
	}

/* When running in debug mode we provide a debugging printf() that sends its 
   output to the debug console.  This is normally done via a macro in a 
   header file that remaps the debug-output macros to the appropriate 
   function, but WinCE's NKDbgPrintfW() requires widechar strings that 
   complicate the macros so we provide a function that performs the 
   conversion before outputting the text */

#if !defined( NDEBUG )

int debugPrintf( const char *format, ... )
	{
	va_list argPtr;
	char buffer[ 1024 ];
	wchar_t wcBuffer[ 1024 ];
	int length, status;

	va_start( argPtr, format );
	length = vsprintf( buffer, format, argPtr );
	va_end( argPtr );
	status = asciiToUnicode( wcBuffer, 1024, buffer, length );
	if( cryptStatusOK( status ) )
		NKDbgPrintfW( L"%s", wcBuffer );
	return( length );
	}
#endif /* Debug build */

/* Windows CE systems need to convert characters from ASCII <-> Unicode
   before/after they're read/written to external formats, the following
   functions perform the necessary conversion.

   winnls.h was already included via the global include of windows.h, however
   it isn't needed for any other part of cryptlib so it was disabled via
   NONLS.  Since winnls.h is now locked out, we have to un-define the guards
   used earlier to get it included */

#undef _WINNLS_
#undef NONLS
#include <winnls.h>

int asciiToUnicode( wchar_t *dest, const int destMaxLen, 
					const char *src, const int length )
	{
	int status;

	assert( isReadPtrDynamic( src, length ) );
	assert( isWritePtrDynamic( dest, destMaxLen ) );

	/* Note that this function doens't terminate the string if the output is 
	   filled, so it's essential that the caller check the return value to 
	   ensure that they're getting a well-formed string */
	status = MultiByteToWideChar( GetACP(), 0, src, destMaxLen, dest, 
								  length );
	return( status <= 0 ? CRYPT_ERROR_BADDATA : status * sizeof( wchar_t ) );
	}

int unicodeToAscii( char *dest, const int destMaxLen, 
					const wchar_t *src, const int length )
	{
	size_t destLen;
	int status;

	assert( isReadPtrDynamic( src, length ) );
	assert( isWritePtrDynamic( dest, destMaxLen ) );

	/* Convert the string, overriding the system default char '?', which
	   causes problems if the output is used as a filename.  This function
	   has stupid semantics in that instead of returning the number of bytes
	   written to the output it returns the number of bytes specified as
	   available in the output buffer, zero-filling the rest (in addition as 
	   for MultiByteToWideChar() it won't terminate the string if the output 
	   is filled).  Because there's no way to tell how long the resulting 
	   string actually is we have to use wcstombs() instead, which is 
	   unfortunate because there's nothing that we can do with the maxLength 
	   parameter */
#if 0
	status = WideCharToMultiByte( GetACP(), 0, src, length, dest,
								  length * sizeof( wchar_t ), "_", NULL );
	return( ( status <= 0 ) ? CRYPT_ERROR_BADDATA : wcslen( dest ) );
#else
	status = wcstombs_s( &destLen, dest, destMaxLen, src, 
						 length * sizeof( wchar_t ) );
	return( ( status <= 0 ) ? CRYPT_ERROR_BADDATA : status );
#endif
	}

BOOL WINAPI DllMain( HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved )
	{
	UNUSED_ARG( hinstDLL );
	UNUSED_ARG( lpvReserved );

	switch( dwReason )
		{
		case DLL_PROCESS_ATTACH:
			/* Disable thread-attach notifications, which we don't do
			   anything with and therefore don't need */
			DisableThreadLibraryCalls( hinstDLL );

			/* Set up the initialisation lock in the kernel */
			preInit();
			break;

		case DLL_PROCESS_DETACH:
			/* Delete the initialisation lock in the kernel */
			postShutdown();
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
		}

	return( TRUE );
	}
#endif /* OS-specific support */

/****************************************************************************
*																			*
*							String Function Support							*
*																			*
****************************************************************************/

/* Match a given substring against a string in a case-insensitive manner.
   If possible we use native calls to handle this since they deal with
   charset-specific issues such as collating sequences, however a few OSes
   don't provide this functionality so we have to do it ourselves.
   
   The length argument to strnicmp() should be const, but we make it non-
   const for compatibility with everyone else's strnicmp() */

#ifdef NO_NATIVE_STRICMP

int strnicmp( const char *src, const char *dest, /* const */ int length )
	{
	LOOP_INDEX i;

	assert( isReadPtrDynamic( src, length ) );

	LOOP_MAX( i = 0, i < length, i++ )
		{
		const int srcCh = toUpper( *src );
		const int destCh = toUpper( *dest );

		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, length - 1 ), -1 );

		/* Need to be careful calling toupper() with side-effects */
		src++, dest++;

		if( srcCh != destCh )
			return( srcCh - destCh );
		}
	ENSURES_EXT( LOOP_BOUND_OK, -1 );

	return( 0 );
	}

int stricmp( const char *src, const char *dest )
	{
	const int length = strlen( src );

	if( length != strlen( dest ) )
		return( 1 );	/* Lengths differ */
	return( strnicmp( src, dest, length ) );
	}
#endif /* NO_NATIVE_STRICMP */

/****************************************************************************
*																			*
*						Minimal Safe String Function Support				*
*																			*
****************************************************************************/

#ifdef NO_NATIVE_STRLCPY

/* Copy and concatenate a string, truncating it if necessary to fit the 
   destination buffer.  Unfortunately the TR 24731 functions don't do this,
   while the OpenBSD safe-string functions do (but don't implement any of
   the rest of the TR 24731 functionality).  Because the idiot maintainer
   of glibc objects to these functions (even Microsoft recognise their
   utility with the _TRUNCATE semantics for strcpy_s/strcat_s), everyone has 
   to manually implement them in their code, as we do here.
   
   Note that these aren't completely identical to the OpenBSD functions, in 
   order to fit the TR 24731 pattern we make the length the second paramter, 
   and give them a TR 24731-like _s suffix to make them distinct from the 
   standard OpenBSD ones (a macro in os_spec.h is sufficient to map this to 
   the proper functions where they're available in libc).
   
   In addition they always return 1, since the length value isn't checked
   anywhere in the code  */

int strlcpy_s( char *dest, const int destLen, const char *src )
	{
	LOOP_INDEX i;

	assert( isWritePtrDynamic( dest, destLen ) );
	assert( isShortIntegerRangeNZ( destLen ) );
	assert( isReadPtr( src, 1 ) );

	/* Copy as much as we can of the source string onto the end of the 
	   destination string */
	LOOP_MAX( i = 0, i < destLen - 1 && *src != '\0', i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, destLen - 2 ), 1 );

		dest[ i ] = *src++;
		}
	ENSURES_EXT( LOOP_BOUND_OK, 1 );
	dest[ i ] = '\0';

	return( 1 );
	}

int strlcat_s( char *dest, const int destLen, const char *src )
	{
	LOOP_INDEX i;

	assert( isWritePtrDynamic( dest, destLen ) );
	assert( isShortIntegerRangeNZ( destLen ) );
	assert( isReadPtr( src, 1 ) );

	/* See how long the existing destination string is */
	LOOP_MAX( i = 0, i < destLen && dest[ i ] != '\0', i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX( i, 0, destLen - 1 ), 1 );
		}
	ENSURES_EXT( LOOP_BOUND_OK, 1 );
	if( i >= destLen )
		{
		DEBUG_DIAG(( "Overflow in strlcat_s" ));
		assert( DEBUG_WARN );
		dest[ destLen - 1 ] = '\0';

		return( 1 );
		}

	/* Copy as much as we can of the source string onto the end of the 
	   destination string */
	LOOP_MAX_CHECKINC( i < destLen - 1 && *src != '\0', i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_MAX_XXX( i, 0, destLen - 2 ), 1 );

		dest[ i ] = *src++;
		}
	ENSURES_EXT( LOOP_BOUND_OK, 1 );
	dest[ i ] = '\0';

	return( 1 );
	}
#endif /* NO_NATIVE_STRLCPY */

/****************************************************************************
*																			*
*								SysVars Support								*
*																			*
****************************************************************************/

#if defined( __WIN32__ )  && \
	!( defined( _M_X64 ) || defined( __MINGW32__ ) || defined( NO_ASM ) )

#ifndef PF_RDTSC_INSTRUCTION_AVAILABLE
  #define PF_RDTSC_INSTRUCTION_AVAILABLE	8
#endif /* !PF_RDTSC_INSTRUCTION_AVAILABLE */

CHECK_RETVAL_ENUM( HWINTRINS_FLAG ) \
static int getHWIntrins( void )
	{
	char vendorID[ 12 + 8 ];
	unsigned long processorID, featureFlags, featureFlags2;
	int sysCaps = HWINTRINS_FLAG_RDTSC;

	/* Check whether the CPU supports extended features like CPUID and 
	   RDTSC, and get any info that we need related to this.  
	   IsProcessorFeaturePresent() only provides information about the
	   availability of rdtsc(), but we use this as a proxy for the
	   availability of cpuid which saves having to use a pile of low-
	   level asm code */
	if( !IsProcessorFeaturePresent( PF_RDTSC_INSTRUCTION_AVAILABLE ) )
		return( HWINTRINS_FLAG_NONE );

	/* We have CPUID, see what else we've got */
	__asm {
		push ebx			/* Save frame pointer, trashed by cpuid */
		xor ecx, ecx
		xor edx, edx		/* Tell VC++ that ECX, EDX will be trashed */
		xor eax, eax		/* CPUID function 0: Get vendor ID */
		cpuid
		mov dword ptr [vendorID], ebx
		mov dword ptr [vendorID+4], edx
		mov dword ptr [vendorID+8], ecx	/* Save vendor ID string */
		mov eax, 1			/* CPUID function 1: Get processor info */
		cpuid
		mov [processorID], eax	/* Save processor ID */
		mov [featureFlags], ecx	/* Save processor feature info */
		mov [featureFlags2], ebx/* Save extended feature info */
		pop ebx				/* Restore frame pointer */
		}

	/* If there's a vendor ID present, check for vendor-specific special
	   features */
	if( !memcmp( vendorID, "CentaurHauls", 12 ) )
		{
	__asm {
		push ebx			/* Save frame pointer, trashed by cpuid */
		xor ebx, ebx
		xor ecx, ecx		/* Tell VC++ that EBX, ECX will be trashed */
		mov eax, 0xC0000000	/* Centaur extended CPUID info */
		cpuid
		cmp eax, 0xC0000001	/* Need at least release 2 ext.feature set */
		jb endCheck			/* No extended info available */
		mov eax, 0xC0000001	/* Centaur extended feature flags */
		cpuid
		mov eax, edx		/* Work with saved copy of feature flags */
		and eax, 01100b
		cmp eax, 01100b		/* Check for RNG present + enabled flags */
		jz noRNG			/* No, RNG not present or enabled */
		or [sysCaps], HWINTRINS_FLAG_XSTORE	/* Remember that we have a HW RNG */
	noRNG:
		mov eax, edx
		and eax, 011000000b
		cmp eax, 011000000b	/* Check for ACE present + enabled flags */
		jz noACE			/* No, ACE not present or enabled */
		or [sysCaps], HWINTRINS_FLAG_XCRYPT	/* Remember that we have HW AES */
	noACE:
		mov eax, edx
		and eax, 0110000000000b
		cmp eax, 0110000000000b	/* Check for PHE present + enabled flags */
		jz noPHE			/* No, PHE not present or enabled */
		or [sysCaps], HWINTRINS_FLAG_XSHA	/* Remember that we have HW SHA-1/SHA-2 */
	noPHE:
		mov eax, edx
		and eax, 011000000000000b
		cmp eax, 011000000000000b /* Check for PMM present + enabled flags */
		jz endCheck			/* No, PMM not present or enabled */
		or [sysCaps], HWINTRINS_FLAG_MONTMUL	/* Remember that we have HW bignum */
	endCheck:
		pop ebx				/* Restore frame pointer */
		}
		}
	if( !memcmp( vendorID, "AuthenticAMD", 12 ) )
		{
		/* Check for AMD Geode LX, family 0x5 = Geode, model 0xA = LX */
		if( ( processorID & 0x0FF0 ) == 0x05A0 )
			sysCaps |= HWINTRINS_FLAG_TRNG;

		/* Check for the presence of a hardware RNG */
		if( featureFlags & ( 1 << 30 ) )
			sysCaps |= HWINTRINS_FLAG_RDRAND;
		}
	if( !memcmp( vendorID, "GenuineIntel", 12 ) )
		{
		/* Check for hardware AES support */
		if( featureFlags & ( 1 << 25 ) )
			sysCaps |= HWINTRINS_FLAG_AES;

		/* Check for the presence of a hardware RNG */
		if( featureFlags & ( 1 << 30 ) )
			sysCaps |= HWINTRINS_FLAG_RDRAND;
		if( featureFlags2 & ( 1 << 18 ) )
			sysCaps |= HWINTRINS_FLAG_RDSEED;
		}

	return( sysCaps );
	}

#elif defined( __WIN32__ )  && defined( _M_X64 )

/* 64-bit VC++ doesn't allow inline asm, but does provide the __cpuid() 
   builtin to perform the operation above.  We don't guard this with the 
   NO_ASM check because it's not (technically) done with inline asm, 
   although it's a bit unclear whether an intrinsic qualifies as asm or
   C */

#pragma intrinsic( __cpuid )

typedef struct { unsigned int eax, ebx, ecx, edx; } CPUID_INFO;

STDC_NONNULL_ARG( ( 1 ) ) \
static void cpuID( OUT_PTR CPUID_INFO *result, const int type )
	{
	int intResult[ 4 ];	/* That's what the function prototype says */

	/* Clear return value */
	memset( result, 0, sizeof( CPUID_INFO ) );

	/* Get the CPUID data and copy it back to the caller.  We clear it 
	   before calling the __cpuid intrinsic because some analysers don't 
	   know about it and will warn about use of uninitialised memory */
	memset( intResult, 0, sizeof( int ) * 4 );
	__cpuid( intResult, type );
	result->eax = intResult[ 0 ];
	result->ebx = intResult[ 1 ];
	result->ecx = intResult[ 2 ];
	result->edx = intResult[ 3 ];
	}

CHECK_RETVAL_ENUM( HWINTRINS_FLAG ) \
static int getHWIntrins( void )
	{
	CPUID_INFO cpuidInfo;
	char vendorID[ 12 + 8 ];
	int *vendorIDptr = ( int * ) vendorID;
	unsigned long processorID, featureFlags, featureFlags2;
	int sysCaps = HWINTRINS_FLAG_RDTSC;	/* x86-64 always has RDTSC */

	/* Get any CPU info that we need.  There is an 
	   IsProcessorFeaturePresent() function, but all that this provides is 
	   an indication of the availability of rdtsc (alongside some stuff that 
	   we don't care about, like MMX and 3DNow).  Since we still need to 
	   check for the presence of other features, we do the whole thing 
	   ourselves */
	cpuID( &cpuidInfo, 0 );
	vendorIDptr[ 0 ] = cpuidInfo.ebx;
	vendorIDptr[ 1 ] = cpuidInfo.edx;
	vendorIDptr[ 2 ] = cpuidInfo.ecx;
	cpuID( &cpuidInfo, 1 );
	processorID = cpuidInfo.eax;
	featureFlags = cpuidInfo.ecx;
	featureFlags2 = cpuidInfo.ebx;

	/* Check for vendor-specific special features */
	if( !memcmp( vendorID, "CentaurHauls", 12 ) )
		{
		/* Get the Centaur extended CPUID info and check whether the feature-
		   flags read capability is present.  VIA only announced their 64-
		   bit CPUs in mid-2010 and availability is limited so it's 
		   uncertain whether this code will ever be exercised, but we provide 
		   it anyway for compatibility with the 32-bit equivalent */
		cpuID( &cpuidInfo, 0xC0000000 );
		if( cpuidInfo.eax >= 0xC0000001 )
			{
			/* Get the Centaur extended feature flags */
			cpuID( &cpuidInfo, 0xC0000001 );
			if( ( cpuidInfo.edx & 0x000C ) == 0x000C )
				sysCaps |= HWINTRINS_FLAG_XSTORE;
			if( ( cpuidInfo.edx & 0x00C0 ) == 0x00C0 )
				sysCaps |= HWINTRINS_FLAG_XCRYPT;
			if( ( cpuidInfo.edx & 0x0C00 ) == 0x0C00 )
				sysCaps |= HWINTRINS_FLAG_XSHA;
			if( ( cpuidInfo.edx & 0x3000 ) == 0x3000 )
				sysCaps |= HWINTRINS_FLAG_MONTMUL;
			}
		}
	if( !memcmp( vendorID, "AuthenticAMD", 12 ) )
		{
		/* Check for AMD Geode LX, family 0x5 = Geode, model 0xA = LX */
		if( ( processorID & 0x0FF0 ) == 0x05A0 )
			sysCaps |= HWINTRINS_FLAG_TRNG;
		}
	if( !memcmp( vendorID, "GenuineIntel", 12 ) )
		{
		/* Check for hardware AES support */
		if( featureFlags & ( 1 << 25 ) )
			sysCaps |= HWINTRINS_FLAG_AES;

		/* Check for the return of a hardware RNG */
		if( featureFlags & ( 1 << 30 ) )
			sysCaps |= HWINTRINS_FLAG_RDRAND;
		if( featureFlags2 & ( 1 << 18 ) )
			sysCaps |= HWINTRINS_FLAG_RDSEED;
		}

	return( sysCaps );
	}

#elif ( defined( __clang__ ) || \
		( defined( __GNUC__ ) && \
		  ( ( __GNUC__ > 4 ) || \
			( __GNUC__ == 4 && __GNUC_MINOR__ >= 4 ) ) ) ) && \
	  ( defined( __i386__ ) || defined( __x86_64__ ) )

/* clang and newer versions of gcc have cpuid as an intrinsic */

#if HWINTRINS_FLAG_RDTSC != 0x01
  #error Need to sync HWINTRINS_FLAG_RDTSC with equivalent asm definition
#endif /* HWINTRINS_FLAG_RDTSC */

#include <cpuid.h>

typedef struct { unsigned int eax, ebx, ecx, edx; } CPUID_INFO;

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN cpuID_Checked( OUT_PTR CPUID_INFO *result, const int type )
	{
	int a, b, c, d;		/* That's what the function prototype says */
	int retVal;

	assert( isWritePtr( result, sizeof( CPUID_INFO ) ) );

	/* Clear return value */
	memset( result, 0, sizeof( CPUID_INFO ) );

	/* Get the CPUID data and copy it back to the caller */
	retVal = __get_cpuid( type, &a, &b, &c, &d );
	if( retVal <= 0 )
		return( FALSE );
	result->eax = a;
	result->ebx = b;
	result->ecx = c;
	result->edx = d;

	return( TRUE );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
static void cpuID( OUT_PTR CPUID_INFO *result, const int type )
	{
	int a, b, c, d;		/* That's what the function prototype says */

	/* The GNU __get_cpuid() is broken, see
	   https://github.com/gcc-mirror/gcc/blob/master/gcc/config/i386/cpuid.h,
	   it's implemented as:

		__get_cpuid (unsigned int __leaf,
					 unsigned int *__eax, unsigned int *__ebx,
					 unsigned int *__ecx, unsigned int *__edx)
			{
			unsigned int __ext = __leaf & 0x80000000;
			unsigned int __maxlevel = __get_cpuid_max (__ext, 0);

			if (__maxlevel == 0 || __maxlevel < __leaf)
				return 0;

	   Since the high bit is masked, it can never work for any query on 
	   extended attributes like VIA's 0xC000000x ones since __maxlevel will 
	   always be less than the 0xC000000x that we want to query on.  To deal 
	   with this we call the lower-level __cpuid() directly, bypassing the 
	   broken wrapper */
	__cpuid( type, a, b, c, d );
	result->eax = a;
	result->ebx = b;
	result->ecx = c;
	result->edx = d;
	}

CHECK_RETVAL_ENUM( HWINTRINS_FLAG ) \
static int getHWIntrins( void )
	{
	CPUID_INFO cpuidInfo;
	char vendorID[ 12 + 8 ];
	int *vendorIDptr = ( int * ) vendorID;
	unsigned long processorID, featureFlags, featureFlags2;
	int sysCaps = 0;

	/* Get any CPU info that we need */
	if( !cpuID_Checked( &cpuidInfo, 0 ) )	/* CPUID function 0: Get vendor ID */
		return( HWINTRINS_FLAG_NONE );
	vendorIDptr[ 0 ] = cpuidInfo.ebx;
	vendorIDptr[ 1 ] = cpuidInfo.edx;
	vendorIDptr[ 2 ] = cpuidInfo.ecx;
	if( !cpuID_Checked( &cpuidInfo, 1 ) )	/* CPUID function 1: Get processor info */
		return( HWINTRINS_FLAG_NONE );
	processorID = cpuidInfo.eax;
	featureFlags = cpuidInfo.ecx;
	featureFlags2 = cpuidInfo.ebx;

	/* Check for vendor-specific special features */
	if( !memcmp( vendorID, "CentaurHauls", 12 ) )
		{
		/* Get the Centaur extended CPUID info and check whether the feature-
		   flags read capability is present */
		cpuID( &cpuidInfo, 0xC0000000 );
		if( cpuidInfo.eax >= 0xC0000001 )
			{
			/* Get the Centaur extended feature flags */
			cpuID( &cpuidInfo, 0xC0000001 );
			if( ( cpuidInfo.edx & 0x000C ) == 0x000C )
				sysCaps |= HWINTRINS_FLAG_XSTORE;
			if( ( cpuidInfo.edx & 0x00C0 ) == 0x00C0 )
				sysCaps |= HWINTRINS_FLAG_XCRYPT;
			if( ( cpuidInfo.edx & 0x0C00 ) == 0x0C00 )
				sysCaps |= HWINTRINS_FLAG_XSHA;
			if( ( cpuidInfo.edx & 0x3000 ) == 0x3000 )
				sysCaps |= HWINTRINS_FLAG_MONTMUL;
			}
		}
	if( !memcmp( vendorID, "AuthenticAMD", 12 ) )
		{
		/* Check for AMD Geode LX, family 0x5 = Geode, model 0xA = LX */
		if( ( processorID & 0x0FF0 ) == 0x05A0 )
			sysCaps |= HWINTRINS_FLAG_TRNG;
		}
	if( !memcmp( vendorID, "GenuineIntel", 12 ) )
		{
		/* Check for hardware AES support */
		if( featureFlags & ( 1 << 25 ) )
			sysCaps |= HWINTRINS_FLAG_AES;

		/* Check for the return of a hardware RNG */
		if( featureFlags & ( 1 << 30 ) )
			sysCaps |= HWINTRINS_FLAG_RDRAND;
		if( featureFlags2 & ( 1 << 18 ) )
			sysCaps |= HWINTRINS_FLAG_RDSEED;
		}

	return( sysCaps );
	}

#elif defined( __GNUC__ ) && ( __GNUC__ >= 3 ) && \
	  defined( __i386__ ) && !defined( NO_ASM )

/* Fallback inline asm cpuid support */

#if HWINTRINS_FLAG_RDTSC != 0x01
  #error Need to sync HWINTRINS_FLAG_RDTSC with equivalent asm definition
#endif /* HWINTRINS_FLAG_RDTSC */

CHECK_RETVAL_ENUM( HWINTRINS_FLAG ) \
static int getHWIntrins( void )
	{
	char vendorID[ 12 + 8 ];
	unsigned long processorID, featureFlags, featureFlags2;
	int hasAdvFeatures = 0, sysCaps = 0;

	/* Check whether the CPU supports extended features like CPUID and 
	   RDTSC, and get any info that we need related to this.  The use of ebx 
	   is a bit problematic because gcc (via the IA32 ABI) uses ebx to store 
	   the address of the global offset table and gets rather upset if it 
	   gets changed, so we have to save/restore it around the cpuid call.  
	   We have to be particularly careful here because ebx is used 
	   implicitly in references to sysCaps (which is a static int), so we 
	   save it as close to the cpuid instruction as possible and restore it 
	   immediately afterwards, away from any memory-referencing instructions 
	   that implicitly use ebx */
	asm volatile( "pushf\n\t"
		"popl %%eax\n\t"
		"movl %%eax, %%ecx\n\t"
		"xorl $0x200000, %%eax\n\t"
		"pushl %%eax\n\t"
		"popf\n\t"
		"pushf\n\t"
		"popl %%eax\n\t"
		"pushl %%ecx\n\t"
		"popf\n\t"
		"xorl %%ecx, %%eax\n\t"
		"jz noCPUID\n\t"
		"movl $1, %[hasAdvFeatures]\n\t"/* hasAdvFeatures = TRUE */
		"movl %[HW_FLAG_RDTSC], %[sysCaps]\n\t"		/* sysCaps = HWINTRINS_FLAG_RDTSC */
		"pushl %%ebx\n\t"	/* Save PIC register */
		"xorl %%eax, %%eax\n\t"	/* CPUID function 0: Get vendor ID */
		"cpuid\n\t"
		"leal %2, %%eax\n\t"
		"movl %%ebx, (%%eax)\n\t"
		"movl %%edx, 4(%%eax)\n\t"
		"movl %%ecx, 8(%%eax)\n\t"
		"movl $1, %%eax\n\t"	/* CPUID function 1: Get processor info */
		"cpuid\n\t"
		"leal %3, %%edx\n\t"
		"movl %%eax, (%%edx)\n\t"	/* processorID */
		"leal %4, %%edx\n\t"
		"movl %%ecx, (%%edx)\n\t"	/* featureFlags */
		"leal %5, %%edx\n\t"
		"movl %%ebx, (%%edx)\n\t"	/* featureFlags2 */
		"popl %%ebx\n"		/* Restore PIC register */
	"noCPUID:\n\n"
#if 0	/* See comment in tools/ccopts.sh for why this is disabled */
		".section .note.GNU-stack, \"\", @progbits; .previous\n"
							/* Mark the stack as non-executable.  This is
							   undocumented outside of mailing-list postings
							   and a bit hit-and-miss, but having at least
							   one of these in included asm code doesn't
							   hurt */
#endif /* 0 */
		: [hasAdvFeatures] "=m"(hasAdvFeatures),/* Output */
			[sysCaps] "=m"(sysCaps),
			[vendorID] "=m"(vendorID), 
			[processorID] "=m"(processorID),
			[featureFlags] "=m"(featureFlags),
			[featureFlags2] "=m"(featureFlags2)
		: [HW_FLAG_RDTSC] "i"(HWINTRINS_FLAG_RDTSC)/* Input */
		: "%eax", "%ecx", "%edx"				/* Registers clobbered */
		);

	/* If there's no CPUID support, there are no special HW capabilities
	   available */
	if( !hasAdvFeatures )
		return( HWINTRINS_FLAG_NONE );

	/* If there's a vendor ID present, check for vendor-specific special
	   features.  Again, we have to be extremely careful with ebx */
	if( !memcmp( vendorID, "CentaurHauls", 12 ) )
		{
	asm volatile( "pushl %%ebx\n\t"	/* Save PIC register */
		"movl $0xC0000000, %%eax\n\t"
		"cpuid\n\t"
		"popl %%ebx\n\t"			/* Restore PIC register */
		"cmpl $0xC0000001, %%eax\n\t"
		"jb endCheck\n\t"
		"pushl %%ebx\n\t"			/* Re-save PIC register */
		"movl $0xC0000001, %%eax\n\t"
		"cpuid\n\t"
		"popl %%ebx\n\t"			/* Re-restore PIC register */
		"movl %%edx, %%eax\n\t"
		"andl $0xC, %%edx\n\t"
		"cmpl $0xC, %%edx\n\t"
		"jz noRNG\n\t"
		"orl %[HW_FLAG_XSTORE], %[sysCaps]\n"	/* HWINTRINS_FLAG_XSTORE */
	"noRNG:\n\t"
		"movl %%edx, %%eax\n\t"
		"andl $0xC0, %%eax\n\t"
		"cmpl $0xC0, %%eax\n\t"
		"jz noACE\n\t"
		"orl %[HW_FLAG_XCRYPT], %[sysCaps]\n"	/* HWINTRINS_FLAG_XCRYPT */
	"noACE:\n\t"
		"movl %%edx, %%eax\n\t"
		"andl $0xC00, %%eax\n\t"
		"cmpl $0xC00, %%eax\n\t"
		"jz noPHE\n\t"
		"orl %[HW_FLAG_XSHA], %[sysCaps]\n"		/* HWINTRINS_FLAG_XSHA */
	"noPHE:\n\t"
		"movl %%edx, %%eax\n\t"
		"andl $0x3000, %%eax\n\t"
		"cmpl $0x3000, %%eax\n\t"
		"jz endCheck\n\t"
		"orl %[HW_FLAG_MONTMUL], %[sysCaps]\n"	/* HWINTRINS_FLAG_MONTMUL */
	"endCheck:\n\n"
		 : [sysCaps] "=m"(sysCaps)	/* Output */
		 : [HW_FLAG_XSTORE] "i"(HWINTRINS_FLAG_XSTORE),/* Input */
			[HW_FLAG_XCRYPT] "i"(HWINTRINS_FLAG_XCRYPT),
			[HW_FLAG_XSHA] "i"(HWINTRINS_FLAG_XSHA),
			[HW_FLAG_MONTMUL] "i"(HWINTRINS_FLAG_MONTMUL)
		 : "%eax", "%ecx", "%edx"	/* Registers clobbered */
		);
		}
	if( !memcmp( vendorID, "AuthenticAMD", 12 ) )
		{
		/* Check for AMD Geode LX, family 0x5 = Geode, model 0xA = LX */
		if( ( processorID & 0x0FF0 ) == 0x05A0 )
			sysCaps |= HWINTRINS_FLAG_TRNG;
		}
	if( !memcmp( vendorID, "GenuineIntel", 12 ) )
		{
		/* Check for hardware AES support */
		if( featureFlags & ( 1 << 25 ) )
			sysCaps |= HWINTRINS_FLAG_AES;

		/* Check for the return of a hardware RNG */
		if( featureFlags & ( 1 << 30 ) )
			sysCaps |= HWINTRINS_FLAG_RDRAND;
		if( featureFlags2 & ( 1 << 18 ) )
			sysCaps |= HWINTRINS_FLAG_RDSEED;
		}

	return( sysCaps );
	}

#elif defined( __GNUC__ ) && ( defined( __arm ) || defined( __arm__ ) ) && \
	  !defined( NO_ASM ) && 0		/* See comment below */

CHECK_RETVAL_ENUM( HWINTRINS_FLAG ) \
static int getHWIntrins( void )
	{
	int processorID;

	/* Get the ARM CPU type information.  Unfortunately this instruction 
	   (and indeed virtually all of the very useful CP15 registers) are 
	   inaccessible from user mode so it's not safe to perform any of these 
	   operations.  If you're running an embedded OS that runs natively in 
	   supervisor mode then you can try enabling this function to check 
	   whether you have access to the other CP15 registers and their 
	   information about hardware capabilities */
	asm volatile (
		"mrc p15, 0, r0, c0, c0, 0\n\t"
		"str r0, %0\n"
		: "=m"(processorID) /* Output */
		:					/* Input */
		: "cc", "r0"		/* Registers clobbered */
		); 

	return( HWINTRINS_FLAG_NONE );
	}

#elif ( defined( __GNUC__ ) || defined( __clang__ ) ) && defined( __riscv ) && \
	  !defined( NO_ASM ) && 0		/* See comment below */

static int getHWIntrins( void )
	{
	long vendorID, archID, impID, isa;

	/* RISC-V MSR read code, from "The RISC-V Instruction Set Manual, 
	   Volume II: Privileged Architecture", section "Control and Status 
	   Registers".  This has the same problems as ARM above, the registers
	   are inaccessible from user mode */
	asm volatile( "csrr %[vendorID], mvendorid\n\t"
		"csrr %[archID], marchid\n\t"
		"csrr %[impID], mimpid\n\t"
		"csrr %[isa], misa\n\n"
		: [vendorID] "=r"(vendorID), /* Output */
			[archID] "=r"(archID),
			[impID] "=r"(impID),
			[isa] "=r"(isa)
		:						/* Input */
		:						/* Registers clobbered */
		);

	return( HWINTRINS_FLAG_NONE );
	}

#else

CHECK_RETVAL_ENUM( HWINTRINS_FLAG ) \
static int getHWIntrins( void )
	{
	return( HWINTRINS_FLAG_NONE );
	}
#endif /* OS-specific support */

/* Initialise OS-specific constants.  This is a bit ugly because the values 
   are often specific to one cryptlib module but there's no (clean) way to
   perform any complex per-module initialisation so we have to know about 
   all of the module-specific sysVar requirements here */

#define MAX_SYSVARS		8

static int sysVars[ MAX_SYSVARS ];

#if ( defined( __WIN32__ ) || defined( __WINCE__ ) )

CHECK_RETVAL \
int initSysVars( void )
	{
#if VC_LT_2010( _MSC_VER )
	OSVERSIONINFO osvi = { sizeof(OSVERSIONINFO) };
#endif /* VC++ < 2010 */
	SYSTEM_INFO systemInfo;

	static_assert( SYSVAR_LAST < MAX_SYSVARS, "System variable value" );

	/* Reset the system variable information */
	memset( sysVars, 0, sizeof( int ) * MAX_SYSVARS );

#if VC_LT_2010( _MSC_VER )
	/* Figure out which version of Windows we're running under */
	if( !GetVersionEx( &osvi ) )
		{
		/* If for any reason the call fails, just use the most likely 
		   values */
		osvi.dwMajorVersion = 5;	/* Win2K and higher */
		osvi.dwPlatformId = VER_PLATFORM_WIN32_NT;
		}
	sysVars[ SYSVAR_OSMAJOR ] = osvi.dwMajorVersion;
	sysVars[ SYSVAR_OSMINOR ] = osvi.dwMinorVersion;

	/* Check for Win32s and Win95/98/ME just in case someone ever digs up 
	   one of these systems and tries to load cryptlib under them */
	if( osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS || \
		osvi.dwPlatformId == VER_PLATFORM_WIN32s )
		{
		DEBUG_DIAG(( "Win32s detected" ));
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_NOTAVAIL );
		}
#endif /* VC++ < 2010 */

	/* Get the system page size */
	GetSystemInfo( &systemInfo );
	sysVars[ SYSVAR_PAGESIZE ] = systemInfo.dwPageSize;

	/* Get system hardware capabilities */
	sysVars[ SYSVAR_HWINTRINS ] = getHWIntrins();

	return( CRYPT_OK );
	}

#elif defined( __UNIX__ )

#include <unistd.h>

#if defined( HAS_DEVCRYPTO )

#include <fcntl.h>
#include <crypto/cryptodev.h>
#include <sys/ioctl.h>

/* Check for the presence of crypto hardware support.  This is something of 
   an exercise in futility because the crypto hardware is anything from 
   slightly slower (very large data blocks) to much, much slower (more 
   standard small data blocks) than software due to the overhead of getting
   the data to and from the cryptologic and the cryptologic overhead. 
   However, people really want to see the fancy crypto hardware used even if
   it yields a net loss in performance so we try and enable it if possible
   unless it really is pointless, a slow software emulation of a slow 
   hardware interface.
   
   Beyond this is the fact that although both the *BSDs and Linux have a
   /dev/crypto, the interface to it is completely different so that 
   different code is needed to talk to it depending on whether it's a BSD
   /dev/crypto or a Linux /dev/crypto.  Even worse, the *BSDs kept the 
   original interface to 20+-year-old hardware so that the *BSD form only 
   allows atomic operations which makes it useless for our purposes, in
   this form neither CIOCGSESSINFO nor CIOCCPHASH exist so the interface 
   would be disabled by the startup tests due to lack of functionality 
   even if the separate code for *BSD was present */

CHECK_RETVAL_BOOL \
static BOOLEAN testCryptoAvail( const int cryptoFD,
								IN_RANGE( CRYPTO_DES_CBC, \
										  CRYPTO_ALGORITHM_MAX ) \
									const int cryptoType )
	{
	struct session_op session;
#ifdef CIOCGSESSINFO
	struct session_info_op sessionInfo;
#endif /* CIOCGSESSINFO */
	const BOOLEAN isCipher = \
			( cryptoType == CRYPTO_3DES_CBC || \
			  cryptoType == CRYPTO_AES_CBC ) ? TRUE : FALSE;

	REQUIRES_B( cryptoType >= CRYPTO_DES_CBC && \
				cryptoType < CRYPTO_ALGORITHM_MAX );

	/* Check whether the requested mechanism is available, and in what 
	   form */
	memset( &session, 0, sizeof( struct session_op ) );
	if( isCipher )
		{
		session.cipher = cryptoType;
		session.key = "0123456789ABCDEF";
		session.keylen = 16;
		}
	else
		session.mac = cryptoType;
	if( ioctl( cryptoFD, CIOCGSESSION, &session ) )
		return( FALSE );
#ifdef CIOCGSESSINFO
	memset( &sessionInfo, 0, sizeof( struct session_info_op ) );
	sessionInfo.ses = session.ses;
	if( ioctl( cryptoFD, CIOCGSESSINFO, &sessionInfo ) )
		{
		ioctl( cryptoFD, CIOCFSESSION, &session.ses );
		return( FALSE );
		}
	ioctl( cryptoFD, CIOCFSESSION, &session.ses );
	if( !( sessionInfo.flags & SIOP_FLAG_KERNEL_DRIVER_ONLY ) )
		{
		/* The sole flag supported by CryptoDev, 
		   SIOP_FLAG_KERNEL_DRIVER_ONLY, is rather confusing since it's
		   documented as meaning that the algorithm uses a driver only 
		   available in-kernel, but whether this means that it's only 
		   available from within the kernel or that it's hardware supported
		   by a kernel driver (as opposed to a software-only implementation) 
		   is unclear.  Code comments and testing on various systems indicates
		   that if it's not set then it's software-only, so if we don't see it 
		   set then we don't use this interface */
		DEBUG_PRINT(( "Crypto %s is available but a software-only "
					  "implementation, skipping...\n", isCipher ? \
					   sessionInfo.cipher_info.cra_driver_name : \
					   sessionInfo.hash_info.cra_driver_name ));
		return( FALSE );
		}

	DEBUG_PRINT(( "Enabling crypto hardware support for %s.\n",
				  isCipher ? sessionInfo.cipher_info.cra_driver_name : \
							 sessionInfo.hash_info.cra_driver_name ));
#endif /* CIOCGSESSINFO */

	return( TRUE );
	}

#ifdef CIOCCPHASH

CHECK_RETVAL_BOOL \
static BOOLEAN checkCopyAvail( const int cryptoFD )
	{
	struct session_op session1, session2;
	struct crypt_op cryptOpInfo;
	BOOLEAN returnValue = FALSE;

	/* Create two SHA-1 sessions */
	memset( &session1, 0, sizeof( struct session_op ) );
	session1.mac = CRYPTO_SHA1;
	if( ioctl( cryptoFD, CIOCGSESSION, &session1 ) )
		return( FALSE );
	memset( &session2, 0, sizeof( struct session_op ) );
	session2.mac = CRYPTO_SHA1;
	if( ioctl( cryptoFD, CIOCGSESSION, &session2 ) )
		{
		( void ) ioctl( cryptoFD, CIOCFSESSION, session1 );
		return( FALSE );
		}

	/* Hash some data using the first session, then copy it to the second 
	   session */
	memset( &cryptOpInfo, 0, sizeof( struct crypt_op ) );
	cryptOpInfo.ses = session1.ses;
	cryptOpInfo.op = COP_ENCRYPT;
	cryptOpInfo.flags = COP_FLAG_RESET | COP_FLAG_UPDATE;
	cryptOpInfo.src = "12345678";
	cryptOpInfo.len = 8;
	if( ioctl( cryptoFD, CIOCCRYPT, &cryptOpInfo ) == 0 )
		{
		struct cphash_op copyInfo;

		memset( &copyInfo, 0, sizeof( struct cphash_op ) );
		copyInfo.src_ses = session1.ses;
		copyInfo.dst_ses = session2.ses;
		if( ioctl( cryptoFD, CIOCCPHASH, &copyInfo ) == 0 )
			returnValue = TRUE;
		}

	/* Clean up */
	( void ) ioctl( cryptoFD, CIOCFSESSION, session1 );
	( void ) ioctl( cryptoFD, CIOCFSESSION, session2 );

	return( returnValue );
	}
#else
  #define checkCopyAvail( cryptoFD )		FALSE
#endif /* CIOCCPHASH */

CHECK_RETVAL_ENUM( HWCRYPT_FLAG ) \
static int getHWCrypt( void )
	{
	static const MAP_TABLE hwCryptInfo[] = {
		{ CRYPTO_3DES_CBC, HWCRYPT_FLAG_CRYPTDEV_3DES },
		{ CRYPTO_AES_CBC, HWCRYPT_FLAG_CRYPTDEV_AES },
		{ CRYPTO_SHA1, HWCRYPT_FLAG_CRYPTDEV_SHA1 },
		{ CRYPTO_SHA2_256, HWCRYPT_FLAG_CRYPTDEV_SHA2 },
		{ CRYPT_ERROR, CRYPT_ERROR },
			{ CRYPT_ERROR, CRYPT_ERROR }
		};
	struct session_op session;
	LOOP_INDEX i;
	int cryptoFD, hwCryptFlags = HWCRYPT_FLAG_NONE;

	/* Open the crypto device and make sure that we can talk to it.  We use
	   SHA-1 as our generic test algorithm both because it should be 
	   supported everywhere and because it doesn't require any extra data 
	   like a key in order to perform the query */
	cryptoFD = open( "/dev/crypto", O_RDWR, 0 );
	if( cryptoFD < 0 )
		{
		DEBUG_DIAG(( "/dev/crypto support is available but no crypto device "
					 "was found" ));
		return( HWCRYPT_FLAG_NONE );
		}
	fcntl( cryptoFD, F_SETFD, FD_CLOEXEC );
	memset( &session, 0, sizeof( struct session_op ) );
	session.mac = CRYPTO_SHA1;
	if( ioctl( cryptoFD, CIOCGSESSION, &session ) )
		{
		DEBUG_DIAG(( "CryptoDev SHA-1 access failed" ));
		close( cryptoFD );

		return( HWCRYPT_FLAG_NONE );
		}
	ioctl( cryptoFD, CIOCFSESSION, &session.ses );

	/* Check whether CIOCCPHASH is supported.  This is required for cloned 
	   hash contexts */
	if( !checkCopyAvail( cryptoFD ) )
		{
		DEBUG_DIAG(( "CryptoDev CIOCCPHASH not supported, using default "
					 "crypto provider" ));
		close( cryptoFD );

		return( HWCRYPT_FLAG_NONE );
		}

	/* Find out which hardware crypto capabilities are available */
	LOOP_SMALL( i = 0, 
				i < FAILSAFE_ARRAYSIZE( hwCryptInfo, MAP_TABLE ) && \
					hwCryptInfo[ i ].source != CRYPT_ERROR,
				i++ )
		{
		ENSURES_EXT( LOOP_INVARIANT_SMALL( i, 0, 
										   FAILSAFE_ARRAYSIZE( hwCryptInfo, \
															   MAP_TABLE ) - 1 ),
					 HWCRYPT_FLAG_NONE );

		if( testCryptoAvail( cryptoFD, hwCryptInfo[ i ].source ) )
			hwCryptFlags |= hwCryptInfo[ i ].destination;
		}
	ENSURES_EXT( i < FAILSAFE_ARRAYSIZE( hwCryptInfo, MAP_TABLE ), 
				 HWCRYPT_FLAG_NONE );
	close( cryptoFD );

	return( hwCryptFlags );
	}
#else

CHECK_RETVAL_ENUM( HWCRYPT_FLAG ) \
static int getHWCrypt( void )
	{
	return( HWCRYPT_FLAG_NONE );
	}
#endif /* HAS_DEVCRYPTO */

CHECK_RETVAL \
int initSysVars( void )
	{
	static_assert( SYSVAR_LAST < MAX_SYSVARS, "System variable value" );

	/* Reset the system variable information */
	memset( sysVars, 0, sizeof( int ) * MAX_SYSVARS );

	/* Get the system page size.  We try for the sysconf() option first 
	   because the original getpagesize() has been deprecated by Posix and,
	   while still present, typically requires system-specific preprocessor
	   defines to enable.  If we can't get it directly we assume 4K, while
	   in theory it could be anything in practice the 4K size is so 
	   universal that when Apple's M1 allowed 16K page sizes a whole pile
	   of software broke with them, see
	   https://github.com/AsahiLinux/docs/wiki/Software-known-to-have-issues-with-16k-page-size */
#if defined( _SC_PAGESIZE )
	sysVars[ SYSVAR_PAGESIZE ] = sysconf( _SC_PAGESIZE );
#elif defined( _SC_PAGE_SIZE )
	sysVars[ SYSVAR_PAGESIZE ] = sysconf( _SC_PAGE_SIZE );
#elif defined( _CRAY )
	sysVars[ SYSVAR_PAGESIZE ] = 4096;	/* Close enough for most systems */
#else
	sysVars[ SYSVAR_PAGESIZE ] = getpagesize();
#endif /* Unix variant-specific brokenness */
	if( sysVars[ SYSVAR_PAGESIZE ] < 1024 )
		{
		DEBUG_DIAG(( "System reports page size < 1024" ));
		assert( DEBUG_WARN );

		/* Suspiciously small reported page size, just assume a sensible 
		   value */
		sysVars[ SYSVAR_PAGESIZE ] = 4096;
		}

	/* Get system hardware capabilities */
	sysVars[ SYSVAR_HWINTRINS ] = getHWIntrins();
	sysVars[ SYSVAR_HWCRYPT ] = getHWCrypt();

#if defined( __IBMC__ ) || defined( __IBMCPP__ )
	/* VisualAge C++ doesn't set the TZ correctly */
	tzset();
#endif /* VisualAge C++ */

	return( CRYPT_OK );
	}

#else

CHECK_RETVAL \
int initSysVars( void )
	{
	/* Reset the system variable information */
	memset( sysVars, 0, sizeof( int ) * MAX_SYSVARS );

	/* Get system hardware capabilities */
	sysVars[ SYSVAR_HWINTRINS ] = getHWIntrins();

	return( CRYPT_OK );
	}
#endif /* OS-specific support */

CHECK_RETVAL \
int getSysVar( IN_ENUM( SYSVAR ) const SYSVAR_TYPE type )
	{
	REQUIRES( isEnumRange( type, SYSVAR ) );

	return( sysVars[ type ] );
	}

/****************************************************************************
*																			*
*								Memory Locking								*
*																			*
****************************************************************************/

/* Many OSes support locking pages in memory, the following helper functions 
   implement this locking */

#if defined( __MAC__ )

#include <Memory.h>

/* Pre-OS X Mac OS has two functions for locking memory, HoldMemory(), which 
   makes the memory ineligible for paging, and LockMemory(), which makes it 
   ineligible for paging and also immovable.  We use HoldMemory() since it's 
   slightly more friendly, but really critical applications could use 
   LockMemory() */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN lockMemory( IN_BUFFER( size ) void *address,
					IN_LENGTH const int size )
	{
	assert( isWritePtr( address, size ) );

	REQUIRES_B( isIntegerRangeNZ( size ) );

#if !defined( CALL_NOT_IN_CARBON ) || CALL_NOT_IN_CARBON
	if( HoldMemory( address, size ) == noErr )
		return( TRUE );
#endif /* Non Mac OS X memory locking */

	return( FALSE );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void unlockMemory( IN_BUFFER( size ) void *address,
				   IN_LENGTH const int size,
				   IN_BOOL const BOOLEAN checkPageOverlap )
	{
	assert( isWritePtr( address, size ) );

	REQUIRES_V( isIntegerRangeNZ( size ) );
	REQUIRES_V( isBooleanValue( checkPageOverlap ) );

	/* If the memory was locked, unlock it now */
#if !defined( CALL_NOT_IN_CARBON ) || CALL_NOT_IN_CARBON
	UnholdMemory( address, size );
#endif /* Non Mac OS X memory locking */
	}

#elif defined( __MSDOS__ ) && defined( __DJGPP__ )

#include <dpmi.h>
#include <go32.h>

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN lockMemory( IN_BUFFER( size ) void *address,
					IN_LENGTH const int size )
	{
	assert( isWritePtr( address, size ) );

	REQUIRES_B( isIntegerRangeNZ( size ) );

	/* Under 32-bit MSDOS use the DPMI functions to lock memory */
	if( _go32_dpmi_lock_data( address, size ) == 0 )
		return( TRUE );

	return( FALSE );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void unlockMemory( IN_BUFFER( size ) void *address,
				   IN_LENGTH const int size,
				   IN_BOOL const BOOLEAN checkPageOverlap )
	{
	assert( isWritePtr( address, size ) );

	REQUIRES_V( isIntegerRangeNZ( size ) );
	REQUIRES_V( isBooleanValue( checkPageOverlap ) );

	/* Under 32-bit MSDOS we *could* use the DPMI functions to unlock
	   memory, but as many DPMI hosts implement page locking in a binary
	   form (no lock count maintained), it's better not to unlock anything
	   at all.  Note that this may lead to a shortage of virtual memory in
	   long-running applications */
	}

#elif defined( __UNIX__ )

/* Since the function prototypes for the SYSV/Posix mlock() call are stored
   all over the place depending on the Unix version it's easier to prototype 
   it ourselves here rather than trying to guess its location */

#if defined( _AIX ) || defined( __alpha__ ) || defined( __hpux ) || \
	defined( __linux__ ) || defined( __osf__ ) || defined( sun )
  #include <sys/mman.h>
  #if defined( sun )
	  #include <sys/types.h>
  #endif /* Slowaris */
#else
  int mlock( void *address, size_t length );
  int munlock( void *address, size_t length );
#endif /* Unix-variant-specific includes */

/* Under many Unix variants the SYSV/Posix mlock() call can be used, but 
   only by the superuser (with occasional OS-specific variants, for example 
   under some newer Linux variants the caller needs the specific 
   CAP_IPC_LOCK privilege rather than just generally being root).  
   
   OSF/1 has mlock(), but this is defined to the nonexistant memlk() so we 
   need to special-case it out.  
   
   QNX (depending on the version) either doesn't have mlock() at all or it's 
   a dummy that just returns -1, so we no-op it out.  
   
   Aches < 5, A/UX, PHUX < 11, Linux < 1.3.something, and Ultrix don't even 
   pretend to have mlock().
   
   Many systems also have plock(), but this is pretty crude since it locks 
   all data, and also has various other shortcomings.  
   
   Finally, PHUX has datalock(), which is just a plock() variant.
   
   Linux 2.6.32 has a kernel bug in which, under high disk-load conditions 
   (100% disk usge) and with multiple cryptlib threads performing memory 
   locking/unlocking the process can get stuck in the "D" state, a.k.a. 
   TASK_UNINTERRUPTIBLE, which is an uninterruptible disk I/O sleep state.  
   If the process doesn't snap out of it when the I/O completes then it's 
   necessary to reboot the machine to clear the state.  To help find this 
   issue use:

	ps -eo ppid,pid,user,stat,pcpu,comm,wchan:32

   which shows D-state processes via the fourth column, the last column 
   will show the name of the kernel function in which the process is
   currently sleeping (also check dmesg for kernel Oops'es) */

#if ( defined( _AIX ) && OS_VERSION < 5 ) || defined( __alpha__ ) || \
	defined( __aux ) || defined( _CRAY ) || defined( __CYGWIN__ ) || \
	( defined( __hpux ) && OS_VERSION < 11 ) || \
	( defined( __linux__ ) && OSVERSION < 2 ) || \
	defined( _M_XENIX ) || defined( __osf__ ) || \
	( defined( __QNX__ ) && OSVERSION <= 6 ) || \
	defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) || \
	defined( __ultrix )
  #define mlock( a, b )		1
  #define munlock( a, b )
#endif /* Unix OS-specific defines */

/* In theory alongside mlock() we can tell the kernel to treat a block of 
   memory specially via madvise() if this facility is available.  In 
   practice this doesn't really work though because madvise() works on a 
   granularity of page boundaries, despite the appearance of working on 
   arbitrary memory regions.  This means that unless the start address is 
   page-aligned, it'll fail.  In addition it if we madvise() malloc'd 
   memory we'll end up messing with the heap in ways that will break memory 
   allocation.  For example MADV_WIPEONFORK will wipe the entire page or 
   page range containing the heap that the client gets, corrupting the heap 
   on fork.

   What this means is that we'd need to mmap() memory in order to madvise() 
   on it, and then implement our own allocator on top of that.  Or, every 
   time we allocate anything, make it a full page, again via mmap().  The 
   chances of something going wrong when we do our own memory management are 
   probably a lot higher than the chances of something ending up in a core 
   dump when we don't, but we at least try and madvise() a MADV_DONTDUMP on
   a best-effort basis until a more universal facility for excluding the 
   memory block from dumps appears */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN lockMemory( IN_BUFFER( size ) void *address,
					IN_LENGTH const int size )
	{
	assert( isWritePtr( address, size ) );

	REQUIRES_B( isIntegerRangeNZ( size ) );

	if( !mlock( address, size ) )
		{
		/* Exclude the memory block from core dumps, with the caveats given 
		   above */
#ifdef MADV_DONTDUMP
		( void ) madvise( address, size, MADV_DONTDUMP );
#endif /* MADV_DONTDUMP */
		return( TRUE );
		}

	return( FALSE );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void unlockMemory( IN_BUFFER( size ) void *address,
				   IN_LENGTH const int size,
				   IN_BOOL const BOOLEAN checkPageOverlap )
	{
	assert( isWritePtr( address, size ) );

	REQUIRES_V( isIntegerRangeNZ( size ) );
	REQUIRES_V( isBooleanValue( checkPageOverlap ) );

	munlock( address, size );
	}

#elif defined( __WIN32__ ) && !defined( NT_DRIVER )

/* For the Win32 debug build we enable extra checking for heap corruption.
   This isn't anywhere near as good as proper memory checkers, but it can 
   catch some errors */

#if !defined( NDEBUG ) && !defined( NT_DRIVER ) && !defined( __BORLANDC__ )
  #define USE_HEAP_CHECKING
  #include <crtdbg.h>
#endif /* Win32 debug version */

/* Get the start address of a page and, given an address in a page and a 
   size, determine on which page the data ends.  These are used to determine 
   which pages a memory block covers */

#if defined( _MSC_VER ) && ( _MSC_VER >= 1400 )
  #define PTR_TYPE	INT_PTR 
#else
  #define PTR_TYPE	long
#endif /* Newer versions of VC++ */

#define getPageStartAddress( address ) \
		( ( PTR_TYPE ) ( address ) & ~( pageSize - 1 ) )
#define getPageEndAddress( address, size ) \
		getPageStartAddress( ( PTR_TYPE ) address + ( size ) - 1 )

/* Functions to exclude a memory region from being emailed to Microsoft.  
   This braindamage, along with functions to prevent the braindamage, only 
   appeared in Windows 10 so we have to invoke the dynamically */

typedef HRESULT ( WINAPI *WERREGISTEREXCLUDEDMEMORYBLOCK )( const void *address, 
															DWORD size );
typedef HRESULT ( WINAPI *WERUNREGISTEREXCLUDEDMEMORYBLOCK )( const void *address );

/* Prototype for helper function in kernel/sec_mem.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int getBlockListInfo( IN_PTR_OPT const void *currentBlockPtr, 
					  OUT_PTR_PTR_COND const void **address, 
					  OUT_LENGTH_Z int *size );

/* Under Win95/98/ME the VirtualLock() function was implemented as 
   'return( TRUE )' ("Thank Microsoft kids" - "Thaaaanks Bill"), but we 
   don't have to worry about those Windows versions any more.  Under Win32/
   Win64 the function does actually work, but with a number of caveats.  The 
   main one is that it was originally intended that VirtualLock() only locks
   memory into a processes' working set, in other words it guarantees that 
   the memory won't be paged while a thread in the process is running, and 
   when all threads are pre-empted the memory is still a target for paging.  
   This would mean that on a loaded system a process that was idle for some 
   time could have the memory unlocked by the system and swapped out to disk.

   In fact with older Windows incarnations like NT, their somewhat strange 
   paging strategy meant that it could potentially get paged even on a 
   completely unloaded system.  Even on relatively recent systems the 
   gradual creeping takeover of free memory for disk buffers/cacheing can
   cause problems, something that was still affecting Win64 systems during
   the Windows 7 time frame.  Ironically the 1GB cache size limit on Win32
   systems actually helped here because the cache couldn't grow beyond this
   size and most systems had more than 1GB of RAM, while on Win64 systems 
   without this limit there was more scope for excessive reads and writes to 
   consume all available memory due to cacheing.

   The lock-into-working-set approach was the original intention, however 
   the memory manager developers never got around to implementing the 
   unlock-if-all-threads idle part.  The behaviour of VirtualLock() was 
   evaluated back under Win2K and XP by trying to force data to be paged 
   under various conditions, which were unsuccesful, so VirtualLock() under 
   these OSes seems to be fairly effective in keeping data off disk.  In 
   newer versions of Windows the contract for VirtualLock() was changed to 
   match the actual implemented behaviour, so that now "pages are guaranteed 
   not to be written to the pagefile while they are locked".

   An additional concern is that although VirtualLock() takes arbitrary 
   memory pointers and a size parameter, the locking is done on a per-page 
   basis so that unlocking a region that shares a page with another locked 
   region means that both reqions are unlocked (this isn't documented for
   VirtualLock() but is covered in excruciating detail for VirtualUnlock()).  
   Since VirtualLock() doesn't do reference counting (emulating the 
   underlying MMU page locking even though it seems to implement an 
   intermediate layer above the MMU so it could in theory do this), the 
   only way around this is to walk the chain of allocated blocks and not 
   unlock a block if there's another block allocated on the same page.  Ick.

   For the NT kernel driver, the memory is always allocated from the non-
   paged pool so there's no need for these gyrations.

   In addition to VirtualLock() we could also use VirtualAlloc(), however 
   this allocates in units of the allocation granularity, which is in theory
   system-dependent and obtainable via the dwAllocationGranularity field in
   the SYSTEM_INFO structure returned by GetSystemInfo() but in practice on
   x86 systems is always 64K, this means the memory is nicely aligned for
   efficient access but wastes 64K for every allocation */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN lockMemory( IN_BUFFER( size ) void *address,
					IN_LENGTH const int size )
	{
	static WERREGISTEREXCLUDEDMEMORYBLOCK pWerRegisterExcludedMemoryBlock = NULL;
	static BOOLEAN werFunctionCheck = FALSE;

	assert( isWritePtr( address, size ) );

	REQUIRES_B( isIntegerRangeNZ( size ) );

	if( !werFunctionCheck )
		{
		HANDLE hKernel32;

		/* Try and get WerRegisterExcludedMemoryBlock().  Since this is a 
		   Windows 10 function, we need to dynamically link it */
		if( ( hKernel32 = GetModuleHandle( "Kernel32.dll" ) ) != NULL )
			{
			pWerRegisterExcludedMemoryBlock = ( WERREGISTEREXCLUDEDMEMORYBLOCK ) \
						GetProcAddress( hKernel32, "WerRegisterExcludedMemoryBlock" );
			}
		werFunctionCheck = TRUE;
		}

	if( !VirtualLock( address, size ) )
		return( FALSE );

	/* Exclude the memory from being emailed to Microsoft in an error 
	   report */
	if( pWerRegisterExcludedMemoryBlock != NULL )
		( void ) pWerRegisterExcludedMemoryBlock( address, size );

	return( TRUE );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void unlockMemory( IN_BUFFER( size ) void *address,
				   IN_LENGTH const int size,
				   IN_BOOL const BOOLEAN checkPageOverlap )
	{
	static WERUNREGISTEREXCLUDEDMEMORYBLOCK pWerUnregisterExcludedMemoryBlock = NULL;
	static BOOLEAN werFunctionCheck = FALSE;
	LOOP_INDEX_PTR void *currentBlockPtr;
	PTR_TYPE firstPageAddress, secondPageAddress;
	const int pageSize = getSysVar( SYSVAR_PAGESIZE );
	int currentBlockSize, status;

	assert( isWritePtr( address, size ) );

	REQUIRES_V( isIntegerRangeNZ( size ) );
	REQUIRES_V( isBooleanValue( checkPageOverlap ) );

	if( !werFunctionCheck )
		{
		HANDLE hKernel32;

		/* Try and get WerUnregisterExcludedMemoryBlock().  Since this is a 
		   Windows 10 function, we need to dynamically link it */
		if( ( hKernel32 = GetModuleHandle( "Kernel32.dll" ) ) != NULL )
			{
			pWerUnregisterExcludedMemoryBlock = ( WERUNREGISTEREXCLUDEDMEMORYBLOCK ) \
						GetProcAddress( hKernel32, "WerUnregisterExcludedMemoryBlock" );
			}
		werFunctionCheck = TRUE;
		}

	/* If this is statically-allocated memory then there's no need to check 
	   whether it overlaps with other dynamically allocated pages, and we're 
	   done */
	if( !checkPageOverlap )
		{
		VirtualUnlock( address, size );
		if( pWerUnregisterExcludedMemoryBlock != NULL )
			( void ) pWerUnregisterExcludedMemoryBlock( address );
		return;
		}

	/* Because VirtualLock() works on a per-page basis, we can't unlock a
	   memory block if there's another locked block on the same page.  The
	   only way to manage this is to walk the block list checking to see
	   whether there's another block allocated on the same memory page:

					+-------------------------------+	+-----------+
		krnlData--->|								|-->|			|
					+-------------------------------+	+-----------+
					|								|	|
			+-------+				+---------------+	|
			|						+-------------------+
			v						v
			+-----------------------+-----------------------+----------------
			|		Page 1			|		Page 2			|		Page 3
			+-----------------------+-----------------------+----------------
	   firstPageAddr		  secondPageAddr
						  Page of currentBlockPtr

	   To do this we get the page or pages that the to-free memory block 
	   resides in and walk down the memory block list checking whether any
	   other blocks reside in those pages.  If they do, we don't unlock 
	   them, since they'll be unlocked when the other memory block is freed.

	   Although in theory this could make freeing memory rather slow, in 
	   practice there are only a small number of allocated blocks to check 
	   so it's relatively quick, especially compared to the overhead imposed 
	   by the lethargic VC++ allocator.  The only real disadvantage is that 
	   the allocation objects remain locked while we do the free, but this
	   isn't any worse than the overhead of touchAllocatedPages().  Note 
	   that the following code assumes that an allocated block will never 
	   cover more than two pages, which is always the case.

	   First we calculate the addresses of the page(s) in which the memory 
	   block resides */
	firstPageAddress = getPageStartAddress( address );
	secondPageAddress = getPageEndAddress( address, size );
	if( firstPageAddress == secondPageAddress )
		secondPageAddress = 0;

	/* Walk down the block list checking whether the page(s) contain another 
	   locked block */
	status = getBlockListInfo( NULL, &currentBlockPtr, &currentBlockSize );
	REQUIRES_V( cryptStatusOK( status ) );
	LOOP_LARGE_CHECKINC( cryptStatusOK( status ),
						 status = getBlockListInfo( currentBlockPtr, 
													&currentBlockPtr, 
													&currentBlockSize ) )
		{
		const PTR_TYPE currentFirstPageAddress = \
						getPageStartAddress( currentBlockPtr );
		PTR_TYPE currentSecondPageAddress = \
						getPageEndAddress( currentBlockPtr, currentBlockSize );

		ENSURES_V( LOOP_INVARIANT_LARGE_GENERIC() );

		if( currentFirstPageAddress == currentSecondPageAddress )
			currentSecondPageAddress = 0;

		/* If there's another block allocated on either of the pages, don't
		   unlock it */
		if( firstPageAddress == currentFirstPageAddress || \
			firstPageAddress == currentSecondPageAddress )
			{
			firstPageAddress = 0;
			if( !secondPageAddress )
				break;
			}
		if( secondPageAddress == currentFirstPageAddress || \
			secondPageAddress == currentSecondPageAddress )
			{
			secondPageAddress = 0;
			if( !firstPageAddress )
				break;
			}
		}
	ENSURES_V( LOOP_BOUND_OK );

	/* Finally, if either page needs unlocking, do so.  The supplied size is 
	   irrelevant since the entire page that the memory block is in is 
	   unlocked */
	if( firstPageAddress )
		VirtualUnlock( ( void * ) firstPageAddress, 16 );
	if( secondPageAddress )
		VirtualUnlock( ( void * ) secondPageAddress, 16 );
	if( pWerUnregisterExcludedMemoryBlock != NULL )
		( void ) pWerUnregisterExcludedMemoryBlock( address );
	}
#endif /* OS-specific page-locking handling */

/****************************************************************************
*																			*
*				Miscellaneous System-specific Support Functions				*
*																			*
****************************************************************************/

/* Align a pointer to a given boundary.  This gets quite complicated because
   the only pointer arithmetic that's normally allowed is addition and 
   subtraction, but to align to a boundary we need to be able to perform 
   bitwise operations.  First we convert the pointer to a char pointer so
   that we can perform normal maths on it, and then we round in the usual
   manner used by roundUp().  Because we have to do pointer-casting we can't 
   use roundUp() directly but have to build our own version here */

STDC_NONNULL_ARG( ( 1 ) ) \
void *ptr_align( const void *ptr, const int units )
	{
	assert( isReadPtr( ptr, 1 ) );
	assert( isShortIntegerRangeNZ( units ) );

	return( ( void * ) ( ( char * ) ptr + ( -( ( intptr_t )( ptr ) ) & ( units - 1 ) ) ) );
	}

/* Determine the difference between two pointers, with some sanity 
   checking.  This assumes that the pointers are fairly close in location,
   used to determine whether pointers that were potentially relocated 
   at some point via ptr_align() have moved */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
int ptr_diff( const void *ptr1, const void *ptr2 )
	{
	ptrdiff_t diff;

	assert( isReadPtr( ptr1, 1 ) );
	assert( isReadPtr( ptr2, 1 ) );
	assert( ptr1 >= ptr2 );

	diff = ( const BYTE * ) ptr1 - ( const BYTE * ) ptr2;
	if( diff < 0 )
		diff = -diff;
	if( diff >= MAX_INTLENGTH )
		return( -1 );

	return( ( int ) diff );
	}
