/****************************************************************************
*																			*
*							cryptlib Test Key Load Code						*
*						Copyright Peter Gutmann 1995-2020					*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

/* Various features can be disabled by configuration options, in order to 
   handle this we need to include the cryptlib config file so that we can 
   selectively disable some tests.
   
   The following include is necessary in case CONFIG_PKC_ALLOCSIZE has been
   set in misc/config.h rather than during the build, since it controls
   CRYPT_MAX_PKCSIZE */
#include "misc/config.h"	/* For key size */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/****************************************************************************
*																			*
*									Key Data								*
*																			*
****************************************************************************/

/* The keys for testing the RSA, DLP( DSA, DH, and Elgamal), and ECDLP 
   (ECDSA and ECDH) implementations.  The key values can be extracted with 
   the following code pasted into the generateKey() function in 
   ctx_dsa.c/ctx_ecc.c/ctx_rsa.c */

#if 0	/* RSA */
{
#include <stdio.h>

BYTE buffer[ CRYPT_MAX_PKCSIZE ];
int length, i;

printf( "static const RSA_KEY rsa%dKey = {\n", keyBits );
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_n, buffer );
printf( "\t/* n */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_n ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_e, buffer );
printf( "},\n\t/* e */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_e ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_d, buffer );
printf( "},\n\t/* d */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_d ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_p, buffer );
printf( "},\n\t/* p */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_p ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_q, buffer );
printf( "},\n\t/* q */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_q ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_u, buffer );
printf( "},\n\t/* u */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_u ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_exponent1, buffer );
printf( "},\n\t/* exponent1 */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_exponent1 ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_exponent2, buffer );
printf( "},\n\t/* exponent2 */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_exponent2 ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
puts( "}\n\t};" );
fflush( stdout );
}
#endif
#if 0	/* DLP */
{
#include <stdio.h>

BYTE buffer[ CRYPT_MAX_PKCSIZE ];
int length, i;

printf( "static const DLP_KEY dlp%dKey = {\n", keyBits );
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_p, buffer );
printf( "\t/* p */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_p ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_q, buffer );
printf( "},\n\t/* q */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_q ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_g, buffer );
printf( "},\n\t/* g */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_g ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_x, buffer );
printf( "},\n\t/* x */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_x ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_y, buffer );
printf( "},\n\t/* y */\n\t%d,\n\t{ ", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_y ) );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
puts( "}\n\t};" );
fflush( stdout );
}
#endif
#if 0	/* ECC */
{
#include <stdio.h>

BYTE buffer[ CRYPT_MAX_PKCSIZE ];
int length, i;

printf( "static const ECC_KEY ecdlpP%dKey = {\n", keySizeBits );
length = BN_bn2bin( &contextInfoPtr->ctxPKC->eccParam_qx, buffer );
printf( "\t/* qx */\n\t%d,\n\t{ ", keySizeBits );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->eccParam_qy, buffer );
printf( "},\n\t/* qy */\n\t%d,\n\t{ ", keySizeBits );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->eccParam_d, buffer );
printf( "},\n\t/* d */\n\t%d,\n\t{ ", keySizeBits );
for( i = 0; i < length; i++ )
	{ if( i && !( i % 8 ) ) printf( "\n\t  " );
	printf( ( i != length - 1 ) ? "0x%02X, " : "0x%02X ", buffer[ i ] ); }
puts( "}\n\t};" );
fflush( stdout );
}
#endif

typedef struct {
	const int nLen; const BYTE n[ 256 ];
	const int eLen; const BYTE e[ 3 ];
	const int dLen; const BYTE d[ 256 ];
	const int pLen; const BYTE p[ 128 ];
	const int qLen; const BYTE q[ 128 ];
	const int uLen; const BYTE u[ 128 ];
	const int e1Len; const BYTE e1[ 128 ];
	const int e2Len; const BYTE e2[ 128 ];
	} RSA_KEY;

static const RSA_KEY rsa1024TestKey = {
	/* n */
	1024,
	{ 0x9C, 0x4D, 0x98, 0x18, 0x67, 0xF9, 0x45, 0xBC,
	  0xB6, 0x75, 0x53, 0x5D, 0x2C, 0xFA, 0x55, 0xE4,
	  0x51, 0x54, 0x9F, 0x0C, 0x16, 0xB1, 0xAF, 0x89,
	  0xF6, 0xF3, 0xE7, 0x78, 0xB1, 0x2B, 0x07, 0xFB,
	  0xDC, 0xDE, 0x64, 0x23, 0x34, 0x87, 0xDA, 0x0B,
	  0xE5, 0xB3, 0x17, 0x16, 0xA4, 0xE3, 0x7F, 0x23,
	  0xDF, 0x96, 0x16, 0x28, 0xA6, 0xD2, 0xF0, 0x0A,
	  0x59, 0xEE, 0x06, 0xB3, 0x76, 0x6C, 0x64, 0x19,
	  0xD9, 0x76, 0x41, 0x25, 0x66, 0xD1, 0x93, 0x51,
	  0x52, 0x06, 0x6B, 0x71, 0x50, 0x0E, 0xAB, 0x30,
	  0xA5, 0xC8, 0x41, 0xFC, 0x30, 0xBC, 0x32, 0xD7,
	  0x4B, 0x22, 0xF2, 0x45, 0x4C, 0x94, 0x68, 0xF1,
	  0x92, 0x8A, 0x4C, 0xF9, 0xD4, 0x5E, 0x87, 0x92,
	  0xA8, 0x54, 0x93, 0x92, 0x94, 0x48, 0xA4, 0xA3,
	  0xEE, 0x19, 0x7F, 0x6E, 0xD3, 0x14, 0xB1, 0x48,
	  0xCE, 0x93, 0xD1, 0xEA, 0x4C, 0xE1, 0x9D, 0xEF },

	/* e */
	17,
	{ 0x01, 0x00, 0x01 },

	/* d */
	1022,
	{ 0x37, 0xE2, 0x66, 0x67, 0x13, 0x85, 0xC4, 0xB1,
	  0x5C, 0x6B, 0x46, 0x8B, 0x21, 0xF1, 0xBF, 0x94,
	  0x0A, 0xA0, 0x3E, 0xDD, 0x8B, 0x9F, 0xAC, 0x2B,
	  0x9F, 0xE8, 0x44, 0xF2, 0x9A, 0x25, 0xD0, 0x8C,
	  0xF4, 0xC3, 0x6E, 0xFA, 0x47, 0x65, 0xEB, 0x48,
	  0x25, 0xB0, 0x8A, 0xA8, 0xC5, 0xFB, 0xB1, 0x11,
	  0x9A, 0x77, 0x87, 0x24, 0xB1, 0xC0, 0xE9, 0xA2,
	  0x49, 0xD5, 0x19, 0x00, 0x41, 0x6F, 0x2F, 0xBA,
	  0x9F, 0x28, 0x47, 0xF9, 0xB8, 0xBA, 0xFF, 0xF4,
	  0x8B, 0x20, 0xC9, 0xC9, 0x39, 0xAB, 0x52, 0x0E,
	  0x8A, 0x5A, 0xAF, 0xB3, 0xA3, 0x93, 0x4D, 0xBB,
	  0xFE, 0x62, 0x9B, 0x02, 0xCC, 0xA7, 0xB4, 0xAE,
	  0x86, 0x65, 0x88, 0x19, 0xD7, 0x44, 0xA7, 0xE4,
	  0x18, 0xB6, 0xCE, 0x01, 0xCD, 0xDF, 0x36, 0x81,
	  0xD5, 0xE1, 0x62, 0xF8, 0xD0, 0x27, 0xF1, 0x86,
	  0xA8, 0x58, 0xA7, 0xEB, 0x39, 0x79, 0x56, 0x41 },

	/* p */
	512,
	{ 0xCF, 0xDA, 0xF9, 0x99, 0x6F, 0x05, 0x95, 0x84,
	  0x09, 0x90, 0xB3, 0xAB, 0x39, 0xB7, 0xDD, 0x1D,
	  0x7B, 0xFC, 0xFD, 0x10, 0x35, 0xA0, 0x18, 0x1D,
	  0x9A, 0x11, 0x30, 0x90, 0xD4, 0x3B, 0xF0, 0x5A,
	  0xC1, 0xA6, 0xF4, 0x53, 0xD0, 0x94, 0xA0, 0xED,
	  0xE0, 0xE4, 0xE0, 0x8E, 0x44, 0x18, 0x42, 0x42,
	  0xE1, 0x2C, 0x0D, 0xF7, 0x30, 0xE2, 0xB8, 0x09,
	  0x73, 0x50, 0x28, 0xF6, 0x55, 0x85, 0x57, 0x03 },

	/* q */
	512,
	{ 0xC0, 0x81, 0xC4, 0x82, 0x6E, 0xF6, 0x1C, 0x92,
	  0x83, 0xEC, 0x17, 0xFB, 0x30, 0x98, 0xED, 0x6E,
	  0x89, 0x92, 0xB2, 0xA1, 0x21, 0x0D, 0xC1, 0x95,
	  0x49, 0x99, 0xD3, 0x79, 0xD3, 0xBD, 0x94, 0x93,
	  0xB9, 0x28, 0x68, 0xFF, 0xDE, 0xEB, 0xE8, 0xD2,
	  0x0B, 0xED, 0x7C, 0x08, 0xD0, 0xD5, 0x59, 0xE3,
	  0xC1, 0x76, 0xEA, 0xC1, 0xCD, 0xB6, 0x8B, 0x39,
	  0x4E, 0x29, 0x59, 0x5F, 0xFA, 0xCE, 0x83, 0xA5 },

	/* u */
	511,
	{ 0x4B, 0x87, 0x97, 0x1F, 0x27, 0xED, 0xAA, 0xAF,
	  0x42, 0xF4, 0x57, 0x82, 0x3F, 0xEC, 0x80, 0xED,
	  0x1E, 0x91, 0xF8, 0xB4, 0x33, 0xDA, 0xEF, 0xC3,
	  0x03, 0x53, 0x0F, 0xCE, 0xB9, 0x5F, 0xE4, 0x29,
	  0xCC, 0xEE, 0x6A, 0x5E, 0x11, 0x0E, 0xFA, 0x66,
	  0x85, 0xDC, 0xFC, 0x48, 0x31, 0x0C, 0x00, 0x97,
	  0xC6, 0x0A, 0xF2, 0x34, 0x60, 0x6B, 0xF7, 0x68,
	  0x09, 0x4E, 0xCF, 0xB1, 0x9E, 0x33, 0x9A, 0x41 },

	/* exponent1 */
	511,
	{ 0x6B, 0x2A, 0x0D, 0xF8, 0x22, 0x7A, 0x71, 0x8C,
	  0xE2, 0xD5, 0x9D, 0x1C, 0x91, 0xA4, 0x8F, 0x37,
	  0x0D, 0x5E, 0xF1, 0x26, 0x73, 0x4F, 0x78, 0x3F,
	  0x82, 0xD8, 0x8B, 0xFE, 0x8F, 0xBD, 0xDB, 0x7D,
	  0x1F, 0x4C, 0xB1, 0xB9, 0xA8, 0xD7, 0x88, 0x65,
	  0x3C, 0xC7, 0x24, 0x53, 0x95, 0x1E, 0x20, 0xC3,
	  0x94, 0x8E, 0x7F, 0x20, 0xCC, 0x2E, 0x88, 0x0E,
	  0x2F, 0x4A, 0xCB, 0xE3, 0xBD, 0x52, 0x02, 0xFB },

	/* exponent2 */
	509,
	{ 0x10, 0x27, 0xD3, 0xD2, 0x0E, 0x75, 0xE1, 0x17,
	  0xFA, 0xB2, 0x49, 0xA0, 0xEF, 0x07, 0x26, 0x85,
	  0xEC, 0x4D, 0xBF, 0x67, 0xFE, 0x5A, 0x25, 0x30,
	  0xDE, 0x28, 0x66, 0xB3, 0x06, 0xAE, 0x16, 0x55,
	  0xFF, 0x68, 0x00, 0xC7, 0xD8, 0x71, 0x7B, 0xEC,
	  0x84, 0xCB, 0xBD, 0x69, 0x0F, 0xFD, 0x97, 0xB9,
	  0xA1, 0x76, 0xD5, 0x64, 0xC6, 0x5A, 0xD7, 0x7C,
	  0x4B, 0xAE, 0xF4, 0xAD, 0x35, 0x63, 0x37, 0x71 }
	};

static const RSA_KEY rsa2048TestKey = {
	/* n */
	2048,
	{ 0xBC, 0xB9, 0x69, 0xBE, 0x8A, 0xDE, 0x29, 0x4B, 
	  0xFC, 0x0C, 0xCA, 0x10, 0xBC, 0x16, 0x30, 0x9B, 
	  0x78, 0xE2, 0xDB, 0x18, 0x61, 0x4F, 0x2C, 0xD8, 
	  0x88, 0xFD, 0xC8, 0x59, 0xD0, 0x24, 0x95, 0x79, 
	  0x95, 0x33, 0x8E, 0x41, 0xAB, 0x8E, 0x36, 0x6A, 
	  0xB1, 0xAA, 0xE7, 0xA0, 0x06, 0x70, 0xA8, 0x47, 
	  0xC3, 0xA7, 0xFB, 0x3F, 0xA6, 0x62, 0xC2, 0xD1, 
	  0x9B, 0xA2, 0x7A, 0x93, 0x65, 0x02, 0x31, 0x5C, 
	  0x61, 0x18, 0xF3, 0x61, 0x4E, 0x11, 0x1F, 0x77, 
	  0xDB, 0x86, 0x11, 0x73, 0xA3, 0x7A, 0x30, 0x46, 
	  0x10, 0xE3, 0x23, 0xE2, 0x9E, 0x41, 0x23, 0xA2, 
	  0x32, 0x25, 0x1D, 0x9B, 0x15, 0x64, 0x52, 0x88, 
	  0x97, 0x70, 0x3D, 0x83, 0x0A, 0xAC, 0x47, 0x2E, 
	  0x0E, 0xFE, 0x56, 0xBA, 0x2E, 0x3A, 0xEB, 0xE7, 
	  0x56, 0xDC, 0x60, 0xA2, 0xEA, 0xBF, 0xFC, 0xD0, 
	  0xAD, 0xED, 0xB3, 0xC2, 0x6B, 0x0E, 0xAE, 0x00, 
	  0x2A, 0x19, 0xE1, 0xFD, 0x85, 0x14, 0x53, 0xA6, 
	  0xD4, 0xBE, 0x7D, 0xF0, 0xC8, 0x39, 0xFF, 0x07, 
	  0x58, 0x79, 0x52, 0x1E, 0xE4, 0xF9, 0xC9, 0xE1, 
	  0x82, 0xD1, 0xF6, 0x1B, 0x8B, 0x69, 0x26, 0x2E, 
	  0x9F, 0x8D, 0xDE, 0xB5, 0x9A, 0x9C, 0xAF, 0x7A, 
	  0x61, 0x00, 0xFC, 0x7B, 0xC1, 0x47, 0x34, 0xBB, 
	  0x49, 0x1C, 0x99, 0x4D, 0x63, 0xC3, 0x47, 0xE8, 
	  0xE9, 0x75, 0x08, 0xD0, 0xE2, 0x9D, 0xA6, 0x56, 
	  0x64, 0x7D, 0xCE, 0x62, 0x7B, 0xE9, 0x4E, 0xE5, 
	  0x25, 0xA2, 0xAF, 0x36, 0xC4, 0x95, 0x17, 0xA5, 
	  0xE9, 0x52, 0x0D, 0xF6, 0x29, 0x1E, 0xAE, 0xC5, 
	  0x6C, 0x43, 0x00, 0x02, 0xE3, 0x03, 0xE5, 0x2C, 
	  0x12, 0x63, 0x7E, 0x5E, 0x97, 0x93, 0x7D, 0x35, 
	  0xBB, 0x58, 0xD0, 0xD1, 0x74, 0x3B, 0xC0, 0x2D, 
	  0x86, 0x66, 0x1B, 0x81, 0x45, 0x64, 0xE5, 0xE0, 
	  0xAC, 0x39, 0x22, 0xEA, 0x25, 0x5B, 0x7D, 0x41 }, 

	/* e */
	17,
	{ 0x01, 0x00, 0x01 }, 

	/* d */
	2047,
	{ 0x4A, 0x93, 0x15, 0xD7, 0x06, 0x76, 0xDD, 0x68, 
	  0xBA, 0x33, 0xAF, 0x91, 0x47, 0x51, 0x99, 0x69, 
	  0x86, 0x2E, 0x56, 0x97, 0x5E, 0xB4, 0x73, 0xAB, 
	  0x29, 0x0E, 0xE7, 0xA1, 0x9D, 0xDF, 0x26, 0xF5, 
	  0xC1, 0x60, 0x7B, 0x01, 0x36, 0x32, 0x5F, 0x0C, 
	  0x70, 0x22, 0x71, 0x9E, 0xC9, 0x8C, 0xB0, 0xE2, 
	  0x92, 0xCD, 0x09, 0x3A, 0x50, 0x9C, 0x4C, 0x11, 
	  0x99, 0xE7, 0x6D, 0x7A, 0x5A, 0xFA, 0xAF, 0xD8, 
	  0xAA, 0x41, 0xBA, 0xC2, 0xA3, 0x9F, 0x9E, 0x88, 
	  0xB5, 0x45, 0x58, 0x16, 0x12, 0xEE, 0x50, 0xAF, 
	  0x0F, 0x33, 0x42, 0x55, 0xE5, 0x65, 0x26, 0x18, 
	  0x8C, 0xAA, 0x1F, 0xF5, 0xCD, 0x51, 0x34, 0x4F, 
	  0xE7, 0x4F, 0xA1, 0xEE, 0xEB, 0x43, 0xC2, 0x68, 
	  0xCF, 0xE1, 0xEF, 0x11, 0x68, 0xFD, 0x3D, 0x84, 
	  0xCF, 0xCD, 0x0B, 0x9E, 0xB5, 0x16, 0xA2, 0x67, 
	  0x2F, 0xA3, 0x73, 0x5A, 0x0B, 0x05, 0xE4, 0xF9, 
	  0x5B, 0x60, 0xE1, 0xEF, 0x7A, 0x12, 0x3C, 0xFC, 
	  0xF7, 0xD6, 0x34, 0x09, 0x77, 0x6D, 0xF3, 0x70, 
	  0x34, 0x16, 0x35, 0x26, 0xB4, 0xF8, 0x5F, 0x05, 
	  0xB9, 0xB2, 0x7F, 0x07, 0x17, 0x62, 0x9E, 0x1C, 
	  0x96, 0xCC, 0x9B, 0xF3, 0x19, 0xE5, 0xDA, 0x86, 
	  0x0A, 0x91, 0x06, 0x8B, 0xB6, 0xCF, 0x21, 0xD8, 
	  0x68, 0x9C, 0x5F, 0xF1, 0xA7, 0xF4, 0x80, 0x7B, 
	  0x09, 0xC5, 0x64, 0x1D, 0x3D, 0xDD, 0x68, 0x66, 
	  0x55, 0x6C, 0xDD, 0xED, 0x48, 0x43, 0x3B, 0x19, 
	  0x84, 0x6F, 0x8E, 0x87, 0x3E, 0x6D, 0xEB, 0xE5, 
	  0x28, 0x22, 0xEA, 0xE1, 0x3F, 0x44, 0xDF, 0x40, 
	  0xE3, 0xED, 0xDB, 0x0D, 0x6C, 0x96, 0x5C, 0x41, 
	  0xD7, 0x32, 0xF7, 0x12, 0x4A, 0xA3, 0x01, 0xD2, 
	  0x23, 0x79, 0x0D, 0xE6, 0xAF, 0x33, 0x8D, 0xDE, 
	  0x88, 0x32, 0x14, 0x56, 0x60, 0x03, 0x9A, 0x93, 
	  0x05, 0x2E, 0xFC, 0xB4, 0x3F, 0xB9, 0xA2, 0x31 }, 

	/* p */
	1024,
	{ 0xEE, 0x5B, 0x04, 0xEB, 0x5C, 0x16, 0x87, 0x89, 
	  0x6C, 0xF7, 0xD4, 0xDC, 0x42, 0x6D, 0xCD, 0xCA, 
	  0x3C, 0x9B, 0x7C, 0x4A, 0x94, 0x1F, 0xAD, 0xFA, 
	  0xCC, 0x6F, 0xE1, 0x7E, 0xA0, 0x50, 0x48, 0xBF, 
	  0xA7, 0x6A, 0x66, 0x66, 0x81, 0x1E, 0x79, 0xF9, 
	  0xE8, 0x45, 0xBB, 0xF4, 0xC9, 0xE1, 0x85, 0x38, 
	  0xDB, 0xF2, 0x7F, 0x77, 0x66, 0x42, 0xB4, 0xAD, 
	  0xFA, 0xFC, 0xFF, 0xE4, 0x7D, 0xC6, 0xB0, 0x4B, 
	  0xB2, 0xAD, 0x2A, 0x16, 0x2E, 0x22, 0x97, 0x8D, 
	  0x98, 0xEF, 0x7C, 0x96, 0xA3, 0x7B, 0xF0, 0x5F, 
	  0x40, 0x4E, 0xE7, 0x66, 0x06, 0x60, 0x25, 0x5B, 
	  0x36, 0x2E, 0x6A, 0x37, 0xEF, 0xC7, 0xF6, 0xDC, 
	  0x34, 0xC6, 0xC4, 0x40, 0x92, 0xC1, 0x20, 0x91, 
	  0x5C, 0xB8, 0xEB, 0xBD, 0xA5, 0xF5, 0x7B, 0x54, 
	  0x93, 0x20, 0x49, 0x02, 0x4F, 0xA4, 0x0A, 0x7F, 
	  0xD4, 0x76, 0x6F, 0x6D, 0x92, 0x8B, 0xD0, 0xDD }, 

	/* q */
	1024,
	{ 0xCA, 0xB1, 0xD9, 0xF4, 0x19, 0x4B, 0xDC, 0x6E, 
	  0xF8, 0x88, 0xED, 0x8C, 0x93, 0x3F, 0x56, 0x79, 
	  0xA4, 0x2E, 0x54, 0x3B, 0xD5, 0x69, 0xCD, 0x4F, 
	  0xE0, 0x0C, 0x2B, 0x82, 0xEC, 0xFF, 0x7C, 0x05, 
	  0x83, 0x7D, 0x68, 0xB6, 0x7B, 0x51, 0x8B, 0x00, 
	  0x3F, 0x90, 0x63, 0x62, 0xA9, 0xFC, 0xA0, 0xBC, 
	  0x47, 0xD9, 0x7B, 0x0E, 0xC3, 0x3A, 0x0C, 0x89, 
	  0x96, 0x23, 0xAC, 0xBA, 0x09, 0xCF, 0x2D, 0xC2, 
	  0x0A, 0x0C, 0xA1, 0xDD, 0x63, 0x82, 0x4B, 0xDC, 
	  0x88, 0x0D, 0x9B, 0xF4, 0x9C, 0x0F, 0x5F, 0xA6, 
	  0xB4, 0xA2, 0xFE, 0xFB, 0x08, 0xB7, 0x0E, 0xED, 
	  0xA5, 0x04, 0x13, 0xAB, 0x6B, 0x66, 0xF1, 0x85, 
	  0xD0, 0xB1, 0xAB, 0xDC, 0x2F, 0x7E, 0x61, 0xB1, 
	  0x28, 0x87, 0xBD, 0xC6, 0xA3, 0xD5, 0xA0, 0x04, 
	  0xD4, 0x9F, 0x49, 0xF9, 0xA9, 0xB4, 0xB1, 0x33, 
	  0x8C, 0xFA, 0x62, 0xDE, 0x9A, 0x16, 0x85, 0xB5 }, 

	/* u */
	1023,
	{ 0x5F, 0x6C, 0x5D, 0x2D, 0x73, 0x9C, 0x2B, 0x8C, 
	  0x1C, 0x8B, 0x96, 0x6C, 0x84, 0xDB, 0x21, 0x86, 
	  0xF1, 0xEA, 0x75, 0xE1, 0xC5, 0x96, 0x23, 0x38, 
	  0x82, 0x02, 0x77, 0x8B, 0xFA, 0x79, 0xE3, 0xA2, 
	  0x88, 0x0C, 0x38, 0x9C, 0x56, 0x44, 0xAA, 0x1C, 
	  0x20, 0xB2, 0x9E, 0x9D, 0xD9, 0xAE, 0x95, 0x6B, 
	  0x43, 0xB1, 0x4C, 0x38, 0x88, 0x9C, 0x12, 0x4E, 
	  0x7C, 0x1F, 0xD1, 0x41, 0x6E, 0x11, 0xAA, 0x48, 
	  0x7A, 0xAC, 0x56, 0xF0, 0x6B, 0xA3, 0x35, 0xE4, 
	  0x6B, 0xC0, 0xF4, 0x33, 0x74, 0xC0, 0x1E, 0xC4, 
	  0x04, 0x44, 0xF0, 0x24, 0x32, 0x83, 0xB0, 0xC7, 
	  0xAC, 0x5C, 0x6D, 0x29, 0x87, 0x1A, 0xA7, 0x03, 
	  0x7B, 0x61, 0x69, 0x18, 0xA1, 0x26, 0x00, 0x0A, 
	  0x96, 0x3A, 0x56, 0x1A, 0xA0, 0xFC, 0xE2, 0x4C, 
	  0x51, 0xE0, 0x8F, 0xE5, 0x68, 0x69, 0xEE, 0xE8, 
	  0xA9, 0x1B, 0x24, 0x0D, 0x55, 0x55, 0x98, 0x72 }, 

	/* exponent1 */
	1023,
	{ 0x71, 0xC3, 0x9F, 0xA5, 0x76, 0x5E, 0x8A, 0x72, 
	  0x5D, 0x40, 0x2C, 0xA8, 0xB4, 0x4C, 0x14, 0x5C, 
	  0xE2, 0x70, 0x93, 0xF2, 0x44, 0xA0, 0x9A, 0x39, 
	  0x8A, 0x3A, 0x1C, 0x36, 0x83, 0xED, 0xCD, 0xCB, 
	  0x2B, 0xEC, 0xEC, 0xD3, 0x1F, 0xED, 0x9B, 0xEA, 
	  0x5B, 0xA2, 0x6D, 0x03, 0x79, 0x17, 0xDA, 0xAE, 
	  0x38, 0xCC, 0x95, 0x6A, 0x37, 0xB4, 0xBE, 0xE8, 
	  0x0B, 0x53, 0x96, 0x0F, 0x48, 0xB8, 0xFC, 0x8C, 
	  0x24, 0xCB, 0xE1, 0xBA, 0x94, 0x6A, 0x8E, 0x4B, 
	  0x57, 0x23, 0x77, 0x23, 0xAF, 0x04, 0x08, 0xC6, 
	  0x6D, 0xBB, 0x3B, 0x56, 0xC6, 0xD4, 0x3D, 0x00, 
	  0x3B, 0xEC, 0x0B, 0x66, 0x87, 0x5B, 0xB9, 0xC7, 
	  0x80, 0xA9, 0x1E, 0x22, 0x73, 0xE9, 0x19, 0xD2, 
	  0x47, 0x9F, 0x3B, 0x65, 0x59, 0x40, 0xC1, 0x8C, 
	  0xAC, 0x6C, 0x4C, 0x6C, 0x7D, 0xF6, 0x9D, 0xCC, 
	  0x45, 0x6C, 0x01, 0xE3, 0x1A, 0x7F, 0x01, 0x41 }, 

	/* exponent2 */
	1022,
	{ 0x32, 0x07, 0x93, 0xF4, 0x5C, 0x0A, 0x0D, 0x6E, 
	  0x96, 0x89, 0xB5, 0x98, 0x6C, 0xFF, 0xC5, 0x28, 
	  0x61, 0x0D, 0xCE, 0x5C, 0xB6, 0x60, 0x56, 0xFC, 
	  0xD0, 0x20, 0x30, 0xDD, 0x30, 0x02, 0x1F, 0x6A, 
	  0x7C, 0xFA, 0x07, 0x4E, 0x83, 0x41, 0xAD, 0x3D, 
	  0x72, 0x73, 0x01, 0x14, 0xE9, 0x40, 0x21, 0xAC, 
	  0x57, 0x4F, 0xA6, 0xC0, 0x0E, 0x0F, 0xD5, 0xE8, 
	  0x5F, 0xD6, 0x8E, 0x5B, 0x9C, 0xF0, 0x36, 0x2B, 
	  0x1E, 0xAF, 0xDF, 0x83, 0xF5, 0x7B, 0xC3, 0x9D, 
	  0xBB, 0x37, 0x20, 0xB7, 0x4F, 0x8D, 0xBB, 0xDE, 
	  0x39, 0xD7, 0xC1, 0x77, 0xD4, 0xBE, 0xDA, 0x40, 
	  0x6D, 0xEA, 0x83, 0xB0, 0x5B, 0xE2, 0x1C, 0xDB, 
	  0x1A, 0x97, 0xC0, 0x03, 0xA8, 0xF5, 0x58, 0xC7, 
	  0x91, 0x69, 0x6F, 0xBE, 0x07, 0xD2, 0x42, 0x9C, 
	  0xEE, 0x9E, 0x22, 0x74, 0x2D, 0x1F, 0x1C, 0x5D, 
	  0xCC, 0xFE, 0x40, 0x49, 0x11, 0x5F, 0x5D, 0xC1 }
	};

typedef struct {
	const int pLen; const BYTE p[ 128 ];
	const int qLen; const BYTE q[ 20 ];
	const int gLen; const BYTE g[ 128 ];
	const int xLen; const BYTE x[ 20 ];
	const int yLen; const BYTE y[ 128 ];
	} DLP_KEY;

static const DLP_KEY dlp1024TestKey = {
	/* p */
	1024,
	{ 0x04, 0x4C, 0xDD, 0x5D, 0xB6, 0xED, 0x23, 0xAE, 
	  0xB2, 0xA7, 0x59, 0xE6, 0xF8, 0x3D, 0xA6, 0x27, 
	  0x85, 0xF2, 0xFE, 0xE2, 0xE8, 0xF3, 0xDA, 0xA3, 
	  0x7B, 0xD6, 0x48, 0xD4, 0x44, 0xCA, 0x6E, 0x10, 
	  0x97, 0x6C, 0x1D, 0x6C, 0x39, 0xA7, 0x0C, 0x88, 
	  0x8E, 0x1F, 0xDD, 0xF7, 0x59, 0x69, 0xDA, 0x36, 
	  0xDD, 0xB8, 0x3E, 0x1A, 0xD2, 0x91, 0x3E, 0x30, 
	  0xB1, 0xB5, 0xC2, 0xBC, 0xA9, 0xA3, 0xA5, 0xDE, 
	  0xC7, 0xCF, 0x51, 0x2C, 0x1B, 0x89, 0xD0, 0x71, 
	  0xE3, 0x71, 0xBB, 0x50, 0x86, 0x26, 0x32, 0x9F, 
	  0xF5, 0x4A, 0x9C, 0xB1, 0x78, 0x7B, 0x47, 0x1F, 
	  0x19, 0xC7, 0x26, 0x22, 0x15, 0x62, 0x71, 0xAB, 
	  0xD7, 0x25, 0xA5, 0xE4, 0x68, 0x71, 0x93, 0x5D, 
	  0x1F, 0x29, 0x01, 0x05, 0x9C, 0x57, 0x3A, 0x09, 
	  0xB0, 0xB8, 0xE4, 0xD2, 0x37, 0x90, 0x36, 0x2F, 
	  0xBF, 0x1E, 0x74, 0xB4, 0x6B, 0xE4, 0x66, 0x07 }, 

	/* q */
	160,
	{ 0xFD, 0xD9, 0xC8, 0x5F, 0x73, 0x62, 0xC9, 0x79, 
	  0xEF, 0xD5, 0x09, 0x07, 0x02, 0xE7, 0xF2, 0x90, 
	  0x97, 0x13, 0x26, 0x1D }, 

	/* g */
	1024,
	{ 0x02, 0x4E, 0xDD, 0x0D, 0x7F, 0x4D, 0xB1, 0x42, 
	  0x01, 0x50, 0xE7, 0x9A, 0x65, 0x73, 0x8B, 0x31, 
	  0x24, 0x6B, 0xC6, 0x74, 0xA7, 0x68, 0x26, 0x11, 
	  0x06, 0x3C, 0x96, 0xA9, 0xA6, 0x23, 0x12, 0x79, 
	  0xC4, 0xEE, 0x21, 0x88, 0xDD, 0xE3, 0xF0, 0x37, 
	  0xCE, 0x3E, 0x54, 0x53, 0x57, 0x03, 0x30, 0xE4, 
	  0xD3, 0xAB, 0x39, 0x4E, 0x39, 0xDC, 0xA2, 0x88, 
	  0x82, 0xF6, 0xE8, 0xBA, 0xAC, 0xF5, 0x7D, 0x2F, 
	  0x23, 0x9A, 0x09, 0x94, 0xB2, 0x89, 0xA2, 0xC9, 
	  0x7C, 0xBE, 0x4D, 0x48, 0x0E, 0x59, 0x51, 0xB8, 
	  0x7D, 0x99, 0x88, 0x79, 0xA8, 0x13, 0x0E, 0x12, 
	  0x56, 0x9D, 0x4B, 0x2E, 0xE0, 0xE1, 0x37, 0x78, 
	  0x6F, 0xCC, 0x4D, 0x97, 0xA9, 0x02, 0x0E, 0xD2, 
	  0x43, 0x83, 0xEC, 0x4F, 0xC2, 0x70, 0xEF, 0x16, 
	  0xDE, 0xBF, 0xBA, 0xD1, 0x6C, 0x8A, 0x36, 0xEE, 
	  0x42, 0x41, 0xE9, 0xE7, 0x66, 0xAE, 0x46, 0x3B }, 

	/* x */
	160,
	{ 0xD9, 0x41, 0x29, 0xF7, 0x40, 0x32, 0x09, 0x71, 
	  0xB8, 0xE2, 0xB8, 0xCB, 0x74, 0x46, 0x0B, 0xD4, 
	  0xF2, 0xAB, 0x54, 0xA1 }, 

	/* y */
	1024,
	{ 0x01, 0x7E, 0x16, 0x5B, 0x65, 0x51, 0x0A, 0xDA, 
	  0x82, 0x1A, 0xD9, 0xF4, 0x1E, 0x66, 0x6D, 0x7D, 
	  0x23, 0xA6, 0x28, 0x2F, 0xE6, 0xC2, 0x03, 0x8E, 
	  0x8C, 0xAB, 0xC2, 0x08, 0x87, 0xC9, 0xE8, 0x51, 
	  0x0A, 0x37, 0x1E, 0xD4, 0x41, 0x7F, 0xA2, 0xC5, 
	  0x48, 0x26, 0xB7, 0xF6, 0xC2, 0x6F, 0xB2, 0xF8, 
	  0xF9, 0x43, 0x43, 0xF9, 0xDA, 0xAB, 0xA2, 0x59, 
	  0x27, 0xBA, 0xC9, 0x1C, 0x8C, 0xAB, 0xC4, 0x90, 
	  0x27, 0xE1, 0x10, 0x39, 0x6F, 0xD2, 0xCD, 0x7C, 
	  0xD1, 0x0B, 0xFA, 0x28, 0xD2, 0x7A, 0x7B, 0x52, 
	  0x8A, 0xA0, 0x5A, 0x0F, 0x10, 0xF7, 0xBA, 0xFD, 
	  0x33, 0x0C, 0x3C, 0xCE, 0xE5, 0xF2, 0xF6, 0x92, 
	  0xED, 0x04, 0xBF, 0xD3, 0xF8, 0x3D, 0x39, 0xCC, 
	  0xAA, 0xCC, 0x0B, 0xB2, 0x6B, 0xD8, 0xB2, 0x8A, 
	  0x5C, 0xCE, 0xDA, 0xF9, 0xE1, 0xA7, 0x23, 0x50, 
	  0xDC, 0xCE, 0xA4, 0xD5, 0xA5, 0x4F, 0x08, 0x0F } 
	};

/* The DH key uses cryptlib-internal mechanisms, the following data and
   associated test can't be used with an unmodified version of cryptlib */

#ifdef TEST_DH

#define CRYPT_IATTRIBUTE_KEY_SPKI	8015

static const BYTE dh1024SPKI[] = {
	0x30, 0x82, 0x01, 0x21,
		0x30, 0x82, 0x01, 0x17,
			0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01,
			0x30, 0x82, 0x01, 0x0A,
				0x02, 0x81, 0x81, 0x00,		/* p */
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
					0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
					0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
					0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
					0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
					0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
					0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
					0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
					0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
					0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
					0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
					0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
					0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
					0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0x02, 0x01,					/* g */
					0x02,
				0x02, 0x81, 0x80,			/* q */
					0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
					0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
					0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
					0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
					0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
					0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
					0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
					0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
					0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
					0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
					0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
					0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
					0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
					0x24, 0x94, 0x33, 0x28, 0xF6, 0x73, 0x29, 0xC0,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x03, 0x04, 0x00,
			0x02, 0x01, 0x00				/* y */
	};
#endif /* TEST_DH */

typedef struct {
	const CRYPT_ECCCURVE_TYPE curveType;
	const int pLen; const BYTE p[ 66 ];
	const int aLen; const BYTE a[ 66 ];
	const int bLen; const BYTE b[ 66 ];
	const int gxLen; const BYTE gx[ 66 ];
	const int gyLen; const BYTE gy[ 66 ];
	const int nLen; const BYTE n[ 66 ];
	const int qxLen; const BYTE qx[ 66 ];
	const int qyLen; const BYTE qy[ 66 ];
	const int dLen; const BYTE d[ 66 ];
	} ECC_KEY;

/* NIST curve P-256 */

static const ECC_KEY eccP256TestKey = {
#if 0
	CRYPT_ECCCURVE_NONE,
	/* p */
	256,
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	  0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
	/* a */
	256,
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	  0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC },
	/* b */
	256,
	{ 0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 
	  0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC, 
	  0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 
	  0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B },
	/* gx */
	256,
	{ 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 
	  0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 
	  0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 
	  0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96 },
	/* gy */
	256,
	{ 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 
	  0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 
	  0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 
	  0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5 },
	/* n */
	256,
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,  
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	  0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 
	  0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51 },
#else
	CRYPT_ECCCURVE_P256,
	0, { 0 },	/* p */
	0, { 0 },	/* a */
	0, { 0 },	/* b */
	0, { 0 },	/* gx */
	0, { 0 },	/* gy */
	0, { 0 },	/* n */
#endif /* 0 */
	/* qx */
	256,
	{ 0x26, 0x0C, 0xAB, 0x1F, 0xF2, 0x5E, 0x8F, 0x54,
	  0x1C, 0x52, 0x66, 0x4A, 0x1B, 0x23, 0x8F, 0x68,
	  0x0D, 0xEB, 0xCB, 0x0B, 0x4A, 0x4E, 0x4C, 0x88,
	  0xCA, 0x53, 0x1F, 0x32, 0xAB, 0x0F, 0x72, 0x56 },
	/* qy */
	256,
	{ 0x94, 0x56, 0xD7, 0x00, 0x6A, 0x50, 0x06, 0xC0,
	  0x87, 0x9B, 0x73, 0x0D, 0x3F, 0x16, 0x37, 0x42,
	  0xE8, 0x8A, 0xA0, 0x7F, 0x9F, 0x87, 0xD5, 0x29,
	  0xCF, 0x3C, 0x83, 0xC7, 0xC3, 0xE3, 0x93, 0x58 },
	/* d */
	256,
	{ 0xC6, 0x91, 0x9E, 0xD5, 0xF2, 0x84, 0xE0, 0x30,
	  0xD5, 0x7B, 0xA8, 0x13, 0x51, 0x0B, 0x50, 0x1C,
	  0x7D, 0x8E, 0x14, 0x66, 0xE2, 0xF1, 0x49, 0x97,
	  0x06, 0x49, 0x61, 0x67, 0xFA, 0xA3, 0xEA, 0x05 }
	};

/****************************************************************************
*																			*
*								Key Load Routines							*
*																			*
****************************************************************************/

/* Set the label for a device object */

static BOOLEAN setLabel( const CRYPT_CONTEXT cryptContext, const C_STR label )
	{
	int status;

	status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
									  label, paramStrlen( label ) );
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		printf( "A key object with the label '%s' already exists inside the\n"
				"device.  To perform this test, you need to delete the "
				"existing object so\nthat cryptlib can create a new one, "
				"line %d.\n", label, __LINE__ );
		return( FALSE );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to set object label failed with status %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load DH, RSA, DSA, and Elgamal PKC encrytion contexts */

#ifdef TEST_DH

typedef struct {
	void *data;							/* Data */
	int length;							/* Length */
	} xMESSAGE_DATA;

#define xsetMessageData( msgDataPtr, dataPtr, dataLength ) \
	{ \
	( msgDataPtr )->data = ( dataPtr ); \
	( msgDataPtr )->length = ( dataLength ); \
	}

BOOLEAN loadDHKey( const CRYPT_DEVICE cryptDevice,
				   CRYPT_CONTEXT *cryptContext )
	{
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, cryptContext,
										   CRYPT_ALGO_DH );
		}
	else
		{
		status = cryptCreateContext( cryptContext, CRYPT_UNUSED,
									 CRYPT_ALGO_DH );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "crypt%sCreateContext() failed with error "
				 "code %d, line %d.\n", isDevice ? "Device" : "", status, 
				 __LINE__ );
		return( FALSE );
		}
	if( !setLabel( *cryptContext, "DH key" ) )
		{
		cryptDestroyContext( *cryptContext );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		xMESSAGE_DATA msgData;

		xsetMessageData( &msgData, ( void * ) dh1024SPKI,
						 sizeof( dh1024SPKI ) );
		status = krnlSendMessage( *cryptContext, IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
		}
	if( cryptStatusError( status ) )
		{
		printf( "DH key load failed, status = %d, line %d.\n", status,
				__LINE__ );
		cryptDestroyContext( *cryptContext );
		return( FALSE );
		}
	return( TRUE );
	}
#endif /* TEST_DH */

static int loadRSAPublicKey( const CRYPT_DEVICE cryptDevice,
							 CRYPT_CONTEXT *cryptContext,
							 const C_STR cryptContextLabel,
							 CRYPT_PKCINFO_RSA *rsaKey,
							 const BOOLEAN isDevice,
							 const BOOLEAN useLargeKey )
	{
	const RSA_KEY *rsaKeyTemplate = useLargeKey ? \
								&rsa2048TestKey : &rsa1024TestKey;
	CRYPT_PKCINFO_RSA rsaTestStructure;
	int status;

	/* Perform a check for CONFIG_PKC_ALLOCSIZE overriding 
	   CRYPT_MAX_PKCSIZE.  If this is set in misc/config.h via something
	   like CONFIG_CONSERVE_MEMORY then it'll have a different value inside
	   cryptlib than outside it, since cryptlib.h will define it to its
	   original value while misc/config.h will override it to match
	   CONFIG_PKC_ALLOCSIZE.  We can't detect this via the preprocessor
	   since the inclusion of misc/config.h to detect the override also
	   overrides the value from cryptlib.h, so we have to check the size
	   of a value typedef'd before the override happened.
	   
	   Some compilers will produce an unused-variable warning for 
	   rsaTestStructure since it's not used in anything except the sizeof()
	   compile-time evaluation.  We also need to cast the sizeof() in the
	   fprintf() to int for pedantic compilers that know that sizeof()
	   is potentially a large unsigned value even though it's actually not 
	   even a 16-bit int value */
	if( sizeof( rsaTestStructure.n ) < CRYPT_MAX_PKCSIZE - 8 || \
		sizeof( rsaTestStructure.n ) > CRYPT_MAX_PKCSIZE + 8 )
		{
		fprintf( outputStream, "CRYPT_MAX_PKCSIZE appears to be %d in "
				 "cryptlib but %d in the test code,\n"
				 "has CONFIG_PKC_ALLOCSIZE been used inconsistently?\n", 
				 CRYPT_MAX_PKCSIZE, ( int ) sizeof( rsaTestStructure.n ) );
		return( CRYPT_ERROR_FAILED );
		}

	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, cryptContext,
										   CRYPT_ALGO_RSA );
		}
	else
		{
		status = cryptCreateContext( cryptContext, CRYPT_UNUSED,
									 CRYPT_ALGO_RSA );
		}
	if( cryptStatusError( status ) )
		{
		fprintf( outputStream, "crypt%sCreateContext() failed with error "
				 "code %d, line %d.\n", isDevice ? "Device" : "", status, 
				 __LINE__ );
		return( status );
		}
	if( isDevice && !setLabel( *cryptContext, cryptContextLabel ) )
		{
		cryptDestroyContext( *cryptContext );
		return( CRYPT_ERROR_FAILED );
		}
	cryptInitComponents( rsaKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( rsaKey->n, rsaKeyTemplate->n, rsaKeyTemplate->nLen );
	cryptSetComponent( rsaKey->e, rsaKeyTemplate->e, rsaKeyTemplate->eLen );
	status = cryptSetAttributeString( *cryptContext,
								CRYPT_CTXINFO_KEY_COMPONENTS, rsaKey,
								sizeof( CRYPT_PKCINFO_RSA ) );
	cryptDestroyComponents( rsaKey );
	if( cryptStatusError( status ) )
		cryptDestroyContext( *cryptContext );
	return( status );
	}

BOOLEAN loadRSAContextsEx( const CRYPT_DEVICE cryptDevice,
						   CRYPT_CONTEXT *cryptContext,
						   CRYPT_CONTEXT *decryptContext,
						   const C_STR cryptContextLabel,
						   const C_STR decryptContextLabel,
						   const BOOLEAN useLargeKey,
						   const BOOLEAN useMinimalKey )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	const RSA_KEY *rsaKeyTemplate = useLargeKey ? \
									&rsa2048TestKey : &rsa1024TestKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	BOOLEAN loadLargeKey = useLargeKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( rsaKey = ( CRYPT_PKCINFO_RSA * ) malloc( sizeof( CRYPT_PKCINFO_RSA ) ) ) == NULL )
		return( FALSE );

	/* Some devices only support a single key size that isn't the same as
	   the built-in one so we adjust the key size being used if necessary */
	if( isDevice )
		{
		CRYPT_QUERY_INFO cryptQueryInfo;

		status = cryptDeviceQueryCapability( cryptDevice, CRYPT_ALGO_RSA,
											 &cryptQueryInfo );
		if( cryptStatusError( status ) )
			{
			free( rsaKey );
			return( FALSE );
			}
		if( cryptQueryInfo.keySize != ( rsa1024TestKey.nLen >> 3 ) )
			{
			if( cryptQueryInfo.keySize != ( rsa2048TestKey.nLen >> 3 ) )
				{
				printf( "Device requires a %d-bit key, which doesn't "
						"correspond to any built-in\ncryptlib key.\n",
						cryptQueryInfo.keySize );
				free( rsaKey );
				return( FALSE );
				}
			rsaKeyTemplate = &rsa2048TestKey;
			loadLargeKey = TRUE;
			}
		}

	/* Create the encryption context */
	if( cryptContext != NULL )
		{
		status = loadRSAPublicKey( cryptDevice, cryptContext,
								   cryptContextLabel, rsaKey, isDevice,
								   loadLargeKey );
		if( status == CRYPT_ERROR_NOTAVAIL && isDevice )
			{
			/* The device doesn't support public-key ops, use a native
			   context for the public key */
			puts( "  Warning: Device doesn't support public-key operations, "
				  "using a cryptlib\n  native context instead." );
			status = loadRSAPublicKey( CRYPT_UNUSED, cryptContext,
									   cryptContextLabel, rsaKey, FALSE,
									   loadLargeKey );
			}
		if( cryptStatusError( status ) )
			{
			free( rsaKey );
			fprintf( outputStream, "Public key load failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		if( decryptContext == NULL )
			{
			/* We're only using a public-key context, return */
			free( rsaKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, decryptContext,
										   CRYPT_ALGO_RSA );
		}
	else
		{
		status = cryptCreateContext( decryptContext, CRYPT_UNUSED,
									 CRYPT_ALGO_RSA );
		}
	if( cryptStatusError( status ) )
		{
		free( rsaKey );
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								cryptContextLabel );
				}
			}
		fprintf( outputStream, "crypt%sCreateContext() failed with error "
				 "code %d, line %d.\n", isDevice ? "Device" : "", status, 
				 __LINE__ );
		return( FALSE );
		}
	if( !setLabel( *decryptContext, decryptContextLabel ) )
		{
		free( rsaKey );
		cryptDestroyContext( *decryptContext );
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								cryptContextLabel );
				}
			}
		return( FALSE );
		}
	cryptInitComponents( rsaKey, CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( rsaKey->n, rsaKeyTemplate->n, rsaKeyTemplate->nLen );
	cryptSetComponent( rsaKey->e, rsaKeyTemplate->e, rsaKeyTemplate->eLen );
	cryptSetComponent( rsaKey->d, rsaKeyTemplate->d, rsaKeyTemplate->dLen );
	cryptSetComponent( rsaKey->p, rsaKeyTemplate->p, rsaKeyTemplate->pLen );
	cryptSetComponent( rsaKey->q, rsaKeyTemplate->q, rsaKeyTemplate->qLen );
	if( !useMinimalKey )
		{
		cryptSetComponent( rsaKey->u, rsaKeyTemplate->u, rsaKeyTemplate->uLen );
		cryptSetComponent( rsaKey->e1, rsaKeyTemplate->e1, rsaKeyTemplate->e1Len );
		cryptSetComponent( rsaKey->e2, rsaKeyTemplate->e2, rsaKeyTemplate->e2Len );
		}
	status = cryptSetAttributeString( *decryptContext,
									  CRYPT_CTXINFO_KEY_COMPONENTS, rsaKey,
									  sizeof( CRYPT_PKCINFO_RSA ) );
	cryptDestroyComponents( rsaKey );
	free( rsaKey );
	if( cryptStatusError( status ) )
		{
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								cryptContextLabel );
				}
			}
		cryptDestroyContext( *decryptContext );
		if( isDevice )
			{
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
							decryptContextLabel );
			}
		printf( "Private key load failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadRSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext )
	{
	return( loadRSAContextsEx( cryptDevice, cryptContext, decryptContext,
							   RSA_PUBKEY_LABEL, RSA_PRIVKEY_LABEL, FALSE, 
							   FALSE ) );
	}
BOOLEAN loadRSAContextsLarge( const CRYPT_DEVICE cryptDevice,
							  CRYPT_CONTEXT *cryptContext,
							  CRYPT_CONTEXT *decryptContext )
	{
	return( loadRSAContextsEx( cryptDevice, cryptContext, decryptContext,
							   RSA_PUBKEY_LABEL, RSA_PRIVKEY_LABEL, TRUE, 
							   FALSE ) );
	}

BOOLEAN loadDSAContextsEx( const CRYPT_DEVICE cryptDevice,
						   CRYPT_CONTEXT *sigCheckContext,
						   CRYPT_CONTEXT *signContext,
						   const C_STR sigCheckContextLabel,
						   const C_STR signContextLabel )
	{
	CRYPT_PKCINFO_DLP *dsaKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	/* Allocate room for the public-key components */
	if( ( dsaKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( FALSE );

	/* Create the signature context */
	if( signContext != NULL )
		{
		if( isDevice )
			{
			status = cryptDeviceCreateContext( cryptDevice, signContext,
											   CRYPT_ALGO_DSA );
			}
		else
			{
			status = cryptCreateContext( signContext, CRYPT_UNUSED,
										 CRYPT_ALGO_DSA );
			}
		if( cryptStatusError( status ) )
			{
			free( dsaKey );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				/* DSA support isn't always enabled, in which case we tell 
				   the caller to skip the test */
				return( status );
				}
			fprintf( outputStream, "cryptCreateContext() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		if( !setLabel( *signContext, signContextLabel ) )
			{
			free( dsaKey );
			cryptDestroyContext( *signContext );
			return( FALSE );
			}
		cryptInitComponents( dsaKey, CRYPT_KEYTYPE_PRIVATE );
		cryptSetComponent( dsaKey->p, dlp1024TestKey.p, dlp1024TestKey.pLen );
		cryptSetComponent( dsaKey->q, dlp1024TestKey.q, dlp1024TestKey.qLen );
		cryptSetComponent( dsaKey->g, dlp1024TestKey.g, dlp1024TestKey.gLen );
		cryptSetComponent( dsaKey->x, dlp1024TestKey.x, dlp1024TestKey.xLen );
		cryptSetComponent( dsaKey->y, dlp1024TestKey.y, dlp1024TestKey.yLen );
		status = cryptSetAttributeString( *signContext,
									CRYPT_CTXINFO_KEY_COMPONENTS, dsaKey,
									sizeof( CRYPT_PKCINFO_DLP ) );
		cryptDestroyComponents( dsaKey );
		if( cryptStatusError( status ) )
			{
			free( dsaKey );
			cryptDestroyContext( *signContext );
			printf( "Private key load failed with error code %d, line %d.\n", 
					status, __LINE__ );
			return( FALSE );
			}
		if( sigCheckContext == NULL )
			{
			free( dsaKey );
			return( TRUE );
			}
		}

	/* Create the sig.check context */
	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, sigCheckContext,
										   CRYPT_ALGO_DSA );
		}
	else
		{
		status = cryptCreateContext( sigCheckContext, CRYPT_UNUSED,
									 CRYPT_ALGO_DSA );
		}
	if( cryptStatusError( status ) )
		{
		free( dsaKey );
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
				}
			}
		fprintf( outputStream, "cryptCreateContext() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !setLabel( *sigCheckContext, sigCheckContextLabel ) )
		{
		free( dsaKey );
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
				}
			}
		cryptDestroyContext( *sigCheckContext );
		return( FALSE );
		}
	cryptInitComponents( dsaKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( dsaKey->p, dlp1024TestKey.p, dlp1024TestKey.pLen );
	cryptSetComponent( dsaKey->q, dlp1024TestKey.q, dlp1024TestKey.qLen );
	cryptSetComponent( dsaKey->g, dlp1024TestKey.g, dlp1024TestKey.gLen );
	cryptSetComponent( dsaKey->y, dlp1024TestKey.y, dlp1024TestKey.yLen );
	status = cryptSetAttributeString( *sigCheckContext,
									  CRYPT_CTXINFO_KEY_COMPONENTS, dsaKey,
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dsaKey );
	free( dsaKey );
	if( cryptStatusError( status ) )
		{
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
				}
			}
		cryptDestroyContext( *sigCheckContext );
		if( isDevice )
			{
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
							sigCheckContextLabel );
			}
		printf( "Public key load failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadDSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *sigCheckContext,
						 CRYPT_CONTEXT *signContext )
	{
	return( loadDSAContextsEx( cryptDevice, sigCheckContext, signContext, 
							   DSA_PUBKEY_LABEL, DSA_PRIVKEY_LABEL ) );
	}

BOOLEAN loadElgamalContexts( CRYPT_CONTEXT *cryptContext,
							 CRYPT_CONTEXT *decryptContext )
	{
	CRYPT_PKCINFO_DLP *elgamalKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( elgamalKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( FALSE );

	/* Create the encryption context */
	if( cryptContext != NULL )
		{
		status = cryptCreateContext( cryptContext, CRYPT_UNUSED,
									 CRYPT_ALGO_ELGAMAL );
		if( cryptStatusError( status ) )
			{
			free( elgamalKey );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				/* Elgamal support isn't always enabled, in which case we 
				   tell the caller to skip the test */
				return( status );
				}
			fprintf( outputStream, "cryptCreateContext() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		if( !setLabel( *cryptContext, ELGAMAL_PUBKEY_LABEL ) )
			{
			free( elgamalKey );
			cryptDestroyContext( *cryptContext );
			return( FALSE );
			}
		cryptInitComponents( elgamalKey, CRYPT_KEYTYPE_PUBLIC );
		cryptSetComponent( elgamalKey->p, dlp1024TestKey.p, dlp1024TestKey.pLen );
		cryptSetComponent( elgamalKey->g, dlp1024TestKey.g, dlp1024TestKey.gLen );
		cryptSetComponent( elgamalKey->q, dlp1024TestKey.q, dlp1024TestKey.qLen );
		cryptSetComponent( elgamalKey->y, dlp1024TestKey.y, dlp1024TestKey.yLen );
		status = cryptSetAttributeString( *cryptContext,
									CRYPT_CTXINFO_KEY_COMPONENTS, elgamalKey,
									sizeof( CRYPT_PKCINFO_DLP ) );
		cryptDestroyComponents( elgamalKey );
		if( cryptStatusError( status ) )
			{
			free( elgamalKey );
			cryptDestroyContext( *cryptContext );
			printf( "Public key load failed with error code %d, line %d.\n", 
					status, __LINE__ );
			return( FALSE );
			}
		if( decryptContext == NULL )
			{
			free( elgamalKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	status = cryptCreateContext( decryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_ELGAMAL );
	if( cryptStatusError( status ) )
		{
		free( elgamalKey );
		if( cryptContext != NULL )
			cryptDestroyContext( *cryptContext );
		fprintf( outputStream, "cryptCreateContext() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !setLabel( *decryptContext, ELGAMAL_PRIVKEY_LABEL ) )
		{
		free( elgamalKey );
		if( cryptContext != NULL )
			cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		return( FALSE );
		}
	cryptInitComponents( elgamalKey, CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( elgamalKey->p, dlp1024TestKey.p, dlp1024TestKey.pLen );
	cryptSetComponent( elgamalKey->g, dlp1024TestKey.g, dlp1024TestKey.gLen );
	cryptSetComponent( elgamalKey->q, dlp1024TestKey.q, dlp1024TestKey.qLen );
	cryptSetComponent( elgamalKey->y, dlp1024TestKey.y, dlp1024TestKey.yLen );
	cryptSetComponent( elgamalKey->x, dlp1024TestKey.x, dlp1024TestKey.xLen );
	status = cryptSetAttributeString( *decryptContext,
									  CRYPT_CTXINFO_KEY_COMPONENTS, elgamalKey,
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( elgamalKey );
	free( elgamalKey );
	if( cryptStatusError( status ) )
		{
		if( cryptContext != NULL )
			cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		printf( "Private key load failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load Diffie-Hellman encrytion contexts */

BOOLEAN loadDHContexts( const CRYPT_DEVICE cryptDevice,
						CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2 )
	{
	CRYPT_PKCINFO_DLP *dhKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	/* Allocate room for the public-key components */
	if( ( dhKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( FALSE );

	/* Create the first encryption context */
	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, cryptContext1,
										   CRYPT_ALGO_DH );
		}
	else
		{
		status = cryptCreateContext( cryptContext1, CRYPT_UNUSED, 
									 CRYPT_ALGO_DH );
		}
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		if( status == CRYPT_ERROR_NOTAVAIL )
			{
			/* DH support isn't always enabled, in which case we tell the 
			   caller to skip the test */
			return( status );
			}
		fprintf( outputStream, "cryptCreateContext() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !setLabel( *cryptContext1, DH_KEY1_LABEL ) )
		{
		free( dhKey );
		cryptDestroyContext( *cryptContext1 );
		return( FALSE );
		}
	cryptInitComponents( dhKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( dhKey->p, dlp1024TestKey.p, dlp1024TestKey.pLen );
	cryptSetComponent( dhKey->q, dlp1024TestKey.q, dlp1024TestKey.qLen );
	cryptSetComponent( dhKey->g, dlp1024TestKey.g, dlp1024TestKey.gLen );
	status = cryptSetAttributeString( *cryptContext1,
									  CRYPT_CTXINFO_KEY_COMPONENTS, dhKey,
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dhKey );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "DH #1 key load failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}
	if( cryptContext2 == NULL )
		{
		free( dhKey );
		return( TRUE );
		}

	/* Create the second encryption context */
	status = cryptCreateContext( cryptContext2, CRYPT_UNUSED, CRYPT_ALGO_DH );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		fprintf( outputStream, "cryptCreateContext() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !setLabel( *cryptContext2, DH_KEY2_LABEL ) )
		{
		free( dhKey );
		if( isDevice )
			{
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
							DH_KEY1_LABEL );
			}
		cryptDestroyContext( *cryptContext1 );
		cryptDestroyContext( *cryptContext2 );
		return( FALSE );
		}
	cryptInitComponents( dhKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( dhKey->p, dlp1024TestKey.p, dlp1024TestKey.pLen );
	cryptSetComponent( dhKey->q, dlp1024TestKey.q, dlp1024TestKey.qLen );
	cryptSetComponent( dhKey->g, dlp1024TestKey.g, dlp1024TestKey.gLen );
	status = cryptSetAttributeString( *cryptContext2,
									  CRYPT_CTXINFO_KEY_COMPONENTS, dhKey,
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dhKey );
	free( dhKey );
	if( cryptStatusError( status ) )
		{
		if( isDevice )
			{
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
							DH_KEY1_LABEL );
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
							DH_KEY2_LABEL );
			}
		printf( "DH #2 key load failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load ECDSA encrytion contexts */

BOOLEAN loadECDSAContextsEx( const CRYPT_DEVICE cryptDevice,
							 CRYPT_CONTEXT *sigCheckContext,
							 CRYPT_CONTEXT *signContext,
							 const C_STR sigCheckContextLabel,
							 const C_STR signContextLabel )
	{
	CRYPT_PKCINFO_ECC *eccKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	const ECC_KEY *eccKeyData = &eccP256TestKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( eccKey = ( CRYPT_PKCINFO_ECC * ) malloc( sizeof( CRYPT_PKCINFO_ECC ) ) ) == NULL )
		return( FALSE );

	/* Create the signature context */
	if( signContext != NULL )
		{
		if( isDevice )
			{
			status = cryptDeviceCreateContext( cryptDevice, signContext,
											   CRYPT_ALGO_ECDSA );
			}
		else
			{
			status = cryptCreateContext( signContext, CRYPT_UNUSED,
										 CRYPT_ALGO_ECDSA );
			}
		if( cryptStatusError( status ) )
			{
			free( eccKey );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				/* ECDSA support isn't always enabled, in which case we tell 
				   the caller to skip the test */
				return( status );
				}
			fprintf( outputStream, "cryptCreateContext() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		if( !setLabel( *signContext, signContextLabel ) )
			{
			free( eccKey );
			cryptDestroyContext( *signContext );
			return( FALSE );
			}
		cryptInitComponents( eccKey, CRYPT_KEYTYPE_PRIVATE );
		eccKey->curveType = CRYPT_ECCCURVE_P256;
		if( eccKeyData->pLen > 0 )
			{
			cryptSetComponent( eccKey->p, eccKeyData->p, eccKeyData->pLen );
			cryptSetComponent( eccKey->a, eccKeyData->a, eccKeyData->aLen );
			cryptSetComponent( eccKey->b, eccKeyData->b, eccKeyData->bLen );
			cryptSetComponent( eccKey->gx, eccKeyData->gx, eccKeyData->gxLen );
			cryptSetComponent( eccKey->gy, eccKeyData->gy, eccKeyData->gyLen );
			cryptSetComponent( eccKey->n, eccKeyData->n, eccKeyData->nLen );
			}
		cryptSetComponent( eccKey->qx, eccKeyData->qx, eccKeyData->qxLen );
		cryptSetComponent( eccKey->qy, eccKeyData->qy, eccKeyData->qyLen );
		cryptSetComponent( eccKey->d, eccKeyData->d, eccKeyData->dLen );
		status = cryptSetAttributeString( *signContext,
									CRYPT_CTXINFO_KEY_COMPONENTS, eccKey,
									sizeof( CRYPT_PKCINFO_ECC ) );
		cryptDestroyComponents( eccKey );
		if( cryptStatusError( status ) )
			{
			free( eccKey );
			cryptDestroyContext( *signContext );
			printf( "Private key load failed with error code %d, line %d.\n", 
					status, __LINE__ );
			return( FALSE );
			}
		if( sigCheckContext == NULL )
			{
			free( eccKey );
			return( TRUE );
			}
		}

	/* Create the sig.check context */
	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, sigCheckContext,
										   CRYPT_ALGO_ECDSA );
		}
	else
		{
		status = cryptCreateContext( sigCheckContext, CRYPT_UNUSED,
									 CRYPT_ALGO_ECDSA );
		}
	if( cryptStatusError( status ) )
		{
		free( eccKey );
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
				}
			}
		fprintf( outputStream, "cryptCreateContext() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !setLabel( *sigCheckContext, sigCheckContextLabel ) )
		{
		free( eccKey );
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
				}
			}
		cryptDestroyContext( *sigCheckContext );
		return( FALSE );
		}
	cryptInitComponents( eccKey, CRYPT_KEYTYPE_PUBLIC );
	eccKey->curveType = CRYPT_ECCCURVE_P256;
	if( eccKeyData->pLen > 0 )
		{
		cryptSetComponent( eccKey->p, eccKeyData->p, eccKeyData->pLen );
		cryptSetComponent( eccKey->a, eccKeyData->a, eccKeyData->aLen );
		cryptSetComponent( eccKey->b, eccKeyData->b, eccKeyData->bLen );
		cryptSetComponent( eccKey->gx, eccKeyData->gx, eccKeyData->gxLen );
		cryptSetComponent( eccKey->gy, eccKeyData->gy, eccKeyData->gyLen );
		cryptSetComponent( eccKey->n, eccKeyData->n, eccKeyData->nLen );
		}
	cryptSetComponent( eccKey->qx, eccKeyData->qx, eccKeyData->qxLen );
	cryptSetComponent( eccKey->qy, eccKeyData->qy, eccKeyData->qyLen );
	status = cryptSetAttributeString( *sigCheckContext,
									  CRYPT_CTXINFO_KEY_COMPONENTS, eccKey,
									  sizeof( CRYPT_PKCINFO_ECC ) );
	cryptDestroyComponents( eccKey );
	free( eccKey );
	if( cryptStatusError( status ) )
		{
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
				}
			}
		cryptDestroyContext( *sigCheckContext );
		printf( "Public key load failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadECDSAContexts( const CRYPT_DEVICE cryptDevice,
						   CRYPT_CONTEXT *sigCheckContext,
						   CRYPT_CONTEXT *signContext )
	{
	return( loadECDSAContextsEx( cryptDevice, sigCheckContext, signContext, 
								 ECDSA_PUBKEY_LABEL, ECDSA_PRIVKEY_LABEL ) );
	}

/* Load EDDSA encrytion contexts */

BOOLEAN loadEDDSAContexts( const CRYPT_DEVICE cryptDevice,
						   CRYPT_CONTEXT *sigCheckContext,
						   CRYPT_CONTEXT *signContext )
	{
	CRYPT_PKCINFO_ECC *eccKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	const ECC_KEY *eccKeyData = &eccP256TestKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( eccKey = ( CRYPT_PKCINFO_ECC * ) malloc( sizeof( CRYPT_PKCINFO_ECC ) ) ) == NULL )
		return( FALSE );

	/* Create the signature context */
	if( signContext != NULL )
		{
		if( isDevice )
			{
			status = cryptDeviceCreateContext( cryptDevice, signContext,
											   CRYPT_ALGO_EDDSA );
			}
		else
			{
			status = cryptCreateContext( signContext, CRYPT_UNUSED,
										 CRYPT_ALGO_EDDSA );
			}
		if( cryptStatusError( status ) )
			{
			free( eccKey );
			if( status == CRYPT_ERROR_NOTAVAIL )
				{
				/* ECDSA support isn't always enabled, in which case we tell 
				   the caller to skip the test */
				return( status );
				}
			fprintf( outputStream, "cryptCreateContext() failed with error "
					 "code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		if( !setLabel( *signContext, ECDSA_PRIVKEY_LABEL ) )
			{
			free( eccKey );
			cryptDestroyContext( *signContext );
			return( FALSE );
			}
		cryptInitComponents( eccKey, CRYPT_KEYTYPE_PRIVATE );
		eccKey->curveType = CRYPT_ECCCURVE_25519;
		if( eccKeyData->pLen > 0 )
			{
			cryptSetComponent( eccKey->p, eccKeyData->p, eccKeyData->pLen );
			cryptSetComponent( eccKey->a, eccKeyData->a, eccKeyData->aLen );
			cryptSetComponent( eccKey->b, eccKeyData->b, eccKeyData->bLen );
			cryptSetComponent( eccKey->gx, eccKeyData->gx, eccKeyData->gxLen );
			cryptSetComponent( eccKey->gy, eccKeyData->gy, eccKeyData->gyLen );
			cryptSetComponent( eccKey->n, eccKeyData->n, eccKeyData->nLen );
			}
		cryptSetComponent( eccKey->qx, eccKeyData->qx, eccKeyData->qxLen );
		cryptSetComponent( eccKey->qy, eccKeyData->qy, eccKeyData->qyLen );
		cryptSetComponent( eccKey->d, eccKeyData->d, eccKeyData->dLen );
		status = cryptSetAttributeString( *signContext,
									CRYPT_CTXINFO_KEY_COMPONENTS, eccKey,
									sizeof( CRYPT_PKCINFO_ECC ) );
		cryptDestroyComponents( eccKey );
		if( cryptStatusError( status ) )
			{
			free( eccKey );
			cryptDestroyContext( *signContext );
			printf( "Private key load failed with error code %d, line %d.\n", 
					status, __LINE__ );
			return( FALSE );
			}
		if( sigCheckContext == NULL )
			{
			free( eccKey );
			return( TRUE );
			}
		}

	/* Create the sig.check context */
	if( isDevice )
		{
		status = cryptDeviceCreateContext( cryptDevice, sigCheckContext,
										   CRYPT_ALGO_EDDSA );
		}
	else
		{
		status = cryptCreateContext( sigCheckContext, CRYPT_UNUSED,
									 CRYPT_ALGO_EDDSA );
		}
	if( cryptStatusError( status ) )
		{
		free( eccKey );
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								ECDSA_PRIVKEY_LABEL );
				}
			}
		fprintf( outputStream, "cryptCreateContext() failed with error "
				 "code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !setLabel( *sigCheckContext, ECDSA_PUBKEY_LABEL ) )
		{
		free( eccKey );
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								ECDSA_PRIVKEY_LABEL );
				}
			}
		cryptDestroyContext( *sigCheckContext );
		return( FALSE );
		}
	cryptInitComponents( eccKey, CRYPT_KEYTYPE_PUBLIC );
	eccKey->curveType = CRYPT_ECCCURVE_25519;
	if( eccKeyData->pLen > 0 )
		{
		cryptSetComponent( eccKey->p, eccKeyData->p, eccKeyData->pLen );
		cryptSetComponent( eccKey->a, eccKeyData->a, eccKeyData->aLen );
		cryptSetComponent( eccKey->b, eccKeyData->b, eccKeyData->bLen );
		cryptSetComponent( eccKey->gx, eccKeyData->gx, eccKeyData->gxLen );
		cryptSetComponent( eccKey->gy, eccKeyData->gy, eccKeyData->gyLen );
		cryptSetComponent( eccKey->n, eccKeyData->n, eccKeyData->nLen );
		}
	cryptSetComponent( eccKey->qx, eccKeyData->qx, eccKeyData->qxLen );
	cryptSetComponent( eccKey->qy, eccKeyData->qy, eccKeyData->qyLen );
	status = cryptSetAttributeString( *sigCheckContext,
									  CRYPT_CTXINFO_KEY_COMPONENTS, eccKey,
									  sizeof( CRYPT_PKCINFO_ECC ) );
	cryptDestroyComponents( eccKey );
	free( eccKey );
	if( cryptStatusError( status ) )
		{
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				{
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								ECDSA_PRIVKEY_LABEL );
				}
			}
		cryptDestroyContext( *sigCheckContext );
		printf( "Public key load failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Destroy the encryption contexts */

void destroyContexts( const CRYPT_DEVICE cryptDevice,
					  const CRYPT_CONTEXT cryptContext,
					  const CRYPT_CONTEXT decryptContext )
	{
	int cryptAlgo, status;

	status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, 
								&cryptAlgo );
	if( cryptStatusError( status ) )
		cryptAlgo = CRYPT_ALGO_RSA;
	status = cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyContext() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		}
	status = cryptDestroyContext( decryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyContext() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		}
	if( cryptDevice == CRYPT_UNUSED )
		return;

	/* If the context is associated with a device then creating the object
	   will generally also create a persistent object in the device, after
	   performing the tests we have to explicitly delete the persistent
	   object */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, RSA_PUBKEY_LABEL );
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL );
			break;

		case CRYPT_ALGO_DSA:
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, DSA_PUBKEY_LABEL );
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, DSA_PRIVKEY_LABEL );
			break;

		case CRYPT_ALGO_ECDSA:
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, ECDSA_PUBKEY_LABEL );
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, ECDSA_PRIVKEY_LABEL );
			break;

		default:
			/* No special-case handling */
			break;
		}
	}
