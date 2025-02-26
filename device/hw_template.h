/****************************************************************************
*																			*
*					cryptlib Crypto HAL Template Header File				*
*					  Copyright Peter Gutmann 1998-2019						*
*																			*
****************************************************************************/

#ifndef _HWTEMPLATE_DEFINED

#define _HWTEMPLATE_DEFINED

/****************************************************************************
*																			*
*								Personality Storage							*
*																			*
****************************************************************************/

/* Each key, along with its associated identifiers, certificates, and other
   metadata, constitutes a personality.  cryptlib manages most of this 
   information externally.  The only data that's stored here is the keying
   information in whatever format the cryptographic hardware uses and a 
   short binary unique-ID value, the storageID, that cryptlib uses to look 
   up a personality.  
   
   Private key data will generally be stored in a hardware-specific internal
   format.  For demonstration purposes we assume that this consists of 
   32-bit big-endian words, chosen because the most widely-deployed 
   architectures are little-endian, so this guarantees that if there's a
   problem it'll be caught by the different endianness.  We need to convert 
   this to and from the generic CRYPT_PKCINFO_RSA/CRYPT_PKCINFO_DLP/
   CRYPT_PKCINFO_ECC format on import and export.  The following structure 
   is used to store data in the dummy hardware-internal format.  The layout 
   of the data is as follows:

	Index	RSA value	DLP value	ECC value
	-----	---------	---------	---------
	  0			n			p			qx
	  1			e			q			qy
	  2			d			q			d
	  3			p			y		(Parameters stored as curveType)
	  4			q			x
	  5			u
	  6			e1
	  7			e2 */	

typedef struct {
	unsigned long data[ CRYPT_MAX_PKCSIZE / sizeof( unsigned long ) ];
	int dataSize;
	} BIGNUM_STORAGE;

#define NO_BIGNUMS			8

/* Each personality contains (at least) the storageID used to reference it
   and whatever keying information is needed by the underlying cryptographic
   hardware.  The following structure contains the information stored for 
   each personality.  The inUse flag is a convenience feature, it can also 
   be indicated through a convention such as an all-zero storageID */

typedef struct {
	/* General management information */
	BOOLEAN inUse;				/* Whether this personality is in use */
	BYTE storageID[ KEYID_SIZE ];/* ID used to look up this personality */

	/* Key data storage */
	union {
		BYTE convKeyInfo[ CRYPT_MAX_KEYSIZE ];
		BIGNUM_STORAGE pkcKeyInfo[ NO_BIGNUMS ];
		} keyInfo;
	} PERSONALITY_INFO;

/* Storage for the personalities.  This would typically be held either in 
   internal protected memory (for example battery-backed device-internal 
   SRAM) or encrypted external memory that's transparently accessed as 
   standard memory.  The memory doesn't explicitly have to be zeroed since
   cryptlib does this on device initialisation, it's done here merely as
   a convenience during debugging */

#define NO_PERSONALITIES	8

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Prototypes for functions in hw_template.c */

int findFreePersonality( int *keyHandle );
void *getPersonality( const int keyHandle );
void deletePersonality( const int keyHandle );

#endif /* _HWTEMPLATE_DEFINED */
