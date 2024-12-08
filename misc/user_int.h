<<<<<<< HEAD
/****************************************************************************
*																			*
*						  Interal User Header File							*
*					Copyright Peter Gutmann 1999-2018						*
*																			*
****************************************************************************/

#ifndef _USER_INT_DEFINED

#define _USER_INT_DEFINED

/* Configuration option types */

typedef enum {
	OPTION_NONE,					/* Non-option */
	OPTION_STRING,					/* Literal string */
	OPTION_NUMERIC,					/* Numeric value */
	OPTION_BOOLEAN					/* Boolean flag */
	} OPTION_TYPE;

/* The configuration options.  Alongside the CRYPT_ATTRIBUTE_TYPE we store a 
   persistent index value for the option that always stays the same even if 
   the attribute type changes.  This avoids the need to change the config 
   file every time that an attribute is added or deleted.  Some options 
   can't be made persistent, for these the index value is set to 
   CRYPT_UNUSED */

typedef struct BOI {
	const CRYPT_ATTRIBUTE_TYPE option;/* Attribute ID */
	const OPTION_TYPE type;			/* Option type */
	const int index;				/* Index value for this option */
	BUFFER_OPT_FIXED( intDefault ) \
	const char *strDefault;			/* Default if it's a string option */
	const int intDefault;			/* Default if it's a numeric/boolean
									   or length if it's a string */
	const void *extendedInfo;		/* Extended option information */
	const int extendedInfoSize;
	} BUILTIN_OPTION_INFO;

typedef struct OI {
	BUFFER_OPT_FIXED( intValue ) \
	char *strValue;					/* Value if it's a string option */
	int intValue;					/* Value if it's a numeric/boolean
									   or length if it's a string */
	const BUILTIN_OPTION_INFO *builtinOptionInfo;
									/* Pointer to corresponding built-in 
									   option info */
	BOOLEAN dirty;					/* Whether option has been changed */
	} OPTION_INFO;

/* The size of the variable-length configuration data, used when we allocate
   storage for it and initialise it from the builtinOptionInfo template */

#define OPTION_INFO_SIZE	( sizeof( OPTION_INFO ) * \
							  CRYPT_OPTION_CONFIGCHANGED - CRYPT_OPTION_FIRST )

/* Sometimes when we change an option this can affect other related options,
   for example changing CRYPT_OPTION_ENCR_HASH can affect 
   CRYPT_OPTION_ENCR_HASHPARAM.  To deal with this, the option information 
   can included extended information indicating which other option is changed
   when the current option is changed.  This is stored as an array of 
   { currentOptionValue, destinationOptionType, destinationOptionvalue } 
   settings */

typedef struct OEI {
	const int currentOptionValue;
	const CRYPT_ATTRIBUTE_TYPE destinationOptionType;
	const int destinationOptionValue;
	} OPTION_EXCEPTION_INFO;
		
/* The attribute ID of the last option that's written to disk, and an upper 
   bound on the corresponding persistent index value used for range checking.  
   Further options beyond this one are ephemeral and are never written to 
   disk */

#define LAST_STORED_OPTION			CRYPT_OPTION_MISC_SIDECHANNELPROTECTION
#define LAST_OPTION_INDEX			1000

/* Prototypes for functions in user_cfg.c */

CHECK_RETVAL_PTR \
const BUILTIN_OPTION_INFO *getBuiltinOptionInfoByCode( IN_RANGE( 0, LAST_OPTION_INDEX ) \
														const int optionCode );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkConfigChanged( IN_ARRAY( configOptionsCount ) \
								const OPTION_INFO *optionList,
							IN_INT_SHORT const int configOptionsCount );

#endif /* _USER_INT_DEFINED */
=======
/****************************************************************************
*																			*
*						  Interal User Header File							*
*					Copyright Peter Gutmann 1999-2018						*
*																			*
****************************************************************************/

#ifndef _USER_INT_DEFINED

#define _USER_INT_DEFINED

/* Configuration option types */

typedef enum {
	OPTION_NONE,					/* Non-option */
	OPTION_STRING,					/* Literal string */
	OPTION_NUMERIC,					/* Numeric value */
	OPTION_BOOLEAN					/* Boolean flag */
	} OPTION_TYPE;

/* The configuration options.  Alongside the CRYPT_ATTRIBUTE_TYPE we store a 
   persistent index value for the option that always stays the same even if 
   the attribute type changes.  This avoids the need to change the config 
   file every time that an attribute is added or deleted.  Some options 
   can't be made persistent, for these the index value is set to 
   CRYPT_UNUSED */

typedef struct BOI {
	const CRYPT_ATTRIBUTE_TYPE option;/* Attribute ID */
	const OPTION_TYPE type;			/* Option type */
	const int index;				/* Index value for this option */
	BUFFER_OPT_FIXED( intDefault ) \
	const char *strDefault;			/* Default if it's a string option */
	const int intDefault;			/* Default if it's a numeric/boolean
									   or length if it's a string */
	const void *extendedInfo;		/* Extended option information */
	const int extendedInfoSize;
	} BUILTIN_OPTION_INFO;

typedef struct OI {
	BUFFER_OPT_FIXED( intValue ) \
	char *strValue;					/* Value if it's a string option */
	int intValue;					/* Value if it's a numeric/boolean
									   or length if it's a string */
	const BUILTIN_OPTION_INFO *builtinOptionInfo;
									/* Pointer to corresponding built-in 
									   option info */
	BOOLEAN dirty;					/* Whether option has been changed */
	} OPTION_INFO;

/* The size of the variable-length configuration data, used when we allocate
   storage for it and initialise it from the builtinOptionInfo template */

#define OPTION_INFO_SIZE	( sizeof( OPTION_INFO ) * \
							  CRYPT_OPTION_CONFIGCHANGED - CRYPT_OPTION_FIRST )

/* Sometimes when we change an option this can affect other related options,
   for example changing CRYPT_OPTION_ENCR_HASH can affect 
   CRYPT_OPTION_ENCR_HASHPARAM.  To deal with this, the option information 
   can included extended information indicating which other option is changed
   when the current option is changed.  This is stored as an array of 
   { currentOptionValue, destinationOptionType, destinationOptionvalue } 
   settings */

typedef struct OEI {
	const int currentOptionValue;
	const CRYPT_ATTRIBUTE_TYPE destinationOptionType;
	const int destinationOptionValue;
	} OPTION_EXCEPTION_INFO;
		
/* The attribute ID of the last option that's written to disk, and an upper 
   bound on the corresponding persistent index value used for range checking.  
   Further options beyond this one are ephemeral and are never written to 
   disk */

#define LAST_STORED_OPTION			CRYPT_OPTION_MISC_SIDECHANNELPROTECTION
#define LAST_OPTION_INDEX			1000

/* Prototypes for functions in user_cfg.c */

CHECK_RETVAL_PTR \
const BUILTIN_OPTION_INFO *getBuiltinOptionInfoByCode( IN_RANGE( 0, LAST_OPTION_INDEX ) \
														const int optionCode );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkConfigChanged( IN_ARRAY( configOptionsCount ) \
								const OPTION_INFO *optionList,
							IN_INT_SHORT const int configOptionsCount );

#endif /* _USER_INT_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
