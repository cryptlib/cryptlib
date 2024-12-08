<<<<<<< HEAD
/****************************************************************************
*																			*
*						TLS Extension Definitions Header File				*
*						Copyright Peter Gutmann 1998-2022					*
*																			*
****************************************************************************/

#ifndef _TLS_EXT_DEFINED

#define _TLS_EXT_DEFINED

#ifdef USE_TLS

/****************************************************************************
*																			*
*								TLS Functions								*
*																			*
****************************************************************************/

/* Prototypes for functions in tls_ext_rw.c */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 3, 4, 5 ) ) \
int getExtensionInfo( IN_RANGE( 0, 65536 ) const int type,
					  IN_BOOL const BOOLEAN isServer,
					  OUT_LENGTH_SHORT_Z int *minLength,
					  OUT_LENGTH_SHORT_Z int *maxLength,
					  OUT_PTR_PTR_OPT const char **description );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readSNI( INOUT_PTR STREAM *stream, 
			 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
			 IN_LENGTH_SHORT_Z const int extLength,
			 IN_BOOL const BOOLEAN isServer );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSNI( INOUT_PTR STREAM *stream,
			  const SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readSupportedVersions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   IN_LENGTH_SHORT_Z const int extLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSupportedVersions( INOUT_PTR STREAM *stream,
							const SESSION_INFO *sessionInfoPtr,
							IN_RANGE( TLS_MINOR_VERSION_TLS, \
									  TLS_MINOR_VERSION_TLS13 ) \
								const int minVersion );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int readSupportedGroups( INOUT_PTR STREAM *stream, 
						 INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 IN_LENGTH_SHORT_Z const int extLength,
						 OUT_ENUM_OPT( CRYPT_ECCCURVE ) \
							CRYPT_ECCCURVE_TYPE *preferredCurveIdPtr,
						 OUT_BOOL BOOLEAN *extErrorInfoSet );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSupportedGroups( INOUT_PTR STREAM *stream,
						  const SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readSignatureAlgos( INOUT_PTR STREAM *stream, 
						INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						IN_LENGTH_SHORT_Z const int extLength,
						OUT_BOOL BOOLEAN *extErrorInfoSet );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeSignatureAlgos( STREAM *stream );

#endif /* USE_TLS */

#endif /* _TLS_EXT_DEFINED */
=======
/****************************************************************************
*																			*
*						TLS Extension Definitions Header File				*
*						Copyright Peter Gutmann 1998-2022					*
*																			*
****************************************************************************/

#ifndef _TLS_EXT_DEFINED

#define _TLS_EXT_DEFINED

#ifdef USE_TLS

/****************************************************************************
*																			*
*								TLS Functions								*
*																			*
****************************************************************************/

/* Prototypes for functions in tls_ext_rw.c */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 3, 4, 5 ) ) \
int getExtensionInfo( IN_RANGE( 0, 65536 ) const int type,
					  IN_BOOL const BOOLEAN isServer,
					  OUT_LENGTH_SHORT_Z int *minLength,
					  OUT_LENGTH_SHORT_Z int *maxLength,
					  OUT_PTR_PTR_OPT const char **description );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readSNI( INOUT_PTR STREAM *stream, 
			 INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
			 IN_LENGTH_SHORT_Z const int extLength,
			 IN_BOOL const BOOLEAN isServer );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSNI( INOUT_PTR STREAM *stream,
			  const SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readSupportedVersions( INOUT_PTR STREAM *stream,
						   INOUT_PTR SESSION_INFO *sessionInfoPtr,
						   IN_LENGTH_SHORT_Z const int extLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSupportedVersions( INOUT_PTR STREAM *stream,
							const SESSION_INFO *sessionInfoPtr,
							IN_RANGE( TLS_MINOR_VERSION_TLS, \
									  TLS_MINOR_VERSION_TLS13 ) \
								const int minVersion );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int readSupportedGroups( INOUT_PTR STREAM *stream, 
						 INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						 IN_LENGTH_SHORT_Z const int extLength,
						 OUT_ENUM_OPT( CRYPT_ECCCURVE ) \
							CRYPT_ECCCURVE_TYPE *preferredCurveIdPtr,
						 OUT_BOOL BOOLEAN *extErrorInfoSet );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSupportedGroups( INOUT_PTR STREAM *stream,
						  const SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readSignatureAlgos( INOUT_PTR STREAM *stream, 
						INOUT_PTR SESSION_INFO *sessionInfoPtr, 
						INOUT_PTR TLS_HANDSHAKE_INFO *handshakeInfo,
						IN_LENGTH_SHORT_Z const int extLength,
						OUT_BOOL BOOLEAN *extErrorInfoSet );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeSignatureAlgos( STREAM *stream );

#endif /* USE_TLS */

#endif /* _TLS_EXT_DEFINED */
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
