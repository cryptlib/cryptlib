/****************************************************************************
*																			*
*					Object-specific Function Header File					*
*					  Copyright Peter Gutmann 1992-2019						*
*																			*
****************************************************************************/

#ifndef _OBJECTFNS_DEFINED

#define _OBJECTFNS_DEFINED

/* This file defines object-specific functions that are called directly 
   from the kernel or from init code.  These represent the external access 
   point for object-specific functionality like init, create-object, and 
   shutdown */

/* Object management (init/shutdown/etc) interface */

CHECK_RETVAL \
int certManagementFunction( IN_ENUM( MANAGEMENT_ACTION ) \
								const MANAGEMENT_ACTION_TYPE action );
CHECK_RETVAL \
int deviceManagementFunction( IN_ENUM( MANAGEMENT_ACTION ) \
								const MANAGEMENT_ACTION_TYPE action );
CHECK_RETVAL \
int keysetManagementFunction( IN_ENUM( MANAGEMENT_ACTION ) \
								const MANAGEMENT_ACTION_TYPE action );
CHECK_RETVAL \
int sessionManagementFunction( IN_ENUM( MANAGEMENT_ACTION ) \
								const MANAGEMENT_ACTION_TYPE action );
CHECK_RETVAL \
int userManagementFunction( IN_ENUM( MANAGEMENT_ACTION ) \
								const MANAGEMENT_ACTION_TYPE action );

/* Create-object interface */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createCertificate( INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo, 
					   STDC_UNUSED const void *auxDataPtr, 
					   STDC_UNUSED const int auxValue );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createEnvelope( INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo, 
					STDC_UNUSED const void *auxDataPtr, 
					STDC_UNUSED const int auxValue );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createSession( INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
				   STDC_UNUSED const void *auxDataPtr, 
				   STDC_UNUSED const int auxValue );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createKeyset( INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
				  STDC_UNUSED const void *auxDataPtr, 
				  STDC_UNUSED const int auxValue );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createDevice( INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
				  STDC_UNUSED const void *auxDataPtr, 
				  STDC_UNUSED const int auxValue );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createUser( INOUT_PTR MESSAGE_CREATEOBJECT_INFO *createInfo,
				STDC_UNUSED const void *auxDataPtr, 
				STDC_UNUSED const int auxValue );
#endif /* _OBJECTFNS_DEFINED */
