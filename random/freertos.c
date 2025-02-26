/****************************************************************************
*																			*
*						FreeRTOS Randomness-Gathering Code					*
*						 Copyright Peter Gutmann 1996-2017					*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see random.c.

   This code represents a template for randomness-gathering only and will
   need to be modified to provide randomness via an FPGA hardware entropy
   source such as a standard ring oscillator generator.  In its current
   form it does not provide any usable entropy and should not be used as an
   entropy source */

/* General includes */

#include <FreeRTOS.h>
#include <task.h>
#include "crypt.h"
#include "random/random.h"

/* The size of the intermediate buffer used to accumulate polled data */

#define RANDOM_BUFSIZE	256

/* OS-specific includes */

void fastPoll( void )
	{
	RANDOM_STATE randomState;
	BYTE buffer[ RANDOM_BUFSIZE ];

	initRandomData( randomState, buffer, RANDOM_BUFSIZE );
	addRandomLong( randomState, xTaskGetTickCount() );
	endRandomData( randomState, 1 );
	}

void slowPoll( void )
	{
	RANDOM_STATE randomState;
	BYTE buffer[ RANDOM_BUFSIZE ];
	static BOOLEAN addedStaticData = FALSE;
	int quality = 0;

	initRandomData( randomState, buffer, RANDOM_BUFSIZE );

	/* Get static system information */
	if( !addedStaticData )
		{
		addRandomLong( randomState, uxTaskGetNumberOfTasks() );
#ifdef INCLUDE_xTaskGetCurrentTaskHandle
		addRandomLong( randomState, ( long ) xTaskGetCurrentTaskHandle() );
#endif /* INCLUDE_xTaskGetCurrentTaskHandle */
#ifdef INCLUDE_xTaskGetIdleTaskHandle
		addRandomLong( randomState, ( long ) xTaskGetIdleTaskHandle() );
#endif /* INCLUDE_xTaskGetIdleTaskHandle */
#ifdef INCLUDE_xTaskGetSchedulerState
		addRandomLong( randomState, xTaskGetSchedulerState() );
#endif /* INCLUDE_xTaskGetSchedulerState */
#ifdef INCLUDE_uxTaskGetStackHighWaterMark
		addRandomLong( randomState, uxTaskGetStackHighWaterMark( NULL ) );
#endif /* INCLUDE_uxTaskGetStackHighWaterMark */
		quality = 1;

		addedStaticData = TRUE;
		}
	endRandomData( randomState, quality );
	}
