/****************************************************************************
*																			*
*						  Zephyr Randomness-Gathering Code					*
*						 Copyright Peter Gutmann 1996-2017					*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see random.c.

   This code represents a template for randomness-gathering only and will
   need to be modified to provide randomness via an external source.  In its
   current form it does not provide any usable entropy and should not be
   used as an entropy source */

/* General includes */

#include <zephyr.h>
#include "crypt.h"
#include "random/random.h"

/* The size of the intermediate buffer used to accumulate polled data */

#define RANDOM_BUFSIZE	256

void fastPoll( void )
	{
	RANDOM_STATE randomState;
	BYTE buffer[ RANDOM_BUFSIZE ], csrandBuffer[ 64 + 8 ];
	k_tid_t threadID;
	int quality = 1;

	/* Add the current thread's ID and priority, the system uptime in 
	   milliseconds, and the CSPRNG if there's one enabled */
	threadID = k_current_get();
	initRandomData( randomState, buffer, RANDOM_BUFSIZE );
	addRandomValue( randomState, threadID );
	addRandomValue( randomState, k_thread_priority_get( threadID ) );
	addRandomValue( randomState, k_uptime_get_32() );
	if( sys_csrand_get( csrandBuffer, 64 ) == 0 )
		{
		addRandomData( randomState, csrandBuffer, 64 );
		quality += 80;
		}
	endRandomData( randomState, quality );
	}

void slowPoll( void )
	{
	RANDOM_STATE randomState;
	BYTE buffer[ RANDOM_BUFSIZE ];
	static BOOLEAN addedStaticData = FALSE;
	int quality = 0;

	initRandomData( randomState, buffer, RANDOM_BUFSIZE );

	if( !addedStaticData )
		{
		addRandomValue( randomState, sys_kernel_version_get() );
		quality = 1;

		addedStaticData = TRUE;
		}

	endRandomData( randomState, quality );
	}
