/****************************************************************************
*																			*
*						Telit Randomness-Gathering Code						*
*						 Copyright Peter Gutmann 1996-2020					*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see random.c */

/* General includes */

#include "crypt.h"
#include "random/random.h"

/* OS-specific includes */

#include "m2m_type.h"
#include "m2m_clock_api.h"
#include "m2m_hw_api.h"
#include "m2m_network_api.h"
#include "m2m_os_api.h"

/* The size of the intermediate buffer used to accumulate polled data */

#define RANDOM_BUFSIZE	256

void fastPoll( void )
	{
	RANDOM_STATE randomState;
	BYTE buffer[ RANDOM_BUFSIZE ];
	struct M2M_T_RTC_TIMEVAL timeVal;
	UINT32 value1, value2;

	initRandomData( randomState, buffer, RANDOM_BUFSIZE );

	/* Get the current time in milliseconds, some hardware counter in 
	   milliseconds, the current task ID, and the number of available memory
	   bytes and number of memory pool fragments.  Note the non-orthogonal 
	   result reporting, the following return-value checks are as per the 
	   docs even though they look wrong */
	if( m2m_get_timeofday( &timeVal, NULL ) == 0 )
		{
		addRandomData( randomState, &timeVal, 
					   sizeof( struct M2M_T_RTC_TIMEVAL ) );
		}
	if( m2m_hw_get_ms_count( &value1 ) == M2M_API_RESULT_SUCCESS )
		addRandomValue( randomState, value1 );
	value1 = m2m_os_get_current_task_id();
	addRandomValue( randomState, value1 );
	value1 = m2m_os_get_mem_info( &value2 );
	addRandomValue( randomState, value1 );
	addRandomValue( randomState, value2 );

	endRandomData( randomState, 5 );
	}

void slowPoll( void )
	{
	RANDOM_STATE randomState;
	BYTE buffer[ RANDOM_BUFSIZE ];
	M2M_T_NETWORK_REG_STATUS_INFO regStatus;
	M2M_T_NETWORK_CELL_INFORMATION cellInfo;
	M2M_T_NETWORK_CURRENT_NETWORK operatorInfo;
	M2M_T_NETWORK_GREG_STATUS_INFO gprsInfo;
	M2M_PDP_DATAVOLINFO dataVol;
	USB_UART_STATE usbState;
	UINT32 value1, value2;
	static BOOLEAN addedStaticData = FALSE;
	int itemsAdded = 0;

	initRandomData( randomState, buffer, RANDOM_BUFSIZE );

	/* Get static system information.  These functions fill a user-supplied 
	   buffer with a null-terminated string with no indication of how large
	   the buffer should be, the docs say "for example 20 bytes length" so we
	   use 64 bytes to provide some safety margin and hope no-one decides to
	   make it longer.  There's also a define M2M_OS_MAX_SW_VERSION_STR_LENGTH 
	   used for another null-terminated-string function which is set to 40 so
	   if this is anything to go by then 64 should hopefully be enough */
	if( !addedStaticData )
		{
		BYTE textStringBuffer[ CRYPT_MAX_TEXTSIZE ];
		BYTE *textStringPtr;

		m2m_info_get_model( textStringBuffer );
		addRandomData( randomState, textStringBuffer, 
					   strlen( textStringBuffer ) );
		m2m_info_get_manufacturer( textStringBuffer );
		addRandomData( randomState, textStringBuffer, 
					   strlen( textStringBuffer ) );
		m2m_info_get_factory_SN( textStringBuffer );
		addRandomData( randomState, textStringBuffer, 
					   strlen( textStringBuffer ) );
		m2m_info_get_serial_num( textStringBuffer );
		addRandomData( randomState, textStringBuffer, 
					   strlen( textStringBuffer ) );
		m2m_info_get_sw_version( textStringBuffer );
		addRandomData( randomState, textStringBuffer, 
					   strlen( textStringBuffer ) );
		m2m_info_get_fw_version( textStringBuffer );
		addRandomData( randomState, textStringBuffer, 
					   strlen( textStringBuffer ) );
		m2m_info_get_MSISDN( textStringBuffer );
		addRandomData( randomState, textStringBuffer, 
					   strlen( textStringBuffer ) );
		m2m_info_get_IMSI( textStringBuffer );
		addRandomData( randomState, textStringBuffer, 
					   strlen( textStringBuffer ) );
		textStringPtr = m2m_os_get_version();
		addRandomData( randomState, textStringPtr, 
					   strlen( textStringPtr ) );
		itemsAdded = 5;

		addedStaticData = TRUE;
		}

	/* Get cellular information: The network registration status (LAC, cell 
	   ID, etc), the network cell neighbour list, the network operator info, 
	   the RSSI and BER, the GPRS info (which seems to be the same as the 
	   network registration status).  Note yet another way of reporting the
	   result status */
	if( m2m_network_get_reg_status( &regStatus ) == 1 )
		{
		addRandomData( randomState, &regStatus, 
					   sizeof( M2M_T_NETWORK_REG_STATUS_INFO ) );
		itemsAdded++;
		}
	if( m2m_network_get_cell_information( &cellInfo ) == 1 )
		{
		addRandomData( randomState, &cellInfo, 
					   sizeof( M2M_T_NETWORK_CELL_INFORMATION ) );
		itemsAdded++;
		}
	if( m2m_network_get_currently_selected_operator( &operatorInfo ) == 1 )
		{
		addRandomData( randomState, &operatorInfo, 
					   sizeof( M2M_T_NETWORK_CURRENT_NETWORK ) );
		itemsAdded++;
		}
	if( m2m_network_get_signal_strength( &value1, &value2 ) == 1 )
		{
		addRandomValue( randomState, value1 );
		addRandomValue( randomState, value2 );
		itemsAdded++;
		}
	if( m2m_network_get_gprs_reg_status( &gprsInfo ) == 1 )
		{
		addRandomData( randomState, &gprsInfo, 
					   sizeof( M2M_T_NETWORK_GREG_STATUS_INFO ) );
		itemsAdded++;
		}

	/* Get state information on possible USB channels.  This function has no
	   return value so we have no idea whether the call succeeded or not, to 
	   deal with this we clear the state variable before use */
	memset( &usbState, 0, sizeof( USB_UART_STATE ) );
	m2m_hw_usb_get_state( USB_CH0, &usbState );
	addRandomData( randomState, &usbState, sizeof( USB_UART_STATE ) );
	m2m_hw_usb_get_state( USB_CH1, &usbState );
	addRandomData( randomState, &usbState, sizeof( USB_UART_STATE ) );
	m2m_hw_usb_get_state( USB_CH_AUTO, &usbState );
	addRandomData( randomState, &usbState, sizeof( USB_UART_STATE ) );
	m2m_hw_usb_get_state( USB_CH_DEFAULT, &usbState );
	addRandomData( randomState, &usbState, sizeof( USB_UART_STATE ) );
	itemsAdded++;

	/* Get miscellaneous information, the device's current IPv4 address, and
	   data sent and received in unspecified units.  Note the usual random
	   asignment of return status values */
	value1 = m2m_pdp_get_my_ip();
	if( value1 != 0 )
		{
		addRandomValue( randomState, value2 );
		itemsAdded++;
		}
	if( m2m_pdp_get_datavol( 1, &dataVol ) == 0 )
		{
		addRandomData( randomState, &dataVol, 
					   sizeof( M2M_PDP_DATAVOLINFO ) );
		itemsAdded++;
		}
	if( m2m_pdp_get_datavol( 2, &dataVol ) == 0 )
		{
		addRandomData( randomState, &dataVol, 
					   sizeof( M2M_PDP_DATAVOLINFO ) );
		itemsAdded++;
		}

	/* Flush any remaining data through and produce an estimate of its
	   value.  Unlike its use in standard OSes this isn't really a true 
	   estimate since virtually all of the entropy is coming from the seed
	   file, all this does is complete the seed-file quality estimate to
	   make sure that we don't fail the entropy test */
	endRandomData( randomState, itemsAdded * 5 );	
	}
