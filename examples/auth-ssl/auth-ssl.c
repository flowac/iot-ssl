/**
 * \file
 *	IoT OpenSSL Auth Demo
 * \author
 *	Alan <alan@ld50.bid>
 */

#include "auth-utils.c"

/*---------------------------------------------------------------------------*/
PROCESS(test_serial_process, "Serial test process");
PROCESS(button_hal_example, "Button HAL Example");
PROCESS(nullnet_example_process, "NullNet unicast example");
AUTOSTART_PROCESSES(&button_hal_example, &nullnet_example_process, &test_serial_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(button_hal_example, ev, data)
{
	button_hal_button_t *btn;
	PROCESS_BEGIN();
	printf("Button initialized.\n");

	while (1)
	{
		PROCESS_YIELD();
		if (ev == button_hal_release_event)
		{
			btn = (button_hal_button_t *)data;
			printf("Button %u released (%s)\n", btn->unique_id, BUTTON_HAL_GET_DESCRIPTION(btn));
			broadcast_pub_key();
		}
	}
	PROCESS_END();
}

PROCESS_THREAD(test_serial_process, ev, data)
{
	static struct etimer et;

	PROCESS_BEGIN();

	etimer_set(&et, CLOCK_SECOND*100);

	while (1)
	{
		PROCESS_WAIT_EVENT();

		if (etimer_expired(&et))
		{
			printf("Waiting for serial data\n");
			etimer_restart(&et);
		}

		if (ev == serial_line_event_message)
		{
			printf("Message received: '%s'\n", (char*)data);
		}
	}

	PROCESS_END();
}

PROCESS_THREAD(nullnet_example_process, ev, data)
{
	static struct etimer periodic_timer;

	PROCESS_BEGIN();
	/* Initialize NullNet */

	// TODO: make the buffer bigger and introduce op codes
	// connect, post, get, delete, etc

	nullnet_buf = OUT_DATA;
	nullnet_len = DATA_LEN;
	nullnet_set_input_callback(input_callback);

	if (!newKeyPair(PUB_KEY, PRIV_KEY))
	{
		LOG_ERR("X25519 key gen error\n");
		goto cleanup;
	}

	etimer_set(&periodic_timer, SEND_INTERVAL);
	LOG_DBG("SSL Version %d --- ", OPENSSL_VERSION_MAJOR);
	LOG_DBG_LLADDR(&linkaddr_node_addr);
	LOG_DBG_("\n");
	broadcast_pub_key();

	while(1)
	{
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
		etimer_reset(&periodic_timer);
	}
cleanup: PROCESS_END();
}
