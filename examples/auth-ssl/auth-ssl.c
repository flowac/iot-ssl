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
	LOG_DBG("Button initialized.\n");

	while (1)
	{
		PROCESS_YIELD();
		if (ev == button_hal_release_event)
		{
			btn = (button_hal_button_t *)data;
			LOG_DBG("Button %u released (%s)\n", btn->unique_id, BUTTON_HAL_GET_DESCRIPTION(btn));

			memset(OUT_DATA, 0, DATA_LEN);
			OUT_DATA[0] = SEND_PUB_KEY;
			OUT_DATA[1] = LINKADDR_SIZE + X25519_LEN;
			memcpy(OUT_DATA + 2, linkaddr_node_addr.u8, LINKADDR_SIZE);
			memcpy(OUT_DATA + 2 + LINKADDR_SIZE, PUB_KEY, X25519_LEN);
			NETSTACK_NETWORK.output(NULL);

			OTP = random_rand();
			printf("Generated OTP %u\n", OTP);
		}
	}
	PROCESS_END();
}

PROCESS_THREAD(test_serial_process, ev, data)
{
	static struct etimer et;
	uint16_t tmp, srcid;
	uint32_t outlen;
	char *msg = data;

	PROCESS_BEGIN();

	etimer_set(&et, CLOCK_SECOND*100);

	while (1)
	{
		PROCESS_WAIT_EVENT();

		if (etimer_expired(&et))
		{
			LOG_DBG("Waiting for serial data\n");
			etimer_restart(&et);
		}

		if (ev == serial_line_event_message)
		{
			LOG_DBG("Message received: '%s'\n", msg);
			switch (msg[0])
			{
			case '0':
				srcid = TMP_REQ_SRC.u8[0];
				if (!gen_secret(TMP_PUB_KEY, PRIV_KEY, &outlen, srcid)) goto cleanup;
				LOG_INFO("Generated secret with %u: ", srcid);

				tmp = strtol(msg + 1, NULL, 10);
				LOG_INFO_("Sending OTP: %d and public key\n", tmp);

				memset(OUT_DATA, 0, DATA_LEN);
				OUT_DATA[0] = RETN_PUB_KEY;
				OUT_DATA[1] = (2 + X25519_LEN) & 0xFF;
				memcpy(OUT_DATA + 2, &tmp, 2);
				memcpy(OUT_DATA + 4, PUB_KEY, X25519_LEN);
				NETSTACK_NETWORK.output(&TMP_REQ_SRC);
				break;

			case '1':
				LOG_INFO("Re-generating public private key pair\n");
				OTP = 0;
				for (tmp = 0; tmp < MAX_DEVICES; ++tmp)
				{
					link_nonce[tmp] = 0;
					if (link_secret[tmp])
					{
						free(link_secret[tmp]);
						link_secret[tmp] = NULL;
					}
				}

				if (!new_key_pair(PUB_KEY, PRIV_KEY)) goto cleanup;
				break;

			case '2':
				LOG_INFO("Broadcast message '%s'\n", msg);
				send_raw_msg(NULL, SEND_RAW_TXT, msg, strlen(msg));
				break;

			default:
				LOG_ERR("Unknown serial operation: %s\n", msg);
				break;
			}
		}
	}

cleanup:
	PROCESS_END();
}

PROCESS_THREAD(nullnet_example_process, ev, data)
{
	static struct etimer periodic_timer;
	uint16_t rand_seed;

	PROCESS_BEGIN();

	// Initialize NullNet
	nullnet_buf = OUT_DATA;
	nullnet_len = DATA_LEN;
	nullnet_set_input_callback(input_callback);

	etimer_set(&periodic_timer, SEND_INTERVAL);
	LOG_DBG("SSL Version %d --- ", OPENSSL_VERSION_MAJOR);
	LOG_DBG_LLADDR(&linkaddr_node_addr);
	LOG_DBG_("\n");

	if (!new_key_pair(PUB_KEY, PRIV_KEY)) goto cleanup;
	// init random number generator with first two bytes of private key
	// one bit overlaps because contiki documentations says RAND_MAX is 0x7FFFFFFF
	rand_seed = PRIV_KEY[0] | (PRIV_KEY[1] << 7);
	random_init(rand_seed);
	memset(link_secret, 0, sizeof(uint8_t *) * MAX_DEVICES);
	memset(link_nonce, 0, sizeof(uint64_t) * MAX_DEVICES);

	while(1)
	{
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
		etimer_reset(&periodic_timer);
	}

cleanup:
	PROCESS_END();
}
