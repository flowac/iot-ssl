/**
 * \file
 *	IoT OpenSSL Auth Demo
 * \author
 *	Alan <alan@ld50.bid>
 */

#include "contiki.h"
#include "dev/button-hal.h"
#include "net/netstack.h"
#include "net/nullnet/nullnet.h"
#include "sys/node-id.h"

#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include "dev/serial-line.h"
#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO
#define SEND_INTERVAL (CLOCK_SECOND << 4)
#define MAX_AUTH_RETRY 2

/*---------------------------------------------------------------------------*/
PROCESS(test_serial_process, "Serial test process");
PROCESS(button_hal_example, "Button HAL Example");
PROCESS(nullnet_example_process, "NullNet unicast example");
AUTOSTART_PROCESSES(&button_hal_example, &nullnet_example_process,&test_serial_process);
/*---------------------------------------------------------------------------*/
static uint8_t accept_next_conn = 0;
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
			accept_next_conn = 1;
		}
	}
	PROCESS_END();
}





PROCESS_THREAD(test_serial_process, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND*100);

  while(1) {
    PROCESS_WAIT_EVENT();

    if (etimer_expired(&et)) {
      printf("Waiting for serial data\n");
      etimer_restart(&et);
    }

    if(ev == serial_line_event_message) {
      printf("Message received: '%s'\n", (char*)data);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
void input_callback(const void *data, uint16_t len, const linkaddr_t *src, const linkaddr_t *dest)
{
	static uint8_t link_auth[16] = {};
	uint8_t srcid = src->u8[0];

	if (accept_next_conn > 0)
	{
		// create a seperate file to make a bad actor / spammer mote
		// make button press pre-req for key exchange instead of using it to bypass
		--accept_next_conn;
		link_auth[srcid] = 0xF0;
		LOG_INFO("Accepted connection from %u due to button click\n", srcid);
	}

	if (link_auth[srcid] > MAX_AUTH_RETRY)
	{
		if (link_auth[srcid] < 0xF0)
		{
			LOG_INFO("Blocked connection from %u due to auth fail\n", srcid);
			return;
		}
		if (link_auth[srcid] == 0xF0)
		{
			LOG_INFO("Authenticated %u, still need destination to accept me\n", srcid);
			// check if reply ok
			if (1)
			{
				LOG_INFO("Authenticated %u bi-directionally", srcid);
				link_auth[srcid] = 0xF1;
			}
			else
			{
				LOG_INFO("Return auth keys to (%u) ", srcid);
				LOG_INFO_LLADDR(src);
				LOG_INFO_("\n");
				NETSTACK_NETWORK.output(src);
				return;
			}
		}
	}

	if (len == sizeof(unsigned))
	{
		// make a read msg function
		unsigned count;
		memcpy(&count, data, sizeof(count));
		LOG_INFO("Received %u from (%u) ", count, srcid);
		LOG_INFO_LLADDR(src);
		LOG_INFO_("\n");

		if (link_auth[srcid] == 0xF1)
		{
			LOG_INFO("Msg is %u\n", count);
			//NETSTACK_NETWORK.output(src);
			return;
		}

		if (count == linkaddr_node_addr.u8[0])
		{
			LOG_INFO("Authenticated %u\n", srcid);
			link_auth[srcid] = 0xF0;
		}
		else
		{
			++link_auth[srcid];
			LOG_INFO("Auth %u failed %u times.\n", srcid, link_auth[srcid]);
		}
	}
}

void printBytes(uint8_t *data, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len; i++) printf("%02x", data[i]);
	printf("\n");
}

#define ED25519_LEN 36 // actually 32
int newKeyPair(uint8_t pub[ED25519_LEN], uint8_t priv[ED25519_LEN])
{
	int ret = 0;
	size_t pubLen = ED25519_LEN, privLen = ED25519_LEN;
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *ctx = NULL;

	if (!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL))) goto cleanup;
	if (!(key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"))) goto cleanup;

	if (EVP_PKEY_get_raw_public_key(key, pub, &pubLen) < 1) goto cleanup;
	if (EVP_PKEY_get_raw_private_key(key, priv, &privLen) < 1) goto cleanup;
	printf("pub[%lu] priv[%lu]\n", pubLen, privLen);
	printBytes(pub, pubLen);
	printBytes(priv, privLen);
	ret = 1;

cleanup:
	if (ctx) EVP_PKEY_CTX_free(ctx);
	if (key) EVP_PKEY_free(key);
	return ret;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(nullnet_example_process, ev, data)
{
	static struct etimer periodic_timer;
	static unsigned count = 0;

	PROCESS_BEGIN();
	/* Initialize NullNet */

	// TODO: make the buffer bigger and introduce op codes
	// connect, post, get, delete, etc

	nullnet_buf = (uint8_t *)&count;
	nullnet_len = sizeof(count);
	nullnet_set_input_callback(input_callback);

	uint8_t pub[ED25519_LEN], priv[ED25519_LEN];
	if (!newKeyPair(pub, priv))
	{
		LOG_ERR("ED25519 error\n");
		goto cleanup;
	}

	etimer_set(&periodic_timer, SEND_INTERVAL);
	LOG_WARN("SSL Version %d --- ", OPENSSL_VERSION_MAJOR);
	LOG_WARN_LLADDR(&linkaddr_node_addr);
	LOG_WARN_("\n");

	while(1)
	{
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

		if (count < 4)
		{
			LOG_INFO("Broadcast %u\n", count);
			NETSTACK_NETWORK.output(NULL);
		}
		count++;
		etimer_reset(&periodic_timer);
	}
cleanup: PROCESS_END();
}
