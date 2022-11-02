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
#define SEND_INTERVAL (CLOCK_SECOND << 1)

#define ED25519_LEN 32
#define DATA_LEN 64
#define MAX_AUTH_RETRY 2
#define MAX_DEVICES 16

enum DTYPE
{
	SEND_PUB_KEY = 0,
	SEND_DEVTYPE = 1,
	KEY_EXCHANGE = 2,
	SEND_MESSAGE = 3,
	INVALID_TYPE
};

uint8_t PUB_KEY[ED25519_LEN], PRIV_KEY[ED25519_LEN]; // public private ED25519 key pair
uint8_t OUT_DATA[DATA_LEN]; // output data

// public key auth
// man in the middle accepts
// public key certificate

void printChars(uint8_t *data, uint32_t len)
{
	uint32_t i;
	for (i = 1; i < len && data[i]; i++) printf("%c", data[i]);
	printf("\n");
}

void printBytes(uint8_t *data, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len; i++) printf("%02x", data[i]);
	printf("\n");
}

void broadcast_pub_key(void)
{
	memset(OUT_DATA, 0, DATA_LEN);
	OUT_DATA[0] = SEND_PUB_KEY;
	memcpy(OUT_DATA + 1, PUB_KEY, ED25519_LEN);
	NETSTACK_NETWORK.output(NULL);
}

void send_link_msg(const linkaddr_t *target, const char *msg)
{
	int msglen = strlen(msg);
	if (msglen > DATA_LEN - 2) msglen = DATA_LEN - 2;

	memset(OUT_DATA, 0, DATA_LEN);
	OUT_DATA[0] = SEND_MESSAGE;
	memcpy(OUT_DATA + 1, msg, msglen);
	NETSTACK_NETWORK.output(target);
}

void input_callback(const void *raw_data, uint16_t len, const linkaddr_t *src, const linkaddr_t *dest)
{
	static uint8_t link_auth[MAX_DEVICES] = {};
	static uint8_t *link_key[MAX_DEVICES] = {};
	uint8_t srcid = src->u8[0];
	uint8_t myid = dest->u8[0]; (void) myid;
	uint8_t *data = (uint8_t *) raw_data;

	if (len < DATA_LEN || srcid > MAX_DEVICES) return;
	if (link_auth[srcid] > MAX_AUTH_RETRY && link_auth[srcid] < 0xFF)
	{
		LOG_INFO("Blocked connection from %u due to auth fail\n", srcid);
		return;
	}

	if (data[0] == SEND_PUB_KEY)
	{
		// TODO: add sender address in data section to prevent a reply all

		//if ((srcid & 1) != (myid & 1)) return; // device ID matching
		if (link_key[srcid]) return;
		link_key[srcid] = calloc(ED25519_LEN, 1);
		memcpy(link_key[srcid], data + 1, ED25519_LEN);

		LOG_INFO("Init key exchange with (%u)\n", srcid);
		memset(OUT_DATA, 0, DATA_LEN);
		OUT_DATA[0] = KEY_EXCHANGE;

		// TODO: calculate proper key hash. current value is placeholder
		memcpy(OUT_DATA + 1, PUB_KEY, ED25519_LEN);
		// TODO: return to sender instead of reply all
		NETSTACK_NETWORK.output(src);
	}
	else if (data[0] == SEND_DEVTYPE)
	{
		// not implemented yet
	}
	else if (data[0] == KEY_EXCHANGE)
	{
		if (link_auth[srcid] == 0xFF) return;

		// need to be updated to confirm keys
		link_auth[srcid] = 0xFF;
		LOG_INFO("Authenticated %u\n", srcid);
		send_link_msg(src, "Hello :)");
	}
	else if (data[0] == SEND_MESSAGE)
	{
		if (link_auth[srcid] != 0xFF) return;
		printf("Got message from %d: ", srcid);
		printChars(data, DATA_LEN);
	}
	else
	{
		LOG_ERR("Invalid message type %d\n", data[0]);
	}
}

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
	LOG_DBG("pub[%lu] priv[%lu]\n", pubLen, privLen);
	printBytes(pub, pubLen);
	printBytes(priv, privLen);
	ret = 1;

cleanup:
	if (ctx) EVP_PKEY_CTX_free(ctx);
	if (key) EVP_PKEY_free(key);
	return ret;
}
