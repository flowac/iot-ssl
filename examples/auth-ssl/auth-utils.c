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

#define X25519_LEN 32
#define DATA_LEN 64
#define MAX_AUTH_RETRY 2
#define MAX_DEVICES 16

enum OP_TYPE
{
	SEND_PUB_KEY = 0,
	SEND_DEVTYPE = 1,
	KEY_EXCHANGE = 2,
	SEND_MESSAGE = 3,
	INVALID_TYPE
};

uint8_t PUB_KEY[X25519_LEN], PRIV_KEY[X25519_LEN]; // public private X25519 key pair
uint8_t OUT_DATA[DATA_LEN]; // output data

// public key auth
// man in the middle accepts
// public key certificate

// check log levels when printing these arrays
void printChars(uint8_t *data, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len && data[i]; i++) printf("%c", data[i]);
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
	memcpy(OUT_DATA + 1, linkaddr_node_addr.u8, LINKADDR_SIZE);
	memcpy(OUT_DATA + 1 + LINKADDR_SIZE, PUB_KEY, X25519_LEN);
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

int newKeyPair(uint8_t pub[X25519_LEN], uint8_t priv[X25519_LEN])
{
	int ret = 0;
	size_t pubLen = X25519_LEN, privLen = X25519_LEN;
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *ctx = NULL;

	if (!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL))) goto cleanup;
	if (!(key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519"))) goto cleanup;

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

uint8_t *genSecret(uint8_t pub[X25519_LEN], uint8_t priv[X25519_LEN], uint32_t *digest_len)
{
	uint8_t *secret = NULL, *digest = NULL;
	uint64_t secret_len;
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *mykey = NULL, *peerkey = NULL;

	// Load keys
	if (!(peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, X25519_LEN))) goto cleanup;
	if (!(mykey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, X25519_LEN))) goto cleanup;
	if (!(ctx = EVP_PKEY_CTX_new(mykey, NULL))) goto cleanup;
	if (1 != EVP_PKEY_derive_init(ctx)) goto cleanup;

	// Derive shared secret
	if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) goto cleanup;
	if (1 != EVP_PKEY_derive(ctx, NULL, &secret_len)) goto cleanup;
	if (!(secret = OPENSSL_malloc(secret_len))) goto cleanup;
	if (1 != (EVP_PKEY_derive(ctx, secret, &secret_len))) goto cleanup;

	// Conceal secret
	if (!(mdctx = EVP_MD_CTX_new())) goto cleanup;
	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)) goto cleanup;
	if (1 != EVP_DigestUpdate(mdctx, secret, secret_len)) goto cleanup;
	if (!(digest = OPENSSL_malloc(EVP_MD_size(EVP_sha256())))) goto cleanup;
	if (1 != EVP_DigestFinal_ex(mdctx, digest, digest_len)) goto cleanup;

cleanup:
	if (ctx)     EVP_PKEY_CTX_free(ctx);
	if (peerkey) EVP_PKEY_free(peerkey);
	if (mykey)   EVP_PKEY_free(mykey);
	if (mdctx)   EVP_MD_CTX_free(mdctx);
	if (secret)  free(secret);
	return digest;
}

void input_callback(const void *raw_data, uint16_t len, const linkaddr_t *src, const linkaddr_t *dest)
{
	static uint8_t link_auth[MAX_DEVICES] = {}; // authentication status
	static uint8_t *link_key[MAX_DEVICES] = {}; // public keys
	static uint8_t *link_secret[MAX_DEVICES] = {}; // shared secret keys
	uint8_t srcid = src->u8[0];
	uint8_t myid = dest->u8[0]; (void) myid;
	uint8_t *data = (uint8_t *) raw_data;
	uint32_t secret_len;
	linkaddr_t broadcast_src;
	enum OP_TYPE opt;

	if (len < DATA_LEN || srcid > MAX_DEVICES) return;
	if (link_auth[srcid] > MAX_AUTH_RETRY && link_auth[srcid] < 0xFF)
	{
		LOG_INFO("Blocked connection from %u due to auth fail\n", srcid);
		return;
	}

	opt = data[0];
	data += 1;
	--len;

	if (opt == SEND_PUB_KEY)
	{
		//if ((srcid & 1) != (myid & 1)) return; // device ID matching
		if (link_key[srcid]) return;
		memcpy(broadcast_src.u8, data, LINKADDR_SIZE);
		data += LINKADDR_SIZE;

		link_key[srcid] = calloc(X25519_LEN, 1);
		memcpy(link_key[srcid], data, X25519_LEN);

		LOG_INFO("Init key exchange with (%u)\n", srcid);
		if (!(link_secret[srcid] = genSecret(link_key[srcid], PRIV_KEY, &secret_len))) return;
		LOG_INFO("Shared secret with %u: ", srcid);
		printBytes(link_secret[srcid], secret_len);
	}
	else if (opt == SEND_DEVTYPE)
	{
		// not implemented yet
	}
	else if (opt == KEY_EXCHANGE)
	{
		// deprecated
		if (link_auth[srcid] == 0xFF) return;

		// need to be updated to confirm keys
		link_auth[srcid] = 0xFF;
		LOG_INFO("Authenticated %u\n", srcid);
		send_link_msg(src, "Hello :)");
	}
	else if (opt == SEND_MESSAGE)
	{
		if (link_auth[srcid] != 0xFF) return;
		printf("Got message from %d: ", srcid);
		printChars(data, len);
	}
	else
	{
		LOG_ERR("Invalid message type %d\n", opt);
	}
}
