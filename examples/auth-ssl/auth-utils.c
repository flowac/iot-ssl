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

#define IV_LEN 12
#define X25519_LEN 32
#define DATA_LEN 64
#define MAX_AUTH_RETRY 2
#define MAX_DEVICES 16

enum OP_TYPE
{
	SEND_PUB_KEY = 0, // broadcast public key
	RETN_PUB_KEY = 1, // send public key to a specific address
	SEND_MESSAGE = 2, // send message
	INVALID_TYPE
};

static uint8_t IV[IV_LEN]; // encryption initialization vector
static uint8_t OUT_DATA[DATA_LEN]; // output data
static uint8_t PUB_KEY[X25519_LEN], PRIV_KEY[X25519_LEN]; // public private X25519 key pair
static uint8_t *link_secret[MAX_DEVICES] = {}; // shared secret keys
static uint64_t link_nonce[MAX_DEVICES] = {}; // nonce of devices

// Calculate shared initialization vector value for the specified node pair
void calc_iv(int idx)
{
	++link_nonce[idx];
	memcpy(IV, link_secret[idx] + (link_secret[idx][0] % 28), 4);
	memcpy(IV + 4, &(link_nonce[idx]), 8);
}

// Helper function to print hex data
void print_bytes(uint8_t *data, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len; i++) printf("%02x", data[i]);
	printf("\n");
}

// Helper function to print characters
void print_chars(uint8_t *data, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len; i++) printf("%c", data[i]);
	printf("\n");
}

// Decrypt and print a link message
void print_link_msg(int idx, uint8_t *data)
{
	int datalen = data[0], outlen = 0, tmplen = 0;
	EVP_CIPHER_CTX *ctx = NULL;

	data += 1;
	if (idx > MAX_DEVICES || !(link_secret[idx])) goto cleanup;
	calc_iv(idx);

	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), link_secret[idx], IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_DecryptUpdate(ctx, OUT_DATA, &tmplen, data + 16, datalen) < 1) goto cleanup;
	outlen = tmplen;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, data) < 1) goto cleanup;
	if (EVP_DecryptFinal_ex(ctx, OUT_DATA + outlen, &tmplen) < 1) goto cleanup;
	outlen += tmplen;

	printf("%d bytes decrypted: ", outlen);
	print_chars(OUT_DATA, outlen);

cleanup:
	if (ctx) EVP_CIPHER_CTX_free(ctx);
}

// Encrypt and send a link message
void send_link_msg(int idx, const linkaddr_t *target, const char *msg)
{
	int msglen = strlen(msg), outlen = 0, tmplen = 0;
	EVP_CIPHER_CTX *ctx = NULL;

	if (idx > MAX_DEVICES || !(link_secret[idx])) goto cleanup;
	calc_iv(idx);
	memset(OUT_DATA, 0, DATA_LEN);

	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), link_secret[idx], IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_EncryptUpdate(ctx, OUT_DATA + 18, &tmplen, (const uint8_t *) msg, msglen) < 1) goto cleanup;
	outlen = tmplen;
	if (EVP_EncryptFinal_ex(ctx, OUT_DATA + 18 + outlen, &tmplen) < 1) goto cleanup;
	outlen += tmplen;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, OUT_DATA + 2) < 1) goto cleanup;

	printf("%d bytes encrypted + 16 byte tag\n", outlen);
	OUT_DATA[0] = SEND_MESSAGE;
	OUT_DATA[1] = (uint8_t) (outlen & 0xFF);
	NETSTACK_NETWORK.output(target);

cleanup:
	if (ctx) EVP_CIPHER_CTX_free(ctx);
}

// Generate shared secret between node pairs
int gen_secret(uint8_t *pub, uint8_t *priv, uint32_t *digest_len, int idx)
{
	uint8_t *secret = NULL, *digest = NULL;
	uint64_t secret_len;
	int ret = 0;
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
	link_secret[idx] = digest;
	ret = 1;

cleanup:
	if (ctx)     EVP_PKEY_CTX_free(ctx);
	if (peerkey) EVP_PKEY_free(peerkey);
	if (mykey)   EVP_PKEY_free(mykey);
	if (mdctx)   EVP_MD_CTX_free(mdctx);
	if (secret)  free(secret);
	return ret;
}

// Generate a public private key pair for the current node
int new_key_pair(uint8_t pub[X25519_LEN], uint8_t priv[X25519_LEN])
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
	print_bytes(pub, pubLen);
	print_bytes(priv, privLen);
	ret = 1;

cleanup:
	if (ctx) EVP_PKEY_CTX_free(ctx);
	if (key) EVP_PKEY_free(key);
	return ret;
}

// Broadcast the public key of the current node
int send_pub_key(int generate, const linkaddr_t *dest)
{
	int ret = 0, i;

	if (generate)
	{
		for (i = 0; i < MAX_DEVICES; ++i)
		{
			if (link_secret[i])
			{
				free(link_secret[i]);
				link_secret[i] = NULL;
			}
		}

		if (!new_key_pair(PUB_KEY, PRIV_KEY))
		{
			LOG_ERR("X25519 key gen error\n");
			goto cleanup;
		}
	}
	LOG_INFO("Sending public key to %d, generate = %d\n", dest ? dest->u8[0] : 0, generate);

	memset(OUT_DATA, 0, DATA_LEN);
	OUT_DATA[0] = generate ? SEND_PUB_KEY : RETN_PUB_KEY;
	memcpy(OUT_DATA + 1, linkaddr_node_addr.u8, LINKADDR_SIZE);
	memcpy(OUT_DATA + 1 + LINKADDR_SIZE, PUB_KEY, X25519_LEN);
	NETSTACK_NETWORK.output(dest);
	ret = 1;

cleanup:
	return ret;
}

// Network connection callback
void input_callback(const void *raw_data, uint16_t len, const linkaddr_t *src, const linkaddr_t *dest)
{
	// TODO: use a one time passcode to perform node authentication
	// TODO: increment failed auth count for failed message decryptions
	// TODO: check if the device ID matching below is needed

	static uint8_t link_auth[MAX_DEVICES] = {}; // authentication status
	uint8_t srcid = src->u8[0];
	uint8_t myid = dest->u8[0]; (void) myid;
	uint8_t *data = (uint8_t *) raw_data;
	uint32_t secret_len;
	linkaddr_t broadcast_src;
	enum OP_TYPE opt;

	if (len < DATA_LEN || srcid > MAX_DEVICES) return;
	if (link_auth[srcid] > MAX_AUTH_RETRY)
	{
		LOG_INFO("Blocked connection from %u due to auth fail\n", srcid);
		return;
	}

	opt = data[0];
	data += 1;
	--len;

	if (opt <= RETN_PUB_KEY)
	{
		//if ((srcid & 1) != (myid & 1)) return; // device ID matching
		memcpy(broadcast_src.u8, data, LINKADDR_SIZE);
		data += LINKADDR_SIZE;

		if (!gen_secret(data, PRIV_KEY, &secret_len, srcid)) return;
		LOG_INFO("Shared secret with %u: ", srcid);
		print_bytes(link_secret[srcid], secret_len);

		if (opt == RETN_PUB_KEY) send_link_msg(srcid, &broadcast_src, "key exchanged");
		else                     send_pub_key(0, &broadcast_src);
	}
	else if (opt == SEND_MESSAGE)
	{
		LOG_INFO_("Got message from %d: ", srcid);
		print_link_msg(srcid, data);
	}
	else
	{
		LOG_ERR("Invalid message type %d\n", opt);
	}
}
