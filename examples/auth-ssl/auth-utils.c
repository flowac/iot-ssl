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
#include "lib/random.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
	CHECK_SECRET = 2, // check the shared secret received
	SEND_MESSAGE = 3, // send encrypted message
	SEND_RAW_TXT = 4, // send plain-text message
	INVALID_TYPE
};

static uint16_t OTP = 0; // one-time passcode
static uint8_t OUT_DATA[DATA_LEN]; // output data buffer for inter-node communications
static linkaddr_t TMP_REQ_SRC; // link address of incoming peering request
static uint8_t TMP_PUB_KEY[X25519_LEN]; // public key of incoming peering request
static uint8_t PUB_KEY[X25519_LEN], PRIV_KEY[X25519_LEN]; // public private X25519 key pair
static uint8_t *link_secret[MAX_DEVICES] = {}; // shared secret keys
static uint64_t link_nonce[MAX_DEVICES] = {}; // nonce of devices

// Calculate shared initialization vector value for the specified node pair
void calc_iv(int idx, uint8_t IV[IV_LEN])
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

// Decrypt a link message
void decrypt_link_msg(int idx, uint8_t *data, uint8_t *outdata, uint32_t *outlen)
{
	int datalen = data[0], tmplen = 0;
	uint8_t IV[IV_LEN]; // AES-GCM initialization vector
	EVP_CIPHER_CTX *ctx = NULL;

	*outlen = 0;
	data += 1;
	if (idx > MAX_DEVICES || !(link_secret[idx])) goto cleanup;
	calc_iv(idx, IV);

	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), link_secret[idx], IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_DecryptUpdate(ctx, outdata, &tmplen, data + 16, datalen) < 1) goto cleanup;
	*outlen = tmplen;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, data) < 1) goto cleanup;
	if (EVP_DecryptFinal_ex(ctx, outdata + *outlen, &tmplen) < 1) goto cleanup;
	*outlen += tmplen;

cleanup:
	if (ctx) EVP_CIPHER_CTX_free(ctx);
}

// Send an encrypted message
void send_enc_msg(int idx, const linkaddr_t *target, const enum OP_TYPE opt, const void *msg, const uint32_t msglen)
{
	int outlen = 0, tmplen = 0;
	uint8_t IV[IV_LEN]; // AES-GCM initialization vector
	EVP_CIPHER_CTX *ctx = NULL;

	if (idx > MAX_DEVICES || !(link_secret[idx])) goto cleanup;
	calc_iv(idx, IV);
	memset(OUT_DATA, 0, DATA_LEN);

	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), link_secret[idx], IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_EncryptUpdate(ctx, OUT_DATA + 18, &tmplen, msg, msglen) < 1) goto cleanup;
	outlen = tmplen;
	if (EVP_EncryptFinal_ex(ctx, OUT_DATA + 18 + outlen, &tmplen) < 1) goto cleanup;
	outlen += tmplen;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, OUT_DATA + 2) < 1) goto cleanup;

	printf("%d bytes encrypted + 16 byte tag\n", outlen);
	OUT_DATA[0] = opt;
	OUT_DATA[1] = (uint8_t) (outlen & 0xFF);
	NETSTACK_NETWORK.output(target);

cleanup:
	if (ctx) EVP_CIPHER_CTX_free(ctx);
}

// Send a plain-text message
void send_raw_msg(const linkaddr_t *dest, const enum OP_TYPE opt, const void *msg, const uint32_t msglen)
{
	memset(OUT_DATA, 0, DATA_LEN);
	OUT_DATA[0] = opt;
	OUT_DATA[1] = (uint8_t) (msglen & 0xFF);
	memcpy(OUT_DATA + 2, msg, msglen);
	NETSTACK_NETWORK.output(dest);
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
	//print_bytes(pub, pubLen);
	//print_bytes(priv, privLen);
	ret = 1;

cleanup:
	if (ctx) EVP_PKEY_CTX_free(ctx);
	if (key) EVP_PKEY_free(key);
	return ret;
}

// Network connection callback
void input_callback(const void *raw_data, uint16_t len, const linkaddr_t *src, const linkaddr_t *dest)
{
	static uint8_t link_auth[MAX_DEVICES] = {}; // authentication status
	uint8_t srcid = src->u8[0];
	uint8_t myid = dest->u8[0]; (void) myid;
	uint8_t *data = (uint8_t *) raw_data;
	uint16_t tmp;
	uint32_t outlen;
	enum OP_TYPE opt;

	if (len < DATA_LEN || srcid > MAX_DEVICES) return;
	if (link_auth[srcid] > MAX_AUTH_RETRY)
	{
		LOG_INFO("Blocked connection from %u due to auth fail\n", srcid);
		return;
	}

	opt = data[0];
	data++;
	--len;

	if (opt == SEND_PUB_KEY)
	{
		data++; // ignore msg length indicator
		memcpy(TMP_REQ_SRC.u8, data, LINKADDR_SIZE);
		memcpy(TMP_PUB_KEY, data + LINKADDR_SIZE, X25519_LEN);
	}
	else if (opt == RETN_PUB_KEY)
	{
		data++; // ignore msg length indicator
		memcpy(&tmp, data, 2);
		if (OTP == 0 || OTP != tmp)
		{
			LOG_ERR("%d entered incorrect OTP: %u\n", srcid, tmp);
			link_auth[srcid]++;
			return;
		}

		LOG_INFO("%d entered correct OTP: %u\n", srcid, OTP);
		OTP = 0;
		if (!gen_secret(data + 2, PRIV_KEY, &outlen, srcid)) return;
		LOG_INFO("Shared secret with %u: ", srcid);
		print_chars(link_secret[srcid], outlen);
		send_enc_msg(srcid, src, CHECK_SECRET, link_secret[srcid], outlen);
	}
	else if (opt == CHECK_SECRET)
	{
		if (!link_secret[srcid]) return;
		LOG_INFO("Got shared secret check from %d: ", srcid);
		decrypt_link_msg(srcid, data, OUT_DATA, &outlen);
		printf("%d bytes decrypted: ", outlen);
		print_chars(OUT_DATA, outlen);

		if (0 == memcmp(link_secret[srcid], OUT_DATA, outlen))
		{
			LOG_INFO("%d is fully authenticated\n", srcid);
			char *retmsg = "Shared secret matched";
			send_enc_msg(srcid, src, SEND_MESSAGE, retmsg, strlen(retmsg));
		}
		else
		{
			LOG_ERR("%d failed to authenticate\n", srcid);
			link_auth[srcid]++;
		}
	}
	else if (opt == SEND_MESSAGE)
	{
		if (!link_secret[srcid]) return;
		LOG_INFO("Got message from %d: ", srcid);
		decrypt_link_msg(srcid, data, OUT_DATA, &outlen);
		printf("%d bytes decrypted: ", outlen);
		print_chars(OUT_DATA, outlen);
	}
	else if (opt == SEND_RAW_TXT)
	{
		LOG_INFO("Got message from %d: ", srcid);
		print_chars(data + 1, data[0]);
	}
	else
	{
		LOG_ERR("Invalid message type %d\n", opt);
	}
}
