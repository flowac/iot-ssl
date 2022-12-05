/**
 * \file
 *	IoT OpenSSL Auth Demo
 * \author
 *	Alan <alan@ld50.bid>
 */

#include "contiki.h"
#include "dev/button-hal.h"
#include "lib/random.h"
#include "sys/clock.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>

#define CBC_IV_LEN  16
#define GCM_IV_LEN  12
#define GCM_TAG_LEN 16
#define KEY_128_LEN 16
#define KEY_256_LEN 32

#define DATA_SIZE_1   (64)
#define DATA_SIZE_2   (2 * 1024)
#define DATA_SIZE_3   (64 * 1024)
#define DATA_SIZE_4   (2 * 1024 * 1024)
#define TEST_CYCLES_1 (32 * 1024 * 1024)
#define TEST_CYCLES_2 (1024 * 1024)
#define TEST_CYCLES_3 (32 * 1024)
#define TEST_CYCLES_4 (1024)

#define DATA_SIZE   DATA_SIZE_4
#define TEST_CYCLES TEST_CYCLES_4

static uint8_t RAW_DATA[DATA_SIZE]; // original data
static uint8_t ENC_DATA[DATA_SIZE]; // encrypted data
static uint8_t DEC_DATA[DATA_SIZE]; // decrypted data
static uint8_t CBC_DATA[DATA_SIZE]; // intermediate data for 2x CBC-128
static uint8_t CBC_IV[CBC_IV_LEN] = {}; // AES-GCM initialization vector
static uint8_t GCM_IV[GCM_IV_LEN] = {}; // AES-GCM initialization vector
static uint8_t GCM_TAG[GCM_TAG_LEN]; // tag data for GCM
static uint8_t KEY_256[KEY_256_LEN]; // 256-bit symmetrical key

void decrypt_cbc_128(const uint8_t *data, const uint32_t datalen, uint8_t *outdata, int *outlen, uint8_t *IV, uint8_t *tmpdata)
{
	int tmplen;
	EVP_CIPHER_CTX *ctx = NULL;

	memset(tmpdata, 0, datalen);
	memset(outdata, 0, datalen);
	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_DecryptInit_ex2(ctx, EVP_aes_128_cbc(), KEY_256 + KEY_128_LEN, IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_DecryptUpdate(ctx, tmpdata, outlen, data, datalen) < 1) goto cleanup;
	if (EVP_DecryptFinal_ex(ctx, tmpdata + *outlen, &tmplen) < 1) goto cleanup;
	EVP_CIPHER_CTX_free(ctx);

	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_DecryptInit_ex2(ctx, EVP_aes_128_cbc(), KEY_256, IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_DecryptUpdate(ctx, outdata, outlen, tmpdata, datalen) < 1) goto cleanup;
	if (EVP_DecryptFinal_ex(ctx, outdata + *outlen, &tmplen) < 1) goto cleanup;
	*outlen += tmplen;
	EVP_CIPHER_CTX_free(ctx);

	return;
cleanup:
	printf("Decrypt CBC 128 failed\n");
}

void encrypt_cbc_128(const uint8_t *data, const uint32_t datalen, uint8_t *outdata, int *outlen, uint8_t *IV, uint8_t *tmpdata)
{
	int tmplen;
	EVP_CIPHER_CTX *ctx = NULL;

	memset(tmpdata, 0, datalen);
	memset(outdata, 0, datalen);
	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_EncryptInit_ex2(ctx, EVP_aes_128_cbc(), KEY_256, IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_EncryptUpdate(ctx, tmpdata, outlen, data, datalen) < 1) goto cleanup;
	if (EVP_EncryptFinal_ex(ctx, tmpdata + *outlen, &tmplen) < 1) goto cleanup;
	EVP_CIPHER_CTX_free(ctx);

	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_EncryptInit_ex2(ctx, EVP_aes_128_cbc(), KEY_256 + KEY_128_LEN, IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_EncryptUpdate(ctx, outdata, outlen, tmpdata, datalen) < 1) goto cleanup;
	if (EVP_EncryptFinal_ex(ctx, outdata + *outlen, &tmplen) < 1) goto cleanup;
	*outlen += tmplen;
	EVP_CIPHER_CTX_free(ctx);

	return;
cleanup:
	printf("Encrypt CBC 128 failed\n");
}

void decrypt_gcm_256(const uint8_t *data, const uint32_t datalen, uint8_t *outdata, int *outlen, uint8_t *tag, uint8_t *IV)
{
	int tmplen;
	EVP_CIPHER_CTX *ctx = NULL;

	memset(outdata, 0, datalen);
	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), KEY_256, IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_DecryptUpdate(ctx, outdata, outlen, data, datalen) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) < 1) goto cleanup;
	if (EVP_DecryptFinal_ex(ctx, outdata + *outlen, &tmplen) < 1) goto cleanup;
	*outlen += tmplen;
	EVP_CIPHER_CTX_free(ctx);

	return;
cleanup:
	printf("Decrypt GCM 256 failed\n");
}

void encrypt_gcm_256(const uint8_t *data, const uint32_t datalen, uint8_t *outdata, int *outlen, uint8_t *tag, uint8_t *IV)
{
	int tmplen;
	EVP_CIPHER_CTX *ctx = NULL;

	memset(tag, 0, GCM_TAG_LEN);
	memset(outdata, 0, datalen);
	if (!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;
	if (EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), KEY_256, IV, NULL) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) < 1) goto cleanup;
	if (EVP_EncryptUpdate(ctx, outdata, outlen, data, datalen) < 1) goto cleanup;
	if (EVP_EncryptFinal_ex(ctx, outdata + *outlen, &tmplen) < 1) goto cleanup;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) < 1) goto cleanup;
	*outlen += tmplen;
	EVP_CIPHER_CTX_free(ctx);

	return;
cleanup:
	printf("Encrypt GCM 256 failed\n");
}

int check_data(const void *data1, const void *data2, const uint32_t datalen)
{
	return 0 == memcmp(data1, data2, datalen);
}

void test_aes()
{
	static int type = 0;
	clock_time_t start, total;
	int outlen;
	int64_t i;

	random_init(12345U);
	for (i = 0; i < DATA_SIZE; i++) RAW_DATA[i] = (uint8_t) (random_rand() & 0xFF);
	for (i = 0; i < KEY_256_LEN; i++) KEY_256[i] = (uint8_t) (random_rand() & 0xFF);

	if (type & 1)
	{
		start = clock_time();
		for (i = 0; i < TEST_CYCLES; i++)
		{
			GCM_IV[0]++;
			encrypt_gcm_256(RAW_DATA, DATA_SIZE, ENC_DATA, &outlen, GCM_TAG, GCM_IV);
			decrypt_gcm_256(ENC_DATA, DATA_SIZE, DEC_DATA, &outlen, GCM_TAG, GCM_IV);
			if (!check_data(RAW_DATA, DEC_DATA, DATA_SIZE)) printf("AES GCM encryption / decryption failed\n");
		}
		total = start - clock_time();
		printf("AES GCM 256 took %lu\n", total);
	}
	else
	{
		start = clock_time();
		for (i = 0; i < TEST_CYCLES; i++)
		{
			CBC_IV[0]++;
			encrypt_cbc_128(RAW_DATA, DATA_SIZE, ENC_DATA, &outlen, CBC_IV, CBC_DATA);
			decrypt_cbc_128(ENC_DATA, DATA_SIZE, DEC_DATA, &outlen, CBC_IV, CBC_DATA);
			if (!check_data(RAW_DATA, DEC_DATA, DATA_SIZE)) printf("AES CBC encryption / decryption failed\n");
		}
		total = start - clock_time();
		printf("AES CBC 128 took %lu\n", total);
	}
	type++;
}
/*---------------------------------------------------------------------------*/
PROCESS(test_aes_process, "AES test process");
AUTOSTART_PROCESSES(&test_aes_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(test_aes_process, ev, data)
{
	PROCESS_BEGIN();
	while (1)
	{
		PROCESS_YIELD();
		if (ev == button_hal_release_event)
		{
			printf("AES test enter %lu\n", clock_time());
			test_aes();
			printf("AES test exit %lu\n", clock_time());
		}
	}
	PROCESS_END();
}
