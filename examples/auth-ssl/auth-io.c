/**
 * \file
 *	IoT OpenSSL Auth I/O functions
 * \author
 *	Alan <alan@ld50.bid>
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

// Helper function to print hex data
void print_bytes(const uint8_t *data, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len; i++) printf("%02x", data[i]);
	printf("\n");
}

// Helper function to print characters
void print_chars(const uint8_t *data, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len; i++) if (!iscntrl(data[i])) printf("%c", data[i]);
	printf("\n");
}

// Simple checksum to display the shared secret in an easy to read format
void print_secret(const uint8_t *data, uint32_t len)
{
	uint8_t tmp;
	uint16_t crc = 0xFFFF;
	uint32_t i;
	for(i = 0; i < len; i++)
	{
		tmp = crc >> 8 ^ *data++;
		tmp ^= tmp >> 4;
		crc <<= 8;
		crc ^= tmp << 12;
		crc ^= tmp << 5;
		crc ^= tmp;
	}
	print_bytes((uint8_t *)&crc, 2);
}
