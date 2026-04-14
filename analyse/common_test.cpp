#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

uint8_t packet[4096] = {0};
uint8_t *ptr;
uint32_t packet_len = 0;
FILE *fp;

void construct_global_header(void)
{
	// =========================
	// 1. Global Header
	// =========================
	struct pcap_global_header gh;

	gh.magic_number  = 0xa1b2c3d4;
	gh.version_major = 2;
	gh.version_minor = 4;
	gh.thiszone      = 0;
	gh.sigfigs       = 0;
	gh.snaplen       = 65535;
	gh.network       = 1; // Ethernet

	fwrite(&gh, sizeof(gh), 1, fp);
}

void construct_ethernet_header(void)
{
	// ---- Ethernet ----
	uint8_t dst[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	uint8_t src[6] = {0x11,0x22,0x33,0x44,0x55,0x66};

	memcpy(ptr, dst, 6); ptr += 6;
	memcpy(ptr, src, 6); ptr += 6;

	*(uint16_t*)ptr = htons(0x893A); ptr += 2;
}

void construct_1905_header(void)
{
	// ---- 1905 Header ----
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0x8028); ptr += 2;
	*(uint16_t*)ptr = htons(0x0001); ptr += 2;
	*ptr++ = 0x00;
	*ptr++ = 0x80;
}

void construct_pcap_header(void)
{
	// =========================
	// 3. Packet Header
	// =========================
	struct pcap_packet_header ph;

	struct timeval tv;
	gettimeofday(&tv, NULL);

	ph.ts_sec  = tv.tv_sec;
	ph.ts_usec = tv.tv_usec;
	ph.incl_len = packet_len;
	ph.orig_len = packet_len;

	fwrite(&ph, sizeof(ph), 1, fp);

	// =========================
	// 4. Write Packet Data
	// =========================
	fwrite(packet, packet_len, 1, fp);
}

void construct_common_headers(const char *pcap_file_name)
{
	fp = fopen(pcap_file_name, "wb");
	construct_global_header();
	ptr = packet;
	construct_ethernet_header();
	construct_1905_header();
}

int construct_pcap_and_test(int (*test_func)(void))
{
	int ret;

	packet_len = ptr - packet;
	construct_pcap_header();
	fclose(fp);

	ret = test_func();
	return ret;
}

