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

int test_handle_bsta_cap_report(void)
{
	int ret;

	printf("packet_len = %d\n", packet_len);
	printf("PCAP file 'output.pcap' created successfully\n");
	__asan_poison_memory_region(&packet[packet_len], 4096 - packet_len);
	em_capability_t obj;
	ret = obj.handle_bsta_cap_report(packet, packet_len);
	__asan_unpoison_memory_region(&packet[packet_len], 4096 - packet_len);
	return ret;
}


void construct_common_headers(const char *pcap_file_name)
{
	fp = fopen(pcap_file_name, "wb");
	construct_global_header();
	ptr = packet;
	construct_ethernet_header();
	construct_1905_header();
}

int construct_pcap_and_test(void)
{
	int ret;

	packet_len = ptr - packet;
	construct_pcap_header();
	fclose(fp);
	ret = test_handle_bsta_cap_report();
	return ret;
}

void construct_pkt1_a_b_c10_d_e_rf_tlvs(void)
{
	// ---- TLV 0xCB ----
	*ptr++ = 0xCB;
	*(uint16_t*)ptr = htons(7); ptr += 2;

	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6); ptr += 6;
	*ptr++ = 0x00;

	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}

//A+B+C10+D+E
int pkt1_a_b_c10_d_e_rf_test(void)
{
	int ret;

	printf("===================== Testing A+B+C10+D+E ======================\n");
	construct_common_headers("pkt1.pcap");
	construct_pkt1_a_b_c10_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

	if (ret == 0) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
	}
	else
	{
		printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
	}
	
	printf("\n");

	return 0;
}

void construct_pkt2_a_b_c16_d_e_rf_tlvs(void)
{
	*ptr++ = 0xCB;

	// length = 13 (value only)
	uint16_t len = htons(13);
	memcpy(ptr, &len, 2);
	ptr += 2;

	// Radio MAC (6 bytes)
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	// Flags (bit7 = 1 → MAC included)
	*ptr++ = 0x80;

	// STA MAC (6 bytes)
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;

	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+D+E
int pkt2_a_b_c16_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+D+E =====================\n");
	construct_common_headers("pkt2.pcap");
	construct_pkt2_a_b_c16_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt4_a_b_c10_e_rf_tlvs(void)
{
	// C10
	// =========================
	*ptr++ = 0xCB;

	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int j = 0; j < 7; j++)
		*ptr++ = (uint8_t)(j + 1);

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+E
int pkt4_a_b_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+E =====================\n");
	construct_common_headers("pkt4.pcap");
	construct_pkt4_a_b_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt3_a_b_e_rf_tlvs(void)
{
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+E
int pkt3_a_b_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+E =====================\n");
	construct_common_headers("pkt3_rf.pcap");
	construct_pkt3_a_b_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt5_a_b_c16_e_rf_tlvs(void)
{
	*ptr++ = 0xCB;

	// length = 13 (value only)
	uint16_t len = htons(13);
	memcpy(ptr, &len, 2);
	ptr += 2;

	// Radio MAC (6 bytes)
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	// Flags (bit7 = 1 → MAC included)
	*ptr++ = 0x80;

	// STA MAC (6 bytes)
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;


	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C16+E
int pkt5_a_b_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+E =====================\n");
	construct_common_headers("pkt5.pcap");
	construct_pkt5_a_b_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt6_a_b_d_e_rf_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+D+E
int pkt6_a_b_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+D+E =====================\n");
	construct_common_headers("pkt6.pcap");
	construct_pkt6_a_b_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt7_a_b_c10_c10_c10_e_rf_tlvs(void)
{
	// 3 × C10 TLVs 0xCB
	// =========================
	for (int i = 0; i < 3; i++) {

		*ptr++ = 0xCB; // Type

		uint16_t len = htons(7); // VALUE = 7
		memcpy(ptr, &len, 2);
		ptr += 2;

		// 7 bytes dummy data
		uint8_t val[7];
		for (int j = 0; j < 7; j++) {
			val[j] = (uint8_t)(j + 1 + i);
		}

		memcpy(ptr, val, 7);
		ptr += 7;
	}

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+C10+C10+E
int pkt7_a_b_c10_c10_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+C10+E =====================\n");
	construct_common_headers("pkt7.pcap");
	construct_pkt7_a_b_c10_c10_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt8_a_b_c16_c16_c16_c16_e_rf_tlvs(void)
{
	// 4 × C16 TLVs
	// =========================
	for (int i = 0; i < 4; i++) {

		*ptr++ = 0xCB; // TLV Type

		uint16_t len = htons(13); // VALUE = 13
		memcpy(ptr, &len, 2);
		ptr += 2;

		// 13-byte value (valid structure)
		uint8_t val[13];

		// First 6 bytes (radio MAC)
		for (int j = 0; j < 6; j++) {
			val[j] = (uint8_t)(0x10 + j + i);
		}

		// Flag
		val[6] = 0x80;

		// Next 6 bytes (STA MAC)
		for (int j = 0; j < 6; j++) {
			val[7 + j] = (uint8_t)(0xA0 + j + i);
		}

		memcpy(ptr, val, 13);
		ptr += 13;
	}

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C16+C16+C16+c16+E
int pkt8_a_b_c16_c16_c16_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C16+C16+c16+E  =====================\n");
	construct_common_headers("pkt8.pcap");
	construct_pkt8_a_b_c16_c16_c16_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt9_a_b_c10_c16_c16_c10_c10_e_rf_tlvs(void)
{
	// C10
	// =========================
	*ptr++ = 0xCB;
	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int j = 0; j < 7; j++)
		*ptr++ = (uint8_t)(j + 1);

	// =========================
	// C16
	// =========================
	for (int k = 0; k < 2; k++) {
		*ptr++ = 0xCB;

		uint16_t len16 = htons(13);
		memcpy(ptr, &len16, 2); ptr += 2;

		// 6 bytes radio MAC
		for (int j = 0; j < 6; j++)
			*ptr++ = (uint8_t)(0x10 + j + k);

		*ptr++ = 0x80; // flag

		// 6 bytes STA MAC
		for (int j = 0; j < 6; j++)
			*ptr++ = (uint8_t)(0xA0 + j + k);
	}

	// =========================
	// C10
	// =========================
	for (int t = 0; t < 2; t++) {
		*ptr++ = 0xCB;

		uint16_t len = htons(7);
		memcpy(ptr, &len, 2); ptr += 2;

		for (int j = 0; j < 7; j++)
			*ptr++ = (uint8_t)(j + 5 + t);
	}

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+C16+C16+c10+C10+E
int pkt9_a_b_c10_c16_c16_c10_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C16+C16+c10+C10+E  =====================\n");
	construct_common_headers("pkt9.pcap");
	construct_pkt9_a_b_c10_c16_c16_c10_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt10_a_b_c10_c10_d_d_d_e_rf_tlvs(void)
{
	// C10 + C10
	// =========================
	for (int i = 0; i < 2; i++) {
		*ptr++ = 0xCB;

		uint16_t len = htons(7);
		memcpy(ptr, &len, 2); ptr += 2;

		for (int j = 0; j < 7; j++)
			*ptr++ = (uint8_t)(j + 1 + i);
	}

	// =========================
	// D + D + D  (0x90)
	// =========================
	for (int i = 0; i < 3; i++) {

		*ptr++ = 0x90;   // D type

		uint16_t len = htons(12);
		memcpy(ptr, &len, 2); ptr += 2;

		// 12-byte value (2 MACs example)
		for (int j = 0; j < 12; j++)
			*ptr++ = (uint8_t)(0x20 + j + i);
	}


	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+C10+D+D+D+E 
int pkt10_a_b_c10_c10_d_d_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+D+D+D+E  =====================\n");
	construct_common_headers("pkt10.pcap");
	construct_pkt10_a_b_c10_c10_d_d_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);

        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt11_a_b_d_d_e_rf_tlvs(void)
{
	// D + D  (0x90)
	// =========================

	for (int i = 0; i < 2; i++) {

		*ptr++ = 0x90;  // TLV type

		uint16_t len = htons(12);
		memcpy(ptr, &len, 2); ptr += 2;

		// 12-byte value
		for (int j = 0; j < 12; j++)
			*ptr++ = (uint8_t)(0x30 + j + i);
	}

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+D+D+E
int pkt11_a_b_d_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+D+D+E =====================\n");
	construct_common_headers("pkt11.pcap");
	construct_pkt11_a_b_d_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt12_a_b_c10_c16_e_rf_tlvs(void)
{
	// C10
	// =========================
	*ptr++ = 0xCB;

	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int j = 0; j < 7; j++)
		*ptr++ = (uint8_t)(j + 1);

	// =========================
	// C16
	// =========================
	*ptr++ = 0xCB;

	uint16_t len16 = htons(13);
	memcpy(ptr, &len16, 2); ptr += 2;

	// Radio MAC (6 bytes)
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	*ptr++ = 0x80; // flag

	// STA MAC (6 bytes)
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+C16+E
int pkt12_a_b_c10_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C16+E =====================\n");
	construct_common_headers("pkt12.pcap");
	construct_pkt12_a_b_c10_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt13_a_b_c16_c10_e_rf_tlvs(void)
{
	// =========================
	// C16
	// =========================
	*ptr++ = 0xCB;

	uint16_t len16 = htons(13);
	memcpy(ptr, &len16, 2); ptr += 2;

	// Radio MAC (6 bytes)
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	*ptr++ = 0x80; // flag

	// STA MAC (6 bytes)
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;

	// C10
	// =========================
	*ptr++ = 0xCB;

	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int j = 0; j < 7; j++)
		*ptr++ = (uint8_t)(j + 1);

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C16+C10+E
int pkt13_a_b_c16_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C10+E =====================\n");
	construct_common_headers("pkt13.pcap");
	construct_pkt13_a_b_c16_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt14_a_b_c10_c10_c16_e_rf_tlvs(void)
{
	// C10 + C10
	// =========================
	for (int i = 0; i < 2; i++) {
		*ptr++ = 0xCB;

		uint16_t len = htons(7);
		memcpy(ptr, &len, 2); ptr += 2;

		for (int j = 0; j < 7; j++)
			*ptr++ = (uint8_t)(j + 1 + i);
	}

	// =========================
	// C16
	// =========================
	*ptr++ = 0xCB;

	uint16_t len16 = htons(13);
	memcpy(ptr, &len16, 2); ptr += 2;

	// Radio MAC
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	*ptr++ = 0x80;

	// STA MAC
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+C10+C16+E
int pkt14_a_b_c10_c10_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+C16+E =====================\n");
	construct_common_headers("pkt14.pcap");
	construct_pkt14_a_b_c10_c10_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt15_a_b_c16_c16_c10_e_rf_tlvs(void)
{
	// C16 + C16
	// =========================
	for (int i = 0; i < 2; i++) {

		*ptr++ = 0xCB;

		uint16_t len = htons(13);
		memcpy(ptr, &len, 2); ptr += 2;

		// Radio MAC
		for (int j = 0; j < 6; j++)
			*ptr++ = (uint8_t)(0x10 + j + i);

		*ptr++ = 0x80;

		// STA MAC
		for (int j = 0; j < 6; j++)
			*ptr++ = (uint8_t)(0xA0 + j + i);
	}

	// =========================
	// C10
	// =========================
	*ptr++ = 0xCB;

	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int j = 0; j < 7; j++)
		*ptr++ = (uint8_t)(j + 1);

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C16+C16+C10+E
int pkt15_a_b_c16_c16_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C16+C10+E =====================\n");
	construct_common_headers("pkt15.pcap");
	construct_pkt15_a_b_c16_c16_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt16_a_b_c10_d_d_e_rf_tlvs(void)
{
	// ---- TLV 0xCB ----
	*ptr++ = 0xCB;
	*(uint16_t*)ptr = htons(7); ptr += 2;

	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6); ptr += 6;
	*ptr++ = 0x00;

	// D + D  (0x90)
	// =========================
	for (int i = 0; i < 2; i++) {

		*ptr++ = 0x90;

		uint16_t len = htons(12);
		memcpy(ptr, &len, 2); ptr += 2;

		// 12-byte value (example data)
		for (int j = 0; j < 12; j++)
			*ptr++ = (uint8_t)(0x40 + j + i);
	}

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}

//A+B+C10+D+D+E
int pkt16_a_b_c10_d_d_e_rf_test(void)
{
	int ret;

	printf("===================== Testing A+B+C10+D+D+E ======================\n");
	construct_common_headers("pkt16.pcap");
	construct_pkt16_a_b_c10_d_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt17_a_b_c16_d_d_e_rf_tlvs(void)
{
	// C16
	// =========================
	*ptr++ = 0xCB;

	uint16_t len16 = htons(13);
	memcpy(ptr, &len16, 2); ptr += 2;

	// Radio MAC
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	*ptr++ = 0x80;

	// STA MAC
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;

	// D + D  (0x90)
	// =========================
	for (int i = 0; i < 2; i++) {

		*ptr++ = 0x90;

		uint16_t len = htons(12);
		memcpy(ptr, &len, 2); ptr += 2;

		// 12-byte value (example data)
		for (int j = 0; j < 12; j++)
			*ptr++ = (uint8_t)(0x40 + j + i);
	}

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}

//A+B+C16+D+D+E
int pkt17_a_b_c16_d_d_e_rf_test(void)
{
	int ret;

	printf("===================== Testing A+B+C16+D+D+E ======================\n");
	construct_common_headers("pkt17.pcap");
	construct_pkt17_a_b_c16_d_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt18_a_b_c10_c10_d_e_rf_tlvs(void)
{
	// C10 + C10
	// =========================
	for (int i = 0; i < 2; i++) {

		*ptr++ = 0xCB;

		uint16_t len = htons(7);
		memcpy(ptr, &len, 2); ptr += 2;

		for (int j = 0; j < 7; j++)
			*ptr++ = (uint8_t)(j + 1 + i);
	}


	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+C10+D+E
int pkt18_a_b_c10_c10_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+D+E =====================\n");
	construct_common_headers("pkt18.pcap");
	construct_pkt18_a_b_c10_c10_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt19_a_b_c16_c16_d_e_rf_tlvs(void)
{
	// C16 + C16
	// =========================
	for (int i = 0; i < 2; i++) {

		*ptr++ = 0xCB;

		uint16_t len = htons(13);
		memcpy(ptr, &len, 2); ptr += 2;

		// Radio MAC (6 bytes)
		for (int j = 0; j < 6; j++)
			*ptr++ = (uint8_t)(0x10 + j + i);

		*ptr++ = 0x80;

		// STA MAC (6 bytes)
		for (int j = 0; j < 6; j++)
			*ptr++ = (uint8_t)(0xA0 + j + i);
	}

	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C16+C16+D+E
int pkt19_a_b_c16_c16_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C16+D+E =====================\n");
	construct_common_headers("pkt19.pcap");
	construct_pkt19_a_b_c16_c16_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt20_a_b_c10_c16_d_e_rf_tlvs(void)
{
	// C10
	// =========================
	*ptr++ = 0xCB;

	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int j = 0; j < 7; j++)
		*ptr++ = (uint8_t)(j + 1);

	// =========================
	// C16
	// =========================
	*ptr++ = 0xCB;

	uint16_t len16 = htons(13);
	memcpy(ptr, &len16, 2); ptr += 2;

	// Radio MAC (6 bytes)
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	*ptr++ = 0x80; // flag

	// STA MAC (6 bytes)
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;

	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+C16+D+E
int pkt20_a_b_c10_c16_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C16+D+E =====================\n");
	construct_common_headers("pkt20.pcap");
	construct_pkt20_a_b_c10_c16_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt21_a_b_c16_c10_d_e_rf_tlvs(void)
{
	// =========================
	// C16
	// =========================
	*ptr++ = 0xCB;

	uint16_t len16 = htons(13);
	memcpy(ptr, &len16, 2); ptr += 2;

	// Radio MAC (6 bytes)
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	*ptr++ = 0x80; // flag

	// STA MAC (6 bytes)
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;

	// C10
	// =========================
	*ptr++ = 0xCB;

	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int j = 0; j < 7; j++)
		*ptr++ = (uint8_t)(j + 1);

	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;


	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C16+C10+D+E
int pkt21_a_b_c16_c10_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C10+D+E =====================\n");
	construct_common_headers("pkt21.pcap");
	construct_pkt21_a_b_c16_c10_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt22_a_b_c10_c10_c10_d_e_rf_tlvs(void)
{
	// 3 × C10 TLVs 0xCB
	// =========================
	for (int i = 0; i < 3; i++) {

		*ptr++ = 0xCB; // Type

		uint16_t len = htons(7); // VALUE = 7
		memcpy(ptr, &len, 2);
		ptr += 2;

		// 7 bytes dummy data
		uint8_t val[7];
		for (int j = 0; j < 7; j++) {
			val[j] = (uint8_t)(j + 1 + i);
		}

		memcpy(ptr, val, 7);
		ptr += 7;
	}
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;


	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C10+C10+C10+D+E
int pkt22_a_b_c10_c10_c10_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C10+C10+C10+D+E =====================\n");
	construct_common_headers("pkt22.pcap");
	construct_pkt22_a_b_c10_c10_c10_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt23_a_b_c16_c16_c16_e_rf_tlvs(void)
{
	// 3 × C16 TLVs
	// =========================
	for (int i = 0; i < 3; i++) {

		*ptr++ = 0xCB;

		uint16_t len = htons(13);
		memcpy(ptr, &len, 2); ptr += 2;

		// Radio MAC (6 bytes)
		uint8_t radio_mac[6] = {
			(uint8_t)(0x10 + i),
			(uint8_t)(0x20 + i),
			(uint8_t)(0x30 + i),
			(uint8_t)(0x40 + i),
			(uint8_t)(0x50 + i),
			(uint8_t)(0x60 + i)
		};
		memcpy(ptr, radio_mac, 6);
		ptr += 6;

		// Flags
		*ptr++ = 0x80;

		// STA MAC (6 bytes)
		uint8_t sta_mac[6] = {
			(uint8_t)(0xAA + i),
			(uint8_t)(0xBB + i),
			(uint8_t)(0xCC + i),
			(uint8_t)(0xDD + i),
			(uint8_t)(0xEE + i),
			(uint8_t)(0xFF + i)
		};
		memcpy(ptr, sta_mac, 6);
		ptr += 6;
	}

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C16+C16+C16+E
int pkt23_a_b_c16_c16_c16_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+C16+C16+E =====================\n");
	construct_common_headers("pkt22.pcap");
	construct_pkt23_a_b_c16_c16_c16_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt24_a_b_c16_d_c10_e_rf_tlvs(void)
{
	// =========================
	// C16
	// =========================
	*ptr++ = 0xCB;

	uint16_t len16 = htons(13);
	memcpy(ptr, &len16, 2); ptr += 2;

	// Radio MAC (6 bytes)
	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6);
	ptr += 6;

	*ptr++ = 0x80; // flag

	// STA MAC (6 bytes)
	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6);
	ptr += 6;

	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	*(uint16_t*)ptr = htons(12); ptr += 2;

	uint8_t client_mac[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
	memcpy(ptr, client_mac, 6); ptr += 6;

	uint8_t xx_mac[6] = {0xaa,0x11,0x76,0x66,0x22,0x33};
	memcpy(ptr, xx_mac, 6); ptr += 6;

	// C10
	// =========================
	*ptr++ = 0xCB;

	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int j = 0; j < 7; j++)
		*ptr++ = (uint8_t)(j + 1);

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+C16+D+C10+E
int pkt24_a_b_c16_d_c10_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+C16+D+C10+E =====================\n");
	construct_common_headers("pkt24.pcap");
	construct_pkt24_a_b_c16_d_c10_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt25_a_b_d_c10_c16_d_e_rf_tlvs(void)
{
	// D (0x90)
	// =========================
	*ptr++ = 0x90;

	uint16_t lenD = htons(12);
	memcpy(ptr, &lenD, 2); ptr += 2;

	for (int i = 0; i < 12; i++)
		*ptr++ = (uint8_t)(0x10 + i);

	// =========================
	// C10 (0xCB)
	// =========================
	*ptr++ = 0xCB;

	uint16_t len10 = htons(7);
	memcpy(ptr, &len10, 2); ptr += 2;

	for (int i = 0; i < 7; i++)
		*ptr++ = (uint8_t)(0x20 + i);

	// =========================
	// C16 (0xCB)
	// =========================
	*ptr++ = 0xCB;

	uint16_t len16 = htons(13);
	memcpy(ptr, &len16, 2); ptr += 2;

	uint8_t radio_mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
	memcpy(ptr, radio_mac, 6); ptr += 6;

	*ptr++ = 0x80;

	uint8_t sta_mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	memcpy(ptr, sta_mac, 6); ptr += 6;

	// =========================
	// D again (0x90)
	// =========================
	*ptr++ = 0x90;

	uint16_t lenD2 = htons(12);
	memcpy(ptr, &lenD2, 2); ptr += 2;

	for (int i = 0; i < 12; i++)
		*ptr++ = (uint8_t)(0x50 + i);

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+D+C10+C16+D+E
int pkt25_a_b_d_c10_c16_d_e_rf_test(void)
{
	int ret;

	printf("================== Testing A+B+D+C10+C16+D+E =====================\n");
	construct_common_headers("pkt25.pcap");
	construct_pkt25_a_b_d_c10_c16_d_e_rf_tlvs();
	ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}


void construct_pkt1_a_b_c0_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB 
	*ptr++ = 0xCB;

	uint16_t len = htons(0);   
	memcpy(ptr, &len, 2);
	ptr += 2;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=0)+E
int pkt1_a_b_c0_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=0)+E  ======================\n");
	construct_common_headers("pkt1.pcap");
	construct_pkt1_a_b_c0_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt2_a_b_c1_e_rb_tlvs(void)
{
	*ptr++ = 0xCB;

	uint16_t len = htons(1);   // ❌ invalid
	memcpy(ptr, &len, 2);
	ptr += 2;

	*ptr++ = 0x01;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=1)+E
int pkt2_a_b_c1_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=1)+E  ======================\n");
	construct_common_headers("pkt2.pcap");
	construct_pkt2_a_b_c1_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt3_a_b_c2_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (L = 2 ❌) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(2);   // ❌ invalid
	memcpy(ptr, &len, 2);
	ptr += 2;

	*ptr++ = 0x01; *ptr++ = 0x02;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=2)+E
int pkt3_a_b_c2_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=2)+E  ======================\n");
	construct_common_headers("pkt3_rb.pcap");
	construct_pkt3_a_b_c2_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt4_a_b_c3_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (L = 3 ❌) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(3);   // ❌ invalid
	memcpy(ptr, &len, 2);
	ptr += 2;

	*ptr++ = 0x01; *ptr++ = 0x02; *ptr++ = 0x03;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=3)+E
int pkt4_a_b_c3_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=3)+E  ======================\n");
	construct_common_headers("pkt4.pcap");
	construct_pkt4_a_b_c3_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt5_a_b_c4_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (L = 4 ❌) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(4);   // ❌ invalid
	memcpy(ptr, &len, 2);
	ptr += 2;

	for(int i=0;i<4;i++) *ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=4)+E
int pkt5_a_b_c4_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=4)+E  ======================\n");
	construct_common_headers("pkt5.pcap");
	construct_pkt5_a_b_c4_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt6_a_b_c5_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (L = 5 ❌) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(5);   // ❌ invalid
	memcpy(ptr, &len, 2);
	ptr += 2;

	for(int i=0;i<5;i++) *ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=5)+E
int pkt6_a_b_c5_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=5)+E  ======================\n");
	construct_common_headers("pkt6.pcap");
	construct_pkt6_a_b_c5_e_rb_tlvs();
	ret = construct_pcap_and_test();

	if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt7_a_b_c6_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (L = 6 ❌) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(6);   // ❌ invalid
	memcpy(ptr, &len, 2);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=6)+E
int pkt7_a_b_c6_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=6)+E  ======================\n");
	construct_common_headers("pkt7.pcap");
	construct_pkt7_a_b_c6_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt8_a_b_c8_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (L = 8 ❌) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(8);   // ❌ invalid
	memcpy(ptr, &len, 2);
	ptr += 2;

	for(int i=0;i<8;i++) *ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=8)+E
int pkt8_a_b_c8_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=8)+E  ======================\n");
	construct_common_headers("pkt4.pcap");
	construct_pkt8_a_b_c8_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt9_a_b_c9_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (L = 9 ❌) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(9);   // ❌ invalid
	memcpy(ptr, &len, 2);
	ptr += 2;

	for(int i=0;i<9;i++) *ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=9)+E
int pkt9_a_b_c9_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=9)+E  ======================\n");
	construct_common_headers("pkt9.pcap");
	construct_pkt9_a_b_c9_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt10_a_b_c10_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB  ----
	*ptr++ = 0xCB;

	uint16_t len = htons(10);   //
	memcpy(ptr, &len, 2);
	ptr += 2;

	for(int i=0;i<10;i++) *ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=10)+E
int pkt10_a_b_c10_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=10)+E  ======================\n");
	construct_common_headers("pkt10.pcap");
	construct_pkt10_a_b_c10_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt11_a_b_c11_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB  ----
	*ptr++ = 0xCB;

	uint16_t len = htons(11);
	memcpy(ptr, &len, 2);
	ptr += 2;

	for(int i=0;i<11;i++) *ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=11)+E
int pkt11_a_b_c11_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=11)+E  ======================\n");
	construct_common_headers("pkt11.pcap");
	construct_pkt11_a_b_c11_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt12_a_b_c12_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB  ----
	*ptr++ = 0xCB;

	uint16_t len = htons(12);
	memcpy(ptr, &len, 2);
	ptr += 2;

	for(int i=0;i<12;i++) *ptr++ = i;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=12)+E
int pkt12_a_b_c12_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=12)+E  ======================\n");
	construct_common_headers("pkt12.pcap");
	construct_pkt12_a_b_c12_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt13_a_b_c20_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (INVALID length=20) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(20);   // ❌ WRONG length
	memcpy(ptr, &len, 2);
	ptr += 2;

	// Put 20 bytes of garbage data
	uint8_t invalid_data[20] = {
		0x10,0x20,0x30,0x40,0x50,0x60,
		0x80, // flag
		0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
		0x01,0x02,0x03,0x04,0x05,0x06,0x07
	};
	memcpy(ptr, invalid_data, 20);
	ptr += 20;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=20)+E
int pkt13_a_b_c20_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=20)+E  ======================\n");
	construct_common_headers("pkt13.pcap");
	construct_pkt13_a_b_c20_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt14_a_b_c15_e_rb_tlvs(void)
{
	// ---- C: TLV 0xCB (INVALID length=15) ----
	*ptr++ = 0xCB;

	uint16_t len = htons(15);   // ❌ WRONG length
	memcpy(ptr, &len, 2);
	ptr += 2;

	// 15 bytes dummy data
	uint8_t invalid_data[15] = {
		0x10,0x20,0x30,0x40,0x50,0x60,
		0x80, // flag
		0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
		0x01,0x02
	};
	memcpy(ptr, invalid_data, 15);
	ptr += 15;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+C(L=15)+E
int pkt14_a_b_c15_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+C(L=15)+E  ======================\n");
	construct_common_headers("pkt14.pcap");
	construct_pkt14_a_b_c15_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}


void construct_pkt15_a_b_d0_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(0);  
	memcpy(ptr, &len, 2);
	ptr += 2;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=0)+E
int pkt15_a_b_d0_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=0)+E  ======================\n");
	construct_common_headers("pkt15.pcap");
	construct_pkt15_a_b_d0_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt16_a_b_d1_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	uint16_t len = htons(1);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;

	*ptr++ = 0x00; // comment this line to crash get_first_tlv
	*(uint16_t*)ptr = htons(0); ptr += 2;
}

//A+B+D(L=1)+E
int pkt16_a_b_d1_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=1)+E  ======================\n");
	construct_common_headers("pkt16.pcap");
	construct_pkt16_a_b_d1_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt17_a_b_d2_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;
	uint16_t len = htons(2);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
	*ptr++ = 0x00;

	*ptr++ = 0x00; // comment this line to crash get_first_tlv
	*(uint16_t*)ptr = htons(0); ptr += 2;
}


//A+B+D(L=2)+E
int pkt17_a_b_d2_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=2)+E  ======================\n");
	construct_common_headers("pkt17.pcap");
	construct_pkt17_a_b_d2_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt18_a_b_d3_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(3);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=3)+E
int pkt18_a_b_d3_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=3)+E  ======================\n");
	construct_common_headers("pkt18.pcap");
	construct_pkt18_a_b_d3_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt19_a_b_d4_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(4);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=4)+E
int pkt19_a_b_d4_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=4)+E  ======================\n");
	construct_common_headers("pkt19.pcap");
	construct_pkt19_a_b_d4_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt20_a_b_d5_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(5);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;


	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=5)+E
int pkt20_a_b_d5_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=5)+E  ======================\n");
	construct_common_headers("pkt20.pcap");
	construct_pkt20_a_b_d5_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt21_a_b_d6_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(6);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}

//A+B+D(L=6)+E
int pkt21_a_b_d6_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=6)+E  ======================\n");
	construct_common_headers("pkt21.pcap");
	construct_pkt21_a_b_d6_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt22_a_b_d7_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(7);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=7)+E
int pkt22_a_b_d7_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=7)+E  ======================\n");
	construct_common_headers("pkt22.pcap");
	construct_pkt22_a_b_d7_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt23_a_b_d8_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(8);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=8)+E
int pkt23_a_b_d8_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=8)+E  ======================\n");
	construct_common_headers("pkt23.pcap");
	construct_pkt23_a_b_d8_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt24_a_b_d9_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(9);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=9)+E
int pkt24_a_b_d9_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=9)+E  ======================\n");
	construct_common_headers("pkt24.pcap");
	construct_pkt24_a_b_d9_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt25_a_b_d10_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(10);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=10)+E
int pkt25_a_b_d10_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=10)+E  ======================\n");
	construct_common_headers("pkt25.pcap");
	construct_pkt25_a_b_d10_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt26_a_b_d11_e_rb_tlvs(void)
{
	// ---- TLV 0x90 ----
	*ptr++ = 0x90;

	uint16_t len = htons(11);   // ❌ WRONG (should be 12)
	memcpy(ptr, &len, 2);
	ptr += 2;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
	*ptr++ = 0x00;
        *ptr++ = 0x00;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=11)+E
int pkt26_a_b_d11_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=11)+E  ======================\n");
	construct_common_headers("pkt26.pcap");
	construct_pkt26_a_b_d11_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt27_a_b_d14_e_rb_tlvs(void)
{
	// ---- TLV 0x90 (INVALID length=14) ----
	*ptr++ = 0x90;

	uint16_t len = htons(14);   // ❌ WRONG
	memcpy(ptr, &len, 2);
	ptr += 2;

	// 14 bytes (overflow case)
	uint8_t data[14] = {
		0x11,0x22,0x33,0x44,0x55,0x66,
		0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
		0x01,0x02
	};
	memcpy(ptr, data, 14);
	ptr += 14;

	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+D(L=14)+E
int pkt27_a_b_d14_e_rb_test(void)
{
	int ret;

	printf("===================== Testing A+B+D(L=14)+E  ======================\n");
	construct_common_headers("pkt27.pcap");
	construct_pkt27_a_b_d14_e_rb_tlvs();
	ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
		printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

	printf("\n");

	return 0;
}

void construct_pkt28_a_b_e_rf_len0_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+E(3) len 0
int pkt28_a_b_e_rf_len0_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 0  ======================\n");
        construct_common_headers("pkt28.pcap");
        construct_pkt28_a_b_e_rf_len0_tlvs();
        ret = construct_pcap_and_test();

        if (ret == 0) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt29_a_b_e_rb_len1_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(1); ptr += 2;

}


//A+B+E(3) len 1
int pkt29_a_b_e_rb_len1_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 1  ======================\n");
        construct_common_headers("pkt29.pcap");
        construct_pkt29_a_b_e_rb_len1_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt30_a_b_e_rb_len2_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(2); ptr += 2;

}


//A+B+E(3) len 2
int pkt30_a_b_e_rb_len2_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 2  ======================\n");
        construct_common_headers("pkt30.pcap");
        construct_pkt30_a_b_e_rb_len2_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}


void construct_pkt31_a_b_e_rb_len3_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(3); ptr += 2;

}


//A+B+E(3) len 3
int pkt31_a_b_e_rb_len3_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 3  ======================\n");
        construct_common_headers("pkt31.pcap");
        construct_pkt31_a_b_e_rb_len3_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt32_a_b_e_rb_len4_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(4); ptr += 2;

}


//A+B+E(3) len 4
int pkt32_a_b_e_rb_len4_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 4  ======================\n");
        construct_common_headers("pkt32.pcap");
        construct_pkt32_a_b_e_rb_len4_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}


void construct_pkt33_a_b_e_rb_len255_tlvs(void)
{
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(255); ptr += 2;

}


//A+B+E(3) len 255
int pkt33_a_b_e_rb_len255_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(3) len 255  ======================\n");
        construct_common_headers("pkt33.pcap");
        construct_pkt33_a_b_e_rb_len255_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt34_a_b_e_rb_tlvs(void)
{
        *(uint16_t*)ptr = htons(0); ptr += 2;

}


//A+B+E(2)
int pkt34_a_b_e_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(2)  ======================\n");
        construct_common_headers("pkt34.pcap");
        construct_pkt34_a_b_e_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt35_a_b_c_len0_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

//A+B+C(3) len 0
int pkt35_a_b_c_len0_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 0  ======================\n");
        construct_common_headers("pkt35.pcap");
        construct_pkt35_a_b_c_len0_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt36_a_b_c_len1_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

	*ptr++ = 0xAA;
}

//A+B+C(3) len 1
int pkt36_a_b_c_len1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 1  ======================\n");
        construct_common_headers("pkt36.pcap");
        construct_pkt36_a_b_c_len1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt37_a_b_c_len2_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
}

//A+B+C(3) len 2
int pkt37_a_b_c_len2_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 2  ======================\n");
        construct_common_headers("pkt37.pcap");
        construct_pkt37_a_b_c_len2_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt38_a_b_c_len3_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
}

//A+B+C(3) len 3
int pkt38_a_b_c_len3_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 3  ======================\n");
        construct_common_headers("pkt38.pcap");
        construct_pkt38_a_b_c_len3_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt39_a_b_c_len4_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;
        
        *(uint16_t*)ptr = htons(4);
        ptr += 2;

	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;


}

//A+B+C(3) len 4
int pkt39_a_b_c_len4_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 4  ======================\n");
        construct_common_headers("pkt39.pcap");
        construct_pkt39_a_b_c_len4_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt40_a_b_c_len255_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;
        
        *(uint16_t*)ptr = htons(255);
        ptr += 2;

	for(int i = 0; i < 255; i++){
		*ptr++ = (uint8_t)i;
	}

}

//A+B+C(3) len 255
int pkt40_a_b_c_len255_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(3) len 255  ======================\n");
        construct_common_headers("pkt40.pcap");
        construct_pkt40_a_b_c_len255_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt41_a_b_c_rb_tlvs(void)
{
        // ---- C: TLV 0xCB
        *ptr++ = 0xCB;
	*ptr++ = 0x00;
}

//A+B+C(2)
int pkt41_a_b_c_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(2)  ======================\n");
        construct_common_headers("pkt41.pcap");
        construct_pkt41_a_b_c_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt42_a_b_d_len0_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

//A+B+D(3) len 0
int pkt42_a_b_d_len0_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 0  ======================\n");
        construct_common_headers("pkt42.pcap");
        construct_pkt42_a_b_d_len0_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt43_a_b_d_len1_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(1);
        ptr += 2;

        *ptr++ = 0xAA;
}

//A+B+D(3) len 1
int pkt43_a_b_d_len1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 1  ======================\n");
        construct_common_headers("pkt43.pcap");
        construct_pkt43_a_b_d_len1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt44_a_b_d_len2_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(2);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
}

//A+B+D(3) len 2
int pkt44_a_b_d_len2_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 2  ======================\n");
        construct_common_headers("pkt44.pcap");
        construct_pkt44_a_b_d_len2_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt45_a_b_d_len3_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(3);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
}

//A+B+D(3) len 3
int pkt45_a_b_d_len3_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 3  ======================\n");
        construct_common_headers("pkt45.pcap");
        construct_pkt45_a_b_d_len3_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt46_a_b_d_len4_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(4);
        ptr += 2;

        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;


}

//A+B+D(3) len 4
int pkt46_a_b_d_len4_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 4  ======================\n");
        construct_common_headers("pkt46.pcap");
        construct_pkt46_a_b_d_len4_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt47_a_b_d_len255_rb_tlvs(void)
{
        *ptr++ = 0x90;

        *(uint16_t*)ptr = htons(255);
        ptr += 2;

        for(int i = 0; i < 255; i++){
                *ptr++ = (uint8_t)i;
        }

}

//A+B+D(3) len 255
int pkt47_a_b_d_len255_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(3) len 255  ======================\n");
        construct_common_headers("pkt47.pcap");
        construct_pkt47_a_b_d_len255_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}

void construct_pkt48_a_b_d_rb_tlvs(void)
{
        *ptr++ = 0xCB;
        *ptr++ = 0x00;
}

//A+B+D(2)
int pkt48_a_b_d_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(2)  ======================\n");
        construct_common_headers("pkt48.pcap");
        construct_pkt48_a_b_d_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

        return 0;
}


void construct_pkt49_a_b_e1_rb_tlvs(void)
{
        *ptr++ = 0x00;
}


//A+B+E(1)
int pkt49_a_b_e1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+E(1)    ======================\n");
        construct_common_headers("pkt49.pcap");
        construct_pkt49_a_b_e1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

	return 0;

}

void construct_pkt50_a_b_c1_rb_tlvs(void)
{
        *ptr++ = 0xCB;
}


//A+B+C(1)
int pkt50_a_b_c1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+C(1)   ======================\n");
        construct_common_headers("pkt50.pcap");
        construct_pkt50_a_b_c1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

	return 0;

}

void construct_pkt51_a_b_d1_rb_tlvs(void)
{
        *ptr++ = 0x90;
}


//A+B+D(1) 
int pkt51_a_b_d1_rb_test(void)
{
        int ret;

        printf("===================== Testing A+B+D(1)    ======================\n");
        construct_common_headers("pkt51.pcap");
        construct_pkt51_a_b_d1_rb_tlvs();
        ret = construct_pcap_and_test();

        if (ret == -1) {
                printf("================== %s: \033[32mPASS\033[0m ==============\n", __func__);
        }
        else
        {
                printf("================== %s: \033[31mFAIL\033[0m ==============\n", __func__);
        }

        printf("\n");

	return 0;

}


int main(void)
{
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt1_a_b_c10_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt2_a_b_c16_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt4_a_b_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt3_a_b_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt5_a_b_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt6_a_b_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt7_a_b_c10_c10_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt8_a_b_c16_c16_c16_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt9_a_b_c10_c16_c16_c10_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt10_a_b_c10_c10_d_d_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt11_a_b_d_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt12_a_b_c10_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt13_a_b_c16_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt14_a_b_c10_c10_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt15_a_b_c16_c16_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt16_a_b_c10_d_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt17_a_b_c16_d_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt18_a_b_c10_c10_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt19_a_b_c16_c16_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt20_a_b_c10_c16_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt21_a_b_c16_c10_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt22_a_b_c10_c10_c10_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt23_a_b_c16_c16_c16_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt24_a_b_c16_d_c10_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt25_a_b_d_c10_c16_d_e_rf_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");

	pkt1_a_b_c0_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt2_a_b_c1_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt3_a_b_c2_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt4_a_b_c3_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt5_a_b_c4_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt6_a_b_c5_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt7_a_b_c6_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt8_a_b_c8_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt9_a_b_c9_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt10_a_b_c10_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt11_a_b_c11_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt12_a_b_c12_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt13_a_b_c20_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt14_a_b_c15_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt15_a_b_d0_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt16_a_b_d1_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt17_a_b_d2_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt18_a_b_d3_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt19_a_b_d4_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt20_a_b_d5_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt21_a_b_d6_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt22_a_b_d7_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt23_a_b_d8_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt24_a_b_d9_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt25_a_b_d10_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt26_a_b_d11_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt27_a_b_d14_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt28_a_b_e_rf_len0_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt29_a_b_e_rb_len1_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt30_a_b_e_rb_len2_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt31_a_b_e_rb_len3_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt32_a_b_e_rb_len4_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt33_a_b_e_rb_len255_test();
        printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt34_a_b_e_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt35_a_b_c_len0_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt36_a_b_c_len1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt37_a_b_c_len2_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt38_a_b_c_len3_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt39_a_b_c_len4_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt40_a_b_c_len255_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt41_a_b_c_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt42_a_b_d_len0_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt43_a_b_d_len1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt44_a_b_d_len2_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt45_a_b_d_len3_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt46_a_b_d_len4_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt47_a_b_d_len255_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
        pkt48_a_b_d_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt49_a_b_e1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt50_a_b_c1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");
	pkt51_a_b_d1_rb_test();
	printf("--------------------------------------------------------------------------------------------------------------\n");


	return 0;
}
