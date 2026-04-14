#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void construct_ap_metrics_valid_tlvs(void)
{
	// ✅ AP Metrics TLV (0x94)
	*ptr++ = 0x94;

	*(uint16_t*)ptr = htons(7);   // ✅ correct length
	ptr += 2;

	// BSSID (6 bytes)
	for (int i = 0; i < 6; i++)
		*ptr++ = i;

	// Channel Utilization (1 byte)
	*ptr++ = 50;

	// EOM
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}
void construct_associated_sta_link_metrics_tlv_invalid_k1_partial(void)
{
	// ---- F: AP Metrics TLV (0x94)
	*ptr++ = 0x94;

	*(uint16_t*)ptr = htons(13);
	ptr += 2;

	// BSSID (6)
	for (int i = 0; i < 6; i++) {
		*ptr++ = i;
	}

	// Channel Utilization (1)
	*ptr++ = 0x50;

	// STA count (2)
	*ptr++ = 0x00;
	*ptr++ = 0x05;

	// ESP flags (1) → only AC-BE (bit7 = 1)
	*ptr++ = 0x80;

	// ESP BE (3 bytes)
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
}

void construct_associated_sta_link_metrics_tlv_pkt1_j3_e3(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(0);
	ptr += 2;

	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_j3_len1_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_j3_len2_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(2);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;

}

void construct_associated_sta_link_metrics_tlv_j3_len3_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(3);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;

}

void construct_associated_sta_link_metrics_tlv_j3_len4_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(4);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_j3_len5_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(5);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;

}

void construct_associated_sta_link_metrics_tlv_j3_len6_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(6);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}


void construct_associated_sta_link_metrics_tlv_k0_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	*(uint16_t*)ptr = htons(7);   // 6 (STA MAC) + 1 (k)
	ptr += 2;

	// ---- STA MAC (6 bytes)
	for (int i = 0; i < 6; i++) {
		*ptr++ = i;
	}

	// ---- k = 0 (no BSSID blocks)
	*ptr++ = 0x00;

}

void construct_associated_sta_link_metrics_tlv_k1_len8_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	// Flow: STA_MAC(6) + k(1) + partial BSSID(1)

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(8);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// partial BSSID
	*ptr++ = 0xAA;

}

void construct_associated_sta_link_metrics_tlv_k1_len9_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(9);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (2 bytes ❌)
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

}

void construct_associated_sta_link_metrics_tlv_k1_len10_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(10);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+10;

}

void construct_associated_sta_link_metrics_tlv_k1_len11_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(11);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++ = i+10;

}

void construct_associated_sta_link_metrics_tlv_k1_len12_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();


	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(12);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (5 bytes ❌)
	for(int i=0;i<5;i++) *ptr++ = i+10;

}

void construct_associated_sta_link_metrics_tlv_k1_len13_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(13);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6 ✅)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// missing all others ❌

}

void construct_associated_sta_link_metrics_tlv_k1_len14_oe(void)
{

	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(14);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x01; // partial time delta ❌

}

void construct_associated_sta_link_metrics_tlv_k1_len15_oe(void)
{

	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(15);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// BSSID (6)  <-- BSSID field
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial time delta (2 bytes ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;

}


void construct_associated_sta_link_metrics_tlv_k1_len16_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(16);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial time delta (3 bytes ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;
	*ptr++ = 0x03;

}

void construct_associated_sta_link_metrics_tlv_k1_len17_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(17);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// full time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// missing others ❌

}

void construct_associated_sta_link_metrics_tlv_k1_len18_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(18);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial DL rate (1 ❌)
	*ptr++ = 0x01;

}

void construct_associated_sta_link_metrics_tlv_k1_len19_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(19);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial DL rate (2 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;

}

void construct_associated_sta_link_metrics_tlv_k1_len20_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(20);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial DL rate (3 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;
	*ptr++ = 0x03;

}

void construct_associated_sta_link_metrics_tlv_k1_len21_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(21);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// full DL rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// missing UL + RCPI ❌

}

void construct_associated_sta_link_metrics_tlv_k1_len22_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(22);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UL (1 ❌)
	*ptr++ = 0x01;

}


void construct_associated_sta_link_metrics_tlv_k1_len23_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(23);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UL (2 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;

}

void construct_associated_sta_link_metrics_tlv_k1_len24_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(24);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UL (3 ❌)
	for(int i=0;i<3;i++) *ptr++ = i+40;

}


void construct_associated_sta_link_metrics_tlv_k1_len25_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(25);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// full UL (4)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// missing RCPI ❌

}

void construct_associated_sta_link_metrics_tlv_k1_len26_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(26);
	ptr += 2;

	// STA MAC
	for(int i=0;i<6;i++) *ptr++ = i;

	*ptr++ = 0x01;

	// BSSID (6)  <-- BSSID field
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// DL rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// UL rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// RCPI (1)
	*ptr++ = 0x55;

}

void construct_associated_sta_link_metrics_tlv_k2_len27_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(27);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 2
	*ptr++ = 0x02;

	// ---------- BLOCK 1 ----------
	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// Downlink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// Uplink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// RCPI (1)
	*ptr++ = 0x55;

	// ---------- BLOCK 2 (partial ❌) ----------
	// BSSID (only 1 byte ❌)
	*ptr++ = 0xAA;

}


void construct_associated_sta_link_metrics_tlv_k2_len28_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(28);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK 1 (full)
	for(int i=0;i<6;i++) *ptr++ = i+10;   // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+20;   // Time delta
	for(int i=0;i<4;i++) *ptr++ = i+30;   // DL
	for(int i=0;i<4;i++) *ptr++ = i+40;   // UL
	*ptr++ = 0x55;                        // RCPI

	// BLOCK 2 (partial ❌)
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

}

void construct_associated_sta_link_metrics_tlv_k2_len29_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(29);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK1
	for(int i=0;i<6;i++) *ptr++ = i+10;   // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+20;   // Time delta
	for(int i=0;i<4;i++) *ptr++ = i+30;   // DL
	for(int i=0;i<4;i++) *ptr++ = i+40;   // UL
	*ptr++ = 0x55;                        // RCPI

	// BLOCK2 (partial ❌ BSSID 3 bytes)
	for(int i=0;i<3;i++) *ptr++ = i+50;

}

void construct_associated_sta_link_metrics_tlv_k2_len30_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(30); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20; // Time
	for(int i=0;i<4;i++) *ptr++=i+30; // DL
	for(int i=0;i<4;i++) *ptr++=i+40; // UL
	*ptr++=0x55; // RCPI

	// BLOCK2 BSSID (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++=i+50;

}

void construct_associated_sta_link_metrics_tlv_k2_len31_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(31); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	// BLOCK2 BSSID (5 ❌)
	for(int i=0;i<5;i++) *ptr++=i+50;

}

void construct_associated_sta_link_metrics_tlv_k2_len32_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(32); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	// BLOCK2
	for(int i=0;i<6;i++) *ptr++=i+50; // BSSID

}


void construct_associated_sta_link_metrics_tlv_k2_len33_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(33); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	// BLOCK1 (full)
	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20; // Time delta
	for(int i=0;i<4;i++) *ptr++=i+30; // Downlink rate
	for(int i=0;i<4;i++) *ptr++=i+40; // Uplink rate
	*ptr++=0x55;                      // RCPI

	// BLOCK2 (partial ❌)
	for(int i=0;i<6;i++) *ptr++=i+50; // BSSID
	*ptr++=0x01; // Time delta (1 byte ❌)

}

void construct_associated_sta_link_metrics_tlv_k2_len34_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(34); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50; // BSSID
	*ptr++=0x01; *ptr++=0x02; // Time delta (2 ❌)

}

void construct_associated_sta_link_metrics_tlv_k2_len35_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(35); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	*ptr++=0x01; *ptr++=0x02; *ptr++=0x03; // Time delta (3 ❌)

}

void construct_associated_sta_link_metrics_tlv_k2_len36_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(36); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20; // Time
	for(int i=0;i<4;i++) *ptr++=i+30; // DL
	for(int i=0;i<4;i++) *ptr++=i+40; // UL
	*ptr++=0x55; // RCPI

	for(int i=0;i<6;i++) *ptr++=i+50; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+60; // Time delta

}

void construct_associated_sta_link_metrics_tlv_k2_len37_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(37); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	*ptr++=0x01; // DL (1 ❌)

}

void construct_associated_sta_link_metrics_tlv_k2_len38_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(38); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	*ptr++=0x01; *ptr++=0x02; // DL (2 ❌)
}

void construct_associated_sta_link_metrics_tlv_k2_len39_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(39); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	*ptr++=0x01; *ptr++=0x02; *ptr++=0x03; // DL (3 ❌)
}

void construct_associated_sta_link_metrics_tlv_k2_len40_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(40); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	for(int i=0;i<4;i++) *ptr++=i+70; // DL
}

void construct_associated_sta_link_metrics_tlv_k2_len41_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(40); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	for(int i=0;i<4;i++) *ptr++=i+70; // DL

	// Uplink rate (1 byte only ❌)
	*ptr++ = 0x01;
}


void construct_associated_sta_link_metrics_tlv_k2_len42_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(42);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK1 (FULL)
	for(int i=0;i<6;i++) *ptr++ = i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+20; // Time
	for(int i=0;i<4;i++) *ptr++ = i+30; // DL
	for(int i=0;i<4;i++) *ptr++ = i+40; // UL
	*ptr++ = 0x55; // RCPI

	// BLOCK2
	for(int i=0;i<6;i++) *ptr++ = i+50; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+60; // Time
	for(int i=0;i<4;i++) *ptr++ = i+70; // DL

	// UL partial (2 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;
}

void construct_associated_sta_link_metrics_tlv_k2_len43_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(43);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK1
	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;
	*ptr++ = 0x55;

	// BLOCK2
	for(int i=0;i<6;i++) *ptr++ = i+50;
	for(int i=0;i<4;i++) *ptr++ = i+60;
	for(int i=0;i<4;i++) *ptr++ = i+70;

	// UL partial (3 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;
	*ptr++ = 0x03;
}

void construct_associated_sta_link_metrics_tlv_k2_len44_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(44);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK1
	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;
	*ptr++ = 0x55;

	// BLOCK2
	for(int i=0;i<6;i++) *ptr++ = i+50; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+60; // Time
	for(int i=0;i<4;i++) *ptr++ = i+70; // DL
	for(int i=0;i<4;i++) *ptr++ = i+80; // UL

	// ❌ RCPI missing
}

void construct_associated_sta_link_metrics_tlv_k2_len45_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(45);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// ---------- BLOCK1 ----------
	for(int i=0;i<6;i++) *ptr++ = i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+20; // Time
	for(int i=0;i<4;i++) *ptr++ = i+30; // DL
	for(int i=0;i<4;i++) *ptr++ = i+40; // UL
	*ptr++ = 0x55; // RCPI

	// ---------- BLOCK2 ----------
	for(int i=0;i<6;i++) *ptr++ = i+50; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+60; // Time
	for(int i=0;i<4;i++) *ptr++ = i+70; // DL
	for(int i=0;i<4;i++) *ptr++ = i+80; // UL
	*ptr++ = 0x66; // RCPI
}

void construct_associated_sta_link_metrics_tlv_k3_len46_oe(void)
{

	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(46);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	// block3 partial (1 byte)
	*ptr++ = 0x90;

}

void construct_associated_sta_link_metrics_tlv_k3_len47_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(47);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<2;i++) *ptr++ = i+90;

}

void construct_associated_sta_link_metrics_tlv_k3_len48_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(48);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<3;i++) *ptr++ = i+90;

}

void construct_associated_sta_link_metrics_tlv_k3_len49_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(49);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<4;i++) *ptr++ = i+90;

}

void construct_associated_sta_link_metrics_tlv_k3_len50_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(50);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<5;i++) *ptr++ = i+90;

}

void construct_associated_sta_link_metrics_tlv_k3_len51_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(51);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<6;i++) *ptr++ = i+90;

}

void construct_associated_sta_link_metrics_tlv_k3_len52_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(52);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<7;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len53_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(53);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<8;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len54_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(54);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<9;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len55_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(55);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<10;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len56_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(56);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<11;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len57_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(57);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<12;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len58_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(58);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<13;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len59_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(59);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<14;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len60_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(60);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<15;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len61_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(61);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<16;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len62_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(62);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<17;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len63_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(63);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<18;i++) *ptr++ = i+90;
}

void construct_associated_sta_link_metrics_tlv_k3_len64_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(64);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 3
	*ptr++ = 0x03;

	// ---------- BLOCK 1 ----------
	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// Downlink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// Uplink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// RCPI (1)
	*ptr++ = 0x55;

	// ---------- BLOCK 2 ----------
	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+50;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+60;

	// Downlink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+70;

	// Uplink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+80;

	// RCPI (1)
	*ptr++ = 0x66;

	// ---------- BLOCK 3 ----------
	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+90;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+100;

	// Downlink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+110;

	// Uplink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+120;

	// RCPI (1)
	*ptr++ = 0x77;

}

void construct_associated_sta_link_metrics_tlv_j3_len1(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	*ptr++ = 0x00;


	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_j3_len2(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(2);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;

	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_j3_len3(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(3);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;


	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_j3_len4(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(4);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;


	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_j3_len5(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(5);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;

	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_j3_len6(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// Start of STA link metrics TLV
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	// Length = j(3)
	*(uint16_t*)ptr = htons(6);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;



	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}


void construct_associated_sta_link_metrics_tlv_k0(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	// ---- J: TLV (0x96)
	*ptr++ = 0x96;

	*(uint16_t*)ptr = htons(7);   // 6 (STA MAC) + 1 (k)
	ptr += 2;

	// ---- STA MAC (6 bytes)
	for (int i = 0; i < 6; i++) {
		*ptr++ = i;
	}

	// ---- k = 0 (no BSSID blocks)
	*ptr++ = 0x00;

	// ---- EOM (3 bytes)
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len8(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	// Flow: STA_MAC(6) + k(1) + partial BSSID(1)

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(8);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// partial BSSID
	*ptr++ = 0xAA;

	// EOM
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len9(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(9);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (2 bytes ❌)
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len10(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(10);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+10;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len11(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(11);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++ = i+10;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len12(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();


	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(12);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (5 bytes ❌)
	for(int i=0;i<5;i++) *ptr++ = i+10;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len13(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(13);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6 ✅)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// missing all others ❌

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len14(void)
{

	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(14);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	*ptr++ = 0x01; // partial time delta ❌

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len15(void)
{

	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(15);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// BSSID (6)  <-- BSSID field
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial time delta (2 bytes ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}


void construct_associated_sta_link_metrics_tlv_k1_len16(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(16);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial time delta (3 bytes ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;
	*ptr++ = 0x03;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len17(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(17);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// full time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// missing others ❌

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len18(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(18);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial DL rate (1 ❌)
	*ptr++ = 0x01;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len19(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(19);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial DL rate (2 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len20(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(20);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial DL rate (3 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;
	*ptr++ = 0x03;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len21(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(21);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// full DL rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// missing UL + RCPI ❌

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len22(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(22);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UL (1 ❌)
	*ptr++ = 0x01;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}


void construct_associated_sta_link_metrics_tlv_k1_len23(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(23);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UL (2 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}


void construct_associated_sta_link_metrics_tlv_k1_len24(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(24);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UL (3 ❌)
	for(int i=0;i<3;i++) *ptr++ = i+40;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}


void construct_associated_sta_link_metrics_tlv_k1_len25(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(25);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// full UL (4)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// missing RCPI ❌

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k1_len26(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(26);
	ptr += 2;

	// STA MAC
	for(int i=0;i<6;i++) *ptr++ = i;

	*ptr++ = 0x01;

	// BSSID (6)  <-- BSSID field
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// DL rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// UL rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// RCPI (1)
	*ptr++ = 0x55;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len27(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(27);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 2
	*ptr++ = 0x02;

	// ---------- BLOCK 1 ----------
	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// Downlink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// Uplink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// RCPI (1)
	*ptr++ = 0x55;

	// ---------- BLOCK 2 (partial ❌) ----------
	// BSSID (only 1 byte ❌)
	*ptr++ = 0xAA;

	// EOM
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len28(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(28);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK 1 (full)
	for(int i=0;i<6;i++) *ptr++ = i+10;   // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+20;   // Time delta
	for(int i=0;i<4;i++) *ptr++ = i+30;   // DL
	for(int i=0;i<4;i++) *ptr++ = i+40;   // UL
	*ptr++ = 0x55;                        // RCPI

	// BLOCK 2 (partial ❌)
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len29(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(29);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK1
	for(int i=0;i<6;i++) *ptr++ = i+10;   // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+20;   // Time delta
	for(int i=0;i<4;i++) *ptr++ = i+30;   // DL
	for(int i=0;i<4;i++) *ptr++ = i+40;   // UL
	*ptr++ = 0x55;                        // RCPI

	// BLOCK2 (partial ❌ BSSID 3 bytes)
	for(int i=0;i<3;i++) *ptr++ = i+50;

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len30(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(30); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20; // Time
	for(int i=0;i<4;i++) *ptr++=i+30; // DL
	for(int i=0;i<4;i++) *ptr++=i+40; // UL
	*ptr++=0x55; // RCPI

	// BLOCK2 BSSID (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++=i+50;

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len31(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(31); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	// BLOCK2 BSSID (5 ❌)
	for(int i=0;i<5;i++) *ptr++=i+50;

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len32(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(32); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	// BLOCK2
	for(int i=0;i<6;i++) *ptr++=i+50; // BSSID

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}


void construct_associated_sta_link_metrics_tlv_k2_len33(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(33); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	// BLOCK1 (full)
	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20; // Time delta
	for(int i=0;i<4;i++) *ptr++=i+30; // Downlink rate
	for(int i=0;i<4;i++) *ptr++=i+40; // Uplink rate
	*ptr++=0x55;                      // RCPI

	// BLOCK2 (partial ❌)
	for(int i=0;i<6;i++) *ptr++=i+50; // BSSID
	*ptr++=0x01; // Time delta (1 byte ❌)

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}


void construct_associated_sta_link_metrics_tlv_k2_len34(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(34); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50; // BSSID
	*ptr++=0x01; *ptr++=0x02; // Time delta (2 ❌)

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len35(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(35); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	*ptr++=0x01; *ptr++=0x02; *ptr++=0x03; // Time delta (3 ❌)

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len36(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(36); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+20; // Time
	for(int i=0;i<4;i++) *ptr++=i+30; // DL
	for(int i=0;i<4;i++) *ptr++=i+40; // UL
	*ptr++=0x55; // RCPI

	for(int i=0;i<6;i++) *ptr++=i+50; // BSSID
	for(int i=0;i<4;i++) *ptr++=i+60; // Time delta

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len37(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(37); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	*ptr++=0x01; // DL (1 ❌)

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len38(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(38); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	*ptr++=0x01; *ptr++=0x02; // DL (2 ❌)

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len39(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(39); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	*ptr++=0x01; *ptr++=0x02; *ptr++=0x03; // DL (3 ❌)

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len40(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(40); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	for(int i=0;i<4;i++) *ptr++=i+70; // DL

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len41(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++=0x96;
	*(uint16_t*)ptr=htons(40); ptr+=2;

	for(int i=0;i<6;i++) *ptr++=i;
	*ptr++=0x02;

	for(int i=0;i<6;i++) *ptr++=i+10;
	for(int i=0;i<4;i++) *ptr++=i+20;
	for(int i=0;i<4;i++) *ptr++=i+30;
	for(int i=0;i<4;i++) *ptr++=i+40;
	*ptr++=0x55;

	for(int i=0;i<6;i++) *ptr++=i+50;
	for(int i=0;i<4;i++) *ptr++=i+60;
	for(int i=0;i<4;i++) *ptr++=i+70; // DL

	// Uplink rate (1 byte only ❌)
	*ptr++ = 0x01;

	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}


void construct_associated_sta_link_metrics_tlv_k2_len42(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(42);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK1 (FULL)
	for(int i=0;i<6;i++) *ptr++ = i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+20; // Time
	for(int i=0;i<4;i++) *ptr++ = i+30; // DL
	for(int i=0;i<4;i++) *ptr++ = i+40; // UL
	*ptr++ = 0x55; // RCPI

	// BLOCK2
	for(int i=0;i<6;i++) *ptr++ = i+50; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+60; // Time
	for(int i=0;i<4;i++) *ptr++ = i+70; // DL

	// UL partial (2 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len43(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(43);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK1
	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;
	*ptr++ = 0x55;

	// BLOCK2
	for(int i=0;i<6;i++) *ptr++ = i+50;
	for(int i=0;i<4;i++) *ptr++ = i+60;
	for(int i=0;i<4;i++) *ptr++ = i+70;

	// UL partial (3 ❌)
	*ptr++ = 0x01;
	*ptr++ = 0x02;
	*ptr++ = 0x03;

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len44(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(44);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// BLOCK1
	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;
	*ptr++ = 0x55;

	// BLOCK2
	for(int i=0;i<6;i++) *ptr++ = i+50; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+60; // Time
	for(int i=0;i<4;i++) *ptr++ = i+70; // DL
	for(int i=0;i<4;i++) *ptr++ = i+80; // UL

	// ❌ RCPI missing

	*ptr++=0x00;*ptr++=0x00;*ptr++=0x00;
}

void construct_associated_sta_link_metrics_tlv_k2_len45(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(45);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// ---------- BLOCK1 ----------
	for(int i=0;i<6;i++) *ptr++ = i+10; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+20; // Time
	for(int i=0;i<4;i++) *ptr++ = i+30; // DL
	for(int i=0;i<4;i++) *ptr++ = i+40; // UL
	*ptr++ = 0x55; // RCPI

	// ---------- BLOCK2 ----------
	for(int i=0;i<6;i++) *ptr++ = i+50; // BSSID
	for(int i=0;i<4;i++) *ptr++ = i+60; // Time
	for(int i=0;i<4;i++) *ptr++ = i+70; // DL
	for(int i=0;i<4;i++) *ptr++ = i+80; // UL
	*ptr++ = 0x66; // RCPI

	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}



void construct_associated_sta_link_metrics_tlv_k3_len46(void)
{

	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(46);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	// block3 partial (1 byte)
	*ptr++ = 0x90;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k3_len47(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(47);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<2;i++) *ptr++ = i+90;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k3_len48(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(48);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<3;i++) *ptr++ = i+90;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k3_len49(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(49);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<4;i++) *ptr++ = i+90;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}


void construct_associated_sta_link_metrics_tlv_k3_len50(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(50);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<5;i++) *ptr++ = i+90;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k3_len51(void)
{

	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(51);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<6;i++) *ptr++ = i+90;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;
}

void construct_associated_sta_link_metrics_tlv_k3_len52(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(52);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<7;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len53(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(53);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<8;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len54(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(54);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<9;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len55(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(55);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<10;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len56(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(56);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<11;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len57(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(57);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<12;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len58(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(58);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<13;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len59(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(59);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<14;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len60(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(60);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<15;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len61(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(61);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<16;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len62(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(62);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<17;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len63(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(63);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<19;i++) *ptr++ = i+10;
	for(int i=0;i<19;i++) *ptr++ = i+40;

	for(int i=0;i<18;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_link_metrics_tlv_k3_len64(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(64);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 3
	*ptr++ = 0x03;

	// ---------- BLOCK 1 ----------
	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// Downlink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// Uplink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// RCPI (1)
	*ptr++ = 0x55;

	// ---------- BLOCK 2 ----------
	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+50;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+60;

	// Downlink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+70;

	// Uplink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+80;

	// RCPI (1)
	*ptr++ = 0x66;

	// ---------- BLOCK 3 ----------
	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+90;

	// Time delta (4)
	for(int i=0;i<4;i++) *ptr++ = i+100;

	// Downlink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+110;

	// Uplink rate (4)
	for(int i=0;i<4;i++) *ptr++ = i+120;

	// RCPI (1)
	*ptr++ = 0x77;

	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

//associated_sta_ext_link_metrics_tlv

void construct_associated_sta_ext_link_metrics_tlv_pkt1_j3_e3(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	// Length = 0
	*(uint16_t*)ptr = htons(0);
	ptr += 2;

	// ---- EOM
	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_ext_link_metrics_tlv_j3_len1_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// partial data ❌
	*ptr++ = 0x00;
}

void construct_associated_sta_ext_link_metrics_tlv_j3_len2_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(2);
	ptr += 2;

	// partial data ❌
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_ext_link_metrics_tlv_j3_len3_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(3);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;
}

void construct_associated_sta_ext_link_metrics_tlv_j3_len4_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(4);
	ptr += 2;

	for(int i=0;i<4;i++) *ptr++ = 0x00;
}

void construct_associated_sta_ext_link_metrics_tlv_j3_len5_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(5);
	ptr += 2;

	for(int i=0;i<5;i++) *ptr++ = 0x00;
}

void construct_associated_sta_ext_link_metrics_tlv_j3_len6_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(6);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = 0x00;
}

void construct_associated_sta_ext_link_metrics_tlv_k0_len7_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	// Length = 7
	*(uint16_t*)ptr = htons(7);
	ptr += 2;

	// STA MAC (6 bytes)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 0 (no BSSID blocks)
	*ptr++ = 0x00;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len8_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(8);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// partial BSSID (1 byte ❌)
	*ptr++ = 0x10;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len9_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(9);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// partial BSSID (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+10;
}


void construct_associated_sta_ext_link_metrics_tlv_k1_len10_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(10);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+10;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len11_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(11);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++ = i+10;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len12_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(12);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (5 bytes ❌)
	for(int i=0;i<5;i++) *ptr++ = i+10;
}


void construct_associated_sta_ext_link_metrics_tlv_k1_len13_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(13);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6 complete)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial DownlinkRate (0 bytes ❌ just boundary case)

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len14_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(14);
	ptr += 2;

	// STA MAC
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// BSSID (6 OK)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial DownlinkRate (1 byte ❌)
	*ptr++ = 0x20;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len15_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(15);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial DownlinkRate (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+20;

}


void construct_associated_sta_ext_link_metrics_tlv_k1_len16_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(16);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial DownlinkRate (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+20;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len17_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(17);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	// DownlinkRate (4 complete)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial UplinkRate (0 bytes ❌)

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len18_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(18);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial UplinkRate (1 byte ❌)
	*ptr++ = 0x30;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len19_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(19);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial UplinkRate (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+30;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len20_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(20);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// DownlinkRate (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial UplinkRate (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+30;
}


void construct_associated_sta_ext_link_metrics_tlv_k1_len21_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(21);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// UplinkRate (4 complete)
	for(int i=0;i<4;i++) *ptr++ = i+30;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len22_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(22);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UtilizationReceive (1 byte ❌)
	*ptr++ = 0x40;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len23_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(23);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UtilizationReceive (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len24_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(24);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UtilizationReceive (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len25_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(25);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// UtilizationReceive (4 complete)
	for(int i=0;i<4;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len26_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(26);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// partial UtilizationTransmit (1 byte ❌)
	*ptr++ = 0x50;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len27_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(27);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// partial UtilizationTransmit (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+50;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len28_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(28);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// partial UtilizationTransmit (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+50;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len29_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(29);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// full block (22 bytes)
	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;
	for(int i=0;i<4;i++) *ptr++ = i+50;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len30_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(30);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// full block
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (1 bytes ❌)
	for(int i=0;i<1;i++) *ptr++ = i+40;
}

void construct_associated_sta_ext_link_metrics_tlv_k2_len31_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(31);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// block1 (22 bytes full)
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len32_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(32);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len33_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(33);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len34_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(34);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (5 bytes ❌)
	for(int i=0;i<5;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len35_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(35);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (6 bytes ❌ → partial BSSID)
	for(int i=0;i<6;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len36_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(36);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (7 bytes ❌)
	for(int i=0;i<7;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len37_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(37);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (8 bytes ❌)
	for(int i=0;i<8;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len38_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(38);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (9 bytes ❌)
	for(int i=0;i<9;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len39_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(39);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (10 bytes ❌)
	for(int i=0;i<10;i++) *ptr++ = i+40;

}


void construct_associated_sta_ext_link_metrics_tlv_k2_len40_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(40);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// block1 (22 bytes full)
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (11 bytes ❌)
	for(int i=0;i<11;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len41_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(41);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (12 bytes ❌)
	for(int i=0;i<12;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len42_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(42);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (13 bytes ❌)
	for(int i=0;i<13;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len43_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(43);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (14 bytes ❌)
	for(int i=0;i<14;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len44_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(44);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (15 bytes ❌)
	for(int i=0;i<15;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len45_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(45);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (16 bytes ❌)
	for(int i=0;i<16;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len46_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(46);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (17 bytes ❌)
	for(int i=0;i<17;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len47_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(47);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (18 bytes ❌)
	for(int i=0;i<18;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len48_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(48);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (19 bytes ❌)
	for(int i=0;i<19;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len49_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(49);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (20 bytes ❌)
	for(int i=0;i<20;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len50_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(50);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (21 bytes ❌)
	for(int i=0;i<21;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len51_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(51);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// ---------- BLOCK 1 ----------
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// ---------- BLOCK 2 ----------
	for(int i=0;i<22;i++) *ptr++ = i+40;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len52_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(52);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	// block1 full (22)
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 full (22)
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (1 byte ❌)
	*ptr++ = 0x90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len53_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(53);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len54_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(54);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len55_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(55);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len56_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(56);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (5 bytes ❌)
	for(int i=0;i<5;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len57_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(57);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (6 bytes ❌)
	for(int i=0;i<6;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len58_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(58);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (7 bytes ❌)
	for(int i=0;i<7;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len59_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(59);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (8 bytes ❌)
	for(int i=0;i<8;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len60_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(60);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (9 bytes ❌)
	for(int i=0;i<9;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len61_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(61);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (10 bytes ❌)
	for(int i=0;i<10;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len62_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(62);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (11 bytes ❌)
	for(int i=0;i<11;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len63_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(63);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (12 bytes ❌)
	for(int i=0;i<12;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len64_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(64);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (13 bytes ❌)
	for(int i=0;i<13;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len65_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(65);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (14 bytes ❌)
	for(int i=0;i<14;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len66_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(66);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (15 bytes ❌)
	for(int i=0;i<15;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len67_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(67);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (16 bytes ❌)
	for(int i=0;i<16;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len68_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(68);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (17 bytes ❌)
	for(int i=0;i<17;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len69_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(69);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (18 bytes ❌)
	for(int i=0;i<18;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len70_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(70);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (19 bytes ❌)
	for(int i=0;i<19;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len71_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(71);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (20 bytes ❌)
	for(int i=0;i<20;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len72_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(72);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (21 bytes ❌)
	for(int i=0;i<21;i++) *ptr++ = i+90;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len73_oe(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(73);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	// ---------- BLOCK 1 ----------
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// ---------- BLOCK 2 ----------
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// ---------- BLOCK 3 ----------
	for(int i=0;i<22;i++) *ptr++ = i+90;

}



void construct_associated_sta_ext_link_metrics_tlv_j3_len1(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;

	// partial data ❌
	*ptr++ = 0x00;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_j3_len2(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(2);
	ptr += 2;

	// partial data ❌
	*ptr++ = 0x00;
	*ptr++ = 0x00;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_j3_len3(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(3);
	ptr += 2;

	*ptr++ = 0x00;
	*ptr++ = 0x00;
	*ptr++ = 0x00;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_j3_len4(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(4);
	ptr += 2;

	for(int i=0;i<4;i++) *ptr++ = 0x00;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_j3_len5(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(5);
	ptr += 2;

	for(int i=0;i<5;i++) *ptr++ = 0x00;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_j3_len6(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	*(uint16_t*)ptr = htons(6);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = 0x00;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k0_len7(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	// ---- TLV (0xC8)
	*ptr++ = 0xC8;

	// Length = 7
	*(uint16_t*)ptr = htons(7);
	ptr += 2;

	// STA MAC (6 bytes)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 0 (no BSSID blocks)
	*ptr++ = 0x00;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len8(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(8);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// partial BSSID (1 byte ❌)
	*ptr++ = 0x10;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len9(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(9);
	ptr += 2;

	// STA MAC (6)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// partial BSSID (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+10;

	*ptr++=0;*ptr++=0;*ptr++=0;
}


void construct_associated_sta_ext_link_metrics_tlv_k1_len10(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(10);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+10;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len11(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(11);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++ = i+10;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len12(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(12);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// partial BSSID (5 bytes ❌)
	for(int i=0;i<5;i++) *ptr++ = i+10;

	*ptr++=0;*ptr++=0;*ptr++=0;
}


void construct_associated_sta_ext_link_metrics_tlv_k1_len13(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(13);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6 complete)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial DownlinkRate (0 bytes ❌ just boundary case)


	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len14(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(14);
	ptr += 2;

	// STA MAC
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 1
	*ptr++ = 0x01;

	// BSSID (6 OK)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial DownlinkRate (1 byte ❌)
	*ptr++ = 0x20;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len15(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(15);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial DownlinkRate (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+20;

	*ptr++=0;*ptr++=0;*ptr++=0;

}


void construct_associated_sta_ext_link_metrics_tlv_k1_len16(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(16);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	// partial DownlinkRate (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+20;
	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len17(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(17);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	// DownlinkRate (4 complete)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial UplinkRate (0 bytes ❌)

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len18(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(18);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial UplinkRate (1 byte ❌)
	*ptr++ = 0x30;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len19(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(19);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;

	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial UplinkRate (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+30;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len20(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	*(uint16_t*)ptr = htons(20);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// BSSID (6)
	for(int i=0;i<6;i++) *ptr++ = i+10;

	// DownlinkRate (4)
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// partial UplinkRate (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+30;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_ext_link_metrics_tlv_k1_len21(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(21);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;

	// UplinkRate (4 complete)
	for(int i=0;i<4;i++) *ptr++ = i+30;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len22(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(22);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UtilizationReceive (1 byte ❌)
	*ptr++ = 0x40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len23(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(23);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UtilizationReceive (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len24(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(24);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// partial UtilizationReceive (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len25(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(25);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;

	// UtilizationReceive (4 complete)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}
void construct_associated_sta_ext_link_metrics_tlv_k1_len26(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(26);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// partial UtilizationTransmit (1 byte ❌)
	*ptr++ = 0x50;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len27(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(27);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// partial UtilizationTransmit (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+50;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len28(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(28);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;

	// partial UtilizationTransmit (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+50;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k1_len29(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(29);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// full block (22 bytes)
	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;
	for(int i=0;i<4;i++) *ptr++ = i+50;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_ext_link_metrics_tlv_k2_len30(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(30);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// full block
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// extra byte ❌
	*ptr++ = 0xFF;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len31(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(31);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// block1 (22 bytes full)
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len32(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(32);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len33(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(33);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len34(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(34);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (5 bytes ❌)
	for(int i=0;i<5;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len35(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(35);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (6 bytes ❌ → partial BSSID)
	for(int i=0;i<6;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len36(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(36);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (7 bytes ❌)
	for(int i=0;i<7;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len37(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(37);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (8 bytes ❌)
	for(int i=0;i<8;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len38(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(38);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (9 bytes ❌)
	for(int i=0;i<9;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len39(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(39);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (10 bytes ❌)
	for(int i=0;i<10;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;
}

void construct_associated_sta_ext_link_metrics_tlv_k2_len40(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(40);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (11 bytes ❌)
	for(int i=0;i<11;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len41(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(41);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (12 bytes ❌)
	for(int i=0;i<12;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len42(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(42);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (13 bytes ❌)
	for(int i=0;i<13;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len43(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(43);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (14 bytes ❌)
	for(int i=0;i<14;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len44(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(44);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (15 bytes ❌)
	for(int i=0;i<15;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len45(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(45);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (16 bytes ❌)
	for(int i=0;i<16;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len46(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(46);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (17 bytes ❌)
	for(int i=0;i<17;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len47(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(47);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (18 bytes ❌)
	for(int i=0;i<18;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len48(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(48);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (19 bytes ❌)
	for(int i=0;i<19;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len49(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(49);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (20 bytes ❌)
	for(int i=0;i<20;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len50(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(50);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 partial (21 bytes ❌)
	for(int i=0;i<21;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k2_len51(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(51);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x02;

	// ---------- BLOCK 1 ----------
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// ---------- BLOCK 2 ----------
	for(int i=0;i<22;i++) *ptr++ = i+40;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len52(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(52);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	// block1 full (22)
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// block2 full (22)
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (1 byte ❌)
	*ptr++ = 0x90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len53(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(53);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (2 bytes ❌)
	for(int i=0;i<2;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len54(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(54);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (3 bytes ❌)
	for(int i=0;i<3;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len55(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(55);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (4 bytes ❌)
	for(int i=0;i<4;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len56(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(56);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (5 bytes ❌)
	for(int i=0;i<5;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len57(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(57);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (6 bytes ❌)
	for(int i=0;i<6;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len58(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(58);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (7 bytes ❌)
	for(int i=0;i<7;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len59(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(59);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (8 bytes ❌)
	for(int i=0;i<8;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len60(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(60);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (9 bytes ❌)
	for(int i=0;i<9;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len61(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(61);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (10 bytes ❌)
	for(int i=0;i<10;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len62(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(62);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (11 bytes ❌)
	for(int i=0;i<11;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len63(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(63);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (12 bytes ❌)
	for(int i=0;i<12;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len64(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(64);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (13 bytes ❌)
	for(int i=0;i<13;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len65(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(65);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (14 bytes ❌)
	for(int i=0;i<14;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len66(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(66);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (15 bytes ❌)
	for(int i=0;i<15;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len67(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(67);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (16 bytes ❌)
	for(int i=0;i<16;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len68(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(68);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (17 bytes ❌)
	for(int i=0;i<17;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len69(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(69);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (18 bytes ❌)
	for(int i=0;i<18;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len70(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(70);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (19 bytes ❌)
	for(int i=0;i<19;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len71(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(71);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (20 bytes ❌)
	for(int i=0;i<20;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len72(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(72);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	for(int i=0;i<22;i++) *ptr++ = i+10;
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// block3 partial (21 bytes ❌)
	for(int i=0;i<21;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}

void construct_associated_sta_ext_link_metrics_tlv_k3_len73(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(73);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x03;

	// ---------- BLOCK 1 ----------
	for(int i=0;i<22;i++) *ptr++ = i+10;

	// ---------- BLOCK 2 ----------
	for(int i=0;i<22;i++) *ptr++ = i+40;

	// ---------- BLOCK 3 ----------
	for(int i=0;i<22;i++) *ptr++ = i+90;

	*ptr++=0;*ptr++=0;*ptr++=0;

}


void construct_associated_sta_link_metrics_tlv_3_full_len29(void)
{

	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	// ================= TLV 1 =================
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(29);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i;   // STA MAC
	*ptr++ = 0x01;

	for (int i = 0; i < 6; i++) *ptr++ = i + 10; // BSSID

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x01; // Time Delta
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x64; // DL
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x32; // UL
	*ptr++ = 0x50; // RCPI

	*ptr++ = 0xAA; *ptr++ = 0xBB; *ptr++ = 0xCC; // Extra

	// ================= TLV 2 =================
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(29);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 1;
	*ptr++ = 0x01;

	for (int i = 0; i < 6; i++) *ptr++ = i + 20;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x02;
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x65;
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x33;
	*ptr++ = 0x55;

	*ptr++ = 0xAA; *ptr++ = 0xBB; *ptr++ = 0xCC;

	// ================= TLV 3 =================
	*ptr++ = 0x96;
	*(uint16_t*)ptr = htons(29);
	ptr += 2;

	for (int i = 0; i < 6; i++) *ptr++ = i + 2;
	*ptr++ = 0x01;

	for (int i = 0; i < 6; i++) *ptr++ = i + 30;

	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x03;
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x66;
	*ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x34;
	*ptr++ = 0x60;

	*ptr++ = 0xAA; *ptr++ = 0xBB; *ptr++ = 0xCC;
}

void construct_ap_extended_metrics_tlv_len30(void)
{
    *ptr++ = 0xC7;

    *(uint16_t*)ptr = htons(30);
    ptr += 2;

    // BSSID (6)
    for(int i = 0; i < 6; i++) *ptr++ = i;

    // 6 fields × 4 bytes each
    for(int i = 0; i < 24; i++) *ptr++ = i+10;
}

void construct_radio_metrics_tlv_len10(void)
{
    *ptr++ = 0xC6;

    *(uint16_t*)ptr = htons(10);
    ptr += 2;

    // Radio ID (6)
    for(int i = 0; i < 6; i++) *ptr++ = i;

    // Metrics (1 byte each)
    *ptr++ = 0x10; // Noise
    *ptr++ = 0x20; // Transmit
    *ptr++ = 0x30; // ReceiveSelf
    *ptr++ = 0x40; // ReceiveOther
}

void construct_assoc_sta_traffic_stats_tlv_len34(void)
{
    *ptr++ = 0xA2;

    *(uint16_t*)ptr = htons(34);
    ptr += 2;

    // STA MAC (6)
    for(int i = 0; i < 6; i++) *ptr++ = i;

    // 7 fields × 4 bytes each
    for(int i = 0; i < 28; i++) *ptr++ = i+10;
}


void construct_associated_sta_ext_link_metrics_tlv_k1_len29_valid(void)
{
	construct_associated_sta_link_metrics_tlv_invalid_k1_partial();
	//construct_ap_extended_metrics_tlv_len30();
	//construct_radio_metrics_tlv_len10();
	//construct_assoc_sta_traffic_stats_tlv_len34();
	//construct_associated_sta_link_metrics_tlv_k1_len26_oe();

	/*        // ---- TLV (0xC8)
	 *ptr++ = 0xC8;

	// Length = 7
	 *(uint16_t*)ptr = htons(7);
	 ptr += 2;

	// STA MAC (6 bytes)
	for(int i=0;i<6;i++) *ptr++ = i;

	// k = 0 (no BSSID blocks)
	 *ptr++ = 0x00;*/

	*ptr++ = 0xC8;
	(*(uint16_t*)ptr) = htons(29);
	ptr += 2;

	for(int i=0;i<6;i++) *ptr++ = i;
	*ptr++ = 0x01;

	// full block (22 bytes)
	for(int i=0;i<6;i++) *ptr++ = i+10;
	for(int i=0;i<4;i++) *ptr++ = i+20;
	for(int i=0;i<4;i++) *ptr++ = i+30;
	for(int i=0;i<4;i++) *ptr++ = i+40;
	for(int i=0;i<4;i++) *ptr++ = i+50;

	//*ptr++ = 0xAA; *ptr++ = 0xBB; *ptr++ = 0xCC;
	*ptr++=0;*ptr++=0;*ptr++=0;

}

pkt_test_case_t handle_ap_metrics_response_suite[] = {

#if 1	
	{"associated_sta_link_metrics_tlv_3_full_len29", "p100.pcap", construct_associated_sta_link_metrics_tlv_3_full_len29, 0},
	{"associated_sta_link_metrics_tlv_invalid_k1", "pkt0krb.pcap", construct_associated_sta_link_metrics_tlv_invalid_k1_partial, -1},
	{"associated_sta_link_metrics_tlv_pkt1_j3_e3", "pkt1.pcap", construct_associated_sta_link_metrics_tlv_pkt1_j3_e3, -1},
	//WIthout EOM
	{"associated_sta_link_metrics_tlv_j3_len1_oe", "p1.pcap", construct_associated_sta_link_metrics_tlv_j3_len1_oe, -1},
	{"associated_sta_link_metrics_tlv_j3_len2_oe", "p2.pcap", construct_associated_sta_link_metrics_tlv_j3_len2_oe, -1},
	{"associated_sta_link_metrics_tlv_j3_len3_oe", "p3.pcap", construct_associated_sta_link_metrics_tlv_j3_len3_oe, -1},
	{"associated_sta_link_metrics_tlv_j3_len4_oe", "p4.pcap", construct_associated_sta_link_metrics_tlv_j3_len4_oe, -1},
	{"associated_sta_link_metrics_tlv_j3_len5_oe", "p5.pcap", construct_associated_sta_link_metrics_tlv_j3_len5_oe, -1},
	{"associated_sta_link_metrics_tlv_j3_len6_oe", "p6.pcap", construct_associated_sta_link_metrics_tlv_j3_len6_oe, -1},

	{"associated_sta_link_metrics_tlv_k0_oe", "p7.pcap", construct_associated_sta_link_metrics_tlv_k0_oe, -1},

	// ---------- k1 : len 8 → 26 ----------
	{"associated_sta_link_metrics_tlv_k1_len8_oe",  "p8.pcap",  construct_associated_sta_link_metrics_tlv_k1_len8_oe,  -1},
	{"associated_sta_link_metrics_tlv_k1_len9_oe",  "p9.pcap",  construct_associated_sta_link_metrics_tlv_k1_len9_oe,  -1},
	{"associated_sta_link_metrics_tlv_k1_len10_oe", "p10.pcap", construct_associated_sta_link_metrics_tlv_k1_len10_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len11_oe", "p11.pcap", construct_associated_sta_link_metrics_tlv_k1_len11_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len12_oe", "p12.pcap", construct_associated_sta_link_metrics_tlv_k1_len12_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len13_oe", "p13.pcap", construct_associated_sta_link_metrics_tlv_k1_len13_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len14_oe", "p14.pcap", construct_associated_sta_link_metrics_tlv_k1_len14_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len15_oe", "p15.pcap", construct_associated_sta_link_metrics_tlv_k1_len15_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len16_oe", "p16.pcap", construct_associated_sta_link_metrics_tlv_k1_len16_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len17_oe", "p17.pcap", construct_associated_sta_link_metrics_tlv_k1_len17_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len18_oe", "p18.pcap", construct_associated_sta_link_metrics_tlv_k1_len18_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len19_oe", "p19.pcap", construct_associated_sta_link_metrics_tlv_k1_len19_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len20_oe", "p20.pcap", construct_associated_sta_link_metrics_tlv_k1_len20_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len21_oe", "p21.pcap", construct_associated_sta_link_metrics_tlv_k1_len21_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len22_oe", "p22.pcap", construct_associated_sta_link_metrics_tlv_k1_len22_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len23_oe", "p23.pcap", construct_associated_sta_link_metrics_tlv_k1_len23_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len24_oe", "p24.pcap", construct_associated_sta_link_metrics_tlv_k1_len24_oe, -1},
	{"associated_sta_link_metrics_tlv_k1_len25_oe", "p25.pcap", construct_associated_sta_link_metrics_tlv_k1_len25_oe, -1},

	// ✅ valid
	{"associated_sta_link_metrics_tlv_k1_len26_oe", "p26.pcap", construct_associated_sta_link_metrics_tlv_k1_len26_oe, -1},


	// ---------- k2 : len 27 → 45 ----------
	{"associated_sta_link_metrics_tlv_k2_len27_oe", "p27.pcap", construct_associated_sta_link_metrics_tlv_k2_len27_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len28_oe", "p28.pcap", construct_associated_sta_link_metrics_tlv_k2_len28_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len29_oe", "p29.pcap", construct_associated_sta_link_metrics_tlv_k2_len29_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len30_oe", "p30.pcap", construct_associated_sta_link_metrics_tlv_k2_len30_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len31_oe", "p31.pcap", construct_associated_sta_link_metrics_tlv_k2_len31_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len32_oe", "p32.pcap", construct_associated_sta_link_metrics_tlv_k2_len32_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len33_oe", "p33.pcap", construct_associated_sta_link_metrics_tlv_k2_len33_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len34_oe", "p34.pcap", construct_associated_sta_link_metrics_tlv_k2_len34_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len35_oe", "p35.pcap", construct_associated_sta_link_metrics_tlv_k2_len35_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len36_oe", "p36.pcap", construct_associated_sta_link_metrics_tlv_k2_len36_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len37_oe", "p37.pcap", construct_associated_sta_link_metrics_tlv_k2_len37_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len38_oe", "p38.pcap", construct_associated_sta_link_metrics_tlv_k2_len38_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len39_oe", "p39.pcap", construct_associated_sta_link_metrics_tlv_k2_len39_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len40_oe", "p40.pcap", construct_associated_sta_link_metrics_tlv_k2_len40_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len41_oe", "p41.pcap", construct_associated_sta_link_metrics_tlv_k2_len41_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len42_oe", "p42.pcap", construct_associated_sta_link_metrics_tlv_k2_len42_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len43_oe", "p43.pcap", construct_associated_sta_link_metrics_tlv_k2_len43_oe, -1},
	{"associated_sta_link_metrics_tlv_k2_len44_oe", "p44.pcap", construct_associated_sta_link_metrics_tlv_k2_len44_oe, -1},

	// ✅ valid
	{"associated_sta_link_metrics_tlv_k2_len45_oe", "p45.pcap", construct_associated_sta_link_metrics_tlv_k2_len45_oe, -1},

	{"associated_sta_link_metrics_tlv_k3_len46_oe", "p46.pcap", construct_associated_sta_link_metrics_tlv_k3_len46_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len47_oe", "p47.pcap", construct_associated_sta_link_metrics_tlv_k3_len47_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len48_oe", "p48.pcap", construct_associated_sta_link_metrics_tlv_k3_len48_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len49_oe", "p49.pcap", construct_associated_sta_link_metrics_tlv_k3_len49_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len50_oe", "p50.pcap", construct_associated_sta_link_metrics_tlv_k3_len50_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len51_oe", "p51.pcap", construct_associated_sta_link_metrics_tlv_k3_len51_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len52_oe", "p52.pcap", construct_associated_sta_link_metrics_tlv_k3_len52_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len53_oe", "p53.pcap", construct_associated_sta_link_metrics_tlv_k3_len53_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len54_oe", "p54.pcap", construct_associated_sta_link_metrics_tlv_k3_len54_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len55_oe", "p55.pcap", construct_associated_sta_link_metrics_tlv_k3_len55_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len56_oe", "p56.pcap", construct_associated_sta_link_metrics_tlv_k3_len56_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len57_oe", "p57.pcap", construct_associated_sta_link_metrics_tlv_k3_len57_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len58_oe", "p58.pcap", construct_associated_sta_link_metrics_tlv_k3_len58_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len59_oe", "p59.pcap", construct_associated_sta_link_metrics_tlv_k3_len59_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len60_oe", "p60.pcap", construct_associated_sta_link_metrics_tlv_k3_len60_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len61_oe", "p61.pcap", construct_associated_sta_link_metrics_tlv_k3_len61_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len62_oe", "p62.pcap", construct_associated_sta_link_metrics_tlv_k3_len62_oe, -1},
	{"associated_sta_link_metrics_tlv_k3_len63_oe", "p63.pcap", construct_associated_sta_link_metrics_tlv_k3_len63_oe, -1},

	// ✅ VALID
	{"associated_sta_link_metrics_tlv_k3_len64", "p64.pcap", construct_associated_sta_link_metrics_tlv_k3_len64, -1},

	//WIth EOM
	{"associated_sta_link_metrics_tlv_j3_len1", "p1.pcap", construct_associated_sta_link_metrics_tlv_j3_len1, -1},
	{"associated_sta_link_metrics_tlv_j3_len2", "p2.pcap", construct_associated_sta_link_metrics_tlv_j3_len2, -1},
	{"associated_sta_link_metrics_tlv_j3_len3", "p3.pcap", construct_associated_sta_link_metrics_tlv_j3_len3, -1},
	{"associated_sta_link_metrics_tlv_j3_len4", "p4.pcap", construct_associated_sta_link_metrics_tlv_j3_len4, -1},
	{"associated_sta_link_metrics_tlv_j3_len5", "p5.pcap", construct_associated_sta_link_metrics_tlv_j3_len5, -1},
	{"associated_sta_link_metrics_tlv_j3_len6", "p6.pcap", construct_associated_sta_link_metrics_tlv_j3_len6, -1},
	{"associated_sta_link_metrics_tlv_k0", "pkt2.pcap",  construct_associated_sta_link_metrics_tlv_k0, -1},
	// ---------- k1 : len 8 → 26 ----------
	{"associated_sta_link_metrics_tlv_k1_len8",  "pkt3.pcap",  construct_associated_sta_link_metrics_tlv_k1_len8,  -1},
	{"associated_sta_link_metrics_tlv_k1_len9",  "pkt4.pcap",  construct_associated_sta_link_metrics_tlv_k1_len9,  -1},
	{"associated_sta_link_metrics_tlv_k1_len10", "pkt5.pcap",  construct_associated_sta_link_metrics_tlv_k1_len10, -1},
	{"associated_sta_link_metrics_tlv_k1_len11", "pkt6.pcap",  construct_associated_sta_link_metrics_tlv_k1_len11, -1},
	{"associated_sta_link_metrics_tlv_k1_len12", "pkt7.pcap",  construct_associated_sta_link_metrics_tlv_k1_len12, -1},
	{"associated_sta_link_metrics_tlv_k1_len13", "pkt8.pcap",  construct_associated_sta_link_metrics_tlv_k1_len13, -1},
	{"associated_sta_link_metrics_tlv_k1_len14", "pkt9.pcap",  construct_associated_sta_link_metrics_tlv_k1_len14, -1},
	{"associated_sta_link_metrics_tlv_k1_len15", "pkt10.pcap", construct_associated_sta_link_metrics_tlv_k1_len15, -1},
	{"associated_sta_link_metrics_tlv_k1_len16", "pkt11.pcap", construct_associated_sta_link_metrics_tlv_k1_len16, -1},
	{"associated_sta_link_metrics_tlv_k1_len17", "pkt12.pcap", construct_associated_sta_link_metrics_tlv_k1_len17, -1},
	{"associated_sta_link_metrics_tlv_k1_len18", "pkt13.pcap", construct_associated_sta_link_metrics_tlv_k1_len18, -1},
	{"associated_sta_link_metrics_tlv_k1_len19", "pkt14.pcap", construct_associated_sta_link_metrics_tlv_k1_len19, -1},
	{"associated_sta_link_metrics_tlv_k1_len20", "pkt15.pcap", construct_associated_sta_link_metrics_tlv_k1_len20, -1},
	{"associated_sta_link_metrics_tlv_k1_len21", "pkt16.pcap", construct_associated_sta_link_metrics_tlv_k1_len21, -1},
	{"associated_sta_link_metrics_tlv_k1_len22", "pkt17.pcap", construct_associated_sta_link_metrics_tlv_k1_len22, -1},
	{"associated_sta_link_metrics_tlv_k1_len23", "pkt18.pcap", construct_associated_sta_link_metrics_tlv_k1_len23, -1},

	{"associated_sta_link_metrics_tlv_k1_len24", "pkt19.pcap", construct_associated_sta_link_metrics_tlv_k1_len24, -1},
	{"associated_sta_link_metrics_tlv_k1_len25", "pkt20.pcap", construct_associated_sta_link_metrics_tlv_k1_len25, -1},

	// ✅ valid
	{"associated_sta_link_metrics_tlv_k1_len26", "pkt21.pcap", construct_associated_sta_link_metrics_tlv_k1_len26, -1},


	// ---------- k2 : len 27 → 45 ----------
	{"associated_sta_link_metrics_tlv_k2_len27", "pkt22.pcap", construct_associated_sta_link_metrics_tlv_k2_len27, -1},
	{"associated_sta_link_metrics_tlv_k2_len28", "pkt23.pcap", construct_associated_sta_link_metrics_tlv_k2_len28, -1},
	{"associated_sta_link_metrics_tlv_k2_len29", "pkt24.pcap", construct_associated_sta_link_metrics_tlv_k2_len29, -1},
	{"associated_sta_link_metrics_tlv_k2_len30", "pkt25.pcap", construct_associated_sta_link_metrics_tlv_k2_len30, -1},
	{"associated_sta_link_metrics_tlv_k2_len31", "pkt26.pcap", construct_associated_sta_link_metrics_tlv_k2_len31, -1},
	{"associated_sta_link_metrics_tlv_k2_len32", "pkt27.pcap", construct_associated_sta_link_metrics_tlv_k2_len32, -1},
	{"associated_sta_link_metrics_tlv_k2_len33", "pkt28.pcap", construct_associated_sta_link_metrics_tlv_k2_len33, -1},
	{"associated_sta_link_metrics_tlv_k2_len34", "pkt29.pcap", construct_associated_sta_link_metrics_tlv_k2_len34, -1},
	{"associated_sta_link_metrics_tlv_k2_len35", "pkt30.pcap", construct_associated_sta_link_metrics_tlv_k2_len35, -1},
	{"associated_sta_link_metrics_tlv_k2_len36", "pkt31.pcap", construct_associated_sta_link_metrics_tlv_k2_len36, -1},
	{"associated_sta_link_metrics_tlv_k2_len37", "pkt32.pcap", construct_associated_sta_link_metrics_tlv_k2_len37, -1},
	{"associated_sta_link_metrics_tlv_k2_len38", "pkt33.pcap", construct_associated_sta_link_metrics_tlv_k2_len38, -1},
	{"associated_sta_link_metrics_tlv_k2_len39", "pkt34.pcap", construct_associated_sta_link_metrics_tlv_k2_len39, -1},
	{"associated_sta_link_metrics_tlv_k2_len40", "pkt35.pcap", construct_associated_sta_link_metrics_tlv_k2_len40, -1},
	{"associated_sta_link_metrics_tlv_k2_len41", "pkt36.pcap", construct_associated_sta_link_metrics_tlv_k2_len41, -1},
	{"associated_sta_link_metrics_tlv_k2_len42", "pkt37.pcap", construct_associated_sta_link_metrics_tlv_k2_len42, -1},
	{"associated_sta_link_metrics_tlv_k2_len43", "pkt38.pcap", construct_associated_sta_link_metrics_tlv_k2_len43, -1},
	{"associated_sta_link_metrics_tlv_k2_len44", "pkt39.pcap", construct_associated_sta_link_metrics_tlv_k2_len44, -1},

	// ✅ valid
	{"associated_sta_link_metrics_tlv_k2_len45", "pkt40.pcap", construct_associated_sta_link_metrics_tlv_k2_len45, -1},

	{"associated_sta_link_metrics_tlv_k3_len46", "pkt41.pcap", construct_associated_sta_link_metrics_tlv_k3_len46, -1},
	{"associated_sta_link_metrics_tlv_k3_len47", "pkt42.pcap", construct_associated_sta_link_metrics_tlv_k3_len47, -1},
	{"associated_sta_link_metrics_tlv_k3_len48", "pkt43.pcap", construct_associated_sta_link_metrics_tlv_k3_len48, -1},
	{"associated_sta_link_metrics_tlv_k3_len49", "pkt44.pcap", construct_associated_sta_link_metrics_tlv_k3_len49, -1},
	{"associated_sta_link_metrics_tlv_k3_len50", "pkt45.pcap", construct_associated_sta_link_metrics_tlv_k3_len50, -1},
	{"associated_sta_link_metrics_tlv_k3_len51", "pkt46.pcap", construct_associated_sta_link_metrics_tlv_k3_len51, -1},
	{"associated_sta_link_metrics_tlv_k3_len52", "pkt47.pcap", construct_associated_sta_link_metrics_tlv_k3_len52, -1},
	{"associated_sta_link_metrics_tlv_k3_len53", "pkt48.pcap", construct_associated_sta_link_metrics_tlv_k3_len53, -1},
	{"associated_sta_link_metrics_tlv_k3_len54", "pkt49.pcap", construct_associated_sta_link_metrics_tlv_k3_len54, -1},
	{"associated_sta_link_metrics_tlv_k3_len55", "pkt50.pcap", construct_associated_sta_link_metrics_tlv_k3_len55, -1},
	{"associated_sta_link_metrics_tlv_k3_len56", "pkt51.pcap", construct_associated_sta_link_metrics_tlv_k3_len56, -1},
	{"associated_sta_link_metrics_tlv_k3_len57", "pkt52.pcap", construct_associated_sta_link_metrics_tlv_k3_len57, -1},
	{"associated_sta_link_metrics_tlv_k3_len58", "pkt53.pcap", construct_associated_sta_link_metrics_tlv_k3_len58, -1},
	{"associated_sta_link_metrics_tlv_k3_len59", "pkt54.pcap", construct_associated_sta_link_metrics_tlv_k3_len59, -1},
	{"associated_sta_link_metrics_tlv_k3_len60", "pkt55.pcap", construct_associated_sta_link_metrics_tlv_k3_len60, -1},
	{"associated_sta_link_metrics_tlv_k3_len61", "pkt56.pcap", construct_associated_sta_link_metrics_tlv_k3_len61, -1},
	{"associated_sta_link_metrics_tlv_k3_len62", "pkt57.pcap", construct_associated_sta_link_metrics_tlv_k3_len62, -1},
	{"associated_sta_link_metrics_tlv_k3_len63", "pkt58.pcap", construct_associated_sta_link_metrics_tlv_k3_len63, -1},

	// ✅ VALID CASE (len64)
	{"associated_sta_link_metrics_tlv_k3_len64", "pkt59.pcap", construct_associated_sta_link_metrics_tlv_k3_len64, 0},
#endif	   


#if 1
	//without EOM
	{"associated_sta_ext_link_metrics_tlv_pkt1_j3_e3", "p0.pcap",construct_associated_sta_ext_link_metrics_tlv_pkt1_j3_e3, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len1_oe", "p1.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len1_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len2_oe", "p2.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len2_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len3_oe", "p3.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len3_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len4_oe", "p4.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len4_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len5_oe", "p5.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len5_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len6_oe", "p6.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len6_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_ko_len7_oe", "p7.pcap",construct_associated_sta_ext_link_metrics_tlv_k0_len7_oe, -1},

	{"associated_sta_ext_link_metrics_tlv_k1_len8_oe", "p8.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len8_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len9_oe", "p9.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len9_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len10_oe", "p10.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len10_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len11_oe", "p11.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len11_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len12_oe", "p12.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len12_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len13_oe", "p13.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len13_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len14_oe", "p14.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len14_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len15_oe", "p15.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len15_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len16_oe", "p16.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len16_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len17_oe", "p17.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len17_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len18_oe", "p18.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len18_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len19_oe", "p19.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len19_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len20_oe", "p20.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len20_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len21_oe", "p21.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len21_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len22_oe", "p22.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len22_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len23_oe", "p23.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len23_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len24_oe", "p24.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len24_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len25_oe", "p25.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len25_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len26_oe", "p26.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len26_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len27_oe", "p27.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len27_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len28_oe", "p28.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len28_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len29_oe", "p29.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len29_oe, -1},

	{"associated_sta_ext_link_metrics_tlv_k1_len30_oe", "p30.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len30_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len31_oe", "p31.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len31_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len32_oe", "p32.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len32_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len33_oe", "p33.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len33_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len34_oe", "p34.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len34_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len35_oe", "p35.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len35_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len36_oe", "p36.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len36_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len37_oe", "p37.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len37_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len38_oe", "p38.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len38_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len39_oe", "p39.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len39_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len40_oe", "p40.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len40_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len41_oe", "p41.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len41_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len42_oe", "p42.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len42_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len43_oe", "p43.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len43_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len44_oe", "p44.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len44_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len45_oe", "p45.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len45_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len46_oe", "p46.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len46_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len47_oe", "p47.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len47_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len48_oe", "p48.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len48_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len49_oe", "p49.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len49_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len50_oe", "p50.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len50_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len51_oe", "p51.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len51_oe, -1},

	{"associated_sta_ext_link_metrics_tlv_k3_len52_oe", "p52.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len52_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len53_oe", "p53.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len53_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len54_oe", "p54.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len54_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len55_oe", "p55.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len55_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len56_oe", "p56.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len56_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len57_oe", "p57.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len57_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len58_oe", "p58.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len58_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len59_oe", "p59.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len59_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len60_oe", "p60.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len60_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len61_oe", "p61.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len61_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len62_oe", "p62.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len62_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len63_oe", "p63.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len63_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len64_oe", "p64.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len64_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len65_oe", "p65.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len65_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len66_oe", "p66.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len66_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len67_oe", "p67.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len67_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len68_oe", "p68.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len68_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len69_oe", "p69.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len69_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len70_oe", "p70.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len70_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len71_oe", "p71.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len71_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len72_oe", "p72.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len72_oe, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len73_oe", "p73.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len73_oe, -1},


	//with eom
	{"associated_sta_ext_link_metrics_tlv_j3_len1", "p1.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len1, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len2", "p2.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len2, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len3", "p3.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len3, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len4", "p4.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len4, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len5", "p5.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len5, -1},
	{"associated_sta_ext_link_metrics_tlv_j3_len6", "p6.pcap", construct_associated_sta_ext_link_metrics_tlv_j3_len6, -1},
	{"associated_sta_ext_link_metrics_tlv_ko_len7", "p7.pcap",construct_associated_sta_ext_link_metrics_tlv_k0_len7, 0},
	{"associated_sta_ext_link_metrics_tlv_k1_len8", "p8.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len8, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len9", "p9.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len9, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len10", "p10.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len10, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len11", "p11.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len11, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len12", "p12.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len12, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len13", "p13.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len13, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len14", "p14.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len14, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len15", "p15.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len15, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len16", "p16.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len16, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len17", "p17.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len17, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len18", "p18.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len18, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len19", "p19.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len19, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len20", "p20.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len20, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len21", "p21.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len21, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len22", "p22.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len22, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len23", "p23.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len23, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len24", "p24.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len24, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len25", "p25.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len25, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len26", "p26.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len26, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len27", "p27.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len27, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len28", "p28.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len28, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len29", "p29.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len29, -1},
	{"associated_sta_ext_link_metrics_tlv_k1_len30", "p30.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len30, -1},

	{"associated_sta_ext_link_metrics_tlv_k2_len31", "p31.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len31, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len32", "p32.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len32, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len33", "p33.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len33, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len34", "p34.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len34, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len35", "p35.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len35, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len36", "p36.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len36, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len37", "p37.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len37, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len38", "p38.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len38, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len39", "p39.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len39, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len40", "p40.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len40, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len41", "p41.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len41, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len42", "p42.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len42, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len43", "p43.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len43, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len44", "p44.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len44, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len45", "p45.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len45, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len46", "p46.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len46, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len47", "p47.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len47, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len48", "p48.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len48, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len49", "p49.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len49, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len50", "p50.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len50, -1},
	{"associated_sta_ext_link_metrics_tlv_k2_len51", "p51.pcap", construct_associated_sta_ext_link_metrics_tlv_k2_len51, -1},

	{"associated_sta_ext_link_metrics_tlv_k3_len52", "p52.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len52, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len53", "p53.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len53, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len54", "p54.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len54, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len55", "p55.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len55, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len56", "p56.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len56, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len57", "p57.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len57, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len58", "p58.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len58, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len59", "p59.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len59, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len60", "p60.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len60, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len61", "p61.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len61, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len62", "p62.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len62, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len63", "p63.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len63, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len64", "p64.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len64, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len65", "p65.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len65, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len66", "p66.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len66, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len67", "p67.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len67, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len68", "p68.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len68, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len69", "p69.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len69, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len70", "p70.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len70, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len71", "p71.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len71, -1},
	{"associated_sta_ext_link_metrics_tlv_k3_len72", "p72.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len72, -1},
	{"ap_extended_metrics_tlv_len30", "p91.pcap", construct_ap_extended_metrics_tlv_len30, 0},
	{"radio_metrics_tlv_len10", "p92.pcap", construct_radio_metrics_tlv_len10, 0},
	{"assoc_sta_traffic_stats_tlv_len34", "p93.pcap", construct_assoc_sta_traffic_stats_tlv_len34, 0},

	{"associated_sta_ext_link_metrics_tlv_k3_len73", "p73.pcap", construct_associated_sta_ext_link_metrics_tlv_k3_len73, 0},

	{"associated_sta_ext_link_metrics_tlv_k1_len29_valid", "p75.pcap", construct_associated_sta_ext_link_metrics_tlv_k1_len29_valid, 0},
	
#endif	
	{NULL, NULL, NULL, 0}
};

#if 1
   pkt_test_case_t handle_ap_metrics_response_suite[] = {

   {"handle_bsta_cap_report_pkt1_a_b_c10_d_e",             "pkt1.pcap",  construct_handle_bsta_cap_report_pkt1_a_b_c10_d_e_rf_tlvs,             -1},
   {"handle_bsta_cap_report_pkt2_a_b_c16_d_e",             "pkt2.pcap",  construct_handle_bsta_cap_report_pkt2_a_b_c16_d_e_rf_tlvs,             -1},
   {"handle_bsta_cap_report_pkt4_a_b_c10_e",               "pkt4.pcap",  construct_handle_bsta_cap_report_pkt4_a_b_c10_e_rf_tlvs,               -1},
   {"handle_bsta_cap_report_pkt3_a_b_e",                   "pkt3.pcap",  construct_handle_bsta_cap_report_pkt3_a_b_e_rf_tlvs,                   -1},
   {"handle_bsta_cap_report_pkt5_a_b_c16_e",               "pkt5.pcap",  construct_handle_bsta_cap_report_pkt5_a_b_c16_e_rf_tlvs,               -1},
   {"handle_bsta_cap_report_pkt6_a_b_d_e",                 "pkt6.pcap",  construct_handle_bsta_cap_report_pkt6_a_b_d_e_rf_tlvs,                 -1},
   {"handle_bsta_cap_report_pkt7_a_b_c10_c10_c10_e",       "pkt7.pcap",  construct_handle_bsta_cap_report_pkt7_a_b_c10_c10_c10_e_rf_tlvs,       -1},
   {"handle_bsta_cap_report_pkt8_a_b_c16_c16_c16_c16_e",   "pkt8.pcap",  construct_handle_bsta_cap_report_pkt8_a_b_c16_c16_c16_c16_e_rf_tlvs,   -1},
   {"handle_bsta_cap_report_pkt9_a_b_c10_c16_c16_c10_c10_e","pkt9.pcap", construct_handle_bsta_cap_report_pkt9_a_b_c10_c16_c16_c10_c10_e_rf_tlvs, -1},
   {"handle_bsta_cap_report_pkt10_a_b_c10_c10_d_d_d_e",    "pkt10.pcap", construct_handle_bsta_cap_report_pkt10_a_b_c10_c10_d_d_d_e_rf_tlvs,    -1},
   {"handle_bsta_cap_report_pkt11_a_b_d_d_e",              "pkt11.pcap", construct_handle_bsta_cap_report_pkt11_a_b_d_d_e_rf_tlvs,              -1},
   {"handle_bsta_cap_report_pkt12_a_b_c10_c16_e",          "pkt12.pcap", construct_handle_bsta_cap_report_pkt12_a_b_c10_c16_e_rf_tlvs,          -1},
   {"handle_bsta_cap_report_pkt13_a_b_c16_c10_e",          "pkt13.pcap", construct_handle_bsta_cap_report_pkt13_a_b_c16_c10_e_rf_tlvs,          -1},
   {"handle_bsta_cap_report_pkt14_a_b_c10_c10_c16_e",      "pkt14.pcap", construct_handle_bsta_cap_report_pkt14_a_b_c10_c10_c16_e_rf_tlvs,      -1},
   {"handle_bsta_cap_report_pkt15_a_b_c16_c16_c10_e",      "pkt15.pcap", construct_handle_bsta_cap_report_pkt15_a_b_c16_c16_c10_e_rf_tlvs,      -1},
   {"handle_bsta_cap_report_pkt16_a_b_c10_d_d_e",          "pkt16.pcap", construct_handle_bsta_cap_report_pkt16_a_b_c10_d_d_e_rf_tlvs,          -1},
   {"handle_bsta_cap_report_pkt17_a_b_c16_d_d_e",          "pkt17.pcap", construct_handle_bsta_cap_report_pkt17_a_b_c16_d_d_e_rf_tlvs,          -1},
   {"handle_bsta_cap_report_pkt18_a_b_c10_c10_d_e",        "pkt18.pcap", construct_handle_bsta_cap_report_pkt18_a_b_c10_c10_d_e_rf_tlvs,        -1},
   {"handle_bsta_cap_report_pkt19_a_b_c16_c16_d_e",        "pkt19.pcap", construct_handle_bsta_cap_report_pkt19_a_b_c16_c16_d_e_rf_tlvs,        -1},
   {"handle_bsta_cap_report_pkt20_a_b_c10_c16_d_e",        "pkt20.pcap", construct_handle_bsta_cap_report_pkt20_a_b_c10_c16_d_e_rf_tlvs,        -1},
   {"handle_bsta_cap_report_pkt21_a_b_c16_c10_d_e",        "pkt21.pcap", construct_handle_bsta_cap_report_pkt21_a_b_c16_c10_d_e_rf_tlvs,        -1},
   {"handle_bsta_cap_report_pkt22_a_b_c10_c10_c10_d_e",    "pkt22.pcap", construct_handle_bsta_cap_report_pkt22_a_b_c10_c10_c10_d_e_rf_tlvs,    -1},
   {"handle_bsta_cap_report_pkt23_a_b_c16_c16_c16_e",      "pkt23.pcap", construct_handle_bsta_cap_report_pkt23_a_b_c16_c16_c16_e_rf_tlvs,      -1},
   {"handle_bsta_cap_report_pkt24_a_b_c16_d_c10_e",        "pkt24.pcap", construct_handle_bsta_cap_report_pkt24_a_b_c16_d_c10_e_rf_tlvs,        -1},
   {"handle_bsta_cap_report_pkt25_a_b_d_c10_c16_d_e",      "pkt25.pcap", construct_handle_bsta_cap_report_pkt25_a_b_d_c10_c16_d_e_rf_tlvs,      -1},

   {"handle_bsta_cap_report_pkt1_a_b_c0_e",       "pkt1rb.pcap",  construct_handle_bsta_cap_report_pkt1_a_b_c0_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt2_a_b_c1_e",       "pkt2rb.pcap",  construct_handle_bsta_cap_report_pkt2_a_b_c1_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt3_a_b_c2_e",       "pkt3rb.pcap",  construct_handle_bsta_cap_report_pkt3_a_b_c2_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt4_a_b_c3_e",       "pkt4rb.pcap",  construct_handle_bsta_cap_report_pkt4_a_b_c3_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt5_a_b_c4_e",       "pkt5rb.pcap",  construct_handle_bsta_cap_report_pkt5_a_b_c4_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt6_a_b_c5_e",       "pkt6rb.pcap",  construct_handle_bsta_cap_report_pkt6_a_b_c5_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt7_a_b_c6_e",       "pkt7rb.pcap",  construct_handle_bsta_cap_report_pkt7_a_b_c6_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt8_a_b_c8_e",       "pkt8rb.pcap",  construct_handle_bsta_cap_report_pkt8_a_b_c8_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt9_a_b_c9_e",       "pkt9rb.pcap",  construct_handle_bsta_cap_report_pkt9_a_b_c9_e_rb_tlvs,       -1},
   {"handle_bsta_cap_report_pkt10_a_b_c10_e",     "pkt10rb.pcap", construct_handle_bsta_cap_report_pkt10_a_b_c10_e_rb_tlvs,     -1},
   {"handle_bsta_cap_report_pkt11_a_b_c11_e",     "pkt11rb.pcap", construct_handle_bsta_cap_report_pkt11_a_b_c11_e_rb_tlvs,     -1},
   {"handle_bsta_cap_report_pkt12_a_b_c12_e",     "pkt12rb.pcap", construct_handle_bsta_cap_report_pkt12_a_b_c12_e_rb_tlvs,     -1},
   {"handle_bsta_cap_report_pkt13_a_b_c20_e",     "pkt13rb.pcap", construct_handle_bsta_cap_report_pkt13_a_b_c20_e_rb_tlvs,     -1},
   {"handle_bsta_cap_report_pkt14_a_b_c15_e",     "pkt14rb.pcap", construct_handle_bsta_cap_report_pkt14_a_b_c15_e_rb_tlvs,     -1},
   {"handle_bsta_cap_report_pkt15_a_b_d0_e",      "pkt15rb.pcap", construct_handle_bsta_cap_report_pkt15_a_b_d0_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt16_a_b_d1_e",      "pkt16rb.pcap", construct_handle_bsta_cap_report_pkt16_a_b_d1_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt17_a_b_d2_e",      "pkt17rb.pcap", construct_handle_bsta_cap_report_pkt17_a_b_d2_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt18_a_b_d3_e",      "pkt18rb.pcap", construct_handle_bsta_cap_report_pkt18_a_b_d3_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt19_a_b_d4_e",      "pkt19rb.pcap", construct_handle_bsta_cap_report_pkt19_a_b_d4_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt20_a_b_d5_e",      "pkt20rb.pcap", construct_handle_bsta_cap_report_pkt20_a_b_d5_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt21_a_b_d6_e",      "pkt21rb.pcap", construct_handle_bsta_cap_report_pkt21_a_b_d6_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt22_a_b_d7_e",      "pkt22rb.pcap", construct_handle_bsta_cap_report_pkt22_a_b_d7_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt23_a_b_d8_e",      "pkt23rb.pcap", construct_handle_bsta_cap_report_pkt23_a_b_d8_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt24_a_b_d9_e",      "pkt24rb.pcap", construct_handle_bsta_cap_report_pkt24_a_b_d9_e_rb_tlvs,      -1},
   {"handle_bsta_cap_report_pkt25_a_b_d10_e",     "pkt25rb.pcap", construct_handle_bsta_cap_report_pkt25_a_b_d10_e_rb_tlvs,     -1},
   {"handle_bsta_cap_report_pkt26_a_b_d11_e",     "pkt26rb.pcap", construct_handle_bsta_cap_report_pkt26_a_b_d11_e_rb_tlvs,     -1},
   {"handle_bsta_cap_report_pkt27_a_b_d14_e",     "pkt27rb.pcap", construct_handle_bsta_cap_report_pkt27_a_b_d14_e_rb_tlvs,     -1},
   {"handle_bsta_cap_report_pkt28_a_b_e_len0",    "pkt28rf.pcap", construct_handle_bsta_cap_report_pkt28_a_b_e_rf_len0_tlvs,    -1},
   {"handle_bsta_cap_report_pkt29_a_b_e_len1",    "pkt29rb.pcap", construct_handle_bsta_cap_report_pkt29_a_b_e_rb_len1_tlvs,    -1},
   {"handle_bsta_cap_report_pkt30_a_b_e_len2",    "pkt30rb.pcap", construct_handle_bsta_cap_report_pkt30_a_b_e_rb_len2_tlvs,    -1},
   {"handle_bsta_cap_report_pkt31_a_b_e_len3",    "pkt31rb.pcap", construct_handle_bsta_cap_report_pkt31_a_b_e_rb_len3_tlvs,    -1},
   {"handle_bsta_cap_report_pkt32_a_b_e_len4",    "pkt32rb.pcap", construct_handle_bsta_cap_report_pkt32_a_b_e_rb_len4_tlvs,    -1},
   {"handle_bsta_cap_report_pkt33_a_b_e_len255",  "pkt33rb.pcap", construct_handle_bsta_cap_report_pkt33_a_b_e_rb_len255_tlvs,  -1},
   {"handle_bsta_cap_report_pkt34_a_b_e",         "pkt34rb.pcap", construct_handle_bsta_cap_report_pkt34_a_b_e_rb_tlvs,         -1},
   {"handle_bsta_cap_report_pkt35_a_b_c_len0",    "pkt35rb.pcap", construct_handle_bsta_cap_report_pkt35_a_b_c_len0_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt36_a_b_c_len1",    "pkt36rb.pcap", construct_handle_bsta_cap_report_pkt36_a_b_c_len1_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt37_a_b_c_len2",    "pkt37rb.pcap", construct_handle_bsta_cap_report_pkt37_a_b_c_len2_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt38_a_b_c_len3",    "pkt38rb.pcap", construct_handle_bsta_cap_report_pkt38_a_b_c_len3_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt39_a_b_c_len4",    "pkt39rb.pcap", construct_handle_bsta_cap_report_pkt39_a_b_c_len4_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt40_a_b_c_len255",  "pkt40rb.pcap", construct_handle_bsta_cap_report_pkt40_a_b_c_len255_rb_tlvs,  -1},
   {"handle_bsta_cap_report_pkt41_a_b_c",         "pkt41rb.pcap", construct_handle_bsta_cap_report_pkt41_a_b_c_rb_tlvs,         -1},
   {"handle_bsta_cap_report_pkt42_a_b_d_len0",    "pkt42rb.pcap", construct_handle_bsta_cap_report_pkt42_a_b_d_len0_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt43_a_b_d_len1",    "pkt43rb.pcap", construct_handle_bsta_cap_report_pkt43_a_b_d_len1_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt44_a_b_d_len2",    "pkt44rb.pcap", construct_handle_bsta_cap_report_pkt44_a_b_d_len2_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt45_a_b_d_len3",    "pkt45rb.pcap", construct_handle_bsta_cap_report_pkt45_a_b_d_len3_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt46_a_b_d_len4",    "pkt46rb.pcap", construct_handle_bsta_cap_report_pkt46_a_b_d_len4_rb_tlvs,    -1},
   {"handle_bsta_cap_report_pkt47_a_b_d_len255",  "pkt47rb.pcap", construct_handle_bsta_cap_report_pkt47_a_b_d_len255_rb_tlvs,  -1},
   {"handle_bsta_cap_report_pkt48_a_b_d",         "pkt48rb.pcap", construct_handle_bsta_cap_report_pkt48_a_b_d_rb_tlvs,         -1},
   {"handle_bsta_cap_report_pkt49_a_b_e1",        "pkt49rb.pcap", construct_handle_bsta_cap_report_pkt49_a_b_e1_rb_tlvs,        -1},
   {"handle_bsta_cap_report_pkt50_a_b_c1",        "pkt50rb.pcap", construct_handle_bsta_cap_report_pkt50_a_b_c1_rb_tlvs,        -1},
   {"handle_bsta_cap_report_pkt51_a_b_d1",        "pkt51rb.pcap", construct_handle_bsta_cap_report_pkt51_a_b_d1_rb_tlvs,        -1},

{"get_first_tlv_pkt1_a_b_e_rb_len0",     "pkt1rb.pcap",  construct_get_first_tlv_pkt1_a_b_e_rb_len0_tlvs,    -1},
{"get_first_tlv_pkt2_a_b_e_rb_len1",     "pkt2rb.pcap",  construct_get_first_tlv_pkt2_a_b_e_rb_len1_tlvs,    -1},
{"get_first_tlv_pkt3_a_b_e_rb_len2",     "pkt3rb.pcap",  construct_get_first_tlv_pkt3_a_b_e_rb_len2_tlvs,    -1},
{"get_first_tlv_pkt4_a_b_e_rb_len3",     "pkt4rb.pcap",  construct_get_first_tlv_pkt4_a_b_e_rb_len3_tlvs,    -1},
{"get_first_tlv_pkt5_a_b_e_rb_len4",     "pkt5rb.pcap",  construct_get_first_tlv_pkt5_a_b_e_rb_len4_tlvs,    -1},
{"get_first_tlv_pkt6_a_b_e_rb_len255",   "pkt6rb.pcap",  construct_get_first_tlv_pkt6_a_b_e_rb_len255_tlvs,  -1},
{"get_first_tlv_pkt7_a_b_e_rb",          "pkt7rb.pcap",  construct_get_first_tlv_pkt7_a_b_e_rb_tlvs,         -1},
{"get_first_tlv_pkt8_a_b_c_len0_rb",     "pkt8rb.pcap",  construct_get_first_tlv_pkt8_a_b_c_len0_rb_tlvs,    -1},
{"get_first_tlv_pkt9_a_b_c_len1_rb",     "pkt9rb.pcap",  construct_get_first_tlv_pkt9_a_b_c_len1_rb_tlvs,    -1},
{"get_first_tlv_pkt10_a_b_c_len2_rb",    "pkt10rb.pcap", construct_get_first_tlv_pkt10_a_b_c_len2_rb_tlvs,   -1},
{"get_first_tlv_pkt11_a_b_c_len3_rb",    "pkt11rb.pcap", construct_get_first_tlv_pkt11_a_b_c_len3_rb_tlvs,   -1},
{"get_first_tlv_pkt12_a_b_c_len4_rb",    "pkt12rb.pcap", construct_get_first_tlv_pkt12_a_b_c_len4_rb_tlvs,   -1},
{"get_first_tlv_pkt13_a_b_c_len255_rb",  "pkt13rb.pcap", construct_get_first_tlv_pkt13_a_b_c_len255_rb_tlvs, -1},
{"get_first_tlv_pkt14_a_b_c_rb",         "pkt14rb.pcap", construct_get_first_tlv_pkt14_a_b_c_rb_tlvs,        -1},
{"get_first_tlv_pkt15_a_b_d_len0_rb",    "pkt15rb.pcap", construct_get_first_tlv_pkt15_a_b_d_len0_rb_tlvs,   -1},
{"get_first_tlv_pkt16_a_b_d_len1_rb",    "pkt16rb.pcap", construct_get_first_tlv_pkt16_a_b_d_len1_rb_tlvs,   -1},
{"get_first_tlv_pkt17_a_b_d_len2_rb",    "pkt17rb.pcap", construct_get_first_tlv_pkt17_a_b_d_len2_rb_tlvs,   -1},
{"get_first_tlv_pkt18_a_b_d_len3_rb",    "pkt18rb.pcap", construct_get_first_tlv_pkt18_a_b_d_len3_rb_tlvs,   -1},
{"get_first_tlv_pkt19_a_b_d_len4_rb",    "pkt19rb.pcap", construct_get_first_tlv_pkt19_a_b_d_len4_rb_tlvs,   -1},
{"get_first_tlv_pkt20_a_b_d_len255_rb",  "pkt20rb.pcap", construct_get_first_tlv_pkt20_a_b_d_len255_rb_tlvs, -1},
{"get_first_tlv_pkt21_a_b_d_rb",         "pkt21rb.pcap", construct_get_first_tlv_pkt21_a_b_d_rb_tlvs,        -1},
{"get_first_tlv_pkt22_a_b_e1_rb",        "pkt22rb.pcap", construct_get_first_tlv_pkt22_a_b_e1_rb_tlvs,       -1},
{"get_first_tlv_pkt23_a_b_c1_rb",        "pkt23rb.pcap", construct_get_first_tlv_pkt23_a_b_c1_rb_tlvs,       -1},
{"get_first_tlv_pkt24_a_b_d1_rb",        "pkt24rb.pcap", construct_get_first_tlv_pkt24_a_b_d1_rb_tlvs,       -1},
{"get_first_tlv_pkt25_a_b_c_len0_e3_rb", "pkt25rb.pcap", construct_get_first_tlv_pkt25_a_b_c_len0_e3_rb_tlvs, -1},
{"get_first_tlv_pkt26_a_b_c_len1_e3_rb", "pkt26rb.pcap", construct_get_first_tlv_pkt26_a_b_c_len1_e3_rb_tlvs, -1},
{"get_first_tlv_pkt27_a_b_c_len2_e_rb",  "pkt27rb.pcap", construct_get_first_tlv_pkt27_a_b_c_len2_e_rb_tlvs,  -1},
{"get_first_tlv_pkt28_a_b_c_len3_e3_rb", "pkt28rb.pcap", construct_get_first_tlv_pkt28_a_b_c_len3_e3_rb_tlvs, -1},
{"get_first_tlv_pkt29_a_b_c_len4_e3_rb", "pkt29rb.pcap", construct_get_first_tlv_pkt29_a_b_c_len4_e3_rb_tlvs, -1},
{"get_first_tlv_pkt30_a_b_c_len5_e3_rb", "pkt30rb.pcap", construct_get_first_tlv_pkt30_a_b_c_len5_e3_rb_tlvs, -1},
{"get_first_tlv_pkt31_a_b_c_len6_e3_rb", "pkt31rb.pcap", construct_get_first_tlv_pkt31_a_b_c_len6_e3_rb_tlvs, -1},
{"get_first_tlv_pkt32_a_b_c_len7_e3_rb", "pkt32rb.pcap", construct_get_first_tlv_pkt32_a_b_c_len7_e3_rb_tlvs, -1},
{"get_first_tlv_pkt33_a_b_c_len8_e3_rb", "pkt33rb.pcap", construct_get_first_tlv_pkt33_a_b_c_len8_e3_rb_tlvs, -1},
{"get_first_tlv_pkt34_a_b_c_len0_e2_rb", "pkt34rb.pcap", construct_get_first_tlv_pkt34_a_b_c_len0_e2_rb_tlvs, -1},
{"get_first_tlv_pkt35_a_b_c_len1_e2_rb", "pkt35rb.pcap", construct_get_first_tlv_pkt35_a_b_c_len1_e2_rb_tlvs, -1},
{"get_first_tlv_pkt36_a_b_c_len2_e2_rb", "pkt36rb.pcap", construct_get_first_tlv_pkt36_a_b_c_len2_e2_rb_tlvs, -1},
{"get_first_tlv_pkt37_a_b_c_len3_e2_rb", "pkt37rb.pcap", construct_get_first_tlv_pkt37_a_b_c_len3_e2_rb_tlvs, -1},
{"get_first_tlv_pkt38_a_b_c_len4_e2_rb", "pkt38rb.pcap", construct_get_first_tlv_pkt38_a_b_c_len4_e2_rb_tlvs, -1},
{"get_first_tlv_pkt39_a_b_c_len5_e2_rb", "pkt39rb.pcap", construct_get_first_tlv_pkt39_a_b_c_len5_e2_rb_tlvs, -1},
{"get_first_tlv_pkt40_a_b_c_len6_e2_rb", "pkt40rb.pcap", construct_get_first_tlv_pkt40_a_b_c_len6_e2_rb_tlvs, -1},
{"get_first_tlv_pkt41_a_b_c_len7_e2_rb", "pkt41rb.pcap", construct_get_first_tlv_pkt41_a_b_c_len7_e2_rb_tlvs, -1},
{"get_first_tlv_pkt42_a_b_c_len8_e2_rb", "pkt42rb.pcap", construct_get_first_tlv_pkt42_a_b_c_len8_e2_rb_tlvs, -1},
{"get_first_tlv_pkt43_a_b_c_len0_e1_rb", "pkt43rb.pcap", construct_get_first_tlv_pkt43_a_b_c_len0_e1_rb_tlvs, -1},
{"get_first_tlv_pkt44_a_b_c_len1_e1_rb", "pkt44rb.pcap", construct_get_first_tlv_pkt44_a_b_c_len1_e1_rb_tlvs, -1},
{"get_first_tlv_pkt45_a_b_c_len2_e1_rb", "pkt45rb.pcap", construct_get_first_tlv_pkt45_a_b_c_len2_e1_rb_tlvs, -1},
{"get_first_tlv_pkt46_a_b_c_len3_e1_rb", "pkt46rb.pcap", construct_get_first_tlv_pkt46_a_b_c_len3_e1_rb_tlvs, -1},
{"get_first_tlv_pkt47_a_b_c_len4_e1_rb", "pkt47rb.pcap", construct_get_first_tlv_pkt47_a_b_c_len4_e1_rb_tlvs, -1},
{"get_first_tlv_pkt48_a_b_c_len5_e1_rb", "pkt48rb.pcap", construct_get_first_tlv_pkt48_a_b_c_len5_e1_rb_tlvs, -1},
{"get_first_tlv_pkt49_a_b_c_len6_e1_rb", "pkt49rb.pcap", construct_get_first_tlv_pkt49_a_b_c_len6_e1_rb_tlvs, -1},
{"get_first_tlv_pkt50_a_b_c_len7_e1_rb", "pkt50rb.pcap", construct_get_first_tlv_pkt50_a_b_c_len7_e1_rb_tlvs, -1},
{"get_first_tlv_pkt51_a_b_c_len8_e1_rb", "pkt51rb.pcap", construct_get_first_tlv_pkt51_a_b_c_len8_e1_rb_tlvs, -1},

{"get_next_tlv_pkt0_a_b_e_rb_len0",      "pkt0rb.pcap",  construct_get_next_tlv_pkt0_a_b_e_rb_len0_tlvs,    -1},
{"get_next_tlv_pkt1_a_b_e_rb_len1",      "pkt1rb.pcap",  construct_get_next_tlv_pkt1_a_b_e_rb_len1_tlvs,    -1},
{"get_next_tlv_pkt2_a_b_e_rb_len2",      "pkt2rb.pcap",  construct_get_next_tlv_pkt2_a_b_e_rb_len2_tlvs,    -1},
{"get_next_tlv_pkt3_a_b_e_rb_len3",      "pkt3rb.pcap",  construct_get_next_tlv_pkt3_a_b_e_rb_len3_tlvs,    -1},
{"get_next_tlv_pkt4_a_b_e_rb_len4",      "pkt4rb.pcap",  construct_get_next_tlv_pkt4_a_b_e_rb_len4_tlvs,    -1},
{"get_next_tlv_pkt5_a_b_e_rb_len255",    "pkt5rb.pcap",  construct_get_next_tlv_pkt5_a_b_e_rb_len255_tlvs,  -1},
{"get_next_tlv_pkt6_a_b_e_rb",           "pkt6rb.pcap",  construct_get_next_tlv_pkt6_a_b_e_rb_tlvs,         -1},
{"get_next_tlv_pkt7_a_b_c_len0_rb",      "pkt7rb.pcap",  construct_get_next_tlv_pkt7_a_b_c_len0_rb_tlvs,    -1},
{"get_next_tlv_pkt8_a_b_c_len1_rb",      "pkt8rb.pcap",  construct_get_next_tlv_pkt8_a_b_c_len1_rb_tlvs,    -1},
{"get_next_tlv_pkt9_a_b_c_len2_rb",      "pkt9rb.pcap",  construct_get_next_tlv_pkt9_a_b_c_len2_rb_tlvs,    -1},
{"get_next_tlv_pkt10_a_b_c_len3_rb",     "pkt10rb.pcap", construct_get_next_tlv_pkt10_a_b_c_len3_rb_tlvs,   -1},
{"get_next_tlv_pkt11_a_b_c_len4_rb",     "pkt11rb.pcap", construct_get_next_tlv_pkt11_a_b_c_len4_rb_tlvs,   -1},
{"get_next_tlv_pkt12_a_b_c_len255_rb",   "pkt12rb.pcap", construct_get_next_tlv_pkt12_a_b_c_len255_rb_tlvs, -1},
{"get_next_tlv_pkt13_a_b_c_rb",          "pkt13rb.pcap", construct_get_next_tlv_pkt13_a_b_c_rb_tlvs,        -1},
{"get_next_tlv_pkt14_a_b_d_len0_rb",     "pkt14rb.pcap", construct_get_next_tlv_pkt14_a_b_d_len0_rb_tlvs,   -1},
{"get_next_tlv_pkt15_a_b_d_len1_rb",     "pkt15rb.pcap", construct_get_next_tlv_pkt15_a_b_d_len1_rb_tlvs,   -1},
{"get_next_tlv_pkt16_a_b_d_len2_rb",     "pkt16rb.pcap", construct_get_next_tlv_pkt16_a_b_d_len2_rb_tlvs,   -1},
{"get_next_tlv_pkt17_a_b_d_len3_rb",     "pkt17rb.pcap", construct_get_next_tlv_pkt17_a_b_d_len3_rb_tlvs,   -1},
{"get_next_tlv_pkt18_a_b_d_len4_rb",     "pkt18rb.pcap", construct_get_next_tlv_pkt18_a_b_d_len4_rb_tlvs,   -1},
{"get_next_tlv_pkt19_a_b_d_len255_rb",   "pkt19rb.pcap", construct_get_next_tlv_pkt19_a_b_d_len255_rb_tlvs, -1},
{"get_next_tlv_pkt20_a_b_d_rb",          "pkt20rb.pcap", construct_get_next_tlv_pkt20_a_b_d_rb_tlvs,        -1},
{"get_next_tlv_pkt21_a_b_e1_rb",         "pkt21rb.pcap", construct_get_next_tlv_pkt21_a_b_e1_rb_tlvs,       -1},
{"get_next_tlv_pkt22_a_b_c1_rb",         "pkt22rb.pcap", construct_get_next_tlv_pkt22_a_b_c1_rb_tlvs,       -1},
{"get_next_tlv_pkt23_a_b_d1_rb",         "pkt23rb.pcap", construct_get_next_tlv_pkt23_a_b_d1_rb_tlvs,       -1},
{"get_next_tlv_pkt24_a_b_c_len0_e3_rb",  "pkt24rb.pcap", construct_get_next_tlv_pkt24_a_b_c_len0_e3_rb_tlvs, -1},
{"get_next_tlv_pkt25_a_b_c_len1_e3_rb",  "pkt25rb.pcap", construct_get_next_tlv_pkt25_a_b_c_len1_e3_rb_tlvs, -1},
{"get_next_tlv_pkt26_a_b_c_len2_e_rb",   "pkt26rb.pcap", construct_get_next_tlv_pkt26_a_b_c_len2_e_rb_tlvs,  -1},
{"get_next_tlv_pkt27_a_b_c_len3_e3_rb",  "pkt27rb.pcap", construct_get_next_tlv_pkt27_a_b_c_len3_e3_rb_tlvs, -1},
{"get_next_tlv_pkt28_a_b_c_len4_e3_rb",  "pkt28rb.pcap", construct_get_next_tlv_pkt28_a_b_c_len4_e3_rb_tlvs, -1},
{"get_next_tlv_pkt29_a_b_c_len5_e3_rb",  "pkt29rb.pcap", construct_get_next_tlv_pkt29_a_b_c_len5_e3_rb_tlvs, -1},
{"get_next_tlv_pkt30_a_b_c_len6_e3_rb",  "pkt30rb.pcap", construct_get_next_tlv_pkt30_a_b_c_len6_e3_rb_tlvs, -1},
{"get_next_tlv_pkt31_a_b_c_len7_e3_rb",  "pkt31rb.pcap", construct_get_next_tlv_pkt31_a_b_c_len7_e3_rb_tlvs, -1},
{"get_next_tlv_pkt32_a_b_c_len8_e3_rb",  "pkt32rb.pcap", construct_get_next_tlv_pkt32_a_b_c_len8_e3_rb_tlvs, -1},
{"get_next_tlv_pkt33_a_b_c_len0_e2_rb",  "pkt33rb.pcap", construct_get_next_tlv_pkt33_a_b_c_len0_e2_rb_tlvs, -1},
{"get_next_tlv_pkt34_a_b_c_len1_e2_rb",  "pkt34rb.pcap", construct_get_next_tlv_pkt34_a_b_c_len1_e2_rb_tlvs, -1},
{"get_next_tlv_pkt35_a_b_c_len2_e2_rb",  "pkt35rb.pcap", construct_get_next_tlv_pkt35_a_b_c_len2_e2_rb_tlvs, -1},
{"get_next_tlv_pkt36_a_b_c_len3_e2_rb",  "pkt36rb.pcap", construct_get_next_tlv_pkt36_a_b_c_len3_e2_rb_tlvs, -1},
{"get_next_tlv_pkt37_a_b_c_len4_e2_rb",  "pkt37rb.pcap", construct_get_next_tlv_pkt37_a_b_c_len4_e2_rb_tlvs, -1},
{"get_next_tlv_pkt38_a_b_c_len5_e2_rb",  "pkt38rb.pcap", construct_get_next_tlv_pkt38_a_b_c_len5_e2_rb_tlvs, -1},
{"get_next_tlv_pkt39_a_b_c_len6_e2_rb",  "pkt39rb.pcap", construct_get_next_tlv_pkt39_a_b_c_len6_e2_rb_tlvs, -1},
{"get_next_tlv_pkt40_a_b_c_len7_e2_rb",  "pkt40rb.pcap", construct_get_next_tlv_pkt40_a_b_c_len7_e2_rb_tlvs, -1},
{"get_next_tlv_pkt41_a_b_c_len8_e2_rb",  "pkt41rb.pcap", construct_get_next_tlv_pkt41_a_b_c_len8_e2_rb_tlvs, -1},
{"get_next_tlv_pkt42_a_b_c_len0_e1_rb",  "pkt42rb.pcap", construct_get_next_tlv_pkt42_a_b_c_len0_e1_rb_tlvs, -1},
{"get_next_tlv_pkt43_a_b_c_len1_e1_rb",  "pkt43rb.pcap", construct_get_next_tlv_pkt43_a_b_c_len1_e1_rb_tlvs, -1},
{"get_next_tlv_pkt44_a_b_c_len2_e1_rb",  "pkt44rb.pcap", construct_get_next_tlv_pkt44_a_b_c_len2_e1_rb_tlvs, -1},
{"get_next_tlv_pkt45_a_b_c_len3_e1_rb",  "pkt45rb.pcap", construct_get_next_tlv_pkt45_a_b_c_len3_e1_rb_tlvs, -1},
{"get_next_tlv_pkt46_a_b_c_len4_e1_rb",  "pkt46rb.pcap", construct_get_next_tlv_pkt46_a_b_c_len4_e1_rb_tlvs, -1},
{"get_next_tlv_pkt47_a_b_c_len5_e1_rb",  "pkt47rb.pcap", construct_get_next_tlv_pkt47_a_b_c_len5_e1_rb_tlvs, -1},
{"get_next_tlv_pkt48_a_b_c_len6_e1_rb",  "pkt48rb.pcap", construct_get_next_tlv_pkt48_a_b_c_len6_e1_rb_tlvs, -1},
{"get_next_tlv_pkt49_a_b_c_len7_e1_rb",  "pkt49rb.pcap", construct_get_next_tlv_pkt49_a_b_c_len7_e1_rb_tlvs, -1},
{"get_next_tlv_pkt50_a_b_c_len8_e1_rb",  "pkt50rb.pcap", construct_get_next_tlv_pkt50_a_b_c_len8_e1_rb_tlvs, -1},

{NULL, NULL, NULL, 0}
};
#endif
