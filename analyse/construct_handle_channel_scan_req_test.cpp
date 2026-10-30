#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void construct_handle_channel_scan_req_pkt1_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // Fresh Scan = 1, Reserved = 0
        *ptr++ = 0x80;

        // r = 1
        *ptr++ = 0x01;

        // RUID = 00:11:22:33:44:55
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt2_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // Fresh Scan = 0, Reserved = 0
        *ptr++ = 0x00;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt3_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(16);
        ptr += 2;

        // Fresh Scan = 1, Reserved = 0
        *ptr++ = 0x80;

        // r = 2
        *ptr++ = 0x02;

        // RUID-1
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

        // RUID-2
        *ptr++ = 0x66;
        *ptr++ = 0x77;
        *ptr++ = 0x88;
        *ptr++ = 0x99;
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt4_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // Fresh Scan = 0, Reserved = 0
        *ptr++ = 0x00;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x10;
        *ptr++ = 0x20;
        *ptr++ = 0x30;
        *ptr++ = 0x40;
        *ptr++ = 0x50;
        *ptr++ = 0x60;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt5_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 10000000 -> bit 7 = 1, bits 6-0 = 0
        *ptr++ = 0x80;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;
        *ptr++ = 0xFF;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt6_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 00000001 -> Fresh Scan = 0, reserved bit 0 = 1
        *ptr++ = 0x01;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt7_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 01000000 -> reserved bit 6 = 1
        *ptr++ = 0x40;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt8_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // Fresh Scan = 0
        *ptr++ = 0x00;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 1 -> INVALID when Fresh Scan = 0
        *ptr++ = 0x01;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt9_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(12);
        ptr += 2;

        // Fresh Scan = 0
        *ptr++ = 0x00;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

        // INVALID: following fields must be omitted
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;
	
	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


void construct_handle_channel_scan_req_pkt10_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 10000001 -> Fresh Scan = 1 + reserved bit 0 = 1
        *ptr++ = 0x81;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;
        *ptr++ = 0xFF;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

//Reserved bits 6–0 validation

/* ============================================================
 * RESERVED BITS 6-0 : RULE FOLLOW (RF)
 * ============================================================ */

/* RF-01: Fresh Scan = 1, Reserved bits = 0 */
void construct_handle_channel_scan_req_pkt11_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // Bit 7 = 1, Reserved bits 6-0 = 0
        *ptr++ = 0x80;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RF-02: Fresh Scan = 0, Reserved bits = 0 */
void construct_handle_channel_scan_req_pkt12_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // Bit 7 = 0, Reserved bits 6-0 = 0
        *ptr++ = 0x00;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x10;
        *ptr++ = 0x20;
        *ptr++ = 0x30;
        *ptr++ = 0x40;
        *ptr++ = 0x50;
        *ptr++ = 0x60;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RF-03: Fresh Scan = 1, Reserved bits = 0, r = 2 */
void construct_handle_channel_scan_req_pkt13_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(16);
        ptr += 2;

        // Bit 7 = 1, Reserved bits 6-0 = 0
        *ptr++ = 0x80;

        // r = 2
        *ptr++ = 0x02;

        // RUID-1
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

        // RUID-2
        *ptr++ = 0x66;
        *ptr++ = 0x77;
        *ptr++ = 0x88;
        *ptr++ = 0x99;
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RF-04: Fresh Scan = 0, Reserved bits = 0 */
void construct_handle_channel_scan_req_pkt14_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // All Reserved bits = 0
        *ptr++ = 0x00;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;
        *ptr++ = 0xFF;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RF-05: Fresh Scan = 1, Reserved bits = 0 */
void construct_handle_channel_scan_req_pkt15_rf_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 10000000 -> Reserved bits 6-0 are all zero
        *ptr++ = 0x80;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x12;
        *ptr++ = 0x34;
        *ptr++ = 0x56;
        *ptr++ = 0x78;
        *ptr++ = 0x9A;
        *ptr++ = 0xBC;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* ============================================================
 * RESERVED BITS 6-0 : RULE BREAK (RB)
 * ============================================================ */

/* RB-01: Reserved bit 0 = 1 (0x01) */
void construct_handle_channel_scan_req_pkt16_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 00000001 -> Reserved bit 0 = 1
        *ptr++ = 0x01;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RB-02: Reserved bit 1 = 1 (0x02) */
void construct_handle_channel_scan_req_pkt17_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 00000010 -> Reserved bit 1 = 1
        *ptr++ = 0x02;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x10;
        *ptr++ = 0x20;
        *ptr++ = 0x30;
        *ptr++ = 0x40;
        *ptr++ = 0x50;
        *ptr++ = 0x60;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RB-03: Reserved bit 2 = 1 (0x04) */
void construct_handle_channel_scan_req_pkt18_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 00000100 -> Reserved bit 2 = 1
        *ptr++ = 0x04;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;
        *ptr++ = 0xFF;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RB-04: Reserved bit 6 = 1 (0x40) */
void construct_handle_channel_scan_req_pkt19_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 01000000 -> Reserved bit 6 = 1
        *ptr++ = 0x40;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x12;
        *ptr++ = 0x34;
        *ptr++ = 0x56;
        *ptr++ = 0x78;
        *ptr++ = 0x9A;
        *ptr++ = 0xBC;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RB-05: All Reserved bits 6-0 = 1 (0x7F) */
void construct_handle_channel_scan_req_pkt20_rb_tlvs(void)
{
        // ---- Channel Scan Request TLV
        *ptr++ = 0xA6;

        *(uint16_t*)ptr = htons(9);
        ptr += 2;

        // 01111111 -> All Reserved bits 6-0 = 1
        *ptr++ = 0x7F;

        // r = 1
        *ptr++ = 0x01;

        // RUID
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // m = 0
        *ptr++ = 0x00;

	 // ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

/* ============================================================
 * R-01 : r = 1
 * One complete radio structure
 * RF
 * ============================================================ */
void construct_handle_channel_scan_req_pkt21_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80; // Fresh Scan = 1
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1
        *ptr++ = 0x51; // Operating Class
        *ptr++ = 0x01; // k = 1
        *ptr++ = 0x24; // Channel

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-02 : r = 2
 * Two complete radio structures
 * RF
 * ============================================================ */
void construct_handle_channel_scan_req_pkt22_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(26); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x02;

        uint8_t ruid1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid1, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        uint8_t ruid2[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        memcpy(ptr, ruid2, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x73;
        *ptr++ = 0x01;
        *ptr++ = 0x95;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-03 : r = 3
 * Three complete radio structures
 * RF
 * ============================================================ */
void construct_handle_channel_scan_req_pkt23_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(39); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x03;

        uint8_t ruid1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid1, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        uint8_t ruid2[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        memcpy(ptr, ruid2, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x73;
        *ptr++ = 0x01;
        *ptr++ = 0x95;

        uint8_t ruid3[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid3, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x06;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-04 : r = 4
 * Four complete radio structures
 * RF
 * ============================================================ */
void construct_handle_channel_scan_req_pkt24_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(52); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x04;

        uint8_t ruid1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid1, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        uint8_t ruid2[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        memcpy(ptr, ruid2, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x73;
        *ptr++ = 0x01;
        *ptr++ = 0x95;

        uint8_t ruid3[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid3, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x06;

        uint8_t ruid4[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid4, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x73;
        *ptr++ = 0x01;
        *ptr++ = 0x11;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-05 : r = 5
 * Five complete radio structures
 * RF
 * ============================================================ */
void construct_handle_channel_scan_req_pkt25_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(65); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x05;

        uint8_t ruid1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid1, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x51; *ptr++ = 0x01; *ptr++ = 0x24;

        uint8_t ruid2[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        memcpy(ptr, ruid2, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x73; *ptr++ = 0x01; *ptr++ = 0x95;

        uint8_t ruid3[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid3, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x51; *ptr++ = 0x01; *ptr++ = 0x06;

        uint8_t ruid4[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid4, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x73; *ptr++ = 0x01; *ptr++ = 0x11;

        uint8_t ruid5[6] = {0x31,0x42,0x53,0x64,0x75,0x86};
        memcpy(ptr, ruid5, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x51; *ptr++ = 0x01; *ptr++ = 0x0B;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-04 : r = 2 but only ONE complete radio
 * RB
 * ============================================================ */
void construct_handle_channel_scan_req_pkt26_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x02; // r = 2

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

	// Second radio missing
// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-05 : r = 3, second radio truncated
 * RB
 * ============================================================ */
void construct_handle_channel_scan_req_pkt27_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(22); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x03;

        uint8_t ruid1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid1, 6); ptr += 6;
        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        // Second RUID truncated
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-06 : r = 4, only TWO complete radios
 * RB
 * ============================================================ */
void construct_handle_channel_scan_req_pkt28_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(26); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x04;

        uint8_t ruid1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid1, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x51; *ptr++ = 0x01; *ptr++ = 0x24;

        uint8_t ruid2[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        memcpy(ptr, ruid2, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x73; *ptr++ = 0x01; *ptr++ = 0x95;

        // Radio 3 and 4 missing
	
	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-07 : r = 3, third radio RUID truncated
 * RB
 * ============================================================ */
void construct_handle_channel_scan_req_pkt29_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(35); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x03;

        uint8_t ruid1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid1, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x51; *ptr++ = 0x01; *ptr++ = 0x24;

        uint8_t ruid2[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        memcpy(ptr, ruid2, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x73; *ptr++ = 0x01; *ptr++ = 0x95;

        // Third RUID only partially present
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* ============================================================
 * R-08 : r = 5, four complete radios, fifth missing
 * RB
 * ============================================================ */
void construct_handle_channel_scan_req_pkt30_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(52); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x05;

        uint8_t ruid1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid1, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x51; *ptr++ = 0x01; *ptr++ = 0x24;

        uint8_t ruid2[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        memcpy(ptr, ruid2, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x73; *ptr++ = 0x01; *ptr++ = 0x95;

        uint8_t ruid3[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid3, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x51; *ptr++ = 0x01; *ptr++ = 0x06;

        uint8_t ruid4[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid4, 6); ptr += 6;
        *ptr++ = 0x01; *ptr++ = 0x73; *ptr++ = 0x01; *ptr++ = 0x11;

        // Fifth radio completely missing
	
	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}

/* ============================================================
 * 6-BYTE RUID PARSING : RULE FOLLOW (RF)
 * ============================================================ */

/* RUID-01: Exactly 6-byte RUID */
void construct_handle_channel_scan_req_pkt31_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* RUID-02: RUID = 00:11:22:33:44:55 */
void construct_handle_channel_scan_req_pkt32_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* RUID-03: RUID = FF:FF:FF:FF:FF:FF */
void construct_handle_channel_scan_req_pkt33_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

	// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* RUID-04: RUID = 01:02:03:04:05:06 */
void construct_handle_channel_scan_req_pkt34_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x01,0x02,0x03,0x04,0x05,0x06};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x73;
        *ptr++ = 0x01;
	*ptr++ = 0x95;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;

}


/* RUID-05: RUID = AA:BB:CC:DD:EE:FF */
void construct_handle_channel_scan_req_pkt35_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x06;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* ============================================================
 * 6-BYTE RUID PARSING : RULE BREAK (RB)
 * ============================================================ */

/* RUID-04: Only 5 RUID bytes available */
void construct_handle_channel_scan_req_pkt36_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        // Only 5 RUID bytes
        uint8_t ruid[5] = {0x00,0x11,0x22,0x33,0x44};
        memcpy(ptr, ruid, 5); ptr += 5;

        // RUID is incomplete
// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RUID-05: Only 1 RUID byte available */
void construct_handle_channel_scan_req_pkt37_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(8); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        // Only 1 RUID byte
        *ptr++ = 0x00;

        // Remaining 5 RUID bytes missing
// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RUID-RB: 5-byte RUID followed by incomplete next field */
void construct_handle_channel_scan_req_pkt38_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        // Only 5 RUID bytes
        uint8_t ruid[5] = {0x10,0x20,0x30,0x40,0x50};
        memcpy(ptr, ruid, 5); ptr += 5;

        // Incomplete RUID / no valid following field
        *ptr++ = 0x01;
// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RUID-RB: RUID truncated to 5 bytes */
void construct_handle_channel_scan_req_pkt39_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        // 5 bytes instead of required 6
        uint8_t ruid[5] = {0xAA,0xBB,0xCC,0xDD,0xEE};
        memcpy(ptr, ruid, 5); ptr += 5;

        // Missing 6th RUID byte
// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* RUID-RB: Only first RUID byte present */
void construct_handle_channel_scan_req_pkt40_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(8); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        // Only first RUID byte present
        *ptr++ = 0xFF;

        // Remaining 5 RUID bytes missing
// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

/* ============================================================
 * FRESH SCAN = 0 => m = 0
 * RULE FOLLOW (RF)
 * ============================================================ */

/* M-01: Fresh Scan = 0, m = 0, following fields omitted */
void construct_handle_channel_scan_req_pkt41_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(9); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x00; // m = 0

        // Following fields omitted

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* M-02 RF: Fresh Scan = 0, m = 0, no operating class */
void construct_handle_channel_scan_req_pkt42_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(9); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x00; // m = 0

        // Operating Class omitted

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* M-03 RF: Fresh Scan = 0, m = 0, no channel list */
void construct_handle_channel_scan_req_pkt43_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(9); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x00; // m = 0

        // Channel List omitted

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* M-04 RF: Fresh Scan = 0, m = 0 */
void construct_handle_channel_scan_req_pkt44_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(9); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x00; // m = 0

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* M-05 RF: Fresh Scan = 0, m = 0, all following fields omitted */
void construct_handle_channel_scan_req_pkt45_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(9); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x00; // m = 0

        // All following fields omitted

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* ============================================================
 * FRESH SCAN = 0 => m MUST BE 0
 * RULE BREAK (RB)
 * ============================================================ */

/* M-02: Fresh Scan = 0, m = 1, Operating Class present */
void construct_handle_channel_scan_req_pkt46_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1 -> INVALID

        *ptr++ = 0x51; // Operating Class
        *ptr++ = 0x01;
        *ptr++ = 0x24;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* M-03: Fresh Scan = 0, m = 2, two operating classes */
void construct_handle_channel_scan_req_pkt47_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(17); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x02; // m = 2 -> INVALID

        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        *ptr++ = 0x73;
        *ptr++ = 0x01;
        *ptr++ = 0x95;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* M-04: Fresh Scan = 0, m = 0, but extra Operating Class bytes */
void construct_handle_channel_scan_req_pkt48_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x00; // m = 0

        // Extra Operating Class data -> INVALID
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* M-05: Fresh Scan = 0, m = 1, Channel List present */
void construct_handle_channel_scan_req_pkt49_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1 -> INVALID

        // Channel List present
        *ptr++ = 0x01;
        *ptr++ = 0x24;
        *ptr++ = 0x01;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* M-04: Fresh Scan = 0, m = 0, extra trailing data */
void construct_handle_channel_scan_req_pkt50_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        *ptr++ = 0x00; // Fresh Scan = 0
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x00; // m = 0

        // Following field must be omitted -> INVALID
        *ptr++ = 0x73;
        *ptr++ = 0x01;
        *ptr++ = 0x95;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

/* ============================================================
 * OPERATING CLASS / CHANNEL LIST
 * RULE FOLLOW (RF)
 * ============================================================ */

/* OP-01: Operating Class + k=1 + 1 channel */
void construct_handle_channel_scan_req_pkt51_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80; // Fresh Scan = 1
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1
        *ptr++ = 0x51; // Operating Class
        *ptr++ = 0x01; // k = 1
        *ptr++ = 0x24; // Channel

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* OP-02: Operating Class + k=2 + 2 channels */
void construct_handle_channel_scan_req_pkt52_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(14); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1
        *ptr++ = 0x51; // Operating Class
        *ptr++ = 0x02; // k = 2
        *ptr++ = 0x24;
        *ptr++ = 0x36;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* OP-03 RF: Operating Class + k=0, no Channel List */
void construct_handle_channel_scan_req_pkt53_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(11); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1
        *ptr++ = 0x51; // Operating Class
        *ptr++ = 0x00; // k = 0

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* OP-04 RF: Different valid Operating Class + k=1 */
void construct_handle_channel_scan_req_pkt54_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x73;
        *ptr++ = 0x01;
        *ptr++ = 0x95;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* OP-05 RF: k=0, Channel List omitted */
void construct_handle_channel_scan_req_pkt55_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(11); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x00;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* ============================================================
 * OPERATING CLASS / CHANNEL LIST
 * RULE BREAK (RB)
 * ============================================================ */

/* OP-03: k=2, but only 1 channel byte available */
void construct_handle_channel_scan_req_pkt56_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1
        *ptr++ = 0x51; // Operating Class
        *ptr++ = 0x02; // k = 2

        *ptr++ = 0x24; // Only 1 channel -> INVALID

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* OP-04: Operating Class present, k byte missing */
void construct_handle_channel_scan_req_pkt57_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(10); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1
        *ptr++ = 0x51; // Operating Class

        // k byte missing -> INVALID

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* OP-RB: k=3, only 2 channel bytes */
void construct_handle_channel_scan_req_pkt58_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(14); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x03; // k = 3

        *ptr++ = 0x24;
        *ptr++ = 0x36; // Only 2 channels -> INVALID

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}



/* OP-RB: k=1, Channel List missing */
void construct_handle_channel_scan_req_pkt59_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x73;
        *ptr++ = 0x01; // k = 1

        // Channel byte missing -> INVALID

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* OP-RB: k=2, no channel bytes */
void construct_handle_channel_scan_req_pkt60_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(12); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x02; // k = 2

        // Both channel bytes missing -> INVALID

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

/* ============================================================
 * EXACT PAYLOAD CONSUMPTION / TRAILING DATA
 * RULE FOLLOW (RF)
 * ============================================================ */

/* TRAIL-01: Valid TLV with exactly expected payload length */
void construct_handle_channel_scan_req_pkt61_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80; // Fresh Scan = 1
        *ptr++ = 0x01; // r = 1

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01; // m = 1
        *ptr++ = 0x51; // Operating Class
        *ptr++ = 0x01; // k = 1
        *ptr++ = 0x24; // Channel

        // No trailing data

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* TRAIL-02 RF: Exact payload, no extra byte */
void construct_handle_channel_scan_req_pkt62_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(14); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x02;
        *ptr++ = 0x24;
        *ptr++ = 0x36;

        // Payload ends exactly here

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* TRAIL-03 RF: Valid payload with k=0 */
void construct_handle_channel_scan_req_pkt63_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(11); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x00;

        // No trailing bytes

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* TRAIL-04 RF: Multiple valid fields, exact end */
void construct_handle_channel_scan_req_pkt64_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(14); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x73;
        *ptr++ = 0x02;
        *ptr++ = 0x95;
        *ptr++ = 0x99;

        // Exact payload end

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* TRAIL-05 RF: Valid single operating-class structure */
void construct_handle_channel_scan_req_pkt65_rf_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        // Exact payload end

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* ============================================================
 * EXACT PAYLOAD CONSUMPTION / TRAILING DATA
 * RULE BREAK (RB)
 * ============================================================ */

/* TRAIL-02: Valid TLV + 1 unexpected trailing byte */
void construct_handle_channel_scan_req_pkt66_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(14); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        // Unexpected trailing byte
        *ptr++ = 0xFF;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* TRAIL-03: Valid TLV + 2 unexpected trailing bytes */
void construct_handle_channel_scan_req_pkt67_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(15); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        // Unexpected trailing bytes
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* TRAIL-04: Extra operating-class structure after expected data */
void construct_handle_channel_scan_req_pkt68_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(17); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        // Unexpected second Operating Class structure
        *ptr++ = 0x73;
        *ptr++ = 0x01;
        *ptr++ = 0x95;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* TRAIL-05: TLV length declares smaller payload,
 * but actual buffer contains extra data */
void construct_handle_channel_scan_req_pkt69_rb_tlvs(void)
{
        *ptr++ = 0xA6;

        // Declared length = 13
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        // Extra data outside declared TLV length
        *ptr++ = 0xFF;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}


/* TRAIL-RB: Extra unexpected byte after valid payload */
void construct_handle_channel_scan_req_pkt70_rb_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(13); ptr += 2;

        *ptr++ = 0x80;
        *ptr++ = 0x01;

        uint8_t ruid[6] = {0x21,0x32,0x43,0x54,0x65,0x76};
        memcpy(ptr, ruid, 6); ptr += 6;

        *ptr++ = 0x01;
        *ptr++ = 0x51;
        *ptr++ = 0x01;
        *ptr++ = 0x24;

        // Unexpected trailing data
        *ptr++ = 0x00;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt_fresh_scan_0(void)
{
    // ---- Channel Scan Request TLV
    *ptr++ = 0xA6;

    // TLV Length = 9
    *(uint16_t*)ptr = htons(9);
    ptr += 2;

    // Fresh Scan = 0, Reserved = 0
    *ptr++ = 0x00;

    // r = 1
    *ptr++ = 0x01;

    // RUID = 00:11:22:33:44:55
    *ptr++ = 0x00;
    *ptr++ = 0x11;
    *ptr++ = 0x22;
    *ptr++ = 0x33;
    *ptr++ = 0x44;
    *ptr++ = 0x55;

    // m = 0
    *ptr++ = 0x00;

    // No Operating Class / Channel List fields

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

void construct_handle_channel_scan_req_pkt_fresh_scan_1(void)
{
    // ---- Channel Scan Request TLV
    *ptr++ = 0xA6;

    // TLV Length = 12
    *(uint16_t*)ptr = htons(12);
    ptr += 2;

    // Fresh Scan = 1, Reserved = 0
    *ptr++ = 0x80;

    // r = 1
    *ptr++ = 0x01;

    // RUID = 00:11:22:33:44:55
    *ptr++ = 0x00;
    *ptr++ = 0x11;
    *ptr++ = 0x22;
    *ptr++ = 0x33;
    *ptr++ = 0x44;
    *ptr++ = 0x55;

    // m = 1
    *ptr++ = 0x01;

    // Operating Class
    *ptr++ = 0x51;

    // k = 1 channel
    *ptr++ = 0x01;

    // Channel List
    *ptr++ = 0x01;

// ---- EOM TLV
    *ptr++ = 0x00;                  // EOM TLV Type
    *(uint16_t*)ptr = htons(0);     // EOM TLV Length = 0
    ptr += 2;
}

/* ============================================================
 * Requests built by create_channel_scan_req_tlv(), the way
 * send_channel_scan_request_msg() does it: the TLV is written into
 * an uninitialized stack buffer, simulated here by filling with 0xFF.
 * ============================================================ */

class scan_req_builder_t : public em_channel_t {
public:
    dm_easy_mesh_t m_dm;

    dm_easy_mesh_t *get_data_model() override { return &m_dm; }
    em_mgr_t *get_mgr() override { return nullptr; }
    int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) override { return 0; }
};

static void add_scan_param_op_class(dm_easy_mesh_t *dm, unsigned int op_class, unsigned int num_channels, const unsigned int *channels)
{
        dm_op_class_t *opclass = &dm->m_op_class[dm->m_num_opclass++];

        memset(opclass, 0, sizeof(dm_op_class_t));
        opclass->m_op_class_info.id.type = em_op_class_type_scan_param;
        opclass->m_op_class_info.op_class = op_class;
        opclass->m_op_class_info.num_channels = num_channels;
        memcpy(opclass->m_op_class_info.channels, channels, num_channels * sizeof(unsigned int));
}

static void construct_scan_req_from_producer(scan_req_builder_t *builder)
{
        short sz;

        /* dirty buffer, like the uninitialized stack in send_channel_scan_request_msg() */
        memset(ptr, 0xFF, 64);

        *ptr++ = 0xA6;
        sz = builder->create_channel_scan_req_tlv(ptr + 2);
        *(uint16_t*)ptr = htons(static_cast<uint16_t>(sz)); ptr += 2;
        printf("generated flags byte = 0x%02x\n", ptr[0]);
        ptr += sz;

        // ---- EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

/* No scan-param op class: Fresh Scan = 0, m = 0 */
void construct_create_channel_scan_req_no_op_class_tlvs(void)
{
        static scan_req_builder_t builder;

        builder.m_dm.m_num_opclass = 0;
        construct_scan_req_from_producer(&builder);
}

/* One 2.4 GHz scan-param op class: Fresh Scan = 1, m = 1 */
void construct_create_channel_scan_req_one_op_class_tlvs(void)
{
        static scan_req_builder_t builder;
        const unsigned int channels[] = {1, 6, 11};

        builder.m_dm.m_num_opclass = 0;
        add_scan_param_op_class(&builder.m_dm, 81, 3, channels);
        construct_scan_req_from_producer(&builder);
}

/* Scan-param op class on another band (5 GHz) is skipped: Fresh Scan = 0, m = 0 */
void construct_create_channel_scan_req_other_band_tlvs(void)
{
        static scan_req_builder_t builder;
        const unsigned int channels[] = {36};

        builder.m_dm.m_num_opclass = 0;
        add_scan_param_op_class(&builder.m_dm, 115, 1, channels);
        construct_scan_req_from_producer(&builder);
}

pkt_test_case_t handle_channel_scan_req_suite[] = {

        /* ============================================================
         * 1. Fresh Scan bit 7 validation
         * RF: pkt1-pkt5
         * RB: pkt6-pkt10
         * ============================================================ */
        {"handle_channel_scan_req_pkt_fresh_scan_0", "pkt1.pcap", construct_handle_channel_scan_req_pkt_fresh_scan_0, 0},
	{"handle_channel_scan_req_pkt_fresh_scan_1", "pkt2.pcap", construct_handle_channel_scan_req_pkt_fresh_scan_1, 0},
        {"handle_channel_scan_req_pkt1",  "pkt1rf.pcap",  construct_handle_channel_scan_req_pkt1_rf_tlvs,   0},
        {"handle_channel_scan_req_pkt2",  "pkt2rf.pcap",  construct_handle_channel_scan_req_pkt2_rf_tlvs,   0},
        {"handle_channel_scan_req_pkt3",  "pkt3rf.pcap",  construct_handle_channel_scan_req_pkt3_rf_tlvs,   0},
        {"handle_channel_scan_req_pkt4",  "pkt4rf.pcap",  construct_handle_channel_scan_req_pkt4_rf_tlvs,   0},
        {"handle_channel_scan_req_pkt5",  "pkt5rf.pcap",  construct_handle_channel_scan_req_pkt5_rf_tlvs,   0},

        {"handle_channel_scan_req_pkt6",  "pkt6rb.pcap",  construct_handle_channel_scan_req_pkt6_rb_tlvs,  -1},
        {"handle_channel_scan_req_pkt7",  "pkt7rb.pcap",  construct_handle_channel_scan_req_pkt7_rb_tlvs,  -1},
        {"handle_channel_scan_req_pkt8",  "pkt8rb.pcap",  construct_handle_channel_scan_req_pkt8_rb_tlvs,  -1},
        {"handle_channel_scan_req_pkt9",  "pkt9rb.pcap",  construct_handle_channel_scan_req_pkt9_rb_tlvs,  -1},
        {"handle_channel_scan_req_pkt10", "pkt10rb.pcap", construct_handle_channel_scan_req_pkt10_rb_tlvs, -1},


        /* ============================================================
         * 2. Reserved bits 6-0 validation
         * RF: pkt11-pkt15
         * RB: pkt16-pkt20
         * ============================================================ */

        {"handle_channel_scan_req_pkt11", "pkt11rf.pcap", construct_handle_channel_scan_req_pkt11_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt12", "pkt12rf.pcap", construct_handle_channel_scan_req_pkt12_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt13", "pkt13rf.pcap", construct_handle_channel_scan_req_pkt13_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt14", "pkt14rf.pcap", construct_handle_channel_scan_req_pkt14_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt15", "pkt15rf.pcap", construct_handle_channel_scan_req_pkt15_rf_tlvs, 0},

        {"handle_channel_scan_req_pkt16", "pkt16rb.pcap", construct_handle_channel_scan_req_pkt16_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt17", "pkt17rb.pcap", construct_handle_channel_scan_req_pkt17_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt18", "pkt18rb.pcap", construct_handle_channel_scan_req_pkt18_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt19", "pkt19rb.pcap", construct_handle_channel_scan_req_pkt19_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt20", "pkt20rb.pcap", construct_handle_channel_scan_req_pkt20_rb_tlvs, -1},


        /* ============================================================
         * 3. Number of Radios r handling
         * RF: pkt21-pkt25
         * RB: pkt26-pkt30
         * ============================================================ */

        {"handle_channel_scan_req_pkt21", "pkt21rf.pcap", construct_handle_channel_scan_req_pkt21_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt22", "pkt22rf.pcap", construct_handle_channel_scan_req_pkt22_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt23", "pkt23rf.pcap", construct_handle_channel_scan_req_pkt23_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt24", "pkt24rf.pcap", construct_handle_channel_scan_req_pkt24_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt25", "pkt25rf.pcap", construct_handle_channel_scan_req_pkt25_rf_tlvs, 0},

        {"handle_channel_scan_req_pkt26", "pkt26rb.pcap", construct_handle_channel_scan_req_pkt26_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt27", "pkt27rb.pcap", construct_handle_channel_scan_req_pkt27_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt28", "pkt28rb.pcap", construct_handle_channel_scan_req_pkt28_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt29", "pkt29rb.pcap", construct_handle_channel_scan_req_pkt29_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt30", "pkt30rb.pcap", construct_handle_channel_scan_req_pkt30_rb_tlvs, -1},


        /* ============================================================
         * 4. 6-byte RUID parsing
         * RF: pkt31-pkt35
         * RB: pkt36-pkt40
         * ============================================================ */

        {"handle_channel_scan_req_pkt31", "pkt31rf.pcap", construct_handle_channel_scan_req_pkt31_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt32", "pkt32rf.pcap", construct_handle_channel_scan_req_pkt32_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt33", "pkt33rf.pcap", construct_handle_channel_scan_req_pkt33_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt34", "pkt34rf.pcap", construct_handle_channel_scan_req_pkt34_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt35", "pkt35rf.pcap", construct_handle_channel_scan_req_pkt35_rf_tlvs, 0},

        {"handle_channel_scan_req_pkt36", "pkt36rb.pcap", construct_handle_channel_scan_req_pkt36_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt37", "pkt37rb.pcap", construct_handle_channel_scan_req_pkt37_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt38", "pkt38rb.pcap", construct_handle_channel_scan_req_pkt38_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt39", "pkt39rb.pcap", construct_handle_channel_scan_req_pkt39_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt40", "pkt40rb.pcap", construct_handle_channel_scan_req_pkt40_rb_tlvs, -1},


        /* ============================================================
         * 5. Fresh Scan = 0 => m = 0
         * RF: pkt41-pkt45
         * RB: pkt46-pkt50
         * ============================================================ */

        {"handle_channel_scan_req_pkt41", "pkt41rf.pcap", construct_handle_channel_scan_req_pkt41_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt42", "pkt42rf.pcap", construct_handle_channel_scan_req_pkt42_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt43", "pkt43rf.pcap", construct_handle_channel_scan_req_pkt43_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt44", "pkt44rf.pcap", construct_handle_channel_scan_req_pkt44_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt45", "pkt45rf.pcap", construct_handle_channel_scan_req_pkt45_rf_tlvs, 0},

        {"handle_channel_scan_req_pkt46", "pkt46rb.pcap", construct_handle_channel_scan_req_pkt46_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt47", "pkt47rb.pcap", construct_handle_channel_scan_req_pkt47_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt48", "pkt48rb.pcap", construct_handle_channel_scan_req_pkt48_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt49", "pkt49rb.pcap", construct_handle_channel_scan_req_pkt49_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt50", "pkt50rb.pcap", construct_handle_channel_scan_req_pkt50_rb_tlvs, -1},


        /* ============================================================
         * 6. Operating Class / Channel List boundary
         * RF: pkt51-pkt55
         * RB: pkt56-pkt60
         * ============================================================ */

        {"handle_channel_scan_req_pkt51", "pkt51rf.pcap", construct_handle_channel_scan_req_pkt51_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt52", "pkt52rf.pcap", construct_handle_channel_scan_req_pkt52_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt53", "pkt53rf.pcap", construct_handle_channel_scan_req_pkt53_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt54", "pkt54rf.pcap", construct_handle_channel_scan_req_pkt54_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt55", "pkt55rf.pcap", construct_handle_channel_scan_req_pkt55_rf_tlvs, 0},

        {"handle_channel_scan_req_pkt56", "pkt56rb.pcap", construct_handle_channel_scan_req_pkt56_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt57", "pkt57rb.pcap", construct_handle_channel_scan_req_pkt57_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt58", "pkt58rb.pcap", construct_handle_channel_scan_req_pkt58_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt59", "pkt59rb.pcap", construct_handle_channel_scan_req_pkt59_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt60", "pkt60rb.pcap", construct_handle_channel_scan_req_pkt60_rb_tlvs, -1},


        /* ============================================================
         * 7. Exact payload consumption / trailing data
         * RF: pkt61-pkt65
         * RB: pkt66-pkt70
         * ============================================================ */

        {"handle_channel_scan_req_pkt61", "pkt61rf.pcap", construct_handle_channel_scan_req_pkt61_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt62", "pkt62rf.pcap", construct_handle_channel_scan_req_pkt62_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt63", "pkt63rf.pcap", construct_handle_channel_scan_req_pkt63_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt64", "pkt64rf.pcap", construct_handle_channel_scan_req_pkt64_rf_tlvs, 0},
        {"handle_channel_scan_req_pkt65", "pkt65rf.pcap", construct_handle_channel_scan_req_pkt65_rf_tlvs, 0},

        {"handle_channel_scan_req_pkt66", "pkt66rb.pcap", construct_handle_channel_scan_req_pkt66_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt67", "pkt67rb.pcap", construct_handle_channel_scan_req_pkt67_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt68", "pkt68rb.pcap", construct_handle_channel_scan_req_pkt68_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt69", "pkt69rb.pcap", construct_handle_channel_scan_req_pkt69_rb_tlvs, -1},
        {"handle_channel_scan_req_pkt70", "pkt70rb.pcap", construct_handle_channel_scan_req_pkt70_rb_tlvs, -1},

        /* ============================================================
         * 8. Requests built by create_channel_scan_req_tlv()
         * ============================================================ */

        {"create_channel_scan_req_no_op_class", "pkt71gen.pcap", construct_create_channel_scan_req_no_op_class_tlvs, 0},
        {"create_channel_scan_req_one_op_class", "pkt72gen.pcap", construct_create_channel_scan_req_one_op_class_tlvs, 0},
        {"create_channel_scan_req_other_band", "pkt73gen.pcap", construct_create_channel_scan_req_other_band_tlvs, 0},

	{NULL, NULL, NULL, 0} // Null terminator to mark the end of the array
};


/* ============================================================
 * get_radio_id() on Channel Scan Request (pre-routing parser)
 * ============================================================ */

/* Payload {0x80, 0x01}: r = 1 but no RUID, frame ends after EOM */
void construct_get_radio_id_scan_req_len2_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(2); ptr += 2;
        *ptr++ = 0x80;
        *ptr++ = 0x01;

        // ---- EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

/* Payload {0x80}: no radio count */
void construct_get_radio_id_scan_req_len1_tlvs(void)
{
        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(1); ptr += 2;
        *ptr++ = 0x80;

        // ---- EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

/* Payload 8 bytes: one byte short of the fixed header */
void construct_get_radio_id_scan_req_len8_tlvs(void)
{
        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};

        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(8); ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x01;
        memcpy(ptr, ruid, 6); ptr += 6;

        // ---- EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

/* Valid fixed header: Fresh Scan = 0, r = 1, m = 0 */
void construct_get_radio_id_scan_req_valid_tlvs(void)
{
        uint8_t ruid[6] = {0x10,0x20,0x30,0x40,0x50,0x60};

        *ptr++ = 0xA6;
        *(uint16_t*)ptr = htons(9); ptr += 2;
        *ptr++ = 0x00;
        *ptr++ = 0x01;
        memcpy(ptr, ruid, 6); ptr += 6;
        *ptr++ = 0x00;

        // ---- EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

pkt_test_case_t get_radio_id_channel_scan_req_suite[] = {
        {"get_radio_id_scan_req_len2", "pkt74rid.pcap", construct_get_radio_id_scan_req_len2_tlvs, -1},
        {"get_radio_id_scan_req_len1", "pkt75rid.pcap", construct_get_radio_id_scan_req_len1_tlvs, -1},
        {"get_radio_id_scan_req_len8", "pkt76rid.pcap", construct_get_radio_id_scan_req_len8_tlvs, -1},
        {"get_radio_id_scan_req_valid", "pkt77rid.pcap", construct_get_radio_id_scan_req_valid_tlvs, 0},

	{NULL, NULL, NULL, 0} // Null terminator to mark the end of the array
};
