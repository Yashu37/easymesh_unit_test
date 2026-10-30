#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void construct_handle_ap_operational_bss_tlv_header_len1_no_eom(void)
{
	*ptr++ = 0x83;                    // TLV Type only
					  // EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;

}

#if 0
void construct_handle_ap_operational_bss_tlv_header_len1_eom(void)
{
        *ptr++ = 0x83;                    // TLV Type only

        // EOM TLV
         *ptr++ = 0x00;
         *(uint16_t*)ptr = htons(0);
         ptr += 2;
}
#endif

void construct_handle_ap_operational_bss_tlv_header_len2_no_eom(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*ptr++ = 0x00;                    // Only 1 byte of TLV Length
					  // EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;

}
/*
   void construct_handle_ap_operational_bss_tlv_header_len2_eom(void)
   {
 *ptr++ = 0x83;                    // TLV Type
 *ptr++ = 0x00;                    // Only 1 byte of TLV Length

// EOM TLV
 *ptr++ = 0x00;
 *(uint16_t*)ptr = htons(0);
 ptr += 2;
 }
 */
void construct_handle_ap_operational_bss_tlv_header_len3_no_value(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(0);       // TLV Length = 0
	ptr += 2;
}
/*
   void construct_handle_ap_operational_bss_tlv_header_len3_eom(void)
   {
 *ptr++ = 0x83;                    // TLV Type
 *(uint16_t*)ptr = htons(0);       // TLV Length = 0
 ptr += 2;

// EOM TLV
 *ptr++ = 0x00;
 *(uint16_t*)ptr = htons(0);
 ptr += 2;
 }
 */
void construct_handle_ap_operational_bss_tlv_valid_k0(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(1);       // TLV Length = 1
	ptr += 2;
	*ptr++ = 0x00;                    // k = 0 radios
					  // EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;

}

void construct_handle_ap_operational_bss_tlv_valid_k0_eom(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(1);       // TLV Length = 1
	ptr += 2;
	*ptr++ = 0x00;                    // k = 0 radios

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_handle_ap_operational_bss_tlv_valid_k1_m0(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(8);       // TLV Length = 8
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x00;                    // m = 0 BSSs

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_handle_ap_operational_bss_tlv_valid_k1_m1(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(19);      // TLV Length = 19
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x01;                    // m = 1 BSS

	// BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0xFF;

	*ptr++ = 0x04;                    // n = 4
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';


	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;

}

void construct_handle_ap_operational_bss_tlv_valid_k2_m0(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(15);      // TLV Length = 15
	ptr += 2;

	*ptr++ = 0x02;                    // k = 2 radios

	// Radio 1 Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x00;                    // m = 0 BSSs

	// Radio 2 Unique Identifier
	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	*ptr++ = 0x00;                    // m = 0 BSSs

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_handle_ap_operational_bss_tlv_valid_k1_m2(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(30);      // TLV Length = 30
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x02;                    // m = 2 BSSs

	// BSS 1 - BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0x01;

	*ptr++ = 0x04;                    // n = 4
	*ptr++ = 'B';
	*ptr++ = 'S';
	*ptr++ = 'S';
	*ptr++ = '1';

	// BSS 2 - BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0x02;

	*ptr++ = 0x04;                    // n = 4
	*ptr++ = 'B';
	*ptr++ = 'S';
	*ptr++ = 'S';
	*ptr++ = '2';

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_handle_ap_operational_bss_tlv_truncated_radio_uid(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(6);       // TLV Length = 6
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Truncated Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;                    // Only 5 bytes, 1 byte missing

	/* EOM TLV
	 *ptr++ = 0x00;
	 *(uint16_t*)ptr = htons(0);
	 ptr += 2;
	 */
}

void construct_handle_ap_operational_bss_tlv_truncated_bss(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(13);      // TLV Length = 13
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x01;                    // m = 1 BSS

	// Truncated BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;                    // Only 5 bytes, 1 byte missing

	/* EOM TLV
	 *ptr++ = 0x00;
	 *(uint16_t*)ptr = htons(0);
	 ptr += 2;
	 */
}

void construct_handle_ap_operational_bss_tlv_missing_ssid_length(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(14);      // TLV Length = 14
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x01;                    // m = 1 BSS

	// BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0xFF;

	// SSID length (n) is missing

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_handle_ap_operational_bss_tlv_truncated_ssid(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(19);      // TLV Length = 19
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x01;                    // m = 1 BSS

	// BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0xFF;

	*ptr++ = 0x05;                    // n = 5 bytes

	// Truncated SSID: only 4 bytes provided
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_handle_ap_operational_bss_tlv_k_exceeds_available_data(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(8);       // TLV Length = 8
	ptr += 2;

	*ptr++ = 0x02;                    // k = 2 radios

	// Radio 1 Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x00;                    // Radio 1: m = 0 BSSs

	// Radio 2 data is missing

	/* EOM TLV
	 *ptr++ = 0x00;
	 *(uint16_t*)ptr = htons(0);
	 ptr += 2;
	 */
}


void construct_handle_ap_operational_bss_tlv_m_exceeds_available_data(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(15);      // TLV Length = 15
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x02;                    // m = 2 BSSs

	// BSS 1 - BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0xFF;

	*ptr++ = 0x00;                    // n = 0, no SSID

	// BSS 2 data is missing

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;

}

/* Copilot review case: 16 byte payload, 1 radio declaring 2 BSSs but only BSS 1 (1 byte SSID) present */
void construct_handle_ap_operational_bss_tlv_second_bss_missing_len16(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(16);      // TLV Length = 16
	ptr += 2;

	*ptr++ = 0x01;                    // k = 1 radio

	// Radio Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x02;                    // m = 2 BSSs

	// BSS 1 - BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0xFF;

	*ptr++ = 0x01;                    // n = 1
	*ptr++ = 'T';

	// BSS 2 data is missing

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

/* Radio 1 with a valid BSS, radio 2 truncated: must be rejected without adding radio 1's BSS */
void construct_handle_ap_operational_bss_tlv_valid_radio1_truncated_radio2(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(22);      // TLV Length = 22
	ptr += 2;

	*ptr++ = 0x02;                    // k = 2 radios

	// Radio 1 Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x01;                    // Radio 1: m = 1 BSS

	// BSS 1 - BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0xFF;

	*ptr++ = 0x04;                    // n = 4
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// Radio 2 Unique Identifier, only 3 of 6 bytes
	*ptr++ = 0x00;
	*ptr++ = 0x66;
	*ptr++ = 0x77;

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

void construct_handle_ap_operational_bss_tlv_valid_k2_m1(void)
{
	*ptr++ = 0x83;                    // TLV Type
	*(uint16_t*)ptr = htons(37);      // TLV Length = 37
	ptr += 2;

	*ptr++ = 0x02;                    // k = 2 radios

	// Radio 1 Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x01;                    // Radio 1: m = 1 BSS

	// BSS 1 - BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0xFF;

	*ptr++ = 0x04;                    // n = 4
	*ptr++ = 'T';
	*ptr++ = 'E';
	*ptr++ = 'S';
	*ptr++ = 'T';

	// Radio 2 Unique Identifier
	*ptr++ = 0x00;
	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;

	*ptr++ = 0x01;                    // Radio 2: m = 1 BSS

	// BSS 1 - BSSID
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;
	*ptr++ = 0xCC;
	*ptr++ = 0xDD;
	*ptr++ = 0xEE;
	*ptr++ = 0x01;

	*ptr++ = 0x04;                    // n = 4
	*ptr++ = 'B';
	*ptr++ = 'S';
	*ptr++ = 'S';
	*ptr++ = '1';

	// EOM TLV
	*ptr++ = 0x00;
	*(uint16_t*)ptr = htons(0);
	ptr += 2;
}

pkt_test_case_t handle_ap_operational_bss_suite[] = {
	{"handle_ap_operational_bss_tlv_header_len1_no_eom", "pkt_header_len1_no_eom.pcap", construct_handle_ap_operational_bss_tlv_header_len1_no_eom, -1},
	//      {"handle_ap_operational_bss_tlv_header_len1_eom", "pkt_header_len1_eom.pcap", construct_handle_ap_operational_bss_tlv_header_len1_eom, -1},
	{"handle_ap_operational_bss_tlv_header_len2_no_eom", "pkt_header_len2_no_eom.pcap", construct_handle_ap_operational_bss_tlv_header_len2_no_eom, -1},
	//     {"handle_ap_operational_bss_tlv_header_len2_eom", "pkt_header_len2_eom.pcap", construct_handle_ap_operational_bss_tlv_header_len2_eom, -1},
	{"handle_ap_operational_bss_tlv_header_len3_no_value", "pkt_header_len3_no_value.pcap", construct_handle_ap_operational_bss_tlv_header_len3_no_value, -1},
	//      {"handle_ap_operational_bss_tlv_header_len3_eom", "pkt_header_len3_eom.pcap", construct_handle_ap_operational_bss_tlv_header_len3_eom, -1},
	{"handle_ap_operational_bss_tlv_valid_k0", "pkt_valid_k0.pcap", construct_handle_ap_operational_bss_tlv_valid_k0, 0},
	{"handle_ap_operational_bss_tlv_valid_k0_eom", "pkt_valid_k0_eom.pcap", construct_handle_ap_operational_bss_tlv_valid_k0_eom, 0},
	{"handle_ap_operational_bss_tlv_valid_k1_m0", "pkt_valid_k1_m0.pcap", construct_handle_ap_operational_bss_tlv_valid_k1_m0, 0},
	{"handle_ap_operational_bss_tlv_valid_k1_m1", "pkt_valid_k1_m1.pcap", construct_handle_ap_operational_bss_tlv_valid_k1_m1, 0},
	{"handle_ap_operational_bss_tlv_valid_k2_m0", "pkt_valid_k2_m0.pcap", construct_handle_ap_operational_bss_tlv_valid_k2_m0, 0},
	{"handle_ap_operational_bss_tlv_valid_k1_m2", "pkt_valid_k1_m2.pcap", construct_handle_ap_operational_bss_tlv_valid_k1_m2, 0},
	{"handle_ap_operational_bss_tlv_truncated_radio_uid", "pkt_truncated_radio_uid.pcap", construct_handle_ap_operational_bss_tlv_truncated_radio_uid, -1},
	{"handle_ap_operational_bss_tlv_truncated_bss", "pkt_truncated_bss.pcap", construct_handle_ap_operational_bss_tlv_truncated_bss, -1},
	{"handle_ap_operational_bss_tlv_missing_ssid_length", "pkt_missing_ssid_length.pcap", construct_handle_ap_operational_bss_tlv_missing_ssid_length, -1},
	{"handle_ap_operational_bss_tlv_truncated_ssid", "pkt_truncated_ssid.pcap", construct_handle_ap_operational_bss_tlv_truncated_ssid, -1},
	{"handle_ap_operational_bss_tlv_k_exceeds_available_data", "pkt_k_exceeds_available_data.pcap", construct_handle_ap_operational_bss_tlv_k_exceeds_available_data, -1},
	{"handle_ap_operational_bss_tlv_m_exceeds_available_data", "pkt_m_exceeds_available_data.pcap", construct_handle_ap_operational_bss_tlv_m_exceeds_available_data, -1},
	{"handle_ap_operational_bss_tlv_second_bss_missing_len16", "pkt_second_bss_missing_len16.pcap", construct_handle_ap_operational_bss_tlv_second_bss_missing_len16, -1},
	{"handle_ap_operational_bss_tlv_valid_radio1_truncated_radio2", "pkt_valid_radio1_truncated_radio2.pcap", construct_handle_ap_operational_bss_tlv_valid_radio1_truncated_radio2, -1},
	{"handle_ap_operational_bss_tlv_valid_k2_m1", "pkt_valid_k2_m1.pcap", construct_handle_ap_operational_bss_tlv_valid_k2_m1, 0},
	{NULL, NULL, NULL, 0}
};
