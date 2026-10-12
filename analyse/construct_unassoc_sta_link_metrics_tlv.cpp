#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void construct_handle_unassoc_sta_link_metrics_tlv_header_len1_no_eom(void)
{
        *ptr++ = 0x98;                    // TLV Type
}

void construct_handle_unassoc_sta_link_metrics_tlv_header_len1_eom(void)
{
        *ptr++ = 0x98;                    // TLV Type

        // EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_header_len2_no_eom(void)
{
        *ptr++ = 0x98;                    // TLV Type
        *ptr++ = 0x00;                    // Only 1 byte of TLV Length
}

void construct_handle_unassoc_sta_link_metrics_tlv_header_len2_eom(void)
{
        *ptr++ = 0x98;                    // TLV Type
        *ptr++ = 0x00;                    // Only 1 byte of TLV Length

        // EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_header_len3_no_eom(void)
{
        *ptr++ = 0x98;                    // TLV Type
        *(uint16_t*)ptr = htons(0);       // TLV Length = 0
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_header_len3_eom(void)
{
        *ptr++ = 0x98;                    // TLV Type
        *(uint16_t*)ptr = htons(0);       // TLV Length = 0
        ptr += 2;

        // EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_len4(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;                    // TLV Type
        *(uint16_t*)ptr = htons(1);       // TLV Length = 2
        ptr += 2;

        // Operating Class only
        *ptr++ = 0x51;

        // Number of STA entries (k) is missing
        // Total TLV = 4 octets

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_valid_k0_len5(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;                    // TLV Type
        *(uint16_t*)ptr = htons(2);       // TLV Length = 2
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 0
        *ptr++ = 0x00;

	// Total TLV = 5 octets

}

void construct_handle_unassoc_sta_link_metrics_tlv_k0_len6(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;                    // TLV Type
        *(uint16_t*)ptr = htons(3);       // TLV Length = 2
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 0
        *ptr++ = 0x00;

        // Extra byte -> makes TLV 6 octets
        *ptr++ = 0x00;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_k0_len11(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;                    // TLV Type
        *(uint16_t*)ptr = htons(8);       // TLV Length = 2
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 0
        *ptr++ = 0x00;

        // Extra bytes -> makes TLV 11 octets(mac addr)
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x00;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_valid_k1(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;                    // TLV Type
        *(uint16_t*)ptr = htons(14);      // TLV Length = 2 + (1 * 12)
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 1
        *ptr++ = 0x01;

        // ---- STA Entry (12 octets) ----

        // STA MAC Address - 6 octets
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // Channel Number - 1 octet
        *ptr++ = 0x06;

        // Time Delta - 4 octets
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;

        // Uplink RCPI - 1 octet
        *ptr++ = 0x96;

        // Total TLV:
        // Type(1) + Length(2) + Value(14) = 17 octets
}

void construct_handle_unassoc_sta_link_metrics_tlv_k1_missing_sta_mac(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(8);       // 1 + 1 + 6 = 8 bytes
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 1
        *ptr++ = 0x01;

        // STA MAC completely missing

	// Channel Number - 1 octet
	*ptr++ = 0x06;

        // Time Delta - 4 octets
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;

        // Uplink RCPI - 1 octet
        *ptr++ = 0x96;

	// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k1_missing_channel(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(13);      // 14 - 1 = 13
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 1
        *ptr++ = 0x01;

        // STA MAC - 6 bytes
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // Channel Number missing

        // Time Delta - 4 bytes
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;

        // Uplink RCPI
        *ptr++ = 0x96;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k1_missing_time_delta(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(10);      // 14 - 4 = 10
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 1
        *ptr++ = 0x01;

        // STA MAC - 6 bytes
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // Channel Number
        *ptr++ = 0x06;

        // Time Delta missing

        // Uplink RCPI
        *ptr++ = 0x96;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k1_missing_rcpi(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(13);      // 14 - 1 = 13
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 1
        *ptr++ = 0x01;

        // STA MAC - 6 bytes
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // Channel Number
        *ptr++ = 0x06;

        // Time Delta - 4 bytes
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;

        // Uplink RCPI missing
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k1_mac_5_bytes(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(13);      // 14 - 1 = 13
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 1
        *ptr++ = 0x01;

        // STA MAC - ONLY 5 bytes
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;

        // Channel Number
        *ptr++ = 0x06;

        // Time Delta - 4 bytes
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;

        // Uplink RCPI
        *ptr++ = 0x96;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k1_time_delta_3_bytes(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(13);      // 14 - 1 = 13
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 1
        *ptr++ = 0x01;

        // STA MAC - 6 bytes
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // Channel Number
        *ptr++ = 0x06;

        // Time Delta - ONLY 3 bytes
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x03;

        // RCPI
        *ptr++ = 0x96;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_valid_k2(void)
{
        // ---- Unassociated STA Link Metrics Response TLV ----
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(26);      // 2 + (2 * 12)
        ptr += 2;

        // Operating Class
        *ptr++ = 0x51;

        // Number of STA entries: k = 2
        *ptr++ = 0x02;

        // ================= STA 1 =================

        // STA MAC - 6 bytes
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;

        // Channel Number
        *ptr++ = 0x06;

        // Time Delta - 4 bytes
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;

        // Uplink RCPI
        *ptr++ = 0x96;

        // ================= STA 2 =================

        // STA MAC - 6 bytes
        *ptr++ = 0x00;
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;

        // Channel Number
        *ptr++ = 0x06;

        // Time Delta - 4 bytes
        *(uint32_t*)ptr = htonl(2000);
        ptr += 4;

        // Uplink RCPI
        *ptr++ = 0x96;

}


void construct_handle_unassoc_sta_link_metrics_tlv_k2_truncated_second_sta(void)
{
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(20);      // 2 + 12 + 6
        ptr += 2;

        *ptr++ = 0x51;                    // Operating Class
        *ptr++ = 0x02;                    // k = 2

        // ================= STA 1 =================
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;
        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;
        *ptr++ = 0x96;

        // ================= STA 2 =================
        // STA MAC missing

        // Only remaining fields
        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(2000);
        ptr += 4;
        *ptr++ = 0x96;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k2_missing_channel(void)
{
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(25);      // 26 - 1
        ptr += 2;

        *ptr++ = 0x51;
        *ptr++ = 0x02;

        // ================= STA 1 =================
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;
        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;
        *ptr++ = 0x96;

        // ================= STA 2 =================
        *ptr++ = 0x00;
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;

        // Channel missing

        *(uint32_t*)ptr = htonl(2000);
        ptr += 4;
        *ptr++ = 0x96;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k2_missing_time_delta(void)
{
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(22);      // 26 - 4
        ptr += 2;

        *ptr++ = 0x51;
        *ptr++ = 0x02;

        // ================= STA 1 =================
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;
        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;
        *ptr++ = 0x96;

        // ================= STA 2 =================
        *ptr++ = 0x00;
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;
        *ptr++ = 0x06;

        // Time Delta missing

        *ptr++ = 0x96;

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k2_missing_rcpi(void)
{
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(25);      // 26 - 1
        ptr += 2;

        *ptr++ = 0x51;
        *ptr++ = 0x02;

        // ================= STA 1 =================
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;
        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;
        *ptr++ = 0x96;

        // ================= STA 2 =================
        *ptr++ = 0x00;
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;
        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(2000);
        ptr += 4;

        // Uplink RCPI missing
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k2_mac_5_bytes(void)
{
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(25);      // 26 - 1
        ptr += 2;

        *ptr++ = 0x51;
        *ptr++ = 0x02;

        // ================= STA 1 =================
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;
        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;
        *ptr++ = 0x96;

        // ================= STA 2 =================
        // STA MAC - ONLY 5 bytes
        *ptr++ = 0x00;
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;

        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(2000);
        ptr += 4;
        *ptr++ = 0x96;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}


void construct_handle_unassoc_sta_link_metrics_tlv_k2_time_delta_3_bytes(void)
{
        *ptr++ = 0x98;
        *(uint16_t*)ptr = htons(25);      // 26 - 1
        ptr += 2;

        *ptr++ = 0x51;
        *ptr++ = 0x02;

        // ================= STA 1 =================
        *ptr++ = 0x00;
        *ptr++ = 0x11;
        *ptr++ = 0x22;
        *ptr++ = 0x33;
        *ptr++ = 0x44;
        *ptr++ = 0x55;
        *ptr++ = 0x06;
        *(uint32_t*)ptr = htonl(1000);
        ptr += 4;
        *ptr++ = 0x96;

        // ================= STA 2 =================
        *ptr++ = 0x00;
        *ptr++ = 0xAA;
        *ptr++ = 0xBB;
        *ptr++ = 0xCC;
        *ptr++ = 0xDD;
        *ptr++ = 0xEE;
        *ptr++ = 0x06;

        // Time Delta - ONLY 3 bytes
        *ptr++ = 0x00;
        *ptr++ = 0x00;
        *ptr++ = 0x03;

        // RCPI
        *ptr++ = 0x96;
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_handle_unassoc_sta_link_metrics_tlv_truncated_k1(void)
{
    packet_len = 2;

    ptr = packet;

    // Operating Class
    *ptr++ = 0x51;

    // Number of STA = 1
    *ptr++ = 0x01;

    /*
     * Only 2 bytes are actually available.
     *
     * But according to num_sta=1:
     * expected TLV length =
     * 2 + sizeof(em_unassoc_sta_metric_t)
     * = 14 bytes
     *
     * This creates a truncated TLV.
     */
}

pkt_test_case_t handle_unassoc_sta_link_metrics_suite[] = {

	{"handle_unassoc_sta_link_metrics_tlv_header_len1_no_eom", "pkt_header_len1_no_eom.pcap", construct_handle_unassoc_sta_link_metrics_tlv_header_len1_no_eom, -1},
	{"handle_unassoc_sta_link_metrics_tlv_header_len1_eom", "pkt_header_len1_eom.pcap", construct_handle_unassoc_sta_link_metrics_tlv_header_len1_eom, -1},
	{"handle_unassoc_sta_link_metrics_tlv_header_len2_no_eom", "pkt_header_len2_no_eom.pcap", construct_handle_unassoc_sta_link_metrics_tlv_header_len2_no_eom, -1},
	{"handle_unassoc_sta_link_metrics_tlv_header_len2_eom", "pkt_header_len2_eom.pcap", construct_handle_unassoc_sta_link_metrics_tlv_header_len2_eom, -1},
	{"handle_unassoc_sta_link_metrics_tlv_header_len3_no_eom", "pkt_header_len3_no_eom.pcap", construct_handle_unassoc_sta_link_metrics_tlv_header_len3_no_eom, -1},
	{"handle_unassoc_sta_link_metrics_tlv_header_len3_eom", "pkt_header_len3_eom.pcap", construct_handle_unassoc_sta_link_metrics_tlv_header_len3_eom, -1},
	{"handle_unassoc_sta_link_metrics_tlv_len4", "pkt_len4.pcap", construct_handle_unassoc_sta_link_metrics_tlv_len4, -1},
	{"handle_unassoc_sta_link_metrics_tlv_valid_k0_len5", "pkt_len5.pcap", construct_handle_unassoc_sta_link_metrics_tlv_valid_k0_len5, 0},
	{"handle_unassoc_sta_link_metrics_tlv_k0_len6", "pkt_k0_len6.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k0_len6, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k0_len11", "pkt_k0_len11.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k0_len11, -1},
	{"handle_unassoc_sta_link_metrics_tlv_valid_k1", "pkt2.pcap", construct_handle_unassoc_sta_link_metrics_tlv_valid_k1, 0},
	{"handle_unassoc_sta_link_metrics_tlv_k1_missing_sta_mac", "pkt16.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k1_missing_sta_mac, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k1_missing_channel", "pkt17.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k1_missing_channel, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k1_missing_time_delta", "pkt18.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k1_missing_time_delta, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k1_missing_rcpi", "pkt19.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k1_missing_rcpi, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k1_mac_5_bytes", "pkt20.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k1_mac_5_bytes, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k1_time_delta_3_bytes", "pkt21.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k1_time_delta_3_bytes, -1},
	{"handle_unassoc_sta_link_metrics_tlv_valid_k2", "pkt22.pcap", construct_handle_unassoc_sta_link_metrics_tlv_valid_k2, 0},
	{"handle_unassoc_sta_link_metrics_tlv_k2_truncated_second_sta", "pkt23.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k2_truncated_second_sta, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k2_missing_channel", "pkt24.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k2_missing_channel, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k2_missing_time_delta", "pkt25.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k2_missing_time_delta, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k2_missing_rcpi", "pkt26.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k2_missing_rcpi, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k2_mac_5_bytes", "pkt27.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k2_mac_5_bytes, -1},
	{"handle_unassoc_sta_link_metrics_tlv_k2_time_delta_3_bytes", "pkt28.pcap", construct_handle_unassoc_sta_link_metrics_tlv_k2_time_delta_3_bytes, -1},	
	{"handle_unassoc_sta_link_metrics_tlv_truncated_k1", "pkt29.pcap", construct_handle_unassoc_sta_link_metrics_tlv_truncated_k1, -1},
	{NULL, NULL, NULL, 0} // Null terminator to mark the end of the array

};
