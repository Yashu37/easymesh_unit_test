#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void construct_valid_timestamp_tlv_real(void)
{
    *ptr++ = 0xA8;   // Timestamp TLV

    // Real timestamp string
    const char *ts = "2024-03-15T10:30:45Z";
    uint8_t ts_len = 20;

    // TLV length = 1 (length field) + 20 (string)
    *(uint16_t*)ptr = htons(21);   // ✅ correct
    ptr += 2;

    *ptr++ = ts_len;   // timestamp length

    memcpy(ptr, ts, ts_len);   // timestamp string
    ptr += ts_len;
}

pkt_test_case_t handle_channel_scan_rprt_suite[] = {

	{"valid_timestamp_tlv_real", "p1.pcap", construct_valid_timestamp_tlv_real, 0},


	{NULL, NULL, NULL, 0}
};


