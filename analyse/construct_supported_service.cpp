#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void construct_supported_service_tlv_type_only(void)
{
	*ptr++ = 0x80;
}

void construct_supported_service_tlv_type_len1(void)
{
	*ptr++ = 0x80;

	*(uint16_t*)ptr = htons(1);
	ptr += 2;
}

void construct_supported_service_tlv_header_only(void)
{
	*ptr++ = 0x80;       // TLV type

	*(uint16_t*)ptr = htons(0);  // TLV length = 0
	ptr += 2;
}

void construct_supported_service_valid_k0(void)
{
	*ptr++ = 0x80;          // TLV type

	*(uint16_t*)ptr = htons(1);  // TLV length = 1
	ptr += 2;

	*ptr++ = 0x00;          // Number of services (k = 0)
// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_valid_k1_controller(void)
{
	*ptr++ = 0x80;              // TLV type

	*(uint16_t*)ptr = htons(2); // TLV length = 2
	ptr += 2;

	*ptr++ = 0x01;              // Number of services (k = 1)
	*ptr++ = 0x00;              // Multi-AP Controller

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_valid_k1_agent(void)
{
	*ptr++ = 0x80;              // TLV type

	*(uint16_t*)ptr = htons(2); // TLV length = 2
	ptr += 2;

	*ptr++ = 0x01;              // Number of services (k = 1)
	*ptr++ = 0x01;              // Multi-AP Agent

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_valid_k2(void)
{
	*ptr++ = 0x80;              // TLV type

	*(uint16_t*)ptr = htons(3); // TLV length = 3
	ptr += 2;

	*ptr++ = 0x02;              // Number of services (k = 2)
	*ptr++ = 0x00;              // Multi-AP Controller
	*ptr++ = 0x01;              // Multi-AP Agent

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_valid_max_services(void)
{
	*ptr++ = 0x80;

	*(uint16_t*)ptr = htons(1 + EM_MAX_SERVICE);
	ptr += 2;

	*ptr++ = EM_MAX_SERVICE;

	for (int i = 0; i < EM_MAX_SERVICE; i++) {
		*ptr++ = (i % 2);  // Alternate Controller (0x00) and Agent (0x01)
	}

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_zero_length(void)
{
	*ptr++ = 0x80;              // SupportedService TLV type

	*(uint16_t*)ptr = htons(0); // TLV length = 0
	ptr += 2;

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_count_exceeds_available_ids(void)
{
	*ptr++ = 0x80;              // SupportedService TLV type

	*(uint16_t*)ptr = htons(2); // TLV length = 2
	ptr += 2;

	*ptr++ = 0x05;              // Service count = 5
	*ptr++ = 0x00;              // Only one service ID available

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_count_smaller_than_available_ids(void)
{
	*ptr++ = 0x80;              // SupportedService TLV type

	*(uint16_t*)ptr = htons(3); // TLV length = 3
	ptr += 2;

	*ptr++ = 0x01;              // Service count = 1
	*ptr++ = 0x00;              // Multi-AP Controller
	*ptr++ = 0x01;              // Multi-AP Agent (extra service ID)

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_declared_length_exceeds_buffer(void)
{
	*ptr++ = 0x80;              // SupportedService TLV type

	*(uint16_t*)ptr = htons(5); // TLV length = 5
	ptr += 2;

	*ptr++ = 0x01;              // Service count = 1
				    // Remaining 4 bytes are missing intentionally.

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_count_exceeds_destination_capacity(void)
{
	*ptr++ = 0x80;  // SupportedService TLV type

	*(uint16_t*)ptr = htons(1 + EM_MAX_SERVICE + 1);
	ptr += 2;

	*ptr++ = EM_MAX_SERVICE + 1;  // Service count exceeds capacity

	for (int i = 0; i < EM_MAX_SERVICE + 1; i++) {
		*ptr++ = 0x00;  // Service ID
	}

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_eom_only(void)
{
	*ptr++ = 0xFF;              // EOM TLV type

	*(uint16_t*)ptr = htons(0); // EOM TLV length = 0
	ptr += 2;
}

void construct_supported_service_other_tlv_followed_by_valid(void)
{
	/* Another TLV */
	*ptr++ = 0x01;              // TLV type

	*(uint16_t*)ptr = htons(1); // TLV length = 1
	ptr += 2;

	*ptr++ = 0xAA;              // TLV value

	/* Valid SupportedService TLV */
	*ptr++ = 0x80;              // SupportedService TLV type

	*(uint16_t*)ptr = htons(2); // TLV length = 2
	ptr += 2;

	*ptr++ = 0x01;              // Number of services (k = 1)
	*ptr++ = 0x00;              // Multi-AP Controller

// EOM TLV
        *ptr++ = 0x00;
        *(uint16_t*)ptr = htons(0);
        ptr += 2;
}

void construct_supported_service_other_tlv_followed_by_eom(void)
{
	/* Another TLV */
	*ptr++ = 0x01;              // TLV type

	*(uint16_t*)ptr = htons(1); // TLV length = 1
	ptr += 2;

	*ptr++ = 0xAA;              // TLV value

	/* EOM TLV */
	*ptr++ = 0xFF;              // EOM TLV type

	*(uint16_t*)ptr = htons(0); // EOM TLV length = 0
	ptr += 2;
}
pkt_test_case_t get_supported_service_suite[] = {

	{"supported_service_tlv_type_only", "p1.pcap", construct_supported_service_tlv_type_only, -1},
	{"supported_service_tlv_type_len1", "p1.pcap", construct_supported_service_tlv_type_len1, -1},
	{"supported_service_tlv_header_only", "p1.pcap", construct_supported_service_tlv_header_only, -1},
	{"supported_service_valid_k0", "p1.pcap", construct_supported_service_valid_k0, 0},
	{"supported_service_valid_k1_controller", "p1.pcap", construct_supported_service_valid_k1_controller, 0},
	{"supported_service_valid_k1_agent", "p2.pcap", construct_supported_service_valid_k1_agent, 0},
	{"supported_service_valid_k2", "p3.pcap", construct_supported_service_valid_k2, 0},
	{"supported_service_valid_max_services", "p4.pcap", construct_supported_service_valid_max_services, 0},
	{"supported_service_zero_length", "p1.pcap", construct_supported_service_zero_length, -1},
	{"supported_service_count_exceeds_available_ids", "p1.pcap", construct_supported_service_count_exceeds_available_ids, -1},
	{"supported_service_count_smaller_than_available_ids", "p1.pcap", construct_supported_service_count_smaller_than_available_ids, -1},
	{"supported_service_declared_length_exceeds_buffer", "p1.pcap", construct_supported_service_declared_length_exceeds_buffer, -1},
	{"supported_service_count_exceeds_destination_capacity", "p1.pcap", construct_supported_service_count_exceeds_destination_capacity, -1},
	{"supported_service_eom_only", "p1.pcap", construct_supported_service_eom_only, -1},
	{"supported_service_other_tlv_followed_by_valid", "p1.pcap", construct_supported_service_other_tlv_followed_by_valid, 0},
	{"supported_service_other_tlv_followed_by_eom", "p1.pcap", construct_supported_service_other_tlv_followed_by_eom, -1},
	{NULL, NULL, NULL, 0}
};
