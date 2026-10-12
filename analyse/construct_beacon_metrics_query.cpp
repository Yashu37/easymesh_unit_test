#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void construct_handle_beacon_metrics_query_valid_channel_not_255_h0(void)
{
	// TLV Type
	*ptr++ = 0x99;

	// TLV Length = 22 bytes
	*ptr++ = 0x00;
	*ptr++ = 0x16;

	// STA MAC
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	// Operating Class
	*ptr++ = 0x81;

	// Channel Number = 36
	*ptr++ = 0x24;

	// BSSID
	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	// Reporting Detail = 1
	*ptr++ = 0x01;

	// SSID Length = 4
	*ptr++ = 0x04;

	// SSID = "test"
	*ptr++ = 't';
	*ptr++ = 'e';
	*ptr++ = 's';
	*ptr++ = 't';

	// Number of AP Channel Reports = 0
	*ptr++ = 0x00;

	// Number of Element IDs = 0
	*ptr++ = 0x00;
}

void construct_handle_beacon_metrics_query_invalid_channel_not_255_h1(void)
{
	*ptr++ = 0x99;

	// Payload length = 25
	*ptr++ = 0x00;
	*ptr++ = 0x19;

	// STA MAC
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	// Operating Class
	*ptr++ = 0x81;

	// Channel Number = 36 (NOT 255)
	*ptr++ = 0x24;

	// BSSID
	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	// Reporting Detail
	*ptr++ = 0x01;

	// SSID length = 4
	*ptr++ = 0x04;

	*ptr++ = 't';
	*ptr++ = 'e';
	*ptr++ = 's';
	*ptr++ = 't';

	// h = 1
	*ptr++ = 0x01;

	// AP Channel Report length = 2
	*ptr++ = 0x02;

	// Operating Class
	*ptr++ = 0x81;

	// Channel List
	*ptr++ = 0x24;

	// m = 0
	*ptr++ = 0x00;
}

void construct_handle_beacon_metrics_query_valid_channel_255_h0(void)
{
	*ptr++ = 0x99;

	// Payload length = 22
	*ptr++ = 0x00;
	*ptr++ = 0x16;

	// STA MAC
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	// Operating Class
	*ptr++ = 0x81;

	// Channel Number = 255
	*ptr++ = 0xFF;

	// BSSID
	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	// Reporting Detail = 1
	*ptr++ = 0x01;

	// SSID length = 4
	*ptr++ = 0x04;

	*ptr++ = 't';
	*ptr++ = 'e';
	*ptr++ = 's';
	*ptr++ = 't';

	// h = 0
	*ptr++ = 0x00;

	// m = 0
	*ptr++ = 0x00;
}

void construct_handle_beacon_metrics_query_valid_channel_255_h1(void)
{
	*ptr++ = 0x99;

	// Payload length = 25
	*ptr++ = 0x00;
	*ptr++ = 0x19;

	// STA MAC
	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	// Operating Class
	*ptr++ = 0x81;

	// Channel Number = 255
	*ptr++ = 0xFF;

	// BSSID
	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	// Reporting Detail = 1
	*ptr++ = 0x01;

	// SSID length = 4
	*ptr++ = 0x04;

	*ptr++ = 't';
	*ptr++ = 'e';
	*ptr++ = 's';
	*ptr++ = 't';

	// h = 1
	*ptr++ = 0x01;

	// k = 2
	*ptr++ = 0x02;

	// Operating Class
	*ptr++ = 0x81;

	// Channel
	*ptr++ = 0x24;

	// m = 0
	*ptr++ = 0x00;
}

void construct_handle_beacon_metrics_query_valid_reporting_detail_1_m0(void)
{
	*ptr++ = 0x99;

	// Payload length = 22
	*ptr++ = 0x00;
	*ptr++ = 0x16;

	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x81;
	*ptr++ = 0x24;

	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	// Reporting Detail = 1
	*ptr++ = 0x01;

	// SSID = test
	*ptr++ = 0x04;
	*ptr++ = 't';
	*ptr++ = 'e';
	*ptr++ = 's';
	*ptr++ = 't';

	// h = 0
	*ptr++ = 0x00;

	// m = 0
	*ptr++ = 0x00;
}

void construct_handle_beacon_metrics_query_valid_reporting_detail_1_m1(void)
{
	*ptr++ = 0x99;

	// Payload length = 24
	*ptr++ = 0x00;
	*ptr++ = 0x18;

	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x81;
	*ptr++ = 0x24;

	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	// Reporting Detail = 1
	*ptr++ = 0x01;

	// SSID
	*ptr++ = 0x04;
	*ptr++ = 't';
	*ptr++ = 'e';
	*ptr++ = 's';
	*ptr++ = 't';

	// h = 0
	*ptr++ = 0x00;

	// m = 1
	*ptr++ = 0x01;

	// Element ID
	*ptr++ = 0x01;
}

void construct_handle_beacon_metrics_query_invalid_reporting_detail_not_1_m1(void)
{
	*ptr++ = 0x99;

	// Payload length = 24
	*ptr++ = 0x00;
	*ptr++ = 0x18;

	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x81;
	*ptr++ = 0x24;

	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	// Reporting Detail = 0
	*ptr++ = 0x00;

	// SSID
	*ptr++ = 0x04;
	*ptr++ = 't';
	*ptr++ = 'e';
	*ptr++ = 's';
	*ptr++ = 't';

	// h = 0
	*ptr++ = 0x00;

	// m = 1 -> INVALID because Reporting Detail != 1
	*ptr++ = 0x01;

	// Element ID
	*ptr++ = 0x01;
}

void construct_handle_beacon_metrics_query_invalid_ssid_length(void)
{
	*ptr++ = 0x99;

	// Payload length = 18
	*ptr++ = 0x00;
	*ptr++ = 0x12;

	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x81;
	*ptr++ = 0x24;

	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	*ptr++ = 0x01;

	// SSID length says 10 bytes
	*ptr++ = 0x0A;

	// Only 2 SSID bytes actually available
	*ptr++ = 't';
	*ptr++ = 'e';
}

void construct_handle_beacon_metrics_query_invalid_ap_channel_report_length(void)
{
	*ptr++ = 0x99;

	// Payload length = 23
	*ptr++ = 0x00;
	*ptr++ = 0x17;

	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x81;

	// Channel = 255, so AP Channel Reports are allowed
	*ptr++ = 0xFF;

	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	*ptr++ = 0x01;

	// SSID length = 0
	*ptr++ = 0x00;

	// h = 1
	*ptr++ = 0x01;

	// k = 10, but only insufficient bytes remain
	*ptr++ = 0x0A;

	// Only one byte available
	*ptr++ = 0x81;
}

void construct_handle_beacon_metrics_query_invalid_element_list_overrun(void)
{
	*ptr++ = 0x99;

	// Payload length = 19
	*ptr++ = 0x00;
	*ptr++ = 0x13;

	*ptr++ = 0x00;
	*ptr++ = 0x11;
	*ptr++ = 0x22;
	*ptr++ = 0x33;
	*ptr++ = 0x44;
	*ptr++ = 0x55;

	*ptr++ = 0x81;
	*ptr++ = 0x24;

	*ptr++ = 0x66;
	*ptr++ = 0x77;
	*ptr++ = 0x88;
	*ptr++ = 0x99;
	*ptr++ = 0xAA;
	*ptr++ = 0xBB;

	*ptr++ = 0x01;

	// SSID length = 0
	*ptr++ = 0x00;

	// h = 0
	*ptr++ = 0x00;

	// m = 5, but no 5 Element IDs follow
	*ptr++ = 0x05;
}

pkt_test_case_t handle_beacon_metrics_query_suite[] = {

	{"handle_beacon_metrics_query_valid_channel_not_255_h0", "pkt1.pcap", construct_handle_beacon_metrics_query_valid_channel_not_255_h0, 0},
	{"handle_beacon_metrics_query_invalid_channel_not_255_h1", "pkt2.pcap", construct_handle_beacon_metrics_query_invalid_channel_not_255_h1, -1},
	{"handle_beacon_metrics_query_valid_channel_255_h0", "pkt3.pcap", construct_handle_beacon_metrics_query_valid_channel_255_h0, 0},
	{"handle_beacon_metrics_query_valid_channel_255_h1", "pkt4.pcap", construct_handle_beacon_metrics_query_valid_channel_255_h1, 0},
	{"handle_beacon_metrics_query_valid_reporting_detail_1_m0", "pkt5.pcap", construct_handle_beacon_metrics_query_valid_reporting_detail_1_m0, 0},
	{"handle_beacon_metrics_query_valid_reporting_detail_1_m1", "pkt6.pcap", construct_handle_beacon_metrics_query_valid_reporting_detail_1_m1, 0},
	{"handle_beacon_metrics_query_invalid_reporting_detail_not_1_m1", "pkt7.pcap", construct_handle_beacon_metrics_query_invalid_reporting_detail_not_1_m1, -1},
	{"handle_beacon_metrics_query_invalid_ssid_length", "pkt8.pcap", construct_handle_beacon_metrics_query_invalid_ssid_length, -1},
	{"handle_beacon_metrics_query_invalid_ap_channel_report_length", "pkt9.pcap", construct_handle_beacon_metrics_query_invalid_ap_channel_report_length, -1},
	{"handle_beacon_metrics_query_invalid_element_list_overrun", "pkt10.pcap", construct_handle_beacon_metrics_query_invalid_element_list_overrun, -1},

	{NULL, NULL, NULL, 0}
};
