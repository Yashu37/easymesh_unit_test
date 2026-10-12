#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int main() {
#if 0	
	run_all_tests_handle_bsta_cap_report();
	run_all_tests_get_first_tlv();
	run_all_tests_get_next_tlv();
	run_all_tests_handle_ap_metrics_response();
	run_all_tests_handle_channel_scan_rprt();
	run_all_tests_handle_channel_scan_req();
	run_all_tests_handle_unassoc_sta_link_metrics_tlv();
	run_all_tests_handle_ap_operational_bss();
        run_all_tests_handle_beacon_metrics_query();
#endif
	//run_all_tests_get_supported_service();
	run_all_tests_handle_channel_scan_req();
	return 0;
}
