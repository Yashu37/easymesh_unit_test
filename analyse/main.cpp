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
#endif
	run_all_tests_handle_channel_scan_rprt();
	return 0;
}
