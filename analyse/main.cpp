#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int main() {
	/* unbuffered stdout so per-test lines flush before any crash/abort */
	setvbuf(stdout, NULL, _IONBF, 0);
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
        run_all_tests_get_supported_service();
	run_all_tests_handle_channel_scan_req();
	run_all_tests_get_radio_id_channel_scan_req();
#endif
	// base64_decode OOB crash check (OneWifi lib/common/util.c).
	// Kept last: it aborts under ASan on invalid-char input.
//	run_all_tests_base64_decode();

	// base64_encode OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_base64_encode();

	// cmd_log OOB crash check (OneWifi lib/common/os.c).
//	run_all_tests_cmd_log();

	// file_get OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_file_get();

	// mon_check_process OOB crash check (OneWifi lib/common/monitor.c).
//	run_all_tests_mon_check_process();

	// mon_sig_crash OOB crash check (OneWifi lib/common/monitor.c).
//	run_all_tests_mon_sig_crash();

	// mon_sig_forward OOB crash check (OneWifi lib/common/monitor.c).
//	run_all_tests_mon_sig_forward();

	// mon_sig_str OOB crash check (OneWifi lib/common/monitor.c).
//	run_all_tests_mon_sig_str();

	// os_cmd_exec_xv OOB crash check (OneWifi lib/common/os_exec.c).
//	run_all_tests_os_cmd_exec_xv();

	// os_pid_from_file OOB crash check (OneWifi lib/common/os.c).
//	run_all_tests_os_pid_from_file();

	// os_popen OOB crash check (OneWifi lib/common/os.c).
//	run_all_tests_os_popen();

	// parse_uri OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_parse_uri();

	// strexread OOB crash check (OneWifi lib/common/util.c).
//	run_all_tests_strexread();

	// unii_5g_chan2list OOB crash check (OneWifi lib/common/util.c).
	run_all_tests_unii_5g_chan2list();
	return 0;
}
