/*
 * UNIT TEST (input constructor): construct_wifi_hal_getSSIDNameStatus
 *
 * wifi_hal_getSSIDNameStatus(apIndex, output_string) looks the interface up by vap_index over all radios and
 * strcpy()s vap_info.u.bss_info.ssid into the caller's buffer (ipc_server_output allocates
 * HAL_IPC_MAX_STRING_LEN = 64 bytes); an unknown index returns RETURN_ERR.
 *
 * The suite is a table of "worlds" (radios, interfaces with vap_index / mode / ssid bytes / fill of the rest of
 * the union) plus the query and the expected output; the runner (wifi_hal_getSSIDNameStatus_test.cpp) builds the
 * world in runner-owned slabs (REAL wifi_vap_info_t), POISONS the tails (including the bytes behind the 64-byte
 * output buffer), calls the function, unpoisons and checks.
 * Inputs crossed: SSIDs of 0, 1, 6, 11, 31, 32 and 33 bytes (the 33-byte AP field and the 32-byte STA field
 * are NOT NUL terminated when completely used, so strcpy() runs into the bytes behind them: zero, 'B' and 0xFF
 * fills), AP / STA / monitor VAPs, lookups across 1..2 radios, unknown / negative / INT_MIN indexes, duplicate
 * vap_index, output untouched on a failed lookup, repeated calls, the log, and a NULL output_string (forked).
 * Rows that overflow the output buffer are forked so the ASan report is visible but the run continues.
 * Expected result is the SAFE contract (at most 32 SSID bytes are copied and the output is NUL terminated),
 * so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gsn.h"

#define S32 "0123456789abcdef0123456789abcdef"
#define S33 "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"
#define S32S "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"
#define AP(i, s, f)   { (i), 0, (s), (f) }
#define STA(i, s, f)  { (i), 1, (s), (f) }
#define MON(i, s, f)  { (i), 2, (s), (f) }
#define RD(n, ...)    { (n), { __VA_ARGS__ } }
#define NONE          { 0, { } }
#define UT            NULL
/* name, nradios, radios[3], query, null_out, calls, check_log, expected_ret, expected_out, forked */
hwr_gsn_case_t wifi_hal_getSSIDNameStatus_suite[] = {
	{ "ap_ssid_empty",                 1, { RD(1, AP(0, "", 0)), NONE, NONE }, 0, 0, 1, 0, 0, "", 0 },
	{ "ap_ssid_1_char",                1, { RD(1, AP(0, "a", 0)), NONE, NONE }, 0, 0, 1, 0, 0, "a", 0 },
	{ "ap_ssid_ascii",                 1, { RD(1, AP(0, "MyHomeWiFi", 0)), NONE, NONE }, 0, 0, 1, 0, 0, "MyHomeWiFi", 0 },
	{ "ap_ssid_with_spaces",           1, { RD(1, AP(0, "My Home WiFi 5G", 0)), NONE, NONE }, 0, 0, 1, 0, 0, "My Home WiFi 5G", 0 },
	{ "ap_ssid_utf8",                  1, { RD(1, AP(0, "caf\xc3\xa9-net", 0)), NONE, NONE }, 0, 0, 1, 0, 0, "caf\xc3\xa9-net", 0 },
	{ "ap_ssid_31_chars",              1, { RD(1, AP(0, "0123456789abcdef0123456789abcde", 0)), NONE, NONE }, 0, 0, 1, 0, 0, "0123456789abcdef0123456789abcde", 0 },
	{ "ap_ssid_32_chars_nul_fits",     1, { RD(1, AP(0, S32, 0)), NONE, NONE }, 0, 0, 1, 0, 0, S32, 0 },
	{ "ap_ssid_32_chars_fill_B",       1, { RD(1, AP(0, S32, 'B')), NONE, NONE }, 0, 0, 1, 0, 0, S32, 0 },
	{ "ap_ssid_short_fill_B",          1, { RD(1, AP(0, "net", 'B')), NONE, NONE }, 0, 0, 1, 0, 0, "net", 0 },
	{ "ap_ssid_short_fill_ff",         1, { RD(1, AP(0, "net", 0xFF)), NONE, NONE }, 0, 0, 1, 0, 0, "net", 0 },
	{ "ap_index_1_of_2",               1, { RD(2, AP(0, "first", 0), AP(1, "second", 0)), NONE, NONE }, 1, 0, 1, 0, 0, "second", 0 },
	{ "ap_second_radio",               2, { RD(1, AP(0, "r0", 0)), RD(1, AP(1, "r1", 0)), NONE }, 1, 0, 1, 0, 0, "r1", 0 },
	{ "ap_index_int_max",              1, { RD(1, AP(INT_MAX, "big", 0)), NONE, NONE }, INT_MAX, 0, 1, 0, 0, "big", 0 },
	{ "duplicate_vap_index_first_wins", 2, { RD(1, AP(3, "one", 0)), RD(1, AP(3, "two", 0)), NONE }, 3, 0, 1, 0, 0, "one", 0 },
	{ "sta_ssid_short",                1, { RD(1, STA(0, "BackhaulNet", 0)), NONE, NONE }, 0, 0, 1, 0, 0, "BackhaulNet", 0 },
	{ "sta_ssid_short_fill_B",         1, { RD(1, STA(0, "BackhaulNet", 'B')), NONE, NONE }, 0, 0, 1, 0, 0, "BackhaulNet", 0 },
	{ "sta_ssid_31_chars_fill_B",      1, { RD(1, STA(0, "0123456789abcdef0123456789abcde", 'B')), NONE, NONE }, 0, 0, 1, 0, 0, "0123456789abcdef0123456789abcde", 0 },
	{ "sta_ssid_32_chars_fill_0",      1, { RD(1, STA(0, S32, 0)), NONE, NONE }, 0, 0, 1, 0, 0, S32, 0 },
	{ "sta_after_ap",                  1, { RD(2, AP(0, "ap", 0), STA(1, "sta", 0)), NONE, NONE }, 1, 0, 1, 0, 0, "sta", 0 },
	{ "monitor_vap_rejected",          1, { RD(1, MON(0, "mon", 0)), NONE, NONE }, 0, 0, 1, 0, -1, UT, 0 },
	/* ---- the SSID field completely used: no NUL, strcpy runs on into whatever follows ---- */
	{ "ap_ssid_33_no_nul_followed_by_0", 1, { RD(1, AP(0, S33, 0)), NONE, NONE }, 0, 0, 1, 0, 0, S32S, 0 },
	/* ---- lookup failures: RETURN_ERR, output untouched ---- */
	{ "unknown_index_no_radios",       0, { NONE, NONE, NONE }, 0, 0, 1, 0, -1, UT, 0 },
	{ "unknown_index_not_present",     1, { RD(2, AP(0, "a", 0), AP(1, "b", 0)), NONE, NONE }, 5, 0, 1, 0, -1, UT, 0 },
	{ "negative_index_minus_1",        1, { RD(1, AP(0, "a", 0)), NONE, NONE }, -1, 0, 1, 0, -1, UT, 0 },
	{ "index_int_min",                 1, { RD(1, AP(0, "a", 0)), NONE, NONE }, INT_MIN, 0, 1, 0, -1, UT, 0 },
	{ "radio_without_interfaces",      2, { NONE, NONE, NONE }, 0, 0, 1, 0, -1, UT, 0 },
	{ "unknown_index_logs_error",      1, { RD(1, AP(0, "a", 0)), NONE, NONE }, 9, 0, 1, 1, -1, UT, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_result", 2, { RD(1, AP(0, "r0", 0)), RD(1, AP(1, "r1name", 0)), NONE }, 1, 0, 3, 0, 0, "r1name", 0 },
	{ "log_has_function_name_and_enter", 1, { RD(1, AP(0, "x", 0)), NONE, NONE }, 0, 0, 1, 1, 0, "x", 0 },
	/* ---- crash group (forked): SSID field not terminated, followed by non-zero bytes -> output buffer overflow ---- */
	{ "crash_ap_ssid_33_no_nul_fill_B",  1, { RD(1, AP(0, S33, 'B')), NONE, NONE }, 0, 0, 1, 0, 0, S32S, 1 },
	{ "crash_ap_ssid_33_no_nul_fill_ff", 1, { RD(1, AP(0, S33, 0xFF)), NONE, NONE }, 0, 0, 1, 0, 0, S32S, 1 },
	{ "crash_sta_ssid_32_no_nul_fill_B", 1, { RD(1, STA(0, S32, 'B')), NONE, NONE }, 0, 0, 1, 0, 0, S32, 1 },
	{ "crash_sta_ssid_32_no_nul_fill_ff", 1, { RD(1, STA(0, S32, 0xFF)), NONE, NONE }, 0, 0, 1, 0, 0, S32, 1 },
	/* ---- crash group (forked): NULL output_string, interface found ---- */
	{ "crash_output_null_ap",          1, { RD(1, AP(0, "ap", 0)), NONE, NONE }, 0, 1, 1, 0, -1, UT, 1 },
	{ "crash_output_null_sta",         1, { RD(1, STA(0, "sta", 0)), NONE, NONE }, 0, 1, 1, 0, -1, UT, 1 },
	{ "crash_output_null_second_radio", 2, { RD(1, AP(0, "a", 0)), RD(1, AP(1, "b", 0)), NONE }, 1, 1, 1, 0, -1, UT, 1 },
	{ "output_null_unknown_index",     1, { RD(1, AP(0, "a", 0)), NONE, NONE }, 7, 1, 1, 0, -1, UT, 0 },
	{ NULL, 0, { NONE, NONE, NONE }, 0, 0, 0, 0, 0, 0, 0 }
};
