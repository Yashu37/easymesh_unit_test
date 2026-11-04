/*
 * UNIT TEST (input constructor): construct_wifi_hal_getSSIDEnable
 *
 * wifi_hal_getSSIDEnable(ssidIndex, output_bool) looks the interface up by vap_index over all radios and
 * stores vap_info.u.bss_info.enabled in *output_bool; an unknown index returns RETURN_ERR.
 *
 * The suite is a table of "worlds" (radios, their interfaces with vap_index / mode / enabled) plus the query
 * and the expected result; the runner (wifi_hal_getSSIDEnable_test.cpp) builds the world in runner-owned
 * slabs, POISONS the tails, calls the function, unpoisons and checks.  Interfaces use the REAL wifi_vap_info_t.
 * Inputs crossed: AP VAPs (enabled 0 / 1, vap_index 0 / 1 / 15 / INT_MAX), lookups across 1..3 radios, unknown
 * / negative / INT_MIN / 0x80000000 indexes, duplicate vap_index (first wins), STA and monitor VAPs with the
 * union pre-filled with 0x00 / 0x01 / 0xFF (so a read through the wrong union member is visible), the output
 * left untouched on a failed lookup, repeated calls, the log, and a NULL output_bool (forked, so the SEGV is
 * visible but does not stop the run).  Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gse.h"

#define AP(i, en)       { (i), 0, (en), 0 }
#define STA(i, en, f)   { (i), 1, (en), (f) }
#define MON(i, en, f)   { (i), 2, (en), (f) }
#define RD(n, ...)      { (n), { __VA_ARGS__ } }
#define NONE            { 0, { } }
/* name, nradios, radios[3], query, null_out, calls, check_log, expected_ret, expected_out, forked */
hwr_gse_case_t wifi_hal_getSSIDEnable_suite[] = {
	{ "ap_enabled",                    1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 0, 1, 0, 0, 1, 0 },
	{ "ap_disabled",                   1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 0, 1, 0, 0, 0, 0 },
	{ "ap_index_1_enabled",            1, { RD(2, AP(0, 0), AP(1, 1)), NONE, NONE }, 1, 0, 1, 0, 0, 1, 0 },
	{ "ap_index_1_disabled",           1, { RD(2, AP(0, 1), AP(1, 0)), NONE, NONE }, 1, 0, 1, 0, 0, 0, 0 },
	{ "ap_index_15",                   1, { RD(1, AP(15, 1)), NONE, NONE }, 15, 0, 1, 0, 0, 1, 0 },
	{ "ap_index_int_max",              1, { RD(1, AP(INT_MAX, 1)), NONE, NONE }, INT_MAX, 0, 1, 0, 0, 1, 0 },
	{ "second_radio_ap_enabled",       2, { RD(1, AP(0, 0)), RD(1, AP(1, 1)), NONE }, 1, 0, 1, 0, 0, 1, 0 },
	{ "second_radio_ap_disabled",      2, { RD(1, AP(0, 1)), RD(1, AP(1, 0)), NONE }, 1, 0, 1, 0, 0, 0, 0 },
	{ "third_radio_ap_enabled",        3, { RD(1, AP(0, 0)), RD(1, AP(1, 0)), RD(1, AP(2, 1)) }, 2, 0, 1, 0, 0, 1, 0 },
	{ "first_radio_second_of_three",   3, { RD(3, AP(0, 0), AP(1, 1), AP(2, 0)), NONE, NONE }, 1, 0, 1, 0, 0, 1, 0 },
	{ "duplicate_vap_index_first_wins", 2, { RD(1, AP(3, 1)), RD(1, AP(3, 0)), NONE }, 3, 0, 1, 0, 0, 1, 0 },
	/* ---- lookup failures: RETURN_ERR, output untouched ---- */
	{ "unknown_index_no_radios",       0, { NONE, NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "unknown_index_not_present",     1, { RD(2, AP(0, 1), AP(1, 1)), NONE, NONE }, 5, 0, 1, 0, -1, -1, 0 },
	{ "negative_index_minus_1",        1, { RD(1, AP(0, 1)), NONE, NONE }, -1, 0, 1, 0, -1, -1, 0 },
	{ "index_int_min",                 1, { RD(1, AP(0, 1)), NONE, NONE }, INT_MIN, 0, 1, 0, -1, -1, 0 },
	{ "radio_without_interfaces",      2, { NONE, NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "unknown_index_logs_error",      1, { RD(1, AP(0, 1)), NONE, NONE }, 9, 0, 1, 1, -1, -1, 0 },
	/* ---- STA / monitor VAPs: u is a union, bss_info is only valid for AP VAPs ---- */
	{ "sta_enabled_union_fill_00",     1, { RD(1, STA(0, 1, 0x00)), NONE, NONE }, 0, 0, 1, 0, 0, 1, 0 },
	{ "sta_enabled_union_fill_01",     1, { RD(1, STA(0, 1, 0x01)), NONE, NONE }, 0, 0, 1, 0, 0, 1, 0 },
	{ "sta_enabled_union_fill_ff",     1, { RD(1, STA(0, 1, 0xFF)), NONE, NONE }, 0, 0, 1, 0, 0, 1, 0 },
	{ "sta_disabled_union_fill_00",    1, { RD(1, STA(0, 0, 0x00)), NONE, NONE }, 0, 0, 1, 0, 0, 0, 0 },
	{ "sta_disabled_union_fill_01",    1, { RD(1, STA(0, 0, 0x01)), NONE, NONE }, 0, 0, 1, 0, 0, 0, 0 },
	{ "sta_disabled_union_fill_ff",    1, { RD(1, STA(0, 0, 0xFF)), NONE, NONE }, 0, 0, 1, 0, 0, 0, 0 },
	{ "sta_after_ap_disabled_fill_01", 1, { RD(2, AP(0, 1), STA(1, 0, 0x01)), NONE, NONE }, 1, 0, 1, 0, 0, 0, 0 },
	{ "monitor_vap_rejected_fill_00",  1, { RD(1, MON(0, 1, 0x00)), NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "monitor_vap_rejected_fill_01",  1, { RD(1, MON(0, 1, 0x01)), NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_result", 2, { RD(1, AP(0, 0)), RD(1, AP(1, 1)), NONE }, 1, 0, 3, 0, 0, 1, 0 },
	{ "log_has_function_name_and_enter", 1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 0, 1, 1, 0, 1, 0 },
	/* ---- crash group (forked): NULL output_bool, interface found ---- */
	{ "crash_output_null_ap_enabled",  1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 1, 1, 0, -1, -1, 1 },
	{ "crash_output_null_ap_disabled", 1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 1, 1, 0, -1, -1, 1 },
	{ "crash_output_null_second_radio", 2, { RD(1, AP(0, 1)), RD(1, AP(1, 1)), NONE }, 1, 1, 1, 0, -1, -1, 1 },
	{ "output_null_unknown_index",     1, { RD(1, AP(0, 1)), NONE, NONE }, 7, 1, 1, 0, -1, -1, 0 },
	{ NULL, 0, { NONE, NONE, NONE }, 0, 0, 0, 0, 0, 0, 0 }
};
