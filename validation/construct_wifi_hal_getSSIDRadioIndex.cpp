/*
 * UNIT TEST (input constructor): construct_wifi_hal_getSSIDRadioIndex
 *
 * wifi_hal_getSSIDRadioIndex(ssidIndex, radioIndex) looks the interface up by vap_index over all radios and
 * stores vap_info.radio_index in *radioIndex; an unknown index returns RETURN_ERR.
 *
 * The suite is a table of "worlds" (radios, their interfaces with vap_index / mode / radio_index) plus the
 * query and the expected result; the runner (wifi_hal_getSSIDRadioIndex_test.cpp) builds the world in
 * runner-owned slabs (REAL wifi_vap_info_t), POISONS the tails, calls the function, unpoisons and checks.
 * Inputs crossed: AP / STA / monitor VAPs, vap_index 0 / 1 / 15 / INT_MAX, radio_index 0 / 1 / 2 / 3 / 15,
 * lookups across 1..3 radios, unknown / negative / INT_MIN indexes, duplicate vap_index (first wins), the output
 * left untouched on a failed lookup, repeated calls, the log, and a NULL radioIndex (forked, so the SEGV is
 * visible but does not stop the run).  Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gsr.h"

#define AP(i, r)   { (i), 0, (r) }
#define STA(i, r)  { (i), 1, (r) }
#define MON(i, r)  { (i), 2, (r) }
#define RD(n, ...) { (n), { __VA_ARGS__ } }
#define NONE       { 0, { } }
#define UNTOUCHED  LLONG_MIN
/* name, nradios, radios[3], query, null_out, calls, check_log, expected_ret, expected_out, forked */
hwr_gsr_case_t wifi_hal_getSSIDRadioIndex_suite[] = {
	{ "ap_radio_0",                    1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 0, 1, 0, 0, 0, 0 },
	{ "ap_radio_1",                    1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 0, 1, 0, 0, 1, 0 },
	{ "ap_radio_2",                    1, { RD(1, AP(0, 2)), NONE, NONE }, 0, 0, 1, 0, 0, 2, 0 },
	{ "ap_radio_3",                    1, { RD(1, AP(0, 3)), NONE, NONE }, 0, 0, 1, 0, 0, 3, 0 },
	{ "ap_radio_15",                   1, { RD(1, AP(0, 15)), NONE, NONE }, 0, 0, 1, 0, 0, 15, 0 },
	{ "ap_index_1_of_2",               1, { RD(2, AP(0, 0), AP(1, 1)), NONE, NONE }, 1, 0, 1, 0, 0, 1, 0 },
	{ "ap_index_0_of_2",               1, { RD(2, AP(0, 2), AP(1, 3)), NONE, NONE }, 0, 0, 1, 0, 0, 2, 0 },
	{ "ap_index_15",                   1, { RD(1, AP(15, 1)), NONE, NONE }, 15, 0, 1, 0, 0, 1, 0 },
	{ "ap_index_int_max",              1, { RD(1, AP(INT_MAX, 1)), NONE, NONE }, INT_MAX, 0, 1, 0, 0, 1, 0 },
	{ "second_radio",                  2, { RD(1, AP(0, 0)), RD(1, AP(1, 1)), NONE }, 1, 0, 1, 0, 0, 1, 0 },
	{ "third_radio",                   3, { RD(1, AP(0, 0)), RD(1, AP(1, 1)), RD(1, AP(2, 2)) }, 2, 0, 1, 0, 0, 2, 0 },
	{ "three_vaps_on_one_radio",       3, { RD(3, AP(0, 1), AP(1, 1), AP(2, 1)), NONE, NONE }, 2, 0, 1, 0, 0, 1, 0 },
	{ "vap_on_radio_other_than_its_map", 2, { RD(1, AP(0, 1)), RD(1, AP(1, 0)), NONE }, 0, 0, 1, 0, 0, 1, 0 },
	{ "duplicate_vap_index_first_wins", 2, { RD(1, AP(3, 1)), RD(1, AP(3, 0)), NONE }, 3, 0, 1, 0, 0, 1, 0 },
	{ "sta_vap_radio_1",               1, { RD(1, STA(0, 1)), NONE, NONE }, 0, 0, 1, 0, 0, 1, 0 },
	{ "sta_vap_after_ap",              1, { RD(2, AP(0, 0), STA(1, 1)), NONE, NONE }, 1, 0, 1, 0, 0, 1, 0 },
	{ "monitor_vap_radio_2",           1, { RD(1, MON(0, 2)), NONE, NONE }, 0, 0, 1, 0, 0, 2, 0 },
	/* ---- lookup failures: RETURN_ERR, output untouched ---- */
	{ "unknown_index_no_radios",       0, { NONE, NONE, NONE }, 0, 0, 1, 0, -1, UNTOUCHED, 0 },
	{ "unknown_index_not_present",     1, { RD(2, AP(0, 1), AP(1, 1)), NONE, NONE }, 5, 0, 1, 0, -1, UNTOUCHED, 0 },
	{ "negative_index_minus_1",        1, { RD(1, AP(0, 1)), NONE, NONE }, -1, 0, 1, 0, -1, UNTOUCHED, 0 },
	{ "index_int_min",                 1, { RD(1, AP(0, 1)), NONE, NONE }, INT_MIN, 0, 1, 0, -1, UNTOUCHED, 0 },
	{ "radio_without_interfaces",      2, { NONE, NONE, NONE }, 0, 0, 1, 0, -1, UNTOUCHED, 0 },
	{ "unknown_index_logs_error",      1, { RD(1, AP(0, 1)), NONE, NONE }, 9, 0, 1, 1, -1, UNTOUCHED, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_result", 2, { RD(1, AP(0, 0)), RD(1, AP(1, 1)), NONE }, 1, 0, 3, 0, 0, 1, 0 },
	{ "log_has_function_name_and_enter", 1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 0, 1, 1, 0, 1, 0 },
	/* ---- crash group (forked): NULL radioIndex, interface found ---- */
	{ "crash_output_null_radio_0",     1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 1, 1, 0, -1, UNTOUCHED, 1 },
	{ "crash_output_null_radio_1",     1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 1, 1, 0, -1, UNTOUCHED, 1 },
	{ "crash_output_null_second_radio", 2, { RD(1, AP(0, 1)), RD(1, AP(1, 1)), NONE }, 1, 1, 1, 0, -1, UNTOUCHED, 1 },
	{ "crash_output_null_sta_vap",     1, { RD(1, STA(0, 1)), NONE, NONE }, 0, 1, 1, 0, -1, UNTOUCHED, 1 },
	{ "output_null_unknown_index",     1, { RD(1, AP(0, 1)), NONE, NONE }, 7, 1, 1, 0, -1, UNTOUCHED, 0 },
	{ NULL, 0, { NONE, NONE, NONE }, 0, 0, 0, 0, 0, 0, 0 }
};
