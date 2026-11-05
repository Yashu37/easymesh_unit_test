/*
 * UNIT TEST (input constructor): construct_wifi_hal_getApNumDevicesAssociated
 *
 * wifi_hal_getApNumDevicesAssociated(apIndex, output_ulong) looks the interface up by vap_index over all radios
 * and stores interface->u.ap.hapd.num_sta in *output_ulong under hapd_lock; an unknown index returns -1.
 *
 * The suite is a table of "worlds" (radios, their interfaces with vap_index / mode / num_sta / fill of the u
 * union) plus the query and the expected result; the runner (wifi_hal_getApNumDevicesAssociated_test.cpp) builds
 * the world in runner-owned slabs (REAL wifi_vap_info_t), POISONS the tails, calls the function, unpoisons and
 * checks the result, the output, that hapd_lock is released and that no interface byte changed.
 * Inputs crossed: AP VAPs with 0 / 1 / 5 / 127 / INT_MAX stations, vap_index 0 / 1 / 15 / INT_MAX / 0xFFFFFFFF
 * (apIndex is an INT converted to the UINT of the lookup), lookups across 1..3 radios, unknown / negative /
 * INT_MIN indexes, duplicate vap_index (first wins), STA and monitor VAPs whose union is filled with 0x00 / 0x01
 * / 0x7F / 0xFF (u.ap.hapd.num_sta is read from those bytes), output untouched on a failure, repeated calls, the
 * log and a NULL output (forked, so the SEGV is visible but does not stop the run).
 * Expected result is the SAFE contract (non-AP VAPs rejected, NULL output rejected, lock released), so a FAIL is
 * a finding.
 */
#include <limits.h>
#include "hwr_gnd.h"

#define AP(i, n)        { (i), 0, (n), 0 }
#define STA(i, f)       { (i), 1, 0, (f) }
#define MON(i, f)       { (i), 2, 0, (f) }
#define RD(n, ...)      { (n), { __VA_ARGS__ } }
#define NONE            { 0, { } }
/* name, nradios, radios[3], query, null_out, calls, check_log, expected_ret, expected_out, forked */
hwr_gnd_case_t wifi_hal_getApNumDevicesAssociated_suite[] = {
	{ "ap_no_stations",                1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 0, 1, 0, 0, 0, 0 },
	{ "ap_one_station",                1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 0, 1, 0, 0, 1, 0 },
	{ "ap_five_stations",              1, { RD(1, AP(0, 5)), NONE, NONE }, 0, 0, 1, 0, 0, 5, 0 },
	{ "ap_127_stations",               1, { RD(1, AP(0, 127)), NONE, NONE }, 0, 0, 1, 0, 0, 127, 0 },
	{ "ap_int_max_stations",           1, { RD(1, AP(0, INT_MAX)), NONE, NONE }, 0, 0, 1, 0, 0, INT_MAX, 0 },
	{ "ap_index_1_of_2",               1, { RD(2, AP(0, 3), AP(1, 7)), NONE, NONE }, 1, 0, 1, 0, 0, 7, 0 },
	{ "ap_index_0_of_2",               1, { RD(2, AP(0, 3), AP(1, 7)), NONE, NONE }, 0, 0, 1, 0, 0, 3, 0 },
	{ "ap_index_15",                   1, { RD(1, AP(15, 2)), NONE, NONE }, 15, 0, 1, 0, 0, 2, 0 },
	{ "ap_index_int_max",              1, { RD(1, AP(INT_MAX, 4)), NONE, NONE }, INT_MAX, 0, 1, 0, 0, 4, 0 },
	{ "ap_index_minus_1_is_0xffffffff", 1, { RD(1, AP(0xFFFFFFFFu, 6)), NONE, NONE }, -1, 0, 1, 0, 0, 6, 0 },
	{ "second_radio",                  2, { RD(1, AP(0, 3)), RD(1, AP(1, 9)), NONE }, 1, 0, 1, 0, 0, 9, 0 },
	{ "third_radio",                   3, { RD(1, AP(0, 1)), RD(1, AP(1, 2)), RD(1, AP(2, 3)) }, 2, 0, 1, 0, 0, 3, 0 },
	{ "first_radio_second_of_three",   3, { RD(3, AP(0, 1), AP(1, 8), AP(2, 3)), NONE, NONE }, 1, 0, 1, 0, 0, 8, 0 },
	{ "duplicate_vap_index_first_wins", 2, { RD(1, AP(3, 11)), RD(1, AP(3, 22)), NONE }, 3, 0, 1, 0, 0, 11, 0 },
	/* ---- lookup failures: -1, output untouched ---- */
	{ "unknown_index_no_radios",       0, { NONE, NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "unknown_index_not_present",     1, { RD(2, AP(0, 1), AP(1, 1)), NONE, NONE }, 5, 0, 1, 0, -1, -1, 0 },
	{ "negative_index_minus_1",        1, { RD(1, AP(0, 1)), NONE, NONE }, -1, 0, 1, 0, -1, -1, 0 },
	{ "index_int_min",                 1, { RD(1, AP(0, 1)), NONE, NONE }, INT_MIN, 0, 1, 0, -1, -1, 0 },
	{ "radio_without_interfaces",      2, { NONE, NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "unknown_index_logs_error",      1, { RD(1, AP(0, 1)), NONE, NONE }, 9, 0, 1, 2, -1, -1, 0 },
	/* ---- non-AP VAPs: u.ap.hapd.num_sta is read from the STA state bytes ---- */
	{ "sta_vap_rejected_union_fill_00", 1, { RD(1, STA(0, 0x00)), NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "sta_vap_rejected_union_fill_01", 1, { RD(1, STA(0, 0x01)), NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "sta_vap_rejected_union_fill_7f", 1, { RD(1, STA(0, 0x7F)), NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "sta_vap_rejected_union_fill_ff", 1, { RD(1, STA(0, 0xFF)), NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "sta_vap_after_ap_rejected",     1, { RD(2, AP(0, 2), STA(1, 0x01)), NONE, NONE }, 1, 0, 1, 0, -1, -1, 0 },
	{ "sta_vap_on_second_radio",       2, { RD(1, AP(0, 2)), RD(1, STA(1, 0x05)), NONE }, 1, 0, 1, 0, -1, -1, 0 },
	{ "monitor_vap_rejected_fill_00",  1, { RD(1, MON(0, 0x00)), NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	{ "monitor_vap_rejected_fill_01",  1, { RD(1, MON(0, 0x01)), NONE, NONE }, 0, 0, 1, 0, -1, -1, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_result", 2, { RD(1, AP(0, 4)), RD(1, AP(1, 6)), NONE }, 1, 0, 3, 0, 0, 6, 0 },
	{ "log_has_function_name_and_count", 1, { RD(1, AP(0, 12)), NONE, NONE }, 0, 0, 1, 1, 0, 12, 0 },
	/* ---- NULL output ---- */
	{ "output_null_unknown_index",     1, { RD(1, AP(0, 1)), NONE, NONE }, 9, 1, 1, 0, -1, -1, 0 },
	{ "crash_output_null_ap_no_stations", 1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 1, 1, 0, -1, -1, 1 },
	{ "crash_output_null_ap_with_stations", 1, { RD(1, AP(0, 5)), NONE, NONE }, 0, 1, 1, 0, -1, -1, 1 },
	{ "crash_output_null_second_radio", 2, { RD(1, AP(0, 1)), RD(1, AP(1, 2)), NONE }, 1, 1, 1, 0, -1, -1, 1 },
	{ "crash_output_null_sta_vap",     1, { RD(1, STA(0, 0x01)), NONE, NONE }, 0, 1, 1, 0, -1, -1, 1 },
	{ NULL, 0, { NONE, NONE, NONE }, 0, 0, 0, 0, 0, 0, 0 }
};
