/*
 * UNIT TEST (input constructor): construct_wifi_hal_setNeighborReportActivation
 *
 * wifi_hal_setNeighborReportActivation(apIndex, activate) looks the interface up by vap_index over all radios and
 * stores `activate` in vap_info.u.bss_info.nbrReportActivated; an unknown index returns RETURN_ERR.
 *
 * The suite is a table of "worlds" (radios, their interfaces with vap_index / mode / activated flag / fill of the
 * union) plus the query, the value to set and the expected result; the runner
 * (wifi_hal_setNeighborReportActivation_test.cpp) builds the world in runner-owned slabs (REAL wifi_vap_info_t),
 * POISONS the tails, snapshots every interface, calls the function, unpoisons and checks that exactly the flag
 * of the expected interface changed (and no other byte of any interface).
 * Inputs crossed: AP VAPs (set 1 / 0, toggling, values 2 and 0xFF, vap_index 0 / 1 / 15 / INT_MAX), lookups across
 * 1..3 radios, unknown / negative / INT_MIN / 0x80000000 indexes (apIndex is a UINT), duplicate vap_index (first
 * wins), other interfaces left untouched, STA and monitor VAPs with the union pre-filled with 0x00 / 0x01 / 0xFF
 * (nbrReportActivated exists only in bss_info, at offset 45, which is another field of sta_info), repeated calls
 * and the log.  Expected result is the SAFE contract (a non-AP VAP is rejected and not modified), so a FAIL is a
 * finding.
 */
#include <limits.h>
#include "hwr_snr.h"

#define AP(i, en)       { (i), 0, (en), 0 }
#define STA(i, en, f)   { (i), 1, (en), (f) }
#define MON(i, en, f)   { (i), 2, (en), (f) }
#define RD(n, ...)      { (n), { __VA_ARGS__ } }
#define NONE            { 0, { } }
/* name, nradios, radios[3], query, activate, calls, check_log, expected_ret, expected_set */
hwr_snr_case_t wifi_hal_setNeighborReportActivation_suite[] = {
	{ "ap_activate",                   1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 1, 1, 0, 0, 0 },
	{ "ap_deactivate",                 1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 0, 1, 0, 0, 0 },
	{ "ap_activate_already_activated", 1, { RD(1, AP(0, 1)), NONE, NONE }, 0, 1, 1, 0, 0, 0 },
	{ "ap_deactivate_already_off",     1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 0, 1, 0, 0, 0 },
	{ "ap_value_2",                    1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 2, 1, 0, 0, 0 },
	{ "ap_value_0xff",                 1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 0xFF, 1, 0, 0, 0 },
	{ "ap_index_1_of_2_only_it_changes", 1, { RD(2, AP(0, 0), AP(1, 0)), NONE, NONE }, 1, 1, 1, 0, 0, 1 },
	{ "ap_index_0_of_2_other_untouched", 1, { RD(2, AP(0, 1), AP(1, 1)), NONE, NONE }, 0, 0, 1, 0, 0, 0 },
	{ "ap_index_15",                   1, { RD(1, AP(15, 0)), NONE, NONE }, 15, 1, 1, 0, 0, 0 },
	{ "ap_index_int_max",              1, { RD(1, AP(INT_MAX, 0)), NONE, NONE }, INT_MAX, 1, 1, 0, 0, 0 },
	{ "ap_index_0x80000000",           1, { RD(1, AP(0x80000000u, 0)), NONE, NONE }, 0x80000000u, 1, 1, 0, 0, 0 },
	{ "second_radio_activate",         2, { RD(1, AP(0, 0)), RD(1, AP(1, 0)), NONE }, 1, 1, 1, 0, 0, 1 },
	{ "third_radio_deactivate",        3, { RD(1, AP(0, 1)), RD(1, AP(1, 1)), RD(1, AP(2, 1)) }, 2, 0, 1, 0, 0, 2 },
	{ "first_radio_second_of_three",   3, { RD(3, AP(0, 0), AP(1, 0), AP(2, 0)), NONE, NONE }, 1, 1, 1, 0, 0, 1 },
	{ "duplicate_vap_index_first_wins", 2, { RD(1, AP(3, 0)), RD(1, AP(3, 0)), NONE }, 3, 1, 1, 0, 0, 0 },
	/* ---- lookup failures: RETURN_ERR, nothing modified ---- */
	{ "unknown_index_no_radios",       0, { NONE, NONE, NONE }, 0, 1, 1, 0, -1, -1 },
	{ "unknown_index_not_present",     1, { RD(2, AP(0, 0), AP(1, 0)), NONE, NONE }, 5, 1, 1, 0, -1, -1 },
	{ "negative_index_minus_1",        1, { RD(1, AP(0, 0)), NONE, NONE }, (unsigned)-1, 1, 1, 0, -1, -1 },
	{ "index_int_min",                 1, { RD(1, AP(0, 0)), NONE, NONE }, (unsigned)INT_MIN, 1, 1, 0, -1, -1 },
	{ "radio_without_interfaces",      2, { NONE, NONE, NONE }, 0, 1, 1, 0, -1, -1 },
	{ "unknown_index_logs_error",      1, { RD(1, AP(0, 0)), NONE, NONE }, 9, 1, 1, 1, -1, -1 },
	/* ---- non-AP VAPs: nbrReportActivated is not a member of sta_info; the byte at offset 45 is another field ---- */
	{ "sta_vap_rejected_union_fill_00", 1, { RD(1, STA(0, 0, 0x00)), NONE, NONE }, 0, 1, 1, 0, -1, -1 },
	{ "sta_vap_rejected_union_fill_01", 1, { RD(1, STA(0, 0, 0x01)), NONE, NONE }, 0, 0, 1, 0, -1, -1 },
	{ "sta_vap_rejected_union_fill_ff", 1, { RD(1, STA(0, 0, 0xFF)), NONE, NONE }, 0, 1, 1, 0, -1, -1 },
	{ "sta_vap_after_ap_rejected",     1, { RD(2, AP(0, 0), STA(1, 0, 0x01)), NONE, NONE }, 1, 1, 1, 0, -1, -1 },
	{ "sta_vap_on_second_radio",       2, { RD(1, AP(0, 0)), RD(1, STA(1, 0, 0x00)), NONE }, 1, 1, 1, 0, -1, -1 },
	{ "monitor_vap_rejected_fill_00",  1, { RD(1, MON(0, 0, 0x00)), NONE, NONE }, 0, 1, 1, 0, -1, -1 },
	{ "monitor_vap_rejected_fill_ff",  1, { RD(1, MON(0, 0, 0xFF)), NONE, NONE }, 0, 1, 1, 0, -1, -1 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_result", 2, { RD(1, AP(0, 0)), RD(1, AP(1, 0)), NONE }, 1, 1, 3, 0, 0, 1 },
	{ "log_has_function_name_and_enter", 1, { RD(1, AP(0, 0)), NONE, NONE }, 0, 1, 1, 1, 0, 0 },
	{ NULL, 0, { NONE, NONE, NONE }, 0, 0, 0, 0, 0, 0 }
};
