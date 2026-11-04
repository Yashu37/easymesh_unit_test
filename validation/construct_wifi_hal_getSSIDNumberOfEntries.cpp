/*
 * UNIT TEST (input constructor): construct_wifi_hal_getSSIDNumberOfEntries
 *
 * wifi_hal_getSSIDNumberOfEntries(numEntries) counts the AP VAPs (vap_index >= 0 as an int, vap_mode ==
 * wifi_vap_mode_ap) over the interfaces of every radio and stores the count in *numEntries.
 *
 * The suite is a table of "worlds" (radios, their rdk index, their interfaces with vap_index / mode) plus
 * the expected count; the runner (wifi_hal_getSSIDNumberOfEntries_test.cpp) builds the world in
 * runner-owned slabs, POISONS the tails, calls the function, unpoisons and checks the result.
 * Inputs crossed: 0..4 radios, 0..8 interfaces per radio, AP / STA / monitor modes, vap_index 0 / INT_MAX /
 * 0x80000000 / UINT_MAX, radios whose rdk index is not their position (swapped, shifted, with a gap), a
 * preset (garbage / zero) output value, repeated calls, the log text and a NULL numEntries (forked, so the
 * SEGV is visible but does not stop the run).  Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <stdarg.h>
#include <limits.h>
#include "hwr_ssid.h"


#define AP(i)  { (i), 0 }
#define STA(i) { (i), 1 }
#define MON(i) { (i), 2 }
#define RD(idx, n, ...) { (idx), (n), { __VA_ARGS__ } }
#define NONE { 0, 0, { } }
/* name, nradios, radios[4], null_out, calls, preset_garbage, check_log, expected, forked */
hwr_ssid_case_t wifi_hal_getSSIDNumberOfEntries_suite[] = {
	{ "no_radios",                      0, { NONE, NONE, NONE, NONE }, 0, 1, 0, 0, 0, 0 },
	{ "one_radio_no_interfaces",        1, { RD(0, 0, ), NONE, NONE, NONE }, 0, 1, 0, 0, 0, 0 },
	{ "one_radio_one_ap",               1, { RD(0, 1, AP(0)), NONE, NONE, NONE }, 0, 1, 0, 0, 1, 0 },
	{ "one_radio_sta_only",             1, { RD(0, 1, STA(0)), NONE, NONE, NONE }, 0, 1, 0, 0, 0, 0 },
	{ "one_radio_monitor_only",         1, { RD(0, 1, MON(0)), NONE, NONE, NONE }, 0, 1, 0, 0, 0, 0 },
	{ "one_radio_ap_sta_mix",           1, { RD(0, 2, AP(0), STA(1)), NONE, NONE, NONE }, 0, 1, 0, 0, 1, 0 },
	{ "one_radio_three_ap",             1, { RD(0, 3, AP(0), AP(1), AP(2)), NONE, NONE, NONE }, 0, 1, 0, 0, 3, 0 },
	{ "one_radio_eight_ap_map_full",    1, { RD(0, 8, AP(0), AP(1), AP(2), AP(3), AP(4), AP(5), AP(6), AP(7)), NONE, NONE, NONE }, 0, 1, 0, 0, 8, 0 },
	{ "one_radio_ap_sta_monitor_mix",   1, { RD(0, 4, AP(0), STA(1), MON(2), AP(3)), NONE, NONE, NONE }, 0, 1, 0, 0, 2, 0 },
	{ "two_radios_one_ap_each",         2, { RD(0, 1, AP(0)), RD(1, 1, AP(1)), NONE, NONE }, 0, 1, 0, 0, 2, 0 },
	{ "two_radios_two_ap_each",         2, { RD(0, 2, AP(0), AP(2)), RD(1, 2, AP(1), AP(3)), NONE, NONE }, 0, 1, 0, 0, 4, 0 },
	{ "two_radios_second_empty",        2, { RD(0, 2, AP(0), AP(1)), RD(1, 0, ), NONE, NONE }, 0, 1, 0, 0, 2, 0 },
	{ "two_radios_first_empty",         2, { RD(0, 0, ), RD(1, 2, AP(0), AP(1)), NONE, NONE }, 0, 1, 0, 0, 2, 0 },
	{ "two_radios_mixed_modes",         2, { RD(0, 3, AP(0), STA(1), AP(2)), RD(1, 2, MON(3), AP(4)), NONE, NONE }, 0, 1, 0, 0, 3, 0 },
	{ "three_radios_one_ap_each",       3, { RD(0, 1, AP(0)), RD(1, 1, AP(1)), RD(2, 1, AP(2)), NONE }, 0, 1, 0, 0, 3, 0 },
	{ "four_radios_four_ap_each",       4, { RD(0, 4, AP(0), AP(1), AP(2), AP(3)), RD(1, 4, AP(4), AP(5), AP(6), AP(7)), RD(2, 4, AP(8), AP(9), AP(10), AP(11)), RD(3, 4, AP(12), AP(13), AP(14), AP(15)) }, 0, 1, 0, 0, 16, 0 },
	{ "vap_index_zero_counted",         1, { RD(0, 1, AP(0)), NONE, NONE, NONE }, 0, 1, 0, 0, 1, 0 },
	{ "vap_index_int_max_counted",      1, { RD(0, 1, AP(INT_MAX)), NONE, NONE, NONE }, 0, 1, 0, 0, 1, 0 },
	{ "vap_index_0x80000000_not_counted", 1, { RD(0, 1, AP(0x80000000u)), NONE, NONE, NONE }, 0, 1, 0, 0, 0, 0 },
	{ "vap_index_uint_max_not_counted", 1, { RD(0, 1, AP(UINT_MAX)), NONE, NONE, NONE }, 0, 1, 0, 0, 0, 0 },
	{ "vap_index_negative_and_valid",   1, { RD(0, 3, AP(UINT_MAX), AP(1), AP(2)), NONE, NONE, NONE }, 0, 1, 0, 0, 2, 0 },
	/* ---- rdk radio index vs position in radio_info[] ---- */
	{ "radio_rdk_indexes_swapped",      2, { RD(1, 2, AP(0), AP(1)), RD(0, 1, AP(2)), NONE, NONE }, 0, 1, 0, 0, 3, 0 },
	{ "radio_rdk_index_gap_0_and_2",    2, { RD(0, 1, AP(0)), RD(2, 2, AP(1), AP(2)), NONE, NONE }, 0, 1, 0, 0, 3, 0 },
	{ "radio_rdk_indexes_start_at_1",   2, { RD(1, 1, AP(0)), RD(2, 1, AP(1)), NONE, NONE }, 0, 1, 0, 0, 2, 0 },
	{ "radio_rdk_index_far_from_pos",   1, { RD(9, 2, AP(0), AP(1)), NONE, NONE, NONE }, 0, 1, 0, 0, 2, 0 },
	/* ---- output parameter / repeats / log ---- */
	{ "output_preset_garbage_overwritten", 1, { RD(0, 2, AP(0), AP(1)), NONE, NONE, NONE }, 0, 1, 1, 0, 2, 0 },
	{ "output_zero_for_empty_overwrites_garbage", 0, { NONE, NONE, NONE, NONE }, 0, 1, 1, 0, 0, 0 },
	{ "repeated_calls_same_result",     2, { RD(0, 2, AP(0), AP(1)), RD(1, 1, AP(2)), NONE, NONE }, 0, 3, 0, 0, 3, 0 },
	{ "log_reports_the_count",          2, { RD(0, 1, AP(0)), RD(1, 1, AP(1)), NONE, NONE }, 0, 1, 0, 1, 2, 0 },
	/* ---- crash group (forked) ---- */
	{ "crash_numEntries_NULL",          1, { RD(0, 1, AP(0)), NONE, NONE, NONE }, 1, 1, 0, 0, 0, 1 },
	{ "crash_numEntries_NULL_no_radios", 0, { NONE, NONE, NONE, NONE }, 1, 1, 0, 0, 0, 1 },
	{ NULL, 0, { NONE, NONE, NONE, NONE }, 0, 0, 0, 0, 0, 0 }
};
