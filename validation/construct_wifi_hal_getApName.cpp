/*
 * UNIT TEST (input constructor): construct_wifi_hal_getApName
 *
 * wifi_hal_getApName(apIndex, output_string) rejects apIndex >= get_total_num_of_vaps() (the sum of
 * radio->capab.maxNumberVAPs over the radios), then copies the interface name of the VAP from the interface
 * index map (get_interface_name_from_vap_index) into the caller's buffer (ipc_server_output allocates
 * HAL_IPC_MAX_STRING_LEN = 64 bytes).
 *
 * The suite is a table of "worlds" (radios with rdk index and maxNumberVAPs, the interface index map) plus the
 * query and the expected output; the runner (wifi_hal_getApName_test.cpp) builds the world in runner-owned slabs,
 * POISONS the tails (including the bytes behind the 64-byte output buffer), calls the function, unpoisons and
 * checks.  Inputs crossed: apIndex 0 / 1 / 2 / 15 / 16 (= total) / 17 / INT_MAX / -1 / INT_MIN, names of 0, 5, 9
 * and 15 characters, 0..3 radios, an index missing from the map, duplicate map entries, radios whose rdk index
 * is not their position in radio_info[] (swapped, gap, start at 1, far away: forked, the unfixed helpers
 * dereference a NULL radio), a NULL output_string, output untouched on failure, repeated calls and the log.
 * Expected result is the SAFE contract, so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gan.h"

#define R2    2, { { 0, 8 }, { 1, 8 }, { 0, 0 } }
#define MAP4  4, { { 0, "wlan0" }, { 1, "wlan1" }, { 2, "wlan2" }, { 15, "wlan15" } }
#define NOMAP 0, { }
#define UT NULL
/* name, nradios, radios[3], nmap, map[6], query, null_out, calls, check_log, expected_ret, expected_out, forked */
hwr_gan_case_t wifi_hal_getApName_suite[] = {
	{ "index_0",                       R2, MAP4, 0, 0, 1, 0, 0, "wlan0", 0 },
	{ "index_1",                       R2, MAP4, 1, 0, 1, 0, 0, "wlan1", 0 },
	{ "index_2",                       R2, MAP4, 2, 0, 1, 0, 0, "wlan2", 0 },
	{ "index_15_last_valid",           R2, MAP4, 15, 0, 1, 0, 0, "wlan15", 0 },
	{ "index_3_in_range_not_in_map",   R2, MAP4, 3, 0, 1, 0, -1, UT, 0 },
	{ "index_16_equals_total",         R2, MAP4, 16, 0, 1, 0, -1, UT, 0 },
	{ "index_17_above_total",          R2, MAP4, 17, 0, 1, 0, -1, UT, 0 },
	{ "index_int_max",                 R2, MAP4, INT_MAX, 0, 1, 0, -1, UT, 0 },
	{ "index_minus_1",                 R2, MAP4, -1, 0, 1, 0, -1, UT, 0 },
	{ "index_int_min",                 R2, MAP4, INT_MIN, 0, 1, 0, -1, UT, 0 },
	{ "one_radio_index_7_last",        1, { { 0, 8 }, { 0, 0 }, { 0, 0 } }, 2, { { 0, "wlan0" }, { 7, "wlan7" } }, 7, 0, 1, 0, 0, "wlan7", 0 },
	{ "one_radio_index_8_equals_total", 1, { { 0, 8 }, { 0, 0 }, { 0, 0 } }, 2, { { 0, "wlan0" }, { 8, "wlan8" } }, 8, 0, 1, 0, -1, UT, 0 },
	{ "three_radios_index_23",         3, { { 0, 8 }, { 1, 8 }, { 2, 8 } }, 2, { { 0, "wlan0" }, { 23, "wlan23" } }, 23, 0, 1, 0, 0, "wlan23", 0 },
	{ "three_radios_index_24_equals_total", 3, { { 0, 8 }, { 1, 8 }, { 2, 8 } }, 2, { { 0, "wlan0" }, { 24, "wlan24" } }, 24, 0, 1, 0, -1, UT, 0 },
	{ "swapped_rdk_indexes_ok",        2, { { 1, 8 }, { 0, 8 }, { 0, 0 } }, 2, { { 0, "wlan0" }, { 9, "wlan9" } }, 9, 0, 1, 0, 0, "wlan9", 0 },
	{ "no_radios_total_0",             0, { { 0, 0 }, { 0, 0 }, { 0, 0 } }, MAP4, 0, 0, 1, 0, -1, UT, 0 },
	{ "radios_with_zero_max_vaps",     2, { { 0, 0 }, { 1, 0 }, { 0, 0 } }, MAP4, 0, 0, 1, 0, -1, UT, 0 },
	{ "empty_map",                     R2, NOMAP, 0, 0, 1, 0, -1, UT, 0 },
	{ "name_empty",                    R2, 1, { { 4, "" } }, 4, 0, 1, 0, 0, "", 0 },
	{ "name_5_chars",                  R2, 1, { { 4, "wlan4" } }, 4, 0, 1, 0, 0, "wlan4", 0 },
	{ "name_9_chars",                  R2, 1, { { 4, "wlan_mesh" } }, 4, 0, 1, 0, 0, "wlan_mesh", 0 },
	{ "name_15_chars_max_ifname",      R2, 1, { { 4, "wlan_backhaul_x" } }, 4, 0, 1, 0, 0, "wlan_backhaul_x", 0 },
	{ "duplicate_map_entries_first_wins", R2, 2, { { 4, "first" }, { 4, "second" } }, 4, 0, 1, 0, 0, "first", 0 },
	/* ---- NULL / repeats / log ---- */
	{ "output_null_valid_index_rejected", R2, MAP4, 1, 1, 1, 0, -1, UT, 0 },
	{ "output_null_unknown_index",     R2, MAP4, 3, 1, 1, 0, -1, UT, 0 },
	{ "repeated_calls_x3_same_result", R2, MAP4, 2, 0, 3, 0, 0, "wlan2", 0 },
	{ "log_has_function_name_and_name", R2, MAP4, 1, 0, 1, 1, 0, "wlan1", 0 },
	{ "wrong_index_logs",              R2, MAP4, 99, 0, 1, 2, -1, UT, 0 },
	/* ---- radios whose rdk index is not their position in radio_info[]: unfixed helpers dereference NULL (forked) ---- */
	{ "crash_rdk_indexes_0_and_2",     2, { { 0, 8 }, { 2, 8 }, { 0, 0 } }, MAP4, 2, 0, 1, 0, 0, "wlan2", 1 },
	{ "crash_rdk_indexes_1_and_2",     2, { { 1, 8 }, { 2, 8 }, { 0, 0 } }, MAP4, 0, 0, 1, 0, 0, "wlan0", 1 },
	{ "crash_rdk_indexes_0_and_3",     2, { { 0, 8 }, { 3, 8 }, { 0, 0 } }, MAP4, 1, 0, 1, 0, 0, "wlan1", 1 },
	{ "crash_single_radio_rdk_index_3", 1, { { 3, 8 }, { 0, 0 }, { 0, 0 } }, MAP4, 0, 0, 1, 0, 0, "wlan0", 1 },
	{ "crash_three_radios_rdk_0_2_4",  3, { { 0, 8 }, { 2, 8 }, { 4, 8 } }, MAP4, 15, 0, 1, 0, 0, "wlan15", 1 },
	{ NULL, 0, { { 0, 0 }, { 0, 0 }, { 0, 0 } }, 0, { }, 0, 0, 0, 0, 0, 0, 0 }
};
