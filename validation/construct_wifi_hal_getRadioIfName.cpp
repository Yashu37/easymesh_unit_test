/*
 * UNIT TEST (input constructor): construct_wifi_hal_getRadioIfName
 *
 * wifi_hal_getRadioIfName(radioIndex, output_string) translates a radio index into the cloud radio name with the
 * table cloud_radio_map = { {0, "wl0", "wlan0"}, {1, "wl1", "wlan2"} } (two entries): it rejects an index
 * greater than g_wifi_hal.num_radios and a NULL output (both return -1), logs the translation and strcpy()s the
 * cloud name (ipc_server_output allocates HAL_IPC_MAX_STRING_LEN = 64 bytes).
 *
 * The runner (wifi_hal_getRadioIfName_test.cpp) sets g_wifi_hal.num_radios per case, owns the output buffer in a
 * slab, POISONS its tail and the unused log slot, calls the function, unpoisons and checks.
 * Inputs crossed: num_radios 0 / 1 / 2 / 3 with every index from 0 to 4 and 255, negative indexes (-1, INT_MIN),
 * INT_MAX, NULL output with valid and invalid indexes, output untouched on a failed call, repeated calls and the
 * log.  The cloud_radio_map table has only two entries, so an index of 2 or more (radio 3 of 3, or an index equal
 * to num_radios) reads outside it and an index equal to num_radios is not "out of range" (the unfixed function
 * compares with `>`).  Rows that read outside the table crash the unfixed function: they run forked so the ASan
 * report (global-buffer-overflow) is visible but the run continues.  Expected result is the SAFE contract (an index
 * that is not a radio, or has no table entry, returns -1 and leaves the output untouched), so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gri.h"

#define UT NULL
/* name, num_radios, index, null_out, calls, check_log, expected_ret, expected_out, forked */
hwr_gri_case_t wifi_hal_getRadioIfName_suite[] = {
	/* ---- valid radios ---- */
	{ "two_radios_index_0",          2, 0, 0, 1, 0, 0, "wl0", 0 },
	{ "two_radios_index_1",          2, 1, 0, 1, 0, 0, "wl1", 0 },
	{ "three_radios_index_0",        3, 0, 0, 1, 0, 0, "wl0", 0 },
	{ "three_radios_index_1",        3, 1, 0, 1, 0, 0, "wl1", 0 },
	{ "one_radio_index_0",           1, 0, 0, 1, 0, 0, "wl0", 0 },
	{ "repeated_calls_x3",           2, 1, 0, 3, 0, 0, "wl1", 0 },
	{ "log_has_translation_line",    2, 1, 0, 1, 1, 0, "wl1", 0 },
	/* ---- index beyond the number of radios: rejected ---- */
	{ "two_radios_index_3",          2, 3, 0, 1, 0, -1, UT, 0 },
	{ "two_radios_index_255",        2, 255, 0, 1, 0, -1, UT, 0 },
	{ "three_radios_index_4",        3, 4, 0, 1, 0, -1, UT, 0 },
	{ "one_radio_index_2",           1, 2, 0, 1, 0, -1, UT, 0 },
	{ "index_int_max",               2, INT_MAX, 0, 1, 0, -1, UT, 0 },
	{ "index_minus_1",               2, -1, 0, 1, 0, -1, UT, 0 },
	{ "index_int_min",               2, INT_MIN, 0, 1, 0, -1, UT, 0 },
	{ "index_3_logs_out_of_range",   2, 3, 0, 1, 2, -1, UT, 0 },
	/* ---- index equal to num_radios (off by one): not a radio ---- */
	{ "zero_radios_index_0",         0, 0, 0, 1, 0, -1, UT, 0 },
	{ "one_radio_index_1",           1, 1, 0, 1, 0, -1, UT, 0 },
	/* ---- no table entry: cloud_radio_map has two entries only (global buffer overflow in the unfixed function) ---- */
	{ "two_radios_index_2_equal_to_num_radios", 2, 2, 0, 1, 0, -1, UT, 1 },
	{ "three_radios_index_2_no_table_entry",    3, 2, 0, 1, 0, -1, UT, 1 },
	{ "four_radios_index_2_no_table_entry",     4, 2, 0, 1, 0, -1, UT, 1 },
	{ "four_radios_index_3_no_table_entry",     4, 3, 0, 1, 0, -1, UT, 1 },
	/* ---- NULL output ---- */
	{ "output_null_valid_index",     2, 1, 1, 1, 0, -1, UT, 0 },
	{ "output_null_index_0",         2, 0, 1, 1, 0, -1, UT, 0 },
	{ "output_null_index_out_of_range", 2, 9, 1, 1, 0, -1, UT, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, NULL, 0 }
};
