/*
 * UNIT TEST (input constructor): construct_wifi_hal_getRadioOperatingFrequencyBand
 *
 * wifi_hal_getRadioOperatingFrequencyBand(radioIndex, output_string) looks the radio up by rdk index and writes
 * the band as a string with snprintf(output_string, 64, ...): "5GHz" for 5 / 5L / 5H, "6GHz" for 6, "2.4GHz" for
 * everything else (ipc_server_output allocates HAL_IPC_MAX_STRING_LEN = 64 bytes).  An unknown radio returns
 * RETURN_ERR.
 *
 * The suite is a table of "worlds" (radios with rdk index and operating band) plus the query and the expected
 * output; the runner (wifi_hal_getRadioOperatingFrequencyBand_test.cpp) builds the world in runner-owned slabs
 * (REAL wifi_radio_operationParam_t), POISONS the tails (including the bytes behind the 64-byte output buffer),
 * calls the function, unpoisons and checks.
 * Inputs crossed: every wifi_freq_bands_t value (2.4, 5, 5L, 5H, 6, 60 GHz), values that are not a band (0, 0x3,
 * 0x40, 0xFF - the function's default "2.4GHz" is documented by these cases), radioIndex 0 / 1 / 2 / non-sequential
 * rdk indexes, unknown / negative / INT_MIN / INT_MAX indexes, duplicate rdk index (first wins), no radios,
 * output untouched on a failed lookup, repeated calls, the log, and a NULL output_string (forked).
 * Expected result is the SAFE contract (the band that was configured is the band reported), so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gfb.h"

#define B24 0x1
#define B5  0x2
#define B5L 0x4
#define B5H 0x8
#define B6  0x10
#define B60 0x20
#define ONE(b)   1, { { 0, (b) }, { 0, 0 }, { 0, 0 } }
#define NOR      0, { { 0, 0 }, { 0, 0 }, { 0, 0 } }
#define UT NULL
/* name, nradios, radios[3], query, null_out, calls, check_log, expected_ret, expected_out, forked */
hwr_gfb_case_t wifi_hal_getRadioOperatingFrequencyBand_suite[] = {
	{ "band_2_4ghz",                   ONE(B24), 0, 0, 1, 0, 0, "2.4GHz", 0 },
	{ "band_5ghz",                     ONE(B5),  0, 0, 1, 0, 0, "5GHz", 0 },
	{ "band_5ghz_low",                 ONE(B5L), 0, 0, 1, 0, 0, "5GHz", 0 },
	{ "band_5ghz_high",                ONE(B5H), 0, 0, 1, 0, 0, "5GHz", 0 },
	{ "band_6ghz",                     ONE(B6),  0, 0, 1, 0, 0, "6GHz", 0 },
	{ "band_60ghz",                    ONE(B60), 0, 0, 1, 0, 0, "60GHz", 0 },
	{ "band_value_0_default",          ONE(0),    0, 0, 1, 0, 0, "2.4GHz", 0 },
	{ "band_value_2_4_plus_5_default", ONE(B24 | B5), 0, 0, 1, 0, 0, "2.4GHz", 0 },
	{ "band_value_0x40_default",       ONE(0x40), 0, 0, 1, 0, 0, "2.4GHz", 0 },
	{ "band_value_0xff_default",       ONE(0xFF), 0, 0, 1, 0, 0, "2.4GHz", 0 },
	{ "three_radios_2_4_5_6_query_0",  3, { { 0, B24 }, { 1, B5 }, { 2, B6 } }, 0, 0, 1, 0, 0, "2.4GHz", 0 },
	{ "three_radios_2_4_5_6_query_1",  3, { { 0, B24 }, { 1, B5 }, { 2, B6 } }, 1, 0, 1, 0, 0, "5GHz", 0 },
	{ "three_radios_2_4_5_6_query_2",  3, { { 0, B24 }, { 1, B5 }, { 2, B6 } }, 2, 0, 1, 0, 0, "6GHz", 0 },
	{ "three_radios_with_60ghz_query_2", 3, { { 0, B24 }, { 1, B5 }, { 2, B60 } }, 2, 0, 1, 0, 0, "60GHz", 0 },
	{ "swapped_rdk_indexes_query_0",   2, { { 1, B5 }, { 0, B24 }, { 0, 0 } }, 0, 0, 1, 0, 0, "2.4GHz", 0 },
	{ "swapped_rdk_indexes_query_1",   2, { { 1, B5 }, { 0, B24 }, { 0, 0 } }, 1, 0, 1, 0, 0, "5GHz", 0 },
	{ "rdk_index_gap_query_5",         2, { { 0, B24 }, { 5, B6 }, { 0, 0 } }, 5, 0, 1, 0, 0, "6GHz", 0 },
	{ "duplicate_rdk_index_first_wins", 2, { { 3, B5 }, { 3, B6 }, { 0, 0 } }, 3, 0, 1, 0, 0, "5GHz", 0 },
	/* ---- lookup failures: RETURN_ERR, output untouched ---- */
	{ "unknown_radio_not_present",     2, { { 0, B24 }, { 1, B5 }, { 0, 0 } }, 2, 0, 1, 0, -1, UT, 0 },
	{ "no_radios",                     NOR, 0, 0, 1, 0, -1, UT, 0 },
	{ "radio_index_minus_1",           ONE(B5), -1, 0, 1, 0, -1, UT, 0 },
	{ "radio_index_int_min",           ONE(B5), INT_MIN, 0, 1, 0, -1, UT, 0 },
	{ "radio_index_int_max",           ONE(B5), INT_MAX, 0, 1, 0, -1, UT, 0 },
	{ "unknown_radio_logs_error",      ONE(B5), 4, 0, 1, 1, -1, UT, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_result", 2, { { 0, B24 }, { 1, B6 }, { 0, 0 } }, 1, 0, 3, 0, 0, "6GHz", 0 },
	{ "log_ok_has_no_error_line",      ONE(B5), 0, 0, 1, 2, 0, "5GHz", 0 },
	/* ---- crash group (forked): NULL output_string, radio found ---- */
	{ "crash_output_null_2_4ghz",      ONE(B24), 0, 1, 1, 0, -1, UT, 1 },
	{ "crash_output_null_5ghz",        ONE(B5),  0, 1, 1, 0, -1, UT, 1 },
	{ "crash_output_null_6ghz",        ONE(B6),  0, 1, 1, 0, -1, UT, 1 },
	{ "output_null_unknown_radio",     ONE(B5),  4, 1, 1, 0, -1, UT, 0 },
	{ NULL, 0, { { 0, 0 }, { 0, 0 }, { 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 }
};
