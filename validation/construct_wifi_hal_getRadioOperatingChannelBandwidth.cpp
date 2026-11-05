/*
 * UNIT TEST (input constructor): construct_wifi_hal_getRadioOperatingChannelBandwidth
 *
 * wifi_hal_getRadioOperatingChannelBandwidth(radioIndex, output_string) looks the radio up by rdk index and
 * writes the channel width as a string with snprintf(output_string, 6 or 7, ...): "20MHz", "40MHz", "80MHz",
 * "160MHz" and "20MHz" for everything else (ipc_server_output allocates HAL_IPC_MAX_STRING_LEN = 64 bytes).  An
 * unknown radio returns RETURN_ERR.
 *
 * The suite is a table of "worlds" (radios with rdk index and operating channel width) plus the query and the
 * expected output; the runner (wifi_hal_getRadioOperatingChannelBandwidth_test.cpp) builds the world in
 * runner-owned slabs (REAL wifi_radio_operationParam_t), POISONS the tails (including the bytes behind the
 * 64-byte output buffer), calls the function, unpoisons and checks.
 * Inputs crossed: every wifi_channelBandwidth_t value (20, 40, 80, 160, 80+80, 320 MHz), values that are not a
 * width (0, 0x3, 0x40, 0xFF: the function's default "20MHz" is documented by these cases - design note), radioIndex
 * 0 / 1 / 2 / non-sequential rdk indexes, unknown / negative / INT_MIN / INT_MAX indexes, duplicate rdk index
 * (first wins), no radios, output untouched on a failed lookup, repeated calls, the log, and a NULL output_string
 * (forked).  Expected result is the SAFE contract (the width that was configured is the width reported), so a
 * FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gcb.h"

#define W20   0x1
#define W40   0x2
#define W80   0x4
#define W160  0x8
#define W8080 0x10
#define W320  0x20
#define ONE(w)   1, { { 0, (w) }, { 0, 0 }, { 0, 0 } }
#define NOR      0, { { 0, 0 }, { 0, 0 }, { 0, 0 } }
#define UT NULL
/* name, nradios, radios[3], query, null_out, calls, check_log, expected_ret, expected_out, forked */
hwr_gcb_case_t wifi_hal_getRadioOperatingChannelBandwidth_suite[] = {
	{ "width_20mhz",                   ONE(W20),   0, 0, 1, 0, 0, "20MHz", 0 },
	{ "width_40mhz",                   ONE(W40),   0, 0, 1, 0, 0, "40MHz", 0 },
	{ "width_80mhz",                   ONE(W80),   0, 0, 1, 0, 0, "80MHz", 0 },
	{ "width_160mhz",                  ONE(W160),  0, 0, 1, 0, 0, "160MHz", 0 },
	{ "width_80_80mhz",                ONE(W8080), 0, 0, 1, 0, 0, "80+80MHz", 0 },
	{ "width_320mhz",                  ONE(W320),  0, 0, 1, 0, 0, "320MHz", 0 },
	{ "width_value_0_default",         ONE(0),     0, 0, 1, 0, 0, "20MHz", 0 },
	{ "width_value_20_plus_40_default", ONE(W20 | W40), 0, 0, 1, 0, 0, "20MHz", 0 },
	{ "width_value_0x40_default",      ONE(0x40),  0, 0, 1, 0, 0, "20MHz", 0 },
	{ "width_value_0xff_default",      ONE(0xFF),  0, 0, 1, 0, 0, "20MHz", 0 },
	{ "three_radios_20_80_160_query_0", 3, { { 0, W20 }, { 1, W80 }, { 2, W160 } }, 0, 0, 1, 0, 0, "20MHz", 0 },
	{ "three_radios_20_80_160_query_1", 3, { { 0, W20 }, { 1, W80 }, { 2, W160 } }, 1, 0, 1, 0, 0, "80MHz", 0 },
	{ "three_radios_20_80_160_query_2", 3, { { 0, W20 }, { 1, W80 }, { 2, W160 } }, 2, 0, 1, 0, 0, "160MHz", 0 },
	{ "three_radios_with_320mhz_query_2", 3, { { 0, W20 }, { 1, W80 }, { 2, W320 } }, 2, 0, 1, 0, 0, "320MHz", 0 },
	{ "swapped_rdk_indexes_query_0",   2, { { 1, W80 }, { 0, W40 }, { 0, 0 } }, 0, 0, 1, 0, 0, "40MHz", 0 },
	{ "swapped_rdk_indexes_query_1",   2, { { 1, W80 }, { 0, W40 }, { 0, 0 } }, 1, 0, 1, 0, 0, "80MHz", 0 },
	{ "rdk_index_gap_query_5",         2, { { 0, W20 }, { 5, W160 }, { 0, 0 } }, 5, 0, 1, 0, 0, "160MHz", 0 },
	{ "duplicate_rdk_index_first_wins", 2, { { 3, W80 }, { 3, W160 }, { 0, 0 } }, 3, 0, 1, 0, 0, "80MHz", 0 },
	/* ---- lookup failures: RETURN_ERR, output untouched ---- */
	{ "unknown_radio_not_present",     2, { { 0, W20 }, { 1, W40 }, { 0, 0 } }, 2, 0, 1, 0, -1, UT, 0 },
	{ "no_radios",                     NOR, 0, 0, 1, 0, -1, UT, 0 },
	{ "radio_index_minus_1",           ONE(W80), -1, 0, 1, 0, -1, UT, 0 },
	{ "radio_index_int_min",           ONE(W80), INT_MIN, 0, 1, 0, -1, UT, 0 },
	{ "radio_index_int_max",           ONE(W80), INT_MAX, 0, 1, 0, -1, UT, 0 },
	{ "unknown_radio_logs_error",      ONE(W80), 4, 0, 1, 1, -1, UT, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_result", 2, { { 0, W20 }, { 1, W160 }, { 0, 0 } }, 1, 0, 3, 0, 0, "160MHz", 0 },
	{ "log_ok_has_no_error_line",      ONE(W80), 0, 0, 1, 2, 0, "80MHz", 0 },
	/* ---- crash group (forked): NULL output_string, radio found ---- */
	{ "crash_output_null_20mhz",       ONE(W20),  0, 1, 1, 0, -1, UT, 1 },
	{ "crash_output_null_160mhz",      ONE(W160), 0, 1, 1, 0, -1, UT, 1 },
	{ "crash_output_null_default_width", ONE(0),  0, 1, 1, 0, -1, UT, 1 },
	{ "output_null_unknown_radio",     ONE(W80),  4, 1, 1, 0, -1, UT, 0 },
	{ NULL, 0, { { 0, 0 }, { 0, 0 }, { 0, 0 } }, 0, 0, 0, 0, 0, 0, 0 }
};
