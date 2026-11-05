/*
 * UNIT TEST (input constructor): construct_platform_wps_event
 *
 * platform_wps_event(data) (platform/banana-pi) logs "platform_wps_event:<line> " and returns 0; the event is passed by value and
 * is not used.  Inputs crossed: vap_index 0 / 7 / 15 / UINT_MAX, event 0 / 1 / 2 / UINT_MAX, wps_data NULL / pointing to a fully POISONED
 * runner slab (the function must not read it) / dangling (0xdeadbeef), repeated calls, a log that already holds text / is almost full /
 * is full (the sink is bounded by HWR_LOG_USE and must not write behind it: the runner poisons the log slot tail).
 */
#include <limits.h>
#include "hwr_pwe.h"

/* name, vap_index, event, data_mode, calls, prefill, expected_ret, expect_log */
hwr_pwe_case_t platform_wps_event_suite[] = {
	{ "zero_event_data_null",           0,        0,        0, 1,   0, 0, 1 },
	{ "vap_0_event_1_data_poisoned",    0,        1,        1, 1,   0, 0, 1 },
	{ "vap_7_event_2_data_poisoned",    7,        2,        1, 1,   0, 0, 1 },
	{ "vap_15_event_0_data_null",       15,       0,        0, 1,   0, 0, 1 },
	{ "vap_max_event_max_data_null",    UINT_MAX, UINT_MAX, 0, 1,   0, 0, 1 },
	{ "vap_max_event_max_poisoned",     UINT_MAX, UINT_MAX, 1, 1,   0, 0, 1 },
	{ "data_dangling_pointer",          3,        1,        2, 1,   0, 0, 1 },
	{ "two_calls_two_lines",            1,        1,        1, 2,   0, 0, 1 },
	{ "ten_calls_log_bounded",          1,        1,        1, 10,  0, 0, 0 },
	{ "log_prefilled_100",              1,        1,        1, 1, 100, 0, 1 },
	{ "log_almost_full_one_byte_left",  1,        1,        1, 1, 254, 0, 0 },
	{ "log_full_nothing_written",       1,        1,        1, 1, 255, 0, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0 }
};
