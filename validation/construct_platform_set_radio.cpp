/*
 * UNIT TEST (input constructor): construct_platform_set_radio
 *
 * platform_set_radio(index, operationParam) (platform/banana-pi) logs "platform_set_radio:<line> " and returns 0; neither argument
 * is used.  Inputs crossed: radio index 0 / 1 / 2 / 3 / UINT_MAX; operationParam NULL and pointing to a fully POISONED runner
 * slab (the function must not read or write it); repeated calls; a log that already holds text, is almost full and is full
 * (the sink is bounded by HWR_LOG_USE and must not write behind it: the runner poisons the log slot tail).
 */
#include <limits.h>
#include "hwr_psr.h"

/* name, index, param_null, prefill, calls, expected_ret, expect_log */
hwr_psr_case_t platform_set_radio_suite[] = {
	{ "index_0_param_null",             0,        1,   0, 1, 0, 1 },
	{ "index_0_param_poisoned",         0,        0,   0, 1, 0, 1 },
	{ "index_1_param_poisoned",         1,        0,   0, 1, 0, 1 },
	{ "index_2_param_null",             2,        1,   0, 1, 0, 1 },
	{ "index_3_param_poisoned",         3,        0,   0, 1, 0, 1 },
	{ "index_max_param_poisoned",       UINT_MAX, 0,   0, 1, 0, 1 },
	{ "index_max_param_null",           UINT_MAX, 1,   0, 1, 0, 1 },
	{ "two_calls_two_lines",            0,        0,   0, 2, 0, 1 },
	{ "ten_calls_log_bounded",          1,        0,   0, 10, 0, 0 },
	{ "log_prefilled_100",              0,        0, 100, 1, 0, 1 },
	{ "log_almost_full_one_byte_left",  0,        0, 254, 1, 0, 0 },
	{ "log_full_nothing_written",       0,        0, 255, 1, 0, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
