/*
 * UNIT TEST (input constructor): construct_platform_pre_init
 *
 * platform_pre_init() (platform/banana-pi) takes no argument, logs "platform_pre_init:<line> " and returns 0.
 * The only inputs are the state of the log sink and the number of calls: empty log, one call, repeated calls (every call
 * returns 0 and appends one line), a log slot that is almost full / completely full (the sink is bounded by HWR_LOG_USE and
 * must not write behind it: the runner poisons the log slot tail), and a log that already holds other text.
 */
#include "hwr_ppi.h"


/* name, prefill, calls, expected_ret, expect_log */
hwr_ppi_case_t platform_pre_init_suite[] = {
	{ "one_call_empty_log",            0,   1, 0, 1 },
	{ "two_calls_two_lines",           0,   2, 0, 1 },
	{ "ten_calls_log_bounded",         0,  10, 0, 0 },
	{ "log_prefilled_100",           100,   1, 0, 1 },
	{ "log_almost_full_one_byte_left", 254, 1, 0, 0 },
	{ "log_full_nothing_written",    255,   1, 0, 0 },
	{ NULL, 0, 0, 0, 0 }
};
