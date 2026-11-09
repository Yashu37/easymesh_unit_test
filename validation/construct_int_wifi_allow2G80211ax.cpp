/*
 * UNIT TEST (input constructor): construct_int_wifi_allow2G80211ax
 *
 * wifi_allow2G80211ax(enable) (platform/intel) is an empty stub that returns 0 for every input: nothing is stored, nothing is logged and no pointer is
 * involved.  The suite pins that contract: every combination returns 0 and leaves the guard slab and the log slot untouched.  Inputs crossed: enable
 * false / true (a C++ bool), 1 / 2 / 10 / 100 repeated calls, calls that flip the value every time, and a log slot that is empty / holds text / is
 * almost full / is full.
 */
#include "hwr_ia2.h"

#define OK 0

/* name, enable, calls, alternate, prefill, expected_ret */
hwr_ia2_case_t int_wifi_allow2G80211ax_suite[] = {
	{ "enable_true",                    1,   1, 0,   0, OK },
	{ "enable_false",                   0,   1, 0,   0, OK },
	{ "enable_true_two_calls",          1,   2, 0,   0, OK },
	{ "enable_false_two_calls",         0,   2, 0,   0, OK },
	{ "enable_true_ten_calls",          1,  10, 0,   0, OK },
	{ "enable_false_ten_calls",         0,  10, 0,   0, OK },
	{ "enable_true_hundred_calls",      1, 100, 0,   0, OK },
	{ "alternating_two_calls",          1,   2, 1,   0, OK },
	{ "alternating_ten_calls",          0,  10, 1,   0, OK },
	{ "alternating_hundred_calls",      1, 100, 1,   0, OK },
	{ "enable_nonzero_2",               2,   1, 0,   0, OK },
	{ "enable_nonzero_negative",       -1,   1, 0,   0, OK },
	{ "log_prefilled_1_true",           1,   1, 0,   1, OK },
	{ "log_prefilled_1_false",          0,   1, 0,   1, OK },
	{ "log_prefilled_100_true",         1,   1, 0, 100, OK },
	{ "log_prefilled_100_false",        0,   1, 0, 100, OK },
	{ "log_almost_full_true",           1,   1, 0, 254, OK },
	{ "log_almost_full_false",          0,   1, 0, 254, OK },
	{ "log_full_true",                  1,   1, 0, 255, OK },
	{ "log_full_false",                 0,   1, 0, 255, OK },
	{ "log_full_alternating",           1,   6, 1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0 }
};
