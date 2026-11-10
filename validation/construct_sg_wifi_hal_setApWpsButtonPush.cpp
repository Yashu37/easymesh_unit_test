/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_setApWpsButtonPush
 *
 * wifi_hal_setApWpsButtonPush(ap_index): logs, calls wifi_hal_nl80211_wps_pbc((unsigned) ap_index) once and returns 0.  Inputs crossed: ap_index 0 .. 15, -1, 1000,
 * INT_MAX, INT_MIN, repeated calls, a log slot that is empty / holds text / is almost full / is full.  The call is forwarded unchanged (negative values arrive as the same
 * 32-bit pattern; the callee's own validation is its own entry in the list).
 */
#include "hwr_wpb.h"
#include <limits.h>

#define OK 0
/* name, ap_index, calls, prefill, expected_ret */
hwr_wpb_case_t sg_wifi_hal_setApWpsButtonPush_suite[] = {
	{ "ap_0",                0,  1,   0, OK },
	{ "ap_1",                1,  1,   0, OK },
	{ "ap_2",                2,  1,   0, OK },
	{ "ap_3",                3,  1,   0, OK },
	{ "ap_7",                7,  1,   0, OK },
	{ "ap_15",              15,  1,   0, OK },
	{ "ap_16",              16,  1,   0, OK },
	{ "ap_1000",          1000,  1,   0, OK },
	{ "ap_minus_1",         -1,  1,   0, OK },
	{ "ap_minus_1000",   -1000,  1,   0, OK },
	{ "ap_int_max",    INT_MAX,  1,   0, OK },
	{ "ap_int_min",    INT_MIN,  1,   0, OK },
	{ "ap_0_two_calls",      0,  2,   0, OK },
	{ "ap_5_ten_calls",      5, 10,   0, OK },
	{ "ap_minus_1_three_calls", -1, 3, 0, OK },
	{ "log_prefilled_1",     2,  1,   1, OK },
	{ "log_prefilled_100",   2,  1, 100, OK },
	{ "log_almost_full",     2,  1, 254, OK },
	{ "log_full",            2,  1, 255, OK },
	{ "log_full_negative",  -7,  1, 255, OK },
	{ NULL, 0, 0, 0, 0 }
};
