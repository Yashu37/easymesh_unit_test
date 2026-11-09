/*
 * UNIT TEST (input constructor): construct_wifi_setProxyArp
 *
 * wifi_setProxyArp(apIndex, enable) (platform/banana-pi) is an empty stub that returns 0 (WIFI_HAL_SUCCESS) for every input; nothing is stored, nothing
 * is logged and no argument is dereferenced (same class as wifi_setQamPlus / wifi_setApRetrylimit: nothing observable, no finding).  The suite pins
 * that contract: every combination returns WIFI_HAL_SUCCESS and leaves the guard slab and the log slot untouched.  Inputs crossed: apIndex 0 / 1 / 15 / -1 / INT_MIN /
 * INT_MAX, enable 0 / 1 / 2 / 0x7F / 0x80 / 0xFF (BOOL is unsigned char), repeated calls, and a log slot that is empty / holds text / is almost
 * full / is full.
 */
#include <limits.h>
#include "hwr_spa.h"

#define ERR WIFI_HAL_SUCCESS

/* name, ap_index, enable, calls, prefill, expected_ret */
hwr_spa_case_t wifi_setProxyArp_suite[] = {
	{ "ap_0_enable",                 0,       1,    1,   0, ERR },
	{ "ap_0_disable",                0,       0,    1,   0, ERR },
	{ "ap_1_enable",                 1,       1,    1,   0, ERR },
	{ "ap_1_disable",                1,       0,    1,   0, ERR },
	{ "ap_15_enable",               15,       1,    1,   0, ERR },
	{ "ap_15_disable",              15,       0,    1,   0, ERR },
	{ "ap_negative_enable",         -1,       1,    1,   0, ERR },
	{ "ap_negative_disable",        -1,       0,    1,   0, ERR },
	{ "ap_int_min_enable",     INT_MIN,       1,    1,   0, ERR },
	{ "ap_int_max_disable",    INT_MAX,       0,    1,   0, ERR },
	{ "enable_2",                    0,       2,    1,   0, ERR },
	{ "enable_0x7f",                 0,    0x7F,    1,   0, ERR },
	{ "enable_0x80",                 0,    0x80,    1,   0, ERR },
	{ "enable_0xff",                 0,    0xFF,    1,   0, ERR },
	{ "two_calls_enable",            0,       1,    2,   0, ERR },
	{ "ten_calls_alternating_ap",    3,       1,   10,   0, ERR },
	{ "log_prefilled_1",             0,       1,    1,   1, ERR },
	{ "log_prefilled_100",           0,       0,    1, 100, ERR },
	{ "log_almost_full",             0,       1,    1, 254, ERR },
	{ "log_full",                    0,       1,    1, 255, ERR },
	{ "log_full_ap_negative",       -1,    0xFF,    1, 255, ERR },
	{ NULL, 0, 0, 0, 0, 0 }
};
