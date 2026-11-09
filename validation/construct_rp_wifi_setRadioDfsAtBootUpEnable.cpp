/*
 * UNIT TEST (input constructor): construct_rp_wifi_setRadioDfsAtBootUpEnable
 *
 * wifi_setRadioDfsAtBootUpEnable(radioIndex, enable) (platform/raspberry-pi) is an empty stub that returns 0 for every input, i.e. the request is
 * accepted and ignored; nothing is stored, nothing is logged and no argument is dereferenced.  The suite pins that contract: every
 * combination returns WIFI_HAL_SUCCESS and leaves the guard slab and the log slot untouched.  Inputs crossed: radioIndex 0 / 1 / 15 / -1 / INT_MIN /
 * INT_MAX, enable 0 / 1 / 2 / 0x7F / 0x80 / 0xFF (BOOL is unsigned char), repeated calls, and a log slot that is empty / holds text / is almost
 * full / is full.
 */
#include <limits.h>
#include "hwr_rdb.h"

#define OK WIFI_HAL_SUCCESS

/* name, radio_index, enable, calls, prefill, expected_ret */
hwr_rdb_case_t rp_wifi_setRadioDfsAtBootUpEnable_suite[] = {
	{ "radio_0_enable",                 0,       1,    1,   0, OK },
	{ "radio_0_disable",                0,       0,    1,   0, OK },
	{ "radio_1_enable",                 1,       1,    1,   0, OK },
	{ "radio_1_disable",                1,       0,    1,   0, OK },
	{ "radio_15_enable",               15,       1,    1,   0, OK },
	{ "radio_15_disable",              15,       0,    1,   0, OK },
	{ "radio_negative_enable",         -1,       1,    1,   0, OK },
	{ "radio_negative_disable",        -1,       0,    1,   0, OK },
	{ "radio_int_min_enable",     INT_MIN,       1,    1,   0, OK },
	{ "radio_int_max_disable",    INT_MAX,       0,    1,   0, OK },
	{ "enable_2",                    0,       2,    1,   0, OK },
	{ "enable_0x7f",                 0,    0x7F,    1,   0, OK },
	{ "enable_0x80",                 0,    0x80,    1,   0, OK },
	{ "enable_0xff",                 0,    0xFF,    1,   0, OK },
	{ "two_calls_enable",            0,       1,    2,   0, OK },
	{ "ten_calls_alternating_ap",    3,       1,   10,   0, OK },
	{ "log_prefilled_1",             0,       1,    1,   1, OK },
	{ "log_prefilled_100",           0,       0,    1, 100, OK },
	{ "log_almost_full",             0,       1,    1, 254, OK },
	{ "log_full",                    0,       1,    1, 255, OK },
	{ "log_full_ap_negative",       -1,    0xFF,    1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0 }
};
