/*
 * UNIT TEST (input constructor): construct_int_wifi_setApMacAddressControlMode
 *
 * wifi_setApMacAddressControlMode(apIndex, filterMode) (platform/intel) is an empty stub that returns RETURN_OK (0) for every input: nothing is stored,
 * nothing is logged and no pointer is involved.  The suite pins that contract: every combination returns WIFI_HAL_SUCCESS and leaves the guard slab and the log
 * slot untouched.  Inputs crossed: apIndex 0 / 1 / 15 / -1 / INT_MIN / INT_MAX, filterMode 0 (disabled) / 1 (white list) / 2 (black list) / 3 / 255 / -1 /
 * INT_MIN / INT_MAX, repeated calls (also with the mode changing on every call), and a log slot that is empty / holds text / is almost full / is full.
 */
#include <limits.h>
#include "hwr_imc.h"

#define OK WIFI_HAL_SUCCESS

/* name, ap_index, filter_mode, calls, alternate, prefill, expected_ret */
hwr_imc_case_t int_wifi_setApMacAddressControlMode_suite[] = {
	{ "mode_0_disabled",             0,       0,   1, 0,   0, OK },
	{ "mode_1_white_list",           0,       1,   1, 0,   0, OK },
	{ "mode_2_black_list",           0,       2,   1, 0,   0, OK },
	{ "mode_3",                      0,       3,   1, 0,   0, OK },
	{ "mode_255",                    0,     255,   1, 0,   0, OK },
	{ "mode_negative",               0,      -1,   1, 0,   0, OK },
	{ "mode_int_min",                0, INT_MIN,   1, 0,   0, OK },
	{ "mode_int_max",                0, INT_MAX,   1, 0,   0, OK },
	{ "ap_1_mode_1",                 1,       1,   1, 0,   0, OK },
	{ "ap_1_mode_2",                 1,       2,   1, 0,   0, OK },
	{ "ap_15_mode_1",               15,       1,   1, 0,   0, OK },
	{ "ap_negative_mode_1",         -1,       1,   1, 0,   0, OK },
	{ "ap_int_min_mode_2",     INT_MIN,       2,   1, 0,   0, OK },
	{ "ap_int_max_mode_0",     INT_MAX,       0,   1, 0,   0, OK },
	{ "ap_int_min_mode_int_min", INT_MIN, INT_MIN, 1, 0,   0, OK },
	{ "ap_int_max_mode_int_max", INT_MAX, INT_MAX, 1, 0,   0, OK },
	{ "two_calls",                   0,       1,   2, 0,   0, OK },
	{ "ten_calls",                   3,       2,  10, 0,   0, OK },
	{ "hundred_calls_alternating",   0,       0, 100, 1,   0, OK },
	{ "log_prefilled_1",             0,       1,   1, 0,   1, OK },
	{ "log_prefilled_100",           0,       2,   1, 0, 100, OK },
	{ "log_almost_full",             0,       1,   1, 0, 254, OK },
	{ "log_full",                    0,       2,   1, 0, 255, OK },
	{ "log_full_ap_negative",       -1,      -1,   1, 0, 255, OK },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
