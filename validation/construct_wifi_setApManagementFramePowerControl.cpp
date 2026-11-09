/*
 * UNIT TEST (input constructor): construct_wifi_setApManagementFramePowerControl
 *
 * wifi_setApManagementFramePowerControl(apIndex, dBm) (platform/banana-pi) is an empty stub that returns 0 (WIFI_HAL_SUCCESS) for every input; nothing
 * is stored, nothing is logged and no argument is dereferenced (same class as wifi_setBssLoad: nothing observable, no finding).  The suite pins that
 * contract: every combination returns WIFI_HAL_SUCCESS and leaves the guard slab and the log slot untouched.  Inputs crossed: apIndex 0 / 1 / 15 / -1 /
 * INT_MIN / INT_MAX, dBm 0 / 1 / -1 / 20 / -100 / 127 / -128 / INT_MIN / INT_MAX, repeated calls, and a log slot that is empty / holds text / is almost
 * full / is full.
 */
#include <limits.h>
#include "hwr_smp.h"

#define OK WIFI_HAL_SUCCESS

/* name, ap_index, dbm, calls, prefill, expected_ret */
hwr_smp_case_t wifi_setApManagementFramePowerControl_suite[] = {
	{ "ap_0_dbm_20", 0, 20, 1, 0, OK },
	{ "ap_1_dbm_20", 1, 20, 1, 0, OK },
	{ "ap_15_dbm_20", 15, 20, 1, 0, OK },
	{ "ap_negative_dbm_20", -1, 20, 1, 0, OK },
	{ "ap_int_min_dbm_20", INT_MIN, 20, 1, 0, OK },
	{ "ap_int_max_dbm_20", INT_MAX, 20, 1, 0, OK },
	{ "dbm_0", 0, 0, 1, 0, OK },
	{ "dbm_1", 0, 1, 1, 0, OK },
	{ "dbm_minus_1", 0, -1, 1, 0, OK },
	{ "dbm_minus_100", 0, -100, 1, 0, OK },
	{ "dbm_127", 0, 127, 1, 0, OK },
	{ "dbm_minus_128", 0, -128, 1, 0, OK },
	{ "dbm_int_min", 0, INT_MIN, 1, 0, OK },
	{ "dbm_int_max", 0, INT_MAX, 1, 0, OK },
	{ "two_calls", 0, 20, 2, 0, OK },
	{ "ten_calls", 3, -30, 10, 0, OK },
	{ "log_prefilled_1", 0, 20, 1, 1, OK },
	{ "log_prefilled_100", 0, 0, 1, 100, OK },
	{ "log_almost_full", 0, 20, 1, 254, OK },
	{ "log_full", 0, 20, 1, 255, OK },
	{ "log_full_dbm_int_min", -1, INT_MIN, 1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0 }
};
