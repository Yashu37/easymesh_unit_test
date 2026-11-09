/*
 * UNIT TEST (input constructor): construct_wifi_getApManagementFramePowerControl
 *
 * wifi_getApManagementFramePowerControl(apIndex, output_dBm) (platform/banana-pi) is an empty stub that returns 0 (WIFI_HAL_SUCCESS).  The HAL
 * interface (halinterface wifi_hal_ap.h) says the function stores the ManagementFramePowerControl value in *output_dBm and returns
 * WIFI_HAL_SUCCESS, or WIFI_HAL_ERROR on any error.  The suite expects: a valid output pointer is written (the stub has no power control, so the
 * value is 0 dBm) and WIFI_HAL_SUCCESS is returned; a NULL output_dBm is an error.  Inputs crossed: apIndex 0 / 1 / 15 / -1 / INT_MIN / INT_MAX,
 * output NULL / valid, a stale value in the output slot (never 0, so a call that leaves it alone is seen), repeated calls.
 */
#include <limits.h>
#include "hwr_gmp.h"

#define OK  WIFI_HAL_SUCCESS
#define ERR WIFI_HAL_ERROR

/* name, ap_index, out_mode, preset, calls, expected_ret, expected_val */
hwr_gmp_case_t wifi_getApManagementFramePowerControl_suite[] = {
	{ "ap_0_valid_output",              0, 1, 0x5A5A5A5A, 1, OK, 0 },
	{ "ap_1_valid_output",              1, 1, 0x5A5A5A5A, 1, OK, 0 },
	{ "ap_15_valid_output",            15, 1, 0x5A5A5A5A, 1, OK, 0 },
	{ "ap_negative_valid_output",      -1, 1, 0x5A5A5A5A, 1, OK, 0 },
	{ "ap_int_min_valid_output",  INT_MIN, 1, 0x5A5A5A5A, 1, OK, 0 },
	{ "ap_int_max_valid_output",  INT_MAX, 1, 0x5A5A5A5A, 1, OK, 0 },
	{ "stale_minus_1",                  0, 1, -1,          1, OK, 0 },
	{ "stale_1",                        0, 1, 1,           1, OK, 0 },
	{ "stale_100",                      0, 1, 100,         1, OK, 0 },
	{ "stale_minus_100",                0, 1, -100,        1, OK, 0 },
	{ "stale_int_max",                  0, 1, INT_MAX,     1, OK, 0 },
	{ "stale_int_min",                  0, 1, INT_MIN,     1, OK, 0 },
	{ "two_calls",                      0, 1, 0x5A5A5A5A, 2, OK, 0 },
	{ "ten_calls",                      3, 1, 0x5A5A5A5A, 10, OK, 0 },
	{ "ap_0_output_null",               0, 0, 0,           1, ERR, 0 },
	{ "ap_1_output_null",               1, 0, 0,           1, ERR, 0 },
	{ "ap_15_output_null",             15, 0, 0,           1, ERR, 0 },
	{ "ap_negative_output_null",       -1, 0, 0,           1, ERR, 0 },
	{ "ap_int_min_output_null",   INT_MIN, 0, 0,           1, ERR, 0 },
	{ "ap_int_max_output_null",   INT_MAX, 0, 0,           1, ERR, 0 },
	{ "output_null_two_calls",          0, 0, 0,           2, ERR, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
