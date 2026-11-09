/*
 * UNIT TEST (input constructor): construct_wifi_getApEnable
 *
 * wifi_getApEnable(apIndex, output_bool) (platform/banana-pi) is an empty stub that returns RETURN_OK.  The HAL interface (halinterface
 * wifi_hal_ap.h) says the function stores the enable status of the AP in *output_bool and returns WIFI_HAL_SUCCESS, or WIFI_HAL_ERROR on any error.
 * The suite expects: a valid output pointer is written (the stub keeps no enable state, assumed value FALSE) and WIFI_HAL_SUCCESS is returned; a NULL
 * output_bool is an error.  Inputs crossed: apIndex 0 / 1 / 15 / -1 / INT_MIN / INT_MAX, output NULL / valid, a stale non-zero value in the output
 * slot (so a call that leaves it alone is seen), repeated calls.
 */
#include <limits.h>
#include "hwr_gae.h"

#define OK  WIFI_HAL_SUCCESS
#define ERR WIFI_HAL_ERROR

/* name, ap_index, out_mode, preset, calls, expected_ret, expected_val */
hwr_gae_case_t wifi_getApEnable_suite[] = {
	{ "ap_0_valid_output",              0, 1, 0x5A, 1, OK, 0 },
	{ "ap_1_valid_output",              1, 1, 0x5A, 1, OK, 0 },
	{ "ap_15_valid_output",            15, 1, 0x5A, 1, OK, 0 },
	{ "ap_negative_valid_output",      -1, 1, 0x5A, 1, OK, 0 },
	{ "ap_int_min_valid_output",  INT_MIN, 1, 0x5A, 1, OK, 0 },
	{ "ap_int_max_valid_output",  INT_MAX, 1, 0x5A, 1, OK, 0 },
	{ "stale_1",                        0, 1, 1,    1, OK, 0 },
	{ "stale_2",                        0, 1, 2,    1, OK, 0 },
	{ "stale_0x7f",                     0, 1, 0x7F, 1, OK, 0 },
	{ "stale_0x80",                     0, 1, 0x80, 1, OK, 0 },
	{ "stale_0xff",                     0, 1, 0xFF, 1, OK, 0 },
	{ "ap_1_stale_1",                   1, 1, 1,    1, OK, 0 },
	{ "ap_15_stale_0xff",              15, 1, 0xFF, 1, OK, 0 },
	{ "two_calls",                      0, 1, 0x5A, 2, OK, 0 },
	{ "ten_calls",                      3, 1, 0x5A, 10, OK, 0 },
	{ "ap_0_output_null",               0, 0, 0,    1, ERR, 0 },
	{ "ap_1_output_null",               1, 0, 0,    1, ERR, 0 },
	{ "ap_15_output_null",             15, 0, 0,    1, ERR, 0 },
	{ "ap_negative_output_null",       -1, 0, 0,    1, ERR, 0 },
	{ "ap_int_min_output_null",   INT_MIN, 0, 0,    1, ERR, 0 },
	{ "ap_int_max_output_null",   INT_MAX, 0, 0,    1, ERR, 0 },
	{ "output_null_two_calls",          0, 0, 0,    2, ERR, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
