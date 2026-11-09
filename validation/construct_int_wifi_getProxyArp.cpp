/*
 * UNIT TEST (input constructor): construct_int_wifi_getProxyArp
 *
 * wifi_getProxyArp(apIndex, enabled) (platform/intel) is an empty stub that returns RETURN_ERR (-1) for every input and never writes *enabled, i.e.
 * the platform reports the feature as unsupported (the banana-pi stub returns 0 here, the intel stub returns RETURN_ERR): no finding.  The suite pins that contract: every
 * combination returns WIFI_HAL_ERROR and leaves the output slot (stale non-zero value, canary bytes around it), the guard slab and the log
 * untouched.  Inputs crossed: apIndex 0 / 1 / 15 / -1 / INT_MIN / INT_MAX, output NULL / valid, stale values, repeated calls.
 */
#include <limits.h>
#include "hwr_igp.h"

#define ERR WIFI_HAL_ERROR

/* name, ap_index, out_mode, preset, calls, expected_ret, expected_val (the output slot must keep its stale value) */
hwr_igp_case_t int_wifi_getProxyArp_suite[] = {
	{ "ap_0_valid_output", 0, 1, 0x5A, 1, ERR, 0x5A },
	{ "ap_1_valid_output", 1, 1, 0x5A, 1, ERR, 0x5A },
	{ "ap_15_valid_output", 15, 1, 0x5A, 1, ERR, 0x5A },
	{ "ap_negative_valid_output", -1, 1, 0x5A, 1, ERR, 0x5A },
	{ "ap_int_min_valid_output", INT_MIN, 1, 0x5A, 1, ERR, 0x5A },
	{ "ap_int_max_valid_output", INT_MAX, 1, 0x5A, 1, ERR, 0x5A },
	{ "stale_1", 0, 1, 1, 1, ERR, 1 },
	{ "stale_2", 0, 1, 2, 1, ERR, 2 },
	{ "stale_0x7F", 0, 1, 0x7F, 1, ERR, 0x7F },
	{ "stale_0x80", 0, 1, 0x80, 1, ERR, 0x80 },
	{ "stale_0xFF", 0, 1, 0xFF, 1, ERR, 0xFF },
	{ "stale_0", 0, 1, 0, 1, ERR, 0 },
	{ "ap_1_stale_1", 1, 1, 1, 1, ERR, 1 },
	{ "ap_15_stale_0xff", 15, 1, 0xFF, 1, ERR, 0xFF },
	{ "two_calls", 0, 1, 0x5A, 2, ERR, 0x5A },
	{ "ten_calls", 3, 1, 0x5A, 10, ERR, 0x5A },
	{ "ap_0_output_null", 0, 0, 0, 1, ERR, 0 },
	{ "ap_1_output_null", 1, 0, 0, 1, ERR, 0 },
	{ "ap_15_output_null", 15, 0, 0, 1, ERR, 0 },
	{ "ap_negative_output_null", -1, 0, 0, 1, ERR, 0 },
	{ "ap_int_min_output_null", INT_MIN, 0, 0, 1, ERR, 0 },
	{ "ap_int_max_output_null", INT_MAX, 0, 0, 1, ERR, 0 },
	{ "output_null_two_calls", 0, 0, 0, 2, ERR, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
