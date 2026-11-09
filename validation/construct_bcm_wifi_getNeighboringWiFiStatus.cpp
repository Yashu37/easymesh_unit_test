/*
 * UNIT TEST (input constructor): construct_bcm_wifi_getNeighboringWiFiStatus
 *
 * wifi_getNeighboringWiFiStatus (platform/broadcom) forwards (radio_index, neighbor_ap_array, output_array_size) to wifi_hal_getNeighboringWiFiStatus,
 * returns WIFI_HAL_NOT_READY unchanged, logs a line when the core returns RETURN_ERR (-1) and returns the core result in every case.  It never touches
 * the output slots itself.  The suite crosses: core result 0 / RETURN_ERR / WIFI_HAL_NOT_READY / other negative and positive values, radio_index 0 / 1 /
 * 2 / -1 / INT_MIN / INT_MAX, each output pointer NULL / the runner's slot (POISONED during the call) / dangling, repeated calls and a log slot that is
 * empty / holds text / is almost full / is full.  Checks: the core was called once per call with the same arguments, the return value, the log line only
 * for RETURN_ERR, and the poisoned output slots untouched.  The core logic itself is tested by the banana-pi wifi_getNeighboringWiFiStatus harness.
 */
#include <limits.h>
#include "hwr_bgn.h"

#define OK    0
#define ERR   (-1)
#define NR    WIFI_HAL_NOT_READY

/* name, radio_index, array_mode, size_mode, core_ret, calls, prefill */
hwr_bgn_case_t wifi_getNeighboringWiFiStatus_bcm_suite[] = {
	{ "core_ok",                        0, 1, 1, OK,       1,   0 },
	{ "core_error_logged",              0, 1, 1, ERR,      1,   0 },
	{ "core_not_ready_forwarded",       0, 1, 1, NR,       1,   0 },
	{ "core_minus_2_forwarded",         0, 1, 1, -2,       1,   0 },
	{ "core_minus_5_forwarded",         0, 1, 1, -5,       1,   0 },
	{ "core_positive_1_forwarded",      0, 1, 1, 1,        1,   0 },
	{ "core_int_min_forwarded",         0, 1, 1, INT_MIN,  1,   0 },
	{ "core_int_max_forwarded",         0, 1, 1, INT_MAX,  1,   0 },
	{ "radio_1_ok",                     1, 1, 1, OK,       1,   0 },
	{ "radio_2_error",                  2, 1, 1, ERR,      1,   0 },
	{ "radio_negative_ok",             -1, 1, 1, OK,       1,   0 },
	{ "radio_int_min_error",      INT_MIN, 1, 1, ERR,      1,   0 },
	{ "radio_int_max_not_ready",  INT_MAX, 1, 1, NR,       1,   0 },
	{ "array_null_ok",                  0, 0, 1, OK,       1,   0 },
	{ "size_null_ok",                   0, 1, 0, OK,       1,   0 },
	{ "both_null_error",                0, 0, 0, ERR,      1,   0 },
	{ "array_dangling_ok",              0, 2, 1, OK,       1,   0 },
	{ "size_dangling_error",            0, 1, 2, ERR,      1,   0 },
	{ "both_dangling_not_ready",        0, 2, 2, NR,       1,   0 },
	{ "two_calls_ok",                   0, 1, 1, OK,       2,   0 },
	{ "two_calls_error",                0, 1, 1, ERR,      2,   0 },
	{ "ten_calls_not_ready",            0, 1, 1, NR,      10,   0 },
	{ "log_prefilled_1_error",          0, 1, 1, ERR,      1,   1 },
	{ "log_prefilled_100_error",        0, 1, 1, ERR,      1, 100 },
	{ "log_almost_full_error",          0, 1, 1, ERR,      1, 254 },
	{ "log_full_error",                 0, 1, 1, ERR,      1, 255 },
	{ "log_full_ok",                    0, 1, 1, OK,       1, 255 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
