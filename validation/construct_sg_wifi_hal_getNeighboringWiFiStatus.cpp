/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_getNeighboringWiFiStatus
 *
 * wifi_hal_getNeighboringWiFiStatus(radioIndex, &array, &size) and wifi_hal_getNeighboringWiFiStatus_test(...) (same worker, test_mode on).  Inputs crossed: neighbor_ap_array / output_array_size NULL;
 * radioIndex 0 / 1 / MAX_NUM_RADIOS / 99 / -1 / INT_MIN; no radio; no private interface; scan_state NONE / ERROR / STARTED / ABORTED / an out-of-range value (7); scan_has_results 0 / API (1) / TEST (2) /
 * both (3) / 0xFC (neither bit); copy_scan_results succeeding / failing.  Expected (CORRECT behaviour): NULL pointer or index outside 0..MAX_NUM_RADIOS-1 -> WIFI_HAL_INVALID_ARGUMENTS (-4); no radio / no
 * interface -> WIFI_HAL_ERROR; ABORTED / ERROR state -> WIFI_HAL_ERROR and the state reset to NONE (even when results are available); API results (or TEST results in the _test call) -> copied whatever the state;
 * otherwise NONE -> WIFI_HAL_ERROR, STARTED -> WIFI_HAL_NOT_READY with errno EAGAIN; after a copy the API flag is cleared (normal call) or the TEST flag is cleared only while the scan is STARTED (_test call);
 * a failing copy -> WIFI_HAL_ERROR; both mutexes are released on every path and the outputs are written only on success.  No crash case is expected.
 */
#include "hwr_wnw.h"
#include <limits.h>

#define NONE 0
#define ERR 1
#define RUN 2
#define ABT 3
/* name, test_api, arr_null, size_null, index, no_radio, no_iface, state, has, copy_ret, last */
hwr_wnw_case_t sg_wifi_hal_getNeighboringWiFiStatus_suite[] = {
	/* ---- arguments ---- */
	{ "array_null",             0, 1,0, 0, 0,0, NONE, 1, 0, 0 },
	{ "size_null",              0, 0,1, 0, 0,0, NONE, 1, 0, 0 },
	{ "both_null",              1, 1,1, 0, 0,0, NONE, 1, 0, 0 },
	{ "index_max_radios",       0, 0,0, MAX_NUM_RADIOS, 0,0, NONE, 1, 0, 0 },
	{ "index_99",               1, 0,0, 99, 0,0, NONE, 3, 0, 0 },
	{ "index_minus_1",          0, 0,0, -1, 0,0, NONE, 1, 0, 0 },
	{ "index_int_min",          0, 0,0, INT_MIN, 0,0, NONE, 1, 0, 0 },
	{ "no_radio",               0, 0,0, 0, 1,0, NONE, 1, 0, 0 },
	{ "no_interface",           0, 0,0, 0, 0,1, NONE, 1, 0, 0 },
	{ "no_interface_test_api",  1, 0,0, 1, 0,1, RUN, 3, 0, 0 },
	/* ---- scan state without results ---- */
	{ "state_none",             0, 0,0, 0, 0,0, NONE, 0, 0, 0 },
	{ "state_none_test_api",    1, 0,0, 1, 0,0, NONE, 0, 0, 0 },
	{ "state_started",          0, 0,0, 0, 0,0, RUN, 0, 0, 0 },
	{ "state_started_test_api", 1, 0,0, 1, 0,0, RUN, 0, 0, 0 },
	{ "state_aborted",          0, 0,0, 0, 0,0, ABT, 0, 0, 0 },
	{ "state_error",            0, 0,0, 1, 0,0, ERR, 0, 0, 0 },
	{ "state_aborted_with_api_results", 0, 0,0, 0, 0,0, ABT, 1, 0, 0 },
	{ "state_error_with_all_results",   1, 0,0, 0, 0,0, ERR, 3, 0, 0 },
	{ "state_aborted_test_api", 1, 0,0, 0, 0,0, ABT, 0, 0, 0 },
	{ "state_7_no_results",     0, 0,0, 0, 0,0, 7, 0, 0, 0 },
	{ "state_7_no_results_test_api", 1, 0,0, 0, 0,0, 7, 2, 0, 0 },
	/* ---- results available ---- */
	{ "api_results_state_none", 0, 0,0, 0, 0,0, NONE, 1, 0, 0 },
	{ "api_results_state_started", 0, 0,0, 1, 0,0, RUN, 1, 0, 0 },
	{ "api_and_test_results_normal_call", 0, 0,0, 0, 0,0, NONE, 3, 0, 0 },
	{ "test_results_normal_call_not_ready", 0, 0,0, 0, 0,0, RUN, 2, 0, 0 },
	{ "test_results_normal_call_none", 0, 0,0, 0, 0,0, NONE, 2, 0, 0 },
	{ "test_api_test_results_state_none", 1, 0,0, 0, 0,0, NONE, 2, 0, 0 },
	{ "test_api_test_results_started_cleared", 1, 0,0, 1, 0,0, RUN, 2, 0, 0 },
	{ "test_api_api_results_started", 1, 0,0, 0, 0,0, RUN, 1, 0, 0 },
	{ "test_api_both_results_state_none", 1, 0,0, 0, 0,0, NONE, 3, 0, 0 },
	{ "test_api_both_results_started", 1, 0,0, 0, 0,0, RUN, 3, 0, 0 },
	{ "results_other_bits_only_none", 0, 0,0, 0, 0,0, NONE, 0xFC, 0, 0 },
	{ "results_other_bits_state_7_copies", 0, 0,0, 0, 0,0, 7, 0xFC, 0, 0 },
	{ "api_results_state_7",    0, 0,0, 0, 0,0, 7, 0xFF, 0, 0 },
	/* ---- copy_scan_results failing ---- */
	{ "copy_fails_normal",      0, 0,0, 0, 0,0, NONE, 1, -1, 0 },
	{ "copy_fails_test_api",    1, 0,0, 1, 0,0, RUN, 2, -1, 0 },
	{ "copy_fails_state_started", 0, 0,0, 0, 0,0, RUN, 1, -1, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
