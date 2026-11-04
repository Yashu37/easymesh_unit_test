/*
 * UNIT TEST (input constructor): construct_wifi_hal_getApAssociatedDeviceTxStatsResult
 *
 * wifi_hal_getApAssociatedDeviceTxStatsResult(radioIndex, clientMacAddress, stats_array, output_array_size,
 * handle) is the HAL IPC server wrapper for the platform function of the same name (without hal_): it logs,
 * forwards all five arguments, returns the platform result and, on success, logs every returned statistics
 * entry (walking *stats_array for *output_array_size entries).  On success the platform function allocates
 * *stats_array (n entries), sets *output_array_size = n and *handle.
 *
 * The platform function is a stub (below): it records its arguments, reads the client MAC, writes *handle
 * and, when its configured result is 0, allocates n entries (pattern 0x3C) and sets the out parameters; on a
 * failure it leaves *stats_array and *output_array_size untouched, like a real implementation.
 * Inputs crossed: radioIndex (8 values) x platform result (0, -1), more platform results (1, -5, INT_MAX,
 * INT_MIN), entry counts 0 / 1 / 3 / 64, repeated calls, the log, and every NULL pointer combination (forked,
 * so the SEGV is visible but does not stop the run).  Expected result is the SAFE contract (arguments
 * forwarded unchanged, the platform result returned, NULL pointers rejected), so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gtx.h"

hwr_gtx_rec_t hwr_gtx_rec;
static int g_ret; static unsigned g_n; static int g_incons;

extern "C" INT wifi_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
	volatile unsigned char m0;
	hwr_gtx_rec.calls++; hwr_gtx_rec.radio = radioIndex; hwr_gtx_rec.mac = clientMacAddress;
	hwr_gtx_rec.arr = stats_array; hwr_gtx_rec.size = output_array_size; hwr_gtx_rec.handle = handle;
	m0 = (*clientMacAddress)[0]; (void)m0;                  /* the platform code looks the client up by MAC */
	*handle = 0x1234;
	if (g_ret != 0) return g_ret;
	*output_array_size = g_n;
	*stats_array = (g_n && !g_incons) ? (wifi_associated_dev_rate_info_tx_stats_t *)malloc(g_n * sizeof(wifi_associated_dev_rate_info_tx_stats_t)) : NULL;
	if (*stats_array) memset(*stats_array, 0x3C, g_n * sizeof(wifi_associated_dev_rate_info_tx_stats_t));
	return 0;
}
void hwr_gtx_configure(int callee_ret, unsigned n_entries, int inconsistent) { g_ret = callee_ret; g_n = n_entries; g_incons = inconsistent; memset(&hwr_gtx_rec, 0, sizeof(hwr_gtx_rec)); }

/* name, radio, callee_ret, n_entries, null_mask, calls, check_log, expected_ret, forked */
#define RR(n, rad, r)  { "radio_" n "_platform_ret_" #r, rad, r, 3, 0, 1, 0, r, 0 }
hwr_gtx_case_t wifi_hal_getApAssociatedDeviceTxStatsResult_suite[] = {
	RR("int_min", INT_MIN, 0), RR("int_min", INT_MIN, -1),
	RR("m1", -1, 0), RR("m1", -1, -1),
	RR("0", 0, 0), RR("0", 0, -1),
	RR("1", 1, 0), RR("1", 1, -1),
	RR("15", 15, 0), RR("15", 15, -1),
	RR("255", 255, 0), RR("255", 255, -1),
	RR("int_max", INT_MAX, 0), RR("int_max", INT_MAX, -1),
	{ "platform_ret_1_propagated",       0, 1,       3, 0, 1, 0, 1, 0 },
	{ "platform_ret_m5_propagated",      0, -5,      3, 0, 1, 0, -5, 0 },
	{ "platform_ret_int_max_propagated", 0, INT_MAX, 3, 0, 1, 0, INT_MAX, 0 },
	{ "platform_ret_int_min_propagated", 0, INT_MIN, 3, 0, 1, 0, INT_MIN, 0 },
	{ "entries_0",                       0, 0, 0,  0, 1, 0, 0, 0 },
	{ "entries_1",                       0, 0, 1,  0, 1, 0, 0, 0 },
	{ "entries_64",                      0, 0, 64, 0, 1, 0, 0, 0 },
	{ "repeated_calls_x3_ok",            2, 0, 5,  0, 3, 0, 0, 0 },
	{ "repeated_calls_x3_failing",       2, -1, 5, 0, 3, 0, -1, 0 },
	{ "log_has_function_name_and_enter", 1, 0, 2,  0, 1, 1, 0, 0 },
	/* ---- hardening (forked): the platform reports 3 entries but returns no array; the wrapper walks it for the log ---- */
	{ "crash_platform_size_without_array", 1, 0, 3, 16, 1, 0, 0, 1 },
	/* ---- crash group (forked): NULL pointers reach the platform function ---- */
	{ "crash_mac_null",                  1, 0, 3, 1, 1, 0, -1, 1 },
	{ "crash_stats_array_null",          1, 0, 3, 2, 1, 0, -1, 1 },
	{ "crash_output_array_size_null",    1, 0, 3, 4, 1, 0, -1, 1 },
	{ "crash_handle_null",               1, 0, 3, 8, 1, 0, -1, 1 },
	{ "crash_all_null",                  1, 0, 3, 15, 1, 0, -1, 1 },
	{ "crash_stats_array_and_size_null", 1, 0, 3, 6, 1, 0, -1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
