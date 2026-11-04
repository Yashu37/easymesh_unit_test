/*
 * UNIT TEST (input constructor): construct_wifi_hal_getApAssociatedDeviceStats
 *
 * wifi_hal_getApAssociatedDeviceStats(apIndex, clientMacAddress, associated_dev_stats, handle) is the HAL IPC
 * server wrapper for the platform function wifi_getApAssociatedDeviceStats: it logs, forwards all four
 * arguments and returns 0 whatever the platform function returned.
 *
 * The platform function is a stub (below) that records its arguments, returns a configurable value and writes
 * the outputs like the real implementation does (stats pattern, *handle).  Inputs crossed: apIndex (INT_MIN ..
 * INT_MAX, 8 values) x platform result (0, -1), more platform results (1, -5, INT_MAX, INT_MIN), handle values
 * (0, 1, ULLONG_MAX), repeated calls, the log text, and every combination of NULL output pointers (forked, so
 * the SEGV is visible but does not stop the run).  Expected result is the SAFE contract (arguments forwarded
 * unchanged, the platform result returned, NULL pointers rejected), so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gas.h"

hwr_gas_rec_t hwr_gas_rec;
static int g_ret; static unsigned long long g_handle;

extern "C" INT wifi_getApAssociatedDeviceStats(INT apIndex, mac_address_t *clientMacAddress, wifi_associated_dev_stats_t *associated_dev_stats, ULLONG *handle)
{
	hwr_gas_rec.calls++; hwr_gas_rec.ap_index = apIndex; hwr_gas_rec.mac = clientMacAddress;
	hwr_gas_rec.stats = associated_dev_stats; hwr_gas_rec.handle = handle;
	memset(associated_dev_stats, 0x3C, sizeof(*associated_dev_stats));      /* like the platform code: fills stats and handle */
	*handle = g_handle;
	return g_ret;
}
void hwr_gas_configure(int callee_ret, unsigned long long handle_val) { g_ret = callee_ret; g_handle = handle_val; memset(&hwr_gas_rec, 0, sizeof(hwr_gas_rec)); }

/* name, ap_index, callee_ret, null_mask, handle_val, calls, check_log, expected_ret, forked */
#define AP(n, ap, r)  { "ap_" n "_platform_ret_" #r, ap, r, 0, 0x1122334455667788ULL, 1, 0, r, 0 }
hwr_gas_case_t wifi_hal_getApAssociatedDeviceStats_suite[] = {
	AP("int_min", INT_MIN, 0), AP("int_min", INT_MIN, -1),
	AP("m1",      -1, 0),      AP("m1",      -1, -1),
	AP("0",        0, 0),      AP("0",        0, -1),
	AP("1",        1, 0),      AP("1",        1, -1),
	AP("15",      15, 0),      AP("15",      15, -1),
	AP("16",      16, 0),      AP("16",      16, -1),
	AP("255",    255, 0),      AP("255",    255, -1),
	AP("int_max", INT_MAX, 0), AP("int_max", INT_MAX, -1),
	{ "platform_ret_1_propagated",       0, 1,        0, 1, 1, 0, 1, 0 },
	{ "platform_ret_m5_propagated",      0, -5,       0, 1, 1, 0, -5, 0 },
	{ "platform_ret_int_max_propagated", 0, INT_MAX,  0, 1, 1, 0, INT_MAX, 0 },
	{ "platform_ret_int_min_propagated", 0, INT_MIN,  0, 1, 1, 0, INT_MIN, 0 },
	{ "handle_zero",                     3, 0, 0, 0ULL, 1, 0, 0, 0 },
	{ "handle_one",                      3, 0, 0, 1ULL, 1, 0, 0, 0 },
	{ "handle_ullong_max",               3, 0, 0, ~0ULL, 1, 0, 0, 0 },
	{ "repeated_calls_x3_ok",            2, 0, 0, 7ULL, 3, 0, 0, 0 },
	{ "repeated_calls_x3_failing",       2, -1, 0, 7ULL, 3, 0, -1, 0 },
	{ "log_has_function_name_and_enter", 1, 0, 0, 5ULL, 1, 1, 0, 0 },
	/* ---- crash group (forked): NULL pointers reach the platform function ---- */
	{ "crash_mac_null",                  1, 0, 1, 5ULL, 1, 0, -1, 1 },
	{ "crash_stats_null",                1, 0, 2, 5ULL, 1, 0, -1, 1 },
	{ "crash_handle_null",               1, 0, 4, 5ULL, 1, 0, -1, 1 },
	{ "crash_all_null",                  1, 0, 7, 5ULL, 1, 0, -1, 1 },
	{ "crash_mac_and_handle_null",       1, 0, 5, 5ULL, 1, 0, -1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
