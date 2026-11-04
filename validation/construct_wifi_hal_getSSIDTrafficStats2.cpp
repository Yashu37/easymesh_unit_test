/*
 * UNIT TEST (input constructor): construct_wifi_hal_getSSIDTrafficStats2
 *
 * wifi_hal_getSSIDTrafficStats2(ssidIndex, output_struct) is the HAL IPC server wrapper for the platform
 * function wifi_getSSIDTrafficStats2: it logs, forwards both arguments and returns 0 whatever the platform
 * function returned.
 *
 * The platform function is a stub (below): it records its arguments, fills the whole output structure with
 * 0x3C (like the real implementation fills every counter) and returns a configurable value.
 * Inputs crossed: ssidIndex INT_MIN .. INT_MAX (8 values) x platform result (0, -1), more platform results
 * (1, -5, INT_MAX, INT_MIN), repeated calls, the log text and a NULL output structure (forked, so the SEGV is
 * visible but does not stop the run).  Expected result is the SAFE contract (arguments forwarded unchanged,
 * the platform result returned, a NULL output rejected), so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gts.h"

hwr_gts_rec_t hwr_gts_rec;
static int g_ret;

extern "C" INT wifi_getSSIDTrafficStats2(INT ssidIndex, wifi_ssidTrafficStats2_t *output_struct)
{
	hwr_gts_rec.calls++; hwr_gts_rec.ssid = ssidIndex; hwr_gts_rec.out = output_struct;
	memset(output_struct, 0x3C, sizeof(*output_struct));
	return g_ret;
}
void hwr_gts_configure(int callee_ret) { g_ret = callee_ret; memset(&hwr_gts_rec, 0, sizeof(hwr_gts_rec)); }

/* name, ssid_index, callee_ret, null_out, calls, check_log, expected_ret, forked */
#define SS(n, s, r)  { "ssid_" n "_platform_ret_" #r, s, r, 0, 1, 0, r, 0 }
hwr_gts_case_t wifi_hal_getSSIDTrafficStats2_suite[] = {
	SS("int_min", INT_MIN, 0), SS("int_min", INT_MIN, -1),
	SS("m1", -1, 0), SS("m1", -1, -1),
	SS("0", 0, 0), SS("0", 0, -1),
	SS("1", 1, 0), SS("1", 1, -1),
	SS("15", 15, 0), SS("15", 15, -1),
	SS("16", 16, 0), SS("16", 16, -1),
	SS("255", 255, 0), SS("255", 255, -1),
	SS("int_max", INT_MAX, 0), SS("int_max", INT_MAX, -1),
	{ "platform_ret_1_propagated",       0, 1,       0, 1, 0, 1, 0 },
	{ "platform_ret_m5_propagated",      0, -5,      0, 1, 0, -5, 0 },
	{ "platform_ret_int_max_propagated", 0, INT_MAX, 0, 1, 0, INT_MAX, 0 },
	{ "platform_ret_int_min_propagated", 0, INT_MIN, 0, 1, 0, INT_MIN, 0 },
	{ "repeated_calls_x3_ok",            2, 0,  0, 3, 0, 0, 0 },
	{ "repeated_calls_x3_failing",       2, -1, 0, 3, 0, -1, 0 },
	{ "log_has_function_name_and_enter", 1, 0,  0, 1, 1, 0, 0 },
	/* ---- crash group (forked): NULL output reaches the platform function ---- */
	{ "crash_output_null_ssid_0",        0, 0,  1, 1, 0, -1, 1 },
	{ "crash_output_null_ssid_1",        1, 0,  1, 1, 0, -1, 1 },
	{ "crash_output_null_ssid_int_max",  INT_MAX, 0, 1, 1, 0, -1, 1 },
	{ "crash_output_null_platform_fail", 0, -1, 1, 1, 0, -1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0 }
};
