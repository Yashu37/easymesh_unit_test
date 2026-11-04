/*
 * UNIT TEST (input constructor): construct_wifi_hal_getApAssociatedClientDiagnosticResult
 *
 * wifi_hal_getApAssociatedClientDiagnosticResult(apIndex, mac_addr, dev_conn) is the HAL IPC server wrapper
 * for the platform function wifi_getApAssociatedClientDiagnosticResult: it logs, forwards the three arguments
 * and returns 0 whatever the platform function returned.  (The platform implementations in rdk-wifi-hal for
 * banana-pi, raspberry-pi and the emulator simply return RETURN_ERR.)
 *
 * The platform function is a stub (below): it records its arguments, reads the client MAC (HAL_IPC_MAC_ADDR_
 * SIZE_BYTES bytes), fills the whole wifi_associated_dev3_t with 0x3C and returns a configurable value.
 * Inputs crossed: apIndex INT_MIN .. INT_MAX (8 values) x platform result (0, -1), more platform results
 * (1, -5, INT_MAX, INT_MIN), repeated calls, the log text, and a NULL mac_addr / dev_conn / both (forked, so
 * the SEGV is visible but does not stop the run).  Expected result is the SAFE contract (arguments forwarded
 * unchanged, the platform result returned, NULL pointers rejected), so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gcd.h"

hwr_gcd_rec_t hwr_gcd_rec;
static int g_ret;

extern "C" INT wifi_getApAssociatedClientDiagnosticResult(INT apIndex, char *mac_addr, wifi_associated_dev3_t *dev_conn)
{
	volatile char sink = 0;
	hwr_gcd_rec.calls++; hwr_gcd_rec.ap_index = apIndex; hwr_gcd_rec.mac = mac_addr; hwr_gcd_rec.dev = dev_conn;
	for (int i = 0; i < HAL_IPC_MAC_ADDR_SIZE_BYTES; i++) sink ^= mac_addr[i];     /* the platform code looks the client up by MAC */
	memset(dev_conn, 0x3C, sizeof(*dev_conn));
	return g_ret;
}
void hwr_gcd_configure(int callee_ret) { g_ret = callee_ret; memset(&hwr_gcd_rec, 0, sizeof(hwr_gcd_rec)); }

/* name, ap_index, callee_ret, null_mask, calls, check_log, expected_ret, forked */
#define AP(n, ap, r)  { "ap_" n "_platform_ret_" #r, ap, r, 0, 1, 0, r, 0 }
hwr_gcd_case_t wifi_hal_getApAssociatedClientDiagnosticResult_suite[] = {
	AP("int_min", INT_MIN, 0), AP("int_min", INT_MIN, -1),
	AP("m1", -1, 0), AP("m1", -1, -1),
	AP("0", 0, 0), AP("0", 0, -1),
	AP("1", 1, 0), AP("1", 1, -1),
	AP("15", 15, 0), AP("15", 15, -1),
	AP("16", 16, 0), AP("16", 16, -1),
	AP("255", 255, 0), AP("255", 255, -1),
	AP("int_max", INT_MAX, 0), AP("int_max", INT_MAX, -1),
	{ "platform_ret_1_propagated",       0, 1,       0, 1, 0, 1, 0 },
	{ "platform_ret_m5_propagated",      0, -5,      0, 1, 0, -5, 0 },
	{ "platform_ret_int_max_propagated", 0, INT_MAX, 0, 1, 0, INT_MAX, 0 },
	{ "platform_ret_int_min_propagated", 0, INT_MIN, 0, 1, 0, INT_MIN, 0 },
	{ "repeated_calls_x3_ok",            2, 0,  0, 3, 0, 0, 0 },
	{ "repeated_calls_x3_failing",       2, -1, 0, 3, 0, -1, 0 },
	{ "log_has_function_name_and_enter", 1, 0,  0, 1, 1, 0, 0 },
	/* ---- crash group (forked): NULL pointers reach the platform function ---- */
	{ "crash_mac_null",                  1, 0,  1, 1, 0, -1, 1 },
	{ "crash_dev_conn_null",             1, 0,  2, 1, 0, -1, 1 },
	{ "crash_both_null",                 1, 0,  3, 1, 0, -1, 1 },
	{ "crash_mac_null_platform_fail",    1, -1, 1, 1, 0, -1, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0 }
};
