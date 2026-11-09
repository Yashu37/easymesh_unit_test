/*
 * UNIT TEST (input constructor): construct_int_wifi_setApManagementFramePowerControl
 *
 * wifi_setApManagementFramePowerControl(apIndex, dBm) (platform/intel) looks up the VAP interface (error line "interface for ap index:<n> not found" and
 * RETURN_ERR when there is none, no vendor command) and otherwise sends the vendor command SET_MGMT_FRAME_PWR_CTRL with the 4-byte dBm value through
 * wifi_drv_vendor_cmd (the interface is only passed on, never dereferenced), returns the vendor result and, when it is non-zero, logs
 * "nl80211: sending _MGMT_FRAME_PWR_CTRL failed: <res> (<strerror>)" (the error text is not checked, see the handler header).  The suite crosses:
 * apIndex 0 / 1 / 15 / -1 / INT_MAX with the interface found / missing / only another VAP present; dBm 0 / 1 / -1 / 10 / 20 / 23 / 30 / 127 / -127 / 128 / 255 /
 * -128 / INT_MIN / INT_MAX; vendor result 0 / -1 / -5 / -22 / -95 / 1 / 22 / INT_MAX; repeated calls; and a log slot that is empty / holds text / is almost
 * full / is full.  Checks: the return value (the vendor result, RETURN_ERR when no interface), the vendor command was sent exactly once per call with
 * OUI_LTQ, the sub-command, the dBm bytes, length 4, nested = -1 and the same interface pointer (never when there is no interface), the log lines, the guard
 * slab.  Row layout: see hwr_imp_case_t.
 */
#include <limits.h>
#include "hwr_imp.h"

/* name, ap_index, has_iface (0 none, 1 found, 2 other VAP), dbm, vendor_ret, calls, prefill */
hwr_imp_case_t int_wifi_setApManagementFramePowerControl_suite[] = {
	/* ---- power values ---- */
	{ "dbm_0",                       0, 1,        0,  0, 1,   0 },
	{ "dbm_1",                       0, 1,        1,  0, 1,   0 },
	{ "dbm_minus_1",                 0, 1,       -1,  0, 1,   0 },
	{ "dbm_10",                      0, 1,       10,  0, 1,   0 },
	{ "dbm_20",                      0, 1,       20,  0, 1,   0 },
	{ "dbm_23",                      0, 1,       23,  0, 1,   0 },
	{ "dbm_30",                      0, 1,       30,  0, 1,   0 },
	{ "dbm_127",                     0, 1,      127,  0, 1,   0 },
	{ "dbm_minus_127",               0, 1,     -127,  0, 1,   0 },
	{ "dbm_128",                     0, 1,      128,  0, 1,   0 },
	{ "dbm_255",                     0, 1,      255,  0, 1,   0 },
	{ "dbm_minus_128",               0, 1,     -128,  0, 1,   0 },
	{ "dbm_int_min",                 0, 1,  INT_MIN,  0, 1,   0 },
	{ "dbm_int_max",                 0, 1,  INT_MAX,  0, 1,   0 },
	/* ---- apIndex / interface ---- */
	{ "ap_1",                        1, 1,       20,  0, 1,   0 },
	{ "ap_15",                      15, 1,       20,  0, 1,   0 },
	{ "ap_negative",                -1, 1,       20,  0, 1,   0 },
	{ "ap_int_max",            INT_MAX, 1,       20,  0, 1,   0 },
	{ "iface_missing",               0, 0,       20,  0, 1,   0 },
	{ "iface_missing_vendor_fails", 15, 0,       20, -22, 1,  0 },
	{ "iface_other_vap_only",        0, 2,       20,  0, 1,   0 },
	{ "iface_missing_two_calls",     3, 0,       20,  0, 2,   0 },
	/* ---- vendor results ---- */
	{ "vendor_minus_1",              0, 1,       20, -1, 1,   0 },
	{ "vendor_minus_5",              0, 1,       20, -5, 1,   0 },
	{ "vendor_minus_22",             0, 1,       20, -22, 1,  0 },
	{ "vendor_minus_95",             0, 1,       20, -95, 1,  0 },
	{ "vendor_positive_1",           0, 1,       20,  1, 1,   0 },
	{ "vendor_positive_22",          0, 1,       20, 22, 1,   0 },
	{ "vendor_int_max",              0, 1,       20, INT_MAX, 1, 0 },
	{ "two_calls_ok",                0, 1,       17,  0, 2,   0 },
	{ "ten_calls_minus_5",           0, 1,       17, -5, 10,  0 },
	/* ---- log slot ---- */
	{ "log_prefilled_1_fail",        0, 1,       20, -22, 1,  1 },
	{ "log_prefilled_100_fail",      0, 1,       20, -22, 1, 100 },
	{ "log_almost_full_fail",        0, 1,       20, -22, 1, 254 },
	{ "log_full_ok",                 0, 1,       20,  0, 1, 255 },
	{ "log_full_iface_missing",      0, 0,       20,  0, 1, 255 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};
