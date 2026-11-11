/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_set_neighbor_report
 *
 * wifi_hal_set_neighbor_report(apIndex, add, mac).  Inputs crossed: apIndex 0 / 1 / 14 / 15 / UINT_MAX; add 0 (remove) / 1 (add) / 2 / UINT_MAX; mac a normal address in an exact 6-byte heap block / all 0xff /
 * all zero / a NULL pointer; the platform function present / absent; the platform function returning 0 / -1.  Expected (CORRECT behaviour): the platform function is looked up exactly once; when present it is
 * called exactly once with apIndex, add and the SAME mac pointer (the wrapper does not read or change the mac bytes) and its return value does not matter; when absent nothing is called.  No crash case is
 * expected.
 */
#include "hwr_wnb.h"
#include <limits.h>

/* name, ap_index, add, mac_mode, no_fn, fn_ret, last */
hwr_wnb_case_t sg_wifi_hal_set_neighbor_report_suite[] = {
	{ "ap0_add",                 0, 1, 1, 0, 0, 0 },
	{ "ap1_remove",              1, 0, 1, 0, 0, 0 },
	{ "ap14_add",                14, 1, 1, 0, 0, 0 },
	{ "ap15_forwarded_unchecked",15, 1, 1, 0, 0, 0 },
	{ "ap_uint_max_forwarded",   UINT_MAX, 1, 1, 0, 0, 0 },
	{ "add_2_forwarded",         3, 2, 1, 0, 0, 0 },
	{ "add_uint_max_forwarded",  3, UINT_MAX, 1, 0, 0, 0 },
	{ "mac_broadcast",           2, 1, 2, 0, 0, 0 },
	{ "mac_all_zero",            2, 0, 3, 0, 0, 0 },
	{ "mac_null_forwarded",      2, 1, 0, 0, 0, 0 },
	{ "platform_returns_error_ignored", 4, 1, 1, 0, -1, 0 },
	{ "platform_returns_1_ignored",     4, 0, 1, 0, 1, 0 },
	{ "no_platform_function",    0, 1, 1, 1, 0, 0 },
	{ "no_platform_function_null_mac", 7, 0, 0, 1, 0, 0 },
	{ "no_platform_function_big_ap", UINT_MAX, UINT_MAX, 1, 1, 0, 0 },
	{ NULL }
};
