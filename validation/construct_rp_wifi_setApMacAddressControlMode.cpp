/*
 * UNIT TEST (input constructor): construct_rp_wifi_setApMacAddressControlMode
 *
 * wifi_setApMacAddressControlMode(apIndex, filterMode) (platform/raspberry-pi) looks up the VAP interface (error line "interface for ap index:<n> not found" and
 * RETURN_ERR when there is none) and, for an AP-mode VAP, sets mac_filter_enable / mac_filter_mode from filterMode: 0 -> FALSE / black list, 1 -> TRUE / white
 * list, 2 -> TRUE / black list; every other filterMode and every non-AP VAP leaves the VAP as it was; it returns RETURN_OK in all found cases.  The suite
 * crosses: filterMode 0 / 1 / 2 / 3 / -1 / 255 / INT_MIN / INT_MAX, VAP mode AP / STA / monitor, stale (enable, mode) values before the call, apIndex 0 / 1 / 15 /
 * -1 / INT_MIN / INT_MAX, interface found / missing / only another VAP present, repeated calls (also changing the mode between calls is covered by the order of
 * rows), and a log slot that is empty / holds text / is almost full / is full.  Checks: return value; mac_filter_enable and mac_filter_mode exactly as expected;
 * every other byte of the interface unchanged (all of it POISONED except vap_mode, mac_filter_enable and mac_filter_mode); one lookup per call; the log lines;
 * the guard slab.  Row layout: see hwr_rmc_case_t.
 */
#include <limits.h>
#include "hwr_rmc.h"

#define AP 0
#define STA 1
#define MON 2
#define BL 0    /* wifi_mac_filter_mode_black_list */
#define WL 1    /* wifi_mac_filter_mode_white_list */

/* name, ap_index, has_iface (0 none, 1 found, 2 other VAP only), vap_mode, filter_mode, pre_enable, pre_mode, calls, prefill */
hwr_rmc_case_t rp_wifi_setApMacAddressControlMode_suite[] = {
	/* ---- AP VAP, every filterMode, from both stale states ---- */
	{ "ap_mode_0_from_enabled_white",   0, 1, AP,        0, 1, WL, 1,   0 },
	{ "ap_mode_0_from_disabled_black",  0, 1, AP,        0, 0, BL, 1,   0 },
	{ "ap_mode_1_from_disabled_black",  0, 1, AP,        1, 0, BL, 1,   0 },
	{ "ap_mode_1_from_enabled_white",   0, 1, AP,        1, 1, WL, 1,   0 },
	{ "ap_mode_2_from_disabled_white",  0, 1, AP,        2, 0, WL, 1,   0 },
	{ "ap_mode_2_from_enabled_black",   0, 1, AP,        2, 1, BL, 1,   0 },
	{ "ap_mode_3_unknown_enabled_white",0, 1, AP,        3, 1, WL, 1,   0 },
	{ "ap_mode_3_unknown_disabled_black",0,1, AP,        3, 0, BL, 1,   0 },
	{ "ap_mode_negative_unknown",       0, 1, AP,       -1, 1, WL, 1,   0 },
	{ "ap_mode_255_unknown",            0, 1, AP,      255, 0, BL, 1,   0 },
	{ "ap_mode_int_min_unknown",        0, 1, AP,  INT_MIN, 1, WL, 1,   0 },
	{ "ap_mode_int_max_unknown",        0, 1, AP,  INT_MAX, 0, WL, 1,   0 },
	/* ---- non-AP VAPs: nothing is applied ---- */
	{ "sta_mode_1_ignored",             0, 1, STA,       1, 0, BL, 1,   0 },
	{ "sta_mode_2_ignored",             0, 1, STA,       2, 0, WL, 1,   0 },
	{ "sta_mode_0_ignored",             0, 1, STA,       0, 1, WL, 1,   0 },
	{ "monitor_mode_1_ignored",         0, 1, MON,       1, 0, BL, 1,   0 },
	{ "monitor_mode_0_ignored",         0, 1, MON,       0, 1, WL, 1,   0 },
	/* ---- apIndex / interface ---- */
	{ "ap_1_mode_1",                    1, 1, AP,        1, 0, BL, 1,   0 },
	{ "ap_15_mode_2",                  15, 1, AP,        2, 0, WL, 1,   0 },
	{ "ap_negative_found_mode_1",      -1, 1, AP,        1, 0, BL, 1,   0 },
	{ "ap_int_min_found_mode_2",  INT_MIN, 1, AP,        2, 0, WL, 1,   0 },
	{ "ap_int_max_found_mode_0",  INT_MAX, 1, AP,        0, 1, WL, 1,   0 },
	{ "iface_missing",                  0, 0, AP,        1, 0, BL, 1,   0 },
	{ "iface_missing_ap_15",           15, 0, AP,        2, 0, BL, 1,   0 },
	{ "iface_other_vap_only",           0, 2, AP,        1, 0, BL, 1,   0 },
	{ "iface_missing_two_calls",        3, 0, AP,        1, 0, BL, 2,   0 },
	/* ---- repeated calls ---- */
	{ "two_calls_mode_1",               0, 1, AP,        1, 0, BL, 2,   0 },
	{ "ten_calls_mode_2",               2, 1, AP,        2, 0, WL, 10,  0 },
	{ "two_calls_unknown_mode",         0, 1, AP,        3, 1, WL, 2,   0 },
	/* ---- log slot ---- */
	{ "log_prefilled_1_missing",        0, 0, AP,        1, 0, BL, 1,   1 },
	{ "log_prefilled_100_missing",      0, 0, AP,        1, 0, BL, 1, 100 },
	{ "log_almost_full_missing",        0, 0, AP,        1, 0, BL, 1, 254 },
	{ "log_full_missing",               0, 0, AP,        1, 0, BL, 1, 255 },
	{ "log_full_found_mode_1",          0, 1, AP,        1, 0, BL, 1, 255 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
