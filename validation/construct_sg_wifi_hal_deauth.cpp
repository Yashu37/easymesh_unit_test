/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_deauth
 *
 * wifi_hal_deauth(vap_index, status, mac).  Inputs crossed: 1 / 2 / 3 interfaces; vap_index of an existing AP VAP (first, middle, last), of an unknown VAP (3, 15, -1, INT_MAX, a
 * VAP when no interface exists) and of a STA VAP; mac NULL / pointer to a fully POISONED runner slab (never read or written by the wrapper) / dangling; status 0, 3, 7, -1, INT_MAX,
 * INT_MIN; repeated calls; a log slot that must stay untouched.  Expected (correct behaviour): an AP VAP -> wifi_drv_sta_deauth once per call with the VAP's own_addr, the mac pointer
 * and the status unchanged; an unknown VAP or a STA VAP -> no deauth and no crash.  Rows with last = 1 break the original (NULL interface dereferenced, STA data read as hostapd data).
 */
#include "hwr_wda.h"
#include <limits.h>

/* name, vap_index, n_if, sta, mac_mode, status, calls, prefill, last */
hwr_wda_case_t sg_wifi_hal_deauth_suite[] = {
	{ "ap_first_of_3",             0, 3, 0, 1,  3,  1,   0, 0 },
	{ "ap_middle_of_3",            1, 3, 0, 1,  3,  1,   0, 0 },
	{ "ap_last_of_3",              2, 3, 0, 1,  3,  1,   0, 0 },
	{ "ap_only_interface",         0, 1, 0, 1,  3,  1,   0, 0 },
	{ "ap_of_2",                   1, 2, 0, 1,  3,  1,   0, 0 },
	{ "ap_status_0",               1, 3, 0, 1,  0,  1,   0, 0 },
	{ "ap_status_7",               1, 3, 0, 1,  7,  1,   0, 0 },
	{ "ap_status_minus1",          1, 3, 0, 1, -1,  1,   0, 0 },
	{ "ap_status_int_max",         1, 3, 0, 1, INT_MAX, 1, 0, 0 },
	{ "ap_status_int_min",         1, 3, 0, 1, INT_MIN, 1, 0, 0 },
	{ "ap_mac_null",               1, 3, 0, 0,  3,  1,   0, 0 },
	{ "ap_mac_dangling",           1, 3, 0, 2,  3,  1,   0, 0 },
	{ "ap_two_calls",              1, 3, 0, 1,  3,  2,   0, 0 },
	{ "ap_fifty_calls",            2, 3, 0, 1,  3, 50,   0, 0 },
	{ "ap_log_full",               1, 3, 0, 1,  3,  1, 255, 0 },
	/* STA VAP: its union holds STA data, not a hostapd_data */
	{ "sta_vap_first",             0, 3, 1, 1,  3,  1,   0, 0 },
	{ "sta_vap_last",              2, 3, 1, 1,  3,  1,   0, 0 },
	{ "sta_vap_two_calls",         1, 3, 1, 1,  3,  2,   0, 0 },
	/* unknown VAP: get_interface_by_vap_index() returns NULL, which the original dereferences */
	{ "unknown_vap_3",             3, 3, 0, 1,  3,  1,   0, 1 },
	{ "unknown_vap_15",           15, 3, 0, 1,  3,  1,   0, 1 },
	{ "unknown_vap_minus1",       -1, 3, 0, 1,  3,  1,   0, 1 },
	{ "unknown_vap_int_max",  INT_MAX, 3, 0, 1,  3,  1,   0, 1 },
	{ "no_interfaces",             0, 0, 0, 1,  3,  1,   0, 1 },
	{ "unknown_vap_mac_null",      5, 3, 0, 0,  3,  1,   0, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
