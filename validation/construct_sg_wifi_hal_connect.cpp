/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_connect
 *
 * wifi_hal_connect(ap_index, bss).  Inputs crossed: 1 / 2 / 3 interfaces; ap_index of a STA VAP (first, middle, last), of an AP VAP (its union holds hostapd data, which the function must not
 * read), of an unknown VAP (3, 15, -1, INT_MAX, INT_MIN, no interface at all); bss NULL / a bss with a non-zero bssid / a bss with an all-zero bssid (the strongest scan entry with the VAP's SSID is
 * used); scan lists of 0 .. 5 entries with matching / non-matching SSIDs and rssi values from INT_MIN to +10 (including exactly -100 and below); a VAP with the ignite (repurposed) SSID; an empty
 * SSID; nl80211_connect_sta failing; repeated calls; a log slot nearly full.  Expected (correct behaviour): NULL bss -> -4; unknown VAP -> -1; AP VAP -> -4; otherwise the explicit bss, or the
 * strongest scan entry whatever its rssi, becomes the backhaul and nl80211_connect_sta runs once (return -1 when it fails); no matching entry -> -1 and no connect; the scan-list mutex is always
 * released.  No row crashes the original.
 */
#include "hwr_whc.h"
#include <limits.h>

/* name, vap_index, n_if, sta_mask, bss_mode, n_scan, match_mask, rssi[5], ignite, ignite_match, empty_ssid, connect_ret, calls, prefill, last */
hwr_whc_case_t sg_wifi_hal_connect_suite[] = {
	/* ---- explicit bss ---- */
	{ "explicit_sta_first_of_3",    0, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "explicit_sta_middle_of_3",   1, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "explicit_sta_last_of_3",     2, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "explicit_sta_only_interface",0, 1, 1, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "explicit_with_scan_list",    1, 3, 7, 1, 3, 7, {-40, -50, -60},       0, 0, 0, 0, 1,   0, 0 },
	{ "explicit_connect_fails",     1, 3, 7, 1, 0, 0, {0},                   0, 0, 0, -1, 1,  0, 0 },
	{ "explicit_two_calls",         1, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 2,   0, 0 },
	{ "explicit_log_full",          1, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 1, 255, 0 },
	/* ---- scan list ---- */
	{ "scan_one_match",             1, 3, 7, 2, 1, 1, {-50},                 0, 0, 0, 0, 1,   0, 0 },
	{ "scan_best_of_two",           1, 3, 7, 2, 2, 3, {-60, -40},            0, 0, 0, 0, 1,   0, 0 },
	{ "scan_best_first_of_two",     1, 3, 7, 2, 2, 3, {-40, -60},            0, 0, 0, 0, 1,   0, 0 },
	{ "scan_stronger_non_matching", 1, 3, 7, 2, 3, 5, {-70, -30, -60},       0, 0, 0, 0, 1,   0, 0 },
	{ "scan_best_of_five",          0, 3, 7, 2, 5, 31, {-80, -70, -45, -66, -90}, 0, 0, 0, 0, 1, 0, 0 },
	{ "scan_equal_rssi_tie",        1, 3, 7, 2, 2, 3, {-55, -55},            0, 0, 0, 0, 1,   0, 0 },
	{ "scan_positive_rssi",         1, 3, 7, 2, 2, 3, {10, -40},             0, 0, 0, 0, 1,   0, 0 },
	{ "scan_rssi_minus_99",         1, 3, 7, 2, 1, 1, {-99},                 0, 0, 0, 0, 1,   0, 0 },
	{ "scan_connect_fails",         1, 3, 7, 2, 2, 3, {-60, -40},            0, 0, 0, -1, 1,  0, 0 },
	{ "scan_two_calls",             1, 3, 7, 2, 2, 3, {-60, -40},            0, 0, 0, 0, 2,   0, 0 },
	{ "scan_empty_list",            1, 3, 7, 2, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "scan_no_matching_ssid",      1, 3, 7, 2, 3, 0, {-50, -40, -30},       0, 0, 0, 0, 1,   0, 0 },
	{ "scan_empty_ssid_matches",    1, 3, 7, 2, 2, 3, {-60, -40},            0, 0, 1, 0, 1,   0, 0 },
	{ "scan_ignite_repurposed_ssid",1, 3, 7, 2, 2, 3, {-60, -40},            1, 1, 0, 0, 1,   0, 0 },
	{ "scan_ignite_normal_ssid_only",1,3, 7, 2, 2, 3, {-60, -40},            1, 0, 0, 0, 1,   0, 0 },
	/* ---- matching entry at rssi -100 or weaker: it is the only candidate, so the correct behaviour is to connect ---- */
	{ "scan_rssi_minus_100",        1, 3, 7, 2, 1, 1, {-100},                0, 0, 0, 0, 1,   0, 0 },
	{ "scan_rssi_minus_120",        1, 3, 7, 2, 1, 1, {-120},                0, 0, 0, 0, 1,   0, 0 },
	{ "scan_rssi_int_min",          1, 3, 7, 2, 1, 1, {INT_MIN},             0, 0, 0, 0, 1,   0, 0 },
	{ "scan_weakest_two_candidates",1, 3, 7, 2, 2, 3, {-110, -105},          0, 0, 0, 0, 1,   0, 0 },
	/* ---- NULL bss / AP VAP / unknown VAP ---- */
	{ "bss_null_sta",               1, 3, 7, 0, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "bss_null_unknown_vap",       9, 3, 7, 0, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "ap_vap_first",               0, 3, 6, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "ap_vap_scan_mode",           2, 3, 3, 2, 2, 3, {-60, -40},            0, 0, 0, 0, 1,   0, 0 },
	{ "unknown_vap_3",              3, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "unknown_vap_15",            15, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "unknown_vap_minus1",        -1, 3, 7, 2, 2, 3, {-60, -40},            0, 0, 0, 0, 1,   0, 0 },
	{ "unknown_vap_int_max",  INT_MAX, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "unknown_vap_int_min",  INT_MIN, 3, 7, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ "no_interfaces",              0, 0, 0, 1, 0, 0, {0},                   0, 0, 0, 0, 1,   0, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, 0 }
};
