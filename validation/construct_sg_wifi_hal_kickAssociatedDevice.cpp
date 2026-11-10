/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_kickAssociatedDevice
 *
 * wifi_hal_kickAssociatedDevice(ap_index, mac).  Inputs crossed: 1 / 2 / 3 interfaces; ap_index of an AP VAP (first, middle, last, only one), of a STA VAP (its union holds wpa_supplicant data, not a hostapd
 * station list), of an unknown VAP (3, 15, -1, INT_MAX, INT_MIN, no interface at all); station list of 0 (sta_list NULL) / 1 / 3 / 8 entries; mac NULL / the broadcast address / the first station of the list /
 * a MAC that is not in the list / all zero / ff:ff:ff:ff:ff:fe (not broadcast) / the interface's own address; repeated calls; a log slot nearly full.  Expected (correct behaviour): an unknown VAP, a STA VAP, a
 * NULL mac or an empty station list -> -1 and no disassociation (and no crash); broadcast -> wifi_drv_sta_disassoc once per station of the list, in list order, with the VAP's own_addr and reason 1; a unicast mac
 * -> once with that mac; return 0; the hapd lock is always released.  Rows with last = 1 break the original (NULL mac dereferenced by memcmp, STA data read as hostapd data).
 */
#include "hwr_wka.h"
#include <limits.h>

/* name, vap_index, n_if, sta_mask, n_sta, mac_mode, calls, prefill, last */
hwr_wka_case_t sg_wifi_hal_kickAssociatedDevice_suite[] = {
	/* ---- AP VAP, unicast ---- */
	{ "ap_first_unicast_in_list",       0, 3, 0, 3, 2, 1,   0, 0 },
	{ "ap_middle_unicast_in_list",      1, 3, 0, 3, 2, 1,   0, 0 },
	{ "ap_last_unicast_in_list",        2, 3, 0, 3, 2, 1,   0, 0 },
	{ "ap_only_interface_unicast",      0, 1, 0, 1, 2, 1,   0, 0 },
	{ "ap_unicast_not_in_list",         1, 3, 0, 3, 3, 1,   0, 0 },
	{ "ap_unicast_all_zero",            1, 3, 0, 3, 4, 1,   0, 0 },
	{ "ap_unicast_almost_broadcast",    1, 3, 0, 3, 5, 1,   0, 0 },
	{ "ap_unicast_own_address",         1, 3, 0, 3, 6, 1,   0, 0 },
	{ "ap_unicast_list_of_8",           1, 3, 0, 8, 2, 1,   0, 0 },
	{ "ap_unicast_two_calls",           1, 3, 0, 3, 2, 2,   0, 0 },
	{ "ap_unicast_fifty_calls",         2, 3, 0, 3, 2, 50,  0, 0 },
	{ "ap_unicast_log_full",            1, 3, 0, 3, 2, 1, 255, 0 },
	/* ---- AP VAP, broadcast ---- */
	{ "ap_broadcast_one_station",       0, 3, 0, 1, 1, 1,   0, 0 },
	{ "ap_broadcast_three_stations",    1, 3, 0, 3, 1, 1,   0, 0 },
	{ "ap_broadcast_eight_stations",    2, 3, 0, 8, 1, 1,   0, 0 },
	{ "ap_broadcast_only_interface",    0, 1, 0, 3, 1, 1,   0, 0 },
	{ "ap_broadcast_two_calls",         1, 3, 0, 3, 1, 2,   0, 0 },
	{ "ap_broadcast_log_full",          1, 3, 0, 3, 1, 1, 255, 0 },
	/* ---- empty station list (sta_list NULL) ---- */
	{ "ap_empty_list_unicast",          1, 3, 0, 0, 2, 1,   0, 0 },
	{ "ap_empty_list_broadcast",        1, 3, 0, 0, 1, 1,   0, 0 },
	/* ---- unknown VAP ---- */
	{ "unknown_vap_3",                  3, 3, 0, 3, 2, 1,   0, 0 },
	{ "unknown_vap_15",                15, 3, 0, 3, 1, 1,   0, 0 },
	{ "unknown_vap_minus1",            -1, 3, 0, 3, 2, 1,   0, 0 },
	{ "unknown_vap_int_max",      INT_MAX, 3, 0, 3, 2, 1,   0, 0 },
	{ "unknown_vap_int_min",      INT_MIN, 3, 0, 3, 2, 1,   0, 0 },
	{ "no_interfaces",                  0, 0, 0, 0, 2, 1,   0, 0 },
	{ "unknown_vap_mac_null",           9, 3, 0, 3, 0, 1,   0, 0 },
	/* ---- NULL mac: memcmp(NULL, ...) in the original ---- */
	{ "ap_mac_null",                    1, 3, 0, 3, 0, 1,   0, 1 },
	{ "ap_mac_null_only_interface",     0, 1, 0, 1, 0, 1,   0, 1 },
	/* ---- STA VAP: its union holds wpa_supplicant data, which the original reads as a hostapd station list ---- */
	{ "sta_vap_unicast",                1, 3, 2, 3, 2, 1,   0, 1 },
	{ "sta_vap_broadcast",              1, 3, 2, 3, 1, 1,   0, 1 },
	{ "sta_vap_first_unicast",          0, 3, 1, 3, 3, 1,   0, 1 },
	{ "sta_vap_last_broadcast",         2, 3, 4, 3, 1, 1,   0, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};
