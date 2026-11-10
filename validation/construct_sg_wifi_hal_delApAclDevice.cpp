/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_delApAclDevice
 *
 * wifi_hal_delApAclDevice(apIndex, DeviceMacAddress) (CHAR * variant).  Inputs crossed: apIndex of an interface / not found / -1 / INT_MAX; the interface a STA VAP (with a NULL and a valid MAC); the MAC string
 * NULL; interface->acl_map NULL; 0 / 1 / 3 / 20 entries in the map; the MAC the first / second / third entry, valid but not listed, the upper-case form of a listed entry, a short string ("ab:cd") listed and
 * not listed, the empty string; nl80211_set_acl succeeding / failing (-1, 5); malloc failing on the rebuild of the entry; 2 / 3 / 4 interfaces with the addressed one first / second / third / last.  The MAC
 * string is an exact heap copy.  Expected (CORRECT behaviour): no interface / STA VAP / MAC NULL -> -1; acl_map NULL or MAC not a key -> 0 with the map untouched and nl80211_set_acl not called; a listed MAC ->
 * the entry removed (order of the others kept), nl80211_set_acl called once, 0; when it fails the entry is put back (key, mac_addr_str, MAC bytes) and the result is -1; no read past the MAC string, no NULL use
 * of a failed malloc.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wdl.h"
#include <limits.h>

/* name, apIndex, no_iface, vap_mode_sta, mac_null, acl_map_null, pre_n, mac_kind, set_acl_ret, malloc_fail, n_if, ap_pos, last */
hwr_wdl_case_t sg_wifi_hal_delApAclDevice_suite[] = {
	/* ---- lookup / state errors ---- */
	{ "interface_not_found",       5, 1,0,0, 0, 3, 0, 0, 0, 2, 1, 0 },
	{ "apIndex_minus1",           -1, 1,0,0, 0, 3, 0, 0, 0, 2, 1, 0 },
	{ "sta_vap",                   3, 0,1,0, 0, 3, 0, 0, 0, 2, 1, 0 },
	{ "sta_vap_mac_null",          3, 0,1,1, 0, 3, 0, 0, 0, 2, 1, 0 },
	{ "acl_map_null",              3, 0,0,0, 1, 0, 0, 0, 0, 2, 1, 0 },
	/* ---- removing ---- */
	{ "remove_first_of_three",     3, 0,0,0, 0, 3, 0, 0, 0, 2, 1, 0 },
	{ "remove_second_of_three",    3, 0,0,0, 0, 3, 1, 0, 0, 2, 1, 0 },
	{ "remove_third_of_three",     3, 0,0,0, 0, 3, 2, 0, 0, 2, 1, 0 },
	{ "remove_only_entry",         3, 0,0,0, 0, 1, 0, 0, 0, 2, 1, 0 },
	{ "remove_first_of_twenty",    3, 0,0,0, 0,20, 0, 0, 0, 2, 1, 0 },
	/* ---- not removing ---- */
	{ "mac_not_listed",            3, 0,0,0, 0, 3, 3, 0, 0, 2, 1, 0 },
	{ "mac_not_listed_empty_map",  3, 0,0,0, 0, 0, 3, 0, 0, 2, 1, 0 },
	{ "mac_upper_case_not_found",  3, 0,0,0, 0, 3, 4, 0, 0, 2, 1, 0 },
	{ "mac_short_string_not_listed", 3, 0,0,0, 0, 3, 6, 0, 0, 2, 1, 0 },
	{ "mac_empty_string",          3, 0,0,0, 0, 3, 7, 0, 0, 2, 1, 0 },
	/* ---- nl80211_set_acl failing: the entry is rebuilt and put back ---- */
	{ "set_acl_fails_first_entry", 3, 0,0,0, 0, 3, 0,-1, 0, 2, 1, 0 },
	{ "set_acl_fails_5_second_entry", 3, 0,0,0, 0, 3, 1, 5, 0, 2, 1, 0 },
	{ "set_acl_fails_last_entry",  3, 0,0,0, 0, 3, 2,-1, 0, 2, 1, 0 },
	{ "set_acl_fails_only_entry",  3, 0,0,0, 0, 1, 0,-1, 0, 2, 1, 0 },
	{ "set_acl_not_called_not_listed", 3, 0,0,0, 0, 3, 3,-1, 0, 2, 1, 0 },
	/* ---- positions / apIndex values ---- */
	{ "ap_first_of_three",         0, 0,0,0, 0, 3, 0, 0, 0, 3, 0, 0 },
	{ "ap_third_of_three",         7, 0,0,0, 0, 3, 0, 0, 0, 3, 2, 0 },
	{ "ap_last_of_four",           9, 0,0,0, 0, 3, 0, 0, 0, 4, 3, 0 },
	{ "apIndex_int_max_found",  INT_MAX, 0,0,0, 0, 3, 0, 0, 0, 2, 1, 0 },
	/* ---- the original passes a NULL MAC to hash_map_get, does not check malloc, copies 18 bytes from the MAC string ---- */
	{ "mac_null",                  3, 0,0,1, 0, 3, 0, 0, 0, 2, 1, 1 },
	{ "mac_null_one_entry",        3, 0,0,1, 0, 1, 0, 0, 0, 2, 1, 1 },
	{ "malloc_fails_set_acl_fails",3, 0,0,0, 0, 3, 0,-1, 1, 2, 1, 1 },
	{ "malloc_fails_set_acl_fails_only_entry", 3, 0,0,0, 0, 1, 0,-1, 1, 2, 1, 1 },
	{ "short_key_listed_set_acl_fails", 3, 0,0,0, 0, 3, 5,-1, 0, 2, 1, 1 },
	{ NULL, 0, 0,0,0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
