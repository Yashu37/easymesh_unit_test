/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_addApAclDeviceChr
 *
 * wifi_hal_addApAclDevice(apIndex, DeviceMacAddress) (CHAR * variant).  Inputs crossed: apIndex of an interface / not found / -1 / INT_MAX; the interface a STA VAP (with a NULL and a valid MAC); the MAC string NULL
 * (map with entries / empty map); interface->acl_map NULL (created) / hash_map_create failing; 0 / 1 / 20 entries in the map; MAC strings: normal, upper case, already in the map, a short string ("ab:cd"), the empty
 * string, a string longer than 17 characters; MAC filter disabled / white list / black list; nl80211_set_acl failing (-1, 5); nl80211_kick_device succeeding / failing; malloc of the entry failing; 2 / 3 / 4
 * interfaces with the addressed one first / second / third / last.  The MAC string is an exact heap copy (strlen + 1 bytes).  Expected (CORRECT behaviour): no interface / MAC NULL / STA VAP / map creation
 * failure / allocation failure -> -1 with nothing added; a MAC already in the map -> 0 with nothing added; otherwise the string put into the map once as a key and as mac_addr_str (cut to the 17 characters
 * of mac_addr_str, terminated), the MAC bytes parsed from it, nl80211_set_acl called once (its failure -> -1), nl80211_kick_device once when the filter is enabled in black-list mode (a failing kick only
 * logged); nothing read past the MAC string.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wab.h"
#include <limits.h>

/* name, apIndex, no_iface, vap_mode_sta, mac_null, acl_map_null, create_fail, pre_n, mac_kind, filter_enable, filter_mode, set_acl_ret, kick_ret, malloc_fail, n_if, ap_pos, last */
hwr_wab_case_t sg_wifi_hal_addApAclDeviceChr_suite[] = {
	/* ---- lookup / state errors ---- */
	{ "interface_not_found",       5, 1,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "apIndex_minus1",           -1, 1,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "sta_vap",                   3, 0,1,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "sta_vap_mac_null",          3, 0,1,1, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	/* ---- adding ---- */
	{ "add_to_empty_map",          3, 0,0,0, 0,0, 0, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "add_second_mac",            3, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "add_to_map_of_20",          3, 0,0,0, 0,0,20, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "add_upper_case_mac",        3, 0,0,0, 0,0, 1, 1, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "add_mac_longer_than_17",    3, 0,0,0, 0,0, 1, 5, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "acl_map_null_created",      3, 0,0,0, 1,0, 0, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "acl_map_create_fails",      3, 0,0,0, 1,1, 0, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "mac_already_present",       3, 0,0,0, 0,0, 3, 2, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "mac_already_present_blacklist", 3, 0,0,0, 0,0, 3, 2, 1,0, 0, 0, 0, 2, 1, 0 },
	{ "set_acl_fails_minus1",      3, 0,0,0, 0,0, 1, 0, 0,0,-1, 0, 0, 2, 1, 0 },
	{ "set_acl_fails_5_blacklist", 3, 0,0,0, 0,0, 1, 0, 1,0, 5, 0, 0, 2, 1, 0 },
	/* ---- MAC filter / kick ---- */
	{ "filter_disabled_no_kick",   3, 0,0,0, 0,0, 1, 0, 0,0, 0,-1, 0, 2, 1, 0 },
	{ "filter_whitelist_no_kick",  3, 0,0,0, 0,0, 1, 0, 1,1, 0,-1, 0, 2, 1, 0 },
	{ "blacklist_kick_ok",         3, 0,0,0, 0,0, 1, 0, 1,0, 0, 0, 0, 2, 1, 0 },
	{ "blacklist_kick_fails",      3, 0,0,0, 0,0, 1, 0, 1,0, 0,-1, 0, 2, 1, 0 },
	/* ---- positions / apIndex values ---- */
	{ "ap_first_of_three",         0, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 3, 0, 0 },
	{ "ap_third_of_three",         7, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 3, 2, 0 },
	{ "ap_last_of_four",           9, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 4, 3, 0 },
	{ "apIndex_int_max_found",  INT_MAX, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	/* ---- the original passes a NULL MAC to hash_map_get / memcpy, does not check malloc, copies 18 bytes from the MAC string ---- */
	{ "mac_null_map_with_entries", 3, 0,0,1, 0,0, 3, 0, 0,0, 0, 0, 0, 2, 1, 1 },
	{ "mac_null_empty_map",        3, 0,0,1, 0,0, 0, 0, 0,0, 0, 0, 0, 2, 1, 1 },
	{ "malloc_fails",              3, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 1, 2, 1, 1 },
	{ "malloc_fails_empty_map",    3, 0,0,0, 0,0, 0, 0, 1,0, 0, 0, 1, 2, 1, 1 },
	{ "mac_short_string",          3, 0,0,0, 0,0, 1, 3, 0,0, 0, 0, 0, 2, 1, 1 },
	{ "mac_empty_string",          3, 0,0,0, 0,0, 1, 4, 0,0, 0, 0, 0, 2, 1, 1 },
	{ NULL, 0, 0,0,0, 0,0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0 }
};
