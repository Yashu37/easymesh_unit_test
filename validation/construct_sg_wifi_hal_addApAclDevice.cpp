/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_addApAclDevice
 *
 * wifi_hal_addApAclDevice(apIndex, DeviceMacAddress).  Inputs crossed: apIndex of an interface / not found / -1 / INT_MAX; the interface a STA VAP; the MAC NULL (AP and STA VAP); interface->acl_map NULL (created by
 * the function) / hash_map_create failing; 0 / 1 / 20 entries already in the map; the MAC already in the map; MAC bytes without a zero byte / all 0xff / first byte 0 / a zero in the middle; the VAP's MAC filter
 * disabled / white list / black list; nl80211_set_acl failing (-1, 5); nl80211_kick_device succeeding / failing; malloc of the map entry failing; 2 / 3 / 4 interfaces with the addressed one first / second / third /
 * last.  The MAC is an exact 6-byte heap copy (mac_address_t has no terminator).  Expected (CORRECT behaviour): no interface / MAC NULL / STA VAP / map creation failure / allocation failure -> -1 with
 * nothing added and nl80211_set_acl not called; MAC already listed -> 0 and nothing added; otherwise the MAC (lower-case "%02x:..." key, 6 raw bytes) put into the map once, nl80211_set_acl called once (its
 * failure -> -1), nl80211_kick_device called once when the filter is enabled in black-list mode (a failing kick is only logged, result 0, nothing read past the 6 MAC bytes).  Rows with last = 1 break the
 * original: they run LAST.
 */
#include "hwr_waa.h"
#include <limits.h>

/* name, apIndex, no_iface, vap_mode_sta, mac_null, acl_map_null, create_fail, pre_n, mac_kind, filter_enable, filter_mode, set_acl_ret, kick_ret, malloc_fail, n_if, ap_pos, last */
hwr_waa_case_t sg_wifi_hal_addApAclDevice_suite[] = {
	/* ---- lookup / state errors ---- */
	{ "interface_not_found",       5, 1,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "apIndex_minus1",           -1, 1,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "sta_vap",                   3, 0,1,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "sta_vap_acl_map_null",      3, 0,1,0, 1,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	/* ---- adding ---- */
	{ "add_to_empty_map",          3, 0,0,0, 0,0, 0, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "add_second_mac",            3, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "add_to_map_of_20",          3, 0,0,0, 0,0,20, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "acl_map_null_created",      3, 0,0,0, 1,0, 0, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "acl_map_create_fails",      3, 0,0,0, 1,1, 0, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "mac_already_present",       3, 0,0,0, 0,0, 3, 4, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "mac_already_present_blacklist", 3, 0,0,0, 0,0, 3, 4, 1,0, 0, 0, 0, 2, 1, 0 },
	{ "mac_all_ff",                3, 0,0,0, 0,0, 1, 1, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "mac_first_byte_zero",       3, 0,0,0, 0,0, 1, 2, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "mac_zero_in_middle",        3, 0,0,0, 0,0, 1, 3, 0,0, 0, 0, 0, 2, 1, 0 },
	{ "set_acl_fails_minus1",      3, 0,0,0, 0,0, 1, 0, 0,0,-1, 0, 0, 2, 1, 0 },
	{ "set_acl_fails_5",           3, 0,0,0, 0,0, 1, 0, 1,0, 5, 0, 0, 2, 1, 0 },
	/* ---- MAC filter / kick ---- */
	{ "filter_disabled_blacklist_no_kick", 3, 0,0,0, 0,0, 1, 0, 0,0, 0,-1, 0, 2, 1, 0 },
	{ "filter_whitelist_no_kick",  3, 0,0,0, 0,0, 1, 0, 1,1, 0,-1, 0, 2, 1, 0 },
	{ "blacklist_kick_ok",         3, 0,0,0, 0,0, 1, 0, 1,0, 0, 0, 0, 2, 1, 0 },
	{ "blacklist_kick_fails_first_byte_zero", 3, 0,0,0, 0,0, 1, 2, 1,0, 0,-1, 0, 2, 1, 0 },
	{ "blacklist_kick_fails_zero_in_middle",  3, 0,0,0, 0,0, 1, 3, 1,0, 0,-1, 0, 2, 1, 0 },
	/* ---- positions / apIndex values ---- */
	{ "ap_first_of_three",         0, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 3, 0, 0 },
	{ "ap_third_of_three",         7, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 3, 2, 0 },
	{ "ap_last_of_four",           9, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 4, 3, 0 },
	{ "apIndex_int_max_found",  INT_MAX, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 0 },
	/* ---- the original dereferences a NULL MAC, does not check malloc, prints the 6-byte MAC with "%s" ---- */
	{ "mac_null",                  3, 0,0,1, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 1 },
	{ "mac_null_sta_vap",          3, 0,1,1, 0,0, 1, 0, 0,0, 0, 0, 0, 2, 1, 1 },
	{ "malloc_fails",              3, 0,0,0, 0,0, 1, 0, 0,0, 0, 0, 1, 2, 1, 1 },
	{ "malloc_fails_empty_map",    3, 0,0,0, 0,0, 0, 0, 1,0, 0, 0, 1, 2, 1, 1 },
	{ "blacklist_kick_fails_mac_no_zero_byte", 3, 0,0,0, 0,0, 1, 0, 1,0, 0,-1, 0, 2, 1, 1 },
	{ "blacklist_kick_fails_mac_all_ff", 3, 0,0,0, 0,0, 1, 1, 1,0, 0,-1, 0, 2, 1, 1 },
	{ NULL, 0, 0,0,0, 0,0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0 }
};
