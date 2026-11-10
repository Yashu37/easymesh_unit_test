/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_delApAclDevices
 *
 * wifi_hal_delApAclDevices(apIndex).  Inputs crossed: apIndex of an interface / not found / -1 / INT_MAX; the interface a STA VAP (with a NULL and a non-NULL acl_map); interface->acl_map NULL; an empty map
 * (with a failing nl80211_set_acl: it must not be called); 1 / 2 / 3 / 20 normal entries (17-character key == mac_addr_str); nl80211_set_acl returning 0 / -1 / 5; 2 / 3 / 4 interfaces with the addressed one first /
 * second / third / last; one more entry whose key is 18 characters or longer than 18 characters (what wifi_hal_addApAclDevice's CHAR * variant stores for such a string): mac_addr_str then holds its first 18
 * characters without a terminator.  Expected (CORRECT behaviour): no interface / STA VAP / acl_map NULL -> -1; an empty map -> 0 without calling nl80211_set_acl; otherwise every entry whose key is
 * what mac_addr_str holds is removed (each entry visited once, the iterator stays valid), the others (a key longer than mac_addr_str) stay, nl80211_set_acl is called once and its result returned; nothing is
 * read past the 18 bytes copied into mac_str.  Rows with last = 1 (an entry with a key of 18 or more characters) break the original: they run LAST.
 */
#include "hwr_wdm.h"
#include <limits.h>

/* name, apIndex, no_iface, vap_mode_sta, acl_map_null, n_entries, long_kind, set_acl_ret, n_if, ap_pos, last */
hwr_wdm_case_t sg_wifi_hal_delApAclDevices_suite[] = {
	/* ---- lookup / state errors ---- */
	{ "interface_not_found",       5, 1,0,0, 3, 0, 0, 2, 1, 0 },
	{ "apIndex_minus1",           -1, 1,0,0, 3, 0, 0, 2, 1, 0 },
	{ "sta_vap",                   3, 0,1,0, 3, 0, 0, 2, 1, 0 },
	{ "sta_vap_acl_map_null",      3, 0,1,1, 0, 0, 0, 2, 1, 0 },
	{ "acl_map_null",              3, 0,0,1, 0, 0, 0, 2, 1, 0 },
	/* ---- empty map ---- */
	{ "empty_map",                 3, 0,0,0, 0, 0, 0, 2, 1, 0 },
	{ "empty_map_set_acl_would_fail", 3, 0,0,0, 0, 0,-1, 2, 1, 0 },
	/* ---- removing every entry ---- */
	{ "one_entry",                 3, 0,0,0, 1, 0, 0, 2, 1, 0 },
	{ "two_entries",               3, 0,0,0, 2, 0, 0, 2, 1, 0 },
	{ "three_entries",             3, 0,0,0, 3, 0, 0, 2, 1, 0 },
	{ "twenty_entries",            3, 0,0,0,20, 0, 0, 2, 1, 0 },
	{ "set_acl_fails_minus1",      3, 0,0,0, 3, 0,-1, 2, 1, 0 },
	{ "set_acl_fails_5",           3, 0,0,0, 2, 0, 5, 2, 1, 0 },
	/* ---- positions / apIndex values ---- */
	{ "ap_first_of_three",         0, 0,0,0, 3, 0, 0, 3, 0, 0 },
	{ "ap_third_of_three",         7, 0,0,0, 3, 0, 0, 3, 2, 0 },
	{ "ap_last_of_four",           9, 0,0,0, 3, 0, 0, 4, 3, 0 },
	{ "apIndex_int_max_found",  INT_MAX, 0,0,0, 3, 0, 0, 2, 1, 0 },
	/* ---- an entry whose key is 18 characters or longer: mac_addr_str has no terminator, the original reads past mac_str in hash_map_remove ---- */
	{ "key_18_characters_single",  3, 0,0,0, 0, 1, 0, 2, 1, 1 },
	{ "key_18_characters_with_entries", 3, 0,0,0, 3, 1, 0, 2, 1, 1 },
	{ "key_longer_than_18_single", 3, 0,0,0, 0, 2, 0, 2, 1, 1 },
	{ "key_longer_than_18_with_entries", 3, 0,0,0, 3, 2, 0, 2, 1, 1 },
	{ NULL, 0, 0,0,0, 0, 0, 0, 0, 0, 0 }
};
