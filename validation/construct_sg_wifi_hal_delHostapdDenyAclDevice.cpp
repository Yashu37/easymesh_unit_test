/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_delHostapdDenyAclDevice
 *
 * wifi_hal_delHostapdDenyAclDevice(apIndex, DeviceMacAddress).  Inputs crossed: apIndex of an interface / not found / -1 / INT_MAX; the interface a STA VAP; MAC string NULL; hapd->conf NULL; hapd->iface NULL;
 * MAC string kinds: listed (first / second / third entry), valid but not listed, upper case, " VLAN_ID=5" suffix, trailing characters, too short, bad hex digit, empty, no colons; 0 / 1 / 3 / 50 MACs in the
 * list; 2 / 3 / 4 interfaces with the addressed one first / second / third / last.  The MAC string is an exact heap copy.  Expected (CORRECT behaviour): no interface / not an AP VAP / MAC NULL / conf NULL /
 * iface NULL / unparsable MAC with a non-empty list -> -1 with the deny list unchanged and hapd_lock unlocked; otherwise 0 (an empty list is not an error: nothing is parsed), a listed MAC removed with the
 * order of the others kept, hostapd_set_acl called once.  Rows with last = 1 (hapd->conf set, hapd->iface NULL, a request that is accepted) break the original: they run LAST.
 */
#include "hwr_wdd.h"
#include <limits.h>

/* name, apIndex, no_iface, vap_mode_sta, mac_null, conf_null, iface_null, mac_kind, pre_n, n_if, ap_pos, last */
hwr_wdd_case_t sg_wifi_hal_delHostapdDenyAclDevice_suite[] = {
	/* ---- lookup / argument / state errors ---- */
	{ "interface_not_found",       5, 1,0,0,0,0, 2, 3, 2, 1, 0 },
	{ "apIndex_minus1",           -1, 1,0,0,0,0, 2, 3, 2, 1, 0 },
	{ "apIndex_int_max_not_found", INT_MAX, 1,0,0,0,0, 2, 3, 2, 1, 0 },
	{ "sta_vap",                   3, 0,1,0,0,0, 2, 3, 2, 1, 0 },
	{ "mac_null",                  3, 0,0,1,0,0, 2, 3, 2, 1, 0 },
	{ "conf_null",                 3, 0,0,0,1,0, 2, 3, 2, 1, 0 },
	{ "mac_null_and_conf_null",    3, 0,0,1,1,0, 2, 3, 2, 1, 0 },
	{ "sta_vap_conf_null",         3, 0,1,0,1,0, 2, 3, 2, 1, 0 },
	/* ---- removing / not removing ---- */
	{ "remove_first_of_three",     3, 0,0,0,0,0, 2, 3, 2, 1, 0 },
	{ "remove_middle_of_three",    3, 0,0,0,0,0, 9, 3, 2, 1, 0 },
	{ "remove_last_of_three",      3, 0,0,0,0,0,10, 3, 2, 1, 0 },
	{ "remove_only_entry",         3, 0,0,0,0,0, 2, 1, 2, 1, 0 },
	{ "remove_first_of_fifty",     3, 0,0,0,0,0, 2,50, 2, 1, 0 },
	{ "mac_not_listed",            3, 0,0,0,0,0, 0, 3, 2, 1, 0 },
	{ "mac_upper_case_not_listed", 3, 0,0,0,0,0, 1, 3, 2, 1, 0 },
	{ "mac_with_vlan_suffix",      3, 0,0,0,0,0, 7, 3, 2, 1, 0 },
	{ "mac_trailing_characters",   3, 0,0,0,0,0, 8, 3, 2, 1, 0 },
	/* ---- unparsable MAC: an error with entries, accepted when the list is empty ---- */
	{ "mac_too_short",             3, 0,0,0,0,0, 3, 3, 2, 1, 0 },
	{ "mac_bad_hex_digit",         3, 0,0,0,0,0, 4, 3, 2, 1, 0 },
	{ "mac_empty_string",          3, 0,0,0,0,0, 5, 3, 2, 1, 0 },
	{ "mac_no_colons",             3, 0,0,0,0,0, 6, 3, 2, 1, 0 },
	{ "empty_list_valid_mac",      3, 0,0,0,0,0, 0, 0, 2, 1, 0 },
	{ "empty_list_mac_too_short",  3, 0,0,0,0,0, 3, 0, 2, 1, 0 },
	{ "empty_list_mac_no_colons",  3, 0,0,0,0,0, 6, 0, 2, 1, 0 },
	/* ---- interface positions / apIndex values ---- */
	{ "ap_first_of_three",         0, 0,0,0,0,0, 2, 3, 3, 0, 0 },
	{ "ap_third_of_three",         7, 0,0,0,0,0, 2, 3, 3, 2, 0 },
	{ "ap_last_of_four",           9, 0,0,0,0,0, 2, 3, 4, 3, 0 },
	{ "apIndex_int_max_found",  INT_MAX, 0,0,0,0,0, 2, 3, 2, 1, 0 },
	/* ---- hapd->iface NULL, nothing reaches hostapd_set_acl ---- */
	{ "iface_null_mac_too_short",  3, 0,0,0,0,1, 3, 3, 2, 1, 0 },
	{ "iface_null_mac_null",       3, 0,0,1,0,1, 2, 3, 2, 1, 0 },
	{ "iface_null_conf_null",      3, 0,0,0,1,1, 2, 3, 2, 1, 0 },
	/* ---- hapd->conf set, hapd->iface NULL, request accepted: the original removes the MAC and then hostapd_set_acl dereferences hapd->iface ---- */
	{ "iface_null_listed_mac",     3, 0,0,0,0,1, 2, 3, 2, 1, 1 },
	{ "iface_null_mac_not_listed", 3, 0,0,0,0,1, 0, 3, 2, 1, 1 },
	{ "iface_null_remove_only_entry", 3, 0,0,0,0,1, 2, 1, 2, 1, 1 },
	{ "iface_null_empty_list",     3, 0,0,0,0,1, 0, 0, 2, 1, 1 },
	{ "iface_null_empty_list_bad_mac", 3, 0,0,0,0,1, 3, 0, 2, 1, 1 },
	{ NULL, 0, 0,0,0,0,0, 0, 0, 0, 0, 0 }
};
