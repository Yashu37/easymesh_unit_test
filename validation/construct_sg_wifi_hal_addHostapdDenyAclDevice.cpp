/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_addHostapdDenyAclDevice
 *
 * wifi_hal_addHostapdDenyAclDevice(apIndex, DeviceMacAddress).  Inputs crossed: apIndex of an interface / not found / -1 / INT_MAX; the interface a STA VAP; MAC string NULL; hapd->conf NULL; hapd->iface NULL;
 * MAC string kinds: valid, upper case, already in the deny list, too short, bad hex digit, empty, no colons, valid + " VLAN_ID=5", valid + trailing characters; 0 / 3 / 50 MACs already in the list; growing the
 * list failing; 2 / 3 / 4 interfaces with the addressed one first / second / third / last.  The MAC string is an exact heap copy.  Expected (CORRECT behaviour): no interface / not an AP VAP / MAC NULL /
 * conf NULL / iface NULL / unparsable MAC / allocation failure (new MAC) -> -1 with the deny list unchanged and hapd_lock unlocked; otherwise 0, the MAC appended unless it is already listed, hostapd_set_acl and
 * hostapd_disassoc_deny_mac called once.  Rows with last = 1 (hapd->conf set, hapd->iface NULL, a MAC that is accepted) break the original: they run LAST.
 */
#include "hwr_wad.h"
#include <limits.h>

/* name, apIndex, no_iface, vap_mode_sta, mac_null, conf_null, iface_null, mac_kind, pre_n, alloc_fail, n_if, ap_pos, last */
hwr_wad_case_t sg_wifi_hal_addHostapdDenyAclDevice_suite[] = {
	/* ---- lookup / argument / state errors ---- */
	{ "interface_not_found",       5, 1,0,0,0,0, 0, 3, 0, 2, 1, 0 },
	{ "apIndex_minus1",           -1, 1,0,0,0,0, 0, 3, 0, 2, 1, 0 },
	{ "apIndex_int_max_not_found", INT_MAX, 1,0,0,0,0, 0, 3, 0, 2, 1, 0 },
	{ "sta_vap",                   3, 0,1,0,0,0, 0, 3, 0, 2, 1, 0 },
	{ "mac_null",                  3, 0,0,1,0,0, 0, 3, 0, 2, 1, 0 },
	{ "conf_null",                 3, 0,0,0,1,0, 0, 3, 0, 2, 1, 0 },
	{ "mac_null_and_conf_null",    3, 0,0,1,1,0, 0, 3, 0, 2, 1, 0 },
	{ "sta_vap_conf_null",         3, 0,1,0,1,0, 0, 3, 0, 2, 1, 0 },
	/* ---- MAC string handling ---- */
	{ "add_mac",                   3, 0,0,0,0,0, 0, 3, 0, 2, 1, 0 },
	{ "add_mac_upper_case",        3, 0,0,0,0,0, 1, 3, 0, 2, 1, 0 },
	{ "add_mac_empty_list",        3, 0,0,0,0,0, 0, 0, 0, 2, 1, 0 },
	{ "add_mac_list_of_50",        3, 0,0,0,0,0, 0,50, 0, 2, 1, 0 },
	{ "mac_already_listed",        3, 0,0,0,0,0, 2, 3, 0, 2, 1, 0 },
	{ "mac_with_vlan_suffix",      3, 0,0,0,0,0, 7, 3, 0, 2, 1, 0 },
	{ "mac_trailing_characters",   3, 0,0,0,0,0, 8, 3, 0, 2, 1, 0 },
	{ "mac_too_short",             3, 0,0,0,0,0, 3, 3, 0, 2, 1, 0 },
	{ "mac_bad_hex_digit",         3, 0,0,0,0,0, 4, 3, 0, 2, 1, 0 },
	{ "mac_empty_string",          3, 0,0,0,0,0, 5, 3, 0, 2, 1, 0 },
	{ "mac_no_colons",             3, 0,0,0,0,0, 6, 3, 0, 2, 1, 0 },
	{ "list_growth_fails",         3, 0,0,0,0,0, 0, 3, 1, 2, 1, 0 },
	{ "list_growth_fails_listed_mac", 3, 0,0,0,0,0, 2, 3, 1, 2, 1, 0 },
	/* ---- interface positions / apIndex values ---- */
	{ "ap_first_of_three",         0, 0,0,0,0,0, 0, 3, 0, 3, 0, 0 },
	{ "ap_third_of_three",         7, 0,0,0,0,0, 0, 3, 0, 3, 2, 0 },
	{ "ap_last_of_four",           9, 0,0,0,0,0, 0, 3, 0, 4, 3, 0 },
	{ "apIndex_int_max_found",  INT_MAX, 0,0,0,0,0, 0, 3, 0, 2, 1, 0 },
	/* ---- hapd->iface NULL, nothing reaches hostapd_set_acl ---- */
	{ "iface_null_mac_too_short",  3, 0,0,0,0,1, 3, 3, 0, 2, 1, 0 },
	{ "iface_null_mac_null",       3, 0,0,1,0,1, 0, 3, 0, 2, 1, 0 },
	{ "iface_null_conf_null",      3, 0,0,0,1,1, 0, 3, 0, 2, 1, 0 },
	{ "iface_null_growth_fails",   3, 0,0,0,0,1, 0, 3, 1, 2, 1, 0 },
	/* ---- hapd->conf set, hapd->iface NULL, MAC accepted: the original adds the MAC and then hostapd_set_acl dereferences hapd->iface ---- */
	{ "iface_null_valid_mac",      3, 0,0,0,0,1, 0, 3, 0, 2, 1, 1 },
	{ "iface_null_upper_case_mac", 3, 0,0,0,0,1, 1, 3, 0, 2, 1, 1 },
	{ "iface_null_mac_already_listed", 3, 0,0,0,0,1, 2, 3, 0, 2, 1, 1 },
	{ "iface_null_vlan_suffix",    3, 0,0,0,0,1, 7, 3, 0, 2, 1, 1 },
	{ "iface_null_empty_list",     3, 0,0,0,0,1, 0, 0, 0, 2, 1, 1 },
	{ NULL, 0, 0,0,0,0,0, 0, 0, 0, 0, 0, 0 }
};
