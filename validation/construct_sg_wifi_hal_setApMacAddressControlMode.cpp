/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_setApMacAddressControlMode
 *
 * wifi_hal_setApMacAddressControlMode(apIndex, mac_filter_mode).  Inputs crossed: apIndex of the existing interfaces 0 / 1 / 5 / 14 and of NO interface (2, 15, UINT_MAX); mode 0 / 1 / 2 and invalid 3 / 100 /
 * UINT_MAX; the bss enabled / disabled; the vap in AP / STA mode; the filter before the call (enabled or not, black or white list); nl80211_set_acl returning 0 / -1 / 5.  Expected (CORRECT behaviour): unknown
 * interface -> RETURN_ERR; bss disabled or STA mode -> RETURN_ERR and the filter unchanged; mode 0 -> filter disabled (list mode unchanged), 1 -> enabled + white list, 2 -> enabled + black list, then the
 * result of nl80211_set_acl (called exactly once, with the looked-up interface) is returned; any other mode -> RETURN_ERR, filter unchanged, nl80211_set_acl not called; nothing else of the vap is touched.
 * No crash case is expected.
 */
#include "hwr_wam.h"
#include <limits.h>

/* name, ap_index, mode, enabled, sta_mode, pre_enable, pre_mode, acl_ret, last */
hwr_wam_case_t sg_wifi_hal_setApMacAddressControlMode_suite[] = {
	{ "vap0_mode0_disable",            0, 0, 1, 0, 1, 1, 0, 0 },
	{ "vap0_mode0_already_disabled",   0, 0, 1, 0, 0, 0, 0, 0 },
	{ "vap1_mode1_whitelist",          1, 1, 1, 0, 0, 0, 0, 0 },
	{ "vap5_mode2_blacklist",          5, 2, 1, 0, 0, 1, 0, 0 },
	{ "vap14_mode1_from_blacklist",    14, 1, 1, 0, 1, 0, 0, 0 },
	{ "vap14_mode2_from_whitelist",    14, 2, 1, 0, 1, 1, 0, 0 },
	{ "vap1_mode2_same_again",         1, 2, 1, 0, 1, 0, 0, 0 },
	{ "acl_fails_minus1_mode1",        5, 1, 1, 0, 0, 0, -1, 0 },
	{ "acl_returns_5_mode2",           0, 2, 1, 0, 0, 1, 5, 0 },
	{ "acl_fails_mode0",               1, 0, 1, 0, 1, 1, -1, 0 },
	{ "bss_disabled_mode1",            0, 1, 0, 0, 0, 0, 0, 0 },
	{ "bss_disabled_mode0",            5, 0, 0, 0, 1, 1, 0, 0 },
	{ "sta_mode_mode2",                1, 2, 1, 1, 0, 0, 0, 0 },
	{ "sta_mode_disabled_mode1",       14, 1, 0, 1, 1, 1, 0, 0 },
	{ "invalid_mode_3",                0, 3, 1, 0, 1, 1, 0, 0 },
	{ "invalid_mode_100",              5, 100, 1, 0, 0, 0, 0, 0 },
	{ "invalid_mode_uint_max",         14, UINT_MAX, 1, 0, 1, 0, 0, 0 },
	{ "no_interface_vap2",             2, 1, 1, 0, 0, 0, 0, 0 },
	{ "no_interface_vap15",            15, 0, 1, 0, 0, 0, 0, 0 },
	{ "no_interface_vap_uint_max",     UINT_MAX, 2, 1, 0, 0, 0, 0, 0 },
	{ NULL }
};
