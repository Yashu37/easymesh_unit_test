/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_add_station_bridge
 *
 * wifi_hal_add_station_bridge(interface_name, bridge_name).  Inputs crossed: interface name "wlan0" / a 15-character name / empty / NULL; bridge name "brlan0" / a 15-character name / empty / NULL (each an
 * exact heap block); nl80211_remove_from_bridge returning 0 / -1; nl80211_create_bridge returning 0 / 1 / -1 / -5.  Expected (CORRECT behaviour): a NULL interface or bridge name -> RETURN_ERR and neither helper
 * is called (both dereference their names); otherwise nl80211_remove_from_bridge runs first (its result is ignored) and nl80211_create_bridge second, both with the pointers passed in, and the result is 0
 * when the bridge creation returned 0, RETURN_ERR otherwise.  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_wsb.h"

/* name, if_mode, br_mode, rm_ret, cr_ret, last */
hwr_wsb_case_t sg_wifi_hal_add_station_bridge_suite[] = {
	{ "normal_names",                 1, 1, 0, 0, 0 },
	{ "long_15_char_names",           2, 2, 0, 0, 0 },
	{ "empty_interface_name",         3, 1, 0, 0, 0 },
	{ "empty_bridge_name",            1, 3, 0, 0, 0 },
	{ "both_empty",                   3, 3, 0, 0, 0 },
	{ "remove_fails_ignored",         1, 1, -1, 0, 0 },
	{ "create_fails_minus1",          1, 1, 0, -1, 0 },
	{ "create_returns_1",             2, 1, 0, 1, 0 },
	{ "create_returns_minus5",        1, 2, 0, -5, 0 },
	{ "both_fail",                    1, 1, -1, -1, 0 },
	{ "interface_null",               0, 1, 0, 0, 1 },
	{ "bridge_null",                  1, 0, 0, 0, 1 },
	{ "both_null",                    0, 0, 0, 0, 1 },
	{ NULL }
};
