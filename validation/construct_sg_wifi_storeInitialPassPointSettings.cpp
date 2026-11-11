/*
 * UNIT TEST (input constructor): construct_sg_wifi_storeInitialPassPointSettings
 *
 * wifi_storeInitialPassPointSettings() (FEATURE_SUPPORT_PASSPOINT build).  No arguments: the inputs are what the five getters report for each of the 15 ap indexes - all 0, all 1, alternating by ap index and
 * setting, all 2, all 0xFF - one call or two consecutive calls (the second reporting different values), and one getter failing (output untouched, returns -1) at a time.  Expected (CORRECT behaviour): for
 * ap index 0 .. 14, in ascending order, each getter is called exactly once per call with a non-NULL output pointer in the order country IE, layer-2 traffic inspection, downstream group address, BSS load,
 * proxy ARP, and a debug line is printed per ap index; hs2Settings[ap] holds exactly the values reported (a failing getter leaves its own field unspecified, the other four fields are still stored and the loop
 * continues); hs2Settings[15] and hs2SettingsStored are not touched.  No crash case is expected.
 */
#include "hwr_wsp.h"

/* name, pattern, pattern2, fail_kind, last */
hwr_wsp_case_t sg_wifi_storeInitialPassPointSettings_suite[] = {
	{ "all_settings_false",            0, -1, -1, 0 },
	{ "all_settings_true",             1, -1, -1, 0 },
	{ "alternating_values",            2, -1, -1, 0 },
	{ "value_2_stored_as_is",          3, -1, -1, 0 },
	{ "value_0xff_stored_as_is",       4, -1, -1, 0 },
	{ "second_call_overwrites_1_to_0", 1, 0, -1, 0 },
	{ "second_call_alternating",       0, 2, -1, 0 },
	{ "second_call_same_values",       2, 2, -1, 0 },
	{ "country_ie_getter_fails",       1, -1, 0, 0 },
	{ "layer2_getter_fails",           2, -1, 1, 0 },
	{ "downstream_group_getter_fails", 1, -1, 2, 0 },
	{ "bss_load_getter_fails",         2, -1, 3, 0 },
	{ "proxy_arp_getter_fails",        1, -1, 4, 0 },
	{ NULL }
};
