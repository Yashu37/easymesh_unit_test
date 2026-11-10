/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_init
 *
 * wifi_hal_init() (generic branch).  Every step is a stub that appends a token to a call trace and returns the row's value.  Inputs crossed: driver name NULL; the driver
 * module appearing after 0 / 3 / 50 polls; init_nl80211, primary-interface, radio-info, eloop, pthread_create and EAP-method registration each failing; the ECO-mode interface
 * creation failing (only logged); 0 / 1 / 2 / 3 radios with every combination of present / sleeping; update_hostap_interfaces failing for the first / second / third radio;
 * update_channel_flags failing; the platform radio-caps / flags-init hooks present or absent; radios whose RDK index is not their position.  The runner derives the expected
 * return value and the exact call trace from these inputs (correct behaviour).  Rows with last = 1 break the original: they run LAST.
 */
#include "hwr_whi.h"

/* name, nrad, shift, present, drv_null, lsmod_false, init, eco, prim, rinfo, eloop, pthr, eap, upd_fail_radio, chan, caps_fn, flags_fn, last */
hwr_whi_case_t sg_wifi_hal_init_suite[] = {
	{ "one_radio_present",            1, 0, 0x1, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "two_radios_present",           2, 0, 0x3, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "three_radios_present",         3, 0, 0x7, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "zero_radios",                  0, 0, 0x0, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "no_platform_hooks",            2, 0, 0x3, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0 },
	{ "only_caps_hook",               2, 0, 0x3, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0 },
	{ "only_flags_hook",              2, 0, 0x3, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0 },
	{ "driver_name_null",             2, 0, 0x3, 1, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "driver_loaded_after_3_polls",  2, 0, 0x3, 0, 3,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "driver_loaded_after_50_polls", 2, 0, 0x3, 0, 50, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "init_nl80211_fails",           2, 0, 0x3, 0, 0, -1, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "init_nl80211_fails_positive",  2, 0, 0x3, 0, 0,  5, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "ecomode_fails_continues",      2, 0, 0x3, 0, 0,  0,-1, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "primary_interfaces_fail",      2, 0, 0x3, 0, 0,  0, 0,-1, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "radio_info_fails",             2, 0, 0x3, 0, 0,  0, 0, 0,-1, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "eloop_init_fails",             2, 0, 0x3, 0, 0,  0, 0, 0, 0,-1, 0, 0, -1, 0, 1, 1, 0 },
	{ "pthread_create_fails",         2, 0, 0x3, 0, 0,  0, 0, 0, 0, 0, 1, 0, -1, 0, 1, 1, 0 },
	{ "pthread_create_fails_eagain",  2, 0, 0x3, 0, 0,  0, 0, 0, 0, 0,11, 0, -1, 0, 1, 1, 0 },
	{ "eap_methods_fail",             2, 0, 0x3, 0, 0,  0, 0, 0, 0, 0, 0,-1, -1, 0, 1, 1, 0 },
	{ "radio0_sleeping",              2, 0, 0x2, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "radio1_sleeping",              2, 0, 0x1, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "all_radios_sleeping",          3, 0, 0x0, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "middle_radio_sleeping",        3, 0, 0x5, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "update_hostap_fails_radio0",   3, 0, 0x7, 0, 0,  0, 0, 0, 0, 0, 0, 0,  0, 0, 1, 1, 0 },
	{ "update_hostap_fails_radio1",   3, 0, 0x7, 0, 0,  0, 0, 0, 0, 0, 0, 0,  1, 0, 1, 1, 0 },
	{ "update_hostap_fails_radio2",   3, 0, 0x7, 0, 0,  0, 0, 0, 0, 0, 0, 0,  2, 0, 1, 1, 0 },
	{ "update_hostap_fail_on_sleeping_radio_not_run", 3, 0, 0x5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0 },
	{ "channel_flags_fail",           2, 0, 0x3, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1,-1, 1, 1, 0 },
	{ "channel_flags_fail_no_radios", 0, 0, 0x0, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 3, 1, 1, 0 },
	{ "first_failure_wins_init_and_eap", 2, 0, 0x3, 0, 0, -1, 0, 0, 0, 0, 0,-1, -1, 0, 1, 1, 0 },
	{ "eco_and_primary_fail",         2, 0, 0x3, 0, 0,  0,-1,-1, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	{ "radios_three_all_hooks_sleeping_mix", 3, 0, 0x2, 0, 7, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0 },
	/* a radio whose RDK index is not its position: get_radio_by_rdk_index() returns NULL, which the loop dereferences */
	{ "radio_rdk_index_shifted",      2, 1, 0x3, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 1 },
	{ "radio_rdk_index_shifted_one",  1, 2, 0x1, 0, 0,  0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 1 },
	{ NULL }
};
