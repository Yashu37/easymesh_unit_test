/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_createVAP
 *
 * wifi_hal_createVAP(index, map).  Inputs crossed: radio index (0 / 1, -1, MAX_NUM_RADIOS, INT_MIN); map NULL; no radio / radio sleeping in ECO mode / radio not configured / radio disabled; map->num_vaps 0 /
 * 1 / 2 / 3 / 8 (the array size) / 9 / 16 / UINT_MAX; every VAP an AP (existing / to be created / invalid parameters / bridge / MAC filter mode) / a STA (existing / created / ignite bridge) / a monitor VAP;
 * existing AP interface not initialised / initialised and not started / started; nl80211_create_interface failing or reporting success with a NULL interface; nl80211_update_interface, bridge creation / up,
 * update_hostap_interface_params, update_hostap_interfaces, start_bss, reload_vap_configuration, wifi_setApMacAddressControlMode failing; platform pre / post create hooks.  The runner allocates the map
 * exactly (a heap block of sizeof(wifi_vap_info_map_t)), so reading or writing vap_array[8] is a heap overflow.  Expected (CORRECT behaviour, per row: return value, create / update / start / reload /
 * MAC-filter call counts, pre / post hook runs, bssid copied into the map, the MAC filter mode): num_vaps beyond the array is rejected with -4 before any VAP is touched; an invalid AP gives -4; the other
 * errors give -1 or skip the VAP as the code does.  Rows with last = 1 (num_vaps beyond the array) break the original: they run LAST.
 */
#include "hwr_wcv.h"
#include <limits.h>

#define AP(ex, en, br)  { 0, ex, en, br, 0, 0, 0 }
#define APM(macf)       { 0, 1, 1, 1, 0, 0, macf }
#define APX             { 0, 1, 1, 1, 0, 1, 0 }
#define STA(ex, ign)    { 1, ex, 0, 0, ign, 0, 0 }
#define MON             { 2, 1, 0, 0, 0, 0, 0 }
#define INV  WIFI_HAL_INVALID_ARGUMENTS
#define ER   RETURN_ERR

hwr_wcv_case_t sg_wifi_hal_createVAP_suite[] = {
	/* ---- argument / radio preconditions ---- */
	{ .test_name = "map_null", .index = 0, .null_map = 1, .exp_ret = INV },
	{ .test_name = "index_minus1", .index = -1, .num_vaps = 1, .v = { AP(1,1,1) }, .exp_ret = INV },
	{ .test_name = "index_max_num_radios", .index = MAX_NUM_RADIOS, .num_vaps = 1, .v = { AP(1,1,1) }, .exp_ret = INV },
	{ .test_name = "index_int_min", .index = INT_MIN, .num_vaps = 1, .v = { AP(1,1,1) }, .exp_ret = INV },
	{ .test_name = "no_radio", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .no_radio = 1, .exp_ret = ER },
	{ .test_name = "radio_sleeping_eco", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .sleeping = 1, .pre_fn = 1, .post_fn = 1, .exp_ret = 0 },
	{ .test_name = "zero_vaps_with_hooks", .index = 0, .num_vaps = 0, .pre_fn = 1, .post_fn = 1, .exp_ret = 0, .exp_pre = 1, .exp_post = 1 },
	/* ---- one AP VAP ---- */
	{ .test_name = "ap_existing_enabled", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .exp_ret = 0, .exp_update = 1, .exp_start = 1, .exp_macctl = 1, .exp_bssid0 = 1 },
	{ .test_name = "ap_existing_radio_1", .index = 1, .num_vaps = 1, .v = { AP(1,1,1) }, .exp_ret = 0, .exp_update = 1, .exp_start = 1, .exp_macctl = 1, .exp_bssid0 = 1 },
	{ .test_name = "ap_existing_vap_disabled", .index = 0, .num_vaps = 1, .v = { AP(1,0,1) }, .exp_ret = 0, .exp_update = 1, .exp_macctl = 1, .exp_bssid0 = 1 },
	{ .test_name = "ap_interface_created", .index = 0, .num_vaps = 1, .v = { AP(0,1,1) }, .exp_ret = 0, .exp_create = 1, .exp_update = 1, .exp_start = 1, .exp_macctl = 1, .exp_bssid0 = 1 },
	{ .test_name = "ap_create_interface_fails", .index = 0, .num_vaps = 1, .v = { AP(0,1,1) }, .create_mode = 1, .exp_ret = 0, .exp_create = 1 },
	{ .test_name = "ap_create_interface_null", .index = 0, .num_vaps = 1, .v = { AP(0,1,1) }, .create_mode = 2, .exp_ret = 0, .exp_create = 1 },
	{ .test_name = "ap_invalid_params", .index = 0, .num_vaps = 1, .v = { APX }, .exp_ret = INV },
	{ .test_name = "ap_second_vap_invalid", .index = 0, .num_vaps = 2, .v = { AP(1,1,1), APX }, .exp_ret = INV, .exp_update = 1, .exp_start = 1, .exp_macctl = 1 },
	{ .test_name = "ap_update_interface_fails", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .post_fn = 1, .update_fail_at = 1, .exp_ret = ER, .exp_update = 1 },
	{ .test_name = "ap_bridge_create_fails", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .bridge_fail = 1, .exp_ret = 0, .exp_update = 1 },
	{ .test_name = "ap_bridge_up_fails", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .bridge_fail = 2, .exp_ret = 0, .exp_update = 1 },
	{ .test_name = "ap_hostapd_params_fail", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .hostap_if_fail = 1, .exp_ret = ER, .exp_update = 1 },
	{ .test_name = "ap_hostapd_interfaces_fail", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .hostapd_ifs_fail = 1, .exp_ret = ER, .exp_update = 1 },
	{ .test_name = "ap_initialised_not_started", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .init_state = 1, .exp_ret = 0, .exp_update = 1, .exp_start = 1, .exp_macctl = 1 },
	{ .test_name = "ap_already_started_reloads", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .init_state = 2, .exp_ret = 0, .exp_update = 1, .exp_reload = 1, .exp_macctl = 1 },
	{ .test_name = "ap_reload_fails", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .init_state = 2, .reload_ret = -1, .exp_ret = ER, .exp_update = 1, .exp_reload = 1, .exp_macctl = 1 },
	{ .test_name = "ap_start_bss_fails", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .start_ret = -1, .exp_ret = ER, .exp_update = 1, .exp_start = 1, .exp_macctl = 1 },
	{ .test_name = "ap_radio_not_configured", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .unconfigured = 1, .exp_ret = 0, .exp_update = 1, .exp_macctl = 1 },
	{ .test_name = "ap_radio_disabled", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .r_disabled = 1, .exp_ret = 0, .exp_update = 1, .exp_macctl = 1 },
	{ .test_name = "ap_mac_control_fails", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .mac_ret = -1, .exp_ret = ER, .exp_update = 1, .exp_start = 1, .exp_macctl = 1 },
	{ .test_name = "ap_mac_filter_black_list", .index = 0, .num_vaps = 1, .v = { APM(1) }, .exp_ret = 0, .exp_update = 1, .exp_start = 1, .exp_macctl = 1 },
	{ .test_name = "ap_mac_filter_white_list", .index = 0, .num_vaps = 1, .v = { APM(2) }, .exp_ret = 0, .exp_update = 1, .exp_start = 1, .exp_macctl = 1 },
	/* ---- STA / monitor VAP ---- */
	{ .test_name = "sta_existing", .index = 0, .num_vaps = 1, .v = { STA(1,0) }, .exp_ret = 0, .exp_update = 1 },
	{ .test_name = "sta_interface_created", .index = 0, .num_vaps = 1, .v = { STA(0,0) }, .exp_ret = 0, .exp_create = 1, .exp_update = 1 },
	{ .test_name = "sta_ignite_bridge", .index = 0, .num_vaps = 1, .v = { STA(1,1) }, .exp_ret = 0, .exp_update = 1 },
	{ .test_name = "sta_ignite_bridge_create_fails", .index = 0, .num_vaps = 1, .v = { STA(1,1) }, .bridge_fail = 1, .exp_ret = ER, .exp_update = 1 },
	{ .test_name = "sta_ignite_bridge_up_fails", .index = 0, .num_vaps = 1, .v = { STA(1,1) }, .bridge_fail = 2, .exp_ret = ER, .exp_update = 1 },
	{ .test_name = "sta_update_interface_fails", .index = 0, .num_vaps = 1, .v = { STA(1,0) }, .update_fail_at = 1, .exp_ret = ER, .exp_update = 1 },
	{ .test_name = "monitor_vap", .index = 0, .num_vaps = 1, .v = { MON }, .exp_ret = 0, .exp_update = 1 },
	/* ---- several VAPs / hooks ---- */
	{ .test_name = "two_ap_one_sta", .index = 0, .num_vaps = 3, .v = { AP(1,1,1), AP(1,1,1), STA(1,0) }, .exp_ret = 0, .exp_update = 3, .exp_start = 2, .exp_macctl = 2, .exp_bssid0 = 1 },
	{ .test_name = "third_interface_create_fails", .index = 0, .num_vaps = 3, .v = { AP(1,1,1), AP(1,1,1), AP(0,1,1) }, .create_mode = 1, .exp_ret = 0, .exp_create = 1, .exp_update = 2, .exp_start = 2, .exp_macctl = 2 },
	{ .test_name = "pre_post_hooks_beacon_fn", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .pre_fn = 1, .post_fn = 1, .beacon_fn = 1, .exp_ret = 0, .exp_update = 1, .exp_start = 1, .exp_macctl = 1, .exp_pre = 1, .exp_post = 1 },
	{ .test_name = "post_hook_skipped_after_error", .index = 0, .num_vaps = 1, .v = { AP(1,1,1) }, .post_fn = 1, .mac_ret = -1, .exp_ret = ER, .exp_update = 1, .exp_start = 1, .exp_macctl = 1 },
	{ .test_name = "num_vaps_8_array_size", .index = 0, .num_vaps = 8, .v = { AP(1,1,1), AP(1,1,1), AP(1,1,1) }, .exp_ret = 0, .exp_update = 8, .exp_start = 8, .exp_macctl = 8, .exp_bssid0 = 1 },
	/* ---- num_vaps beyond the 8-entry vap_array: the original reads (and writes the bssid of) vap_array[8..] ---- */
	{ .test_name = "num_vaps_9_beyond_array", .index = 0, .num_vaps = 9, .v = { AP(1,1,1), AP(1,1,1), AP(1,1,1) }, .exp_ret = INV, .last = 1 },
	{ .test_name = "num_vaps_16_beyond_array", .index = 0, .num_vaps = 16, .v = { AP(1,1,1), AP(1,1,1), AP(1,1,1) }, .exp_ret = INV, .last = 1 },
	{ .test_name = "num_vaps_uint_max", .index = 0, .num_vaps = UINT_MAX, .v = { AP(1,1,1), AP(1,1,1), AP(1,1,1) }, .exp_ret = INV, .last = 1 },
	{ .test_name = NULL }
};
