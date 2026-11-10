/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_setRadioOperatingParameters
 *
 * wifi_hal_setRadioOperatingParameters(index, operationParam).  Inputs crossed: radio index (valid 0 / 1, -1, MAX_NUM_RADIOS, INT_MAX, INT_MIN); operationParam NULL; country (valid / beyond the
 * table); channel (valid / 0 / out of range); channel width (20 / 40 / 80 / 160 with and without DFS on 5 GHz and on 2.4 GHz / invalid); radio missing / sleeping in ECO mode / EcoPowerDown /
 * without a primary interface / malloc failing; platform pre-init, nvram and DFS hooks present / absent / failing; radio not configured yet / configured with the same enable state
 * (channel unchanged, channel changed, width changed, DFS or country changed) / configured with a different enable state (enable <-> disable with AP VAPs started / enabled, STA VAPs, an
 * empty interface map); update_hostap_config_params / nl80211_update_wiphy / nl80211_switch_channel (-1, -EOPNOTSUPP, another errno) / update_hostap_interface_params failing.
 * Expected (CORRECT behaviour, per case: return value, switch / wiphy / nvram / hostapd-config call counts, the radio's channel / enable state and configured flag afterwards, no leak, the
 * configuration_in_progress flag cleared): a failed call leaves the radio configuration as it was before the call (the reload_config path restores it).  No row crashes the original.
 */
#include "hwr_wro.h"
#include <limits.h>
#include <errno.h>

hwr_wro_case_t sg_wifi_hal_setRadioOperatingParameters_suite[] = {
#define W20  WIFI_CHANNELBANDWIDTH_20MHZ
#define W40  WIFI_CHANNELBANDWIDTH_40MHZ
#define W80  WIFI_CHANNELBANDWIDTH_80MHZ
#define W160 WIFI_CHANNELBANDWIDTH_160MHZ
#define INV  WIFI_HAL_INVALID_ARGUMENTS
#define ER   RETURN_ERR
	/* ---- argument validation: nothing runs, the radio stays as it was ---- */
	{ .test_name = "param_null", .index = 0, .param_null = 1, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "index_minus1", .index = -1, .channel = 36, .width = W20, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "index_max_num_radios", .index = MAX_NUM_RADIOS, .channel = 36, .width = W20, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "index_int_max", .index = INT_MAX, .channel = 36, .width = W20, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "index_int_min", .index = INT_MIN, .channel = 36, .width = W20, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "bad_country", .index = 0, .bad_country = 1, .channel = 36, .width = W20, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "channel_zero", .index = 0, .channel = 0, .width = W20, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "channel_out_of_range", .index = 0, .channel = 234, .width = W20, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "width_zero", .index = 0, .channel = 36, .width = 0, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "width_unknown", .index = 0, .channel = 36, .width = 0x1000, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	{ .test_name = "width_160_5g_no_dfs", .index = 0, .channel = 36, .width = W160, .dfs_new = 0, .configured = 1, .exp_ret = INV, .exp_cfgd = 1 },
	/* ---- radio / platform preconditions ---- */
	{ .test_name = "no_radio", .index = 0, .channel = 36, .width = W20, .no_radio = 1, .exp_ret = ER },
	{ .test_name = "pre_init_hook_fails", .index = 0, .channel = 36, .width = W20, .configured = 1, .pre_mode = 2, .exp_ret = ER, .exp_cfgd = 1 },
	{ .test_name = "pre_init_hook_ok_first_config", .index = 0, .channel = 36, .width = W20, .pre_mode = 1, .nvram_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "radio_sleeping_eco", .index = 0, .channel = 36, .width = W20, .sleeping = 1, .nvram_fn = 1, .exp_ret = 0, .exp_cfgd = 0 },
	{ .test_name = "eco_power_down", .index = 0, .channel = 36, .width = W20, .eco = 1, .configured = 1, .nvram_fn = 1, .exp_ret = 0, .exp_cfgd = 1 },
	{ .test_name = "no_primary_interface", .index = 0, .channel = 36, .width = W20, .configured = 1, .no_primary = 1, .exp_ret = ER, .exp_cfgd = 1 },
	{ .test_name = "malloc_fails", .index = 0, .channel = 36, .width = W20, .configured = 1, .malloc_fail = 1, .exp_ret = ER, .exp_cfgd = 1 },
	/* ---- first configuration (radio not configured yet) ---- */
	{ .test_name = "first_config_nvram", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .nvram_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "first_config_no_nvram_hook", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_cfg = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "first_config_radio_index_1", .index = 1, .channel = 100, .width = W80, .enable_new = 1, .nvram_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 100, .exp_cfgd = 1 },
	{ .test_name = "first_config_160_5g_dfs", .index = 0, .channel = 36, .width = W160, .dfs_new = 1, .enable_new = 1, .nvram_fn = 1, .dfs_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "first_config_160_2g", .index = 0, .channel = 6, .width = W160, .band = WIFI_FREQUENCY_2_4_BAND, .enable_new = 1, .nvram_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 6, .exp_cfgd = 1 },
	/* ---- configured, enable state unchanged ---- */
	{ .test_name = "reconfig_nothing_changed", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "channel_change_switch_ok", .index = 0, .channel = 40, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .exp_ret = 0, .exp_sw = 1, .exp_nvram = 1, .exp_ch = 40, .exp_cfgd = 1 },
	{ .test_name = "width_change_switch_ok", .index = 0, .channel = 36, .width = W40, .enable_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .exp_ret = 0, .exp_sw = 1, .exp_nvram = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "channel_change_power_differs", .index = 0, .channel = 40, .width = W20, .enable_new = 1, .power_new = 80, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .r_power = 50, .nvram_fn = 1, .exp_ret = 0, .exp_sw = 1, .exp_nvram = 1, .exp_ch = 40, .exp_cfgd = 1 },
	{ .test_name = "channel_change_dfs_differs", .index = 0, .channel = 40, .width = W20, .dfs_new = 1, .enable_new = 1, .configured = 1, .r_enable = 1, .r_dfs = 0, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .dfs_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 40, .exp_cfgd = 1 },
	{ .test_name = "channel_change_dfs_differs_no_hook", .index = 0, .channel = 40, .width = W20, .dfs_new = 1, .enable_new = 1, .configured = 1, .r_enable = 1, .r_dfs = 0, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 40, .exp_cfgd = 1 },
	{ .test_name = "country_changes", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .country_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .exp_ret = 0, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "switch_fails_minus1_rolls_back", .index = 0, .channel = 40, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .switch_ret = -1, .exp_ret = ER, .exp_sw = 1, .exp_wiphy = 1, .exp_cfg = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "switch_eopnotsupp_updates_hostapd", .index = 0, .channel = 40, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .switch_ret = -EOPNOTSUPP, .exp_ret = 0, .exp_sw = 1, .exp_wiphy = 1, .exp_nvram = 1, .exp_cfg = 1, .exp_ch = 40, .exp_cfgd = 1 },
	{ .test_name = "switch_fails_other_errno_keeps_old_channel", .index = 0, .channel = 40, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .switch_ret = -EIO, .exp_ret = ER, .exp_sw = 1, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "hostapd_cfg_fails_first_config", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .nvram_fn = 1, .hostap_fail = 1, .exp_ret = ER, .exp_cfg = 2, .exp_cfgd = 0 },
	{ .test_name = "hostapd_cfg_fails_once_rolls_back", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .hostap_fail = 2, .exp_ret = ER, .exp_wiphy = 1, .exp_cfg = 2, .exp_ch = 36, .exp_cfgd = 1 },
	{ .test_name = "wiphy_update_fails", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .wiphy_fail = 1, .exp_ret = ER, .exp_wiphy = 2, .exp_cfg = 2, .exp_ch = 36, .exp_cfgd = 1 },
	/* ---- configured, enable state toggled: every VAP of the radio is restarted / stopped ---- */
	{ .test_name = "toggle_disable_ap_started", .index = 0, .channel = 36, .width = W20, .enable_new = 0, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .n_ap = 1, .ap_started = 1, .ap_enabled = 1, .exp_ret = 0, .exp_nvram = 1, .exp_cfg = 1, .exp_en = 1, .exp_cfgd = 1 },
	{ .test_name = "toggle_enable_ap_enabled", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 0, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .n_ap = 1, .ap_enabled = 1, .exp_ret = 0, .exp_nvram = 1, .exp_cfg = 1, .exp_en = 2, .exp_cfgd = 1 },
	{ .test_name = "toggle_empty_interface_map", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 0, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .exp_ret = 0, .exp_nvram = 1, .exp_cfg = 1, .exp_en = 2, .exp_cfgd = 1 },
	{ .test_name = "toggle_disable_sta_completed", .index = 0, .channel = 36, .width = W20, .enable_new = 0, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .n_sta = 1, .sta_completed = 1, .exp_ret = 0, .exp_nvram = 1, .exp_cfg = 1, .exp_en = 1, .exp_cfgd = 1 },
	{ .test_name = "toggle_enable_sta", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 0, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .n_sta = 1, .exp_ret = 0, .exp_nvram = 1, .exp_cfg = 1, .exp_en = 2, .exp_cfgd = 1 },
	{ .test_name = "toggle_enable_two_ap_one_sta", .index = 0, .channel = 36, .width = W20, .enable_new = 1, .configured = 1, .r_enable = 0, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .n_ap = 2, .ap_enabled = 1, .n_sta = 1, .exp_ret = 0, .exp_nvram = 1, .exp_cfg = 1, .exp_en = 2, .exp_cfgd = 1 },
	{ .test_name = "toggle_ifparam_fails_ap_disabling", .index = 0, .channel = 36, .width = W20, .enable_new = 0, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .ifparam_fail = 1, .n_ap = 1, .ap_started = 1, .ap_enabled = 1, .exp_ret = ER, .exp_cfg = 1, .exp_cfgd = 1 },
	{ .test_name = "toggle_hostapd_cfg_fails_keeps_old_enable", .index = 0, .channel = 36, .width = W20, .enable_new = 0, .configured = 1, .r_enable = 1, .r_channel = 36, .r_width = W20, .nvram_fn = 1, .hostap_fail = 1, .exp_ret = ER, .exp_cfg = 1, .exp_en = 2, .exp_cfgd = 1 },
	{ .test_name = NULL }
};
