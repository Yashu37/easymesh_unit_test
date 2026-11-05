/*
 * UNIT TEST (input constructor): construct_platform_create_vap
 *
 * platform_create_vap(index, map) (platform/banana-pi, HOSTAPD_VERSION >= 211) walks map->vap_array[0..num_vaps-1]; for every AP
 * vap whose interface exists, is enabled, has 11be and MLD enabled, it calls ieee802_11_set_beacon() for every link of the
 * interface's MLD (hapd->mld->links) and returns -1 at the first failing call (the remaining links / vaps are not touched);
 * everything else is skipped with `continue`; 0 otherwise.  `index` is not used.
 * Inputs crossed: 0 / 1 / 2 / 3 / 8 vaps; STA and monitor vap_modes in the map; interface missing / disabled / 11be disabled /
 * MLD disabled / interface vap_mode not AP; MLD with 0 / 1 / 2 / 3 links; the vap_index lookup (vap_array position != vap_index);
 * set_beacon failing at the first / second / third call; and the unsafe inputs: map NULL, num_vaps 9 / 10 / 1000 (past the 8-entry
 * array: the runner poisons the bytes after the map), MLD pointer NULL although mld_enable.
 * Expected = the SAFE contract: NULL map / num_vaps > 8 -> -1 without reading, MLD NULL -> skipped with an error line.  The
 * rows that crash the unfixed function run forked.
 */
#include "hwr_pcv.h"

wifi_interface_info_t hwr_pcv_if[HWR_MAX_IF];
int hwr_pcv_if_used[HWR_MAX_IF];
struct hostapd_mld hwr_pcv_mld[HWR_MAX_IF];
struct hostapd_data hwr_pcv_link[HWR_MAX_IF][HWR_MAX_LINK];
int hwr_pcv_beacon_calls, hwr_pcv_fail_at, hwr_pcv_called[32];

extern "C" wifi_interface_info_t *hwr_pcv_get_interface_by_vap_index(unsigned int vap_index)
{
	for (int i = 0; i < HWR_MAX_IF; i++)
		if (hwr_pcv_if_used[i] && hwr_pcv_if[i].vap_info.vap_index == vap_index) return &hwr_pcv_if[i];
	return NULL;
}
extern "C" int hwr_pcv_set_beacon(struct hostapd_data *hapd)
{
	int n = hwr_pcv_beacon_calls++;

	if (n < 32) hwr_pcv_called[n] = hapd->mld_link_id;
	return hwr_pcv_fail_at == n + 1 ? -1 : 0;
}
extern "C" char *hwr_pcv_get_interface_name(wifi_interface_info_t *interface) { return interface ? interface->name : NULL; }

#define V(mode, idx, has, ifm, en, d11, mld, nl, mn) { mode, idx, has, ifm, en, d11, mld, nl, mn }
#define AP_OK(idx, nl)  V(0, idx, 1, 0, 1, 0, 1, nl, 0)
/* name, map_null, num_vaps, nvap, v[], fail_at, expected_ret, expected_calls, expected_errs, forked */
hwr_pcv_case_t platform_create_vap_suite[] = {
	{ "zero_vaps",                      0, 0, 0, {}, 0, 0, "", 0, 0 },
	{ "one_ap_two_links",               0, 1, 1, { AP_OK(0, 2) }, 0, 0, "0 1", 0, 0 },
	{ "one_ap_one_link",                0, 1, 1, { AP_OK(3, 1) }, 0, 0, "30", 0, 0 },
	{ "one_ap_three_links",             0, 1, 1, { AP_OK(1, 3) }, 0, 0, "10 11 12", 0, 0 },
	{ "one_ap_mld_zero_links",          0, 1, 1, { AP_OK(0, 0) }, 0, 0, "", 0, 0 },
	{ "three_aps_all_set",              0, 3, 3, { AP_OK(0, 1), AP_OK(1, 2), AP_OK(2, 1) }, 0, 0, "0 10 11 20", 0, 0 },
	{ "eight_aps_full_array",           0, 8, 8, { AP_OK(0, 1), AP_OK(1, 1), AP_OK(2, 1), AP_OK(3, 1), AP_OK(4, 1), AP_OK(5, 1), AP_OK(6, 1), AP_OK(7, 1) }, 0, 0, "0 10 20 30 40 50 60 70", 0, 0 },
	{ "lookup_by_vap_index_not_position", 0, 2, 2, { AP_OK(5, 1), AP_OK(2, 2) }, 0, 0, "50 20 21", 0, 0 },
	{ "map_vap_mode_sta_skipped",       0, 1, 1, { V(1, 0, 1, 0, 1, 0, 1, 2, 0) }, 0, 0, "", 0, 0 },
	{ "map_vap_mode_monitor_skipped",   0, 1, 1, { V(2, 0, 1, 0, 1, 0, 1, 2, 0) }, 0, 0, "", 0, 0 },
	{ "interface_missing_error_line",   0, 1, 1, { V(0, 4, 0, 0, 1, 0, 1, 2, 0) }, 0, 0, "", 1, 0 },
	{ "interface_missing_next_ok",      0, 2, 2, { V(0, 4, 0, 0, 1, 0, 1, 2, 0), AP_OK(1, 1) }, 0, 0, "10", 1, 0 },
	{ "interface_disabled",             0, 1, 1, { V(0, 0, 1, 0, 0, 0, 1, 2, 0) }, 0, 0, "", 0, 0 },
	{ "interface_11be_disabled",        0, 1, 1, { V(0, 0, 1, 0, 1, 1, 1, 2, 0) }, 0, 0, "", 0, 0 },
	{ "interface_mld_disabled",         0, 1, 1, { V(0, 0, 1, 0, 1, 0, 0, 2, 0) }, 0, 0, "", 0, 0 },
	{ "interface_vap_mode_sta",         0, 1, 1, { V(0, 0, 1, 1, 1, 0, 1, 2, 0) }, 0, 0, "", 0, 0 },
	{ "skip_then_set_second",           0, 3, 3, { V(0, 0, 1, 0, 0, 0, 1, 1, 0), AP_OK(1, 1), V(1, 2, 1, 0, 1, 0, 1, 1, 0) }, 0, 0, "10", 0, 0 },
	{ "beacon_fails_first_link",        0, 1, 1, { AP_OK(0, 2) }, 1, -1, "0", 1, 0 },
	{ "beacon_fails_second_link",       0, 1, 1, { AP_OK(0, 3) }, 2, -1, "0 1", 1, 0 },
	{ "beacon_fails_last_link",         0, 1, 1, { AP_OK(0, 2) }, 2, -1, "0 1", 1, 0 },
	{ "beacon_fails_stops_next_vaps",   0, 3, 3, { AP_OK(0, 1), AP_OK(1, 2), AP_OK(2, 1) }, 2, -1, "0 10", 1, 0 },
	{ "beacon_fails_on_second_vap",     0, 2, 2, { AP_OK(0, 1), AP_OK(1, 1) }, 2, -1, "0 10", 1, 0 },
	/* ---- unsafe inputs ---- */
	{ "crash_map_null",                 1, 0, 0, {}, 0, -1, "", 1, 1 },
	{ "crash_num_vaps_9",               0, 9, 8, { AP_OK(0, 1), AP_OK(1, 1), AP_OK(2, 1), AP_OK(3, 1), AP_OK(4, 1), AP_OK(5, 1), AP_OK(6, 1), AP_OK(7, 1) }, 0, -1, "", 1, 1 },
	{ "crash_num_vaps_10",              0, 10, 1, { AP_OK(0, 1) }, 0, -1, "", 1, 1 },
	{ "crash_num_vaps_1000",            0, 1000, 0, {}, 0, -1, "", 1, 1 },
	{ "num_vaps_8_all_skipped_ok",      0, 8, 8, { V(1,0,0,0,0,0,0,0,0), V(1,1,0,0,0,0,0,0,0), V(1,2,0,0,0,0,0,0,0), V(1,3,0,0,0,0,0,0,0), V(1,4,0,0,0,0,0,0,0), V(1,5,0,0,0,0,0,0,0), V(1,6,0,0,0,0,0,0,0), V(1,7,0,0,0,0,0,0,0) }, 0, 0, "", 0, 0 },
	{ "crash_mld_null_but_enabled",     0, 1, 1, { V(0, 0, 1, 0, 1, 0, 1, 2, 1) }, 0, 0, "", 1, 1 },
	{ "crash_mld_null_second_vap",      0, 2, 2, { AP_OK(0, 1), V(0, 1, 1, 0, 1, 0, 1, 1, 1) }, 0, 0, "0", 1, 1 },
	{ NULL, 0, 0, 0, {}, 0, 0, NULL, 0, 0 }
};
