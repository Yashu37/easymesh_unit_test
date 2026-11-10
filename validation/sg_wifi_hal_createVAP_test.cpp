/*
 * TEST RUNNER: sg_wifi_hal_createVAP_test
 *
 * test_sg_wifi_hal_createVAP() POISONS what the function must not touch, calls the handler and unpoisons: the stand-in radio slots other than the addressed one, the interface slots that no VAP of the map
 * refers to, the map entries beyond map->num_vaps (inside the 8-entry array), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The map itself is a heap block of exactly
 * sizeof(wifi_vap_info_map_t), so an access to vap_array[8..] is a heap-buffer-overflow.  run_all_tests compares the result with the row's CORRECT behaviour: return value, number of
 * nl80211_create_interface / nl80211_update_interface / start_bss / reload_vap_configuration / wifi_setApMacAddressControlMode calls, platform pre / post hook runs, the bssid copied into the map and the
 * MAC filter mode passed to the vendor HAL; the guard slab stays unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wcv.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static wifi_vap_info_map_t *map;

static const hwr_wcv_vap_t *spec(const hwr_wcv_case_t *t, unsigned k) { return &t->v[k < 3 ? k : 2]; }
static unsigned nv(const hwr_wcv_case_t *t) { return t->num_vaps < 8 ? t->num_vaps : 8; }

static void poison(int on, const hwr_wcv_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	int slot = (t->index >= 0 && t->index < HWR_WCV_MAXR) ? t->index : 0;

	for (int i = 0; i < HWR_WCV_MAXR; i++) if (i != slot) fn(&hwr_wcv_world.radios[i], sizeof(hwr_wcv_world.radios[i]));
	for (unsigned k = nv(t); k < HWR_WCV_MAXI; k++) fn(&hwr_wcv_world.ifs[k], sizeof(hwr_wcv_world.ifs[k]));
	if (map) for (unsigned k = nv(t); k < 8; k++) fn(&map->vap_array[k], sizeof(map->vap_array[k]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_createVAP(const hwr_wcv_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_createVAP((wifi_radio_index_t)t->index, map);
	poison(0, t);
}

static int check(const hwr_wcv_case_t *t)
{
	const hwr_wcv_world_t *w = &hwr_wcv_world;

	if (ret_val != t->exp_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, t->exp_ret); return 0; }
	if (w->c_create != t->exp_create) { snprintf(why, sizeof(why), "nl80211_create_interface ran %d times, expected %d", w->c_create, t->exp_create); return 0; }
	if (w->c_update != t->exp_update) { snprintf(why, sizeof(why), "nl80211_update_interface ran %d times, expected %d", w->c_update, t->exp_update); return 0; }
	if (w->c_start != t->exp_start) { snprintf(why, sizeof(why), "start_bss ran %d times, expected %d", w->c_start, t->exp_start); return 0; }
	if (w->c_reload != t->exp_reload) { snprintf(why, sizeof(why), "reload_vap_configuration ran %d times, expected %d", w->c_reload, t->exp_reload); return 0; }
	if (w->c_macctl != t->exp_macctl) { snprintf(why, sizeof(why), "wifi_setApMacAddressControlMode ran %d times, expected %d", w->c_macctl, t->exp_macctl); return 0; }
	if (w->c_pre != t->exp_pre) { snprintf(why, sizeof(why), "pre-create hook ran %d times, expected %d", w->c_pre, t->exp_pre); return 0; }
	if (w->c_post != t->exp_post) { snprintf(why, sizeof(why), "post-create hook ran %d times, expected %d", w->c_post, t->exp_post); return 0; }
	if (t->exp_bssid0) {
		const unsigned char *m = w->ifs[0].mac;
		if (memcmp(map->vap_array[0].u.bss_info.bssid, m, 6) != 0) { snprintf(why, sizeof(why), "bssid of vap 0 was not copied from the interface mac"); return 0; }
	}
	if (t->exp_macctl == 1) {
		int mf = spec(t, 0)->macf, want = mf == 0 ? 0 : mf == 1 ? 2 : 1;
		if (w->last_filtermode != want) { snprintf(why, sizeof(why), "MAC filter mode %d passed to the vendor HAL, expected %d", w->last_filtermode, want); return 0; }
	}
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_wcv_case_t *t)
{
	hwr_wcv_world_t *w = &hwr_wcv_world;
	int slot = (t->index >= 0 && t->index < HWR_WCV_MAXR) ? t->index : 0;

	memset(w, 0, sizeof(*w));
	w->no_radio = t->no_radio; w->pre_fn = t->pre_fn; w->post_fn = t->post_fn; w->beacon_fn = t->beacon_fn; w->create_mode = t->create_mode;
	w->update_fail_at = t->update_fail_at; w->bridge_fail = t->bridge_fail; w->hostap_if_fail = t->hostap_if_fail; w->hostapd_ifs_fail = t->hostapd_ifs_fail;
	w->mac_ret = t->mac_ret; w->start_ret = t->start_ret; w->reload_ret = t->reload_ret;
	for (int i = 0; i < HWR_WCV_MAXR; i++) { w->radios[i].index = i; w->radios[i].radio_presence = true; w->radios[i].configured = true; w->radios[i].oper_param.enable = true; }
	w->radios[slot].radio_presence = !t->sleeping; w->radios[slot].configured = !t->unconfigured; w->radios[slot].oper_param.enable = !t->r_disabled;
	for (int k = 0; k < HWR_WCV_MAXI; k++) {
		wifi_interface_info_t *f = &w->ifs[k];
		unsigned char mac[6] = { 0x02, 0, 0, 0, (unsigned char)slot, (unsigned char)k };
		memcpy(f->mac, mac, 6);
		snprintf(f->name, sizeof(f->name), "wlan%d", k);
		f->vap_info.vap_index = k;
		if ((unsigned)k < nv(t) && spec(t, k)->exists) {
			w->exists[k] = 1;
			if (spec(t, k)->mode == 0) { f->vap_initialized = t->init_state >= 1; f->bss_started = t->init_state == 2; }
		}
	}
	map = t->null_map ? NULL : (wifi_vap_info_map_t *)calloc(1, sizeof(wifi_vap_info_map_t));
	if (!map) return;
	map->num_vaps = t->num_vaps;
	for (unsigned k = 0; k < 8; k++) {
		const hwr_wcv_vap_t *s = spec(t, k);
		wifi_vap_info_t *v = &map->vap_array[k];
		v->vap_index = k; v->radio_index = slot; v->vap_mode = s->mode == 0 ? wifi_vap_mode_ap : s->mode == 1 ? wifi_vap_mode_sta : wifi_vap_mode_monitor;
		snprintf(v->vap_name, sizeof(v->vap_name), "vap%u", k);
		if (s->mode == 0) {
			v->u.bss_info.enabled = s->enabled;
			snprintf(v->u.bss_info.ssid, sizeof(v->u.bss_info.ssid), "%s", s->invalid ? "" : "TestNet");
			snprintf(v->bridge_name, sizeof(v->bridge_name), "%s", s->bridge ? "br0" : "");
			v->u.bss_info.mac_filter_enable = s->macf != 0;
			v->u.bss_info.mac_filter_mode = s->macf == 1 ? wifi_mac_filter_mode_black_list : wifi_mac_filter_mode_white_list;
		} else {
			v->u.sta_info.ignite_enabled = s->ignite;
			snprintf(v->repurposed_bridge_name, sizeof(v->repurposed_bridge_name), "brR");
			snprintf(v->bridge_name, sizeof(v->bridge_name), "br0");
		}
	}
}

extern "C" void run_all_tests_sg_wifi_hal_createVAP(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_createVAP_suite[i].test_name != NULL; i++) {
			hwr_wcv_case_t *test = &sg_wifi_hal_createVAP_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_createVAP(test);

			int ok = check(test);
			free(map); map = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_createVAP: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
