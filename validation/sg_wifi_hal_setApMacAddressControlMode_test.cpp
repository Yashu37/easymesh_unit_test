/*
 * TEST RUNNER: sg_wifi_hal_setApMacAddressControlMode_test
 *
 * test_sg_wifi_hal_setApMacAddressControlMode() POISONS what the function must not touch, calls the handler and unpoisons: the interfaces other than the addressed one (all of them when no interface exists),
 * every byte of the addressed interface's vap_info except the fields the function reads or writes (vap_index, vap_mode, u.bss_info.enabled, mac_filter_enable, mac_filter_mode), the interface tail, the guard
 * slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return value, filter enable / list mode,
 * nl80211_set_acl called once with the right interface (or not at all), guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include "hwr_wam.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static const int vaps[HWR_WAM_MAXI] = { 0, 1, 5, 14 };
static int idx_of(uint32_t vap) { for (int i = 0; i < HWR_WAM_MAXI; i++) if ((uint32_t)vaps[i] == vap) return i; return -1; }

struct range { size_t off, len; };

static void poison_except(void (*fn)(void const volatile *, size_t), char *base, size_t size, const range *keep, int nkeep)
{
	size_t pos = 0;
	/* keep[] is sorted by offset */
	for (int k = 0; k < nkeep; k++) {
		if (keep[k].off > pos) fn(base + pos, keep[k].off - pos);
		pos = keep[k].off + keep[k].len;
	}
	if (pos < size) fn(base + pos, size - pos);
}

static void poison(int on, const hwr_wam_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wam_world_t *w = &hwr_wam_world;
	int a = idx_of(t->ap_index);

	for (int i = 0; i < HWR_WAM_MAXI; i++) {
		wifi_interface_info_t *f = &w->ifs[i];
		if (i != a) { fn(f, sizeof(*f)); continue; }
		range keep[5];
		wifi_vap_info_t *v = &f->vap_info;
		range r[5] = {
			{ offsetof(wifi_vap_info_t, vap_index), sizeof(v->vap_index) },
			{ offsetof(wifi_vap_info_t, vap_mode), sizeof(v->vap_mode) },
			{ (size_t)((char *)&v->u.bss_info.enabled - (char *)v), sizeof(v->u.bss_info.enabled) },
			{ (size_t)((char *)&v->u.bss_info.mac_filter_enable - (char *)v), sizeof(v->u.bss_info.mac_filter_enable) },
			{ (size_t)((char *)&v->u.bss_info.mac_filter_mode - (char *)v), sizeof(v->u.bss_info.mac_filter_mode) },
		};
		for (int x = 0; x < 5; x++) keep[x] = r[x];
		for (int x = 0; x < 5; x++) for (int y = x + 1; y < 5; y++) if (keep[y].off < keep[x].off) { range tmp = keep[x]; keep[x] = keep[y]; keep[y] = tmp; }
		poison_except(fn, (char *)v, sizeof(*v), keep, 5);
		fn(f->tail, sizeof(f->tail));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_setApMacAddressControlMode(const hwr_wam_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_setApMacAddressControlMode(t->ap_index, t->mode);
	poison(0, t);
}

static int check(const hwr_wam_case_t *t)
{
	const hwr_wam_world_t *w = &hwr_wam_world;
	int a = idx_of(t->ap_index);
	int want = RETURN_ERR, want_acl = 0;
	int want_en = t->pre_enable, want_mode = t->pre_mode;

	if (a >= 0 && t->enabled && !t->sta_mode) {
		if (t->mode <= 2) {
			want_acl = 1; want = t->acl_ret;
			if (t->mode == 0) want_en = 0;
			else { want_en = 1; want_mode = (t->mode == 2) ? (int)wifi_mac_filter_mode_black_list : (int)wifi_mac_filter_mode_white_list; }
		}
	}
	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->acl_calls != want_acl) { snprintf(why, sizeof(why), "nl80211_set_acl called %d times, expected %d", w->acl_calls, want_acl); return 0; }
	if (want_acl && w->acl_if != &w->ifs[a]) { snprintf(why, sizeof(why), "nl80211_set_acl got the wrong interface"); return 0; }
	if (a >= 0) {
		const wifi_vap_info_t *v = &w->ifs[a].vap_info;
		if ((int)v->u.bss_info.mac_filter_enable != want_en) { snprintf(why, sizeof(why), "mac_filter_enable is %d, expected %d", (int)v->u.bss_info.mac_filter_enable, want_en); return 0; }
		if ((int)v->u.bss_info.mac_filter_mode != want_mode) { snprintf(why, sizeof(why), "mac_filter_mode is %d, expected %d", (int)v->u.bss_info.mac_filter_mode, want_mode); return 0; }
		if (want_acl && (w->acl_enable != want_en || w->acl_mode != want_mode)) { snprintf(why, sizeof(why), "nl80211_set_acl saw enable %d mode %d", w->acl_enable, w->acl_mode); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wam_case_t *t)
{
	hwr_wam_world_t *w = &hwr_wam_world;

	memset(w, 0, sizeof(*w));
	w->acl_ret = t->acl_ret;
	for (int i = 0; i < HWR_WAM_MAXI; i++) {
		wifi_vap_info_t *v = &w->ifs[i].vap_info;
		w->vap_ids[i] = vaps[i];
		v->vap_index = vaps[i];
		v->vap_mode = (i == idx_of(t->ap_index) && t->sta_mode) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		v->u.bss_info.enabled = (i == idx_of(t->ap_index)) ? (t->enabled != 0) : true;
		v->u.bss_info.mac_filter_enable = (i == idx_of(t->ap_index)) ? (t->pre_enable != 0) : false;
		v->u.bss_info.mac_filter_mode = (i == idx_of(t->ap_index) && t->pre_mode) ? wifi_mac_filter_mode_white_list : wifi_mac_filter_mode_black_list;
	}
}

extern "C" void run_all_tests_sg_wifi_hal_setApMacAddressControlMode(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_setApMacAddressControlMode_suite[i].test_name != NULL; i++) {
			hwr_wam_case_t *test = &sg_wifi_hal_setApMacAddressControlMode_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_setApMacAddressControlMode(test);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_setApMacAddressControlMode: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
