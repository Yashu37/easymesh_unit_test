/*
 * TEST RUNNER: sg_wifi_hal_getScanResults_test
 *
 * test_sg_wifi_hal_getScanResults() POISONS what the function must not touch, calls the handler and unpoisons: the stand-in radio slots other than the addressed one, the interface slots beyond the ones on
 * the radio, the scan entries beyond the ones on the STA interface, the two output variables (*bss, *num_bss) when the call must fail without writing them, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The result array is the function's own calloc block, so a write past it is a heap-buffer-overflow.  run_all_tests compares the result with a reference model of the CORRECT
 * behaviour (see the construct file): return value, *num_bss, the copied entries in order (memcmp), the outputs untouched / NULL+0 as specified, the scan mutex unlocked, guard slab unchanged.  Rows with last = 1
 * break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wgs.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static struct { alignas(8) wifi_bss_info_t *bss; alignas(8) UINT num; alignas(8) char pad[8]; } out;
#define SENT_PTR ((wifi_bss_info_t *)0x1234)
#define SENT_NUM 0xABCDu

static int slot_of(const hwr_wgs_case_t *t) { return t->index < HWR_WGS_MAXR ? (int)t->index : 0; }
static int args_ok(const hwr_wgs_case_t *t) { return !t->null_channel && !t->null_bss && !t->null_num; }
static int has_sta(const hwr_wgs_case_t *t) { return !t->imap_null && t->n_if > 0 && t->sta_pos >= 0; }
static int want_freq(const hwr_wgs_case_t *t) { return t->ch_num == 255 ? 0 : (t->ch_num <= 14 ? 2407 + 5 * t->ch_num : 5000 + 5 * t->ch_num); }
/* 0 ok, else the error kind: 1 plain error (outputs untouched), 2 calloc failure (outputs NULL / 0) */
static int kind(const hwr_wgs_case_t *t)
{
	if (!args_ok(t) || t->no_radio || t->index >= HWR_WGS_MAXR || !has_sta(t) || t->band_mismatch || t->ch_num == 0) return 1;
	return t->calloc_fail ? 2 : 0;
}
static int expected_count(const hwr_wgs_case_t *t)
{
	int c = 0;
	if (t->ch_num == 255) return t->n_scan;
	for (int k = 0; k < t->n_scan; k++) if ((t->match_mask >> k) & 1) c++;
	return c;
}

static void poison(int on, const hwr_wgs_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	for (int i = 0; i < HWR_WGS_MAXR; i++) if (i != slot_of(t)) fn(&hwr_wgs_world.radios[i], sizeof(hwr_wgs_world.radios[i]));
	for (int k = t->n_if; k < HWR_WGS_MAXI; k++) fn(&hwr_wgs_world.ifs[k], sizeof(hwr_wgs_world.ifs[k]));
	for (int k = t->n_scan; k < HWR_WGS_MAXS; k++) fn(&hwr_wgs_world.scan[k], sizeof(hwr_wgs_world.scan[k]));
	if (kind(t) == 1) { fn(&out.bss, 8); fn(&out.num, 8); }
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_getScanResults(const hwr_wgs_case_t *t, wifi_channel_t *ch)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_getScanResults((wifi_radio_index_t)t->index, t->null_channel ? NULL : ch, t->null_bss ? NULL : &out.bss, t->null_num ? NULL : &out.num);
	poison(0, t);
}

static int mutex_free(const hwr_wgs_case_t *t)
{
	for (int k = 0; k < HWR_WGS_MAXI; k++) {
		if (pthread_mutex_trylock(&hwr_wgs_world.ifs[k].scan_info_mutex) != 0) return 0;
		pthread_mutex_unlock(&hwr_wgs_world.ifs[k].scan_info_mutex);
	}
	return 1;
}

static int check(const hwr_wgs_case_t *t)
{
	int k = kind(t);
	hwr_wgs_world_t *w = &hwr_wgs_world;

	if (k) {
		if (ret_val != RETURN_ERR) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, RETURN_ERR); return 0; }
		if (k == 1 && (out.bss != SENT_PTR || out.num != SENT_NUM)) { snprintf(why, sizeof(why), "*bss / *num_bss modified although the call failed"); return 0; }
		if (k == 2 && (out.bss != NULL || out.num != 0)) { snprintf(why, sizeof(why), "calloc failure: *bss %p *num_bss %u, expected NULL / 0", (void *)out.bss, out.num); return 0; }
	} else {
		int cnt = expected_count(t), j = 0;
		if (ret_val != RETURN_OK) { snprintf(why, sizeof(why), "returned %d, expected 0", ret_val); return 0; }
		if (out.num != (UINT)cnt) { snprintf(why, sizeof(why), "num_bss %u, expected %d", out.num, cnt); return 0; }
		if (out.bss == NULL || out.bss == SENT_PTR) { snprintf(why, sizeof(why), "*bss not set"); return 0; }
		for (int e = 0; e < t->n_scan && j < cnt; e++) {
			if (t->ch_num != 255 && !((t->match_mask >> e) & 1)) continue;
			if (memcmp(&out.bss[j], &w->scan[e], sizeof(wifi_bss_info_t)) != 0) { snprintf(why, sizeof(why), "bss[%d] is not scan entry %d", j, e); return 0; }
			j++;
		}
		if (!t->calloc_fail && w->calloc_calls != 1) { snprintf(why, sizeof(why), "calloc called %d times", w->calloc_calls); return 0; }
		if (t->ch_num != 255 && strcmp(w->last_country, t->country == 1 ? "CA" : "US") != 0) { snprintf(why, sizeof(why), "country \"%s\" used for the frequency lookup", w->last_country); return 0; }
	}
	if (!mutex_free(t)) { snprintf(why, sizeof(why), "scan_info_mutex left locked"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wgs_case_t *t)
{
	hwr_wgs_world_t *w = &hwr_wgs_world;
	int slot = slot_of(t);

	memset(w, 0, sizeof(*w));
	w->no_radio = t->no_radio; w->calloc_fail = t->calloc_fail;
	for (int i = 0; i < HWR_WGS_MAXR; i++) {
		w->radios[i].interface_map = &w->imaps[i];
		w->radios[i].oper_param.band = WIFI_FREQUENCY_5_BAND;
		w->radios[i].oper_param.operatingClass = 115;
		w->radios[i].oper_param.countryCode = t->country == 1 ? wifi_countrycode_CA : (t->country == 2 ? (wifi_countrycode_type_t)9999 : wifi_countrycode_US);
	}
	if (t->imap_null) w->radios[slot].interface_map = NULL;
	for (int k = 0; k < HWR_WGS_MAXI; k++) {
		w->ifs[k].vap_info.vap_mode = (k == t->sta_pos) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		pthread_mutex_init(&w->ifs[k].scan_info_mutex, NULL);
		w->ifs[k].scan_info_map = &w->smap;
		if (k < t->n_if) w->imaps[slot].items[w->imaps[slot].n++] = &w->ifs[k];
	}
	for (int e = 0; e < HWR_WGS_MAXS; e++) {
		wifi_bss_info_t *b = &w->scan[e];
		memset(b, 0x40 + e, sizeof(*b));
		b->bssid[5] = (unsigned char)(e + 1);
		if ((t->match_mask >> e) & 1) b->freq = want_freq(t);
		else if ((t->zero_mask >> e) & 1) b->freq = 0;
		else b->freq = want_freq(t) + 5;
		if (e < t->n_scan) w->smap.items[w->smap.n++] = b;
	}
	out.bss = SENT_PTR; out.num = SENT_NUM;
}

extern "C" void run_all_tests_sg_wifi_hal_getScanResults(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_getScanResults_suite[i].test_name != NULL; i++) {
			hwr_wgs_case_t *test = &sg_wifi_hal_getScanResults_suite[i];
			wifi_channel_t ch;

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			ch.channel = test->ch_num;
			ch.band = test->band_mismatch ? WIFI_FREQUENCY_2_4_BAND : WIFI_FREQUENCY_5_BAND;
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_getScanResults(test, &ch);

			int ok = check(test);
			if (out.bss && out.bss != SENT_PTR) free(out.bss);
			out.bss = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_getScanResults: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
