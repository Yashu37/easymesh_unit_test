/*
 * TEST RUNNER: sg_wifi_hal_findNetworks_test
 *
 * test_sg_wifi_hal_findNetworks() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots beyond the existing ones, the union of every interface (the function
 * only reads vap_info and the scan list), the scan list of every interface except the addressed STA VAP, the scan entries beyond the addressed interface's list, the guard slab and the log slot
 * tail [HWR_LOG_USE, HWR_LOG_SZ).  The output pointer / count are written by the function and stay readable.  run_all_tests compares the result with a reference model of the CORRECT behaviour
 * (see the construct file): return value, *num_bss, the copied entries in list order, outputs untouched on an early error, scan mutex released, no allocation left once the runner has freed the
 * returned array, guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wfn.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static wifi_channel_t chan_arg;
static wifi_bss_info_t *arr_out;
static unsigned int num_out;
#define ARR_SENTINEL ((wifi_bss_info_t *)(unsigned long)0x10)
#define NUM_SENTINEL 0xAAAAu

static int exists(const hwr_wfn_case_t *t) { return t->vap_index >= 0 && (unsigned)t->vap_index < t->n_if; }
static int is_sta(const hwr_wfn_case_t *t, int k) { return (t->sta_mask >> k) & 1; }

static void poison(int on, const hwr_wfn_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	int tgt = exists(t) && is_sta(t, t->vap_index) ? t->vap_index : -1;

	for (unsigned i = t->n_if; i < HWR_WFN_MAXI; i++) fn(&hwr_wfn_world.ifs[i], sizeof(hwr_wfn_world.ifs[i]));
	for (unsigned i = 0; i < t->n_if; i++) {
		fn(&hwr_wfn_world.ifs[i].u, sizeof(hwr_wfn_world.ifs[i].u));
		if ((int)i == tgt) { for (unsigned k = t->n_scan; k < HWR_WFN_MAXS; k++) fn(&hwr_wfn_world.scan[i][k], sizeof(hwr_wfn_world.scan[i][k])); }
		else fn(hwr_wfn_world.scan[i], sizeof(hwr_wfn_world.scan[i]));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_findNetworks(const hwr_wfn_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_findNetworks(t->vap_index, t->null_chan ? NULL : &chan_arg, t->null_arr ? NULL : &arr_out, t->null_num ? NULL : &num_out);
	poison(0, t);
}

/* reference model of the frequency -> channel mapping (independent of the stub) */
static int model_chan(unsigned f)
{
	if (f >= 2412 && f <= 2472 && (f - 2407) % 5 == 0) return (f - 2407) / 5;
	if (f == 2484) return 14;
	if (f >= 5170 && f <= 5885 && f % 5 == 0) return (f - 5000) / 5;
	if (f >= 5955 && f <= 7115 && (f - 5950) % 5 == 0) return (f - 5950) / 5;
	return 0;
}

static int check(const hwr_wfn_case_t *t)
{
	const hwr_wfn_world_t *w = &hwr_wfn_world;
	int early = t->null_chan || t->null_arr || t->null_num || !exists(t) || !is_sta(t, t->vap_index);
	int idx[HWR_WFN_MAXS], n = 0;

	if (early) {
		if (ret_val != RETURN_ERR) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, RETURN_ERR); return 0; }
		if (!t->null_arr && arr_out != ARR_SENTINEL) { snprintf(why, sizeof(why), "*bss_array modified on an early error"); return 0; }
		if (!t->null_num && num_out != NUM_SENTINEL) { snprintf(why, sizeof(why), "*num_bss modified on an early error"); return 0; }
	} else if (t->calloc_fail) {
		if (ret_val != RETURN_ERR) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, RETURN_ERR); return 0; }
		if (arr_out != NULL || num_out != 0) { snprintf(why, sizeof(why), "outputs not cleared after the allocation failure"); return 0; }
	} else {
		for (unsigned k = 0; k < t->n_scan; k++) if (t->chan == 0 || model_chan(t->freq[k]) == t->chan) idx[n++] = k;
		if (ret_val != RETURN_OK) { snprintf(why, sizeof(why), "returned %d, expected 0", ret_val); return 0; }
		if (num_out != (unsigned)n) { snprintf(why, sizeof(why), "*num_bss %u, expected %d", num_out, n); return 0; }
		if (arr_out == NULL) { snprintf(why, sizeof(why), "*bss_array is NULL"); return 0; }
		for (int k = 0; k < n; k++)
			if (memcmp(&arr_out[k], &w->scan[t->vap_index][idx[k]], sizeof(wifi_bss_info_t)) != 0) { snprintf(why, sizeof(why), "entry %d is not scan entry %d", k, idx[k]); return 0; }
	}
	if (exists(t) && is_sta(t, t->vap_index)) {
		wifi_interface_info_t *f = (wifi_interface_info_t *)&w->ifs[t->vap_index];
		if (pthread_mutex_trylock(&f->scan_info_mutex) != 0) { snprintf(why, sizeof(why), "scan_info_mutex left locked"); return 0; }
		pthread_mutex_unlock(&f->scan_info_mutex);
	}
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_wfn_case_t *t)
{
	hwr_wfn_world_t *w = &hwr_wfn_world;

	memset(w, 0, sizeof(*w));
	w->num_ifs = t->n_if; w->calloc_fail = t->calloc_fail;
	chan_arg.channel = t->chan; chan_arg.band = WIFI_FREQUENCY_5_BAND;
	arr_out = ARR_SENTINEL; num_out = NUM_SENTINEL;
	for (unsigned i = 0; i < HWR_WFN_MAXI; i++) {
		wifi_interface_info_t *f = &w->ifs[i];
		f->vap_info.vap_index = i;
		f->vap_info.vap_mode = (i < t->n_if && is_sta(t, i)) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		pthread_mutex_init(&f->scan_info_mutex, NULL);
		f->scan_info_map = &w->maps[i];
		memset(&f->u, 0xEE, sizeof(f->u));
		for (unsigned k = 0; k < HWR_WFN_MAXS; k++) {
			wifi_bss_info_t *e = &w->scan[i][k];
			memset(e, 0, sizeof(*e));
			e->bssid[0] = 0xB0; e->bssid[1] = (unsigned char)k; e->bssid[2] = (unsigned char)i;
			snprintf(e->ssid, sizeof(e->ssid), "net%u", k);
			e->freq = t->freq[k]; e->rssi = -40 - (int)k;
			if (k < t->n_scan) w->maps[i].items[w->maps[i].n++] = e;
		}
	}
}

extern "C" void run_all_tests_sg_wifi_hal_findNetworks(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_findNetworks_suite[i].test_name != NULL; i++) {
			hwr_wfn_case_t *test = &sg_wifi_hal_findNetworks_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_log_buf, 'x', test->prefill);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_findNetworks(test);

			int ok = check(test);
			if (arr_out != NULL && arr_out != ARR_SENTINEL) { free(arr_out); hwr_wfn_world.live_alloc--; }
			if (ok && hwr_wfn_world.live_alloc != 0) { snprintf(why, sizeof(why), "%d allocation(s) not freed", hwr_wfn_world.live_alloc); ok = 0; }
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_findNetworks: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
