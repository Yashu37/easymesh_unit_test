/*
 * TEST RUNNER: sg_wifi_hal_startScan_test
 *
 * test_sg_wifi_hal_startScan() POISONS what the function must not touch, calls the handler and unpoisons: the radio slots at or above MAX_NUM_RADIOS (all radios when the call must be rejected before the radio is
 * used), the interface slots not on the radio, the unused tail of the interface map, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  chan_list is an exact heap block of num entries, so a read past
 * it is a heap-buffer-overflow; chan_list_str / freq_list / ssid_list are stack arrays of the function.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file):
 * return value, the scan call (interface, flags, frequency count and values, dwell time, SSID), scan-result flush count, radio->rnr_enabled, allocator balance, guard slab unchanged.
 * Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wss.h"
#include <sanitizer/asan_interface.h>
#include <linux/nl80211.h>

static char why[240];
static int ret_val;
static unsigned *clist;
static wifi_interface_info_t *sta_if;

static int idx_bad(const hwr_wss_case_t *t) { return t->index < 0 || t->index >= MAX_NUM_RADIOS; }
static int rejects_early(const hwr_wss_case_t *t) { return idx_bad(t) || t->dwell < 0; }
static int has_sta(const hwr_wss_case_t *t) { return !t->no_radio && !t->imap_null && t->sta_pos >= 0 && t->sta_pos < t->n_if; }
static int mode_ok(const hwr_wss_case_t *t) { return t->scan_mode == 0 || (t->scan_mode == 1 && t->num != 0 && !t->chan_null); }
static unsigned chan_at(const hwr_wss_case_t *t, unsigned i)
{
	switch (t->chan_kind) {
	case 0: return t->chan_val;
	case 1: return (i % 2) ? 0 : t->chan_val;
	case 2: return i % 233 + 1;
	case 3: return 255;
	default: return 0;
	}
}
static int usable(const hwr_wss_case_t *t, unsigned ch) { return !t->bad_country && ch != 0 && ch <= 233; }
static unsigned freq_of(unsigned ch) { return ch <= 14 ? 2407 + 5 * ch : 5000 + 5 * ch; }
/* the model's frequency list: up to 128 usable channels, in order */
static int model_freqs(const hwr_wss_case_t *t, unsigned *out)
{
	int n = 0;
	unsigned num = t->scan_mode == 0 ? 1 : t->num;
	for (unsigned i = 0; i < num && n < 128; i++) {
		unsigned ch = t->scan_mode == 0 ? t->radio_channel : chan_at(t, i);
		if (!usable(t, ch)) continue;
		out[n++] = freq_of(ch);
	}
	return n;
}
static int expect_ret(const hwr_wss_case_t *t, int nfreq)
{
	if (rejects_early(t)) return WIFI_HAL_INVALID_ARGUMENTS;
	if (t->no_radio || !has_sta(t) || !mode_ok(t) || t->malloc_fail || nfreq == 0) return RETURN_ERR;
	return t->start_ret == 0 ? RETURN_OK : RETURN_ERR;
}

static void poison(int on, const hwr_wss_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wss_world_t *w = &hwr_wss_world;

	for (int i = 0; i < HWR_WSS_MAXR; i++)
		if (rejects_early(t) || i >= MAX_NUM_RADIOS) fn(&w->hal.radio_info[i], sizeof(w->hal.radio_info[i]));
	for (int k = t->n_if; k < HWR_WSS_MAXI; k++) fn(&w->ifs[k], sizeof(w->ifs[k]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_startScan(const hwr_wss_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_startScan((wifi_radio_index_t)t->index, (wifi_neighborScanMode_t)(t->scan_mode == 0 ? WIFI_RADIO_SCAN_MODE_ONCHAN : t->scan_mode == 1 ? WIFI_RADIO_SCAN_MODE_OFFCHAN : 77),
		t->dwell, t->num, t->chan_null ? NULL : clist);
	poison(0, t);
}

static int check(const hwr_wss_case_t *t)
{
	const hwr_wss_world_t *w = &hwr_wss_world;
	unsigned mf[130]; int nf = 0;
	int reached_start = !rejects_early(t) && !t->no_radio && has_sta(t) && mode_ok(t) && !t->malloc_fail;

	if (reached_start) nf = model_freqs(t, mf);
	int want = expect_ret(t, nf), started = reached_start && nf > 0;

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->start_calls != (started ? 1 : 0)) { snprintf(why, sizeof(why), "nl80211_start_scan ran %d times, expected %d", w->start_calls, started ? 1 : 0); return 0; }
	if (w->cleanup_calls != (started ? 1 : 0)) { snprintf(why, sizeof(why), "scan results flushed %d times, expected %d", w->cleanup_calls, started ? 1 : 0); return 0; }
	if (w->live_alloc != 0) { snprintf(why, sizeof(why), "allocator balance %d (leak)", w->live_alloc); return 0; }
	if (started) {
		if (w->last_iface != sta_if) { snprintf(why, sizeof(why), "scan started on the wrong interface"); return 0; }
		if (w->last_flags != (NL80211_SCAN_FLAG_COLOCATED_6GHZ | NL80211_SCAN_FLAG_FLUSH)) { snprintf(why, sizeof(why), "scan flags 0x%x", w->last_flags); return 0; }
		if (w->last_nfreq != nf) { snprintf(why, sizeof(why), "frequency count %d, expected %d", w->last_nfreq, nf); return 0; }
		for (int k = 0; k < nf; k++) if (w->last_freqs[k] != mf[k]) { snprintf(why, sizeof(why), "frequency %d is %u, expected %u", k, w->last_freqs[k], mf[k]); return 0; }
		if (w->last_dwell != t->dwell || w->last_nssid != 1) { snprintf(why, sizeof(why), "dwell / ssid count wrong"); return 0; }
		if (strlen(w->last_ssid0) != (size_t)t->ssid_len || (t->ssid_len && w->last_ssid0[0] != 'S')) { snprintf(why, sizeof(why), "scan SSID wrong"); return 0; }
		int six = 0;
		for (int r = 0; r < MAX_NUM_RADIOS; r++) if (t->band6_mask & (1u << r)) six = 1;
		if (w->hal.radio_info[t->index].rnr_enabled != (six != 0)) { snprintf(why, sizeof(why), "rnr_enabled is %d, expected %d", w->hal.radio_info[t->index].rnr_enabled, six); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wss_case_t *t)
{
	hwr_wss_world_t *w = &hwr_wss_world;

	memset(w, 0, sizeof(*w));
	w->no_radio = t->no_radio; w->malloc_fail = t->malloc_fail; w->start_ret = t->start_ret;
	w->hal.num_radios = MAX_NUM_RADIOS;
	for (int r = 0; r < HWR_WSS_MAXR; r++) {
		wifi_radio_info_t *ri = &w->hal.radio_info[r];
		ri->oper_param.channel = t->radio_channel;
		ri->oper_param.band = (t->band6_mask & (1u << r)) ? WIFI_FREQUENCY_6_BAND : WIFI_FREQUENCY_5_BAND;
		ri->oper_param.countryCode = t->bad_country ? (wifi_countrycode_type_t)(wifi_countrycode_ZW + 5) : wifi_countrycode_US;
		ri->interface_map = t->imap_null ? NULL : &w->imaps[r];
	}
	sta_if = NULL;
	for (int k = 0; k < t->n_if && k < HWR_WSS_MAXI; k++) {
		wifi_interface_info_t *f = &w->ifs[k];
		pthread_mutex_init(&f->scan_info_mutex, NULL);
		f->scan_info_map = &w->smap;
		f->vap_info.vap_mode = (k == t->sta_pos) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		if (k == t->sta_pos) {
			sta_if = f;
			for (int i = 0; i < t->ssid_len; i++) f->vap_info.u.sta_info.ssid[i] = i == 0 ? 'S' : (char)('a' + i % 26);
		}
		w->imaps[t->index >= 0 && t->index < HWR_WSS_MAXR ? t->index : 0].items[k] = f;
	}
	if (t->n_if > 0 && t->index >= 0 && t->index < HWR_WSS_MAXR) w->imaps[t->index].n = t->n_if;
	clist = NULL;
	if (!t->chan_null && t->scan_mode != 2) {
		unsigned n = t->num ? t->num : 1;
		clist = (unsigned *)malloc(n * sizeof(unsigned));
		for (unsigned i = 0; i < n; i++) clist[i] = chan_at(t, i);
		if (t->num == 0) { free(clist); clist = (unsigned *)malloc(4); clist[0] = 1; }
	}
}

extern "C" void run_all_tests_sg_wifi_hal_startScan(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_startScan_suite[i].test_name != NULL; i++) {
			hwr_wss_case_t *test = &sg_wifi_hal_startScan_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_startScan(test);

			int ok = check(test);
			free(clist); clist = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_startScan: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
