/*
 * TEST RUNNER: bcm_wifi_getRadioChannelStats_test
 *
 * Same shape as the other *_test.cpp runners: test_bcm_wifi_getRadioChannelStats() POISONS what the function must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns the channel-statistics array: a heap block of exactly array_size entries (ASan catches any
 * access behind it; a block of one entry when the size is <= 0), channel numbers pre-filled, every statistic pre-filled with a stale value.
 * During the call it POISONS the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).
 * Checks: return value; for every array entry either the stale values (no survey entry for its channel, or the handler stopped before it) or the
 * 11 statistics of the LAST survey entry that was processed for that channel (processing stops at the first unconvertible frequency or survey entry with a
 * missing attribute); a size <= 0 or a failed lookup / command must not write the array.
 * Rows with last = 1 are the invalid-input rows that corrupt / crash the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_bgk.h"
#include <sanitizer/asan_interface.h>

static bgk_iface_t iface_obj;
static bgk_radio_t radio_obj;
static char why[200];

/* poison, call, unpoison -- returns what the function returned */
int test_bcm_wifi_getRadioChannelStats(const bgk_case_t *t, wifi_channelStats_t *arr)
{
	__asan_poison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	int ret = hwr_bcm_wifi_getRadioChannelStats(t->radio_index, arr, t->array_size);
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	__asan_unpoison_memory_region(hwr_guard_slab, HWR_GUARD_SZ);
	return ret;
}

static void setup(const bgk_case_t *t)
{
	bgk_world_t *w = &hwr_bgk_world;

	memset(w, 0, sizeof(*w));
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(&iface_obj, 0, sizeof(iface_obj)); iface_obj.index = 7; iface_obj.phy_index = 1;
	radio_obj.rdk_index = 0; radio_obj.primary = t->has_iface ? &iface_obj : NULL;
	w->radio = t->has_radio ? &radio_obj : NULL;
	w->cmd_fail = t->cmd_fail; w->dump_rc = t->dump_rc; w->omit_reply = t->omit_reply;
	w->nent = t->nent;
	for (int k = 0; k < t->nent; k++) w->e[k] = t->e[k];
}

#define CHK(cond, ...) do { if (!(cond)) { snprintf(why, sizeof(why), __VA_ARGS__); return 0; } } while (0)

static void stale(wifi_channelStats_t *e, int ch)
{
	memset(e, 0, sizeof(*e));
	e->ch_number = ch; e->ch_in_pool = 1; e->ch_noise = -1234; e->ch_radar_noise = 9; e->ch_max_80211_rssi = -1111; e->ch_non_80211_noise = -2222;
	e->ch_utilization = 77; e->ch_utilization_total = 0x1111; e->ch_utilization_busy = 0x2222; e->ch_utilization_busy_tx = 0x3333;
	e->ch_utilization_busy_rx = 0x4444; e->ch_utilization_busy_self = 0x5555; e->ch_utilization_busy_ext = 0x6666;
}

static int check_entry(const wifi_channelStats_t *g, int i, int ch, int k, int ok_arr)
{
	wifi_channelStats_t x;

	stale(&x, ch);
	if (k >= 0) {
		x.ch_noise = -90 - k; x.ch_radar_noise = (BOOL)(k & 1); x.ch_max_80211_rssi = -40 - k; x.ch_non_80211_noise = -95 - k;
		x.ch_utilization = 10 + k; x.ch_utilization_total = 1000000ULL + k; x.ch_utilization_busy = 2000ULL + k; x.ch_utilization_busy_tx = 300ULL + k;
		x.ch_utilization_busy_rx = 400ULL + k; x.ch_utilization_busy_self = 500ULL + k; x.ch_utilization_busy_ext = 600ULL + k;
	}
	(void)ok_arr;
	CHK(g->ch_number == x.ch_number && g->ch_in_pool == x.ch_in_pool, "entry %d (channel %d): channel number / pool flag changed", i, ch);
	CHK(g->ch_noise == x.ch_noise, "entry %d (channel %d): noise %d, expected %d (%s)", i, ch, g->ch_noise, x.ch_noise, k >= 0 ? "survey entry applied" : "must stay untouched");
	CHK(g->ch_radar_noise == x.ch_radar_noise, "entry %d (channel %d): radar noise wrong", i, ch);
	CHK(g->ch_max_80211_rssi == x.ch_max_80211_rssi && g->ch_non_80211_noise == x.ch_non_80211_noise, "entry %d (channel %d): rssi / non-802.11 noise wrong", i, ch);
	CHK(g->ch_utilization == x.ch_utilization, "entry %d (channel %d): utilization %d, expected %d", i, ch, g->ch_utilization, x.ch_utilization);
	CHK(g->ch_utilization_total == x.ch_utilization_total && g->ch_utilization_busy == x.ch_utilization_busy, "entry %d (channel %d): total / busy time wrong", i, ch);
	CHK(g->ch_utilization_busy_tx == x.ch_utilization_busy_tx && g->ch_utilization_busy_rx == x.ch_utilization_busy_rx, "entry %d (channel %d): tx / rx time wrong", i, ch);
	CHK(g->ch_utilization_busy_self == x.ch_utilization_busy_self && g->ch_utilization_busy_ext == x.ch_utilization_busy_ext, "entry %d (channel %d): self / ext time wrong", i, ch);
	return 1;
}

/* one call; returns 1 if everything holds.  *got receives the return value */
static int one_call(const bgk_case_t *t, wifi_channelStats_t *blk, int blk_n, int *got)
{
	int ret = test_bcm_wifi_getRadioChannelStats(t, t->array_mode ? blk : NULL);
	int reached = t->has_radio && t->has_iface && t->radio_index == 0 && !t->cmd_fail;   /* the command was sent and the handler ran */

	*got = ret;
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (!t->array_mode) return 1;
	{
		int model[64];
		int n = t->array_size > 0 ? t->array_size : 0;

		for (int i = 0; i < blk_n; i++) model[i] = -1;
		if (reached && !t->exp_untouched && n > 0 && t->omit_reply == 0) {
			for (int k = 0; k < t->nent; k++) {
				if (t->e[k].omit_attr != 0 || t->e[k].ch == 0) break;
				for (int i = 0; i < n; i++) if (t->arr_first + i * t->arr_step == t->e[k].ch) model[i] = k;
			}
		}
		for (int i = 0; i < blk_n; i++)
			if (!check_entry(&blk[i], i, t->arr_first + i * t->arr_step, model[i], 1)) return 0;
	}
	return 1;
}

static int run_one(const bgk_case_t *t)
{
	int ok, got = 0;
	int blk_n = t->array_size > 0 ? t->array_size : 1;
	wifi_channelStats_t *blk = t->array_mode ? (wifi_channelStats_t *)malloc(blk_n * sizeof(*blk)) : NULL;

	printf("--- Running Test: %s ---\n", t->test_name);
	setup(t);
	why[0] = 0;
	for (int i = 0; blk && i < blk_n; i++) stale(&blk[i], t->arr_first + i * t->arr_step);
	ok = one_call(t, blk, blk_n, &got);
	if (ok && t->calls > 1) { int r2; ok = one_call(t, blk, blk_n, &r2); }
	free(blk);
	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", t->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", t->test_name, t->expected_ret, got, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_bcm_wifi_getRadioChannelStats(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, invalid / failure rows last: the first crash aborts the run, every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; bcm_wifi_getRadioChannelStats_suite[i].test_name != NULL; i++) {
			if (bcm_wifi_getRadioChannelStats_suite[i].last != last) continue;
			if (run_one(&bcm_wifi_getRadioChannelStats_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_getRadioChannelStats (broadcom): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
