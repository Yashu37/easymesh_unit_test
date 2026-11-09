/*
 * TEST RUNNER: wifi_startNeighborScan_test
 *
 * Same shape as the other *_test.cpp runners: construct_wifi_startNeighborScan_input() builds the world for a row (interfaces, radio, hostapd channel
 * table, caller's channel list), test_wifi_startNeighborScan() POISONS the tail of the channel list [chan_num, 16), the unused tail of the channel
 * table, the guard slab and the log slot tail, calls the handler and unpoisons, then run_all_tests compares the return value and the side effects
 * (scan_state, nl80211 call counts, frequency filter, scan flags / dwell / probe SSID).  crash_* rows run LAST, so on the unfixed function every
 * other row has reported before the ASan abort.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <initializer_list>
#include <sys/wait.h>
#include "hwr_wsn.h"
#include <sanitizer/asan_interface.h>

static char why[200];

static void poison(int on, const hwr_wsn_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	unsigned valid = t->list_null ? 0 : t->chan_num;

	if (valid > 16) valid = 16;
	fn(&list_slab[valid], (16 - valid) * sizeof(unsigned int));
	fn(&chan_slab[6], 2 * sizeof(wsn_chan_t));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static int check(const hwr_wsn_case_t *t, int ret, wsn_interface_t *si)
{
	wsn_world_t *w = &hwr_wsn_world;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (si->scan_state != t->exp_state) { snprintf(why, sizeof(why), "scan_state %d, expected %d", si->scan_state, t->exp_state); return 0; }
	if (w->start_calls != t->exp_start_calls) { snprintf(why, sizeof(why), "%d nl80211_start_scan calls, expected %d", w->start_calls, t->exp_start_calls); return 0; }
	if (w->results_calls != t->exp_results_calls) { snprintf(why, sizeof(why), "%d nl80211_get_scan_results calls, expected %d", w->results_calls, t->exp_results_calls); return 0; }
	/* exp_cleanup = 1: the old scan data is cleaned up (scan_info_map and scan_info_ap_map[0]: 2 hash_map_cleanup calls) */
	if (w->cleanup_calls != 2 * t->exp_cleanup) { snprintf(why, sizeof(why), "%d hash_map_cleanup calls, expected %d", w->cleanup_calls, 2 * t->exp_cleanup); return 0; }
	/* the 3 stale frequencies (7,7,7) put in scan_filter before the call must be gone when the old scan data was cleaned up */
	if (t->exp_cleanup && si->scan_filter.num == 3 && si->scan_filter.values[0] == 7 && si->scan_filter.values[1] == 7 && si->scan_filter.values[2] == 7)
		{ snprintf(why, sizeof(why), "stale scan filter was not cleaned up"); return 0; }
	if (w->start_calls || w->results_calls) {
		if (w->start_num != t->exp_num) { snprintf(why, sizeof(why), "filter has %u frequencies, expected %u", w->start_num, t->exp_num); return 0; }
		for (unsigned i = 0; i < t->exp_num; i++)
			if (w->start_values[i] != t->exp_vals[i]) { snprintf(why, sizeof(why), "filter[%u] = %u, expected %u", i, w->start_values[i], t->exp_vals[i]); return 0; }
	}
	if (w->start_calls) {
		if (w->start_flags != t->exp_flags) { snprintf(why, sizeof(why), "scan flags 0x%x, expected 0x%x", w->start_flags, t->exp_flags); return 0; }
		if (w->start_active != t->exp_active) { snprintf(why, sizeof(why), "active flag %d, expected %d", w->start_active, t->exp_active); return 0; }
		if (w->start_dwell != t->dwell) { snprintf(why, sizeof(why), "dwell %d handed on, expected %d", w->start_dwell, t->dwell); return 0; }
		if (t->exp_active && strcmp(w->start_ssid, "BackhaulNet") != 0) { snprintf(why, sizeof(why), "probe ssid '%s', expected the STA vap's 'BackhaulNet'", w->start_ssid); return 0; }
	}
	return 1;
}

/* poison the unused tails, call the handler, unpoison -- returns what wifi_startNeighborScan returned */
int test_wifi_startNeighborScan(const hwr_wsn_case_t *t, int idx, UINT *list)
{
	poison(1, t);
	int ret = wifi_startNeighborScan(idx, (wifi_neighborScanMode_t)t->mode, t->dwell, t->chan_num, list);
	poison(0, t);
	return ret;
}

static int run_one(hwr_wsn_case_t *test)
{
	int idx = resolve_index(test->ap_index);
	wsn_interface_t *si = construct_wifi_startNeighborScan_input(test, idx);
	UINT *list = test->list_null ? NULL : list_slab;

	printf("--- Running Test: %s ---\n", test->test_name);
	why[0] = 0;
	int ret = test_wifi_startNeighborScan(test, idx, list);
	int ok = check(test, ret, si);

	hwr_wsn_cleanup_filter(si);
	if (ok) {
		printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
	} else {
		printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
	}
	printf("------------------------------------------------------------------------------------------------------------------------------\n");
	return ok;
}

extern "C" void run_all_tests_wifi_startNeighborScan(void)
{
	int pass = 0, fail = 0;

	/* normal rows first, crash_* rows last: on the unfixed function the first crash aborts the run, so every other row has already reported */
	for (int last = 0; last < 2; last++)
		for (int i = 0; wifi_startNeighborScan_suite[i].test_name != NULL; i++) {
			if (wifi_startNeighborScan_suite[i].forked != last) continue;
			if (run_one(&wifi_startNeighborScan_suite[i])) pass++; else fail++;
		}
	printf("\nwifi_startNeighborScan: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
