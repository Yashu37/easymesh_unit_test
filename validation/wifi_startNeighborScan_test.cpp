/*
 * TEST RUNNER: wifi_startNeighborScan_test
 *
 * The runner owns the whole world: the AP / STA / private interfaces, the radio, the hostapd channel table (a slab of 8 entries, 6 used) and the
 * caller's channel list (a slab of 16 UINTs of which exactly chan_num are valid).  During the call it POISONS the tail of the channel list
 * [chan_num, 16), the unused tail of the channel table, the whole guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ), so a read of a list entry
 * the caller did not pass, a read past the table or a log write past the slot aborts under ASan.  The scan_filter is filled with stale values before
 * the call (the function must clean it up) and freed afterwards.  Rows flagged `forked` crash the unfixed function (NULL chan_list, NULL hapd.iface):
 * they run in a child so the ASan report is visible but the run continues.
 * Checks: return value, scan_state afterwards, number of nl80211_start_scan / nl80211_get_scan_results / hash_map_cleanup calls, the frequency filter
 * (what nl80211 saw), the scan flags / active flag / dwell time / probe SSID handed to nl80211_start_scan (a STA scan carries the STA vap's SSID).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <initializer_list>
#include <sys/wait.h>
#include "hwr_wsn.h"
#include <sanitizer/asan_interface.h>

static unsigned int    list_slab[16];
static wsn_chan_t      chan_slab[8];
static wsn_hw_mode_t   mode_obj;
static wsn_hiface_t    hif_obj;
static wsn_interface_t ifA, ifP;
static wsn_radio_t     radio_obj;
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

static int resolve_index(int idx) { return idx == 1000 ? MAX_VAP : idx == 1001 ? MAX_VAP - 1 : idx; }

static wsn_interface_t *setup(const hwr_wsn_case_t *t, int idx)
{
	wsn_interface_t *si;
	static const wsn_chan_t table[6] = { {1, 2412, 0}, {6, 2437, 0}, {11, 2462, WSN_CHAN_DISABLED}, {36, 5180, 0}, {52, 5260, WSN_CHAN_DISABLED}, {100, 5500, 0} };

	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
	memset(&hwr_wsn_world, 0, sizeof(hwr_wsn_world));
	memset(&ifA, 0, sizeof(ifA)); memset(&ifP, 0, sizeof(ifP)); memset(&radio_obj, 0, sizeof(radio_obj));
	memset(list_slab, 0xA5, sizeof(list_slab));
	memset(chan_slab, 0, sizeof(chan_slab)); memcpy(chan_slab, table, sizeof(table));
	for (int i = 0; i < WSN_MAXL && (unsigned)i < t->chan_num; i++) list_slab[i] = t->list[i];

	mode_obj.num_channels = 6; mode_obj.channels = chan_slab;
	hif_obj.current_mode = (t->hapd_state == 2) ? &mode_obj : NULL;
	for (wsn_interface_t *p : { &ifA, &ifP }) {
		pthread_mutex_init(&p->scan_state_mutex, NULL);
		pthread_mutex_init(&p->scan_info_mutex, NULL);
		pthread_mutex_init(&p->scan_info_ap_mutex, NULL);
		p->vap_info.radio_index = 0;
		p->u.ap.hapd.iface = (t->hapd_state == 0) ? NULL : &hif_obj;
	}
	snprintf(ifA.name, sizeof(ifA.name), "wlan0.1"); snprintf(ifP.name, sizeof(ifP.name), "wlan0");
	ifA.vap_info.vap_mode = (t->vap_mode == 0) ? wifi_vap_mode_ap : wifi_vap_mode_sta;
	ifP.vap_info.vap_mode = wifi_vap_mode_ap;
	snprintf(ifA.vap_info.u.sta_info.ssid, sizeof(ifA.vap_info.u.sta_info.ssid), "BackhaulNet");
	snprintf(ifP.vap_info.u.sta_info.ssid, sizeof(ifP.vap_info.u.sta_info.ssid), "PrivateNet");
	snprintf(radio_obj.name, sizeof(radio_obj.name), "wlan0");
	radio_obj.oper_param.countryCode = t->country; radio_obj.oper_param.operatingClass = t->op_class; radio_obj.oper_param.channel = t->radio_channel;

	si = (t->has_priv == 2) ? &ifP : &ifA;
	si->scan_state = t->pre_state; si->scan_has_results = t->pre_results;
	si->scan_filter.values = (unsigned int *)malloc(3 * sizeof(unsigned int));
	si->scan_filter.values[0] = si->scan_filter.values[1] = si->scan_filter.values[2] = 7; si->scan_filter.num = 3;

	hwr_wsn_world.ap_iface = t->has_ap_iface ? &ifA : NULL; hwr_wsn_world.ap_vap_index = (unsigned)idx;
	hwr_wsn_world.radio = t->has_radio ? &radio_obj : NULL; hwr_wsn_world.radio_index = 0;
	hwr_wsn_world.priv_iface = (t->has_priv == 0) ? NULL : (t->has_priv == 1 ? &ifA : &ifP);
	hwr_wsn_world.nl_start_rc = t->nl_start_rc; hwr_wsn_world.nl_results_rc = t->nl_results_rc;
	return si;
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

static int run_case(const hwr_wsn_case_t *t)
{
	int idx = resolve_index(t->ap_index), ret = 0;
	wsn_interface_t *si = setup(t, idx);
	UINT *list = t->list_null ? NULL : list_slab;

	why[0] = 0;
	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1, t);
		pid = fork();
		if (pid == 0) {
			ret = wifi_startNeighborScan(idx, (wifi_neighborScanMode_t)t->mode, t->dwell, t->chan_num, list);
			poison(0, t);
			_exit(check(t, ret, si) ? 0 : 2);
		}
		waitpid(pid, &st, 0);
		poison(0, t);
		hwr_wsn_cleanup_filter(si);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1, t);
	ret = wifi_startNeighborScan(idx, (wifi_neighborScanMode_t)t->mode, t->dwell, t->chan_num, list);
	poison(0, t);
	int ok = check(t, ret, si);
	hwr_wsn_cleanup_filter(si);
	return ok;
}

extern "C" void run_all_tests_wifi_startNeighborScan(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_startNeighborScan_suite[i].test_name != NULL; i++) {
		hwr_wsn_case_t *test = &wifi_startNeighborScan_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_startNeighborScan: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
