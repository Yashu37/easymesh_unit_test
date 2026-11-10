/*
 * TEST RUNNER: sg_wifi_hal_connect_test
 *
 * test_sg_wifi_hal_connect() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots beyond the existing ones, the union (backhaul / hostapd data) and
 * the scan list of every interface except the addressed STA VAP, the scan entries beyond the addressed interface's list, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The
 * runner's bss argument (a stack copy) is read by the function and stays readable.  run_all_tests compares the result with a reference model of the CORRECT behaviour: NULL bss -> -4; an
 * unknown VAP -> -1; an AP VAP -> -4; otherwise the explicit bss (non-zero bssid) or the strongest scan entry with the VAP's SSID (whatever its rssi; none -> -1 and no connect) is stored as the
 * backhaul, nl80211_connect_sta runs once per call and its failure gives -1.  The backhaul of an untouched interface keeps its 0xCC fill, the scan-list mutex is released and the guard slab
 * stays unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_whc.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static wifi_bss_info_t bss_arg;

static int exists(const hwr_whc_case_t *t) { return t->vap_index >= 0 && (unsigned)t->vap_index < t->n_if; }
static int is_sta(const hwr_whc_case_t *t, int k) { return (t->sta_mask >> k) & 1; }
static int calls_of(const hwr_whc_case_t *t) { return t->calls ? t->calls : 1; }

static void poison(int on, const hwr_whc_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	int tgt = exists(t) && is_sta(t, t->vap_index) ? t->vap_index : -1;

	for (unsigned i = t->n_if; i < HWR_WHC_MAXI; i++) fn(&hwr_whc_world.ifs[i], sizeof(hwr_whc_world.ifs[i]));
	for (unsigned i = 0; i < t->n_if; i++) {
		if ((int)i == tgt) {
			for (unsigned k = t->n_scan; k < HWR_WHC_MAXS; k++) fn(&hwr_whc_world.scan[i][k], sizeof(hwr_whc_world.scan[i][k]));
		} else {
			fn(&hwr_whc_world.ifs[i].u, sizeof(hwr_whc_world.ifs[i].u));
			fn(hwr_whc_world.scan[i], sizeof(hwr_whc_world.scan[i]));
		}
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_connect(const hwr_whc_case_t *t)
{
	poison(1, t);
	for (int i = 0; i < calls_of(t); i++) ret_val = hwr_sg_wifi_hal_connect(t->vap_index, t->bss_mode == 0 ? NULL : &bss_arg);
	poison(0, t);
}

static const char *vap_ssid(const hwr_whc_case_t *t) { return t->ignite ? "Repurposed" : t->empty_ssid ? "" : "HomeNet"; }
static const char *entry_ssid(const hwr_whc_case_t *t, int k)
{
	if (!((t->match_mask >> k) & 1)) return "Other";
	return t->ignite ? (t->ignite_match ? "Repurposed" : "HomeNet") : t->empty_ssid ? "" : "HomeNet";
}

static int check(const hwr_whc_case_t *t)
{
	const hwr_whc_world_t *w = &hwr_whc_world;
	int want_ret, want_connect = 0; const wifi_bss_info_t *src = NULL;

	if (t->bss_mode == 0) want_ret = WIFI_HAL_INVALID_ARGUMENTS;
	else if (!exists(t)) want_ret = RETURN_ERR;
	else if (!is_sta(t, t->vap_index)) want_ret = WIFI_HAL_INVALID_ARGUMENTS;
	else if (t->bss_mode == 1) { src = &bss_arg; want_connect = 1; want_ret = t->connect_ret ? RETURN_ERR : RETURN_OK; }
	else {
		int best = -1;
		for (unsigned k = 0; k < t->n_scan; k++)
			if (strcmp(entry_ssid(t, k), vap_ssid(t)) == 0 && (best < 0 || t->rssi[k] > t->rssi[best])) best = k;
		if (best < 0) want_ret = RETURN_ERR;
		else { src = &w->scan[t->vap_index][best]; want_connect = 1; want_ret = t->connect_ret ? RETURN_ERR : RETURN_OK; }
	}
	if (ret_val != want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want_ret); return 0; }
	if (w->connect_calls != want_connect * calls_of(t)) { snprintf(why, sizeof(why), "nl80211_connect_sta ran %d times, expected %d", w->connect_calls, want_connect * calls_of(t)); return 0; }
	if (want_connect) {
		wifi_interface_info_t *f = (wifi_interface_info_t *)&w->ifs[t->vap_index];
		if (w->connect_if != f) { snprintf(why, sizeof(why), "connect got a different interface"); return 0; }
		if (memcmp(&f->u.sta.backhaul, src, sizeof(wifi_bss_info_t)) != 0) { snprintf(why, sizeof(why), "backhaul bssid %02x:%02x, expected %02x:%02x", f->u.sta.backhaul.bssid[0], f->u.sta.backhaul.bssid[1], src->bssid[0], src->bssid[1]); return 0; }
	}
	for (unsigned i = 0; i < t->n_if; i++) {
		if (!is_sta(t, i)) continue;
		wifi_interface_info_t *f = (wifi_interface_info_t *)&w->ifs[i];
		if (!(want_connect && (int)i == t->vap_index) && f->u.sta.backhaul.bssid[0] != 0xCC) { snprintf(why, sizeof(why), "backhaul of interface %u was modified", i); return 0; }
		if (pthread_mutex_trylock(&f->scan_info_mutex) != 0) { snprintf(why, sizeof(why), "scan_info_mutex of interface %u left locked", i); return 0; }
		pthread_mutex_unlock(&f->scan_info_mutex);
	}
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_whc_case_t *t)
{
	hwr_whc_world_t *w = &hwr_whc_world;

	memset(w, 0, sizeof(*w));
	w->num_ifs = t->n_if; w->connect_ret = t->connect_ret;
	memset(&bss_arg, 0x5A, sizeof(bss_arg));
	{ unsigned char b[6] = { 0xAA, 1, 2, 3, 4, 5 }; memcpy(bss_arg.bssid, b, 6); }
	if (t->bss_mode == 2) memset(bss_arg.bssid, 0, 6);
	for (unsigned i = 0; i < HWR_WHC_MAXI; i++) {
		wifi_interface_info_t *f = &w->ifs[i];
		f->vap_info.vap_index = i;
		f->vap_info.vap_mode = (i < t->n_if && is_sta(t, i)) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		pthread_mutex_init(&f->scan_info_mutex, NULL);
		f->scan_info_map = &w->maps[i];
		if (i < t->n_if && !is_sta(t, i)) { memset(&f->u, 0xEE, sizeof(f->u)); continue; }
		memset(&f->u.sta.backhaul, 0xCC, sizeof(f->u.sta.backhaul));
		snprintf(f->vap_info.u.sta_info.ssid, sizeof(f->vap_info.u.sta_info.ssid), "%s", t->empty_ssid ? "" : "HomeNet");
		snprintf(f->vap_info.u.sta_info.repurposed_ssid, sizeof(f->vap_info.u.sta_info.repurposed_ssid), "Repurposed");
		f->vap_info.u.sta_info.ignite_enabled = t->ignite;
		for (unsigned k = 0; k < HWR_WHC_MAXS; k++) {
			wifi_bss_info_t *e = &w->scan[i][k];
			memset(e, 0, sizeof(*e));
			e->bssid[0] = 0xB0; e->bssid[1] = (unsigned char)k; e->bssid[2] = (unsigned char)i;
			snprintf(e->ssid, sizeof(e->ssid), "%s", entry_ssid(t, k));
			e->rssi = t->rssi[k];
			if (k < t->n_scan) w->maps[i].items[w->maps[i].n++] = e;
		}
	}
}

extern "C" void run_all_tests_sg_wifi_hal_connect(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_connect_suite[i].test_name != NULL; i++) {
			hwr_whc_case_t *test = &sg_wifi_hal_connect_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_log_buf, 'x', test->prefill);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_connect(test);

			if (check(test)) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_connect: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
