/*
 * TEST RUNNER: sg_wifi_hal_sm_deinit_test
 *
 * test_sg_wifi_hal_sm_deinit() POISONS what the function must not touch, calls the handler and unpoisons: the stand-in interface slots beyond the existing ones, the union of every AP VAP
 * (the function must not read hostapd data as a STA pointer), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The wpa_sm / eapol objects are heap blocks allocated by the
 * runner and freed by the deinit stubs, so ASan reports a double free, a use after free or a leak.  run_all_tests compares the result with the CORRECT behaviour: a STA VAP with a wpa_sm ->
 * eapol_sm_deinit once with its eapol, wpa_sm_deinit once with its wpa_sm, both pointers cleared, return 0 (a repeated call does nothing more); a STA VAP without a wpa_sm -> 0 and nothing
 * deinitialised; an AP or unknown VAP -> -1 and nothing deinitialised.  The guard slab stays unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wsd.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static struct wpa_sm *sm0[HWR_WSD_MAXI];
static struct eapol_sm *ea0[HWR_WSD_MAXI];

static int exists(const hwr_wsd_case_t *t) { return t->vap_index >= 0 && (unsigned)t->vap_index < t->n_if; }
static int is_sta(const hwr_wsd_case_t *t, int k) { return (t->sta_mask >> k) & 1; }

static void poison(int on, const hwr_wsd_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	for (unsigned i = t->n_if; i < HWR_WSD_MAXI; i++) fn(&hwr_wsd_world.ifs[i], sizeof(hwr_wsd_world.ifs[i]));
	for (unsigned i = 0; i < t->n_if; i++) if (!is_sta(t, i)) fn(&hwr_wsd_world.ifs[i].u, sizeof(hwr_wsd_world.ifs[i].u));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_sm_deinit(const hwr_wsd_case_t *t)
{
	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret_val = hwr_sg_wifi_hal_sm_deinit(t->vap_index);
	poison(0, t);
}

static int check(const hwr_wsd_case_t *t)
{
	const hwr_wsd_world_t *w = &hwr_wsd_world;
	int ok_sta = exists(t) && is_sta(t, t->vap_index);
	int has_sm = ok_sta && ((t->sm_mask >> t->vap_index) & 1);
	int want_ret = ok_sta ? 0 : -1;

	if (ret_val != want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want_ret); return 0; }
	if (w->sm_calls != has_sm) { snprintf(why, sizeof(why), "wpa_sm_deinit ran %d times, expected %d", w->sm_calls, has_sm); return 0; }
	if (w->eapol_calls != has_sm) { snprintf(why, sizeof(why), "eapol_sm_deinit ran %d times, expected %d", w->eapol_calls, has_sm); return 0; }
	if (has_sm) {
		if (w->sm_arg != sm0[t->vap_index]) { snprintf(why, sizeof(why), "wpa_sm_deinit got a different wpa_sm"); return 0; }
		if (w->eapol_arg != ea0[t->vap_index]) { snprintf(why, sizeof(why), "eapol_sm_deinit got a different eapol"); return 0; }
		if (w->ifs[t->vap_index].u.sta.wpa_sm != NULL) { snprintf(why, sizeof(why), "wpa_sm pointer not cleared"); return 0; }
	}
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

/* free what the function (correctly) left alone: the runner owns every object the deinit stubs did not free */
static void cleanup(const hwr_wsd_case_t *t)
{
	const hwr_wsd_world_t *w = &hwr_wsd_world;

	for (unsigned i = 0; i < t->n_if; i++) {
		if (sm0[i] && w->sm_arg != sm0[i]) free(sm0[i]);
		if (ea0[i] && w->eapol_arg != ea0[i]) free(ea0[i]);
	}
}

static void setup(const hwr_wsd_case_t *t)
{
	hwr_wsd_world_t *w = &hwr_wsd_world;

	memset(w, 0, sizeof(*w));
	memset(sm0, 0, sizeof(sm0)); memset(ea0, 0, sizeof(ea0));
	w->num_ifs = t->n_if;
	for (unsigned i = 0; i < HWR_WSD_MAXI; i++) {
		w->ifs[i].vap_info.vap_index = i;
		w->ifs[i].vap_info.vap_mode = (i < t->n_if && is_sta(t, i)) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		if (i < t->n_if && !is_sta(t, i)) memset(&w->ifs[i].u, 0xEE, sizeof(w->ifs[i].u));
		if (i < t->n_if && is_sta(t, i) && ((t->sm_mask >> i) & 1)) {
			sm0[i] = (struct wpa_sm *)calloc(1, sizeof(struct wpa_sm));
			if (!t->no_eapol) { ea0[i] = (struct eapol_sm *)calloc(1, sizeof(struct eapol_sm)); sm0[i]->eapol = ea0[i]; }
			w->ifs[i].u.sta.wpa_sm = sm0[i];
		}
	}
}

extern "C" void run_all_tests_sg_wifi_hal_sm_deinit(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_sm_deinit_suite[i].test_name != NULL; i++) {
			hwr_wsd_case_t *test = &sg_wifi_hal_sm_deinit_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_log_buf, 'x', test->prefill);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_sm_deinit(test);

			int ok = check(test);
			cleanup(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_sm_deinit: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
