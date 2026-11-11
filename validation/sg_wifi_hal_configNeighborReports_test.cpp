/*
 * TEST RUNNER: sg_wifi_hal_configNeighborReports_test
 *
 * test_sg_wifi_hal_configNeighborReports() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots other than the addressed one (all of them when no interface /
 * STA mode makes the call fail early, except the STA one is only read), conf->radio_measurements[1..4] and the conf members before / after the written ones, the interface pad bytes, the guard slab and the
 * log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the state with a reference model of the CORRECT behaviour (see the construct file): return value, activation flags, conf->bss_transition,
 * radio_measurements[0] bit 1 set / cleared with the rest kept, auto-response flag, the lock released, guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wcn.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;

static int noif(const hwr_wcn_case_t *t) { return t->apIndex >= HWR_WCN_MAXI; }
static int fails(const hwr_wcn_case_t *t) { return noif(t) || t->vap_sta; }

static void poison(int on, const hwr_wcn_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wcn_world_t *w = &hwr_wcn_world;

	for (int i = 0; i < HWR_WCN_MAXI; i++) if (noif(t) || i != (int)t->apIndex) fn(&w->ifs[i], sizeof(w->ifs[i]));
	if (!noif(t)) {
		wifi_interface_info_t *f = &w->ifs[t->apIndex];
		fn(f->pad, sizeof(f->pad));
		if (!t->vap_sta) {
			fn(&f->u.ap.conf.before, sizeof(f->u.ap.conf.before));
			fn(&f->u.ap.conf.radio_measurements[1], 4);
			fn(&f->u.ap.conf.after, sizeof(f->u.ap.conf.after));
		}
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_configNeighborReports(const hwr_wcn_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_configNeighborReports(t->apIndex, t->enable != 0, t->auto_resp != 0);
	poison(0, t);
}

static int check(const hwr_wcn_case_t *t)
{
	const hwr_wcn_world_t *w = &hwr_wcn_world;
	int want_ret = fails(t) ? RETURN_ERR : RETURN_OK;

	if (ret_val != want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want_ret); return 0; }
	if (!noif(t)) {
		const wifi_interface_info_t *f = &w->ifs[t->apIndex];
		int en = fails(t) ? t->old_enable : t->enable, au = fails(t) ? t->old_auto : t->auto_resp;
		if (f->vap_info.u.bss_info.nbrReportActivated != en || f->vap_info.u.bss_info.bssTransitionActivated != en) { snprintf(why, sizeof(why), "activation flags %d/%d, expected %d", f->vap_info.u.bss_info.nbrReportActivated, f->vap_info.u.bss_info.bssTransitionActivated, en); return 0; }
		if (f->wnm_bss_trans_query_auto_resp != au) { snprintf(why, sizeof(why), "auto response %d, expected %d", f->wnm_bss_trans_query_auto_resp, au); return 0; }
		if (!t->vap_sta) {
			const struct hostapd_bss_config *c = &f->u.ap.conf;
			unsigned want_rm = fails(t) ? t->rm0 : (t->enable ? (t->rm0 | 0x02) : (t->rm0 & ~0x02u));
			if (c->bss_transition != en) { snprintf(why, sizeof(why), "bss_transition %d, expected %d", c->bss_transition, en); return 0; }
			if (c->radio_measurements[0] != (u8)want_rm) { snprintf(why, sizeof(why), "radio_measurements[0] 0x%x, expected 0x%x", c->radio_measurements[0], want_rm); return 0; }
			for (int k = 1; k < 5; k++) if (c->radio_measurements[k] != (u8)(0xA0 + k)) { snprintf(why, sizeof(why), "radio_measurements[%d] modified", k); return 0; }
			if (c->before != 0x1234 || c->after != 0x5678) { snprintf(why, sizeof(why), "neighbouring conf fields modified"); return 0; }
		}
	}
	{
		pthread_mutex_t *m = (pthread_mutex_t *)&w->hal.hapd_lock;
		if (pthread_mutex_trylock(m) != 0) { snprintf(why, sizeof(why), "hapd_lock still locked"); return 0; }
		pthread_mutex_unlock(m);
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wcn_case_t *t)
{
	hwr_wcn_world_t *w = &hwr_wcn_world;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	for (int i = 0; i < HWR_WCN_MAXI; i++) {
		wifi_interface_info_t *f = &w->ifs[i];
		f->vap_info.vap_mode = (i == (int)t->apIndex && t->vap_sta) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		f->vap_info.u.bss_info.nbrReportActivated = t->old_enable; f->vap_info.u.bss_info.bssTransitionActivated = t->old_enable;
		f->wnm_bss_trans_query_auto_resp = t->old_auto;
		if (f->vap_info.vap_mode == wifi_vap_mode_ap) {
			f->u.ap.conf.before = 0x1234; f->u.ap.conf.after = 0x5678; f->u.ap.conf.bss_transition = t->old_enable;
			f->u.ap.conf.radio_measurements[0] = (u8)t->rm0;
			for (int k = 1; k < 5; k++) f->u.ap.conf.radio_measurements[k] = (u8)(0xA0 + k);
		}
	}
}

extern "C" void run_all_tests_sg_wifi_hal_configNeighborReports(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_configNeighborReports_suite[i].test_name != NULL; i++) {
			hwr_wcn_case_t *test = &sg_wifi_hal_configNeighborReports_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_configNeighborReports(test);

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
	printf("\nwifi_hal_configNeighborReports: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
