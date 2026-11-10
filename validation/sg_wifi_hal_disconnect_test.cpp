/*
 * TEST RUNNER: sg_wifi_hal_disconnect_test
 *
 * test_sg_wifi_hal_disconnect() POISONS what the function must not touch, calls the handler and unpoisons: the stand-in interface slots beyond the existing ones, the union (STA data /
 * hostapd data) of every interface (the function only reads vap_info), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the result with the CORRECT
 * behaviour: a STA VAP -> nl80211_disconnect_sta once per call with that VAP's interface, return 0 (-1 when it fails); an AP VAP -> -4 and no disconnect; an unknown VAP -> -1 and no
 * disconnect.  The guard slab stays unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wdc.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;

static int exists(const hwr_wdc_case_t *t) { return t->vap_index >= 0 && (unsigned)t->vap_index < t->n_if; }
static int is_sta(const hwr_wdc_case_t *t, int k) { return (t->sta_mask >> k) & 1; }

static void poison(int on, const hwr_wdc_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	for (unsigned i = t->n_if; i < HWR_WDC_MAXI; i++) fn(&hwr_wdc_world.ifs[i], sizeof(hwr_wdc_world.ifs[i]));
	for (unsigned i = 0; i < t->n_if; i++) fn(&hwr_wdc_world.ifs[i].u, sizeof(hwr_wdc_world.ifs[i].u));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_disconnect(const hwr_wdc_case_t *t)
{
	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret_val = hwr_sg_wifi_hal_disconnect(t->vap_index);
	poison(0, t);
}

static int check(const hwr_wdc_case_t *t)
{
	const hwr_wdc_world_t *w = &hwr_wdc_world;
	int sta = exists(t) && is_sta(t, t->vap_index);
	int want_ret = !exists(t) ? RETURN_ERR : !sta ? WIFI_HAL_INVALID_ARGUMENTS : t->disc_ret ? RETURN_ERR : RETURN_OK;
	int want_calls = sta ? t->calls : 0;

	if (ret_val != want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want_ret); return 0; }
	if (w->disc_calls != want_calls) { snprintf(why, sizeof(why), "nl80211_disconnect_sta ran %d times, expected %d", w->disc_calls, want_calls); return 0; }
	if (sta && w->disc_if != &w->ifs[t->vap_index]) { snprintf(why, sizeof(why), "disconnect got a different interface"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_wdc_case_t *t)
{
	hwr_wdc_world_t *w = &hwr_wdc_world;

	memset(w, 0, sizeof(*w));
	w->num_ifs = t->n_if; w->disc_ret = t->disc_ret;
	for (unsigned i = 0; i < HWR_WDC_MAXI; i++) {
		w->ifs[i].vap_info.vap_index = i;
		w->ifs[i].vap_info.vap_mode = (i < t->n_if && is_sta(t, i)) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		memset(&w->ifs[i].u, 0xEE, sizeof(w->ifs[i].u));
	}
}

extern "C" void run_all_tests_sg_wifi_hal_disconnect(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_disconnect_suite[i].test_name != NULL; i++) {
			hwr_wdc_case_t *test = &sg_wifi_hal_disconnect_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_log_buf, 'x', test->prefill);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_disconnect(test);

			if (check(test)) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_disconnect: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
