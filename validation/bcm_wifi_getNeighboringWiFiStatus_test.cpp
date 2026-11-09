/*
 * TEST RUNNER: bcm_wifi_getNeighboringWiFiStatus_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_getNeighboringWiFiStatus_bcm() POISONS what the wrapper must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns the two output slots (a wifi_neighbor_ap2_t * slot and a UINT slot, with sentinel
 * values) and POISONS them (mode 1) together with the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) during the call: the wrapper only
 * forwards the pointers, so any read or write of the slots aborts under ASan.  Checks: the core stub was called once per call with the same
 * radio_index and pointers, the return value equals the core result, the error line is logged exactly when the core returned RETURN_ERR (and nothing
 * otherwise), the slots keep their sentinel values, the guard slab is unchanged.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_bgn.h"
#include <sanitizer/asan_interface.h>

static wifi_neighbor_ap2_t *array_slot;
static UINT size_slot;
static char log_before[HWR_LOG_SZ];
#define SENT_ARRAY ((wifi_neighbor_ap2_t *)0x1234)
#define SENT_SIZE 0xDEADu

static void poison(int on, const hwr_bgn_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->array_mode == 1) fn(&array_slot, sizeof(array_slot));
	if (t->size_mode == 1) fn(&size_slot, sizeof(size_slot));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void *ptr_of(int mode, void *slot) { return mode == 0 ? NULL : mode == 1 ? slot : (void *)(unsigned long)0xdeadbeefUL; }

/* poison, call, unpoison -- returns what the wrapper returned (last call) */
int test_wifi_getNeighboringWiFiStatus_bcm(const hwr_bgn_case_t *t, wifi_neighbor_ap2_t **pa, UINT *ps)
{
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_bcm_wifi_getNeighboringWiFiStatus(t->radio_index, pa, ps);
	poison(0, t);
	return ret;
}

static int check(const hwr_bgn_case_t *t, int ret, wifi_neighbor_ap2_t **pa, UINT *ps, char *why, size_t wn)
{
	const hwr_bgn_world_t *w = &hwr_bgn_world;
	int logged = strstr(hwr_log_buf + t->prefill, "wifi_hal_getNeighboringWiFiStatus failed") != NULL;
	int log_changed = memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0;

	if (ret != t->core_ret) { snprintf(why, wn, "returned %d, the core returned %d", ret, t->core_ret); return 0; }
	if (w->calls != t->calls) { snprintf(why, wn, "core called %d times, expected %d", w->calls, t->calls); return 0; }
	if (w->last_radio != t->radio_index || w->last_array != pa || w->last_size != ps) { snprintf(why, wn, "arguments not forwarded unchanged"); return 0; }
	if (t->core_ret == -1) {
		if (t->prefill + 70 < HWR_LOG_USE && !logged) { snprintf(why, wn, "RETURN_ERR not logged"); return 0; }
	} else if (log_changed) { snprintf(why, wn, "unexpected log output for core result %d", t->core_ret); return 0; }
	if (array_slot != SENT_ARRAY || size_slot != SENT_SIZE) { snprintf(why, wn, "output slots modified"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_getNeighboringWiFiStatus_bcm(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_getNeighboringWiFiStatus_bcm_suite[i].test_name != NULL; i++) {
		hwr_bgn_case_t *test = &wifi_getNeighboringWiFiStatus_bcm_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_bgn_world, 0, sizeof(hwr_bgn_world));
		hwr_bgn_world.ret = test->core_ret;
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		array_slot = SENT_ARRAY; size_slot = SENT_SIZE;

		wifi_neighbor_ap2_t **pa = (wifi_neighbor_ap2_t **)ptr_of(test->array_mode, &array_slot);
		UINT *ps = (UINT *)ptr_of(test->size_mode, &size_slot);
		int ret = test_wifi_getNeighboringWiFiStatus_bcm(test, pa, ps);

		if (check(test, ret, pa, ps, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->core_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getNeighboringWiFiStatus (broadcom): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
