/*
 * TEST RUNNER: rp_wifi_setRadioDfsAtBootUpEnable_test
 *
 * Same shape as the other *_test.cpp runners: test_rp_wifi_setRadioDfsAtBootUpEnable() POISONS what the function must not touch (the guard slab and the log
 * slot tail [HWR_LOG_USE, HWR_LOG_SZ)), calls the handler and unpoisons; run_all_tests compares the result.  The function takes only two scalars, so
 * the checks are: return value (WIFI_HAL_SUCCESS, the stub's answer), guard slab unchanged and the whole log unchanged (the function does
 * not log).
 */
#include <stdio.h>
#include <string.h>
#include "hwr_rdb.h"
#include <sanitizer/asan_interface.h>

static char log_before[HWR_LOG_SZ];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what wifi_setRadioDfsAtBootUpEnable returned (last call) */
static int test_rp_wifi_setRadioDfsAtBootUpEnable(const hwr_rdb_case_t *t)
{
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_rp_wifi_setRadioDfsAtBootUpEnable(t->radio_index, (BOOL)t->enable);
	poison(0);
	return ret;
}

static int check(const hwr_rdb_case_t *t, int ret, char *why, size_t wn)
{
	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_rp_wifi_setRadioDfsAtBootUpEnable(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; rp_wifi_setRadioDfsAtBootUpEnable_suite[i].test_name != NULL; i++) {
		hwr_rdb_case_t *test = &rp_wifi_setRadioDfsAtBootUpEnable_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_rp_wifi_setRadioDfsAtBootUpEnable(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_setRadioDfsAtBootUpEnable (raspberry-pi): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
