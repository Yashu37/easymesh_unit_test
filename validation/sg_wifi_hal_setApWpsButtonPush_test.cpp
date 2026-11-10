/*
 * TEST RUNNER: sg_wifi_hal_setApWpsButtonPush_test
 *
 * test_sg_wifi_hal_setApWpsButtonPush() POISONS what the function must not touch (the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ)), calls the handler and
 * unpoisons; run_all_tests compares the result.  Checks: return value 0; the callee was called exactly once per call with the index converted to unsigned; the log holds
 * the "WPS Push Button for radio index <n>" line (bounded to the log slot); the guard slab is untouched.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wpb.h"
#include <sanitizer/asan_interface.h>

static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_setApWpsButtonPush(const hwr_wpb_case_t *t)
{
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_sg_wifi_hal_setApWpsButtonPush(t->ap_index);
	poison(0);
	return ret;
}

static int check(const hwr_wpb_case_t *t, int ret)
{
	char want[64];

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (hwr_wpb_world.calls != t->calls) { snprintf(why, sizeof(why), "wps_pbc called %d times, expected %d", hwr_wpb_world.calls, t->calls); return 0; }
	if (hwr_wpb_world.last_index != (unsigned int)t->ap_index) { snprintf(why, sizeof(why), "wps_pbc got %u, expected %u", hwr_wpb_world.last_index, (unsigned int)t->ap_index); return 0; }
	snprintf(want, sizeof(want), "radio index %d", t->ap_index);
	if (t->prefill + 1 < HWR_LOG_USE - 60 && strstr(hwr_log_buf, want) == NULL) { snprintf(why, sizeof(why), "log line with \"%s\" missing", want); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_setApWpsButtonPush(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_setApWpsButtonPush_suite[i].test_name != NULL; i++) {
		hwr_wpb_case_t *test = &sg_wifi_hal_setApWpsButtonPush_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_wpb_world, 0, sizeof(hwr_wpb_world));
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_sg_wifi_hal_setApWpsButtonPush(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_setApWpsButtonPush: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
