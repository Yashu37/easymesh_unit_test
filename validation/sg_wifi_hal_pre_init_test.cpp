/*
 * TEST RUNNER: sg_wifi_hal_pre_init_test
 *
 * test_sg_wifi_hal_pre_init() POISONS what the function must not touch (the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ)), calls the handler and unpoisons;
 * run_all_tests compares the result.  Checks: return value 0; the hook getter was called once per call; the hook ran once per call when present and never when absent; the
 * "platfrom pre init" log line is present exactly when the hook exists (while there is room in the log slot); the guard slab is untouched.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wpi.h"
#include <sanitizer/asan_interface.h>

static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_pre_init(const hwr_wpi_case_t *t)
{
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_sg_wifi_hal_pre_init();
	poison(0);
	return ret;
}

static int check(const hwr_wpi_case_t *t, int ret)
{
	int want_hook = t->hook_present ? t->calls : 0;
	int has = strstr(hwr_log_buf, "pre init") != NULL;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (hwr_wpi_world.getter_calls != t->calls) { snprintf(why, sizeof(why), "getter called %d times, expected %d", hwr_wpi_world.getter_calls, t->calls); return 0; }
	if (hwr_wpi_world.hook_calls != want_hook) { snprintf(why, sizeof(why), "hook ran %d times, expected %d", hwr_wpi_world.hook_calls, want_hook); return 0; }
	if (t->prefill < 200 && has != (t->hook_present != 0)) { snprintf(why, sizeof(why), "pre-init log %s, expected %s", has ? "present" : "absent", t->hook_present ? "present" : "absent"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_pre_init(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_pre_init_suite[i].test_name != NULL; i++) {
		hwr_wpi_case_t *test = &sg_wifi_hal_pre_init_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_wpi_world, 0, sizeof(hwr_wpi_world));
		hwr_wpi_world.hook_present = test->hook_present;
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_sg_wifi_hal_pre_init(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_pre_init: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
