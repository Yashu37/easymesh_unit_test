/*
 * TEST RUNNER: wifi_hal_setRadioStatsEnable_test
 *
 * The runner POISONS the runner-owned buffers, calls wifi_hal_setRadioStatsEnable(), UNPOISONS and checks
 * the return value and the log:
 *   hwr_guard_slab : [0, HWR_GUARD_SZ)            - a canary the function must never touch
 *   hwr_log_buf    : [HWR_LOG_USE, HWR_LOG_SZ)    - the unused part of the log slot
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "hwr_setRadioStatsEnable.h"
#include <sanitizer/asan_interface.h>

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static int run_case(const hwr_srse_case_t *t)
{
	int ok = 1;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

	for (int i = 0; i < t->calls; i++) {
		BOOL en = (BOOL)((t->check == 1 && (i & 1)) ? !t->enabled : t->enabled);
		poison_all(1);
		INT ret = hwr_wifi_hal_setRadioStatsEnable(t->radio_index, en);
		poison_all(0);
		if (ret != 0) { snprintf(why, sizeof(why), "call %d returned %d", i, ret); ok = 0; }
	}
	for (int i = 0; i < HWR_GUARD_SZ; i++) if (hwr_guard_slab[i] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", i); ok = 0; break; }
	if (t->check == 2 && (!strstr(hwr_log_buf, "wifi_hal_setRadioStatsEnable") || !strstr(hwr_log_buf, "Enter"))) { snprintf(why, sizeof(why), "log lacks function name / Enter: '%s'", hwr_log_buf); ok = 0; }
	if (t->check == 3 && !strstr(hwr_log_buf, "EMTPY FUNCTION")) { snprintf(why, sizeof(why), "log lacks the empty-function notice: '%s'", hwr_log_buf); ok = 0; }
	return ok;
}

extern "C" void run_all_tests_wifi_hal_setRadioStatsEnable(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_setRadioStatsEnable_suite[i].test_name != NULL; i++) {
		hwr_srse_case_t *test = &wifi_hal_setRadioStatsEnable_suite[i];

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
	printf("\nwifi_hal_setRadioStatsEnable: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
