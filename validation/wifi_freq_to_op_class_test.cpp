/*
 * TEST RUNNER: wifi_freq_to_op_class_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_freq_to_op_class() POISONS what the function must not touch (the guard slab and the log slot
 * tail [HWR_LOG_USE, HWR_LOG_SZ)), calls the handler and unpoisons; run_all_tests compares the result.  The function is pure (its two output bytes
 * op_class / channel are locals of the function), so the checks are: return value, guard slab unchanged, and the log: empty after a successful call,
 * and after a failed one holding the "Failed to get op class" line with the frequency printed as %d.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_fco.h"
#include <sanitizer/asan_interface.h>

static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what wifi_freq_to_op_class returned (last call) */
static UINT test_wifi_freq_to_op_class(const hwr_fco_case_t *t)
{
	UINT ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) {
		memset(hwr_log_buf, 0, HWR_LOG_USE);          /* the log sink is only written before the poison covers the tail */
		ret = hwr_wifi_freq_to_op_class(t->freq);
	}
	poison(0);
	return ret;
}

static int check(const hwr_fco_case_t *t, UINT ret)
{
	char want[64];

	if (ret != t->expected) { snprintf(why, sizeof(why), "returned %u, expected %u", ret, t->expected); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	for (int k = HWR_LOG_USE; k < HWR_LOG_SZ; k++) if (hwr_log_buf[k] != 0) { snprintf(why, sizeof(why), "log byte %d beyond the slot modified", k); return 0; }
	if (t->expected == (unsigned)RETURN_ERR) {
		snprintf(want, sizeof(want), "for freq : %d", (int)t->freq);
		if (strstr(hwr_log_buf, "Failed to get op class") == NULL || strstr(hwr_log_buf, want) == NULL) { snprintf(why, sizeof(why), "failure not logged with the frequency (log: '%s')", hwr_log_buf); return 0; }
	} else if (hwr_log_buf[0] != 0) { snprintf(why, sizeof(why), "unexpected log on success: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_freq_to_op_class(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_freq_to_op_class_suite[i].test_name != NULL; i++) {
		hwr_fco_case_t *test = &wifi_freq_to_op_class_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		why[0] = 0;
		UINT ret = test_wifi_freq_to_op_class(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%u, got=%u) %s =====\n", test->test_name, test->expected, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_freq_to_op_class: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
