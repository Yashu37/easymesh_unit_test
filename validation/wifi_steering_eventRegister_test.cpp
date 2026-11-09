/*
 * TEST RUNNER: wifi_steering_eventRegister_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_steering_eventRegister() POISONS what the function must not touch (the guard slab and the log
 * slot tail [HWR_LOG_USE, HWR_LOG_SZ)), calls the handler and unpoisons; run_all_tests compares the result.  The callback is the only other thing the
 * function receives: the runner's counting callback (mode 1) and the dangling pointer (mode 2) must never be called.  Checks: return value
 * (RETURN_OK), callback call count 0, guard slab unchanged and the whole log unchanged (the function does not log).
 */
#include <stdio.h>
#include <string.h>
#include "hwr_ser.h"
#include <sanitizer/asan_interface.h>

static int cb_calls;
static char log_before[HWR_LOG_SZ];

static void counting_cb(UINT steeringgroupIndex, wifi_steering_event_t *event) { (void)steeringgroupIndex; (void)event; cb_calls++; }

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what wifi_steering_eventRegister returned (last call) */
static int test_wifi_steering_eventRegister(const hwr_ser_case_t *t)
{
	wifi_steering_eventCB_t cb = t->cb_mode == 0 ? NULL : t->cb_mode == 1 ? counting_cb : (wifi_steering_eventCB_t)(unsigned long)0xdeadbeefUL;
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_wifi_steering_eventRegister(cb);
	poison(0);
	return ret;
}

static int check(const hwr_ser_case_t *t, int ret, char *why, size_t wn)
{
	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (cb_calls != 0) { snprintf(why, wn, "the callback was called %d time(s)", cb_calls); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_steering_eventRegister(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_steering_eventRegister_suite[i].test_name != NULL; i++) {
		hwr_ser_case_t *test = &wifi_steering_eventRegister_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		cb_calls = 0;
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_wifi_steering_eventRegister(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_steering_eventRegister: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
