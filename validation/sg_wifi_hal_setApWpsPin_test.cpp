/*
 * TEST RUNNER: sg_wifi_hal_setApWpsPin_test
 *
 * test_sg_wifi_hal_setApWpsPin() POISONS what the function must not touch (the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ)), calls the handler and unpoisons.
 * The pin is a heap string of exactly the requested length, so any read past its NUL aborts under ASan.  Checks: return value (-1 for a NULL pin, otherwise the callee's value
 * unchanged); the callee is not called for a NULL pin, and is called once per call with the same pointer and the index as unsigned otherwise; the "WPS Pin is NULL" log appears
 * exactly for a NULL pin; the guard slab is untouched.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wpp.h"
#include <sanitizer/asan_interface.h>

static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_setApWpsPin(const hwr_wpp_case_t *t, char *pin)
{
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_sg_wifi_hal_setApWpsPin(t->ap_index, pin);
	poison(0);
	return ret;
}

static int check(const hwr_wpp_case_t *t, const char *pin, int ret)
{
	int is_null = t->pin_len == -1;
	int has = strstr(hwr_log_buf, "WPS Pin is NULL") != NULL;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (is_null && hwr_wpp_world.calls != 0) { snprintf(why, sizeof(why), "callee called %d times for a NULL pin", hwr_wpp_world.calls); return 0; }
	if (!is_null) {
		if (hwr_wpp_world.calls != t->calls) { snprintf(why, sizeof(why), "callee called %d times, expected %d", hwr_wpp_world.calls, t->calls); return 0; }
		if (hwr_wpp_world.last_pin != pin) { snprintf(why, sizeof(why), "callee got a different pin pointer"); return 0; }
		if (hwr_wpp_world.last_index != (unsigned int)t->ap_index) { snprintf(why, sizeof(why), "callee got index %u, expected %u", hwr_wpp_world.last_index, (unsigned int)t->ap_index); return 0; }
	}
	if (is_null != has && t->prefill < 200) { snprintf(why, sizeof(why), "NULL-pin log %s, expected %s", has ? "present" : "missing", is_null ? "present" : "absent"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_setApWpsPin(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_setApWpsPin_suite[i].test_name != NULL; i++) {
		hwr_wpp_case_t *test = &sg_wifi_hal_setApWpsPin_suite[i];
		char *pin = NULL;

		printf("--- Running Test: %s ---\n", test->test_name);

		if (test->pin_len == -2) pin = strdup(test->pin_text);
		else if (test->pin_len >= 0) { pin = (char *)malloc(test->pin_len + 1); for (int k = 0; k < test->pin_len; k++) pin[k] = '0' + (k % 10); pin[test->pin_len] = '\0'; }
		memset(&hwr_wpp_world, 0, sizeof(hwr_wpp_world));
		hwr_wpp_world.ret = test->callee_ret;
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_sg_wifi_hal_setApWpsPin(test, pin);

		if (check(test, pin, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		free(pin);
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_setApWpsPin: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
