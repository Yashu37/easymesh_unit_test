/*
 * TEST RUNNER: wifi_getDownStreamGroupAddress_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_getDownStreamGroupAddress() POISONS what the function must not touch, calls the handler
 * and unpoisons; run_all_tests compares the result.  The runner owns the output slot: a 24-byte canary slab (0x5A) with the 1-byte BOOL at offset 8, like a
 * member inside a larger struct.  During the call it POISONS the head [0, 8) and the tail [9, 24) of the slab (so a write of more than 1 byte or at a
 * wrong offset aborts under ASan), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The BOOL itself holds a stale value
 * (preset, never 0).  Checks: return value (WIFI_HAL_SUCCESS for a valid pointer, WIFI_HAL_ERROR for NULL), *disabled == expected_val after a
 * successful call (the original stub leaves the stale value), the canary bytes around the int unchanged, the guard slab unchanged and the log
 * untouched.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_gdg.h"
#include <sanitizer/asan_interface.h>

#define OFF 8
static unsigned char slab[24];
static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&slab[0], OFF);
	fn(&slab[OFF + sizeof(BOOL)], sizeof(slab) - OFF - sizeof(BOOL));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_wifi_getDownStreamGroupAddress(const hwr_gdg_case_t *t)
{
	BOOL *out = t->out_mode ? (BOOL *)&slab[OFF] : NULL;
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_wifi_getDownStreamGroupAddress(t->ap_index, out);
	poison(0);
	return ret;
}

static int check(const hwr_gdg_case_t *t, int ret)
{
	unsigned char got;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (int k = 0; k < (int)sizeof(slab); k++)
		if ((k < OFF || k >= OFF + (int)sizeof(BOOL)) && slab[k] != 0x5A) { snprintf(why, sizeof(why), "canary byte %d modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	for (int k = 0; k < HWR_LOG_SZ; k++) if (hwr_log_buf[k] != 0) { snprintf(why, sizeof(why), "the log was modified"); return 0; }
	if (t->out_mode) {
		memcpy(&got, &slab[OFF], sizeof(got));
		if (got != (unsigned char)t->expected_val) { snprintf(why, sizeof(why), "*disabled = %d, expected %d (the stale value %d was left unchanged)", (int)got, t->expected_val, t->preset); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_wifi_getDownStreamGroupAddress(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_getDownStreamGroupAddress_suite[i].test_name != NULL; i++) {
		hwr_gdg_case_t *test = &wifi_getDownStreamGroupAddress_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		memset(slab, 0x5A, sizeof(slab));
		slab[OFF] = (unsigned char)test->preset;

		why[0] = 0;
		int ret = test_wifi_getDownStreamGroupAddress(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getDownStreamGroupAddress: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
