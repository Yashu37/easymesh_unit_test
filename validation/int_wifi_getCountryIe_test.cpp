/*
 * TEST RUNNER: int_wifi_getCountryIe_test
 *
 * Same shape as the other *_test.cpp runners: test_int_wifi_getCountryIe() POISONS what the function must not touch, calls the handler
 * and unpoisons; run_all_tests compares the result.  The runner owns the output slot: a 24-byte canary slab (0x5A) with the 1-byte BOOL at offset 8, like a
 * member inside a larger struct.  During the call it POISONS the WHOLE slab (the stub must neither read nor write the BOOL: any access aborts under ASan), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The BOOL itself holds a stale value
 * (preset, never 0).  Checks: return value (WIFI_HAL_ERROR, the stub's "unsupported" answer), *enabled == expected_val (the stale value: the stub reports "unsupported" and writes nothing) (the stub must leave the output alone), the canary bytes around the int unchanged, the guard slab unchanged and the log
 * untouched.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_ice.h"
#include <sanitizer/asan_interface.h>

#define OFF 8
static unsigned char slab[24];
static int slab_in_use;
static char why[200];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (slab_in_use) fn(&slab[0], sizeof(slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_int_wifi_getCountryIe(const hwr_ice_case_t *t)
{
	BOOL *out = t->out_mode ? (BOOL *)&slab[OFF] : NULL;
	int ret = 0;

	slab_in_use = t->out_mode;
	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_int_wifi_getCountryIe(t->ap_index, out);
	poison(0);
	return ret;
}

static int check(const hwr_ice_case_t *t, int ret)
{
	unsigned char got;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (int k = 0; k < (int)sizeof(slab); k++)
		if ((k < OFF || k >= OFF + (int)sizeof(BOOL)) && slab[k] != 0x5A) { snprintf(why, sizeof(why), "canary byte %d modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	for (int k = 0; k < HWR_LOG_SZ; k++) if (hwr_log_buf[k] != 0) { snprintf(why, sizeof(why), "the log was modified"); return 0; }
	if (t->out_mode) {
		memcpy(&got, &slab[OFF], sizeof(got));
		if (got != (unsigned char)t->expected_val) { snprintf(why, sizeof(why), "*enabled = %d, expected %d (it must stay %d)", (int)got, t->expected_val, t->preset); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_int_wifi_getCountryIe(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; int_wifi_getCountryIe_suite[i].test_name != NULL; i++) {
		hwr_ice_case_t *test = &int_wifi_getCountryIe_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		memset(slab, 0x5A, sizeof(slab));
		slab[OFF] = (unsigned char)test->preset;

		why[0] = 0;
		int ret = test_int_wifi_getCountryIe(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getCountryIe (intel): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
