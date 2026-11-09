/*
 * TEST RUNNER: int_wifi_getApInterworkingElement_test
 *
 * Same shape as the other *_test.cpp runners: test_int_wifi_getApInterworkingElement() POISONS what the function must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns the output slab: 16 canary bytes, the wifi_InterworkingElement_t filled with stale 0x5A
 * bytes, 16 canary bytes.  During the call it POISONS the WHOLE slab (the stub never reads or writes the structure, so any access aborts under ASan), the
 * guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  Checks: return value (WIFI_HAL_ERROR, the stub's "unsupported" answer), the structure and
 * the canary bytes unchanged, the guard slab unchanged, the whole log unchanged (the function does not log).
 */
#include <stdio.h>
#include <string.h>
#include "hwr_iie.h"
#include <sanitizer/asan_interface.h>

#define PAD 16
static unsigned char slab[PAD + sizeof(wifi_InterworkingElement_t) + PAD];
static char log_before[HWR_LOG_SZ];
static char why[200];

static void poison(int on, const hwr_iie_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->out_mode == 1) fn(slab, sizeof(slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static wifi_InterworkingElement_t *out_of(int mode)
{
	return mode == 0 ? NULL : mode == 1 ? (wifi_InterworkingElement_t *)&slab[PAD] : (wifi_InterworkingElement_t *)(unsigned long)0xdeadbeefUL;
}

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_int_wifi_getApInterworkingElement(const hwr_iie_case_t *t)
{
	wifi_InterworkingElement_t *out = out_of(t->out_mode);
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_int_wifi_getApInterworkingElement(t->ap_index, out);
	poison(0, t);
	return ret;
}

static int check(const hwr_iie_case_t *t, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (int k = 0; k < (int)sizeof(slab); k++)
		if (slab[k] != 0x5A) { snprintf(why, sizeof(why), "slab byte %d modified (%s)", k, (k < PAD || k >= PAD + (int)sizeof(wifi_InterworkingElement_t)) ? "canary" : "structure"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, sizeof(why), "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_int_wifi_getApInterworkingElement(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; int_wifi_getApInterworkingElement_suite[i].test_name != NULL; i++) {
		hwr_iie_case_t *test = &int_wifi_getApInterworkingElement_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		memset(slab, 0x5A, sizeof(slab));

		why[0] = 0;
		int ret = test_int_wifi_getApInterworkingElement(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getApInterworkingElement (intel): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
