/*
 * TEST RUNNER: wifi_getApAssociatedClientDiagnosticResult_test
 *
 * Same shape as the other *_test.cpp runners: test_wifi_getApAssociatedClientDiagnosticResult() POISONS what the function must not touch, calls the
 * handler and unpoisons; run_all_tests compares the result.  The runner owns a 64-byte key slab and a wifi_associated_dev3_t slab, both preset to 0xA5.
 * In pointer mode 1 the WHOLE slab is POISONED during the call: any read of key or any read / write of *assoc aborts under ASan.  The guard slab and
 * the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.  Checks: return value (WIFI_HAL_ERROR, the stub's "unsupported" answer), both slabs
 * unchanged, guard slab unchanged and the whole log unchanged (the function does not log).
 */
#include <stdio.h>
#include <string.h>
#include "hwr_gcl.h"
#include <sanitizer/asan_interface.h>

static unsigned char key_slab[64];
static unsigned char assoc_slab[sizeof(wifi_associated_dev3_t)];
static char log_before[HWR_LOG_SZ];

static void poison(int on, const hwr_gcl_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->key_mode == 1) fn(key_slab, sizeof(key_slab));
	if (t->assoc_mode == 1) fn(assoc_slab, sizeof(assoc_slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void *ptr_of(int mode, void *slab) { return mode == 0 ? NULL : mode == 1 ? slab : (void *)(unsigned long)0xdeadbeefUL; }

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_wifi_getApAssociatedClientDiagnosticResult(const hwr_gcl_case_t *t)
{
	char *key = (char *)ptr_of(t->key_mode, key_slab);
	wifi_associated_dev3_t *assoc = (wifi_associated_dev3_t *)ptr_of(t->assoc_mode, assoc_slab);
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_wifi_getApAssociatedClientDiagnosticResult(t->ap_index, key, assoc);
	poison(0, t);
	return ret;
}

static int check(const hwr_gcl_case_t *t, int ret, char *why, size_t wn)
{
	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (size_t k = 0; k < sizeof(key_slab); k++) if (key_slab[k] != 0xA5) { snprintf(why, wn, "key byte %zu modified", k); return 0; }
	for (size_t k = 0; k < sizeof(assoc_slab); k++) if (assoc_slab[k] != 0xA5) { snprintf(why, wn, "assoc byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_getApAssociatedClientDiagnosticResult(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_getApAssociatedClientDiagnosticResult_suite[i].test_name != NULL; i++) {
		hwr_gcl_case_t *test = &wifi_getApAssociatedClientDiagnosticResult_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(key_slab, 0xA5, sizeof(key_slab));
		memset(assoc_slab, 0xA5, sizeof(assoc_slab));
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_wifi_getApAssociatedClientDiagnosticResult(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_getApAssociatedClientDiagnosticResult: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
