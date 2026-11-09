/*
 * TEST RUNNER: wifi_setApRetrylimit_test
 *
 * priv is the only memory the function could touch.  The runner owns a 64-byte slab (hwr_srl_priv, preset to 0xA5) and POISONS ALL of it during the
 * call (mode 1): any read or write of priv aborts under ASan.  The guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.
 * After the calls it checks the return value (0), that the slab, the guard slab and the whole log are unchanged (the function does not log).
 */
#include <stdio.h>
#include <string.h>
#include "hwr_srl.h"
#include <sanitizer/asan_interface.h>

static unsigned char hwr_srl_priv[64];
static char hwr_srl_log_before[HWR_LOG_SZ];

static void poison(int on, const hwr_srl_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->priv_mode == 1) fn(hwr_srl_priv, sizeof(hwr_srl_priv));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what wifi_setApRetrylimit returned (last call) */
static int test_wifi_setApRetrylimit(const hwr_srl_case_t *t)
{
	void *priv = t->priv_mode == 0 ? NULL : t->priv_mode == 1 ? (void *)hwr_srl_priv : (void *)(unsigned long)0xdeadbeefUL;
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_wifi_setApRetrylimit(priv);
	poison(0, t);
	return ret;
}

static int check(const hwr_srl_case_t *t, int ret, char *why, size_t wn)
{
	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (size_t k = 0; k < sizeof(hwr_srl_priv); k++) if (hwr_srl_priv[k] != 0xA5) { snprintf(why, wn, "priv byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, hwr_srl_log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_setApRetrylimit(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_setApRetrylimit_suite[i].test_name != NULL; i++) {
		hwr_srl_case_t *test = &wifi_setApRetrylimit_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(hwr_srl_log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_srl_priv, 0xA5, sizeof(hwr_srl_priv));
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_wifi_setApRetrylimit(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_setApRetrylimit: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
