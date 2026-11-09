/*
 * TEST RUNNER: int_wifi_setApRetrylimit_test
 *
 * Same shape as the other *_test.cpp runners: test_int_wifi_setApRetrylimit() POISONS what the function must not touch, calls the handler and unpoisons;
 * run_all_tests compares the result.  priv is NULL, the runner's guard slab (fully POISONED during the call: the function only passes the pointer on, any
 * read or write aborts under ASan) or a dangling pointer.  During the call the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are POISONED.
 * Checks: return value; the vendor stub was called once per call with OUI_LTQ, the RETRY_LIMIT sub-command, the 8-byte payload {4, 7}, length 8, nested = -1, the
 * same priv (and never for a NULL priv); the log content (the failure line with the result; the error TEXT is not checked, see the note in the handler header); the guard slab is unchanged.
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "hwr_irl.h"
#include <sanitizer/asan_interface.h>

static char log_before[HWR_LOG_SZ];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void *priv_of(int mode) { return mode == 0 ? NULL : mode == 1 ? (void *)hwr_guard_slab : (void *)(unsigned long)0xdeadbeefUL; }

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_int_wifi_setApRetrylimit(const hwr_irl_case_t *t, void *priv)
{
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_int_wifi_setApRetrylimit(priv);
	poison(0);
	return ret;
}

static int check(const hwr_irl_case_t *t, int ret, void *priv, char *why, size_t wn)
{
	const hwr_irl_world_t *w = &hwr_irl_world;
	int expect_ret = t->priv_mode == 0 ? -1 : t->vendor_ret;
	int expect_calls = t->priv_mode == 0 ? 0 : t->calls;
	int text_ok = t->prefill + 200 < HWR_LOG_USE;            /* the line fits into the log slot */
	const char *l = hwr_log_buf + t->prefill;
	char want[128];

	if (ret != expect_ret) { snprintf(why, wn, "returned %d, expected %d", ret, expect_ret); return 0; }
	if (w->calls != expect_calls) { snprintf(why, wn, "vendor command sent %d times, expected %d", w->calls, expect_calls); return 0; }
	if (expect_calls) {
		static const int want_rl[2] = { 4, 7 };
		if (w->last_priv != priv) { snprintf(why, wn, "priv not passed on unchanged"); return 0; }
		if (w->last_oui != IRL_OUI_LTQ || w->last_subcmd != IRL_SUBCMD_RETRY_LIMIT) { snprintf(why, wn, "wrong OUI / sub-command (0x%x / 0x%x)", w->last_oui, w->last_subcmd); return 0; }
		if (w->last_len != 8 || memcmp(w->last_data, want_rl, 8) != 0) { snprintf(why, wn, "payload not {4, 7} (len %lu)", w->last_len); return 0; }
		if (w->last_nested != -1 || w->last_extra != NULL) { snprintf(why, wn, "nested / extra arguments wrong"); return 0; }
	}
	if (t->priv_mode == 0) {
		if (text_ok && strstr(l, "couldn't find primary interface") == NULL) { snprintf(why, wn, "NULL priv not logged"); return 0; }
	} else if (t->vendor_ret != 0) {
		if (text_ok) {
			snprintf(want, sizeof(want), "failed: %d (", t->vendor_ret);
			if (strstr(l, want) == NULL) { snprintf(why, wn, "failure line with result %d not logged", t->vendor_ret); return 0; }
		}
	} else if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "unexpected log output for a successful command"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_int_wifi_setApRetrylimit(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; int_wifi_setApRetrylimit_suite[i].test_name != NULL; i++) {
		hwr_irl_case_t *test = &int_wifi_setApRetrylimit_suite[i];
		char why[200] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_irl_world, 0, sizeof(hwr_irl_world));
		hwr_irl_world.ret = test->vendor_ret;
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		void *priv = priv_of(test->priv_mode);
		int ret = test_int_wifi_setApRetrylimit(test, priv);

		if (check(test, ret, priv, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->priv_mode == 0 ? -1 : test->vendor_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_setApRetrylimit (intel): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
