/*
 * TEST RUNNER: qc_wifi_setApRetrylimit_test
 *
 * Same shape as the other *_test.cpp runners: test_qc_wifi_setApRetrylimit() POISONS what the function must not touch, calls the handler and unpoisons;
 * run_all_tests compares the result.  The runner owns the interface object: during the call it is fully POISONED except the 4 bytes of vap_info.vap_index
 * (the only member the function reads), so any other read or write aborts under ASan.  The guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are
 * poisoned too.  Checks: return value (RETURN_ERR for NULL, 0 otherwise); wifi_setApRetryLimit called once per call with (vap_index, 7) and never for NULL;
 * the log lines (error line for NULL, "AP_RETRY_LIMIT failed:<res>" for a failing call, nothing for success); interface bytes and guard slab unchanged.
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "hwr_qrl.h"
#include <sanitizer/asan_interface.h>

static qrl_iface_t iface_obj, iface_ref;
static char log_before[HWR_LOG_SZ];
#define VOFF (offsetof(qrl_iface_t, vap_info) + offsetof(wifi_vap_info_t, vap_index))

static void poison(int on, const hwr_qrl_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->priv_mode == 1) {
		fn((char *)&iface_obj, VOFF);
		fn((char *)&iface_obj + VOFF + sizeof(wifi_vap_index_t), sizeof(iface_obj) - VOFF - sizeof(wifi_vap_index_t));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_qc_wifi_setApRetrylimit(const hwr_qrl_case_t *t)
{
	void *priv = t->priv_mode == 0 ? NULL : (void *)&iface_obj;
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_qc_wifi_setApRetrylimit(priv);
	poison(0, t);
	return ret;
}

static int check(const hwr_qrl_case_t *t, int ret, char *why, size_t wn)
{
	const hwr_qrl_world_t *w = &hwr_qrl_world;
	int expect_ret = t->priv_mode == 0 ? -1 : 0;
	int expect_calls = t->priv_mode == 0 ? 0 : t->calls;
	int fits = t->prefill + 100 * t->calls < HWR_LOG_USE - 1;
	const char *l = hwr_log_buf + t->prefill;
	char want[64];

	if (ret != expect_ret) { snprintf(why, wn, "returned %d, expected %d", ret, expect_ret); return 0; }
	if (w->calls != expect_calls) { snprintf(why, wn, "wifi_setApRetryLimit called %d times, expected %d", w->calls, expect_calls); return 0; }
	if (expect_calls && (w->last_ap != (int)t->vap_index || w->last_limit != 7)) { snprintf(why, wn, "called with (%d, %u), expected (%d, 7)", w->last_ap, w->last_limit, (int)t->vap_index); return 0; }
	if (fits) {
		if (t->priv_mode == 0) {
			if (strstr(l, "error couldn't find primary interface") == NULL) { snprintf(why, wn, "error line not logged"); return 0; }
		} else if (t->limit_ret != 0) {
			snprintf(want, sizeof(want), "AP_RETRY_LIMIT failed:%d", t->limit_ret);
			if (strstr(l, want) == NULL) { snprintf(why, wn, "'%s' not logged", want); return 0; }
		} else if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "unexpected log output for a successful call"); return 0; }
	}
	if (t->prefill >= HWR_LOG_USE - 1 && memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0 && t->prefill == 255) { snprintf(why, wn, "log modified although the slot is full"); return 0; }
	if (t->priv_mode == 1 && memcmp(&iface_obj, &iface_ref, sizeof(iface_obj)) != 0) { snprintf(why, wn, "interface object modified"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_qc_wifi_setApRetrylimit(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; qc_wifi_setApRetrylimit_suite[i].test_name != NULL; i++) {
		hwr_qrl_case_t *test = &qc_wifi_setApRetrylimit_suite[i];
		char why[200] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_qrl_world, 0, sizeof(hwr_qrl_world));
		hwr_qrl_world.ret = test->limit_ret;
		memset(&iface_obj, 0x77, sizeof(iface_obj));
		iface_obj.vap_info.vap_index = test->vap_index;
		memcpy(&iface_ref, &iface_obj, sizeof(iface_obj));
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_qc_wifi_setApRetrylimit(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_setApRetrylimit (qualcomm): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
