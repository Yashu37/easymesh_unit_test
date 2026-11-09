/*
 * TEST RUNNER: int_wifi_setApManagementFramePowerControl_test
 *
 * Same shape as the other *_test.cpp runners: test_int_wifi_setApManagementFramePowerControl() POISONS what the function must not touch, calls the
 * handler and unpoisons; run_all_tests compares the result.  The interface object the lookup returns is a runner-owned struct that is fully POISONED
 * during the call (the function only passes its pointer on: any read or write aborts under ASan); the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ) are POISONED as well.
 * Checks: return value; the vendor stub was called once per call with OUI_LTQ, the sub-command, the 4 bytes of dBm, length 4, nested = -1, the interface
 * pointer (and never when there is no interface); the log lines (see the constructor); the guard slab is unchanged.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_imp.h"
#include <sanitizer/asan_interface.h>

static imp_iface_t iface_obj;
static char log_before[HWR_LOG_SZ];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&iface_obj, sizeof(iface_obj));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_int_wifi_setApManagementFramePowerControl(const hwr_imp_case_t *t)
{
	int ret = 0;

	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_int_wifi_setApManagementFramePowerControl(t->ap_index, t->dbm);
	poison(0);
	return ret;
}

static int check(const hwr_imp_case_t *t, int ret, char *why, size_t wn)
{
	const hwr_imp_world_t *w = &hwr_imp_world;
	int found = t->has_iface == 1;
	int expect_ret = found ? t->vendor_ret : -1;
	int expect_calls = found ? t->calls : 0;
	int text_ok = t->prefill + 200 < HWR_LOG_USE;            /* the line fits into the log slot */
	const char *l = hwr_log_buf + t->prefill;
	char want[96];

	if (ret != expect_ret) { snprintf(why, wn, "returned %d, expected %d", ret, expect_ret); return 0; }
	if (w->calls != expect_calls) { snprintf(why, wn, "vendor command sent %d times, expected %d", w->calls, expect_calls); return 0; }
	if (expect_calls) {
		if (w->last_priv != (void *)&iface_obj) { snprintf(why, wn, "interface pointer not passed on unchanged"); return 0; }
		if (w->last_oui != IMP_OUI_LTQ || w->last_subcmd != IMP_SUBCMD_PWR) { snprintf(why, wn, "wrong OUI / sub-command (0x%x / 0x%x)", w->last_oui, w->last_subcmd); return 0; }
		if (w->last_len != 4 || memcmp(w->last_data, &t->dbm, 4) != 0) { snprintf(why, wn, "payload is not the 4 bytes of dBm %d (len %lu)", t->dbm, w->last_len); return 0; }
		if (w->last_nested != -1 || w->last_extra != NULL) { snprintf(why, wn, "nested / extra arguments wrong"); return 0; }
	}
	if (!found) {
		if (text_ok) {
			snprintf(want, sizeof(want), "interface for ap index:%d not found", t->ap_index);
			if (strstr(l, want) == NULL) { snprintf(why, wn, "'%s' not logged", want); return 0; }
		}
	} else if (t->vendor_ret != 0) {
		if (text_ok) {
			snprintf(want, sizeof(want), "failed: %d (", t->vendor_ret);
			if (strstr(l, want) == NULL) { snprintf(why, wn, "failure line with result %d not logged", t->vendor_ret); return 0; }
		}
	} else if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "unexpected log output for a successful command"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_int_wifi_setApManagementFramePowerControl(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; int_wifi_setApManagementFramePowerControl_suite[i].test_name != NULL; i++) {
		hwr_imp_case_t *test = &int_wifi_setApManagementFramePowerControl_suite[i];
		char why[200] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_imp_world, 0, sizeof(hwr_imp_world));
		hwr_imp_world.ret = test->vendor_ret;
		if (test->has_iface) {
			hwr_imp_world.iface = &iface_obj;
			hwr_imp_world.iface_vap = test->has_iface == 1 ? (unsigned)test->ap_index : (unsigned)test->ap_index + 1u;
		}
		memset(&iface_obj, 0x77, sizeof(iface_obj));
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_int_wifi_setApManagementFramePowerControl(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->has_iface == 1 ? test->vendor_ret : -1, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_setApManagementFramePowerControl (intel): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
