/*
 * TEST RUNNER: sg_wifi_hal_get_default_ssid_test
 *
 * The ssid argument is the only memory the wrapper could touch.  The runner owns a 64-byte slab (preset to 0xA5) and POISONS ALL of it during the call (ssid_mode 1): any read or
 * write of ssid by the wrapper aborts under ASan.  The guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.  Checks: return value (-1 without a hook, the
 * hook's value unchanged otherwise); one getter call per call; the hook ran once per call when present (never when absent) with the same ssid pointer and vap_index; the
 * "platform ssid init" log appears exactly when the hook exists (while the log slot has room); the slab and the guard slab are unchanged.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wds.h"
#include <sanitizer/asan_interface.h>

static unsigned char slab[64];
static char why[200];

static void poison(int on, const hwr_wds_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->ssid_mode == 1) fn(slab, sizeof(slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char *ssid_of(const hwr_wds_case_t *t) { return t->ssid_mode == 0 ? NULL : t->ssid_mode == 1 ? (char *)slab : (char *)(unsigned long)0xdeadbeefUL; }

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_get_default_ssid(const hwr_wds_case_t *t)
{
	char *ssid = ssid_of(t);
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_sg_wifi_hal_get_default_ssid(ssid, t->vap_index);
	poison(0, t);
	return ret;
}

static int check(const hwr_wds_case_t *t, int ret)
{
	int want_hook = t->hook_present ? t->calls : 0;
	int has = strstr(hwr_log_buf, "platform ssid init") != NULL;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (hwr_wds_world.getter_calls != t->calls) { snprintf(why, sizeof(why), "getter called %d times, expected %d", hwr_wds_world.getter_calls, t->calls); return 0; }
	if (hwr_wds_world.hook_calls != want_hook) { snprintf(why, sizeof(why), "hook ran %d times, expected %d", hwr_wds_world.hook_calls, want_hook); return 0; }
	if (t->hook_present && (hwr_wds_world.last_ssid != ssid_of(t) || hwr_wds_world.last_vap != t->vap_index)) { snprintf(why, sizeof(why), "hook received different arguments"); return 0; }
	if (t->prefill < 200 && has != (t->hook_present != 0)) { snprintf(why, sizeof(why), "log %s, expected %s", has ? "present" : "absent", t->hook_present ? "present" : "absent"); return 0; }
	for (size_t k = 0; k < sizeof(slab); k++) if (slab[k] != 0xA5) { snprintf(why, sizeof(why), "ssid byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_get_default_ssid(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_get_default_ssid_suite[i].test_name != NULL; i++) {
		hwr_wds_case_t *test = &sg_wifi_hal_get_default_ssid_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_wds_world, 0, sizeof(hwr_wds_world));
		hwr_wds_world.hook_present = test->hook_present; hwr_wds_world.hook_ret = test->hook_ret;
		memset(slab, 0xA5, sizeof(slab));
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_sg_wifi_hal_get_default_ssid(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_get_default_ssid: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
