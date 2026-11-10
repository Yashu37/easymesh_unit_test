/*
 * TEST RUNNER: sg_wifi_hal_get_default_radius_key_test
 *
 * The radius_key argument is the only memory the wrapper could touch.  The runner owns a 64-byte slab (preset to 0xA5) and POISONS ALL of it during the call (key_mode 1): any read or
 * write of radius_key by the wrapper aborts under ASan.  The guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.  Checks: return value (-1 without a hook, the
 * hook's value unchanged otherwise); one getter call per call; the hook ran once per call when present (never when absent) with the same radius_key pointer; the
 * "platform  default_radius_key" log appears exactly when the hook exists (while the log slot has room); the slab and the guard slab are unchanged.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wrk.h"
#include <sanitizer/asan_interface.h>

static unsigned char slab[64];
static char why[200];

static void poison(int on, const hwr_wrk_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->key_mode == 1) fn(slab, sizeof(slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char *key_of(const hwr_wrk_case_t *t) { return t->key_mode == 0 ? NULL : t->key_mode == 1 ? (char *)slab : (char *)(unsigned long)0xdeadbeefUL; }

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_get_default_radius_key(const hwr_wrk_case_t *t)
{
	char *radius_key = key_of(t);
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_sg_wifi_hal_get_default_radius_key(radius_key);
	poison(0, t);
	return ret;
}

static int check(const hwr_wrk_case_t *t, int ret)
{
	int want_hook = t->hook_present ? t->calls : 0;
	int has = strstr(hwr_log_buf, "platform  default_radius_key") != NULL;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (hwr_wrk_world.getter_calls != t->calls) { snprintf(why, sizeof(why), "getter called %d times, expected %d", hwr_wrk_world.getter_calls, t->calls); return 0; }
	if (hwr_wrk_world.hook_calls != want_hook) { snprintf(why, sizeof(why), "hook ran %d times, expected %d", hwr_wrk_world.hook_calls, want_hook); return 0; }
	if (t->hook_present && (hwr_wrk_world.last_key != key_of(t))) { snprintf(why, sizeof(why), "hook received a different radius_key pointer"); return 0; }
	if (t->prefill < 200 && has != (t->hook_present != 0)) { snprintf(why, sizeof(why), "log %s, expected %s", has ? "present" : "absent", t->hook_present ? "present" : "absent"); return 0; }
	for (size_t k = 0; k < sizeof(slab); k++) if (slab[k] != 0xA5) { snprintf(why, sizeof(why), "radius_key byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_get_default_radius_key(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_get_default_radius_key_suite[i].test_name != NULL; i++) {
		hwr_wrk_case_t *test = &sg_wifi_hal_get_default_radius_key_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_wrk_world, 0, sizeof(hwr_wrk_world));
		hwr_wrk_world.hook_present = test->hook_present; hwr_wrk_world.hook_ret = test->hook_ret;
		memset(slab, 0xA5, sizeof(slab));
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_sg_wifi_hal_get_default_radius_key(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_get_default_radius_key: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
