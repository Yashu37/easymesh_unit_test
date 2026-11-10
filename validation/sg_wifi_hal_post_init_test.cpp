/*
 * TEST RUNNER: sg_wifi_hal_post_init_test
 *
 * The argument is the only memory the function could touch.  The runner owns a 128-byte slab (preset to 0xA5) and POISONS ALL of it during the call (arg_mode 1): any read or
 * write of the argument aborts under ASan.  The guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.  Checks: return value 0; one hook-getter call per
 * call; the hook ran once per call when present (never when absent) and received the argument pointer unchanged; the "platform post init" log appears exactly when the hook
 * exists (while the log slot has room); the slab and the guard slab are unchanged.  Both variants (HAL_IPC / plain) run the same rows.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wpo.h"
#include <sanitizer/asan_interface.h>

static unsigned char slab[128];
static char why[200];

static void poison(int on, const hwr_wpo_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->arg_mode == 1) fn(slab, sizeof(slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static void *arg_of(const hwr_wpo_case_t *t) { return t->arg_mode == 0 ? NULL : t->arg_mode == 1 ? (void *)slab : (void *)(unsigned long)0xdeadbeefUL; }

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_post_init(const hwr_wpo_case_t *t)
{
	void *arg = arg_of(t);
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++)
		ret = t->variant == 0 ? hwr_sg_wifi_hal_post_init_ipc((wifi_hal_post_init_t *)arg) : hwr_sg_wifi_hal_post_init_vap((wifi_vap_info_map_t *)arg);
	poison(0, t);
	return ret;
}

static int check(const hwr_wpo_case_t *t, int ret)
{
	int want_hook = t->hook_present ? t->calls : 0;
	int has = strstr(hwr_log_buf, "post init") != NULL;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (hwr_wpo_world.getter_calls != t->calls) { snprintf(why, sizeof(why), "getter called %d times, expected %d", hwr_wpo_world.getter_calls, t->calls); return 0; }
	if (hwr_wpo_world.hook_calls != want_hook) { snprintf(why, sizeof(why), "hook ran %d times, expected %d", hwr_wpo_world.hook_calls, want_hook); return 0; }
	if (t->hook_present && hwr_wpo_world.last_arg != arg_of(t)) { snprintf(why, sizeof(why), "hook received a different argument"); return 0; }
	if (t->prefill < 200 && has != (t->hook_present != 0)) { snprintf(why, sizeof(why), "post-init log %s, expected %s", has ? "present" : "absent", t->hook_present ? "present" : "absent"); return 0; }
	for (size_t k = 0; k < sizeof(slab); k++) if (slab[k] != 0xA5) { snprintf(why, sizeof(why), "argument byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_post_init(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_post_init_suite[i].test_name != NULL; i++) {
		hwr_wpo_case_t *test = &sg_wifi_hal_post_init_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_wpo_world, 0, sizeof(hwr_wpo_world));
		hwr_wpo_world.hook_present = test->hook_present;
		memset(slab, 0xA5, sizeof(slab));
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_sg_wifi_hal_post_init(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_post_init (HAL_IPC + plain variants): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
