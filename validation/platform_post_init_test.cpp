/*
 * TEST RUNNER: platform_post_init_test
 *
 * The runner owns vap_map in a slab (hwr_map_slab, sizeof(wifi_vap_info_map_t)) and POISONS ALL of it during the call: the
 * function does not use vap_map, so any read or write of it aborts under ASan.  The log slot tail [HWR_LOG_USE, HWR_LOG_SZ) is
 * poisoned too.  system() is a recording stub (fail_mask per call).  After the calls it checks: the commands (each call runs
 * exactly wifi0, wifi1, wifi2 in order - a failure does not stop the others), the return value of the last call, and the number
 * of "failed" lines in the log.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_ppo.h"
#include <sanitizer/asan_interface.h>

static unsigned char hwr_map_slab[sizeof(wifi_vap_info_map_t)];

static int run_case(const hwr_ppo_case_t *t, char *why, size_t wn)
{
	static const char *want[3] = { "brctl addif brlan0 wifi0", "brctl addif brlan0 wifi1", "brctl addif brlan0 wifi2" };
	int ret = 0, nfail = 0;
	const char *p;

	memset(&hwr_ppo_rec, 0, sizeof(hwr_ppo_rec));
	hwr_ppo_rec.fail_mask = t->fail_mask; hwr_ppo_rec.fail_status = t->fail_status;
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	memset(hwr_map_slab, 0xA5, sizeof(hwr_map_slab));
	__asan_poison_memory_region(hwr_map_slab, sizeof(hwr_map_slab));
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	for (int i = 0; i < t->calls; i++)
		ret = hwr_platform_post_init(t->map_null ? NULL : (wifi_vap_info_map_t *)hwr_map_slab);
	__asan_unpoison_memory_region(hwr_map_slab, sizeof(hwr_map_slab));
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);

	if (hwr_ppo_rec.n != 3 * t->calls) { snprintf(why, wn, "%d system() calls, expected %d", hwr_ppo_rec.n, 3 * t->calls); return 0; }
	for (int i = 0; i < hwr_ppo_rec.n; i++)
		if (strcmp(hwr_ppo_rec.cmd[i], want[i % 3])) { snprintf(why, wn, "command %d is '%s'", i, hwr_ppo_rec.cmd[i]); return 0; }
	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d%s", ret, t->expected_ret, ret == 0 ? " (brctl failure not reported)" : ""); return 0; }
	for (p = hwr_log_buf; (p = strstr(p, "failed")) != NULL; p++) nfail++;
	if (nfail != t->expect_log_fail) { snprintf(why, wn, "%d 'failed' log lines, expected %d", nfail, t->expect_log_fail); return 0; }
	for (size_t k = 0; k < sizeof(hwr_map_slab); k++) if (hwr_map_slab[k] != 0xA5) { snprintf(why, wn, "vap_map byte %zu modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_platform_post_init(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_post_init_suite[i].test_name != NULL; i++) {
		hwr_ppo_case_t *test = &platform_post_init_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test, why, sizeof(why));

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nplatform_post_init: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
