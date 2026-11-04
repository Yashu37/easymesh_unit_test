/*
 * TEST RUNNER: wifi_hal_getSSIDTrafficStats2_test
 *
 * The runner owns the output structure (hwr_out_slab), POISONS its tail, calls the function, UNPOISONS and
 * checks the result:
 *   hwr_out_slab : [sizeof(wifi_ssidTrafficStats2_t), end)   - nothing behind the structure may be written
 *   hwr_log_buf  : [HWR_LOG_USE, HWR_LOG_SZ)
 * Rows flagged `forked` are expected to crash the unfixed function (NULL output): they run in a child so the
 * ASan report is visible but the run continues.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_gts.h"
#include <sanitizer/asan_interface.h>

#define PADB 64
static unsigned char hwr_out_slab[sizeof(wifi_ssidTrafficStats2_t) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_out_slab[sizeof(wifi_ssidTrafficStats2_t)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static int run_case(const hwr_gts_case_t *t)
{
	wifi_ssidTrafficStats2_t *out = t->null_out ? NULL : (wifi_ssidTrafficStats2_t *)hwr_out_slab;
	INT ret = 0;

	why[0] = 0;
	memset(hwr_out_slab, 0, sizeof(hwr_out_slab));
	memset(hwr_log_buf, 0, HWR_LOG_USE);
	hwr_gts_configure(t->callee_ret);

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getSSIDTrafficStats2(t->ssid_index, out); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died (SEGV on the NULL output)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return an error for the NULL output"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		hwr_gts_configure(t->callee_ret);
		poison_all(1);
		ret = hwr_wifi_hal_getSSIDTrafficStats2(t->ssid_index, out);
		poison_all(0);
		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, platform returned %d%s", i, ret, t->callee_ret, ret == 0 && t->callee_ret != 0 ? " (failure reported as success)" : ""); return 0; }
		if (hwr_gts_rec.calls != 1) { snprintf(why, sizeof(why), "platform function called %d times", hwr_gts_rec.calls); return 0; }
		if (hwr_gts_rec.ssid != t->ssid_index || hwr_gts_rec.out != out) { snprintf(why, sizeof(why), "arguments not forwarded unchanged"); return 0; }
	}
	if (hwr_out_slab[0] != 0x3C || hwr_out_slab[sizeof(wifi_ssidTrafficStats2_t) - 1] != 0x3C) { snprintf(why, sizeof(why), "output structure not filled"); return 0; }
	if (t->check_log && (!strstr(hwr_log_buf, "wifi_hal_getSSIDTrafficStats2") || !strstr(hwr_log_buf, "Enter"))) { snprintf(why, sizeof(why), "log lacks function name / Enter: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getSSIDTrafficStats2(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getSSIDTrafficStats2_suite[i].test_name != NULL; i++) {
		hwr_gts_case_t *test = &wifi_hal_getSSIDTrafficStats2_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_getSSIDTrafficStats2: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
