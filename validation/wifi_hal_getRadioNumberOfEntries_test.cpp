/*
 * TEST RUNNER: wifi_hal_getRadioNumberOfEntries_test
 *
 * The runner owns the output (hwr_out_slab), POISONS everything behind the single ULONG, calls the function,
 * UNPOISONS and checks the result:
 *   hwr_out_slab : [sizeof(ULONG), end)        - *output is the only ULONG it may write
 *   hwr_log_buf  : [HWR_LOG_USE, HWR_LOG_SZ)
 * The output is preset to 0 or to a 0xA5 pattern.  Rows flagged `forked` are expected to crash the unfixed
 * function (NULL output): they run in a child so the ASan report is visible but the run continues.  The function
 * is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_grn.h"
#include <sanitizer/asan_interface.h>

static unsigned char hwr_out_slab[sizeof(ULONG) + 64];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_out_slab[sizeof(ULONG)], sizeof(hwr_out_slab) - sizeof(ULONG));
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static int run_case(const hwr_grn_case_t *t)
{
	ULONG *out = t->null_out ? NULL : (ULONG *)hwr_out_slab;
	INT ret = 0;

	why[0] = 0;
	hwr_grn_world.num_radios = t->num_radios;

	if (t->forked) {                                         /* SEGV report visible, run continues */
		int st; pid_t pid;
		memset(hwr_out_slab, 0, sizeof(hwr_out_slab)); memset(hwr_log_buf, 0, HWR_LOG_USE);
		fflush(stdout);
		poison_all(1);
		pid = fork();
		if (pid == 0) { ret = hwr_wifi_hal_getRadioNumberOfEntries(out); _exit(ret == t->expected_ret ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison_all(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (SEGV on NULL output)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return an error for NULL output"); return 0; }
		return 1;
	}

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_out_slab, t->preset ? 0xA5 : 0, sizeof(hwr_out_slab)); memset(hwr_log_buf, 0, HWR_LOG_USE);
		poison_all(1);
		ret = hwr_wifi_hal_getRadioNumberOfEntries(out);
		poison_all(0);
		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", i, ret, t->expected_ret); return 0; }
		if (*(ULONG *)hwr_out_slab != t->expected_out) { snprintf(why, sizeof(why), "*output = %lu, expected %lu", *(ULONG *)hwr_out_slab, t->expected_out); return 0; }
		for (size_t k = sizeof(ULONG); k < sizeof(hwr_out_slab); k++) if (hwr_out_slab[k] != (t->preset ? 0xA5 : 0)) { snprintf(why, sizeof(why), "byte %zu behind *output modified", k); return 0; }
	}
	if (t->check_log && (!strstr(hwr_log_buf, "wifi_hal_getRadioNumberOfEntries") || !strstr(hwr_log_buf, "Enter"))) { snprintf(why, sizeof(why), "log lacks function name / Enter: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getRadioNumberOfEntries(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getRadioNumberOfEntries_suite[i].test_name != NULL; i++) {
		hwr_grn_case_t *test = &wifi_hal_getRadioNumberOfEntries_suite[i];

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
	printf("\nwifi_hal_getRadioNumberOfEntries: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
