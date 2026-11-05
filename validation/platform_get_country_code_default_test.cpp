/*
 * TEST RUNNER: platform_get_country_code_default_test
 *
 * The runner owns the buffer in a slab and POISONS the tail behind the 3 bytes of "US\0" the function may write (bytes [3, end)); the log slot
 * tail [HWR_LOG_USE, HWR_LOG_SZ) is poisoned too.  The buffer is preset to zeros / 0xA5 / "DE" / "ABCD".  Rows flagged `forked` crash the
 * unfixed function (NULL code): they run in a child so the ASan report is visible but the run continues; the child also checks the result.
 * Checks: return value, the code string, byte 3 (first byte behind "US\0": must keep its preset value), the previous log text and one log line per call.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_pcc.h"
#include <sanitizer/asan_interface.h>

#define WRITE_MAX 3
static unsigned char hwr_code_slab[128];
static char why[160];
static unsigned char preset3;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_code_slab[WRITE_MAX], sizeof(hwr_code_slab) - WRITE_MAX);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static int check_result(const hwr_pcc_case_t *t, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (t->null_code) return 1;
	if (t->expected_code == NULL) return 1;
	if (strcmp((char *)hwr_code_slab, t->expected_code)) { snprintf(why, sizeof(why), "code '%.8s', expected '%s'", (char *)hwr_code_slab, t->expected_code); return 0; }
	for (int i = 0; i < t->log_prefill; i++) if (hwr_log_buf[i] != 'x') { snprintf(why, sizeof(why), "previous log byte %d modified", i); return 0; }
	if (t->log_prefill + 70 < HWR_LOG_USE) {               /* one "platform_get_country_code_default:<line> " line per call when it fits */
		int n = 0;
		for (const char *p = hwr_log_buf + t->log_prefill; (p = strstr(p, "platform_get_country_code_default:")) != NULL; p++) n++;
		if (n != t->calls) { snprintf(why, sizeof(why), "%d log lines, expected %d", n, t->calls); return 0; }
	}
	return 1;
}

static int run_case(const hwr_pcc_case_t *t)
{
	char *code;
	int ret = 0;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_log_buf, 'x', t->log_prefill);
	memset(hwr_code_slab, 0xA5, sizeof(hwr_code_slab));
	if (t->prefill == 0) memset(hwr_code_slab, 0, 4);
	else if (t->prefill == 2) { hwr_code_slab[0] = 'D'; hwr_code_slab[1] = 'E'; hwr_code_slab[2] = 0; hwr_code_slab[3] = 0; }
	else if (t->prefill == 3) { memcpy(hwr_code_slab, "ABCD", 4); }
	preset3 = hwr_code_slab[3];
	code = t->null_code ? NULL : (char *)hwr_code_slab;

	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1);
		pid = fork();
		if (pid == 0) { for (int i = 0; i < t->calls; i++) ret = hwr_platform_get_country_code_default(code); poison(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (NULL code written)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_platform_get_country_code_default(code);
	poison(0);
	if (hwr_code_slab[3] != preset3) { snprintf(why, sizeof(why), "byte 3 behind the code modified"); return 0; }
	return check_result(t, ret);
}

extern "C" void run_all_tests_platform_get_country_code_default(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_get_country_code_default_suite[i].test_name != NULL; i++) {
		hwr_pcc_case_t *test = &platform_get_country_code_default_suite[i];

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
	printf("\nplatform_get_country_code_default: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
