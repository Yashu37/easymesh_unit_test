/*
 * TEST RUNNER: platform_flags_init_test
 *
 * The runner owns a 64-byte canary slab (hwr_pfi_slab, 0x5A) and puts the int at offset 16, like a member inside a larger struct.  During the call it POISONS
 * the head [0, 16) and the tail [20, 64) of the slab (so any write of more than 4 bytes or at a wrong offset aborts under ASan) and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  Rows flagged `forked` crash the unfixed function (NULL flags): they run in a child so the ASan report is visible but the
 * run continues; the child also checks the result.  Checks: return value, *flags == 0x12 exactly (assigned, not OR-ed), the canary bytes around
 * the int unchanged, the previous log text, and one "platform_flags_init:<line> " line per call when it fits.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "hwr_pfi.h"
#include <sanitizer/asan_interface.h>

#define OFF 16
static unsigned char hwr_pfi_slab[64];
static char why[160];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_pfi_slab[0], OFF);
	fn(&hwr_pfi_slab[OFF + 4], sizeof(hwr_pfi_slab) - OFF - 4);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static int check_result(const hwr_pfi_case_t *t, int ret)
{
	unsigned int got;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (t->null_flags) return 1;
	memcpy(&got, &hwr_pfi_slab[OFF], 4);
	if (got != (PLATFORM_FLAGS_STA_INACTIVITY_TIMER | PLATFORM_FLAGS_CONTROL_PORT_FRAME)) { snprintf(why, sizeof(why), "*flags = 0x%x, expected 0x12", got); return 0; }
	for (int k = 0; k < (int)sizeof(hwr_pfi_slab); k++) if ((k < OFF || k >= OFF + 4) && hwr_pfi_slab[k] != 0x5A) { snprintf(why, sizeof(why), "canary byte %d modified", k); return 0; }
	for (int k = 0; k < t->log_prefill; k++) if (hwr_log_buf[k] != 'x') { snprintf(why, sizeof(why), "previous log byte %d modified", k); return 0; }
	if (t->log_prefill + 60 < HWR_LOG_USE) {
		int n = 0;
		for (const char *p = hwr_log_buf + t->log_prefill; (p = strstr(p, "platform_flags_init:")) != NULL; p++) n++;
		if (n != t->calls) { snprintf(why, sizeof(why), "%d log lines, expected %d", n, t->calls); return 0; }
	}
	return 1;
}

static int run_case(const hwr_pfi_case_t *t)
{
	int *flags;
	int ret = 0;

	why[0] = 0;
	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_log_buf, 'x', t->log_prefill);
	memset(hwr_pfi_slab, 0x5A, sizeof(hwr_pfi_slab));
	memcpy(&hwr_pfi_slab[OFF], &t->preset, 4);
	flags = t->null_flags ? NULL : (int *)&hwr_pfi_slab[OFF];

	if (t->forked) {
		int st; pid_t pid;
		fflush(stdout);
		poison(1);
		pid = fork();
		if (pid == 0) { for (int i = 0; i < t->calls; i++) ret = hwr_platform_flags_init(flags); poison(0); _exit(check_result(t, ret) ? 0 : 2); }
		waitpid(pid, &st, 0);
		poison(0);
		if (!WIFEXITED(st)) { snprintf(why, sizeof(why), "child died"); return 0; }
		if (WEXITSTATUS(st) == 1) { snprintf(why, sizeof(why), "child aborted by AddressSanitizer (NULL flags written)"); return 0; }
		if (WEXITSTATUS(st) != 0) { snprintf(why, sizeof(why), "child did not return the expected result"); return 0; }
		return 1;
	}
	poison(1);
	for (int i = 0; i < t->calls; i++) ret = hwr_platform_flags_init(flags);
	poison(0);
	return check_result(t, ret);
}

extern "C" void run_all_tests_platform_flags_init(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_flags_init_suite[i].test_name != NULL; i++) {
		hwr_pfi_case_t *test = &platform_flags_init_suite[i];

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
	printf("\nplatform_flags_init: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
