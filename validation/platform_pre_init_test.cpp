/*
 * TEST RUNNER: platform_pre_init_test
 *
 * The runner presets the log slot (prefill bytes of 'x'), POISONS the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) and the guard
 * slab around the call, calls the function `calls` times, unpoisons and checks the return value (0), that the log was only
 * appended to inside the first HWR_LOG_USE bytes, that the previous text is intact, and (expect_log) that one
 * "platform_pre_init:<line> " line per call was appended.  Any write behind HWR_LOG_USE would abort under ASan.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_ppi.h"
#include <sanitizer/asan_interface.h>

static int run_case(const hwr_ppi_case_t *t, char *why, size_t wn)
{
	int ret = 0, n = 0;
	const char *p;

	memset(hwr_log_buf, 0, HWR_LOG_SZ);
	memset(hwr_log_buf, 'x', t->prefill);
	__asan_poison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	for (int i = 0; i < t->calls; i++) ret = hwr_platform_pre_init();
	__asan_unpoison_memory_region(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);

	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (int i = 0; i < t->prefill; i++) if (hwr_log_buf[i] != 'x') { snprintf(why, wn, "previous log byte %d modified", i); return 0; }
	for (int i = HWR_LOG_USE; i < HWR_LOG_SZ; i++) if (hwr_log_buf[i] != 0) { snprintf(why, wn, "log byte %d behind HWR_LOG_USE written", i); return 0; }
	if (t->expect_log) {
		for (p = hwr_log_buf + t->prefill; (p = strstr(p, "platform_pre_init:")) != NULL; p++) n++;
		if (n != t->calls) { snprintf(why, wn, "%d log lines, expected %d", n, t->calls); return 0; }
		if (hwr_log_buf[strlen(hwr_log_buf) - 1] != '\n') { snprintf(why, wn, "log line not newline terminated"); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_platform_pre_init(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; platform_pre_init_suite[i].test_name != NULL; i++) {
		hwr_ppi_case_t *test = &platform_pre_init_suite[i];
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
	printf("\nplatform_pre_init: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
