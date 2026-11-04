/*
 * TEST RUNNER: dpp_dummy_test
 *
 * Same shape as the other *_test.cpp runners.  dpp_dummy() takes no
 * caller-owned buffer, so the only caller-owned memory is the runner's own
 * read-back buffer dpp_cap_buf[]: its whole body is poisoned across the
 * call, so any stray write into it by the handler would abort here.
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int dpp_dummy_run_current(void);

int test_dpp_dummy(void)
{
	__asan_poison_memory_region(dpp_cap_buf, DPP_CAP_SZ);

	int ret = dpp_dummy_run_current();

	__asan_unpoison_memory_region(dpp_cap_buf, DPP_CAP_SZ);

	return ret;
}

void run_all_tests_dpp_dummy(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; dpp_dummy_suite[i].test_name != NULL; i++) {
		dpp_dummy_test_case_t *test = &dpp_dummy_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		construct_dpp_dummy_input(test);

		int ret = test_dpp_dummy();

		if (ret == test->expected_result) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
			       test->test_name, test->expected_result, ret);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\ndpp_dummy: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
