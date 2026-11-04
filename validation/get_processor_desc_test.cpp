/*
 * TEST RUNNER: get_processor_desc_test
 *
 * Same shape as the other *_test.cpp runners.  The handler returns a pointer
 * into the global processor_desc[] table (ASan red-zones guard the table
 * itself: any dereference below index 0 or at/above hal_ipc_desc_type_max
 * aborts).  The runner copies the entry's name into its own gpd_name_buf[],
 * using only GPD_NAME_USE of its GPD_NAME_SZ bytes; the tail
 * [GPD_NAME_USE, GPD_NAME_SZ) is poisoned across the call, so an over-long
 * copy aborts here.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int get_processor_desc_run_current(void);

int test_get_processor_desc(void)
{
	/* Poison the name slot beyond the bytes the runner copies. */
	__asan_poison_memory_region(&gpd_name_buf[GPD_NAME_USE], GPD_NAME_SZ - GPD_NAME_USE);

	int ret = get_processor_desc_run_current();

	__asan_unpoison_memory_region(&gpd_name_buf[GPD_NAME_USE], GPD_NAME_SZ - GPD_NAME_USE);

	return ret;
}

void run_all_tests_get_processor_desc(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; get_processor_desc_suite[i].test_name != NULL; i++) {
		gpd_test_case_t *test = &get_processor_desc_suite[i];

		printf("--- Running Test: %s (type=%d) ---\n", test->test_name, test->type_value);

		construct_get_processor_desc_input(test);

		int ret = test_get_processor_desc();

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
	printf("\nget_processor_desc: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
