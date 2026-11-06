/*
 * TEST RUNNER: cleanup_client_data_test
 *
 * Same shape as the other *_test.cpp runners.  The pointer the function gets
 * the address of lives in the runner-owned slab hcc_slot_slab; the bytes past
 * it are poisoned across every call (the scenario calls hcc_poison_fn(1) right
 * before cleanup_client_data() and hcc_poison_fn(0) right after it):
 *   hcc_slot_slab : [sizeof(unsigned char *), +HIPC_PAD)
 *   hipc_log_buf  : [HIPC_LOG_USE, HIPC_LOG_SZ)
 * (the scratch blocks are real heap allocations guarded by ASan red-zones).
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hcc_slot_slab[sizeof(unsigned char *)], HIPC_PAD);
	fn(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);
}

int test_cleanup_client_data(void)
{
	hcc_poison_fn = poison_all;
	return cleanup_client_data_run_current();
}

void run_all_tests_cleanup_client_data(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; cleanup_client_data_suite[i].test_name != NULL; i++) {
		hcc_test_case_t *test = &cleanup_client_data_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		construct_cleanup_client_data_input(test);

		int ret = test_cleanup_client_data();

		if (ret == test->expected_result) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n",
			       test->test_name, test->expected_result, ret, hipc_exec_why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\ncleanup_client_data: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
