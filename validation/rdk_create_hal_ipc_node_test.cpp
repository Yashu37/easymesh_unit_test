/*
 * TEST RUNNER: rdk_create_hal_ipc_node_test
 *
 * Same shape as the other *_test.cpp runners.  g_ipc_node[] is the runner-owned
 * slab hcre_gnode_slab; the bytes past the array and the unused part of the log
 * slot are poisoned across every call (the scenario calls hcre_poison_fn(1)
 * right before rdk_create_hal_ipc_node() and hcre_poison_fn(0) right after):
 *   hcre_gnode_slab : [sizeof(hal_ipc_node_t) * hal_ipc_node_type_max, +HIPC_PAD)
 *   hipc_log_buf    : [HIPC_LOG_USE, HIPC_LOG_SZ)
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

	fn(&hcre_gnode_slab[sizeof(hal_ipc_node_t) * hal_ipc_node_type_max], HIPC_PAD);
	fn(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);
}

int test_rdk_create_hal_ipc_node(void)
{
	hcre_poison_fn = poison_all;
	return rdk_create_hal_ipc_node_run_current();
}

void run_all_tests_rdk_create_hal_ipc_node(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; rdk_create_hal_ipc_node_suite[i].test_name != NULL; i++) {
		hcre_test_case_t *test = &rdk_create_hal_ipc_node_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		construct_rdk_create_hal_ipc_node_input(test);

		int ret = test_rdk_create_hal_ipc_node();

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
	printf("\nrdk_create_hal_ipc_node: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
