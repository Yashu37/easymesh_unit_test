/*
 * TEST RUNNER: rdk_hal_ipc_exec_test
 *
 * Same shape as the other *_test.cpp runners.  Everything the function reads
 * or writes through its two pointer parameters lives in runner-owned slabs,
 * and the bytes past each valid size are poisoned across the call:
 *   hipc_node_slab : [sizeof(hal_ipc_node_t), +HIPC_PAD)      - node_path read
 *   hipc_desc_slab : [sizeof(hal_ipc_processor_desc_t), +PAD) - the descriptor sent
 *   hipc_scr_slab  : [scratch_buf_size, HIPC_SCR_SZ)          - the scratch buffer sent
 *   hipc_log_buf   : [HIPC_LOG_USE, HIPC_LOG_SZ)              - the log line
 * The send() stub reads every byte it is handed, so any over-read of the
 * descriptor or scratch buffer aborts here.  The function is NOT modified.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int rdk_hal_ipc_exec_run_current(void);

int test_rdk_hal_ipc_exec(void)
{
	/* the real sizes the function is allowed to touch */
	size_t scr_size = hipc_cur_scr_size;

	__asan_poison_memory_region(&hipc_node_slab[sizeof(hal_ipc_node_t)], HIPC_PAD);
	__asan_poison_memory_region(&hipc_desc_slab[sizeof(hal_ipc_processor_desc_t)], HIPC_PAD);
	__asan_poison_memory_region(&hipc_scr_slab[scr_size], HIPC_SCR_SZ - scr_size);
	__asan_poison_memory_region(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);

	int ret = rdk_hal_ipc_exec_run_current();

	__asan_unpoison_memory_region(&hipc_node_slab[sizeof(hal_ipc_node_t)], HIPC_PAD);
	__asan_unpoison_memory_region(&hipc_desc_slab[sizeof(hal_ipc_processor_desc_t)], HIPC_PAD);
	__asan_unpoison_memory_region(&hipc_scr_slab[scr_size], HIPC_SCR_SZ - scr_size);
	__asan_unpoison_memory_region(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);

	return ret;
}

void run_all_tests_rdk_hal_ipc_exec(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; rdk_hal_ipc_exec_suite[i].test_name != NULL; i++) {
		hipc_exec_test_case_t *test = &rdk_hal_ipc_exec_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		construct_rdk_hal_ipc_exec_input(test);

		int ret = test_rdk_hal_ipc_exec();

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
	printf("\nrdk_hal_ipc_exec: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
