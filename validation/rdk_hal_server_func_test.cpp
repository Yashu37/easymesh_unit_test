/*
 * TEST RUNNER: rdk_hal_server_func_test
 *
 * Same shape as the other *_test.cpp runners.  Everything the server reads
 * from "the network" or from its node argument lives in runner-owned
 * buffers, and the bytes past each valid length are poisoned across the call:
 *   hipc_node_slab : [sizeof(hal_ipc_node_t), +HIPC_PAD)   - node_path / node struct
 *   hsrv_stream[i] : [request length, HSRV_STREAM_SZ)      - the client byte streams
 *   hipc_log_buf   : [HIPC_LOG_USE, HIPC_LOG_SZ)           - the log line
 * (the scratch buffers are real heap allocations, so ASan's own heap
 * red-zones guard them).  The function is NOT modified.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int rdk_hal_server_func_run_current(void);

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hipc_node_slab[sizeof(hal_ipc_node_t)], HIPC_PAD);
	fn(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);
	for (int i = 0; i < HSRV_MAX_CLIENTS; i++)
		fn(&hsrv_stream[i][hsrv_stream_len[i]], HSRV_STREAM_SZ - hsrv_stream_len[i]);
}

int test_rdk_hal_server_func(void)
{
	/* the scenario builds the node + client streams, then calls hsrv_poison_fn(1) right before
	 * rdk_hal_server_func() and hsrv_poison_fn(0) right after it: poison_all() above does the
	 * __asan_poison_memory_region / __asan_unpoison_memory_region on the runner-owned buffers */
	hsrv_poison_fn = poison_all;
	return rdk_hal_server_func_run_current();
}

void run_all_tests_rdk_hal_server_func(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; rdk_hal_server_func_suite[i].test_name != NULL; i++) {
		hsrv_test_case_t *test = &rdk_hal_server_func_suite[i];

		if (getenv("HSRV_ONLY") && strcmp(getenv("HSRV_ONLY"), test->test_name))   /* HSRV_ONLY=<case> runs one case */
			continue;

		printf("--- Running Test: %s ---\n", test->test_name);

		construct_rdk_hal_server_func_input(test);

		int ret = test_rdk_hal_server_func();

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
	printf("\nrdk_hal_server_func: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
