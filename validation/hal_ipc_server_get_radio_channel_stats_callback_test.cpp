/*
 * TEST RUNNER: hal_ipc_server_get_radio_channel_stats_callback_test
 *
 * Same shape as the other *_test.cpp runners.  The getter takes no
 * parameters and only logs a debug line (the log stub vsnprintf()s it into
 * the runner-owned hipc_log_buf[] using only HIPC_LOG_USE of its
 * HIPC_LOG_SZ bytes) and returns the stored pointer.  The tail
 * [HIPC_LOG_USE, HIPC_LOG_SZ) of the log slot is poisoned across the call,
 * so any write past the size the logger was given aborts here.
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int hal_ipc_server_get_radio_channel_stats_callback_run_current(void);

int test_hal_ipc_server_get_radio_channel_stats_callback(void)
{
	/* Poison the log slot beyond the size handed to the logger. */
	__asan_poison_memory_region(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);

	int ret = hal_ipc_server_get_radio_channel_stats_callback_run_current();

	__asan_unpoison_memory_region(&hipc_log_buf[HIPC_LOG_USE], HIPC_LOG_SZ - HIPC_LOG_USE);

	return ret;
}

void run_all_tests_hal_ipc_server_get_radio_channel_stats_callback(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; hal_ipc_server_get_radio_channel_stats_callback_suite[i].test_name != NULL; i++) {
		hipc_grcs_test_case_t *test = &hal_ipc_server_get_radio_channel_stats_callback_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		construct_hal_ipc_server_get_radio_channel_stats_callback_input(test);

		int ret = test_hal_ipc_server_get_radio_channel_stats_callback();

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
	printf("\nhal_ipc_server_get_radio_channel_stats_callback: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}
