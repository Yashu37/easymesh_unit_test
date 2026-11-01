/*
 * TEST RUNNER: pktgen_is_running_test
 *
 * Poisoned around the call:
 *   - the file content buffer pgr_data past its content (input);
 *   - inside the handler: the fgets slot past 512 and the sscanf slot past
 *     512 (= sizeof(str) / sizeof(run_if)).
 * str / run_if are internal (auto-guarded by ASan).
 * PASS = return matches and run_if length matches (<= 511).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int onewifi_pktgen_is_running(void);

int test_pktgen_is_running(const pktgen_is_running_test_case_t *tc)
{
    __asan_poison_memory_region(&pgr_data[pgr_data_len], sizeof(pgr_data) - pgr_data_len);

    int ret = onewifi_pktgen_is_running();

    __asan_unpoison_memory_region(&pgr_data[pgr_data_len], sizeof(pgr_data) - pgr_data_len);

    printf("    ret=%d str_len=%zu run_if_len=%zu\n", ret, pgr_str_len, pgr_if_len);
    return ret == tc->expect_ret && pgr_if_len == (size_t)tc->expect_if && pgr_str_len <= 511;
}

void run_all_tests_pktgen_is_running(void)
{
    for (int i = 0; pktgen_is_running_suite[i].test_name != NULL; i++) {
        pktgen_is_running_test_case_t *test = &pktgen_is_running_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_pktgen_is_running_input(test);

        int pass = test_pktgen_is_running(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d run_if_len=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_if);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
