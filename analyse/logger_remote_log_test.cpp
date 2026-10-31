/*
 * TEST RUNNER: logger_remote_log_test
 *
 * The caller-owned inputs are the three msg strings. We poison each one's
 * tail past its terminator so any over-read by the %s formatting aborts.
 * The internal msg_str[1024] is auto-guarded by ASan (the long_text case
 * stresses its bounded snprintf). PASS = the qm send happened exactly when
 * remote logging is enabled.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void logger_remote_log(logger_t *self, logger_msg_t *msg);

int test_logger_remote(const logger_remote_test_case_t *tc)
{
    __asan_poison_memory_region(&lrl_ts[lrl_ts_len + 1],     sizeof(lrl_ts)   - (lrl_ts_len + 1));
    __asan_poison_memory_region(&lrl_tag[lrl_tag_len + 1],   sizeof(lrl_tag)  - (lrl_tag_len + 1));
    __asan_poison_memory_region(&lrl_text[lrl_text_len + 1], sizeof(lrl_text) - (lrl_text_len + 1));

    logger_remote_log(NULL, &lrl_msg);

    __asan_unpoison_memory_region(&lrl_ts[lrl_ts_len + 1],     sizeof(lrl_ts)   - (lrl_ts_len + 1));
    __asan_unpoison_memory_region(&lrl_tag[lrl_tag_len + 1],   sizeof(lrl_tag)  - (lrl_tag_len + 1));
    __asan_unpoison_memory_region(&lrl_text[lrl_text_len + 1], sizeof(lrl_text) - (lrl_text_len + 1));

    printf("    send_count=%d (text_len=%zu)\n", lrl_send_count, lrl_text_len);
    return (lrl_send_count > 0) ? 1 : 0;
}

void run_all_tests_logger_remote(void)
{
    for (int i = 0; logger_remote_suite[i].test_name != NULL; i++) {
        logger_remote_test_case_t *test = &logger_remote_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        lrl_send_count = 0;
        construct_logger_remote_input(test);

        int sent = test_logger_remote(test);

        if (sent == test->expect_send) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected_send=%d, got=%d) =====\n",
                   test->test_name, test->expect_send, sent);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
