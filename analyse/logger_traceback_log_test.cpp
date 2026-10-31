/*
 * TEST RUNNER: logger_traceback_log_test
 *
 * Caller inputs are msg->lm_tag / lm_text; we poison each one's tail past
 * its terminator so any over-read by the snprintf is flagged. The static
 * ring msgs[32][1024] is auto-guarded by ASan. For wrap_40 we call the
 * handler `repeat` times to exercise the ring wrap. PASS = the flush count
 * matches (and no ASan abort).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void logger_traceback_log(logger_t *l, logger_msg_t *msg);

int test_logger_tb(const logger_tb_test_case_t *tc)
{
    __asan_poison_memory_region(&ltb_tag[ltb_tag_len + 1],   sizeof(ltb_tag)  - (ltb_tag_len + 1));
    __asan_poison_memory_region(&ltb_text[ltb_text_len + 1], sizeof(ltb_text) - (ltb_text_len + 1));

    for (int r = 0; r < ltb_repeat; r++)
        logger_traceback_log(NULL, &ltb_msg);

    __asan_unpoison_memory_region(&ltb_tag[ltb_tag_len + 1],   sizeof(ltb_tag)  - (ltb_tag_len + 1));
    __asan_unpoison_memory_region(&ltb_text[ltb_text_len + 1], sizeof(ltb_text) - (ltb_text_len + 1));

    printf("    flush_count=%d (repeat=%d)\n", tb_flush_count, ltb_repeat);
    return tb_flush_count;
}

void run_all_tests_logger_tb(void)
{
    for (int i = 0; logger_tb_suite[i].test_name != NULL; i++) {
        logger_tb_test_case_t *test = &logger_tb_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        tb_flush_count = 0;
        construct_logger_tb_input(test);

        int flushed = test_logger_tb(test);

        if (flushed == test->expect_flush) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected_flush=%d, got=%d) =====\n",
                   test->test_name, test->expect_flush, flushed);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
