/*
 * TEST RUNNER: log_dynamic_state_handler_test
 *
 * The handler is a libev callback with no caller-owned buffer; its
 * full_path[] array is internal and filled by log_dynamic_full_path_get.
 * To keep the poison coverage, we ALSO run a base64_encode-style poisoned
 * check directly on that array-writer (own a larger buffer, poison past the
 * size we hand it). Then we drive the handler and check the callback fired
 * exactly when expected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void log_dynamic_state_handler(struct ev_loop *loop, ev_stat *watcher, int revents);
void log_dynamic_full_path_get(char *buf, int len);

static char lds_pbuf[256];

static void poisoned_full_path_check(void)
{
    int len = 64;
    __asan_poison_memory_region(&lds_pbuf[len], sizeof(lds_pbuf) - len);
    log_dynamic_full_path_get(lds_pbuf, len);
    __asan_unpoison_memory_region(&lds_pbuf[len], sizeof(lds_pbuf) - len);
}

int test_log_state(const log_state_test_case_t *tc)
{
    /* explicit poisoned-buffer check of the array-writer */
    poisoned_full_path_check();

    /* ev params are unreferenced inside the handler; NULL is fine */
    log_dynamic_state_handler(NULL, NULL, 0);

    printf("    callback invoked %d time(s)\n", lds_cb_count);
    return (lds_cb_count > 0) ? 1 : 0;
}

void run_all_tests_log_state(void)
{
    for (int i = 0; log_state_suite[i].test_name != NULL; i++) {
        log_state_test_case_t *test = &log_state_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_log_state_input(test);

        int got = test_log_state(test);

        if (got == test->expect_cb) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected_cb=%d, got=%d) =====\n",
                   test->test_name, test->expect_cb, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
