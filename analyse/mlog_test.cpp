/*
 * TEST RUNNER: mlog_test
 *
 * mlog is variadic (extern "C", called with int sev/module). The caller
 * input we can poison is the %s payload buffer; its tail is poisoned so any
 * over-read by vsnprintf aborts. The internal buff/timestr/se_tag are
 * auto-guarded by ASan; huge_text stresses the bounded vsnprintf and
 * empty_fmt exercises the strip=&buff[-1] edge.
 *
 * PASS = the registered logger captured a message exactly when mlog did not
 * early-return.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

extern "C" void mlog(int sev, int module, const char *fmt, ...);

int test_mlog(const mlog_test_case_t *tc)
{
    mlog_captured = 0;
    mlog_captured_text[0] = 0;

    int poisoned = 0;
    if (tc->kind == MLOG_LONG) {
        __asan_poison_memory_region(&mlog_payload[mlog_payload_len + 1],
                                    sizeof(mlog_payload) - (mlog_payload_len + 1));
        poisoned = 1;
    }

    switch (tc->kind) {
        case MLOG_NORMAL: mlog(tc->sev, tc->module, "hello %d", 42);     break;
        case MLOG_EMPTY:  mlog(tc->sev, tc->module, "");                 break;
        case MLOG_LONG:   mlog(tc->sev, tc->module, "%s", mlog_payload); break;
        default:          mlog(tc->sev, tc->module, "x");                break;
    }

    if (poisoned)
        __asan_unpoison_memory_region(&mlog_payload[mlog_payload_len + 1],
                                      sizeof(mlog_payload) - (mlog_payload_len + 1));

    printf("    captured=%d tag=\"%s\" text_len=%zu\n",
           mlog_captured, mlog_captured_tag, strlen(mlog_captured_text));
    return mlog_captured;
}

void run_all_tests_mlog(void)
{
    for (int i = 0; mlog_suite[i].test_name != NULL; i++) {
        mlog_test_case_t *test = &mlog_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_mlog_input(test);

        int cap = test_mlog(test);

        if (cap == test->expect_captured) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected_captured=%d, got=%d) =====\n",
                   test->test_name, test->expect_captured, cap);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
