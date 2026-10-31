/*
 * TEST RUNNER: log_dynamic_update_test
 *
 * log_dynamic_update's only caller-owned output is new_trigger (an int*).
 * We back it in a larger buffer and poison past the int so a stray write
 * would abort. The severity[256]/remote_name[64] arrays are internal and
 * auto-guarded by ASan; the long_name / long_severity cases stress their
 * bounded snprintf/parse writes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool log_dynamic_update(int *new_trigger);

static unsigned char ldu_trig_backing[sizeof(int) + 32];

int test_log_update(const log_update_test_case_t *tc)
{
    int *trig = (int *)ldu_trig_backing;
    memset(ldu_trig_backing, 0, sizeof(ldu_trig_backing));

    /* poison memory past the int new_trigger (over-write guard) */
    __asan_poison_memory_region(ldu_trig_backing + sizeof(int),
                                sizeof(ldu_trig_backing) - sizeof(int));

    bool ret = log_dynamic_update(trig);

    int trigger = *trig;
    __asan_unpoison_memory_region(ldu_trig_backing + sizeof(int),
                                  sizeof(ldu_trig_backing) - sizeof(int));

    printf("    ret=%d new_trigger=%d local=\"%s\" remote=\"%s\"\n",
           ret, trigger, ldu_last_local, ldu_last_remote);
    return ret ? 1 : 0;
}

void run_all_tests_log_update(void)
{
    for (int i = 0; log_update_suite[i].test_name != NULL; i++) {
        log_update_test_case_t *test = &log_update_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_log_update_input(test);

        int got = test_log_update(test);

        if (got == test->expect_ret) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect_ret, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
