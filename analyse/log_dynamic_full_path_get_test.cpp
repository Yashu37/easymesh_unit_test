/*
 * TEST RUNNER: log_dynamic_full_path_get_test
 *
 * The caller-owned output is buf. We back it with a larger buffer and
 * poison everything past the len we pass in, so if the function's snprintf
 * writes beyond len ASan aborts. The internal timestamp[64] is auto-guarded.
 *
 * PASS: with len > 0, the result must be NUL-terminated within len.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void log_dynamic_full_path_get(char *buf, int len);

static char ldfp_backing[256];

int test_log_fullpath(const log_fullpath_test_case_t *tc)
{
    int len = ldfp_len;
    if (len > (int)sizeof(ldfp_backing)) len = sizeof(ldfp_backing);

    memset(ldfp_backing, 0, sizeof(ldfp_backing));
    __asan_poison_memory_region(&ldfp_backing[len], sizeof(ldfp_backing) - len);

    log_dynamic_full_path_get(ldfp_backing, len);

    size_t n = strnlen(ldfp_backing, len);
    int ok = (len == 0) ? 1 : (n < (size_t)len);

    char shown[64];
    snprintf(shown, sizeof(shown), "%.*s", (int)(n < 63 ? n : 63), ldfp_backing);

    __asan_unpoison_memory_region(&ldfp_backing[len], sizeof(ldfp_backing) - len);

    printf("    len=%d buf=\"%s\" (strlen=%zu)\n", len, shown, n);
    return ok;
}

void run_all_tests_log_fullpath(void)
{
    for (int i = 0; log_fullpath_suite[i].test_name != NULL; i++) {
        log_fullpath_test_case_t *test = &log_fullpath_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_log_fullpath_input(test);

        int ok = test_log_fullpath(test);

        if (ok) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (not terminated within len) =====\n", test->test_name);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
