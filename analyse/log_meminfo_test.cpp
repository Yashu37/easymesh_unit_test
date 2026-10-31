/*
 * TEST RUNNER: log_meminfo_test
 *
 * The caller-owned output is str. We place it in the middle of a backing
 * buffer (room on both sides) and poison everything OUTSIDE [str, str+size):
 *   - bytes before str  -> catches an index-below-0 write (negative pos)
 *   - bytes after str+size -> catches an over-write
 * The internal buf[1024] is auto-guarded by ASan.
 *
 * expect == -1 marks the suspected OOB (negative pos); ordered last since a
 * hit aborts the run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void log_meminfo(char *str, int size, int pos, const char *str_prefix, const char *str_append);

#define LMI_LEAD 64
static char lmi_backing[64 + 512];

int test_log_meminfo(const log_meminfo_test_case_t *tc)
{
    int size = lmi_size;
    if (size > 512) size = 512;

    char *str = &lmi_backing[LMI_LEAD];
    memset(lmi_backing, 0, sizeof(lmi_backing));

    if (tc->expect == -1)
        printf("    (this case uses a negative pos -> suspected write below index 0)\n");

    /* poison before str (catches below-0) and after str+size (catches over-write) */
    __asan_poison_memory_region(&lmi_backing[0], LMI_LEAD);
    __asan_poison_memory_region(&lmi_backing[LMI_LEAD + size],
                                sizeof(lmi_backing) - (LMI_LEAD + size));

    log_meminfo(str, size, lmi_pos, "MEM", "!");

    int wrote = (lmi_pos < size && lmi_pos >= 0) ? (str[lmi_pos] != 0 ? 1 : 0) : 0;

    __asan_unpoison_memory_region(&lmi_backing[0], LMI_LEAD);
    __asan_unpoison_memory_region(&lmi_backing[LMI_LEAD + size],
                                  sizeof(lmi_backing) - (LMI_LEAD + size));

    printf("    size=%d pos=%d wrote=%d\n", size, lmi_pos, wrote);
    return wrote;
}

void run_all_tests_log_meminfo(void)
{
    for (int i = 0; log_meminfo_suite[i].test_name != NULL; i++) {
        log_meminfo_test_case_t *test = &log_meminfo_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_log_meminfo_input(test);

        int wrote = test_log_meminfo(test);

        if (test->expect == -1) {
            printf("===== %s: \033[33mNO CRASH\033[0m (wrote=%d) =====\n", test->test_name, wrote);
        } else if (wrote == test->expect) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect, wrote);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
