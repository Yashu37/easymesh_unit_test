/*
 * TEST RUNNER: unii_5g_chan2list_test
 *
 * The function takes two ints and returns a pointer into its internal
 * static lists[] table. There is no caller buffer or input array to
 * __asan_poison; ASan's global red-zone around lists[] is the boundary
 * check and is what would catch a read past the -1 terminator.
 *
 * expect == -1 marks the suspected-OOB case (width == 0); if the bug is
 * present ASan aborts the run, so it is ordered last.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

const int *unii_5g_chan2list(int chan, int width);

int test_unii_5g_chan2list(const unii_test_case_t *tc)
{
    if (tc->expect == -1)
        printf("    (this case is suspected to read past the table's -1 terminator)\n");

    const int *r = unii_5g_chan2list(unii_chan, unii_width);

    printf("    chan=%d width=%d -> %s\n", unii_chan, unii_width, r ? "non-NULL" : "NULL");
    return (r != NULL) ? 1 : 0;
}

void run_all_tests_unii_5g_chan2list(void)
{
    for (int i = 0; unii_suite[i].test_name != NULL; i++) {
        unii_test_case_t *test = &unii_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_unii_5g_chan2list_input(test);

        int got = test_unii_5g_chan2list(test);

        if (test->expect == -1) {
            printf("===== %s: \033[33mNO CRASH\033[0m (returned %d) =====\n", test->test_name, got);
        } else if (got == test->expect) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
