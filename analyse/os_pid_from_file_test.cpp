/*
 * TEST RUNNER: os_pid_from_file_test
 *
 * buf[64] is internal to os_pid_from_file and filled by a size-bounded
 * fgets, so there is no caller buffer to __asan_poison; ASan's stack
 * red-zones around buf are the boundary check, and the long_line case
 * feeds >64 bytes to exercise that boundary. The runner drives each pid
 * file and checks whether a (non-zero) pid was returned.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

pid_t os_pid_from_file(char *pid_file);

int test_os_pid_from_file(void)
{
    pid_t ret = os_pid_from_file(ospid_path);
    printf("    returned pid = %ld\n", (long)ret);
    return (ret != 0) ? 1 : 0;
}

void run_all_tests_os_pid_from_file(void)
{
    for (int i = 0; os_pid_suite[i].test_name != NULL; i++) {
        os_pid_test_case_t *test = &os_pid_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_pid_from_file_input(test);

        int nonzero = test_os_pid_from_file();

        /* tidy up temp file */
        if (test->kind != OSPID_MISSING)
            remove(ospid_path);

        if (nonzero == test->expect_nonzero) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected nonzero=%d, got=%d) =====\n",
                   test->test_name, test->expect_nonzero, nonzero);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
