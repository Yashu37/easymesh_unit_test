/*
 * TEST RUNNER: os_name_to_pid_test
 *
 * Caller input is proc_name; we poison its tail past the terminator so any
 * over-read (e.g. by strcmp) is flagged. The internal rbuff[1024] is
 * auto-guarded by ASan. PASS = a pid was found exactly when expected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

pid_t os_name_to_pid(const char *proc_name);

int test_os_name_pid(const os_name_pid_test_case_t *tc)
{
    __asan_poison_memory_region(&onp_name[onp_name_len + 1],
                                sizeof(onp_name) - (onp_name_len + 1));

    pid_t pid = os_name_to_pid(onp_name);

    __asan_unpoison_memory_region(&onp_name[onp_name_len + 1],
                                  sizeof(onp_name) - (onp_name_len + 1));

    int found = (pid > 0) ? 1 : 0;
    printf("    name=\"%s\" -> pid=%d\n", onp_name, (int)pid);
    return found;
}

void run_all_tests_os_name_pid(void)
{
    for (int i = 0; os_name_pid_suite[i].test_name != NULL; i++) {
        os_name_pid_test_case_t *test = &os_name_pid_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_name_pid_input(test);

        int found = test_os_name_pid(test);

        if (found == test->expect_found) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected_found=%d, got=%d) =====\n",
                   test->test_name, test->expect_found, found);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
