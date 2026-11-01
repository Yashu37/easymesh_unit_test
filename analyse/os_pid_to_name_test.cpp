/*
 * TEST RUNNER: os_pid_to_name_test
 *
 * Caller output is proc_name. The runner hands the function opn_name and
 * POISONS everything past buf_size bytes (the size the caller really owns),
 * so a write past the caller's buffer is flagged by ASan. buf[64] is
 * internal (auto-guarded by ASan).
 * PASS = return matches and the result is NUL-terminated within buf_size.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int32_t os_pid_to_name(pid_t pid, char *proc_name, int32_t len);

int test_os_pid_to_name(const os_pid_to_name_test_case_t *tc)
{
    size_t bs = (size_t)tc->buf_size;

    __asan_poison_memory_region(&opn_name[bs], sizeof(opn_name) - bs);

    int32_t rc = os_pid_to_name((pid_t)opn_pid, opn_name, tc->len);

    __asan_unpoison_memory_region(&opn_name[bs], sizeof(opn_name) - bs);

    size_t l = strnlen(opn_name, bs);
    printf("    pid=%d buf_size=%zu len=%d -> rc=%d name=\"%.*s\"\n",
           opn_pid, bs, tc->len, rc, (int)l, opn_name);
    return (rc == tc->expect_ret) && (tc->len <= 0 || l < bs);
}

void run_all_tests_os_pid_to_name(void)
{
    for (int i = 0; os_pid_to_name_suite[i].test_name != NULL; i++) {
        os_pid_to_name_test_case_t *test = &os_pid_to_name_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_pid_to_name_input(test);

        int pass = test_os_pid_to_name(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected rc=%d) =====\n", test->test_name, test->expect_ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
