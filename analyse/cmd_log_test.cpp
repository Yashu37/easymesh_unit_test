/*
 * TEST RUNNER: cmd_log_test
 *
 * cmd_log's array buf[1024] is a local (stack) array, which ASan already
 * brackets with red-zones, so there is no caller buffer to poison here:
 * if cmd_log reads or writes buf out of bounds the run aborts on its own.
 * The runner just drives each command and compares the return code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int cmd_log(const char *shell_cmd);

int test_cmd_log(void)
{
    int rc = cmd_log(cmdlog_cmd);
    /* normalise pclose() status to the child's exit code for comparison */
    int code = (rc == -1) ? -1 : (WIFEXITED(rc) ? WEXITSTATUS(rc) : rc);
    printf("rc=%d (exit code=%d)\n", rc, code);
    return code;
}

void run_all_tests_cmd_log(void)
{
    for (int i = 0; cmd_log_suite[i].test_name != NULL; i++) {
        cmd_log_test_case_t *test = &cmd_log_suite[i];

        printf("--- Running Test: %s  cmd=\"%s\" ---\n", test->test_name, test->shell_cmd);

        construct_cmd_log_input(test);

        int code = test_cmd_log();

        if (code == test->expected_rc) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expected_rc, code);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
