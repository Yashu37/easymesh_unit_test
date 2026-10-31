/*
 * TEST RUNNER: os_popen_test
 *
 * pipefd[2] is internal to os_popen and only indexed [0]/[1], so there is
 * no caller buffer to __asan_poison; ASan auto-guards the stack array. The
 * runner calls os_popen, reads all output from the returned fd into a
 * local buffer (bounded reads), and reaps the child. A valid call must
 * return a pid > 0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

pid_t os_popen(const char *shell_cmd, int *pipe_desc);

static char osp_cmdbuf[512];

int test_os_popen(const os_popen_test_case_t *tc)
{
    /* The caller-owned input is the command string. Copy it into our own
     * buffer and poison the tail past its terminator so any over-read of
     * shell_cmd is flagged by ASan. */
    size_t clen = strlen(osp_cmd);
    if (clen >= sizeof(osp_cmdbuf)) clen = sizeof(osp_cmdbuf) - 1;
    memcpy(osp_cmdbuf, osp_cmd, clen);
    osp_cmdbuf[clen] = '\0';
    __asan_poison_memory_region(&osp_cmdbuf[clen + 1], sizeof(osp_cmdbuf) - (clen + 1));

    int fd = -1;
    pid_t pid = os_popen(osp_cmdbuf, &fd);

    __asan_unpoison_memory_region(&osp_cmdbuf[clen + 1], sizeof(osp_cmdbuf) - (clen + 1));

    if (pid <= 0) {
        printf("    os_popen returned pid=%d (failure)\n", (int)pid);
        return -1;
    }

    /* drain the pipe */
    char   rbuf[512];
    ssize_t n;
    size_t total = 0;
    while ((n = read(fd, rbuf, sizeof(rbuf))) > 0)
        total += (size_t)n;
    close(fd);

    int status = 0;
    waitpid(pid, &status, 0);

    int exited = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("    pid=%d output_bytes=%zu child_exit=%d\n", (int)pid, total, exited);

    /* report whether any output was produced (1) or not (0) */
    return (total > 0) ? 1 : 0;
}

void run_all_tests_os_popen(void)
{
    for (int i = 0; os_popen_suite[i].test_name != NULL; i++) {
        os_popen_test_case_t *test = &os_popen_suite[i];

        printf("--- Running Test: %s  cmd=\"%s\" ---\n", test->test_name, test->shell_cmd);

        construct_os_popen_input(test);

        int got = test_os_popen(test);

        if (got == test->expect_output) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected output=%d, got=%d) =====\n",
                   test->test_name, test->expect_output, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
