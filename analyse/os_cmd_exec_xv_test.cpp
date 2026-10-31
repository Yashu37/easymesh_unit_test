/*
 * TEST RUNNER: os_cmd_exec_xv_test
 *
 * os_cmd_exec_xv takes a va_list; we build one with a small variadic
 * wrapper. The only runner-owned buffer the function reads is the %s
 * argument string (g_arg) -- so, base64_encode style, we poison g_arg's
 * tail beyond its content length before the call, so any over-read of the
 * argument (e.g. by the second vsnprintf on the long-command path that
 * reuses the consumed va_list) is flagged by ASan. The internal cmd1[256]
 * and the heap output buffer are auto-guarded by ASan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool os_cmd_exec_xv(char **buffer, int *len, int *exit_code, int flags, char *fmt, va_list args);

/* variadic wrapper that constructs the va_list for the function under test */
static bool call_exec(char **buf, int *len, int *ec, int flags, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    bool r = os_cmd_exec_xv(buf, len, ec, flags, (char *)fmt, ap);
    va_end(ap);
    return r;
}

int test_os_cmd_exec_xv(const os_cmd_exec_test_case_t *tc)
{
    char *out = NULL;
    int   len = -1, ec = -1;
    bool  ret;

    if (tc->arg_len > 0) {
        /* poison everything past the argument's content so an over-read aborts */
        __asan_poison_memory_region(&g_arg[g_arg_len + 1],
                                    sizeof(g_arg) - (g_arg_len + 1));

        ret = call_exec(&out, &len, &ec, tc->flags, tc->fmt, g_arg);

        __asan_unpoison_memory_region(&g_arg[g_arg_len + 1],
                                      sizeof(g_arg) - (g_arg_len + 1));
    } else {
        ret = call_exec(&out, &len, &ec, tc->flags, tc->fmt);
    }

    printf("    ret=%d len=%d exit=%d out=%s\n",
           ret, len, ec, out ? "(got buffer)" : "(null)");
    if (out) free(out);

    return ret ? 1 : 0;
}

void run_all_tests_os_cmd_exec_xv(void)
{
    for (int i = 0; os_cmd_exec_suite[i].test_name != NULL; i++) {
        os_cmd_exec_test_case_t *test = &os_cmd_exec_suite[i];

        printf("--- Running Test: %s  fmt=\"%s\" arg_len=%d ---\n",
               test->test_name, test->fmt, test->arg_len);

        construct_os_cmd_exec_xv_input(test);

        int got = test_os_cmd_exec_xv(test);

        if (got == test->expect_ret) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d, got=%d) =====\n",
                   test->test_name, test->expect_ret, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
