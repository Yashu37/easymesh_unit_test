/*
 * TEST CASES / CONSTRUCTOR: construct_os_cmd_exec_xv
 *
 * os_cmd_exec_xv(buffer, len, exit_code, flags, fmt, va_list) builds the
 * command with vsnprintf into cmd1[256], runs it via popen, and collects
 * output into a growing heap buffer. Cases:
 *   - short commands (cmd1 path)
 *   - a command LONGER than 256 via a big %s arg -> triggers the
 *     alloca()+second-vsnprintf path that reuses the consumed va_list
 *   - large command output (multi-chunk fread/realloc loop)
 *   - failing command with/without OS_CMD_FLAG_ANY_EXIT_CODE
 *
 * The %s argument string is runner-owned (g_arg), so its tail is poisoned
 * by the runner to catch any over-read by vsnprintf.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        g_arg[1024];        /* the %s argument (poisoned tail) */
size_t      g_arg_len;          /* its content length             */
const char *oce_case_name;

os_cmd_exec_test_case_t os_cmd_exec_suite[] = {
    /* name              fmt            arg_fill  arg_len  flags                    expect_ret */
    { "echo_hello",      "echo hello",   0,       0,       0,                        1 },
    { "echo_arg_world",  "echo %s",      'w',     5,       0,                        1 },  /* short %s */
    { "long_arg_alloca", "echo %s",      'A',     300,     0,                        1 },  /* >256 -> alloca + va reuse */
    { "big_output",      "seq 1 2000",   0,       0,       0,                        1 },  /* multi-chunk output */
    { "false_default",   "false",        0,       0,       0,                        0 },  /* nonzero exit -> false */
    { "false_any_exit",  "false",        0,       0,       OS_CMD_FLAG_ANY_EXIT_CODE,1 },  /* accept nonzero exit */

    { NULL, NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_os_cmd_exec_xv_input(const os_cmd_exec_test_case_t *tc)
{
    oce_case_name = tc->test_name;

    memset(g_arg, 0, sizeof(g_arg));
    g_arg_len = tc->arg_len;
    if (tc->arg_len > 0) {
        size_t n = tc->arg_len;
        if (n >= sizeof(g_arg)) n = sizeof(g_arg) - 1;
        memset(g_arg, tc->arg_fill, n);
        g_arg[n] = '\0';
        g_arg_len = n;
    }
}
