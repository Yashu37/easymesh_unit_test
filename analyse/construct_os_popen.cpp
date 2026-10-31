/*
 * TEST CASES / CONSTRUCTOR: construct_os_popen
 *
 * os_popen(shell_cmd, &fd) forks a child running the command via
 * /bin/sh -c and returns its pid plus a read fd. Cases exercise simple
 * output, multi-line output, large output, no output, and a command that
 * exits non-zero. The constructor just selects the command; the runner
 * calls os_popen, drains the pipe and reaps the child.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

const char *osp_cmd;
const char *osp_case_name;

os_popen_test_case_t os_popen_suite[] = {
    /* name              shell_cmd                      expect_output (bytes>0?) */
    { "echo_hello",      "echo hello",                   1 },
    { "multi_line",      "printf 'a\\nb\\nc\\n'",        1 },
    { "large_output",    "seq 1 3000",                   1 },
    { "no_output_true",  "true",                         0 },
    { "nonzero_exit",    "echo oops; exit 3",            1 },

    { NULL, NULL, 0 }  /* sentinel */
};

void construct_os_popen_input(const os_popen_test_case_t *tc)
{
    osp_case_name = tc->test_name;
    osp_cmd       = tc->shell_cmd;
}
