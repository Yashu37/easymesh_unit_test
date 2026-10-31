/*
 * TEST CASES / CONSTRUCTOR: construct_cmd_log
 *
 * cmd_log(const char *shell_cmd) reads the command's output into a local
 * buf[1024] via fgets(buf, sizeof(buf), ...). The cases below stress that
 * buffer: empty output, many short lines, and a SINGLE line far longer
 * than 1024 bytes (the only input that could expose a buf overflow).
 *
 * All commands are harmless and succeed, so expected_rc is 0 (pclose
 * returns the child's exit status). The real question is whether cmd_log
 * accesses buf out of bounds -> ASan would abort.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

const char *cmdlog_cmd;       /* current command (declared extern in common.h) */
const char *cmdlog_case_name;

cmd_log_test_case_t cmd_log_suite[] = {
    /* name                 shell_cmd                                   expected_rc */
    { "echo_hello",         "echo hello",                                0 },
    { "true_no_output",     "true",                                      0 },
    { "empty_echo",         "echo -n ''",                                0 },
    { "many_short_lines",   "seq 1 200",                                 0 },  /* 200 fgets rounds */
    { "line_just_under_1k", "printf 'a%.0s' $(seq 1 1000)",              0 },  /* ~1000-char line  */
    { "line_over_1k",       "printf 'a%.0s' $(seq 1 5000)",              0 },  /* 5000-char line > buf -> split across fgets */
    { "line_exactly_1023",  "printf 'a%.0s' $(seq 1 1023)",              0 },  /* fills buf to the brim */
    { "binary_ish_output",  "printf 'abc\\ndef\\nghi\\n'",               0 },

    { NULL, NULL, 0 }  /* sentinel */
};

void construct_cmd_log_input(const cmd_log_test_case_t *tc)
{
    cmdlog_case_name = tc->test_name;
    cmdlog_cmd       = tc->shell_cmd;
}
