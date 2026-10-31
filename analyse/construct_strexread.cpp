/*
 * TEST CASES / CONSTRUCTOR: construct_strexread
 *
 * strexread(prog, argv) execvp's prog with argv and returns its captured
 * stdout (heap) or NULL. Cases: a simple command, multiple args, large
 * output, a non-existent program, a command that exits non-zero, and the
 * prog==NULL / argv==NULL guards.
 *
 * The caller-owned inputs are prog and the argv array; the runner copies
 * prog into a runner-owned buffer and builds a runner-owned argv array,
 * then poisons their tails.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* runner-owned storage (poisoned by the runner) */
char        sxr_prog[256];          /* prog string            */
size_t      sxr_prog_len;
char        sxr_args[8][256];       /* up to 7 argv strings   */
const char *sxr_argv[8];            /* argv array (NULL-term)  */
int         sxr_argc;               /* number of argv entries (excl NULL) */
int         sxr_prog_null;          /* pass prog = NULL        */
int         sxr_argv_null;          /* pass argv = NULL        */
const char *sxr_case_name;

strexread_test_case_t strexread_suite[] = {
    /* name              prog        a0       a1     a2     mode             expect_nonnull */
    { "echo_hello",      "echo",     "echo",  "hi",  NULL,  SXR_NORMAL,      1 },
    { "echo_multi",      "echo",     "echo",  "a",   "bb",  SXR_NORMAL,      1 },
    { "seq_large",       "seq",      "seq",   "1",   "3000",SXR_NORMAL,      1 },
    { "false_cmd",       "false",    "false", NULL,  NULL,  SXR_NORMAL,      0 },  /* exit 1 -> NULL */
    { "nonexistent",     "no_such_cmd_xyz","no_such_cmd_xyz",NULL,NULL, SXR_NORMAL, 0 },
    { "prog_null",       NULL,       "x",     NULL,  NULL,  SXR_PROG_NULL,   0 },
    { "argv_null",       "echo",     NULL,    NULL,  NULL,  SXR_ARGV_NULL,   0 },

    { NULL, NULL, NULL, NULL, NULL, 0, 0 }  /* sentinel */
};

void construct_strexread_input(const strexread_test_case_t *tc)
{
    sxr_case_name  = tc->test_name;
    sxr_prog_null  = (tc->mode == SXR_PROG_NULL);
    sxr_argv_null  = (tc->mode == SXR_ARGV_NULL);

    memset(sxr_prog, 0, sizeof(sxr_prog));
    if (tc->prog) {
        snprintf(sxr_prog, sizeof(sxr_prog), "%s", tc->prog);
    }
    sxr_prog_len = strlen(sxr_prog);

    const char *in[3] = { tc->a0, tc->a1, tc->a2 };
    sxr_argc = 0;
    for (int k = 0; k < 3 && in[k] != NULL; k++) {
        snprintf(sxr_args[sxr_argc], sizeof(sxr_args[sxr_argc]), "%s", in[k]);
        sxr_argv[sxr_argc] = sxr_args[sxr_argc];
        sxr_argc++;
    }
    sxr_argv[sxr_argc] = NULL;   /* NULL-terminate argv */
}
