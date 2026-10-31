/*
 * TEST CASES / CONSTRUCTOR: construct_mlog
 *
 * mlog(sev, module, fmt, ...) formats buff[8192]/timestr[80]/se_tag[64].
 * Cases: a normal message, an EMPTY fmt (exercises the strip = &buff[-1]
 * edge), a HUGE %s text (> buff), a module id out of range (clamped), and
 * a disabled severity (early return). The %s payload is a runner-owned
 * buffer whose tail is poisoned by the runner.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* mlog capture globals (defined here, read by test; used by the handler cb) */
int  mlog_captured;
char mlog_captured_text[8300];
char mlog_captured_tag[128];

char        mlog_payload[16384];   /* %s payload (poisoned tail) */
size_t      mlog_payload_len;
const char *mlog_case_name;

mlog_test_case_t mlog_suite[] = {
    /* name            sev  module  kind           payload_fill  expect_captured */
    { "normal",        1,   1,      MLOG_NORMAL,    0,            1 },  /* INFO/WIFI "hello 42" */
    { "empty_fmt",     1,   1,      MLOG_EMPTY,     0,            1 },  /* buff="" edge */
    { "huge_text",     1,   1,      MLOG_LONG,      12000,        1 },  /* > buff[8192] -> truncated */
    { "module_oob",    1,   99,     MLOG_NORMAL,    0,            1 },  /* module clamped to MISC */
    { "disabled_sev",  0,   1,      MLOG_NORMAL,    0,            0 },  /* LOG_SEVERITY_DISABLED -> early return */

    { NULL, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_mlog_input(const mlog_test_case_t *tc)
{
    mlog_case_name = tc->test_name;
    memset(mlog_payload, 0, sizeof(mlog_payload));
    if (tc->payload_fill > 0) {
        int n = 0;
        while (n < tc->payload_fill && (size_t)(n + 1) < sizeof(mlog_payload)) mlog_payload[n++] = 'X';
        mlog_payload[n] = '\0';
    }
    mlog_payload_len = strlen(mlog_payload);
}
