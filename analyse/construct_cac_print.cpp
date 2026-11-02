/*
 * TEST CASES / CONSTRUCTOR: construct_cac_print
 *
 * The format and its %s argument come from poisoned runner buffers. A short
 * arg fits in buff[256]; a long arg (cac_big) makes the unbounded vsprintf
 * overflow buff.
 *
 * Cases: short literal, short %s, medium %s (~150, still fits after the
 * ~23-char timestamp+space), and LONG %s (~400) which overflows buff[256].
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char cac_log_path[64] = "/tmp/cac_print_test.log";
alignas(16) char cac_fmt_buf[CAC_FMT_MAX + CAC_PAD];
alignas(16) char cac_arg_buf[CAC_ARG_MAX + CAC_PAD];

cac_print_test_case_t cac_print_suite[] = {
    /* name         fmt         arg_len  overflow */
    { "short_lit",  "hello\n",  0,       0 },
    { "short_s",    "%s\n",     10,      0 },
    { "medium_s",   "%s\n",     150,     0 },
    { "long_s",     "%s\n",     400,     1 },   /* unbounded vsprintf overflows buff[256] */

    { NULL, NULL, 0, 0 }  /* sentinel */
};

void construct_cac_print_input(const cac_print_test_case_t *tc)
{
    memset(cac_fmt_buf, 0, sizeof(cac_fmt_buf));
    memset(cac_arg_buf, 0, sizeof(cac_arg_buf));
    snprintf(cac_fmt_buf, CAC_FMT_MAX, "%s", tc->fmt);
    if (tc->arg_len > 0) {
        memset(cac_arg_buf, 'A', tc->arg_len);
        cac_arg_buf[tc->arg_len] = 0;
    }
}
