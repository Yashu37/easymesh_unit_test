/*
 * TEST CASES / CONSTRUCTOR: construct_logger_traceback_log
 *
 * logger_traceback_log stores high-severity messages into a static ring
 * msgs[32][1024] and, on a severe (<=WARNING) message, flushes them via
 * mlog. Cases run IN ORDER (the ring state persists):
 *   store_1, store_2            -> 2 entries buffered (no flush)
 *   tb_module                   -> early return (traceback module)
 *   flush                       -> flushes the 2 entries  (flush_count=2)
 *   wrap_40 (repeat 40 stores)  -> fills/wraps the 32-slot ring (no flush)
 *   flush_all                   -> flushes all 32         (flush_count=32)
 *   long_text                   -> stores a >1024 text (bounded snprintf)
 *
 * severity > WARNING(4) = store; <= WARNING = flush. lm_tag/lm_text are
 * runner-owned (poisoned tails).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

#define TB_MODULE_TRACEBACK 99
#define TB_WARNING          4

char         ltb_tag[64];
char         ltb_text[4096];
size_t       ltb_tag_len, ltb_text_len;
logger_msg_t ltb_msg;
int          ltb_repeat;
int          tb_flush_count;
const char  *ltb_case_name;

logger_tb_test_case_t logger_tb_suite[] = {
    /* name          module              severity  tag     text       fill  repeat  expect_flush */
    { "store_1",      0,                  7,        "T1",   "first",    0,    1,      0 },
    { "store_2",      0,                  7,        "T2",   "second",   0,    1,      0 },
    { "tb_module",    TB_MODULE_TRACEBACK,7,        "T3",   "ignored",  0,    1,      0 },
    { "flush",        0,                  3,        "F",    "x",        0,    1,      2 },
    { "wrap_40",      0,                  7,        "W",    "w",        0,    40,     0 },
    { "flush_all",    0,                  3,        "F",    "x",        0,    1,      32 },
    { "long_text",    0,                  7,        "L",    "X",        2000, 1,      0 },

    { NULL, 0, 0, NULL, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_logger_tb_input(const logger_tb_test_case_t *tc)
{
    ltb_case_name = tc->test_name;
    ltb_repeat = tc->repeat;

    snprintf(ltb_tag, sizeof(ltb_tag), "%s", tc->tag);
    memset(ltb_text, 0, sizeof(ltb_text));
    if (tc->fill > 0) {
        int n = 0;
        while (n < tc->fill && (size_t)(n + 1) < sizeof(ltb_text)) ltb_text[n++] = 'X';
        ltb_text[n] = '\0';
    } else {
        snprintf(ltb_text, sizeof(ltb_text), "%s", tc->text);
    }
    ltb_tag_len  = strlen(ltb_tag);
    ltb_text_len = strlen(ltb_text);

    ltb_msg.lm_tag      = ltb_tag;
    ltb_msg.lm_text     = ltb_text;
    ltb_msg.lm_module   = tc->module;
    ltb_msg.lm_severity = tc->severity;
}
