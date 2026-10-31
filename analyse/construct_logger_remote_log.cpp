/*
 * TEST CASES / CONSTRUCTOR: construct_logger_remote_log
 *
 * logger_remote_log(self, msg) formats "[tid] ts name: tag: text" into
 * msg_str[1024]. Cases: a normal message, a VERY LONG text (stresses the
 * bounded snprintf into msg_str), empty fields, and remote-disabled (early
 * return). The three msg strings are runner-owned (poisoned tails).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

extern bool log_remote_enabled;

char            lrl_ts[64];
char            lrl_tag[64];
char            lrl_text[4096];
size_t          lrl_ts_len, lrl_tag_len, lrl_text_len;
logger_msg_t    lrl_msg;
int             lrl_send_count;
const char     *lrl_case_name;

logger_remote_test_case_t logger_remote_suite[] = {
    /* name            ts            tag      text_fill_len  text        enabled  expect_send */
    { "normal",        "2026-11-01", "WIFI",   0,            "hello",     1,       1 },
    { "long_text",     "2026-11-01", "WIFI",   2000,         "X",         1,       1 },  /* > msg_str[1024] */
    { "empty_fields",  "",           "",       0,            "",          1,       1 },
    { "remote_off",    "2026-11-01", "WIFI",   0,            "hi",        0,       0 },  /* early return */

    { NULL, NULL, NULL, 0, NULL, 0, 0 }  /* sentinel */
};

void construct_logger_remote_input(const logger_remote_test_case_t *tc)
{
    lrl_case_name = tc->test_name;
    log_remote_enabled = tc->enabled ? true : false;

    snprintf(lrl_ts,  sizeof(lrl_ts),  "%s", tc->ts);
    snprintf(lrl_tag, sizeof(lrl_tag), "%s", tc->tag);

    memset(lrl_text, 0, sizeof(lrl_text));
    if (tc->text_fill_len > 0) {
        int n = 0;
        while (n < tc->text_fill_len && (size_t)(n + 1) < sizeof(lrl_text)) lrl_text[n++] = 'X';
        lrl_text[n] = '\0';
    } else {
        snprintf(lrl_text, sizeof(lrl_text), "%s", tc->text);
    }

    lrl_ts_len   = strlen(lrl_ts);
    lrl_tag_len  = strlen(lrl_tag);
    lrl_text_len = strlen(lrl_text);

    lrl_msg.lm_timestamp = lrl_ts;
    lrl_msg.lm_tag       = lrl_tag;
    lrl_msg.lm_text      = lrl_text;
}
