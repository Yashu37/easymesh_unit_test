/*
 * TEST CASES / CONSTRUCTOR: construct_log_dynamic_update
 *
 * Drives log_dynamic_update through: no-json (goto out, empty severities),
 * json-ok with a normal severity + trigger, and a VERY LONG log_name that
 * stresses the remote_name[64] snprintf (must truncate), plus a long
 * severity value that stresses the [256] severity buffers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int         ldu_json_ok;
const char *ldu_sev_value;
int         ldu_parse_trigger;
char        ldu_last_local[320];
char        ldu_last_remote[320];
const char *ldu_case_name;

void ldu_set_log_name(const char *name);

/* a >64-char name to stress remote_name[64] */
static const char *LONG_NAME =
    "this_is_a_really_long_process_name_well_over_sixty_four_characters_xxxxx";

log_update_test_case_t log_update_suite[] = {
    /* name              json_ok  sev_value   trigger  use_long_name  expect_ret */
    { "no_json",          0,      "",          0,       0,             1 },
    { "json_debug",       1,      "DEBUG",     3,       0,             1 },
    { "long_name",        1,      "INFO",      1,       1,             1 },  /* remote_name[64] truncation */
    { "long_severity",    1,      "SEVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", 0, 0, 1 },

    { NULL, 0, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_log_update_input(const log_update_test_case_t *tc)
{
    ldu_case_name     = tc->test_name;
    ldu_json_ok       = tc->json_ok;
    ldu_sev_value     = tc->sev_value;
    ldu_parse_trigger = tc->trigger;
    memset(ldu_last_local, 0, sizeof(ldu_last_local));
    memset(ldu_last_remote, 0, sizeof(ldu_last_remote));
    ldu_set_log_name(tc->use_long_name ? LONG_NAME : "OneWifi");
}
