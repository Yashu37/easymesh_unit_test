/*
 * TEST CASES / CONSTRUCTOR: construct_log_dynamic_state_handler
 *
 * Drives the libev state handler through its branches via test knobs:
 *   - update returns false        -> early return
 *   - update true, trigger fires  -> builds full_path, fopen, callback
 *   - no callback / not-greater   -> condition false, no dump
 *
 * /tmp/logdump is created so the dump fopen succeeds and the callback runs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int lds_update_ret;
int lds_new_trigger;
int lds_cb_count;
const char *lds_case_name;

void lds_setup(const char *dir, int trigger_value, int have_cb);

log_state_test_case_t log_state_suite[] = {
    /* name            update_ret  new_trigger  trig_value  have_cb  expect_cb */
    { "trigger_fires",     1,         5,          0,          1,       1 },
    { "no_update",         0,         5,          0,          1,       0 },
    { "no_callback",       1,         5,          0,          0,       0 },
    { "not_greater",       1,         0,          0,          1,       0 },

    { NULL, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_log_state_input(const log_state_test_case_t *tc)
{
    lds_case_name   = tc->test_name;
    lds_update_ret  = tc->update_ret;
    lds_new_trigger = tc->new_trigger;
    lds_cb_count    = 0;

    mkdir("/tmp/logdump", 0777);   /* so the dump fopen can succeed */
    lds_setup("/tmp/logdump", tc->trig_value, tc->have_cb);
}
