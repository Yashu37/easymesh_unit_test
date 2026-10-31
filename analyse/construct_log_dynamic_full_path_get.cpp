/*
 * TEST CASES / CONSTRUCTOR: construct_log_dynamic_full_path_get
 *
 * log_dynamic_full_path_get(buf, len) writes "<dir>/<name>-<ts>.dump" into
 * buf, bounded by len. Cases vary len (roomy, tight, 1) to exercise the
 * bounded snprintf into the caller buffer. The runner owns buf and poisons
 * the tail past len.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int         ldfp_len;
const char *ldfp_case_name;

log_fullpath_test_case_t log_fullpath_suite[] = {
    /* name          len */
    { "roomy_128",   128 },
    { "tight_20",    20  },
    { "size_1",      1   },
    { "size_4",      4   },

    { NULL, 0 }  /* sentinel */
};

void construct_log_fullpath_input(const log_fullpath_test_case_t *tc)
{
    ldfp_case_name = tc->test_name;
    ldfp_len = tc->len;
}
