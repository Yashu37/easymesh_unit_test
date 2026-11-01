/*
 * TEST CASES / CONSTRUCTOR: construct_os_file_open
 *
 * os_file_open(location, prefix) builds "<location>/<prefix>_<name>_<ts>.<pid>"
 * in file[64] and opens it. Cases: a normal /tmp open, a long prefix that
 * forces file[64] truncation, a long location, and a bad (non-existent)
 * location where fopen fails (returns NULL). location/prefix are
 * runner-owned (poisoned tails).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        ofo_location[256];
char        ofo_prefix[256];
size_t      ofo_loc_len, ofo_pre_len;
const char *ofo_case_name;

os_file_open_test_case_t os_file_open_suite[] = {
    /* name              location   prefix       pre_fill  loc_fill  expect_fp */
    { "normal_tmp",      "/tmp",    "osafile",     0,        0,        1 },
    { "long_prefix",     "/tmp",    "p",           200,      0,        1 },  /* file[64] truncation */
    { "empty_prefix",    "/tmp",    "",            0,        0,        1 },
    { "bad_location",    "/no/such/dir", "osafile", 0,       0,        0 },  /* fopen fails -> NULL */

    { NULL, NULL, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_os_file_open_input(const os_file_open_test_case_t *tc)
{
    ofo_case_name = tc->test_name;

    snprintf(ofo_location, sizeof(ofo_location), "%s", tc->location);
    memset(ofo_prefix, 0, sizeof(ofo_prefix));
    if (tc->pre_fill > 0) {
        int n = 0;
        while (n < tc->pre_fill && (size_t)(n + 1) < sizeof(ofo_prefix)) ofo_prefix[n++] = 'p';
        ofo_prefix[n] = '\0';
    } else {
        snprintf(ofo_prefix, sizeof(ofo_prefix), "%s", tc->prefix);
    }

    ofo_loc_len = strlen(ofo_location);
    ofo_pre_len = strlen(ofo_prefix);
}
