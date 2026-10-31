/*
 * TEST CASES / CONSTRUCTOR: construct_osp_unit_dhcpc_hostname_get
 *
 * osp_unit_dhcpc_hostname_get(buff, buffsz) writes "<serial>_<model>" into
 * buff. Cases vary buffsz (roomy, tight, size 1), make the combined string
 * longer than buffsz (snprintf must truncate), and make each getter fail.
 * The stub serial/model values and the ok-flags are set per case.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* stub knobs read by the handler */
const char *osp_stub_serial = "SN12345";
const char *osp_stub_model  = "ModelX";
int         osp_stub_serial_ok = 1;
int         osp_stub_model_ok  = 1;

size_t      ohg_buffsz;
const char *ohg_case_name;

osp_hostname_test_case_t osp_hostname_suite[] = {
    /* name              buffsz  serial       model      ser_ok mod_ok  expect_ret */
    { "roomy_64",         64,    "SN12345",   "ModelX",   1, 1,   1 },
    { "tight_8",          8,     "SN12345",   "ModelX",   1, 1,   1 },  /* truncated */
    { "size_1",           1,     "SN12345",   "ModelX",   1, 1,   1 },  /* only NUL written */
    { "long_values",      16,    "SERIAL_LONG_123","MODEL_LONG_ABC", 1, 1, 1 }, /* > buffsz -> truncate */
    { "serial_fail",      64,    "SN12345",   "ModelX",   0, 1,   0 },
    { "model_fail",       64,    "SN12345",   "ModelX",   1, 0,   0 },

    { NULL, 0, NULL, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_osp_hostname_input(const osp_hostname_test_case_t *tc)
{
    ohg_case_name     = tc->test_name;
    ohg_buffsz        = tc->buffsz;
    osp_stub_serial   = tc->serial;
    osp_stub_model    = tc->model;
    osp_stub_serial_ok = tc->ser_ok;
    osp_stub_model_ok  = tc->mod_ok;
}
