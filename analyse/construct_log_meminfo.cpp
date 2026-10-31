/*
 * TEST CASES / CONSTRUCTOR: construct_log_meminfo
 *
 * log_meminfo(str, size, pos, prefix, append) writes a memory-info string
 * into str+pos (bounded by size-pos). Cases: a normal write, a write at a
 * positive offset, pos >= size (early return), and -- the suspected bug --
 * a NEGATIVE pos, which moves str before the caller buffer and writes at an
 * index below 0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int         lmi_size;
int         lmi_pos;
const char *lmi_case_name;

log_meminfo_test_case_t log_meminfo_suite[] = {
    /* name              size   pos    expect (1=wrote, 0=early return, -1=suspected OOB) */
    { "normal",          256,   0,      1 },
    { "pos_offset_10",   256,   10,     1 },
    { "pos_ge_size",     64,    64,     0 },   /* early return */
    /* negative pos LAST: writes below index 0 -> ASan should abort */
    { "negative_pos",    256,  -8,     -1 },

    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_log_meminfo_input(const log_meminfo_test_case_t *tc)
{
    lmi_case_name = tc->test_name;
    lmi_size = tc->size;
    lmi_pos  = tc->pos;
}
