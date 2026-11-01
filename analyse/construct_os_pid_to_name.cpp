/*
 * TEST CASES / CONSTRUCTOR: construct_os_pid_to_name
 *
 * os_pid_to_name(pid, proc_name, len) reads /proc/<pid>/comm (opened "r+",
 * so only our own process is readable) and copies it into proc_name with
 * strscpy(..., len). Our own comm is "main" (4 chars, needs 5 bytes).
 * The runner treats proc_name as a buffer of exactly buf_size bytes
 * (the rest of the 128-byte runner buffer is poisoned).
 *
 * Cases: buffer 64 / len 64, exact fit (5/5), truncation (4/4, 1/1),
 * len 0, a pid that does not exist, and len < 0 with a 4-byte buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char opn_name[128];
int  opn_pid;

os_pid_to_name_test_case_t os_pid_to_name_suite[] = {
    /* name                pid_kind        buf_size  len  ret */
    { "self_len_64",       OPN_SELF,          64,     64,   0 },
    { "self_exact_5",      OPN_SELF,           5,      5,   0 },
    { "self_trunc_4",      OPN_SELF,           4,      4,   0 },
    { "self_trunc_1",      OPN_SELF,           1,      1,   0 },
    { "self_len_0",        OPN_SELF,           1,      0,   0 },
    { "no_such_pid",       OPN_NONE,          64,     64,  -1 },
    { "self_len_neg1",     OPN_SELF,           4,     -1,  -1 },   /* rejected by the fix (was SIZE_MAX -> overflow) */

    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_os_pid_to_name_input(const os_pid_to_name_test_case_t *tc)
{
    memset(opn_name, 0, sizeof(opn_name));
    opn_pid = (tc->pid_kind == OPN_SELF) ? (int)getpid() : 0x3fffffff;
}
