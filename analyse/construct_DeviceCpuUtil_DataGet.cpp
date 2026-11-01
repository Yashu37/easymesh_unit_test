/*
 * TEST CASES / CONSTRUCTOR: construct_DeviceCpuUtil_DataGet
 *
 * Writes the case's /proc/stat content to a temp file (dcu_path).
 * The function keeps static state (init + previous counters), so the
 * cases run in order: missing file, first read (init), 50% busy,
 * no change (hz_total 0), 25% busy after a 300-char line, no "cpu " line.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char dcu_path[64] = "/tmp/dcu_proc_stat_test";
char dcu_slot[DCU_SLOT_SZ + DCU_PAD];
int  dcu_lines;
alignas(16) char dcu_util_buf[sizeof(unsigned int) + DCU_PAD];
static char dcu_long[400];

DeviceCpuUtil_DataGet_test_case_t DeviceCpuUtil_DataGet_suite[] = {
    /* name             content                                                    ret    util */
    { "missing_file",   NULL,                                                       false, 0  },
    { "first_read",     "cpu  100 0 100 800 0 0 0\ncpu0 1 2 3 4\n",                 true,  0  },
    { "busy_50",        "cpu  150 0 150 900 0 0 0\n",                               true,  50 },
    { "no_change",      "cpu  150 0 150 900 0 0 0\n",                               true,  0  },
    { "long_line_first", "LONG",                                                    true,  25 },
    { "no_cpu_line",    "intr 1 2 3\nctxt 5\n",                                     true,  77 },   /* util untouched */

    { NULL, NULL, false, 0 }  /* sentinel */
};

void construct_DeviceCpuUtil_DataGet_input(const DeviceCpuUtil_DataGet_test_case_t *tc)
{
    remove(dcu_path);
    if (tc->content) {
        FILE *f = fopen(dcu_path, "w");
        if (!strcmp(tc->content, "LONG")) {
            memset(dcu_long, 'x', 300); dcu_long[300] = 0;          /* 300-char line split by fgets */
            fprintf(f, "intr %s\ncpu  175 0 175 1050 0 0 0\n", dcu_long);   /* +50 busy / +150 idle -> 25% */
        } else {
            fputs(tc->content, f);
        }
        fclose(f);
    }
    memset(dcu_util_buf, 0, sizeof(dcu_util_buf));
    *(unsigned int *)dcu_util_buf = 77;
    dcu_lines = 0;
}
