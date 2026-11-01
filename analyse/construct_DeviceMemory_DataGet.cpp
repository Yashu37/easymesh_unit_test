/*
 * TEST CASES / CONSTRUCTOR: construct_DeviceMemory_DataGet
 *
 * Writes the case's /proc/meminfo content to a temp file (dmg_path).
 *
 * Cases: missing file, normal (Total-Free used), a 300-char leading line
 * (fgets splits it), MemTotal with no parseable value (parse_error), and
 * a file with neither key (util_mem = 0 - 0).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char dmg_path[64] = "/tmp/dmg_meminfo_test";
char dmg_slot[DMG_SLOT_SZ + DMG_PAD];
int  dmg_lines;
alignas(16) char dmg_util_buf[sizeof(unsigned int) + DMG_PAD];
static char dmg_long[400];

DeviceMemory_DataGet_test_case_t DeviceMemory_DataGet_suite[] = {
    /* name            content                                              ret    util       */
    { "missing_file",  NULL,                                                false, 0          },
    { "normal",        "MemTotal: 2000000 kB\nMemFree: 500000 kB\n",        true,  1500000u   },
    { "long_line",     "LONG",                                              true,  800000u    },
    { "parse_error",   "MemTotal: notanumber\n",                            false, 0          },
    { "no_keys",       "Buffers: 100 kB\nCached: 200 kB\n",                 true,  0          },

    { NULL, NULL, false, 0 }  /* sentinel */
};

void construct_DeviceMemory_DataGet_input(const DeviceMemory_DataGet_test_case_t *tc)
{
    remove(dmg_path);
    if (tc->content) {
        FILE *f = fopen(dmg_path, "w");
        if (!strcmp(tc->content, "LONG")) {
            memset(dmg_long, 'x', 300); dmg_long[300] = 0;                     /* 300-char line split by fgets */
            fprintf(f, "%s\nMemTotal: 1000000 kB\nMemFree: 200000 kB\n", dmg_long);  /* 1000000-200000 = 800000 */
        } else {
            fputs(tc->content, f);
        }
        fclose(f);
    }
    memset(dmg_util_buf, 0, sizeof(dmg_util_buf));
    *(unsigned int *)dmg_util_buf = 0xDEAD;   /* sentinel; overwritten only on success */
    dmg_lines = 0;
}
