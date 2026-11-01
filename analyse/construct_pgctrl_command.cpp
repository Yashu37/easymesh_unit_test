/*
 * TEST CASES / CONSTRUCTOR: construct_pgctrl_command
 *
 * pgctrl_command(file, format, ...) formats into cmd[512] and writes
 * strlen(cmd) bytes. file / format / the %s argument are runner buffers.
 *
 * Cases: open fails, "start\n", "%s" + 100-char arg, "%s" with a 511-char
 * arg (fits exactly), 512-char arg (truncated to 511), 4000-char arg,
 * "add_device %s@%d\n" with an int, write fails, and a 4000-char path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   pgc_slot[PGC_SLOT_SZ + PGC_SLOT_PAD];
char   pgc_out[PGC_SLOT_SZ + PGC_SLOT_PAD];
size_t pgc_out_len, pgc_open_path_len;
int    pgc_vs_ret, pgc_open_fail, pgc_write_fail;
char   pgc_file[PGC_STR_SZ];
char   pgc_fmt[PGC_STR_SZ];
char   pgc_arg[PGC_STR_SZ];

pgctrl_command_test_case_t pgctrl_command_suite[] = {
    /* name             kind arg_len path_len open_fail write_fail ret out_len */
    { "open_fails",       0,    0,     0,       1,        0,      -1,   0 },
    { "start",            0,    0,     0,       0,        0,       0,   6 },
    { "arg_100",          1,  100,     0,       0,        0,       0, 100 },
    { "arg_511",          1,  511,     0,       0,        0,       0, 511 },
    { "arg_512",          1,  512,     0,       0,        0,       0, 511 },
    { "arg_4000",         1, 4000,     0,       0,        0,       0, 511 },
    { "fmt_with_int",     2,   10,     0,       0,        0,       0,  24 },
    { "write_fails",      0,    0,     0,       0,        1,      -1,   6 },
    { "path_4000",        0,    0,  4000,       0,        0,       0,   6 },

    { NULL, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_pgctrl_command_input(const pgctrl_command_test_case_t *tc)
{
    memset(pgc_file, 0, sizeof(pgc_file));
    memset(pgc_fmt, 0, sizeof(pgc_fmt));
    memset(pgc_arg, 0, sizeof(pgc_arg));
    if (tc->path_len) memset(pgc_file, 'p', (size_t)tc->path_len);
    else snprintf(pgc_file, sizeof(pgc_file), "/proc/net/pktgen/pgctrl");
    switch (tc->kind) {
    case 0: snprintf(pgc_fmt, sizeof(pgc_fmt), "start\n"); break;
    case 1: snprintf(pgc_fmt, sizeof(pgc_fmt), "%%s"); break;
    case 2: snprintf(pgc_fmt, sizeof(pgc_fmt), "add_device %%s@%%d\n"); break;
    }
    memset(pgc_arg, 'a', (size_t)tc->arg_len);
    pgc_open_fail  = tc->open_fail;
    pgc_write_fail = tc->write_fail;
    pgc_out_len = 0; pgc_open_path_len = 0; pgc_vs_ret = 0;
}
