/*
 * TEST CASES / CONSTRUCTOR: construct_pktgen_is_running
 *
 * /proc/net/pktgen/kpktgend_0 is served from pgr_data. Its first line
 * "Running: <if>" makes the function return 1.
 *
 * Cases: fopen fails, empty file, "Running: wlan0", "Stopped: ..." line,
 * "Running:" with nothing after, interface of 502 chars (fills str to
 * exactly 511), interface of 503 / 5000 chars (fgets cuts the line at 511
 * -> token 502), line without newline, and "Running: a b" (only "a").
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   pgr_data[PGR_DATA_SZ];
size_t pgr_data_len;
int    pgr_fopen_fail;
char   pgr_slot_str[PGR_SLOT_SZ + PGR_SLOT_PAD];
char   pgr_slot_if[PGR_SLOT_SZ + PGR_SLOT_PAD];
size_t pgr_str_len, pgr_if_len;

pktgen_is_running_test_case_t pktgen_is_running_suite[] = {
    /* name               kind if_len fopen_fail ret if_out */
    { "fopen_fails",        0,    0,     1,       0,   0 },
    { "empty_file",         1,    0,     0,       0,   0 },
    { "running_wlan0",      2,    0,     0,       1,   5 },
    { "stopped_line",       3,    0,     0,       0,   0 },
    { "running_no_if",      4,    0,     0,       0,   0 },
    { "if_502",             5,  502,     0,       1, 502 },
    { "if_503",             5,  503,     0,       1, 502 },
    { "if_5000",            5, 5000,     0,       1, 502 },
    { "no_newline",         6,    0,     0,       1,   4 },
    { "two_tokens",         7,    0,     0,       1,   1 },

    { NULL, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_pktgen_is_running_input(const pktgen_is_running_test_case_t *tc)
{
    memset(pgr_data, 0, sizeof(pgr_data));
    size_t off = 0;
    switch (tc->kind) {
    case 2: off = (size_t)snprintf(pgr_data, sizeof(pgr_data), "Running: wlan0\nStopped: \nResult: OK\n"); break;
    case 3: off = (size_t)snprintf(pgr_data, sizeof(pgr_data), "Stopped: wlan0\n"); break;
    case 4: off = (size_t)snprintf(pgr_data, sizeof(pgr_data), "Running: \n"); break;
    case 5:
        off = (size_t)snprintf(pgr_data, sizeof(pgr_data), "Running: ");
        memset(pgr_data + off, 'i', (size_t)tc->if_len); off += (size_t)tc->if_len;
        pgr_data[off++] = '\n';
        break;
    case 6: off = (size_t)snprintf(pgr_data, sizeof(pgr_data), "Running: eth0"); break;
    case 7: off = (size_t)snprintf(pgr_data, sizeof(pgr_data), "Running: a b\n"); break;
    default: break;
    }
    pgr_data_len = off;
    pgr_fopen_fail = tc->fopen_fail;
    pgr_str_len = pgr_if_len = 0;
}
