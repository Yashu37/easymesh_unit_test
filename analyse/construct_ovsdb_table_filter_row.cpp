/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_table_filter_row
 *
 * columns[] is a NULL-terminated argv: columns[0] is the op ("+" / "-"),
 * the rest are column names. Each string lives in its own 2048-byte runner
 * buffer (tail poisoned); the argv array lives in otf_argv[64] (slots past
 * the NULL poisoned).
 *
 * Cases: row NULL, columns NULL, empty filter, invalid op, "+" with no
 * columns, "+" with 3 columns, "-" with 2, 20 columns x 100 chars (~2 KB,
 * str truncated to 1023), and one 1500-char column.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char  otf_strs[OTF_MAX_COLS][OTF_STR_SZ];
char *otf_argv[OTF_MAX_COLS + 1];
int   otf_ncols;
int   otf_which, otf_argc;
size_t otf_str_len;

ovsdb_table_filter_row_test_case_t ovsdb_table_filter_row_suite[] = {
    /* name              row cols_null op    ncols col_len  which argc */
    { "row_null",         0,    0,     "+",   2,     0,      0,   -1 },
    { "columns_null",     1,    1,     "+",   0,     0,      0,   -1 },
    { "empty_filter",     1,    0,     NULL,  0,     0,      0,   -1 },
    { "invalid_op",       1,    0,     "*",   2,     0,      0,   -1 },
    { "plus_no_columns",  1,    0,     "+",   0,     0,    '+',    0 },
    { "plus_3_columns",   1,    0,     "+",   3,     0,    '+',    3 },
    { "minus_2_columns",  1,    0,     "-",   2,     0,    '-',    2 },
    { "plus_20_x_100",    1,    0,     "+",  20,   100,    '+',   20 },
    { "minus_1_x_1500",   1,    0,     "-",   1,  1500,    '-',    1 },

    { NULL, 0, 0, NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_table_filter_row_input(const ovsdb_table_filter_row_test_case_t *tc)
{
    static const char *names[] = { "if_name", "enabled", "ssid", "mode", "channel" };
    memset(otf_strs, 0, sizeof(otf_strs));
    memset(otf_argv, 0, sizeof(otf_argv));
    otf_ncols = 0;
    if (tc->op) {
        snprintf(otf_strs[0], OTF_STR_SZ, "%s", tc->op);
        otf_argv[otf_ncols++] = otf_strs[0];
        for (int i = 0; i < tc->ncols; i++) {
            char *s = otf_strs[otf_ncols];
            if (tc->col_len) memset(s, 'c', (size_t)tc->col_len);
            else             snprintf(s, OTF_STR_SZ, "%s", names[i % 5]);
            otf_argv[otf_ncols++] = s;
        }
    }
    otf_argv[otf_ncols] = NULL;
    otf_which = 0; otf_argc = -1; otf_str_len = 0;
}
