/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_table_monitor_columns
 *
 * The table's schema columns are {"_uuid","_version","if_name","enabled"}.
 * The requested columns[] is a NULL-terminated argv built per case; every
 * string sits in its own 2048-byte runner buffer (tail poisoned) and both
 * argv arrays have their slots past the NULL poisoned.
 *
 * Cases: columns NULL, empty argv, all schema columns (partial = false),
 * a subset with _version (partial = true), monitor registration failing,
 * 20 columns x 100 chars (~2 KB -> tmp truncated to 1023), and a single
 * 1500-char column.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char  otm_strs[OTM_MAX_COLS][OTM_STR_SZ];
char *otm_argv[OTM_MAX_COLS + 1];
char  otm_schema_strs[4][16];
char *otm_schema_argv[8];
int   otm_ncols, otm_which, otm_colc, otm_monitor_ok;
size_t otm_tmp_len;
ovsdb_table_t otm_table;

static const char *schema_cols[] = { "_uuid", "_version", "if_name", "enabled" };

ovsdb_table_monitor_columns_test_case_t ovsdb_table_monitor_columns_suite[] = {
    /* name              cols_null kind ncols col_len mon_ok ret which partial colc */
    { "columns_null",       1,      0,   0,     0,     1,    1,  'A',   0,     0 },
    { "empty_argv",         0,      0,   0,     0,     1,    1,  'A',   0,     0 },
    { "all_schema_cols",    0,      1,   4,     0,     1,    1,  'C',   0,     4 },
    { "subset_with_ver",    0,      2,   2,     0,     1,    1,  'C',   1,     2 },
    { "monitor_fails",      0,      1,   4,     0,     0,    0,  'C',   0,     4 },
    { "cols_20_x_100",      0,      3,  20,   100,     1,    1,  'C',   1,    20 },
    { "one_col_1500",       0,      3,   1,  1500,     1,    1,  'C',   1,     1 },

    { NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_table_monitor_columns_input(const ovsdb_table_monitor_columns_test_case_t *tc)
{
    memset(otm_strs, 0, sizeof(otm_strs));
    memset(otm_argv, 0, sizeof(otm_argv));
    memset(otm_schema_strs, 0, sizeof(otm_schema_strs));
    memset(otm_schema_argv, 0, sizeof(otm_schema_argv));
    for (int i = 0; i < 4; i++) {
        snprintf(otm_schema_strs[i], sizeof(otm_schema_strs[i]), "%s", schema_cols[i]);
        otm_schema_argv[i] = otm_schema_strs[i];
    }

    otm_ncols = 0;
    for (int i = 0; i < tc->ncols; i++) {
        char *s = otm_strs[i];
        if (tc->kind == 1)      snprintf(s, OTM_STR_SZ, "%s", schema_cols[i]);
        else if (tc->kind == 2) snprintf(s, OTM_STR_SZ, "%s", i == 0 ? "_version" : "if_name");
        else                    memset(s, 'c', (size_t)tc->col_len);
        otm_argv[otm_ncols++] = s;
    }
    otm_argv[otm_ncols] = NULL;

    memset(&otm_table, 0, sizeof(otm_table));
    snprintf(otm_table.table_name, sizeof(otm_table.table_name), "Wifi_VIF_Config");
    otm_table.columns = otm_schema_argv;

    otm_which = 0; otm_colc = -1; otm_tmp_len = 0;
    otm_monitor_ok = tc->monitor_ok;
}
