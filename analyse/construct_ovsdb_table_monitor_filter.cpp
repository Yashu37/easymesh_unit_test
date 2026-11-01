/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_table_monitor_filter
 *
 * The table's schema columns[] has schema_n entries ("c0".."cN", or none).
 * filter[] is a NULL-terminated argv: filter[0] is the op ("-", "+") or a
 * plain column list. Every string sits in its own runner buffer (tail
 * poisoned) and both argv arrays have their slots past the NULL poisoned.
 *
 * Cases: filter NULL, "-" removing 2 of 4 (+ _version kept), "-" removing
 * all + _version, "-" with a 60-column schema, "-" with an empty schema,
 * "+" with 2 columns, a plain list, an empty-string op, and LAST the empty
 * filter argv {NULL} (crashed before the fix; now treated as no filter).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char  otf2_schema_strs[OTF2_MAX][16];
char *otf2_schema_argv[OTF2_MAX + 1];
char  otf2_filter_strs[OTF2_MAX][16];
char *otf2_filter_argv[OTF2_MAX + 1];
int   otf2_schema_n, otf2_filter_n;
int   otf2_called, otf2_got_null, otf2_got_count, otf2_has_version;
ovsdb_table_t otf2_table;

ovsdb_table_monitor_filter_test_case_t ovsdb_table_monitor_filter_suite[] = {
    /* name                 schema_n filter_null filter (space separated)     got_null count has_ver */
    { "filter_null",            4,      1,     "",                               1,     0,   0 },
    { "minus_two_of_four",      4,      0,     "- c1 c3",                        0,     3,   1 },
    { "minus_all_and_ver",      4,      0,     "- c0 c1 c2 c3 _version",         0,     0,   0 },
    { "minus_schema_60",       60,      0,     "- c0 c59",                       0,    59,   1 },
    { "minus_empty_schema",     0,      0,     "- c0",                           0,     1,   1 },
    { "plus_two",               4,      0,     "+ c0 c2",                        0,     2,   0 },
    { "plain_list",             4,      0,     "c1 c2 _version",                 0,     3,   1 },
    { "empty_string_op",        4,      0,     "EMPTYOP",                        0,     1,   0 },
    { "empty_filter_argv",      4,      0,     NULL,                             1,     0,   0 },   /* {NULL} -> no filter (fix) */

    { NULL, 0, 0, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_table_monitor_filter_input(const ovsdb_table_monitor_filter_test_case_t *tc)
{
    memset(otf2_schema_strs, 0, sizeof(otf2_schema_strs));
    memset(otf2_schema_argv, 0, sizeof(otf2_schema_argv));
    memset(otf2_filter_strs, 0, sizeof(otf2_filter_strs));
    memset(otf2_filter_argv, 0, sizeof(otf2_filter_argv));

    otf2_schema_n = tc->schema_n;
    for (int i = 0; i < otf2_schema_n; i++) {
        snprintf(otf2_schema_strs[i], 16, "c%d", i);
        otf2_schema_argv[i] = otf2_schema_strs[i];
    }

    otf2_filter_n = 0;
    if (tc->filter && !strcmp(tc->filter, "EMPTYOP")) {
        otf2_filter_strs[0][0] = '\0';                 /* filter[0] = "" */
        otf2_filter_argv[otf2_filter_n++] = otf2_filter_strs[0];
    } else if (tc->filter) {
        char tmp[256]; snprintf(tmp, sizeof(tmp), "%s", tc->filter);
        for (char *tok = strtok(tmp, " "); tok; tok = strtok(NULL, " ")) {
            snprintf(otf2_filter_strs[otf2_filter_n], 16, "%s", tok);
            otf2_filter_argv[otf2_filter_n] = otf2_filter_strs[otf2_filter_n];
            otf2_filter_n++;
        }
    }
    otf2_filter_argv[otf2_filter_n] = NULL;

    memset(&otf2_table, 0, sizeof(otf2_table));
    snprintf(otf2_table.table_name, sizeof(otf2_table.table_name), "Wifi_VIF_Config");
    otf2_table.columns = otf2_schema_argv;

    otf2_called = otf2_got_null = otf2_got_count = otf2_has_version = 0;
}
