/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_sync_update_where
 *
 * where is a JSON string whose encoded length is chosen per case so
 * json_get_str() into where_str[128] is exercised at: NULL (update all
 * rows), short, exactly 127 (fits), 128 (one too many -> empty) and 1000.
 * The tran_call_s result drives the count: 1, 0, 2, NULL, malformed.
 * A 255-char table name checks the table input.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char        osw_table[256];
size_t      osw_table_len, osw_table_seen;
int         osw_calls;
const char *osw_result;

ovsdb_sync_update_where_test_case_t ovsdb_sync_update_where_suite[] = {
    /* name                 where_len result                       table_fill ret */
    { "where_null_all",        -1,  "[{},{\"count\":3}]",              0,       3 },
    { "where_short",           10,  "[{},{\"count\":1}]",              0,       1 },
    { "where_127_fits",       127,  "[{},{\"count\":1}]",              0,       1 },
    { "where_128_too_long",   128,  "[{},{\"count\":1}]",              0,       1 },
    { "where_1000",          1000,  "[{},{\"count\":1}]",              0,       1 },
    { "no_match",              10,  "[{},{\"count\":0}]",              0,       0 },
    { "two_rows",              10,  "[{},{\"count\":2}]",              0,       2 },
    { "no_result",             10,  NULL,                              0,      -1 },
    { "malformed_result",      10,  "[{}]",                            0,      -1 },
    { "table_255",             10,  "[{},{\"count\":1}]",            255,       1 },

    { NULL, 0, NULL, 0, 0 }  /* sentinel */
};

json_t *construct_ovsdb_sync_update_where_where(const ovsdb_sync_update_where_test_case_t *tc)
{
    if (tc->where_len < 0) return NULL;
    int n = tc->where_len - 2;              /* "xxx" encodes to n + 2 chars */
    char *s = (char *)malloc((size_t)n + 1);
    memset(s, 'w', (size_t)n); s[n] = 0;
    json_t *w = json_string(s);
    free(s);
    return w;
}

void construct_ovsdb_sync_update_where_input(const ovsdb_sync_update_where_test_case_t *tc)
{
    memset(osw_table, 0, sizeof(osw_table));
    if (tc->table_fill) memset(osw_table, 't', (size_t)tc->table_fill);
    else                snprintf(osw_table, sizeof(osw_table), "Wifi_VIF_Config");
    osw_table_len  = strlen(osw_table);
    osw_table_seen = 0;
    osw_calls      = 0;
    osw_result     = tc->result;
}
