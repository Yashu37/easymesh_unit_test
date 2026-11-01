/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_sync_upsert_where
 *
 * where is a JSON string whose encoded length is chosen per case so
 * json_get_str() into where_str[128] is exercised at: NULL, short,
 * exactly 127 (fits), 128 (one too many -> empty) and 1000. The update
 * count (1 / 0 / 2 / -1) and insert result drive every branch. uuid may be
 * NULL (optional). A 200-char uuid from the db and a 255-char table name
 * check the other inputs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   osp_table[256];
size_t osp_table_len, osp_table_seen;
alignas(16) unsigned char osp_uuidbuf[64];
int    osp_update_count, osp_insert_ok, osp_updates, osp_inserts;
char   osp_db_uuid[256];

#define U1 "0123abcd-4567-89ef-0123-456789abcdef"

ovsdb_sync_upsert_where_test_case_t ovsdb_sync_upsert_where_suite[] = {
    /* name                where_len upd ins_ok use_uuid uuid_fill table_fill ret inserts */
    { "where_null",           -1,     1,   1,     1,       0,        0,      1,   0 },
    { "updated_short",        10,     1,   1,     1,       0,        0,      1,   0 },
    { "where_127_fits",      127,     1,   1,     1,       0,        0,      1,   0 },
    { "where_128_too_long",  128,     1,   1,     1,       0,        0,      1,   0 },
    { "where_1000",         1000,     0,   1,     1,       0,        0,      1,   1 },
    { "no_match_insert",      10,     0,   1,     1,       0,        0,      1,   1 },
    { "insert_fails",         10,     0,   0,     1,       0,        0,      0,   1 },
    { "two_rows",             10,     2,   1,     1,       0,        0,      0,   0 },
    { "update_error",         10,    -1,   1,     1,       0,        0,      0,   0 },
    { "uuid_null",            10,     0,   1,     0,       0,        0,      1,   1 },
    { "db_uuid_200",          10,     0,   1,     1,     200,        0,      1,   1 },
    { "table_255",            10,     1,   1,     1,       0,      255,      1,   0 },

    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

json_t *construct_ovsdb_sync_upsert_where_where(const ovsdb_sync_upsert_where_test_case_t *tc)
{
    if (tc->where_len < 0) return NULL;
    int n = tc->where_len - 2;              /* "xxx" encodes to n + 2 chars */
    char *s = (char *)malloc((size_t)n + 1);
    memset(s, 'w', (size_t)n); s[n] = 0;
    json_t *w = json_string(s);
    free(s);
    return w;
}

void construct_ovsdb_sync_upsert_where_input(const ovsdb_sync_upsert_where_test_case_t *tc)
{
    memset(osp_table, 0, sizeof(osp_table));
    if (tc->table_fill) memset(osp_table, 't', (size_t)tc->table_fill);
    else                snprintf(osp_table, sizeof(osp_table), "Wifi_VIF_Config");
    osp_table_len = strlen(osp_table);

    memset(osp_uuidbuf, 0, sizeof(osp_uuidbuf));
    memset(osp_db_uuid, 0, sizeof(osp_db_uuid));
    if (tc->uuid_fill) memset(osp_db_uuid, 'u', (size_t)tc->uuid_fill);
    else               snprintf(osp_db_uuid, sizeof(osp_db_uuid), "%s", U1);

    osp_update_count = tc->update_count;
    osp_insert_ok    = tc->insert_ok;
    osp_updates = osp_inserts = 0;
    osp_table_seen = 0;
}
