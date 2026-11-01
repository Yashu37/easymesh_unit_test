/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_sync_update_one_get_uuid
 *
 * where is a JSON string value whose encoded length is chosen per case, so
 * json_get_str() into where_str[128] is exercised at: NULL where, short,
 * exactly 127 encoded chars (fits), 128 (one too many -> empty) and 1000
 * (much too long -> empty). Select count 0/1/2/-1 and update count 1/0
 * drive every branch. A 200-char uuid from the db checks the uuid copy.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   osu_table[256];
size_t osu_table_len, osu_table_seen;
alignas(16) unsigned char osu_uuidbuf[64];
int    osu_select_count, osu_update_count, osu_updates;
char   osu_db_uuid[256];

#define U1 "0123abcd-4567-89ef-0123-456789abcdef"

ovsdb_sync_update_one_get_uuid_test_case_t ovsdb_sync_update_one_get_uuid_suite[] = {
    /* name                 where_len sel upd uuid_fill table_fill ret updates */
    { "where_null",            -1,     1,  1,     0,        0,      1,   1 },
    { "where_short",           10,     1,  1,     0,        0,      1,   1 },
    { "where_127_fits",       127,     1,  1,     0,        0,      1,   1 },
    { "where_128_too_long",   128,     1,  1,     0,        0,      1,   1 },
    { "where_1000",          1000,     1,  1,     0,        0,      1,   1 },
    { "select_none",           10,     0,  1,     0,        0,      0,   0 },
    { "select_two",            10,     2,  1,     0,        0,      2,   0 },
    { "select_error",          10,    -1,  1,     0,        0,     -1,   0 },
    { "update_zero",           10,     1,  0,     0,        0,      0,   1 },
    { "db_uuid_200",           10,     1,  1,   200,        0,      1,   1 },
    { "table_255",             10,     1,  1,     0,      255,      1,   1 },

    { NULL, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

json_t *construct_ovsdb_sync_update_one_get_uuid_where(const ovsdb_sync_update_one_get_uuid_test_case_t *tc)
{
    if (tc->where_len < 0) return NULL;
    /* a JSON string "xxx" encodes to n + 2 chars */
    int n = tc->where_len - 2;
    char *s = (char *)malloc((size_t)n + 1);
    memset(s, 'w', (size_t)n); s[n] = 0;
    json_t *w = json_string(s);
    free(s);
    return w;
}

void construct_ovsdb_sync_update_one_get_uuid_input(const ovsdb_sync_update_one_get_uuid_test_case_t *tc)
{
    memset(osu_table, 0, sizeof(osu_table));
    if (tc->table_fill) memset(osu_table, 't', (size_t)tc->table_fill);
    else                snprintf(osu_table, sizeof(osu_table), "Wifi_VIF_Config");
    osu_table_len = strlen(osu_table);

    memset(osu_uuidbuf, 0, sizeof(osu_uuidbuf));
    memset(osu_db_uuid, 0, sizeof(osu_db_uuid));
    if (tc->uuid_fill) memset(osu_db_uuid, 'u', (size_t)tc->uuid_fill);
    else               snprintf(osu_db_uuid, sizeof(osu_db_uuid), "%s", U1);

    osu_select_count = tc->select_count;
    osu_update_count = tc->update_count;
    osu_updates      = 0;
    osu_table_seen   = 0;
}
