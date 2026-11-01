/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_sync_get_uuid_and_count
 *
 * where is a JSON condition array (dumped into where_str[128]); the stubbed
 * select returns the case's rows. uuid is either the runner's ovs_uuid_t
 * (inside a larger buffer, tail past 37 poisoned) or NULL (-> local uuid1).
 *
 * Cases: one row with uuid, uuid NULL, no rows, select NULL, 2 rows, row
 * without _uuid, empty uuid string, 200-char uuid (STRSCPY -> 36), where
 * NULL, where of 126 / 127 / 128 dump chars, and a 1000-char where.
 * where_out = what json_gets left in the slot: 127 + NUL fits; 128 and
 * longer are refused ("json_gets() error", 17), then json_get_str resets
 * where_str to "".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   ogc_slot[OGC_SLOT_SZ + OGC_SLOT_PAD];
size_t ogc_where_len;
void  *ogc_rows;
alignas(16) char ogc_uuid_buf[sizeof(ovs_uuid_t) + 64];
char   ogc_table[OGC_STR_SZ];
char   ogc_sock[OGC_STR_SZ];

#define U1 "0123abcd-4567-89ef-0123-456789abcdef"

ovsdb_sync_get_uuid_and_count_test_case_t ovsdb_sync_get_uuid_and_count_suite[] = {
    /* name              uuid_null rows where_len count uuid_len where_out */
    { "one_row",            0,      1,     0,      1,    36,     -1 },
    { "uuid_arg_null",      1,      1,     0,      1,    -1,     -1 },
    { "no_rows",            0,      0,     0,      0,     0,     -1 },
    { "select_null",        0,     -1,     0,      0,     0,     -1 },
    { "two_rows",           0,      2,     0,      2,     0,     -1 },
    { "row_no_uuid",        0,      3,     0,     -1,     0,     -1 },
    { "uuid_empty",         0,      4,     0,     -1,     0,     -1 },
    { "uuid_200",           0,      5,     0,      1,    36,     -1 },
    { "where_null",         0,      1,    -1,      1,    36,      0 },
    { "where_dump_126",     0,      1,   126,      1,    36,    126 },
    { "where_dump_127",     0,      1,   127,      1,    36,    127 },
    { "where_dump_128",     0,      1,   128,      1,    36,     17 },
    { "where_1000",         0,      1,  1000,      1,    36,     17 },

    { NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void *construct_ovsdb_sync_get_uuid_and_count_where(const ovsdb_sync_get_uuid_and_count_test_case_t *tc)
{
    if (tc->where_len < 0) return NULL;
    if (tc->where_len == 0) return json_pack("[[s,s,s]]", "if_name", "==", "wl0");
    /* [["if_name","==","xxx"]] -> dump = 23 + n chars */
    int n = tc->where_len - 23;
    char *s = (char *)malloc((size_t)n + 1); memset(s, 'x', (size_t)n); s[n] = 0;
    json_t *w = json_pack("[[s,s,s]]", "if_name", "==", s);
    free(s);
    return w;
}

void construct_ovsdb_sync_get_uuid_and_count_input(const ovsdb_sync_get_uuid_and_count_test_case_t *tc)
{
    char big[201]; memset(big, 'u', 200); big[200] = 0;
    if (ogc_rows) json_decref((json_t *)ogc_rows);
    switch (tc->rows) {
    case -1: ogc_rows = NULL; break;
    case 0:  ogc_rows = json_array(); break;
    case 1:  ogc_rows = json_pack("[{s:[s,s]}]", "_uuid", "uuid", U1); break;
    case 2:  ogc_rows = json_pack("[{s:[s,s]},{s:[s,s]}]", "_uuid", "uuid", U1, "_uuid", "uuid", U1); break;
    case 3:  ogc_rows = json_pack("[{s:s}]", "if_name", "wl0"); break;
    case 4:  ogc_rows = json_pack("[{s:[s,s]}]", "_uuid", "uuid", ""); break;
    case 5:  ogc_rows = json_pack("[{s:[s,s]}]", "_uuid", "uuid", big); break;
    }
    memset(ogc_uuid_buf, 0xAB, sizeof(ogc_uuid_buf));
    snprintf(ogc_table, sizeof(ogc_table), "Wifi_VIF_Config");
    snprintf(ogc_sock, sizeof(ogc_sock), "/var/run/db.sock");
    ogc_where_len = 0;
}
