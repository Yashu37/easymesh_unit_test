/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_cache_upsert
 *
 * Same schema layout as the update_cb harness (OCU_*: _update_type @0,
 * _uuid[37] @4, _version[37] @41, if_name[64] @78, schema_size 142).
 * The caller record is ocs_rec (runner buffer, tail past schema_size
 * poisoned). Pool slot 0 = cached row, slot 1 = calloc'd new row.
 * to_json is a pjs-style test serializer (error via
 * snprintf(err, sizeof(pjs_errmsg_t))).
 *
 * Cases: no primary key, cached + unchanged (no db call), cached + changed,
 * new row, to_json fails (300-char error), sync_upsert fails, new row with a
 * 200-char uuid from the db (truncated to 36), and a 63-char if_name.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

alignas(16) unsigned char ocs_pool[2][OCS_SLOT_SZ];
alignas(16) char ocs_rec[OCU_SCHEMA_SZ + 64];
int    ocs_cached, ocs_upserts, ocs_asked_uuid, ocs_upsert_ok, ocs_tj_fail;
size_t ocs_perr_len;
char   ocs_db_uuid[256];
ovsdb_table_t ocs_table;

#define U1 "0123abcd-4567-89ef-0123-456789abcdef"
#define V1 "11111111-2222-3333-4444-555555555555"

static void *ocs_to_json(void *in, pjs_errmsg_t err)
{
    char *rec = (char *)in;
    if (ocs_tj_fail) {
        char big[301]; memset(big, 'E', 300); big[300] = 0;
        snprintf(err, sizeof(pjs_errmsg_t), "convert error: %s", big);
        ocs_perr_len = strnlen(err, sizeof(pjs_errmsg_t));
        return NULL;
    }
    return json_pack("{s:s}", "if_name", rec + OCU_KEY_OFF);
}

ovsdb_cache_upsert_test_case_t ovsdb_cache_upsert_suite[] = {
    /* name               no_key cached rec_name  tj_fail up_ok db_uuid_fill ret upserts inserted */
    { "no_primary_key",      1,    0,   "wl0",      0,     1,      0,       -1,   0,     0 },
    { "cached_unchanged",    0,    1,   "wl0",      0,     1,      0,        0,   0,     0 },
    { "cached_changed",      0,    1,   "wl9",      0,     1,      0,        0,   1,     0 },
    { "new_row",             0,    0,   "wl0",      0,     1,      0,        0,   1,     1 },
    { "to_json_fails",       0,    0,   "wl0",      1,     1,      0,       -1,   0,     0 },
    { "sync_upsert_fails",   0,    0,   "wl0",      0,     0,      0,       -1,   1,     0 },
    { "new_long_db_uuid",    0,    0,   "wl0",      0,     1,    200,        0,   1,     1 },
    { "new_ifname_63",       0,    0,   NULL,       0,     1,      0,        0,   1,     1 },

    { NULL, 0, 0, NULL, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_cache_upsert_input(const ovsdb_cache_upsert_test_case_t *tc)
{
    memset(ocs_pool, 0, sizeof(ocs_pool));
    memset(ocs_rec, 0, sizeof(ocs_rec));
    memset(&ocs_table, 0, sizeof(ocs_table));
    snprintf(ocs_table.table_name, sizeof(ocs_table.table_name), "Wifi_VIF_Config");
    snprintf(ocs_table.key_name, sizeof(ocs_table.key_name), "if_name");
    ocs_table.schema_size     = OCU_SCHEMA_SZ;
    ocs_table.row_size        = (int)(sizeof(ovsdb_cache_row_t) + OCU_SCHEMA_SZ);
    ocs_table.upd_type_offset = OCU_UPD_OFF;
    ocs_table.uuid_offset     = OCU_UUID_OFF;
    ocs_table.version_offset  = OCU_VER_OFF;
    ocs_table.key_offset      = tc->no_key ? -1 : OCU_KEY_OFF;
    ocs_table.key2_offset     = -1;
    ocs_table.to_json         = ocs_to_json;

    /* cached row: uuid U1, version V1, if_name wl0 */
    ovsdb_cache_row_t *crow = (ovsdb_cache_row_t *)ocs_pool[0];
    snprintf(crow->record + OCU_UUID_OFF, 37, "%s", U1);
    snprintf(crow->record + OCU_VER_OFF, 37, "%s", V1);
    snprintf(crow->record + OCU_KEY_OFF, 64, "wl0");

    /* caller record: only if_name set (uuid/version come from cache or db) */
    if (tc->rec_name) snprintf(ocs_rec + OCU_KEY_OFF, 64, "%s", tc->rec_name);
    else              memset(ocs_rec + OCU_KEY_OFF, 'n', 63);

    memset(ocs_db_uuid, 0, sizeof(ocs_db_uuid));
    if (tc->db_uuid_fill) memset(ocs_db_uuid, 'u', (size_t)tc->db_uuid_fill);
    else                  snprintf(ocs_db_uuid, sizeof(ocs_db_uuid), "%s", U1);

    ocs_cached     = tc->cached;
    ocs_tj_fail    = tc->tj_fail;
    ocs_upsert_ok  = tc->upsert_ok;
    ocs_upserts    = ocs_asked_uuid = 0;
    ocs_perr_len   = 0;
    oci_inserts    = 0;
    oci_msg_len    = 0;
}
