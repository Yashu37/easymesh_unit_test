/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_cache_update_cb
 *
 * Schema record layout used by the test table (schema_size = 142):
 *   [0]   int  _update_type      (upd_type_offset)
 *   [4]   char _uuid[37]         (uuid_offset)
 *   [41]  char _version[37]      (version_offset, ovs_uuid_t)
 *   [78]  char if_name[64]       (key_offset)
 * row_size = header + 142. Pool slot 0 = cached row, slot 1 = new row
 * (calloc); each slot's tail past row_size is poisoned by the runner.
 * from_json is a pjs-style test parser (bounded copies; "fail" column ->
 * error via snprintf(err, sizeof(pjs_errmsg_t))).
 *
 * Cases cover every branch: bad type, mon_data NULL, table mismatch,
 * NEW (insert / parse error / already cached -> MODIFY), MODIFY (missing,
 * equal -> skip, changed -> callback, old parse error, 255-char if_name),
 * DEL (cached / missing).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

alignas(16) unsigned char ocu_pool[2][OCU_SLOT_SZ];
int    ocu_cached, ocu_removes, ocu_freed, ocu_cbs, ocu_marks;
char   ocu_uuid[64];
size_t ocu_uuid_len;
ovsdb_table_t ocu_table;
ovsdb_update_monitor_t ocu_mon;

#define U1 "0123abcd-4567-89ef-0123-456789abcdef"

static bool ocu_from_json(void *out, void *vjs, bool update, pjs_errmsg_t err)
{
    (void)update;
    json_t *js = (json_t *)vjs;
    char *rec = (char *)out;
    if (json_object_get(js, "fail")) {
        char big[301]; memset(big, 'E', 300); big[300] = 0;
        snprintf(err, sizeof(pjs_errmsg_t), "parse error: %s", big);
        return false;
    }
    const char *u = json_string_value(json_array_get(json_object_get(js, "_uuid"), 1));
    const char *v = json_string_value(json_array_get(json_object_get(js, "_version"), 1));
    const char *n = json_string_value(json_object_get(js, "if_name"));
    if (u) snprintf(rec + OCU_UUID_OFF, 37, "%s", u);
    if (v) snprintf(rec + OCU_VER_OFF, 37, "%s", v);
    if (n) snprintf(rec + OCU_KEY_OFF, 64, "%s", n);
    return true;
}
static void ocu_mark_changed(void *old, void *rec) { (void)old; (void)rec; ocu_marks++; }
static void ocu_cache_cb(ovsdb_update_monitor_t *self, void *old_rec, void *record, ovsdb_cache_row_t *row)
{
    (void)self; (void)old_rec; (void)record; (void)row; ocu_cbs++;
}

ovsdb_cache_update_cb_test_case_t ovsdb_cache_update_cb_suite[] = {
    /* name                 type                   data tbl_ok cached json_new                                                 json_old           cb ins free */
    { "bad_type",           7,                      1,   1,    0, "{}",                                                     "{}",                0, 0, 0 },
    { "mon_data_null",      OVSDB_UPDATE_NEW,       0,   1,    0, "{}",                                                     "{}",                0, 0, 0 },
    { "table_mismatch",     OVSDB_UPDATE_NEW,       1,   0,    0, "{}",                                                     "{}",                0, 0, 0 },
    { "new_insert",         OVSDB_UPDATE_NEW,       1,   1,    0, "{\"_uuid\":[\"uuid\",\"" U1 "\"],\"if_name\":\"wl0\"}",   "{}",                1, 1, 0 },
    { "new_parse_error",    OVSDB_UPDATE_NEW,       1,   1,    0, "{\"fail\":1}",                                           "{}",                0, 0, 1 },
    { "new_cached_as_mod",  OVSDB_UPDATE_NEW,       1,   1,    1, "{\"_uuid\":[\"uuid\",\"" U1 "\"],\"if_name\":\"wl1\"}",   "{}",                1, 0, 0 },
    { "mod_missing",        OVSDB_UPDATE_MODIFY,    1,   1,    0, "{}",                                                     "{}",                0, 0, 0 },
    { "mod_equal_skip",     OVSDB_UPDATE_MODIFY,    1,   1,    1, "{\"_uuid\":[\"uuid\",\"" U1 "\"],\"if_name\":\"wl0\"}",   "{}",                0, 0, 0 },
    { "mod_changed",        OVSDB_UPDATE_MODIFY,    1,   1,    1, "{\"_uuid\":[\"uuid\",\"" U1 "\"],\"if_name\":\"wl9\"}",   "{\"if_name\":\"wl0\"}", 1, 0, 0 },
    { "mod_old_parse_err",  OVSDB_UPDATE_MODIFY,    1,   1,    1, "{\"_uuid\":[\"uuid\",\"" U1 "\"],\"if_name\":\"wl9\"}",   "{\"fail\":1}",      0, 0, 0 },
    { "mod_long_ifname",    OVSDB_UPDATE_MODIFY,    1,   1,    1, "LONG",                                                   "{}",                1, 0, 0 },
    { "del_cached",         OVSDB_UPDATE_DEL,       1,   1,    1, "{}",                                                     "{}",                1, 0, 1 },
    { "del_missing",        OVSDB_UPDATE_DEL,       1,   1,    0, "{}",                                                     "{}",                0, 0, 0 },

    { NULL, 0, 0, 0, 0, NULL, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_cache_update_cb_input(const ovsdb_cache_update_cb_test_case_t *tc)
{
    memset(ocu_pool, 0, sizeof(ocu_pool));
    memset(&ocu_table, 0, sizeof(ocu_table));
    snprintf(ocu_table.table_name, sizeof(ocu_table.table_name), "Wifi_VIF_Config");
    ocu_table.schema_size     = OCU_SCHEMA_SZ;
    ocu_table.row_size        = (int)(sizeof(ovsdb_cache_row_t) + OCU_SCHEMA_SZ);
    ocu_table.upd_type_offset = OCU_UPD_OFF;
    ocu_table.uuid_offset     = OCU_UUID_OFF;
    ocu_table.version_offset  = OCU_VER_OFF;
    ocu_table.key_offset      = OCU_KEY_OFF;
    ocu_table.key2_offset     = -1;
    ocu_table.from_json       = ocu_from_json;
    ocu_table.mark_changed    = ocu_mark_changed;
    ocu_table.cache_callback  = ocu_cache_cb;

    /* cached row (slot 0): same uuid, if_name "wl0" */
    ovsdb_cache_row_t *crow = (ovsdb_cache_row_t *)ocu_pool[0];
    snprintf(crow->record + OCU_UUID_OFF, 37, "%s", U1);
    snprintf(crow->record + OCU_KEY_OFF, 64, "wl0");

    snprintf(ocu_uuid, sizeof(ocu_uuid), "%s", U1);
    ocu_uuid_len = strlen(ocu_uuid);

    if (ocu_mon.mon_json_new) json_decref((json_t *)ocu_mon.mon_json_new);
    if (ocu_mon.mon_json_old) json_decref((json_t *)ocu_mon.mon_json_old);
    memset(&ocu_mon, 0, sizeof(ocu_mon));
    ocu_mon.mon_type  = tc->mon_type;
    ocu_mon.mon_data  = tc->has_data ? &ocu_table : NULL;
    ocu_mon.mon_table = tc->table_ok ? "Wifi_VIF_Config" : "Wifi_Radio_Config";
    ocu_mon.mon_uuid  = ocu_uuid;
    if (!strcmp(tc->json_new, "LONG")) {
        char nm[256]; memset(nm, 'n', 255); nm[255] = 0;
        ocu_mon.mon_json_new = json_pack("{s:[s,s],s:s}", "_uuid", "uuid", U1, "if_name", nm);
    } else {
        ocu_mon.mon_json_new = json_loads(tc->json_new, 0, NULL);
    }
    ocu_mon.mon_json_old = json_loads(tc->json_old, 0, NULL);

    ocu_cached  = tc->cached;
    ocu_removes = ocu_freed = ocu_cbs = ocu_marks = 0;
    oci_inserts = 0;
    oci_msg_len = 0;
}
