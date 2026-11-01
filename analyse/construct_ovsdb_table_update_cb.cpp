/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_table_update_cb
 *
 * Schema record layout = OCU_* (_update_type @0, _uuid[37] @4,
 * _version[37] @41, if_name[64] @78, schema_size 142). from_json is a
 * pjs-style test parser (bounded copies; a "fail" column -> 300-char error
 * via snprintf(err, sizeof(pjs_errmsg_t))). The callback records the
 * if_name and _update_type it was given.
 *
 * Cases cover every branch: bad type, mon_data NULL, table mismatch,
 * NEW / MODIFY (mark_changed) / DEL (record built from json_old), old parse
 * error, new parse error, uuid mismatch (still calls back), partial update,
 * and a 255-char if_name (truncated to 63).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int    otu_cbs, otu_marks, otu_last_type;
size_t otu_last_name_len;
char   otu_uuid[64];
size_t otu_uuid_len;
ovsdb_table_t otu_table;
ovsdb_update_monitor_t otu_mon;

#define U1 "0123abcd-4567-89ef-0123-456789abcdef"
#define ROW(name) "{\"_uuid\":[\"uuid\",\"" U1 "\"],\"if_name\":\"" name "\"}"

static bool otu_from_json(void *out, void *vjs, bool update, pjs_errmsg_t err)
{
    (void)update;
    json_t *js = (json_t *)vjs;
    char *rec = (char *)out;
    if (js && json_object_get(js, "fail")) {
        char big[301]; memset(big, 'E', 300); big[300] = 0;
        snprintf(err, sizeof(pjs_errmsg_t), "parse error: %s", big);
        return false;
    }
    const char *u = json_string_value(json_array_get(json_object_get(js, "_uuid"), 1));
    const char *n = json_string_value(json_object_get(js, "if_name"));
    if (u) snprintf(rec + OCU_UUID_OFF, 37, "%s", u);
    if (n) snprintf(rec + OCU_KEY_OFF, 64, "%s", n);
    return true;
}
static void otu_mark_changed(void *old, void *rec) { (void)old; (void)rec; otu_marks++; }
static void otu_table_cb(ovsdb_update_monitor_t *self, void *old_rec, void *record)
{
    (void)self; (void)old_rec;
    char *rec = (char *)record;
    otu_cbs++;
    otu_last_type = *(int *)(rec + OCU_UPD_OFF);
    otu_last_name_len = strnlen(rec + OCU_KEY_OFF, 64);
}

ovsdb_table_update_cb_test_case_t ovsdb_table_update_cb_suite[] = {
    /* name               type                 data tbl partial json_new         json_old          uuid_ok cb marks */
    { "bad_type",          9,                   1,   1,   0,   ROW("wl0"),        "{}",               1,   0,  0 },
    { "mon_data_null",     OVSDB_UPDATE_NEW,    0,   1,   0,   ROW("wl0"),        "{}",               1,   0,  0 },
    { "table_mismatch",    OVSDB_UPDATE_NEW,    1,   0,   0,   ROW("wl0"),        "{}",               1,   0,  0 },
    { "new_ok",            OVSDB_UPDATE_NEW,    1,   1,   0,   ROW("wl0"),        "{}",               1,   1,  0 },
    { "modify_ok",         OVSDB_UPDATE_MODIFY, 1,   1,   0,   ROW("wl9"),        "{\"if_name\":\"wl0\"}", 1, 1, 1 },
    { "delete_ok",         OVSDB_UPDATE_DEL,    1,   1,   0,   "{}",              ROW("wl0"),         1,   1,  0 },
    { "old_parse_error",   OVSDB_UPDATE_MODIFY, 1,   1,   0,   ROW("wl9"),        "{\"fail\":1}",     1,   0,  0 },
    { "new_parse_error",   OVSDB_UPDATE_NEW,    1,   1,   0,   "{\"fail\":1}",    "{}",               1,   0,  0 },
    { "uuid_mismatch",     OVSDB_UPDATE_NEW,    1,   1,   0,   ROW("wl0"),        "{}",               0,   1,  0 },
    { "partial_update",    OVSDB_UPDATE_MODIFY, 1,   1,   1,   ROW("wl9"),        "{}",               1,   1,  1 },
    { "if_name_255",       OVSDB_UPDATE_NEW,    1,   1,   0,   "LONG",            "{}",               1,   1,  0 },

    { NULL, 0, 0, 0, 0, NULL, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_table_update_cb_input(const ovsdb_table_update_cb_test_case_t *tc)
{
    memset(&otu_table, 0, sizeof(otu_table));
    snprintf(otu_table.table_name, sizeof(otu_table.table_name), "Wifi_VIF_Config");
    otu_table.schema_size     = OCU_SCHEMA_SZ;
    otu_table.upd_type_offset = OCU_UPD_OFF;
    otu_table.uuid_offset     = OCU_UUID_OFF;
    otu_table.version_offset  = OCU_VER_OFF;
    otu_table.key_offset      = OCU_KEY_OFF;
    otu_table.partial_update  = tc->partial != 0;
    otu_table.from_json       = otu_from_json;
    otu_table.mark_changed    = otu_mark_changed;
    otu_table.table_callback  = otu_table_cb;

    snprintf(otu_uuid, sizeof(otu_uuid), "%s", tc->uuid_ok ? U1 : "ffffffff-0000-0000-0000-000000000000");
    otu_uuid_len = strlen(otu_uuid);

    if (otu_mon.mon_json_new) json_decref((json_t *)otu_mon.mon_json_new);
    if (otu_mon.mon_json_old) json_decref((json_t *)otu_mon.mon_json_old);
    memset(&otu_mon, 0, sizeof(otu_mon));
    otu_mon.mon_type  = (ovsdb_update_type_t)tc->mon_type;
    otu_mon.mon_data  = tc->has_data ? &otu_table : NULL;
    otu_mon.mon_table = tc->table_ok ? "Wifi_VIF_Config" : "Wifi_Radio_Config";
    otu_mon.mon_uuid  = otu_uuid;
    if (!strcmp(tc->json_new, "LONG")) {
        char nm[256]; memset(nm, 'n', 255); nm[255] = 0;
        otu_mon.mon_json_new = json_pack("{s:[s,s],s:s}", "_uuid", "uuid", U1, "if_name", nm);
    } else {
        otu_mon.mon_json_new = json_loads(tc->json_new, 0, NULL);
    }
    otu_mon.mon_json_old = json_loads(tc->json_old, 0, NULL);

    otu_cbs = otu_marks = 0;
    otu_last_type = -1;
    otu_last_name_len = 0;
}
