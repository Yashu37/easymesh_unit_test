/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_table_from_json
 *
 * Record layout = the update_cb harness schema (OCU_*: _update_type @0,
 * _uuid[37] @4, _version[37] @41, if_name[64] @78, schema_size 142).
 * table->from_json is a pjs-style test parser: bounded copies into the
 * record fields; on a "fail" column it writes a 300-char error with
 * snprintf(err, sizeof(pjs_errmsg_t)) (-> truncated to 127) and fails.
 *
 * Cases: full row, empty row, 255-char if_name and 200-char uuid (both
 * truncated to their field), parse failure, and a NULL jrow.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

alignas(16) char otj_rec[OCU_SCHEMA_SZ + 64];
ovsdb_table_t otj_table;
size_t otj_perr_len;
int    otj_calls;

static bool otj_from_json(void *out, void *vjs, bool update, pjs_errmsg_t err)
{
    (void)update;
    json_t *js = (json_t *)vjs;
    char *rec = (char *)out;
    otj_calls++;
    if (!js || json_object_get(js, "fail")) {
        char big[301]; memset(big, 'E', 300); big[300] = 0;
        snprintf(err, sizeof(pjs_errmsg_t), "parse error: %s", big);
        otj_perr_len = strnlen(err, sizeof(pjs_errmsg_t));
        return false;
    }
    const char *u = json_string_value(json_array_get(json_object_get(js, "_uuid"), 1));
    const char *n = json_string_value(json_object_get(js, "if_name"));
    if (u) snprintf(rec + OCU_UUID_OFF, 37, "%s", u);
    if (n) snprintf(rec + OCU_KEY_OFF, 64, "%s", n);
    return true;
}

ovsdb_table_from_json_test_case_t ovsdb_table_from_json_suite[] = {
    /* name              json                                                                       ret */
    { "full_row",        "{\"_uuid\":[\"uuid\",\"0123abcd-4567-89ef-0123-456789abcdef\"],\"if_name\":\"wl0\"}", 1 },
    { "empty_row",       "{}",                                                                        1 },
    { "long_values",     "LONG",                                                                      1 },
    { "parse_failure",   "{\"fail\":1}",                                                              0 },
    { "jrow_null",       NULL,                                                                        0 },

    { NULL, NULL, 0 }  /* sentinel */
};

void *construct_ovsdb_table_from_json_jrow(const ovsdb_table_from_json_test_case_t *tc)
{
    if (!tc->json) return NULL;
    if (!strcmp(tc->json, "LONG")) {
        char nm[256], uu[201];
        memset(nm, 'n', 255); nm[255] = 0;
        memset(uu, 'u', 200); uu[200] = 0;
        return json_pack("{s:[s,s],s:s}", "_uuid", "uuid", uu, "if_name", nm);
    }
    return json_loads(tc->json, 0, NULL);
}

void construct_ovsdb_table_from_json_input(const ovsdb_table_from_json_test_case_t *tc)
{
    (void)tc;
    memset(otj_rec, 0, sizeof(otj_rec));
    memset(&otj_table, 0, sizeof(otj_table));
    snprintf(otj_table.table_name, sizeof(otj_table.table_name), "Wifi_VIF_Config");
    otj_table.schema_size = OCU_SCHEMA_SZ;
    otj_table.from_json   = otj_from_json;
    otj_perr_len = 0;
    otj_calls    = 0;
}
