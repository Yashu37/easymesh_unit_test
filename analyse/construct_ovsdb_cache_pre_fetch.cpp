/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_cache_pre_fetch
 *
 * The table reuses the _ovsdb_cache_insert_row record layout (uuid at 0,
 * key at 37, key2 at 293, schema_size 549); row_size = header + 549.
 * table->from_json is a test schema parser in the style of pjs: it copies
 * "_uuid"[1] and "if_name" into the record with bounded copies, and on
 * failure writes its error with snprintf(err, sizeof(pjs_errmsg_t), ...).
 *
 * Cases: row already cached, no result, 0 rows, 2 rows, no _uuid, _uuid not
 * a string, from_json fails with a 300-char error (truncated to 127),
 * success, success with a 255-char key and a 255-char if_name value.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

alignas(16) unsigned char ocp_rowpool[OCP_POOL_SZ];
size_t      ocp_calloc_size;
int         ocp_row_exists, ocp_freed, ocp_fj_fail;
size_t      ocp_perr_len;
const char *ocp_result_json;
char        ocp_key[256];
size_t      ocp_key_len;
ovsdb_table_t ocp_table;

static char ocp_json_buf[2048];

#define UUID_STR "0123abcd-4567-89ef-0123-456789abcdef"
#define ONE_ROW(row) "[{\"rows\":[" row "]}]"

/* test schema parser (pjs style): bounded copies + bounded error text */
static bool ocp_from_json(void *out, void *vjs, bool update, pjs_errmsg_t err)
{
    (void)update;
    json_t *js = (json_t *)vjs;
    char *rec = (char *)out;
    if (ocp_fj_fail) {
        char big[301]; memset(big, 'E', 300); big[300] = 0;
        snprintf(err, sizeof(pjs_errmsg_t), "parse error: %s", big);
        ocp_perr_len = strnlen(err, sizeof(pjs_errmsg_t));
        return false;
    }
    const char *u = json_string_value(json_array_get(json_object_get(js, "_uuid"), 1));
    const char *n = json_string_value(json_object_get(js, "if_name"));
    if (u) snprintf(rec + OCI_UUID_OFF, 37, "%s", u);
    if (n) snprintf(rec + OCI_KEY_OFF, 256, "%s", n);
    return true;
}

ovsdb_cache_pre_fetch_test_case_t ovsdb_cache_pre_fetch_suite[] = {
    /* name                  exists result                                                         fj_fail key_fill ret */
    { "already_cached",        1,  NULL,                                                              0,     0,   0 },
    { "no_result",             0,  NULL,                                                              0,     0,  -1 },
    { "zero_rows",             0,  "[{\"rows\":[]}]",                                                 0,     0,  -1 },
    { "two_rows",              0,  "[{\"rows\":[{},{}]}]",                                            0,     0,  -1 },
    { "no_uuid",               0,  ONE_ROW("{\"if_name\":\"wl0\"}"),                                  0,     0,  -1 },
    { "uuid_not_string",       0,  ONE_ROW("{\"_uuid\":[\"uuid\",42]}"),                              0,     0,  -1 },
    { "from_json_fails",       0,  ONE_ROW("{\"_uuid\":[\"uuid\",\"" UUID_STR "\"]}"),                1,     0,  -1 },
    { "success",               0,  ONE_ROW("{\"_uuid\":[\"uuid\",\"" UUID_STR "\"],\"if_name\":\"wl0\"}"), 0, 0,   0 },
    { "success_long_values",   0,  "LONG",                                                            0,   255,   0 },

    { NULL, 0, NULL, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_cache_pre_fetch_input(const ovsdb_cache_pre_fetch_test_case_t *tc)
{
    memset(&ocp_table, 0, sizeof(ocp_table));
    snprintf(ocp_table.table_name, sizeof(ocp_table.table_name), "Wifi_VIF_Config");
    snprintf(ocp_table.key_name, sizeof(ocp_table.key_name), "if_name");
    ocp_table.schema_size = OCI_SCHEMA_SZ;
    ocp_table.row_size    = (int)(sizeof(ovsdb_cache_row_t) + OCI_SCHEMA_SZ);
    ocp_table.uuid_offset = OCI_UUID_OFF;
    ocp_table.key_offset  = OCI_KEY_OFF;
    ocp_table.key2_offset = -1;
    ocp_table.from_json   = ocp_from_json;

    memset(ocp_key, 0, sizeof(ocp_key));
    if (tc->key_fill) memset(ocp_key, 'k', (size_t)tc->key_fill);
    else              snprintf(ocp_key, sizeof(ocp_key), "wl0");
    ocp_key_len = strlen(ocp_key);

    if (tc->result && !strcmp(tc->result, "LONG")) {
        char longname[256]; memset(longname, 'n', 255); longname[255] = 0;
        snprintf(ocp_json_buf, sizeof(ocp_json_buf),
                 "[{\"rows\":[{\"_uuid\":[\"uuid\",\"%s\"],\"if_name\":\"%s\"}]}]", UUID_STR, longname);
        ocp_result_json = ocp_json_buf;
    } else {
        ocp_result_json = tc->result;
    }
    ocp_row_exists  = tc->row_exists;
    ocp_fj_fail     = tc->fj_fail;
    ocp_freed       = 0;
    ocp_perr_len    = 0;
    ocp_calloc_size = 0;
    oci_inserts     = 0;
    oci_msg_len     = 0;
}
