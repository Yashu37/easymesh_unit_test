/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_table_to_json
 *
 * Record layout = the update_cb harness schema (OCU_*: _update_type @0,
 * _uuid[37] @4, _version[37] @41, if_name[64] @78, schema_size 142).
 * table->to_json is a pjs-style test serializer: it reads the record
 * fields with strnlen bounded by each field size; when asked to fail it
 * writes a 300-char error with snprintf(err, sizeof(pjs_errmsg_t)).
 *
 * Cases: normal record, empty record, fields filled to their full size
 * (63-char if_name / 36-char uuid; each NUL is the last byte of its field,
 * and if_name's NUL is the last byte of the record), and a conversion error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

alignas(16) char ott_rec[OCU_SCHEMA_SZ + 64];
ovsdb_table_t ott_table;
size_t ott_perr_len;
int    ott_calls, ott_fail;

static void *ott_to_json(void *in, pjs_errmsg_t err)
{
    char *rec = (char *)in;
    ott_calls++;
    if (ott_fail) {
        char big[301]; memset(big, 'E', 300); big[300] = 0;
        snprintf(err, sizeof(pjs_errmsg_t), "convert error: %s", big);
        ott_perr_len = strnlen(err, sizeof(pjs_errmsg_t));
        return NULL;
    }
    char u[37], n[64];
    snprintf(u, sizeof(u), "%.*s", (int)strnlen(rec + OCU_UUID_OFF, 36), rec + OCU_UUID_OFF);
    snprintf(n, sizeof(n), "%.*s", (int)strnlen(rec + OCU_KEY_OFF, 63), rec + OCU_KEY_OFF);
    return json_pack("{s:[s,s],s:s}", "_uuid", "uuid", u, "if_name", n);
}

ovsdb_table_to_json_test_case_t ovsdb_table_to_json_suite[] = {
    /* name              kind fail ret_obj */
    { "normal_record",     1,   0,    1 },
    { "empty_record",      0,   0,    1 },
    { "full_size_fields",  2,   0,    1 },
    { "convert_error",     1,   1,    0 },

    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_table_to_json_input(const ovsdb_table_to_json_test_case_t *tc)
{
    memset(ott_rec, 0, sizeof(ott_rec));
    if (tc->kind == 1) {
        snprintf(ott_rec + OCU_UUID_OFF, 37, "0123abcd-4567-89ef-0123-456789abcdef");
        snprintf(ott_rec + OCU_KEY_OFF, 64, "wl0");
    } else if (tc->kind == 2) {
        memset(ott_rec + OCU_UUID_OFF, 'u', 36);
        memset(ott_rec + OCU_KEY_OFF, 'n', 63);
    }
    memset(&ott_table, 0, sizeof(ott_table));
    snprintf(ott_table.table_name, sizeof(ott_table.table_name), "Wifi_VIF_Config");
    ott_table.schema_size = OCU_SCHEMA_SZ;
    ott_table.to_json     = ott_to_json;
    ott_fail     = tc->fail;
    ott_perr_len = 0;
    ott_calls    = 0;
}
