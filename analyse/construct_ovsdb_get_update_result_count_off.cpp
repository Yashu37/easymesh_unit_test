/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_get_update_result_count_off
 *
 * result is an OVSDB transact result array, e.g. [{}, {"count": 1}] or
 * [{}, {"error": ...}]. table / oper are copied into runner buffers (tail
 * poisoned by the runner).
 *
 * Cases: result NULL, empty array, success with/without the leading {},
 * offset 1 of 3 statuses, offset past the end, negative offset, status
 * without count, short error, 300-char error string (errstr 256 -> refused,
 * "json_gets() error"), 252-char error (254 + NUL fits), error object with
 * 50 keys, and a 3000-element result (json_dumps_static 8192 overflow ->
 * refused).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   ogug_slot[OGU_SLOT_SZ + OGU_SLOT_PAD];
size_t ogug_errstr_len;
int    ogug_calls;
char   ogu_table[OGU_STR_SZ];
char   ogu_oper[OGU_STR_SZ];

ovsdb_get_update_result_count_off_test_case_t ovsdb_get_update_result_count_off_suite[] = {
    /* name               kind  offset count errlen */
    { "result_null",        0,    0,    -1,   -1 },
    { "empty_array",        1,    0,    -1,   -1 },
    { "success",            2,    0,     1,   -1 },
    { "success_no_lead",    3,    0,     4,   -1 },
    { "offset_1_of_3",      4,    1,     7,   -1 },
    { "offset_past_end",    2,    5,    -1,   -1 },
    { "offset_negative",    2,   -1,    -1,   -1 },
    { "status_no_count",    5,    0,    -1,   -1 },
    { "error_short",        6,    0,    -1,   12 },
    { "error_300",          7,    0,    -1,   17 },
    { "error_252",          8,    0,    -1,  254 },
    { "error_obj_50_keys",  9,    0,    -1,   17 },
    { "result_3000",       10,    0,     1,   -1 },

    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

static json_t *strn(int n, char c)
{
    char *s = (char *)malloc((size_t)n + 1); memset(s, c, (size_t)n); s[n] = 0;
    json_t *j = json_string(s); free(s); return j;
}

void *construct_ovsdb_get_update_result_count_off_result(const ovsdb_get_update_result_count_off_test_case_t *tc)
{
    switch (tc->kind) {
    case 1:  return json_array();
    case 2:  return json_pack("[{},{s:i}]", "count", 1);
    case 3:  return json_pack("[{s:i}]", "count", 4);
    case 4:  return json_pack("[{},{s:i},{s:i},{s:i}]", "count", 5, "count", 7, "count", 9);
    case 5:  return json_pack("[{},{s:s}]", "foo", "bar");
    case 6:  return json_pack("[{},{s:s}]", "error", "constraint");
    case 7:  return json_pack("[{},{s:o}]", "error", strn(300, 'e'));
    case 8:  return json_pack("[{},{s:o}]", "error", strn(252, 'e'));
    case 9: {
        json_t *e = json_object();
        for (int i = 0; i < 50; i++) { char k[16]; snprintf(k, sizeof(k), "key%02d", i); json_object_set_new(e, k, json_string("value")); }
        return json_pack("[{},{s:o}]", "error", e);
    }
    case 10: {
        json_t *r = json_pack("[{},{s:i}]", "count", 1);
        for (int i = 0; i < 3000; i++) json_array_append_new(r, json_pack("{s:i}", "count", i));
        return r;
    }
    default: return NULL;
    }
}

void construct_ovsdb_get_update_result_count_off_input(const ovsdb_get_update_result_count_off_test_case_t *tc)
{
    (void)tc;
    snprintf(ogu_table, sizeof(ogu_table), "Wifi_VIF_Config");
    snprintf(ogu_oper, sizeof(ogu_oper), "update");
    ogug_errstr_len = (size_t)-1;
    ogug_calls = 0;
}
