/*
 * HANDLER: onewifi_ovsdb_cache_pre_fetch
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_cache.c. No fixes.
 * Local perr (pjs_errmsg_t = char[128]) is handed to table->from_json(),
 * which writes its error text with snprintf(err, sizeof(pjs_errmsg_t)).
 * The row comes from calloc(1, table->row_size) and from_json fills
 * row->record. Caller input key is poisoned by the runner; perr is internal
 * (auto-guarded by ASan); the row comes from a runner pool with a poisoned
 * tail past row_size.
 *
 * Scaffolding (NOT the function under test):
 *   - onewifi_ovsdb_cache_find_row_by_key: stub, "found" per test case.
 *   - onewifi_ovsdb_tran_cond / onewifi_ovsdb_tran_call_s: stubs; call_s
 *     returns the JSON result chosen by the test case (real jansson json).
 *   - calloc/free -> runner row pool (poisoned tail).
 *   - _ovsdb_cache_insert_row: the real copy from ovsdb_cache_insert_row.cpp.
 *   - LOG no-op (so json_dumps_static is never called).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
enum { OTR_SELECT = 0 };                 /* lib/ovsdb/ovsdb.h (value irrelevant here) */
enum { OFUNC_EQ = 0 };
enum { OCLM_STR = 0 };

void _ovsdb_cache_insert_row(ovsdb_table_t *table, ovsdb_cache_row_t *row);

static ovsdb_cache_row_t *onewifi_ovsdb_cache_find_row_by_key(ovsdb_table_t *table, const char *key)
{
    (void)table; (void)key;
    return ocp_row_exists ? (ovsdb_cache_row_t *)ocp_rowpool : NULL;
}
static json_t *onewifi_ovsdb_tran_cond(int type, const char *col, int func, const void *val)
{
    (void)type; (void)col; (void)func; (void)val;
    return json_null();
}
static json_t *onewifi_ovsdb_tran_call_s(const char *sock, const char *table, int op, json_t *where, json_t *row)
{
    (void)sock; (void)table; (void)op; (void)row;
    json_decref(where);
    return ocp_result_json ? json_loads(ocp_result_json, 0, NULL) : NULL;
}
static void *ocp_calloc(size_t n, size_t sz)
{
    if (n * sz > OCP_POOL_SZ) return NULL;
    memset(ocp_rowpool, 0, n * sz);
    ocp_calloc_size = n * sz;
    return ocp_rowpool;
}
static void ocp_free(void *p) { (void)p; ocp_freed = 1; }
#define calloc(n, s) ocp_calloc((n), (s))
#define free(p)      ocp_free(p)

/* --- copied verbatim from lib/ovsdb/ovsdb_cache.c --- */
int onewifi_ovsdb_cache_pre_fetch(const char *ovsdb_sock_path, ovsdb_table_t *table, char *key)
{
    ovsdb_cache_row_t *row;
    pjs_errmsg_t perr;
    json_t *result;
    json_t *jrows;
    json_t *jrow;
    json_t *juuid;
    json_t *where;
    const char *uuid;
    int ret;

    if (onewifi_ovsdb_cache_find_row_by_key(table, key))
    {
        // already exists
        return 0;
    }

    where = onewifi_ovsdb_tran_cond(OCLM_STR, table->key_name, OFUNC_EQ, key);
    result = onewifi_ovsdb_tran_call_s(ovsdb_sock_path, table->table_name, OTR_SELECT, where, NULL);
    if (!result)
    {
        LOG(WARNING, "%s query: %s %s no result", __FUNCTION__, table->table_name, key);
        return -1;
    }
    LOG(DEBUG, "%s query %s %s result: %s", __FUNCTION__,
            table->table_name, key, json_dumps_static(result, 0));
    jrows = json_object_get(json_array_get(result, 0), "rows");
    if (json_array_size(jrows) != 1)
    {
        LOG(WARNING, "%s query: %s %s num rows: %zd", __FUNCTION__,
                table->table_name, key, json_array_size(jrows));
        json_decref(result);
        return -1;
    }
    jrow = json_array_get(jrows, 0);
    LOG(DEBUG, "row: %s", json_dumps_static(jrow, 0));
    juuid = json_object_get(jrow, "_uuid");
    uuid = json_string_value(json_array_get(juuid, 1));
    LOG(DEBUG, "uuid: %s", uuid);
    if (!uuid)
    {
        LOG(WARNING, "%s query: %s %s no uuid", __FUNCTION__,
                table->table_name, key);
        json_decref(result);
        return -1;
    }

    row = calloc(1, table->row_size);
    ret = table->from_json(row->record, jrow, false, perr);
    json_decref(result);
    if (!ret)
    {
        free(row);
        LOG(ERR, "Table %s parsing %s error: %s",
                table->table_name, uuid, perr);
        return -1;
    }

    // add new
    LOG(NOTICE, "pre-fetch %s %s uuid: %s", table->table_name, key, uuid);
    _ovsdb_cache_insert_row(table, row);

    return 0;
}
