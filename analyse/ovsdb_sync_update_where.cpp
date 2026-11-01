/*
 * HANDLER: onewifi_ovsdb_sync_update_where
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_sync_api.c. No fixes.
 * Local where_str[WHERE_STR_SIZE] (128) is filled by
 * json_get_str(where, where_str, sizeof(where_str)) -> json_gets() ->
 * json_dump_callback with json_gets_fn, which refuses any chunk that would
 * reach buf + buf_sz and always NUL-terminates (helpers copied VERBATIM).
 * Caller input table is poisoned by the runner; where_str is internal
 * (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test):
 *   - json_get_str / json_gets / json_gets_fn: verbatim from
 *     lib/json_util/string.c.
 *   - onewifi_ovsdb_tran_call_s: stub returning the result JSON per case.
 *   - onewifi_ovsdb_get_update_result_count: stub reading
 *     [{...}, {"count": N}] (-1 if NULL / malformed); releases result.
 *   - LOG no-op (json_dumps_static never called).
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
#define WHERE_STR_SIZE (128) // length of temp string for debug log   (ovsdb_sync_api.c:39)
enum { OTR_UPDATE = 0 };

/* verbatim from lib/json_util/string.c */
struct json_gets_data
{
    char   *buf;
    size_t  buf_sz;
    char   *pbuf;
};

static int json_gets_fn(
        const char *input,
        size_t input_len,
        void *ctx)
{
    struct json_gets_data *data = ctx;
    int retval = -1;

    /* Boundary check */
    if (data->pbuf + input_len >= data->buf + data->buf_sz)
    {
        /* Pad string */
        goto error;
    }

    memcpy(data->pbuf, input, input_len);

    data->pbuf += input_len;

    retval = 0;

error:
    /* Pad string */
    *data->pbuf = '\0';

    return retval;
}

static bool json_gets(
        const json_t *json,
        char *output,
        size_t output_sz,
        int flags)
{
    struct json_gets_data data;

    data.buf = output;
    data.buf_sz = output_sz;
    data.pbuf = output;

    if (json_dump_callback(json, json_gets_fn, &data, flags) != 0)
    {
        snprintf(output, output_sz, "json_gets() error");
        return false;
    }

    return true;
}

static bool json_get_str(const json_t *json, char *output, size_t output_sz)
{
    *output = 0;
    if (!json) return true;
    if (!json_gets(json, output, output_sz, JSON_ENCODE_ANY))
    {
        *output = 0;
        return false;
    }
    return true;
}

static json_t *onewifi_ovsdb_tran_call_s(const char *sock, const char *table, int op, json_t *where, json_t *row)
{
    (void)sock; (void)op;
    osw_calls++;
    osw_table_seen = strlen(table);
    if (where) json_decref(where);
    if (row) json_decref(row);
    return osw_result ? json_loads(osw_result, 0, NULL) : NULL;
}
static int onewifi_ovsdb_get_update_result_count(json_t *result, const char *table, const char *oper)
{
    (void)table; (void)oper;
    int count = -1;
    json_t *jc = json_object_get(json_array_get(result, 1), "count");
    if (json_is_integer(jc)) count = (int)json_integer_value(jc);
    if (result) {
        json_decref(result);
    }
    return count;
}

/* --- copied verbatim from lib/ovsdb/ovsdb_sync_api.c --- */
// return count or -1 on error
// if where is NULL, update ALL rows in table
int onewifi_ovsdb_sync_update_where(const char *ovsdb_sock_path, const char *table, json_t *where, json_t *row)
{
    int rc;
    json_t *result = NULL;
    char where_str[WHERE_STR_SIZE];

    json_get_str(where, where_str, sizeof(where_str));
    LOG(DEBUG, "Table %s where: '%s' update: %s", table, where_str, json_dumps_static(row, 0));
    result = onewifi_ovsdb_tran_call_s(ovsdb_sock_path, table, OTR_UPDATE, where, row);
    // successfull result: [{}, {"count": 1}]
    // errors handled by:
    rc =  onewifi_ovsdb_get_update_result_count(result, table, "update");
    if (rc == 0)
    {
        // warn if no match - nothing updated
        LOG(DEBUG, "OVSDB: Update table '%s' where '%s': no match", table, where_str);
    }

    return rc;
}
