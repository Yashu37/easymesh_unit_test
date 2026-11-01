/*
 * HANDLER: onewifi_ovsdb_sync_upsert_where
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_sync_api.c. No fixes.
 * Local where_str[WHERE_STR_SIZE] (128) is filled by
 * json_get_str(where, where_str, sizeof(where_str)) -> json_gets() ->
 * json_dump_callback with json_gets_fn, which refuses any chunk that would
 * reach buf + buf_sz and always NUL-terminates (helpers copied VERBATIM).
 * Caller inputs (table name, uuid output) are poisoned by the runner;
 * where_str is internal (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test):
 *   - json_get_str / json_gets / json_gets_fn: verbatim from
 *     lib/json_util/string.c.
 *   - onewifi_ovsdb_sync_update_one_get_uuid: stub (count per case; on 1
 *     writes the uuid with a bounded copy); releases where/row like the real.
 *   - onewifi_ovsdb_sync_insert: stub (ok per case; writes the uuid with a
 *     bounded copy); releases row.
 *   - LOG no-op.
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

static int onewifi_ovsdb_sync_update_one_get_uuid(const char *sock, const char *table, json_t *where, json_t *row, ovs_uuid_t *uuid)
{
    (void)sock;
    osp_updates++;
    osp_table_seen = strlen(table);
    if (where) json_decref(where);
    json_decref(row);
    if (uuid && osp_update_count == 1)
        snprintf(uuid->uuid, sizeof(uuid->uuid), "%s", osp_db_uuid);
    return osp_update_count;
}
static bool onewifi_ovsdb_sync_insert(const char *sock, const char *table, json_t *row, ovs_uuid_t *uuid)
{
    (void)sock; (void)table;
    osp_inserts++;
    json_decref(row);
    if (!osp_insert_ok) return false;
    if (uuid) snprintf(uuid->uuid, sizeof(uuid->uuid), "%s", osp_db_uuid);
    return true;
}

/* --- copied verbatim from lib/ovsdb/ovsdb_sync_api.c --- */
// uuid is optional, 'where' should match a single row
bool onewifi_ovsdb_sync_upsert_where(const char *ovsdb_sock_path, const char *table, json_t *where, json_t *row, ovs_uuid_t *uuid)
{
    int count;
    char where_str[WHERE_STR_SIZE];

    json_get_str(where, where_str, sizeof(where_str));
    json_incref(row);
    count = onewifi_ovsdb_sync_update_one_get_uuid(ovsdb_sock_path, table, where, row, uuid);
    if (count == 1)
    {
        json_decref(row);
        return true;
    }
    else if (count == 0)
    {
        LOG(TRACE, "upsert %s: update where '%s': no match - performing insert",
                table, where_str);
        return onewifi_ovsdb_sync_insert(ovsdb_sock_path, table, row, uuid);
    }
    else
    {
        LOG(ERR, "%s: unexpected count: %d", __FUNCTION__, count);
        json_decref(row);
    }
    return false;
}
