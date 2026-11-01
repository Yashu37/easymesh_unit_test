/*
 * HANDLER: ovsdb_sync_get_uuid_and_count
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_sync_api.c. No fixes.
 * Local arrays:
 *   - where_str[WHERE_STR_SIZE = 128]: json_get_str(where, where_str,
 *     sizeof(where_str)) -> json_gets(..., 128, JSON_ENCODE_ANY).
 *   - uuid1 (ovs_uuid_t, uuid[37]) used when the caller passes uuid NULL.
 * STRSCPY(uuid->uuid, str_uuid) copies the selected row's _uuid bounded
 * by sizeof(uuid->uuid) = 37.
 *
 * Poison route: json_gets() is redirected to ogc_json_gets(), which runs
 * the VERBATIM json_gets / json_gets_fn on the runner slot ogc_slot with
 * the SAME size (128), then copies the result back. The runner poisons
 * ogc_slot past 128 around the call, plus the caller's uuid, table and
 * sock path.
 *
 * Scaffolding (NOT the function under test):
 *   - json_gets / json_gets_fn / json_get_str: verbatim from
 *     lib/json_util/string.c. strscpy verbatim from lib/common/util.c.
 *   - LOG: really formats its arguments (vsnprintf), so where_str is read.
 *   - onewifi_ovsdb_sync_select_where: stub that consumes where (like the
 *     real transact call) and returns the case's rows array.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <jansson.h>
#include "common.h"

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
static void ogc_log(const char *fmt, ...)
{
    char scratch[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define LOG(sev, ...) ogc_log(__VA_ARGS__)
#define WHERE_STR_SIZE (128) // length of temp string for debug log   (lib/ovsdb/ovsdb_sync_api.c)
#define ASSERT_ARRAY(x)     (x)
#define STRSCPY(dest, src)  strscpy(ASSERT_ARRAY(dest), (src), sizeof(dest))   /* lib/common/util.h */

/* verbatim from lib/common/util.c */
static ssize_t strscpy(char *dest, const char *src, size_t size)
{
    size_t len;
    if (size == 0) return -E2BIG;
    len = strnlen(src, size - 1);
    memcpy(dest, src, len);
    dest[len] = 0;
    if (src[len]) return -E2BIG;
    return (ssize_t)len;
}

/* verbatim from lib/json_util/string.c */
struct json_gets_data
{
    char   *buf;
    size_t  buf_sz;
    char   *pbuf;
};

static int json_gets_fn(const char *input, size_t input_len, void *ctx);

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

int json_gets_fn(
        const char *input,
        size_t input_len,
        void *ctx)
{
    struct json_gets_data *data = (struct json_gets_data *)ctx;
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

/* json_gets redirect: write into a runner-owned slot, tail past output_sz poisoned */
static bool ogc_json_gets(const json_t *json, char *output, size_t output_sz, int flags)
{
    bool r;
    if (output_sz > OGC_SLOT_SZ) output_sz = OGC_SLOT_SZ;
    memset(ogc_slot, 0, output_sz);
    r = json_gets(json, ogc_slot, output_sz, flags);
    memcpy(output, ogc_slot, output_sz);
    ogc_where_len = strnlen(ogc_slot, output_sz);
    return r;
}
#define json_gets(j, o, s, f)  ogc_json_gets((j), (o), (s), (f))

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

static json_t* onewifi_ovsdb_sync_select_where(const char *sock, const char *table, json_t *where)
{
    (void)sock; (void)table;
    if (where) json_decref(where);         /* transact call consumes where */
    json_t *r = (json_t *)ogc_rows;
    ogc_rows = NULL;                       /* ownership passes to the caller */
    return r;
}

/* --- copied verbatim from lib/ovsdb/ovsdb_sync_api.c --- */
int ovsdb_sync_get_uuid_and_count(const char *ovsdb_sock_path, const char *table, json_t *where, ovs_uuid_t *uuid)
{
    int count = -1;
    json_t *jrows = NULL;
    json_t *juuid = NULL;
    const char *str_uuid = NULL;
    ovs_uuid_t uuid1;
    char where_str[WHERE_STR_SIZE];

    json_get_str(where, where_str, sizeof(where_str));
    if (!uuid) uuid = &uuid1;
    // select
    jrows = onewifi_ovsdb_sync_select_where(ovsdb_sock_path, table, where);
    // count
    count = json_array_size(jrows);
    if (count == 0)
    {
        LOG(TRACE, "get uuid %s where '%s': no records found",
                table, where_str);
        goto out;
    }
    if (count > 1)
    {
        LOG(ERR, "get uuid %s where '%s' unexpected count: %d",
                table, where_str, count);
        goto out;
    }
    // extract uuid
    juuid = json_object_get(json_array_get(jrows, 0), "_uuid");
    str_uuid = json_string_value(json_array_get(juuid, 1));
    if (!juuid || !str_uuid || !*str_uuid)
    {
        LOG(ERR, "get uuid %s where '%s' count: %d no uuid",
                table, where_str, count);
        count = -1; // mark failure
        goto out;
    }
    LOG(TRACE, "get uuid %s where '%s' count: %d uuid: %s",
            table, where_str, count, str_uuid);
out:
    STRSCPY(uuid->uuid, str_uuid ? str_uuid : "");
    json_decref(jrows);
    return count;
}
