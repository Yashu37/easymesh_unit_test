/*
 * HANDLER: ovsdb_get_update_result_count_off
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_sync_api.c. No fixes.
 * Local errstr[256] is filled by json_gets(jerr, errstr, sizeof(errstr),
 * JSON_ENCODE_ANY) when the selected status object carries "error".
 * json_dumps_static (in the LOG args) uses the static dumps_static_buf[8192].
 *
 * Poison route: json_gets() is redirected to ogug_json_gets(), which runs
 * the VERBATIM json_gets / json_gets_fn on a runner slot with the SAME size
 * as the real buffer -- ogug_slot_err (256) for errstr, ogug_slot (8192)
 * for dumps_static_buf -- then copies the result back. The runner poisons
 * ogug_slot_err past 256 and ogug_slot past 8192 around the call, so a
 * write past the size given aborts. errstr is also guarded by ASan stack
 * redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - json_gets / json_gets_fn / json_dumps_static: verbatim from
 *     lib/json_util/string.c.
 *   - LOG: really formats its arguments (vsnprintf), so json_dumps_static
 *     and errstr are executed / read.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <jansson.h>
#include "common.h"

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
static void ogu_log(const char *fmt, ...)
{
    char scratch[16384];
    va_list ap; va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define LOG(sev, ...) ogu_log(__VA_ARGS__)

/* verbatim from lib/json_util/string.c */
struct json_gets_data
{
    char   *buf;
    size_t  buf_sz;
    char   *pbuf;
};

static char dumps_static_buf[8192];

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
static bool ogug_json_gets(const json_t *json, char *output, size_t output_sz, int flags)
{
    bool r;
    char *slot = (output_sz == OGU_ERR_SZ) ? ogug_slot_err : ogug_slot;   /* errstr : dumps_static_buf */
    if (output_sz > OGU_SLOT_SZ) output_sz = OGU_SLOT_SZ;
    memset(slot, 0, output_sz);
    r = json_gets(json, slot, output_sz, flags);
    memcpy(output, slot, output_sz);
    if (output_sz == OGU_ERR_SZ) ogug_errstr_len = strnlen(slot, output_sz);
    ogug_calls++;
    return r;
}
#define json_gets(j, o, s, f)  ogug_json_gets((j), (o), (s), (f))

static const char *json_dumps_static(const json_t *json, int flags)
{
    // this is mostly used by debug logs so enable ENCODE_ANY by default
    // to get a meaningful output instead of getting empty strings
    // when json is a simple value instead of object
    flags |= JSON_ENCODE_ANY;
    if (!json_gets(json, dumps_static_buf, sizeof(dumps_static_buf), flags))
    {
        dumps_static_buf[0] = '\0';
    }

    return dumps_static_buf;
}

/* --- copied verbatim from lib/ovsdb/ovsdb_sync_api.c --- */
int ovsdb_get_update_result_count_off(json_t *result, const char *table, const char *oper, int offset)
{
    // success: result: [{}, {"count": 1}]
    // error: result: [{}, {"error": ...}]
    int count = -1;
    int offt = 0;
    json_t *jstatus = NULL;
    json_t *jerr = NULL;
    json_t *jcount = NULL;
    json_t *jfirst = NULL;

    if (result == NULL)
    {
        LOG(ERR, "Table %s %s result: NULL", table, oper);
        return -1;
    }

    /* Check if the first element is an empty array, skip it in that case */
    jfirst = json_array_get(result, 0);
    if (jfirst == NULL)
    {
        LOG(ERR, "Table %s %s result invalid", table, oper);
        goto out;
    }
    if (json_is_object(jfirst) && json_object_size(jfirst) == 0)
    {
        offt = 1;
    }

    LOG(DEBUG, "Table %s %s result: %s off: %d", table, oper, json_dumps_static(result, 0), offset);
    if (json_array_size(result) < (size_t)(offset + offt)) {
        LOG(ERR, "Table %s %s result size is smaller then requested offset %d", table, oper, offset + offt);
        goto out;
    }

    jstatus = json_array_get(result, offset + offt);
    if (!jstatus) {
        LOG(ERR, "Table %s %s: no status", table, oper);
        goto out;
    }

    jerr = json_object_get(jstatus, "error");
    if (jerr) {
        char errstr[256] = "";
        json_gets(jerr, errstr, sizeof(errstr), JSON_ENCODE_ANY);
        LOG(ERR, "Table %s %s error: %s status: %s", table, oper, errstr,
                json_dumps_static(jstatus, JSON_ENCODE_ANY));
        goto out;
    }

    jcount = json_object_get(jstatus, "count");
    if (!jcount) {
        LOG(ERR, "Table %s %s error: no count", table, oper);
        goto out;
    }
    count = json_integer_value(jcount);
    LOG(DEBUG, "Table %s %s count: %d", table, oper, count);
out:
    return count;

}
