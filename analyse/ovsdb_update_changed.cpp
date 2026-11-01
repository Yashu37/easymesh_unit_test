/*
 * HANDLER: onewifi_ovsdb_update_changed
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_update.c. No fixes.
 * Local v_old[256] / v_new[256] are filled (MODIFY only) by
 * json_gets(j, v, sizeof(v), JSON_ENCODE_ANY | JSON_COMPACT); json_gets'
 * callback json_gets_fn stops when pbuf + input_len >= buf + buf_sz.
 *
 * Poison route: json_gets() is redirected to oucg_json_gets(), which runs
 * the VERBATIM json_gets / json_gets_fn on a runner-owned slot of the SAME
 * size (256) whose tail is poisoned, then copies the result into v_old /
 * v_new. So a write by json_gets past 256 aborts on our poison. v_old /
 * v_new themselves are also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - json_gets / json_gets_fn: verbatim from lib/json_util/string.c.
 *   - LOG: really formats its arguments (vsnprintf), so v_old / v_new,
 *     mon_table and field are read. str_bool from lib/common/util.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
static void ouc_log(const char *fmt, ...)
{
    char scratch[2048];
    va_list ap; va_start(ap, fmt);
    vsnprintf(scratch, sizeof(scratch), fmt, ap);
    va_end(ap);
}
#define LOG(sev, ...) ouc_log(__VA_ARGS__)

static char* str_bool(bool a) { return a ? (char *)"true" : (char *)"false"; }   /* lib/common/util.c */

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

/* json_gets redirect: write into a runner-owned, tail-poisoned slot of the same size */
static bool oucg_json_gets(const json_t *json, char *output, size_t output_sz, int flags)
{
    char *slot = oucg_slot[oucg_next++ & 1];
    bool r;
    if (output_sz > OUC_SLOT_SZ) output_sz = OUC_SLOT_SZ;
    memset(slot, 0, output_sz);
    __asan_poison_memory_region(slot + output_sz, OUC_SLOT_SZ + OUC_SLOT_PAD - output_sz);
    r = json_gets(json, slot, output_sz, flags);
    __asan_unpoison_memory_region(slot + output_sz, OUC_SLOT_SZ + OUC_SLOT_PAD - output_sz);
    memcpy(output, slot, output_sz);
    oucg_len[(oucg_next - 1) & 1] = strnlen(slot, output_sz);
    return r;
}
#define json_gets(j, o, s, f)  oucg_json_gets((j), (o), (s), (f))

/* --- copied verbatim from lib/ovsdb/ovsdb_update.c --- */
bool onewifi_ovsdb_update_changed(ovsdb_update_monitor_t *self, char *field)
{
    bool changed = false;
    char *tname = "UNK";
    json_t *j_old;
    json_t *j_new;
    char v_old[256] = "";
    char v_new[256] = "";
    switch (self->mon_type)
    {
        // on NEW and DEL mark as changed
        case OVSDB_UPDATE_NEW:
            tname = "NEW";
            changed = true;
            break;
        case OVSDB_UPDATE_DEL:
            tname = "DEL";
            changed = true;
            break;
        case OVSDB_UPDATE_MODIFY:
            // on MODIFY mark as changed if it exists in old
            // ovsdb will always send old values for fields that changed
            tname = "MOD";
            j_old = json_object_get(self->mon_json_old, field);
            if (j_old != NULL)
            {
                changed = true;
                j_new = json_object_get(self->mon_json_new, field);
                json_gets(j_old, v_old, sizeof(v_old), JSON_ENCODE_ANY | JSON_COMPACT);
                json_gets(j_new, v_new, sizeof(v_new), JSON_ENCODE_ANY | JSON_COMPACT);
            }
            break;
        case OVSDB_UPDATE_ERROR:
            tname = "ERR";
        default:
            break;
    }
    if (changed)
    {
        LOG(TRACE, "update '%s' changed: %s '%s.%s' '%s' => '%s'",
                tname, str_bool(changed),
                self->mon_table, field,
                v_old, v_new);
    }
    else
    {
        LOG(TRACE, "update '%s' changed: %s '%s.%s'",
                tname, str_bool(changed),
                self->mon_table, field);
    }
    return changed;
}
