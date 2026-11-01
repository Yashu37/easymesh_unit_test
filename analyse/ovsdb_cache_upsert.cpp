/*
 * HANDLER: onewifi_ovsdb_cache_upsert
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_cache.c. No fixes.
 * Local arrays: perr (pjs_errmsg_t = char[128], written only by
 * table->to_json with a bounded snprintf) and uuid (ovs_uuid_t, char[37],
 * filled by onewifi_ovsdb_sync_upsert). Copies into the caller record and
 * into rows use strscpy(..., sizeof(ovs_uuid_t)) and memcpy(schema_size).
 * The caller record, the cached row and the new row all live in runner
 * buffers with poisoned tails; perr/uuid are internal (ASan-guarded).
 *
 * Scaffolding (NOT the function under test):
 *   - strscpy: verbatim from lib/common/util.c.
 *   - onewifi_ovsdb_cache_find_row_by_key: stub (cached row per case).
 *   - onewifi_ovsdb_sync_upsert: stub; returns ok/fail per case and, when
 *     asked for the uuid, writes it with a bounded copy (like the real one).
 *   - calloc -> runner row pool.  _ovsdb_cache_insert_row: real copy.
 *   - LOG no-op.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)

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

void _ovsdb_cache_insert_row(ovsdb_table_t *table, ovsdb_cache_row_t *row);

static ovsdb_cache_row_t *onewifi_ovsdb_cache_find_row_by_key(ovsdb_table_t *table, const char *key)
{
    (void)table; (void)key;
    return ocs_cached ? (ovsdb_cache_row_t *)ocs_pool[0] : NULL;
}
static bool onewifi_ovsdb_sync_upsert(const char *sock, const char *table, const char *col,
                                      const char *val, json_t *row, ovs_uuid_t *uuid)
{
    (void)sock; (void)table; (void)col; (void)val;
    json_decref(row);
    ocs_upserts++;
    ocs_asked_uuid = (uuid != NULL);
    if (!ocs_upsert_ok) return false;
    if (uuid) snprintf(uuid->uuid, sizeof(uuid->uuid), "%s", ocs_db_uuid);
    return true;
}
static void *ocs_calloc(size_t n, size_t sz)
{
    if (n * sz > OCS_SLOT_SZ) return NULL;
    memset(ocs_pool[1], 0, n * sz);
    return ocs_pool[1];
}
#define calloc(n, s) ocs_calloc((n), (s))

/* --- copied verbatim from lib/ovsdb/ovsdb_cache.c --- */
int onewifi_ovsdb_cache_upsert(const char *ovsdb_sock_path, ovsdb_table_t *table, void *record)
{
    char *rec = record;
    ovsdb_cache_row_t *row;
    char *key;
    ovs_uuid_t uuid;
    bool ret;
    // check if primary key defined
    if (table->key_offset < 0)
    {
        LOG(ERR, "table %s upsert: no key", table->table_name);
        return -1;
    }
    // find existing
    key = rec + table->key_offset;
    row = onewifi_ovsdb_cache_find_row_by_key(table, key);
    if (row)
    {
        // copy uuid and version for compare
        strscpy(rec + table->uuid_offset,    row->record + table->uuid_offset, sizeof(ovs_uuid_t));
        strscpy(rec + table->version_offset, row->record + table->version_offset, sizeof(ovs_uuid_t));
        if (memcmp(rec, row->record, table->schema_size) == 0)
        {
            LOG(INFO, "upsert %s %s: no change", table->table_name, key);
            return 0;
        }
    }
    // changed or new, upsert to db
    // convert to json
    pjs_errmsg_t perr;
    json_t *jrow = table->to_json(record, perr);
    if (!jrow)
    {
        LOG(ERR, "convert %s %s: %s", table->table_name, key, perr);
        return -1;
    }
    // if already have row, skip retrieve uuid
    bool have_uuid = row && (rec[table->uuid_offset] != 0);

    ret = onewifi_ovsdb_sync_upsert(ovsdb_sock_path, table->table_name, table->key_name, key, jrow, have_uuid ? NULL : &uuid);
    if (!ret)
    {
        LOG(ERR, "upsert %s %s: error", table->table_name, key);
        return -1;
    }
    // store to cache
    if (row)
    {
        // update existing
        memcpy(row->record, record, table->schema_size);
    }
    else
    {
        // add new
        ovsdb_cache_row_t *new_row;
        new_row = calloc(1, table->row_size);
        strscpy(record + table->uuid_offset, uuid.uuid, sizeof(ovs_uuid_t));
        memcpy(new_row->record, record, table->schema_size);
        LOG(INFO, "upsert %s %s: uuid: %s", table->table_name, key, uuid.uuid);
        _ovsdb_cache_insert_row(table, new_row);
    }
    return 0;
}
