/*
 * HANDLER: onewifi_ovsdb_cache_update_cb
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_cache.c. No fixes.
 * C++-only change: "int *_update_type = ...;" is split into a declaration
 * plus assignment, because C++ rejects case labels that jump over an
 * initialised declaration (C allows it). Same behaviour.
 * Local arrays:
 *   - perr (char[128]) -> written only by table->from_json (bounded snprintf)
 *   - record[table->schema_size], old_record[table->schema_size]: VLAs; all
 *     writes are memset/memcpy of sizeof(record), from_json of one schema
 *     record, an int at upd_type_offset and ovs_uuid_t at version_offset
 *     (both inside the schema). ASan guards the VLAs (stack redzones).
 * The cached row and new rows come from a runner pool whose tail past
 * row_size is poisoned; caller input mon_uuid is poisoned past its NUL.
 *
 * Scaffolding (NOT the function under test):
 *   - ds_tree_find / ds_tree_remove stubs (cached row per test case).
 *   - calloc/free -> runner row pool.  _ovsdb_cache_insert_row: real copy.
 *   - LOG no-op; log_module_severity_get returns 0 (TRACE dump skipped).
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
#define LOG_SEVERITY_TRACE 8
#define MODULE_ID 0
static int log_module_severity_get(int m) { (void)m; return 0; }

void _ovsdb_cache_insert_row(ovsdb_table_t *table, ovsdb_cache_row_t *row);

static void *ocu_tree_find(ds_tree_t *t, const char *k)
{
    (void)t; (void)k;
    return ocu_cached ? (void *)ocu_pool[0] : NULL;
}
static void ocu_tree_remove(ds_tree_t *t, void *d) { (void)t; (void)d; ocu_removes++; }
static void *ocu_calloc(size_t n, size_t sz)
{
    if (n * sz > OCU_SLOT_SZ) return NULL;
    memset(ocu_pool[1], 0, n * sz);
    return ocu_pool[1];
}
static void ocu_free(void *p) { (void)p; ocu_freed++; }
#define ds_tree_find(t, k)   ocu_tree_find((t), (k))
#define ds_tree_remove(t, d) ocu_tree_remove((t), (d))
#define calloc(n, s)         ocu_calloc((n), (s))
#define free(p)              ocu_free(p)

/* --- copied verbatim from lib/ovsdb/ovsdb_cache.c --- */
void onewifi_ovsdb_cache_update_cb(ovsdb_update_monitor_t *self)
{
    ovsdb_table_t *table;
    ovsdb_cache_row_t *row;
    pjs_errmsg_t perr;
    char *mon_uuid;
    char *row_uuid;
    char *typestr;
    char *key = NULL;
    bool ret;
    bool new_ver;
    int mon_type;

    mon_uuid = (char*)self->mon_uuid;

    switch (self->mon_type)
    {
        case OVSDB_UPDATE_NEW:      typestr = "NEW"; break;
        case OVSDB_UPDATE_MODIFY:   typestr = "MOD"; break;
        case OVSDB_UPDATE_DEL:      typestr = "DEL"; break;
        default:
            LOG(ERR, "Table %s update %s type error %d",
                    self->mon_table, mon_uuid, self->mon_type);
            return;
    }

    table = self->mon_data;
    if (!table)
    {
        LOG(ERR, "Table %s %s %s: mon_data NULL",
            self->mon_table, typestr, mon_uuid);
        return;
    }

    // table integrity check
    if (strcmp(table->table_name, self->mon_table))
    {
        LOG(ERR, "Table %s %s mismatch %s",
            table->table_name, typestr, self->mon_table);
        return;
    }

    row = ds_tree_find(&table->rows, mon_uuid);

    if (row && table->key_offset >= 0)
    {
        key = row->record + table->key_offset;
    }

    LOG(INFO, "MON upd: %s table: %s row: %s cached: %s%s%s",
        typestr, table->table_name, mon_uuid, row?"y":"n",
        row?" key: ":"", row?key:"");

    if (LOG_SEVERITY_TRACE <= log_module_severity_get(MODULE_ID))
    {
        // json_old contains _uuid and columns that have changed with old values
        LOG(TRACE, "OLD: %s", json_dumps_static(self->mon_json_old, 0));
        // json_new always contains full record of monitored columns
        LOG(TRACE, "NEW: %s", json_dumps_static(self->mon_json_new, 0));
    }

    char record[table->schema_size];
    char old_record[table->schema_size];
    memset(old_record, 0, sizeof(old_record));
    self->mon_old_rec = old_record;

    mon_type = self->mon_type;
    if (row && (mon_type == OVSDB_UPDATE_NEW))
    {
        LOG(NOTICE, "Table %s %s found cached %s doing update",
                table->table_name, typestr, mon_uuid);
        mon_type = OVSDB_UPDATE_MODIFY;
    }

    switch (mon_type)
    {
        case OVSDB_UPDATE_NEW:
            if (row)
            {
                LOG(ERR, "Table %s %s unexpected %s already exists",
                    table->table_name, typestr, mon_uuid);
                return;
            }
            row = calloc(1, table->row_size);
            ret = table->from_json(row->record, self->mon_json_new,
                    table->partial_update, perr);
            if (!ret)
            {
                free(row);
                LOG(ERR, "Table %s %s parsing %s error: %s",
                    table->table_name, typestr, mon_uuid, perr);
                return;
            }
            // uuid integrity check
            row_uuid = row->record + table->uuid_offset;
            if (strcmp(row_uuid, mon_uuid))
            {
                LOG(ERR, "Table %s %s uuid mismatch %s %s",
                    table->table_name, typestr, mon_uuid, row_uuid);
            }

            _ovsdb_cache_insert_row(table, row);
            break;

        case OVSDB_UPDATE_MODIFY:
            if (!row)
            {
                LOG(ERR, "Table %s %s unexpected %s does not exist",
                    table->table_name, typestr, mon_uuid);
                return;
            }
            memset(record, 0, sizeof(record));
            ret = table->from_json(record, self->mon_json_new, true, perr);
            if (!ret)
            {
                LOG(ERR, "Table %s %s parsing %s error: %s",
                    table->table_name, typestr, mon_uuid, perr);
                return;
            }
            // set _update_type
            int *_update_type;  /* C++ only: split from the initialised declaration (case-label jump) */
            _update_type = (int*)(record + table->upd_type_offset);
            *_update_type = mon_type;
            // uuid integrity check
            row_uuid = record + table->uuid_offset;
            if (strcmp(row_uuid, mon_uuid))
            {
                LOG(ERR, "Table %s %s uuid mismatch %s %s",
                    table->table_name, typestr, mon_uuid, row_uuid);
            }
            if (self->mon_type != OVSDB_UPDATE_NEW)
            {
                // check if version changed
                new_ver = memcmp(row->record + table->version_offset,
                        record + table->version_offset,
                        sizeof(ovs_uuid_t));
                // ignore version change in record compare
                memcpy(row->record + table->version_offset,
                        record + table->version_offset,
                        sizeof(ovs_uuid_t));
                // ignore _update_type
                memcpy(row->record + table->upd_type_offset,
                        record + table->upd_type_offset,
                        sizeof(int));
                // clear previous _changed flags
                table->mark_changed(old_record, row->record);
                // compare
                if (memcmp(record, row->record, sizeof(record)) == 0)
                {
                    LOG(INFO, "=== upd: %s table: %s row: %s %s%s, EQUAL record - skip callback",
                        typestr, table->table_name, mon_uuid,
                        new_ver?"new-ver: ":"same-ver",
                        new_ver?record + table->version_offset:"");
                    return;
                }
                // convert old
                ret = table->from_json(old_record, self->mon_json_old, true, perr);
                if (!ret)
                {
                    LOG(ERR, "Table %s %s parsing OLD %s error: %s",
                            table->table_name, typestr, mon_uuid, perr);
                    return;
                }
                // mark _changed
                table->mark_changed(old_record, record);
            }
            memcpy(row->record, record, sizeof(record));
            break;

        case OVSDB_UPDATE_DEL:
            if (!row)
            {
                LOG(ERR, "Table %s %s unexpected %s does not exist",
                    table->table_name, typestr, mon_uuid);
                return;
            }
            // remove row from the list
            ds_tree_remove(&table->rows, row);
            if (table->key_offset >= 0)
            {
                ds_tree_remove(&table->rows_k, row);
            }
            if (table->key2_offset >= 0)
            {
                ds_tree_remove(&table->rows_k2, row);
            }
            // callback
            if (table->cache_callback) table->cache_callback(self, old_record, row->record, row);
            // free row
            free(row);
            return;

        default:
            return;
    }

    if (table->cache_callback) table->cache_callback(self, old_record, row->record, row);

    LOG(INFO, "<<< DONE: MON upd: %s table: %s row: %s ver: %s",
        typestr, table->table_name, mon_uuid, row->record + table->version_offset);

    return;
}
