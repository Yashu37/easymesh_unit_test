/*
 * HANDLER: onewifi_ovsdb_table_update_cb
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_table.c. No fixes.
 * Local arrays:
 *   - perr (char[128]) -> written only by table->from_json (bounded snprintf)
 *   - record[table->schema_size], old_record[table->schema_size]: VLAs,
 *     memset to sizeof(), filled by from_json with one schema record, plus
 *     an int at upd_type_offset (inside the schema). ASan guards the VLAs.
 * Caller input mon_uuid is poisoned past its NUL by the runner.
 *
 * Scaffolding (NOT the function under test):
 *   - LOG no-op; log_module_severity_get returns 0 (TRACE dump skipped).
 *   - table->from_json / mark_changed / table_callback: test functions.
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

/* --- copied verbatim from lib/ovsdb/ovsdb_table.c --- */
void onewifi_ovsdb_table_update_cb(ovsdb_update_monitor_t *self)
{
    ovsdb_table_t *table;
    pjs_errmsg_t perr;
    char *mon_uuid;
    char *row_uuid;
    char *typestr;
    bool ret;
    int mon_type = self->mon_type;

    mon_uuid = (char*)self->mon_uuid;

    switch (mon_type)
    {
        case OVSDB_UPDATE_NEW:      typestr = "NEW"; break;
        case OVSDB_UPDATE_MODIFY:   typestr = "MOD"; break;
        case OVSDB_UPDATE_DEL:      typestr = "DEL"; break;
        default:
            LOG(ERR, "Table %s update %s type error %d",
                    self->mon_table, mon_uuid, mon_type);
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

    LOG(INFO, "MON upd: %s table: %s row: %s", typestr, table->table_name, mon_uuid );

    if (LOG_SEVERITY_TRACE <= log_module_severity_get(MODULE_ID))
    {
        // json_old contains _uuid and columns that have changed with old values
        LOG(TRACE, "OLD: %s", json_dumps_static(self->mon_json_old, 0));
        // json_new always contains full record of monitored columns
        LOG(TRACE, "NEW: %s", json_dumps_static(self->mon_json_new, 0));
    }

    char record[table->schema_size];
    char old_record[table->schema_size];
    bool partial = table->partial_update;
    json_t *j_rec = NULL;

    memset(old_record, 0, sizeof(old_record));
    memset(record, 0, sizeof(record));
    self->mon_old_rec = old_record;

    // ovsdb monitor update json_old/json_new record behaviour:
    //   on NEW:    old = empty,                        new = full record
    //   on MODIFY: old = old values of changed fields, new = full record
    //   on DELETE: old = full old record,              new = empty
    // this maps to converted old_record/record for callback:
    //   on NEW:    old = empty,                        rec = full record
    //   on MODIFY: old = old values of changed fields, rec = full record
    //   on DELETE: old = full old record,              rec = full old record

    // convert old
    if (mon_type != OVSDB_UPDATE_NEW) {
        ret = table->from_json(old_record, self->mon_json_old, true, perr);
        if (!ret)
        {
            LOG(ERR, "Table %s %s parsing OLD %s error: %s",
                    table->table_name, typestr, mon_uuid, perr);
            return;
        }
    }
    // convert current
    if (mon_type == OVSDB_UPDATE_DEL) {
        j_rec = self->mon_json_old;
    } else {
        j_rec = self->mon_json_new;
    }
    ret = table->from_json(record, j_rec, partial, perr);
    if (!ret)
    {
        LOG(ERR, "Table %s %s parsing %s error: %s",
                table->table_name, typestr, mon_uuid, perr);
        return;
    }
    // set _update_type
    int *_update_type = (int*)(record + table->upd_type_offset);
    *_update_type = mon_type;
    // mark _changed
    if (mon_type == OVSDB_UPDATE_MODIFY) {
        table->mark_changed(old_record, record);
    }
    // uuid integrity check
    row_uuid = record + table->uuid_offset;
    if (strcmp(row_uuid, mon_uuid))
    {
        LOG(ERR, "Table %s %s uuid mismatch '%s' '%s'",
                table->table_name, typestr, mon_uuid, row_uuid);
    }

    // callback
    if (table->table_callback) table->table_callback(self, old_record, record);

    LOG(DEBUG, "<<< DONE: MON upd: %s table: %s row: %s ver: %s",
        typestr, table->table_name, mon_uuid, record + table->version_offset);

    return;
}
