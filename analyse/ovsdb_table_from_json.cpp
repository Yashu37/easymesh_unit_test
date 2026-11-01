/*
 * HANDLER: onewifi_ovsdb_table_from_json
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_table.c. No fixes.
 * Local perr (pjs_errmsg_t = char[128]) is handed to table->from_json(),
 * which writes its error text with snprintf(err, sizeof(pjs_errmsg_t)), and
 * is then only printed by LOG. The caller record is filled by from_json;
 * the runner poisons the record buffer past schema_size. perr is internal
 * (auto-guarded by ASan).
 *
 * Scaffolding: LOG no-op. table->from_json is the test's pjs-style parser.
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

/* --- copied verbatim from lib/ovsdb/ovsdb_table.c --- */
bool onewifi_ovsdb_table_from_json(ovsdb_table_t *table, json_t *jrow, void *record)
{
    pjs_errmsg_t perr;
    bool ret;
    ret = table->from_json(record, jrow, false, perr);
    if (!ret)
    {
        LOG(ERR, "Table %s parsing error: %s", table->table_name, perr);
        return false;
    }
    return true;
}
