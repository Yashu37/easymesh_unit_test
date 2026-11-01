/*
 * HANDLER: onewifi_ovsdb_table_to_json
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_table.c. No fixes.
 * Local perr (pjs_errmsg_t = char[128]) is handed to table->to_json(),
 * which writes its error text with snprintf(err, sizeof(pjs_errmsg_t)), and
 * is then only printed by LOG. The caller record is only READ by to_json;
 * the runner poisons the record buffer past schema_size. perr is internal
 * (auto-guarded by ASan).
 *
 * Scaffolding: LOG no-op. table->to_json is the test's pjs-style serializer.
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
json_t* onewifi_ovsdb_table_to_json(ovsdb_table_t *table, void *record)
{
    pjs_errmsg_t perr;
    json_t *jrow = table->to_json(record, perr);
    if (!jrow)
    {
        LOG(ERR, "Table %s convert error: %s", table->table_name, perr);
        return NULL;
    }
    return jrow;
}
