/*
 * HANDLER: _ovsdb_cache_insert_row
 *
 * Function copied VERBATIM from OneWifi lib/ovsdb/ovsdb_cache.c. No fixes.
 * Local msg[128] is filled by snprintf(msg, sizeof(msg), "insert %s key: %s",
 * row_uuid, key), so a long uuid/key is truncated, not overflowed. The
 * strings row_uuid/key/key2 are read from the caller's row->record at the
 * table's offsets; the runner poisons the row buffer past the record.
 * msg is internal (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test):
 *   - ovsdb_table_t / ovsdb_cache_row_t: subset in common.h (only the fields
 *     this function touches; same names/types as lib/ovsdb/ovsdb_table.h).
 *   - ds_tree_insert stub: records the key it was given.
 *   - onewifi_ovsdb_cache_dump_table stub: records the msg length (the
 *     real one only prints at DEBUG level).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
static void oci_tree_insert_stub(ds_tree_t *root, void *data, void *key)
{
    (void)root; (void)data;
    oci_inserts++;
    oci_last_key_len = strlen((const char *)key);
}
#define ds_tree_insert(r, d, k) oci_tree_insert_stub((r), (d), (k))

static void onewifi_ovsdb_cache_dump_table(ovsdb_table_t *table, char *str)
{
    (void)table;
    oci_msg_len = strlen(str);
}

/* --- copied verbatim from lib/ovsdb/ovsdb_cache.c --- */
void _ovsdb_cache_insert_row(ovsdb_table_t *table, ovsdb_cache_row_t *row)
{
    char *row_uuid = row->record + table->uuid_offset;
    char *key = "";
    char *key2 = "";
    char msg[128];

    ds_tree_insert(&table->rows, row, row_uuid);
    if (table->key_offset >= 0)
    {
        key = row->record + table->key_offset;
        ds_tree_insert(&table->rows_k, row, key);
    }
    if (table->key2_offset >= 0)
    {
        key2 = row->record + table->key2_offset;
        ds_tree_insert(&table->rows_k2, row, key2);
    }
    snprintf(msg, sizeof(msg), "insert %s key: %s", row_uuid, key);
    onewifi_ovsdb_cache_dump_table(table, msg);
}
