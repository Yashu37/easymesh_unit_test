/*
 * TEST CASES / CONSTRUCTOR: construct_ovsdb_cache_insert_row
 *
 * The row record is laid out like a schema struct:
 *   [0..36]    _uuid   (char[37], 36-char uuid + NUL)
 *   [37..292]  key     (char[256])
 *   [293..548] key2    (char[256])
 * schema_size = 549. The row lives in a runner buffer; everything after
 * header + schema_size is poisoned by the runner.
 *
 * Cases: uuid only (no keys), uuid + key, uuid + key + key2, a 255-char key
 * (msg would be ~304 chars -> truncated to 127), empty strings, and a key
 * that ends exactly at the last byte of the record (its NUL is the last byte).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

alignas(16) unsigned char oci_rowbuf[OCI_ROWBUF_SZ];
ovsdb_table_t oci_table;
int    oci_inserts;
size_t oci_last_key_len, oci_msg_len;

ovsdb_cache_insert_row_test_case_t ovsdb_cache_insert_row_suite[] = {
    /* name              use_key use_key2 key                       key_fill key2_fill uuid_empty inserts */
    { "uuid_only",          0,      0,    NULL,                        0,       0,       0,       1 },
    { "uuid_key",           1,      0,    "wl0.1",                     0,       0,       0,       2 },
    { "uuid_key_key2",      1,      1,    "wl0.1",                     0,      10,       0,       3 },
    { "key_255",            1,      0,    NULL,                      255,       0,       0,       2 },
    { "key2_255",           1,      1,    "eth0",                      0,     255,       0,       3 },
    { "empty_strings",      1,      1,    "",                          0,       0,       1,       3 },

    { NULL, 0, 0, NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_ovsdb_cache_insert_row_input(const ovsdb_cache_insert_row_test_case_t *tc)
{
    memset(oci_rowbuf, 0, sizeof(oci_rowbuf));
    memset(&oci_table, 0, sizeof(oci_table));
    snprintf(oci_table.table_name, sizeof(oci_table.table_name), "Wifi_VIF_Config");
    oci_table.schema_size = OCI_SCHEMA_SZ;
    oci_table.uuid_offset = OCI_UUID_OFF;
    oci_table.key_offset  = tc->use_key  ? OCI_KEY_OFF  : -1;
    oci_table.key2_offset = tc->use_key2 ? OCI_KEY2_OFF : -1;

    ovsdb_cache_row_t *row = (ovsdb_cache_row_t *)oci_rowbuf;
    if (!tc->uuid_empty)
        memcpy(row->record + OCI_UUID_OFF, "0123abcd-4567-89ef-0123-456789abcdef", 36);
    if (tc->key_fill) memset(row->record + OCI_KEY_OFF, 'k', (size_t)tc->key_fill);
    else if (tc->key) snprintf(row->record + OCI_KEY_OFF, 256, "%s", tc->key);
    if (tc->key2_fill) memset(row->record + OCI_KEY2_OFF, 'z', (size_t)tc->key2_fill);   /* 255 -> NUL is last byte */

    oci_inserts = 0;
    oci_last_key_len = oci_msg_len = 0;
}
