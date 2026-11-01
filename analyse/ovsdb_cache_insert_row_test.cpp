/*
 * TEST RUNNER: ovsdb_cache_insert_row_test
 *
 * The caller-owned input is the row (header + record). It lives in
 * oci_rowbuf; we POISON everything past header + schema_size, so any read
 * past the end of the record (e.g. %s running off a key) is flagged.
 * msg[128] is internal (auto-guarded by ASan).
 * PASS = the expected number of ds_tree_insert calls happened and the msg
 * handed to dump_table is at most 127 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void _ovsdb_cache_insert_row(ovsdb_table_t *table, ovsdb_cache_row_t *row);

int test_ovsdb_cache_insert_row(const ovsdb_cache_insert_row_test_case_t *tc)
{
    size_t used = sizeof(ovsdb_cache_row_t) + (size_t)oci_table.schema_size;

    __asan_poison_memory_region(&oci_rowbuf[used], sizeof(oci_rowbuf) - used);

    _ovsdb_cache_insert_row(&oci_table, (ovsdb_cache_row_t *)oci_rowbuf);

    __asan_unpoison_memory_region(&oci_rowbuf[used], sizeof(oci_rowbuf) - used);

    printf("    key_off=%d key2_off=%d -> inserts=%d msg_len=%zu\n",
           oci_table.key_offset, oci_table.key2_offset, oci_inserts, oci_msg_len);
    return oci_inserts == tc->expect_inserts && oci_msg_len <= 127;
}

void run_all_tests_ovsdb_cache_insert_row(void)
{
    for (int i = 0; ovsdb_cache_insert_row_suite[i].test_name != NULL; i++) {
        ovsdb_cache_insert_row_test_case_t *test = &ovsdb_cache_insert_row_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_cache_insert_row_input(test);

        int pass = test_ovsdb_cache_insert_row(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected inserts=%d) =====\n", test->test_name, test->expect_inserts);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
