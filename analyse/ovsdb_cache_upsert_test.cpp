/*
 * TEST RUNNER: ovsdb_cache_upsert_test
 *
 * Poisoned around the call (all caller/runner-owned):
 *   - the caller record ocs_rec past schema_size (catches strscpy/memcpy
 *     past the record);
 *   - both row-pool slots past row_size (cached row and calloc'd new row).
 * perr[128] and uuid (char[37]) are internal (auto-guarded by ASan).
 * PASS = return, number of db upserts and whether a new row was inserted
 * all match; perr <= 127 chars; the record uuid is NUL-terminated in 37.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int onewifi_ovsdb_cache_upsert(const char *ovsdb_sock_path, ovsdb_table_t *table, void *record);

int test_ovsdb_cache_upsert(const ovsdb_cache_upsert_test_case_t *tc)
{
    size_t rs = (size_t)ocs_table.row_size;
    size_t ss = (size_t)ocs_table.schema_size;

    __asan_poison_memory_region(&ocs_rec[ss], sizeof(ocs_rec) - ss);
    for (int i = 0; i < 2; i++)
        __asan_poison_memory_region(&ocs_pool[i][rs], OCS_SLOT_SZ - rs);

    int ret = onewifi_ovsdb_cache_upsert("/var/run/db.sock", &ocs_table, ocs_rec);

    for (int i = 0; i < 2; i++)
        __asan_unpoison_memory_region(&ocs_pool[i][rs], OCS_SLOT_SZ - rs);
    __asan_unpoison_memory_region(&ocs_rec[ss], sizeof(ocs_rec) - ss);

    int inserted = oci_inserts > 0;
    size_t ulen = strnlen(ocs_rec + OCU_UUID_OFF, 37);
    printf("    ret=%d upserts=%d asked_uuid=%d inserted=%d perr_len=%zu rec_uuid_len=%zu\n",
           ret, ocs_upserts, ocs_asked_uuid, inserted, ocs_perr_len, ulen);
    return ret == tc->expect_ret && ocs_upserts == tc->expect_upserts &&
           inserted == tc->expect_insert && ocs_perr_len <= 127 && ulen < 37;
}

void run_all_tests_ovsdb_cache_upsert(void)
{
    for (int i = 0; ovsdb_cache_upsert_suite[i].test_name != NULL; i++) {
        ovsdb_cache_upsert_test_case_t *test = &ovsdb_cache_upsert_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_cache_upsert_input(test);

        int pass = test_ovsdb_cache_upsert(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d upserts=%d ins=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_upserts, test->expect_insert);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
