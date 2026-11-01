/*
 * TEST RUNNER: ovsdb_cache_update_cb_test
 *
 * Poisoned around the call:
 *   - caller input mon_uuid: tail of ocu_uuid past its NUL;
 *   - both row-pool slots (cached row, calloc'd new row): everything past
 *     table->row_size, so a memcpy/from_json past the row is flagged.
 * perr[128] and the VLAs record/old_record[schema_size] are internal
 * (auto-guarded by ASan stack redzones).
 * PASS = cache_callback / insert / free happened exactly as expected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void onewifi_ovsdb_cache_update_cb(ovsdb_update_monitor_t *self);

int test_ovsdb_cache_update_cb(const ovsdb_cache_update_cb_test_case_t *tc)
{
    size_t rs = (size_t)ocu_table.row_size;

    __asan_poison_memory_region(&ocu_uuid[ocu_uuid_len + 1], sizeof(ocu_uuid) - (ocu_uuid_len + 1));
    for (int i = 0; i < 2; i++)
        __asan_poison_memory_region(&ocu_pool[i][rs], OCU_SLOT_SZ - rs);

    onewifi_ovsdb_cache_update_cb(&ocu_mon);

    for (int i = 0; i < 2; i++)
        __asan_unpoison_memory_region(&ocu_pool[i][rs], OCU_SLOT_SZ - rs);
    __asan_unpoison_memory_region(&ocu_uuid[ocu_uuid_len + 1], sizeof(ocu_uuid) - (ocu_uuid_len + 1));

    int inserted = oci_inserts > 0;
    printf("    type=%d cached=%d -> callbacks=%d inserted=%d freed=%d removes=%d marks=%d\n",
           tc->mon_type, tc->cached, ocu_cbs, inserted, ocu_freed, ocu_removes, ocu_marks);
    return ocu_cbs == tc->expect_cb && inserted == tc->expect_insert && ocu_freed == tc->expect_free;
}

void run_all_tests_ovsdb_cache_update_cb(void)
{
    for (int i = 0; ovsdb_cache_update_cb_suite[i].test_name != NULL; i++) {
        ovsdb_cache_update_cb_test_case_t *test = &ovsdb_cache_update_cb_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_cache_update_cb_input(test);

        int pass = test_ovsdb_cache_update_cb(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected cb=%d ins=%d free=%d) =====\n",
                   test->test_name, test->expect_cb, test->expect_insert, test->expect_free);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
