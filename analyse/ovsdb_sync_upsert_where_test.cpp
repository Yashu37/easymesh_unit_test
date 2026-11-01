/*
 * TEST RUNNER: ovsdb_sync_upsert_where_test
 *
 * Poisoned around the call (caller-owned):
 *   - table name: tail of osp_table past its NUL;
 *   - uuid output: ovs_uuid_t at the start of a 64-byte runner buffer,
 *     bytes past sizeof(ovs_uuid_t) (37) poisoned.
 * where_str[128] is internal (auto-guarded by ASan); json_gets_fn's
 * boundary check is what keeps it in range.
 * PASS = return value and number of insert calls match; uuid (when given)
 * NUL-terminated within 37.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool onewifi_ovsdb_sync_upsert_where(const char *ovsdb_sock_path, const char *table, json_t *where, json_t *row, ovs_uuid_t *uuid);
json_t *construct_ovsdb_sync_upsert_where_where(const ovsdb_sync_upsert_where_test_case_t *tc);

int test_ovsdb_sync_upsert_where(const ovsdb_sync_upsert_where_test_case_t *tc)
{
    json_t *where = construct_ovsdb_sync_upsert_where_where(tc);
    json_t *row   = json_pack("{s:s}", "enabled", "true");
    ovs_uuid_t *uuid = tc->use_uuid ? (ovs_uuid_t *)osp_uuidbuf : NULL;

    __asan_poison_memory_region(&osp_table[osp_table_len + 1], sizeof(osp_table) - (osp_table_len + 1));
    __asan_poison_memory_region(&osp_uuidbuf[sizeof(ovs_uuid_t)], sizeof(osp_uuidbuf) - sizeof(ovs_uuid_t));

    bool ok = onewifi_ovsdb_sync_upsert_where("/var/run/db.sock", osp_table, where, row, uuid);

    __asan_unpoison_memory_region(&osp_uuidbuf[sizeof(ovs_uuid_t)], sizeof(osp_uuidbuf) - sizeof(ovs_uuid_t));
    __asan_unpoison_memory_region(&osp_table[osp_table_len + 1], sizeof(osp_table) - (osp_table_len + 1));

    /* where and row are owned (and released) by the call chain */
    size_t ul = strnlen((const char *)osp_uuidbuf, sizeof(ovs_uuid_t));
    printf("    where_len=%d update_count=%d -> ret=%d updates=%d inserts=%d uuid_len=%zu\n",
           tc->where_len, tc->update_count, ok, osp_updates, osp_inserts, ul);
    return ok == (tc->expect_ret != 0) && osp_inserts == tc->expect_inserts &&
           osp_updates == 1 && ul < sizeof(ovs_uuid_t);
}

void run_all_tests_ovsdb_sync_upsert_where(void)
{
    for (int i = 0; ovsdb_sync_upsert_where_suite[i].test_name != NULL; i++) {
        ovsdb_sync_upsert_where_test_case_t *test = &ovsdb_sync_upsert_where_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_sync_upsert_where_input(test);

        int pass = test_ovsdb_sync_upsert_where(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d inserts=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_inserts);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
