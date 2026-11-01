/*
 * TEST RUNNER: ovsdb_sync_update_one_get_uuid_test
 *
 * Poisoned around the call (caller-owned):
 *   - table name: tail of osu_table past its NUL;
 *   - uuid output: ovs_uuid_t at the start of a 64-byte runner buffer,
 *     bytes past sizeof(ovs_uuid_t) (37) poisoned.
 * where_str[128] is internal (auto-guarded by ASan); json_gets_fn's own
 * boundary check is what keeps it in range.
 * PASS = returned count and number of update calls match, uuid NUL-
 * terminated within 37.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int onewifi_ovsdb_sync_update_one_get_uuid(const char *ovsdb_sock_path, const char *table, json_t *where, json_t *row, ovs_uuid_t *uuid);
json_t *construct_ovsdb_sync_update_one_get_uuid_where(const ovsdb_sync_update_one_get_uuid_test_case_t *tc);

int test_ovsdb_sync_update_one_get_uuid(const ovsdb_sync_update_one_get_uuid_test_case_t *tc)
{
    json_t *where = construct_ovsdb_sync_update_one_get_uuid_where(tc);
    json_t *row   = json_pack("{s:s}", "enabled", "true");
    ovs_uuid_t *uuid = (ovs_uuid_t *)osu_uuidbuf;

    __asan_poison_memory_region(&osu_table[osu_table_len + 1], sizeof(osu_table) - (osu_table_len + 1));
    __asan_poison_memory_region(&osu_uuidbuf[sizeof(ovs_uuid_t)], sizeof(osu_uuidbuf) - sizeof(ovs_uuid_t));

    int ret = onewifi_ovsdb_sync_update_one_get_uuid("/var/run/db.sock", osu_table, where, row, uuid);

    __asan_unpoison_memory_region(&osu_uuidbuf[sizeof(ovs_uuid_t)], sizeof(osu_uuidbuf) - sizeof(ovs_uuid_t));
    __asan_unpoison_memory_region(&osu_table[osu_table_len + 1], sizeof(osu_table) - (osu_table_len + 1));

    /* where and row are owned (and released) by the function -- no decref here */
    size_t ul = strnlen(uuid->uuid, sizeof(uuid->uuid));
    printf("    where_len=%d select=%d -> ret=%d updates=%d uuid_len=%zu\n",
           tc->where_len, tc->select_count, ret, osu_updates, ul);
    return ret == tc->expect_ret && osu_updates == tc->expect_updates && ul < sizeof(uuid->uuid);
}

void run_all_tests_ovsdb_sync_update_one_get_uuid(void)
{
    for (int i = 0; ovsdb_sync_update_one_get_uuid_suite[i].test_name != NULL; i++) {
        ovsdb_sync_update_one_get_uuid_test_case_t *test = &ovsdb_sync_update_one_get_uuid_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_sync_update_one_get_uuid_input(test);

        int pass = test_ovsdb_sync_update_one_get_uuid(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d updates=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_updates);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
