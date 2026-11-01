/*
 * TEST RUNNER: ovsdb_sync_update_where_test
 *
 * Caller input is the table name; we poison its tail past the NUL so any
 * over-read is flagged. where_str[128] is internal (auto-guarded by ASan);
 * json_gets_fn's boundary check is what keeps it in range.
 * PASS = returned count matches and tran_call_s was called once.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int onewifi_ovsdb_sync_update_where(const char *ovsdb_sock_path, const char *table, json_t *where, json_t *row);
json_t *construct_ovsdb_sync_update_where_where(const ovsdb_sync_update_where_test_case_t *tc);

int test_ovsdb_sync_update_where(const ovsdb_sync_update_where_test_case_t *tc)
{
    json_t *where = construct_ovsdb_sync_update_where_where(tc);
    json_t *row   = json_pack("{s:s}", "enabled", "true");

    __asan_poison_memory_region(&osw_table[osw_table_len + 1], sizeof(osw_table) - (osw_table_len + 1));

    int ret = onewifi_ovsdb_sync_update_where("/var/run/db.sock", osw_table, where, row);

    __asan_unpoison_memory_region(&osw_table[osw_table_len + 1], sizeof(osw_table) - (osw_table_len + 1));

    /* where and row are owned (and released) by the call chain */
    printf("    where_len=%d table_len=%zu -> ret=%d calls=%d\n", tc->where_len, osw_table_len, ret, osw_calls);
    return ret == tc->expect_ret && osw_calls == 1;
}

void run_all_tests_ovsdb_sync_update_where(void)
{
    for (int i = 0; ovsdb_sync_update_where_suite[i].test_name != NULL; i++) {
        ovsdb_sync_update_where_test_case_t *test = &ovsdb_sync_update_where_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_sync_update_where_input(test);

        int pass = test_ovsdb_sync_update_where(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
