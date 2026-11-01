/*
 * TEST RUNNER: ovsdb_cache_pre_fetch_test
 *
 * Poisoned around the call:
 *   - caller input key: tail of ocp_key past its NUL;
 *   - the row: calloc is redirected to ocp_rowpool, and everything past
 *     table->row_size in that pool is poisoned, so a write past the row by
 *     from_json (or a read past it by _ovsdb_cache_insert_row) is flagged.
 * perr[128] is internal (auto-guarded by ASan).
 * PASS = return matches, the row was inserted exactly on success, it was
 * freed exactly when from_json failed, and perr stayed within 127 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int onewifi_ovsdb_cache_pre_fetch(const char *ovsdb_sock_path, ovsdb_table_t *table, char *key);

int test_ovsdb_cache_pre_fetch(const ovsdb_cache_pre_fetch_test_case_t *tc)
{
    size_t rs = (size_t)ocp_table.row_size;

    __asan_poison_memory_region(&ocp_key[ocp_key_len + 1], sizeof(ocp_key) - (ocp_key_len + 1));
    __asan_poison_memory_region(&ocp_rowpool[rs], sizeof(ocp_rowpool) - rs);

    int ret = onewifi_ovsdb_cache_pre_fetch("/var/run/db.sock", &ocp_table, ocp_key);

    __asan_unpoison_memory_region(&ocp_rowpool[rs], sizeof(ocp_rowpool) - rs);
    __asan_unpoison_memory_region(&ocp_key[ocp_key_len + 1], sizeof(ocp_key) - (ocp_key_len + 1));

    int want_insert = (tc->expect_ret == 0 && !tc->row_exists) ? 1 : 0;
    int inserted    = oci_inserts > 0;
    printf("    ret=%d inserted=%d freed=%d calloc=%zu perr_len=%zu msg_len=%zu\n",
           ret, inserted, ocp_freed, ocp_calloc_size, ocp_perr_len, oci_msg_len);
    return ret == tc->expect_ret && inserted == want_insert &&
           ocp_freed == tc->fj_fail && ocp_perr_len <= 127 && oci_msg_len <= 127;
}

void run_all_tests_ovsdb_cache_pre_fetch(void)
{
    for (int i = 0; ovsdb_cache_pre_fetch_suite[i].test_name != NULL; i++) {
        ovsdb_cache_pre_fetch_test_case_t *test = &ovsdb_cache_pre_fetch_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_cache_pre_fetch_input(test);

        int pass = test_ovsdb_cache_pre_fetch(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
