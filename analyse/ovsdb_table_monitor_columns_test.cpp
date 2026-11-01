/*
 * TEST RUNNER: ovsdb_table_monitor_columns_test
 *
 * Poisoned around the call (caller-owned):
 *   - requested columns[]: argv slots after the NULL + each string's tail;
 *   - the table's schema columns[]: argv slots after the NULL + each
 *     string's tail (walked by is_array_in_array).
 * tmp[1024] is internal (auto-guarded by ASan).
 * PASS = return, which monitor API ran, colc and partial_update match, and
 * tmp stayed <= 1023 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

typedef void ovsdb_table_callback_t(ovsdb_update_monitor_t *self, void *old_rec, void *record);
bool onewifi_ovsdb_table_monitor_columns(int ovsdb_fd, ovsdb_table_t *table,
        ovsdb_table_callback_t *callback, char **columns);

static void otm_cb(ovsdb_update_monitor_t *self, void *old_rec, void *record) { (void)self; (void)old_rec; (void)record; }

static void poison_argv(char **argv, size_t argv_sz, char (*strs)[OTM_STR_SZ], int n, size_t ssz, int on)
{
    size_t used = (size_t)(n + 1) * sizeof(char *);
    if (on) __asan_poison_memory_region((char *)argv + used, argv_sz - used);
    else    __asan_unpoison_memory_region((char *)argv + used, argv_sz - used);
    for (int i = 0; i < n; i++) {
        size_t l = strlen(strs[i]);
        if (on) __asan_poison_memory_region(&strs[i][l + 1], ssz - (l + 1));
        else    __asan_unpoison_memory_region(&strs[i][l + 1], ssz - (l + 1));
    }
}

int test_ovsdb_table_monitor_columns(const ovsdb_table_monitor_columns_test_case_t *tc)
{
    char **cols = tc->cols_null ? NULL : otm_argv;

    poison_argv(otm_argv, sizeof(otm_argv), otm_strs, otm_ncols, OTM_STR_SZ, 1);
    size_t sused = 5 * sizeof(char *);
    __asan_poison_memory_region((char *)otm_schema_argv + sused, sizeof(otm_schema_argv) - sused);
    for (int i = 0; i < 4; i++) {
        size_t l = strlen(otm_schema_strs[i]);
        __asan_poison_memory_region(&otm_schema_strs[i][l + 1], sizeof(otm_schema_strs[i]) - (l + 1));
    }

    bool ok = onewifi_ovsdb_table_monitor_columns(3, &otm_table, otm_cb, cols);

    for (int i = 0; i < 4; i++)
        __asan_unpoison_memory_region(otm_schema_strs[i], sizeof(otm_schema_strs[i]));
    __asan_unpoison_memory_region((char *)otm_schema_argv + sused, sizeof(otm_schema_argv) - sused);
    poison_argv(otm_argv, sizeof(otm_argv), otm_strs, otm_ncols, OTM_STR_SZ, 0);

    printf("    ncols=%d -> ret=%d monitor='%c' colc=%d partial=%d tmp_len=%zu\n",
           otm_ncols, ok, otm_which ? otm_which : '0', otm_colc, otm_table.partial_update, otm_tmp_len);
    return ok == (tc->expect_ret != 0) && otm_which == tc->expect_which &&
           otm_table.partial_update == (tc->expect_partial != 0) &&
           (otm_which != 'C' || otm_colc == tc->expect_colc) && otm_tmp_len <= 1023;
}

void run_all_tests_ovsdb_table_monitor_columns(void)
{
    for (int i = 0; ovsdb_table_monitor_columns_suite[i].test_name != NULL; i++) {
        ovsdb_table_monitor_columns_test_case_t *test = &ovsdb_table_monitor_columns_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_table_monitor_columns_input(test);

        int pass = test_ovsdb_table_monitor_columns(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d monitor=%c partial=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_which, test->expect_partial);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
