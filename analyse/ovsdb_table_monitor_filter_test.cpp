/*
 * TEST RUNNER: ovsdb_table_monitor_filter_test
 *
 * Poisoned around the call (caller-owned):
 *   - filter[]: argv slots after the NULL + each string's tail past its NUL;
 *   - table->columns[]: argv slots after the NULL + each string's tail.
 * cols[schema_count + 2] is an internal VLA (ASan stack redzones).
 * PASS = monitor_columns got NULL / the expected number of columns and
 * _version presence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

typedef void ovsdb_table_callback_t(ovsdb_update_monitor_t *self, void *old_rec, void *record);
bool onewifi_ovsdb_table_monitor_filter(int ovsdb_fd, ovsdb_table_t *table,
        ovsdb_table_callback_t *callback, char **filter);

static void poison_set(char **argv, char (*strs)[16], int n, int on)
{
    size_t used = (size_t)(n + 1) * sizeof(char *), total = (OTF2_MAX + 1) * sizeof(char *);
    for (int i = 0; i < n; i++) {
        size_t l = strlen(strs[i]);
        if (on) __asan_poison_memory_region(&strs[i][l + 1], 16 - (l + 1));
        else    __asan_unpoison_memory_region(&strs[i][l + 1], 16 - (l + 1));
    }
    if (on) __asan_poison_memory_region((char *)argv + used, total - used);
    else    __asan_unpoison_memory_region((char *)argv + used, total - used);
}

int test_ovsdb_table_monitor_filter(const ovsdb_table_monitor_filter_test_case_t *tc)
{
    char **filter = tc->filter_null ? NULL : otf2_filter_argv;

    poison_set(otf2_schema_argv, otf2_schema_strs, otf2_schema_n, 1);
    poison_set(otf2_filter_argv, otf2_filter_strs, otf2_filter_n, 1);

    bool ok = onewifi_ovsdb_table_monitor_filter(3, &otf2_table, NULL, filter);

    poison_set(otf2_filter_argv, otf2_filter_strs, otf2_filter_n, 0);
    poison_set(otf2_schema_argv, otf2_schema_strs, otf2_schema_n, 0);

    printf("    schema=%d filter_n=%d -> ret=%d got_null=%d count=%d has_version=%d\n",
           otf2_schema_n, otf2_filter_n, ok, otf2_got_null, otf2_got_count, otf2_has_version);
    return ok && otf2_called && otf2_got_null == tc->expect_null &&
           otf2_got_count == tc->expect_count && otf2_has_version == tc->expect_version;
}

void run_all_tests_ovsdb_table_monitor_filter(void)
{
    for (int i = 0; ovsdb_table_monitor_filter_suite[i].test_name != NULL; i++) {
        ovsdb_table_monitor_filter_test_case_t *test = &ovsdb_table_monitor_filter_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);
        fflush(stdout);

        construct_ovsdb_table_monitor_filter_input(test);

        int pass = test_ovsdb_table_monitor_filter(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected null=%d count=%d ver=%d) =====\n",
                   test->test_name, test->expect_null, test->expect_count, test->expect_version);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
