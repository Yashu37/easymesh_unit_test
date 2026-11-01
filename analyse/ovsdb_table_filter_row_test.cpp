/*
 * TEST RUNNER: ovsdb_table_filter_row_test
 *
 * Poisoned around the call (caller-owned):
 *   - the argv array: every slot after the NULL terminator, so walking past
 *     the end of columns[] is flagged;
 *   - every column string: tail past its NUL (strlcat over-read).
 * str[1024] is internal (auto-guarded by ASan).
 * PASS = the row is returned, the right filter (+/-) ran with the right
 * argc (or none), and str stayed <= 1023 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

json_t* onewifi_ovsdb_table_filter_row(json_t *row, char *columns[]);

int test_ovsdb_table_filter_row(const ovsdb_table_filter_row_test_case_t *tc)
{
    json_t *row = tc->has_row ? json_object() : NULL;
    char **cols = tc->cols_null ? NULL : otf_argv;

    size_t used = (size_t)(otf_ncols + 1) * sizeof(char *);
    __asan_poison_memory_region((char *)otf_argv + used, sizeof(otf_argv) - used);
    for (int i = 0; i < otf_ncols; i++) {
        size_t l = strlen(otf_strs[i]);
        __asan_poison_memory_region(&otf_strs[i][l + 1], OTF_STR_SZ - (l + 1));
    }

    json_t *out = onewifi_ovsdb_table_filter_row(row, cols);

    for (int i = 0; i < otf_ncols; i++)
        __asan_unpoison_memory_region(otf_strs[i], OTF_STR_SZ);
    __asan_unpoison_memory_region((char *)otf_argv + used, sizeof(otf_argv) - used);

    printf("    ncols=%d -> same_row=%d filter='%c' argc=%d str_len=%zu\n",
           otf_ncols, out == row, otf_which ? otf_which : '0', otf_argc, otf_str_len);
    if (row) json_decref(row);
    return out == row && otf_which == tc->expect_which && otf_argc == tc->expect_argc && otf_str_len <= 1023;
}

void run_all_tests_ovsdb_table_filter_row(void)
{
    for (int i = 0; ovsdb_table_filter_row_suite[i].test_name != NULL; i++) {
        ovsdb_table_filter_row_test_case_t *test = &ovsdb_table_filter_row_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_table_filter_row_input(test);

        int pass = test_ovsdb_table_filter_row(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected filter=%d argc=%d) =====\n",
                   test->test_name, test->expect_which, test->expect_argc);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
