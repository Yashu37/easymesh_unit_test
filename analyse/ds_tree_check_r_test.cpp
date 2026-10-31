/*
 * TEST RUNNER: ds_tree_check_r_test
 *
 * ds_tree_check_r walks a pointer-based tree; there is no caller-owned
 * linear buffer to __asan_poison. As a guard we poison the UNUSED tail of
 * the caller-owned node storage (cases use at most 3 of 8 nodes): if the
 * checker ever followed a bad pointer into that region, ASan would abort.
 * The internal rc[2]/otn_child[2] (size 2, indexed 0/1) and the helper's
 * node_ptr[22] are auto-guarded by ASan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int ds_tree_check_r(ds_tree_t *root, ds_tree_node_t *node);

int test_ds_tree_check(const ds_tree_check_test_case_t *tc)
{
    /* poison unused node slots [3..8) (cases use at most 3 nodes) */
    __asan_poison_memory_region(&dsc_nodes[3], (8 - 3) * sizeof(ds_tree_node_t));

    int rc = ds_tree_check_r(&dsc_root, dsc_root.ot_root);

    __asan_unpoison_memory_region(&dsc_nodes[3], (8 - 3) * sizeof(ds_tree_node_t));

    printf("    ds_tree_check_r returned %d\n", rc);
    return (rc >= 0) ? 1 : 0;
}

void run_all_tests_ds_tree_check(void)
{
    for (int i = 0; ds_tree_check_suite[i].test_name != NULL; i++) {
        ds_tree_check_test_case_t *test = &ds_tree_check_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ds_tree_check_input(test);

        int ok = test_ds_tree_check(test);

        if (ok == test->expect_ok) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected_ok=%d, got=%d) =====\n",
                   test->test_name, test->expect_ok, ok);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
