/*
 * TEST RUNNER: ds_tree_graphviz_r_test
 *
 * The dumper walks a pointer tree and writes to a FILE*; there is no
 * caller-owned linear buffer to __asan_poison. As a guard we poison the
 * UNUSED node slots [5..8) (the largest case uses 5 nodes): following a bad
 * pointer into them would abort. snode/schild/node_ptr are auto-guarded.
 * Output goes to /dev/null. Completing without an ASan abort = pass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void ds_tree_graphviz_r(ds_tree_t *root, FILE *fdot, ds_tree_node_t *node);

int test_ds_tree_gv(const ds_tree_gv_test_case_t *tc)
{
    FILE *fdot = fopen("/dev/null", "w");
    if (!fdot) { printf("    cannot open /dev/null\n"); return 0; }

    __asan_poison_memory_region(&dgv_nodes[5], (8 - 5) * sizeof(ds_tree_node_t));

    ds_tree_graphviz_r(&dgv_root, fdot, dgv_root.ot_root);

    __asan_unpoison_memory_region(&dgv_nodes[5], (8 - 5) * sizeof(ds_tree_node_t));

    fclose(fdot);
    printf("    graphviz dump completed\n");
    return 1;   /* reached here => no crash */
}

void run_all_tests_ds_tree_gv(void)
{
    for (int i = 0; ds_tree_gv_suite[i].test_name != NULL; i++) {
        ds_tree_gv_test_case_t *test = &ds_tree_gv_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ds_tree_gv_input(test);

        int ok = test_ds_tree_gv(test);

        if (ok) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
