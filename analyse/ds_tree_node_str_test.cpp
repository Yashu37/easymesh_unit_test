/*
 * TEST RUNNER: ds_tree_node_str_test
 *
 * The caller-owned input is the node (in dns_backing); we poison the memory
 * past the ds_tree_node_t struct, so any read beyond the node aborts. The
 * returned node_ptr[22] is an internal static array, auto-guarded by ASan.
 *
 * PASS: a non-NULL string is returned; when an expected substring is given
 * it must appear; and (default path) the string must fit node_ptr[22].
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char *ds_tree_node_str(ds_tree_t *root, ds_tree_node_t *node);

int test_ds_node_str(const ds_node_str_test_case_t *tc)
{
    ds_tree_node_t *node = (ds_tree_node_t *)dns_backing;

    /* poison memory past the node struct (over-read guard) */
    __asan_poison_memory_region(&dns_backing[sizeof(ds_tree_node_t)],
                                sizeof(dns_backing) - sizeof(ds_tree_node_t));

    char *out = ds_tree_node_str(&dns_root, node);

    __asan_unpoison_memory_region(&dns_backing[sizeof(ds_tree_node_t)],
                                  sizeof(dns_backing) - sizeof(ds_tree_node_t));

    printf("    out=\"%s\"\n", out ? out : "(NULL)");

    if (!out) return 0;
    if (tc->expect && strstr(out, tc->expect) == NULL) return 0;
    if (!dns_use_strfn && strlen(out) >= 22) return 0;   /* must fit node_ptr[22] */
    return 1;
}

void run_all_tests_ds_node_str(void)
{
    for (int i = 0; ds_node_str_suite[i].test_name != NULL; i++) {
        ds_node_str_test_case_t *test = &ds_node_str_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ds_node_str_input(test);

        int ok = test_ds_node_str(test);

        if (ok) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
