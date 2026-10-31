/*
 * TEST RUNNER: file_get_test
 *
 * file_get's hunk[4096] is a local (stack) array that ASan brackets with
 * red-zones automatically, and the heap buffer it builds is ASan-tracked,
 * so there is nothing to poison here: an out-of-bounds access aborts on
 * its own. The runner drives each file and checks NULL-ness, then frees
 * the returned buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char *file_get(const char *path);

int test_file_get(void)
{
    char *ret = file_get(fileget_path);
    int is_null = (ret == NULL) ? 1 : 0;

    if (ret) {
        printf("ret=non-NULL, strlen=%zu\n", strlen(ret));
        free(ret);
    } else {
        printf("ret=NULL\n");
    }
    return is_null;
}

void run_all_tests_file_get(void)
{
    for (int i = 0; file_get_suite[i].test_name != NULL; i++) {
        file_get_test_case_t *test = &file_get_suite[i];

        printf("--- Running Test: %s  size=%zd ---\n", test->test_name, (ssize_t)test->size);

        construct_file_get_input(test);

        int is_null = test_file_get();

        /* tidy up the temp file */
        if (test->size >= 0)
            remove(fileget_path);

        if (is_null == test->expected_null) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected_null=%d, got=%d) =====\n",
                   test->test_name, test->expected_null, is_null);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
