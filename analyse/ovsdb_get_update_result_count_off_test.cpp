/*
 * TEST RUNNER: ovsdb_get_update_result_count_off_test
 *
 * Poisoned around the call (caller-owned inputs): table and oper past their
 * NUL. The json_gets output slot has its tail past the given size poisoned
 * inside the handler's json_gets redirect. errstr[256] is internal
 * (auto-guarded by ASan).
 * PASS = count matches and errstr length matches (-1 = errstr not used).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int ovsdb_get_update_result_count_off(json_t *result, const char *table, const char *oper, int offset);
void *construct_ovsdb_get_update_result_count_off_result(const ovsdb_get_update_result_count_off_test_case_t *tc);

int test_ovsdb_get_update_result_count_off(const ovsdb_get_update_result_count_off_test_case_t *tc)
{
    json_t *result = (json_t *)construct_ovsdb_get_update_result_count_off_result(tc);
    size_t tl = strlen(ogu_table), ol = strlen(ogu_oper);

    __asan_poison_memory_region(&ogu_table[tl + 1], sizeof(ogu_table) - (tl + 1));
    __asan_poison_memory_region(&ogu_oper[ol + 1], sizeof(ogu_oper) - (ol + 1));

    int count = ovsdb_get_update_result_count_off(result, ogu_table, ogu_oper, tc->offset);

    __asan_unpoison_memory_region(&ogu_oper[ol + 1], sizeof(ogu_oper) - (ol + 1));
    __asan_unpoison_memory_region(&ogu_table[tl + 1], sizeof(ogu_table) - (tl + 1));

    if (result) json_decref(result);
    long el = ogug_errstr_len == (size_t)-1 ? -1 : (long)ogug_errstr_len;
    printf("    offset=%d -> count=%d errstr_len=%ld json_gets_calls=%d\n", tc->offset, count, el, ogug_calls);
    return count == tc->expect_count && el == tc->expect_errlen;
}

void run_all_tests_ovsdb_get_update_result_count_off(void)
{
    for (int i = 0; ovsdb_get_update_result_count_off_suite[i].test_name != NULL; i++) {
        ovsdb_get_update_result_count_off_test_case_t *test = &ovsdb_get_update_result_count_off_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_get_update_result_count_off_input(test);

        int pass = test_ovsdb_get_update_result_count_off(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected count=%d errstr_len=%d) =====\n",
                   test->test_name, test->expect_count, test->expect_errlen);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
