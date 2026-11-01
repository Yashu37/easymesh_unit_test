/*
 * TEST RUNNER: ovsdb_table_from_json_test
 *
 * The caller-owned output is the record (otj_rec); we POISON everything past
 * schema_size, so a write past the record by from_json is flagged.
 * perr[128] is internal (auto-guarded by ASan).
 * PASS = return matches, from_json called once, perr <= 127 chars, and the
 * record fields are NUL-terminated within their sizes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool onewifi_ovsdb_table_from_json(ovsdb_table_t *table, json_t *jrow, void *record);
void *construct_ovsdb_table_from_json_jrow(const ovsdb_table_from_json_test_case_t *tc);

int test_ovsdb_table_from_json(const ovsdb_table_from_json_test_case_t *tc)
{
    json_t *jrow = (json_t *)construct_ovsdb_table_from_json_jrow(tc);
    size_t ss = (size_t)otj_table.schema_size;

    __asan_poison_memory_region(&otj_rec[ss], sizeof(otj_rec) - ss);

    bool ok = onewifi_ovsdb_table_from_json(&otj_table, jrow, otj_rec);

    __asan_unpoison_memory_region(&otj_rec[ss], sizeof(otj_rec) - ss);

    if (jrow) json_decref(jrow);
    size_t ul = strnlen(otj_rec + OCU_UUID_OFF, 37), nl = strnlen(otj_rec + OCU_KEY_OFF, 64);
    printf("    ret=%d calls=%d perr_len=%zu uuid_len=%zu if_name_len=%zu\n", ok, otj_calls, otj_perr_len, ul, nl);
    return ok == (tc->expect_ret != 0) && otj_calls == 1 && otj_perr_len <= 127 && ul < 37 && nl < 64;
}

void run_all_tests_ovsdb_table_from_json(void)
{
    for (int i = 0; ovsdb_table_from_json_suite[i].test_name != NULL; i++) {
        ovsdb_table_from_json_test_case_t *test = &ovsdb_table_from_json_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_table_from_json_input(test);

        int pass = test_ovsdb_table_from_json(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
