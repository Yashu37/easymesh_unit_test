/*
 * TEST RUNNER: ovsdb_table_to_json_test
 *
 * The caller-owned input is the record (ott_rec); we POISON everything past
 * schema_size, so a read past the record by to_json is flagged.
 * perr[128] is internal (auto-guarded by ASan).
 * PASS = a JSON object is returned exactly when expected, to_json called
 * once, and perr <= 127 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

json_t* onewifi_ovsdb_table_to_json(ovsdb_table_t *table, void *record);

int test_ovsdb_table_to_json(const ovsdb_table_to_json_test_case_t *tc)
{
    size_t ss = (size_t)ott_table.schema_size;

    __asan_poison_memory_region(&ott_rec[ss], sizeof(ott_rec) - ss);

    json_t *j = onewifi_ovsdb_table_to_json(&ott_table, ott_rec);

    __asan_unpoison_memory_region(&ott_rec[ss], sizeof(ott_rec) - ss);

    int got = j != NULL;
    printf("    -> json=%s calls=%d perr_len=%zu\n", got ? "object" : "NULL", ott_calls, ott_perr_len);
    if (j) json_decref(j);
    return got == tc->expect_obj && ott_calls == 1 && ott_perr_len <= 127;
}

void run_all_tests_ovsdb_table_to_json(void)
{
    for (int i = 0; ovsdb_table_to_json_suite[i].test_name != NULL; i++) {
        ovsdb_table_to_json_test_case_t *test = &ovsdb_table_to_json_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_table_to_json_input(test);

        int pass = test_ovsdb_table_to_json(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected json=%d) =====\n", test->test_name, test->expect_obj);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
