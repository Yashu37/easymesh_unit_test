/*
 * TEST RUNNER: ovsdb_table_update_cb_test
 *
 * Caller input mon_uuid is poisoned past its NUL (catches strcmp over-read).
 * perr[128] and the VLAs record/old_record[schema_size] are internal
 * (auto-guarded by ASan stack redzones).
 * PASS = table_callback / mark_changed calls match, and on a callback the
 * record carries the right _update_type and an if_name within 63 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

void onewifi_ovsdb_table_update_cb(ovsdb_update_monitor_t *self);

int test_ovsdb_table_update_cb(const ovsdb_table_update_cb_test_case_t *tc)
{
    __asan_poison_memory_region(&otu_uuid[otu_uuid_len + 1], sizeof(otu_uuid) - (otu_uuid_len + 1));

    onewifi_ovsdb_table_update_cb(&otu_mon);

    __asan_unpoison_memory_region(&otu_uuid[otu_uuid_len + 1], sizeof(otu_uuid) - (otu_uuid_len + 1));

    printf("    type=%d -> callbacks=%d marks=%d rec_type=%d if_name_len=%zu\n",
           tc->mon_type, otu_cbs, otu_marks, otu_last_type, otu_last_name_len);
    int ok = otu_cbs == tc->expect_cb && otu_marks == tc->expect_marks;
    if (otu_cbs) ok = ok && otu_last_type == tc->mon_type && otu_last_name_len < 64;
    return ok;
}

void run_all_tests_ovsdb_table_update_cb(void)
{
    for (int i = 0; ovsdb_table_update_cb_suite[i].test_name != NULL; i++) {
        ovsdb_table_update_cb_test_case_t *test = &ovsdb_table_update_cb_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_table_update_cb_input(test);

        int pass = test_ovsdb_table_update_cb(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected cb=%d marks=%d) =====\n",
                   test->test_name, test->expect_cb, test->expect_marks);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
