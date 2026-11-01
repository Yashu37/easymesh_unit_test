/*
 * TEST RUNNER: ovsdb_update_changed_test
 *
 * Poisoned around the call (caller-owned inputs): field and mon_table past
 * their NUL, and the json_gets output slots oucg_slot[0/1] past 256 (same
 * size as v_old / v_new).
 * v_old / v_new are internal (auto-guarded by ASan).
 * PASS = changed matches and the dumped lengths match (-1 = "didn't fit":
 * any length < 256).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool onewifi_ovsdb_update_changed(ovsdb_update_monitor_t *self, char *field);

int test_ovsdb_update_changed(const ovsdb_update_changed_test_case_t *tc)
{
    size_t fl = strlen(ouc_field), tl = strlen(ouc_table);

    __asan_poison_memory_region(&ouc_field[fl + 1], sizeof(ouc_field) - (fl + 1));
    __asan_poison_memory_region(&ouc_table[tl + 1], sizeof(ouc_table) - (tl + 1));
    __asan_poison_memory_region(&oucg_slot[0][OUC_SLOT_SZ], OUC_SLOT_PAD);   /* v_old json_gets slot */
    __asan_poison_memory_region(&oucg_slot[1][OUC_SLOT_SZ], OUC_SLOT_PAD);   /* v_new json_gets slot */

    bool changed = onewifi_ovsdb_update_changed(&ouc_mon, ouc_field);

    __asan_unpoison_memory_region(&oucg_slot[1][OUC_SLOT_SZ], OUC_SLOT_PAD);
    __asan_unpoison_memory_region(&oucg_slot[0][OUC_SLOT_SZ], OUC_SLOT_PAD);
    __asan_unpoison_memory_region(&ouc_table[tl + 1], sizeof(ouc_table) - (tl + 1));
    __asan_unpoison_memory_region(&ouc_field[fl + 1], sizeof(ouc_field) - (fl + 1));

    printf("    type=%d -> changed=%d json_gets_calls=%d v_old_len=%zu v_new_len=%zu\n",
           tc->mon_type, changed, oucg_next, oucg_len[0], oucg_len[1]);
    int ok = changed == (tc->expect_changed != 0) && oucg_len[0] < 256 && oucg_len[1] < 256;
    if (tc->expect_old >= 0) ok = ok && oucg_len[0] == (size_t)tc->expect_old;
    if (tc->expect_new >= 0) ok = ok && oucg_len[1] == (size_t)tc->expect_new;
    return ok;
}

void run_all_tests_ovsdb_update_changed(void)
{
    for (int i = 0; ovsdb_update_changed_suite[i].test_name != NULL; i++) {
        ovsdb_update_changed_test_case_t *test = &ovsdb_update_changed_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_update_changed_input(test);

        int pass = test_ovsdb_update_changed(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected changed=%d old=%d new=%d) =====\n",
                   test->test_name, test->expect_changed, test->expect_old, test->expect_new);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
