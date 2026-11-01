/*
 * TEST RUNNER: os_nif_list_get_test
 *
 * buf[256] and rm[2] are internal stack arrays (auto-guarded by ASan).
 * The written array le_ifname[64] lives in each entry that malloc() hands
 * out; malloc is redirected to the runner-owned onlg_pool, and here we
 * POISON every slot's tail past sizeof(struct os_nif_list_entry). So if
 * os_reg_match_cpy wrote past the entry, ASan aborts on our poison.
 * The poison is lifted after the call so the runner can walk the list.
 *
 * PASS = return value matches, entry count matches (-1 = any >= 1), and
 * every ifname is NUL-terminated within 63 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool os_nif_list_get(ds_list_t *list);
void os_nif_list_free(ds_list_t *list);

#define ONLG_ENTRY_SZ  sizeof(struct os_nif_list_entry)

int test_os_nif_list_get(const os_nif_list_get_test_case_t *tc)
{
    ds_list_t list;

    for (int i = 0; i < ONLG_POOL_SLOTS; i++)
        __asan_poison_memory_region(&onlg_pool[i][ONLG_ENTRY_SZ], ONLG_SLOT_PAD);

    bool ok = os_nif_list_get(&list);

    for (int i = 0; i < ONLG_POOL_SLOTS; i++)
        __asan_unpoison_memory_region(&onlg_pool[i][ONLG_ENTRY_SZ], ONLG_SLOT_PAD);

    int count = 0, bad_len = 0;
    size_t maxlen = 0;
    if (ok) {
        ds_list_iter_t it;
        for (struct os_nif_list_entry *n = (struct os_nif_list_entry *)ds_list_ifirst(&it, &list);
             n != NULL; n = (struct os_nif_list_entry *)ds_list_inext(&it)) {
            size_t l = strnlen(n->le_ifname, sizeof(n->le_ifname));
            if (l >= sizeof(n->le_ifname)) bad_len++;
            if (l > maxlen) maxlen = l;
            count++;
        }
        os_nif_list_free(&list);
    }

    printf("    ret=%d entries=%d max_ifname_len=%zu pool_used=%d\n", ok, count, maxlen, onlg_pool_used);

    int pass = (ok == (tc->expect_ret != 0)) && !bad_len &&
               ((tc->expect_count < 0) ? (count >= 1) : (count == tc->expect_count));
    return pass;
}

void run_all_tests_os_nif_list_get(void)
{
    for (int i = 0; os_nif_list_get_suite[i].test_name != NULL; i++) {
        os_nif_list_get_test_case_t *test = &os_nif_list_get_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_nif_list_get_input(test);

        int pass = test_os_nif_list_get(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d count=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_count);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
