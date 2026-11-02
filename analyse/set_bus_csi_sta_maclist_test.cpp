/*
 * TEST RUNNER: set_bus_csi_sta_maclist_test
 * Poison: the name slot past 128; the csi_info struct past its size; the
 * bus_handle past 16. name[128] is ASan-stack guarded.
 * PASS = return matches and bus_set_string_fn called once with name < 128.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int set_bus_csi_sta_maclist(bus_handle_t *bus_handle, csi_analytics_info_t *csi_info);

int test_set_bus_csi_sta_maclist(const set_bus_csi_sta_maclist_test_case_t *tc)
{
    __asan_poison_memory_region(&sbm_slot[SBM_NAME_SZ], SBM_PAD);
    __asan_poison_memory_region(&sbm_info_buf[sizeof(csi_analytics_info_t)], SBM_PAD);
    __asan_poison_memory_region(&sbm_bh_buf[16], SBM_PAD);

    int ret = set_bus_csi_sta_maclist((bus_handle_t *)sbm_bh_buf, (csi_analytics_info_t *)sbm_info_buf);

    __asan_unpoison_memory_region(&sbm_bh_buf[16], SBM_PAD);
    __asan_unpoison_memory_region(&sbm_info_buf[sizeof(csi_analytics_info_t)], SBM_PAD);
    __asan_unpoison_memory_region(&sbm_slot[SBM_NAME_SZ], SBM_PAD);

    printf("    ret=%d set_calls=%d name_len=%zu name=\"%.40s\"\n", ret, sbm_set_calls, sbm_name_len, sbm_name_seen);
    return ret == tc->expect_ret && sbm_set_calls == 1 && sbm_name_len < SBM_NAME_SZ;
}

void run_all_tests_set_bus_csi_sta_maclist(void)
{
    for (int i = 0; set_bus_csi_sta_maclist_suite[i].test_name != NULL; i++) {
        set_bus_csi_sta_maclist_test_case_t *test = &set_bus_csi_sta_maclist_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_set_bus_csi_sta_maclist_input(test);
        int pass = test_set_bus_csi_sta_maclist(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
