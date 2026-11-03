/*
 * TEST RUNNER: set_bus_csi_sub_enable_status_test
 * Poison: name slot past 128; bus_handle past 16. name[128] ASan-stack guarded.
 * PASS = return matches, bus_set_fn called once with the right bool, name<128.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int set_bus_csi_sub_enable_status(bus_handle_t *bus_handle, uint32_t csi_session_index, bool status);

int test_set_bus_csi_sub_enable_status(const set_bus_csi_sub_enable_status_test_case_t *tc)
{
    __asan_poison_memory_region(&ses_slot[SES_NAME_SZ], SES_PAD);
    __asan_poison_memory_region(&ses_bh_buf[16], SES_PAD);

    int ret = set_bus_csi_sub_enable_status((bus_handle_t *)ses_bh_buf, tc->session, tc->status ? true : false);

    __asan_unpoison_memory_region(&ses_bh_buf[16], SES_PAD);
    __asan_unpoison_memory_region(&ses_slot[SES_NAME_SZ], SES_PAD);

    printf("    ret=%d set_calls=%d bool=%d name_len=%zu name=\"%.40s\"\n", ret, ses_set_calls, ses_last_bool, ses_name_len, ses_name_seen);
    return ret == tc->expect_ret && ses_set_calls == 1 && ses_last_bool == (tc->status?1:0) && ses_name_len < SES_NAME_SZ;
}

void run_all_tests_set_bus_csi_sub_enable_status(void)
{
    for (int i = 0; set_bus_csi_sub_enable_status_suite[i].test_name != NULL; i++) {
        set_bus_csi_sub_enable_status_test_case_t *test = &set_bus_csi_sub_enable_status_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_set_bus_csi_sub_enable_status_input(test);
        int pass = test_set_bus_csi_sub_enable_status(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
