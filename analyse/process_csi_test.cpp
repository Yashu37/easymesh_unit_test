/*
 * TEST RUNNER: process_csi_test
 * Poison: the mac_str write slot past 18; the caller mac_addr past 6; the
 * ctrl/app stand-ins past their sizes. result_mac[6]/mac_str[18] internal.
 * PASS = return matches (-1 for every driven path; create_wifi_event NULL on
 * the found paths).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int process_csi(unsigned char *mac_addr, wifi_csi_data_t *csi_data);

int test_process_csi(const process_csi_test_case_t *tc)
{
    __asan_poison_memory_region(&pcs_slot_mac[PCS_MAC_SZ], PCS_PAD);
    __asan_poison_memory_region(&pcs_mac_buf[6], PCS_PAD);
    __asan_poison_memory_region(&pcs_ctrl_buf[sizeof(wifi_ctrl_t)], PCS_PAD);
    __asan_poison_memory_region(&pcs_app_buf[sizeof(wifi_app_t)], PCS_PAD);

    int ret = process_csi(pcs_mac_buf, (wifi_csi_data_t *)pcs_csi_buf);

    __asan_unpoison_memory_region(&pcs_app_buf[sizeof(wifi_app_t)], PCS_PAD);
    __asan_unpoison_memory_region(&pcs_ctrl_buf[sizeof(wifi_ctrl_t)], PCS_PAD);
    __asan_unpoison_memory_region(&pcs_mac_buf[6], PCS_PAD);
    __asan_unpoison_memory_region(&pcs_slot_mac[PCS_MAC_SZ], PCS_PAD);

    printf("    ret=%d key=\"%s\"\n", ret, pcs_key_seen);
    return ret == tc->expect_ret;
}

void run_all_tests_process_csi(void)
{
    for (int i = 0; process_csi_suite[i].test_name != NULL; i++) {
        process_csi_test_case_t *test = &process_csi_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_csi_input(test);
        int pass = test_process_csi(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
