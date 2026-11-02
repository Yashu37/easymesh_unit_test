/*
 * TEST RUNNER: webconfig_hal_csi_data_apply_test
 * Poison: the mac_str slot past 18; apps past its size; decoded-data past its
 * size. mac_str[18] and total_str_mac[512] are internal (ASan-stack guarded;
 * strcat/snprintf ASan-intercepted so an append overrun would trip).
 * PASS = return 0 (or -1 for NULL queue) and update_mac_list fired as expected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int webconfig_hal_csi_data_apply(wifi_app_t *apps, webconfig_subdoc_decoded_data_t *data);

int test_webconfig_hal_csi_data_apply(const webconfig_hal_csi_data_apply_test_case_t *tc)
{
    /* build the decoded-data: a single pointer field (csi_data_queue) */
    *(void **)whc_dec_buf = whc_null_queue ? NULL : (void *)0x1;

    __asan_poison_memory_region(&whc_slot_mac[WHC_MAC_SZ], WHC_PAD);
    __asan_poison_memory_region(&whc_apps_buf[sizeof(wifi_app_t)], WHC_PAD);
    __asan_poison_memory_region(&whc_dec_buf[sizeof(void*)], WHC_PAD);

    int ret = webconfig_hal_csi_data_apply((wifi_app_t *)whc_apps_buf, (webconfig_subdoc_decoded_data_t *)whc_dec_buf);

    __asan_unpoison_memory_region(&whc_dec_buf[sizeof(void*)], WHC_PAD);
    __asan_unpoison_memory_region(&whc_apps_buf[sizeof(wifi_app_t)], WHC_PAD);
    __asan_unpoison_memory_region(&whc_slot_mac[WHC_MAC_SZ], WHC_PAD);

    printf("    ret=%d update=%d result_len=%zu\n", ret, whc_update_calls, strlen(whc_result));
    int exp_ret = tc->null_queue ? -1 : 0;
    return ret == exp_ret && whc_update_calls == tc->expect_update && strlen(whc_result) < 512;
}

void run_all_tests_webconfig_hal_csi_data_apply(void)
{
    for (int i = 0; webconfig_hal_csi_data_apply_suite[i].test_name != NULL; i++) {
        webconfig_hal_csi_data_apply_test_case_t *test = &webconfig_hal_csi_data_apply_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_webconfig_hal_csi_data_apply_input(test);
        int pass = test_webconfig_hal_csi_data_apply(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
