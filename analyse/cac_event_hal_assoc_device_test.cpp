/*
 * TEST RUNNER: cac_event_hal_assoc_device_test
 *
 * Poisoned around the call: the caller arg (assoc_dev_data_t) and apps
 * (wifi_app_t) past their sizes; each malloc pool entry past
 * sizeof(cac_associated_devices_t); the client_mac slot past 32 and the
 * temp_str slot past 64. Internal arrays are ASan-stack guarded.
 * PASS = return matches, a station is stored/updated for the success cases.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int cac_event_hal_assoc_device(wifi_app_t *apps, void *arg);

int test_cac_event_hal_assoc_device(const cac_event_hal_assoc_device_test_case_t *tc)
{
    __asan_poison_memory_region(&cad_arg_buf[sizeof(assoc_dev_data_t)], CAD_PAD);
    __asan_poison_memory_region(&cad_apps_buf[sizeof(wifi_app_t)], CAD_PAD);
    for (int i = 0; i < CAD_POOL; i++)
        __asan_poison_memory_region(&cad_pool[i][sizeof(cac_associated_devices_t)], CAD_PAD);
    __asan_poison_memory_region(&cad_slot_mac[CAD_MAC_SZ], CAD_PAD);
    __asan_poison_memory_region(&cad_slot_tmp[CAD_TMP_SZ], CAD_PAD);
    fflush(stdout);

    int ret = cac_event_hal_assoc_device((wifi_app_t *)cad_apps_buf, cad_arg_buf);

    __asan_unpoison_memory_region(&cad_slot_tmp[CAD_TMP_SZ], CAD_PAD);
    __asan_unpoison_memory_region(&cad_slot_mac[CAD_MAC_SZ], CAD_PAD);
    for (int i = 0; i < CAD_POOL; i++)
        __asan_unpoison_memory_region(&cad_pool[i][sizeof(cac_associated_devices_t)], CAD_PAD);
    __asan_unpoison_memory_region(&cad_apps_buf[sizeof(wifi_app_t)], CAD_PAD);
    __asan_unpoison_memory_region(&cad_arg_buf[sizeof(assoc_dev_data_t)], CAD_PAD);

    printf("    ret=%d put=%d key=\"%s\" tmp_len=%zu\n", ret, cad_put_data != NULL, cad_put_key, cad_tmp_len);
    return ret == tc->expect_ret && (cad_put_data != NULL) == (tc->expect_put != 0) && cad_tmp_len < CAD_TMP_SZ;
}

void run_all_tests_cac_event_hal_assoc_device(void)
{
    for (int i = 0; cac_event_hal_assoc_device_suite[i].test_name != NULL; i++) {
        cac_event_hal_assoc_device_test_case_t *test = &cac_event_hal_assoc_device_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_cac_event_hal_assoc_device_input(test);
        int pass = test_cac_event_hal_assoc_device(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d put=%d) =====\n", test->test_name, test->expect_ret, test->expect_put);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
