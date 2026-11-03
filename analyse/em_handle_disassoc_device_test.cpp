/*
 * TEST RUNNER: em_handle_disassoc_device
 *
 * Poisoned around the call:
 *   - the caller's arg (hdd_arg_buf): bytes past sizeof(assoc_dev_data_t);
 *   - the wifi_mgr/wifi_ctrl stand-ins: bytes past their sizes.
 * client_mac[32], key[64], sta_mac_str[18], bss_str[18] are internal stack
 * arrays guarded by ASan redzones; the cache is index-bounded.
 *
 * PASS = return code matches the path (0 for found/not-found-in-map paths,
 * RETURN_ERR for missing vap-in-cache / missing vap_info).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_handle_disassoc_device(wifi_app_t *app, void *arg);

int test_em_handle_disassoc_device(const em_hdd_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&hdd_arg_buf[sizeof(assoc_dev_data_t)], HDD_PAD);
    __asan_poison_memory_region(&hdd_mgr_buf[sizeof(wifi_mgr_t)], HDD_PAD);
    __asan_poison_memory_region(&hdd_ctrl_buf[sizeof(wifi_ctrl_t)], HDD_PAD);

    int ret = em_handle_disassoc_device((wifi_app_t *)0x1, (void *)hdd_arg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&hdd_ctrl_buf[sizeof(wifi_ctrl_t)], HDD_PAD);
    __asan_unpoison_memory_region(&hdd_mgr_buf[sizeof(wifi_mgr_t)], HDD_PAD);
    __asan_unpoison_memory_region(&hdd_arg_buf[sizeof(assoc_dev_data_t)], HDD_PAD);

    printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    return ret == tc->want_ret;
}

void run_all_tests_em_handle_disassoc_device(void)
{
    for (int i = 0; em_handle_disassoc_device_suite[i].test_name != NULL; i++) {
        em_hdd_test_case_t *test = &em_handle_disassoc_device_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_handle_disassoc_device_input(test);
        int pass = test_em_handle_disassoc_device(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
