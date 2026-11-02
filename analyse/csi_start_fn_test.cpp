/*
 * TEST RUNNER: csi_start_fn_test
 * Poison: the mac_str/evicted slot past 18; caller mac_addr past 6; the app
 * and rdk_vap stand-ins past their sizes. Internal arrays ASan-stack guarded.
 * PASS = return matches; a new/MLO/eviction case ends with one hash_map_put.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int csi_start_fn(void *csi_app, unsigned int ap_index, unsigned char *mac_addr, int sounding_app);

int test_csi_start_fn(const csi_start_fn_test_case_t *tc)
{
    void *app = tc->app_null ? NULL : (void *)csf_app_buf;

    __asan_poison_memory_region(&csf_slot_mac[CSF_MAC_SZ], CSF_PAD);
    __asan_poison_memory_region(&csf_mac_buf[6], CSF_PAD);
    __asan_poison_memory_region(&csf_app_buf[sizeof(wifi_app_t)], CSF_PAD);
    __asan_poison_memory_region(&csf_vap_buf[sizeof(rdk_wifi_vap_info_t)], CSF_PAD);

    int ret = csi_start_fn(app, 4, csf_mac_buf, tc->sounding_app);

    __asan_unpoison_memory_region(&csf_vap_buf[sizeof(rdk_wifi_vap_info_t)], CSF_PAD);
    __asan_unpoison_memory_region(&csf_app_buf[sizeof(wifi_app_t)], CSF_PAD);
    __asan_unpoison_memory_region(&csf_mac_buf[6], CSF_PAD);
    __asan_unpoison_memory_region(&csf_slot_mac[CSF_MAC_SZ], CSF_PAD);

    printf("    ret=%d put_calls=%d remove_calls=%d\n", ret, csf_put_calls, csf_remove_calls);
    int put_ok = (tc->expect_ret == 0) ? (csf_put_calls == 1) : 1;
    return ret == tc->expect_ret && put_ok;
}

void run_all_tests_csi_start_fn(void)
{
    for (int i = 0; csi_start_fn_suite[i].test_name != NULL; i++) {
        csi_start_fn_test_case_t *test = &csi_start_fn_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_csi_start_fn_input(test);
        int pass = test_csi_start_fn(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
