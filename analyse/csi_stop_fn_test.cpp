/*
 * TEST RUNNER: csi_stop_fn_test
 * Poison: the mac_str slot past 18; caller mac_addr past 6; app stand-in past
 * its size. mac_str[18] is ASan-stack guarded.
 * PASS = return matches and remove happens only on the disable paths.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int csi_stop_fn(void *csi_app, unsigned int ap_index, unsigned char *mac_addr, int sounding_app);

int test_csi_stop_fn(const csi_stop_fn_test_case_t *tc)
{
    void *app = tc->app_null ? NULL : (void *)csp_app_buf;
    __asan_poison_memory_region(&csp_slot_mac[CSP_MAC_SZ], CSP_PAD);
    __asan_poison_memory_region(&csp_mac_buf[6], CSP_PAD);
    __asan_poison_memory_region(&csp_app_buf[sizeof(wifi_app_t)], CSP_PAD);

    int ret = csi_stop_fn(app, 4, csp_mac_buf, tc->sounding);

    __asan_unpoison_memory_region(&csp_app_buf[sizeof(wifi_app_t)], CSP_PAD);
    __asan_unpoison_memory_region(&csp_mac_buf[6], CSP_PAD);
    __asan_unpoison_memory_region(&csp_slot_mac[CSP_MAC_SZ], CSP_PAD);

    printf("    ret=%d remove=%d key=\"%s\"\n", ret, csp_remove_calls, csp_key_seen);
    return ret == tc->expect_ret && csp_remove_calls == tc->expect_remove;
}

void run_all_tests_csi_stop_fn(void)
{
    for (int i = 0; csi_stop_fn_suite[i].test_name != NULL; i++) {
        csi_stop_fn_test_case_t *test = &csi_stop_fn_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_csi_stop_fn_input(test);
        int pass = test_csi_stop_fn(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d remove=%d) =====\n", test->test_name, test->expect_ret, test->expect_remove);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
