/*
 * TEST RUNNER: em_init
 *
 * Poisoned around the call:
 *   - the caller's app (wifi_app_t): bytes past the struct;
 *   - the ctrl stand-in: bytes past the 512-byte ctrl buffer.
 * dataElements[12] is an internal stack array (ASan stack redzones).
 *
 * PASS = return code matches, and on success exactly 12 elements were
 * registered (reg_num == 12), the cache was initialised, and the first
 * element name is the channel-scan-request namespace -- confirming the fixed
 * read-only table is built and passed with its correct ARRAYSIZE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_init(wifi_app_t *app, unsigned int create_flag);

int test_em_init(const em_emi_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&emi_app_buf[sizeof(wifi_app_t)], EMI_PAD);
    __asan_poison_memory_region(&emi_appctrl_buf[512 - 32], 32);  /* tail of the ctrl stand-in */

    int ret = em_init((wifi_app_t *)emi_app_buf, 0);

    /* UNPOISON */
    __asan_unpoison_memory_region(&emi_appctrl_buf[512 - 32], 32);
    __asan_unpoison_memory_region(&emi_app_buf[sizeof(wifi_app_t)], EMI_PAD);

    int ok = (ret == tc->want_ret);
    if (ok && tc->want_ret == 0)
        ok = (emi_reg_num == 12) && (emi_cache_init_calls == 1) &&
             (strcmp(emi_elem0_name, "Device.WiFi.EM.ChannelScanRequest") == 0);
    printf("    ret=%d reg_calls=%d reg_num=%d cache_init=%d elem0=\"%s\" (want %d)\n", ret,
           emi_reg_calls, emi_reg_num, emi_cache_init_calls, emi_elem0_name, tc->want_ret);
    return ok;
}

void run_all_tests_em_init(void)
{
    for (int i = 0; em_init_suite[i].test_name != NULL; i++) {
        em_emi_test_case_t *test = &em_init_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_init_input(test);
        int pass = test_em_init(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
