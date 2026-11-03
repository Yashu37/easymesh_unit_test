/*
 * TEST RUNNER: em_config_channel_scan
 *
 * Poisoned around the call:
 *   - the caller's data/scan_req (eccs_req_buf): bytes past sizeof(channel_scan_request_t);
 *   - the wifi_mgr stand-in (eccs_mgr_buf): bytes past sizeof(wifi_mgr_t).
 * radio_mac[6] and mac_str[18] are internal stack arrays guarded by ASan
 * redzones.
 *
 * PASS = em_process_scan_init_command was invoked the expected number of times
 * and (on a match) with the expected radio_index. The function is void, so
 * there is no return code to check; the NULL/short-len/NULL-mgr guards result
 * in no scan-init call.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void em_config_channel_scan(void *data, unsigned int len);

int test_em_config_channel_scan(const em_eccs_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&eccs_req_buf[sizeof(channel_scan_request_t)], ECCS_PAD);
    __asan_poison_memory_region(&eccs_mgr_buf[sizeof(wifi_mgr_t)], ECCS_PAD);

    void *data = tc->data_null ? NULL : (void *)eccs_req_buf;
    unsigned int len = tc->small_len ? (unsigned int)(sizeof(channel_scan_request_t) - 1)
                                     : (unsigned int)sizeof(channel_scan_request_t);
    em_config_channel_scan(data, len);

    /* UNPOISON */
    __asan_unpoison_memory_region(&eccs_mgr_buf[sizeof(wifi_mgr_t)], ECCS_PAD);
    __asan_unpoison_memory_region(&eccs_req_buf[sizeof(channel_scan_request_t)], ECCS_PAD);

    int ok = (eccs_scan_init_calls == tc->want_calls);
    if (ok && tc->want_calls == 1) ok = (eccs_scan_init_radio == tc->want_radio);
    printf("    scan_init_calls=%d radio=%d (want %d/%d)\n", eccs_scan_init_calls, eccs_scan_init_radio,
           tc->want_calls, tc->want_radio);
    return ok;
}

void run_all_tests_em_config_channel_scan(void)
{
    for (int i = 0; em_config_channel_scan_suite[i].test_name != NULL; i++) {
        em_eccs_test_case_t *test = &em_config_channel_scan_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_config_channel_scan_input(test);
        int pass = test_em_config_channel_scan(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
