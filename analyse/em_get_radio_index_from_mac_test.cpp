/*
 * TEST RUNNER: em_get_radio_index_from_mac
 *
 * Poisoned around the call:
 *   - the caller's query MAC (erm_ruuid_buf): bytes past the 6-byte mac_addr_t;
 *   - the wifi_mgr stand-in (erm_mgr_buf): bytes past sizeof(wifi_mgr_t).
 * rad_str / bss_str (char[18]) and radio_mac (uchar[6]) are internal stack
 * arrays guarded by ASan stack redzones.
 *
 * PASS = the returned radio index matches the expected value for the case
 * (a vap-bssid match, a radio-interface-MAC match, or RETURN_ERR on no match).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_get_radio_index_from_mac(mac_addr_t ruuid);

int test_em_get_radio_index_from_mac(const em_gri_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&erm_ruuid_buf[6], ERM_PAD);
    __asan_poison_memory_region(&erm_mgr_buf[sizeof(wifi_mgr_t)], ERM_PAD);

    int ret = em_get_radio_index_from_mac((unsigned char *)erm_ruuid_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&erm_mgr_buf[sizeof(wifi_mgr_t)], ERM_PAD);
    __asan_unpoison_memory_region(&erm_ruuid_buf[6], ERM_PAD);

    printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    return ret == tc->want_ret;
}

void run_all_tests_em_get_radio_index_from_mac(void)
{
    for (int i = 0; em_get_radio_index_from_mac_suite[i].test_name != NULL; i++) {
        em_gri_test_case_t *test = &em_get_radio_index_from_mac_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_get_radio_index_from_mac_input(test);
        int pass = test_em_get_radio_index_from_mac(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
