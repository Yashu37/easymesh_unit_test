/*
 * TEST RUNNER: em_get_vap_index_from_bssid
 *
 * Poisoned around the call:
 *   - the caller's query BSSID (evb_bssid_buf): bytes past the 6-byte mac.
 * bss_str / search_str (char[18]) are internal stack arrays guarded by ASan
 * stack redzones.
 *
 * PASS = the returned vap index matches the expected value (a non-mesh vap
 * match, or RETURN_ERR when the only match is STA-mesh / nothing matches).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_get_vap_index_from_bssid(mac_addr_t bssid);

int test_em_get_vap_index_from_bssid(const em_gvb_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&evb_bssid_buf[6], EVB_PAD);

    int ret = em_get_vap_index_from_bssid((unsigned char *)evb_bssid_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&evb_bssid_buf[6], EVB_PAD);

    printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    return ret == tc->want_ret;
}

void run_all_tests_em_get_vap_index_from_bssid(void)
{
    for (int i = 0; em_get_vap_index_from_bssid_suite[i].test_name != NULL; i++) {
        em_gvb_test_case_t *test = &em_get_vap_index_from_bssid_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_get_vap_index_from_bssid_input(test);
        int pass = test_em_get_vap_index_from_bssid(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
