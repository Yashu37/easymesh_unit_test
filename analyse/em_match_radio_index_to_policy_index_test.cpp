/*
 * TEST RUNNER: em_match_radio_index_to_policy_index
 *
 * Poisoned around the call:
 *   - the caller's policies (emm_pol_buf): bytes past the struct;
 *   - the wifi_mgr stand-in (emm_mgr_buf): bytes past sizeof(wifi_mgr_t).
 * radio_mac (uchar[6]) is an internal stack array guarded by ASan redzones.
 *
 * PASS = the returned policy index matches the expected value (policy 0 on a
 * match, RETURN_ERR when no interface-map entry or no lookup match).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_match_radio_index_to_policy_index(radio_metrics_policies_t *radio_metrics_policies, int radio_index);

int test_em_match_radio_index_to_policy_index(const em_mri_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&emm_pol_buf[sizeof(radio_metrics_policies_t)], EMM_PAD);
    __asan_poison_memory_region(&emm_mgr_buf[sizeof(wifi_mgr_t)], EMM_PAD);

    int ret = em_match_radio_index_to_policy_index((radio_metrics_policies_t *)emm_pol_buf, tc->radio_index);

    /* UNPOISON */
    __asan_unpoison_memory_region(&emm_mgr_buf[sizeof(wifi_mgr_t)], EMM_PAD);
    __asan_unpoison_memory_region(&emm_pol_buf[sizeof(radio_metrics_policies_t)], EMM_PAD);

    printf("    ret=%d grifm_calls=%d (want %d)\n", ret, emm_grifm_calls, tc->want_ret);
    return ret == tc->want_ret;
}

void run_all_tests_em_match_radio_index_to_policy_index(void)
{
    for (int i = 0; em_match_radio_index_to_policy_index_suite[i].test_name != NULL; i++) {
        em_mri_test_case_t *test = &em_match_radio_index_to_policy_index_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_match_radio_index_to_policy_index_input(test);
        int pass = test_em_match_radio_index_to_policy_index(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
