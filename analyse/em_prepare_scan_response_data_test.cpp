/*
 * TEST RUNNER: em_prepare_scan_response_data
 *
 * Poisoned around the call:
 *   - the caller's provider_response (epsr_resp_buf): bytes past the struct;
 *   - the wifi_mgr stand-in (epsr_mgr_buf): bytes past sizeof(wifi_mgr_t);
 *   - the output scan_response (epsr_scanresp_buf): bytes past
 *     sizeof(channel_scan_response_t).
 * radio_mac[6], mac_str[18] and time_str[32] are internal stack arrays guarded
 * by ASan redzones; the scan-source array is a sized heap allocation.
 *
 * PASS = return code matches and (on the OK paths) num_results matches the
 * expected count, confirming the EM_MAX_RESULTS / EM_MAX_NEIGHBORS caps and the
 * skip paths behave.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_prepare_scan_response_data(wifi_provider_response_t *provider_response,
    channel_scan_response_t *scan_response);

int test_em_prepare_scan_response_data(const em_epsr_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&epsr_resp_buf[sizeof(wifi_provider_response_t)], EPSR_PAD);
    __asan_poison_memory_region(&epsr_mgr_buf[sizeof(wifi_mgr_t)], EPSR_PAD);
    __asan_poison_memory_region(&epsr_scanresp_buf[sizeof(channel_scan_response_t)], EPSR_PAD);

    int ret = em_prepare_scan_response_data((wifi_provider_response_t *)epsr_resp_buf,
                                            (channel_scan_response_t *)epsr_scanresp_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&epsr_scanresp_buf[sizeof(channel_scan_response_t)], EPSR_PAD);
    __asan_unpoison_memory_region(&epsr_mgr_buf[sizeof(wifi_mgr_t)], EPSR_PAD);
    __asan_unpoison_memory_region(&epsr_resp_buf[sizeof(wifi_provider_response_t)], EPSR_PAD);

    int ok = (ret == tc->want_ret);
    channel_scan_response_t *sr = (channel_scan_response_t *)epsr_scanresp_buf;
    if (ok && tc->want_ret == 0) {
        ok = ((int)sr->num_results == tc->want_num_results);
        unsigned int nbr0 = sr->num_results > 0 ? sr->results[0].num_neighbors : 0;
        printf("    ret=%d num_results=%u nbr0=%u (want_results %d)\n", ret, sr->num_results, nbr0, tc->want_num_results);
    } else {
        printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    }
    return ok;
}

void run_all_tests_em_prepare_scan_response_data(void)
{
    for (int i = 0; em_prepare_scan_response_data_suite[i].test_name != NULL; i++) {
        em_epsr_test_case_t *test = &em_prepare_scan_response_data_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_prepare_scan_response_data_input(test);
        int pass = test_em_prepare_scan_response_data(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
