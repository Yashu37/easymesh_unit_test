/*
 * TEST RUNNER: em_process_neighbour_data
 *
 * Poisoned around the call:
 *   - the caller's provider_response (epnd_resp_buf): bytes past the struct;
 *   - the wifi_mgr stand-in (epnd_mgr_buf): bytes past sizeof(wifi_mgr_t).
 * scan_response and local_ssids[16][33] are internal stack arrays guarded by
 * ASan redzones; g_pending_btm.neighbors is bounded by EM_MAX_NEIGHBORS.
 *
 * PASS = return code matches and (on the BTM paths) g_pending_btm.num_neighbors
 * matches the expected count (confirming the EM_MAX_NEIGHBORS cap and the
 * ssid-match filtering).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_process_neighbour_data(wifi_provider_response_t *provider_response);

int test_em_process_neighbour_data(const em_epnd_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&epnd_resp_buf[sizeof(wifi_provider_response_t)], EPND_PAD);
    __asan_poison_memory_region(&epnd_mgr_buf[sizeof(wifi_mgr_t)], EPND_PAD);

    int ret = em_process_neighbour_data((wifi_provider_response_t *)epnd_resp_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&epnd_mgr_buf[sizeof(wifi_mgr_t)], EPND_PAD);
    __asan_unpoison_memory_region(&epnd_resp_buf[sizeof(wifi_provider_response_t)], EPND_PAD);

    int ok = (ret == tc->want_ret);
    if (ok && tc->want_ret == 0 && tc->btm_pending)
        ok = ((int)g_pending_btm.num_neighbors == tc->want_num_neighbors);
    printf("    ret=%d num_neighbors=%u push=%d pub=%d stop=%d (want %d/%d)\n", ret,
           g_pending_btm.num_neighbors, epnd_push_calls, epnd_publish_calls, epnd_stop_calls,
           tc->want_ret, tc->want_num_neighbors);
    return ok;
}

void run_all_tests_em_process_neighbour_data(void)
{
    for (int i = 0; em_process_neighbour_data_suite[i].test_name != NULL; i++) {
        em_epnd_test_case_t *test = &em_process_neighbour_data_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_process_neighbour_data_input(test);
        int pass = test_em_process_neighbour_data(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
