/*
 * TEST RUNNER: process_instant_msmt_monitor
 *
 * Poisoned around the call:
 *   - the caller's provider_response (pim_resp_buf): bytes past the struct;
 *   - the sta_data source array (pim_stats_buf): bytes past the used entries.
 * s_mac[13] is an internal stack array guarded by ASan redzones; the per-radio
 * radio_data allocations are heap (freed via g_harvester_module at teardown is
 * not done by the handler, so the runner frees them).
 *
 * PASS = the stop / upload stubs were invoked the expected number of times
 * (threshold path stops; a matching mac uploads; no match uploads nothing).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void process_instant_msmt_monitor(wifi_provider_response_t *provider_response);

int test_process_instant_msmt_monitor(const em_pim_test_case_t *tc)
{
    size_t used = (size_t)tc->nstats * sizeof(sta_data_t);

    /* POISON */
    __asan_poison_memory_region(&pim_resp_buf[sizeof(wifi_provider_response_t)], PIM_PAD);
    if (used < PIM_STATS_SZ)
        __asan_poison_memory_region(&pim_stats_buf[used], PIM_STATS_SZ - used);

    process_instant_msmt_monitor((wifi_provider_response_t *)pim_resp_buf);

    /* UNPOISON */
    if (used < PIM_STATS_SZ)
        __asan_unpoison_memory_region(&pim_stats_buf[used], PIM_STATS_SZ - used);
    __asan_unpoison_memory_region(&pim_resp_buf[sizeof(wifi_provider_response_t)], PIM_PAD);

    /* free any radio_data the handler malloc'd (count==0 path) */
    for (int r = 0; r < pim_num_radios; r++) { if (g_harvester_module.radio_data[r]) { free(g_harvester_module.radio_data[r]); g_harvester_module.radio_data[r] = NULL; } }

    int ok = (pim_stop_calls == tc->want_stop) && (pim_upload_calls == tc->want_upload);
    printf("    stop_calls=%d upload_calls=%d (want %d/%d)\n", pim_stop_calls, pim_upload_calls,
           tc->want_stop, tc->want_upload);
    return ok;
}

void run_all_tests_process_instant_msmt_monitor(void)
{
    for (int i = 0; process_instant_msmt_monitor_suite[i].test_name != NULL; i++) {
        em_pim_test_case_t *test = &process_instant_msmt_monitor_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_instant_msmt_monitor_input(test);
        int pass = test_process_instant_msmt_monitor(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
