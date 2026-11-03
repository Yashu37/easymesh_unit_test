/*
 * TEST RUNNER: radio_chan_stats_response
 *
 * Poisoned around the call:
 *   - the caller's provider_response (rcs_resp_buf): bytes past the struct;
 *   - the wifi_mgr stand-in (rcs_mgr_buf): bytes past sizeof(wifi_mgr_t).
 * radio_mac[6] and radio_str[18] are internal stack arrays guarded by ASan
 * redzones; the channel-stats source is a sized heap allocation; the cache /
 * radio config / survey arrays are index-bounded (radio_index checked, vap loop
 * bounded by num_vaps).
 *
 * PASS = return code matches; on the OK paths the radio_metrics.noise is the
 * expected ANPI ((ch_noise + 110) * 2) for the configured ch_noise.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int radio_chan_stats_response(wifi_provider_response_t *provider_response);

int test_radio_chan_stats_response(const em_rcs_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&rcs_resp_buf[sizeof(wifi_provider_response_t)], RCS_PAD);
    __asan_poison_memory_region(&rcs_mgr_buf[sizeof(wifi_mgr_t)], RCS_PAD);

    int ret = radio_chan_stats_response((wifi_provider_response_t *)rcs_resp_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&rcs_mgr_buf[sizeof(wifi_mgr_t)], RCS_PAD);
    __asan_unpoison_memory_region(&rcs_resp_buf[sizeof(wifi_provider_response_t)], RCS_PAD);

    int ok = (ret == tc->want_ret);
    if (ok && tc->want_ret == 0 && tc->radio_index >= 0 && tc->radio_index < MAX_NUM_RADIOS) {
        unsigned char noise = em_ap_metrics_report_cache.radio_report[tc->radio_index].radio_metrics.noise;
        ok = (noise == (unsigned char)(((-90) + 110) * 2));   /* ANPI for ch_noise -90 => 40 */
        printf("    ret=%d noise=%u (want 40)\n", ret, noise);
    } else {
        printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    }
    return ok;
}

void run_all_tests_radio_chan_stats_response(void)
{
    for (int i = 0; radio_chan_stats_response_suite[i].test_name != NULL; i++) {
        em_rcs_test_case_t *test = &radio_chan_stats_response_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_radio_chan_stats_response_input(test);
        int pass = test_radio_chan_stats_response(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
