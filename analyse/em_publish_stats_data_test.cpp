/*
 * TEST RUNNER: em_publish_stats_data
 *
 * Poisoned around the call:
 *   - the caller's scan_response (eps_scanresp_buf): bytes past
 *     sizeof(channel_scan_response_t);
 *   - the wifi_ctrl stand-in (eps_ctrl_buf): bytes past sizeof(wifi_ctrl_t).
 * eventName[200] is an internal stack array guarded by ASan redzones; the
 * subdoc/stats/encoded allocations are heap (ASan-guarded, and the handler
 * frees them on every path).
 *
 * PASS = return code matches, and on success the published event name is
 * exactly "Device.WiFi.EM.ChannelScanReport" (confirming eventName is written
 * within its 200-byte bound).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_publish_stats_data(channel_scan_response_t *scan_response);

int test_em_publish_stats_data(const em_eps_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&eps_scanresp_buf[sizeof(channel_scan_response_t)], EPS_PAD);
    __asan_poison_memory_region(&eps_ctrl_buf[sizeof(wifi_ctrl_t)], EPS_PAD);

    int ret = em_publish_stats_data((channel_scan_response_t *)eps_scanresp_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&eps_ctrl_buf[sizeof(wifi_ctrl_t)], EPS_PAD);
    __asan_unpoison_memory_region(&eps_scanresp_buf[sizeof(channel_scan_response_t)], EPS_PAD);

    int ok = (ret == tc->want_ret);
    if (ok && tc->want_ret == 0)
        ok = (strcmp(eps_published_event, "Device.WiFi.EM.ChannelScanReport") == 0);
    printf("    ret=%d publish_calls=%d event=\"%s\" (want %d)\n", ret, eps_publish_calls,
           eps_published_event, tc->want_ret);
    return ok;
}

void run_all_tests_em_publish_stats_data(void)
{
    for (int i = 0; em_publish_stats_data_suite[i].test_name != NULL; i++) {
        em_eps_test_case_t *test = &em_publish_stats_data_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_publish_stats_data_input(test);
        int pass = test_em_publish_stats_data(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
