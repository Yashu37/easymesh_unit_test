/*
 * TEST RUNNER: start_sta_channel_scan_test
 * Poison: the caller scan_req past the struct; the wifi_mgr stand-in past its
 * size. radio_mac[6] / country[8] / channels[64] are internal (ASan-stack
 * guarded) -- so the unbounded channels[] write is caught.
 * The overflow_70ch case is expected to overflow channels[64] (reproducer).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

extern int ssc_scan_calls, ssc_scan_num;
void start_sta_channel_scan(void *data, unsigned int len);

int test_start_sta_channel_scan(const start_sta_channel_scan_test_case_t *tc)
{
    __asan_poison_memory_region(&ssc_req_buf[sizeof(channel_scan_request_t)], SSC_PAD);
    __asan_poison_memory_region(&ssc_mgr_buf[sizeof(wifi_mgr_t)], SSC_PAD);
    printf("    (calling num_channels=%u)\n", tc->num_channels); fflush(stdout);

    start_sta_channel_scan(ssc_req_buf, (unsigned int)sizeof(channel_scan_request_t));

    __asan_unpoison_memory_region(&ssc_mgr_buf[sizeof(wifi_mgr_t)], SSC_PAD);
    __asan_unpoison_memory_region(&ssc_req_buf[sizeof(channel_scan_request_t)], SSC_PAD);

    printf("    scan_calls=%d scan_num=%d\n", ssc_scan_calls, ssc_scan_num);
    return ssc_scan_calls == 1;
}

void run_all_tests_start_sta_channel_scan(void)
{
    for (int i = 0; start_sta_channel_scan_suite[i].test_name != NULL; i++) {
        start_sta_channel_scan_test_case_t *test = &start_sta_channel_scan_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_start_sta_channel_scan_input(test);
        int pass = test_start_sta_channel_scan(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
