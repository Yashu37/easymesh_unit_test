/*
 * TEST RUNNER: analytics_event_hal_scan_results_test
 *
 * Poisoned around the call:
 *   - the caller's arg (scan_results_t): bytes past its size;
 *   - the str snprintf slot asr_slot past 128 (= sizeof(str)).
 * str[128] is internal (auto-guarded by ASan).
 * PASS = return, snprintf calls and str length match.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_hal_scan_results(wifi_app_t *apps, void *arg);

int test_analytics_event_hal_scan_results(const analytics_event_hal_scan_results_test_case_t *tc)
{
    void *arg = tc->arg_null ? NULL : (void *)asr_arg_buf;

    /* POISON */
    __asan_poison_memory_region(&asr_arg_buf[sizeof(scan_results_t)], ASR_PAD);   /* arg struct */
    __asan_poison_memory_region(&asr_slot[ASR_SLOT_SZ], ASR_PAD);                 /* str[128]   */

    int ret = analytics_event_hal_scan_results(NULL, arg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&asr_slot[ASR_SLOT_SZ], ASR_PAD);
    __asan_unpoison_memory_region(&asr_arg_buf[sizeof(scan_results_t)], ASR_PAD);

    printf("    radio_index=%u num=%u -> ret=%d snprintf_calls=%d str_len=%zu \"%s\"\n",
           tc->radio_index, tc->num, ret, asr_calls, asr_len, asr_calls ? asr_slot : "");
    return ret == tc->expect_ret && asr_calls == tc->expect_calls && asr_len == (size_t)tc->expect_len;
}

void run_all_tests_analytics_event_hal_scan_results(void)
{
    for (int i = 0; analytics_event_hal_scan_results_suite[i].test_name != NULL; i++) {
        analytics_event_hal_scan_results_test_case_t *test = &analytics_event_hal_scan_results_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_hal_scan_results_input(test);

        int pass = test_analytics_event_hal_scan_results(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d calls=%d len=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_calls, test->expect_len);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
