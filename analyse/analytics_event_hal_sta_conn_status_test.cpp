/*
 * TEST RUNNER: analytics_event_hal_sta_conn_status_test
 *
 * Poisoned around the call:
 *   - the caller's arg (rdk_sta_data_t): bytes past its size;
 *   - the temp_str snprintf slot scs_slot past 128 (= sizeof(temp_str)).
 * temp_str[128] is internal (auto-guarded by ASan).
 * PASS = return, number of snprintf calls and temp_str length match.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_hal_sta_conn_status(wifi_app_t *apps, void *arg);

int test_analytics_event_hal_sta_conn_status(const analytics_event_hal_sta_conn_status_test_case_t *tc)
{
    void *arg = tc->arg_null ? NULL : (void *)scs_arg_buf;

    /* POISON */
    __asan_poison_memory_region(&scs_arg_buf[sizeof(rdk_sta_data_t)], SCS_PAD);   /* arg struct      */
    __asan_poison_memory_region(&scs_slot[SCS_SLOT_SZ], SCS_PAD);                 /* temp_str[128]   */

    int ret = analytics_event_hal_sta_conn_status(NULL, arg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&scs_slot[SCS_SLOT_SZ], SCS_PAD);
    __asan_unpoison_memory_region(&scs_arg_buf[sizeof(rdk_sta_data_t)], SCS_PAD);

    printf("    status=%d vap_index=%d -> ret=%d snprintf_calls=%d temp_str_len=%zu \"%s\"\n",
           tc->status, tc->vap_index, ret, scs_calls, scs_len, scs_calls ? scs_slot : "");
    return ret == tc->expect_ret && scs_calls == tc->expect_calls && scs_len == (size_t)tc->expect_len;
}

void run_all_tests_analytics_event_hal_sta_conn_status(void)
{
    for (int i = 0; analytics_event_hal_sta_conn_status_suite[i].test_name != NULL; i++) {
        analytics_event_hal_sta_conn_status_test_case_t *test = &analytics_event_hal_sta_conn_status_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_hal_sta_conn_status_input(test);

        int pass = test_analytics_event_hal_sta_conn_status(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d calls=%d len=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_calls, test->expect_len);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
