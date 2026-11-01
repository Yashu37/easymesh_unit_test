/*
 * TEST RUNNER: analytics_event_sta_connect_in_progress_test
 *
 * Poisoned around the call:
 *   - the caller's arg (bss_candidate_t): bytes past its size;
 *   - the write slots of the internal arrays past their real sizes:
 *       scp_slot_mac past 18 (bssid_str), scp_slot_tmp past 512 (temp_str).
 * The arrays themselves are internal (auto-guarded by ASan).
 * PASS = return value matches and temp_str is the expected text.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_sta_connect_in_progress(wifi_app_t *apps, void *arg);

int test_analytics_event_sta_connect_in_progress(const analytics_event_sta_connect_in_progress_test_case_t *tc)
{
    void *arg = tc->arg_null ? NULL : (void *)scp_arg_buf;

    /* POISON */
    __asan_poison_memory_region(&scp_arg_buf[sizeof(bss_candidate_t)], SCP_PAD);   /* arg struct     */
    __asan_poison_memory_region(&scp_slot_mac[SCP_MAC_SZ], SCP_PAD);               /* bssid_str[18]  */
    __asan_poison_memory_region(&scp_slot_tmp[SCP_TMP_SZ], SCP_PAD);               /* temp_str[512]  */

    int ret = analytics_event_sta_connect_in_progress(NULL, arg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&scp_slot_tmp[SCP_TMP_SZ], SCP_PAD);
    __asan_unpoison_memory_region(&scp_slot_mac[SCP_MAC_SZ], SCP_PAD);
    __asan_unpoison_memory_region(&scp_arg_buf[sizeof(bss_candidate_t)], SCP_PAD);

    printf("    arg_null=%d -> ret=%d to_mac_str_calls=%d temp_str_len=%zu \"%s\"\n",
           tc->arg_null, ret, scp_mac_calls, scp_tmp_len, scp_slot_tmp);
    return ret == tc->expect_ret && !strcmp(scp_slot_tmp, tc->expect);
}

void run_all_tests_analytics_event_sta_connect_in_progress(void)
{
    for (int i = 0; analytics_event_sta_connect_in_progress_suite[i].test_name != NULL; i++) {
        analytics_event_sta_connect_in_progress_test_case_t *test = &analytics_event_sta_connect_in_progress_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_sta_connect_in_progress_input(test);

        int pass = test_analytics_event_sta_connect_in_progress(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d \"%s\") =====\n", test->test_name, test->expect_ret, test->expect);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
