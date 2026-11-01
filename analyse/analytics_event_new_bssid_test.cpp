/*
 * TEST RUNNER: analytics_event_new_bssid_test
 *
 * Poisoned around the call:
 *   - the caller's arg (vap_svc_ext_t): bytes past its size;
 *   - the write slots of the internal arrays past their real sizes:
 *       anb_slot_mac past 18 (bssid_str), anb_slot_tmp past 512 (temp_str).
 * The arrays themselves are internal (auto-guarded by ASan).
 * PASS = return value matches and temp_str is the expected text.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_new_bssid(wifi_app_t *apps, void *arg);

int test_analytics_event_new_bssid(const analytics_event_new_bssid_test_case_t *tc)
{
    void *arg = tc->arg_null ? NULL : (void *)anb_arg_buf;

    /* POISON */
    __asan_poison_memory_region(&anb_arg_buf[sizeof(vap_svc_ext_t)], ANB_PAD);   /* arg struct     */
    __asan_poison_memory_region(&anb_slot_mac[ANB_MAC_SZ], ANB_PAD);             /* bssid_str[18]  */
    __asan_poison_memory_region(&anb_slot_tmp[ANB_TMP_SZ], ANB_PAD);             /* temp_str[512]  */

    int ret = analytics_event_new_bssid(NULL, arg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&anb_slot_tmp[ANB_TMP_SZ], ANB_PAD);
    __asan_unpoison_memory_region(&anb_slot_mac[ANB_MAC_SZ], ANB_PAD);
    __asan_unpoison_memory_region(&anb_arg_buf[sizeof(vap_svc_ext_t)], ANB_PAD);

    printf("    arg_null=%d vap_index=%u freq=%u -> ret=%d to_mac_str_calls=%d temp_str_len=%zu \"%s\"\n",
           tc->arg_null, tc->vap_index, tc->freq, ret, anb_mac_calls, anb_tmp_len, anb_slot_tmp);
    return ret == tc->expect_ret && !strcmp(anb_slot_tmp, tc->expect);
}

void run_all_tests_analytics_event_new_bssid(void)
{
    for (int i = 0; analytics_event_new_bssid_suite[i].test_name != NULL; i++) {
        analytics_event_new_bssid_test_case_t *test = &analytics_event_new_bssid_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_new_bssid_input(test);

        int pass = test_analytics_event_new_bssid(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d \"%s\") =====\n", test->test_name, test->expect_ret, test->expect);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
