/*
 * TEST RUNNER: analytics_event_trigger_disconnection_analytics_test
 *
 * Poisoned around the call:
 *   - the caller's arg (vap_svc_ext_t): bytes past its size;
 *   - the write slots of the internal arrays past their real sizes:
 *       tda_slot_mac past 18 (bssid_str), tda_slot_tmp past 512 (temp_str).
 * The arrays themselves are internal (auto-guarded by ASan).
 * PASS = return value matches and temp_str is the expected text.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_trigger_disconnection_analytics(wifi_app_t *apps, void *arg);

int test_analytics_event_trigger_disconnection_analytics(const analytics_event_trigger_disconnection_analytics_test_case_t *tc)
{
    void *arg = tc->arg_null ? NULL : (void *)tda_arg_buf;

    /* POISON */
    __asan_poison_memory_region(&tda_arg_buf[sizeof(vap_svc_ext_t)], TDA_PAD);   /* arg struct     */
    __asan_poison_memory_region(&tda_slot_mac[TDA_MAC_SZ], TDA_PAD);             /* bssid_str[18]  */
    __asan_poison_memory_region(&tda_slot_tmp[TDA_TMP_SZ], TDA_PAD);             /* temp_str[512]  */

    int ret = analytics_event_trigger_disconnection_analytics(NULL, arg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&tda_slot_tmp[TDA_TMP_SZ], TDA_PAD);
    __asan_unpoison_memory_region(&tda_slot_mac[TDA_MAC_SZ], TDA_PAD);
    __asan_unpoison_memory_region(&tda_arg_buf[sizeof(vap_svc_ext_t)], TDA_PAD);

    printf("    arg_null=%d vap_index=%u -> ret=%d to_mac_str_calls=%d temp_str_len=%zu \"%s\"\n",
           tc->arg_null, tc->vap_index, ret, tda_mac_calls, tda_tmp_len, tda_slot_tmp);
    return ret == tc->expect_ret && !strcmp(tda_slot_tmp, tc->expect);
}

void run_all_tests_analytics_event_trigger_disconnection_analytics(void)
{
    for (int i = 0; analytics_event_trigger_disconnection_analytics_suite[i].test_name != NULL; i++) {
        analytics_event_trigger_disconnection_analytics_test_case_t *test = &analytics_event_trigger_disconnection_analytics_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_trigger_disconnection_analytics_input(test);

        int pass = test_analytics_event_trigger_disconnection_analytics(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d \"%s\") =====\n", test->test_name, test->expect_ret, test->expect);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
