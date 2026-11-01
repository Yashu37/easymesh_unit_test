/*
 * TEST RUNNER: analytics_event_wpa3_rfc_test
 *
 * Poisoned around the call:
 *   - the caller's arg (bool): bytes past sizeof(bool);
 *   - the str snprintf slot awr_slot past 32 (= sizeof(str)).
 * str[32] is internal (auto-guarded by ASan).
 * PASS = RETURN_OK and str is "True" / "False".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_wpa3_rfc(wifi_app_t *apps, void *arg);

int test_analytics_event_wpa3_rfc(const analytics_event_wpa3_rfc_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&awr_arg_buf[sizeof(bool)], AWR_PAD);   /* arg bool */
    __asan_poison_memory_region(&awr_slot[AWR_SLOT_SZ], AWR_PAD);       /* str[32]  */

    int ret = analytics_event_wpa3_rfc(NULL, awr_arg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&awr_slot[AWR_SLOT_SZ], AWR_PAD);
    __asan_unpoison_memory_region(&awr_arg_buf[sizeof(bool)], AWR_PAD);

    printf("    rfc=%d -> ret=%d str_len=%zu \"%s\"\n", tc->rfc, ret, awr_len, awr_slot);
    return ret == 0 && !strcmp(awr_slot, tc->expect);
}

void run_all_tests_analytics_event_wpa3_rfc(void)
{
    for (int i = 0; analytics_event_wpa3_rfc_suite[i].test_name != NULL; i++) {
        analytics_event_wpa3_rfc_test_case_t *test = &analytics_event_wpa3_rfc_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_wpa3_rfc_input(test);

        int pass = test_analytics_event_wpa3_rfc(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected \"%s\") =====\n", test->test_name, test->expect);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
