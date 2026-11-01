/*
 * TEST RUNNER: analytics_event_hal_potential_misconfiguration_test
 *
 * Poisoned around the call:
 *   - the caller's arg (probe_ttl_data_t): bytes past its size, i.e. right
 *     after mac_str[18] (catches reading past mac_str);
 *   - the temp_str sprintf slot apm_slot past 128 (= sizeof(temp_str)).
 * temp_str[128] is internal (auto-guarded by ASan).
 * PASS = RETURN_OK and temp_str length matches (< 128).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_hal_potential_misconfiguration(wifi_app_t *apps, void *arg);

int test_analytics_event_hal_potential_misconfiguration(const analytics_event_hal_potential_misconfiguration_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&apm_arg_buf[sizeof(probe_ttl_data_t)], APM_PAD);   /* arg struct     */
    __asan_poison_memory_region(&apm_slot[APM_SLOT_SZ], APM_PAD);                   /* temp_str[128]  */

    int ret = analytics_event_hal_potential_misconfiguration(NULL, apm_arg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&apm_slot[APM_SLOT_SZ], APM_PAD);
    __asan_unpoison_memory_region(&apm_arg_buf[sizeof(probe_ttl_data_t)], APM_PAD);

    printf("    mac_str=\"%s\" count=%u -> ret=%d temp_str_len=%zu \"%s\"\n",
           tc->mac_str, tc->count, ret, apm_len, apm_slot);
    return ret == 0 && apm_len == (size_t)tc->expect_len;
}

void run_all_tests_analytics_event_hal_potential_misconfiguration(void)
{
    for (int i = 0; analytics_event_hal_potential_misconfiguration_suite[i].test_name != NULL; i++) {
        analytics_event_hal_potential_misconfiguration_test_case_t *test = &analytics_event_hal_potential_misconfiguration_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_hal_potential_misconfiguration_input(test);

        int pass = test_analytics_event_hal_potential_misconfiguration(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected temp_str_len=%d) =====\n", test->test_name, test->expect_len);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
