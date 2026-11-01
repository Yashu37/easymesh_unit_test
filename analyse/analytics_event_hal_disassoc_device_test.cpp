/*
 * TEST RUNNER: analytics_event_hal_disassoc_device_test
 *
 * Poisoned around the call:
 *   - the caller's arg (assoc_dev_data_t) and apps (wifi_app_t): bytes past
 *     each struct;
 *   - the write slots of the internal arrays past their real sizes:
 *       add_slot_mac past 32 (client_mac), add_slot_tmp past 64 (temp_str).
 * The arrays themselves are internal (auto-guarded by ASan).
 * PASS = RETURN_OK, the lookup key is lower-case, remove / free happen as
 * expected, and temp_str length matches (< 64).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_hal_disassoc_device(wifi_app_t *apps, void *arg);

int test_analytics_event_hal_disassoc_device(const analytics_event_hal_disassoc_device_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&add_arg_buf[sizeof(assoc_dev_data_t)], ADD_PAD);   /* arg struct     */
    __asan_poison_memory_region(&add_apps_buf[sizeof(wifi_app_t)], ADD_PAD);        /* apps struct    */
    __asan_poison_memory_region(&add_slot_mac[ADD_MAC_SZ], ADD_PAD);                /* client_mac[32] */
    __asan_poison_memory_region(&add_slot_tmp[ADD_TMP_SZ], ADD_PAD);                /* temp_str[64]   */

    int ret = analytics_event_hal_disassoc_device((wifi_app_t *)add_apps_buf, add_arg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&add_slot_tmp[ADD_TMP_SZ], ADD_PAD);
    __asan_unpoison_memory_region(&add_slot_mac[ADD_MAC_SZ], ADD_PAD);
    __asan_unpoison_memory_region(&add_apps_buf[sizeof(wifi_app_t)], ADD_PAD);
    __asan_unpoison_memory_region(&add_arg_buf[sizeof(assoc_dev_data_t)], ADD_PAD);

    int lower = 1;
    for (const char *p = add_key_seen; *p; p++) if (*p >= 'A' && *p <= 'F') lower = 0;
    printf("    ap_index=%d reason=%d -> ret=%d key=\"%s\" removes=%d freed=%d temp_str_len=%zu \"%s\"\n",
           tc->ap_index, tc->reason, ret, add_key_seen, add_remove_calls, add_freed != NULL, add_tmp_len, add_slot_tmp);
    return ret == 0 && lower && add_remove_calls == tc->expect_removes &&
           (add_freed != NULL) == (tc->expect_freed != 0) && add_tmp_len == (size_t)tc->expect_tmp_len;
}

void run_all_tests_analytics_event_hal_disassoc_device(void)
{
    for (int i = 0; analytics_event_hal_disassoc_device_suite[i].test_name != NULL; i++) {
        analytics_event_hal_disassoc_device_test_case_t *test = &analytics_event_hal_disassoc_device_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_hal_disassoc_device_input(test);

        int pass = test_analytics_event_hal_disassoc_device(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected removes=%d freed=%d temp_str_len=%d) =====\n",
                   test->test_name, test->expect_removes, test->expect_freed, test->expect_tmp_len);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
