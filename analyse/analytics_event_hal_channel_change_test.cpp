/*
 * TEST RUNNER: analytics_event_hal_channel_change_test
 *
 * Poisoned around the call:
 *   - the caller's arg (wifi_channel_change_event_t): bytes past its size;
 *   - the desc snprintf slot acc_slot past 128 (= sizeof(desc)).
 * desc[128] and the static dfs_states[6] are internal (auto-guarded by
 * ASan stack / global redzones -- an index of 6+ into dfs_states aborts).
 * PASS = RETURN_OK, one snprintf, desc starts with the expected text and
 * is < 128 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_hal_channel_change(wifi_app_t *apps, void *arg);

int test_analytics_event_hal_channel_change(const analytics_event_hal_channel_change_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&acc_arg_buf[sizeof(wifi_channel_change_event_t)], ACC_PAD);   /* arg struct */
    __asan_poison_memory_region(&acc_slot[ACC_SLOT_SZ], ACC_PAD);                              /* desc[128]  */

    int ret = analytics_event_hal_channel_change(NULL, acc_arg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&acc_slot[ACC_SLOT_SZ], ACC_PAD);
    __asan_unpoison_memory_region(&acc_arg_buf[sizeof(wifi_channel_change_event_t)], ACC_PAD);

    printf("    event=%d sub_event=%u -> ret=%d desc_len=%zu \"%s\"\n",
           tc->event, tc->sub_event, ret, acc_len, acc_slot);
    return ret == 0 && acc_calls == 1 && acc_len < ACC_SLOT_SZ &&
           !strncmp(acc_slot, tc->expect_prefix, strlen(tc->expect_prefix));
}

void run_all_tests_analytics_event_hal_channel_change(void)
{
    for (int i = 0; analytics_event_hal_channel_change_suite[i].test_name != NULL; i++) {
        analytics_event_hal_channel_change_test_case_t *test = &analytics_event_hal_channel_change_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_hal_channel_change_input(test);

        int pass = test_analytics_event_hal_channel_change(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected prefix \"%s\") =====\n", test->test_name, test->expect_prefix);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
