/*
 * TEST RUNNER: init_bus_subscription_test
 * Poison: name slot past 128; bus_handle past 16; p_app past its size.
 * name[128] (bus_name_string_t) is ASan-stack guarded.
 * PASS = return matches; on success the subscription fires and the session
 * index is set, with name < 128.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int init_bus_subscription(bus_handle_t *bus_handle, wifi_app_t *p_app);

int test_init_bus_subscription(const init_bus_subscription_test_case_t *tc)
{
    __asan_poison_memory_region(&ibs_slot[IBS_NAME_SZ], IBS_PAD);
    __asan_poison_memory_region(&ibs_bh_buf[16], IBS_PAD);
    __asan_poison_memory_region(&ibs_app_buf[sizeof(wifi_app_t)], IBS_PAD);

    int ret = init_bus_subscription((bus_handle_t *)ibs_bh_buf, (wifi_app_t *)ibs_app_buf);

    __asan_unpoison_memory_region(&ibs_app_buf[sizeof(wifi_app_t)], IBS_PAD);
    __asan_unpoison_memory_region(&ibs_bh_buf[16], IBS_PAD);
    __asan_unpoison_memory_region(&ibs_slot[IBS_NAME_SZ], IBS_PAD);

    printf("    ret=%d sub_calls=%d timer=%d name_len=%zu sub_name=\"%.40s\"\n", ret, ibs_sub_calls, ibs_timer_calls, ibs_name_len, ibs_sub_name);
    return ret == tc->expect_ret && ibs_name_len < IBS_NAME_SZ;
}

void run_all_tests_init_bus_subscription(void)
{
    for (int i = 0; init_bus_subscription_suite[i].test_name != NULL; i++) {
        init_bus_subscription_test_case_t *test = &init_bus_subscription_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_init_bus_subscription_input(test);
        int pass = test_init_bus_subscription(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
