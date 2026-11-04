/*
 * TEST RUNNER: radio_temperature_response
 *
 * Poisoned around the call:
 *   - the wifi_ctrl_t stand-in (lrt_ctrl_buf) past sizeof(wifi_ctrl_t);
 *   - the levl wifi_app stand-in (lrt_app_buf) past sizeof(struct wifi_app);
 *   - the caller's wifi_provider_response_t (lrt_resp_buf) past its size;
 *   - the caller's stat array (lrt_stat_buf = ONE radio_data_t) past element 0,
 *     even for stat_array_size = 3: any over-read of the stat array aborts.
 * eventName[64] is an internal stack array guarded by ASan redzones.
 *
 * PASS = return value, publish count, published event name / value / type
 * match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int radio_temperature_response(wifi_provider_response_t *provider_response);

int test_radio_temperature_response(const lv_lrt_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lrt_ctrl_buf[sizeof(wifi_ctrl_t)], LRT_PAD);
    __asan_poison_memory_region(&lrt_app_buf[sizeof(struct wifi_app)], LRT_PAD);
    __asan_poison_memory_region(&lrt_resp_buf[sizeof(wifi_provider_response_t)], LRT_PAD);
    __asan_poison_memory_region(&lrt_stat_buf[sizeof(radio_data_t)], LRT_PAD);

    int ret = radio_temperature_response((wifi_provider_response_t *)lrt_resp_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lrt_stat_buf[sizeof(radio_data_t)], LRT_PAD);
    __asan_unpoison_memory_region(&lrt_resp_buf[sizeof(wifi_provider_response_t)], LRT_PAD);
    __asan_unpoison_memory_region(&lrt_app_buf[sizeof(struct wifi_app)], LRT_PAD);
    __asan_unpoison_memory_region(&lrt_ctrl_buf[sizeof(wifi_ctrl_t)], LRT_PAD);

    int ok = (ret == tc->want_ret) && (lrt_pub_calls == tc->want_pub);
    if (tc->want_pub)
        ok = ok && strcmp(lrt_pub_name, tc->want_name) == 0 && lrt_pub_value == tc->temp && lrt_pub_type == 7;
    printf("    ret=%d (want %d) publish=%d (want %d) name=\"%s\" value=%u\n", ret, tc->want_ret,
           lrt_pub_calls, tc->want_pub, lrt_pub_name, lrt_pub_value);
    return ok;
}

void run_all_tests_radio_temperature_response(void)
{
    for (int i = 0; radio_temperature_response_suite[i].test_name != NULL; i++) {
        lv_lrt_test_case_t *test = &radio_temperature_response_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_radio_temperature_response_input(test);
        int pass = test_radio_temperature_response(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
