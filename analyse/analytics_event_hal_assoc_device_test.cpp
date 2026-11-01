/*
 * TEST RUNNER: analytics_event_hal_assoc_device_test
 *
 * Poisoned around the call:
 *   - the caller's arg (assoc_dev_data_t) and apps (wifi_app_t): bytes past
 *     each struct;
 *   - every malloc pool slot past sizeof(analytics_sta_info_t);
 *   - the write slots of the internal arrays past their real sizes:
 *       aad_slot_mac past 32 (client_mac), aad_slot_tmp past 64 (temp_str).
 * The arrays themselves are internal (auto-guarded by ASan).
 * PASS = RETURN_OK (RETURN_ERR when malloc fails), the right station is stored/updated with the lower-case
 * key, and temp_str length matches (< 64).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int analytics_event_hal_assoc_device(wifi_app_t *apps, void *arg);

int test_analytics_event_hal_assoc_device(const analytics_event_hal_assoc_device_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&aad_arg_buf[sizeof(assoc_dev_data_t)], AAD_PAD);     /* arg struct     */
    __asan_poison_memory_region(&aad_apps_buf[sizeof(wifi_app_t)], AAD_PAD);          /* apps struct    */
    for (int i = 0; i < AAD_POOL_SLOTS; i++)
        __asan_poison_memory_region(&aad_pool[i][sizeof(analytics_sta_info_t)], AAD_PAD); /* malloc slots */
    __asan_poison_memory_region(&aad_slot_mac[AAD_MAC_SZ], AAD_PAD);                  /* client_mac[32] */
    __asan_poison_memory_region(&aad_slot_tmp[AAD_TMP_SZ], AAD_PAD);                  /* temp_str[64]   */
    fflush(stdout);

    int ret = analytics_event_hal_assoc_device((wifi_app_t *)aad_apps_buf, aad_arg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&aad_slot_tmp[AAD_TMP_SZ], AAD_PAD);
    __asan_unpoison_memory_region(&aad_slot_mac[AAD_MAC_SZ], AAD_PAD);
    for (int i = 0; i < AAD_POOL_SLOTS; i++)
        __asan_unpoison_memory_region(&aad_pool[i][sizeof(analytics_sta_info_t)], AAD_PAD);
    __asan_unpoison_memory_region(&aad_apps_buf[sizeof(wifi_app_t)], AAD_PAD);
    __asan_unpoison_memory_region(&aad_arg_buf[sizeof(assoc_dev_data_t)], AAD_PAD);

    assoc_dev_data_t *a = (assoc_dev_data_t *)aad_arg_buf;
    analytics_sta_info_t *s = (analytics_sta_info_t *)(aad_put_data ? aad_put_data : aad_existing);
    int stored = s && s->ap_index == (unsigned int)a->ap_index && !memcmp(s->sta_mac, a->dev_stats.cli_MACAddress, 6);
    int lower = 1;
    for (const char *p = aad_put_key; *p; p++) if (*p >= 'A' && *p <= 'F') lower = 0;
    printf("    ap_index=%d -> ret=%d put_key=\"%s\" stored=%d temp_str_len=%zu \"%s\"\n",
           tc->ap_index, ret, aad_put_key, stored, aad_tmp_len, aad_slot_tmp);
    if (tc->malloc_fail) stored = 1;   /* nothing is stored when malloc fails */
    return ret == (tc->malloc_fail ? -1 : 0) && (aad_put_data != NULL) == (tc->expect_put != 0) && stored && lower &&
           aad_tmp_len == (size_t)tc->expect_tmp_len;
}

void run_all_tests_analytics_event_hal_assoc_device(void)
{
    for (int i = 0; analytics_event_hal_assoc_device_suite[i].test_name != NULL; i++) {
        analytics_event_hal_assoc_device_test_case_t *test = &analytics_event_hal_assoc_device_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_analytics_event_hal_assoc_device_input(test);

        int pass = test_analytics_event_hal_assoc_device(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected put=%d temp_str_len=%d) =====\n",
                   test->test_name, test->expect_put, test->expect_tmp_len);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
