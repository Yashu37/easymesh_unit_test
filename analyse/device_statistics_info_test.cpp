/*
 * TEST RUNNER: device_statistics_info_test
 *
 * Poisoned around the call:
 *   - the caller's data (analytics_data_t): bytes past its size;
 *   - every station entry (analytics_sta_info_t): bytes past its size;
 *   - the write slots of the internal arrays, past the real sizes:
 *       ds_slot_tm  past 128 (tm_str), ds_slot_mac past 32 (client_mac),
 *       ds_slot_128 past 128 (temp_str), ds_slot_256 past 256 (sta_stats_str).
 * The arrays themselves are internal (auto-guarded by ASan).
 * PASS = no ASan abort, radio stats taken for every non-failing radio, and
 * every string stayed within its array (len < size).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void device_statistics_info(analytics_data_t *data);

int test_device_statistics_info(const device_statistics_info_test_case_t *tc)
{
    /* POISON: caller input + station entries + the 4 array write slots past their real sizes */
    __asan_poison_memory_region(&ds_data_buf[sizeof(analytics_data_t)], DS_PAD);          /* data struct */
    for (int i = 0; i < DS_MAX_STA; i++)
        __asan_poison_memory_region(&ds_sta_pool[i][sizeof(analytics_sta_info_t)], DS_PAD); /* station entries */
    __asan_poison_memory_region(&ds_slot_tm[DS_TM_SZ], DS_PAD);      /* tm_str[128]        */
    __asan_poison_memory_region(&ds_slot_mac[DS_MAC_SZ], DS_PAD);    /* client_mac[32]     */
    __asan_poison_memory_region(&ds_slot_128[DS_TMP_SZ], DS_PAD);    /* temp_str[128]      */
    __asan_poison_memory_region(&ds_slot_256[DS_STA_SZ], DS_PAD);    /* sta_stats_str[256] */

    device_statistics_info((analytics_data_t *)ds_data_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&ds_slot_256[DS_STA_SZ], DS_PAD);
    __asan_unpoison_memory_region(&ds_slot_128[DS_TMP_SZ], DS_PAD);
    __asan_unpoison_memory_region(&ds_slot_mac[DS_MAC_SZ], DS_PAD);
    __asan_unpoison_memory_region(&ds_slot_tm[DS_TM_SZ], DS_PAD);
    for (int i = 0; i < DS_MAX_STA; i++)
        __asan_unpoison_memory_region(&ds_sta_pool[i][sizeof(analytics_sta_info_t)], DS_PAD);
    __asan_unpoison_memory_region(&ds_data_buf[sizeof(analytics_data_t)], DS_PAD);

    int want_radios = tc->radios - (tc->fail_idx >= 0 && tc->fail_idx < tc->radios ? 1 : 0);
    printf("    radios=%d stations=%d -> radio_stats=%d tm_len=%zu max_temp_str_len=%zu max_sta_stats_len=%zu client_mac_len=%zu\n",
           tc->radios, tc->nsta, ds_radio_calls, ds_tm_len, ds_tmp_len, ds_sta_len, ds_mac_len);
    return ds_radio_calls == want_radios && ds_tm_len < DS_TM_SZ && ds_tmp_len < DS_TMP_SZ &&
           ds_sta_len < DS_STA_SZ && ds_mac_len < DS_MAC_SZ &&
           (tc->minutes % 60 != 0 || ds_tm_len > 0);
}

void run_all_tests_device_statistics_info(void)
{
    for (int i = 0; device_statistics_info_suite[i].test_name != NULL; i++) {
        device_statistics_info_test_case_t *test = &device_statistics_info_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_device_statistics_info_input(test);

        int pass = test_device_statistics_info(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
