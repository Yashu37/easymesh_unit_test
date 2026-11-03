/*
 * TEST RUNNER: em_process_beacon_rep
 *
 * Poisoned around the call:
 *   - the 802.11 frame tail (epbr_mgmt_buf): bytes past the passed `len`;
 *   - the rep header (epbr_rep_buf): bytes past sizeof(wifi_hal_rrm_report_t);
 *   - the sta_mac (epbr_sta_mac): bytes past the 6-byte mac.
 * report (sta_beacon_report_reponse_t) and mac_str[18] are internal stack
 * objects guarded by ASan redzones; report.data is a sized heap allocation
 * (freed by the handler).
 *
 * PASS = return code matches and the publish was invoked the expected number
 * of times (confirming the len/data_len validation and that the payload memcpy
 * stays within the frame).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_process_beacon_rep(mac_address_t sta_mac, wifi_hal_rrm_report_t *rep, wifi_app_t *app,
    const struct ieee80211_mgmt *mgmt, size_t len, int ap_index);

int test_em_process_beacon_rep(const em_epbr_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&epbr_mgmt_buf[epbr_len], EPBR_PAD);
    __asan_poison_memory_region(&epbr_rep_buf[sizeof(wifi_hal_rrm_report_t)], EPBR_PAD);
    __asan_poison_memory_region(&epbr_sta_mac[6], EPBR_PAD);

    int rc = em_process_beacon_rep((unsigned char *)epbr_sta_mac,
                                   (wifi_hal_rrm_report_t *)epbr_rep_buf,
                                   (wifi_app_t *)epbr_app_buf,
                                   (const struct ieee80211_mgmt *)epbr_mgmt_buf,
                                   epbr_len, 2);

    /* UNPOISON */
    __asan_unpoison_memory_region(&epbr_sta_mac[6], EPBR_PAD);
    __asan_unpoison_memory_region(&epbr_rep_buf[sizeof(wifi_hal_rrm_report_t)], EPBR_PAD);
    __asan_unpoison_memory_region(&epbr_mgmt_buf[epbr_len], EPBR_PAD);

    int ok = (rc == tc->want_rc) && (epbr_publish_calls == tc->want_publish);
    printf("    rc=%d publish_calls=%d last_data_len=%u (want %d/%d)\n", rc, epbr_publish_calls,
           epbr_last_data_len, tc->want_rc, tc->want_publish);
    return ok;
}

void run_all_tests_em_process_beacon_rep(void)
{
    for (int i = 0; em_process_beacon_rep_suite[i].test_name != NULL; i++) {
        em_epbr_test_case_t *test = &em_process_beacon_rep_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_process_beacon_rep_input(test);
        int pass = test_em_process_beacon_rep(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
