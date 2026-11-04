/*
 * TEST RUNNER: schedule_mac_for_sounding_locked
 *
 * Poisoned around the call:
 *   - the caller's mac_address buffer (lsm_mac_buf) past the 6-byte mac;
 *   - the wifi_ctrl_t stand-in (lsm_ctrl_buf) past sizeof(wifi_ctrl_t);
 *   - the levl and csi wifi_app stand-ins (lsm_app_buf / lsm_csi_buf) past
 *     sizeof(struct wifi_app).
 * mac_str (18 bytes) is an internal stack array guarded by ASan redzones; the
 * sounding entry and timeout data are heap blocks (leaks / double frees are
 * reported).
 *
 * PASS = return value and the current/pending puts, csi start/stop calls,
 * status publishes and scheduler calls match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int schedule_mac_for_sounding_locked(int ap_index, mac_address_t mac_address, int duration, int interval);

int test_schedule_mac_for_sounding_locked(const lv_lsm_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lsm_mac_buf[6], LSM_PAD);
    __asan_poison_memory_region(&lsm_ctrl_buf[sizeof(wifi_ctrl_t)], LSM_PAD);
    __asan_poison_memory_region(&lsm_app_buf[sizeof(struct wifi_app)], LSM_PAD);
    __asan_poison_memory_region(&lsm_csi_buf[sizeof(struct wifi_app)], LSM_PAD);

    int ret = schedule_mac_for_sounding_locked(3, (unsigned char *)lsm_mac_buf, 5000, 200);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lsm_csi_buf[sizeof(struct wifi_app)], LSM_PAD);
    __asan_unpoison_memory_region(&lsm_app_buf[sizeof(struct wifi_app)], LSM_PAD);
    __asan_unpoison_memory_region(&lsm_ctrl_buf[sizeof(wifi_ctrl_t)], LSM_PAD);
    __asan_unpoison_memory_region(&lsm_mac_buf[6], LSM_PAD);

    lsm_cleanup();
    int ok = (ret == tc->want_ret) && (lsm_curr_put == tc->want_curr_put) &&
             (lsm_pend_put == tc->want_pend_put) && (lsm_start_calls == tc->want_start) &&
             (lsm_stop_calls == tc->want_stop) && (lsm_pub_calls == tc->want_pub) &&
             (lsm_sched_calls == tc->want_sched);
    if (tc->want_curr_put + tc->want_pend_put)
        ok = ok && strcmp(lsm_last_key, "aa:bb:cc:dd:ee:01") == 0;
    printf("    ret=%d (want %d) curr_put=%d pend_put=%d start=%d stop=%d publish=%d sched=%d key=\"%s\"\n",
           ret, tc->want_ret, lsm_curr_put, lsm_pend_put, lsm_start_calls, lsm_stop_calls,
           lsm_pub_calls, lsm_sched_calls, lsm_last_key);
    return ok;
}

void run_all_tests_schedule_mac_for_sounding_locked(void)
{
    for (int i = 0; schedule_mac_for_sounding_locked_suite[i].test_name != NULL; i++) {
        lv_lsm_test_case_t *test = &schedule_mac_for_sounding_locked_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_schedule_mac_for_sounding_locked_input(test);
        int pass = test_schedule_mac_for_sounding_locked(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
