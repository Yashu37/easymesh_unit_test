/*
 * TEST RUNNER: levl_event_webconfig_set_data
 *
 * Poisoned around the call:
 *   - the levl wifi_app stand-in (lse_apps_buf) past sizeof(struct wifi_app);
 *   - the caller's webconfig_subdoc_data_t (lse_doc_buf) past its size: the
 *     handler reads only type and the levl config (mac[6] + 3 ints) from it.
 * null_mac (6 bytes) is an internal stack array guarded by ASan redzones.
 *
 * PASS = return value, stored max/duration/interval and the schedule call
 * (count + ap/mac/duration/interval) match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int levl_event_webconfig_set_data(wifi_app_t *apps, void *arg, int sub_type);

int test_levl_event_webconfig_set_data(const lv_lse_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lse_apps_buf[sizeof(struct wifi_app)], LSE_PAD);
    __asan_poison_memory_region(&lse_doc_buf[sizeof(webconfig_subdoc_data_t)], LSE_PAD);

    int ret = levl_event_webconfig_set_data((wifi_app_t *)lse_apps_buf, lse_doc_buf, 0);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lse_doc_buf[sizeof(webconfig_subdoc_data_t)], LSE_PAD);
    __asan_unpoison_memory_region(&lse_apps_buf[sizeof(struct wifi_app)], LSE_PAD);

    struct wifi_app *app = (struct wifi_app *)lse_apps_buf;
    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    int ok = (ret == 0) && (app->data.u.levl.max_num_csi_clients == tc->want_max) &&
             (app->data.u.levl.sounding_duration == tc->want_dur) &&
             (app->data.u.levl.publish_interval == tc->want_int) && (lse_sched_calls == tc->want_sched);
    if (tc->want_sched)
        ok = ok && lse_sched_ap == tc->ap_ret && memcmp(lse_sched_mac, mac, 6) == 0 &&
             lse_sched_dur == tc->dur && lse_sched_int == tc->interval;
    printf("    ret=%d max=%d(want %d) dur=%d(want %d) int=%d(want %d) sched=%d(want %d)\n", ret,
           app->data.u.levl.max_num_csi_clients, tc->want_max, app->data.u.levl.sounding_duration, tc->want_dur,
           app->data.u.levl.publish_interval, tc->want_int, lse_sched_calls, tc->want_sched);
    return ok;
}

void run_all_tests_levl_event_webconfig_set_data(void)
{
    for (int i = 0; levl_event_webconfig_set_data_suite[i].test_name != NULL; i++) {
        lv_lse_test_case_t *test = &levl_event_webconfig_set_data_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_levl_event_webconfig_set_data_input(test);
        int pass = test_levl_event_webconfig_set_data(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
