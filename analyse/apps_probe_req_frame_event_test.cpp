/*
 * TEST RUNNER: apps_probe_req_frame_event
 *
 * Poisoned around the call:
 *   - the wifi_app stand-in (lpr_app_buf) past sizeof(struct wifi_app);
 *   - the caller's frame_data_t (lpr_msg_buf) past sizeof(frame_data_t): the
 *     handler copies exactly sizeof(frame_data_t) from msg, so any longer read
 *     would trip.
 * mac_str (18 bytes) is an internal stack array guarded by ASan redzones;
 * the per-MAC element and frame copies are heap blocks with redzones.
 *
 * PASS = saved-frame count, first frame's ap_index, map key and update_probe_map
 * call count match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void apps_probe_req_frame_event(wifi_app_t *app, frame_data_t *msg);

int test_apps_probe_req_frame_event(const lv_lpr_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lpr_app_buf[sizeof(struct wifi_app)], LPR_PAD);
    __asan_poison_memory_region(&lpr_msg_buf[sizeof(frame_data_t)], LPR_PAD);

    apps_probe_req_frame_event((wifi_app_t *)lpr_app_buf, (frame_data_t *)lpr_msg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lpr_msg_buf[sizeof(frame_data_t)], LPR_PAD);
    __asan_unpoison_memory_region(&lpr_app_buf[sizeof(struct wifi_app)], LPR_PAD);

    char key[64]; int upd = 0, first = 0;
    int frames = lpr_result(key, sizeof(key), &upd, &first);
    lpr_teardown();
    int ok = (frames == tc->want_frames) && (first == tc->want_first_ap) &&
             (upd == tc->want_update) && (strcmp(key, tc->want_key) == 0);
    printf("    frames=%d (want %d) first_ap=%d (want %d) update_calls=%d key=\"%s\"\n",
           frames, tc->want_frames, first, tc->want_first_ap, upd, key);
    return ok;
}

void run_all_tests_apps_probe_req_frame_event(void)
{
    for (int i = 0; apps_probe_req_frame_event_suite[i].test_name != NULL; i++) {
        lv_lpr_test_case_t *test = &apps_probe_req_frame_event_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_apps_probe_req_frame_event_input(test);
        int pass = test_apps_probe_req_frame_event(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
