/*
 * TEST RUNNER: apps_assoc_req_frame_event
 *
 * Poisoned around the call:
 *   - the wifi_app stand-in (aar_app_buf) past sizeof(struct wifi_app);
 *   - the caller's frame_data_t (aar_msg_buf) past sizeof(frame_data_t).
 * mac_str (18 bytes) and namespace[50] are internal stack arrays guarded by
 * ASan redzones; saved probe frames are heap blocks (freed by the handler when
 * sent).
 *
 * PASS = number of forwarded frames, the namespaces used and the probe frames
 * still saved in the map match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void apps_assoc_req_frame_event(wifi_app_t *app, frame_data_t *msg);

int test_apps_assoc_req_frame_event(const lv_aar_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&aar_app_buf[sizeof(struct wifi_app)], AAR_PAD);
    __asan_poison_memory_region(&aar_msg_buf[sizeof(frame_data_t)], AAR_PAD);

    apps_assoc_req_frame_event((wifi_app_t *)aar_app_buf, (frame_data_t *)aar_msg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&aar_msg_buf[sizeof(frame_data_t)], AAR_PAD);
    __asan_unpoison_memory_region(&aar_app_buf[sizeof(struct wifi_app)], AAR_PAD);

    int remaining = aar_remaining();
    aar_teardown();
    int ok = (aar_send_calls == tc->want_sends) && (remaining == tc->want_remaining) &&
             (strcmp(aar_sent_ns[0], tc->want_ns0) == 0) &&
             (tc->want_sends < 2 || strcmp(aar_sent_ns[1], tc->want_ns1) == 0);
    printf("    sends=%d (want %d) ns0=\"%s\" ns1=\"%s\" remaining=%d (want %d)\n", aar_send_calls,
           tc->want_sends, aar_sent_ns[0], aar_sent_ns[1], remaining, tc->want_remaining);
    return ok;
}

void run_all_tests_apps_assoc_req_frame_event(void)
{
    for (int i = 0; apps_assoc_req_frame_event_suite[i].test_name != NULL; i++) {
        lv_aar_test_case_t *test = &apps_assoc_req_frame_event_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_apps_assoc_req_frame_event_input(test);
        int pass = test_apps_assoc_req_frame_event(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
