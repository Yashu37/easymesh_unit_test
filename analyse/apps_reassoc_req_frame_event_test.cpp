/*
 * TEST RUNNER: apps_reassoc_req_frame_event
 *
 * Poisoned around the call:
 *   - the wifi_app stand-in (arf_app_buf) past sizeof(struct wifi_app);
 *   - the caller's frame_data_t (arf_msg_buf) past sizeof(frame_data_t).
 * namespace[50] is an internal stack array guarded by ASan redzones; the
 * longest formatted value (ap_index INT_MIN) is 46 bytes + NUL.
 *
 * PASS = the frame was forwarded once with the expected namespace string.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void apps_reassoc_req_frame_event(wifi_app_t *apps, frame_data_t *msg);

int test_apps_reassoc_req_frame_event(const lv_arf_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&arf_app_buf[sizeof(struct wifi_app)], ARF_PAD);
    __asan_poison_memory_region(&arf_msg_buf[sizeof(frame_data_t)], ARF_PAD);

    apps_reassoc_req_frame_event((wifi_app_t *)arf_app_buf, (frame_data_t *)arf_msg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&arf_msg_buf[sizeof(frame_data_t)], ARF_PAD);
    __asan_unpoison_memory_region(&arf_app_buf[sizeof(struct wifi_app)], ARF_PAD);

    int ok = (arf_send_calls == 1) && (strcmp(arf_sent_ns, tc->want_ns) == 0);
    printf("    send_calls=%d ns=\"%s\" (len %zu)\n", arf_send_calls, arf_sent_ns, strlen(arf_sent_ns));
    return ok;
}

void run_all_tests_apps_reassoc_req_frame_event(void)
{
    for (int i = 0; apps_reassoc_req_frame_event_suite[i].test_name != NULL; i++) {
        lv_arf_test_case_t *test = &apps_reassoc_req_frame_event_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_apps_reassoc_req_frame_event_input(test);
        int pass = test_apps_reassoc_req_frame_event(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
