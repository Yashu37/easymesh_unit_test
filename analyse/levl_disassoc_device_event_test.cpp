/*
 * TEST RUNNER: levl_disassoc_device_event
 *
 * Poisoned around the call:
 *   - the wifi_ctrl_t stand-in (lds_ctrl_buf) past sizeof(wifi_ctrl_t);
 *   - the levl and csi wifi_app stand-ins (lds_app_buf / lds_csi_buf) past
 *     sizeof(struct wifi_app);
 *   - the caller's assoc_dev_data_t (lds_data_buf) past its size: the handler
 *     reads only ap_index and the 6-byte cli_MACAddress from it.
 * mac_str (18 bytes) is an internal stack array guarded by ASan redzones; the
 * sounding / pending entries are heap blocks (a double free / use after free
 * would be reported).
 *
 * PASS = stop / publish / cancel / free-arg counts, the num_current_sounding
 * counter and which entries remain match the case; stopped MAC + ap index match.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void levl_disassoc_device_event(wifi_app_t *apps, void *data);

int test_levl_disassoc_device_event(const lv_lds_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lds_ctrl_buf[sizeof(wifi_ctrl_t)], LDS_PAD);
    __asan_poison_memory_region(&lds_app_buf[sizeof(struct wifi_app)], LDS_PAD);
    __asan_poison_memory_region(&lds_csi_buf[sizeof(struct wifi_app)], LDS_PAD);
    __asan_poison_memory_region(&lds_data_buf[sizeof(assoc_dev_data_t)], LDS_PAD);

    levl_disassoc_device_event(NULL, tc->null_data ? NULL : (void *)lds_data_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lds_data_buf[sizeof(assoc_dev_data_t)], LDS_PAD);
    __asan_unpoison_memory_region(&lds_csi_buf[sizeof(struct wifi_app)], LDS_PAD);
    __asan_unpoison_memory_region(&lds_app_buf[sizeof(struct wifi_app)], LDS_PAD);
    __asan_unpoison_memory_region(&lds_ctrl_buf[sizeof(wifi_ctrl_t)], LDS_PAD);

    int cur_left = lds_curr_present(), pend_left = lds_pend_present();
    int nsnd = ((struct wifi_app *)lds_app_buf)->data.u.levl.num_current_sounding;
    lds_set_slots(NULL, 0, 0, 0);          /* free any entry the handler did not consume */
    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    int ok = (lds_stop_calls == tc->want_stop) && (lds_pub_calls == tc->want_pub) &&
             (lds_cancel_calls == tc->want_cancel) && (lds_freearg_calls == tc->want_freearg) &&
             (nsnd == tc->want_nsnd) && (cur_left == tc->want_cur_left) && (pend_left == tc->want_pend_left);
    if (tc->want_stop)
        ok = ok && memcmp(lds_stop_mac, mac, 6) == 0 && lds_stop_ap == 3 &&
             memcmp(lds_pub_mac, mac, 6) == 0 && lds_pub_status == 0;
    if (tc->want_cancel)
        ok = ok && lds_cancel_id == 7;
    printf("    stop=%d(ap %d) pub=%d cancel=%d freearg=%d nsnd=%d(want %d) cur_left=%d pend_left=%d\n",
           lds_stop_calls, lds_stop_ap, lds_pub_calls, lds_cancel_calls, lds_freearg_calls,
           nsnd, tc->want_nsnd, cur_left, pend_left);
    return ok;
}

void run_all_tests_levl_disassoc_device_event(void)
{
    for (int i = 0; levl_disassoc_device_event_suite[i].test_name != NULL; i++) {
        lv_lds_test_case_t *test = &levl_disassoc_device_event_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_levl_disassoc_device_event_input(test);
        int pass = test_levl_disassoc_device_event(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
