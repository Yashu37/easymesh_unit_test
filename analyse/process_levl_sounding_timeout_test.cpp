/*
 * TEST RUNNER: process_levl_sounding_timeout
 *
 * Poisoned around the call:
 *   - the wifi_ctrl_t stand-in (lst_ctrl_buf) past sizeof(wifi_ctrl_t);
 *   - the levl wifi_app stand-in (lst_app_buf) and the csi wifi_app stand-in
 *     (lst_csi_buf) past sizeof(struct wifi_app).
 * mac_str (18 bytes) and stop_mac (6 bytes) are internal stack arrays guarded
 * by ASan redzones; t_data and the sounding entry are heap blocks (a double
 * free / use after free would be reported).
 *
 * PASS = return value, csi_stop / publish / reschedule call counts, and the
 * stopped MAC + ap index match the case; the sounding entry is gone when found.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int process_levl_sounding_timeout(timeout_data_t *t_data);

int test_process_levl_sounding_timeout(const lv_lst_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lst_ctrl_buf[sizeof(wifi_ctrl_t)], LST_PAD);
    __asan_poison_memory_region(&lst_app_buf[sizeof(struct wifi_app)], LST_PAD);
    __asan_poison_memory_region(&lst_csi_buf[sizeof(struct wifi_app)], LST_PAD);

    int ret = process_levl_sounding_timeout(lst_tdata);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lst_csi_buf[sizeof(struct wifi_app)], LST_PAD);
    __asan_unpoison_memory_region(&lst_app_buf[sizeof(struct wifi_app)], LST_PAD);
    __asan_unpoison_memory_region(&lst_ctrl_buf[sizeof(wifi_ctrl_t)], LST_PAD);

    int slot_left = lst_slot_present();
    lst_set_slot(NULL, 0);                 /* free any entry the handler did not consume */
    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    int ok = (ret == tc->want_ret) && (lst_stop_calls == tc->want_stop) &&
             (lst_pub_calls == tc->want_pub) && (lst_sched_calls == tc->want_sched);
    if (tc->want_stop)
        ok = ok && memcmp(lst_stop_mac, mac, 6) == 0 && lst_stop_ap == 3 && lst_pub_status == 0 && !slot_left;
    printf("    ret=%d (want %d) stop=%d(ap %d) publish=%d(status %d) sched=%d slot_left=%d\n", ret,
           tc->want_ret, lst_stop_calls, lst_stop_ap, lst_pub_calls, lst_pub_status, lst_sched_calls, slot_left);
    return ok;
}

void run_all_tests_process_levl_sounding_timeout(void)
{
    for (int i = 0; process_levl_sounding_timeout_suite[i].test_name != NULL; i++) {
        lv_lst_test_case_t *test = &process_levl_sounding_timeout_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_levl_sounding_timeout_input(test);
        int pass = test_process_levl_sounding_timeout(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
