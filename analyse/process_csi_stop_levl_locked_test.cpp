/*
 * TEST RUNNER: process_csi_stop_levl_locked
 *
 * Poisoned around the call:
 *   - the wifi_ctrl_t stand-in (lcs_ctrl_buf) past sizeof(wifi_ctrl_t);
 *   - the levl and csi wifi_app stand-ins (lcs_app_buf / lcs_csi_buf) past
 *     sizeof(struct wifi_app).
 * mac_str (18 bytes) is an internal stack array guarded by ASan redzones; the
 * sounding entries are heap blocks (a use after free of the iterator or the
 * moved entry would be reported) and the pending keys are strdup'd.
 *
 * PASS = return value, stop / publish / cancel counts and the number of
 * entries left in the current map / moved to the pending map match the case;
 * pending keys equal the MAC strings and the entries have sched id cleared.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int process_csi_stop_levl_locked(wifi_app_t *app);

int test_process_csi_stop_levl_locked(const lv_lcs_test_case_t *tc)
{
    wifi_app_t *app = tc->null_app ? NULL : (wifi_app_t *)lcs_app_buf;

    /* POISON */
    __asan_poison_memory_region(&lcs_ctrl_buf[sizeof(wifi_ctrl_t)], LCS_PAD);
    __asan_poison_memory_region(&lcs_app_buf[sizeof(struct wifi_app)], LCS_PAD);
    __asan_poison_memory_region(&lcs_csi_buf[sizeof(struct wifi_app)], LCS_PAD);

    int ret = process_csi_stop_levl_locked(app);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lcs_csi_buf[sizeof(struct wifi_app)], LCS_PAD);
    __asan_unpoison_memory_region(&lcs_app_buf[sizeof(struct wifi_app)], LCS_PAD);
    __asan_unpoison_memory_region(&lcs_ctrl_buf[sizeof(wifi_ctrl_t)], LCS_PAD);

    int curr = lcs_curr_count(), pend = lcs_pend_count(), pok = lcs_pend_ok();
    lcs_set_entries(0, 0);                 /* free anything left (also pending keys/values) */
    int ok = (ret == tc->want_ret) && (lcs_stop_calls == tc->want_stop) && (lcs_pub_calls == tc->want_pub) &&
             (lcs_cancel_calls == tc->want_cancel) && (lcs_freearg_calls == tc->want_cancel) &&
             (curr == tc->want_curr) && (pend == tc->want_pend) && pok;
    if (tc->want_cancel) ok = ok && lcs_cancel_id == tc->sched_id;
    printf("    ret=%d (want %d) stop=%d pub=%d cancel=%d curr_left=%d pend=%d pend_ok=%d\n", ret, tc->want_ret,
           lcs_stop_calls, lcs_pub_calls, lcs_cancel_calls, curr, pend, pok);
    return ok;
}

void run_all_tests_process_csi_stop_levl_locked(void)
{
    for (int i = 0; process_csi_stop_levl_locked_suite[i].test_name != NULL; i++) {
        lv_lcs_test_case_t *test = &process_csi_stop_levl_locked_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_csi_stop_levl_locked_input(test);
        int pass = test_process_csi_stop_levl_locked(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
