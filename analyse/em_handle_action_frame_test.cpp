/*
 * TEST RUNNER: em_handle_action_frame
 *
 * Poisoned around the call:
 *   - the caller's frame_data_t (ehaf_arg_buf): bytes past the struct;
 *   - the wifi_ctrl stand-in (ehaf_ctrl_buf): bytes past sizeof(wifi_ctrl_t).
 * rep and mac_addr[6] are internal stack objects guarded by ASan redzones.
 *
 * PASS = return code matches and em_process_beacon_rep was invoked the expected
 * number of times (action/mode/parse gating; mac_addr copy stays in bounds).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_handle_action_frame(wifi_app_t *apps, void *arg);

int test_em_handle_action_frame(const em_ehaf_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&ehaf_arg_buf[sizeof(frame_data_t)], EHAF_PAD);
    __asan_poison_memory_region(&ehaf_ctrl_buf[sizeof(wifi_ctrl_t)], EHAF_PAD);

    void *arg = tc->arg_null ? NULL : (void *)ehaf_arg_buf;
    int rc = em_handle_action_frame((wifi_app_t *)0x1, arg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&ehaf_ctrl_buf[sizeof(wifi_ctrl_t)], EHAF_PAD);
    __asan_unpoison_memory_region(&ehaf_arg_buf[sizeof(frame_data_t)], EHAF_PAD);

    int ok = (rc == tc->want_rc) && (ehaf_process_calls == tc->want_proc);
    printf("    rc=%d process_calls=%d (want %d/%d)\n", rc, ehaf_process_calls, tc->want_rc, tc->want_proc);
    return ok;
}

void run_all_tests_em_handle_action_frame(void)
{
    for (int i = 0; em_handle_action_frame_suite[i].test_name != NULL; i++) {
        em_ehaf_test_case_t *test = &em_handle_action_frame_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_handle_action_frame_input(test);
        int pass = test_em_handle_action_frame(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
