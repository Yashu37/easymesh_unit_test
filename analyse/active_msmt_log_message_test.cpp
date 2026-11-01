/*
 * TEST RUNNER: active_msmt_log_message_test
 *
 * Poisoned around the call:
 *   - the caller's string argument aml_arg_buf: bytes past strlen+1;
 *   - the wifi_mgr_t stand-in aml_mgr_buf: bytes past sizeof(wifi_mgr_t);
 *   - the msg vsnprintf slot aml_slot past 1024 (= sizeof(msg)).
 * msg[1024] is internal (auto-guarded by ASan).
 * PASS = the trace hook fired as expected and the recorded message matches.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void active_msmt_log_message(blaster_log_level_t level, char *fmt, ...);

int test_active_msmt_log_message(const active_msmt_log_message_test_case_t *tc)
{
    size_t alen = strlen(aml_arg_buf) + 1;

    /* POISON */
    __asan_poison_memory_region(&aml_arg_buf[alen], AML_ARG_MAX + AML_PAD - alen);   /* arg past NUL */
    __asan_poison_memory_region(&aml_mgr_buf[sizeof(wifi_mgr_t)], AML_PAD);          /* wifi_mgr     */
    __asan_poison_memory_region(&aml_slot[AML_SLOT_SZ], AML_PAD);                    /* msg[1024]    */

    active_msmt_log_message(aml_levels[tc->level_idx],
        (char *)"%s:%d no need to start pktgen for offline client: %s\n",
        "SetActiveMsmtStepSrcMac", 873, aml_arg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&aml_slot[AML_SLOT_SZ], AML_PAD);
    __asan_unpoison_memory_region(&aml_mgr_buf[sizeof(wifi_mgr_t)], AML_PAD);
    __asan_unpoison_memory_region(&aml_arg_buf[alen], AML_ARG_MAX + AML_PAD - alen);

    int contains = tc->expect_contains[0] == 0 ? 1 :
                   (strncmp(aml_trace_out, tc->expect_contains, strlen(tc->expect_contains)) == 0);
    printf("    level_idx=%d trace_calls=%d msg_len=%zu trace=\"%.80s\"\n",
           tc->level_idx, aml_trace_calls, aml_msg_len, aml_trace_out);
    return aml_trace_calls == tc->expect_trace && contains && aml_msg_len < AML_SLOT_SZ;
}

void run_all_tests_active_msmt_log_message(void)
{
    for (int i = 0; active_msmt_log_message_suite[i].test_name != NULL; i++) {
        active_msmt_log_message_test_case_t *test = &active_msmt_log_message_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_active_msmt_log_message_input(test);
        int pass = test_active_msmt_log_message(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected trace=%d) =====\n", test->test_name, test->expect_trace);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
