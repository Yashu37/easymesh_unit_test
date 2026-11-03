/*
 * TEST RUNNER: schedule_from_pending_map_locked
 *
 * Poisoned around the call:
 *   - the wifi_app stand-in (lsp_app_buf): bytes past sizeof(struct wifi_app).
 * mac_str (18 bytes) and mac_addr (6 bytes) are internal stack arrays guarded
 * by ASan redzones; pending entries are heap blocks with redzones.
 *
 * PASS = return value, schedule call count/ap index and remaining pending
 * entries match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int schedule_from_pending_map_locked(wifi_app_t *wifi_app);

int test_schedule_from_pending_map_locked(const lv_lsp_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&lsp_app_buf[sizeof(struct wifi_app)], LSP_PAD);

    int ret = schedule_from_pending_map_locked(tc->null_mode == 1 ? NULL : (wifi_app_t *)lsp_app_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lsp_app_buf[sizeof(struct wifi_app)], LSP_PAD);

    int remaining = lsp_n;
    lsp_free_entries();
    int ok = (ret == tc->want_ret) && (lsp_sched_calls == tc->want_sched) &&
             (lsp_sched_ap == tc->want_ap) && (remaining == tc->want_remaining);
    if (tc->want_sched) ok = ok && lsp_sched_dur >= 5000 && lsp_sched_mac[0] == 0x02;
    printf("    ret=%d (want %d) sched_calls=%d ap=%d (want %d) remaining=%d (want %d)\n",
           ret, tc->want_ret, lsp_sched_calls, lsp_sched_ap, tc->want_ap, remaining, tc->want_remaining);
    return ok;
}

void run_all_tests_schedule_from_pending_map_locked(void)
{
    for (int i = 0; schedule_from_pending_map_locked_suite[i].test_name != NULL; i++) {
        lv_lsp_test_case_t *test = &schedule_from_pending_map_locked_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_schedule_from_pending_map_locked_input(test);
        int pass = test_schedule_from_pending_map_locked(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
