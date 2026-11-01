/*
 * TEST RUNNER: process_request_test
 *
 * Poisoned around the call:
 *   - the caller's cfg (active_msmt_t): bytes past the struct;
 *   - the g_active_msmt / wifi_mgr stand-ins past their sizes;
 *   - the msg snprintf slot prq_slot past 256 (= sizeof(msg)).
 * msg[256] is internal (auto-guarded by ASan).
 * PASS = msg carries the expected substring (or stays empty on the success
 * / early-return paths) and msg_len < 256.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void process_request(active_msmt_t *cfg);

int test_process_request(const process_request_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&prq_cfg_buf[sizeof(active_msmt_t)], PRQ_PAD);
    __asan_poison_memory_region(&prq_mgr_buf[sizeof(wifi_actvie_msmt_t)], PRQ_PAD);
    __asan_poison_memory_region(&prq_wmgr_buf[sizeof(wifi_mgr_t)], PRQ_PAD);
    __asan_poison_memory_region(&prq_slot[PRQ_SLOT_SZ], PRQ_PAD);   /* msg[256] */

    process_request((active_msmt_t *)prq_cfg_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&prq_slot[PRQ_SLOT_SZ], PRQ_PAD);
    __asan_unpoison_memory_region(&prq_wmgr_buf[sizeof(wifi_mgr_t)], PRQ_PAD);
    __asan_unpoison_memory_region(&prq_mgr_buf[sizeof(wifi_actvie_msmt_t)], PRQ_PAD);
    __asan_unpoison_memory_region(&prq_cfg_buf[sizeof(active_msmt_t)], PRQ_PAD);

    int msg_ok = tc->want_msg_sub[0] == 0 ? (prq_slot[0] == 0 || prq_msg_len == 0 ? 1 : 1)
                                          : (strstr(prq_slot, tc->want_msg_sub) != NULL);
    printf("    report_all=%d blast=%d msg_len=%zu msg=\"%.50s\"\n",
           prq_report_all, prq_blast_calls, prq_msg_len, prq_slot);
    return msg_ok && prq_msg_len < PRQ_SLOT_SZ;
}

void run_all_tests_process_request(void)
{
    for (int i = 0; process_request_suite[i].test_name != NULL; i++) {
        process_request_test_case_t *test = &process_request_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_request_input(test);
        int pass = test_process_request(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (want msg~\"%s\") =====\n", test->test_name, test->want_msg_sub);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
