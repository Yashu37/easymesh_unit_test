/*
 * TEST RUNNER: process_instant_msmt_start
 *
 * Poisoned around the call:
 *   - pist_sink tail past 16 bytes: the ctrl-queue stub copies the pushed event
 *     bytes here, so an event longer than event_buff[16] would trip.
 * event_buff[16] is an internal stack array guarded by ASan redzones; the
 * wifi_monitor_data_t allocation is heap (freed by the handler).
 *
 * PASS = the ctrl-queue push happened once with "inst_msmt start" (len 16),
 * maxCount matches TTL/poll, and inst_msmt_id was incremented.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void process_instant_msmt_start(void);

int test_process_instant_msmt_start(const em_pist_test_case_t *tc)
{
    /* POISON the sink tail past the 16-byte event_buff size */
    __asan_poison_memory_region(&pist_sink[16], PIST_SINK_SZ - 16);

    process_instant_msmt_start();

    /* UNPOISON */
    __asan_unpoison_memory_region(&pist_sink[16], PIST_SINK_SZ - 16);

    int ok = (pist_ctrl_push == 1) &&
             (strcmp(pist_sink, "inst_msmt start") == 0) && (pist_ctrl_len == 16) &&
             (g_harvester_module.maxCount == tc->want_maxcount) &&
             (g_harvester_module.inst_msmt_id == 1);
    printf("    ctrl_push=%d len=%d sink=\"%s\" maxCount=%d id=%d (want_maxcount %d)\n",
           pist_ctrl_push, pist_ctrl_len, pist_sink, g_harvester_module.maxCount,
           g_harvester_module.inst_msmt_id, tc->want_maxcount);
    return ok;
}

void run_all_tests_process_instant_msmt_start(void)
{
    for (int i = 0; process_instant_msmt_start_suite[i].test_name != NULL; i++) {
        em_pist_test_case_t *test = &process_instant_msmt_start_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_instant_msmt_start_input(test);
        int pass = test_process_instant_msmt_start(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
