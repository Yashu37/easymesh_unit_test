/*
 * TEST RUNNER: process_instant_msmt_stop
 *
 * Poisoned around the call:
 *   - pims_sink tail past 16 bytes: the ctrl-queue stub copies the pushed
 *     event bytes here, so an event longer than event_buff[16] would trip.
 * event_buff[16] is an internal stack array guarded by ASan redzones; the
 * wifi_monitor_data_t allocation and radio_data are heap (freed by the handler
 * on the active path; the runner frees any left on the inactive path).
 *
 * PASS = the ctrl-queue push happened the expected number of times, and on the
 * active path the pushed event is "inst_msmt compl" (15 chars) with len 16.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void process_instant_msmt_stop(void);

int test_process_instant_msmt_stop(const em_pims_test_case_t *tc)
{
    /* POISON the sink tail past the 16-byte event_buff size */
    __asan_poison_memory_region(&pims_sink[16], PIMS_PAD);

    process_instant_msmt_stop();

    /* UNPOISON */
    __asan_unpoison_memory_region(&pims_sink[16], PIMS_PAD);

    /* inactive path doesn't free radio_data -> free here to avoid a leak */
    for (int r = 0; r < pims_num_radios; r++) { if (g_harvester_module.radio_data[r]) { free(g_harvester_module.radio_data[r]); g_harvester_module.radio_data[r] = NULL; } }

    int ok = (pims_ctrl_push == tc->want_ctrl_push);
    if (ok && tc->want_ctrl_push == 1)
        ok = (strcmp(pims_sink, "inst_msmt compl") == 0) && (pims_ctrl_len == 16);
    printf("    ctrl_push=%d len=%d sink=\"%s\" (want_push %d)\n", pims_ctrl_push, pims_ctrl_len,
           pims_sink, tc->want_ctrl_push);
    return ok;
}

void run_all_tests_process_instant_msmt_stop(void)
{
    for (int i = 0; process_instant_msmt_stop_suite[i].test_name != NULL; i++) {
        em_pims_test_case_t *test = &process_instant_msmt_stop_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_process_instant_msmt_stop_input(test);
        int pass = test_process_instant_msmt_stop(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
