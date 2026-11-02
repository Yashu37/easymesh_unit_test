/*
 * TEST RUNNER: printBlastMetricData_test
 *
 * Poisoned around the call:
 *   - the blaster_stats / staData / wifi_mgr / wifi_ctrl stand-ins past
 *     their sizes (the PlanId source lives inside blaster_stats, so its
 *     tail is guarded too).
 * PlanId[38] / freqBand / chanBw are internal (auto-guarded by ASan);
 * to_plan_char writes <=36 bytes into PlanId[38].
 * PASS = non-NULL path logs via CcspTraceInfo (no error), NULL path logs
 * via CcspTraceError, and nothing overflows.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void printBlastMetricData(single_client_msmt_type_t msmtType, wifi_actvie_msmt_t *blaster_stats,
                          blaster_hashmap_t *staData, bool activeClient, const char *callerFunc);

int test_printBlastMetricData(const printBlastMetricData_test_case_t *tc)
{
    blaster_hashmap_t *sd = tc->null_data ? NULL : (blaster_hashmap_t *)pbm_sd_buf;

    /* POISON */
    __asan_poison_memory_region(&pbm_bs_buf[sizeof(wifi_actvie_msmt_t)], PBM_PAD);
    __asan_poison_memory_region(&pbm_sd_buf[sizeof(blaster_hashmap_t)], PBM_PAD);
    __asan_poison_memory_region(&pbm_wmgr_buf[sizeof(wifi_mgr_t)], PBM_PAD);
    __asan_poison_memory_region(&pbm_wctrl_buf[sizeof(wifi_ctrl_t)], PBM_PAD);

    printBlastMetricData(single_client_msmt_type_one, (wifi_actvie_msmt_t *)pbm_bs_buf, sd, false, "runner");

    /* UNPOISON */
    __asan_unpoison_memory_region(&pbm_wctrl_buf[sizeof(wifi_ctrl_t)], PBM_PAD);
    __asan_unpoison_memory_region(&pbm_wmgr_buf[sizeof(wifi_mgr_t)], PBM_PAD);
    __asan_unpoison_memory_region(&pbm_sd_buf[sizeof(blaster_hashmap_t)], PBM_PAD);
    __asan_unpoison_memory_region(&pbm_bs_buf[sizeof(wifi_actvie_msmt_t)], PBM_PAD);

    printf("    info=%d debug=%d err=%d\n", pbm_info_calls, pbm_debug_calls, pbm_err_calls);
    int info_ok = tc->expect_info_ge ? (pbm_info_calls >= 1) : 1;
    int err_ok  = (pbm_err_calls > 0) == (tc->expect_err != 0);
    return info_ok && err_ok;
}

void run_all_tests_printBlastMetricData(void)
{
    for (int i = 0; printBlastMetricData_suite[i].test_name != NULL; i++) {
        printBlastMetricData_test_case_t *test = &printBlastMetricData_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_printBlastMetricData_input(test);
        int pass = test_printBlastMetricData(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
