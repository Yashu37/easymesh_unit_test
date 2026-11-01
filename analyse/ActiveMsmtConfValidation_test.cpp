/*
 * TEST RUNNER: ActiveMsmtConfValidation_test
 *
 * Poisoned around the call:
 *   - the caller's cfg (active_msmt_t): bytes past the struct;
 *   - the msg snprintf slot amc_slot past 256 (= sizeof(msg)).
 * msg[256] is internal (auto-guarded by ASan).
 * PASS = return value matches and the recorded error message contains the
 * expected substring.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int ActiveMsmtConfValidation(active_msmt_t *cfg);

int test_ActiveMsmtConfValidation(const ActiveMsmtConfValidation_test_case_t *tc)
{
    active_msmt_t *cfg = (tc->kind == AMC_NULL) ? NULL : (active_msmt_t *)amc_cfg_buf;

    /* POISON */
    __asan_poison_memory_region(&amc_cfg_buf[sizeof(active_msmt_t)], AMC_PAD);   /* cfg struct */
    __asan_poison_memory_region(&amc_slot[AMC_SLOT_SZ], AMC_PAD);                /* msg[256]   */

    int ret = ActiveMsmtConfValidation(cfg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&amc_slot[AMC_SLOT_SZ], AMC_PAD);
    __asan_unpoison_memory_region(&amc_cfg_buf[sizeof(active_msmt_t)], AMC_PAD);

    int err_ok = tc->expect_err_sub[0] == 0 ? 1 : (strstr(amc_last_err, tc->expect_err_sub) != NULL);
    printf("    kind=%d -> ret=%d msg_len=%zu report_err=%d report_all=%d last_err=\"%.60s\"\n",
           tc->kind, ret, amc_msg_len, amc_report_err, amc_report_all, amc_last_err);
    return ret == tc->expect_ret && err_ok && amc_msg_len < AMC_SLOT_SZ;
}

void run_all_tests_ActiveMsmtConfValidation(void)
{
    for (int i = 0; ActiveMsmtConfValidation_suite[i].test_name != NULL; i++) {
        ActiveMsmtConfValidation_test_case_t *test = &ActiveMsmtConfValidation_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_ActiveMsmtConfValidation_input(test);
        int pass = test_ActiveMsmtConfValidation(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d err~\"%s\") =====\n", test->test_name, test->expect_ret, test->expect_err_sub);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
