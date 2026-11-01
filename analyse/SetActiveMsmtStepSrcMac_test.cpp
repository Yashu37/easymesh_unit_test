/*
 * TEST RUNNER: SetActiveMsmtStepSrcMac_test
 *
 * Poisoned around the call:
 *   - the caller's SrcMac: bytes past its NUL;
 *   - the g_active_msmt stand-in: bytes past sizeof(wifi_actvie_msmt_t).
 * bmac[6] is internal (auto-guarded by ASan).
 * PASS = cfg->Step[STEP].SrcMac holds the parsed MAC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void SetActiveMsmtStepSrcMac(char *SrcMac, unsigned long StepIns);

int test_SetActiveMsmtStepSrcMac(const SetActiveMsmtStepSrcMac_test_case_t *tc)
{
    size_t slen = strlen(ssm_src_buf) + 1;

    /* POISON */
    __asan_poison_memory_region(&ssm_src_buf[slen], 64 + SSM_PAD - slen);             /* SrcMac past NUL */
    __asan_poison_memory_region(&ssm_mgr_buf[sizeof(wifi_actvie_msmt_t)], SSM_PAD);   /* g_active_msmt   */

    SetActiveMsmtStepSrcMac(ssm_src_buf, 5);

    /* UNPOISON */
    __asan_unpoison_memory_region(&ssm_mgr_buf[sizeof(wifi_actvie_msmt_t)], SSM_PAD);
    __asan_unpoison_memory_region(&ssm_src_buf[slen], 64 + SSM_PAD - slen);

    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)ssm_mgr_buf;
    unsigned char *sm = g->active_msmt.Step[5].SrcMac;
    printf("    SrcMac=\"%s\" -> Step.SrcMac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           tc->src_mac, sm[0], sm[1], sm[2], sm[3], sm[4], sm[5]);
    return memcmp(sm, tc->expect_mac, 6) == 0;
}

void run_all_tests_SetActiveMsmtStepSrcMac(void)
{
    for (int i = 0; SetActiveMsmtStepSrcMac_suite[i].test_name != NULL; i++) {
        SetActiveMsmtStepSrcMac_test_case_t *test = &SetActiveMsmtStepSrcMac_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_SetActiveMsmtStepSrcMac_input(test);
        int pass = test_SetActiveMsmtStepSrcMac(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
