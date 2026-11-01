/*
 * TEST RUNNER: SetActiveMsmtStepDstMac_test
 *
 * Poisoned around the call:
 *   - the caller's DstMac: bytes past its NUL;
 *   - the g_active_msmt stand-in: bytes past sizeof(wifi_actvie_msmt_t);
 *   - the wifi_mgr stand-in: bytes past sizeof(wifi_mgr_t);
 *   - the msg snprintf slot sad_slot past 256 (= sizeof(msg)).
 * bmac[6] and msg[256] are internal (auto-guarded by ASan).
 * PASS = the chosen branch ran (report_error for ext / diagnostics for gw)
 * and cfg->Step[STEP].DestMac holds the parsed MAC (or stays 0 when the
 * step was invalid).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void SetActiveMsmtStepDstMac(char *DstMac, unsigned long StepIns);

int test_SetActiveMsmtStepDstMac(const SetActiveMsmtStepDstMac_test_case_t *tc)
{
    size_t dlen = strlen(sad_dst_buf) + 1;

    /* POISON */
    __asan_poison_memory_region(&sad_dst_buf[dlen], 64 + SAD_PAD - dlen);             /* DstMac past NUL */
    __asan_poison_memory_region(&sad_mgr_buf[sizeof(wifi_actvie_msmt_t)], SAD_PAD);   /* g_active_msmt   */
    __asan_poison_memory_region(&sad_wmgr_buf[sizeof(wifi_mgr_t)], SAD_PAD);          /* wifi_mgr        */
    __asan_poison_memory_region(&sad_slot[SAD_SLOT_SZ], SAD_PAD);                     /* msg[256]        */

    SetActiveMsmtStepDstMac(sad_dst_buf, 5);

    /* UNPOISON */
    __asan_unpoison_memory_region(&sad_slot[SAD_SLOT_SZ], SAD_PAD);
    __asan_unpoison_memory_region(&sad_wmgr_buf[sizeof(wifi_mgr_t)], SAD_PAD);
    __asan_unpoison_memory_region(&sad_mgr_buf[sizeof(wifi_actvie_msmt_t)], SAD_PAD);
    __asan_unpoison_memory_region(&sad_dst_buf[dlen], 64 + SAD_PAD - dlen);

    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)sad_mgr_buf;
    unsigned char *dm = g->active_msmt.Step[5].DestMac;
    int mac_ok = memcmp(dm, tc->expect_mac, 6) == 0;

    int branch_ok;
    if (tc->invalid)        branch_ok = (sad_report_err == 0 && sad_diag_calls == 0);
    else if (tc->ext_mode)  branch_ok = (sad_report_err == 1 && sad_diag_calls == 0 && strstr(sad_last_err, "Failed to find MAC") != NULL);
    else                    branch_ok = (sad_report_err == 0 && sad_diag_calls == 1);

    printf("    DstMac=\"%s\" -> DestMac=%02x:%02x:%02x:%02x:%02x:%02x report_err=%d diag=%d msg_len=%zu\n",
           tc->dst_mac, dm[0], dm[1], dm[2], dm[3], dm[4], dm[5], sad_report_err, sad_diag_calls, sad_msg_len);
    return mac_ok && branch_ok && sad_msg_len < SAD_SLOT_SZ;
}

void run_all_tests_SetActiveMsmtStepDstMac(void)
{
    for (int i = 0; SetActiveMsmtStepDstMac_suite[i].test_name != NULL; i++) {
        SetActiveMsmtStepDstMac_test_case_t *test = &SetActiveMsmtStepDstMac_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_SetActiveMsmtStepDstMac_input(test);
        int pass = test_SetActiveMsmtStepDstMac(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
