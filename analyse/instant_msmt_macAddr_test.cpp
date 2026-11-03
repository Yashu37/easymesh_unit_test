/*
 * TEST RUNNER: instant_msmt_macAddr
 *
 * Poisoned around the call:
 *   - the caller's mac string buffer (iam_mac_buf): bytes past its NUL up to
 *     IAM_MAC_SZ;
 *   - the wifi_mgr stand-in (iam_mgr_buf): bytes past sizeof(wifi_mgr_t).
 * bmac (mac_address_t) is an internal stack array guarded by ASan redzones;
 * instantMac is a fixed char[32] written with a 12-byte strncpy.
 *
 * PASS = ap_index / sta_mac recorded only when the stub reports the client
 * associated on a VAP.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void instant_msmt_macAddr(char *mac_addr);

int test_instant_msmt_macAddr(const harv_iam_test_case_t *tc)
{
    size_t len = strlen(iam_mac_buf);

    /* POISON */
    __asan_poison_memory_region(&iam_mac_buf[len + 1], IAM_MAC_SZ - (len + 1));
    __asan_poison_memory_region(&iam_mgr_buf[sizeof(wifi_mgr_t)], IAM_PAD);

    instant_msmt_macAddr(iam_mac_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&iam_mgr_buf[sizeof(wifi_mgr_t)], IAM_PAD);
    __asan_unpoison_memory_region(&iam_mac_buf[len + 1], IAM_MAC_SZ - (len + 1));

    int ok = (g_harvester_module.inst_msmt.ap_index == tc->want_ap);
    if (tc->want_found)
        ok = ok && memcmp(g_harvester_module.inst_msmt.sta_mac, tc->want_mac, 6) == 0;
    else
        ok = ok && g_harvester_module.inst_msmt.sta_mac[0] == 0;
    printf("    ap_index=%d (want %d) assoc_checks=%d instantMac=\"%.12s\"\n",
           g_harvester_module.inst_msmt.ap_index, tc->want_ap, iam_assoc_checks,
           g_harvester_module.instantMac);
    return ok;
}

void run_all_tests_instant_msmt_macAddr(void)
{
    for (int i = 0; instant_msmt_macAddr_suite[i].test_name != NULL; i++) {
        harv_iam_test_case_t *test = &instant_msmt_macAddr_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_instant_msmt_macAddr_input(test);
        int pass = test_instant_msmt_macAddr(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
