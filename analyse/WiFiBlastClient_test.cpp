/*
 * TEST RUNNER: WiFiBlastClient_test
 *
 * WiFiBlastClient takes no arguments; it pulls its state from the stand-ins
 * returned by the stubbed get_* helpers. Poisoned around the call:
 *   - the g_active_msmt / wifi_mgr / wifi_ctrl / wifi_app stand-ins past
 *     their sizes;
 *   - the macStr slot past 18 and the msg slot past 256.
 * macStr[18] / msg[256] / bmac[6] are internal (auto-guarded by ASan).
 * PASS = the chosen branch ran (report_error for ext, diagnostics for gw,
 * neither for the app-NULL early return) and msg stayed < 256.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void WiFiBlastClient(void);

int test_WiFiBlastClient(const WiFiBlastClient_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&wbc_mgr_buf[sizeof(wifi_actvie_msmt_t)], WBC_PAD);
    __asan_poison_memory_region(&wbc_wmgr_buf[sizeof(wifi_mgr_t)], WBC_PAD);
    __asan_poison_memory_region(&wbc_wctrl_buf[sizeof(wifi_ctrl_t)], WBC_PAD);
    __asan_poison_memory_region(&wbc_app_buf[sizeof(wifi_app_t)], WBC_PAD);
    __asan_poison_memory_region(&wbc_slot_mac[WBC_MAC_SZ], WBC_PAD);   /* macStr[18] */
    __asan_poison_memory_region(&wbc_slot_msg[WBC_MSG_SZ], WBC_PAD);   /* msg[256]   */

    WiFiBlastClient();

    /* UNPOISON */
    __asan_unpoison_memory_region(&wbc_slot_msg[WBC_MSG_SZ], WBC_PAD);
    __asan_unpoison_memory_region(&wbc_slot_mac[WBC_MAC_SZ], WBC_PAD);
    __asan_unpoison_memory_region(&wbc_app_buf[sizeof(wifi_app_t)], WBC_PAD);
    __asan_unpoison_memory_region(&wbc_wctrl_buf[sizeof(wifi_ctrl_t)], WBC_PAD);
    __asan_unpoison_memory_region(&wbc_wmgr_buf[sizeof(wifi_mgr_t)], WBC_PAD);
    __asan_unpoison_memory_region(&wbc_mgr_buf[sizeof(wifi_actvie_msmt_t)], WBC_PAD);

    printf("    report_err=%d diag=%d msg_len=%zu last_err=\"%.50s\"\n",
           wbc_report_err, wbc_diag_calls, wbc_msg_len, wbc_last_err);
    return wbc_report_err == tc->expect_report && wbc_diag_calls == tc->expect_diag && wbc_msg_len < WBC_MSG_SZ;
}

void run_all_tests_WiFiBlastClient(void)
{
    for (int i = 0; WiFiBlastClient_suite[i].test_name != NULL; i++) {
        WiFiBlastClient_test_case_t *test = &WiFiBlastClient_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_WiFiBlastClient_input(test);
        int pass = test_WiFiBlastClient(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected report=%d diag=%d) =====\n", test->test_name, test->expect_report, test->expect_diag);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
