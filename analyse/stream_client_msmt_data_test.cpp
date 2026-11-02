/*
 * TEST RUNNER: stream_client_msmt_data_test
 *
 * Poisoned around the call:
 *   - the act_monitor / wifi_ctrl stand-ins past their sizes;
 *   - the sta_key write slot scm_slot_key past 18 (= STA_KEY_LEN).
 * sta_key is internal (auto-guarded by ASan).
 * PASS = the right branch ran (upload for gw, pod for ext, neither on the
 * early-return paths) and, when a key is built, it is 17 chars lower-case.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void stream_client_msmt_data(bool ActiveMsmtFlag);

int test_stream_client_msmt_data(const stream_client_msmt_data_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&scm_mgr_buf[sizeof(wifi_actvie_msmt_t)], SCM_PAD);
    __asan_poison_memory_region(&scm_wctrl_buf[sizeof(wifi_ctrl_t)], SCM_PAD);
    __asan_poison_memory_region(&scm_slot_key[SCM_KEY_SZ], SCM_PAD);   /* sta_key[18] */

    stream_client_msmt_data(tc->flag ? true : false);

    /* UNPOISON */
    __asan_unpoison_memory_region(&scm_slot_key[SCM_KEY_SZ], SCM_PAD);
    __asan_unpoison_memory_region(&scm_wctrl_buf[sizeof(wifi_ctrl_t)], SCM_PAD);
    __asan_unpoison_memory_region(&scm_mgr_buf[sizeof(wifi_actvie_msmt_t)], SCM_PAD);

    int key_ok = 1;
    if (scm_key_len) {
        key_ok = (scm_key_len == 17);
        for (const char *p = scm_key_seen; *p; p++) if (*p >= 'A' && *p <= 'F') key_ok = 0;
    }
    printf("    flag=%d upload=%d pod=%d key_len=%zu key=\"%s\"\n",
           tc->flag, scm_upload_calls, scm_pod_calls, scm_key_len, scm_key_seen);
    return scm_upload_calls == tc->expect_up && scm_pod_calls == tc->expect_pod && key_ok;
}

void run_all_tests_stream_client_msmt_data(void)
{
    for (int i = 0; stream_client_msmt_data_suite[i].test_name != NULL; i++) {
        stream_client_msmt_data_test_case_t *test = &stream_client_msmt_data_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_stream_client_msmt_data_input(test);
        int pass = test_stream_client_msmt_data(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected up=%d pod=%d) =====\n", test->test_name, test->expect_up, test->expect_pod);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
