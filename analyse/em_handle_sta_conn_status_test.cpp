/*
 * TEST RUNNER: em_handle_sta_conn_status
 *
 * Poisoned around the call:
 *   - the caller's sta_data (hscs_data_buf): bytes past sizeof(rdk_sta_data_t);
 *   - the wifi_ctrl stand-in (hscs_ctrl_buf): bytes past sizeof(wifi_ctrl_t).
 * path[256] is an internal stack array guarded by ASan redzones; the published
 * payload is a sized heap allocation (freed by the handler).
 *
 * PASS (success): publish was called once with event WIFI_EM_ASSOCIATION_STATUS
 * and a payload length of sizeof(rdk_sta_data_t) -- confirming path is written
 * within its 256-byte bound. (The success path has no return value, so ret is
 * not checked there.)
 * PASS (null_data): ret == RETURN_ERR.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_handle_sta_conn_status(wifi_app_t *app, void *data);

int test_em_handle_sta_conn_status(const em_hscs_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&hscs_data_buf[sizeof(rdk_sta_data_t)], HSCS_PAD);
    __asan_poison_memory_region(&hscs_ctrl_buf[sizeof(wifi_ctrl_t)], HSCS_PAD);

    void *data = tc->data_null ? NULL : (void *)hscs_data_buf;
    int ret = em_handle_sta_conn_status((wifi_app_t *)0x1, data);

    /* UNPOISON */
    __asan_unpoison_memory_region(&hscs_ctrl_buf[sizeof(wifi_ctrl_t)], HSCS_PAD);
    __asan_unpoison_memory_region(&hscs_data_buf[sizeof(rdk_sta_data_t)], HSCS_PAD);

    int ok;
    if (tc->data_null) {
        ok = (ret == tc->want_ret);
        printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    } else {
        ok = (hscs_publish_calls == 1) &&
             (strcmp(hscs_published_event, "Device.WiFi.EM.AssociationStatus") == 0) &&
             (hscs_last_len == (int)sizeof(rdk_sta_data_t));
        printf("    publish_calls=%d event=\"%s\" len=%d (want len %zu)\n",
               hscs_publish_calls, hscs_published_event, hscs_last_len, sizeof(rdk_sta_data_t));
    }
    return ok;
}

void run_all_tests_em_handle_sta_conn_status(void)
{
    for (int i = 0; em_handle_sta_conn_status_suite[i].test_name != NULL; i++) {
        em_hscs_test_case_t *test = &em_handle_sta_conn_status_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_handle_sta_conn_status_input(test);
        int pass = test_em_handle_sta_conn_status(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
