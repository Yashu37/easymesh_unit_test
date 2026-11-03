/*
 * TEST RUNNER: em_publish_failed_connection
 *
 * Poisoned around the call:
 *   - the caller's fc (pfc_fc_buf): bytes past sizeof(wifi_em_failed_conn_t);
 *   - the wifi_ctrl stand-in (pfc_ctrl_buf): bytes past sizeof(wifi_ctrl_t).
 * bssid_str/sta_str (char[18]) and json_buf[128] are internal stack arrays
 * guarded by ASan redzones.
 *
 * PASS = return code matches, and on success the published JSON is the
 * expected string (confirming json_buf is written within its 128-byte bound).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_publish_failed_connection(const wifi_em_failed_conn_t *fc);

int test_em_publish_failed_connection(const em_pfc_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&pfc_fc_buf[sizeof(wifi_em_failed_conn_t)], PFC_PAD);
    __asan_poison_memory_region(&pfc_ctrl_buf[sizeof(wifi_ctrl_t)], PFC_PAD);

    int ret = em_publish_failed_connection((const wifi_em_failed_conn_t *)pfc_fc_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&pfc_ctrl_buf[sizeof(wifi_ctrl_t)], PFC_PAD);
    __asan_unpoison_memory_region(&pfc_fc_buf[sizeof(wifi_em_failed_conn_t)], PFC_PAD);

    int ok = (ret == tc->want_ret);
    if (ok && tc->want_ret == 0)
        ok = (strcmp(pfc_published_json,
                     "{\"bssid\":\"10:11:12:13:14:15\",\"sta_mac\":\"20:21:22:23:24:25\",\"status\":1,\"reason\":7}") == 0);
    printf("    ret=%d calls=%d json=\"%s\" (want %d)\n", ret, pfc_publish_calls, pfc_published_json, tc->want_ret);
    return ok;
}

void run_all_tests_em_publish_failed_connection(void)
{
    for (int i = 0; em_publish_failed_connection_suite[i].test_name != NULL; i++) {
        em_pfc_test_case_t *test = &em_publish_failed_connection_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_publish_failed_connection_input(test);
        int pass = test_em_publish_failed_connection(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
