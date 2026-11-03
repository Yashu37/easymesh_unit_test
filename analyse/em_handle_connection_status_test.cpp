/*
 * TEST RUNNER: em_handle_connection_status
 *
 * Poisoned around the call:
 *   - the caller's conn_status (ehcs_conn_buf): bytes past sizeof(em_connection_status_event_t).
 * sta_mac_str[18] and bssid_str[18] are internal stack arrays guarded by ASan
 * redzones; the published payload is a sized heap allocation (freed by the
 * handler).
 *
 * PASS = return code matches, and on success the published event is
 * WIFI_EM_REPORT_CONNECTION_STATUS with a payload length of
 * sizeof(em_connection_status_event_t).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_handle_connection_status(wifi_app_t *app, void *data);

int test_em_handle_connection_status(const em_ehcs_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&ehcs_conn_buf[sizeof(em_connection_status_event_t)], EHCS_PAD);

    wifi_app_t *app = tc->app_null ? NULL : (wifi_app_t *)ehcs_app_buf;
    void *data = tc->conn_null ? NULL : (void *)ehcs_conn_buf;
    int ret = em_handle_connection_status(app, data);

    /* UNPOISON */
    __asan_unpoison_memory_region(&ehcs_conn_buf[sizeof(em_connection_status_event_t)], EHCS_PAD);

    int ok = (ret == tc->want_ret);
    if (ok && tc->want_ret == 0)
        ok = (ehcs_publish_calls == 1) &&
             (strcmp(ehcs_published_event, "Device.WiFi.EM.ConnectionStatus") == 0) &&
             (ehcs_last_len == (int)sizeof(em_connection_status_event_t));
    printf("    ret=%d publish_calls=%d event=\"%s\" len=%d (want %d)\n", ret, ehcs_publish_calls,
           ehcs_published_event, ehcs_last_len, tc->want_ret);
    return ok;
}

void run_all_tests_em_handle_connection_status(void)
{
    for (int i = 0; em_handle_connection_status_suite[i].test_name != NULL; i++) {
        em_ehcs_test_case_t *test = &em_handle_connection_status_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_handle_connection_status_input(test);
        int pass = test_em_handle_connection_status(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
