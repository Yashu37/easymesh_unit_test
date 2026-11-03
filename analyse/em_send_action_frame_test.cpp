/*
 * TEST RUNNER: em_send_action_frame
 *
 * Poisoned around the call:
 *   - the caller's query (esaf_query_buf): bytes past sizeof(beacon_query_params_t);
 *   - the wifi_mgr stand-in (esaf_mgr_buf): bytes past sizeof(wifi_mgr_t).
 * country[8], client_mac[32], bssid_str[32] are internal stack arrays guarded
 * by ASan redzones.
 *
 * PASS = return code matches (0 when the bssid/MLD resolves + radio/country OK
 * + HAL send OK; RETURN_ERR on no-match / NULL radio / country failure / send
 * failure).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_send_action_frame(void *data);

int test_em_send_action_frame(const em_esaf_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&esaf_query_buf[sizeof(beacon_query_params_t)], ESAF_PAD);
    __asan_poison_memory_region(&esaf_mgr_buf[sizeof(wifi_mgr_t)], ESAF_PAD);

    int rc = em_send_action_frame((void *)esaf_query_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&esaf_mgr_buf[sizeof(wifi_mgr_t)], ESAF_PAD);
    __asan_unpoison_memory_region(&esaf_query_buf[sizeof(beacon_query_params_t)], ESAF_PAD);

    printf("    rc=%d send_calls=%d (want %d)\n", rc, esaf_send_calls, tc->want_rc);
    return rc == tc->want_rc;
}

void run_all_tests_em_send_action_frame(void)
{
    for (int i = 0; em_send_action_frame_suite[i].test_name != NULL; i++) {
        em_esaf_test_case_t *test = &em_send_action_frame_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_send_action_frame_input(test);
        int pass = test_em_send_action_frame(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
