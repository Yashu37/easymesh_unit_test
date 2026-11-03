/*
 * TEST RUNNER: em_handle_failed_connection
 *
 * Poisoned around the call:
 *   - the caller's arg (hfc_arg_buf): bytes past sizeof(sta_fail_data_t).
 * sd, fc, sta_str[18] and bss_str[18] are internal stack objects guarded by
 * ASan redzones.
 *
 * PASS = return code matches the path (RETURN_OK for the publish path,
 * RETURN_ERR for NULL arg / missing vap / publish failure).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_handle_failed_connection(wifi_app_t *app, void *arg);

int test_em_handle_failed_connection(const em_hfc_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&hfc_arg_buf[sizeof(sta_fail_data_t)], HFC_PAD);

    void *arg = tc->arg_null ? NULL : (void *)hfc_arg_buf;
    int ret = em_handle_failed_connection((wifi_app_t *)0x1, arg);

    /* UNPOISON */
    __asan_unpoison_memory_region(&hfc_arg_buf[sizeof(sta_fail_data_t)], HFC_PAD);

    printf("    ret=%d publish_calls=%d (want %d)\n", ret, hfc_publish_calls, tc->want_ret);
    return ret == tc->want_ret;
}

void run_all_tests_em_handle_failed_connection(void)
{
    for (int i = 0; em_handle_failed_connection_suite[i].test_name != NULL; i++) {
        em_hfc_test_case_t *test = &em_handle_failed_connection_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_handle_failed_connection_input(test);
        int pass = test_em_handle_failed_connection(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
