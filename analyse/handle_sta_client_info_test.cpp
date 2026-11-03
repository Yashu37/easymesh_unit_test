/*
 * TEST RUNNER: handle_sta_client_info
 *
 * Poisoned around the call:
 *   - the caller's sta_info (hsci_sta_buf): bytes past sizeof(sta_client_info_t).
 * client_mac[32] is an internal stack array guarded by ASan redzones; the
 * cache entry is a heap allocation (freed by the store reset).
 *
 * PASS = return code matches the path (RETURN_OK for the map-miss insert and
 * the existing-entry refresh, RETURN_ERR for NULL input), and on OK the stored
 * entry carries client_type "Smartphone".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int handle_sta_client_info(wifi_app_t *app, void *data);

int test_handle_sta_client_info(const em_hsci_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&hsci_sta_buf[sizeof(sta_client_info_t)], HSCI_PAD);

    void *data = tc->sta_null ? NULL : (void *)hsci_sta_buf;
    int ret = handle_sta_client_info((wifi_app_t *)0x1, data);

    /* UNPOISON */
    __asan_unpoison_memory_region(&hsci_sta_buf[sizeof(sta_client_info_t)], HSCI_PAD);

    int ok = (ret == tc->want_ret);
    if (ok && tc->want_ret == 0) {
        sta_client_info_t *stored = (sta_client_info_t *)hsci_store_get();
        ok = stored && (strcmp((char *)stored->client_type, "Smartphone") == 0);
    }
    printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    return ok;
}

void run_all_tests_handle_sta_client_info(void)
{
    for (int i = 0; handle_sta_client_info_suite[i].test_name != NULL; i++) {
        em_hsci_test_case_t *test = &handle_sta_client_info_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_handle_sta_client_info_input(test);
        int pass = test_handle_sta_client_info(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    hsci_store_reset();
}
