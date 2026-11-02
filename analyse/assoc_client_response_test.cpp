/*
 * TEST RUNNER: assoc_client_response
 *
 * Poisoned around the call:
 *   - the caller's provider_response (acr_resp_buf): bytes past the struct;
 *   - the wifi_mgr stand-in (acr_mgr_buf): bytes past sizeof(wifi_mgr_t);
 *   - the TAIL of the target per-vap assoc_stats array, i.e. the threshold_hit[]
 *     bytes that sit immediately after assoc_stats[BSS_MAX_NUM_STATIONS]. A
 *     correct run never touches them (the memset clears only assoc_stats and
 *     stat_array_size is written past them); an unclamped memcpy that copies
 *     more than BSS_MAX_NUM_STATIONS entries runs straight into this poison.
 * vap_name[32] is an internal stack array (ASan redzones).
 *
 * PASS = return code matches (and no ASan report) for the non-crash cases;
 * the overflow case is expected to trip AddressSanitizer (reproducer).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int assoc_client_response(wifi_app_t *app, wifi_provider_response_t *provider_response);

int test_assoc_client_response(const em_acr_test_case_t *tc)
{
    unsigned int r = tc->radio_index, v = (unsigned int)tc->vap_array_index;
    int tail_poisoned = 0;

    /* POISON caller buffers */
    __asan_poison_memory_region(&acr_resp_buf[sizeof(wifi_provider_response_t)], ACR_PAD);
    __asan_poison_memory_region(&acr_mgr_buf[sizeof(wifi_mgr_t)], ACR_PAD);
    /* POISON the tail just past the target assoc_stats[] (only when the slot is valid) */
    if (r < MAX_NUM_RADIOS && tc->vap_array_index >= 0 && v < MAX_NUM_VAP_PER_RADIO) {
        __asan_poison_memory_region(client_assoc_stats[r].client_assoc_data[v].threshold_hit,
            sizeof(client_assoc_stats[r].client_assoc_data[v].threshold_hit));
        tail_poisoned = 1;
    }

    int ret = assoc_client_response((wifi_app_t *)0x1, (wifi_provider_response_t *)acr_resp_buf);

    /* UNPOISON */
    if (tail_poisoned)
        __asan_unpoison_memory_region(client_assoc_stats[r].client_assoc_data[v].threshold_hit,
            sizeof(client_assoc_stats[r].client_assoc_data[v].threshold_hit));
    __asan_unpoison_memory_region(&acr_mgr_buf[sizeof(wifi_mgr_t)], ACR_PAD);
    __asan_unpoison_memory_region(&acr_resp_buf[sizeof(wifi_provider_response_t)], ACR_PAD);

    printf("    ret=%d ready_calls=%d (want %d)\n", ret, acr_ready_calls, tc->want_ret);
    return ret == tc->want_ret;
}

void run_all_tests_assoc_client_response(void)
{
    for (int i = 0; assoc_client_response_suite[i].test_name != NULL; i++) {
        em_acr_test_case_t *test = &assoc_client_response_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_assoc_client_response_input(test);
        int pass = test_assoc_client_response(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
