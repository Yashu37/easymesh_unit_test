/*
 * TEST RUNNER: monitor_enable_instant_msmt
 *
 * Poisoned around the call:
 *   - the caller's query MAC (men_mac_buf): bytes past the 6-byte mac;
 *   - the wifi_mgr stand-in (men_mgr_buf): bytes past sizeof(wifi_mgr_t).
 * sta (char[18]) is an internal stack array guarded by ASan redzones.
 *
 * PASS = the start/stop stubs were invoked the expected number of times for
 * the active/enable/match + found-vap combination.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void monitor_enable_instant_msmt(mac_address_t sta_mac, bool enable);

int test_monitor_enable_instant_msmt(const em_men_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&men_mac_buf[6], MEN_PAD);
    __asan_poison_memory_region(&men_mgr_buf[sizeof(wifi_mgr_t)], MEN_PAD);

    monitor_enable_instant_msmt((unsigned char *)men_mac_buf, tc->enable ? true : false);

    /* UNPOISON */
    __asan_unpoison_memory_region(&men_mgr_buf[sizeof(wifi_mgr_t)], MEN_PAD);
    __asan_unpoison_memory_region(&men_mac_buf[6], MEN_PAD);

    int ok = (men_start_calls == tc->want_start) && (men_stop_calls == tc->want_stop);
    printf("    start_calls=%d stop_calls=%d assoc_checks=%d (want %d/%d)\n", men_start_calls,
           men_stop_calls, men_assoc_checks, tc->want_start, tc->want_stop);
    return ok;
}

void run_all_tests_monitor_enable_instant_msmt(void)
{
    for (int i = 0; monitor_enable_instant_msmt_suite[i].test_name != NULL; i++) {
        em_men_test_case_t *test = &monitor_enable_instant_msmt_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_monitor_enable_instant_msmt_input(test);
        int pass = test_monitor_enable_instant_msmt(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
