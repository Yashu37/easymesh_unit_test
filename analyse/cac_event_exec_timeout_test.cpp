/*
 * TEST RUNNER: cac_event_exec_timeout_test
 *
 * Poisoned around the call:
 *   - the apps (wifi_app_t) and the wifi_mgr stand-in past their sizes;
 *   - the mac_str write slot cet_slot_mac past 18.
 * mac_str[18] / vap_name[32] / basic_buf[32] are internal (ASan stack).
 * PASS = an expiring entry is removed with its lower-case 17-char MAC key,
 * a non-expiring entry is not removed, and no assoc_map removes nothing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int cac_event_exec_timeout(wifi_app_t *apps, void *arg);

int test_cac_event_exec_timeout(const cac_event_exec_timeout_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&cet_apps_buf[sizeof(wifi_app_t)], CET_PAD);
    __asan_poison_memory_region(&cet_mgr_buf[sizeof(wifi_mgr_t)], CET_PAD);
    __asan_poison_memory_region(&cet_slot_mac[CET_MAC_SZ], CET_PAD);

    int ret = cac_event_exec_timeout((wifi_app_t *)cet_apps_buf, NULL);

    /* UNPOISON */
    __asan_unpoison_memory_region(&cet_slot_mac[CET_MAC_SZ], CET_PAD);
    __asan_unpoison_memory_region(&cet_mgr_buf[sizeof(wifi_mgr_t)], CET_PAD);
    __asan_unpoison_memory_region(&cet_apps_buf[sizeof(wifi_app_t)], CET_PAD);

    int key_ok = 1;
    if (cet_remove_calls) {
        key_ok = (strlen(cet_removed_key) == 17);
        for (const char *p = cet_removed_key; *p; p++) if (*p >= 'A' && *p <= 'F') key_ok = 0;
    }
    printf("    ret=%d remove_calls=%d removed_key=\"%s\"\n", ret, cet_remove_calls, cet_removed_key);
    return ret == 0 && cet_remove_calls == tc->expect_remove && key_ok;
}

void run_all_tests_cac_event_exec_timeout(void)
{
    for (int i = 0; cac_event_exec_timeout_suite[i].test_name != NULL; i++) {
        cac_event_exec_timeout_test_case_t *test = &cac_event_exec_timeout_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_cac_event_exec_timeout_input(test);
        int pass = test_cac_event_exec_timeout(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected remove=%d) =====\n", test->test_name, test->expect_remove);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
