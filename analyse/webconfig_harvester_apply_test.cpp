/*
 * TEST RUNNER: webconfig_harvester_apply
 *
 * Poisoned around the call:
 *   - the decoded mac_address field past its NUL (up to its 13 bytes);
 *   - the WHA_PAD tail after the wha_subdoc_data_t (wha_wd_buf).
 * sta_mac (mac_address_t) is an internal stack array guarded by ASan redzones.
 *
 * PASS = all five sibling calls happened once, and the mac handed to
 * monitor_enable_instant_msmt equals the parsed string (for an empty string the
 * handler returns early from the parser and sta_mac is left unset, so only the
 * call counts are checked).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void webconfig_harvester_apply(wifi_app_t *app, wifi_event_t *event);

int test_webconfig_harvester_apply(const harv_wha_test_case_t *tc)
{
    wha_subdoc_data_t *wd = (wha_subdoc_data_t *)wha_wd_buf;
    wifi_event_t ev;
    ev.u.webconfig_data = wd;

    char *mac = wd->u.decoded.harvester.mac_address;
    size_t len = strlen(mac);
    size_t cap = sizeof(wd->u.decoded.harvester.mac_address);

    /* POISON */
    __asan_poison_memory_region(&mac[len + 1], cap - (len + 1));
    __asan_poison_memory_region(&wha_wd_buf[sizeof(wha_subdoc_data_t)], WHA_PAD);

    webconfig_harvester_apply(NULL, &ev);

    /* UNPOISON */
    __asan_unpoison_memory_region(&wha_wd_buf[sizeof(wha_subdoc_data_t)], WHA_PAD);
    __asan_unpoison_memory_region(&mac[len + 1], cap - (len + 1));

    int ok = wha_rep_calls == 1 && wha_def_calls == 1 && wha_ttl_calls == 1 &&
             wha_mac_calls == 1 && wha_en_calls == 1 &&
             (tc->mac[0] == 0 || memcmp(wha_en_mac, tc->want_mac, 6) == 0) && wha_en_val == tc->enabled;
    printf("    calls rep/def/ttl/mac/en=%d/%d/%d/%d/%d en=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           wha_rep_calls, wha_def_calls, wha_ttl_calls, wha_mac_calls, wha_en_calls, wha_en_val,
           wha_en_mac[0], wha_en_mac[1], wha_en_mac[2], wha_en_mac[3], wha_en_mac[4], wha_en_mac[5]);
    return ok;
}

void run_all_tests_webconfig_harvester_apply(void)
{
    for (int i = 0; webconfig_harvester_apply_suite[i].test_name != NULL; i++) {
        harv_wha_test_case_t *test = &webconfig_harvester_apply_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_webconfig_harvester_apply_input(test);
        int pass = test_webconfig_harvester_apply(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
