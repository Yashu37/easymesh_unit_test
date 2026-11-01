/*
 * TEST RUNNER: get_app_by_inst_test
 *
 * Poisoned around the call: the bytes past the caller's apps_mgr struct
 * (input), and the key_str snprintf slot gai_slot past 32. key_str[32] is
 * internal (auto-guarded by ASan).
 * PASS = the right app is returned (or NULL) and the key length matches.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *apps_mgr, wifi_app_inst_t inst);

int test_get_app_by_inst(const get_app_by_inst_test_case_t *tc)
{
    wifi_apps_mgr_t *mgr = (wifi_apps_mgr_t *)gai_mgr_buf;

    __asan_poison_memory_region(&gai_mgr_buf[sizeof(wifi_apps_mgr_t)], sizeof(gai_mgr_buf) - sizeof(wifi_apps_mgr_t));
    __asan_poison_memory_region(&gai_slot[GAI_SLOT_SZ], GAI_SLOT_PAD);   /* key_str snprintf slot */

    wifi_app_t *app = get_app_by_inst(mgr, (wifi_app_inst_t)tc->inst);

    __asan_unpoison_memory_region(&gai_slot[GAI_SLOT_SZ], GAI_SLOT_PAD);
    __asan_unpoison_memory_region(&gai_mgr_buf[sizeof(wifi_apps_mgr_t)], sizeof(gai_mgr_buf) - sizeof(wifi_apps_mgr_t));

    printf("    inst=%d -> app=%s key=\"%s\" key_len=%zu\n", tc->inst, app ? "found" : "NULL", gai_key_seen, gai_key_len);
    return (app != NULL) == (tc->expect_found != 0) && gai_key_len == (size_t)tc->expect_key_len;
}

void run_all_tests_get_app_by_inst(void)
{
    for (int i = 0; get_app_by_inst_suite[i].test_name != NULL; i++) {
        get_app_by_inst_test_case_t *test = &get_app_by_inst_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_get_app_by_inst_input(test);

        int pass = test_get_app_by_inst(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected found=%d key_len=%d) =====\n",
                   test->test_name, test->expect_found, test->expect_key_len);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
