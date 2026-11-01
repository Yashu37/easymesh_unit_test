/*
 * TEST RUNNER: app_register_test
 *
 * Poisoned around the call (caller-owned / runner-owned):
 *   - descriptor: bytes past sizeof(wifi_app_descriptor_t);
 *   - apps_mgr: bytes past sizeof(wifi_apps_mgr_t);
 *   - the malloc pool: each slot's tail past sizeof(wifi_app_t).
 * The snprintf slot for key_str is poisoned past 32 inside the handler.
 * key_str[32] is internal (auto-guarded by ASan).
 * PASS = RETURN_OK, key length / put / init_fn calls match and the stored
 * app carries the descriptor and ctrl.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int app_register(wifi_apps_mgr_t *apps_mgr, wifi_app_descriptor_t *descriptor);

#define APR_DPAD (sizeof(apr_desc_buf) - sizeof(wifi_app_descriptor_t))
#define APR_MPAD (sizeof(apr_mgr_buf) - sizeof(wifi_apps_mgr_t))

int test_app_register(const app_register_test_case_t *tc)
{
    for (int i = 0; i < APR_POOL_SLOTS; i++)
        __asan_poison_memory_region(&apr_pool[i][sizeof(wifi_app_t)], APR_POOL_PAD);
    __asan_poison_memory_region(&apr_desc_buf[sizeof(wifi_app_descriptor_t)], APR_DPAD);
    __asan_poison_memory_region(&apr_mgr_buf[sizeof(wifi_apps_mgr_t)], APR_MPAD);
    fflush(stdout);

    int ret = app_register((wifi_apps_mgr_t *)apr_mgr_buf, (wifi_app_descriptor_t *)apr_desc_buf);

    __asan_unpoison_memory_region(&apr_mgr_buf[sizeof(wifi_apps_mgr_t)], APR_MPAD);
    __asan_unpoison_memory_region(&apr_desc_buf[sizeof(wifi_app_descriptor_t)], APR_DPAD);
    for (int i = 0; i < APR_POOL_SLOTS; i++)
        __asan_unpoison_memory_region(&apr_pool[i][sizeof(wifi_app_t)], APR_POOL_PAD);

    wifi_app_t *app = (wifi_app_t *)apr_put_data;
    int stored_ok = !app || (app->desc.inst == tc->inst && app->ctrl == (void *)0x1234 &&
                             strnlen(app->desc.desc, sizeof(app->desc.desc)) == 255);
    printf("    inst=%d -> ret=%d key=\"%s\" key_len=%zu put=%d init_calls=%d stored_ok=%d\n",
           tc->inst, ret, apr_key_seen, apr_key_len, app != NULL, apr_init_calls, stored_ok);
    return ret == 0 && apr_key_len == (size_t)tc->expect_key_len && (app != NULL) == (tc->expect_put != 0) &&
           apr_init_calls == tc->expect_init && stored_ok;
}

void run_all_tests_app_register(void)
{
    for (int i = 0; app_register_suite[i].test_name != NULL; i++) {
        app_register_test_case_t *test = &app_register_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_app_register_input(test);

        int pass = test_app_register(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected key_len=%d put=%d init=%d) =====\n",
                   test->test_name, test->expect_key_len, test->expect_put, test->expect_init);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
