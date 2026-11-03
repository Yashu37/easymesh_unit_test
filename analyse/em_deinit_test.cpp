/*
 * TEST RUNNER: em_deinit
 *
 * Poisoned around the call:
 *   - the wifi_ctrl stand-in (edi_ctrl_buf): bytes past sizeof(wifi_ctrl_t).
 * mac_str[18] is an internal stack array guarded by ASan redzones; the
 * client-type entries are sized heap allocations freed by the handler.
 *
 * PASS = RETURN_OK and the map was destroyed exactly once, with no leak
 * (every entry removed+freed) and no overflow of mac_str.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_deinit(wifi_app_t *app);

int test_em_deinit(const em_edi_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&edi_ctrl_buf[sizeof(wifi_ctrl_t)], EDI_PAD);

    int ret = em_deinit((wifi_app_t *)0x1);

    /* UNPOISON */
    __asan_unpoison_memory_region(&edi_ctrl_buf[sizeof(wifi_ctrl_t)], EDI_PAD);

    int ok = (ret == tc->want_ret) && (edi_destroy_calls == 1);
    printf("    ret=%d destroy_calls=%d (want %d)\n", ret, edi_destroy_calls, tc->want_ret);
    return ok;
}

void run_all_tests_em_deinit(void)
{
    for (int i = 0; em_deinit_suite[i].test_name != NULL; i++) {
        em_edi_test_case_t *test = &em_deinit_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_deinit_input(test);
        int pass = test_em_deinit(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
