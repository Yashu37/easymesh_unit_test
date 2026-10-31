/*
 * TEST RUNNER: dpp_mac_str_tmp_test
 *
 * The caller-owned input is the 6-byte mac buffer: we poison everything
 * past mac[5] so any over-read by dpp_mac_to_str aborts. The returned
 * string lives in an internal static array (auto-guarded by ASan).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char *dpp_mac_str_tmp(uint8_t *mac);

int test_dpp_mac_str_tmp(const dpp_mac_test_case_t *tc)
{
    /* poison the mac buffer past the 6 valid bytes (over-read guard) */
    __asan_poison_memory_region(&dmt_mac[6], sizeof(dmt_mac) - 6);

    char *out = dpp_mac_str_tmp(dmt_mac);

    __asan_unpoison_memory_region(&dmt_mac[6], sizeof(dmt_mac) - 6);

    int ok = (out && dmt_expect && strcmp(out, dmt_expect) == 0) ? 1 : 0;
    printf("    out=\"%s\" expected=\"%s\"\n", out ? out : "(null)", dmt_expect);
    return ok;
}

void run_all_tests_dpp_mac_str_tmp(void)
{
    for (int i = 0; dpp_mac_suite[i].test_name != NULL; i++) {
        dpp_mac_test_case_t *test = &dpp_mac_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_dpp_mac_str_tmp_input(test);

        int ok = test_dpp_mac_str_tmp(test);

        if (ok) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (string mismatch) =====\n", test->test_name);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
