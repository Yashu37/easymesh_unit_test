/*
 * TEST RUNNER: osp_unit_dhcpc_hostname_get_test
 *
 * The caller-owned buffer is buff (size buffsz). We back it with a larger
 * buffer and poison everything past buffsz, so if the function's snprintf
 * writes beyond buffsz ASan aborts. The internal VLAs are auto-guarded by
 * ASan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool osp_unit_dhcpc_hostname_get(void *buff, size_t buffsz);

static char ohg_backing[256];

int test_osp_hostname(const osp_hostname_test_case_t *tc)
{
    size_t sz = ohg_buffsz;
    if (sz > sizeof(ohg_backing)) sz = sizeof(ohg_backing);

    memset(ohg_backing, 0, sizeof(ohg_backing));
    /* poison everything past the buffsz the function is told it has */
    __asan_poison_memory_region(&ohg_backing[sz], sizeof(ohg_backing) - sz);

    bool ret = osp_unit_dhcpc_hostname_get(ohg_backing, sz);

    /* read result while still inside the allowed region */
    char shown[64];
    snprintf(shown, sizeof(shown), "%.*s", (int)(sz < 63 ? sz : 63), ohg_backing);

    __asan_unpoison_memory_region(&ohg_backing[sz], sizeof(ohg_backing) - sz);

    printf("    buffsz=%zu ret=%d buff=\"%s\"\n", sz, ret, ret ? shown : "");
    return ret ? 1 : 0;
}

void run_all_tests_osp_hostname(void)
{
    for (int i = 0; osp_hostname_suite[i].test_name != NULL; i++) {
        osp_hostname_test_case_t *test = &osp_hostname_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_osp_hostname_input(test);

        int got = test_osp_hostname(test);

        if (got == test->expect_ret) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) =====\n",
                   test->test_name, test->expect_ret, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
