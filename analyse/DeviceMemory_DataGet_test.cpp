/*
 * TEST RUNNER: DeviceMemory_DataGet_test
 *
 * Poisoned around the call:
 *   - the caller's util_mem: bytes past sizeof(uint32_t);
 *   - the buf fgets slot dmg_slot past 256 (= sizeof(buf)).
 * buf[256] is internal (auto-guarded by ASan).
 * PASS = return value matches and *util_mem matches on success.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

bool DeviceMemory_DataGet(uint32_t *util_mem);

int test_DeviceMemory_DataGet(const DeviceMemory_DataGet_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&dmg_util_buf[sizeof(uint32_t)], DMG_PAD);   /* util_mem */
    __asan_poison_memory_region(&dmg_slot[DMG_SLOT_SZ], DMG_PAD);            /* buf[256] */

    bool ret = DeviceMemory_DataGet((uint32_t *)dmg_util_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&dmg_slot[DMG_SLOT_SZ], DMG_PAD);
    __asan_unpoison_memory_region(&dmg_util_buf[sizeof(uint32_t)], DMG_PAD);

    unsigned int util = *(unsigned int *)dmg_util_buf;
    printf("    ret=%d util_mem=%u fgets_calls=%d\n", ret, util, dmg_lines);
    if (!tc->expect_ret) return ret == false;
    return ret == true && util == tc->expect_util;
}

void run_all_tests_DeviceMemory_DataGet(void)
{
    for (int i = 0; DeviceMemory_DataGet_suite[i].test_name != NULL; i++) {
        DeviceMemory_DataGet_test_case_t *test = &DeviceMemory_DataGet_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_DeviceMemory_DataGet_input(test);
        int pass = test_DeviceMemory_DataGet(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d util=%u) =====\n", test->test_name, test->expect_ret, test->expect_util);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    remove(dmg_path);
}
