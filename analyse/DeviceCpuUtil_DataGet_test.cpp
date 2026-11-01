/*
 * TEST RUNNER: DeviceCpuUtil_DataGet_test
 *
 * Poisoned around the call:
 *   - the caller's util_cpu: bytes past sizeof(unsigned int);
 *   - the buff fgets slot dcu_slot past 256 (= sizeof(buff)).
 * buff[256] / token[5] are internal (auto-guarded by ASan).
 * PASS = return value and *util_cpu match.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

bool DeviceCpuUtil_DataGet(unsigned int *util_cpu);

int test_DeviceCpuUtil_DataGet(const DeviceCpuUtil_DataGet_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&dcu_util_buf[sizeof(unsigned int)], DCU_PAD);   /* util_cpu  */
    __asan_poison_memory_region(&dcu_slot[DCU_SLOT_SZ], DCU_PAD);                /* buff[256] */

    bool ret = DeviceCpuUtil_DataGet((unsigned int *)dcu_util_buf);

    /* UNPOISON */
    __asan_unpoison_memory_region(&dcu_slot[DCU_SLOT_SZ], DCU_PAD);
    __asan_unpoison_memory_region(&dcu_util_buf[sizeof(unsigned int)], DCU_PAD);

    unsigned int util = *(unsigned int *)dcu_util_buf;
    printf("    ret=%d util_cpu=%u fgets_calls=%d\n", ret, util, dcu_lines);
    return ret == tc->expect_ret && util == tc->expect_util;
}

void run_all_tests_DeviceCpuUtil_DataGet(void)
{
    for (int i = 0; DeviceCpuUtil_DataGet_suite[i].test_name != NULL; i++) {
        DeviceCpuUtil_DataGet_test_case_t *test = &DeviceCpuUtil_DataGet_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_DeviceCpuUtil_DataGet_input(test);
        int pass = test_DeviceCpuUtil_DataGet(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d util=%u) =====\n", test->test_name, test->expect_ret, test->expect_util);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    remove(dcu_path);
}
