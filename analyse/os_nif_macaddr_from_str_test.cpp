/*
 * TEST RUNNER: os_nif_macaddr_from_str_test
 *
 * Two caller-owned buffers are poisoned around the call:
 *   - input str: copied into onm_str[256], tail past the NUL poisoned
 *     (catches an over-read by strscpy/strsep);
 *   - output mac: placed at the start of a 64-byte runner buffer, bytes
 *     past sizeof(os_macaddr_t) (6) poisoned (catches mac->addr[6+] writes).
 * pstr[64] is internal (auto-guarded by ASan).
 * PASS = return value matches the expected one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool os_nif_macaddr_from_str(os_macaddr_t* mac, const char* str);

static unsigned char onm_macbuf[64];

int test_os_nif_macaddr_from_str(const os_nif_macaddr_test_case_t *tc)
{
    memset(onm_macbuf, 0, sizeof(onm_macbuf));
    os_macaddr_t *mac = (os_macaddr_t *)onm_macbuf;

    __asan_poison_memory_region(&onm_str[onm_str_len + 1], sizeof(onm_str) - (onm_str_len + 1));
    __asan_poison_memory_region(&onm_macbuf[sizeof(os_macaddr_t)], sizeof(onm_macbuf) - sizeof(os_macaddr_t));

    bool ok = os_nif_macaddr_from_str(mac, onm_str);

    __asan_unpoison_memory_region(&onm_macbuf[sizeof(os_macaddr_t)], sizeof(onm_macbuf) - sizeof(os_macaddr_t));
    __asan_unpoison_memory_region(&onm_str[onm_str_len + 1], sizeof(onm_str) - (onm_str_len + 1));

    printf("    str=\"%.40s%s\" -> ret=%d mac=" PRI_os_macaddr_t "\n", onm_str, onm_str_len > 40 ? "..." : "",
           ok, FMT_os_macaddr_t(*mac));
    return ok ? 1 : 0;
}

void run_all_tests_os_nif_macaddr_from_str(void)
{
    for (int i = 0; os_nif_macaddr_from_str_suite[i].test_name != NULL; i++) {
        os_nif_macaddr_test_case_t *test = &os_nif_macaddr_from_str_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_nif_macaddr_from_str_input(test);

        int got = test_os_nif_macaddr_from_str(test);

        if (got == test->expect_ret) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d, got=%d) =====\n",
                   test->test_name, test->expect_ret, got);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
