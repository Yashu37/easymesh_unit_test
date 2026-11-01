/*
 * TEST RUNNER: os_nif_softwds_destroy_test
 *
 * Caller input is ifname; we poison its tail past the terminator so any
 * over-read (by snprintf %s) is flagged. cmd[1024] is internal
 * (auto-guarded by ASan). PASS = return matches, cmd_log was called once,
 * and the command it saw is at most 1023 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool os_nif_softwds_destroy(char* ifname);

int test_os_nif_softwds_destroy(const os_nif_softwds_destroy_test_case_t *tc)
{
    if (osd_ifname_len + 1 < sizeof(osd_ifname))
        __asan_poison_memory_region(&osd_ifname[osd_ifname_len + 1], sizeof(osd_ifname) - (osd_ifname_len + 1));

    bool ok = os_nif_softwds_destroy(osd_ifname);

    if (osd_ifname_len + 1 < sizeof(osd_ifname))
        __asan_unpoison_memory_region(&osd_ifname[osd_ifname_len + 1], sizeof(osd_ifname) - (osd_ifname_len + 1));

    printf("    ifname_len=%zu -> ret=%d cmd_log_calls=%d cmd_len=%zu\n", osd_ifname_len, ok, osd_calls, osd_cmd_len);
    return (ok == (tc->expect_ret != 0)) && osd_calls == 1 && osd_cmd_len <= 1023;
}

void run_all_tests_os_nif_softwds_destroy(void)
{
    for (int i = 0; os_nif_softwds_destroy_suite[i].test_name != NULL; i++) {
        os_nif_softwds_destroy_test_case_t *test = &os_nif_softwds_destroy_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_nif_softwds_destroy_input(test);

        int pass = test_os_nif_softwds_destroy(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
