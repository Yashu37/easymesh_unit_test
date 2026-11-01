/*
 * TEST RUNNER: os_nif_gateway_set_test
 *
 * Caller input is ifname; we poison its tail past the terminator so any
 * over-read (by snprintf %s) is flagged. iproute[128] is internal
 * (auto-guarded by ASan). PASS = the call returns true AND the command the
 * stubbed system() saw is at most 127 chars (snprintf kept it bounded).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool os_nif_gateway_set(char* ifname, os_ipaddr_t gwaddr);
extern char   ogs_last_cmd[512];
extern size_t ogs_last_cmd_len;

int test_os_nif_gateway_set(const os_nif_gw_test_case_t *tc)
{
    __asan_poison_memory_region(&ogs_ifname[ogs_ifname_len + 1], sizeof(ogs_ifname) - (ogs_ifname_len + 1));

    bool ok = os_nif_gateway_set(ogs_ifname, ogs_gw);

    __asan_unpoison_memory_region(&ogs_ifname[ogs_ifname_len + 1], sizeof(ogs_ifname) - (ogs_ifname_len + 1));

    printf("    ifname_len=%zu -> ret=%d cmd_len=%zu cmd=\"%.60s%s\"\n", ogs_ifname_len, ok,
           ogs_last_cmd_len, ogs_last_cmd, ogs_last_cmd_len > 60 ? "..." : "");
    return (ok && ogs_last_cmd_len <= 127) ? 1 : 0;
}

void run_all_tests_os_nif_gateway_set(void)
{
    for (int i = 0; os_nif_gateway_set_suite[i].test_name != NULL; i++) {
        os_nif_gw_test_case_t *test = &os_nif_gateway_set_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_nif_gateway_set_input(test);

        int got = test_os_nif_gateway_set(test);

        if (got == 1) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
