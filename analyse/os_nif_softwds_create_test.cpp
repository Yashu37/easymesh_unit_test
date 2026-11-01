/*
 * TEST RUNNER: os_nif_softwds_create_test
 *
 * Three caller-owned inputs are poisoned around the call:
 *   - ifname and parent: tail past each NUL poisoned (catches over-read by
 *     snprintf %s);
 *   - mac: placed at the start of a 64-byte runner buffer, bytes past
 *     sizeof(os_macaddr_t) (6) poisoned (catches reads past mac->addr[5]).
 * cmd[1024] is internal (auto-guarded by ASan).
 * PASS = return matches AND every command the stubbed cmd_log saw is at
 * most 1023 chars AND the cleanup ran exactly when create failed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

bool os_nif_softwds_create(char* ifname, char* parent, os_macaddr_t* mac, bool wrap);

static unsigned char osc_macbuf[64];

int test_os_nif_softwds_create(const os_nif_softwds_test_case_t *tc)
{
    memset(osc_macbuf, 0, sizeof(osc_macbuf));
    os_macaddr_t *mac = (os_macaddr_t *)osc_macbuf;
    static const uint8_t m[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    memcpy(mac->addr, m, sizeof(m));

    __asan_poison_memory_region(&osc_ifname[osc_ifname_len + 1], sizeof(osc_ifname) - (osc_ifname_len + 1));
    __asan_poison_memory_region(&osc_parent[osc_parent_len + 1], sizeof(osc_parent) - (osc_parent_len + 1));
    __asan_poison_memory_region(&osc_macbuf[sizeof(os_macaddr_t)], sizeof(osc_macbuf) - sizeof(os_macaddr_t));

    bool ok = os_nif_softwds_create(osc_ifname, osc_parent, mac, tc->wrap != 0);

    __asan_unpoison_memory_region(&osc_macbuf[sizeof(os_macaddr_t)], sizeof(osc_macbuf) - sizeof(os_macaddr_t));
    __asan_unpoison_memory_region(&osc_parent[osc_parent_len + 1], sizeof(osc_parent) - (osc_parent_len + 1));
    __asan_unpoison_memory_region(&osc_ifname[osc_ifname_len + 1], sizeof(osc_ifname) - (osc_ifname_len + 1));

    int want_calls = tc->create_exit ? 2 : 1;
    printf("    ifname_len=%zu parent_len=%zu -> ret=%d cmd_log_calls=%d max_cmd_len=%zu\n",
           osc_ifname_len, osc_parent_len, ok, osc_calls, osc_max_cmd_len);
    return (ok == (tc->expect_ret != 0)) && osc_max_cmd_len <= 1023 && osc_calls == want_calls;
}

void run_all_tests_os_nif_softwds_create(void)
{
    for (int i = 0; os_nif_softwds_create_suite[i].test_name != NULL; i++) {
        os_nif_softwds_test_case_t *test = &os_nif_softwds_create_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_os_nif_softwds_create_input(test);

        int pass = test_os_nif_softwds_create(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d) =====\n", test->test_name, test->expect_ret);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
