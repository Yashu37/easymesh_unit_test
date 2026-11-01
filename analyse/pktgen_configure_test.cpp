/*
 * TEST RUNNER: pktgen_configure_test
 *
 * Poisoned around the call (caller-owned inputs): if_name and dest_mac past
 * their NUL. The snprintf slot for dev_path is poisoned past PATH_MAX inside
 * the handler's snprintf redirect. dev_path[4096] is internal (auto-guarded
 * by ASan).
 * PASS = return, number of pgctrl calls and dev_path length match.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int pktgen_configure(char *if_name, char *dest_mac, int packet_size);

static void psn(char *b, size_t sz, int on)
{
    size_t l = strlen(b);
    if (on) __asan_poison_memory_region(b + l + 1, sz - (l + 1));
    else    __asan_unpoison_memory_region(b + l + 1, sz - (l + 1));
}

int test_pktgen_configure(const pktgen_configure_test_case_t *tc)
{
    psn(pgf_ifname, sizeof(pgf_ifname), 1);
    psn(pgf_mac, sizeof(pgf_mac), 1);

    int ret = pktgen_configure(pgf_ifname, pgf_mac, 1500);

    psn(pgf_mac, sizeof(pgf_mac), 0);
    psn(pgf_ifname, sizeof(pgf_ifname), 0);

    printf("    ret=%d pgctrl_calls=%d dev_path_len=%zu max_file_len=%zu\n", ret, pgf_calls, pgf_dev_len, pgf_max_path);
    return ret == tc->expect_ret && pgf_calls == tc->expect_calls && pgf_dev_len == (size_t)tc->expect_dev;
}

void run_all_tests_pktgen_configure(void)
{
    for (int i = 0; pktgen_configure_suite[i].test_name != NULL; i++) {
        pktgen_configure_test_case_t *test = &pktgen_configure_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_pktgen_configure_input(test);

        int pass = test_pktgen_configure(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d calls=%d dev_len=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_calls, test->expect_dev);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
