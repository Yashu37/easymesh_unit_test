/*
 * TEST RUNNER: ovsdb_method_send_s_test
 *
 * Caller input is ovsdb_sock_path; we poison its tail past the NUL so any
 * over-read is flagged. err[128] and res (error.message[64]) are internal
 * (auto-guarded by ASan).
 * PASS = a result object is returned exactly when expected and the request
 * was sent the expected number of times.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

json_t *onewifi_ovsdb_method_send_s(const char *ovsdb_sock_path, ovsdb_mt_t mt, json_t *jparams);

int test_ovsdb_method_send_s(const ovsdb_method_send_s_test_case_t *tc)
{
    __asan_poison_memory_region(&oms_sock[oms_sock_len + 1], sizeof(oms_sock) - (oms_sock_len + 1));

    json_t *res = onewifi_ovsdb_method_send_s(oms_sock, (ovsdb_mt_t)tc->mt, json_array());

    __asan_unpoison_memory_region(&oms_sock[oms_sock_len + 1], sizeof(oms_sock) - (oms_sock_len + 1));

    int got = res != NULL;
    printf("    mt=%d sock_len=%zu -> result=%s writes=%d\n", tc->mt, oms_sock_len, got ? "object" : "NULL", oms_writes);
    if (res) json_decref(res);
    return got == tc->expect_result && oms_writes == tc->expect_writes;
}

void run_all_tests_ovsdb_method_send_s(void)
{
    for (int i = 0; ovsdb_method_send_s_suite[i].test_name != NULL; i++) {
        ovsdb_method_send_s_test_case_t *test = &ovsdb_method_send_s_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_method_send_s_input(test);

        int pass = test_ovsdb_method_send_s(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected result=%d writes=%d) =====\n",
                   test->test_name, test->expect_result, test->expect_writes);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
