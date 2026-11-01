/*
 * TEST RUNNER: ovsdb_tran_comment_test
 *
 * Caller input ovsdb_comment (otc_comment_buf) is POISONED past its NUL, so
 * an over-read of it by STRSCPY is flagged. comment[128] is internal
 * (auto-guarded by ASan).
 * PASS = return matches, a comment op is appended exactly when expected,
 * and the comment string is <= 127 chars.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

typedef enum { OTR_INSERT, OTR_SELECT, OTR_UPDATE, OTR_MUTATE, OTR_DELETE, OTR_WAIT } ovsdb_tro_t;
bool onewifi_ovsdb_tran_comment(json_t *js_array, ovsdb_tro_t oper, json_t *where);
void *construct_ovsdb_tran_comment_where(const ovsdb_tran_comment_test_case_t *tc);

int test_ovsdb_tran_comment(const ovsdb_tran_comment_test_case_t *tc)
{
    json_t *arr = json_array();
    json_t *where = (json_t *)construct_ovsdb_tran_comment_where(tc);
    size_t l = strlen(otc_comment_buf);

    __asan_poison_memory_region(&otc_comment_buf[l + 1], sizeof(otc_comment_buf) - (l + 1));

    bool ok = onewifi_ovsdb_tran_comment(arr, (ovsdb_tro_t)tc->oper, where);

    __asan_unpoison_memory_region(&otc_comment_buf[l + 1], sizeof(otc_comment_buf) - (l + 1));

    int appended = (int)json_array_size(arr);
    const char *c = appended ? json_string_value(json_object_get(json_array_get(arr, 0), "comment")) : NULL;
    size_t clen = c ? strlen(c) : 0;
    printf("    ret=%d appended=%d comment_len=%zu \"%.60s%s\"\n", ok, appended, clen, c ? c : "", clen > 60 ? "..." : "");
    json_decref(arr);
    if (where) json_decref(where);
    return ok == (tc->expect_ret != 0) && appended == tc->expect_appended && clen <= 127;
}

void run_all_tests_ovsdb_tran_comment(void)
{
    for (int i = 0; ovsdb_tran_comment_suite[i].test_name != NULL; i++) {
        ovsdb_tran_comment_test_case_t *test = &ovsdb_tran_comment_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_tran_comment_input(test);

        int pass = test_ovsdb_tran_comment(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected ret=%d appended=%d) =====\n",
                   test->test_name, test->expect_ret, test->expect_appended);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
