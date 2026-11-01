/*
 * TEST RUNNER: ovsdb_sync_get_uuid_and_count_test
 *
 * Poisoned around the call (caller-owned):
 *   - the uuid output: ovs_uuid_t sits at the start of ogc_uuid_buf; the
 *     64 bytes past sizeof(ovs_uuid_t) are poisoned (catches a STRSCPY
 *     write past uuid[37]);
 *   - table and sock path past their NUL.
 *   - the where_str json_gets slot ogc_slot past 128.
 * where_str[128] / uuid1 are internal (auto-guarded by ASan).
 * PASS = count matches, uuid length matches (-1 = uuid NULL), where_str
 * length matches (-1 = any < 128).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

int ovsdb_sync_get_uuid_and_count(const char *ovsdb_sock_path, const char *table, json_t *where, ovs_uuid_t *uuid);
void *construct_ovsdb_sync_get_uuid_and_count_where(const ovsdb_sync_get_uuid_and_count_test_case_t *tc);

int test_ovsdb_sync_get_uuid_and_count(const ovsdb_sync_get_uuid_and_count_test_case_t *tc)
{
    json_t *where = (json_t *)construct_ovsdb_sync_get_uuid_and_count_where(tc);   /* consumed by select */
    ovs_uuid_t *uuid = tc->uuid_null ? NULL : (ovs_uuid_t *)ogc_uuid_buf;
    size_t tl = strlen(ogc_table), sl = strlen(ogc_sock);

    __asan_poison_memory_region(&ogc_uuid_buf[sizeof(ovs_uuid_t)], sizeof(ogc_uuid_buf) - sizeof(ovs_uuid_t));
    __asan_poison_memory_region(&ogc_table[tl + 1], sizeof(ogc_table) - (tl + 1));
    __asan_poison_memory_region(&ogc_sock[sl + 1], sizeof(ogc_sock) - (sl + 1));
    __asan_poison_memory_region(&ogc_slot[OGC_SLOT_SZ], OGC_SLOT_PAD);   /* where_str json_gets slot */

    int count = ovsdb_sync_get_uuid_and_count(ogc_sock, ogc_table, where, uuid);

    __asan_unpoison_memory_region(&ogc_slot[OGC_SLOT_SZ], OGC_SLOT_PAD);
    __asan_unpoison_memory_region(&ogc_sock[sl + 1], sizeof(ogc_sock) - (sl + 1));
    __asan_unpoison_memory_region(&ogc_table[tl + 1], sizeof(ogc_table) - (tl + 1));
    __asan_unpoison_memory_region(&ogc_uuid_buf[sizeof(ovs_uuid_t)], sizeof(ogc_uuid_buf) - sizeof(ovs_uuid_t));

    long ul = uuid ? (long)strnlen(uuid->uuid, sizeof(uuid->uuid)) : -1;
    printf("    -> count=%d uuid_len=%ld where_str_len=%zu\n", count, ul, ogc_where_len);
    int ok = count == tc->expect_count && ul == tc->expect_uuid_len && ogc_where_len < 128;
    if (tc->expect_where >= 0) ok = ok && ogc_where_len == (size_t)tc->expect_where;
    return ok;
}

void run_all_tests_ovsdb_sync_get_uuid_and_count(void)
{
    for (int i = 0; ovsdb_sync_get_uuid_and_count_suite[i].test_name != NULL; i++) {
        ovsdb_sync_get_uuid_and_count_test_case_t *test = &ovsdb_sync_get_uuid_and_count_suite[i];

        printf("--- Running Test: %s ---\n", test->test_name);

        construct_ovsdb_sync_get_uuid_and_count_input(test);

        int pass = test_ovsdb_sync_get_uuid_and_count(test);

        if (pass) {
            printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        } else {
            printf("===== %s: \033[31mFAIL\033[0m (expected count=%d uuid_len=%d where=%d) =====\n",
                   test->test_name, test->expect_count, test->expect_uuid_len, test->expect_where);
        }
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
