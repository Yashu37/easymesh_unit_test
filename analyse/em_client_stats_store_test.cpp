/*
 * TEST RUNNER: em_client_stats_store
 *
 * Poisoned around the call:
 *   - the caller's dev3 (ecs_dev3_buf): bytes past sizeof(wifi_associated_dev3_t).
 * mac_str / bss_str (char[18]) and key[64] are internal stack arrays guarded
 * by ASan stack redzones; the global cache is index-bounded.
 *
 * PASS = the returned code matches the expected path (RETURN_OK for the add /
 * update paths, RETURN_ERR for null dev3 / bad radio / missing vap / null vap).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

int em_client_stats_store(unsigned int radio_index, unsigned int vap_index, int sta_cnt,
    wifi_associated_dev3_t *dev3, struct timespec *timestamp);

int test_em_client_stats_store(const em_css_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&ecs_dev3_buf[sizeof(wifi_associated_dev3_t)], ECS_PAD);

    struct timespec ts = { 123, 456 };
    wifi_associated_dev3_t *dev3 = tc->dev3_null ? NULL : (wifi_associated_dev3_t *)ecs_dev3_buf;
    int ret = em_client_stats_store(tc->radio_index, tc->vap_index, tc->sta_cnt, dev3, &ts);

    /* UNPOISON */
    __asan_unpoison_memory_region(&ecs_dev3_buf[sizeof(wifi_associated_dev3_t)], ECS_PAD);

    printf("    ret=%d (want %d)\n", ret, tc->want_ret);
    return ret == tc->want_ret;
}

void run_all_tests_em_client_stats_store(void)
{
    for (int i = 0; em_client_stats_store_suite[i].test_name != NULL; i++) {
        em_css_test_case_t *test = &em_client_stats_store_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_em_client_stats_store_input(test);
        int pass = test_em_client_stats_store(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
    ecs_store_reset();
}
