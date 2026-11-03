/*
 * TEST RUNNER: get_max_probe_ttl_cnt
 *
 * Poisoned around the call:
 *   - the ttl "file" backing store (gmt_file_buf) past the file content, up to
 *     GMT_FILE_SZ + GMT_PAD: any read beyond the file end would trip.
 * buff[64] is an internal stack array guarded by ASan redzones (fgets limit 64).
 *
 * PASS = returned TTL count matches the case (the overflowing digit line only
 * has to return without a memory error).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

unsigned int get_max_probe_ttl_cnt(void);

int test_get_max_probe_ttl_cnt(const lv_gmt_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&gmt_file_buf[gmt_file_len], GMT_FILE_SZ + GMT_PAD - gmt_file_len);

    unsigned int ret = get_max_probe_ttl_cnt();

    /* UNPOISON */
    __asan_unpoison_memory_region(&gmt_file_buf[gmt_file_len], GMT_FILE_SZ + GMT_PAD - gmt_file_len);

    int ok = (tc->want == 0xFFFFFFFFu) || (ret == tc->want);
    printf("    file_len=%zu ret=%u (want %u)\n", gmt_file_len, ret, tc->want);
    return ok;
}

void run_all_tests_get_max_probe_ttl_cnt(void)
{
    for (int i = 0; get_max_probe_ttl_cnt_suite[i].test_name != NULL; i++) {
        lv_gmt_test_case_t *test = &get_max_probe_ttl_cnt_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_get_max_probe_ttl_cnt_input(test);
        int pass = test_get_max_probe_ttl_cnt(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
