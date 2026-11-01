/*
 * TEST RUNNER: convert_channel_width_to_str_test
 *
 * Poisoned around the call:
 *   - the caller's str buffer: bytes past the declared len (catches a
 *     snprintf that writes more than len).
 * arr_str / arr_enum are internal static globals (auto-guarded by ASan).
 * PASS = str holds the expected text.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void convert_channel_width_to_str(wifi_channelBandwidth_t cw, char *str, size_t len);

int test_convert_channel_width_to_str(const convert_channel_width_to_str_test_case_t *tc)
{
    /* POISON */
    __asan_poison_memory_region(&ccw_str_buf[tc->len], CCW_STR_SZ + CCW_PAD - tc->len);   /* str past len */

    convert_channel_width_to_str((wifi_channelBandwidth_t)tc->cw, ccw_str_buf, tc->len);

    /* UNPOISON */
    __asan_unpoison_memory_region(&ccw_str_buf[tc->len], CCW_STR_SZ + CCW_PAD - tc->len);

    printf("    cw=0x%x len=%zu -> str=\"%s\"\n", tc->cw, tc->len, ccw_str_buf);
    return strcmp(ccw_str_buf, tc->expect) == 0;
}

void run_all_tests_convert_channel_width_to_str(void)
{
    for (int i = 0; convert_channel_width_to_str_suite[i].test_name != NULL; i++) {
        convert_channel_width_to_str_test_case_t *test = &convert_channel_width_to_str_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_convert_channel_width_to_str_input(test);
        int pass = test_convert_channel_width_to_str(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected \"%s\") =====\n", test->test_name, test->expect);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
