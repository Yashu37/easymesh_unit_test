/*
 * TEST RUNNER: telemetry_event_cac_test
 *
 * Poisoned around the call:
 *   - the caller's deny_type / deny_reason / mac buffers past their NULs;
 *   - the telemetry_buff slot past 64 and the telemetry_val slot past 128.
 * telemetry_buff[64] / telemetry_val[128] are internal (ASan stack guarded).
 * PASS = the t2 telemetry hook fired as expected (once for a matched band,
 * never for no-band / NULL mac) and both slots stayed within size.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

void telemetry_event_cac(char *deny_type, int index, char *deny_reason, char *mac, int threshold, int value);

int test_telemetry_event_cac(const telemetry_event_cac_test_case_t *tc)
{
    size_t tl = strlen(tec_type_buf) + 1, rl = strlen(tec_reason_buf) + 1, ml = strlen(tec_mac_buf) + 1;
    char *mac = tc->null_mac ? NULL : tec_mac_buf;

    /* POISON */
    __asan_poison_memory_region(&tec_type_buf[tl], 64 + TEC_PAD - tl);
    __asan_poison_memory_region(&tec_reason_buf[rl], 64 + TEC_PAD - rl);
    if (!tc->null_mac) __asan_poison_memory_region(&tec_mac_buf[ml], 32 + TEC_PAD - ml);
    __asan_poison_memory_region(&tec_slot_buff[TEC_BUFF_SZ], TEC_PAD);
    __asan_poison_memory_region(&tec_slot_val[TEC_VAL_SZ], TEC_PAD);

    telemetry_event_cac(tec_type_buf, 0, tec_reason_buf, mac, 5, 7);

    /* UNPOISON */
    __asan_unpoison_memory_region(&tec_slot_val[TEC_VAL_SZ], TEC_PAD);
    __asan_unpoison_memory_region(&tec_slot_buff[TEC_BUFF_SZ], TEC_PAD);
    if (!tc->null_mac) __asan_unpoison_memory_region(&tec_mac_buf[ml], 32 + TEC_PAD - ml);
    __asan_unpoison_memory_region(&tec_reason_buf[rl], 64 + TEC_PAD - rl);
    __asan_unpoison_memory_region(&tec_type_buf[tl], 64 + TEC_PAD - tl);

    printf("    band=%d t2_calls=%d buff_len=%zu val_len=%zu marker=\"%.30s\"\n",
           tc->band, tec_t2_calls, tec_buff_len, tec_val_len, tec_t2_marker);
    return tec_t2_calls == tc->expect_t2 && tec_buff_len < TEC_BUFF_SZ && tec_val_len < TEC_VAL_SZ;
}

void run_all_tests_telemetry_event_cac(void)
{
    for (int i = 0; telemetry_event_cac_suite[i].test_name != NULL; i++) {
        telemetry_event_cac_test_case_t *test = &telemetry_event_cac_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_telemetry_event_cac_input(test);
        int pass = test_telemetry_event_cac(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m (expected t2=%d) =====\n", test->test_name, test->expect_t2);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
