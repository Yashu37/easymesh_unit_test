/*
 * TEST RUNNER: levl_set_handler
 *
 * Poisoned around the call:
 *   - the caller's raw_data_t (lsh_pdata_buf) past its size;
 *   - the caller's event_name (lsh_name_buf, exactly strlen+1 bytes) past the
 *     terminating NUL;
 *   - the caller's string value (lsh_str_buf, exactly strlen+1 bytes) past the
 *     terminating NUL: any over-read by str_to_mac_bytes / strdup / strtok_r
 *     aborts.
 * parameter[200] is an internal stack array and the levl_config_t is a heap
 * block (a double free / use after free would be reported).
 *
 * PASS = return code, push count and the pushed config (MAC, max clients,
 * duration, publish interval) match the case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sanitizer/asan_interface.h>
#include "common.h"

typedef enum { bus_error_success = 0, bus_error_general = 1, bus_error_invalid_input = 2, bus_error_out_of_resources = 3 } bus_error_t;
typedef struct { int data_type; union { uint32_t u32; void *bytes; } raw_data; size_t raw_data_len; } raw_data_t;
typedef struct { int unused; } bus_user_data_t;
bus_error_t levl_set_handler(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

int test_levl_set_handler(const lv_lsh_test_case_t *tc)
{
    char *name = tc->name ? lsh_name_buf : NULL;

    /* POISON */
    __asan_poison_memory_region(&lsh_pdata_buf[sizeof(raw_data_t)], LSH_PAD);
    __asan_poison_memory_region(&lsh_name_buf[lsh_name_len], LSH_PAD);
    __asan_poison_memory_region(&lsh_str_buf[lsh_str_len], LSH_PAD);

    int ret = (int)levl_set_handler(name, (raw_data_t *)lsh_pdata_buf, NULL);

    /* UNPOISON */
    __asan_unpoison_memory_region(&lsh_str_buf[lsh_str_len], LSH_PAD);
    __asan_unpoison_memory_region(&lsh_name_buf[lsh_name_len], LSH_PAD);
    __asan_unpoison_memory_region(&lsh_pdata_buf[sizeof(raw_data_t)], LSH_PAD);

    static const unsigned char good[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01}, zero[6] = {0};
    int ok = (ret == tc->want_ret) && (lsh_push_calls == tc->want_push);
    if (tc->want_push) {
        ok = ok && lsh_pushed.max_num_csi_clients == tc->want_max &&
             lsh_pushed.levl_sounding_duration == tc->want_dur && lsh_pushed.levl_publish_interval == tc->want_int;
        if (tc->check_mac == 1) ok = ok && memcmp(lsh_pushed.clientMac, good, 6) == 0;
        if (tc->check_mac == 2) ok = ok && memcmp(lsh_pushed.clientMac, zero, 6) == 0;
    }
    printf("    ret=%d (want %d) push=%d (want %d) max=%d dur=%d int=%d mac0=%02x\n", ret, tc->want_ret,
           lsh_push_calls, tc->want_push, lsh_pushed.max_num_csi_clients, lsh_pushed.levl_sounding_duration,
           lsh_pushed.levl_publish_interval, lsh_pushed.clientMac[0]);
    return ok;
}

void run_all_tests_levl_set_handler(void)
{
    for (int i = 0; levl_set_handler_suite[i].test_name != NULL; i++) {
        lv_lsh_test_case_t *test = &levl_set_handler_suite[i];
        printf("--- Running Test: %s ---\n", test->test_name);
        construct_levl_set_handler_input(test);
        int pass = test_levl_set_handler(test);
        if (pass) printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
        else      printf("===== %s: \033[31mFAIL\033[0m =====\n", test->test_name);
        printf("------------------------------------------------------------------------------------------------------------------------------\n");
    }
}
